//! Canonical desktop aggregate for one complete runner-launch cleanup input set.
//!
//! This module joins an independently supplied, ledger-authoritative launch and
//! optional session with the lifecycle client's retained direct-child outcome
//! and an exact caller-supplied command-effect set. It deliberately does not
//! query the ledger, construct core worker-cleanup evidence, or handle the
//! trusted-applier no-descendant case.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    CommandDomainBackend as CoreCommandDomainBackend, CommandDomainCleanupCompleteness,
    CommandDomainCleanupDisposition, CommandDomainCleanupIncomplete, Digest, EventLedger,
    LedgerError, RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
};
use grok_build_runner::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, CommandDomainCleanupProofError,
    RunnerRole, ShutdownPreparedAcknowledgement, ValidatedCommandDomainCleanupProof,
    WireStateDisposition,
};
use serde::{Deserialize, Serialize};

use crate::runner_client::{DirectChildOutcome, RunnerCleanupRequired};

const RUNNER_LAUNCH_CLEANUP_VERSION: u32 = 1;
const RUNNER_LAUNCH_CLEANUP_PREFIX: &[u8] =
    b"grok-build.desktop.runner-launch-cleanup-aggregate.v1\0";
const EXPECTED_DOMAIN_SET_PREFIX: &[u8] = b"grok-build.desktop.expected-command-domain-set.v1\0";
const NO_REGISTERED_SESSION_SET_PREFIX: &[u8] =
    b"grok-build.desktop.no-registered-session-command-set.v1\0";
const SHUTDOWN_ACK_PREFIX: &[u8] = b"grok-build/runner-shutdown-prepared/v2\0";
const MAX_IDENTIFIER_BYTES: usize = 256;

/// Maximum canonical bytes retained by one launch-cleanup aggregate.
///
/// The aggregate remains separate from the core cleanup envelope. This bound
/// limits decoding and durable-storage cost; it is not conversion authority.
pub const MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES: usize = 1_048_576;

/// Maximum command domains admitted into one launch-cleanup aggregate.
pub const MAX_RUNNER_LAUNCH_COMMAND_DOMAINS: usize = 1_024;

/// Canonical ledger-derived expectation for all command domains in one session.
///
/// Construction sorts by effect identity and rejects duplicate effects. The
/// caller remains responsible for deriving this exact set from authoritative
/// ledger rows; this value does not perform that query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedCommandDomainCleanupSet {
    runner_session_id: String,
    backend: CommandDomainCleanupBackend,
    bindings: Vec<CommandDomainCleanupBinding>,
    set_digest: Digest,
}

impl ExpectedCommandDomainCleanupSet {
    /// Validates and canonicalizes one independently derived expected set.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed session identity, an oversized set, a
    /// binding from another session, a duplicate effect, or an encoding that
    /// exceeds the aggregate bound.
    pub fn try_new(
        runner_session_id: impl Into<String>,
        backend: CommandDomainCleanupBackend,
        mut bindings: Vec<CommandDomainCleanupBinding>,
    ) -> Result<Self, RunnerLaunchCleanupEvidenceError> {
        let runner_session_id = runner_session_id.into();
        validate_identifier("expected_set.runner_session_id", &runner_session_id)?;
        if bindings.len() > MAX_RUNNER_LAUNCH_COMMAND_DOMAINS {
            return Err(RunnerLaunchCleanupEvidenceError::TooManyCommandDomains {
                count: bindings.len(),
            });
        }
        for binding in &bindings {
            if binding.runner_session_id() != runner_session_id {
                return Err(RunnerLaunchCleanupEvidenceError::ExpectedSetSessionMismatch);
            }
        }
        bindings.sort_by(|left, right| left.command_effect_id().cmp(right.command_effect_id()));
        if let Some(duplicate) = bindings
            .windows(2)
            .find(|pair| pair[0].command_effect_id() == pair[1].command_effect_id())
        {
            return Err(
                RunnerLaunchCleanupEvidenceError::DuplicateExpectedCommandEffect {
                    effect_id: duplicate[0].command_effect_id().to_owned(),
                },
            );
        }
        let set_digest = expected_set_digest(&runner_session_id, backend, &bindings)?;
        Ok(Self {
            runner_session_id,
            backend,
            bindings,
            set_digest,
        })
    }

    /// Returns the exact registered runner session that owns the set.
    #[must_use]
    pub fn runner_session_id(&self) -> &str {
        &self.runner_session_id
    }

    /// Returns the one required platform backend for every command domain.
    #[must_use]
    pub const fn backend(&self) -> CommandDomainCleanupBackend {
        self.backend
    }

    /// Returns bindings sorted by unique command-effect identity.
    #[must_use]
    pub fn bindings(&self) -> &[CommandDomainCleanupBinding] {
        &self.bindings
    }

    /// Returns the domain-separated commitment to the exact expected set.
    #[must_use]
    pub const fn set_digest(&self) -> &Digest {
        &self.set_digest
    }
}

/// Complete construction input for one runner-launch cleanup aggregate.
#[derive(Clone, Copy)]
pub struct RunnerLaunchCleanupEvidenceInput<'a> {
    /// Separately loaded authoritative launch intent.
    pub ledger_launch: &'a RunnerLaunchIntent,
    /// Separately loaded authoritative session, absent before registration.
    pub ledger_session: Option<&'a RunnerSessionPolicyRecord>,
    /// Handoff produced by the exact retained runner lifecycle client.
    pub cleanup_required: &'a RunnerCleanupRequired,
    /// Separately derived exact command set, required for registered sessions.
    pub expected_command_domains: Option<&'a ExpectedCommandDomainCleanupSet>,
    /// Validated native proof values, in any input order.
    pub command_domain_proofs: &'a [ValidatedCommandDomainCleanupProof],
}

/// Semantically distinct direct-child cleanup paths admitted by the aggregate.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerLaunchCleanupDisposition {
    /// Descriptor/platform admission refused before any process could exist.
    RefusedBeforeSpawnNoCommands,
    /// The operating-system spawn call failed and produced no child.
    SpawnFailedNoCommands,
    /// A child existed but no session registered, so no command effect was admitted.
    ReapedUnregisteredChildNoCommands,
    /// The exact registered direct child was reaped and every expected command
    /// domain has one matching validated platform proof.
    ReapedRegisteredSession,
}

/// Immutable, restart-validatable launch-cleanup aggregate.
///
/// This is not, and cannot be converted by this module into, a core
/// `WorkerCleanupEvidence` value.
#[must_use = "persist or explicitly consume the validated launch-cleanup aggregate"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRunnerLaunchCleanupEvidence {
    launch: RunnerLaunchIntent,
    session: Option<RunnerSessionPolicyRecord>,
    direct_child: DirectChildOutcome,
    disposition: RunnerLaunchCleanupDisposition,
    backend: Option<CommandDomainCleanupBackend>,
    expected_domain_set_digest: Digest,
    command_domain_count: usize,
    evidence_bytes: Vec<u8>,
    evidence_digest: Digest,
}

/// Ledger-reloaded launch cleanup whose opaque command proofs were revalidated
/// by the runner's native proof decoder.
///
/// This value is still not a core `WorkerCleanupEvidence`. In particular, it
/// does not create or backfill the cleanup effect intent that must have been
/// durable before platform cleanup began.
#[must_use = "bind the ledger-backed aggregate to an already-durable cleanup effect"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerValidatedRunnerLaunchCleanupEvidence {
    aggregate: ValidatedRunnerLaunchCleanupEvidence,
    latest_command_domain_cleanup_at_unix_ms: Option<u64>,
}

impl LedgerValidatedRunnerLaunchCleanupEvidence {
    /// Returns the exact restart-validatable launch aggregate.
    pub const fn aggregate(&self) -> &ValidatedRunnerLaunchCleanupEvidence {
        &self.aggregate
    }

    /// Returns the latest durable command-domain cleanup time, absent when no
    /// runner session or command domain ever existed.
    #[must_use]
    pub const fn latest_command_domain_cleanup_at_unix_ms(&self) -> Option<u64> {
        self.latest_command_domain_cleanup_at_unix_ms
    }

    /// Consumes the wrapper without adding cleanup-effect authority.
    pub fn into_aggregate(self) -> ValidatedRunnerLaunchCleanupEvidence {
        self.aggregate
    }
}

impl ValidatedRunnerLaunchCleanupEvidence {
    /// Reopens exact persisted aggregate bytes against independent authority.
    ///
    /// The expected command set must be freshly reconstructed by trusted
    /// coordinator code from the authoritative ledger before calling this
    /// method. Embedded proof bytes are revalidated through their native
    /// platform validators.
    ///
    /// # Errors
    ///
    /// Returns an error for a digest, canonical encoding, authority, role,
    /// direct-child, acknowledgement, backend, exact-set, or native-proof
    /// mismatch.
    #[allow(
        clippy::too_many_arguments,
        reason = "readback keeps every independent authority input explicit"
    )]
    pub fn readback(
        evidence_bytes: &[u8],
        expected_digest: &Digest,
        ledger_launch: &RunnerLaunchIntent,
        ledger_session: Option<&RunnerSessionPolicyRecord>,
        cleanup_required: &RunnerCleanupRequired,
        expected_command_domains: Option<&ExpectedCommandDomainCleanupSet>,
    ) -> Result<Self, RunnerLaunchCleanupEvidenceError> {
        validate_evidence_length(evidence_bytes)?;
        if Digest::sha256(evidence_bytes) != *expected_digest {
            return Err(RunnerLaunchCleanupEvidenceError::DigestMismatch);
        }
        let canonical = evidence_bytes
            .strip_prefix(RUNNER_LAUNCH_CLEANUP_PREFIX)
            .ok_or(RunnerLaunchCleanupEvidenceError::InvalidDomain)?;
        if canonical.is_empty() {
            return Err(RunnerLaunchCleanupEvidenceError::Decoding);
        }
        let payload: CanonicalRunnerLaunchCleanup = serde_json::from_slice(canonical)
            .map_err(|_| RunnerLaunchCleanupEvidenceError::Decoding)?;
        let reencoded =
            serde_json::to_vec(&payload).map_err(|_| RunnerLaunchCleanupEvidenceError::Encoding)?;
        if reencoded != canonical {
            return Err(RunnerLaunchCleanupEvidenceError::NonCanonical);
        }
        if payload.schema_version != RUNNER_LAUNCH_CLEANUP_VERSION {
            return Err(RunnerLaunchCleanupEvidenceError::UnsupportedVersion {
                version: payload.schema_version,
            });
        }

        let context = validate_authoritative_context(
            ledger_launch,
            ledger_session,
            cleanup_required,
            expected_command_domains,
        )?;
        if payload.launch != *ledger_launch
            || payload.session.as_ref() != ledger_session
            || payload.direct_child
                != CanonicalDirectChildOutcome::from(cleanup_required.direct_child_outcome())
            || payload.disposition != context.disposition
            || payload.backend != context.backend
            || payload.expected_domain_set_digest != context.expected_domain_set_digest
            || payload.shutdown_prepared.as_ref() != cleanup_required.shutdown_prepared()
        {
            return Err(RunnerLaunchCleanupEvidenceError::ReadbackAuthorityMismatch);
        }
        if payload.command_domains.len() > MAX_RUNNER_LAUNCH_COMMAND_DOMAINS {
            return Err(RunnerLaunchCleanupEvidenceError::TooManyCommandDomains {
                count: payload.command_domains.len(),
            });
        }

        let mut reopened = Vec::with_capacity(payload.command_domains.len());
        for domain in &payload.command_domains {
            let binding = CommandDomainCleanupBinding::try_new(
                domain.runner_session_id.clone(),
                domain.command_effect_id.clone(),
                domain.command_request_digest.clone(),
            )
            .map_err(RunnerLaunchCleanupEvidenceError::CommandDomainProof)?;
            // Launch-level cleanup aggregates domains that existed and were
            // reaped. A proof that no domain was created also carries zero
            // survivors, so requiring the disposition explicitly is what keeps
            // the two from substituting for one another here.
            let proof = ValidatedCommandDomainCleanupProof::readback_with_disposition(
                &domain.os_evidence_bytes,
                &domain.os_evidence_digest,
                domain.backend,
                &binding,
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            )
            .map_err(RunnerLaunchCleanupEvidenceError::CommandDomainProof)?;
            reopened.push(proof);
        }
        let canonical_domains = canonicalize_command_proofs(expected_command_domains, &reopened)?;
        if canonical_domains != payload.command_domains {
            return Err(RunnerLaunchCleanupEvidenceError::ReadbackDomainMismatch);
        }

        Ok(Self {
            launch: ledger_launch.clone(),
            session: ledger_session.cloned(),
            direct_child: cleanup_required.direct_child_outcome().clone(),
            disposition: context.disposition,
            backend: context.backend,
            expected_domain_set_digest: context.expected_domain_set_digest,
            command_domain_count: canonical_domains.len(),
            evidence_bytes: evidence_bytes.to_vec(),
            evidence_digest: expected_digest.clone(),
        })
    }

    /// Returns the exact authoritative launch bound into this aggregate.
    #[must_use]
    pub const fn launch(&self) -> &RunnerLaunchIntent {
        &self.launch
    }

    /// Returns the authoritative registered session, when one existed.
    #[must_use]
    pub const fn session(&self) -> Option<&RunnerSessionPolicyRecord> {
        self.session.as_ref()
    }

    /// Returns the retained direct-child outcome used by the proof.
    #[must_use]
    pub const fn direct_child_outcome(&self) -> &DirectChildOutcome {
        &self.direct_child
    }

    /// Returns the semantically distinct cleanup path.
    #[must_use]
    pub const fn disposition(&self) -> RunnerLaunchCleanupDisposition {
        self.disposition
    }

    /// Returns the one command-domain backend, absent before session registration.
    #[must_use]
    pub const fn backend(&self) -> Option<CommandDomainCleanupBackend> {
        self.backend
    }

    /// Returns the exact expected command-set commitment.
    #[must_use]
    pub const fn expected_domain_set_digest(&self) -> &Digest {
        &self.expected_domain_set_digest
    }

    /// Returns the exact number of distinct command-domain proofs.
    #[must_use]
    pub const fn command_domain_count(&self) -> usize {
        self.command_domain_count
    }

    /// Returns the complete domain-separated canonical aggregate bytes.
    #[must_use]
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    /// Returns SHA-256 of the exact aggregate bytes.
    #[must_use]
    pub const fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

/// Constructs one canonical launch-cleanup aggregate from independently
/// supplied authority and validated command-domain proofs.
///
/// # Errors
///
/// Returns an error unless launch, session, handoff, role, direct child,
/// acknowledgement, expected set, and every command-domain proof agree exactly.
pub fn adapt_runner_launch_cleanup_evidence(
    input: RunnerLaunchCleanupEvidenceInput<'_>,
) -> Result<ValidatedRunnerLaunchCleanupEvidence, RunnerLaunchCleanupEvidenceError> {
    let context = validate_authoritative_context(
        input.ledger_launch,
        input.ledger_session,
        input.cleanup_required,
        input.expected_command_domains,
    )?;
    let command_domains =
        canonicalize_command_proofs(input.expected_command_domains, input.command_domain_proofs)?;
    let payload = CanonicalRunnerLaunchCleanup {
        schema_version: RUNNER_LAUNCH_CLEANUP_VERSION,
        launch: input.ledger_launch.clone(),
        session: input.ledger_session.cloned(),
        direct_child: CanonicalDirectChildOutcome::from(
            input.cleanup_required.direct_child_outcome(),
        ),
        disposition: context.disposition,
        backend: context.backend,
        expected_domain_set_digest: context.expected_domain_set_digest,
        shutdown_prepared: input.cleanup_required.shutdown_prepared().cloned(),
        command_domains,
    };
    let evidence_bytes = encode_payload(&payload)?;
    let evidence_digest = Digest::sha256(&evidence_bytes);
    ValidatedRunnerLaunchCleanupEvidence::readback(
        &evidence_bytes,
        &evidence_digest,
        input.ledger_launch,
        input.ledger_session,
        input.cleanup_required,
        input.expected_command_domains,
    )
}

/// Reconstructs one launch aggregate from schema-v11 ledger authority and
/// independently revalidates every retained native command-domain proof.
///
/// Registered sessions require the complete, known-outcome exact command set.
/// Unregistered launch attempts remain unsupported until core exposes exact
/// launch-only readback; accepting the launch embedded in a handoff would not
/// be ledger-backed authority even when no child was spawned.
///
/// # Errors
///
/// Returns an error for corrupt ledger state, a handoff/session mismatch, an
/// incomplete or unresolved command set, backend confusion, invalid native
/// proof bytes, or an unregistered launch that cannot yet be reloaded.
pub fn adapt_ledger_runner_launch_cleanup_evidence(
    ledger: &EventLedger,
    cleanup_required: &RunnerCleanupRequired,
    backend: CoreCommandDomainBackend,
) -> Result<LedgerValidatedRunnerLaunchCleanupEvidence, LedgerRunnerLaunchCleanupError> {
    let launch = cleanup_required.launch();
    let native_backend = native_backend(backend);
    let Some(handoff_session) = cleanup_required.session() else {
        match ledger.load_runner_session(&launch.sprint_id, &launch.session_id) {
            Err(LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }) => {
                return Err(LedgerRunnerLaunchCleanupError::UnregisteredLaunchNeedsLedgerAuthority);
            }
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(LedgerRunnerLaunchCleanupError::HandoffOmittedDurableSession),
        }
    };

    let ledger_session = ledger.load_runner_session(&launch.sprint_id, &launch.session_id)?;
    if ledger_session != *handoff_session {
        return Err(LedgerRunnerLaunchCleanupError::HandoffSessionDiffersFromLedger);
    }
    let complete = match ledger.load_command_domain_cleanup_completeness(
        &launch.sprint_id,
        &launch.launch_id,
        &ledger_session.session_id,
        backend,
    )? {
        CommandDomainCleanupCompleteness::Complete(complete) => complete,
        CommandDomainCleanupCompleteness::Incomplete(reason) => {
            return Err(LedgerRunnerLaunchCleanupError::IncompleteCommandDomains(
                reason,
            ));
        }
    };
    if complete.sprint_id != launch.sprint_id
        || complete.launch_id != launch.launch_id
        || complete.session_id != ledger_session.session_id
        || complete.backend != backend
    {
        return Err(LedgerRunnerLaunchCleanupError::CompleteSetAuthorityMismatch);
    }

    let mut bindings = Vec::with_capacity(complete.entries.len());
    let mut native_proofs = Vec::with_capacity(complete.entries.len());
    let mut latest_cleanup = None;
    for entry in complete.entries {
        let binding = CommandDomainCleanupBinding::try_new(
            entry.binding.session_id.clone(),
            entry.binding.effect_id.clone(),
            entry.binding.request_digest.clone(),
        )?;
        // The durable record already states which disposition it claims. The
        // native bytes must support that exact claim rather than merely some
        // zero-survivor claim, so a persisted disposition and its evidence can
        // no longer disagree.
        let proof = ValidatedCommandDomainCleanupProof::readback_with_disposition(
            &entry.proof.platform_proof_bytes,
            &entry.proof.platform_proof_digest,
            native_backend,
            &binding,
            entry.proof.disposition,
        )?;
        latest_cleanup = Some(
            latest_cleanup
                .unwrap_or(0)
                .max(entry.proof.cleaned_at_unix_ms),
        );
        bindings.push(binding);
        native_proofs.push(proof);
    }
    let expected = ExpectedCommandDomainCleanupSet::try_new(
        ledger_session.session_id.clone(),
        native_backend,
        bindings,
    )?;
    let aggregate = adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
        ledger_launch: launch,
        ledger_session: Some(&ledger_session),
        cleanup_required,
        expected_command_domains: Some(&expected),
        command_domain_proofs: &native_proofs,
    })?;
    Ok(LedgerValidatedRunnerLaunchCleanupEvidence {
        aggregate,
        latest_command_domain_cleanup_at_unix_ms: latest_cleanup,
    })
}

const fn native_backend(backend: CoreCommandDomainBackend) -> CommandDomainCleanupBackend {
    match backend {
        CoreCommandDomainBackend::MacOsDedicatedIdentity => {
            CommandDomainCleanupBackend::MacOsDedicatedIdentity
        }
        CoreCommandDomainBackend::LinuxCgroupV2 => CommandDomainCleanupBackend::LinuxCgroupV2,
    }
}

/// Failure while joining durable command-domain authority to native runner
/// proof validation.
#[derive(Debug)]
pub enum LedgerRunnerLaunchCleanupError {
    /// Core persistence or readback failed.
    Ledger(LedgerError),
    /// Existing launch aggregate validation failed.
    Aggregate(RunnerLaunchCleanupEvidenceError),
    /// Native proof bytes or their exact binding failed validation.
    NativeProof(CommandDomainCleanupProofError),
    /// The lifecycle handoff omitted a session that is durable in the ledger.
    HandoffOmittedDurableSession,
    /// The handoff session differs from exact durable session authority.
    HandoffSessionDiffersFromLedger,
    /// One or more command effects has missing proof or unresolved outcome.
    IncompleteCommandDomains(CommandDomainCleanupIncomplete),
    /// The supposedly complete set crossed sprint, launch, session, or backend.
    CompleteSetAuthorityMismatch,
    /// Core cannot yet reload launch-only authority for an unregistered attempt.
    UnregisteredLaunchNeedsLedgerAuthority,
}

impl Display for LedgerRunnerLaunchCleanupError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ledger(error) => write!(formatter, "cleanup ledger rejected: {error}"),
            Self::Aggregate(error) => write!(formatter, "cleanup aggregate rejected: {error}"),
            Self::NativeProof(error) => write!(formatter, "native cleanup proof rejected: {error}"),
            Self::HandoffOmittedDurableSession => formatter.write_str(
                "cleanup handoff omitted the exact runner session already durable in the ledger",
            ),
            Self::HandoffSessionDiffersFromLedger => formatter.write_str(
                "cleanup handoff session differs from exact durable runner-session authority",
            ),
            Self::IncompleteCommandDomains(reason) => {
                write!(formatter, "command-domain cleanup set is incomplete: {reason:?}")
            }
            Self::CompleteSetAuthorityMismatch => formatter.write_str(
                "complete command-domain set crosses sprint, launch, session, or backend",
            ),
            Self::UnregisteredLaunchNeedsLedgerAuthority => formatter.write_str(
                "an unregistered launch cannot be ledger-backed until exact launch-only readback is available",
            ),
        }
    }
}

impl Error for LedgerRunnerLaunchCleanupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Ledger(error) => Some(error),
            Self::Aggregate(error) => Some(error),
            Self::NativeProof(error) => Some(error),
            Self::HandoffOmittedDurableSession
            | Self::HandoffSessionDiffersFromLedger
            | Self::IncompleteCommandDomains(_)
            | Self::CompleteSetAuthorityMismatch
            | Self::UnregisteredLaunchNeedsLedgerAuthority => None,
        }
    }
}

impl From<LedgerError> for LedgerRunnerLaunchCleanupError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<RunnerLaunchCleanupEvidenceError> for LedgerRunnerLaunchCleanupError {
    fn from(error: RunnerLaunchCleanupEvidenceError) -> Self {
        Self::Aggregate(error)
    }
}

impl From<CommandDomainCleanupProofError> for LedgerRunnerLaunchCleanupError {
    fn from(error: CommandDomainCleanupProofError) -> Self {
        Self::NativeProof(error)
    }
}

/// Closed launch-cleanup aggregate construction or readback failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunnerLaunchCleanupEvidenceError {
    /// A supplied contract failed its own validation.
    InvalidContract {
        /// Contract or relationship that failed.
        field: &'static str,
    },
    /// A bounded identifier is not canonical.
    InvalidIdentifier {
        /// Identifier field that failed.
        field: &'static str,
    },
    /// The lifecycle handoff launch differs from the authoritative launch.
    HandoffLaunchMismatch,
    /// The lifecycle handoff session differs from authoritative ledger state.
    HandoffSessionMismatch,
    /// Launch and registered-session immutable fields differ.
    LaunchSessionMismatch,
    /// Trusted-applier no-descendant proof is not implemented by this adapter.
    TrustedApplierUnsupported,
    /// A registered session was supplied without an expected command set.
    MissingExpectedCommandSet,
    /// A command set was supplied before any session registered.
    UnexpectedExpectedCommandSet,
    /// The expected command set belongs to another runner session.
    ExpectedSetSessionMismatch,
    /// More command domains were supplied than the hard count bound.
    TooManyCommandDomains {
        /// Observed domain count.
        count: usize,
    },
    /// The expected set contains two requests for one effect identity.
    DuplicateExpectedCommandEffect {
        /// Duplicated effect identity.
        effect_id: String,
    },
    /// One expected command effect has no platform proof.
    MissingCommandDomainProof {
        /// Missing effect identity.
        effect_id: String,
    },
    /// A platform proof does not belong to the exact expected effect set.
    ExtraCommandDomainProof {
        /// Extra effect identity.
        effect_id: String,
    },
    /// Two platform proofs claim the same command effect.
    DuplicateCommandDomainProof {
        /// Duplicated effect identity.
        effect_id: String,
    },
    /// A proof belongs to another registered runner session.
    CommandDomainSessionMismatch,
    /// A proof uses a backend other than the one expected for the session.
    CommandDomainBackendMismatch,
    /// A proof substitutes a request digest under an expected effect identity.
    CommandDomainRequestMismatch,
    /// A nested native command-domain proof failed validation.
    CommandDomainProof(CommandDomainCleanupProofError),
    /// Native held-child state or waiting for the exact direct child is ambiguous.
    AmbiguousDirectChild,
    /// Direct-child state is impossible for the supplied registration state.
    InvalidDirectChildState,
    /// A shutdown acknowledgement is absent/present or bound inconsistently.
    InvalidShutdownAcknowledgement,
    /// Canonical expected-set or aggregate encoding failed.
    Encoding,
    /// Aggregate evidence is empty.
    EmptyEvidence,
    /// Aggregate evidence exceeds its hard byte bound.
    EvidenceTooLarge {
        /// Observed byte count.
        bytes: usize,
    },
    /// The aggregate domain-separation prefix is absent or changed.
    InvalidDomain,
    /// Strict aggregate decoding failed.
    Decoding,
    /// Valid JSON used a noncanonical byte representation.
    NonCanonical,
    /// The aggregate schema version is unsupported.
    UnsupportedVersion {
        /// Observed schema version.
        version: u32,
    },
    /// Exact aggregate bytes differ from the expected digest.
    DigestMismatch,
    /// Persisted authority fields differ from independent authoritative input.
    ReadbackAuthorityMismatch,
    /// Persisted nested domains differ from their canonical exact-set replay.
    ReadbackDomainMismatch,
}

impl Display for RunnerLaunchCleanupEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract { field } => {
                write!(formatter, "invalid cleanup contract: {field}")
            }
            Self::InvalidIdentifier { field } => {
                write!(formatter, "invalid cleanup identifier: {field}")
            }
            Self::HandoffLaunchMismatch => {
                formatter.write_str("cleanup handoff launch differs from authoritative launch")
            }
            Self::HandoffSessionMismatch => {
                formatter.write_str("cleanup handoff session differs from authoritative session")
            }
            Self::LaunchSessionMismatch => {
                formatter.write_str("runner launch and registered session differ")
            }
            Self::TrustedApplierUnsupported => formatter.write_str(
                "trusted-applier launch cleanup requires a separate no-descendant proof",
            ),
            Self::MissingExpectedCommandSet => {
                formatter.write_str("registered cleanup requires an exact expected command set")
            }
            Self::UnexpectedExpectedCommandSet => {
                formatter.write_str("unregistered cleanup cannot claim command domains")
            }
            Self::ExpectedSetSessionMismatch => {
                formatter.write_str("expected command set belongs to another runner session")
            }
            Self::TooManyCommandDomains { count } => write!(
                formatter,
                "cleanup aggregate has {count} command domains; maximum is {MAX_RUNNER_LAUNCH_COMMAND_DOMAINS}"
            ),
            Self::DuplicateExpectedCommandEffect { effect_id } => write!(
                formatter,
                "expected command effect {effect_id} is duplicated"
            ),
            Self::MissingCommandDomainProof { effect_id } => write!(
                formatter,
                "expected command effect {effect_id} has no cleanup proof"
            ),
            Self::ExtraCommandDomainProof { effect_id } => write!(
                formatter,
                "cleanup proof for command effect {effect_id} is not expected"
            ),
            Self::DuplicateCommandDomainProof { effect_id } => write!(
                formatter,
                "command effect {effect_id} has duplicate cleanup proofs"
            ),
            Self::CommandDomainSessionMismatch => {
                formatter.write_str("command-domain proof belongs to another runner session")
            }
            Self::CommandDomainBackendMismatch => {
                formatter.write_str("command-domain proof uses the wrong platform backend")
            }
            Self::CommandDomainRequestMismatch => {
                formatter.write_str("command-domain proof substitutes the expected request")
            }
            Self::CommandDomainProof(error) => {
                write!(formatter, "command-domain cleanup proof failed: {error}")
            }
            Self::AmbiguousDirectChild => {
                formatter.write_str("native or exact direct-child state is ambiguous")
            }
            Self::InvalidDirectChildState => {
                formatter.write_str("direct-child outcome is impossible for registration state")
            }
            Self::InvalidShutdownAcknowledgement => formatter
                .write_str("shutdown acknowledgement differs from the exact registered lifecycle"),
            Self::Encoding => formatter.write_str("cleanup aggregate canonical encoding failed"),
            Self::EmptyEvidence => formatter.write_str("cleanup aggregate evidence is empty"),
            Self::EvidenceTooLarge { bytes } => write!(
                formatter,
                "cleanup aggregate evidence has {bytes} bytes; maximum is {MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES}"
            ),
            Self::InvalidDomain => formatter.write_str("cleanup aggregate has the wrong domain"),
            Self::Decoding => formatter.write_str("cleanup aggregate failed strict decoding"),
            Self::NonCanonical => {
                formatter.write_str("cleanup aggregate is not byte-for-byte canonical")
            }
            Self::UnsupportedVersion { version } => {
                write!(formatter, "unsupported cleanup aggregate version {version}")
            }
            Self::DigestMismatch => {
                formatter.write_str("cleanup aggregate digest differs from exact bytes")
            }
            Self::ReadbackAuthorityMismatch => formatter
                .write_str("cleanup aggregate differs from independently supplied authority"),
            Self::ReadbackDomainMismatch => formatter
                .write_str("cleanup aggregate domains differ from canonical exact-set replay"),
        }
    }
}

impl Error for RunnerLaunchCleanupEvidenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CommandDomainProof(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRunnerLaunchCleanup {
    schema_version: u32,
    launch: RunnerLaunchIntent,
    session: Option<RunnerSessionPolicyRecord>,
    direct_child: CanonicalDirectChildOutcome,
    disposition: RunnerLaunchCleanupDisposition,
    backend: Option<CommandDomainCleanupBackend>,
    expected_domain_set_digest: Digest,
    shutdown_prepared: Option<ShutdownPreparedAcknowledgement>,
    command_domains: Vec<CanonicalCommandDomainProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalDirectChildOutcome {
    LaunchRefusedBeforeSpawn,
    SpawnFailed,
    Exited { code: Option<i32>, success: bool },
    KilledAfterTimeout { code: Option<i32> },
    KilledAfterTransportSetupFailure { code: Option<i32> },
}

impl From<&DirectChildOutcome> for CanonicalDirectChildOutcome {
    fn from(outcome: &DirectChildOutcome) -> Self {
        match outcome {
            DirectChildOutcome::LaunchRefusedBeforeSpawn => Self::LaunchRefusedBeforeSpawn,
            DirectChildOutcome::SpawnFailed => Self::SpawnFailed,
            DirectChildOutcome::Exited { code, success } => Self::Exited {
                code: *code,
                success: *success,
            },
            DirectChildOutcome::KilledAfterTimeout { code } => {
                Self::KilledAfterTimeout { code: *code }
            }
            DirectChildOutcome::KilledAfterTransportSetupFailure { code } => {
                Self::KilledAfterTransportSetupFailure { code: *code }
            }
            DirectChildOutcome::NativeChildStateUnknown | DirectChildOutcome::WaitFailed { .. } => {
                unreachable!("ambiguous direct-child outcomes are rejected before encoding")
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCommandDomainProof {
    backend: CommandDomainCleanupBackend,
    runner_session_id: String,
    command_effect_id: String,
    command_request_digest: Digest,
    os_evidence_digest: Digest,
    os_evidence_bytes: Vec<u8>,
}

#[derive(Serialize)]
struct CanonicalExpectedDomainSet<'a> {
    schema_version: u32,
    runner_session_id: &'a str,
    backend: CommandDomainCleanupBackend,
    bindings: Vec<CanonicalExpectedBinding<'a>>,
}

#[derive(Serialize)]
struct CanonicalExpectedBinding<'a> {
    command_effect_id: &'a str,
    command_request_digest: &'a Digest,
}

struct ValidatedContext {
    disposition: RunnerLaunchCleanupDisposition,
    backend: Option<CommandDomainCleanupBackend>,
    expected_domain_set_digest: Digest,
}

fn validate_authoritative_context(
    launch: &RunnerLaunchIntent,
    session: Option<&RunnerSessionPolicyRecord>,
    cleanup_required: &RunnerCleanupRequired,
    expected_set: Option<&ExpectedCommandDomainCleanupSet>,
) -> Result<ValidatedContext, RunnerLaunchCleanupEvidenceError> {
    launch
        .validate()
        .map_err(|_| RunnerLaunchCleanupEvidenceError::InvalidContract {
            field: "runner_launch_intent",
        })?;
    if launch.purpose == RunnerSessionPurpose::Applier {
        return Err(RunnerLaunchCleanupEvidenceError::TrustedApplierUnsupported);
    }
    if cleanup_required.launch() != launch {
        return Err(RunnerLaunchCleanupEvidenceError::HandoffLaunchMismatch);
    }
    if cleanup_required.session() != session {
        return Err(RunnerLaunchCleanupEvidenceError::HandoffSessionMismatch);
    }

    if let Some(session) = session {
        session
            .validate()
            .map_err(|_| RunnerLaunchCleanupEvidenceError::InvalidContract {
                field: "runner_session_policy",
            })?;
        validate_launch_session_binding(launch, session)?;
    }

    let disposition = match cleanup_required.direct_child_outcome() {
        DirectChildOutcome::NativeChildStateUnknown | DirectChildOutcome::WaitFailed { .. } => {
            return Err(RunnerLaunchCleanupEvidenceError::AmbiguousDirectChild);
        }
        DirectChildOutcome::LaunchRefusedBeforeSpawn => {
            if session.is_some() || cleanup_required.shutdown_prepared().is_some() {
                return Err(RunnerLaunchCleanupEvidenceError::InvalidDirectChildState);
            }
            RunnerLaunchCleanupDisposition::RefusedBeforeSpawnNoCommands
        }
        DirectChildOutcome::SpawnFailed => {
            if session.is_some() || cleanup_required.shutdown_prepared().is_some() {
                return Err(RunnerLaunchCleanupEvidenceError::InvalidDirectChildState);
            }
            RunnerLaunchCleanupDisposition::SpawnFailedNoCommands
        }
        DirectChildOutcome::KilledAfterTransportSetupFailure { .. } => {
            if session.is_some() || cleanup_required.shutdown_prepared().is_some() {
                return Err(RunnerLaunchCleanupEvidenceError::InvalidDirectChildState);
            }
            RunnerLaunchCleanupDisposition::ReapedUnregisteredChildNoCommands
        }
        DirectChildOutcome::Exited { .. } | DirectChildOutcome::KilledAfterTimeout { .. } => {
            if session.is_some() {
                RunnerLaunchCleanupDisposition::ReapedRegisteredSession
            } else {
                if cleanup_required.shutdown_prepared().is_some() {
                    return Err(RunnerLaunchCleanupEvidenceError::InvalidShutdownAcknowledgement);
                }
                RunnerLaunchCleanupDisposition::ReapedUnregisteredChildNoCommands
            }
        }
    };

    let (backend, expected_domain_set_digest) = match (session, expected_set) {
        (Some(session), Some(expected_set)) => {
            if expected_set.runner_session_id() != session.session_id {
                return Err(RunnerLaunchCleanupEvidenceError::ExpectedSetSessionMismatch);
            }
            if let Some(acknowledgement) = cleanup_required.shutdown_prepared() {
                validate_shutdown_acknowledgement(
                    acknowledgement,
                    session,
                    expected_set.bindings().len(),
                )?;
            }
            (
                Some(expected_set.backend()),
                expected_set.set_digest().clone(),
            )
        }
        (Some(_), None) => {
            return Err(RunnerLaunchCleanupEvidenceError::MissingExpectedCommandSet);
        }
        (None, Some(_)) => {
            return Err(RunnerLaunchCleanupEvidenceError::UnexpectedExpectedCommandSet);
        }
        (None, None) => (None, no_registered_session_set_digest(&launch.session_id)),
    };

    Ok(ValidatedContext {
        disposition,
        backend,
        expected_domain_set_digest,
    })
}

fn validate_launch_session_binding(
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), RunnerLaunchCleanupEvidenceError> {
    if session.contract_version != launch.contract_version
        || session.sprint_id != launch.sprint_id
        || session.launch_id != launch.launch_id
        || session.session_id != launch.session_id
        || session.purpose != launch.purpose
        || session.worker_id != launch.worker_id
        || session.worker_lease != launch.worker_lease
        || session.policy_hash != launch.policy_hash
        || session.runner_binary_digest != launch.runner_binary_digest
        || session.protocol_digest != launch.protocol_digest
        || session.private_state_digest != launch.private_state_digest
        || session.grant_hash != launch.grant_hash
        || session.policy_version != launch.policy_version
        || session.registered_at_unix_ms < launch.created_at_unix_ms
    {
        return Err(RunnerLaunchCleanupEvidenceError::LaunchSessionMismatch);
    }
    Ok(())
}

fn validate_shutdown_acknowledgement(
    acknowledgement: &ShutdownPreparedAcknowledgement,
    session: &RunnerSessionPolicyRecord,
    expected_command_count: usize,
) -> Result<(), RunnerLaunchCleanupEvidenceError> {
    let expected_role = match session.purpose {
        RunnerSessionPurpose::TaskWorker => RunnerRole::Worker,
        RunnerSessionPurpose::FinalVerifier => RunnerRole::FinalVerifier,
        RunnerSessionPurpose::LiveStateVerifier => RunnerRole::LiveStateVerifier,
        RunnerSessionPurpose::Applier => {
            return Err(RunnerLaunchCleanupEvidenceError::TrustedApplierUnsupported);
        }
    };
    let expected_command_count = u64::try_from(expected_command_count)
        .map_err(|_| RunnerLaunchCleanupEvidenceError::InvalidShutdownAcknowledgement)?;
    let minimum_request_count = expected_command_count
        .checked_add(2)
        .ok_or(RunnerLaunchCleanupEvidenceError::InvalidShutdownAcknowledgement)?;
    if acknowledgement.session_id != session.session_id
        || acknowledgement.runner_nonce != session.session_nonce
        || acknowledgement.role != expected_role
        || acknowledgement.accepted_request_count < minimum_request_count
        || acknowledgement.command_effects_admitted != expected_command_count
        || acknowledgement.command_effects_admitted
            > acknowledgement.accepted_request_count.saturating_sub(2)
        || (matches!(
            expected_role,
            RunnerRole::Applier | RunnerRole::LiveStateVerifier
        ) && acknowledgement.command_effects_admitted != 0)
        || !acknowledgement.runner_exit_pending
        || acknowledgement.state_disposition != WireStateDisposition::Unproven
        || (expected_role == RunnerRole::FinalVerifier && !acknowledgement.private_shadow_present)
        || acknowledgement.acknowledgement_digest
            != shutdown_acknowledgement_digest(acknowledgement)
    {
        return Err(RunnerLaunchCleanupEvidenceError::InvalidShutdownAcknowledgement);
    }
    Ok(())
}

fn shutdown_acknowledgement_digest(acknowledgement: &ShutdownPreparedAcknowledgement) -> Digest {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SHUTDOWN_ACK_PREFIX);
    preimage.extend_from_slice(
        &u64::try_from(acknowledgement.session_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    preimage.extend_from_slice(acknowledgement.session_id.as_bytes());
    preimage.extend_from_slice(acknowledgement.runner_nonce.as_str().as_bytes());
    preimage.push(match acknowledgement.role {
        RunnerRole::Worker => 0,
        RunnerRole::FinalVerifier => 1,
        RunnerRole::Applier => 2,
        RunnerRole::LiveStateVerifier => 3,
    });
    preimage.extend_from_slice(&acknowledgement.accepted_request_count.to_be_bytes());
    preimage.extend_from_slice(&acknowledgement.command_effects_admitted.to_be_bytes());
    preimage.push(u8::from(acknowledgement.runner_exit_pending));
    preimage.push(u8::from(acknowledgement.private_shadow_present));
    preimage.push(match acknowledgement.state_disposition {
        WireStateDisposition::Unproven => 0,
    });
    Digest::sha256(&preimage)
}

fn canonicalize_command_proofs(
    expected_set: Option<&ExpectedCommandDomainCleanupSet>,
    proofs: &[ValidatedCommandDomainCleanupProof],
) -> Result<Vec<CanonicalCommandDomainProof>, RunnerLaunchCleanupEvidenceError> {
    let Some(expected_set) = expected_set else {
        if let Some(proof) = proofs.first() {
            return Err(RunnerLaunchCleanupEvidenceError::ExtraCommandDomainProof {
                effect_id: proof.binding().command_effect_id().to_owned(),
            });
        }
        return Ok(Vec::new());
    };
    if proofs.len() > MAX_RUNNER_LAUNCH_COMMAND_DOMAINS {
        return Err(RunnerLaunchCleanupEvidenceError::TooManyCommandDomains {
            count: proofs.len(),
        });
    }
    let expected_by_effect: BTreeMap<&str, &CommandDomainCleanupBinding> = expected_set
        .bindings()
        .iter()
        .map(|binding| (binding.command_effect_id(), binding))
        .collect();
    let mut proof_by_effect = BTreeMap::new();
    for proof in proofs {
        proof
            .validate()
            .map_err(RunnerLaunchCleanupEvidenceError::CommandDomainProof)?;
        if proof.binding().runner_session_id() != expected_set.runner_session_id() {
            return Err(RunnerLaunchCleanupEvidenceError::CommandDomainSessionMismatch);
        }
        if proof.backend() != expected_set.backend() {
            return Err(RunnerLaunchCleanupEvidenceError::CommandDomainBackendMismatch);
        }
        let effect_id = proof.binding().command_effect_id();
        let Some(expected_binding) = expected_by_effect.get(effect_id) else {
            return Err(RunnerLaunchCleanupEvidenceError::ExtraCommandDomainProof {
                effect_id: effect_id.to_owned(),
            });
        };
        if proof.binding() != *expected_binding {
            return Err(RunnerLaunchCleanupEvidenceError::CommandDomainRequestMismatch);
        }
        if proof_by_effect.insert(effect_id, proof).is_some() {
            return Err(
                RunnerLaunchCleanupEvidenceError::DuplicateCommandDomainProof {
                    effect_id: effect_id.to_owned(),
                },
            );
        }
    }

    let mut canonical = Vec::with_capacity(expected_set.bindings().len());
    for expected in expected_set.bindings() {
        let Some(proof) = proof_by_effect.get(expected.command_effect_id()) else {
            return Err(
                RunnerLaunchCleanupEvidenceError::MissingCommandDomainProof {
                    effect_id: expected.command_effect_id().to_owned(),
                },
            );
        };
        canonical.push(CanonicalCommandDomainProof {
            backend: proof.backend(),
            runner_session_id: proof.binding().runner_session_id().to_owned(),
            command_effect_id: proof.binding().command_effect_id().to_owned(),
            command_request_digest: proof.binding().command_request_digest().clone(),
            os_evidence_digest: proof.os_evidence_digest().clone(),
            os_evidence_bytes: proof.os_evidence_bytes().to_vec(),
        });
    }
    Ok(canonical)
}

fn expected_set_digest(
    runner_session_id: &str,
    backend: CommandDomainCleanupBackend,
    bindings: &[CommandDomainCleanupBinding],
) -> Result<Digest, RunnerLaunchCleanupEvidenceError> {
    let payload = CanonicalExpectedDomainSet {
        schema_version: RUNNER_LAUNCH_CLEANUP_VERSION,
        runner_session_id,
        backend,
        bindings: bindings
            .iter()
            .map(|binding| CanonicalExpectedBinding {
                command_effect_id: binding.command_effect_id(),
                command_request_digest: binding.command_request_digest(),
            })
            .collect(),
    };
    let canonical =
        serde_json::to_vec(&payload).map_err(|_| RunnerLaunchCleanupEvidenceError::Encoding)?;
    let total = EXPECTED_DOMAIN_SET_PREFIX
        .len()
        .checked_add(canonical.len())
        .ok_or(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge { bytes: usize::MAX })?;
    if total > MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES {
        return Err(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge { bytes: total });
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(EXPECTED_DOMAIN_SET_PREFIX);
    bytes.extend_from_slice(&canonical);
    Ok(Digest::sha256(&bytes))
}

fn no_registered_session_set_digest(session_id: &str) -> Digest {
    let mut bytes = Vec::with_capacity(NO_REGISTERED_SESSION_SET_PREFIX.len() + session_id.len());
    bytes.extend_from_slice(NO_REGISTERED_SESSION_SET_PREFIX);
    bytes.extend_from_slice(session_id.as_bytes());
    Digest::sha256(&bytes)
}

fn encode_payload(
    payload: &CanonicalRunnerLaunchCleanup,
) -> Result<Vec<u8>, RunnerLaunchCleanupEvidenceError> {
    let canonical =
        serde_json::to_vec(payload).map_err(|_| RunnerLaunchCleanupEvidenceError::Encoding)?;
    let total = RUNNER_LAUNCH_CLEANUP_PREFIX
        .len()
        .checked_add(canonical.len())
        .ok_or(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge { bytes: usize::MAX })?;
    if total > MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES {
        return Err(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge { bytes: total });
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(RUNNER_LAUNCH_CLEANUP_PREFIX);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), RunnerLaunchCleanupEvidenceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(RunnerLaunchCleanupEvidenceError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_evidence_length(bytes: &[u8]) -> Result<(), RunnerLaunchCleanupEvidenceError> {
    if bytes.is_empty() {
        return Err(RunnerLaunchCleanupEvidenceError::EmptyEvidence);
    }
    if bytes.len() > MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES {
        return Err(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge { bytes: bytes.len() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use grok_build_core::{CONTRACT_VERSION, CommandSpec, PathScope, WorkerLease};

    fn digest(marker: u8) -> Digest {
        Digest::sha256(&[marker])
    }

    fn launch(purpose: RunnerSessionPurpose) -> RunnerLaunchIntent {
        let worker_id =
            (purpose == RunnerSessionPurpose::TaskWorker).then(|| "worker-cleanup-1".to_owned());
        let worker_lease = worker_id.as_ref().map(|worker_id| {
            WorkerLease::new(
                "sprint-cleanup-1".into(),
                1,
                "task-cleanup-1".into(),
                worker_id.clone(),
                vec![PathScope::Workspace],
                99,
            )
            .expect("construct canonical cleanup worker lease")
        });
        RunnerLaunchIntent {
            contract_version: CONTRACT_VERSION,
            launch_id: "launch-cleanup-1".into(),
            sprint_id: "sprint-cleanup-1".into(),
            session_id: "runner-session-macos-1".into(),
            purpose,
            worker_id,
            worker_lease,
            policy_hash: digest(1),
            runner_binary_digest: digest(2),
            protocol_digest: digest(3),
            private_state_digest: digest(4),
            grant_hash: digest(5),
            policy_version: 1,
            created_at_unix_ms: 100,
        }
    }

    fn session(launch: &RunnerLaunchIntent) -> RunnerSessionPolicyRecord {
        RunnerSessionPolicyRecord {
            contract_version: launch.contract_version,
            sprint_id: launch.sprint_id.clone(),
            launch_id: launch.launch_id.clone(),
            session_id: launch.session_id.clone(),
            purpose: launch.purpose,
            worker_id: launch.worker_id.clone(),
            worker_lease: launch.worker_lease.clone(),
            policy_hash: launch.policy_hash.clone(),
            session_nonce: digest(6),
            runner_binary_digest: launch.runner_binary_digest.clone(),
            protocol_digest: launch.protocol_digest.clone(),
            private_state_digest: launch.private_state_digest.clone(),
            grant_hash: launch.grant_hash.clone(),
            policy_version: launch.policy_version,
            registered_at_unix_ms: 101,
        }
    }

    fn handoff(
        launch: RunnerLaunchIntent,
        session: Option<RunnerSessionPolicyRecord>,
        direct_child: DirectChildOutcome,
        acknowledgement: Option<ShutdownPreparedAcknowledgement>,
    ) -> RunnerCleanupRequired {
        crate::runner_client::runner_cleanup_required_for_test(
            launch,
            session,
            direct_child,
            acknowledgement,
        )
    }

    fn expected_set(
        session_id: &str,
        binding: CommandDomainCleanupBinding,
    ) -> ExpectedCommandDomainCleanupSet {
        ExpectedCommandDomainCleanupSet::try_new(
            session_id,
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            vec![binding],
        )
        .expect("valid expected command set")
    }

    #[derive(Serialize)]
    struct TestObservationDigest<'a> {
        sequence: u32,
        observed_at_unix_ms: u64,
        uid: u32,
        process_ids: &'a [u32],
        creation_sealed: bool,
    }

    #[derive(Serialize)]
    struct TestObservation {
        sequence: u32,
        observed_at_unix_ms: u64,
        uid: u32,
        process_ids: Vec<u32>,
        enumeration_digest: Digest,
        creation_sealed: bool,
    }

    fn observation(sequence: u32, time: u64, process_ids: Vec<u32>) -> TestObservation {
        let canonical = serde_json::to_vec(&TestObservationDigest {
            sequence,
            observed_at_unix_ms: time,
            uid: 601,
            process_ids: &process_ids,
            creation_sealed: true,
        })
        .expect("observation preimage");
        let mut bytes = b"grok-build.macos-process-observation.v1\0".to_vec();
        bytes.extend_from_slice(&canonical);
        TestObservation {
            sequence,
            observed_at_unix_ms: time,
            uid: 601,
            process_ids,
            enumeration_digest: Digest::sha256(&bytes),
            creation_sealed: true,
        }
    }

    #[derive(Clone, Serialize)]
    struct TestAssignedIdentity {
        account_name: String,
        uid: u32,
        gid: u32,
        account_record_digest: Digest,
    }

    #[derive(Clone, Copy, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum TestMacosNetwork {
        Denied,
    }

    #[derive(Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestPreparationBinding {
        contract_version: u32,
        attempt_id: String,
        sprint_id: String,
        launch_id: String,
        runner_session_id: String,
        cleanup_effect_id: String,
        input_snapshot: Digest,
        native_journal_id: String,
        expected_platform_binding_digest: Digest,
        claimed_at_unix_ms: u64,
    }

    #[derive(Clone, Copy, Serialize)]
    #[serde(rename_all = "snake_case")]
    enum TestDescriptorPurpose {
        StandardInput,
        StandardOutput,
        StandardError,
        HoldControl,
        SetupReport,
    }

    #[derive(Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestDescriptorBinding {
        target_fd: u32,
        purpose: TestDescriptorPurpose,
        object_digest: Digest,
        inherited_through_exec: bool,
    }

    #[derive(Clone, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "snake_case", tag = "source")]
    enum TestExecutableIdentity {
        SystemToolchain {
            policy_entry_id: String,
            binary_digest: Digest,
        },
    }

    /// Mirror of the runner's `MacosHelperInstallAudit`.
    #[derive(Clone, Copy, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestMacosInstallAudit {
        auditing_uid: u32,
        binary_owner_uid: u32,
        binary_mode: u32,
        directory_owner_uid: u32,
        directory_mode: u32,
    }

    /// Mirror of the runner's `MacosHelperAttestation`.
    ///
    /// Only the kind this fixture exercises is spelled out; the enum is
    /// internally tagged, so the canonical bytes are
    /// `{"kind":"local_code_identity","install_audit":{…}}`.
    #[derive(Clone, Copy, Serialize)]
    #[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
    enum TestMacosAttestation {
        LocalCodeIdentity {
            install_audit: TestMacosInstallAudit,
        },
    }

    #[derive(Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestMacosSession {
        protocol_version: u32,
        policy_version: u32,
        session_nonce: Digest,
        helper_binary_digest: Digest,
        helper_requirement_digest: Digest,
        client_binary_digest: Digest,
        client_requirement_digest: Digest,
        pool_record_digest: Digest,
        workspace_grant_hash: Digest,
        execution_policy_hash: Digest,
        command_network: TestMacosNetwork,
        authenticated_at_unix_ms: u64,
        peer_requirement_matched: bool,
        attestation: TestMacosAttestation,
    }

    #[derive(Clone, Serialize)]
    #[serde(deny_unknown_fields)]
    struct TestMacosLaunchRequest {
        protocol_version: u32,
        policy_version: u32,
        session_nonce: Digest,
        request_id: String,
        preparation: TestPreparationBinding,
        runner_session_id: String,
        effect_id: String,
        workspace_grant_hash: Digest,
        execution_policy_hash: Digest,
        staged_workspace_id: String,
        executable_identity: TestExecutableIdentity,
        descriptor_bindings: Vec<TestDescriptorBinding>,
        argv: Vec<String>,
        relative_working_directory: String,
        environment: BTreeMap<String, String>,
        deadline_unix_ms: u64,
        max_output_bytes: u64,
        max_processes: u32,
        max_memory_bytes: Option<u64>,
        command_network: TestMacosNetwork,
        seatbelt_profile_digest: Digest,
        request_digest: Digest,
    }

    #[derive(Serialize)]
    struct TestRequestDigestPreimage<'a> {
        protocol_version: u32,
        policy_version: u32,
        session_nonce: &'a Digest,
        request_id: &'a str,
        preparation: &'a TestPreparationBinding,
        runner_session_id: &'a str,
        effect_id: &'a str,
        workspace_grant_hash: &'a Digest,
        execution_policy_hash: &'a Digest,
        staged_workspace_id: &'a str,
        executable_identity: &'a TestExecutableIdentity,
        descriptor_bindings: &'a [TestDescriptorBinding],
        argv: &'a [String],
        relative_working_directory: &'a str,
        environment: &'a BTreeMap<String, String>,
        deadline_unix_ms: u64,
        max_output_bytes: u64,
        max_processes: u32,
        max_memory_bytes: Option<u64>,
        command_network: TestMacosNetwork,
        seatbelt_profile_digest: &'a Digest,
    }

    fn test_request_digest(request: &TestMacosLaunchRequest) -> Digest {
        let preimage = TestRequestDigestPreimage {
            protocol_version: request.protocol_version,
            policy_version: request.policy_version,
            session_nonce: &request.session_nonce,
            request_id: &request.request_id,
            preparation: &request.preparation,
            runner_session_id: &request.runner_session_id,
            effect_id: &request.effect_id,
            workspace_grant_hash: &request.workspace_grant_hash,
            execution_policy_hash: &request.execution_policy_hash,
            staged_workspace_id: &request.staged_workspace_id,
            executable_identity: &request.executable_identity,
            descriptor_bindings: &request.descriptor_bindings,
            argv: &request.argv,
            relative_working_directory: &request.relative_working_directory,
            environment: &request.environment,
            deadline_unix_ms: request.deadline_unix_ms,
            max_output_bytes: request.max_output_bytes,
            max_processes: request.max_processes,
            max_memory_bytes: request.max_memory_bytes,
            command_network: request.command_network,
            seatbelt_profile_digest: &request.seatbelt_profile_digest,
        };
        let canonical = serde_json::to_vec(&preimage).expect("macOS request digest preimage");
        let mut bytes = b"grok-build.macos-helper-launch.v2\0".to_vec();
        bytes.extend_from_slice(&canonical);
        Digest::sha256(&bytes)
    }

    fn test_preparation_binding(session_id: &str) -> TestPreparationBinding {
        TestPreparationBinding {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-macos-1".into(),
            sprint_id: "sprint-macos-1".into(),
            launch_id: "launch-macos-1".into(),
            runner_session_id: session_id.into(),
            cleanup_effect_id: "cleanup-effect-macos-1".into(),
            input_snapshot: digest(14),
            native_journal_id: "native-journal-macos-1".into(),
            expected_platform_binding_digest: digest(15),
            claimed_at_unix_ms: 900,
        }
    }

    fn test_macos_session() -> TestMacosSession {
        TestMacosSession {
            protocol_version: 2,
            policy_version: 1,
            session_nonce: digest(16),
            helper_binary_digest: digest(26),
            helper_requirement_digest: digest(27),
            client_binary_digest: digest(28),
            client_requirement_digest: digest(29),
            pool_record_digest: digest(30),
            workspace_grant_hash: digest(17),
            execution_policy_hash: digest(18),
            command_network: TestMacosNetwork::Denied,
            authenticated_at_unix_ms: 800,
            peer_requirement_matched: true,
            attestation: TestMacosAttestation::LocalCodeIdentity {
                install_audit: TestMacosInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            },
        }
    }

    fn test_macos_request(
        preparation: TestPreparationBinding,
        session: &TestMacosSession,
        effect_id: &str,
    ) -> TestMacosLaunchRequest {
        let mut request = TestMacosLaunchRequest {
            protocol_version: session.protocol_version,
            policy_version: session.policy_version,
            session_nonce: session.session_nonce.clone(),
            request_id: "request-macos-1".into(),
            runner_session_id: preparation.runner_session_id.clone(),
            preparation,
            effect_id: effect_id.into(),
            workspace_grant_hash: session.workspace_grant_hash.clone(),
            execution_policy_hash: session.execution_policy_hash.clone(),
            staged_workspace_id: "shadow-macos-1".into(),
            executable_identity: TestExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(19),
            },
            descriptor_bindings: vec![
                TestDescriptorBinding {
                    target_fd: 0,
                    purpose: TestDescriptorPurpose::StandardInput,
                    object_digest: digest(20),
                    inherited_through_exec: true,
                },
                TestDescriptorBinding {
                    target_fd: 1,
                    purpose: TestDescriptorPurpose::StandardOutput,
                    object_digest: digest(21),
                    inherited_through_exec: true,
                },
                TestDescriptorBinding {
                    target_fd: 2,
                    purpose: TestDescriptorPurpose::StandardError,
                    object_digest: digest(22),
                    inherited_through_exec: true,
                },
                TestDescriptorBinding {
                    target_fd: 3,
                    purpose: TestDescriptorPurpose::HoldControl,
                    object_digest: digest(23),
                    inherited_through_exec: false,
                },
                TestDescriptorBinding {
                    target_fd: 4,
                    purpose: TestDescriptorPurpose::SetupReport,
                    object_digest: digest(24),
                    inherited_through_exec: false,
                },
            ],
            argv: vec!["cargo".into(), "test".into()],
            relative_working_directory: ".".into(),
            environment: BTreeMap::new(),
            deadline_unix_ms: 2_000,
            max_output_bytes: 1_024,
            max_processes: 8,
            max_memory_bytes: None,
            command_network: TestMacosNetwork::Denied,
            seatbelt_profile_digest: digest(25),
            request_digest: digest(0),
        };
        request.request_digest = test_request_digest(&request);
        request
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum TestJournalState {
        Cleaned,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum TestTerminationReason {
        Exited,
    }

    #[derive(Serialize)]
    struct TestJournal {
        state: TestJournalState,
        admission_session: TestMacosSession,
        request: TestMacosLaunchRequest,
        assigned_identity: Option<TestAssignedIdentity>,
        cleanup_agent_digest: Option<Digest>,
        held_preparation_evidence: Option<()>,
        release_authorization: Option<()>,
        release_evidence: Option<()>,
        termination_reason: Option<TestTerminationReason>,
        observations: Vec<TestObservation>,
        identity_released: bool,
    }

    #[derive(Serialize)]
    struct TestMacosEvidence {
        journal_record: TestJournal,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
    enum TestPlatformEvidence {
        MacOsDedicatedIdentity(TestMacosEvidence),
    }

    #[derive(Serialize)]
    struct TestBinding {
        runner_session_id: String,
        command_effect_id: String,
        command_request_digest: Digest,
    }

    #[derive(Serialize)]
    struct TestDomainPayload {
        schema_version: u32,
        backend: CommandDomainCleanupBackend,
        binding: TestBinding,
        surviving_processes: u64,
        platform_evidence: TestPlatformEvidence,
    }

    fn command_proof() -> ValidatedCommandDomainCleanupProof {
        let session_id = "runner-session-macos-1";
        let effect_id = "command-effect-macos-1";
        let admission_session = test_macos_session();
        let request = test_macos_request(
            test_preparation_binding(session_id),
            &admission_session,
            effect_id,
        );
        let helper_request_digest = request.request_digest.clone();
        let canonical_command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: std::path::PathBuf::new(),
        };
        canonical_command
            .validate()
            .expect("fixture command is canonical");
        let command_request_digest = Digest::sha256(
            &serde_json::to_vec(&canonical_command).expect("canonical Core command"),
        );
        assert_ne!(
            command_request_digest, helper_request_digest,
            "the outer Core command identity remains distinct from the signed-helper request identity"
        );
        let payload = TestDomainPayload {
            schema_version: 1,
            backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            binding: TestBinding {
                runner_session_id: session_id.into(),
                command_effect_id: effect_id.into(),
                command_request_digest: command_request_digest.clone(),
            },
            surviving_processes: 0,
            platform_evidence: TestPlatformEvidence::MacOsDedicatedIdentity(TestMacosEvidence {
                journal_record: TestJournal {
                    state: TestJournalState::Cleaned,
                    admission_session,
                    request,
                    assigned_identity: Some(TestAssignedIdentity {
                        account_name: "_grokbuild601".into(),
                        uid: 601,
                        gid: 601,
                        account_record_digest: digest(10),
                    }),
                    cleanup_agent_digest: Some(digest(12)),
                    held_preparation_evidence: None,
                    release_authorization: None,
                    release_evidence: None,
                    termination_reason: Some(TestTerminationReason::Exited),
                    observations: vec![
                        observation(1, 1_000, vec![71]),
                        observation(2, 1_001, Vec::new()),
                        observation(3, 1_002, Vec::new()),
                    ],
                    identity_released: true,
                },
            }),
        };
        let canonical = serde_json::to_vec(&payload).expect("test proof payload");
        let mut bytes = b"grok-build.runner-command-domain-cleanup-proof.v1\0".to_vec();
        bytes.extend_from_slice(&canonical);
        let binding =
            CommandDomainCleanupBinding::try_new(session_id, effect_id, command_request_digest)
                .expect("valid proof binding");
        ValidatedCommandDomainCleanupProof::readback(
            &bytes,
            &Digest::sha256(&bytes),
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            &binding,
        )
        .expect("fixture is native-valid macOS proof")
    }

    fn registered_fixture() -> (
        RunnerLaunchIntent,
        RunnerSessionPolicyRecord,
        RunnerCleanupRequired,
        ExpectedCommandDomainCleanupSet,
        ValidatedCommandDomainCleanupProof,
    ) {
        let launch = launch(RunnerSessionPurpose::TaskWorker);
        let session = session(&launch);
        let proof = command_proof();
        let expected = expected_set(&session.session_id, proof.binding().clone());
        let cleanup = handoff(
            launch.clone(),
            Some(session.clone()),
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            },
            None,
        );
        (launch, session, cleanup, expected, proof)
    }

    #[test]
    fn exact_registered_launch_set_becomes_canonical_and_reopens() {
        let (launch, session, cleanup, expected, proof) = registered_fixture();
        let aggregate = adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
            ledger_launch: &launch,
            ledger_session: Some(&session),
            cleanup_required: &cleanup,
            expected_command_domains: Some(&expected),
            command_domain_proofs: std::slice::from_ref(&proof),
        })
        .expect("exact launch cleanup aggregate");

        assert_eq!(aggregate.launch(), &launch);
        assert_eq!(aggregate.session(), Some(&session));
        assert_eq!(aggregate.command_domain_count(), 1);
        assert_eq!(aggregate.backend(), Some(expected.backend()));
        assert_eq!(
            aggregate.expected_domain_set_digest(),
            expected.set_digest()
        );
        assert_eq!(
            aggregate.disposition(),
            RunnerLaunchCleanupDisposition::ReapedRegisteredSession
        );
        assert_eq!(
            &Digest::sha256(aggregate.evidence_bytes()),
            aggregate.evidence_digest()
        );

        let reopened = ValidatedRunnerLaunchCleanupEvidence::readback(
            aggregate.evidence_bytes(),
            aggregate.evidence_digest(),
            &launch,
            Some(&session),
            &cleanup,
            Some(&expected),
        )
        .expect("exact aggregate reopens");
        assert_eq!(reopened, aggregate);
    }

    #[test]
    fn pre_spawn_refusal_is_distinct_and_requires_no_commands() {
        let launch = launch(RunnerSessionPurpose::FinalVerifier);
        let cleanup = handoff(
            launch.clone(),
            None,
            DirectChildOutcome::LaunchRefusedBeforeSpawn,
            None,
        );
        let aggregate = adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
            ledger_launch: &launch,
            ledger_session: None,
            cleanup_required: &cleanup,
            expected_command_domains: None,
            command_domain_proofs: &[],
        })
        .expect("provable pre-spawn refusal");
        assert_eq!(
            aggregate.disposition(),
            RunnerLaunchCleanupDisposition::RefusedBeforeSpawnNoCommands
        );
        assert_eq!(aggregate.backend(), None);
        assert_eq!(aggregate.command_domain_count(), 0);
    }

    #[test]
    fn missing_extra_and_duplicate_proofs_fail_closed() {
        let (launch, session, cleanup, expected, proof) = registered_fixture();
        let base = |proofs: &[ValidatedCommandDomainCleanupProof]| {
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&expected),
                command_domain_proofs: proofs,
            })
        };
        assert!(matches!(
            base(&[]),
            Err(RunnerLaunchCleanupEvidenceError::MissingCommandDomainProof { .. })
        ));
        assert!(matches!(
            base(&[proof.clone(), proof.clone()]),
            Err(RunnerLaunchCleanupEvidenceError::DuplicateCommandDomainProof { .. })
        ));

        let empty = ExpectedCommandDomainCleanupSet::try_new(
            &session.session_id,
            expected.backend(),
            Vec::new(),
        )
        .expect("empty canonical set");
        assert!(matches!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&empty),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::ExtraCommandDomainProof { .. })
        ));
    }

    #[test]
    fn backend_session_and_request_substitution_fail_closed() {
        let (launch, session, cleanup, _expected, proof) = registered_fixture();
        let linux = ExpectedCommandDomainCleanupSet::try_new(
            &session.session_id,
            CommandDomainCleanupBackend::LinuxCgroupV2,
            vec![proof.binding().clone()],
        )
        .expect("canonical alternate backend set");
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&linux),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::CommandDomainBackendMismatch)
        );

        let wrong_request = CommandDomainCleanupBinding::try_new(
            &session.session_id,
            proof.binding().command_effect_id(),
            digest(99),
        )
        .expect("valid substituted request binding");
        let wrong_request_set = expected_set(&session.session_id, wrong_request);
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&wrong_request_set),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::CommandDomainRequestMismatch)
        );

        let wrong_session_binding = CommandDomainCleanupBinding::try_new(
            "other-runner-session",
            proof.binding().command_effect_id(),
            proof.binding().command_request_digest().clone(),
        )
        .expect("valid other-session binding");
        assert!(matches!(
            ExpectedCommandDomainCleanupSet::try_new(
                &session.session_id,
                expected_set(&session.session_id, proof.binding().clone()).backend(),
                vec![wrong_session_binding],
            ),
            Err(RunnerLaunchCleanupEvidenceError::ExpectedSetSessionMismatch)
        ));
    }

    #[test]
    fn wrong_launch_session_and_ambiguous_direct_child_are_rejected() {
        let (launch, session, cleanup, expected, proof) = registered_fixture();
        let mut wrong_launch = launch.clone();
        wrong_launch.grant_hash = digest(88);
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &wrong_launch,
                ledger_session: Some(&session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&expected),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::HandoffLaunchMismatch)
        );

        let mut wrong_session = session.clone();
        wrong_session.policy_hash = digest(87);
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&wrong_session),
                cleanup_required: &cleanup,
                expected_command_domains: Some(&expected),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::HandoffSessionMismatch)
        );

        let ambiguous = handoff(
            launch.clone(),
            Some(session.clone()),
            DirectChildOutcome::WaitFailed {
                message: "ambiguous wait".into(),
            },
            None,
        );
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: Some(&session),
                cleanup_required: &ambiguous,
                expected_command_domains: Some(&expected),
                command_domain_proofs: std::slice::from_ref(&proof),
            }),
            Err(RunnerLaunchCleanupEvidenceError::AmbiguousDirectChild)
        );

        let native_unknown = handoff(
            launch.clone(),
            None,
            DirectChildOutcome::NativeChildStateUnknown,
            None,
        );
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &launch,
                ledger_session: None,
                cleanup_required: &native_unknown,
                expected_command_domains: None,
                command_domain_proofs: &[],
            }),
            Err(RunnerLaunchCleanupEvidenceError::AmbiguousDirectChild)
        );
    }

    #[test]
    fn truncation_and_authority_readback_substitution_are_rejected() {
        let (launch, session, cleanup, expected, proof) = registered_fixture();
        let aggregate = adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
            ledger_launch: &launch,
            ledger_session: Some(&session),
            cleanup_required: &cleanup,
            expected_command_domains: Some(&expected),
            command_domain_proofs: std::slice::from_ref(&proof),
        })
        .expect("aggregate");
        let mut truncated = aggregate.evidence_bytes().to_vec();
        truncated.pop();
        assert_eq!(
            ValidatedRunnerLaunchCleanupEvidence::readback(
                &truncated,
                aggregate.evidence_digest(),
                &launch,
                Some(&session),
                &cleanup,
                Some(&expected),
            ),
            Err(RunnerLaunchCleanupEvidenceError::DigestMismatch)
        );
        assert!(matches!(
            ValidatedRunnerLaunchCleanupEvidence::readback(
                &truncated,
                &Digest::sha256(&truncated),
                &launch,
                Some(&session),
                &cleanup,
                Some(&expected),
            ),
            Err(RunnerLaunchCleanupEvidenceError::Decoding
                | RunnerLaunchCleanupEvidenceError::NonCanonical)
        ));

        let mut substituted_launch = launch.clone();
        substituted_launch.launch_id = "other-launch".into();
        let substituted_handoff = handoff(
            substituted_launch.clone(),
            Some({
                let mut value = session.clone();
                value.launch_id = substituted_launch.launch_id.clone();
                value
            }),
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            },
            None,
        );
        let substituted_session = substituted_handoff.session().expect("session");
        assert!(matches!(
            ValidatedRunnerLaunchCleanupEvidence::readback(
                aggregate.evidence_bytes(),
                aggregate.evidence_digest(),
                &substituted_launch,
                Some(substituted_session),
                &substituted_handoff,
                Some(&expected),
            ),
            Err(RunnerLaunchCleanupEvidenceError::ExpectedSetSessionMismatch
                | RunnerLaunchCleanupEvidenceError::ReadbackAuthorityMismatch)
        ));
    }

    #[test]
    fn shutdown_acknowledgement_is_bound_and_applier_remains_unsupported() {
        let verifier_launch = launch(RunnerSessionPurpose::FinalVerifier);
        let session = session(&verifier_launch);
        let expected = ExpectedCommandDomainCleanupSet::try_new(
            &session.session_id,
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            Vec::new(),
        )
        .expect("empty verifier command set");
        let acknowledgement = ShutdownPreparedAcknowledgement::new(
            &session.session_id,
            session.session_nonce.clone(),
            RunnerRole::FinalVerifier,
            2,
            0,
            true,
        );
        let cleanup = handoff(
            verifier_launch.clone(),
            Some(session.clone()),
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            },
            Some(acknowledgement),
        );
        let _aggregate = adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
            ledger_launch: &verifier_launch,
            ledger_session: Some(&session),
            cleanup_required: &cleanup,
            expected_command_domains: Some(&expected),
            command_domain_proofs: &[],
        })
        .expect("acknowledgement is exactly bound");

        let mut substituted_acknowledgement = ShutdownPreparedAcknowledgement::new(
            &session.session_id,
            session.session_nonce.clone(),
            RunnerRole::FinalVerifier,
            2,
            0,
            true,
        );
        substituted_acknowledgement.accepted_request_count = 3;
        let substituted_cleanup = handoff(
            verifier_launch.clone(),
            Some(session.clone()),
            DirectChildOutcome::Exited {
                code: Some(0),
                success: true,
            },
            Some(substituted_acknowledgement),
        );
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &verifier_launch,
                ledger_session: Some(&session),
                cleanup_required: &substituted_cleanup,
                expected_command_domains: Some(&expected),
                command_domain_proofs: &[],
            }),
            Err(RunnerLaunchCleanupEvidenceError::InvalidShutdownAcknowledgement)
        );

        let applier_launch = launch(RunnerSessionPurpose::Applier);
        let applier_cleanup = handoff(
            applier_launch.clone(),
            None,
            DirectChildOutcome::LaunchRefusedBeforeSpawn,
            None,
        );
        assert_eq!(
            adapt_runner_launch_cleanup_evidence(RunnerLaunchCleanupEvidenceInput {
                ledger_launch: &applier_launch,
                ledger_session: None,
                cleanup_required: &applier_cleanup,
                expected_command_domains: None,
                command_domain_proofs: &[],
            }),
            Err(RunnerLaunchCleanupEvidenceError::TrustedApplierUnsupported)
        );
    }

    #[test]
    fn readback_rejects_empty_and_oversized_aggregate_bytes_before_decode() {
        let (launch, session, cleanup, expected, _) = registered_fixture();
        assert_eq!(
            ValidatedRunnerLaunchCleanupEvidence::readback(
                &[],
                &Digest::sha256(&[]),
                &launch,
                Some(&session),
                &cleanup,
                Some(&expected),
            ),
            Err(RunnerLaunchCleanupEvidenceError::EmptyEvidence)
        );
        let oversized = vec![0; MAX_RUNNER_LAUNCH_CLEANUP_EVIDENCE_BYTES + 1];
        assert_eq!(
            ValidatedRunnerLaunchCleanupEvidence::readback(
                &oversized,
                &Digest::sha256(&oversized),
                &launch,
                Some(&session),
                &cleanup,
                Some(&expected),
            ),
            Err(RunnerLaunchCleanupEvidenceError::EvidenceTooLarge {
                bytes: oversized.len(),
            })
        );
    }
}
