//! Pure desktop adaptation of one contained runner command exchange into the
//! core ledger's authoritative verification evidence.
//!
//! The runner authenticates the complete stdout/stderr commitments with a
//! domain-separated digest. This boundary retains that exact framed preimage,
//! revalidates the durable effect/session authority, and constructs the core
//! receipt. A command exit is execution evidence, not a completion claim;
//! only a typed normal exit with code zero is a passing result.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Write};
use std::path::Path;

use grok_build_core::{
    CONTRACT_VERSION, CommandDomainBackend, CommandDomainCleanupDisposition,
    CommandDomainCleanupProof, CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureIntentV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCapturePhysicalResolutionActionV1, CommandOutputCaptureRestartStateV1,
    CommandOutputCaptureStoreHeadV1, CommandOutputSensitiveRejectionAnchorV1,
    CommandOutputSensitiveRejectionCleanupReceiptV1, CommandSpec, CommandTerminationV1,
    ContractError, Digest, EffectIntent, EffectKind, IssuedWorkspaceGrant,
    MAX_EFFECT_EVIDENCE_BYTES, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputCleanRunnerReferenceV1, SensitiveOutputRejectionRunnerReferenceV1,
    VerificationEffectEvidence, VerificationReceipt,
};
use grok_build_runner::{
    CapabilityCommandOutputStore, CommandDomainCleanupBackend as RunnerCommandDomainCleanupBackend,
    CommandDomainCleanupBinding, CommandOutputCaptureJournalStateV1, RunnerRequest, RunnerResponse,
    RunnerResponseV12, SensitiveOutputCleanJournalReceiptV2,
    SensitiveOutputRejectionJournalReceiptV2, WireCommandBackendIdentity, WireCommandCleanupProof,
    WireCommandFailureCodeV12, WireCommandOutputCaptureAnchorV1,
    WireCommandOutputCaptureTerminalV1, WireCommandOutputSensitiveRejectionV12, WireCommandSpec,
    WireCommandStreamEvidence, WireCommandTerminalEvidence, WireContainmentRefusalEvidenceV12,
    WireEffectContext, WireFailureClass, WireProtocolError, WireReconciliationReference,
    command_stream_output_evidence_bytes, command_terminal_record_bytes,
    inspect_private_state_digest, runner_protocol_digest,
};

use crate::RunnerEffectResponse;
use crate::runner_client::RunnerCommandEffectResponse;

const COMMAND_TERMINAL_CAPTURE_SCHEMA: &str = "runner-wire-command-terminal/v11";

/// Explicit coordinator-owned inputs for one completed verification command.
#[derive(Clone, Copy)]
pub struct VerificationEvidenceInput<'a> {
    /// Exact correlated command request and response from the runner.
    pub exchange: &'a RunnerEffectResponse,
    /// Durable `RunCommand` intent committed before execution.
    pub intent: &'a EffectIntent,
    /// Exact registered task-worker or final-verifier session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact canonical lifecycle private-state root containing immutable
    /// command-output artifacts for this runner launch.
    pub private_state_root: &'a Path,
    /// Integrity-checked workspace authority behind the session.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact core command whose canonical bytes were committed pre-effect.
    pub command: &'a CommandSpec,
    /// Exact graph task for task verification; absent for final verification.
    pub task_id: Option<&'a str>,
    /// Coordinator-issued verification receipt identity.
    pub receipt_id: &'a str,
    /// Coordinator-issued terminal observation identity.
    pub observation_id: &'a str,
    /// Exact successful effect-observation time.
    pub observed_at_unix_ms: u64,
}

/// Coordinator-owned inputs for validating one exact command terminal without
/// projecting it into a verification receipt.
#[derive(Clone, Copy)]
pub struct CommandTerminalInput<'a> {
    /// Exact correlated command request and response from the runner.
    pub exchange: &'a RunnerEffectResponse,
    /// Durable `RunCommand` intent committed before execution.
    pub intent: &'a EffectIntent,
    /// Exact registered task-worker or final-verifier session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact lifecycle private-state root containing immutable output bytes.
    pub private_state_root: &'a Path,
    /// Integrity-checked workspace authority behind the session.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact command whose canonical bytes are the intent request preimage.
    pub command: &'a CommandSpec,
    /// Exact core request bytes authenticated by the effect intent. These are
    /// a canonical `CommandSpec` for verification or a canonical provider tool
    /// call for an ordinary task command.
    pub core_request_bytes: &'a [u8],
    /// Exact graph task for a task-worker command; absent for final verification.
    pub task_id: Option<&'a str>,
    /// Coordinator-owned terminal observation time.
    pub observed_at_unix_ms: u64,
}

/// Exact inputs for adapting one additive-v12 command response.
#[derive(Clone, Copy)]
pub struct CommandV12ResponseInput<'a> {
    /// Exact policy-bound command exchange retained after durable claim.
    pub exchange: &'a RunnerCommandEffectResponse,
    /// Durable pre-effect capture intent loaded from the owning ledger.
    pub capture_intent: &'a CommandOutputCaptureIntentV1,
    /// Durable `RunCommand` effect intent.
    pub intent: &'a EffectIntent,
    /// Exact initialized worker or final-verifier session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact lifecycle private-state root that owns the v2 journal.
    pub private_state_root: &'a Path,
    /// Integrity-checked workspace authority behind the session.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact canonical command whose bytes formed the effect request digest.
    pub command: &'a CommandSpec,
    /// Exact core request bytes authenticated by the effect intent.
    pub core_request_bytes: &'a [u8],
    /// Exact graph task for worker commands; absent for final verification.
    pub task_id: Option<&'a str>,
    /// Deterministic coordinator-owned observation identity.
    pub observation_id: &'a str,
    /// Coordinator-owned terminal observation time.
    pub observed_at_unix_ms: u64,
}

/// Message-free typed v12 command failure retained without inventing a v11
/// response or a command terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedCommandFailureV12 {
    /// Exact closed failure phase emitted by the runner.
    pub class: WireFailureClass,
    /// Exact closed failure reason emitted by the runner.
    pub code: WireCommandFailureCodeV12,
    /// Path-free reconciliation endpoint when the response requires one.
    pub reconciliation: Option<WireReconciliationReference>,
    /// Independently revalidated pre-launch containment-refusal evidence.
    ///
    /// Present only when the runner attached a proof that no command domain was
    /// created, and only after this desktop reopened those exact bytes against
    /// this effect's own binding. It is evidence about the refusal, never
    /// authority to reclassify it: the failure class and code are unchanged by
    /// its presence or absence.
    pub containment_refusal: Option<ValidatedContainmentRefusal>,
}

/// One desktop-revalidated pre-launch containment refusal.
///
/// The desktop does not take the runner's word for any of this. It reopens the
/// canonical proof bytes, requires the exact `NoDomainCreatedBeforeEffect`
/// disposition, and requires the binding inside the proof to be this command
/// effect's own session, effect, and request digest. A crossed or forged
/// attachment fails the whole response rather than being ignored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedContainmentRefusal {
    /// Exact capture the runner read back as its untouched reservation.
    pub capture_id: String,
    /// Exact untouched `Acquired` head the runner read back.
    pub untouched_store_head: CommandOutputCaptureStoreHeadV1,
    /// Platform accounting backend the absent domain would have used.
    pub command_domain_backend: CommandDomainBackend,
    /// Exact canonical no-domain proof bytes.
    pub no_domain_proof_bytes: Vec<u8>,
    /// SHA-256 of those exact bytes.
    pub no_domain_proof_digest: Digest,
}

/// Closed desktop result of one strictly correlated v12 command exchange.
#[allow(
    clippy::large_enum_variant,
    reason = "the root-reexported closed response preserves its public variant payload shape and exact adapted authority without boxing"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdaptedCommandResponseV12 {
    /// Clean scan, publication, and contained terminal all validated.
    Completed(AdaptedCommandTerminal),
    /// Rejected bytes were neutralized and no output artifact exists.
    SensitiveOutputRejected(AdaptedSensitiveOutputRejection),
    /// Message-free typed runner failure; no terminal is inferred.
    Failed(AdaptedCommandFailureV12),
}

/// Closed v12 verification result that preserves rejected-output and typed
/// failure branches without manufacturing a verification receipt.
#[allow(
    clippy::large_enum_variant,
    reason = "the root-reexported closed response preserves its public variant payload shape and exact adapted authority without boxing"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdaptedVerificationResponseV12 {
    /// Clean output and one exact current verification receipt.
    Completed(AdaptedVerificationEvidence),
    /// Sensitive bytes were rejected and no verification receipt exists.
    SensitiveOutputRejected(AdaptedSensitiveOutputRejection),
    /// The runner returned a message-free typed failure and no terminal was
    /// inferred.
    Failed(AdaptedCommandFailureV12),
}

/// Exact durable inputs for reconstructing one command terminal after the
/// process-local request/response exchange has been lost.
///
/// The runner must first decode and validate `terminal` from the retained
/// `TerminalPrepared` bytes and validate the exact retained launch binding.
/// This adapter then reuses the live authority, artifact, capture, backend,
/// and cleanup-proof checks without manufacturing a transport response.
#[derive(Clone, Copy)]
pub struct RecoveredCommandTerminalInput<'a> {
    /// Runner-owned strict decode of the retained canonical terminal record.
    pub terminal: &'a WireCommandTerminalEvidence,
    /// Exact retained terminal bytes whose digest/head are committed by the
    /// physical receipt and whose canonical decode produced `terminal`.
    pub retained_terminal_bytes: &'a [u8],
    /// Exact acquired capture authority durably handed to the original runner.
    pub output_capture: &'a WireCommandOutputCaptureAnchorV1,
    /// Complete fenced physical restart receipt already validated by core.
    pub physical: &'a CommandOutputCapturePhysicalReconciliationV1,
    /// Durable `RunCommand` intent committed before execution.
    pub intent: &'a EffectIntent,
    /// Exact registered task-worker session.
    pub runner_session: &'a RunnerSessionPolicyRecord,
    /// Exact lifecycle private-state root containing immutable output bytes.
    pub private_state_root: &'a Path,
    /// Integrity-checked workspace authority behind the session.
    pub authority: &'a IssuedWorkspaceGrant,
    /// Exact provider command committed by the effect request.
    pub command: &'a CommandSpec,
    /// Exact canonical provider command request bytes.
    pub core_request_bytes: &'a [u8],
    /// Exact graph task for the ordinary command.
    pub task_id: &'a str,
    /// Coordinator-owned terminal observation time.
    pub observed_at_unix_ms: u64,
}

/// Exact provider-neutral command result plus path-free terminal custody.
///
/// This type deliberately contains no [`VerificationReceipt`]. Ordinary task
/// commands can therefore reuse the full wire, journal, physical-artifact,
/// cleanup, and authority validation boundary without manufacturing a
/// finish-critical verification artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedCommandTerminal {
    /// Exact typed contained termination.
    pub termination: CommandTerminationV1,
    /// Bounded stdout prefix and complete-stream commitment.
    pub stdout: WireCommandStreamEvidence,
    /// Bounded stderr prefix and complete-stream commitment.
    pub stderr: WireCommandStreamEvidence,
    /// Immutable complete-output artifact reference.
    pub output_artifacts: CommandOutputArtifactSetReferenceV1,
    /// Canonical complete-stream commitment preimage.
    pub output_evidence_bytes: Vec<u8>,
    /// Measured contained execution duration.
    pub duration_ms: u64,
    /// Validated path-free capture and native-cleanup closure.
    command_terminal: ValidatedCommandTerminalClosure,
}

impl AdaptedCommandTerminal {
    /// Returns the validated capture and command-domain terminal closure.
    #[must_use]
    pub const fn command_terminal(&self) -> &ValidatedCommandTerminalClosure {
        &self.command_terminal
    }
}

/// Canonical verification evidence preimage and its successful-effect digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalVerificationEvidence {
    /// Exact canonical JSON accepted by the core ledger.
    pub bytes: Vec<u8>,
    /// Plain SHA-256 of [`Self::bytes`].
    pub digest: Digest,
}

/// Verification evidence ready for the ledger's atomic observation method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedVerificationEvidence {
    /// Exact effect-bound receipt and complete output preimage.
    pub evidence: VerificationEffectEvidence,
    /// Canonical evidence bytes and `EffectOutcome::Succeeded` digest.
    pub canonical_evidence: CanonicalVerificationEvidence,
    /// Validated path-free capture and native-cleanup closure retained for the
    /// coordinator's atomic core terminal join.
    command_terminal: ValidatedCommandTerminalClosure,
}

impl AdaptedVerificationEvidence {
    /// Returns the exact indexed verification receipt.
    #[must_use]
    pub const fn receipt(&self) -> &VerificationReceipt {
        &self.evidence.verification
    }

    /// Returns the validated path-free command terminal closure that must be
    /// joined to the effect observation and verification evidence atomically.
    #[must_use]
    pub const fn command_terminal(&self) -> &ValidatedCommandTerminalClosure {
        &self.command_terminal
    }
}

/// Secret-free, core-ready closure for one command output rejected by the
/// pre-admitted detector policy.
///
/// This type deliberately has no output bytes, output lengths, stream
/// commitments, artifact references, detector match, or verification receipt.
/// Its private fields can be populated only by the exact v12 response adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdaptedSensitiveOutputRejection {
    /// Actual typed command termination observed after detection/termination
    /// and before the final rejection record. This is execution evidence,
    /// never verification evidence.
    termination: CommandTerminationV1,
    /// Exact length-free rejection anchor used as the effect evidence.
    anchor: CommandOutputSensitiveRejectionAnchorV1,
    /// Exact runner-journal cleanup identity bound to the rejection anchor.
    cleanup: CommandOutputSensitiveRejectionCleanupReceiptV1,
    /// Independently authenticated native command-domain zero-survivor proof.
    command_cleanup: CommandDomainCleanupProof,
}

impl AdaptedSensitiveOutputRejection {
    /// Returns the actual typed command termination.
    #[must_use]
    pub const fn termination(&self) -> CommandTerminationV1 {
        self.termination
    }

    /// Returns the exact secret-free core rejection anchor.
    #[must_use]
    pub const fn anchor(&self) -> &CommandOutputSensitiveRejectionAnchorV1 {
        &self.anchor
    }

    /// Returns the exact runner cleanup receipt bound to the anchor.
    #[must_use]
    pub const fn cleanup(&self) -> &CommandOutputSensitiveRejectionCleanupReceiptV1 {
        &self.cleanup
    }

    /// Returns the exact independently validated command-domain cleanup proof.
    #[must_use]
    pub const fn command_cleanup(&self) -> &CommandDomainCleanupProof {
        &self.command_cleanup
    }
}

/// Path-free runner terminal custody retained after full wire, journal, and
/// physical-artifact validation.
///
/// Observation/proof identities and timestamps remain coordinator-owned. This
/// value preserves the exact capture closure, native backend identity, and
/// authenticated cleanup proof needed to construct the core terminal records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCommandTerminalClosure {
    output_capture: WireCommandOutputCaptureTerminalV1,
    backend: WireCommandBackendIdentity,
    cleanup_proof: WireCommandCleanupProof,
    clean_runner: Option<SensitiveOutputCleanRunnerReferenceV1>,
}

impl ValidatedCommandTerminalClosure {
    /// Returns the exact `Finished -> Published -> TerminalPrepared` closure.
    #[must_use]
    pub const fn output_capture(&self) -> &WireCommandOutputCaptureTerminalV1 {
        &self.output_capture
    }

    /// Returns the exact native command-domain backend identity.
    #[must_use]
    pub const fn backend(&self) -> &WireCommandBackendIdentity {
        &self.backend
    }

    /// Returns the exact digest-authenticated native cleanup proof.
    #[must_use]
    pub const fn cleanup_proof(&self) -> &WireCommandCleanupProof {
        &self.cleanup_proof
    }

    /// Exact independently revalidated runner-v2 clean branch. Legacy v11
    /// and pre-v29 recovery fixtures return `None` and cannot satisfy current
    /// successful command terminalization.
    #[must_use]
    pub const fn clean_runner(&self) -> Option<&SensitiveOutputCleanRunnerReferenceV1> {
        self.clean_runner.as_ref()
    }
}

/// Fail-closed verification-evidence adaptation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationEvidenceError {
    /// A supplied core contract or authority was invalid.
    Contract {
        /// Contract being checked.
        entity: &'static str,
        /// Bounded contract error text.
        detail: String,
    },
    /// The runner exchange was malformed or not exactly correlated.
    Wire {
        /// Bounded wire error text.
        detail: String,
    },
    /// Immutable command-output bytes could not be physically reopened and
    /// fully verified from the exact lifecycle private-state root.
    ArtifactCustody {
        /// Stable reopen, stream-read, or physical-integrity failure.
        detail: String,
    },
    /// An exact cross-contract relationship differed.
    Mismatch {
        /// Relationship that failed.
        field: &'static str,
        /// Stable failure description.
        detail: &'static str,
    },
    /// A path could not cross the runner's exact UTF-8 boundary.
    NonUtf8Path {
        /// Path-bearing contract field.
        field: &'static str,
    },
    /// Canonical core JSON could not be produced or exceeded its bound.
    CanonicalEncoding {
        /// Contract being encoded.
        entity: &'static str,
        /// Stable encoding failure text.
        detail: String,
    },
}

impl Display for VerificationEvidenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract { entity, detail } => {
                write!(formatter, "{entity} contract rejected: {detail}")
            }
            Self::Wire { detail } => write!(formatter, "runner evidence rejected: {detail}"),
            Self::ArtifactCustody { detail } => {
                write!(
                    formatter,
                    "command-output artifact custody rejected: {detail}"
                )
            }
            Self::Mismatch { field, detail } => {
                write!(formatter, "verification mismatch at {field}: {detail}")
            }
            Self::NonUtf8Path { field } => {
                write!(formatter, "verification path at {field} is not exact UTF-8")
            }
            Self::CanonicalEncoding { entity, detail } => {
                write!(formatter, "canonical {entity} encoding rejected: {detail}")
            }
        }
    }
}

impl Error for VerificationEvidenceError {}

/// Adapts one exact task-local or final-verifier command result into canonical
/// core verification evidence.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] for any contract, role, task, worker,
/// sprint, session, grant, policy, protocol, timing, nonce, effect-context,
/// transport-commitment, command, complete-output, or canonical-encoding
/// mismatch.
pub fn adapt_verification_evidence(
    input: VerificationEvidenceInput<'_>,
) -> Result<AdaptedVerificationEvidence, VerificationEvidenceError> {
    let core_request_bytes = serde_json::to_vec(input.command).map_err(|error| {
        VerificationEvidenceError::CanonicalEncoding {
            entity: "verification command",
            detail: error.to_string(),
        }
    })?;
    let adapted = adapt_command_terminal(CommandTerminalInput {
        exchange: input.exchange,
        intent: input.intent,
        runner_session: input.runner_session,
        private_state_root: input.private_state_root,
        authority: input.authority,
        command: input.command,
        core_request_bytes: &core_request_bytes,
        task_id: input.task_id,
        observed_at_unix_ms: input.observed_at_unix_ms,
    })?;
    let AdaptedCommandTerminal {
        termination,
        output_artifacts,
        output_evidence_bytes,
        duration_ms,
        command_terminal,
        ..
    } = adapted;
    let verification = VerificationReceipt {
        receipt_id: input.receipt_id.to_owned(),
        sprint_id: input.intent.sprint_id.clone(),
        task_id: input.task_id.map(str::to_owned),
        snapshot_id: input.intent.input_snapshot.clone(),
        command: input.command.clone(),
        policy_hash: input.intent.policy_hash.clone(),
        exit_status: termination.exit_status(),
        termination: Some(termination),
        output_digest: Digest::sha256(&output_evidence_bytes),
        duration_ms,
        finished_at_unix_ms: input.observed_at_unix_ms,
    };
    verification
        .validate_current()
        .map_err(|error| contract_error("verification receipt", &error))?;
    let evidence = VerificationEffectEvidence {
        contract_version: CONTRACT_VERSION,
        verification,
        effect_id: input.intent.effect_id.clone(),
        observation_id: input.observation_id.to_owned(),
        runner_launch_id: input.runner_session.launch_id.clone(),
        runner_session_id: input.runner_session.session_id.clone(),
        output_artifacts: Some(output_artifacts),
        output_evidence_bytes,
    };
    evidence
        .validate_current()
        .map_err(|error| contract_error("verification effect evidence", &error))?;
    let canonical_evidence = canonical_verification_evidence(&evidence)?;
    Ok(AdaptedVerificationEvidence {
        evidence,
        canonical_evidence,
        command_terminal,
    })
}

/// Validates one exact command exchange and immutable output capture without
/// constructing a verification receipt.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] for any crossed command, role,
/// session, effect context, transport commitment, capture anchor, physical
/// output artifact, terminal record, backend, or cleanup proof.
pub fn adapt_command_terminal(
    input: CommandTerminalInput<'_>,
) -> Result<AdaptedCommandTerminal, VerificationEvidenceError> {
    validate_common(&input)?;
    let exchange = validate_exchange(&input)?;
    let (_, _, evidence) = command_exchange_parts(&input)?;
    Ok(AdaptedCommandTerminal {
        termination: exchange.0,
        stdout: evidence.stdout.clone(),
        stderr: evidence.stderr.clone(),
        output_artifacts: exchange.1,
        output_evidence_bytes: exchange.2,
        duration_ms: exchange.3,
        command_terminal: exchange.4,
    })
}

/// Adapts one exact additive-v12 command response without collapsing its
/// clean, rejected-output, or typed-failure branch.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] for crossed durable authority,
/// policy, command, capture, physical journal, cleanup proof, or response
/// correlation. Rejected output is accepted only from the exact durable v2
/// rejection receipt; this adapter never creates a replacement receipt.
#[allow(
    clippy::too_many_lines,
    reason = "the v12 adapter keeps role, policy, capture, clean/reject journal, and cleanup joins visible in one fail-closed boundary"
)]
pub fn adapt_command_response_v12(
    input: CommandV12ResponseInput<'_>,
) -> Result<AdaptedCommandResponseV12, VerificationEvidenceError> {
    validate_common_authority(CommonCommandAuthority {
        intent: input.intent,
        runner_session: input.runner_session,
        private_state_root: input.private_state_root,
        authority: input.authority,
        command: input.command,
        core_request_bytes: input.core_request_bytes,
        task_id: input.task_id,
        observed_at_unix_ms: input.observed_at_unix_ms,
    })?;
    input
        .capture_intent
        .validate()
        .map_err(|error| contract_error("command output capture intent", &error))?;
    let exchange = input.exchange;
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    validate_effect_context(&exchange.request.effect, input.intent, input.runner_session)?;
    let computed_transport = exchange
        .request
        .computed_transport_commitment_digest()
        .map_err(|error| wire_error(&error))?;
    if exchange.request.effect.transport_commitment_digest != computed_transport
        || exchange.request.session_id != input.runner_session.session_id
        || exchange.request.runner_nonce != input.runner_session.session_nonce
        || exchange.response.runner_nonce != input.runner_session.session_nonce
    {
        return mismatch(
            "runner.v12_transport",
            "session, nonce, or full policy-bound transport commitment differs",
        );
    }
    let (wire_command, output_capture) = match exchange.request.request.command_request() {
        RunnerRequest::WorkerRunCommand {
            command,
            output_capture,
        } if input.runner_session.purpose == RunnerSessionPurpose::TaskWorker => {
            (command, output_capture)
        }
        RunnerRequest::FinalVerifierRunCommand {
            command,
            output_capture,
        } if input.runner_session.purpose == RunnerSessionPurpose::FinalVerifier => {
            (command, output_capture)
        }
        _ => {
            return mismatch(
                "runner.v12_request_shape",
                "requires the role-exact worker or final-verifier command",
            );
        }
    };
    validate_wire_command(wire_command, input.command)?;
    output_capture
        .acquired()
        .validate_against(input.capture_intent)
        .map_err(|error| contract_error("command output acquisition", &error))?;
    if input.capture_intent.source.effect_id != input.intent.effect_id
        || input.capture_intent.source.request_digest != input.intent.request_digest
        || input.capture_intent.source.runner_session_id != input.runner_session.session_id
        || input.capture_intent.source.runner_launch_id != input.runner_session.launch_id
    {
        return mismatch(
            "runner.v12_capture_intent",
            "capture source differs from the exact command effect, request, launch, or session",
        );
    }

    match &exchange.response.response {
        RunnerResponseV12::CommandCompleted {
            evidence,
            scan_receipt,
            ..
        } => {
            evidence
                .validate_for_output_capture(output_capture)
                .map_err(|error| wire_error(&error))?;
            validate_physical_output_artifacts(
                input.private_state_root,
                &input.runner_session.private_state_digest,
                output_capture,
                evidence,
            )?;
            let store =
                CapabilityCommandOutputStore::open(input.private_state_root).map_err(|error| {
                    VerificationEvidenceError::ArtifactCustody {
                        detail: format!("cannot reopen v2 clean journal store: {error}"),
                    }
                })?;
            let reopened = store
                .reopen_sensitive_output_clean_v2(&input.capture_intent.capture_id)
                .map_err(|error| VerificationEvidenceError::ArtifactCustody {
                    detail: format!("cannot reopen exact v2 clean journal: {error}"),
                })?
                .ok_or_else(|| VerificationEvidenceError::ArtifactCustody {
                    detail: "v12 clean response has no exact durable clean journal".into(),
                })?;
            if &reopened != scan_receipt {
                return mismatch(
                    "runner.v12_clean_journal",
                    "wire clean receipt differs from exact durable v2 readback",
                );
            }
            let clean_runner = core_clean_runner_reference(scan_receipt)?;
            let output_evidence_bytes =
                command_stream_output_evidence_bytes(&evidence.stdout, &evidence.stderr);
            if Digest::sha256(&output_evidence_bytes) != evidence.output_digest {
                return mismatch(
                    "runner.command_output",
                    "complete stream commitments differ from the runner-authenticated output digest",
                );
            }
            Ok(AdaptedCommandResponseV12::Completed(
                AdaptedCommandTerminal {
                    termination: evidence.termination,
                    stdout: evidence.stdout.clone(),
                    stderr: evidence.stderr.clone(),
                    output_artifacts: evidence.output_artifacts.clone(),
                    output_evidence_bytes,
                    duration_ms: evidence.duration_ms,
                    command_terminal: ValidatedCommandTerminalClosure {
                        output_capture: evidence.output_capture.clone(),
                        backend: evidence.backend.clone(),
                        cleanup_proof: evidence.cleanup_proof.clone(),
                        clean_runner: Some(clean_runner),
                    },
                },
            ))
        }
        RunnerResponseV12::CommandOutputAbandoned { rejection } => {
            adapt_sensitive_output_rejection_v12(input, output_capture, rejection)
                .map(AdaptedCommandResponseV12::SensitiveOutputRejected)
        }
        RunnerResponseV12::CommandFailed {
            class,
            code,
            reconciliation,
            containment_refusal,
            ..
        } => {
            let containment_refusal = containment_refusal
                .as_deref()
                .map(|refusal| {
                    validate_containment_refusal(
                        refusal,
                        input.intent,
                        input.runner_session,
                        input.capture_intent,
                        output_capture.acquired(),
                    )
                })
                .transpose()?;
            Ok(AdaptedCommandResponseV12::Failed(
                AdaptedCommandFailureV12 {
                    class: *class,
                    code: *code,
                    reconciliation: reconciliation.clone(),
                    containment_refusal,
                },
            ))
        }
    }
}

/// Reopens one attached containment refusal against this desktop's own
/// authority.
///
/// Nothing here trusts a field because the runner sent it. The proof bytes are
/// re-decoded, the disposition is required to be exactly the absent-domain one,
/// and the binding inside the proof must be the effect, session, and request
/// digest this desktop already holds. The untouched head must be the exact head
/// this desktop handed over at acquisition, which is what makes "the capture was
/// never written" a comparison rather than a claim.
fn validate_containment_refusal(
    refusal: &WireContainmentRefusalEvidenceV12,
    intent: &EffectIntent,
    runner_session: &RunnerSessionPolicyRecord,
    capture_intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<ValidatedContainmentRefusal, VerificationEvidenceError> {
    let binding = CommandDomainCleanupBinding::try_new(
        runner_session.session_id.clone(),
        intent.effect_id.clone(),
        intent.request_digest.clone(),
    )
    .map_err(|error| VerificationEvidenceError::Contract {
        entity: "runner.v12_containment_refusal_binding",
        detail: error.to_string(),
    })?;
    let proof = refusal
        .readback(&binding)
        .map_err(|error| wire_error(&error))?;
    if refusal.capture_id != capture_intent.capture_id
        || refusal.capture_id != acquired.capture_id
        || refusal.untouched_store_head != acquired.store_head
    {
        return Err(VerificationEvidenceError::Mismatch {
            field: "runner.v12_containment_refusal_capture",
            detail: "refusal head differs from the exact acquired capture reservation",
        });
    }
    let command_domain_backend = match proof.backend() {
        RunnerCommandDomainCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        RunnerCommandDomainCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
    };
    Ok(ValidatedContainmentRefusal {
        capture_id: refusal.capture_id.clone(),
        untouched_store_head: refusal.untouched_store_head.clone(),
        command_domain_backend,
        no_domain_proof_bytes: proof.os_evidence_bytes().to_vec(),
        no_domain_proof_digest: proof.os_evidence_digest().clone(),
    })
}

/// Adapts one additive-v12 formal or final verification response while
/// retaining the exact non-success branch.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] when the command exchange, durable
/// capture, runner journal, cleanup proof, or verification receipt is crossed.
pub fn adapt_verification_response_v12(
    input: CommandV12ResponseInput<'_>,
    receipt_id: &str,
) -> Result<AdaptedVerificationResponseV12, VerificationEvidenceError> {
    let response = adapt_command_response_v12(input)?;
    match response {
        AdaptedCommandResponseV12::Completed(adapted) => {
            verification_evidence_from_adapted_command(
                adapted,
                input.intent,
                input.runner_session,
                input.command,
                input.task_id,
                receipt_id,
                input.observation_id,
                input.observed_at_unix_ms,
            )
            .map(AdaptedVerificationResponseV12::Completed)
        }
        AdaptedCommandResponseV12::SensitiveOutputRejected(rejection) => Ok(
            AdaptedVerificationResponseV12::SensitiveOutputRejected(rejection),
        ),
        AdaptedCommandResponseV12::Failed(failure) => {
            Ok(AdaptedVerificationResponseV12::Failed(failure))
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact effect, session, command, task, receipt, observation, and time form one verification identity"
)]
fn verification_evidence_from_adapted_command(
    adapted: AdaptedCommandTerminal,
    intent: &EffectIntent,
    runner_session: &RunnerSessionPolicyRecord,
    command: &CommandSpec,
    task_id: Option<&str>,
    receipt_id: &str,
    observation_id: &str,
    observed_at_unix_ms: u64,
) -> Result<AdaptedVerificationEvidence, VerificationEvidenceError> {
    let AdaptedCommandTerminal {
        termination,
        output_artifacts,
        output_evidence_bytes,
        duration_ms,
        command_terminal,
        ..
    } = adapted;
    let verification = VerificationReceipt {
        receipt_id: receipt_id.to_owned(),
        sprint_id: intent.sprint_id.clone(),
        task_id: task_id.map(str::to_owned),
        snapshot_id: intent.input_snapshot.clone(),
        command: command.clone(),
        policy_hash: intent.policy_hash.clone(),
        exit_status: termination.exit_status(),
        termination: Some(termination),
        output_digest: Digest::sha256(&output_evidence_bytes),
        duration_ms,
        finished_at_unix_ms: observed_at_unix_ms,
    };
    verification
        .validate_current()
        .map_err(|error| contract_error("verification receipt", &error))?;
    let evidence = VerificationEffectEvidence {
        contract_version: CONTRACT_VERSION,
        verification,
        effect_id: intent.effect_id.clone(),
        observation_id: observation_id.to_owned(),
        runner_launch_id: runner_session.launch_id.clone(),
        runner_session_id: runner_session.session_id.clone(),
        output_artifacts: Some(output_artifacts),
        output_evidence_bytes,
    };
    evidence
        .validate_current()
        .map_err(|error| contract_error("verification effect evidence", &error))?;
    let canonical_evidence = canonical_verification_evidence(&evidence)?;
    Ok(AdaptedVerificationEvidence {
        evidence,
        canonical_evidence,
        command_terminal,
    })
}

pub(crate) fn core_clean_runner_reference(
    receipt: &SensitiveOutputCleanJournalReceiptV2,
) -> Result<SensitiveOutputCleanRunnerReferenceV1, VerificationEvidenceError> {
    receipt
        .validate()
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("runner clean receipt is invalid: {error}"),
        })?;
    let reference = SensitiveOutputCleanRunnerReferenceV1 {
        journal_id: receipt.journal_id.clone(),
        capture_id: receipt.capture_id.clone(),
        runner_session_id: receipt.runner_session_id.clone(),
        effect_id: receipt.effect_id.clone(),
        request_digest: receipt.request_digest.clone(),
        intent_digest: receipt.intent_digest.clone(),
        acquired: receipt.acquired.clone(),
        acquired_anchor_digest: receipt.acquired_anchor_digest.clone(),
        acquired_store_head: receipt.acquired_store_head.clone(),
        writer_attached_store_head: receipt.writer_attached_store_head.clone(),
        launch_intended_store_head: receipt.launch_intended_store_head.clone(),
        core_dump_suppression: receipt.core_dump_suppression.clone(),
        detector_policy: receipt.detector_policy.clone(),
        intent_bound_journal_head: receipt.intent_bound_journal_head.clone(),
        acquired_bound_journal_head: receipt.acquired_bound_journal_head.clone(),
        writer_attached_journal_head: receipt.writer_attached_journal_head.clone(),
        launch_intended_journal_head: receipt.launch_intended_journal_head.clone(),
        scanned_clean_journal_head: receipt.scanned_clean_journal_head.clone(),
        finished_journal_head: receipt.finished_journal_head.clone(),
        published_journal_head: receipt.published_journal_head.clone(),
        terminal_prepared_journal_head: receipt.terminal_prepared_journal_head.clone(),
        finished_store_head: receipt.finished_store_head.clone(),
        published_store_head: receipt.published_store_head.clone(),
        terminal_prepared_store_head: receipt.terminal_prepared_store_head.clone(),
        terminal_record_digest: receipt.terminal_record_digest.clone(),
        termination: receipt.termination,
        scanned_clean_at_unix_ms: receipt.scanned_clean_at_unix_ms,
        finished_at_unix_ms: receipt.finished_at_unix_ms,
        published_at_unix_ms: receipt.published_at_unix_ms,
        terminal_prepared_at_unix_ms: receipt.terminal_prepared_at_unix_ms,
    };
    reference
        .validate()
        .map_err(|error| contract_error("core clean runner reference", &error))?;
    Ok(reference)
}

pub(crate) fn core_rejection_runner_reference(
    receipt: &SensitiveOutputRejectionJournalReceiptV2,
) -> Result<SensitiveOutputRejectionRunnerReferenceV1, VerificationEvidenceError> {
    receipt
        .validate()
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("runner rejection receipt is invalid: {error}"),
        })?;
    let reference = SensitiveOutputRejectionRunnerReferenceV1 {
        journal_id: receipt.journal_id.clone(),
        capture_id: receipt.capture_id.clone(),
        runner_session_id: receipt.runner_session_id.clone(),
        effect_id: receipt.effect_id.clone(),
        request_digest: receipt.request_digest.clone(),
        intent_digest: receipt.intent_digest.clone(),
        acquired: receipt.acquired.clone(),
        acquired_anchor_digest: receipt.acquired_anchor_digest.clone(),
        acquired_store_head: receipt.acquired_store_head.clone(),
        writer_attached_store_head: receipt.writer_attached_store_head.clone(),
        launch_intended_store_head: receipt.launch_intended_store_head.clone(),
        core_dump_suppression: receipt.core_dump_suppression.clone(),
        detector_policy: receipt.detector_policy.clone(),
        intent_bound_journal_head: receipt.intent_bound_journal_head.clone(),
        acquired_bound_journal_head: receipt.acquired_bound_journal_head.clone(),
        writer_attached_journal_head: receipt.writer_attached_journal_head.clone(),
        launch_intended_journal_head: receipt.launch_intended_journal_head.clone(),
        detected_journal_head: receipt.detected_journal_head.clone(),
        cleanup_intended_journal_head: receipt.cleanup_intended_journal_head.clone(),
        cleaned_journal_head: receipt.cleaned_journal_head.clone(),
        rejected_terminal_journal_head: receipt.rejected_terminal_journal_head.clone(),
        v1_cleaned_store_head: receipt.v1_cleaned_store_head.clone(),
        command_domain_cleanup_proof_id: receipt.command_domain_cleanup_proof_id.clone(),
        staging_neutralization: receipt.staging_neutralization.clone(),
        termination: receipt.termination,
        cleanup_receipt_id: receipt.cleanup_receipt_id.clone(),
        cleanup_receipt_digest: receipt.cleanup_receipt_digest.clone(),
    };
    reference
        .validate()
        .map_err(|error| contract_error("core rejection runner reference", &error))?;
    Ok(reference)
}

#[allow(
    clippy::too_many_lines,
    reason = "the rejection adapter keeps durable journal, cleanup, artifact, and private-state identity checks in one audit boundary"
)]
fn adapt_sensitive_output_rejection_v12(
    input: CommandV12ResponseInput<'_>,
    output_capture: &WireCommandOutputCaptureAnchorV1,
    rejection: &WireCommandOutputSensitiveRejectionV12,
) -> Result<AdaptedSensitiveOutputRejection, VerificationEvidenceError> {
    let store = CapabilityCommandOutputStore::open(input.private_state_root).map_err(|error| {
        VerificationEvidenceError::ArtifactCustody {
            detail: format!("cannot reopen v2 rejection store: {error}"),
        }
    })?;
    let reopened = store
        .reopen_sensitive_output_rejection_v2(&input.capture_intent.capture_id)
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("cannot reopen exact v2 rejection journal: {error}"),
        })?
        .ok_or_else(|| VerificationEvidenceError::ArtifactCustody {
            detail: "v12 rejection response has no exact durable rejection journal".into(),
        })?;
    let capture = store
        .reopen_capture(&input.capture_intent.capture_id)
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("cannot reopen exact rejected v1 capture: {error}"),
        })?;
    if reopened != rejection.journal_receipt
        || capture.state() != CommandOutputCaptureJournalStateV1::Cleaned
        || capture.expected_reference().is_some()
        || capture.cleaned_store_head() != Some(&rejection.output_capture_cleaned_store_head)
    {
        return mismatch(
            "runner.v12_rejection_journal",
            "wire rejection differs from exact Cleaned v1 and terminal v2 readback",
        );
    }
    let runner_cleanup = core_rejection_runner_reference(&rejection.journal_receipt)?;
    let anchor = CommandOutputSensitiveRejectionAnchorV1::try_new(
        input.capture_intent,
        output_capture.acquired(),
        input.observation_id,
        runner_cleanup.clone(),
    )
    .map_err(|error| contract_error("sensitive-output rejection anchor", &error))?;
    let cleanup_binding = CommandDomainCleanupBinding::try_new(
        input.runner_session.session_id.clone(),
        input.intent.effect_id.clone(),
        input.intent.request_digest.clone(),
    )
    .map_err(|error| VerificationEvidenceError::Wire {
        detail: error.to_string(),
    })?;
    let validated_cleanup = rejection
        .cleanup_proof
        .readback(rejection.backend, &cleanup_binding)
        .map_err(|error| VerificationEvidenceError::Wire {
            detail: error.to_string(),
        })?;
    if validated_cleanup.surviving_processes() != 0
        || rejection.command_domain_cleanup_proof_id
            != validated_cleanup.os_evidence_digest().as_str()
    {
        return mismatch(
            "runner.v12_rejection_cleanup",
            "rejection cleanup identity does not prove exact zero-survivor readback",
        );
    }
    let backend = match validated_cleanup.backend() {
        grok_build_runner::CommandDomainCleanupBackend::LinuxCgroupV2 => {
            CommandDomainBackend::LinuxCgroupV2
        }
        grok_build_runner::CommandDomainCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
    };
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: rejection.command_domain_cleanup_proof_id.clone(),
        sprint_id: input.intent.sprint_id.clone(),
        launch_id: input.runner_session.launch_id.clone(),
        session_id: input.runner_session.session_id.clone(),
        effect_id: input.intent.effect_id.clone(),
        observation_id: Some(input.observation_id.to_owned()),
        request_digest: input.intent.request_digest.clone(),
        backend,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: validated_cleanup.os_evidence_digest().clone(),
        platform_proof_bytes: validated_cleanup.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms: input.observed_at_unix_ms,
    };
    command_cleanup
        .validate()
        .map_err(|error| contract_error("sensitive-output command cleanup", &error))?;
    let cleanup = CommandOutputSensitiveRejectionCleanupReceiptV1::try_new(
        &anchor,
        format!("{}:sensitive-output-cleanup", input.intent.effect_id),
        runner_cleanup,
        command_cleanup.proof_id.clone(),
    )
    .map_err(|error| contract_error("sensitive-output rejection cleanup", &error))?;
    let final_private_state_digest = inspect_private_state_digest(input.private_state_root)
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("cannot reauthenticate rejection private-state root: {error}"),
        })?;
    if final_private_state_digest != input.runner_session.private_state_digest {
        return Err(VerificationEvidenceError::ArtifactCustody {
            detail: "private-state root identity changed during rejection validation".into(),
        });
    }
    Ok(AdaptedSensitiveOutputRejection {
        termination: rejection.termination,
        anchor,
        cleanup,
        command_cleanup,
    })
}

/// Reconstructs one exact ordinary command result from a core-validated
/// physical restart receipt and runner-validated retained terminal record.
///
/// Unlike [`adapt_command_terminal`], this path does not claim that the old
/// process-local response frame still exists. Every durable authority and
/// physical artifact check remains identical.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] for a crossed intent, session, grant,
/// task, command request, acquired anchor, physical receipt, terminal record,
/// immutable output artifact, backend, or command-domain cleanup proof.
#[allow(
    clippy::too_many_lines,
    reason = "restart adaptation intentionally keeps every durable and physical authority comparison in one audit boundary"
)]
pub fn adapt_recovered_command_terminal(
    input: RecoveredCommandTerminalInput<'_>,
) -> Result<AdaptedCommandTerminal, VerificationEvidenceError> {
    validate_common_authority(CommonCommandAuthority {
        intent: input.intent,
        runner_session: input.runner_session,
        private_state_root: input.private_state_root,
        authority: input.authority,
        command: input.command,
        core_request_bytes: input.core_request_bytes,
        task_id: Some(input.task_id),
        observed_at_unix_ms: input.observed_at_unix_ms,
    })?;
    let physical = input.physical;
    let terminal = input.terminal;
    let acquired = input.output_capture.acquired();
    let terminal_prepared =
        physical
            .terminal_prepared
            .as_ref()
            .ok_or(VerificationEvidenceError::Mismatch {
                field: "runner.command_output_capture.physical_terminal",
                detail: "restart receipt lacks its exact TerminalPrepared payload",
            })?;
    let canonical_terminal = command_terminal_record_bytes(terminal).map_err(|error| {
        VerificationEvidenceError::Wire {
            detail: format!("cannot reconstruct retained command terminal record: {error}"),
        }
    })?;
    let exact_physical_terminal = physical.effect_id == input.intent.effect_id
        && physical.final_state == CommandOutputCaptureRestartStateV1::TerminalPrepared
        && matches!(
            physical.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
                | CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered
        )
        && physical.physical_acquired.as_ref() == Some(acquired)
        && matches!(
            physical.launch_history,
            grok_build_core::CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { .. }
        )
        && physical.finished_store_head.as_ref()
            == Some(&terminal.output_capture.finished_store_head)
        && physical.published_store_head.as_ref()
            == Some(&terminal.output_capture.published_store_head)
        && physical.artifact_reference.as_ref() == Some(&terminal.output_artifacts)
        && terminal_prepared.store_head == terminal.output_capture.terminal_prepared_store_head
        && terminal_prepared.store_head == physical.final_store_head
        && terminal_prepared.canonical_bytes_digest
            == terminal.output_capture.terminal_record_digest
        && terminal_prepared.canonical_bytes_digest
            == Digest::sha256(input.retained_terminal_bytes)
        && input.retained_terminal_bytes == canonical_terminal;
    if !exact_physical_terminal {
        return mismatch(
            "runner.command_output_capture.physical_terminal",
            "restart state, action, acquisition, launch, heads, artifact, or terminal digest differs",
        );
    }
    input
        .output_capture
        .validate()
        .map_err(|error| wire_error(&error))?;
    terminal
        .validate_for_output_capture(input.output_capture)
        .map_err(|error| wire_error(&error))?;
    let source = &terminal.output_artifacts.source;
    if source.sprint_id != input.intent.sprint_id
        || source.runner_launch_id != input.runner_session.launch_id
        || source.runner_session_id != input.runner_session.session_id
        || source.effect_id != input.intent.effect_id
        || source.request_digest != input.intent.request_digest
    {
        return mismatch(
            "runner.command_output_artifacts.source",
            "artifact source differs from the exact sprint, launch, session, effect, or request",
        );
    }
    let cleanup_binding = CommandDomainCleanupBinding::try_new(
        input.runner_session.session_id.clone(),
        input.intent.effect_id.clone(),
        input.intent.request_digest.clone(),
    )
    .map_err(|error| VerificationEvidenceError::Wire {
        detail: error.to_string(),
    })?;
    let validated_cleanup = terminal
        .cleanup_proof
        .readback(terminal.backend.command_domain_backend, &cleanup_binding)
        .map_err(|error| VerificationEvidenceError::Wire {
            detail: error.to_string(),
        })?;
    if validated_cleanup.surviving_processes() != 0 {
        return mismatch(
            "runner.command_cleanup.surviving_processes",
            "retained terminal cleanup proof does not prove zero survivors",
        );
    }
    validate_physical_output_artifacts(
        input.private_state_root,
        &input.runner_session.private_state_digest,
        input.output_capture,
        terminal,
    )?;
    let output_evidence_bytes =
        command_stream_output_evidence_bytes(&terminal.stdout, &terminal.stderr);
    if Digest::sha256(&output_evidence_bytes) != terminal.output_digest {
        return mismatch(
            "runner.command_output",
            "complete stream commitments differ from the runner-authenticated output digest",
        );
    }
    Ok(AdaptedCommandTerminal {
        termination: terminal.termination,
        stdout: terminal.stdout.clone(),
        stderr: terminal.stderr.clone(),
        output_artifacts: terminal.output_artifacts.clone(),
        output_evidence_bytes,
        duration_ms: terminal.duration_ms,
        command_terminal: ValidatedCommandTerminalClosure {
            output_capture: terminal.output_capture.clone(),
            backend: terminal.backend.clone(),
            cleanup_proof: terminal.cleanup_proof.clone(),
            clean_runner: None,
        },
    })
}

/// Produces the exact canonical evidence preimage and success digest expected
/// by the core ledger.
///
/// # Errors
///
/// Returns [`VerificationEvidenceError`] if the evidence is invalid, cannot be
/// canonically encoded, or exceeds the effect-evidence bound.
pub fn canonical_verification_evidence(
    evidence: &VerificationEffectEvidence,
) -> Result<CanonicalVerificationEvidence, VerificationEvidenceError> {
    evidence
        .verification
        .validate_current()
        .map_err(|error| contract_error("current verification receipt", &error))?;
    evidence
        .validate_current()
        .map_err(|error| contract_error("verification effect evidence", &error))?;
    let bytes = serde_json::to_vec(evidence).map_err(|error| {
        VerificationEvidenceError::CanonicalEncoding {
            entity: "verification effect evidence",
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_EFFECT_EVIDENCE_BYTES {
        return Err(VerificationEvidenceError::CanonicalEncoding {
            entity: "verification effect evidence",
            detail: format!(
                "{} bytes exceed the ledger bound of {MAX_EFFECT_EVIDENCE_BYTES}",
                bytes.len()
            ),
        });
    }
    let digest = Digest::sha256(&bytes);
    Ok(CanonicalVerificationEvidence { bytes, digest })
}

#[derive(Clone, Copy)]
struct CommonCommandAuthority<'a> {
    intent: &'a EffectIntent,
    runner_session: &'a RunnerSessionPolicyRecord,
    private_state_root: &'a Path,
    authority: &'a IssuedWorkspaceGrant,
    command: &'a CommandSpec,
    core_request_bytes: &'a [u8],
    task_id: Option<&'a str>,
    observed_at_unix_ms: u64,
}

fn validate_common(input: &CommandTerminalInput<'_>) -> Result<(), VerificationEvidenceError> {
    validate_common_authority(CommonCommandAuthority {
        intent: input.intent,
        runner_session: input.runner_session,
        private_state_root: input.private_state_root,
        authority: input.authority,
        command: input.command,
        core_request_bytes: input.core_request_bytes,
        task_id: input.task_id,
        observed_at_unix_ms: input.observed_at_unix_ms,
    })
}

fn validate_common_authority(
    input: CommonCommandAuthority<'_>,
) -> Result<(), VerificationEvidenceError> {
    input
        .authority
        .validate_integrity()
        .map_err(|error| contract_error("workspace grant", &error))?;
    input
        .intent
        .validate()
        .map_err(|error| contract_error("effect intent", &error))?;
    input
        .runner_session
        .validate()
        .map_err(|error| contract_error("runner session policy", &error))?;
    let private_state_digest =
        inspect_private_state_digest(input.private_state_root).map_err(|error| {
            VerificationEvidenceError::ArtifactCustody {
                detail: format!("cannot authenticate exact lifecycle private-state root: {error}"),
            }
        })?;
    if private_state_digest != input.runner_session.private_state_digest {
        return Err(VerificationEvidenceError::ArtifactCustody {
            detail: "private-state root identity differs from the registered runner session".into(),
        });
    }
    input
        .command
        .validate()
        .map_err(|error| contract_error("verification command", &error))?;
    require_utf8_path(
        &input.authority.contract().canonical_root,
        "workspace_grant.canonical_root",
    )?;
    require_utf8_path(
        &input.command.working_directory,
        "command.working_directory",
    )?;
    let grant = input.authority.contract();
    let session = input.runner_session;
    if input.intent.kind != EffectKind::RunCommand
        || session.contract_version != input.intent.contract_version
        || session.sprint_id != input.intent.sprint_id
        || session.policy_hash != input.intent.policy_hash
        || session.grant_hash != grant.grant_hash
        || session.policy_version != grant.policy_version
        || !grant.permissions.execute_commands
    {
        return mismatch(
            "effect.session_authority",
            "effect kind, contract, sprint, policy, grant, version, or command authority differs",
        );
    }
    let role_matches = match input.task_id {
        Some(task_id) => {
            session.purpose == RunnerSessionPurpose::TaskWorker
                && session.worker_id.is_some()
                && input.intent.task_id.as_deref() == Some(task_id)
                && input.intent.worker_id.as_deref() == session.worker_id.as_deref()
                && input.intent.worker_lease.as_ref() == session.worker_lease.as_ref()
        }
        None => {
            session.purpose == RunnerSessionPurpose::FinalVerifier
                && session.worker_id.is_none()
                && session.worker_lease.is_none()
                && input.intent.task_id.is_none()
                && input.intent.worker_id.is_none()
                && input.intent.worker_lease.is_none()
        }
    };
    if !role_matches {
        return mismatch(
            "effect.verification_scope",
            "task verification requires its exact task worker and final verification requires a sprint-scoped final verifier",
        );
    }
    if session.protocol_digest != runner_protocol_digest() {
        return mismatch(
            "runner_session.protocol_digest",
            "does not identify the runner protocol used by this adapter",
        );
    }
    if session.registered_at_unix_ms > input.intent.created_at_unix_ms
        || input.observed_at_unix_ms < input.intent.created_at_unix_ms
    {
        return mismatch(
            "effect.timeline",
            "runner registration must precede the intent and observation must follow it",
        );
    }
    if Digest::sha256(input.core_request_bytes) != input.intent.request_digest {
        return mismatch(
            "effect_intent.request_digest",
            "does not hash the exact canonical command-bearing core request",
        );
    }
    Ok(())
}

fn validate_exchange(
    input: &CommandTerminalInput<'_>,
) -> Result<
    (
        CommandTerminationV1,
        CommandOutputArtifactSetReferenceV1,
        Vec<u8>,
        u64,
        ValidatedCommandTerminalClosure,
    ),
    VerificationEvidenceError,
> {
    let exchange = input.exchange;
    exchange
        .response
        .validate_correlation(&exchange.request)
        .map_err(|error| wire_error(&error))?;
    let effect = exchange
        .request
        .effect
        .as_ref()
        .ok_or(VerificationEvidenceError::Mismatch {
            field: "runner.effect_context",
            detail: "verification command requires its durable effect context",
        })?;
    validate_effect_context(effect, input.intent, input.runner_session)?;
    validate_transport_commitment(exchange, effect)?;
    if exchange.request.session_id != input.runner_session.session_id
        || exchange.request.runner_nonce.as_ref() != Some(&input.runner_session.session_nonce)
        || exchange.response.runner_nonce != input.runner_session.session_nonce
    {
        return mismatch(
            "runner.session",
            "request or response session identity and nonce differs from the registered runner",
        );
    }
    let (wire_command, output_capture, evidence) = command_exchange_parts(input)?;
    validate_wire_command(wire_command, input.command)?;
    evidence
        .validate_for_output_capture(output_capture)
        .map_err(|error| wire_error(&error))?;
    validate_physical_output_artifacts(
        input.private_state_root,
        &input.runner_session.private_state_digest,
        output_capture,
        evidence,
    )?;
    let output_evidence_bytes =
        command_stream_output_evidence_bytes(&evidence.stdout, &evidence.stderr);
    if Digest::sha256(&output_evidence_bytes) != evidence.output_digest {
        return mismatch(
            "runner.command_output",
            "complete stream commitments differ from the runner-authenticated output digest",
        );
    }
    Ok((
        evidence.termination,
        evidence.output_artifacts.clone(),
        output_evidence_bytes,
        evidence.duration_ms,
        ValidatedCommandTerminalClosure {
            output_capture: evidence.output_capture.clone(),
            backend: evidence.backend.clone(),
            cleanup_proof: evidence.cleanup_proof.clone(),
            clean_runner: None,
        },
    ))
}

fn command_exchange_parts<'a>(
    input: &CommandTerminalInput<'a>,
) -> Result<
    (
        &'a WireCommandSpec,
        &'a WireCommandOutputCaptureAnchorV1,
        &'a WireCommandTerminalEvidence,
    ),
    VerificationEvidenceError,
> {
    match (
        &input.exchange.request.request,
        &input.exchange.response.response,
    ) {
        (
            RunnerRequest::WorkerRunCommand {
                command,
                output_capture,
            },
            RunnerResponse::CommandCompleted { evidence },
        ) if input.runner_session.purpose == RunnerSessionPurpose::TaskWorker => {
            Ok((command, output_capture, evidence))
        }
        (
            RunnerRequest::FinalVerifierRunCommand {
                command,
                output_capture,
            },
            RunnerResponse::CommandCompleted { evidence },
        ) if input.runner_session.purpose == RunnerSessionPurpose::FinalVerifier => {
            Ok((command, output_capture, evidence))
        }
        _ => mismatch(
            "runner.response_shape",
            "requires the role-exact command request and CommandCompleted response",
        ),
    }
}

struct RetainedPrefixVerifier<'a> {
    expected: &'a [u8],
    compared: usize,
    mismatch: bool,
}

impl<'a> RetainedPrefixVerifier<'a> {
    const fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            compared: 0,
            mismatch: false,
        }
    }

    fn exact(&self) -> bool {
        !self.mismatch && self.compared == self.expected.len()
    }
}

impl Write for RetainedPrefixVerifier<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.expected.len().saturating_sub(self.compared);
        let compared = remaining.min(bytes.len());
        if bytes[..compared] != self.expected[self.compared..self.compared + compared] {
            self.mismatch = true;
        }
        self.compared += compared;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn validate_physical_output_artifacts(
    private_state_root: &Path,
    expected_private_state_digest: &Digest,
    output_capture: &WireCommandOutputCaptureAnchorV1,
    evidence: &WireCommandTerminalEvidence,
) -> Result<(), VerificationEvidenceError> {
    let store = CapabilityCommandOutputStore::open(private_state_root).map_err(|error| {
        VerificationEvidenceError::ArtifactCustody {
            detail: format!("cannot open exact lifecycle private-state root: {error}"),
        }
    })?;
    if &output_capture.acquired().private_state_digest != expected_private_state_digest {
        return mismatch(
            "runner.command_output_capture.private_state_digest",
            "request capture authority differs from the registered runner private-state root",
        );
    }
    let capture = store
        .reopen_capture(&evidence.output_capture.capture_id)
        .map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("exact capture journal reopen failed: {error}"),
        })?;
    let terminal_record_bytes = command_terminal_record_bytes(evidence).map_err(|error| {
        VerificationEvidenceError::Wire {
            detail: format!("cannot reconstruct exact command terminal record: {error}"),
        }
    })?;
    let terminal_payload =
        capture
            .terminal()
            .ok_or_else(|| VerificationEvidenceError::ArtifactCustody {
                detail: "capture journal has no durable TerminalPrepared payload".into(),
            })?;
    if capture.acquired() != Some(output_capture.acquired())
        || capture.finished_store_head() != Some(&evidence.output_capture.finished_store_head)
        || capture.published_store_head() != Some(&evidence.output_capture.published_store_head)
        || capture.terminal_prepared_store_head()
            != Some(&evidence.output_capture.terminal_prepared_store_head)
        || capture.expected_reference() != Some(&evidence.output_artifacts)
        || terminal_payload.schema != COMMAND_TERMINAL_CAPTURE_SCHEMA
        || terminal_payload.canonical_bytes != terminal_record_bytes
        || terminal_payload.canonical_bytes_digest != evidence.output_capture.terminal_record_digest
    {
        return mismatch(
            "runner.command_output_capture.journal",
            "durable acquisition, monotonic heads, artifact reference, or terminal payload differs from the exact request and response",
        );
    }
    let reopened = store.reopen(&evidence.output_artifacts).map_err(|error| {
        VerificationEvidenceError::ArtifactCustody {
            detail: format!("exact artifact reopen failed: {error}"),
        }
    })?;
    let mut stdout_prefix = RetainedPrefixVerifier::new(&evidence.stdout.retained_bytes);
    let mut stderr_prefix = RetainedPrefixVerifier::new(&evidence.stderr.retained_bytes);

    // Invoke both reads before interpreting either result. Successful
    // adaptation therefore scans and revalidates every raw byte while keeping
    // memory proportional only to the already-bounded retained prefixes.
    let stdout_result = reopened.copy_stdout_to(&mut stdout_prefix);
    let stderr_result = reopened.copy_stderr_to(&mut stderr_prefix);
    let stdout_length =
        stdout_result.map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("full stdout artifact verification failed: {error}"),
        })?;
    let stderr_length =
        stderr_result.map_err(|error| VerificationEvidenceError::ArtifactCustody {
            detail: format!("full stderr artifact verification failed: {error}"),
        })?;
    if stdout_length != evidence.output_artifacts.stdout.byte_length
        || stderr_length != evidence.output_artifacts.stderr.byte_length
    {
        return mismatch(
            "runner.command_output_artifacts.length",
            "physically read stream lengths differ from the immutable artifact reference",
        );
    }
    if !stdout_prefix.exact() {
        return mismatch(
            "runner.command_output_artifacts.stdout.retained_bytes",
            "wire-retained stdout is not the exact prefix of immutable raw stdout",
        );
    }
    if !stderr_prefix.exact() {
        return mismatch(
            "runner.command_output_artifacts.stderr.retained_bytes",
            "wire-retained stderr is not the exact prefix of immutable raw stderr",
        );
    }
    let final_private_state_digest =
        inspect_private_state_digest(private_state_root).map_err(|error| {
            VerificationEvidenceError::ArtifactCustody {
                detail: format!("cannot reauthenticate lifecycle private-state root: {error}"),
            }
        })?;
    if &final_private_state_digest != expected_private_state_digest {
        return Err(VerificationEvidenceError::ArtifactCustody {
            detail: "private-state root identity changed during artifact verification".into(),
        });
    }
    Ok(())
}

fn validate_effect_context(
    effect: &WireEffectContext,
    intent: &EffectIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<(), VerificationEvidenceError> {
    if effect.contract_version != intent.contract_version
        || effect.launch_id != session.launch_id
        || effect.effect_id != intent.effect_id
        || effect.idempotency_key != intent.idempotency_key
        || effect.sprint_id != intent.sprint_id
        || effect.task_id != intent.task_id
        || effect.worker_id != intent.worker_id
        || effect.worker_lease != intent.worker_lease
        || effect.policy_hash != intent.policy_hash
        || effect.input_snapshot != intent.input_snapshot
        || effect.request_digest != intent.request_digest
    {
        return mismatch(
            "runner.effect_context",
            "launch, effect, idempotency, task/worker/lease scope, policy, input, or request digest differs",
        );
    }
    Ok(())
}

fn validate_transport_commitment(
    exchange: &RunnerEffectResponse,
    effect: &WireEffectContext,
) -> Result<(), VerificationEvidenceError> {
    let computed = exchange
        .request
        .computed_transport_commitment_digest()
        .map_err(|error| wire_error(&error))?;
    if effect.transport_commitment_digest != computed {
        return mismatch(
            "runner.transport_commitment_digest",
            "does not commit the exact nonce, ordering, effect context, and command request",
        );
    }
    Ok(())
}

fn validate_wire_command(
    wire: &WireCommandSpec,
    command: &CommandSpec,
) -> Result<(), VerificationEvidenceError> {
    let working_directory =
        command
            .working_directory
            .to_str()
            .ok_or(VerificationEvidenceError::NonUtf8Path {
                field: "command.working_directory",
            })?;
    if wire.program != command.program
        || wire.arguments != command.arguments
        || wire.working_directory != working_directory
    {
        return mismatch(
            "runner.command",
            "wire program, argument vector, or working directory differs from the durable command",
        );
    }
    Ok(())
}

fn require_utf8_path(path: &Path, field: &'static str) -> Result<(), VerificationEvidenceError> {
    if path.to_str().is_none() {
        return Err(VerificationEvidenceError::NonUtf8Path { field });
    }
    Ok(())
}

fn mismatch<T>(field: &'static str, detail: &'static str) -> Result<T, VerificationEvidenceError> {
    Err(VerificationEvidenceError::Mismatch { field, detail })
}

fn contract_error(entity: &'static str, error: &ContractError) -> VerificationEvidenceError {
    VerificationEvidenceError::Contract {
        entity,
        detail: error.to_string(),
    }
}

fn wire_error(error: &WireProtocolError) -> VerificationEvidenceError {
    VerificationEvidenceError::Wire {
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CommandOutputArtifactSetReferenceV1, CommandOutputArtifactSourceV1,
        CommandOutputCaptureIntentV1, CommandOutputCaptureStoreHeadV1, PathScope,
        SensitiveOutputDetectionPolicyReferenceV1, WorkerLease, WorkspaceGrantIssuer,
        WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use grok_build_runner::{
        CommandDomainCleanupBackend, RUNNER_WIRE_PROTOCOL_VERSION,
        RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequestEnvelope, RunnerRequestEnvelopeV12,
        RunnerRequestV12, RunnerResponseEnvelope, RunnerResponseEnvelopeV12, RunnerResponseV12,
        WireCommandBackendIdentity, WireCommandCleanupProof, WireCommandFailureCodeV12,
        WireCommandStreamEvidence, WireCommandTerminalEvidence, WireFailureClass,
        command_stream_output_digest,
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
    const DISPATCH_CLAIM_DOMAIN: &[u8] = b"grok-build/runner-effect-dispatch-claim/v1\0";
    const CLEANUP_EVIDENCE_PREFIX: &[u8] = b"grok-build.runner-command-domain-cleanup-proof.v1\0";
    const CLEANUP_EVIDENCE_JSON: &str = r#"{"schema_version":1,"backend":"linux_cgroup_v2","binding":{"runner_session_id":"verification-session","command_effect_id":"verification-effect","command_request_digest":"302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20"},"surviving_processes":0,"platform_evidence":{"kind":"linux_cgroup_v2","evidence":{"journal_record":{"state":"removed","native_launch":{"contract_version":1,"attempt_id":"linux-preparation-attempt-1","native_journal_id":"linux-native-journal-1","expected_platform_binding_digest":"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986","sprint_id":"sprint-linux-1","launch_id":"launch-linux-1","session_id":"verification-session","cleanup_effect_id":"cleanup-effect-linux-1","input_snapshot":"ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879","grant_hash":"e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71","policy_hash":"e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db","claimed_at_unix_ms":10},"runner_session_id":"verification-session","effect_id":"verification-effect","grant_hash":"e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71","policy_hash":"e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db","command_hash":"67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6","request_digest":"302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20","leaf_name":"gb-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_delegation_identity":{"device":11,"inode":12},"expected_owner_uid":501,"leaf_identity":{"device":41,"inode":42},"requested_limits":{"pids_max":8,"memory_max":"max","memory_swap_max":"max"},"read_back_limits":{"pids_max":8,"memory_max":"max","memory_swap_max":"max","memory_oom_group":true},"staged_launcher":null,"release_authorization":null,"release_binding":null,"release_intent_recorded":false,"release_observation":null,"cleanup_observations":[{"sequence":1,"attempt":1,"file":"cgroup_events","bytes":[112,111,112,117,108,97,116,101,100,32,48,10,102,114,111,122,101,110,32,48,10]},{"sequence":2,"attempt":1,"file":"cgroup_procs","bytes":[]},{"sequence":3,"attempt":1,"file":"cgroup_procs","bytes":[]}],"kill_value":[49,10]}}}}"#;

    fn cleanup_proof() -> WireCommandCleanupProof {
        let mut os_evidence_bytes = CLEANUP_EVIDENCE_PREFIX.to_vec();
        os_evidence_bytes.extend_from_slice(CLEANUP_EVIDENCE_JSON.as_bytes());
        WireCommandCleanupProof {
            os_evidence_digest: Digest::sha256(&os_evidence_bytes),
            os_evidence_bytes,
        }
    }

    fn command_terminal(
        store: &CapabilityCommandOutputStore,
        published: &PublishedFixtureCapture,
        complete_stdout: &[u8],
        retained_stdout: &[u8],
        termination: CommandTerminationV1,
    ) -> WireCommandTerminalEvidence {
        let stdout = WireCommandStreamEvidence {
            retained_bytes: retained_stdout.to_vec(),
            complete_digest: Digest::sha256(complete_stdout),
            complete_length: u64::try_from(complete_stdout.len()).expect("output length fits u64"),
            truncated: retained_stdout.len() < complete_stdout.len(),
        };
        let stderr = WireCommandStreamEvidence {
            retained_bytes: Vec::new(),
            complete_digest: Digest::sha256(&[]),
            complete_length: 0,
            truncated: false,
        };
        let output_digest = command_stream_output_digest(&stdout, &stderr);
        let acquired = published.output_capture.acquired();
        let provisional_terminal_head = CommandOutputCaptureStoreHeadV1 {
            generation: published
                .published_store_head
                .generation
                .checked_add(1)
                .expect("fixture terminal generation does not overflow"),
            record_digest: Digest::sha256(
                format!("pending-terminal-head-{}", acquired.capture_id).as_bytes(),
            ),
        };
        let output_capture = WireCommandOutputCaptureTerminalV1::try_new(
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            published.finished_store_head.clone(),
            published.published_store_head.clone(),
            provisional_terminal_head,
            published.output_artifacts.clone(),
            Digest::sha256(b"pending terminal-record digest"),
        )
        .expect("construct pre-journal command terminal");
        let mut terminal = WireCommandTerminalEvidence {
            output_capture,
            termination,
            stdout,
            stderr,
            output_artifacts: published.output_artifacts.clone(),
            output_digest,
            launch_digest: Digest::sha256(b"contained launch fixture"),
            preflight_digest: Digest::sha256(b"contained preflight fixture"),
            backend: WireCommandBackendIdentity {
                command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "fake-contained-v1".into(),
                implementation_digest: Digest::sha256(b"fake backend implementation"),
            },
            cleanup_proof: cleanup_proof(),
            duration_ms: 25,
        };
        terminal
            .bind_terminal_record_digest()
            .expect("bind canonical terminal record before journal append");
        let terminal_record = command_terminal_record_bytes(&terminal)
            .expect("construct canonical terminal journal payload");
        let recovery = store
            .prepare_capture_terminal(
                &acquired.capture_id,
                &published.published_store_head,
                COMMAND_TERMINAL_CAPTURE_SCHEMA,
                terminal_record.clone(),
            )
            .expect("persist exact TerminalPrepared payload");
        assert_eq!(recovery.acquired(), Some(acquired));
        assert_eq!(
            recovery.finished_store_head(),
            Some(&published.finished_store_head)
        );
        assert_eq!(
            recovery.published_store_head(),
            Some(&published.published_store_head)
        );
        assert_eq!(
            recovery.expected_reference(),
            Some(&published.output_artifacts)
        );
        let terminal_payload = recovery.terminal().expect("TerminalPrepared payload");
        assert_eq!(terminal_payload.schema, COMMAND_TERMINAL_CAPTURE_SCHEMA);
        assert_eq!(terminal_payload.canonical_bytes, terminal_record);
        assert_eq!(
            terminal_payload.canonical_bytes_digest,
            terminal.output_capture.terminal_record_digest
        );
        terminal.output_capture.terminal_prepared_store_head = recovery
            .terminal_prepared_store_head()
            .expect("TerminalPrepared head")
            .clone();
        terminal
            .validate_for_output_capture(&published.output_capture)
            .expect("final terminal binds exact acquired capture");
        terminal
    }

    struct PublishedFixtureCapture {
        capture_intent: CommandOutputCaptureIntentV1,
        output_capture: WireCommandOutputCaptureAnchorV1,
        output_artifacts: CommandOutputArtifactSetReferenceV1,
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        published_store_head: CommandOutputCaptureStoreHeadV1,
    }

    fn publish_output_capture(
        store: &CapabilityCommandOutputStore,
        session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> PublishedFixtureCapture {
        let maximum = u64::try_from(
            stdout_bytes
                .len()
                .checked_add(stderr_bytes.len())
                .expect("fixture output length does not overflow usize"),
        )
        .expect("fixture output length fits u64")
        .max(1);
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: session.sprint_id.clone(),
            runner_launch_id: session.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            effect_id: intent.effect_id.clone(),
            request_digest: intent.request_digest.clone(),
        };
        let capture_id =
            Digest::sha256(format!("{}:{}", intent.effect_id, intent.idempotency_key).as_bytes())
                .as_str()
                .to_owned();
        let capture_intent = CommandOutputCaptureIntentV1::try_new(
            capture_id,
            source,
            session.private_state_digest.clone(),
            maximum,
            intent.created_at_unix_ms,
        )
        .expect("construct exact fixture capture intent");
        let mut claim_preimage = Vec::from(DISPATCH_CLAIM_DOMAIN);
        claim_preimage.extend_from_slice(intent.effect_id.as_bytes());
        let dispatch_claim_id = Digest::sha256(&claim_preimage);
        let acquired = store
            .reserve_anchored_capture(
                &capture_intent,
                dispatch_claim_id.as_str(),
                intent.created_at_unix_ms + 1,
            )
            .expect("reserve journaled verification-output capture")
            .into_acquired_anchor_for_handoff()
            .expect("close exact acquired capture handoff");
        let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired)
            .expect("construct exact request capture anchor");
        let capture = store
            .reopen_anchored_capture(output_capture.acquired())
            .expect("reopen exact acquired capture for writing");
        let (mut stdout, mut stderr, mut publisher) = capture.split();
        publisher
            .record_launch_intended(
                "runner-native-launch/v1",
                br#"{"fixture":"verification-launch"}"#.to_vec(),
            )
            .expect("persist exact fixture LaunchIntended payload");
        stdout
            .append(stdout_bytes)
            .expect("append physical fixture stdout");
        stderr
            .append(stderr_bytes)
            .expect("append physical fixture stderr");
        let stdout = stdout.finish().expect("finish physical fixture stdout");
        let stderr = stderr.finish().expect("finish physical fixture stderr");
        let published_artifacts = publisher
            .publish(stdout, stderr)
            .expect("publish journaled verification-output artifacts");
        let finished_store_head = published_artifacts
            .capture_finished_store_head()
            .expect("published capture retains Finished head")
            .clone();
        let published_store_head = published_artifacts
            .capture_published_store_head()
            .expect("published capture retains Published head")
            .clone();
        let output_artifacts = published_artifacts.reference().clone();
        PublishedFixtureCapture {
            capture_intent,
            output_capture,
            output_artifacts,
            finished_store_head,
            published_store_head,
        }
    }

    struct Fixture {
        root: PathBuf,
        private_state_root: PathBuf,
        authority: IssuedWorkspaceGrant,
        session: RunnerSessionPolicyRecord,
        command: CommandSpec,
        intent: EffectIntent,
        capture_intent: CommandOutputCaptureIntentV1,
        exchange: RunnerEffectResponse,
        task_id: Option<String>,
    }

    impl Fixture {
        fn task_worker(output: &[u8]) -> Self {
            Self::new(
                RunnerSessionPurpose::TaskWorker,
                output,
                output,
                CommandTerminationV1::Exited { code: 0 },
            )
        }

        fn final_verifier(output: &[u8]) -> Self {
            Self::new(
                RunnerSessionPurpose::FinalVerifier,
                output,
                output,
                CommandTerminationV1::Exited { code: 0 },
            )
        }

        fn task_worker_with_termination(output: &[u8], termination: CommandTerminationV1) -> Self {
            Self::new(
                RunnerSessionPurpose::TaskWorker,
                output,
                output,
                termination,
            )
        }

        fn truncated_task_worker(complete_output: &[u8], retained_output: &[u8]) -> Self {
            Self::new(
                RunnerSessionPurpose::TaskWorker,
                complete_output,
                retained_output,
                CommandTerminationV1::Exited { code: 0 },
            )
        }

        fn truncated_task_worker_with_termination(
            complete_output: &[u8],
            retained_output: &[u8],
            termination: CommandTerminationV1,
        ) -> Self {
            Self::new(
                RunnerSessionPurpose::TaskWorker,
                complete_output,
                retained_output,
                termination,
            )
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the adversarial fixture keeps every authority identity independently visible"
        )]
        fn new(
            purpose: RunnerSessionPurpose,
            complete_output: &[u8],
            retained_output: &[u8],
            termination: CommandTerminationV1,
        ) -> Self {
            let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "grok-build-verification-evidence-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create verification fixture");
            let workspace = root.join("workspace");
            fs::create_dir(&workspace).expect("create verification workspace");
            let private_state_root = root.join("private-state");
            fs::create_dir(&private_state_root).expect("create verification private state");
            fs::set_permissions(&private_state_root, fs::Permissions::from_mode(0o700))
                .expect("secure verification private state");
            let private_state_root =
                fs::canonicalize(private_state_root).expect("canonical verification private state");
            let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: format!("grant-{unique}"),
                workspace_root: workspace,
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue workspace authority");
            let task_id =
                (purpose == RunnerSessionPurpose::TaskWorker).then(|| format!("task-{unique}"));
            let worker_id = task_id.as_ref().map(|_| format!("worker-{unique}"));
            let worker_lease =
                task_id
                    .as_ref()
                    .zip(worker_id.as_ref())
                    .map(|(task_id, worker_id)| {
                        WorkerLease::new(
                            format!("sprint-{unique}"),
                            1,
                            task_id.clone(),
                            worker_id.clone(),
                            vec![PathScope::Workspace],
                            90,
                        )
                        .expect("construct canonical verification worker lease")
                    });
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: format!("sprint-{unique}"),
                launch_id: format!("launch-{unique}"),
                session_id: "verification-session".into(),
                purpose,
                worker_id: worker_id.clone(),
                worker_lease: worker_lease.clone(),
                policy_hash: Digest::sha256(format!("policy-{unique}").as_bytes()),
                session_nonce: Digest::sha256(format!("nonce-{unique}").as_bytes()),
                runner_binary_digest: Digest::sha256(b"admitted runner binary"),
                protocol_digest: runner_protocol_digest(),
                private_state_digest: inspect_private_state_digest(&private_state_root)
                    .expect("authenticate verification private state"),
                grant_hash: authority.contract().grant_hash.clone(),
                policy_version: authority.contract().policy_version,
                registered_at_unix_ms: 100,
            };
            let command = CommandSpec {
                program: "/usr/bin/cargo".into(),
                arguments: vec!["test".into(), "--locked".into()],
                working_directory: PathBuf::from("fixture"),
            };
            let request_bytes = serde_json::to_vec(&command).expect("canonical command");
            assert_eq!(
                Digest::sha256(&request_bytes).as_str(),
                "302065194cfd5e2bebf7fb7d2cb39b98256c895a3910a20cab034b93ceb8de20"
            );
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: "verification-effect".into(),
                idempotency_key: format!("verification-key-{unique}"),
                sprint_id: session.sprint_id.clone(),
                task_id: task_id.clone(),
                worker_id,
                worker_lease,
                causation_event_id: None,
                correlation_id: format!("verification-correlation-{unique}"),
                kind: EffectKind::RunCommand,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: session.policy_hash.clone(),
                input_snapshot: Digest::sha256(format!("snapshot-{unique}").as_bytes()),
                created_at_unix_ms: 110,
            };
            let wire_command = WireCommandSpec {
                program: command.program.clone(),
                arguments: command.arguments.clone(),
                working_directory: command
                    .working_directory
                    .to_str()
                    .expect("UTF-8 fixture")
                    .into(),
            };
            let store = CapabilityCommandOutputStore::open(&private_state_root)
                .expect("open verification output store");
            let published = publish_output_capture(&store, &session, &intent, complete_output, &[]);
            let request = match purpose {
                RunnerSessionPurpose::TaskWorker => RunnerRequest::WorkerRunCommand {
                    command: wire_command,
                    output_capture: published.output_capture.clone(),
                },
                RunnerSessionPurpose::FinalVerifier => RunnerRequest::FinalVerifierRunCommand {
                    command: wire_command,
                    output_capture: published.output_capture.clone(),
                },
                RunnerSessionPurpose::Applier | RunnerSessionPurpose::LiveStateVerifier => {
                    unreachable!("fixture roles are closed")
                }
            };
            let response = RunnerResponse::CommandCompleted {
                evidence: command_terminal(
                    &store,
                    &published,
                    complete_output,
                    retained_output,
                    termination,
                ),
            };
            let exchange = effect_exchange(&session, &intent, request, response);
            Self {
                root,
                private_state_root,
                authority,
                session,
                command,
                intent,
                capture_intent: published.capture_intent,
                exchange,
                task_id,
            }
        }

        fn input<'a>(
            &'a self,
            exchange: &'a RunnerEffectResponse,
        ) -> VerificationEvidenceInput<'a> {
            VerificationEvidenceInput {
                exchange,
                intent: &self.intent,
                runner_session: &self.session,
                private_state_root: &self.private_state_root,
                authority: &self.authority,
                command: &self.command,
                task_id: self.task_id.as_deref(),
                receipt_id: "verification-receipt",
                observation_id: "verification-observation",
                observed_at_unix_ms: 120,
            }
        }

        fn artifact_directory(&self) -> PathBuf {
            let directories = fs::read_dir(&self.private_state_root)
                .expect("read fixture private-state root")
                .map(|entry| entry.expect("read fixture artifact entry"))
                .filter(|entry| {
                    entry
                        .file_type()
                        .expect("read fixture artifact file type")
                        .is_dir()
                        && entry.path().join("manifest.json").is_file()
                })
                .collect::<Vec<_>>();
            assert_eq!(directories.len(), 1, "fixture has one published artifact");
            directories[0].path()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn effect_exchange(
        session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        request: RunnerRequest,
        response: RunnerResponse,
    ) -> RunnerEffectResponse {
        let mut request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            runner_nonce: Some(session.session_nonce.clone()),
            sequence: 1,
            request_id: "verification-effect-request".into(),
            effect: Some(WireEffectContext {
                contract_version: grok_build_core::CONTRACT_VERSION,
                launch_id: session.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: intent.task_id.clone(),
                worker_id: intent.worker_id.clone(),
                worker_lease: intent.worker_lease.clone(),
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(b"placeholder"),
            }),
            request,
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind transport commitment");
        let response = RunnerResponseEnvelope {
            protocol_version: request.protocol_version,
            session_id: request.session_id.clone(),
            runner_nonce: session.session_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            response,
        };
        RunnerEffectResponse { request, response }
    }

    #[test]
    fn task_worker_builds_exact_canonical_verification_evidence() {
        let fixture = Fixture::task_worker(b"all tests passed\n");
        let adapted = adapt_verification_evidence(fixture.input(&fixture.exchange))
            .expect("adapt task verification");
        assert_eq!(adapted.receipt().task_id, fixture.task_id);
        assert!(adapted.receipt().passed());
        let RunnerResponse::CommandCompleted { evidence } = &fixture.exchange.response.response
        else {
            unreachable!("fixture command response")
        };
        assert_eq!(
            adapted.evidence.output_evidence_bytes,
            command_stream_output_evidence_bytes(&evidence.stdout, &evidence.stderr)
        );
        assert_eq!(adapted.receipt().duration_ms, evidence.duration_ms);
        assert_eq!(
            adapted.command_terminal().output_capture(),
            &evidence.output_capture
        );
        assert_eq!(adapted.command_terminal().backend(), &evidence.backend);
        assert_eq!(
            adapted.command_terminal().cleanup_proof(),
            &evidence.cleanup_proof
        );
        assert_eq!(
            adapted.canonical_evidence.bytes,
            serde_json::to_vec(&adapted.evidence).expect("canonical evidence")
        );
        assert_eq!(
            adapted.canonical_evidence.digest,
            Digest::sha256(&adapted.canonical_evidence.bytes)
        );
    }

    #[test]
    fn missing_physical_output_artifact_rejects_current_verification() {
        let fixture = Fixture::task_worker(b"physical stdout\n");
        fs::remove_dir_all(fixture.artifact_directory()).expect("remove fixture artifact");
        assert!(matches!(
            adapt_verification_evidence(fixture.input(&fixture.exchange)),
            Err(VerificationEvidenceError::ArtifactCustody { .. })
        ));
    }

    #[test]
    fn tampered_physical_output_bytes_reject_current_verification() {
        let fixture = Fixture::task_worker(b"physical stdout\n");
        let stdout_path = fixture.artifact_directory().join("stdout.raw");
        let mut tampered = fs::read(&stdout_path).expect("read physical fixture stdout");
        tampered[0] ^= 1;
        fs::write(stdout_path, tampered).expect("tamper physical fixture stdout");
        assert!(matches!(
            adapt_verification_evidence(fixture.input(&fixture.exchange)),
            Err(VerificationEvidenceError::ArtifactCustody { .. })
        ));
    }

    #[test]
    fn crossed_private_state_root_rejects_current_verification() {
        let fixture = Fixture::task_worker(b"physical stdout\n");
        let crossed = Fixture::task_worker(b"crossed physical stdout\n");
        let mut input = fixture.input(&fixture.exchange);
        input.private_state_root = &crossed.private_state_root;
        assert!(matches!(
            adapt_verification_evidence(input),
            Err(VerificationEvidenceError::ArtifactCustody { .. })
        ));
    }

    #[test]
    fn noncanonical_physical_manifest_rejects_current_verification() {
        let fixture = Fixture::task_worker(b"physical stdout\n");
        let manifest_path = fixture.artifact_directory().join("manifest.json");
        let mut noncanonical = fs::read(&manifest_path).expect("read physical fixture manifest");
        noncanonical.push(b'\n');
        fs::write(manifest_path, noncanonical).expect("make fixture manifest noncanonical");
        assert!(matches!(
            adapt_verification_evidence(fixture.input(&fixture.exchange)),
            Err(VerificationEvidenceError::ArtifactCustody { .. })
        ));
    }

    #[test]
    fn retained_prefix_must_match_physical_raw_output() {
        let fixture = Fixture::truncated_task_worker(b"complete physical stdout", b"xomplete");
        let error = adapt_verification_evidence(fixture.input(&fixture.exchange))
            .expect_err("substituted retained prefix must fail physical comparison");
        assert!(matches!(
            error,
            VerificationEvidenceError::Mismatch {
                field: "runner.command_output_artifacts.stdout.retained_bytes",
                ..
            }
        ));
    }

    #[test]
    fn silent_final_verifier_retains_nonempty_complete_stream_commitment() {
        let fixture = Fixture::final_verifier(&[]);
        let adapted = adapt_verification_evidence(fixture.input(&fixture.exchange))
            .expect("adapt silent final verification");
        assert_eq!(adapted.receipt().task_id, None);
        assert!(!adapted.evidence.output_evidence_bytes.is_empty());
        let RunnerResponse::CommandCompleted { evidence } = &fixture.exchange.response.response
        else {
            unreachable!("fixture command response")
        };
        assert_eq!(adapted.receipt().output_digest, evidence.output_digest);
    }

    #[test]
    fn nonzero_command_exit_is_evidence_but_not_a_passing_receipt() {
        let fixture = Fixture::task_worker_with_termination(
            b"test failed\n",
            CommandTerminationV1::Exited { code: 7 },
        );
        let adapted = adapt_verification_evidence(fixture.input(&fixture.exchange))
            .expect("adapt executed failing verification");
        assert_eq!(adapted.receipt().exit_status, Some(7));
        assert_eq!(
            adapted.receipt().termination,
            Some(CommandTerminationV1::Exited { code: 7 })
        );
        assert!(!adapted.receipt().passed());
    }

    #[test]
    fn v12_failure_never_infers_verification_from_terminal_capture_state() {
        let fixture = Fixture::task_worker(b"physically published but not verified\n");
        let store = CapabilityCommandOutputStore::open(&fixture.private_state_root)
            .expect("reopen exact private capture store");
        assert_eq!(
            store
                .capture_state(&fixture.capture_intent.capture_id)
                .expect("reopen exact v1 terminal state"),
            grok_build_runner::CommandOutputCaptureJournalStateV1::TerminalPrepared,
            "the adversarial fixture starts with physically terminal capture state"
        );

        let legacy = &fixture.exchange.request;
        let detector_policy = SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let mut request = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: legacy.session_id.clone(),
            runner_nonce: legacy
                .runner_nonce
                .clone()
                .expect("command fixture has exact runner nonce"),
            sequence: legacy.sequence,
            request_id: legacy.request_id.clone(),
            effect: legacy
                .effect
                .clone()
                .expect("command fixture has exact effect context"),
            request: RunnerRequestV12::RunCommand {
                request: legacy.request.clone(),
                detector_policy: detector_policy.clone(),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind exact v12 request commitment");
        let response = RunnerResponseEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            response: RunnerResponseV12::CommandFailed {
                containment_refusal: None,
                detector_policy,
                class: WireFailureClass::AfterKnownEffect,
                code: WireCommandFailureCodeV12::InternalFailure,
                reconciliation: None,
            },
        };
        let exchange = RunnerCommandEffectResponse { request, response };
        let command_bytes =
            serde_json::to_vec(&fixture.command).expect("encode exact core command");
        let adapted = adapt_verification_response_v12(
            CommandV12ResponseInput {
                exchange: &exchange,
                intent: &fixture.intent,
                runner_session: &fixture.session,
                private_state_root: &fixture.private_state_root,
                authority: &fixture.authority,
                command: &fixture.command,
                capture_intent: &fixture.capture_intent,
                core_request_bytes: &command_bytes,
                task_id: fixture.task_id.as_deref(),
                observation_id: "v12-typed-failure-observation",
                observed_at_unix_ms: 120,
            },
            "must-not-exist-verification-receipt",
        )
        .expect("typed v12 failure remains a typed non-verification result");
        assert!(matches!(
            adapted,
            AdaptedVerificationResponseV12::Failed(AdaptedCommandFailureV12 {
                class: WireFailureClass::AfterKnownEffect,
                code: WireCommandFailureCodeV12::InternalFailure,
                reconciliation: None,
                containment_refusal: None,
            })
        ));
    }

    /// Builds the exact `ContainmentUnavailable` exchange the live runner emits,
    /// optionally carrying live kernel-read absence evidence.
    fn containment_refusal_exchange(
        fixture: &Fixture,
        refusal: Option<Box<grok_build_runner::WireContainmentRefusalEvidenceV12>>,
    ) -> RunnerCommandEffectResponse {
        let legacy = &fixture.exchange.request;
        let detector_policy = SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let mut request = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: legacy.session_id.clone(),
            runner_nonce: legacy
                .runner_nonce
                .clone()
                .expect("command fixture has exact runner nonce"),
            sequence: legacy.sequence,
            request_id: legacy.request_id.clone(),
            effect: legacy
                .effect
                .clone()
                .expect("command fixture has exact effect context"),
            request: RunnerRequestV12::RunCommand {
                request: legacy.request.clone(),
                detector_policy: detector_policy.clone(),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind exact v12 request commitment");
        let response = RunnerResponseEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: request.session_id.clone(),
            runner_nonce: request.runner_nonce.clone(),
            sequence: request.sequence,
            request_id: request.request_id.clone(),
            effect: request.effect.clone(),
            response: RunnerResponseV12::CommandFailed {
                detector_policy,
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                reconciliation: None,
                containment_refusal: refusal,
            },
        };
        RunnerCommandEffectResponse { request, response }
    }

    fn adapt_containment_refusal(
        fixture: &Fixture,
        exchange: &RunnerCommandEffectResponse,
    ) -> Result<AdaptedCommandResponseV12, VerificationEvidenceError> {
        let command_bytes =
            serde_json::to_vec(&fixture.command).expect("encode exact core command");
        adapt_command_response_v12(CommandV12ResponseInput {
            exchange,
            intent: &fixture.intent,
            runner_session: &fixture.session,
            private_state_root: &fixture.private_state_root,
            authority: &fixture.authority,
            command: &fixture.command,
            capture_intent: &fixture.capture_intent,
            core_request_bytes: &command_bytes,
            task_id: fixture.task_id.as_deref(),
            observation_id: "containment-refusal-observation",
            observed_at_unix_ms: 120,
        })
    }

    #[cfg(target_os = "linux")]
    fn fixture_acquired(fixture: &Fixture) -> CommandOutputCaptureAcquiredV1 {
        match &fixture.exchange.request.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => panic!("command fixture must carry capture authority"),
        }
    }

    /// The containment refusal is now backed by evidence the desktop reopens
    /// for itself, and those exact bytes close the `NoDomainCreatedBeforeEffect`
    /// disposition. The failure class and code are untouched, so the refusal
    /// still means exactly what it meant before -- it is simply no longer taken
    /// on trust.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_containment_refusal_closes_the_no_domain_disposition_on_evidence() {
        let fixture = Fixture::task_worker(b"unused output\n");
        let acquired = fixture_acquired(&fixture);
        let Some(refusal) = grok_build_runner::live_containment_refusal_evidence_v12(
            &fixture.session.session_id,
            &fixture.intent.effect_id,
            &fixture.intent.request_digest,
            &acquired.capture_id,
            acquired.store_head.clone(),
        ) else {
            // This binary also exercises process launch, and a process that has
            // created a child cannot answer the absence question. The
            // unconditional positive proof lives in the runner's dedicated
            // fork-free binary; here the fail-closed half is the assertion.
            let exchange = containment_refusal_exchange(&fixture, None);
            let adapted = adapt_containment_refusal(&fixture, &exchange)
                .expect("an evidence-free refusal must still adapt");
            assert!(matches!(
                adapted,
                AdaptedCommandResponseV12::Failed(AdaptedCommandFailureV12 {
                    containment_refusal: None,
                    ..
                })
            ));
            return;
        };
        let exchange = containment_refusal_exchange(&fixture, Some(Box::new(refusal)));
        let adapted = adapt_containment_refusal(&fixture, &exchange)
            .expect("a self-consistent refusal must adapt");
        let AdaptedCommandResponseV12::Failed(failure) = adapted else {
            panic!("a containment refusal is a typed failure, never a terminal")
        };
        assert_eq!(failure.class, WireFailureClass::BeforeEffect);
        assert_eq!(
            failure.code,
            WireCommandFailureCodeV12::ContainmentUnavailable
        );
        let validated = failure
            .containment_refusal
            .expect("the desktop must surface the evidence it revalidated");
        assert_eq!(validated.capture_id, acquired.capture_id);
        assert_eq!(validated.untouched_store_head, acquired.store_head);
        assert_eq!(
            validated.command_domain_backend,
            CommandDomainBackend::LinuxCgroupV2
        );

        // These exact bytes form the durable no-domain proof; no desktop-invented
        // field contributes authority.
        let proof = CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: "command-capture-no-domain-evidence-test".into(),
            sprint_id: fixture.capture_intent.source.sprint_id.clone(),
            launch_id: fixture.capture_intent.source.runner_launch_id.clone(),
            session_id: fixture.capture_intent.source.runner_session_id.clone(),
            effect_id: fixture.intent.effect_id.clone(),
            observation_id: None,
            request_digest: fixture.intent.request_digest.clone(),
            backend: validated.command_domain_backend,
            disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            surviving_processes: 0,
            platform_proof_digest: validated.no_domain_proof_digest.clone(),
            platform_proof_bytes: validated.no_domain_proof_bytes.clone(),
            cleaned_at_unix_ms: 121,
        };
        proof
            .validate()
            .expect("runner-read absence bytes close the disposition");
    }

    /// Evidence the desktop cannot reopen against its own authority fails the
    /// whole response. It is never silently dropped, because a refusal that
    /// carried a forged attachment is not the refusal it claims to be.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_crossed_containment_refusal_fails_the_response() {
        let fixture = Fixture::task_worker(b"unused output\n");
        let acquired = fixture_acquired(&fixture);
        let Some(honest) = grok_build_runner::live_containment_refusal_evidence_v12(
            &fixture.session.session_id,
            &fixture.intent.effect_id,
            &fixture.intent.request_digest,
            &acquired.capture_id,
            acquired.store_head.clone(),
        ) else {
            return;
        };

        // One input differs: the proof inside was read for another effect.
        let crossed_effect = grok_build_runner::live_containment_refusal_evidence_v12(
            &fixture.session.session_id,
            "another-command-effect",
            &fixture.intent.request_digest,
            &acquired.capture_id,
            acquired.store_head.clone(),
        )
        .expect("absence answers for a second binding");
        let exchange = containment_refusal_exchange(&fixture, Some(Box::new(crossed_effect)));
        assert!(
            adapt_containment_refusal(&fixture, &exchange).is_err(),
            "a proof bound to another effect must fail the response"
        );

        // One input differs: the head is not the acquired reservation.
        let mut crossed_head = honest.clone();
        crossed_head.untouched_store_head.generation =
            acquired.store_head.generation.saturating_add(1);
        let exchange = containment_refusal_exchange(&fixture, Some(Box::new(crossed_head)));
        assert!(
            adapt_containment_refusal(&fixture, &exchange).is_err(),
            "a head that is not the acquired reservation must fail the response"
        );

        // One input differs: the retained bytes were altered after minting.
        let mut tampered = honest;
        tampered.no_domain_proof_bytes.push(b'\n');
        let exchange = containment_refusal_exchange(&fixture, Some(Box::new(tampered)));
        assert!(
            adapt_containment_refusal(&fixture, &exchange).is_err(),
            "bytes that no longer match their digest must fail the response"
        );
    }

    /// A refusal that carries nothing still adapts exactly as it always did, so
    /// the evidence is additive and a host that cannot read its own absence
    /// answers is not newly broken.
    #[test]
    fn a_refusal_without_evidence_adapts_exactly_as_before() {
        let fixture = Fixture::task_worker(b"unused output\n");
        let exchange = containment_refusal_exchange(&fixture, None);
        let adapted = adapt_containment_refusal(&fixture, &exchange)
            .expect("an evidence-free refusal must still adapt");
        assert!(matches!(
            adapted,
            AdaptedCommandResponseV12::Failed(AdaptedCommandFailureV12 {
                class: WireFailureClass::BeforeEffect,
                code: WireCommandFailureCodeV12::ContainmentUnavailable,
                reconciliation: None,
                containment_refusal: None,
            })
        ));
    }

    #[test]
    fn every_non_exit_terminal_is_typed_nonpassing_evidence() {
        for termination in [
            CommandTerminationV1::Signaled { signal: 9 },
            CommandTerminationV1::TimedOut,
            CommandTerminationV1::Canceled,
        ] {
            let fixture = Fixture::task_worker_with_termination(b"partial output\n", termination);
            let adapted = adapt_verification_evidence(fixture.input(&fixture.exchange))
                .expect("adapt typed non-exit verification");
            assert_eq!(adapted.receipt().termination, Some(termination));
            assert_eq!(adapted.receipt().exit_status, None);
            assert!(!adapted.receipt().passed());
        }

        let fixture = Fixture::truncated_task_worker_with_termination(
            b"retained prefix omitted suffix",
            b"retained prefix",
            CommandTerminationV1::OutputLimitExceeded,
        );
        let adapted = adapt_verification_evidence(fixture.input(&fixture.exchange))
            .expect("adapt output-limit verification");
        assert_eq!(
            adapted.receipt().termination,
            Some(CommandTerminationV1::OutputLimitExceeded)
        );
        assert_eq!(adapted.receipt().exit_status, None);
        assert!(!adapted.receipt().passed());
    }

    #[test]
    fn crossed_registered_nonce_is_rejected_even_when_wire_is_correlated() {
        let fixture = Fixture::task_worker(b"output");
        let mut exchange = fixture.exchange.clone();
        let crossed = Digest::sha256(b"crossed nonce");
        exchange.request.runner_nonce = Some(crossed.clone());
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed commitment");
        exchange.response.runner_nonce = crossed;
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("crossed registered nonce must fail");
        assert!(matches!(
            error,
            VerificationEvidenceError::Mismatch {
                field: "runner.session",
                ..
            }
        ));
    }

    #[test]
    fn crossed_command_is_rejected_at_wire_request_digest_boundary() {
        let fixture = Fixture::task_worker(b"output");
        let mut exchange = fixture.exchange.clone();
        let RunnerRequest::WorkerRunCommand { command, .. } = &mut exchange.request.request else {
            unreachable!("fixture worker command")
        };
        command.arguments.push("--ignored".into());
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed command");
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("crossed command must fail");
        assert!(matches!(error, VerificationEvidenceError::Wire { .. }));
    }

    #[test]
    fn crossed_command_output_capture_is_rejected_even_when_transport_is_rebound() {
        let fixture = Fixture::task_worker(b"output");
        let crossed = Fixture::task_worker(b"crossed output");
        let crossed_output_capture = match &crossed.exchange.request.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. } => output_capture.clone(),
            _ => unreachable!("crossed fixture worker command"),
        };
        let mut exchange = fixture.exchange.clone();
        let RunnerRequest::WorkerRunCommand { output_capture, .. } = &mut exchange.request.request
        else {
            unreachable!("fixture worker command")
        };
        *output_capture = crossed_output_capture;
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed output-capture commitment");
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("crossed output capture must fail exact response correlation");
        assert!(matches!(error, VerificationEvidenceError::Wire { .. }));
    }

    #[test]
    fn crossed_wire_worker_lease_is_rejected_even_when_transport_is_rebound() {
        let fixture = Fixture::task_worker(b"output");
        let durable_lease = fixture
            .intent
            .worker_lease
            .as_ref()
            .expect("task-worker fixture lease");
        let crossed = WorkerLease::new(
            durable_lease.sprint_id.clone(),
            durable_lease.lease_epoch + 1,
            durable_lease.task_id.clone(),
            durable_lease.worker_id.clone(),
            durable_lease.path_scopes.clone(),
            durable_lease.acquired_at_unix_ms + 1,
        )
        .expect("construct crossed canonical worker lease");
        let mut exchange = fixture.exchange.clone();
        exchange
            .request
            .effect
            .as_mut()
            .expect("wire effect context")
            .worker_lease = Some(crossed);
        exchange
            .request
            .bind_transport_commitment_digest()
            .expect("rebind crossed wire commitment");
        exchange.response.effect = exchange.request.effect.clone();
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("crossed wire lease must not adapt");
        assert!(matches!(
            error,
            VerificationEvidenceError::Mismatch {
                field: "runner.effect_context",
                ..
            }
        ));
    }

    #[test]
    fn forged_complete_output_digest_is_rejected_by_wire_validation() {
        let fixture = Fixture::task_worker(b"output");
        let mut exchange = fixture.exchange.clone();
        let RunnerResponse::CommandCompleted { evidence } = &mut exchange.response.response else {
            unreachable!("fixture command output")
        };
        evidence.output_digest = Digest::sha256(b"forged output digest");
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("forged output digest must fail");
        assert!(matches!(error, VerificationEvidenceError::Wire { .. }));
    }

    #[test]
    fn final_verification_cannot_use_a_task_worker_session() {
        let fixture = Fixture::task_worker(b"output");
        let mut input = fixture.input(&fixture.exchange);
        input.task_id = None;
        let error = adapt_verification_evidence(input)
            .expect_err("task worker cannot authorize final verification");
        assert!(matches!(
            error,
            VerificationEvidenceError::Mismatch {
                field: "effect.verification_scope",
                ..
            }
        ));
    }

    #[test]
    fn durable_intent_must_hash_the_exact_canonical_command() {
        let fixture = Fixture::task_worker(b"output");
        let mut intent = fixture.intent.clone();
        intent.request_digest = Digest::sha256(b"crossed durable command");
        let input = VerificationEvidenceInput {
            intent: &intent,
            ..fixture.input(&fixture.exchange)
        };
        let error = adapt_verification_evidence(input)
            .expect_err("crossed durable request digest must fail");
        assert!(matches!(
            error,
            VerificationEvidenceError::Mismatch {
                field: "effect_intent.request_digest",
                ..
            }
        ));
    }

    #[test]
    fn transport_commitment_cannot_be_replaced_even_when_echoed() {
        let fixture = Fixture::task_worker(b"output");
        let mut exchange = fixture.exchange.clone();
        let forged = Digest::sha256(b"forged transport commitment");
        exchange
            .request
            .effect
            .as_mut()
            .expect("effect context")
            .transport_commitment_digest = forged.clone();
        exchange
            .response
            .effect
            .as_mut()
            .expect("response effect context")
            .transport_commitment_digest = forged;
        let error = adapt_verification_evidence(fixture.input(&exchange))
            .expect_err("forged transport commitment must fail");
        assert!(matches!(error, VerificationEvidenceError::Wire { .. }));
    }
}
