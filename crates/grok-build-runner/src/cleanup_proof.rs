//! Canonical, restart-validatable cleanup evidence for one command domain.
//!
//! A command-domain proof is only one input to runner-launch cleanup. It does
//! not prove that the runner process exited, that every command effect for the
//! launch is represented, or that a core worker-cleanup receipt may be issued.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use grok_build_core::{CommandDomainCleanupDisposition, CommandSpec, Digest};
use serde::{Deserialize, Serialize};

use crate::command_domain_absence::LinuxCommandDomainAbsenceObservationV1;
use crate::linux_containment::{
    CgroupCleanupEvidence, DomainJournalRecord, evidence_from_removed_record,
};
use crate::macos_helper_lifecycle::cleanup_evidence as macos_evidence_from_cleaned_record;
use crate::macos_helper_protocol::{MacosCleanupEvidence, MacosHelperJournalRecord};

const COMMAND_DOMAIN_EVIDENCE_VERSION: u32 = 1;
const COMMAND_DOMAIN_EVIDENCE_PREFIX: &[u8] =
    b"grok-build.runner-command-domain-cleanup-proof.v1\0";
const MAX_BINDING_ID_BYTES: usize = 256;

/// Maximum canonical bytes retained for one command-domain cleanup proof.
///
/// This equals the core envelope bound so a single domain proof can never
/// exceed the eventual receipt's byte limit. Multiple proofs still require a
/// separately designed launch-level aggregate rather than concatenation.
pub const MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES: usize = 1_048_576;

/// Closed platform backends that can prove one complete command domain empty.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandDomainCleanupBackend {
    /// Delegated Linux cgroup-v2 domain with kill, stable-empty, and removal evidence.
    LinuxCgroupV2,
    /// Dedicated macOS identity with creation seal, stable-empty, and release evidence.
    MacOsDedicatedIdentity,
}

/// Immutable binding from one cleanup proof to one exact command effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandDomainCleanupBinding {
    runner_session_id: String,
    command_effect_id: String,
    command_request_digest: Digest,
}

impl CommandDomainCleanupBinding {
    /// Validates and constructs a non-authoritative command-effect binding.
    ///
    /// This value identifies the durable command request a platform journal
    /// must match; it is not cleanup evidence by itself.
    ///
    /// # Errors
    ///
    /// Returns an error when either identifier is empty, oversized, or
    /// contains ASCII whitespace/control bytes.
    pub fn try_new(
        runner_session_id: impl Into<String>,
        command_effect_id: impl Into<String>,
        command_request_digest: Digest,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        let binding = Self {
            runner_session_id: runner_session_id.into(),
            command_effect_id: command_effect_id.into(),
            command_request_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Returns the runner session that owned the command effect.
    #[must_use]
    pub fn runner_session_id(&self) -> &str {
        &self.runner_session_id
    }

    /// Returns the exact command effect whose domain was cleaned.
    #[must_use]
    pub fn command_effect_id(&self) -> &str {
        &self.command_effect_id
    }

    /// Returns the digest of the exact canonical command request.
    #[must_use]
    pub const fn command_request_digest(&self) -> &Digest {
        &self.command_request_digest
    }

    fn validate(&self) -> Result<(), CommandDomainCleanupProofError> {
        validate_binding_id("runner_session_id", &self.runner_session_id)?;
        validate_binding_id("command_effect_id", &self.command_effect_id)
    }
}

/// Validated canonical OS evidence that one command domain has zero survivors.
///
/// Fields are private and the type has no arbitrary-field constructor or
/// deserializer. Production construction is available only to the runner's
/// validated Linux and macOS platform candidates. Durable readback requires
/// the expected digest, backend, and exact command-effect binding.
///
/// This is deliberately not a `WorkerCleanupEvidence`: a coordinator must
/// still prove the exact command-effect set for the launch and independently
/// observe the direct runner process exit before creating launch-level cleanup
/// evidence.
/// Two dispositions can hold zero survivors for opposite reasons: a domain that
/// existed and was reaped, and a domain that never existed. Both are recorded
/// here, and the disposition is derived from the platform evidence variant
/// rather than supplied by a caller, so a consumer that requires one can never
/// silently accept the other. Every pre-existing consumer requires
/// [`CommandDomainCleanupDisposition::ReapedZeroSurvivors`] explicitly.
#[must_use = "a command-domain proof is only a launch-cleanup input and must be durably bound by the coordinator"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCommandDomainCleanupProof {
    backend: CommandDomainCleanupBackend,
    disposition: CommandDomainCleanupDisposition,
    binding: CommandDomainCleanupBinding,
    surviving_processes: u64,
    os_evidence_bytes: Vec<u8>,
    os_evidence_digest: Digest,
}

impl ValidatedCommandDomainCleanupProof {
    /// Reopens exact persisted bytes and rejects digest, backend, request,
    /// canonical-encoding, or platform-evidence substitution.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, truncated, noncanonical, or
    /// semantically invalid evidence, or when any expected binding differs.
    pub fn readback(
        os_evidence_bytes: &[u8],
        expected_digest: &Digest,
        expected_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        validate_evidence_length(os_evidence_bytes)?;
        if Digest::sha256(os_evidence_bytes) != *expected_digest {
            return Err(CommandDomainCleanupProofError::DigestMismatch);
        }
        let decoded = decode_evidence(os_evidence_bytes)?;
        let proof = Self {
            backend: decoded.backend,
            disposition: decoded.disposition,
            binding: decoded.binding,
            surviving_processes: decoded.surviving_processes,
            os_evidence_bytes: os_evidence_bytes.to_vec(),
            os_evidence_digest: expected_digest.clone(),
        };
        proof.validate_expected(expected_digest, expected_backend, expected_binding)?;
        Ok(proof)
    }

    /// Reopens exact persisted bytes and additionally requires one exact
    /// resource-cleanup disposition.
    ///
    /// A caller that needs a reaped domain must not accept a proof that no
    /// domain was created, and the reverse. Every call site states which one it
    /// means rather than inferring it from the zero survivor count, which both
    /// dispositions share.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDomainCleanupProofError::ExpectedDispositionMismatch`]
    /// when the decoded platform evidence supports a different disposition, and
    /// otherwise every error [`Self::readback`] returns.
    pub fn readback_with_disposition(
        os_evidence_bytes: &[u8],
        expected_digest: &Digest,
        expected_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        expected_disposition: CommandDomainCleanupDisposition,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        let proof = Self::readback(
            os_evidence_bytes,
            expected_digest,
            expected_backend,
            expected_binding,
        )?;
        proof.require_disposition(expected_disposition)?;
        Ok(proof)
    }

    /// Rejects a proof whose platform evidence supports a different closed
    /// resource-cleanup disposition.
    ///
    /// # Errors
    ///
    /// Returns [`CommandDomainCleanupProofError::ExpectedDispositionMismatch`]
    /// on any difference.
    pub fn require_disposition(
        &self,
        expected: CommandDomainCleanupDisposition,
    ) -> Result<(), CommandDomainCleanupProofError> {
        if self.disposition == expected {
            Ok(())
        } else {
            Err(CommandDomainCleanupProofError::ExpectedDispositionMismatch)
        }
    }

    /// Revalidates this proof's digest, canonical bytes, platform journal, and
    /// exact redundant fields.
    ///
    /// # Errors
    ///
    /// Returns an error if any retained field differs from independently
    /// decoded and platform-validated evidence.
    pub fn validate(&self) -> Result<(), CommandDomainCleanupProofError> {
        self.binding.validate()?;
        validate_evidence_length(&self.os_evidence_bytes)?;
        if Digest::sha256(&self.os_evidence_bytes) != self.os_evidence_digest {
            return Err(CommandDomainCleanupProofError::DigestMismatch);
        }
        let decoded = decode_evidence(&self.os_evidence_bytes)?;
        if decoded.backend != self.backend
            || decoded.disposition != self.disposition
            || decoded.binding != self.binding
            || decoded.surviving_processes != self.surviving_processes
        {
            return Err(CommandDomainCleanupProofError::ReadbackMismatch);
        }
        Ok(())
    }

    /// Revalidates the proof and compares it with durable coordinator state.
    ///
    /// # Errors
    ///
    /// Returns an error when self-validation fails or the expected digest,
    /// backend, or command-effect binding differs.
    pub fn validate_expected(
        &self,
        expected_digest: &Digest,
        expected_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<(), CommandDomainCleanupProofError> {
        self.validate()?;
        expected_binding.validate()?;
        if &self.os_evidence_digest != expected_digest {
            return Err(CommandDomainCleanupProofError::DigestMismatch);
        }
        if self.backend != expected_backend {
            return Err(CommandDomainCleanupProofError::ExpectedBackendMismatch);
        }
        if &self.binding != expected_binding {
            return Err(CommandDomainCleanupProofError::ExpectedBindingMismatch);
        }
        Ok(())
    }

    /// Returns the platform accounting backend for this command domain.
    #[must_use]
    pub const fn backend(&self) -> CommandDomainCleanupBackend {
        self.backend
    }

    /// Returns the closed resource-cleanup disposition this evidence supports.
    ///
    /// The value is derived from the platform evidence variant during decode;
    /// no caller can assert it.
    #[must_use]
    pub const fn disposition(&self) -> CommandDomainCleanupDisposition {
        self.disposition
    }

    /// Returns the exact command-effect request binding.
    #[must_use]
    pub const fn binding(&self) -> &CommandDomainCleanupBinding {
        &self.binding
    }

    /// Returns the observed survivor count, which is always zero after validation.
    #[must_use]
    pub const fn surviving_processes(&self) -> u64 {
        self.surviving_processes
    }

    /// Returns the complete domain-separated canonical OS evidence bytes.
    #[must_use]
    pub fn os_evidence_bytes(&self) -> &[u8] {
        &self.os_evidence_bytes
    }

    /// Returns SHA-256 of the exact OS evidence bytes.
    #[must_use]
    pub const fn os_evidence_digest(&self) -> &Digest {
        &self.os_evidence_digest
    }

    #[allow(
        dead_code,
        reason = "the Linux orchestration adapter consumes this bridge when its public launch integration lands"
    )]
    pub(crate) fn from_linux_candidate(
        candidate: &CgroupCleanupEvidence,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        candidate.validate().map_err(|_| {
            CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            }
        })?;
        Self::from_payload(&CanonicalCommandDomainEvidence {
            schema_version: COMMAND_DOMAIN_EVIDENCE_VERSION,
            backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            binding: canonical_binding(&binding_from_linux(candidate)?),
            surviving_processes: candidate.surviving_processes,
            platform_evidence: CanonicalPlatformEvidence::LinuxCgroupV2(Box::new(
                LinuxCanonicalEvidence {
                    journal_record: candidate.journal_record.clone(),
                },
            )),
        })
    }

    #[allow(
        dead_code,
        reason = "the signed-helper adapter consumes this bridge when its transport integration lands"
    )]
    pub(crate) fn from_macos_candidate(
        candidate: &MacosCleanupEvidence,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        candidate.validate().map_err(|_| {
            CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            }
        })?;
        Self::from_payload(&CanonicalCommandDomainEvidence {
            schema_version: COMMAND_DOMAIN_EVIDENCE_VERSION,
            backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            binding: canonical_binding(&binding_from_macos(candidate)?),
            surviving_processes: candidate.surviving_processes,
            platform_evidence: CanonicalPlatformEvidence::MacOsDedicatedIdentity(Box::new(
                MacosCanonicalEvidence {
                    journal_record: candidate.journal_record.clone(),
                },
            )),
        })
    }

    /// Mints the `NoDomainCreatedBeforeEffect` half of the Linux contract from
    /// one kernel-read absence observation.
    ///
    /// This is deliberately a separate constructor from
    /// [`Self::from_linux_candidate`]: the reaping contract requires a durable
    /// `Removed` journal record, and no absence observation can or should
    /// satisfy it. The two are disjoint producers of disjoint dispositions.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation does not re-derive its own absence
    /// conclusion, or when its binding is not canonical.
    pub(crate) fn from_linux_absence_observation(
        observation: &LinuxCommandDomainAbsenceObservationV1,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        observation.validate().map_err(|_| {
            CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            }
        })?;
        let binding = CommandDomainCleanupBinding::try_new(
            observation.runner_session_id.clone(),
            observation.effect_id.clone(),
            Digest::parse(&observation.request_digest).map_err(|_| {
                CommandDomainCleanupProofError::InvalidBinding {
                    field: "command_request_digest",
                }
            })?,
        )?;
        Self::from_payload(&CanonicalCommandDomainEvidence {
            schema_version: COMMAND_DOMAIN_EVIDENCE_VERSION,
            backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            binding: canonical_binding(&binding),
            surviving_processes: 0,
            platform_evidence: CanonicalPlatformEvidence::LinuxCgroupV2NoDomain(Box::new(
                LinuxNoDomainCanonicalEvidence {
                    absence_observation: observation.clone(),
                },
            )),
        })
    }

    fn from_payload(
        payload: &CanonicalCommandDomainEvidence,
    ) -> Result<Self, CommandDomainCleanupProofError> {
        let os_evidence_bytes = encode_evidence(payload)?;
        let os_evidence_digest = Digest::sha256(&os_evidence_bytes);
        let decoded = decode_evidence(&os_evidence_bytes)?;
        let proof = Self {
            backend: decoded.backend,
            disposition: decoded.disposition,
            binding: decoded.binding,
            surviving_processes: decoded.surviving_processes,
            os_evidence_bytes,
            os_evidence_digest,
        };
        proof.validate()?;
        Ok(proof)
    }
}

/// Closed failure from command-domain cleanup proof construction or readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDomainCleanupProofError {
    /// A command-effect binding identifier is not canonical.
    InvalidBinding {
        /// Exact invalid binding field.
        field: &'static str,
    },
    /// The OS evidence byte string is empty.
    EmptyEvidence,
    /// The OS evidence exceeds the hard byte bound.
    EvidenceTooLarge {
        /// Observed byte count.
        bytes: usize,
    },
    /// The domain-separation prefix is absent or altered.
    InvalidDomain,
    /// Strict JSON decoding failed.
    Decoding,
    /// Canonical JSON encoding failed.
    Encoding,
    /// Valid JSON used an alternate byte representation.
    NonCanonical,
    /// The evidence schema version is unsupported.
    UnsupportedVersion {
        /// Observed schema version.
        version: u32,
    },
    /// The top-level backend and platform payload variant differ.
    BackendConfusion,
    /// A platform journal or its raw observations failed native validation.
    InvalidPlatformEvidence {
        /// Backend whose evidence failed validation.
        backend: CommandDomainCleanupBackend,
    },
    /// The redundant top-level command binding differs from the journal.
    JournalBindingMismatch,
    /// A nonzero survivor count was supplied.
    NonzeroSurvivors {
        /// Observed survivor count.
        survivors: u64,
    },
    /// Persisted bytes do not match their expected SHA-256 digest.
    DigestMismatch,
    /// The decoded fields differ from the immutable proof fields.
    ReadbackMismatch,
    /// The proof backend differs from coordinator expectation.
    ExpectedBackendMismatch,
    /// The proof command-effect binding differs from coordinator expectation.
    ExpectedBindingMismatch,
    /// The platform evidence supports a different resource-cleanup disposition.
    ExpectedDispositionMismatch,
}

impl Display for CommandDomainCleanupProofError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding { field } => {
                write!(
                    formatter,
                    "invalid command-domain cleanup binding field {field}"
                )
            }
            Self::EmptyEvidence => formatter.write_str("command-domain cleanup evidence is empty"),
            Self::EvidenceTooLarge { bytes } => write!(
                formatter,
                "command-domain cleanup evidence has {bytes} bytes; maximum is {MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES}"
            ),
            Self::InvalidDomain => {
                formatter.write_str("command-domain cleanup evidence has the wrong domain")
            }
            Self::Decoding => {
                formatter.write_str("command-domain cleanup evidence failed strict decoding")
            }
            Self::Encoding => {
                formatter.write_str("command-domain cleanup evidence could not be encoded")
            }
            Self::NonCanonical => formatter
                .write_str("command-domain cleanup evidence is not byte-for-byte canonical"),
            Self::UnsupportedVersion { version } => write!(
                formatter,
                "unsupported command-domain cleanup evidence version {version}"
            ),
            Self::BackendConfusion => formatter.write_str(
                "command-domain cleanup backend differs from its platform evidence variant",
            ),
            Self::InvalidPlatformEvidence { backend } => write!(
                formatter,
                "{} command-domain cleanup evidence failed native validation",
                backend_name(*backend)
            ),
            Self::JournalBindingMismatch => formatter.write_str(
                "command-domain cleanup journal differs from the redundant request binding",
            ),
            Self::NonzeroSurvivors { survivors } => write!(
                formatter,
                "command-domain cleanup retained {survivors} surviving processes"
            ),
            Self::DigestMismatch => formatter
                .write_str("command-domain cleanup evidence digest does not match its bytes"),
            Self::ReadbackMismatch => formatter.write_str(
                "command-domain cleanup proof fields differ from canonical evidence readback",
            ),
            Self::ExpectedBackendMismatch => formatter
                .write_str("command-domain cleanup backend differs from durable expectation"),
            Self::ExpectedBindingMismatch => formatter.write_str(
                "command-domain cleanup request binding differs from durable expectation",
            ),
            Self::ExpectedDispositionMismatch => formatter.write_str(
                "command-domain cleanup evidence supports a different resource-cleanup disposition",
            ),
        }
    }
}

impl Error for CommandDomainCleanupProofError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCommandDomainEvidence {
    schema_version: u32,
    backend: CommandDomainCleanupBackend,
    binding: CanonicalCommandBinding,
    surviving_processes: u64,
    platform_evidence: CanonicalPlatformEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalCommandBinding {
    runner_session_id: String,
    command_effect_id: String,
    command_request_digest: Digest,
}

/// Closed platform payloads. Each variant is reached only through its own wire
/// tag, and each carries the complete native record for exactly one
/// disposition. `linux_cgroup_v2` remains the reaping contract byte-for-byte;
/// `linux_cgroup_v2_no_domain` is the disjoint absence contract and can never
/// satisfy the reaping validator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "evidence", rename_all = "snake_case")]
enum CanonicalPlatformEvidence {
    LinuxCgroupV2(Box<LinuxCanonicalEvidence>),
    LinuxCgroupV2NoDomain(Box<LinuxNoDomainCanonicalEvidence>),
    MacOsDedicatedIdentity(Box<MacosCanonicalEvidence>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxCanonicalEvidence {
    journal_record: DomainJournalRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxNoDomainCanonicalEvidence {
    absence_observation: LinuxCommandDomainAbsenceObservationV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MacosCanonicalEvidence {
    journal_record: MacosHelperJournalRecord,
}

struct DecodedEvidence {
    backend: CommandDomainCleanupBackend,
    disposition: CommandDomainCleanupDisposition,
    binding: CommandDomainCleanupBinding,
    surviving_processes: u64,
}

fn encode_evidence(
    payload: &CanonicalCommandDomainEvidence,
) -> Result<Vec<u8>, CommandDomainCleanupProofError> {
    let canonical =
        serde_json::to_vec(payload).map_err(|_| CommandDomainCleanupProofError::Encoding)?;
    let mut bytes = Vec::with_capacity(COMMAND_DOMAIN_EVIDENCE_PREFIX.len() + canonical.len());
    bytes.extend_from_slice(COMMAND_DOMAIN_EVIDENCE_PREFIX);
    bytes.extend_from_slice(&canonical);
    validate_evidence_length(&bytes)?;
    Ok(bytes)
}

fn decode_evidence(bytes: &[u8]) -> Result<DecodedEvidence, CommandDomainCleanupProofError> {
    validate_evidence_length(bytes)?;
    let canonical = bytes
        .strip_prefix(COMMAND_DOMAIN_EVIDENCE_PREFIX)
        .ok_or(CommandDomainCleanupProofError::InvalidDomain)?;
    if canonical.is_empty() {
        return Err(CommandDomainCleanupProofError::Decoding);
    }
    let payload: CanonicalCommandDomainEvidence =
        serde_json::from_slice(canonical).map_err(|_| CommandDomainCleanupProofError::Decoding)?;
    let reencoded =
        serde_json::to_vec(&payload).map_err(|_| CommandDomainCleanupProofError::Encoding)?;
    if reencoded != canonical {
        return Err(CommandDomainCleanupProofError::NonCanonical);
    }
    if payload.schema_version != COMMAND_DOMAIN_EVIDENCE_VERSION {
        return Err(CommandDomainCleanupProofError::UnsupportedVersion {
            version: payload.schema_version,
        });
    }
    if payload.surviving_processes != 0 {
        return Err(CommandDomainCleanupProofError::NonzeroSurvivors {
            survivors: payload.surviving_processes,
        });
    }
    let binding = CommandDomainCleanupBinding::try_new(
        payload.binding.runner_session_id,
        payload.binding.command_effect_id,
        payload.binding.command_request_digest,
    )?;
    let (platform_binding, disposition) = match (payload.backend, payload.platform_evidence) {
        (
            CommandDomainCleanupBackend::LinuxCgroupV2,
            CanonicalPlatformEvidence::LinuxCgroupV2(platform),
        ) => {
            let evidence =
                evidence_from_removed_record(&platform.journal_record).map_err(|_| {
                    CommandDomainCleanupProofError::InvalidPlatformEvidence {
                        backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                    }
                })?;
            (
                binding_from_linux(&evidence)?,
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            )
        }
        (
            CommandDomainCleanupBackend::LinuxCgroupV2,
            CanonicalPlatformEvidence::LinuxCgroupV2NoDomain(platform),
        ) => {
            // A no-created-domain proof requires an absent leaf. It cannot substitute
            // for observations of killing, reaping, or removing a created domain.
            platform.absence_observation.validate().map_err(|_| {
                CommandDomainCleanupProofError::InvalidPlatformEvidence {
                    backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                }
            })?;
            (
                binding_from_linux_absence(&platform.absence_observation)?,
                CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
            )
        }
        (
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            CanonicalPlatformEvidence::MacOsDedicatedIdentity(platform),
        ) => {
            let evidence =
                macos_evidence_from_cleaned_record(platform.journal_record).map_err(|_| {
                    CommandDomainCleanupProofError::InvalidPlatformEvidence {
                        backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                    }
                })?;
            (
                binding_from_macos(&evidence)?,
                CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            )
        }
        _ => return Err(CommandDomainCleanupProofError::BackendConfusion),
    };
    if binding != platform_binding {
        return Err(CommandDomainCleanupProofError::JournalBindingMismatch);
    }
    Ok(DecodedEvidence {
        backend: payload.backend,
        disposition,
        binding,
        surviving_processes: payload.surviving_processes,
    })
}

fn binding_from_linux(
    evidence: &CgroupCleanupEvidence,
) -> Result<CommandDomainCleanupBinding, CommandDomainCleanupProofError> {
    let digest = Digest::parse(evidence.request_digest.clone()).map_err(|_| {
        CommandDomainCleanupProofError::InvalidPlatformEvidence {
            backend: CommandDomainCleanupBackend::LinuxCgroupV2,
        }
    })?;
    CommandDomainCleanupBinding::try_new(
        evidence.journal_record.runner_session_id.clone(),
        evidence.journal_record.effect_id.clone(),
        digest,
    )
}

fn binding_from_linux_absence(
    observation: &LinuxCommandDomainAbsenceObservationV1,
) -> Result<CommandDomainCleanupBinding, CommandDomainCleanupProofError> {
    let digest = Digest::parse(observation.request_digest.clone()).map_err(|_| {
        CommandDomainCleanupProofError::InvalidPlatformEvidence {
            backend: CommandDomainCleanupBackend::LinuxCgroupV2,
        }
    })?;
    CommandDomainCleanupBinding::try_new(
        observation.runner_session_id.clone(),
        observation.effect_id.clone(),
        digest,
    )
}

fn binding_from_macos(
    evidence: &MacosCleanupEvidence,
) -> Result<CommandDomainCleanupBinding, CommandDomainCleanupProofError> {
    let request = &evidence.journal_record.request;
    let (program, arguments) = request.argv.split_first().ok_or(
        CommandDomainCleanupProofError::InvalidPlatformEvidence {
            backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
        },
    )?;
    // The signed helper represents the workspace root as "." while the
    // canonical Core CommandSpec represents that same root as an empty path.
    // Core rejects "." as a caller-authored normalized working directory, so
    // this projection is lossless. Non-root normalized paths are retained
    // byte-for-byte by the helper request.
    let working_directory = if request.relative_working_directory == "." {
        PathBuf::new()
    } else {
        PathBuf::from(&request.relative_working_directory)
    };
    let command = CommandSpec {
        program: program.clone(),
        arguments: arguments.to_vec(),
        working_directory,
    };
    command.validate().map_err(
        |_| CommandDomainCleanupProofError::InvalidPlatformEvidence {
            backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
        },
    )?;
    let command_bytes =
        serde_json::to_vec(&command).map_err(|_| CommandDomainCleanupProofError::Encoding)?;
    CommandDomainCleanupBinding::try_new(
        evidence.journal_record.runner_session_id().to_owned(),
        evidence.journal_record.effect_id().to_owned(),
        Digest::sha256(&command_bytes),
    )
}

fn canonical_binding(binding: &CommandDomainCleanupBinding) -> CanonicalCommandBinding {
    CanonicalCommandBinding {
        runner_session_id: binding.runner_session_id.clone(),
        command_effect_id: binding.command_effect_id.clone(),
        command_request_digest: binding.command_request_digest.clone(),
    }
}

fn validate_binding_id(
    field: &'static str,
    value: &str,
) -> Result<(), CommandDomainCleanupProofError> {
    if value.is_empty()
        || value.len() > MAX_BINDING_ID_BYTES
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(CommandDomainCleanupProofError::InvalidBinding { field });
    }
    Ok(())
}

fn validate_evidence_length(bytes: &[u8]) -> Result<(), CommandDomainCleanupProofError> {
    if bytes.is_empty() {
        return Err(CommandDomainCleanupProofError::EmptyEvidence);
    }
    if bytes.len() > MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES {
        return Err(CommandDomainCleanupProofError::EvidenceTooLarge { bytes: bytes.len() });
    }
    Ok(())
}

const fn backend_name(backend: CommandDomainCleanupBackend) -> &'static str {
    match backend {
        CommandDomainCleanupBackend::LinuxCgroupV2 => "Linux cgroup-v2",
        CommandDomainCleanupBackend::MacOsDedicatedIdentity => "macOS dedicated-identity",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::command_domain_absence::LinuxCommandDomainAbsenceObservationV1;
    use crate::linux_containment::{
        CgroupObjectIdentity, DomainJournalState, LeafFile, LimitValue, LinuxNativeLaunchIdentity,
        RawCleanupObservation, ReadBackDomainLimits, RequestedDomainLimits,
    };
    use crate::macos_helper_protocol::{
        MACOS_HELPER_PROTOCOL_VERSION, MacosAssignedIdentity, MacosChildDescriptorBinding,
        MacosChildDescriptorPurpose, MacosExecutableIdentity, MacosHelperAttestation,
        MacosHelperInstallAudit, MacosHelperJournalState, MacosHelperLaunchRequest,
        MacosHelperNetwork, MacosHelperPreparationBinding, MacosHelperProtocolError,
        MacosHelperSession, MacosProcessObservation, MacosTerminationReason,
    };
    use grok_build_core::CONTRACT_VERSION;

    fn digest(marker: u8) -> Digest {
        Digest::sha256(&[marker])
    }

    fn linux_candidate_for(binding: &CommandDomainCleanupBinding) -> CgroupCleanupEvidence {
        let requested_limits = RequestedDomainLimits {
            pids_max: 8,
            memory_max: LimitValue::Max,
            memory_swap_max: LimitValue::Max,
        };
        let read_back_limits = ReadBackDomainLimits {
            pids_max: 8,
            memory_max: LimitValue::Max,
            memory_swap_max: LimitValue::Max,
            memory_oom_group: true,
        };
        let leaf_identity = CgroupObjectIdentity {
            device: 41,
            inode: 42,
        };
        let observations = vec![
            RawCleanupObservation {
                sequence: 1,
                attempt: 1,
                file: LeafFile::CgroupEvents,
                bytes: b"populated 0\nfrozen 0\n".to_vec(),
            },
            RawCleanupObservation {
                sequence: 2,
                attempt: 1,
                file: LeafFile::CgroupProcs,
                bytes: Vec::new(),
            },
            RawCleanupObservation {
                sequence: 3,
                attempt: 1,
                file: LeafFile::CgroupProcs,
                bytes: Vec::new(),
            },
        ];
        let request_digest = binding.command_request_digest().to_string();
        let leaf_name = format!("gb-{}", "a".repeat(64));
        let journal_record = DomainJournalRecord {
            state: DomainJournalState::Removed,
            native_launch: LinuxNativeLaunchIdentity {
                contract_version: CONTRACT_VERSION,
                attempt_id: "linux-preparation-attempt-1".into(),
                native_journal_id: "linux-native-journal-1".into(),
                expected_platform_binding_digest: digest(2),
                sprint_id: "sprint-linux-1".into(),
                launch_id: "launch-linux-1".into(),
                session_id: binding.runner_session_id().into(),
                cleanup_effect_id: "cleanup-effect-linux-1".into(),
                input_snapshot: digest(7),
                grant_hash: digest(4),
                policy_hash: digest(5),
                claimed_at_unix_ms: 10,
            },
            runner_session_id: binding.runner_session_id().into(),
            effect_id: binding.command_effect_id().into(),
            grant_hash: digest(4).to_string(),
            policy_hash: digest(5).to_string(),
            command_hash: digest(6).to_string(),
            request_digest: request_digest.clone(),
            leaf_name: leaf_name.clone(),
            expected_delegation_identity: CgroupObjectIdentity {
                device: 11,
                inode: 12,
            },
            expected_owner_uid: 501,
            leaf_identity: Some(leaf_identity),
            requested_limits,
            read_back_limits: Some(read_back_limits),
            staged_launcher: None,
            release_authorization: None,
            release_binding: None,
            release_intent_recorded: false,
            release_observation: None,
            cleanup_observations: observations.clone(),
            kill_value: Some(b"1\n".to_vec()),
        };
        let candidate = CgroupCleanupEvidence {
            journal_record,
            request_digest,
            leaf_name,
            leaf_identity,
            requested_limits,
            read_back_limits,
            kill_value: b"1\n".to_vec(),
            observations,
            stable_empty_reads: 2,
            leaf_removed: true,
            surviving_processes: 0,
        };
        candidate.validate().expect("valid Linux cleanup candidate");
        candidate
    }

    fn linux_candidate() -> CgroupCleanupEvidence {
        linux_candidate_for(
            &CommandDomainCleanupBinding::try_new(
                "runner-session-linux-1",
                "command-effect-linux-1",
                digest(3),
            )
            .expect("default Linux test binding"),
        )
    }

    pub(crate) fn validated_linux_cleanup_proof_for(
        binding: &CommandDomainCleanupBinding,
    ) -> ValidatedCommandDomainCleanupProof {
        ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate_for(binding))
            .expect("native-validating Linux cleanup fixture becomes canonical proof")
    }

    pub(crate) fn alternate_validated_linux_cleanup_proof_for(
        binding: &CommandDomainCleanupBinding,
    ) -> ValidatedCommandDomainCleanupProof {
        let mut candidate = linux_candidate_for(binding);
        candidate.journal_record.native_launch.attempt_id =
            "linux-preparation-attempt-alternate".into();
        candidate
            .validate()
            .expect("alternate Linux cleanup candidate remains native-valid");
        ValidatedCommandDomainCleanupProof::from_linux_candidate(&candidate)
            .expect("alternate native-validating Linux fixture becomes canonical proof")
    }

    pub(crate) fn tampered_linux_cleanup_proof_for(
        binding: &CommandDomainCleanupBinding,
    ) -> ValidatedCommandDomainCleanupProof {
        let mut proof = validated_linux_cleanup_proof_for(binding);
        proof.os_evidence_bytes.push(b'\n');
        proof
    }

    pub(crate) fn surviving_linux_cleanup_proof_for(
        binding: &CommandDomainCleanupBinding,
    ) -> ValidatedCommandDomainCleanupProof {
        let mut proof = validated_linux_cleanup_proof_for(binding);
        proof.surviving_processes = 1;
        proof
    }

    fn macos_observation(
        sequence: u32,
        observed_at_unix_ms: u64,
        process_ids: Vec<u32>,
    ) -> MacosProcessObservation {
        let mut observation = MacosProcessObservation {
            sequence,
            observed_at_unix_ms,
            uid: 601,
            process_ids,
            enumeration_digest: digest(0),
            creation_sealed: true,
        };
        observation.enumeration_digest = observation
            .computed_digest()
            .expect("canonical macOS process observation");
        observation
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the canonical macOS fixture keeps every authenticated request and journal field explicit"
    )]
    fn macos_candidate_for_command(
        argv: Vec<String>,
        relative_working_directory: impl Into<String>,
    ) -> MacosCleanupEvidence {
        let assigned_identity = MacosAssignedIdentity {
            account_name: "_grokbuild601".into(),
            uid: 601,
            gid: 601,
            account_record_digest: digest(10),
        };
        let preparation = MacosHelperPreparationBinding {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-macos-1".into(),
            sprint_id: "sprint-macos-1".into(),
            launch_id: "launch-macos-1".into(),
            runner_session_id: "runner-session-macos-1".into(),
            cleanup_effect_id: "cleanup-effect-macos-1".into(),
            input_snapshot: digest(14),
            native_journal_id: "native-journal-macos-1".into(),
            expected_platform_binding_digest: digest(15),
            claimed_at_unix_ms: 900,
        };
        let descriptor_bindings = [
            (0, MacosChildDescriptorPurpose::StandardInput, true),
            (1, MacosChildDescriptorPurpose::StandardOutput, true),
            (2, MacosChildDescriptorPurpose::StandardError, true),
            (3, MacosChildDescriptorPurpose::HoldControl, false),
            (4, MacosChildDescriptorPurpose::SetupReport, false),
        ]
        .into_iter()
        .map(
            |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
                target_fd,
                purpose,
                object_digest: digest(20 + u8::try_from(target_fd).unwrap()),
                inherited_through_exec,
            },
        )
        .collect();
        let mut request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 1,
            session_nonce: digest(16),
            request_id: "request-macos-1".into(),
            preparation,
            runner_session_id: "runner-session-macos-1".into(),
            effect_id: "command-effect-macos-1".into(),
            workspace_grant_hash: digest(17),
            execution_policy_hash: digest(18),
            staged_workspace_id: "shadow-macos-1".into(),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(19),
            },
            descriptor_bindings,
            argv,
            relative_working_directory: relative_working_directory.into(),
            environment: BTreeMap::new(),
            deadline_unix_ms: 2_000,
            max_output_bytes: 1_024,
            max_processes: 8,
            max_memory_bytes: None,
            command_network: MacosHelperNetwork::Denied,
            seatbelt_profile_digest: digest(25),
            request_digest: digest(0),
        };
        request.request_digest = request.computed_digest().unwrap();
        let admission_session = MacosHelperSession {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 1,
            session_nonce: digest(16),
            helper_binary_digest: digest(26),
            helper_requirement_digest: digest(27),
            client_binary_digest: digest(28),
            client_requirement_digest: digest(29),
            pool_record_digest: digest(30),
            workspace_grant_hash: digest(17),
            execution_policy_hash: digest(18),
            command_network: MacosHelperNetwork::Denied,
            authenticated_at_unix_ms: 800,
            peer_requirement_matched: true,
            // Local code attestation is sufficient for runtime admission.
            attestation: MacosHelperAttestation::LocalCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            },
        };
        let journal_record = MacosHelperJournalRecord {
            state: MacosHelperJournalState::Cleaned,
            admission_session,
            request,
            assigned_identity: Some(assigned_identity.clone()),
            cleanup_agent_digest: Some(digest(12)),
            held_preparation_evidence: None,
            release_authorization: None,
            release_evidence: None,
            termination_reason: Some(MacosTerminationReason::Exited),
            observations: vec![
                macos_observation(1, 1_000, vec![71]),
                macos_observation(2, 1_001, Vec::new()),
                macos_observation(3, 1_002, Vec::new()),
            ],
            identity_released: true,
        };
        let candidate = MacosCleanupEvidence {
            request_digest: journal_record.request_digest().clone(),
            journal_record,
            assigned_identity,
            surviving_processes: 0,
            stable_empty_observations: 2,
        };
        candidate.validate().expect("valid macOS cleanup candidate");
        candidate
    }

    fn macos_candidate() -> MacosCleanupEvidence {
        macos_candidate_for_command(vec!["cargo".into(), "test".into()], ".")
    }

    fn payload(proof: &ValidatedCommandDomainCleanupProof) -> CanonicalCommandDomainEvidence {
        let canonical = proof
            .os_evidence_bytes()
            .strip_prefix(COMMAND_DOMAIN_EVIDENCE_PREFIX)
            .expect("proof has command-domain prefix");
        serde_json::from_slice(canonical).expect("proof has canonical JSON payload")
    }

    fn readback_payload(
        payload: &CanonicalCommandDomainEvidence,
        expected_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<ValidatedCommandDomainCleanupProof, CommandDomainCleanupProofError> {
        let bytes = encode_evidence(payload).expect("test payload encodes within bound");
        let digest = Digest::sha256(&bytes);
        ValidatedCommandDomainCleanupProof::readback(
            &bytes,
            &digest,
            expected_backend,
            expected_binding,
        )
    }

    #[test]
    fn linux_candidate_becomes_restart_validatable_canonical_proof() {
        let proof = ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate())
            .expect("validated Linux candidate becomes proof");

        assert_eq!(proof.backend(), CommandDomainCleanupBackend::LinuxCgroupV2);
        assert_eq!(proof.surviving_processes(), 0);
        assert_eq!(
            proof.binding().runner_session_id(),
            "runner-session-linux-1"
        );
        assert_eq!(
            proof.binding().command_effect_id(),
            "command-effect-linux-1"
        );
        assert!(!proof.os_evidence_bytes().is_empty());
        assert!(proof.os_evidence_bytes().len() <= MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES);
        assert_eq!(
            &Digest::sha256(proof.os_evidence_bytes()),
            proof.os_evidence_digest()
        );
        proof.validate().expect("proof revalidates");

        let reopened = ValidatedCommandDomainCleanupProof::readback(
            proof.os_evidence_bytes(),
            proof.os_evidence_digest(),
            proof.backend(),
            proof.binding(),
        )
        .expect("exact journal bytes reopen after restart");
        assert_eq!(reopened, proof);
    }

    #[test]
    fn macos_candidate_becomes_restart_validatable_canonical_proof() {
        let candidate = macos_candidate();
        let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
            .expect("validated macOS candidate becomes proof");
        let canonical_command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::new(),
        };
        let canonical_command_digest = Digest::sha256(
            &serde_json::to_vec(&canonical_command).expect("encode canonical Core command"),
        );

        assert_eq!(
            proof.backend(),
            CommandDomainCleanupBackend::MacOsDedicatedIdentity
        );
        assert_eq!(proof.surviving_processes(), 0);
        assert_eq!(
            proof.binding().runner_session_id(),
            "runner-session-macos-1"
        );
        assert_eq!(
            proof.binding().command_effect_id(),
            "command-effect-macos-1"
        );
        assert_eq!(
            proof.binding().command_request_digest(),
            &canonical_command_digest,
            "macOS cleanup binds the canonical Core CommandSpec request"
        );
        assert_ne!(
            proof.binding().command_request_digest(),
            &candidate.request_digest,
            "the signed-helper launch-request self-digest is a distinct identity"
        );
        proof.validate().expect("proof revalidates");
        let reopened = ValidatedCommandDomainCleanupProof::readback(
            proof.os_evidence_bytes(),
            proof.os_evidence_digest(),
            proof.backend(),
            proof.binding(),
        )
        .expect("exact helper journal reopens after restart");
        assert_eq!(reopened, proof);
    }

    /// Local code attestation permits terminal evidence; an unattested session
    /// must still fail. The durable proof preserves which attestation was used.
    #[test]
    fn a_locally_attested_admission_session_closes_the_macos_terminal_evidence_chain() {
        let candidate = macos_candidate();
        assert_eq!(
            candidate.journal_record.admission_session.attestation,
            MacosHelperAttestation::LocalCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            },
            "the fixture must exercise local attestation, not publisher attestation"
        );
        let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
            .expect("a locally attested helper session mints terminal cleanup evidence");
        assert!(
            String::from_utf8_lossy(proof.os_evidence_bytes())
                .contains("\"kind\":\"local_code_identity\""),
            "the durable proof must record which attestation admitted the session"
        );

        let mut unattested = candidate.clone();
        unattested.journal_record.admission_session.attestation =
            MacosHelperAttestation::Unattested;
        assert_eq!(
            unattested.validate(),
            Err(MacosHelperProtocolError::Invalid {
                field: "session.attestation",
                reason: "an unattested helper is never admitted: its loaded image was not pinned to an install-time code requirement",
            }),
            "an unattested helper still terminates the chain"
        );
        assert_eq!(
            ValidatedCommandDomainCleanupProof::from_macos_candidate(&unattested),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            })
        );

        let mut ill_installed = candidate.clone();
        ill_installed.journal_record.admission_session.attestation =
            MacosHelperAttestation::LocalCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o775,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            };
        assert_eq!(
            ValidatedCommandDomainCleanupProof::from_macos_candidate(&ill_installed),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            }),
            "a helper binary an untrusted writer could replace mints nothing"
        );
    }

    /// Publisher attestation uses the same admission checks as local attestation
    /// and records its additional provenance in the durable proof.
    #[test]
    fn a_publisher_attested_admission_session_uses_the_identical_chain() {
        let mut candidate = macos_candidate();
        candidate.journal_record.admission_session.attestation =
            MacosHelperAttestation::PublisherCodeIdentity {
                install_audit: MacosHelperInstallAudit {
                    auditing_uid: 501,
                    binary_owner_uid: 0,
                    binary_mode: 0o755,
                    directory_owner_uid: 0,
                    directory_mode: 0o755,
                },
            };
        let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
            .expect("a Developer-ID helper session mints the same terminal evidence");
        assert!(
            String::from_utf8_lossy(proof.os_evidence_bytes())
                .contains("\"kind\":\"publisher_code_identity\""),
            "publisher provenance is recorded, not silently equated with local"
        );
        proof.validate().expect("proof revalidates");
    }

    #[test]
    fn macos_nested_working_directory_rejoins_canonical_core_binding() {
        let candidate =
            macos_candidate_for_command(vec!["cargo".into(), "test".into()], "src/tools");
        let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
            .expect("nested macOS candidate becomes canonical proof");
        let command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::from("src/tools"),
        };
        command
            .validate()
            .expect("nested Core working directory is canonical");
        let expected_binding = CommandDomainCleanupBinding::try_new(
            candidate.journal_record.runner_session_id(),
            candidate.journal_record.effect_id(),
            Digest::sha256(
                &serde_json::to_vec(&command).expect("encode nested canonical Core command"),
            ),
        )
        .expect("construct nested expected Core binding");

        proof
            .validate_expected(
                proof.os_evidence_digest(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                &expected_binding,
            )
            .expect("nested helper working directory rejoins exact Core command");
        assert_eq!(proof.binding(), &expected_binding);
    }

    #[test]
    fn self_consistent_macos_working_directory_substitution_cannot_cross_core_binding() {
        let mut candidate =
            macos_candidate_for_command(vec!["cargo".into(), "test".into()], "src/tools");
        let original_helper_request_digest = candidate.request_digest.clone();
        let expected_command = CommandSpec {
            program: "cargo".into(),
            arguments: vec!["test".into()],
            working_directory: PathBuf::from("src/tools"),
        };
        let expected_binding = CommandDomainCleanupBinding::try_new(
            candidate.journal_record.runner_session_id(),
            candidate.journal_record.effect_id(),
            Digest::sha256(
                &serde_json::to_vec(&expected_command)
                    .expect("encode original canonical Core command"),
            ),
        )
        .expect("construct original expected Core binding");

        candidate.journal_record.request.relative_working_directory = "src/substituted".into();
        let substituted_helper_request_digest = candidate
            .journal_record
            .request
            .computed_digest()
            .expect("recompute self-consistent substituted helper digest");
        candidate.journal_record.request.request_digest = substituted_helper_request_digest.clone();
        candidate.request_digest = substituted_helper_request_digest;
        assert_ne!(candidate.request_digest, original_helper_request_digest);
        candidate
            .validate()
            .expect("substituted helper request remains internally canonical");
        let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
            .expect("self-consistent substituted helper request becomes its own proof");

        assert_eq!(
            proof.validate_expected(
                proof.os_evidence_digest(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                &expected_binding,
            ),
            Err(CommandDomainCleanupProofError::ExpectedBindingMismatch),
            "recomputing the helper self-digest cannot cross the expected Core command binding"
        );
    }

    #[test]
    fn backend_confusion_and_redundant_binding_substitution_are_rejected() {
        let proof = ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate())
            .expect("Linux proof");
        let mut confused = payload(&proof);
        confused.backend = CommandDomainCleanupBackend::MacOsDedicatedIdentity;
        assert_eq!(
            readback_payload(
                &confused,
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::BackendConfusion)
        );

        let mut substituted = payload(&proof);
        substituted.binding.command_effect_id = "command-effect-substituted".into();
        assert_eq!(
            readback_payload(&substituted, proof.backend(), proof.binding()),
            Err(CommandDomainCleanupProofError::JournalBindingMismatch)
        );
    }

    #[test]
    fn altered_linux_kernel_or_macos_helper_observations_are_rejected() {
        let linux_proof =
            ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate())
                .expect("Linux proof");
        let mut altered_linux = payload(&linux_proof);
        let CanonicalPlatformEvidence::LinuxCgroupV2(platform) =
            &mut altered_linux.platform_evidence
        else {
            panic!("Linux proof has Linux evidence");
        };
        platform.journal_record.cleanup_observations[2].bytes = b"71\n".to_vec();
        assert_eq!(
            readback_payload(&altered_linux, linux_proof.backend(), linux_proof.binding()),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            })
        );

        let macos_proof =
            ValidatedCommandDomainCleanupProof::from_macos_candidate(&macos_candidate())
                .expect("macOS proof");
        let mut altered_macos = payload(&macos_proof);
        let CanonicalPlatformEvidence::MacOsDedicatedIdentity(platform) =
            &mut altered_macos.platform_evidence
        else {
            panic!("macOS proof has macOS evidence");
        };
        platform.journal_record.observations[2].enumeration_digest = digest(99);
        assert_eq!(
            readback_payload(&altered_macos, macos_proof.backend(), macos_proof.binding()),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            })
        );
    }

    #[test]
    fn truncation_noncanonical_bytes_and_nonzero_survivors_are_rejected() {
        let proof = ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate())
            .expect("Linux proof");
        let mut truncated = proof.os_evidence_bytes().to_vec();
        truncated.pop();
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                &truncated,
                proof.os_evidence_digest(),
                proof.backend(),
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::DigestMismatch)
        );
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                &truncated,
                &Digest::sha256(&truncated),
                proof.backend(),
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::Decoding)
        );

        let mut alternate = proof.os_evidence_bytes().to_vec();
        alternate.push(b'\n');
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                &alternate,
                &Digest::sha256(&alternate),
                proof.backend(),
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::NonCanonical)
        );

        let mut survivor_substitution = payload(&proof);
        survivor_substitution.surviving_processes = 1;
        assert_eq!(
            readback_payload(&survivor_substitution, proof.backend(), proof.binding(),),
            Err(CommandDomainCleanupProofError::NonzeroSurvivors { survivors: 1 })
        );
    }

    #[test]
    fn expected_state_substitution_and_unbounded_input_are_rejected() {
        let proof = ValidatedCommandDomainCleanupProof::from_linux_candidate(&linux_candidate())
            .expect("Linux proof");
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                proof.os_evidence_bytes(),
                proof.os_evidence_digest(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::ExpectedBackendMismatch)
        );
        let different_binding = CommandDomainCleanupBinding::try_new(
            proof.binding().runner_session_id(),
            "different-effect",
            proof.binding().command_request_digest().clone(),
        )
        .expect("valid alternate expected binding");
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                proof.os_evidence_bytes(),
                proof.os_evidence_digest(),
                proof.backend(),
                &different_binding,
            ),
            Err(CommandDomainCleanupProofError::ExpectedBindingMismatch)
        );

        let empty = Vec::new();
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                &empty,
                &Digest::sha256(&empty),
                proof.backend(),
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::EmptyEvidence)
        );
        let oversized = vec![0; MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES + 1];
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                &oversized,
                &Digest::sha256(&oversized),
                proof.backend(),
                proof.binding(),
            ),
            Err(CommandDomainCleanupProofError::EvidenceTooLarge {
                bytes: oversized.len(),
            })
        );
    }

    #[test]
    fn arbitrary_candidates_and_unproven_applier_backend_cannot_enter_proof_type() {
        let mut forged_linux = linux_candidate();
        forged_linux.surviving_processes = 1;
        assert_eq!(
            ValidatedCommandDomainCleanupProof::from_linux_candidate(&forged_linux),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            })
        );

        let mut forged_macos = macos_candidate();
        forged_macos.journal_record.identity_released = false;
        assert_eq!(
            ValidatedCommandDomainCleanupProof::from_macos_candidate(&forged_macos),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            })
        );

        assert!(
            serde_json::from_slice::<CommandDomainCleanupBackend>(
                br#""trusted_applier_direct_child_wait""#,
            )
            .is_err()
        );
        assert!(
            CommandDomainCleanupBinding::try_new("runner session", "effect", digest(1)).is_err()
        );
    }

    fn absence_binding() -> CommandDomainCleanupBinding {
        CommandDomainCleanupBinding::try_new(
            "runner-session-absence-1",
            "command-effect-absence-1",
            digest(9),
        )
        .expect("absence test binding")
    }

    /// A shaped absence record for platform-neutral decode tests. Its live
    /// counterpart is produced by real kernel reads and proven separately in
    /// `command_domain_absence::tests`; this fixture exists to exercise the
    /// canonical envelope on every target.
    fn absence_observation() -> LinuxCommandDomainAbsenceObservationV1 {
        LinuxCommandDomainAbsenceObservationV1 {
            schema_version: 1,
            runner_session_id: "runner-session-absence-1".into(),
            effect_id: "command-effect-absence-1".into(),
            request_digest: digest(9).as_str().to_owned(),
            self_cgroup_bytes: b"0::/\n".to_vec(),
            scanned_filesystem_magic: 0x6367_7270,
            scanned_root_identity: crate::command_domain_absence::LinuxScannedRootIdentity {
                device: 51,
                inode: 52,
            },
            scanned_directory_count: 3,
            sampled_root_entries: vec!["init.scope".into(), "system.slice".into()],
            domain_leaf_candidates: Vec::new(),
            task_children_reads: vec![crate::command_domain_absence::LinuxTaskChildrenRead {
                thread_id: 7,
                bytes: Vec::new(),
            }],
            reaped_child_accounting: crate::command_domain_absence::LinuxReapedChildAccounting {
                minor_faults: 0,
                major_faults: 0,
                user_time_ticks: 0,
                system_time_ticks: 0,
            },
        }
    }

    /// The canonical envelope round-trips an absence observation and derives
    /// the `NoDomainCreatedBeforeEffect` disposition from the platform variant,
    /// never from a caller assertion.
    #[test]
    fn an_absence_observation_decodes_as_the_no_domain_disposition() {
        let binding = absence_binding();
        let proof = ValidatedCommandDomainCleanupProof::from_linux_absence_observation(
            &absence_observation(),
        )
        .expect("absence observation becomes a canonical proof");
        assert_eq!(
            proof.disposition(),
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        );
        assert_eq!(proof.backend(), CommandDomainCleanupBackend::LinuxCgroupV2);
        assert_eq!(proof.binding(), &binding);
        assert_eq!(proof.surviving_processes(), 0);
        let reopened = ValidatedCommandDomainCleanupProof::readback(
            proof.os_evidence_bytes(),
            proof.os_evidence_digest(),
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &binding,
        )
        .expect("absence proof reopens from its exact bytes");
        assert_eq!(reopened, proof);
    }

    /// The decode arm is an extension, not a loosening: the reaping arm is
    /// reached only through its own `linux_cgroup_v2` tag and still requires a
    /// durable `Removed` journal record, so no absence record can satisfy it
    /// and no reaping record can satisfy the absence arm.
    #[test]
    fn the_two_linux_arms_cannot_satisfy_each_other() {
        let reaping = validated_linux_cleanup_proof_for(
            &CommandDomainCleanupBinding::try_new(
                "runner-session-linux-1",
                "command-effect-linux-1",
                digest(3),
            )
            .expect("reaping binding"),
        );
        assert_eq!(
            reaping.disposition(),
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
        );
        assert_eq!(
            reaping
                .require_disposition(CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect),
            Err(CommandDomainCleanupProofError::ExpectedDispositionMismatch)
        );

        let absence = ValidatedCommandDomainCleanupProof::from_linux_absence_observation(
            &absence_observation(),
        )
        .expect("absence proof");
        assert_eq!(
            absence.require_disposition(CommandDomainCleanupDisposition::ReapedZeroSurvivors),
            Err(CommandDomainCleanupProofError::ExpectedDispositionMismatch)
        );

        // Retagging absence bytes as the reaping contract fails the reaping
        // validator outright rather than decoding into it.
        let retagged = String::from_utf8(absence.os_evidence_bytes().to_vec())
            .expect("canonical evidence is UTF-8")
            .replace("linux_cgroup_v2_no_domain", "linux_cgroup_v2");
        let retagged = retagged.into_bytes();
        assert!(matches!(
            ValidatedCommandDomainCleanupProof::readback(
                &retagged,
                &Digest::sha256(&retagged),
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &absence_binding(),
            ),
            Err(CommandDomainCleanupProofError::Decoding
                | CommandDomainCleanupProofError::InvalidPlatformEvidence { .. }
                | CommandDomainCleanupProofError::NonCanonical)
        ));
    }

    /// An absence proof whose observation does not re-derive absence is refused
    /// at decode, so a caller cannot mint one by asserting the disposition.
    #[test]
    fn an_absence_proof_over_a_present_domain_is_refused() {
        let mut observation = absence_observation();
        observation.domain_leaf_candidates = vec![format!("gb-{}", "d".repeat(64))];
        assert_eq!(
            ValidatedCommandDomainCleanupProof::from_linux_absence_observation(&observation),
            Err(CommandDomainCleanupProofError::InvalidPlatformEvidence {
                backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            })
        );
    }

    /// The redundant top-level binding cannot disagree with the binding inside
    /// the absence observation.
    #[test]
    fn an_absence_proof_with_a_crossed_binding_is_refused() {
        let proof = ValidatedCommandDomainCleanupProof::from_linux_absence_observation(
            &absence_observation(),
        )
        .expect("absence proof");
        let crossed = CommandDomainCleanupBinding::try_new(
            "runner-session-absence-1",
            "command-effect-absence-2",
            digest(9),
        )
        .expect("crossed binding");
        assert_eq!(
            ValidatedCommandDomainCleanupProof::readback(
                proof.os_evidence_bytes(),
                proof.os_evidence_digest(),
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &crossed,
            ),
            Err(CommandDomainCleanupProofError::ExpectedBindingMismatch)
        );
    }
}
