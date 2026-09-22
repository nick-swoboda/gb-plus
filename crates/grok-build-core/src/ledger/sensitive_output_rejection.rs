//! Schema-v29 sensitive-output rejection authority.
//!
//! This module is deliberately additive. It does not widen the frozen v1
//! capture terminal: a detected secret closes through a separate, mutually
//! exclusive `FailedAfterKnownEffect`/`Abandoned` proof family whose retained
//! values describe policy and cleanup identity only.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::command_output_capture_authority::{
    COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureObservationClassV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCaptureReconciliationClaimV1, CommandOutputCaptureReconciliationResolutionV1,
    CommandOutputCaptureRestartStateV1, CommandOutputCaptureStoreHeadV1,
    CommandOutputCaptureTerminalAnchorV1, CommandOutputCaptureTerminalDispositionV1,
};
use super::{
    ClaimedObservationWriteFailure, CommandDomainBackend, CommandDomainCleanupDisposition,
    CommandDomainCleanupProof, EventLedger, LedgerError, PersistedEffect,
    RunnerEffectObservationAuthority, decode_stored, encode, insert_agent_event,
    insert_claimed_effect_observation, insert_effect_evidence_payload, load_effect_from,
    reference_mismatch, secure_database_files, sqlite_integer, validate_new_effect_observation,
    validate_runner_effect_observation_authority,
};
use crate::{
    CONTRACT_VERSION, CommandTerminationV1, ContractError, Digest, EffectObservation, EffectOutcome,
};

pub(super) const MIGRATION_V29: &str = include_str!("sensitive_output_rejection_v29.sql");

const POLICY_ID: &str = "gb.sensitive-output-detector.v1";
const PUBLIC_LITERAL_MARKERS_V1: [&str; 9] = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "XAI_API_KEY=",
    "OPENAI_API_KEY=",
    "ANTHROPIC_API_KEY=",
    "AWS_SECRET_ACCESS_KEY=",
    "gb-secret-canary-",
];
const POLICY_DIGEST_DOMAIN: &[u8] = b"grok-build/sensitive-output-detection-policy/v1\0";
const CORE_DUMP_SUPPRESSION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/sensitive-output-core-dump-profile/v1\0";
const STAGING_NEUTRALIZATION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/sensitive-output-staging-neutralization/v1\0";
const SENSITIVE_OUTPUT_JOURNAL_RECORD_DIGEST_DOMAIN: &[u8] =
    b"grok-build/sensitive-output-journal/v2\0";
const SENSITIVE_OUTPUT_RUNNER_CLEANUP_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"grok-build/sensitive-output-runner-cleanup-receipt/v2\0";
const SENSITIVE_OUTPUT_JOURNAL_FORMAT_VERSION: u32 = 2;
const REJECTION_ANCHOR_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-sensitive-rejection-anchor/v1\0";
const CLEANUP_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-sensitive-rejection-cleanup/v1\0";
const CLOSURE_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-sensitive-rejection-closure/v1\0";
const CLEAN_SCAN_PUBLICATION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-clean-scan-publication-receipt/v1\0";
const CLEAN_SCAN_RECEIPT_ID_PREFIX: &str = "clean-scan-publication-v1:";
const CLEAN_SCAN_RESOLUTION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-clean-scan-resolution-receipt/v1\0";
const CLEAN_SCAN_RESOLUTION_RECEIPT_ID_PREFIX: &str = "clean-scan-resolution-v1:";
const MAX_ID_BYTES: usize = 4096;

/// Typed reason a capture was closed without publication.
///
/// Existing pre-capture reasons are included so callers never need a generic
/// string reason. Schema v29 admits only `SensitiveOutputRejected` in its new
/// post-effect proof family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputAbandonmentReasonV2 {
    /// Execution failed before output capture began.
    FailedBeforeCapture,
    /// Execution was canceled before output capture began.
    CanceledBeforeCapture,
    /// Streaming detection fired before bytes reached any persistent or wire sink.
    SensitiveOutputRejected,
}

impl CommandOutputAbandonmentReasonV2 {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::FailedBeforeCapture => "FailedBeforeCapture",
            Self::CanceledBeforeCapture => "CanceledBeforeCapture",
            Self::SensitiveOutputRejected => "SensitiveOutputRejected",
        }
    }
}

/// Public identity of the detector policy admitted before command dispatch.
///
/// The digest authenticates the exact ordered public finite marker grammar.
/// No user value, detected bytes, offset, length, message, or secret-derived
/// value is represented by this contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputDetectionPolicyReferenceV1 {
    /// Stable repository-owned policy identity.
    pub policy_id: String,
    /// Monotonic policy version.
    pub policy_version: u32,
    /// Digest of the identity and exact public marker grammar, never output.
    pub policy_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalPolicy<'a> {
    policy_id: &'a str,
    policy_version: u32,
    public_literal_markers: &'a [&'a str],
}

impl SensitiveOutputDetectionPolicyReferenceV1 {
    /// Returns the sole detector identity admitted by schema v29.
    #[must_use]
    pub fn core_v1() -> Self {
        Self {
            policy_id: POLICY_ID.to_owned(),
            policy_version: 1,
            policy_digest: compute_policy_digest(POLICY_ID, 1, &PUBLIC_LITERAL_MARKERS_V1),
        }
    }

    /// Returns the ordered finite literal grammar authenticated by `policy_digest`.
    ///
    /// The literals are public policy material. They contain no user or
    /// secret-derived bytes and make runner/core policy equality mechanical.
    #[must_use]
    pub const fn public_literal_markers_v1() -> &'static [&'static str] {
        &PUBLIC_LITERAL_MARKERS_V1
    }

    /// Validates the exact fixed detector identity.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any substituted ID, version, or digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self != &Self::core_v1() {
            return Err(ContractError::new(
                "sensitive_output_detection_policy_reference_v1",
                "must equal the repository-owned v1 detector identity",
            ));
        }
        Ok(())
    }
}

/// Canonical runner profile proving crash dumps were disabled before native
/// command launch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputCoreDumpSuppressionV1 {
    /// Profile schema version. Version one is the sole admitted shape.
    pub schema_version: u32,
    /// Runner-observed current `RLIMIT_CORE`, required to be zero.
    pub core_limit_current: u64,
    /// Runner-observed hard `RLIMIT_CORE`, required to be zero.
    pub core_limit_maximum: u64,
    /// Linux `PR_GET_DUMPABLE == 0`; absent on non-Linux targets.
    pub linux_dumpable_disabled: Option<bool>,
    /// Digest of the exact preceding canonical profile fields.
    pub profile_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCoreDumpSuppression {
    schema_version: u32,
    core_limit_current: u64,
    core_limit_maximum: u64,
    linux_dumpable_disabled: Option<bool>,
}

impl SensitiveOutputCoreDumpSuppressionV1 {
    /// Constructs the exact v1 Linux profile.
    #[must_use]
    pub fn linux() -> Self {
        Self::for_platform(Some(true))
    }

    /// Constructs the exact v1 macOS profile.
    #[must_use]
    pub fn macos() -> Self {
        Self::for_platform(None)
    }

    fn for_platform(linux_dumpable_disabled: Option<bool>) -> Self {
        let canonical = CanonicalCoreDumpSuppression {
            schema_version: 1,
            core_limit_current: 0,
            core_limit_maximum: 0,
            linux_dumpable_disabled,
        };
        let bytes = serde_json::to_vec(&canonical)
            .expect("fixed core-dump suppression profile is serializable");
        Self {
            schema_version: canonical.schema_version,
            core_limit_current: canonical.core_limit_current,
            core_limit_maximum: canonical.core_limit_maximum,
            linux_dumpable_disabled: canonical.linux_dumpable_disabled,
            profile_digest: domain_digest(CORE_DUMP_SUPPRESSION_DIGEST_DOMAIN, &bytes),
        }
    }

    /// Validates the exact zero-limit platform shape and canonical digest.
    ///
    /// # Errors
    ///
    /// Returns a contract error for nonzero limits, false Linux dumpability,
    /// unsupported version, or a substituted digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1
            || self.core_limit_current != 0
            || self.core_limit_maximum != 0
            || matches!(self.linux_dumpable_disabled, Some(false))
        {
            return Err(ContractError::new(
                "sensitive_output_core_dump_suppression_v1",
                "requires v1, zero current/hard core limits, and Linux dumpable=false when present",
            ));
        }
        let canonical = serde_json::to_vec(&CanonicalCoreDumpSuppression {
            schema_version: self.schema_version,
            core_limit_current: self.core_limit_current,
            core_limit_maximum: self.core_limit_maximum,
            linux_dumpable_disabled: self.linux_dumpable_disabled,
        })
        .map_err(|error| {
            ContractError::new(
                "sensitive_output_core_dump_suppression_v1",
                format!("cannot encode canonical profile: {error}"),
            )
        })?;
        if self.profile_digest != domain_digest(CORE_DUMP_SUPPRESSION_DIGEST_DOMAIN, &canonical) {
            return Err(ContractError::new(
                "sensitive_output_core_dump_suppression_v1.profile_digest",
                "does not match the canonical zero-dump profile",
            ));
        }
        Ok(())
    }

    fn validate_for_backend(&self, backend: CommandDomainBackend) -> Result<(), ContractError> {
        self.validate()?;
        let expected = match backend {
            CommandDomainBackend::LinuxCgroupV2 => Some(true),
            CommandDomainBackend::MacOsDedicatedIdentity => None,
        };
        if self.linux_dumpable_disabled != expected {
            return Err(ContractError::new(
                "sensitive_output_core_dump_suppression_v1.linux_dumpable_disabled",
                "must match the exact command-domain platform backend",
            ));
        }
        Ok(())
    }
}

/// Length-free proof that both exact held staging objects were synchronized,
/// read back at zero length, and retained no rejected bytes.
///
/// The contract deliberately has no prior length, content digest, offset,
/// ordering, or detector-derived field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputStagingNeutralizationReceiptV1 {
    /// Receipt schema version; v1 is the sole admitted shape.
    pub schema_version: u32,
    /// Exact private capture identity.
    pub capture_id: String,
    /// Exact full acquisition identity.
    pub acquired_anchor_digest: Digest,
    /// Exact held stdout object, necessarily zero-length.
    pub stdout: CommandOutputCaptureFileIdentityV1,
    /// Exact held stderr object, necessarily zero-length.
    pub stderr: CommandOutputCaptureFileIdentityV1,
    /// Aggregate retained staging length, necessarily zero.
    pub aggregate_zero_length: u64,
    /// Digest of every preceding canonical field.
    pub receipt_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalStagingNeutralization<'a> {
    schema_version: u32,
    capture_id: &'a str,
    acquired_anchor_digest: &'a Digest,
    stdout: &'a CommandOutputCaptureFileIdentityV1,
    stderr: &'a CommandOutputCaptureFileIdentityV1,
    aggregate_zero_length: u64,
}

impl SensitiveOutputStagingNeutralizationReceiptV1 {
    /// Constructs the canonical zero-only DTO for one acquisition.
    ///
    /// Construction alone grants no cleanup or completion authority. The
    /// runner must first zero, synchronize, and read back its held descriptors;
    /// core admits the DTO only inside the exact generation-six journal chain
    /// joined to independent command-domain cleanup.
    ///
    /// # Errors
    ///
    /// Returns a contract error when either held object is not the exact
    /// acquired zero-length identity.
    pub fn try_new(acquired: &CommandOutputCaptureAcquiredV1) -> Result<Self, ContractError> {
        acquired.validate()?;
        let canonical = CanonicalStagingNeutralization {
            schema_version: 1,
            capture_id: &acquired.capture_id,
            acquired_anchor_digest: &acquired.acquired_anchor_digest,
            stdout: &acquired.stdout,
            stderr: &acquired.stderr,
            aggregate_zero_length: 0,
        };
        let receipt_digest = compute_digest(STAGING_NEUTRALIZATION_DIGEST_DOMAIN, &canonical)?;
        let receipt = Self {
            schema_version: 1,
            capture_id: acquired.capture_id.clone(),
            acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            stdout: acquired.stdout.clone(),
            stderr: acquired.stderr.clone(),
            aggregate_zero_length: 0,
            receipt_digest,
        };
        receipt.validate_against(acquired)?;
        Ok(receipt)
    }

    /// Validates the self-contained zero-only shape and canonical digest.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any nonzero or noncanonical substitution.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_id(&self.capture_id)?;
        self.stdout.validate()?;
        self.stderr.validate()?;
        if self.schema_version != 1 || self.aggregate_zero_length != 0 || self.stdout == self.stderr
        {
            return Err(ContractError::new(
                "sensitive_output_staging_neutralization_receipt_v1",
                "requires v1, distinct exact held objects, and constant zero length",
            ));
        }
        let expected = compute_digest(
            STAGING_NEUTRALIZATION_DIGEST_DOMAIN,
            &CanonicalStagingNeutralization {
                schema_version: self.schema_version,
                capture_id: &self.capture_id,
                acquired_anchor_digest: &self.acquired_anchor_digest,
                stdout: &self.stdout,
                stderr: &self.stderr,
                aggregate_zero_length: self.aggregate_zero_length,
            },
        )?;
        if self.receipt_digest != expected {
            return Err(ContractError::new(
                "sensitive_output_staging_neutralization_receipt_v1.receipt_digest",
                "does not match the canonical zero-only receipt",
            ));
        }
        Ok(())
    }

    /// Validates exact capture, acquisition, and held-object identity.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a crossed acquisition or object.
    pub fn validate_against(
        &self,
        acquired: &CommandOutputCaptureAcquiredV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        acquired.validate()?;
        if self.capture_id != acquired.capture_id
            || self.acquired_anchor_digest != acquired.acquired_anchor_digest
            || self.stdout != acquired.stdout
            || self.stderr != acquired.stderr
        {
            return Err(ContractError::new(
                "sensitive_output_staging_neutralization_receipt_v1",
                "must name the exact acquired capture and both held staging objects",
            ));
        }
        Ok(())
    }
}

fn compute_policy_digest(policy_id: &str, policy_version: u32, markers: &[&str]) -> Digest {
    let canonical = serde_json::to_vec(&CanonicalPolicy {
        policy_id,
        policy_version,
        public_literal_markers: markers,
    })
    .expect("public detector policy reference is serializable");
    domain_digest(POLICY_DIGEST_DOMAIN, &canonical)
}

/// One secret-free runner-v12 journal head.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputJournalHeadV1 {
    /// One-based append-only journal generation.
    pub generation: u64,
    /// Digest of the exact secret-free state record at this generation.
    pub record_digest: Digest,
}

impl SensitiveOutputJournalHeadV1 {
    /// Validates a nonzero generation.
    ///
    /// # Errors
    ///
    /// Returns a contract error for generation zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.generation == 0 {
            return Err(ContractError::new(
                "sensitive_output_journal_head_v1.generation",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "the unboxed variants are the exact canonical journal preimages; indirection changes no serialized bytes or authority and obscures the frozen wire shape"
)]
enum SensitiveOutputJournalRecordDataV2 {
    IntentBound {
        runner_session_id: String,
        effect_id: String,
        request_digest: Digest,
        intent_digest: Digest,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    },
    AcquiredBound {
        acquired: CommandOutputCaptureAcquiredV1,
    },
    WriterAttached {
        writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    },
    LaunchIntended {
        launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
        core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    },
    ScannedClean {
        scanned_clean_at_unix_ms: u64,
    },
    SensitiveOutputDetected,
    Finished {
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        finished_at_unix_ms: u64,
    },
    CleanupIntended {
        command_domain_cleanup_proof_id: String,
        staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    },
    Published {
        published_store_head: CommandOutputCaptureStoreHeadV1,
        published_at_unix_ms: u64,
    },
    Cleaned {
        v1_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
    TerminalPrepared {
        terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: Digest,
        termination: CommandTerminationV1,
        terminal_prepared_at_unix_ms: u64,
    },
    SensitiveOutputRejected {
        termination: CommandTerminationV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
}

#[derive(Serialize)]
struct SensitiveOutputJournalRecordDigestPreimage<'a> {
    format_version: u32,
    generation: u64,
    journal_id: &'a str,
    capture_id: &'a str,
    predecessor_digest: Option<&'a Digest>,
    data: &'a SensitiveOutputJournalRecordDataV2,
}

fn expected_sensitive_output_journal_head(
    generation: u64,
    journal_id: &str,
    capture_id: &str,
    predecessor_digest: Option<&Digest>,
    data: &SensitiveOutputJournalRecordDataV2,
) -> Result<SensitiveOutputJournalHeadV1, ContractError> {
    let canonical = serde_json::to_vec(&SensitiveOutputJournalRecordDigestPreimage {
        format_version: SENSITIVE_OUTPUT_JOURNAL_FORMAT_VERSION,
        generation,
        journal_id,
        capture_id,
        predecessor_digest,
        data,
    })
    .map_err(|error| {
        ContractError::new(
            "sensitive_output_journal_record_v2",
            format!("cannot encode canonical record: {error}"),
        )
    })?;
    Ok(SensitiveOutputJournalHeadV1 {
        generation,
        record_digest: domain_digest(SENSITIVE_OUTPUT_JOURNAL_RECORD_DIGEST_DOMAIN, &canonical),
    })
}

/// Re-derives the exact secret-free runner-v2 acquisition prefix without
/// granting store, launch, or lifecycle authority.
///
/// This helper remains in the module that owns the frozen journal preimage so
/// current lifecycle schemas do not copy its domain, serde shape, or field
/// order. Callers must separately authenticate that the supplied heads came
/// from the private store; these digest computations prove only canonical
/// identity.
#[allow(
    clippy::too_many_arguments,
    reason = "the two-record prefix visibly authenticates every frozen IntentBound field and the complete AcquiredBound value"
)]
pub(super) fn derive_sensitive_output_acquisition_journal_heads_v2(
    journal_id: &str,
    capture_id: &str,
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &Digest,
    intent_digest: &Digest,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<[SensitiveOutputJournalHeadV1; 2], ContractError> {
    let intent_bound = expected_sensitive_output_journal_head(
        1,
        journal_id,
        capture_id,
        None,
        &SensitiveOutputJournalRecordDataV2::IntentBound {
            runner_session_id: runner_session_id.to_owned(),
            effect_id: effect_id.to_owned(),
            request_digest: request_digest.clone(),
            intent_digest: intent_digest.clone(),
            detector_policy: detector_policy.clone(),
        },
    )?;
    let acquired_bound = expected_sensitive_output_journal_head(
        2,
        journal_id,
        capture_id,
        Some(&intent_bound.record_digest),
        &SensitiveOutputJournalRecordDataV2::AcquiredBound {
            acquired: acquired.clone(),
        },
    )?;
    Ok([intent_bound, acquired_bound])
}

#[allow(
    clippy::too_many_arguments,
    reason = "the common journal prefix authenticates four exact records and every admitted input"
)]
fn compute_sensitive_output_common_journal_chain(
    journal_id: &str,
    capture_id: &str,
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &Digest,
    intent_digest: &Digest,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    writer_attached_store_head: &CommandOutputCaptureStoreHeadV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
) -> Result<[SensitiveOutputJournalHeadV1; 4], ContractError> {
    let [intent_bound, acquired_bound] = derive_sensitive_output_acquisition_journal_heads_v2(
        journal_id,
        capture_id,
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
        acquired,
    )?;
    let writer_attached = expected_sensitive_output_journal_head(
        3,
        journal_id,
        capture_id,
        Some(&acquired_bound.record_digest),
        &SensitiveOutputJournalRecordDataV2::WriterAttached {
            writer_attached_store_head: writer_attached_store_head.clone(),
        },
    )?;
    let launch_intended = expected_sensitive_output_journal_head(
        4,
        journal_id,
        capture_id,
        Some(&writer_attached.record_digest),
        &SensitiveOutputJournalRecordDataV2::LaunchIntended {
            launch_intended_store_head: launch_intended_store_head.clone(),
            core_dump_suppression: core_dump_suppression.clone(),
        },
    )?;
    Ok([
        intent_bound,
        acquired_bound,
        writer_attached,
        launch_intended,
    ])
}

#[allow(
    clippy::too_many_arguments,
    reason = "the common journal prefix authenticates four exact records and every admitted input"
)]
fn validate_sensitive_output_common_journal_chain(
    journal_id: &str,
    capture_id: &str,
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &Digest,
    intent_digest: &Digest,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    writer_attached_store_head: &CommandOutputCaptureStoreHeadV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
    expected_heads: [&SensitiveOutputJournalHeadV1; 4],
) -> Result<Digest, ContractError> {
    let actual_heads = compute_sensitive_output_common_journal_chain(
        journal_id,
        capture_id,
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
        acquired,
        writer_attached_store_head,
        launch_intended_store_head,
        core_dump_suppression,
    )?;
    for (actual, expected) in actual_heads.iter().zip(expected_heads) {
        if actual != expected {
            return Err(ContractError::new(
                "sensitive_output_journal_v2.common_chain",
                "generations one through four do not recompute from the exact admitted fields",
            ));
        }
    }
    Ok(actual_heads[3].record_digest.clone())
}

/// Exact secret-free runner-v2 clean-branch readback before it is joined to a
/// core v27 terminal.
///
/// This shape intentionally mirrors the runner receipt without importing a
/// runner crate into core. Desktop translation must copy every field exactly;
/// core then revalidates the complete acquisition, request, policy, heads,
/// termination, and runner-sampled boundary order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputCleanRunnerReferenceV1 {
    /// Exact runner-owned v2 journal identity.
    pub journal_id: String,
    /// Exact private capture identity.
    pub capture_id: String,
    /// Exact admitted runner session.
    pub runner_session_id: String,
    /// Exact admitted effect identity.
    pub effect_id: String,
    /// Exact admitted opaque request digest.
    pub request_digest: Digest,
    /// Exact core capture-intent digest.
    pub intent_digest: Digest,
    /// Complete exact physical acquisition.
    pub acquired: CommandOutputCaptureAcquiredV1,
    /// Exact physical acquisition digest.
    pub acquired_anchor_digest: Digest,
    /// Frozen-v1 `Acquired` store head.
    pub acquired_store_head: CommandOutputCaptureStoreHeadV1,
    /// Frozen-v1 `WriterAttached` store head.
    pub writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    /// Frozen-v1 `LaunchIntended` store head.
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact pre-launch zero-dump profile.
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    /// Exact detector policy admitted before dispatch.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Generation-one `IntentBound` head.
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-two `AcquiredBound` head.
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-three `WriterAttached` head.
    pub writer_attached_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-four `LaunchIntended` head.
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-five `ScannedClean` head.
    pub scanned_clean_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-six `Finished` head.
    pub finished_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-seven `Published` head.
    pub published_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-eight `TerminalPrepared` head.
    pub terminal_prepared_journal_head: SensitiveOutputJournalHeadV1,
    /// Frozen-v1 `Finished` store head.
    pub finished_store_head: CommandOutputCaptureStoreHeadV1,
    /// Frozen-v1 `Published` store head.
    pub published_store_head: CommandOutputCaptureStoreHeadV1,
    /// Frozen-v1 `TerminalPrepared` store head.
    pub terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact frozen-v1 terminal record digest.
    pub terminal_record_digest: Digest,
    /// Exact typed command termination.
    pub termination: CommandTerminationV1,
    /// Runner-sampled generation-five boundary time.
    pub scanned_clean_at_unix_ms: u64,
    /// Runner-sampled generation-six boundary time.
    pub finished_at_unix_ms: u64,
    /// Runner-sampled generation-seven boundary time.
    pub published_at_unix_ms: u64,
    /// Runner-sampled generation-eight boundary time.
    pub terminal_prepared_at_unix_ms: u64,
}

impl SensitiveOutputCleanRunnerReferenceV1 {
    /// Validates the exact clean runner branch without trusting adapter claims.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed acquisition, noncanonical
    /// policy, wrong generation, reused head, or nonmonotonic boundary.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear validator recomputes the complete frozen clean journal chain and keeps all eight identity checks auditable together"
    )]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_id(&self.capture_id)?;
        for (field, value) in [
            ("journal_id", self.journal_id.as_str()),
            ("runner_session_id", self.runner_session_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
        ] {
            require_id(field, value)?;
        }
        self.acquired.validate()?;
        self.detector_policy.validate()?;
        self.core_dump_suppression.validate()?;
        self.termination.validate()?;
        for head in [
            &self.intent_bound_journal_head,
            &self.acquired_bound_journal_head,
            &self.writer_attached_journal_head,
            &self.launch_intended_journal_head,
            &self.scanned_clean_journal_head,
            &self.finished_journal_head,
            &self.published_journal_head,
            &self.terminal_prepared_journal_head,
        ] {
            head.validate()?;
        }
        for head in [
            &self.acquired_store_head,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.finished_store_head,
            &self.published_store_head,
            &self.terminal_prepared_store_head,
        ] {
            head.validate()?;
        }
        if self.capture_id != self.acquired.capture_id
            || self.runner_session_id != self.acquired.source.runner_session_id
            || self.effect_id != self.acquired.source.effect_id
            || self.request_digest != self.acquired.source.request_digest
            || self.intent_digest != self.acquired.intent_digest
            || self.acquired_anchor_digest != self.acquired.acquired_anchor_digest
            || self.acquired_store_head != self.acquired.store_head
            || self.intent_bound_journal_head.generation != 1
            || self.acquired_bound_journal_head.generation != 2
            || self.writer_attached_journal_head.generation != 3
            || self.launch_intended_journal_head.generation != 4
            || self.scanned_clean_journal_head.generation != 5
            || self.finished_journal_head.generation != 6
            || self.published_journal_head.generation != 7
            || self.terminal_prepared_journal_head.generation != 8
            || !all_digests_distinct(&[
                &self.intent_bound_journal_head.record_digest,
                &self.acquired_bound_journal_head.record_digest,
                &self.writer_attached_journal_head.record_digest,
                &self.launch_intended_journal_head.record_digest,
                &self.scanned_clean_journal_head.record_digest,
                &self.finished_journal_head.record_digest,
                &self.published_journal_head.record_digest,
                &self.terminal_prepared_journal_head.record_digest,
            ])
            || !all_digests_distinct(&[
                &self.acquired_store_head.record_digest,
                &self.writer_attached_store_head.record_digest,
                &self.launch_intended_store_head.record_digest,
                &self.finished_store_head.record_digest,
                &self.published_store_head.record_digest,
                &self.terminal_prepared_store_head.record_digest,
            ])
            || self.acquired_store_head.generation >= self.writer_attached_store_head.generation
            || self.writer_attached_store_head.generation
                >= self.launch_intended_store_head.generation
            || self.launch_intended_store_head.generation >= self.finished_store_head.generation
            || self.finished_store_head.generation >= self.published_store_head.generation
            || self.published_store_head.generation >= self.terminal_prepared_store_head.generation
            || self.scanned_clean_at_unix_ms < self.acquired.acquired_at_unix_ms
            || self.finished_at_unix_ms < self.scanned_clean_at_unix_ms
            || self.published_at_unix_ms < self.finished_at_unix_ms
            || self.terminal_prepared_at_unix_ms < self.published_at_unix_ms
        {
            return Err(ContractError::new(
                "sensitive_output_clean_runner_reference_v1",
                "must bind the full acquisition and exact ordered clean runner-v2/v1 branches",
            ));
        }
        let launch_digest = validate_sensitive_output_common_journal_chain(
            &self.journal_id,
            &self.capture_id,
            &self.runner_session_id,
            &self.effect_id,
            &self.request_digest,
            &self.intent_digest,
            &self.detector_policy,
            &self.acquired,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.core_dump_suppression,
            [
                &self.intent_bound_journal_head,
                &self.acquired_bound_journal_head,
                &self.writer_attached_journal_head,
                &self.launch_intended_journal_head,
            ],
        )?;
        let scanned = expected_sensitive_output_journal_head(
            5,
            &self.journal_id,
            &self.capture_id,
            Some(&launch_digest),
            &SensitiveOutputJournalRecordDataV2::ScannedClean {
                scanned_clean_at_unix_ms: self.scanned_clean_at_unix_ms,
            },
        )?;
        let finished = expected_sensitive_output_journal_head(
            6,
            &self.journal_id,
            &self.capture_id,
            Some(&scanned.record_digest),
            &SensitiveOutputJournalRecordDataV2::Finished {
                finished_store_head: self.finished_store_head.clone(),
                finished_at_unix_ms: self.finished_at_unix_ms,
            },
        )?;
        let published = expected_sensitive_output_journal_head(
            7,
            &self.journal_id,
            &self.capture_id,
            Some(&finished.record_digest),
            &SensitiveOutputJournalRecordDataV2::Published {
                published_store_head: self.published_store_head.clone(),
                published_at_unix_ms: self.published_at_unix_ms,
            },
        )?;
        let terminal = expected_sensitive_output_journal_head(
            8,
            &self.journal_id,
            &self.capture_id,
            Some(&published.record_digest),
            &SensitiveOutputJournalRecordDataV2::TerminalPrepared {
                terminal_prepared_store_head: self.terminal_prepared_store_head.clone(),
                terminal_record_digest: self.terminal_record_digest.clone(),
                termination: self.termination,
                terminal_prepared_at_unix_ms: self.terminal_prepared_at_unix_ms,
            },
        )?;
        if scanned != self.scanned_clean_journal_head
            || finished != self.finished_journal_head
            || published != self.published_journal_head
            || terminal != self.terminal_prepared_journal_head
        {
            return Err(ContractError::new(
                "sensitive_output_clean_runner_reference_v1.journal_chain",
                "generations five through eight do not recompute from exact clean-branch fields",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn canonicalize_journal_heads_for_test(&mut self) -> Result<(), ContractError> {
        let common = compute_sensitive_output_common_journal_chain(
            &self.journal_id,
            &self.capture_id,
            &self.runner_session_id,
            &self.effect_id,
            &self.request_digest,
            &self.intent_digest,
            &self.detector_policy,
            &self.acquired,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.core_dump_suppression,
        )?;
        let scanned = expected_sensitive_output_journal_head(
            5,
            &self.journal_id,
            &self.capture_id,
            Some(&common[3].record_digest),
            &SensitiveOutputJournalRecordDataV2::ScannedClean {
                scanned_clean_at_unix_ms: self.scanned_clean_at_unix_ms,
            },
        )?;
        let finished = expected_sensitive_output_journal_head(
            6,
            &self.journal_id,
            &self.capture_id,
            Some(&scanned.record_digest),
            &SensitiveOutputJournalRecordDataV2::Finished {
                finished_store_head: self.finished_store_head.clone(),
                finished_at_unix_ms: self.finished_at_unix_ms,
            },
        )?;
        let published = expected_sensitive_output_journal_head(
            7,
            &self.journal_id,
            &self.capture_id,
            Some(&finished.record_digest),
            &SensitiveOutputJournalRecordDataV2::Published {
                published_store_head: self.published_store_head.clone(),
                published_at_unix_ms: self.published_at_unix_ms,
            },
        )?;
        let terminal = expected_sensitive_output_journal_head(
            8,
            &self.journal_id,
            &self.capture_id,
            Some(&published.record_digest),
            &SensitiveOutputJournalRecordDataV2::TerminalPrepared {
                terminal_prepared_store_head: self.terminal_prepared_store_head.clone(),
                terminal_record_digest: self.terminal_record_digest.clone(),
                termination: self.termination,
                terminal_prepared_at_unix_ms: self.terminal_prepared_at_unix_ms,
            },
        )?;
        self.intent_bound_journal_head = common[0].clone();
        self.acquired_bound_journal_head = common[1].clone();
        self.writer_attached_journal_head = common[2].clone();
        self.launch_intended_journal_head = common[3].clone();
        self.scanned_clean_journal_head = scanned;
        self.finished_journal_head = finished;
        self.published_journal_head = published;
        self.terminal_prepared_journal_head = terminal;
        Ok(())
    }
}

/// Core-owned authority that one current-policy capture traversed the exact
/// clean runner-v2 branch before its v27 `Published` terminal was admitted.
///
/// The embedded acquisition is intentional: the receipt digest authenticates
/// the complete preallocated capture authority, not only a caller-selected
/// subset or an untyped runner assertion. The four times are runner-sampled
/// boundary observations bound into generations five through eight; they are
/// not database durability timestamps.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCleanScanPublicationReceiptV1 {
    /// Shared repository contract version.
    pub contract_version: u32,
    /// Private command-output capture layout version.
    pub layout_version: u32,
    /// Deterministic core identity derived from the exact v27 terminal anchor.
    pub clean_scan_receipt_id: String,
    /// Exact private capture identity.
    pub capture_id: String,
    /// Exact admitted `RunCommand` effect identity.
    pub effect_id: String,
    /// Exact effect observation committed with the terminal.
    pub observation_id: String,
    /// Exact runner session admitted by the capture intent.
    pub runner_session_id: String,
    /// Exact admitted opaque request digest.
    pub request_digest: Digest,
    /// Digest of the canonical pre-effect capture intent.
    pub intent_digest: Digest,
    /// Complete exact physical acquisition anchored before dispatch.
    pub acquired: CommandOutputCaptureAcquiredV1,
    /// Exact detector policy admitted before dispatch.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact pre-launch zero-dump profile bound into runner-v2 generation four.
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    /// Exact secret-free runner-v2 journal identity.
    pub runner_journal_id: String,
    /// Generation-one `IntentBound` head.
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-two `AcquiredBound` head.
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-three `WriterAttached` head.
    pub writer_attached_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-four `LaunchIntended` head binding the zero-dump profile.
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-five `ScannedClean` head.
    pub scanned_clean_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-six `Finished` head.
    pub finished_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-seven `Published` head.
    pub published_journal_head: SensitiveOutputJournalHeadV1,
    /// Generation-eight `TerminalPrepared` head.
    pub terminal_prepared_journal_head: SensitiveOutputJournalHeadV1,
    /// Exact v1 `Acquired` store head copied from the full acquisition.
    pub acquired_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact v1 `WriterAttached` store head.
    pub writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact v1 `LaunchIntended` store head.
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact v1 `Finished` store head.
    pub finished_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact v1 `Published` store head.
    pub published_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact v1 `TerminalPrepared` store head.
    pub terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact bounded terminal record digest authenticated by generation eight.
    pub terminal_record_digest: Digest,
    /// Exact typed command termination authenticated by generation eight.
    pub termination: CommandTerminationV1,
    /// Runner-sampled scan boundary bound into generation five.
    pub scanned_clean_at_unix_ms: u64,
    /// Runner-sampled finish boundary bound into generation six.
    pub finished_at_unix_ms: u64,
    /// Runner-sampled publication boundary bound into generation seven.
    pub published_at_unix_ms: u64,
    /// Runner-sampled terminal-prepared boundary bound into generation eight.
    pub terminal_prepared_at_unix_ms: u64,
    /// Exact v27 Published terminal identity committed in the same transaction.
    pub terminal_anchor_digest: Digest,
    /// Digest of every preceding canonical field.
    pub clean_scan_receipt_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCleanScanPublicationReceipt<'a> {
    contract_version: u32,
    layout_version: u32,
    clean_scan_receipt_id: &'a str,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    runner_session_id: &'a str,
    request_digest: &'a Digest,
    intent_digest: &'a Digest,
    acquired: &'a CommandOutputCaptureAcquiredV1,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    core_dump_suppression: &'a SensitiveOutputCoreDumpSuppressionV1,
    runner_journal_id: &'a str,
    intent_bound_journal_head: &'a SensitiveOutputJournalHeadV1,
    acquired_bound_journal_head: &'a SensitiveOutputJournalHeadV1,
    writer_attached_journal_head: &'a SensitiveOutputJournalHeadV1,
    launch_intended_journal_head: &'a SensitiveOutputJournalHeadV1,
    scanned_clean_journal_head: &'a SensitiveOutputJournalHeadV1,
    finished_journal_head: &'a SensitiveOutputJournalHeadV1,
    published_journal_head: &'a SensitiveOutputJournalHeadV1,
    terminal_prepared_journal_head: &'a SensitiveOutputJournalHeadV1,
    acquired_store_head: &'a CommandOutputCaptureStoreHeadV1,
    writer_attached_store_head: &'a CommandOutputCaptureStoreHeadV1,
    launch_intended_store_head: &'a CommandOutputCaptureStoreHeadV1,
    finished_store_head: &'a CommandOutputCaptureStoreHeadV1,
    published_store_head: &'a CommandOutputCaptureStoreHeadV1,
    terminal_prepared_store_head: &'a CommandOutputCaptureStoreHeadV1,
    terminal_record_digest: &'a Digest,
    termination: CommandTerminationV1,
    scanned_clean_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    published_at_unix_ms: u64,
    terminal_prepared_at_unix_ms: u64,
    terminal_anchor_digest: &'a Digest,
}

impl CommandOutputCleanScanPublicationReceiptV1 {
    /// Joins one exact translated runner-v2 clean receipt to its core-owned v27
    /// Published terminal.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any adapter substitution or terminal cross.
    pub fn try_new_from_runner_reference(
        intent: &CommandOutputCaptureIntentV1,
        runner: &SensitiveOutputCleanRunnerReferenceV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
    ) -> Result<Self, ContractError> {
        runner.validate()?;
        runner.acquired.validate_against(intent)?;
        Self::try_new(
            intent,
            &runner.acquired,
            runner.detector_policy.clone(),
            runner.core_dump_suppression.clone(),
            runner.journal_id.clone(),
            runner.intent_bound_journal_head.clone(),
            runner.acquired_bound_journal_head.clone(),
            runner.writer_attached_journal_head.clone(),
            runner.launch_intended_journal_head.clone(),
            runner.scanned_clean_journal_head.clone(),
            runner.finished_journal_head.clone(),
            runner.published_journal_head.clone(),
            runner.terminal_prepared_journal_head.clone(),
            runner.writer_attached_store_head.clone(),
            runner.launch_intended_store_head.clone(),
            runner.finished_store_head.clone(),
            runner.published_store_head.clone(),
            runner.terminal_prepared_store_head.clone(),
            runner.terminal_record_digest.clone(),
            runner.termination,
            runner.scanned_clean_at_unix_ms,
            runner.finished_at_unix_ms,
            runner.published_at_unix_ms,
            runner.terminal_prepared_at_unix_ms,
            terminal,
        )
    }

    /// Constructs the core receipt from exact runner-v2 clean-branch fields and
    /// the v27 Published terminal they authorize.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed request, acquisition, policy,
    /// journal, store, termination, time, or terminal identity.
    #[allow(
        clippy::too_many_arguments,
        reason = "the constructor binds every independent runner-v2 and v1 custody boundary"
    )]
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
        runner_journal_id: impl Into<String>,
        intent_bound_journal_head: SensitiveOutputJournalHeadV1,
        acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
        writer_attached_journal_head: SensitiveOutputJournalHeadV1,
        launch_intended_journal_head: SensitiveOutputJournalHeadV1,
        scanned_clean_journal_head: SensitiveOutputJournalHeadV1,
        finished_journal_head: SensitiveOutputJournalHeadV1,
        published_journal_head: SensitiveOutputJournalHeadV1,
        terminal_prepared_journal_head: SensitiveOutputJournalHeadV1,
        writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
        launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        published_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: Digest,
        termination: CommandTerminationV1,
        scanned_clean_at_unix_ms: u64,
        finished_at_unix_ms: u64,
        published_at_unix_ms: u64,
        terminal_prepared_at_unix_ms: u64,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
    ) -> Result<Self, ContractError> {
        intent.validate()?;
        acquired.validate_against(intent)?;
        detector_policy.validate()?;
        core_dump_suppression.validate()?;
        terminal.validate()?;
        let runner_journal_id = runner_journal_id.into();
        let clean_scan_receipt_id = clean_scan_receipt_id(&terminal.terminal_anchor_digest);
        let canonical = CanonicalCleanScanPublicationReceipt {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            clean_scan_receipt_id: &clean_scan_receipt_id,
            capture_id: &intent.capture_id,
            effect_id: &intent.source.effect_id,
            observation_id: &terminal.observation_id,
            runner_session_id: &intent.source.runner_session_id,
            request_digest: &intent.source.request_digest,
            intent_digest: &intent.intent_digest,
            acquired,
            detector_policy: &detector_policy,
            core_dump_suppression: &core_dump_suppression,
            runner_journal_id: &runner_journal_id,
            intent_bound_journal_head: &intent_bound_journal_head,
            acquired_bound_journal_head: &acquired_bound_journal_head,
            writer_attached_journal_head: &writer_attached_journal_head,
            launch_intended_journal_head: &launch_intended_journal_head,
            scanned_clean_journal_head: &scanned_clean_journal_head,
            finished_journal_head: &finished_journal_head,
            published_journal_head: &published_journal_head,
            terminal_prepared_journal_head: &terminal_prepared_journal_head,
            acquired_store_head: &acquired.store_head,
            writer_attached_store_head: &writer_attached_store_head,
            launch_intended_store_head: &launch_intended_store_head,
            finished_store_head: &finished_store_head,
            published_store_head: &published_store_head,
            terminal_prepared_store_head: &terminal_prepared_store_head,
            terminal_record_digest: &terminal_record_digest,
            termination,
            scanned_clean_at_unix_ms,
            finished_at_unix_ms,
            published_at_unix_ms,
            terminal_prepared_at_unix_ms,
            terminal_anchor_digest: &terminal.terminal_anchor_digest,
        };
        let clean_scan_receipt_digest =
            compute_digest(CLEAN_SCAN_PUBLICATION_DIGEST_DOMAIN, &canonical)?;
        let receipt = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            clean_scan_receipt_id,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            observation_id: terminal.observation_id.clone(),
            runner_session_id: intent.source.runner_session_id.clone(),
            request_digest: intent.source.request_digest.clone(),
            intent_digest: intent.intent_digest.clone(),
            acquired: acquired.clone(),
            detector_policy,
            core_dump_suppression,
            runner_journal_id,
            intent_bound_journal_head,
            acquired_bound_journal_head,
            writer_attached_journal_head,
            launch_intended_journal_head,
            scanned_clean_journal_head,
            finished_journal_head,
            published_journal_head,
            terminal_prepared_journal_head,
            acquired_store_head: acquired.store_head.clone(),
            writer_attached_store_head,
            launch_intended_store_head,
            finished_store_head,
            published_store_head,
            terminal_prepared_store_head,
            terminal_record_digest,
            termination,
            scanned_clean_at_unix_ms,
            finished_at_unix_ms,
            published_at_unix_ms,
            terminal_prepared_at_unix_ms,
            terminal_anchor_digest: terminal.terminal_anchor_digest.clone(),
            clean_scan_receipt_digest,
        };
        receipt.validate_against(intent, acquired, &receipt.detector_policy, terminal)?;
        Ok(receipt)
    }

    /// Validates the self-contained canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a noncanonical identity, branch, or order.
    #[allow(
        clippy::too_many_lines,
        reason = "the self-contained receipt validator must visibly rederive every normalized field, all eight journal heads, and the terminal-bound digest"
    )]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_versions(self.contract_version, self.layout_version)?;
        require_capture_id(&self.capture_id)?;
        for (field, value) in [
            ("clean_scan_receipt_id", self.clean_scan_receipt_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
            ("observation_id", self.observation_id.as_str()),
            ("runner_session_id", self.runner_session_id.as_str()),
            ("runner_journal_id", self.runner_journal_id.as_str()),
        ] {
            require_id(field, value)?;
        }
        self.acquired.validate()?;
        self.detector_policy.validate()?;
        self.core_dump_suppression.validate()?;
        self.termination.validate()?;
        for head in [
            &self.intent_bound_journal_head,
            &self.acquired_bound_journal_head,
            &self.writer_attached_journal_head,
            &self.launch_intended_journal_head,
            &self.scanned_clean_journal_head,
            &self.finished_journal_head,
            &self.published_journal_head,
            &self.terminal_prepared_journal_head,
        ] {
            head.validate()?;
        }
        for head in [
            &self.acquired_store_head,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.finished_store_head,
            &self.published_store_head,
            &self.terminal_prepared_store_head,
        ] {
            head.validate()?;
        }
        let journal_digests = [
            &self.intent_bound_journal_head.record_digest,
            &self.acquired_bound_journal_head.record_digest,
            &self.writer_attached_journal_head.record_digest,
            &self.launch_intended_journal_head.record_digest,
            &self.scanned_clean_journal_head.record_digest,
            &self.finished_journal_head.record_digest,
            &self.published_journal_head.record_digest,
            &self.terminal_prepared_journal_head.record_digest,
        ];
        let store_digests = [
            &self.acquired_store_head.record_digest,
            &self.writer_attached_store_head.record_digest,
            &self.launch_intended_store_head.record_digest,
            &self.finished_store_head.record_digest,
            &self.published_store_head.record_digest,
            &self.terminal_prepared_store_head.record_digest,
        ];
        if self.intent_bound_journal_head.generation != 1
            || self.acquired_bound_journal_head.generation != 2
            || self.writer_attached_journal_head.generation != 3
            || self.launch_intended_journal_head.generation != 4
            || self.scanned_clean_journal_head.generation != 5
            || self.finished_journal_head.generation != 6
            || self.published_journal_head.generation != 7
            || self.terminal_prepared_journal_head.generation != 8
            || !all_digests_distinct(&journal_digests)
            || !all_digests_distinct(&store_digests)
            || self.acquired_store_head.generation >= self.writer_attached_store_head.generation
            || self.writer_attached_store_head.generation
                >= self.launch_intended_store_head.generation
            || self.launch_intended_store_head.generation >= self.finished_store_head.generation
            || self.finished_store_head.generation >= self.published_store_head.generation
            || self.published_store_head.generation >= self.terminal_prepared_store_head.generation
        {
            return Err(ContractError::new(
                "command_output_clean_scan_publication_receipt_v1.heads",
                "must prove exact clean generations five through eight and strictly ordered distinct v1 heads",
            ));
        }
        if self.scanned_clean_at_unix_ms < self.acquired.acquired_at_unix_ms
            || self.finished_at_unix_ms < self.scanned_clean_at_unix_ms
            || self.published_at_unix_ms < self.finished_at_unix_ms
            || self.terminal_prepared_at_unix_ms < self.published_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_clean_scan_publication_receipt_v1.boundary_times",
                "must prove acquisition <= clean scan <= finish <= publication <= terminal preparation",
            ));
        }
        if self.clean_scan_receipt_id != clean_scan_receipt_id(&self.terminal_anchor_digest)
            || self.acquired_store_head != self.acquired.store_head
        {
            return Err(ContractError::new(
                "command_output_clean_scan_publication_receipt_v1.identity",
                "receipt identity and acquired store head must derive from exact authorities",
            ));
        }
        SensitiveOutputCleanRunnerReferenceV1 {
            journal_id: self.runner_journal_id.clone(),
            capture_id: self.capture_id.clone(),
            runner_session_id: self.runner_session_id.clone(),
            effect_id: self.effect_id.clone(),
            request_digest: self.request_digest.clone(),
            intent_digest: self.intent_digest.clone(),
            acquired: self.acquired.clone(),
            acquired_anchor_digest: self.acquired.acquired_anchor_digest.clone(),
            acquired_store_head: self.acquired_store_head.clone(),
            writer_attached_store_head: self.writer_attached_store_head.clone(),
            launch_intended_store_head: self.launch_intended_store_head.clone(),
            core_dump_suppression: self.core_dump_suppression.clone(),
            detector_policy: self.detector_policy.clone(),
            intent_bound_journal_head: self.intent_bound_journal_head.clone(),
            acquired_bound_journal_head: self.acquired_bound_journal_head.clone(),
            writer_attached_journal_head: self.writer_attached_journal_head.clone(),
            launch_intended_journal_head: self.launch_intended_journal_head.clone(),
            scanned_clean_journal_head: self.scanned_clean_journal_head.clone(),
            finished_journal_head: self.finished_journal_head.clone(),
            published_journal_head: self.published_journal_head.clone(),
            terminal_prepared_journal_head: self.terminal_prepared_journal_head.clone(),
            finished_store_head: self.finished_store_head.clone(),
            published_store_head: self.published_store_head.clone(),
            terminal_prepared_store_head: self.terminal_prepared_store_head.clone(),
            terminal_record_digest: self.terminal_record_digest.clone(),
            termination: self.termination,
            scanned_clean_at_unix_ms: self.scanned_clean_at_unix_ms,
            finished_at_unix_ms: self.finished_at_unix_ms,
            published_at_unix_ms: self.published_at_unix_ms,
            terminal_prepared_at_unix_ms: self.terminal_prepared_at_unix_ms,
        }
        .validate()?;
        let expected = compute_digest(
            CLEAN_SCAN_PUBLICATION_DIGEST_DOMAIN,
            &CanonicalCleanScanPublicationReceipt {
                contract_version: self.contract_version,
                layout_version: self.layout_version,
                clean_scan_receipt_id: &self.clean_scan_receipt_id,
                capture_id: &self.capture_id,
                effect_id: &self.effect_id,
                observation_id: &self.observation_id,
                runner_session_id: &self.runner_session_id,
                request_digest: &self.request_digest,
                intent_digest: &self.intent_digest,
                acquired: &self.acquired,
                detector_policy: &self.detector_policy,
                core_dump_suppression: &self.core_dump_suppression,
                runner_journal_id: &self.runner_journal_id,
                intent_bound_journal_head: &self.intent_bound_journal_head,
                acquired_bound_journal_head: &self.acquired_bound_journal_head,
                writer_attached_journal_head: &self.writer_attached_journal_head,
                launch_intended_journal_head: &self.launch_intended_journal_head,
                scanned_clean_journal_head: &self.scanned_clean_journal_head,
                finished_journal_head: &self.finished_journal_head,
                published_journal_head: &self.published_journal_head,
                terminal_prepared_journal_head: &self.terminal_prepared_journal_head,
                acquired_store_head: &self.acquired_store_head,
                writer_attached_store_head: &self.writer_attached_store_head,
                launch_intended_store_head: &self.launch_intended_store_head,
                finished_store_head: &self.finished_store_head,
                published_store_head: &self.published_store_head,
                terminal_prepared_store_head: &self.terminal_prepared_store_head,
                terminal_record_digest: &self.terminal_record_digest,
                termination: self.termination,
                scanned_clean_at_unix_ms: self.scanned_clean_at_unix_ms,
                finished_at_unix_ms: self.finished_at_unix_ms,
                published_at_unix_ms: self.published_at_unix_ms,
                terminal_prepared_at_unix_ms: self.terminal_prepared_at_unix_ms,
                terminal_anchor_digest: &self.terminal_anchor_digest,
            },
        )?;
        if self.clean_scan_receipt_digest != expected {
            return Err(ContractError::new(
                "command_output_clean_scan_publication_receipt_v1.clean_scan_receipt_digest",
                "does not match the canonical clean-scan publication receipt",
            ));
        }
        Ok(())
    }

    /// Validates the receipt against the exact durable input and v27 terminal.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed or stale binding.
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        intent.validate()?;
        acquired.validate_against(intent)?;
        detector_policy.validate()?;
        terminal.validate()?;
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.observation_id != terminal.observation_id
            || self.runner_session_id != intent.source.runner_session_id
            || self.request_digest != intent.source.request_digest
            || self.intent_digest != intent.intent_digest
            || self.acquired != *acquired
            || self.detector_policy != *detector_policy
            || self.acquired_store_head != acquired.store_head
            || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Published
            || terminal.capture_id != self.capture_id
            || terminal.effect_id != self.effect_id
            || terminal.dispatch_claim_id.as_deref() != Some(acquired.dispatch_claim_id.as_str())
            || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
            || terminal.store_head != self.terminal_prepared_store_head
            || terminal.terminal_record_digest != self.terminal_record_digest
            || terminal.terminal_anchor_digest != self.terminal_anchor_digest
            || terminal.anchored_at_unix_ms < self.terminal_prepared_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_clean_scan_publication_receipt_v1",
                "must match exact request, acquisition, current policy, clean branch, and Published terminal",
            ));
        }
        Ok(())
    }
}

fn clean_scan_receipt_id(terminal_anchor_digest: &Digest) -> String {
    format!(
        "{CLEAN_SCAN_RECEIPT_ID_PREFIX}{}",
        terminal_anchor_digest.as_str()
    )
}

/// Core-owned authority for one current-policy clean runner-v2 branch that
/// resolves an immutable `Unknown`/`ReconciliationRequired` capture as
/// `Published` without rewriting the original observation or terminal.
///
/// Every authority input is embedded deliberately. The receipt is therefore
/// independently revalidatable after restart and cannot borrow a clean scan,
/// acquisition, claim, terminal, or resolution from another effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCleanScanResolutionReceiptV1 {
    /// Shared repository contract version.
    pub contract_version: u32,
    /// Private command-output capture layout version.
    pub layout_version: u32,
    /// Deterministic receipt identity derived from the exact resolution.
    pub clean_scan_resolution_receipt_id: String,
    /// Exact pre-effect capture intent.
    pub intent: CommandOutputCaptureIntentV1,
    /// Exact physical acquisition admitted before dispatch.
    pub acquired: CommandOutputCaptureAcquiredV1,
    /// Immutable diagnostic terminal that remains `Unknown`.
    pub unknown_terminal: CommandOutputCaptureTerminalAnchorV1,
    /// Exact fenced reconciliation claim consumed by the resolution.
    pub reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    /// Exact append-only `Published` reconciliation result.
    pub resolution: CommandOutputCaptureReconciliationResolutionV1,
    /// Exact immutable restart receipt for the narrowly typed same-head
    /// branch. Absent for the ordinary head-advancing branch so historical
    /// v29 advancing receipt bytes remain canonical without change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_same_head_receipt: Option<CommandOutputCapturePhysicalReconciliationV1>,
    /// Detector policy admitted before the original dispatch.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Full runner-v2 clean branch, including every generation-one-to-eight head.
    pub clean_runner: SensitiveOutputCleanRunnerReferenceV1,
    /// Digest of every preceding canonical field.
    pub clean_scan_resolution_receipt_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCleanScanResolutionReceipt<'a> {
    contract_version: u32,
    layout_version: u32,
    clean_scan_resolution_receipt_id: &'a str,
    intent: &'a CommandOutputCaptureIntentV1,
    acquired: &'a CommandOutputCaptureAcquiredV1,
    unknown_terminal: &'a CommandOutputCaptureTerminalAnchorV1,
    reconciliation_claim: &'a CommandOutputCaptureReconciliationClaimV1,
    resolution: &'a CommandOutputCaptureReconciliationResolutionV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_same_head_receipt: Option<&'a CommandOutputCapturePhysicalReconciliationV1>,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    clean_runner: &'a SensitiveOutputCleanRunnerReferenceV1,
}

impl CommandOutputCleanScanResolutionReceiptV1 {
    /// Constructs one exact current-policy clean resolution receipt.
    ///
    /// # Errors
    ///
    /// Returns a contract error unless every embedded authority belongs to the
    /// same capture and the clean runner's terminal-prepared head is the exact
    /// fenced `Published` resolution head.
    #[allow(
        clippy::too_many_arguments,
        reason = "construction deliberately exposes every independently crossed durable authority"
    )]
    pub fn try_new_from_runner_reference(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        unknown_terminal: &CommandOutputCaptureTerminalAnchorV1,
        reconciliation_claim: &CommandOutputCaptureReconciliationClaimV1,
        resolution: &CommandOutputCaptureReconciliationResolutionV1,
        restart_same_head_receipt: Option<&CommandOutputCapturePhysicalReconciliationV1>,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        clean_runner: &SensitiveOutputCleanRunnerReferenceV1,
    ) -> Result<Self, ContractError> {
        let clean_scan_resolution_receipt_id =
            clean_scan_resolution_receipt_id(&resolution.resolution_anchor_digest);
        let canonical = CanonicalCleanScanResolutionReceipt {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            clean_scan_resolution_receipt_id: &clean_scan_resolution_receipt_id,
            intent,
            acquired,
            unknown_terminal,
            reconciliation_claim,
            resolution,
            restart_same_head_receipt,
            detector_policy: &detector_policy,
            clean_runner,
        };
        let clean_scan_resolution_receipt_digest =
            compute_digest(CLEAN_SCAN_RESOLUTION_DIGEST_DOMAIN, &canonical)?;
        let receipt = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            clean_scan_resolution_receipt_id,
            intent: intent.clone(),
            acquired: acquired.clone(),
            unknown_terminal: unknown_terminal.clone(),
            reconciliation_claim: reconciliation_claim.clone(),
            resolution: resolution.clone(),
            restart_same_head_receipt: restart_same_head_receipt.cloned(),
            detector_policy,
            clean_runner: clean_runner.clone(),
            clean_scan_resolution_receipt_digest,
        };
        receipt.validate_against(
            intent,
            acquired,
            unknown_terminal,
            reconciliation_claim,
            resolution,
            &receipt.detector_policy,
        )?;
        Ok(receipt)
    }

    /// Validates the complete self-contained clean-resolution authority.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any noncanonical or crossed embedded input.
    #[allow(
        clippy::too_many_lines,
        reason = "one self-contained receipt validation keeps branch, identity, and canonical-digest checks together"
    )]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_versions(self.contract_version, self.layout_version)?;
        require_id(
            "clean_scan_resolution_receipt_id",
            &self.clean_scan_resolution_receipt_id,
        )?;
        self.intent.validate()?;
        self.acquired.validate_against(&self.intent)?;
        self.unknown_terminal.validate()?;
        self.reconciliation_claim.validate()?;
        let same_head = self.resolution.store_head == self.unknown_terminal.store_head;
        match (same_head, self.restart_same_head_receipt.as_ref()) {
            (true, Some(restart_receipt)) => {
                self.resolution.validate_against_restart_same_head(
                    &self.intent,
                    &self.acquired,
                    &self.unknown_terminal,
                    &self.reconciliation_claim,
                    restart_receipt,
                )?;
            }
            (false, None) => self.resolution.validate_against(
                &self.intent,
                &self.unknown_terminal,
                &self.reconciliation_claim,
            )?,
            (true, None) => {
                return Err(ContractError::new(
                    "command_output_clean_scan_resolution_receipt_v1.restart_same_head_receipt",
                    "same-head publication requires its exact immutable restart receipt",
                ));
            }
            (false, Some(_)) => {
                return Err(ContractError::new(
                    "command_output_clean_scan_resolution_receipt_v1.restart_same_head_receipt",
                    "head-advancing publication cannot borrow restart same-head authority",
                ));
            }
        }
        self.detector_policy.validate()?;
        self.clean_runner.validate()?;
        let artifacts = self.resolution.artifact_reference.as_ref().ok_or_else(|| {
            ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.resolution",
                "must resolve Published with an exact immutable artifact reference",
            )
        })?;
        if self.contract_version != self.intent.contract_version
            || self.layout_version != self.intent.layout_version
            || self.clean_scan_resolution_receipt_id
                != clean_scan_resolution_receipt_id(&self.resolution.resolution_anchor_digest)
            || self.unknown_terminal.observation_class
                != CommandOutputCaptureObservationClassV1::Unknown
            || self.unknown_terminal.disposition
                != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
            || self.unknown_terminal.artifact_reference.is_some()
            || self.unknown_terminal.capture_id != self.intent.capture_id
            || self.unknown_terminal.effect_id != self.intent.source.effect_id
            || self.unknown_terminal.dispatch_claim_id.as_deref()
                != Some(self.acquired.dispatch_claim_id.as_str())
            || self.unknown_terminal.acquired_anchor_digest.as_ref()
                != Some(&self.acquired.acquired_anchor_digest)
            || self.reconciliation_claim.capture_id != self.intent.capture_id
            || self.resolution.disposition != CommandOutputCaptureTerminalDispositionV1::Published
            || artifacts.source != self.intent.source
            || self.clean_runner.capture_id != self.intent.capture_id
            || self.clean_runner.effect_id != self.intent.source.effect_id
            || self.clean_runner.runner_session_id != self.intent.source.runner_session_id
            || self.clean_runner.request_digest != self.intent.source.request_digest
            || self.clean_runner.intent_digest != self.intent.intent_digest
            || self.clean_runner.acquired != self.acquired
            || self.clean_runner.detector_policy != self.detector_policy
            || self.clean_runner.terminal_prepared_store_head != self.resolution.store_head
            || (!same_head
                && self.clean_runner.terminal_prepared_store_head.record_digest
                    != self.resolution.resolution_record_digest)
            || self.clean_runner.terminal_prepared_at_unix_ms > self.resolution.resolved_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1",
                "must bind one exact current-policy clean runner branch to its immutable Unknown terminal and fenced Published resolution",
            ));
        }
        let expected = compute_digest(
            CLEAN_SCAN_RESOLUTION_DIGEST_DOMAIN,
            &CanonicalCleanScanResolutionReceipt {
                contract_version: self.contract_version,
                layout_version: self.layout_version,
                clean_scan_resolution_receipt_id: &self.clean_scan_resolution_receipt_id,
                intent: &self.intent,
                acquired: &self.acquired,
                unknown_terminal: &self.unknown_terminal,
                reconciliation_claim: &self.reconciliation_claim,
                resolution: &self.resolution,
                restart_same_head_receipt: self.restart_same_head_receipt.as_ref(),
                detector_policy: &self.detector_policy,
                clean_runner: &self.clean_runner,
            },
        )?;
        if self.clean_scan_resolution_receipt_digest != expected {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.clean_scan_resolution_receipt_digest",
                "does not match the canonical clean-resolution authority",
            ));
        }
        Ok(())
    }

    /// Revalidates this receipt against exact durable authorities.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any stale or crossed authority.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        unknown_terminal: &CommandOutputCaptureTerminalAnchorV1,
        reconciliation_claim: &CommandOutputCaptureReconciliationClaimV1,
        resolution: &CommandOutputCaptureReconciliationResolutionV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if self.intent != *intent
            || self.acquired != *acquired
            || self.unknown_terminal != *unknown_terminal
            || self.reconciliation_claim != *reconciliation_claim
            || self.resolution != *resolution
            || self.detector_policy != *detector_policy
        {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1",
                "embedded authority differs from the exact durable intent, acquisition, terminal, claim, resolution, or policy",
            ));
        }
        Ok(())
    }
}

fn validate_clean_resolution_physical_join(
    receipt: &CommandOutputCleanScanResolutionReceiptV1,
    advancing_physical: Option<&CommandOutputCapturePhysicalReconciliationV1>,
) -> Result<(), ContractError> {
    let same_head = receipt.resolution.store_head == receipt.unknown_terminal.store_head;
    let physical = match (
        same_head,
        receipt.restart_same_head_receipt.as_ref(),
        advancing_physical,
    ) {
        (true, Some(restart_receipt), None) => {
            receipt.resolution.validate_against_restart_same_head(
                &receipt.intent,
                &receipt.acquired,
                &receipt.unknown_terminal,
                &receipt.reconciliation_claim,
                restart_receipt,
            )?;
            restart_receipt
        }
        (false, None, Some(physical)) => {
            physical.validate_for_unknown_resolution(
                &receipt.intent,
                &receipt.acquired,
                &receipt.unknown_terminal,
                &receipt.reconciliation_claim,
                &receipt.resolution,
            )?;
            physical
        }
        (true, _, Some(_)) => {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.physical_join",
                "same-head publication must use only its embedded immutable restart receipt",
            ));
        }
        (false, Some(_), _) => {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.physical_join",
                "head-advancing publication cannot borrow restart same-head authority",
            ));
        }
        (true, None, None) => {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.physical_join",
                "same-head publication lacks its embedded immutable restart receipt",
            ));
        }
        (false, None, None) => {
            return Err(ContractError::new(
                "command_output_clean_scan_resolution_receipt_v1.physical_join",
                "head-advancing publication lacks its new fenced physical receipt",
            ));
        }
    };
    let state_head = |state| {
        physical
            .lifecycle_history
            .iter()
            .find(|entry| entry.state == state)
            .map(|entry| &entry.store_head)
    };
    if physical.final_state != CommandOutputCaptureRestartStateV1::TerminalPrepared
        || state_head(CommandOutputCaptureRestartStateV1::Acquired)
            != Some(&receipt.clean_runner.acquired_store_head)
        || state_head(CommandOutputCaptureRestartStateV1::WriterAttached)
            != Some(&receipt.clean_runner.writer_attached_store_head)
        || state_head(CommandOutputCaptureRestartStateV1::LaunchIntended)
            != Some(&receipt.clean_runner.launch_intended_store_head)
        || state_head(CommandOutputCaptureRestartStateV1::Finished)
            != Some(&receipt.clean_runner.finished_store_head)
        || state_head(CommandOutputCaptureRestartStateV1::Published)
            != Some(&receipt.clean_runner.published_store_head)
        || state_head(CommandOutputCaptureRestartStateV1::TerminalPrepared)
            != Some(&receipt.clean_runner.terminal_prepared_store_head)
        || (!same_head && physical.reconciled_at_unix_ms != receipt.resolution.resolved_at_unix_ms)
        || (same_head
            && physical.reconciled_at_unix_ms != receipt.unknown_terminal.anchored_at_unix_ms)
    {
        return Err(ContractError::new(
            "command_output_clean_scan_resolution_receipt_v1.physical_join",
            "runner-v2 clean store heads must equal the complete fenced v1 TerminalPrepared history",
        ));
    }
    Ok(())
}

fn clean_scan_resolution_receipt_id(resolution_anchor_digest: &Digest) -> String {
    format!(
        "{CLEAN_SCAN_RESOLUTION_RECEIPT_ID_PREFIX}{}",
        resolution_anchor_digest.as_str()
    )
}

fn all_digests_distinct(digests: &[&Digest]) -> bool {
    digests
        .iter()
        .enumerate()
        .all(|(index, digest)| digests[(index + 1)..].iter().all(|other| *other != *digest))
}

/// Immutable, length-free final anchor that output was rejected under the
/// exact pre-effect detector policy after cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputSensitiveRejectionAnchorV1 {
    /// Shared repository contract version.
    pub contract_version: u32,
    /// Private command-output capture layout version.
    pub layout_version: u32,
    /// Caller-preallocated private capture identity.
    pub capture_id: String,
    /// Exact admitted `RunCommand` effect identity.
    pub effect_id: String,
    /// Exact failed-after-known-effect observation identity.
    pub observation_id: String,
    /// Exact one-use runner dispatch claim identity.
    pub dispatch_claim_id: String,
    /// Digest of the canonical pre-effect capture intent.
    pub intent_digest: Digest,
    /// Digest of the exact physical capture acquisition.
    pub acquired_anchor_digest: Digest,
    /// Typed reason publication was forbidden.
    pub reason: CommandOutputAbandonmentReasonV2,
    /// Exact detector policy admitted before dispatch.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact pre-launch zero-dump profile bound into runner-v2 generation four.
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    /// Exact zero-only staging receipt bound into runner-v2 generation six.
    pub staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    /// Complete runner-v2 rejection receipt whose eight records core recomputes.
    pub runner_cleanup: SensitiveOutputRejectionRunnerReferenceV1,
    /// Exact typed command termination observed before domain cleanup.
    pub termination: CommandTerminationV1,
    /// Exact runner-v12 journal identity.
    pub runner_journal_id: String,
    /// Generation-four `LaunchIntended` head binding the zero-dump profile.
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    /// Final post-cleanup `SensitiveOutputRejected` head.
    pub rejected_terminal_journal_head: SensitiveOutputJournalHeadV1,
    /// Digest of the canonical rejection anchor.
    pub rejection_anchor_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalRejectionAnchor<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    dispatch_claim_id: &'a str,
    intent_digest: &'a Digest,
    acquired_anchor_digest: &'a Digest,
    reason: CommandOutputAbandonmentReasonV2,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    core_dump_suppression: &'a SensitiveOutputCoreDumpSuppressionV1,
    staging_neutralization: &'a SensitiveOutputStagingNeutralizationReceiptV1,
    runner_cleanup: &'a SensitiveOutputRejectionRunnerReferenceV1,
    termination: CommandTerminationV1,
    runner_journal_id: &'a str,
    launch_intended_journal_head: &'a SensitiveOutputJournalHeadV1,
    rejected_terminal_journal_head: &'a SensitiveOutputJournalHeadV1,
}

impl CommandOutputSensitiveRejectionAnchorV1 {
    /// Constructs a rejection anchor without accepting output-derived data.
    ///
    /// # Errors
    ///
    /// Returns a contract error for crossed capture, acquisition, observation,
    /// policy, or timestamp identity.
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        observation_id: impl Into<String>,
        runner_cleanup: SensitiveOutputRejectionRunnerReferenceV1,
    ) -> Result<Self, ContractError> {
        intent.validate()?;
        acquired.validate_against(intent)?;
        runner_cleanup.validate()?;
        if runner_cleanup.acquired != *acquired
            || runner_cleanup.capture_id != intent.capture_id
            || runner_cleanup.runner_session_id != intent.source.runner_session_id
            || runner_cleanup.effect_id != intent.source.effect_id
            || runner_cleanup.request_digest != intent.source.request_digest
            || runner_cleanup.intent_digest != intent.intent_digest
        {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1.runner_cleanup",
                "must be the exact full runner-v2 rejection readback for this admitted request",
            ));
        }
        let observation_id = observation_id.into();
        require_id(
            "command_output_sensitive_rejection_anchor_v1.observation_id",
            &observation_id,
        )?;
        let detector_policy = runner_cleanup.detector_policy.clone();
        let core_dump_suppression = runner_cleanup.core_dump_suppression.clone();
        let staging_neutralization = runner_cleanup.staging_neutralization.clone();
        let termination = runner_cleanup.termination;
        let runner_journal_id = runner_cleanup.journal_id.clone();
        let launch_intended_journal_head = runner_cleanup.launch_intended_journal_head.clone();
        let rejected_terminal_journal_head = runner_cleanup.rejected_terminal_journal_head.clone();
        let reason = CommandOutputAbandonmentReasonV2::SensitiveOutputRejected;
        let rejection_anchor_digest = compute_rejection_digest(&CanonicalRejectionAnchor {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: &intent.capture_id,
            effect_id: &intent.source.effect_id,
            observation_id: &observation_id,
            dispatch_claim_id: &acquired.dispatch_claim_id,
            intent_digest: &intent.intent_digest,
            acquired_anchor_digest: &acquired.acquired_anchor_digest,
            reason,
            detector_policy: &detector_policy,
            core_dump_suppression: &core_dump_suppression,
            staging_neutralization: &staging_neutralization,
            runner_cleanup: &runner_cleanup,
            termination,
            runner_journal_id: &runner_journal_id,
            launch_intended_journal_head: &launch_intended_journal_head,
            rejected_terminal_journal_head: &rejected_terminal_journal_head,
        })?;
        let anchor = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            observation_id,
            dispatch_claim_id: acquired.dispatch_claim_id.clone(),
            intent_digest: intent.intent_digest.clone(),
            acquired_anchor_digest: acquired.acquired_anchor_digest.clone(),
            reason,
            detector_policy,
            core_dump_suppression,
            staging_neutralization,
            runner_cleanup,
            termination,
            runner_journal_id,
            launch_intended_journal_head,
            rejected_terminal_journal_head,
            rejection_anchor_digest,
        };
        anchor.validate()?;
        Ok(anchor)
    }

    /// Returns the sole safe effect-evidence bytes for this rejection.
    ///
    /// These canonical bytes contain policy and lifecycle identity only.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the anchor is invalid or serialization
    /// fails.
    pub fn canonical_evidence_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| {
            ContractError::new(
                "command_output_sensitive_rejection_anchor_v1",
                format!("cannot encode canonical evidence: {error}"),
            )
        })
    }

    /// Validates the self-contained anchor.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any invalid or substituted field.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_versions(self.contract_version, self.layout_version)?;
        require_capture_id(&self.capture_id)?;
        require_id(
            "command_output_sensitive_rejection_anchor_v1.effect_id",
            &self.effect_id,
        )?;
        require_id(
            "command_output_sensitive_rejection_anchor_v1.observation_id",
            &self.observation_id,
        )?;
        require_id(
            "command_output_sensitive_rejection_anchor_v1.dispatch_claim_id",
            &self.dispatch_claim_id,
        )?;
        if self.reason != CommandOutputAbandonmentReasonV2::SensitiveOutputRejected {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1.reason",
                "schema v29 admits only SensitiveOutputRejected",
            ));
        }
        self.detector_policy.validate()?;
        self.core_dump_suppression.validate()?;
        self.staging_neutralization.validate()?;
        self.runner_cleanup.validate()?;
        self.termination.validate()?;
        self.launch_intended_journal_head.validate()?;
        self.rejected_terminal_journal_head.validate()?;
        if self.launch_intended_journal_head.generation != 4
            || self.rejected_terminal_journal_head.generation != 8
            || self.launch_intended_journal_head.record_digest
                == self.rejected_terminal_journal_head.record_digest
        {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1.rejected_terminal_journal_head",
                "must be the eighth and final reject-chain record",
            ));
        }
        require_id(
            "command_output_sensitive_rejection_anchor_v1.runner_journal_id",
            &self.runner_journal_id,
        )?;
        if self.capture_id != self.runner_cleanup.capture_id
            || self.effect_id != self.runner_cleanup.effect_id
            || self.intent_digest != self.runner_cleanup.intent_digest
            || self.acquired_anchor_digest != self.runner_cleanup.acquired_anchor_digest
            || self.dispatch_claim_id != self.runner_cleanup.acquired.dispatch_claim_id
            || self.detector_policy != self.runner_cleanup.detector_policy
            || self.core_dump_suppression != self.runner_cleanup.core_dump_suppression
            || self.staging_neutralization != self.runner_cleanup.staging_neutralization
            || self.termination != self.runner_cleanup.termination
            || self.runner_journal_id != self.runner_cleanup.journal_id
            || self.launch_intended_journal_head != self.runner_cleanup.launch_intended_journal_head
            || self.rejected_terminal_journal_head
                != self.runner_cleanup.rejected_terminal_journal_head
        {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1.runner_cleanup",
                "all projected fields must equal the exact independently revalidated runner-v2 receipt",
            ));
        }
        let expected = compute_rejection_digest(&CanonicalRejectionAnchor {
            contract_version: self.contract_version,
            layout_version: self.layout_version,
            capture_id: &self.capture_id,
            effect_id: &self.effect_id,
            observation_id: &self.observation_id,
            dispatch_claim_id: &self.dispatch_claim_id,
            intent_digest: &self.intent_digest,
            acquired_anchor_digest: &self.acquired_anchor_digest,
            reason: self.reason,
            detector_policy: &self.detector_policy,
            core_dump_suppression: &self.core_dump_suppression,
            staging_neutralization: &self.staging_neutralization,
            runner_cleanup: &self.runner_cleanup,
            termination: self.termination,
            runner_journal_id: &self.runner_journal_id,
            launch_intended_journal_head: &self.launch_intended_journal_head,
            rejected_terminal_journal_head: &self.rejected_terminal_journal_head,
        })?;
        if self.rejection_anchor_digest != expected {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1.rejection_anchor_digest",
                "does not match the canonical length-free rejection anchor",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        observation: &EffectObservation,
    ) -> Result<(), ContractError> {
        self.validate()?;
        acquired.validate_against(intent)?;
        self.staging_neutralization.validate_against(acquired)?;
        if self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.observation_id != observation.observation_id
            || self.dispatch_claim_id != acquired.dispatch_claim_id
            || self.intent_digest != intent.intent_digest
            || self.acquired_anchor_digest != acquired.acquired_anchor_digest
            || observation.effect_id != intent.source.effect_id
            || !matches!(
                observation.outcome,
                EffectOutcome::FailedAfterKnownEffect { .. }
            )
            || Digest::sha256(&self.canonical_evidence_bytes()?)
                != *observation.outcome.evidence_digest()
        {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_anchor_v1",
                "must match the exact FailedAfterKnownEffect observation and capture authority",
            ));
        }
        Ok(())
    }
}

/// Exact secret-free runner-v2 rejection readback translated into core types.
///
/// This is intentionally field-for-field with the runner's final rejection
/// receipt. Core independently recomputes all eight records and every
/// predecessor link before the reference can authorize a rejection.
#[allow(
    missing_docs,
    reason = "public fields mirror the closed runner-v2 rejection receipt"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputRejectionRunnerReferenceV1 {
    pub journal_id: String,
    pub capture_id: String,
    pub runner_session_id: String,
    pub effect_id: String,
    pub request_digest: Digest,
    pub intent_digest: Digest,
    pub acquired: CommandOutputCaptureAcquiredV1,
    pub acquired_anchor_digest: Digest,
    pub acquired_store_head: CommandOutputCaptureStoreHeadV1,
    pub writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub writer_attached_journal_head: SensitiveOutputJournalHeadV1,
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    pub detected_journal_head: SensitiveOutputJournalHeadV1,
    pub cleanup_intended_journal_head: SensitiveOutputJournalHeadV1,
    pub cleaned_journal_head: SensitiveOutputJournalHeadV1,
    pub rejected_terminal_journal_head: SensitiveOutputJournalHeadV1,
    pub v1_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    pub command_domain_cleanup_proof_id: String,
    pub staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    pub termination: CommandTerminationV1,
    pub cleanup_receipt_id: String,
    pub cleanup_receipt_digest: Digest,
}

#[derive(Serialize)]
struct SensitiveOutputRunnerCleanupReceiptDigestPreimage<'a> {
    journal_id: &'a str,
    capture_id: &'a str,
    runner_session_id: &'a str,
    effect_id: &'a str,
    request_digest: &'a Digest,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    detected_journal_head: &'a SensitiveOutputJournalHeadV1,
    v1_cleaned_store_head: &'a CommandOutputCaptureStoreHeadV1,
    command_domain_cleanup_proof_id: &'a str,
    staging_neutralization: &'a SensitiveOutputStagingNeutralizationReceiptV1,
    cleanup_receipt_id: &'a str,
}

impl SensitiveOutputRejectionRunnerReferenceV1 {
    /// Validates every bound input and independently recomputes generations
    /// one through eight, including every predecessor digest.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed input, noncanonical receipt,
    /// store-head inversion, boundary inversion, or journal substitution.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear validator independently recomputes the complete rejection chain and cleanup receipt without hiding predecessor checks behind partial helpers"
    )]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_id(&self.capture_id)?;
        for (field, value) in [
            ("journal_id", self.journal_id.as_str()),
            ("runner_session_id", self.runner_session_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
            (
                "command_domain_cleanup_proof_id",
                self.command_domain_cleanup_proof_id.as_str(),
            ),
            ("cleanup_receipt_id", self.cleanup_receipt_id.as_str()),
        ] {
            require_id(field, value)?;
        }
        self.acquired.validate()?;
        self.core_dump_suppression.validate()?;
        self.detector_policy.validate()?;
        self.staging_neutralization
            .validate_against(&self.acquired)?;
        self.termination.validate()?;
        for head in [
            &self.intent_bound_journal_head,
            &self.acquired_bound_journal_head,
            &self.writer_attached_journal_head,
            &self.launch_intended_journal_head,
            &self.detected_journal_head,
            &self.cleanup_intended_journal_head,
            &self.cleaned_journal_head,
            &self.rejected_terminal_journal_head,
        ] {
            head.validate()?;
        }
        for head in [
            &self.acquired_store_head,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.v1_cleaned_store_head,
        ] {
            head.validate()?;
        }
        if self.capture_id != self.acquired.capture_id
            || self.runner_session_id != self.acquired.source.runner_session_id
            || self.effect_id != self.acquired.source.effect_id
            || self.request_digest != self.acquired.source.request_digest
            || self.intent_digest != self.acquired.intent_digest
            || self.acquired_anchor_digest != self.acquired.acquired_anchor_digest
            || self.acquired_store_head != self.acquired.store_head
            || self.acquired_store_head.generation >= self.writer_attached_store_head.generation
            || self.writer_attached_store_head.generation
                >= self.launch_intended_store_head.generation
            || !all_digests_distinct(&[
                &self.acquired_store_head.record_digest,
                &self.writer_attached_store_head.record_digest,
                &self.launch_intended_store_head.record_digest,
                &self.v1_cleaned_store_head.record_digest,
            ])
            || !all_digests_distinct(&[
                &self.intent_bound_journal_head.record_digest,
                &self.acquired_bound_journal_head.record_digest,
                &self.writer_attached_journal_head.record_digest,
                &self.launch_intended_journal_head.record_digest,
                &self.detected_journal_head.record_digest,
                &self.cleanup_intended_journal_head.record_digest,
                &self.cleaned_journal_head.record_digest,
                &self.rejected_terminal_journal_head.record_digest,
            ])
        {
            return Err(ContractError::new(
                "sensitive_output_runner_cleanup_reference_v1.identity",
                "must bind the exact request, acquisition, and ordered distinct store/journal heads",
            ));
        }
        let expected_cleanup_receipt_digest = compute_digest(
            SENSITIVE_OUTPUT_RUNNER_CLEANUP_RECEIPT_DIGEST_DOMAIN,
            &SensitiveOutputRunnerCleanupReceiptDigestPreimage {
                journal_id: &self.journal_id,
                capture_id: &self.capture_id,
                runner_session_id: &self.runner_session_id,
                effect_id: &self.effect_id,
                request_digest: &self.request_digest,
                detector_policy: &self.detector_policy,
                detected_journal_head: &self.detected_journal_head,
                v1_cleaned_store_head: &self.v1_cleaned_store_head,
                command_domain_cleanup_proof_id: &self.command_domain_cleanup_proof_id,
                staging_neutralization: &self.staging_neutralization,
                cleanup_receipt_id: &self.cleanup_receipt_id,
            },
        )?;
        if self.cleanup_receipt_digest != expected_cleanup_receipt_digest {
            return Err(ContractError::new(
                "sensitive_output_rejection_runner_reference_v1.cleanup_receipt_digest",
                "does not match the exact runner-v2 cleanup receipt preimage",
            ));
        }
        let launch_digest = validate_sensitive_output_common_journal_chain(
            &self.journal_id,
            &self.capture_id,
            &self.runner_session_id,
            &self.effect_id,
            &self.request_digest,
            &self.intent_digest,
            &self.detector_policy,
            &self.acquired,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.core_dump_suppression,
            [
                &self.intent_bound_journal_head,
                &self.acquired_bound_journal_head,
                &self.writer_attached_journal_head,
                &self.launch_intended_journal_head,
            ],
        )?;
        let detected = expected_sensitive_output_journal_head(
            5,
            &self.journal_id,
            &self.capture_id,
            Some(&launch_digest),
            &SensitiveOutputJournalRecordDataV2::SensitiveOutputDetected,
        )?;
        let cleanup_intended = expected_sensitive_output_journal_head(
            6,
            &self.journal_id,
            &self.capture_id,
            Some(&detected.record_digest),
            &SensitiveOutputJournalRecordDataV2::CleanupIntended {
                command_domain_cleanup_proof_id: self.command_domain_cleanup_proof_id.clone(),
                staging_neutralization: self.staging_neutralization.clone(),
            },
        )?;
        let cleaned = expected_sensitive_output_journal_head(
            7,
            &self.journal_id,
            &self.capture_id,
            Some(&cleanup_intended.record_digest),
            &SensitiveOutputJournalRecordDataV2::Cleaned {
                v1_cleaned_store_head: self.v1_cleaned_store_head.clone(),
                cleanup_receipt_id: self.cleanup_receipt_id.clone(),
                cleanup_receipt_digest: self.cleanup_receipt_digest.clone(),
            },
        )?;
        let rejected = expected_sensitive_output_journal_head(
            8,
            &self.journal_id,
            &self.capture_id,
            Some(&cleaned.record_digest),
            &SensitiveOutputJournalRecordDataV2::SensitiveOutputRejected {
                termination: self.termination,
                cleanup_receipt_id: self.cleanup_receipt_id.clone(),
                cleanup_receipt_digest: self.cleanup_receipt_digest.clone(),
            },
        )?;
        if detected != self.detected_journal_head
            || cleanup_intended != self.cleanup_intended_journal_head
            || cleaned != self.cleaned_journal_head
            || rejected != self.rejected_terminal_journal_head
        {
            return Err(ContractError::new(
                "sensitive_output_runner_cleanup_reference_v1.journal_chain",
                "generations five through eight do not recompute from exact rejection fields",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn canonicalize_journal_heads_for_test(&mut self) -> Result<(), ContractError> {
        let common = compute_sensitive_output_common_journal_chain(
            &self.journal_id,
            &self.capture_id,
            &self.runner_session_id,
            &self.effect_id,
            &self.request_digest,
            &self.intent_digest,
            &self.detector_policy,
            &self.acquired,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.core_dump_suppression,
        )?;
        let detected = expected_sensitive_output_journal_head(
            5,
            &self.journal_id,
            &self.capture_id,
            Some(&common[3].record_digest),
            &SensitiveOutputJournalRecordDataV2::SensitiveOutputDetected,
        )?;
        self.cleanup_receipt_digest = compute_digest(
            SENSITIVE_OUTPUT_RUNNER_CLEANUP_RECEIPT_DIGEST_DOMAIN,
            &SensitiveOutputRunnerCleanupReceiptDigestPreimage {
                journal_id: &self.journal_id,
                capture_id: &self.capture_id,
                runner_session_id: &self.runner_session_id,
                effect_id: &self.effect_id,
                request_digest: &self.request_digest,
                detector_policy: &self.detector_policy,
                detected_journal_head: &detected,
                v1_cleaned_store_head: &self.v1_cleaned_store_head,
                command_domain_cleanup_proof_id: &self.command_domain_cleanup_proof_id,
                staging_neutralization: &self.staging_neutralization,
                cleanup_receipt_id: &self.cleanup_receipt_id,
            },
        )?;
        let cleanup_intended = expected_sensitive_output_journal_head(
            6,
            &self.journal_id,
            &self.capture_id,
            Some(&detected.record_digest),
            &SensitiveOutputJournalRecordDataV2::CleanupIntended {
                command_domain_cleanup_proof_id: self.command_domain_cleanup_proof_id.clone(),
                staging_neutralization: self.staging_neutralization.clone(),
            },
        )?;
        let cleaned = expected_sensitive_output_journal_head(
            7,
            &self.journal_id,
            &self.capture_id,
            Some(&cleanup_intended.record_digest),
            &SensitiveOutputJournalRecordDataV2::Cleaned {
                v1_cleaned_store_head: self.v1_cleaned_store_head.clone(),
                cleanup_receipt_id: self.cleanup_receipt_id.clone(),
                cleanup_receipt_digest: self.cleanup_receipt_digest.clone(),
            },
        )?;
        let rejected = expected_sensitive_output_journal_head(
            8,
            &self.journal_id,
            &self.capture_id,
            Some(&cleaned.record_digest),
            &SensitiveOutputJournalRecordDataV2::SensitiveOutputRejected {
                termination: self.termination,
                cleanup_receipt_id: self.cleanup_receipt_id.clone(),
                cleanup_receipt_digest: self.cleanup_receipt_digest.clone(),
            },
        )?;
        self.intent_bound_journal_head = common[0].clone();
        self.acquired_bound_journal_head = common[1].clone();
        self.writer_attached_journal_head = common[2].clone();
        self.launch_intended_journal_head = common[3].clone();
        self.detected_journal_head = detected;
        self.cleanup_intended_journal_head = cleanup_intended;
        self.cleaned_journal_head = cleaned;
        self.rejected_terminal_journal_head = rejected;
        Ok(())
    }
}

/// Exact public cleanup receipt for a rejected private capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputSensitiveRejectionCleanupReceiptV1 {
    /// Shared repository contract version.
    pub contract_version: u32,
    /// Private command-output capture layout version.
    pub layout_version: u32,
    /// Stable caller-supplied cleanup receipt identity.
    pub cleanup_receipt_id: String,
    /// Exact private capture identity.
    pub capture_id: String,
    /// Exact admitted `RunCommand` effect identity.
    pub effect_id: String,
    /// Exact failed-after-known-effect observation identity.
    pub observation_id: String,
    /// Digest of the rejection anchor this cleanup closes.
    pub rejection_anchor_digest: Digest,
    /// Exact pre-effect detector policy identity.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Secret-free runner-v12 cleanup and journal proof.
    pub runner_cleanup: SensitiveOutputRejectionRunnerReferenceV1,
    /// Exact core command-domain emptiness proof identity.
    pub command_domain_cleanup_proof_id: String,
    /// Digest of the canonical cleanup receipt.
    pub cleanup_receipt_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCleanup<'a> {
    contract_version: u32,
    layout_version: u32,
    cleanup_receipt_id: &'a str,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    rejection_anchor_digest: &'a Digest,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    runner_cleanup: &'a SensitiveOutputRejectionRunnerReferenceV1,
    command_domain_cleanup_proof_id: &'a str,
}

impl CommandOutputSensitiveRejectionCleanupReceiptV1 {
    /// Constructs a length-free cleanup receipt with exact runner and
    /// command-domain identities.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid or crossed identity.
    pub fn try_new(
        anchor: &CommandOutputSensitiveRejectionAnchorV1,
        cleanup_receipt_id: impl Into<String>,
        runner_cleanup: SensitiveOutputRejectionRunnerReferenceV1,
        command_domain_cleanup_proof_id: impl Into<String>,
    ) -> Result<Self, ContractError> {
        anchor.validate()?;
        runner_cleanup.validate()?;
        let cleanup_receipt_id = cleanup_receipt_id.into();
        let command_domain_cleanup_proof_id = command_domain_cleanup_proof_id.into();
        require_id(
            "command_output_sensitive_rejection_cleanup_receipt_v1.cleanup_receipt_id",
            &cleanup_receipt_id,
        )?;
        require_id(
            "command_output_sensitive_rejection_cleanup_receipt_v1.command_domain_cleanup_proof_id",
            &command_domain_cleanup_proof_id,
        )?;
        if runner_cleanup != anchor.runner_cleanup
            || runner_cleanup.command_domain_cleanup_proof_id != command_domain_cleanup_proof_id
            || runner_cleanup.journal_id != anchor.runner_journal_id
            || runner_cleanup.rejected_terminal_journal_head
                != anchor.rejected_terminal_journal_head
        {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_cleanup_receipt_v1.runner_cleanup",
                "must bind the exact runner receipt, command cleanup identity, and final head",
            ));
        }
        let canonical = CanonicalCleanup {
            contract_version: anchor.contract_version,
            layout_version: anchor.layout_version,
            cleanup_receipt_id: &cleanup_receipt_id,
            capture_id: &anchor.capture_id,
            effect_id: &anchor.effect_id,
            observation_id: &anchor.observation_id,
            rejection_anchor_digest: &anchor.rejection_anchor_digest,
            detector_policy: &anchor.detector_policy,
            runner_cleanup: &runner_cleanup,
            command_domain_cleanup_proof_id: &command_domain_cleanup_proof_id,
        };
        let cleanup_receipt_digest = compute_digest(CLEANUP_RECEIPT_DIGEST_DOMAIN, &canonical)?;
        let receipt = Self {
            contract_version: anchor.contract_version,
            layout_version: anchor.layout_version,
            cleanup_receipt_id,
            capture_id: anchor.capture_id.clone(),
            effect_id: anchor.effect_id.clone(),
            observation_id: anchor.observation_id.clone(),
            rejection_anchor_digest: anchor.rejection_anchor_digest.clone(),
            detector_policy: anchor.detector_policy.clone(),
            runner_cleanup,
            command_domain_cleanup_proof_id,
            cleanup_receipt_digest,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates exact runner cleanup identity and canonical receipt identity.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid runner or command cleanup identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_versions(self.contract_version, self.layout_version)?;
        require_capture_id(&self.capture_id)?;
        for (field, value) in [
            ("cleanup_receipt_id", self.cleanup_receipt_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
            ("observation_id", self.observation_id.as_str()),
            (
                "command_domain_cleanup_proof_id",
                self.command_domain_cleanup_proof_id.as_str(),
            ),
        ] {
            require_id(field, value)?;
        }
        self.detector_policy.validate()?;
        self.runner_cleanup.validate()?;
        let expected = compute_digest(
            CLEANUP_RECEIPT_DIGEST_DOMAIN,
            &CanonicalCleanup {
                contract_version: self.contract_version,
                layout_version: self.layout_version,
                cleanup_receipt_id: &self.cleanup_receipt_id,
                capture_id: &self.capture_id,
                effect_id: &self.effect_id,
                observation_id: &self.observation_id,
                rejection_anchor_digest: &self.rejection_anchor_digest,
                detector_policy: &self.detector_policy,
                runner_cleanup: &self.runner_cleanup,
                command_domain_cleanup_proof_id: &self.command_domain_cleanup_proof_id,
            },
        )?;
        if self.cleanup_receipt_digest != expected {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_cleanup_receipt_v1.cleanup_receipt_digest",
                "does not match the canonical cleanup receipt",
            ));
        }
        Ok(())
    }
}

/// Exact closure of the original v27 capture obligation through v29 rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputSensitiveRejectionClosureV1 {
    /// Shared repository contract version.
    pub contract_version: u32,
    /// Original schema-v27 capture reconciliation obligation identity.
    pub obligation_id: String,
    /// Exact private capture identity.
    pub capture_id: String,
    /// Exact admitted `RunCommand` effect identity.
    pub effect_id: String,
    /// Exact failed-after-known-effect observation identity.
    pub observation_id: String,
    /// Digest of the immutable rejection anchor.
    pub rejection_anchor_digest: Digest,
    /// Digest of the exact cleanup receipt.
    pub cleanup_receipt_digest: Digest,
    /// Exact core command-domain emptiness proof identity.
    pub command_domain_cleanup_proof_id: String,
    /// Time the original capture obligation became closed.
    pub closed_at_unix_ms: u64,
    /// Digest of the canonical obligation closure.
    pub closure_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalClosure<'a> {
    contract_version: u32,
    obligation_id: &'a str,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    rejection_anchor_digest: &'a Digest,
    cleanup_receipt_digest: &'a Digest,
    command_domain_cleanup_proof_id: &'a str,
    closed_at_unix_ms: u64,
}

impl CommandOutputSensitiveRejectionClosureV1 {
    pub(super) fn derive(
        obligation_id: String,
        anchor: &CommandOutputSensitiveRejectionAnchorV1,
        cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
        closed_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        require_id(
            "command_output_sensitive_rejection_closure_v1.obligation_id",
            &obligation_id,
        )?;
        let canonical = CanonicalClosure {
            contract_version: anchor.contract_version,
            obligation_id: &obligation_id,
            capture_id: &anchor.capture_id,
            effect_id: &anchor.effect_id,
            observation_id: &anchor.observation_id,
            rejection_anchor_digest: &anchor.rejection_anchor_digest,
            cleanup_receipt_digest: &cleanup.cleanup_receipt_digest,
            command_domain_cleanup_proof_id: &cleanup.command_domain_cleanup_proof_id,
            closed_at_unix_ms,
        };
        let closure_digest = compute_digest(CLOSURE_DIGEST_DOMAIN, &canonical)?;
        let closure = Self {
            contract_version: anchor.contract_version,
            obligation_id,
            capture_id: anchor.capture_id.clone(),
            effect_id: anchor.effect_id.clone(),
            observation_id: anchor.observation_id.clone(),
            rejection_anchor_digest: anchor.rejection_anchor_digest.clone(),
            cleanup_receipt_digest: cleanup.cleanup_receipt_digest.clone(),
            command_domain_cleanup_proof_id: cleanup.command_domain_cleanup_proof_id.clone(),
            closed_at_unix_ms,
            closure_digest,
        };
        closure.validate()?;
        Ok(closure)
    }

    /// Validates the canonical closure identity.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid identity, version, time, or digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION || self.closed_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_closure_v1",
                "contract version and closure time must be current and nonzero",
            ));
        }
        require_capture_id(&self.capture_id)?;
        for value in [
            self.obligation_id.as_str(),
            self.effect_id.as_str(),
            self.observation_id.as_str(),
            self.command_domain_cleanup_proof_id.as_str(),
        ] {
            require_id(
                "command_output_sensitive_rejection_closure_v1.identity",
                value,
            )?;
        }
        let expected = compute_digest(
            CLOSURE_DIGEST_DOMAIN,
            &CanonicalClosure {
                contract_version: self.contract_version,
                obligation_id: &self.obligation_id,
                capture_id: &self.capture_id,
                effect_id: &self.effect_id,
                observation_id: &self.observation_id,
                rejection_anchor_digest: &self.rejection_anchor_digest,
                cleanup_receipt_digest: &self.cleanup_receipt_digest,
                command_domain_cleanup_proof_id: &self.command_domain_cleanup_proof_id,
                closed_at_unix_ms: self.closed_at_unix_ms,
            },
        )?;
        if self.closure_digest != expected {
            return Err(ContractError::new(
                "command_output_sensitive_rejection_closure_v1.closure_digest",
                "does not match the canonical closure",
            ));
        }
        Ok(())
    }
}

/// Exact durable v29 rejection readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCommandOutputSensitiveRejectionV1 {
    /// Immutable secret-free rejection anchor.
    pub anchor: CommandOutputSensitiveRejectionAnchorV1,
    /// Exact runner and command-domain cleanup receipt.
    pub cleanup: CommandOutputSensitiveRejectionCleanupReceiptV1,
    /// Exact release of the original capture obligation.
    pub closure: CommandOutputSensitiveRejectionClosureV1,
}

/// Exact authority under which one successfully published command output may
/// be consumed after restart.
///
/// The historical variant carries the immutable positive exemption identity;
/// it is never inferred from a missing current-policy row. The current variant
/// carries both the admitted public detector policy and its fully revalidated
/// clean-scan publication receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the unboxed closed authority contract preserves direct canonical serialization and exact typed readback"
)]
pub enum CommandOutputPublicationAuthorityV1 {
    /// The capture predates schema v29 and has an exact migration exemption.
    PreV29Exemption {
        /// Exact private capture identity named by the exemption.
        capture_id: String,
        /// Exact command effect identity named by the exemption.
        effect_id: String,
        /// Exact immutable capture-intent digest named by the exemption.
        intent_digest: Digest,
    },
    /// The current detector policy and exact clean-scan publication receipt.
    CurrentPolicy {
        /// Policy admitted before command dispatch.
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        /// Receipt binding the clean runner branch to the Published terminal.
        clean_scan_receipt: CommandOutputCleanScanPublicationReceiptV1,
    },
    /// Current detector policy and exact clean scan for a fenced later
    /// resolution of an immutable Unknown terminal.
    CurrentPolicyResolution {
        /// Policy admitted before the original command dispatch.
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        /// Receipt binding the full clean runner branch to the exact resolution.
        clean_scan_resolution_receipt: Box<CommandOutputCleanScanResolutionReceiptV1>,
    },
}
impl EventLedger {
    /// Loads the complete effective authority for one successfully Published
    /// command output.
    ///
    /// This is the restart consumption boundary: callers cannot interpret a
    /// missing v29 policy or clean receipt themselves. A historical result is
    /// returned only for the exact positive migration exemption, while a
    /// current result requires the exact clean-scan receipt and all v27 finish
    /// authority to remain valid.
    ///
    /// # Errors
    ///
    /// Returns not-found when no capture exists and corruption when the effect
    /// is not an exact Published finish or any policy/receipt authority is
    /// partial, crossed, stale, or noncanonical.
    pub fn load_command_output_publication_authority_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<CommandOutputPublicationAuthorityV1, LedgerError> {
        let capture =
            super::command_output_capture_authority::load_from_effect(&self.connection, effect_id)?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "command output publication authority",
                    id: effect_id.to_owned(),
                })?;
        require_policy_state_for_capture(&self.connection, &capture.intent)?;
        if load_for_effect(&self.connection, effect_id)?.is_some() {
            return Err(LedgerError::Corrupt {
                entity: "command output publication authority",
                detail: "a sensitive-output rejection cannot authorize publication".into(),
            });
        }
        let terminal = capture
            .terminal
            .as_ref()
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output publication authority",
                detail: "Published authority lacks its terminal anchor".into(),
            })?;
        let effective_disposition = capture
            .reconciliation_resolution
            .as_ref()
            .map_or(terminal.disposition, |resolution| resolution.disposition);
        if effective_disposition != CommandOutputCaptureTerminalDispositionV1::Published
            || !super::command_output_capture_authority::finish_is_proven_for_effect(
                &self.connection,
                effect_id,
            )?
        {
            return Err(LedgerError::Corrupt {
                entity: "command output publication authority",
                detail: "effect lacks an exact effective Published finish".into(),
            });
        }
        let Some(detector_policy) = load_policy_for_effect(&self.connection, effect_id)? else {
            return Ok(CommandOutputPublicationAuthorityV1::PreV29Exemption {
                capture_id: capture.intent.capture_id,
                effect_id: capture.intent.source.effect_id,
                intent_digest: capture.intent.intent_digest,
            });
        };
        if capture.reconciliation_resolution.is_some() {
            let clean_scan_resolution_receipt = load_clean_scan_resolution_for_effect(
                &self.connection,
                effect_id,
            )?
            .ok_or_else(|| LedgerError::Corrupt {
                entity: "command output publication authority",
                detail: "current-policy Published resolution lacks its exact clean-scan resolution receipt".into(),
            })?;
            if clean_scan_resolution_receipt.detector_policy != detector_policy {
                return Err(LedgerError::Corrupt {
                    entity: "command output publication authority",
                    detail: "clean-resolution receipt differs from the admitted detector policy"
                        .into(),
                });
            }
            return Ok(
                CommandOutputPublicationAuthorityV1::CurrentPolicyResolution {
                    detector_policy,
                    clean_scan_resolution_receipt: Box::new(clean_scan_resolution_receipt),
                },
            );
        }
        let clean_scan_receipt = load_clean_scan_publication_for_effect(
            &self.connection,
            effect_id,
        )?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output publication authority",
            detail: "current-policy Published effect lacks its exact clean-scan receipt".into(),
        })?;
        if clean_scan_receipt.detector_policy != detector_policy {
            return Err(LedgerError::Corrupt {
                entity: "command output publication authority",
                detail: "clean-scan receipt differs from the admitted detector policy".into(),
            });
        }
        Ok(CommandOutputPublicationAuthorityV1::CurrentPolicy {
            detector_policy,
            clean_scan_receipt,
        })
    }

    /// Loads and revalidates the exact current-policy clean-scan authority for
    /// one Published command effect.
    ///
    /// # Errors
    ///
    /// Returns not-found when no receipt exists and corruption for any crossed,
    /// partial, stale, or noncanonical input/terminal join.
    pub fn load_command_output_clean_scan_publication_receipt_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<CommandOutputCleanScanPublicationReceiptV1, LedgerError> {
        load_clean_scan_publication_for_effect(&self.connection, effect_id)?.ok_or_else(|| {
            LedgerError::ArtifactNotFound {
                entity: "command output clean-scan publication receipt",
                id: effect_id.to_owned(),
            }
        })
    }

    /// Loads and revalidates the exact current-policy clean-scan authority for
    /// a fenced Published resolution of an immutable Unknown terminal.
    ///
    /// # Errors
    ///
    /// Returns not-found when no resolution receipt exists and corruption for
    /// any missing, crossed, stale, or noncanonical authority.
    pub fn load_command_output_clean_scan_resolution_receipt_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<CommandOutputCleanScanResolutionReceiptV1, LedgerError> {
        load_clean_scan_resolution_for_effect(&self.connection, effect_id)?.ok_or_else(|| {
            LedgerError::ArtifactNotFound {
                entity: "command output clean-scan resolution receipt",
                id: effect_id.to_owned(),
            }
        })
    }

    /// Loads the detector policy admitted before one command's dispatch.
    ///
    /// # Errors
    ///
    /// Returns not-found for a pre-v29 exempt capture and corruption for a
    /// crossed or noncanonical policy companion.
    pub fn load_sensitive_output_detection_policy_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<SensitiveOutputDetectionPolicyReferenceV1, LedgerError> {
        let policy = load_policy_for_effect(&self.connection, effect_id)?;
        let intent =
            super::command_output_capture_authority::load_from_effect(&self.connection, effect_id)?
                .ok_or_else(|| LedgerError::ArtifactNotFound {
                    entity: "command output capture intent",
                    id: effect_id.to_owned(),
                })?;
        require_policy_state_for_capture(&self.connection, &intent.intent)?;
        policy.ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "sensitive output detection policy",
            id: effect_id.to_owned(),
        })
    }

    /// Loads and revalidates one exact v29 rejection by effect identity.
    ///
    /// # Errors
    ///
    /// Returns not-found when no rejection exists and corruption for any
    /// crossed, partial, mutable, or noncanonical authority.
    pub fn load_command_output_sensitive_rejection_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<PersistedCommandOutputSensitiveRejectionV1, LedgerError> {
        load_for_effect(&self.connection, effect_id)?.ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command output sensitive rejection",
            id: effect_id.to_owned(),
        })
    }

    /// Atomically closes one live claimed command whose streaming detector
    /// rejected output before any persistent or wire sink.
    ///
    /// The effect evidence is derived only from the secret-free rejection
    /// anchor. The v29 anchor, runner-v12 cleanup identity, capture closure,
    /// `FailedAfterKnownEffect` observation, event, and exact
    /// `ReapedZeroSurvivors` proof commit together. No verification receipt or
    /// artifact can be created by this boundary.
    ///
    /// # Errors
    ///
    /// Returns retry custody only when commit was definitely not attempted.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn record_claimed_command_sensitive_output_rejection(
        &mut self,
        authority: RunnerEffectObservationAuthority,
        observation: &EffectObservation,
        event: &crate::AgentEvent,
        anchor: &CommandOutputSensitiveRejectionAnchorV1,
        cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
        command_cleanup: &CommandDomainCleanupProof,
    ) -> Result<PersistedEffect, ClaimedObservationWriteFailure> {
        let evidence_bytes =
            match validate_rejection_inputs(observation, event, anchor, cleanup, command_cleanup) {
                Ok(bytes) => bytes,
                Err(error) => {
                    return Err(ClaimedObservationWriteFailure::definitely_precommit(
                        error, authority,
                    ));
                }
            };
        if authority.ledger_instance_id != self.instance_id {
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                reference_mismatch(
                    "sensitive output rejection",
                    "observation authority belongs to another ledger instance",
                ),
                authority,
            ));
        }
        let transaction = match self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
        {
            Ok(transaction) => transaction,
            Err(error) => {
                return Err(ClaimedObservationWriteFailure::definitely_precommit(
                    error.into(),
                    authority,
                ));
            }
        };
        let precommit = (|| -> Result<(), LedgerError> {
            let persisted = validate_new_effect_observation(&transaction, observation, event)?;
            validate_runner_effect_observation_authority(
                &transaction,
                &authority.effect,
                &authority.claim,
                &authority.launch,
                &authority.session,
                authority.running_boundary.as_ref(),
                authority.formal_check_admission.as_ref(),
                authority.integration_admission.as_ref(),
                authority.final_verification_admission.as_ref(),
                authority.application_admission.as_deref(),
                authority.live_state_capture_admission.as_deref(),
                &persisted,
            )?;
            super::command_output_capture_authority::validate_claim_acquisition(
                &transaction,
                &authority.claim,
            )?;
            let capture = super::command_output_capture_authority::load_from_effect(
                &transaction,
                &observation.effect_id,
            )?
            .ok_or_else(|| {
                reference_mismatch(
                    "sensitive output rejection",
                    "claimed command lacks its capture intent",
                )
            })?;
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                reference_mismatch(
                    "sensitive output rejection",
                    "claimed command lacks its exact acquisition",
                )
            })?;
            if capture.terminal.is_some()
                || capture.reconciliation_obligation_closure.is_some()
                || authority.claim.dispatch_claim_id != anchor.dispatch_claim_id
                || authority.claim.launch_id != command_cleanup.launch_id
                || authority.claim.session_id != command_cleanup.session_id
            {
                return Err(reference_mismatch(
                    "sensitive output rejection",
                    "capture, dispatch, or command cleanup authority is crossed or terminal",
                ));
            }
            anchor.validate_against(&capture.intent, acquired, observation)?;
            require_exact_cleanup(anchor, cleanup, command_cleanup)?;
            let policy =
                load_policy_for_effect(&transaction, &observation.effect_id)?.ok_or_else(|| {
                    reference_mismatch(
                        "sensitive output rejection",
                        "capture lacks a pre-effect detector policy",
                    )
                })?;
            if policy != anchor.detector_policy {
                return Err(reference_mismatch(
                    "sensitive output rejection",
                    "terminal detector policy differs from pre-effect admission",
                ));
            }
            let obligation_id =
                super::command_output_capture_authority::reconciliation_obligation_id(
                    &anchor.capture_id,
                );
            insert_rejection(
                &transaction,
                anchor,
                cleanup,
                &obligation_id,
                command_cleanup.cleaned_at_unix_ms,
                None,
            )?;
            insert_agent_event(&transaction, event)?;
            insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
            insert_claimed_effect_observation(
                &transaction,
                observation,
                &event.event_id,
                &authority.claim.dispatch_claim_id,
            )?;
            super::command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
                &transaction,
                command_cleanup,
            )
        })();
        if let Err(error) = precommit {
            drop(transaction);
            return Err(ClaimedObservationWriteFailure::definitely_precommit(
                error, authority,
            ));
        }
        drop(authority);
        if let Err(error) = transaction.commit() {
            return Err(ClaimedObservationWriteFailure::commit_attempted(
                LedgerError::PostCommitStateUncertain {
                    operation: "sensitive output rejection",
                    recovery_id: observation.effect_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }
        secure_database_files(&self.database_path)
            .and_then(|()| {
                let effect = load_effect_from(&self.connection, &observation.effect_id)?;
                let rejection = load_for_effect(&self.connection, &observation.effect_id)?
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "sensitive output rejection",
                        detail: "committed rejection is absent on exact readback".into(),
                    })?;
                let persisted_cleanup =
                    self.load_command_domain_cleanup_proof(&observation.effect_id)?;
                if effect.observation.as_ref() != Some(observation)
                    || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
                    || effect.terminal_event.as_ref() != Some(event)
                    || rejection.anchor != *anchor
                    || rejection.cleanup != *cleanup
                    || persisted_cleanup.proof != *command_cleanup
                {
                    return Err(LedgerError::Corrupt {
                        entity: "sensitive output rejection",
                        detail: "post-commit effect, abandonment, or cleanup differs".into(),
                    });
                }
                Ok(effect)
            })
            .map_err(ClaimedObservationWriteFailure::commit_attempted)
    }

    /// Consumes one exact restart-reconciliation claim to record a durable
    /// runner-v12 rejection without recreating command execution authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for a stale/crossed claim, policy, journal head,
    /// cleanup proof, observation, or uncertain commit/readback.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn record_reconciled_command_sensitive_output_rejection(
        &mut self,
        permit: super::CommandOutputCaptureReconciliationPermit,
        observation: &EffectObservation,
        event: &crate::AgentEvent,
        anchor: &CommandOutputSensitiveRejectionAnchorV1,
        cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
        command_cleanup: &CommandDomainCleanupProof,
    ) -> Result<PersistedEffect, LedgerError> {
        self.require_writable()?;
        let evidence_bytes =
            validate_rejection_inputs(observation, event, anchor, cleanup, command_cleanup)?;
        let claim = permit.into_claim_for_ledger(self.instance_id)?;
        if claim.capture_id != anchor.capture_id {
            return Err(reference_mismatch(
                "reconciled sensitive output rejection",
                "reconciliation claim and rejection capture are crossed",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capture =
            super::command_output_capture_authority::load_from_id(&transaction, &claim.capture_id)?;
        let persisted = validate_new_effect_observation(&transaction, observation, event)?;
        let dispatch = persisted.dispatch_claim.as_ref().ok_or_else(|| {
            reference_mismatch(
                "reconciled sensitive output rejection",
                "restart rejection lacks its durable dispatch claim",
            )
        })?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "reconciled sensitive output rejection",
                "restart rejection lacks its capture acquisition",
            )
        })?;
        if capture.terminal.is_some()
            || capture.reconciliation_obligation_closure.is_some()
            || dispatch.dispatch_claim_id != anchor.dispatch_claim_id
            || dispatch.launch_id != command_cleanup.launch_id
            || dispatch.session_id != command_cleanup.session_id
        {
            return Err(reference_mismatch(
                "reconciled sensitive output rejection",
                "capture, dispatch, or cleanup is crossed or terminal",
            ));
        }
        anchor.validate_against(&capture.intent, acquired, observation)?;
        require_exact_cleanup(anchor, cleanup, command_cleanup)?;
        let policy =
            load_policy_for_effect(&transaction, &observation.effect_id)?.ok_or_else(|| {
                reference_mismatch(
                    "reconciled sensitive output rejection",
                    "capture lacks pre-effect detector policy",
                )
            })?;
        if policy != anchor.detector_policy {
            return Err(reference_mismatch(
                "reconciled sensitive output rejection",
                "terminal detector policy differs from pre-effect admission",
            ));
        }
        insert_rejection(
            &transaction,
            anchor,
            cleanup,
            &capture.reconciliation_obligation_id,
            command_cleanup.cleaned_at_unix_ms,
            Some((&claim.claim_id, claim.fencing_token.as_str())),
        )?;
        insert_agent_event(&transaction, event)?;
        insert_effect_evidence_payload(&transaction, observation, &evidence_bytes)?;
        insert_claimed_effect_observation(
            &transaction,
            observation,
            &event.event_id,
            &dispatch.dispatch_claim_id,
        )?;
        super::command_domain_cleanup::insert_atomic_command_domain_cleanup_proof(
            &transaction,
            command_cleanup,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "reconciled sensitive output rejection",
                recovery_id: anchor.capture_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path)?;
        let effect = load_effect_from(&self.connection, &observation.effect_id)?;
        let rejection =
            load_for_effect(&self.connection, &observation.effect_id)?.ok_or_else(|| {
                LedgerError::Corrupt {
                    entity: "reconciled sensitive output rejection",
                    detail: "committed rejection is absent on exact readback".into(),
                }
            })?;
        let persisted_cleanup = self.load_command_domain_cleanup_proof(&observation.effect_id)?;
        if effect.observation.as_ref() != Some(observation)
            || effect.evidence_bytes.as_deref() != Some(evidence_bytes.as_slice())
            || effect.terminal_event.as_ref() != Some(event)
            || rejection.anchor != *anchor
            || rejection.cleanup != *cleanup
            || persisted_cleanup.proof != *command_cleanup
        {
            return Err(LedgerError::Corrupt {
                entity: "reconciled sensitive output rejection",
                detail: "post-commit effect or abandonment differs".into(),
            });
        }
        Ok(effect)
    }
}

fn validate_rejection_inputs(
    observation: &EffectObservation,
    event: &crate::AgentEvent,
    anchor: &CommandOutputSensitiveRejectionAnchorV1,
    cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
    command_cleanup: &CommandDomainCleanupProof,
) -> Result<Vec<u8>, LedgerError> {
    observation.validate()?;
    event.validate()?;
    anchor.validate()?;
    cleanup.validate()?;
    command_cleanup.validate()?;
    if observation.kind != crate::EffectKind::RunCommand
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedAfterKnownEffect { .. }
        )
        || anchor.effect_id != observation.effect_id
        || anchor.observation_id != observation.observation_id
    {
        return Err(reference_mismatch(
            "sensitive output rejection",
            "requires exact RunCommand FailedAfterKnownEffect observation",
        ));
    }
    require_exact_cleanup(anchor, cleanup, command_cleanup)?;
    let bytes = anchor.canonical_evidence_bytes()?;
    if Digest::sha256(&bytes) != *observation.outcome.evidence_digest() {
        return Err(reference_mismatch(
            "sensitive output rejection",
            "effect evidence must be exact canonical secret-free anchor bytes",
        ));
    }
    Ok(bytes)
}

fn require_exact_cleanup(
    anchor: &CommandOutputSensitiveRejectionAnchorV1,
    cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
    command_cleanup: &CommandDomainCleanupProof,
) -> Result<(), LedgerError> {
    if cleanup.capture_id != anchor.capture_id
        || cleanup.effect_id != anchor.effect_id
        || cleanup.observation_id != anchor.observation_id
        || cleanup.rejection_anchor_digest != anchor.rejection_anchor_digest
        || cleanup.detector_policy != anchor.detector_policy
        || cleanup.command_domain_cleanup_proof_id != command_cleanup.proof_id
        || cleanup.runner_cleanup != anchor.runner_cleanup
        || cleanup.runner_cleanup.journal_id != anchor.runner_journal_id
        || cleanup.runner_cleanup.launch_intended_journal_head
            != anchor.launch_intended_journal_head
        || cleanup.runner_cleanup.core_dump_suppression != anchor.core_dump_suppression
        || cleanup.runner_cleanup.rejected_terminal_journal_head
            != anchor.rejected_terminal_journal_head
        || command_cleanup.effect_id != anchor.effect_id
        || command_cleanup.observation_id.as_deref() != Some(anchor.observation_id.as_str())
        || command_cleanup.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || command_cleanup.surviving_processes != 0
    {
        return Err(reference_mismatch(
            "sensitive output rejection cleanup",
            "requires exact runner journal cleanup and ReapedZeroSurvivors command-domain proof",
        ));
    }
    anchor
        .core_dump_suppression
        .validate_for_backend(command_cleanup.backend)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic insert intentionally exposes the complete 52-column canonical receipt projection in one reviewable SQL boundary"
)]
pub(super) fn insert_clean_scan_publication(
    transaction: &Transaction<'_>,
    receipt: &CommandOutputCleanScanPublicationReceiptV1,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    command_cleanup: &CommandDomainCleanupProof,
) -> Result<(), LedgerError> {
    if !schema_is_installed(transaction)? {
        return Err(reference_mismatch(
            "command output clean-scan publication receipt",
            "schema v29 is required for current-policy publication",
        ));
    }
    let policy = load_policy_for_effect(transaction, &terminal.effect_id)?.ok_or_else(|| {
        reference_mismatch(
            "command output clean-scan publication receipt",
            "Published capture lacks its pre-effect detector policy",
        )
    })?;
    receipt.validate_against(intent, acquired, &policy, terminal)?;
    receipt
        .core_dump_suppression
        .validate_for_backend(command_cleanup.backend)?;
    let bytes = encode("command output clean-scan publication receipt", receipt)?;
    let (termination_kind, termination_code, termination_signal) =
        termination_storage_parts(receipt.termination);
    transaction.execute(
        "INSERT INTO command_output_clean_scan_publication_receipts_v29 (
            clean_scan_receipt_digest, clean_scan_receipt_id, capture_id,
            effect_id, observation_id, runner_session_id, request_digest,
            intent_digest, acquired_anchor_digest, detector_policy_id,
            detector_policy_version, detector_policy_digest,
            core_dump_schema_version, core_limit_current, core_limit_maximum,
            linux_dumpable_disabled, core_dump_profile_digest, runner_journal_id,
            launch_intended_head_generation, launch_intended_head_digest,
            scanned_clean_head_generation, scanned_clean_head_digest,
            finished_head_generation, finished_head_digest,
            published_head_generation, published_head_digest,
            terminal_prepared_head_generation, terminal_prepared_head_digest,
            acquired_store_head_generation, acquired_store_head_digest,
            writer_attached_store_head_generation, writer_attached_store_head_digest,
            launch_intended_store_head_generation, launch_intended_store_head_digest,
            finished_store_head_generation, finished_store_head_digest,
            published_store_head_generation, published_store_head_digest,
            terminal_prepared_store_head_generation,
            terminal_prepared_store_head_digest, terminal_record_digest,
            termination_kind, termination_code, termination_signal,
            scanned_clean_at_unix_ms, finished_at_unix_ms,
            published_at_unix_ms, terminal_prepared_at_unix_ms,
            terminal_anchor_digest, layout_version, contract_version,
            clean_scan_receipt_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
            ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35,
            ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46,
            ?47, ?48, ?49, ?50, ?51, ?52
         )",
        params![
            receipt.clean_scan_receipt_digest.as_str(),
            receipt.clean_scan_receipt_id,
            receipt.capture_id,
            receipt.effect_id,
            receipt.observation_id,
            receipt.runner_session_id,
            receipt.request_digest.as_str(),
            receipt.intent_digest.as_str(),
            receipt.acquired.acquired_anchor_digest.as_str(),
            receipt.detector_policy.policy_id,
            i64::from(receipt.detector_policy.policy_version),
            receipt.detector_policy.policy_digest.as_str(),
            i64::from(receipt.core_dump_suppression.schema_version),
            sqlite_integer(
                "clean-scan core current limit",
                receipt.core_dump_suppression.core_limit_current,
            )?,
            sqlite_integer(
                "clean-scan core maximum limit",
                receipt.core_dump_suppression.core_limit_maximum,
            )?,
            receipt
                .core_dump_suppression
                .linux_dumpable_disabled
                .map(i64::from),
            receipt.core_dump_suppression.profile_digest.as_str(),
            receipt.runner_journal_id,
            sqlite_integer(
                "clean-scan launch-intended journal generation",
                receipt.launch_intended_journal_head.generation,
            )?,
            receipt.launch_intended_journal_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan journal generation",
                receipt.scanned_clean_journal_head.generation,
            )?,
            receipt.scanned_clean_journal_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan finished journal generation",
                receipt.finished_journal_head.generation,
            )?,
            receipt.finished_journal_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan published journal generation",
                receipt.published_journal_head.generation,
            )?,
            receipt.published_journal_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan terminal-prepared journal generation",
                receipt.terminal_prepared_journal_head.generation,
            )?,
            receipt
                .terminal_prepared_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "clean-scan acquired store generation",
                receipt.acquired_store_head.generation,
            )?,
            receipt.acquired_store_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan writer-attached store generation",
                receipt.writer_attached_store_head.generation,
            )?,
            receipt.writer_attached_store_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan launch-intended store generation",
                receipt.launch_intended_store_head.generation,
            )?,
            receipt.launch_intended_store_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan finished store generation",
                receipt.finished_store_head.generation,
            )?,
            receipt.finished_store_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan published store generation",
                receipt.published_store_head.generation,
            )?,
            receipt.published_store_head.record_digest.as_str(),
            sqlite_integer(
                "clean-scan terminal-prepared store generation",
                receipt.terminal_prepared_store_head.generation,
            )?,
            receipt.terminal_prepared_store_head.record_digest.as_str(),
            receipt.terminal_record_digest.as_str(),
            termination_kind,
            termination_code,
            termination_signal,
            sqlite_integer(
                "clean-scan runner scan time",
                receipt.scanned_clean_at_unix_ms,
            )?,
            sqlite_integer("clean-scan runner finish time", receipt.finished_at_unix_ms,)?,
            sqlite_integer(
                "clean-scan runner publication time",
                receipt.published_at_unix_ms,
            )?,
            sqlite_integer(
                "clean-scan runner terminal-prepared time",
                receipt.terminal_prepared_at_unix_ms,
            )?,
            receipt.terminal_anchor_digest.as_str(),
            i64::from(receipt.layout_version),
            i64::from(receipt.contract_version),
            bytes,
        ],
    )?;
    Ok(())
}

/// Stages one current-policy clean-resolution receipt before the reciprocal
/// v27 resolution row is inserted in the same transaction.
///
/// The table's deferred FK and the resolution's reciprocal trigger make this
/// an atomic two-sided authority: neither row can commit alone.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the insert visibly rebinds every durable authority and normalized resolution selector"
)]
pub(super) fn insert_clean_scan_resolution(
    transaction: &Transaction<'_>,
    receipt: &CommandOutputCleanScanResolutionReceiptV1,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    unknown_terminal: &CommandOutputCaptureTerminalAnchorV1,
    reconciliation_claim: &CommandOutputCaptureReconciliationClaimV1,
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
    resolution_physical: Option<&CommandOutputCapturePhysicalReconciliationV1>,
    command_cleanup: &CommandDomainCleanupProof,
) -> Result<(), LedgerError> {
    if !schema_is_installed(transaction)? {
        return Err(reference_mismatch(
            "command output clean-scan resolution receipt",
            "schema v29 is required for current-policy Unknown publication",
        ));
    }
    let policy =
        load_policy_for_effect(transaction, &intent.source.effect_id)?.ok_or_else(|| {
            reference_mismatch(
                "command output clean-scan resolution receipt",
                "current-policy Unknown publication lacks its pre-effect detector policy",
            )
        })?;
    receipt.validate_against(
        intent,
        acquired,
        unknown_terminal,
        reconciliation_claim,
        resolution,
        &policy,
    )?;
    validate_clean_resolution_physical_join(receipt, resolution_physical)?;
    receipt
        .clean_runner
        .core_dump_suppression
        .validate_for_backend(command_cleanup.backend)?;
    if command_cleanup.effect_id != resolution.effect_id
        || command_cleanup.observation_id.as_deref() != Some(resolution.observation_id.as_str())
        || command_cleanup.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || command_cleanup.surviving_processes != 0
    {
        return Err(reference_mismatch(
            "command output clean-scan resolution receipt",
            "command cleanup must prove the exact resolved command domain empty",
        ));
    }
    let artifacts = resolution.artifact_reference.as_ref().ok_or_else(|| {
        reference_mismatch(
            "command output clean-scan resolution receipt",
            "Published resolution lacks exact immutable artifacts",
        )
    })?;
    let bytes = encode("command output clean-scan resolution receipt", receipt)?;
    transaction.execute(
        "INSERT INTO command_output_clean_scan_resolution_receipts_v29 (
            clean_scan_resolution_receipt_digest,
            clean_scan_resolution_receipt_id, capture_id, effect_id,
            observation_id, intent_digest, acquired_anchor_digest,
            terminal_anchor_digest, reconciliation_claim_id,
            reconciliation_fencing_token, resolution_anchor_digest,
            artifact_manifest_digest, resolution_store_head_generation,
            resolution_store_head_digest, resolution_record_digest,
            detector_policy_id, detector_policy_version,
            detector_policy_digest, runner_journal_id,
            terminal_prepared_head_generation,
            terminal_prepared_head_digest,
            terminal_prepared_store_head_generation,
            terminal_prepared_store_head_digest,
            terminal_prepared_at_unix_ms, resolved_at_unix_ms,
            layout_version, contract_version,
            clean_scan_resolution_receipt_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
            ?26, ?27, ?28
         )",
        params![
            receipt.clean_scan_resolution_receipt_digest.as_str(),
            receipt.clean_scan_resolution_receipt_id,
            intent.capture_id,
            intent.source.effect_id,
            unknown_terminal.observation_id,
            intent.intent_digest.as_str(),
            acquired.acquired_anchor_digest.as_str(),
            unknown_terminal.terminal_anchor_digest.as_str(),
            reconciliation_claim.claim_id,
            reconciliation_claim.fencing_token.as_str(),
            resolution.resolution_anchor_digest.as_str(),
            artifacts.manifest_digest.as_str(),
            sqlite_integer(
                "clean-scan resolution store generation",
                resolution.store_head.generation,
            )?,
            resolution.store_head.record_digest.as_str(),
            resolution.resolution_record_digest.as_str(),
            policy.policy_id,
            i64::from(policy.policy_version),
            policy.policy_digest.as_str(),
            receipt.clean_runner.journal_id,
            sqlite_integer(
                "clean-scan resolution terminal journal generation",
                receipt
                    .clean_runner
                    .terminal_prepared_journal_head
                    .generation,
            )?,
            receipt
                .clean_runner
                .terminal_prepared_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "clean-scan resolution terminal store generation",
                receipt.clean_runner.terminal_prepared_store_head.generation,
            )?,
            receipt
                .clean_runner
                .terminal_prepared_store_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "clean-scan resolution terminal-prepared time",
                receipt.clean_runner.terminal_prepared_at_unix_ms,
            )?,
            sqlite_integer(
                "clean-scan resolution completion time",
                resolution.resolved_at_unix_ms,
            )?,
            i64::from(receipt.layout_version),
            i64::from(receipt.contract_version),
            bytes,
        ],
    )?;
    Ok(())
}

fn load_clean_scan_publication_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<CommandOutputCleanScanPublicationReceiptV1>, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "SELECT clean_scan_receipt_json, clean_scan_receipt_digest,
                    clean_scan_receipt_id, capture_id, observation_id,
                    terminal_anchor_digest
             FROM command_output_clean_scan_publication_receipts_v29
             WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(bytes, digest, receipt_id, capture_id, observation_id, terminal_anchor_digest)| {
            let receipt: CommandOutputCleanScanPublicationReceiptV1 =
                decode_canonical("command output clean-scan publication receipt", &bytes)?;
            receipt.validate()?;
            if receipt.effect_id != effect_id
                || receipt.clean_scan_receipt_digest.as_str() != digest
                || receipt.clean_scan_receipt_id != receipt_id
                || receipt.capture_id != capture_id
                || receipt.observation_id != observation_id
                || receipt.terminal_anchor_digest.as_str() != terminal_anchor_digest
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output clean-scan publication receipt",
                    detail: "normalized receipt columns differ from canonical JSON".into(),
                });
            }
            let exact = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM command_output_clean_scan_publication_exact_v29
                     WHERE effect_id = ?1 AND capture_id = ?2
                       AND observation_id = ?3 AND clean_scan_receipt_digest = ?4
                       AND terminal_anchor_digest = ?5
                 )",
                params![
                    receipt.effect_id,
                    receipt.capture_id,
                    receipt.observation_id,
                    receipt.clean_scan_receipt_digest.as_str(),
                    receipt.terminal_anchor_digest.as_str(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact {
                return Err(LedgerError::Corrupt {
                    entity: "command output clean-scan publication receipt",
                    detail: "receipt no longer resolves its exact current-policy acquisition and Published terminal".into(),
                });
            }
            Ok(receipt)
        },
    )
    .transpose()
}

pub(super) fn load_clean_scan_resolution_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<CommandOutputCleanScanResolutionReceiptV1>, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "SELECT clean_scan_resolution_receipt_json,
                    clean_scan_resolution_receipt_digest,
                    clean_scan_resolution_receipt_id, capture_id,
                    observation_id, terminal_anchor_digest,
                    resolution_anchor_digest
             FROM command_output_clean_scan_resolution_receipts_v29
             WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            bytes,
            digest,
            receipt_id,
            capture_id,
            observation_id,
            terminal_anchor_digest,
            resolution_anchor_digest,
        )| {
            let receipt: CommandOutputCleanScanResolutionReceiptV1 =
                decode_canonical("command output clean-scan resolution receipt", &bytes)?;
            receipt.validate()?;
            if receipt.intent.source.effect_id != effect_id
                || receipt.clean_scan_resolution_receipt_digest.as_str() != digest
                || receipt.clean_scan_resolution_receipt_id != receipt_id
                || receipt.intent.capture_id != capture_id
                || receipt.unknown_terminal.observation_id != observation_id
                || receipt.unknown_terminal.terminal_anchor_digest.as_str()
                    != terminal_anchor_digest
                || receipt.resolution.resolution_anchor_digest.as_str()
                    != resolution_anchor_digest
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output clean-scan resolution receipt",
                    detail: "normalized receipt columns differ from canonical JSON".into(),
                });
            }
            let exact = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM command_output_clean_scan_resolution_exact_v29
                     WHERE effect_id = ?1 AND capture_id = ?2
                       AND observation_id = ?3
                       AND clean_scan_resolution_receipt_digest = ?4
                       AND terminal_anchor_digest = ?5
                       AND resolution_anchor_digest = ?6
                 )",
                params![
                    receipt.intent.source.effect_id,
                    receipt.intent.capture_id,
                    receipt.unknown_terminal.observation_id,
                    receipt.clean_scan_resolution_receipt_digest.as_str(),
                    receipt.unknown_terminal.terminal_anchor_digest.as_str(),
                    receipt.resolution.resolution_anchor_digest.as_str(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact {
                return Err(LedgerError::Corrupt {
                    entity: "command output clean-scan resolution receipt",
                    detail: "receipt no longer resolves its exact current-policy Unknown terminal and Published resolution".into(),
                });
            }
            Ok(receipt)
        },
    )
    .transpose()
}

const fn termination_storage_parts(
    termination: CommandTerminationV1,
) -> (&'static str, Option<i32>, Option<i32>) {
    match termination {
        CommandTerminationV1::Exited { code } => ("Exited", Some(code), None),
        CommandTerminationV1::Signaled { signal } => ("Signaled", None, Some(signal)),
        CommandTerminationV1::TimedOut => ("TimedOut", None, None),
        CommandTerminationV1::Canceled => ("Canceled", None, None),
        CommandTerminationV1::OutputLimitExceeded => ("OutputLimitExceeded", None, None),
    }
}

pub(super) fn insert_policy_admission(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
) -> Result<(), LedgerError> {
    if !schema_is_installed(transaction)? {
        return Ok(());
    }
    let policy = SensitiveOutputDetectionPolicyReferenceV1::core_v1();
    let bytes = encode("sensitive output detection policy", &policy)?;
    transaction.execute(
        "INSERT INTO command_output_sensitive_detection_policy_admissions_v29 (
            capture_id, effect_id, policy_id, policy_version, policy_digest,
            admitted_at_unix_ms, contract_version, policy_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            intent.capture_id,
            intent.source.effect_id,
            policy.policy_id,
            i64::from(policy.policy_version),
            policy.policy_digest.as_str(),
            sqlite_integer(
                "sensitive output policy admission time",
                intent.created_at_unix_ms
            )?,
            i64::from(intent.contract_version),
            bytes,
        ],
    )?;
    Ok(())
}

pub(super) fn require_policy_state_for_capture(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
) -> Result<(), LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(());
    }
    let policy = load_policy_for_effect(connection, &intent.source.effect_id)?;
    let exempt = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM pre_v29_sensitive_output_policy_exemptions
             WHERE effect_id = ?1 AND capture_id = ?2 AND intent_digest = ?3
         )",
        params![
            intent.source.effect_id,
            intent.capture_id,
            intent.intent_digest.as_str()
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if policy.is_some() == exempt {
        return Err(LedgerError::Corrupt {
            entity: "sensitive output policy admission",
            detail: "capture must have exactly one enforced policy or pre-v29 exemption".into(),
        });
    }
    Ok(())
}

pub(super) fn finish_is_proven_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<bool, LedgerError> {
    Ok(load_for_effect(connection, effect_id)?.is_some())
}

/// Returns whether one effective `Published` disposition is backed by the
/// exact current clean-scan receipt or by a positive immutable pre-v29
/// exemption. Mere absence of the current policy row is corruption, never
/// historical authority.
pub(super) fn published_finish_is_proven_for_capture(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
) -> Result<bool, LedgerError> {
    require_policy_state_for_capture(connection, intent)?;
    if load_policy_for_effect(connection, &intent.source.effect_id)?.is_none() {
        return Ok(true);
    }
    let capture = super::command_output_capture_authority::load_from_effect(
        connection,
        &intent.source.effect_id,
    )?
    .ok_or_else(|| LedgerError::Corrupt {
        entity: "command output clean-scan finish authority",
        detail: "policy-bound effect lost its capture lifecycle".into(),
    })?;
    if capture.reconciliation_resolution.is_some() {
        return Ok(
            load_clean_scan_resolution_for_effect(connection, &intent.source.effect_id)?.is_some(),
        );
    }
    Ok(load_clean_scan_publication_for_effect(connection, &intent.source.effect_id)?.is_some())
}

/// Returns whether a staged v29 rejection authorizes a command-domain cleanup
/// whose physical cleanup time precedes the later coordinator observation.
///
/// The command-domain module calls this only while atomically inserting the
/// exact proof referenced by an already-staged rejection/cleanup/closure
/// chain. No partial chain can relax its ordinary observation-time ordering.
pub(super) fn staged_rejection_allows_cleanup_before_observation(
    connection: &Connection,
    proof: &CommandDomainCleanupProof,
    observed_at_unix_ms: u64,
) -> Result<bool, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS (
                 SELECT 1
                 FROM command_output_sensitive_rejection_anchors_v29 anchor
                 JOIN command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
                   ON cleanup.rejection_anchor_digest = anchor.rejection_anchor_digest
                  AND cleanup.capture_id = anchor.capture_id
                  AND cleanup.effect_id = anchor.effect_id
                  AND cleanup.observation_id = anchor.observation_id
                 JOIN command_output_sensitive_rejection_closures_v29 closure
                   ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
                  AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
                  AND closure.command_domain_cleanup_proof_id =
                      cleanup.command_domain_cleanup_proof_id
                 WHERE cleanup.command_domain_cleanup_proof_id = ?1
                   AND anchor.effect_id = ?2
                   AND anchor.observation_id = ?3
                   AND closure.closed_at_unix_ms = ?4
                   AND closure.closed_at_unix_ms <= ?5
             )",
            params![
                proof.proof_id,
                proof.effect_id,
                proof.observation_id,
                sqlite_integer(
                    "sensitive output command cleanup time",
                    proof.cleaned_at_unix_ms,
                )?,
                sqlite_integer(
                    "sensitive output coordinator observation time",
                    observed_at_unix_ms,
                )?,
            ],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

#[allow(
    clippy::too_many_lines,
    reason = "exact readback revalidates every normalized and canonical rejection join in one fail-closed boundary"
)]
pub(super) fn load_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<PersistedCommandOutputSensitiveRejectionV1>, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "SELECT anchor.rejection_json, cleanup.cleanup_json, closure.closure_json
             FROM command_output_sensitive_rejection_anchors_v29 anchor
             LEFT JOIN command_output_sensitive_rejection_cleanup_receipts_v29 cleanup
               ON cleanup.rejection_anchor_digest = anchor.rejection_anchor_digest
             LEFT JOIN command_output_sensitive_rejection_closures_v29 closure
               ON closure.rejection_anchor_digest = anchor.rejection_anchor_digest
              AND closure.cleanup_receipt_digest = cleanup.cleanup_receipt_digest
             WHERE anchor.effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((anchor_bytes, cleanup_bytes, closure_bytes)) = row else {
        return Ok(None);
    };
    let cleanup_bytes = cleanup_bytes.ok_or_else(|| LedgerError::Corrupt {
        entity: "command output sensitive rejection",
        detail: "rejection anchor lacks its cleanup receipt".into(),
    })?;
    let closure_bytes = closure_bytes.ok_or_else(|| LedgerError::Corrupt {
        entity: "command output sensitive rejection",
        detail: "rejection anchor lacks its obligation closure".into(),
    })?;
    let anchor: CommandOutputSensitiveRejectionAnchorV1 =
        decode_canonical("command output sensitive rejection anchor", &anchor_bytes)?;
    let cleanup: CommandOutputSensitiveRejectionCleanupReceiptV1 =
        decode_canonical("command output sensitive rejection cleanup", &cleanup_bytes)?;
    let closure: CommandOutputSensitiveRejectionClosureV1 =
        decode_canonical("command output sensitive rejection closure", &closure_bytes)?;
    let intent = super::command_output_capture_authority::load_from_effect(connection, effect_id)?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output sensitive rejection",
            detail: "rejection lacks its capture intent".into(),
        })?;
    let acquired = intent
        .acquired
        .as_ref()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output sensitive rejection",
            detail: "rejection lacks its capture acquisition".into(),
        })?;
    let effect = super::load_effect_from(connection, effect_id)?;
    let observation = effect
        .observation
        .as_ref()
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output sensitive rejection",
            detail: "rejection lacks its effect observation".into(),
        })?;
    anchor
        .validate_against(&intent.intent, acquired, observation)
        .map_err(contract_corrupt(
            "command output sensitive rejection anchor",
        ))?;
    cleanup.validate().map_err(contract_corrupt(
        "command output sensitive rejection cleanup",
    ))?;
    closure.validate().map_err(contract_corrupt(
        "command output sensitive rejection closure",
    ))?;
    if cleanup.capture_id != anchor.capture_id
        || cleanup.effect_id != anchor.effect_id
        || cleanup.observation_id != anchor.observation_id
        || cleanup.rejection_anchor_digest != anchor.rejection_anchor_digest
        || cleanup.detector_policy != anchor.detector_policy
        || cleanup.runner_cleanup.journal_id != anchor.runner_journal_id
        || cleanup.runner_cleanup.rejected_terminal_journal_head
            != anchor.rejected_terminal_journal_head
        || cleanup.runner_cleanup != anchor.runner_cleanup
        || closure.capture_id != anchor.capture_id
        || closure.effect_id != anchor.effect_id
        || closure.observation_id != anchor.observation_id
        || closure.rejection_anchor_digest != anchor.rejection_anchor_digest
        || closure.cleanup_receipt_digest != cleanup.cleanup_receipt_digest
        || closure.command_domain_cleanup_proof_id != cleanup.command_domain_cleanup_proof_id
    {
        return Err(LedgerError::Corrupt {
            entity: "command output sensitive rejection",
            detail: "anchor, cleanup receipt, or closure identities are crossed".into(),
        });
    }
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM command_output_sensitive_rejection_exact_finishes_v29
             WHERE effect_id = ?1 AND rejection_anchor_digest = ?2
               AND cleanup_receipt_digest = ?3 AND closure_digest = ?4
         )",
        params![
            effect_id,
            anchor.rejection_anchor_digest.as_str(),
            cleanup.cleanup_receipt_digest.as_str(),
            closure.closure_digest.as_str(),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output sensitive rejection",
            detail: "normalized rejection authority is incomplete or crossed".into(),
        });
    }
    Ok(Some(PersistedCommandOutputSensitiveRejectionV1 {
        anchor,
        cleanup,
        closure,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic writer keeps anchor, cleanup, closure, and optional claim release visibly co-located"
)]
pub(super) fn insert_rejection(
    transaction: &Transaction<'_>,
    anchor: &CommandOutputSensitiveRejectionAnchorV1,
    cleanup: &CommandOutputSensitiveRejectionCleanupReceiptV1,
    obligation_id: &str,
    closed_at_unix_ms: u64,
    reconciliation_claim: Option<(&str, &str)>,
) -> Result<CommandOutputSensitiveRejectionClosureV1, LedgerError> {
    anchor.validate()?;
    cleanup.validate()?;
    let closure = CommandOutputSensitiveRejectionClosureV1::derive(
        obligation_id.to_owned(),
        anchor,
        cleanup,
        closed_at_unix_ms,
    )?;
    let anchor_bytes = encode("command output sensitive rejection anchor", anchor)?;
    let cleanup_bytes = encode("command output sensitive rejection cleanup", cleanup)?;
    let closure_bytes = encode("command output sensitive rejection closure", &closure)?;
    let (termination_kind, termination_code, termination_signal) = match anchor.termination {
        CommandTerminationV1::Exited { code } => ("Exited", Some(code), None),
        CommandTerminationV1::Signaled { signal } => ("Signaled", None, Some(signal)),
        CommandTerminationV1::TimedOut => ("TimedOut", None, None),
        CommandTerminationV1::Canceled => ("Canceled", None, None),
        CommandTerminationV1::OutputLimitExceeded => ("OutputLimitExceeded", None, None),
    };
    transaction.execute(
        "INSERT INTO command_output_sensitive_rejection_anchors_v29 (
            rejection_anchor_digest, capture_id, effect_id, observation_id,
            dispatch_claim_id, intent_digest, acquired_anchor_digest, reason,
            detector_policy_id, detector_policy_version, detector_policy_digest,
            core_dump_schema_version, core_limit_current, core_limit_maximum,
            linux_dumpable_disabled, core_dump_profile_digest,
            staging_neutralization_receipt_digest,
            termination_kind, termination_code, termination_signal,
            runner_journal_id, launch_intended_head_generation,
            launch_intended_head_digest, rejected_terminal_head_generation,
            rejected_terminal_head_digest, effect_evidence_digest,
            layout_version, contract_version, rejection_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                   ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29)",
        params![
            anchor.rejection_anchor_digest.as_str(),
            anchor.capture_id,
            anchor.effect_id,
            anchor.observation_id,
            anchor.dispatch_claim_id,
            anchor.intent_digest.as_str(),
            anchor.acquired_anchor_digest.as_str(),
            anchor.reason.storage_name(),
            anchor.detector_policy.policy_id,
            i64::from(anchor.detector_policy.policy_version),
            anchor.detector_policy.policy_digest.as_str(),
            i64::from(anchor.core_dump_suppression.schema_version),
            sqlite_integer(
                "sensitive output core current limit",
                anchor.core_dump_suppression.core_limit_current,
            )?,
            sqlite_integer(
                "sensitive output core maximum limit",
                anchor.core_dump_suppression.core_limit_maximum,
            )?,
            anchor
                .core_dump_suppression
                .linux_dumpable_disabled
                .map(i64::from),
            anchor.core_dump_suppression.profile_digest.as_str(),
            anchor.staging_neutralization.receipt_digest.as_str(),
            termination_kind,
            termination_code,
            termination_signal,
            anchor.runner_journal_id,
            sqlite_integer(
                "sensitive output launch-intended head generation",
                anchor.launch_intended_journal_head.generation,
            )?,
            anchor.launch_intended_journal_head.record_digest.as_str(),
            sqlite_integer(
                "sensitive output rejected terminal head generation",
                anchor.rejected_terminal_journal_head.generation,
            )?,
            anchor.rejected_terminal_journal_head.record_digest.as_str(),
            Digest::sha256(&anchor_bytes).as_str(),
            i64::from(anchor.layout_version),
            i64::from(anchor.contract_version),
            anchor_bytes,
        ],
    )?;
    transaction.execute(
        "INSERT INTO command_output_sensitive_rejection_cleanup_receipts_v29 (
            cleanup_receipt_digest, cleanup_receipt_id, capture_id, effect_id,
            observation_id, rejection_anchor_digest, detector_policy_id,
            detector_policy_version, detector_policy_digest,
            core_dump_schema_version, core_limit_current, core_limit_maximum,
            linux_dumpable_disabled, core_dump_profile_digest,
            staging_neutralization_receipt_digest,
            runner_journal_id, launch_intended_head_generation,
            launch_intended_head_digest, detected_head_generation, detected_head_digest,
            cleanup_intended_head_generation, cleanup_intended_head_digest,
            cleaned_head_generation, cleaned_head_digest,
            rejected_terminal_head_generation, rejected_terminal_head_digest,
            runner_cleanup_receipt_id,
            runner_cleanup_receipt_digest, command_domain_cleanup_proof_id,
            layout_version, contract_version, cleanup_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                   ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32)",
        params![
            cleanup.cleanup_receipt_digest.as_str(),
            cleanup.cleanup_receipt_id,
            cleanup.capture_id,
            cleanup.effect_id,
            cleanup.observation_id,
            cleanup.rejection_anchor_digest.as_str(),
            cleanup.detector_policy.policy_id,
            i64::from(cleanup.detector_policy.policy_version),
            cleanup.detector_policy.policy_digest.as_str(),
            i64::from(cleanup.runner_cleanup.core_dump_suppression.schema_version),
            sqlite_integer(
                "sensitive output cleanup core current limit",
                cleanup
                    .runner_cleanup
                    .core_dump_suppression
                    .core_limit_current,
            )?,
            sqlite_integer(
                "sensitive output cleanup core maximum limit",
                cleanup
                    .runner_cleanup
                    .core_dump_suppression
                    .core_limit_maximum,
            )?,
            cleanup
                .runner_cleanup
                .core_dump_suppression
                .linux_dumpable_disabled
                .map(i64::from),
            cleanup
                .runner_cleanup
                .core_dump_suppression
                .profile_digest
                .as_str(),
            cleanup
                .runner_cleanup
                .staging_neutralization
                .receipt_digest
                .as_str(),
            cleanup.runner_cleanup.journal_id,
            sqlite_integer(
                "sensitive output launch-intended head generation",
                cleanup
                    .runner_cleanup
                    .launch_intended_journal_head
                    .generation,
            )?,
            cleanup
                .runner_cleanup
                .launch_intended_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "sensitive output detected head generation",
                cleanup.runner_cleanup.detected_journal_head.generation,
            )?,
            cleanup
                .runner_cleanup
                .detected_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "sensitive output cleanup-intended head generation",
                cleanup
                    .runner_cleanup
                    .cleanup_intended_journal_head
                    .generation,
            )?,
            cleanup
                .runner_cleanup
                .cleanup_intended_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "sensitive output cleaned head generation",
                cleanup.runner_cleanup.cleaned_journal_head.generation,
            )?,
            cleanup
                .runner_cleanup
                .cleaned_journal_head
                .record_digest
                .as_str(),
            sqlite_integer(
                "sensitive output rejected terminal head generation",
                cleanup
                    .runner_cleanup
                    .rejected_terminal_journal_head
                    .generation,
            )?,
            cleanup
                .runner_cleanup
                .rejected_terminal_journal_head
                .record_digest
                .as_str(),
            cleanup.runner_cleanup.cleanup_receipt_id,
            cleanup.runner_cleanup.cleanup_receipt_digest.as_str(),
            cleanup.command_domain_cleanup_proof_id,
            i64::from(cleanup.layout_version),
            i64::from(cleanup.contract_version),
            cleanup_bytes,
        ],
    )?;
    transaction.execute(
        "INSERT INTO command_output_sensitive_rejection_closures_v29 (
            closure_digest, obligation_id, capture_id, effect_id, observation_id,
            rejection_anchor_digest, cleanup_receipt_digest,
            command_domain_cleanup_proof_id, reconciliation_claim_id,
            reconciliation_fencing_token, closed_at_unix_ms, contract_version,
            closure_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            closure.closure_digest.as_str(),
            closure.obligation_id,
            closure.capture_id,
            closure.effect_id,
            closure.observation_id,
            closure.rejection_anchor_digest.as_str(),
            closure.cleanup_receipt_digest.as_str(),
            closure.command_domain_cleanup_proof_id,
            reconciliation_claim.map(|value| value.0),
            reconciliation_claim.map(|value| value.1),
            sqlite_integer("sensitive output closure time", closure.closed_at_unix_ms)?,
            i64::from(closure.contract_version),
            closure_bytes,
        ],
    )?;
    if let Some((claim_id, fencing_token)) = reconciliation_claim {
        transaction.execute(
            "INSERT INTO command_output_sensitive_rejection_claim_releases_v29 (
                claim_id, capture_id, claim_epoch, fencing_token,
                rejection_anchor_digest, closure_digest, released_at_unix_ms,
                contract_version
             )
             SELECT claim.claim_id, claim.capture_id, claim.claim_epoch,
                    claim.fencing_token, ?3, ?4, ?5, ?6
             FROM command_output_capture_reconciliation_claims claim
             WHERE claim.claim_id = ?1 AND claim.fencing_token = ?2",
            params![
                claim_id,
                fencing_token,
                anchor.rejection_anchor_digest.as_str(),
                closure.closure_digest.as_str(),
                sqlite_integer(
                    "sensitive output claim release time",
                    closure.closed_at_unix_ms
                )?,
                i64::from(closure.contract_version),
            ],
        )?;
    }
    Ok(closure)
}

pub(super) fn load_policy_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<SensitiveOutputDetectionPolicyReferenceV1>, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "SELECT policy_json, policy_id, policy_version, policy_digest
             FROM command_output_sensitive_detection_policy_admissions_v29
             WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(bytes, policy_id, policy_version, policy_digest)| {
        let policy: SensitiveOutputDetectionPolicyReferenceV1 =
            decode_canonical("sensitive output detection policy", &bytes)?;
        policy.validate().map_err(|error| LedgerError::Corrupt {
            entity: "sensitive output detection policy",
            detail: error.to_string(),
        })?;
        if policy.policy_id != policy_id
            || i64::from(policy.policy_version) != policy_version
            || policy.policy_digest.as_str() != policy_digest
        {
            return Err(LedgerError::Corrupt {
                entity: "sensitive output detection policy",
                detail: "normalized policy columns differ from canonical JSON".into(),
            });
        }
        Ok(policy)
    })
    .transpose()
}

fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'command_output_sensitive_detection_policy_admissions_v29'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

pub(super) fn sqlite_policy_canonical(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<SensitiveOutputDetectionPolicyReferenceV1>(
        bytes,
        SensitiveOutputDetectionPolicyReferenceV1::validate,
    )
    .map(|()| "ok".to_owned())
}

pub(super) fn sqlite_anchor_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<CommandOutputSensitiveRejectionAnchorV1>(
        bytes,
        CommandOutputSensitiveRejectionAnchorV1::validate,
    )
    .and_then(|()| {
        serde_json::from_slice::<CommandOutputSensitiveRejectionAnchorV1>(bytes)
            .map(|value| value.rejection_anchor_digest.as_str().to_owned())
            .map_err(|error| error.to_string())
    })
}

pub(super) fn sqlite_clean_scan_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<CommandOutputCleanScanPublicationReceiptV1>(
        bytes,
        CommandOutputCleanScanPublicationReceiptV1::validate,
    )
    .and_then(|()| {
        serde_json::from_slice::<CommandOutputCleanScanPublicationReceiptV1>(bytes)
            .map(|value| value.clean_scan_receipt_digest.as_str().to_owned())
            .map_err(|error| error.to_string())
    })
}

pub(super) fn sqlite_clean_scan_resolution_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<CommandOutputCleanScanResolutionReceiptV1>(
        bytes,
        CommandOutputCleanScanResolutionReceiptV1::validate,
    )
    .and_then(|()| {
        serde_json::from_slice::<CommandOutputCleanScanResolutionReceiptV1>(bytes)
            .map(|value| {
                value
                    .clean_scan_resolution_receipt_digest
                    .as_str()
                    .to_owned()
            })
            .map_err(|error| error.to_string())
    })
}

pub(super) fn sqlite_cleanup_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<CommandOutputSensitiveRejectionCleanupReceiptV1>(
        bytes,
        CommandOutputSensitiveRejectionCleanupReceiptV1::validate,
    )
    .and_then(|()| {
        serde_json::from_slice::<CommandOutputSensitiveRejectionCleanupReceiptV1>(bytes)
            .map(|value| value.cleanup_receipt_digest.as_str().to_owned())
            .map_err(|error| error.to_string())
    })
}

pub(super) fn sqlite_closure_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql::<CommandOutputSensitiveRejectionClosureV1>(
        bytes,
        CommandOutputSensitiveRejectionClosureV1::validate,
    )
    .and_then(|()| {
        serde_json::from_slice::<CommandOutputSensitiveRejectionClosureV1>(bytes)
            .map(|value| value.closure_digest.as_str().to_owned())
            .map_err(|error| error.to_string())
    })
}

fn canonical_sql<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ContractError>,
) -> Result<(), String>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice::<T>(bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes {
        return Err("stored value is not canonical JSON".into());
    }
    Ok(())
}

fn decode_canonical<T>(entity: &'static str, bytes: &[u8]) -> Result<T, LedgerError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = decode_stored(entity, bytes)?;
    if encode(entity, &value)? != bytes {
        return Err(LedgerError::Corrupt {
            entity,
            detail: "stored JSON is not canonical".into(),
        });
    }
    Ok(value)
}

fn compute_rejection_digest(
    canonical: &CanonicalRejectionAnchor<'_>,
) -> Result<Digest, ContractError> {
    compute_digest(REJECTION_ANCHOR_DIGEST_DOMAIN, canonical)
}

fn compute_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest, ContractError> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        ContractError::new(
            "sensitive_output_rejection",
            format!("cannot encode: {error}"),
        )
    })?;
    Ok(domain_digest(domain, &canonical))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(canonical);
    Digest::sha256(&bytes)
}

fn require_versions(contract_version: u32, layout_version: u32) -> Result<(), ContractError> {
    if contract_version != CONTRACT_VERSION
        || layout_version != COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION
    {
        return Err(ContractError::new(
            "command_output_sensitive_rejection",
            "must use the current contract and capture layout versions",
        ));
    }
    Ok(())
}

fn require_capture_id(value: &str) -> Result<(), ContractError> {
    Digest::parse(value.to_owned()).map(|_| ()).map_err(|_| {
        ContractError::new(
            "command_output_sensitive_rejection.capture_id",
            "must contain exactly 64 lowercase hexadecimal characters",
        )
    })
}

fn require_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.len() > MAX_ID_BYTES {
        return Err(ContractError::new(
            field,
            format!("must contain 1..={MAX_ID_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn contract_corrupt(entity: &'static str) -> impl FnOnce(ContractError) -> LedgerError {
    move |error| LedgerError::Corrupt {
        entity,
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
