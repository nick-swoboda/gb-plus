//! Schema-v27 durable command-output capture authority.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{
    EventLedger, FreshRunnerEffectDispatchPermit, LedgerError, PersistedEffect,
    PersistedRunnerEffectDispatchClaim, encode, reference_mismatch, secure_database_files,
    sqlite_integer,
};
use crate::{
    COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION, CONTRACT_VERSION, CommandOutputArtifactSetReferenceV1,
    CommandOutputArtifactSourceV1, ContractError, Digest, EffectObservation, EffectOutcome,
};

pub(super) const MIGRATION_V27: &str = include_str!("command_output_capture_authority_v27.sql");

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'command_output_capture_intents'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Requires every `RunCommand` owned by `sprint_id` either to carry its exact
/// migration-only pre-v27 exemption or to have a fully proven schema-v27
/// command-output finish.
///
/// The current-schema branch revalidates the intent, obligation, terminal,
/// resolution, closure, and claim-release joins rather than trusting closure
/// row presence. A missing current capture is never treated as historical:
/// only the immutable migration exemption can make capture not applicable.
pub(super) fn require_closed_reconciliation_obligations_for_sprint(
    connection: &Connection,
    sprint_id: &str,
    entity: &'static str,
) -> Result<(), LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(());
    }
    let effect_ids = {
        let mut statement = connection.prepare(
            "SELECT effect_id
             FROM effect_intents
             WHERE sprint_id = ?1 AND effect_kind = 'RunCommand'
             ORDER BY effect_id ASC",
        )?;
        statement
            .query_map([sprint_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for effect_id in effect_ids {
        if !finish_is_proven_for_effect(connection, &effect_id)? {
            return Err(reference_mismatch(
                entity,
                format!(
                    "RunCommand effect `{effect_id}` lacks an exact closed command-output capture obligation or migration exemption"
                ),
            ));
        }
    }
    Ok(())
}

const CAPTURE_INTENT_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-intent/v1\0";
const CAPTURE_ACQUIRED_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-acquired/v1\0";
const CAPTURE_TERMINAL_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-capture-terminal/v1\0";
const CAPTURE_RECONCILIATION_LEASE_ID_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-reconciliation-lease/v1\0";
const CAPTURE_RECONCILIATION_CLAIM_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-reconciliation-claim/v1\0";
const CAPTURE_RECONCILIATION_RESOLUTION_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-reconciliation-resolution/v1\0";
const CAPTURE_RESTART_RECOVERY_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-restart-recovery-receipt/v1\0";
const CAPTURE_PHYSICAL_HISTORY_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-physical-history/v1\0";
const CAPTURE_PHYSICAL_FENCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-recovery-fence/v1\0";
const CAPTURE_RECONCILIATION_FENCING_TOKEN_DOMAIN: &[u8] =
    b"grok-build/command-output-capture-reconciliation-fencing-token/v1\0";
const RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN: &[u8] =
    b"grok-build/runner-effect-dispatch-claim/v1\0";

/// Version of the private command-output capture layout authenticated by core.
pub const COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION: u32 = 1;

/// Maximum retained aggregate stdout plus stderr bytes authenticated by v27.
pub const MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES: u64 = 128 * 1024 * 1024;
/// Maximum additional bytes admitted while the contained supervisor crosses
/// and drains its bounded cleanup window: two 64-KiB streams over one crossing
/// observation plus 400 cleanup observations.
pub const COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1: u64 = (64 * 1024 * 2) * (400 + 1);

/// Derives the exact aggregate raw-output custody ceiling from one admitted
/// execution-policy output ceiling.
///
/// Core launch admission and every runner protocol version that uses this
/// capture layout must call this function. That keeps the persisted capture
/// intent and native runner allocation on one overflow-checked formula.
///
/// # Errors
///
/// Returns an error for zero, overflow, or a derived ceiling beyond the
/// immutable capture-store bound.
pub fn current_command_output_capture_maximum_v1(
    policy_max_output_bytes: u64,
) -> Result<u64, ContractError> {
    if policy_max_output_bytes == 0 {
        return Err(ContractError::new(
            "current_command_output_capture_maximum_v1.policy_max_output_bytes",
            "command-output policy ceiling must be greater than zero",
        ));
    }
    let maximum = policy_max_output_bytes
        .checked_add(COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES_V1)
        .ok_or_else(|| {
            ContractError::new(
                "current_command_output_capture_maximum_v1.policy_max_output_bytes",
                "command-output capture ceiling overflowed u64",
            )
        })?;
    if maximum > MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES {
        return Err(ContractError::new(
            "current_command_output_capture_maximum_v1.policy_max_output_bytes",
            format!(
                "command-output capture ceiling {maximum} exceeds immutable-store ceiling {MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES}"
            ),
        ));
    }
    Ok(maximum)
}
/// Maximum exact native-launch binding retained in restart evidence.
///
/// This intentionally matches the runner journal's v1 launch-binding bound so
/// conversion at the crate boundary is lossless without making core depend on
/// runner (which already depends on core).
pub const MAX_COMMAND_OUTPUT_CAPTURE_RESTART_LAUNCH_BINDING_BYTES: usize = 256 * 1024;
/// Maximum duration of one restart-reconciliation ownership claim.
pub const MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS: u64 = 5 * 60 * 1_000;

/// Immutable head of the append-only private capture-store record chain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureStoreHeadV1 {
    /// One-based record generation.
    pub generation: u64,
    /// Digest of the exact canonical record at this generation.
    pub record_digest: Digest,
}

impl CommandOutputCaptureStoreHeadV1 {
    /// Validates the nonzero record generation.
    ///
    /// # Errors
    ///
    /// Returns a contract error for generation zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.generation == 0 {
            return Err(ContractError::new(
                "command_output_capture_store_head_v1.generation",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Descriptor-derived identity of the private capture working directory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureDirectoryIdentityV1 {
    /// Platform device identity, widened to the portable unsigned domain.
    pub device_id: u64,
    /// Platform inode/file identity.
    pub inode: u64,
    /// Effective owner UID that acquired the private namespace.
    pub owner_uid: u32,
    /// Permission bits only; v1 requires exactly `0700`.
    pub mode: u32,
    /// Link count observed through the held descriptor.
    pub link_count: u64,
}

impl CommandOutputCaptureDirectoryIdentityV1 {
    /// Validates the exact private-directory shape.
    ///
    /// # Errors
    ///
    /// Returns a contract error unless the inode and link count are nonzero
    /// and permission bits are exactly owner-only `0700`.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.inode == 0 {
            return Err(ContractError::new(
                "command_output_capture_directory_identity_v1.inode",
                "must be greater than zero",
            ));
        }
        if self.mode != 0o700 {
            return Err(ContractError::new(
                "command_output_capture_directory_identity_v1.mode",
                "must be exactly 0700",
            ));
        }
        if self.link_count == 0 {
            return Err(ContractError::new(
                "command_output_capture_directory_identity_v1.link_count",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Descriptor-derived identity of one reserved raw output stream file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureFileIdentityV1 {
    /// Platform device identity, widened to the portable unsigned domain.
    pub device_id: u64,
    /// Platform inode/file identity.
    pub inode: u64,
    /// Effective owner UID that acquired the private namespace.
    pub owner_uid: u32,
    /// Permission bits only; v1 requires exactly `0600`.
    pub mode: u32,
    /// Held-descriptor link count; v1 requires exactly one.
    pub link_count: u64,
    /// Initial length; v1 acquisition requires an empty stream file.
    pub byte_length: u64,
}

impl CommandOutputCaptureFileIdentityV1 {
    /// Validates the exact fresh regular-file shape.
    ///
    /// # Errors
    ///
    /// Returns a contract error unless the inode is nonzero and the file is a
    /// private, single-link, zero-length reservation.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.inode == 0 {
            return Err(ContractError::new(
                "command_output_capture_file_identity_v1.inode",
                "must be greater than zero",
            ));
        }
        if self.mode != 0o600 {
            return Err(ContractError::new(
                "command_output_capture_file_identity_v1.mode",
                "must be exactly 0600",
            ));
        }
        if self.link_count != 1 {
            return Err(ContractError::new(
                "command_output_capture_file_identity_v1.link_count",
                "must be exactly one",
            ));
        }
        if self.byte_length != 0 {
            return Err(ContractError::new(
                "command_output_capture_file_identity_v1.byte_length",
                "must be zero at acquisition",
            ));
        }
        Ok(())
    }
}

/// Core-side immutable intent committed with one new `RunCommand` effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureIntentV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Private capture layout version.
    pub layout_version: u32,
    /// Caller-preallocated 256-bit identity, encoded as 64 lowercase hex.
    pub capture_id: String,
    /// Exact command lifecycle that will own the output.
    pub source: CommandOutputArtifactSourceV1,
    /// Exact authenticated private-state root identity.
    pub private_state_digest: Digest,
    /// Maximum aggregate raw stdout plus stderr bytes.
    pub max_aggregate_output_bytes: u64,
    /// Time at which the capture and effect intent become durable.
    pub created_at_unix_ms: u64,
    /// Domain-separated digest of every preceding canonical field.
    pub intent_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCaptureIntent<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    source: &'a CommandOutputArtifactSourceV1,
    private_state_digest: &'a Digest,
    max_aggregate_output_bytes: u64,
    created_at_unix_ms: u64,
}

impl CommandOutputCaptureIntentV1 {
    /// Constructs a self-authenticating capture intent from caller authority.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid capture ID, source, limit,
    /// timestamp, or canonical encoding.
    pub fn try_new(
        capture_id: impl Into<String>,
        source: CommandOutputArtifactSourceV1,
        private_state_digest: Digest,
        max_aggregate_output_bytes: u64,
        created_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let capture_id = capture_id.into();
        let intent_digest = compute_intent_digest(
            CONTRACT_VERSION,
            COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION,
            &capture_id,
            &source,
            &private_state_digest,
            max_aggregate_output_bytes,
            created_at_unix_ms,
        )?;
        let intent = Self {
            contract_version: CONTRACT_VERSION,
            layout_version: COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION,
            capture_id,
            source,
            private_state_digest,
            max_aggregate_output_bytes,
            created_at_unix_ms,
            intent_digest,
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validates all indexed fields and the canonical intent digest.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a crossed, noncanonical, or unsupported
    /// intent.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_contract_and_layout(
            "command_output_capture_intent_v1",
            self.contract_version,
            self.layout_version,
        )?;
        require_capture_id(&self.capture_id)?;
        self.source.validate()?;
        require_capture_limit(self.max_aggregate_output_bytes)?;
        if self.created_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_capture_intent_v1.created_at_unix_ms",
                "must be greater than zero",
            ));
        }
        let expected = compute_intent_digest(
            self.contract_version,
            self.layout_version,
            &self.capture_id,
            &self.source,
            &self.private_state_digest,
            self.max_aggregate_output_bytes,
            self.created_at_unix_ms,
        )?;
        if self.intent_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_intent_v1.intent_digest",
                "does not match the canonical capture intent",
            ));
        }
        Ok(())
    }
}

/// Exact physical reservation anchored before a runner dispatch claim commits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureAcquiredV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Private capture layout version.
    pub layout_version: u32,
    /// Exact preallocated capture identity.
    pub capture_id: String,
    /// Full command-output source copied from the durable intent.
    pub source: CommandOutputArtifactSourceV1,
    /// Exact private-state root copied from the durable intent.
    pub private_state_digest: Digest,
    /// Exact authenticated aggregate limit copied from the durable intent.
    pub max_aggregate_output_bytes: u64,
    /// Digest of the exact durable capture intent.
    pub intent_digest: Digest,
    /// Deterministic dispatch-claim identity for the owning effect.
    pub dispatch_claim_id: String,
    /// Synchronized `Acquired` record head in the private store.
    pub store_head: CommandOutputCaptureStoreHeadV1,
    /// Exact private capture working-directory identity.
    pub working_directory: CommandOutputCaptureDirectoryIdentityV1,
    /// Exact fresh stdout file identity.
    pub stdout: CommandOutputCaptureFileIdentityV1,
    /// Exact fresh stderr file identity.
    pub stderr: CommandOutputCaptureFileIdentityV1,
    /// Time at which physical acquisition completed.
    pub acquired_at_unix_ms: u64,
    /// Domain-separated digest of every preceding canonical field.
    pub acquired_anchor_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCaptureAcquired<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    source: &'a CommandOutputArtifactSourceV1,
    private_state_digest: &'a Digest,
    max_aggregate_output_bytes: u64,
    intent_digest: &'a Digest,
    dispatch_claim_id: &'a str,
    store_head: &'a CommandOutputCaptureStoreHeadV1,
    working_directory: &'a CommandOutputCaptureDirectoryIdentityV1,
    stdout: &'a CommandOutputCaptureFileIdentityV1,
    stderr: &'a CommandOutputCaptureFileIdentityV1,
    acquired_at_unix_ms: u64,
}

impl CommandOutputCaptureAcquiredV1 {
    /// Constructs a self-authenticating acquired anchor.
    ///
    /// # Errors
    ///
    /// Returns a contract error for crossed intent metadata, invalid object
    /// identities, or canonical encoding failure.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        dispatch_claim_id: impl Into<String>,
        store_head: CommandOutputCaptureStoreHeadV1,
        working_directory: CommandOutputCaptureDirectoryIdentityV1,
        stdout: CommandOutputCaptureFileIdentityV1,
        stderr: CommandOutputCaptureFileIdentityV1,
        acquired_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        intent.validate()?;
        let dispatch_claim_id = dispatch_claim_id.into();
        let acquired_anchor_digest = compute_acquired_digest(
            intent,
            &dispatch_claim_id,
            &store_head,
            &working_directory,
            &stdout,
            &stderr,
            acquired_at_unix_ms,
        )?;
        let acquired = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            source: intent.source.clone(),
            private_state_digest: intent.private_state_digest.clone(),
            max_aggregate_output_bytes: intent.max_aggregate_output_bytes,
            intent_digest: intent.intent_digest.clone(),
            dispatch_claim_id,
            store_head,
            working_directory,
            stdout,
            stderr,
            acquired_at_unix_ms,
            acquired_anchor_digest,
        };
        acquired.validate_against(intent)?;
        Ok(acquired)
    }

    /// Validates this acquisition independently and against its exact intent.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed authority or invalid physical
    /// reservation shape.
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        self.validate()?;
        if self.acquired_at_unix_ms < intent.created_at_unix_ms {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.acquired_at_unix_ms",
                "must not precede capture intent",
            ));
        }
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.source != intent.source
            || self.private_state_digest != intent.private_state_digest
            || self.max_aggregate_output_bytes != intent.max_aggregate_output_bytes
            || self.intent_digest != intent.intent_digest
        {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1",
                "must copy the exact immutable capture intent authority",
            ));
        }
        Ok(())
    }

    /// Validates the complete self-contained acquired anchor.
    ///
    /// This check is intentionally independent of ledger state so the runner
    /// wire boundary can reject a malformed anchor before reopening private
    /// storage. [`Self::validate_against`] additionally binds it to the exact
    /// durable capture intent.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid identity, limit, object shape,
    /// deterministic dispatch claim, or canonical anchor digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_contract_and_layout(
            "command_output_capture_acquired_v1",
            self.contract_version,
            self.layout_version,
        )?;
        require_capture_id(&self.capture_id)?;
        self.source.validate()?;
        require_capture_limit(self.max_aggregate_output_bytes)?;
        self.store_head.validate()?;
        self.working_directory.validate()?;
        self.stdout.validate()?;
        self.stderr.validate()?;
        if self.dispatch_claim_id != expected_dispatch_claim_id(&self.source.effect_id) {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.dispatch_claim_id",
                "must equal the deterministic dispatch claim for the exact effect",
            ));
        }
        if self.stdout.owner_uid != self.working_directory.owner_uid
            || self.stderr.owner_uid != self.working_directory.owner_uid
        {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.owner_uid",
                "directory and both stream files must have the same owner",
            ));
        }
        if (self.stdout.device_id, self.stdout.inode) == (self.stderr.device_id, self.stderr.inode)
        {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.stream_identity",
                "stdout and stderr must be distinct files",
            ));
        }
        if self.acquired_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.acquired_at_unix_ms",
                "must be greater than zero",
            ));
        }
        let expected = compute_acquired_digest_from_fields(
            self.contract_version,
            self.layout_version,
            &self.capture_id,
            &self.source,
            &self.private_state_digest,
            self.max_aggregate_output_bytes,
            &self.intent_digest,
            &self.dispatch_claim_id,
            &self.store_head,
            &self.working_directory,
            &self.stdout,
            &self.stderr,
            self.acquired_at_unix_ms,
        )?;
        if self.acquired_anchor_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_acquired_v1.acquired_anchor_digest",
                "does not match the canonical acquired anchor",
            ));
        }
        Ok(())
    }
}

/// Closed observation class copied into a capture terminal anchor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputCaptureObservationClassV1 {
    /// The command effect succeeded.
    Succeeded,
    /// Evidence proves the command effect never began.
    FailedBeforeEffect,
    /// The command occurred and a later known failure was observed.
    FailedAfterKnownEffect,
    /// Cancellation completed before the command began.
    CancelledBeforeEffect,
    /// Command completion remains uncertain.
    Unknown,
}

impl CommandOutputCaptureObservationClassV1 {
    fn from_outcome(outcome: &EffectOutcome) -> Self {
        match outcome {
            EffectOutcome::Succeeded { .. } => Self::Succeeded,
            EffectOutcome::FailedBeforeEffect { .. } => Self::FailedBeforeEffect,
            EffectOutcome::FailedAfterKnownEffect { .. } => Self::FailedAfterKnownEffect,
            EffectOutcome::CancelledBeforeEffect { .. } => Self::CancelledBeforeEffect,
            EffectOutcome::Unknown { .. } => Self::Unknown,
        }
    }

    pub(super) const fn storage_name(self) -> &'static str {
        match self {
            Self::Succeeded => "Succeeded",
            Self::FailedBeforeEffect => "FailedBeforeEffect",
            Self::FailedAfterKnownEffect => "FailedAfterKnownEffect",
            Self::CancelledBeforeEffect => "CancelledBeforeEffect",
            Self::Unknown => "Unknown",
        }
    }
}

/// Closed durable disposition of one capture reconciliation obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputCaptureTerminalDispositionV1 {
    /// Raw streams and the terminal response record are immutable.
    Published,
    /// Exact cleanup proves the reservation was removed before a known effect.
    Abandoned,
    /// Evidence remains insufficient; this is terminal evidence, not finish.
    ReconciliationRequired,
}

impl CommandOutputCaptureTerminalDispositionV1 {
    pub(super) const fn storage_name(self) -> &'static str {
        match self {
            Self::Published => "Published",
            Self::Abandoned => "Abandoned",
            Self::ReconciliationRequired => "ReconciliationRequired",
        }
    }
}

/// Immutable terminal anchor joined atomically to one command observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureTerminalAnchorV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Private capture layout version.
    pub layout_version: u32,
    /// Exact preallocated capture identity.
    pub capture_id: String,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Exact effect observation committed in the same transaction.
    pub observation_id: String,
    /// Dispatch claim when transport was admitted; absent only before dispatch.
    pub dispatch_claim_id: Option<String>,
    /// Exact capture-intent digest.
    pub intent_digest: Digest,
    /// Acquired anchor when physical acquisition reached core.
    pub acquired_anchor_digest: Option<Digest>,
    /// Closed class copied from the effect observation.
    pub observation_class: CommandOutputCaptureObservationClassV1,
    /// Published, proven abandoned, or still reconciliation-required.
    pub disposition: CommandOutputCaptureTerminalDispositionV1,
    /// Exact synchronized terminal/cleanup/reconciliation store head.
    pub store_head: CommandOutputCaptureStoreHeadV1,
    /// Digest of the bounded terminal or cleanup record.
    pub terminal_record_digest: Digest,
    /// Complete immutable stream reference when publication succeeded.
    pub artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
    /// Time at which core anchored the terminal candidate.
    pub anchored_at_unix_ms: u64,
    /// Domain-separated digest of every preceding canonical field.
    pub terminal_anchor_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCaptureTerminal<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    dispatch_claim_id: Option<&'a str>,
    intent_digest: &'a Digest,
    acquired_anchor_digest: Option<&'a Digest>,
    observation_class: CommandOutputCaptureObservationClassV1,
    disposition: CommandOutputCaptureTerminalDispositionV1,
    store_head: &'a CommandOutputCaptureStoreHeadV1,
    terminal_record_digest: &'a Digest,
    artifact_reference: Option<&'a CommandOutputArtifactSetReferenceV1>,
    anchored_at_unix_ms: u64,
}

impl CommandOutputCaptureTerminalAnchorV1 {
    /// Constructs a canonical terminal anchor for an exact observation.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid outcome/disposition, crossed
    /// acquisition, artifact source, or timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        acquired: Option<&CommandOutputCaptureAcquiredV1>,
        observation: &EffectObservation,
        disposition: CommandOutputCaptureTerminalDispositionV1,
        store_head: CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: Digest,
        artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
        anchored_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        if let Some(acquired) = acquired {
            acquired.validate_against(intent)?;
        }
        let observation_class =
            CommandOutputCaptureObservationClassV1::from_outcome(&observation.outcome);
        let dispatch_claim_id = acquired.map(|value| value.dispatch_claim_id.clone());
        let acquired_anchor_digest = acquired.map(|value| value.acquired_anchor_digest.clone());
        let terminal_anchor_digest = compute_terminal_digest(
            intent,
            observation,
            dispatch_claim_id.as_deref(),
            acquired_anchor_digest.as_ref(),
            observation_class,
            disposition,
            &store_head,
            &terminal_record_digest,
            artifact_reference.as_ref(),
            anchored_at_unix_ms,
        )?;
        let terminal = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            observation_id: observation.observation_id.clone(),
            dispatch_claim_id,
            intent_digest: intent.intent_digest.clone(),
            acquired_anchor_digest,
            observation_class,
            disposition,
            store_head,
            terminal_record_digest,
            artifact_reference,
            anchored_at_unix_ms,
            terminal_anchor_digest,
        };
        terminal.validate_against(intent, acquired, observation)?;
        Ok(terminal)
    }

    /// Validates the terminal anchor against its exact intent, optional
    /// acquisition, and observation.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed identity, illegal terminal
    /// branch, or digest mismatch.
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: Option<&CommandOutputCaptureAcquiredV1>,
        observation: &EffectObservation,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        observation.validate()?;
        self.validate()?;
        if let Some(acquired) = acquired {
            acquired.validate_against(intent)?;
        }
        let expected_class =
            CommandOutputCaptureObservationClassV1::from_outcome(&observation.outcome);
        let expected_claim = acquired.map(|value| value.dispatch_claim_id.as_str());
        let expected_acquired = acquired.map(|value| &value.acquired_anchor_digest);
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.observation_id != observation.observation_id
            || self.dispatch_claim_id.as_deref() != expected_claim
            || self.intent_digest != intent.intent_digest
            || self.acquired_anchor_digest.as_ref() != expected_acquired
            || self.observation_class != expected_class
            || observation.effect_id != intent.source.effect_id
            || observation.sprint_id != intent.source.sprint_id
            || observation.request_digest != intent.source.request_digest
        {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1",
                "must match the exact capture, acquisition, and observation authority",
            ));
        }
        if let Some(reference) = &self.artifact_reference
            && (reference.format_version != COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION
                || reference.source != intent.source)
        {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.artifact_reference",
                "must carry the exact capture intent source",
            ));
        }
        if self.anchored_at_unix_ms < intent.created_at_unix_ms
            || self.anchored_at_unix_ms < observation.observed_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.anchored_at_unix_ms",
                "must not precede intent or observation",
            ));
        }
        let expected = compute_terminal_digest(
            intent,
            observation,
            self.dispatch_claim_id.as_deref(),
            self.acquired_anchor_digest.as_ref(),
            self.observation_class,
            self.disposition,
            &self.store_head,
            &self.terminal_record_digest,
            self.artifact_reference.as_ref(),
            self.anchored_at_unix_ms,
        )?;
        if self.terminal_anchor_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.terminal_anchor_digest",
                "does not match the canonical terminal anchor",
            ));
        }
        Ok(())
    }

    /// Validates the self-contained terminal anchor independently of ledger state.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid branch, identity, optional
    /// artifact, deterministic dispatch claim, timestamp, or canonical digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_contract_and_layout(
            "command_output_capture_terminal_anchor_v1",
            self.contract_version,
            self.layout_version,
        )?;
        require_capture_id(&self.capture_id)?;
        if self.effect_id.trim().is_empty() || self.observation_id.trim().is_empty() {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.identity",
                "effect and observation identities must be nonblank",
            ));
        }
        self.store_head.validate()?;
        if let Some(dispatch_claim_id) = &self.dispatch_claim_id
            && dispatch_claim_id != &expected_dispatch_claim_id(&self.effect_id)
        {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.dispatch_claim_id",
                "must equal the deterministic claim for the exact effect",
            ));
        }
        let terminal_branch_valid = match (self.observation_class, self.disposition) {
            (
                CommandOutputCaptureObservationClassV1::Succeeded
                | CommandOutputCaptureObservationClassV1::FailedAfterKnownEffect,
                CommandOutputCaptureTerminalDispositionV1::Published,
            ) => {
                self.dispatch_claim_id.is_some()
                    && self.acquired_anchor_digest.is_some()
                    && self.artifact_reference.is_some()
            }
            (
                CommandOutputCaptureObservationClassV1::FailedBeforeEffect
                | CommandOutputCaptureObservationClassV1::CancelledBeforeEffect,
                CommandOutputCaptureTerminalDispositionV1::Abandoned,
            ) => self.artifact_reference.is_none(),
            (
                CommandOutputCaptureObservationClassV1::Unknown,
                CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
            ) => {
                self.dispatch_claim_id.is_some()
                    && self.acquired_anchor_digest.is_some()
                    && self.artifact_reference.is_none()
            }
            _ => false,
        };
        if !terminal_branch_valid {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.disposition",
                "does not match the closed observation and artifact branch",
            ));
        }
        if let Some(reference) = &self.artifact_reference {
            reference.validate()?;
            if reference.source.effect_id != self.effect_id {
                return Err(ContractError::new(
                    "command_output_capture_terminal_anchor_v1.artifact_reference",
                    "must carry the exact terminal effect",
                ));
            }
        }
        if self.anchored_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.anchored_at_unix_ms",
                "must be greater than zero",
            ));
        }
        let expected = compute_terminal_digest_from_fields(
            self.contract_version,
            self.layout_version,
            &self.capture_id,
            &self.effect_id,
            &self.observation_id,
            self.dispatch_claim_id.as_deref(),
            &self.intent_digest,
            self.acquired_anchor_digest.as_ref(),
            self.observation_class,
            self.disposition,
            &self.store_head,
            &self.terminal_record_digest,
            self.artifact_reference.as_ref(),
            self.anchored_at_unix_ms,
        )?;
        if self.terminal_anchor_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_terminal_anchor_v1.terminal_anchor_digest",
                "does not match the canonical terminal anchor",
            ));
        }
        Ok(())
    }
}

/// Complete durable command-output capture lifecycle loaded by exact ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCommandOutputCapture {
    /// Immutable core-side pre-effect intent.
    pub intent: CommandOutputCaptureIntentV1,
    /// Immutable physical acquisition, when dispatch became eligible.
    pub acquired: Option<CommandOutputCaptureAcquiredV1>,
    /// Immutable terminal anchor, when the capture obligation was closed or
    /// explicitly retained for reconciliation.
    pub terminal: Option<CommandOutputCaptureTerminalAnchorV1>,
    /// Monotonic resolution of an immutable `Unknown` terminal, when later
    /// fenced cleanup/storage reconciliation closed the obligation.
    pub reconciliation_resolution: Option<CommandOutputCaptureReconciliationResolutionV1>,
    /// Deterministic reconciliation lease identity.
    pub reconciliation_obligation_id: String,
    /// Exact terminal anchor digest that released the lease, when known.
    pub reconciliation_obligation_closure: Option<Digest>,
}

/// Restart classification that never recreates execution authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutputCaptureRecovery {
    /// Intent is durable but no acquired anchor exists; reconcile the exact
    /// capture ID before deciding whether cleanup is required.
    ExistingIntent(PersistedCommandOutputCapture),
    /// Acquisition or an unresolved terminal candidate exists; execution and
    /// redispatch are forbidden.
    ReconciliationRequired(PersistedCommandOutputCapture),
    /// One immutable terminal anchor and reconciliation release are exact.
    Terminal(PersistedCommandOutputCapture),
    /// Streaming detection rejected the output before any persistent or wire
    /// output sink and the additive v29 cleanup/closure chain is exact.
    SensitiveOutputRejected {
        /// Exact schema-v27 capture intent and physical acquisition to which
        /// the rejection is bound.
        capture: PersistedCommandOutputCapture,
        /// Exact additive schema-v29 rejection, cleanup, and closure proof.
        rejection:
            Box<super::sensitive_output_rejection::PersistedCommandOutputSensitiveRejectionV1>,
    },
}

/// Result of atomically admitting one new-current `RunCommand` capture intent.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Fresh owns the non-boxed one-use permit; callers destructure this admission exactly once.
pub enum CommandOutputCaptureIntentAdmission {
    /// This call committed and exactly read back a new effect and capture.
    Fresh {
        /// Exact newly committed effect.
        effect: PersistedEffect,
        /// Exact persisted capture lifecycle (intent-only at this boundary).
        capture: PersistedCommandOutputCapture,
        /// Move-only authority that can accept one typed acquisition.
        permit: FreshRunnerEffectDispatchPermit,
    },
    /// Exact intent-only replay; no execution authority is reminted.
    Existing {
        /// Exact durable effect.
        effect: PersistedEffect,
        /// Exact intent-only capture.
        capture: PersistedCommandOutputCapture,
    },
    /// Acquisition, claim, observation, terminal candidate, or unresolved
    /// ownership exists; only reconciliation may proceed.
    ReconciliationRequired {
        /// Exact durable effect.
        effect: PersistedEffect,
        /// Complete current capture lifecycle.
        capture: PersistedCommandOutputCapture,
    },
}

/// Immutable, bounded single-owner restart-reconciliation claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureReconciliationClaimV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Caller-preallocated unique claim identity (64 lowercase hex).
    pub claim_id: String,
    /// Exact capture being reconciled.
    pub capture_id: String,
    /// Stable bounded coordinator/recovery-owner identity.
    pub owner_id: String,
    /// Monotonic per-capture fencing epoch, starting at one.
    pub claim_epoch: u64,
    /// Prior claim identity for every epoch after one.
    pub previous_claim_id: Option<String>,
    /// Domain-separated token presented by the move-only claimant.
    pub fencing_token: Digest,
    /// Time at which ownership was acquired.
    pub acquired_at_unix_ms: u64,
    /// Exclusive expiry of this claim.
    pub expires_at_unix_ms: u64,
    /// Canonical digest of every preceding field.
    pub claim_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalReconciliationClaim<'a> {
    contract_version: u32,
    claim_id: &'a str,
    capture_id: &'a str,
    owner_id: &'a str,
    claim_epoch: u64,
    previous_claim_id: Option<&'a str>,
    fencing_token: &'a Digest,
    acquired_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl CommandOutputCaptureReconciliationClaimV1 {
    fn try_new(
        claim_id: impl Into<String>,
        capture_id: impl Into<String>,
        owner_id: impl Into<String>,
        claim_epoch: u64,
        previous_claim_id: Option<String>,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let claim_id = claim_id.into();
        let capture_id = capture_id.into();
        let owner_id = owner_id.into();
        let fencing_token =
            reconciliation_fencing_token(&capture_id, claim_epoch, &claim_id, &owner_id);
        let claim_digest = compute_reconciliation_claim_digest(
            CONTRACT_VERSION,
            &claim_id,
            &capture_id,
            &owner_id,
            claim_epoch,
            previous_claim_id.as_deref(),
            &fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let claim = Self {
            contract_version: CONTRACT_VERSION,
            claim_id,
            capture_id,
            owner_id,
            claim_epoch,
            previous_claim_id,
            fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
            claim_digest,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Validates identity, epoch, bounded expiry, fencing token, and digest.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid or crossed claim.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_capture_id(&self.claim_id)?;
        require_capture_id(&self.capture_id)?;
        if self.owner_id.trim().is_empty() || self.owner_id.len() > 256 {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.owner_id",
                "must contain 1..=256 UTF-8 bytes",
            ));
        }
        if self.claim_epoch == 0 {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.claim_epoch",
                "must be greater than zero",
            ));
        }
        if (self.claim_epoch == 1) != self.previous_claim_id.is_none() {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.previous_claim_id",
                "must be absent exactly at epoch one",
            ));
        }
        if let Some(previous) = &self.previous_claim_id {
            require_capture_id(previous)?;
            if previous == &self.claim_id {
                return Err(ContractError::new(
                    "command_output_capture_reconciliation_claim_v1.previous_claim_id",
                    "must differ from claim_id",
                ));
            }
        }
        let ttl = self
            .expires_at_unix_ms
            .checked_sub(self.acquired_at_unix_ms)
            .ok_or_else(|| {
                ContractError::new(
                    "command_output_capture_reconciliation_claim_v1.expires_at_unix_ms",
                    "must follow acquisition",
                )
            })?;
        if self.acquired_at_unix_ms == 0
            || ttl == 0
            || ttl > MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.expires_at_unix_ms",
                format!(
                    "must be 1..={MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS}ms after acquisition"
                ),
            ));
        }
        let fencing_token = reconciliation_fencing_token(
            &self.capture_id,
            self.claim_epoch,
            &self.claim_id,
            &self.owner_id,
        );
        if self.fencing_token != fencing_token {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.fencing_token",
                "does not match the canonical capture, epoch, claim, and owner",
            ));
        }
        let expected = compute_reconciliation_claim_digest(
            self.contract_version,
            &self.claim_id,
            &self.capture_id,
            &self.owner_id,
            self.claim_epoch,
            self.previous_claim_id.as_deref(),
            &self.fencing_token,
            self.acquired_at_unix_ms,
            self.expires_at_unix_ms,
        )?;
        if self.claim_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_claim_v1.claim_digest",
                "does not match the canonical reconciliation claim",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn reconciliation_claim_for_test(
    claim_id: &str,
    capture_id: &str,
    owner_id: &str,
    claim_epoch: u64,
    previous_claim_id: Option<String>,
    acquired_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<CommandOutputCaptureReconciliationClaimV1, ContractError> {
    CommandOutputCaptureReconciliationClaimV1::try_new(
        claim_id,
        capture_id,
        owner_id,
        claim_epoch,
        previous_claim_id,
        acquired_at_unix_ms,
        expires_at_unix_ms,
    )
}

/// Exact physical journal state observed by a fenced restart owner.
///
/// The names intentionally match the runner journal's v1 state machine. Core
/// keeps its own contract so the dependency remains one-way (`runner -> core`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputCaptureRestartStateV1 {
    /// Only the immutable physical intent exists.
    Intent,
    /// Empty output objects were reserved.
    Acquired,
    /// A runner attached to the reserved output objects.
    WriterAttached,
    /// Native launch intent crossed the durable journal boundary.
    LaunchIntended,
    /// Both output streams reached a synchronized terminal record.
    Finished,
    /// Immutable output artifacts were published.
    Published,
    /// Exact terminal response bytes were retained.
    TerminalPrepared,
    /// Cleanup intent crossed the durable journal boundary.
    CleanupIntended,
    /// Held-descriptor unlink proof reached the durable journal.
    Cleaned,
}

impl CommandOutputCaptureRestartStateV1 {
    pub(super) const fn storage_name(self) -> &'static str {
        match self {
            Self::Intent => "Intent",
            Self::Acquired => "Acquired",
            Self::WriterAttached => "WriterAttached",
            Self::LaunchIntended => "LaunchIntended",
            Self::Finished => "Finished",
            Self::Published => "Published",
            Self::TerminalPrepared => "TerminalPrepared",
            Self::CleanupIntended => "CleanupIntended",
            Self::Cleaned => "Cleaned",
        }
    }

    const fn is_at_or_after_launch(self) -> bool {
        matches!(
            self,
            Self::LaunchIntended
                | Self::Finished
                | Self::Published
                | Self::TerminalPrepared
                | Self::CleanupIntended
                | Self::Cleaned
        )
    }
}

/// Exact canonical native-launch bytes retained by the physical journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureRestartLaunchEvidenceV1 {
    /// Bounded ASCII schema that uniquely defines the canonical bytes.
    pub schema: String,
    /// Exact canonical native-launch binding bytes.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 commitment to `canonical_bytes`.
    pub canonical_bytes_digest: Digest,
    /// Exact immutable `LaunchIntended` journal head.
    pub store_head: CommandOutputCaptureStoreHeadV1,
}

impl CommandOutputCaptureRestartLaunchEvidenceV1 {
    /// Constructs exact launch evidence without interpreting runner-owned bytes.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid schema, empty/oversized bytes,
    /// or invalid journal head.
    pub fn try_new(
        schema: impl Into<String>,
        canonical_bytes: Vec<u8>,
        store_head: CommandOutputCaptureStoreHeadV1,
    ) -> Result<Self, ContractError> {
        let evidence = Self {
            schema: schema.into(),
            canonical_bytes_digest: Digest::sha256(&canonical_bytes),
            canonical_bytes,
            store_head,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Validates exact bounded launch bytes and their immutable journal head.
    ///
    /// # Errors
    ///
    /// Returns a contract error for a noncanonical schema, bytes, digest, or
    /// store head.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema.is_empty()
            || self.schema.len() > 128
            || !self.schema.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
            })
        {
            return Err(ContractError::new(
                "command_output_capture_restart_launch_evidence_v1.schema",
                "must be a 1..=128-byte ASCII schema token",
            ));
        }
        if self.canonical_bytes.is_empty()
            || self.canonical_bytes.len() > MAX_COMMAND_OUTPUT_CAPTURE_RESTART_LAUNCH_BINDING_BYTES
        {
            return Err(ContractError::new(
                "command_output_capture_restart_launch_evidence_v1.canonical_bytes",
                format!(
                    "must contain 1..={MAX_COMMAND_OUTPUT_CAPTURE_RESTART_LAUNCH_BINDING_BYTES} bytes"
                ),
            ));
        }
        if self.canonical_bytes_digest != Digest::sha256(&self.canonical_bytes) {
            return Err(ContractError::new(
                "command_output_capture_restart_launch_evidence_v1.canonical_bytes_digest",
                "must equal SHA-256 of the exact canonical bytes",
            ));
        }
        self.store_head.validate()
    }
}

/// One state/head pair in the exact validated physical journal history.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCapturePhysicalHistoryEntryV1 {
    /// State represented by this immutable record.
    pub state: CommandOutputCaptureRestartStateV1,
    /// Exact one-based record generation and chained digest.
    pub store_head: CommandOutputCaptureStoreHeadV1,
}

/// Exact action taken for an interrupted journal-record publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandOutputCapturePendingResolutionV1 {
    /// No pending record existed at the fenced cut.
    None,
    /// A complete canonical successor was durably rolled forward.
    RolledForward {
        /// One-based successor generation.
        sequence: u64,
        /// Exact successor state.
        state: CommandOutputCaptureRestartStateV1,
        /// Exact successor record digest.
        record_digest: Digest,
    },
    /// Torn/noncanonical temporary bytes were removed under the fence.
    RemovedTorn {
        /// One-based candidate generation encoded by the deterministic name.
        sequence: u64,
        /// Digest of the exact deterministic temporary name that was removed.
        name_digest: Digest,
    },
}

/// Exact namespace action performed under the physical recovery fence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandOutputCapturePhysicalResolutionActionV1 {
    /// An absent journal became `Intent -> CleanupIntended -> Cleaned`.
    IntentTombstoned,
    /// An existing Intent-only journal was cleaned before acquisition.
    PreAcquisitionCleaned,
    /// An exact acquired working set was cleaned with unlink proof.
    WorkingSetCleaned,
    /// Finished stream commitments were recovered into immutable publication.
    FinishedPublicationRecovered,
    /// A complete pending `TerminalPrepared` successor was rolled forward.
    TerminalPreparedRecovered,
    /// An already-terminal physical state was exactly read back.
    TerminalReadback,
}

impl CommandOutputCapturePhysicalResolutionActionV1 {
    pub(super) const fn storage_name(self) -> &'static str {
        match self {
            Self::IntentTombstoned => "IntentTombstoned",
            Self::PreAcquisitionCleaned => "PreAcquisitionCleaned",
            Self::WorkingSetCleaned => "WorkingSetCleaned",
            Self::FinishedPublicationRecovered => "FinishedPublicationRecovered",
            Self::TerminalPreparedRecovered => "TerminalPreparedRecovered",
            Self::TerminalReadback => "TerminalReadback",
        }
    }
}

/// Explicit launch-history classification retained even after cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "classification", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandOutputCaptureLaunchHistoryV1 {
    /// The validated lifecycle never crossed `LaunchIntended`.
    NoneBeforeLaunch,
    /// Exact launch bytes and the historical `LaunchIntended` head.
    ExactLaunchEvidence {
        /// Exact bounded native-launch evidence.
        evidence: CommandOutputCaptureRestartLaunchEvidenceV1,
    },
}

impl CommandOutputCaptureLaunchHistoryV1 {
    pub(super) const fn evidence(&self) -> Option<&CommandOutputCaptureRestartLaunchEvidenceV1> {
        match self {
            Self::NoneBeforeLaunch => None,
            Self::ExactLaunchEvidence { evidence } => Some(evidence),
        }
    }
}

/// Digest-only anchor for exact retained terminal response bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCapturePhysicalTerminalEvidenceV1 {
    /// Bounded ASCII schema that uniquely defines the terminal bytes.
    pub schema: String,
    /// Digest of the exact retained canonical terminal bytes.
    pub canonical_bytes_digest: Digest,
    /// Exact immutable `TerminalPrepared` journal head.
    pub store_head: CommandOutputCaptureStoreHeadV1,
}

impl CommandOutputCapturePhysicalTerminalEvidenceV1 {
    /// Validates a bounded schema and exact terminal journal head.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid schema or head.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema.is_empty()
            || self.schema.len() > 128
            || !self.schema.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
            })
        {
            return Err(ContractError::new(
                "command_output_capture_physical_terminal_evidence_v1.schema",
                "must be a 1..=128-byte ASCII schema token",
            ));
        }
        self.store_head.validate()
    }
}

/// Canonical core-side evidence for one physical restart reconciliation.
///
/// This is deliberately a core contract rather than a runner type: runner
/// depends on core already. A fixed runner can construct it only after holding
/// the exact physical fence, resolving pending publications, validating the
/// full lifecycle chain and physical objects, and reading back the final cut.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCapturePhysicalReconciliationV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Private capture layout version.
    pub layout_version: u32,
    /// Exact caller-preallocated capture identity.
    pub capture_id: String,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Exact immutable capture-intent digest.
    pub intent_digest: Digest,
    /// Full exact core claim persisted in the physical recovery fence.
    pub reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    /// Prior physical fence digest, when any.
    pub predecessor_fence_digest: Option<Digest>,
    /// Number of immutable fences in the validated physical fence chain.
    pub physical_fence_chain_length: u64,
    /// Digest of the exact runner recovery-fence preimage.
    pub physical_fence_digest: Digest,
    /// Exact head requested by core, absent only for the unacquired branch.
    pub requested_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    /// State before pending-record resolution/recovery mutation; absent only
    /// when no physical journal existed at the claimed cut.
    pub initial_state: Option<CommandOutputCaptureRestartStateV1>,
    /// Exact initial journal head, paired with `initial_state`.
    pub initial_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    /// Exact action applied to a pending record under the same fence.
    pub pending_resolution: CommandOutputCapturePendingResolutionV1,
    /// High-level recovery action applied after initial classification.
    pub resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
    /// Complete ordered state/head history at final readback.
    pub lifecycle_history: Vec<CommandOutputCapturePhysicalHistoryEntryV1>,
    /// Domain-separated digest of `lifecycle_history`.
    pub lifecycle_history_digest: Digest,
    /// Exact final durable state.
    pub final_state: CommandOutputCaptureRestartStateV1,
    /// Exact final chained journal head.
    pub final_store_head: CommandOutputCaptureStoreHeadV1,
    /// Complete physical Acquired anchor retained by the runner, even when core
    /// never committed the corresponding acquisition.
    pub physical_acquired: Option<CommandOutputCaptureAcquiredV1>,
    /// Digest of the exact immutable physical Acquired journal record.
    pub physical_acquired_record_digest: Option<Digest>,
    /// Explicit pre-launch versus exact-launch history classification.
    pub launch_history: CommandOutputCaptureLaunchHistoryV1,
    /// Exact immutable Finished head, when any.
    pub finished_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    /// Exact immutable Published head, when any.
    pub published_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    /// Complete published artifact reference, when any.
    pub artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
    /// Exact retained terminal payload digest/head, when any.
    pub terminal_prepared: Option<CommandOutputCapturePhysicalTerminalEvidenceV1>,
    /// Exact immutable Cleaned head, when any.
    pub cleaned_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    /// Digest of the exact descriptor-based cleanup completion proof, when any.
    pub cleanup_completion_proof_digest: Option<Digest>,
    /// Time at which the fenced final cut became durable and was read back.
    pub reconciled_at_unix_ms: u64,
    /// Domain-separated digest of every preceding field.
    pub reconciliation_digest: Digest,
}

/// Compatibility name retained for the schema table and early callers.
pub type CommandOutputCaptureRestartRecoveryReceiptV1 =
    CommandOutputCapturePhysicalReconciliationV1;

#[derive(Serialize)]
struct CanonicalCapturePhysicalReconciliation<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    effect_id: &'a str,
    intent_digest: &'a Digest,
    reconciliation_claim: &'a CommandOutputCaptureReconciliationClaimV1,
    predecessor_fence_digest: Option<&'a Digest>,
    physical_fence_chain_length: u64,
    physical_fence_digest: &'a Digest,
    requested_store_head: Option<&'a CommandOutputCaptureStoreHeadV1>,
    initial_state: Option<CommandOutputCaptureRestartStateV1>,
    initial_store_head: Option<&'a CommandOutputCaptureStoreHeadV1>,
    pending_resolution: &'a CommandOutputCapturePendingResolutionV1,
    resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
    lifecycle_history: &'a [CommandOutputCapturePhysicalHistoryEntryV1],
    lifecycle_history_digest: &'a Digest,
    final_state: CommandOutputCaptureRestartStateV1,
    final_store_head: &'a CommandOutputCaptureStoreHeadV1,
    physical_acquired: Option<&'a CommandOutputCaptureAcquiredV1>,
    physical_acquired_record_digest: Option<&'a Digest>,
    launch_history: &'a CommandOutputCaptureLaunchHistoryV1,
    finished_store_head: Option<&'a CommandOutputCaptureStoreHeadV1>,
    published_store_head: Option<&'a CommandOutputCaptureStoreHeadV1>,
    artifact_reference: Option<&'a CommandOutputArtifactSetReferenceV1>,
    terminal_prepared: Option<&'a CommandOutputCapturePhysicalTerminalEvidenceV1>,
    cleaned_store_head: Option<&'a CommandOutputCaptureStoreHeadV1>,
    cleanup_completion_proof_digest: Option<&'a Digest>,
    reconciled_at_unix_ms: u64,
}

impl CommandOutputCapturePhysicalReconciliationV1 {
    /// Returns the exact canonical bytes retained as effect evidence.
    ///
    /// # Errors
    ///
    /// Returns a contract error if canonical serialization fails.
    pub fn canonical_evidence_bytes(&self) -> Result<Vec<u8>, ContractError> {
        serde_json::to_vec(self).map_err(|error| {
            ContractError::new(
                "command_output_capture_physical_reconciliation_v1",
                format!("cannot encode canonical evidence bytes: {error}"),
            )
        })
    }

    /// SHA-256 digest used by the exact effect observation evidence boundary.
    ///
    /// # Errors
    ///
    /// Returns a contract error if canonical serialization fails.
    pub fn effect_evidence_digest(&self) -> Result<Digest, ContractError> {
        Ok(Digest::sha256(&self.canonical_evidence_bytes()?))
    }

    /// Constructs exact physical reconciliation evidence.
    ///
    /// # Errors
    ///
    /// Returns a contract error for crossed authority, a malformed fence,
    /// non-monotonic history, inconsistent historical anchors, or a cut outside
    /// the live core claim.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        predecessor_fence_digest: Option<Digest>,
        physical_fence_chain_length: u64,
        requested_store_head: Option<CommandOutputCaptureStoreHeadV1>,
        initial_state: Option<CommandOutputCaptureRestartStateV1>,
        initial_store_head: Option<CommandOutputCaptureStoreHeadV1>,
        pending_resolution: CommandOutputCapturePendingResolutionV1,
        resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
        lifecycle_history: Vec<CommandOutputCapturePhysicalHistoryEntryV1>,
        physical_acquired: Option<CommandOutputCaptureAcquiredV1>,
        launch_history: CommandOutputCaptureLaunchHistoryV1,
        artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
        terminal_prepared: Option<CommandOutputCapturePhysicalTerminalEvidenceV1>,
        cleanup_completion_proof_digest: Option<Digest>,
        reconciled_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let final_entry = lifecycle_history.last().ok_or_else(|| {
            ContractError::new(
                "command_output_capture_physical_reconciliation_v1.lifecycle_history",
                "must contain at least the immutable Intent record",
            )
        })?;
        let final_state = final_entry.state;
        let final_store_head = final_entry.store_head.clone();
        let lifecycle_history_digest = compute_physical_history_digest(&lifecycle_history)?;
        let physical_fence_digest = compute_physical_fence_digest(
            &intent.capture_id,
            predecessor_fence_digest.as_ref(),
            claim,
        )?;
        let physical_acquired_record_digest = physical_acquired
            .as_ref()
            .map(|value| value.store_head.record_digest.clone());
        let finished_store_head = lifecycle_history
            .iter()
            .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::Finished)
            .map(|entry| entry.store_head.clone());
        let published_store_head = lifecycle_history
            .iter()
            .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::Published)
            .map(|entry| entry.store_head.clone());
        let cleaned_store_head = lifecycle_history
            .iter()
            .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::Cleaned)
            .map(|entry| entry.store_head.clone());
        let reconciliation_digest = compute_physical_reconciliation_digest(
            intent.contract_version,
            intent.layout_version,
            &intent.capture_id,
            &intent.source.effect_id,
            &intent.intent_digest,
            claim,
            predecessor_fence_digest.as_ref(),
            physical_fence_chain_length,
            &physical_fence_digest,
            requested_store_head.as_ref(),
            initial_state,
            initial_store_head.as_ref(),
            &pending_resolution,
            resolution_action,
            &lifecycle_history,
            &lifecycle_history_digest,
            final_state,
            &final_store_head,
            physical_acquired.as_ref(),
            physical_acquired_record_digest.as_ref(),
            &launch_history,
            finished_store_head.as_ref(),
            published_store_head.as_ref(),
            artifact_reference.as_ref(),
            terminal_prepared.as_ref(),
            cleaned_store_head.as_ref(),
            cleanup_completion_proof_digest.as_ref(),
            reconciled_at_unix_ms,
        )?;
        let evidence = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            intent_digest: intent.intent_digest.clone(),
            reconciliation_claim: claim.clone(),
            predecessor_fence_digest,
            physical_fence_chain_length,
            physical_fence_digest,
            requested_store_head,
            initial_state,
            initial_store_head,
            pending_resolution,
            resolution_action,
            lifecycle_history,
            lifecycle_history_digest,
            final_state,
            final_store_head,
            physical_acquired,
            physical_acquired_record_digest,
            launch_history,
            finished_store_head,
            published_store_head,
            artifact_reference,
            terminal_prepared,
            cleaned_store_head,
            cleanup_completion_proof_digest,
            reconciled_at_unix_ms,
            reconciliation_digest,
        };
        evidence.validate_against(intent, claim, None)?;
        Ok(evidence)
    }

    /// Validates physical evidence against exact durable core authority.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed intent, claim, acquisition, or
    /// artifact source and for a timestamp outside the live claim.
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        acquired: Option<&CommandOutputCaptureAcquiredV1>,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        claim.validate()?;
        if let Some(acquired) = acquired {
            acquired.validate_against(intent)?;
        }
        self.validate()?;
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.intent_digest != intent.intent_digest
            || self.reconciliation_claim != *claim
            || claim.capture_id != intent.capture_id
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1",
                "must bind the exact intent, claim fence, and optional acquisition",
            ));
        }
        if let Some(core_acquired) = acquired
            && self.physical_acquired.as_ref() != Some(core_acquired)
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.physical_acquired",
                "must equal the exact durable core acquisition when core has one",
            ));
        }
        if let Some(core_acquired) = acquired
            && self.requested_store_head.as_ref() != Some(&core_acquired.store_head)
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.requested_store_head",
                "a core-acquired restart must request the exact durable acquisition head",
            ));
        }
        if self.reconciled_at_unix_ms < claim.acquired_at_unix_ms
            || self.reconciled_at_unix_ms >= claim.expires_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.reconciled_at_unix_ms",
                "must fall within the exact live reconciliation-claim interval",
            ));
        }
        let acquired_history = self
            .lifecycle_history
            .iter()
            .find(|entry| entry.state == CommandOutputCaptureRestartStateV1::Acquired);
        match self.physical_acquired.as_ref() {
            Some(physical_acquired)
                if acquired_history.map(|entry| &entry.store_head)
                    == Some(&physical_acquired.store_head) =>
            {
                physical_acquired.validate_against(intent)?;
            }
            None if acquired_history.is_none()
                && !self.lifecycle_history.iter().any(|entry| {
                    matches!(
                        entry.state,
                        CommandOutputCaptureRestartStateV1::WriterAttached
                            | CommandOutputCaptureRestartStateV1::LaunchIntended
                            | CommandOutputCaptureRestartStateV1::Finished
                            | CommandOutputCaptureRestartStateV1::Published
                            | CommandOutputCaptureRestartStateV1::TerminalPrepared
                    )
                }) => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.acquired_anchor_digest",
                    "physical acquisition must match the exact Acquired history head",
                ));
            }
        }
        if let Some(reference) = self.artifact_reference.as_ref()
            && reference.source != intent.source
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.artifact_reference",
                "must carry the exact immutable capture source",
            ));
        }
        Ok(())
    }

    /// Validates a new fenced physical cut that resolves an immutable Unknown terminal.
    ///
    /// Unlike initial restart validation, the requested head is the exact
    /// Unknown terminal head rather than the original Acquired head.
    ///
    /// # Errors
    ///
    /// Returns a contract error for crossed intent, acquisition, terminal,
    /// claim, initial/final head, disposition, artifacts, or completion proof.
    pub fn validate_for_unknown_resolution(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        resolution: &CommandOutputCaptureReconciliationResolutionV1,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        acquired.validate_against(intent)?;
        terminal.validate()?;
        claim.validate()?;
        resolution.validate_against(intent, terminal, claim)?;
        self.validate()?;
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.intent_digest != intent.intent_digest
            || self.reconciliation_claim != *claim
            || self.physical_acquired.as_ref() != Some(acquired)
            || terminal.capture_id != intent.capture_id
            || terminal.effect_id != intent.source.effect_id
            || terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
            || terminal.disposition
                != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
            || resolution.capture_id != intent.capture_id
            || resolution.effect_id != intent.source.effect_id
            || resolution.observation_id != terminal.observation_id
            || resolution.terminal_anchor_digest != terminal.terminal_anchor_digest
            || resolution.reconciliation_claim_id != claim.claim_id
            || resolution.reconciliation_fencing_token != claim.fencing_token
            || self
                .artifact_reference
                .as_ref()
                .is_some_and(|reference| reference.source != intent.source)
            || resolution
                .artifact_reference
                .as_ref()
                .is_some_and(|reference| reference.source != intent.source)
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.unknown_resolution",
                "must bind the exact intent, acquisition, Unknown terminal, claim, and resolution",
            ));
        }
        if self.requested_store_head.as_ref() != Some(&terminal.store_head)
            || self.initial_store_head.as_ref().is_none_or(|initial| {
                initial.generation < terminal.store_head.generation
                    || initial.generation > self.final_store_head.generation
            })
            || self.final_store_head != resolution.store_head
            || self.final_store_head.generation <= terminal.store_head.generation
            || self.final_store_head.record_digest != resolution.resolution_record_digest
            || self.reconciled_at_unix_ms != resolution.resolved_at_unix_ms
            || self.reconciled_at_unix_ms < claim.acquired_at_unix_ms
            || self.reconciled_at_unix_ms >= claim.expires_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.unknown_resolution",
                "must retain the requested Unknown head, exact current initial cut, and advancing resolution head and time",
            ));
        }
        let exact_branch = match self.final_state {
            CommandOutputCaptureRestartStateV1::Cleaned => {
                resolution.disposition == CommandOutputCaptureTerminalDispositionV1::Abandoned
                    && resolution.artifact_reference.is_none()
                    && self.artifact_reference.is_none()
                    && self.cleaned_store_head.as_ref() == Some(&self.final_store_head)
                    && self.cleanup_completion_proof_digest.is_some()
            }
            CommandOutputCaptureRestartStateV1::Published => {
                resolution.disposition == CommandOutputCaptureTerminalDispositionV1::Published
                    && resolution.artifact_reference.as_ref() == self.artifact_reference.as_ref()
                    && self.artifact_reference.is_some()
                    && self.terminal_prepared.is_none()
            }
            CommandOutputCaptureRestartStateV1::TerminalPrepared => {
                resolution.disposition == CommandOutputCaptureTerminalDispositionV1::Published
                    && resolution.artifact_reference.as_ref() == self.artifact_reference.as_ref()
                    && self.artifact_reference.is_some()
                    && self
                        .terminal_prepared
                        .as_ref()
                        .is_some_and(|terminal| terminal.store_head == self.final_store_head)
            }
            _ => false,
        };
        if !exact_branch {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.unknown_resolution",
                "requires exact Cleaned abandonment or Published/TerminalPrepared artifact publication",
            ));
        }
        Ok(())
    }

    /// Validates the complete self-contained physical reconciliation envelope.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid fencing, non-monotonic lifecycle
    /// history, crossed anchors/actions, invalid timestamp, or canonical digest.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_contract_and_layout(
            "command_output_capture_physical_reconciliation_v1",
            self.contract_version,
            self.layout_version,
        )?;
        require_capture_id(&self.capture_id)?;
        if self.effect_id.trim().is_empty() {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.effect_id",
                "must be nonblank",
            ));
        }
        self.reconciliation_claim.validate()?;
        if self.reconciliation_claim.capture_id != self.capture_id {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.reconciliation_claim",
                "must target the exact physical capture",
            ));
        }
        let expected_fence = compute_physical_fence_digest(
            &self.capture_id,
            self.predecessor_fence_digest.as_ref(),
            &self.reconciliation_claim,
        )?;
        if self.physical_fence_digest != expected_fence {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.physical_fence_digest",
                "does not match the exact runner recovery-fence preimage",
            ));
        }
        if self.physical_fence_chain_length == 0
            || (self.physical_fence_chain_length == 1) != self.predecessor_fence_digest.is_none()
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.physical_fence_chain_length",
                "must be nonzero and have no predecessor exactly at physical fence one",
            ));
        }
        if let Some(requested) = self.requested_store_head.as_ref() {
            requested.validate()?;
        }
        if self.lifecycle_history.is_empty() || self.lifecycle_history.len() > 8 {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.lifecycle_history",
                "must contain 1..=8 immutable record heads",
            ));
        }
        for (index, entry) in self.lifecycle_history.iter().enumerate() {
            entry.store_head.validate()?;
            let expected_generation = u64::try_from(index + 1).map_err(|_| {
                ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.lifecycle_history",
                    "history generation does not fit u64",
                )
            })?;
            if entry.store_head.generation != expected_generation
                || (index == 0 && entry.state != CommandOutputCaptureRestartStateV1::Intent)
                || (index > 0
                    && !valid_physical_history_transition(
                        self.lifecycle_history[index - 1].state,
                        entry.state,
                    ))
            {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.lifecycle_history",
                    "must be a contiguous valid v1 state transition chain from Intent",
                ));
            }
        }
        let final_entry = self.lifecycle_history.last().ok_or_else(|| {
            ContractError::new(
                "command_output_capture_physical_reconciliation_v1.lifecycle_history",
                "must contain at least the immutable Intent record",
            )
        })?;
        if self.final_state != final_entry.state
            || self.final_store_head != final_entry.store_head
            || self.lifecycle_history_digest
                != compute_physical_history_digest(&self.lifecycle_history)?
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.final_store_head",
                "must equal the final exact history entry and history digest",
            ));
        }
        match (&self.initial_state, &self.initial_store_head) {
            (None, None)
                if matches!(
                    self.resolution_action,
                    CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
                        | CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
                ) => {}
            (Some(state), Some(head))
                if self
                    .lifecycle_history
                    .iter()
                    .any(|entry| entry.state == *state && entry.store_head == *head)
                    && self.resolution_action
                        != CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.initial_store_head",
                    "initial classification/head must be paired and match the selected recovery action",
                ));
            }
        }
        match &self.pending_resolution {
            CommandOutputCapturePendingResolutionV1::None => {}
            CommandOutputCapturePendingResolutionV1::RolledForward {
                sequence,
                state,
                record_digest,
            } if self.lifecycle_history.iter().any(|entry| {
                entry.store_head.generation == *sequence
                    && entry.state == *state
                    && entry.store_head.record_digest == *record_digest
            }) => {}
            CommandOutputCapturePendingResolutionV1::RemovedTorn { sequence, .. }
                if *sequence >= 1 && *sequence <= 9 => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.pending_resolution",
                    "must bind the exact rolled-forward successor or bounded removed candidate",
                ));
            }
        }
        let state_head = |state| {
            self.lifecycle_history
                .iter()
                .find(|entry| entry.state == state)
                .map(|entry| &entry.store_head)
        };
        match self.physical_acquired.as_ref() {
            Some(acquired)
                if self.physical_acquired_record_digest.as_ref()
                    == Some(&acquired.store_head.record_digest) =>
            {
                acquired.validate()?;
            }
            None if self.physical_acquired_record_digest.is_none() => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.physical_acquired_record_digest",
                    "must bind the exact physical Acquired anchor and record head",
                ));
            }
        }
        match self.launch_history.evidence() {
            Some(launch)
                if state_head(CommandOutputCaptureRestartStateV1::LaunchIntended)
                    == Some(&launch.store_head) =>
            {
                launch.validate()?;
            }
            None if state_head(CommandOutputCaptureRestartStateV1::LaunchIntended).is_none() => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.launch_intended",
                    "must be present exactly with the historical LaunchIntended head",
                ));
            }
        }
        if self.finished_store_head.as_ref()
            != state_head(CommandOutputCaptureRestartStateV1::Finished)
            || self.published_store_head.as_ref()
                != state_head(CommandOutputCaptureRestartStateV1::Published)
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.lifecycle_anchors",
                "Finished and Published anchors must match their exact history heads",
            ));
        }
        match self.artifact_reference.as_ref() {
            Some(reference)
                if state_head(CommandOutputCaptureRestartStateV1::Published).is_some() =>
            {
                reference.validate()?;
            }
            None if state_head(CommandOutputCaptureRestartStateV1::Published).is_none() => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.artifact_reference",
                    "must be present exactly when Published exists in history",
                ));
            }
        }
        match self.terminal_prepared.as_ref() {
            Some(terminal)
                if state_head(CommandOutputCaptureRestartStateV1::TerminalPrepared)
                    == Some(&terminal.store_head) =>
            {
                terminal.validate()?;
            }
            None if state_head(CommandOutputCaptureRestartStateV1::TerminalPrepared).is_none() => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.terminal_prepared",
                    "must be present exactly with the TerminalPrepared history head",
                ));
            }
        }
        let cleaned_head = state_head(CommandOutputCaptureRestartStateV1::Cleaned);
        if self.cleaned_store_head.as_ref() != cleaned_head
            || self.cleanup_completion_proof_digest.is_some() != cleaned_head.is_some()
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.cleaned_store_head",
                "Cleaned head and cleanup proof digest must be present exactly with Cleaned history",
            ));
        }
        if self.resolution_action
            == CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
            && (self
                .lifecycle_history
                .iter()
                .map(|entry| entry.state)
                .collect::<Vec<_>>()
                != vec![
                    CommandOutputCaptureRestartStateV1::Intent,
                    CommandOutputCaptureRestartStateV1::CleanupIntended,
                    CommandOutputCaptureRestartStateV1::Cleaned,
                ]
                || self.physical_acquired.is_some()
                || self.launch_history.evidence().is_some()
                || self.artifact_reference.is_some()
                || self.terminal_prepared.is_some())
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.resolution_action",
                "intent tombstone must be exactly Intent -> CleanupIntended -> Cleaned",
            ));
        }
        if matches!(
            self.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
                | CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
        ) && self.final_state != CommandOutputCaptureRestartStateV1::Cleaned
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.resolution_action",
                "cleanup namespace actions require an exact final Cleaned head",
            ));
        }
        match self.resolution_action {
            CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned => {}
            CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
                if self.final_state == CommandOutputCaptureRestartStateV1::Cleaned
                    && self.launch_history.evidence().is_none()
                    && self.artifact_reference.is_none()
                    && self.terminal_prepared.is_none()
                    && matches!(
                        self.initial_state,
                        None | Some(
                            CommandOutputCaptureRestartStateV1::Intent
                                | CommandOutputCaptureRestartStateV1::Acquired
                                | CommandOutputCaptureRestartStateV1::CleanupIntended
                        )
                    ) => {}
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
                if self.final_state == CommandOutputCaptureRestartStateV1::Cleaned
                    && self.physical_acquired.is_some() => {}
            CommandOutputCapturePhysicalResolutionActionV1::FinishedPublicationRecovered
                if self.final_state == CommandOutputCaptureRestartStateV1::Published
                    && self.finished_store_head.is_some()
                    && self.published_store_head.is_some()
                    && self.artifact_reference.is_some()
                    && self.terminal_prepared.is_none()
                    && self.cleaned_store_head.is_none()
                    && (matches!(
                        self.pending_resolution,
                        CommandOutputCapturePendingResolutionV1::None
                    ) && self.initial_state
                        == Some(CommandOutputCaptureRestartStateV1::Finished)
                        || matches!(
                            &self.pending_resolution,
                            CommandOutputCapturePendingResolutionV1::RolledForward {
                                sequence,
                                state: CommandOutputCaptureRestartStateV1::Finished,
                                record_digest,
                            } if self.finished_store_head.as_ref().is_some_and(|head| {
                                head.generation == *sequence
                                    && head.record_digest == *record_digest
                            })
                        ) && self.initial_state
                            == Some(CommandOutputCaptureRestartStateV1::LaunchIntended)
                        || matches!(
                            &self.pending_resolution,
                            CommandOutputCapturePendingResolutionV1::RolledForward {
                                sequence,
                                state: CommandOutputCaptureRestartStateV1::Published,
                                record_digest,
                            } if self.published_store_head.as_ref().is_some_and(|head| {
                                head.generation == *sequence
                                    && head.record_digest == *record_digest
                            })
                        ) && self.initial_state
                            == Some(CommandOutputCaptureRestartStateV1::Finished)
                            && self.initial_store_head.as_ref()
                                == self.finished_store_head.as_ref()
                            && self.finished_store_head.as_ref().is_some_and(|finished| {
                                self.published_store_head.as_ref().is_some_and(|published| {
                                    finished.generation.checked_add(1) == Some(published.generation)
                                })
                            })
                        || matches!(
                            &self.pending_resolution,
                            CommandOutputCapturePendingResolutionV1::RemovedTorn {
                                sequence,
                                ..
                            } if self.published_store_head.as_ref().is_some_and(|published| {
                                published.generation == *sequence
                            })
                        ) && self.initial_state
                            == Some(CommandOutputCaptureRestartStateV1::Finished)
                            && self.initial_store_head.as_ref()
                                == self.finished_store_head.as_ref()
                            && self.finished_store_head.as_ref().is_some_and(|finished| {
                                self.published_store_head.as_ref().is_some_and(|published| {
                                    finished.generation.checked_add(1) == Some(published.generation)
                                })
                            })) => {}
            CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered
                if self.initial_state == Some(CommandOutputCaptureRestartStateV1::Published)
                    && self.final_state == CommandOutputCaptureRestartStateV1::TerminalPrepared
                    && self.published_store_head.is_some()
                    && self.artifact_reference.is_some()
                    && self.terminal_prepared.is_some()
                    && self.cleaned_store_head.is_none()
                    && matches!(
                        &self.pending_resolution,
                        CommandOutputCapturePendingResolutionV1::RolledForward {
                            sequence,
                            state: CommandOutputCaptureRestartStateV1::TerminalPrepared,
                            record_digest,
                        } if self.terminal_prepared.as_ref().is_some_and(|terminal| {
                            terminal.store_head.generation == *sequence
                                && terminal.store_head.record_digest == *record_digest
                        })
                    ) => {}
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
                if matches!(
                    self.final_state,
                    CommandOutputCaptureRestartStateV1::Published
                        | CommandOutputCaptureRestartStateV1::TerminalPrepared
                        | CommandOutputCaptureRestartStateV1::Cleaned
                ) && self.initial_state == Some(self.final_state)
                    && self.initial_store_head.as_ref() == Some(&self.final_store_head)
                    && (matches!(
                        self.pending_resolution,
                        CommandOutputCapturePendingResolutionV1::None
                    ) || matches!(
                        self.pending_resolution,
                        CommandOutputCapturePendingResolutionV1::RemovedTorn { sequence, .. }
                            if sequence == self.final_store_head.generation.saturating_add(1)
                    )) => {}
            _ => {
                return Err(ContractError::new(
                    "command_output_capture_physical_reconciliation_v1.resolution_action",
                    "namespace action does not match its exact initial/final lifecycle shape",
                ));
            }
        }
        if let Some(requested) = self.requested_store_head.as_ref()
            && !self
                .lifecycle_history
                .iter()
                .any(|entry| entry.store_head == *requested)
        {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.requested_store_head",
                "must identify one exact head in the validated physical history",
            ));
        }
        if self.reconciled_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.reconciled_at_unix_ms",
                "must be greater than zero",
            ));
        }
        let expected = compute_physical_reconciliation_digest(
            self.contract_version,
            self.layout_version,
            &self.capture_id,
            &self.effect_id,
            &self.intent_digest,
            &self.reconciliation_claim,
            self.predecessor_fence_digest.as_ref(),
            self.physical_fence_chain_length,
            &self.physical_fence_digest,
            self.requested_store_head.as_ref(),
            self.initial_state,
            self.initial_store_head.as_ref(),
            &self.pending_resolution,
            self.resolution_action,
            &self.lifecycle_history,
            &self.lifecycle_history_digest,
            self.final_state,
            &self.final_store_head,
            self.physical_acquired.as_ref(),
            self.physical_acquired_record_digest.as_ref(),
            &self.launch_history,
            self.finished_store_head.as_ref(),
            self.published_store_head.as_ref(),
            self.artifact_reference.as_ref(),
            self.terminal_prepared.as_ref(),
            self.cleaned_store_head.as_ref(),
            self.cleanup_completion_proof_digest.as_ref(),
            self.reconciled_at_unix_ms,
        )?;
        if self.reconciliation_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_physical_reconciliation_v1.reconciliation_digest",
                "does not match the canonical fenced physical reconciliation",
            ));
        }
        Ok(())
    }
}

/// Immutable result of later fenced reconciliation for an `Unknown` capture.
///
/// The original effect observation and `ReconciliationRequired` terminal stay
/// immutable. This record can only append a proven `Published` or `Abandoned`
/// storage disposition after both runner and command domains are cleaned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOutputCaptureReconciliationResolutionV1 {
    /// Shared core contract version.
    pub contract_version: u32,
    /// Private capture layout version.
    pub layout_version: u32,
    /// Exact preallocated capture identity.
    pub capture_id: String,
    /// Exact `RunCommand` effect whose outcome remains `Unknown`.
    pub effect_id: String,
    /// Exact immutable `Unknown` observation.
    pub observation_id: String,
    /// Exact immutable `ReconciliationRequired` terminal candidate.
    pub terminal_anchor_digest: Digest,
    /// Exact single-owner reconciliation claim consumed by this resolution.
    pub reconciliation_claim_id: String,
    /// Exact claim fencing token.
    pub reconciliation_fencing_token: Digest,
    /// Storage result proven after reconciliation.
    pub disposition: CommandOutputCaptureTerminalDispositionV1,
    /// Exact synchronized resolution record head.
    pub store_head: CommandOutputCaptureStoreHeadV1,
    /// Digest of the bounded resolution record.
    pub resolution_record_digest: Digest,
    /// Complete immutable stream reference when reconciliation published data.
    pub artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
    /// Time at which the fenced reconciliation completed.
    pub resolved_at_unix_ms: u64,
    /// Domain-separated digest of every preceding canonical field.
    pub resolution_anchor_digest: Digest,
}

#[derive(Serialize)]
struct CanonicalCaptureReconciliationResolution<'a> {
    contract_version: u32,
    layout_version: u32,
    capture_id: &'a str,
    effect_id: &'a str,
    observation_id: &'a str,
    terminal_anchor_digest: &'a Digest,
    reconciliation_claim_id: &'a str,
    reconciliation_fencing_token: &'a Digest,
    disposition: CommandOutputCaptureTerminalDispositionV1,
    store_head: &'a CommandOutputCaptureStoreHeadV1,
    resolution_record_digest: &'a Digest,
    artifact_reference: Option<&'a CommandOutputArtifactSetReferenceV1>,
    resolved_at_unix_ms: u64,
}

impl CommandOutputCaptureReconciliationResolutionV1 {
    /// Constructs a self-authenticating monotonic resolution.
    ///
    /// # Errors
    ///
    /// Returns a contract error unless the terminal is the exact unresolved
    /// `Unknown` candidate, the claim is exact and live at resolution time,
    /// the store head advances, and the artifact branch matches disposition.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        intent: &CommandOutputCaptureIntentV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        disposition: CommandOutputCaptureTerminalDispositionV1,
        store_head: CommandOutputCaptureStoreHeadV1,
        resolution_record_digest: Digest,
        artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
        resolved_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let resolution_anchor_digest = compute_reconciliation_resolution_digest(
            intent.contract_version,
            intent.layout_version,
            &intent.capture_id,
            &intent.source.effect_id,
            &terminal.observation_id,
            &terminal.terminal_anchor_digest,
            &claim.claim_id,
            &claim.fencing_token,
            disposition,
            &store_head,
            &resolution_record_digest,
            artifact_reference.as_ref(),
            resolved_at_unix_ms,
        )?;
        let resolution = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            observation_id: terminal.observation_id.clone(),
            terminal_anchor_digest: terminal.terminal_anchor_digest.clone(),
            reconciliation_claim_id: claim.claim_id.clone(),
            reconciliation_fencing_token: claim.fencing_token.clone(),
            disposition,
            store_head,
            resolution_record_digest,
            artifact_reference,
            resolved_at_unix_ms,
            resolution_anchor_digest,
        };
        resolution.validate_against(intent, terminal, claim)?;
        Ok(resolution)
    }

    /// Constructs a restart-only resolution at the immutable Unknown terminal
    /// head when that head is already the exact cleaned or published physical
    /// cut retained by `RestartClaimedUnresolved` evidence.
    ///
    /// # Errors
    ///
    /// Returns a contract error unless the receipt binds the exact acquisition
    /// and Unknown terminal, the new claim is live, and the same-head branch is
    /// Cleaned/Abandoned or Published with the exact retained artifacts.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_restart_same_head(
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        restart_receipt: &CommandOutputCapturePhysicalReconciliationV1,
        disposition: CommandOutputCaptureTerminalDispositionV1,
        resolved_at_unix_ms: u64,
    ) -> Result<Self, ContractError> {
        let artifact_reference = (disposition
            == CommandOutputCaptureTerminalDispositionV1::Published)
            .then(|| restart_receipt.artifact_reference.clone())
            .flatten();
        let resolution_anchor_digest = compute_reconciliation_resolution_digest(
            intent.contract_version,
            intent.layout_version,
            &intent.capture_id,
            &intent.source.effect_id,
            &terminal.observation_id,
            &terminal.terminal_anchor_digest,
            &claim.claim_id,
            &claim.fencing_token,
            disposition,
            &terminal.store_head,
            &restart_receipt.reconciliation_digest,
            artifact_reference.as_ref(),
            resolved_at_unix_ms,
        )?;
        let resolution = Self {
            contract_version: intent.contract_version,
            layout_version: intent.layout_version,
            capture_id: intent.capture_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            observation_id: terminal.observation_id.clone(),
            terminal_anchor_digest: terminal.terminal_anchor_digest.clone(),
            reconciliation_claim_id: claim.claim_id.clone(),
            reconciliation_fencing_token: claim.fencing_token.clone(),
            disposition,
            store_head: terminal.store_head.clone(),
            resolution_record_digest: restart_receipt.reconciliation_digest.clone(),
            artifact_reference,
            resolved_at_unix_ms,
            resolution_anchor_digest,
        };
        resolution.validate_against_restart_same_head(
            intent,
            acquired,
            terminal,
            claim,
            restart_receipt,
        )?;
        Ok(resolution)
    }

    /// Validates the narrowly typed restart-only same-head resolution branch.
    ///
    /// # Errors
    ///
    /// Returns a contract error for any crossed receipt, acquisition, claim,
    /// terminal, cleanup/publication branch, artifact, timestamp, or digest.
    pub fn validate_against_restart_same_head(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        restart_receipt: &CommandOutputCapturePhysicalReconciliationV1,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        acquired.validate_against(intent)?;
        terminal.validate()?;
        claim.validate()?;
        self.validate()?;
        restart_receipt.validate_against(
            intent,
            &restart_receipt.reconciliation_claim,
            Some(acquired),
        )?;
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.observation_id != terminal.observation_id
            || self.terminal_anchor_digest != terminal.terminal_anchor_digest
            || self.reconciliation_claim_id != claim.claim_id
            || self.reconciliation_fencing_token != claim.fencing_token
            || claim.capture_id != intent.capture_id
            || terminal.capture_id != intent.capture_id
            || terminal.effect_id != intent.source.effect_id
            || terminal.dispatch_claim_id.as_deref() != Some(acquired.dispatch_claim_id.as_str())
            || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
            || terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
            || terminal.disposition
                != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
            || terminal.store_head != restart_receipt.final_store_head
            || terminal.terminal_record_digest != restart_receipt.reconciliation_digest
            || terminal.anchored_at_unix_ms != restart_receipt.reconciled_at_unix_ms
            || self.store_head != terminal.store_head
            || self.resolution_record_digest != restart_receipt.reconciliation_digest
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.restart_same_head",
                "must bind the exact restart Unknown receipt, acquisition, terminal, and current claim",
            ));
        }
        if self.resolved_at_unix_ms < terminal.anchored_at_unix_ms
            || self.resolved_at_unix_ms < claim.acquired_at_unix_ms
            || self.resolved_at_unix_ms >= claim.expires_at_unix_ms
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.resolved_at_unix_ms",
                "must be within the current live claim and not precede the restart terminal",
            ));
        }
        let exact_branch = match restart_receipt.final_state {
            CommandOutputCaptureRestartStateV1::Cleaned => {
                self.disposition == CommandOutputCaptureTerminalDispositionV1::Abandoned
                    && self.artifact_reference.is_none()
                    && restart_receipt.cleaned_store_head.as_ref()
                        == Some(&restart_receipt.final_store_head)
                    && restart_receipt.cleanup_completion_proof_digest.is_some()
            }
            CommandOutputCaptureRestartStateV1::Published => {
                self.disposition == CommandOutputCaptureTerminalDispositionV1::Published
                    && self.artifact_reference.as_ref()
                        == restart_receipt.artifact_reference.as_ref()
                    && self.artifact_reference.is_some()
                    && restart_receipt.terminal_prepared.is_none()
            }
            CommandOutputCaptureRestartStateV1::TerminalPrepared => {
                self.disposition == CommandOutputCaptureTerminalDispositionV1::Published
                    && self.artifact_reference.as_ref()
                        == restart_receipt.artifact_reference.as_ref()
                    && self.artifact_reference.is_some()
                    && restart_receipt
                        .terminal_prepared
                        .as_ref()
                        .is_some_and(|terminal| {
                            terminal.store_head == restart_receipt.final_store_head
                        })
            }
            _ => false,
        };
        if !exact_branch {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.restart_same_head",
                "same-head resolution is exact only for cleaned abandonment or retained Published/TerminalPrepared publication",
            ));
        }
        Ok(())
    }

    /// Validates the resolution independently and against exact ledger authority.
    ///
    /// # Errors
    ///
    /// Returns a contract error for crossed authority or a noncanonical branch.
    pub fn validate_against(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        terminal: &CommandOutputCaptureTerminalAnchorV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<(), ContractError> {
        intent.validate()?;
        terminal.validate()?;
        claim.validate()?;
        self.validate()?;
        if self.contract_version != intent.contract_version
            || self.layout_version != intent.layout_version
            || self.capture_id != intent.capture_id
            || self.effect_id != intent.source.effect_id
            || self.observation_id != terminal.observation_id
            || self.terminal_anchor_digest != terminal.terminal_anchor_digest
            || self.reconciliation_claim_id != claim.claim_id
            || self.reconciliation_fencing_token != claim.fencing_token
            || claim.capture_id != intent.capture_id
            || terminal.capture_id != intent.capture_id
            || terminal.effect_id != intent.source.effect_id
            || terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
            || terminal.disposition
                != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1",
                "must bind the exact intent, Unknown terminal, and fenced claim",
            ));
        }
        if self.resolved_at_unix_ms < terminal.anchored_at_unix_ms
            || self.resolved_at_unix_ms < claim.acquired_at_unix_ms
            || self.resolved_at_unix_ms >= claim.expires_at_unix_ms
            || self.store_head.generation <= terminal.store_head.generation
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.resolved_at_unix_ms",
                "must be in the live claim interval and advance the terminal store head",
            ));
        }
        if let Some(reference) = self.artifact_reference.as_ref()
            && reference.source != intent.source
        {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.artifact_reference",
                "must carry the exact capture intent source",
            ));
        }
        Ok(())
    }

    /// Validates the complete self-contained resolution envelope.
    ///
    /// # Errors
    ///
    /// Returns a contract error for invalid identity, disposition, artifact,
    /// store head, timestamp, or canonical digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_capture_contract_and_layout(
            "command_output_capture_reconciliation_resolution_v1",
            self.contract_version,
            self.layout_version,
        )?;
        require_capture_id(&self.capture_id)?;
        require_capture_id(&self.reconciliation_claim_id)?;
        if self.effect_id.trim().is_empty() || self.observation_id.trim().is_empty() {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.identity",
                "effect and observation identities must be nonblank",
            ));
        }
        self.store_head.validate()?;
        let branch_valid = match self.disposition {
            CommandOutputCaptureTerminalDispositionV1::Published => {
                self.artifact_reference.is_some()
            }
            CommandOutputCaptureTerminalDispositionV1::Abandoned => {
                self.artifact_reference.is_none()
            }
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired => false,
        };
        if !branch_valid {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.disposition",
                "must be Published with artifacts or Abandoned without artifacts",
            ));
        }
        if let Some(reference) = self.artifact_reference.as_ref() {
            reference.validate()?;
            if reference.format_version != COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION
                || reference.source.effect_id != self.effect_id
            {
                return Err(ContractError::new(
                    "command_output_capture_reconciliation_resolution_v1.artifact_reference",
                    "must be a supported artifact reference for the exact effect",
                ));
            }
        }
        if self.resolved_at_unix_ms == 0 {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.resolved_at_unix_ms",
                "must be greater than zero",
            ));
        }
        let expected = compute_reconciliation_resolution_digest(
            self.contract_version,
            self.layout_version,
            &self.capture_id,
            &self.effect_id,
            &self.observation_id,
            &self.terminal_anchor_digest,
            &self.reconciliation_claim_id,
            &self.reconciliation_fencing_token,
            self.disposition,
            &self.store_head,
            &self.resolution_record_digest,
            self.artifact_reference.as_ref(),
            self.resolved_at_unix_ms,
        )?;
        if self.resolution_anchor_digest != expected {
            return Err(ContractError::new(
                "command_output_capture_reconciliation_resolution_v1.resolution_anchor_digest",
                "does not match the canonical reconciliation resolution",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn physical_reconciliation_with_artifact_for_test(
    receipt: &CommandOutputCapturePhysicalReconciliationV1,
    artifact_reference: CommandOutputArtifactSetReferenceV1,
) -> Result<CommandOutputCapturePhysicalReconciliationV1, ContractError> {
    let mut crossed = receipt.clone();
    crossed.artifact_reference = Some(artifact_reference);
    crossed.reconciliation_digest = compute_physical_reconciliation_digest(
        crossed.contract_version,
        crossed.layout_version,
        &crossed.capture_id,
        &crossed.effect_id,
        &crossed.intent_digest,
        &crossed.reconciliation_claim,
        crossed.predecessor_fence_digest.as_ref(),
        crossed.physical_fence_chain_length,
        &crossed.physical_fence_digest,
        crossed.requested_store_head.as_ref(),
        crossed.initial_state,
        crossed.initial_store_head.as_ref(),
        &crossed.pending_resolution,
        crossed.resolution_action,
        &crossed.lifecycle_history,
        &crossed.lifecycle_history_digest,
        crossed.final_state,
        &crossed.final_store_head,
        crossed.physical_acquired.as_ref(),
        crossed.physical_acquired_record_digest.as_ref(),
        &crossed.launch_history,
        crossed.finished_store_head.as_ref(),
        crossed.published_store_head.as_ref(),
        crossed.artifact_reference.as_ref(),
        crossed.terminal_prepared.as_ref(),
        crossed.cleaned_store_head.as_ref(),
        crossed.cleanup_completion_proof_digest.as_ref(),
        crossed.reconciled_at_unix_ms,
    )?;
    crossed.validate()?;
    Ok(crossed)
}
#[cfg(test)]
pub(super) fn physical_reconciliation_with_physical_acquired_for_test(
    receipt: &CommandOutputCapturePhysicalReconciliationV1,
    physical_acquired: CommandOutputCaptureAcquiredV1,
) -> Result<CommandOutputCapturePhysicalReconciliationV1, ContractError> {
    let mut crossed = receipt.clone();
    crossed.physical_acquired_record_digest =
        Some(physical_acquired.store_head.record_digest.clone());
    crossed.physical_acquired = Some(physical_acquired);
    crossed.reconciliation_digest = compute_physical_reconciliation_digest(
        crossed.contract_version,
        crossed.layout_version,
        &crossed.capture_id,
        &crossed.effect_id,
        &crossed.intent_digest,
        &crossed.reconciliation_claim,
        crossed.predecessor_fence_digest.as_ref(),
        crossed.physical_fence_chain_length,
        &crossed.physical_fence_digest,
        crossed.requested_store_head.as_ref(),
        crossed.initial_state,
        crossed.initial_store_head.as_ref(),
        &crossed.pending_resolution,
        crossed.resolution_action,
        &crossed.lifecycle_history,
        &crossed.lifecycle_history_digest,
        crossed.final_state,
        &crossed.final_store_head,
        crossed.physical_acquired.as_ref(),
        crossed.physical_acquired_record_digest.as_ref(),
        &crossed.launch_history,
        crossed.finished_store_head.as_ref(),
        crossed.published_store_head.as_ref(),
        crossed.artifact_reference.as_ref(),
        crossed.terminal_prepared.as_ref(),
        crossed.cleaned_store_head.as_ref(),
        crossed.cleanup_completion_proof_digest.as_ref(),
        crossed.reconciled_at_unix_ms,
    )?;
    crossed.validate()?;
    Ok(crossed)
}

#[cfg(test)]
pub(super) fn reconciliation_resolution_with_artifact_for_test(
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
    artifact_reference: CommandOutputArtifactSetReferenceV1,
) -> Result<CommandOutputCaptureReconciliationResolutionV1, ContractError> {
    let mut crossed = resolution.clone();
    crossed.artifact_reference = Some(artifact_reference);
    crossed.resolution_anchor_digest = compute_reconciliation_resolution_digest(
        crossed.contract_version,
        crossed.layout_version,
        &crossed.capture_id,
        &crossed.effect_id,
        &crossed.observation_id,
        &crossed.terminal_anchor_digest,
        &crossed.reconciliation_claim_id,
        &crossed.reconciliation_fencing_token,
        crossed.disposition,
        &crossed.store_head,
        &crossed.resolution_record_digest,
        crossed.artifact_reference.as_ref(),
        crossed.resolved_at_unix_ms,
    )?;
    crossed.validate()?;
    Ok(crossed)
}

#[cfg(test)]
pub(super) fn reconciliation_resolution_with_record_digest_for_test(
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
    resolution_record_digest: Digest,
) -> Result<CommandOutputCaptureReconciliationResolutionV1, ContractError> {
    let mut crossed = resolution.clone();
    crossed.resolution_record_digest = resolution_record_digest;
    crossed.resolution_anchor_digest = compute_reconciliation_resolution_digest(
        crossed.contract_version,
        crossed.layout_version,
        &crossed.capture_id,
        &crossed.effect_id,
        &crossed.observation_id,
        &crossed.terminal_anchor_digest,
        &crossed.reconciliation_claim_id,
        &crossed.reconciliation_fencing_token,
        crossed.disposition,
        &crossed.store_head,
        &crossed.resolution_record_digest,
        crossed.artifact_reference.as_ref(),
        crossed.resolved_at_unix_ms,
    )?;
    crossed.validate()?;
    Ok(crossed)
}

/// Move-only custody of one exact, unexpired reconciliation claim.
#[must_use = "dropping this permit abandons the claim until explicit release or expiry"]
pub struct CommandOutputCaptureReconciliationPermit {
    claim: CommandOutputCaptureReconciliationClaimV1,
    ledger_instance_id: u64,
}

impl std::fmt::Debug for CommandOutputCaptureReconciliationPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandOutputCaptureReconciliationPermit")
            .field("claim_id", &self.claim.claim_id)
            .field("capture_id", &self.claim.capture_id)
            .field("claim_epoch", &self.claim.claim_epoch)
            .finish_non_exhaustive()
    }
}

impl CommandOutputCaptureReconciliationPermit {
    /// Borrows the exact durable claim carried by this capability.
    #[must_use]
    pub const fn claim(&self) -> &CommandOutputCaptureReconciliationClaimV1 {
        &self.claim
    }

    pub(super) fn claim_for_ledger(
        &self,
        ledger_instance_id: u64,
    ) -> Result<&CommandOutputCaptureReconciliationClaimV1, LedgerError> {
        if self.ledger_instance_id != ledger_instance_id {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "permit belongs to another open EventLedger instance",
            ));
        }
        Ok(&self.claim)
    }

    pub(super) fn into_claim_for_ledger(
        self,
        ledger_instance_id: u64,
    ) -> Result<CommandOutputCaptureReconciliationClaimV1, LedgerError> {
        if self.ledger_instance_id != ledger_instance_id {
            return Err(reference_mismatch(
                "command output capture reconciliation terminal",
                "permit belongs to another open EventLedger instance",
            ));
        }
        Ok(self.claim)
    }
}

/// Result of a compare-and-set reconciliation claim attempt.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Terminal readback intentionally returns the complete validated lifecycle.
pub enum CommandOutputCaptureReconciliationAdmission {
    /// This call committed and read back a new fenced claim.
    Fresh {
        /// Exact immutable claim.
        claim: CommandOutputCaptureReconciliationClaimV1,
        /// Move-only claimant custody.
        permit: CommandOutputCaptureReconciliationPermit,
    },
    /// Another unexpired claimant owns the capture at the supplied time.
    Busy(CommandOutputCaptureReconciliationClaimV1),
    /// The capture already has a closed terminal obligation.
    Terminal(PersistedCommandOutputCapture),
}

impl EventLedger {
    /// Loads and exactly validates one capture lifecycle by its caller-supplied ID.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when the capture is absent or any immutable row
    /// is noncanonical or crossed.
    pub fn load_command_output_capture(
        &self,
        capture_id: &str,
    ) -> Result<PersistedCommandOutputCapture, LedgerError> {
        load_from_id(&self.connection, capture_id)
    }

    /// Loads and exactly validates the unique capture lifecycle bound to an effect.
    ///
    /// This recovery accessor does not recreate a dispatch permit. It exists so
    /// a caller holding only a durable effect identity can recover the exact
    /// caller-preallocated capture ID and any acquired/terminal anchors without
    /// scanning capture storage.
    ///
    /// # Errors
    ///
    /// Returns a ledger error when no capture is bound to `effect_id`, or when
    /// any immutable lifecycle row is noncanonical or crossed.
    pub fn load_command_output_capture_for_effect(
        &self,
        effect_id: &str,
    ) -> Result<PersistedCommandOutputCapture, LedgerError> {
        load_from_effect(&self.connection, effect_id)?.ok_or_else(|| {
            LedgerError::ArtifactNotFound {
                entity: "command output capture intent",
                id: effect_id.to_owned(),
            }
        })
    }

    /// Classifies restart work without recreating transport authority.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for an absent or corrupt lifecycle.
    pub fn classify_command_output_capture_recovery(
        &self,
        capture_id: &str,
    ) -> Result<CommandOutputCaptureRecovery, LedgerError> {
        let capture = load_from_id(&self.connection, capture_id)?;
        if let Some(rejection) = super::sensitive_output_rejection::load_for_effect(
            &self.connection,
            &capture.intent.source.effect_id,
        )? {
            return Ok(CommandOutputCaptureRecovery::SensitiveOutputRejected {
                capture,
                rejection: Box::new(rejection),
            });
        }
        if finish_is_proven_for_effect(&self.connection, &capture.intent.source.effect_id)? {
            Ok(CommandOutputCaptureRecovery::Terminal(capture))
        } else if capture.acquired.is_some() || capture.terminal.is_some() {
            Ok(CommandOutputCaptureRecovery::ReconciliationRequired(
                capture,
            ))
        } else {
            Ok(CommandOutputCaptureRecovery::ExistingIntent(capture))
        }
    }

    /// Compare-and-set acquires bounded, single-owner restart reconciliation.
    ///
    /// An unexpired existing owner returns `Busy`. An expired owner is closed
    /// as `Expired` in the same transaction that advances the epoch. A closed
    /// capture returns `Terminal`. Only a newly committed/read-back claim
    /// carries a move-only permit.
    ///
    /// # Errors
    ///
    /// Returns a ledger error for invalid identity/time, crossed history,
    /// storage failure, or uncertain commit/readback.
    pub fn claim_command_output_capture_reconciliation(
        &mut self,
        capture_id: &str,
        claim_id: &str,
        owner_id: &str,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<CommandOutputCaptureReconciliationAdmission, LedgerError> {
        self.require_writable()?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let capture = load_from_id(&transaction, capture_id)?;
        if capture.reconciliation_obligation_closure.is_some()
            || super::sensitive_output_rejection::finish_is_proven_for_effect(
                &transaction,
                &capture.intent.source.effect_id,
            )?
        {
            transaction.commit()?;
            return Ok(CommandOutputCaptureReconciliationAdmission::Terminal(
                capture,
            ));
        }
        let latest = load_latest_reconciliation_claim(&transaction, capture_id)?;
        if let Some(existing) = latest.as_ref() {
            let release = load_reconciliation_claim_release(&transaction, existing)?;
            if release.is_none() && reconciliation_claim_is_live_at(existing, acquired_at_unix_ms) {
                transaction.commit()?;
                return Ok(CommandOutputCaptureReconciliationAdmission::Busy(
                    existing.clone(),
                ));
            }
            if release.is_none() {
                insert_reconciliation_claim_release(
                    &transaction,
                    existing,
                    "Expired",
                    acquired_at_unix_ms,
                    None,
                    None,
                )?;
            }
        }
        let epoch = latest.as_ref().map_or(Ok(1_u64), |claim| {
            claim
                .claim_epoch
                .checked_add(1)
                .ok_or(LedgerError::IntegerOutOfRange(
                    "capture reconciliation claim epoch",
                ))
        })?;
        let claim = CommandOutputCaptureReconciliationClaimV1::try_new(
            claim_id,
            capture_id,
            owner_id,
            epoch,
            latest.map(|claim| claim.claim_id),
            acquired_at_unix_ms,
            expires_at_unix_ms,
        )?;
        insert_reconciliation_claim(&transaction, &claim)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation claim",
                recovery_id: claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path).map_err(|error| {
            LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation claim",
                recovery_id: claim.capture_id.clone(),
                detail: error.to_string(),
            }
        })?;
        let readback =
            load_latest_reconciliation_claim(&self.connection, capture_id)?.ok_or_else(|| {
                LedgerError::Corrupt {
                    entity: "command output capture reconciliation claim",
                    detail: "committed claim is absent on exact readback".into(),
                }
            })?;
        if readback != claim
            || load_reconciliation_claim_release(&self.connection, &claim)?.is_some()
        {
            return Err(LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation claim",
                recovery_id: capture_id.to_owned(),
                detail: "post-commit readback differs from the exact active claim".into(),
            });
        }
        Ok(CommandOutputCaptureReconciliationAdmission::Fresh {
            claim: claim.clone(),
            permit: CommandOutputCaptureReconciliationPermit {
                claim,
                ledger_instance_id: self.instance_id,
            },
        })
    }

    /// Atomically renews an exact live claim by consuming it and advancing its epoch.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/expired/cross-ledger permit, invalid new
    /// interval, terminal capture, or uncertain commit/readback. The old
    /// permit is consumed on every path.
    pub fn renew_command_output_capture_reconciliation(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        new_claim_id: &str,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<CommandOutputCaptureReconciliationPermit, LedgerError> {
        self.require_writable()?;
        if permit.ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "command output capture reconciliation renewal",
                "permit belongs to another open EventLedger instance",
            ));
        }
        let old = permit.claim;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let capture = load_from_id(&transaction, &old.capture_id)?;
        let latest = load_latest_reconciliation_claim(&transaction, &old.capture_id)?;
        if capture.reconciliation_obligation_closure.is_some()
            || super::sensitive_output_rejection::finish_is_proven_for_effect(
                &transaction,
                &capture.intent.source.effect_id,
            )?
            || latest.as_ref() != Some(&old)
            || load_reconciliation_claim_release(&transaction, &old)?.is_some()
            || acquired_at_unix_ms < old.acquired_at_unix_ms
            || !reconciliation_claim_is_live_at(&old, acquired_at_unix_ms)
        {
            return Err(reference_mismatch(
                "command output capture reconciliation renewal",
                "permit is stale, expired, released, crossed, or terminal",
            ));
        }
        let epoch = old
            .claim_epoch
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange(
                "capture reconciliation claim epoch",
            ))?;
        let renewed = CommandOutputCaptureReconciliationClaimV1::try_new(
            new_claim_id,
            &old.capture_id,
            &old.owner_id,
            epoch,
            Some(old.claim_id.clone()),
            acquired_at_unix_ms,
            expires_at_unix_ms,
        )?;
        insert_reconciliation_claim_release(
            &transaction,
            &old,
            "Superseded",
            acquired_at_unix_ms,
            None,
            Some(&renewed),
        )?;
        insert_reconciliation_claim(&transaction, &renewed)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation renewal",
                recovery_id: renewed.capture_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path).map_err(|error| {
            LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation renewal",
                recovery_id: renewed.capture_id.clone(),
                detail: error.to_string(),
            }
        })?;
        let readback = load_latest_reconciliation_claim(&self.connection, &renewed.capture_id)?;
        if readback.as_ref() != Some(&renewed)
            || load_reconciliation_claim_release(&self.connection, &renewed)?.is_some()
        {
            return Err(LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation renewal",
                recovery_id: renewed.capture_id.clone(),
                detail: "post-commit readback differs from renewed claim".into(),
            });
        }
        Ok(CommandOutputCaptureReconciliationPermit {
            claim: renewed,
            ledger_instance_id: self.instance_id,
        })
    }

    /// Explicitly releases one exact reconciliation claim without terminalizing.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale/crossed permit, invalid release time, or
    /// uncertain storage outcome. The permit is consumed on every path.
    pub fn release_command_output_capture_reconciliation(
        &mut self,
        permit: CommandOutputCaptureReconciliationPermit,
        released_at_unix_ms: u64,
    ) -> Result<CommandOutputCaptureReconciliationClaimV1, LedgerError> {
        self.require_writable()?;
        if permit.ledger_instance_id != self.instance_id {
            return Err(reference_mismatch(
                "command output capture reconciliation release",
                "permit belongs to another open EventLedger instance",
            ));
        }
        let claim = permit.claim;
        if released_at_unix_ms < claim.acquired_at_unix_ms {
            return Err(reference_mismatch(
                "command output capture reconciliation release",
                "release must not precede acquisition",
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if load_latest_reconciliation_claim(&transaction, &claim.capture_id)?.as_ref()
            != Some(&claim)
            || load_reconciliation_claim_release(&transaction, &claim)?.is_some()
        {
            return Err(reference_mismatch(
                "command output capture reconciliation release",
                "permit is stale, crossed, or already released",
            ));
        }
        insert_reconciliation_claim_release(
            &transaction,
            &claim,
            "Released",
            released_at_unix_ms,
            None,
            None,
        )?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation release",
                recovery_id: claim.capture_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path).map_err(|error| {
            LedgerError::PostCommitStateUncertain {
                operation: "command output capture reconciliation release",
                recovery_id: claim.capture_id.clone(),
                detail: error.to_string(),
            }
        })?;
        Ok(claim)
    }
}

pub(super) fn reconciliation_obligation_id(capture_id: &str) -> String {
    digest_framed(
        CAPTURE_RECONCILIATION_LEASE_ID_DOMAIN,
        capture_id.as_bytes(),
    )
    .as_str()
    .to_owned()
}

pub(super) fn insert_intent(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
) -> Result<(), LedgerError> {
    intent.validate()?;
    let obligation_id = reconciliation_obligation_id(&intent.capture_id);
    transaction.execute(
        "INSERT INTO command_output_capture_intents (
            capture_id, effect_id, sprint_id, runner_launch_id,
            runner_session_id, request_digest, private_state_digest,
            max_aggregate_output_bytes, layout_version, created_at_unix_ms,
            intent_digest, contract_version, intent_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            intent.capture_id,
            intent.source.effect_id,
            intent.source.sprint_id,
            intent.source.runner_launch_id,
            intent.source.runner_session_id,
            intent.source.request_digest.as_str(),
            intent.private_state_digest.as_str(),
            sqlite_integer(
                "command_output_capture_intent.max_aggregate_output_bytes",
                intent.max_aggregate_output_bytes,
            )?,
            i64::from(intent.layout_version),
            sqlite_integer(
                "command_output_capture_intent.created_at_unix_ms",
                intent.created_at_unix_ms,
            )?,
            intent.intent_digest.as_str(),
            i64::from(intent.contract_version),
            encode("command output capture intent", intent)?,
        ],
    )?;
    super::sensitive_output_rejection::insert_policy_admission(transaction, intent)?;
    transaction.execute(
        "INSERT INTO command_output_capture_reconciliation_obligations (
            obligation_id, capture_id, effect_id, intent_digest, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            obligation_id,
            intent.capture_id,
            intent.source.effect_id,
            intent.intent_digest.as_str(),
            i64::from(intent.contract_version),
        ],
    )?;
    Ok(())
}

pub(super) fn insert_acquired(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), LedgerError> {
    acquired.validate_against(intent)?;
    let reconciliation_history_exists = transaction.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM command_output_capture_reconciliation_claims
             WHERE capture_id = ?1
         )",
        [&intent.capture_id],
        |row| row.get::<_, bool>(0),
    )?;
    if reconciliation_history_exists {
        return Err(reference_mismatch(
            "command output capture acquisition",
            "any reconciliation-claim history permanently fences fresh acquisition",
        ));
    }
    insert_acquired_row(transaction, acquired)
}

fn insert_acquired_row(
    transaction: &Transaction<'_>,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO command_output_capture_acquisitions (
            capture_id, effect_id, sprint_id, runner_launch_id,
            runner_session_id, request_digest, private_state_digest,
            max_aggregate_output_bytes, intent_digest, dispatch_claim_id,
            store_head_generation, store_head_digest,
            working_device_id, working_inode, working_owner_uid, working_mode,
            working_link_count, stdout_device_id, stdout_inode, stdout_owner_uid,
            stdout_mode, stdout_link_count, stdout_byte_length,
            stderr_device_id, stderr_inode, stderr_owner_uid, stderr_mode,
            stderr_link_count, stderr_byte_length, acquired_at_unix_ms,
            acquired_anchor_digest, layout_version, contract_version,
            acquired_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
            ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34
         )",
        params![
            acquired.capture_id,
            acquired.source.effect_id,
            acquired.source.sprint_id,
            acquired.source.runner_launch_id,
            acquired.source.runner_session_id,
            acquired.source.request_digest.as_str(),
            acquired.private_state_digest.as_str(),
            sqlite_integer(
                "command_output_capture_acquired.max_aggregate_output_bytes",
                acquired.max_aggregate_output_bytes,
            )?,
            acquired.intent_digest.as_str(),
            acquired.dispatch_claim_id,
            sqlite_integer(
                "command_output_capture_acquired.store_head_generation",
                acquired.store_head.generation,
            )?,
            acquired.store_head.record_digest.as_str(),
            sqlite_integer(
                "command_output_capture_acquired.working_device_id",
                acquired.working_directory.device_id
            )?,
            sqlite_integer(
                "command_output_capture_acquired.working_inode",
                acquired.working_directory.inode
            )?,
            i64::from(acquired.working_directory.owner_uid),
            i64::from(acquired.working_directory.mode),
            sqlite_integer(
                "command_output_capture_acquired.working_link_count",
                acquired.working_directory.link_count
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_device_id",
                acquired.stdout.device_id
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_inode",
                acquired.stdout.inode
            )?,
            i64::from(acquired.stdout.owner_uid),
            i64::from(acquired.stdout.mode),
            sqlite_integer(
                "command_output_capture_acquired.stdout_link_count",
                acquired.stdout.link_count
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_byte_length",
                acquired.stdout.byte_length
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_device_id",
                acquired.stderr.device_id
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_inode",
                acquired.stderr.inode
            )?,
            i64::from(acquired.stderr.owner_uid),
            i64::from(acquired.stderr.mode),
            sqlite_integer(
                "command_output_capture_acquired.stderr_link_count",
                acquired.stderr.link_count
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_byte_length",
                acquired.stderr.byte_length
            )?,
            sqlite_integer(
                "command_output_capture_acquired.acquired_at_unix_ms",
                acquired.acquired_at_unix_ms
            )?,
            acquired.acquired_anchor_digest.as_str(),
            i64::from(acquired.layout_version),
            i64::from(acquired.contract_version),
            encode("command output capture acquired anchor", acquired)?,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) fn insert_acquired_without_rust_reconciliation_fence_for_test(
    transaction: &Transaction<'_>,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), LedgerError> {
    insert_acquired_row(transaction, acquired)
}

fn insert_restart_recovery_receipt(
    transaction: &Transaction<'_>,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
) -> Result<(), LedgerError> {
    receipt.validate()?;
    let launch = receipt.launch_history.evidence();
    let launch_schema = launch.map(|launch| launch.schema.as_str());
    let launch_bytes = launch.map(|launch| launch.canonical_bytes.as_slice());
    let launch_digest = launch.map(|launch| launch.canonical_bytes_digest.as_str());
    let launch_generation = launch
        .map(|launch| {
            sqlite_integer(
                "command_output_capture_restart_recovery_receipt.launch_store_head_generation",
                launch.store_head.generation,
            )
        })
        .transpose()?;
    let launch_head_digest = launch.map(|launch| launch.store_head.record_digest.as_str());
    transaction.execute(
        "INSERT INTO command_output_capture_restart_recovery_receipts (
            receipt_digest, capture_id, effect_id, intent_digest,
            reconciliation_claim_id, reconciliation_fencing_token,
            recovery_fence_claim_digest, physical_fence_chain_length,
            physical_fence_digest, observed_state, resolution_action,
            store_head_generation, store_head_digest, journal_history_digest,
            acquired_anchor_digest, launch_schema, launch_canonical_bytes,
            launch_canonical_bytes_digest, launch_store_head_generation,
            launch_store_head_digest, cleaned_record_digest,
            pending_record_present, recovered_at_unix_ms, layout_version,
            contract_version, receipt_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
            ?26
         )",
        params![
            receipt.reconciliation_digest.as_str(),
            receipt.capture_id,
            receipt.effect_id,
            receipt.intent_digest.as_str(),
            receipt.reconciliation_claim.claim_id,
            receipt.reconciliation_claim.fencing_token.as_str(),
            receipt.reconciliation_claim.claim_digest.as_str(),
            sqlite_integer(
                "command_output_capture_physical_reconciliation.physical_fence_chain_length",
                receipt.physical_fence_chain_length,
            )?,
            receipt.physical_fence_digest.as_str(),
            receipt.final_state.storage_name(),
            receipt.resolution_action.storage_name(),
            sqlite_integer(
                "command_output_capture_restart_recovery_receipt.store_head_generation",
                receipt.final_store_head.generation,
            )?,
            receipt.final_store_head.record_digest.as_str(),
            receipt.lifecycle_history_digest.as_str(),
            receipt
                .physical_acquired
                .as_ref()
                .map(|value| value.acquired_anchor_digest.as_str()),
            launch_schema,
            launch_bytes,
            launch_digest,
            launch_generation,
            launch_head_digest,
            receipt
                .cleaned_store_head
                .as_ref()
                .map(|head| head.record_digest.as_str()),
            false,
            sqlite_integer(
                "command_output_capture_restart_recovery_receipt.recovered_at_unix_ms",
                receipt.reconciled_at_unix_ms,
            )?,
            i64::from(receipt.layout_version),
            i64::from(receipt.contract_version),
            encode("command output capture restart recovery receipt", receipt)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_restart_recovery_receipt(
    connection: &Connection,
    receipt_digest: &str,
) -> Result<CommandOutputCaptureRestartRecoveryReceiptV1, LedgerError> {
    let bytes = connection
        .query_row(
            "SELECT receipt_json
             FROM command_output_capture_restart_recovery_receipts
             WHERE receipt_digest = ?1",
            [receipt_digest],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command output capture restart recovery receipt",
            id: receipt_digest.to_owned(),
        })?;
    let receipt: CommandOutputCaptureRestartRecoveryReceiptV1 =
        super::decode_stored("command output capture restart recovery receipt", &bytes)?;
    receipt.validate().map_err(|error| LedgerError::Corrupt {
        entity: "command output capture restart recovery receipt",
        detail: error.to_string(),
    })?;
    if encode("command output capture restart recovery receipt", &receipt)? != bytes {
        return Err(LedgerError::Corrupt {
            entity: "command output capture restart recovery receipt",
            detail: "stored JSON is not canonical".into(),
        });
    }
    let launch = receipt.launch_history.evidence();
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM command_output_capture_restart_recovery_receipts recovery
             WHERE recovery.receipt_digest = ?1
               AND recovery.capture_id = ?2
               AND recovery.effect_id = ?3
               AND recovery.intent_digest = ?4
               AND recovery.reconciliation_claim_id = ?5
               AND recovery.reconciliation_fencing_token = ?6
               AND recovery.recovery_fence_claim_digest = ?7
               AND recovery.physical_fence_chain_length = ?8
               AND recovery.physical_fence_digest = ?9
               AND recovery.observed_state = ?10
               AND recovery.resolution_action = ?11
               AND recovery.store_head_generation = ?12
               AND recovery.store_head_digest = ?13
               AND recovery.journal_history_digest = ?14
               AND recovery.acquired_anchor_digest IS ?15
               AND recovery.launch_schema IS ?16
               AND recovery.launch_canonical_bytes IS ?17
               AND recovery.launch_canonical_bytes_digest IS ?18
               AND recovery.launch_store_head_generation IS ?19
               AND recovery.launch_store_head_digest IS ?20
               AND recovery.cleaned_record_digest IS ?21
               AND recovery.pending_record_present = ?22
               AND recovery.recovered_at_unix_ms = ?23
               AND recovery.layout_version = ?24
               AND recovery.contract_version = ?25
               AND recovery.receipt_json = ?26
         )",
        params![
            receipt.reconciliation_digest.as_str(),
            receipt.capture_id,
            receipt.effect_id,
            receipt.intent_digest.as_str(),
            receipt.reconciliation_claim.claim_id,
            receipt.reconciliation_claim.fencing_token.as_str(),
            receipt.reconciliation_claim.claim_digest.as_str(),
            sqlite_integer(
                "command_output_capture_physical_reconciliation.physical_fence_chain_length",
                receipt.physical_fence_chain_length,
            )?,
            receipt.physical_fence_digest.as_str(),
            receipt.final_state.storage_name(),
            receipt.resolution_action.storage_name(),
            sqlite_integer(
                "command_output_capture_restart_recovery_receipt.store_head_generation",
                receipt.final_store_head.generation,
            )?,
            receipt.final_store_head.record_digest.as_str(),
            receipt.lifecycle_history_digest.as_str(),
            receipt
                .physical_acquired
                .as_ref()
                .map(|value| value.acquired_anchor_digest.as_str()),
            launch.map(|value| value.schema.as_str()),
            launch.map(|value| value.canonical_bytes.as_slice()),
            launch.map(|value| value.canonical_bytes_digest.as_str()),
            launch
                .map(|value| sqlite_integer(
                    "command_output_capture_restart_recovery_receipt.launch_store_head_generation",
                    value.store_head.generation,
                ))
                .transpose()?,
            launch.map(|value| value.store_head.record_digest.as_str()),
            receipt
                .cleaned_store_head
                .as_ref()
                .map(|head| head.record_digest.as_str()),
            false,
            sqlite_integer(
                "command_output_capture_restart_recovery_receipt.recovered_at_unix_ms",
                receipt.reconciled_at_unix_ms,
            )?,
            i64::from(receipt.layout_version),
            i64::from(receipt.contract_version),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output capture restart recovery receipt",
            detail: "redundant receipt columns differ from exact canonical bytes".into(),
        });
    }
    Ok(receipt)
}

pub(super) fn load_restart_claimed_unresolved_receipt_for_terminal(
    connection: &Connection,
    terminal_anchor_digest: &Digest,
) -> Result<Option<CommandOutputCapturePhysicalReconciliationV1>, LedgerError> {
    let receipt_digest = connection
        .query_row(
            "SELECT restart_recovery_receipt_digest
             FROM command_output_capture_terminal_validations
             WHERE terminal_anchor_digest = ?1
               AND validation_kind = 'RestartClaimedUnresolved'",
            [terminal_anchor_digest.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    receipt_digest
        .map(|digest| load_restart_recovery_receipt(connection, &digest))
        .transpose()
}

pub(super) fn insert_terminal(
    transaction: &Transaction<'_>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    observation: &EffectObservation,
) -> Result<(), LedgerError> {
    let (intent, acquired, reconciliation_obligation_id) =
        load_preterminal_capture_for_insert(transaction, &terminal.capture_id)?;
    if intent.source.effect_id != terminal.effect_id {
        return Err(reference_mismatch(
            "command output capture terminal",
            "terminal effect differs from its exact preterminal capture",
        ));
    }
    terminal.validate_against(&intent, acquired.as_ref(), observation)?;
    let artifact_manifest_digest = terminal
        .artifact_reference
        .as_ref()
        .map(|reference| reference.manifest_digest.as_str());
    let artifact_reference_json = terminal
        .artifact_reference
        .as_ref()
        .map(|reference| encode("command output terminal artifact reference", reference))
        .transpose()?;
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_anchors (
            capture_id, effect_id, observation_id, dispatch_claim_id,
            intent_digest, acquired_anchor_digest, observation_class,
            disposition, store_head_generation, store_head_digest,
            terminal_record_digest, artifact_manifest_digest,
            artifact_reference_json, anchored_at_unix_ms,
            terminal_anchor_digest, layout_version, contract_version,
            terminal_anchor_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18
         )",
        params![
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            terminal.dispatch_claim_id,
            terminal.intent_digest.as_str(),
            terminal.acquired_anchor_digest.as_ref().map(Digest::as_str),
            terminal.observation_class.storage_name(),
            terminal.disposition.storage_name(),
            sqlite_integer(
                "command_output_capture_terminal.store_head_generation",
                terminal.store_head.generation,
            )?,
            terminal.store_head.record_digest.as_str(),
            terminal.terminal_record_digest.as_str(),
            artifact_manifest_digest,
            artifact_reference_json,
            sqlite_integer(
                "command_output_capture_terminal.anchored_at_unix_ms",
                terminal.anchored_at_unix_ms,
            )?,
            terminal.terminal_anchor_digest.as_str(),
            i64::from(terminal.layout_version),
            i64::from(terminal.contract_version),
            encode("command output capture terminal anchor", terminal)?,
        ],
    )?;
    if terminal.disposition != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired {
        transaction.execute(
            "INSERT INTO command_output_capture_reconciliation_obligation_closures (
                obligation_id, capture_id, effect_id, terminal_anchor_digest,
                closed_at_unix_ms, contract_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                reconciliation_obligation_id,
                terminal.capture_id,
                terminal.effect_id,
                terminal.terminal_anchor_digest.as_str(),
                sqlite_integer(
                    "command_output_capture_reconciliation_obligation_closure.closed_at_unix_ms",
                    terminal.anchored_at_unix_ms,
                )?,
                i64::from(terminal.contract_version),
            ],
        )?;
    }
    Ok(())
}

fn load_preterminal_capture_for_insert(
    connection: &Connection,
    capture_id: &str,
) -> Result<
    (
        CommandOutputCaptureIntentV1,
        Option<CommandOutputCaptureAcquiredV1>,
        String,
    ),
    LedgerError,
> {
    let intent_bytes = connection
        .query_row(
            "SELECT intent_json FROM command_output_capture_intents WHERE capture_id = ?1",
            [capture_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command output capture intent",
            id: capture_id.to_owned(),
        })?;
    let intent: CommandOutputCaptureIntentV1 =
        super::decode_stored("command output capture intent", &intent_bytes)?;
    intent.validate().map_err(|error| LedgerError::Corrupt {
        entity: "command output capture intent",
        detail: error.to_string(),
    })?;
    if encode("command output capture intent", &intent)? != intent_bytes {
        return Err(LedgerError::Corrupt {
            entity: "command output capture intent",
            detail: "stored JSON is not the canonical intent encoding".into(),
        });
    }
    require_exact_intent_row(connection, &intent, &intent_bytes)?;

    let acquired_bytes = connection
        .query_row(
            "SELECT acquired_json FROM command_output_capture_acquisitions
             WHERE capture_id = ?1",
            [capture_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let acquired = acquired_bytes
        .map(|bytes| {
            let acquired: CommandOutputCaptureAcquiredV1 =
                super::decode_stored("command output capture acquired anchor", &bytes)?;
            acquired
                .validate_against(&intent)
                .map_err(|error| LedgerError::Corrupt {
                    entity: "command output capture acquired anchor",
                    detail: error.to_string(),
                })?;
            if encode("command output capture acquired anchor", &acquired)? != bytes {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture acquired anchor",
                    detail: "stored JSON is not the canonical acquired encoding".into(),
                });
            }
            require_exact_acquired_row(connection, &acquired, &bytes)?;
            Ok(acquired)
        })
        .transpose()?;
    require_exact_recovery_source(connection, &intent, acquired.as_ref(), None)?;

    let obligation_id = reconciliation_obligation_id(capture_id);
    let exact_obligation = connection.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM command_output_capture_reconciliation_obligations
             WHERE obligation_id = ?1 AND capture_id = ?2 AND effect_id = ?3
               AND intent_digest = ?4 AND contract_version = ?5
         )",
        params![
            obligation_id,
            intent.capture_id,
            intent.source.effect_id,
            intent.intent_digest.as_str(),
            i64::from(intent.contract_version),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    let terminal_exists = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM command_output_capture_terminal_anchors
             WHERE capture_id = ?1 OR effect_id = ?2
         )",
        params![intent.capture_id, intent.source.effect_id],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact_obligation || terminal_exists {
        return Err(LedgerError::Corrupt {
            entity: "command output capture terminal",
            detail: "preterminal capture lacks its exact open obligation or is already terminal"
                .into(),
        });
    }
    Ok((intent, acquired, obligation_id))
}

pub(super) fn insert_direct_terminal_validation(
    transaction: &Transaction<'_>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    command_domain_cleanup_proof_id: &str,
) -> Result<(), LedgerError> {
    if terminal.disposition == CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired {
        return Err(reference_mismatch(
            "command output capture direct terminal",
            "Unknown observations require the cleanup-free unresolved terminal boundary",
        ));
    }
    require_no_active_reconciliation_claim(transaction, &terminal.capture_id)?;
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_validations (
            terminal_anchor_digest, capture_id, effect_id, observation_id,
            validation_kind, command_domain_cleanup_proof_id,
            reconciliation_claim_id, reconciliation_fencing_token,
            runner_cleanup_receipt_id, restart_recovery_receipt_digest,
            terminal_anchored_at_unix_ms, sprint_id, contract_version
         ) SELECT ?1, ?2, ?3, ?4, 'DirectClaimed', ?5, NULL, NULL, NULL,
                  NULL, ?6, intent.sprint_id, ?7
           FROM command_output_capture_intents intent
          WHERE intent.capture_id = ?2 AND intent.effect_id = ?3",
        params![
            terminal.terminal_anchor_digest.as_str(),
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            command_domain_cleanup_proof_id,
            sqlite_integer(
                "command output capture direct terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            i64::from(terminal.contract_version),
        ],
    )?;
    Ok(())
}

pub(super) fn insert_direct_unresolved_terminal_validation(
    transaction: &Transaction<'_>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
) -> Result<(), LedgerError> {
    if terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
    {
        return Err(reference_mismatch(
            "command output capture unresolved terminal",
            "requires the exact Unknown/ReconciliationRequired branch",
        ));
    }
    let capture = load_from_id(transaction, &terminal.capture_id)?;
    if capture
        .acquired
        .as_ref()
        .is_none_or(|acquired| terminal.store_head != acquired.store_head)
    {
        return Err(reference_mismatch(
            "command output capture unresolved terminal",
            "Unknown must anchor the exact last core-proven Acquired store head",
        ));
    }
    require_no_active_reconciliation_claim(transaction, &terminal.capture_id)?;
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_validations (
            terminal_anchor_digest, capture_id, effect_id, observation_id,
            validation_kind, command_domain_cleanup_proof_id,
            reconciliation_claim_id, reconciliation_fencing_token,
            runner_cleanup_receipt_id, restart_recovery_receipt_digest,
            terminal_anchored_at_unix_ms, sprint_id, contract_version
         ) SELECT ?1, ?2, ?3, ?4, 'DirectClaimedUnresolved', NULL, NULL, NULL,
                  NULL, NULL, ?5, intent.sprint_id, ?6
           FROM command_output_capture_intents intent
          WHERE intent.capture_id = ?2 AND intent.effect_id = ?3",
        params![
            terminal.terminal_anchor_digest.as_str(),
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            sqlite_integer(
                "command output capture unresolved terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            i64::from(terminal.contract_version),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // One atomic append visibly binds claim, resolution, and obligation closure.
pub(super) fn insert_unknown_reconciliation_resolution(
    transaction: &Transaction<'_>,
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    resolution_physical: Option<&CommandOutputCapturePhysicalReconciliationV1>,
    command_domain_cleanup_proof_id: &str,
    runner_cleanup_receipt_id: &str,
) -> Result<(), LedgerError> {
    let capture = load_from_id(transaction, &claim.capture_id)?;
    let terminal = capture.terminal.as_ref().ok_or_else(|| {
        reference_mismatch(
            "command output capture reconciliation resolution",
            "capture lacks its immutable Unknown terminal",
        )
    })?;
    let physical_recovery_receipt_digest = if resolution.store_head == terminal.store_head {
        if resolution_physical.is_some() {
            return Err(reference_mismatch(
                "command output capture reconciliation resolution",
                "same-head resolution must use the original restart terminal receipt",
            ));
        }
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation resolution",
                "restart same-head resolution lacks its exact acquisition",
            )
        })?;
        let restart_receipt = load_restart_claimed_unresolved_receipt_for_terminal(
            transaction,
            &terminal.terminal_anchor_digest,
        )?
        .ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation resolution",
                "same-head resolution is confined to RestartClaimedUnresolved evidence",
            )
        })?;
        resolution.validate_against_restart_same_head(
            &capture.intent,
            acquired,
            terminal,
            claim,
            &restart_receipt,
        )?;
        restart_receipt.reconciliation_digest
    } else {
        resolution.validate_against(&capture.intent, terminal, claim)?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation resolution",
                "advancing resolution lacks its exact durable acquisition",
            )
        })?;
        let physical = resolution_physical.ok_or_else(|| {
            reference_mismatch(
                "command output capture reconciliation resolution",
                "advancing resolution requires a new exact fenced physical receipt",
            )
        })?;
        physical.validate_for_unknown_resolution(
            &capture.intent,
            acquired,
            terminal,
            claim,
            resolution,
        )?;
        insert_restart_recovery_receipt(transaction, physical)?;
        physical.reconciliation_digest.clone()
    };
    if capture.reconciliation_resolution.is_some()
        || capture.reconciliation_obligation_closure.is_some()
        || load_latest_reconciliation_claim(transaction, &claim.capture_id)?.as_ref() != Some(claim)
        || load_reconciliation_claim_release(transaction, claim)?.is_some()
    {
        return Err(reference_mismatch(
            "command output capture reconciliation resolution",
            "claim is stale/released or capture is already resolved",
        ));
    }

    insert_reconciliation_claim_release(
        transaction,
        claim,
        "ConsumedTerminal",
        resolution.resolved_at_unix_ms,
        Some(&terminal.terminal_anchor_digest),
        None,
    )?;
    let artifact_manifest_digest = resolution
        .artifact_reference
        .as_ref()
        .map(|reference| reference.manifest_digest.as_str());
    let artifact_reference_json = resolution
        .artifact_reference
        .as_ref()
        .map(|reference| {
            encode(
                "command output reconciliation artifact reference",
                reference,
            )
        })
        .transpose()?;
    transaction.execute(
        "INSERT INTO command_output_capture_reconciliation_resolutions (
            resolution_anchor_digest, capture_id, effect_id, observation_id,
            terminal_anchor_digest, reconciliation_claim_id,
            reconciliation_fencing_token, disposition, store_head_generation,
            store_head_digest, resolution_record_digest, artifact_manifest_digest,
            artifact_reference_json, command_domain_cleanup_proof_id,
            runner_cleanup_receipt_id, physical_recovery_receipt_digest,
            resolved_at_unix_ms, layout_version, contract_version, resolution_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20
         )",
        params![
            resolution.resolution_anchor_digest.as_str(),
            resolution.capture_id,
            resolution.effect_id,
            resolution.observation_id,
            resolution.terminal_anchor_digest.as_str(),
            resolution.reconciliation_claim_id,
            resolution.reconciliation_fencing_token.as_str(),
            resolution.disposition.storage_name(),
            sqlite_integer(
                "command_output_capture_reconciliation_resolution.store_head_generation",
                resolution.store_head.generation,
            )?,
            resolution.store_head.record_digest.as_str(),
            resolution.resolution_record_digest.as_str(),
            artifact_manifest_digest,
            artifact_reference_json,
            command_domain_cleanup_proof_id,
            runner_cleanup_receipt_id,
            physical_recovery_receipt_digest.as_str(),
            sqlite_integer(
                "command_output_capture_reconciliation_resolution.resolved_at_unix_ms",
                resolution.resolved_at_unix_ms,
            )?,
            i64::from(resolution.layout_version),
            i64::from(resolution.contract_version),
            encode(
                "command output capture reconciliation resolution",
                resolution
            )?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO command_output_capture_reconciliation_obligation_closures (
            obligation_id, capture_id, effect_id, terminal_anchor_digest,
            closed_at_unix_ms, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            capture.reconciliation_obligation_id,
            resolution.capture_id,
            resolution.effect_id,
            resolution.terminal_anchor_digest.as_str(),
            sqlite_integer(
                "command_output_capture_reconciliation_resolution.closed_at_unix_ms",
                resolution.resolved_at_unix_ms,
            )?,
            i64::from(resolution.contract_version),
        ],
    )?;
    Ok(())
}

fn require_no_active_reconciliation_claim(
    connection: &Connection,
    capture_id: &str,
) -> Result<(), LedgerError> {
    let active_claim_exists = match load_latest_reconciliation_claim(connection, capture_id)? {
        Some(claim) => load_reconciliation_claim_release(connection, &claim)?.is_none(),
        None => false,
    };
    if active_claim_exists {
        return Err(reference_mismatch(
            "command output capture direct terminal",
            "an active restart-reconciliation claim must be explicitly released before live terminalization",
        ));
    }
    Ok(())
}

pub(super) fn insert_pre_dispatch_terminal_validation(
    transaction: &Transaction<'_>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_validations (
            terminal_anchor_digest, capture_id, effect_id, observation_id,
            validation_kind, command_domain_cleanup_proof_id,
            reconciliation_claim_id, reconciliation_fencing_token,
            runner_cleanup_receipt_id, restart_recovery_receipt_digest,
            terminal_anchored_at_unix_ms, sprint_id, contract_version
         ) SELECT ?1, ?2, ?3, ?4, 'PreDispatchAbandoned', NULL, NULL, NULL,
                  NULL, NULL, ?5, intent.sprint_id, ?6
           FROM command_output_capture_intents intent
          WHERE intent.capture_id = ?2 AND intent.effect_id = ?3",
        params![
            terminal.terminal_anchor_digest.as_str(),
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            sqlite_integer(
                "command output capture pre-dispatch terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            i64::from(terminal.contract_version),
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_restart_recovery_terminal_validation(
    transaction: &Transaction<'_>,
    validation_kind: &str,
    intent: &CommandOutputCaptureIntentV1,
    acquired: Option<&CommandOutputCaptureAcquiredV1>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
    expected_terminal_record_digest: &Digest,
    command_domain_cleanup_proof_id: Option<&str>,
) -> Result<(), LedgerError> {
    receipt.validate_against(intent, claim, acquired)?;
    let latest = load_latest_reconciliation_claim(transaction, &claim.capture_id)?;
    if latest.as_ref() != Some(claim)
        || load_reconciliation_claim_release(transaction, claim)?.is_some()
        || terminal.capture_id != claim.capture_id
        || terminal.effect_id != receipt.effect_id
        || terminal.store_head != receipt.final_store_head
        || &terminal.terminal_record_digest != expected_terminal_record_digest
        || terminal.anchored_at_unix_ms != receipt.reconciled_at_unix_ms
    {
        return Err(reference_mismatch(
            "command output capture restart recovery terminal",
            "claim is stale/crossed or terminal differs from the exact physical receipt",
        ));
    }
    insert_restart_recovery_receipt(transaction, receipt)?;
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_validations (
            terminal_anchor_digest, capture_id, effect_id, observation_id,
            validation_kind, command_domain_cleanup_proof_id,
            reconciliation_claim_id, reconciliation_fencing_token,
            runner_cleanup_receipt_id, restart_recovery_receipt_digest,
            terminal_anchored_at_unix_ms, sprint_id, contract_version
         ) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9,
                  ?10, intent.sprint_id, ?11
           FROM command_output_capture_intents intent
          WHERE intent.capture_id = ?2 AND intent.effect_id = ?3",
        params![
            terminal.terminal_anchor_digest.as_str(),
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            validation_kind,
            command_domain_cleanup_proof_id,
            claim.claim_id,
            claim.fencing_token.as_str(),
            receipt.reconciliation_digest.as_str(),
            sqlite_integer(
                "command output capture restart terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            i64::from(terminal.contract_version),
        ],
    )?;
    insert_reconciliation_claim_release(
        transaction,
        claim,
        "ConsumedTerminal",
        terminal.anchored_at_unix_ms,
        Some(&terminal.terminal_anchor_digest),
        None,
    )?;
    Ok(())
}

pub(super) fn insert_restart_intent_abandoned_terminal_validation(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
    command_domain_cleanup_proof_id: &str,
) -> Result<(), LedgerError> {
    let exact_cleaned_readback = receipt.resolution_action
        == CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        && receipt.initial_state == Some(CommandOutputCaptureRestartStateV1::Cleaned)
        && receipt.initial_store_head.as_ref() == Some(&receipt.final_store_head);
    let exact_core_unacquired_physical_cut = match receipt.physical_acquired.as_ref() {
        None => {
            matches!(
                receipt.resolution_action,
                CommandOutputCapturePhysicalResolutionActionV1::IntentTombstoned
                    | CommandOutputCapturePhysicalResolutionActionV1::PreAcquisitionCleaned
            ) || exact_cleaned_readback
        }
        Some(_) => {
            (receipt.resolution_action
                == CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
                || exact_cleaned_readback)
                && receipt.lifecycle_history.iter().all(|entry| {
                    !matches!(
                        entry.state,
                        CommandOutputCaptureRestartStateV1::WriterAttached
                            | CommandOutputCaptureRestartStateV1::LaunchIntended
                            | CommandOutputCaptureRestartStateV1::Finished
                            | CommandOutputCaptureRestartStateV1::Published
                            | CommandOutputCaptureRestartStateV1::TerminalPrepared
                    )
                })
        }
    };
    if terminal.observation_class != CommandOutputCaptureObservationClassV1::FailedBeforeEffect
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Abandoned
        || terminal.dispatch_claim_id.is_some()
        || terminal.acquired_anchor_digest.is_some()
        || receipt.final_state != CommandOutputCaptureRestartStateV1::Cleaned
        || receipt.launch_history.evidence().is_some()
        || receipt.requested_store_head.is_some()
        || !exact_core_unacquired_physical_cut
    {
        return Err(reference_mismatch(
            "command output capture restart intent abandonment",
            "requires exact core-unacquired pre-launch Cleaned history and FailedBeforeEffect/Abandoned terminal",
        ));
    }
    insert_restart_recovery_terminal_validation(
        transaction,
        "RestartIntentAbandoned",
        intent,
        None,
        terminal,
        claim,
        receipt,
        &receipt.reconciliation_digest,
        Some(command_domain_cleanup_proof_id),
    )
}

pub(super) fn insert_restart_claimed_before_launch_abandoned_terminal_validation(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
    command_domain_cleanup_proof_id: &str,
) -> Result<(), LedgerError> {
    if terminal.observation_class != CommandOutputCaptureObservationClassV1::FailedBeforeEffect
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Abandoned
        || terminal.dispatch_claim_id.as_deref() != Some(acquired.dispatch_claim_id.as_str())
        || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
        || receipt.final_state != CommandOutputCaptureRestartStateV1::Cleaned
        || receipt.physical_acquired.as_ref() != Some(acquired)
        || receipt.launch_history.evidence().is_some()
        || !matches!(
            receipt.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::WorkingSetCleaned
                | CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
        )
        || (receipt.resolution_action
            == CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
            && (receipt.initial_state != Some(CommandOutputCaptureRestartStateV1::Cleaned)
                || receipt.initial_store_head.as_ref() != Some(&receipt.final_store_head)))
        || receipt.lifecycle_history.iter().any(|entry| {
            matches!(
                entry.state,
                CommandOutputCaptureRestartStateV1::LaunchIntended
                    | CommandOutputCaptureRestartStateV1::Finished
                    | CommandOutputCaptureRestartStateV1::Published
                    | CommandOutputCaptureRestartStateV1::TerminalPrepared
            )
        })
    {
        return Err(reference_mismatch(
            "command output capture restart claimed before-launch abandonment",
            "requires exact acquired/writer pre-launch Cleaned history and FailedBeforeEffect/Abandoned terminal",
        ));
    }
    insert_restart_recovery_terminal_validation(
        transaction,
        "RestartClaimedBeforeLaunchAbandoned",
        intent,
        Some(acquired),
        terminal,
        claim,
        receipt,
        &receipt.reconciliation_digest,
        Some(command_domain_cleanup_proof_id),
    )
}

pub(super) fn insert_restart_claimed_unresolved_terminal_validation(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
) -> Result<(), LedgerError> {
    if terminal.observation_class != CommandOutputCaptureObservationClassV1::Unknown
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        || terminal.dispatch_claim_id.as_deref() != Some(acquired.dispatch_claim_id.as_str())
        || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
        || receipt.physical_acquired.as_ref() != Some(acquired)
        || receipt.launch_history.evidence().is_none()
        || !receipt.final_state.is_at_or_after_launch()
    {
        return Err(reference_mismatch(
            "command output capture restart claimed unresolved terminal",
            "requires exact acquired post-launch history and Unknown/ReconciliationRequired terminal",
        ));
    }
    insert_restart_recovery_terminal_validation(
        transaction,
        "RestartClaimedUnresolved",
        intent,
        Some(acquired),
        terminal,
        claim,
        receipt,
        &receipt.reconciliation_digest,
        None,
    )
}

pub(super) fn insert_restart_terminal_prepared_published_terminal_validation(
    transaction: &Transaction<'_>,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    receipt: &CommandOutputCaptureRestartRecoveryReceiptV1,
    command_domain_cleanup_proof_id: &str,
) -> Result<(), LedgerError> {
    let terminal_prepared = receipt.terminal_prepared.as_ref().ok_or_else(|| {
        reference_mismatch(
            "command output capture restart TerminalPrepared publication",
            "physical reconciliation lacks exact retained terminal evidence",
        )
    })?;
    if terminal.observation_class != CommandOutputCaptureObservationClassV1::Succeeded
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::Published
        || terminal.dispatch_claim_id.as_deref() != Some(acquired.dispatch_claim_id.as_str())
        || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
        || receipt.physical_acquired.as_ref() != Some(acquired)
        || receipt.final_state != CommandOutputCaptureRestartStateV1::TerminalPrepared
        || !matches!(
            receipt.resolution_action,
            CommandOutputCapturePhysicalResolutionActionV1::TerminalReadback
                | CommandOutputCapturePhysicalResolutionActionV1::TerminalPreparedRecovered
        )
        || receipt.launch_history.evidence().is_none()
        || receipt.artifact_reference.as_ref() != terminal.artifact_reference.as_ref()
        || terminal_prepared.store_head != receipt.final_store_head
        || terminal.terminal_record_digest != terminal_prepared.canonical_bytes_digest
    {
        return Err(reference_mismatch(
            "command output capture restart TerminalPrepared publication",
            "requires exact acquired Published/TerminalPrepared history and succeeded terminal",
        ));
    }
    insert_restart_recovery_terminal_validation(
        transaction,
        "RestartTerminalPreparedPublished",
        intent,
        Some(acquired),
        terminal,
        claim,
        receipt,
        &terminal_prepared.canonical_bytes_digest,
        Some(command_domain_cleanup_proof_id),
    )
}

pub(super) fn insert_reconciliation_terminal_validation(
    transaction: &Transaction<'_>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    command_domain_cleanup_proof_id: &str,
    runner_cleanup_receipt_id: &str,
) -> Result<(), LedgerError> {
    let latest = load_latest_reconciliation_claim(transaction, &claim.capture_id)?;
    if latest.as_ref() != Some(claim)
        || load_reconciliation_claim_release(transaction, claim)?.is_some()
        || terminal.capture_id != claim.capture_id
        || terminal.anchored_at_unix_ms < claim.acquired_at_unix_ms
        || terminal.anchored_at_unix_ms >= claim.expires_at_unix_ms
    {
        return Err(reference_mismatch(
            "command output capture reconciliation terminal",
            "claim is stale, released, expired, crossed, or outside its fenced interval",
        ));
    }
    transaction.execute(
        "INSERT INTO command_output_capture_terminal_validations (
            terminal_anchor_digest, capture_id, effect_id, observation_id,
            validation_kind, command_domain_cleanup_proof_id,
            reconciliation_claim_id, reconciliation_fencing_token,
            runner_cleanup_receipt_id, restart_recovery_receipt_digest,
            terminal_anchored_at_unix_ms, sprint_id, contract_version
         ) SELECT ?1, ?2, ?3, ?4, 'RestartReconciliation', ?5, ?6, ?7, ?8,
                  NULL, ?9, intent.sprint_id, ?10
           FROM command_output_capture_intents intent
          WHERE intent.capture_id = ?2 AND intent.effect_id = ?3",
        params![
            terminal.terminal_anchor_digest.as_str(),
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            command_domain_cleanup_proof_id,
            claim.claim_id,
            claim.fencing_token.as_str(),
            runner_cleanup_receipt_id,
            sqlite_integer(
                "command output capture reconciliation terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            i64::from(terminal.contract_version),
        ],
    )?;
    insert_reconciliation_claim_release(
        transaction,
        claim,
        "ConsumedTerminal",
        terminal.anchored_at_unix_ms,
        Some(&terminal.terminal_anchor_digest),
        None,
    )?;
    Ok(())
}

pub(super) fn validate_claim_acquisition(
    connection: &Connection,
    claim: &PersistedRunnerEffectDispatchClaim,
) -> Result<(), LedgerError> {
    let capture = load_from_effect(connection, &claim.effect_id)?.ok_or_else(|| {
        LedgerError::ArtifactNotFound {
            entity: "command output capture intent",
            id: claim.effect_id.clone(),
        }
    })?;
    let acquired = capture.acquired.ok_or_else(|| {
        reference_mismatch(
            "command output capture dispatch",
            "RunCommand dispatch requires one exact acquired capture anchor",
        )
    })?;
    if acquired.dispatch_claim_id != claim.dispatch_claim_id
        || acquired.source.effect_id != claim.effect_id
        || acquired.source.sprint_id != claim.sprint_id
        || acquired.source.runner_launch_id != claim.launch_id
        || acquired.source.runner_session_id != claim.session_id
        || acquired.source.request_digest != claim.request_digest
    {
        return Err(reference_mismatch(
            "command output capture dispatch",
            "acquired capture differs from the exact runner dispatch claim",
        ));
    }
    Ok(())
}

pub(super) fn load_from_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<PersistedCommandOutputCapture>, LedgerError> {
    load_from_effect_with_validated_source(connection, effect_id, None)
}

fn load_from_effect_with_validated_source(
    connection: &Connection,
    effect_id: &str,
    validated_source: Option<(&PersistedEffect, &EffectObservation)>,
) -> Result<Option<PersistedCommandOutputCapture>, LedgerError> {
    if validated_source.is_some_and(|(effect, observation)| {
        effect.intent.effect_id != effect_id
            || effect.observation.as_ref() != Some(observation)
            || observation.effect_id != effect_id
    }) {
        return Err(reference_mismatch(
            "command output capture validated source",
            "caller-supplied effect or observation crosses the requested effect",
        ));
    }
    // Schemas before v27 have no capture authority to load.  Preserve their
    // historical read contract without mistaking a missing table for ledger
    // corruption; a migrated v27 ledger still fails closed below when a
    // current RunCommand has no capture row.
    if !schema_is_installed(connection)? {
        return Ok(None);
    }
    let capture_id = connection
        .query_row(
            "SELECT capture_id FROM command_output_capture_intents WHERE effect_id = ?1",
            [effect_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let historical_exemption = load_pre_v27_exemption(connection, effect_id)?;
    if capture_id.is_some() && historical_exemption {
        return Err(LedgerError::Corrupt {
            entity: "command output capture authority",
            detail:
                "one effect has both current capture authority and a pre-v27 migration exemption"
                    .into(),
        });
    }
    capture_id
        .map(|capture_id| {
            load_from_id_with_validated_source(connection, &capture_id, validated_source)
        })
        .transpose()
}

fn load_pre_v27_exemption(connection: &Connection, effect_id: &str) -> Result<bool, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT sprint_id, request_digest, created_at_unix_ms,
                    contract_version, intent_digest
             FROM pre_v27_command_output_capture_exemptions
             WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM effect_intents
             WHERE effect_id = ?1
               AND sprint_id = ?2
               AND effect_kind = 'RunCommand'
               AND request_digest = ?3
               AND created_at_unix_ms = ?4
               AND contract_version = ?5
               AND grok_sha256(intent_json) = ?6
         )",
        params![effect_id, stored.0, stored.1, stored.2, stored.3, stored.4],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "pre-v27 command output capture exemption",
            detail: "migration exemption differs from its exact historical RunCommand intent"
                .into(),
        });
    }
    Ok(true)
}

fn require_exact_intent_row(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
    bytes: &[u8],
) -> Result<(), LedgerError> {
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM command_output_capture_intents
             WHERE capture_id = ?1 AND effect_id = ?2 AND sprint_id = ?3
               AND runner_launch_id = ?4 AND runner_session_id = ?5
               AND request_digest = ?6 AND private_state_digest = ?7
               AND max_aggregate_output_bytes = ?8 AND layout_version = ?9
               AND created_at_unix_ms = ?10 AND intent_digest = ?11
               AND contract_version = ?12 AND intent_json = ?13
         )",
        params![
            intent.capture_id,
            intent.source.effect_id,
            intent.source.sprint_id,
            intent.source.runner_launch_id,
            intent.source.runner_session_id,
            intent.source.request_digest.as_str(),
            intent.private_state_digest.as_str(),
            sqlite_integer(
                "command_output_capture_intent.max_aggregate_output_bytes",
                intent.max_aggregate_output_bytes,
            )?,
            i64::from(intent.layout_version),
            sqlite_integer(
                "command_output_capture_intent.created_at_unix_ms",
                intent.created_at_unix_ms,
            )?,
            intent.intent_digest.as_str(),
            i64::from(intent.contract_version),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output capture intent",
            detail: "redundant intent columns differ from canonical JSON".into(),
        });
    }
    Ok(())
}

fn require_exact_recovery_source(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
    acquired: Option<&CommandOutputCaptureAcquiredV1>,
    validated_effect: Option<&PersistedEffect>,
) -> Result<(), LedgerError> {
    let exact_source = connection.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM command_output_capture_exact_runner_sources_v27 source
             WHERE source.capture_id = ?1
               AND source.effect_id = ?2
               AND source.sprint_id = ?3
               AND source.launch_id = ?4
               AND source.session_id = ?5
               AND source.request_digest = ?6
               AND source.created_at_unix_ms = ?7
               AND source.contract_version = ?8
         )",
        params![
            intent.capture_id,
            intent.source.effect_id,
            intent.source.sprint_id,
            intent.source.runner_launch_id,
            intent.source.runner_session_id,
            intent.source.request_digest.as_str(),
            sqlite_integer(
                "command output capture recovery source creation time",
                intent.created_at_unix_ms,
            )?,
            i64::from(intent.contract_version),
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact_source {
        return Err(LedgerError::Corrupt {
            entity: "command output capture recovery source",
            detail: "capture intent no longer joins its exact effect, runner binding, launch, session, and private state".into(),
        });
    }

    let loaded_effect;
    let effect = if let Some(effect) = validated_effect {
        effect
    } else {
        loaded_effect = super::load_effect_from_for_recovery(connection, &intent.source.effect_id)?;
        &loaded_effect
    };
    if effect.intent.effect_id != intent.source.effect_id
        || effect.intent.kind != crate::EffectKind::RunCommand
        || effect.intent.sprint_id != intent.source.sprint_id
        || effect.intent.request_digest != intent.source.request_digest
        || effect.intent.created_at_unix_ms != intent.created_at_unix_ms
        || effect.intent.contract_version != intent.contract_version
    {
        return Err(LedgerError::Corrupt {
            entity: "command output capture recovery source",
            detail: "capture intent differs from its exact canonical RunCommand intent".into(),
        });
    }
    match (acquired, effect.dispatch_claim.as_ref()) {
        (None, None) => {}
        (Some(acquired), Some(dispatch))
            if dispatch.dispatch_claim_id == acquired.dispatch_claim_id
                && dispatch.effect_id == intent.source.effect_id
                && dispatch.sprint_id == intent.source.sprint_id
                && dispatch.launch_id == intent.source.runner_launch_id
                && dispatch.session_id == intent.source.runner_session_id
                && dispatch.request_digest == intent.source.request_digest
                && dispatch.contract_version == intent.contract_version => {}
        _ => {
            return Err(LedgerError::Corrupt {
                entity: "command output capture recovery source",
                detail:
                    "capture acquisition and durable runner dispatch claim are absent or crossed"
                        .into(),
            });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn require_exact_acquired_row(
    connection: &Connection,
    acquired: &CommandOutputCaptureAcquiredV1,
    bytes: &[u8],
) -> Result<(), LedgerError> {
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM command_output_capture_acquisitions
             WHERE capture_id = ?1 AND effect_id = ?2 AND sprint_id = ?3
               AND runner_launch_id = ?4 AND runner_session_id = ?5
               AND request_digest = ?6 AND private_state_digest = ?7
               AND max_aggregate_output_bytes = ?8 AND intent_digest = ?9
               AND dispatch_claim_id = ?10 AND store_head_generation = ?11
               AND store_head_digest = ?12 AND working_device_id = ?13
               AND working_inode = ?14 AND working_owner_uid = ?15
               AND working_mode = ?16 AND working_link_count = ?17
               AND stdout_device_id = ?18 AND stdout_inode = ?19
               AND stdout_owner_uid = ?20 AND stdout_mode = ?21
               AND stdout_link_count = ?22 AND stdout_byte_length = ?23
               AND stderr_device_id = ?24 AND stderr_inode = ?25
               AND stderr_owner_uid = ?26 AND stderr_mode = ?27
               AND stderr_link_count = ?28 AND stderr_byte_length = ?29
               AND acquired_at_unix_ms = ?30 AND acquired_anchor_digest = ?31
               AND layout_version = ?32 AND contract_version = ?33
               AND acquired_json = ?34
         )",
        params![
            acquired.capture_id,
            acquired.source.effect_id,
            acquired.source.sprint_id,
            acquired.source.runner_launch_id,
            acquired.source.runner_session_id,
            acquired.source.request_digest.as_str(),
            acquired.private_state_digest.as_str(),
            sqlite_integer(
                "command_output_capture_acquired.max_aggregate_output_bytes",
                acquired.max_aggregate_output_bytes,
            )?,
            acquired.intent_digest.as_str(),
            acquired.dispatch_claim_id,
            sqlite_integer(
                "command_output_capture_acquired.store_head_generation",
                acquired.store_head.generation,
            )?,
            acquired.store_head.record_digest.as_str(),
            sqlite_integer(
                "command_output_capture_acquired.working_device_id",
                acquired.working_directory.device_id,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.working_inode",
                acquired.working_directory.inode,
            )?,
            i64::from(acquired.working_directory.owner_uid),
            i64::from(acquired.working_directory.mode),
            sqlite_integer(
                "command_output_capture_acquired.working_link_count",
                acquired.working_directory.link_count,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_device_id",
                acquired.stdout.device_id,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_inode",
                acquired.stdout.inode,
            )?,
            i64::from(acquired.stdout.owner_uid),
            i64::from(acquired.stdout.mode),
            sqlite_integer(
                "command_output_capture_acquired.stdout_link_count",
                acquired.stdout.link_count,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stdout_byte_length",
                acquired.stdout.byte_length,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_device_id",
                acquired.stderr.device_id,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_inode",
                acquired.stderr.inode,
            )?,
            i64::from(acquired.stderr.owner_uid),
            i64::from(acquired.stderr.mode),
            sqlite_integer(
                "command_output_capture_acquired.stderr_link_count",
                acquired.stderr.link_count,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.stderr_byte_length",
                acquired.stderr.byte_length,
            )?,
            sqlite_integer(
                "command_output_capture_acquired.acquired_at_unix_ms",
                acquired.acquired_at_unix_ms,
            )?,
            acquired.acquired_anchor_digest.as_str(),
            i64::from(acquired.layout_version),
            i64::from(acquired.contract_version),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output capture acquired anchor",
            detail: "redundant acquisition columns differ from canonical JSON".into(),
        });
    }
    Ok(())
}

fn require_exact_terminal_row(
    connection: &Connection,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    bytes: &[u8],
) -> Result<(), LedgerError> {
    let artifact_manifest = terminal
        .artifact_reference
        .as_ref()
        .map(|reference| reference.manifest_digest.as_str());
    let artifact_json = terminal
        .artifact_reference
        .as_ref()
        .map(|reference| encode("command output terminal artifact reference", reference))
        .transpose()?;
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM command_output_capture_terminal_anchors
             WHERE capture_id = ?1 AND effect_id = ?2 AND observation_id = ?3
               AND dispatch_claim_id IS ?4 AND intent_digest = ?5
               AND acquired_anchor_digest IS ?6 AND observation_class = ?7
               AND disposition = ?8 AND store_head_generation = ?9
               AND store_head_digest = ?10 AND terminal_record_digest = ?11
               AND artifact_manifest_digest IS ?12
               AND artifact_reference_json IS ?13
               AND anchored_at_unix_ms = ?14 AND terminal_anchor_digest = ?15
               AND layout_version = ?16 AND contract_version = ?17
               AND terminal_anchor_json = ?18
         )",
        params![
            terminal.capture_id,
            terminal.effect_id,
            terminal.observation_id,
            terminal.dispatch_claim_id,
            terminal.intent_digest.as_str(),
            terminal.acquired_anchor_digest.as_ref().map(Digest::as_str),
            terminal.observation_class.storage_name(),
            terminal.disposition.storage_name(),
            sqlite_integer(
                "command_output_capture_terminal.store_head_generation",
                terminal.store_head.generation,
            )?,
            terminal.store_head.record_digest.as_str(),
            terminal.terminal_record_digest.as_str(),
            artifact_manifest,
            artifact_json,
            sqlite_integer(
                "command_output_capture_terminal.anchored_at_unix_ms",
                terminal.anchored_at_unix_ms,
            )?,
            terminal.terminal_anchor_digest.as_str(),
            i64::from(terminal.layout_version),
            i64::from(terminal.contract_version),
            bytes,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output capture terminal anchor",
            detail: "redundant terminal columns differ from canonical JSON".into(),
        });
    }
    Ok(())
}

pub(super) fn load_from_id(
    connection: &Connection,
    capture_id: &str,
) -> Result<PersistedCommandOutputCapture, LedgerError> {
    load_from_id_with_validated_source(connection, capture_id, None)
}

#[allow(clippy::items_after_statements, clippy::too_many_lines)] // One fail-closed loader exact-compares every immutable lifecycle row and closure.
fn load_from_id_with_validated_source(
    connection: &Connection,
    capture_id: &str,
    validated_source: Option<(&PersistedEffect, &EffectObservation)>,
) -> Result<PersistedCommandOutputCapture, LedgerError> {
    let intent_bytes = connection
        .query_row(
            "SELECT intent_json FROM command_output_capture_intents WHERE capture_id = ?1",
            [capture_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command output capture intent",
            id: capture_id.to_owned(),
        })?;
    let intent: CommandOutputCaptureIntentV1 =
        super::decode_stored("command output capture intent", &intent_bytes)?;
    intent.validate().map_err(|error| LedgerError::Corrupt {
        entity: "command output capture intent",
        detail: error.to_string(),
    })?;
    if encode("command output capture intent", &intent)? != intent_bytes {
        return Err(LedgerError::Corrupt {
            entity: "command output capture intent",
            detail: "stored JSON is not the canonical intent encoding".into(),
        });
    }
    require_exact_intent_row(connection, &intent, &intent_bytes)?;
    super::sensitive_output_rejection::require_policy_state_for_capture(connection, &intent)?;
    if load_pre_v27_exemption(connection, &intent.source.effect_id)? {
        return Err(LedgerError::Corrupt {
            entity: "command output capture authority",
            detail: "current capture authority coexists with a pre-v27 migration exemption".into(),
        });
    }
    let acquired_bytes = connection
        .query_row(
            "SELECT acquired_json FROM command_output_capture_acquisitions WHERE capture_id = ?1",
            [capture_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let acquired = acquired_bytes
        .map(|bytes| {
            let acquired: CommandOutputCaptureAcquiredV1 =
                super::decode_stored("command output capture acquired anchor", &bytes)?;
            acquired
                .validate_against(&intent)
                .map_err(|error| LedgerError::Corrupt {
                    entity: "command output capture acquired anchor",
                    detail: error.to_string(),
                })?;
            if encode("command output capture acquired anchor", &acquired)? != bytes {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture acquired anchor",
                    detail: "stored JSON is not the canonical acquired encoding".into(),
                });
            }
            require_exact_acquired_row(connection, &acquired, &bytes)?;
            Ok(acquired)
        })
        .transpose()?;
    require_exact_recovery_source(
        connection,
        &intent,
        acquired.as_ref(),
        validated_source.map(|(effect, _)| effect),
    )?;
    let _ = load_latest_reconciliation_claim(connection, &intent.capture_id)?;

    let terminal_bytes = connection
        .query_row(
            "SELECT terminal_anchor_json FROM command_output_capture_terminal_anchors
             WHERE capture_id = ?1",
            [capture_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let terminal = terminal_bytes
        .map(|bytes| {
            let terminal: CommandOutputCaptureTerminalAnchorV1 =
                super::decode_stored("command output capture terminal anchor", &bytes)?;
            let loaded_effect;
            let observation = if let Some((effect, observation)) = validated_source {
                if effect.observation.as_ref() != Some(observation)
                    || observation.effect_id != intent.source.effect_id
                {
                    return Err(LedgerError::Corrupt {
                        entity: "command output capture terminal anchor",
                        detail: "caller-supplied observation crosses its validated effect".into(),
                    });
                }
                observation
            } else {
                loaded_effect = super::load_effect_from(connection, &intent.source.effect_id)?;
                loaded_effect
                    .observation
                    .as_ref()
                    .ok_or_else(|| LedgerError::Corrupt {
                        entity: "command output capture terminal anchor",
                        detail: "terminal anchor lacks its exact effect observation".into(),
                    })?
            };
            terminal
                .validate_against(&intent, acquired.as_ref(), observation)
                .map_err(|error| LedgerError::Corrupt {
                    entity: "command output capture terminal anchor",
                    detail: error.to_string(),
                })?;
            if encode("command output capture terminal anchor", &terminal)? != bytes {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal anchor",
                    detail: "stored JSON is not the canonical terminal encoding".into(),
                });
            }
            require_exact_terminal_row(connection, &terminal, &bytes)?;
            validate_terminal_validation(connection, &intent, acquired.as_ref(), &terminal)?;
            Ok(terminal)
        })
        .transpose()?;

    struct StoredResolutionRow {
        bytes: Vec<u8>,
        physical_receipt_digest: String,
        resolution_anchor_digest: String,
        capture_id: String,
        effect_id: String,
        observation_id: String,
        terminal_anchor_digest: String,
        reconciliation_claim_id: String,
        reconciliation_fencing_token: String,
        disposition: String,
        store_head_generation: i64,
        store_head_digest: String,
        resolution_record_digest: String,
        artifact_manifest_digest: Option<String>,
        artifact_reference_json: Option<Vec<u8>>,
        command_cleanup_proof_id: String,
        runner_cleanup_receipt_id: String,
        resolved_at_unix_ms: i64,
        layout_version: i64,
        contract_version: i64,
    }

    let resolution_row = connection
        .query_row(
            "SELECT resolution_json, physical_recovery_receipt_digest,
                    resolution_anchor_digest, capture_id, effect_id, observation_id,
                    terminal_anchor_digest, reconciliation_claim_id,
                    reconciliation_fencing_token, disposition,
                    store_head_generation, store_head_digest,
                    resolution_record_digest, artifact_manifest_digest,
                    artifact_reference_json, command_domain_cleanup_proof_id,
                    runner_cleanup_receipt_id, resolved_at_unix_ms,
                    layout_version, contract_version
             FROM command_output_capture_reconciliation_resolutions
             WHERE capture_id = ?1",
            [capture_id],
            |row| {
                Ok(StoredResolutionRow {
                    bytes: row.get(0)?,
                    physical_receipt_digest: row.get(1)?,
                    resolution_anchor_digest: row.get(2)?,
                    capture_id: row.get(3)?,
                    effect_id: row.get(4)?,
                    observation_id: row.get(5)?,
                    terminal_anchor_digest: row.get(6)?,
                    reconciliation_claim_id: row.get(7)?,
                    reconciliation_fencing_token: row.get(8)?,
                    disposition: row.get(9)?,
                    store_head_generation: row.get(10)?,
                    store_head_digest: row.get(11)?,
                    resolution_record_digest: row.get(12)?,
                    artifact_manifest_digest: row.get(13)?,
                    artifact_reference_json: row.get(14)?,
                    command_cleanup_proof_id: row.get(15)?,
                    runner_cleanup_receipt_id: row.get(16)?,
                    resolved_at_unix_ms: row.get(17)?,
                    layout_version: row.get(18)?,
                    contract_version: row.get(19)?,
                })
            },
        )
        .optional()?;
    let reconciliation_resolution = resolution_row
        .map(|stored| {
            let resolution: CommandOutputCaptureReconciliationResolutionV1 = super::decode_stored(
                "command output capture reconciliation resolution",
                &stored.bytes,
            )?;
            let expected_artifact_manifest = resolution
                .artifact_reference
                .as_ref()
                .map(|reference| reference.manifest_digest.as_str());
            let expected_artifact_json = resolution
                .artifact_reference
                .as_ref()
                .map(|reference| encode("command output resolution artifact", reference))
                .transpose()?;
            if stored.resolution_anchor_digest != resolution.resolution_anchor_digest.as_str()
                || stored.capture_id != resolution.capture_id
                || stored.effect_id != resolution.effect_id
                || stored.observation_id != resolution.observation_id
                || stored.terminal_anchor_digest != resolution.terminal_anchor_digest.as_str()
                || stored.reconciliation_claim_id != resolution.reconciliation_claim_id
                || stored.reconciliation_fencing_token
                    != resolution.reconciliation_fencing_token.as_str()
                || stored.disposition != resolution.disposition.storage_name()
                || stored.store_head_generation
                    != sqlite_integer(
                        "command output resolution store generation",
                        resolution.store_head.generation,
                    )?
                || stored.store_head_digest != resolution.store_head.record_digest.as_str()
                || stored.resolution_record_digest != resolution.resolution_record_digest.as_str()
                || stored.artifact_manifest_digest.as_deref() != expected_artifact_manifest
                || stored.artifact_reference_json != expected_artifact_json
                || stored.command_cleanup_proof_id.trim().is_empty()
                || stored.runner_cleanup_receipt_id.trim().is_empty()
                || stored.resolved_at_unix_ms
                    != sqlite_integer(
                        "command output resolution time",
                        resolution.resolved_at_unix_ms,
                    )?
                || stored.layout_version != i64::from(resolution.layout_version)
                || stored.contract_version != i64::from(resolution.contract_version)
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation resolution",
                    detail: "redundant resolution columns differ from canonical JSON".into(),
                });
            }
            let terminal = terminal.as_ref().ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture reconciliation resolution",
                detail: "resolution lacks its immutable Unknown terminal".into(),
            })?;
            let claim =
                load_latest_reconciliation_claim(connection, capture_id)?.ok_or_else(|| {
                    LedgerError::Corrupt {
                        entity: "command output capture reconciliation resolution",
                        detail: "resolution lacks its exact reconciliation claim".into(),
                    }
                })?;
            let physical_receipt =
                load_restart_recovery_receipt(connection, &stored.physical_receipt_digest)?;
            let validation = if resolution.store_head == terminal.store_head {
                let acquired = acquired.as_ref().ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture reconciliation resolution",
                    detail: "restart same-head resolution lacks its exact acquisition".into(),
                })?;
                let restart_receipt = load_restart_claimed_unresolved_receipt_for_terminal(
                    connection,
                    &terminal.terminal_anchor_digest,
                )?
                .ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture reconciliation resolution",
                    detail: "same-head resolution lacks RestartClaimedUnresolved evidence".into(),
                })?;
                if physical_receipt == restart_receipt {
                    resolution.validate_against_restart_same_head(
                        &intent,
                        acquired,
                        terminal,
                        &claim,
                        &restart_receipt,
                    )
                } else {
                    Err(ContractError::new(
                        "command_output_capture_reconciliation_resolution_v1.restart_same_head",
                        "resolution receipt FK must select the original restart terminal receipt",
                    ))
                }
            } else {
                let acquired = acquired.as_ref().ok_or_else(|| LedgerError::Corrupt {
                    entity: "command output capture reconciliation resolution",
                    detail: "advancing resolution lacks its exact acquisition".into(),
                })?;
                physical_receipt.validate_for_unknown_resolution(
                    &intent,
                    acquired,
                    terminal,
                    &claim,
                    &resolution,
                )
            };
            validation.map_err(|error| LedgerError::Corrupt {
                entity: "command output capture reconciliation resolution",
                detail: error.to_string(),
            })?;
            if encode(
                "command output capture reconciliation resolution",
                &resolution,
            )? != stored.bytes
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation resolution",
                    detail: "stored JSON is not the canonical resolution encoding".into(),
                });
            }
            validate_reconciliation_resolution_authority(
                connection,
                &intent,
                terminal,
                &claim,
                &resolution,
            )?;
            Ok(resolution)
        })
        .transpose()?;

    let obligation_id = reconciliation_obligation_id(capture_id);
    let stored_obligation = connection
        .query_row(
            "SELECT obligation_id, capture_id, effect_id, intent_digest, contract_version
             FROM command_output_capture_reconciliation_obligations
             WHERE capture_id = ?1",
            [capture_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output capture reconciliation lease",
            detail: "capture intent lacks its immutable reconciliation lease".into(),
        })?;
    if stored_obligation.0 != obligation_id
        || stored_obligation.1 != intent.capture_id
        || stored_obligation.2 != intent.source.effect_id
        || stored_obligation.3 != intent.intent_digest.as_str()
        || stored_obligation.4 != i64::from(intent.contract_version)
    {
        return Err(LedgerError::Corrupt {
            entity: "command output capture reconciliation obligation",
            detail: "obligation columns differ from the exact capture intent".into(),
        });
    }
    let reconciliation_obligation_closure = connection
        .query_row(
            "SELECT obligation_id, capture_id, effect_id, terminal_anchor_digest,
                    closed_at_unix_ms, contract_version
             FROM command_output_capture_reconciliation_obligation_closures
             WHERE obligation_id = ?1",
            [&obligation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .map(|stored| {
            let terminal = terminal.as_ref().ok_or_else(|| LedgerError::Corrupt {
                entity: "command output capture reconciliation obligation closure",
                detail: "closure exists without an immutable terminal".into(),
            })?;
            let expected_closed_at = match terminal.disposition {
                CommandOutputCaptureTerminalDispositionV1::Published
                | CommandOutputCaptureTerminalDispositionV1::Abandoned => {
                    terminal.anchored_at_unix_ms
                }
                CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired => {
                    reconciliation_resolution
                        .as_ref()
                        .ok_or_else(|| LedgerError::Corrupt {
                            entity: "command output capture reconciliation obligation closure",
                            detail: "Unknown closure lacks its exact resolution".into(),
                        })?
                        .resolved_at_unix_ms
                }
            };
            if stored.0 != obligation_id
                || stored.1 != intent.capture_id
                || stored.2 != intent.source.effect_id
                || stored.3 != terminal.terminal_anchor_digest.as_str()
                || stored.4
                    != sqlite_integer(
                        "command output capture obligation closure time",
                        expected_closed_at,
                    )?
                || stored.5 != i64::from(intent.contract_version)
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation obligation closure",
                    detail: "closure columns differ from exact terminal or resolution authority"
                        .into(),
                });
            }
            Ok(terminal.terminal_anchor_digest.clone())
        })
        .transpose()?;
    if let Some(terminal) = terminal.as_ref() {
        let exact_closure =
            reconciliation_obligation_closure.as_ref() == Some(&terminal.terminal_anchor_digest);
        match terminal.disposition {
            CommandOutputCaptureTerminalDispositionV1::Published
            | CommandOutputCaptureTerminalDispositionV1::Abandoned
                if !exact_closure || reconciliation_resolution.is_some() =>
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation obligation closure",
                    detail: "direct terminal closure or resolution shape is crossed".into(),
                });
            }
            CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                if reconciliation_resolution.is_some() != exact_closure =>
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation obligation closure",
                    detail: "Unknown terminal resolution and closure must appear atomically".into(),
                });
            }
            _ => {}
        }
    } else if reconciliation_resolution.is_some() || reconciliation_obligation_closure.is_some() {
        return Err(LedgerError::Corrupt {
            entity: "command output capture reconciliation obligation closure",
            detail: "resolution or closure exists without a terminal anchor".into(),
        });
    }
    Ok(PersistedCommandOutputCapture {
        intent,
        acquired,
        terminal,
        reconciliation_resolution,
        reconciliation_obligation_id: obligation_id,
        reconciliation_obligation_closure,
    })
}

fn validate_reconciliation_resolution_authority(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
) -> Result<(), LedgerError> {
    let exact = connection.query_row(
        "SELECT EXISTS (
             SELECT 1
             FROM command_output_capture_reconciliation_resolutions resolution
             JOIN effect_intents effect_intent
               ON effect_intent.effect_id = resolution.effect_id
              AND effect_intent.sprint_id = ?2
             JOIN command_output_capture_reconciliation_claim_releases release
              ON release.claim_id = resolution.reconciliation_claim_id
              AND release.capture_id = resolution.capture_id
              AND release.fencing_token = resolution.reconciliation_fencing_token
              AND release.claim_epoch = ?14
              AND release.contract_version = ?12
              AND release.release_kind = 'ConsumedTerminal'
              AND release.terminal_anchor_digest = resolution.terminal_anchor_digest
              AND release.released_at_unix_ms = resolution.resolved_at_unix_ms
             JOIN command_output_capture_restart_recovery_receipts physical
               ON physical.receipt_digest = resolution.physical_recovery_receipt_digest
              AND physical.capture_id = resolution.capture_id
              AND physical.effect_id = resolution.effect_id
             JOIN command_domain_cleanup_proofs command_cleanup
               ON command_cleanup.proof_id = resolution.command_domain_cleanup_proof_id
              AND command_cleanup.sprint_id = ?2
              AND command_cleanup.effect_id = resolution.effect_id
              AND command_cleanup.observation_id = resolution.observation_id
              AND command_cleanup.launch_id = ?3
              AND command_cleanup.session_id = ?4
              AND command_cleanup.request_digest = ?11
              AND command_cleanup.disposition = 'ReapedZeroSurvivors'
              AND command_cleanup.surviving_processes = 0
              AND command_cleanup.contract_version = ?12
              AND command_cleanup.cleaned_at_unix_ms >= ?13
              AND command_cleanup.cleaned_at_unix_ms <= resolution.resolved_at_unix_ms
             JOIN worker_cleanup_receipts runner_cleanup
               ON runner_cleanup.sprint_id = ?2
              AND runner_cleanup.receipt_id = resolution.runner_cleanup_receipt_id
              AND runner_cleanup.launch_id = ?3
              AND runner_cleanup.session_id = ?4
              AND runner_cleanup.worker_lease_id IS effect_intent.worker_lease_id
              AND runner_cleanup.worker_lease_epoch IS effect_intent.worker_lease_epoch
              AND runner_cleanup.surviving_processes = 0
              AND runner_cleanup.contract_version = ?12
              AND runner_cleanup.cleaned_at_unix_ms >= ?13
              AND runner_cleanup.cleaned_at_unix_ms <= resolution.resolved_at_unix_ms
             WHERE resolution.resolution_anchor_digest = ?1
               AND resolution.capture_id = ?5
               AND resolution.effect_id = ?6
               AND resolution.observation_id = ?7
               AND resolution.terminal_anchor_digest = ?8
               AND resolution.reconciliation_claim_id = ?9
               AND resolution.reconciliation_fencing_token = ?10
         )",
        params![
            resolution.resolution_anchor_digest.as_str(),
            intent.source.sprint_id,
            intent.source.runner_launch_id,
            intent.source.runner_session_id,
            intent.capture_id,
            intent.source.effect_id,
            terminal.observation_id,
            terminal.terminal_anchor_digest.as_str(),
            claim.claim_id,
            claim.fencing_token.as_str(),
            intent.source.request_digest.as_str(),
            i64::from(intent.contract_version),
            sqlite_integer(
                "command output capture terminal anchored time",
                terminal.anchored_at_unix_ms,
            )?,
            sqlite_integer(
                "command output capture reconciliation claim epoch",
                claim.claim_epoch,
            )?,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !exact {
        return Err(LedgerError::Corrupt {
            entity: "command output capture reconciliation resolution",
            detail: "resolution lacks exact claim release and zero-survivor cleanup authority"
                .into(),
        });
    }
    Ok(())
}
#[allow(clippy::too_many_lines)]
fn validate_terminal_validation(
    connection: &Connection,
    intent: &CommandOutputCaptureIntentV1,
    acquired: Option<&CommandOutputCaptureAcquiredV1>,
    terminal: &CommandOutputCaptureTerminalAnchorV1,
) -> Result<(), LedgerError> {
    let stored = connection
        .query_row(
            "SELECT capture_id, effect_id, observation_id, validation_kind,
                    command_domain_cleanup_proof_id, reconciliation_claim_id,
                    reconciliation_fencing_token, runner_cleanup_receipt_id,
                    restart_recovery_receipt_digest, sprint_id, contract_version,
                    terminal_anchored_at_unix_ms
             FROM command_output_capture_terminal_validations
             WHERE terminal_anchor_digest = ?1",
            [terminal.terminal_anchor_digest.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::Corrupt {
            entity: "command output capture terminal validation",
            detail: "terminal anchor lacks its immutable authority companion".into(),
        })?;
    if stored.0 != terminal.capture_id
        || stored.1 != terminal.effect_id
        || stored.2 != terminal.observation_id
        || stored.9 != intent.source.sprint_id
        || stored.10 != i64::from(terminal.contract_version)
        || stored.11
            != sqlite_integer(
                "command output capture terminal validation anchored time",
                terminal.anchored_at_unix_ms,
            )?
    {
        return Err(LedgerError::Corrupt {
            entity: "command output capture terminal validation",
            detail: "validation identity or contract columns cross the terminal anchor".into(),
        });
    }
    match stored.3.as_str() {
        "PreDispatchAbandoned"
            if stored.4.is_none()
                && stored.5.is_none()
                && stored.6.is_none()
                && stored.7.is_none()
                && stored.8.is_none()
                && acquired.is_none()
                && terminal.dispatch_claim_id.is_none()
                && terminal.disposition == CommandOutputCaptureTerminalDispositionV1::Abandoned => {
        }
        "DirectClaimed"
            if stored.4.is_some()
                && stored.5.is_none()
                && stored.6.is_none()
                && stored.7.is_none()
                && stored.8.is_none()
                && acquired.is_some() =>
        {
            let exact = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1
                     FROM command_domain_cleanup_proofs proof
                     JOIN effect_observations observation
                       ON observation.effect_id = proof.effect_id
                      AND observation.observation_id = proof.observation_id
                      AND observation.sprint_id = proof.sprint_id
                      AND observation.contract_version = proof.contract_version
                     WHERE proof.proof_id = ?1
                       AND proof.sprint_id = ?2
                       AND proof.launch_id = ?3
                       AND proof.session_id = ?4
                       AND proof.effect_id = ?5
                       AND proof.observation_id = ?6
                       AND proof.request_digest = ?7
                       AND proof.surviving_processes = 0
                       AND proof.contract_version = ?8
                       AND proof.cleaned_at_unix_ms >= observation.observed_at_unix_ms
                       AND proof.cleaned_at_unix_ms <= ?9
                       AND (
                           proof.disposition = 'ReapedZeroSurvivors'
                           OR (?10 IN ('FailedBeforeEffect', 'CancelledBeforeEffect')
                               AND proof.disposition = 'NoDomainCreatedBeforeEffect')
                       )
                 )",
                params![
                    stored.4,
                    intent.source.sprint_id,
                    intent.source.runner_launch_id,
                    intent.source.runner_session_id,
                    terminal.effect_id,
                    terminal.observation_id,
                    intent.source.request_digest.as_str(),
                    i64::from(intent.contract_version),
                    sqlite_integer(
                        "command output capture terminal anchored time",
                        terminal.anchored_at_unix_ms,
                    )?,
                    terminal.observation_class.storage_name(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal validation",
                    detail: "direct terminal lacks its exact command-domain cleanup proof".into(),
                });
            }
        }
        "DirectClaimedUnresolved"
            if stored.4.is_none()
                && stored.5.is_none()
                && stored.6.is_none()
                && stored.7.is_none()
                && stored.8.is_none()
                && acquired.is_some()
                && terminal.observation_class
                    == CommandOutputCaptureObservationClassV1::Unknown
                && terminal.disposition
                    == CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                && acquired.is_some_and(|value| terminal.store_head == value.store_head) =>
        {
            let exact_record = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1
                     FROM effect_observations observation
                     WHERE observation.effect_id = ?1
                       AND observation.observation_id = ?2
                       AND observation.outcome = 'Unknown'
                       AND observation.evidence_digest = ?3
                 )",
                params![
                    terminal.effect_id,
                    terminal.observation_id,
                    terminal.terminal_record_digest.as_str(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact_record {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal validation",
                    detail:
                        "direct unresolved terminal does not bind the exact Unknown evidence record"
                            .into(),
                });
            }
        }
        "RestartIntentAbandoned"
        | "RestartClaimedBeforeLaunchAbandoned"
        | "RestartClaimedUnresolved"
        | "RestartTerminalPreparedPublished"
            if stored.5.is_some()
                && stored.6.is_some()
                && stored.7.is_none()
                && stored.8.is_some() =>
        {
            let receipt = load_restart_recovery_receipt(
                connection,
                stored.8.as_deref().expect("guarded restart receipt"),
            )?;
            receipt
                .validate_against(intent, &receipt.reconciliation_claim, acquired)
                .map_err(|error| LedgerError::Corrupt {
                    entity: "command output capture restart recovery receipt",
                    detail: error.to_string(),
                })?;
            let stored_claim = load_reconciliation_claim_by_id(
                connection,
                stored.5.as_deref().expect("guarded restart claim"),
            )?;
            let exact_claim = stored_claim.as_ref() == Some(&receipt.reconciliation_claim);
            let release =
                load_reconciliation_claim_release(connection, &receipt.reconciliation_claim)?;
            let exact_release = release.as_ref().is_some_and(
                |(release_kind, released_at, terminal_anchor_digest)| {
                    release_kind == "ConsumedTerminal"
                        && *released_at == terminal.anchored_at_unix_ms
                        && terminal_anchor_digest.as_ref() == Some(&terminal.terminal_anchor_digest)
                },
            );
            let branch_exact = match stored.3.as_str() {
                "RestartIntentAbandoned" => {
                    acquired.is_none()
                        && terminal.observation_class
                            == CommandOutputCaptureObservationClassV1::FailedBeforeEffect
                        && terminal.disposition
                            == CommandOutputCaptureTerminalDispositionV1::Abandoned
                        && receipt.launch_history.evidence().is_none()
                }
                "RestartClaimedBeforeLaunchAbandoned" => {
                    acquired.is_some()
                        && terminal.observation_class
                            == CommandOutputCaptureObservationClassV1::FailedBeforeEffect
                        && terminal.disposition
                            == CommandOutputCaptureTerminalDispositionV1::Abandoned
                        && receipt.physical_acquired.as_ref() == acquired
                        && receipt.launch_history.evidence().is_none()
                }
                "RestartClaimedUnresolved" => {
                    acquired.is_some()
                        && terminal.observation_class
                            == CommandOutputCaptureObservationClassV1::Unknown
                        && terminal.disposition
                            == CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
                        && receipt.launch_history.evidence().is_some()
                }
                "RestartTerminalPreparedPublished" => {
                    acquired.is_some()
                        && terminal.observation_class
                            == CommandOutputCaptureObservationClassV1::Succeeded
                        && terminal.disposition
                            == CommandOutputCaptureTerminalDispositionV1::Published
                        && receipt.physical_acquired.as_ref() == acquired
                        && receipt.launch_history.evidence().is_some()
                        && receipt.final_state
                            == CommandOutputCaptureRestartStateV1::TerminalPrepared
                        && receipt.artifact_reference.as_ref()
                            == terminal.artifact_reference.as_ref()
                }
                _ => false,
            };
            let expected_cleanup_disposition = match stored.3.as_str() {
                "RestartIntentAbandoned" | "RestartClaimedBeforeLaunchAbandoned" => {
                    Some("NoDomainCreatedBeforeEffect")
                }
                "RestartTerminalPreparedPublished" => Some("ReapedZeroSurvivors"),
                _ => None,
            };
            let cleanup_exact = match (stored.4.as_deref(), expected_cleanup_disposition) {
                (None, None) => true,
                (Some(proof_id), Some(disposition)) => connection.query_row(
                    "SELECT EXISTS (
                         SELECT 1 FROM command_domain_cleanup_proofs proof
                         WHERE proof.proof_id = ?1
                           AND proof.sprint_id = ?2
                           AND proof.launch_id = ?3
                           AND proof.session_id = ?4
                           AND proof.effect_id = ?5
                           AND proof.observation_id = ?6
                           AND proof.request_digest = ?7
                           AND proof.disposition = ?8
                           AND proof.surviving_processes = 0
                           AND proof.contract_version = ?9
                           AND proof.cleaned_at_unix_ms >= (
                               SELECT observation.observed_at_unix_ms
                               FROM effect_observations observation
                               WHERE observation.effect_id = ?5
                                 AND observation.observation_id = ?6
                           )
                           AND proof.cleaned_at_unix_ms <= ?10
                     )",
                    params![
                        proof_id,
                        intent.source.sprint_id,
                        intent.source.runner_launch_id,
                        intent.source.runner_session_id,
                        terminal.effect_id,
                        terminal.observation_id,
                        intent.source.request_digest.as_str(),
                        disposition,
                        i64::from(intent.contract_version),
                        sqlite_integer(
                            "command output capture terminal anchored time",
                            terminal.anchored_at_unix_ms,
                        )?,
                    ],
                    |row| row.get::<_, bool>(0),
                )?,
                _ => false,
            };
            let expected_terminal_record_digest = if stored.3 == "RestartTerminalPreparedPublished"
            {
                receipt
                    .terminal_prepared
                    .as_ref()
                    .map(|terminal| &terminal.canonical_bytes_digest)
            } else {
                Some(&receipt.reconciliation_digest)
            };
            let physical_evidence_exact = if matches!(
                stored.3.as_str(),
                "RestartIntentAbandoned"
                    | "RestartClaimedBeforeLaunchAbandoned"
                    | "RestartClaimedUnresolved"
            ) {
                let expected_bytes =
                    receipt
                        .canonical_evidence_bytes()
                        .map_err(|error| LedgerError::Corrupt {
                            entity: "command output capture restart recovery receipt",
                            detail: error.to_string(),
                        })?;
                let expected_digest =
                    receipt
                        .effect_evidence_digest()
                        .map_err(|error| LedgerError::Corrupt {
                            entity: "command output capture restart recovery receipt",
                            detail: error.to_string(),
                        })?;
                connection
                    .query_row(
                        "SELECT observation.evidence_digest, payload.evidence_digest,
                                payload.evidence_bytes
                         FROM effect_observations observation
                         JOIN effect_evidence_payloads payload
                           ON payload.effect_id = observation.effect_id
                          AND payload.observation_id = observation.observation_id
                          AND payload.sprint_id = observation.sprint_id
                          AND payload.contract_version = observation.contract_version
                         WHERE observation.effect_id = ?1
                           AND observation.observation_id = ?2
                           AND observation.sprint_id = ?3
                           AND observation.contract_version = ?4",
                        params![
                            terminal.effect_id,
                            terminal.observation_id,
                            intent.source.sprint_id,
                            i64::from(intent.contract_version),
                        ],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                            ))
                        },
                    )
                    .optional()?
                    .is_some_and(|(observation_digest, payload_digest, payload_bytes)| {
                        observation_digest == expected_digest.as_str()
                            && payload_digest == expected_digest.as_str()
                            && payload_bytes == expected_bytes
                    })
            } else {
                true
            };
            if !exact_claim
                || !exact_release
                || !cleanup_exact
                || !branch_exact
                || !physical_evidence_exact
                || receipt.reconciliation_claim.claim_id.as_str()
                    != stored.5.as_deref().expect("guarded restart claim")
                || receipt.reconciliation_claim.fencing_token.as_str()
                    != stored.6.as_deref().expect("guarded restart fence")
                || terminal.store_head != receipt.final_store_head
                || Some(&terminal.terminal_record_digest) != expected_terminal_record_digest
                || terminal.anchored_at_unix_ms != receipt.reconciled_at_unix_ms
            {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal validation",
                    detail:
                        "restart terminal lacks exact physical reconciliation and consumed claim"
                            .into(),
                });
            }
        }
        "RestartReconciliation"
            if stored.4.is_some()
                && stored.5.is_some()
                && stored.6.is_some()
                && stored.7.is_some()
                && stored.8.is_none()
                && acquired.is_some() =>
        {
            let stored_claim = load_reconciliation_claim_by_id(
                connection,
                stored.5.as_deref().expect("guarded restart claim"),
            )?;
            let Some(claim) = stored_claim.as_ref() else {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal validation",
                    detail: "recovery terminal lacks its exact latest reconciliation claim".into(),
                });
            };
            let exact_claim = claim.claim_id.as_str()
                == stored.5.as_deref().expect("guarded restart claim")
                && claim.fencing_token.as_str()
                    == stored.6.as_deref().expect("guarded restart fence");
            let release = load_reconciliation_claim_release(connection, claim)?;
            let exact_release = release.as_ref().is_some_and(
                |(release_kind, released_at, terminal_anchor_digest)| {
                    release_kind == "ConsumedTerminal"
                        && *released_at == terminal.anchored_at_unix_ms
                        && terminal_anchor_digest.as_ref() == Some(&terminal.terminal_anchor_digest)
                },
            );
            let exact_cleanup = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1
                     FROM effect_intents effect_intent
                     JOIN effect_observations observation
                       ON observation.effect_id = effect_intent.effect_id
                      AND observation.sprint_id = effect_intent.sprint_id
                      AND observation.observation_id = ?7
                      AND observation.contract_version = effect_intent.contract_version
                     JOIN worker_cleanup_receipts cleanup
                       ON cleanup.sprint_id = ?2
                      AND cleanup.receipt_id = ?3
                      AND cleanup.launch_id = ?4
                      AND cleanup.session_id = ?5
                      AND cleanup.worker_lease_id IS effect_intent.worker_lease_id
                      AND cleanup.worker_lease_epoch IS effect_intent.worker_lease_epoch
                      AND cleanup.surviving_processes = 0
                      AND cleanup.contract_version = ?9
                      AND cleanup.cleaned_at_unix_ms >= ?11
                      AND cleanup.cleaned_at_unix_ms <= ?10
                     JOIN command_domain_cleanup_proofs command_cleanup
                       ON command_cleanup.proof_id = ?1
                      AND command_cleanup.sprint_id = ?2
                      AND command_cleanup.launch_id = ?4
                      AND command_cleanup.session_id = ?5
                      AND command_cleanup.effect_id = ?6
                      AND command_cleanup.observation_id = ?7
                      AND command_cleanup.request_digest = ?8
                      AND command_cleanup.surviving_processes = 0
                      AND command_cleanup.contract_version = ?9
                      AND command_cleanup.cleaned_at_unix_ms >= observation.observed_at_unix_ms
                      AND command_cleanup.cleaned_at_unix_ms <= ?10
                      AND (
                          command_cleanup.disposition = 'ReapedZeroSurvivors'
                          OR (?12 IN ('FailedBeforeEffect', 'CancelledBeforeEffect')
                              AND command_cleanup.disposition = 'NoDomainCreatedBeforeEffect')
                      )
                     WHERE effect_intent.effect_id = ?6
                       AND effect_intent.sprint_id = ?2
                       AND effect_intent.request_digest = ?8
                       AND effect_intent.contract_version = ?9
                 )",
                params![
                    stored.4,
                    intent.source.sprint_id,
                    stored.7,
                    intent.source.runner_launch_id,
                    intent.source.runner_session_id,
                    terminal.effect_id,
                    terminal.observation_id,
                    intent.source.request_digest.as_str(),
                    i64::from(intent.contract_version),
                    sqlite_integer(
                        "command output capture terminal anchored time",
                        terminal.anchored_at_unix_ms,
                    )?,
                    sqlite_integer(
                        "command output capture reconciliation claim acquisition",
                        claim.acquired_at_unix_ms,
                    )?,
                    terminal.observation_class.storage_name(),
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact_claim || !exact_release || !exact_cleanup {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture terminal validation",
                    detail: "recovery terminal lacks exact fenced claim, runner cleanup, or command cleanup".into(),
                });
            }
        }
        _ => {
            return Err(LedgerError::Corrupt {
                entity: "command output capture terminal validation",
                detail: "validation branch does not match terminal lifecycle authority".into(),
            });
        }
    }
    Ok(())
}

pub(super) fn finish_is_proven_for_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<bool, LedgerError> {
    finish_is_proven_for_effect_with_validated_source(connection, effect_id, None)
}

pub(super) fn finish_is_proven_for_validated_effect(
    connection: &Connection,
    effect: &PersistedEffect,
    observation: &EffectObservation,
) -> Result<bool, LedgerError> {
    if effect.observation.as_ref() != Some(observation)
        || effect.intent.effect_id != observation.effect_id
    {
        return Err(reference_mismatch(
            "command output capture validated source",
            "caller-supplied observation differs from its fully validated effect",
        ));
    }
    finish_is_proven_for_effect_with_validated_source(
        connection,
        &effect.intent.effect_id,
        Some((effect, observation)),
    )
}

fn finish_is_proven_for_effect_with_validated_source(
    connection: &Connection,
    effect_id: &str,
    validated_source: Option<(&PersistedEffect, &EffectObservation)>,
) -> Result<bool, LedgerError> {
    // Command-output capture became a finish obligation in schema v27.  A
    // genuinely historical schema has no such obligation; once v27 is
    // installed, however, a missing row remains an unproven finish.
    if !schema_is_installed(connection)? {
        return Ok(true);
    }
    if super::sensitive_output_rejection::finish_is_proven_for_effect(connection, effect_id)? {
        return Ok(true);
    }
    let Some(capture) =
        load_from_effect_with_validated_source(connection, effect_id, validated_source)?
    else {
        return load_pre_v27_exemption(connection, effect_id);
    };
    let Some(terminal) = capture.terminal.as_ref() else {
        return Ok(false);
    };
    if capture.reconciliation_obligation_closure.as_ref() != Some(&terminal.terminal_anchor_digest)
    {
        return Ok(false);
    }
    let active_claim_exists =
        match load_latest_reconciliation_claim(connection, &capture.intent.capture_id)? {
            Some(claim) => load_reconciliation_claim_release(connection, &claim)?.is_none(),
            None => false,
        };
    if active_claim_exists {
        return Ok(false);
    }
    let effective_disposition = capture
        .reconciliation_resolution
        .as_ref()
        .map_or(terminal.disposition, |resolution| resolution.disposition);
    if effective_disposition == CommandOutputCaptureTerminalDispositionV1::Published
        && !super::sensitive_output_rejection::published_finish_is_proven_for_capture(
            connection,
            &capture.intent,
        )?
    {
        return Ok(false);
    }
    Ok(matches!(
        effective_disposition,
        CommandOutputCaptureTerminalDispositionV1::Published
            | CommandOutputCaptureTerminalDispositionV1::Abandoned
    ))
}

pub(super) fn sprint_finish_is_proven(
    connection: &Connection,
    sprint_id: &str,
) -> Result<bool, LedgerError> {
    if !schema_is_installed(connection)? {
        return Ok(true);
    }
    let mut statement = connection.prepare(
        "SELECT effect_id FROM effect_intents
         WHERE sprint_id = ?1 AND effect_kind = 'RunCommand'
         ORDER BY effect_id",
    )?;
    let ids = statement
        .query_map([sprint_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for effect_id in ids {
        if !finish_is_proven_for_effect(connection, &effect_id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn insert_reconciliation_claim(
    transaction: &Transaction<'_>,
    claim: &CommandOutputCaptureReconciliationClaimV1,
) -> Result<(), LedgerError> {
    claim.validate()?;
    transaction.execute(
        "INSERT INTO command_output_capture_reconciliation_claims (
            claim_id, capture_id, owner_id, claim_epoch, previous_claim_id,
            fencing_token, acquired_at_unix_ms, expires_at_unix_ms,
            claim_digest, contract_version, claim_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            claim.claim_id,
            claim.capture_id,
            claim.owner_id,
            sqlite_integer(
                "command_output_capture_reconciliation_claim.claim_epoch",
                claim.claim_epoch,
            )?,
            claim.previous_claim_id,
            claim.fencing_token.as_str(),
            sqlite_integer(
                "command_output_capture_reconciliation_claim.acquired_at_unix_ms",
                claim.acquired_at_unix_ms,
            )?,
            sqlite_integer(
                "command_output_capture_reconciliation_claim.expires_at_unix_ms",
                claim.expires_at_unix_ms,
            )?,
            claim.claim_digest.as_str(),
            i64::from(claim.contract_version),
            encode("command output capture reconciliation claim", claim)?,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)] // Full-chain validation prevents redundant-column corruption from rewinding claim CAS state.
fn load_latest_reconciliation_claim(
    connection: &Connection,
    capture_id: &str,
) -> Result<Option<CommandOutputCaptureReconciliationClaimV1>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT claim_id
         FROM command_output_capture_reconciliation_claims
         WHERE capture_id = ?1
            OR CASE WHEN json_valid(CAST(claim_json AS TEXT))
                    THEN json_extract(CAST(claim_json AS TEXT), '$.capture_id') = ?1
                    ELSE 0 END
         ORDER BY claim_id",
    )?;
    let claim_ids = statement
        .query_map([capture_id], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut claims = Vec::with_capacity(claim_ids.len());
    for claim_id in claim_ids {
        let claim = load_reconciliation_claim_by_id(connection, &claim_id)?.ok_or_else(|| {
            LedgerError::Corrupt {
                entity: "command output capture reconciliation claim",
                detail: "claim history changed while its exact row was being loaded".into(),
            }
        })?;
        if claim.capture_id != capture_id {
            return Err(LedgerError::Corrupt {
                entity: "command output capture reconciliation claim",
                detail: "claim history crosses its canonical capture identity".into(),
            });
        }
        claims.push(claim);
    }
    claims.sort_by_key(|claim| claim.claim_epoch);
    for (index, claim) in claims.iter().enumerate() {
        let expected_epoch = u64::try_from(index)
            .map_err(|_| {
                LedgerError::IntegerOutOfRange(
                    "command output capture reconciliation claim history index",
                )
            })?
            .checked_add(1)
            .ok_or(LedgerError::IntegerOutOfRange(
                "command output capture reconciliation claim history epoch",
            ))?;
        let expected_previous = index
            .checked_sub(1)
            .and_then(|previous| claims.get(previous))
            .map(|previous| previous.claim_id.as_str());
        if claim.claim_epoch != expected_epoch
            || claim.previous_claim_id.as_deref() != expected_previous
        {
            return Err(LedgerError::Corrupt {
                entity: "command output capture reconciliation claim",
                detail: "claim history is not one contiguous predecessor chain".into(),
            });
        }
    }
    for pair in claims.windows(2) {
        let previous = &pair[0];
        let successor = &pair[1];
        let release =
            load_reconciliation_claim_release(connection, previous)?.ok_or_else(|| {
                LedgerError::Corrupt {
                    entity: "command output capture reconciliation claim",
                    detail: "claim successor exists without an exact predecessor release".into(),
                }
            })?;
        let exact_edge = match release.0.as_str() {
            "Released" => release.1 <= successor.acquired_at_unix_ms,
            "Expired" => {
                release.1 == successor.acquired_at_unix_ms
                    && previous.expires_at_unix_ms <= successor.acquired_at_unix_ms
            }
            "Superseded" => {
                release.1 == successor.acquired_at_unix_ms
                    && previous.owner_id == successor.owner_id
            }
            "ConsumedTerminal" => {
                if release.1 > successor.acquired_at_unix_ms {
                    false
                } else if let Some(terminal_digest) = release.2.as_ref() {
                    connection.query_row(
                        "SELECT EXISTS (
                             SELECT 1 FROM command_output_capture_terminal_anchors
                             WHERE terminal_anchor_digest = ?1
                               AND capture_id = ?2
                               AND observation_class = 'Unknown'
                               AND disposition = 'ReconciliationRequired'
                         )",
                        params![terminal_digest.as_str(), previous.capture_id],
                        |row| row.get::<_, bool>(0),
                    )?
                } else {
                    false
                }
            }
            _ => false,
        };
        if !exact_edge {
            return Err(LedgerError::Corrupt {
                entity: "command output capture reconciliation claim",
                detail: "claim predecessor release does not authorize its exact successor".into(),
            });
        }
    }
    if let Some(latest) = claims.last() {
        let _ = load_reconciliation_claim_release(connection, latest)?;
    }
    Ok(claims.pop())
}

fn load_reconciliation_claim_by_id(
    connection: &Connection,
    claim_id: &str,
) -> Result<Option<CommandOutputCaptureReconciliationClaimV1>, LedgerError> {
    let bytes = connection
        .query_row(
            "SELECT claim_json FROM command_output_capture_reconciliation_claims
             WHERE claim_id = ?1",
            [claim_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            let claim: CommandOutputCaptureReconciliationClaimV1 =
                super::decode_stored("command output capture reconciliation claim", &bytes)?;
            claim.validate().map_err(|error| LedgerError::Corrupt {
                entity: "command output capture reconciliation claim",
                detail: error.to_string(),
            })?;
            let exact = connection.query_row(
                "SELECT EXISTS (
                     SELECT 1 FROM command_output_capture_reconciliation_claims
                     WHERE claim_id = ?1 AND capture_id = ?2 AND owner_id = ?3
                       AND claim_epoch = ?4 AND previous_claim_id IS ?5
                       AND fencing_token = ?6 AND acquired_at_unix_ms = ?7
                       AND expires_at_unix_ms = ?8 AND claim_digest = ?9
                       AND contract_version = ?10 AND claim_json = ?11
                 )",
                params![
                    claim.claim_id,
                    claim.capture_id,
                    claim.owner_id,
                    sqlite_integer(
                        "command output capture reconciliation claim epoch",
                        claim.claim_epoch,
                    )?,
                    claim.previous_claim_id,
                    claim.fencing_token.as_str(),
                    sqlite_integer(
                        "command output capture reconciliation claim acquisition",
                        claim.acquired_at_unix_ms,
                    )?,
                    sqlite_integer(
                        "command output capture reconciliation claim expiry",
                        claim.expires_at_unix_ms,
                    )?,
                    claim.claim_digest.as_str(),
                    i64::from(claim.contract_version),
                    bytes,
                ],
                |row| row.get::<_, bool>(0),
            )?;
            if !exact {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation claim",
                    detail: "redundant claim columns differ from canonical JSON".into(),
                });
            }
            Ok(claim)
        })
        .transpose()
}

#[allow(clippy::too_many_lines)] // Every immutable release branch exact-compares its distinct authority fields.
pub(super) fn load_reconciliation_claim_release(
    connection: &Connection,
    claim: &CommandOutputCaptureReconciliationClaimV1,
) -> Result<Option<(String, u64, Option<Digest>)>, LedgerError> {
    struct StoredReleaseRow {
        claim_id: String,
        capture_id: String,
        claim_epoch: i64,
        fencing_token: String,
        release_kind: String,
        released_at_unix_ms: i64,
        terminal_anchor_digest: Option<String>,
        successor_claim_id: Option<String>,
        successor_fencing_token: Option<String>,
        successor_claim_digest: Option<String>,
        contract_version: i64,
    }
    let legacy = connection
        .query_row(
            "SELECT claim_id, capture_id, claim_epoch, fencing_token, release_kind,
                    released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
                    successor_fencing_token, successor_claim_digest, contract_version
             FROM command_output_capture_reconciliation_claim_releases
             WHERE claim_id = ?1",
            [&claim.claim_id],
            |row| {
                Ok(StoredReleaseRow {
                    claim_id: row.get(0)?,
                    capture_id: row.get(1)?,
                    claim_epoch: row.get(2)?,
                    fencing_token: row.get(3)?,
                    release_kind: row.get(4)?,
                    released_at_unix_ms: row.get(5)?,
                    terminal_anchor_digest: row.get(6)?,
                    successor_claim_id: row.get(7)?,
                    successor_fencing_token: row.get(8)?,
                    successor_claim_digest: row.get(9)?,
                    contract_version: row.get(10)?,
                })
            },
        )
        .optional()?
        .map(|stored| {
            let released_at = u64::try_from(stored.released_at_unix_ms).map_err(|_| {
                LedgerError::IntegerOutOfRange("command output capture reconciliation release time")
            })?;
            let terminal_digest = stored
                .terminal_anchor_digest
                .as_deref()
                .map(Digest::parse)
                .transpose()
                .map_err(|error| LedgerError::Corrupt {
                    entity: "command output capture reconciliation claim release",
                    detail: error.to_string(),
                })?;
            let exact_identity = stored.claim_id == claim.claim_id
                && stored.capture_id == claim.capture_id
                && stored.claim_epoch
                    == sqlite_integer(
                        "command output capture reconciliation release epoch",
                        claim.claim_epoch,
                    )?
                && stored.fencing_token == claim.fencing_token.as_str()
                && stored.contract_version == i64::from(claim.contract_version)
                && released_at >= claim.acquired_at_unix_ms;
            let exact_branch = match stored.release_kind.as_str() {
                "Released" => {
                    terminal_digest.is_none()
                        && stored.successor_claim_id.is_none()
                        && stored.successor_fencing_token.is_none()
                        && stored.successor_claim_digest.is_none()
                }
                "Expired" => {
                    released_at >= claim.expires_at_unix_ms
                        && terminal_digest.is_none()
                        && stored.successor_claim_id.is_none()
                        && stored.successor_fencing_token.is_none()
                        && stored.successor_claim_digest.is_none()
                }
                "ConsumedTerminal" => {
                    released_at < claim.expires_at_unix_ms
                        && terminal_digest.is_some()
                        && stored.successor_claim_id.is_none()
                        && stored.successor_fencing_token.is_none()
                        && stored.successor_claim_digest.is_none()
                        && connection.query_row(
                            "SELECT EXISTS (
                                 SELECT 1
                                 FROM command_output_capture_intents intent
                                 JOIN command_output_capture_terminal_anchors terminal
                                   ON terminal.capture_id = intent.capture_id
                                  AND terminal.effect_id = intent.effect_id
                                  AND terminal.terminal_anchor_digest = ?1
                                 LEFT JOIN command_output_capture_terminal_validations validation
                                   ON validation.terminal_anchor_digest =
                                      terminal.terminal_anchor_digest
                                  AND validation.capture_id = intent.capture_id
                                  AND validation.effect_id = intent.effect_id
                                  AND validation.observation_id = terminal.observation_id
                                  AND validation.reconciliation_claim_id = ?3
                                  AND validation.reconciliation_fencing_token = ?4
                                  AND validation.terminal_anchored_at_unix_ms = ?5
                                  AND validation.contract_version = ?6
                                 WHERE intent.capture_id = ?2
                                   AND terminal.contract_version = ?6
                                   AND (
                                       (terminal.observation_class = 'Unknown'
                                        AND terminal.disposition =
                                            'ReconciliationRequired'
                                        AND terminal.anchored_at_unix_ms <= ?5)
                                       OR (
                                           terminal.anchored_at_unix_ms = ?5
                                           AND validation.validation_kind IN (
                                               'RestartIntentAbandoned',
                                               'RestartClaimedBeforeLaunchAbandoned',
                                               'RestartClaimedUnresolved',
                                               'RestartTerminalPreparedPublished',
                                               'RestartReconciliation'
                                           )
                                       )
                                   )
                             )",
                            params![
                                terminal_digest.as_ref().map(Digest::as_str),
                                claim.capture_id,
                                claim.claim_id,
                                claim.fencing_token.as_str(),
                                stored.released_at_unix_ms,
                                i64::from(claim.contract_version),
                            ],
                            |row| row.get::<_, bool>(0),
                        )?
                }
                "Superseded" => {
                    released_at < claim.expires_at_unix_ms
                        && terminal_digest.is_none()
                        && stored.successor_claim_id.is_some()
                        && stored.successor_fencing_token.is_some()
                        && stored.successor_claim_digest.is_some()
                        && connection.query_row(
                            "SELECT EXISTS (
                                 SELECT 1
                                 FROM command_output_capture_reconciliation_claims successor
                                 WHERE successor.claim_id = ?1
                                   AND successor.capture_id = ?2
                                   AND successor.owner_id = ?3
                                   AND successor.claim_epoch = ?4
                                   AND successor.previous_claim_id = ?5
                                   AND successor.fencing_token = ?6
                                   AND successor.claim_digest = ?7
                                   AND successor.acquired_at_unix_ms = ?8
                                   AND successor.contract_version = ?9
                             )",
                            params![
                                stored.successor_claim_id,
                                claim.capture_id,
                                claim.owner_id,
                                sqlite_integer(
                                    "command output capture successor claim epoch",
                                    claim.claim_epoch.checked_add(1).ok_or(
                                        LedgerError::IntegerOutOfRange(
                                            "command output capture successor claim epoch",
                                        ),
                                    )?,
                                )?,
                                claim.claim_id,
                                stored.successor_fencing_token,
                                stored.successor_claim_digest,
                                stored.released_at_unix_ms,
                                i64::from(claim.contract_version),
                            ],
                            |row| row.get::<_, bool>(0),
                        )?
                }
                _ => false,
            };
            if !exact_identity || !exact_branch {
                return Err(LedgerError::Corrupt {
                    entity: "command output capture reconciliation claim release",
                    detail: "release row differs from its exact claim and branch authority".into(),
                });
            }
            Ok((stored.release_kind, released_at, terminal_digest))
        })
        .transpose()?;
    let v29_installed = connection.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'command_output_sensitive_rejection_claim_releases_v29'
         )",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !v29_installed {
        return Ok(legacy);
    }
    let stored = connection
        .query_row(
            "SELECT capture_id, claim_epoch, fencing_token,
                    rejection_anchor_digest, closure_digest,
                    released_at_unix_ms, contract_version
             FROM command_output_sensitive_rejection_claim_releases_v29
             WHERE claim_id = ?1",
            [&claim.claim_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    if legacy.is_some() && stored.is_some() {
        return Err(LedgerError::Corrupt {
            entity: "command output capture reconciliation claim release",
            detail: "legacy and v29 release families coexist for one claim".into(),
        });
    }
    if legacy.is_some() {
        return Ok(legacy);
    }
    stored
        .map(|stored| {
            let released_at = u64::try_from(stored.5).map_err(|_| {
                LedgerError::IntegerOutOfRange("v29 sensitive rejection claim release time")
            })?;
            let terminal_digest =
                Digest::parse(stored.3.clone()).map_err(|error| LedgerError::Corrupt {
                    entity: "v29 sensitive rejection claim release",
                    detail: error.to_string(),
                })?;
            let exact = stored.0 == claim.capture_id
                && stored.1
                    == sqlite_integer(
                        "v29 sensitive rejection claim release epoch",
                        claim.claim_epoch,
                    )?
                && stored.2 == claim.fencing_token.as_str()
                && stored.6 == i64::from(claim.contract_version)
                && released_at >= claim.acquired_at_unix_ms
                && released_at < claim.expires_at_unix_ms
                && connection.query_row(
                    "SELECT EXISTS (
                         SELECT 1
                         FROM command_output_sensitive_rejection_exact_finishes_v29 exact
                         JOIN command_output_sensitive_rejection_closures_v29 closure
                           ON closure.closure_digest = ?2
                          AND closure.rejection_anchor_digest = ?1
                          AND closure.reconciliation_claim_id = ?3
                          AND closure.reconciliation_fencing_token = ?4
                          AND closure.closed_at_unix_ms = ?5
                         WHERE exact.rejection_anchor_digest = ?1
                           AND exact.closure_digest = ?2
                     )",
                    params![
                        stored.3,
                        stored.4,
                        claim.claim_id,
                        claim.fencing_token.as_str(),
                        stored.5,
                    ],
                    |row| row.get::<_, bool>(0),
                )?;
            if !exact {
                return Err(LedgerError::Corrupt {
                    entity: "v29 sensitive rejection claim release",
                    detail: "release differs from exact latest claim and final rejection".into(),
                });
            }
            Ok((
                "ConsumedTerminal".to_owned(),
                released_at,
                Some(terminal_digest),
            ))
        })
        .transpose()
}

fn insert_reconciliation_claim_release(
    transaction: &Transaction<'_>,
    claim: &CommandOutputCaptureReconciliationClaimV1,
    release_kind: &str,
    released_at_unix_ms: u64,
    terminal_anchor_digest: Option<&Digest>,
    successor: Option<&CommandOutputCaptureReconciliationClaimV1>,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO command_output_capture_reconciliation_claim_releases (
            claim_id, capture_id, claim_epoch, fencing_token, release_kind,
            released_at_unix_ms, terminal_anchor_digest, successor_claim_id,
            successor_fencing_token, successor_claim_digest, contract_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            claim.claim_id,
            claim.capture_id,
            sqlite_integer(
                "command_output_capture_reconciliation_release.claim_epoch",
                claim.claim_epoch,
            )?,
            claim.fencing_token.as_str(),
            release_kind,
            sqlite_integer(
                "command_output_capture_reconciliation_release.released_at_unix_ms",
                released_at_unix_ms,
            )?,
            terminal_anchor_digest.map(Digest::as_str),
            successor.map(|claim| claim.claim_id.as_str()),
            successor.map(|claim| claim.fencing_token.as_str()),
            successor.map(|claim| claim.claim_digest.as_str()),
            i64::from(claim.contract_version),
        ],
    )?;
    Ok(())
}

fn require_capture_contract_and_layout(
    entity: &'static str,
    contract_version: u32,
    layout_version: u32,
) -> Result<(), ContractError> {
    if contract_version != CONTRACT_VERSION {
        return Err(ContractError::new(
            entity,
            format!("expected version {CONTRACT_VERSION}, got {contract_version}"),
        ));
    }
    if layout_version != COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION {
        return Err(ContractError::new(
            entity,
            format!(
                "expected version {COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION}, got {layout_version}"
            ),
        ));
    }
    Ok(())
}

fn require_capture_id(capture_id: &str) -> Result<(), ContractError> {
    Digest::parse(capture_id.to_owned())
        .map(|_| ())
        .map_err(|_| {
            ContractError::new(
                "command_output_capture.capture_id",
                "must contain exactly 64 lowercase hexadecimal characters",
            )
        })
}

fn require_capture_limit(limit: u64) -> Result<(), ContractError> {
    if limit == 0 || limit > MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES {
        return Err(ContractError::new(
            "command_output_capture.max_aggregate_output_bytes",
            format!("must be in 1..={MAX_COMMAND_OUTPUT_CAPTURE_AGGREGATE_BYTES}"),
        ));
    }
    Ok(())
}

fn compute_intent_digest(
    contract_version: u32,
    layout_version: u32,
    capture_id: &str,
    source: &CommandOutputArtifactSourceV1,
    private_state_digest: &Digest,
    max_aggregate_output_bytes: u64,
    created_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_INTENT_DIGEST_DOMAIN,
        &CanonicalCaptureIntent {
            contract_version,
            layout_version,
            capture_id,
            source,
            private_state_digest,
            max_aggregate_output_bytes,
            created_at_unix_ms,
        },
        "command_output_capture_intent_v1",
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_acquired_digest(
    intent: &CommandOutputCaptureIntentV1,
    dispatch_claim_id: &str,
    store_head: &CommandOutputCaptureStoreHeadV1,
    working_directory: &CommandOutputCaptureDirectoryIdentityV1,
    stdout: &CommandOutputCaptureFileIdentityV1,
    stderr: &CommandOutputCaptureFileIdentityV1,
    acquired_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    compute_acquired_digest_from_fields(
        intent.contract_version,
        intent.layout_version,
        &intent.capture_id,
        &intent.source,
        &intent.private_state_digest,
        intent.max_aggregate_output_bytes,
        &intent.intent_digest,
        dispatch_claim_id,
        store_head,
        working_directory,
        stdout,
        stderr,
        acquired_at_unix_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_acquired_digest_from_fields(
    contract_version: u32,
    layout_version: u32,
    capture_id: &str,
    source: &CommandOutputArtifactSourceV1,
    private_state_digest: &Digest,
    max_aggregate_output_bytes: u64,
    intent_digest: &Digest,
    dispatch_claim_id: &str,
    store_head: &CommandOutputCaptureStoreHeadV1,
    working_directory: &CommandOutputCaptureDirectoryIdentityV1,
    stdout: &CommandOutputCaptureFileIdentityV1,
    stderr: &CommandOutputCaptureFileIdentityV1,
    acquired_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_ACQUIRED_DIGEST_DOMAIN,
        &CanonicalCaptureAcquired {
            contract_version,
            layout_version,
            capture_id,
            source,
            private_state_digest,
            max_aggregate_output_bytes,
            intent_digest,
            dispatch_claim_id,
            store_head,
            working_directory,
            stdout,
            stderr,
            acquired_at_unix_ms,
        },
        "command_output_capture_acquired_v1",
    )
}

pub(super) fn expected_dispatch_claim_id(effect_id: &str) -> String {
    let mut preimage =
        Vec::with_capacity(RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN.len() + effect_id.len());
    preimage.extend_from_slice(RUNNER_EFFECT_DISPATCH_CLAIM_ID_DOMAIN);
    preimage.extend_from_slice(effect_id.as_bytes());
    Digest::sha256(&preimage).as_str().to_owned()
}

#[allow(clippy::too_many_arguments)]
fn compute_terminal_digest(
    intent: &CommandOutputCaptureIntentV1,
    observation: &EffectObservation,
    dispatch_claim_id: Option<&str>,
    acquired_anchor_digest: Option<&Digest>,
    observation_class: CommandOutputCaptureObservationClassV1,
    disposition: CommandOutputCaptureTerminalDispositionV1,
    store_head: &CommandOutputCaptureStoreHeadV1,
    terminal_record_digest: &Digest,
    artifact_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    anchored_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    compute_terminal_digest_from_fields(
        intent.contract_version,
        intent.layout_version,
        &intent.capture_id,
        &intent.source.effect_id,
        &observation.observation_id,
        dispatch_claim_id,
        &intent.intent_digest,
        acquired_anchor_digest,
        observation_class,
        disposition,
        store_head,
        terminal_record_digest,
        artifact_reference,
        anchored_at_unix_ms,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_terminal_digest_from_fields(
    contract_version: u32,
    layout_version: u32,
    capture_id: &str,
    effect_id: &str,
    observation_id: &str,
    dispatch_claim_id: Option<&str>,
    intent_digest: &Digest,
    acquired_anchor_digest: Option<&Digest>,
    observation_class: CommandOutputCaptureObservationClassV1,
    disposition: CommandOutputCaptureTerminalDispositionV1,
    store_head: &CommandOutputCaptureStoreHeadV1,
    terminal_record_digest: &Digest,
    artifact_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    anchored_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_TERMINAL_DIGEST_DOMAIN,
        &CanonicalCaptureTerminal {
            contract_version,
            layout_version,
            capture_id,
            effect_id,
            observation_id,
            dispatch_claim_id,
            intent_digest,
            acquired_anchor_digest,
            observation_class,
            disposition,
            store_head,
            terminal_record_digest,
            artifact_reference,
            anchored_at_unix_ms,
        },
        "command_output_capture_terminal_anchor_v1",
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_reconciliation_resolution_digest(
    contract_version: u32,
    layout_version: u32,
    capture_id: &str,
    effect_id: &str,
    observation_id: &str,
    terminal_anchor_digest: &Digest,
    reconciliation_claim_id: &str,
    reconciliation_fencing_token: &Digest,
    disposition: CommandOutputCaptureTerminalDispositionV1,
    store_head: &CommandOutputCaptureStoreHeadV1,
    resolution_record_digest: &Digest,
    artifact_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    resolved_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_RECONCILIATION_RESOLUTION_DIGEST_DOMAIN,
        &CanonicalCaptureReconciliationResolution {
            contract_version,
            layout_version,
            capture_id,
            effect_id,
            observation_id,
            terminal_anchor_digest,
            reconciliation_claim_id,
            reconciliation_fencing_token,
            disposition,
            store_head,
            resolution_record_digest,
            artifact_reference,
            resolved_at_unix_ms,
        },
        "command_output_capture_reconciliation_resolution_v1",
    )
}

fn compute_physical_history_digest(
    history: &[CommandOutputCapturePhysicalHistoryEntryV1],
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_PHYSICAL_HISTORY_DIGEST_DOMAIN,
        &history,
        "command_output_capture_physical_reconciliation_v1.lifecycle_history",
    )
}

#[derive(Serialize)]
struct CanonicalPhysicalFence<'a> {
    format_version: u32,
    capture_id: &'a str,
    predecessor_fence_digest: Option<&'a Digest>,
    claim: &'a CommandOutputCaptureReconciliationClaimV1,
}

fn compute_physical_fence_digest(
    capture_id: &str,
    predecessor_fence_digest: Option<&Digest>,
    claim: &CommandOutputCaptureReconciliationClaimV1,
) -> Result<Digest, ContractError> {
    let bytes = serde_json::to_vec(&CanonicalPhysicalFence {
        format_version: COMMAND_OUTPUT_CAPTURE_LAYOUT_VERSION,
        capture_id,
        predecessor_fence_digest,
        claim,
    })
    .map_err(|error| {
        ContractError::new(
            "command_output_capture_physical_reconciliation_v1.physical_fence_digest",
            format!("cannot encode exact runner fence preimage: {error}"),
        )
    })?;
    let mut preimage = Vec::with_capacity(CAPTURE_PHYSICAL_FENCE_DIGEST_DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(CAPTURE_PHYSICAL_FENCE_DIGEST_DOMAIN);
    preimage.extend_from_slice(&bytes);
    Ok(Digest::sha256(&preimage))
}

const fn valid_physical_history_transition(
    from: CommandOutputCaptureRestartStateV1,
    to: CommandOutputCaptureRestartStateV1,
) -> bool {
    matches!(
        (from, to),
        (
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureRestartStateV1::Acquired
                | CommandOutputCaptureRestartStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureRestartStateV1::WriterAttached
                | CommandOutputCaptureRestartStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureRestartStateV1::LaunchIntended
                | CommandOutputCaptureRestartStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureRestartStateV1::Finished
                | CommandOutputCaptureRestartStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureRestartStateV1::Published
                | CommandOutputCaptureRestartStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::Published,
            CommandOutputCaptureRestartStateV1::TerminalPrepared
        ) | (
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureRestartStateV1::Cleaned
        )
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_physical_reconciliation_digest(
    contract_version: u32,
    layout_version: u32,
    capture_id: &str,
    effect_id: &str,
    intent_digest: &Digest,
    reconciliation_claim: &CommandOutputCaptureReconciliationClaimV1,
    predecessor_fence_digest: Option<&Digest>,
    physical_fence_chain_length: u64,
    physical_fence_digest: &Digest,
    requested_store_head: Option<&CommandOutputCaptureStoreHeadV1>,
    initial_state: Option<CommandOutputCaptureRestartStateV1>,
    initial_store_head: Option<&CommandOutputCaptureStoreHeadV1>,
    pending_resolution: &CommandOutputCapturePendingResolutionV1,
    resolution_action: CommandOutputCapturePhysicalResolutionActionV1,
    lifecycle_history: &[CommandOutputCapturePhysicalHistoryEntryV1],
    lifecycle_history_digest: &Digest,
    final_state: CommandOutputCaptureRestartStateV1,
    final_store_head: &CommandOutputCaptureStoreHeadV1,
    physical_acquired: Option<&CommandOutputCaptureAcquiredV1>,
    physical_acquired_record_digest: Option<&Digest>,
    launch_history: &CommandOutputCaptureLaunchHistoryV1,
    finished_store_head: Option<&CommandOutputCaptureStoreHeadV1>,
    published_store_head: Option<&CommandOutputCaptureStoreHeadV1>,
    artifact_reference: Option<&CommandOutputArtifactSetReferenceV1>,
    terminal_prepared: Option<&CommandOutputCapturePhysicalTerminalEvidenceV1>,
    cleaned_store_head: Option<&CommandOutputCaptureStoreHeadV1>,
    cleanup_completion_proof_digest: Option<&Digest>,
    reconciled_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_RESTART_RECOVERY_RECEIPT_DIGEST_DOMAIN,
        &CanonicalCapturePhysicalReconciliation {
            contract_version,
            layout_version,
            capture_id,
            effect_id,
            intent_digest,
            reconciliation_claim,
            predecessor_fence_digest,
            physical_fence_chain_length,
            physical_fence_digest,
            requested_store_head,
            initial_state,
            initial_store_head,
            pending_resolution,
            resolution_action,
            lifecycle_history,
            lifecycle_history_digest,
            final_state,
            final_store_head,
            physical_acquired,
            physical_acquired_record_digest,
            launch_history,
            finished_store_head,
            published_store_head,
            artifact_reference,
            terminal_prepared,
            cleaned_store_head,
            cleanup_completion_proof_digest,
            reconciled_at_unix_ms,
        },
        "command_output_capture_physical_reconciliation_v1",
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_reconciliation_claim_digest(
    contract_version: u32,
    claim_id: &str,
    capture_id: &str,
    owner_id: &str,
    claim_epoch: u64,
    previous_claim_id: Option<&str>,
    fencing_token: &Digest,
    acquired_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<Digest, ContractError> {
    canonical_digest(
        CAPTURE_RECONCILIATION_CLAIM_DIGEST_DOMAIN,
        &CanonicalReconciliationClaim {
            contract_version,
            claim_id,
            capture_id,
            owner_id,
            claim_epoch,
            previous_claim_id,
            fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
        },
        "command_output_capture_reconciliation_claim_v1",
    )
}

fn reconciliation_fencing_token(
    capture_id: &str,
    claim_epoch: u64,
    claim_id: &str,
    owner_id: &str,
) -> Digest {
    let mut bytes =
        Vec::with_capacity(capture_id.len() + claim_id.len() + owner_id.len() + 8 + (4 * 8));
    for value in [
        capture_id.as_bytes(),
        claim_id.as_bytes(),
        owner_id.as_bytes(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&claim_epoch.to_be_bytes());
    digest_framed(CAPTURE_RECONCILIATION_FENCING_TOKEN_DOMAIN, &bytes)
}

fn canonical_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
    field: &'static str,
) -> Result<Digest, ContractError> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        ContractError::new(field, format!("cannot encode canonical JSON: {error}"))
    })?;
    let length = u64::try_from(canonical.len())
        .map_err(|_| ContractError::new(field, "canonical JSON exceeds u64 length"))?;
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

fn digest_framed(domain: &[u8], value: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + value.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(value.len() as u64).to_be_bytes());
    preimage.extend_from_slice(value);
    Digest::sha256(&preimage)
}

fn reconciliation_claim_is_live_at(
    claim: &CommandOutputCaptureReconciliationClaimV1,
    at_unix_ms: u64,
) -> bool {
    at_unix_ms >= claim.acquired_at_unix_ms && at_unix_ms < claim.expires_at_unix_ms
}

pub(super) fn sqlite_intent_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureIntentV1>(bytes, |value| {
        value.validate()?;
        Ok(value.intent_digest.clone())
    })
}

pub(super) fn sqlite_acquired_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureAcquiredV1>(bytes, |value| {
        value.validate()?;
        Ok(value.acquired_anchor_digest.clone())
    })
}

pub(super) fn sqlite_terminal_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureTerminalAnchorV1>(bytes, |value| {
        value.validate()?;
        Ok(value.terminal_anchor_digest.clone())
    })
}

pub(super) fn sqlite_reconciliation_claim_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureReconciliationClaimV1>(bytes, |value| {
        value.validate()?;
        Ok(value.claim_digest.clone())
    })
}

pub(super) fn sqlite_reconciliation_resolution_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureReconciliationResolutionV1>(bytes, |value| {
        value.validate()?;
        Ok(value.resolution_anchor_digest.clone())
    })
}

pub(super) fn sqlite_restart_recovery_receipt_digest(bytes: &[u8]) -> Result<String, String> {
    canonical_sql_digest::<CommandOutputCaptureRestartRecoveryReceiptV1>(bytes, |value| {
        value.validate()?;
        Ok(value.reconciliation_digest.clone())
    })
}

fn canonical_sql_digest<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<Digest, ContractError>,
) -> Result<String, String>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let digest = validate(&value).map_err(|error| error.to_string())?;
    let canonical = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    if canonical != bytes {
        return Err("capture authority JSON is not canonical".into());
    }
    Ok(digest.as_str().to_owned())
}

#[cfg(test)]
mod tests;
