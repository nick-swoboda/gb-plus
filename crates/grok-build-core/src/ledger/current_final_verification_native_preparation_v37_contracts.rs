//! Canonical schema-v37 native-preparation records and `SQLite` validators.
//!
//! These records are inert evidence contracts. They do not construct a native
//! source, call a service, release a child, dispatch work, or grant replay
//! authority. The connection-local write admission below only prevents direct
//! SQL from bypassing the owning ledger transaction.

use std::cell::RefCell;

use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, types::ValueRef};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    ContractError, CurrentFinalVerificationNativeContainmentBackendV2, Digest,
    MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2,
    MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2,
};

use super::LedgerError;
use super::current_final_verification_capture_v36::CurrentFinalVerificationCaptureAcquisitionAuthorityV1;
use super::current_final_verification_launch_v35::CurrentFinalVerificationLaunchAuthorityV1;

/// Current native-preparation contract version.
pub(super) const NATIVE_PREPARATION_VERSION_V1: u32 = 1;
/// Nominal replay domain of an authenticated native-preparation proof.
pub(super) const NATIVE_PREPARATION_OPERATION_DOMAIN_V1: &str = "NativePreparationV1";
/// Maximum exact service evidence retained by one preparation result.
pub(super) const MAX_NATIVE_PREPARATION_EVIDENCE_BYTES_V1: usize = 64 * 1024;
const RUNNER_PROTOCOL_VERSION_V13: u32 = 13;

pub(super) const NATIVE_PLATFORM_EXPECTATION_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-platform-expectation-v1/canonical-json\0";
pub(super) const NATIVE_PREPARATION_ATTEMPT_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-preparation-attempt-v1/canonical-json\0";
pub(super) const NATIVE_CLEANUP_OBLIGATION_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-cleanup-obligation-v1/canonical-json\0";
pub(super) const NATIVE_SOURCE_PAYLOAD_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-source-payload-v1/canonical-json\0";
pub(super) const NATIVE_SOURCE_CONSUMPTION_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-source-consumption-v1/canonical-json\0";
pub(super) const NATIVE_PREPARATION_OUTCOME_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-preparation-outcome-v1/canonical-json\0";
pub(super) const NATIVE_PREPARATION_EVIDENCE_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-preparation-evidence-v1/exact-bytes\0";
pub(super) const NATIVE_AUTHENTICATED_IDENTITY_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-authenticated-identity-v1/exact-bytes\0";

const WRITE_ADMISSION_FUNCTION: &str =
    "grok_current_final_verification_native_preparation_write_admitted_v37";

const SUPPORTED_TARGETS_V1: [&str; 3] = [
    "macos-15-apple-silicon",
    "ubuntu-26.04-x86_64",
    "fedora-44-x86_64",
];

/// Sealed comparison inputs for one supported target and native service.
///
/// The target image, authenticated service source, service protocol, runner
/// binary, and V13 protocol remain distinct identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePreparationPlatformExpectationV1 {
    expectation_version: u32,
    target_id: String,
    target_identity_digest: Digest,
    expected_source_identity_digest: Digest,
    expected_service_protocol_version: u32,
    expected_service_protocol_digest: Digest,
    expected_service_manifest_digest: Digest,
}

impl NativePreparationPlatformExpectationV1 {
    pub(super) fn target_id(&self) -> &str {
        &self.target_id
    }

    pub(super) const fn target_identity_digest(&self) -> &Digest {
        &self.target_identity_digest
    }

    pub(super) const fn expected_source_identity_digest(&self) -> &Digest {
        &self.expected_source_identity_digest
    }

    pub(super) const fn expected_service_protocol_version(&self) -> u32 {
        self.expected_service_protocol_version
    }

    pub(super) const fn expected_service_protocol_digest(&self) -> &Digest {
        &self.expected_service_protocol_digest
    }

    pub(super) const fn expected_service_manifest_digest(&self) -> &Digest {
        &self.expected_service_manifest_digest
    }

    #[cfg(test)]
    pub(super) fn set_target_id_for_test(&mut self, target_id: &str) {
        self.target_id = target_id.to_owned();
    }

    #[cfg(test)]
    pub(super) fn from_test(
        target_id: String,
        target_identity_digest: Digest,
        expected_source_identity_digest: Digest,
        expected_service_protocol_version: u32,
        expected_service_protocol_digest: Digest,
        expected_service_manifest_digest: Digest,
    ) -> Result<Self, ContractError> {
        let value = Self {
            expectation_version: NATIVE_PREPARATION_VERSION_V1,
            target_id,
            target_identity_digest,
            expected_source_identity_digest,
            expected_service_protocol_version,
            expected_service_protocol_digest,
            expected_service_manifest_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_platform_expectation.expectation_version",
            self.expectation_version,
        )?;
        if !SUPPORTED_TARGETS_V1.contains(&self.target_id.as_str()) {
            return Err(contract_error(
                "native_platform_expectation.target_id",
                "must name one closed v0.1 target",
            ));
        }
        if self.expected_service_protocol_version == 0 {
            return Err(contract_error(
                "native_platform_expectation.expected_service_protocol_version",
                "must be greater than zero",
            ));
        }
        require_canonical_bound("native_platform_expectation", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            NATIVE_PLATFORM_EXPECTATION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Exact durable native-preparation attempt committed before the callback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationNativePreparationAttemptV1 {
    /// Contract discriminator.
    pub preparation_version: u32,
    /// Reserved identity of this one native-preparation attempt.
    pub preparation_attempt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact current final-verification attempt.
    pub attempt_id: String,
    /// Exact schema-v35 launch authority.
    pub launch_authority_digest: Digest,
    /// Exact schema-v36 capture authority.
    pub capture_authority_digest: Digest,
    /// Exact physical capture anchor.
    pub acquired_anchor_digest: Digest,
    /// Reserved service-journal identity.
    pub native_journal_id: String,
    /// Reserved pending cleanup effect.
    pub cleanup_effect_id: String,
    /// Reserved native-preparation receipt.
    pub preparation_receipt_id: String,
    /// Separate supported-target and authenticated-service expectations.
    pub platform_expectation: NativePreparationPlatformExpectationV1,
    /// Exact compiled native containment policy.
    pub native_policy_digest: Digest,
    /// Exact admitted runner binary.
    pub runner_binary_digest: Digest,
    /// Exact admitted runner binary length.
    pub runner_binary_size_bytes: u64,
    /// Exact runner wire version.
    pub runner_protocol_version: u32,
    /// Exact runner protocol/schema identity.
    pub runner_protocol_digest: Digest,
    /// Stable private-state namespace.
    pub private_state_id: String,
    /// Exact private-state identity.
    pub private_state_digest: Digest,
    /// Exact workspace grant.
    pub workspace_grant_hash: Digest,
    /// Exact compiled execution policy.
    pub execution_policy_digest: Digest,
    /// Identity of the open ledger database object.
    pub ledger_database_identity_digest: Digest,
    /// Identity of the retained state root.
    pub state_root_identity_digest: Digest,
    /// Identity of the held launch/cleanup exclusion object.
    pub launch_cleanup_lock_identity_digest: Digest,
    /// Durable attempt-claim time.
    pub claimed_at_unix_ms: u64,
}

impl CurrentFinalVerificationNativePreparationAttemptV1 {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_preparation_attempt.preparation_version",
            self.preparation_version,
        )?;
        require_digest_identity(
            "native_preparation_attempt.preparation_attempt_id",
            &self.preparation_attempt_id,
        )?;
        require_identifier("native_preparation_attempt.sprint_id", &self.sprint_id)?;
        require_identifier("native_preparation_attempt.attempt_id", &self.attempt_id)?;
        for (field, value) in [
            (
                "native_preparation_attempt.native_journal_id",
                self.native_journal_id.as_str(),
            ),
            (
                "native_preparation_attempt.cleanup_effect_id",
                self.cleanup_effect_id.as_str(),
            ),
            (
                "native_preparation_attempt.preparation_receipt_id",
                self.preparation_receipt_id.as_str(),
            ),
        ] {
            require_digest_identity(field, value)?;
        }
        self.platform_expectation.validate()?;
        require_identifier(
            "native_preparation_attempt.private_state_id",
            &self.private_state_id,
        )?;
        if self.runner_binary_size_bytes == 0
            || i64::try_from(self.runner_binary_size_bytes).is_err()
        {
            return Err(contract_error(
                "native_preparation_attempt.runner_binary_size_bytes",
                "must fit a positive SQLite integer",
            ));
        }
        if self.runner_protocol_version != RUNNER_PROTOCOL_VERSION_V13 {
            return Err(contract_error(
                "native_preparation_attempt.runner_protocol_version",
                "must equal the admitted runner wire V13",
            ));
        }
        if self.claimed_at_unix_ms == 0 || i64::try_from(self.claimed_at_unix_ms).is_err() {
            return Err(contract_error(
                "native_preparation_attempt.claimed_at_unix_ms",
                "must fit a positive SQLite integer",
            ));
        }
        require_canonical_bound("native_preparation_attempt", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            NATIVE_PREPARATION_ATTEMPT_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    pub(super) fn validate_for_parent(
        &self,
        launch: &CurrentFinalVerificationLaunchAuthorityV1,
        capture: &CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        let preparation = &launch.launch_preparation;
        let reserved = &launch.reservations.fields;
        let target_matches_backend = match preparation.containment_backend {
            CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt => {
                self.platform_expectation.target_id == "macos-15-apple-silicon"
            }
            CurrentFinalVerificationNativeContainmentBackendV2::
                LinuxBubblewrapLandlockSeccompCgroupV2 => matches!(
                    self.platform_expectation.target_id.as_str(),
                    "ubuntu-26.04-x86_64" | "fedora-44-x86_64"
                ),
        };
        if self.sprint_id != launch.sprint_id
            || self.attempt_id != launch.attempt_id
            || self.attempt_id != capture.attempt_id
            || self.preparation_attempt_id != reserved.native_launch_preparation_attempt_id
            || self.native_journal_id != reserved.native_launch_journal_id
            || self.cleanup_effect_id != reserved.native_launch_cleanup_effect_id
            || self.preparation_receipt_id != reserved.native_launch_preparation_receipt_id
            || self.launch_authority_digest != launch.launch_authority_digest
            || self.launch_authority_digest != capture.launch_authority_digest
            || self.capture_authority_digest != capture.capture_authority_digest
            || self.acquired_anchor_digest != capture.acquired.acquired_anchor_digest
            || self.platform_expectation.target_identity_digest
                != preparation.target_identity_digest
            || !target_matches_backend
            || self.native_policy_digest != preparation.native_policy_digest
            || self.runner_binary_digest != preparation.runner_binary_digest
            || self.runner_binary_size_bytes != preparation.runner_binary_size_bytes
            || self.runner_protocol_version != preparation.runner_protocol_version
            || self.runner_protocol_digest != preparation.runner_protocol_digest
            || self.private_state_id != preparation.private_state_id
            || self.private_state_digest != preparation.private_state_digest
            || self.workspace_grant_hash != launch.workspace_grant.grant_hash
            || self.execution_policy_digest != launch.execution_policy.policy_hash
            || self.claimed_at_unix_ms < capture.acquired_at_unix_ms
        {
            return Err(contract_error(
                "native_preparation_attempt.parent",
                "crosses the exact v35 launch preparation or v36 capture authority",
            ));
        }
        Ok(())
    }
}

/// Only state admitted for the v37 cleanup obligation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum NativeCleanupObligationStateV1 {
    Pending,
}

/// Durable pending cleanup obligation paired atomically with the attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationNativeCleanupObligationV1 {
    /// Contract discriminator.
    pub obligation_version: u32,
    /// Exact cleanup effect reserved by schema v35.
    pub cleanup_effect_id: String,
    /// Exact paired schema-v37 attempt.
    pub preparation_attempt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact current final-verification attempt.
    pub attempt_id: String,
    /// Exact service-journal identity.
    pub native_journal_id: String,
    pub(super) state: NativeCleanupObligationStateV1,
}

impl CurrentFinalVerificationNativeCleanupObligationV1 {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_cleanup_obligation.obligation_version",
            self.obligation_version,
        )?;
        for (field, value) in [
            (
                "native_cleanup_obligation.cleanup_effect_id",
                self.cleanup_effect_id.as_str(),
            ),
            (
                "native_cleanup_obligation.preparation_attempt_id",
                self.preparation_attempt_id.as_str(),
            ),
            (
                "native_cleanup_obligation.native_journal_id",
                self.native_journal_id.as_str(),
            ),
        ] {
            require_digest_identity(field, value)?;
        }
        require_identifier("native_cleanup_obligation.sprint_id", &self.sprint_id)?;
        require_identifier("native_cleanup_obligation.attempt_id", &self.attempt_id)?;
        require_canonical_bound("native_cleanup_obligation", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            NATIVE_CLEANUP_OBLIGATION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    pub(super) fn validate_for_attempt(
        &self,
        attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if self.preparation_attempt_id != attempt.preparation_attempt_id
            || self.sprint_id != attempt.sprint_id
            || self.attempt_id != attempt.attempt_id
            || self.native_journal_id != attempt.native_journal_id
            || self.cleanup_effect_id != attempt.cleanup_effect_id
            || self.state != NativeCleanupObligationStateV1::Pending
        {
            return Err(contract_error(
                "native_cleanup_obligation.attempt",
                "crosses the exact native-preparation attempt",
            ));
        }
        Ok(())
    }
}

/// Closed disposition asserted by one authenticated native source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativePreparationDispositionV1 {
    /// The authenticated source reports a durably held child.
    HeldChildPrepared,
    /// The authenticated source refused before creating native state.
    RefusedBeforeNativeEffect,
    /// The authenticated source reports that native state may exist.
    NativeEffectUncertain,
}

/// Exact canonical payload authenticated by the lower native-service channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationNativePreparationSourcePayloadV1 {
    /// Contract discriminator.
    pub payload_version: u32,
    /// Exact schema-v37 attempt.
    pub preparation_attempt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact current final-verification attempt.
    pub attempt_id: String,
    /// Exact schema-v35 launch authority.
    pub launch_authority_digest: Digest,
    /// Exact schema-v36 capture authority.
    pub capture_authority_digest: Digest,
    /// Exact physical capture anchor.
    pub acquired_anchor_digest: Digest,
    /// Exact service-journal identity.
    pub native_journal_id: String,
    /// Exact pending cleanup effect.
    pub cleanup_effect_id: String,
    /// Exact reserved preparation receipt.
    pub preparation_receipt_id: String,
    /// Exact supported-target and authenticated-service expectation.
    pub platform_expectation: NativePreparationPlatformExpectationV1,
    /// Exact compiled native containment policy.
    pub native_policy_digest: Digest,
    /// Exact admitted runner binary.
    pub runner_binary_digest: Digest,
    /// Exact admitted runner binary length.
    pub runner_binary_size_bytes: u64,
    /// Exact runner wire version.
    pub runner_protocol_version: u32,
    /// Exact runner protocol/schema identity.
    pub runner_protocol_digest: Digest,
    /// Stable private-state namespace.
    pub private_state_id: String,
    /// Exact private-state identity.
    pub private_state_digest: Digest,
    /// Exact workspace grant.
    pub workspace_grant_hash: Digest,
    /// Exact compiled execution policy.
    pub execution_policy_digest: Digest,
    /// Digest of the OS-authenticated service source identity.
    pub authenticated_source_identity_digest: Digest,
    /// Digest of the live authenticated source session.
    pub source_session_identity_digest: Digest,
    /// Nominal operation replay domain.
    pub operation_domain: String,
    /// Source-owned canonical decimal u64 sequence.
    pub operation_sequence: String,
    /// Closed source-reported preparation disposition.
    pub disposition: NativePreparationDispositionV1,
    /// Digest of the exact native evidence bytes.
    pub native_evidence_digest: Digest,
    /// Exact bounded native evidence bytes.
    pub native_evidence_bytes: Vec<u8>,
    /// Source-reported preparation finish time.
    pub finished_at_unix_ms: u64,
}

impl CurrentFinalVerificationNativePreparationSourcePayloadV1 {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_source_payload.payload_version",
            self.payload_version,
        )?;
        require_digest_identity(
            "native_source_payload.preparation_attempt_id",
            &self.preparation_attempt_id,
        )?;
        require_identifier("native_source_payload.sprint_id", &self.sprint_id)?;
        require_identifier("native_source_payload.attempt_id", &self.attempt_id)?;
        for (field, value) in [
            (
                "native_source_payload.native_journal_id",
                self.native_journal_id.as_str(),
            ),
            (
                "native_source_payload.cleanup_effect_id",
                self.cleanup_effect_id.as_str(),
            ),
            (
                "native_source_payload.preparation_receipt_id",
                self.preparation_receipt_id.as_str(),
            ),
        ] {
            require_digest_identity(field, value)?;
        }
        self.platform_expectation.validate()?;
        require_identifier(
            "native_source_payload.private_state_id",
            &self.private_state_id,
        )?;
        if self.runner_binary_size_bytes == 0
            || i64::try_from(self.runner_binary_size_bytes).is_err()
        {
            return Err(contract_error(
                "native_source_payload.runner_binary_size_bytes",
                "must fit a positive SQLite integer",
            ));
        }
        if self.runner_protocol_version != RUNNER_PROTOCOL_VERSION_V13 {
            return Err(contract_error(
                "native_source_payload.runner_protocol_version",
                "must equal the admitted runner wire V13",
            ));
        }
        if self.operation_domain != NATIVE_PREPARATION_OPERATION_DOMAIN_V1 {
            return Err(contract_error(
                "native_source_payload.operation_domain",
                "must equal the native-preparation V1 replay domain",
            ));
        }
        canonical_operation_sequence(&self.operation_sequence)?;
        validate_native_evidence(&self.native_evidence_digest, &self.native_evidence_bytes)?;
        if self.finished_at_unix_ms == 0 || i64::try_from(self.finished_at_unix_ms).is_err() {
            return Err(contract_error(
                "native_source_payload.finished_at_unix_ms",
                "must fit a positive SQLite integer",
            ));
        }
        require_canonical_bound("native_source_payload", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(source_payload_digest_bytes(&self.canonical_bytes()?))
    }

    pub(super) fn validate_for_attempt(
        &self,
        attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
        cleanup: &CurrentFinalVerificationNativeCleanupObligationV1,
        authenticated_source_identity_digest: &Digest,
        source_session_identity_digest: &Digest,
        operation_sequence: &str,
        consumed_at_unix_ms: u64,
    ) -> Result<(), ContractError> {
        self.validate()?;
        cleanup.validate_for_attempt(attempt)?;
        canonical_operation_sequence(operation_sequence)?;
        if self.preparation_attempt_id != attempt.preparation_attempt_id
            || self.sprint_id != attempt.sprint_id
            || self.attempt_id != attempt.attempt_id
            || self.launch_authority_digest != attempt.launch_authority_digest
            || self.capture_authority_digest != attempt.capture_authority_digest
            || self.acquired_anchor_digest != attempt.acquired_anchor_digest
            || self.native_journal_id != attempt.native_journal_id
            || self.cleanup_effect_id != attempt.cleanup_effect_id
            || self.preparation_receipt_id != attempt.preparation_receipt_id
            || self.platform_expectation != attempt.platform_expectation
            || self.native_policy_digest != attempt.native_policy_digest
            || self.runner_binary_digest != attempt.runner_binary_digest
            || self.runner_binary_size_bytes != attempt.runner_binary_size_bytes
            || self.runner_protocol_version != attempt.runner_protocol_version
            || self.runner_protocol_digest != attempt.runner_protocol_digest
            || self.private_state_id != attempt.private_state_id
            || self.private_state_digest != attempt.private_state_digest
            || self.workspace_grant_hash != attempt.workspace_grant_hash
            || self.execution_policy_digest != attempt.execution_policy_digest
            || self.authenticated_source_identity_digest != *authenticated_source_identity_digest
            || self.authenticated_source_identity_digest
                != attempt.platform_expectation.expected_source_identity_digest
            || self.source_session_identity_digest != *source_session_identity_digest
            || self.operation_sequence != operation_sequence
            || consumed_at_unix_ms < attempt.claimed_at_unix_ms
            || self.finished_at_unix_ms > consumed_at_unix_ms
        {
            return Err(contract_error(
                "native_source_payload.attempt",
                "crosses its exact preparation, source, sequence, cleanup, policy, or time",
            ));
        }
        Ok(())
    }
}

/// Closed reason for retaining only rejection metadata, never source bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NativeSourceRejectionReasonV1 {
    /// Source bytes exceed the canonical payload limit.
    Oversized,
    /// Source bytes cannot decode as the declared contract.
    Malformed,
    /// Decoded source bytes are not exact canonical JSON.
    NonCanonical,
    /// Source payload crosses its durable parent identities.
    CrossedIdentity,
    /// Source or consumption time crosses the durable attempt.
    TimeInvalid,
    /// Native evidence is empty, oversized, or digest-inconsistent.
    EvidenceInvalid,
    /// The authenticated source identity differs from the sealed expectation.
    SourceIdentityMismatch,
}

/// Source-consumption terminal class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum NativeSourceConsumptionDispositionV1 {
    Accepted,
    SourceRejected,
}

/// Immutable source-consumption metadata.
///
/// This shape intentionally has no raw-payload field. Accepted payload bytes
/// live in their separately validated column. A rejected native-control
/// message retains only bounded length and one-way digest metadata so replay
/// and rejection classification stay auditable; no raw or reversible source
/// bytes are retained.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationNativeSourceConsumptionV1 {
    /// Contract discriminator.
    pub consumption_version: u32,
    /// Immutable identity of this consumption.
    pub source_consumption_id: String,
    /// Exact schema-v37 attempt.
    pub preparation_attempt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact current final-verification attempt.
    pub attempt_id: String,
    /// Nominal operation replay domain.
    pub operation_domain: String,
    /// Digest of the OS-authenticated service source identity.
    pub authenticated_source_identity_digest: Digest,
    /// Digest of the live authenticated source session.
    pub source_session_identity_digest: Digest,
    /// Source-owned canonical decimal u64 sequence.
    pub operation_sequence: String,
    /// Digest of the exact presented source bytes.
    pub payload_digest: Digest,
    /// Exact presented source byte length.
    pub payload_length: u64,
    pub(super) disposition: NativeSourceConsumptionDispositionV1,
    /// Typed reason retained only for rejection.
    pub rejection_reason: Option<NativeSourceRejectionReasonV1>,
    /// Exact receipt linked only for an accepted source.
    pub accepted_preparation_receipt_id: Option<String>,
    /// Core consumption time.
    pub consumed_at_unix_ms: u64,
}

impl CurrentFinalVerificationNativeSourceConsumptionV1 {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_source_consumption.consumption_version",
            self.consumption_version,
        )?;
        require_digest_identity(
            "native_source_consumption.source_consumption_id",
            &self.source_consumption_id,
        )?;
        require_digest_identity(
            "native_source_consumption.preparation_attempt_id",
            &self.preparation_attempt_id,
        )?;
        require_identifier("native_source_consumption.sprint_id", &self.sprint_id)?;
        require_identifier("native_source_consumption.attempt_id", &self.attempt_id)?;
        if self.operation_domain != NATIVE_PREPARATION_OPERATION_DOMAIN_V1 {
            return Err(contract_error(
                "native_source_consumption.operation_domain",
                "must equal the native-preparation V1 replay domain",
            ));
        }
        canonical_operation_sequence(&self.operation_sequence)?;
        if i64::try_from(self.payload_length).is_err() {
            return Err(contract_error(
                "native_source_consumption.payload_length",
                "must fit a nonnegative SQLite integer",
            ));
        }
        let canonical_bound = u64::try_from(MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2)
            .map_err(|_| {
                contract_error(
                    "native_source_consumption.payload_length",
                    "canonical source-payload bound does not fit u64",
                )
            })?;
        match (
            self.disposition,
            self.rejection_reason,
            self.accepted_preparation_receipt_id.as_deref(),
        ) {
            (NativeSourceConsumptionDispositionV1::Accepted, None, Some(receipt_id)) => {
                require_digest_identity(
                    "native_source_consumption.accepted_preparation_receipt_id",
                    receipt_id,
                )?;
                if self.payload_length == 0 {
                    return Err(contract_error(
                        "native_source_consumption.payload_length",
                        "accepted source payload must not be empty",
                    ));
                }
                if self.payload_length > canonical_bound {
                    return Err(contract_error(
                        "native_source_consumption.payload_length",
                        "accepted source payload exceeds the canonical bound",
                    ));
                }
            }
            (NativeSourceConsumptionDispositionV1::SourceRejected, Some(_), None) => {}
            _ => {
                return Err(contract_error(
                    "native_source_consumption.disposition",
                    "accepted requires one receipt and no rejection; rejected requires one reason and no receipt",
                ));
            }
        }
        match self.rejection_reason {
            Some(NativeSourceRejectionReasonV1::Oversized)
                if self.payload_length <= canonical_bound =>
            {
                return Err(contract_error(
                    "native_source_consumption.rejection_reason",
                    "Oversized requires a payload length above the canonical bound",
                ));
            }
            Some(
                NativeSourceRejectionReasonV1::Malformed
                | NativeSourceRejectionReasonV1::NonCanonical
                | NativeSourceRejectionReasonV1::CrossedIdentity
                | NativeSourceRejectionReasonV1::TimeInvalid
                | NativeSourceRejectionReasonV1::EvidenceInvalid,
            ) if self.payload_length > canonical_bound => {
                return Err(contract_error(
                    "native_source_consumption.rejection_reason",
                    "non-oversize rejection requires a payload within the canonical length bound",
                ));
            }
            _ => {}
        }
        if self.consumed_at_unix_ms == 0 || i64::try_from(self.consumed_at_unix_ms).is_err() {
            return Err(contract_error(
                "native_source_consumption.consumed_at_unix_ms",
                "must fit a positive SQLite integer",
            ));
        }
        require_canonical_bound("native_source_consumption", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            NATIVE_SOURCE_CONSUMPTION_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Exact outcome atomically paired with an accepted authenticated source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationNativePreparationOutcomeV1 {
    /// Contract discriminator.
    pub outcome_version: u32,
    /// Exact reserved native-preparation receipt.
    pub preparation_receipt_id: String,
    /// Exact schema-v37 attempt.
    pub preparation_attempt_id: String,
    /// Exact accepted source consumption.
    pub source_consumption_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact current final-verification attempt.
    pub attempt_id: String,
    /// Exact service-journal identity.
    pub native_journal_id: String,
    /// Exact still-pending cleanup effect.
    pub cleanup_effect_id: String,
    /// Closed source-derived disposition.
    pub disposition: NativePreparationDispositionV1,
    /// Digest of the exact native evidence.
    pub native_evidence_digest: Digest,
    /// Exact bounded native evidence bytes.
    pub native_evidence_bytes: Vec<u8>,
    /// Exact source-derived finish time.
    pub finished_at_unix_ms: u64,
}

impl CurrentFinalVerificationNativePreparationOutcomeV1 {
    pub(super) fn validate(&self) -> Result<(), ContractError> {
        require_version(
            "native_preparation_outcome.outcome_version",
            self.outcome_version,
        )?;
        for (field, value) in [
            (
                "native_preparation_outcome.preparation_receipt_id",
                self.preparation_receipt_id.as_str(),
            ),
            (
                "native_preparation_outcome.preparation_attempt_id",
                self.preparation_attempt_id.as_str(),
            ),
            (
                "native_preparation_outcome.source_consumption_id",
                self.source_consumption_id.as_str(),
            ),
            (
                "native_preparation_outcome.native_journal_id",
                self.native_journal_id.as_str(),
            ),
            (
                "native_preparation_outcome.cleanup_effect_id",
                self.cleanup_effect_id.as_str(),
            ),
        ] {
            require_digest_identity(field, value)?;
        }
        require_identifier("native_preparation_outcome.sprint_id", &self.sprint_id)?;
        require_identifier("native_preparation_outcome.attempt_id", &self.attempt_id)?;
        validate_native_evidence(&self.native_evidence_digest, &self.native_evidence_bytes)?;
        if self.finished_at_unix_ms == 0 || i64::try_from(self.finished_at_unix_ms).is_err() {
            return Err(contract_error(
                "native_preparation_outcome.finished_at_unix_ms",
                "must fit a positive SQLite integer",
            ));
        }
        require_canonical_bound("native_preparation_outcome", &encode_canonical(self)?)
    }

    pub(super) fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(self)
    }

    pub(super) fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            NATIVE_PREPARATION_OUTCOME_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }

    pub(super) fn validate_for_source(
        &self,
        source_payload: &CurrentFinalVerificationNativePreparationSourcePayloadV1,
        source_consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
        attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
        cleanup: &CurrentFinalVerificationNativeCleanupObligationV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        source_consumption.validate()?;
        cleanup.validate_for_attempt(attempt)?;
        source_payload.validate_for_attempt(
            attempt,
            cleanup,
            &source_consumption.authenticated_source_identity_digest,
            &source_consumption.source_session_identity_digest,
            &source_consumption.operation_sequence,
            source_consumption.consumed_at_unix_ms,
        )?;
        if source_consumption.disposition != NativeSourceConsumptionDispositionV1::Accepted
            || source_consumption.rejection_reason.is_some()
            || source_consumption
                .accepted_preparation_receipt_id
                .as_deref()
                != Some(self.preparation_receipt_id.as_str())
            || source_consumption.preparation_attempt_id != attempt.preparation_attempt_id
            || source_consumption.sprint_id != attempt.sprint_id
            || source_consumption.attempt_id != attempt.attempt_id
            || source_consumption.authenticated_source_identity_digest
                != source_payload.authenticated_source_identity_digest
            || source_consumption.source_session_identity_digest
                != source_payload.source_session_identity_digest
            || source_consumption.operation_domain != source_payload.operation_domain
            || source_consumption.operation_sequence != source_payload.operation_sequence
            || source_consumption.payload_digest != source_payload.canonical_digest()?
            || source_consumption.payload_length
                != u64::try_from(source_payload.canonical_bytes()?.len()).map_err(|_| {
                    contract_error(
                        "native_preparation_outcome.source_payload",
                        "canonical length does not fit u64",
                    )
                })?
            || self.preparation_receipt_id != attempt.preparation_receipt_id
            || self.preparation_receipt_id != source_payload.preparation_receipt_id
            || self.preparation_attempt_id != attempt.preparation_attempt_id
            || self.preparation_attempt_id != source_payload.preparation_attempt_id
            || self.source_consumption_id != source_consumption.source_consumption_id
            || self.sprint_id != attempt.sprint_id
            || self.sprint_id != source_payload.sprint_id
            || self.attempt_id != attempt.attempt_id
            || self.attempt_id != source_payload.attempt_id
            || self.native_journal_id != attempt.native_journal_id
            || self.native_journal_id != source_payload.native_journal_id
            || self.cleanup_effect_id != cleanup.cleanup_effect_id
            || self.cleanup_effect_id != source_payload.cleanup_effect_id
            || self.disposition != source_payload.disposition
            || self.native_evidence_digest != source_payload.native_evidence_digest
            || self.native_evidence_bytes != source_payload.native_evidence_bytes
            || self.finished_at_unix_ms != source_payload.finished_at_unix_ms
            || self.finished_at_unix_ms < attempt.claimed_at_unix_ms
            || self.finished_at_unix_ms > source_consumption.consumed_at_unix_ms
        {
            return Err(contract_error(
                "native_preparation_outcome.source",
                "does not derive exactly from the accepted source and pending obligation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "the closed writer-claim vocabulary intentionally repeats the record namespace"
)]
pub(super) struct NativePreparationSchemaWriteClaimV1 {
    pub(super) record_kind: String,
    pub(super) record_id: String,
    pub(super) record_digest: String,
}

thread_local! {
    static WRITE_ADMISSION: RefCell<Option<Vec<NativePreparationSchemaWriteClaimV1>>> =
        const { RefCell::new(None) };
}

struct WriteAdmissionGuard;

impl Drop for WriteAdmissionGuard {
    fn drop(&mut self) {
        WRITE_ADMISSION.with(|slot| {
            *slot.borrow_mut() = None;
        });
    }
}

/// Runs one owning ledger operation with only the named schema writes enabled.
pub(super) fn with_schema_write_admission<T>(
    claims: Vec<NativePreparationSchemaWriteClaimV1>,
    operation: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    if claims.is_empty()
        || claims.iter().any(|claim| {
            !matches!(
                claim.record_kind.as_str(),
                "attempt" | "cleanup" | "source" | "outcome"
            ) || Digest::parse(claim.record_id.clone()).is_err()
                || Digest::parse(claim.record_digest.clone()).is_err()
        })
    {
        return Err(LedgerError::Corrupt {
            entity: "current native-preparation write admission",
            detail: "write claims must be nonempty closed kinds with canonical identities"
                .to_owned(),
        });
    }
    let prior = WRITE_ADMISSION.with(|slot| slot.borrow_mut().replace(claims));
    if prior.is_some() {
        WRITE_ADMISSION.with(|slot| {
            *slot.borrow_mut() = prior;
        });
        return Err(LedgerError::Corrupt {
            entity: "current native-preparation write admission",
            detail: "nested write admission is forbidden".to_owned(),
        });
    }
    let _guard = WriteAdmissionGuard;
    operation()
}

fn write_is_admitted(record_kind: &str, record_id: &str, record_digest: &str) -> i64 {
    WRITE_ADMISSION.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|claims| {
            claims.iter().any(|claim| {
                claim.record_kind == record_kind
                    && claim.record_id == record_id
                    && claim.record_digest == record_digest
            })
        }))
    })
}

pub(super) fn source_payload_digest_bytes(bytes: &[u8]) -> Digest {
    domain_digest(NATIVE_SOURCE_PAYLOAD_DIGEST_DOMAIN_V1, bytes)
}

pub(super) fn native_evidence_digest(bytes: &[u8]) -> Digest {
    domain_digest(NATIVE_PREPARATION_EVIDENCE_DIGEST_DOMAIN_V1, bytes)
}

pub(super) fn raw_identity_digest(bytes: &[u8; 32]) -> Digest {
    domain_digest(NATIVE_AUTHENTICATED_IDENTITY_DIGEST_DOMAIN_V1, bytes)
}

pub(super) fn write_claim(
    record_kind: &str,
    record_id: &str,
    record_digest: &Digest,
) -> NativePreparationSchemaWriteClaimV1 {
    NativePreparationSchemaWriteClaimV1 {
        record_kind: record_kind.to_owned(),
        record_id: record_id.to_owned(),
        record_digest: record_digest.to_string(),
    }
}

pub(super) fn canonical_operation_sequence(value: &str) -> Result<u64, ContractError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(contract_error(
            "native_operation_sequence",
            "must be canonical decimal u64 text",
        ));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        contract_error(
            "native_operation_sequence",
            "must be canonical decimal u64 text",
        )
    })?;
    if parsed.to_string() != value {
        return Err(contract_error(
            "native_operation_sequence",
            "must round-trip as canonical decimal u64 text",
        ));
    }
    Ok(parsed)
}

fn validate_native_evidence(digest: &Digest, bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.is_empty() || bytes.len() > MAX_NATIVE_PREPARATION_EVIDENCE_BYTES_V1 {
        return Err(contract_error(
            "native_preparation_evidence",
            "must contain 1..=65536 exact bytes",
        ));
    }
    if *digest != native_evidence_digest(bytes) {
        return Err(contract_error(
            "native_preparation_evidence_digest",
            "does not authenticate the exact evidence bytes",
        ));
    }
    Ok(())
}

fn encode_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value).map_err(|error| {
        contract_error(
            "current_final_verification_native_preparation_v37.canonical_json",
            format!("cannot encode canonical JSON: {error}"),
        )
    })
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<(), ContractError>,
) -> Result<T, ContractError> {
    require_canonical_bound(
        "current_final_verification_native_preparation_v37.canonical_json",
        bytes,
    )?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| {
        contract_error(
            "current_final_verification_native_preparation_v37.canonical_json",
            "cannot decode the declared contract",
        )
    })?;
    validate(&value)?;
    if encode_canonical(&value)? != bytes {
        return Err(contract_error(
            "current_final_verification_native_preparation_v37.canonical_json",
            "is not exact canonical JSON",
        ));
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let output = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in output {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(encoded).expect("SHA-256 encoding is always a canonical digest")
}

fn require_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version == NATIVE_PREPARATION_VERSION_V1 {
        Ok(())
    } else {
        Err(contract_error(field, "must equal version 1"))
    }
}

fn require_identifier(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2
        || value.as_bytes().contains(&0)
    {
        Err(contract_error(
            field,
            format!(
                "must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2} non-NUL UTF-8 bytes and not be blank"
            ),
        ))
    } else {
        Ok(())
    }
}

fn require_digest_identity(field: &'static str, value: &str) -> Result<(), ContractError> {
    if Digest::parse(value.to_owned()).is_err() {
        Err(contract_error(
            field,
            "must contain exactly 64 lowercase hexadecimal bytes",
        ))
    } else {
        Ok(())
    }
}

fn require_canonical_bound(field: &'static str, bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        Err(contract_error(
            field,
            format!("must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes"),
        ))
    } else {
        Ok(())
    }
}

fn contract_error(field: &'static str, message: impl Into<String>) -> ContractError {
    ContractError::new(field, message)
}

fn sql_u32(context: &rusqlite::functions::Context<'_>, index: usize) -> Option<u32> {
    u32::try_from(context.get::<i64>(index).ok()?).ok()
}

fn sql_u64(context: &rusqlite::functions::Context<'_>, index: usize) -> Option<u64> {
    u64::try_from(context.get::<i64>(index).ok()?).ok()
}

fn sql_bytes_equal(context: &rusqlite::functions::Context<'_>, index: usize, bytes: &[u8]) -> bool {
    context
        .get_raw(index)
        .as_blob()
        .is_ok_and(|stored| stored == bytes)
}

fn sql_text(context: &rusqlite::functions::Context<'_>, index: usize) -> Option<String> {
    context.get::<String>(index).ok()
}

#[expect(
    clippy::option_option,
    reason = "outer None means wrong SQL type; inner None means canonical SQL NULL"
)]
fn sql_optional_text(
    context: &rusqlite::functions::Context<'_>,
    index: usize,
) -> Option<Option<String>> {
    match context.get_raw(index) {
        ValueRef::Null => Some(None),
        ValueRef::Text(value) => std::str::from_utf8(value)
            .ok()
            .map(|value| Some(value.to_owned())),
        _ => None,
    }
}

fn attempt_projection_matches(
    attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
    context: &rusqlite::functions::Context<'_>,
) -> bool {
    let expectation_digest = attempt.platform_expectation.canonical_digest().ok();
    Some(attempt.preparation_attempt_id.clone()) == sql_text(context, 1)
        && Some(attempt.preparation_version) == sql_u32(context, 2)
        && Some(attempt.sprint_id.clone()) == sql_text(context, 3)
        && Some(attempt.attempt_id.clone()) == sql_text(context, 4)
        && Some(attempt.launch_authority_digest.to_string()) == sql_text(context, 5)
        && Some(attempt.capture_authority_digest.to_string()) == sql_text(context, 6)
        && Some(attempt.acquired_anchor_digest.to_string()) == sql_text(context, 7)
        && Some(attempt.native_journal_id.clone()) == sql_text(context, 8)
        && Some(attempt.cleanup_effect_id.clone()) == sql_text(context, 9)
        && Some(attempt.preparation_receipt_id.clone()) == sql_text(context, 10)
        && Some(attempt.platform_expectation.target_id.clone()) == sql_text(context, 11)
        && Some(
            attempt
                .platform_expectation
                .target_identity_digest
                .to_string(),
        ) == sql_text(context, 12)
        && Some(attempt.native_policy_digest.to_string()) == sql_text(context, 13)
        && Some(attempt.runner_binary_digest.to_string()) == sql_text(context, 14)
        && Some(attempt.runner_binary_size_bytes) == sql_u64(context, 15)
        && Some(attempt.runner_protocol_version) == sql_u32(context, 16)
        && Some(attempt.runner_protocol_digest.to_string()) == sql_text(context, 17)
        && Some(attempt.private_state_id.clone()) == sql_text(context, 18)
        && Some(attempt.private_state_digest.to_string()) == sql_text(context, 19)
        && Some(attempt.workspace_grant_hash.to_string()) == sql_text(context, 20)
        && Some(attempt.execution_policy_digest.to_string()) == sql_text(context, 21)
        && Some(
            attempt
                .platform_expectation
                .expected_source_identity_digest
                .to_string(),
        ) == sql_text(context, 22)
        && Some(
            attempt
                .platform_expectation
                .expected_service_protocol_version,
        ) == sql_u32(context, 23)
        && Some(
            attempt
                .platform_expectation
                .expected_service_protocol_digest
                .to_string(),
        ) == sql_text(context, 24)
        && Some(
            attempt
                .platform_expectation
                .expected_service_manifest_digest
                .to_string(),
        ) == sql_text(context, 25)
        && expectation_digest.as_ref().map(ToString::to_string) == sql_text(context, 26)
        && Some(attempt.ledger_database_identity_digest.to_string()) == sql_text(context, 27)
        && Some(attempt.state_root_identity_digest.to_string()) == sql_text(context, 28)
        && Some(attempt.launch_cleanup_lock_identity_digest.to_string()) == sql_text(context, 29)
        && Some(attempt.claimed_at_unix_ms) == sql_u64(context, 30)
}

fn cleanup_projection_matches(
    cleanup: &CurrentFinalVerificationNativeCleanupObligationV1,
    context: &rusqlite::functions::Context<'_>,
) -> bool {
    Some(cleanup.cleanup_effect_id.clone()) == sql_text(context, 1)
        && Some(cleanup.preparation_attempt_id.clone()) == sql_text(context, 2)
        && Some(cleanup.sprint_id.clone()) == sql_text(context, 3)
        && Some(cleanup.attempt_id.clone()) == sql_text(context, 4)
        && Some(cleanup.native_journal_id.clone()) == sql_text(context, 5)
        && sql_text(context, 6).as_deref() == Some("Pending")
}

fn source_consumption_projection_matches(
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
    context: &rusqlite::functions::Context<'_>,
) -> bool {
    let disposition = match consumption.disposition {
        NativeSourceConsumptionDispositionV1::Accepted => "Accepted",
        NativeSourceConsumptionDispositionV1::SourceRejected => "SourceRejected",
    };
    let rejection_reason = consumption.rejection_reason.map(rejection_reason_name);
    Some(consumption.source_consumption_id.clone()) == sql_text(context, 1)
        && Some(consumption.preparation_attempt_id.clone()) == sql_text(context, 2)
        && Some(consumption.sprint_id.clone()) == sql_text(context, 3)
        && Some(consumption.attempt_id.clone()) == sql_text(context, 4)
        && Some(consumption.operation_domain.clone()) == sql_text(context, 5)
        && Some(consumption.authenticated_source_identity_digest.to_string())
            == sql_text(context, 6)
        && Some(consumption.source_session_identity_digest.to_string()) == sql_text(context, 7)
        && Some(consumption.operation_sequence.clone()) == sql_text(context, 8)
        && Some(consumption.payload_digest.to_string()) == sql_text(context, 9)
        && Some(consumption.payload_length) == sql_u64(context, 10)
        && sql_text(context, 11).as_deref() == Some(disposition)
        && sql_optional_text(context, 12)
            .as_ref()
            .map(|value| value.as_deref())
            == Some(rejection_reason)
        && sql_optional_text(context, 13)
            == Some(consumption.accepted_preparation_receipt_id.clone())
        && Some(consumption.consumed_at_unix_ms) == sql_u64(context, 14)
}

fn outcome_projection_matches(
    outcome: &CurrentFinalVerificationNativePreparationOutcomeV1,
    context: &rusqlite::functions::Context<'_>,
) -> bool {
    Some(outcome.preparation_receipt_id.clone()) == sql_text(context, 1)
        && Some(outcome.preparation_attempt_id.clone()) == sql_text(context, 2)
        && Some(outcome.source_consumption_id.clone()) == sql_text(context, 3)
        && Some(outcome.sprint_id.clone()) == sql_text(context, 4)
        && Some(outcome.attempt_id.clone()) == sql_text(context, 5)
        && Some(outcome.native_journal_id.clone()) == sql_text(context, 6)
        && Some(outcome.cleanup_effect_id.clone()) == sql_text(context, 7)
        && sql_text(context, 8).as_deref() == Some(disposition_name(outcome.disposition))
        && Some(outcome.native_evidence_digest.to_string()) == sql_text(context, 9)
        && sql_bytes_equal(context, 10, &outcome.native_evidence_bytes)
        && Some(outcome.finished_at_unix_ms) == sql_u64(context, 11)
}

pub(super) fn disposition_name(disposition: NativePreparationDispositionV1) -> &'static str {
    match disposition {
        NativePreparationDispositionV1::HeldChildPrepared => "HeldChildPrepared",
        NativePreparationDispositionV1::RefusedBeforeNativeEffect => "RefusedBeforeNativeEffect",
        NativePreparationDispositionV1::NativeEffectUncertain => "NativeEffectUncertain",
    }
}

pub(super) fn rejection_reason_name(reason: NativeSourceRejectionReasonV1) -> &'static str {
    match reason {
        NativeSourceRejectionReasonV1::Oversized => "Oversized",
        NativeSourceRejectionReasonV1::Malformed => "Malformed",
        NativeSourceRejectionReasonV1::NonCanonical => "NonCanonical",
        NativeSourceRejectionReasonV1::CrossedIdentity => "CrossedIdentity",
        NativeSourceRejectionReasonV1::TimeInvalid => "TimeInvalid",
        NativeSourceRejectionReasonV1::EvidenceInvalid => "EvidenceInvalid",
        NativeSourceRejectionReasonV1::SourceIdentityMismatch => "SourceIdentityMismatch",
    }
}

pub(super) fn source_disposition_name(
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
) -> &'static str {
    match consumption.disposition {
        NativeSourceConsumptionDispositionV1::Accepted => "Accepted",
        NativeSourceConsumptionDispositionV1::SourceRejected => "SourceRejected",
    }
}

pub(super) fn sqlite_attempt_matches_parent(
    attempt_json: &[u8],
    launch_authority_json: &[u8],
    capture_authority_json: &[u8],
) -> i64 {
    if super::current_final_verification_launch_v35::sqlite_launch_canonical(launch_authority_json)
        != Ok(1)
        || super::current_final_verification_capture_v36::sqlite_capture_canonical(
            capture_authority_json,
        ) != Ok(1)
    {
        return 0;
    }
    let Ok(attempt) = decode_exact::<CurrentFinalVerificationNativePreparationAttemptV1>(
        attempt_json,
        CurrentFinalVerificationNativePreparationAttemptV1::validate,
    ) else {
        return 0;
    };
    let Ok(launch) = decode_exact::<CurrentFinalVerificationLaunchAuthorityV1>(
        launch_authority_json,
        |_| Ok(()),
    ) else {
        return 0;
    };
    let Ok(capture) = decode_exact::<CurrentFinalVerificationCaptureAcquisitionAuthorityV1>(
        capture_authority_json,
        |_| Ok(()),
    ) else {
        return 0;
    };
    i64::from(attempt.validate_for_parent(&launch, &capture).is_ok())
}

/// Registers every deterministic schema-v37 validator and the writer guard.
#[expect(
    clippy::too_many_lines,
    reason = "all closed SQLite UDF registrations remain visibly centralized"
)]
pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    connection.create_scalar_function(
        WRITE_ADMISSION_FUNCTION,
        3,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(write_is_admitted(
                &context.get::<String>(0)?,
                &context.get::<String>(1)?,
                &context.get::<String>(2)?,
            ))
        },
    )?;

    register_canonical_and_digest::<CurrentFinalVerificationNativePreparationAttemptV1>(
        connection,
        "grok_current_final_verification_native_preparation_attempt_v37_canonical",
        "grok_current_final_verification_native_preparation_attempt_v37_digest",
        CurrentFinalVerificationNativePreparationAttemptV1::validate,
        NATIVE_PREPARATION_ATTEMPT_DIGEST_DOMAIN_V1,
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_preparation_attempt_v37_matches",
        31,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let Ok(attempt) = decode_exact::<CurrentFinalVerificationNativePreparationAttemptV1>(
                &bytes,
                CurrentFinalVerificationNativePreparationAttemptV1::validate,
            ) else {
                return Ok(0_i64);
            };
            Ok(i64::from(attempt_projection_matches(&attempt, context)))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_attempt_v37_matches_parent",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(sqlite_attempt_matches_parent(
                &context.get::<Vec<u8>>(0)?,
                &context.get::<Vec<u8>>(1)?,
                &context.get::<Vec<u8>>(2)?,
            ))
        },
    )?;

    register_canonical_and_digest::<CurrentFinalVerificationNativeCleanupObligationV1>(
        connection,
        "grok_current_final_verification_native_cleanup_obligation_v37_canonical",
        "grok_current_final_verification_native_cleanup_obligation_v37_digest",
        CurrentFinalVerificationNativeCleanupObligationV1::validate,
        NATIVE_CLEANUP_OBLIGATION_DIGEST_DOMAIN_V1,
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_cleanup_obligation_v37_matches",
        7,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let Ok(cleanup) = decode_exact::<CurrentFinalVerificationNativeCleanupObligationV1>(
                &bytes,
                CurrentFinalVerificationNativeCleanupObligationV1::validate,
            ) else {
                return Ok(0_i64);
            };
            Ok(i64::from(cleanup_projection_matches(&cleanup, context)))
        },
    )?;

    connection.create_scalar_function(
        "grok_current_final_verification_native_operation_sequence_v37_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(i64::from(
                canonical_operation_sequence(&context.get::<String>(0)?).is_ok(),
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_source_payload_v37_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let Some(bytes) = context.get::<Option<Vec<u8>>>(0)? else {
                return Ok(0_i64);
            };
            Ok(i64::from(
                decode_exact::<CurrentFinalVerificationNativePreparationSourcePayloadV1>(
                    &bytes,
                    CurrentFinalVerificationNativePreparationSourcePayloadV1::validate,
                )
                .is_ok(),
            ))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_source_payload_v37_digest",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(context
                .get::<Option<Vec<u8>>>(0)?
                .map_or_else(String::new, |bytes| {
                    source_payload_digest_bytes(&bytes).to_string()
                }))
        },
    )?;
    register_canonical_and_digest::<CurrentFinalVerificationNativeSourceConsumptionV1>(
        connection,
        "grok_current_final_verification_native_source_consumption_v37_canonical",
        "grok_current_final_verification_native_source_consumption_v37_digest",
        CurrentFinalVerificationNativeSourceConsumptionV1::validate,
        NATIVE_SOURCE_CONSUMPTION_DIGEST_DOMAIN_V1,
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_source_consumption_v37_matches",
        15,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let Ok(consumption) = decode_exact::<CurrentFinalVerificationNativeSourceConsumptionV1>(
                &bytes,
                CurrentFinalVerificationNativeSourceConsumptionV1::validate,
            ) else {
                return Ok(0_i64);
            };
            Ok(i64::from(source_consumption_projection_matches(
                &consumption,
                context,
            )))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_source_payload_v37_matches_attempt",
        7,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let Some(payload_bytes) = context.get::<Option<Vec<u8>>>(0)? else {
                return Ok(0_i64);
            };
            let attempt_bytes = context.get::<Vec<u8>>(1)?;
            let cleanup_bytes = context.get::<Vec<u8>>(2)?;
            let Ok(payload) =
                decode_exact::<CurrentFinalVerificationNativePreparationSourcePayloadV1>(
                    &payload_bytes,
                    CurrentFinalVerificationNativePreparationSourcePayloadV1::validate,
                )
            else {
                return Ok(0_i64);
            };
            let Ok(attempt) = decode_exact::<CurrentFinalVerificationNativePreparationAttemptV1>(
                &attempt_bytes,
                CurrentFinalVerificationNativePreparationAttemptV1::validate,
            ) else {
                return Ok(0_i64);
            };
            let Ok(cleanup) = decode_exact::<CurrentFinalVerificationNativeCleanupObligationV1>(
                &cleanup_bytes,
                CurrentFinalVerificationNativeCleanupObligationV1::validate,
            ) else {
                return Ok(0_i64);
            };
            let Ok(source_identity) = Digest::parse(context.get::<String>(3)?) else {
                return Ok(0_i64);
            };
            let Ok(session_identity) = Digest::parse(context.get::<String>(4)?) else {
                return Ok(0_i64);
            };
            let operation_sequence = context.get::<String>(5)?;
            let Some(consumed_at) = sql_u64(context, 6) else {
                return Ok(0_i64);
            };
            Ok(i64::from(
                payload
                    .validate_for_attempt(
                        &attempt,
                        &cleanup,
                        &source_identity,
                        &session_identity,
                        &operation_sequence,
                        consumed_at,
                    )
                    .is_ok(),
            ))
        },
    )?;

    register_canonical_and_digest::<CurrentFinalVerificationNativePreparationOutcomeV1>(
        connection,
        "grok_current_final_verification_native_preparation_outcome_v37_canonical",
        "grok_current_final_verification_native_preparation_outcome_v37_digest",
        CurrentFinalVerificationNativePreparationOutcomeV1::validate,
        NATIVE_PREPARATION_OUTCOME_DIGEST_DOMAIN_V1,
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_evidence_v37_digest",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| Ok(native_evidence_digest(&context.get::<Vec<u8>>(0)?).to_string()),
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_preparation_outcome_v37_matches",
        12,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let Ok(outcome) = decode_exact::<CurrentFinalVerificationNativePreparationOutcomeV1>(
                &bytes,
                CurrentFinalVerificationNativePreparationOutcomeV1::validate,
            ) else {
                return Ok(0_i64);
            };
            Ok(i64::from(outcome_projection_matches(&outcome, context)))
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_native_outcome_v37_matches_source",
        5,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let outcome_bytes = context.get::<Vec<u8>>(0)?;
            let Some(payload_bytes) = context.get::<Option<Vec<u8>>>(1)? else {
                return Ok(0_i64);
            };
            let consumption_bytes = context.get::<Vec<u8>>(2)?;
            let attempt_bytes = context.get::<Vec<u8>>(3)?;
            let cleanup_bytes = context.get::<Vec<u8>>(4)?;
            let Ok(outcome) = decode_exact::<CurrentFinalVerificationNativePreparationOutcomeV1>(
                &outcome_bytes,
                CurrentFinalVerificationNativePreparationOutcomeV1::validate,
            ) else {
                return Ok(0_i64);
            };
            let Ok(payload) =
                decode_exact::<CurrentFinalVerificationNativePreparationSourcePayloadV1>(
                    &payload_bytes,
                    CurrentFinalVerificationNativePreparationSourcePayloadV1::validate,
                )
            else {
                return Ok(0_i64);
            };
            let Ok(consumption) = decode_exact::<CurrentFinalVerificationNativeSourceConsumptionV1>(
                &consumption_bytes,
                CurrentFinalVerificationNativeSourceConsumptionV1::validate,
            ) else {
                return Ok(0_i64);
            };
            let Ok(attempt) = decode_exact::<CurrentFinalVerificationNativePreparationAttemptV1>(
                &attempt_bytes,
                CurrentFinalVerificationNativePreparationAttemptV1::validate,
            ) else {
                return Ok(0_i64);
            };
            let Ok(cleanup) = decode_exact::<CurrentFinalVerificationNativeCleanupObligationV1>(
                &cleanup_bytes,
                CurrentFinalVerificationNativeCleanupObligationV1::validate,
            ) else {
                return Ok(0_i64);
            };
            Ok(i64::from(
                outcome
                    .validate_for_source(&payload, &consumption, &attempt, &cleanup)
                    .is_ok(),
            ))
        },
    )?;
    Ok(())
}

fn register_canonical_and_digest<T>(
    connection: &Connection,
    canonical_name: &str,
    digest_name: &str,
    validate: fn(&T) -> Result<(), ContractError>,
    digest_domain: &'static [u8],
) -> Result<(), LedgerError>
where
    T: DeserializeOwned + Serialize + 'static,
{
    connection.create_scalar_function(
        canonical_name,
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        move |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            Ok(i64::from(decode_exact::<T>(&bytes, validate).is_ok()))
        },
    )?;
    connection.create_scalar_function(
        digest_name,
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        move |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            Ok(domain_digest(digest_domain, &bytes).to_string())
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::types::Value;
    use rusqlite::{Connection, params_from_iter};

    use super::{
        CurrentFinalVerificationNativeCleanupObligationV1,
        CurrentFinalVerificationNativePreparationAttemptV1,
        CurrentFinalVerificationNativePreparationOutcomeV1,
        CurrentFinalVerificationNativePreparationSourcePayloadV1,
        CurrentFinalVerificationNativeSourceConsumptionV1,
        MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2, NATIVE_PREPARATION_OPERATION_DOMAIN_V1,
        NATIVE_PREPARATION_VERSION_V1, NativeCleanupObligationStateV1,
        NativePreparationDispositionV1, NativePreparationPlatformExpectationV1,
        NativeSourceConsumptionDispositionV1, NativeSourceRejectionReasonV1,
        canonical_operation_sequence, native_evidence_digest, register_schema_functions,
        source_payload_digest_bytes,
    };
    use crate::Digest;

    fn digest(byte: char) -> Digest {
        Digest::parse(byte.to_string().repeat(64)).expect("fixture digest")
    }

    fn id(byte: char) -> String {
        digest(byte).to_string()
    }

    fn platform() -> NativePreparationPlatformExpectationV1 {
        NativePreparationPlatformExpectationV1::from_test(
            "macos-15-apple-silicon".to_owned(),
            digest('1'),
            digest('2'),
            1,
            digest('3'),
            digest('4'),
        )
        .expect("platform fixture")
    }

    fn attempt() -> CurrentFinalVerificationNativePreparationAttemptV1 {
        CurrentFinalVerificationNativePreparationAttemptV1 {
            preparation_version: NATIVE_PREPARATION_VERSION_V1,
            preparation_attempt_id: id('5'),
            sprint_id: "sprint-v37".to_owned(),
            attempt_id: "attempt-v37".to_owned(),
            launch_authority_digest: digest('6'),
            capture_authority_digest: digest('7'),
            acquired_anchor_digest: digest('8'),
            native_journal_id: id('9'),
            cleanup_effect_id: id('a'),
            preparation_receipt_id: id('b'),
            platform_expectation: platform(),
            native_policy_digest: digest('c'),
            runner_binary_digest: digest('d'),
            runner_binary_size_bytes: 4096,
            runner_protocol_version: 13,
            runner_protocol_digest: digest('e'),
            private_state_id: "private-state-v37".to_owned(),
            private_state_digest: digest('f'),
            workspace_grant_hash: digest('0'),
            execution_policy_digest: digest('1'),
            ledger_database_identity_digest: digest('2'),
            state_root_identity_digest: digest('3'),
            launch_cleanup_lock_identity_digest: digest('4'),
            claimed_at_unix_ms: 100,
        }
    }

    fn cleanup() -> CurrentFinalVerificationNativeCleanupObligationV1 {
        let attempt = attempt();
        CurrentFinalVerificationNativeCleanupObligationV1 {
            obligation_version: NATIVE_PREPARATION_VERSION_V1,
            cleanup_effect_id: attempt.cleanup_effect_id,
            preparation_attempt_id: attempt.preparation_attempt_id,
            sprint_id: attempt.sprint_id,
            attempt_id: attempt.attempt_id,
            native_journal_id: attempt.native_journal_id,
            state: NativeCleanupObligationStateV1::Pending,
        }
    }

    fn source_payload() -> CurrentFinalVerificationNativePreparationSourcePayloadV1 {
        let attempt = attempt();
        let evidence = b"v37-native-evidence".to_vec();
        CurrentFinalVerificationNativePreparationSourcePayloadV1 {
            payload_version: NATIVE_PREPARATION_VERSION_V1,
            preparation_attempt_id: attempt.preparation_attempt_id,
            sprint_id: attempt.sprint_id,
            attempt_id: attempt.attempt_id,
            launch_authority_digest: attempt.launch_authority_digest,
            capture_authority_digest: attempt.capture_authority_digest,
            acquired_anchor_digest: attempt.acquired_anchor_digest,
            native_journal_id: attempt.native_journal_id,
            cleanup_effect_id: attempt.cleanup_effect_id,
            preparation_receipt_id: attempt.preparation_receipt_id,
            platform_expectation: attempt.platform_expectation,
            native_policy_digest: attempt.native_policy_digest,
            runner_binary_digest: attempt.runner_binary_digest,
            runner_binary_size_bytes: attempt.runner_binary_size_bytes,
            runner_protocol_version: attempt.runner_protocol_version,
            runner_protocol_digest: attempt.runner_protocol_digest,
            private_state_id: attempt.private_state_id,
            private_state_digest: attempt.private_state_digest,
            workspace_grant_hash: attempt.workspace_grant_hash,
            execution_policy_digest: attempt.execution_policy_digest,
            authenticated_source_identity_digest: digest('2'),
            source_session_identity_digest: digest('5'),
            operation_domain: NATIVE_PREPARATION_OPERATION_DOMAIN_V1.to_owned(),
            operation_sequence: "7".to_owned(),
            disposition: NativePreparationDispositionV1::HeldChildPrepared,
            native_evidence_digest: native_evidence_digest(&evidence),
            native_evidence_bytes: evidence,
            finished_at_unix_ms: 200,
        }
    }

    fn accepted_consumption() -> CurrentFinalVerificationNativeSourceConsumptionV1 {
        let payload = source_payload();
        let payload_bytes = payload.canonical_bytes().expect("source payload bytes");
        CurrentFinalVerificationNativeSourceConsumptionV1 {
            consumption_version: NATIVE_PREPARATION_VERSION_V1,
            source_consumption_id: id('6'),
            preparation_attempt_id: payload.preparation_attempt_id,
            sprint_id: payload.sprint_id,
            attempt_id: payload.attempt_id,
            operation_domain: payload.operation_domain,
            authenticated_source_identity_digest: payload.authenticated_source_identity_digest,
            source_session_identity_digest: payload.source_session_identity_digest,
            operation_sequence: payload.operation_sequence,
            payload_digest: source_payload_digest_bytes(&payload_bytes),
            payload_length: u64::try_from(payload_bytes.len()).expect("fixture length"),
            disposition: NativeSourceConsumptionDispositionV1::Accepted,
            rejection_reason: None,
            accepted_preparation_receipt_id: Some(payload.preparation_receipt_id),
            consumed_at_unix_ms: 250,
        }
    }

    fn outcome() -> CurrentFinalVerificationNativePreparationOutcomeV1 {
        let payload = source_payload();
        CurrentFinalVerificationNativePreparationOutcomeV1 {
            outcome_version: NATIVE_PREPARATION_VERSION_V1,
            preparation_receipt_id: payload.preparation_receipt_id,
            preparation_attempt_id: payload.preparation_attempt_id,
            source_consumption_id: id('6'),
            sprint_id: payload.sprint_id,
            attempt_id: payload.attempt_id,
            native_journal_id: payload.native_journal_id,
            cleanup_effect_id: payload.cleanup_effect_id,
            disposition: payload.disposition,
            native_evidence_digest: payload.native_evidence_digest,
            native_evidence_bytes: payload.native_evidence_bytes,
            finished_at_unix_ms: payload.finished_at_unix_ms,
        }
    }

    fn rejected_consumption(
        reason: NativeSourceRejectionReasonV1,
        payload_length: u64,
    ) -> CurrentFinalVerificationNativeSourceConsumptionV1 {
        let payload = source_payload();
        CurrentFinalVerificationNativeSourceConsumptionV1 {
            consumption_version: NATIVE_PREPARATION_VERSION_V1,
            source_consumption_id: id('7'),
            preparation_attempt_id: payload.preparation_attempt_id,
            sprint_id: payload.sprint_id,
            attempt_id: payload.attempt_id,
            operation_domain: payload.operation_domain,
            authenticated_source_identity_digest: payload.authenticated_source_identity_digest,
            source_session_identity_digest: payload.source_session_identity_digest,
            operation_sequence: payload.operation_sequence,
            payload_digest: digest('8'),
            payload_length,
            disposition: NativeSourceConsumptionDispositionV1::SourceRejected,
            rejection_reason: Some(reason),
            accepted_preparation_receipt_id: None,
            consumed_at_unix_ms: 150,
        }
    }

    #[test]
    fn operation_sequence_accepts_the_complete_u64_boundaries_without_contiguity() {
        for accepted in ["0", "7", "18446744073709551615"] {
            assert_eq!(
                canonical_operation_sequence(accepted).expect("canonical sequence"),
                accepted.parse::<u64>().expect("fixture u64")
            );
        }
        for rejected in [
            "",
            "00",
            "07",
            "-1",
            "+1",
            " 7",
            "7 ",
            "18446744073709551616",
            "999999999999999999999",
        ] {
            assert!(
                canonical_operation_sequence(rejected).is_err(),
                "{rejected:?} must not be canonical"
            );
        }
    }

    #[test]
    fn rejection_reason_and_length_partition_is_total_and_nonoverlapping() {
        let bound = u64::try_from(MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2)
            .expect("canonical bound fits u64");

        let mut accepted = accepted_consumption();
        accepted.payload_length = 1;
        assert!(accepted.validate().is_ok());
        accepted.payload_length = bound;
        assert!(accepted.validate().is_ok());
        accepted.payload_length = 0;
        assert!(accepted.validate().is_err());
        accepted.payload_length = bound + 1;
        assert!(accepted.validate().is_err());

        assert!(
            rejected_consumption(NativeSourceRejectionReasonV1::Oversized, bound + 1)
                .validate()
                .is_ok()
        );
        assert!(
            rejected_consumption(NativeSourceRejectionReasonV1::Oversized, bound)
                .validate()
                .is_err()
        );
        for reason in [
            NativeSourceRejectionReasonV1::Malformed,
            NativeSourceRejectionReasonV1::NonCanonical,
            NativeSourceRejectionReasonV1::CrossedIdentity,
            NativeSourceRejectionReasonV1::TimeInvalid,
            NativeSourceRejectionReasonV1::EvidenceInvalid,
        ] {
            assert!(rejected_consumption(reason, 0).validate().is_ok());
            assert!(rejected_consumption(reason, bound).validate().is_ok());
            assert!(rejected_consumption(reason, bound + 1).validate().is_err());
        }
        assert!(
            rejected_consumption(NativeSourceRejectionReasonV1::SourceIdentityMismatch, 0)
                .validate()
                .is_ok()
        );
        assert!(
            rejected_consumption(
                NativeSourceRejectionReasonV1::SourceIdentityMismatch,
                bound + 1,
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn attempt_projection_matcher_rejects_every_normalized_column_mutation() {
        let connection = Connection::open_in_memory().expect("open in-memory SQLite");
        register_schema_functions(&connection).expect("register schema-v37 functions");
        let attempt = attempt();
        let expectation_digest = attempt
            .platform_expectation
            .canonical_digest()
            .expect("expectation digest");
        let values = vec![
            Value::Blob(attempt.canonical_bytes().expect("attempt bytes")),
            Value::Text(attempt.preparation_attempt_id),
            Value::Integer(i64::from(attempt.preparation_version)),
            Value::Text(attempt.sprint_id),
            Value::Text(attempt.attempt_id),
            Value::Text(attempt.launch_authority_digest.to_string()),
            Value::Text(attempt.capture_authority_digest.to_string()),
            Value::Text(attempt.acquired_anchor_digest.to_string()),
            Value::Text(attempt.native_journal_id),
            Value::Text(attempt.cleanup_effect_id),
            Value::Text(attempt.preparation_receipt_id),
            Value::Text(attempt.platform_expectation.target_id),
            Value::Text(
                attempt
                    .platform_expectation
                    .target_identity_digest
                    .to_string(),
            ),
            Value::Text(attempt.native_policy_digest.to_string()),
            Value::Text(attempt.runner_binary_digest.to_string()),
            Value::Integer(i64::try_from(attempt.runner_binary_size_bytes).expect("runner size")),
            Value::Integer(i64::from(attempt.runner_protocol_version)),
            Value::Text(attempt.runner_protocol_digest.to_string()),
            Value::Text(attempt.private_state_id),
            Value::Text(attempt.private_state_digest.to_string()),
            Value::Text(attempt.workspace_grant_hash.to_string()),
            Value::Text(attempt.execution_policy_digest.to_string()),
            Value::Text(
                attempt
                    .platform_expectation
                    .expected_source_identity_digest
                    .to_string(),
            ),
            Value::Integer(i64::from(
                attempt
                    .platform_expectation
                    .expected_service_protocol_version,
            )),
            Value::Text(
                attempt
                    .platform_expectation
                    .expected_service_protocol_digest
                    .to_string(),
            ),
            Value::Text(
                attempt
                    .platform_expectation
                    .expected_service_manifest_digest
                    .to_string(),
            ),
            Value::Text(expectation_digest.to_string()),
            Value::Text(attempt.ledger_database_identity_digest.to_string()),
            Value::Text(attempt.state_root_identity_digest.to_string()),
            Value::Text(attempt.launch_cleanup_lock_identity_digest.to_string()),
            Value::Integer(i64::try_from(attempt.claimed_at_unix_ms).expect("claim time")),
        ];
        let placeholders = (1..=values.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        let statement = format!(
            "SELECT grok_current_final_verification_native_preparation_attempt_v37_matches({placeholders})"
        );
        let exact = connection
            .query_row(&statement, params_from_iter(values.iter()), |row| {
                row.get::<_, i64>(0)
            })
            .expect("exact projection call");
        assert_eq!(exact, 1);

        for index in 1..values.len() {
            let mut mutated = values.clone();
            match &mut mutated[index] {
                Value::Integer(value) => *value = value.saturating_add(1),
                Value::Text(value) => value.push('x'),
                Value::Blob(value) => value.push(b' '),
                Value::Null | Value::Real(_) => unreachable!("closed fixture values"),
            }
            let result = connection
                .query_row(&statement, params_from_iter(mutated.iter()), |row| {
                    row.get::<_, i64>(0)
                })
                .expect("mutated projection call");
            assert_eq!(result, 0, "normalized column {index} was not checked");
        }
    }

    #[test]
    fn source_and_outcome_cross_matchers_reject_independent_mutations() {
        let attempt = attempt();
        let cleanup = cleanup();
        let payload = source_payload();
        let consumption = accepted_consumption();
        let outcome = outcome();
        assert!(
            payload
                .validate_for_attempt(
                    &attempt,
                    &cleanup,
                    &payload.authenticated_source_identity_digest,
                    &payload.source_session_identity_digest,
                    &payload.operation_sequence,
                    consumption.consumed_at_unix_ms,
                )
                .is_ok()
        );
        assert!(
            outcome
                .validate_for_source(&payload, &consumption, &attempt, &cleanup)
                .is_ok()
        );

        let mut crossed_policy = payload.clone();
        crossed_policy.native_policy_digest = digest('9');
        assert!(
            crossed_policy
                .validate_for_attempt(
                    &attempt,
                    &cleanup,
                    &crossed_policy.authenticated_source_identity_digest,
                    &crossed_policy.source_session_identity_digest,
                    &crossed_policy.operation_sequence,
                    consumption.consumed_at_unix_ms,
                )
                .is_err()
        );

        let mut future = payload.clone();
        future.finished_at_unix_ms = consumption.consumed_at_unix_ms + 1;
        assert!(
            future
                .validate_for_attempt(
                    &attempt,
                    &cleanup,
                    &future.authenticated_source_identity_digest,
                    &future.source_session_identity_digest,
                    &future.operation_sequence,
                    consumption.consumed_at_unix_ms,
                )
                .is_err()
        );

        let mut crossed_outcome = outcome.clone();
        crossed_outcome.disposition = NativePreparationDispositionV1::NativeEffectUncertain;
        assert!(
            crossed_outcome
                .validate_for_source(&payload, &consumption, &attempt, &cleanup)
                .is_err()
        );

        let mut crossed_evidence = outcome.clone();
        crossed_evidence.native_evidence_bytes = b"different-native-evidence".to_vec();
        crossed_evidence.native_evidence_digest =
            native_evidence_digest(&crossed_evidence.native_evidence_bytes);
        assert!(
            crossed_evidence
                .validate_for_source(&payload, &consumption, &attempt, &cleanup)
                .is_err()
        );

        let mut crossed_consumption = consumption;
        crossed_consumption.operation_sequence = "8".to_owned();
        assert!(
            outcome
                .validate_for_source(&payload, &crossed_consumption, &attempt, &cleanup)
                .is_err()
        );
    }

    #[test]
    fn rejected_consumption_retains_metadata_but_no_payload_or_canary() {
        let canary = b"V37-REJECTED-RAW-PAYLOAD-CANARY";
        let mut rejected = rejected_consumption(
            NativeSourceRejectionReasonV1::Malformed,
            u64::try_from(canary.len()).expect("canary length fits u64"),
        );
        rejected.payload_digest = source_payload_digest_bytes(canary);
        let canonical = rejected
            .canonical_bytes()
            .expect("rejected metadata canonical bytes");
        assert!(
            !canonical
                .windows(canary.len())
                .any(|window| window == canary)
        );
        let text = std::str::from_utf8(&canonical).expect("canonical JSON is UTF-8");
        assert!(!text.contains("accepted_payload_json"));
        assert!(!text.contains("native_evidence_bytes"));
        assert!(!text.contains("canonical_payload"));
        assert!(text.contains("\"payload_digest\""));
        assert!(text.contains("\"payload_length\""));

        let connection = Connection::open_in_memory().expect("open in-memory SQLite");
        register_schema_functions(&connection).expect("register schema-v37 functions");
        let (canonical_null, digest_null, cross_null): (i64, String, i64) = connection
            .query_row(
                "SELECT
                    grok_current_final_verification_native_source_payload_v37_canonical(NULL),
                    grok_current_final_verification_native_source_payload_v37_digest(NULL),
                    grok_current_final_verification_native_source_payload_v37_matches_attempt(
                        NULL, NULL, NULL, NULL, NULL, NULL, NULL
                    )",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("NULL source branch must remain rejection-safe");
        assert_eq!(canonical_null, 0);
        assert!(digest_null.is_empty());
        assert_eq!(cross_null, 0);
    }
}
