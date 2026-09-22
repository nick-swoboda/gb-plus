//! Additive schema-v36 current final-verifier capture-acquisition authority.
//!
//! One fresh transaction consumes the same-process schema-v35 permit and a
//! sealed store-origin proof, binds the exact V1 acquisition plus the exact
//! sensitive-output journal generations one and two, and appends the reserved
//! `CaptureAcquired` event. The module deliberately has no production store
//! bridge, native spawn, runner initialization, dispatch, or service route.
//! A process crash after physical generation two but before this transaction
//! cannot recreate the ephemeral v35 permit: that state requires a future
//! durable restart-reopen reconciliation/abandonment bridge and is not a fresh
//! v36 admission path.

use std::cell::RefCell;
use std::fmt::{self, Debug, Formatter};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    CommandOutputCaptureAcquiredV1, ContractError, CurrentFinalVerificationAuthorityEventKindV1,
    CurrentFinalVerificationAuthorityEventV1, Digest,
    MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2,
    MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2, SensitiveOutputDetectionPolicyReferenceV1,
    SensitiveOutputJournalHeadV1,
};

use super::current_final_verification_launch_v35::{
    FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
    PersistedCurrentFinalVerificationLaunchV1,
};
use super::{EventLedger, LedgerError, secure_database_files};

pub(super) const MIGRATION_V36: &str = include_str!("current_final_verification_capture_v36.sql");

const ACQUISITION_VERSION_V1: u32 = 1;
const SENSITIVE_OUTPUT_JOURNAL_ID_PREFIX_V2: &str = "sensitive-output-journal-v2-";
const ACQUISITION_REQUEST_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-capture-request-v1/canonical-json\0";
const CAPTURE_AUTHORITY_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-capture-authority-v1/canonical-json\0";

/// Exact, caller-copyable acquisition values presented at the v36 boundary.
///
/// This DTO is never sufficient for a fresh write. Fresh admission additionally
/// consumes both the v35 move-only permit and the sealed store-origin proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationCaptureAcquisitionRequestV1 {
    /// Contract discriminator.
    pub acquisition_version: u32,
    /// Exact current operational attempt.
    pub attempt_id: String,
    /// Exact schema-v35 launch authority being consumed.
    pub launch_authority_digest: Digest,
    /// Store-authenticated V1 acquired anchor copied without projection loss.
    pub acquired: CommandOutputCaptureAcquiredV1,
    /// Exact fixed detector bound into sensitive-output generation one.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact deterministic private sensitive-output journal identity.
    pub sensitive_output_journal_id: String,
    /// Exact `IntentBound` generation-one head.
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Exact `AcquiredBound` generation-two head.
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
}

impl CurrentFinalVerificationCaptureAcquisitionRequestV1 {
    fn validate_intrinsic(&self) -> Result<(), ContractError> {
        require_version(
            "capture_acquisition_request.acquisition_version",
            self.acquisition_version,
        )?;
        require_identifier("capture_acquisition_request.attempt_id", &self.attempt_id)?;
        self.acquired.validate()?;
        self.detector_policy.validate()?;
        self.intent_bound_journal_head.validate()?;
        self.acquired_bound_journal_head.validate()?;
        let expected_journal_id = format!(
            "{SENSITIVE_OUTPUT_JOURNAL_ID_PREFIX_V2}{}",
            self.acquired.capture_id
        );
        if self.sensitive_output_journal_id != expected_journal_id
            || self.acquired.store_head.generation != 2
            || self.intent_bound_journal_head.generation != 1
            || self.acquired_bound_journal_head.generation != 2
            || self.intent_bound_journal_head.record_digest
                == self.acquired_bound_journal_head.record_digest
            || self.acquired.working_directory.device_id != self.acquired.stdout.device_id
            || self.acquired.working_directory.device_id != self.acquired.stderr.device_id
            || (
                self.acquired.working_directory.device_id,
                self.acquired.working_directory.inode,
            ) == (self.acquired.stdout.device_id, self.acquired.stdout.inode)
            || (
                self.acquired.working_directory.device_id,
                self.acquired.working_directory.inode,
            ) == (self.acquired.stderr.device_id, self.acquired.stderr.inode)
        {
            return Err(ContractError::new(
                "capture_acquisition_request",
                "must identify the exact same-device V1 generation-two acquisition and deterministic sensitive-output generations one and two",
            ));
        }
        let expected_heads =
            super::sensitive_output_rejection::derive_sensitive_output_acquisition_journal_heads_v2(
                &self.sensitive_output_journal_id,
                &self.acquired.capture_id,
                &self.acquired.source.runner_session_id,
                &self.acquired.source.effect_id,
                &self.acquired.source.request_digest,
                &self.acquired.intent_digest,
                &self.detector_policy,
                &self.acquired,
            )?;
        if [
            self.intent_bound_journal_head.clone(),
            self.acquired_bound_journal_head.clone(),
        ] != expected_heads
        {
            return Err(ContractError::new(
                "capture_acquisition_request.sensitive_output_journal_heads",
                "do not re-derive as the exact IntentBound/AcquiredBound chain",
            ));
        }
        require_canonical_bound("capture_acquisition_request", &encode_canonical(self)?)
    }

    fn validate_for_launch(
        &self,
        launch: &PersistedCurrentFinalVerificationLaunchV1,
    ) -> Result<(), ContractError> {
        self.validate_for_launch_authority(&launch.launch_authority)
    }

    fn validate_for_launch_authority(
        &self,
        authority: &super::CurrentFinalVerificationLaunchAuthorityV1,
    ) -> Result<(), ContractError> {
        self.validate_intrinsic()?;
        self.acquired.validate_against(&authority.capture_intent)?;
        if self.attempt_id != authority.attempt_id
            || self.launch_authority_digest != authority.launch_authority_digest
            || self.detector_policy != authority.detector_policy
            || self.acquired.capture_id != authority.reservations.fields.capture_id
            || self.acquired.source.runner_launch_id
                != authority.reservations.fields.runner_launch_id
            || self.acquired.source.runner_session_id
                != authority.reservations.fields.runner_session_id
            || self.acquired.source.effect_id != authority.reservations.fields.effect_id
            || self.acquired.source.request_digest != authority.v13_command_request_digest
            || self.acquired.dispatch_claim_id != authority.reservations.fields.dispatch_id
            || self.acquired.acquired_at_unix_ms < authority.committed_at_unix_ms
        {
            return Err(ContractError::new(
                "capture_acquisition_request",
                "crosses the exact v35 launch, reserved lifecycle identities, or acquisition time",
            ));
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        self.validate_intrinsic()?;
        encode_canonical(self)
    }

    fn canonical_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            ACQUISITION_REQUEST_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        ))
    }
}

/// Sealed proof that the private store reopened and authenticated the exact
/// V1 and sensitive-output generation-two heads.
///
/// V36 intentionally has no production constructor. A future lower authority
/// owner must mint this move-only proof from runner-private store verification;
/// a public acquired anchor, wire anchor, boolean, or digest cannot substitute.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v36 remains dormant until a lower store owner supplies this sealed proof"
    )
)]
pub(crate) struct AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1 {
    request: CurrentFinalVerificationCaptureAcquisitionRequestV1,
}

impl Debug for AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1")
            .field("request", &"<redacted move-only store origin>")
            .finish()
    }
}

impl AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 remains dormant until a lower store owner supplies this sealed proof"
        )
    )]
    fn contract(&self) -> &CurrentFinalVerificationCaptureAcquisitionRequestV1 {
        &self.request
    }

    #[cfg(test)]
    fn from_test(
        request: CurrentFinalVerificationCaptureAcquisitionRequestV1,
    ) -> Result<Self, ContractError> {
        request.validate_intrinsic()?;
        Ok(Self { request })
    }
}

/// Immutable current capture authority reconstructed from schema v36.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationCaptureAcquisitionAuthorityV1 {
    /// Contract discriminator.
    pub acquisition_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact operational attempt.
    pub attempt_id: String,
    /// Exact schema-v35 launch authority.
    pub launch_authority_digest: Digest,
    /// Digest of the exact canonical acquisition request.
    pub acquisition_request_digest: Digest,
    /// Exact reserved logical capture-intent identity.
    pub capture_intent_id: String,
    /// Exact physical acquisition.
    pub acquired: CommandOutputCaptureAcquiredV1,
    /// Exact fixed detector identity.
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    /// Exact deterministic sensitive-output journal identity.
    pub sensitive_output_journal_id: String,
    /// Exact generation-one `IntentBound` head.
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Exact generation-two `AcquiredBound` head.
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    /// Exact preceding `LaunchCommitted` event identity.
    pub launch_event_id: String,
    /// Exact preceding event sequence.
    pub launch_event_sequence: u64,
    /// Exact reserved `CaptureAcquired` event identity.
    pub capture_event_id: String,
    /// Exact contiguous capture event sequence.
    pub capture_event_sequence: u64,
    /// Store-observed acquisition time and event time.
    pub acquired_at_unix_ms: u64,
    /// Domain-separated digest of every preceding field.
    pub capture_authority_digest: Digest,
}

#[derive(Serialize)]
struct CaptureAuthorityDigestPreimageV1<'a> {
    acquisition_version: u32,
    sprint_id: &'a str,
    attempt_id: &'a str,
    launch_authority_digest: &'a Digest,
    acquisition_request_digest: &'a Digest,
    capture_intent_id: &'a str,
    acquired: &'a CommandOutputCaptureAcquiredV1,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    sensitive_output_journal_id: &'a str,
    intent_bound_journal_head: &'a SensitiveOutputJournalHeadV1,
    acquired_bound_journal_head: &'a SensitiveOutputJournalHeadV1,
    launch_event_id: &'a str,
    launch_event_sequence: u64,
    capture_event_id: &'a str,
    capture_event_sequence: u64,
    acquired_at_unix_ms: u64,
}

impl CurrentFinalVerificationCaptureAcquisitionAuthorityV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 capture authority is dormant until the sealed store-origin bridge exists"
        )
    )]
    fn new(
        launch: &PersistedCurrentFinalVerificationLaunchV1,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<Self, ContractError> {
        Self::new_for_launch_authority(&launch.launch_authority, request, event)
    }

    fn new_for_launch_authority(
        launch_authority: &super::CurrentFinalVerificationLaunchAuthorityV1,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<Self, ContractError> {
        let mut authority = Self {
            acquisition_version: ACQUISITION_VERSION_V1,
            sprint_id: launch_authority.sprint_id.clone(),
            attempt_id: launch_authority.attempt_id.clone(),
            launch_authority_digest: launch_authority.launch_authority_digest.clone(),
            acquisition_request_digest: request.canonical_digest()?,
            capture_intent_id: launch_authority
                .reservations
                .fields
                .capture_intent_id
                .clone(),
            acquired: request.acquired.clone(),
            detector_policy: request.detector_policy.clone(),
            sensitive_output_journal_id: request.sensitive_output_journal_id.clone(),
            intent_bound_journal_head: request.intent_bound_journal_head.clone(),
            acquired_bound_journal_head: request.acquired_bound_journal_head.clone(),
            launch_event_id: launch_authority.launch_event_id.clone(),
            launch_event_sequence: launch_authority.launch_event_sequence,
            capture_event_id: event.event_id.clone(),
            capture_event_sequence: event.event_sequence,
            acquired_at_unix_ms: request.acquired.acquired_at_unix_ms,
            capture_authority_digest: Digest::sha256(&[]),
        };
        authority.capture_authority_digest = authority.computed_digest()?;
        authority.validate_for_launch_authority(launch_authority, request, event)?;
        Ok(authority)
    }

    fn digest_preimage(&self) -> CaptureAuthorityDigestPreimageV1<'_> {
        CaptureAuthorityDigestPreimageV1 {
            acquisition_version: self.acquisition_version,
            sprint_id: &self.sprint_id,
            attempt_id: &self.attempt_id,
            launch_authority_digest: &self.launch_authority_digest,
            acquisition_request_digest: &self.acquisition_request_digest,
            capture_intent_id: &self.capture_intent_id,
            acquired: &self.acquired,
            detector_policy: &self.detector_policy,
            sensitive_output_journal_id: &self.sensitive_output_journal_id,
            intent_bound_journal_head: &self.intent_bound_journal_head,
            acquired_bound_journal_head: &self.acquired_bound_journal_head,
            launch_event_id: &self.launch_event_id,
            launch_event_sequence: self.launch_event_sequence,
            capture_event_id: &self.capture_event_id,
            capture_event_sequence: self.capture_event_sequence,
            acquired_at_unix_ms: self.acquired_at_unix_ms,
        }
    }

    fn computed_digest(&self) -> Result<Digest, ContractError> {
        Ok(domain_digest(
            CAPTURE_AUTHORITY_DIGEST_DOMAIN_V1,
            &encode_canonical(&self.digest_preimage())?,
        ))
    }

    fn validate_for(
        &self,
        launch: &PersistedCurrentFinalVerificationLaunchV1,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<(), ContractError> {
        self.validate_for_launch_authority(&launch.launch_authority, request, event)
    }

    fn validate_for_launch_authority(
        &self,
        launch_authority: &super::CurrentFinalVerificationLaunchAuthorityV1,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> Result<(), ContractError> {
        request.validate_for_launch_authority(launch_authority)?;
        validate_capture_event_for_launch_authority(event, launch_authority, request)?;
        if self.acquisition_version != ACQUISITION_VERSION_V1
            || self.sprint_id != launch_authority.sprint_id
            || self.attempt_id != launch_authority.attempt_id
            || self.launch_authority_digest != launch_authority.launch_authority_digest
            || self.acquisition_request_digest != request.canonical_digest()?
            || self.capture_intent_id != launch_authority.reservations.fields.capture_intent_id
            || self.acquired != request.acquired
            || self.detector_policy != request.detector_policy
            || self.sensitive_output_journal_id != request.sensitive_output_journal_id
            || self.intent_bound_journal_head != request.intent_bound_journal_head
            || self.acquired_bound_journal_head != request.acquired_bound_journal_head
            || self.launch_event_id != launch_authority.launch_event_id
            || self.launch_event_sequence != launch_authority.launch_event_sequence
            || self.capture_event_id != event.event_id
            || self.capture_event_sequence != event.event_sequence
            || self.acquired_at_unix_ms != request.acquired.acquired_at_unix_ms
            || self.capture_authority_digest != self.computed_digest()?
        {
            return Err(ContractError::new(
                "capture_acquisition_authority",
                "crosses the exact v35 launch, store acquisition, journal prefix, or reserved event",
            ));
        }
        require_canonical_bound("capture_acquisition_authority", &encode_canonical(self)?)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, ContractError> {
        if self.capture_authority_digest != self.computed_digest()? {
            return Err(ContractError::new(
                "capture_acquisition_authority.capture_authority_digest",
                "does not authenticate the exact capture authority",
            ));
        }
        let bytes = encode_canonical(self)?;
        require_canonical_bound("capture_acquisition_authority", &bytes)?;
        Ok(bytes)
    }
}

/// Exact durable readback of one schema-v36 acquisition commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
    /// Exact schema-v35 parent.
    pub launch: PersistedCurrentFinalVerificationLaunchV1,
    /// Real `CaptureAcquired` event.
    pub capture_event: CurrentFinalVerificationAuthorityEventV1,
    /// Exact immutable capture authority.
    pub capture_authority: CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
}

/// Move-only authority for the next native-launch stage.
///
/// It exists only after fresh transaction commit, file hardening, and exact
/// readback. It has no production consumer in schema v36.
pub struct FreshCurrentFinalVerificationNativeLaunchPermitV1 {
    attempt_id: String,
    launch_authority_digest: Digest,
    capture_authority_digest: Digest,
    acquired_anchor_digest: Digest,
    ledger_instance_id: u64,
}

impl Debug for FreshCurrentFinalVerificationNativeLaunchPermitV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshCurrentFinalVerificationNativeLaunchPermitV1")
            .field("authority", &"<redacted move-only permit>")
            .finish()
    }
}

impl FreshCurrentFinalVerificationNativeLaunchPermitV1 {
    /// Exact attempt authorized for the future native launch stage.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Exact acquisition authority consumed by the future stage.
    #[must_use]
    pub const fn capture_authority_digest(&self) -> &Digest {
        &self.capture_authority_digest
    }

    /// Borrows and validates this permit against one exact ledger instance and
    /// schema-v36 capture without consuming it.
    ///
    /// This exists so the next-stage owner can return the original move-only
    /// permit after a failure proven to precede any durable next-stage claim.
    /// It never manufactures or duplicates authority.
    pub(super) fn validate_for_ledger_instance(
        &self,
        ledger_instance_id: u64,
        capture: &PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    ) -> Result<(), LedgerError> {
        if self.ledger_instance_id != ledger_instance_id
            || self.attempt_id != capture.capture_authority.attempt_id
            || self.launch_authority_digest != capture.capture_authority.launch_authority_digest
            || self.capture_authority_digest != capture.capture_authority.capture_authority_digest
            || self.acquired_anchor_digest
                != capture.capture_authority.acquired.acquired_anchor_digest
        {
            return Err(mismatch(
                "fresh current final-verification native-launch permit",
                "permit crosses its exact ledger instance or capture acquisition",
            ));
        }
        Ok(())
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 has no native-launch consumer or production route"
        )
    )]
    pub(super) fn consume_for_ledger_instance(
        self,
        ledger_instance_id: u64,
        capture: &PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    ) -> Result<(), LedgerError> {
        self.validate_for_ledger_instance(ledger_instance_id, capture)
    }
}

/// Fresh-versus-replay result. Only `Fresh` can carry the next-stage permit.
pub enum CurrentFinalVerificationCaptureAcquisitionCommitV1 {
    /// One exact fresh commit and its sole move-only permit.
    Fresh {
        /// Exact durable readback.
        persisted: PersistedCurrentFinalVerificationCaptureAcquisitionV1,
        /// Sole permission to enter the future native-launch stage.
        native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
    },
    /// Exact idempotent readback with no capability.
    Replay {
        /// Exact durable readback.
        persisted: PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    },
}

impl CurrentFinalVerificationCaptureAcquisitionCommitV1 {
    /// Borrows exact durable readback in either disposition.
    #[must_use]
    pub const fn persisted(&self) -> &PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
        match self {
            Self::Fresh { persisted, .. } | Self::Replay { persisted } => persisted,
        }
    }

    /// Returns true only for the call that durably committed the acquisition.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }
}

/// Exact move-only custody returned when v36 proves that no database commit
/// occurred. It can support a retry or a future cleanup path without
/// reconstructing either authority from identifiers.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v36 fresh commit is dormant until the store-origin bridge exists"
    )
)]
pub(crate) struct FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1 {
    launch_permit: FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
    store_origin: AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1,
}

impl Debug for FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1")
            .field("authority", &"<redacted move-only custody>")
            .finish()
    }
}

impl FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1 {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 has no production store-origin constructor or route"
        )
    )]
    fn new(
        launch_permit: FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
        store_origin: AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1,
    ) -> Self {
        Self {
            launch_permit,
            store_origin,
        }
    }
}

/// Typed failure of the dormant v36 fresh-commit seam.
///
/// `DefinitelyPreCommit` returns exact move-only retry/cleanup custody.
/// `PostCommitStateUncertain` returns no authority and requires durable
/// readback; it can never be retried as a fresh acquisition.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "schema-v36 fresh commit is dormant until the store-origin bridge exists"
    )
)]
pub(crate) enum CurrentFinalVerificationCaptureAcquisitionCommitErrorV1 {
    /// The transaction definitely did not commit.
    DefinitelyPreCommit {
        /// Exact failure.
        error: Box<LedgerError>,
        /// Original move-only launch/store custody.
        custody: Box<FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1>,
    },
    /// `SQLite` commit or post-commit hardening/readback could not establish the
    /// durable result. No fresh/native capability is returned.
    PostCommitStateUncertain {
        /// Exact recovery-only failure.
        error: Box<LedgerError>,
    },
}

impl Debug for CurrentFinalVerificationCaptureAcquisitionCommitErrorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitelyPreCommit { .. } => formatter
                .debug_struct("DefinitelyPreCommit")
                .field("error", &"<redacted definite-precommit error>")
                .field("custody", &"<redacted move-only custody>")
                .finish(),
            Self::PostCommitStateUncertain { .. } => formatter
                .debug_struct("PostCommitStateUncertain")
                .field("error", &"<redacted recovery-only error>")
                .finish(),
        }
    }
}

impl CurrentFinalVerificationCaptureAcquisitionCommitErrorV1 {
    fn precommit(
        error: LedgerError,
        custody: FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1,
    ) -> Self {
        Self::DefinitelyPreCommit {
            error: Box::new(error),
            custody: Box::new(custody),
        }
    }

    fn postcommit(error: LedgerError) -> Self {
        Self::PostCommitStateUncertain {
            error: Box::new(error),
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 has no production store-origin constructor or route"
        )
    )]
    fn into_precommit(
        self,
    ) -> Result<
        (
            LedgerError,
            FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1,
        ),
        LedgerError,
    > {
        match self {
            Self::DefinitelyPreCommit { error, custody } => Ok((*error, *custody)),
            Self::PostCommitStateUncertain { error } => Err(*error),
        }
    }
}

impl EventLedger {
    /// Atomically commits one exact current capture-acquisition frontier.
    ///
    /// The API is crate-private and deliberately dormant because the sealed
    /// store-origin proof has no production constructor. Replay never returns
    /// a native-launch permit.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-v35 parent, crossed move-only authority,
    /// caller-manufactured acquisition, stale/substituted journal or store
    /// heads, noncanonical bytes, an occupied later frontier, or failed exact
    /// post-commit readback.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "the dormant seam visibly consumes both move-only authorities and keeps every transaction/readback cut linear"
    )]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "schema-v36 has no production store-origin constructor or route"
        )
    )]
    pub(crate) fn commit_current_final_verification_capture_acquisition_v36(
        &mut self,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        fresh_custody: FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1,
    ) -> Result<
        CurrentFinalVerificationCaptureAcquisitionCommitV1,
        CurrentFinalVerificationCaptureAcquisitionCommitErrorV1,
    > {
        let mut custody = Some(fresh_custody);
        macro_rules! precommit {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        let custody = custody
                            .take()
                            .expect("precommit custody is returned at most once");
                        return Err(
                            CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                                LedgerError::from(error),
                                custody,
                            ),
                        );
                    }
                }
            };
        }

        precommit!(self.require_writable());
        precommit!(request.validate_intrinsic());
        let request_bytes = precommit!(request.canonical_bytes());
        let request_digest = precommit!(request.canonical_digest());
        let launch =
            precommit!(self.load_current_final_verification_launch_v35(&request.attempt_id));
        precommit!(request.validate_for_launch(&launch));
        let event = precommit!(capture_event(&launch, request));
        let authority = precommit!(CurrentFinalVerificationCaptureAcquisitionAuthorityV1::new(
            &launch, request, &event,
        ));

        let transaction = precommit!(
            self.connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
        );
        if let Some((existing_attempt, existing_digest, existing_bytes)) = precommit!(
            load_capture_collision_v36(&transaction, request, &request_digest, &authority,)
        ) {
            if existing_attempt != request.attempt_id
                || existing_digest != request_digest
                || existing_bytes != request_bytes
            {
                let custody = custody
                    .take()
                    .expect("collision returns exact precommit custody");
                return Err(
                    CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                        mismatch(
                            "current final-verification capture acquisition",
                            "an attempt or acquisition identity is already bound to different immutable bytes",
                        ),
                        custody,
                    ),
                );
            }
            let transactional = precommit!(load_capture_v36_from(
                &transaction,
                &launch,
                &request.attempt_id,
            ));
            drop(transaction);
            let persisted = match self
                .load_current_final_verification_capture_acquisition_v36(&request.attempt_id)
            {
                Ok(persisted) => persisted,
                Err(error) => {
                    drop(custody.take());
                    return Err(
                        CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(
                            LedgerError::PostCommitStateUncertain {
                                operation: "current final-verification capture acquisition replay readback",
                                recovery_id: request.attempt_id.clone(),
                                detail: error.to_string(),
                            },
                        ),
                    );
                }
            };
            if persisted != transactional {
                drop(custody.take());
                return Err(
                    CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(
                        LedgerError::PostCommitStateUncertain {
                            operation: "current final-verification capture acquisition replay readback",
                            recovery_id: request.attempt_id.clone(),
                            detail: "replay readback changed across the transaction boundary"
                                .into(),
                        },
                    ),
                );
            }
            drop(custody.take());
            return Ok(CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { persisted });
        }

        if custody
            .as_ref()
            .expect("fresh custody remains present")
            .store_origin
            .contract()
            != request
        {
            let custody = custody
                .take()
                .expect("origin mismatch returns exact precommit custody");
            return Err(
                CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                    mismatch(
                        "current final-verification capture acquisition",
                        "fresh acquisition crosses its sealed private-store origin",
                    ),
                    custody,
                ),
            );
        }
        precommit!(
            custody
                .as_ref()
                .expect("fresh custody remains present")
                .launch_permit
                .validate_for_ledger_instance(self.instance_id, &launch)
        );

        precommit!(transaction.pragma_update(None, "defer_foreign_keys", true));
        let deferred: i64 =
            precommit!(
                transaction.pragma_query_value(None, "defer_foreign_keys", |row| row.get(0))
            );
        if deferred != 1 {
            let custody = custody
                .take()
                .expect("pragma mismatch returns exact precommit custody");
            return Err(
                CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                    corrupt(
                        "current final-verification capture acquisition",
                        "SQLite did not retain the required deferred foreign-key mode",
                    ),
                    custody,
                ),
            );
        }
        let expected = PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
            launch: launch.clone(),
            capture_event: event.clone(),
            capture_authority: authority.clone(),
        };
        let guard = CaptureWriteGuardV1 {
            attempt_id: request.attempt_id.clone(),
            event_digest: event.event_digest.clone(),
            capture_authority_digest: authority.capture_authority_digest.clone(),
        };
        precommit!(with_capture_write_guard(guard, || {
            insert_capture_v36(&transaction, request, &authority)?;
            insert_capture_event_v36(&transaction, &event)
        }));
        let transactional = precommit!(load_capture_v36_from(
            &transaction,
            &launch,
            &request.attempt_id,
        ));
        if transactional != expected {
            let custody = custody
                .take()
                .expect("readback mismatch returns exact precommit custody");
            return Err(
                CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                    corrupt(
                        "current final-verification capture acquisition",
                        "transactional readback differs from the exact derived acquisition",
                    ),
                    custody,
                ),
            );
        }
        precommit!(verify_no_foreign_key_violations_v36(&transaction));
        if let Err(error) = transaction.commit() {
            drop(custody.take());
            return Err(
                CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(
                    LedgerError::PostCommitStateUncertain {
                        operation: "current final-verification capture acquisition SQLite commit",
                        recovery_id: request.attempt_id.clone(),
                        detail: error.to_string(),
                    },
                ),
            );
        }

        let persisted = match secure_database_files(&self.database_path)
            .and_then(|()| {
                self.load_current_final_verification_capture_acquisition_v36(&request.attempt_id)
            })
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "current final-verification capture acquisition commit",
                recovery_id: request.attempt_id.clone(),
                detail: error.to_string(),
            }) {
            Ok(persisted) => persisted,
            Err(error) => {
                drop(custody.take());
                return Err(
                    CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(error),
                );
            }
        };
        if persisted != expected {
            drop(custody.take());
            return Err(
                CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(
                    LedgerError::PostCommitStateUncertain {
                        operation: "current final-verification capture acquisition commit",
                        recovery_id: request.attempt_id.clone(),
                        detail: "post-commit readback differs from the exact derived acquisition"
                            .into(),
                    },
                ),
            );
        }
        let native_launch_permit = FreshCurrentFinalVerificationNativeLaunchPermitV1 {
            attempt_id: authority.attempt_id.clone(),
            launch_authority_digest: authority.launch_authority_digest.clone(),
            capture_authority_digest: authority.capture_authority_digest.clone(),
            acquired_anchor_digest: authority.acquired.acquired_anchor_digest.clone(),
            ledger_instance_id: self.instance_id,
        };
        drop(custody.take());
        Ok(CurrentFinalVerificationCaptureAcquisitionCommitV1::Fresh {
            persisted,
            native_launch_permit,
        })
    }

    /// Replays one exact already-committed request without requiring or
    /// recreating either move-only input and without returning a permit.
    ///
    /// # Errors
    ///
    /// Returns an error if no v36 row exists or the request differs from its
    /// exact canonical committed bytes.
    pub fn replay_current_final_verification_capture_acquisition_v36(
        &self,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
    ) -> Result<CurrentFinalVerificationCaptureAcquisitionCommitV1, LedgerError> {
        request.validate_intrinsic()?;
        let launch = self.load_current_final_verification_launch_v35(&request.attempt_id)?;
        request.validate_for_launch(&launch)?;
        let persisted = load_capture_v36_from(&self.connection, &launch, &request.attempt_id)?;
        let stored_request = load_capture_request_bytes_v36(&self.connection, &request.attempt_id)?;
        if stored_request != request.canonical_bytes()? {
            return Err(mismatch(
                "current final-verification capture acquisition replay",
                "request differs from the exact committed canonical bytes",
            ));
        }
        Ok(CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { persisted })
    }

    /// Loads one exact schema-v36 capture frontier without recreating either
    /// the store-origin proof or native-launch permit.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, noncanonical, crossed, stale, or tampered
    /// rows, event bytes, normalized projections, or v35 parent authority.
    pub fn load_current_final_verification_capture_acquisition_v36(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedCurrentFinalVerificationCaptureAcquisitionV1, LedgerError> {
        let launch = self.load_current_final_verification_launch_v35(attempt_id)?;
        load_capture_v36_from(&self.connection, &launch, attempt_id)
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v36 atomic commit"
    )
)]
fn load_capture_collision_v36(
    connection: &Connection,
    request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
    request_digest: &Digest,
    authority: &CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
) -> Result<Option<(String, Digest, Vec<u8>)>, LedgerError> {
    connection
        .query_row(
            "SELECT attempt_id, acquisition_request_digest, acquisition_request_json
             FROM current_final_verification_capture_acquisitions_v36
             WHERE attempt_id = ?1 OR launch_authority_digest = ?2
                OR acquisition_request_digest = ?3 OR capture_intent_id = ?4
                OR capture_id = ?5 OR capture_intent_digest = ?6
                OR acquired_anchor_digest = ?7 OR acquired_store_head_digest = ?8
                OR sensitive_output_journal_id = ?9 OR intent_bound_journal_digest = ?10
                OR acquired_bound_journal_digest = ?11 OR capture_event_id = ?12
                OR capture_authority_digest = ?13",
            params![
                request.attempt_id,
                request.launch_authority_digest.as_str(),
                request_digest.as_str(),
                authority.capture_intent_id,
                request.acquired.capture_id,
                request.acquired.intent_digest.as_str(),
                request.acquired.acquired_anchor_digest.as_str(),
                request.acquired.store_head.record_digest.as_str(),
                request.sensitive_output_journal_id,
                request.intent_bound_journal_head.record_digest.as_str(),
                request.acquired_bound_journal_head.record_digest.as_str(),
                authority.capture_event_id,
                authority.capture_authority_digest.as_str(),
            ],
            |row| {
                let digest = Digest::parse(row.get::<_, String>(1)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok((row.get(0)?, digest, row.get(2)?))
            },
        )
        .optional()
        .map_err(Into::into)
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v36 atomic commit"
    )
)]
fn insert_capture_v36(
    transaction: &Transaction<'_>,
    request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
    authority: &CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_capture_acquisitions_v36 (
             attempt_id, acquisition_version, sprint_id, launch_authority_digest,
             acquisition_request_digest, acquisition_request_json,
             capture_intent_id, capture_id, capture_intent_digest,
             acquired_anchor_digest, acquired_json, acquired_store_head_generation,
             acquired_store_head_digest, sensitive_output_journal_id,
             intent_bound_journal_generation, intent_bound_journal_digest,
             acquired_bound_journal_generation, acquired_bound_journal_digest,
             launch_event_id, launch_event_sequence, capture_event_id,
             capture_event_sequence, acquired_at_unix_ms,
             capture_authority_digest, capture_authority_json
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
             ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25
         )",
        params![
            authority.attempt_id,
            i64::from(authority.acquisition_version),
            authority.sprint_id,
            authority.launch_authority_digest.as_str(),
            authority.acquisition_request_digest.as_str(),
            request.canonical_bytes()?,
            authority.capture_intent_id,
            authority.acquired.capture_id,
            authority.acquired.intent_digest.as_str(),
            authority.acquired.acquired_anchor_digest.as_str(),
            encode_canonical(&authority.acquired)?,
            sqlite_integer(
                "acquired_store_head_generation",
                authority.acquired.store_head.generation,
            )?,
            authority.acquired.store_head.record_digest.as_str(),
            authority.sensitive_output_journal_id,
            sqlite_integer(
                "intent_bound_journal_generation",
                authority.intent_bound_journal_head.generation,
            )?,
            authority.intent_bound_journal_head.record_digest.as_str(),
            sqlite_integer(
                "acquired_bound_journal_generation",
                authority.acquired_bound_journal_head.generation,
            )?,
            authority.acquired_bound_journal_head.record_digest.as_str(),
            authority.launch_event_id,
            sqlite_integer("launch_event_sequence", authority.launch_event_sequence)?,
            authority.capture_event_id,
            sqlite_integer("capture_event_sequence", authority.capture_event_sequence)?,
            sqlite_integer("acquired_at_unix_ms", authority.acquired_at_unix_ms)?,
            authority.capture_authority_digest.as_str(),
            authority.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v36 atomic commit"
    )
)]
fn insert_capture_event_v36(
    transaction: &Transaction<'_>,
    event: &CurrentFinalVerificationAuthorityEventV1,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_events_v34 (
             sprint_id, event_sequence, event_id, event_version, event_kind,
             attempt_id, request_id, request_digest, occurred_at_unix_ms,
             event_digest, event_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.sprint_id,
            sqlite_integer("capture_event_sequence", event.event_sequence)?,
            event.event_id,
            i64::from(event.event_version),
            event_kind_sql(event.event_kind),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            sqlite_integer("capture_event_time", event.occurred_at_unix_ms)?,
            event.event_digest.as_str(),
            event.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn load_capture_request_bytes_v36(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Vec<u8>, LedgerError> {
    connection
        .query_row(
            "SELECT acquisition_request_json
             FROM current_final_verification_capture_acquisitions_v36
             WHERE attempt_id = ?1",
            [attempt_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification capture acquisition v36",
            id: attempt_id.to_owned(),
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "exact readback checks every normalized acquisition projection and parent edge in one auditable path"
)]
fn load_capture_v36_from(
    connection: &Connection,
    launch: &PersistedCurrentFinalVerificationLaunchV1,
    attempt_id: &str,
) -> Result<PersistedCurrentFinalVerificationCaptureAcquisitionV1, LedgerError> {
    let (request_bytes, acquired_bytes, authority_bytes) = connection
        .query_row(
            "SELECT acquisition_request_json, acquired_json, capture_authority_json
             FROM current_final_verification_capture_acquisitions_v36
             WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification capture acquisition v36",
            id: attempt_id.to_owned(),
        })?;
    let request: CurrentFinalVerificationCaptureAcquisitionRequestV1 =
        decode_exact("current final-verification capture request", &request_bytes)
            .map_err(|detail| corrupt("current final-verification capture request", detail))?;
    let acquired: CommandOutputCaptureAcquiredV1 =
        decode_exact("command-output capture acquired", &acquired_bytes)
            .map_err(|detail| corrupt("command-output capture acquired", detail))?;
    let authority: CurrentFinalVerificationCaptureAcquisitionAuthorityV1 = decode_exact(
        "current final-verification capture authority",
        &authority_bytes,
    )
    .map_err(|detail| corrupt("current final-verification capture authority", detail))?;
    request.validate_for_launch(launch)?;
    acquired.validate_against(&launch.launch_authority.capture_intent)?;
    if request.acquired != acquired || authority.acquired != acquired {
        return Err(corrupt(
            "current final-verification capture acquisition",
            "request, standalone acquired bytes, and authority differ",
        ));
    }
    let event = load_capture_event_v36(connection, &authority.capture_event_id)?;
    authority.validate_for(launch, &request, &event)?;
    let projection_matches: bool = connection.query_row(
        "SELECT
             attempt_id = ?1 AND acquisition_version = ?2 AND sprint_id = ?3
             AND launch_authority_digest = ?4 AND acquisition_request_digest = ?5
             AND capture_intent_id = ?6 AND capture_id = ?7
             AND capture_intent_digest = ?8 AND acquired_anchor_digest = ?9
             AND acquired_store_head_generation = ?10
             AND acquired_store_head_digest = ?11
             AND sensitive_output_journal_id = ?12
             AND intent_bound_journal_generation = ?13
             AND intent_bound_journal_digest = ?14
             AND acquired_bound_journal_generation = ?15
             AND acquired_bound_journal_digest = ?16
             AND launch_event_id = ?17 AND launch_event_sequence = ?18
             AND capture_event_id = ?19 AND capture_event_sequence = ?20
             AND acquired_at_unix_ms = ?21 AND capture_authority_digest = ?22
             AND acquisition_request_json = ?23 AND acquired_json = ?24
             AND capture_authority_json = ?25
         FROM current_final_verification_capture_acquisitions_v36
         WHERE attempt_id = ?1",
        params![
            authority.attempt_id,
            i64::from(authority.acquisition_version),
            authority.sprint_id,
            authority.launch_authority_digest.as_str(),
            authority.acquisition_request_digest.as_str(),
            authority.capture_intent_id,
            authority.acquired.capture_id,
            authority.acquired.intent_digest.as_str(),
            authority.acquired.acquired_anchor_digest.as_str(),
            sqlite_integer(
                "acquired_store_head_generation",
                authority.acquired.store_head.generation
            )?,
            authority.acquired.store_head.record_digest.as_str(),
            authority.sensitive_output_journal_id,
            sqlite_integer(
                "intent_bound_journal_generation",
                authority.intent_bound_journal_head.generation
            )?,
            authority.intent_bound_journal_head.record_digest.as_str(),
            sqlite_integer(
                "acquired_bound_journal_generation",
                authority.acquired_bound_journal_head.generation
            )?,
            authority.acquired_bound_journal_head.record_digest.as_str(),
            authority.launch_event_id,
            sqlite_integer("launch_event_sequence", authority.launch_event_sequence)?,
            authority.capture_event_id,
            sqlite_integer("capture_event_sequence", authority.capture_event_sequence)?,
            sqlite_integer("acquired_at_unix_ms", authority.acquired_at_unix_ms)?,
            authority.capture_authority_digest.as_str(),
            request_bytes,
            acquired_bytes,
            authority_bytes,
        ],
        |row| row.get(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification capture acquisition",
            "stored normalized projection differs from exact canonical bytes",
        ));
    }
    Ok(PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
        launch: launch.clone(),
        capture_event: event,
        capture_authority: authority,
    })
}

fn load_capture_event_v36(
    connection: &Connection,
    event_id: &str,
) -> Result<CurrentFinalVerificationAuthorityEventV1, LedgerError> {
    let event_bytes = connection
        .query_row(
            "SELECT event_json FROM current_final_verification_events_v34
             WHERE event_id = ?1 AND event_kind = 'CaptureAcquired'",
            [event_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification CaptureAcquired event",
            id: event_id.to_owned(),
        })?;
    let event: CurrentFinalVerificationAuthorityEventV1 = decode_exact(
        "current final-verification CaptureAcquired event",
        &event_bytes,
    )
    .map_err(|detail| corrupt("current final-verification CaptureAcquired event", detail))?;
    event.validate_integrity()?;
    let projection_matches: bool = connection.query_row(
        "SELECT sprint_id = ?1 AND event_sequence = ?2 AND event_id = ?3
             AND event_version = ?4 AND event_kind = ?5 AND attempt_id = ?6
             AND request_id = ?7 AND request_digest = ?8
             AND occurred_at_unix_ms = ?9 AND event_digest = ?10
             AND event_json = ?11
         FROM current_final_verification_events_v34 WHERE event_id = ?3",
        params![
            event.sprint_id,
            sqlite_integer("capture_event_sequence", event.event_sequence)?,
            event.event_id,
            i64::from(event.event_version),
            event_kind_sql(event.event_kind),
            event.attempt_id,
            event.request_id,
            event.request_digest.as_str(),
            sqlite_integer("capture_event_time", event.occurred_at_unix_ms)?,
            event.event_digest.as_str(),
            event_bytes,
        ],
        |row| row.get(0),
    )?;
    if !projection_matches {
        return Err(corrupt(
            "current final-verification CaptureAcquired event",
            "stored normalized projection differs from exact canonical bytes",
        ));
    }
    Ok(event)
}

fn capture_event(
    launch: &PersistedCurrentFinalVerificationLaunchV1,
    request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
) -> Result<CurrentFinalVerificationAuthorityEventV1, ContractError> {
    capture_event_for_launch_authority(&launch.launch_authority, request)
}

fn capture_event_for_launch_authority(
    authority: &super::CurrentFinalVerificationLaunchAuthorityV1,
    request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
) -> Result<CurrentFinalVerificationAuthorityEventV1, ContractError> {
    request.validate_for_launch_authority(authority)?;
    let event_sequence = authority
        .launch_event_sequence
        .checked_add(1)
        .ok_or_else(|| ContractError::new("capture_event.event_sequence", "overflowed"))?;
    let mut event = CurrentFinalVerificationAuthorityEventV1 {
        event_version: ACQUISITION_VERSION_V1,
        event_id: authority
            .reservations
            .fields
            .capture_acquired_event_id
            .clone(),
        sprint_id: authority.sprint_id.clone(),
        event_sequence,
        event_kind: CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired,
        attempt_id: authority.attempt_id.clone(),
        request_id: authority.reservations.fields.capture_intent_id.clone(),
        request_digest: authority.capture_intent.intent_digest.clone(),
        occurred_at_unix_ms: request.acquired.acquired_at_unix_ms,
        event_digest: Digest::sha256(&[]),
    };
    event.event_digest = event.computed_event_digest()?;
    event.validate_integrity()?;
    Ok(event)
}

fn validate_capture_event_for_launch_authority(
    event: &CurrentFinalVerificationAuthorityEventV1,
    launch_authority: &super::CurrentFinalVerificationLaunchAuthorityV1,
    request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
) -> Result<(), ContractError> {
    if event != &capture_event_for_launch_authority(launch_authority, request)? {
        return Err(ContractError::new(
            "capture_event",
            "does not equal the exact reserved CaptureAcquired event",
        ));
    }
    require_canonical_bound("capture_event", &event.canonical_bytes()?)
}

#[derive(Clone)]
struct CaptureWriteGuardV1 {
    attempt_id: String,
    event_digest: Digest,
    capture_authority_digest: Digest,
}

thread_local! {
    static CAPTURE_WRITE_GUARD_V1: RefCell<Option<CaptureWriteGuardV1>> = const { RefCell::new(None) };
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v36 atomic commit"
    )
)]
struct CaptureWriteGuardResetV1;

impl Drop for CaptureWriteGuardResetV1 {
    fn drop(&mut self) {
        CAPTURE_WRITE_GUARD_V1.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used only by the deliberately dormant schema-v36 atomic commit"
    )
)]
fn with_capture_write_guard<T>(
    guard: CaptureWriteGuardV1,
    operation: impl FnOnce() -> Result<T, LedgerError>,
) -> Result<T, LedgerError> {
    let was_empty = CAPTURE_WRITE_GUARD_V1.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            false
        } else {
            *slot = Some(guard);
            true
        }
    });
    if !was_empty {
        return Err(corrupt(
            "current final-verification capture writer",
            "nested private capture-write admission is forbidden",
        ));
    }
    let _reset = CaptureWriteGuardResetV1;
    operation()
}

pub(super) fn sqlite_capture_write_admitted(
    record_kind: &str,
    attempt_id: &str,
    record_identity: &str,
) -> i64 {
    CAPTURE_WRITE_GUARD_V1.with(|slot| {
        i64::from(slot.borrow().as_ref().is_some_and(|guard| {
            guard.attempt_id == attempt_id
                && match record_kind {
                    "event" => guard.event_digest.as_str() == record_identity,
                    "capture" => guard.capture_authority_digest.as_str() == record_identity,
                    _ => false,
                }
        }))
    })
}

pub(super) fn sqlite_capture_request_canonical(bytes: &[u8]) -> Result<i64, String> {
    let request: CurrentFinalVerificationCaptureAcquisitionRequestV1 =
        decode_exact("current final-verification capture request", bytes)?;
    request
        .validate_intrinsic()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_capture_request_digest(bytes: &[u8]) -> Result<String, String> {
    let request: CurrentFinalVerificationCaptureAcquisitionRequestV1 =
        decode_exact("current final-verification capture request", bytes)?;
    request
        .canonical_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_acquired_canonical(bytes: &[u8]) -> Result<i64, String> {
    let acquired: CommandOutputCaptureAcquiredV1 =
        decode_exact("command-output capture acquired", bytes)?;
    acquired
        .validate()
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_acquired_digest(bytes: &[u8]) -> Result<String, String> {
    let acquired: CommandOutputCaptureAcquiredV1 =
        decode_exact("command-output capture acquired", bytes)?;
    acquired
        .validate()
        .map(|()| acquired.acquired_anchor_digest.to_string())
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_capture_canonical(bytes: &[u8]) -> Result<i64, String> {
    let authority: CurrentFinalVerificationCaptureAcquisitionAuthorityV1 =
        decode_exact("current final-verification capture authority", bytes)?;
    if authority.capture_authority_digest
        != authority
            .computed_digest()
            .map_err(|error| error.to_string())?
    {
        return Err("capture authority digest mismatch".into());
    }
    require_canonical_bound("capture_acquisition_authority", bytes)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn sqlite_capture_digest(bytes: &[u8]) -> Result<String, String> {
    let authority: CurrentFinalVerificationCaptureAcquisitionAuthorityV1 =
        decode_exact("current final-verification capture authority", bytes)?;
    if authority.capture_authority_digest
        != authority
            .computed_digest()
            .map_err(|error| error.to_string())?
    {
        return Err("capture authority digest mismatch".into());
    }
    Ok(authority.capture_authority_digest.to_string())
}

pub(super) fn sqlite_capture_matches(
    authority_bytes: &[u8],
    request_bytes: &[u8],
    launch_bytes: &[u8],
) -> Result<i64, String> {
    let authority: CurrentFinalVerificationCaptureAcquisitionAuthorityV1 = decode_exact(
        "current final-verification capture authority",
        authority_bytes,
    )?;
    let request: CurrentFinalVerificationCaptureAcquisitionRequestV1 =
        decode_exact("current final-verification capture request", request_bytes)?;
    let launch_authority: super::CurrentFinalVerificationLaunchAuthorityV1 =
        decode_exact("current final-verification launch authority", launch_bytes)?;
    if super::current_final_verification_launch_v35::sqlite_launch_canonical(launch_bytes)? != 1 {
        return Ok(0);
    }
    let event = capture_event_for_launch_authority(&launch_authority, &request)
        .map_err(|error| error.to_string())?;
    authority
        .validate_for_launch_authority(&launch_authority, &request, &event)
        .map(|()| 1)
        .map_err(|error| error.to_string())
}

pub(super) fn verify_no_foreign_key_violations_v36(
    connection: &Connection,
) -> Result<(), LedgerError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        Err(corrupt(
            "current final-verification capture acquisition",
            "foreign-key check reported a violation before commit",
        ))
    } else {
        Ok(())
    }
}

const fn event_kind_sql(kind: CurrentFinalVerificationAuthorityEventKindV1) -> &'static str {
    match kind {
        CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted => "AttemptAdmitted",
        CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted => "LaunchCommitted",
        CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired => "CaptureAcquired",
        CurrentFinalVerificationAuthorityEventKindV1::V13Initialized => "V13Initialized",
        CurrentFinalVerificationAuthorityEventKindV1::CommandDispatched => "CommandDispatched",
        CurrentFinalVerificationAuthorityEventKindV1::ControlIssued => "ControlIssued",
        CurrentFinalVerificationAuthorityEventKindV1::ControlObserved => "ControlObserved",
        CurrentFinalVerificationAuthorityEventKindV1::ControlReconciled => "ControlReconciled",
        CurrentFinalVerificationAuthorityEventKindV1::TerminalObserved => "TerminalObserved",
        CurrentFinalVerificationAuthorityEventKindV1::EffectCutObserved => "EffectCutObserved",
        CurrentFinalVerificationAuthorityEventKindV1::OutputCustodyClosed => "OutputCustodyClosed",
        CurrentFinalVerificationAuthorityEventKindV1::CommandDomainCleanupObserved => {
            "CommandDomainCleanupObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerDirectChildObserved => {
            "RunnerDirectChildObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerDomainObserved => {
            "RunnerDomainObserved"
        }
        CurrentFinalVerificationAuthorityEventKindV1::RunnerCleanupClosed => "RunnerCleanupClosed",
        CurrentFinalVerificationAuthorityEventKindV1::EvidenceClosed => "EvidenceClosed",
        CurrentFinalVerificationAuthorityEventKindV1::OutcomeDerived => "OutcomeDerived",
    }
}

fn encode_canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(value).map_err(|error| {
        ContractError::new(
            "current_final_verification_capture_v36.canonical_json",
            format!("cannot encode canonical JSON: {error}"),
        )
    })
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    entity: &'static str,
    bytes: &[u8],
) -> Result<T, String> {
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        return Err(format!(
            "{entity} bytes must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes"
        ));
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| format!("cannot decode {entity}: {error}"))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("cannot canonicalize {entity}: {error}"))?;
    if canonical != bytes {
        return Err(format!("{entity} is not exact canonical JSON"));
    }
    Ok(value)
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

fn require_version(field: &'static str, version: u32) -> Result<(), ContractError> {
    if version == ACQUISITION_VERSION_V1 {
        Ok(())
    } else {
        Err(ContractError::new(field, "must equal version 1"))
    }
}

fn require_identifier(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2
        || value.as_bytes().contains(&0)
    {
        Err(ContractError::new(
            field,
            format!(
                "must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2} non-NUL UTF-8 bytes and not be blank"
            ),
        ))
    } else {
        Ok(())
    }
}

fn require_canonical_bound(field: &'static str, bytes: &[u8]) -> Result<(), ContractError> {
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        Err(ContractError::new(
            field,
            format!(
                "canonical bytes must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes"
            ),
        ))
    } else {
        Ok(())
    }
}

fn sqlite_integer(field: &'static str, value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::IntegerOutOfRange(field))
}

fn mismatch(entity: &'static str, detail: impl Into<String>) -> LedgerError {
    LedgerError::ReferenceMismatch {
        entity,
        detail: detail.into(),
    }
}

fn corrupt(entity: &'static str, detail: impl Into<String>) -> LedgerError {
    LedgerError::Corrupt {
        entity,
        detail: detail.into(),
    }
}
#[cfg(test)]
pub(super) mod tests {
    use std::fs;
    use std::time::Duration;

    use rusqlite::types::{Value, ValueRef};
    use rusqlite::{Connection, params_from_iter};

    use super::*;
    use crate::ledger::current_final_verification_launch_v35::tests::{
        LaunchFixture, exact_v35_launch_fixture, launch_fixture, token,
    };
    use crate::ledger::{
        MIGRATIONS, load_schema_objects, register_schema_functions, run_migrations,
        verify_exact_schema,
    };
    use crate::{
        CommandOutputCaptureDirectoryIdentityV1, CommandOutputCaptureFileIdentityV1,
        CommandOutputCaptureStoreHeadV1, CurrentFinalVerificationLaunchCommitV1,
    };

    struct CaptureFixture {
        launch_fixture: LaunchFixture,
        launch: PersistedCurrentFinalVerificationLaunchV1,
        request: CurrentFinalVerificationCaptureAcquisitionRequestV1,
        launch_permit: Option<FreshCurrentFinalVerificationCaptureAcquisitionPermitV1>,
    }

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn launch_and_permit(
        fixture: &mut LaunchFixture,
    ) -> (
        PersistedCurrentFinalVerificationLaunchV1,
        FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
    ) {
        match fixture
            .ledger
            .commit_current_final_verification_launch_v35(
                &fixture.request,
                token(&fixture.request),
                &fixture.issued_grant,
                &fixture.compiled_policy,
            )
            .expect("commit exact v35 launch")
        {
            CurrentFinalVerificationLaunchCommitV1::Fresh {
                persisted,
                capture_acquisition_permit,
            } => (persisted, capture_acquisition_permit),
            CurrentFinalVerificationLaunchCommitV1::Replay { .. } => {
                panic!("new fixture must produce a fresh v35 launch")
            }
        }
    }

    fn acquired_for(
        launch: &PersistedCurrentFinalVerificationLaunchV1,
        label: &str,
        acquired_at_unix_ms: u64,
        directory_inode: u64,
        stdout_inode: u64,
        stderr_inode: u64,
    ) -> CommandOutputCaptureAcquiredV1 {
        let authority = &launch.launch_authority;
        CommandOutputCaptureAcquiredV1::try_new(
            &authority.capture_intent,
            authority.reservations.fields.dispatch_id.clone(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: digest(&format!("v1-acquired-store-head-{label}")),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 7,
                inode: directory_inode,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: stdout_inode,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 7,
                inode: stderr_inode,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            acquired_at_unix_ms,
        )
        .expect("construct exact test store acquisition")
    }

    fn request_for_acquired(
        launch: &PersistedCurrentFinalVerificationLaunchV1,
        acquired: CommandOutputCaptureAcquiredV1,
    ) -> CurrentFinalVerificationCaptureAcquisitionRequestV1 {
        let detector_policy = launch.launch_authority.detector_policy.clone();
        let sensitive_output_journal_id = format!(
            "{SENSITIVE_OUTPUT_JOURNAL_ID_PREFIX_V2}{}",
            acquired.capture_id
        );
        let heads = super::super::sensitive_output_rejection::derive_sensitive_output_acquisition_journal_heads_v2(
            &sensitive_output_journal_id,
            &acquired.capture_id,
            &acquired.source.runner_session_id,
            &acquired.source.effect_id,
            &acquired.source.request_digest,
            &acquired.intent_digest,
            &detector_policy,
            &acquired,
        )
        .expect("derive exact sensitive-output acquisition prefix");
        CurrentFinalVerificationCaptureAcquisitionRequestV1 {
            acquisition_version: 1,
            attempt_id: launch.launch_authority.attempt_id.clone(),
            launch_authority_digest: launch.launch_authority.launch_authority_digest.clone(),
            acquired,
            detector_policy,
            sensitive_output_journal_id,
            intent_bound_journal_head: heads[0].clone(),
            acquired_bound_journal_head: heads[1].clone(),
        }
    }

    const CAPTURE_INSERT_COLUMNS_V36: [&str; 25] = [
        "attempt_id",
        "acquisition_version",
        "sprint_id",
        "launch_authority_digest",
        "acquisition_request_digest",
        "acquisition_request_json",
        "capture_intent_id",
        "capture_id",
        "capture_intent_digest",
        "acquired_anchor_digest",
        "acquired_json",
        "acquired_store_head_generation",
        "acquired_store_head_digest",
        "sensitive_output_journal_id",
        "intent_bound_journal_generation",
        "intent_bound_journal_digest",
        "acquired_bound_journal_generation",
        "acquired_bound_journal_digest",
        "launch_event_id",
        "launch_event_sequence",
        "capture_event_id",
        "capture_event_sequence",
        "acquired_at_unix_ms",
        "capture_authority_digest",
        "capture_authority_json",
    ];

    fn capture_insert_values(
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
        authority: &CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
    ) -> Vec<Value> {
        vec![
            Value::Text(authority.attempt_id.clone()),
            Value::Integer(i64::from(authority.acquisition_version)),
            Value::Text(authority.sprint_id.clone()),
            Value::Text(authority.launch_authority_digest.to_string()),
            Value::Text(authority.acquisition_request_digest.to_string()),
            Value::Blob(
                request
                    .canonical_bytes()
                    .expect("canonical acquisition request"),
            ),
            Value::Text(authority.capture_intent_id.clone()),
            Value::Text(authority.acquired.capture_id.clone()),
            Value::Text(authority.acquired.intent_digest.to_string()),
            Value::Text(authority.acquired.acquired_anchor_digest.to_string()),
            Value::Blob(encode_canonical(&authority.acquired).expect("canonical acquired anchor")),
            Value::Integer(
                i64::try_from(authority.acquired.store_head.generation)
                    .expect("store generation fits SQLite"),
            ),
            Value::Text(authority.acquired.store_head.record_digest.to_string()),
            Value::Text(authority.sensitive_output_journal_id.clone()),
            Value::Integer(
                i64::try_from(authority.intent_bound_journal_head.generation)
                    .expect("intent-bound generation fits SQLite"),
            ),
            Value::Text(
                authority
                    .intent_bound_journal_head
                    .record_digest
                    .to_string(),
            ),
            Value::Integer(
                i64::try_from(authority.acquired_bound_journal_head.generation)
                    .expect("acquired-bound generation fits SQLite"),
            ),
            Value::Text(
                authority
                    .acquired_bound_journal_head
                    .record_digest
                    .to_string(),
            ),
            Value::Text(authority.launch_event_id.clone()),
            Value::Integer(
                i64::try_from(authority.launch_event_sequence)
                    .expect("launch sequence fits SQLite"),
            ),
            Value::Text(authority.capture_event_id.clone()),
            Value::Integer(
                i64::try_from(authority.capture_event_sequence)
                    .expect("capture sequence fits SQLite"),
            ),
            Value::Integer(
                i64::try_from(authority.acquired_at_unix_ms).expect("acquisition time fits SQLite"),
            ),
            Value::Text(authority.capture_authority_digest.to_string()),
            Value::Blob(
                authority
                    .canonical_bytes()
                    .expect("canonical capture authority"),
            ),
        ]
    }

    fn execute_capture_insert_values(
        connection: &Connection,
        values: &[Value],
        replace: bool,
    ) -> rusqlite::Result<usize> {
        assert_eq!(values.len(), CAPTURE_INSERT_COLUMNS_V36.len());
        let algorithm = if replace { " OR REPLACE" } else { "" };
        let sql = format!(
            "INSERT{algorithm} INTO current_final_verification_capture_acquisitions_v36 ({}) VALUES ({})",
            CAPTURE_INSERT_COLUMNS_V36.join(", "),
            (1..=CAPTURE_INSERT_COLUMNS_V36.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        connection.execute(&sql, params_from_iter(values))
    }

    fn capture_guard(
        authority: &CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
        event: &CurrentFinalVerificationAuthorityEventV1,
    ) -> CaptureWriteGuardV1 {
        CaptureWriteGuardV1 {
            attempt_id: authority.attempt_id.clone(),
            event_digest: event.event_digest.clone(),
            capture_authority_digest: authority.capture_authority_digest.clone(),
        }
    }

    fn derived_capture(
        fixture: &CaptureFixture,
    ) -> (
        CurrentFinalVerificationAuthorityEventV1,
        CurrentFinalVerificationCaptureAcquisitionAuthorityV1,
    ) {
        let event = capture_event(&fixture.launch, &fixture.request).expect("derive capture event");
        let authority = CurrentFinalVerificationCaptureAcquisitionAuthorityV1::new(
            &fixture.launch,
            &fixture.request,
            &event,
        )
        .expect("derive capture authority");
        (event, authority)
    }

    fn mutate_sqlite_value(column: &str, value: &Value) -> Value {
        match value {
            Value::Integer(integer) => Value::Integer(integer.saturating_add(1)),
            Value::Real(real) => Value::Real(real + 1.0),
            Value::Text(_) => Value::Text(digest(&format!("crossed-{column}")).to_string()),
            Value::Blob(blob) => {
                let mut crossed = blob.clone();
                if crossed.is_empty() {
                    crossed.push(b'x');
                } else {
                    crossed[0] ^= 1;
                }
                Value::Blob(crossed)
            }
            Value::Null => Value::Integer(1),
        }
    }

    fn json_scalar_mutations(canonical: &[u8]) -> Vec<Vec<u8>> {
        let mut spans = Vec::new();
        let mut index = 0;
        while index < canonical.len() {
            match canonical[index] {
                b'"' => {
                    let start = index;
                    index += 1;
                    while index < canonical.len() {
                        match canonical[index] {
                            b'\\' => index += 2,
                            b'"' => {
                                index += 1;
                                break;
                            }
                            _ => index += 1,
                        }
                    }
                    let mut next = index;
                    while next < canonical.len() && canonical[next].is_ascii_whitespace() {
                        next += 1;
                    }
                    if canonical.get(next) != Some(&b':') {
                        spans.push((start, index, b"\"scalar-mutated\"".as_slice()));
                    }
                }
                b'-' | b'0'..=b'9' => {
                    let start = index;
                    index += 1;
                    while index < canonical.len()
                        && matches!(
                            canonical[index],
                            b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                        )
                    {
                        index += 1;
                    }
                    let replacement = if &canonical[start..index] == b"1" {
                        b"2".as_slice()
                    } else {
                        b"1".as_slice()
                    };
                    spans.push((start, index, replacement));
                }
                b't' if canonical[index..].starts_with(b"true") => {
                    spans.push((index, index + 4, b"false".as_slice()));
                    index += 4;
                }
                b'f' if canonical[index..].starts_with(b"false") => {
                    spans.push((index, index + 5, b"true".as_slice()));
                    index += 5;
                }
                b'n' if canonical[index..].starts_with(b"null") => {
                    spans.push((index, index + 4, b"true".as_slice()));
                    index += 4;
                }
                _ => index += 1,
            }
        }
        spans
            .into_iter()
            .map(|(start, end, replacement)| {
                let mut mutated =
                    Vec::with_capacity(canonical.len() - (end - start) + replacement.len());
                mutated.extend_from_slice(&canonical[..start]);
                mutated.extend_from_slice(replacement);
                mutated.extend_from_slice(&canonical[end..]);
                mutated
            })
            .collect()
    }

    const EVENT_INSERT_COLUMNS_V36: [&str; 11] = [
        "sprint_id",
        "event_sequence",
        "event_id",
        "event_version",
        "event_kind",
        "attempt_id",
        "request_id",
        "request_digest",
        "occurred_at_unix_ms",
        "event_digest",
        "event_json",
    ];

    fn event_insert_values(event: &CurrentFinalVerificationAuthorityEventV1) -> Vec<Value> {
        vec![
            Value::Text(event.sprint_id.clone()),
            Value::Integer(i64::try_from(event.event_sequence).expect("event sequence fits")),
            Value::Text(event.event_id.clone()),
            Value::Integer(i64::from(event.event_version)),
            Value::Text(event_kind_sql(event.event_kind).into()),
            Value::Text(event.attempt_id.clone()),
            Value::Text(event.request_id.clone()),
            Value::Text(event.request_digest.to_string()),
            Value::Integer(i64::try_from(event.occurred_at_unix_ms).expect("event time fits")),
            Value::Text(event.event_digest.to_string()),
            Value::Blob(event.canonical_bytes().expect("canonical event")),
        ]
    }

    fn execute_event_insert_values(
        connection: &Connection,
        values: &[Value],
    ) -> rusqlite::Result<usize> {
        assert_eq!(values.len(), EVENT_INSERT_COLUMNS_V36.len());
        let sql = format!(
            "INSERT INTO current_final_verification_events_v34 ({}) VALUES ({})",
            EVENT_INSERT_COLUMNS_V36.join(", "),
            (1..=EVENT_INSERT_COLUMNS_V36.len())
                .map(|index| format!("?{index}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        connection.execute(&sql, params_from_iter(values))
    }

    #[derive(Debug, Eq, PartialEq)]
    enum RawSqliteValueV36 {
        Null,
        Integer(i64),
        RealBits(u64),
        Text(Vec<u8>),
        Blob(Vec<u8>),
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RawSqliteCellV36 {
        storage_class: &'static str,
        value: RawSqliteValueV36,
    }

    fn raw_table_image_v36(
        connection: &Connection,
        table: &str,
        order_by: &str,
    ) -> Vec<Vec<RawSqliteCellV36>> {
        let sql = format!("SELECT * FROM {table} ORDER BY {order_by}");
        let mut statement = connection
            .prepare(&sql)
            .expect("prepare raw v35 table image");
        let column_count = statement.column_count();
        let mut rows = statement.query([]).expect("query raw v35 table image");
        let mut image = Vec::new();
        while let Some(row) = rows.next().expect("read raw v35 row") {
            let mut cells = Vec::with_capacity(column_count);
            for index in 0..column_count {
                let cell = match row.get_ref(index).expect("read raw v35 SQLite cell") {
                    ValueRef::Null => RawSqliteCellV36 {
                        storage_class: "null",
                        value: RawSqliteValueV36::Null,
                    },
                    ValueRef::Integer(value) => RawSqliteCellV36 {
                        storage_class: "integer",
                        value: RawSqliteValueV36::Integer(value),
                    },
                    ValueRef::Real(value) => RawSqliteCellV36 {
                        storage_class: "real",
                        value: RawSqliteValueV36::RealBits(value.to_bits()),
                    },
                    ValueRef::Text(bytes) => RawSqliteCellV36 {
                        storage_class: "text",
                        value: RawSqliteValueV36::Text(bytes.to_vec()),
                    },
                    ValueRef::Blob(bytes) => RawSqliteCellV36 {
                        storage_class: "blob",
                        value: RawSqliteValueV36::Blob(bytes.to_vec()),
                    },
                };
                cells.push(cell);
            }
            image.push(cells);
        }
        image
    }

    fn populated_v35_raw_image(connection: &Connection) -> [Vec<Vec<RawSqliteCellV36>>; 5] {
        [
            raw_table_image_v36(
                connection,
                "current_final_verification_attempts_v32",
                "attempt_id",
            ),
            raw_table_image_v36(
                connection,
                "current_final_verification_events_v34",
                "sprint_id, event_sequence",
            ),
            raw_table_image_v36(
                connection,
                "current_final_verification_operational_attempts_v34",
                "attempt_id",
            ),
            raw_table_image_v36(
                connection,
                "current_final_verification_launches_v35",
                "attempt_id",
            ),
            raw_table_image_v36(
                connection,
                "current_final_verification_lifecycle_reservations_v35",
                "attempt_id, reservation_role",
            ),
        ]
    }

    fn capture_fixture(label: &str) -> CaptureFixture {
        let mut launch_fixture = launch_fixture(label);
        let (launch, launch_permit) = launch_and_permit(&mut launch_fixture);
        let request =
            request_for_acquired(&launch, acquired_for(&launch, label, 50, 100, 101, 102));
        request
            .validate_for_launch(&launch)
            .expect("valid exact v36 request");
        CaptureFixture {
            launch_fixture,
            launch,
            request,
            launch_permit: Some(launch_permit),
        }
    }

    fn custody_for(
        launch_permit: FreshCurrentFinalVerificationCaptureAcquisitionPermitV1,
        request: &CurrentFinalVerificationCaptureAcquisitionRequestV1,
    ) -> FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1 {
        let origin =
            AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1::from_test(request.clone())
                .expect("seal test-only store origin");
        FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1::new(launch_permit, origin)
    }

    fn commit_fresh(
        fixture: &mut CaptureFixture,
    ) -> (
        PersistedCurrentFinalVerificationCaptureAcquisitionV1,
        FreshCurrentFinalVerificationNativeLaunchPermitV1,
    ) {
        let custody = custody_for(
            fixture
                .launch_permit
                .take()
                .expect("fresh fixture retains v35 permit"),
            &fixture.request,
        );
        match fixture
            .launch_fixture
            .ledger
            .commit_current_final_verification_capture_acquisition_v36(&fixture.request, custody)
            .expect("commit exact v36 acquisition")
        {
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Fresh {
                persisted,
                native_launch_permit,
            } => (persisted, native_launch_permit),
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { .. } => {
                panic!("new fixture must produce a fresh v36 capture")
            }
        }
    }

    pub(in crate::ledger) fn fresh_capture_and_native_launch_permit(
        label: &str,
    ) -> (
        EventLedger,
        PersistedCurrentFinalVerificationCaptureAcquisitionV1,
        FreshCurrentFinalVerificationNativeLaunchPermitV1,
        super::super::current_final_verification_launch_v35::tests::TestFiles,
    ) {
        let mut fixture = capture_fixture(label);
        let (persisted, permit) = commit_fresh(&mut fixture);
        (
            fixture.launch_fixture.ledger,
            persisted,
            permit,
            fixture.launch_fixture.files,
        )
    }

    fn retry_precommit_custody_to_fresh(
        fixture: &mut CaptureFixture,
        failure: CurrentFinalVerificationCaptureAcquisitionCommitErrorV1,
    ) -> PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
        let (_cause, custody) = failure
            .into_precommit()
            .expect("fault is definitely pre-commit and returns exact custody");
        match fixture
            .launch_fixture
            .ledger
            .commit_current_final_verification_capture_acquisition_v36(&fixture.request, custody)
            .expect("the exact returned custody retries to one fresh commit")
        {
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Fresh {
                persisted,
                native_launch_permit,
            } => {
                native_launch_permit
                    .consume_for_ledger_instance(
                        fixture.launch_fixture.ledger.instance_id,
                        &persisted,
                    )
                    .expect("fresh retry returns the exact same-instance next-stage permit");
                let replay = fixture
                    .launch_fixture
                    .ledger
                    .replay_current_final_verification_capture_acquisition_v36(&fixture.request)
                    .expect("committed retry is replayable without fresh authority");
                assert!(matches!(
                    replay,
                    CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay {
                        persisted: replayed
                    } if replayed == persisted
                ));
                let reopened = EventLedger::open_read_only(&fixture.launch_fixture.files.database)
                    .expect("restart opens committed retry read-only");
                assert_eq!(
                    reopened
                        .load_current_final_verification_capture_acquisition_v36(
                            &fixture.request.attempt_id,
                        )
                        .expect("restart reads exact committed retry without reminting a permit"),
                    persisted,
                );
                persisted
            }
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { .. } => {
                panic!("a definitely pre-commit fault cannot turn its first retry into replay")
            }
        }
    }

    #[test]
    fn v36_schema_is_additive_strict_closed_and_exact() {
        assert_eq!(MIGRATION_V36.matches("CREATE TABLE ").count(), 1);
        assert_eq!(MIGRATION_V36.matches("STRICT, WITHOUT ROWID").count(), 1);
        assert!(!MIGRATION_V36.contains("DROP TABLE"));
        assert!(!MIGRATION_V36.contains("ALTER TABLE"));
        assert!(MIGRATION_V36.contains("WHEN 'CaptureAcquired' THEN"));
        assert!(MIGRATION_V36.contains("ELSE 1"));
        assert!(MIGRATION_V36.contains("acquired_store_head_generation = 2"));
        assert!(MIGRATION_V36.contains("intent_bound_journal_generation = 1"));
        assert!(MIGRATION_V36.contains("acquired_bound_journal_generation = 2"));
        for identity in [
            "capture_intent_id",
            "capture_event_id",
            "capture_authority_digest",
            "acquired_anchor_digest",
            "sensitive_output_journal_id",
        ] {
            assert!(
                MIGRATION_V36.contains(&format!("existing.{identity} = NEW.{identity}")),
                "missing explicit no-replace guard for {identity}"
            );
        }

        let fixture = capture_fixture("schema");
        verify_exact_schema(&fixture.launch_fixture.ledger.connection)
            .expect("fresh current schema retains the exact v36 migration");
        let version: i64 = fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read schema version");
        assert_eq!(version, super::super::SCHEMA_VERSION);
    }

    #[test]
    fn fresh_commit_exact_replay_restart_and_same_instance_permit_are_separate() {
        let mut fixture = capture_fixture("fresh-replay");
        let (persisted, native_permit) = commit_fresh(&mut fixture);
        let authority = &persisted.capture_authority;
        assert_eq!(authority.acquired.store_head.generation, 2);
        assert_eq!(authority.intent_bound_journal_head.generation, 1);
        assert_eq!(authority.acquired_bound_journal_head.generation, 2);
        assert_eq!(
            persisted.capture_event.event_kind,
            CurrentFinalVerificationAuthorityEventKindV1::CaptureAcquired
        );
        assert_eq!(
            persisted.capture_event.event_id,
            fixture
                .launch
                .launch_authority
                .reservations
                .fields
                .capture_acquired_event_id
        );
        assert_eq!(
            persisted.capture_event.request_id,
            fixture
                .launch
                .launch_authority
                .reservations
                .fields
                .capture_intent_id
        );
        assert_eq!(
            persisted.capture_event.request_digest,
            fixture.launch.launch_authority.capture_intent.intent_digest
        );
        native_permit
            .consume_for_ledger_instance(fixture.launch_fixture.ledger.instance_id, &persisted)
            .expect("fresh next-stage permit binds the exact same ledger instance");

        let replay = fixture
            .launch_fixture
            .ledger
            .replay_current_final_verification_capture_acquisition_v36(&fixture.request)
            .expect("exact replay succeeds without authority inputs");
        assert!(matches!(
            replay,
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { persisted: replay }
                if replay == persisted
        ));
        let read_only = EventLedger::open_read_only(&fixture.launch_fixture.files.database)
            .expect("reopen exact v36 database read-only");
        assert_eq!(
            read_only
                .load_current_final_verification_capture_acquisition_v36(
                    &fixture.request.attempt_id,
                )
                .expect("restart readback succeeds without permit"),
            persisted
        );
        let counts: (i64, i64, i64) = fixture
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34),
                    (SELECT COUNT(*) FROM command_output_capture_acquisitions)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read exact lifecycle counts");
        assert_eq!(counts, (1, 3, 0), "v36 never promotes a v27 acquisition");
    }

    #[test]
    fn request_rejects_crossed_store_shapes_journal_substitution_and_unknown_fields() {
        let fixture = capture_fixture("negative-shapes");

        let crossed_directory =
            acquired_for(&fixture.launch, "crossed-directory", 51, 201, 201, 202);
        let crossed = request_for_acquired(&fixture.launch, crossed_directory);
        assert!(crossed.validate_intrinsic().is_err());

        let mut wrong_generation = fixture.request.clone();
        wrong_generation.acquired.store_head.generation = 3;
        assert!(wrong_generation.validate_intrinsic().is_err());

        let mut crossed_journal = fixture.request.clone();
        crossed_journal.sensitive_output_journal_id = format!(
            "{SENSITIVE_OUTPUT_JOURNAL_ID_PREFIX_V2}{}",
            digest("different-capture")
        );
        assert!(crossed_journal.validate_intrinsic().is_err());

        let mut crossed_head = fixture.request.clone();
        crossed_head.acquired_bound_journal_head.record_digest = digest("substituted-head");
        assert!(crossed_head.validate_intrinsic().is_err());

        let mut value = serde_json::to_value(&fixture.request).expect("request to value");
        value.as_object_mut().expect("request object").insert(
            "caller_claimed_store_auth".into(),
            serde_json::Value::Bool(true),
        );
        let unknown = serde_json::to_vec(&value).expect("encode unknown-field request");
        assert!(sqlite_capture_request_canonical(&unknown).is_err());

        assert!(matches!(
            fixture
                .launch_fixture
                .ledger
                .replay_current_final_verification_capture_acquisition_v36(&fixture.request),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
    }

    #[test]
    fn crossed_sealed_origin_and_crossed_v35_permit_create_no_v36_rows() {
        let mut first = capture_fixture("crossed-first");
        let second = capture_fixture("crossed-second");
        let crossed_origin = AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1::from_test(
            second.request.clone(),
        )
        .expect("seal crossed test origin");
        let crossed_custody = FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1::new(
            first.launch_permit.take().expect("first launch permit"),
            crossed_origin,
        );
        assert!(
            first
                .launch_fixture
                .ledger
                .commit_current_final_verification_capture_acquisition_v36(
                    &first.request,
                    crossed_custody,
                )
                .is_err()
        );
        let first_count: i64 = first
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                [],
                |row| row.get(0),
            )
            .expect("count first v36 rows");
        assert_eq!(first_count, 0);

        let mut third = capture_fixture("crossed-third");
        let mut fourth = capture_fixture("crossed-fourth");
        let origin = AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1::from_test(
            fourth.request.clone(),
        )
        .expect("seal fourth origin");
        let crossed_custody = FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1::new(
            third.launch_permit.take().expect("crossed third permit"),
            origin,
        );
        assert!(
            fourth
                .launch_fixture
                .ledger
                .commit_current_final_verification_capture_acquisition_v36(
                    &fourth.request,
                    crossed_custody,
                )
                .is_err()
        );
        let fourth_count: i64 = fourth
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                [],
                |row| row.get(0),
            )
            .expect("count fourth v36 rows");
        assert_eq!(fourth_count, 0);
    }

    #[test]
    fn alternate_current_identity_collision_is_rejected_before_any_second_row() {
        let mut fixture = capture_fixture("alternate-collision");
        let duplicate_permit = fixture
            .launch_permit
            .as_ref()
            .expect("fresh permit")
            .duplicate_for_test();
        let _ = commit_fresh(&mut fixture);

        let alternate = request_for_acquired(
            &fixture.launch,
            acquired_for(
                &fixture.launch,
                "alternate-collision-second",
                52,
                310,
                311,
                312,
            ),
        );
        let custody = custody_for(duplicate_permit, &alternate);
        assert!(matches!(
            fixture
                .launch_fixture
                .ledger
                .commit_current_final_verification_capture_acquisition_v36(
                    &alternate,
                    custody,
                ),
            Err(CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::DefinitelyPreCommit {
                error,
                ..
            }) if matches!(error.as_ref(), LedgerError::ReferenceMismatch { .. })
        ));
        let counts: (i64, i64) = fixture
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read collision counts");
        assert_eq!(counts, (1, 3));
    }

    #[test]
    fn transaction_cuts_never_leave_a_partial_capture_or_event() {
        let mut fixture = capture_fixture("transaction-cuts");
        let event = capture_event(&fixture.launch, &fixture.request).expect("derive event");
        let authority = CurrentFinalVerificationCaptureAcquisitionAuthorityV1::new(
            &fixture.launch,
            &fixture.request,
            &event,
        )
        .expect("derive authority");
        for cut_after_event in [false, true] {
            {
                let transaction = fixture
                    .launch_fixture
                    .ledger
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .expect("begin cut transaction");
                transaction
                    .pragma_update(None, "defer_foreign_keys", true)
                    .expect("defer event FK");
                let guard = CaptureWriteGuardV1 {
                    attempt_id: authority.attempt_id.clone(),
                    event_digest: event.event_digest.clone(),
                    capture_authority_digest: authority.capture_authority_digest.clone(),
                };
                with_capture_write_guard(guard, || {
                    insert_capture_v36(&transaction, &fixture.request, &authority)?;
                    if cut_after_event {
                        insert_capture_event_v36(&transaction, &event)?;
                    }
                    Ok(())
                })
                .expect("write exact cut prefix");
            }
            let counts: (i64, i64) = fixture
                .launch_fixture
                .ledger
                .connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                        (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("read post-cut counts");
            assert_eq!(counts, (0, 2));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "four distinct real SQLite/guard cut points prove exact move-only custody recovery and retry"
    )]
    fn definite_precommit_failures_return_reusable_exact_custody() {
        let mut busy = capture_fixture("retry-busy");
        busy.launch_fixture
            .ledger
            .connection
            .busy_timeout(Duration::ZERO)
            .expect("disable busy waiting for deterministic cut");
        let blocker = Connection::open(&busy.launch_fixture.files.database)
            .expect("open independent writer blocker");
        blocker
            .busy_timeout(Duration::ZERO)
            .expect("disable blocker busy waiting");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold the exact writer lock before v36 transaction begin");
        let custody = custody_for(
            busy.launch_permit.take().expect("busy fixture permit"),
            &busy.request,
        );
        let Err(failure) = busy
            .launch_fixture
            .ledger
            .commit_current_final_verification_capture_acquisition_v36(&busy.request, custody)
        else {
            panic!("writer lock must be a definite pre-commit failure");
        };
        assert!(matches!(
            failure,
            CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::DefinitelyPreCommit { .. }
        ));
        blocker
            .execute_batch("ROLLBACK")
            .expect("release independent writer blocker");
        drop(blocker);
        let _ = retry_precommit_custody_to_fresh(&mut busy, failure);

        let mut after_row = capture_fixture("retry-after-row");
        after_row
            .launch_fixture
            .ledger
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER inject_v36_failure_after_capture_row
                 BEFORE INSERT ON current_final_verification_events_v34
                 WHEN NEW.event_kind = 'CaptureAcquired'
                 BEGIN SELECT RAISE(ABORT, 'inject after capture row'); END;",
            )
            .expect("install post-row event fault");
        let custody = custody_for(
            after_row.launch_permit.take().expect("post-row permit"),
            &after_row.request,
        );
        let Err(failure) = after_row
            .launch_fixture
            .ledger
            .commit_current_final_verification_capture_acquisition_v36(&after_row.request, custody)
        else {
            panic!("event fault must roll back the preceding capture row");
        };
        let counts: (i64, i64) = after_row
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read rolled-back post-row state");
        assert_eq!(counts, (0, 2));
        after_row
            .launch_fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER inject_v36_failure_after_capture_row")
            .expect("remove post-row event fault");
        let _ = retry_precommit_custody_to_fresh(&mut after_row, failure);

        let mut after_event = capture_fixture("retry-after-event");
        after_event
            .launch_fixture
            .ledger
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER inject_v36_failure_after_capture_event
                 AFTER INSERT ON current_final_verification_events_v34
                 WHEN NEW.event_kind = 'CaptureAcquired'
                 BEGIN SELECT RAISE(ABORT, 'inject after capture event'); END;",
            )
            .expect("install post-event fault");
        let custody = custody_for(
            after_event.launch_permit.take().expect("post-event permit"),
            &after_event.request,
        );
        let Err(failure) = after_event
            .launch_fixture
            .ledger
            .commit_current_final_verification_capture_acquisition_v36(
                &after_event.request,
                custody,
            )
        else {
            panic!("post-event trigger must roll back the whole transaction");
        };
        let counts: (i64, i64) = after_event
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read rolled-back post-event state");
        assert_eq!(counts, (0, 2));
        after_event
            .launch_fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER inject_v36_failure_after_capture_event")
            .expect("remove post-event fault");
        let _ = retry_precommit_custody_to_fresh(&mut after_event, failure);

        let mut occupied_guard = capture_fixture("retry-occupied-guard");
        let custody = custody_for(
            occupied_guard
                .launch_permit
                .take()
                .expect("occupied-guard permit"),
            &occupied_guard.request,
        );
        let outer_guard = CaptureWriteGuardV1 {
            attempt_id: "unrelated-occupied-attempt".into(),
            event_digest: digest("unrelated-occupied-event"),
            capture_authority_digest: digest("unrelated-occupied-authority"),
        };
        let nested = with_capture_write_guard(outer_guard, || {
            Ok::<_, LedgerError>(
                occupied_guard
                    .launch_fixture
                    .ledger
                    .commit_current_final_verification_capture_acquisition_v36(
                        &occupied_guard.request,
                        custody,
                    ),
            )
        })
        .expect("outer test guard itself succeeds");
        let Err(failure) = nested else {
            panic!("occupied private guard must reject nested fresh admission");
        };
        let _ = retry_precommit_custody_to_fresh(&mut occupied_guard, failure);
    }

    #[test]
    fn preledger_crash_has_no_restart_fresh_or_replay_route() {
        let mut fixture = capture_fixture("preledger-crash");
        let custody = custody_for(
            fixture
                .launch_permit
                .take()
                .expect("physical acquisition still has ephemeral v35 permit"),
            &fixture.request,
        );
        drop(custody);
        drop(fixture.launch_fixture.ledger);

        let restarted = EventLedger::open(&fixture.launch_fixture.files.database)
            .expect("restart exact database after pre-ledger crash");
        assert!(matches!(
            restarted.load_current_final_verification_capture_acquisition_v36(
                &fixture.request.attempt_id
            ),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            restarted.replay_current_final_verification_capture_acquisition_v36(&fixture.request),
            Err(LedgerError::ArtifactNotFound { .. })
        ));
        let counts: (i64, i64) = restarted
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read exact pre-ledger crash state");
        assert_eq!(counts, (0, 2));
    }

    #[test]
    fn move_only_authority_debug_is_redacted() {
        let mut fixture = capture_fixture("debug-redaction");
        let duplicated_permit = fixture
            .launch_permit
            .as_ref()
            .expect("debug fixture permit")
            .duplicate_for_test();
        let store_origin = AuthenticatedCurrentFinalVerificationCaptureStoreOriginV1::from_test(
            fixture.request.clone(),
        )
        .expect("debug fixture store origin");
        let custody = FreshCurrentFinalVerificationCaptureAcquisitionRetryCustodyV1::new(
            duplicated_permit,
            store_origin,
        );
        let custody_debug = format!("{custody:?}");
        let error_debug = format!(
            "{:?}",
            CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::precommit(
                mismatch("redaction test", "fixed non-bound detail"),
                custody,
            )
        );
        let uncertain_debug = format!(
            "{:?}",
            CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::postcommit(
                LedgerError::PostCommitStateUncertain {
                    operation: "debug redaction",
                    recovery_id: fixture.request.attempt_id.clone(),
                    detail: fixture.request.acquired.capture_id.clone(),
                },
            )
        );
        let permit_debug = format!(
            "{:?}",
            fixture
                .launch_permit
                .as_ref()
                .expect("original debug fixture permit")
        );
        let (_persisted, native_permit) = commit_fresh(&mut fixture);
        let native_debug = format!("{native_permit:?}");
        for rendered in [
            custody_debug,
            error_debug,
            uncertain_debug,
            permit_debug,
            native_debug,
        ] {
            for forbidden in [
                fixture.request.attempt_id.as_str(),
                fixture.request.launch_authority_digest.as_str(),
                fixture.request.acquired.capture_id.as_str(),
                fixture.request.acquired.intent_digest.as_str(),
                fixture.request.acquired.acquired_anchor_digest.as_str(),
                fixture.request.acquired.store_head.record_digest.as_str(),
                fixture.request.sensitive_output_journal_id.as_str(),
                fixture
                    .request
                    .intent_bound_journal_head
                    .record_digest
                    .as_str(),
                fixture
                    .request
                    .acquired_bound_journal_head
                    .record_digest
                    .as_str(),
                fixture
                    .launch
                    .launch_authority
                    .launch_preparation
                    .private_state_id
                    .as_str(),
                fixture
                    .launch
                    .launch_authority
                    .launch_preparation
                    .private_state_digest
                    .as_str(),
                fixture
                    .launch
                    .launch_authority
                    .workspace_grant
                    .canonical_root
                    .to_string_lossy()
                    .as_ref(),
                "cargo",
                "--workspace",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "move-only Debug leaked bound field {forbidden:?}: {rendered}",
                );
            }
        }
    }

    #[test]
    fn direct_sql_mutation_and_or_replace_are_closed_even_without_recursive_triggers() {
        let mut fixture = capture_fixture("direct-sql");
        let (persisted, _) = commit_fresh(&mut fixture);
        let connection = &fixture.launch_fixture.ledger.connection;
        assert!(
            connection
                .execute(
                    "UPDATE current_final_verification_capture_acquisitions_v36
                 SET acquired_at_unix_ms = acquired_at_unix_ms + 1",
                    [],
                )
                .is_err()
        );
        assert!(
            connection
                .execute(
                    "DELETE FROM current_final_verification_capture_acquisitions_v36",
                    [],
                )
                .is_err()
        );
        connection
            .pragma_update(None, "recursive_triggers", false)
            .expect("disable recursive triggers for explicit no-replace proof");
        let guard = CaptureWriteGuardV1 {
            attempt_id: persisted.capture_authority.attempt_id.clone(),
            event_digest: persisted.capture_event.event_digest.clone(),
            capture_authority_digest: persisted.capture_authority.capture_authority_digest.clone(),
        };
        let replace = with_capture_write_guard(guard, || {
            connection
                .execute(
                    "INSERT OR REPLACE INTO current_final_verification_capture_acquisitions_v36
                     SELECT * FROM current_final_verification_capture_acquisitions_v36",
                    [],
                )
                .map(|_| ())
                .map_err(LedgerError::from)
        });
        assert!(replace.is_err());
        connection
            .pragma_update(None, "recursive_triggers", true)
            .expect("restore recursive triggers");
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                [],
                |row| row.get(0),
            )
            .expect("count immutable row");
        assert_eq!(count, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the primary plus twelve alternate immutable capture identities are intentionally isolated one at a time"
    )]
    fn insert_or_replace_cannot_cross_any_capture_identity() {
        let mut fixture = capture_fixture("replace-identity-matrix");
        let (persisted, _) = commit_fresh(&mut fixture);
        let baseline = capture_insert_values(&fixture.request, &persisted.capture_authority);
        let collision_columns = [
            "attempt_id",
            "launch_authority_digest",
            "acquisition_request_digest",
            "capture_intent_id",
            "capture_id",
            "capture_intent_digest",
            "acquired_anchor_digest",
            "acquired_store_head_digest",
            "sensitive_output_journal_id",
            "intent_bound_journal_digest",
            "acquired_bound_journal_digest",
            "capture_event_id",
            "capture_authority_digest",
        ];
        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "recursive_triggers", false)
            .expect("disable recursive triggers for explicit v36 no-replace proof");
        for target in collision_columns {
            let mut crossed = baseline.clone();
            for column in collision_columns {
                let position = CAPTURE_INSERT_COLUMNS_V36
                    .iter()
                    .position(|candidate| candidate == &column)
                    .expect("collision column exists");
                crossed[position] = if column == "sensitive_output_journal_id" {
                    Value::Text(format!(
                        "{SENSITIVE_OUTPUT_JOURNAL_ID_PREFIX_V2}{}",
                        digest(&format!("replacement-{target}-{column}"))
                    ))
                } else {
                    Value::Text(digest(&format!("replacement-{target}-{column}")).to_string())
                };
            }
            let target_position = CAPTURE_INSERT_COLUMNS_V36
                .iter()
                .position(|candidate| candidate == &target)
                .expect("target collision column exists");
            crossed[target_position] = baseline[target_position].clone();
            let attempt_id = match &crossed[0] {
                Value::Text(value) => value.clone(),
                _ => panic!("attempt identity remains text"),
            };
            let capture_authority_digest = match &crossed[23] {
                Value::Text(value) => {
                    Digest::parse(value).expect("authority digest remains shaped")
                }
                _ => panic!("authority digest remains text"),
            };
            let guard = CaptureWriteGuardV1 {
                attempt_id,
                event_digest: digest(&format!("replacement-event-{target}")),
                capture_authority_digest,
            };
            let error = with_capture_write_guard(guard, || {
                execute_capture_insert_values(
                    &fixture.launch_fixture.ledger.connection,
                    &crossed,
                    true,
                )?;
                Ok(())
            })
            .expect_err("isolated replacement collision must fail");
            assert!(
                error
                    .to_string()
                    .contains("current final-verification capture identity already exists"),
                "{target} was not rejected by the explicit v36 no-replace trigger: {error}",
            );
            assert_eq!(
                fixture
                    .launch_fixture
                    .ledger
                    .load_current_final_verification_capture_acquisition_v36(
                        &fixture.request.attempt_id,
                    )
                    .expect("load unchanged capture after isolated replacement collision"),
                persisted,
                "{target}",
            );
        }
        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "recursive_triggers", true)
            .expect("restore recursive triggers after v36 no-replace matrix");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all 25 stored values and every nested scalar in each of three canonical blobs are independently crossed"
    )]
    fn every_capture_projection_and_nested_canonical_scalar_is_guarded() {
        let mut fixture = capture_fixture("capture-projection-matrix");
        let (event, authority) = derived_capture(&fixture);
        let baseline = capture_insert_values(&fixture.request, &authority);
        let transaction = fixture
            .launch_fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin capture projection matrix");
        transaction
            .pragma_update(None, "defer_foreign_keys", true)
            .expect("defer capture-event parent during projection matrix");
        with_capture_write_guard(capture_guard(&authority, &event), || {
            for (position, column) in CAPTURE_INSERT_COLUMNS_V36.iter().enumerate() {
                let mut crossed = baseline.clone();
                crossed[position] = mutate_sqlite_value(column, &baseline[position]);
                assert!(
                    execute_capture_insert_values(&transaction, &crossed, false).is_err(),
                    "runtime insert accepted crossed stored value {column}",
                );
                let count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(count, 0, "failed {column} insert left a capture row");
            }

            for (position, label) in [
                (5_usize, "acquisition_request_json"),
                (10_usize, "acquired_json"),
                (24_usize, "capture_authority_json"),
            ] {
                let Value::Blob(canonical) = &baseline[position] else {
                    panic!("{label} remains a blob");
                };
                let mutations = json_scalar_mutations(canonical);
                assert!(
                    !mutations.is_empty(),
                    "{label} contains nested scalar leaves"
                );
                for (scalar_index, mutation) in mutations.into_iter().enumerate() {
                    let mut crossed = baseline.clone();
                    crossed[position] = Value::Blob(mutation);
                    assert!(
                        execute_capture_insert_values(&transaction, &crossed, false).is_err(),
                        "runtime insert accepted {label} scalar mutation {scalar_index}",
                    );
                    let count: i64 = transaction.query_row(
                        "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                        [],
                        |row| row.get(0),
                    )?;
                    assert_eq!(
                        count, 0,
                        "failed {label} scalar mutation {scalar_index} left a row",
                    );
                }
            }

            assert_eq!(
                execute_capture_insert_values(&transaction, &baseline, false)?,
                1,
                "the exact unmodified capture control passes the same private guard",
            );
            Ok(())
        })
        .expect("run capture projection matrix");
        transaction
            .rollback()
            .expect("roll back capture projection control without event parent");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all 11 event storage values and every nested event scalar are independently crossed"
    )]
    fn every_capture_event_projection_and_nested_scalar_is_guarded() {
        let mut fixture = capture_fixture("capture-event-projection-matrix");
        let (event, authority) = derived_capture(&fixture);
        let capture_values = capture_insert_values(&fixture.request, &authority);
        let event_baseline = event_insert_values(&event);
        let transaction = fixture
            .launch_fixture
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin capture-event projection matrix");
        transaction
            .pragma_update(None, "defer_foreign_keys", true)
            .expect("defer event parent during event projection matrix");
        with_capture_write_guard(capture_guard(&authority, &event), || {
            execute_capture_insert_values(&transaction, &capture_values, false)?;
            for (position, column) in EVENT_INSERT_COLUMNS_V36.iter().enumerate() {
                let mut crossed = event_baseline.clone();
                crossed[position] = if *column == "event_kind" {
                    Value::Text("CommandDispatched".into())
                } else {
                    mutate_sqlite_value(column, &event_baseline[position])
                };
                assert!(
                    execute_event_insert_values(&transaction, &crossed).is_err(),
                    "runtime insert accepted crossed capture-event value {column}",
                );
                let capture_event_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM current_final_verification_events_v34
                     WHERE event_kind = 'CaptureAcquired'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(
                    capture_event_count, 0,
                    "failed {column} event insert persisted"
                );
            }

            let Value::Blob(event_json) = &event_baseline[10] else {
                panic!("event_json remains a blob");
            };
            let mutations = json_scalar_mutations(event_json);
            assert!(!mutations.is_empty(), "event_json contains scalar leaves");
            for (scalar_index, mutation) in mutations.into_iter().enumerate() {
                let mut crossed = event_baseline.clone();
                crossed[10] = Value::Blob(mutation);
                assert!(
                    execute_event_insert_values(&transaction, &crossed).is_err(),
                    "runtime insert accepted event_json scalar mutation {scalar_index}",
                );
                let capture_event_count: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM current_final_verification_events_v34
                     WHERE event_kind = 'CaptureAcquired'",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(capture_event_count, 0, "failed event scalar persisted");
            }
            assert_eq!(
                execute_event_insert_values(&transaction, &event_baseline)?,
                1,
                "the exact unmodified capture-event control passes the same private guard",
            );
            Ok(())
        })
        .expect("run capture-event projection matrix");
        transaction
            .rollback()
            .expect("roll back capture/event projection control");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact CaptureAcquired writer and every one of the fourteen later closed event kinds are enumerated"
    )]
    fn direct_capture_event_without_capture_row_and_every_later_event_are_closed() {
        let mut fixture = capture_fixture("closed-event-frontier");
        let (capture_event, capture_authority) = derived_capture(&fixture);
        let direct =
            with_capture_write_guard(capture_guard(&capture_authority, &capture_event), || {
                execute_event_insert_values(
                    &fixture.launch_fixture.ledger.connection,
                    &event_insert_values(&capture_event),
                )?;
                Ok(())
            });
        assert!(
            direct.is_err(),
            "CaptureAcquired cannot precede its exact v36 row"
        );
        let _ = commit_fresh(&mut fixture);

        let reservations = &fixture.launch.launch_authority.reservations.fields;
        let later = [
            (
                CurrentFinalVerificationAuthorityEventKindV1::V13Initialized,
                reservations.v13_initialized_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::CommandDispatched,
                reservations.command_dispatched_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::ControlIssued,
                reservations.control_issued_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::ControlObserved,
                reservations.control_observed_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::ControlReconciled,
                reservations.control_reconciled_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::TerminalObserved,
                reservations.terminal_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::EffectCutObserved,
                reservations.effect_cut_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::OutputCustodyClosed,
                reservations.output_custody_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::CommandDomainCleanupObserved,
                reservations.command_cleanup_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::RunnerDirectChildObserved,
                reservations.runner_direct_child_observed_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::RunnerDomainObserved,
                reservations.runner_domain_observed_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::RunnerCleanupClosed,
                reservations.runner_cleanup_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::EvidenceClosed,
                reservations.evidence_closure_event_id.as_str(),
            ),
            (
                CurrentFinalVerificationAuthorityEventKindV1::OutcomeDerived,
                reservations.outcome_derived_event_id.as_str(),
            ),
        ];
        for (index, (event_kind, event_id)) in later.into_iter().enumerate() {
            let mut event = CurrentFinalVerificationAuthorityEventV1 {
                event_version: 1,
                event_id: event_id.to_owned(),
                sprint_id: fixture.launch.launch_authority.sprint_id.clone(),
                event_sequence: capture_event.event_sequence + 1,
                event_kind,
                attempt_id: fixture.launch.launch_authority.attempt_id.clone(),
                request_id: format!("closed-later-request-{index}"),
                request_digest: digest(&format!("closed-later-request-{index}")),
                occurred_at_unix_ms: fixture.request.acquired.acquired_at_unix_ms + 1,
                event_digest: Digest::sha256(&[]),
            };
            event.event_digest = event
                .computed_event_digest()
                .expect("derive exact later event digest");
            event
                .validate_integrity()
                .expect("later event is internally canonical before writer rejection");
            let error = execute_event_insert_values(
                &fixture.launch_fixture.ledger.connection,
                &event_insert_values(&event),
            )
            .expect_err("schema v36 keeps every post-capture writer closed");
            assert!(
                error
                    .to_string()
                    .contains("event kind lacks exact current writer authority"),
                "{event_kind:?} did not fail at the closed writer frontier: {error}",
            );
        }
        let event_count: i64 = fixture
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_events_v34",
                [],
                |row| row.get(0),
            )
            .expect("count unchanged event frontier");
        assert_eq!(event_count, 3);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "readback is fault-injected one stored capture and event value at a time, including every canonical blob"
    )]
    fn persisted_readback_rejects_every_capture_and_event_storage_tamper() {
        let mut fixture = capture_fixture("persisted-readback-tamper");
        let (persisted, _) = commit_fresh(&mut fixture);
        let baseline_capture =
            capture_insert_values(&fixture.request, &persisted.capture_authority);
        let baseline_event = event_insert_values(&persisted.capture_event);
        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "foreign_keys", false)
            .expect("open test-only FK tamper seam");
        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "ignore_check_constraints", true)
            .expect("open test-only CHECK tamper seam");

        for (position, column) in CAPTURE_INSERT_COLUMNS_V36.iter().enumerate() {
            let transaction = fixture
                .launch_fixture
                .ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin capture readback-tamper transaction");
            transaction
                .execute_batch(
                    "DROP TRIGGER current_final_verification_capture_acquisitions_v36_no_update;",
                )
                .expect("open immutable capture row for transactional tamper");
            let sql = format!(
                "UPDATE current_final_verification_capture_acquisitions_v36
                 SET {column} = ?1 WHERE attempt_id = ?2",
            );
            transaction
                .execute(
                    &sql,
                    params![
                        mutate_sqlite_value(column, &baseline_capture[position]),
                        fixture.request.attempt_id,
                    ],
                )
                .expect("inject one capture storage tamper");
            assert!(
                load_capture_v36_from(&transaction, &fixture.launch, &fixture.request.attempt_id,)
                    .is_err(),
                "readback accepted persisted capture tamper {column}",
            );
            transaction
                .rollback()
                .expect("roll back one capture storage tamper");
        }

        for (position, column) in EVENT_INSERT_COLUMNS_V36.iter().enumerate() {
            let transaction = fixture
                .launch_fixture
                .ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin event readback-tamper transaction");
            transaction
                .execute_batch("DROP TRIGGER current_final_verification_events_v34_no_update;")
                .expect("open immutable event row for transactional tamper");
            let sql = format!(
                "UPDATE current_final_verification_events_v34
                 SET {column} = ?1 WHERE event_id = ?2",
            );
            transaction
                .execute(
                    &sql,
                    params![
                        if *column == "event_kind" {
                            Value::Text("CommandDispatched".into())
                        } else {
                            mutate_sqlite_value(column, &baseline_event[position])
                        },
                        persisted.capture_event.event_id,
                    ],
                )
                .expect("inject one event storage tamper");
            assert!(
                load_capture_v36_from(&transaction, &fixture.launch, &fixture.request.attempt_id,)
                    .is_err(),
                "readback accepted persisted capture-event tamper {column}",
            );
            transaction
                .rollback()
                .expect("roll back one event storage tamper");
        }

        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "ignore_check_constraints", false)
            .expect("restore CHECK enforcement after tamper matrix");
        fixture
            .launch_fixture
            .ledger
            .connection
            .pragma_update(None, "foreign_keys", true)
            .expect("restore FK enforcement after tamper matrix");
        assert_eq!(
            fixture
                .launch_fixture
                .ledger
                .load_current_final_verification_capture_acquisition_v36(
                    &fixture.request.attempt_id,
                )
                .expect("exact readback survives every rolled-back tamper"),
            persisted,
        );
    }

    #[test]
    fn seeded_legacy_v27_capture_is_never_promoted_to_v36() {
        let counts = crate::ledger::tests::seeded_v27_and_v36_capture_counts_for_test(
            "v36-no-v27-promotion",
        );
        assert_eq!(counts, (1, 0));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "fresh, exact upgraded, and divergent migration sources are compared in one closed schema proof"
    )]
    fn v35_to_v36_schema_is_exact_and_divergent_v35_is_rejected_preflight() {
        let fresh_database = crate::ledger::tests::schema_template::exact_database_at(
            u8::try_from(MIGRATIONS.len()).expect("template version fits u8"),
            "v36-fresh-schema",
        );
        let fresh = Connection::open(&fresh_database.path).expect("open fresh schema database");
        register_schema_functions(&fresh).expect("register schema functions");

        let upgraded_database =
            crate::ledger::tests::schema_template::exact_database_at(35, "v36-upgrade-source");
        let mut upgraded =
            Connection::open(&upgraded_database.path).expect("open upgrade database");
        register_schema_functions(&upgraded).expect("register upgrade functions");
        let v35_table_sql = upgraded
            .prepare(
                "SELECT name, sql FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .expect("prepare v35 table schema")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query v35 table schema")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect v35 table schema");
        upgraded
            .pragma_update(None, "user_version", 35_i64)
            .expect("mark exact v35");
        run_migrations(&mut upgraded).expect("upgrade exact v35 to v36");
        assert_eq!(
            load_schema_objects(&upgraded).unwrap(),
            load_schema_objects(&fresh).unwrap()
        );
        // run_migrations lands on the current schema, not v36, so every table
        // introduced after the v35 snapshot must be excluded from this
        // unchanged-table comparison.
        let upgraded_old_table_sql = upgraded
            .prepare(
                "SELECT name, sql FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                   AND name NOT IN (
                       'current_final_verification_capture_acquisitions_v36',
                       'current_final_verification_native_preparation_attempts_v37',
                       'current_final_verification_native_preparation_outcomes_v37',
                       'current_final_verification_native_source_consumptions_v37',
                       'current_final_verification_native_cleanup_obligations_v37',
                       'contained_command_release_admissions',
                       'contained_command_release_outcomes'
                   )
                 ORDER BY name",
            )
            .expect("prepare upgraded old table schema")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query upgraded old table schema")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect upgraded old table schema");
        assert_eq!(upgraded_old_table_sql, v35_table_sql);

        let divergent_database =
            crate::ledger::tests::schema_template::exact_database_at(35, "v36-divergent-source");
        let mut divergent =
            Connection::open(&divergent_database.path).expect("open divergent database");
        register_schema_functions(&divergent).expect("register divergent functions");
        divergent
            .execute_batch(
                "DROP TRIGGER current_final_verification_launches_v35_no_update;
                 CREATE TRIGGER current_final_verification_launches_v35_no_update
                 BEFORE UPDATE ON current_final_verification_launches_v35
                 BEGIN SELECT RAISE(ABORT, 'divergent'); END;",
            )
            .expect("diverge exact v35 source");
        divergent
            .pragma_update(None, "user_version", 35_i64)
            .expect("mark divergent v35");
        assert!(matches!(
            run_migrations(&mut divergent),
            Err(LedgerError::Corrupt {
                entity: "ledger schema migration source",
                ..
            })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the populated migration proof snapshots every raw value, storage class, and byte in five authority tables"
    )]
    fn populated_v35_migrates_without_changing_any_existing_byte_or_storage_type() {
        let mut fixture = exact_v35_launch_fixture("populated-v35-to-v36");
        let (before_loaded, launch_permit) = launch_and_permit(&mut fixture);
        drop(launch_permit);
        let before_raw = populated_v35_raw_image(&fixture.ledger.connection);
        assert_eq!(before_raw[0].len(), 1, "one v32 attempt row is populated");
        assert_eq!(
            before_raw[1].len(),
            2,
            "admission and launch events are populated"
        );
        assert_eq!(
            before_raw[2].len(),
            1,
            "one v34 operational row is populated"
        );
        assert_eq!(before_raw[3].len(), 1, "one v35 launch row is populated");
        assert_eq!(
            before_raw[3][0].len(),
            33,
            "v35 launch has the exact column set"
        );
        assert_eq!(
            before_raw[4].len(),
            49,
            "all lifecycle reservations are populated"
        );
        assert!(
            before_raw[4].iter().all(|row| row.len() == 4),
            "each reservation has the exact four-column shape",
        );
        let database = fixture.files.database.clone();
        drop(fixture.ledger);

        let upgraded = EventLedger::open(&database).expect("migrate populated exact v35 to v36");
        let after_loaded = upgraded
            .load_current_final_verification_launch_v35(&before_loaded.launch_authority.attempt_id)
            .expect("load byte-preserved v35 launch through v36");
        assert_eq!(after_loaded, before_loaded);
        assert_eq!(populated_v35_raw_image(&upgraded.connection), before_raw);
        let no_capture_backfill: i64 = upgraded
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36",
                [],
                |row| row.get(0),
            )
            .expect("count no-backfill v36 rows");
        assert_eq!(no_capture_backfill, 0);
        verify_no_foreign_key_violations_v36(&upgraded.connection)
            .expect("populated upgrade foreign keys remain clean");
        verify_exact_schema(&upgraded.connection)
            .expect("populated upgraded schema equals fresh schema-v36 exactly");
    }

    #[cfg(unix)]
    #[test]
    fn postcommit_hardening_uncertainty_commits_exactly_once_and_never_returns_a_permit() {
        let mut fixture = capture_fixture("postcommit-uncertainty");
        let hardlink = fixture
            .launch_fixture
            .files
            .root
            .join("capture-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.launch_fixture.files.database, &hardlink)
            .expect("install post-commit hardening fault");
        let custody = custody_for(
            fixture.launch_permit.take().expect("fresh v35 permit"),
            &fixture.request,
        );
        assert!(matches!(
            fixture
                .launch_fixture
                .ledger
                .commit_current_final_verification_capture_acquisition_v36(
                    &fixture.request,
                    custody,
                ),
            Err(CurrentFinalVerificationCaptureAcquisitionCommitErrorV1::PostCommitStateUncertain {
                error,
            }) if matches!(error.as_ref(), LedgerError::PostCommitStateUncertain {
                    operation: "current final-verification capture acquisition commit",
                    recovery_id,
                    ..
                } if recovery_id == &fixture.request.attempt_id)
        ));
        fs::remove_file(&hardlink).expect("remove hardening fault");
        let committed = fixture
            .launch_fixture
            .ledger
            .load_current_final_verification_capture_acquisition_v36(&fixture.request.attempt_id)
            .expect("recover exact committed capture without a permit");
        let replay = fixture
            .launch_fixture
            .ledger
            .replay_current_final_verification_capture_acquisition_v36(&fixture.request)
            .expect("exact readback-only replay");
        assert!(matches!(
            replay,
            CurrentFinalVerificationCaptureAcquisitionCommitV1::Replay { persisted }
                if persisted == committed
        ));
        let counts: (i64, i64) = fixture
            .launch_fixture
            .ledger
            .connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM current_final_verification_capture_acquisitions_v36),
                    (SELECT COUNT(*) FROM current_final_verification_events_v34)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read post-uncertainty counts");
        assert_eq!(counts, (1, 3));
    }

    #[test]
    fn native_launch_permit_borrowed_validation_preserves_exact_move_only_custody() {
        let mut fixture = capture_fixture("borrowed-native-permit");
        let (persisted, permit) = commit_fresh(&mut fixture);
        permit
            .validate_for_ledger_instance(fixture.launch_fixture.ledger.instance_id, &persisted)
            .expect("borrowed validation accepts its exact same-ledger capture");

        let mut crossed_fixture = capture_fixture("borrowed-native-permit-crossed");
        let (crossed, crossed_permit) = commit_fresh(&mut crossed_fixture);
        drop(crossed_permit);
        assert!(matches!(
            permit
                .validate_for_ledger_instance(fixture.launch_fixture.ledger.instance_id, &crossed,),
            Err(LedgerError::ReferenceMismatch {
                entity: "fresh current final-verification native-launch permit",
                ..
            })
        ));

        permit
            .consume_for_ledger_instance(fixture.launch_fixture.ledger.instance_id, &persisted)
            .expect("failed and successful borrowed checks did not consume exact custody");
    }
}
