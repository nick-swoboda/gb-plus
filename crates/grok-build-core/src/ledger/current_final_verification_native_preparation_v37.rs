//! Additive schema-v37 current final-verifier native preparation.
//!
//! One fresh operation consumes the schema-v36 move-only permit, commits the
//! exact current preparation attempt together with its still-pending cleanup
//! obligation, hardens and reads that prefix back, then invokes one callback
//! while the same process- and connection-independent exclusion remains held.
//! An authenticated source is consumed at most once. A valid source and its
//! exact source-derived outcome commit atomically; a rejected source retains
//! metadata only. No path in this module initializes V13, releases a held
//! child, dispatches a command, advances the current event frontier, cleans a
//! native domain, composes an outcome, applies changes, or completes a sprint.

use std::fmt::{self, Debug, Formatter};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_native_origin::AuthenticatedNativePreparationSourceV1;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{ContractError, Digest, MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2};

use super::current_final_verification_capture_v36::{
    FreshCurrentFinalVerificationNativeLaunchPermitV1,
    PersistedCurrentFinalVerificationCaptureAcquisitionV1,
};
pub use super::current_final_verification_native_preparation_v37_contracts::{
    CurrentFinalVerificationNativeCleanupObligationV1,
    CurrentFinalVerificationNativePreparationAttemptV1,
    CurrentFinalVerificationNativePreparationOutcomeV1,
    CurrentFinalVerificationNativePreparationSourcePayloadV1,
    CurrentFinalVerificationNativeSourceConsumptionV1, NativePreparationDispositionV1,
    NativePreparationPlatformExpectationV1, NativeSourceRejectionReasonV1,
};
use super::current_final_verification_native_preparation_v37_contracts::{
    NATIVE_PREPARATION_OPERATION_DOMAIN_V1, NATIVE_PREPARATION_VERSION_V1,
    NativeCleanupObligationStateV1, NativeSourceConsumptionDispositionV1, disposition_name,
    native_evidence_digest, raw_identity_digest, rejection_reason_name, source_disposition_name,
    source_payload_digest_bytes, with_schema_write_admission, write_claim,
};
use super::{
    EventLedger, LaunchCleanupExclusion, LedgerError, LedgerStateFilesystemIdentities,
    launch_cleanup_lock_path, ledger_regular_file_identity, secure_database_files,
    verify_user_only_permissions,
};

pub(super) const MIGRATION_V37: &str =
    include_str!("current_final_verification_native_preparation_v37.sql");

const SOURCE_CONSUMPTION_ID_DOMAIN_V1: &[u8] =
    b"grok-build/current-final-verification-native-source-consumption-v1/id\0";

/// Durable coordinator action available from one schema-v37 readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentFinalVerificationNativePreparationReadinessV1 {
    /// The callback returned no proof, panicked, replayed a consumed source, or
    /// returned a source that was rejected. Only cleanup/reconciliation may
    /// continue.
    NotReady,
    /// The authenticated service refused before a native effect.
    RefusedBeforeNativeEffect,
    /// The authenticated service reported possible native state.
    NativeEffectUncertain,
    /// A held child was freshly prepared. A load or restart still classifies
    /// this as cleanup-only and never recreates release authority.
    HeldChildPrepared,
}

/// Complete exact readback of the current-only native-preparation prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCurrentFinalVerificationNativePreparationV1 {
    /// Exact schema-v36 parent and its complete v35/v34 prefix.
    pub capture: PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    /// Immutable one-attempt preparation identity.
    pub attempt: CurrentFinalVerificationNativePreparationAttemptV1,
    /// Still-pending cleanup obligation committed with the attempt.
    pub cleanup_obligation: CurrentFinalVerificationNativeCleanupObligationV1,
    /// The one authenticated source consumption, when a proof was returned.
    pub source_consumption: Option<CurrentFinalVerificationNativeSourceConsumptionV1>,
    /// Exact accepted canonical source; absent for no-proof and rejection.
    pub accepted_source: Option<CurrentFinalVerificationNativePreparationSourcePayloadV1>,
    /// Exact accepted-source-derived outcome; absent for no-proof/rejection.
    pub outcome: Option<CurrentFinalVerificationNativePreparationOutcomeV1>,
}

impl PersistedCurrentFinalVerificationNativePreparationV1 {
    /// Classifies durable state without granting callback, retry, release,
    /// initialization, dispatch, or cleanup authority.
    #[must_use]
    pub fn readiness(&self) -> CurrentFinalVerificationNativePreparationReadinessV1 {
        match self.outcome.as_ref().map(|outcome| outcome.disposition) {
            None => CurrentFinalVerificationNativePreparationReadinessV1::NotReady,
            Some(NativePreparationDispositionV1::HeldChildPrepared) => {
                CurrentFinalVerificationNativePreparationReadinessV1::HeldChildPrepared
            }
            Some(NativePreparationDispositionV1::RefusedBeforeNativeEffect) => {
                CurrentFinalVerificationNativePreparationReadinessV1::RefusedBeforeNativeEffect
            }
            Some(NativePreparationDispositionV1::NativeEffectUncertain) => {
                CurrentFinalVerificationNativePreparationReadinessV1::NativeEffectUncertain
            }
        }
    }
}

/// Move-only admission for one externally authenticated platform expectation.
///
/// The durable expectation remains a serializable comparison DTO. This
/// wrapper is deliberately non-cloneable and non-serializable, and has no
/// production constructor until the trusted native-service admission tranche
/// can mint it.
pub struct FreshNativePreparationPlatformAdmissionV1 {
    expectation: NativePreparationPlatformExpectationV1,
}

impl Debug for FreshNativePreparationPlatformAdmissionV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshNativePreparationPlatformAdmissionV1")
            .field("authority", &"<redacted move-only admission>")
            .finish()
    }
}

impl FreshNativePreparationPlatformAdmissionV1 {
    #[cfg(test)]
    fn from_test(expectation: NativePreparationPlatformExpectationV1) -> Self {
        Self { expectation }
    }

    fn validate(&self) -> Result<(), ContractError> {
        self.expectation.validate()
    }

    const fn expectation(&self) -> &NativePreparationPlatformExpectationV1 {
        &self.expectation
    }
}

/// Callback-scoped non-cloneable proof of the exact pending-obligation prefix.
///
/// It contains comparison state only. It is not a native child handle, V13
/// transport, release token, dispatch capability, or cleanup capability.
pub struct LiveCurrentFinalVerificationNativePreparationClaimV1<'a> {
    persisted: &'a PersistedCurrentFinalVerificationNativePreparationV1,
}

impl LiveCurrentFinalVerificationNativePreparationClaimV1<'_> {
    /// Exact durable schema-v36 capture parent.
    #[must_use]
    pub const fn capture(&self) -> &PersistedCurrentFinalVerificationCaptureAcquisitionV1 {
        &self.persisted.capture
    }

    /// Exact durable schema-v37 preparation attempt.
    #[must_use]
    pub const fn attempt(&self) -> &CurrentFinalVerificationNativePreparationAttemptV1 {
        &self.persisted.attempt
    }

    /// Exact still-pending cleanup obligation committed before this callback.
    #[must_use]
    pub const fn cleanup_obligation(&self) -> &CurrentFinalVerificationNativeCleanupObligationV1 {
        &self.persisted.cleanup_obligation
    }
}

/// Sole move-only authority for a future v38 held-child release stage.
///
/// It is created only from a freshly committed exact `HeldChildPrepared`
/// outcome. It cannot be loaded, replayed, cloned, or serialized.
pub struct FreshCurrentFinalVerificationV38PermitV1 {
    attempt_id: String,
    preparation_attempt_id: String,
    preparation_receipt_id: String,
    attempt_digest: Digest,
    capture_authority_digest: Digest,
    cleanup_effect_id: String,
    native_journal_id: String,
    launch_cleanup_lock_identity_digest: Digest,
    platform_expectation_digest: Digest,
    outcome_digest: Digest,
    ledger_instance_id: u64,
}

impl Debug for FreshCurrentFinalVerificationV38PermitV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshCurrentFinalVerificationV38PermitV1")
            .field("authority", &"<redacted move-only permit>")
            .finish()
    }
}

impl FreshCurrentFinalVerificationV38PermitV1 {
    /// Exact current final-verification attempt.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Exact reserved native-preparation receipt.
    #[must_use]
    pub fn preparation_receipt_id(&self) -> &str {
        &self.preparation_receipt_id
    }

    #[allow(
        dead_code,
        reason = "v38 will consume this exact held-outcome comparison authority"
    )]
    pub(super) fn validate_for_ledger_instance(
        &self,
        ledger_instance_id: u64,
        persisted: &PersistedCurrentFinalVerificationNativePreparationV1,
    ) -> Result<(), LedgerError> {
        let Some(outcome) = persisted.outcome.as_ref() else {
            return Err(reference_mismatch(
                "fresh current final-verification v38 permit",
                "held outcome is absent",
            ));
        };
        if self.ledger_instance_id != ledger_instance_id
            || self.attempt_id != persisted.attempt.attempt_id
            || self.preparation_attempt_id != persisted.attempt.preparation_attempt_id
            || self.preparation_receipt_id != persisted.attempt.preparation_receipt_id
            || self.attempt_digest != persisted.attempt.canonical_digest()?
            || self.capture_authority_digest
                != persisted.capture.capture_authority.capture_authority_digest
            || self.cleanup_effect_id != persisted.cleanup_obligation.cleanup_effect_id
            || self.native_journal_id != persisted.attempt.native_journal_id
            || self.launch_cleanup_lock_identity_digest
                != persisted.attempt.launch_cleanup_lock_identity_digest
            || self.platform_expectation_digest
                != persisted.attempt.platform_expectation.canonical_digest()?
            || outcome.disposition != NativePreparationDispositionV1::HeldChildPrepared
            || self.outcome_digest != outcome.canonical_digest()?
        {
            return Err(reference_mismatch(
                "fresh current final-verification v38 permit",
                "permit crosses its exact ledger, capture, preparation, or held outcome",
            ));
        }
        Ok(())
    }
}

/// Fresh execution result. Only this call can carry a future v38 permit.
pub struct CurrentFinalVerificationNativePreparationCommitV1 {
    /// Exact durable readback.
    pub persisted: PersistedCurrentFinalVerificationNativePreparationV1,
    /// Present only for this call's freshly committed held outcome.
    pub v38_permit: Option<FreshCurrentFinalVerificationV38PermitV1>,
}

/// Exact move-only custody returned only when no schema-v37 prefix could have
/// committed and the native callback was not invoked.
pub struct FreshCurrentFinalVerificationNativePreparationRetryCustodyV1 {
    native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
    platform_admission: FreshNativePreparationPlatformAdmissionV1,
}

impl Debug for FreshCurrentFinalVerificationNativePreparationRetryCustodyV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshCurrentFinalVerificationNativePreparationRetryCustodyV1")
            .field("authority", &"<redacted exact retry custody>")
            .finish()
    }
}

impl FreshCurrentFinalVerificationNativePreparationRetryCustodyV1 {
    /// Returns the exact original move-only inputs.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FreshCurrentFinalVerificationNativeLaunchPermitV1,
        FreshNativePreparationPlatformAdmissionV1,
    ) {
        (self.native_launch_permit, self.platform_admission)
    }
}

/// Typed failure of the schema-v37 fresh preparation seam.
pub enum CurrentFinalVerificationNativePreparationErrorV1 {
    /// No prefix commit occurred and callback invocation was impossible.
    DefinitelyBeforePrefix {
        /// Exact failure.
        error: Box<LedgerError>,
        /// Exact original move-only inputs.
        custody: Box<FreshCurrentFinalVerificationNativePreparationRetryCustodyV1>,
    },
    /// The prefix or later source/outcome state may be durable. No fresh
    /// authority is returned; recovery is readback/cleanup-only.
    PrefixStateUncertain {
        /// Exact recovery-only failure.
        error: Box<LedgerError>,
    },
}

impl Debug for CurrentFinalVerificationNativePreparationErrorV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefinitelyBeforePrefix { error, .. } => {
                let mut debug = formatter.debug_struct("DefinitelyBeforePrefix");
                #[cfg(test)]
                debug.field("error", error);
                #[cfg(not(test))]
                {
                    let _ = error;
                    debug.field("error", &"<redacted>");
                }
                debug.field("custody", &"<redacted>").finish()
            }
            Self::PrefixStateUncertain { error } => {
                let mut debug = formatter.debug_struct("PrefixStateUncertain");
                #[cfg(test)]
                debug.field("error", error);
                #[cfg(not(test))]
                {
                    let _ = error;
                    debug.field("error", &"<redacted>");
                }
                debug.finish()
            }
        }
    }
}

impl CurrentFinalVerificationNativePreparationErrorV1 {
    fn before_prefix(
        error: LedgerError,
        native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
        platform_admission: FreshNativePreparationPlatformAdmissionV1,
    ) -> Self {
        Self::DefinitelyBeforePrefix {
            error: Box::new(error),
            custody: Box::new(
                FreshCurrentFinalVerificationNativePreparationRetryCustodyV1 {
                    native_launch_permit,
                    platform_admission,
                },
            ),
        }
    }

    fn uncertain(error: LedgerError) -> Self {
        Self::PrefixStateUncertain {
            error: Box::new(error),
        }
    }
}

struct AuthenticatedNativePreparationSourceViewV1 {
    authenticated_source_identity_digest: Digest,
    source_session_identity_digest: Digest,
    operation_sequence: String,
    payload_digest: Digest,
    payload_length: u64,
    bounded_canonical_payload: Option<Vec<u8>>,
}

impl AuthenticatedNativePreparationSourceViewV1 {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the move-only authenticated source must be consumed exactly once"
    )]
    fn from_authenticated(source: AuthenticatedNativePreparationSourceV1) -> Self {
        let payload = source.canonical_payload();
        Self {
            authenticated_source_identity_digest: raw_identity_digest(
                source.authenticated_source_identity(),
            ),
            source_session_identity_digest: raw_identity_digest(source.session_identity()),
            operation_sequence: source.operation_sequence().to_string(),
            payload_digest: source_payload_digest_bytes(payload),
            payload_length: u64::try_from(payload.len())
                .expect("an in-memory source payload length always fits u64"),
            bounded_canonical_payload: (payload.len()
                <= MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2)
                .then(|| payload.to_vec()),
        }
    }
}

/// Registers every schema-v37 deterministic validator and private writer UDF.
pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    super::current_final_verification_native_preparation_v37_contracts::register_schema_functions(
        connection,
    )
}

pub(super) fn verify_no_foreign_key_violations_v37(
    connection: &Connection,
) -> Result<(), LedgerError> {
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if rows.next()?.is_some() {
        Err(corrupt(
            "current final-verification native preparation",
            "foreign-key check reported a violation before commit",
        ))
    } else {
        Ok(())
    }
}

impl EventLedger {
    /// Commits and invokes the only current native-preparation attempt.
    ///
    /// The callback is invoked exactly once only after the attempt and pending
    /// cleanup obligation commit together, database files are hardened, exact
    /// readback succeeds, and database/state-root/lock identities are
    /// revalidated. `None` is a closed no-proof result. A panic is caught and
    /// treated identically: the durable prefix remains cleanup-only.
    ///
    /// No production constructor currently exists for either the sealed
    /// platform admission or authenticated native source, so this
    /// crate-private seam remains deliberately dormant.
    ///
    /// # Errors
    ///
    /// Definite failures before the prefix commit return the exact move-only
    /// inputs. Commit/readback/identity failures after that point return no
    /// authority and require readback plus cleanup/reconciliation.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn with_current_final_verification_native_preparation_v37<F>(
        &mut self,
        native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
        platform_admission: FreshNativePreparationPlatformAdmissionV1,
        claimed_at_unix_ms: u64,
        prepare: F,
    ) -> Result<
        CurrentFinalVerificationNativePreparationCommitV1,
        CurrentFinalVerificationNativePreparationErrorV1,
    >
    where
        F: FnOnce(
            &LiveCurrentFinalVerificationNativePreparationClaimV1<'_>,
        ) -> Option<AuthenticatedNativePreparationSourceV1>,
    {
        self.with_current_final_verification_native_preparation_source_view_v37(
            native_launch_permit,
            platform_admission,
            claimed_at_unix_ms,
            |claim| {
                prepare(claim).map(AuthenticatedNativePreparationSourceViewV1::from_authenticated)
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    fn with_current_final_verification_native_preparation_source_view_v37<F>(
        &mut self,
        native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
        platform_admission: FreshNativePreparationPlatformAdmissionV1,
        claimed_at_unix_ms: u64,
        prepare: F,
    ) -> Result<
        CurrentFinalVerificationNativePreparationCommitV1,
        CurrentFinalVerificationNativePreparationErrorV1,
    >
    where
        F: FnOnce(
            &LiveCurrentFinalVerificationNativePreparationClaimV1<'_>,
        ) -> Option<AuthenticatedNativePreparationSourceViewV1>,
    {
        self.with_current_final_verification_native_preparation_source_view_after_prefix_v37(
            native_launch_permit,
            platform_admission,
            claimed_at_unix_ms,
            || {},
            prepare,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn with_current_final_verification_native_preparation_source_view_after_prefix_v37<F, H>(
        &mut self,
        native_launch_permit: FreshCurrentFinalVerificationNativeLaunchPermitV1,
        platform_admission: FreshNativePreparationPlatformAdmissionV1,
        claimed_at_unix_ms: u64,
        after_prefix: H,
        prepare: F,
    ) -> Result<
        CurrentFinalVerificationNativePreparationCommitV1,
        CurrentFinalVerificationNativePreparationErrorV1,
    >
    where
        F: FnOnce(
            &LiveCurrentFinalVerificationNativePreparationClaimV1<'_>,
        ) -> Option<AuthenticatedNativePreparationSourceViewV1>,
        H: FnOnce(),
    {
        let mut custody = Some((native_launch_permit, platform_admission));
        macro_rules! before_prefix {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        let (permit, admission) =
                            custody.take().expect("pre-prefix custody remains exact");
                        return Err(
                            CurrentFinalVerificationNativePreparationErrorV1::before_prefix(
                                error, permit, admission,
                            ),
                        );
                    }
                }
            };
        }

        before_prefix!(self.require_writable());
        before_prefix!(
            custody
                .as_ref()
                .expect("pre-prefix custody remains exact")
                .1
                .validate()
                .map_err(LedgerError::from)
        );
        let exclusion = before_prefix!(self.acquire_launch_cleanup_exclusion());
        let attempt_id = custody
            .as_ref()
            .expect("pre-prefix custody remains exact")
            .0
            .attempt_id()
            .to_owned();
        let capture = before_prefix!(
            self.load_current_final_verification_capture_acquisition_v36(&attempt_id,)
        );
        before_prefix!(
            custody
                .as_ref()
                .expect("pre-prefix custody remains exact")
                .0
                .validate_for_ledger_instance(self.instance_id, &capture)
        );
        before_prefix!(validate_platform_compatibility(
            custody
                .as_ref()
                .expect("pre-prefix custody remains exact")
                .1
                .expectation(),
            &capture,
        ));
        let filesystem_identities = before_prefix!(self.current_state_filesystem_identities());
        before_prefix!(self.revalidate_state_filesystem_identities(&filesystem_identities,));
        before_prefix!(exclusion.revalidate_retained_path_identity());
        let attempt = before_prefix!(derive_attempt(
            &capture,
            custody
                .as_ref()
                .expect("pre-prefix custody remains exact")
                .1
                .expectation(),
            &filesystem_identities,
            &exclusion,
            claimed_at_unix_ms,
        ));
        let cleanup = before_prefix!(derive_cleanup_obligation(&attempt));

        if before_prefix!(v37_prefix_exists(&self.connection, &attempt.attempt_id)) {
            drop(custody.take());
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                reference_mismatch(
                    "current final-verification native preparation",
                    "schema-v37 prefix already exists; fresh callback authority cannot replay",
                ),
            ));
        }

        let attempt_digest = before_prefix!(attempt.canonical_digest().map_err(LedgerError::from));
        let cleanup_digest = before_prefix!(cleanup.canonical_digest().map_err(LedgerError::from));
        let transaction = before_prefix!(
            self.connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(LedgerError::from)
        );
        before_prefix!(
            transaction
                .pragma_update(None, "defer_foreign_keys", true)
                .map_err(LedgerError::from)
        );
        let prefix_claims = vec![
            write_claim("attempt", &attempt.preparation_attempt_id, &attempt_digest),
            write_claim("cleanup", &cleanup.cleanup_effect_id, &cleanup_digest),
        ];
        before_prefix!(with_schema_write_admission(prefix_claims, || {
            insert_attempt_v37(&transaction, &attempt, &attempt_digest)?;
            insert_cleanup_v37(&transaction, &cleanup, &cleanup_digest)
        }));
        let expected_prefix = PersistedCurrentFinalVerificationNativePreparationV1 {
            capture: capture.clone(),
            attempt: attempt.clone(),
            cleanup_obligation: cleanup.clone(),
            source_consumption: None,
            accepted_source: None,
            outcome: None,
        };
        let transactional =
            before_prefix!(load_native_preparation_from(&transaction, capture.clone()));
        if transactional != expected_prefix {
            let (permit, admission) = custody.take().expect("prefix transaction still precommit");
            return Err(
                CurrentFinalVerificationNativePreparationErrorV1::before_prefix(
                    corrupt(
                        "current final-verification native preparation",
                        "transactional prefix readback differs from exact derived state",
                    ),
                    permit,
                    admission,
                ),
            );
        }
        before_prefix!(verify_no_foreign_key_violations_v37(&transaction));
        if let Err(error) = transaction.commit() {
            drop(custody.take());
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                LedgerError::PostCommitStateUncertain {
                    operation: "current final-verification native preparation prefix",
                    recovery_id: attempt.preparation_attempt_id.clone(),
                    detail: error.to_string(),
                },
            ));
        }

        let (permit, admission) = custody
            .take()
            .expect("committed prefix consumes exact fresh inputs");
        if let Err(error) = permit.consume_for_ledger_instance(self.instance_id, &capture) {
            drop(admission);
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                error,
            ));
        }
        drop(admission);
        after_prefix();

        let prefix = secure_database_files(&self.database_path)
            .and_then(|()| {
                self.load_current_final_verification_native_preparation_v37(&attempt.attempt_id)
            })
            .map_err(|error| {
                CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                    LedgerError::PostCommitStateUncertain {
                        operation: "current final-verification native preparation prefix",
                        recovery_id: attempt.preparation_attempt_id.clone(),
                        detail: error.to_string(),
                    },
                )
            })?;
        if prefix != expected_prefix {
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                corrupt(
                    "current final-verification native preparation",
                    "post-commit prefix readback differs from exact derived state",
                ),
            ));
        }
        let independent_prefix =
            independently_load_native_preparation_v37(&self.database_path, &attempt.attempt_id)
                .map_err(|error| {
                    CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                        LedgerError::PostCommitStateUncertain {
                            operation: "current final-verification native preparation prefix",
                            recovery_id: attempt.preparation_attempt_id.clone(),
                            detail: error.to_string(),
                        },
                    )
                })?;
        if independent_prefix != expected_prefix {
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                corrupt(
                    "current final-verification native preparation",
                    "independent path-reopened prefix differs from exact derived state",
                ),
            ));
        }

        self.revalidate_state_filesystem_identities(&filesystem_identities)
            .and_then(|()| exclusion.revalidate_retained_path_identity())
            .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)?;
        let live = LiveCurrentFinalVerificationNativePreparationClaimV1 { persisted: &prefix };
        let source = catch_unwind(AssertUnwindSafe(|| prepare(&live)))
            .ok()
            .flatten();
        self.revalidate_state_filesystem_identities(&filesystem_identities)
            .and_then(|()| exclusion.revalidate_retained_path_identity())
            .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)?;
        let callback_readback = independently_load_native_preparation_v37(
            &self.database_path,
            &prefix.attempt.attempt_id,
        )
        .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)?;
        if callback_readback != prefix {
            return Err(CurrentFinalVerificationNativePreparationErrorV1::uncertain(
                corrupt(
                    "current final-verification native preparation",
                    "post-callback path-reopened prefix differs from callback input",
                ),
            ));
        }
        self.revalidate_state_filesystem_identities(&filesystem_identities)
            .and_then(|()| exclusion.revalidate_retained_path_identity())
            .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)?;
        let Some(source) = source else {
            return Ok(CurrentFinalVerificationNativePreparationCommitV1 {
                persisted: prefix,
                v38_permit: None,
            });
        };
        let consumed_at_unix_ms = current_unix_ms_at_or_after(prefix.attempt.claimed_at_unix_ms)
            .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)?;

        self.consume_current_native_preparation_source_v37(
            prefix,
            source,
            consumed_at_unix_ms,
            &filesystem_identities,
            &exclusion,
        )
        .map_err(CurrentFinalVerificationNativePreparationErrorV1::uncertain)
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "owned prefix and source views make single-consumption explicit"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "the custody-preserving commit/readback sequence is intentionally linear"
    )]
    fn consume_current_native_preparation_source_v37(
        &mut self,
        prefix: PersistedCurrentFinalVerificationNativePreparationV1,
        source: AuthenticatedNativePreparationSourceViewV1,
        consumed_at_unix_ms: u64,
        filesystem_identities: &LedgerStateFilesystemIdentities,
        exclusion: &LaunchCleanupExclusion,
    ) -> Result<CurrentFinalVerificationNativePreparationCommitV1, LedgerError> {
        let source_consumption_id = source_consumption_id(&source);
        if source_tuple_exists(&self.connection, &source)? {
            let persisted = self.load_current_final_verification_native_preparation_v37(
                &prefix.attempt.attempt_id,
            )?;
            self.revalidate_state_filesystem_identities(filesystem_identities)?;
            exclusion.revalidate_retained_path_identity()?;
            let independent = independently_load_native_preparation_v37(
                &self.database_path,
                &prefix.attempt.attempt_id,
            )?;
            if independent != persisted {
                return Err(corrupt(
                    "current final-verification native source replay",
                    "independent path-reopened readback differs from replay state",
                ));
            }
            self.revalidate_state_filesystem_identities(filesystem_identities)?;
            exclusion.revalidate_retained_path_identity()?;
            return Ok(CurrentFinalVerificationNativePreparationCommitV1 {
                persisted,
                v38_permit: None,
            });
        }

        self.revalidate_state_filesystem_identities(filesystem_identities)?;
        exclusion.revalidate_retained_path_identity()?;
        let classification = classify_source(&prefix, &source, consumed_at_unix_ms);
        match classification {
            SourceClassificationV1::Rejected(reason) => {
                let consumption = rejected_consumption(
                    &prefix,
                    &source,
                    source_consumption_id,
                    reason,
                    consumed_at_unix_ms,
                )?;
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                persist_rejected_source(&mut self.connection, &prefix, &consumption)?;
                secure_database_files(&self.database_path)?;
                let persisted = self.load_current_final_verification_native_preparation_v37(
                    &prefix.attempt.attempt_id,
                )?;
                if persisted.source_consumption.as_ref() != Some(&consumption)
                    || persisted.accepted_source.is_some()
                    || persisted.outcome.is_some()
                {
                    return Err(corrupt(
                        "current final-verification native preparation rejection",
                        "post-commit readback differs from exact metadata-only rejection",
                    ));
                }
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                let independent = independently_load_native_preparation_v37(
                    &self.database_path,
                    &prefix.attempt.attempt_id,
                )?;
                if independent != persisted {
                    return Err(corrupt(
                        "current final-verification native preparation rejection",
                        "independent path-reopened readback differs from exact rejection",
                    ));
                }
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                Ok(CurrentFinalVerificationNativePreparationCommitV1 {
                    persisted,
                    v38_permit: None,
                })
            }
            SourceClassificationV1::Accepted(payload) => {
                let consumption = accepted_consumption(
                    &prefix,
                    &source,
                    &payload,
                    source_consumption_id,
                    consumed_at_unix_ms,
                )?;
                let outcome = outcome_from_source(&prefix, &consumption, &payload)?;
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                persist_accepted_source_and_outcome(
                    &mut self.connection,
                    &prefix,
                    &consumption,
                    &payload,
                    &outcome,
                )?;
                secure_database_files(&self.database_path)?;
                let persisted = self.load_current_final_verification_native_preparation_v37(
                    &prefix.attempt.attempt_id,
                )?;
                if persisted.source_consumption.as_ref() != Some(&consumption)
                    || persisted.accepted_source.as_ref() != Some(&payload)
                    || persisted.outcome.as_ref() != Some(&outcome)
                {
                    return Err(corrupt(
                        "current final-verification native preparation outcome",
                        "post-commit readback differs from exact accepted source and outcome",
                    ));
                }
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                let independent = independently_load_native_preparation_v37(
                    &self.database_path,
                    &prefix.attempt.attempt_id,
                )?;
                if independent != persisted {
                    return Err(corrupt(
                        "current final-verification native preparation outcome",
                        "independent path-reopened readback differs from exact accepted outcome",
                    ));
                }
                self.revalidate_state_filesystem_identities(filesystem_identities)?;
                exclusion.revalidate_retained_path_identity()?;
                let v38_permit = if outcome.disposition
                    == NativePreparationDispositionV1::HeldChildPrepared
                {
                    Some(FreshCurrentFinalVerificationV38PermitV1 {
                        attempt_id: persisted.attempt.attempt_id.clone(),
                        preparation_attempt_id: persisted.attempt.preparation_attempt_id.clone(),
                        preparation_receipt_id: persisted.attempt.preparation_receipt_id.clone(),
                        attempt_digest: persisted.attempt.canonical_digest()?,
                        capture_authority_digest: persisted
                            .capture
                            .capture_authority
                            .capture_authority_digest
                            .clone(),
                        cleanup_effect_id: persisted.cleanup_obligation.cleanup_effect_id.clone(),
                        native_journal_id: persisted.attempt.native_journal_id.clone(),
                        launch_cleanup_lock_identity_digest: persisted
                            .attempt
                            .launch_cleanup_lock_identity_digest
                            .clone(),
                        platform_expectation_digest: persisted
                            .attempt
                            .platform_expectation
                            .canonical_digest()?,
                        outcome_digest: outcome.canonical_digest()?,
                        ledger_instance_id: self.instance_id,
                    })
                } else {
                    None
                };
                Ok(CurrentFinalVerificationNativePreparationCommitV1 {
                    persisted,
                    v38_permit,
                })
            }
        }
    }

    /// Loads and fully revalidates one schema-v37 preparation state.
    ///
    /// This readback never invokes native code and never recreates either the
    /// v36 permit or future v38 permit.
    ///
    /// # Errors
    ///
    /// Returns an error when any durable parent, canonical projection,
    /// filesystem identity, companion-lock identity, or cross-record join is
    /// absent or no longer exact.
    pub fn load_current_final_verification_native_preparation_v37(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedCurrentFinalVerificationNativePreparationV1, LedgerError> {
        let capture = self.load_current_final_verification_capture_acquisition_v36(attempt_id)?;
        let persisted = load_native_preparation_from(&self.connection, capture)?;
        let current = self.current_state_filesystem_identities()?;
        if current.database.identity_digest() != persisted.attempt.ledger_database_identity_digest
            || current.state_root.identity_digest() != persisted.attempt.state_root_identity_digest
        {
            return Err(corrupt(
                "current final-verification native preparation filesystem identity",
                "current database or state-root identity differs from the committed attempt",
            ));
        }
        let lock_path = launch_cleanup_lock_path(&self.database_path);
        verify_user_only_permissions(&lock_path)?;
        let lock_metadata = std::fs::symlink_metadata(&lock_path)?;
        let lock_identity = ledger_regular_file_identity(&lock_path, &lock_metadata)?;
        if lock_identity.identity_digest() != persisted.attempt.launch_cleanup_lock_identity_digest
        {
            return Err(corrupt(
                "current final-verification native preparation lock identity",
                "current companion lock path differs from the committed attempt",
            ));
        }
        Ok(persisted)
    }

    /// Exact readback-only replay. It invokes no callback and returns no permit.
    ///
    /// # Errors
    ///
    /// Returns the same validation and persistence errors as the exact loader.
    pub fn replay_current_final_verification_native_preparation_v37(
        &self,
        attempt_id: &str,
    ) -> Result<PersistedCurrentFinalVerificationNativePreparationV1, LedgerError> {
        self.load_current_final_verification_native_preparation_v37(attempt_id)
    }
}

fn derive_attempt(
    capture: &PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    expectation: &NativePreparationPlatformExpectationV1,
    filesystem: &LedgerStateFilesystemIdentities,
    exclusion: &LaunchCleanupExclusion,
    claimed_at_unix_ms: u64,
) -> Result<CurrentFinalVerificationNativePreparationAttemptV1, LedgerError> {
    let launch = &capture.launch.launch_authority;
    let preparation = &launch.launch_preparation;
    let reserved = &launch.reservations.fields;
    let attempt = CurrentFinalVerificationNativePreparationAttemptV1 {
        preparation_version: NATIVE_PREPARATION_VERSION_V1,
        preparation_attempt_id: reserved.native_launch_preparation_attempt_id.clone(),
        sprint_id: launch.sprint_id.clone(),
        attempt_id: launch.attempt_id.clone(),
        launch_authority_digest: launch.launch_authority_digest.clone(),
        capture_authority_digest: capture.capture_authority.capture_authority_digest.clone(),
        acquired_anchor_digest: capture
            .capture_authority
            .acquired
            .acquired_anchor_digest
            .clone(),
        native_journal_id: reserved.native_launch_journal_id.clone(),
        cleanup_effect_id: reserved.native_launch_cleanup_effect_id.clone(),
        preparation_receipt_id: reserved.native_launch_preparation_receipt_id.clone(),
        platform_expectation: expectation.clone(),
        native_policy_digest: preparation.native_policy_digest.clone(),
        runner_binary_digest: preparation.runner_binary_digest.clone(),
        runner_binary_size_bytes: preparation.runner_binary_size_bytes,
        runner_protocol_version: preparation.runner_protocol_version,
        runner_protocol_digest: preparation.runner_protocol_digest.clone(),
        private_state_id: preparation.private_state_id.clone(),
        private_state_digest: preparation.private_state_digest.clone(),
        workspace_grant_hash: launch.workspace_grant.grant_hash.clone(),
        execution_policy_digest: launch.execution_policy.policy_hash.clone(),
        ledger_database_identity_digest: filesystem.database.identity_digest(),
        state_root_identity_digest: filesystem.state_root.identity_digest(),
        launch_cleanup_lock_identity_digest: exclusion.retained_identity().identity_digest(),
        claimed_at_unix_ms,
    };
    attempt.validate_for_parent(launch, &capture.capture_authority)?;
    Ok(attempt)
}

fn derive_cleanup_obligation(
    attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
) -> Result<CurrentFinalVerificationNativeCleanupObligationV1, LedgerError> {
    let cleanup = CurrentFinalVerificationNativeCleanupObligationV1 {
        obligation_version: NATIVE_PREPARATION_VERSION_V1,
        cleanup_effect_id: attempt.cleanup_effect_id.clone(),
        preparation_attempt_id: attempt.preparation_attempt_id.clone(),
        sprint_id: attempt.sprint_id.clone(),
        attempt_id: attempt.attempt_id.clone(),
        native_journal_id: attempt.native_journal_id.clone(),
        state: NativeCleanupObligationStateV1::Pending,
    };
    cleanup.validate_for_attempt(attempt)?;
    Ok(cleanup)
}

fn validate_platform_compatibility(
    expectation: &NativePreparationPlatformExpectationV1,
    capture: &PersistedCurrentFinalVerificationCaptureAcquisitionV1,
) -> Result<(), LedgerError> {
    use crate::CurrentFinalVerificationNativeContainmentBackendV2::{
        LinuxBubblewrapLandlockSeccompCgroupV2, MacOsDedicatedIdentitySeatbelt,
    };

    expectation.validate()?;
    let preparation = &capture.launch.launch_authority.launch_preparation;
    let compatible = match preparation.containment_backend {
        MacOsDedicatedIdentitySeatbelt => expectation.target_id() == "macos-15-apple-silicon",
        LinuxBubblewrapLandlockSeccompCgroupV2 => matches!(
            expectation.target_id(),
            "ubuntu-26.04-x86_64" | "fedora-44-x86_64"
        ),
    };
    if !compatible || expectation.target_identity_digest() != &preparation.target_identity_digest {
        return Err(reference_mismatch(
            "current final-verification native platform expectation",
            "target is incompatible with the exact v35 containment backend or target identity",
        ));
    }
    Ok(())
}

fn v37_prefix_exists(connection: &Connection, attempt_id: &str) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT 1
             FROM current_final_verification_native_preparation_attempts_v37
             WHERE attempt_id = ?1",
            [attempt_id],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(Into::into)
}

fn insert_attempt_v37(
    transaction: &Transaction<'_>,
    attempt: &CurrentFinalVerificationNativePreparationAttemptV1,
    attempt_digest: &Digest,
) -> Result<(), LedgerError> {
    let expectation_digest = attempt.platform_expectation.canonical_digest()?;
    transaction.execute(
        "INSERT INTO current_final_verification_native_preparation_attempts_v37 (
            preparation_attempt_id, preparation_version, sprint_id, attempt_id,
            launch_authority_digest, capture_authority_digest,
            acquired_anchor_digest, native_journal_id, cleanup_effect_id,
            preparation_receipt_id, target_id, target_identity_digest,
            native_policy_digest, runner_binary_digest, runner_binary_size_bytes,
            runner_protocol_version, runner_protocol_digest, private_state_id,
            private_state_digest, workspace_grant_hash, execution_policy_digest,
            expected_source_identity_digest, expected_service_protocol_version,
            expected_service_protocol_digest, expected_service_manifest_digest,
            platform_expectation_digest, ledger_database_identity_digest,
            state_root_identity_digest, launch_cleanup_lock_identity_digest,
            claimed_at_unix_ms, attempt_digest, attempt_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
            ?27, ?28, ?29, ?30, ?31, ?32
         )",
        params![
            attempt.preparation_attempt_id,
            i64::from(attempt.preparation_version),
            attempt.sprint_id,
            attempt.attempt_id,
            attempt.launch_authority_digest.as_str(),
            attempt.capture_authority_digest.as_str(),
            attempt.acquired_anchor_digest.as_str(),
            attempt.native_journal_id,
            attempt.cleanup_effect_id,
            attempt.preparation_receipt_id,
            attempt.platform_expectation.target_id(),
            attempt
                .platform_expectation
                .target_identity_digest()
                .as_str(),
            attempt.native_policy_digest.as_str(),
            attempt.runner_binary_digest.as_str(),
            sqlite_i64(
                "native_preparation_attempt.runner_binary_size_bytes",
                attempt.runner_binary_size_bytes,
            )?,
            i64::from(attempt.runner_protocol_version),
            attempt.runner_protocol_digest.as_str(),
            attempt.private_state_id,
            attempt.private_state_digest.as_str(),
            attempt.workspace_grant_hash.as_str(),
            attempt.execution_policy_digest.as_str(),
            attempt
                .platform_expectation
                .expected_source_identity_digest()
                .as_str(),
            i64::from(
                attempt
                    .platform_expectation
                    .expected_service_protocol_version(),
            ),
            attempt
                .platform_expectation
                .expected_service_protocol_digest()
                .as_str(),
            attempt
                .platform_expectation
                .expected_service_manifest_digest()
                .as_str(),
            expectation_digest.as_str(),
            attempt.ledger_database_identity_digest.as_str(),
            attempt.state_root_identity_digest.as_str(),
            attempt.launch_cleanup_lock_identity_digest.as_str(),
            sqlite_i64(
                "native_preparation_attempt.claimed_at_unix_ms",
                attempt.claimed_at_unix_ms,
            )?,
            attempt_digest.as_str(),
            attempt.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn insert_cleanup_v37(
    transaction: &Transaction<'_>,
    cleanup: &CurrentFinalVerificationNativeCleanupObligationV1,
    cleanup_digest: &Digest,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_native_cleanup_obligations_v37 (
            cleanup_effect_id, preparation_attempt_id, sprint_id, attempt_id,
            native_journal_id, state, obligation_digest, obligation_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'Pending', ?6, ?7)",
        params![
            cleanup.cleanup_effect_id,
            cleanup.preparation_attempt_id,
            cleanup.sprint_id,
            cleanup.attempt_id,
            cleanup.native_journal_id,
            cleanup_digest.as_str(),
            cleanup.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn insert_source_consumption_v37(
    transaction: &Transaction<'_>,
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
    accepted_payload: Option<&[u8]>,
    consumption_digest: &Digest,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_native_source_consumptions_v37 (
            source_consumption_id, preparation_attempt_id, sprint_id, attempt_id,
            operation_domain, authenticated_source_identity_digest,
            source_session_identity_digest, operation_sequence, payload_digest,
            payload_length, disposition, rejection_reason, accepted_payload_json,
            accepted_preparation_receipt_id, consumed_at_unix_ms,
            consumption_digest, consumption_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17
         )",
        params![
            consumption.source_consumption_id,
            consumption.preparation_attempt_id,
            consumption.sprint_id,
            consumption.attempt_id,
            consumption.operation_domain,
            consumption.authenticated_source_identity_digest.as_str(),
            consumption.source_session_identity_digest.as_str(),
            consumption.operation_sequence,
            consumption.payload_digest.as_str(),
            sqlite_i64(
                "native_source_consumption.payload_length",
                consumption.payload_length,
            )?,
            source_disposition_name(consumption),
            consumption.rejection_reason.map(rejection_reason_name),
            accepted_payload,
            consumption.accepted_preparation_receipt_id,
            sqlite_i64(
                "native_source_consumption.consumed_at_unix_ms",
                consumption.consumed_at_unix_ms,
            )?,
            consumption_digest.as_str(),
            consumption.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

fn insert_outcome_v37(
    transaction: &Transaction<'_>,
    outcome: &CurrentFinalVerificationNativePreparationOutcomeV1,
    outcome_digest: &Digest,
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO current_final_verification_native_preparation_outcomes_v37 (
            preparation_receipt_id, preparation_attempt_id, source_consumption_id,
            sprint_id, attempt_id, native_journal_id, cleanup_effect_id,
            disposition, native_evidence_digest, native_evidence_bytes,
            finished_at_unix_ms, outcome_digest, outcome_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            outcome.preparation_receipt_id,
            outcome.preparation_attempt_id,
            outcome.source_consumption_id,
            outcome.sprint_id,
            outcome.attempt_id,
            outcome.native_journal_id,
            outcome.cleanup_effect_id,
            disposition_name(outcome.disposition),
            outcome.native_evidence_digest.as_str(),
            outcome.native_evidence_bytes,
            sqlite_i64(
                "native_preparation_outcome.finished_at_unix_ms",
                outcome.finished_at_unix_ms,
            )?,
            outcome_digest.as_str(),
            outcome.canonical_bytes()?,
        ],
    )?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear loader validates every append-only row and cross-record join"
)]
fn load_native_preparation_from(
    connection: &Connection,
    capture: PersistedCurrentFinalVerificationCaptureAcquisitionV1,
) -> Result<PersistedCurrentFinalVerificationNativePreparationV1, LedgerError> {
    let (attempt_bytes, stored_attempt_digest, attempt_projection_matches) = connection
        .query_row(
            "SELECT
                attempt_json,
                attempt_digest,
                grok_current_final_verification_native_preparation_attempt_v37_matches(
                    attempt_json, preparation_attempt_id, preparation_version,
                    sprint_id, attempt_id, launch_authority_digest,
                    capture_authority_digest, acquired_anchor_digest,
                    native_journal_id, cleanup_effect_id, preparation_receipt_id,
                    target_id, target_identity_digest, native_policy_digest,
                    runner_binary_digest, runner_binary_size_bytes,
                    runner_protocol_version, runner_protocol_digest,
                    private_state_id, private_state_digest, workspace_grant_hash,
                    execution_policy_digest, expected_source_identity_digest,
                    expected_service_protocol_version,
                    expected_service_protocol_digest,
                    expected_service_manifest_digest, platform_expectation_digest,
                    ledger_database_identity_digest, state_root_identity_digest,
                    launch_cleanup_lock_identity_digest, claimed_at_unix_ms
                )
             FROM current_final_verification_native_preparation_attempts_v37
             WHERE attempt_id = ?1",
            [&capture.capture_authority.attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "current final-verification native preparation",
            id: capture.capture_authority.attempt_id.clone(),
        })?;
    let attempt: CurrentFinalVerificationNativePreparationAttemptV1 =
        decode_exact("current native-preparation attempt", &attempt_bytes)?;
    attempt.validate_for_parent(&capture.launch.launch_authority, &capture.capture_authority)?;
    if attempt_projection_matches != 1
        || attempt.canonical_digest()?.as_str() != stored_attempt_digest
    {
        return Err(corrupt(
            "current final-verification native preparation attempt",
            "stored digest or exhaustive normalized projection differs from canonical JSON",
        ));
    }

    let (cleanup_bytes, stored_cleanup_digest, cleanup_projection_matches) = connection
        .query_row(
            "SELECT
                obligation_json,
                obligation_digest,
                grok_current_final_verification_native_cleanup_obligation_v37_matches(
                    obligation_json, cleanup_effect_id, preparation_attempt_id,
                    sprint_id, attempt_id, native_journal_id, state
                )
             FROM current_final_verification_native_cleanup_obligations_v37
             WHERE preparation_attempt_id = ?1",
            [&attempt.preparation_attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| {
            corrupt(
                "current final-verification native preparation",
                "attempt lacks its atomically paired pending cleanup obligation",
            )
        })?;
    let cleanup: CurrentFinalVerificationNativeCleanupObligationV1 =
        decode_exact("current native cleanup obligation", &cleanup_bytes)?;
    cleanup.validate_for_attempt(&attempt)?;
    if cleanup_projection_matches != 1
        || cleanup.canonical_digest()?.as_str() != stored_cleanup_digest
    {
        return Err(corrupt(
            "current final-verification native cleanup obligation",
            "stored digest or exhaustive normalized projection differs from canonical JSON",
        ));
    }

    let source_row = connection
        .query_row(
            "SELECT
                consumption_json,
                accepted_payload_json,
                consumption_digest,
                grok_current_final_verification_native_source_consumption_v37_matches(
                    consumption_json, source_consumption_id, preparation_attempt_id,
                    sprint_id, attempt_id, operation_domain,
                    authenticated_source_identity_digest,
                    source_session_identity_digest, operation_sequence,
                    payload_digest, payload_length, disposition, rejection_reason,
                    accepted_preparation_receipt_id, consumed_at_unix_ms
                )
             FROM current_final_verification_native_source_consumptions_v37
             WHERE preparation_attempt_id = ?1",
            [&attempt.preparation_attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let (source_consumption, accepted_source) = match source_row {
        None => (None, None),
        Some((
            consumption_bytes,
            accepted_bytes,
            stored_consumption_digest,
            consumption_projection_matches,
        )) => {
            let consumption: CurrentFinalVerificationNativeSourceConsumptionV1 =
                decode_exact("current native source consumption", &consumption_bytes)?;
            consumption.validate()?;
            if consumption_projection_matches != 1
                || consumption.canonical_digest()?.as_str() != stored_consumption_digest
                || consumption.source_consumption_id
                    != derive_source_consumption_id(
                        &consumption.authenticated_source_identity_digest,
                        &consumption.source_session_identity_digest,
                        &consumption.operation_sequence,
                    )
                || consumption.preparation_attempt_id != attempt.preparation_attempt_id
                || consumption.sprint_id != attempt.sprint_id
                || consumption.attempt_id != attempt.attempt_id
                || consumption.consumed_at_unix_ms < attempt.claimed_at_unix_ms
            {
                return Err(corrupt(
                    "current final-verification native source consumption",
                    "source consumption crosses its exact preparation prefix",
                ));
            }
            match (consumption.disposition, accepted_bytes) {
                (NativeSourceConsumptionDispositionV1::Accepted, Some(bytes)) => {
                    if consumption.payload_digest != source_payload_digest_bytes(&bytes)
                        || consumption.payload_length
                            != u64::try_from(bytes.len()).map_err(|_| {
                                LedgerError::IntegerOutOfRange(
                                    "native_source_consumption.payload_length",
                                )
                            })?
                    {
                        return Err(corrupt(
                            "current final-verification native source consumption",
                            "accepted payload bytes differ from consumption metadata",
                        ));
                    }
                    let payload: CurrentFinalVerificationNativePreparationSourcePayloadV1 =
                        decode_exact("current native source payload", &bytes)?;
                    payload.validate_for_attempt(
                        &attempt,
                        &cleanup,
                        &consumption.authenticated_source_identity_digest,
                        &consumption.source_session_identity_digest,
                        &consumption.operation_sequence,
                        consumption.consumed_at_unix_ms,
                    )?;
                    (Some(consumption), Some(payload))
                }
                (NativeSourceConsumptionDispositionV1::SourceRejected, None) => {
                    (Some(consumption), None)
                }
                _ => {
                    return Err(corrupt(
                        "current final-verification native source consumption",
                        "accepted/rejected payload presence is inconsistent",
                    ));
                }
            }
        }
    };

    let outcome_row = connection
        .query_row(
            "SELECT
                outcome_json,
                native_evidence_bytes,
                outcome_digest,
                grok_current_final_verification_native_preparation_outcome_v37_matches(
                    outcome_json, preparation_receipt_id, preparation_attempt_id,
                    source_consumption_id, sprint_id, attempt_id, native_journal_id,
                    cleanup_effect_id, disposition, native_evidence_digest,
                    native_evidence_bytes, finished_at_unix_ms
                )
             FROM current_final_verification_native_preparation_outcomes_v37
             WHERE preparation_attempt_id = ?1",
            [&attempt.preparation_attempt_id],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let outcome = match outcome_row {
        None => None,
        Some((
            outcome_bytes,
            evidence_bytes,
            stored_outcome_digest,
            outcome_projection_matches,
        )) => {
            let outcome: CurrentFinalVerificationNativePreparationOutcomeV1 =
                decode_exact("current native-preparation outcome", &outcome_bytes)?;
            if outcome_projection_matches != 1
                || outcome.canonical_digest()?.as_str() != stored_outcome_digest
                || outcome.native_evidence_bytes != evidence_bytes
                || outcome.native_evidence_digest != native_evidence_digest(&evidence_bytes)
            {
                return Err(corrupt(
                    "current final-verification native-preparation outcome",
                    "outcome evidence column differs from exact canonical outcome",
                ));
            }
            let consumption = source_consumption.as_ref().ok_or_else(|| {
                corrupt(
                    "current final-verification native-preparation outcome",
                    "outcome lacks its accepted source consumption",
                )
            })?;
            let payload = accepted_source.as_ref().ok_or_else(|| {
                corrupt(
                    "current final-verification native-preparation outcome",
                    "outcome lacks its exact accepted source payload",
                )
            })?;
            outcome.validate_for_source(payload, consumption, &attempt, &cleanup)?;
            Some(outcome)
        }
    };
    let source_is_accepted = source_consumption
        .as_ref()
        .is_some_and(|source| source.disposition == NativeSourceConsumptionDispositionV1::Accepted);
    if source_is_accepted != outcome.is_some() || source_is_accepted != accepted_source.is_some() {
        return Err(corrupt(
            "current final-verification native preparation",
            "accepted source and derived outcome are not atomically paired",
        ));
    }

    Ok(PersistedCurrentFinalVerificationNativePreparationV1 {
        capture,
        attempt,
        cleanup_obligation: cleanup,
        source_consumption,
        accepted_source,
        outcome,
    })
}

#[expect(
    clippy::large_enum_variant,
    reason = "the accepted canonical record stays owned without adding pointer indirection"
)]
enum SourceClassificationV1 {
    Accepted(CurrentFinalVerificationNativePreparationSourcePayloadV1),
    Rejected(NativeSourceRejectionReasonV1),
}

fn classify_source(
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    source: &AuthenticatedNativePreparationSourceViewV1,
    consumed_at_unix_ms: u64,
) -> SourceClassificationV1 {
    if &source.authenticated_source_identity_digest
        != prefix
            .attempt
            .platform_expectation
            .expected_source_identity_digest()
    {
        return SourceClassificationV1::Rejected(
            NativeSourceRejectionReasonV1::SourceIdentityMismatch,
        );
    }
    let Some(canonical_payload) = source.bounded_canonical_payload.as_deref() else {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::Oversized);
    };
    if source.payload_digest != source_payload_digest_bytes(canonical_payload)
        || source.payload_length
            != u64::try_from(canonical_payload.len())
                .expect("a bounded in-memory source payload length always fits u64")
    {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::Malformed);
    }
    let Ok(payload) = serde_json::from_slice::<
        CurrentFinalVerificationNativePreparationSourcePayloadV1,
    >(canonical_payload) else {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::Malformed);
    };
    if let Err(error) = payload.validate() {
        if error.field().contains("evidence") {
            return SourceClassificationV1::Rejected(
                NativeSourceRejectionReasonV1::EvidenceInvalid,
            );
        }
        if error.field().contains("finished_at") {
            return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::TimeInvalid);
        }
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::Malformed);
    }
    if serde_json::to_vec(&payload).ok().as_deref() != Some(canonical_payload) {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::NonCanonical);
    }
    if payload.finished_at_unix_ms < prefix.attempt.claimed_at_unix_ms
        || payload.finished_at_unix_ms > consumed_at_unix_ms
    {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::TimeInvalid);
    }
    if payload
        .validate_for_attempt(
            &prefix.attempt,
            &prefix.cleanup_obligation,
            &source.authenticated_source_identity_digest,
            &source.source_session_identity_digest,
            &source.operation_sequence,
            consumed_at_unix_ms,
        )
        .is_err()
    {
        return SourceClassificationV1::Rejected(NativeSourceRejectionReasonV1::CrossedIdentity);
    }
    SourceClassificationV1::Accepted(payload)
}

fn rejected_consumption(
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    source: &AuthenticatedNativePreparationSourceViewV1,
    source_consumption_id: String,
    reason: NativeSourceRejectionReasonV1,
    consumed_at_unix_ms: u64,
) -> Result<CurrentFinalVerificationNativeSourceConsumptionV1, LedgerError> {
    let consumption = CurrentFinalVerificationNativeSourceConsumptionV1 {
        consumption_version: NATIVE_PREPARATION_VERSION_V1,
        source_consumption_id,
        preparation_attempt_id: prefix.attempt.preparation_attempt_id.clone(),
        sprint_id: prefix.attempt.sprint_id.clone(),
        attempt_id: prefix.attempt.attempt_id.clone(),
        operation_domain: NATIVE_PREPARATION_OPERATION_DOMAIN_V1.to_owned(),
        authenticated_source_identity_digest: source.authenticated_source_identity_digest.clone(),
        source_session_identity_digest: source.source_session_identity_digest.clone(),
        operation_sequence: source.operation_sequence.clone(),
        payload_digest: source.payload_digest.clone(),
        payload_length: source.payload_length,
        disposition: NativeSourceConsumptionDispositionV1::SourceRejected,
        rejection_reason: Some(reason),
        accepted_preparation_receipt_id: None,
        consumed_at_unix_ms,
    };
    consumption.validate()?;
    Ok(consumption)
}

fn accepted_consumption(
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    source: &AuthenticatedNativePreparationSourceViewV1,
    payload: &CurrentFinalVerificationNativePreparationSourcePayloadV1,
    source_consumption_id: String,
    consumed_at_unix_ms: u64,
) -> Result<CurrentFinalVerificationNativeSourceConsumptionV1, LedgerError> {
    let payload_bytes = payload.canonical_bytes()?;
    let consumption = CurrentFinalVerificationNativeSourceConsumptionV1 {
        consumption_version: NATIVE_PREPARATION_VERSION_V1,
        source_consumption_id,
        preparation_attempt_id: prefix.attempt.preparation_attempt_id.clone(),
        sprint_id: prefix.attempt.sprint_id.clone(),
        attempt_id: prefix.attempt.attempt_id.clone(),
        operation_domain: NATIVE_PREPARATION_OPERATION_DOMAIN_V1.to_owned(),
        authenticated_source_identity_digest: source.authenticated_source_identity_digest.clone(),
        source_session_identity_digest: source.source_session_identity_digest.clone(),
        operation_sequence: source.operation_sequence.clone(),
        payload_digest: source_payload_digest_bytes(&payload_bytes),
        payload_length: u64::try_from(payload_bytes.len())
            .map_err(|_| LedgerError::IntegerOutOfRange("native source payload length"))?,
        disposition: NativeSourceConsumptionDispositionV1::Accepted,
        rejection_reason: None,
        accepted_preparation_receipt_id: Some(prefix.attempt.preparation_receipt_id.clone()),
        consumed_at_unix_ms,
    };
    consumption.validate()?;
    payload.validate_for_attempt(
        &prefix.attempt,
        &prefix.cleanup_obligation,
        &consumption.authenticated_source_identity_digest,
        &consumption.source_session_identity_digest,
        &consumption.operation_sequence,
        consumption.consumed_at_unix_ms,
    )?;
    Ok(consumption)
}

fn outcome_from_source(
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
    payload: &CurrentFinalVerificationNativePreparationSourcePayloadV1,
) -> Result<CurrentFinalVerificationNativePreparationOutcomeV1, LedgerError> {
    let outcome = CurrentFinalVerificationNativePreparationOutcomeV1 {
        outcome_version: NATIVE_PREPARATION_VERSION_V1,
        preparation_receipt_id: prefix.attempt.preparation_receipt_id.clone(),
        preparation_attempt_id: prefix.attempt.preparation_attempt_id.clone(),
        source_consumption_id: consumption.source_consumption_id.clone(),
        sprint_id: prefix.attempt.sprint_id.clone(),
        attempt_id: prefix.attempt.attempt_id.clone(),
        native_journal_id: prefix.attempt.native_journal_id.clone(),
        cleanup_effect_id: prefix.cleanup_obligation.cleanup_effect_id.clone(),
        disposition: payload.disposition,
        native_evidence_digest: payload.native_evidence_digest.clone(),
        native_evidence_bytes: payload.native_evidence_bytes.clone(),
        finished_at_unix_ms: payload.finished_at_unix_ms,
    };
    outcome.validate_for_source(
        payload,
        consumption,
        &prefix.attempt,
        &prefix.cleanup_obligation,
    )?;
    Ok(outcome)
}

fn source_consumption_id(source: &AuthenticatedNativePreparationSourceViewV1) -> String {
    derive_source_consumption_id(
        &source.authenticated_source_identity_digest,
        &source.source_session_identity_digest,
        &source.operation_sequence,
    )
}

fn derive_source_consumption_id(
    authenticated_source_identity_digest: &Digest,
    source_session_identity_digest: &Digest,
    operation_sequence: &str,
) -> String {
    let fields = [
        authenticated_source_identity_digest.as_str().as_bytes(),
        source_session_identity_digest.as_str().as_bytes(),
        operation_sequence.as_bytes(),
    ];
    let mut preimage = Vec::with_capacity(
        SOURCE_CONSUMPTION_ID_DOMAIN_V1.len()
            + fields
                .iter()
                .map(|field| std::mem::size_of::<u64>() + field.len())
                .sum::<usize>(),
    );
    preimage.extend_from_slice(SOURCE_CONSUMPTION_ID_DOMAIN_V1);
    for field in fields {
        preimage.extend_from_slice(
            &u64::try_from(field.len())
                .expect("identity field lengths fit u64")
                .to_be_bytes(),
        );
        preimage.extend_from_slice(field);
    }
    Digest::sha256(&preimage).to_string()
}

fn source_tuple_exists(
    connection: &Connection,
    source: &AuthenticatedNativePreparationSourceViewV1,
) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT 1
             FROM current_final_verification_native_source_consumptions_v37
             WHERE operation_domain = ?1
               AND authenticated_source_identity_digest = ?2
               AND source_session_identity_digest = ?3
               AND operation_sequence = ?4",
            params![
                NATIVE_PREPARATION_OPERATION_DOMAIN_V1,
                source.authenticated_source_identity_digest.as_str(),
                source.source_session_identity_digest.as_str(),
                source.operation_sequence,
            ],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

fn persist_rejected_source(
    connection: &mut Connection,
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
) -> Result<(), LedgerError> {
    let consumption_digest = consumption.canonical_digest()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "defer_foreign_keys", true)?;
    with_schema_write_admission(
        vec![write_claim(
            "source",
            &consumption.source_consumption_id,
            &consumption_digest,
        )],
        || insert_source_consumption_v37(&transaction, consumption, None, &consumption_digest),
    )?;
    let expected = PersistedCurrentFinalVerificationNativePreparationV1 {
        capture: prefix.capture.clone(),
        attempt: prefix.attempt.clone(),
        cleanup_obligation: prefix.cleanup_obligation.clone(),
        source_consumption: Some(consumption.clone()),
        accepted_source: None,
        outcome: None,
    };
    let transactional = load_native_preparation_from(&transaction, prefix.capture.clone())?;
    if transactional != expected {
        return Err(corrupt(
            "current final-verification native source rejection",
            "transactional readback differs from exact metadata-only rejection",
        ));
    }
    verify_no_foreign_key_violations_v37(&transaction)?;
    transaction
        .commit()
        .map_err(|error| LedgerError::PostCommitStateUncertain {
            operation: "current final-verification native source rejection",
            recovery_id: consumption.source_consumption_id.clone(),
            detail: error.to_string(),
        })
}

fn persist_accepted_source_and_outcome(
    connection: &mut Connection,
    prefix: &PersistedCurrentFinalVerificationNativePreparationV1,
    consumption: &CurrentFinalVerificationNativeSourceConsumptionV1,
    payload: &CurrentFinalVerificationNativePreparationSourcePayloadV1,
    outcome: &CurrentFinalVerificationNativePreparationOutcomeV1,
) -> Result<(), LedgerError> {
    let payload_bytes = payload.canonical_bytes()?;
    let consumption_digest = consumption.canonical_digest()?;
    let outcome_digest = outcome.canonical_digest()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.pragma_update(None, "defer_foreign_keys", true)?;
    with_schema_write_admission(
        vec![
            write_claim(
                "source",
                &consumption.source_consumption_id,
                &consumption_digest,
            ),
            write_claim("outcome", &outcome.preparation_receipt_id, &outcome_digest),
        ],
        || {
            insert_source_consumption_v37(
                &transaction,
                consumption,
                Some(&payload_bytes),
                &consumption_digest,
            )?;
            insert_outcome_v37(&transaction, outcome, &outcome_digest)
        },
    )?;
    let expected = PersistedCurrentFinalVerificationNativePreparationV1 {
        capture: prefix.capture.clone(),
        attempt: prefix.attempt.clone(),
        cleanup_obligation: prefix.cleanup_obligation.clone(),
        source_consumption: Some(consumption.clone()),
        accepted_source: Some(payload.clone()),
        outcome: Some(outcome.clone()),
    };
    let transactional = load_native_preparation_from(&transaction, prefix.capture.clone())?;
    if transactional != expected {
        return Err(corrupt(
            "current final-verification native preparation outcome",
            "transactional readback differs from exact source-derived outcome",
        ));
    }
    verify_no_foreign_key_violations_v37(&transaction)?;
    transaction
        .commit()
        .map_err(|error| LedgerError::PostCommitStateUncertain {
            operation: "current final-verification native preparation outcome",
            recovery_id: outcome.preparation_receipt_id.clone(),
            detail: error.to_string(),
        })
}

fn independently_load_native_preparation_v37(
    database_path: &std::path::Path,
    attempt_id: &str,
) -> Result<PersistedCurrentFinalVerificationNativePreparationV1, LedgerError> {
    let ledger = EventLedger::open_read_only(database_path)?;
    ledger.load_current_final_verification_native_preparation_v37(attempt_id)
}

fn current_unix_ms_at_or_after(minimum_unix_ms: u64) -> Result<u64, LedgerError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        LedgerError::InvalidTimestamp("native source consumption system clock after the Unix epoch")
    })?;
    let unix_ms = u64::try_from(duration.as_millis()).map_err(|_| {
        LedgerError::IntegerOutOfRange("native source consumption system clock milliseconds")
    })?;
    if unix_ms < minimum_unix_ms {
        return Err(LedgerError::InvalidTimestamp(
            "native source consumption Core clock at or after preparation claim",
        ));
    }
    Ok(unix_ms)
}

fn decode_exact<T>(entity: &'static str, bytes: &[u8]) -> Result<T, LedgerError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        return Err(corrupt(
            entity,
            "canonical JSON length is outside the supported bound",
        ));
    }
    let value: T =
        serde_json::from_slice(bytes).map_err(|source| LedgerError::Json { entity, source })?;
    let encoded =
        serde_json::to_vec(&value).map_err(|source| LedgerError::Json { entity, source })?;
    if encoded != bytes {
        return Err(corrupt(
            entity,
            "stored JSON is not exact canonical encoding",
        ));
    }
    Ok(value)
}

fn sqlite_i64(field: &'static str, value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::IntegerOutOfRange(field))
}

fn reference_mismatch(entity: &'static str, detail: impl Into<String>) -> LedgerError {
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
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::super::current_final_verification_capture_v36::tests::fresh_capture_and_native_launch_permit;
    use super::*;
    use crate::CurrentFinalVerificationNativeContainmentBackendV2::{
        LinuxBubblewrapLandlockSeccompCgroupV2, MacOsDedicatedIdentitySeatbelt,
    };

    const CLAIMED_AT_UNIX_MS: u64 = 100;
    const FINISHED_AT_UNIX_MS: u64 = 150;
    const SOURCE_IDENTITY: [u8; 32] = [0x37; 32];
    const SESSION_IDENTITY: [u8; 32] = [0x38; 32];

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn expectation(
        capture: &PersistedCurrentFinalVerificationCaptureAcquisitionV1,
    ) -> FreshNativePreparationPlatformAdmissionV1 {
        let preparation = &capture.launch.launch_authority.launch_preparation;
        let target_id = match preparation.containment_backend {
            MacOsDedicatedIdentitySeatbelt => "macos-15-apple-silicon",
            LinuxBubblewrapLandlockSeccompCgroupV2 => "ubuntu-26.04-x86_64",
        };
        FreshNativePreparationPlatformAdmissionV1::from_test(
            NativePreparationPlatformExpectationV1::from_test(
                target_id.to_owned(),
                preparation.target_identity_digest.clone(),
                raw_identity_digest(&SOURCE_IDENTITY),
                1,
                digest("native-service-protocol"),
                digest("native-service-manifest"),
            )
            .expect("construct sealed test-only platform expectation"),
        )
    }

    fn accepted_payload(
        claim: &LiveCurrentFinalVerificationNativePreparationClaimV1<'_>,
        disposition: NativePreparationDispositionV1,
    ) -> CurrentFinalVerificationNativePreparationSourcePayloadV1 {
        let attempt = claim.attempt();
        assert_eq!(
            claim.capture().capture_authority.attempt_id,
            attempt.attempt_id
        );
        assert_eq!(
            claim.cleanup_obligation().cleanup_effect_id,
            attempt.cleanup_effect_id
        );
        let evidence = b"exact-native-preparation-evidence".to_vec();
        CurrentFinalVerificationNativePreparationSourcePayloadV1 {
            payload_version: NATIVE_PREPARATION_VERSION_V1,
            preparation_attempt_id: attempt.preparation_attempt_id.clone(),
            sprint_id: attempt.sprint_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            launch_authority_digest: attempt.launch_authority_digest.clone(),
            capture_authority_digest: attempt.capture_authority_digest.clone(),
            acquired_anchor_digest: attempt.acquired_anchor_digest.clone(),
            native_journal_id: attempt.native_journal_id.clone(),
            cleanup_effect_id: attempt.cleanup_effect_id.clone(),
            preparation_receipt_id: attempt.preparation_receipt_id.clone(),
            platform_expectation: attempt.platform_expectation.clone(),
            native_policy_digest: attempt.native_policy_digest.clone(),
            runner_binary_digest: attempt.runner_binary_digest.clone(),
            runner_binary_size_bytes: attempt.runner_binary_size_bytes,
            runner_protocol_version: attempt.runner_protocol_version,
            runner_protocol_digest: attempt.runner_protocol_digest.clone(),
            private_state_id: attempt.private_state_id.clone(),
            private_state_digest: attempt.private_state_digest.clone(),
            workspace_grant_hash: attempt.workspace_grant_hash.clone(),
            execution_policy_digest: attempt.execution_policy_digest.clone(),
            authenticated_source_identity_digest: raw_identity_digest(&SOURCE_IDENTITY),
            source_session_identity_digest: raw_identity_digest(&SESSION_IDENTITY),
            operation_domain: NATIVE_PREPARATION_OPERATION_DOMAIN_V1.to_owned(),
            operation_sequence: "1".to_owned(),
            disposition,
            native_evidence_digest: native_evidence_digest(&evidence),
            native_evidence_bytes: evidence,
            finished_at_unix_ms: FINISHED_AT_UNIX_MS,
        }
    }

    fn bounded_source_view(
        operation_sequence: &str,
        payload: Vec<u8>,
    ) -> AuthenticatedNativePreparationSourceViewV1 {
        AuthenticatedNativePreparationSourceViewV1 {
            authenticated_source_identity_digest: raw_identity_digest(&SOURCE_IDENTITY),
            source_session_identity_digest: raw_identity_digest(&SESSION_IDENTITY),
            operation_sequence: operation_sequence.to_owned(),
            payload_digest: source_payload_digest_bytes(&payload),
            payload_length: u64::try_from(payload.len()).expect("test payload length fits u64"),
            bounded_canonical_payload: Some(payload),
        }
    }

    fn create_user_only_empty_file(path: &std::path::Path) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create exact replacement file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure replacement file");
    }

    #[test]
    fn fresh_no_proof_commits_exact_pending_prefix_and_restart_remains_not_ready() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-no-proof");
        let expectation = expectation(&capture);
        let database_path = ledger.database_path.clone();
        let attempt_id = capture.capture_authority.attempt_id.clone();

        let committed = ledger
            .with_current_final_verification_native_preparation_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                |_| None,
            )
            .expect("commit exact no-proof prefix");
        assert_eq!(
            committed.persisted.readiness(),
            CurrentFinalVerificationNativePreparationReadinessV1::NotReady
        );
        assert!(committed.persisted.source_consumption.is_none());
        assert!(committed.v38_permit.is_none());

        drop(ledger);
        let reopened = EventLedger::open(database_path).expect("reopen exact v37 ledger");
        let readback = reopened
            .load_current_final_verification_native_preparation_v37(&attempt_id)
            .expect("read exact no-proof prefix after restart");
        assert_eq!(readback, committed.persisted);
        assert_eq!(
            readback.readiness(),
            CurrentFinalVerificationNativePreparationReadinessV1::NotReady
        );
    }

    #[test]
    fn preprefix_platform_mismatch_returns_exact_move_only_retry_custody() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-preprefix-custody");
        let mut crossed_expectation = expectation(&capture);
        crossed_expectation
            .expectation
            .set_target_id_for_test("ubuntu-26.04-x86_64");
        let result = ledger.with_current_final_verification_native_preparation_source_view_v37(
            permit,
            crossed_expectation,
            CLAIMED_AT_UNIX_MS,
            |_| None,
        );
        let Err(failure) = result else {
            panic!("crossed target must fail before prefix");
        };
        let CurrentFinalVerificationNativePreparationErrorV1::DefinitelyBeforePrefix {
            error,
            custody,
        } = failure
        else {
            panic!("crossed target must return exact pre-prefix custody")
        };
        assert!(matches!(*error, LedgerError::ReferenceMismatch { .. }));
        let (returned_permit, returned_expectation) = custody.into_parts();
        assert_eq!(
            returned_permit.attempt_id(),
            capture.capture_authority.attempt_id
        );
        assert_eq!(
            returned_expectation.expectation().target_id(),
            "ubuntu-26.04-x86_64"
        );
    }

    #[test]
    fn rejected_source_persists_only_exact_metadata_and_no_outcome() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-rejected-source");
        let expectation = expectation(&capture);
        let malformed_canary = b"{rejected-native-source-canary".to_vec();
        let committed = ledger
            .with_current_final_verification_native_preparation_source_view_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                |_| Some(bounded_source_view("1", malformed_canary.clone())),
            )
            .expect("commit metadata-only source rejection");
        let consumption = committed
            .persisted
            .source_consumption
            .as_ref()
            .expect("rejection has exact consumption metadata");
        assert_eq!(
            consumption.rejection_reason,
            Some(NativeSourceRejectionReasonV1::Malformed)
        );
        assert!(consumption.consumed_at_unix_ms >= CLAIMED_AT_UNIX_MS);
        assert!(committed.persisted.accepted_source.is_none());
        assert!(committed.persisted.outcome.is_none());
        let retained_payload: Option<Vec<u8>> = ledger
            .connection
            .query_row(
                "SELECT accepted_payload_json
                 FROM current_final_verification_native_source_consumptions_v37
                 WHERE preparation_attempt_id = ?1",
                [&committed.persisted.attempt.preparation_attempt_id],
                |row| row.get(0),
            )
            .expect("read rejection payload column");
        assert!(retained_payload.is_none());
    }

    #[test]
    fn oversized_source_is_never_copied_or_retained_as_raw_bytes() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-oversized-source");
        let expectation = expectation(&capture);
        let oversized = vec![0x5a; MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 + 1];
        let payload_digest = source_payload_digest_bytes(&oversized);
        let payload_length = u64::try_from(oversized.len()).expect("test length fits u64");
        drop(oversized);
        let source = AuthenticatedNativePreparationSourceViewV1 {
            authenticated_source_identity_digest: raw_identity_digest(&SOURCE_IDENTITY),
            source_session_identity_digest: raw_identity_digest(&SESSION_IDENTITY),
            operation_sequence: "1".to_owned(),
            payload_digest: payload_digest.clone(),
            payload_length,
            bounded_canonical_payload: None,
        };
        let committed = ledger
            .with_current_final_verification_native_preparation_source_view_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                |_| Some(source),
            )
            .expect("commit metadata-only oversized rejection");
        let consumption = committed
            .persisted
            .source_consumption
            .as_ref()
            .expect("oversized source has rejection metadata");
        assert_eq!(
            consumption.rejection_reason,
            Some(NativeSourceRejectionReasonV1::Oversized)
        );
        assert_eq!(consumption.payload_digest, payload_digest);
        assert_eq!(consumption.payload_length, payload_length);
        assert!(committed.persisted.accepted_source.is_none());
        assert!(committed.persisted.outcome.is_none());
        let (accepted_payload, consumption_json): (Option<Vec<u8>>, Vec<u8>) = ledger
            .connection
            .query_row(
                "SELECT accepted_payload_json, consumption_json
                 FROM current_final_verification_native_source_consumptions_v37
                 WHERE preparation_attempt_id = ?1",
                [&committed.persisted.attempt.preparation_attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read oversized rejection storage");
        assert!(accepted_payload.is_none());
        assert!(
            !consumption_json
                .windows(32)
                .any(|window| window == [0x5a; 32])
        );
    }

    #[test]
    fn future_source_time_is_rejected_against_post_callback_core_clock() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-future-source-time");
        let expectation = expectation(&capture);
        let future_finished_at =
            current_unix_ms_at_or_after(1).expect("read test Core clock") + 60_000;
        let committed = ledger
            .with_current_final_verification_native_preparation_source_view_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                |claim| {
                    let mut payload =
                        accepted_payload(claim, NativePreparationDispositionV1::HeldChildPrepared);
                    payload.finished_at_unix_ms = future_finished_at;
                    Some(bounded_source_view(
                        "1",
                        payload.canonical_bytes().expect("canonical future payload"),
                    ))
                },
            )
            .expect("commit typed future-time rejection");
        assert_eq!(
            committed
                .persisted
                .source_consumption
                .as_ref()
                .and_then(|consumption| consumption.rejection_reason),
            Some(NativeSourceRejectionReasonV1::TimeInvalid)
        );
        assert!(committed.persisted.accepted_source.is_none());
        assert!(committed.v38_permit.is_none());
    }

    #[test]
    fn accepted_held_source_commits_exact_pair_and_only_fresh_call_gets_v38_permit() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-held-source");
        let expectation = expectation(&capture);
        let committed = ledger
            .with_current_final_verification_native_preparation_source_view_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                |claim| {
                    let payload =
                        accepted_payload(claim, NativePreparationDispositionV1::HeldChildPrepared);
                    Some(bounded_source_view(
                        "1",
                        payload
                            .canonical_bytes()
                            .expect("canonical accepted source payload"),
                    ))
                },
            )
            .expect("commit accepted source and exact held outcome");
        assert_eq!(
            committed.persisted.readiness(),
            CurrentFinalVerificationNativePreparationReadinessV1::HeldChildPrepared
        );
        assert!(
            committed
                .persisted
                .source_consumption
                .as_ref()
                .expect("accepted consumption")
                .consumed_at_unix_ms
                >= FINISHED_AT_UNIX_MS
        );
        let v38 = committed
            .v38_permit
            .as_ref()
            .expect("fresh held outcome grants exactly one v38 permit");
        assert_eq!(v38.attempt_id(), committed.persisted.attempt.attempt_id);
        assert_eq!(
            v38.preparation_receipt_id(),
            committed.persisted.attempt.preparation_receipt_id
        );
        v38.validate_for_ledger_instance(ledger.instance_id, &committed.persisted)
            .expect("v38 permit remains bound to exact accepted state");
        let replay = ledger
            .replay_current_final_verification_native_preparation_v37(
                &committed.persisted.attempt.attempt_id,
            )
            .expect("readback accepted state");
        assert_eq!(replay, committed.persisted);
    }

    #[test]
    fn loader_rejects_normalized_projection_and_stored_digest_tampering() {
        for (label, mutation) in [
            (
                "v37-projection-tamper",
                "UPDATE current_final_verification_native_preparation_attempts_v37
                 SET claimed_at_unix_ms = claimed_at_unix_ms + 1",
            ),
            (
                "v37-digest-tamper",
                "UPDATE current_final_verification_native_preparation_attempts_v37
                 SET attempt_digest =
                    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
            ),
        ] {
            let (mut ledger, capture, permit, _files) =
                fresh_capture_and_native_launch_permit(label);
            let expectation = expectation(&capture);
            ledger
                .with_current_final_verification_native_preparation_source_view_v37(
                    permit,
                    expectation,
                    CLAIMED_AT_UNIX_MS,
                    |_| None,
                )
                .expect("commit exact prefix before tamper");
            ledger
                .connection
                .execute_batch(
                    "DROP TRIGGER current_final_verification_native_preparation_attempts_v37_no_update;
                     PRAGMA ignore_check_constraints = ON;",
                )
                .expect("enable deliberate corruption fixture");
            ledger
                .connection
                .execute(mutation, [])
                .expect("mutate one protected column");
            let result = ledger.load_current_final_verification_native_preparation_v37(
                &capture.capture_authority.attempt_id,
            );
            assert!(matches!(result, Err(LedgerError::Corrupt { .. })));
        }
    }

    #[test]
    fn callback_lock_replacement_yields_recovery_only_and_persistent_readback_rejection() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-callback-lock-replacement");
        let expectation = expectation(&capture);
        let lock_path = launch_cleanup_lock_path(&ledger.database_path);
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_for_call = Arc::clone(&callback_count);
        let result = ledger.with_current_final_verification_native_preparation_source_view_v37(
            permit,
            expectation,
            CLAIMED_AT_UNIX_MS,
            move |_| {
                callback_count_for_call.fetch_add(1, Ordering::SeqCst);
                fs::remove_file(&lock_path).expect("unlink retained lock path");
                create_user_only_empty_file(&lock_path);
                None
            },
        );
        assert!(matches!(
            result,
            Err(CurrentFinalVerificationNativePreparationErrorV1::PrefixStateUncertain { .. })
        ));
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
        assert!(
            ledger
                .load_current_final_verification_native_preparation_v37(
                    &capture.capture_authority.attempt_id
                )
                .is_err()
        );
    }

    #[test]
    fn detached_database_path_after_prefix_prevents_callback_invocation() {
        let (mut ledger, capture, permit, _files) =
            fresh_capture_and_native_launch_permit("v37-detached-database-path");
        let expectation = expectation(&capture);
        let database_path = ledger.database_path.clone();
        let detached_database = database_path.with_extension("sqlite3.detached");
        let callback_count = Arc::new(AtomicUsize::new(0));
        let callback_count_for_call = Arc::clone(&callback_count);
        let result = ledger
            .with_current_final_verification_native_preparation_source_view_after_prefix_v37(
                permit,
                expectation,
                CLAIMED_AT_UNIX_MS,
                || {
                    fs::rename(&database_path, &detached_database)
                        .expect("detach the SQLite main file after prefix commit");
                    for suffix in ["-wal", "-shm"] {
                        let source = std::path::PathBuf::from(format!(
                            "{}{suffix}",
                            database_path.display()
                        ));
                        if source.exists() {
                            let destination = std::path::PathBuf::from(format!(
                                "{}{suffix}",
                                detached_database.display()
                            ));
                            fs::rename(source, destination)
                                .expect("detach the SQLite sidecar after prefix commit");
                        }
                    }
                    create_user_only_empty_file(&database_path);
                },
                move |_| {
                    callback_count_for_call.fetch_add(1, Ordering::SeqCst);
                    None
                },
            );
        assert!(matches!(
            result,
            Err(CurrentFinalVerificationNativePreparationErrorV1::PrefixStateUncertain { .. })
        ));
        assert_eq!(callback_count.load(Ordering::SeqCst), 0);
    }
}
