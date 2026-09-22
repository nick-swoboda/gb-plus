//! Pure, deterministic, and deliberately nonauthorizing derivation of current
//! final-verification evidence.
//!
//! The values in this module are integrity DTOs. They do not prove that any
//! source was admitted or durably recorded, and they never mint retry, repair,
//! application, completion, or promotion authority. A future ledger writer
//! must independently load and join every source before admitting the derived
//! result. In particular, a runner shutdown transcript is protocol readback;
//! it cannot replace independent direct-child and accounting-domain evidence.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Deserializer, Serialize};

use crate::Digest;

/// Current integrity-contract version for the pure evidence kernel.
pub const CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2: u32 = 2;
/// Maximum UTF-8 bytes in any identity accepted by this kernel.
pub const MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2: usize = 256;
/// Maximum canonical bytes accepted for any one DTO or digest preimage.
pub const MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2: usize = 1_048_576;
/// Maximum authenticated control observations considered for one attempt.
pub const MAX_CURRENT_FINAL_VERIFICATION_CONTROL_ACTIONS_V2: usize = 1;

const IDENTITY_SPINE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-identity-spine/v2\0";
const LIFECYCLE_RESERVATION_SET_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-lifecycle-reservation-set/v2\0";
const TERMINAL_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-terminal-source/v2\0";
const EFFECT_CUT_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-effect-cut-source/v2\0";
const OUTPUT_CUSTODY_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-output-custody-source/v2\0";
const COMMAND_DOMAIN_CLEANUP_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-command-domain-cleanup-source/v2\0";
const RUNNER_CLEANUP_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-runner-cleanup-source/v2\0";
const CONTROL_ACTION_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-control-action-source/v2\0";
const CONTROL_RECONCILIATION_SOURCE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/current-final-verification-control-reconciliation-source/v2\0";
const EVIDENCE_CLOSURE_DIGEST_DOMAIN: &[u8] =
    b"grok-build/non-authorizing-final-verification-evidence-closure/v2\0";
const DERIVED_OUTCOME_DIGEST_DOMAIN: &[u8] =
    b"grok-build/non-authorizing-final-verification-derived-outcome/v2\0";

/// Validation failure at the pure integrity boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonAuthorizingCurrentFinalVerificationEvidenceErrorV2 {
    /// A version discriminator is unsupported.
    UnsupportedVersion {
        /// Contract field.
        field: &'static str,
        /// Observed value.
        observed: u32,
    },
    /// A required identifier is empty or exceeds its byte bound.
    InvalidIdentifier {
        /// Contract field.
        field: &'static str,
    },
    /// A required event sequence is zero or internally out of order.
    InvalidEventOrder {
        /// Contract field.
        field: &'static str,
    },
    /// A numeric observation violates its closed variant.
    InvalidObservation {
        /// Contract field.
        field: &'static str,
    },
    /// A collection exceeds its fixed maximum.
    CountLimitExceeded {
        /// Contract field.
        field: &'static str,
        /// Maximum members.
        maximum: usize,
        /// Observed members.
        observed: usize,
    },
    /// Canonical JSON encoding failed or exceeded its fixed maximum.
    CanonicalEncoding {
        /// Contract field.
        field: &'static str,
        /// Stable diagnostic reason.
        reason: String,
    },
    /// A claimed digest does not authenticate its exact source fields.
    DigestMismatch {
        /// Contract field.
        field: &'static str,
    },
    /// One source belongs to a different current identity spine.
    CrossedIdentity {
        /// Crossed source class.
        source: &'static str,
    },
    /// A later lifecycle identity does not equal the identity fixed at launch.
    ReservationMismatch {
        /// Contract field that failed its launch reservation.
        field: &'static str,
    },
    /// Control identities are reused or their local event order is invalid.
    NonCanonicalControls,
}

impl Display for NonAuthorizingCurrentFinalVerificationEvidenceErrorV2 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { field, observed } => {
                write!(formatter, "{field}: unsupported version {observed}")
            }
            Self::InvalidIdentifier { field } => write!(
                formatter,
                "{field}: must contain 1..={MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2} UTF-8 bytes"
            ),
            Self::InvalidEventOrder { field } => {
                write!(formatter, "{field}: event sequence is zero or out of order")
            }
            Self::InvalidObservation { field } => {
                write!(formatter, "{field}: observation violates its closed variant")
            }
            Self::CountLimitExceeded {
                field,
                maximum,
                observed,
            } => write!(
                formatter,
                "{field}: maximum is {maximum} members; observed {observed}"
            ),
            Self::CanonicalEncoding { field, reason } => {
                write!(formatter, "{field}: canonical encoding failed: {reason}")
            }
            Self::DigestMismatch { field } => {
                write!(formatter, "{field}: digest does not authenticate exact fields")
            }
            Self::CrossedIdentity { source } => {
                write!(formatter, "{source}: source uses a different identity spine")
            }
            Self::ReservationMismatch { field } => {
                write!(formatter, "{field}: identity does not match its launch reservation")
            }
            Self::NonCanonicalControls => formatter.write_str(
                "control_resolution: control and event identities must be distinct and canonically ordered",
            ),
        }
    }
}

impl Error for NonAuthorizingCurrentFinalVerificationEvidenceErrorV2 {}

/// Closed native containment stack committed before the runner is launched.
/// This is deliberately stronger than command accounting alone.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationNativeContainmentBackendV2 {
    /// macOS dedicated process identity plus Seatbelt policy enforcement.
    MacOsDedicatedIdentitySeatbelt,
    /// Linux Bubblewrap namespaces plus Landlock, seccomp, and cgroup-v2.
    LinuxBubblewrapLandlockSeccompCgroupV2,
}

/// Exact lifecycle identities reserved by launch authority. Presence in this
/// set is not evidence that any later stage occurred: only the authoritative
/// ledger can consume a reservation into a durable event or source row.
#[allow(
    missing_docs,
    reason = "fields are the closed, self-describing lifecycle reservation tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLifecycleReservationFieldsV2 {
    pub reservation_version: u32,
    pub runner_launch_id: String,
    pub runner_session_id: String,
    pub effect_id: String,
    pub capture_id: String,
    pub capture_intent_id: String,
    pub dispatch_id: String,
    pub command_request_id: String,
    pub effect_idempotency_key: String,
    pub native_launch_preparation_attempt_id: String,
    pub native_launch_journal_id: String,
    pub native_launch_cleanup_effect_id: String,
    pub native_launch_preparation_receipt_id: String,
    pub native_launch_release_receipt_id: String,
    pub native_launch_cleanup_receipt_id: String,
    pub capture_acquired_event_id: String,
    pub v13_initialized_event_id: String,
    pub command_dispatched_event_id: String,
    pub control_issued_event_id: String,
    pub control_observed_event_id: String,
    pub control_reconciled_event_id: String,
    pub terminal_event_id: String,
    pub effect_cut_event_id: String,
    pub output_custody_event_id: String,
    pub command_cleanup_event_id: String,
    pub runner_direct_child_observed_event_id: String,
    pub runner_domain_observed_event_id: String,
    pub runner_cleanup_event_id: String,
    pub evidence_closure_event_id: String,
    pub outcome_derived_event_id: String,
    pub initialization_request_id: String,
    pub initialization_receipt_id: String,
    pub control_id: String,
    pub control_reconciliation_id: String,
    pub terminal_observation_id: String,
    pub effect_cut_observation_id: String,
    pub shutdown_request_id: String,
    pub shutdown_receipt_id: String,
    pub command_accounting_domain_id: String,
    pub command_cleanup_observation_id: String,
    pub runner_accounting_domain_id: String,
    pub runner_direct_child_observer_id: String,
    pub runner_direct_child_observation_id: String,
    pub runner_domain_observer_id: String,
    pub runner_domain_observation_id: String,
    pub output_custody_closure_receipt_id: String,
    pub runner_cleanup_proof_id: String,
    pub evidence_closure_id: String,
    pub outcome_id: String,
    pub verification_receipt_id: String,
}

impl CurrentFinalVerificationLifecycleReservationFieldsV2 {
    fn identifiers(&self) -> [&str; 49] {
        [
            &self.runner_launch_id,
            &self.runner_session_id,
            &self.effect_id,
            &self.capture_id,
            &self.capture_intent_id,
            &self.dispatch_id,
            &self.command_request_id,
            &self.effect_idempotency_key,
            &self.native_launch_preparation_attempt_id,
            &self.native_launch_journal_id,
            &self.native_launch_cleanup_effect_id,
            &self.native_launch_preparation_receipt_id,
            &self.native_launch_release_receipt_id,
            &self.native_launch_cleanup_receipt_id,
            &self.capture_acquired_event_id,
            &self.v13_initialized_event_id,
            &self.command_dispatched_event_id,
            &self.control_issued_event_id,
            &self.control_observed_event_id,
            &self.control_reconciled_event_id,
            &self.terminal_event_id,
            &self.effect_cut_event_id,
            &self.output_custody_event_id,
            &self.command_cleanup_event_id,
            &self.runner_direct_child_observed_event_id,
            &self.runner_domain_observed_event_id,
            &self.runner_cleanup_event_id,
            &self.evidence_closure_event_id,
            &self.outcome_derived_event_id,
            &self.initialization_request_id,
            &self.initialization_receipt_id,
            &self.control_id,
            &self.control_reconciliation_id,
            &self.terminal_observation_id,
            &self.effect_cut_observation_id,
            &self.shutdown_request_id,
            &self.shutdown_receipt_id,
            &self.command_accounting_domain_id,
            &self.command_cleanup_observation_id,
            &self.runner_accounting_domain_id,
            &self.runner_direct_child_observer_id,
            &self.runner_direct_child_observation_id,
            &self.runner_domain_observer_id,
            &self.runner_domain_observation_id,
            &self.output_custody_closure_receipt_id,
            &self.runner_cleanup_proof_id,
            &self.evidence_closure_id,
            &self.outcome_id,
            &self.verification_receipt_id,
        ]
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed 49-identity schema stays contiguous for field-by-field audit"
    )]
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version(
            "identity_spine.frontier.lifecycle_reservations.reservation_version",
            self.reservation_version,
        )?;
        for (field, value) in [
            (
                "identity_spine.frontier.lifecycle_reservations.runner_launch_id",
                &self.runner_launch_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_session_id",
                &self.runner_session_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.effect_id",
                &self.effect_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.capture_id",
                &self.capture_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.capture_intent_id",
                &self.capture_intent_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.dispatch_id",
                &self.dispatch_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.command_request_id",
                &self.command_request_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.effect_idempotency_key",
                &self.effect_idempotency_key,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_preparation_attempt_id",
                &self.native_launch_preparation_attempt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_journal_id",
                &self.native_launch_journal_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_cleanup_effect_id",
                &self.native_launch_cleanup_effect_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_preparation_receipt_id",
                &self.native_launch_preparation_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_release_receipt_id",
                &self.native_launch_release_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.native_launch_cleanup_receipt_id",
                &self.native_launch_cleanup_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.capture_acquired_event_id",
                &self.capture_acquired_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.v13_initialized_event_id",
                &self.v13_initialized_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.command_dispatched_event_id",
                &self.command_dispatched_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.control_issued_event_id",
                &self.control_issued_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.control_observed_event_id",
                &self.control_observed_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.control_reconciled_event_id",
                &self.control_reconciled_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.terminal_event_id",
                &self.terminal_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.effect_cut_event_id",
                &self.effect_cut_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.output_custody_event_id",
                &self.output_custody_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.command_cleanup_event_id",
                &self.command_cleanup_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_direct_child_observed_event_id",
                &self.runner_direct_child_observed_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_domain_observed_event_id",
                &self.runner_domain_observed_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_cleanup_event_id",
                &self.runner_cleanup_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.evidence_closure_event_id",
                &self.evidence_closure_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.outcome_derived_event_id",
                &self.outcome_derived_event_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.initialization_request_id",
                &self.initialization_request_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.initialization_receipt_id",
                &self.initialization_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.control_id",
                &self.control_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.control_reconciliation_id",
                &self.control_reconciliation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.terminal_observation_id",
                &self.terminal_observation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.effect_cut_observation_id",
                &self.effect_cut_observation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.shutdown_request_id",
                &self.shutdown_request_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.shutdown_receipt_id",
                &self.shutdown_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.command_accounting_domain_id",
                &self.command_accounting_domain_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.command_cleanup_observation_id",
                &self.command_cleanup_observation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_accounting_domain_id",
                &self.runner_accounting_domain_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_direct_child_observer_id",
                &self.runner_direct_child_observer_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_direct_child_observation_id",
                &self.runner_direct_child_observation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_domain_observer_id",
                &self.runner_domain_observer_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_domain_observation_id",
                &self.runner_domain_observation_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.output_custody_closure_receipt_id",
                &self.output_custody_closure_receipt_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.runner_cleanup_proof_id",
                &self.runner_cleanup_proof_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.evidence_closure_id",
                &self.evidence_closure_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.outcome_id",
                &self.outcome_id,
            ),
            (
                "identity_spine.frontier.lifecycle_reservations.verification_receipt_id",
                &self.verification_receipt_id,
            ),
        ] {
            require_core_identity(field, value)?;
        }
        require_pairwise_distinct(
            "identity_spine.frontier.lifecycle_reservations.identifiers",
            &self.identifiers(),
        )?;
        require_canonical_size(
            "identity_spine.frontier.lifecycle_reservations.fields",
            self,
        )
    }
}

/// Self-digesting, canonical launch reservation set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLifecycleReservationSetV2 {
    /// Exact closed reservation fields.
    pub fields: CurrentFinalVerificationLifecycleReservationFieldsV2,
    /// Domain-separated digest of the exact reservation fields.
    pub reservation_digest: Digest,
}

impl CurrentFinalVerificationLifecycleReservationSetV2 {
    /// Constructs one validated reservation set and its canonical digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate, or oversized identities.
    pub fn new(
        fields: CurrentFinalVerificationLifecycleReservationFieldsV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        fields.validate()?;
        let reservation_digest = canonical_digest(
            "identity_spine.frontier.lifecycle_reservations.fields",
            LIFECYCLE_RESERVATION_SET_DIGEST_DOMAIN,
            &fields,
        )?;
        Ok(Self {
            fields,
            reservation_digest,
        })
    }

    /// Validates the exact reservation fields and their domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate, oversized, or digest-crossed
    /// reservations.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.fields.validate()?;
        require_digest_match(
            "identity_spine.frontier.lifecycle_reservations.reservation_digest",
            &self.reservation_digest,
            &canonical_digest(
                "identity_spine.frontier.lifecycle_reservations.fields",
                LIFECYCLE_RESERVATION_SET_DIGEST_DOMAIN,
                &self.fields,
            )?,
        )?;
        require_canonical_size("identity_spine.frontier.lifecycle_reservations", self)
    }
}

/// Exact launch-committed frontier. Later-stage identities are reservations;
/// their presence does not claim capture acquisition, initialization, or
/// dispatch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationLaunchCommittedFrontierV2 {
    /// Complete set of later lifecycle identities fixed before launch.
    pub lifecycle_reservations: CurrentFinalVerificationLifecycleReservationSetV2,
    /// Closed native containment backend fixed before launch.
    pub containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
    /// Digest of the exact supported target/runner image identity.
    pub target_identity_digest: Digest,
    /// Digest of the exact native containment policy fixed before launch.
    pub native_policy_digest: Digest,
    /// Digest of the exact launch preparation.
    pub launch_preparation_digest: Digest,
    /// Digest of the exact launch authority.
    pub launch_authority_digest: Digest,
    /// Exact admitted runner binary digest committed before launch.
    pub runner_binary_digest: Digest,
    /// Exact private-state identity digest committed before launch.
    pub private_state_digest: Digest,
    /// Digest of the exact preallocated capture intent.
    pub capture_intent_digest: Digest,
    /// Digest of the detector policy committed before capture acquisition.
    pub detector_policy_digest: Digest,
    /// Exact admitted runner protocol identity committed before launch.
    pub runner_protocol_digest: Digest,
    /// Durable launch-commit event identity.
    pub committed_event_id: String,
    /// Durable launch-commit event sequence.
    pub committed_event_sequence: u64,
}

/// Exact capture-acquired frontier, retaining its complete launch prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationCaptureAcquiredFrontierV2 {
    /// Exact launch-committed prefix.
    pub launch: Box<CurrentFinalVerificationLaunchCommittedFrontierV2>,
    /// Digest of the exact acquired capture anchor.
    pub output_capture_anchor_digest: Digest,
    /// Durable capture-acquisition event identity.
    pub acquired_event_id: String,
    /// Durable capture-acquisition event sequence.
    pub acquired_event_sequence: u64,
}

/// Exact V13-initialized frontier, retaining its complete capture prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationV13InitializedFrontierV2 {
    /// Exact capture-acquired prefix.
    pub capture: Box<CurrentFinalVerificationCaptureAcquiredFrontierV2>,
    /// Exact V13 initialization request commitment.
    pub initialization_request_commitment_digest: Digest,
    /// Exact V13 initialization receipt commitment.
    pub initialization_receipt_commitment_digest: Digest,
    /// Diagnostic digest of the schema-v32 V1 attempt payload embedded by the
    /// dormant V13 contract. It can never substitute for the spine's additive
    /// operational attempt-authority digest.
    pub v13_embedded_v32_attempt_payload_digest: Digest,
    /// Exact runner-generated V13 nonce.
    pub runner_nonce: Digest,
    /// Durable initialization event identity.
    pub initialized_event_id: String,
    /// Durable initialization event sequence.
    pub initialized_event_sequence: u64,
}

/// Exact command-dispatched frontier, retaining its complete initialization
/// prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationDispatchedFrontierV2 {
    /// Exact V13-initialized prefix.
    pub initialized: Box<CurrentFinalVerificationV13InitializedFrontierV2>,
    /// Digest of the exact canonical command request.
    pub command_request_digest: Digest,
    /// Digest of the exact V13 transport commitment.
    pub command_transport_commitment_digest: Digest,
    /// Durable dispatch event identity.
    pub dispatched_event_id: String,
    /// Durable dispatch event sequence.
    pub dispatched_event_sequence: u64,
}

/// Closed maximum lifecycle frontier claimed by one current verifier attempt.
/// This pure value is caller-manufacturable and nonauthorizing: authoritative
/// absence exists only after a future ledger atomically authenticates the
/// frontier and fences every later-stage row. Placeholder identities or empty
/// digests are never used for a later frontier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationReachedFrontierV2 {
    /// Launch committed; capture acquisition did not complete.
    LaunchCommitted {
        /// Exact reached frontier.
        frontier: Box<CurrentFinalVerificationLaunchCommittedFrontierV2>,
    },
    /// Capture acquired; V13 initialization did not complete.
    CaptureAcquired {
        /// Exact reached frontier.
        frontier: CurrentFinalVerificationCaptureAcquiredFrontierV2,
    },
    /// V13 initialized; command dispatch did not complete.
    V13Initialized {
        /// Exact reached frontier.
        frontier: CurrentFinalVerificationV13InitializedFrontierV2,
    },
    /// Exact command dispatch committed.
    Dispatched {
        /// Exact reached frontier.
        frontier: CurrentFinalVerificationDispatchedFrontierV2,
    },
}

impl CurrentFinalVerificationReachedFrontierV2 {
    #[allow(
        clippy::too_many_lines,
        reason = "the closed reached-frontier validation remains contiguous for auditability"
    )]
    fn validate_after(
        &self,
        authority_event_id: &str,
        authority_sequence: u64,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let launch = self.launch();
        launch.lifecycle_reservations.validate_integrity()?;
        require_core_identity(
            "identity_spine.frontier.committed_event_id",
            &launch.committed_event_id,
        )?;
        let mut all_ids = launch.lifecycle_reservations.fields.identifiers().to_vec();
        all_ids.push(authority_event_id);
        all_ids.push(&launch.committed_event_id);
        require_pairwise_distinct("identity_spine.frontier.all_identity_ids", &all_ids)?;
        if launch.committed_event_sequence <= authority_sequence {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "identity_spine.frontier.committed_event_sequence",
                },
            );
        }

        if let Some(capture) = self.capture() {
            require_core_identity(
                "identity_spine.frontier.acquired_event_id",
                &capture.acquired_event_id,
            )?;
            require_reservation(
                "identity_spine.frontier.acquired_event_id",
                &capture.acquired_event_id,
                &launch
                    .lifecycle_reservations
                    .fields
                    .capture_acquired_event_id,
            )?;
            if capture.acquired_event_sequence <= launch.committed_event_sequence {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                        field: "identity_spine.frontier.acquired_event_sequence",
                    },
                );
            }
        }
        if let Some(initialized) = self.initialized() {
            require_core_identity(
                "identity_spine.frontier.initialized_event_id",
                &initialized.initialized_event_id,
            )?;
            require_reservation(
                "identity_spine.frontier.initialized_event_id",
                &initialized.initialized_event_id,
                &launch
                    .lifecycle_reservations
                    .fields
                    .v13_initialized_event_id,
            )?;
            if initialized.initialized_event_sequence <= initialized.capture.acquired_event_sequence
            {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                        field: "identity_spine.frontier.initialized_event_sequence",
                    },
                );
            }
        }
        if let Some(dispatched) = self.dispatched() {
            require_core_identity(
                "identity_spine.frontier.dispatched_event_id",
                &dispatched.dispatched_event_id,
            )?;
            require_reservation(
                "identity_spine.frontier.dispatched_event_id",
                &dispatched.dispatched_event_id,
                &launch
                    .lifecycle_reservations
                    .fields
                    .command_dispatched_event_id,
            )?;
            if dispatched.dispatched_event_sequence
                <= dispatched.initialized.initialized_event_sequence
            {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                        field: "identity_spine.frontier.dispatched_event_sequence",
                    },
                );
            }
        }
        Ok(())
    }

    fn launch(&self) -> &CurrentFinalVerificationLaunchCommittedFrontierV2 {
        match self {
            Self::LaunchCommitted { frontier } => frontier,
            Self::CaptureAcquired { frontier } => &frontier.launch,
            Self::V13Initialized { frontier } => &frontier.capture.launch,
            Self::Dispatched { frontier } => &frontier.initialized.capture.launch,
        }
    }

    fn capture(&self) -> Option<&CurrentFinalVerificationCaptureAcquiredFrontierV2> {
        match self {
            Self::LaunchCommitted { .. } => None,
            Self::CaptureAcquired { frontier } => Some(frontier),
            Self::V13Initialized { frontier } => Some(&frontier.capture),
            Self::Dispatched { frontier } => Some(&frontier.initialized.capture),
        }
    }

    fn initialized(&self) -> Option<&CurrentFinalVerificationV13InitializedFrontierV2> {
        match self {
            Self::LaunchCommitted { .. } | Self::CaptureAcquired { .. } => None,
            Self::V13Initialized { frontier } => Some(frontier),
            Self::Dispatched { frontier } => Some(&frontier.initialized),
        }
    }

    fn dispatched(&self) -> Option<&CurrentFinalVerificationDispatchedFrontierV2> {
        match self {
            Self::Dispatched { frontier } => Some(frontier),
            Self::LaunchCommitted { .. }
            | Self::CaptureAcquired { .. }
            | Self::V13Initialized { .. } => None,
        }
    }

    const fn reached_event_sequence(&self) -> u64 {
        match self {
            Self::LaunchCommitted { frontier } => frontier.committed_event_sequence,
            Self::CaptureAcquired { frontier } => frontier.acquired_event_sequence,
            Self::V13Initialized { frontier } => frontier.initialized_event_sequence,
            Self::Dispatched { frontier } => frontier.dispatched_event_sequence,
        }
    }
}

/// All non-derived identity fields shared by every current evidence source.
#[allow(
    missing_docs,
    reason = "fields form one exact identity tuple and are named by their owning contracts"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationIdentitySpineFieldsV2 {
    pub spine_version: u32,
    pub sprint_id: String,
    pub task_graph_id: String,
    pub attempt_id: String,
    pub admission_id: String,
    pub sprint_spec_digest: Digest,
    pub task_graph_digest: Digest,
    pub task_graph_payload_digest: Digest,
    pub repair_slot_reserve_digest: Digest,
    /// Digest of the additive operational attempt authority; the schema-v32
    /// ordinal-as-event record is never accepted here.
    pub operational_attempt_authority_digest: Digest,
    pub complete_task_done_set_digest: Digest,
    pub complete_criterion_evidence_set_digest: Digest,
    pub workspace_grant_hash: Digest,
    pub input_snapshot_digest: Digest,
    pub execution_policy_digest: Digest,
    pub verification_command_digest: Digest,
    pub authority_admitted_event_id: String,
    /// Future operational durable event sequence; never a schema-v32 attempt ordinal.
    pub authority_admitted_event_sequence: u64,
    pub reached_frontier: CurrentFinalVerificationReachedFrontierV2,
}

impl CurrentFinalVerificationIdentitySpineFieldsV2 {
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("identity_spine.spine_version", self.spine_version)?;
        for (field, value) in [
            ("identity_spine.sprint_id", self.sprint_id.as_str()),
            ("identity_spine.task_graph_id", self.task_graph_id.as_str()),
            ("identity_spine.attempt_id", self.attempt_id.as_str()),
            ("identity_spine.admission_id", self.admission_id.as_str()),
        ] {
            require_identifier(field, value)?;
        }
        require_core_identity(
            "identity_spine.authority_admitted_event_id",
            &self.authority_admitted_event_id,
        )?;
        if self.authority_admitted_event_sequence == 0 {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "identity_spine.authority_admitted_event_sequence",
                },
            );
        }
        self.reached_frontier.validate_after(
            &self.authority_admitted_event_id,
            self.authority_admitted_event_sequence,
        )?;
        require_canonical_size("identity_spine.fields", self)
    }
}

/// Complete, self-digesting current identity spine shared byte-for-byte by all
/// final-verification evidence sources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationIdentitySpineV2 {
    /// Exact identity fields.
    pub fields: CurrentFinalVerificationIdentitySpineFieldsV2,
    /// Domain-separated digest of the exact fields.
    pub spine_digest: Digest,
}

impl CurrentFinalVerificationIdentitySpineV2 {
    /// Constructs and validates one complete identity spine.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity fields or oversized canonical
    /// bytes.
    pub fn new(
        fields: CurrentFinalVerificationIdentitySpineFieldsV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        fields.validate()?;
        let spine_digest = canonical_digest(
            "identity_spine.fields",
            IDENTITY_SPINE_DIGEST_DOMAIN,
            &fields,
        )?;
        Ok(Self {
            fields,
            spine_digest,
        })
    }

    /// Validates exact fields and the domain-separated spine digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, size overflow, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.fields.validate()?;
        let computed = canonical_digest(
            "identity_spine.fields",
            IDENTITY_SPINE_DIGEST_DOMAIN,
            &self.fields,
        )?;
        if computed != self.spine_digest {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch {
                    field: "identity_spine.spine_digest",
                },
            );
        }
        require_canonical_size("identity_spine", self)
    }
}

/// Authenticated coordinator control action.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationControlActionKindV2 {
    /// Pause the current sprint.
    Pause,
    /// Interrupt for authenticated steering.
    SteeringInterruption,
    /// Explicitly cancel the sprint.
    Cancel,
}

/// One authenticated control observation. Event sequences, rather than a
/// caller-authored `before_effect` Boolean, determine its relation to effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCurrentFinalVerificationControlActionV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Core/coordinator-issued control identity.
    pub control_id: String,
    /// Closed authenticated action.
    pub action: CurrentFinalVerificationControlActionKindV2,
    /// Durable coordinator event identity.
    pub issued_event_id: String,
    /// Sequence of the coordinator issue event.
    pub issued_event_sequence: u64,
    /// Independent runner/service observation event identity.
    pub observed_event_id: String,
    /// Sequence at which the action was observed.
    pub observed_event_sequence: u64,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}

impl AuthenticatedCurrentFinalVerificationControlActionV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities or impossible local ordering.
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        control_id: impl Into<String>,
        action: CurrentFinalVerificationControlActionKindV2,
        issued_event_id: impl Into<String>,
        issued_event_sequence: u64,
        observed_event_id: impl Into<String>,
        observed_event_sequence: u64,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            control_id: control_id.into(),
            action,
            issued_event_id: issued_event_id.into(),
            issued_event_sequence,
            observed_event_id: observed_event_id.into(),
            observed_event_sequence,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("control_action.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        for (field, value) in [
            ("control_action.control_id", self.control_id.as_str()),
            (
                "control_action.issued_event_id",
                self.issued_event_id.as_str(),
            ),
            (
                "control_action.observed_event_id",
                self.observed_event_id.as_str(),
            ),
        ] {
            require_core_identity(field, value)?;
        }
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "control_action.control_id",
            &self.control_id,
            &reservations.control_id,
        )?;
        require_reservation(
            "control_action.issued_event_id",
            &self.issued_event_id,
            &reservations.control_issued_event_id,
        )?;
        require_reservation(
            "control_action.observed_event_id",
            &self.observed_event_id,
            &reservations.control_observed_event_id,
        )?;
        if self.control_id == self.issued_event_id
            || self.control_id == self.observed_event_id
            || self.issued_event_id == self.observed_event_id
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::NonCanonicalControls,
            );
        }
        let mut prior_event_ids = vec![
            self.identity_spine
                .fields
                .authority_admitted_event_id
                .as_str(),
        ];
        let mut prior_event_sequences =
            vec![self.identity_spine.fields.authority_admitted_event_sequence];
        append_frontier_events(
            &self.identity_spine.fields.reached_frontier,
            &mut prior_event_ids,
            &mut prior_event_sequences,
        );
        if prior_event_ids.contains(&self.control_id.as_str())
            || prior_event_ids.contains(&self.issued_event_id.as_str())
            || prior_event_ids.contains(&self.observed_event_id.as_str())
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::NonCanonicalControls,
            );
        }
        if self.issued_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
            || prior_event_sequences.contains(&self.issued_event_sequence)
            || prior_event_sequences.contains(&self.observed_event_sequence)
            || self.observed_event_sequence <= self.issued_event_sequence
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "control_action.event_sequence",
                },
            );
        }
        require_canonical_size("control_action", &self.digest_preimage())
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "control_action",
            CONTROL_ACTION_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact control source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        if self.source_digest != self.computed_source_digest()? {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch {
                    field: "control_action.source_digest",
                },
            );
        }
        Ok(())
    }

    fn digest_preimage(&self) -> ControlActionDigestPreimageV2<'_> {
        ControlActionDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            control_id: &self.control_id,
            action: self.action,
            issued_event_id: &self.issued_event_id,
            issued_event_sequence: self.issued_event_sequence,
            observed_event_id: &self.observed_event_id,
            observed_event_sequence: self.observed_event_sequence,
        }
    }
}

#[derive(Serialize)]
struct ControlActionDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    control_id: &'a str,
    action: CurrentFinalVerificationControlActionKindV2,
    issued_event_id: &'a str,
    issued_event_sequence: u64,
    observed_event_id: &'a str,
    observed_event_sequence: u64,
}

/// Closed control-domain source for a raw canceled terminal. Absence means
/// reconciliation is still unfinished; explicit unmatched reconciliation is
/// positive `Unknown` evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationControlResolutionSourceV2 {
    /// Exact authenticated control action matching the canceled terminal.
    Authenticated {
        /// Self-digesting authenticated control source.
        source: Box<AuthenticatedCurrentFinalVerificationControlActionV2>,
    },
    /// A bounded event-stream reconciliation proved no authenticated match.
    UnmatchedAfterReconciliation {
        /// Source contract version.
        source_version: u32,
        /// Exact common identity spine.
        identity_spine: Box<CurrentFinalVerificationIdentitySpineV2>,
        /// Control identity claimed by the raw canceled terminal.
        claimed_control_id: String,
        /// Exact reconciliation identity.
        reconciliation_id: String,
        /// Digest of the exact reconciliation receipt.
        reconciliation_receipt_digest: Digest,
        /// Digest of the exact event-stream head examined.
        event_stream_head_digest: Digest,
        /// Highest durable event sequence included in reconciliation.
        reconciled_through_event_sequence: u64,
        /// Durable reconciliation event identity.
        reconciled_event_id: String,
        /// Durable reconciliation event sequence.
        reconciled_event_sequence: u64,
        /// Domain-separated digest of every preceding variant field.
        source_digest: Digest,
    },
}

impl CurrentFinalVerificationControlResolutionSourceV2 {
    /// Constructs explicit bounded evidence that no matching authenticated
    /// control was present through one durable event-stream head.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, order, or canonical size.
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the exact reconciliation tuple"
    )]
    pub fn unmatched_after_reconciliation(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        claimed_control_id: impl Into<String>,
        reconciliation_id: impl Into<String>,
        reconciliation_receipt_digest: Digest,
        event_stream_head_digest: Digest,
        reconciled_through_event_sequence: u64,
        reconciled_event_id: impl Into<String>,
        reconciled_event_sequence: u64,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self::UnmatchedAfterReconciliation {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine: Box::new(identity_spine),
            claimed_control_id: claimed_control_id.into(),
            reconciliation_id: reconciliation_id.into(),
            reconciliation_receipt_digest,
            event_stream_head_digest,
            reconciled_through_event_sequence,
            reconciled_event_id: reconciled_event_id.into(),
            reconciled_event_sequence,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        let digest = source.computed_source_digest()?;
        let Self::UnmatchedAfterReconciliation { source_digest, .. } = &mut source else {
            unreachable!("constructor fixes unmatched variant");
        };
        *source_digest = digest;
        Ok(source)
    }

    /// Validates the exact control-resolution source and integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed source fields or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        match self {
            Self::Authenticated { source } => source.validate_integrity(),
            Self::UnmatchedAfterReconciliation { source_digest, .. } => require_digest_match(
                "control_resolution.source_digest",
                source_digest,
                &self.computed_source_digest()?,
            ),
        }
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        match self {
            Self::Authenticated { source } => source.validate_integrity(),
            Self::UnmatchedAfterReconciliation {
                source_version,
                identity_spine,
                claimed_control_id,
                reconciliation_id,
                reconciled_through_event_sequence,
                reconciled_event_id,
                reconciled_event_sequence,
                ..
            } => {
                require_version("control_resolution.source_version", *source_version)?;
                identity_spine.validate_integrity()?;
                for (field, value) in [
                    (
                        "control_resolution.claimed_control_id",
                        claimed_control_id.as_str(),
                    ),
                    (
                        "control_resolution.reconciliation_id",
                        reconciliation_id.as_str(),
                    ),
                    (
                        "control_resolution.reconciled_event_id",
                        reconciled_event_id.as_str(),
                    ),
                ] {
                    require_core_identity(field, value)?;
                }
                let reservations = lifecycle_reservations(identity_spine);
                require_reservation(
                    "control_resolution.claimed_control_id",
                    claimed_control_id,
                    &reservations.control_id,
                )?;
                require_reservation(
                    "control_resolution.reconciliation_id",
                    reconciliation_id,
                    &reservations.control_reconciliation_id,
                )?;
                require_reservation(
                    "control_resolution.reconciled_event_id",
                    reconciled_event_id,
                    &reservations.control_reconciled_event_id,
                )?;
                if *reconciled_through_event_sequence
                    <= identity_spine
                        .fields
                        .reached_frontier
                        .reached_event_sequence()
                    || *reconciled_event_sequence <= *reconciled_through_event_sequence
                {
                    return Err(
                        NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                            field: "control_resolution.reconciled_event_sequence",
                        },
                    );
                }
                if claimed_control_id == reconciliation_id
                    || claimed_control_id == reconciled_event_id
                    || reconciliation_id == reconciled_event_id
                {
                    return Err(
                        NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::NonCanonicalControls,
                    );
                }
                require_canonical_size("control_resolution", &self.digest_preimage())
            }
        }
    }

    fn identity_spine(&self) -> &CurrentFinalVerificationIdentitySpineV2 {
        match self {
            Self::Authenticated { source } => &source.identity_spine,
            Self::UnmatchedAfterReconciliation { identity_spine, .. } => identity_spine,
        }
    }

    fn source_digest(&self) -> &Digest {
        match self {
            Self::Authenticated { source } => &source.source_digest,
            Self::UnmatchedAfterReconciliation { source_digest, .. } => source_digest,
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "control_resolution",
            CONTROL_RECONCILIATION_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    fn digest_preimage(&self) -> ControlReconciliationDigestPreimageV2<'_> {
        match self {
            Self::UnmatchedAfterReconciliation {
                source_version,
                identity_spine,
                claimed_control_id,
                reconciliation_id,
                reconciliation_receipt_digest,
                event_stream_head_digest,
                reconciled_through_event_sequence,
                reconciled_event_id,
                reconciled_event_sequence,
                ..
            } => ControlReconciliationDigestPreimageV2 {
                source_version: *source_version,
                identity_spine,
                claimed_control_id,
                reconciliation_id,
                reconciliation_receipt_digest,
                event_stream_head_digest,
                reconciled_through_event_sequence: *reconciled_through_event_sequence,
                reconciled_event_id,
                reconciled_event_sequence: *reconciled_event_sequence,
            },
            Self::Authenticated { .. } => {
                unreachable!("authenticated variant owns its nested source digest")
            }
        }
    }
}

#[derive(Serialize)]
struct ControlReconciliationDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    claimed_control_id: &'a str,
    reconciliation_id: &'a str,
    reconciliation_receipt_digest: &'a Digest,
    event_stream_head_digest: &'a Digest,
    reconciled_through_event_sequence: u64,
    reconciled_event_id: &'a str,
    reconciled_event_sequence: u64,
}

/// Exact raw runner terminal observation. It is not a verification claim.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed terminal tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationTerminalObservationV2 {
    Exited {
        exit_code: u8,
    },
    Signaled {
        signal: u8,
        core_dumped: bool,
    },
    TimedOut,
    OutputLimitExceeded {
        limit_bytes: u64,
        observed_at_least_bytes: u64,
    },
    RunnerCanceled {
        claimed_control_id: String,
    },
    ProvenNoEffect {
        proof_id: String,
        proof_digest: Digest,
    },
    Unknown {
        reconciliation_id: String,
        evidence_digest: Digest,
    },
}

impl CurrentFinalVerificationTerminalObservationV2 {
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        match self {
            Self::Signaled { signal, .. } if !(1..=127).contains(signal) => Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "terminal_source.observation.signal",
                },
            ),
            Self::OutputLimitExceeded {
                limit_bytes,
                observed_at_least_bytes,
            } if *limit_bytes == 0 || observed_at_least_bytes < limit_bytes => Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "terminal_source.observation.output_limit",
                },
            ),
            Self::RunnerCanceled { claimed_control_id } => require_identifier(
                "terminal_source.observation.claimed_control_id",
                claimed_control_id,
            ),
            Self::ProvenNoEffect { proof_id, .. } => {
                require_identifier("terminal_source.observation.proof_id", proof_id)
            }
            Self::Unknown {
                reconciliation_id, ..
            } => require_identifier(
                "terminal_source.observation.reconciliation_id",
                reconciliation_id,
            ),
            _ => Ok(()),
        }
    }

    fn embedded_observation_identity(&self) -> Option<&str> {
        match self {
            Self::ProvenNoEffect { proof_id, .. } => Some(proof_id),
            Self::Unknown {
                reconciliation_id, ..
            } => Some(reconciliation_id),
            Self::Exited { .. }
            | Self::Signaled { .. }
            | Self::TimedOut
            | Self::OutputLimitExceeded { .. }
            | Self::RunnerCanceled { .. } => None,
        }
    }
}

/// Self-digesting terminal source for one exact current identity spine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationTerminalSourceV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Exact terminal observation identity reserved at launch.
    pub terminal_observation_id: String,
    /// Durable terminal event identity.
    pub terminal_event_id: String,
    /// Durable terminal event sequence.
    pub terminal_event_sequence: u64,
    /// Closed raw runner observation.
    pub observation: CurrentFinalVerificationTerminalObservationV2,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}

impl CurrentFinalVerificationTerminalSourceV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed terminal evidence.
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        terminal_observation_id: impl Into<String>,
        terminal_event_id: impl Into<String>,
        terminal_event_sequence: u64,
        observation: CurrentFinalVerificationTerminalObservationV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            terminal_observation_id: terminal_observation_id.into(),
            terminal_event_id: terminal_event_id.into(),
            terminal_event_sequence,
            observation,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("terminal_source.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity(
            "terminal_source.terminal_observation_id",
            &self.terminal_observation_id,
        )?;
        require_core_identity("terminal_source.terminal_event_id", &self.terminal_event_id)?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "terminal_source.terminal_observation_id",
            &self.terminal_observation_id,
            &reservations.terminal_observation_id,
        )?;
        require_reservation(
            "terminal_source.terminal_event_id",
            &self.terminal_event_id,
            &reservations.terminal_event_id,
        )?;
        if self.terminal_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "terminal_source.terminal_event_sequence",
                },
            );
        }
        self.observation.validate()?;
        if let Some(identity) = self.observation.embedded_observation_identity() {
            require_reservation(
                "terminal_source.observation.identity",
                identity,
                &self.terminal_observation_id,
            )?;
        }
        if let CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
            claimed_control_id,
        } = &self.observation
        {
            require_reservation(
                "terminal_source.observation.claimed_control_id",
                claimed_control_id,
                &reservations.control_id,
            )?;
        }
        require_canonical_size("terminal_source", &self.digest_preimage())
    }

    fn digest_preimage(&self) -> TerminalSourceDigestPreimageV2<'_> {
        TerminalSourceDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            terminal_observation_id: &self.terminal_observation_id,
            terminal_event_id: &self.terminal_event_id,
            terminal_event_sequence: self.terminal_event_sequence,
            observation: &self.observation,
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "terminal_source",
            TERMINAL_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact terminal source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        require_digest_match(
            "terminal_source.source_digest",
            &self.source_digest,
            &self.computed_source_digest()?,
        )
    }
}

#[derive(Serialize)]
struct TerminalSourceDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    terminal_observation_id: &'a str,
    terminal_event_id: &'a str,
    terminal_event_sequence: u64,
    observation: &'a CurrentFinalVerificationTerminalObservationV2,
}

/// Closed, independently recorded effect cut.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed effect-cut tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationEffectCutObservationV2 {
    ProvenNoEffect {
        proof_id: String,
        proof_digest: Digest,
    },
    EffectStarted {
        start_observation_id: String,
    },
    Unknown {
        reconciliation_id: String,
        evidence_digest: Digest,
    },
}

impl CurrentFinalVerificationEffectCutObservationV2 {
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let (field, identity) = match self {
            Self::ProvenNoEffect { proof_id, .. } => ("effect_cut.observation.proof_id", proof_id),
            Self::EffectStarted {
                start_observation_id,
            } => (
                "effect_cut.observation.start_observation_id",
                start_observation_id,
            ),
            Self::Unknown {
                reconciliation_id, ..
            } => (
                "effect_cut.observation.reconciliation_id",
                reconciliation_id,
            ),
        };
        require_identifier(field, identity)
    }

    fn observation_identity(&self) -> &str {
        match self {
            Self::ProvenNoEffect { proof_id, .. } => proof_id,
            Self::EffectStarted {
                start_observation_id,
            } => start_observation_id,
            Self::Unknown {
                reconciliation_id, ..
            } => reconciliation_id,
        }
    }
}

/// Self-digesting effect-cut source for one exact current identity spine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationEffectCutSourceV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Exact effect-cut observation identity reserved at launch.
    pub effect_cut_observation_id: String,
    /// Event identity at which effect state became exact.
    pub effect_cut_event_id: String,
    /// Event sequence at which effect state became exact.
    pub effect_cut_event_sequence: u64,
    /// Closed effect-cut observation.
    pub observation: CurrentFinalVerificationEffectCutObservationV2,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}

impl CurrentFinalVerificationEffectCutSourceV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed effect-cut evidence.
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        effect_cut_observation_id: impl Into<String>,
        effect_cut_event_id: impl Into<String>,
        effect_cut_event_sequence: u64,
        observation: CurrentFinalVerificationEffectCutObservationV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            effect_cut_observation_id: effect_cut_observation_id.into(),
            effect_cut_event_id: effect_cut_event_id.into(),
            effect_cut_event_sequence,
            observation,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("effect_cut.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity(
            "effect_cut.effect_cut_observation_id",
            &self.effect_cut_observation_id,
        )?;
        require_core_identity("effect_cut.effect_cut_event_id", &self.effect_cut_event_id)?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "effect_cut.effect_cut_observation_id",
            &self.effect_cut_observation_id,
            &reservations.effect_cut_observation_id,
        )?;
        require_reservation(
            "effect_cut.effect_cut_event_id",
            &self.effect_cut_event_id,
            &reservations.effect_cut_event_id,
        )?;
        if self.effect_cut_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "effect_cut.effect_cut_event_sequence",
                },
            );
        }
        self.observation.validate()?;
        require_reservation(
            "effect_cut.observation.identity",
            self.observation.observation_identity(),
            &self.effect_cut_observation_id,
        )?;
        require_canonical_size("effect_cut", &self.digest_preimage())
    }

    fn digest_preimage(&self) -> EffectCutSourceDigestPreimageV2<'_> {
        EffectCutSourceDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            effect_cut_observation_id: &self.effect_cut_observation_id,
            effect_cut_event_id: &self.effect_cut_event_id,
            effect_cut_event_sequence: self.effect_cut_event_sequence,
            observation: &self.observation,
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "effect_cut",
            EFFECT_CUT_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact effect-cut source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        require_digest_match(
            "effect_cut.source_digest",
            &self.source_digest,
            &self.computed_source_digest()?,
        )
    }
}

#[derive(Serialize)]
struct EffectCutSourceDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    effect_cut_observation_id: &'a str,
    effect_cut_event_id: &'a str,
    effect_cut_event_sequence: u64,
    observation: &'a CurrentFinalVerificationEffectCutObservationV2,
}

/// Closed current pre-effect abandonment reason for an already acquired
/// capture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationPreEffectAbandonmentReasonV2 {
    /// Initialization or dispatch failed before the command effect.
    FailedBeforeEffect,
    /// Authenticated control canceled capture before the command effect.
    CanceledBeforeEffect,
}

/// Closed output-custody source. Clean publication, non-sensitive pre-effect
/// abandonment, and exact sensitive abandonment are distinct variants.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed custody tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentFinalVerificationOutputCustodyObservationV2 {
    PublishedClean {
        publication_receipt_id: String,
        publication_receipt_digest: Digest,
        output_artifact_set_digest: Digest,
        stdout_artifact_digest: Digest,
        stderr_artifact_digest: Digest,
    },
    AbandonedSensitive {
        rejection_closure_id: String,
        rejection_closure_digest: Digest,
        neutralization_receipt_digest: Digest,
    },
    AbandonedBeforeEffect {
        abandonment_receipt_id: String,
        abandonment_receipt_digest: Digest,
        neutralization_receipt_digest: Digest,
        reason: CurrentFinalVerificationPreEffectAbandonmentReasonV2,
    },
    ClosedBeforeCapture {
        closure_receipt_id: String,
        closure_receipt_digest: Digest,
    },
    Unknown {
        reconciliation_id: String,
        evidence_digest: Digest,
    },
}

impl CurrentFinalVerificationOutputCustodyObservationV2 {
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let (field, identity) = match self {
            Self::PublishedClean {
                publication_receipt_id,
                ..
            } => (
                "output_custody.observation.publication_receipt_id",
                publication_receipt_id,
            ),
            Self::AbandonedSensitive {
                rejection_closure_id,
                ..
            } => (
                "output_custody.observation.rejection_closure_id",
                rejection_closure_id,
            ),
            Self::AbandonedBeforeEffect {
                abandonment_receipt_id,
                ..
            } => (
                "output_custody.observation.abandonment_receipt_id",
                abandonment_receipt_id,
            ),
            Self::ClosedBeforeCapture {
                closure_receipt_id, ..
            } => (
                "output_custody.observation.closure_receipt_id",
                closure_receipt_id,
            ),
            Self::Unknown {
                reconciliation_id, ..
            } => (
                "output_custody.observation.reconciliation_id",
                reconciliation_id,
            ),
        };
        require_identifier(field, identity)
    }

    fn closure_identity(&self) -> &str {
        match self {
            Self::PublishedClean {
                publication_receipt_id,
                ..
            } => publication_receipt_id,
            Self::AbandonedSensitive {
                rejection_closure_id,
                ..
            } => rejection_closure_id,
            Self::AbandonedBeforeEffect {
                abandonment_receipt_id,
                ..
            } => abandonment_receipt_id,
            Self::ClosedBeforeCapture {
                closure_receipt_id, ..
            } => closure_receipt_id,
            Self::Unknown {
                reconciliation_id, ..
            } => reconciliation_id,
        }
    }
}

/// Self-digesting output-custody source for one exact current identity spine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentFinalVerificationOutputCustodySourceV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Event identity at which custody became terminal.
    pub custody_event_id: String,
    /// Event sequence at which custody became terminal.
    pub custody_event_sequence: u64,
    /// Closed custody observation.
    pub observation: CurrentFinalVerificationOutputCustodyObservationV2,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}

impl CurrentFinalVerificationOutputCustodySourceV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed custody evidence.
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        custody_event_id: impl Into<String>,
        custody_event_sequence: u64,
        observation: CurrentFinalVerificationOutputCustodyObservationV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            custody_event_id: custody_event_id.into(),
            custody_event_sequence,
            observation,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("output_custody.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity("output_custody.custody_event_id", &self.custody_event_id)?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "output_custody.custody_event_id",
            &self.custody_event_id,
            &reservations.output_custody_event_id,
        )?;
        if self.custody_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "output_custody.custody_event_sequence",
                },
            );
        }
        self.observation.validate()?;
        require_reservation(
            "output_custody.observation.closure_identity",
            self.observation.closure_identity(),
            &reservations.output_custody_closure_receipt_id,
        )?;
        require_canonical_size("output_custody", &self.digest_preimage())
    }

    fn digest_preimage(&self) -> OutputCustodySourceDigestPreimageV2<'_> {
        OutputCustodySourceDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            custody_event_id: &self.custody_event_id,
            custody_event_sequence: self.custody_event_sequence,
            observation: &self.observation,
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "output_custody",
            OUTPUT_CUSTODY_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact custody source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        require_digest_match(
            "output_custody.source_digest",
            &self.source_digest,
            &self.computed_source_digest()?,
        )
    }
}

#[derive(Serialize)]
struct OutputCustodySourceDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    custody_event_id: &'a str,
    custody_event_sequence: u64,
    observation: &'a CurrentFinalVerificationOutputCustodyObservationV2,
}

/// Current native command accounting backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentCommandDomainBackendV2 {
    /// macOS dedicated identity and kernel/guest accounting.
    MacOsDedicatedIdentity,
    /// Linux delegated cgroup-v2 accounting.
    LinuxCgroupV2,
}

/// Closed command-domain cleanup observation.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed command-domain tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentCommandDomainCleanupObservationV2 {
    ReapedEmpty {
        observed_processes: u32,
        platform_proof_digest: Digest,
    },
    NoDomainCreatedBeforeEffect {
        observed_processes: u32,
        platform_proof_digest: Digest,
    },
    SurvivorsPresent {
        observed_processes: u32,
        evidence_digest: Digest,
    },
    Unknown {
        reconciliation_id: String,
        evidence_digest: Digest,
    },
}

impl CurrentCommandDomainCleanupObservationV2 {
    fn validate(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        match self {
            Self::ReapedEmpty {
                observed_processes, ..
            }
            | Self::NoDomainCreatedBeforeEffect {
                observed_processes, ..
            } if *observed_processes != 0 => Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "command_domain_cleanup.observation.observed_processes",
                },
            ),
            Self::SurvivorsPresent {
                observed_processes, ..
            } if *observed_processes == 0 => Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "command_domain_cleanup.observation.observed_processes",
                },
            ),
            Self::Unknown {
                reconciliation_id, ..
            } => require_identifier(
                "command_domain_cleanup.observation.reconciliation_id",
                reconciliation_id,
            ),
            _ => Ok(()),
        }
    }

    const fn is_clean(&self) -> bool {
        matches!(
            self,
            Self::ReapedEmpty { .. } | Self::NoDomainCreatedBeforeEffect { .. }
        )
    }

    fn embedded_observation_identity(&self) -> Option<&str> {
        match self {
            Self::Unknown {
                reconciliation_id, ..
            } => Some(reconciliation_id),
            Self::ReapedEmpty { .. }
            | Self::NoDomainCreatedBeforeEffect { .. }
            | Self::SurvivorsPresent { .. } => None,
        }
    }
}

/// Self-digesting current command-domain cleanup source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentCommandDomainCleanupSourceV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Closed native backend.
    pub backend: CurrentCommandDomainBackendV2,
    /// Exact command accounting-domain identity reserved at launch.
    pub command_accounting_domain_id: String,
    /// Independent cleanup observation identity.
    pub cleanup_observation_id: String,
    /// Durable command-cleanup event identity.
    pub cleanup_event_id: String,
    /// Event sequence at which the domain state was read back.
    pub cleanup_event_sequence: u64,
    /// Closed cleanup observation.
    pub observation: CurrentCommandDomainCleanupObservationV2,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}

impl CurrentCommandDomainCleanupSourceV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed cleanup evidence.
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        backend: CurrentCommandDomainBackendV2,
        command_accounting_domain_id: impl Into<String>,
        cleanup_observation_id: impl Into<String>,
        cleanup_event_id: impl Into<String>,
        cleanup_event_sequence: u64,
        observation: CurrentCommandDomainCleanupObservationV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            backend,
            command_accounting_domain_id: command_accounting_domain_id.into(),
            cleanup_observation_id: cleanup_observation_id.into(),
            cleanup_event_id: cleanup_event_id.into(),
            cleanup_event_sequence,
            observation,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("command_domain_cleanup.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity(
            "command_domain_cleanup.command_accounting_domain_id",
            &self.command_accounting_domain_id,
        )?;
        require_core_identity(
            "command_domain_cleanup.cleanup_observation_id",
            &self.cleanup_observation_id,
        )?;
        require_core_identity(
            "command_domain_cleanup.cleanup_event_id",
            &self.cleanup_event_id,
        )?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        if !command_backend_matches_containment(
            self.backend,
            self.identity_spine
                .fields
                .reached_frontier
                .launch()
                .containment_backend,
        ) {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "command_domain_cleanup.backend",
                },
            );
        }
        require_reservation(
            "command_domain_cleanup.command_accounting_domain_id",
            &self.command_accounting_domain_id,
            &reservations.command_accounting_domain_id,
        )?;
        require_reservation(
            "command_domain_cleanup.cleanup_observation_id",
            &self.cleanup_observation_id,
            &reservations.command_cleanup_observation_id,
        )?;
        require_reservation(
            "command_domain_cleanup.cleanup_event_id",
            &self.cleanup_event_id,
            &reservations.command_cleanup_event_id,
        )?;
        if self.cleanup_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "command_domain_cleanup.cleanup_event_sequence",
                },
            );
        }
        self.observation.validate()?;
        if let Some(identity) = self.observation.embedded_observation_identity() {
            require_reservation(
                "command_domain_cleanup.observation.identity",
                identity,
                &self.cleanup_observation_id,
            )?;
        }
        require_canonical_size("command_domain_cleanup", &self.digest_preimage())
    }

    fn digest_preimage(&self) -> CommandDomainCleanupSourceDigestPreimageV2<'_> {
        CommandDomainCleanupSourceDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            backend: self.backend,
            command_accounting_domain_id: &self.command_accounting_domain_id,
            cleanup_observation_id: &self.cleanup_observation_id,
            cleanup_event_id: &self.cleanup_event_id,
            cleanup_event_sequence: self.cleanup_event_sequence,
            observation: &self.observation,
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "command_domain_cleanup",
            COMMAND_DOMAIN_CLEANUP_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact command-domain source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        require_digest_match(
            "command_domain_cleanup.source_digest",
            &self.source_digest,
            &self.computed_source_digest()?,
        )
    }
}

#[derive(Serialize)]
struct CommandDomainCleanupSourceDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    backend: CurrentCommandDomainBackendV2,
    command_accounting_domain_id: &'a str,
    cleanup_observation_id: &'a str,
    cleanup_event_id: &'a str,
    cleanup_event_sequence: u64,
    observation: &'a CurrentCommandDomainCleanupObservationV2,
}

/// Independent direct-child observation for runner cleanup.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed direct-child tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentIndependentDirectChildObservationV2 {
    Reaped {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        process_id: u32,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    NotSpawned {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    StillPresent {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        process_id: u32,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    Unknown {
        observer_id: String,
        reconciliation_id: String,
        observed_event_id: String,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
}

impl CurrentIndependentDirectChildObservationV2 {
    fn validate(
        &self,
        spine: &CurrentFinalVerificationIdentitySpineV2,
        cleanup_sequence: u64,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let (observer_id, identity, event_id, sequence, process_id) = match self {
            Self::Reaped {
                observer_id,
                observation_id,
                observed_event_id,
                process_id,
                observed_event_sequence,
                ..
            }
            | Self::StillPresent {
                observer_id,
                observation_id,
                observed_event_id,
                process_id,
                observed_event_sequence,
                ..
            } => (
                observer_id,
                observation_id,
                observed_event_id,
                *observed_event_sequence,
                Some(*process_id),
            ),
            Self::NotSpawned {
                observer_id,
                observation_id,
                observed_event_id,
                observed_event_sequence,
                ..
            } => (
                observer_id,
                observation_id,
                observed_event_id,
                *observed_event_sequence,
                None,
            ),
            Self::Unknown {
                observer_id,
                reconciliation_id,
                observed_event_id,
                observed_event_sequence,
                ..
            } => (
                observer_id,
                reconciliation_id,
                observed_event_id,
                *observed_event_sequence,
                None,
            ),
        };
        let reservations = lifecycle_reservations(spine);
        require_independent_observer(
            "runner_cleanup.direct_child.observer_id",
            observer_id,
            spine,
            &reservations.runner_direct_child_observer_id,
        )?;
        require_core_identity("runner_cleanup.direct_child.observation_id", identity)?;
        require_core_identity("runner_cleanup.direct_child.observed_event_id", event_id)?;
        require_reservation(
            "runner_cleanup.direct_child.observation_id",
            identity,
            &reservations.runner_direct_child_observation_id,
        )?;
        require_reservation(
            "runner_cleanup.direct_child.observed_event_id",
            event_id,
            &reservations.runner_direct_child_observed_event_id,
        )?;
        if process_id == Some(0) {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "runner_cleanup.direct_child.process_id",
                },
            );
        }
        if sequence <= spine.fields.reached_frontier.reached_event_sequence()
            || sequence >= cleanup_sequence
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "runner_cleanup.direct_child.observed_event_sequence",
                },
            );
        }
        Ok(())
    }

    const fn is_clean(&self) -> bool {
        matches!(self, Self::Reaped { .. } | Self::NotSpawned { .. })
    }

    fn identity_event_evidence_sequence(&self) -> (&str, &str, &Digest, u64) {
        match self {
            Self::Reaped {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            }
            | Self::NotSpawned {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            }
            | Self::StillPresent {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            } => (
                observation_id,
                observed_event_id,
                evidence_digest,
                *observed_event_sequence,
            ),
            Self::Unknown {
                reconciliation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            } => (
                reconciliation_id,
                observed_event_id,
                evidence_digest,
                *observed_event_sequence,
            ),
        }
    }
}

/// Independent accounting-domain observation for runner cleanup.
#[allow(
    missing_docs,
    reason = "variant fields are the complete closed runner-domain tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CurrentIndependentRunnerDomainObservationV2 {
    Empty {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        observed_members: u32,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    NotCreated {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        observed_members: u32,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    SurvivorsPresent {
        observer_id: String,
        observation_id: String,
        observed_event_id: String,
        observed_members: u32,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
    Unknown {
        observer_id: String,
        reconciliation_id: String,
        observed_event_id: String,
        observed_event_sequence: u64,
        evidence_digest: Digest,
    },
}

impl CurrentIndependentRunnerDomainObservationV2 {
    fn validate(
        &self,
        spine: &CurrentFinalVerificationIdentitySpineV2,
        cleanup_sequence: u64,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let (observer_id, identity, event_id, members, sequence) = match self {
            Self::Empty {
                observer_id,
                observation_id,
                observed_event_id,
                observed_members,
                observed_event_sequence,
                ..
            }
            | Self::NotCreated {
                observer_id,
                observation_id,
                observed_event_id,
                observed_members,
                observed_event_sequence,
                ..
            }
            | Self::SurvivorsPresent {
                observer_id,
                observation_id,
                observed_event_id,
                observed_members,
                observed_event_sequence,
                ..
            } => (
                observer_id,
                observation_id,
                observed_event_id,
                *observed_members,
                *observed_event_sequence,
            ),
            Self::Unknown {
                observer_id,
                reconciliation_id,
                observed_event_id,
                observed_event_sequence,
                ..
            } => (
                observer_id,
                reconciliation_id,
                observed_event_id,
                0,
                *observed_event_sequence,
            ),
        };
        let reservations = lifecycle_reservations(spine);
        require_independent_observer(
            "runner_cleanup.domain.observer_id",
            observer_id,
            spine,
            &reservations.runner_domain_observer_id,
        )?;
        require_core_identity("runner_cleanup.domain.observation_id", identity)?;
        require_core_identity("runner_cleanup.domain.observed_event_id", event_id)?;
        require_reservation(
            "runner_cleanup.domain.observation_id",
            identity,
            &reservations.runner_domain_observation_id,
        )?;
        require_reservation(
            "runner_cleanup.domain.observed_event_id",
            event_id,
            &reservations.runner_domain_observed_event_id,
        )?;
        match self {
            Self::Empty { .. } | Self::NotCreated { .. } if members != 0 => {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                        field: "runner_cleanup.domain.observed_members",
                    },
                );
            }
            Self::SurvivorsPresent { .. } if members == 0 => {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                        field: "runner_cleanup.domain.observed_members",
                    },
                );
            }
            _ => {}
        }
        if sequence <= spine.fields.reached_frontier.reached_event_sequence()
            || sequence >= cleanup_sequence
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "runner_cleanup.domain.observed_event_sequence",
                },
            );
        }
        Ok(())
    }

    const fn is_clean(&self) -> bool {
        matches!(self, Self::Empty { .. } | Self::NotCreated { .. })
    }

    fn identity_event_evidence_sequence(&self) -> (&str, &str, &Digest, u64) {
        match self {
            Self::Empty {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            }
            | Self::NotCreated {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            }
            | Self::SurvivorsPresent {
                observation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            } => (
                observation_id,
                observed_event_id,
                evidence_digest,
                *observed_event_sequence,
            ),
            Self::Unknown {
                reconciliation_id,
                observed_event_id,
                evidence_digest,
                observed_event_sequence,
                ..
            } => (
                reconciliation_id,
                observed_event_id,
                evidence_digest,
                *observed_event_sequence,
            ),
        }
    }
}

/// Optional V13-style shutdown transcript readback. It never proves cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRunnerShutdownTranscriptV2 {
    /// Shutdown request identity.
    pub request_id: String,
    /// Shutdown receipt identity.
    pub receipt_id: String,
    /// Digest of the exact request.
    pub request_digest: Digest,
    /// Digest of the exact acknowledgement.
    pub receipt_digest: Digest,
    /// Event sequence of the acknowledgement.
    pub acknowledged_event_sequence: u64,
}

impl CurrentRunnerShutdownTranscriptV2 {
    fn validate(
        &self,
        spine: &CurrentFinalVerificationIdentitySpineV2,
        cleanup_sequence: u64,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_core_identity("runner_cleanup.shutdown.request_id", &self.request_id)?;
        require_core_identity("runner_cleanup.shutdown.receipt_id", &self.receipt_id)?;
        let reservations = lifecycle_reservations(spine);
        require_reservation(
            "runner_cleanup.shutdown.request_id",
            &self.request_id,
            &reservations.shutdown_request_id,
        )?;
        require_reservation(
            "runner_cleanup.shutdown.receipt_id",
            &self.receipt_id,
            &reservations.shutdown_receipt_id,
        )?;
        if self.acknowledged_event_sequence
            <= spine.fields.reached_frontier.reached_event_sequence()
            || self.acknowledged_event_sequence > cleanup_sequence
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "runner_cleanup.shutdown.acknowledged_event_sequence",
                },
            );
        }
        Ok(())
    }
}

/// Self-digesting runner cleanup source requiring independent child and domain
/// observations. The optional shutdown transcript cannot make either clean.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRunnerCleanupSourceV2 {
    /// Source contract version.
    pub source_version: u32,
    /// Exact common identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Closed native containment backend fixed by launch authority.
    pub containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
    /// Exact runner accounting-domain identity reserved at launch.
    pub runner_accounting_domain_id: String,
    /// Exact runner-cleanup proof identity.
    pub cleanup_proof_id: String,
    /// Final cleanup event identity.
    pub cleanup_event_id: String,
    /// Sequence after both independent observations.
    pub cleanup_event_sequence: u64,
    /// Independent direct-child evidence.
    pub direct_child: CurrentIndependentDirectChildObservationV2,
    /// Independent runner accounting-domain evidence.
    pub accounting_domain: CurrentIndependentRunnerDomainObservationV2,
    /// Optional protocol shutdown readback; explicit `null` is required when absent.
    #[serde(deserialize_with = "required_option")]
    pub shutdown_transcript: Option<CurrentRunnerShutdownTranscriptV2>,
    /// Domain-separated digest of every preceding field.
    pub source_digest: Digest,
}
impl CurrentRunnerCleanupSourceV2 {
    /// Constructs a source and computes its integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or non-independent observations.
    #[allow(
        clippy::too_many_arguments,
        reason = "constructor mirrors the exact cleanup tuple"
    )]
    pub fn new(
        identity_spine: CurrentFinalVerificationIdentitySpineV2,
        containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
        runner_accounting_domain_id: impl Into<String>,
        cleanup_proof_id: impl Into<String>,
        cleanup_event_id: impl Into<String>,
        cleanup_event_sequence: u64,
        direct_child: CurrentIndependentDirectChildObservationV2,
        accounting_domain: CurrentIndependentRunnerDomainObservationV2,
        shutdown_transcript: Option<CurrentRunnerShutdownTranscriptV2>,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let mut source = Self {
            source_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine,
            containment_backend,
            runner_accounting_domain_id: runner_accounting_domain_id.into(),
            cleanup_proof_id: cleanup_proof_id.into(),
            cleanup_event_id: cleanup_event_id.into(),
            cleanup_event_sequence,
            direct_child,
            accounting_domain,
            shutdown_transcript,
            source_digest: Digest::sha256(&[]),
        };
        source.validate_shape()?;
        source.source_digest = source.computed_source_digest()?;
        Ok(source)
    }

    fn validate_shape(&self) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("runner_cleanup.source_version", self.source_version)?;
        self.identity_spine.validate_integrity()?;
        if self.containment_backend
            != self
                .identity_spine
                .fields
                .reached_frontier
                .launch()
                .containment_backend
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "runner_cleanup.containment_backend",
                },
            );
        }
        require_core_identity(
            "runner_cleanup.runner_accounting_domain_id",
            &self.runner_accounting_domain_id,
        )?;
        require_core_identity("runner_cleanup.cleanup_proof_id", &self.cleanup_proof_id)?;
        require_core_identity("runner_cleanup.cleanup_event_id", &self.cleanup_event_id)?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "runner_cleanup.runner_accounting_domain_id",
            &self.runner_accounting_domain_id,
            &reservations.runner_accounting_domain_id,
        )?;
        require_reservation(
            "runner_cleanup.cleanup_proof_id",
            &self.cleanup_proof_id,
            &reservations.runner_cleanup_proof_id,
        )?;
        require_reservation(
            "runner_cleanup.cleanup_event_id",
            &self.cleanup_event_id,
            &reservations.runner_cleanup_event_id,
        )?;
        if self.cleanup_event_sequence
            <= self
                .identity_spine
                .fields
                .reached_frontier
                .reached_event_sequence()
        {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                    field: "runner_cleanup.cleanup_event_sequence",
                },
            );
        }
        self.direct_child
            .validate(&self.identity_spine, self.cleanup_event_sequence)?;
        self.accounting_domain
            .validate(&self.identity_spine, self.cleanup_event_sequence)?;
        let (direct_identity, _, direct_digest, _) =
            self.direct_child.identity_event_evidence_sequence();
        let (domain_identity, _, domain_digest, _) =
            self.accounting_domain.identity_event_evidence_sequence();
        if direct_identity == domain_identity || direct_digest == domain_digest {
            return Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "runner_cleanup.independent_observations",
                },
            );
        }
        if let Some(shutdown) = &self.shutdown_transcript {
            shutdown.validate(&self.identity_spine, self.cleanup_event_sequence)?;
        }
        require_canonical_size("runner_cleanup", &self.digest_preimage())
    }

    fn digest_preimage(&self) -> RunnerCleanupSourceDigestPreimageV2<'_> {
        RunnerCleanupSourceDigestPreimageV2 {
            source_version: self.source_version,
            identity_spine: &self.identity_spine,
            containment_backend: self.containment_backend,
            runner_accounting_domain_id: &self.runner_accounting_domain_id,
            cleanup_proof_id: &self.cleanup_proof_id,
            cleanup_event_id: &self.cleanup_event_id,
            cleanup_event_sequence: self.cleanup_event_sequence,
            direct_child: &self.direct_child,
            accounting_domain: &self.accounting_domain,
            shutdown_transcript: self.shutdown_transcript.as_ref(),
        }
    }

    fn computed_source_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "runner_cleanup",
            RUNNER_CLEANUP_SOURCE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    /// Validates the exact runner-cleanup source and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, ordering, size, or digest drift.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        self.validate_shape()?;
        require_digest_match(
            "runner_cleanup.source_digest",
            &self.source_digest,
            &self.computed_source_digest()?,
        )
    }
}

#[derive(Serialize)]
struct RunnerCleanupSourceDigestPreimageV2<'a> {
    source_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
    runner_accounting_domain_id: &'a str,
    cleanup_proof_id: &'a str,
    cleanup_event_id: &'a str,
    cleanup_event_sequence: u64,
    direct_child: &'a CurrentIndependentDirectChildObservationV2,
    accounting_domain: &'a CurrentIndependentRunnerDomainObservationV2,
    shutdown_transcript: Option<&'a CurrentRunnerShutdownTranscriptV2>,
}

/// One source that remains absent from a nonauthorizing derivation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationMissingSourceV2 {
    /// Raw terminal observation.
    Terminal,
    /// Independent effect cut.
    EffectCut,
    /// Terminal output custody.
    OutputCustody,
    /// Command-domain cleanup.
    CommandDomainCleanup,
    /// Runner cleanup.
    RunnerCleanup,
    /// Exact control resolution for a raw canceled terminal.
    ControlResolution,
}

/// Closed reason for a positive, source-backed `Unknown` classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentFinalVerificationUnknownReasonV2 {
    /// Runner terminal source explicitly reports ambiguity.
    TerminalSourceUnknown,
    /// Effect cut explicitly reports ambiguity.
    EffectCutUnknown,
    /// Output custody explicitly reports ambiguity.
    OutputCustodyUnknown,
    /// Command-domain cleanup explicitly reports ambiguity.
    CommandDomainCleanupUnknown,
    /// The command accounting domain still contains processes.
    CommandDomainSurvivorsPresent,
    /// Independent direct-child state is ambiguous.
    RunnerDirectChildUnknown,
    /// The direct child is still present.
    RunnerDirectChildPresent,
    /// Independent runner-domain state is ambiguous.
    RunnerDomainUnknown,
    /// The runner accounting domain still contains members.
    RunnerDomainSurvivorsPresent,
    /// A retained core dump contradicts the hardened execution profile.
    CoreDumpObserved,
    /// Terminal and effect-cut sources cannot both be true.
    TerminalEffectContradiction,
    /// Terminal and output-custody sources cannot both be true.
    TerminalCustodyContradiction,
    /// Cleanup and effect-cut sources cannot both be true.
    CleanupEffectContradiction,
    /// A claimed control does not match an authenticated source.
    ControlIdentityContradiction,
    /// Authenticated control and effect/terminal event order is unsafe.
    ControlEffectOrderingContradiction,
    /// Complete sources use a contradictory cross-source event order.
    SourceEventOrderingContradiction,
}

/// Complete input set for pure derivation. Every optional source field must be
/// serialized explicitly as an object or `null`; omission is rejected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingCurrentFinalVerificationEvidenceInputsV2 {
    /// Exact identity spine expected from every source.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Raw terminal source or explicit `null` while unfinished.
    #[serde(deserialize_with = "required_option")]
    pub terminal: Option<CurrentFinalVerificationTerminalSourceV2>,
    /// Effect-cut source or explicit `null` while unfinished.
    #[serde(deserialize_with = "required_option")]
    pub effect_cut: Option<CurrentFinalVerificationEffectCutSourceV2>,
    /// Output-custody source or explicit `null` while unfinished.
    #[serde(deserialize_with = "required_option")]
    pub output_custody: Option<CurrentFinalVerificationOutputCustodySourceV2>,
    /// Command-domain cleanup source or explicit `null` while unfinished.
    #[serde(deserialize_with = "required_option")]
    pub command_domain_cleanup: Option<CurrentCommandDomainCleanupSourceV2>,
    /// Runner cleanup source or explicit `null` while unfinished.
    #[serde(deserialize_with = "required_option")]
    pub runner_cleanup: Option<CurrentRunnerCleanupSourceV2>,
    /// Exact control-domain resolution for a canceled terminal, or explicit
    /// `null` when absent/not applicable.
    #[serde(deserialize_with = "required_option")]
    pub control_resolution: Option<CurrentFinalVerificationControlResolutionSourceV2>,
}

/// Complete, nonauthorizing digest join over every terminal evidence domain.
/// This type is never emitted for a partial source set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingCurrentFinalVerificationEvidenceClosureV2 {
    /// Closure contract version.
    pub closure_version: u32,
    /// Exact complete identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Exact semantic closure identity reserved at launch.
    pub evidence_closure_id: String,
    /// Reserved future ledger event identity. Its presence is not an event-
    /// existence claim; only a later ledger transaction can consume it.
    pub reserved_evidence_closure_event_id: String,
    /// Exact terminal source digest.
    pub terminal_source_digest: Digest,
    /// Exact effect-cut source digest.
    pub effect_cut_source_digest: Digest,
    /// Exact output-custody source digest.
    pub output_custody_source_digest: Digest,
    /// Exact command-domain cleanup source digest.
    pub command_domain_cleanup_source_digest: Digest,
    /// Exact runner-cleanup source digest.
    pub runner_cleanup_source_digest: Digest,
    /// Exact control-resolution source digest, explicit `null` when not applicable.
    #[serde(deserialize_with = "required_option")]
    pub control_resolution_source_digest: Option<Digest>,
    /// Domain-separated digest of every preceding field.
    pub closure_digest: Digest,
}

impl NonAuthorizingCurrentFinalVerificationEvidenceClosureV2 {
    fn new(
        inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let terminal = inputs.terminal.as_ref().expect("complete-source guard");
        let effect_cut = inputs.effect_cut.as_ref().expect("complete-source guard");
        let output_custody = inputs
            .output_custody
            .as_ref()
            .expect("complete-source guard");
        let command_domain_cleanup = inputs
            .command_domain_cleanup
            .as_ref()
            .expect("complete-source guard");
        let runner_cleanup = inputs
            .runner_cleanup
            .as_ref()
            .expect("complete-source guard");
        let reservations = lifecycle_reservations(&inputs.identity_spine);
        let mut closure = Self {
            closure_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine: inputs.identity_spine.clone(),
            evidence_closure_id: reservations.evidence_closure_id.clone(),
            reserved_evidence_closure_event_id: reservations.evidence_closure_event_id.clone(),
            terminal_source_digest: terminal.source_digest.clone(),
            effect_cut_source_digest: effect_cut.source_digest.clone(),
            output_custody_source_digest: output_custody.source_digest.clone(),
            command_domain_cleanup_source_digest: command_domain_cleanup.source_digest.clone(),
            runner_cleanup_source_digest: runner_cleanup.source_digest.clone(),
            control_resolution_source_digest: inputs
                .control_resolution
                .as_ref()
                .map(|resolution| resolution.source_digest().clone()),
            closure_digest: Digest::sha256(&[]),
        };
        closure.closure_digest = closure.computed_closure_digest()?;
        closure.validate_integrity()?;
        Ok(closure)
    }

    /// Validates the complete nonauthorizing closure's exact digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, count, version, size, or digest.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("evidence_closure.closure_version", self.closure_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity(
            "evidence_closure.evidence_closure_id",
            &self.evidence_closure_id,
        )?;
        require_core_identity(
            "evidence_closure.reserved_evidence_closure_event_id",
            &self.reserved_evidence_closure_event_id,
        )?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "evidence_closure.evidence_closure_id",
            &self.evidence_closure_id,
            &reservations.evidence_closure_id,
        )?;
        require_reservation(
            "evidence_closure.reserved_evidence_closure_event_id",
            &self.reserved_evidence_closure_event_id,
            &reservations.evidence_closure_event_id,
        )?;
        require_canonical_size("evidence_closure", &self.digest_preimage())?;
        require_digest_match(
            "evidence_closure.closure_digest",
            &self.closure_digest,
            &self.computed_closure_digest()?,
        )
    }

    fn computed_closure_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "evidence_closure",
            EVIDENCE_CLOSURE_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    fn digest_preimage(&self) -> EvidenceClosureDigestPreimageV2<'_> {
        EvidenceClosureDigestPreimageV2 {
            closure_version: self.closure_version,
            identity_spine: &self.identity_spine,
            evidence_closure_id: &self.evidence_closure_id,
            reserved_evidence_closure_event_id: &self.reserved_evidence_closure_event_id,
            terminal_source_digest: &self.terminal_source_digest,
            effect_cut_source_digest: &self.effect_cut_source_digest,
            output_custody_source_digest: &self.output_custody_source_digest,
            command_domain_cleanup_source_digest: &self.command_domain_cleanup_source_digest,
            runner_cleanup_source_digest: &self.runner_cleanup_source_digest,
            control_resolution_source_digest: self.control_resolution_source_digest.as_ref(),
        }
    }
}

#[derive(Serialize)]
struct EvidenceClosureDigestPreimageV2<'a> {
    closure_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    evidence_closure_id: &'a str,
    reserved_evidence_closure_event_id: &'a str,
    terminal_source_digest: &'a Digest,
    effect_cut_source_digest: &'a Digest,
    output_custody_source_digest: &'a Digest,
    command_domain_cleanup_source_digest: &'a Digest,
    runner_cleanup_source_digest: &'a Digest,
    control_resolution_source_digest: Option<&'a Digest>,
}

/// Closed classification derived by the pure kernel. No variant grants
/// authority until independently admitted by the ledger.
#[allow(
    missing_docs,
    reason = "variant fields are the exact closed outcome tuple"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2 {
    Verified,
    NonzeroExit {
        exit_code: u8,
    },
    Signaled {
        signal: u8,
    },
    TimedOut,
    OutputLimitExceeded,
    SensitiveOutputRejected,
    FailedBeforeEffect,
    ControlInterruptedBeforeEffect {
        control_id: String,
        action: CurrentFinalVerificationControlActionKindV2,
    },
    Canceled {
        control_id: String,
    },
    Unknown {
        reason: CurrentFinalVerificationUnknownReasonV2,
    },
}

/// Integrity-checkable, explicitly nonauthorizing derived outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonAuthorizingCurrentFinalVerificationDerivedOutcomeV2 {
    /// Outcome contract version.
    pub outcome_version: u32,
    /// Exact complete identity spine.
    pub identity_spine: CurrentFinalVerificationIdentitySpineV2,
    /// Exact semantic outcome identity reserved at launch.
    pub outcome_id: String,
    /// Reserved future ledger event identity. Its presence is not an event-
    /// existence claim; only a later ledger transaction can consume it.
    pub reserved_outcome_derived_event_id: String,
    /// Exact complete evidence-closure digest.
    pub evidence_closure_digest: Digest,
    /// Closed core-derived classification.
    pub outcome: NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2,
    /// Domain-separated digest of every preceding field.
    pub outcome_digest: Digest,
}

impl NonAuthorizingCurrentFinalVerificationDerivedOutcomeV2 {
    fn new(
        closure: &NonAuthorizingCurrentFinalVerificationEvidenceClosureV2,
        outcome: NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2,
    ) -> Result<Self, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        let reservations = lifecycle_reservations(&closure.identity_spine);
        let mut derived = Self {
            outcome_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
            identity_spine: closure.identity_spine.clone(),
            outcome_id: reservations.outcome_id.clone(),
            reserved_outcome_derived_event_id: reservations.outcome_derived_event_id.clone(),
            evidence_closure_digest: closure.closure_digest.clone(),
            outcome,
            outcome_digest: Digest::sha256(&[]),
        };
        derived.outcome_digest = derived.computed_outcome_digest()?;
        derived.validate_integrity()?;
        Ok(derived)
    }

    /// Validates the nonauthorizing outcome's exact integrity digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed fields, size, version, or digest.
    pub fn validate_integrity(
        &self,
    ) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        require_version("derived_outcome.outcome_version", self.outcome_version)?;
        self.identity_spine.validate_integrity()?;
        require_core_identity("derived_outcome.outcome_id", &self.outcome_id)?;
        require_core_identity(
            "derived_outcome.reserved_outcome_derived_event_id",
            &self.reserved_outcome_derived_event_id,
        )?;
        let reservations = lifecycle_reservations(&self.identity_spine);
        require_reservation(
            "derived_outcome.outcome_id",
            &self.outcome_id,
            &reservations.outcome_id,
        )?;
        require_reservation(
            "derived_outcome.reserved_outcome_derived_event_id",
            &self.reserved_outcome_derived_event_id,
            &reservations.outcome_derived_event_id,
        )?;
        match &self.outcome {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::NonzeroExit {
                exit_code,
            } if *exit_code == 0 => {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                        field: "derived_outcome.outcome.exit_code",
                    },
                );
            }
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Signaled { signal }
                if !(1..=127).contains(signal) =>
            {
                return Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                        field: "derived_outcome.outcome.signal",
                    },
                );
            }
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::ControlInterruptedBeforeEffect {
                control_id,
                ..
            }
            | NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Canceled {
                control_id,
            } => require_identifier("derived_outcome.outcome.control_id", control_id)?,
            _ => {}
        }
        require_canonical_size("derived_outcome", &self.digest_preimage())?;
        require_digest_match(
            "derived_outcome.outcome_digest",
            &self.outcome_digest,
            &self.computed_outcome_digest()?,
        )
    }

    fn computed_outcome_digest(
        &self,
    ) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
        canonical_digest(
            "derived_outcome",
            DERIVED_OUTCOME_DIGEST_DOMAIN,
            &self.digest_preimage(),
        )
    }

    fn digest_preimage(&self) -> DerivedOutcomeDigestPreimageV2<'_> {
        DerivedOutcomeDigestPreimageV2 {
            outcome_version: self.outcome_version,
            identity_spine: &self.identity_spine,
            outcome_id: &self.outcome_id,
            reserved_outcome_derived_event_id: &self.reserved_outcome_derived_event_id,
            evidence_closure_digest: &self.evidence_closure_digest,
            outcome: &self.outcome,
        }
    }
}

#[derive(Serialize)]
struct DerivedOutcomeDigestPreimageV2<'a> {
    outcome_version: u32,
    identity_spine: &'a CurrentFinalVerificationIdentitySpineV2,
    outcome_id: &'a str,
    reserved_outcome_derived_event_id: &'a str,
    evidence_closure_digest: &'a Digest,
    outcome: &'a NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2,
}

/// Pure derivation result. `NotReady` never carries a partial closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NonAuthorizingCurrentFinalVerificationDerivationV2 {
    /// One or more required source domains have not reached a terminal source.
    NotReady {
        /// Exact identity spine of the unfinished attempt.
        identity_spine: Box<CurrentFinalVerificationIdentitySpineV2>,
        /// Deterministic, sorted set of absent sources.
        missing_sources: Vec<CurrentFinalVerificationMissingSourceV2>,
    },
    /// Every source domain is present; classification remains nonauthorizing.
    Derived {
        /// Complete exact source digest join.
        closure: Box<NonAuthorizingCurrentFinalVerificationEvidenceClosureV2>,
        /// Classification derived only from the joined sources.
        outcome: Box<NonAuthorizingCurrentFinalVerificationDerivedOutcomeV2>,
    },
}

/// Derives one nonauthorizing current final-verification outcome from exact
/// integrity sources. No classification is accepted from the caller.
///
/// # Errors
///
/// Returns an error for malformed source integrity, crossed identity spines,
/// noncanonical controls, or fixed-bound violations. Missing sources produce
/// `NotReady`; contradictory or positively ambiguous complete sources produce
/// a typed `Unknown` outcome.
pub fn derive_non_authorizing_current_final_verification_evidence_v2(
    inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
) -> Result<
    NonAuthorizingCurrentFinalVerificationDerivationV2,
    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2,
> {
    validate_inputs(inputs)?;
    let missing_sources = missing_sources(inputs);
    if !missing_sources.is_empty() {
        return Ok(
            NonAuthorizingCurrentFinalVerificationDerivationV2::NotReady {
                identity_spine: Box::new(inputs.identity_spine.clone()),
                missing_sources,
            },
        );
    }

    let closure = NonAuthorizingCurrentFinalVerificationEvidenceClosureV2::new(inputs)?;
    let outcome_kind = classify_complete_sources(inputs);
    let outcome =
        NonAuthorizingCurrentFinalVerificationDerivedOutcomeV2::new(&closure, outcome_kind)?;
    Ok(
        NonAuthorizingCurrentFinalVerificationDerivationV2::Derived {
            closure: Box::new(closure),
            outcome: Box::new(outcome),
        },
    )
}

fn validate_inputs(
    inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    inputs.identity_spine.validate_integrity()?;
    if let Some(source) = &inputs.terminal {
        source.validate_integrity()?;
        require_same_spine("terminal", &inputs.identity_spine, &source.identity_spine)?;
    }
    if let Some(source) = &inputs.effect_cut {
        source.validate_integrity()?;
        require_same_spine("effect_cut", &inputs.identity_spine, &source.identity_spine)?;
    }
    if let Some(source) = &inputs.output_custody {
        source.validate_integrity()?;
        require_same_spine(
            "output_custody",
            &inputs.identity_spine,
            &source.identity_spine,
        )?;
    }
    if let Some(source) = &inputs.command_domain_cleanup {
        source.validate_integrity()?;
        require_same_spine(
            "command_domain_cleanup",
            &inputs.identity_spine,
            &source.identity_spine,
        )?;
    }
    if let Some(source) = &inputs.runner_cleanup {
        source.validate_integrity()?;
        require_same_spine(
            "runner_cleanup",
            &inputs.identity_spine,
            &source.identity_spine,
        )?;
    }

    if let Some(resolution) = &inputs.control_resolution {
        resolution.validate_integrity()?;
        require_same_spine(
            "control_resolution",
            &inputs.identity_spine,
            resolution.identity_spine(),
        )?;
    }
    require_canonical_size("evidence_inputs", inputs)
}

fn missing_sources(
    inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
) -> Vec<CurrentFinalVerificationMissingSourceV2> {
    let mut missing = Vec::new();
    if inputs.terminal.is_none() {
        missing.push(CurrentFinalVerificationMissingSourceV2::Terminal);
    }
    if inputs.effect_cut.is_none() {
        missing.push(CurrentFinalVerificationMissingSourceV2::EffectCut);
    }
    if inputs.output_custody.is_none() {
        missing.push(CurrentFinalVerificationMissingSourceV2::OutputCustody);
    }
    if inputs.command_domain_cleanup.is_none() {
        missing.push(CurrentFinalVerificationMissingSourceV2::CommandDomainCleanup);
    }
    if inputs.runner_cleanup.is_none() {
        missing.push(CurrentFinalVerificationMissingSourceV2::RunnerCleanup);
    }
    if let Some(terminal_source) = &inputs.terminal
        && let CurrentFinalVerificationTerminalObservationV2::RunnerCanceled { .. } =
            &terminal_source.observation
    {
        let resolved = match &inputs.control_resolution {
            Some(CurrentFinalVerificationControlResolutionSourceV2::Authenticated { .. }) => true,
            Some(
                CurrentFinalVerificationControlResolutionSourceV2::UnmatchedAfterReconciliation {
                    reconciled_through_event_sequence,
                    ..
                },
            ) => *reconciled_through_event_sequence >= terminal_source.terminal_event_sequence,
            None => false,
        };
        if !resolved {
            missing.push(CurrentFinalVerificationMissingSourceV2::ControlResolution);
        }
    }
    missing
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed ADR-0009 outcome matrix stays contiguous for auditable precedence"
)]
fn classify_complete_sources(
    inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
) -> NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2 {
    let terminal = inputs.terminal.as_ref().expect("complete-source guard");
    let effect_cut = inputs.effect_cut.as_ref().expect("complete-source guard");
    let custody = inputs
        .output_custody
        .as_ref()
        .expect("complete-source guard");
    let command_cleanup = inputs
        .command_domain_cleanup
        .as_ref()
        .expect("complete-source guard");
    let runner_cleanup = inputs
        .runner_cleanup
        .as_ref()
        .expect("complete-source guard");

    if let Some(reason) = positive_unknown_reason(
        terminal,
        effect_cut,
        custody,
        command_cleanup,
        runner_cleanup,
    ) {
        return unknown(reason);
    }
    let effect_started = matches!(
        effect_cut.observation,
        CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. }
    );
    if (effect_started && effect_cut.effect_cut_event_sequence >= terminal.terminal_event_sequence)
        || custody.custody_event_sequence
            <= terminal
                .terminal_event_sequence
                .max(effect_cut.effect_cut_event_sequence)
        || command_cleanup.cleanup_event_sequence <= custody.custody_event_sequence
        || runner_cleanup.cleanup_event_sequence <= command_cleanup.cleanup_event_sequence
        || runner_cleanup_direct_sequence(&runner_cleanup.direct_child)
            <= command_cleanup.cleanup_event_sequence
        || runner_cleanup_domain_sequence(&runner_cleanup.accounting_domain)
            <= command_cleanup.cleanup_event_sequence
        || lifecycle_event_identity_is_duplicated(
            terminal,
            effect_cut,
            custody,
            command_cleanup,
            runner_cleanup,
        )
        || control_lifecycle_event_identity_is_duplicated(
            inputs.control_resolution.as_ref(),
            &inputs.identity_spine,
            terminal,
            effect_cut,
            custody,
            command_cleanup,
            runner_cleanup,
        )
    {
        return unknown(CurrentFinalVerificationUnknownReasonV2::SourceEventOrderingContradiction);
    }
    if !command_cleanup.observation.is_clean()
        || !runner_cleanup.direct_child.is_clean()
        || !runner_cleanup.accounting_domain.is_clean()
    {
        unreachable!("all non-clean cases are handled by positive_unknown_reason");
    }

    if !clean_cleanup_matches_reached_frontier(
        &inputs.identity_spine.fields.reached_frontier,
        &effect_cut.observation,
        &command_cleanup.observation,
        &runner_cleanup.direct_child,
        &runner_cleanup.accounting_domain,
    ) {
        return unknown(CurrentFinalVerificationUnknownReasonV2::CleanupEffectContradiction);
    }

    if let CurrentFinalVerificationTerminalObservationV2::RunnerCanceled { claimed_control_id } =
        &terminal.observation
    {
        return classify_controlled_cancel(
            inputs,
            terminal,
            effect_cut,
            custody,
            claimed_control_id,
        );
    }

    if inputs.control_resolution.is_some() {
        return unknown(
            CurrentFinalVerificationUnknownReasonV2::ControlEffectOrderingContradiction,
        );
    }

    match (
        &terminal.observation,
        &effect_cut.observation,
        &custody.observation,
    ) {
        (
            CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect {
                proof_id: _,
                proof_digest: terminal_proof_digest,
            },
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                proof_id: _,
                proof_digest: effect_proof_digest,
            },
            custody_observation,
        ) if terminal_proof_digest == effect_proof_digest
            && pre_effect_custody_matches(
                &inputs.identity_spine,
                custody_observation,
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ) =>
        {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::FailedBeforeEffect
        }
        (CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect { .. }, _, _)
        | (_, CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect { .. }, _) => {
            unknown(CurrentFinalVerificationUnknownReasonV2::TerminalEffectContradiction)
        }
        (
            _,
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::AbandonedSensitive { .. },
        ) => NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::SensitiveOutputRejected,
        (
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. },
        ) => NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Verified,
        (
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code },
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. },
        ) if *exit_code > 0 => {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::NonzeroExit {
                exit_code: *exit_code,
            }
        }
        (
            CurrentFinalVerificationTerminalObservationV2::Signaled { signal, .. },
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. },
        ) => {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Signaled { signal: *signal }
        }
        (
            CurrentFinalVerificationTerminalObservationV2::TimedOut,
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. },
        ) => NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::TimedOut,
        (
            CurrentFinalVerificationTerminalObservationV2::OutputLimitExceeded { .. },
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. },
        ) => NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::OutputLimitExceeded,
        _ => unknown(CurrentFinalVerificationUnknownReasonV2::TerminalCustodyContradiction),
    }
}

fn clean_cleanup_matches_reached_frontier(
    frontier: &CurrentFinalVerificationReachedFrontierV2,
    effect_cut: &CurrentFinalVerificationEffectCutObservationV2,
    command_domain: &CurrentCommandDomainCleanupObservationV2,
    direct_child: &CurrentIndependentDirectChildObservationV2,
    runner_domain: &CurrentIndependentRunnerDomainObservationV2,
) -> bool {
    let command_not_created = matches!(
        command_domain,
        CurrentCommandDomainCleanupObservationV2::NoDomainCreatedBeforeEffect { .. }
    );
    let command_reaped = matches!(
        command_domain,
        CurrentCommandDomainCleanupObservationV2::ReapedEmpty { .. }
    );
    let direct_not_spawned = matches!(
        direct_child,
        CurrentIndependentDirectChildObservationV2::NotSpawned { .. }
    );
    let direct_reaped = matches!(
        direct_child,
        CurrentIndependentDirectChildObservationV2::Reaped { .. }
    );
    let runner_not_created = matches!(
        runner_domain,
        CurrentIndependentRunnerDomainObservationV2::NotCreated { .. }
    );
    let runner_empty = matches!(
        runner_domain,
        CurrentIndependentRunnerDomainObservationV2::Empty { .. }
    );
    let proven_no_effect = matches!(
        effect_cut,
        CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect { .. }
    );
    let effect_started = matches!(
        effect_cut,
        CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. }
    );

    match frontier {
        CurrentFinalVerificationReachedFrontierV2::LaunchCommitted { .. } => {
            proven_no_effect && command_not_created && direct_not_spawned && runner_not_created
        }
        CurrentFinalVerificationReachedFrontierV2::CaptureAcquired { .. } => {
            proven_no_effect
                && command_not_created
                && ((direct_not_spawned && runner_not_created) || (direct_reaped && runner_empty))
        }
        CurrentFinalVerificationReachedFrontierV2::V13Initialized { .. } => {
            proven_no_effect && command_not_created && direct_reaped && runner_empty
        }
        CurrentFinalVerificationReachedFrontierV2::Dispatched { .. } => {
            direct_reaped
                && runner_empty
                && ((effect_started && command_reaped)
                    || (proven_no_effect && (command_not_created || command_reaped)))
        }
    }
}

fn positive_unknown_reason(
    terminal: &CurrentFinalVerificationTerminalSourceV2,
    effect_cut: &CurrentFinalVerificationEffectCutSourceV2,
    custody: &CurrentFinalVerificationOutputCustodySourceV2,
    command_cleanup: &CurrentCommandDomainCleanupSourceV2,
    runner_cleanup: &CurrentRunnerCleanupSourceV2,
) -> Option<CurrentFinalVerificationUnknownReasonV2> {
    if matches!(
        terminal.observation,
        CurrentFinalVerificationTerminalObservationV2::Unknown { .. }
    ) {
        return Some(CurrentFinalVerificationUnknownReasonV2::TerminalSourceUnknown);
    }
    if matches!(
        effect_cut.observation,
        CurrentFinalVerificationEffectCutObservationV2::Unknown { .. }
    ) {
        return Some(CurrentFinalVerificationUnknownReasonV2::EffectCutUnknown);
    }
    if matches!(
        custody.observation,
        CurrentFinalVerificationOutputCustodyObservationV2::Unknown { .. }
    ) {
        return Some(CurrentFinalVerificationUnknownReasonV2::OutputCustodyUnknown);
    }
    match command_cleanup.observation {
        CurrentCommandDomainCleanupObservationV2::SurvivorsPresent { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::CommandDomainSurvivorsPresent);
        }
        CurrentCommandDomainCleanupObservationV2::Unknown { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::CommandDomainCleanupUnknown);
        }
        _ => {}
    }
    match runner_cleanup.direct_child {
        CurrentIndependentDirectChildObservationV2::StillPresent { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::RunnerDirectChildPresent);
        }
        CurrentIndependentDirectChildObservationV2::Unknown { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::RunnerDirectChildUnknown);
        }
        _ => {}
    }
    match runner_cleanup.accounting_domain {
        CurrentIndependentRunnerDomainObservationV2::SurvivorsPresent { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::RunnerDomainSurvivorsPresent);
        }
        CurrentIndependentRunnerDomainObservationV2::Unknown { .. } => {
            return Some(CurrentFinalVerificationUnknownReasonV2::RunnerDomainUnknown);
        }
        _ => {}
    }
    if matches!(
        terminal.observation,
        CurrentFinalVerificationTerminalObservationV2::Signaled {
            core_dumped: true,
            ..
        }
    ) {
        return Some(CurrentFinalVerificationUnknownReasonV2::CoreDumpObserved);
    }
    None
}

fn classify_controlled_cancel(
    inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
    terminal: &CurrentFinalVerificationTerminalSourceV2,
    effect_cut: &CurrentFinalVerificationEffectCutSourceV2,
    custody: &CurrentFinalVerificationOutputCustodySourceV2,
    claimed_control_id: &str,
) -> NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2 {
    let Some(resolution) = &inputs.control_resolution else {
        unreachable!("complete-source guard requires control resolution");
    };
    let CurrentFinalVerificationControlResolutionSourceV2::Authenticated { source: control } =
        resolution
    else {
        return unknown(CurrentFinalVerificationUnknownReasonV2::ControlIdentityContradiction);
    };
    if control.control_id != claimed_control_id {
        return unknown(CurrentFinalVerificationUnknownReasonV2::ControlIdentityContradiction);
    }
    if control.observed_event_sequence >= terminal.terminal_event_sequence {
        return unknown(
            CurrentFinalVerificationUnknownReasonV2::ControlEffectOrderingContradiction,
        );
    }
    match (
        control.action,
        &effect_cut.observation,
        &custody.observation,
    ) {
        (
            action @ (CurrentFinalVerificationControlActionKindV2::Pause
            | CurrentFinalVerificationControlActionKindV2::SteeringInterruption),
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect { .. },
            custody_observation,
        ) if control.observed_event_sequence < effect_cut.effect_cut_event_sequence
            && pre_effect_custody_matches(
                &inputs.identity_spine,
                custody_observation,
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
            ) =>
        {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::ControlInterruptedBeforeEffect {
                control_id: control.control_id.clone(),
                action,
            }
        }
        (
            CurrentFinalVerificationControlActionKindV2::Cancel,
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect { .. },
            custody_observation,
        ) if control.observed_event_sequence < effect_cut.effect_cut_event_sequence
            && pre_effect_custody_matches(
                &inputs.identity_spine,
                custody_observation,
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
            ) =>
        {
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Canceled {
                control_id: control.control_id.clone(),
            }
        }
        (
            CurrentFinalVerificationControlActionKindV2::Cancel,
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean { .. }
            | CurrentFinalVerificationOutputCustodyObservationV2::AbandonedSensitive { .. },
        ) => NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Canceled {
            control_id: control.control_id.clone(),
        },
        _ => unknown(
            CurrentFinalVerificationUnknownReasonV2::ControlEffectOrderingContradiction,
        ),
    }
}

fn pre_effect_custody_matches(
    spine: &CurrentFinalVerificationIdentitySpineV2,
    custody: &CurrentFinalVerificationOutputCustodyObservationV2,
    expected_reason: CurrentFinalVerificationPreEffectAbandonmentReasonV2,
) -> bool {
    match (&spine.fields.reached_frontier, custody) {
        (
            CurrentFinalVerificationReachedFrontierV2::LaunchCommitted { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::ClosedBeforeCapture { .. },
        ) => true,
        (
            CurrentFinalVerificationReachedFrontierV2::CaptureAcquired { .. }
            | CurrentFinalVerificationReachedFrontierV2::V13Initialized { .. }
            | CurrentFinalVerificationReachedFrontierV2::Dispatched { .. },
            CurrentFinalVerificationOutputCustodyObservationV2::AbandonedBeforeEffect {
                reason,
                ..
            },
        ) => *reason == expected_reason,
        _ => false,
    }
}

const fn unknown(
    reason: CurrentFinalVerificationUnknownReasonV2,
) -> NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2 {
    NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown { reason }
}

const fn runner_cleanup_direct_sequence(
    observation: &CurrentIndependentDirectChildObservationV2,
) -> u64 {
    match observation {
        CurrentIndependentDirectChildObservationV2::Reaped {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentDirectChildObservationV2::NotSpawned {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentDirectChildObservationV2::StillPresent {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentDirectChildObservationV2::Unknown {
            observed_event_sequence,
            ..
        } => *observed_event_sequence,
    }
}

const fn runner_cleanup_domain_sequence(
    observation: &CurrentIndependentRunnerDomainObservationV2,
) -> u64 {
    match observation {
        CurrentIndependentRunnerDomainObservationV2::Empty {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentRunnerDomainObservationV2::NotCreated {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentRunnerDomainObservationV2::SurvivorsPresent {
            observed_event_sequence,
            ..
        }
        | CurrentIndependentRunnerDomainObservationV2::Unknown {
            observed_event_sequence,
            ..
        } => *observed_event_sequence,
    }
}

fn lifecycle_event_identity_is_duplicated(
    terminal: &CurrentFinalVerificationTerminalSourceV2,
    effect_cut: &CurrentFinalVerificationEffectCutSourceV2,
    custody: &CurrentFinalVerificationOutputCustodySourceV2,
    command_cleanup: &CurrentCommandDomainCleanupSourceV2,
    runner_cleanup: &CurrentRunnerCleanupSourceV2,
) -> bool {
    let (_, direct_event_id, _, direct_sequence) = runner_cleanup
        .direct_child
        .identity_event_evidence_sequence();
    let (_, domain_event_id, _, domain_sequence) = runner_cleanup
        .accounting_domain
        .identity_event_evidence_sequence();
    let ids = [
        terminal.terminal_event_id.as_str(),
        effect_cut.effect_cut_event_id.as_str(),
        custody.custody_event_id.as_str(),
        command_cleanup.cleanup_event_id.as_str(),
        direct_event_id,
        domain_event_id,
        runner_cleanup.cleanup_event_id.as_str(),
    ];
    let sequences = [
        terminal.terminal_event_sequence,
        effect_cut.effect_cut_event_sequence,
        custody.custody_event_sequence,
        command_cleanup.cleanup_event_sequence,
        direct_sequence,
        domain_sequence,
        runner_cleanup.cleanup_event_sequence,
    ];
    let duplicates = ids
        .iter()
        .enumerate()
        .any(|(index, id)| ids[..index].contains(id))
        || sequences
            .iter()
            .enumerate()
            .any(|(index, sequence)| sequences[..index].contains(sequence));
    duplicates
        || runner_cleanup
            .shutdown_transcript
            .as_ref()
            .is_some_and(|shutdown| sequences.contains(&shutdown.acknowledged_event_sequence))
}

fn control_lifecycle_event_identity_is_duplicated(
    control_resolution: Option<&CurrentFinalVerificationControlResolutionSourceV2>,
    spine: &CurrentFinalVerificationIdentitySpineV2,
    terminal: &CurrentFinalVerificationTerminalSourceV2,
    effect_cut: &CurrentFinalVerificationEffectCutSourceV2,
    custody: &CurrentFinalVerificationOutputCustodySourceV2,
    command_cleanup: &CurrentCommandDomainCleanupSourceV2,
    runner_cleanup: &CurrentRunnerCleanupSourceV2,
) -> bool {
    let (_, direct_event_id, _, direct_sequence) = runner_cleanup
        .direct_child
        .identity_event_evidence_sequence();
    let (_, domain_event_id, _, domain_sequence) = runner_cleanup
        .accounting_domain
        .identity_event_evidence_sequence();
    let mut lifecycle_ids = vec![
        spine.fields.authority_admitted_event_id.as_str(),
        terminal.terminal_event_id.as_str(),
        effect_cut.effect_cut_event_id.as_str(),
        custody.custody_event_id.as_str(),
        command_cleanup.cleanup_event_id.as_str(),
        direct_event_id,
        domain_event_id,
        runner_cleanup.cleanup_event_id.as_str(),
    ];
    let mut lifecycle_sequences = vec![
        spine.fields.authority_admitted_event_sequence,
        terminal.terminal_event_sequence,
        effect_cut.effect_cut_event_sequence,
        custody.custody_event_sequence,
        command_cleanup.cleanup_event_sequence,
        direct_sequence,
        domain_sequence,
        runner_cleanup.cleanup_event_sequence,
    ];
    append_frontier_events(
        &spine.fields.reached_frontier,
        &mut lifecycle_ids,
        &mut lifecycle_sequences,
    );
    if let Some(shutdown) = &runner_cleanup.shutdown_transcript {
        lifecycle_sequences.push(shutdown.acknowledged_event_sequence);
    }
    if lifecycle_ids
        .iter()
        .enumerate()
        .any(|(index, id)| lifecycle_ids[..index].contains(id))
        || lifecycle_sequences
            .iter()
            .enumerate()
            .any(|(index, sequence)| lifecycle_sequences[..index].contains(sequence))
    {
        return true;
    }
    match control_resolution {
        Some(CurrentFinalVerificationControlResolutionSourceV2::Authenticated { source }) => {
            lifecycle_ids.contains(&source.control_id.as_str())
                || lifecycle_ids.contains(&source.issued_event_id.as_str())
                || lifecycle_ids.contains(&source.observed_event_id.as_str())
                || lifecycle_sequences.contains(&source.issued_event_sequence)
                || lifecycle_sequences.contains(&source.observed_event_sequence)
        }
        Some(CurrentFinalVerificationControlResolutionSourceV2::UnmatchedAfterReconciliation {
            claimed_control_id,
            reconciliation_id,
            reconciled_event_id,
            reconciled_event_sequence,
            ..
        }) => {
            lifecycle_ids.contains(&claimed_control_id.as_str())
                || lifecycle_ids.contains(&reconciliation_id.as_str())
                || lifecycle_ids.contains(&reconciled_event_id.as_str())
                || lifecycle_sequences.contains(reconciled_event_sequence)
        }
        None => false,
    }
}

fn append_frontier_events<'a>(
    frontier: &'a CurrentFinalVerificationReachedFrontierV2,
    ids: &mut Vec<&'a str>,
    sequences: &mut Vec<u64>,
) {
    let launch = frontier.launch();
    ids.push(&launch.committed_event_id);
    sequences.push(launch.committed_event_sequence);
    if let Some(capture) = frontier.capture() {
        ids.push(&capture.acquired_event_id);
        sequences.push(capture.acquired_event_sequence);
    }
    if let Some(initialized) = frontier.initialized() {
        ids.push(&initialized.initialized_event_id);
        sequences.push(initialized.initialized_event_sequence);
    }
    if let Some(dispatched) = frontier.dispatched() {
        ids.push(&dispatched.dispatched_event_id);
        sequences.push(dispatched.dispatched_event_sequence);
    }
}

fn require_version(
    field: &'static str,
    observed: u32,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if observed == CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2 {
        Ok(())
    } else {
        Err(
            NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::UnsupportedVersion {
                field,
                observed,
            },
        )
    }
}

fn require_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if value.trim().is_empty() || value.len() > MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2 {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidIdentifier { field })
    } else {
        Ok(())
    }
}

fn require_core_identity(
    field: &'static str,
    value: &str,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidIdentifier { field })
    }
}

fn require_pairwise_distinct(
    field: &'static str,
    identifiers: &[&str],
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if identifiers
        .iter()
        .enumerate()
        .any(|(index, identifier)| identifiers[..index].contains(identifier))
    {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation { field })
    } else {
        Ok(())
    }
}

fn require_reservation(
    field: &'static str,
    observed: &str,
    reserved: &str,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if observed == reserved {
        Ok(())
    } else {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch { field })
    }
}

fn require_independent_observer(
    field: &'static str,
    observer_id: &str,
    spine: &CurrentFinalVerificationIdentitySpineV2,
    reserved_observer_id: &str,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    require_core_identity(field, observer_id)?;
    require_reservation(field, observer_id, reserved_observer_id)?;
    let reservations = lifecycle_reservations(spine);
    if observer_id == reservations.runner_launch_id
        || observer_id == reservations.runner_session_id
        || observer_id == reservations.command_request_id
    {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation { field })
    } else {
        Ok(())
    }
}

fn lifecycle_reservations(
    spine: &CurrentFinalVerificationIdentitySpineV2,
) -> &CurrentFinalVerificationLifecycleReservationFieldsV2 {
    &spine
        .fields
        .reached_frontier
        .launch()
        .lifecycle_reservations
        .fields
}

const fn command_backend_matches_containment(
    command_backend: CurrentCommandDomainBackendV2,
    containment_backend: CurrentFinalVerificationNativeContainmentBackendV2,
) -> bool {
    matches!(
        (command_backend, containment_backend),
        (
            CurrentCommandDomainBackendV2::MacOsDedicatedIdentity,
            CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt,
        ) | (
            CurrentCommandDomainBackendV2::LinuxCgroupV2,
            CurrentFinalVerificationNativeContainmentBackendV2::LinuxBubblewrapLandlockSeccompCgroupV2,
        )
    )
}

fn require_same_spine(
    source: &'static str,
    expected: &CurrentFinalVerificationIdentitySpineV2,
    observed: &CurrentFinalVerificationIdentitySpineV2,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if observed == expected {
        Ok(())
    } else {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CrossedIdentity { source })
    }
}

fn require_digest_match(
    field: &'static str,
    claimed: &Digest,
    computed: &Digest,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    if claimed == computed {
        Ok(())
    } else {
        Err(NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch { field })
    }
}

fn require_canonical_size<T: Serialize + ?Sized>(
    field: &'static str,
    value: &T,
) -> Result<(), NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CanonicalEncoding {
            field,
            reason: error.to_string(),
        }
    })?;
    if canonical.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        Err(
            NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CanonicalEncoding {
                field,
                reason: format!(
                    "maximum is {MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes; observed {}",
                    canonical.len()
                ),
            },
        )
    } else {
        Ok(())
    }
}

fn canonical_digest<T: Serialize + ?Sized>(
    field: &'static str,
    domain: &[u8],
    value: &T,
) -> Result<Digest, NonAuthorizingCurrentFinalVerificationEvidenceErrorV2> {
    let canonical = serde_json::to_vec(value).map_err(|error| {
        NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CanonicalEncoding {
            field,
            reason: error.to_string(),
        }
    })?;
    if canonical.len() > MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2 {
        return Err(
            NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CanonicalEncoding {
                field,
                reason: format!(
                    "maximum is {MAX_CURRENT_FINAL_VERIFICATION_CANONICAL_BYTES_V2} bytes; observed {}",
                    canonical.len()
                ),
            },
        );
    }
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[cfg(test)]
mod tests;
