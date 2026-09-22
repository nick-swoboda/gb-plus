//! Deterministic projection from validated durable evidence to typed UI events.
//!
//! The projection reads only the core ledger image and the canonical provider
//! protocols persisted by the coordinator. Provider-local streaming events are
//! intentionally excluded. An effect is shown as running only when a durable
//! terminal outcome proves that it began; an unfinished or uncertain effect is
//! shown as unknown instead. The sole pending exception is a pre-admitted
//! `CleanupWorkerDomain` proposal with no observation: it is a process-lifecycle
//! obligation, so it remains proposal-only and does not poison workspace
//! snapshot identity. An explicit unknown cleanup still renders unknown, and
//! completion still requires every effect to have terminal success.
//! Consequently the same ledger state always yields the same canonical bytes
//! before and after restart. Projection types are output-only: UI code must
//! reconstruct them from ledger evidence rather than deserialize an
//! unauthenticated event stream.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str;

use grok_build_core::{
    AgentEvent, AgentEventKind, ApplicationEvidence, ApplicationReceipt, CONTRACT_VERSION,
    ChangeSet, CommandOutputSensitiveRejectionAnchorV1, CommandSpec, Digest, EffectKind,
    EffectObservation, EffectOutcome, EventLedger, FileOperation, LedgerError,
    LiveStateCaptureEvidence, MAX_TERMINAL_REASON_BYTES, NonSuccessTerminalState,
    PersistedCommandOutputSensitiveRejectionV1, PersistedCompletionLiveStateAuthority,
    PersistedEffect, PersistedFinishReceipt, PersistedMutationArtifact, PersistedSprint,
    PersistedTerminalProof, RollbackEvidence, RollbackReceipt, RollbackRequest,
    RunnerEffectRequestAuthority, SprintLiveStateCaptureRequest, SprintState,
    TaskIntegrationArtifactReference, TaskIntegrationEvidence, TaskIntegrationReceipt,
    TaskIntegrationRequest, VerificationEffectEvidence, WorkerCleanupEvidence,
    WorkerCleanupRequest,
};
use grok_build_providers::{
    ProviderToolCall, ProviderToolIntent, ProviderToolResult, decode_planning_evidence,
    decode_planning_request, decode_tool_call, decode_tool_result, decode_turn_evidence,
    decode_turn_request,
};
use serde::Serialize;

use crate::durable_coordinator::{
    containment_reason, is_containment_rejection, validate_provider_call_for_effect,
};
use crate::ui_model::{CriteriaAggregateStatus, TerminalBanner, UiSafeNextAction, UiTerminalCause};

/// Maximum typed rows emitted for one sprint projection.
pub const MAX_DURABLE_UI_EVENTS: usize = 1_024;
/// Maximum canonical projection size accepted by the framework boundary.
pub const MAX_DURABLE_UI_BYTES: usize = 1024 * 1024;

const MAX_UI_IDENTIFIER_BYTES: usize = 512;
const MAX_UI_PATH_BYTES: usize = 4_096;
const PROVIDER_FAILURE_HEADER: &str = "grok-build.provider-failure.v1";
const FILE_FAILURE_HEADER: &str = "grok-build.file-tool-failure.v1";

/// Why a durable effect cannot be presented as known terminal execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UiUnknownReason {
    /// Only the proposal is durable; no terminal observation exists.
    MissingObservation,
    /// A terminal observation explicitly classifies the outcome as unknown.
    UncertainObservation,
}

/// Exact regular-file mutation represented by linked snapshot evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UiMutationKind {
    /// A regular file was created.
    Create,
    /// An existing regular file was replaced.
    Replace,
    /// An existing regular file was deleted.
    Delete,
}

/// Closed unsuccessful terminal states visible to Milestone-one UI code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UiNonSuccessTerminalState {
    /// Progress requires new authority or user input.
    Blocked,
    /// Bounded work failed.
    Failed,
    /// Work was deliberately canceled.
    Canceled,
    /// Side-effect outcome cannot be proven.
    Unknown,
}

/// One normalized durable event consumed by a future native runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableUiEvent {
    ordinal: u64,
    source_sequence: u64,
    source_event_id: String,
    payload: DurableUiEventKind,
}

impl DurableUiEvent {
    /// Contiguous one-based position in the normalized projection.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Durable ledger event sequence proving this UI event.
    #[must_use]
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    /// Durable ledger event identity proving this UI event.
    #[must_use]
    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    /// Typed normalized payload.
    #[must_use]
    pub const fn payload(&self) -> &DurableUiEventKind {
        &self.payload
    }
}

/// Closed normalized UI vocabulary derived from durable evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum DurableUiEventKind {
    /// Exact intent and proposal event are durable.
    EffectProposed {
        /// Effect identity.
        effect_id: String,
        /// Durable idempotency key.
        idempotency_key: String,
        /// Coordinator-owned effect category.
        kind: EffectKind,
        /// Snapshot against which the request was authorized.
        input_snapshot: Digest,
    },
    /// Terminal evidence proves the effect began.
    EffectRunning {
        /// Effect identity.
        effect_id: String,
    },
    /// Exact canonical result evidence proves success.
    EffectSucceeded {
        /// Effect identity.
        effect_id: String,
        /// Digest of the exact evidence preimage.
        evidence_digest: Digest,
    },
    /// Evidence proves execution did not begin.
    EffectFailedBefore {
        /// Effect identity.
        effect_id: String,
        /// Digest of the exact failure or cancellation evidence.
        evidence_digest: Digest,
        /// True only for `CancelledBeforeEffect`.
        cancelled: bool,
    },
    /// Evidence proves the effect began and later failed.
    EffectFailedAfter {
        /// Effect identity.
        effect_id: String,
        /// Digest of exact failure evidence.
        evidence_digest: Digest,
    },
    /// A command was stopped after the fixed detector recognized sensitive
    /// output and the private capture plus native command domain were cleaned.
    /// This event deliberately carries policy identity only: never output,
    /// offsets, lengths, detector messages, or output-derived digests.
    #[serde(rename = "sensitive_output_rejected")]
    SensitiveOutputRejected {
        /// Command effect identity.
        effect_id: String,
        /// Repository-owned public detector policy identity.
        detector_policy_id: String,
        /// Repository-owned public detector policy version.
        detector_policy_version: u32,
    },
    /// Execution outcome is not durably knowable.
    EffectUnknown {
        /// Effect identity.
        effect_id: String,
        /// Evidence digest, absent when no observation exists.
        evidence_digest: Option<Digest>,
        /// Exact durable uncertainty class.
        reason: UiUnknownReason,
    },
    /// A successful mutation has an atomic snapshot and one-operation link.
    SnapshotLinked {
        /// Effect identity.
        effect_id: String,
        /// Input snapshot authorized by the intent.
        input_snapshot: Digest,
        /// Exact post-effect snapshot.
        result_snapshot: Digest,
        /// Per-effect change-set identity.
        change_set_id: String,
        /// Normalized workspace-relative path.
        path: String,
        /// Exact mutation category.
        mutation: UiMutationKind,
        /// True when content returned to an earlier durable snapshot.
        result_snapshot_reused: bool,
    },
    /// A command was durably rejected before execution.
    ContainmentBlocked {
        /// Command effect identity.
        effect_id: String,
        /// Stable coordinator-owned reason.
        reason: String,
    },
    /// A durable unsuccessful sprint terminal record exists.
    SprintTerminal {
        /// Exact unsuccessful state.
        state: UiNonSuccessTerminalState,
        /// Durable terminal record identity.
        record_id: String,
        /// Digest of canonical typed terminal evidence.
        evidence_digest: Digest,
        /// Bounded durable reason.
        reason: String,
        /// Proof-derived specialized cause, absent for generic terminals.
        cause: Option<UiTerminalCause>,
        /// Proof-derived safe action, absent for generic terminals.
        safe_next_action: Option<UiSafeNextAction>,
    },
    /// A validated completion receipt chain exists.
    SprintCompleted {
        /// Durable completion receipt identity.
        receipt_id: String,
        /// Exact applied and verified final snapshot.
        final_snapshot: Digest,
        /// Aggregate criterion claim derived only from validated completion.
        criteria_status: CriteriaAggregateStatus,
    },
}

/// Immutable, bounded, canonical UI event stream for one durable sprint image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableUiProjection {
    contract_version: u32,
    sprint_id: String,
    events: Vec<DurableUiEvent>,
}

impl DurableUiProjection {
    /// Loads one sprint and every exact schema-v29 sensitive-output authority
    /// needed to render it, then reconstructs the normalized UI stream.
    ///
    /// A `FailedAfterKnownEffect` command is rendered as
    /// `SensitiveOutputRejected` only when the core loader returns its complete,
    /// revalidated anchor, cleanup receipt, and capture-obligation closure.
    /// Absence remains an ordinary typed command failure; a partial or crossed
    /// authority rejects the complete projection.
    ///
    /// # Errors
    ///
    /// Returns [`UiProjectionError`] when the sprint cannot be loaded or any
    /// candidate rejection authority is incomplete, crossed, or noncanonical.
    pub fn from_ledger(ledger: &EventLedger, sprint_id: &str) -> Result<Self, UiProjectionError> {
        let sprint = ledger
            .load_sprint(sprint_id)
            .map_err(|error| invalid_sprint(error.to_string()))?;
        let mut sensitive_output_rejections = BTreeMap::new();
        for effect in &sprint.effects {
            if effect.intent.kind != EffectKind::RunCommand
                || !effect.observation.as_ref().is_some_and(|observation| {
                    matches!(
                        observation.outcome,
                        EffectOutcome::FailedAfterKnownEffect { .. }
                    )
                })
            {
                continue;
            }
            if let Some(rejection) = admit_sensitive_output_rejection_readback(
                effect,
                ledger.load_command_output_sensitive_rejection_for_effect(&effect.intent.effect_id),
            )? {
                sensitive_output_rejections.insert(effect.intent.effect_id.clone(), rejection);
            }
        }
        Self::from_persisted_with_sensitive_output_rejections(&sprint, &sensitive_output_rejections)
    }

    /// Reconstructs a normalized UI stream from one core-validated sprint image.
    ///
    /// No provider-local text or transient callback participates. Missing,
    /// unreadable, noncanonical, or cross-correlated evidence rejects the whole
    /// projection rather than producing a partial or optimistic frame.
    /// This image-only entry point has no authority to classify sensitive-output
    /// rejection. Call [`Self::from_ledger`] when that terminal may be rendered.
    ///
    /// # Errors
    ///
    /// Returns [`UiProjectionError`] when any durable relationship, strict
    /// evidence preimage, mutation link, terminal record, or UI bound fails.
    pub fn from_persisted(sprint: &PersistedSprint) -> Result<Self, UiProjectionError> {
        Self::from_persisted_with_sensitive_output_rejections(sprint, &BTreeMap::new())
    }

    fn from_persisted_with_sensitive_output_rejections(
        sprint: &PersistedSprint,
        sensitive_output_rejections: &BTreeMap<String, PersistedCommandOutputSensitiveRejectionV1>,
    ) -> Result<Self, UiProjectionError> {
        sprint
            .spec
            .validate()
            .map_err(|error| invalid_sprint(error.to_string()))?;
        if let Some(graph) = &sprint.graph {
            graph
                .validate_for_sprint(&sprint.spec)
                .map_err(|error| invalid_sprint(error.to_string()))?;
        }
        if sprint.legacy_completion.is_some() {
            return Err(UiProjectionError::InvalidTerminal(
                "legacy v1-v8 completion is readable diagnostics only and is not proven v9 finish evidence"
                    .into(),
            ));
        }

        let mut effects = sprint.effects.iter().collect::<Vec<_>>();
        effects.sort_by(|left, right| {
            left.proposed_event
                .sequence
                .cmp(&right.proposed_event.sequence)
                .then_with(|| left.intent.effect_id.cmp(&right.intent.effect_id))
        });

        let mut builder = ProjectionBuilder::new(&sprint.spec.sprint_id)?;
        let mut snapshot_known = true;
        let mut seen_snapshots = BTreeSet::from([sprint.spec.base_snapshot.clone()]);
        for effect in effects {
            if !snapshot_known {
                return Err(effect_error(
                    effect,
                    "a later effect exists after snapshot authority became uncertain",
                ));
            }
            if !seen_snapshots.contains(&effect.intent.input_snapshot) {
                return Err(effect_error(
                    effect,
                    "intent input snapshot is outside every authenticated durable snapshot branch",
                ));
            }
            project_effect(
                sprint,
                effect,
                sensitive_output_rejections.get(&effect.intent.effect_id),
                &mut snapshot_known,
                &mut seen_snapshots,
                &mut builder,
            )?;
        }
        if let Some(completion) = &sprint.completion
            && (!snapshot_known
                || !all_effects_succeeded(&sprint.effects)
                || !seen_snapshots.contains(&completion.receipt.final_snapshot))
        {
            return Err(UiProjectionError::InvalidTerminal(
                "completion conflicts with effect outcomes or authenticated snapshot branches"
                    .into(),
            ));
        }
        project_terminal(sprint, &mut builder)?;
        builder.finish()
    }

    /// Sprint identity bound to every source event.
    #[must_use]
    pub fn sprint_id(&self) -> &str {
        &self.sprint_id
    }

    /// Ordered normalized events.
    #[must_use]
    pub fn events(&self) -> &[DurableUiEvent] {
        &self.events
    }

    /// Returns true only when a validated durable completion chain was mapped.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.events
            .iter()
            .any(|event| matches!(event.payload, DurableUiEventKind::SprintCompleted { .. }))
    }

    /// Encodes the exact compact JSON passed across the native UI boundary.
    ///
    /// # Errors
    ///
    /// Returns [`UiProjectionError`] if the projection is internally malformed,
    /// cannot be encoded, or exceeds [`MAX_DURABLE_UI_BYTES`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, UiProjectionError> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| UiProjectionError::CanonicalEncoding(error.to_string()))?;
        if bytes.len() > MAX_DURABLE_UI_BYTES {
            return Err(UiProjectionError::ByteLimitExceeded {
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<(), UiProjectionError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(UiProjectionError::InvalidProjection(
                "projection contract version differs from core".into(),
            ));
        }
        validate_identifier("sprint id", &self.sprint_id)?;
        if self.events.len() > MAX_DURABLE_UI_EVENTS {
            return Err(UiProjectionError::EventLimitExceeded {
                actual: self.events.len(),
            });
        }
        let mut previous_source_sequence = 0;
        for (index, event) in self.events.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(UiProjectionError::OrdinalOverflow)?;
            if event.ordinal != expected {
                return Err(UiProjectionError::InvalidProjection(format!(
                    "event ordinal must be {expected}, got {}",
                    event.ordinal
                )));
            }
            validate_identifier("source event id", &event.source_event_id)?;
            if event.source_sequence == 0 {
                return Err(UiProjectionError::InvalidProjection(
                    "source event sequence must be nonzero".into(),
                ));
            }
            if event.source_sequence < previous_source_sequence {
                return Err(UiProjectionError::InvalidProjection(
                    "source event sequences must be nondecreasing".into(),
                ));
            }
            previous_source_sequence = event.source_sequence;
            validate_payload(&event.payload)?;
        }
        Ok(())
    }
}

fn admit_sensitive_output_rejection_readback(
    effect: &PersistedEffect,
    readback: Result<PersistedCommandOutputSensitiveRejectionV1, LedgerError>,
) -> Result<Option<PersistedCommandOutputSensitiveRejectionV1>, UiProjectionError> {
    match readback {
        Ok(rejection) => Ok(Some(rejection)),
        Err(LedgerError::ArtifactNotFound { .. }) => Ok(None),
        Err(error) => Err(effect_error(
            effect,
            &format!("schema-v29 sensitive-output authority failed exact readback: {error}"),
        )),
    }
}

fn all_effects_succeeded(effects: &[PersistedEffect]) -> bool {
    effects.iter().all(|effect| {
        effect.observation.as_ref().is_some_and(|observation| {
            matches!(observation.outcome, EffectOutcome::Succeeded { .. })
        })
    })
}

/// Closed failure from durable-to-UI projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UiProjectionError {
    /// The sprint or graph is invalid.
    InvalidSprint(String),
    /// An effect relationship or strict evidence preimage is invalid.
    InvalidEffect {
        /// Effect identity, when readable.
        effect_id: String,
        /// Bounded fail-closed reason.
        reason: String,
    },
    /// Terminal evidence is contradictory or invalid.
    InvalidTerminal(String),
    /// Normalized event count exceeds the UI safety ceiling.
    EventLimitExceeded {
        /// Actual event count.
        actual: usize,
    },
    /// Canonical projection bytes exceed the UI safety ceiling.
    ByteLimitExceeded {
        /// Actual encoded size.
        actual: usize,
    },
    /// A contiguous ordinal could not be represented.
    OrdinalOverflow,
    /// A constructed projection violates its own envelope.
    InvalidProjection(String),
    /// Compact JSON encoding failed.
    CanonicalEncoding(String),
}

impl Display for UiProjectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSprint(reason) => write!(formatter, "invalid UI sprint source: {reason}"),
            Self::InvalidEffect { effect_id, reason } => {
                write!(
                    formatter,
                    "invalid UI effect source `{effect_id}`: {reason}"
                )
            }
            Self::InvalidTerminal(reason) => {
                write!(formatter, "invalid UI terminal source: {reason}")
            }
            Self::EventLimitExceeded { actual } => write!(
                formatter,
                "durable UI event count {actual} exceeds {MAX_DURABLE_UI_EVENTS}"
            ),
            Self::ByteLimitExceeded { actual } => write!(
                formatter,
                "durable UI projection size {actual} exceeds {MAX_DURABLE_UI_BYTES} bytes"
            ),
            Self::OrdinalOverflow => formatter.write_str("durable UI event ordinal overflow"),
            Self::InvalidProjection(reason) => {
                write!(formatter, "invalid durable UI projection: {reason}")
            }
            Self::CanonicalEncoding(reason) => {
                write!(
                    formatter,
                    "could not encode durable UI projection: {reason}"
                )
            }
        }
    }
}

impl Error for UiProjectionError {}

struct ProjectionBuilder {
    sprint_id: String,
    events: Vec<DurableUiEvent>,
}

impl ProjectionBuilder {
    fn new(sprint_id: &str) -> Result<Self, UiProjectionError> {
        validate_identifier("sprint id", sprint_id)?;
        Ok(Self {
            sprint_id: sprint_id.into(),
            events: Vec::new(),
        })
    }

    fn push(
        &mut self,
        source: &AgentEvent,
        payload: DurableUiEventKind,
    ) -> Result<(), UiProjectionError> {
        if self.events.len() >= MAX_DURABLE_UI_EVENTS {
            return Err(UiProjectionError::EventLimitExceeded {
                actual: self.events.len().saturating_add(1),
            });
        }
        source
            .validate()
            .map_err(|error| UiProjectionError::InvalidProjection(error.to_string()))?;
        if source.sprint_id != self.sprint_id {
            return Err(UiProjectionError::InvalidProjection(
                "source event belongs to a different sprint".into(),
            ));
        }
        validate_identifier("source event id", &source.event_id)?;
        validate_payload(&payload)?;
        let ordinal = u64::try_from(self.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(UiProjectionError::OrdinalOverflow)?;
        self.events.push(DurableUiEvent {
            ordinal,
            source_sequence: source.sequence,
            source_event_id: source.event_id.clone(),
            payload,
        });
        Ok(())
    }

    fn finish(mut self) -> Result<DurableUiProjection, UiProjectionError> {
        // Effect lifecycles can overlap: cleanup is durably pre-admitted before
        // the effect it will eventually close has reached its terminal event.
        // Validation remains effect-local, while presentation is a stable merge
        // over the authoritative ledger sequence.
        self.events.sort_by(|left, right| {
            left.source_sequence
                .cmp(&right.source_sequence)
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        for (index, event) in self.events.iter_mut().enumerate() {
            event.ordinal = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(UiProjectionError::OrdinalOverflow)?;
        }
        let projection = DurableUiProjection {
            contract_version: CONTRACT_VERSION,
            sprint_id: self.sprint_id,
            events: self.events,
        };
        projection.canonical_bytes()?;
        Ok(projection)
    }
}

struct ValidatedEffect {
    tool_result: Option<ProviderToolResult>,
    containment_blocked: bool,
    sensitive_output_rejection: Option<CommandOutputSensitiveRejectionAnchorV1>,
    result_snapshot: Option<Digest>,
}

#[allow(clippy::too_many_arguments)]
fn project_effect(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    sensitive_output_rejection: Option<&PersistedCommandOutputSensitiveRejectionV1>,
    snapshot_known: &mut bool,
    seen_snapshots: &mut BTreeSet<Digest>,
    builder: &mut ProjectionBuilder,
) -> Result<(), UiProjectionError> {
    let validated = validate_effect_evidence(sprint, effect, sensitive_output_rejection)?;
    builder.push(
        &effect.proposed_event,
        DurableUiEventKind::EffectProposed {
            effect_id: effect.intent.effect_id.clone(),
            idempotency_key: effect.intent.idempotency_key.clone(),
            kind: effect.intent.kind,
            input_snapshot: effect.intent.input_snapshot.clone(),
        },
    )?;

    let Some(observation) = &effect.observation else {
        require_no_mutation_artifact(effect)?;
        // Pre-admitted cleanup without an observation does not prove workspace
        // writes. Keep it pending; every required effect must still succeed.
        if effect.intent.kind == EffectKind::CleanupWorkerDomain {
            return Ok(());
        }
        builder.push(
            &effect.proposed_event,
            DurableUiEventKind::EffectUnknown {
                effect_id: effect.intent.effect_id.clone(),
                evidence_digest: None,
                reason: UiUnknownReason::MissingObservation,
            },
        )?;
        *snapshot_known = false;
        return Ok(());
    };
    let terminal = effect
        .terminal_event
        .as_ref()
        .ok_or_else(|| effect_error(effect, "terminal observation has no event"))?;
    let evidence_digest = observation.outcome.evidence_digest().clone();
    match observation.outcome {
        EffectOutcome::Succeeded { .. } => {
            builder.push(
                terminal,
                DurableUiEventKind::EffectRunning {
                    effect_id: effect.intent.effect_id.clone(),
                },
            )?;
            if effect.intent.kind.is_regular_file_mutation() {
                let tool_result = validated.tool_result.as_ref().ok_or_else(|| {
                    effect_error(effect, "successful mutation lacks a typed tool result")
                })?;
                let linked = validate_mutation_link(sprint, effect, tool_result)?;
                let result_snapshot_reused = !seen_snapshots.insert(linked.result_snapshot.clone());
                builder.push(
                    terminal,
                    DurableUiEventKind::SnapshotLinked {
                        effect_id: effect.intent.effect_id.clone(),
                        input_snapshot: effect.intent.input_snapshot.clone(),
                        result_snapshot: linked.result_snapshot.clone(),
                        change_set_id: linked.change_set_id,
                        path: linked.path,
                        mutation: linked.mutation,
                        result_snapshot_reused,
                    },
                )?;
            } else {
                require_no_mutation_artifact(effect)?;
            }
            if let Some(result_snapshot) = validated.result_snapshot {
                seen_snapshots.insert(result_snapshot);
            }
            builder.push(
                terminal,
                DurableUiEventKind::EffectSucceeded {
                    effect_id: effect.intent.effect_id.clone(),
                    evidence_digest,
                },
            )?;
        }
        EffectOutcome::FailedBeforeEffect { .. }
        | EffectOutcome::CancelledBeforeEffect { .. }
        | EffectOutcome::FailedAfterKnownEffect { .. }
        | EffectOutcome::Unknown { .. } => project_non_success(
            effect,
            observation,
            terminal,
            &validated,
            snapshot_known,
            builder,
        )?,
    }
    Ok(())
}

fn project_non_success(
    effect: &PersistedEffect,
    observation: &grok_build_core::EffectObservation,
    terminal: &AgentEvent,
    validated: &ValidatedEffect,
    snapshot_known: &mut bool,
    builder: &mut ProjectionBuilder,
) -> Result<(), UiProjectionError> {
    require_no_mutation_artifact(effect)?;
    let evidence_digest = observation.outcome.evidence_digest().clone();
    match observation.outcome {
        EffectOutcome::FailedBeforeEffect { .. } | EffectOutcome::CancelledBeforeEffect { .. } => {
            builder.push(
                terminal,
                DurableUiEventKind::EffectFailedBefore {
                    effect_id: effect.intent.effect_id.clone(),
                    evidence_digest,
                    cancelled: matches!(
                        observation.outcome,
                        EffectOutcome::CancelledBeforeEffect { .. }
                    ),
                },
            )?;
            if validated.containment_blocked {
                builder.push(
                    terminal,
                    DurableUiEventKind::ContainmentBlocked {
                        effect_id: effect.intent.effect_id.clone(),
                        reason: containment_reason(),
                    },
                )?;
            }
        }
        EffectOutcome::FailedAfterKnownEffect { .. } => {
            builder.push(
                terminal,
                DurableUiEventKind::EffectRunning {
                    effect_id: effect.intent.effect_id.clone(),
                },
            )?;
            builder.push(
                terminal,
                DurableUiEventKind::EffectFailedAfter {
                    effect_id: effect.intent.effect_id.clone(),
                    evidence_digest,
                },
            )?;
            if let Some(rejection) = &validated.sensitive_output_rejection {
                builder.push(
                    terminal,
                    DurableUiEventKind::SensitiveOutputRejected {
                        effect_id: effect.intent.effect_id.clone(),
                        detector_policy_id: rejection.detector_policy.policy_id.clone(),
                        detector_policy_version: rejection.detector_policy.policy_version,
                    },
                )?;
            }
            *snapshot_known = false;
        }
        EffectOutcome::Unknown { .. } => {
            builder.push(
                terminal,
                DurableUiEventKind::EffectUnknown {
                    effect_id: effect.intent.effect_id.clone(),
                    evidence_digest: Some(evidence_digest),
                    reason: UiUnknownReason::UncertainObservation,
                },
            )?;
            *snapshot_known = false;
        }
        EffectOutcome::Succeeded { .. } => {
            return Err(effect_error(
                effect,
                "successful observation entered non-success projection",
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one projection gate keeps envelope, typed-finish, sensitive-output, containment, and failure-evidence validation contiguous"
)]
fn validate_effect_evidence(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    sensitive_output_rejection: Option<&PersistedCommandOutputSensitiveRejectionV1>,
) -> Result<ValidatedEffect, UiProjectionError> {
    validate_effect_envelope(effect)?;
    if effect.intent.kind == EffectKind::ProviderRequest {
        require_no_finish_receipt(effect)?;
        validate_provider_effect(sprint, effect)?;
        return Ok(ValidatedEffect {
            tool_result: None,
            containment_blocked: false,
            sensitive_output_rejection: None,
            result_snapshot: None,
        });
    }
    if effect.intent.kind.requires_typed_finish_receipt() {
        return validate_typed_finish_effect(sprint, effect);
    }
    require_no_finish_receipt(effect)?;

    if sensitive_output_rejection.is_some()
        && (effect.intent.kind != EffectKind::RunCommand
            || !effect.observation.as_ref().is_some_and(|observation| {
                matches!(
                    observation.outcome,
                    EffectOutcome::FailedAfterKnownEffect { .. }
                )
            }))
    {
        return Err(effect_error(
            effect,
            "schema-v29 sensitive-output authority is attached to a non-rejection effect",
        ));
    }

    if effect.intent.kind == EffectKind::RunCommand
        && sensitive_output_rejection.is_none()
        && let Some(validated) = try_validate_verification_effect(sprint, effect)?
    {
        return Ok(validated);
    }

    let call = if effect.intent.kind == EffectKind::RunCommand {
        recover_run_command_provider_call(sprint, effect)?
    } else {
        decode_tool_call(&effect.request_bytes)
            .map_err(|error| effect_error(effect, &error.to_string()))?
    };
    validate_tool_call_identity(effect, &call)?;
    let Some(observation) = &effect.observation else {
        return Ok(ValidatedEffect {
            tool_result: None,
            containment_blocked: false,
            sensitive_output_rejection: None,
            result_snapshot: None,
        });
    };
    let evidence = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| effect_error(effect, "observation has no evidence bytes"))?;
    match observation.outcome {
        EffectOutcome::Succeeded { .. } => {
            let result = decode_tool_result(evidence)
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            if result.call != call {
                return Err(effect_error(
                    effect,
                    "tool result does not bind the exact canonical request call",
                ));
            }
            Ok(ValidatedEffect {
                tool_result: Some(result),
                containment_blocked: false,
                sensitive_output_rejection: None,
                result_snapshot: None,
            })
        }
        EffectOutcome::FailedBeforeEffect { .. }
            if effect.intent.kind == EffectKind::RunCommand =>
        {
            if !is_containment_rejection(effect, &call) {
                return Err(effect_error(
                    effect,
                    "command failure is not the exact containment rejection",
                ));
            }
            Ok(ValidatedEffect {
                tool_result: None,
                containment_blocked: true,
                sensitive_output_rejection: None,
                result_snapshot: None,
            })
        }
        EffectOutcome::FailedAfterKnownEffect { .. }
            if effect.intent.kind == EffectKind::RunCommand
                && sensitive_output_rejection.is_some() =>
        {
            let rejection = resolve_sensitive_output_rejection(
                effect,
                observation,
                evidence,
                sensitive_output_rejection,
            )?
            .ok_or_else(|| {
                effect_error(
                    effect,
                    "schema-v29 sensitive-output authority disappeared during projection",
                )
            })?;
            Ok(ValidatedEffect {
                tool_result: None,
                containment_blocked: false,
                sensitive_output_rejection: Some(rejection),
                result_snapshot: None,
            })
        }
        EffectOutcome::FailedBeforeEffect { .. }
        | EffectOutcome::FailedAfterKnownEffect { .. }
        | EffectOutcome::Unknown { .. } => {
            validate_failure_text(effect, evidence, FILE_FAILURE_HEADER, 2)?;
            Ok(ValidatedEffect {
                tool_result: None,
                containment_blocked: false,
                sensitive_output_rejection: None,
                result_snapshot: None,
            })
        }
        EffectOutcome::CancelledBeforeEffect { .. } => Err(effect_error(
            effect,
            "Milestone-one coordinator has no canonical cancellation evidence",
        )),
    }
}

fn recover_run_command_provider_call(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
) -> Result<ProviderToolCall, UiProjectionError> {
    let command = decode_exact_json::<CommandSpec>(
        effect,
        &effect.request_bytes,
        "ordinary command request",
    )?;
    command
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let causal_event_id = effect.intent.causation_event_id.as_deref().ok_or_else(|| {
        effect_error(
            effect,
            "ordinary command has no causal provider terminal event",
        )
    })?;
    let mut causal_provider_effects = sprint.effects.iter().filter(|candidate| {
        candidate.intent.kind == EffectKind::ProviderRequest
            && candidate
                .terminal_event
                .as_ref()
                .is_some_and(|event| event.event_id == causal_event_id)
    });
    let provider_effect = causal_provider_effects.next().ok_or_else(|| {
        effect_error(
            effect,
            "ordinary command has no exact causal provider-turn evidence",
        )
    })?;
    if causal_provider_effects.next().is_some() {
        return Err(effect_error(
            effect,
            "ordinary command has multiple causal provider-turn effects",
        ));
    }
    validate_effect_envelope(provider_effect)?;
    validate_provider_effect(sprint, provider_effect)?;
    let graph = sprint
        .graph
        .as_ref()
        .ok_or_else(|| effect_error(effect, "ordinary command has no durable task graph"))?;
    let request = decode_turn_request(&sprint.spec, graph, &provider_effect.request_bytes)
        .map_err(|error| effect_error(provider_effect, &error.to_string()))?;
    let evidence = provider_effect.evidence_bytes.as_deref().ok_or_else(|| {
        effect_error(
            provider_effect,
            "causal provider turn has no exact terminal evidence",
        )
    })?;
    let turn = decode_turn_evidence(&sprint.spec, graph, &request, evidence)
        .map_err(|error| effect_error(provider_effect, &error.to_string()))?;
    let ProviderToolIntent::RunCommand {
        command: provider_command,
    } = &turn.call.intent
    else {
        return Err(effect_error(
            effect,
            "causal provider turn did not authorize a command",
        ));
    };
    if provider_command != &command {
        return Err(effect_error(
            effect,
            "ordinary command differs from its causal provider call",
        ));
    }
    validate_provider_call_for_effect(&turn.call, &effect.intent, &effect.request_bytes)
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    Ok(turn.call)
}

fn require_no_finish_receipt(effect: &PersistedEffect) -> Result<(), UiProjectionError> {
    if effect.finish_receipt == PersistedFinishReceipt::NotRequired {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "ordinary effect carries a typed or legacy finish receipt",
        ))
    }
}

fn try_validate_verification_effect(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
) -> Result<Option<ValidatedEffect>, UiProjectionError> {
    let Some(observation) = &effect.observation else {
        return Ok(None);
    };
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
        return Ok(None);
    }
    let evidence_bytes = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| effect_error(effect, "verification observation has no evidence"))?;
    let Ok(evidence) = serde_json::from_slice::<VerificationEffectEvidence>(evidence_bytes) else {
        return Ok(None);
    };
    let canonical_evidence =
        serde_json::to_vec(&evidence).map_err(|error| effect_error(effect, &error.to_string()))?;
    if canonical_evidence != evidence_bytes {
        return Err(effect_error(
            effect,
            "verification effect evidence is not canonical",
        ));
    }
    evidence
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let command = decode_exact_json::<grok_build_core::CommandSpec>(
        effect,
        &effect.request_bytes,
        "verification command request",
    )?;
    command
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let verification = &evidence.verification;
    let scope_matches = match verification.task_id.as_deref() {
        Some(task_id) => {
            effect.intent.task_id.as_deref() == Some(task_id) && effect.intent.worker_id.is_some()
        }
        None => effect.intent.task_id.is_none() && effect.intent.worker_id.is_none(),
    };
    if effect.intent.kind != EffectKind::RunCommand
        || effect.intent.sprint_id != sprint.spec.sprint_id
        || evidence.effect_id != effect.intent.effect_id
        || evidence.observation_id != observation.observation_id
        || verification.sprint_id != effect.intent.sprint_id
        || verification.command != command
        || verification.snapshot_id != effect.intent.input_snapshot
        || verification.policy_hash != effect.intent.policy_hash
        || verification.finished_at_unix_ms != observation.observed_at_unix_ms
        || !scope_matches
    {
        return Err(effect_error(
            effect,
            "verification evidence does not bind the exact command, snapshot, scope, policy, and observation",
        ));
    }
    if let Some(completion) = &sprint.completion
        && completion
            .verification_evidence
            .iter()
            .find(|candidate| candidate.effect_id == effect.intent.effect_id)
            != Some(&evidence)
    {
        return Err(effect_error(
            effect,
            "completion does not select this exact effect-bound verification evidence",
        ));
    }
    Ok(Some(ValidatedEffect {
        tool_result: None,
        containment_blocked: false,
        sensitive_output_rejection: None,
        result_snapshot: None,
    }))
}

enum TypedFinishRequest {
    TaskIntegration(TaskIntegrationRequest),
    Application(ChangeSet),
    Cleanup(WorkerCleanupRequest),
    Rollback(RollbackRequest),
    LiveStateCapture(SprintLiveStateCaptureRequest),
}

fn validate_typed_finish_effect(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
) -> Result<ValidatedEffect, UiProjectionError> {
    require_no_mutation_artifact(effect)?;
    let request = decode_typed_finish_request(effect)?;
    let Some(observation) = &effect.observation else {
        if effect.finish_receipt != PersistedFinishReceipt::NotRequired {
            return Err(effect_error(
                effect,
                "unfinished typed effect carries finish authority",
            ));
        }
        return Ok(empty_validated_effect());
    };
    if !matches!(observation.outcome, EffectOutcome::Succeeded { .. }) {
        if effect.finish_receipt != PersistedFinishReceipt::NotRequired {
            return Err(effect_error(
                effect,
                "unsuccessful typed effect carries finish authority",
            ));
        }
        return Ok(empty_validated_effect());
    }
    let evidence_bytes = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| effect_error(effect, "successful typed effect has no evidence"))?;
    let result_snapshot =
        validate_successful_typed_finish(sprint, effect, observation, &request, evidence_bytes)?;
    Ok(ValidatedEffect {
        tool_result: None,
        containment_blocked: false,
        sensitive_output_rejection: None,
        result_snapshot,
    })
}

fn empty_validated_effect() -> ValidatedEffect {
    ValidatedEffect {
        tool_result: None,
        containment_blocked: false,
        sensitive_output_rejection: None,
        result_snapshot: None,
    }
}

fn decode_typed_finish_request(
    effect: &PersistedEffect,
) -> Result<TypedFinishRequest, UiProjectionError> {
    match effect.intent.kind {
        EffectKind::IntegrateChangeSet => {
            let request = decode_exact_json::<TaskIntegrationRequest>(
                effect,
                &effect.request_bytes,
                "task-integration request",
            )?;
            request
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            if request.change_set.base_snapshot != effect.intent.input_snapshot {
                return Err(effect_error(
                    effect,
                    "task-integration request base differs from the authorized input snapshot",
                ));
            }
            Ok(TypedFinishRequest::TaskIntegration(request))
        }
        EffectKind::ApplyChangeSet => {
            let change_set = decode_exact_json::<ChangeSet>(
                effect,
                &effect.request_bytes,
                "change-set request",
            )?;
            change_set
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            if change_set.base_snapshot != effect.intent.input_snapshot {
                return Err(effect_error(
                    effect,
                    "change-set request base differs from the authorized input snapshot",
                ));
            }
            Ok(TypedFinishRequest::Application(change_set))
        }
        EffectKind::CleanupWorkerDomain => {
            let request = decode_exact_json::<WorkerCleanupRequest>(
                effect,
                &effect.request_bytes,
                "cleanup request",
            )?;
            request
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            Ok(TypedFinishRequest::Cleanup(request))
        }
        EffectKind::RollbackChangeSet => {
            let request = decode_exact_json::<RollbackRequest>(
                effect,
                &effect.request_bytes,
                "rollback request",
            )?;
            request
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            Ok(TypedFinishRequest::Rollback(request))
        }
        EffectKind::CaptureWorkspaceState => {
            let request = decode_exact_json::<SprintLiveStateCaptureRequest>(
                effect,
                &effect.request_bytes,
                "live-state capture request",
            )?;
            request
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            if request.plan.sprint_id != effect.intent.sprint_id
                || request.plan.expected_snapshot != effect.intent.input_snapshot
                || request.plan.policy_hash != effect.intent.policy_hash
                || effect.intent.task_id.is_some()
                || effect.intent.worker_id.is_some()
                || effect.intent.worker_lease.is_some()
            {
                return Err(effect_error(
                    effect,
                    "live-state capture request crosses sprint, snapshot, policy, or sprint scope",
                ));
            }
            Ok(TypedFinishRequest::LiveStateCapture(request))
        }
        _ => Err(effect_error(
            effect,
            "ordinary effect entered typed finish validation",
        )),
    }
}

fn validate_successful_typed_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    request: &TypedFinishRequest,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    match (request, &effect.finish_receipt) {
        (
            TypedFinishRequest::TaskIntegration(request),
            PersistedFinishReceipt::TaskIntegration(receipt),
        ) => validate_task_integration_finish(
            sprint,
            effect,
            observation,
            request,
            receipt,
            evidence_bytes,
        ),
        (
            TypedFinishRequest::Application(change_set),
            PersistedFinishReceipt::Application(receipt),
        ) => validate_application_finish(
            sprint,
            effect,
            observation,
            change_set,
            receipt,
            evidence_bytes,
        ),
        (TypedFinishRequest::Cleanup(request), PersistedFinishReceipt::WorkerCleanup(evidence)) => {
            validate_cleanup_finish(
                sprint,
                effect,
                observation,
                request,
                evidence,
                evidence_bytes,
            )
        }
        (TypedFinishRequest::Rollback(request), PersistedFinishReceipt::Rollback(receipt)) => {
            validate_rollback_finish(
                sprint,
                effect,
                observation,
                request,
                receipt,
                evidence_bytes,
            )
        }
        (
            TypedFinishRequest::LiveStateCapture(request),
            PersistedFinishReceipt::LiveStateCapture(evidence),
        ) => validate_live_state_capture_finish(
            sprint,
            effect,
            observation,
            request,
            evidence,
            evidence_bytes,
        ),
        (
            _,
            PersistedFinishReceipt::LegacyApplicationUnproven
            | PersistedFinishReceipt::LegacyTaskIntegrationUnproven,
        ) => Err(effect_error(
            effect,
            "legacy finish receipt is explicitly unproven",
        )),
        _ => Err(effect_error(
            effect,
            "successful finish-critical effect lacks its exact typed receipt variant",
        )),
    }
}

fn validate_task_integration_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    request: &TaskIntegrationRequest,
    receipt: &TaskIntegrationReceipt,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    receipt
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let integration_evidence = decode_exact_json::<TaskIntegrationEvidence>(
        effect,
        evidence_bytes,
        "task integration evidence",
    )?;
    integration_evidence
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let requested_artifact: &TaskIntegrationArtifactReference = &request.artifact;
    if receipt.sprint_id != effect.intent.sprint_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || effect.intent.task_id.as_deref() != Some(receipt.task_id.as_str())
        || effect.intent.worker_id.as_deref() != Some(receipt.worker_id.as_str())
        || receipt.worker_policy_hash != effect.intent.policy_hash
        || receipt.change_set_id != request.change_set.change_set_id
        || receipt.input_snapshot != request.change_set.base_snapshot
        || receipt.result_snapshot != request.change_set.result_snapshot
        || receipt.integrated_at_unix_ms != observation.observed_at_unix_ms
        || integration_evidence.receipt != *receipt
        || integration_evidence.artifact != *requested_artifact
    {
        return Err(effect_error(
            effect,
            "task integration evidence does not bind its exact effect, worker, change set, snapshots, artifact, and observation",
        ));
    }
    require_exact_finish_evidence(effect, &integration_evidence, evidence_bytes)?;
    require_completion_selects_integration(sprint, effect, receipt)?;
    Ok(Some(receipt.result_snapshot.clone()))
}

fn validate_application_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    change_set: &ChangeSet,
    receipt: &ApplicationReceipt,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    let application_evidence = serde_json::from_slice::<ApplicationEvidence>(evidence_bytes)
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    application_evidence
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    receipt
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    if receipt.sprint_id != effect.intent.sprint_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || effect.intent.task_id.is_some()
        || effect.intent.worker_id.is_some()
        || receipt.policy_hash != effect.intent.policy_hash
        || receipt.change_set_id != change_set.change_set_id
        || receipt.base_snapshot != change_set.base_snapshot
        || receipt.result_snapshot != change_set.result_snapshot
        || receipt.applied_at_unix_ms != observation.observed_at_unix_ms
        || application_evidence.receipt != *receipt
    {
        return Err(effect_error(
            effect,
            "application evidence does not bind its exact receipt, effect, change set, snapshots, policy, and observation",
        ));
    }
    require_exact_finish_evidence(effect, &application_evidence, evidence_bytes)?;
    require_completion_selects_application(sprint, effect, &application_evidence)?;
    Ok(Some(receipt.result_snapshot.clone()))
}

fn validate_cleanup_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    request: &WorkerCleanupRequest,
    evidence: &WorkerCleanupEvidence,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    evidence
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    if evidence.receipt.sprint_id != effect.intent.sprint_id
        || evidence.receipt.effect_id != effect.intent.effect_id
        || evidence.receipt.observation_id != observation.observation_id
        || evidence.receipt.policy_hash != effect.intent.policy_hash
        || evidence.receipt.cleaned_at_unix_ms != observation.observed_at_unix_ms
        || request.sprint_id != evidence.receipt.sprint_id
        || request.launch_id != evidence.receipt.launch_id
        || request.session_id != evidence.receipt.session_id
        || request.policy_hash != evidence.receipt.policy_hash
        || request.grant_hash != evidence.receipt.grant_hash
        || request.policy_version != evidence.receipt.policy_version
        || request.platform_backend != evidence.receipt.platform_backend
    {
        return Err(effect_error(
            effect,
            "cleanup evidence does not bind its exact effect, policy, and observation",
        ));
    }
    require_exact_finish_evidence(effect, evidence, evidence_bytes)?;
    require_completion_selects_cleanup(sprint, effect, evidence)?;
    Ok(None)
}

fn validate_rollback_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    request: &RollbackRequest,
    receipt: &RollbackReceipt,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    let rollback_evidence = serde_json::from_slice::<RollbackEvidence>(evidence_bytes)
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    rollback_evidence
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    receipt
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    if receipt.sprint_id != effect.intent.sprint_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.completed_at_unix_ms != observation.observed_at_unix_ms
        || request.sprint_id != receipt.sprint_id
        || request.application_receipt_id != receipt.application_receipt_id
        || request.application_transaction_id != receipt.application_transaction_id
        || rollback_evidence.receipt != *receipt
    {
        return Err(effect_error(
            effect,
            "rollback evidence does not bind its exact receipt, effect, and observation",
        ));
    }
    require_exact_finish_evidence(effect, &rollback_evidence, evidence_bytes)?;
    if sprint.completion.is_some() {
        return Err(effect_error(
            effect,
            "a completed sprint cannot contain a successful rollback",
        ));
    }
    Ok(None)
}

fn validate_live_state_capture_finish(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    observation: &EffectObservation,
    request: &SprintLiveStateCaptureRequest,
    evidence: &LiveStateCaptureEvidence,
    evidence_bytes: &[u8],
) -> Result<Option<Digest>, UiProjectionError> {
    evidence
        .validate_against_request(request)
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        effect_error(
            effect,
            "successful live-state capture has no durable dispatch claim",
        )
    })?;
    let RunnerEffectRequestAuthority::SprintLiveStateCapture { admission_id } = &claim.authority
    else {
        return Err(effect_error(
            effect,
            "live-state capture dispatch claim has crossed phase authority",
        ));
    };
    let receipt = &evidence.receipt;
    if receipt.sprint_id != effect.intent.sprint_id
        || receipt.effect_id != effect.intent.effect_id
        || receipt.observation_id != observation.observation_id
        || receipt.admission_id != *admission_id
        || receipt.dispatch_claim_id != claim.dispatch_claim_id
        || receipt.runner_launch_id != claim.launch_id
        || receipt.runner_session_id != claim.session_id
        || receipt.policy_hash != effect.intent.policy_hash
        || receipt.grant_hash != sprint.spec.workspace_grant.grant_hash
        || receipt.policy_version != sprint.spec.workspace_grant.policy_version
        || receipt.expected_snapshot != effect.intent.input_snapshot
        || receipt.captured_at_unix_ms != observation.observed_at_unix_ms
        || receipt.capture_started_at_unix_ms < effect.intent.created_at_unix_ms
        || claim.contract_version != CONTRACT_VERSION
        || claim.effect_id != effect.intent.effect_id
        || claim.sprint_id != effect.intent.sprint_id
        || claim.request_digest != effect.intent.request_digest
        || claim.policy_hash != effect.intent.policy_hash
        || claim.input_snapshot != effect.intent.input_snapshot
        || claim.running_boundary_id.is_some()
    {
        return Err(effect_error(
            effect,
            "live-state capture evidence crosses its exact effect, claim, lifecycle, grant, policy, snapshot, or observation",
        ));
    }
    require_exact_finish_evidence(effect, evidence, evidence_bytes)?;
    require_terminal_selects_live_state_capture(sprint, effect, evidence)?;
    Ok(None)
}

fn require_terminal_selects_live_state_capture(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    evidence: &LiveStateCaptureEvidence,
) -> Result<(), UiProjectionError> {
    let selected = match (&sprint.completion, &sprint.terminal_outcome) {
        (None, None) => true,
        (Some(completion), None) => matches!(
            &completion.live_state_authority,
            PersistedCompletionLiveStateAuthority::Linked {
                capture_evidence,
                ..
            } if capture_evidence == evidence
        ),
        (None, Some(terminal)) => matches!(
            &terminal.proof,
            PersistedTerminalProof::LiveStateDriftBlocked {
                capture_evidence,
                ..
            } if capture_evidence.as_ref() == evidence
        ),
        (Some(_), Some(_)) => false,
    };
    if selected {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "terminal authority omits or replaces the exact live-state capture evidence",
        ))
    }
}

fn require_exact_finish_evidence<T: Serialize>(
    effect: &PersistedEffect,
    evidence: &T,
    evidence_bytes: &[u8],
) -> Result<(), UiProjectionError> {
    let canonical =
        serde_json::to_vec(evidence).map_err(|error| effect_error(effect, &error.to_string()))?;
    if canonical == evidence_bytes {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "typed finish evidence is not the exact canonical observation evidence",
        ))
    }
}

fn require_completion_selects_integration(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    receipt: &TaskIntegrationReceipt,
) -> Result<(), UiProjectionError> {
    if sprint.completion.as_ref().is_none_or(|completion| {
        completion
            .task_integrations
            .iter()
            .any(|candidate| candidate == receipt)
    }) {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "completion omits or replaces the typed task integration receipt",
        ))
    }
}

fn require_completion_selects_application(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    evidence: &ApplicationEvidence,
) -> Result<(), UiProjectionError> {
    let selected = sprint.completion.as_ref().is_none_or(|completion| {
        matches!(
            &completion.application,
            grok_build_core::PersistedCompletionApplication::Applied {
                application_evidence,
                ..
            } if application_evidence == evidence
        )
    });
    if selected {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "completion omits or replaces the typed application evidence",
        ))
    }
}

fn require_completion_selects_cleanup(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    evidence: &WorkerCleanupEvidence,
) -> Result<(), UiProjectionError> {
    if sprint.completion.as_ref().is_none_or(|completion| {
        completion
            .worker_cleanup_evidence
            .iter()
            .any(|candidate| candidate == evidence)
    }) {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "completion omits or replaces the typed cleanup evidence",
        ))
    }
}

fn decode_exact_json<T>(
    effect: &PersistedEffect,
    bytes: &[u8],
    entity: &str,
) -> Result<T, UiProjectionError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let value = serde_json::from_slice::<T>(bytes)
        .map_err(|error| effect_error(effect, &format!("{entity}: {error}")))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| effect_error(effect, &format!("{entity}: {error}")))?;
    if canonical != bytes {
        return Err(effect_error(effect, &format!("{entity} is not canonical")));
    }
    Ok(value)
}

fn validate_effect_envelope(effect: &PersistedEffect) -> Result<(), UiProjectionError> {
    effect
        .intent
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    effect
        .proposed_event
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    validate_identifier("effect id", &effect.intent.effect_id)?;
    validate_identifier("idempotency key", &effect.intent.idempotency_key)?;
    if Digest::sha256(&effect.request_bytes) != effect.intent.request_digest {
        return Err(effect_error(effect, "request preimage digest mismatch"));
    }
    let proposal_matches = matches!(
        &effect.proposed_event.payload,
        AgentEventKind::ToolProposed {
            tool_call_id,
            tool_name,
        } if tool_call_id == &effect.intent.idempotency_key
            && tool_name == effect.intent.kind.tool_name()
    );
    if !proposal_matches
        || effect.proposed_event.sprint_id != effect.intent.sprint_id
        || effect.proposed_event.task_id != effect.intent.task_id
        || effect.proposed_event.worker_id != effect.intent.worker_id
    {
        return Err(effect_error(
            effect,
            "proposal event does not exactly bind the effect intent",
        ));
    }

    match (
        &effect.observation,
        &effect.evidence_bytes,
        &effect.terminal_event,
    ) {
        (None, None, None) => Ok(()),
        (Some(observation), Some(evidence), Some(terminal)) => {
            observation
                .validate_against(&effect.intent)
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            terminal
                .validate()
                .map_err(|error| effect_error(effect, &error.to_string()))?;
            if evidence.is_empty()
                || Digest::sha256(evidence) != *observation.outcome.evidence_digest()
            {
                return Err(effect_error(effect, "terminal evidence digest mismatch"));
            }
            let terminal_matches = matches!(
                &terminal.payload,
                AgentEventKind::ToolFinished {
                    tool_call_id,
                    succeeded,
                } if tool_call_id == &effect.intent.idempotency_key
                    && *succeeded == observation.outcome.succeeded()
            );
            if !terminal_matches
                || terminal.sprint_id != effect.intent.sprint_id
                || terminal.task_id != effect.intent.task_id
                || terminal.worker_id != effect.intent.worker_id
                || terminal.causation_id.as_deref() != Some(effect.proposed_event.event_id.as_str())
            {
                return Err(effect_error(
                    effect,
                    "terminal event does not exactly bind the observation",
                ));
            }
            Ok(())
        }
        _ => Err(effect_error(
            effect,
            "observation, evidence, and terminal event must be present together",
        )),
    }
}

fn validate_provider_effect(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
) -> Result<(), UiProjectionError> {
    if effect.intent.task_id.is_none() {
        let decoded = decode_planning_request(&effect.request_bytes)
            .map_err(|error| effect_error(effect, &error.to_string()))?;
        if decoded != sprint.spec {
            return Err(effect_error(
                effect,
                "planning request differs from the durable sprint",
            ));
        }
        validate_provider_outcome(sprint, effect, None)
    } else {
        let graph = sprint
            .graph
            .as_ref()
            .ok_or_else(|| effect_error(effect, "provider turn exists before graph attachment"))?;
        let request = decode_turn_request(&sprint.spec, graph, &effect.request_bytes)
            .map_err(|error| effect_error(effect, &error.to_string()))?;
        if Some(request.task_id.as_str()) != effect.intent.task_id.as_deref()
            || request.sprint_id != effect.intent.sprint_id
        {
            return Err(effect_error(
                effect,
                "provider-turn request context differs from its effect intent",
            ));
        }
        validate_provider_outcome(sprint, effect, Some(&request))
    }
}

fn validate_provider_outcome(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    turn_request: Option<&grok_build_providers::ProviderTurnRequest>,
) -> Result<(), UiProjectionError> {
    let Some(observation) = &effect.observation else {
        return Ok(());
    };
    let evidence = effect
        .evidence_bytes
        .as_deref()
        .ok_or_else(|| effect_error(effect, "provider observation has no evidence"))?;
    match observation.outcome {
        EffectOutcome::Succeeded { .. } => {
            if let Some(request) = turn_request {
                let graph = sprint.graph.as_ref().ok_or_else(|| {
                    effect_error(effect, "provider turn has no durable task graph")
                })?;
                decode_turn_evidence(&sprint.spec, graph, request, evidence)
                    .map_err(|error| effect_error(effect, &error.to_string()))?;
            } else {
                decode_planning_evidence(&sprint.spec, evidence)
                    .map_err(|error| effect_error(effect, &error.to_string()))?;
            }
            Ok(())
        }
        EffectOutcome::Unknown { .. } => {
            validate_failure_text(effect, evidence, PROVIDER_FAILURE_HEADER, 3)
        }
        EffectOutcome::FailedBeforeEffect { .. }
        | EffectOutcome::FailedAfterKnownEffect { .. }
        | EffectOutcome::CancelledBeforeEffect { .. } => Err(effect_error(
            effect,
            "Milestone-one provider effects support only success or unknown failure evidence",
        )),
    }
}

fn validate_tool_call_identity(
    effect: &PersistedEffect,
    call: &ProviderToolCall,
) -> Result<(), UiProjectionError> {
    validate_provider_call_for_effect(call, &effect.intent, &effect.request_bytes)
        .map_err(|error| effect_error(effect, &error.to_string()))
}

fn validate_sensitive_output_rejection_effect(
    effect: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &[u8],
    authority: &PersistedCommandOutputSensitiveRejectionV1,
) -> Result<CommandOutputSensitiveRejectionAnchorV1, UiProjectionError> {
    authority
        .anchor
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    authority
        .cleanup
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    authority
        .closure
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let rejection = &authority.anchor;
    let cleanup = &authority.cleanup;
    let closure = &authority.closure;
    let canonical = rejection
        .canonical_evidence_bytes()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    if canonical != evidence
        || effect.intent.kind != EffectKind::RunCommand
        || rejection.effect_id != effect.intent.effect_id
        || rejection.observation_id != observation.observation_id
        || observation.effect_id != effect.intent.effect_id
        || !matches!(
            observation.outcome,
            EffectOutcome::FailedAfterKnownEffect { .. }
        )
        || observation.outcome.evidence_digest() != &Digest::sha256(evidence)
        || cleanup.capture_id != rejection.capture_id
        || cleanup.effect_id != rejection.effect_id
        || cleanup.observation_id != rejection.observation_id
        || cleanup.rejection_anchor_digest != rejection.rejection_anchor_digest
        || cleanup.detector_policy != rejection.detector_policy
        || cleanup.runner_cleanup.journal_id != rejection.runner_journal_id
        || cleanup.runner_cleanup.rejected_terminal_journal_head
            != rejection.rejected_terminal_journal_head
        || closure.capture_id != rejection.capture_id
        || closure.effect_id != rejection.effect_id
        || closure.observation_id != rejection.observation_id
        || closure.rejection_anchor_digest != rejection.rejection_anchor_digest
        || closure.cleanup_receipt_digest != cleanup.cleanup_receipt_digest
        || closure.command_domain_cleanup_proof_id != cleanup.command_domain_cleanup_proof_id
        || closure.closed_at_unix_ms > observation.observed_at_unix_ms
    {
        return Err(effect_error(
            effect,
            "sensitive-output rejection does not bind the exact durable schema-v29 anchor, cleanup, closure, command effect, and observation",
        ));
    }
    Ok(rejection.clone())
}

fn resolve_sensitive_output_rejection(
    effect: &PersistedEffect,
    observation: &EffectObservation,
    evidence: &[u8],
    authority: Option<&PersistedCommandOutputSensitiveRejectionV1>,
) -> Result<Option<CommandOutputSensitiveRejectionAnchorV1>, UiProjectionError> {
    authority
        .map(|authority| {
            validate_sensitive_output_rejection_effect(effect, observation, evidence, authority)
        })
        .transpose()
}

struct LinkedMutation {
    result_snapshot: Digest,
    change_set_id: String,
    path: String,
    mutation: UiMutationKind,
}

fn validate_mutation_link(
    sprint: &PersistedSprint,
    effect: &PersistedEffect,
    result: &ProviderToolResult,
) -> Result<LinkedMutation, UiProjectionError> {
    let PersistedMutationArtifact::Linked {
        link,
        snapshot,
        change_set,
    } = &effect.mutation_artifact
    else {
        return Err(effect_error(
            effect,
            "successful mutation lacks an atomic artifact link",
        ));
    };
    link.validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    snapshot
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    change_set
        .validate()
        .map_err(|error| effect_error(effect, &error.to_string()))?;
    let observation = effect
        .observation
        .as_ref()
        .ok_or_else(|| effect_error(effect, "linked mutation has no observation"))?;
    let (expected_operation, mutation, path) = expected_mutation_operation(effect, result)?;
    if link.sprint_id != sprint.spec.sprint_id
        || link.effect_id != effect.intent.effect_id
        || link.observation_id != observation.observation_id
        || link.input_snapshot != effect.intent.input_snapshot
        || link.result_snapshot != snapshot.snapshot_id
        || link.change_set_id != change_set.change_set_id
        || snapshot.grant_hash != sprint.spec.workspace_grant.grant_hash
        || change_set.base_snapshot != effect.intent.input_snapshot
        || change_set.result_snapshot != snapshot.snapshot_id
        || change_set.operations.as_slice() != [expected_operation]
    {
        return Err(effect_error(
            effect,
            "mutation link, snapshot, change set, and exact tool result disagree",
        ));
    }
    validate_path(&path)?;
    Ok(LinkedMutation {
        result_snapshot: snapshot.snapshot_id.clone(),
        change_set_id: change_set.change_set_id.clone(),
        path,
        mutation,
    })
}

fn expected_mutation_operation(
    effect: &PersistedEffect,
    result: &ProviderToolResult,
) -> Result<(FileOperation, UiMutationKind, String), UiProjectionError> {
    match (&result.call.intent, &result.output) {
        (
            ProviderToolIntent::CreateRegularFile { path, .. },
            grok_build_providers::ProviderToolOutput::RegularFileCreated {
                path: output_path,
                result_hash,
            },
        ) if path == output_path => Ok((
            FileOperation::Create {
                path: path.clone(),
                result_hash: result_hash.clone(),
            },
            UiMutationKind::Create,
            path.to_str()
                .ok_or_else(|| effect_error(effect, "mutation path is not UTF-8"))?
                .into(),
        )),
        (
            ProviderToolIntent::ReplaceRegularFile { path, .. },
            grok_build_providers::ProviderToolOutput::RegularFileReplaced {
                path: output_path,
                previous_hash,
                result_hash,
            },
        ) if path == output_path => Ok((
            FileOperation::Modify {
                path: path.clone(),
                base_hash: previous_hash.clone(),
                result_hash: result_hash.clone(),
            },
            UiMutationKind::Replace,
            path.to_str()
                .ok_or_else(|| effect_error(effect, "mutation path is not UTF-8"))?
                .into(),
        )),
        (
            ProviderToolIntent::DeleteRegularFile { path, .. },
            grok_build_providers::ProviderToolOutput::RegularFileDeleted {
                path: output_path,
                previous_hash,
            },
        ) if path == output_path => Ok((
            FileOperation::Delete {
                path: path.clone(),
                base_hash: previous_hash.clone(),
            },
            UiMutationKind::Delete,
            path.to_str()
                .ok_or_else(|| effect_error(effect, "mutation path is not UTF-8"))?
                .into(),
        )),
        _ => Err(effect_error(
            effect,
            "tool evidence is not one exact successful mutation",
        )),
    }
}

fn require_no_mutation_artifact(effect: &PersistedEffect) -> Result<(), UiProjectionError> {
    if effect.mutation_artifact == PersistedMutationArtifact::NotRequired {
        Ok(())
    } else {
        Err(effect_error(
            effect,
            "non-successful or non-mutation effect carries mutation artifacts",
        ))
    }
}

fn validate_failure_text(
    effect: &PersistedEffect,
    bytes: &[u8],
    header: &str,
    expected_lines: usize,
) -> Result<(), UiProjectionError> {
    let text = str::from_utf8(bytes)
        .map_err(|_| effect_error(effect, "failure evidence is not valid UTF-8"))?;
    if text.contains('\0') || !text.ends_with('\n') {
        return Err(effect_error(
            effect,
            "failure evidence must end with one line feed and contain no NUL",
        ));
    }
    let lines = text
        .strip_suffix('\n')
        .unwrap_or(text)
        .split('\n')
        .collect::<Vec<_>>();
    let shape_valid = lines.len() == expected_lines
        && lines.first() == Some(&header)
        && lines.last().is_some_and(|line| {
            line.strip_prefix("error=")
                .is_some_and(|message| !message.trim().is_empty())
        });
    let provider_middle_valid =
        expected_lines != 3 || lines.get(1) == Some(&"effect_status=unknown");
    if !shape_valid || !provider_middle_valid {
        return Err(effect_error(
            effect,
            "failure evidence is not the exact Milestone-one text envelope",
        ));
    }
    Ok(())
}

fn project_terminal(
    sprint: &PersistedSprint,
    builder: &mut ProjectionBuilder,
) -> Result<(), UiProjectionError> {
    match (&sprint.completion, &sprint.terminal_outcome) {
        (Some(_), Some(_)) => Err(UiProjectionError::InvalidTerminal(
            "successful and unsuccessful terminal evidence coexist".into(),
        )),
        (Some(completion), None) => {
            TerminalBanner::from_state(SprintState::Completed, Some(completion), None)
                .map_err(|error| UiProjectionError::InvalidTerminal(error.to_string()))?
                .ok_or_else(|| {
                    UiProjectionError::InvalidTerminal(
                        "completion evidence produced no terminal banner".into(),
                    )
                })?;
            if completion.receipt.sprint_id != sprint.spec.sprint_id {
                return Err(UiProjectionError::InvalidTerminal(
                    "completion evidence belongs to a different sprint".into(),
                ));
            }
            builder.push(
                &completion.event,
                DurableUiEventKind::SprintCompleted {
                    receipt_id: completion.receipt.receipt_id.clone(),
                    final_snapshot: completion.receipt.final_snapshot.clone(),
                    criteria_status: CriteriaAggregateStatus::Satisfied,
                },
            )
        }
        (None, Some(terminal)) => {
            let banner = TerminalBanner::from_persisted_terminal(terminal)
                .map_err(|error| UiProjectionError::InvalidTerminal(error.to_string()))?;
            terminal
                .evidence
                .validate()
                .map_err(|error| UiProjectionError::InvalidTerminal(error.to_string()))?;
            terminal
                .event
                .validate()
                .map_err(|error| UiProjectionError::InvalidTerminal(error.to_string()))?;
            let canonical = serde_json::to_vec(&terminal.evidence)
                .map_err(|error| UiProjectionError::CanonicalEncoding(error.to_string()))?;
            if canonical != terminal.evidence_bytes
                || Digest::sha256(&terminal.evidence_bytes) != terminal.evidence_digest
            {
                return Err(UiProjectionError::InvalidTerminal(
                    "terminal evidence is noncanonical or has a digest mismatch".into(),
                ));
            }
            let state = map_non_success_state(terminal.evidence.state);
            let expected_sprint_state = map_terminal_sprint_state(terminal.evidence.state);
            let event_matches = matches!(
                &terminal.event.payload,
                AgentEventKind::SprintTerminalRecorded {
                    record_id,
                    state: event_state,
                    evidence_digest,
                } if record_id == &terminal.evidence.record_id
                    && *event_state == terminal.evidence.state
                    && evidence_digest == &terminal.evidence_digest
            );
            if terminal.terminal_state != expected_sprint_state
                || terminal.evidence.sprint_id != sprint.spec.sprint_id
                || terminal.event.sprint_id != sprint.spec.sprint_id
                || terminal.event.event_id != terminal.evidence.record_id
                || !event_matches
            {
                return Err(UiProjectionError::InvalidTerminal(
                    "terminal state, event, record, or sprint identity differs".into(),
                ));
            }
            builder.push(
                &terminal.event,
                DurableUiEventKind::SprintTerminal {
                    state,
                    record_id: terminal.evidence.record_id.clone(),
                    evidence_digest: terminal.evidence_digest.clone(),
                    reason: terminal.evidence.reason.clone(),
                    cause: banner.terminal_cause().cloned(),
                    safe_next_action: banner.safe_next_action(),
                },
            )
        }
        (None, None) => Ok(()),
    }
}

const fn map_non_success_state(state: NonSuccessTerminalState) -> UiNonSuccessTerminalState {
    match state {
        NonSuccessTerminalState::Blocked => UiNonSuccessTerminalState::Blocked,
        NonSuccessTerminalState::Failed => UiNonSuccessTerminalState::Failed,
        NonSuccessTerminalState::Canceled => UiNonSuccessTerminalState::Canceled,
        NonSuccessTerminalState::Unknown => UiNonSuccessTerminalState::Unknown,
    }
}

const fn map_terminal_sprint_state(state: NonSuccessTerminalState) -> SprintState {
    match state {
        NonSuccessTerminalState::Blocked => SprintState::Blocked,
        NonSuccessTerminalState::Failed => SprintState::Failed,
        NonSuccessTerminalState::Canceled => SprintState::Canceled,
        NonSuccessTerminalState::Unknown => SprintState::Unknown,
    }
}

fn validate_payload(payload: &DurableUiEventKind) -> Result<(), UiProjectionError> {
    match payload {
        DurableUiEventKind::EffectProposed {
            effect_id,
            idempotency_key,
            ..
        } => {
            validate_identifier("effect id", effect_id)?;
            validate_identifier("idempotency key", idempotency_key)
        }
        DurableUiEventKind::EffectRunning { effect_id }
        | DurableUiEventKind::EffectSucceeded { effect_id, .. }
        | DurableUiEventKind::EffectFailedBefore { effect_id, .. }
        | DurableUiEventKind::EffectFailedAfter { effect_id, .. }
        | DurableUiEventKind::EffectUnknown { effect_id, .. } => {
            validate_identifier("effect id", effect_id)
        }
        DurableUiEventKind::SensitiveOutputRejected {
            effect_id,
            detector_policy_id,
            detector_policy_version,
        } => {
            validate_identifier("effect id", effect_id)?;
            let expected = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
            if detector_policy_id != &expected.policy_id
                || *detector_policy_version != expected.policy_version
            {
                return Err(UiProjectionError::InvalidProjection(
                    "sensitive-output UI event requires the exact repository-owned v1 detector policy"
                        .into(),
                ));
            }
            Ok(())
        }
        DurableUiEventKind::SnapshotLinked {
            effect_id,
            change_set_id,
            path,
            ..
        } => {
            validate_identifier("effect id", effect_id)?;
            validate_identifier("change-set id", change_set_id)?;
            validate_path(path)
        }
        DurableUiEventKind::ContainmentBlocked { effect_id, reason } => {
            validate_identifier("effect id", effect_id)?;
            validate_visible_text("containment reason", reason, MAX_TERMINAL_REASON_BYTES)
        }
        DurableUiEventKind::SprintTerminal {
            state,
            record_id,
            reason,
            cause,
            safe_next_action,
            ..
        } => {
            validate_identifier("terminal record id", record_id)?;
            validate_visible_text("terminal reason", reason, MAX_TERMINAL_REASON_BYTES)?;
            match (state, cause, safe_next_action) {
                (
                    UiNonSuccessTerminalState::Blocked,
                    Some(UiTerminalCause::LiveStateDrift {
                        capture_receipt_id,
                        expected_snapshot,
                        observed_snapshot,
                    }),
                    Some(UiSafeNextAction::StartNewSprintFromObservedWorkspace),
                ) => {
                    validate_identifier("live-state drift capture receipt id", capture_receipt_id)?;
                    if expected_snapshot == observed_snapshot {
                        return Err(UiProjectionError::InvalidProjection(
                            "live-state drift terminal requires distinct expected and observed snapshots"
                                .into(),
                        ));
                    }
                    Ok(())
                }
                (_, None, None) => Ok(()),
                _ => Err(UiProjectionError::InvalidProjection(
                    "typed terminal cause, state, and safe next action disagree".into(),
                )),
            }
        }
        DurableUiEventKind::SprintCompleted {
            receipt_id,
            criteria_status,
            ..
        } => {
            validate_identifier("completion receipt id", receipt_id)?;
            if *criteria_status != CriteriaAggregateStatus::Satisfied {
                return Err(UiProjectionError::InvalidProjection(
                    "SprintCompleted requires the derived aggregate status Satisfied".into(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), UiProjectionError> {
    if value.trim().is_empty() || value.len() > MAX_UI_IDENTIFIER_BYTES || value.contains('\0') {
        return Err(UiProjectionError::InvalidProjection(format!(
            "{field} must contain 1..={MAX_UI_IDENTIFIER_BYTES} visible bytes and no NUL"
        )));
    }
    Ok(())
}

fn validate_visible_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), UiProjectionError> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(UiProjectionError::InvalidProjection(format!(
            "{field} must contain 1..={maximum} visible bytes and no NUL"
        )));
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), UiProjectionError> {
    if value.is_empty() || value.len() > MAX_UI_PATH_BYTES || value.contains('\0') {
        return Err(UiProjectionError::InvalidProjection(format!(
            "UI path must contain 1..={MAX_UI_PATH_BYTES} bytes and no NUL"
        )));
    }
    Ok(())
}

fn invalid_sprint(reason: String) -> UiProjectionError {
    UiProjectionError::InvalidSprint(reason)
}

fn effect_error(effect: &PersistedEffect, reason: &str) -> UiProjectionError {
    UiProjectionError::InvalidEffect {
        effect_id: effect.intent.effect_id.clone(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, EffectIntent, ExecutionOrigin, PathScope,
        PersistedFinishReceipt, PersistedMutationArtifact, ProviderProfile, SprintBudget,
        SprintSpec, TaskGraphProvenance, WorkerCleanupBackend, WorkerLease, WorkspaceGrant,
        WorkspaceNetworkPolicy, WorkspacePermissions,
    };
    use grok_build_providers::{ProviderToolOutput, encode_tool_call, encode_tool_result};

    use super::*;

    const SPRINT_ID: &str = "sprint-ui-cleanup";
    const TASK_ID: &str = "task-ui-cleanup";
    const WORKER_ID: &str = "worker-ui-cleanup";

    fn fixture_digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn fixture_spec() -> SprintSpec {
        SprintSpec {
            sprint_id: SPRINT_ID.into(),
            objective: "exercise cleanup projection semantics".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "projection-safe".into(),
                description: "the projection remains fail closed".into(),
                kind: AcceptanceKind::HumanJudgment,
            }],
            provider: ProviderProfile {
                backend_id: "fixture-provider".into(),
                model_id: "fixture-model".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudget {
                max_tasks: 1,
                max_attempts_per_task: 1,
                max_tool_calls: 4,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: "grant-ui-cleanup".into(),
                canonical_root: PathBuf::from("/tmp/grok-build-ui-cleanup"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: fixture_digest("grant"),
            },
            base_snapshot: fixture_digest("base-snapshot"),
        }
    }

    fn fixture_sprint(effects: Vec<PersistedEffect>) -> PersistedSprint {
        PersistedSprint {
            spec: fixture_spec(),
            graph: None,
            graph_provenance: TaskGraphProvenance::NotAttached,
            created_at_unix_ms: 50,
            events: Vec::new(),
            effects,
            completion: None,
            legacy_completion: None,
            legacy_task_attempt_completion_invalidation: None,
            terminal_outcome: None,
        }
    }

    fn fixture_lease() -> WorkerLease {
        WorkerLease::new(
            SPRINT_ID.into(),
            1,
            TASK_ID.into(),
            WORKER_ID.into(),
            vec![PathScope::Workspace],
            100,
        )
        .expect("valid fixture lease")
    }

    fn proposed_event(intent: &EffectIntent, sequence: u64) -> AgentEvent {
        AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: format!("{}:proposed", intent.effect_id),
            sprint_id: intent.sprint_id.clone(),
            task_id: intent.task_id.clone(),
            worker_id: intent.worker_id.clone(),
            causation_id: None,
            correlation_id: intent.correlation_id.clone(),
            policy_hash: Some(intent.policy_hash.clone()),
            occurred_at_unix_ms: intent.created_at_unix_ms,
            payload: AgentEventKind::ToolProposed {
                tool_call_id: intent.idempotency_key.clone(),
                tool_name: intent.kind.tool_name().into(),
            },
        }
    }

    fn with_terminal_observation(
        mut effect: PersistedEffect,
        outcome: EffectOutcome,
        evidence_bytes: Vec<u8>,
        sequence: u64,
    ) -> PersistedEffect {
        let succeeded = outcome.succeeded();
        let observation_id = format!("{}:observation", effect.intent.effect_id);
        effect.observation = Some(EffectObservation {
            contract_version: CONTRACT_VERSION,
            observation_id,
            effect_id: effect.intent.effect_id.clone(),
            idempotency_key: effect.intent.idempotency_key.clone(),
            sprint_id: effect.intent.sprint_id.clone(),
            task_id: effect.intent.task_id.clone(),
            worker_id: effect.intent.worker_id.clone(),
            worker_lease: effect.intent.worker_lease.clone(),
            correlation_id: effect.intent.correlation_id.clone(),
            kind: effect.intent.kind,
            request_digest: effect.intent.request_digest.clone(),
            policy_hash: effect.intent.policy_hash.clone(),
            input_snapshot: effect.intent.input_snapshot.clone(),
            outcome,
            observed_at_unix_ms: effect.intent.created_at_unix_ms + 1,
        });
        effect.evidence_bytes = Some(evidence_bytes);
        effect.terminal_event = Some(AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence,
            event_id: format!("{}:terminal", effect.intent.effect_id),
            sprint_id: effect.intent.sprint_id.clone(),
            task_id: effect.intent.task_id.clone(),
            worker_id: effect.intent.worker_id.clone(),
            causation_id: Some(effect.proposed_event.event_id.clone()),
            correlation_id: effect.intent.correlation_id.clone(),
            policy_hash: Some(effect.intent.policy_hash.clone()),
            occurred_at_unix_ms: effect.intent.created_at_unix_ms + 1,
            payload: AgentEventKind::ToolFinished {
                tool_call_id: effect.intent.idempotency_key.clone(),
                succeeded,
            },
        });
        effect
    }

    fn pending_cleanup_effect(sequence: u64) -> PersistedEffect {
        let spec = fixture_spec();
        let policy_hash = fixture_digest("execution-policy");
        let request = WorkerCleanupRequest {
            contract_version: CONTRACT_VERSION,
            sprint_id: SPRINT_ID.into(),
            launch_id: "launch-ui-cleanup".into(),
            session_id: "session-ui-cleanup".into(),
            policy_hash: policy_hash.clone(),
            grant_hash: spec.workspace_grant.grant_hash,
            policy_version: spec.workspace_grant.policy_version,
            platform_backend: WorkerCleanupBackend::LinuxCgroupV2,
        };
        let request_bytes = serde_json::to_vec(&request).expect("canonical cleanup request");
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: "cleanup-effect".into(),
            idempotency_key: "cleanup-key".into(),
            sprint_id: SPRINT_ID.into(),
            task_id: None,
            worker_id: None,
            worker_lease: Some(fixture_lease()),
            causation_event_id: None,
            correlation_id: "cleanup-correlation".into(),
            kind: EffectKind::CleanupWorkerDomain,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash,
            input_snapshot: spec.base_snapshot,
            created_at_unix_ms: 200,
        };
        let proposed_event = proposed_event(&intent, sequence);
        PersistedEffect {
            intent,
            request_bytes,
            proposed_event,
            dispatch_claim: None,
            observation: None,
            evidence_bytes: None,
            terminal_event: None,
            mutation_artifact: PersistedMutationArtifact::NotRequired,
            finish_receipt: PersistedFinishReceipt::NotRequired,
        }
    }

    fn successful_read_effect(proposal_sequence: u64, label: &str) -> PersistedEffect {
        let call = ProviderToolCall {
            sprint_id: SPRINT_ID.into(),
            task_id: TASK_ID.into(),
            sequence: 1,
            call_id: format!("read-call-{label}"),
            idempotency_key: format!("read-key-{label}"),
            intent: ProviderToolIntent::ReadRelativeFile {
                path: PathBuf::from("src/lib.rs"),
                max_bytes: 1_024,
            },
        };
        let request_bytes = encode_tool_call(&call).expect("canonical read request");
        let contents = format!("exact read evidence: {label}\n").into_bytes();
        let result = ProviderToolResult {
            result_id: format!("read-result-{label}"),
            call: call.clone(),
            output: ProviderToolOutput::RelativeFileRead {
                path: PathBuf::from("src/lib.rs"),
                content_hash: Digest::sha256(&contents),
                contents,
            },
        };
        let evidence_bytes = encode_tool_result(&result).expect("canonical read evidence");
        let lease = fixture_lease();
        let task_effect_key = format!(
            "task-attempt-{}-{}",
            Digest::sha256(lease.lease_id.as_bytes()),
            call.idempotency_key
        );
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("read-effect-{label}"),
            idempotency_key: task_effect_key,
            sprint_id: SPRINT_ID.into(),
            task_id: Some(TASK_ID.into()),
            worker_id: Some(WORKER_ID.into()),
            worker_lease: Some(lease),
            causation_event_id: None,
            correlation_id: format!("{SPRINT_ID}:walking-skeleton-v1"),
            kind: EffectKind::ReadRelativeFile,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: fixture_digest("execution-policy"),
            input_snapshot: fixture_spec().base_snapshot,
            created_at_unix_ms: 300 + proposal_sequence,
        };
        let proposed_event = proposed_event(&intent, proposal_sequence);
        let effect = PersistedEffect {
            intent,
            request_bytes,
            proposed_event,
            dispatch_claim: None,
            observation: None,
            evidence_bytes: None,
            terminal_event: None,
            mutation_artifact: PersistedMutationArtifact::NotRequired,
            finish_receipt: PersistedFinishReceipt::NotRequired,
        };
        with_terminal_observation(
            effect,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence_bytes,
            proposal_sequence + 1,
        )
    }

    #[test]
    fn pending_cleanup_allows_a_later_exact_task_effect_without_claiming_success_or_done() {
        let cleanup = pending_cleanup_effect(1);
        let task_effect = successful_read_effect(2, "later");
        let sprint = fixture_sprint(vec![cleanup, task_effect]);

        let projection = DurableUiProjection::from_persisted(&sprint)
            .expect("a pending process cleanup does not poison workspace identity");

        assert!(projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectProposed { effect_id, .. }
                if effect_id == "cleanup-effect"
        )));
        assert!(!projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectUnknown { effect_id, .. }
                | DurableUiEventKind::EffectSucceeded { effect_id, .. }
                if effect_id == "cleanup-effect"
        )));
        assert!(projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectSucceeded { effect_id, .. }
                if effect_id == "read-effect-later"
        )));
        assert!(!projection.is_done());
    }

    #[test]
    fn interleaved_effect_lifecycles_merge_by_durable_source_sequence() {
        let mut first = successful_read_effect(1, "first-interleaved");
        first
            .terminal_event
            .as_mut()
            .expect("first effect is terminal")
            .sequence = 4;
        let second = successful_read_effect(2, "second-interleaved");

        let projection = DurableUiProjection::from_persisted(&fixture_sprint(vec![first, second]))
            .expect("interleaved durable effect lifecycles remain projectable");
        let source_sequences = projection
            .events()
            .iter()
            .map(DurableUiEvent::source_sequence)
            .collect::<Vec<_>>();

        assert_eq!(source_sequences, [1, 2, 3, 3, 4, 4]);
        assert!(
            projection
                .events()
                .iter()
                .enumerate()
                .all(|(index, event)| {
                    event.ordinal()
                        == u64::try_from(index)
                            .expect("bounded event index")
                            .saturating_add(1)
                })
        );
    }

    #[test]
    fn incomplete_cleanup_fails_the_completion_effect_predicate() {
        let cleanup = pending_cleanup_effect(1);
        let task_effect = successful_read_effect(2, "terminal");

        assert!(!all_effects_succeeded(&[cleanup, task_effect]));
    }

    #[test]
    fn explicit_unknown_cleanup_remains_an_uncertain_unknown() {
        let evidence_bytes = b"cleanup reconciliation is uncertain".to_vec();
        let cleanup = with_terminal_observation(
            pending_cleanup_effect(1),
            EffectOutcome::Unknown {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            evidence_bytes,
            2,
        );
        let projection = DurableUiProjection::from_persisted(&fixture_sprint(vec![cleanup]))
            .expect("explicit cleanup uncertainty is representable");

        assert!(projection.events().iter().any(|event| matches!(
            event.payload(),
            DurableUiEventKind::EffectUnknown {
                effect_id,
                evidence_digest: Some(_),
                reason: UiUnknownReason::UncertainObservation,
            } if effect_id == "cleanup-effect"
        )));
        assert!(!projection.is_done());
    }

    #[test]
    fn missing_non_cleanup_observation_still_poisons_later_snapshot_authority() {
        let mut missing_read = successful_read_effect(1, "missing");
        missing_read.observation = None;
        missing_read.evidence_bytes = None;
        missing_read.terminal_event = None;
        let later_read = successful_read_effect(2, "after-missing");

        assert!(matches!(
            DurableUiProjection::from_persisted(&fixture_sprint(vec![missing_read, later_read])),
            Err(UiProjectionError::InvalidEffect { effect_id, reason })
                if effect_id == "read-effect-after-missing"
                    && reason.contains("snapshot authority became uncertain")
        ));
    }

    #[test]
    fn drift_terminal_payload_requires_blocked_state_and_exact_safe_action() {
        let expected_snapshot = fixture_digest("expected drift snapshot");
        let observed_snapshot = fixture_digest("observed drift snapshot");
        let payload = DurableUiEventKind::SprintTerminal {
            state: UiNonSuccessTerminalState::Blocked,
            record_id: "terminal-live-state-drift".into(),
            evidence_digest: fixture_digest("terminal evidence"),
            reason: "Live workspace state differs from the selected completion snapshot.".into(),
            cause: Some(UiTerminalCause::LiveStateDrift {
                capture_receipt_id: "capture-live-state-drift".into(),
                expected_snapshot: expected_snapshot.clone(),
                observed_snapshot: observed_snapshot.clone(),
            }),
            safe_next_action: Some(UiSafeNextAction::StartNewSprintFromObservedWorkspace),
        };
        validate_payload(&payload).expect("valid typed drift terminal payload");

        let crossed_state = DurableUiEventKind::SprintTerminal {
            state: UiNonSuccessTerminalState::Failed,
            record_id: "terminal-live-state-drift".into(),
            evidence_digest: fixture_digest("terminal evidence"),
            reason: "Live workspace state differs from the selected completion snapshot.".into(),
            cause: Some(UiTerminalCause::LiveStateDrift {
                capture_receipt_id: "capture-live-state-drift".into(),
                expected_snapshot,
                observed_snapshot,
            }),
            safe_next_action: Some(UiSafeNextAction::StartNewSprintFromObservedWorkspace),
        };
        assert!(matches!(
            validate_payload(&crossed_state),
            Err(UiProjectionError::InvalidProjection(reason))
                if reason.contains("cause, state, and safe next action")
        ));

        let generic_blocker = DurableUiEventKind::SprintTerminal {
            state: UiNonSuccessTerminalState::Blocked,
            record_id: "terminal-generic-blocker".into(),
            evidence_digest: fixture_digest("generic terminal evidence"),
            reason: "Additional authority is required.".into(),
            cause: None,
            safe_next_action: None,
        };
        validate_payload(&generic_blocker).expect("generic terminal behavior remains valid");
    }

    #[test]
    fn completed_projection_prints_only_the_derived_satisfied_aggregate() {
        let payload = DurableUiEventKind::SprintCompleted {
            receipt_id: "completion-1".into(),
            final_snapshot: fixture_digest("completed snapshot"),
            criteria_status: CriteriaAggregateStatus::Satisfied,
        };
        validate_payload(&payload).expect("validated completion aggregate");
        let json = serde_json::to_string(&payload).expect("serialize completion projection");
        assert!(json.contains("\"criteria_status\":\"satisfied\""));
        assert!(!json.contains("passed"));
        assert!(!json.contains("accepted"));

        let caller_selected = DurableUiEventKind::SprintCompleted {
            receipt_id: "completion-1".into(),
            final_snapshot: fixture_digest("completed snapshot"),
            criteria_status: CriteriaAggregateStatus::Pending,
        };
        assert!(matches!(
            validate_payload(&caller_selected),
            Err(UiProjectionError::InvalidProjection(reason))
                if reason.contains("derived aggregate status Satisfied")
        ));
    }

    #[test]
    fn incomplete_v29_rejection_authority_readback_rejects_the_projection() {
        let effect = successful_read_effect(1, "incomplete-v29-authority");
        let error = admit_sensitive_output_rejection_readback(
            &effect,
            Err(LedgerError::Corrupt {
                entity: "command output sensitive rejection authority",
                detail: "rejection anchor exists without its cleanup receipt or closure".into(),
            }),
        )
        .expect_err("partial v29 authority must fail closed");

        assert!(matches!(
            error,
            UiProjectionError::InvalidEffect { effect_id, reason }
                if effect_id == "read-effect-incomplete-v29-authority"
                    && reason.contains("failed exact readback")
                    && reason.contains("without its cleanup receipt or closure")
        ));
    }

    #[test]
    fn crossed_v29_rejection_authority_readback_rejects_the_projection() {
        let effect = successful_read_effect(1, "crossed-v29-authority");
        let error = admit_sensitive_output_rejection_readback(
            &effect,
            Err(LedgerError::Corrupt {
                entity: "command output sensitive rejection authority",
                detail: "cleanup effect identity crosses the rejection anchor".into(),
            }),
        )
        .expect_err("crossed v29 authority must fail closed");

        assert!(matches!(
            error,
            UiProjectionError::InvalidEffect { effect_id, reason }
                if effect_id == "read-effect-crossed-v29-authority"
                    && reason.contains("failed exact readback")
                    && reason.contains("crosses the rejection anchor")
        ));
    }

    #[test]
    fn sensitive_output_ui_vocabulary_carries_only_public_policy_identity() {
        let policy = grok_build_core::SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let payload = DurableUiEventKind::SensitiveOutputRejected {
            effect_id: "command-effect-sensitive-output".into(),
            detector_policy_id: policy.policy_id,
            detector_policy_version: policy.policy_version,
        };
        validate_payload(&payload).expect("fixed public rejection vocabulary is valid");

        let json = serde_json::to_string(&payload).expect("serialize rejection UI event");
        assert!(json.contains("sensitive_output_rejected"));
        assert!(json.contains("detector_policy_id"));
        for forbidden in [
            "stdout",
            "stderr",
            "artifact",
            "output_length",
            "offset",
            "match",
            "sk-live-secret-canary",
            "verified",
            "accepted",
            "satisfied",
        ] {
            assert!(
                !json.contains(forbidden),
                "rejection UI event exposed forbidden field or canary {forbidden}"
            );
        }

        let substituted = DurableUiEventKind::SensitiveOutputRejected {
            effect_id: "command-effect-sensitive-output".into(),
            detector_policy_id: "caller-authored-detector".into(),
            detector_policy_version: 99,
        };
        assert!(matches!(
            validate_payload(&substituted),
            Err(UiProjectionError::InvalidProjection(reason))
                if reason.contains("repository-owned v1 detector policy")
        ));
    }
}
