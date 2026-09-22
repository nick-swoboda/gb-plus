//! Canonical framing, decoding, and shared validation.

#[cfg(any(test, feature = "future-contracts"))]
use super::validate_current_direct_exec_command_v1;
use super::{
    COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN, COMMAND_TERMINAL_DIGEST_DOMAIN,
    COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN, ChangeSet, CommandDomainCleanupBinding,
    CommandOutputArtifactSetReferenceV1, CommandOutputCaptureStoreHeadV1, CommandSpec,
    CommandTerminationV1, Component, Deserialize, Digest, Display, LEGACY_SHELL_PROGRAMS_V11_V12,
    MAX_CHANGE_SET_OPERATIONS, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES,
    MAX_COMMAND_OUTPUT_ARTIFACT_BYTES, MAX_COMMAND_TEXT_BYTES, MAX_ERROR_MESSAGE_BYTES,
    MAX_ID_BYTES, MAX_INLINE_COMMAND_RETAINED_BYTES, MAX_INLINE_FILE_BYTES, MAX_PATH_BYTES,
    MAX_RECOVERY_IDENTITIES, MAX_WIRE_FRAME_BYTES, MAX_WIRE_SEARCH_MATCHES, Path, PathBuf,
    RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequest, RunnerResponse, RunnerRole,
    RunnerRoleInputAuthority, Serialize, StageBundleReference, WireCommandBackendIdentity,
    WireCommandCleanupProof, WireCommandOutputCaptureAnchorV1, WireCommandOutputCaptureTerminalV1,
    WireCommandSpec, WireCommandStreamEvidence, WireCommandTerminalEvidence, WireEffectContext,
    WireFailureClass, WireProtocolError, WireReconciliationReference,
    current_command_output_capture_maximum_v1,
};

#[allow(
    clippy::too_many_lines,
    reason = "the closed response validator keeps every variant's evidence invariants in one audit boundary"
)]
pub(super) fn validate_response(response: &RunnerResponse) -> Result<(), WireProtocolError> {
    match response {
        RunnerResponse::Initialized { receipt } => {
            validate_identifier("initialization.launch_id", &receipt.launch_id)?;
            validate_identifier("initialization.sprint_id", &receipt.sprint_id)?;
            if let Some(worker_id) = &receipt.logical_worker_id {
                validate_identifier("initialization.logical_worker_id", worker_id)?;
            }
            if matches!(receipt.role, RunnerRole::Worker) != receipt.logical_worker_id.is_some() {
                return Err(invalid(
                    "initialization role and logical worker identity disagree",
                ));
            }
            validate_role_input_authority_shape(receipt.role, &receipt.role_input_authority)?;
            validate_identifier("initialization.grant_id", &receipt.grant_id)?;
            validate_identifier("initialization.policy_id", &receipt.policy_id)?;
            validate_absolute_path_text("initialization.canonical_root", &receipt.canonical_root)
        }
        RunnerResponse::InitializationRejected { code, message } => {
            validate_identifier("initialization_rejection.code", code)?;
            if message.is_empty() || message.len() > MAX_ERROR_MESSAGE_BYTES {
                return Err(invalid(
                    "initialization rejection message is blank or exceeds its bound",
                ));
            }
            Ok(())
        }
        RunnerResponse::WorkspaceCaptured { capture } => capture.validate(),
        RunnerResponse::LiveWorkspaceCaptured { manifest } => manifest
            .validate()
            .map_err(|error| invalid(error.to_string())),
        RunnerResponse::ShadowCreated { .. } => Ok(()),
        RunnerResponse::FileRead {
            path,
            digest,
            bytes,
        } => {
            validate_relative_path_text(path)?;
            if bytes.len() > MAX_INLINE_FILE_BYTES || Digest::sha256(bytes) != *digest {
                return Err(invalid(
                    "inline read response exceeds its bound or differs from its digest",
                ));
            }
            Ok(())
        }
        RunnerResponse::LiteralSearch {
            path,
            file_length,
            matches,
            ..
        } => {
            validate_relative_path_text(path)?;
            if matches.len() > MAX_WIRE_SEARCH_MATCHES {
                return Err(invalid("literal response exceeds the match bound"));
            }
            let mut previous = None;
            for item in matches {
                if item.line == 0
                    || item.column == 0
                    || item.byte_offset >= *file_length
                    || previous.is_some_and(|offset| item.byte_offset <= offset)
                {
                    return Err(invalid(
                        "literal response coordinates are invalid or unsorted",
                    ));
                }
                previous = Some(item.byte_offset);
            }
            Ok(())
        }
        RunnerResponse::FileMutated {
            path,
            input_snapshot,
            result_snapshot,
            previous_digest,
            result_digest,
        } => {
            validate_relative_path_text(path)?;
            if previous_digest.is_none() && result_digest.is_none()
                || previous_digest.is_some() && previous_digest == result_digest
                || input_snapshot == result_snapshot
            {
                return Err(invalid("mutation receipt does not describe a state change"));
            }
            Ok(())
        }
        RunnerResponse::FileReconciled { path, .. } => validate_relative_path_text(path),
        RunnerResponse::StagePrepared {
            change_set,
            expected_bundle,
        } => validate_bundle_change_set(expected_bundle, change_set),
        RunnerResponse::StageBundlePersisted { bundle }
        | RunnerResponse::StageBundleReconciled { bundle } => bundle
            .validate()
            .map_err(|error| invalid(error.to_string())),
        RunnerResponse::RecoveryCompleted {
            recovered_change_sets,
            abandoned_preparations,
        } => {
            validate_identity_list(recovered_change_sets)?;
            validate_identity_list(abandoned_preparations)?;
            if recovered_change_sets
                .iter()
                .any(|identity| abandoned_preparations.binary_search(identity).is_ok())
            {
                return Err(invalid(
                    "recovered and abandoned recovery identities overlap",
                ));
            }
            Ok(())
        }
        RunnerResponse::ApplicationApplied { evidence } => evidence.validate(),
        RunnerResponse::TargetsRestored { evidence }
        | RunnerResponse::RollbackCompleted { evidence } => evidence.validate(),
        RunnerResponse::RollbackCompletedWithEvidence { evidence } => evidence.validate(),
        RunnerResponse::RollbackLiveConflict { conflict } => conflict.validate(),
        RunnerResponse::CommandCompleted { evidence } => validate_command_terminal_shape(evidence),
        RunnerResponse::CancellationPrepared { acknowledgement }
        | RunnerResponse::ShutdownPrepared { acknowledgement } => acknowledgement.validate(),
        RunnerResponse::Failed {
            code,
            class,
            reconciliation,
            message,
        } => {
            validate_identifier("failure.code", code)?;
            if message.len() > MAX_ERROR_MESSAGE_BYTES {
                return Err(invalid("failure message exceeds the wire bound"));
            }
            match (class, reconciliation) {
                (WireFailureClass::BeforeEffect | WireFailureClass::AfterKnownEffect, None) => {
                    Ok(())
                }
                (WireFailureClass::ReconciliationRequired, Some(reference)) => {
                    validate_reconciliation_reference(reference)
                }
                (WireFailureClass::BeforeEffect | WireFailureClass::AfterKnownEffect, Some(_))
                | (WireFailureClass::ReconciliationRequired, None) => Err(invalid(
                    "failure class and typed reconciliation reference disagree",
                )),
            }
        }
    }
}

pub(super) fn validate_role_input_authority_shape(
    role: RunnerRole,
    authority: &RunnerRoleInputAuthority,
) -> Result<(), WireProtocolError> {
    match (role, authority) {
        (
            RunnerRole::Worker | RunnerRole::FinalVerifier,
            RunnerRoleInputAuthority::IntegrationHead,
        )
        | (RunnerRole::Applier, RunnerRoleInputAuthority::PlanningBase) => Ok(()),
        (
            RunnerRole::Applier,
            RunnerRoleInputAuthority::PostCompletionAppliedResult {
                authority,
                authority_digest,
            },
        ) => {
            authority
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
            let canonical = serde_json::to_vec(authority)
                .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
            if Digest::sha256(&canonical) != *authority_digest {
                return Err(invalid(
                    "post-completion role-input authority digest differs from its canonical value",
                ));
            }
            Ok(())
        }
        (
            RunnerRole::LiveStateVerifier,
            RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest },
        ) => {
            plan.validate()
                .map_err(|error| invalid(error.to_string()))?;
            if plan
                .plan_digest()
                .map_err(|error| invalid(error.to_string()))?
                != *plan_digest
            {
                return Err(invalid(
                    "live-state finalization plan digest differs from its canonical value",
                ));
            }
            Ok(())
        }
        _ => Err(invalid(
            "initialization role differs from its retained input authority",
        )),
    }
}

pub(super) fn validate_reconciliation_reference(
    reference: &WireReconciliationReference,
) -> Result<(), WireProtocolError> {
    match reference {
        WireReconciliationReference::File { path } => validate_relative_path_text(path),
        WireReconciliationReference::StageBundle { bundle } => bundle
            .validate()
            .map_err(|error| invalid(error.to_string())),
        WireReconciliationReference::Application { bundle } => bundle
            .validate()
            .map_err(|error| invalid(error.to_string())),
        WireReconciliationReference::ApplicationRecovery => Ok(()),
        WireReconciliationReference::SessionPrivateState { state_id } => {
            validate_identifier("session_private_state.state_id", state_id)
        }
        WireReconciliationReference::CommandOutputCapture {
            capture_id,
            last_known_store_head,
            expected_output_artifacts,
            ..
        } => {
            validate_capture_id(capture_id)?;
            last_known_store_head
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
            if let Some(reference) = expected_output_artifacts {
                reference
                    .validate()
                    .map_err(|error| invalid(error.to_string()))?;
            }
            Ok(())
        }
    }
}

pub(super) fn validate_failure_reference_correlation(
    request: &RunnerRequest,
    reference: &WireReconciliationReference,
) -> Result<(), WireProtocolError> {
    let matches = match (request, reference) {
        (
            RunnerRequest::WorkerCreateFile { path, .. }
            | RunnerRequest::WorkerReplaceFile { path, .. }
            | RunnerRequest::WorkerDeleteFile { path, .. }
            | RunnerRequest::WorkerReconcileFile { path, .. },
            WireReconciliationReference::File {
                path: reference_path,
            },
        ) => path == reference_path,
        (
            RunnerRequest::WorkerStageChanges {
                expected_bundle, ..
            }
            | RunnerRequest::WorkerReconcileStage { expected_bundle }
            | RunnerRequest::ApplierReconcileStageBundle { expected_bundle },
            WireReconciliationReference::StageBundle { bundle },
        ) => expected_bundle == bundle,
        (
            RunnerRequest::ApplierApplyBundle { bundle }
            | RunnerRequest::ApplierReconcile { bundle }
            | RunnerRequest::ApplierRollback { bundle, .. },
            WireReconciliationReference::Application {
                bundle: reference_bundle,
            },
        ) => bundle == reference_bundle,
        (
            RunnerRequest::ApplierRecoverPending
            | RunnerRequest::ApplierApplyBundle { .. }
            | RunnerRequest::ApplierReconcile { .. }
            | RunnerRequest::ApplierRollback { .. },
            WireReconciliationReference::ApplicationRecovery,
        )
        | (
            RunnerRequest::WorkerCreateShadow { .. }
            | RunnerRequest::WorkerCreateFile { .. }
            | RunnerRequest::WorkerReplaceFile { .. }
            | RunnerRequest::WorkerDeleteFile { .. },
            WireReconciliationReference::SessionPrivateState { .. },
        ) => true,
        (
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. },
            WireReconciliationReference::CommandOutputCapture {
                capture_id,
                acquired_anchor_digest,
                last_known_store_head,
                expected_output_artifacts,
            },
        ) => {
            let acquired = output_capture.acquired();
            capture_id == &acquired.capture_id
                && acquired_anchor_digest == &acquired.acquired_anchor_digest
                && last_known_store_head.generation >= acquired.store_head.generation
                && (last_known_store_head.generation != acquired.store_head.generation
                    || last_known_store_head.record_digest == acquired.store_head.record_digest)
                && expected_output_artifacts.as_ref().is_none_or(|reference| {
                    reference.source == acquired.source
                        && reference
                            .stdout
                            .byte_length
                            .checked_add(reference.stderr.byte_length)
                            .is_some_and(|length| length <= acquired.max_aggregate_output_bytes)
                })
        }
        _ => false,
    };
    if !matches {
        return Err(invalid(
            "failure reconciliation reference does not derive from the exact correlated request",
        ));
    }
    Ok(())
}

pub(crate) fn validate_bundle_change_set(
    bundle: &StageBundleReference,
    change_set: &ChangeSet,
) -> Result<(), WireProtocolError> {
    bundle
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    change_set
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if change_set.operations.len() > MAX_CHANGE_SET_OPERATIONS
        || change_set.change_set_id != bundle.change_set_id
        || change_set.base_snapshot != bundle.base_snapshot
        || change_set.result_snapshot != bundle.result_snapshot
    {
        return Err(invalid(
            "stage bundle and validated change-set contract disagree or exceed operation bounds",
        ));
    }
    for operation in &change_set.operations {
        let path = operation
            .path()
            .to_str()
            .ok_or_else(|| invalid("change-set operation path is not UTF-8"))?;
        validate_relative_path_text(path)?;
    }
    Ok(())
}

pub(super) fn change_set_operations_digest(
    change_set: &ChangeSet,
) -> Result<Digest, WireProtocolError> {
    change_set
        .applied_operations_digest()
        .map_err(|error| invalid(error.to_string()))
}

pub(super) fn change_set_endpoints_digest(
    change_set: &ChangeSet,
) -> Result<Digest, WireProtocolError> {
    change_set
        .touched_path_endpoints_digest()
        .map_err(|error| invalid(error.to_string()))
}

pub(super) fn change_set_target_digest(
    change_set: &ChangeSet,
) -> Result<Digest, WireProtocolError> {
    change_set
        .touched_target_set_digest()
        .map_err(|error| invalid(error.to_string()))
}

pub(super) fn change_set_restored_endpoints_digest(
    change_set: &ChangeSet,
) -> Result<Digest, WireProtocolError> {
    change_set
        .restored_base_endpoints_digest()
        .map_err(|error| invalid(error.to_string()))
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub(super) fn validate_identity_list(identities: &[String]) -> Result<(), WireProtocolError> {
    if identities.len() > MAX_RECOVERY_IDENTITIES {
        return Err(invalid("identity list exceeds the wire bound"));
    }
    let mut previous: Option<&str> = None;
    for identity in identities {
        validate_identifier("change_set_id", identity)?;
        if previous.is_some_and(|previous| identity.as_str() <= previous) {
            return Err(invalid(
                "identity list contains duplicates or is not canonically sorted",
            ));
        }
        previous = Some(identity);
    }
    Ok(())
}

pub(super) fn validate_command_stream(
    stream: &WireCommandStreamEvidence,
) -> Result<(), WireProtocolError> {
    let retained_length = u64::try_from(stream.retained_bytes.len())
        .map_err(|_| invalid("retained command stream length exceeds u64"))?;
    if retained_length > stream.complete_length
        || stream.truncated != (retained_length < stream.complete_length)
    {
        return Err(invalid(
            "command stream retained length, complete length, and truncation flag disagree",
        ));
    }
    if !stream.truncated && Digest::sha256(&stream.retained_bytes) != stream.complete_digest {
        return Err(invalid(
            "complete command stream digest differs from its retained bytes",
        ));
    }
    Ok(())
}

pub(super) fn validate_command_terminal_shape_without_record_digest(
    evidence: &WireCommandTerminalEvidence,
) -> Result<(), WireProtocolError> {
    evidence.output_capture.validate()?;
    evidence
        .termination
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    validate_command_stream(&evidence.stdout)?;
    validate_command_stream(&evidence.stderr)?;
    evidence
        .output_artifacts
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if evidence.output_capture.expected_output_artifacts != evidence.output_artifacts {
        return Err(invalid(
            "command-output terminal expected artifact reference differs from the published response reference",
        ));
    }
    if evidence.output_artifacts.stdout.byte_length != evidence.stdout.complete_length
        || evidence.output_artifacts.stdout.content_digest != evidence.stdout.complete_digest
        || evidence.output_artifacts.stderr.byte_length != evidence.stderr.complete_length
        || evidence.output_artifacts.stderr.content_digest != evidence.stderr.complete_digest
    {
        return Err(invalid(
            "command-output artifact commitments differ from the wire stream commitments",
        ));
    }
    if evidence
        .output_artifacts
        .output_evidence_bytes()
        .map_err(|error| invalid(error.to_string()))?
        != command_stream_output_evidence_bytes(&evidence.stdout, &evidence.stderr)
    {
        return Err(invalid(
            "command-output artifacts reconstruct a different complete-stream evidence preimage",
        ));
    }
    let retained_length = evidence
        .stdout
        .retained_bytes
        .len()
        .checked_add(evidence.stderr.retained_bytes.len())
        .ok_or_else(|| invalid("aggregate retained command output length overflowed usize"))?;
    if retained_length > MAX_INLINE_COMMAND_RETAINED_BYTES {
        return Err(invalid(
            "aggregate retained command output exceeds the inline wire bound",
        ));
    }
    let complete_length = evidence
        .stdout
        .complete_length
        .checked_add(evidence.stderr.complete_length)
        .ok_or_else(|| invalid("aggregate complete command output length overflowed u64"))?;
    if complete_length > MAX_COMMAND_OUTPUT_ARTIFACT_BYTES {
        return Err(invalid(
            "aggregate complete command output exceeds the immutable artifact-store bound",
        ));
    }
    if matches!(
        evidence.termination,
        CommandTerminationV1::OutputLimitExceeded
    ) && !evidence.stdout.truncated
        && !evidence.stderr.truncated
    {
        return Err(invalid(
            "output-limit termination requires omitted observed output",
        ));
    }
    if evidence.backend.backend_id.trim().is_empty()
        || evidence.backend.backend_id.len() > 128
        || evidence.backend.backend_id.chars().any(char::is_control)
    {
        return Err(invalid(
            "containment backend identity is blank, unbounded, or contains control characters",
        ));
    }
    if evidence.output_digest != command_stream_output_digest(&evidence.stdout, &evidence.stderr) {
        return Err(invalid(
            "command output digest differs from the stream-framed complete commitments",
        ));
    }
    if evidence.cleanup_proof.os_evidence_bytes.is_empty()
        || evidence.cleanup_proof.os_evidence_bytes.len()
            > MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES
        || Digest::sha256(&evidence.cleanup_proof.os_evidence_bytes)
            != evidence.cleanup_proof.os_evidence_digest
    {
        return Err(invalid(
            "command cleanup proof bytes are empty, oversized, or differ from their digest",
        ));
    }
    Ok(())
}

pub(super) fn validate_command_terminal_shape(
    evidence: &WireCommandTerminalEvidence,
) -> Result<(), WireProtocolError> {
    validate_command_terminal_shape_without_record_digest(evidence)?;
    let canonical = command_terminal_record_bytes_unchecked(evidence)?;
    if canonical.len() > MAX_WIRE_FRAME_BYTES
        || Digest::sha256(&canonical) != evidence.output_capture.terminal_record_digest
    {
        return Err(invalid(
            "command terminal record is oversized or differs from its canonical v11 payload digest",
        ));
    }
    Ok(())
}

pub(super) fn validate_command_terminal_bound(
    evidence: &WireCommandTerminalEvidence,
    expected_binding: &CommandDomainCleanupBinding,
    runner_session_id: &str,
    effect: &WireEffectContext,
) -> Result<(), WireProtocolError> {
    validate_command_terminal_shape(evidence)?;
    let source = &evidence.output_artifacts.source;
    if source.sprint_id != effect.sprint_id
        || source.runner_launch_id != effect.launch_id
        || source.runner_session_id != runner_session_id
        || source.effect_id != effect.effect_id
        || source.request_digest != effect.request_digest
    {
        return Err(invalid(
            "command-output artifact source differs from the exact sprint, launch, session, effect, or canonical core request digest",
        ));
    }
    let _validated_cleanup_proof = evidence
        .cleanup_proof
        .readback(evidence.backend.command_domain_backend, expected_binding)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(())
}

pub(super) fn validate_command_terminal_capture_bound(
    anchor: &WireCommandOutputCaptureAnchorV1,
    evidence: &WireCommandTerminalEvidence,
) -> Result<(), WireProtocolError> {
    anchor.validate()?;
    validate_command_terminal_shape(evidence)?;
    let acquired = anchor.acquired();
    let terminal = &evidence.output_capture;
    let aggregate_length = evidence
        .output_artifacts
        .stdout
        .byte_length
        .checked_add(evidence.output_artifacts.stderr.byte_length)
        .ok_or_else(|| invalid("command-output artifact aggregate length overflowed u64"))?;
    if terminal.capture_id != acquired.capture_id
        || terminal.acquired_anchor_digest != acquired.acquired_anchor_digest
        || terminal.finished_store_head.generation <= acquired.store_head.generation
        || terminal.finished_store_head.record_digest == acquired.store_head.record_digest
        || evidence.output_artifacts.source != acquired.source
        || aggregate_length > acquired.max_aggregate_output_bytes
    {
        return Err(invalid(
            "command terminal differs from its acquired capture, monotonic store head, artifact source, or aggregate output ceiling",
        ));
    }
    Ok(())
}

pub(super) fn append_command_output_frame(preimage: &mut Vec<u8>, bytes: &[u8]) {
    preimage.extend_from_slice(
        &u64::try_from(bytes.len())
            .expect("supported targets use at most 64-bit usize")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(bytes);
}

/// Builds the canonical stream-framed preimage for complete stdout/stderr commitments.
#[must_use]
pub fn command_stream_output_evidence_bytes(
    stdout: &WireCommandStreamEvidence,
    stderr: &WireCommandStreamEvidence,
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(256);
    append_command_output_frame(&mut preimage, COMMAND_STREAM_OUTPUT_DIGEST_DOMAIN);
    for (name, stream) in [
        (b"stdout".as_slice(), stdout),
        (b"stderr".as_slice(), stderr),
    ] {
        append_command_output_frame(&mut preimage, name);
        append_command_output_frame(&mut preimage, &stream.complete_length.to_be_bytes());
        append_command_output_frame(&mut preimage, stream.complete_digest.as_str().as_bytes());
    }
    preimage
}

/// Computes the canonical digest of complete stdout/stderr commitments.
#[must_use]
pub fn command_stream_output_digest(
    stdout: &WireCommandStreamEvidence,
    stderr: &WireCommandStreamEvidence,
) -> Digest {
    Digest::sha256(&command_stream_output_evidence_bytes(stdout, stderr))
}

/// Derives the exact aggregate raw-output custody ceiling from the policy's
/// ordinary output ceiling and the supervisor's bounded terminal drain.
///
/// Desktop acquisition, runner session validation, and native command
/// preparation must all call this function rather than independently copying
/// the drain arithmetic.
///
/// # Errors
///
/// Returns an error for zero, overflow, or a value beyond the immutable output
/// artifact-store ceiling.
pub fn command_output_capture_maximum(
    policy_max_output_bytes: u64,
) -> Result<u64, WireProtocolError> {
    current_command_output_capture_maximum_v1(policy_max_output_bytes)
        .map_err(|error| invalid(error.message().to_owned()))
}

#[derive(Serialize)]
pub(super) struct CanonicalCommandOutputCaptureTerminalRecord<'a> {
    pub(super) capture_id: &'a str,
    pub(super) acquired_anchor_digest: &'a Digest,
    pub(super) finished_store_head: &'a CommandOutputCaptureStoreHeadV1,
    pub(super) published_store_head: &'a CommandOutputCaptureStoreHeadV1,
    pub(super) expected_output_artifacts: &'a CommandOutputArtifactSetReferenceV1,
}

#[derive(Serialize)]
pub(super) struct CanonicalCommandTerminalRecord<'a> {
    pub(super) protocol_version: u32,
    pub(super) output_capture: CanonicalCommandOutputCaptureTerminalRecord<'a>,
    pub(super) termination: &'a CommandTerminationV1,
    pub(super) stdout: &'a WireCommandStreamEvidence,
    pub(super) stderr: &'a WireCommandStreamEvidence,
    pub(super) output_artifacts: &'a CommandOutputArtifactSetReferenceV1,
    pub(super) output_digest: &'a Digest,
    pub(super) launch_digest: &'a Digest,
    pub(super) preflight_digest: &'a Digest,
    pub(super) backend: &'a WireCommandBackendIdentity,
    pub(super) cleanup_proof: &'a WireCommandCleanupProof,
    pub(super) duration_ms: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecodedCommandOutputCaptureTerminalRecord {
    pub(super) capture_id: String,
    pub(super) acquired_anchor_digest: Digest,
    pub(super) finished_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) published_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) expected_output_artifacts: CommandOutputArtifactSetReferenceV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DecodedCommandTerminalRecord {
    pub(super) protocol_version: u32,
    pub(super) output_capture: DecodedCommandOutputCaptureTerminalRecord,
    pub(super) termination: CommandTerminationV1,
    pub(super) stdout: WireCommandStreamEvidence,
    pub(super) stderr: WireCommandStreamEvidence,
    pub(super) output_artifacts: CommandOutputArtifactSetReferenceV1,
    pub(super) output_digest: Digest,
    pub(super) launch_digest: Digest,
    pub(super) preflight_digest: Digest,
    pub(super) backend: WireCommandBackendIdentity,
    pub(super) cleanup_proof: WireCommandCleanupProof,
    pub(super) duration_ms: u64,
}

pub(super) fn command_terminal_record_bytes_unchecked(
    evidence: &WireCommandTerminalEvidence,
) -> Result<Vec<u8>, WireProtocolError> {
    let capture = &evidence.output_capture;
    let record = CanonicalCommandTerminalRecord {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
        output_capture: CanonicalCommandOutputCaptureTerminalRecord {
            capture_id: &capture.capture_id,
            acquired_anchor_digest: &capture.acquired_anchor_digest,
            finished_store_head: &capture.finished_store_head,
            published_store_head: &capture.published_store_head,
            expected_output_artifacts: &capture.expected_output_artifacts,
        },
        termination: &evidence.termination,
        stdout: &evidence.stdout,
        stderr: &evidence.stderr,
        output_artifacts: &evidence.output_artifacts,
        output_digest: &evidence.output_digest,
        launch_digest: &evidence.launch_digest,
        preflight_digest: &evidence.preflight_digest,
        backend: &evidence.backend,
        cleanup_proof: &evidence.cleanup_proof,
        duration_ms: evidence.duration_ms,
    };
    let canonical = serde_json::to_vec(&record)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let mut preimage = Vec::with_capacity(
        COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
    );
    preimage.extend_from_slice(COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical command terminal record length exceeds u64"))?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

/// Builds the canonical v11 payload committed before `TerminalPrepared` is
/// appended to the capture journal.
///
/// The resulting terminal-prepared head is intentionally excluded: it does
/// not exist until the record carrying this payload has been durably appended.
/// The response carries that later head separately and binds it monotonically.
///
/// # Errors
///
/// Returns an error when any other terminal field is malformed or cannot be
/// canonically encoded.
pub fn command_terminal_record_bytes(
    evidence: &WireCommandTerminalEvidence,
) -> Result<Vec<u8>, WireProtocolError> {
    validate_command_terminal_shape_without_record_digest(evidence)?;
    command_terminal_record_bytes_unchecked(evidence)
}

/// Computes the canonical v11 digest stored by the terminal journal record.
///
/// # Errors
///
/// Returns an error when the terminal payload is malformed or cannot be
/// canonically encoded.
pub fn command_terminal_record_digest(
    evidence: &WireCommandTerminalEvidence,
) -> Result<Digest, WireProtocolError> {
    Ok(Digest::sha256(&command_terminal_record_bytes(evidence)?))
}

/// Strictly reconstructs a terminal response from the exact bytes retained by
/// a durable `TerminalPrepared` capture record.
///
/// The retained payload deliberately excludes the terminal head because that
/// head did not exist until the payload was appended. This decoder verifies
/// the v11 domain/length frame, strict JSON schema, byte-for-byte canonical
/// re-encoding, installs the supplied exact successor head, binds the digest of
/// the complete retained bytes, and then validates the full terminal shape.
///
/// # Errors
///
/// Returns an error for truncated, oversized, non-v11, non-canonical,
/// unknown-field, digest-inconsistent, or semantically invalid evidence.
pub fn decode_command_terminal_record_bytes(
    bytes: &[u8],
    terminal_prepared_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<WireCommandTerminalEvidence, WireProtocolError> {
    terminal_prepared_store_head
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let prefix_length = COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN
        .len()
        .saturating_add(std::mem::size_of::<u64>());
    if bytes.len() < prefix_length {
        return Err(WireProtocolError::TruncatedPrefix);
    }
    if bytes.len() > MAX_WIRE_FRAME_BYTES {
        return Err(invalid("command terminal record exceeds the wire bound"));
    }
    if !bytes.starts_with(COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN) {
        return Err(invalid("command terminal record has the wrong v11 domain"));
    }
    let length_start = COMMAND_TERMINAL_RECORD_DIGEST_DOMAIN.len();
    let length_end = length_start + std::mem::size_of::<u64>();
    let length_bytes: [u8; std::mem::size_of::<u64>()] = bytes[length_start..length_end]
        .try_into()
        .map_err(|_| WireProtocolError::TruncatedPrefix)?;
    let declared_length = u64::from_be_bytes(length_bytes);
    let declared_length = usize::try_from(declared_length)
        .map_err(|_| invalid("command terminal record length exceeds usize"))?;
    let payload = &bytes[length_end..];
    if payload.len() != declared_length {
        return Err(WireProtocolError::TruncatedPayload {
            expected: declared_length,
            actual: payload.len(),
        });
    }
    if declared_length == 0 || declared_length > MAX_WIRE_FRAME_BYTES - prefix_length {
        return Err(invalid(
            "command terminal JSON length is outside the wire bound",
        ));
    }
    let decoded: DecodedCommandTerminalRecord = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    if decoded.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION {
        return Err(WireProtocolError::Version {
            expected: RUNNER_WIRE_PROTOCOL_VERSION,
            actual: decoded.protocol_version,
        });
    }
    let canonical = serde_json::to_vec(&decoded)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if canonical != payload {
        return Err(WireProtocolError::NonCanonical);
    }
    let DecodedCommandTerminalRecord {
        protocol_version: _,
        output_capture,
        termination,
        stdout,
        stderr,
        output_artifacts,
        output_digest,
        launch_digest,
        preflight_digest,
        backend,
        cleanup_proof,
        duration_ms,
    } = decoded;
    let output_capture = WireCommandOutputCaptureTerminalV1::try_new(
        output_capture.capture_id,
        output_capture.acquired_anchor_digest,
        output_capture.finished_store_head,
        output_capture.published_store_head,
        terminal_prepared_store_head.clone(),
        output_capture.expected_output_artifacts,
        Digest::sha256(bytes),
    )?;
    let evidence = WireCommandTerminalEvidence {
        output_capture,
        termination,
        stdout,
        stderr,
        output_artifacts,
        output_digest,
        launch_digest,
        preflight_digest,
        backend,
        cleanup_proof,
        duration_ms,
    };
    validate_command_terminal_shape(&evidence)?;
    if command_terminal_record_bytes_unchecked(&evidence)? != bytes {
        return Err(WireProtocolError::NonCanonical);
    }
    Ok(evidence)
}

/// Builds the domain-separated canonical aggregate terminal-evidence preimage.
///
/// Callers must first validate the containing response against its exact
/// request; this derived preimage is not a substitute for effect correlation.
///
/// # Errors
///
/// Returns an error when the terminal shape is invalid or cannot be encoded.
pub fn command_terminal_evidence_bytes(
    evidence: &WireCommandTerminalEvidence,
) -> Result<Vec<u8>, WireProtocolError> {
    validate_command_terminal_shape(evidence)?;
    let canonical = serde_json::to_vec(evidence)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let mut preimage = Vec::with_capacity(
        COMMAND_TERMINAL_DIGEST_DOMAIN.len() + std::mem::size_of::<u64>() + canonical.len(),
    );
    preimage.extend_from_slice(COMMAND_TERMINAL_DIGEST_DOMAIN);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .map_err(|_| invalid("canonical command terminal length exceeds u64"))?
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

/// Computes the derived digest of one canonical aggregate command terminal.
///
/// # Errors
///
/// Returns an error when the terminal shape is invalid or cannot be encoded.
pub fn command_terminal_digest(
    evidence: &WireCommandTerminalEvidence,
) -> Result<Digest, WireProtocolError> {
    Ok(Digest::sha256(&command_terminal_evidence_bytes(evidence)?))
}

pub(super) fn validate_legacy_runner_command_v11_v12(
    command: &WireCommandSpec,
) -> Result<(), WireProtocolError> {
    if command.program.is_empty()
        || command.program.len() > MAX_COMMAND_TEXT_BYTES
        || command.program.as_bytes().contains(&0)
        || command.arguments.len() > MAX_COMMAND_ARGUMENTS
    {
        return Err(invalid(
            "command program or argument count is outside bounds",
        ));
    }
    let basename = Path::new(&command.program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&command.program)
        .to_ascii_lowercase();
    if LEGACY_SHELL_PROGRAMS_V11_V12.contains(&basename.as_str()) {
        return Err(invalid("shell and command-wrapper programs are forbidden"));
    }
    for argument in &command.arguments {
        if argument.len() > MAX_COMMAND_TEXT_BYTES || argument.as_bytes().contains(&0) {
            return Err(invalid("command argument is outside the text bound"));
        }
    }
    validate_relative_path_text_allow_root(&command.working_directory)
}

#[cfg(any(test, feature = "future-contracts"))]
pub(crate) fn validate_current_runner_command_v13(
    command: &WireCommandSpec,
) -> Result<CommandSpec, WireProtocolError> {
    let core_command = CommandSpec {
        program: command.program.clone(),
        arguments: command.arguments.clone(),
        working_directory: PathBuf::from(&command.working_directory),
    };
    validate_current_direct_exec_command_v1(&core_command).map_err(|error| {
        let message = if error.field().starts_with("current_direct_exec_command_v1") {
            error.message().to_owned()
        } else {
            error.to_string()
        };
        invalid(message)
    })?;
    Ok(core_command)
}

pub(super) fn validate_command_effect_request(
    effect: &WireEffectContext,
    role: RunnerRole,
    command: &WireCommandSpec,
    output_capture: &WireCommandOutputCaptureAnchorV1,
    session_id: &str,
) -> Result<(), WireProtocolError> {
    let scope_matches = match role {
        RunnerRole::Worker => {
            effect.task_id.is_some() && effect.worker_id.is_some() && effect.worker_lease.is_some()
        }
        RunnerRole::FinalVerifier => {
            effect.task_id.is_none() && effect.worker_id.is_none() && effect.worker_lease.is_none()
        }
        RunnerRole::Applier | RunnerRole::LiveStateVerifier => false,
    };
    if !scope_matches {
        return Err(invalid(
            "command effect task and worker scope differs from its request role",
        ));
    }
    validate_legacy_runner_command_v11_v12(command)?;
    let core_command = CommandSpec {
        program: command.program.clone(),
        arguments: command.arguments.clone(),
        working_directory: PathBuf::from(&command.working_directory),
    };
    core_command
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let canonical = serde_json::to_vec(&core_command)
        .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if effect.request_digest != Digest::sha256(&canonical) {
        return Err(invalid(
            "command-effect request digest differs from the exact canonical core command",
        ));
    }
    output_capture.validate_request_binding(session_id, effect)
}

pub(super) fn validate_inline_file_bound(bound: u64) -> Result<(), WireProtocolError> {
    if bound == 0 || bound > 1_048_576_u64 {
        return Err(invalid(
            "requested file byte bound is outside the wire ceiling",
        ));
    }
    Ok(())
}

pub(crate) fn validate_identifier(field: &str, value: &str) -> Result<(), WireProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid(format!(
            "{field} is blank, oversized, or contains unsupported bytes"
        )));
    }
    Ok(())
}

pub(super) fn validate_capture_id(value: &str) -> Result<(), WireProtocolError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(invalid(
            "command-output capture identifier must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub(super) fn validate_absolute_path_text(
    field: &str,
    text: &str,
) -> Result<(), WireProtocolError> {
    let _ = validated_absolute_path(field, text)?;
    Ok(())
}

pub(super) fn validated_absolute_path(
    field: &str,
    text: &str,
) -> Result<PathBuf, WireProtocolError> {
    if text.is_empty() || text.len() > MAX_PATH_BYTES || text.as_bytes().contains(&0) {
        return Err(invalid(format!(
            "{field} is blank, oversized, or contains NUL"
        )));
    }
    let path = PathBuf::from(text);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid(format!(
            "{field} must be a normalized absolute path"
        )));
    }
    Ok(path)
}

pub(super) fn validated_relative_path(text: &str) -> Result<PathBuf, WireProtocolError> {
    validate_relative_path_text(text)?;
    Ok(PathBuf::from(text))
}

pub(super) fn validate_relative_path_text(text: &str) -> Result<(), WireProtocolError> {
    if text.is_empty() || text.len() > MAX_PATH_BYTES || text.as_bytes().contains(&0) {
        return Err(invalid(
            "relative path is blank, oversized, or contains NUL",
        ));
    }
    validate_relative_components(Path::new(text), false)
}

pub(super) fn validate_relative_path_text_allow_root(text: &str) -> Result<(), WireProtocolError> {
    if text.len() > MAX_PATH_BYTES || text.as_bytes().contains(&0) {
        return Err(invalid("working directory is oversized or contains NUL"));
    }
    if text.is_empty() {
        return Ok(());
    }
    validate_relative_components(Path::new(text), false)
}

pub(super) fn validate_relative_components(
    path: &Path,
    allow_root: bool,
) -> Result<(), WireProtocolError> {
    if path.is_absolute() || (!allow_root && path.as_os_str().is_empty()) {
        return Err(invalid("path must be normalized and workspace-relative"));
    }
    for component in path.components() {
        match component {
            Component::Normal(name)
                if !name
                    .to_str()
                    .is_some_and(|text| text.eq_ignore_ascii_case(".git")) => {}
            Component::Normal(_) => {
                return Err(invalid(
                    "protected .git paths are forbidden case-insensitively",
                ));
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(invalid("path contains a non-normal component"));
            }
        }
    }
    Ok(())
}

pub(super) fn portable_path(path: &Path) -> Result<String, WireProtocolError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid("runner result path is not UTF-8"))
}

pub(super) fn require_nonzero(value: u64, field: &str) -> Result<(), WireProtocolError> {
    if value == 0 {
        return Err(invalid(format!("{field} must be nonzero")));
    }
    Ok(())
}

pub(super) fn bounded_error_message(message: impl Display) -> String {
    let mut message = message.to_string();
    if message.len() <= MAX_ERROR_MESSAGE_BYTES {
        return message;
    }

    let mut boundary = MAX_ERROR_MESSAGE_BYTES;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message.truncate(boundary);
    message
}

pub(super) fn invalid(message: impl Into<String>) -> WireProtocolError {
    WireProtocolError::InvalidContract(message.into())
}
