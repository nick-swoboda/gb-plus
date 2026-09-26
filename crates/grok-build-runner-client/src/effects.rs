//! Effect dispatch, provider-call translation, and claimed-failure evidence.

use super::{
    CONTRACT_VERSION, Digest, EffectIntent, EffectKind, FreshRunnerEffectDispatchPermit,
    MAX_CLAIMED_EFFECT_FAILURE_DETAIL_CHARS, MAX_CLAIMED_EFFECT_FAILURE_EVIDENCE_BYTES,
    MAX_PROVIDER_FILE_BYTES, Path, PersistedRunnerEffectDispatchClaim, ProviderToolCall,
    ProviderToolIntent, RunnerClientError, RunnerEffectFailurePhase, RunnerEffectRequestAuthority,
    RunnerRequest, RunnerRequestWriteProgress, RunnerRole, RunnerSessionPurpose,
    RunnerTaskEffectDispatchClass, WireReconciliationReference, decode_tool_call, io,
    task_lease_provider_call_effect_key,
};

pub(super) fn failure_phase(progress: RunnerRequestWriteProgress) -> RunnerEffectFailurePhase {
    match progress {
        RunnerRequestWriteProgress::NotStarted => RunnerEffectFailurePhase::NoRequestBytesWritten,
        RunnerRequestWriteProgress::Started { written, total } => {
            RunnerEffectFailurePhase::RequestWriteStarted {
                written_request_bytes: written,
                total_request_bytes: total,
            }
        }
    }
}

#[derive(serde::Serialize)]
pub(super) struct ClaimedEffectFailureEvidence<'a> {
    domain: &'static str,
    contract_version: u32,
    effect_id: &'a str,
    dispatch_claim_id: &'a str,
    request_frame_digest: &'a str,
    request_frame_bytes: usize,
    accepted_request_bytes: usize,
    phase: &'static str,
    correlated_response_frame_digest: Option<&'a str>,
    error_class: &'static str,
    detail: &'a str,
}

#[allow(
    clippy::too_many_arguments,
    reason = "canonical failure evidence binds every independent claim and transport dimension"
)]
/// Encodes bounded failure evidence for one exact claimed runner effect.
#[doc(hidden)]
pub fn claimed_effect_failure_evidence(
    intent: &EffectIntent,
    claim: &PersistedRunnerEffectDispatchClaim,
    request_frame: &[u8],
    phase: RunnerEffectFailurePhase,
    has_correlated_exchange: bool,
    response_frame_digest: Option<&Digest>,
    error: &RunnerClientError,
) -> Vec<u8> {
    let (phase_name, accepted_request_bytes) = match phase {
        RunnerEffectFailurePhase::NoRequestBytesWritten => ("no-request-bytes-written", 0),
        RunnerEffectFailurePhase::RequestWriteStarted {
            written_request_bytes,
            total_request_bytes,
        } => {
            debug_assert_eq!(total_request_bytes.get(), request_frame.len());
            debug_assert!(written_request_bytes <= total_request_bytes);
            ("request-write-started", written_request_bytes.get())
        }
        RunnerEffectFailurePhase::CorrelatedResponseRejected => {
            ("correlated-response-rejected", request_frame.len())
        }
    };
    debug_assert!(!request_frame.is_empty());
    debug_assert_eq!(claim.effect_id, intent.effect_id);
    debug_assert_eq!(claim.request_digest, intent.request_digest);
    debug_assert_eq!(
        claim.opaque_transport_request_digest,
        Digest::sha256(request_frame)
    );
    debug_assert_eq!(
        has_correlated_exchange,
        matches!(phase, RunnerEffectFailurePhase::CorrelatedResponseRejected)
    );
    debug_assert_eq!(response_frame_digest.is_some(), has_correlated_exchange);

    let detail = sanitized_failure_detail(error);
    let evidence = ClaimedEffectFailureEvidence {
        domain: "grok-build.runner-claimed-effect-failure.v1",
        contract_version: CONTRACT_VERSION,
        effect_id: &intent.effect_id,
        dispatch_claim_id: &claim.dispatch_claim_id,
        request_frame_digest: claim.opaque_transport_request_digest.as_str(),
        request_frame_bytes: request_frame.len(),
        accepted_request_bytes,
        phase: phase_name,
        correlated_response_frame_digest: response_frame_digest.map(Digest::as_str),
        error_class: runner_client_error_class(error),
        detail: &detail,
    };
    let bytes = serde_json::to_vec(&evidence)
        .expect("a bounded primitive-only claimed failure evidence record is serializable");
    debug_assert!(!bytes.is_empty());
    debug_assert!(bytes.len() <= MAX_CLAIMED_EFFECT_FAILURE_EVIDENCE_BYTES);
    bytes
}

pub(super) fn runner_client_error_class(error: &RunnerClientError) -> &'static str {
    match error {
        RunnerClientError::InvalidLifecycle(_) => "invalid-lifecycle",
        RunnerClientError::Ledger(_) => "ledger",
        RunnerClientError::Wire(_) => "wire",
        RunnerClientError::CommandOutputStore(_) => "command-output-store",
        RunnerClientError::Io(io_error) => match io_error.kind() {
            io::ErrorKind::TimedOut => "io-timeout",
            io::ErrorKind::WriteZero => "io-write-zero",
            io::ErrorKind::BrokenPipe => "io-broken-pipe",
            io::ErrorKind::UnexpectedEof => "io-unexpected-eof",
            _ => "io",
        },
        RunnerClientError::InitializationRejected { .. } => "initialization-rejected",
        RunnerClientError::UnexpectedResponse(_) => "unexpected-response",
        RunnerClientError::CommandExecutionDisabled => "command-execution-disabled",
        RunnerClientError::MissingDurableApplicationArtifactAuthority => {
            "missing-application-artifact-authority"
        }
        RunnerClientError::DescriptorExecutionUnavailable { .. } => {
            "descriptor-execution-unavailable"
        }
        RunnerClientError::PlatformLaunchBindingUnavailable { .. } => {
            "platform-launch-binding-unavailable"
        }
    }
}

pub(super) fn sanitized_failure_detail(error: &RunnerClientError) -> String {
    error
        .to_string()
        .chars()
        .take(MAX_CLAIMED_EFFECT_FAILURE_DETAIL_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub(super) fn validate_worker_provider_tool_request(
    intent: &EffectIntent,
    core_request_bytes: &[u8],
    request: &RunnerRequest,
) -> Result<(), RunnerClientError> {
    if !matches!(
        request,
        RunnerRequest::WorkerReadFile { .. }
            | RunnerRequest::WorkerSearchLiteral { .. }
            | RunnerRequest::WorkerCreateFile { .. }
            | RunnerRequest::WorkerReplaceFile { .. }
            | RunnerRequest::WorkerDeleteFile { .. }
    ) {
        return Ok(());
    }

    let (_call, expected_request) = worker_request_from_provider_call(intent, core_request_bytes)?;
    if expected_request != *request {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner file request differs from the exact canonical provider tool call".into(),
        ));
    }
    Ok(())
}

/// Maps one canonical provider file call to its exact runner request.
#[doc(hidden)]
pub fn worker_request_from_provider_call(
    intent: &EffectIntent,
    core_request_bytes: &[u8],
) -> Result<(grok_build_providers::ProviderToolCall, RunnerRequest), RunnerClientError> {
    let call = decode_worker_provider_call(intent, core_request_bytes)?;
    if matches!(
        call.intent,
        ProviderToolIntent::RunCommand { .. } | ProviderToolIntent::TaskReadyForVerification
    ) {
        return Err(RunnerClientError::InvalidLifecycle(
            "worker file request requires the exact file-tool provider intent".into(),
        ));
    }

    let expected_request = match &call.intent {
        ProviderToolIntent::ReadRelativeFile { path, max_bytes } => RunnerRequest::WorkerReadFile {
            path: provider_path_to_wire(path)?,
            max_bytes: u64::try_from(*max_bytes).map_err(|_| {
                RunnerClientError::InvalidLifecycle(
                    "provider read byte bound does not fit the runner wire contract".into(),
                )
            })?,
        },
        ProviderToolIntent::SearchLiteral {
            path,
            literal,
            max_matches,
        } => RunnerRequest::WorkerSearchLiteral {
            path: provider_path_to_wire(path)?,
            needle: literal.as_bytes().to_vec(),
            max_bytes: u64::try_from(MAX_PROVIDER_FILE_BYTES).map_err(|_| {
                RunnerClientError::InvalidLifecycle(
                    "provider file byte bound does not fit the runner wire contract".into(),
                )
            })?,
            max_matches: usize::try_from(*max_matches).map_err(|_| {
                RunnerClientError::InvalidLifecycle(
                    "provider match bound does not fit the runner wire contract".into(),
                )
            })?,
        },
        ProviderToolIntent::CreateRegularFile { path, contents } => {
            RunnerRequest::WorkerCreateFile {
                path: provider_path_to_wire(path)?,
                contents: contents.clone(),
            }
        }
        ProviderToolIntent::ReplaceRegularFile {
            path,
            expected_hash,
            contents,
        } => RunnerRequest::WorkerReplaceFile {
            path: provider_path_to_wire(path)?,
            expected_digest: expected_hash.clone(),
            contents: contents.clone(),
        },
        ProviderToolIntent::DeleteRegularFile {
            path,
            expected_hash,
        } => RunnerRequest::WorkerDeleteFile {
            path: provider_path_to_wire(path)?,
            expected_digest: expected_hash.clone(),
        },
        ProviderToolIntent::RunCommand { .. } | ProviderToolIntent::TaskReadyForVerification => {
            unreachable!("non-file provider intents returned above")
        }
    };
    Ok((call, expected_request))
}

pub(super) fn decode_worker_provider_call(
    intent: &EffectIntent,
    core_request_bytes: &[u8],
) -> Result<ProviderToolCall, RunnerClientError> {
    let call = decode_tool_call(core_request_bytes).map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "worker core request is not one canonical provider tool call: {error}"
        ))
    })?;
    validate_worker_provider_call_context(&call, intent)?;
    Ok(call)
}

/// Validates a worker tool call against its durable intent and attempt lease.
/// `validate_effect_request` has already bound the worker role and session lease.
/// The idempotency key must use the same lease-scoped derivation as the
/// coordinator; a raw provider call key is insufficient.
pub(super) fn validate_worker_provider_call_context(
    call: &ProviderToolCall,
    intent: &EffectIntent,
) -> Result<(), RunnerClientError> {
    let expected_kind = match &call.intent {
        ProviderToolIntent::ReadRelativeFile { .. } => EffectKind::ReadRelativeFile,
        ProviderToolIntent::SearchLiteral { .. } => EffectKind::SearchLiteral,
        ProviderToolIntent::CreateRegularFile { .. } => EffectKind::CreateRegularFile,
        ProviderToolIntent::ReplaceRegularFile { .. } => EffectKind::ReplaceRegularFile,
        ProviderToolIntent::DeleteRegularFile { .. } => EffectKind::DeleteRegularFile,
        ProviderToolIntent::RunCommand { .. } => EffectKind::RunCommand,
        ProviderToolIntent::TaskReadyForVerification => {
            return Err(RunnerClientError::InvalidLifecycle(
                "worker effect request cannot contain TaskReadyForVerification".into(),
            ));
        }
    };
    let lease_id = intent
        .worker_lease
        .as_ref()
        .map(|lease| lease.lease_id.as_str())
        .ok_or_else(|| {
            RunnerClientError::InvalidLifecycle(format!(
                "worker provider call effect {} lacks exact task-attempt authority",
                intent.effect_id
            ))
        })?;
    let expected_idempotency_key =
        task_lease_provider_call_effect_key(lease_id, &call.idempotency_key);
    if call.sprint_id != intent.sprint_id
        || intent.task_id.as_deref() != Some(call.task_id.as_str())
        || expected_idempotency_key != intent.idempotency_key
        || expected_kind != intent.kind
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "provider tool call sprint, task, lease-scoped idempotency key, or effect kind differs from the durable intent"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn provider_path_to_wire(path: &Path) -> Result<String, RunnerClientError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        RunnerClientError::InvalidLifecycle(
            "provider tool path is not representable by the UTF-8 runner wire contract".into(),
        )
    })
}

pub(super) fn task_dispatch_class(
    permit: &FreshRunnerEffectDispatchPermit,
) -> Result<RunnerTaskEffectDispatchClass, RunnerClientError> {
    match permit {
        FreshRunnerEffectDispatchPermit::TaskRunning(_) => {
            Ok(RunnerTaskEffectDispatchClass::TaskRunning)
        }
        FreshRunnerEffectDispatchPermit::TaskFormalCheck(_) => {
            Ok(RunnerTaskEffectDispatchClass::TaskFormalCheck)
        }
        FreshRunnerEffectDispatchPermit::TaskIntegration(_) => {
            Ok(RunnerTaskEffectDispatchClass::TaskIntegration)
        }
        FreshRunnerEffectDispatchPermit::SprintFinalVerification(_) => {
            Ok(RunnerTaskEffectDispatchClass::SprintFinalVerification)
        }
        FreshRunnerEffectDispatchPermit::SprintApplication(_) => {
            Ok(RunnerTaskEffectDispatchClass::SprintApplication)
        }
        FreshRunnerEffectDispatchPermit::SprintLiveStateCapture(_) => {
            Ok(RunnerTaskEffectDispatchClass::SprintLiveStateCapture)
        }
        FreshRunnerEffectDispatchPermit::SprintRollback(_) => {
            Err(RunnerClientError::InvalidLifecycle(
                "ordinary rollback dispatch is disabled at this lifecycle boundary".into(),
            ))
        }
    }
}

pub(super) fn validate_task_dispatch_request(
    class: RunnerTaskEffectDispatchClass,
    request: &RunnerRequest,
) -> Result<(), RunnerClientError> {
    match (class, request) {
        (RunnerTaskEffectDispatchClass::TaskRunning, RunnerRequest::WorkerRunCommand { .. }) => {
            Ok(())
        }
        (RunnerTaskEffectDispatchClass::TaskRunning, RunnerRequest::WorkerStageChanges { .. }) => {
            Err(RunnerClientError::InvalidLifecycle(
                "candidate publication requires fresh TaskIntegration authority".into(),
            ))
        }
        (
            RunnerTaskEffectDispatchClass::TaskFormalCheck,
            RunnerRequest::WorkerRunCommand { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::TaskIntegration,
            RunnerRequest::WorkerStageChanges { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintFinalVerification,
            RunnerRequest::FinalVerifierRunCommand { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintApplication,
            RunnerRequest::ApplierApplyBundle { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintLiveStateCapture,
            RunnerRequest::LiveStateVerifierCapture { .. },
        )
        | (RunnerTaskEffectDispatchClass::TaskRunning, _) => Ok(()),
        (RunnerTaskEffectDispatchClass::TaskFormalCheck, _) => {
            Err(RunnerClientError::InvalidLifecycle(
                "TaskFormalCheck authority admits only WorkerRunCommand".into(),
            ))
        }
        (RunnerTaskEffectDispatchClass::TaskIntegration, _) => {
            Err(RunnerClientError::InvalidLifecycle(
                "TaskIntegration authority admits only WorkerStageChanges".into(),
            ))
        }
        (RunnerTaskEffectDispatchClass::SprintFinalVerification, _) => {
            Err(RunnerClientError::InvalidLifecycle(
                "SprintFinalVerification authority admits only FinalVerifierRunCommand".into(),
            ))
        }
        (RunnerTaskEffectDispatchClass::SprintApplication, _) => {
            Err(RunnerClientError::InvalidLifecycle(
                "SprintApplication authority admits only ApplierApplyBundle".into(),
            ))
        }
        (RunnerTaskEffectDispatchClass::SprintLiveStateCapture, _) => {
            Err(RunnerClientError::InvalidLifecycle(
                "SprintLiveStateCapture authority admits only LiveStateVerifierCapture".into(),
            ))
        }
    }
}

pub(super) fn claim_matches_task_dispatch_class(
    claim: &PersistedRunnerEffectDispatchClaim,
    class: RunnerTaskEffectDispatchClass,
) -> bool {
    match (class, &claim.authority) {
        (
            RunnerTaskEffectDispatchClass::TaskRunning,
            RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
        ) => claim.running_boundary_id.as_deref() == Some(running_boundary_id.as_str()),
        (
            RunnerTaskEffectDispatchClass::TaskFormalCheck,
            RunnerEffectRequestAuthority::TaskFormalCheck { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::TaskIntegration,
            RunnerEffectRequestAuthority::TaskIntegration { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintFinalVerification,
            RunnerEffectRequestAuthority::SprintFinalVerification { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintApplication,
            RunnerEffectRequestAuthority::SprintApplication { .. },
        )
        | (
            RunnerTaskEffectDispatchClass::SprintLiveStateCapture,
            RunnerEffectRequestAuthority::SprintLiveStateCapture { .. },
        ) => claim.running_boundary_id.is_none(),
        _ => false,
    }
}

pub(super) fn exact_effect_kind(request: &RunnerRequest) -> Result<EffectKind, RunnerClientError> {
    match request {
        RunnerRequest::WorkerReadFile { .. } => Ok(EffectKind::ReadRelativeFile),
        RunnerRequest::WorkerSearchLiteral { .. } => Ok(EffectKind::SearchLiteral),
        RunnerRequest::WorkerCreateFile { .. } => Ok(EffectKind::CreateRegularFile),
        RunnerRequest::WorkerReplaceFile { .. } => Ok(EffectKind::ReplaceRegularFile),
        RunnerRequest::WorkerDeleteFile { .. } => Ok(EffectKind::DeleteRegularFile),
        RunnerRequest::WorkerStageChanges { .. } => Ok(EffectKind::IntegrateChangeSet),
        RunnerRequest::WorkerRunCommand { .. }
        | RunnerRequest::FinalVerifierRunCommand { .. } => Ok(EffectKind::RunCommand),
        RunnerRequest::ApplierApplyBundle { .. } => Ok(EffectKind::ApplyChangeSet),
        RunnerRequest::LiveStateVerifierCapture { .. } => {
            Ok(EffectKind::CaptureWorkspaceState)
        }
        RunnerRequest::ApplierRollback { .. } => Err(RunnerClientError::InvalidLifecycle(
            "ordinary rollback dispatch is disabled until the complete core rollback request and durable artifact authority map to one exact runner request"
                .into(),
        )),
        RunnerRequest::InitializeSession { .. }
        | RunnerRequest::WorkerCaptureLive { .. }
        | RunnerRequest::WorkerCreateShadow { .. }
        | RunnerRequest::WorkerReconcileFile { .. }
        | RunnerRequest::WorkerPrepareStage { .. }
        | RunnerRequest::WorkerReconcileStage { .. }
        | RunnerRequest::WorkerCancel
        | RunnerRequest::FinalVerifierCapture { .. }
        | RunnerRequest::ApplierRecoverPending
        | RunnerRequest::ApplierReconcileStageBundle { .. }
        | RunnerRequest::ApplierReconcile { .. }
        | RunnerRequest::ApplierCaptureLive { .. }
        | RunnerRequest::Shutdown => Err(RunnerClientError::InvalidLifecycle(
            "request has no exact core EffectKind mapping in this client slice".into(),
        )),
    }
}

pub(super) const fn control_role(request: &RunnerRequest) -> Option<RunnerRole> {
    match request {
        RunnerRequest::WorkerCaptureLive { .. }
        | RunnerRequest::WorkerCreateShadow { .. }
        | RunnerRequest::WorkerReconcileFile { .. }
        | RunnerRequest::WorkerPrepareStage { .. }
        | RunnerRequest::WorkerReconcileStage { .. }
        | RunnerRequest::WorkerCancel => Some(RunnerRole::Worker),
        RunnerRequest::FinalVerifierCapture { .. } => Some(RunnerRole::FinalVerifier),
        RunnerRequest::ApplierRecoverPending
        | RunnerRequest::ApplierReconcileStageBundle { .. }
        | RunnerRequest::ApplierReconcile { .. }
        | RunnerRequest::ApplierCaptureLive { .. } => Some(RunnerRole::Applier),
        RunnerRequest::InitializeSession { .. }
        | RunnerRequest::WorkerReadFile { .. }
        | RunnerRequest::WorkerSearchLiteral { .. }
        | RunnerRequest::WorkerCreateFile { .. }
        | RunnerRequest::WorkerReplaceFile { .. }
        | RunnerRequest::WorkerDeleteFile { .. }
        | RunnerRequest::WorkerStageChanges { .. }
        | RunnerRequest::WorkerRunCommand { .. }
        | RunnerRequest::FinalVerifierRunCommand { .. }
        | RunnerRequest::LiveStateVerifierCapture { .. }
        | RunnerRequest::ApplierApplyBundle { .. }
        | RunnerRequest::ApplierRollback { .. }
        | RunnerRequest::Shutdown => None,
    }
}

pub(super) const fn control_label(request: &RunnerRequest) -> &'static str {
    match request {
        RunnerRequest::WorkerCaptureLive { .. } => "worker-capture-live",
        RunnerRequest::WorkerCreateShadow { .. } => "worker-create-shadow",
        RunnerRequest::WorkerReconcileFile { .. } => "worker-reconcile-file",
        RunnerRequest::WorkerPrepareStage { .. } => "worker-prepare-stage",
        RunnerRequest::WorkerReconcileStage { .. } => "worker-reconcile-stage",
        RunnerRequest::FinalVerifierCapture { .. } => "final-verifier-capture",
        RunnerRequest::ApplierRecoverPending => "applier-recover-pending",
        RunnerRequest::ApplierReconcileStageBundle { .. } => "applier-reconcile-stage-bundle",
        RunnerRequest::ApplierReconcile { .. } => "applier-reconcile",
        RunnerRequest::ApplierCaptureLive { .. } => "applier-capture-live",
        _ => "invalid-control",
    }
}

pub(super) fn control_resolves_reconciliation(
    request: &RunnerRequest,
    reference: &WireReconciliationReference,
) -> bool {
    match (request, reference) {
        (
            RunnerRequest::WorkerReconcileFile { path, .. },
            WireReconciliationReference::File {
                path: reference_path,
            },
        ) => path == reference_path,
        (
            RunnerRequest::WorkerReconcileStage { expected_bundle }
            | RunnerRequest::ApplierReconcileStageBundle { expected_bundle },
            WireReconciliationReference::StageBundle { bundle },
        ) => expected_bundle == bundle,
        (
            RunnerRequest::ApplierReconcile { bundle },
            WireReconciliationReference::Application {
                bundle: reference_bundle,
            },
        ) => bundle == reference_bundle,
        _ => false,
    }
}

pub(super) fn runner_purpose(role: RunnerRole) -> RunnerSessionPurpose {
    match role {
        RunnerRole::Worker => RunnerSessionPurpose::TaskWorker,
        RunnerRole::FinalVerifier => RunnerSessionPurpose::FinalVerifier,
        RunnerRole::Applier => RunnerSessionPurpose::Applier,
        RunnerRole::LiveStateVerifier => RunnerSessionPurpose::LiveStateVerifier,
    }
}
