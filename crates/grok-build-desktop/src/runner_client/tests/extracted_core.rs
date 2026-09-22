// Test-only compilation of the extracted runner client. It keeps the legacy
// lifecycle-owner proofs at their original private boundary without exposing
// proof hooks through the production crate API.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;

use grok_build_core::{
    AgentEvent, AgentEventKind, ApplicationEvidence, ApplicationRequest,
    ApplicationRequestArtifactAuthority, CONTRACT_VERSION, ChangeSet,
    CommandOutputArtifactSourceV1, CommandOutputCaptureIntentV1, CommandSpec,
    CommandTerminationV1, CompiledExecutionPolicy, Digest, EffectIntent, EffectKind,
    EnvironmentVariable, EventLedger, ExecutionNetwork, ExecutionOrigin,
    FreshApplicationDispatchPermit, FreshFinalVerificationDispatchPermit,
    FreshLiveStateCaptureDispatchPermit, FreshRunnerEffectDispatchPermit,
    FreshTaskFormalCheckDispatchPermit, FreshTaskIntegrationDispatchPermit,
    IssuedWorkspaceGrant, LedgerError, LiveRunnerCleanupClaim, LiveRunnerLaunchPreparationClaim,
    MutationMode, PathScope, PersistedEffect, PersistedFinishReceipt,
    PersistedMutationArtifact, PersistedRunnerEffectDispatchClaim,
    PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation, PersistedSprint,
    PostCompletionRollbackApplicationArtifactAuthority,
    PostCompletionRollbackApplicationArtifactAuthorityState, PostCompletionRollbackApplierRole,
    PostCompletionRollbackIntent, ResourceLimits, RollbackReferenceEvidence,
    RunnerCleanupTerminalRecord, RunnerEffectObservationAuthority, RunnerEffectRequestAuthority,
    RunnerLaunchIntent, RunnerLaunchPreparationAttempt, RunnerLaunchPreparationDisposition,
    RunnerLaunchPreparationOutcome, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputDetectionPolicyReferenceV1, SprintLiveStateCapturePlan,
    SprintLiveStateCaptureRequest, SprintSpec, TaskAttemptRunningBoundary,
    TaskIntegrationArtifactReference, TaskIntegrationRequest, WorkerCleanupBackend,
    WorkerCleanupRequest, WorkerLease,
};
use grok_build_providers::{
    MAX_PROVIDER_FILE_BYTES, ProviderToolCall, ProviderToolIntent, decode_tool_call,
};
use grok_build_runner::{
    CapabilityCommandOutputStore, CommandOutputStoreError, InitializationReceipt,
    MAX_WIRE_FRAME_BYTES, PlatformLaunchBinding, RUNNER_WIRE_PROTOCOL_VERSION,
    RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest, RunnerRequestEnvelope,
    RunnerRequestEnvelopeV12, RunnerRequestEnvelopeV15, RunnerRequestV12, RunnerResponse,
    RunnerResponseEnvelope, RunnerResponseEnvelopeV12, RunnerRole, RunnerRoleInputAuthority,
    ShutdownPreparedAcknowledgement, StageBundleReference, WireCommandOutputCaptureAnchorV1,
    WireCommandSpec, WireContainedCommandReleaseAuthorityV1, WireEffectContext,
    WireEnvironmentVariable, WireExecutionNetwork, WireExecutionPolicyRequest, WireFailureClass,
    WireMutationMode, WirePathScope, WireProtocolError, WireReconciliationReference,
    WireResourceLimits, WireRollbackArtifactReference, WireRootIdentity,
    WireRunnerLaunchPreparationV1, WireWorkspaceGrant, command_output_capture_maximum,
    decode_response_frame, decode_response_frame_v12,
    encode_native_launch_preparation_preflight_refusal, encode_request_frame,
    encode_request_frame_v12, encode_request_frame_v15, inspect_private_state_digest,
    inspect_runner_binary, runner_protocol_digest, sprint_spec_digest,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use sha2::{Digest as _, Sha256};

#[path = "../../../../grok-build-runner-client/src/native_launch_service.rs"]
mod native_launch_service;

use self::native_launch_service::{
    NativeLaunchCleanupAuthority, NativeLaunchCleanupCustody, NativeLaunchReleaseFailure,
    NativeLaunchService, NativeReleasedRunner, NativeReleasedRunnerFailure, cleanup_runner_domain,
    prepare_held_child, release_held_child,
};
use self::native_launch_service::{
    NativeLaunchCleanupObservation, NativeLaunchCleanupRequest, NativeLaunchPreparationResponse,
    NativeLaunchReleaseAttempt, NativeLaunchReleaseRequest, NativeLaunchReleaseResponse,
};

pub(crate) fn task_lease_provider_call_effect_key(lease_id: &str, provider_key: &str) -> String {
    grok_build_runner_client::task_lease_provider_call_effect_key(lease_id, provider_key)
}

pub(crate) fn containment_reason() -> String {
    grok_build_runner_client::containment_reason()
}

static INSTALLED_SERVICE_NAMED_EXEC: AtomicBool = AtomicBool::new(false);

#[path = "../../../../grok-build-runner-client/src/cleanup.rs"]
mod cleanup;
#[path = "../../../../grok-build-runner-client/src/effects.rs"]
mod effects;
#[path = "../../../../grok-build-runner-client/src/launch.rs"]
mod launch;
#[path = "../../../../grok-build-runner-client/src/recovery.rs"]
mod recovery;
#[path = "../../../../grok-build-runner-client/src/session.rs"]
mod session;
#[path = "../../../../grok-build-runner-client/src/transport.rs"]
mod transport;
#[path = "../../../../grok-build-runner-client/src/types.rs"]
mod types;

use cleanup::{
    cleanup_authority_after_preparation_error, direct_child_after_preparation_claim_error,
    ensure_native_ordinary_platform_launch_binding_available, launch_cleanup_admission_matches,
    ordinary_cleanup_backend,
    prepare_and_release_ordinary_launch, prepare_ordinary_launch_cleanup,
    runner_launch_preparation_attempt, spawn_failure_binding_matches, spawn_ordinary_direct_child,
};
use effects::{
    claim_matches_task_dispatch_class, control_label, control_resolves_reconciliation,
    control_role, exact_effect_kind, failure_phase, runner_purpose, task_dispatch_class,
    validate_task_dispatch_request, validate_worker_provider_call_context,
    validate_worker_provider_tool_request,
};
#[cfg(target_os = "linux")]
use launch::authenticated_proc_descriptor_path;
use launch::{
    admit_nonce_into, digest_retained_binary, ensure_descriptor_execution_supported,
    initialization_envelope, launch_failure, prepare_launch, prepare_launch_with_context,
    validate_applier_application_request, validate_applier_input_snapshot,
    validate_native_linux_elf, wire_scope,
};
use recovery::{
    DurableRunnerLaunch, PreparedWorkerStage, RunnerLaunchLedger, RunnerLaunchPersistenceFailure,
    ordinary_role_input_authority, validate_durable_role_input,
};
use transport::{
    NativeIdentityBoundTransport,
    RunnerLaunchBoundaryFailure, RunnerLaunchBoundaryResult, RunnerProcess,
    RunnerProcessSpawnError, RunnerRequestWriteProgress, RunnerSpawnOutcome,
    ScriptedNativeCleanupCustody, ScriptedNativeCleanupMutation, SpawnerBackedNativeLaunchService,
    drain_runner_stderr, finish_transport, native_transport_identity_digest, read_frame_until,
    set_nonblocking, wait_for_fd_with_stderr, write_all_until,
};
#[cfg(target_os = "linux")]
use types::SEALED_RUNNER_MEMFD_NAME;
use types::{
    INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE, MAX_CLAIMED_EFFECT_FAILURE_DETAIL_CHARS,
    MAX_CLAIMED_EFFECT_FAILURE_EVIDENCE_BYTES, MAX_RETAINED_RUNNER_BINARY_BYTES,
    MAX_RUNNER_STDERR_BYTES, MAX_SEEN_RUNNER_NONCES, MIN_RUNNER_EXECUTABLE_FD,
    NATIVE_ELF_MACHINE, NATIVE_LAUNCH_TARGET, PROCESS_EXIT_GRACE, PROCESS_EXIT_POLL,
    PROCESS_KILL_GRACE, RUNNER_EXCHANGE_DEADLINE, SEEN_RUNNER_NONCES,
    map_post_completion_ledger_error, require_post_completion_application_artifact_authority,
};

pub(crate) use cleanup::runner_cleanup_required_for_test;
pub use cleanup::{
    DirectChildOutcome, PostCompletionRollbackTransportFailure,
    PostCompletionRollbackTransportOutcome, RunnerCleanupRequired, RunnerControlResponse,
    RunnerEffectSessionFailure, RunnerLaunchFailure, RunnerSessionFailure,
    RunnerSessionRegistrationState, pre_session_launch_refusal_outcome,
    runner_launch_preparation_attempt_at,
};
pub use effects::{claimed_effect_failure_evidence, worker_request_from_provider_call};
pub use launch::{RetainedRunnerExecutable, current_unix_ms};
pub use transport::{
    RunnerTransport, RunnerTransportExchangeFailure,
};
pub(crate) use types::claimed_live_state_capture_response_for_test;
pub use types::{
    ClaimedLiveStateCaptureResponse, ClaimedRunnerCommandEffectResponse,
    ClaimedRunnerEffectExchange, ClaimedRunnerEffectFailure, ClaimedRunnerEffectResponse,
    LiveStateCaptureSessionFailure, RunnerClientError, RunnerClientLaunch,
    RunnerCommandEffectResponse, RunnerEffectFailurePhase, RunnerEffectResponse,
    RunnerLifecycleClient, RunnerTaskEffectDispatchClass, fresh_command_output_capture_id,
    fresh_command_output_capture_intent,
};
