//! Durable host-side transport for one sandbox-runner subprocess.
//!
//! A launch intent is committed before `Command::spawn`, initialization is the
//! sole sequence-zero exchange, and the compiler-produced session policy is
//! committed before any effect request can be written. This module transports
//! evidence; it never turns a runner response or process exit into cleanup,
//! verification, application, or completion authority.

#[doc(hidden)]
pub mod native_launch_service;

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
#[cfg(test)]
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;

#[cfg(test)]
use grok_build_core::SprintLiveStateCapturePlan;
use grok_build_core::{
    AgentEvent, AgentEventKind, ApplicationEvidence, ApplicationRequest,
    ApplicationRequestArtifactAuthority, CONTRACT_VERSION, ChangeSet,
    CommandOutputArtifactSourceV1, CommandOutputCaptureIntentV1, CommandSpec,
    CompiledExecutionPolicy, Digest, EffectIntent, EffectKind, EnvironmentVariable, EventLedger,
    ExecutionNetwork, ExecutionOrigin, FreshApplicationDispatchPermit,
    FreshFinalVerificationDispatchPermit, FreshLiveStateCaptureDispatchPermit,
    FreshRunnerEffectDispatchPermit, FreshTaskFormalCheckDispatchPermit,
    FreshTaskIntegrationDispatchPermit, IssuedWorkspaceGrant, LedgerError, LiveRunnerCleanupClaim,
    LiveRunnerLaunchPreparationClaim, MutationMode, PathScope, PersistedEffect,
    PersistedFinishReceipt, PersistedMutationArtifact, PersistedRunnerEffectDispatchClaim,
    PersistedRunnerLaunchCleanupAdmission, PersistedRunnerLaunchPreparation, PersistedSprint,
    PostCompletionRollbackApplicationArtifactAuthority,
    PostCompletionRollbackApplicationArtifactAuthorityState, PostCompletionRollbackApplierRole,
    PostCompletionRollbackIntent, ResourceLimits, RollbackReferenceEvidence,
    RunnerCleanupTerminalRecord, RunnerEffectObservationAuthority, RunnerEffectRequestAuthority,
    RunnerLaunchIntent, RunnerLaunchPreparationAttempt, RunnerLaunchPreparationDisposition,
    RunnerLaunchPreparationOutcome, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SensitiveOutputDetectionPolicyReferenceV1, SprintLiveStateCaptureRequest, SprintSpec,
    TaskAttemptRunningBoundary, TaskIntegrationArtifactReference, TaskIntegrationRequest,
    WorkerCleanupBackend, WorkerCleanupRequest, WorkerLease,
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

use self::native_launch_service::{
    NativeLaunchCleanupAuthority, NativeLaunchCleanupCustody, NativeLaunchReleaseFailure,
    NativeLaunchService, NativeReleasedRunner, NativeReleasedRunnerFailure, cleanup_runner_domain,
    prepare_held_child, release_held_child,
};
#[cfg(test)]
use self::native_launch_service::{
    NativeLaunchCleanupObservation, NativeLaunchCleanupRequest, NativeLaunchPreparationResponse,
    NativeLaunchReleaseAttempt, NativeLaunchReleaseRequest, NativeLaunchReleaseResponse,
};
/// Derives the one durable effect key for a provider call in a worker lease.
///
/// A retry receives a different lease, so the same provider key cannot become
/// replay authority for another task attempt.
#[must_use]
pub fn task_lease_provider_call_effect_key(lease_id: &str, provider_key: &str) -> String {
    format!(
        "task-attempt-{}-{provider_key}",
        Digest::sha256(lease_id.as_bytes())
    )
}

/// Returns the exact shared refusal used when aggregate containment is absent.
#[must_use]
pub fn containment_reason() -> String {
    "aggregate command containment is not ready; command execution did not begin".into()
}

/// Installed-service spawn uses a named nlink=1 copy so `/proc/self/exe` can
/// be re-opened (`open-native-service-process-image`). Ordinary launches keep
/// the sealed memfd. Set only around `launch_linux_installed_service_session`.
static INSTALLED_SERVICE_NAMED_EXEC: AtomicBool = AtomicBool::new(false);

mod cleanup;
mod effects;
mod launch;
mod recovery;
mod session;
mod transport;
mod types;

use cleanup::{
    ensure_native_ordinary_platform_launch_binding_available, launch_cleanup_admission_matches,
    prepare_and_release_ordinary_launch, prepare_ordinary_launch_cleanup,
    spawn_failure_binding_matches, spawn_ordinary_direct_child,
};
use effects::{
    claim_matches_task_dispatch_class, control_label, control_resolves_reconciliation,
    control_role, exact_effect_kind, failure_phase, runner_purpose, task_dispatch_class,
    validate_task_dispatch_request, validate_worker_provider_call_context,
    validate_worker_provider_tool_request,
};
#[cfg(target_os = "linux")]
use launch::authenticated_proc_descriptor_path;
use launch::{ensure_descriptor_execution_supported, launch_failure};
#[cfg(test)]
use recovery::ordinary_role_input_authority;
use recovery::{
    DurableRunnerLaunch, PreparedWorkerStage, RunnerLaunchLedger, RunnerLaunchPersistenceFailure,
};
#[cfg(test)]
use transport::SpawnerBackedNativeLaunchService;
use transport::{
    RunnerLaunchBoundaryFailure, RunnerLaunchBoundaryResult, RunnerProcess,
    RunnerProcessSpawnError, RunnerRequestWriteProgress, RunnerSpawnOutcome, finish_transport,
};
#[cfg(target_os = "linux")]
use types::SEALED_RUNNER_MEMFD_NAME;
use types::{
    INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE, MAX_CLAIMED_EFFECT_FAILURE_DETAIL_CHARS,
    MAX_CLAIMED_EFFECT_FAILURE_EVIDENCE_BYTES, MAX_RETAINED_RUNNER_BINARY_BYTES,
    MAX_RUNNER_STDERR_BYTES, MAX_SEEN_RUNNER_NONCES, MIN_RUNNER_EXECUTABLE_FD, NATIVE_ELF_MACHINE,
    NATIVE_LAUNCH_TARGET, PROCESS_EXIT_GRACE, PROCESS_EXIT_POLL, PROCESS_KILL_GRACE,
    RUNNER_EXCHANGE_DEADLINE, SEEN_RUNNER_NONCES, map_post_completion_ledger_error,
    require_post_completion_application_artifact_authority,
};

#[cfg(test)]
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
    RunnerCommandTransportResponse, RunnerTransport, RunnerTransportExchangeFailure,
    RunnerTransportResponse,
};
#[cfg(test)]
pub(crate) use types::claimed_live_state_capture_response_for_test;
pub use types::{
    ClaimedLiveStateCaptureResponse, ClaimedRunnerCommandEffectResponse,
    ClaimedRunnerEffectExchange, ClaimedRunnerEffectFailure, ClaimedRunnerEffectResponse,
    LiveStateCaptureSessionFailure, RunnerClientError, RunnerClientLaunch,
    RunnerCommandEffectResponse, RunnerEffectFailurePhase, RunnerEffectResponse,
    RunnerLifecycleClient, RunnerTaskEffectDispatchClass, fresh_command_output_capture_id,
    fresh_command_output_capture_intent,
};

#[cfg(test)]
mod compatibility_tests {
    use super::{claimed_live_state_capture_response_for_test, runner_cleanup_required_for_test};

    #[test]
    fn legacy_test_hooks_remain_reexported() {
        let _ = claimed_live_state_capture_response_for_test;
        let _ = runner_cleanup_required_for_test;
    }
}
