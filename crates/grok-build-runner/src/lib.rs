//! Sandboxed execution and safe workspace mutation.
//!
//! [`CapabilityWorkspace`] and [`ShadowFileTools`] provide the retained,
//! descriptor-relative capture, shadow, staging, and model file-tool boundary.
//! [`CapabilitySafeApplier`] provides journaled descriptor-relative live apply,
//! including deterministic creation of missing parent directories. The older
//! [`ShadowWorkspace`] and [`SafeApplier`] pipelines remain path-based migration
//! APIs and explicitly retain their same-user race warning.

#[cfg(feature = "future-contracts")]
mod application_composition_publisher;
mod apply;
mod capability_apply;
mod capability_workspace;
mod cleanup_proof;
mod command;
mod command_domain_absence;
mod command_output_store;
mod contained_service;
mod durable_directory;
mod environment;
mod file_tools;
mod linux_cgroup_io;
mod linux_command_plan;
mod linux_containment;
mod linux_dev_domain;
mod linux_held_launcher;
#[cfg(feature = "future-contracts")]
mod macos_command_plan;
#[cfg(target_os = "macos")]
mod macos_dev_helper;
#[cfg(feature = "future-contracts")]
mod macos_helper_journal;
mod macos_helper_lifecycle;
mod macos_helper_protocol;
#[cfg(target_os = "macos")]
mod macos_helper_transport;
#[cfg(target_os = "macos")]
mod macos_native_held_launch;
#[cfg(feature = "future-contracts")]
mod macos_runner_held_journal;
mod macos_runner_held_protocol;
#[cfg(feature = "future-contracts")]
mod macos_service_command_journal;
#[cfg(all(target_os = "macos", feature = "future-contracts"))]
mod macos_vz_guest;
mod path;
mod platform_launch;
mod preflight;
mod process_boundary;
mod sensitive_output;
mod sensitive_output_terminal_observation;
mod service;
mod service_contract;
mod service_snapshot;
mod service_tree;
mod snapshot_store;
mod stage_bundle;
#[cfg(feature = "test-support")]
mod test_support;
mod wire;
#[cfg(feature = "future-contracts")]
mod wire_v13;
mod workspace;

pub use capability_apply::{
    CapabilityApplyError, CapabilityApplyOutcome, CapabilityApplyReconciliation,
    CapabilityRecoveryReport, CapabilityRollbackArtifact, CapabilityRollbackArtifactKind,
    CapabilityRollbackArtifactReference, CapabilityRollbackAttempt,
    CapabilityRollbackExpectedEndpoint, CapabilityRollbackLiveConflict,
    CapabilityRollbackObservedEndpoint, CapabilityRollbackOutcome, CapabilityRollbackPathConflict,
    CapabilityRollbackPathObservation, CapabilityRollbackSuccessEvidence,
    CapabilityRollbackTargetContract, CapabilitySafeApplier,
};
pub use capability_workspace::{
    CapabilityShadowDiscardEvidence, CapabilityShadowDiscardRecoveryReport, CapabilityShadowStore,
    CapabilityShadowWorkspace, CapabilityVerifierWorkspace, CapabilityWorkspace,
    CapabilityWorkspaceError,
};
pub use cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, CommandDomainCleanupProofError,
    MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES, ValidatedCommandDomainCleanupProof,
};
#[cfg(feature = "test-support")]
pub use command_domain_absence::{
    CommandDomainAbsenceError, LinuxCommandDomainAbsenceObservationV1, LinuxReapedChildAccounting,
    LinuxScannedRootIdentity, LinuxTaskChildrenRead, observe_linux_command_domain_absence,
};
pub use command_output_store::{
    CapabilityCommandOutputStore, CommandOutputCapture, CommandOutputCaptureCanonicalPayloadV1,
    CommandOutputCaptureFencedResolution, CommandOutputCaptureId,
    CommandOutputCaptureJournalStateV1, CommandOutputCapturePendingRecordClassV1,
    CommandOutputCapturePendingRecordV1, CommandOutputCaptureRecovery,
    CommandOutputCaptureReservation, CommandOutputPublisher, CommandOutputStoreError,
    CommandOutputStreamCapture, CommandOutputStreamCustody, CommandOutputStreamFinishFailure,
    FinishedCommandOutputStream, MAX_COMMAND_OUTPUT_ARTIFACT_BYTES,
    SENSITIVE_OUTPUT_PARTIAL_TERMINAL_UNKNOWN_FORMAT_VERSION_V1,
    SensitiveOutputCleanJournalReceiptV2, SensitiveOutputCleanPublicationRecoveryV1,
    SensitiveOutputCleanTerminalPreparationV1, SensitiveOutputJournalRecoveryV2,
    SensitiveOutputJournalStageV2, SensitiveOutputPartialTerminalUnknownCustodyV1,
    SensitiveOutputPartialTerminalUnknownReasonV1, SensitiveOutputPartialTerminalUnknownV1,
    SensitiveOutputPreLaunchAbortResolutionV2, SensitiveOutputPreLaunchAbortedV2,
    SensitiveOutputRejectionJournalReceiptV2, SensitiveOutputRejectionNativeProofRejoinV1,
    SensitiveOutputRejectionRecoveryV1, SensitiveOutputSplitLaunchUnknownQuarantineV2,
    SensitiveOutputStagingNeutralizationReceiptV1, SensitiveOutputUnknownQuarantineV2,
    SensitiveOutputUnknownTerminalJoinV2, ValidatedCommandOutputArtifactSet,
};
pub use contained_service::{
    MAX_SERVICE_CONTROL_BYTES, MAX_SERVICE_EVENTS, ServiceControl, ServiceEvent,
    ServiceFrameReader, ServiceObservation, ServiceOperation, ServiceStagingError,
    ServiceStagingReceiver, ServiceTermination, run_contained_stdio_service_if_requested,
};
pub use environment::{
    EnvironmentError, EnvironmentPolicy, ScrubbedEnvironment, is_secret_environment_name,
};
pub use file_tools::{
    FileMutationReceipt, FileReadResult, FileToolError, FileToolLimits, LiteralMatch,
    LiteralSearchResult, ShadowFileTools, UnsafeFileKind,
};
pub use grok_build_core::{
    COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION, CommandOutputArtifactSetReferenceV1,
    CommandOutputArtifactSourceV1, CommandOutputStreamArtifactV1, CommandOutputStreamV1,
};
#[doc(hidden)]
pub use linux_cgroup_io::{
    run_linux_native_service_installer_if_requested, run_linux_native_service_open_if_requested,
    run_linux_service_bootstrap_probe_if_requested,
    run_linux_service_child_descriptor_probe_if_requested,
};
pub use linux_dev_domain::run_linux_command_canary_helper_if_requested;
pub use linux_held_launcher::run_linux_held_launcher_if_requested;
#[cfg(all(target_os = "macos", feature = "future-contracts"))]
pub use macos_vz_guest::{
    run_macos_vz_guest_if_requested, run_macos_vz_lifecycle_probe_if_requested,
};
pub use service_contract::{
    CONTAINED_SERVICE_CONTRACT_VERSION, CONTAINED_SERVICE_PROFILE_VERSION, ContainedServiceProfile,
    ContainedServiceRequest, ServiceArchitecture, ServiceLimits, ServicePurpose, ServiceScope,
    ServiceView, service_elf_architecture, service_environment,
};
pub use service_snapshot::{
    MAX_SERVICE_VIEW_FRAME_BYTES, ServiceSnapshot, ServiceSnapshotFile, ServiceSnapshotFrame,
    ServiceSnapshotOperation, ServiceSnapshotPolicy, ServiceSnapshotReceiver,
};
pub use service_tree::{service_path_component_allowed, service_tree_digest};

/// Runs the development-only macOS dedicated-identity helper.
///
/// This is the entry point of the separately named `grok-build-dev-helper`
/// bin target, with its own identity pool, state root and requirement. It cannot be
/// registered through `SMAppService`, and cannot open a production session:
/// the only session type it can publish is validated to be
/// non-production-signed.
///
/// The single argument is the owner-private development state root that the
/// development client created and wrote its manifest into.
///
/// # Errors
///
/// Returns the rendered refusal when the state root, manifest, peer
/// authentication, or served run is not admissible.
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn run_macos_development_helper(
    arguments: &[std::ffi::OsString],
) -> Result<(), std::string::String> {
    macos_dev_helper::run_development_helper_main(arguments).map_err(|error| error.to_string())
}
pub use path::{CanonicalRoot, PathValidationError, ValidatedPath};
pub use platform_launch::{
    MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES, MAX_PLATFORM_LAUNCH_BINDING_BYTES,
    NATIVE_LAUNCH_PREPARATION_EVIDENCE_SCHEMA_VERSION, NativeLaunchPreparationEvidenceError,
    PLATFORM_LAUNCH_ADMISSION_SCHEMA_VERSION, PLATFORM_LAUNCH_BINDING_SCHEMA_VERSION,
    PlatformLaunchBinding, PlatformLaunchBindingError, ValidatedNativeLaunchPreparationEvidence,
    decode_native_launch_preparation_evidence, encode_native_launch_preparation_evidence,
    encode_native_launch_preparation_preflight_refusal,
    validate_native_launch_preparation_authority,
};
pub use preflight::{
    Capability, CapabilityCheck, CapabilityState, HostPlatform, PreflightDisposition,
    SandboxPreflight, inspect_host_sandbox,
};
pub use process_boundary::{
    DescriptorAccess, DescriptorKind, DescriptorObservation, OwnedDescriptorError,
    ProcessBoundaryError, RunnerOwnedDescriptor, RunnerProcessSeal, seal_stdio_runner_process,
};
pub use sensitive_output::SensitiveOutputCoreDumpSuppressionV1;
pub use sensitive_output_terminal_observation::{
    MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1,
    SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_DIGEST_DOMAIN_V1,
    SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
    SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FORMAT_VERSION_V1,
    SensitiveOutputCleanTerminalResponseV1, SensitiveOutputTerminalObservationBranchV1,
    SensitiveOutputTerminalObservationError, SensitiveOutputTerminalObservationV1,
};
pub use service::{
    RunnerServiceError, inspect_private_state_digest, inspect_runner_binary,
    run_stdio_runner_process, runner_protocol_digest, serve_runner_session,
    serve_runner_session_on_installed_linux_service,
};
pub use snapshot_store::{SnapshotStore, SnapshotStoreError};
pub use stage_bundle::{CapabilityStageBundleStore, StageBundleError, StageBundleReference};
#[cfg(feature = "test-support")]
pub use test_support::{
    ClaimedCommandOutputV2TestProofBoxInput, CommandOutputV2TestProofBoxError,
    SensitiveOutputCleanTestCutV1, SensitiveOutputCleanTestProofBoxV1,
    SensitiveOutputJournalCutTestProofBoxV1, SensitiveOutputRejectionTestCutV1,
    SensitiveOutputRejectionTestProofBoxV1, StaticElfLinkageMeasurementV1,
    complete_sensitive_output_clean_test_proof_box_v1,
    complete_sensitive_output_rejection_test_proof_box_v1,
    cut_sensitive_output_clean_test_proof_box_v1, cut_sensitive_output_rejection_test_proof_box_v1,
    cut_sensitive_output_split_launch_test_proof_box_v1, live_containment_refusal_evidence_v12,
    measure_static_elf_linkage_v1,
};
pub use wire::{
    COMMAND_OUTPUT_CAPTURE_DRAIN_ALLOWANCE_BYTES, COMMAND_TERMINAL_CAPTURE_SCHEMA,
    CONTAINED_CAPTURE_LAUNCH_SCHEMA, InitializationReceipt,
    MAX_CONTAINED_CAPTURE_LAUNCH_BINDING_BYTES, MAX_INLINE_COMMAND_RETAINED_BYTES,
    MAX_INLINE_FILE_BYTES, MAX_WIRE_FRAME_BYTES, MAX_WIRE_LITERAL_BYTES, MAX_WIRE_SEARCH_MATCHES,
    RUNNER_WIRE_PROTOCOL_VERSION, RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest,
    RunnerRequestEnvelope, RunnerRequestEnvelopeV12, RunnerRequestEnvelopeV14,
    RunnerRequestEnvelopeV15, RunnerRequestV12, RunnerResponse, RunnerResponseEnvelope,
    RunnerResponseEnvelopeV12, RunnerResponseV12, RunnerRole, RunnerRoleInputAuthority,
    ShutdownPreparedAcknowledgement, ValidatedCommandCaptureLaunchBinding,
    ValidatedCommandCaptureLaunchBindingV12, WireApplicationEvidence, WireBinaryIdentity,
    WireCommandBackendIdentity, WireCommandCleanupProof, WireCommandFailureCodeV12,
    WireCommandOutputCaptureAnchorV1, WireCommandOutputCaptureTerminalV1,
    WireCommandOutputSensitiveRejectionV12, WireCommandSpec, WireCommandStreamEvidence,
    WireCommandTerminalEvidence, WireContainedCommandReleaseAuthorityV1,
    WireContainmentRefusalEvidenceV12, WireEffectContext, WireEnvironmentVariable,
    WireExecutionNetwork, WireExecutionPolicyRequest, WireExplicitRollbackEvidence,
    WireFailureClass, WireFileExpectation, WireLiteralMatch, WireMutationMode, WirePathScope,
    WireProtocolError, WireReconciliationReference, WireResourceLimits, WireRollbackArtifact,
    WireRollbackArtifactKind, WireRollbackArtifactReference, WireRollbackEvidence,
    WireRollbackExpectedEndpoint, WireRollbackLiveConflict, WireRollbackObservedEndpoint,
    WireRollbackPathConflict, WireRollbackPathObservation, WireRollbackTargetContract,
    WireRootIdentity, WireRunnerLaunchPreparationV1, WireStateDisposition, WireWorkspaceCapture,
    WireWorkspaceGrant, WireWorkspaceNetworkPolicy, WireWorkspacePermissions,
    classify_request_frame_version, command_output_capture_maximum, command_stream_output_digest,
    command_stream_output_evidence_bytes, command_terminal_digest, command_terminal_evidence_bytes,
    command_terminal_record_bytes, command_terminal_record_digest,
    decode_command_terminal_record_bytes, decode_contained_capture_launch_binding,
    decode_contained_capture_launch_binding_v12, decode_request_frame, decode_request_frame_v12,
    decode_request_frame_v14, decode_response_frame, decode_response_frame_v12,
    encode_request_frame, encode_request_frame_v12, encode_request_frame_v14,
    encode_request_frame_v15, encode_response_frame, encode_response_frame_v12, sprint_spec_digest,
};
#[cfg(feature = "future-contracts")]
pub use wire_v13::{
    DormantFinalVerifierSessionValidatorV13, RUNNER_WIRE_PROTOCOL_VERSION_V13,
    RunnerCommandAuthorityReadbackV13, RunnerCommandRequestEnvelopeV13, RunnerCommandRequestV13,
    RunnerCommandResponseEnvelopeV13, RunnerCommandResponseV13,
    RunnerFinalVerifierInitializationReceiptV13, RunnerFinalVerifierInitializationRequestV13,
    RunnerRawTerminalOutcomeV13, RunnerRawTerminalResponseV13, RunnerRawTerminalUnknownReasonV13,
    RunnerShutdownReceiptV13, RunnerShutdownRequestV13, RunnerSprintAuthorityReadbackV13,
    RunnerSprintAuthorityRequestEnvelopeV13, RunnerSprintAuthorityRequestV13,
    RunnerSprintAuthorityResponseEnvelopeV13, RunnerSprintAuthorityResponseV13,
    decode_command_request_frame_v13, decode_command_response_frame_v13,
    decode_final_verifier_initialization_receipt_frame_v13,
    decode_final_verifier_initialization_request_frame_v13, decode_raw_terminal_response_frame_v13,
    decode_shutdown_receipt_frame_v13, decode_shutdown_request_frame_v13,
    decode_sprint_authority_request_frame_v13, decode_sprint_authority_response_frame_v13,
    encode_command_request_frame_v13, encode_command_response_frame_v13,
    encode_final_verifier_initialization_receipt_frame_v13,
    encode_final_verifier_initialization_request_frame_v13, encode_raw_terminal_response_frame_v13,
    encode_shutdown_receipt_frame_v13, encode_shutdown_request_frame_v13,
    encode_sprint_authority_request_frame_v13, encode_sprint_authority_response_frame_v13,
    runner_protocol_digest_v13, sprint_spec_digest_v2,
};
pub use workspace::{
    ManifestEntry, ShadowWorkspace, StagedChangeSet, UnsafeEntryKind, WorkspaceManifest,
    WorkspacePipelineError,
};

/// Returns the contract version understood by the runner.
#[must_use]
pub const fn contract_version() -> u32 {
    grok_build_core::CONTRACT_VERSION
}
pub use apply::{ApplyOutcome, ApplyReconciliation, RecoveryReport, SafeApplier, SafeApplyError};
pub use command::{
    CancellationToken, CapturedOutput, CommandResult, CommandSupervisor, CommandTermination,
    LinuxSandboxPlan, SandboxEvidence, SupervisorError, SupervisorPaths, plan_linux_bubblewrap,
};
