//! Subprocess evidence for the sealed runner wire/session boundary.

use std::fs;
use std::io::{Read as _, Write as _};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::io::{Seek as _, SeekFrom};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::symlink;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use grok_build_core::{
    AcceptanceCriterion, AcceptanceKind, CommandOutputArtifactSourceV1,
    CommandOutputCaptureAcquiredV1, CommandOutputCaptureDirectoryIdentityV1,
    CommandOutputCaptureFileIdentityV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureStoreHeadV1, CommandSpec, Digest, ExecutionNetwork, ExecutionOrigin,
    ExecutionPolicyCompiler, ExecutionPolicyRequest, FileOperation, IssuedWorkspaceGrant,
    LiveStateCaptureBranch, MutationMode, PathScope, ProviderProfile, ResourceLimits,
    SensitiveOutputDetectionPolicyReferenceV1, SprintBudget, SprintLiveStateCapturePlan,
    SprintLiveStateCaptureRequest, SprintSpec, WorkerLease, WorkspaceGrantIssuer,
    WorkspaceGrantRequest, WorkspaceNetworkPolicy, WorkspacePermissions,
};
use grok_build_runner::{
    CapabilityStageBundleStore, CapabilityWorkspace, InitializationReceipt,
    RUNNER_WIRE_PROTOCOL_VERSION, RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest,
    RunnerRequestEnvelope, RunnerRequestEnvelopeV12, RunnerRequestV12, RunnerResponse,
    RunnerResponseEnvelope, RunnerResponseEnvelopeV12, RunnerResponseV12, RunnerRole,
    RunnerRoleInputAuthority, WireBinaryIdentity, WireCommandFailureCodeV12,
    WireCommandOutputCaptureAnchorV1, WireCommandSpec, WireEffectContext, WireExecutionNetwork,
    WireExecutionPolicyRequest, WireMutationMode, WirePathScope, WireResourceLimits,
    WireWorkspaceGrant, command_output_capture_maximum, decode_response_frame,
    decode_response_frame_v12, encode_request_frame, encode_request_frame_v12,
    inspect_private_state_digest, inspect_runner_binary, sprint_spec_digest,
};
// The v15 launch-preparation and contained-command-release symbols have exactly
// one consumer, `a_contained_command_runs_on_an_installed_native_service`, which
// is `#[cfg(target_os = "linux")]`. Imported unconditionally they are unused on
// macOS; deleted they break the Linux build. Gate the import to its consumer,
// do not resolve this by deletion.
#[cfg(target_os = "linux")]
use grok_build_runner::{
    CapabilityCommandOutputStore, RunnerRequestEnvelopeV15, WireContainedCommandReleaseAuthorityV1,
    WireRunnerLaunchPreparationV1, encode_request_frame_v15,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use sha2::{Digest as _, Sha256};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);
static RUNNER_SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn fixture_live_state_plan(
    expected_snapshot: Digest,
    grant_hash: Digest,
    policy_hash: Digest,
) -> SprintLiveStateCapturePlan {
    let cleanup_ids = vec!["cleanup-1".to_owned()];
    let mut cleanup_preimage = b"grok-build.live-state-required-cleanup-set.sha256.v1\0".to_vec();
    cleanup_preimage.extend_from_slice(&1_u64.to_be_bytes());
    cleanup_preimage.extend_from_slice(&9_u64.to_be_bytes());
    cleanup_preimage.extend_from_slice(b"cleanup-1");
    let plan = SprintLiveStateCapturePlan {
        contract_version: grok_build_core::CONTRACT_VERSION,
        plan_id: "capture-plan-1".into(),
        sprint_id: "sprint-1".into(),
        branch: LiveStateCaptureBranch::VerifiedNoOp {
            final_verification_receipt_id: "verification-1".into(),
            task_integration_receipt_id: "integration-1".into(),
        },
        expected_snapshot,
        grant_hash,
        policy_hash,
        policy_version: 1,
        source_event_id: "event-1".into(),
        source_event_sequence: 1,
        required_cleanup_receipt_ids: cleanup_ids,
        required_cleanup_set_digest: Digest::sha256(&cleanup_preimage),
        planned_at_unix_ms: 100,
    };
    plan.validate().expect("validate live-state fixture plan");
    plan
}

fn runner_spawn_guard() -> std::sync::MutexGuard<'static, ()> {
    RUNNER_SPAWN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The one runner image every test in this file inspects and spawns.
///
/// `inspect_runner_binary` admits only a singly linked executable, so that no
/// second name for the running image can exist while it is being launched.
/// Cargo *copies* `target/<profile>/grok-build-runner` out of `deps/` on macOS
/// (link count 1) but *hardlinks* it on Linux (link count 2), so pointing the
/// launcher evidence straight at `CARGO_BIN_EXE_grok-build-runner` satisfies
/// the gate on one platform by accident and violates it on the other. The gate
/// is right in both cases; the fixture was wrong. Staging one private copy
/// gives every test a genuinely singly linked image, and the same file is both
/// inspected and executed so the runner's self-observation still has to agree
/// with the launcher's evidence field for field.
fn staged_runner_binary() -> &'static Path {
    static STAGED: OnceLock<PathBuf> = OnceLock::new();
    STAGED
        .get_or_init(|| {
            let directory = std::env::temp_dir().join(format!(
                "grok-build-runner-wire-image-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&directory);
            fs::create_dir(&directory).expect("create staged runner directory");
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .expect("make the staged runner directory owner-only");
            let staged = directory.join("grok-build-runner");
            fs::copy(env!("CARGO_BIN_EXE_grok-build-runner"), &staged)
                .expect("copy the runner binary into its private staging directory");
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))
                .expect("make the staged runner owner-only executable");
            let staged = fs::canonicalize(&staged).expect("canonicalize the staged runner binary");
            assert_eq!(
                fs::symlink_metadata(&staged)
                    .expect("inspect the staged runner binary")
                    .nlink(),
                1,
                "a copied runner image must carry exactly one link"
            );
            staged
        })
        .as_path()
}

fn fixture_sprint_spec(grant: &IssuedWorkspaceGrant, base_snapshot: Digest) -> SprintSpec {
    SprintSpec {
        sprint_id: "sprint-1".into(),
        objective: "exercise the subprocess runner contract".into(),
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: "criterion-1".into(),
            description: "the runner retains exact sprint authority".into(),
            kind: AcceptanceKind::HumanJudgment,
        }],
        provider: ProviderProfile {
            backend_id: "fake-provider".into(),
            model_id: "fake-model".into(),
            execution_origin: ExecutionOrigin::HostIsolated,
        },
        budget: SprintBudget {
            max_tasks: 1,
            max_attempts_per_task: 1,
            max_tool_calls: 16,
            max_duration_ms: 30_000,
        },
        max_workers: 1,
        workspace_grant: grant.contract().clone(),
        base_snapshot,
    }
}

struct Fixture {
    top: PathBuf,
    live: PathBuf,
    state: PathBuf,
    base_snapshot: Digest,
    grant: IssuedWorkspaceGrant,
    policy_hash: Digest,
    init: RunnerRequestEnvelope,
}

impl Fixture {
    #[allow(
        clippy::too_many_lines,
        reason = "subprocess fixture keeps launcher and runner contracts visibly identical"
    )]
    fn new(role: RunnerRole) -> Self {
        let requested = Path::new("/tmp").join(format!(
            "grok-build-runner-wire-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&requested).expect("create wire fixture");
        let top = fs::canonicalize(&requested).expect("canonicalize wire fixture");
        let live = top.join("live");
        fs::create_dir(&live).expect("create live workspace");
        fs::create_dir(live.join("src")).expect("create source directory");
        fs::write(live.join("src/lib.rs"), b"pub fn value() -> u8 { 1 }\n")
            .expect("write source fixture");
        let live = fs::canonicalize(live).expect("canonicalize live workspace");
        let private_parent = top.join("private-parent");
        fs::create_dir(&private_parent).expect("create private parent");
        let state = private_parent.join("state");
        fs::create_dir(&state).expect("create private state");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("make private state owner-only");
        let state = fs::canonicalize(state).expect("canonicalize private state");

        let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: format!("grant-{role:?}"),
            workspace_root: live.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue wire fixture grant");
        let (mutation_mode, write_scopes) = match role {
            RunnerRole::Worker => (
                MutationMode::ShadowWorkspace,
                vec![PathScope::Relative(PathBuf::from("src"))],
            ),
            RunnerRole::FinalVerifier | RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                (MutationMode::ReadOnly, Vec::new())
            }
        };
        let policy_id = format!("policy-{role:?}");
        let native_policy_request = ExecutionPolicyRequest {
            policy_id: policy_id.clone(),
            read_scopes: vec![PathScope::Workspace],
            write_scopes,
            environment: Vec::new(),
            network: ExecutionNetwork::None,
            mutation_mode,
            resource_limits: ResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024 * 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
            approval_id: None,
        };
        let policy = ExecutionPolicyCompiler::compile(&grant, native_policy_request)
            .expect("compile wire fixture policy");
        let policy_hash = policy.contract().policy_hash.clone();
        let base_snapshot = CapabilityWorkspace::open(grant.clone())
            .expect("open fixture workspace capability")
            .capture(&grant, 1)
            .expect("capture fixture base")
            .snapshot()
            .snapshot_id
            .clone();
        let binary = staged_runner_binary();
        let (binary_digest, binary_identity) =
            inspect_runner_binary(binary).expect("inspect launcher binary");
        let private_state_digest =
            inspect_private_state_digest(&state).expect("inspect private path chain");
        let sprint_spec = fixture_sprint_spec(&grant, base_snapshot.clone());
        let logical_worker_id = matches!(role, RunnerRole::Worker).then(|| "worker-1".into());
        let worker_lease = matches!(role, RunnerRole::Worker)
            .then(|| {
                WorkerLease::new(
                    "sprint-1".into(),
                    2,
                    "task-1".into(),
                    "worker-1".into(),
                    vec![PathScope::Relative(PathBuf::from("src"))],
                    1,
                )
            })
            .transpose()
            .expect("construct canonical fixture worker lease");
        let wire_policy_request = WireExecutionPolicyRequest {
            policy_id,
            read_scopes: vec![WirePathScope::Workspace],
            write_scopes: match role {
                RunnerRole::Worker => vec![WirePathScope::Relative { path: "src".into() }],
                RunnerRole::FinalVerifier | RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                    Vec::new()
                }
            },
            environment: Vec::new(),
            network: WireExecutionNetwork::None,
            mutation_mode: match role {
                RunnerRole::Worker => WireMutationMode::ShadowWorkspace,
                RunnerRole::FinalVerifier | RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                    WireMutationMode::ReadOnly
                }
            },
            resource_limits: WireResourceLimits {
                wall_time_ms: 1_000,
                max_output_bytes: 1024 * 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
            approval_id: None,
        };
        let init = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: format!("session-{role:?}"),
            runner_nonce: None,
            sequence: 0,
            request_id: "request-init".into(),
            effect: None,
            request: RunnerRequest::InitializeSession {
                launch_id: format!("launch-{role:?}"),
                sprint_id: "sprint-1".into(),
                expected_sprint_spec_digest: sprint_spec_digest(&sprint_spec)
                    .expect("digest fixture sprint"),
                sprint_spec: Box::new(sprint_spec),
                logical_worker_id,
                worker_lease,
                role,
                role_input_authority: match role {
                    RunnerRole::Worker | RunnerRole::FinalVerifier => {
                        RunnerRoleInputAuthority::IntegrationHead
                    }
                    RunnerRole::Applier => RunnerRoleInputAuthority::PlanningBase,
                    RunnerRole::LiveStateVerifier => {
                        let plan = fixture_live_state_plan(
                            base_snapshot.clone(),
                            grant.contract().grant_hash.clone(),
                            policy_hash.clone(),
                        );
                        let plan_digest = plan.plan_digest().expect("digest capture plan");
                        RunnerRoleInputAuthority::LiveStateFinalization {
                            plan: Box::new(plan),
                            plan_digest,
                        }
                    }
                },
                workspace_grant: Box::new(
                    WireWorkspaceGrant::try_from(grant.contract())
                        .expect("fixture workspace path is UTF-8"),
                ),
                execution_policy_request: Box::new(wire_policy_request),
                expected_policy_hash: policy_hash.clone(),
                expected_base_snapshot: base_snapshot.clone(),
                expected_private_state_digest: private_state_digest,
                expected_binary_digest: binary_digest,
                expected_binary_identity: binary_identity,
                private_state_root: state
                    .to_str()
                    .expect("fixture private-state path is UTF-8")
                    .to_owned(),
                shadow_root: matches!(role, RunnerRole::Worker).then(|| {
                    state
                        .join("shadow-1")
                        .to_str()
                        .expect("fixture shadow path is UTF-8")
                        .to_owned()
                }),
            },
        };
        Self {
            top,
            live,
            state,
            base_snapshot,
            grant,
            policy_hash,
            init,
        }
    }

    fn effect_request(
        &self,
        nonce: Digest,
        sequence: u64,
        input_snapshot: Digest,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelope {
        Self::effect_request_for(
            &self.init,
            &self.policy_hash,
            nonce,
            sequence,
            input_snapshot,
            request,
        )
    }

    fn command_effect_request_v12(
        &self,
        nonce: Digest,
        sequence: u64,
        input_snapshot: Digest,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelopeV12 {
        Self::command_effect_request_for_v12(
            &self.init,
            &self.policy_hash,
            nonce,
            sequence,
            input_snapshot,
            request,
        )
    }

    fn live_state_capture_request(&self) -> SprintLiveStateCaptureRequest {
        let RunnerRequest::InitializeSession {
            role_input_authority: RunnerRoleInputAuthority::LiveStateFinalization { plan, .. },
            ..
        } = &self.init.request
        else {
            panic!("fixture is not a live-state verifier")
        };
        SprintLiveStateCaptureRequest::from_plan((**plan).clone())
            .expect("construct live-state capture request")
    }

    fn command_output_capture(
        &self,
        sequence: u64,
        command: &WireCommandSpec,
    ) -> WireCommandOutputCaptureAnchorV1 {
        Self::command_output_capture_for(&self.init, sequence, command)
    }

    /// Reserves a real v2 capture journal in this fixture's private state.
    ///
    /// The fabricated identities in [`Self::command_output_capture`] are enough
    /// for wire-shape tests that never reopen the journal. The installed-service
    /// production drive reaches `reopen_anchored_capture_v2` after minting a
    /// permit, so the journal must exist on disk with the identities the wire
    /// carries.
    #[cfg(target_os = "linux")]
    fn reserved_command_output_capture(
        &self,
        sequence: u64,
        command: &WireCommandSpec,
    ) -> WireCommandOutputCaptureAnchorV1 {
        const DISPATCH_CLAIM_DOMAIN: &[u8] = b"grok-build/runner-effect-dispatch-claim/v1\0";

        let RunnerRequest::InitializeSession {
            launch_id,
            sprint_id,
            expected_private_state_digest,
            execution_policy_request,
            ..
        } = &self.init.request
        else {
            unreachable!("reserved capture requires session initialization")
        };
        let canonical_command = serde_json::to_vec(&CommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: PathBuf::from(&command.working_directory),
        })
        .expect("encode command capture source");
        let effect_id = format!("effect-{sequence}");
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: sprint_id.clone(),
            runner_launch_id: launch_id.clone(),
            runner_session_id: self.init.session_id.clone(),
            effect_id: effect_id.clone(),
            request_digest: Digest::sha256(&canonical_command),
        };
        let mut capture_preimage = serde_json::to_vec(&source).expect("encode capture source");
        capture_preimage.extend_from_slice(expected_private_state_digest.as_str().as_bytes());
        capture_preimage.extend_from_slice(&sequence.to_be_bytes());
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(&capture_preimage).as_str(),
            source,
            expected_private_state_digest.clone(),
            command_output_capture_maximum(
                execution_policy_request.resource_limits.max_output_bytes,
            )
            .expect("fixture output capture maximum"),
            1,
        )
        .expect("construct capture intent");
        let mut claim_preimage = Vec::from(DISPATCH_CLAIM_DOMAIN);
        claim_preimage.extend_from_slice(effect_id.as_bytes());
        let dispatch_claim_id = Digest::sha256(&claim_preimage).to_string();
        let store = CapabilityCommandOutputStore::open(&self.state)
            .expect("open fixture private-state capture store");
        let reservation = store
            .reserve_anchored_capture_v2(
                &intent,
                &dispatch_claim_id,
                2,
                &SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            )
            .expect("reserve real v2 capture journal");
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .expect("hand off reserved capture without a held writer fence");
        WireCommandOutputCaptureAnchorV1::try_new(acquired).expect("construct wire capture anchor")
    }

    fn command_output_capture_for(
        init: &RunnerRequestEnvelope,
        sequence: u64,
        command: &WireCommandSpec,
    ) -> WireCommandOutputCaptureAnchorV1 {
        const DISPATCH_CLAIM_DOMAIN: &[u8] = b"grok-build/runner-effect-dispatch-claim/v1\0";

        let RunnerRequest::InitializeSession {
            launch_id,
            sprint_id,
            expected_private_state_digest,
            execution_policy_request,
            ..
        } = &init.request
        else {
            unreachable!("capture fixture requires session initialization")
        };
        let canonical_command = serde_json::to_vec(&CommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: PathBuf::from(&command.working_directory),
        })
        .expect("encode command capture source");
        let effect_id = format!("effect-{sequence}");
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: sprint_id.clone(),
            runner_launch_id: launch_id.clone(),
            runner_session_id: init.session_id.clone(),
            effect_id: effect_id.clone(),
            request_digest: Digest::sha256(&canonical_command),
        };
        let mut capture_preimage = serde_json::to_vec(&source).expect("encode capture source");
        capture_preimage.extend_from_slice(expected_private_state_digest.as_str().as_bytes());
        capture_preimage.extend_from_slice(&sequence.to_be_bytes());
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(&capture_preimage).as_str(),
            source,
            expected_private_state_digest.clone(),
            command_output_capture_maximum(
                execution_policy_request.resource_limits.max_output_bytes,
            )
            .expect("fixture output capture maximum"),
            1,
        )
        .expect("construct capture intent");
        let mut claim_preimage = Vec::from(DISPATCH_CLAIM_DOMAIN);
        claim_preimage.extend_from_slice(effect_id.as_bytes());
        let identity_seed = 10_000_u64.saturating_add(sequence.saturating_mul(3));
        let acquired = CommandOutputCaptureAcquiredV1::try_new(
            &intent,
            Digest::sha256(&claim_preimage).as_str(),
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(&capture_preimage),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 1,
                inode: identity_seed,
                owner_uid: 501,
                mode: 0o700,
                link_count: 1,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 1,
                inode: identity_seed + 1,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 1,
                inode: identity_seed + 2,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            2,
        )
        .expect("construct acquired capture");
        WireCommandOutputCaptureAnchorV1::try_new(acquired).expect("construct wire capture anchor")
    }

    fn effect_request_for(
        init: &RunnerRequestEnvelope,
        policy_hash: &Digest,
        nonce: Digest,
        sequence: u64,
        input_snapshot: Digest,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelope {
        let request_bytes = match &request {
            RunnerRequest::LiveStateVerifierCapture { request } => serde_json::to_vec(request),
            RunnerRequest::WorkerRunCommand { command, .. }
            | RunnerRequest::FinalVerifierRunCommand { command, .. } => {
                serde_json::to_vec(&CommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory: PathBuf::from(&command.working_directory),
                })
            }
            _ => request.to_core_task_integration_request().map_or_else(
                |_| serde_json::to_vec(&request),
                |core_request| serde_json::to_vec(&core_request),
            ),
        }
        .expect("persist exact request bytes");
        let is_control = request.is_session_control();
        let RunnerRequest::InitializeSession {
            launch_id,
            sprint_id,
            logical_worker_id,
            worker_lease,
            role,
            ..
        } = &init.request
        else {
            unreachable!()
        };
        let worker = matches!(role, RunnerRole::Worker);
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: init.session_id.clone(),
            runner_nonce: Some(nonce),
            sequence,
            request_id: format!("request-{sequence}"),
            effect: (!is_control).then(|| WireEffectContext {
                contract_version: grok_build_core::CONTRACT_VERSION,
                launch_id: launch_id.clone(),
                effect_id: format!("effect-{sequence}"),
                idempotency_key: format!("idempotency-{sequence}"),
                sprint_id: sprint_id.clone(),
                task_id: worker.then(|| "task-1".into()),
                worker_id: logical_worker_id.clone(),
                worker_lease: worker_lease.clone(),
                policy_hash: policy_hash.clone(),
                input_snapshot,
                request_digest: Digest::sha256(&request_bytes),
                transport_commitment_digest: Digest::sha256(b"placeholder"),
            }),
            request,
        };
        if !is_control {
            envelope
                .bind_transport_commitment_digest()
                .expect("bind transport commitment");
        }
        envelope
    }

    fn command_effect_request_for_v12(
        init: &RunnerRequestEnvelope,
        policy_hash: &Digest,
        nonce: Digest,
        sequence: u64,
        input_snapshot: Digest,
        request: RunnerRequest,
    ) -> RunnerRequestEnvelopeV12 {
        assert!(matches!(
            request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ));
        let legacy = Self::effect_request_for(
            init,
            policy_hash,
            nonce,
            sequence,
            input_snapshot,
            request.clone(),
        );
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: legacy.session_id,
            runner_nonce: legacy
                .runner_nonce
                .expect("command request has runner nonce"),
            sequence: legacy.sequence,
            request_id: legacy.request_id,
            effect: legacy.effect.expect("command request has effect context"),
            request: RunnerRequestV12::RunCommand {
                request,
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            },
        };
        envelope
            .bind_transport_commitment_digest()
            .expect("bind additive-v12 command request");
        envelope
    }

    fn read_only_init(
        &self,
        role: RunnerRole,
        expected_snapshot: Digest,
        shadow_root: Option<String>,
    ) -> (RunnerRequestEnvelope, Digest) {
        assert!(!matches!(role, RunnerRole::Worker));
        let policy_id = format!("policy-{role:?}-read-only");
        let policy = ExecutionPolicyCompiler::compile(
            &self.grant,
            ExecutionPolicyRequest {
                policy_id: policy_id.clone(),
                read_scopes: vec![PathScope::Workspace],
                write_scopes: Vec::new(),
                environment: Vec::new(),
                network: ExecutionNetwork::None,
                mutation_mode: MutationMode::ReadOnly,
                resource_limits: ResourceLimits {
                    wall_time_ms: 1_000,
                    max_output_bytes: 1024 * 1024,
                    max_processes: 1,
                    max_memory_bytes: None,
                },
                approval_id: None,
            },
        )
        .expect("compile read-only runner policy");
        let policy_hash = policy.contract().policy_hash.clone();
        let RunnerRequest::InitializeSession {
            sprint_spec,
            expected_sprint_spec_digest,
            workspace_grant,
            expected_private_state_digest,
            expected_binary_digest,
            expected_binary_identity,
            private_state_root,
            ..
        } = &self.init.request
        else {
            unreachable!()
        };
        let init = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: format!("session-{role:?}-read-only"),
            runner_nonce: None,
            sequence: 0,
            request_id: "request-init".into(),
            effect: None,
            request: RunnerRequest::InitializeSession {
                launch_id: format!("launch-{role:?}-read-only"),
                sprint_id: "sprint-1".into(),
                expected_sprint_spec_digest: expected_sprint_spec_digest.clone(),
                sprint_spec: sprint_spec.clone(),
                logical_worker_id: None,
                worker_lease: None,
                role,
                role_input_authority: match role {
                    RunnerRole::FinalVerifier => RunnerRoleInputAuthority::IntegrationHead,
                    RunnerRole::Applier => RunnerRoleInputAuthority::PlanningBase,
                    RunnerRole::LiveStateVerifier => {
                        let plan = fixture_live_state_plan(
                            expected_snapshot.clone(),
                            self.grant.contract().grant_hash.clone(),
                            policy_hash.clone(),
                        );
                        let plan_digest = plan.plan_digest().expect("digest capture plan");
                        RunnerRoleInputAuthority::LiveStateFinalization {
                            plan: Box::new(plan),
                            plan_digest,
                        }
                    }
                    RunnerRole::Worker => unreachable!("read-only fixture is non-worker"),
                },
                workspace_grant: workspace_grant.clone(),
                execution_policy_request: Box::new(WireExecutionPolicyRequest {
                    policy_id,
                    read_scopes: vec![WirePathScope::Workspace],
                    write_scopes: Vec::new(),
                    environment: Vec::new(),
                    network: WireExecutionNetwork::None,
                    mutation_mode: WireMutationMode::ReadOnly,
                    resource_limits: WireResourceLimits {
                        wall_time_ms: 1_000,
                        max_output_bytes: 1024 * 1024,
                        max_processes: 1,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                }),
                expected_policy_hash: policy_hash.clone(),
                expected_base_snapshot: expected_snapshot,
                expected_private_state_digest: expected_private_state_digest.clone(),
                expected_binary_digest: expected_binary_digest.clone(),
                expected_binary_identity: *expected_binary_identity,
                private_state_root: private_state_root.clone(),
                shadow_root,
            },
        };
        (init, policy_hash)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.top);
    }
}

struct RunnerChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: Option<std::thread::JoinHandle<Vec<u8>>>,
}

impl RunnerChild {
    fn spawn() -> Self {
        Self::spawn_command(Command::new(staged_runner_binary()))
    }

    fn spawn_command(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sealed runner");
        let mut stderr = child.stderr.take().expect("runner stderr");
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take().expect("runner stdout"),
            // Drained on its own thread from the moment of spawn. Piping the
            // runner's stderr and only reading it in `finish` deadlocks any
            // child that writes more than one pipe buffer: the runner blocks in
            // `write(2)` on a full stderr pipe, and the test blocks reading a
            // response the runner can no longer emit. Measured, not theorized --
            // a hung drive showed the runner in `pipe_write` on fd 2 while the
            // only test thread was reading stdout.
            stderr: Some(std::thread::spawn(move || {
                let mut drained = Vec::new();
                let _ = stderr.read_to_end(&mut drained);
                drained
            })),
            child,
        }
    }

    fn send(&mut self, request: &RunnerRequestEnvelope) {
        self.stdin
            .as_mut()
            .expect("runner stdin")
            .write_all(&encode_request_frame(request).expect("encode request"))
            .expect("send request");
        self.stdin
            .as_mut()
            .expect("runner stdin")
            .flush()
            .expect("flush request");
    }

    fn send_v12(&mut self, request: &RunnerRequestEnvelopeV12) {
        self.stdin
            .as_mut()
            .expect("runner stdin")
            .write_all(&encode_request_frame_v12(request).expect("encode v12 request"))
            .expect("send v12 request");
        self.stdin
            .as_mut()
            .expect("runner stdin")
            .flush()
            .expect("flush v12 request");
    }

    fn response(&mut self) -> RunnerResponseEnvelope {
        let mut prefix = [0_u8; 4];
        self.stdout
            .read_exact(&mut prefix)
            .expect("read response prefix");
        let length = usize::try_from(u32::from_be_bytes(prefix)).expect("response length fits");
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        self.stdout
            .read_exact(&mut frame[4..])
            .expect("read response payload");
        decode_response_frame(&frame).expect("decode strict response")
    }

    fn response_v12(&mut self) -> RunnerResponseEnvelopeV12 {
        let mut prefix = [0_u8; 4];
        self.stdout
            .read_exact(&mut prefix)
            .expect("read v12 response prefix");
        let length = usize::try_from(u32::from_be_bytes(prefix)).expect("response length fits");
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        self.stdout
            .read_exact(&mut frame[4..])
            .expect("read v12 response payload");
        decode_response_frame_v12(&frame).expect("decode strict v12 response")
    }

    fn initialize(&mut self, request: &RunnerRequestEnvelope) -> InitializationReceipt {
        self.send(request);
        let response = self.response();
        response
            .validate_correlation(request)
            .expect("correlate initialization");
        match response.response {
            RunnerResponse::Initialized { receipt } => receipt,
            other => panic!("runner refused valid initialization: {other:?}"),
        }
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        drop(self.stdin.take());
        let status = self.child.wait().expect("wait for runner");
        let mut stdout = Vec::new();
        self.stdout.read_to_end(&mut stdout).expect("drain stdout");
        let stderr = self
            .stderr
            .take()
            .expect("runner stderr drain")
            .join()
            .expect("join the runner stderr drain");
        (status, stdout, stderr)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn required_test_memfd_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::FUTURE_WRITE
        | rustix::fs::SealFlags::EXEC
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn stream_test_digest(file: &mut fs::File) -> Digest {
    file.seek(SeekFrom::Start(0)).expect("rewind sealed image");
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).expect("read sealed image");
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0)).expect("rewind sealed image");
    let mut text = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    Digest::parse(text).expect("parse streamed sealed-image digest")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn seal_runner_test_image(source: &Path) -> (fs::File, Digest, WireBinaryIdentity) {
    let (expected_digest, source_identity) =
        inspect_runner_binary(source).expect("inspect configured runner source");
    let mut source_file = fs::File::open(source).expect("open configured runner source");
    let created = rustix::fs::memfd_create(
        "grok-build-runner-exec-v1",
        rustix::fs::MemfdFlags::CLOEXEC
            | rustix::fs::MemfdFlags::ALLOW_SEALING
            | rustix::fs::MemfdFlags::EXEC,
    )
    .expect("create executable sealing memfd");
    let retained = rustix::io::fcntl_dupfd_cloexec(&created, 3)
        .expect("retain sealed runner descriptor above stdio");
    drop(created);
    let mut sealed = fs::File::from(retained);
    rustix::fs::fchmod(&sealed, rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR)
        .expect("set exact sealed-image mode");
    let copied = std::io::copy(&mut source_file, &mut sealed).expect("copy runner into memfd");
    assert_eq!(copied, source_identity.byte_length);
    sealed.flush().expect("flush runner memfd");
    sealed.sync_all().expect("synchronize runner memfd");
    rustix::fs::fcntl_add_seals(&sealed, required_test_memfd_seals())
        .expect("make runner memfd immutable");
    assert_eq!(
        rustix::fs::fcntl_get_seals(&sealed).expect("read back runner memfd seals"),
        required_test_memfd_seals()
    );
    let metadata = sealed.metadata().expect("inspect sealed runner memfd");
    assert!(metadata.is_file());
    assert_eq!(metadata.nlink(), 0);
    assert_eq!(metadata.mode() & 0o7_777, 0o500);
    assert_eq!(stream_test_digest(&mut sealed), expected_digest);
    let identity = WireBinaryIdentity {
        device_id: metadata.dev(),
        inode: metadata.ino(),
        byte_length: metadata.len(),
        mode: metadata.mode(),
        owner_uid: metadata.uid(),
        link_count: metadata.nlink(),
    };
    (sealed, expected_digest, identity)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn sealed_memfd_exec_initializes_after_source_mutation_and_name_replacement() {
    let _guard = runner_spawn_guard();
    let mut fixture = Fixture::new(RunnerRole::Applier);
    let configured = fixture.top.join("configured-runner");
    fs::copy(staged_runner_binary(), &configured).expect("copy configured runner");
    fs::set_permissions(&configured, fs::Permissions::from_mode(0o700))
        .expect("secure configured runner");
    let source_before = fs::symlink_metadata(&configured).expect("inspect source inode");
    let (retained, expected_digest, expected_identity) = seal_runner_test_image(&configured);
    let proc_path = format!("/proc/self/fd/{}", retained.as_raw_fd());
    let procfs = rustix::fs::statfs("/proc/self/fd").expect("inspect procfs");
    assert_eq!(procfs.f_type, rustix::fs::PROC_SUPER_MAGIC);

    let mut write_attempt = retained.try_clone().expect("clone sealed memfd handle");
    write_attempt
        .seek(SeekFrom::Start(0))
        .expect("seek sealed write attempt");
    assert_eq!(
        write_attempt
            .write_all(b"mutate")
            .expect_err("content seal must reject in-place writes")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        write_attempt
            .set_len(0)
            .expect_err("size seals must reject truncation")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );

    fs::copy("/usr/bin/false", &configured)
        .or_else(|_| fs::copy("/bin/false", &configured))
        .expect("mutate configured source bytes in place");
    let source_after_mutation =
        fs::symlink_metadata(&configured).expect("reinspect mutated source inode");
    assert_eq!(source_before.dev(), source_after_mutation.dev());
    assert_eq!(source_before.ino(), source_after_mutation.ino());

    let renamed = fixture.top.join("mutated-original-runner");
    fs::rename(&configured, &renamed).expect("replace configured runner name");
    fs::copy("/usr/bin/false", &configured)
        .or_else(|_| fs::copy("/bin/false", &configured))
        .expect("replace configured runner with false");
    fs::set_permissions(&configured, fs::Permissions::from_mode(0o700))
        .expect("secure replacement runner");

    {
        let RunnerRequest::InitializeSession {
            expected_binary_digest,
            expected_binary_identity,
            ..
        } = &mut fixture.init.request
        else {
            unreachable!()
        };
        *expected_binary_digest = expected_digest.clone();
        *expected_binary_identity = expected_identity;
    }

    let mut command = Command::new(&proc_path);
    command.arg0(configured.as_os_str());
    let mut child = RunnerChild::spawn_command(command);
    let receipt = child.initialize(&fixture.init);
    assert_eq!(receipt.binary_digest, expected_digest);
    assert_eq!(receipt.binary_identity, expected_identity);

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    let response = child.response();
    response
        .validate_correlation(&shutdown)
        .expect("correlate descriptor-exec shutdown");
    assert!(matches!(
        response.response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    let (status, trailing_stdout, stderr) = child.finish();
    assert!(status.success(), "descriptor runner stderr: {stderr:?}");
    assert!(trailing_stdout.is_empty());
}

fn assert_failed_before_effect(response: &RunnerResponseEnvelope, code: &str) {
    assert!(matches!(
        &response.response,
        RunnerResponse::Failed {
            code: actual,
            class: grok_build_runner::WireFailureClass::BeforeEffect,
            reconciliation: None,
            ..
        } if actual == code
    ));
}

fn assert_v12_failed_before_effect_with_either(
    response: &RunnerResponseEnvelopeV12,
    first: WireCommandFailureCodeV12,
    second: WireCommandFailureCodeV12,
) {
    assert!(
        matches!(
            &response.response,
            RunnerResponseV12::CommandFailed {
                code: actual,
                class: grok_build_runner::WireFailureClass::BeforeEffect,
                reconciliation: None,
                ..
            } if *actual == first || *actual == second
        ),
        "unexpected pipelined command refusal: {:?}",
        response.response
    );
}

fn assert_pipelined_refusal_diagnostic(response: &RunnerResponseEnvelopeV12, stderr: &[u8]) {
    let RunnerResponseV12::CommandFailed { code, .. } = &response.response else {
        panic!("expected a typed command refusal")
    };
    let detail = match code {
        WireCommandFailureCodeV12::InvalidAuthority => {
            "invalid command: cancellation was already requested before contained preflight"
                .to_owned()
        }
        WireCommandFailureCodeV12::ContainmentUnavailable => {
            // This fixture installs neither a native service nor a dedicated-identity
            // transport, and requests no memory ceiling. Assert its exact diagnostic
            // instead of accepting unrelated stderr or suppressing production output.
            let reason = if cfg!(target_os = "macos") {
                "the macOS dedicated-identity helper transport is not installed; this backend holds no reserved execution identity and therefore enforces none of the mandatory contained-execution controls"
            } else if cfg!(target_os = "linux") {
                "the Linux native command service is not installed; this backend holds no delegated cgroup-v2 domain, no journaled command plan, and no admitted launch image, and therefore enforces none of the mandatory contained-execution controls"
            } else {
                panic!("this wire fixture requires a macOS or Linux contained backend")
            };
            format!(
                "sandbox capability missing: {reason}: cannot enforce \
                 [DescriptorExec, ExactArgv, ReplacedEnvironment, ClosedInheritedDescriptors, \
                 DescriptorWorkingDirectory, FilesystemPolicy, NetworkPolicy, ExternalWallClock, \
                 CompleteBoundedOutput, DescendantLimit, DescendantDomainKill, ActiveCanaries]"
            )
        }
        other => panic!("unexpected pipelined refusal code: {other:?}"),
    };
    assert_eq!(
        std::str::from_utf8(stderr).expect("refusal diagnostic is UTF-8"),
        format!("contained command refused before launch: {detail}\n"),
        "exactly one diagnostic must agree with the typed refusal"
    );
}

fn assert_v12_failed_before_effect(
    response: &RunnerResponseEnvelopeV12,
    code: WireCommandFailureCodeV12,
) {
    assert!(matches!(
        &response.response,
        RunnerResponseV12::CommandFailed {
            code: actual,
            class: grok_build_runner::WireFailureClass::BeforeEffect,
            reconciliation: None,
            ..
        } if *actual == code
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // One end-to-end wire fixture seals every verifier-only boundary.
fn live_state_verifier_capture_is_effect_bound_complete_and_role_sealed() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::LiveStateVerifier);
    let core_request = fixture.live_state_capture_request();
    let missing_effect = RunnerRequestEnvelope {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
        session_id: fixture.init.session_id.clone(),
        runner_nonce: Some(Digest::sha256(b"runner nonce")),
        sequence: 1,
        request_id: "request-effectless-live-capture".into(),
        effect: None,
        request: RunnerRequest::LiveStateVerifierCapture {
            request: Box::new(core_request.clone()),
        },
    };
    assert!(encode_request_frame(&missing_effect).is_err());

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    assert_eq!(receipt.role, RunnerRole::LiveStateVerifier);
    assert!(receipt.logical_worker_id.is_none());
    assert!(receipt.worker_lease.is_none());
    assert!(matches!(
        receipt.role_input_authority,
        RunnerRoleInputAuthority::LiveStateFinalization { .. }
    ));

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::LiveStateVerifierCapture {
            request: Box::new(core_request.clone()),
        },
    );
    assert!(!capture.request.is_session_control());
    child.send(&capture);
    let response = child.response();
    response
        .validate_correlation(&capture)
        .expect("correlate exact live-state capture");

    let mut crossed_grant = response.clone();
    let RunnerResponse::LiveWorkspaceCaptured { manifest } = &mut crossed_grant.response else {
        panic!("expected complete live workspace manifest")
    };
    manifest.grant_hash = Digest::sha256(b"crossed grant");
    assert!(crossed_grant.validate_correlation(&capture).is_err());

    let mut crossed_time = response.clone();
    let RunnerResponse::LiveWorkspaceCaptured { manifest } = &mut crossed_time.response else {
        unreachable!()
    };
    manifest.capture_started_at_unix_ms = core_request.plan.planned_at_unix_ms - 1;
    assert!(crossed_time.validate_correlation(&capture).is_err());

    let RunnerResponse::LiveWorkspaceCaptured { manifest } = response.response else {
        panic!("expected complete live workspace manifest")
    };
    manifest
        .validate()
        .expect("validate canonical core manifest");
    assert_eq!(manifest.grant_hash, fixture.grant.contract().grant_hash);
    assert_eq!(manifest.manifest_digest, fixture.base_snapshot);
    assert_eq!(
        manifest
            .computed_digest()
            .expect("recompute manifest digest"),
        fixture.base_snapshot
    );
    assert!(manifest.capture_started_at_unix_ms >= core_request.plan.planned_at_unix_ms);
    assert!(manifest.captured_at_unix_ms >= manifest.capture_started_at_unix_ms);
    assert_eq!(manifest.entries.len(), 1);
    assert_eq!(manifest.entries[0].path, "src/lib.rs");
    assert_eq!(
        manifest.entries[0].content_digest,
        Digest::sha256(b"pub fn value() -> u8 { 1 }\n")
    );
    assert_eq!(manifest.entries[0].byte_length, 27);

    let shutdown = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    let shutdown_response = child.response();
    shutdown_response
        .validate_correlation(&shutdown)
        .expect("correlate live-state shutdown");
    let RunnerResponse::ShutdownPrepared { acknowledgement } = shutdown_response.response else {
        panic!("expected live-state shutdown acknowledgement")
    };
    assert_eq!(acknowledgement.role, RunnerRole::LiveStateVerifier);
    assert!(!acknowledgement.private_shadow_present);
    let applier_acknowledgement = grok_build_runner::ShutdownPreparedAcknowledgement::new(
        &acknowledgement.session_id,
        receipt.runner_nonce,
        RunnerRole::Applier,
        acknowledgement.accepted_request_count,
        0,
        false,
    );
    assert_ne!(
        acknowledgement.acknowledgement_digest,
        applier_acknowledgement.acknowledgement_digest
    );
    assert!(child.finish().0.success());
}

#[test]
fn live_state_post_capture_conversion_failure_is_after_known_effect() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::LiveStateVerifier);
    let core_request = fixture.live_state_capture_request();
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);

    fs::write(
        fixture.live.join("not\\portable"),
        b"captured but not portable\n",
    )
    .expect("write native-only manifest path");
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::LiveStateVerifierCapture {
            request: Box::new(core_request),
        },
    );
    child.send(&capture);
    let response = child.response();
    response
        .validate_correlation(&capture)
        .expect("correlate after-known capture failure");
    assert!(matches!(
        response.response,
        RunnerResponse::Failed {
            ref code,
            class: grok_build_runner::WireFailureClass::AfterKnownEffect,
            reconciliation: None,
            ..
        } if code == "live_workspace_evidence_unavailable"
    ));

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    assert!(matches!(
        child.response().response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    assert!(child.finish().0.success());
}

#[test]
fn live_state_first_descriptor_scan_rejection_is_after_known_effect() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::LiveStateVerifier);
    let core_request = fixture.live_state_capture_request();
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);

    symlink("src/lib.rs", fixture.live.join("unsafe-link"))
        .expect("create descriptor-scan rejection fixture");
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::LiveStateVerifierCapture {
            request: Box::new(core_request),
        },
    );
    child.send(&capture);
    let response = child.response();
    response
        .validate_correlation(&capture)
        .expect("correlate first-scan capture failure");
    assert!(matches!(
        response.response,
        RunnerResponse::Failed {
            ref code,
            class: grok_build_runner::WireFailureClass::AfterKnownEffect,
            reconciliation: None,
            ..
        } if code == "live_workspace_capture_incomplete"
    ));

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    assert!(matches!(
        child.response().response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    assert!(child.finish().0.success());
}

#[test]
fn live_state_verifier_rejects_a_crossed_initialized_plan_before_capture() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::LiveStateVerifier);
    let mut crossed_request = fixture.live_state_capture_request();
    crossed_request.plan.plan_id = "capture-plan-crossed".into();
    crossed_request
        .validate()
        .expect("validate crossed request shape");
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce,
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::LiveStateVerifierCapture {
            request: Box::new(crossed_request),
        },
    );
    child.send(&capture);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("effect context"));
}

#[test]
fn valid_worker_session_binds_snapshots_and_command_stays_fail_closed() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let RunnerRequest::InitializeSession { worker_lease, .. } = &fixture.init.request else {
        unreachable!()
    };
    assert_eq!(receipt.worker_lease.as_ref(), worker_lease.as_ref());

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let response = child.response();
    response
        .validate_correlation(&capture)
        .expect("capture correlation");
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected workspace capture")
    };

    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id.clone(),
        },
    );
    child.send(&create_shadow);
    let response = child.response();
    response
        .validate_correlation(&create_shadow)
        .expect("shadow correlation");
    assert!(matches!(
        response.response,
        RunnerResponse::ShadowCreated { .. }
    ));

    let command_spec = WireCommandSpec {
        program: "/bin/sleep".into(),
        arguments: vec!["30".into()],
        working_directory: String::new(),
    };
    let output_capture = fixture.command_output_capture(3, &command_spec);
    let command = fixture.command_effect_request_v12(
        receipt.runner_nonce.clone(),
        3,
        capture.snapshot_id,
        RunnerRequest::WorkerRunCommand {
            command: command_spec,
            output_capture,
        },
    );
    child.send_v12(&command);
    let response = child.response_v12();
    response
        .validate_correlation(&command)
        .expect("command correlation");
    assert_v12_failed_before_effect(&response, WireCommandFailureCodeV12::ContainmentUnavailable);

    let cancellation = fixture.effect_request(
        receipt.runner_nonce,
        4,
        Digest::sha256(b"ledger-input-shutdown"),
        RunnerRequest::WorkerCancel,
    );
    child.send(&cancellation);
    let response = child.response();
    response
        .validate_correlation(&cancellation)
        .expect("cancellation correlation");
    let RunnerResponse::CancellationPrepared { acknowledgement } = response.response else {
        panic!("expected non-authoritative cancellation acknowledgement")
    };
    assert!(acknowledgement.runner_exit_pending);
    assert!(acknowledgement.private_shadow_present);
    let (status, stdout, stderr) = child.finish();
    assert!(
        status.success(),
        "runner stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(stdout.is_empty());
}

#[test]
fn pipelined_fail_closed_command_then_shutdown_is_drained_in_order() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let capture_response = child.response();
    capture_response
        .validate_correlation(&capture)
        .expect("correlate pipelined-test capture");
    let RunnerResponse::WorkspaceCaptured { capture } = capture_response.response else {
        panic!("expected pipelined-test capture")
    };
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id.clone(),
        },
    );
    child.send(&create_shadow);
    let create_shadow_response = child.response();
    create_shadow_response
        .validate_correlation(&create_shadow)
        .expect("correlate pipelined-test shadow creation");
    assert!(matches!(
        create_shadow_response.response,
        RunnerResponse::ShadowCreated { .. }
    ));

    let command_spec = WireCommandSpec {
        program: "/usr/bin/true".into(),
        arguments: Vec::new(),
        working_directory: String::new(),
    };
    let output_capture = fixture.command_output_capture(3, &command_spec);
    let command = fixture.command_effect_request_v12(
        receipt.runner_nonce.clone(),
        3,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerRunCommand {
            command: command_spec,
            output_capture,
        },
    );
    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        4,
        capture.snapshot_id,
        RunnerRequest::Shutdown,
    );
    let command_frame = encode_request_frame_v12(&command).expect("encode fail-closed v12 command");
    let shutdown_frame = encode_request_frame(&shutdown).expect("encode pipelined shutdown");
    let mut pipelined = Vec::with_capacity(command_frame.len() + shutdown_frame.len());
    pipelined.extend_from_slice(&command_frame);
    pipelined.extend_from_slice(&shutdown_frame);
    let written = child
        .stdin
        .as_mut()
        .expect("runner stdin")
        .write(&pipelined)
        .expect("write pipelined requests once");
    assert_eq!(written, pipelined.len());

    let command_response = child.response_v12();
    command_response
        .validate_correlation(&command)
        .expect("correlate first pipelined response");
    // The command is now a real contained job, and `coordinate_active_step`
    // drains pending input -- admitting and therefore cancelling on the
    // pipelined shutdown -- before it looks at the job's outcome. Two
    // fail-closed refusals are therefore genuinely reachable and neither is
    // preferred: the backend's own containment refusal when preparation and
    // preflight win, or the boundary's pre-preflight cancellation refusal when
    // the pipelined shutdown does. Both are typed `BeforeEffect` failures with
    // no reconciliation, which is exactly what this test exists to prove about
    // ordering and draining. Asserting one of them would be asserting a race.
    assert_v12_failed_before_effect_with_either(
        &command_response,
        WireCommandFailureCodeV12::ContainmentUnavailable,
        WireCommandFailureCodeV12::InvalidAuthority,
    );

    let shutdown_response = child.response();
    shutdown_response
        .validate_correlation(&shutdown)
        .expect("correlate second pipelined response");
    let RunnerResponse::ShutdownPrepared { acknowledgement } = shutdown_response.response else {
        panic!("expected pipelined shutdown acknowledgement")
    };
    // Exactly one command effect was admitted to the containment boundary.
    // This read zero while the command seam returned a type-level `None` for
    // every request and no job was ever spawned.
    assert_eq!(acknowledgement.command_effects_admitted, 1);

    let (status, trailing_stdout, stderr) = child.finish();
    assert!(
        status.success(),
        "runner stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(trailing_stdout.is_empty());
    assert_pipelined_refusal_diagnostic(&command_response, &stderr);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized subprocess flow proves no-op preparation remains read-only until exact claimed publication"
)]
fn verified_noop_prepare_and_claimed_stage_are_end_to_end() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut worker = RunnerChild::spawn();
    let receipt = worker.initialize(&fixture.init);

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    worker.send(&capture);
    let response = worker.response();
    response
        .validate_correlation(&capture)
        .expect("no-op base capture correlation");
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected no-op base capture")
    };

    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id.clone(),
        },
    );
    worker.send(&create_shadow);
    let response = worker.response();
    response
        .validate_correlation(&create_shadow)
        .expect("no-op shadow correlation");
    assert!(matches!(
        response.response,
        RunnerResponse::ShadowCreated { .. }
    ));

    let prepare = fixture.effect_request(
        receipt.runner_nonce.clone(),
        3,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerPrepareStage {
            change_set_id: "changeset-noop-e2e".into(),
            created_at_unix_ms: 2,
        },
    );
    worker.send(&prepare);
    let response = worker.response();
    response
        .validate_correlation(&prepare)
        .expect("no-op preparation correlation");
    let RunnerResponse::StagePrepared {
        change_set,
        expected_bundle,
    } = response.response
    else {
        panic!("expected verified no-op stage preparation")
    };
    assert_eq!(change_set.change_set_id, "changeset-noop-e2e");
    assert_eq!(change_set.base_snapshot, fixture.base_snapshot);
    assert_eq!(change_set.result_snapshot, fixture.base_snapshot);
    assert!(change_set.operations.is_empty());

    let bundle_store = CapabilityStageBundleStore::open(&fixture.state)
        .expect("open fixture bundle store for reconciliation");
    assert!(bundle_store.reconcile(&expected_bundle).is_err());

    let stage = fixture.effect_request(
        receipt.runner_nonce.clone(),
        4,
        change_set.base_snapshot.clone(),
        RunnerRequest::WorkerStageChanges {
            change_set: change_set.clone(),
            expected_bundle: expected_bundle.clone(),
        },
    );
    worker.send(&stage);
    let response = worker.response();
    response
        .validate_correlation(&stage)
        .expect("no-op claimed-stage correlation");
    let RunnerResponse::StageBundlePersisted { bundle } = response.response else {
        panic!("expected verified no-op bundle publication")
    };
    assert_eq!(bundle, expected_bundle);
    assert_eq!(
        bundle_store
            .reconcile(&expected_bundle)
            .expect("reconcile exact no-op publication"),
        expected_bundle
    );
    assert_eq!(
        bundle_store
            .load(&expected_bundle)
            .expect("load exact no-op publication")
            .change_set(),
        change_set.as_ref()
    );

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        5,
        fixture.base_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    worker.send(&shutdown);
    let response = worker.response();
    response
        .validate_correlation(&shutdown)
        .expect("no-op worker shutdown correlation");
    assert!(matches!(
        response.response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    assert!(worker.finish().0.success());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized end-to-end test proves worker, verifier, and applier role separation"
)]
fn mutation_stage_final_verifier_and_applier_evidence_boundaries_are_end_to_end() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut worker = RunnerChild::spawn();
    let worker_receipt = worker.initialize(&fixture.init);

    let capture = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    worker.send(&capture);
    let response = worker.response();
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected worker base capture")
    };
    assert_eq!(capture.snapshot_id, fixture.base_snapshot);

    let create_shadow = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: fixture.base_snapshot.clone(),
        },
    );
    worker.send(&create_shadow);
    assert!(matches!(
        worker.response().response,
        RunnerResponse::ShadowCreated { .. }
    ));

    let contents = b"pub fn generated() -> u8 { 2 }\n".to_vec();
    let create_file = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        3,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateFile {
            path: "src/generated.rs".into(),
            contents,
        },
    );
    worker.send(&create_file);
    let mutation = worker.response();
    mutation
        .validate_correlation(&create_file)
        .expect("mutation correlation");
    let RunnerResponse::FileMutated {
        input_snapshot,
        result_snapshot,
        ..
    } = mutation.response
    else {
        panic!("expected descriptor-recaptured mutation receipt")
    };
    assert_eq!(input_snapshot, fixture.base_snapshot);
    assert_ne!(result_snapshot, input_snapshot);

    let prepare_stage = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        4,
        result_snapshot.clone(),
        RunnerRequest::WorkerPrepareStage {
            change_set_id: "changeset-e2e-1".into(),
            created_at_unix_ms: 2,
        },
    );
    worker.send(&prepare_stage);
    let prepare_response = worker.response();
    prepare_response
        .validate_correlation(&prepare_stage)
        .expect("stage preparation correlation");
    let RunnerResponse::StagePrepared {
        change_set,
        expected_bundle,
    } = prepare_response.response
    else {
        panic!("expected exact read-only stage preparation")
    };
    assert_eq!(change_set.base_snapshot, fixture.base_snapshot);
    assert_eq!(change_set.result_snapshot, result_snapshot);

    let mut mismatched_change_set = change_set.as_ref().clone();
    let FileOperation::Create { result_hash, .. } = &mut mismatched_change_set.operations[0] else {
        panic!("fixture mutation must stage one create")
    };
    *result_hash = Digest::sha256(b"different authorized endpoint");
    let mismatched_stage = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        5,
        mismatched_change_set.base_snapshot.clone(),
        RunnerRequest::WorkerStageChanges {
            change_set: Box::new(mismatched_change_set),
            expected_bundle: expected_bundle.clone(),
        },
    );
    worker.send(&mismatched_stage);
    let mismatch_response = worker.response();
    mismatch_response
        .validate_correlation(&mismatched_stage)
        .expect("mismatch refusal correlation");
    assert!(matches!(
        mismatch_response.response,
        RunnerResponse::Failed {
            class: grok_build_runner::WireFailureClass::BeforeEffect,
            ..
        }
    ));

    let stage = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        6,
        change_set.base_snapshot.clone(),
        RunnerRequest::WorkerStageChanges {
            change_set,
            expected_bundle: expected_bundle.clone(),
        },
    );
    worker.send(&stage);
    let stage_response = worker.response();
    stage_response
        .validate_correlation(&stage)
        .expect("stage correlation");
    let RunnerResponse::StageBundlePersisted { bundle } = stage_response.response else {
        panic!("expected immutable stage reference")
    };
    assert_eq!(bundle, expected_bundle);
    assert_eq!(bundle.base_snapshot, fixture.base_snapshot);
    assert_eq!(bundle.result_snapshot, result_snapshot);

    let reconcile_stage = fixture.effect_request(
        worker_receipt.runner_nonce.clone(),
        7,
        result_snapshot.clone(),
        RunnerRequest::WorkerReconcileStage {
            expected_bundle: bundle.clone(),
        },
    );
    worker.send(&reconcile_stage);
    let reconcile_response = worker.response();
    reconcile_response
        .validate_correlation(&reconcile_stage)
        .expect("stage reconciliation correlation");
    assert!(matches!(
        reconcile_response.response,
        RunnerResponse::StageBundleReconciled {
            bundle: reconciled
        } if reconciled == bundle
    ));

    let shutdown = fixture.effect_request(
        worker_receipt.runner_nonce,
        8,
        result_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    worker.send(&shutdown);
    let _ = worker.response();
    assert!(worker.finish().0.success());

    let shadow_root = fixture
        .state
        .join("shadow-1")
        .to_str()
        .expect("fixture shadow path is UTF-8")
        .to_owned();
    let (verifier_init, verifier_policy_hash) = fixture.read_only_init(
        RunnerRole::FinalVerifier,
        result_snapshot.clone(),
        Some(shadow_root),
    );
    let mut verifier = RunnerChild::spawn();
    let verifier_receipt = verifier.initialize(&verifier_init);
    let verify_capture = Fixture::effect_request_for(
        &verifier_init,
        &verifier_policy_hash,
        verifier_receipt.runner_nonce.clone(),
        1,
        result_snapshot.clone(),
        RunnerRequest::FinalVerifierCapture {
            created_at_unix_ms: 3,
        },
    );
    verifier.send(&verify_capture);
    let response = verifier.response();
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected final-verifier capture")
    };
    assert_eq!(capture.snapshot_id, result_snapshot);

    let command_spec = WireCommandSpec {
        program: "/usr/bin/true".into(),
        arguments: Vec::new(),
        working_directory: String::new(),
    };
    let output_capture = Fixture::command_output_capture_for(&verifier_init, 2, &command_spec);
    let verify_command = Fixture::command_effect_request_for_v12(
        &verifier_init,
        &verifier_policy_hash,
        verifier_receipt.runner_nonce.clone(),
        2,
        result_snapshot.clone(),
        RunnerRequest::FinalVerifierRunCommand {
            command: command_spec,
            output_capture,
        },
    );
    verifier.send_v12(&verify_command);
    let verify_response = verifier.response_v12();
    verify_response
        .validate_correlation(&verify_command)
        .expect("final-verifier v12 command correlation");
    assert_v12_failed_before_effect(
        &verify_response,
        WireCommandFailureCodeV12::ContainmentUnavailable,
    );
    let verifier_shutdown = Fixture::effect_request_for(
        &verifier_init,
        &verifier_policy_hash,
        verifier_receipt.runner_nonce,
        3,
        result_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    verifier.send(&verifier_shutdown);
    let _ = verifier.response();
    assert!(verifier.finish().0.success());

    fs::write(fixture.live.join("unrelated.txt"), b"preserve me\n")
        .expect("inject unrelated live edit before apply");

    let (applier_init, applier_policy_hash) =
        fixture.read_only_init(RunnerRole::Applier, fixture.base_snapshot.clone(), None);
    let mut applier = RunnerChild::spawn();
    let applier_receipt = applier.initialize(&applier_init);
    let recover = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        applier_receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::ApplierRecoverPending,
    );
    applier.send(&recover);
    assert!(matches!(
        applier.response().response,
        RunnerResponse::RecoveryCompleted { .. }
    ));
    let reopen_staged_bundle = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        applier_receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::ApplierReconcileStageBundle {
            expected_bundle: bundle.clone(),
        },
    );
    applier.send(&reopen_staged_bundle);
    let reopened = applier.response();
    reopened
        .validate_correlation(&reopen_staged_bundle)
        .expect("fresh-process stage-bundle reconciliation correlation");
    assert!(matches!(
        reopened.response,
        RunnerResponse::StageBundleReconciled {
            bundle: reconciled
        } if reconciled == bundle
    ));
    let apply = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        applier_receipt.runner_nonce.clone(),
        3,
        bundle.base_snapshot.clone(),
        RunnerRequest::ApplierApplyBundle {
            bundle: bundle.clone(),
        },
    );
    applier.send(&apply);
    let response = applier.response();
    response
        .validate_correlation(&apply)
        .expect("application correlation");
    let RunnerResponse::ApplicationApplied { evidence } = response.response else {
        panic!("expected exact application evidence")
    };
    assert_eq!(evidence.bundle, bundle);
    assert_eq!(
        fs::read(fixture.live.join("src/generated.rs")).expect("read applied target"),
        b"pub fn generated() -> u8 { 2 }\n"
    );
    assert_eq!(
        fs::read(fixture.live.join("unrelated.txt")).expect("read unrelated live edit"),
        b"preserve me\n"
    );

    let first_applier_shutdown = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        applier_receipt.runner_nonce.clone(),
        4,
        bundle.result_snapshot.clone(),
        RunnerRequest::Shutdown,
    );
    applier.send(&first_applier_shutdown);
    let _ = applier.response();
    assert!(applier.finish().0.success());

    let mut applier = RunnerChild::spawn();
    let restarted_receipt = applier.initialize(&applier_init);
    let recover = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce.clone(),
        1,
        bundle.base_snapshot.clone(),
        RunnerRequest::ApplierRecoverPending,
    );
    applier.send(&recover);
    let recovery = applier.response();
    assert!(matches!(
        recovery.response,
        RunnerResponse::RecoveryCompleted {
            recovered_change_sets,
            abandoned_preparations,
        } if recovered_change_sets.is_empty() && abandoned_preparations.is_empty()
    ));
    let reconcile = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce.clone(),
        2,
        bundle.base_snapshot.clone(),
        RunnerRequest::ApplierReconcile {
            bundle: bundle.clone(),
        },
    );
    applier.send(&reconcile);
    let response = applier.response();
    response
        .validate_correlation(&reconcile)
        .expect("committed reconciliation correlation");
    let RunnerResponse::ApplicationApplied {
        evidence: reconciled,
    } = response.response
    else {
        panic!("committed reconciliation must return application evidence")
    };
    assert_eq!(reconciled.transaction_id, evidence.transaction_id);

    let mut forged_reference = reconciled.rollback.clone();
    forged_reference.transaction_inode = forged_reference.transaction_inode.wrapping_add(1);
    forged_reference.artifacts_digest =
        Digest::sha256(&forged_reference.reopened_artifacts_bytes());
    let forged_rollback = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce.clone(),
        3,
        bundle.result_snapshot.clone(),
        RunnerRequest::ApplierRollback {
            bundle: bundle.clone(),
            rollback: forged_reference,
        },
    );
    applier.send(&forged_rollback);
    let response = applier.response();
    response
        .validate_correlation(&forged_rollback)
        .expect("forged rollback refusal correlation");
    assert_failed_before_effect(&response, "rollback_reference_mismatch");
    assert!(fixture.live.join("src/generated.rs").exists());

    let authorized_rollback = reconciled.rollback.clone();
    fs::write(
        fixture.live.join("src/generated.rs"),
        b"pub fn generated() -> u8 { 99 }\n",
    )
    .expect("inject stable stale target");
    let conflict_request = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce.clone(),
        4,
        bundle.result_snapshot.clone(),
        RunnerRequest::ApplierRollback {
            bundle: bundle.clone(),
            rollback: authorized_rollback.clone(),
        },
    );
    applier.send(&conflict_request);
    let conflict_response = applier.response();
    conflict_response
        .validate_correlation(&conflict_request)
        .expect("live-conflict correlation");
    let RunnerResponse::RollbackLiveConflict { conflict } = conflict_response.response else {
        panic!("stable stale target must return typed no-effect conflict")
    };
    assert!(!conflict.rollback_mutation_started);
    assert_eq!(conflict.bundle, bundle);
    assert_eq!(conflict.rollback, authorized_rollback);
    assert_eq!(conflict.conflicts.len(), 1);
    assert_eq!(conflict.conflicts[0].path, "src/generated.rs");
    assert_eq!(
        fs::read(fixture.live.join("src/generated.rs")).expect("read stale target"),
        b"pub fn generated() -> u8 { 99 }\n"
    );
    fs::write(
        fixture.live.join("src/generated.rs"),
        b"pub fn generated() -> u8 { 2 }\n",
    )
    .expect("restore exact application endpoint");
    let rollback = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce.clone(),
        5,
        bundle.result_snapshot.clone(),
        RunnerRequest::ApplierRollback {
            bundle: bundle.clone(),
            rollback: authorized_rollback.clone(),
        },
    );
    applier.send(&rollback);
    let response = applier.response();
    response
        .validate_correlation(&rollback)
        .expect("rollback correlation");
    let RunnerResponse::RollbackCompletedWithEvidence {
        evidence: rollback_evidence,
    } = response.response
    else {
        panic!("explicit rollback must return immediate and post-restore evidence")
    };
    assert_eq!(rollback_evidence.bundle, bundle);
    assert_eq!(rollback_evidence.rollback, authorized_rollback);
    assert_eq!(
        rollback_evidence.target_contract.len(),
        rollback_evidence.pre_effect_observations.len()
    );
    assert_eq!(
        rollback_evidence.target_contract.len(),
        rollback_evidence.post_restore_observations.len()
    );
    assert!(rollback_evidence.effect_started_at_unix_ms > 0);
    assert!(
        rollback_evidence.final_live_manifest_observed_at_unix_ms
            >= rollback_evidence.effect_started_at_unix_ms
    );
    assert!(!fixture.live.join("src/generated.rs").exists());
    assert_eq!(
        fs::read(fixture.live.join("unrelated.txt")).expect("read preserved unrelated edit"),
        b"preserve me\n"
    );

    let applier_shutdown = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restarted_receipt.runner_nonce,
        6,
        result_snapshot,
        RunnerRequest::Shutdown,
    );
    applier.send(&applier_shutdown);
    let _ = applier.response();
    assert!(applier.finish().0.success());

    let mut applier = RunnerChild::spawn();
    let restored_receipt = applier.initialize(&applier_init);
    let recover = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restored_receipt.runner_nonce.clone(),
        1,
        bundle.base_snapshot.clone(),
        RunnerRequest::ApplierRecoverPending,
    );
    applier.send(&recover);
    let _ = applier.response();
    let reconcile = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restored_receipt.runner_nonce.clone(),
        2,
        bundle.base_snapshot.clone(),
        RunnerRequest::ApplierReconcile {
            bundle: bundle.clone(),
        },
    );
    applier.send(&reconcile);
    let response = applier.response();
    response
        .validate_correlation(&reconcile)
        .expect("restored reconciliation correlation");
    assert!(matches!(
        response.response,
        RunnerResponse::TargetsRestored { .. }
    ));
    let replay = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restored_receipt.runner_nonce.clone(),
        3,
        bundle.result_snapshot.clone(),
        RunnerRequest::ApplierRollback {
            bundle: bundle.clone(),
            rollback: authorized_rollback,
        },
    );
    applier.send(&replay);
    let replayed = applier.response();
    replayed
        .validate_correlation(&replay)
        .expect("retained rollback evidence readback correlation");
    assert!(matches!(
        replayed.response,
        RunnerResponse::RollbackCompletedWithEvidence { .. }
    ));
    let shutdown = Fixture::effect_request_for(
        &applier_init,
        &applier_policy_hash,
        restored_receipt.runner_nonce,
        4,
        bundle.base_snapshot,
        RunnerRequest::Shutdown,
    );
    applier.send(&shutdown);
    let _ = applier.response();
    assert!(applier.finish().0.success());
}

#[test]
fn invalid_initialization_yields_one_rejection_frame_then_nonzero_exit() {
    let _guard = runner_spawn_guard();
    let mut fixture = Fixture::new(RunnerRole::Worker);
    let RunnerRequest::InitializeSession {
        expected_binary_digest,
        ..
    } = &mut fixture.init.request
    else {
        unreachable!()
    };
    *expected_binary_digest = Digest::sha256(b"wrong binary");
    let mut child = RunnerChild::spawn();
    child.send(&fixture.init);
    let rejection = child.response();
    rejection
        .validate_correlation(&fixture.init)
        .expect("correlated initialization refusal");
    assert!(matches!(
        rejection.response,
        RunnerResponse::InitializationRejected { .. }
    ));
    let (status, stdout, _) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(
        stdout.is_empty(),
        "initialization must emit exactly one frame"
    );
}

#[test]
fn initialized_session_rejects_initialization_replay_without_a_second_frame() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let RunnerRequest::InitializeSession {
        expected_sprint_spec_digest,
        ..
    } = &fixture.init.request
    else {
        unreachable!()
    };
    assert_eq!(receipt.sprint_spec_digest, *expected_sprint_spec_digest);

    child.send(&fixture.init);
    let (status, trailing_stdout, _) = child.finish();
    assert!(!status.success());
    assert!(
        trailing_stdout.is_empty(),
        "initialization replay must not receive a second response frame"
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized subprocess test covers the three independent launcher expectations"
)]
fn policy_private_state_and_binary_identity_mismatches_are_explicitly_rejected() {
    let _guard = runner_spawn_guard();

    let mut policy_fixture = Fixture::new(RunnerRole::Worker);
    let RunnerRequest::InitializeSession {
        expected_policy_hash,
        ..
    } = &mut policy_fixture.init.request
    else {
        unreachable!()
    };
    *expected_policy_hash = Digest::sha256(b"wrong compiled policy");
    let mut child = RunnerChild::spawn();
    child.send(&policy_fixture.init);
    let response = child.response();
    assert!(matches!(
        response.response,
        RunnerResponse::InitializationRejected { ref message, .. }
            if message.contains("compiled policy hash")
    ));
    assert_eq!(child.finish().0.code(), Some(78));

    let private_fixture = Fixture::new(RunnerRole::Worker);
    let moved = private_fixture.top.join("private-parent/old-state");
    fs::rename(&private_fixture.state, &moved).expect("move expected private state");
    fs::create_dir(&private_fixture.state).expect("replace expected private state");
    fs::set_permissions(&private_fixture.state, fs::Permissions::from_mode(0o700))
        .expect("set replacement private mode");
    let mut child = RunnerChild::spawn();
    child.send(&private_fixture.init);
    let response = child.response();
    assert!(matches!(
        response.response,
        RunnerResponse::InitializationRejected { ref message, .. }
            if message.contains("path-chain digest")
    ));
    assert_eq!(child.finish().0.code(), Some(78));

    let mut binary_fixture = Fixture::new(RunnerRole::Worker);
    let RunnerRequest::InitializeSession {
        expected_binary_identity,
        ..
    } = &mut binary_fixture.init.request
    else {
        unreachable!()
    };
    expected_binary_identity.inode = expected_binary_identity.inode.wrapping_add(1);
    let mut child = RunnerChild::spawn();
    child.send(&binary_fixture.init);
    let response = child.response();
    assert!(matches!(
        response.response,
        RunnerResponse::InitializationRejected { ref message, .. }
            if message.contains("stable identity")
    ));
    assert_eq!(child.finish().0.code(), Some(78));
}

#[test]
fn stale_nonce_from_prior_process_is_rejected() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut first = RunnerChild::spawn();
    let first_receipt = first.initialize(&fixture.init);
    let shutdown = fixture.effect_request(
        first_receipt.runner_nonce.clone(),
        1,
        Digest::sha256(b"first shutdown"),
        RunnerRequest::Shutdown,
    );
    first.send(&shutdown);
    let _ = first.response();
    assert!(first.finish().0.success());

    let mut second = RunnerChild::spawn();
    let second_receipt = second.initialize(&fixture.init);
    assert_ne!(first_receipt.runner_nonce, second_receipt.runner_nonce);
    let stale = fixture.effect_request(
        first_receipt.runner_nonce,
        1,
        Digest::sha256(b"stale shutdown"),
        RunnerRequest::Shutdown,
    );
    second.send(&stale);
    let (status, stdout, stderr) = second.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("stale process nonce"));
}

#[test]
fn applier_requires_exactly_one_startup_recovery_before_other_operations() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Applier);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let input = Digest::sha256(b"applier input");

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        input.clone(),
        RunnerRequest::ApplierCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let response = child.response();
    assert_failed_before_effect(&response, "applier_recovery_required");

    let recover = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        input.clone(),
        RunnerRequest::ApplierRecoverPending,
    );
    child.send(&recover);
    let response = child.response();
    response
        .validate_correlation(&recover)
        .expect("recovery correlation");
    assert!(matches!(
        response.response,
        RunnerResponse::RecoveryCompleted { .. }
    ));

    let shutdown = fixture.effect_request(receipt.runner_nonce, 3, input, RunnerRequest::Shutdown);
    child.send(&shutdown);
    assert!(matches!(
        child.response().response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    assert!(child.finish().0.success());
}

#[test]
fn sequence_and_cross_sprint_worker_context_are_fatal_before_dispatch() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let gap = fixture.effect_request(
        receipt.runner_nonce,
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&gap);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("sequence"));

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let _ = child.response();
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: fixture.base_snapshot.clone(),
        },
    );
    child.send(&create_shadow);
    let _ = child.response();
    let mut crossed = fixture.effect_request(
        receipt.runner_nonce,
        3,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    let effect = crossed.effect.as_mut().expect("effect context");
    effect.sprint_id = "sprint-2".into();
    effect.worker_id = Some("worker-2".into());
    effect.worker_lease = Some(
        WorkerLease::new(
            "sprint-2".into(),
            1,
            "task-1".into(),
            "worker-2".into(),
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        )
        .expect("construct internally valid crossed lease"),
    );
    crossed
        .bind_transport_commitment_digest()
        .expect("rebind crossed context");
    child.send(&crossed);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("effect context"));
}

#[test]
fn worker_lease_epoch_substitution_and_cross_identity_are_fatal_before_dispatch() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let cases = [
        (
            "stale-epoch",
            "sprint-1",
            "task-1",
            "worker-1",
            1,
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        ),
        (
            "same-identity-substitution",
            "sprint-1",
            "task-1",
            "worker-1",
            2,
            vec![PathScope::Workspace],
            1,
        ),
        (
            "cross-task",
            "sprint-1",
            "task-2",
            "worker-1",
            2,
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        ),
        (
            "cross-worker",
            "sprint-1",
            "task-1",
            "worker-2",
            2,
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        ),
        (
            "cross-sprint",
            "sprint-2",
            "task-1",
            "worker-1",
            2,
            vec![PathScope::Relative(PathBuf::from("src"))],
            1,
        ),
    ];

    for (label, sprint_id, task_id, worker_id, epoch, scopes, acquired_at) in cases {
        let mut child = RunnerChild::spawn();
        let receipt = child.initialize(&fixture.init);
        let mut request = fixture.effect_request(
            receipt.runner_nonce,
            1,
            fixture.base_snapshot.clone(),
            RunnerRequest::WorkerReadFile {
                path: "src/lib.rs".into(),
                max_bytes: 1024,
            },
        );
        let effect = request.effect.as_mut().expect("worker effect context");
        effect.sprint_id = sprint_id.into();
        effect.task_id = Some(task_id.into());
        effect.worker_id = Some(worker_id.into());
        effect.worker_lease = Some(
            WorkerLease::new(
                sprint_id.into(),
                epoch,
                task_id.into(),
                worker_id.into(),
                scopes,
                acquired_at,
            )
            .expect("construct internally canonical substituted lease"),
        );
        request
            .bind_transport_commitment_digest()
            .expect("bind exact substituted lease transport");
        child.send(&request);
        let (status, stdout, stderr) = child.finish();
        assert_eq!(status.code(), Some(78), "{label}");
        assert!(stdout.is_empty(), "{label}");
        assert!(
            String::from_utf8_lossy(&stderr).contains("effect context"),
            "{label}: {}",
            String::from_utf8_lossy(&stderr)
        );
    }
}

#[test]
fn crossed_command_core_digest_is_rejected_by_wire_before_containment_dispatch() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let response = child.response();
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected capture")
    };
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id.clone(),
        },
    );
    child.send(&create_shadow);
    let _ = child.response();

    let command_spec = WireCommandSpec {
        program: "/usr/bin/true".into(),
        arguments: Vec::new(),
        working_directory: String::new(),
    };
    let output_capture = fixture.command_output_capture(3, &command_spec);
    let mut command = fixture.effect_request(
        receipt.runner_nonce.clone(),
        3,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerRunCommand {
            command: command_spec,
            output_capture,
        },
    );
    command
        .effect
        .as_mut()
        .expect("command effect")
        .request_digest = Digest::sha256(b"crossed durable core command");
    command
        .bind_transport_commitment_digest()
        .expect("rebind transport after crossed core digest");
    assert!(matches!(
        encode_request_frame(&command),
        Err(grok_build_runner::WireProtocolError::InvalidContract(message))
            if message.contains("exact canonical core command")
    ));

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        3,
        capture.snapshot_id,
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    assert!(matches!(
        child.response().response,
        RunnerResponse::ShutdownPrepared { .. }
    ));
    let (status, stdout, stderr) = child.finish();
    assert!(status.success());
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one serialized subprocess test falsifies four independent pre-dispatch guards"
)]
fn duplicate_role_policy_and_snapshot_confusion_are_fatal_before_dispatch() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let _ = child.response();
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: fixture.base_snapshot.clone(),
        },
    );
    child.send(&create_shadow);
    let _ = child.response();
    let first = fixture.effect_request(
        receipt.runner_nonce.clone(),
        3,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    child.send(&first);
    let _ = child.response();
    let mut duplicate = fixture.effect_request(
        receipt.runner_nonce,
        4,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    duplicate
        .effect
        .as_mut()
        .expect("duplicate effect")
        .effect_id = first
        .effect
        .as_ref()
        .expect("first effect")
        .effect_id
        .clone();
    duplicate
        .bind_transport_commitment_digest()
        .expect("rebind duplicate effect");
    child.send(&duplicate);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("effect identity was reused"));
    fs::remove_dir_all(fixture.state.join("shadow-1"))
        .expect("remove terminated duplicate-test shadow");

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let wrong_role = fixture.effect_request(
        receipt.runner_nonce,
        1,
        Digest::sha256(b"wrong role"),
        RunnerRequest::ApplierRecoverPending,
    );
    child.send(&wrong_role);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("session role"));

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let response = child.response();
    let RunnerResponse::WorkspaceCaptured { capture } = response.response else {
        panic!("expected capture")
    };
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id,
        },
    );
    child.send(&create_shadow);
    let _ = child.response();
    let wrong_snapshot = fixture.effect_request(
        receipt.runner_nonce,
        3,
        Digest::sha256(b"wrong snapshot"),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    child.send(&wrong_snapshot);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("effect context"));
    fs::remove_dir_all(fixture.state.join("shadow-1"))
        .expect("remove terminated snapshot-test shadow");

    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let _ = child.response();
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: fixture.base_snapshot.clone(),
        },
    );
    child.send(&create_shadow);
    let _ = child.response();
    let mut wrong_policy = fixture.effect_request(
        receipt.runner_nonce,
        3,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    wrong_policy
        .effect
        .as_mut()
        .expect("policy effect")
        .policy_hash = Digest::sha256(b"different policy");
    wrong_policy
        .bind_transport_commitment_digest()
        .expect("rebind wrong policy");
    child.send(&wrong_policy);
    let (status, stdout, stderr) = child.finish();
    assert_eq!(status.code(), Some(78));
    assert!(stdout.is_empty());
    assert!(String::from_utf8_lossy(&stderr).contains("effect context"));
}

#[test]
fn workspace_same_path_replacement_is_detected_after_initialization() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let moved = fixture.top.join("old-live");
    fs::rename(&fixture.live, &moved).expect("move trusted live root");
    fs::create_dir(&fixture.live).expect("install replacement live root");

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let response = child.response();
    assert_failed_before_effect(&response, "workspace_operation_rejected");

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        2,
        Digest::sha256(b"shutdown replaced root"),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    let _ = child.response();
    assert!(child.finish().0.success());
}

#[test]
fn complete_shadow_recapture_rejects_unexpected_edit_before_tool_dispatch() {
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut child = RunnerChild::spawn();
    let receipt = child.initialize(&fixture.init);
    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let _ = child.response();
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: fixture.base_snapshot.clone(),
        },
    );
    child.send(&create_shadow);
    let _ = child.response();

    fs::write(fixture.state.join("shadow-1/src/unexpected.rs"), b"race\n")
        .expect("inject unexpected same-user shadow edit");
    let read = fixture.effect_request(
        receipt.runner_nonce.clone(),
        3,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerReadFile {
            path: "src/lib.rs".into(),
            max_bytes: 1024,
        },
    );
    child.send(&read);
    assert_failed_before_effect(&child.response(), "shadow_input_snapshot_mismatch");

    let shutdown = fixture.effect_request(
        receipt.runner_nonce,
        4,
        Digest::sha256(b"shutdown after shadow race"),
        RunnerRequest::Shutdown,
    );
    child.send(&shutdown);
    let _ = child.response();
    assert!(child.finish().0.success());
}

#[test]
fn binary_and_private_state_observations_change_after_substitution() {
    let fixture = Fixture::new(RunnerRole::Worker);
    let initial = inspect_private_state_digest(&fixture.state).expect("initial private digest");
    let moved = fixture.top.join("old-state");
    fs::rename(&fixture.state, &moved).expect("move private state");
    fs::create_dir(&fixture.state).expect("replace private state");
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700))
        .expect("set replacement mode");
    let replacement =
        inspect_private_state_digest(&fixture.state).expect("replacement private digest");
    assert_ne!(initial, replacement);

    let binary = staged_runner_binary();
    let (_, identity) = inspect_runner_binary(binary).expect("inspect runner binary");
    assert_eq!(
        identity.link_count, 1,
        "the image the tests inspect and execute must itself be singly linked"
    );
    let forged = WireBinaryIdentity {
        inode: identity.inode.wrapping_add(1),
        ..identity
    };
    assert_ne!(identity, forged);

    let unsafe_mode = fixture.top.join("unsafe-mode-runner");
    fs::copy(binary, &unsafe_mode).expect("copy runner fixture");
    fs::set_permissions(&unsafe_mode, fs::Permissions::from_mode(0o775))
        .expect("make runner group writable");
    assert!(inspect_runner_binary(&unsafe_mode).is_err());

    // The link-count clause is load-bearing, not incidental: an image with a
    // second name can be executed under a name the launcher never inspected.
    // Admit a copy, add one hardlink, watch the identical bytes be refused,
    // remove the alias, and watch admission come back, so the refusal is
    // attributable to the link count and to nothing else about the file.
    let linked = fixture.top.join("linked-runner");
    fs::copy(binary, &linked).expect("copy singly linked runner");
    fs::set_permissions(&linked, fs::Permissions::from_mode(0o700)).expect("set safe runner mode");
    let (admitted_digest, admitted_identity) =
        inspect_runner_binary(&linked).expect("admit safe copied runner");
    assert_eq!(admitted_identity.link_count, 1);

    let alias = fixture.top.join("runner-alias");
    fs::hard_link(&linked, &alias).expect("create runner hardlink");
    assert_eq!(
        fs::symlink_metadata(&linked)
            .expect("inspect hardlinked runner")
            .nlink(),
        2
    );
    let refusal = inspect_runner_binary(&linked).expect_err("refuse a doubly linked runner image");
    assert_eq!(refusal.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(refusal.to_string().contains("singly linked"));
    assert!(
        inspect_runner_binary(&alias).is_err(),
        "the gate must refuse the image under either of its names"
    );

    fs::remove_file(&alias).expect("drop the runner hardlink");
    let (restored_digest, restored_identity) =
        inspect_runner_binary(&linked).expect("readmit the singly linked runner image");
    assert_eq!(restored_digest, admitted_digest);
    assert_eq!(restored_identity, admitted_identity);
}

/// One contained command, driven through the real runner binary onto a live
/// **installed** native service.
///
/// The service this runs against is not built by this test. It is installed by
/// the runner's own installer mode, running as an identity that is not the
/// runner, before the test process starts; `GBD_TEST_INSTALL_ROOT` only names
/// where that already-installed anchor lives. Reading it here is a test-side
/// convenience and never enters production launch: the runner receives the
/// install root as an ordinary startup argument, which is what this test
/// passes.
///
/// Absent the variable the test returns rather than fabricating a service.
/// A host with no installed service has nothing to prove here, and inventing
/// one would prove something about the invention.
#[cfg(target_os = "linux")]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one linear drive: initialize, capture, shadow, then the single v15 command that carries this runner's identity and the desktop's release"
)]
fn a_contained_command_runs_on_an_installed_native_service() {
    let Some(install_root) = std::env::var_os("GBD_TEST_INSTALL_ROOT") else {
        return;
    };
    let _guard = runner_spawn_guard();
    let fixture = Fixture::new(RunnerRole::Worker);
    let mut command = Command::new(staged_runner_binary());
    command
        .arg("--linux-native-service-install-root")
        .arg(&install_root);
    let mut child = RunnerChild::spawn_command(command);
    let receipt = child.initialize(&fixture.init);

    let capture = fixture.effect_request(
        receipt.runner_nonce.clone(),
        1,
        fixture.base_snapshot.clone(),
        RunnerRequest::WorkerCaptureLive {
            created_at_unix_ms: 1,
        },
    );
    child.send(&capture);
    let capture_response = child.response();
    let RunnerResponse::WorkspaceCaptured { capture } = capture_response.response else {
        panic!("expected the installed-service capture")
    };
    let create_shadow = fixture.effect_request(
        receipt.runner_nonce.clone(),
        2,
        capture.snapshot_id.clone(),
        RunnerRequest::WorkerCreateShadow {
            base_snapshot: capture.snapshot_id.clone(),
        },
    );
    child.send(&create_shadow);
    assert!(matches!(
        child.response().response,
        RunnerResponse::ShadowCreated { .. }
    ));

    // A real static ELF, built here from the checked-in baseline source. A
    // dynamically linked target is refused by the plan -- correctly, because
    // its linkage would additionally require an authenticated interpreter and
    // the complete runtime-object closure, and this plan has no production
    // source for either. `/usr/bin/true` is dynamic on this host, so using it
    // would prove only that the refusal fires.
    let target = build_static_command_target(&fixture.top);
    let command_spec = WireCommandSpec {
        program: target.to_str().expect("UTF-8 target path").to_owned(),
        arguments: Vec::new(),
        working_directory: String::new(),
    };
    let output_capture = fixture.reserved_command_output_capture(3, &command_spec);
    let v12 = fixture.command_effect_request_v12(
        receipt.runner_nonce,
        3,
        capture.snapshot_id,
        RunnerRequest::WorkerRunCommand {
            command: command_spec,
            output_capture,
        },
    );

    // The runner's own launch preparation. The binding is carried as bytes and
    // the digest is a fresh SHA-256 of exactly those bytes, which is what
    // `try_from_wire_preparation` re-checks the attempt against.
    let binding_canonical_bytes = b"grok-build-installed-service-drive-binding-v1".to_vec();
    let binding_digest = Digest::sha256(&binding_canonical_bytes);
    let preparation = WireRunnerLaunchPreparationV1 {
        attempt: grok_build_core::RunnerLaunchPreparationAttempt {
            contract_version: v12.effect.contract_version,
            attempt_id: "installed-service-drive-attempt".into(),
            sprint_id: v12.effect.sprint_id.clone(),
            launch_id: v12.effect.launch_id.clone(),
            cleanup_effect_id: "installed-service-drive-cleanup".into(),
            native_journal_id: "installed-service-drive-journal".into(),
            expected_platform_binding_digest: binding_digest.clone(),
            claimed_at_unix_ms: 1,
        },
        binding_canonical_bytes,
        binding_digest,
    };
    let release = WireContainedCommandReleaseAuthorityV1 {
        command_effect_id: v12.effect.effect_id.clone(),
        request_digest: v12.effect.request_digest.clone(),
        native_evidence_digest: Digest::sha256(b"installed-service-drive-native-evidence"),
    };
    let mut v15 = RunnerRequestEnvelopeV15 {
        protocol_version: 15,
        session_id: v12.session_id.clone(),
        runner_nonce: v12.runner_nonce.clone(),
        sequence: v12.sequence,
        request_id: v12.request_id.clone(),
        effect: v12.effect.clone(),
        request: v12.request.clone(),
        contained_command_release: Some(release),
        runner_launch_preparation: Some(preparation),
    };
    v15.bind_transport_commitment_digest()
        .expect("bind the v15 transport commitment");
    child
        .stdin
        .as_mut()
        .expect("runner stdin")
        .write_all(&encode_request_frame_v15(&v15).expect("encode the v15 command"))
        .expect("send the v15 command");
    child.stdin.as_mut().expect("runner stdin").flush().unwrap();

    // Read the frame directly rather than through `response_v12`, so a runner
    // that exits without answering reports *why* instead of an EOF panic that
    // discards its diagnostics.
    let mut prefix = [0_u8; 4];
    let framed = child.stdout.read_exact(&mut prefix).is_ok();
    let decoded = framed.then(|| {
        let length = usize::try_from(u32::from_be_bytes(prefix)).expect("response length fits");
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&prefix);
        frame.resize(4 + length, 0);
        child
            .stdout
            .read_exact(&mut frame[4..])
            .expect("read the installed-service response body");
        decode_response_frame_v12(&frame).expect("decode the installed-service response")
    });
    let (status, _trailing, stderr) = child.finish();
    match decoded {
        Some(envelope) => println!("GBDINSTALLEDDRIVE response={:?}", envelope.response),
        None => println!("GBDINSTALLEDDRIVE response=none status={status:?}"),
    }
    println!(
        "GBDINSTALLEDDRIVE stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

/// Builds the real static ELF this drive runs, from the checked-in baseline
/// source rather than from whatever the host happens to ship.
#[cfg(target_os = "linux")]
fn build_static_command_target(root: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("walking-skeleton-baseline")
        .join("baseline_exit.rs")
        .canonicalize()
        .expect("canonicalize the walking-skeleton baseline command source");
    let artefact = root.join("installed-service-drive-target");
    let output = Command::new("rustc")
        .arg("--edition")
        .arg("2021")
        .arg("--crate-name")
        .arg("installed_service_drive_target")
        .arg("-O")
        .arg("-C")
        .arg("target-feature=+crt-static")
        .args(["-C", "relocation-model=static"])
        .arg("-o")
        .arg(&artefact)
        .arg(source)
        .output()
        .expect("run rustc to build the static drive target");
    assert!(
        output.status.success(),
        "building the static drive target must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The plan refuses a group- or world-writable target. `rustc` inherits the
    // caller's umask, so the mode is set explicitly rather than assumed.
    fs::set_permissions(&artefact, fs::Permissions::from_mode(0o755))
        .expect("make the drive target owner-writable only");
    artefact
}
