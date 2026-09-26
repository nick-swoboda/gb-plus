//! End-to-end coverage through the production coordinator, ledger, workspace
//! grants, runner client and runner executable, driven by [`FakeProvider`].
//!
//! macOS refuses before launch because this route has no descriptor-exec bridge.
//! Linux launches the sealed runner, initializes it, creates the worker's private
//! shadow and records `Leased -> Running`. Three file/search effects succeed.
//! The command effect reaches the containment backend's service-unavailable
//! refusal and remains `Unknown` without an admitted command-journal reopener.
//! The coordinator reports `TaskUnknownCleanupRequired` across restart.
//!
//! The command fixture is a static ELF at an absolute path, so executable
//! admission succeeds before the backend refuses. The worker owns shadow
//! creation; the desktop only names its destination.

use std::fs;
use std::path::{Path, PathBuf};

use grok_build_core::{
    AcceptanceCriterion, AcceptanceKind, AgentEventKind, CommandSpec, CompiledExecutionPolicy,
    EffectKind, EventLedger, ExecutionNetwork, ExecutionPolicyCompiler, ExecutionPolicyRequest,
    IssuedWorkspaceGrant, MutationMode, PathScope, PersistedSprint, ResourceLimits, SprintBudget,
    SprintSpec, TaskAttemptRecoveryFacts, TaskState, WorkspaceGrantIssuer, WorkspaceGrantRequest,
    WorkspaceNetworkPolicy, WorkspacePermissions, WorkspaceSnapshot,
};
#[cfg(not(target_os = "linux"))]
use grok_build_desktop::DurableCoordinatorError;
use grok_build_desktop::{
    DesktopRunnerLifecycleOwner, DurableWalkingSkeleton, RunnerLifecycleOwnerConfig,
};
use grok_build_providers::{FakeProvider, ModelProvider};
use grok_build_runner::{ShadowWorkspace, WorkspaceManifest};

/// Exact files shipped by `fixtures/walking-skeleton`. `docs/report.txt` is
/// deliberately absent: creating it is part of the requested change.
const FIXTURE_FILES: [&str; 5] = [
    "AGENTS.md",
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
    "src/lib.rs",
];

/// The fixture's own objective, stated in its `AGENTS.md`.
const FIXTURE_OBJECTIVE: &str = "Make status() return \"ready\" and create docs/report.txt containing \
     'walking skeleton complete'";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let temporary = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
        let root = temporary.join(format!(
            "grok-build-walking-skeleton-production-spine-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale spine root");
        }
        fs::create_dir_all(&root).expect("create spine root");
        Self(root)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("walking-skeleton")
        .canonicalize()
        .expect("canonicalize the walking-skeleton fixture")
}

/// Resolves the real `grok-build-runner` executable this workspace built.
///
/// `CARGO_BIN_EXE_*` is only defined for the *current* package's binaries, so a
/// `grok-build-desktop` integration test cannot ask Cargo for another package's
/// executable. It is resolved instead from the profile directory that holds
/// this test binary (`target/<profile>/deps/<test>` -> `target/<profile>`), or
/// from an explicit override. A missing binary is a loud failure, never a skip:
/// the spine is not allowed to pass by not being exercised.
fn workspace_runner_binary() -> PathBuf {
    if let Some(configured) = std::env::var_os("GROK_BUILD_RUNNER_BINARY") {
        let path = PathBuf::from(configured);
        assert!(
            path.is_file(),
            "GROK_BUILD_RUNNER_BINARY does not name a file: {}",
            path.display()
        );
        return path;
    }
    let test_binary = std::env::current_exe().expect("resolve this test executable");
    let profile = test_binary
        .parent()
        .and_then(Path::parent)
        .expect("test executable must live under target/<profile>/deps");
    let candidate = profile.join("grok-build-runner");
    assert!(
        candidate.is_file(),
        "the production spine needs the real runner executable at {}; build it first with \
         `cargo build -p grok-build-runner --all-features --locked`, or point \
         GROK_BUILD_RUNNER_BINARY at it",
        candidate.display()
    );
    candidate
}

/// Installs a private, singly linked copy of the runner for this run.
///
/// Cargo hardlinks its binaries from `deps/` on Linux, and the launch boundary
/// admits only a singly linked file, so the spine copies rather than naming the
/// build output directly. The copy is also the canonical path the launch
/// boundary requires.
fn install_runner_binary(root: &TestRoot) -> PathBuf {
    let directory = root.path("runner-binary");
    fs::create_dir(&directory).expect("create the private runner-binary directory");
    let installed = directory.join("grok-build-runner");
    fs::copy(workspace_runner_binary(), &installed).expect("install the private runner copy");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700))
            .expect("secure the private runner copy");
    }
    fs::canonicalize(&installed).expect("canonicalize the installed runner copy")
}

/// The single source file the sprint's acceptance command is compiled from.
///
/// Resolved the same way as the fixture project, so a moved checkout is a loud
/// failure rather than a silent fallback.
fn baseline_command_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("walking-skeleton-baseline")
        .join("baseline_exit.rs")
        .canonicalize()
        .expect("canonicalize the walking-skeleton baseline command source")
}

/// Compiles the fixture's baseline acceptance command into this run's own root
/// and returns its absolute path.
///
/// The command the walking skeleton runs is built here rather than named as a
/// path that happens to exist, for two reasons the contained boundary makes
/// concrete:
///
/// - `prepare_v12` refuses a bare program name outright, "a bare executable
///   name requires an explicit controlled PATH", and then *authenticates* the
///   absolute one it is given, stating, opening and hashing the file. So the
///   program must be absolute and must really exist where the runner runs.
/// - On Linux it is linked with `-C target-feature=+crt-static`, and the ELF is
///   then read back here to prove it carries no `PT_INTERP` and no
///   `PT_DYNAMIC`. That is the property that keeps a target's linkage on
///   `LinuxTargetLinkageV1::StaticElf`, whose `validate_mounts` arm requires
///   zero interpreter and runtime-object mounts, i.e. it is what keeps the
///   deferred loader-closure item deferred rather than forcing it.
///
/// macOS cannot statically link libSystem and never reaches this command at
/// all: that spine stops before any worker process exists. It is still built
/// there, so both hosts commit an absolute path to a real executable and the
/// two spines differ only where they are measured to differ.
fn build_baseline_command(root: &TestRoot) -> PathBuf {
    let directory = root.path("baseline-command");
    fs::create_dir(&directory).expect("create the baseline-command directory");
    let binary = directory.join("walking-skeleton-baseline");
    let source = baseline_command_source();

    let mut rustc = std::process::Command::new("rustc");
    rustc
        .arg("--edition")
        .arg("2021")
        .arg("-O")
        .arg("--crate-name")
        .arg("walking_skeleton_baseline");
    #[cfg(target_os = "linux")]
    rustc.args([
        "-C",
        "target-feature=+crt-static",
        "-C",
        "relocation-model=static",
    ]);
    let output = rustc
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("run rustc to build the walking-skeleton baseline command");
    assert!(
        output.status.success(),
        "building the baseline acceptance command must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        binary.is_file(),
        "rustc reported success but produced no baseline command at {}",
        binary.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert!(
            fs::metadata(&binary)
                .expect("stat the baseline command")
                .permissions()
                .mode()
                & 0o111
                != 0,
            "the baseline command must be executable, or executable identity capture refuses it"
        );
    }
    #[cfg(target_os = "linux")]
    assert_static_elf(&binary);
    fs::canonicalize(&binary).expect("canonicalize the baseline acceptance command")
}

/// Require a static ELF using the same linkage prover as production command plans.
#[cfg(target_os = "linux")]
fn assert_static_elf(binary: &Path) {
    let measured = grok_build_runner::measure_static_elf_linkage_v1(binary).unwrap_or_else(|error| {
        panic!(
            "the baseline command at {} must measure as a static ELF, or its plan linkage would \
             not be StaticElf and `validate_mounts` would demand an interpreter mount: {error}",
            binary.display()
        )
    });
    assert!(
        measured.program_headers > 0 && measured.loadable_segments > 0,
        "a static linkage must come from a table that was really walked: {measured:?}"
    );
    assert_eq!(
        measured.byte_length,
        fs::metadata(binary)
            .expect("stat the baseline command")
            .len(),
        "the measured length must be the length of the file the test just built"
    );
}

/// The sprint's automated acceptance criterion, and therefore, since the
/// deterministic provider derives its two command turns from that criterion,
/// exactly what the walking skeleton's fourth tool commands.
fn locked_acceptance_command(program: &Path) -> CommandSpec {
    assert!(
        program.is_absolute(),
        "the acceptance command must name an absolute executable: {}",
        program.display()
    );
    CommandSpec {
        program: program
            .to_str()
            .expect("the baseline command path is UTF-8")
            .to_owned(),
        arguments: Vec::new(),
        working_directory: PathBuf::new(),
    }
}

fn compile_policy(authority: &IssuedWorkspaceGrant) -> CompiledExecutionPolicy {
    ExecutionPolicyCompiler::compile(
        authority,
        ExecutionPolicyRequest {
            policy_id: "walking-skeleton-production-spine-policy".into(),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: vec![
                PathScope::Relative(PathBuf::from("docs")),
                PathScope::Relative(PathBuf::from("src")),
            ],
            environment: Vec::new(),
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ShadowWorkspace,
            resource_limits: ResourceLimits {
                wall_time_ms: 60_000,
                max_output_bytes: 1024 * 1024,
                max_processes: 1,
                max_memory_bytes: None,
            },
            approval_id: None,
        },
    )
    .expect("compile the production execution policy")
}

fn sprint_spec(
    authority: &IssuedWorkspaceGrant,
    base: &WorkspaceSnapshot,
    baseline_command: &Path,
) -> SprintSpec {
    SprintSpec {
        sprint_id: "walking-skeleton-production-spine".into(),
        objective: FIXTURE_OBJECTIVE.into(),
        acceptance_criteria: vec![AcceptanceCriterion {
            criterion_id: "fixture-ready".into(),
            description: "The deterministic fixture test passes".into(),
            kind: AcceptanceKind::Automated(locked_acceptance_command(baseline_command)),
        }],
        provider: FakeProvider::new().profile(),
        budget: SprintBudget {
            max_tasks: 1,
            max_attempts_per_task: 1,
            max_tool_calls: 8,
            max_duration_ms: 60_000,
        },
        max_workers: 1,
        workspace_grant: authority.contract().clone(),
        base_snapshot: base.snapshot_id.clone(),
    }
}

/// Creates the owner-private runner state root the launch boundary hashes into
/// its private-state identity. Installation owns this directory in production;
/// the launch boundary only inspects it and refuses when its path chain is not
/// a real, canonical directory chain.
fn create_private_state_root(root: &TestRoot) -> PathBuf {
    let private_state_root = root.path("runner-private-state");
    fs::create_dir(&private_state_root).expect("create the private runner-state root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&private_state_root, fs::Permissions::from_mode(0o700))
            .expect("secure the private runner-state root");
    }
    private_state_root
}

fn lifecycle_owner(root: &TestRoot, runner_binary: &Path) -> DesktopRunnerLifecycleOwner {
    DesktopRunnerLifecycleOwner::new(RunnerLifecycleOwnerConfig {
        runner_binary: runner_binary.to_path_buf(),
        private_state_root: root.path("runner-private-state"),
    })
    .expect("create the production desktop runner lifecycle owner")
}

/// The exact refusal the fail-closed ordinary launch boundary produces on a
/// target with no descriptor-exec bridge.
///
/// `ensure_native_ordinary_platform_launch_binding_available` now admits the
/// launch wherever that bridge exists, so this string is only reachable where
/// it does not. It carries the platform measurement verbatim, so a macOS
/// release that gained `fexecve` would break this assertion by itself rather
/// than passing silently.
#[cfg(not(target_os = "linux"))]
fn expected_launch_refusal() -> String {
    "runner launch failed: runner platform launch binding is unavailable on macos-aarch64 for \
     MacOsDedicatedIdentity: macOS 15 exposes neither fexecve nor execveat, and /dev/fd execution \
     is not admitted"
        .to_owned()
}

/// Asserts the fail-closed shape the ledger must have after a refused launch:
/// planning committed, the attempt still `Leased`, and no launch authority.
#[cfg(not(target_os = "linux"))]
fn assert_fail_closed_custody(sprint: &PersistedSprint, ledger: &EventLedger) {
    assert_eq!(sprint.effects.len(), 1, "only planning may have committed");
    let task_id = assert_durable_planning(sprint);

    // Task custody: Leased, one active attempt, and no Running boundary.
    let history = ledger
        .load_task_attempt_history(&sprint.spec.sprint_id, &task_id)
        .expect("load durable task-attempt history");
    assert_eq!(
        history.task_state,
        TaskState::Leased,
        "the refused launch must leave the attempt Leased, never Running"
    );
    let active = history
        .active_attempt()
        .expect("the lease acquisition is durable");
    assert!(
        active.running_boundary.is_none(),
        "no Leased -> Running boundary may exist without a live worker"
    );
    assert!(
        active.disposition.is_none(),
        "the attempt must stay open rather than acquire an invented disposition"
    );

    // No orphaned launch authority: the ledger proves nothing was launched.
    let projection = ledger
        .load_task_attempt_recovery_projection(
            &sprint.spec.sprint_id,
            &task_id,
            &active.attempt.attempt_id,
        )
        .expect("load durable recovery projection");
    assert_eq!(
        projection.facts,
        TaskAttemptRecoveryFacts::NeverLaunched,
        "a refused launch must leave no launch, session, or native authority"
    );

    assert_task_transitions(sprint, &[("Planned", "Ready"), ("Ready", "Leased")]);
}

/// Asserts the custody shape after a real worker process launched, initialized,
/// created its own private shadow, carried the attempt into `Running`, and then
/// completed four Running-phase provider turns, three of which dispatched a
/// real runner file or search effect to a successful terminal, before the
/// fourth turn's ordinary command ended `Unknown`. Returns the exact active
/// attempt identity for projection assertions.
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "one custody shape keeps its effect table, attempt authority, clock fence, and key derivation adjacent for auditability"
)]
fn assert_running_worker_custody(sprint: &PersistedSprint, ledger: &EventLedger) -> String {
    let task_id = assert_durable_planning(sprint);

    // Exactly ten durable effects, in commit order: planning; the atomically
    // admitted worker-domain cleanup effect the launch/cleanup admission
    // committed; then four alternating pairs of a Running-phase provider turn
    // and the tool effect that turn authorized. The cleanup effect is
    // unobserved and unclaimed, which is what "cleanup is still owed" looks
    // like in the ledger.
    assert_eq!(
        sprint.effects.len(),
        10,
        "planning, the admitted cleanup effect, and four provider-turn/tool pairs \
         are the only durable effects"
    );
    let cleanup = &sprint.effects[1];
    assert_eq!(cleanup.intent.kind, EffectKind::CleanupWorkerDomain);
    assert!(
        cleanup.observation.is_none() && cleanup.dispatch_claim.is_none(),
        "the admitted cleanup effect must stay open until a backend proves zero survivors"
    );

    let history = ledger
        .load_task_attempt_history(&sprint.spec.sprint_id, &task_id)
        .expect("load durable task-attempt history");
    assert_eq!(
        history.task_state,
        TaskState::Running,
        "an initialized, shadow-owning worker must carry the attempt into Running"
    );
    let active = history
        .active_attempt()
        .expect("the lease acquisition is durable");
    let running = active
        .running_boundary
        .as_ref()
        .expect("a Running attempt must retain its exact Leased -> Running boundary");
    assert_eq!(running.attempt, active.attempt);
    assert_eq!(
        running.runner_launch_id,
        format!("{}:worker-launch-v1", active.attempt.attempt_id)
    );
    assert_eq!(
        running.runner_session_id,
        format!("{}:worker-session-v1", active.attempt.attempt_id)
    );
    assert!(
        active.disposition.is_none(),
        "the attempt must stay open rather than acquire an invented disposition"
    );

    // Every phase-fenced effect must follow the running boundary recorded after
    // the real spawn and initialization handshake.
    let session = ledger
        .load_runner_session(&sprint.spec.sprint_id, &running.runner_session_id)
        .expect("load the durable session registration");
    assert_eq!(
        session.registered_at_unix_ms, running.started_at_unix_ms,
        "the Running boundary must repeat the session's own registration instant"
    );
    assert!(
        running.started_at_unix_ms > 1_700_000_000_000,
        "the boundary must be a real wall-clock instant, not the fixture cursor: {}",
        running.started_at_unix_ms
    );
    for effect in sprint
        .effects
        .iter()
        .filter(|effect| effect.intent.worker_lease.is_some())
        .filter(|effect| effect.intent.kind != EffectKind::CleanupWorkerDomain)
    {
        assert!(
            effect.intent.created_at_unix_ms > running.started_at_unix_ms,
            "effect {} was stamped at {} before its own Running boundary {}",
            effect.intent.effect_id,
            effect.intent.created_at_unix_ms,
            running.started_at_unix_ms
        );
    }

    // Every Running-phase provider turn really completed: each is durably
    // observed Succeeded and carries no runner dispatch claim, because a
    // provider effect is desktop-owned.
    for index in [2_usize, 4, 6, 8] {
        let provider_turn = &sprint.effects[index];
        assert_eq!(provider_turn.intent.kind, EffectKind::ProviderRequest);
        assert_eq!(
            provider_turn.intent.worker_lease.as_ref(),
            Some(&active.attempt.worker_lease),
            "a Running-phase turn must repeat the attempt's exact worker lease"
        );
        assert!(
            matches!(
                provider_turn
                    .observation
                    .as_ref()
                    .map(|value| &value.outcome),
                Some(grok_build_core::EffectOutcome::Succeeded { .. })
            ),
            "Running-phase provider turn {index} must carry its exact successful terminal"
        );
        assert!(
            provider_turn.dispatch_claim.is_none(),
            "a desktop-owned provider effect must never hold a runner dispatch claim"
        );
    }

    // The runner client must accept the coordinator's lease-scoped tool keys
    // and dispatch the authorized file/search effects over the runner wire.
    let lease_digest =
        grok_build_core::Digest::sha256(active.attempt.worker_lease.lease_id.as_bytes());
    let tool_table = [
        (
            3_usize,
            2_usize,
            EffectKind::ReadRelativeFile,
            "fake-v1-01-read-agents",
        ),
        (5, 4, EffectKind::ReadRelativeFile, "fake-v1-02-read-source"),
        (7, 6, EffectKind::SearchLiteral, "fake-v1-03-search-todo"),
        (9, 8, EffectKind::RunCommand, "fake-v1-04-baseline-test"),
    ];
    for (tool_index, turn_index, kind, provider_key) in tool_table {
        let tool = &sprint.effects[tool_index];
        assert_eq!(tool.intent.kind, kind);
        let provider_terminal = sprint.effects[turn_index]
            .terminal_event
            .as_ref()
            .expect("the observed provider turn must retain its terminal event");
        assert_eq!(
            tool.intent.causation_event_id.as_deref(),
            Some(provider_terminal.event_id.as_str()),
            "the tool intent must be caused by the exact provider terminal that authorized it"
        );
        assert_eq!(
            tool.intent.worker_lease.as_ref(),
            Some(&active.attempt.worker_lease)
        );
        assert_eq!(
            tool.intent.idempotency_key,
            format!("task-attempt-{lease_digest}-{provider_key}"),
            "the durable key is the lease-scoped one the coordinator mints"
        );
        assert!(
            tool.dispatch_claim.is_some(),
            "an admitted tool effect must hold the exact durable dispatch claim it was sent under"
        );
    }

    // The three file and search effects reached the real runner and came back
    // with exact successful terminals. The ordinary command did not: its
    // transport ended `Unknown`, which is the spine's current stop.
    for index in [3_usize, 5, 7] {
        assert!(
            matches!(
                sprint.effects[index]
                    .observation
                    .as_ref()
                    .map(|value| &value.outcome),
                Some(grok_build_core::EffectOutcome::Succeeded { .. })
            ),
            "worker tool effect {index} must carry its exact successful terminal"
        );
    }
    assert!(
        matches!(
            sprint.effects[9]
                .observation
                .as_ref()
                .map(|value| &value.outcome),
            Some(grok_build_core::EffectOutcome::Unknown { .. })
        ),
        "the ordinary command must terminalize Unknown rather than be invented either way"
    );
    assert_eq!(
        sprint.effects[9]
            .observation
            .as_ref()
            .map(|value| value.outcome.clone()),
        Some(grok_build_core::EffectOutcome::Unknown {
            evidence_digest: expected_command_unknown_evidence_digest(),
        }),
        "the Unknown evidence must be the digest of the exact typed failure the runner returned"
    );

    assert_task_transitions(
        sprint,
        &[
            ("Planned", "Ready"),
            ("Ready", "Leased"),
            ("Leased", "Running"),
        ],
    );
    active.attempt.attempt_id.clone()
}

/// The exact evidence digest an `Unknown` task command must carry, and with it
/// the exact typed failure the runner answered with.
///
/// The reason string itself is not stored, only `sha256` of the evidence
/// record built from it, which makes this assertion an equality against a
/// string this test states in full rather than a substring match on something
/// the product happened to write. Both halves are the product's own formats:
/// `task_effect_unknown_evidence` for the record and
/// `adapt_ordinary_command_response` for the reason.
///
/// This is where the increment is visible. While the fourth tool commanded a
/// bare `cargo`, `prepare_v12` refused with "a bare executable name requires an
/// explicit controlled PATH", which `contained_command_failure_code` maps to
/// `InvalidAuthority`, one gate short of any containment backend. With an
/// absolute static executable the boundary composes the backend and stops at
/// the backend's own service-unavailable refusal, which maps to
/// `ContainmentUnavailable`. Substituting `InvalidAuthority` below fails this
/// assertion, so the two are distinguished by measurement and not by prose.
#[cfg(target_os = "linux")]
fn expected_command_unknown_evidence_digest() -> grok_build_core::Digest {
    let reason = "runner returned typed command failure BeforeEffect/ContainmentUnavailable; \
                  capture reconciliation is required";
    grok_build_core::Digest::sha256(
        format!(
            "grok-build.runner-task-effect.v1\neffect_status=unknown-after-dispatch\nreason={reason}\n"
        )
        .as_bytes(),
    )
}

/// The worker owns shadow creation, so a run that reached `WorkerCreateShadow`
/// must leave a real private directory holding exactly the fixture bytes the
/// worker captured from the live root, no more, no less, and nothing mutated.
#[cfg(target_os = "linux")]
fn assert_worker_created_shadow(shadow_root: &Path) {
    let metadata = fs::symlink_metadata(shadow_root)
        .expect("the worker must have created its own private shadow");
    assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "the worker's private shadow must be one real directory"
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o700,
            "the worker's private shadow must be owner-private"
        );
    }
    assert_unchanged_fixture_tree(shadow_root, "the worker-created private shadow");
}

/// Loads the durable recovery projection for the sprint's single attempt.
#[cfg(target_os = "linux")]
fn recovery_facts(
    sprint: &PersistedSprint,
    ledger: &EventLedger,
    attempt_id: &str,
) -> TaskAttemptRecoveryFacts {
    let task_id = sprint.graph.as_ref().expect("durable graph").tasks[0]
        .task_id
        .clone();
    ledger
        .load_task_attempt_recovery_projection(&sprint.spec.sprint_id, &task_id, attempt_id)
        .expect("load durable recovery projection")
        .facts
}

/// Planning really happened: the first durable effect is a fully observed,
/// desktop-owned provider request with no runner-transport claim attached, the
/// provider's graph is the one-task walking skeleton, and no terminal was
/// invented. Returns that task's identity.
fn assert_durable_planning(sprint: &PersistedSprint) -> String {
    let planning = sprint
        .effects
        .first()
        .expect("planning must have committed durably");
    assert_eq!(planning.intent.kind, EffectKind::ProviderRequest);
    assert!(
        planning.observation.is_some(),
        "the planning effect must carry its exact terminal observation"
    );
    assert!(
        planning.dispatch_claim.is_none(),
        "a desktop-owned provider effect must never hold a runner dispatch claim"
    );

    let graph = sprint.graph.as_ref().expect("durable provider task graph");
    assert_eq!(graph.tasks.len(), 1);

    // No phantom success and no non-success terminal was invented.
    assert!(sprint.completion.is_none(), "no phantom completion");
    assert!(sprint.terminal_outcome.is_none(), "no invented terminal");

    graph.tasks[0].task_id.clone()
}

fn assert_task_transitions(sprint: &PersistedSprint, expected: &[(&str, &str)]) {
    let transitions: Vec<(&str, &str)> = sprint
        .events
        .iter()
        .filter_map(|event| match &event.payload {
            AgentEventKind::TaskStateChanged { from, to } => Some((from.as_str(), to.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(
        transitions, expected,
        "the durable task transitions must stop exactly where this target stops"
    );
}

/// The worker's private shadow is created by the worker, so a run that never
/// started one must leave nothing at all at the named destination.
#[cfg(not(target_os = "linux"))]
fn assert_worker_shadow_absent(shadow_root: &Path) {
    assert!(
        fs::symlink_metadata(shadow_root).is_err(),
        "no worker ran, so nothing may exist at the worker-owned shadow destination {}",
        shadow_root.display()
    );
}

fn assert_unchanged_fixture_tree(root: &Path, label: &str) {
    let source = fixture_source_root();
    for relative in FIXTURE_FILES {
        assert_eq!(
            fs::read(root.join(relative)).expect("read tree file"),
            fs::read(source.join(relative)).expect("read fixture file"),
            "{label} {relative} must be byte-identical to the checked-in fixture"
        );
    }
    assert!(
        fs::read_to_string(root.join("src/lib.rs"))
            .expect("read tree source")
            .contains("pub const fn status() -> &'static str {\n    \"TODO\"\n}"),
        "{label} status() must still return the unmodified fixture value"
    );
    assert!(
        !root.join("docs/report.txt").exists(),
        "{label} must not contain the requested report file"
    );
    assert!(
        !root.join("docs").exists(),
        "{label} must not contain the requested report directory"
    );
}

struct SpineFixture {
    workspace: PathBuf,
    runner_binary: PathBuf,
    authority: IssuedWorkspaceGrant,
    base: WorkspaceSnapshot,
    shadow: ShadowWorkspace,
    policy: CompiledExecutionPolicy,
    spec: SprintSpec,
    database: PathBuf,
    /// Declared last so the whole tree is removed only after every handle above
    /// has been dropped.
    root: TestRoot,
}

impl SpineFixture {
    fn new() -> Self {
        let root = TestRoot::new();
        let workspace = root.path("project");
        materialize_trusted_project(&workspace);
        let runner_binary = install_runner_binary(&root);
        let private_state_root = create_private_state_root(&root);

        let authority = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            grant_id: "walking-skeleton-production-spine-grant".into(),
            workspace_root: workspace.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        })
        .expect("issue the trusted project grant");
        let manifest =
            WorkspaceManifest::capture(&authority, 1_000).expect("capture the live base");
        let base = manifest.snapshot().clone();
        // Two real runner rules shape where the private shadow lives, and both
        // were invisible while no worker process could start:
        //
        // 1. the runner admits a fixed shadow root only as one safe child of
        //    the private runner-state root, so it is named there rather than
        //    beside it; and
        // 2. for the `Worker` role the runner requires that exact path to be
        //    *absent* at initialization, because `WorkerCreateShadow` is what
        //    materializes it from the worker's own descriptor-relative live
        //    capture. The desktop therefore names the destination and creates
        //    nothing.
        let shadow = ShadowWorkspace::worker_created_destination(
            &authority,
            &manifest,
            private_state_root.join("private-shadow"),
        )
        .expect("name the worker-created private shadow");
        assert!(
            !shadow.root().exists(),
            "the desktop must not pre-create the worker's private shadow"
        );

        let policy = compile_policy(&authority);
        let spec = sprint_spec(&authority, &base, &build_baseline_command(&root));

        let database = root.path("state/ledger.sqlite3");
        fs::create_dir(database.parent().expect("database parent"))
            .expect("create database directory");

        Self {
            workspace,
            runner_binary,
            authority,
            base,
            shadow,
            policy,
            spec,
            database,
            root,
        }
    }

    fn coordinator(&self) -> DurableWalkingSkeleton<FakeProvider, DesktopRunnerLifecycleOwner> {
        DurableWalkingSkeleton::open_with_runner_lifecycle(
            &self.database,
            FakeProvider::new(),
            lifecycle_owner(&self.root, &self.runner_binary),
        )
        .expect("open the production coordinator")
    }
}

/// Materializes a real trusted project directory from the checked-in fixture.
fn materialize_trusted_project(destination: &Path) {
    let source = fixture_source_root();
    fs::create_dir(destination).expect("create trusted project directory");
    fs::create_dir(destination.join("src")).expect("create trusted project source directory");
    for relative in FIXTURE_FILES {
        let bytes = fs::read(source.join(relative)).expect("read fixture file");
        fs::write(destination.join(relative), bytes).expect("write trusted project file");
    }
}

/// macOS: the spine cannot start a worker process at all, and says exactly why.
#[cfg(not(target_os = "linux"))]
#[test]
fn walking_skeleton_production_spine_stops_at_the_absent_descriptor_exec_bridge() {
    let fixture = SpineFixture::new();
    let mut coordinator = fixture.coordinator();
    coordinator
        .create_draft(&fixture.authority, &fixture.spec, &fixture.base, 1_001)
        .expect("durably create the draft sprint");

    let refusal = coordinator
        .run_until_blocked(
            &fixture.spec.sprint_id,
            &fixture.authority,
            &fixture.policy,
            &fixture.shadow,
            2_000,
        )
        .expect_err("the production spine cannot launch a sandboxed worker on this target");

    // The boundary that actually refuses. This is the worker *process* launch,
    // not the contained-command boundary: the spine never reaches the
    // FakeProvider's turn-4 command dispatch at all, because a task attempt
    // cannot cross into Running without a live runner. That is why this host
    // builds the absolute baseline executable and never resolves it.
    let DurableCoordinatorError::Protocol(detail) = &refusal else {
        panic!("unexpected refusal shape: {refusal:?}");
    };
    assert_eq!(
        *detail,
        expected_launch_refusal(),
        "the refusal must name the exact unavailable native launch binding and its measured cause"
    );

    // Nothing was written anywhere a change could hide, and, because no worker
    // process ever existed, the worker-owned private shadow was never created.
    assert_unchanged_fixture_tree(&fixture.workspace, "the live trusted root");
    assert_worker_shadow_absent(fixture.shadow.root());

    let before_restart = coordinator
        .load_sprint(&fixture.spec.sprint_id)
        .expect("load the durable sprint image before restart");
    {
        let live = EventLedger::open(&fixture.database).expect("open a second live ledger handle");
        assert_fail_closed_custody(&before_restart, &live);
    }
    drop(coordinator);

    // Restart integrity: a ledger reopened from disk in a fresh coordinator
    // reads back the identical durable image and refuses identically without
    // replaying the provider.
    let reopened = EventLedger::open(&fixture.database).expect("reopen the ledger from disk");
    let after_restart = reopened
        .load_sprint(&fixture.spec.sprint_id)
        .expect("read the durable sprint image back from disk");
    assert_eq!(
        after_restart, before_restart,
        "the durable sprint image must survive restart byte-for-byte"
    );
    assert_fail_closed_custody(&after_restart, &reopened);
    drop(reopened);

    let mut restarted = fixture.coordinator();
    let restarted_refusal = restarted
        .run_until_blocked(
            &fixture.spec.sprint_id,
            &fixture.authority,
            &fixture.policy,
            &fixture.shadow,
            4_000,
        )
        .expect_err("restart must reach the same honest refusal");
    assert_eq!(
        format!("{restarted_refusal:?}"),
        format!("{refusal:?}"),
        "restart must not change the refusal"
    );
    let after_second_run = restarted
        .load_sprint(&fixture.spec.sprint_id)
        .expect("reload the durable sprint image after the second run");
    assert_eq!(
        after_second_run, before_restart,
        "a repeated refusal must not append effects, events, or authority"
    );
}

/// A Linux worker creates its private shadow and reaches `Running`. Three
/// file/search effects succeed with lease-scoped keys. The absolute static
/// command fixture then reaches the containment service refusal. Without a
/// native command-journal reopener, its effect remains `Unknown` and the
/// coordinator reports `TaskUnknownCleanupRequired`.
#[cfg(target_os = "linux")]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one drive of the spine keeps its stop point, custody, restart readback, and recovery classification in one auditable sequence"
)]
fn walking_skeleton_production_spine_runs_four_provider_turns_and_stops_at_the_unknown_command() {
    let fixture = SpineFixture::new();
    let mut coordinator = fixture.coordinator();
    coordinator
        .create_draft(&fixture.authority, &fixture.spec, &fixture.base, 1_001)
        .expect("durably create the draft sprint");

    let blocked = coordinator
        .run_until_blocked(
            &fixture.spec.sprint_id,
            &fixture.authority,
            &fixture.policy,
            &fixture.shadow,
            2_000,
        )
        .expect("the spine now stops with a typed cleanup requirement, not a refusal");
    assert_command_unknown_cleanup_stop(&blocked, &fixture.spec.sprint_id);

    // The live trusted root is still untouched: a worker that only captured and
    // copied has written nothing back.
    assert_unchanged_fixture_tree(&fixture.workspace, "the live trusted root");
    // The worker created the shadow from its own capture; the desktop only
    // named the destination.
    assert_worker_created_shadow(fixture.shadow.root());

    let before_restart = coordinator
        .load_sprint(&fixture.spec.sprint_id)
        .expect("load the durable sprint image before restart");
    let attempt_id = {
        let live = EventLedger::open(&fixture.database).expect("open a second live ledger handle");
        let attempt_id = assert_running_worker_custody(&before_restart, &live);
        // The launch and its initialized session are durable, not merely
        // claimed: both read back from the ledger by their exact identities.
        live.load_runner_launch_intent(
            &before_restart.spec.sprint_id,
            &format!("{attempt_id}:worker-launch-v1"),
        )
        .expect("the admitted launch must be durable");
        live.load_runner_session(
            &before_restart.spec.sprint_id,
            &format!("{attempt_id}:worker-session-v1"),
        )
        .expect("the initialized session must be durable");
        // The attempt owns a command effect whose terminal is durably `Unknown`,
        // so the recovery projection is fail-closed `UncertainAuthority` naming
        // that exact observation rather than plain `CurrentAuthority`.
        assert_eq!(
            recovery_facts(&before_restart, &live, &attempt_id),
            TaskAttemptRecoveryFacts::UncertainAuthority {
                evidence_id: format!("{}:observation", before_restart.effects[9].intent.effect_id)
            },
            "the projection must name the exact Unknown command observation"
        );
        attempt_id
    };
    drop(coordinator);

    // Restart integrity: the durable image reads back identically from disk, and
    // a fresh coordinator neither launches a replacement worker nor invents
    // forward authority over a recovered `Running` attempt.
    let reopened = EventLedger::open(&fixture.database).expect("reopen the ledger from disk");
    let after_restart = reopened
        .load_sprint(&fixture.spec.sprint_id)
        .expect("read the durable sprint image back from disk");
    assert_eq!(
        after_restart, before_restart,
        "the durable sprint image must survive restart byte-for-byte"
    );
    assert_eq!(
        assert_running_worker_custody(&after_restart, &reopened),
        attempt_id
    );
    drop(reopened);

    // A restarted coordinator recovers the exact `Running` boundary from the
    // ledger, replays the already-observed provider turns and tool terminals
    // from durable evidence only, finds the command terminal `Unknown`, and
    // reports the identical cleanup requirement. It does not relaunch a second
    // worker over the recovered authority, does not redispatch any tool, and
    // does not invent a replacement shadow: a `Running` boundary is replay
    // authority, never a live process handle.
    let mut restarted = fixture.coordinator();
    let restarted_status = restarted
        .run_until_blocked(
            &fixture.spec.sprint_id,
            &fixture.authority,
            &fixture.policy,
            &fixture.shadow,
            4_000,
        )
        .expect("restart reconciles the recovered Running attempt instead of relaunching");
    assert_command_unknown_cleanup_stop(&restarted_status, &fixture.spec.sprint_id);
    let after_second_run = restarted
        .load_sprint(&fixture.spec.sprint_id)
        .expect("reload the durable sprint image after the second run");
    assert_eq!(
        after_second_run, before_restart,
        "a repeated refusal must not append effects, events, or authority"
    );

    // Nothing ran a second time, so neither tree moved and no second shadow was
    // created beside the worker's own.
    assert_unchanged_fixture_tree(&fixture.workspace, "the live trusted root");
    assert_worker_created_shadow(fixture.shadow.root());

    let final_ledger =
        EventLedger::open(&fixture.database).expect("reopen the ledger for a custody re-read");
    assert_eq!(
        assert_running_worker_custody(&after_second_run, &final_ledger),
        attempt_id
    );
    final_ledger
        .load_runner_launch_intent(
            &after_second_run.spec.sprint_id,
            &format!("{attempt_id}:worker-launch-v1"),
        )
        .expect("the recovered attempt must still carry its exact durable launch");
    final_ledger
        .load_runner_session(
            &after_second_run.spec.sprint_id,
            &format!("{attempt_id}:worker-session-v1"),
        )
        .expect("the recovered attempt must still carry its exact durable session");
    assert_eq!(
        recovery_facts(&after_second_run, &final_ledger, &attempt_id),
        TaskAttemptRecoveryFacts::UncertainAuthority {
            evidence_id: format!(
                "{}:observation",
                after_second_run.effects[9].intent.effect_id
            )
        },
        "restart must not change the fail-closed classification"
    );
}

/// The exact stop the production spine now reaches on Linux. Four Running-phase
/// provider turns complete, three of them dispatching a real runner file or
/// search effect to a successful terminal; the fourth authorizes the sprint's
/// absolute static baseline command, whose transport ends `Unknown` at the
/// contained backend's own refusal. Closing that `Unknown` needs a native command-journal reopener
/// that no admitted native service supplies on this target, so the coordinator
/// stops with a typed cleanup requirement rather than inventing a terminal.
#[cfg(target_os = "linux")]
fn assert_command_unknown_cleanup_stop(
    status: &grok_build_desktop::WalkingSkeletonStatus,
    sprint_id: &str,
) {
    let grok_build_desktop::WalkingSkeletonStatus::TaskUnknownCleanupRequired {
        task_id,
        attempt_id,
        effect_id,
        reason,
    } = status
    else {
        panic!("unexpected spine stop point: {status:?}");
    };
    assert_eq!(task_id, &format!("{sprint_id}:task-1"));
    assert_eq!(effect_id, &format!("{sprint_id}:{attempt_id}:tool-v1-0004"));
    assert_eq!(
        reason,
        &format!(
            "task-command Unknown cleanup requires a native command journal reopener for effect \
             {effect_id}"
        ),
        "the spine must stop at the ordinary command's missing native cleanup custody"
    );
}
