//! Explicit, test-only daily-use durability soak.

use std::fs;
use std::io::{Cursor, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use grok_build_plus_host::PlusSessionStore;
use serde::Serialize;

use crate::backend::{
    Backend, PreparedGitOperation, WorkspaceSessionEffect, project_operation_drift,
};
use crate::contracts::{ProjectId, SessionId, WorkspaceId};
use crate::diagnostics::export_diagnostic_zip;
use crate::events::{DiagnosticEventAction, EventPayload, GitEventAction, GitEventPhase};
use crate::git_process::{MAX_GIT_METADATA_BYTES, git_command, require_git_success, run_git};
use crate::git_review::{discard_git_hunk, list_git_review, stage_git_hunk, unstage_git_hunk};
use crate::project_transition_support::BackendProjectTransitions as _;
use crate::pty::{INTERACTIVE_SHELL_LABEL, PtyEventSink, PtyManager, PtyState, PtyTarget};
use crate::queue::{EnqueueRequest, QueueCoordinator, QueueItemState, RunState};
use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeTransport;
use crate::workspace::{list_workspace_directory, open_workspace_file};
use crate::worktrees::{
    WorktreeRemoveView, create_managed_worktree, export_worktree_recovery, remove_managed_worktree,
    remove_worktree_after_export,
};

const SOAK_CYCLES: usize = 25;
const EXPECTED_PROPOSAL_BYTES: &[u8] = b"Proposed by plus tool loop\n";

struct SoakFixture {
    root: PathBuf,
    pty: PtyManager,
}

impl SoakFixture {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "grok-build-daily-use-soak-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create daily-use soak root");
        Self {
            root,
            pty: PtyManager::default(),
        }
    }
}

impl Drop for SoakFixture {
    fn drop(&mut self) {
        self.pty.shutdown_all();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn tracked_baseline() -> String {
    (1..=40)
        .map(|line| format!("line {line}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn git(root: &Path, args: &[&str]) {
    let mut command = git_command(root);
    command.args(args);
    let output = run_git(command, None, MAX_GIT_METADATA_BYTES).expect("run bounded fixture Git");
    require_git_success(output, "prepare daily-use soak fixture").expect("fixture Git success");
}

fn prepare_repository(root: &Path) {
    fs::create_dir_all(root).expect("create soak repository");
    git(root, &["init", "--quiet", "--initial-branch=main"]);
    git(root, &["config", "user.name", "Grok Build Daily Soak"]);
    git(
        root,
        &["config", "user.email", "grok-build-daily-soak@invalid"],
    );
    fs::write(root.join("tracked.txt"), tracked_baseline()).expect("seed tracked file");
    fs::write(root.join("plus-tool-note.txt"), "tool-note daily soak\n")
        .expect("seed FakeProvider read fixture");
    fs::write(root.join(".gitignore"), "ignored-cache/\n").expect("seed ignore fixture");
    git(
        root,
        &[
            "add",
            "--",
            "tracked.txt",
            "plus-tool-note.txt",
            ".gitignore",
        ],
    );
    git(root, &["commit", "--quiet", "-m", "daily soak baseline"]);
}

fn queue_request(
    project_id: &str,
    project_root: &Path,
    cycle: usize,
    suffix: &str,
    auto_start: bool,
) -> EnqueueRequest {
    EnqueueRequest {
        project_id: ProjectId::new(project_id),
        workspace_id: WorkspaceId::new(format!("workspace-{project_id}")),
        workspace_root: project_root.display().to_string(),
        session_id: SessionId::new(format!("session-{project_id}-{cycle}")),
        transport: RuntimeTransport::GrokCliAcp,
        prompt: format!("daily soak cycle {cycle} {suffix}"),
        auto_start,
        retry_of_run_id: None,
        predecessor_run_id: None,
    }
}

fn exercise_queue_restart(
    root: &Path,
    alpha_id: &str,
    alpha_root: &Path,
    beta_id: &str,
    beta_root: &Path,
    cycle: usize,
) {
    let queue_root = root.join(format!("queue-cycle-{cycle:02}"));
    let (alpha_run_id, beta_run_id, alpha_item_id, beta_item_id, manual_item_id) = {
        let queue = QueueCoordinator::open(queue_root.clone());
        let alpha = queue
            .enqueue(queue_request(alpha_id, alpha_root, cycle, "alpha", true))
            .expect("enqueue alpha soak prompt");
        let manual_alpha = queue
            .enqueue(queue_request(
                alpha_id,
                alpha_root,
                cycle,
                "manual alpha",
                false,
            ))
            .expect("enqueue second alpha prompt");
        let beta = queue
            .enqueue(queue_request(beta_id, beta_root, cycle, "beta", true))
            .expect("enqueue beta soak prompt");

        let alpha_run = queue
            .begin_run(&alpha.id, RuntimeCancelHandle::new())
            .expect("start first project run");
        let same_project = queue
            .begin_run(&manual_alpha.id, RuntimeCancelHandle::new())
            .expect_err("second run in one project must refuse");
        assert!(same_project.contains("already has an active agent run"));
        let beta_run = queue
            .begin_run(&beta.id, RuntimeCancelHandle::new())
            .expect("start second global run");
        assert_eq!(queue.view().active_global_runs, 2);
        assert!(
            queue
                .candidates(None, false)
                .expect("full queue view")
                .is_empty()
        );
        (
            alpha_run.run.id,
            beta_run.run.id,
            alpha.id,
            beta.id,
            manual_alpha.id,
        )
    };

    let reopened = QueueCoordinator::open(queue_root.clone());
    let recovered = reopened
        .take_recovered_interruptions()
        .expect("read recovered interruptions");
    assert_eq!(recovered.len(), 2);
    assert!(
        recovered
            .iter()
            .any(|run| run.id == alpha_run_id && run.state == RunState::Interrupted)
    );
    assert!(
        recovered
            .iter()
            .any(|run| run.id == beta_run_id && run.state == RunState::Interrupted)
    );
    let view = reopened.view();
    for interrupted in [&alpha_item_id, &beta_item_id] {
        assert!(view.items.iter().any(|item| {
            item.id == interrupted.as_str() && item.state == QueueItemState::Interrupted
        }));
    }
    assert!(view.items.iter().any(|item| {
        item.id == manual_item_id.as_str() && item.state == QueueItemState::Queued
    }));
    assert!(
        reopened
            .candidates(None, false)
            .expect("no automatic replay candidates")
            .is_empty()
    );
    drop(reopened);
    fs::remove_dir_all(queue_root).expect("remove queue cycle root");
}

fn json_hunk_id(value: &impl Serialize, lane: &str) -> String {
    let value = serde_json::to_value(value).expect("serialize Git Review view");
    value[lane]
        .as_array()
        .expect("Git Review lane")
        .iter()
        .find(|file| file["path"] == "tracked.txt")
        .and_then(|file| file["hunks"].as_array())
        .and_then(|hunks| hunks.first())
        .and_then(|hunk| hunk["id"].as_str())
        .map(str::to_owned)
        .expect("tracked.txt hunk identity")
}

fn json_string(value: &impl Serialize, field: &str) -> String {
    serde_json::to_value(value).expect("serialize product view")[field]
        .as_str()
        .map(str::to_owned)
        .expect("required serialized field")
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn exercise_pty(fixture: &SoakFixture, target: &PtyTarget, other: &PtyTarget, cycle: usize) {
    let sink: PtyEventSink = Arc::new(|_| Ok(()));
    let started = fixture
        .pty
        .start(target.clone(), 24, 80, sink)
        .expect("start daily-use PTY");
    assert_eq!(started.state, PtyState::Live);
    assert_eq!(started.cwd, target.cwd.display().to_string());
    assert_eq!(started.label, INTERACTIVE_SHELL_LABEL);

    let marker = format!("DAILY-SOAK-PTY-{cycle:02}");
    fixture
        .pty
        .write(target, format!("printf '{marker}\\n'\r").as_bytes())
        .expect("write daily-use PTY marker");
    let deadline = Instant::now() + Duration::from_secs(2);
    let observed = loop {
        let view = fixture.pty.status(target).expect("read daily-use PTY");
        if contains_bytes(&view.scrollback, marker.as_bytes()) || Instant::now() >= deadline {
            break view;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(contains_bytes(&observed.scrollback, marker.as_bytes()));
    let resized = fixture
        .pty
        .resize(target, 30, 100)
        .expect("resize daily-use PTY");
    assert_eq!((resized.rows, resized.cols), (30, 100));
    let other_view = fixture.pty.status(other).expect("read other project PTY");
    assert!(!contains_bytes(&other_view.scrollback, marker.as_bytes()));
    fixture.pty.stop(target).expect("stop daily-use PTY");
}

#[allow(
    clippy::too_many_lines,
    reason = "the test preserves one linear worktree, hunk, dirty-refusal, recovery-export, and verified-removal transaction"
)]
fn exercise_worktree_and_git(
    fixture: &SoakFixture,
    backend: &mut Backend,
    other_pty_target: &PtyTarget,
    cycle: usize,
) {
    let task = format!("Daily Soak {cycle:02}");
    create_worktree_fixture(backend, &task);
    let project = backend
        .active_project_record()
        .expect("active soak project");
    let worktree_id = project
        .active_worktree_id
        .clone()
        .expect("active worktree identity");
    let worktree = project
        .worktrees
        .iter()
        .find(|worktree| worktree.id == worktree_id)
        .cloned()
        .expect("active worktree record");

    let pty_target = backend.active_pty_target().expect("worktree PTY target");
    exercise_pty(fixture, &pty_target, other_pty_target, cycle);

    let selected =
        tracked_baseline().replacen("line 1", &format!("selected daily-use edit {cycle:02}"), 1);
    fs::write(worktree.path.join("tracked.txt"), selected).expect("write selected hunk edit");
    let review = list_git_review(&backend.active_project_record().expect("review project"));
    let unstaged_id = json_hunk_id(&review, "unstagedFiles");
    let staged = run_git_fixture(
        backend,
        GitEventAction::HunkStaged,
        &unstaged_id,
        |prepared| stage_git_hunk(&prepared.store, &prepared.project, &unstaged_id),
    );
    assert_eq!(staged.outcome, "staged");
    let staged_id = json_hunk_id(&staged.review, "stagedFiles");
    let unstaged = run_git_fixture(
        backend,
        GitEventAction::HunkUnstaged,
        &staged_id,
        |prepared| unstage_git_hunk(&prepared.store, &prepared.project, &staged_id),
    );
    assert_eq!(unstaged.outcome, "unstaged");
    let discard_id = json_hunk_id(&unstaged.review, "unstagedFiles");
    let discarded = run_git_fixture(
        backend,
        GitEventAction::HunkDiscarded,
        &discard_id,
        |prepared| {
            discard_git_hunk(
                &prepared.store,
                &prepared.project,
                &discard_id,
                &format!("DISCARD HUNK {}", &discard_id[..12]),
            )
        },
    );
    assert_eq!(discarded.outcome, "discarded");
    assert_eq!(
        fs::read_to_string(worktree.path.join("tracked.txt")).expect("read discarded file"),
        tracked_baseline()
    );

    let workspace_name = format!("workspace-cycle-{cycle:02}.txt");
    let workspace_contents = format!("workspace refresh cycle {cycle:02}\n");
    fs::write(worktree.path.join(&workspace_name), &workspace_contents)
        .expect("write workspace refresh fixture");
    let authority = backend
        .workspace_read_authority()
        .expect("worktree workspace authority");
    let listing = list_workspace_directory(&authority, ".").expect("refresh workspace listing");
    assert!(listing.contains_entry(&workspace_name, "file"));
    assert!(
        open_workspace_file(&authority, &workspace_name)
            .expect("open refreshed workspace file")
            .is_exact_text(&workspace_name, &workspace_contents)
    );

    fs::write(
        worktree.path.join("tracked.txt"),
        format!("staged dirty cycle {cycle:02}\n"),
    )
    .expect("write dirty tracked file");
    git(&worktree.path, &["add", "--", "tracked.txt"]);
    let ignored_name = format!("ignored-cache/private-{cycle:02}.txt");
    fs::create_dir_all(worktree.path.join("ignored-cache")).expect("create ignored directory");
    fs::write(
        worktree.path.join(&ignored_name),
        "ignored recovery bytes\n",
    )
    .expect("write ignored recovery fixture");

    let prepared = backend
        .prepare_git_operation(
            GitEventAction::WorktreeRemoved,
            GitEventPhase::Requested,
            Some(&worktree_id),
        )
        .expect("prepare dirty removal");
    let refused = finish_remove_fixture(
        backend,
        &prepared,
        remove_managed_worktree(&prepared.store, &prepared.project, &worktree_id),
    )
    .expect("dirty removal response");
    assert_eq!(refused.outcome, "refused");
    assert_eq!(refused.dirty.staged, ["tracked.txt"]);
    assert!(refused.dirty.untracked.contains(&workspace_name));
    assert!(refused.dirty.ignored.contains(&ignored_name));
    assert!(worktree.path.exists());

    let recovery_root = fixture.root.join("recovery");
    fs::create_dir_all(&recovery_root).expect("create recovery destination");
    let exported = run_git_fixture(
        backend,
        GitEventAction::RecoveryExported,
        &worktree_id,
        |prepared| {
            export_worktree_recovery(
                &prepared.store,
                &prepared.project,
                &worktree_id,
                &recovery_root,
            )
        },
    );
    let manifest_hash = json_string(&exported, "manifestHash");
    let export_path = PathBuf::from(json_string(&exported, "path"));
    assert!(export_path.join("manifest.json").is_file());
    assert!(export_path.join("staged.patch").is_file());
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::WorktreeRemoved,
            GitEventPhase::PostExportRequested,
            Some(&worktree_id),
        )
        .expect("prepare verified removal");
    let removed = finish_remove_fixture(
        backend,
        &prepared,
        remove_worktree_after_export(
            &prepared.store,
            &prepared.project,
            &worktree_id,
            &manifest_hash,
            &format!("REMOVE {task}"),
        ),
    )
    .expect("remove verified recovery worktree");
    assert_eq!(removed.outcome, "removed-after-export");
    assert_eq!(removed.removed_id.as_deref(), Some(worktree_id.as_str()));
    assert!(!worktree.path.exists());
    assert!(
        backend
            .active_project_record()
            .expect("base project after worktree removal")
            .active_worktree_id
            .is_none()
    );
}

fn run_git_fixture<T>(
    backend: &mut Backend,
    action: GitEventAction,
    identity: &str,
    effect: impl FnOnce(&PreparedGitOperation) -> Result<T, String>,
) -> T {
    let prepared = backend
        .prepare_git_operation(action, GitEventPhase::Requested, Some(identity))
        .expect("prepare soak Git operation");
    backend
        .revalidate_operation(&prepared.context)
        .expect("revalidate soak Git operation");
    let result = effect(&prepared);
    backend
        .finish_prepared_git_with_phase(&prepared, result, GitEventPhase::Completed)
        .expect("finish soak Git operation")
        .0
}

fn create_worktree_fixture(backend: &mut Backend, task: &str) {
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::WorktreeCreated,
            GitEventPhase::Requested,
            None,
        )
        .expect("prepare soak worktree creation");
    let record = create_managed_worktree(&prepared.store, &prepared.project, task, "HEAD")
        .expect("create soak worktree");
    let worktree_id = record.id.clone();
    let (projects, bound) = prepared
        .store
        .register_managed_worktree(&prepared.project.id, record, true)
        .expect("register soak worktree");
    backend
        .revalidate_workspace_effect(
            &prepared.context,
            &projects,
            &bound,
            WorkspaceSessionEffect::FollowWorkspace,
        )
        .expect("revalidate soak worktree creation");
    let status = format!("Active worktree `{task}`: {}", bound.folder().display());
    backend.load_active_project(projects, Some(bound), status);
    backend
        .record_git_event(
            prepared.event_context,
            GitEventAction::WorktreeCreated,
            GitEventPhase::Completed,
            Some(&worktree_id),
        )
        .expect("record soak worktree creation");
}

fn finish_remove_fixture(
    backend: &mut Backend,
    prepared: &PreparedGitOperation,
    result: Result<WorktreeRemoveView, String>,
) -> Result<WorktreeRemoveView, String> {
    let view = result?;
    if view.removed_id.is_none() {
        return backend
            .finish_prepared_git_with_phase(prepared, Ok(view), GitEventPhase::Refused)
            .map(|(view, _)| view);
    }
    let (projects, bound) = prepared
        .store
        .forget_managed_worktree(
            &prepared.project.id,
            view.removed_id.as_deref().expect("removed worktree id"),
        )
        .map_err(|error| error.to_string())?;
    let bound = bound.ok_or_else(project_operation_drift)?;
    let session_effect =
        if prepared.project.active_worktree_id.as_deref() == view.removed_id.as_deref() {
            WorkspaceSessionEffect::FollowWorkspace
        } else {
            WorkspaceSessionEffect::Preserve
        };
    backend.revalidate_workspace_effect(&prepared.context, &projects, &bound, session_effect)?;
    let status = format!("Active workspace: {}", bound.folder().display());
    backend.load_active_project(projects, Some(bound), status);
    backend.record_git_event(
        prepared.event_context.clone(),
        GitEventAction::WorktreeRemoved,
        GitEventPhase::Completed,
        prepared.identity.as_deref(),
    )?;
    Ok(view)
}

fn assert_diagnostic_omits(path: &Path, sentinel: &str) {
    let bytes = fs::read(path).expect("read diagnostic ZIP");
    assert!(!contains_bytes(&bytes, sentinel.as_bytes()));
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("open diagnostic ZIP");
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).expect("read diagnostic entry");
        let mut body = Vec::new();
        entry
            .read_to_end(&mut body)
            .expect("read diagnostic entry bytes");
        assert!(
            !contains_bytes(&body, sentinel.as_bytes()),
            "diagnostic entry {} exposed the soak sentinel",
            entry.name()
        );
    }
}

fn exercise_diagnostics_and_activity(
    fixture: &SoakFixture,
    backend: &mut Backend,
    state_root: &Path,
    cycle: usize,
) {
    let sentinel = format!("DAILY_SOAK_SECRET_SENTINEL_{cycle:02}_DO_NOT_EXPORT");
    backend.chat.clone_from(&sentinel);
    backend.command_outcome.clone_from(&sentinel);
    fs::write(
        state_root.join(format!("excluded-sensitive-state-{cycle:02}")),
        &sentinel,
    )
    .expect("write excluded diagnostic sentinel");

    let context = backend
        .active_event_context()
        .expect("diagnostic Activity context");
    let requested = backend
        .events
        .record(
            context.clone(),
            EventPayload::Diagnostic {
                action: DiagnosticEventAction::ExportRequested,
                entry_count: None,
            },
        )
        .expect("record diagnostic intent");
    let destination = fixture.root.join(format!("diagnostic-{cycle:02}.zip"));
    let exported = export_diagnostic_zip(&backend.diagnostic_input(), &destination)
        .expect("export daily-use diagnostic");
    let completed = backend
        .events
        .record(
            context,
            EventPayload::Diagnostic {
                action: DiagnosticEventAction::ExportCompleted,
                entry_count: Some(exported.entry_count),
            },
        )
        .expect("record diagnostic completion");
    assert!(requested.sequence < completed.sequence);
    assert_diagnostic_omits(&destination, &sentinel);

    let timeline = backend.events.timeline(None);
    assert!(timeline.available);
    assert!(
        timeline
            .events
            .windows(2)
            .all(|events| events[0].sequence < events[1].sequence)
    );
    assert!(!contains_bytes(
        &serde_json::to_vec(&timeline).expect("encode timeline"),
        sentinel.as_bytes()
    ));
    fs::remove_file(destination).expect("remove diagnostic ZIP fixture");
}

#[test]
#[ignore = "explicit 25-cycle daily-use durability soak"]
#[allow(
    clippy::too_many_lines,
    reason = "the named soak keeps all repeated daily-use invariants under one cycle counter and one cleanup guard"
)]
fn daily_use_two_project_restart_soak() {
    let fixture = SoakFixture::new();
    let alpha_root = fixture.root.join("alpha");
    let beta_root = fixture.root.join("beta");
    prepare_repository(&alpha_root);
    prepare_repository(&beta_root);
    let alpha_root = alpha_root.canonicalize().expect("canonical alpha root");
    let beta_root = beta_root.canonicalize().expect("canonical beta root");
    let state_root = fixture.root.join("state");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(&state_root));

    let alpha_id = backend
        .bind_project(&alpha_root.display().to_string())
        .expect("bind alpha project")
        .present_current()
        .active_project_id
        .expect("alpha project id");
    let beta_id = backend
        .bind_project(&beta_root.display().to_string())
        .expect("bind beta project")
        .present_current()
        .active_project_id
        .expect("beta project id");
    assert_ne!(alpha_id, beta_id);
    assert_eq!(backend.snapshot().projects.len(), 2);

    backend
        .switch_project(&alpha_id)
        .expect("activate alpha base");
    let alpha_pty = backend.active_pty_target().expect("alpha base PTY target");
    backend
        .switch_project(&beta_id)
        .expect("activate beta base");
    let beta_pty = backend.active_pty_target().expect("beta base PTY target");

    for cycle in 0..SOAK_CYCLES {
        exercise_queue_restart(
            &fixture.root,
            &alpha_id,
            &alpha_root,
            &beta_id,
            &beta_root,
            cycle,
        );

        let (target_id, other_id, target_root, other_pty) = if cycle % 2 == 0 {
            (&alpha_id, &beta_id, &alpha_root, &beta_pty)
        } else {
            (&beta_id, &alpha_id, &beta_root, &alpha_pty)
        };
        backend
            .switch_project(target_id)
            .expect("activate cycle project");
        let proposal_path = target_root.join("plus-tool-proposed.txt");
        if proposal_path.exists() {
            fs::remove_file(&proposal_path).expect("reset prior accepted proposal fixture");
        }
        let marker = format!("daily-use-project-marker-{cycle:02}");
        let staged = backend
            .send_fake_chat_for_smoke(&marker)
            .expect("run explicit test-only FakeProvider turn")
            .present_current();
        assert_eq!(staged.security.kind, "off");
        assert!(staged.chat.contains(&marker));
        assert!(staged.chat.contains("run_contained → failed:"));
        assert!(!staged.chat.contains("run_contained → completed:"));
        assert_eq!(staged.staged.len(), 1);
        assert_eq!(staged.staged[0].path, "plus-tool-proposed.txt");
        assert!(!proposal_path.exists());
        if cycle % 2 == 0 {
            let accepted = backend
                .accept_file("plus-tool-proposed.txt")
                .expect("Accept exact soak proposal")
                .present_current();
            assert!(accepted.staged.is_empty());
            assert_eq!(
                fs::read(&proposal_path).expect("read accepted soak proposal"),
                EXPECTED_PROPOSAL_BYTES
            );
        } else {
            let rejected = backend
                .reject_file("plus-tool-proposed.txt")
                .expect("Reject exact soak proposal")
                .present_current();
            assert!(rejected.staged.is_empty());
            assert!(!proposal_path.exists());
        }

        backend
            .switch_project(other_id)
            .expect("switch to other project");
        assert!(!backend.snapshot().chat.contains(&marker));
        backend
            .switch_project(target_id)
            .expect("return to cycle project");
        assert!(backend.snapshot().chat.contains(&marker));

        exercise_worktree_and_git(&fixture, &mut backend, other_pty, cycle);
        exercise_diagnostics_and_activity(&fixture, &mut backend, &state_root, cycle);

        drop(backend);
        backend = Backend::new(PlusSessionStore::from_state_root(&state_root));
        assert_eq!(
            backend.snapshot().active_project_id.as_deref(),
            Some(target_id.as_str())
        );
        assert!(backend.snapshot().chat.contains(&marker));
        backend
            .switch_project(other_id)
            .expect("switch after restart");
        assert!(!backend.snapshot().chat.contains(&marker));
        backend
            .switch_project(target_id)
            .expect("restore cycle project after restart");
    }

    fixture.pty.shutdown_all();
    println!(
        "DAILY USE SOAK PASSED cycles={SOAK_CYCLES} projects=2 fake_provider=test-only desktop=false capture=false voice=false"
    );
}
