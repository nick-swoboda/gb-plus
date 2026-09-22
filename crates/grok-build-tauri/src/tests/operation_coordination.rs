use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use grok_build_plus_host::{
    PlusSessionStore, bind_project_folder, managed_worktree_identity, managed_worktree_record,
};

use crate::backend::{Backend, WorkspaceSessionEffect};
use crate::events::{GitEventAction, GitEventPhase};
use crate::operations::ProjectOperationPermits;
use crate::queue::RunState;
use crate::runtime::cancel::RuntimeCancelHandle;

fn fixture_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-operation-{label}-{}",
        std::process::id()
    ))
}

#[test]
fn project_workspace_identity_drift_refuses_a_prepared_operation() {
    let root = fixture_root("drift");
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    fs::create_dir_all(&alpha).expect("create alpha");
    fs::create_dir_all(&beta).expect("create beta");
    let alpha = alpha.canonicalize().expect("canonical alpha");
    let beta = beta.canonicalize().expect("canonical beta");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&alpha.display().to_string())
        .expect("bind alpha");
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::HunkStaged,
            GitEventPhase::Requested,
            Some("fixture-hunk"),
        )
        .expect("prepare alpha operation");
    backend
        .bind_project(&beta.display().to_string())
        .expect("switch generation to beta");
    let error = backend
        .finish_prepared_git_with_phase(
            &prepared,
            Ok::<_, String>("uncommitted fixture result"),
            GitEventPhase::Completed,
        )
        .expect_err("identity drift must refuse completion");
    assert!(error.contains("project, session, workspace, root, or generation changed"));
    fs::remove_dir_all(root).expect("remove drift fixture");
}

#[test]
fn intentional_workspace_transition_accepts_only_exact_post_effect_session() {
    let root = fixture_root("workspace-effect");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind project");
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::WorktreeCreated,
            GitEventPhase::Requested,
            None,
        )
        .expect("prepare worktree transition");
    let (worktree_id, _) = managed_worktree_identity(&prepared.project.id, "exact transition")
        .expect("derive managed worktree identity");
    let worktree_path = store
        .managed_worktree_path(&prepared.project.id, &worktree_id)
        .expect("derive managed worktree path");
    fs::create_dir_all(&worktree_path).expect("create managed worktree directory");
    let record = managed_worktree_record(
        &prepared.project.id,
        "exact transition",
        worktree_path,
        &"0".repeat(40),
    )
    .expect("build managed worktree record");
    let (projects, bound) = store
        .register_managed_worktree(&prepared.project.id, record, true)
        .expect("register and activate managed worktree");

    assert!(backend.revalidate_operation(&prepared.context).is_err());
    backend
        .revalidate_workspace_effect(
            &prepared.context,
            &projects,
            &bound,
            WorkspaceSessionEffect::FollowWorkspace,
        )
        .expect("the exact effect-owned workspace/session transition is valid");

    let mut crossed_projects = projects.clone();
    crossed_projects.projects[0].name.push_str(" crossed");
    assert!(
        backend
            .revalidate_workspace_effect(
                &prepared.context,
                &crossed_projects,
                &bound,
                WorkspaceSessionEffect::FollowWorkspace,
            )
            .is_err()
    );
    store
        .create_plus_session("crossed session")
        .expect("create competing session");
    assert!(
        backend
            .revalidate_workspace_effect(
                &prepared.context,
                &projects,
                &bound,
                WorkspaceSessionEffect::FollowWorkspace,
            )
            .is_err()
    );
    fs::remove_dir_all(root).expect("remove workspace-effect fixture");
}

#[test]
fn recovery_export_completion_refreshes_receipt_without_changing_workspace() {
    let root = fixture_root("recovery-metadata");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind project");
    let project = backend.active_project_record().expect("active project");
    let (worktree_id, _) = managed_worktree_identity(&project.id, "recovery metadata")
        .expect("derive managed worktree identity");
    let worktree_path = store
        .managed_worktree_path(&project.id, &worktree_id)
        .expect("derive managed worktree path");
    fs::create_dir_all(&worktree_path).expect("create managed worktree directory");
    let record = managed_worktree_record(
        &project.id,
        "recovery metadata",
        worktree_path,
        &"0".repeat(40),
    )
    .expect("build managed worktree record");
    let (projects, bound) = store
        .register_managed_worktree(&project.id, record, true)
        .expect("register managed worktree");
    backend.load_active_project(
        projects,
        Some(bound),
        "Active recovery fixture worktree".into(),
    );
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::RecoveryExported,
            GitEventPhase::Requested,
            Some(&worktree_id),
        )
        .expect("prepare recovery metadata refresh");
    let manifest = "a".repeat(64);
    let state = "b".repeat(64);
    store
        .remember_worktree_recovery(&project.id, &worktree_id, &manifest, &state)
        .expect("persist recovery receipt");
    backend
        .finish_prepared_git_with_phase(&prepared, Ok(()), GitEventPhase::Completed)
        .expect("finish recovery metadata refresh");

    assert_eq!(
        backend.operation_context().expect("context after refresh"),
        prepared.context
    );
    let refreshed = backend.active_project_record().expect("refreshed project");
    let worktree = refreshed.active_worktree().expect("active worktree");
    assert_eq!(
        worktree.recovery_manifest.as_deref(),
        Some(manifest.as_str())
    );
    assert_eq!(worktree.recovery_state.as_deref(), Some(state.as_str()));
    fs::remove_dir_all(root).expect("remove recovery-metadata fixture");
}

#[test]
fn nonactive_worktree_update_preserves_exact_custom_session() {
    let root = fixture_root("preserved-session");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let mut backend = Backend::new(store.clone());
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind project");
    store
        .create_plus_session("custom session")
        .expect("select custom session");
    let prepared = backend
        .prepare_git_operation(
            GitEventAction::WorktreeCreated,
            GitEventPhase::Requested,
            None,
        )
        .expect("prepare metadata-only worktree update");
    let (worktree_id, _) = managed_worktree_identity(&prepared.project.id, "nonactive worktree")
        .expect("derive managed worktree identity");
    let worktree_path = store
        .managed_worktree_path(&prepared.project.id, &worktree_id)
        .expect("derive managed worktree path");
    fs::create_dir_all(&worktree_path).expect("create managed worktree directory");
    let record = managed_worktree_record(
        &prepared.project.id,
        "nonactive worktree",
        worktree_path,
        &"0".repeat(40),
    )
    .expect("build managed worktree record");
    let (projects, _) = store
        .register_managed_worktree(&prepared.project.id, record, false)
        .expect("register nonactive worktree");
    let bound = bind_project_folder(&workspace).expect("active base binding");

    backend
        .revalidate_workspace_effect(
            &prepared.context,
            &projects,
            &bound,
            WorkspaceSessionEffect::Preserve,
        )
        .expect("metadata-only update preserves the exact custom session");
    assert!(
        backend
            .revalidate_workspace_effect(
                &prepared.context,
                &projects,
                &bound,
                WorkspaceSessionEffect::FollowWorkspace,
            )
            .is_err()
    );
    fs::remove_dir_all(root).expect("remove preserved-session fixture");
}

#[test]
fn stop_does_not_wait_for_a_blocked_project_operation_permit() {
    let root = fixture_root("stop");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind project");
    let project = backend.active_project_typed_id().expect("project id");
    let queue = backend.queue.clone();
    let item = queue
        .enqueue(
            backend
                .queue_request("blocked Git stop", true)
                .expect("request"),
        )
        .expect("enqueue");
    let cancel = RuntimeCancelHandle::new();
    queue
        .begin_run(&item.id, cancel.clone())
        .expect("begin run");
    let permits = ProjectOperationPermits::default();
    let gate = permits.gate(&project).expect("project gate");
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let _permit = gate.lock().expect("hold project operation permit");
        entered_tx.send(()).expect("signal blocked effect");
        release_rx.recv().expect("release blocked effect");
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("operation permit held");
    let run_id = queue
        .request_stop(&project)
        .expect("persist Stop and cancel");
    assert!(cancel.cancelled());
    assert_eq!(
        queue
            .view()
            .runs
            .into_iter()
            .find(|run| run.id == run_id.as_str())
            .expect("stopped run")
            .state,
        RunState::StopRequested
    );
    release_tx.send(()).expect("release operation");
    worker.join().expect("join operation worker");
    fs::remove_dir_all(root).expect("remove stop fixture");
}
