use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use grok_build_plus_host::{
    PlusGuestFacts, PlusGuestFailure, PlusGuestFailureKind, PlusGuestKind, PlusGuestLifecycle,
    PlusGuestObservation, PlusGuestTarget, PlusSessionStore,
    plus_contained_command_with_security_typed,
};

use crate::backend::{Backend, SharedBackend, snapshot_with_probe};
use crate::queue::RunState;
use crate::runtime::cancel::RuntimeCancelHandle;

fn fixture_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-snapshot-{label}-{}",
        std::process::id()
    ))
}

fn unavailable_guest() -> PlusGuestObservation {
    let detail = "fixture guest probe blocked".to_owned();
    PlusGuestObservation {
        facts: PlusGuestFacts {
            on_linux: false,
            colima_present: true,
            colima_running: false,
            install_root_has_handoff: false,
            runner_present: false,
            helper_present: false,
            harness_cgroup_usable: false,
        },
        lifecycle: PlusGuestLifecycle::GuestDown {
            reasons: vec![detail.clone()],
        },
        target: None,
        failures: vec![PlusGuestFailure {
            kind: PlusGuestFailureKind::RuntimeDown,
            detail,
        }],
    }
}

fn missing_colima() -> PlusGuestObservation {
    let mut observation = unavailable_guest();
    observation.facts.colima_present = false;
    observation.failures[0].kind = PlusGuestFailureKind::RuntimeMissing;
    observation
}

fn ready_guest() -> PlusGuestObservation {
    let target = PlusGuestTarget {
        kind: PlusGuestKind::Remote,
        install_root: "/opt/grok-build".into(),
        runner: "/opt/grok-build/grok-build-runner".into(),
        helper: Some("/opt/grok-build/grok-build".into()),
        colima: Some("/usr/local/bin/colima".into()),
    };
    PlusGuestObservation {
        facts: PlusGuestFacts {
            on_linux: false,
            colima_present: true,
            colima_running: true,
            install_root_has_handoff: true,
            runner_present: true,
            helper_present: true,
            harness_cgroup_usable: true,
        },
        lifecycle: PlusGuestLifecycle::Ready(target.clone()),
        target: Some(target),
        failures: Vec::new(),
    }
}

#[test]
fn stop_intent_is_persisted_and_cancellation_begins_while_guest_probe_is_blocked() {
    let root = fixture_root("stop-during-probe");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let workspace = workspace.canonicalize().expect("canonical workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind project");
    let project = backend.active_project_typed_id().expect("project id");
    let request = backend
        .queue_request("blocked probe stop", true)
        .expect("request");
    let queue = backend.queue.clone();
    let item = queue.enqueue(request).expect("enqueue");
    let cancel = RuntimeCancelHandle::new();
    queue
        .begin_run(&item.id, cancel.clone())
        .expect("begin run");
    let shared: SharedBackend = std::sync::Arc::new(std::sync::Mutex::new(backend));
    let worker_shared = shared.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        snapshot_with_probe(&worker_shared, || {
            entered_tx.send(()).expect("signal blocked probe");
            release_rx.recv().expect("release blocked probe");
            unavailable_guest()
        })
        .expect("present snapshot")
    });

    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("snapshot reached probe");
    assert!(
        shared.try_lock().is_ok(),
        "snapshot probing must not retain the backend lock"
    );
    let run_id = queue
        .request_stop(&project)
        .expect("persist Stop and cancel");
    assert!(
        cancel.cancelled(),
        "cancellation must begin before probe release"
    );
    let run = queue
        .view()
        .runs
        .into_iter()
        .find(|run| run.id == run_id.as_str())
        .expect("stopped run");
    assert_eq!(run.state, RunState::StopRequested);

    release_tx.send(()).expect("release probe");
    let snapshot = worker.join().expect("join snapshot worker");
    assert!(snapshot.snapshot_revision > 0);
    fs::remove_dir_all(root).expect("remove snapshot fixture");
}

#[test]
fn snapshot_revisions_are_monotonic_and_frontend_rejects_older_snapshots() {
    let root = fixture_root("revision");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    let first = backend.snapshot();
    let second = backend.snapshot();
    assert!(second.snapshot_revision > first.snapshot_revision);
    let encoded = serde_json::to_value(second).expect("encode snapshot");
    assert!(encoded.get("snapshotRevision").is_some());
    let frontend = include_str!("../../ui/app.js");
    assert!(frontend.contains("revision < state.snapshotRevision"));
    fs::remove_dir_all(root).expect("remove revision fixture");
}

#[test]
fn command_security_guidance_uses_typed_guest_failure_and_keeps_setup_details_collapsed() {
    let root = fixture_root("command-security-guidance");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .set_command_security_enabled(true)
        .expect("persist enabled preference");
    let snapshot = backend
        .remember_command_security_setup("safe start refused: fixture reason", unavailable_guest())
        .present_current();

    assert_eq!(snapshot.security.kind, "needs-attention");
    assert_eq!(
        snapshot.security.copy,
        "Colima is stopped. Set up the secure command runner."
    );
    assert!(
        snapshot
            .security
            .details
            .contains("fixture guest probe blocked")
    );
    assert!(
        snapshot
            .security
            .details
            .contains("safe start refused: fixture reason")
    );
    fs::remove_dir_all(root).expect("remove guidance fixture");
}

#[test]
fn command_security_progresses_from_container_check_to_install_setup_and_test() {
    let root = fixture_root("command-security-stages");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));

    let initial = backend.snapshot_seed().present_current();
    assert_eq!(initial.security.action, "check");
    assert_eq!(initial.security.action_label, "Check for Container");
    assert_eq!(initial.security.copy, "Adds isolation to agent commands.");
    assert!(!initial.security.action_failed);

    let missing = backend
        .mark_container_checked(missing_colima())
        .present_current();
    assert_eq!(missing.security.action, "install");
    assert_eq!(missing.security.action_label, "Install Colima");

    let stopped = backend
        .mark_container_checked(unavailable_guest())
        .present_current();
    assert_eq!(stopped.security.action, "setup");
    assert_eq!(stopped.security.action_label, "Set up container");

    backend
        .set_command_security_enabled(true)
        .expect("persist Command security preference");
    let ready = backend
        .mark_container_checked(ready_guest())
        .present_current();
    assert_eq!(ready.security.action, "test");
    assert_eq!(ready.security.action_label, "Test contained run");
    assert_eq!(ready.security.kind, "on");

    let mut restored = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    let restored = restored.snapshot_seed().present_current();
    assert_eq!(restored.security.action, "check");
    assert!(!restored.security.checked);
    let failed = backend
        .remember_command_security_failure("fixture install failed", missing_colima())
        .present_current();
    assert!(failed.security.action_failed);
    assert!(failed.security.details.contains("fixture install failed"));
    fs::remove_dir_all(root).expect("remove stages fixture");
}

#[test]
fn bootstrap_and_unrelated_snapshots_never_probe_colima() {
    let root = fixture_root("cached-unchecked-snapshots");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    for _ in 0..32 {
        let snapshot = backend.snapshot_seed().present_current();
        assert!(!snapshot.security.checked);
        assert!(!snapshot.security.can_run_commands);
        assert_eq!(snapshot.security.action, "check");
    }
    fs::remove_dir_all(root).expect("remove cached snapshot fixture");
}

#[test]
fn explicit_command_security_check_performs_one_observation() {
    let root = fixture_root("one-explicit-observation");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .set_command_security_enabled(true)
        .expect("enable command security");
    let checked = backend
        .mark_container_checked(ready_guest())
        .present_current();
    assert!(checked.security.checked);
    assert!(checked.security.can_run_commands);
    for _ in 0..16 {
        assert!(backend.snapshot_seed().present_current().security.checked);
    }
    fs::remove_dir_all(root).expect("remove explicit observation fixture");
}

#[test]
fn contained_execution_revalidates_without_duplicate_snapshot_probe() {
    let root = fixture_root("contained-one-observation");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("create workspace");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .bind_project(&workspace.display().to_string())
        .expect("bind workspace");
    let prepared = backend
        .prepare_security_effect(
            unavailable_guest(),
            crate::events::SecurityEventSurface::Checks,
            "running fixture",
        )
        .expect("persist requested intent");
    let outcome = plus_contained_command_with_security_typed(
        &prepared.bound,
        prepared.preference,
        false,
        &prepared.observation.lifecycle,
    );
    let snapshot = backend
        .finish_security_effect(prepared, outcome, "fixture")
        .expect("persist exact outcome")
        .present_current();
    assert!(snapshot.security.checked);
    assert!(!snapshot.security.can_run_commands);
    fs::remove_dir_all(root).expect("remove contained fixture");
}

#[test]
fn turn_off_persists_before_future_command_refusal() {
    let root = fixture_root("turn-off");
    let mut backend = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    backend
        .set_command_security_enabled(true)
        .expect("enable command security");
    assert!(
        backend
            .mark_container_checked(ready_guest())
            .present_current()
            .security
            .can_run_commands
    );
    backend
        .set_command_security_enabled(false)
        .expect("persist off");
    let snapshot = backend.snapshot_seed().present_current();
    assert!(!snapshot.security.enabled);
    assert!(!snapshot.security.checked);
    assert!(!snapshot.security.can_run_commands);
    let mut restored = Backend::new(PlusSessionStore::from_state_root(root.join("state")));
    assert_eq!(
        restored.snapshot_seed().present_current().security.kind,
        "off"
    );
    fs::remove_dir_all(root).expect("remove turn-off fixture");
}
