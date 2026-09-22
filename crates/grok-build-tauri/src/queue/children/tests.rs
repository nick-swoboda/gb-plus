use super::*;
use crate::queue::executions::tests::fixture;
use crate::queue::{
    Arc, AtomicBool, EnqueueRequest, PLUS_QUEUE_FILE, QueueItem, RunCompletion, fs,
};

fn admission(index: usize, isolated: bool) -> ChildAdmission {
    ChildAdmission {
        workspace: WorkspaceId::new(if isolated {
            format!("isolated-{index}")
        } else {
            "workspace".into()
        }),
        role: PlusChildRole::Worker,
        snapshot: "a".repeat(64),
        isolated,
        invocation: format!("{index:064x}"),
        predecessor: None,
        transient: false,
    }
}

#[test]
fn cancellation_accepts_proven_terminal_children_but_refuses_missing_active_ownership() {
    let (root, queue, parent) = fixture("child-cancel-finish-race");
    let parent = parent.run.id;
    queue.configure_family(&parent, None, 8).unwrap();
    queue.yield_parent(&parent).unwrap();
    let first = queue
        .admit_child(&parent, admission(1, true), RuntimeCancelHandle::new())
        .unwrap();
    assert!(queue.try_acquire_execution(&first.id).unwrap());
    queue.stop_child(&parent, &first.id).unwrap();
    queue
        .finish_child(&parent, &first.id, ChildState::Stopped)
        .unwrap();
    // A snapshot selected this child while active, but it finished before the
    // cancellation registry was acquired. The retained terminal record proves it.
    queue
        .cancel_run_ids(std::slice::from_ref(&first.id))
        .unwrap();
    let second = queue
        .admit_child(&parent, admission(2, true), RuntimeCancelHandle::new())
        .unwrap();
    let cancel = queue.cancels.lock().unwrap().remove(&second.id).unwrap();
    assert!(
        queue
            .cancel_run_ids(std::slice::from_ref(&second.id))
            .is_err()
    );
    queue
        .cancels
        .lock()
        .unwrap()
        .insert(second.id.clone(), cancel);
    assert!(queue.cancel_run_ids(&[RunId::new("unknown")]).is_err());
    queue.stop_child(&parent, &second.id).unwrap();
    queue
        .finish_child(&parent, &second.id, ChildState::Stopped)
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

fn add_root(queue: &QueueCoordinator, project: &str) -> QueueItem {
    queue
        .enqueue(EnqueueRequest {
            project_id: ProjectId::new(project),
            workspace_id: WorkspaceId::new(format!("workspace-{project}")),
            workspace_root: format!("/tmp/{project}"),
            session_id: SessionId::new(format!("session-{project}")),
            transport: RuntimeTransport::GrokCliAcp,
            prompt: "fixture".into(),
            auto_start: true,
            retry_of_run_id: None,
            predecessor_run_id: None,
        })
        .unwrap()
}

#[test]
fn two_children_hold_exactly_two_leases_and_parent_cannot_escape_family_cleanup() {
    let (root, queue, parent) = fixture("two-children");
    let parent = parent.run.id;
    queue.configure_family(&parent, None, 8).unwrap();
    assert!(
        queue
            .admit_child(&parent, admission(1, true), RuntimeCancelHandle::new())
            .is_err()
    );
    queue.yield_parent(&parent).unwrap();
    let first = queue
        .admit_child(&parent, admission(1, true), RuntimeCancelHandle::new())
        .unwrap();
    let second = queue
        .admit_child(&parent, admission(2, true), RuntimeCancelHandle::new())
        .unwrap();
    assert!(!queue.try_acquire_execution(&second.id).unwrap());
    assert!(queue.try_acquire_execution(&first.id).unwrap());
    assert!(queue.try_acquire_execution(&second.id).unwrap());
    queue.request_parent_resume(&parent).unwrap();
    assert!(!queue.try_acquire_execution(&parent).unwrap());
    assert!(queue.complete_run(&parent, RunCompletion::Done).is_err());
    assert_eq!(queue.read(|book| Ok(book.executions.held())).unwrap(), 2);
    assert!(
        queue
            .finish_child(&RunId::new("foreign"), &first.id, ChildState::Done)
            .is_err()
    );
    queue
        .finish_child(&parent, &first.id, ChildState::NeedsReview)
        .unwrap();
    assert!(queue.try_acquire_execution(&parent).unwrap());
    assert!(queue.complete_run(&parent, RunCompletion::Done).is_err());
    queue
        .finish_child(&parent, &second.id, ChildState::Done)
        .unwrap();
    queue
        .complete_run(&parent, RunCompletion::NeedsReview)
        .unwrap();
    assert_eq!(queue.child_records(&parent).unwrap().len(), 2);
    assert_eq!(queue.view().active_global_runs, 0);
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nonisolated_children_serialize_and_parent_waits_for_their_slot() {
    let (root, queue, parent) = fixture("serial-children");
    let parent = parent.run.id;
    queue.configure_family(&parent, None, 8).unwrap();
    queue.yield_parent(&parent).unwrap();
    let first = queue
        .admit_child(&parent, admission(1, false), RuntimeCancelHandle::new())
        .unwrap();
    let second = queue
        .admit_child(&parent, admission(2, false), RuntimeCancelHandle::new())
        .unwrap();
    assert!(queue.try_acquire_execution(&first.id).unwrap());
    assert!(!queue.try_acquire_execution(&second.id).unwrap());
    queue.request_parent_resume(&parent).unwrap();
    assert!(!queue.try_acquire_execution(&parent).unwrap());
    queue
        .finish_child(&parent, &first.id, ChildState::Done)
        .unwrap();
    assert!(queue.try_acquire_execution(&second.id).unwrap());
    assert!(!queue.try_acquire_execution(&parent).unwrap());
    queue
        .finish_child(&parent, &second.id, ChildState::Done)
        .unwrap();
    assert!(queue.try_acquire_execution(&parent).unwrap());
    queue.complete_run(&parent, RunCompletion::Done).unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_fifo_honors_eligible_roots_without_deadlocking_two_existing_families() {
    let (root, queue, parent) = fixture("child-fairness");
    let parent = parent.run.id;
    queue.configure_family(&parent, None, 8).unwrap();
    queue.yield_parent(&parent).unwrap();
    let earlier = add_root(&queue, "earlier");
    let child = queue
        .admit_child(&parent, admission(1, true), RuntimeCancelHandle::new())
        .unwrap();
    let later = add_root(&queue, "later");
    assert!(!queue.try_acquire_execution(&child.id).unwrap());
    assert_eq!(queue.candidates(None, false).unwrap()[0].id, earlier.id);
    assert!(
        queue
            .begin_run(&later.id, RuntimeCancelHandle::new())
            .is_err()
    );
    let second_root = queue
        .begin_run(&earlier.id, RuntimeCancelHandle::new())
        .unwrap();
    assert!(queue.try_acquire_execution(&child.id).unwrap());
    queue
        .finish_child(&parent, &child.id, ChildState::Done)
        .unwrap();
    queue.request_parent_resume(&parent).unwrap();
    // The third root is older than this continuation, but cannot add a third family.
    assert!(queue.try_acquire_execution(&parent).unwrap());
    queue.complete_run(&parent, RunCompletion::Done).unwrap();
    queue
        .complete_run(&second_root.run.id, RunCompletion::Done)
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parent_stop_reaches_every_child_and_preserves_unproven_cleanup() {
    let (root, queue, parent) = fixture("child-stop");
    queue.configure_family(&parent.run.id, None, 8).unwrap();
    queue.yield_parent(&parent.run.id).unwrap();
    let proof = Arc::new(AtomicBool::new(false));
    let first_cancel = RuntimeCancelHandle::new();
    first_cancel
        .retain_hook_cleanup_fixture(proof.clone())
        .unwrap();
    let second_cancel = RuntimeCancelHandle::new();
    let first = queue
        .admit_child(&parent.run.id, admission(1, true), first_cancel.clone())
        .unwrap();
    let second = queue
        .admit_child(&parent.run.id, admission(2, true), second_cancel.clone())
        .unwrap();
    assert!(queue.try_acquire_execution(&first.id).unwrap());
    queue.request_stop(&parent.run.project_id).unwrap();
    assert!(first_cancel.cancelled() && second_cancel.cancelled());
    assert!(queue.try_acquire_execution(&second.id).is_err());
    assert!(
        queue
            .admit_child(
                &parent.run.id,
                admission(3, true),
                RuntimeCancelHandle::new()
            )
            .is_err()
    );
    assert!(
        queue
            .finish_child(&parent.run.id, &first.id, ChildState::Stopped)
            .is_err()
    );
    assert!(
        queue
            .complete_run(&parent.run.id, RunCompletion::Stopped("stopped".into()))
            .is_err()
    );
    proof.store(true, Ordering::Release);
    queue
        .finish_child(&parent.run.id, &first.id, ChildState::Stopped)
        .unwrap();
    queue
        .finish_child(&parent.run.id, &second.id, ChildState::Stopped)
        .unwrap();
    queue
        .complete_run(&parent.run.id, RunCompletion::Stopped("stopped".into()))
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn child_restart_has_no_authority_or_automatic_reexecution() {
    let (root, queue, parent) = fixture("child-restart");
    queue.configure_family(&parent.run.id, None, 8).unwrap();
    queue.yield_parent(&parent.run.id).unwrap();
    let mut input = admission(1, true);
    input.transient = true;
    let child = queue
        .admit_child(&parent.run.id, input, RuntimeCancelHandle::new())
        .unwrap();
    assert!(queue.try_acquire_execution(&child.id).unwrap());
    drop(queue);
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(
        queue.child_records(&parent.run.id).unwrap()[0].state,
        ChildState::Interrupted
    );
    assert_eq!(queue.view().runs[0].state, RunState::Interrupted);
    assert!(queue.candidates(None, false).unwrap().is_empty());
    assert!(queue.try_acquire_execution(&child.id).is_err());
    assert!(queue.read(|book| Ok(book.executions.is_empty())).unwrap());
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn continuations_consume_one_budget_and_refuse_duplicate_effects_or_binding_drift() {
    let (root, queue, parent) = fixture("child-budget");
    let parent = parent.run.id;
    queue.configure_family(&parent, None, 8).unwrap();
    queue.yield_parent(&parent).unwrap();
    let mut previous: Option<ChildRecord> = None;
    for index in 1..=8 {
        let mut input = admission(index, true);
        input.workspace = WorkspaceId::new("one-isolation");
        input.predecessor = previous.as_ref().map(|child| child.id.clone());
        let child = queue
            .admit_child(&parent, input, RuntimeCancelHandle::new())
            .unwrap();
        if let Some(previous) = &previous {
            assert_eq!(previous.agent_id, child.agent_id);
            assert_eq!(previous.session, child.session);
        }
        assert!(queue.try_acquire_execution(&child.id).unwrap());
        queue
            .finish_child(&parent, &child.id, ChildState::Done)
            .unwrap();
        previous = Some(child);
    }
    assert!(
        queue
            .admit_child(&parent, admission(9, true), RuntimeCancelHandle::new())
            .is_err()
    );
    assert!(
        queue
            .admit_child(&parent, admission(1, true), RuntimeCancelHandle::new())
            .is_err()
    );
    assert_eq!(queue.child_records(&parent).unwrap().len(), 8);
    queue.request_parent_resume(&parent).unwrap();
    assert!(queue.try_acquire_execution(&parent).unwrap());
    queue.complete_run(&parent, RunCompletion::Done).unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn child_save_cut_rolls_back_admission_and_keeps_cleanup_owner_on_completion() {
    let (root, queue, parent) = fixture("child-save-cut");
    queue.configure_family(&parent.run.id, None, 8).unwrap();
    queue.yield_parent(&parent.run.id).unwrap();
    let path = root.join(PLUS_QUEUE_FILE);
    let saved = root.join("saved-fixture.json");
    fs::rename(&path, &saved).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        queue
            .admit_child(
                &parent.run.id,
                admission(1, true),
                RuntimeCancelHandle::new()
            )
            .is_err()
    );
    assert!(queue.child_records(&parent.run.id).unwrap().is_empty());
    fs::remove_dir(&path).unwrap();
    fs::rename(&saved, &path).unwrap();
    let child = queue
        .admit_child(
            &parent.run.id,
            admission(1, true),
            RuntimeCancelHandle::new(),
        )
        .unwrap();
    assert!(queue.try_acquire_execution(&child.id).unwrap());
    fs::rename(&path, &saved).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        queue
            .finish_child(&parent.run.id, &child.id, ChildState::Done)
            .is_err()
    );
    assert!(queue.cancels.lock().unwrap().contains_key(&child.id));
    assert_eq!(queue.read(|book| Ok(book.executions.held())).unwrap(), 1);
    fs::remove_dir(&path).unwrap();
    fs::rename(&saved, &path).unwrap();
    queue
        .finish_child(&parent.run.id, &child.id, ChildState::Done)
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn v7_migration_preserves_original_and_rejects_smuggled_child_authority() {
    for forged in [false, true] {
        let (root, queue, parent) = fixture(if forged {
            "v7-forged-child"
        } else {
            "v7-child-migration"
        });
        if forged {
            queue.configure_family(&parent.run.id, None, 8).unwrap();
            queue.yield_parent(&parent.run.id).unwrap();
            queue
                .admit_child(
                    &parent.run.id,
                    admission(1, true),
                    RuntimeCancelHandle::new(),
                )
                .unwrap();
        }
        drop(queue);
        let path = root.join(PLUS_QUEUE_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schemaVersion"] = serde_json::json!(7);
        if !forged {
            value.as_object_mut().unwrap().remove("children");
        }
        let bytes = serde_json::to_vec_pretty(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let queue = QueueCoordinator::open(root.clone());
        assert_eq!(queue.view().available, !forged, "{}", queue.view().status);
        if forged {
            assert_eq!(fs::read(&path).unwrap(), bytes);
        } else {
            assert_eq!(
                fs::read(root.join("plus-queue.before-v8.json")).unwrap(),
                bytes
            );
        }
        drop(queue);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn live_child_messages_reserve_the_same_eight_invocation_budget() {
    let (root, queue, parent) = fixture("message-budget");
    queue.configure_family(&parent.run.id, None, 8).unwrap();
    queue.yield_parent(&parent.run.id).unwrap();
    let child = queue
        .admit_child(
            &parent.run.id,
            admission(1, true),
            RuntimeCancelHandle::new(),
        )
        .unwrap();
    for _ in 0..7 {
        assert!(
            queue
                .reserve_child_message(&parent.run.id, &child.id, false)
                .unwrap()
        );
    }
    assert!(
        queue
            .reserve_child_message(&parent.run.id, &child.id, false)
            .is_err()
    );
    assert!(
        queue
            .admit_child(
                &parent.run.id,
                admission(2, true),
                RuntimeCancelHandle::new()
            )
            .is_err()
    );
    queue.stop_child(&parent.run.id, &child.id).unwrap();
    assert!(
        queue
            .reserve_child_message(&parent.run.id, &child.id, false)
            .is_err()
    );
    queue
        .finish_child(&parent.run.id, &child.id, ChildState::Stopped)
        .unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}
