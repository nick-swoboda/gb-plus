//! Queue durability and scheduler regression tests.

use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use super::*;

#[test]
fn workflow_root_can_finish_but_cannot_be_replayed_as_chat_or_steered() {
    let root = root("workflow-kind");
    let queue = QueueCoordinator::open(root.clone());
    let ticket = workflows::WorkflowTicket {
        job_id: "a".repeat(64),
        attempt: 1,
    };
    let item = queue
        .enqueue_workflow(request("p1", 1), ticket.clone())
        .unwrap();
    assert!(queue.enqueue_workflow(request("p1", 2), ticket).is_err());
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    queue
        .configure_family(&run.id, Some("workflow".into()), 32)
        .unwrap();
    assert!(
        queue
            .enqueue_steer(
                &run.project_id,
                &run.session_id,
                &run.id,
                "must not become script input"
            )
            .is_err()
    );
    queue.complete_run(&run.id, RunCompletion::Done).unwrap();
    let next = queue
        .enqueue_workflow(
            request("p1", 3),
            workflows::WorkflowTicket {
                job_id: "b".repeat(64),
                attempt: 1,
            },
        )
        .unwrap();
    let failed = queue
        .begin_run(&next.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    queue
        .complete_run(&failed.id, RunCompletion::Failed("fixture".into()))
        .unwrap();
    assert!(
        queue
            .retry(&failed.id)
            .unwrap_err()
            .contains("explicit Resume")
    );
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn stale_workflow_stop_cannot_cancel_a_later_chat_in_the_same_project() {
    let root = root("workflow-stop");
    let queue = QueueCoordinator::open(root.clone());
    let project = ProjectId::new("p1");
    let ticket = workflows::WorkflowTicket {
        job_id: "c".repeat(64),
        attempt: 1,
    };
    let item = queue
        .enqueue_workflow(request("p1", 1), ticket.clone())
        .unwrap();
    let cancelled = RuntimeCancelHandle::new();
    let run = queue.begin_run(&item.id, cancelled.clone()).unwrap().run;
    assert!(
        queue
            .stop_workflow(
                &project,
                &workflows::WorkflowTicket {
                    job_id: ticket.job_id.clone(),
                    attempt: 2
                },
                &run.id
            )
            .is_err()
    );
    assert!(!cancelled.cancelled());
    queue.stop_workflow(&project, &ticket, &run.id).unwrap();
    assert!(cancelled.cancelled());
    queue
        .complete_run(&run.id, RunCompletion::Stopped("fixture".into()))
        .unwrap();
    let item = queue.enqueue(request("p1", 2)).unwrap();
    let current = RuntimeCancelHandle::new();
    let new = queue.begin_run(&item.id, current.clone()).unwrap().run;
    assert!(queue.stop_workflow(&project, &ticket, &run.id).is_err());
    assert!(!current.cancelled());
    queue.complete_run(&new.id, RunCompletion::Done).unwrap();
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn queue_v8_children_migrate_with_exact_backup_and_no_automatic_execution() {
    let root = root("workflow-migration");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    queue.configure_family(&run.id, None, 8).unwrap();
    queue.yield_parent(&run.id).unwrap();
    queue
        .admit_child(
            &run.id,
            children::ChildAdmission {
                workspace: WorkspaceId::new("captured-child"),
                role: grok_build_plus_host::PlusChildRole::Explore,
                snapshot: "a".repeat(64),
                isolated: true,
                invocation: "b".repeat(64),
                predecessor: None,
                transient: false,
            },
            RuntimeCancelHandle::new(),
        )
        .unwrap();
    drop(queue);
    let file = root.join(PLUS_QUEUE_FILE);
    let mut old: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    old["schemaVersion"] = serde_json::json!(8);
    let bytes = serde_json::to_vec(&old).unwrap();
    fs::write(&file, &bytes).unwrap();
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(queue.view().active_global_runs, 0);
    assert_eq!(
        queue.view().children[0].state,
        children::ChildState::Interrupted
    );
    assert_eq!(
        fs::read(root.join("plus-queue.before-v9.json")).unwrap(),
        bytes
    );
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-queue-{label}-{}-{}",
        std::process::id(),
        unix_time_millis()
    ))
}

fn request(project: &str, sequence: u64) -> EnqueueRequest {
    EnqueueRequest {
        project_id: ProjectId::new(project),
        workspace_id: WorkspaceId::new(format!("workspace-{project}")),
        workspace_root: format!("/tmp/{project}"),
        session_id: SessionId::new(format!("session-{project}")),
        transport: RuntimeTransport::GrokCliAcp,
        prompt: format!("prompt {sequence} for {project}"),
        auto_start: true,
        retry_of_run_id: None,
        predecessor_run_id: None,
    }
}

#[test]
fn model_and_connection_probes_hold_scheduler_and_refuse_active_or_suspended_work() {
    let root = root("probe-reservation");
    let queue = QueueCoordinator::open(root.clone());
    let guard = queue.lock_idle_scheduler().unwrap();
    assert!(queue.scheduler.try_lock().is_err());
    drop(guard);
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap();
    assert!(queue.lock_idle_scheduler().is_err());
    queue
        .complete_run(&run.run.id, RunCompletion::Failed("fixture stopped".into()))
        .unwrap();
    queue.set_lifecycle_suspended(true);
    assert!(queue.lock_idle_scheduler().is_err());
    queue.set_lifecycle_suspended(false);
    drop(queue.lock_idle_scheduler().unwrap());
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn terminal_delivery_keeps_cancellation_and_capacity_until_owned_cli_is_reaped() {
    let root = root("cleanup-reservation");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let cancel = RuntimeCancelHandle::new();
    let mut command = std::process::Command::new("/bin/sleep");
    command.arg("10");
    let mut child = crate::bounded_process::OwnedProcess::spawn(&mut command).unwrap();
    cancel
        .retain_cleanup(child.cleanup_proof().unwrap())
        .unwrap();
    let run = queue.begin_run(&item.id, cancel.clone()).unwrap();
    assert!(!queue.run_cleanup_proven(&run.run.id));
    assert!(
        queue
            .complete_run(&run.run.id, RunCompletion::Done)
            .is_err()
    );
    assert_eq!(queue.view().active_global_runs, 1);
    assert!(queue.cancels.lock().unwrap().contains_key(&run.run.id));
    assert!(queue.lock_idle_scheduler().is_err());
    child.stop().unwrap();
    assert!(queue.run_cleanup_proven(&run.run.id));
    queue
        .complete_run(&run.run.id, RunCompletion::Done)
        .unwrap();
    assert_eq!(queue.view().active_global_runs, 0);
    assert!(cancel.cleanup_proven());
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_terminal_persistence_keeps_the_exact_cancel_handle_for_recovery() {
    let root = root("terminal-save-failure");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let cancel = RuntimeCancelHandle::new();
    let run = queue.begin_run(&item.id, cancel.clone()).unwrap();
    let target = root.join(PLUS_QUEUE_FILE);
    let backup = root.join("fixture-original-queue.json");
    fs::rename(&target, &backup).unwrap();
    fs::create_dir(&target).unwrap();
    assert!(
        queue
            .complete_run(&run.run.id, RunCompletion::Done)
            .is_err()
    );
    assert_eq!(queue.view().active_global_runs, 1);
    assert!(queue.cancels.lock().unwrap().contains_key(&run.run.id));
    fs::remove_dir(target).unwrap();
    fs::rename(backup, root.join(PLUS_QUEUE_FILE)).unwrap();
    assert_eq!(queue.request_stop(&run.run.project_id).unwrap(), run.run.id);
    assert!(cancel.cancelled());
    queue
        .complete_run(
            &run.run.id,
            RunCompletion::Stopped("fixture stopped".into()),
        )
        .unwrap();
    assert_eq!(queue.view().active_global_runs, 0);
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn send_now_is_bound_to_the_exact_run_and_consumed_once() {
    let root = root("send-now");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin");
    let intent = queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "Use the compact layout.",
        )
        .expect("steer");
    let repeated = queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "Use the compact layout.",
        )
        .expect("repeated steer");
    queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "Then keep the controls compact.",
        )
        .expect("ordered steer");
    assert_eq!(intent.state, SteerIntentState::Pending);
    assert_ne!(intent.id, repeated.id);
    let consumed = queue.submit_pending_steers(&begun.run.id).expect("consume");
    assert_eq!(
        consumed
            .iter()
            .map(|intent| intent.message.as_str())
            .collect::<Vec<_>>(),
        vec![
            "Use the compact layout.",
            "Use the compact layout.",
            "Then keep the controls compact.",
        ]
    );
    assert!(
        queue
            .submit_pending_steers(&begun.run.id)
            .expect("consume once")
            .is_empty()
    );
    let wrong = queue
        .enqueue_steer(
            &ProjectId::new("other"),
            &begun.run.session_id,
            &begun.run.id,
            "wrong project",
        )
        .expect_err("identity drift");
    assert!(wrong.contains("identity changed"));
    queue
        .complete_run(&begun.run.id, RunCompletion::Done)
        .expect("complete");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn waiting_message_moves_atomically_to_the_exact_active_run() {
    let root = root("queued-to-steer");
    let queue = QueueCoordinator::open(root.clone());
    let active = queue.enqueue(request("p1", 1)).expect("enqueue active");
    let begun = queue
        .begin_run(&active.id, RuntimeCancelHandle::new())
        .expect("begin active");
    let waiting = queue.enqueue(request("p1", 2)).expect("enqueue waiting");
    let unrelated = queue.enqueue(request("p2", 3)).expect("enqueue unrelated");

    let drift = queue
        .steer_queued_item(
            &waiting.id,
            &ProjectId::new("wrong-project"),
            &begun.run.session_id,
            &begun.run.id,
        )
        .expect_err("project drift must refuse");
    assert!(drift.contains("active run identity changed"));
    assert!(
        queue
            .view()
            .items
            .iter()
            .any(|item| item.id == waiting.id.as_str())
    );

    let crossed = queue
        .steer_queued_item(
            &unrelated.id,
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
        )
        .expect_err("cross-project item must refuse");
    assert!(crossed.contains("message and run identities differ"));
    assert!(
        queue
            .view()
            .items
            .iter()
            .any(|item| item.id == unrelated.id.as_str())
    );

    let intent = queue
        .steer_queued_item(
            &waiting.id,
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
        )
        .expect("atomically steer waiting message");
    assert_eq!(intent.message, waiting.prompt);
    assert_eq!(intent.ordinal, waiting.ordinal);
    assert_eq!(intent.run_id, begun.run.id);
    let view = queue.view();
    assert!(
        !view.items.iter().any(|item| item.id == waiting.id.as_str()),
        "the same message cannot remain both waiting and steering"
    );
    assert!(view.steering.iter().any(|candidate| {
        candidate.id == intent.id.as_str()
            && candidate.state == SteerIntentState::Pending
            && candidate.ordinal == waiting.ordinal
    }));

    let promoted = queue
        .complete_run(&begun.run.id, RunCompletion::Done)
        .expect("finish before steering is consumed");
    assert_eq!(promoted.len(), 1);
    assert_eq!(promoted[0].item.prompt, waiting.prompt);
    assert_eq!(promoted[0].item.ordinal, waiting.ordinal);
    assert_eq!(
        promoted[0].item.predecessor_run_id.as_ref(),
        Some(&begun.run.id),
        "a late confirmation must become the exact next turn without loss"
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn uncertain_submissions_are_never_promoted_or_replayed_after_restart() {
    let root = root("uncertain-delivery");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    let submitted = queue
        .enqueue_steer(
            &run.project_id,
            &run.session_id,
            &run.id,
            "Run exactly once.",
        )
        .unwrap();
    assert_eq!(
        queue.submit_pending_steers(&run.id).unwrap()[0].state,
        SteerIntentState::Submitted
    );
    assert!(
        queue
            .record_steer_delivery(
                &RunId::new("foreign"),
                &submitted.id,
                SteerIntentState::AcknowledgedByCli
            )
            .is_err()
    );
    queue
        .record_steer_delivery(&run.id, &submitted.id, SteerIntentState::AcknowledgedByCli)
        .unwrap();
    queue
        .record_steer_delivery(&run.id, &submitted.id, SteerIntentState::AcknowledgedByCli)
        .unwrap();
    assert!(
        queue
            .record_steer_delivery(&run.id, &submitted.id, SteerIntentState::Pending)
            .is_err()
    );
    let unsent = queue
        .enqueue_steer(&run.project_id, &run.session_id, &run.id, "Still unsent.")
        .unwrap();
    drop(queue);
    let recovered = QueueCoordinator::open(root.clone());
    let view = recovered.view();
    assert!(view.available, "{}", view.status);
    assert_eq!(
        view.steering
            .iter()
            .find(|row| row.id == submitted.id.as_str())
            .unwrap()
            .state,
        SteerIntentState::Uncertain
    );
    assert_eq!(
        view.steering
            .iter()
            .find(|row| row.id == unsent.id.as_str())
            .unwrap()
            .state,
        SteerIntentState::PromotedToNext
    );
    assert_eq!(
        view.items
            .iter()
            .filter(|row| row.prompt == "Run exactly once.")
            .count(),
        0
    );
    assert_eq!(
        view.items
            .iter()
            .filter(|row| row.prompt == "Still unsent.")
            .count(),
        1
    );
    drop(recovered);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_consumed_is_backed_up_and_migrated_to_uncertain() {
    let root = root("delivery-migration");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).unwrap();
    let run = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .unwrap()
        .run;
    queue
        .enqueue_steer(
            &run.project_id,
            &run.session_id,
            &run.id,
            "Legacy delivery.",
        )
        .unwrap();
    drop(queue);
    let path = root.join(PLUS_QUEUE_FILE);
    let mut legacy: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    legacy["schemaVersion"] = serde_json::json!(5);
    legacy.as_object_mut().unwrap().remove("executions");
    legacy["steerIntents"][0]["state"] = serde_json::json!("consumed");
    let original = serde_json::to_vec(&legacy).unwrap();
    fs::write(&path, &original).unwrap();
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available, "{}", queue.view().status);
    assert_eq!(queue.view().steering[0].state, SteerIntentState::Uncertain);
    assert_eq!(
        fs::read(root.join("plus-queue.before-v6.json")).unwrap(),
        original
    );
    drop(queue);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_promoted_message_can_be_steered_again_without_duplicate_order() {
    let root = root("resteer-promoted");
    let queue = QueueCoordinator::open(root.clone());
    let first = queue.enqueue(request("p1", 1)).expect("enqueue first");
    let first_run = queue
        .begin_run(&first.id, RuntimeCancelHandle::new())
        .expect("begin first");
    let original = queue
        .enqueue_steer(
            &first_run.run.project_id,
            &first_run.run.session_id,
            &first_run.run.id,
            "preserve this message",
        )
        .expect("first steer");
    let promoted = queue
        .complete_run(&first_run.run.id, RunCompletion::Done)
        .expect("promote first steer");
    let newer = queue.enqueue(request("p1", 4)).expect("enqueue newer run");
    let newer_run = queue
        .begin_run(&newer.id, RuntimeCancelHandle::new())
        .expect("begin newer run");
    let resteered = queue
        .steer_queued_item(
            &promoted[0].item.id,
            &newer_run.run.project_id,
            &newer_run.run.session_id,
            &newer_run.run.id,
        )
        .expect("re-steer a previously promoted message");
    assert_eq!(resteered.ordinal, original.ordinal);
    let resteered_view = queue.view();
    assert!(
        !resteered_view
            .steering
            .iter()
            .any(|candidate| candidate.id == original.id.as_str()),
        "the superseded promotion must not retain the same durable order"
    );
    assert!(resteered_view.steering.iter().any(|candidate| {
        candidate.id == resteered.id.as_str() && candidate.state == SteerIntentState::Pending
    }));
    let repromoted = queue
        .complete_run(&newer_run.run.id, RunCompletion::Done)
        .expect("promote re-steered message");
    assert_eq!(repromoted.len(), 1);
    assert_eq!(repromoted[0].item.ordinal, original.ordinal);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn late_send_now_becomes_the_next_turn_and_send_next_waits_for_predecessor() {
    let root = root("late-steer");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin");
    queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "late guidance",
        )
        .expect("steer");
    let mut explicit = request("p1", 2);
    explicit.prompt = "send next".into();
    let explicit = queue
        .enqueue_send_next(explicit, &begun.run.id)
        .expect("send next");
    assert!(queue.candidates(None, false).expect("blocked").is_empty());

    let promoted = queue
        .complete_run(&begun.run.id, RunCompletion::Done)
        .expect("complete");
    assert_eq!(promoted.len(), 1);
    assert_eq!(promoted[0].item.prompt, "late guidance");
    let candidates = queue.candidates(None, false).expect("candidates");
    assert_eq!(candidates.len(), 1, "one project still serializes");
    assert_eq!(
        candidates[0].id, promoted[0].item.id,
        "the earlier Send now must stay ahead of the later Send next"
    );
    let promoted_run = queue
        .begin_run(&promoted[0].item.id, RuntimeCancelHandle::new())
        .expect("start promoted steer");
    assert!(
        queue
            .candidates(None, false)
            .expect("serialized")
            .is_empty()
    );
    queue
        .complete_run(&promoted_run.run.id, RunCompletion::Done)
        .expect("finish promoted steer");
    let after_promoted = queue.candidates(None, false).expect("explicit next");
    assert_eq!(after_promoted[0].id, explicit.id);
    let view = queue.view();
    assert!(view.steering.iter().any(|steer| {
        steer.id == promoted[0].intent_id.as_str()
            && steer.state == SteerIntentState::PromotedToNext
    }));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn send_next_waits_for_predecessor_review_resolution_and_global_capacity() {
    let root = root("send-next-gates");
    let queue = QueueCoordinator::open(root.clone());
    let first = queue.enqueue(request("p1", 1)).expect("first");
    let second = queue.enqueue(request("p2", 2)).expect("second");
    let first_run = queue
        .begin_run(&first.id, RuntimeCancelHandle::new())
        .expect("first run");
    let second_run = queue
        .begin_run(&second.id, RuntimeCancelHandle::new())
        .expect("second run");
    let mut next_request = request("p1", 3);
    next_request.prompt = "after predecessor".into();
    let next = queue
        .enqueue_send_next(next_request, &first_run.run.id)
        .expect("send next");
    assert!(queue.candidates(None, false).expect("full").is_empty());

    queue
        .set_review_blocked(&ProjectId::new("p1"), true)
        .expect("review gate");
    queue
        .complete_run(&first_run.run.id, RunCompletion::NeedsReview)
        .expect("predecessor terminal");
    assert!(
        queue
            .candidates(Some(&ProjectId::new("p1")), false)
            .expect("review candidates")
            .is_empty()
    );

    let third = queue.enqueue(request("p3", 4)).expect("third");
    let third_candidate = queue.candidates(None, false).expect("third candidate");
    assert_eq!(third_candidate[0].id, third.id);
    let third_run = queue
        .begin_run(&third.id, RuntimeCancelHandle::new())
        .expect("third run");
    queue
        .set_review_blocked(&ProjectId::new("p1"), false)
        .expect("release review");
    assert!(
        queue
            .candidates(None, false)
            .expect("still full")
            .is_empty()
    );

    queue
        .complete_run(&second_run.run.id, RunCompletion::Done)
        .expect("free capacity");
    let candidates = queue.candidates(None, false).expect("next eligible");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, next.id);
    queue
        .complete_run(&third_run.run.id, RunCompletion::Done)
        .expect("finish third");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn restart_promotes_unconsumed_steering_without_replaying_the_interrupted_run() {
    let root = root("steer-restart");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin");
    queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "survive as next",
        )
        .expect("steer");
    drop(queue);

    let reopened = QueueCoordinator::open(root.clone());
    let view = reopened.view();
    assert!(view.items.iter().any(|item| {
        item.state == QueueItemState::Interrupted && item.id == begun.item.id.as_str()
    }));
    assert!(view.items.iter().any(|item| {
        item.state == QueueItemState::Queued
            && item.prompt == "survive as next"
            && item.predecessor_run_id.as_deref() == Some(begun.run.id.as_str())
    }));
    assert_eq!(
        view.items
            .iter()
            .filter(|item| item.state == QueueItemState::Running)
            .count(),
        0
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn pending_agent_proposal_blocks_only_its_project_queue_until_resolved() {
    let root = root("review-project-gate");
    let queue = QueueCoordinator::open(root.clone());
    let project_a = ProjectId::new("project-a");
    let project_b = ProjectId::new("project-b");
    let item_a = queue.enqueue(request("project-a", 1)).expect("queue A");
    let item_b = queue.enqueue(request("project-b", 2)).expect("queue B");
    queue.set_review_blocked(&project_a, true).expect("block A");
    let candidates = queue.candidates(None, true).expect("candidates");
    assert_eq!(
        candidates.iter().map(|item| &item.id).collect::<Vec<_>>(),
        vec![&item_b.id],
        "another project must remain eligible"
    );
    let refused = queue
        .begin_run(&item_a.id, RuntimeCancelHandle::new())
        .expect_err("final transition must also refuse the blocked project");
    assert!(refused.contains("waiting for every Agent change"));
    queue
        .set_review_blocked(&project_a, false)
        .expect("resolve A");
    let candidates = queue
        .candidates(Some(&project_a), true)
        .expect("A eligible");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, item_a.id);
    assert!(
        !queue
            .view()
            .review_blocked_project_ids
            .contains(&project_a.as_str().to_owned())
    );
    assert!(
        !queue
            .view()
            .review_blocked_project_ids
            .contains(&project_b.as_str().to_owned())
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn scheduler_enforces_two_global_and_one_per_project_in_oldest_order() {
    let root = root("scheduler");
    let queue = QueueCoordinator::open(root.clone());
    let p1a = queue.enqueue(request("p1", 1)).expect("enqueue p1a");
    let p1b = queue.enqueue(request("p1", 2)).expect("enqueue p1b");
    let p2 = queue.enqueue(request("p2", 3)).expect("enqueue p2");
    let p3 = queue.enqueue(request("p3", 4)).expect("enqueue p3");

    let candidates = queue.candidates(None, false).expect("initial candidates");
    assert_eq!(
        candidates
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec![p1a.id.as_str(), p2.id.as_str()]
    );
    let run1 = queue
        .begin_run(&p1a.id, RuntimeCancelHandle::new())
        .expect("start p1");
    let run2 = queue
        .begin_run(&p2.id, RuntimeCancelHandle::new())
        .expect("start p2");
    assert!(queue.begin_run(&p3.id, RuntimeCancelHandle::new()).is_err());
    assert!(
        queue
            .begin_run(&p1b.id, RuntimeCancelHandle::new())
            .is_err()
    );
    assert!(
        queue
            .candidates(None, false)
            .expect("full candidates")
            .is_empty()
    );

    queue
        .complete_run(&run1.run.id, RunCompletion::Done)
        .expect("finish p1");
    let candidates = queue.candidates(None, false).expect("next candidates");
    assert_eq!(candidates[0].id, p1b.id);
    queue
        .set_paused(&ProjectId::new("p1"), true)
        .expect("pause p1");
    let candidates = queue.candidates(None, false).expect("paused candidates");
    assert_eq!(candidates[0].id, p3.id);
    queue
        .complete_run(&run2.run.id, RunCompletion::Done)
        .expect("finish p2");
    fs::remove_dir_all(root).expect("remove scheduler fixture");
}

#[test]
fn queue_view_keeps_the_run_for_every_newest_board_item() {
    let mut book = QueueBook::default();
    for ordinal in 1_u64..=201 {
        let active = ordinal == 1;
        let item = QueueItem {
            id: QueueItemId::new(format!("queue-terminal-{ordinal}")),
            project_id: ProjectId::new(format!("project-{ordinal}")),
            workspace_id: WorkspaceId::new(format!("workspace-{ordinal}")),
            workspace_root: format!("/tmp/project-{ordinal}"),
            session_id: SessionId::new(format!("session-{ordinal}")),
            transport: RuntimeTransport::GrokCliAcp,
            workflow: None,
            prompt: format!("terminal prompt {ordinal}"),
            auto_start: true,
            state: if active {
                QueueItemState::Running
            } else {
                QueueItemState::Done
            },
            enqueued_at_unix_ms: ordinal,
            ordinal,
            retry_of_run_id: None,
            predecessor_run_id: None,
            blocked_reason: None,
        };
        book.runs.push(RunRecord {
            id: RunId::new(format!("run-terminal-{ordinal}")),
            queue_item_id: item.id.clone(),
            project_id: item.project_id.clone(),
            workspace_id: item.workspace_id.clone(),
            session_id: item.session_id.clone(),
            transport: item.transport,
            state: if active {
                RunState::Running
            } else {
                RunState::Done
            },
            started_at_unix_ms: ordinal,
            ended_at_unix_ms: (!active).then_some(ordinal + 1),
            stop_reason: None,
        });
        book.items.push(item);
    }
    for ordinal in 202_u64..=400 {
        book.items.push(QueueItem {
            id: QueueItemId::new(format!("queue-waiting-{ordinal}")),
            project_id: ProjectId::new(format!("waiting-project-{ordinal}")),
            workspace_id: WorkspaceId::new(format!("waiting-workspace-{ordinal}")),
            workspace_root: format!("/tmp/waiting-project-{ordinal}"),
            session_id: SessionId::new(format!("waiting-session-{ordinal}")),
            transport: RuntimeTransport::GrokCliAcp,
            workflow: None,
            prompt: format!("waiting prompt {ordinal}"),
            auto_start: false,
            state: QueueItemState::Queued,
            enqueued_at_unix_ms: ordinal,
            ordinal,
            retry_of_run_id: None,
            predecessor_run_id: None,
            blocked_reason: None,
        });
    }
    book.next_ordinal = 401;
    book.executions
        .admit_parent(
            book.runs[0].id.clone(),
            book.runs[0].project_id.clone(),
            book.runs[0].workspace_id.clone(),
        )
        .expect("bind active fixture execution");
    validate_book(&book).expect("valid board-bound queue fixture");
    let view = queue_view(&book);
    assert_eq!(view.runs.len(), 2);
    assert!(
        view.runs
            .iter()
            .any(|run| run.queue_item_id == "queue-terminal-1" && run.state == RunState::Running)
    );
    assert!(
        view.runs
            .iter()
            .any(|run| run.queue_item_id == "queue-terminal-201")
    );
}

#[test]
fn manual_enqueue_waits_while_send_now_remains_automatically_eligible() {
    let root = root("manual");
    let queue = QueueCoordinator::open(root.clone());
    let mut manual_request = request("p1", 1);
    manual_request.auto_start = false;
    let manual = queue.enqueue(manual_request).expect("manual enqueue");
    let automatic = queue.enqueue(request("p1", 2)).expect("automatic enqueue");
    let candidates = queue.candidates(None, false).expect("automatic candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, automatic.id);
    let manual_candidate = queue
        .candidates(Some(&ProjectId::new("p1")), true)
        .expect("manual run next");
    assert_eq!(manual_candidate.len(), 1);
    assert_eq!(manual_candidate[0].id, manual.id);
    fs::remove_dir_all(root).expect("remove manual fixture");
}

#[test]
fn verified_transport_switch_rebinds_waiting_prompts_but_never_an_active_run() {
    let root = root("transport-rebind");
    let queue = QueueCoordinator::open(root.clone());
    let active = queue.enqueue(request("active", 1)).expect("active item");
    let begun = queue
        .begin_run(&active.id, RuntimeCancelHandle::new())
        .expect("active run");
    let waiting = queue.enqueue(request("waiting", 2)).expect("waiting item");
    queue
        .mark_blocked(&waiting.id, "old transport unavailable")
        .expect("blocked");
    let mut held_request = request("held", 3);
    held_request.auto_start = false;
    let held = queue.enqueue(held_request).expect("held item");

    assert_eq!(
        queue
            .rebind_waiting_transport(RuntimeTransport::XaiKeychain)
            .expect("rebind"),
        2
    );
    let view = queue.view();
    assert_eq!(
        view.runs
            .iter()
            .find(|run| run.id == begun.run.id.as_str())
            .expect("run")
            .transport,
        RuntimeTransport::GrokCliAcp
    );
    let waiting = view
        .items
        .iter()
        .find(|item| item.id == waiting.id.as_str())
        .expect("waiting");
    assert_eq!(waiting.transport, RuntimeTransport::XaiKeychain);
    assert_eq!(waiting.blocked_reason, None);
    let held = view
        .items
        .iter()
        .find(|item| item.id == held.id.as_str())
        .expect("held");
    assert_eq!(held.transport, RuntimeTransport::XaiKeychain);
    assert!(!held.auto_start);
    fs::remove_dir_all(root).expect("remove rebind fixture");
}

#[test]
fn restart_marks_running_interrupted_and_never_replays() {
    let root = root("restart");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin");
    let orphan = root.join("queue-run-state").join("a".repeat(64));
    fs::create_dir_all(&orphan).expect("create orphan run state");
    fs::write(orphan.join("transient.json"), b"not replayable").expect("write orphan run state");
    drop(queue);

    let reopened = QueueCoordinator::open(root.clone());
    let view = reopened.view();
    let restored_item = view
        .items
        .iter()
        .find(|candidate| candidate.id == item.id.as_str())
        .expect("restored item");
    assert_eq!(restored_item.state, QueueItemState::Interrupted);
    let restored_run = view
        .runs
        .iter()
        .find(|candidate| candidate.id == begun.run.id.as_str())
        .expect("restored run");
    assert_eq!(restored_run.state, RunState::Interrupted);
    assert!(!orphan.exists());
    assert!(
        reopened
            .candidates(None, false)
            .expect("no replay")
            .is_empty()
    );
    fs::remove_dir_all(root).expect("remove restart fixture");
}

#[test]
fn retry_creates_new_queue_and_run_id() {
    let root = root("retry");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let first = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("first run");
    queue
        .complete_run(
            &first.run.id,
            RunCompletion::Failed("provider unavailable".into()),
        )
        .expect("fail first");
    let retry = queue.retry(&first.run.id).expect("retry");
    assert_ne!(retry.id, item.id);
    assert_eq!(retry.retry_of_run_id.as_ref(), Some(&first.run.id));
    let second = queue
        .begin_run(&retry.id, RuntimeCancelHandle::new())
        .expect("second run");
    assert_ne!(second.run.id, first.run.id);
    queue
        .complete_run(&second.run.id, RunCompletion::Done)
        .expect("finish second");
    fs::remove_dir_all(root).expect("remove retry fixture");
}

#[test]
fn queued_terminal_and_review_tasks_can_be_removed_without_releasing_review() {
    let root = root("remove-retained");
    let queue = QueueCoordinator::open(root.clone());

    let queued = queue.enqueue(request("queued", 1)).expect("enqueue queued");
    let removed = queue.remove_item(&queued.id).expect("remove queued");
    assert_eq!(removed.outcome, QueueRemovalOutcome::Removed);
    assert!(removed.run_id.is_none());
    assert!(queue.view().items.is_empty());

    let done = queue.enqueue(request("done", 2)).expect("enqueue done");
    let done_run = queue
        .begin_run(&done.id, RuntimeCancelHandle::new())
        .expect("begin done");
    queue
        .complete_run(&done_run.run.id, RunCompletion::Done)
        .expect("complete done");
    let removed = queue.remove_item(&done.id).expect("remove done");
    assert_eq!(removed.outcome, QueueRemovalOutcome::Removed);
    assert_eq!(removed.run_id.as_ref(), Some(&done_run.run.id));
    assert!(queue.view().items.is_empty());
    assert!(queue.view().runs.is_empty());

    let review = queue.enqueue(request("review", 3)).expect("enqueue review");
    let review_run = queue
        .begin_run(&review.id, RuntimeCancelHandle::new())
        .expect("begin review");
    queue
        .complete_run(&review_run.run.id, RunCompletion::NeedsReview)
        .expect("complete review");
    queue.remove_item(&review.id).expect("remove review card");
    let view = queue.view();
    assert!(view.items.is_empty());
    assert!(view.runs.is_empty());
    assert!(
        view.review_blocked_project_ids
            .contains(&"review".to_owned()),
        "removing a task card must not resolve its independent Review gate"
    );
    fs::remove_dir_all(root).expect("remove retained-removal fixture");
}

#[test]
fn running_task_removal_persists_stop_before_cancel_then_removes_on_completion() {
    let root = root("remove-running");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("running", 1)).expect("enqueue");
    let cancel = RuntimeCancelHandle::new();
    let begun = queue
        .begin_run(&item.id, cancel.clone())
        .expect("begin run");

    let removal = queue.remove_item(&item.id).expect("request removal");
    assert_eq!(removal.outcome, QueueRemovalOutcome::StopRequested);
    assert_eq!(removal.run_id.as_ref(), Some(&begun.run.id));
    assert!(cancel.cancelled());
    let persisted = QueueStore {
        state_root: root.clone(),
    }
    .load()
    .expect("load removal intent");
    assert!(persisted.remove_after_stop_item_ids.contains(&item.id));
    assert!(
        persisted
            .runs
            .iter()
            .any(|run| { run.id == begun.run.id && run.state == RunState::StopRequested })
    );
    assert_eq!(queue.view().items.len(), 1, "Stopping remains visible");

    queue
        .complete_run(
            &begun.run.id,
            RunCompletion::Stopped("Stopped for removal".into()),
        )
        .expect("finish removal");
    assert!(queue.view().items.is_empty());
    assert!(queue.view().runs.is_empty());
    let persisted = QueueStore {
        state_root: root.clone(),
    }
    .load()
    .expect("load completed removal");
    assert!(persisted.remove_after_stop_item_ids.is_empty());
    fs::remove_dir_all(root).expect("remove running-removal fixture");
}

#[test]
fn restart_finishes_a_durable_remove_after_stop_without_replay() {
    let root = root("remove-restart");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("restart", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin run");
    queue.remove_item(&item.id).expect("persist removal intent");
    drop(queue);

    let reopened = QueueCoordinator::open(root.clone());
    assert!(reopened.view().items.is_empty());
    assert!(reopened.view().runs.is_empty());
    let interruptions = reopened
        .take_recovered_interruptions()
        .expect("read interruption evidence");
    assert_eq!(interruptions.len(), 1);
    assert_eq!(interruptions[0].id, begun.run.id);
    assert_eq!(interruptions[0].state, RunState::Interrupted);
    assert!(
        reopened
            .candidates(None, true)
            .expect("no replay candidates")
            .is_empty()
    );
    fs::remove_dir_all(root).expect("remove restart-removal fixture");
}

#[test]
fn prompt_byte_limit_refuses_multibyte_overflow_without_queue_mutation() {
    let root = root("prompt-byte-limit");
    let queue = QueueCoordinator::open(root.clone());
    let mut oversized = request("prompt-limit", 1);
    oversized.prompt = "é".repeat((MAX_PROMPT_BYTES / 2) + 1);
    let error = queue
        .enqueue(oversized)
        .expect_err("oversized UTF-8 prompt");
    assert!(error.contains("1–12000 UTF-8 bytes"));
    assert!(queue.view().items.is_empty());
    assert!(queue.view().runs.is_empty());
    fs::remove_dir_all(root).expect("remove prompt-limit fixture");
}

#[test]
fn cancel_intent_is_persisted_before_handle_is_signalled() {
    let root = root("cancel");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let cancel = RuntimeCancelHandle::new();
    let begun = queue.begin_run(&item.id, cancel.clone()).expect("begin");
    let stopped = queue
        .request_stop(&ProjectId::new("p1"))
        .expect("request stop");
    assert_eq!(stopped, begun.run.id);
    assert!(cancel.cancelled());
    assert!(queue.is_stop_requested(&begun.run.id));
    let persisted = QueueStore {
        state_root: root.clone(),
    }
    .load()
    .expect("load persisted cancel intent");
    assert!(
        persisted
            .runs
            .iter()
            .any(|run| { run.id == begun.run.id && run.state == RunState::StopRequested })
    );
    queue
        .complete_run(
            &begun.run.id,
            RunCompletion::Stopped("Stopped by user".into()),
        )
        .expect("finish stopped");
    fs::remove_dir_all(root).expect("remove cancel fixture");
}

#[test]
fn synthetic_lock_persists_all_stop_intents_before_any_cancel_effect() {
    let root = root("lock-stop-order");
    let queue = QueueCoordinator::open(root.clone());
    let first_item = queue.enqueue(request("p1", 1)).expect("first enqueue");
    let second_item = queue.enqueue(request("p2", 2)).expect("second enqueue");
    let first_cancel = RuntimeCancelHandle::new();
    let second_cancel = RuntimeCancelHandle::new();
    let first = queue
        .begin_run(&first_item.id, first_cancel.clone())
        .expect("first run");
    let second = queue
        .begin_run(&second_item.id, second_cancel.clone())
        .expect("second run");

    let run_ids = queue
        .persist_stop_all_intents()
        .expect("persist lock intents");
    assert_eq!(run_ids.len(), 2);
    assert!(!first_cancel.cancelled());
    assert!(!second_cancel.cancelled());
    let persisted = QueueStore {
        state_root: root.clone(),
    }
    .load()
    .expect("read stop intents");
    for run_id in [&first.run.id, &second.run.id] {
        assert!(
            persisted
                .runs
                .iter()
                .any(|run| { &run.id == run_id && run.state == RunState::StopRequested })
        );
    }

    queue
        .cancel_run_ids(&run_ids)
        .expect("apply cancel effects");
    assert!(first_cancel.cancelled());
    assert!(second_cancel.cancelled());
    fs::remove_dir_all(root).expect("remove lock fixture");
}

#[test]
fn lifecycle_suspension_closes_candidate_and_begin_run_races() {
    let root = root("lock-scheduler-gate");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    queue.set_lifecycle_suspended(true);
    assert!(
        queue
            .candidates(None, false)
            .expect("candidates")
            .is_empty()
    );
    assert!(
        queue
            .begin_run(&item.id, RuntimeCancelHandle::new())
            .expect_err("begin must fail while locked")
            .contains("macOS lock")
    );
    queue.set_lifecycle_suspended(false);
    assert_eq!(queue.candidates(None, false).expect("resumed").len(), 1);
    fs::remove_dir_all(root).expect("remove lock gate fixture");
}

#[test]
fn stop_during_running_transition_waits_for_exact_cancel_registration() {
    let root = root("cancel-register-race");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let hook_entered = Arc::clone(&entered);
    let hook_release = Arc::clone(&release);
    *BEFORE_CANCEL_REGISTER_HOOK.lock().expect("set queue hook") = Some((
        item.id.as_str().to_owned(),
        Box::new(move || {
            hook_entered.wait();
            hook_release.wait();
        }),
    ));
    let cancel = RuntimeCancelHandle::new();
    let begin_queue = queue.clone();
    let begin_item = item.id.clone();
    let begin_cancel = cancel.clone();
    let begin_thread = thread::spawn(move || begin_queue.begin_run(&begin_item, begin_cancel));
    entered.wait();

    let stop_queue = queue.clone();
    let stop = thread::spawn(move || stop_queue.request_stop(&ProjectId::new("p1")));
    let deadline = Instant::now() + Duration::from_secs(2);
    while !queue
        .view()
        .runs
        .iter()
        .any(|run| run.state == RunState::StopRequested)
    {
        assert!(Instant::now() < deadline, "StopRequested was not persisted");
        thread::yield_now();
    }
    assert!(!cancel.cancelled(), "registration is intentionally paused");
    release.wait();
    let begun = begin_thread
        .join()
        .expect("begin thread")
        .expect("begin run");
    let stopped = stop.join().expect("stop thread").expect("stop run");
    assert_eq!(stopped, begun.run.id);
    assert!(cancel.cancelled());
    fs::remove_dir_all(root).expect("remove cancel race fixture");
}

#[test]
fn state_file_is_owner_only_atomic_and_bounded() {
    let root = root("durability");
    let queue = QueueCoordinator::open(root.clone());
    queue.enqueue(request("p1", 1)).expect("enqueue");
    let path = root.join(PLUS_QUEUE_FILE);
    let bytes = fs::read(&path).expect("read queue file");
    let book: QueueBook = serde_json::from_slice(&bytes).expect("decode queue file");
    validate_book(&book).expect("validate queue file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path)
                .expect("queue metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    assert!(fs::read_dir(&root).expect("list queue root").all(|entry| {
        !entry
            .expect("queue entry")
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
    fs::remove_dir_all(root).expect("remove durability fixture");
}

#[test]
fn stale_atomic_temp_is_removed_without_replacing_committed_queue() {
    let root = root("crash-cut");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("commit queue item");
    let stale = root.join(format!(
        ".{PLUS_QUEUE_FILE}.{}-stale.tmp",
        std::process::id()
    ));
    fs::write(&stale, b"{partial").expect("write simulated crash temp");
    drop(queue);

    let reopened = QueueCoordinator::open(root.clone());
    let view = reopened.view();
    assert!(view.available);
    assert!(
        view.items
            .iter()
            .any(|candidate| candidate.id == item.id.as_str())
    );
    assert!(!stale.exists());
    fs::remove_dir_all(root).expect("remove crash-cut fixture");
}

#[test]
fn future_queue_schema_is_unavailable_not_reinterpreted() {
    let root = root("future-schema");
    create_owner_directory(&root).expect("create future-schema root");
    let path = root.join(PLUS_QUEUE_FILE);
    fs::write(
        &path,
        br#"{"schemaVersion":99,"nextOrdinal":1,"pausedProjects":[],"reviewBlockedProjects":[],"items":[],"runs":[]}"#,
    )
    .expect("write future queue schema");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict future-schema fixture");
    }
    let queue = QueueCoordinator::open(root.clone());
    let view = queue.view();
    assert!(!view.available);
    assert!(view.status.contains("schema 99"));
    assert!(view.items.is_empty());
    fs::remove_dir_all(root).expect("remove future-schema fixture");
}

#[test]
fn schema_two_migrates_with_no_fabricated_remove_after_stop_intent() {
    let root = root("schema-two-removal");
    create_owner_directory(&root).expect("create migration root");
    let path = root.join(PLUS_QUEUE_FILE);
    fs::write(
        &path,
        br#"{"schemaVersion":2,"nextOrdinal":1,"pausedProjects":[],"reviewBlockedProjects":[],"items":[],"runs":[]}"#,
    )
    .expect("write schema two queue");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restrict migration fixture");
    }
    let queue = QueueCoordinator::open(root.clone());
    assert!(queue.view().available);
    let migrated: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read migrated queue"))
            .expect("decode migrated queue");
    assert_eq!(migrated["schemaVersion"], QUEUE_SCHEMA_VERSION);
    assert_eq!(migrated["removeAfterStopItemIds"], serde_json::json!([]));
    assert_eq!(migrated["steerIntents"], serde_json::json!([]));
    fs::remove_dir_all(root).expect("remove migration fixture");
}

#[test]
fn schema_three_preserves_manual_and_paused_messages_as_held() {
    let root = root("schema-three-held");
    create_owner_directory(&root).expect("root");
    let path = root.join(PLUS_QUEUE_FILE);
    fs::write(
        &path,
        br#"{
  "schemaVersion": 3,
  "nextOrdinal": 3,
  "pausedProjects": ["paused"],
  "reviewBlockedProjects": [],
  "removeAfterStopItemIds": [],
  "items": [
{"id":"queue-paused","projectId":"paused","workspaceId":"workspace-paused","workspaceRoot":"/tmp/paused","sessionId":"session-paused","transport":"GrokCliAcp","prompt":"paused prompt","autoStart":true,"state":"queued","enqueuedAtUnixMs":1,"ordinal":1,"retryOfRunId":null,"blockedReason":null},
{"id":"queue-manual","projectId":"manual","workspaceId":"workspace-manual","workspaceRoot":"/tmp/manual","sessionId":"session-manual","transport":"GrokCliAcp","prompt":"manual prompt","autoStart":false,"state":"queued","enqueuedAtUnixMs":2,"ordinal":2,"retryOfRunId":null,"blockedReason":null}
  ],
  "runs": []
}"#,
    )
    .expect("write v3");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
    }
    let queue = QueueCoordinator::open(root.clone());
    let view = queue.view();
    assert!(view.paused_project_ids.is_empty());
    assert_eq!(view.items.len(), 2);
    assert!(view.items.iter().all(|item| {
        !item.auto_start && item.blocked_reason.as_deref() == Some("Held from an earlier version.")
    }));
    assert!(
        queue
            .candidates(None, false)
            .expect("candidates")
            .is_empty()
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn schema_four_steering_without_shared_order_is_refused() {
    let root = root("schema-four-steering");
    let queue = QueueCoordinator::open(root.clone());
    let item = queue.enqueue(request("p1", 1)).expect("enqueue");
    let begun = queue
        .begin_run(&item.id, RuntimeCancelHandle::new())
        .expect("begin");
    queue
        .enqueue_steer(
            &begun.run.project_id,
            &begun.run.session_id,
            &begun.run.id,
            "schema four steer",
        )
        .expect("steer");
    drop(queue);

    let path = root.join(PLUS_QUEUE_FILE);
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read v5")).expect("decode v5");
    legacy["schemaVersion"] = serde_json::json!(4);
    legacy["steerIntents"][0]
        .as_object_mut()
        .expect("steer object")
        .remove("ordinal");
    fs::write(
        &path,
        serde_json::to_vec_pretty(&legacy).expect("encode v4"),
    )
    .expect("write v4");

    let refused = QueueCoordinator::open(root.clone()).view();
    assert!(!refused.available);
    assert!(refused.status.contains("lacks a shared durable order"));
    fs::remove_dir_all(root).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn non_owner_queue_permissions_are_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = root("permissions");
    let queue = QueueCoordinator::open(root.clone());
    queue.enqueue(request("p1", 1)).expect("commit queue item");
    let path = root.join(PLUS_QUEUE_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("weaken fixture permissions");
    drop(queue);
    let reopened = QueueCoordinator::open(root.clone());
    let view = reopened.view();
    assert!(!view.available);
    assert!(view.status.contains("not owner-only"));
    fs::remove_dir_all(root).expect("remove permissions fixture");
}

#[test]
fn second_process_lease_cannot_recover_or_schedule_the_same_queue() {
    let root = root("process-lease");
    let first = QueueCoordinator::open(root.clone());
    first.enqueue(request("p1", 1)).expect("persist first item");

    let second = QueueCoordinator::open(root.clone());
    let blocked = second.view();
    assert!(!blocked.available);
    assert!(blocked.status.contains("already owned"));
    assert!(second.candidates(None, false).is_err());
    drop(second);
    drop(first);

    let recovered = QueueCoordinator::open(root.clone());
    let view = recovered.view();
    assert!(
        view.available,
        "recovered queue unavailable: {}",
        view.status
    );
    assert_eq!(view.items.len(), 1);
    fs::remove_dir_all(root).expect("remove process-lease fixture");
}
