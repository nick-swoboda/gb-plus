//! Model-lease and family challenges; no model or process is launched.
use super::*;

fn parent(book: &mut PlusExecutionBook, name: &str, project: &str) -> RunId {
    let run = RunId::new(name);
    book.admit_parent(
        run.clone(),
        ProjectId::new(project),
        WorkspaceId::new(format!("base-{project}")),
    )
    .unwrap();
    book.configure_family(&run, None, 8).unwrap();
    run
}
fn child(
    book: &PlusExecutionBook,
    parent: &RunId,
    name: &str,
    isolated: bool,
) -> PlusExecutionMember {
    let root = book.member(parent).unwrap();
    PlusExecutionMember {
        run: RunId::new(name),
        family: parent.clone(),
        project: root.project.clone(),
        workspace: WorkspaceId::new(format!("workspace-{name}")),
        role: Some(PlusChildRole::Worker),
        snapshot: Some("a".repeat(64)),
        isolated,
        execution: PlusExecutionState::Yielded,
    }
}
// Match the queue's fail-closed persistence transaction: a rejected transition
// never replaces the last valid in-memory/durable record.
fn apply<T>(
    book: &mut PlusExecutionBook,
    f: impl FnOnce(&mut PlusExecutionBook) -> Result<T, String>,
) -> Result<T, String> {
    let mut candidate = book.clone();
    let result = f(&mut candidate)?;
    candidate.validate()?;
    *book = candidate;
    Ok(result)
}

#[test]
fn two_children_hold_exactly_two_slots_and_parent_must_reacquire() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "parent", "project");
    book.yield_parent(&p).unwrap();
    for (i, name) in ["first", "second"].into_iter().enumerate() {
        book.admit_child(&p, child(&book, &p, name, true), i as u64 + 1)
            .unwrap();
        assert!(book.try_acquire(&RunId::new(name), None).unwrap());
    }
    assert_eq!(book.held(), 2);
    book.request_resume(&p, 3).unwrap();
    assert!(!book.try_acquire(&p, None).unwrap());
    assert!(
        book.admit_parent(
            RunId::new("unrelated"),
            ProjectId::new("elsewhere"),
            WorkspaceId::new("base")
        )
        .is_err()
    );
    let first = RunId::new("first");
    book.retire(&first).unwrap();
    assert!(book.finish(&first, false).is_err());
    assert_eq!(book.held(), 2);
    book.finish(&first, true).unwrap();
    assert!(book.try_acquire(&p, None).unwrap());
    assert_eq!(book.held(), 2);
    assert!(book.finish(&p, true).is_err());
    book.finish(&RunId::new("second"), true).unwrap();
    book.finish(&p, true).unwrap();
    assert_eq!(book.held(), 0);
}

#[test]
fn project_barrier_survives_parent_yield_and_serial_children_exclude_each_other() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "p", "one");
    book.yield_parent(&p).unwrap();
    let first = child(&book, &p, "a", false);
    let second = child(&book, &p, "b", false);
    book.admit_child(&p, first, 1).unwrap();
    book.admit_child(&p, second, 2).unwrap();
    assert!(book.try_acquire(&RunId::new("a"), None).unwrap());
    assert!(!book.try_acquire(&RunId::new("b"), None).unwrap());
    assert!(
        book.admit_parent(
            RunId::new("another"),
            ProjectId::new("one"),
            WorkspaceId::new("other")
        )
        .is_err()
    );
    book.request_resume(&p, 3).unwrap();
    assert!(!book.try_acquire(&p, None).unwrap());
    book.finish(&RunId::new("a"), true).unwrap();
    assert!(book.try_acquire(&RunId::new("b"), None).unwrap());
    assert!(!book.try_acquire(&p, None).unwrap());
    book.finish(&RunId::new("b"), true).unwrap();
    assert!(book.try_acquire(&p, None).unwrap());
}

#[test]
fn admission_rejects_cross_project_snapshot_and_depth_and_keeps_budget() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "p", "one");
    book.yield_parent(&p).unwrap();
    let mut wrong = child(&book, &p, "wrong", true);
    wrong.project = ProjectId::new("two");
    assert!(apply(&mut book, |b| b.admit_child(&p, wrong, 1)).is_err());
    assert_eq!(book.budgets[0].used, 0);
    book.admit_child(&p, child(&book, &p, "good", true), 1)
        .unwrap();
    let mut drift = child(&book, &p, "drift", true);
    drift.snapshot = Some("b".repeat(64));
    assert!(apply(&mut book, |b| b.admit_child(&p, drift, 2)).is_err());
    assert_eq!(book.budgets[0].used, 1);
    assert!(book.configure_family(&RunId::new("good"), None, 8).is_err());
    let forged = child(&book, &p, "nested", true);
    assert!(apply(&mut book, |b| b.admit_child(&RunId::new("good"), forged, 2)).is_err());
}

#[test]
fn ordinary_and_workflow_budgets_are_separate_and_cannot_be_reset() {
    for workflow in [false, true] {
        let mut book = PlusExecutionBook::default();
        let p = RunId::new("p");
        book.admit_parent(p.clone(), ProjectId::new("one"), WorkspaceId::new("base"))
            .unwrap();
        let maximum = if workflow { 32 } else { 8 };
        book.configure_family(&p, workflow.then(|| "workflow".into()), maximum)
            .unwrap();
        book.yield_parent(&p).unwrap();
        assert!(
            book.configure_family(&p, Some("replacement".into()), 32)
                .is_err()
        );
        for index in 0..maximum {
            let name = format!("child-{index}");
            book.admit_child(&p, child(&book, &p, &name, true), u64::from(index) + 1)
                .unwrap();
            book.finish(&RunId::new(name), true).unwrap();
        }
        let extra = child(&book, &p, "extra", true);
        assert!(apply(&mut book, |b| b.admit_child(&p, extra, 99)).is_err());
        assert_eq!(book.budgets[0].used, maximum);
    }
}

#[test]
fn waiting_order_preserves_other_project_fairness_and_retiring_slots() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "p", "one");
    book.yield_parent(&p).unwrap();
    book.admit_child(&p, child(&book, &p, "child", true), 20)
        .unwrap();
    book.request_resume(&p, 30).unwrap();
    assert!(!book.try_acquire(&p, None).unwrap());
    assert!(!book.try_acquire(&RunId::new("child"), Some(10)).unwrap());
    assert!(book.try_acquire(&RunId::new("child"), Some(40)).unwrap());
    assert!(book.try_acquire(&p, None).unwrap());
    book.retire(&p).unwrap();
    assert_eq!(book.held(), 2);
    assert!(book.finish(&p, false).is_err());
}

#[test]
fn serialized_drift_is_refused_and_recovery_never_resumes_an_execution() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "p", "one");
    book.yield_parent(&p).unwrap();
    book.admit_child(&p, child(&book, &p, "child", true), 1)
        .unwrap();
    book.try_acquire(&RunId::new("child"), None).unwrap();
    let mut forged = book.clone();
    forged.budgets.clear();
    assert!(forged.validate().is_err());
    let mut forged = book.clone();
    forged.member_mut(&RunId::new("child")).unwrap().family = RunId::new("missing");
    assert!(forged.validate().is_err());
    let mut decoded: PlusExecutionBook =
        serde_json::from_slice(&serde_json::to_vec(&book).unwrap()).unwrap();
    decoded.validate().unwrap();
    assert_eq!(decoded.recover_interrupted().len(), 2);
    assert_eq!(decoded.held(), 0);
    decoded.validate().unwrap();
    assert!(decoded.try_acquire(&RunId::new("child"), None).is_err());
}

#[test]
fn completed_families_cannot_exhaust_future_execution_capacity() {
    let mut book = PlusExecutionBook::default();
    for cycle in 0..100 {
        let p = parent(&mut book, &format!("parent-{cycle}"), "one");
        book.yield_parent(&p).unwrap();
        let id = RunId::new(format!("child-{cycle}"));
        book.admit_child(&p, child(&book, &p, id.as_str(), true), cycle * 2 + 1)
            .unwrap();
        assert!(book.try_acquire(&id, None).unwrap());
        book.finish(&id, true).unwrap();
        book.request_resume(&p, cycle * 2 + 2).unwrap();
        assert!(book.try_acquire(&p, None).unwrap());
        book.finish(&p, true).unwrap();
        assert_eq!(book.held(), 0);
    }
    assert!(book.members.is_empty());
    assert!(book.budgets.is_empty());
}

#[test]
fn serialized_authority_cannot_alias_a_parent_workspace_or_invent_a_workflow() {
    let mut book = PlusExecutionBook::default();
    let p = parent(&mut book, "parent", "project");
    book.yield_parent(&p).unwrap();
    let mut aliased = child(&book, &p, "aliased", true);
    aliased.workspace = book.member(&p).unwrap().workspace.clone();
    assert!(apply(&mut book, |b| b.admit_child(&p, aliased, 1)).is_err());
    assert_eq!(book.budgets[0].used, 0);
    for invalid in [String::new(), "x".repeat(129), "workflow\nother".to_owned()] {
        let mut forged = book.clone();
        forged.budgets[0].workflow = Some(invalid);
        let decoded: PlusExecutionBook =
            serde_json::from_slice(&serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(decoded.validate().is_err());
    }
    book.member_mut(&p).unwrap().execution = PlusExecutionState::Terminal;
    assert!(book.validate().is_err());
}
