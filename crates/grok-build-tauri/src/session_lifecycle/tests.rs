use std::cell::RefCell;

use super::execute_session_resign_policy;
use crate::contracts::RunId;

#[test]
fn session_lock_persistence_failure_still_revokes_credentials_and_capabilities_fail_closed() {
    let actions = RefCell::new(Vec::new());
    let result = execute_session_resign_policy(
        Err("fixture queue sync failure".into()),
        |_| {
            actions.borrow_mut().push("cancel");
            Ok(())
        },
        || {
            actions.borrow_mut().push("revoke");
            Ok(())
        },
    );
    assert_eq!(&*actions.borrow(), &["revoke"]);
    let reason = result.expect_err("persistence failure must remain visible");
    assert!(reason.contains("durable Stop intent could not be persisted"));
    assert!(reason.contains("cancellation was skipped"));

    actions.borrow_mut().clear();
    execute_session_resign_policy(
        Ok(vec![RunId::new("run-lock-fixture")]),
        |run_ids| {
            assert_eq!(run_ids[0].as_str(), "run-lock-fixture");
            actions.borrow_mut().push("cancel");
            Ok(())
        },
        || {
            actions.borrow_mut().push("revoke");
            Ok(())
        },
    )
    .expect("persisted intent permits cancellation and mandatory revocation");
    assert_eq!(&*actions.borrow(), &["cancel", "revoke"]);
}
