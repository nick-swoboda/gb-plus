//! The one control that needs its own process, because it destroys it.
//!
//! `command_domain_absence_live.rs` proves the enforced half in a process that
//! forks nothing. This binary proves the opposite half by forking on purpose:
//! once this process has created and reaped a child, it can no longer produce
//! an absence observation at all. That is what makes the observation a reading
//! of process state rather than an assertion about it -- the previous
//! increment's finding was a field that carried the constant its own writer had
//! chosen, and a record that survived this test would have exactly that shape.
//!
//! It lives alone because a forked process poisons every other live read in the
//! same binary, which is the property being demonstrated.

#![cfg(target_os = "linux")]

use std::process::Command;

use grok_build_runner::{CommandDomainAbsenceError, observe_linux_command_domain_absence};

#[test]
fn a_process_that_has_created_a_child_cannot_claim_no_domain() {
    // The enforced half, before anything forks.
    observe_linux_command_domain_absence(
        "runner-session-fork-control",
        "effect-fork-control",
        &"7".repeat(64),
    )
    .expect("a pristine process must be able to read its own absence answers");

    // Exactly one input changes: this process now has a child.
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .status()
        .expect("spawn one child process");
    assert!(status.success());

    // The same reads, in the same namespace, now refuse. Nothing about the
    // cgroup subtree changed; what changed is that a child existed, and a child
    // may have been contained by a domain this scan cannot see.
    let error = observe_linux_command_domain_absence(
        "runner-session-fork-control",
        "effect-fork-control",
        &"7".repeat(64),
    )
    .expect_err("a process that created a child cannot claim no domain was created");
    assert!(
        matches!(
            error,
            CommandDomainAbsenceError::ReapedChildAccounted
                | CommandDomainAbsenceError::LiveChildPresent { .. }
        ),
        "expected a child-accounting refusal, observed {error}"
    );
}
