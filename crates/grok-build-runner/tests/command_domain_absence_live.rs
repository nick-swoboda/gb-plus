//! Live Linux command-domain absence reads, in a process that forks nothing.
//!
//! These tests must not share a binary with anything that creates a child
//! process. That is not a testing inconvenience to work around -- it is the
//! contract: the observation answers a question about this whole process, and a
//! process that has created a child cannot truthfully answer it. The runner
//! service that produces this evidence in production is single-purpose and
//! forks nothing; a `cargo test` binary that also exercises process launch is
//! not, so the live reads get a binary of their own.

#![cfg(target_os = "linux")]

use grok_build_runner::{
    CommandDomainAbsenceError, LinuxCommandDomainAbsenceObservationV1, LinuxReapedChildAccounting,
    observe_linux_command_domain_absence,
};

/// Linux cgroup-v2 superblock magic (`CGROUP2_SUPER_MAGIC`).
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

fn enforced() -> LinuxCommandDomainAbsenceObservationV1 {
    observe_linux_command_domain_absence(
        "runner-session-absence-v1",
        "effect-absence-v1",
        &"7".repeat(64),
    )
    .expect("this Linux runner process must be able to read its own absence answers")
}

/// The enforced half: every kernel answer read at this instant is the
/// absence answer, so the observation validates.
#[test]
fn enforced_absence_observation_reads_back_as_absent() {
    let observation = enforced();
    observation
        .validate()
        .expect("a live absence observation must re-derive its own conclusion");
    assert_eq!(observation.scanned_filesystem_magic, CGROUP2_SUPER_MAGIC);
    assert!(observation.scanned_directory_count >= 1);
    assert!(observation.domain_leaf_candidates.is_empty());
    assert!(!observation.task_children_reads.is_empty());
    assert!(observation.self_cgroup_bytes.starts_with(b"0::"));
}

/// Control one: a command domain that exists. Exactly one input differs
/// from the enforced half -- the scan found a leaf -- and the absence claim
/// must fail. Without this the disposition could not distinguish an absent
/// domain from a present one.
#[test]
fn control_present_domain_leaf_refuses_the_absence_claim() {
    let mut control = enforced();
    let leaf = format!("gb-{}", "b".repeat(64));
    control.domain_leaf_candidates = vec![leaf.clone()];
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::DomainLeafPresent { leaf_name: leaf })
    );
}

/// Control two: the same emptiness read against a namespace that is not the
/// cgroup-v2 hierarchy. The read is honest and the answer is still "no leaf
/// here", but it proves nothing about command domains -- an unproven
/// absence rather than a proven one.
#[test]
fn control_non_cgroup_namespace_refuses_the_absence_claim() {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    let mut control = enforced();
    control.scanned_filesystem_magic = TMPFS_MAGIC;
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::NotCgroupV2 { magic: TMPFS_MAGIC })
    );
}

/// Control three: a scan that visited nothing. Absence over an empty search
/// is unproven absence.
#[test]
fn control_empty_scan_refuses_the_absence_claim() {
    let mut control = enforced();
    control.scanned_directory_count = 0;
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::EmptyScan)
    );
}

/// Control four: the kernel still lists a live child, so a domain may exist
/// even though no leaf was found.
#[test]
fn control_live_child_refuses_the_absence_claim() {
    let mut control = enforced();
    let thread_id = control.task_children_reads[0].thread_id;
    control.task_children_reads[0].bytes = b"4242 ".to_vec();
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::LiveChildPresent { thread_id })
    );
}

/// Control five: the kernel has already accounted for a reaped child. A
/// live-children read alone cannot see that, which is why the accounting
/// fields are part of the observation.
#[test]
fn control_reaped_child_accounting_refuses_the_absence_claim() {
    for mutate in [
        |accounting: &mut LinuxReapedChildAccounting| accounting.minor_faults = 1,
        |accounting: &mut LinuxReapedChildAccounting| accounting.major_faults = 1,
        |accounting: &mut LinuxReapedChildAccounting| accounting.user_time_ticks = 1,
        |accounting: &mut LinuxReapedChildAccounting| accounting.system_time_ticks = 1,
    ] {
        let mut control = enforced();
        mutate(&mut control.reaped_child_accounting);
        assert_eq!(
            control.validate(),
            Err(CommandDomainAbsenceError::ReapedChildAccounted)
        );
    }
}

/// A record that observed a leaf in the mount root but omitted it from its
/// candidate list must not decode as absence.
#[test]
fn a_hidden_root_leaf_refuses_the_absence_claim() {
    let mut control = enforced();
    let leaf = format!("gb-{}", "c".repeat(64));
    control.sampled_root_entries.push(leaf.clone());
    control.sampled_root_entries.sort();
    control.sampled_root_entries.dedup();
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::DomainLeafPresent { leaf_name: leaf })
    );
}

/// The binding is part of the observation: an absence read for one effect
/// cannot be presented for another.
#[test]
fn a_crossed_binding_refuses_the_absence_claim() {
    let mut control = enforced();
    control.effect_id = String::new();
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::InvalidBinding { field: "effect_id" })
    );
    let mut control = enforced();
    control.request_digest = "not-a-digest".into();
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::InvalidBinding {
            field: "request_digest"
        })
    );
}

/// A cgroup-v1 host cannot host this domain, so an absence read there is
/// not evidence about it.
#[test]
fn control_non_unified_hierarchy_refuses_the_absence_claim() {
    let mut control = enforced();
    control.self_cgroup_bytes = b"1:name=systemd:/user.slice\n".to_vec();
    assert_eq!(
        control.validate(),
        Err(CommandDomainAbsenceError::NotUnifiedHierarchy)
    );
}

/// The canonical record round-trips byte-for-byte, so a later reader
/// re-derives the same conclusion from the same retained kernel bytes.
#[test]
fn the_absence_observation_round_trips_canonically() {
    let observation = enforced();
    let encoded = serde_json::to_vec(&observation).expect("encode absence observation");
    let decoded: LinuxCommandDomainAbsenceObservationV1 =
        serde_json::from_slice(&encoded).expect("decode absence observation");
    assert_eq!(decoded, observation);
    assert_eq!(
        serde_json::to_vec(&decoded).expect("re-encode absence observation"),
        encoded
    );
    decoded.validate().expect("decoded record still validates");
}
