// Guards for the permit gate. Fragment included from `command/tests/mod.rs`.
//
// `LinuxCgroupV2Backend::launch` takes a `ValidatedBackendPermit` by value, and
// the only mint for that type requires `report.controls == required_controls(..)`
// exactly. So the twelve-control set is what stands between a real terminal and
// contained-looking evidence for a command that ran under fewer controls.
//
// ADR-0014's ordering finding has a regression guard in code. This finding had
// only prose, and prose cannot fail a build. The danger it guards is specific:
// the cheapest way to "unblock" a terminal is to delete an element from
// `required_controls` until the honest set matches. These tests make that
// deletion fail loudly instead of silently opening the gate.

/// The required set is exactly these twelve, and grows to thirteen only for a
/// finite memory ceiling.
///
/// Written as an exact equality rather than a count, so removing one control and
/// adding another cannot pass.
#[test]
fn required_controls_is_exactly_the_twelve_the_boundary_promises() {
    let no_memory_ceiling = ResourceLimits {
        wall_time_ms: 2_000,
        max_output_bytes: 4_096,
        max_processes: 1,
        max_memory_bytes: None,
    };
    let required = contained_boundary::required_controls(no_memory_ceiling);
    let expected = BTreeSet::from([
        BackendControl::ActiveCanaries,
        BackendControl::ClosedInheritedDescriptors,
        BackendControl::CompleteBoundedOutput,
        BackendControl::DescendantDomainKill,
        BackendControl::DescendantLimit,
        BackendControl::DescriptorExec,
        BackendControl::DescriptorWorkingDirectory,
        BackendControl::ExactArgv,
        BackendControl::ExternalWallClock,
        BackendControl::FilesystemPolicy,
        BackendControl::NetworkPolicy,
        BackendControl::ReplacedEnvironment,
    ]);
    assert_eq!(
        required, expected,
        "the required control set changed; a permit is only honest if this set is \
         the full boundary the product promises"
    );
    assert_eq!(required.len(), 12);

    let with_memory_ceiling = ResourceLimits {
        max_memory_bytes: Some(64 * 1024 * 1024),
        ..no_memory_ceiling
    };
    let required = contained_boundary::required_controls(with_memory_ceiling);
    assert!(required.contains(&BackendControl::MemoryLimit));
    assert_eq!(required.len(), 13);
}

/// A control set short of the required one cannot mint a permit, and the
/// refusal names what is missing.
///
/// This is the gate that makes `launch` unreachable today: the production Linux
/// backend reports `{ActiveCanaries}`, one of twelve. The test states that
/// relationship directly rather than relying on the backend being present, so
/// it guards the rule on both hosts.
#[test]
fn a_control_set_short_of_the_required_one_cannot_satisfy_the_permit_gate() {
    let limits = ResourceLimits {
        wall_time_ms: 2_000,
        max_output_bytes: 4_096,
        max_processes: 1,
        max_memory_bytes: None,
    };
    let required = contained_boundary::required_controls(limits);

    // Exactly what the production Linux backend reports today.
    let honest = BTreeSet::from([BackendControl::ActiveCanaries]);
    assert!(
        honest.is_subset(&required),
        "the honest set must be drawn from the required one"
    );
    assert_ne!(
        honest, required,
        "one proven control is not twelve, so the permit gate must stay shut"
    );

    let missing = required.difference(&honest).copied().collect::<Vec<_>>();
    assert_eq!(
        missing.len(),
        11,
        "eleven controls stand between the honest set and a mintable permit"
    );
    assert!(
        !missing.contains(&BackendControl::ActiveCanaries),
        "the one control that is proven must not appear as missing"
    );
}

/// The permit gate can now open, and this is the arithmetic that says so.
///
/// `enforced_controls()` is the intersection of two sets: what a live canary
/// proved, and `LINUX_PRODUCTION_INSTALLED_CONTROLS`. For the whole of this
/// sequence the second was one element, so the intersection could never reach
/// twelve however good the canary was — the gate was shut on the installed side.
///
/// It is no longer. Every required control now has a named installer on the
/// command's own path, so the intersection is bounded only by what the canary
/// proves, and that has been measured at twelve in the command's own leaf
/// (`a_canary_suite_proves_controls_inside_a_prepared_commands_own_leaf`).
///
/// This is deliberately an assertion about the *installed* half alone. It does
/// not claim any control is enforced, and it must not: naming a control here
/// while no canary proved it is exactly the substitution the intersection
/// exists to prevent.
#[cfg(target_os = "linux")]
#[test]
fn every_required_control_has_a_named_installer_on_the_commands_path() {
    let limits = ResourceLimits {
        wall_time_ms: 2_000,
        max_output_bytes: 4_096,
        max_processes: 1,
        max_memory_bytes: Some(64 * 1024 * 1024),
    };
    let required = contained_boundary::required_controls(limits);
    let installed = super::linux_backend::linux_production_installed_controls();

    let missing = required.difference(&installed).copied().collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "the installed half of the intersection must cover every required control, or the \
         permit gate is shut regardless of what a canary proves; missing {missing:?}"
    );
    // And the required set with a finite memory ceiling is the full thirteen,
    // so this covers `MemoryLimit` too rather than only the twelve.
    assert_eq!(required.len(), 13);
}
