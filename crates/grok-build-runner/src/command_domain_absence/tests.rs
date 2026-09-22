use super::*;

/// The delegated-domain leaf grammar the absence scan recognizes must be the
/// grammar `prepare_domain` mints, not a second copy that could drift.
#[test]
fn absence_scan_recognizes_exactly_the_minted_leaf_grammar() {
    let nonce = "a".repeat(64);
    assert!(is_domain_leaf_name(&format!("gb-{nonce}")));
    assert!(!is_domain_leaf_name(&format!("gb-{}", "a".repeat(63))));
    assert!(!is_domain_leaf_name(&format!("gb-{}", "a".repeat(65))));
    assert!(!is_domain_leaf_name(&format!("gb-{}", "A".repeat(64))));
    assert!(!is_domain_leaf_name(&format!("gbd-canary-{nonce}")));
    assert!(!is_domain_leaf_name("gb-"));
    assert!(!is_domain_leaf_name("system.slice"));
}

/// A non-Linux host has no cgroup-v2 domain to observe, so it must produce no
/// observation rather than a weaker one.
#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_hosts_produce_no_absence_observation() {
    let error = observe_linux_command_domain_absence("session", "effect", &"0".repeat(64))
        .expect_err("a non-Linux host cannot observe a cgroup-v2 domain");
    assert_eq!(
        error,
        CommandDomainAbsenceError::ReadUnavailable {
            field: "linux_cgroup_v2"
        }
    );
}
