// The re-anchored launch identity. Fragment included from `tests/mod.rs`.

fn wire_attempt(sprint: &str, launch: &str, digest: &Digest) -> RunnerLaunchPreparationAttempt {
    RunnerLaunchPreparationAttempt {
        contract_version: CONTRACT_VERSION,
        attempt_id: "attempt-wire-1".to_owned(),
        sprint_id: sprint.to_owned(),
        launch_id: launch.to_owned(),
        cleanup_effect_id: "cleanup-effect-wire-1".to_owned(),
        native_journal_id: "native-journal-wire-1".to_owned(),
        expected_platform_binding_digest: digest.clone(),
        claimed_at_unix_ms: 7_000,
    }
}

fn wire_identity(
    attempt: &RunnerLaunchPreparationAttempt,
    binding_digest: &Digest,
    sprint: &str,
    launch: &str,
) -> Result<LinuxNativeLaunchIdentity, CgroupError> {
    LinuxNativeLaunchIdentity::try_from_wire_preparation(
        attempt,
        binding_digest,
        &LinuxRunnerLaunchAnchor {
            sprint_id: sprint,
            launch_id: launch,
            session_id: "session-wire-1",
            input_snapshot: &Digest::sha256(b"input-snapshot"),
            grant_hash: &Digest::sha256(b"grant"),
            policy_hash: &Digest::sha256(b"policy"),
        },
    )
}

/// The identity is built, and every value the binding used to supply now comes
/// from the runner's own state.
#[test]
fn a_wire_preparation_yields_an_identity_anchored_on_runner_state() {
    let digest = Digest::sha256(b"canonical-binding-bytes");
    let attempt = wire_attempt("sprint-w", "launch-w", &digest);
    let identity =
        wire_identity(&attempt, &digest, "sprint-w", "launch-w").expect("the identity is built");

    assert_eq!(identity.session_id, "session-wire-1");
    assert_eq!(identity.grant_hash, Digest::sha256(b"grant"));
    assert_eq!(identity.policy_hash, Digest::sha256(b"policy"));
    assert_eq!(identity.input_snapshot, Digest::sha256(b"input-snapshot"));
    // And the attempt's own fields travel unchanged.
    assert_eq!(identity.attempt_id, attempt.attempt_id);
    assert_eq!(identity.cleanup_effect_id, attempt.cleanup_effect_id);
    assert_eq!(identity.expected_platform_binding_digest, digest);
}

/// Each re-anchored cross-check refuses, one varied input at a time.
#[test]
fn each_reanchored_cross_check_refuses_its_own_mismatch() {
    let digest = Digest::sha256(b"canonical-binding-bytes");
    let attempt = wire_attempt("sprint-w", "launch-w", &digest);

    // Sprint: the attempt names a different sprint than the request it arrived with.
    assert!(
        wire_identity(&attempt, &digest, "sprint-other", "launch-w").is_err(),
        "a preparation for another sprint must be refused"
    );
    // Launch: likewise for the launch.
    assert!(
        wire_identity(&attempt, &digest, "sprint-w", "launch-other").is_err(),
        "a preparation for another launch must be refused"
    );
    // Binding digest: the attempt's expected digest must equal the digest the
    // wire already tied to the binding's real canonical bytes.
    assert!(
        wire_identity(&attempt, &Digest::sha256(b"other-bytes"), "sprint-w", "launch-w").is_err(),
        "an attempt expecting a different binding digest must be refused"
    );
    // Contract version.
    let mut stale = attempt.clone();
    stale.contract_version = CONTRACT_VERSION + 1;
    assert!(
        wire_identity(&stale, &digest, "sprint-w", "launch-w").is_err(),
        "a stale contract version must be refused"
    );
    // And the attempt's own validator still runs: a zero claim timestamp is
    // refused by `validate`, not by the join.
    let mut undated = attempt.clone();
    undated.claimed_at_unix_ms = 0;
    assert!(
        wire_identity(&undated, &digest, "sprint-w", "launch-w").is_err(),
        "an attempt with no claim timestamp must be refused"
    );
}

/// The identity this constructor builds is the same shape `try_from_claim`
/// builds, so nothing downstream can tell them apart by inspection.
///
/// This matters because `prepare_domain` compares a journal record's
/// `native_launch` for equality: if the two constructors produced different
/// shapes, a domain prepared under one could never be released under the other.
#[test]
fn the_wire_identity_validates_exactly_as_a_claim_built_one_does() {
    let digest = Digest::sha256(b"canonical-binding-bytes");
    let attempt = wire_attempt("sprint-w", "launch-w", &digest);
    let identity =
        wire_identity(&attempt, &digest, "sprint-w", "launch-w").expect("the identity is built");
    identity
        .validate()
        .expect("a wire-built identity satisfies the same validator");
}
