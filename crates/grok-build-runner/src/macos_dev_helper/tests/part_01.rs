use super::*;
use crate::macos_helper_protocol::MacosHelperSession;

fn digest(label: &str) -> Digest {
    Digest::sha256(label.as_bytes())
}

/// The install audit of a user-owned, build-from-source helper binary.
const fn install_audit() -> MacosHelperInstallAudit {
    MacosHelperInstallAudit {
        auditing_uid: 501,
        binary_owner_uid: 501,
        binary_mode: 0o755,
        directory_owner_uid: 501,
        directory_mode: 0o755,
    }
}

/// An honest unprivileged session: authenticated peer, locally attested.
fn development_session() -> MacosDevelopmentHelperSession {
    let mut session = MacosDevelopmentHelperSession {
        topology: MacosHelperTopology::Development,
        helper_topology: MacosDevelopmentHelperTopology::SameImageThread,
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: 3,
        session_nonce: digest("nonce"),
        helper_binary_digest: digest("helper-binary"),
        helper_requirement_digest: digest("helper-requirement"),
        client_binary_digest: digest("client-binary"),
        client_requirement_digest: digest("client-requirement"),
        identity_pool_digest: digest("identity-pool"),
        workspace_grant_hash: digest("grant"),
        execution_policy_hash: digest("policy"),
        command_network: MacosHelperNetwork::Denied,
        authenticated_at_unix_ms: 1_700_000_000_000,
        peer_requirement_matched: true,
        attestation: MacosHelperAttestation::LocalCodeIdentity {
            install_audit: install_audit(),
        },
        dedicated_account_pool: false,
        session_digest: digest("placeholder"),
    };
    session.session_digest = session
        .computed_digest()
        .expect("compute development session digest");
    session
}

/// The only honest field-for-field production reading of a dev session.
///
/// Every field a production session shares is copied verbatim, including the
/// attestation the unprivileged helper publishes.
fn honest_production_reading(
    session: &MacosDevelopmentHelperSession,
) -> MacosHelperSession {
    MacosHelperSession {
        protocol_version: session.protocol_version,
        policy_version: session.policy_version,
        session_nonce: session.session_nonce.clone(),
        helper_binary_digest: session.helper_binary_digest.clone(),
        helper_requirement_digest: session.helper_requirement_digest.clone(),
        client_binary_digest: session.client_binary_digest.clone(),
        client_requirement_digest: session.client_requirement_digest.clone(),
        pool_record_digest: session.identity_pool_digest.clone(),
        workspace_grant_hash: session.workspace_grant_hash.clone(),
        execution_policy_hash: session.execution_policy_hash.clone(),
        command_network: session.command_network,
        authenticated_at_unix_ms: session.authenticated_at_unix_ms,
        peer_requirement_matched: session.peer_requirement_matched,
        attestation: session.attestation,
    }
}

/// Local attestation is valid for both session types. Both reject unattested
/// helpers and unsafe install paths. The development validator rejects a
/// dedicated-account claim, and the topology tag prevents canonical frames
/// from decoding as the other session type.
#[test]
fn an_unattested_or_ill_installed_helper_is_refused_and_the_topologies_stay_disjoint() {
    let session = development_session();
    session
        .validate()
        .expect("an honest unprivileged session satisfies its own contract");

    let reading = honest_production_reading(&session);
    reading
        .validate()
        .expect("ADR-0012: a locally attested helper is a first-class production peer");

    let mut unattested = session.clone();
    unattested.attestation = MacosHelperAttestation::Unattested;
    unattested.session_digest = unattested
        .computed_digest()
        .expect("compute unattested session digest");
    let expected_refusal = MacosHelperProtocolError::Invalid {
        field: "session.attestation",
        reason: "an unattested helper is never admitted: its loaded image was not pinned to an install-time code requirement",
    };
    assert_eq!(
        unattested.validate(),
        Err(MacosDevelopmentHelperError::Protocol(
            expected_refusal.clone()
        )),
        "an unattested unprivileged helper is refused by its own contract"
    );
    assert_eq!(
        honest_production_reading(&unattested).validate(),
        Err(expected_refusal),
        "and by the production contract, on the identical field"
    );

    let mut ill_installed = session.clone();
    ill_installed.attestation = MacosHelperAttestation::LocalCodeIdentity {
        install_audit: MacosHelperInstallAudit {
            directory_mode: 0o777,
            ..install_audit()
        },
    };
    ill_installed.session_digest = ill_installed
        .computed_digest()
        .expect("compute ill-installed session digest");
    assert_eq!(
        ill_installed.validate(),
        Err(MacosDevelopmentHelperError::Protocol(
            MacosHelperProtocolError::Invalid {
                field: "session.attestation.directory_mode",
                reason: "the helper install directory is writable by group or other",
            }
        )),
        "a world-writable install directory makes the code pin unfounded"
    );

    let mut dishonest = session.clone();
    dishonest.dedicated_account_pool = true;
    dishonest.session_digest = dishonest
        .computed_digest()
        .expect("compute dishonest session digest");
    assert_eq!(
        dishonest.validate(),
        Err(MacosDevelopmentHelperError::invalid(
            "development_session.dedicated_account_pool",
            "an unprivileged helper cannot own otherwise-unused local execution accounts",
        )),
        "the unprivileged contract must refuse a dedicated-account claim"
    );

    let development_bytes =
        serde_json::to_vec(&session).expect("encode the unprivileged session");
    assert!(
        String::from_utf8_lossy(&development_bytes).contains("\"topology\":\"development\""),
        "every unprivileged artifact must self-identify in its own bytes"
    );
    assert!(
        serde_json::from_slice::<MacosHelperSession>(&development_bytes).is_err(),
        "unprivileged session bytes must not decode as a production session"
    );
    let production_bytes =
        serde_json::to_vec(&reading).expect("encode the production reading");
    assert!(
        serde_json::from_slice::<MacosDevelopmentHelperSession>(&production_bytes).is_err(),
        "production session bytes must not decode as an unprivileged session"
    );
}

/// The barrier that actually stops an unprivileged run reaching Gate 1.
///
/// With local attestation admitted, the session contract no longer separates
/// the two topologies by signature. What separates them is the host authority
/// nobody can fabricate: production's terminal evidence is bound to a
/// `MacosAssignedIdentity` naming a real local execution account, and every
/// identity this module issues is validated to have none.
#[test]
fn no_unprivileged_identity_record_can_claim_a_dedicated_execution_account() {
    let state_root = MacosDevelopmentStateRoot::create().expect("create dev state root");
    let pool = MacosDevelopmentIdentityPool::open(&state_root).expect("open dev identity pool");
    let reservation = pool.reserve("generation-1").expect("reserve a dev slot");
    let record = reservation.record();
    assert!(
        !record.dedicated_account,
        "an unprivileged host cannot create an execution account"
    );
    assert_eq!(
        record.real_uid,
        rustix::process::getuid().as_raw(),
        "the dev domain runs as the invoking user, not a reserved identity"
    );

    let mut claimed = record.clone();
    claimed.dedicated_account = true;
    claimed.identity_digest = claimed.computed_digest().expect("recompute identity digest");
    assert_eq!(
        claimed.validate(),
        Err(MacosDevelopmentHelperError::invalid(
            "development_identity.dedicated_account",
            "a development host cannot create an otherwise-unused execution account",
        )),
        "the dedicated-account claim is refused even when its digest is repaired"
    );
}

/// Development frame codes are disjoint from production frame codes.
#[test]
fn development_frame_codes_are_disjoint_from_production_frame_codes() {
    let production = [
        MacosHelperFrameKind::Session,
        MacosHelperFrameKind::LaunchRequest,
        MacosHelperFrameKind::HeldPreparationEvidence,
        MacosHelperFrameKind::CleanupEvidence,
    ];
    let development = [
        MacosHelperFrameKind::DevelopmentSession,
        MacosHelperFrameKind::DevelopmentRunRequest,
        MacosHelperFrameKind::DevelopmentRunChunk,
        MacosHelperFrameKind::DevelopmentRunEvidence,
    ];
    for kind in production {
        assert!(!kind.development(), "{kind} must not be a development frame");
    }
    for kind in development {
        assert!(kind.development(), "{kind} must be a development frame");
        assert!(
            !production.contains(&kind),
            "{kind} must not collide with a production frame class"
        );
        assert_eq!(MacosHelperFrameKind::from_code(kind.code()), Some(kind));
    }
}

/// A development identity is never an otherwise-unused execution account.
#[test]
fn a_development_identity_never_claims_a_dedicated_account() {
    let state_root =
        MacosDevelopmentStateRoot::create().expect("create a development state root");
    let pool = MacosDevelopmentIdentityPool::open(&state_root).expect("open the dev pool");
    let first = pool.reserve("gen-first").expect("reserve the first slot");
    let second = pool.reserve("gen-second").expect("reserve the second slot");
    let third = pool.reserve("gen-third").expect("reserve the third slot");
    assert_ne!(first.record().slot, second.record().slot);
    assert_ne!(second.record().slot, third.record().slot);
    assert!(
        pool.reserve("gen-fourth").is_err(),
        "a fourth reservation must be refused, exactly as production queues a fourth request"
    );
    for reservation in [&first, &second, &third] {
        reservation
            .record()
            .validate()
            .expect("a reserved development identity validates");
        assert!(
            !reservation.record().dedicated_account,
            "a development host cannot create an execution account"
        );
        assert_eq!(
            reservation.record().real_uid,
            rustix::process::getuid().as_raw(),
            "the development domain runs as the invoking developer"
        );
    }
    drop(first);
    let reclaimed = pool
        .reserve("gen-reclaimed")
        .expect("a released slot returns to the pool");
    assert_eq!(reclaimed.record().generation_id, "gen-reclaimed");

    let mut forged = reclaimed.record().clone();
    forged.dedicated_account = true;
    forged.identity_digest = forged.computed_digest().expect("recompute forged digest");
    assert_eq!(
        forged.validate(),
        Err(MacosDevelopmentHelperError::invalid(
            "development_identity.dedicated_account",
            "a development host cannot create an otherwise-unused execution account",
        )),
        "a dedicated-account claim must be refused even when internally consistent"
    );
}

/// The development state root is owner private and short enough to bind.
#[test]
fn the_development_state_root_is_owner_private_and_bindable() {
    let state_root =
        MacosDevelopmentStateRoot::create().expect("create a development state root");
    state_root
        .validate_private()
        .expect("a fresh development state root is owner private");
    let socket = state_root.socket_path();
    assert!(
        socket.as_os_str().as_bytes().len() < MAX_UNIX_SOCKET_PATH_BYTES,
        "the development socket path must fit the platform sun_path bound"
    );
    assert!(
        !socket.starts_with("/Library"),
        "the development state root must not share the production helper's root"
    );
    let path = state_root.path().to_path_buf();
    drop(state_root);
    assert!(
        !path.exists(),
        "a development state root is removed when its owner drops it"
    );
}

/// Chunk payloads round-trip and refuse malformed hexadecimal.
#[test]
fn development_chunks_round_trip_and_refuse_malformed_payloads() {
    let bytes = (0_u8..=255).collect::<Vec<_>>();
    let chunk = MacosDevelopmentRunChunk {
        topology: MacosHelperTopology::Development,
        stream: MacosDevelopmentStream::Stderr,
        sequence: 9,
        bytes_hex: lower_hex(&bytes),
    };
    assert_eq!(chunk.decoded().expect("decode chunk"), bytes);

    let malformed = MacosDevelopmentRunChunk {
        bytes_hex: "0G".into(),
        ..chunk.clone()
    };
    assert!(malformed.decoded().is_err(), "uppercase hex is refused");

    let odd = MacosDevelopmentRunChunk {
        bytes_hex: "abc".into(),
        ..chunk
    };
    assert!(odd.decoded().is_err(), "odd-length hex is refused");
}

/// The development manifest is a closed executable policy, not a search root.
#[test]
fn the_development_manifest_admits_only_absolute_compiled_executables() {
    let mut manifest = MacosDevelopmentHelperManifest {
        topology: MacosHelperTopology::Development,
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: 1,
        client_requirement: "cdhash H\"00\"".into(),
        workspace_grant_hash: digest("grant"),
        execution_policy_hash: digest("policy"),
        command_network: MacosHelperNetwork::Denied,
        staged_workspace_id: "dev-workspace".into(),
        staged_workspace_path: "/tmp/dev-workspace".into(),
        executables: BTreeMap::from([("system-true".to_owned(), "/usr/bin/true".to_owned())]),
    };
    manifest.validate().expect("a fixed dev manifest validates");

    manifest
        .executables
        .insert("relative".to_owned(), "usr/bin/true".to_owned());
    assert!(
        manifest.validate().is_err(),
        "a relative executable entry must be refused"
    );
    manifest.executables.remove("relative");

    manifest.staged_workspace_id = "../escape".into();
    assert!(
        manifest.validate().is_err(),
        "path syntax in the staged workspace identifier must be refused"
    );
}

/// Evidence may claim the in-process applier only with its precondition.
///
/// The whole safety argument for calling `sandbox_init` after `fork` is that
/// the launching task had exactly one thread. Evidence that claims
/// `InProcessFork` while reporting more is refused by the validator, so a
/// reader never has to take the precondition on trust, and a future change
/// that forgot to measure it could not publish a passing artifact.
#[test]
fn in_process_profile_application_evidence_requires_a_single_threaded_launcher() {
    let single = MacosDevelopmentLauncherState {
        thread_count: 1,
        descriptor_count: 11,
    };
    let many = MacosDevelopmentLauncherState {
        thread_count: 3,
        descriptor_count: 11,
    };
    assert_ne!(
        single, many,
        "the launcher state must distinguish thread counts"
    );
    assert_eq!(
        MacosDevelopmentProfileApplier::InProcessFork.to_string(),
        "in_process_fork"
    );
    assert_eq!(
        MacosDevelopmentProfileApplier::SeparateProgram.to_string(),
        "separate_program"
    );
    // The canonical encodings are distinct tags, so one applier's evidence can
    // never decode as the other's.
    let in_process = serde_json::to_string(&MacosDevelopmentProfileApplier::InProcessFork)
        .expect("encode applier");
    let separate = serde_json::to_string(&MacosDevelopmentProfileApplier::SeparateProgram)
        .expect("encode applier");
    assert_eq!(in_process, "\"in_process_fork\"");
    assert_eq!(separate, "\"separate_program\"");
}

/// The single-thread predicate is measured, and the child stage table is total.
#[test]
fn the_launch_component_predicate_and_child_stage_table_are_measured_not_assumed() {
    let threads =
        current_process_thread_count().expect("libproc reports this task's thread count");
    assert!(threads >= 1, "a live task has at least one thread");
    assert_eq!(
        single_threaded_launch_component(),
        threads == 1,
        "the predicate must be exactly the measurement"
    );

    let ceiling = crate::macos_native_held_launch::descriptor_ceiling();
    assert!(
        (64..=65_536).contains(&ceiling),
        "the close-loop ceiling stays in its documented range: {ceiling}"
    );

    // Every reserved status names a stage, and nothing else does; an ordinary
    // program's exit status must never be mistaken for a setup failure.
    let mut named = 0;
    for status in 121..=127 {
        assert!(
            child_setup_stage(status).is_some(),
            "reserved status {status} must name a setup stage"
        );
        named += 1;
    }
    assert_eq!(named, 7, "the reserved range is exactly seven stages");
    for status in [0, 1, 2, 101, 120, 128, 255] {
        assert!(
            child_setup_stage(status).is_none(),
            "status {status} is an ordinary exit, not a setup stage"
        );
    }
}

/// Forking is refused outright unless this task is single threaded.
///
/// The refusal is the load-bearing half of the safety argument, so it is
/// asserted directly rather than only being reached through the helper. A test
/// harness normally runs tests on spawned threads, in which case this exercises
/// the refusal; if it ever runs single threaded, the same call must instead
/// hand back a stopped child holding exactly the standard three descriptors.
#[test]
fn forking_to_apply_a_profile_is_refused_unless_the_task_is_single_threaded() {
    let directory = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open a working-directory descriptor");
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .expect("open /dev/null");
    let outcome = fork_apply_seatbelt_and_exec(
        Path::new("/usr/bin/true"),
        &["/usr/bin/true".to_owned()],
        &BTreeMap::new(),
        "(version 1)(allow default)",
        directory.as_fd(),
        [null.as_fd(), null.as_fd(), null.as_fd()],
    );
    let threads =
        current_process_thread_count().expect("libproc reports this task's thread count");
    if threads == 1 {
        let pid = outcome.expect("a single-threaded task may fork to apply a profile");
        let observation = await_stopped_child(pid, Duration::from_secs(10))
            .expect("await the forked child")
            .expect("the child reached its pre-exec observation point");
        assert_eq!(
            observation.descriptors,
            vec![0, 1, 2],
            "the child's table at its execve boundary is exactly the standard three"
        );
        assert!(observation.session_leader, "the child created a new session");
        continue_stdio_child(pid).expect("resume the child");
        let _ignored = rustix::process::waitpid(
            Pid::from_raw(pid),
            rustix::process::WaitOptions::empty(),
        );
    } else {
        let error = outcome.expect_err("a multi-threaded task must never fork here");
        assert!(
            error
                .to_string()
                .contains("single-threaded launch component"),
            "the refusal must name the precondition it enforces: {error}"
        );
    }
}
