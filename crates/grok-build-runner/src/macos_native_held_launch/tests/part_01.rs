use std::process::Command;

use super::*;

fn observed_child(outcome: MacosNativeHeldLaunchOutcome) -> MacosNativeObservedHeldAtChild {
    match outcome {
        MacosNativeHeldLaunchOutcome::ObservedHeldAt(child) => *child,
        MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned { failure, .. } => {
            panic!("launch was cleaned after {:?}", failure.phase)
        }
        MacosNativeHeldLaunchOutcome::ReconciliationRequired(reconciliation) => {
            panic!(
                "launch requires reconciliation after {:?}: {}",
                reconciliation.failure.phase, reconciliation.cleanup_failure
            )
        }
    }
}

fn assert_exact_child_absent_via_ps(pid: u32) {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-o", "pid=,ppid=,pgid=,comm=", "-p"])
        .arg(pid.to_string())
        .output()
        .expect("run independent ps absence observer");
    assert!(
        output.status.success() || output.status.code() == Some(1),
        "unexpected ps observer failure: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("ps output is UTF-8");
    if rendered.trim().is_empty() {
        return;
    }
    let fields = rendered.split_whitespace().collect::<Vec<_>>();
    assert!(fields.len() >= 4, "unexpected ps output: {fields:?}");
    let exact_child_still_present = fields[0] == pid.to_string()
        && fields[1] == std::process::id().to_string()
        && fields[2] == pid.to_string();
    assert!(
        !exact_child_still_present,
        "ps still observed the exact child identity tuple: {fields:?}"
    );
}

fn independently_finish_reconciliation(
    reconciliation: &MacosNativeHeldLaunchReconciliationRequiredV1,
) {
    let pid = reconciliation.pid().expect("reconciliation retains PID");
    let _expected_start = reconciliation
        .available_start_identity
        .expect("test spawn exposes a start identity");
    let pid = Pid::from_raw(i32::try_from(pid).expect("test PID fits pid_t"))
        .expect("test PID is positive");
    let already_reaped = matches!(
        waitpid(Some(pid), WaitOptions::NOHANG),
        Ok(Some(_)) | Err(_)
    );
    if !already_reaped {
        // `waitpid(exact_pid, WNOHANG) == 0` independently proves that this
        // process still owns that exact unreaped direct child; a reused or
        // unrelated PID returns `ECHILD` instead.
        kill_process(pid, Signal::KILL).expect("independently signal exact child");
        // Bounded and escalating for the same D-0013 reason the product path
        // is: a survivor must fail this test, never suspend it.
        reap_exact_condemned_child(pid).expect("independently reap exact child within its bound");
    }
    assert_exact_child_absent_via_ps(u32::try_from(pid.as_raw_pid()).expect("positive PID"));
}

#[test]
fn real_spawn_is_observed_held_at_as_session_leader_with_exact_fd_allowlist() {
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    let child = observed_child(
        launch_inert_system_fixture(&authority).expect("launch cleanup-only held-at fixture"),
    );
    let receipt = child.receipt();
    assert!(receipt.matches_launch_authority(&authority).unwrap());
    let bytes = receipt.canonical_bytes().expect("encode held receipt");
    let reopened = MacosNativeObservedHeldAtReceiptV1::decode_canonical(&bytes)
        .expect("reopen exact held-at receipt");
    assert_eq!(&reopened, receipt);

    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-o", "stat=,ppid=,pgid=", "-p"])
        .arg(receipt.pid().to_string())
        .output()
        .expect("run independent ps observer");
    assert!(output.status.success());
    let fields = String::from_utf8(output.stdout)
        .expect("ps output is UTF-8")
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 3, "unexpected ps observation: {fields:?}");
    assert!(
        fields[0].contains('T'),
        "ps did not observe a stopped child"
    );
    assert_eq!(fields[1], std::process::id().to_string());
    assert_eq!(fields[2], receipt.pid().to_string());

    let cleanup = match child.terminate_and_reap() {
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(receipt) => receipt,
        MacosNativeObservedHeldAtCleanupOutcome::ReconciliationRequired(value) => {
            panic!("cleanup unexpectedly requires reconciliation: {value:?}")
        }
    };
    assert!(!cleanup.canonical_bytes().expect("cleanup bytes").is_empty());
}

#[test]
fn canonical_receipt_rejects_observation_tampering() {
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    let child = observed_child(
        launch_inert_system_fixture(&authority).expect("launch held-at tamper fixture"),
    );
    let bytes = child
        .receipt()
        .canonical_bytes()
        .expect("encode held receipt");
    let json = bytes
        .strip_prefix(RECEIPT_DOMAIN)
        .expect("receipt domain is present");
    let mut value: serde_json::Value =
        serde_json::from_slice(json).expect("decode receipt JSON");
    value["observations"][1]["status"] = serde_json::Value::from(2_u64);
    let mut crossed = RECEIPT_DOMAIN.to_vec();
    crossed.extend_from_slice(&serde_json::to_vec(&value).expect("encode crossed receipt"));
    assert!(MacosNativeObservedHeldAtReceiptV1::decode_canonical(&crossed).is_err());
    assert!(matches!(
        child.terminate_and_reap(),
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(_)
    ));
}

#[test]
fn every_environment_injection_is_rejected_before_spawn() {
    let descriptors = std::array::from_fn::<_, 5, _>(|_| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("open inert descriptor")
    });
    let cwd = File::open(".").expect("open cwd");
    let argv = vec!["true".to_owned()];
    let environment = BTreeMap::from([(
        "DYLD_INSERT_LIBRARIES".to_owned(),
        "/tmp/never-loaded.dylib".to_owned(),
    )]);
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    let spec = MacosNativeHeldLaunchSpec::new(
        &authority,
        Path::new("/usr/bin/true"),
        &argv,
        &environment,
        cwd.as_fd(),
        descriptors.each_ref().map(AsFd::as_fd),
    );
    assert!(launch_cleanup_only_observed_held_at_child(spec).is_err());
}

#[test]
fn maximal_receipt_size_is_preflighted_before_native_spawn() {
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    let quoted = "\"".repeat(MAX_TEXT_BYTES);
    let argv = std::iter::once("true".to_owned())
        .chain(std::iter::repeat_n(quoted, 7))
        .collect::<Vec<_>>();
    assert!(argv.iter().map(String::len).sum::<usize>() <= 32 * 1_024);
    let result = launch_system_fixture_with_faults(
        &authority,
        Path::new("/usr/bin/true"),
        &argv,
        MacosNativeLaunchFaults {
            launch: MacosNativeLaunchFault::SpawnMustNotBeReached,
            cleanup: MacosNativeCleanupFault::None,
        },
    );
    assert!(matches!(
        result,
        Err(MacosNativeHeldLaunchError::Invalid(_))
    ));
}

#[test]
fn every_injected_post_spawn_cut_emits_exact_cleanup_and_no_survivor() {
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    for launch in [
        MacosNativeLaunchFault::FirstObservation,
        MacosNativeLaunchFault::SecondObservation,
        MacosNativeLaunchFault::ParentValidation,
        MacosNativeLaunchFault::ReceiptEncoding,
        MacosNativeLaunchFault::ExecutableReobservation,
    ] {
        let outcome = launch_system_fixture_with_faults(
            &authority,
            Path::new("/usr/bin/true"),
            &["true".to_owned()],
            MacosNativeLaunchFaults {
                launch,
                cleanup: MacosNativeCleanupFault::None,
            },
        )
        .expect("run injected post-spawn cut");
        let (pid, cleanup) = match outcome {
            MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned {
                cleanup_receipt, ..
            } => (cleanup_receipt.pid, cleanup_receipt),
            MacosNativeHeldLaunchOutcome::ObservedHeldAt(_) => {
                panic!("injected cut unexpectedly emitted ObservedHeldAt")
            }
            MacosNativeHeldLaunchOutcome::ReconciliationRequired(value) => {
                panic!("ordinary injected cleanup unexpectedly needs reconciliation: {value:?}")
            }
        };
        assert!(!cleanup.canonical_bytes().expect("cleanup bytes").is_empty());
        assert_exact_child_absent_via_ps(pid);
    }
}

#[test]
fn cleanup_faults_emit_only_reconciliation_and_independent_cleanup_closes_pid() {
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    for cleanup in [
        MacosNativeCleanupFault::BeforeSignal,
        MacosNativeCleanupFault::AfterSignal,
        MacosNativeCleanupFault::AfterWait,
        MacosNativeCleanupFault::ReceiptEncoding,
    ] {
        let outcome = launch_system_fixture_with_faults(
            &authority,
            Path::new("/usr/bin/true"),
            &["true".to_owned()],
            MacosNativeLaunchFaults {
                launch: MacosNativeLaunchFault::FirstObservation,
                cleanup,
            },
        )
        .expect("run injected cleanup cut");
        let reconciliation = match outcome {
            MacosNativeHeldLaunchOutcome::ReconciliationRequired(value) => value,
            MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned { .. } => {
                panic!("cleanup fault emitted a false cleanup receipt")
            }
            MacosNativeHeldLaunchOutcome::ObservedHeldAt(_) => {
                panic!("cleanup fault emitted ObservedHeldAt")
            }
        };
        reconciliation
            .validate()
            .expect("validate bounded reconciliation");
        let pid = reconciliation.pid().expect("spawned child PID is retained");
        assert!(pid > 1);
        independently_finish_reconciliation(&reconciliation);
    }
}

#[test]
fn sigcont_between_observations_is_refused_and_cleaned() {
    let path = Path::new("/bin/sleep");
    let authority = system_fixture_authority(path).expect("construct sleep authority");
    let outcome = launch_system_fixture_with_faults(
        &authority,
        path,
        &["sleep".to_owned(), "30".to_owned()],
        MacosNativeLaunchFaults {
            launch: MacosNativeLaunchFault::ContinueBeforeSecondObservation,
            cleanup: MacosNativeCleanupFault::None,
        },
    )
    .expect("run SIGCONT-between-observations fixture");
    match outcome {
        MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned {
            cleanup_receipt, ..
        } => assert_exact_child_absent_via_ps(cleanup_receipt.pid),
        MacosNativeHeldLaunchOutcome::ObservedHeldAt(child) => {
            let child = *child;
            let pid = child.receipt().pid();
            let _ = child.terminate_and_reap();
            panic!("SIGCONT-crossed child {pid} was incorrectly accepted")
        }
        MacosNativeHeldLaunchOutcome::ReconciliationRequired(value) => {
            panic!("SIGCONT refusal did not prove cleanup: {value:?}")
        }
    }
}

/// D-0013. The post-spawn cleanup path used to send one `SIGKILL` and then
/// block in `waitpid` forever. On Darwin a `POSIX_SPAWN_START_SUSPENDED` child
/// can survive that single signal — the task stays Mach-suspended with the kill
/// pending, `ps` reports `Ss` instead of `T`, and nothing ever reaps it — so the
/// launcher hung instead of reporting the survivor its own name forbids.
///
/// Both halves of the remedy are pinned here against a real kernel child:
/// the reap re-signals between polls, and it is bounded, so a child that
/// outlives the bound becomes a typed refusal rather than a suspended thread.
#[test]
fn condemned_child_reap_escalates_between_polls_and_is_bounded_by_a_deadline() {
    // Escalation. This child is genuinely held, so only a signal delivered by
    // the reap itself can make it terminate; a reap that merely polls would
    // wait out the whole bound and report a survivor.
    let authority = inert_system_fixture_authority().expect("construct exact authority");
    let mut child = observed_child(
        launch_inert_system_fixture(&authority).expect("launch held escalation fixture"),
    );
    let held = Pid::from_raw(i32::try_from(child.receipt().pid()).expect("PID fits pid_t"))
        .expect("positive PID");
    // The reap below takes custody of this exact child, so the move-only
    // handle must not also try to signal the PID after it is reaped.
    child.cleanup_consumed = true;
    let status = reap_exact_child_within(held, Signal::CONT, Duration::from_secs(30))
        .expect("escalating reap releases and reaps a still-held exact child");
    assert!(
        status.exited(),
        "the escalated child did not run to its own exit: {status:?}"
    );
    assert_exact_child_absent_via_ps(u32::try_from(held.as_raw_pid()).expect("positive PID"));

    // Bound. `SIGCONT` cannot terminate a resumed `sleep`, so this reap can
    // only end by expiring — and it must expire, not block.
    let path = Path::new("/bin/sleep");
    let authority = system_fixture_authority(path).expect("construct sleep authority");
    let survivor = observed_child(
        launch_system_fixture_with_faults(
            &authority,
            path,
            &["sleep".to_owned(), "30".to_owned()],
            MacosNativeLaunchFaults::NONE,
        )
        .expect("launch held bound fixture"),
    );
    let pid = Pid::from_raw(i32::try_from(survivor.receipt().pid()).expect("PID fits pid_t"))
        .expect("positive PID");
    let started = Instant::now();
    let refusal = reap_exact_child_within(pid, Signal::CONT, Duration::from_millis(250))
        .expect_err("a child the escalation cannot terminate must expire the bound");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250),
        "the reap gave up before its own deadline after {elapsed:?}"
    );
    assert!(
        refusal.contains(&pid.as_raw_pid().to_string()) && refusal.contains("survives this launch"),
        "expiry did not name the surviving exact child: {refusal}"
    );

    // The bound reports a survivor; it does not leave one behind.
    assert!(matches!(
        survivor.terminate_and_reap(),
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(_)
    ));
    assert_exact_child_absent_via_ps(u32::try_from(pid.as_raw_pid()).expect("positive PID"));
}

#[test]
fn observed_held_at_receipt_makes_no_continuing_stopped_claim() {
    let path = Path::new("/bin/sleep");
    let authority = system_fixture_authority(path).expect("construct sleep authority");
    let child = observed_child(
        launch_system_fixture_with_faults(
            &authority,
            path,
            &["sleep".to_owned(), "30".to_owned()],
            MacosNativeLaunchFaults::NONE,
        )
        .expect("launch sleep fixture"),
    );
    let pid = child.receipt().pid();
    kill_process(
        Pid::from_raw(i32::try_from(pid).expect("PID fits pid_t")).expect("positive PID"),
        Signal::CONT,
    )
    .expect("same-UID SIGCONT proves point-in-time scope");
    let mut resumed = false;
    for _ in 0..10_000 {
        let output = Command::new("/bin/ps")
            .env_clear()
            .args(["-o", "stat=", "-p"])
            .arg(pid.to_string())
            .output()
            .expect("observe resumed child");
        let state = String::from_utf8_lossy(&output.stdout);
        if !state.trim().is_empty() && !state.contains('T') {
            resumed = true;
            break;
        }
        std::thread::yield_now();
    }
    assert!(
        resumed,
        "SIGCONT did not produce an independently visible resumed state"
    );
    assert!(matches!(
        child.terminate_and_reap(),
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(_)
    ));
    assert_exact_child_absent_via_ps(pid);
}
