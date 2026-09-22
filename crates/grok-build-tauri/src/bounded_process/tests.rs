use super::*;
use std::io::{Read, Write};
use std::process::Stdio;

const FIXTURE: &str = "GBPLUS_BOUNDED_PROCESS_FIXTURE";

#[test]
fn larger_snapshot_input_cannot_expand_other_helpers_or_output_capture() {
    let mut bounds = limits(Duration::from_secs(1));
    bounds.input = MAX_BYTES + 1;
    assert!(collect(Command::new("/nonexistent-fixture"), &[], &bounds).is_err());
    assert!(
        collect_git_snapshot(
            Command::new("/nonexistent-fixture"),
            &[],
            &bounds,
            Box::new(())
        )
        .is_err()
    );
    bounds.input = 160 * 1024 * 1024;
    bounds.output = MAX_BYTES + 1;
    assert!(
        collect_git_snapshot(Command::new("/usr/bin/git"), &[], &bounds, Box::new(())).is_err()
    );
}

fn fixture(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "bounded_process::tests::helper_fixture",
            "--nocapture",
        ])
        .env(FIXTURE, mode);
    command
}

fn limits(timeout: Duration) -> Limits {
    Limits {
        input: 1024 * 1024,
        output: 1024 * 1024,
        error: 8192,
        timeout,
    }
}

#[test]
#[allow(
    clippy::zombie_processes,
    reason = "this re-executed fixture deliberately leaves its child for the owning process-group cleanup test"
)]
fn helper_fixture() {
    let Ok(mode) = std::env::var(FIXTURE) else {
        return;
    };
    match mode.as_str() {
        "exchange" => {
            std::io::stdout()
                .write_all(&vec![b'O'; 256 * 1024])
                .unwrap();
            std::io::stdout().flush().unwrap();
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            assert_eq!(input, vec![b'I'; 512 * 1024]);
            std::io::stdout().write_all(b"EXCHANGE-COMPLETE").unwrap();
        }
        "hold-input" | "hold-output" => std::thread::sleep(Duration::from_secs(10)),
        "overflow" => {
            for _ in 0..1024 {
                if std::io::stdout().write_all(&[b'X'; 8192]).is_err() {
                    break;
                }
            }
        }
        "descendant" => {
            // Same group, inherited pipe; the direct child exits first. The
            // collector must terminate the descendant before reaping its leader.
            let child = fixture("hold-output").stdin(Stdio::null()).spawn().unwrap();
            println!("DESCENDANT:{}", child.id());
            drop(child);
        }
        other => panic!("unknown fixture mode: {other}"),
    }
}

#[test]
fn concurrent_input_and_output_do_not_deadlock() {
    let output = collect(
        fixture("exchange"),
        &vec![b'I'; 512 * 1024],
        &limits(Duration::from_secs(5)),
    )
    .unwrap();
    assert!(output.status.success());
    assert!(
        output
            .stdout
            .windows(b"EXCHANGE-COMPLETE".len())
            .any(|part| part == b"EXCHANGE-COMPLETE")
    );
    assert!(output.stdout.len() >= 256 * 1024);
}

#[test]
fn blocked_input_and_oversized_output_end_within_the_deadline() {
    let started = Instant::now();
    let error = collect(
        fixture("hold-input"),
        &vec![b'I'; 1024 * 1024],
        &limits(Duration::from_millis(150)),
    )
    .err()
    .unwrap();
    assert!(error.contains("deadline"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
    let started = Instant::now();
    let mut bounds = limits(Duration::from_secs(3));
    bounds.output = 1024;
    let error = collect(fixture("overflow"), &[], &bounds).err().unwrap();
    assert!(error.contains("output exceeded"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_descendant_cannot_keep_collection_alive_after_its_parent_exits() {
    let started = Instant::now();
    let output = collect(fixture("descendant"), &[], &limits(Duration::from_secs(3))).unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("DESCENDANT:")
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn excessive_input_is_refused_before_launch() {
    let mut command = Command::new("/nonexistent/never-executed");
    command.arg("fixture");
    let mut bounds = limits(Duration::from_secs(1));
    bounds.input = 1;
    let error = collect(command, b"too much", &bounds).err().unwrap();
    assert!(error.contains("admitted bound"), "{error}");
}

#[test]
fn an_already_exited_helper_is_reaped_without_a_false_permission_failure() {
    for _ in 0..8 {
        let mut command = Command::new("/usr/bin/true");
        let mut owned = OwnedProcess::spawn(&mut command).unwrap();
        let proof = owned.cleanup_proof().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !owned.leader().unwrap().exited().unwrap() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(POLL);
        }
        #[cfg(target_os = "macos")]
        assert!(darwin_group::only_exited_members(owned.leader().unwrap().child.id()).unwrap());
        assert!(owned.stop().unwrap().success());
        assert!(proof.proven());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn live_group_members_are_never_mistaken_for_exited_helpers() {
    let mut command = fixture("hold-output");
    let mut owned = OwnedProcess::spawn(&mut command).unwrap();
    assert!(!darwin_group::only_exited_members(owned.leader().unwrap().child.id()).unwrap());
    owned.stop().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn an_exited_leader_does_not_hide_a_live_descendant() {
    let mut command = fixture("descendant");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut owned = OwnedProcess::spawn(&mut command).unwrap();
    let proof = owned.cleanup_proof().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !owned.leader().unwrap().exited().unwrap() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(POLL);
    }
    assert!(!darwin_group::only_exited_members(owned.leader().unwrap().child.id()).unwrap());
    assert!(!proof.proven());
    assert!(owned.stop().unwrap().success());
    assert!(proof.proven());
}

#[test]
fn lost_wait_ownership_never_authorizes_signalling_a_historical_process_group() {
    let mut command = Command::new("/usr/bin/true");
    let mut owned = OwnedProcess::spawn(&mut command).unwrap();
    // Simulate another wait consumer violating the ownership contract. The
    // production wrapper never exposes Child; this injection is test-only.
    let mut leader = owned.leader.take().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while leader.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(POLL);
    }
    assert!(leader.signal().is_err());
    assert!(!leader.signalled);
    assert!(!leader.proof.proven());
}
