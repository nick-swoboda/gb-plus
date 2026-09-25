use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use super::*;

#[test]
fn maintenance_uses_the_managed_install_and_normal_cli_environment() {
    let home = Path::new("/fixture/home");
    for (operation, args) in [
        (Operation::Version, vec!["--version"]),
        (Operation::Update, vec!["update"]),
        (Operation::Check, vec!["update", "--check", "--json"]),
    ] {
        let cmd = command(home, operation);
        assert_eq!(cmd.get_program(), home.join(".grok/bin/grok"));
        assert_eq!(cmd.get_current_dir(), Some(home));
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), args);
        let env = cmd.get_envs().collect::<Vec<_>>();
        assert_eq!(env.len(), 2);
        assert!(env.contains(&("HOME".as_ref(), Some(home.as_os_str()))));
        assert!(env.contains(&("GROK_HOME".as_ref(), Some(home.join(".grok").as_os_str()))));
    }
}

#[test]
fn maintenance_accepts_future_versions_without_relaxing_contained_admission() {
    for release in ["1.0.30", "1.0.41", "2.0.0", "3.1.2-rc.4+build5"] {
        let line = format!("grok {release} (fixture) [stable]\n");
        assert_eq!(version(line.as_bytes()).unwrap(), release);
    }
    assert!(
        !super::super::parse_cli_version(b"grok 2.0.0")
            .unwrap()
            .supported
    );
    for bytes in [
        b"unknown 1.0.30".as_slice(),
        b"grok",
        b"grok <unsafe>",
        b"grok 1.0.30\x1b",
    ] {
        assert!(version(bytes).is_err());
    }
    assert!(version(&[b'a'; MAX_VERSION_BYTES + 1]).is_err());
    assert!(version(b"grok \xff").is_err());
}

#[test]
fn publisher_is_verified_before_execution_and_before_running_the_replacement() {
    let events = RefCell::new(Vec::new());
    let mut versions = VecDeque::from([b"grok 1.0.30".to_vec(), b"grok 2.0.0".to_vec()]);
    let result = perform_update(
        || {
            events.borrow_mut().push("verify");
            Ok(())
        },
        |operation| match operation {
            Operation::Version => {
                events.borrow_mut().push("version");
                Ok(versions.pop_front().unwrap())
            }
            Operation::Update => {
                events.borrow_mut().push("update");
                Ok(b"private updater output".to_vec())
            }
            Operation::Check => panic!("A changed version needs no second network check"),
        },
    )
    .unwrap();
    assert_eq!(
        *events.borrow(),
        ["verify", "version", "update", "verify", "version"]
    );
    assert_eq!(result.version, "2.0.0");
    assert!(result.detail.contains("Updated from 1.0.30 to 2.0.0"));
    assert!(!result.detail.contains("private"));
}

#[test]
fn invalid_publishers_cannot_execute_or_inspect_a_replacement() {
    for refused_check in [1, 2] {
        let checks = Cell::new(0);
        let operations = RefCell::new(Vec::new());
        let result = perform_update(
            || {
                checks.set(checks.get() + 1);
                if checks.get() == refused_check {
                    Err("signature refused".into())
                } else {
                    Ok(())
                }
            },
            |operation| {
                operations.borrow_mut().push(operation);
                Ok(b"grok 1.0.30".to_vec())
            },
        );
        assert_eq!(result.unwrap_err(), "signature refused");
        let expected = if refused_check == 1 {
            vec![]
        } else {
            vec![Operation::Version, Operation::Update]
        };
        assert_eq!(*operations.borrow(), expected);
    }
}

#[test]
fn updater_failure_or_timeout_cannot_report_success() {
    for failure in ["update failed", "process deadline exceeded"] {
        let mut operations = Vec::new();
        let result = perform_update(
            || Ok(()),
            |operation| {
                operations.push(operation);
                if operation == Operation::Update {
                    Err(failure.into())
                } else {
                    Ok(b"grok 1.0.30".to_vec())
                }
            },
        );
        assert_eq!(result.unwrap_err(), failure);
        assert_eq!(operations, [Operation::Version, Operation::Update]);
    }
}

#[test]
fn unchanged_version_requires_successful_current_release_evidence() {
    let current = serde_json::json!({"currentVersion":"1.0.30", "latestVersion":"1.0.30", "updateAvailable":false, "error":null});
    let mut cases = vec![(Ok(serde_json::to_vec(&current).unwrap()), true)];
    for (key, value) in [
        ("error", serde_json::json!("private network error")),
        ("latestVersion", serde_json::Value::Null),
        ("latestVersion", serde_json::json!("1.0.31")),
        ("currentVersion", serde_json::json!("1.0.29")),
        ("updateAvailable", serde_json::json!(true)),
    ] {
        let mut status = current.clone();
        status[key] = value;
        cases.push((Ok(serde_json::to_vec(&status).unwrap()), false));
    }
    cases.extend([
        (Ok(b"{}".to_vec()), false),
        (Ok(b"not json".to_vec()), false),
        (Err("network unavailable".into()), false),
    ]);
    for (check, expected_current) in cases {
        let result = perform_update(
            || Ok(()),
            |operation| match operation {
                Operation::Version => Ok(b"grok 1.0.30".to_vec()),
                Operation::Update => Ok(Vec::new()),
                Operation::Check => check.clone(),
            },
        )
        .unwrap();
        assert_eq!(result.detail == "Grok CLI is up to date.", expected_current);
        assert!(!result.detail.contains("private"));
    }
}
