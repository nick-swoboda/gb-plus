use super::*;

#[test]
fn unbound_runtimes_remain_contained_and_unknown_engines_do_not_execute() {
    assert_eq!(EngineSettings::default().mode, EngineMode::GbPlusContained);
    assert!(EngineSettings::default().developer_cli.is_none());
    assert!(
        serde_json::from_str::<EngineSettings>(
            r#"{"schemaVersion":1,"mode":"futureEngine","developerCli":null}"#
        )
        .is_err()
    );
    assert!(
        EngineSettings {
            schema_version: 2,
            ..EngineSettings::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn fresh_install_keeps_standard_after_account_state_is_created_and_after_restart() {
    let root = fixture_root("fresh");
    let settings = EngineSettings::load(&root).unwrap();
    assert_eq!(settings.mode, EngineMode::GrokCliStandard);
    assert!(settings.developer_cli.is_none());
    std::fs::write(root.join(crate::queue::PLUS_QUEUE_FILE), b"fixture").unwrap();
    assert_eq!(EngineSettings::load(&root).unwrap(), settings);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_accounts_and_queues_do_not_silently_gain_host_authority() {
    for name in [
        super::super::account_preferences::ACCOUNT_PREFERENCES_FILE,
        crate::queue::PLUS_QUEUE_FILE,
    ] {
        let root = fixture_root(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(name), b"retained without parsing").unwrap();
        let settings = EngineSettings::load(&root).unwrap();
        assert_eq!(settings.mode, EngineMode::GbPlusContained);
        assert_eq!(
            std::fs::read(root.join(name)).unwrap(),
            b"retained without parsing"
        );
        std::fs::remove_file(root.join(name)).unwrap();
        assert_eq!(EngineSettings::load(&root).unwrap(), settings);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn explicit_engine_choices_survive_restart_unchanged() {
    for mode in [EngineMode::GbPlusContained, EngineMode::GrokCliStandard] {
        let root = fixture_root("explicit");
        let settings = EngineSettings {
            mode,
            ..EngineSettings::default()
        };
        settings.save(&root).unwrap();
        let bytes = std::fs::read(root.join("engine-v1.json")).unwrap();
        assert_eq!(EngineSettings::load(&root).unwrap(), settings);
        assert_eq!(std::fs::read(root.join("engine-v1.json")).unwrap(), bytes);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unreadable_or_future_engine_state_is_not_replaced_with_a_new_default() {
    for bytes in [
        b"invalid".as_slice(),
        br#"{"schemaVersion":2,"mode":"gbPlusContained","developerCli":null}"#,
    ] {
        let root = fixture_root("invalid");
        OwnerStateRoot::new(&root)
            .file("engine-v1.json", 16 * 1024)
            .unwrap()
            .replace(bytes)
            .unwrap();
        assert!(EngineSettings::load(&root).is_err());
        assert_eq!(std::fs::read(root.join("engine-v1.json")).unwrap(), bytes);
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn fixture_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gbplus-engine-{label}-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ))
}

#[test]
fn engine_changes_keep_a_reversible_backup() {
    let root = std::env::temp_dir().join(format!(
        "gbplus-engine-{}-{}",
        std::process::id(),
        super::super::types::unix_time_millis()
    ));
    let original = EngineSettings::default();
    original.save(&root).unwrap();
    let bytes = std::fs::read(root.join("engine-v1.json")).unwrap();
    let changed = EngineSettings {
        mode: EngineMode::GrokCliStandard,
        ..original
    };
    changed.save(&root).unwrap();
    assert_eq!(
        std::fs::read(root.join("engine-before-change.json")).unwrap(),
        bytes
    );
    assert_eq!(EngineSettings::load(&root).unwrap(), changed);
    std::fs::remove_dir_all(root).unwrap();
}
