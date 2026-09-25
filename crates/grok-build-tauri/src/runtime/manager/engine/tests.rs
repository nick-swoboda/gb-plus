use super::*;
use grok_build_plus_host::PlusRuntimeToolPolicy;

#[test]
fn legacy_api_account_without_engine_settings_keeps_its_transport_and_reconnect_grant() {
    use crate::runtime::account_preferences::{
        AccountPreferenceStore, AccountPreferences, ReconnectGrant,
    };
    use crate::runtime::types::RuntimeTransport;
    let root = std::env::temp_dir().join(format!(
        "gbplus-legacy-engine-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    let grant = ReconnectGrant::fixed(
        RuntimeTransport::XaiKeychain,
        crate::runtime::types::unix_time_millis(),
    )
    .unwrap();
    AccountPreferenceStore::new(root.clone())
        .save(AccountPreferences {
            selected_transport: RuntimeTransport::XaiKeychain,
            reconnect_grant: Some(grant),
            ..Default::default()
        })
        .unwrap();
    let manager = RuntimeManager::offline(root.clone());
    assert!(!manager.standard_engine());
    assert_eq!(manager.selected, RuntimeTransport::XaiKeychain);
    assert_eq!(manager.reconnect_grant, Some(grant));
    assert!(matches!(
        manager.connection,
        super::super::ConnectionState::Disconnected
    ));
    drop(manager);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn standard_parents_keep_isolated_children_contained() {
    let parent = EngineState {
        settings: EngineSettings {
            mode: EngineMode::GrokCliStandard,
            ..Default::default()
        },
        workspace: Some(PathBuf::from("/fixture/project")),
        ..Default::default()
    };
    let continued = parent.for_run(PlusRuntimeToolPolicy::Parent);
    assert_eq!(continued.settings.mode, EngineMode::GrokCliStandard);
    assert!(continued.workspace.is_none());
    for role in [
        PlusRuntimeToolPolicy::Explore,
        PlusRuntimeToolPolicy::Plan,
        PlusRuntimeToolPolicy::Worker,
    ] {
        let child = parent.for_run(role);
        assert_eq!(child.settings.mode, EngineMode::GbPlusContained);
        assert!(child.workspace.is_none() && child.settings.developer_cli.is_none());
    }
}
