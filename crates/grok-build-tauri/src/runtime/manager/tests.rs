use std::fs;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use grok_build_plus_host::{PendingFileSet, PlusSessionStore, bind_project_folder};

use super::*;

impl RuntimeManager {
    /// Uses the already verified production broker lease, with no credential
    /// access shortcut or authorization UI. A real native probe establishes
    /// Connected before the synthetic child/workflow scheduler can use it.
    pub(crate) fn native_live_fixture(
        state_root: PathBuf,
        credential: XaiCredentialLease,
    ) -> Result<Self, String> {
        let mut runtime = Self::offline(state_root);
        runtime.selected = RuntimeTransport::XaiKeychain;
        runtime.credential_broker = None;
        runtime.credential_lease = Some(credential);
        runtime.connect_internal(&|_| Ok(()), false)?;
        Ok(runtime)
    }
}
use crate::runtime::keychain::SecretBytes;
use crate::runtime::types::{AdapterProbe, AdapterSession, RuntimeUsage};

struct EmptySecrets;

impl ProviderSecretStore for EmptySecrets {
    fn inspect_xai_key(&self) -> KeychainPresence {
        KeychainPresence::Absent
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        Ok(None)
    }
    fn store_xai_key(&self, _key: &SecretBytes) -> Result<(), String> {
        Ok(())
    }
    fn delete_xai_key(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct SecretCounts {
    inspect: AtomicUsize,
    load: AtomicUsize,
    load_without_ui: AtomicUsize,
    store: AtomicUsize,
}

struct CountingSecrets {
    value: Mutex<Option<Vec<u8>>>,
    counts: Arc<SecretCounts>,
}

impl CountingSecrets {
    fn present() -> (Arc<Self>, Arc<SecretCounts>) {
        let counts = Arc::new(SecretCounts::default());
        (
            Arc::new(Self {
                value: Mutex::new(Some(b"manager-fixture-key".to_vec())),
                counts: Arc::clone(&counts),
            }),
            counts,
        )
    }
}

impl ProviderSecretStore for CountingSecrets {
    fn inspect_xai_key(&self) -> KeychainPresence {
        self.counts.inspect.fetch_add(1, Ordering::Relaxed);
        if self.value.lock().expect("secret lock").is_some() {
            KeychainPresence::Present
        } else {
            KeychainPresence::Absent
        }
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.load.fetch_add(1, Ordering::Relaxed);
        self.value
            .lock()
            .expect("secret lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn load_xai_key_without_ui(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.load_without_ui.fetch_add(1, Ordering::Relaxed);
        self.value
            .lock()
            .expect("secret lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String> {
        self.counts.store.fetch_add(1, Ordering::Relaxed);
        *self.value.lock().expect("secret lock") = Some(key.as_slice().to_vec());
        Ok(())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        *self.value.lock().expect("secret lock") = None;
        Ok(())
    }
}

static NEXT_RUNTIME_TEST: AtomicUsize = AtomicUsize::new(1);

fn runtime_fixture_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "grok-build-runtime-{label}-{}-{}",
        std::process::id(),
        NEXT_RUNTIME_TEST.fetch_add(1, Ordering::Relaxed)
    ));
    crate::runtime::engine::EngineSettings::default()
        .save(&root)
        .expect("contained transport fixture");
    root
}

#[test]
fn persisted_binding_requires_one_exact_non_placeholder_public_identity() {
    let identity = "A38B0F65923F277B3EBB2FA6887FFCD9F6C96E0D";
    assert!(!binding_matches_identity(None, None));
    assert!(!binding_matches_identity(Some(identity), None));
    assert!(!binding_matches_identity(None, Some(identity)));
    assert!(!binding_matches_identity(
        Some(identity),
        Some("0123456789ABCDEF0123456789ABCDEF01234567")
    ));
    assert!(binding_matches_identity(Some(identity), Some(identity)));
}

struct StubAdapter {
    transport: RuntimeTransport,
    probe_result: Mutex<Option<Result<AdapterProbe, String>>>,
    fail_teardown: bool,
}

impl LiveRuntimeAdapter for StubAdapter {
    fn transport(&self) -> RuntimeTransport {
        self.transport
    }
    fn probe(&mut self, _events: &RuntimeEventSink<'_>) -> Result<AdapterProbe, AdapterFailure> {
        self.probe_result
            .lock()
            .expect("probe result")
            .take()
            .expect("one probe")
            .map_err(AdapterFailure::protocol)
    }
    fn start_or_restore_session(
        &mut self,
        _provider_session_id: Option<&ProviderSessionId>,
    ) -> Result<AdapterSession, AdapterFailure> {
        Ok(AdapterSession {
            provider_session_id: None,
        })
    }
    fn send_turn(
        &mut self,
        _context: &AdapterContext<'_>,
        _prompt: &str,
        _image: Option<&AdapterImage<'_>>,
        _steering: &RuntimeSteeringSource<'_>,
        _events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        Ok(AdapterTurn {
            assistant_text: "live".into(),
            pending: PendingFileSet::default(),
            provider_session_id: None,
            usage: Some(RuntimeUsage::default()),
            outcome: AdapterTurnOutcome::Completed,
        })
    }
    fn continue_with_tool_results(
        &mut self,
        _context: &AdapterContext<'_>,
        _events: &RuntimeEventSink<'_>,
    ) -> Result<AdapterTurn, AdapterFailure> {
        Err(AdapterFailure::protocol("not applicable"))
    }
    fn cancel_run(&mut self) -> Result<(), String> {
        if self.fail_teardown {
            Err("fixture cancel failure".into())
        } else {
            Ok(())
        }
    }
    fn close_session(&mut self) -> Result<(), String> {
        if self.fail_teardown {
            Err("fixture close failure".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn failed_selected_transport_never_falls_back_or_becomes_connected() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::XaiKeychain,
        probe_result: Mutex::new(Some(Err("representative live failure".into()))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::XaiKeychain,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    let error = manager.connect(&|_| Ok(())).expect_err("probe must fail");
    assert_eq!(error, "representative live failure");
    assert!(matches!(
        manager.connection(),
        ConnectionState::Failed {
            transport: RuntimeTransport::XaiKeychain,
            ..
        }
    ));
    assert_eq!(manager.selected(), RuntimeTransport::XaiKeychain);
}

#[test]
fn read_aloud_reuses_the_connected_credential_lease() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture".into(),
        }))),
        fail_teardown: false,
    };
    let (secrets, counts) = CountingSecrets::present();
    let mut manager =
        RuntimeManager::with_adapter(RuntimeTransport::GrokCliAcp, secrets, Box::new(adapter));
    manager
        .ensure_xai_credential_lease()
        .expect("explicitly opened API-key lease");
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::GrokCliAcp,
        model: "fixture".into(),
        verified_at: 1,
    };
    let credential = manager
        .read_aloud_credential()
        .expect("broker API key is the mixed-session TTS credential");
    assert_eq!(credential.source(), ReadAloudCredentialSource::ApiKey);
    assert_eq!(counts.load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 0);
    assert_eq!(manager.selected, RuntimeTransport::GrokCliAcp);
    assert!(matches!(
        manager.connection,
        ConnectionState::Connected {
            transport: RuntimeTransport::GrokCliAcp,
            ..
        }
    ));
}

#[test]
fn acp_without_separate_direct_tts_credential_stays_disabled_with_exact_reason() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::GrokCliAcp,
        model: "fixture".into(),
        verified_at: 2,
    };
    manager.read_aloud_failure = Some(GROK_CLI_ACP_NO_TTS_REASON.into());
    let reason = manager
        .read_aloud_credential()
        .expect_err("ACP itself must not become a TTS credential path");
    assert_eq!(reason, GROK_CLI_ACP_NO_TTS_REASON);
}

#[test]
fn startup_constructs_runtime_without_keychain_requests() {
    let (secrets, counts) = CountingSecrets::present();
    let manager = RuntimeManager::with_secret_store(PathBuf::from("/not-used"), secrets);
    assert_eq!(manager.keychain_presence, KeychainPresence::Unchecked);
    assert_eq!(counts.inspect.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 0);
}

#[test]
fn snapshot_and_event_fanout_never_read_xai_keychain_secret() {
    let (secrets, counts) = CountingSecrets::present();
    let manager = RuntimeManager::with_secret_store(PathBuf::from("/not-used"), secrets);
    for _ in 0..512 {
        let snapshot = manager.snapshot();
        assert_eq!(snapshot.keychain_presence, KeychainPresence::Unchecked);
    }
    assert_eq!(
        counts.load.load(Ordering::Relaxed),
        0,
        "snapshot and event fanout must never request secret data"
    );
    assert_eq!(
        counts.inspect.load(Ordering::Relaxed),
        0,
        "presence remains honestly unchecked without automatic inspection"
    );
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 0);
}

#[test]
fn grok_cli_selection_never_reads_keychain_and_preserves_its_broker_binding() {
    let (secrets, counts) = CountingSecrets::present();
    let root = runtime_fixture_root("cli-selection-no-keychain");
    let mut manager = RuntimeManager::with_secret_store(root.clone(), secrets);
    let broker_sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
    manager
        .select(RuntimeTransport::XaiKeychain)
        .expect("select API-key transport without opening its secret");
    manager.keychain_broker_sha256 = Some(broker_sha.clone());

    manager
        .select(RuntimeTransport::GrokCliAcp)
        .expect("select CLI without touching provider key");
    manager
        .disconnect()
        .expect("disconnect CLI without touching provider key");
    assert_eq!(manager.keychain_broker_sha256.as_ref(), Some(&broker_sha));
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.store.load(Ordering::Relaxed), 0);

    drop(manager);
    let saved = AccountPreferenceStore::new(root.clone())
        .load()
        .expect("load Account preferences")
        .expect("saved Account preferences");
    assert_eq!(saved.keychain_broker_sha256.as_ref(), Some(&broker_sha));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn explicit_transport_selection_survives_restart_without_connected_claim() {
    let root = runtime_fixture_root("selected-transport-restart");
    let mut first = RuntimeManager::offline(root.clone());
    first
        .select(RuntimeTransport::XaiKeychain)
        .expect("persist explicit selection");
    assert!(matches!(first.connection(), ConnectionState::Disconnected));
    drop(first);

    let restored = RuntimeManager::offline(root.clone());
    assert_eq!(restored.selected(), RuntimeTransport::XaiKeychain);
    assert!(matches!(
        restored.connection(),
        ConnectionState::Disconnected
    ));
    assert!(!restored.snapshot().onboarding_acknowledged);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn onboarding_acknowledgement_stops_first_run_redirect_after_restart() {
    let root = runtime_fixture_root("onboarding-restart");
    let mut first = RuntimeManager::offline(root.clone());
    first
        .acknowledge_onboarding()
        .expect("persist onboarding acknowledgement");
    drop(first);

    let restored = RuntimeManager::offline(root.clone()).snapshot();
    assert!(restored.onboarding_acknowledged);
    assert!(matches!(restored.connection, ConnectionState::Disconnected));
    assert!(restored.account_preference_issue.is_none());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn saved_key_connect_reads_once_and_never_stores_or_prompts_during_send() {
    let (secrets, counts) = CountingSecrets::present();
    let adapter = StubAdapter {
        transport: RuntimeTransport::XaiKeychain,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager =
        RuntimeManager::with_adapter(RuntimeTransport::XaiKeychain, secrets, Box::new(adapter));
    manager
        .ensure_xai_credential_lease()
        .expect("explicit saved-key open");
    manager.connect(&|_| Ok(())).expect("live probe");

    let root = runtime_fixture_root("saved-key-send");
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let bound = bind_project_folder(&workspace).expect("bind");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    manager
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "hello",
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .expect("send through already-open lease");
    assert_eq!(counts.load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.store.load(Ordering::Relaxed), 0);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn corrupt_account_preferences_fail_disconnected_without_silent_transport_switch() {
    use crate::runtime::account_preferences::{
        ACCOUNT_PREFERENCES_FILE, AccountPreferenceStore, AccountPreferences,
    };

    let root = runtime_fixture_root("corrupt-account-preferences");
    AccountPreferenceStore::new(root.clone())
        .save(AccountPreferences {
            selected_transport: RuntimeTransport::XaiKeychain,
            onboarding_acknowledged: true,
            ..AccountPreferences::default()
        })
        .expect("seed preferences");
    fs::write(root.join(ACCOUNT_PREFERENCES_FILE), b"not-json").expect("corrupt preferences");

    let mut manager = RuntimeManager::offline(root.clone());
    let refused = manager.snapshot();
    assert_eq!(refused.selected_transport, RuntimeTransport::GrokCliAcp);
    assert!(matches!(refused.connection, ConnectionState::Disconnected));
    assert!(!refused.onboarding_acknowledged);
    assert!(
        refused
            .account_preference_issue
            .as_deref()
            .is_some_and(|issue| issue.contains("were refused"))
    );

    manager
        .select(RuntimeTransport::XaiKeychain)
        .expect("explicit selection repairs preference record");
    drop(manager);
    let repaired = RuntimeManager::offline(root.clone()).snapshot();
    assert_eq!(repaired.selected_transport, RuntimeTransport::XaiKeychain);
    assert!(matches!(repaired.connection, ConnectionState::Disconnected));
    assert!(repaired.account_preference_issue.is_none());
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn child_runtime_forks_inherit_only_mediated_provider_authentication() {
    use grok_build_plus_host::PlusRuntimeToolPolicy;
    let (secrets, counts) = CountingSecrets::present();
    let root = runtime_fixture_root("child-authority");
    let mut manager = RuntimeManager::with_secret_store(root.clone(), secrets);
    manager.selected = RuntimeTransport::XaiKeychain;
    manager.ensure_xai_credential_lease().unwrap();
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::XaiKeychain,
        model: "fixture-model".into(),
        verified_at: 1,
    };
    manager.attach_browser(BrowserManager::new(&root));
    manager.attach_capture(CaptureManager::production());
    manager.attach_desktop(DesktopManager::production());
    manager.attach_mcp(crate::extensions::mcp::broker::McpBroker::new(&root));
    let mut leases = Vec::new();
    for role in [
        PlusRuntimeToolPolicy::Explore,
        PlusRuntimeToolPolicy::Plan,
        PlusRuntimeToolPolicy::Worker,
    ] {
        let mut child = manager
            .fork_connected_transport_for_run(root.join("child-runtime"), role)
            .unwrap();
        assert!(
            child.browser.is_none()
                && child.capture.is_none()
                && child.desktop.is_none()
                && child.mcp.is_none()
        );
        assert!(child.credential_broker.is_none() && child.read_aloud_credential.is_none());
        assert_eq!(child.child_executor().unwrap().unwrap().tool_policy(), role);
        assert_eq!(
            child.build_selected_adapter().unwrap().transport(),
            RuntimeTransport::XaiKeychain
        );
        leases.push(child.credential_lease.as_ref().unwrap().clone());
        for requested in [
            PlusRuntimeToolPolicy::Parent,
            PlusRuntimeToolPolicy::Explore,
        ] {
            assert!(
                child
                    .fork_connected_transport_for_run(root.join("forbidden-fork"), requested)
                    .is_err()
            );
        }
        child.mcp.clone_from(&manager.mcp);
        assert!(child.build_selected_adapter().is_err());
    }
    assert_eq!(counts.load.load(Ordering::Relaxed), 1);
    manager.disconnect().unwrap();
    assert!(leases.iter().all(|lease| lease.ensure_active().is_err()));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn child_factory_preserves_frozen_hook_restrictions_without_mcp_authority() {
    use crate::contracts::{ProjectId, RunId, SessionId, WorkspaceId};
    use crate::queue::children::{ChildRecord, ChildState};
    let root = runtime_fixture_root("child-hooks");
    fs::create_dir_all(&root).unwrap();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    let project = ProjectId::new("hook-project");
    let mut manager = RuntimeManager::offline(root.clone());
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::GrokCliAcp,
        model: "fixture".into(),
        verified_at: 1,
    };
    manager.hook_policy = Some(crate::extensions::hooks::FrozenHookPolicy::fixture(
        project.clone(),
        root.clone(),
    ));
    manager.attach_mcp(crate::extensions::mcp::broker::McpBroker::new(&root));
    let template = manager
        .child_runtime_template(root.join("template"))
        .unwrap();
    assert!(template.mcp.is_none() && template.hook_policy.is_some());
    let mut record = ChildRecord {
        id: RunId::new("child"),
        agent_id: RunId::new("child"),
        parent: RunId::new("parent"),
        project,
        workspace: WorkspaceId::new("isolated"),
        session: SessionId::new("child-session"),
        role: grok_build_plus_host::PlusChildRole::Plan,
        snapshot: "a".repeat(64),
        isolated: true,
        transport: RuntimeTransport::GrokCliAcp,
        invocation: "b".repeat(64),
        predecessor: None,
        transient: false,
        review_pending: false,
        state: ChildState::Waiting,
        created_at_unix_ms: 1,
        ended_at_unix_ms: None,
    };
    let bound = grok_build_plus_host::bind_project_folder(source).unwrap();
    let child = template
        .prepare_child_runtime(&root, &record, &bound, RuntimeCancelHandle::new())
        .unwrap();
    assert!(
        child.mcp.is_none() && child.credential_broker.is_none() && child.hook_policy.is_some()
    );
    assert!(
        child.prepare_hooks().is_err(),
        "An enabled hook with unavailable containment cannot disappear from a child"
    );
    record.project = ProjectId::new("other-project");
    let crossed = template
        .prepare_child_runtime(&root, &record, &bound, RuntimeCancelHandle::new())
        .unwrap();
    assert!(crossed.prepare_hooks().err().unwrap().contains("crossed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn disconnect_revokes_xai_credential_across_run_forks() {
    let (secrets, counts) = CountingSecrets::present();
    let root = runtime_fixture_root("disconnect-revocation");
    let mut manager = RuntimeManager::with_secret_store(root.clone(), secrets);
    manager.selected = RuntimeTransport::XaiKeychain;
    manager
        .ensure_xai_credential_lease()
        .expect("explicit credential open");
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::XaiKeychain,
        model: "fixture-model".into(),
        verified_at: 1,
    };
    let owner_lease = manager
        .credential_lease
        .as_ref()
        .expect("owner lease")
        .clone();
    let mut project_a = manager
        .fork_connected_transport_for_run(
            PathBuf::from("/not-used/a"),
            grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )
        .expect("project A fork");
    let project_b = manager
        .fork_connected_transport_for_run(
            PathBuf::from("/not-used/b"),
            grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )
        .expect("project B fork");
    let project_b_lease = project_b
        .credential_lease
        .as_ref()
        .expect("project B lease")
        .clone();

    project_a.disconnect().expect("borrower disconnect");
    assert!(owner_lease.is_active());
    assert!(
        project_b_lease.is_active(),
        "one completed project run must not revoke another project"
    );

    manager.disconnect().expect("Account owner disconnect");
    assert!(owner_lease.ensure_active().is_err());
    assert!(project_b_lease.ensure_active().is_err());
    assert_eq!(counts.load.load(Ordering::Relaxed), 1);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn failed_probe_revokes_credential_and_never_becomes_connected() {
    let (secrets, counts) = CountingSecrets::present();
    let adapter = StubAdapter {
        transport: RuntimeTransport::XaiKeychain,
        probe_result: Mutex::new(Some(Err("representative live failure".into()))),
        fail_teardown: false,
    };
    let mut manager =
        RuntimeManager::with_adapter(RuntimeTransport::XaiKeychain, secrets, Box::new(adapter));
    manager
        .ensure_xai_credential_lease()
        .expect("explicit credential open");
    let lease = manager
        .credential_lease
        .as_ref()
        .expect("active lease")
        .clone();
    let error = manager.connect(&|_| Ok(())).expect_err("probe must fail");
    assert_eq!(error, "representative live failure");
    assert!(matches!(
        manager.connection(),
        ConnectionState::Failed {
            transport: RuntimeTransport::XaiKeychain,
            ..
        }
    ));
    assert!(lease.ensure_active().is_err());
    assert_eq!(counts.load.load(Ordering::Relaxed), 1);
}

#[test]
fn send_requires_the_same_live_probed_transport() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.connect(&|_| Ok(())).expect("probe");
    let root = std::env::temp_dir().join(format!(
        "grok-build-plus-runtime-manager-{}",
        std::process::id()
    ));
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let bound = bind_project_folder(&workspace).expect("bind");
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let turn = manager
        .send_turn(
            &AdapterContext {
                scope: crate::runtime::types::RuntimeInvocationScope::fixture(),
                extension_context: "",
                hooks: None,
                bound: &bound,
                store: &store,
            },
            "hello",
            &|_| Ok(Vec::new()),
            &|_| Ok(()),
        )
        .expect("live turn");
    assert_eq!(turn.assistant_text, "live");
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn queued_fork_inherits_exact_live_verification_without_a_probe_adapter() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.connect(&|_| Ok(())).expect("live probe");
    let fork = manager
        .fork_connected_transport_for_run(
            PathBuf::from("/not-used/queued-run"),
            grok_build_plus_host::PlusRuntimeToolPolicy::Parent,
        )
        .expect("fork connected transport");
    assert!(matches!(
        fork.connection,
        ConnectionState::Connected {
            transport: RuntimeTransport::GrokCliAcp,
            ref model,
            ..
        } if model == "fixture-model"
    ));
    assert!(fork.adapter.is_none());
    assert_eq!(fork.selected, RuntimeTransport::GrokCliAcp);
}

#[test]
fn teardown_failure_clears_connected_before_returning_error() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: true,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.connect(&|_| Ok(())).expect("connect fixture");
    assert!(manager.connection().connected());
    assert!(manager.disconnect().is_err());
    assert!(matches!(
        manager.connection(),
        ConnectionState::Disconnected
    ));
    assert!(manager.adapter.is_none());
    assert!(
        manager
            .fork_connected_transport_for_run(
                PathBuf::from("/not-used"),
                grok_build_plus_host::PlusRuntimeToolPolicy::Parent
            )
            .is_err(),
        "stale Connected must not authorize a queued fork"
    );
}

#[test]
fn automatic_reconnect_is_one_attempt_and_never_renews_the_fixed_grant() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    let authorized_at = unix_time_millis().saturating_sub(1_000);
    let grant =
        ReconnectGrant::fixed(RuntimeTransport::GrokCliAcp, authorized_at).expect("fixed grant");
    manager.reconnect_grant = Some(grant);

    manager
        .reconnect_authorized(&|_| Ok(()))
        .expect("one automatic reconnect");
    assert!(manager.connection().connected());
    assert_eq!(manager.reconnect_grant, Some(grant));
    assert!(manager.reconnect_authorized(&|_| Ok(())).is_err());
    assert_eq!(manager.reconnect_grant, Some(grant));
}

#[test]
fn runtime_clock_rollback_clears_grant_and_never_probes() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "must-not-probe".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.reconnect_grant = Some(
        ReconnectGrant::fixed(
            RuntimeTransport::GrokCliAcp,
            unix_time_millis().saturating_add(60_000),
        )
        .expect("future fixture"),
    );
    let error = manager
        .reconnect_authorized(&|_| Ok(()))
        .expect_err("clock rollback must refuse");
    assert!(error.contains("clock rollback"));
    assert!(manager.reconnect_grant.is_none());
    assert!(!manager.auto_reconnect_attempted);
}

#[test]
fn unlock_exposes_reconnecting_then_probes_once_and_ignores_duplicates() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.reconnect_grant = Some(
        ReconnectGrant::fixed(RuntimeTransport::GrokCliAcp, unix_time_millis()).expect("grant"),
    );
    manager.suspended_for_lock = true;
    assert!(manager.begin_unlock_reconnect().expect("begin unlock"));
    assert!(matches!(
        manager.reconnect_state_at(unix_time_millis()),
        ReconnectState::Reconnecting {
            transport: RuntimeTransport::GrokCliAcp
        }
    ));
    manager
        .finish_unlock_reconnect(&|_| Ok(()))
        .expect("finish unlock probe");
    assert!(manager.connection().connected());
    assert!(!manager.begin_unlock_reconnect().expect("duplicate unlock"));
}

#[test]
fn toggle_off_clears_grant_and_toggle_on_while_connected_renews() {
    let adapter = StubAdapter {
        transport: RuntimeTransport::GrokCliAcp,
        probe_result: Mutex::new(Some(Ok(AdapterProbe {
            model: "fixture-model".into(),
        }))),
        fail_teardown: false,
    };
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(adapter),
    );
    manager.connect(&|_| Ok(())).expect("explicit connect");
    assert!(manager.reconnect_grant.is_some());
    manager
        .set_auto_reconnect(false)
        .expect("disable reconnect");
    assert!(manager.reconnect_grant.is_none());
    assert_eq!(
        manager.reconnect_state_at(unix_time_millis()),
        ReconnectState::Disabled
    );
    manager
        .set_auto_reconnect(true)
        .expect("renew while connected");
    assert!(matches!(
        manager.reconnect_state_at(unix_time_millis()),
        ReconnectState::Active { .. }
    ));
}

#[test]
fn typed_auth_failure_clears_grant_but_rate_limit_retains_it() {
    let mut manager = RuntimeManager::with_adapter(
        RuntimeTransport::GrokCliAcp,
        Arc::new(EmptySecrets),
        Box::new(StubAdapter {
            transport: RuntimeTransport::GrokCliAcp,
            probe_result: Mutex::new(Some(Ok(AdapterProbe {
                model: "unused".into(),
            }))),
            fail_teardown: false,
        }),
    );
    let grant = ReconnectGrant::fixed(RuntimeTransport::GrokCliAcp, unix_time_millis())
        .expect("fixed grant");
    manager.reconnect_grant = Some(grant);
    let rate = AdapterFailure::new(AdapterFailureKind::RateLimit, "rate limited");
    manager.record_run_failure(RuntimeTransport::GrokCliAcp, &rate.reason, Some(&rate));
    assert_eq!(manager.reconnect_grant, Some(grant));
    let authentication =
        AdapterFailure::new(AdapterFailureKind::Authentication, "authentication refused");
    manager.record_run_failure(
        RuntimeTransport::GrokCliAcp,
        &authentication.reason,
        Some(&authentication),
    );
    assert!(manager.reconnect_grant.is_none());
}

#[test]
fn synthetic_lock_revokes_xai_lease_without_erasing_the_grant() {
    let root = runtime_fixture_root("lock-revocation");
    fs::create_dir_all(&root).expect("fixture root");
    let (secrets, _) = CountingSecrets::present();
    let mut manager = RuntimeManager::with_secret_store(root.clone(), secrets);
    manager.selected = RuntimeTransport::XaiKeychain;
    manager
        .ensure_xai_credential_lease()
        .expect("open stable credential");
    let lease = manager.credential_lease.as_ref().expect("lease").clone();
    manager.connection = ConnectionState::Connected {
        transport: RuntimeTransport::XaiKeychain,
        model: "fixture-model".into(),
        verified_at: unix_time_millis(),
    };
    manager.reconnect_grant = Some(
        ReconnectGrant::fixed(RuntimeTransport::XaiKeychain, unix_time_millis()).expect("grant"),
    );
    manager.suspend_for_lock().expect("suspend for lock");
    assert!(!lease.is_active());
    assert!(manager.reconnect_grant.is_some());
    assert_eq!(
        manager.reconnect_state_at(unix_time_millis()),
        ReconnectState::SuspendedForLock
    );
    fs::remove_dir_all(root).expect("cleanup");
}
