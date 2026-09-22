//! Opt-in existing-account fixture: synthetic context and workspace reads only.
use super::*;
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!(
            "gbplus-native-continuity-{}-{}",
            std::process::id(),
            super::super::types::unix_time_millis()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn adapter(
    credential: XaiCredentialLease,
    root: &std::path::Path,
    protocol: super::super::native_protocol::NativeProtocol,
) -> XaiKeychainAdapter {
    let executor = crate::runtime::role_tools::ChildTools::new(
        grok_build_plus_host::PlusRuntimeToolPolicy::Explore,
    )
    .unwrap();
    let mut adapter = XaiKeychainAdapter::new_with_external(
        credential,
        RuntimeCancelHandle::new(),
        Arc::new(executor),
    );
    adapter.bind_context_root(root);
    adapter.configure_native_protocol(protocol).unwrap();
    adapter
}
pub(super) fn continuity(credential: &XaiCredentialLease) {
    for protocol in [
        super::super::native_protocol::NativeProtocol::Http,
        super::super::native_protocol::NativeProtocol::WebSocket,
    ] {
        continuity_using(credential, protocol);
    }
}
fn continuity_using(
    credential: &XaiCredentialLease,
    protocol: super::super::native_protocol::NativeProtocol,
) {
    use std::io::Read as _;
    let fixture = Fixture::new();
    let workspace = fixture.0.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let mut entropy = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut entropy)
        .unwrap();
    let user_marker = fictional_name(&entropy[..8]);
    let file_marker = fictional_name(&entropy[16..24]);
    std::fs::write(
        workspace.join("facts.txt"),
        format!("The imaginary book title is {file_marker}.\n"),
    )
    .unwrap();
    let bound = grok_build_plus_host::bind_project_folder(&workspace).unwrap();
    let store = PlusSessionStore::from_state_root(fixture.0.join("store"));
    let context = AdapterContext {
        scope: super::super::types::RuntimeInvocationScope::fixture(),
        bound: &bound,
        store: &store,
        extension_context: "",
        hooks: None,
    };
    let provider_root = fixture.0.join("provider");
    let mut live = adapter(credential.clone(), &provider_root, protocol);
    let session = live
        .start_or_restore_session(None)
        .unwrap()
        .provider_session_id
        .unwrap();
    let reads = std::sync::atomic::AtomicUsize::new(0);
    let events = |event| {
        if matches!(event,RuntimeEvent::ToolCompleted {ref name,..} if name=="read_file") {
            reads.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    };
    let first=live.send_turn(&context,&format!("For a fictional library inventory, the room name is {user_marker}. Read facts.txt to learn the imaginary book title. Keep both names for our conversation and reply briefly after reading."),None,&|_|Ok(Vec::new()),&events).unwrap();
    assert_eq!(first.outcome, AdapterTurnOutcome::Completed);
    assert!(first.pending.items.is_empty());
    assert!(
        reads.load(Ordering::Relaxed) > 0,
        "provider must read the unique file marker through the app tool"
    );
    std::fs::remove_file(workspace.join("facts.txt")).unwrap();
    let completed_reads = reads.load(Ordering::Relaxed);
    let prompt = "What are the room name and book title in the fictional library inventory we just discussed? Use our conversation only; the source file is no longer available.";
    for restarted in [false, true] {
        if restarted {
            live.close_session().unwrap();
            live = adapter(credential.clone(), &provider_root, protocol);
            assert_eq!(
                live.start_or_restore_session(Some(&session))
                    .unwrap()
                    .provider_session_id,
                Some(session.clone())
            );
        }
        let turn = live
            .send_turn(&context, prompt, None, &|_| Ok(Vec::new()), &events)
            .unwrap();
        assert_eq!(turn.outcome, AdapterTurnOutcome::Completed);
        assert!(
            turn.assistant_text.to_lowercase().contains(&user_marker),
            "user marker was not retained; restarted={restarted}"
        );
        assert!(
            turn.assistant_text.to_lowercase().contains(&file_marker),
            "recorded tool result was not retained; restarted={restarted}"
        );
        assert_eq!(
            reads.load(Ordering::Relaxed),
            completed_reads,
            "continuation must reuse context without reading the removed file"
        );
        assert!(turn.pending.items.is_empty());
    }
    live.close_session().unwrap();
    eprintln!(
        "Native continuity: {protocol:?}, two turns and reconstructed adapter, exact user/file facts, no reread or proposal."
    );
}

fn fictional_name(entropy: &[u8]) -> String {
    const WORDS: [&str; 16] = [
        "amber", "brook", "cedar", "delta", "elm", "fern", "grove", "hazel", "iris", "juniper",
        "lake", "maple", "oak", "pine", "reed", "willow",
    ];
    entropy
        .iter()
        .map(|byte| WORDS[usize::from(byte & 15)])
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn collaboration(credential: &XaiCredentialLease) {
    let fixture = Fixture::new();
    let mut runtime = crate::runtime::manager::RuntimeManager::native_live_fixture(
        fixture.0.join("account"),
        credential.clone(),
    )
    .unwrap();
    crate::workflows::live_fixture::qualify(&fixture.0, &runtime);
    crate::collaboration::live_fixture::qualify(&fixture.0, &runtime);
    crate::collaboration::live_parent::qualify(&fixture.0, &runtime);
    runtime.disconnect().unwrap();
}
