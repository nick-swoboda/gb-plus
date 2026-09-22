use super::*;
use crate::contracts::ProjectId;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn hooks_default_off_are_project_bound_and_keep_the_reviewed_content_after_source_changes() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.source.join("bin")).unwrap();
    std::fs::create_dir(fixture.source.join("hooks")).unwrap();
    let mut image = vec![0; 64];
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    image[16] = 3;
    image[18] = 183;
    std::fs::write(fixture.source.join("bin/guard"), image).unwrap();
    std::fs::set_permissions(
        fixture.source.join("bin/guard"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(fixture.source.join("hooks/hooks.json"), br#"{"hooks":{"PreToolUse":[{"matcher":"propose_write","hooks":[{"type":"command","command":"bin/guard","args":["--hook"]}]}]}}"#).unwrap();
    let preview = fixture.preview();
    let hook = preview
        .components
        .iter()
        .find(|c| c.name == "hooks")
        .unwrap();
    assert!(hook.quarantine.is_none());
    fixture.store.install(&preview.digest).unwrap();
    let project = ProjectId::new("hook-project");
    assert!(fixture.store.enabled_hooks(&project).unwrap().is_empty());
    fixture
        .store
        .set_enabled(&project, &preview.digest, &hook.id, true)
        .unwrap();
    let frozen = fixture.store.enabled_hooks(&project).unwrap();
    assert_eq!(frozen.len(), 1);
    assert!(
        fixture
            .store
            .enabled_hooks(&ProjectId::new("other-project"))
            .unwrap()
            .is_empty()
    );
    std::fs::write(
        fixture.source.join("hooks/hooks.json"),
        "unreviewed replacement",
    )
    .unwrap();
    assert_eq!(fixture.store.enabled_hooks(&project).unwrap().len(), 1);
    fixture
        .store
        .set_enabled(&project, &preview.digest, &hook.id, false)
        .unwrap();
    assert!(fixture.store.enabled_hooks(&project).unwrap().is_empty());
    assert_eq!(
        frozen.len(),
        1,
        "The admitted run retains its immutable selected version."
    );
}

#[test]
fn mcp_inspection_uses_frozen_content_and_execution_requires_explicit_project_enablement() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.source.join(".mcp.json"),
        br#"{"mcpServers":{"docs":{"type":"http","url":"https://example.com/mcp"}}}"#,
    )
    .unwrap();
    let preview = fixture.preview();
    let component = preview
        .components
        .iter()
        .find(|c| c.name == "mcpServers")
        .unwrap();
    let project = ProjectId::new("mcp-project");
    assert!(
        fixture
            .store
            .mcp_servers(&project, &preview.digest, &component.id)
            .is_err()
    );
    fixture.store.install(&preview.digest).unwrap();
    assert!(component.quarantine.is_none());
    assert!(
        fixture
            .store
            .enabled_mcp_servers(&project)
            .unwrap()
            .is_empty()
    );
    std::fs::write(
        fixture.source.join(".mcp.json"),
        br#"{"mcpServers":{"docs":{"command":"/bin/sh"}}}"#,
    )
    .unwrap();
    let entries = fixture
        .store
        .mcp_servers(&project, &preview.digest, &component.id)
        .unwrap();
    assert_eq!(
        entries[0].1.as_ref().unwrap().endpoint,
        "https://example.com/mcp"
    );
    fixture
        .store
        .set_enabled(&project, &preview.digest, &component.id, true)
        .unwrap();
    let enabled = fixture.store.enabled_mcp_servers(&project).unwrap();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].endpoint, "https://example.com/mcp");
    assert!(
        fixture
            .store
            .enabled_mcp_servers(&ProjectId::new("other-project"))
            .unwrap()
            .is_empty()
    );
    fixture
        .store
        .set_enabled(&project, &preview.digest, &component.id, false)
        .unwrap();
    assert!(
        fixture
            .store
            .enabled_mcp_servers(&project)
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .store
            .mcp_servers(&project, &preview.digest, &"0".repeat(64))
            .is_err()
    );
}

struct Fixture {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    source: PathBuf,
    store: ExtensionStore,
}
impl Fixture {
    fn new() -> Self {
        let serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let root = std::env::temp_dir().join(format!(
            "gbplus-extension-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir_all(source.join("skills/facts")).unwrap();
        std::fs::write(source.join("plugin.json"), br#"{"name":"fixture-plugin","version":"1.0.0","license":"MIT","description":"Inert fixture"}"#).unwrap();
        std::fs::write(
            source.join("LICENSE"),
            "MIT license fixture, not a published license grant",
        )
        .unwrap();
        std::fs::write(
            source.join("skills/facts/SKILL.md"),
            "# Facts\nUse cobalt = 42. [Guide](guide.md)",
        )
        .unwrap();
        std::fs::write(
            source.join("skills/facts/guide.md"),
            "Preserve exact facts.",
        )
        .unwrap();
        let store = ExtensionStore::new(&root.join("state"));
        Self {
            _serial: serial,
            root: root.canonicalize().unwrap(),
            source: source.canonicalize().unwrap(),
            store,
        }
    }
    fn preview(&self) -> ExtensionPreview {
        self.store.preview_local(&self.source).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn preview_install_and_project_enablement_are_separate_and_frozen_across_source_edits() {
    let f = Fixture::new();
    let project = ProjectId::new("project-one");
    let preview = f.preview();
    let skill = &preview
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::Skills)
        .unwrap()
        .id;
    assert!(f.store.skill_context(&project).unwrap().is_empty());
    assert!(
        f.store
            .set_enabled(&project, &preview.digest, skill, true)
            .is_err()
    );
    f.store.install(&preview.digest).unwrap();
    assert!(f.store.skill_context(&project).unwrap().is_empty());
    f.store
        .set_enabled(&project, &preview.digest, skill, true)
        .unwrap();
    std::fs::write(
        f.source.join("skills/facts/SKILL.md"),
        "modified outside the app",
    )
    .unwrap();
    let pinned = f.store.skill_context(&project).unwrap();
    assert!(pinned.contains("cobalt = 42"));
    assert!(pinned.contains("Preserve exact facts."));
    assert!(!pinned.contains("modified outside"));
    assert!(
        f.store
            .skill_context(&ProjectId::new("project-two"))
            .unwrap()
            .is_empty()
    );
    let restored = ExtensionStore::new(&f.root.join("state"));
    assert_eq!(restored.skill_context(&project).unwrap(), pinned);
    f.store
        .set_enabled(&project, &preview.digest, skill, false)
        .unwrap();
    assert!(f.store.skill_context(&project).unwrap().is_empty());
    assert!(pinned.contains("cobalt = 42"));
}

#[test]
fn custom_auth_paths_refuse_before_local_preview_persistence() {
    const CHILD: &str = "GB_PLUS_AUTH_PREVIEW_FIXTURE";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let store = ExtensionStore::new(&root.join("state"));
        assert!(
            store.preview_local(&root.join("source")).is_err(),
            "A local source containing the configured authentication file must be refused before copying."
        );
        assert!(!root.join("state/extensions-v1/metadata.json").exists());
        return;
    }
    let fixture = Fixture::new();
    let auth = fixture.source.join("custom-login.data");
    std::fs::write(
        &auth,
        b"SYNTHETIC authentication fixture; no real credential",
    )
    .unwrap();
    // A separate test process gives the production once-resolved auth path its
    // own deterministic environment without modifying this process's globals.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "extensions::tests::custom_auth_paths_refuse_before_local_preview_persistence",
            "--nocapture",
        ])
        .env(CHILD, &fixture.root)
        .env("GROK_AUTH_PATH", auth)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn newly_protected_cached_origins_remain_visible_and_can_be_disabled_without_loading() {
    const CHILD: &str = "GB_PLUS_CACHED_ORIGIN_FIXTURE";
    let project = ProjectId::new("protected-origin-project");
    if let Some(root) = std::env::var_os(CHILD) {
        let store = ExtensionStore::new(&PathBuf::from(root).join("state"));
        let view = serde_json::to_value(store.view(&project).unwrap()).unwrap();
        let entry = &view["extensions"][0];
        let digest = entry["preview"]["digest"].as_str().unwrap();
        let component = entry["enabledComponents"][0].as_str().unwrap();
        assert!(entry["preview"]["components"][0]["quarantine"].is_string());
        assert!(store.skill_context(&project).is_err());
        store
            .set_enabled(&project, digest, component, false)
            .unwrap();
        assert!(store.skill_context(&project).unwrap().is_empty());
        assert!(
            store
                .set_enabled(&project, digest, component, true)
                .is_err()
        );
        assert!(
            store
                .skill_context(&ProjectId::new("other-project"))
                .unwrap()
                .is_empty()
        );
        return;
    }
    let fixture = Fixture::new();
    let preview = fixture.preview();
    fixture.store.install(&preview.digest).unwrap();
    let component = &preview
        .components
        .iter()
        .find(|component| component.kind == ComponentKind::Skills)
        .unwrap()
        .id;
    fixture
        .store
        .set_enabled(&project, &preview.digest, component, true)
        .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "extensions::tests::newly_protected_cached_origins_remain_visible_and_can_be_disabled_without_loading", "--nocapture"])
        .env(CHILD, &fixture.root)
        .env("GROK_AUTH_PATH", fixture.source.join("future-login.data"))
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn quarantined_native_mcp_cannot_bypass_admission_through_catalog_inspection() {
    let fixture = Fixture::new();
    std::fs::remove_file(fixture.source.join("LICENSE")).unwrap();
    std::fs::write(fixture.source.join("plugin.json"), br#"{"name":"fixture-plugin","version":"1.0.0","mcpServers":{"local":{"type":"stdio","command":"server"}}}"#).unwrap();
    // Header-shaped metadata fixture only; this test never starts a process.
    let mut bytes = [0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16] = 3;
    bytes[18] = 183;
    std::fs::write(fixture.source.join("server"), bytes).unwrap();
    std::fs::set_permissions(
        fixture.source.join("server"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let preview = fixture.preview();
    fixture.store.install(&preview.digest).unwrap();
    let component = preview
        .components
        .iter()
        .find(|component| component.name == "mcpServers")
        .unwrap();
    assert!(component.quarantine.is_some());
    assert!(
        fixture
            .store
            .mcp_servers(&ProjectId::new("project"), &preview.digest, &component.id)
            .is_err()
    );
}

#[test]
fn unsupported_install_scripts_hooks_and_unknown_fields_never_become_enabled() {
    let f = Fixture::new();
    let marker = f.root.join("must-not-exist");
    std::fs::write(
        f.source.join("install.sh"),
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(
        f.source.join("install.sh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(f.source.join("plugin.json"), br#"{"name":"fixture-plugin","version":"1.0.0","license":"MIT","hooks":{"PreToolUse":[]},"install":"install.sh","mcpServers":{"fake":{"command":"sh"}}}"#).unwrap();
    let preview = f.preview();
    f.store.install(&preview.digest).unwrap();
    assert!(
        f.store
            .preview_file(&preview.digest, "install.sh")
            .unwrap()
            .contains("touch")
    );
    for component in preview
        .components
        .iter()
        .filter(|c| c.kind != ComponentKind::Skills)
    {
        assert!(component.quarantine.is_some());
        assert!(
            f.store
                .set_enabled(
                    &ProjectId::new("project"),
                    &preview.digest,
                    &component.id,
                    true
                )
                .is_err()
        );
    }
    assert!(!marker.exists());
    std::fs::remove_file(f.source.join("LICENSE")).unwrap();
    let unlicensed = f.preview();
    assert!(unlicensed.components.iter().all(|c| c.quarantine.is_some()));
}

#[test]
fn links_credential_files_ambiguous_manifests_and_broken_capsules_refuse() {
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.source.join("LICENSE"), f.source.join("linked-license")).unwrap();
    assert!(f.store.preview_local(&f.source).is_err());
    std::fs::remove_file(f.source.join("linked-license")).unwrap();
    std::fs::write(f.source.join(".env.local"), "TOKEN=not-a-real-token").unwrap();
    assert!(f.store.preview_local(&f.source).is_err());
    std::fs::remove_file(f.source.join(".env.local")).unwrap();
    std::fs::create_dir(f.source.join(".grok-plugin")).unwrap();
    std::fs::copy(
        f.source.join("plugin.json"),
        f.source.join(".grok-plugin/plugin.json"),
    )
    .unwrap();
    assert!(f.store.preview_local(&f.source).is_err());
    std::fs::remove_file(f.source.join(".grok-plugin/plugin.json")).unwrap();
    let preview = f.preview();
    let capsule = f
        .root
        .join("state/extensions-v1/content")
        .join(format!("{}.gbext", preview.digest));
    std::fs::write(capsule, b"corrupt").unwrap();
    assert!(f.store.install(&preview.digest).is_err());
}

#[test]
fn unknown_metadata_versions_and_interrupted_previews_are_recoverable_without_enablement() {
    let f = Fixture::new();
    let preview = f.preview();
    let metadata = f.root.join("state/extensions-v1/metadata.json");
    let original = std::fs::read(&metadata).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    value["version"] = serde_json::json!(99);
    let unknown = serde_json::to_vec(&value).unwrap();
    std::fs::write(&metadata, &unknown).unwrap();
    assert!(f.store.install(&preview.digest).is_err());
    assert_eq!(std::fs::read(&metadata).unwrap(), unknown);
    value["version"] = serde_json::json!(1);
    value["entries"][&preview.digest]["complete"] = serde_json::json!(false);
    std::fs::write(&metadata, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(f.store.install(&preview.digest).is_err());
    assert!(
        f.store
            .skill_context(&ProjectId::new("project"))
            .unwrap()
            .is_empty()
    );
    f.preview();
    f.store.install(&preview.digest).unwrap();
}

#[test]
fn capsules_reject_traversal_duplicates_trailing_bytes_and_reference_escape() {
    let f = Fixture::new();
    let bundle = content::Bundle::capture(&f.source).unwrap();
    let encoded = bundle.encode().unwrap();
    assert_eq!(
        content::Bundle::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );
    let mut excess = encoded.clone();
    excess.push(0);
    assert!(content::Bundle::decode(&excess).is_err());
    for path in [
        "../outside",
        "/absolute",
        "a//b",
        "a/./b",
        "a\\b",
        "file.",
        "x/.env",
    ] {
        assert!(content::validate_path(path).is_err(), "{path}");
    }
    std::fs::write(
        f.source.join("skills/facts/SKILL.md"),
        "[Escape](../../../outside.md)",
    )
    .unwrap();
    let p = f.preview();
    f.store.install(&p.digest).unwrap();
    let id = &p
        .components
        .iter()
        .find(|c| c.kind == ComponentKind::Skills)
        .unwrap()
        .id;
    assert!(
        f.store
            .set_enabled(&ProjectId::new("project"), &p.digest, id, true)
            .is_err()
    );
    assert!(
        f.store
            .skill_context(&ProjectId::new("project"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn inline_mcp_credentials_refuse_before_any_durable_preview_is_created() {
    let f = Fixture::new();
    for config in [
        r#"{"mcpServers":{"example":{"headers":{"Authorization":"Bearer fixture-secret"}}}}"#,
        r#"{"mcpServers":{"example":{"headers":{"Authorization":["Bearer fixture-secret"]}}}}"#,
        r#"{"mcpServers":{"example":{"env":{"XAI_API_KEY":123456}}}}"#,
        r#"{"mcpServers":{"example":{"env":{"XAI_API_KEY":{"value":"fixture-secret"}}}}}"#,
        r#"{"mcpServers":{"example":{"headers":{"Authorization":false}}}}"#,
        r#"{"mcpServers":{"example":{"env":{"AWS_SECRET_ACCESS_KEY":"fixture-secret"}}}}"#,
        r#"{"mcpServers":{"example":{"env":{"AWS_ACCESS_KEY_ID":"fixture-secret"}}}}"#,
        r#"{"mcpServers":{"example":{"secretKey":"fixture-secret","privateKey":"fixture-secret"}}}"#,
        r#"{"mcpServers":{"example":{"env":{"XAI_API_KEY":"fixture-secret"}}}}"#,
        r#"{"mcpServers":{"example":{"url":"https://example.test/mcp?access_token=fixture-secret"}}}"#,
        r#"{"mcpServers":{"example":{"url":"https://username:fixture-secret@example.test/mcp"}}}"#,
    ] {
        std::fs::write(f.source.join(".mcp.json"), config).unwrap();
        let error = f.store.preview_local(&f.source).err().unwrap();
        assert!(!error.contains("fixture-secret"));
        assert!(!f.root.join("state/extensions-v1").exists());
    }
    // A literal reference is inert metadata; it never reads the environment or
    // grants access to the host's provider credential.
    std::fs::write(
        f.source.join(".mcp.json"),
        r#"{"mcpServers":{"example":{"headers":{"Authorization":null},"env":{"XAI_API_KEY":"${XAI_API_KEY}","AWS_SECRET_ACCESS_KEY":"${AWS_SECRET_ACCESS_KEY}","AWS_ACCESS_KEY_ID":""}}}}"#,
    )
    .unwrap();
    let preview = f.preview();
    assert!(
        preview
            .components
            .iter()
            .any(|c| c.kind == ComponentKind::Tools && c.quarantine.is_some())
    );
}
