use super::*;
use serde_json::Value;
use std::os::unix::fs::MetadataExt as _;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "gbplus-mcp-policy-{}-{}",
            std::process::id(),
            NEXT_REVIEW.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
    fn manager(&self, project: &str) -> (McpReviews, Arc<Review>) {
        let manager = McpReviews::new(&self.0, accounts::Accounts::new(&self.0));
        let mut catalog = McpCatalog::new(ProjectId::new(project), "a".repeat(64)).unwrap();
        catalog.push_page(None, &json!({"tools":[{"name":"fixture","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}]})).unwrap();
        let review = Arc::new(Review {
            id: "b".repeat(64),
            server: ServerSpec {
                project: ProjectId::new(project),
                identity: "a".repeat(64),
                name: "fixture".into(),
                endpoint: "https://example.invalid/mcp".into(),
                local: None,
                account_identity: None,
                authorization: None,
            },
            catalog,
            created: Instant::now(),
        });
        manager.records.lock().unwrap().push(Arc::clone(&review));
        (manager, review)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn tool_policies_survive_owner_only_storage_and_stale_ui_cannot_overwrite_them() {
    let fixture = Fixture::new();
    let (manager, review) = fixture.manager("project-a");
    let project = &review.server.project;
    let tool = review.catalog.tools().unwrap().next().unwrap();
    let changed = manager
        .change_policy(
            project,
            &review.id,
            0,
            tool.app_name(),
            tool.fingerprint(),
            McpToolPolicy::Deny,
        )
        .unwrap();
    assert_eq!(changed.revision, 1);
    assert_eq!(changed.tools[0].policy, McpToolPolicy::Deny);
    assert!(!changed.tool_execution_enabled);
    let path = fixture.0.join("mcp-permissions-v1").join(format!(
        "{}.json",
        super::super::digest(project.as_str().as_bytes())
    ));
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let bytes = std::fs::read(&path).unwrap();
    let (restarted, reread) = fixture.manager("project-a");
    let restored = PermissionStore::new(&fixture.0, project).read().unwrap();
    assert_eq!(
        present(&reread, &restored).unwrap().tools[0].policy,
        McpToolPolicy::Deny
    );
    assert!(
        restarted
            .change_policy(
                project,
                &reread.id,
                0,
                tool.app_name(),
                tool.fingerprint(),
                McpToolPolicy::Ask
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(
        manager
            .change_policy(
                &ProjectId::new("project-b"),
                &review.id,
                1,
                tool.app_name(),
                tool.fingerprint(),
                McpToolPolicy::Ask
            )
            .is_err()
    );
    manager.close(project, &review.id).unwrap();
    assert!(
        manager
            .change_policy(
                project,
                &review.id,
                1,
                tool.app_name(),
                tool.fingerprint(),
                McpToolPolicy::Ask
            )
            .is_err()
    );
}

#[test]
fn frontend_cannot_promote_server_hints_to_reusable_permission() {
    assert!(
        serde_json::from_value::<crate::commands::McpPolicyChoice>(json!({
            "reviewId":"b".repeat(64),"revision":0,"appName":"gbext_example",
            "fingerprint":"a".repeat(64),"policy":"allowReviewedReadOnly","class":"reviewedReadOnly"
        }))
        .is_err()
    );
    let fixture = Fixture::new();
    let (manager, review) = fixture.manager("project-a");
    let tool = review.catalog.tools().unwrap().next().unwrap();
    assert!(tool.claimed_read_only());
    assert!(
        manager
            .change_policy(
                &review.server.project,
                &review.id,
                0,
                tool.app_name(),
                tool.fingerprint(),
                McpToolPolicy::AllowReviewedReadOnly
            )
            .is_err()
    );
    assert_eq!(
        PermissionStore::new(&fixture.0, &review.server.project)
            .read()
            .unwrap()
            .revision(),
        0
    );
}

#[test]
fn unknown_permission_version_is_preserved_without_an_automatic_reset() {
    let fixture = Fixture::new();
    let (manager, review) = fixture.manager("project-a");
    let tool = review.catalog.tools().unwrap().next().unwrap();
    manager
        .change_policy(
            &review.server.project,
            &review.id,
            0,
            tool.app_name(),
            tool.fingerprint(),
            McpToolPolicy::Deny,
        )
        .unwrap();
    let owner = crate::owner_state::OwnerStateRoot::new(fixture.0.join("mcp-permissions-v1"));
    let key = super::super::digest(review.server.project.as_str().as_bytes());
    let file = owner
        .file(
            format!("{key}.json"),
            grok_build_plus_host::MCP_MAX_PERMISSION_BYTES as u64,
        )
        .unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&file.read().unwrap().unwrap()).unwrap();
    value["version"] = json!(65535);
    let bytes = serde_json::to_vec(&value).unwrap();
    file.replace(&bytes).unwrap();
    assert!(
        PermissionStore::new(&fixture.0, &review.server.project)
            .read()
            .is_err()
    );
    assert!(
        manager
            .change_policy(
                &review.server.project,
                &review.id,
                1,
                tool.app_name(),
                tool.fingerprint(),
                McpToolPolicy::Ask
            )
            .is_err()
    );
    assert_eq!(file.read().unwrap().unwrap(), bytes);
}

#[test]
fn legacy_permission_commit_keeps_exact_backup_and_blocked_tool_binding() {
    let fixture = Fixture::new();
    let (manager, review) = fixture.manager("project-a");
    let tool = review.catalog.tools().unwrap().next().unwrap();
    let key = super::super::digest(review.server.project.as_str().as_bytes());
    let owner = crate::owner_state::OwnerStateRoot::new(fixture.0.join("mcp-permissions-v1"));
    let file = owner.file(format!("{key}.json"), 128 * 1024).unwrap();
    let original = serde_json::to_vec(&json!({"version":1,"project":"project-a","revision":41,"policies":{
        format!("{}deadbeef", tool.app_name()):{"fingerprint":tool.fingerprint(),"policy":"deny"}
    }})).unwrap();
    file.replace(&original).unwrap();
    let read = PermissionStore::new(&fixture.0, &review.server.project)
        .read()
        .unwrap();
    assert_eq!(read.revision(), 42);
    assert_eq!(
        read.decision(
            &review.catalog,
            tool.app_name(),
            McpEffectClass::Unclassified
        )
        .unwrap(),
        McpPermissionDecision::Denied
    );
    assert_eq!(file.read().unwrap().unwrap(), original);
    manager
        .change_policy(
            &review.server.project,
            &review.id,
            read.revision(),
            tool.app_name(),
            tool.fingerprint(),
            McpToolPolicy::Deny,
        )
        .unwrap();
    assert_eq!(
        owner
            .file(format!("{key}-before-v2.json"), 128 * 1024)
            .unwrap()
            .read()
            .unwrap()
            .unwrap(),
        original
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&file.read().unwrap().unwrap()).unwrap()["version"],
        2
    );
}

#[test]
fn server_inspection_never_expands_environment_or_launches_unsupported_transports() {
    let content = "a".repeat(64);
    let component = "b".repeat(64);
    let map = json!({
        "public":{"type":"http","url":"https://example.com/mcp"},
        "local":{"command":"/bin/sh","args":["-c","never execute"]},
        "secret":{"url":"https://example.com/mcp","headers":{"Authorization":"${TOKEN}"}},
        "plaintext":{"url":"http://example.com/mcp"}
    });
    let bundle = super::super::content::Bundle {
        files: std::collections::BTreeMap::new(),
    };
    let rows = specs(&ProjectId::new("a"), &content, &component, &map, &bundle).unwrap();
    assert_eq!(rows.iter().filter(|(_, spec)| spec.is_some()).count(), 1);
    let first = rows.iter().find_map(|(_, spec)| spec.as_ref()).unwrap();
    for (project, content, component) in [
        ("b", content.clone(), component.clone()),
        ("a", "c".repeat(64), component.clone()),
        ("a", content, "d".repeat(64)),
    ] {
        let other = specs(
            &ProjectId::new(project),
            &content,
            &component,
            &map,
            &bundle,
        )
        .unwrap();
        assert_ne!(
            first.identity,
            other
                .iter()
                .find_map(|(_, spec)| spec.as_ref())
                .unwrap()
                .identity
        );
    }
}
