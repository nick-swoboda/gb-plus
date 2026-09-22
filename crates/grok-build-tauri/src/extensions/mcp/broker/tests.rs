//! Public read-only interoperability is explicit and independent of model calls.

use super::*;
use std::time::{Duration, Instant};

#[test]
#[ignore = "explicit public Microsoft Learn MCP search through the app approval broker"]
fn public_mcp_search_uses_the_production_broker_and_one_identified_approval() {
    assert_eq!(
        std::env::var("GROK_BUILD_MCP_PUBLIC_SEARCH_SMOKE").as_deref(),
        Ok("1")
    );
    let (root, project) = enabled_fixture();
    let broker = McpBroker::new(&root);
    let cancel = RuntimeCancelHandle::new();
    let executor = broker
        .prepare(project.as_str(), "public-search-run", cancel.clone(), None)
        .unwrap()
        .unwrap();
    let tool = executor.servers[0]
        .catalog
        .tools()
        .unwrap()
        .find(|tool| tool.wire_name() == "microsoft_docs_search")
        .unwrap();
    assert_eq!(tool.input_schema()["properties"]["query"]["type"], "string");
    let name = tool.app_name().to_owned();
    let arguments = json!({"query":"Azure REST API documentation"});
    let worker_executor = Arc::clone(&executor);
    let worker_name = name.clone();
    let worker_arguments = arguments.clone();
    let worker = std::thread::spawn(move || {
        worker_executor.execute("public-search-call-1", &worker_name, &worker_arguments)
    });
    let mut running = Running {
        cancel,
        worker: Some(worker),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let view = loop {
        if let Some(view) = broker.approvals.list(&project).unwrap().into_iter().next() {
            break serde_json::to_value(view).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "app broker did not issue its approval"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(view["endpoint"], "https://learn.microsoft.com/api/mcp");
    assert_eq!(view["tool"]["wireName"], "microsoft_docs_search");
    assert_eq!(view["arguments"], arguments);
    let id = view["id"].as_str().unwrap();
    let commitment = view["commitment"].as_str().unwrap();
    assert!(
        broker
            .approvals
            .answer(&ProjectId::new("another-project"), id, commitment, true)
            .is_err()
    );
    broker
        .approvals
        .answer(&project, id, commitment, true)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    while !running.worker.as_ref().unwrap().is_finished() {
        assert!(
            Instant::now() < deadline,
            "public fixture exceeded its test deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let result = running.worker.take().unwrap().join().unwrap().unwrap();
    assert_ne!(result.get("isError"), Some(&Value::Bool(true)));
    assert!(!result["content"].as_array().unwrap().is_empty());
    assert_eq!(
        executor
            .execute("public-search-call-1", &name, &arguments)
            .unwrap(),
        result
    );
    assert!(broker.approvals.list(&project).unwrap().is_empty());
    drop(executor);
    let journal = InvocationJournal::open(&root, &project, "public-search-run").unwrap();
    let key = super::super::super::digest(b"public-search-call-1");
    assert!(journal.previous(&key, "lost transient binding").is_err());
    drop(journal);
    drop(running);
    std::fs::remove_dir_all(root).unwrap();
    println!(
        "Public MCP search completed through the production app broker: one approved invocation, same-id replay reused its in-memory result, zero model calls."
    );
}

struct Running {
    cancel: RuntimeCancelHandle,
    worker: Option<std::thread::JoinHandle<Result<Value, String>>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.cancel.request_cancel();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn enabled_fixture() -> (std::path::PathBuf, ProjectId) {
    let root = std::env::temp_dir().join(format!(
        "gbplus-public-mcp-call-{}-{}",
        std::process::id(),
        crate::runtime::types::unix_time_millis()
    ));
    std::fs::create_dir_all(root.join("source")).unwrap();
    let root = root.canonicalize().unwrap();
    std::fs::write(
        root.join("source/plugin.json"),
        br#"{"name":"public-docs-fixture","version":"1.0.0","license":"MIT"}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("source/LICENSE"),
        "MIT\nApp-owned interoperability fixture configuration.\n",
    )
    .unwrap();
    std::fs::write(root.join("source/.mcp.json"), br#"{"mcpServers":{"microsoft-learn":{"type":"http","url":"https://learn.microsoft.com/api/mcp"}}}"#).unwrap();
    let store = crate::extensions::ExtensionStore::new(&root);
    let preview = store.preview_local(&root.join("source")).unwrap();
    store.install(&preview.digest).unwrap();
    let project = ProjectId::new("public-mcp-fixture");
    let component = preview
        .components
        .iter()
        .find(|item| item.name == "mcpServers")
        .unwrap();
    assert!(store.enabled_mcp_servers(&project).unwrap().is_empty());
    store
        .set_enabled(&project, &preview.digest, &component.id, true)
        .unwrap();
    (root, project)
}
