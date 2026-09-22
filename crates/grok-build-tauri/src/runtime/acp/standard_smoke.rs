//! Explicit live check against a new, disposable project.

use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use grok_build_plus_host::{PlusSessionStore, bind_project_folder};
use serde_json::json;

use super::{
    AcpLaunchConfig, AdapterContext, GrokCliAcpAdapter, LiveRuntimeAdapter, RuntimeCancelHandle,
    RuntimeEvent, fs, standard,
};

pub(crate) fn run(root: &Path) -> Result<String, String> {
    if !root.is_absolute() || root.exists() {
        return Err("The CLI smoke check requires a new absolute fixture directory.".into());
    }
    fs::create_dir(root).map_err(|e| e.to_string())?;
    let workspace = root.join("project");
    fs::create_dir(&workspace).map_err(|e| e.to_string())?;
    fs::write(workspace.join("AGENTS.md"), "This is a disposable GB Plus integration fixture. The project code word is amber-orchid. Read only the fixture files. Do not change files or run commands.\n").map_err(|e| e.to_string())?;
    fs::write(workspace.join("native.txt"), "native-fact: silver-harbor\n")
        .map_err(|e| e.to_string())?;
    fs::write(workspace.join("plus.txt"), "app-fact: violet-garden\n")
        .map_err(|e| e.to_string())?;
    let bound = bind_project_folder(workspace.to_str().ok_or("Fixture path must be UTF-8.")?)
        .map_err(|e| e.to_string())?;
    let store = PlusSessionStore::from_state_root(root.join("state"));
    let pool = standard::StandardAgentPool::default();
    let settings = super::super::engine::EngineSettings {
        mode: super::super::engine::EngineMode::GrokCliStandard,
        ..Default::default()
    };
    let config = AcpLaunchConfig::standard(root, &workspace, &settings, Some(pool.lease(root)?))?;
    let mut session = None;
    let mut results = Vec::new();
    let mut scope = super::super::types::RuntimeInvocationScope {
        project_id: crate::contracts::ProjectId::new("standard-smoke"),
        workspace_id: crate::contracts::WorkspaceId::new("standard-smoke-workspace"),
        session_id: crate::contracts::SessionId::new("standard-smoke-chat"),
        run_id: crate::contracts::RunId::new("standard-smoke-first"),
    };
    for (index, prompt) in [
        "Use your native file-reading tool to read native.txt. Discover the gbplus MCP server's read_file tool and use it to read plus.txt. Report both facts and the code word from this project's AGENTS.md. Do not edit files or use commands.",
        "Without using any tools, repeat the two facts and project code word from the previous turn.",
        "Use one native subagent to read native.txt. Do not delegate through MCP, run commands, or modify files. After it finishes, report both earlier facts and the project code word.",
        "Use web search to find the official Grok Build changelog on x.ai. Report its link, both earlier facts, and the project code word. Do not run commands or modify files.",
    ].iter().enumerate() {
        scope.run_id = crate::contracts::RunId::new(format!("standard-smoke-{index}"));
        let cancel = RuntimeCancelHandle::new();
        let mut adapter = GrokCliAcpAdapter::new(config.clone(), cancel.clone());
        let probe = adapter.probe(&|_| Ok(())).map_err(|e| e.to_string())?;
        let version = adapter.process.as_ref().and_then(|process| process.initialized.as_ref())
            .and_then(|value| value.pointer("/_meta/agentVersion")).cloned();
        adapter.start_or_restore_session(session.as_ref()).map_err(|e| e.to_string())?;
        let context = AdapterContext { scope: scope.clone(), bound: &bound, store: &store, extension_context: "", hooks: None };
        let tool_calls = Mutex::new(Vec::new());
        let started = Instant::now();
        let turn = adapter.send_turn(&context, prompt, None, &|_| Ok(Vec::new()), &|event| {
            if let RuntimeEvent::ToolRequest { name, .. } = event {
                tool_calls.lock().map_err(|_| "Fixture event lock failed.")?.push(name);
            }
            Ok(())
        }).map_err(|e| e.to_string())?;
        let facts_present = ["silver-harbor", "violet-garden", "amber-orchid"].iter()
            .all(|fact| turn.assistant_text.contains(fact));
        let calls = tool_calls.into_inner().map_err(|_| "Fixture event lock failed.")?;
        results.push(json!({"turn":index + 1,"cliVersion":version,"model":probe.model,"seconds":started.elapsed().as_secs_f64(),"factsPresent":facts_present,"appToolCalls":calls,"idleLeaseReleased":cancel.cleanup_proven()}));
        session = turn.provider_session_id;
        if !facts_present || (index == 0 && calls.is_empty()) || (index == 1 && !calls.is_empty()) {
            pool.clear()?;
            return Err(format!("CLI standard smoke did not meet the fixture contract: {}", json!(results)));
        }
    }
    pool.clear()?;
    Ok(
        json!({"checks":results,"sharedCliHome":true,"credentialFilesReadByFixture":false})
            .to_string(),
    )
}
