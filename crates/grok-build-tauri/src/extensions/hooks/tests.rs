use super::*;
use crate::contracts::{ProjectId, RunId};
use crate::extensions::mcp::config::LocalSpec;
use std::sync::atomic::{AtomicBool, Ordering};

#[test]
fn high_power_input_is_withheld_and_ordinary_input_keeps_its_exact_structure() {
    let arguments =
        json!({"path":"file.txt","after":"PRIVATE HIGH POWER FIXTURE","nested":{"x":1}});
    for name in [
        "browser_type",
        "desktop_type",
        "gbext_fixture",
        "app_agent_spawn",
        "app_workflow_parallel",
    ] {
        let bytes = hook_input(name, &arguments).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("PRIVATE HIGH POWER FIXTURE"));
        let input: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(input["tool_input"], json!({}));
        assert_eq!(input["tool_input_unavailable"], true);
    }
    let input: Value =
        serde_json::from_slice(&hook_input("propose_write", &arguments).unwrap()).unwrap();
    assert_eq!(input["tool_input"], arguments);
    assert_eq!(input["tool_input_unavailable"], false);
    assert!(hook_input("propose_write", &json!({"after":"x".repeat(65536)})).is_err());
}

#[test]
fn unmatched_hooks_preserve_large_tool_inputs_and_crossed_scope_or_exhausted_budgets_refuse_before_launch()
 {
    let executor = HookRunExecutor {
        context: ServiceContext::new(
            ProjectId::new("project"),
            "run".into(),
            "/unavailable-workspace".into(),
            "/unavailable-state".into(),
        ),
        specs: vec![HookSpec {
            identity: "a".repeat(64),
            matcher: vec!["read_file".into()],
            timeout_seconds: 10,
            local: LocalSpec {
                content: "b".repeat(64),
                command: "bin/guard".into(),
                arguments: Vec::new(),
                executable_digest: grok_build_plus_host::Digest::sha256(b"fixture"),
                executable_bytes: 7,
                architecture: grok_build_plus_host::ServiceArchitecture::LinuxAarch64,
            },
        }],
        cancel: RuntimeCancelHandle::new(),
        approvals: McpApprovals::default(),
        calls: Mutex::new(0),
    };
    let mut scope = RuntimeInvocationScope::fixture();
    scope.project_id = ProjectId::new("project");
    scope.run_id = RunId::new("run");
    executor
        .before_tool(
            &scope,
            "propose_write",
            &json!({"after":"x".repeat(131_072)}),
        )
        .unwrap();
    assert_eq!(*executor.calls.lock().unwrap(), 0);
    let mut crossed = scope.clone();
    crossed.project_id = ProjectId::new("other");
    assert!(
        executor
            .before_tool(&crossed, "read_file", &json!({}))
            .is_err()
    );
    crossed = scope.clone();
    crossed.run_id = RunId::new("other");
    assert!(
        executor
            .before_tool(&crossed, "read_file", &json!({}))
            .is_err()
    );
    *executor.calls.lock().unwrap() = 64;
    assert!(
        executor
            .before_tool(&scope, "read_file", &json!({}))
            .unwrap_err()
            .contains("64 hook")
    );
    assert!(matches!(
        executor
            .refuse_or_interrupt("known refusal".into())
            .unwrap(),
        HookGateDecision::Refuse(_)
    ));
    let proof = Arc::new(AtomicBool::new(false));
    executor
        .cancel
        .retain_hook_cleanup_fixture(Arc::clone(&proof))
        .unwrap();
    assert!(
        executor
            .refuse_or_interrupt("uncertain cleanup".into())
            .is_err()
    );
    proof.store(true, Ordering::Release);
    executor.cancel.request_cancel().unwrap();
    assert!(
        executor
            .before_tool(&scope, "propose_write", &json!({}))
            .is_err()
    );
}
