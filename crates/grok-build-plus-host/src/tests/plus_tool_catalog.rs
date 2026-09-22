use serde_json::Value;

use super::{
    PLUS_TOOL_DESCRIPTORS, ToolGrant, ToolProtocolAvailability, plus_live_tool_declarations,
    plus_live_tool_instructions, plus_tool_acp_name_clause, plus_tool_name_clause,
};

const NAMES: &[&str] = &[
    "list_dir",
    "read_file",
    "grep",
    "glob",
    "propose_write",
    "propose_replace",
    "todo_write",
    "run_contained",
    "browser_navigate",
    "browser_inspect",
    "browser_click",
    "browser_type",
    "browser_key",
    "browser_scroll",
    "browser_screenshot",
    "desktop_click",
    "desktop_type",
    "desktop_key",
    "desktop_scroll",
];

#[test]
fn tool_catalog_projects_identical_provider_acp_order_and_grants() {
    let catalog_names = PLUS_TOOL_DESCRIPTORS
        .iter()
        .map(|descriptor| descriptor.wire_name)
        .collect::<Vec<_>>();
    assert_eq!(catalog_names, NAMES);
    assert!(PLUS_TOOL_DESCRIPTORS.iter().all(|descriptor| {
        descriptor.protocol == ToolProtocolAvailability::NativeAndAcp
            && descriptor.persistence_safe_label == descriptor.wire_name
            && descriptor.name.as_str() == descriptor.wire_name
    }));
    let Value::Array(declarations) = plus_live_tool_declarations() else {
        panic!("provider declarations are an array");
    };
    let declaration_names = declarations
        .iter()
        .map(|declaration| declaration["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(declaration_names, NAMES);
    assert_eq!(
        plus_tool_name_clause(),
        "list_dir, read_file, grep, glob, propose_write, propose_replace, todo_write, run_contained, browser_navigate, browser_inspect, browser_click, browser_type, browser_key, browser_scroll, browser_screenshot, desktop_click, desktop_type, desktop_key, and desktop_scroll"
    );
    assert_eq!(
        plus_tool_acp_name_clause(),
        "list_dir, read_file, grep, glob,\npropose_write, propose_replace, todo_write, run_contained, browser_navigate,\nbrowser_inspect, browser_click, browser_type, browser_key, browser_scroll,\nbrowser_screenshot, desktop_click, desktop_type, desktop_key, and desktop_scroll"
    );
    assert!(plus_live_tool_instructions().contains(plus_tool_name_clause()));
    assert_eq!(
        PLUS_TOOL_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.grant == ToolGrant::Browser)
            .count(),
        7
    );
    assert_eq!(
        PLUS_TOOL_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.grant == ToolGrant::Desktop)
            .count(),
        4
    );
}
