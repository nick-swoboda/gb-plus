//! Frozen same-product contracts used while internal modules move.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const EXPECTED_TOOL_DECLARATIONS_SHA256: &str =
    "8bab29c1f9a359fe248c4168cdb90fa5e6c6e8a9f5a67c7ea89f569bbecc1113";
const EXPECTED_ACP_PROFILE_SHA256: &str =
    // Prior profile: 8ef34539cdf48f9cfc563b008c2fafeb410069fba3e23a92b1d172ee01594060.
    // Approved expansion replaces textual effects with an explicit app MCP gateway.
    "0cd965e0c82f166a47a0d8772c945a68db6db4c6a869b59b6f0e01e3d25bc9aa";
const EXPECTED_TOOL_INSTRUCTIONS_SHA256: &str =
    "6fae82b5d658f7bca3b979c20221ddae72f638295d8bb78a0fb30744d384bac4";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref())
        .unwrap_or_else(|error| panic!("read {}: {error}", path.as_ref().display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
            encoded
        })
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing start marker {start:?}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing end marker {end:?}"))
        .0
}

#[test]
fn provider_tool_declarations_match_the_frozen_schema() {
    let canonical = grok_build_plus_host::plus_live_tool_declarations().to_string();
    let actual = sha256_hex(canonical.as_bytes());
    eprintln!("provider_tool_declarations_sha256={actual}");
    assert_eq!(actual, EXPECTED_TOOL_DECLARATIONS_SHA256);
}

#[test]
fn strict_acp_profile_matches_the_frozen_capability_contract() {
    let profile = crate::runtime::acp::strict_acp_profile();
    let actual = sha256_hex(profile.as_bytes());
    eprintln!("strict_acp_profile_sha256={actual}");
    // Remove the shared foundation before checking the unchanged gateway contract.
    let (header, body) = profile.split_once("\n---\n\n").unwrap();
    let protocol = body
        .strip_prefix(grok_build_plus_host::PLUS_APP_SYSTEM_PROMPT)
        .unwrap()
        .strip_prefix("\n<gb_plus_tool_protocol>\n")
        .unwrap()
        .strip_suffix("</gb_plus_tool_protocol>\n")
        .unwrap();
    let mut baseline = format!("{header}\n---\n\n{protocol}");
    for (current, original) in [
        (
            "description: App-owned tool gateway profile for the GB Plus GUI",
            "description: Constrained chat-only profile owned by the GB Plus GUI",
        ),
        (
            "Use only tools discovered from the app-owned gbplus MCP server. Core tools are\n",
            "Use only tools discovered from the app-owned gbplus MCP server. Its catalog is\n",
        ),
        (
            ". This same gateway may also list explicitly enabled project\nextensions for the current run; their independent app approvals still apply.\nNo CLI-native filesystem, terminal, Git, browser, plugin,",
            ". No CLI-native filesystem, terminal, Git, browser, plugin,",
        ),
    ] {
        assert_eq!(baseline.matches(current).count(), 1);
        baseline = baseline.replacen(current, original, 1);
    }
    assert_eq!(sha256_hex(baseline.as_bytes()), EXPECTED_ACP_PROFILE_SHA256);
}

#[test]
fn tauri_command_registry_matches_the_frozen_order() {
    let source = read(crate_root().join("src/lib.rs"));
    let registry = between(&source, ".invoke_handler(tauri::generate_handler![", "])");
    let actual = registry
        .lines()
        .map(|line| line.trim().trim_end_matches(','))
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let expected = include_str!("../../tests/fixtures/tauri-command-registry.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let additions = [
        "set_engine_settings",
        "pending_cli_interactions",
        "answer_cli_interaction",
        "cli_background_activity",
        "stop_cli_background",
        "render_chat_markdown",
        "get_cli_permission",
        "set_cli_permission",
        "open_chat_link",
        "stage_cli_image",
        "discard_cli_image",
        "inspect_grok_cli",
        "update_grok_cli",
        "reset_provider_context",
        "list_session_models",
        "get_session_native_protocol",
        "set_session_native_protocol",
        "select_session_model",
        "list_project_extensions",
        "agent_settings",
        "set_agents_enabled",
        "child_agent_result",
        "stop_child_agent",
        "decide_child_changes",
        "list_project_workflows",
        "workflow_result",
        "start_project_workflow",
        "resume_project_workflow",
        "stop_project_workflow",
        "preview_local_extension",
        "preview_https_extension",
        "install_extension",
        "set_extension_component",
        "inspect_extension_file",
        "list_extension_mcp_servers",
        "inspect_extension_mcp_catalog",
        "set_extension_mcp_policy",
        "close_extension_mcp_review",
        "list_mcp_call_approvals",
        "answer_mcp_call_approval",
        "list_mcp_elicitations",
        "answer_mcp_elicitation",
        "open_mcp_elicitation_link",
        "mcp_account_status",
        "review_mcp_account",
        "begin_mcp_account_signin",
        "disconnect_mcp_account",
        "cleanup_mcp_accounts",
        "cancel_mcp_account_signin",
        "close_mcp_account_review",
        "project_memory_view",
        "set_project_memory",
        "remember_project_fact",
        "forget_project_fact",
    ];
    let preserved = actual
        .iter()
        .copied()
        .filter(|command| !additions.contains(command))
        .collect::<Vec<_>>();
    assert_eq!(preserved, expected);
    // Preserve the original registry and require each approved expansion once,
    // in its reviewed order. Prefix matching cannot authorize extra commands.
    let introduced = actual
        .iter()
        .copied()
        .filter(|command| !expected.contains(command))
        .collect::<Vec<_>>();
    assert_eq!(introduced, additions);
}

#[test]
fn existing_app_snapshot_fields_remain_in_order() {
    let source = read(crate_root().join("src/backend.rs"));
    let snapshot = between(&source, "pub(crate) struct AppSnapshot {", "\n}");
    let actual = snapshot
        .lines()
        .map(str::trim)
        .filter_map(|line| line.split_once(':').map(|(field, _)| field))
        .map(|field| field.trim_start_matches("pub(crate) "))
        .collect::<Vec<_>>();
    let expected = include_str!("../../tests/fixtures/app-snapshot-fields.txt")
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    let mut cursor = 0;
    for field in actual {
        if expected.get(cursor) == Some(&field) {
            cursor += 1;
        }
    }
    assert_eq!(
        cursor,
        expected.len(),
        "existing snapshot fields changed or reordered"
    );
}

#[test]
fn native_tool_instructions_match_the_frozen_contract() {
    let actual = sha256_hex(grok_build_plus_host::plus_live_tool_instructions().as_bytes());
    assert_eq!(actual, EXPECTED_TOOL_INSTRUCTIONS_SHA256);
}

#[test]
fn primary_tauri_contract_graph_excludes_desktop_and_slint() {
    let tauri = read(crate_root().join("Cargo.toml"));
    let plus_host = read(crate_root().join("../grok-build-plus-host/Cargo.toml"));
    let runner_client = read(crate_root().join("../grok-build-runner-client/Cargo.toml"));
    let desktop = read(crate_root().join("../grok-build-desktop/Cargo.toml"));

    assert!(tauri.contains("grok-build-plus-host ="));
    for (name, manifest) in [
        ("Tauri", tauri.as_str()),
        ("Plus host", plus_host.as_str()),
        ("runner client", runner_client.as_str()),
    ] {
        assert!(
            !manifest.contains("grok-build-desktop") && !manifest.contains("slint ="),
            "{name} reintroduced the legacy Desktop/Slint graph"
        );
    }
    assert!(desktop.contains("default = []"));
    assert!(desktop.contains("required-features = [\"slint-ui\"]"));
}

#[test]
fn future_contracts_are_explicit_and_default_off() {
    let runner_manifest = read(crate_root().join("../grok-build-runner/Cargo.toml"));
    let runner_root = read(crate_root().join("../grok-build-runner/src/lib.rs"));

    assert!(runner_manifest.contains("default = []"));
    assert!(runner_manifest.contains("future-contracts = []"));
    assert!(runner_manifest.contains("test-support = [\"future-contracts\"]"));
    for module in [
        "application_composition_publisher",
        "macos_command_plan",
        "macos_helper_journal",
        "macos_runner_held_journal",
        "macos_service_command_journal",
        "macos_vz_guest",
        "wire_v13",
    ] {
        let declaration = format!("mod {module};");
        let offset = runner_root
            .find(&declaration)
            .unwrap_or_else(|| panic!("missing future module {module}"));
        let prefix = &runner_root[..offset];
        let cfg = prefix
            .rfind("#[cfg(")
            .map(|start| &prefix[start..])
            .unwrap_or_default();
        assert!(
            cfg.contains("future-contracts"),
            "future module {module} is present in the default graph"
        );
    }
}
