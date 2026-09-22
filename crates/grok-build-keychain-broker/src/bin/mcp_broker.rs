//! Separate MCP-only credential helper; never reads the provider namespace.

fn main() {
    if let Err(error) = grok_build_keychain_broker::run_mcp_broker() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
