//! Opt-in public catalog probe. It performs no model or MCP tool invocation.

#[cfg(not(feature = "mcp-https"))]
fn main() {
    eprintln!("Enable the mcp-https feature to run this explicit catalog probe.");
    std::process::exit(78);
}

#[cfg(feature = "mcp-https")]
fn main() {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
        .and_then(|runtime| runtime.block_on(probe::run()));
    if let Err(reason) = result {
        eprintln!("MCP catalog probe failed: {reason}");
        std::process::exit(1);
    }
}

#[cfg(feature = "mcp-https")]
mod probe {
    use grok_build_plus_host::{ProjectId, inspect_mcp_https_catalog, worktree_recovery_digest};
    use serde_json::json;
    use std::sync::atomic::AtomicBool;
    const ENDPOINT: &str = "https://learn.microsoft.com/api/mcp";
    pub(super) async fn run() -> Result<(), String> {
        let (catalog, version) = inspect_mcp_https_catalog(
            ENDPOINT,
            ProjectId::new("public-mcp-catalog-probe"),
            worktree_recovery_digest(ENDPOINT.as_bytes()),
            &AtomicBool::new(false),
        )
        .await?;
        let tools = catalog.tools()?.map(|tool| json!({
            "name":tool.wire_name(), "appName":tool.app_name(), "fingerprint":tool.fingerprint(),
            "serverClaimsReadOnly":tool.claimed_read_only(), "permissionGranted":false
        })).collect::<Vec<_>>();
        println!(
            "{}",
            json!({"endpoint":ENDPOINT,"protocolVersion":version.as_str(),"tools":tools,"toolInvocations":0,"modelInvocations":0})
        );
        Ok(())
    }
}
