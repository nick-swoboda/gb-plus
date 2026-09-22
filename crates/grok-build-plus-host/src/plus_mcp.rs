//! Bounded, transport-independent MCP exchanges for the app's extension broker.
//!
//! Parsing a message or constructing a request grants no tool permission. The
//! caller must resolve project/extension authority and journal a tool invocation
//! before handing its request to an HTTPS or contained-stdio carrier. The protocol
//! and catalog do not dispatch effects. The transport modules use explicit HTTPS
//! or admitted contained-service boundaries; none provides arbitrary host execution,
//! ambient credential discovery, model sampling, or browser control.

mod catalog;
#[cfg(feature = "mcp-https")]
mod connection;
#[cfg(feature = "mcp-https")]
mod https;
#[cfg(feature = "mcp-https")]
mod inspection;
mod permissions;
mod protocol;
mod stdio;
#[cfg(feature = "mcp-https")]
mod stdio_connection;
mod version;

pub use catalog::{McpCatalog, McpTool};
#[cfg(feature = "mcp-https")]
pub use connection::McpHttpsConnection;
#[cfg(feature = "mcp-https")]
pub use https::{
    McpBearerAuthorization, McpHttpEvent, McpHttpOutcome, McpHttpsClient, mcp_pin_public_addresses,
};
#[cfg(feature = "mcp-https")]
pub use inspection::inspect_mcp_https_catalog;
pub use permissions::{
    MCP_MAX_PERMISSION_BYTES, McpEffectClass, McpPermissionBook, McpPermissionDecision,
    McpPermissionReview, McpToolPolicy,
};
pub use protocol::{McpEvent, McpOperation, McpProtocol, McpRequestIdentity};

/// 192-bit namespace suffix. `gbplus__` + `gbext_` + 48 hex digits is 62 bytes,
/// within the admitted CLI's 64-byte limit on the fully qualified tool name.
pub const MCP_APP_TOOL_HASH_HEX_LENGTH: usize = 48;
pub use stdio::ContainedMcpConnection;
#[cfg(feature = "mcp-https")]
pub use stdio_connection::McpStdioConnection;
pub use version::McpProtocolVersion;

/// Preferred MCP revision; only the explicit compatibility table is accepted.
pub const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
/// Maximum encoded JSON-RPC message, before deserialization.
pub const MCP_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Combined incoming and outgoing message bytes for one connection.
pub const MCP_MAX_CONNECTION_BYTES: usize = 16 * 1024 * 1024;

fn digest(value: &serde_json::Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode bounded MCP metadata.")?;
    Ok(super::worktree_recovery_digest(&bytes))
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
}

#[cfg(test)]
mod tests;
