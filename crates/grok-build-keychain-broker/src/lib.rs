//! Versioned macOS Keychain broker for Grok Build+.
//!
//! The production helper is the only process allowed to read the v3 provider
//! credential. Its code hash stays stable while the main desktop executable
//! changes, and both sides validate the other before a bounded secret frame is
//! exchanged over a private, mutually authenticated Unix socket.

#[cfg(any(target_os = "macos", test))]
mod protocol;
mod types;

#[cfg(target_os = "macos")]
mod macos;

pub use types::{BrokerAction, BrokerSecret, CredentialVersion, McpCredentialKey};

#[cfg(target_os = "macos")]
pub use macos::{BrokerClient, BrokerClientConfig};

/// Fixed executable for MCP credentials. It never owns provider accounts.
pub const MCP_BROKER_EXECUTABLE_NAME: &str = "grok-build-mcp-keychain-broker";
/// Exact MCP helper identity, independently pinned by the signed app.
pub const MCP_BROKER_CODE_IDENTIFIER: &str = "com.grokbuild.plus.mcp-credential-broker";

/// Run the separate MCP-only one-shot helper.
///
/// # Errors
/// Refuses unsupported platforms, unauthenticated peers and malformed requests.
pub fn run_mcp_broker() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::run_production_server(protocol::BrokerNamespace::Mcp)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("MCP Keychain credentials require macOS.".into())
    }
}

/// Fixed helper executable name inside `Grok Build+.app/Contents/Helpers`.
pub const BROKER_EXECUTABLE_NAME: &str = "grok-build-keychain-broker";

/// Code-signing identifier of the stable helper executable.
pub const BROKER_CODE_IDENTIFIER: &str = "com.grokbuild.plus.credential-broker";

/// Code-signing identifier of the only production app peer.
pub const PARENT_CODE_IDENTIFIER: &str = "com.grokbuild.plus";

/// Version of the private single-frame socket protocol.
pub const BROKER_PROTOCOL_VERSION: u16 = 1;

/// Version of the Keychain account owned by the stable helper.
pub const BROKER_ACCOUNT_VERSION: u16 = 3;

/// Production Keychain service. The broker accepts no caller-supplied service.
pub const PROVIDER_KEYCHAIN_SERVICE: &str = "org.grok-build.desktop.provider";

/// Dedicated Keychain service for app-bound MCP credentials.
pub const MCP_KEYCHAIN_SERVICE: &str = "org.grok-build.desktop.mcp";

const PROVIDER_ACCOUNT_DIGEST: &str =
    "ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b";

/// Returns the fixed account for one credential storage generation.
#[must_use]
pub fn provider_account(version: CredentialVersion) -> String {
    match version {
        CredentialVersion::LegacyV1 => format!("xai:{PROVIDER_ACCOUNT_DIGEST}"),
        CredentialVersion::StableV2 => format!("xai:v2:{PROVIDER_ACCOUNT_DIGEST}"),
        CredentialVersion::BrokerV3 => format!("xai:v3:{PROVIDER_ACCOUNT_DIGEST}"),
    }
}

/// Runs the production one-shot launchd broker using its embedded app signer.
///
/// # Errors
///
/// Returns a bounded, non-secret validation, protocol, or Keychain error.
pub fn run_production_broker() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        macos::run_production_server(protocol::BrokerNamespace::Provider)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err("The Grok Build+ Keychain broker is available only on macOS.".into())
    }
}

#[cfg(all(target_os = "macos", feature = "broker-fixture"))]
pub use macos::{FixtureParentVariant, run_fixture_broker, run_fixture_parent};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_keychain_targets_are_fixed_and_versioned() {
        assert_eq!(
            provider_account(CredentialVersion::LegacyV1),
            "xai:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
        );
        assert_eq!(
            provider_account(CredentialVersion::StableV2),
            "xai:v2:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
        );
        assert_eq!(
            provider_account(CredentialVersion::BrokerV3),
            "xai:v3:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
        );
        assert_eq!(BROKER_PROTOCOL_VERSION, 1);
        assert_eq!(BROKER_ACCOUNT_VERSION, 3);
    }
}
