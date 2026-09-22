//! Portable credential identities; OS transport construction stays target-gated.
use std::fmt;

#[cfg(any(target_os = "macos", test))]
pub(crate) const MAX_SECRET_BYTES: usize = 8 * 1024;

/// Exact provider-credential storage generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CredentialVersion {
    /// Original pre-stable account.
    LegacyV1 = 1,
    /// Main-app-owned stable account used before the broker.
    StableV2 = 2,
    /// Stable-helper-owned account.
    BrokerV3 = 3,
}

impl CredentialVersion {
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn parse(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::LegacyV1),
            2 => Ok(Self::StableV2),
            3 => Ok(Self::BrokerV3),
            _ => Err("Keychain broker refused an unknown credential version.".into()),
        }
    }
}

/// Non-secret SHA-256 binding of one app project, server, issuer and client.
/// This identifies only a fixed MCP Keychain namespace, never an arbitrary item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpCredentialKey([u8; 32]);
impl McpCredentialKey {
    /// Creates an item identity from an app-computed binding digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
    #[cfg(any(target_os = "macos", test))]
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.0
    }
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn account(self) -> String {
        let mut account = String::from("mcp:v1:");
        for byte in self.0 {
            use std::fmt::Write as _;
            write!(&mut account, "{byte:02x}").expect("write to String");
        }
        account
    }
}

/// Fixed operation supported by the broker protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BrokerAction {
    /// Inspect presence without returning secret data.
    Inspect = 1,
    /// Explicit user flow may show macOS authorization UI.
    LoadInteractive = 2,
    /// Automatic reconnect must not show authorization UI.
    LoadWithoutUi = 3,
    /// Store v3 bytes supplied by the verified app peer.
    Store = 4,
    /// Delete one exact version during explicit cleanup.
    Delete = 5,
}

impl BrokerAction {
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn parse(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Inspect),
            2 => Ok(Self::LoadInteractive),
            3 => Ok(Self::LoadWithoutUi),
            4 => Ok(Self::Store),
            5 => Ok(Self::Delete),
            _ => Err("Keychain broker refused an unknown operation.".into()),
        }
    }
}

/// Owned secret frame that overwrites its allocation on drop.
pub struct BrokerSecret(Vec<u8>);

impl BrokerSecret {
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            return Err("Keychain broker refused an empty or oversized secret frame.".into());
        }
        Ok(Self(bytes))
    }

    /// Borrows the secret for an in-memory provider lease or socket write.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Transfers ownership while leaving this object's allocation empty.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for BrokerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrokerSecret([redacted])")
    }
}

impl Drop for BrokerSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
