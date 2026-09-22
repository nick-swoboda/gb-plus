//! Revocable credentials bound by the app to one project, server and endpoint.
use reqwest::header::HeaderValue;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

/// An app-issued bearer lease. The app resolves its credential from its own
/// validated account record; provider-supplied project or server fields are not
/// accepted at the execution boundary. Debug/serialization are intentionally absent.
pub struct McpBearerAuthorization {
    project: crate::ProjectId,
    server: String,
    endpoint: reqwest::Url,
    header: HeaderValue,
    addresses: Vec<SocketAddr>,
    expires_at_unix_ms: Option<u64>,
    revoked: Arc<AtomicBool>,
}

impl McpBearerAuthorization {
    /// Bind a credential to a complete classified DNS answer and exact app scope.
    /// No network or credential lookup occurs here.
    ///
    /// # Errors
    /// Refuses invalid scopes, endpoints, token syntax, private DNS answers,
    /// expired credentials or an already-revoked lease.
    pub fn new(
        project: crate::ProjectId,
        server: String,
        endpoint: &str,
        token: &[u8],
        addresses: Vec<SocketAddr>,
        expires_at_unix_ms: Option<u64>,
        revoked: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        super::super::McpCatalog::new(project.clone(), server.clone())?;
        let endpoint = super::endpoint_url(endpoint)?;
        let core = token.split(|b| *b == b'=').next().unwrap_or_default();
        if token.is_empty()
            || token.len() > 3072
            || core.is_empty()
            || !token
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(b))
            || token
                .iter()
                .position(|b| *b == b'=')
                .is_some_and(|n| token[n..].iter().any(|b| *b != b'='))
        {
            return Err("MCP bearer token syntax is invalid.".into());
        }
        let addresses = super::public_network::pin_addresses(
            addresses,
            endpoint
                .port_or_known_default()
                .ok_or("MCP endpoint has no port.")?,
        )?;
        let host = endpoint.host_str().ok_or("MCP endpoint has no host.")?;
        if let Ok(literal) = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            && (!super::public_network::public_address(literal)
                || addresses.iter().any(|address| address.ip() != literal))
        {
            return Err(
                "MCP literal endpoint is private or differs from its admitted address.".into(),
            );
        }
        let mut bytes = b"Bearer ".to_vec();
        bytes.extend_from_slice(token);
        let mut header =
            HeaderValue::from_bytes(&bytes).map_err(|_| "MCP bearer header is invalid.")?;
        bytes.fill(0);
        header.set_sensitive(true);
        let lease = Self {
            project,
            server,
            endpoint,
            header,
            addresses,
            expires_at_unix_ms,
            revoked,
        };
        lease.check()?;
        Ok(lease)
    }
    pub(super) fn check(&self) -> Result<(), String> {
        let now = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "MCP credential clock is unavailable.")?
                .as_millis(),
        )
        .map_err(|_| "MCP credential clock exceeded its bound.")?;
        if self.revoked.load(Ordering::Acquire)
            || self
                .expires_at_unix_ms
                .is_some_and(|n| n <= now.saturating_add(30_000))
        {
            return Err(
                "MCP account was revoked or needs a fresh token. Submitted calls are not replayed."
                    .into(),
            );
        }
        Ok(())
    }
    pub(super) fn endpoint(&self) -> &reqwest::Url {
        &self.endpoint
    }
    pub(super) fn header(&self) -> HeaderValue {
        self.header.clone()
    }
    pub(super) fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
    pub(super) fn check_scope(
        &self,
        project: &crate::ProjectId,
        server: &str,
    ) -> Result<(), String> {
        self.check()?;
        if project != &self.project || server != self.server {
            return Err("MCP credential cannot cross its project or server binding.".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease(revoked: Arc<AtomicBool>) -> McpBearerAuthorization {
        McpBearerAuthorization::new(
            crate::ProjectId::new("fixture-project"),
            "a".repeat(64),
            "https://example.com/mcp",
            b"synthetic-token",
            vec!["8.8.8.8:443".parse().unwrap()],
            None,
            revoked,
        )
        .unwrap()
    }
    #[test]
    fn credentials_are_scoped_revocable_and_redacted_in_http_debug() {
        let revoked = Arc::new(AtomicBool::new(false));
        let grant = lease(revoked.clone());
        assert!(
            grant
                .check_scope(&crate::ProjectId::new("other"), &"a".repeat(64))
                .is_err()
        );
        assert!(
            grant
                .check_scope(&crate::ProjectId::new("fixture-project"), &"b".repeat(64))
                .is_err()
        );
        assert!(
            grant
                .check_scope(&crate::ProjectId::new("fixture-project"), &"a".repeat(64))
                .is_ok()
        );
        assert!(!format!("{:?}", grant.header()).contains("synthetic-token"));
        revoked.store(true, Ordering::Release);
        assert!(grant.check().is_err());
    }
    #[test]
    fn a_literal_endpoint_cannot_bypass_its_address_admission() {
        for endpoint in [
            "https://127.0.0.1/mcp",
            "https://2130706433/mcp",
            "https://0x7f000001/mcp",
            "https://[::1]/mcp",
            "https://1.1.1.1/mcp",
        ] {
            assert!(
                McpBearerAuthorization::new(
                    crate::ProjectId::new("fixture-project"),
                    "a".repeat(64),
                    endpoint,
                    b"synthetic",
                    vec!["8.8.8.8:443".parse().unwrap()],
                    None,
                    Arc::new(AtomicBool::new(false)),
                )
                .is_err(),
                "literal endpoint and supplied addresses must agree: {endpoint}"
            );
        }
    }

    #[test]
    fn private_addresses_header_injection_and_expired_tokens_refuse() {
        for (token, address, expires) in [
            (b"bad\r\nheader".as_slice(), "8.8.8.8:443", None),
            (b"synthetic".as_slice(), "127.0.0.1:443", None),
            (b"synthetic".as_slice(), "8.8.8.8:443", Some(1)),
        ] {
            assert!(
                McpBearerAuthorization::new(
                    crate::ProjectId::new("fixture-project"),
                    "a".repeat(64),
                    "https://example.com/mcp",
                    token,
                    vec![address.parse().unwrap()],
                    expires,
                    Arc::new(AtomicBool::new(false))
                )
                .is_err()
            );
        }
    }
}
