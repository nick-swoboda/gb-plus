//! HTTPS carrier for broker-owned MCP sessions. No automatic retries or auth.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use reqwest::{Client, Response, Url};
use rustls_platform_verifier::BuilderVerifierExt as _;

use super::{MCP_MAX_CONNECTION_BYTES, MCP_MAX_FRAME_BYTES, McpProtocolVersion};

mod authorization;
mod public_network;
pub use public_network::pin_addresses as mcp_pin_public_addresses;
#[path = "https/sse.rs"]
mod sse;
pub use authorization::McpBearerAuthorization;

const MAX_CLIENTS: usize = 8;
const MAX_REQUESTS: usize = 4;
static CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Bounded observations; JSON bytes still require `McpProtocol` validation.
pub enum McpHttpEvent {
    /// A JSON-RPC message, which must be correlated by the independent broker.
    Message(Vec<u8>),
    /// An opaque SSE replay cursor, emitted after its message is accepted by the
    /// callback. Advance durable replay only after that message's journal commit.
    Cursor(String),
}

/// HTTP completion does not by itself prove a model/tool consumed a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpHttpOutcome {
    /// HTTP 202 acknowledged a notification or response with no result body.
    Accepted,
    /// JSON or SSE body ended; only matching JSON-RPC messages prove completion.
    BodyEnded,
    /// Optional standalone server-to-client SSE is unsupported (HTTP 405).
    StreamUnavailable,
    /// HTTP 401/403 requires app account/scope inspection. No retry was performed.
    AuthenticationRequired,
    /// The MCP session no longer exists. Outstanding effects remain uncertain.
    SessionExpired,
    /// HTTP 404 arrived without an assigned session; endpoint availability is unknown.
    EndpointUnavailable,
}

struct ClientReservation;
impl ClientReservation {
    fn acquire() -> Result<Self, String> {
        CLIENTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_CLIENTS).then_some(count + 1)
            })
            .map_err(|_| "MCP HTTPS connection capacity is occupied.")?;
        Ok(Self)
    }
}
impl Drop for ClientReservation {
    fn drop(&mut self) {
        CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RequestReservation<'a>(&'a AtomicUsize);
impl Drop for RequestReservation<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One fixed HTTPS endpoint, optional opaque session, and finite carrier budget.
/// A broker must resolve enabled content and permission before constructing it.
/// It performs no credential, cookie, proxy or project-file discovery.
pub struct McpHttpsClient {
    client: Client,
    endpoint: Url,
    authorization: Option<Arc<McpBearerAuthorization>>,
    session: Mutex<Option<String>>,
    protocol_version: Mutex<Option<McpProtocolVersion>>,
    initializing: AtomicBool,
    closed: AtomicBool,
    active_data: AtomicUsize,
    active_control: AtomicUsize,
    bytes: AtomicUsize,
    _reservation: ClientReservation,
}

impl McpHttpsClient {
    /// Construct an independent HTTPS client with platform certificate validation.
    /// No network I/O occurs until `post` or `listen` is explicitly awaited.
    ///
    /// # Errors
    /// Refuses credentials/query/fragment in the endpoint, non-HTTPS URLs,
    /// exhausted capacity or TLS configuration failure. No insecure fallback exists.
    pub fn new(endpoint: &str) -> Result<Self, String> {
        Self::new_inner(endpoint_url(endpoint)?, None)
    }

    /// Create a carrier for one already-resolved and app-bound credential lease.
    ///
    /// # Errors
    /// Refuses a revoked/expired lease or the same carrier/TLS limits as `new`.
    pub fn new_authenticated(authorization: Arc<McpBearerAuthorization>) -> Result<Self, String> {
        authorization.check()?;
        Self::new_inner(authorization.endpoint().clone(), Some(authorization))
    }

    fn new_inner(
        endpoint: Url,
        authorization: Option<Arc<McpBearerAuthorization>>,
    ) -> Result<Self, String> {
        let reservation = ClientReservation::acquire()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "MCP TLS versions unavailable.")?
            .with_platform_verifier()
            .map_err(|_| "MCP platform certificate verifier unavailable.")?
            .with_no_client_auth();
        let mut builder = Client::builder()
            .tls_backend_preconfigured(config)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .referer(false)
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_mins(15))
            .pool_max_idle_per_host(0);
        if let Some(authorization) = &authorization {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::AUTHORIZATION, authorization.header());
            builder = builder.default_headers(headers).resolve_to_addrs(
                endpoint.host_str().ok_or("MCP endpoint has no host.")?,
                authorization.addresses(),
            );
        }
        let client = builder
            .build()
            .map_err(|_| "MCP HTTPS client setup failed.")?;
        Ok(Self {
            client,
            endpoint,
            authorization,
            session: Mutex::new(None),
            protocol_version: Mutex::new(None),
            initializing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            active_data: AtomicUsize::new(0),
            active_control: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            _reservation: reservation,
        })
    }

    /// POST one already-authorized and journaled JSON-RPC message. Every response
    /// to server elicitation is a new POST, independent of the original SSE body.
    /// No failed/uncertain request is replayed by this carrier.
    ///
    /// # Errors
    /// Refuses invalid framing, deadlines, malformed headers, oversized responses,
    /// redirects or cancellation. Errors contain no server body, URL or token.
    pub async fn post(
        &self,
        message: &[u8],
        cancelled: &AtomicBool,
        events: &mut (impl FnMut(McpHttpEvent) -> Result<(), String> + Send),
    ) -> Result<McpHttpOutcome, String> {
        let result = self.post_inner(message, cancelled, events).await;
        if result.is_err() {
            self.close();
        }
        result
    }

    async fn post_inner(
        &self,
        message: &[u8],
        cancelled: &AtomicBool,
        events: &mut (impl FnMut(McpHttpEvent) -> Result<(), String> + Send),
    ) -> Result<McpHttpOutcome, String> {
        self.check_cancelled(cancelled)?;
        if message.is_empty() || message.len() > MCP_MAX_FRAME_BYTES {
            return Err("MCP HTTPS message exceeds its bound.".into());
        }
        let value: serde_json::Value = serde_json::from_slice(message)
            .map_err(|_| "MCP POST requires one JSON-RPC message.")?;
        if !value.is_object() || value["jsonrpc"] != "2.0" {
            return Err("MCP POST requires one JSON-RPC object.".into());
        }
        let initialize =
            value.get("method").and_then(serde_json::Value::as_str) == Some("initialize");
        if initialize && self.initializing.swap(true, Ordering::AcqRel) {
            return Err("MCP HTTPS initialization cannot be replayed.".into());
        }
        let is_request = value.get("method").is_some() && value.get("id").is_some();
        let _slot = self.reserve(!is_request)?;
        self.account(message.len())?;
        let mut request = self
            .client
            .post(self.endpoint.clone())
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(message.to_vec());
        if value.get("method").and_then(serde_json::Value::as_str) != Some("tools/call") {
            request = request.timeout(Duration::from_secs(10));
        }
        if !initialize {
            request = self.session_headers(request)?;
        }
        let response = self.send(request, cancelled).await?;
        validate_headers(&response)?;
        if let Some(outcome) = self.status(&response) {
            return Ok(outcome);
        }
        if !is_request {
            if response.status().as_u16() != 202 {
                return Err("MCP response/notification was not acknowledged with HTTP 202.".into());
            }
            let bytes = self.read_json(response, cancelled).await?;
            if !bytes.is_empty() {
                return Err("MCP HTTP 202 included an unexpected body.".into());
            }
            return Ok(McpHttpOutcome::Accepted);
        }
        if response.status().as_u16() != 200 {
            return Err("MCP request returned an unsupported HTTP status.".into());
        }
        self.observe_session(&response, initialize)?;
        self.read_body(response, cancelled, events).await
    }

    /// Open the optional independent SSE channel. Reconnection is explicit and
    /// may pass only a cursor previously observed on this same app-bound endpoint.
    /// This method never resends a POST or performs legacy transport fallback.
    ///
    /// # Errors
    /// Uses the same bounds and cancellation as POST. The broker must treat
    /// unfinished requests as uncertain on loss; an SSE disconnect is not cancel.
    pub async fn listen(
        &self,
        last_event_id: Option<&str>,
        cancelled: &AtomicBool,
        events: &mut (impl FnMut(McpHttpEvent) -> Result<(), String> + Send),
    ) -> Result<McpHttpOutcome, String> {
        let result = self.listen_inner(last_event_id, cancelled, events).await;
        if result.is_err() {
            self.close();
        }
        result
    }

    async fn listen_inner(
        &self,
        last_event_id: Option<&str>,
        cancelled: &AtomicBool,
        events: &mut (impl FnMut(McpHttpEvent) -> Result<(), String> + Send),
    ) -> Result<McpHttpOutcome, String> {
        self.check_cancelled(cancelled)?;
        let _slot = self.reserve(false)?;
        let mut request = self.session_headers(
            self.client
                .get(self.endpoint.clone())
                .header("Accept", "text/event-stream"),
        )?;
        if let Some(cursor) = last_event_id {
            if cursor.is_empty() || cursor.len() > 256 || cursor.chars().any(char::is_control) {
                return Err("MCP replay cursor is invalid.".into());
            }
            request = request.header("Last-Event-ID", cursor);
        }
        let response = self.send(request, cancelled).await?;
        validate_headers(&response)?;
        if let Some(outcome) = self.status(&response) {
            return Ok(outcome);
        }
        if response.status().as_u16() == 405 {
            return Ok(McpHttpOutcome::StreamUnavailable);
        }
        if response.status().as_u16() != 200 || content_type(&response)? != "text/event-stream" {
            return Err("MCP standalone stream is not an HTTP 200 SSE response.".into());
        }
        self.observe_session(&response, false)?;
        self.read_body(response, cancelled, events).await
    }

    fn session_headers(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder, String> {
        let version = *self
            .protocol_version
            .lock()
            .map_err(|_| "MCP version lock is unavailable.")?;
        let version =
            version.ok_or("MCP protocol must be validated before sending subsequent messages.")?;
        request = request.header("MCP-Protocol-Version", version.as_str());
        if let Some(session) = self
            .session
            .lock()
            .map_err(|_| "MCP session lock is unavailable.")?
            .as_ref()
        {
            let mut value = reqwest::header::HeaderValue::from_str(session)
                .map_err(|_| "MCP session header is invalid.")?;
            value.set_sensitive(true);
            request = request.header("Mcp-Session-Id", value);
        }
        Ok(request)
    }

    /// Bind HTTP headers to the version validated by the owning `McpProtocol`.
    /// Call this after parsing initialization and before sending its initialized
    /// notification. This changes wire behavior and grants no tool authority.
    ///
    /// # Errors
    /// Refuses pre-initialization use, closed clients, or a later version change.
    pub fn finish_initialization(&self, version: McpProtocolVersion) -> Result<(), String> {
        if !self.initializing.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            return Err("MCP HTTP initialization is not awaiting validation.".into());
        }
        let mut selected = self
            .protocol_version
            .lock()
            .map_err(|_| "MCP version lock is unavailable.")?;
        if selected.is_some_and(|previous| previous != version) {
            return Err("MCP HTTP negotiated version cannot change on this connection.".into());
        }
        *selected = Some(version);
        Ok(())
    }

    fn observe_session(&self, response: &Response, initialize: bool) -> Result<(), String> {
        let Some(value) = response.headers().get("mcp-session-id") else {
            return Ok(());
        };
        let value = value
            .to_str()
            .map_err(|_| "MCP session header is not text.")?;
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err("MCP session header is invalid or oversized.".into());
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| "MCP session lock is unavailable.")?;
        if initialize && session.is_none() {
            *session = Some(value.to_owned());
        } else if session.as_deref() != Some(value) {
            return Err("MCP server changed the owning session identity.".into());
        }
        Ok(())
    }

    fn status(&self, response: &Response) -> Option<McpHttpOutcome> {
        match response.status().as_u16() {
            401 | 403 => {
                self.close();
                Some(McpHttpOutcome::AuthenticationRequired)
            }
            404 => {
                self.close();
                Some(
                    if self.session.lock().is_ok_and(|session| session.is_some()) {
                        McpHttpOutcome::SessionExpired
                    } else {
                        McpHttpOutcome::EndpointUnavailable
                    },
                )
            }
            _ => None,
        }
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        cancelled: &AtomicBool,
    ) -> Result<Response, String> {
        // Poll the one send future; restarting it would duplicate a partial POST.
        let mut pending = Box::pin(request.send());
        loop {
            self.check_cancelled(cancelled)?;
            if let Ok(result) = tokio::time::timeout(Duration::from_millis(100), &mut pending).await
            {
                return result
                    .map_err(|_| "MCP HTTPS request failed; delivery may be uncertain.".into());
            }
        }
    }

    async fn next_chunk(
        &self,
        response: &mut Response,
        cancelled: &AtomicBool,
    ) -> Result<Option<reqwest::Body>, String> {
        loop {
            self.check_cancelled(cancelled)?;
            match tokio::time::timeout(Duration::from_millis(100), response.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    self.account(bytes.len())?;
                    return Ok(Some(reqwest::Body::from(bytes)));
                }
                Ok(Ok(None)) => return Ok(None),
                Ok(Err(_)) => return Err("MCP HTTPS body ended with uncertain delivery.".into()),
                Err(_) => {}
            }
        }
    }

    async fn read_json(
        &self,
        mut response: Response,
        cancelled: &AtomicBool,
    ) -> Result<Vec<u8>, String> {
        if response
            .content_length()
            .is_some_and(|n| n > MCP_MAX_FRAME_BYTES as u64)
        {
            return Err("MCP JSON body exceeded its bound.".into());
        }
        let mut body = Vec::new();
        while let Some(chunk) = self.next_chunk(&mut response, cancelled).await? {
            let bytes = chunk
                .as_bytes()
                .ok_or("MCP response chunk is not buffered bytes.")?;
            if body.len().saturating_add(bytes.len()) > MCP_MAX_FRAME_BYTES {
                return Err("MCP JSON body exceeded its bound.".into());
            }
            body.extend_from_slice(bytes);
        }
        Ok(body)
    }

    async fn read_body(
        &self,
        mut response: Response,
        cancelled: &AtomicBool,
        events: &mut (impl FnMut(McpHttpEvent) -> Result<(), String> + Send),
    ) -> Result<McpHttpOutcome, String> {
        match content_type(&response)?.as_str() {
            "application/json" => {
                events(McpHttpEvent::Message(
                    self.read_json(response, cancelled).await?,
                ))?;
            }
            "text/event-stream" => {
                let mut decoder = sse::Decoder::default();
                while let Some(chunk) = self.next_chunk(&mut response, cancelled).await? {
                    decoder.push(
                        chunk
                            .as_bytes()
                            .ok_or("MCP SSE chunk is not buffered bytes.")?,
                        events,
                    )?;
                }
                decoder.finish()?;
            }
            _ => return Err("MCP response uses an unsupported content type.".into()),
        }
        Ok(McpHttpOutcome::BodyEnded)
    }

    /// Revoke this carrier. Active awaited operations observe it within a bounded
    /// polling interval; outstanding requests must be recorded as uncertain.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    fn check_cancelled(&self, cancelled: &AtomicBool) -> Result<(), String> {
        if let Some(authorization) = &self.authorization {
            authorization.check()?;
        }
        if self.closed.load(Ordering::Acquire) || cancelled.load(Ordering::Acquire) {
            return Err("MCP HTTPS operation was stopped; pending delivery is uncertain.".into());
        }
        Ok(())
    }

    pub(super) fn check_scope(
        &self,
        project: &crate::ProjectId,
        server: &str,
    ) -> Result<(), String> {
        if let Some(authorization) = &self.authorization {
            authorization.check_scope(project, server)?;
        }
        Ok(())
    }

    fn account(&self, bytes: usize) -> Result<(), String> {
        self.bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|n| *n <= MCP_MAX_CONNECTION_BYTES)
            })
            .map_err(|_| "MCP HTTPS connection byte budget exceeded.")?;
        Ok(())
    }

    fn reserve(&self, control: bool) -> Result<RequestReservation<'_>, String> {
        // A tool SSE response may wait for elicitation/cancellation. Data
        // requests and the optional GET stream cannot consume its response slot.
        let (active, maximum) = if control {
            (&self.active_control, 1)
        } else {
            (&self.active_data, MAX_REQUESTS - 1)
        };
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < maximum).then_some(n + 1)
            })
            .map_err(|_| "MCP HTTPS request capacity is occupied.")?;
        Ok(RequestReservation(active))
    }
}

fn endpoint_url(text: &str) -> Result<Url, String> {
    if text.len() > 4096 || text.chars().any(char::is_control) {
        return Err("MCP endpoint is invalid or oversized.".into());
    }
    let url = Url::parse(text).map_err(|_| "MCP endpoint is not a valid URL.")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(
            "MCP requires an HTTPS endpoint without embedded credentials, query or fragment."
                .into(),
        );
    }
    Ok(url)
}

fn validate_headers(response: &Response) -> Result<(), String> {
    let headers = response.headers();
    if headers.len() > 64
        || headers
            .iter()
            .map(|(n, v)| n.as_str().len() + v.as_bytes().len())
            .sum::<usize>()
            > 16 * 1024
    {
        return Err("MCP HTTP response headers exceeded their bound.".into());
    }
    for name in [
        "content-type",
        "content-length",
        "content-encoding",
        "mcp-session-id",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err("MCP HTTP response repeats a framing or session header.".into());
        }
    }
    if headers
        .get("content-encoding")
        .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err("Compressed MCP responses are not admitted.".into());
    }
    Ok(())
}

fn content_type(response: &Response) -> Result<String, String> {
    response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_ascii_lowercase())
        .ok_or_else(|| "MCP response omitted its content type.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_data_requests_cannot_consume_the_independent_control_slot() {
        let client = McpHttpsClient::new("https://example.invalid/mcp").unwrap();
        let data = (0..3)
            .map(|_| client.reserve(false).unwrap())
            .collect::<Vec<_>>();
        assert!(client.reserve(false).is_err());
        let control = client.reserve(true).unwrap();
        assert!(client.reserve(true).is_err());
        assert_eq!(
            client.active_data.load(Ordering::Acquire)
                + client.active_control.load(Ordering::Acquire),
            MAX_REQUESTS
        );
        drop(control);
        assert!(client.reserve(true).is_ok());
        drop(data);
        assert_eq!(client.active_data.load(Ordering::Acquire), 0);
    }

    #[test]
    fn http_headers_require_and_preserve_the_validated_negotiated_revision() {
        let client = McpHttpsClient::new("https://example.com/mcp").unwrap();
        let request = || client.client.post(client.endpoint.clone());
        assert!(client.session_headers(request()).is_err());
        assert!(
            client
                .finish_initialization(McpProtocolVersion::June2025)
                .is_err()
        );
        client.initializing.store(true, Ordering::Release);
        client
            .finish_initialization(McpProtocolVersion::June2025)
            .unwrap();
        let built = client.session_headers(request()).unwrap().build().unwrap();
        assert_eq!(built.headers()["MCP-Protocol-Version"], "2025-06-18");
        assert!(
            client
                .finish_initialization(McpProtocolVersion::November2025)
                .is_err()
        );
        let built = client.session_headers(request()).unwrap().build().unwrap();
        assert_eq!(built.headers()["MCP-Protocol-Version"], "2025-06-18");
        client.close();
        assert!(
            client
                .finish_initialization(McpProtocolVersion::June2025)
                .is_err()
        );
    }
}
