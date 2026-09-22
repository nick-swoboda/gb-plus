//! Optional bounded WebSocket carrier behind the host-owned request boundary.
#[cfg(test)]
mod bridge_tests;
#[cfg(test)]
#[path = "websocket/carrier_tests.rs"]
mod carrier_tests;
mod chain;
mod exchange;
mod leases;
mod privacy;
mod session;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, handshake::client::Request, protocol::WebSocketConfig,
};

const MAX_MESSAGE: usize = 1024 * 1024;
const MAX_WRITE: usize = 12 * 1024 * 1024 + 64 * 1024;
const MAX_FRAME: usize = 1024 * 1024;

/// Fixed finite carrier limits; the application adds request/aggregate bounds.
#[must_use]
fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(MAX_WRITE)
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_FRAME))
        .accept_unmasked_frames(false)
}

/// Construct the sole permitted endpoint after establishing logging privacy.
///
/// # Errors
/// Refuses unavailable privacy or malformed/bounded credential bytes. Errors never include them.
fn request(credential: &[u8]) -> Result<Request, String> {
    privacy::ensure()?;
    if credential.is_empty()
        || credential.len() > 4096
        || !credential.iter().all(|b| (33..=126).contains(b))
    {
        return Err("Credential rejected".into());
    }
    let mut request = "wss://api.x.ai/v1/responses"
        .into_client_request()
        .map_err(|_| "Request setup failed")?;
    let mut bearer = b"Bearer ".to_vec();
    bearer.extend_from_slice(credential);
    let header = tokio_tungstenite::tungstenite::http::HeaderValue::from_bytes(&bearer);
    bearer.fill(0);
    let mut header = header.map_err(|_| "Credential header rejected")?;
    header.set_sensitive(true);
    request.headers_mut().insert("authorization", header);
    Ok(request)
}

use super::{
    PlusHostError, PlusLiveChatRequest, PlusLiveStreamEvent, plus_live_usage_from_value,
    validate_live_request_binding,
};
use sha2::Digest as _;
/// Optional bounded native connection; construction performs no inference.
pub struct PlusLiveWebSocket {
    carrier: session::Session,
    account: Option<[u8; 32]>,
}
impl PlusLiveWebSocket {
    /// Construct without opening a network connection.
    ///
    /// # Errors
    /// Refuses unavailable private logging, runtime creation or cleanup services.
    pub fn new() -> Result<Self, PlusHostError> {
        Ok(Self {
            carrier: session::Session::new()
                .map_err(|reason| PlusHostError::LiveSecurity(reason.into()))?,
            account: None,
        })
    }
    /// Close the warm connection and discard its memory-only continuation.
    ///
    /// # Errors
    /// Reports a failed ownership lock after closing any recovered socket.
    pub fn close(&mut self) -> Result<(), PlusHostError> {
        self.account = None;
        self.carrier
            .close()
            .map_err(|reason| PlusHostError::LiveSecurity(reason.into()))
    }
    /// Send once using a host-owned authenticated request and full local context.
    /// Unknown delivery interrupts; no protocol fallback or resend happens here.
    /// Construct, use and close this synchronous owner on a blocking worker,
    /// as with the native HTTP carrier.
    ///
    /// # Errors
    /// Refuses changed bindings, protocol limits, cancellation and transport loss.
    pub fn send(
        &mut self,
        request: &PlusLiveChatRequest,
        mut cancelled: impl FnMut() -> bool,
        mut emit: impl FnMut(PlusLiveStreamEvent),
    ) -> Result<Vec<u8>, PlusHostError> {
        validate_live_request_binding(request)?;
        // A changed host credential starts a fresh connection. No secret is
        // retained by this guard, and no account identifier reaches diagnostics.
        let account: [u8; 32] = sha2::Sha256::digest(&request.authorization).into();
        if self.account.is_some_and(|prior| prior != account) {
            self.close()?;
        }
        self.account = Some(account);
        let response = self.carrier.request(
            &request.authorization, &request.body, &mut cancelled, |event| {
                match event["type"].as_str() {
                    Some("response.output_text.delta") => {
                        if let Some(delta) = event["delta"].as_str() && !delta.is_empty() {
                            emit(PlusLiveStreamEvent::AssistantDelta(delta.into()));
                        }
                    }
                    Some("response.reasoning_text.delta" | "response.reasoning_summary_text.delta") => {
                        if let Some(delta) = event["delta"].as_str() && !delta.is_empty() {
                            emit(PlusLiveStreamEvent::ThoughtDelta(delta.into()));
                        }
                    }
                    Some("response.completed") => {
                        if let Some(usage) = event.pointer("/response/usage").and_then(plus_live_usage_from_value) {
                            emit(PlusLiveStreamEvent::Usage(usage));
                        }
                    }
                    _ => {}
                }
                Ok(())
            },
        ).map_err(|failure| match failure {
            exchange::Failure::Cancelled => PlusHostError::LiveCancelled,
            exchange::Failure::Rejected(status) => PlusHostError::LiveHttp { status },
            exchange::Failure::Deadline => PlusHostError::LiveTransport(
                "Native WebSocket deadline expired; submitted delivery is uncertain.".into(),
            ),
            exchange::Failure::Closed | exchange::Failure::Io => PlusHostError::LiveTransport(
                "Native WebSocket closed or lost transport; submitted delivery is uncertain.".into(),
            ),
            exchange::Failure::Protocol => PlusHostError::Live(
                "Native WebSocket protocol or provider failure; raw response detail was withheld.".into(),
            ),
        })?;
        // This runs before the app dispatches any returned effect. A parent must
        // not retain a socket while its execution lease yields to two children.
        let delegates = response["output"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["type"] == "function_call"
                    && item["name"]
                        .as_str()
                        .is_some_and(crate::PlusCollaborationCommand::recognizes)
            })
        });
        if delegates {
            self.close()?;
        }
        if cancelled() {
            self.close()?;
            return Err(PlusHostError::LiveCancelled);
        }
        serde_json::to_vec(&response)
            .map_err(|_| PlusHostError::Live("Native WebSocket completion encoding failed.".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio_tungstenite::tungstenite::{Message, WebSocket, protocol::Role};
    #[test]
    fn actual_parser_rejects_oversized_and_invalid_utf8_frames() {
        // Server frames are unmasked. A small configured maximum permits this
        // regression without allocating a production-limit payload.
        let cfg = config().max_frame_size(Some(4)).max_message_size(Some(4));
        let mut socket = WebSocket::from_raw_socket(
            Cursor::new(vec![0x81, 5, b'a', b'b', b'c', b'd', b'e']),
            Role::Client,
            Some(cfg),
        );
        assert!(socket.read().is_err());
        let mut socket = WebSocket::from_raw_socket(
            Cursor::new(vec![0x81, 1, 0xff]),
            Role::Client,
            Some(config()),
        );
        assert!(socket.read().is_err());
        let mut socket = WebSocket::from_raw_socket(
            Cursor::new(vec![0x81, 2, b'o', b'k']),
            Role::Client,
            Some(config()),
        );
        assert_eq!(socket.read().unwrap(), Message::text("ok"));
    }
    #[test]
    fn fixed_authenticated_request_rejects_header_injection() {
        for invalid in [b"".as_slice(), b"a\r\nx: forged", b"a b", b"\0"] {
            assert!(request(invalid).is_err());
        }
        let request = request(b"SYNTHETIC_ADMISSION_TOKEN").unwrap();
        assert_eq!(request.uri().to_string(), "wss://api.x.ai/v1/responses");
        assert!(request.headers()["authorization"].is_sensitive());
        assert_eq!(
            request.headers()["authorization"].to_str().unwrap(),
            "Bearer SYNTHETIC_ADMISSION_TOKEN"
        );
    }
}
