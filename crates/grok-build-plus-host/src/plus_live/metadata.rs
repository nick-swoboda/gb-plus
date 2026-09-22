//! Fixed authenticated model metadata and stateless compaction endpoints.

use super::*;

/// Retrieves models available to this exact API-key identity. Language metadata
/// includes modalities; missing context-window information remains absent.
///
/// # Errors
/// Refuses HTTP redirects, invalid framing/JSON, cancellation, and bounded I/O failures.
pub fn get_plus_live_model_catalog(
    identity: &PlusLiveIdentity,
    language_metadata: bool,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Value, PlusHostError> {
    let path = if language_metadata {
        "/v1/language-models"
    } else {
        "/v1/models"
    };
    fixed_json_request("GET", path, b"", identity, &mut cancelled)
}

/// Compacts exact local context through the official xAI endpoint. The response
/// remains opaque provider data; callers must journal it before continuation.
///
/// # Errors
/// Refuses oversized context, cancellation, redirects, and protocol failures.
pub fn post_plus_live_compaction(
    input: &[Value],
    model: &str,
    identity: &PlusLiveIdentity,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Value, PlusHostError> {
    // Reuse model/effort/input bounds and never permit provider-side storage.
    let validated = encode_plus_live_conversation_request(input, model, None, identity)?;
    drop(validated);
    let body = serde_json::to_vec(&serde_json::json!({"model":model,"input":input,"store":false}))
        .map_err(|error| PlusHostError::Live(error.to_string()))?;
    fixed_json_request(
        "POST",
        "/v1/responses/compact",
        &body,
        identity,
        &mut cancelled,
    )
}

fn fixed_json_request(
    method: &str,
    path: &str,
    body: &[u8],
    identity: &PlusLiveIdentity,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Value, PlusHostError> {
    if cancelled() {
        return Err(PlusHostError::LiveCancelled);
    }
    let server = ServerName::try_from(PLUS_LIVE_HOST)
        .map_err(|_| PlusHostError::Live("Invalid fixed xAI TLS name.".into()))?
        .to_owned();
    let connection = ClientConnection::new(live_client_config()?, server).map_err(|error| {
        PlusHostError::LiveTransport(format!("xAI TLS session failed: {error}"))
    })?;
    let tcp = connect_live_tcp()?;
    tcp.set_read_timeout(Some(LIVE_STREAM_POLL_TIMEOUT))
        .map_err(|error| PlusHostError::LiveTransport(error.to_string()))?;
    let mut tls = StreamOwned::new(connection, tcp);
    let started = Instant::now();
    while tls.conn.is_handshaking() {
        if cancelled() {
            return Err(PlusHostError::LiveCancelled);
        }
        if started.elapsed() > LIVE_CONNECT_TIMEOUT {
            return Err(PlusHostError::LiveTransport(
                "xAI metadata TLS handshake timed out.".into(),
            ));
        }
        match tls.conn.complete_io(&mut tls.sock) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(PlusHostError::LiveTransport(error.to_string())),
        }
    }
    write_metadata_request(&mut tls, method, path, body, identity)?;
    let mut reader = LiveBodyReader::new(tls, cancelled)?;
    if !(200..300).contains(&reader.status_code) {
        return Err(PlusHostError::LiveHttp {
            status: reader.status_code,
        });
    }
    let mut bytes = Vec::new();
    while let Some(piece) = reader.next_piece(cancelled)? {
        if started.elapsed() > Duration::from_mins(2)
            || bytes.len().saturating_add(piece.len()) > LIVE_MAX_RESPONSE_BYTES
        {
            return Err(PlusHostError::LiveTransport(
                "xAI metadata response exceeded its time or byte bound.".into(),
            ));
        }
        bytes.extend_from_slice(&piece);
    }
    if cancelled() {
        return Err(PlusHostError::LiveCancelled);
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| PlusHostError::Live("xAI metadata response is not valid JSON.".into()))
}

fn write_metadata_request(
    stream: &mut impl Write,
    method: &str,
    path: &str,
    body: &[u8],
    identity: &PlusLiveIdentity,
) -> Result<(), PlusHostError> {
    if !matches!(
        (method, path),
        ("GET", "/v1/models" | "/v1/language-models") | ("POST", "/v1/responses/compact")
    ) || identity.api_key.iter().any(u8::is_ascii_control)
        || body.len() > LIVE_MAX_REQUEST_BODY_BYTES
    {
        return Err(PlusHostError::LiveSecurity(
            "xAI metadata request violates its fixed transport binding.".into(),
        ));
    }
    let mut header =
        format!("{method} {path} HTTP/1.1\r\nHost: {PLUS_LIVE_HOST}\r\nAuthorization: Bearer ")
            .into_bytes();
    header.extend_from_slice(&identity.api_key);
    header.extend_from_slice(format!("\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes());
    let result = stream.write_all(&header);
    header.fill(0);
    result
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush())
        .map_err(|error| PlusHostError::LiveTransport(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_transport_uses_only_fixed_paths_and_refuses_credential_header_injection() {
        let identity = PlusLiveIdentity::from_configured_key("fixture").unwrap();
        let mut bytes = Vec::new();
        write_metadata_request(&mut bytes, "GET", "/v1/language-models", b"", &identity).unwrap();
        assert!(bytes.starts_with(b"GET /v1/language-models HTTP/1.1\r\nHost: api.x.ai\r\n"));
        let mut rejected = Vec::new();
        assert!(
            write_metadata_request(
                &mut rejected,
                "GET",
                "https://foreign.invalid",
                b"",
                &identity
            )
            .is_err()
        );
        let bad = PlusLiveIdentity::from_configured_key("fixture\r\nInjected: value").unwrap();
        assert!(write_metadata_request(&mut rejected, "GET", "/v1/models", b"", &bad).is_err());
        assert!(rejected.is_empty());
    }
}
