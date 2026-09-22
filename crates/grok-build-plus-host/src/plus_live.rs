//! Live xAI chat selection, request/response handling, and HTTPS POST.
//!
//! The only credential identity this module reads is process-env `XAI_API_KEY`.
//! It does not implement Keychain / Secret Service and does not write a key file.

use std::fmt::{self, Debug, Formatter, Write as _};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::BuilderVerifierExt;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::PlusHostError;
use super::plus_tools::{plus_live_tool_declarations, plus_live_tool_instructions};

mod metadata;
pub use metadata::{get_plus_live_model_catalog, post_plus_live_compaction};

/// Process-environment identity already named by the detector, trust deny-list,
/// and Gate-2 live fixture. This is the one secret the live path reads.
pub const PLUS_LIVE_KEY_ENV: &str = "XAI_API_KEY";

/// Exact remote endpoint bound before a key is attached to a request.
pub const PLUS_LIVE_ENDPOINT: &str = "https://api.x.ai/v1/responses";

/// macOS Keychain service reserved by the repository's provider-secret policy.
pub const PLUS_KEYCHAIN_SERVICE: &str = "org.grok-build.desktop.provider";

/// Host portion of [`PLUS_LIVE_ENDPOINT`].
pub const PLUS_LIVE_HOST: &str = "api.x.ai";

/// Path portion of [`PLUS_LIVE_ENDPOINT`].
pub const PLUS_LIVE_PATH: &str = "/v1/responses";

/// Official xAI text-to-speech endpoint used by Grok Read Aloud.
pub const PLUS_TTS_ENDPOINT: &str = "https://api.x.ai/v1/tts";

/// Path portion of [`PLUS_TTS_ENDPOINT`].
pub const PLUS_TTS_PATH: &str = "/v1/tts";

/// Built-in xAI voice used by the product's Grok Read Aloud control.
pub const PLUS_TTS_VOICE: &str = "eve";

/// Current xAI chat model used by the documented `/v1/responses` examples.
pub const PLUS_LIVE_MODEL: &str = "grok-4.6";

/// Label when `XAI_API_KEY` is set.
pub const PLUS_LIVE_PROVIDER_LABEL: &str = "Provider: live xAI (XAI_API_KEY)";

const LIVE_TLS_PORT: u16 = 443;
const LIVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const LIVE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const LIVE_STREAM_POLL_TIMEOUT: Duration = Duration::from_millis(250);
const LIVE_STREAM_DEADLINE: Duration = Duration::from_mins(2);
const LIVE_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const LIVE_MAX_HEADER_BYTES: usize = 64 * 1024;
const LIVE_MAX_REQUEST_BODY_BYTES: usize = 12 * 1024 * 1024;
const LIVE_MAX_IMAGE_BASE64_BYTES: usize = 8 * 1024 * 1024;
const TTS_MAX_TEXT_CHARS: usize = 15_000;
const TTS_MAX_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
const TTS_RESPONSE_DEADLINE: Duration = Duration::from_mins(3);

/// Non-empty `XAI_API_KEY` value. Debug redacts the secret.
#[derive(Clone)]
pub struct PlusLiveIdentity {
    api_key: Vec<u8>,
}

impl PlusLiveIdentity {
    /// Reads [`PLUS_LIVE_KEY_ENV`]. Empty or missing is unconfigured.
    #[must_use]
    pub fn from_process_env() -> Option<Self> {
        match std::env::var(PLUS_LIVE_KEY_ENV) {
            Ok(api_key) => Self::from_configured_key(api_key),
            _ => None,
        }
    }

    /// Same identity type as env, for tests that must not mutate process env.
    #[must_use]
    pub fn from_configured_key(api_key: impl Into<String>) -> Option<Self> {
        Self::from_configured_key_bytes(api_key.into().into_bytes())
    }

    /// Consumes non-empty UTF-8 key bytes without routing them through JSON,
    /// argv, a child environment, or another persistent representation.
    #[must_use]
    pub fn from_configured_key_bytes(api_key: Vec<u8>) -> Option<Self> {
        let text = std::str::from_utf8(&api_key).ok()?;
        if text.trim().is_empty() {
            None
        } else {
            Some(Self { api_key })
        }
    }
}

impl Drop for PlusLiveIdentity {
    fn drop(&mut self) {
        self.api_key.fill(0);
    }
}

impl Debug for PlusLiveIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlusLiveIdentity { api_key: [redacted] }")
    }
}

/// Bound live request produced by [`encode_plus_live_chat_request`].
pub struct PlusLiveChatRequest {
    /// Exact `https://api.x.ai/v1/responses` URL.
    pub endpoint: &'static str,
    /// Host used for TLS SNI and the HTTP Host header.
    pub host: &'static str,
    /// Path used for the POST line.
    pub path: &'static str,
    /// Canonical JSON body. Contains the user text; never the API key.
    pub body: String,
    authorization: Vec<u8>,
}

/// Bound official xAI `/v1/tts` request. Debug and Drop preserve the same
/// credential hygiene as the live Chat request.
pub struct PlusLiveTtsRequest {
    /// Exact `https://api.x.ai/v1/tts` URL.
    pub endpoint: &'static str,
    /// Host used for TLS SNI and the HTTP Host header.
    pub host: &'static str,
    /// Path used for the POST line.
    pub path: &'static str,
    /// Canonical JSON body. Contains speakable assistant text, never the key.
    body: String,
    authorization: Vec<u8>,
}

impl Debug for PlusLiveTtsRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlusLiveTtsRequest")
            .field("endpoint", &self.endpoint)
            .field("host", &self.host)
            .field("path", &self.path)
            .field(
                "body",
                &format_args!("[redacted assistant text; {} bytes]", self.body.len()),
            )
            .field("authorization", &"[redacted]")
            .finish()
    }
}

impl Drop for PlusLiveTtsRequest {
    fn drop(&mut self) {
        self.authorization.fill(0);
    }
}

impl PlusLiveTtsRequest {
    /// Borrows the canonical JSON body and bearer bytes only for one native
    /// transport call. The request retains ownership and zeroes authorization
    /// on drop; callers must not persist, log, or forward either value.
    pub fn with_transport_parts<T>(&self, transport: impl FnOnce(&str, &[u8]) -> T) -> T {
        transport(&self.body, &self.authorization)
    }
}

/// Bounded transient audio returned by the official xAI TTS endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusLiveTtsAudio {
    /// Provider response MIME type. GB Plus currently requires MP3.
    pub content_type: String,
    /// Exact audio bytes. The caller keeps these in memory only.
    pub bytes: Vec<u8>,
}

impl PlusLiveChatRequest {
    /// JSON body bytes the transport sends.
    #[must_use]
    pub fn json_body(&self) -> &str {
        &self.body
    }
}

impl Debug for PlusLiveChatRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlusLiveChatRequest")
            .field("endpoint", &self.endpoint)
            .field("host", &self.host)
            .field("path", &self.path)
            .field(
                "body",
                &format_args!("[redacted; {} bytes]", self.body.len()),
            )
            .field("authorization", &"[redacted]")
            .finish()
    }
}

impl Drop for PlusLiveChatRequest {
    fn drop(&mut self) {
        self.authorization.fill(0);
    }
}

/// Stable Keychain account identity for the fixed xAI Responses endpoint.
#[must_use]
pub fn plus_keychain_account() -> String {
    let digest = Sha256::digest(PLUS_LIVE_ENDPOINT.as_bytes());
    let mut account = String::with_capacity(4 + digest.len() * 2);
    account.push_str("xai:");
    for byte in digest {
        let _ = write!(account, "{byte:02x}");
    }
    account
}

#[derive(Serialize)]
struct LiveResponsesBody {
    model: &'static str,
    input: Value,
    store: bool,
    instructions: &'static str,
    tools: Value,
}

#[derive(Serialize)]
struct LiveTtsOutputFormat {
    codec: &'static str,
    sample_rate: u32,
    bit_rate: u32,
}

#[derive(Serialize)]
struct LiveTtsBody<'a> {
    text: &'a str,
    voice_id: &'static str,
    language: &'static str,
    output_format: LiveTtsOutputFormat,
}

/// One bounded transient PNG attached to a native Responses prompt.
pub struct PlusLiveImage<'a> {
    /// Base64 bytes without a data-URL prefix.
    pub base64_png: &'a str,
}

/// One native `/v1/responses` `function_call` extracted from a live body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusLiveFunctionCall {
    /// Declared tool name (`list_dir`, `read_file`, `propose_write`, `run_contained`).
    pub name: String,
    /// JSON object string for the tool arguments.
    pub arguments_json: String,
}

/// Assistant text plus any native function calls from a live response body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusLiveReply {
    /// `output_text` / chat-completions content. Empty when the model only called tools.
    pub assistant_text: String,
    /// Native `function_call` items, in order.
    pub function_calls: Vec<PlusLiveFunctionCall>,
}

/// Provider-reported xAI usage. Missing values remain absent.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlusLiveUsage {
    /// Input tokens reported by the Responses API.
    pub input_tokens: Option<u64>,
    /// Output tokens reported by the Responses API.
    pub output_tokens: Option<u64>,
    /// Reasoning tokens reported in output-token details.
    pub reasoning_tokens: Option<u64>,
    /// Cached input tokens reported in input-token details.
    pub cached_tokens: Option<u64>,
}

/// One normalized event decoded from a native Responses SSE stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusLiveStreamEvent {
    /// Visible assistant text delta.
    AssistantDelta(String),
    /// Provider reasoning/thought delta.
    ThoughtDelta(String),
    /// Direct provider usage update.
    Usage(PlusLiveUsage),
}

/// Window / smoke label for the current process identity.
#[must_use]
pub fn plus_chat_provider_label() -> &'static str {
    plus_chat_provider_label_for(PlusLiveIdentity::from_process_env().as_ref())
}

/// Label for an explicit identity (tests and Send share this spelling).
#[must_use]
pub fn plus_chat_provider_label_for(identity: Option<&PlusLiveIdentity>) -> &'static str {
    if identity.is_some() {
        PLUS_LIVE_PROVIDER_LABEL
    } else {
        super::PLUS_PROVIDER_LABEL
    }
}

/// Builds the exact `/v1/responses` JSON. The user text is the `input` field.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the body cannot be encoded.
pub fn encode_plus_live_chat_request(
    user_text: &str,
    identity: &PlusLiveIdentity,
) -> Result<PlusLiveChatRequest, PlusHostError> {
    encode_plus_live_chat_request_with_image(user_text, None, identity)
}

/// Builds a stateless Responses request from exact locally journaled items.
/// Opaque reasoning and compaction items are replayed without rewriting them.
///
/// # Errors
/// Returns an error for an invalid model/effort or a request over 12 MiB.
pub fn encode_plus_live_conversation_request(
    input: &[Value],
    model: &str,
    reasoning_effort: Option<&str>,
    identity: &PlusLiveIdentity,
) -> Result<PlusLiveChatRequest, PlusHostError> {
    if model.is_empty()
        || model.len() > 128
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
        || reasoning_effort.is_some_and(|effort| {
            !matches!(
                effort,
                "none" | "minimal" | "low" | "medium" | "high" | "xhigh"
            )
        })
    {
        return Err(PlusHostError::Live(
            "Invalid Responses model or reasoning effort.".into(),
        ));
    }
    let mut value = serde_json::json!({
        "model":model,"input":input,"store":false,"include":["reasoning.encrypted_content"],
        "instructions":super::plus_prompt::native_system_prompt(),
        "tools":plus_live_tool_declarations(),
    });
    if let Some(effort) = reasoning_effort {
        value["reasoning"] = serde_json::json!({"effort":effort});
    }
    let body =
        serde_json::to_string(&value).map_err(|error| PlusHostError::Live(error.to_string()))?;
    if body.len() > LIVE_MAX_REQUEST_BODY_BYTES {
        return Err(PlusHostError::Live(
            "Responses request exceeded 12 MiB.".into(),
        ));
    }
    Ok(PlusLiveChatRequest {
        endpoint: PLUS_LIVE_ENDPOINT,
        host: PLUS_LIVE_HOST,
        path: PLUS_LIVE_PATH,
        body,
        authorization: identity.api_key.clone(),
    })
}

/// Builds the exact `/v1/responses` JSON with an optional transient PNG.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the image or body exceeds its bound or
/// JSON encoding fails.
pub fn encode_plus_live_chat_request_with_image(
    user_text: &str,
    image: Option<&PlusLiveImage<'_>>,
    identity: &PlusLiveIdentity,
) -> Result<PlusLiveChatRequest, PlusHostError> {
    let input = if let Some(image) = image {
        if image.base64_png.is_empty()
            || image.base64_png.len() > LIVE_MAX_IMAGE_BASE64_BYTES
            || !image
                .base64_png
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(PlusHostError::Live(
                "live xAI image attachment was empty, malformed, or exceeded 8 MiB base64".into(),
            ));
        }
        Value::Array(vec![serde_json::json!({
            "role": "user",
            "content": [
                {
                    "type": "input_image",
                    "image_url": format!("data:image/png;base64,{}", image.base64_png),
                    "detail": "high"
                },
                { "type": "input_text", "text": user_text }
            ]
        })])
    } else {
        Value::String(user_text.to_owned())
    };
    let body = serde_json::to_string(&LiveResponsesBody {
        model: PLUS_LIVE_MODEL,
        input,
        store: false,
        instructions: plus_live_tool_instructions(),
        tools: plus_live_tool_declarations(),
    })
    .map_err(|error| {
        PlusHostError::Live(format!("live xAI request could not be encoded: {error}"))
    })?;
    if body.len() > LIVE_MAX_REQUEST_BODY_BYTES {
        return Err(PlusHostError::Live(
            "live xAI request exceeded the fixed 12 MiB body cap".into(),
        ));
    }
    Ok(PlusLiveChatRequest {
        endpoint: PLUS_LIVE_ENDPOINT,
        host: PLUS_LIVE_HOST,
        path: PLUS_LIVE_PATH,
        body,
        authorization: identity.api_key.clone(),
    })
}

/// Builds one exact official xAI TTS request using the same in-memory provider
/// identity as the selected `XaiKeychain` Chat path.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when text is empty, exceeds the provider's
/// 15,000-character limit, or cannot be encoded.
pub fn encode_plus_live_tts_request(
    text: &str,
    identity: &PlusLiveIdentity,
) -> Result<PlusLiveTtsRequest, PlusHostError> {
    let text = text.trim();
    let char_count = text.chars().count();
    if char_count == 0 {
        return Err(PlusHostError::Live(
            "Grok Read Aloud requires non-empty assistant text".into(),
        ));
    }
    if char_count > TTS_MAX_TEXT_CHARS {
        return Err(PlusHostError::Live(
            "Grok Read Aloud text exceeded the official 15,000-character xAI TTS limit".into(),
        ));
    }
    let body = serde_json::to_string(&LiveTtsBody {
        text,
        voice_id: PLUS_TTS_VOICE,
        language: "auto",
        output_format: LiveTtsOutputFormat {
            codec: "mp3",
            sample_rate: 24_000,
            bit_rate: 128_000,
        },
    })
    .map_err(|error| {
        PlusHostError::Live(format!("xAI TTS request could not be encoded: {error}"))
    })?;
    Ok(PlusLiveTtsRequest {
        endpoint: PLUS_TTS_ENDPOINT,
        host: PLUS_LIVE_HOST,
        path: PLUS_TTS_PATH,
        body,
        authorization: identity.api_key.clone(),
    })
}

/// Extracts assistant text from a `/v1/responses` or chat-completions body.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the body is not JSON or has no
/// assistant text.
pub fn decode_plus_live_chat_response(body: &[u8]) -> Result<String, PlusHostError> {
    Ok(decode_plus_live_reply(body)?.assistant_text)
}

/// Extracts assistant text and native function calls from a live body.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the body is not JSON or has neither
/// assistant text nor function calls.
pub fn decode_plus_live_reply(body: &[u8]) -> Result<PlusLiveReply, PlusHostError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| PlusHostError::Live(format!("live xAI response is not JSON: {error}")))?;
    let function_calls = function_calls_from_value(&value);
    let assistant_text = responses_output_text(&value)
        .or_else(|| chat_completion_text(&value))
        .unwrap_or_default();
    if assistant_text.is_empty() && function_calls.is_empty() {
        return Err(PlusHostError::Live(
            "live xAI response had no assistant text or tool calls".into(),
        ));
    }
    Ok(PlusLiveReply {
        assistant_text,
        function_calls,
    })
}

fn function_calls_from_value(value: &Value) -> Vec<PlusLiveFunctionCall> {
    let mut calls = Vec::new();
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        for item in output {
            if item.get("type").and_then(Value::as_str) != Some("function_call") {
                continue;
            }
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let arguments_json = match item.get("arguments") {
                Some(Value::String(text)) => text.clone(),
                Some(other) => other.to_string(),
                None => "{}".into(),
            };
            calls.push(PlusLiveFunctionCall {
                name,
                arguments_json,
            });
        }
    }
    if let Some(tool_calls) = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for item in tool_calls {
            let function = item.get("function");
            let name = function
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let arguments_json = function
                .and_then(|value| value.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or("{}")
                .to_owned();
            calls.push(PlusLiveFunctionCall {
                name,
                arguments_json,
            });
        }
    }
    calls
}

fn responses_output_text(value: &Value) -> Option<String> {
    let output = value.get("output")?.as_array()?;
    for item in output {
        let content = item.get("content").and_then(Value::as_array);
        let Some(content) = content else {
            continue;
        };
        for part in content {
            if part.get("type").and_then(Value::as_str) != Some("output_text") {
                continue;
            }
            if let Some(text) = part.get("text").and_then(Value::as_str)
                && !text.is_empty()
            {
                return Some(text.to_owned());
            }
        }
    }
    None
}

fn chat_completion_text(value: &Value) -> Option<String> {
    let content = value
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()?;
    if content.is_empty() {
        None
    } else {
        Some(content.to_owned())
    }
}

/// Posts one bound live request to `api.x.ai` over rustls + platform verifier.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] for endpoint mismatch, TLS, HTTP, or
/// transport failures. Never falls back to [`super::FakeProvider`].
pub fn post_plus_live_chat(request: &PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError> {
    if request.endpoint != PLUS_LIVE_ENDPOINT
        || request.host != PLUS_LIVE_HOST
        || request.path != PLUS_LIVE_PATH
    {
        return Err(PlusHostError::Live(
            "live xAI request is not bound to https://api.x.ai/v1/responses".into(),
        ));
    }

    let server_name = ServerName::try_from(PLUS_LIVE_HOST)
        .map_err(|_| PlusHostError::Live("live xAI host is not a valid TLS name".into()))?
        .to_owned();
    let config = live_client_config()?;
    let connection = ClientConnection::new(config, server_name).map_err(|error| {
        PlusHostError::LiveTransport(format!("live xAI TLS session failed: {error}"))
    })?;
    let tcp = connect_live_tcp()?;
    let mut tls = StreamOwned::new(connection, tcp);
    write_live_http(&mut tls, request)?;
    let raw = read_live_http(&mut tls)?;
    parse_live_http_body(&raw)
}

/// Generates one bounded transient MP3 through the official xAI TTS endpoint.
/// The request uses the same in-memory API-key identity as `XaiKeychain` Chat and
/// never follows redirects, stores audio, or falls back to another voice.
///
/// # Errors
///
/// Returns [`PlusHostError`] for binding drift, cancellation, TLS/HTTP failure,
/// a non-MP3 response, or an audio body above the fixed 24 MiB cap.
pub fn post_plus_live_tts(
    request: &PlusLiveTtsRequest,
    mut cancelled: impl FnMut() -> bool,
) -> Result<PlusLiveTtsAudio, PlusHostError> {
    if request.endpoint != PLUS_TTS_ENDPOINT
        || request.host != PLUS_LIVE_HOST
        || request.path != PLUS_TTS_PATH
    {
        return Err(PlusHostError::Live(
            "Grok Read Aloud request is not bound to https://api.x.ai/v1/tts".into(),
        ));
    }
    if cancelled() {
        return Err(PlusHostError::LiveCancelled);
    }
    let server_name = ServerName::try_from(PLUS_LIVE_HOST)
        .map_err(|_| PlusHostError::Live("xAI TTS host is not a valid TLS name".into()))?
        .to_owned();
    let connection =
        ClientConnection::new(live_client_config()?, server_name).map_err(|error| {
            PlusHostError::LiveTransport(format!("xAI TTS TLS session failed: {error}"))
        })?;
    let tcp = connect_live_tcp()?;
    tcp.set_read_timeout(Some(LIVE_STREAM_POLL_TIMEOUT))
        .map_err(|error| {
            PlusHostError::LiveTransport(format!("xAI TTS poll timeout failed: {error}"))
        })?;
    let mut tls = StreamOwned::new(connection, tcp);
    write_tts_http(&mut tls, request)?;
    let raw = read_tts_http(&mut tls, &mut cancelled)?;
    parse_tts_http(&raw)
}

/// Posts one Responses request with `stream=true`, emits bounded normalized
/// SSE events, and returns the exact completed Responses object as JSON.
///
/// The caller supplies cancellation state so the trusted desktop can stop a
/// read without waiting for the full provider timeout.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] for endpoint mismatch, cancellation,
/// timeout, malformed HTTP/chunk framing, malformed SSE, provider failure, or
/// a stream that ends without `response.completed`. Never falls back to a
/// stub provider.
pub fn post_plus_live_chat_streaming(
    request: &PlusLiveChatRequest,
    mut cancelled: impl FnMut() -> bool,
    emit: impl FnMut(PlusLiveStreamEvent),
) -> Result<Vec<u8>, PlusHostError> {
    validate_live_request_binding(request)?;
    let mut body_value: Value = serde_json::from_str(&request.body).map_err(|error| {
        PlusHostError::Live(format!("live xAI request body is not JSON: {error}"))
    })?;
    let object = body_value
        .as_object_mut()
        .ok_or_else(|| PlusHostError::Live("live xAI request body is not a JSON object".into()))?;
    object.insert("stream".into(), Value::Bool(true));
    let streaming_body = serde_json::to_vec(&body_value).map_err(|error| {
        PlusHostError::Live(format!(
            "live xAI streaming request could not be encoded: {error}"
        ))
    })?;

    let server_name = ServerName::try_from(PLUS_LIVE_HOST)
        .map_err(|_| PlusHostError::Live("live xAI host is not a valid TLS name".into()))?
        .to_owned();
    let connection =
        ClientConnection::new(live_client_config()?, server_name).map_err(|error| {
            PlusHostError::LiveTransport(format!("live xAI TLS session failed: {error}"))
        })?;
    let tcp = connect_live_tcp()?;
    tcp.set_read_timeout(Some(LIVE_STREAM_POLL_TIMEOUT))
        .map_err(|error| {
            PlusHostError::LiveTransport(format!("live xAI poll timeout failed: {error}"))
        })?;
    let mut tls = StreamOwned::new(connection, tcp);
    write_live_http_parts(&mut tls, request, &streaming_body, "text/event-stream")?;
    let reader = LiveBodyReader::new(tls, &mut cancelled)?;
    if !(200..300).contains(&reader.status_code) {
        return Err(PlusHostError::LiveHttp {
            status: reader.status_code,
        });
    }

    read_live_sse_response(reader, cancelled, emit)
}

fn read_live_sse_response(
    mut reader: LiveBodyReader<impl Read>,
    mut cancelled: impl FnMut() -> bool,
    mut emit: impl FnMut(PlusLiveStreamEvent),
) -> Result<Vec<u8>, PlusHostError> {
    let mut decoder = ResponsesSseDecoder::default();
    while let Some(piece) = reader.next_piece(&mut cancelled)? {
        decoder.push(&piece, &mut emit)?;
        if cancelled() {
            return Err(PlusHostError::LiveCancelled);
        }
        // A completed provider response is the protocol boundary. Close our
        // connection instead of waiting for HTTP EOF or another chunk.
        if decoder.completed.is_some() || decoder.saw_done {
            break;
        }
    }
    decoder.finish(&mut emit)
}

fn validate_live_request_binding(request: &PlusLiveChatRequest) -> Result<(), PlusHostError> {
    if request.endpoint != PLUS_LIVE_ENDPOINT
        || request.host != PLUS_LIVE_HOST
        || request.path != PLUS_LIVE_PATH
    {
        return Err(PlusHostError::Live(
            "live xAI request is not bound to https://api.x.ai/v1/responses".into(),
        ));
    }
    Ok(())
}

fn live_client_config() -> Result<Arc<ClientConfig>, PlusHostError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| PlusHostError::Live(format!("live xAI TLS versions failed: {error}")))?
        .with_platform_verifier()
        .map_err(|error| {
            PlusHostError::Live(format!("live xAI platform verifier unavailable: {error}"))
        })?
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn connect_live_tcp() -> Result<TcpStream, PlusHostError> {
    let address = (PLUS_LIVE_HOST, LIVE_TLS_PORT)
        .to_socket_addrs()
        .map_err(|error| PlusHostError::LiveTransport(format!("live xAI DNS failed: {error}")))?
        .next()
        .ok_or_else(|| PlusHostError::LiveTransport("live xAI DNS returned no addresses".into()))?;
    let stream = TcpStream::connect_timeout(&address, LIVE_CONNECT_TIMEOUT).map_err(|error| {
        PlusHostError::LiveTransport(format!("live xAI connect failed: {error}"))
    })?;
    stream
        .set_read_timeout(Some(LIVE_IO_TIMEOUT))
        .map_err(|error| {
            PlusHostError::LiveTransport(format!("live xAI read timeout failed: {error}"))
        })?;
    stream
        .set_write_timeout(Some(LIVE_IO_TIMEOUT))
        .map_err(|error| {
            PlusHostError::LiveTransport(format!("live xAI write timeout failed: {error}"))
        })?;
    Ok(stream)
}

fn write_live_http(
    stream: &mut impl Write,
    request: &PlusLiveChatRequest,
) -> Result<(), PlusHostError> {
    write_live_http_parts(stream, request, request.body.as_bytes(), "application/json")
}

fn write_live_http_parts(
    stream: &mut impl Write,
    request: &PlusLiveChatRequest,
    body: &[u8],
    accept: &str,
) -> Result<(), PlusHostError> {
    if body.len() > LIVE_MAX_REQUEST_BODY_BYTES {
        return Err(PlusHostError::Live(
            "live xAI request exceeded the fixed 12 MiB body cap".into(),
        ));
    }
    let mut header = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Bearer ",
        request.path, request.host,
    )
    .into_bytes();
    header.extend_from_slice(&request.authorization);
    header.extend_from_slice(
        format!(
            "\r\n\
         Content-Type: application/json\r\n\
         Accept: {accept}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
            body.len(),
        )
        .as_bytes(),
    );
    let header_result = stream.write_all(&header);
    header.fill(0);
    header_result
        .map_err(|error| PlusHostError::LiveTransport(format!("live xAI write failed: {error}")))?;
    stream
        .write_all(body)
        .map_err(|error| PlusHostError::LiveTransport(format!("live xAI write failed: {error}")))?;
    stream
        .flush()
        .map_err(|error| PlusHostError::LiveTransport(format!("live xAI flush failed: {error}")))
}

fn write_tts_http(
    stream: &mut impl Write,
    request: &PlusLiveTtsRequest,
) -> Result<(), PlusHostError> {
    let body = request.body.as_bytes();
    if body.len() > LIVE_MAX_REQUEST_BODY_BYTES {
        return Err(PlusHostError::Live(
            "xAI TTS request exceeded the fixed 12 MiB body cap".into(),
        ));
    }
    let mut header = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: Bearer ",
        request.path, request.host,
    )
    .into_bytes();
    header.extend_from_slice(&request.authorization);
    header.extend_from_slice(
        format!(
            "\r\n\
         Content-Type: application/json\r\n\
         Accept: audio/mpeg\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
            body.len(),
        )
        .as_bytes(),
    );
    let header_result = stream.write_all(&header);
    header.fill(0);
    header_result
        .map_err(|error| PlusHostError::LiveTransport(format!("xAI TTS write failed: {error}")))?;
    stream
        .write_all(body)
        .map_err(|error| PlusHostError::LiveTransport(format!("xAI TTS write failed: {error}")))?;
    stream
        .flush()
        .map_err(|error| PlusHostError::LiveTransport(format!("xAI TTS flush failed: {error}")))
}

fn read_tts_http(
    stream: &mut impl Read,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, PlusHostError> {
    const FRAMING_RESERVE: usize = 1024 * 1024;
    let raw_cap = TTS_MAX_RESPONSE_BYTES
        .saturating_add(LIVE_MAX_HEADER_BYTES)
        .saturating_add(FRAMING_RESERVE);
    let started = Instant::now();
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if cancelled() {
            return Err(PlusHostError::LiveCancelled);
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if raw.len().saturating_add(count) > raw_cap {
                    return Err(PlusHostError::Live(
                        "xAI TTS response exceeded its bounded audio/framing cap".into(),
                    ));
                }
                raw.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if started.elapsed() >= TTS_RESPONSE_DEADLINE {
                    return Err(PlusHostError::LiveTransport(
                        "xAI TTS response timed out".into(),
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => {
                return Err(PlusHostError::LiveTransport(format!(
                    "xAI TTS read failed: {error}"
                )));
            }
        }
    }
    if cancelled() {
        return Err(PlusHostError::LiveCancelled);
    }
    Ok(raw)
}

fn parse_tts_http(raw: &[u8]) -> Result<PlusLiveTtsAudio, PlusHostError> {
    let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(PlusHostError::Live(format!(
            "xAI TTS response was missing HTTP headers (received {} bytes)",
            raw.len()
        )));
    };
    if header_end > LIVE_MAX_HEADER_BYTES {
        return Err(PlusHostError::Live(
            "xAI TTS response headers exceeded the 64 KiB cap".into(),
        ));
    }
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| PlusHostError::Live("xAI TTS response headers were not UTF-8".into()))?;
    let body = &raw[header_end + 4..];
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| PlusHostError::Live("xAI TTS response had no status line".into()))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err(PlusHostError::Live(
            "xAI TTS response used an unsupported HTTP version".into(),
        ));
    }
    let code = status_parts
        .next()
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| PlusHostError::Live("xAI TTS response status was not a number".into()))?;
    if (300..400).contains(&code) {
        return Err(PlusHostError::Live(
            "xAI TTS returned a redirect; redirects are not followed".into(),
        ));
    }
    if !(200..300).contains(&code) {
        return Err(PlusHostError::LiveHttp { status: code });
    }

    let mut content_type = None;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-type" => content_type = Some(value.to_ascii_lowercase()),
            "content-length" => content_length = value.parse::<usize>().ok(),
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }
    let content_type = content_type.ok_or_else(|| {
        PlusHostError::Live("xAI TTS response omitted its audio content type".into())
    })?;
    if content_type.split(';').next().map(str::trim) != Some("audio/mpeg") {
        return Err(PlusHostError::Live(
            "xAI TTS response was not the requested audio/mpeg format".into(),
        ));
    }
    let bytes = if chunked {
        decode_chunked_body_bounded(body, TTS_MAX_RESPONSE_BYTES, "xAI TTS response")?
    } else if let Some(length) = content_length {
        if length == 0 || length > TTS_MAX_RESPONSE_BYTES || body.len() < length {
            return Err(PlusHostError::Live(
                "xAI TTS content length was empty, oversized, or truncated".into(),
            ));
        }
        body[..length].to_vec()
    } else {
        if body.is_empty() || body.len() > TTS_MAX_RESPONSE_BYTES {
            return Err(PlusHostError::Live(
                "xAI TTS response body was empty or exceeded 24 MiB".into(),
            ));
        }
        body.to_vec()
    };
    if bytes.is_empty() {
        return Err(PlusHostError::Live("xAI TTS returned empty audio".into()));
    }
    Ok(PlusLiveTtsAudio {
        content_type: "audio/mpeg".into(),
        bytes,
    })
}

fn read_live_http(stream: &mut impl Read) -> Result<Vec<u8>, PlusHostError> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if raw.len().saturating_add(count) > LIVE_MAX_RESPONSE_BYTES {
                    return Err(PlusHostError::Live(
                        "live xAI response exceeded the 1 MiB cap".into(),
                    ));
                }
                raw.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(PlusHostError::LiveTransport(
                    "live xAI read timed out".into(),
                ));
            }
            Err(error) => {
                return Err(PlusHostError::LiveTransport(format!(
                    "live xAI read failed: {error}"
                )));
            }
        }
    }
    Ok(raw)
}

fn parse_live_http_body(raw: &[u8]) -> Result<Vec<u8>, PlusHostError> {
    let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(PlusHostError::Live(
            "live xAI response was missing HTTP headers".into(),
        ));
    };
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| PlusHostError::Live("live xAI response headers were not UTF-8".into()))?;
    let body = &raw[header_end + 4..];
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| PlusHostError::Live("live xAI response was missing a status line".into()))?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts.next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err(PlusHostError::Live(
            "live xAI response used an unsupported HTTP version".into(),
        ));
    }
    let code = status_parts
        .next()
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| PlusHostError::Live("live xAI response status was not a number".into()))?;
    if (300..400).contains(&code) {
        return Err(PlusHostError::Live(
            "live xAI returned a redirect; redirects are not followed".into(),
        ));
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
        if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        }
    }

    let payload = if chunked {
        decode_chunked_body(body)?
    } else if let Some(length) = content_length {
        body.get(..length.min(body.len())).unwrap_or(body).to_vec()
    } else {
        body.to_vec()
    };

    if !(200..300).contains(&code) {
        return Err(PlusHostError::LiveHttp { status: code });
    }
    Ok(payload)
}

fn decode_chunked_body(remaining: &[u8]) -> Result<Vec<u8>, PlusHostError> {
    decode_chunked_body_bounded(remaining, LIVE_MAX_RESPONSE_BYTES, "live xAI response")
}

fn decode_chunked_body_bounded(
    mut remaining: &[u8],
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, PlusHostError> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = remaining.windows(2).position(|window| window == b"\r\n") else {
            return Err(PlusHostError::Live(
                "live xAI chunked body was truncated".into(),
            ));
        };
        let size_line = std::str::from_utf8(&remaining[..line_end])
            .map_err(|_| PlusHostError::Live("live xAI chunk size was not UTF-8".into()))?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| PlusHostError::Live("live xAI chunk size was not hexadecimal".into()))?;
        remaining = &remaining[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if remaining.len() < size.saturating_add(2) {
            return Err(PlusHostError::Live(
                "live xAI chunked body was truncated".into(),
            ));
        }
        out.extend_from_slice(&remaining[..size]);
        if out.len() > maximum {
            return Err(PlusHostError::Live(format!(
                "{label} exceeded its fixed byte cap"
            )));
        }
        if remaining.get(size..size + 2) != Some(b"\r\n") {
            return Err(PlusHostError::Live(
                "live xAI chunk was missing a trailing CRLF".into(),
            ));
        }
        remaining = &remaining[size + 2..];
    }
}

#[derive(Clone, Copy)]
enum LiveBodyMode {
    Chunked,
    ContentLength(usize),
    UntilEof,
}

struct LiveBodyReader<R> {
    stream: R,
    pending: Vec<u8>,
    offset: usize,
    mode: LiveBodyMode,
    chunk_remaining: usize,
    decoded_total: usize,
    finished: bool,
    started: Instant,
    status_code: u16,
}

impl<R: Read> LiveBodyReader<R> {
    fn new(mut stream: R, cancelled: &mut impl FnMut() -> bool) -> Result<Self, PlusHostError> {
        let started = Instant::now();
        let mut raw = Vec::new();
        let header_end = loop {
            if let Some(index) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                if index > LIVE_MAX_HEADER_BYTES {
                    return Err(PlusHostError::Live(
                        "live xAI response headers exceeded the 64 KiB cap".into(),
                    ));
                }
                break index;
            }
            if raw.len() >= LIVE_MAX_HEADER_BYTES {
                return Err(PlusHostError::Live(
                    "live xAI response headers exceeded the 64 KiB cap".into(),
                ));
            }
            let mut buffer = [0_u8; 8192];
            let count = read_cancellable(&mut stream, &mut buffer, cancelled, started)?;
            if count == 0 {
                return Err(PlusHostError::Live(
                    "live xAI response ended before its HTTP headers".into(),
                ));
            }
            raw.extend_from_slice(&buffer[..count]);
        };
        let header_text = std::str::from_utf8(&raw[..header_end])
            .map_err(|_| PlusHostError::Live("live xAI response headers were not UTF-8".into()))?;
        let (status_code, mode) = parse_streaming_headers(header_text)?;
        let pending = raw[header_end + 4..].to_vec();
        Ok(Self {
            stream,
            pending,
            offset: 0,
            mode,
            chunk_remaining: 0,
            decoded_total: 0,
            finished: false,
            started,
            status_code,
        })
    }

    fn next_piece(
        &mut self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Option<Vec<u8>>, PlusHostError> {
        if self.finished {
            return Ok(None);
        }
        match self.mode {
            LiveBodyMode::Chunked => self.next_chunked_piece(cancelled),
            LiveBodyMode::ContentLength(remaining) => {
                if remaining == 0 {
                    self.finished = true;
                    return Ok(None);
                }
                self.ensure_pending(1, cancelled)?;
                if self.available().is_empty() {
                    return Err(PlusHostError::Live(
                        "live xAI response body was truncated".into(),
                    ));
                }
                let count = remaining.min(self.available().len()).min(8192);
                let piece = self.take_pending(count);
                self.mode = LiveBodyMode::ContentLength(remaining - count);
                self.record_decoded(piece.len())?;
                Ok(Some(piece))
            }
            LiveBodyMode::UntilEof => {
                if self.available().is_empty() {
                    self.read_more(cancelled)?;
                }
                if self.available().is_empty() {
                    self.finished = true;
                    return Ok(None);
                }
                let count = self.available().len().min(8192);
                let piece = self.take_pending(count);
                self.record_decoded(piece.len())?;
                Ok(Some(piece))
            }
        }
    }

    fn next_chunked_piece(
        &mut self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Option<Vec<u8>>, PlusHostError> {
        if self.chunk_remaining == 0 {
            let line = self.read_crlf_line(cancelled)?;
            let text = std::str::from_utf8(&line)
                .map_err(|_| PlusHostError::Live("live xAI chunk size was not UTF-8".into()))?;
            let size_hex = text.split(';').next().unwrap_or(text).trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| {
                PlusHostError::Live("live xAI chunk size was not hexadecimal".into())
            })?;
            if size == 0 {
                self.finished = true;
                return Ok(None);
            }
            if self.decoded_total.saturating_add(size) > LIVE_MAX_RESPONSE_BYTES {
                return Err(PlusHostError::Live(
                    "live xAI response exceeded the 1 MiB cap".into(),
                ));
            }
            self.chunk_remaining = size;
        }

        self.ensure_pending(1, cancelled)?;
        if self.available().is_empty() {
            return Err(PlusHostError::Live(
                "live xAI chunked response was truncated".into(),
            ));
        }
        let count = self.chunk_remaining.min(self.available().len()).min(8192);
        let piece = self.take_pending(count);
        self.chunk_remaining -= count;
        self.record_decoded(piece.len())?;
        if self.chunk_remaining == 0 {
            self.ensure_pending(2, cancelled)?;
            if self.available().get(..2) != Some(b"\r\n") {
                return Err(PlusHostError::Live(
                    "live xAI chunk was missing a trailing CRLF".into(),
                ));
            }
            self.offset += 2;
            self.compact_pending();
        }
        Ok(Some(piece))
    }

    fn read_crlf_line(
        &mut self,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<Vec<u8>, PlusHostError> {
        loop {
            if let Some(index) = self
                .available()
                .windows(2)
                .position(|window| window == b"\r\n")
            {
                let line = self.take_pending(index);
                self.offset += 2;
                self.compact_pending();
                return Ok(line);
            }
            if self.available().len() > 128 {
                return Err(PlusHostError::Live(
                    "live xAI chunk-size line exceeded 128 bytes".into(),
                ));
            }
            if self.read_more(cancelled)? == 0 {
                return Err(PlusHostError::Live(
                    "live xAI chunk-size line was truncated".into(),
                ));
            }
        }
    }

    fn ensure_pending(
        &mut self,
        minimum: usize,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<(), PlusHostError> {
        while self.available().len() < minimum {
            if self.read_more(cancelled)? == 0 {
                break;
            }
        }
        Ok(())
    }

    fn read_more(&mut self, cancelled: &mut impl FnMut() -> bool) -> Result<usize, PlusHostError> {
        self.compact_pending();
        let mut buffer = [0_u8; 8192];
        let count = read_cancellable(&mut self.stream, &mut buffer, cancelled, self.started)?;
        self.pending.extend_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn available(&self) -> &[u8] {
        &self.pending[self.offset..]
    }

    fn take_pending(&mut self, count: usize) -> Vec<u8> {
        let end = self.offset + count;
        let out = self.pending[self.offset..end].to_vec();
        self.offset = end;
        self.compact_pending();
        out
    }

    fn compact_pending(&mut self) {
        if self.offset == self.pending.len() {
            self.pending.clear();
            self.offset = 0;
        } else if self.offset >= 8192 {
            self.pending.drain(..self.offset);
            self.offset = 0;
        }
    }

    fn record_decoded(&mut self, count: usize) -> Result<(), PlusHostError> {
        self.decoded_total = self.decoded_total.saturating_add(count);
        if self.decoded_total > LIVE_MAX_RESPONSE_BYTES {
            return Err(PlusHostError::Live(
                "live xAI response exceeded the 1 MiB cap".into(),
            ));
        }
        Ok(())
    }
}

fn read_cancellable(
    reader: &mut impl Read,
    buffer: &mut [u8],
    cancelled: &mut impl FnMut() -> bool,
    started: Instant,
) -> Result<usize, PlusHostError> {
    loop {
        if cancelled() {
            return Err(PlusHostError::LiveCancelled);
        }
        if started.elapsed() >= LIVE_STREAM_DEADLINE {
            return Err(PlusHostError::LiveTransport(
                "live xAI streaming request timed out".into(),
            ));
        }
        match reader.read(buffer) {
            Ok(count) => return Ok(count),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                return Err(PlusHostError::LiveTransport(format!(
                    "live xAI streaming read failed: {error}"
                )));
            }
        }
    }
}

fn parse_streaming_headers(header_text: &str) -> Result<(u16, LiveBodyMode), PlusHostError> {
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| PlusHostError::Live("live xAI response had no status line".into()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err(PlusHostError::Live(
            "live xAI response used an unsupported HTTP version".into(),
        ));
    }
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| PlusHostError::Live("live xAI response status was invalid".into()))?;
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }
    let mode = if chunked {
        LiveBodyMode::Chunked
    } else if let Some(length) = content_length {
        LiveBodyMode::ContentLength(length)
    } else {
        LiveBodyMode::UntilEof
    };
    Ok((status, mode))
}

#[derive(Default)]
struct ResponsesSseDecoder {
    line_buffer: Vec<u8>,
    data_lines: Vec<String>,
    completed: Option<Value>,
    saw_done: bool,
    total_bytes: usize,
}

impl ResponsesSseDecoder {
    fn push(
        &mut self,
        bytes: &[u8],
        emit: &mut impl FnMut(PlusLiveStreamEvent),
    ) -> Result<(), PlusHostError> {
        self.total_bytes = self.total_bytes.saturating_add(bytes.len());
        if self.total_bytes > LIVE_MAX_RESPONSE_BYTES {
            return Err(PlusHostError::Live(
                "live xAI SSE stream exceeded the 1 MiB cap".into(),
            ));
        }
        self.line_buffer.extend_from_slice(bytes);
        while let Some(index) = self.line_buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.line_buffer.drain(..=index).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.process_line(&line, emit)?;
        }
        Ok(())
    }

    fn finish(
        mut self,
        emit: &mut impl FnMut(PlusLiveStreamEvent),
    ) -> Result<Vec<u8>, PlusHostError> {
        if !self.line_buffer.is_empty() {
            let mut line = std::mem::take(&mut self.line_buffer);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.process_line(&line, emit)?;
        }
        if !self.data_lines.is_empty() {
            self.process_event(emit)?;
        }
        let completed = self.completed.ok_or_else(|| {
            let suffix = if self.saw_done { " before [DONE]" } else { "" };
            PlusHostError::Live(format!(
                "live xAI stream ended{suffix} without response.completed"
            ))
        })?;
        serde_json::to_vec(&completed).map_err(|error| {
            PlusHostError::Live(format!(
                "completed xAI response could not be encoded: {error}"
            ))
        })
    }

    fn process_line(
        &mut self,
        line: &[u8],
        emit: &mut impl FnMut(PlusLiveStreamEvent),
    ) -> Result<(), PlusHostError> {
        if line.is_empty() {
            if !self.data_lines.is_empty() {
                self.process_event(emit)?;
            }
            return Ok(());
        }
        if line.starts_with(b":") || line.starts_with(b"event:") {
            return Ok(());
        }
        if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            let text = std::str::from_utf8(data)
                .map_err(|_| PlusHostError::Live("live xAI SSE data was not UTF-8".into()))?;
            self.data_lines.push(text.to_owned());
        }
        Ok(())
    }

    fn process_event(
        &mut self,
        emit: &mut impl FnMut(PlusLiveStreamEvent),
    ) -> Result<(), PlusHostError> {
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        if data == "[DONE]" {
            self.saw_done = true;
            return Ok(());
        }
        let value: Value = serde_json::from_str(&data)
            .map_err(|error| PlusHostError::Live(format!("live xAI SSE is not JSON: {error}")))?;
        let kind = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match kind {
            "response.output_text.delta" => {
                if let Some(delta) = value.get("delta").and_then(Value::as_str)
                    && !delta.is_empty()
                {
                    emit(PlusLiveStreamEvent::AssistantDelta(delta.to_owned()));
                }
            }
            "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => {
                if let Some(delta) = value.get("delta").and_then(Value::as_str)
                    && !delta.is_empty()
                {
                    emit(PlusLiveStreamEvent::ThoughtDelta(delta.to_owned()));
                }
            }
            "response.completed" => {
                let response = value.get("response").cloned().ok_or_else(|| {
                    PlusHostError::Live("response.completed carried no response".into())
                })?;
                if let Some(usage) = response.get("usage").and_then(plus_live_usage_from_value) {
                    emit(PlusLiveStreamEvent::Usage(usage));
                }
                self.completed = Some(response);
            }
            "response.failed" | "response.incomplete" | "error" => {
                // Provider error text can reflect transient request/tool data.
                // Activity and Chat retain a classification, never that payload.
                return Err(PlusHostError::Live(
                    "live xAI stream reported a provider failure".into(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn plus_live_usage_from_value(value: &Value) -> Option<PlusLiveUsage> {
    let usage = PlusLiveUsage {
        input_tokens: value.get("input_tokens").and_then(Value::as_u64),
        output_tokens: value.get("output_tokens").and_then(Value::as_u64),
        reasoning_tokens: value
            .pointer("/output_tokens_details/reasoning_tokens")
            .and_then(Value::as_u64),
        cached_tokens: value
            .pointer("/input_tokens_details/cached_tokens")
            .and_then(Value::as_u64),
    };
    if usage == PlusLiveUsage::default() {
        None
    } else {
        Some(usage)
    }
}

#[cfg(test)]
#[path = "tests/plus_live_streaming.rs"]
mod streaming_tests;

#[cfg(test)]
#[path = "tests/plus_live_tts.rs"]
mod tts_tests;

#[cfg(feature = "responses-websocket")]
mod websocket;
#[cfg(feature = "responses-websocket")]
pub use websocket::PlusLiveWebSocket;
