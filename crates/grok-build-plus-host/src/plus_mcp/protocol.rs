//! Requests are classified before IDs, with independent peer/client ID spaces.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{
    MCP_MAX_CONNECTION_BYTES, MCP_MAX_FRAME_BYTES, MCP_PROTOCOL_VERSION, McpProtocolVersion,
};

const MAX_EXCHANGES: u64 = 256;
const MAX_PEER_REQUESTS: usize = 64;
const MAX_PENDING: usize = 8;
const MAX_MESSAGES: usize = 4096;
const MAX_ELICITATION_BYTES: usize = 64 * 1024;

/// App-issued correlation identity, scoped to this connection only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpRequestIdentity(String);

impl McpRequestIdentity {
    /// Opaque wire correlation text; never an app project/session identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed set of broker-originated operations; no arbitrary RPC method dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpOperation {
    /// Establish this client's deliberately restricted capabilities.
    Initialize,
    /// Read one tool-catalog page. The broker bounds and validates all pages.
    ListTools,
    /// Invoke a tool only after independent app authority and durable intent.
    CallTool,
    /// Inspect whether the existing connection responds.
    Ping,
}

/// Observations and outgoing messages for the independent app event loop.
pub enum McpEvent {
    /// Send this encoded message on the same owning connection.
    Send(Vec<u8>),
    /// The initialization response was validated; send preceding messages first.
    Initialized,
    /// A matched, validated response. Tool output remains untrusted data.
    Result {
        /// Original app-issued request correlation.
        identity: McpRequestIdentity,
        /// Original operation; server content cannot change it.
        operation: McpOperation,
        /// Bounded result object; no automatic URI/resource fetching occurs.
        value: Value,
    },
    /// A matched remote JSON-RPC error; server data is omitted from diagnostics.
    RemoteError {
        /// Original app-issued request correlation.
        identity: McpRequestIdentity,
        /// Original operation.
        operation: McpOperation,
        /// Integer JSON-RPC error code, without a server-controlled message.
        code: i64,
    },
    /// App UI must decide this request independently of the model's RPC loop.
    Elicitation {
        /// Peer correlation, scoped to this connection's inbound ID space.
        identity: Value,
        /// Bounded form/URL request; displaying it never opens a URL automatically.
        params: Value,
    },
    /// Withdraw the matching UI request. This is not a model-tool cancellation.
    ElicitationCancelled(Value),
    /// Invalidate the tool catalog and its grants before admitting another call.
    ToolsChanged,
    /// Bounded observational message. Its arbitrary payload is not retained.
    Observation,
}

impl std::fmt::Debug for McpEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(bytes) => formatter.debug_tuple("Send").field(&bytes.len()).finish(),
            Self::Initialized => formatter.write_str("Initialized"),
            Self::Result {
                identity,
                operation,
                ..
            } => formatter
                .debug_struct("Result")
                .field("identity", identity)
                .field("operation", operation)
                .finish_non_exhaustive(),
            Self::RemoteError {
                identity,
                operation,
                code,
            } => formatter
                .debug_struct("RemoteError")
                .field("identity", identity)
                .field("operation", operation)
                .field("code", code)
                .finish(),
            Self::Elicitation { .. } => {
                formatter.write_str("Elicitation(<private app UI request>)")
            }
            Self::ElicitationCancelled(_) => formatter.write_str("ElicitationCancelled"),
            Self::ToolsChanged => formatter.write_str("ToolsChanged"),
            Self::Observation => formatter.write_str("Observation"),
        }
    }
}

struct PeerRequest {
    fingerprint: String,
    answer: Option<Value>,
    cancelled: bool,
}

/// Bounded state for one connection. Losing the carrier requires a new instance.
pub struct McpProtocol {
    pending: BTreeMap<String, McpOperation>,
    peer: BTreeMap<String, PeerRequest>,
    next: u64,
    messages: usize,
    bytes: usize,
    version: Option<McpProtocolVersion>,
    closed: bool,
}

impl Default for McpProtocol {
    fn default() -> Self {
        Self {
            pending: BTreeMap::new(),
            peer: BTreeMap::new(),
            next: 1,
            messages: 0,
            bytes: 0,
            version: None,
            closed: false,
        }
    }
}

impl McpProtocol {
    /// Revision proven by this connection's validated initialization response.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<McpProtocolVersion> {
        self.version
    }
    /// Reserve an identity before any write. The caller must not replay an
    /// uncertain write, including on a replacement connection.
    ///
    /// # Errors
    /// Refuses invalid lifecycle/parameters, closed connections, or any budget.
    pub fn begin(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<(McpRequestIdentity, Vec<u8>), String> {
        if self.closed || self.pending.len() >= MAX_PENDING || self.next > MAX_EXCHANGES {
            return Err("MCP connection is closed or its request budget is occupied.".into());
        }
        let (method, params) = self.request_parameters(&operation, params)?;
        let identity = McpRequestIdentity(format!("gbplus-{}", self.next));
        let bytes = self.encode(&json!({
            "jsonrpc":"2.0", "id":identity.as_str(), "method":method, "params":params
        }))?;
        self.next += 1;
        self.pending.insert(identity.0.clone(), operation);
        Ok((identity, bytes))
    }

    fn request_parameters(
        &self,
        operation: &McpOperation,
        params: Value,
    ) -> Result<(&'static str, Value), String> {
        if *operation == McpOperation::Initialize {
            if self.next != 1 || !self.pending.is_empty() || self.version.is_some() {
                return Err("MCP initialization cannot be repeated on a connection.".into());
            }
            if params != json!({}) {
                return Err("The app supplies MCP initialization capabilities.".into());
            }
            return Ok((
                "initialize",
                json!({
                    "protocolVersion":MCP_PROTOCOL_VERSION,
                    "capabilities":{"elicitation":{"form":{},"url":{}}},
                    "clientInfo":{"name":"GB Plus","version":env!("CARGO_PKG_VERSION")}
                }),
            ));
        }
        if self.version.is_none() || !params.is_object() {
            return Err("MCP operation requires initialization and object parameters.".into());
        }
        match operation {
            McpOperation::Initialize => unreachable!(),
            McpOperation::ListTools => {
                if params.as_object().is_none_or(|object| object.len() > 1)
                    || params.get("cursor").is_some_and(|cursor| {
                        cursor
                            .as_str()
                            .is_none_or(|text| !super::bounded_text(text, 4096))
                    })
                    || params
                        .as_object()
                        .is_some_and(|object| object.keys().any(|key| key != "cursor"))
                {
                    return Err("MCP catalog cursor is invalid or oversized.".into());
                }
                Ok(("tools/list", params))
            }
            McpOperation::CallTool => {
                if params.as_object().is_none_or(|object| object.len() != 2)
                    || params
                        .get("name")
                        .and_then(Value::as_str)
                        .is_none_or(|name| !super::catalog::tool_name(name))
                    || !params.get("arguments").is_some_and(Value::is_object)
                {
                    return Err(
                        "MCP tool call must contain only its name and object arguments.".into(),
                    );
                }
                Ok(("tools/call", params))
            }
            McpOperation::Ping if params == json!({}) => Ok(("ping", params)),
            McpOperation::Ping => Err("MCP ping has no caller parameters.".into()),
        }
    }

    /// Decode one complete message. Requests are identified by `method` before
    /// consulting either independent request-ID namespace.
    ///
    /// # Errors
    /// Invalid, unmatched or excessive messages poison this connection. Pending
    /// requests remain available to the caller as uncertain delivery identities.
    pub fn receive(&mut self, bytes: &[u8]) -> Result<Vec<McpEvent>, String> {
        let result = self.receive_inner(bytes);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn receive_inner(&mut self, bytes: &[u8]) -> Result<Vec<McpEvent>, String> {
        self.account(bytes.len())?;
        let message: Value =
            serde_json::from_slice(bytes).map_err(|_| "MCP message is not bounded valid JSON.")?;
        if !message.is_object() || message["jsonrpc"] != "2.0" {
            return Err("MCP requires a single JSON-RPC 2.0 object.".into());
        }
        if message.get("method").is_some() {
            if message.get("result").is_some() || message.get("error").is_some() {
                return Err("MCP message combines a request with a response.".into());
            }
            return self.peer_message(&message);
        }
        self.response(&message)
    }

    fn response(&mut self, message: &Value) -> Result<Vec<McpEvent>, String> {
        let id = message
            .get("id")
            .and_then(Value::as_str)
            .ok_or("MCP response has no app-issued string identity.")?;
        let operation = self
            .pending
            .get(id)
            .cloned()
            .ok_or("MCP response does not match an outstanding app request.")?;
        let identity = McpRequestIdentity(id.to_owned());
        let event = match (message.get("result"), message.get("error")) {
            (Some(result), None) if result.is_object() => {
                if operation == McpOperation::Initialize {
                    let version = validate_initialization(result)?;
                    let initialized = self
                        .encode(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
                    self.pending.remove(id);
                    self.version = Some(version);
                    return Ok(vec![McpEvent::Send(initialized), McpEvent::Initialized]);
                }
                if operation == McpOperation::CallTool {
                    validate_tool_result(result)?;
                }
                McpEvent::Result {
                    identity,
                    operation,
                    value: result.clone(),
                }
            }
            (None, Some(error)) => {
                let code = error
                    .get("code")
                    .and_then(Value::as_i64)
                    .ok_or("MCP error has no integer code.")?;
                if error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.len() > 4096)
                {
                    return Err("MCP error message is missing or oversized.".into());
                }
                if operation == McpOperation::Initialize {
                    self.closed = true;
                }
                McpEvent::RemoteError {
                    identity,
                    operation,
                    code,
                }
            }
            _ => return Err("MCP response must contain exactly one result or error.".into()),
        };
        self.pending.remove(id);
        Ok(vec![event])
    }

    fn peer_message(&mut self, message: &Value) -> Result<Vec<McpEvent>, String> {
        let method = message["method"]
            .as_str()
            .filter(|method| {
                !method.is_empty() && method.len() <= 128 && !method.chars().any(char::is_control)
            })
            .ok_or("MCP method is missing or invalid.")?;
        if message.get("id").is_none() {
            return self.notification(method, message.get("params"));
        }
        let id = &message["id"];
        let key = peer_key(id)?;
        let fingerprint = super::digest(message)?;
        if let Some(previous) = self.peer.get(&key) {
            if previous.fingerprint != fingerprint {
                return Err("MCP peer reused a request identity with different content.".into());
            }
            return if let Some(answer) = previous.answer.clone() {
                Ok(vec![McpEvent::Send(self.encode(&answer)?)])
            } else {
                Ok(vec![McpEvent::Observation])
            };
        }
        if self.peer.len() >= MAX_PEER_REQUESTS {
            return Err("MCP peer request budget exceeded.".into());
        }
        let answer = match method {
            "ping" => Some(json!({"jsonrpc":"2.0","id":id,"result":{}})),
            "elicitation/create" if self.version.is_some() => None,
            _ => Some(
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"This client does not provide the requested capability."}}),
            ),
        };
        if answer.is_none() {
            validate_elicitation(&message["params"], self.version)?;
            if self
                .peer
                .values()
                .filter(|request| request.answer.is_none() && !request.cancelled)
                .count()
                >= MAX_PENDING
            {
                return Err("MCP pending elicitation limit exceeded.".into());
            }
        }
        self.peer.insert(
            key,
            PeerRequest {
                fingerprint,
                answer: answer.clone(),
                cancelled: false,
            },
        );
        match answer {
            Some(answer) => Ok(vec![McpEvent::Send(self.encode(&answer)?)]),
            None => Ok(vec![McpEvent::Elicitation {
                identity: id.clone(),
                params: message["params"].clone(),
            }]),
        }
    }

    fn notification(
        &mut self,
        method: &str,
        params: Option<&Value>,
    ) -> Result<Vec<McpEvent>, String> {
        if method == "notifications/cancelled" {
            let id = params
                .and_then(|value| value.get("requestId"))
                .ok_or("MCP cancellation has no peer request identity.")?;
            let key = peer_key(id)?;
            if let Some(request) = self.peer.get_mut(&key)
                && request.answer.is_none()
                && !request.cancelled
            {
                request.cancelled = true;
                return Ok(vec![McpEvent::ElicitationCancelled(id.clone())]);
            }
        }
        if method == "notifications/tools/list_changed" {
            if self.version.is_none() {
                return Err("MCP catalog changed before initialization.".into());
            }
            return Ok(vec![McpEvent::ToolsChanged]);
        }
        // Includes logging, progress, and unknown extensions. No notification
        // can invoke a tool, open a URL, supply roots, or request model sampling.
        Ok(vec![McpEvent::Observation])
    }

    pub(super) fn elicitation_pending(&self, id: &Value) -> Result<bool, String> {
        Ok(!self.closed
            && self
                .peer
                .get(&peer_key(id)?)
                .is_some_and(|request| !request.cancelled && request.answer.is_none()))
    }

    /// Reply only to an outstanding UI elicitation on this same connection.
    /// The app must validate an accepted form against its displayed schema and
    /// keep sensitive form/URL interactions outside provider conversation storage.
    ///
    /// # Errors
    /// Refuses stale/cancelled IDs, malformed actions or excessive content.
    pub fn answer_elicitation(&mut self, id: &Value, result: &Value) -> Result<Vec<u8>, String> {
        if self.closed {
            return Err("MCP connection is closed.".into());
        }
        let key = peer_key(id)?;
        let request = self
            .peer
            .get(&key)
            .ok_or("MCP elicitation is no longer pending.")?;
        if request.cancelled || request.answer.is_some() {
            return Err("MCP elicitation is cancelled or already answered.".into());
        }
        let action = result["action"]
            .as_str()
            .ok_or("MCP elicitation has no action.")?;
        if !matches!(action, "accept" | "decline" | "cancel")
            || result
                .as_object()
                .is_none_or(|object| object.keys().any(|key| key != "action" && key != "content"))
            || result
                .get("content")
                .is_some_and(|content| action != "accept" || !content.is_object())
            || serde_json::to_vec(&result)
                .map_err(|_| "Cannot encode MCP elicitation answer.")?
                .len()
                > MAX_ELICITATION_BYTES
        {
            return Err("MCP elicitation answer is invalid or oversized.".into());
        }
        let answer = json!({"jsonrpc":"2.0","id":id,"result":result});
        let bytes = self.encode(&answer)?;
        self.peer
            .get_mut(&key)
            .ok_or("MCP elicitation disappeared.")?
            .answer = Some(answer);
        Ok(bytes)
    }

    /// Encode cancellation for an outstanding app request. Sending it proves
    /// neither that the server stopped nor that any tool effect was undone.
    ///
    /// # Errors
    /// Refuses stale identities, initialization cancellation, or exhausted bounds.
    pub fn cancel(&mut self, identity: &McpRequestIdentity) -> Result<Vec<u8>, String> {
        match self.pending.get(identity.as_str()) {
            Some(McpOperation::Initialize) | None => {
                return Err("MCP request cannot be cancelled in this state.".into());
            }
            Some(_) => {}
        }
        self.encode(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":identity.as_str()}}))
    }

    /// Close locally and return pending delivery identities for the app journal.
    /// It never retries, releases a model lease, or claims remote cleanup.
    #[must_use]
    pub fn interrupt(&mut self) -> Vec<McpRequestIdentity> {
        self.closed = true;
        self.pending
            .keys()
            .cloned()
            .map(McpRequestIdentity)
            .collect()
    }

    fn encode(&mut self, value: &Value) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(value).map_err(|_| "Cannot encode MCP message.")?;
        bytes.push(b'\n');
        self.account(bytes.len())?;
        Ok(bytes)
    }

    fn account(&mut self, size: usize) -> Result<(), String> {
        if self.closed
            || size == 0
            || size > MCP_MAX_FRAME_BYTES
            || self.messages >= MAX_MESSAGES
            || self.bytes.saturating_add(size) > MCP_MAX_CONNECTION_BYTES
        {
            self.closed = true;
            return Err("MCP connection, message or aggregate budget exceeded.".into());
        }
        self.messages += 1;
        self.bytes += size;
        Ok(())
    }
}

fn peer_key(id: &Value) -> Result<String, String> {
    if id.as_i64().is_some()
        || id.as_str().is_some_and(|text| {
            !text.is_empty() && text.len() <= 128 && !text.chars().any(char::is_control)
        })
    {
        Ok(id.to_string())
    } else {
        Err("MCP peer request identity is invalid or oversized.".into())
    }
}

fn validate_initialization(value: &Value) -> Result<McpProtocolVersion, String> {
    let version = McpProtocolVersion::parse(value["protocolVersion"].as_str().unwrap_or(""))?;
    if !value
        .pointer("/capabilities/tools")
        .is_some_and(Value::is_object)
        || value
            .pointer("/serverInfo/name")
            .and_then(Value::as_str)
            .is_none_or(|s| !super::bounded_text(s, 256))
        || value
            .pointer("/serverInfo/version")
            .and_then(Value::as_str)
            .is_none_or(|s| !super::bounded_text(s, 128))
    {
        return Err(
            "MCP server did not negotiate the admitted protocol and tool capability.".into(),
        );
    }
    Ok(version)
}

fn validate_elicitation(params: &Value, version: Option<McpProtocolVersion>) -> Result<(), String> {
    if serde_json::to_vec(params)
        .map_err(|_| "Cannot inspect MCP elicitation.")?
        .len()
        > MAX_ELICITATION_BYTES
        || params
            .get("message")
            .and_then(Value::as_str)
            .is_none_or(|s| !super::bounded_text(s, 4096))
    {
        return Err("MCP elicitation is missing its message or exceeds its bound.".into());
    }
    let mode = match params.get("mode") {
        None => "form",
        Some(Value::String(mode)) => mode,
        Some(_) => return Err("MCP elicitation mode must be text.".into()),
    };
    match mode {
        "form" if params.get("requestedSchema").is_some_and(Value::is_object) => Ok(()),
        "url"
            if version == Some(McpProtocolVersion::November2025)
                && params
                    .get("url")
                    .and_then(Value::as_str)
                    .is_some_and(|s| super::bounded_text(s, 4096))
                && params
                    .get("elicitationId")
                    .and_then(Value::as_str)
                    .is_some_and(|s| super::bounded_text(s, 256)) =>
        {
            Ok(())
        }
        _ => Err("Unsupported or malformed MCP elicitation mode.".into()),
    }
}

fn validate_tool_result(result: &Value) -> Result<(), String> {
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 256)
        .ok_or("MCP tool response has no bounded content array.")?;
    if result
        .get("isError")
        .is_some_and(|value| !value.is_boolean())
        || result
            .get("structuredContent")
            .is_some_and(|value| !value.is_object())
        || result.get("task").is_some()
    {
        return Err("MCP tool returned an unsupported or malformed result contract.".into());
    }
    for item in content {
        let valid = match item.get("type").and_then(Value::as_str) {
            Some("text") => item.get("text").is_some_and(Value::is_string),
            Some("image" | "audio") => {
                item.get("data").is_some_and(Value::is_string)
                    && item
                        .get("mimeType")
                        .and_then(Value::as_str)
                        .is_some_and(|mime| super::bounded_text(mime, 128))
            }
            Some("resource_link") => {
                item.get("uri")
                    .and_then(Value::as_str)
                    .is_some_and(|uri| super::bounded_text(uri, 4096))
                    && item
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| super::bounded_text(name, 256))
            }
            Some("resource") => item.get("resource").is_some_and(|resource| {
                resource
                    .get("uri")
                    .and_then(Value::as_str)
                    .is_some_and(|uri| super::bounded_text(uri, 4096))
                    && (resource.get("text").is_some_and(Value::is_string)
                        != resource.get("blob").is_some_and(Value::is_string))
            }),
            _ => false,
        };
        if !valid {
            return Err(
                "MCP tool returned unknown or malformed content; no resource was fetched.".into(),
            );
        }
    }
    Ok(())
}
