//! Independent asynchronous MCP control and request paths for the app broker.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::{
    McpEvent, McpHttpEvent, McpHttpOutcome, McpHttpsClient, McpOperation, McpProtocol,
    McpProtocolVersion, McpRequestIdentity,
};

type Reply = Result<Value, String>;

struct Dispatch {
    protocol: McpProtocol,
    client: Arc<McpHttpsClient>,
    pending: BTreeMap<String, oneshot::Sender<Reply>>,
    initializing: Option<McpRequestIdentity>,
    controls: mpsc::Sender<Control>,
    observations: mpsc::Sender<McpEvent>,
    failed: bool,
    ready: bool,
}

enum Control {
    Send(Vec<u8>),
    Barrier(oneshot::Sender<()>),
}

impl Dispatch {
    fn receive(&mut self, event: McpHttpEvent) -> Result<(), String> {
        // This connection does not persist a replay cursor or reconnect. A
        // future resumable owner must commit accepted messages before cursors.
        let McpHttpEvent::Message(bytes) = event else {
            return Ok(());
        };
        let parsed = self.protocol.receive(&bytes)?;
        if parsed.iter().any(|e| matches!(e, McpEvent::Initialized)) {
            self.client.finish_initialization(
                self.protocol
                    .negotiated_version()
                    .ok_or("MCP negotiated revision is absent.")?,
            )?;
        }
        for event in parsed {
            match event {
                McpEvent::Send(bytes) => self.control(Control::Send(bytes))?,
                McpEvent::Initialized => {
                    let id = self
                        .initializing
                        .take()
                        .ok_or("Unexpected MCP initialization result.")?;
                    self.complete(&id, Ok(json!({})))?;
                }
                McpEvent::Result {
                    identity, value, ..
                } => self.complete(&identity, Ok(value))?,
                McpEvent::RemoteError { identity, code, .. } => {
                    self.complete(
                        &identity,
                        Err(format!("MCP request was rejected with RPC code {code}.")),
                    )?;
                }
                McpEvent::ToolsChanged => {
                    // No queued/previously reviewed tool may start while the
                    // owner is still processing an invalidation notification.
                    let _ = self.observations.try_send(McpEvent::ToolsChanged);
                    self.fail();
                    return Err(
                        "MCP catalog changed; reconnect and review its current tools.".into(),
                    );
                }
                McpEvent::Observation => {}
                observation => self
                    .observations
                    .try_send(observation)
                    .map_err(|_| "MCP observation capacity is occupied or its owner stopped.")?,
            }
        }
        Ok(())
    }

    fn complete(&mut self, identity: &McpRequestIdentity, result: Reply) -> Result<(), String> {
        let recipient = self
            .pending
            .remove(identity.as_str())
            .ok_or("MCP reply has no waiting app operation.")?;
        recipient
            .send(result)
            .map_err(|_| "MCP operation owner stopped before its reply.".into())
    }

    fn control(&self, message: Control) -> Result<(), String> {
        self.controls
            .try_send(message)
            .map_err(|_| "MCP control capacity is occupied or closed.".into())
    }

    fn answer_elicitation(&mut self, id: &Value, result: &Value) -> Result<bool, String> {
        if self.failed || !self.protocol.elicitation_pending(id)? {
            return Ok(false);
        }
        let bytes = self.protocol.answer_elicitation(id, result)?;
        if let Err(error) = self.control(Control::Send(bytes)) {
            self.fail();
            return Err(error);
        }
        Ok(true)
    }

    fn fail(&mut self) {
        self.failed = true;
        self.client.close();
        // Keep protocol identities unresolved for interruption reporting. Do not
        // convert a disconnected operation into a definitively unsent request.
        for (_, recipient) in std::mem::take(&mut self.pending) {
            let _ = recipient.send(Err(
                "MCP connection interrupted; delivery may be uncertain.".into(),
            ));
        }
    }
}

/// One app-owned HTTPS connection with an independent bounded control writer.
/// It supplies transport/protocol machinery, not permission, account discovery,
/// durable replay, or model scheduling. The broker owns the returned observation
/// receiver and must resolve elicitation independently from a waiting model.
pub struct McpHttpsConnection {
    client: Arc<McpHttpsClient>,
    dispatch: Arc<Mutex<Dispatch>>,
    writer: JoinHandle<()>,
}

impl McpHttpsConnection {
    /// Start a connection's control loop without sending network traffic.
    /// Call inside the app's Tokio runtime; initialize before any other request.
    ///
    /// # Errors
    /// Refuses unsupported endpoint configuration, absent Tokio runtime, and
    /// exhausted carrier capacity. No host processes or credentials are loaded.
    pub fn new(endpoint: &str) -> Result<(Self, mpsc::Receiver<McpEvent>), String> {
        Self::with_client(Arc::new(McpHttpsClient::new(endpoint)?))
    }

    /// Start the same bounded dispatcher with an app-resolved OAuth credential.
    ///
    /// # Errors
    /// Refuses an invalid/revoked credential or unavailable runtime/carrier capacity.
    pub fn new_authenticated(
        authorization: Arc<super::McpBearerAuthorization>,
    ) -> Result<(Self, mpsc::Receiver<McpEvent>), String> {
        Self::with_client(Arc::new(McpHttpsClient::new_authenticated(authorization)?))
    }

    fn with_client(
        client: Arc<McpHttpsClient>,
    ) -> Result<(Self, mpsc::Receiver<McpEvent>), String> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "MCP requires an app-owned asynchronous runtime.")?;
        let (controls, mut receiver) = mpsc::channel(32);
        let (observations, observer) = mpsc::channel(32);
        let dispatch = Arc::new(Mutex::new(Dispatch {
            protocol: McpProtocol::default(),
            client: Arc::clone(&client),
            pending: BTreeMap::new(),
            initializing: None,
            controls,
            observations,
            failed: false,
            ready: false,
        }));
        let writer_client = Arc::clone(&client);
        let writer_dispatch = Arc::clone(&dispatch);
        let writer = runtime.spawn(async move {
            while let Some(control) = receiver.recv().await {
                match control {
                    Control::Barrier(ready) => {
                        let _ = ready.send(());
                    }
                    Control::Send(bytes) => {
                        let cancelled = AtomicBool::new(false);
                        let result = writer_client
                            .post(&bytes, &cancelled, &mut |event| {
                                writer_dispatch
                                    .lock()
                                    .map_err(|_| "MCP dispatch lock failed.")?
                                    .receive(event)
                            })
                            .await;
                        if !matches!(result, Ok(McpHttpOutcome::Accepted)) {
                            writer_client.close();
                            if let Ok(mut dispatch) = writer_dispatch.lock() {
                                dispatch.fail();
                            }
                            return;
                        }
                    }
                }
            }
        });
        Ok((
            Self {
                client,
                dispatch,
                writer,
            },
            observer,
        ))
    }

    /// Negotiate an exact supported revision and wait for the independent
    /// initialized notification to be acknowledged before allowing further work.
    ///
    /// # Errors
    /// Refuses duplicate initialization, incompatible capabilities, a stopped
    /// owner, control deadline expiry, or uncertain network delivery.
    pub async fn initialize(&self, cancelled: &AtomicBool) -> Result<McpProtocolVersion, String> {
        let mut initialization = RequestGuard {
            connection: self,
            completed: false,
        };
        if let Err(error) = self
            .request(McpOperation::Initialize, json!({}), cancelled, &mut |_| {
                Ok(())
            })
            .await
        {
            let _ = self.interrupt();
            return Err(error);
        }
        let (sender, mut receiver) = oneshot::channel();
        self.lock()?.control(Control::Barrier(sender))?;
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                let _ = self.interrupt();
                return Err("MCP initialization acknowledgement interrupted or timed out.".into());
            }
            match receiver.try_recv() {
                Ok(()) => {
                    let mut dispatch = self.lock()?;
                    if dispatch.failed {
                        return Err("MCP initialization was interrupted.".into());
                    }
                    dispatch.ready = true;
                    initialization.completed = true;
                    return dispatch
                        .protocol
                        .negotiated_version()
                        .ok_or("MCP revision is unavailable.".into());
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err(
                        "MCP control writer stopped before initialization acknowledgement.".into(),
                    );
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    }

    /// Perform one operation through the independent dispatcher. `before_send`
    /// must persist a tool invocation's authorized intent before the first POST.
    /// It receives this connection's exact request ID; the broker binds that ID
    /// to its own durable connection/run identity. Errors never cause replay.
    ///
    /// # Errors
    /// Refuses invalid lifecycle, stopped owners, failed intent persistence,
    /// unmatched/invalid responses, exhausted budgets or uncertain delivery.
    pub async fn request(
        &self,
        operation: McpOperation,
        parameters: Value,
        cancelled: &AtomicBool,
        before_send: &mut (impl FnMut(&McpRequestIdentity) -> Result<(), String> + Send),
    ) -> Reply {
        if cancelled.load(Ordering::Acquire) {
            return Err("MCP operation was cancelled before admission.".into());
        }
        let deadline = Instant::now()
            + if operation == McpOperation::CallTool {
                Duration::from_mins(15)
            } else {
                Duration::from_secs(15)
            };
        let (id, bytes, mut recipient) = {
            let mut dispatch = self.lock()?;
            if dispatch.failed {
                return Err("MCP connection is interrupted.".into());
            }
            if operation != McpOperation::Initialize && !dispatch.ready {
                return Err("MCP initialization acknowledgement is still required.".into());
            }
            let (id, bytes) = dispatch.protocol.begin(operation.clone(), parameters)?;
            if operation == McpOperation::Initialize {
                dispatch.initializing = Some(id.clone());
            }
            let (sender, recipient) = oneshot::channel();
            dispatch.pending.insert(id.as_str().to_owned(), sender);
            (id, bytes, recipient)
        };
        // Also revokes on future cancellation/drop, including before-send cuts.
        let mut guard = RequestGuard {
            connection: self,
            completed: false,
        };
        before_send(&id)?;
        let mut observer = |event| self.lock()?.receive(event);
        let mut pending = Box::pin(self.client.post(&bytes, cancelled, &mut observer));
        loop {
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(
                    "MCP operation cancelled or timed out; submitted effects may be uncertain."
                        .into(),
                );
            }
            match recipient.try_recv() {
                Ok(result) => {
                    guard.completed = true;
                    return result;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("MCP reply owner stopped.".into());
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
            }
            if let Ok(outcome) =
                tokio::time::timeout(Duration::from_millis(100), &mut pending).await
            {
                if !matches!(outcome?, McpHttpOutcome::BodyEnded) {
                    return Err(
                        "MCP operation requires authentication or its session is unavailable."
                            .into(),
                    );
                }
                let reply = recipient
                    .try_recv()
                    .map_err(|_| "MCP response ended without the matching operation result.")?;
                guard.completed = true;
                return reply;
            }
        }
    }

    /// Read a complete app-bound catalog with a 45-second aggregate deadline.
    /// Initialize this connection first. No tool calls or permissions occur.
    ///
    /// # Errors
    /// Refuses incomplete, changed, oversized or stalled catalog sequences.
    pub async fn catalog(
        &self,
        project: crate::ProjectId,
        identity: String,
        cancelled: &AtomicBool,
    ) -> Result<super::McpCatalog, String> {
        self.client.check_scope(&project, &identity)?;
        tokio::time::timeout(Duration::from_secs(45), async {
            let mut catalog = super::McpCatalog::new(project, identity)?;
            let mut cursor = None;
            loop {
                let parameters = cursor
                    .as_ref()
                    .map_or_else(|| json!({}), |cursor| json!({"cursor":cursor}));
                let page = self
                    .request(McpOperation::ListTools, parameters, cancelled, &mut |_| {
                        Ok(())
                    })
                    .await?;
                cursor = catalog.push_page(cursor.as_deref(), &page)?;
                if cursor.is_none() {
                    return Ok(catalog);
                }
            }
        })
        .await
        .map_err(|_| "MCP catalog exceeded its aggregate deadline.")?
    }

    /// Answer a pending elicitation after the app UI's explicit decision. This
    /// queues only the answer; it does not claim the peer consumed it.
    /// Returns false if the request was cancelled, answered or closed first.
    ///
    /// # Errors
    /// Refuses malformed identities/responses and full control queues.
    pub fn answer_elicitation(&self, id: &Value, result: &Value) -> Result<bool, String> {
        self.lock()?.answer_elicitation(id, result)
    }

    /// Poll the optional independent server stream in an owner-held future.
    /// HTTP 405 means that stream is unavailable, without disabling POST. This
    /// connection never reconnects automatically or replays a submitted request.
    ///
    /// # Errors
    /// Refuses use before initialization, malformed traffic, cancellation, and
    /// changed catalogs. Dropping this future revokes the owning connection.
    pub async fn listen(&self, cancelled: &AtomicBool) -> Result<McpHttpOutcome, String> {
        if !self.lock()?.ready {
            return Err("Initialize MCP before opening its server stream.".into());
        }
        let mut guard = RequestGuard {
            connection: self,
            completed: false,
        };
        let result = self
            .client
            .listen(None, cancelled, &mut |event| self.lock()?.receive(event))
            .await?;
        if matches!(
            result,
            McpHttpOutcome::StreamUnavailable | McpHttpOutcome::BodyEnded
        ) {
            guard.completed = true;
        }
        Ok(result)
    }

    /// Revoke locally, abort the control writer, and retain unfinished protocol
    /// identities for the owning journal. This is not proof of remote rollback.
    #[must_use]
    pub fn interrupt(&self) -> Vec<McpRequestIdentity> {
        self.client.close();
        self.writer.abort();
        if let Ok(mut dispatch) = self.dispatch.lock() {
            let pending = dispatch.protocol.interrupt();
            dispatch.fail();
            pending
        } else {
            Vec::new()
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Dispatch>, String> {
        self.dispatch
            .lock()
            .map_err(|_| "MCP dispatch lock is unavailable.".into())
    }
}

impl Drop for McpHttpsConnection {
    fn drop(&mut self) {
        let _ = self.interrupt();
    }
}

struct RequestGuard<'a> {
    connection: &'a McpHttpsConnection,
    completed: bool,
}
impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.connection.interrupt();
        }
    }
}

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
