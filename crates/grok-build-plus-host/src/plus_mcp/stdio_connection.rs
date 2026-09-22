//! Independent bounded stdio actor. Only an already-contained service enters it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::{mpsc as async_mpsc, oneshot};

use super::{
    ContainedMcpConnection, McpCatalog, McpEvent, McpOperation, McpProtocolVersion,
    McpRequestIdentity,
};

type Reply = Result<Value, String>;
type Reservation = (McpRequestIdentity, oneshot::Receiver<Reply>);

enum Command {
    Reserve(
        McpOperation,
        Value,
        oneshot::Sender<Result<Reservation, String>>,
    ),
    Commit(McpRequestIdentity),
    Answer(Value, Value),
}

struct Pending {
    bytes: Option<Vec<u8>>,
    reply: oneshot::Sender<Reply>,
}

struct Shared {
    stop: AtomicBool,
    cleanup_proven: AtomicBool,
    ready: Mutex<Option<McpProtocolVersion>>,
    finished: Mutex<Option<Result<(), String>>>,
}

/// Async broker operations over one independently polled, contained MCP process.
/// This does not launch host executables, select a workspace, or grant permission.
/// The application must retain the observation receiver and resolve elicitations.
pub struct McpStdioConnection {
    commands: mpsc::SyncSender<Command>,
    shared: Arc<Shared>,
}

impl McpStdioConnection {
    /// Take ownership of a service that passed exact app/guest admission.
    /// Four retained actors bound this carrier independently of model scheduling.
    ///
    /// # Errors
    /// Refuses exhausted actor capacity or failure to start the control thread.
    pub fn from_contained(
        connection: ContainedMcpConnection,
    ) -> Result<(Self, async_mpsc::Receiver<McpEvent>), String> {
        Self::start(Box::new(connection))
    }

    fn start(peer: Box<dyn Peer>) -> Result<(Self, async_mpsc::Receiver<McpEvent>), String> {
        let slot = Slot::acquire()?;
        let (commands, receiver) = mpsc::sync_channel(32);
        let (observations, observer) = async_mpsc::channel(32);
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            cleanup_proven: AtomicBool::new(false),
            ready: Mutex::new(None),
            finished: Mutex::new(None),
        });
        let owner = Arc::clone(&shared);
        let _thread = std::thread::Builder::new()
            .name("gb-mcp-stdio".into())
            .spawn(move || {
                let _slot = slot;
                let mut actor = Actor {
                    peer,
                    commands: receiver,
                    observations,
                    shared: owner,
                    pending: BTreeMap::new(),
                };
                let result = actor.run();
                actor.shared.stop.store(true, Ordering::Release);
                for (_, pending) in std::mem::take(&mut actor.pending) {
                    let _ = pending.reply.send(Err(
                        "Contained MCP interrupted; submitted delivery may be uncertain.".into(),
                    ));
                }
                // The slot is retained until complete-domain stop finishes, including
                // when the public owner or an operation future has been dropped.
                let cleanup = actor.peer.stop();
                actor
                    .shared
                    .cleanup_proven
                    .store(cleanup.is_ok(), Ordering::Release);
                if let Ok(mut finished) = actor.shared.finished.lock() {
                    *finished = Some(cleanup.and(result));
                }
            })
            .map_err(|error| error.to_string())?;
        Ok((Self { commands, shared }, observer))
    }

    /// Await protocol readiness while the actor handles peer messages independently.
    ///
    /// # Errors
    /// Refuses cancellation, stopped services or an expired readiness deadline.
    pub async fn initialize(&self, cancelled: &AtomicBool) -> Result<McpProtocolVersion, String> {
        let mut guard = Guard {
            connection: self,
            completed: false,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.check(cancelled, deadline)?;
            if let Some(version) = *self
                .shared
                .ready
                .lock()
                .map_err(|_| "Contained MCP readiness unavailable.")?
            {
                guard.completed = true;
                return Ok(version);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Reserve an exact wire ID, persist authorized intent through `before_send`,
    /// then permit the actor to write it. No failed or uncertain call is retried.
    /// Dropping the future stops the connection, including the pre-commit gap.
    ///
    /// # Errors
    /// Refuses malformed requests, failed intent persistence, cancellation,
    /// unready/changed services, peer errors and bounded-capacity exhaustion.
    pub async fn request(
        &self,
        operation: McpOperation,
        parameters: Value,
        cancelled: &AtomicBool,
        before_send: &mut (impl FnMut(&McpRequestIdentity) -> Result<(), String> + Send),
    ) -> Reply {
        bounded(&parameters, super::MCP_MAX_FRAME_BYTES)?;
        let mut guard = Guard {
            connection: self,
            completed: false,
        };
        let deadline = Instant::now()
            + if operation == McpOperation::CallTool {
                Duration::from_mins(15)
            } else {
                Duration::from_secs(15)
            };
        self.check(cancelled, deadline)?;
        let (sender, mut reservation) = oneshot::channel();
        self.command(Command::Reserve(operation, parameters, sender))?;
        let (identity, mut result) = loop {
            self.check(cancelled, deadline)?;
            match reservation.try_recv() {
                Ok(value) => break value?,
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("Contained MCP reservation owner stopped.".into());
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };
        before_send(&identity)?;
        self.check(cancelled, deadline)?;
        self.command(Command::Commit(identity))?;
        loop {
            self.check(cancelled, deadline)?;
            match result.try_recv() {
                Ok(value) => {
                    guard.completed = true;
                    return value;
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    return Err("Contained MCP reply owner stopped.".into());
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }

    /// Read a complete catalog after initialization, within 45 seconds.
    ///
    /// # Errors
    /// Refuses invalid, changed, oversized, incomplete or stalled catalogs.
    pub async fn catalog(
        &self,
        project: crate::ProjectId,
        identity: String,
        cancelled: &AtomicBool,
    ) -> Result<McpCatalog, String> {
        tokio::time::timeout(Duration::from_secs(45), async {
            let mut catalog = McpCatalog::new(project, identity)?;
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
        .map_err(|_| "Contained MCP catalog exceeded its aggregate deadline.")?
    }

    /// Queue a bounded app-validated answer without waiting for model progress.
    /// True means queued locally, never server consumption. A peer cancellation
    /// or earlier answer may make the queued answer a no-op.
    ///
    /// # Errors
    /// Refuses oversized input or a full/stopped control queue.
    pub fn answer_elicitation(&self, identity: &Value, result: &Value) -> Result<bool, String> {
        bounded(identity, 1024)?;
        bounded(result, 64 * 1024)?;
        if self.shared.stop.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.command(Command::Answer(identity.clone(), result.clone()))?;
        Ok(true)
    }

    /// Revoke this connection. Submitted effects retain uncertain delivery until
    /// their owner reconciles the durable journal; this does not claim rollback.
    pub fn interrupt(&self) {
        self.shared.stop.store(true, Ordering::Release);
    }

    /// True only after this actor's complete-domain stop returned verified cleanup.
    #[must_use]
    pub fn cleanup_proven(&self) -> bool {
        self.shared.cleanup_proven.load(Ordering::Acquire)
    }

    /// Keep a caller-supplied attenuation check active while this service runs.
    /// The callback may revoke existing authority; it cannot grant new authority.
    /// Dropping this monitoring future revokes the connection as well.
    ///
    /// # Errors
    /// Stops on cancellation, completed cleanup or a failed authority check.
    pub async fn monitor_authority(
        &self,
        cancelled: &AtomicBool,
        check: &(impl Fn() -> Result<(), String> + Sync),
    ) -> Result<(), String> {
        let _guard = Guard {
            connection: self,
            completed: false,
        };
        loop {
            if cancelled.load(Ordering::Acquire) || self.shared.stop.load(Ordering::Acquire) {
                return Err("Contained MCP owner stopped.".into());
            }
            check()?;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Stop and await the complete-domain cleanup result.
    ///
    /// # Errors
    /// Reports uncertain cleanup or a failed connection; no new process is started.
    pub async fn stop(&self) -> Result<(), String> {
        self.interrupt();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(result) = self
                .shared
                .finished
                .lock()
                .map_err(|_| "Contained MCP cleanup state unavailable.")?
                .clone()
            {
                return result;
            }
            if Instant::now() >= deadline {
                return Err("Contained MCP cleanup remains uncertain; its retained owner is still responsible.".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn command(&self, command: Command) -> Result<(), String> {
        if self.shared.stop.load(Ordering::Acquire) {
            return Err("Contained MCP connection has stopped.".into());
        }
        self.commands
            .try_send(command)
            .map_err(|_| "Contained MCP control capacity is occupied or closed.".into())
    }

    fn check(&self, cancelled: &AtomicBool, deadline: Instant) -> Result<(), String> {
        if cancelled.load(Ordering::Acquire)
            || self.shared.stop.load(Ordering::Acquire)
            || Instant::now() >= deadline
        {
            return Err(
                "Contained MCP interrupted or timed out; submitted effects may be uncertain."
                    .into(),
            );
        }
        Ok(())
    }
}

impl Drop for McpStdioConnection {
    fn drop(&mut self) {
        self.interrupt();
    }
}

fn bounded(value: &Value, maximum: usize) -> Result<(), String> {
    if serde_json::to_vec(value)
        .map_err(|_| "Cannot encode MCP data.")?
        .len()
        > maximum
    {
        return Err("Contained MCP data exceeded its bound.".into());
    }
    Ok(())
}

struct Guard<'a> {
    connection: &'a McpStdioConnection,
    completed: bool,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.connection.interrupt();
        }
    }
}

static ACTORS: AtomicUsize = AtomicUsize::new(0);
struct Slot;
impl Slot {
    fn acquire() -> Result<Self, String> {
        ACTORS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 4).then_some(count + 1)
            })
            .map_err(|_| "Contained MCP actor capacity is occupied.")?;
        Ok(Self)
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        ACTORS.fetch_sub(1, Ordering::AcqRel);
    }
}

trait Peer: Send {
    fn poll(&mut self) -> Result<Option<McpEvent>, String>;
    fn reserve(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<(McpRequestIdentity, Vec<u8>), String>;
    fn send(&mut self, bytes: &[u8]) -> Result<(), String>;
    fn answer(&mut self, identity: &Value, result: &Value) -> Result<(), String>;
    fn version(&self) -> Option<McpProtocolVersion>;
    fn stop(&mut self) -> Result<(), String>;
}
impl Peer for ContainedMcpConnection {
    fn poll(&mut self) -> Result<Option<McpEvent>, String> {
        self.poll()
    }
    fn reserve(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<(McpRequestIdentity, Vec<u8>), String> {
        self.reserve(operation, params)
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.send(bytes)
    }
    fn answer(&mut self, identity: &Value, result: &Value) -> Result<(), String> {
        self.answer_elicitation(identity, result).map(|_| ())
    }
    fn version(&self) -> Option<McpProtocolVersion> {
        self.version()
    }
    fn stop(&mut self) -> Result<(), String> {
        self.stop()
    }
}

struct Actor {
    peer: Box<dyn Peer>,
    commands: mpsc::Receiver<Command>,
    observations: async_mpsc::Sender<McpEvent>,
    shared: Arc<Shared>,
    pending: BTreeMap<String, Pending>,
}

impl Actor {
    fn run(&mut self) -> Result<(), String> {
        while !self.shared.stop.load(Ordering::Acquire) {
            match self.commands.try_recv() {
                Ok(command) => self.command(command)?,
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            for _ in 0..4 {
                if self.shared.stop.load(Ordering::Acquire) {
                    break;
                }
                let Some(event) = self.peer.poll()? else {
                    break;
                };
                self.receive(event)?;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    fn command(&mut self, command: Command) -> Result<(), String> {
        if self.shared.stop.load(Ordering::Acquire) {
            return Err("Contained MCP revoked before control submission.".into());
        }
        match command {
            Command::Reserve(operation, params, recipient) => {
                if self.pending.len() >= 8 {
                    return Err("Contained MCP request capacity is occupied.".into());
                }
                let (id, bytes) = self.peer.reserve(operation, params)?;
                let (sender, result) = oneshot::channel();
                if self
                    .pending
                    .insert(
                        id.as_str().into(),
                        Pending {
                            bytes: Some(bytes),
                            reply: sender,
                        },
                    )
                    .is_some()
                {
                    return Err("Contained MCP reused a request identity.".into());
                }
                recipient
                    .send(Ok((id, result)))
                    .map_err(|_| "Contained MCP reservation owner stopped.")?;
            }
            Command::Commit(identity) => {
                let bytes = self
                    .pending
                    .get_mut(identity.as_str())
                    .and_then(|pending| pending.bytes.take())
                    .ok_or("Contained MCP commit has no unsent reservation.")?;
                self.peer.send(&bytes)?;
            }
            Command::Answer(identity, result) => self.peer.answer(&identity, &result)?,
        }
        Ok(())
    }

    fn receive(&mut self, event: McpEvent) -> Result<(), String> {
        match event {
            McpEvent::Initialized => {
                let mut ready = self
                    .shared
                    .ready
                    .lock()
                    .map_err(|_| "Contained MCP readiness unavailable.")?;
                if ready.is_some() {
                    return Err("Contained MCP initialized twice.".into());
                }
                *ready = Some(
                    self.peer
                        .version()
                        .ok_or("Contained MCP protocol revision unavailable.")?,
                );
            }
            McpEvent::Result {
                identity, value, ..
            } => self.complete(&identity, Ok(value))?,
            McpEvent::RemoteError { identity, code, .. } => self.complete(
                &identity,
                Err(format!(
                    "Contained MCP request rejected with RPC code {code}."
                )),
            )?,
            McpEvent::ToolsChanged => {
                return Err(
                    "Contained MCP catalog changed; review it again before any further call."
                        .into(),
                );
            }
            McpEvent::Observation => {}
            McpEvent::Send(_) => {
                return Err("Contained MCP carrier left an unhandled protocol write.".into());
            }
            observation => self
                .observations
                .try_send(observation)
                .map_err(|_| "Contained MCP observation owner stopped or exceeded capacity.")?,
        }
        Ok(())
    }

    fn complete(&mut self, identity: &McpRequestIdentity, result: Reply) -> Result<(), String> {
        let pending = self
            .pending
            .remove(identity.as_str())
            .ok_or("Contained MCP reply has no waiting operation.")?;
        if pending.bytes.is_some() {
            return Err("Contained MCP replied before the app committed its request.".into());
        }
        pending
            .reply
            .send(result)
            .map_err(|_| "Contained MCP reply owner stopped.".into())
    }
}

#[cfg(test)]
mod tests;
