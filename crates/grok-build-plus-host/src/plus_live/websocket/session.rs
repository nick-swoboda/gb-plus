//! Owned warm socket; the app supplies a complete local context for every call.
use super::{
    chain::{Chain, Prepared},
    exchange::{Failure, bounded, exchange},
    leases::SocketLease,
};
use serde_json::Value;
use std::{
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    runtime::{Builder, Runtime},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};

type State = Mutex<Option<Warm>>;
type Registry = Mutex<Vec<Weak<State>>>;
static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();
static REAPER: OnceLock<Result<(), ()>> = OnceLock::new();
// A one-second reaper tick begins closing before the five-minute idle limit.
const EXPIRE: Duration = Duration::from_secs(299);
struct Warm {
    // Socket drops before its lease, including during cancellation/unwind.
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    chain: Chain,
    used: Instant,
    _lease: SocketLease,
}
/// Per-adapter connection owner. Creation never starts a model or opens a socket.
pub struct Session {
    state: Arc<State>,
    runtime: Runtime,
}
impl Session {
    /// Construct on the app's blocking worker, which may have an entered Tokio
    /// handle. Handle presence does not mean that this thread is polling a task.
    /// Refuses unavailable privacy, runtime creation or reaping services.
    pub fn new() -> Result<Self, &'static str> {
        super::privacy::ensure().map_err(|_| "WebSocket log privacy is unavailable.")?;
        ensure_reaper()?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "WebSocket runtime creation failed.")?;
        Ok(Self {
            state: Arc::new(Mutex::new(None)),
            runtime,
        })
    }
    /// Close the complete socket before yielding a parent's execution lease.
    pub fn close(&self) -> Result<(), &'static str> {
        match self.state.lock() {
            Ok(mut state) => {
                state.take();
                Ok(())
            }
            Err(poisoned) => {
                poisoned.into_inner().take();
                Err("WebSocket ownership lock failed; socket was closed.")
            }
        }
    }
    /// Request once. Loss after submission returns interruption and clears the chain.
    /// Credentials are fixed by the owning adapter's account lease, not provider fields.
    pub fn request(
        &mut self,
        credential: &[u8],
        body: &str,
        mut cancelled: impl FnMut() -> bool,
        mut emit: impl FnMut(&Value) -> Result<(), Failure>,
    ) -> Result<Value, Failure> {
        if cancelled() {
            let _ = self.close();
            return Err(Failure::Cancelled);
        }
        let (warm, prepared) = self.prepare(body)?;
        let result = self.runtime.block_on(async {
            let mut warm = if let Some(warm) = warm {
                warm
            } else {
                let lease = SocketLease::acquire().map_err(|_| Failure::Protocol)?;
                let request = super::request(credential).map_err(|_| Failure::Protocol)?;
                let config = super::super::live_client_config().map_err(|_| Failure::Protocol)?;
                let (socket, _) = bounded(
                    connect_async_tls_with_config(
                        request,
                        Some(super::config()),
                        true,
                        Some(Connector::Rustls(config)),
                    ),
                    Instant::now() + Duration::from_secs(30),
                    &mut cancelled,
                )
                .await?
                .map_err(|_| Failure::Io)?;
                Warm {
                    socket,
                    chain: Chain::default(),
                    used: Instant::now(),
                    _lease: lease,
                }
            };
            let response = exchange(
                &mut warm.socket,
                &mut warm.chain,
                prepared,
                &mut cancelled,
                &mut emit,
            )
            .await?;
            warm.used = Instant::now();
            Ok((response, warm))
        });
        match result {
            Ok((response, warm)) => {
                if cancelled() {
                    return Err(Failure::Cancelled);
                }
                *self.state.lock().map_err(|_| Failure::Protocol)? = Some(warm);
                register(&self.state).map_err(|_| {
                    let _ = self.close();
                    Failure::Protocol
                })?;
                Ok(response)
            }
            Err(error) => Err(error),
        }
    }

    fn prepare(&self, body: &str) -> Result<(Option<Warm>, Prepared), Failure> {
        let mut warm = self.state.lock().map_err(|_| Failure::Protocol)?.take();
        if warm.as_ref().is_some_and(|w| w.used.elapsed() >= EXPIRE) {
            warm = None;
        }
        let empty = Chain::default();
        let prepared = warm
            .as_ref()
            .map_or(&empty, |warm| &warm.chain)
            .prepare(body)
            .map_err(|_| Failure::Protocol)?;
        if prepared.fresh_connection {
            // The admitted endpoint reused response IDs for separate full-input
            // requests on one connection. Retire it before a new submission;
            // never rewrite provider IDs or relax the durable journal guard.
            drop(warm.take());
            return Ok((None, empty.prepare(body).map_err(|_| Failure::Protocol)?));
        }
        Ok((warm, prepared))
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Tests exercise the production send path through an already connected local
/// socket. This cannot change the production endpoint or credential boundary.
#[cfg(test)]
pub(super) fn loopback() -> (Session, std::net::TcpStream) {
    use tokio_tungstenite::tungstenite::protocol::Role;
    let session = Session::new().unwrap();
    let (warm, peer) = session.runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let socket = WebSocketStream::from_raw_socket(
            MaybeTlsStream::Plain(client),
            Role::Client,
            Some(super::config()),
        )
        .await;
        (
            Warm {
                socket,
                chain: Chain::default(),
                used: Instant::now(),
                _lease: SocketLease::acquire().unwrap(),
            },
            peer.into_std().unwrap(),
        )
    });
    *session.state.lock().unwrap() = Some(warm);
    peer.set_nonblocking(false).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    (session, peer)
}
fn ensure_reaper() -> Result<(), &'static str> {
    let registry = REGISTRY
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();
    REAPER
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("gbplus-wss-idle".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        let Ok(mut registered) = registry.lock() else {
                            return;
                        };
                        registered.retain(|weak| {
                            weak.upgrade()
                                .is_some_and(|state| retain_unexpired(&state, Instant::now()))
                        });
                    }
                })
                .map(|_| ())
                .map_err(|_| ())
        })
        .as_ref()
        .copied()
        .map_err(|()| "WebSocket idle reaper could not start.")
}
fn register(state: &Arc<State>) -> Result<(), &'static str> {
    let mut registered = REGISTRY
        .get()
        .ok_or("WebSocket reaper absent.")?
        .lock()
        .map_err(|_| "WebSocket reaper failed.")?;
    registered.retain(|weak| weak.strong_count() > 0);
    if registered
        .iter()
        .any(|weak| weak.ptr_eq(&Arc::downgrade(state)))
    {
        return Ok(());
    }
    // Empty states may be retained until the next reaper tick. No unbounded list.
    if registered.len() >= 64 {
        return Err("WebSocket owner inventory exceeded its bound.");
    }
    registered.push(Arc::downgrade(state));
    Ok(())
}

fn retain_unexpired(state: &Arc<State>, now: Instant) -> bool {
    let mut state = match state.try_lock() {
        Ok(state) => state,
        Err(std::sync::TryLockError::WouldBlock) => return true,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            poisoned.into_inner().take();
            return false;
        }
    };
    if state
        .as_ref()
        .is_some_and(|warm| now.saturating_duration_since(warm.used) >= EXPIRE)
    {
        state.take();
    }
    state.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;
    use tokio_tungstenite::tungstenite::protocol::Role;
    #[test]
    fn full_context_retires_the_real_socket_before_a_new_submission() {
        use serde_json::json;
        use std::io::Read as _;
        let _fixture = super::super::leases::TEST_LOCK.lock().unwrap();
        for instructions in [false, true] {
            let (session, mut peer) = loopback();
            peer.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let user = json!({"role":"user","content":"synthetic fact"});
            let mut body = json!({"model":"synthetic","store":false,"input":[user],"tools":[]});
            if instructions {
                body["instructions"] = json!("Explicit app policy");
            }
            {
                let mut state = session.state.lock().unwrap();
                let chain = &mut state.as_mut().unwrap().chain;
                let first = chain.prepare(&body.to_string()).unwrap();
                chain
                    .completed(
                        first,
                        &json!({"id":"completed-on-old-socket","status":"completed","output":[]}),
                    )
                    .unwrap();
            }
            if !instructions {
                // A changed model also requires full input and a new identity.
                body["model"] = json!("another-admitted-model");
            }
            body["input"] = json!([user,{"role":"user","content":"next turn"}]);
            let (warm, prepared) = session.prepare(&body.to_string()).unwrap();
            assert!(warm.is_none());
            assert!(!prepared.fresh_connection);
            let wire: Value = serde_json::from_str(&prepared.wire).unwrap();
            assert_eq!(wire["input"], body["input"]);
            assert_eq!(wire.get("instructions"), body.get("instructions"));
            assert!(wire.get("previous_response_id").is_none());
            assert_eq!(
                peer.read(&mut [0]).unwrap(),
                0,
                "Old socket must close before connecting or sending"
            );
            let one = SocketLease::acquire().unwrap();
            let two = SocketLease::acquire().unwrap();
            assert!(SocketLease::acquire().is_err());
            drop((one, two));
        }
    }

    #[test]
    fn idle_expiry_closes_the_real_socket_before_releasing_its_lease() {
        let _fixture = super::super::leases::TEST_LOCK.lock().unwrap();
        let session = Session::new().unwrap();
        let (warm, mut peer) = session.runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            let socket = WebSocketStream::from_raw_socket(
                MaybeTlsStream::Plain(client),
                Role::Client,
                Some(super::super::config()),
            )
            .await;
            (
                Warm {
                    socket,
                    chain: Chain::default(),
                    used: Instant::now(),
                    _lease: SocketLease::acquire().unwrap(),
                },
                peer,
            )
        });
        let used = warm.used;
        *session.state.lock().unwrap() = Some(warm);
        assert!(retain_unexpired(
            &session.state,
            used + Duration::from_secs(298)
        ));
        assert!(!retain_unexpired(
            &session.state,
            used + Duration::from_mins(5)
        ));
        session.runtime.block_on(async {
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        });
        let one = SocketLease::acquire().unwrap();
        let two = SocketLease::acquire().unwrap();
        assert!(SocketLease::acquire().is_err());
        drop((one, two));
    }
}
