use super::*;
use std::collections::VecDeque;

static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Evidence {
    intent: AtomicBool,
    writes: AtomicUsize,
    answers: AtomicUsize,
    stopped: AtomicBool,
}

struct FixturePeer {
    protocol: super::super::McpProtocol,
    events: VecDeque<McpEvent>,
    evidence: Arc<Evidence>,
    call: Option<Value>,
    behavior: &'static str,
}

impl FixturePeer {
    fn open(
        behavior: &'static str,
    ) -> (
        McpStdioConnection,
        async_mpsc::Receiver<McpEvent>,
        Arc<Evidence>,
    ) {
        let evidence = Arc::new(Evidence::default());
        let mut peer = Self {
            protocol: super::super::McpProtocol::default(),
            events: VecDeque::new(),
            evidence: Arc::clone(&evidence),
            call: None,
            behavior,
        };
        let (id, _) = peer
            .protocol
            .begin(McpOperation::Initialize, json!({}))
            .unwrap();
        peer.receive(&json!({"jsonrpc":"2.0","id":id.as_str(),"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}));
        let (connection, observer) = McpStdioConnection::start(Box::new(peer)).unwrap();
        (connection, observer, evidence)
    }

    fn receive(&mut self, value: &Value) {
        for event in self
            .protocol
            .receive(&serde_json::to_vec(value).unwrap())
            .unwrap()
        {
            if !matches!(event, McpEvent::Send(_)) {
                self.events.push_back(event);
            }
        }
    }
}

impl Peer for FixturePeer {
    fn poll(&mut self) -> Result<Option<McpEvent>, String> {
        Ok(self.events.pop_front())
    }
    fn reserve(
        &mut self,
        operation: McpOperation,
        params: Value,
    ) -> Result<(McpRequestIdentity, Vec<u8>), String> {
        let reservation = self.protocol.begin(operation, params)?;
        if self.behavior == "premature" {
            self.receive(
                &json!({"jsonrpc":"2.0","id":reservation.0.as_str(),"result":{"content":[]}}),
            );
        }
        Ok(reservation)
    }
    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        let value: Value = serde_json::from_slice(bytes).unwrap();
        if value["method"] == "tools/call" {
            assert!(
                self.evidence.intent.load(Ordering::Acquire),
                "tool bytes preceded intent"
            );
        }
        self.evidence.writes.fetch_add(1, Ordering::AcqRel);
        match self.behavior {
            "elicitation" => {
                self.call = Some(value["id"].clone());
                self.receive(&json!({"jsonrpc":"2.0","id":"peer-1","method":"elicitation/create","params":{"message":"Choose fixture value","requestedSchema":{"type":"object","properties":{}}}}));
            }
            "change" => self.receive(&json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})),
            "hold" => {}
            _ => self.receive(&json!({"jsonrpc":"2.0","id":value["id"],"result":{"content":[{"type":"text","text":"fixture complete"}]}})),
        }
        Ok(())
    }
    fn answer(&mut self, identity: &Value, result: &Value) -> Result<(), String> {
        let _bytes = self.protocol.answer_elicitation(identity, result)?;
        self.evidence.answers.fetch_add(1, Ordering::AcqRel);
        let id = self.call.take().ok_or("Fixture has no pending call.")?;
        self.receive(&json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"answer received"}]}}));
        Ok(())
    }
    fn version(&self) -> Option<McpProtocolVersion> {
        self.protocol.negotiated_version()
    }
    fn stop(&mut self) -> Result<(), String> {
        self.evidence.stopped.store(true, Ordering::Release);
        Ok(())
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}
fn params() -> Value {
    json!({"name":"fixture_tool","arguments":{}})
}

#[test]
fn intent_failure_never_writes_reserved_tool_bytes_and_stops_the_service() {
    let _serial = SERIAL.lock().unwrap();
    runtime().block_on(async {
        let (connection, _observer, evidence) = FixturePeer::open("normal");
        let cancelled = AtomicBool::new(false);
        connection.initialize(&cancelled).await.unwrap();
        let result = connection
            .request(McpOperation::CallTool, params(), &cancelled, &mut |_| {
                Err("journal failure".into())
            })
            .await;
        assert_eq!(result.unwrap_err(), "journal failure");
        connection.stop().await.unwrap();
        assert_eq!(evidence.writes.load(Ordering::Acquire), 0);
        assert!(evidence.stopped.load(Ordering::Acquire));
    });
}

#[test]
fn peer_elicitation_completes_while_the_original_tool_request_is_waiting() {
    let _serial = SERIAL.lock().unwrap();
    runtime().block_on(async {
        let (connection, mut observer, evidence) = FixturePeer::open("elicitation");
        let cancelled = AtomicBool::new(false);
        connection.initialize(&cancelled).await.unwrap();
        let connection = Arc::new(connection);
        let responder = Arc::clone(&connection);
        let answer = tokio::spawn(async move {
            let event = tokio::time::timeout(Duration::from_secs(2), observer.recv())
                .await
                .unwrap()
                .unwrap();
            let McpEvent::Elicitation { identity, .. } = event else {
                panic!("Expected peer elicitation");
            };
            responder
                .answer_elicitation(&identity, &json!({"action":"accept","content":{}}))
                .unwrap();
        });
        let result = connection
            .request(McpOperation::CallTool, params(), &cancelled, &mut |_| {
                evidence.intent.store(true, Ordering::Release);
                Ok(())
            })
            .await
            .unwrap();
        answer.await.unwrap();
        assert_eq!(result["content"][0]["text"], "answer received");
        connection.stop().await.unwrap();
        assert_eq!(evidence.writes.load(Ordering::Acquire), 1);
        assert_eq!(evidence.answers.load(Ordering::Acquire), 1);
        assert!(evidence.stopped.load(Ordering::Acquire));
    });
}

#[test]
fn dropped_pending_request_stops_the_actor_without_replaying_an_effect() {
    let _serial = SERIAL.lock().unwrap();
    runtime().block_on(async {
        let (connection, _observer, evidence) = FixturePeer::open("hold");
        let cancelled = AtomicBool::new(false);
        connection.initialize(&cancelled).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(150),
            connection.request(McpOperation::CallTool, params(), &cancelled, &mut |_| {
                evidence.intent.store(true, Ordering::Release);
                Ok(())
            }),
        )
        .await;
        assert!(result.is_err());
        connection.stop().await.unwrap();
        assert_eq!(evidence.writes.load(Ordering::Acquire), 1);
        assert!(
            connection
                .request(
                    McpOperation::CallTool,
                    params(),
                    &cancelled,
                    &mut |_| Ok(())
                )
                .await
                .is_err()
        );
        assert_eq!(evidence.writes.load(Ordering::Acquire), 1);
    });
}

#[test]
fn changed_catalog_and_precommit_responses_revoke_connection_authority() {
    let _serial = SERIAL.lock().unwrap();
    runtime().block_on(async {
        for behavior in ["change", "premature"] {
            let (connection, _observer, evidence) = FixturePeer::open(behavior);
            let cancelled = AtomicBool::new(false);
            connection.initialize(&cancelled).await.unwrap();
            assert!(
                connection
                    .request(McpOperation::CallTool, params(), &cancelled, &mut |_| {
                        evidence.intent.store(true, Ordering::Release);
                        Ok(())
                    })
                    .await
                    .is_err()
            );
            assert!(connection.stop().await.is_err());
            assert!(evidence.stopped.load(Ordering::Acquire));
            assert_eq!(
                evidence.writes.load(Ordering::Acquire),
                usize::from(behavior == "change")
            );
        }
    });
}

#[test]
fn cancellation_before_commit_never_submits_the_reserved_operation() {
    let _serial = SERIAL.lock().unwrap();
    runtime().block_on(async {
        let (connection, _observer, evidence) = FixturePeer::open("normal");
        let cancelled = AtomicBool::new(false);
        connection.initialize(&cancelled).await.unwrap();
        assert!(
            connection
                .request(McpOperation::CallTool, params(), &cancelled, &mut |_| {
                    cancelled.store(true, Ordering::Release);
                    Ok(())
                })
                .await
                .is_err()
        );
        connection.stop().await.unwrap();
        assert_eq!(evidence.writes.load(Ordering::Acquire), 0);
        assert!(evidence.stopped.load(Ordering::Acquire));
    });
}
