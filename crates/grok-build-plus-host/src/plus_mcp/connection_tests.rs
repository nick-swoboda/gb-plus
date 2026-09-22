use super::*;

fn dispatcher() -> (Dispatch, mpsc::Receiver<Control>, mpsc::Receiver<McpEvent>) {
    let mut protocol = McpProtocol::default();
    let (id, _) = protocol.begin(McpOperation::Initialize, json!({})).unwrap();
    protocol.receive(&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id.as_str(),"result":{
        "protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}
    }})).unwrap()).unwrap();
    let (controls, control_receiver) = mpsc::channel(32);
    let (observations, observation_receiver) = mpsc::channel(32);
    (
        Dispatch {
            protocol,
            client: Arc::new(McpHttpsClient::new("https://example.invalid/mcp").unwrap()),
            pending: BTreeMap::new(),
            initializing: None,
            controls,
            observations,
            failed: false,
            ready: true,
        },
        control_receiver,
        observation_receiver,
    )
}

fn message(value: &Value) -> McpHttpEvent {
    McpHttpEvent::Message(serde_json::to_vec(value).unwrap())
}

#[test]
fn independent_control_dispatch_cannot_complete_a_colliding_client_request() {
    let (mut dispatch, mut controls, _) = dispatcher();
    let (id, _) = dispatch
        .protocol
        .begin(McpOperation::Ping, json!({}))
        .unwrap();
    let (sender, mut recipient) = oneshot::channel();
    dispatch.pending.insert(id.as_str().to_owned(), sender);
    dispatch
        .receive(message(
            &json!({"jsonrpc":"2.0","id":id.as_str(),"method":"ping"}),
        ))
        .unwrap();
    assert!(matches!(controls.try_recv().unwrap(), Control::Send(_)));
    assert!(matches!(
        recipient.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    dispatch
        .receive(message(
            &json!({"jsonrpc":"2.0","id":id.as_str(),"result":{}}),
        ))
        .unwrap();
    assert_eq!(recipient.try_recv().unwrap().unwrap(), json!({}));
}

#[test]
fn elicitation_and_cancellation_reach_the_independent_observer() {
    let (mut dispatch, _, mut observations) = dispatcher();
    dispatch.receive(message(&json!({"jsonrpc":"2.0","id":77,"method":"elicitation/create","params":{
        "message":"Choose a label","requestedSchema":{"type":"object","properties":{"label":{"type":"string"}}}
    }}))).unwrap();
    assert!(matches!(
        observations.try_recv().unwrap(),
        McpEvent::Elicitation { .. }
    ));
    dispatch
        .receive(message(
            &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":77}}),
        ))
        .unwrap();
    assert!(matches!(
        observations.try_recv().unwrap(),
        McpEvent::ElicitationCancelled(_)
    ));
}

#[test]
fn cancelled_elicitation_answer_does_not_interrupt_an_unrelated_tool_request() {
    let (mut dispatch, mut controls, _observations) = dispatcher();
    let (id, _) = dispatch
        .protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"fixture","arguments":{}}),
        )
        .unwrap();
    let (sender, mut result) = oneshot::channel();
    dispatch.pending.insert(id.as_str().to_owned(), sender);
    dispatch.receive(message(&json!({"jsonrpc":"2.0","id":77,"method":"elicitation/create","params":{
        "message":"Choose a name","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}
    }}))).unwrap();
    dispatch
        .receive(message(
            &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":77}}),
        ))
        .unwrap();
    assert!(
        !dispatch
            .answer_elicitation(
                &json!(77),
                &json!({"action":"accept","content":{"name":"Alex"}})
            )
            .unwrap()
    );
    assert!(!dispatch.failed);
    assert!(controls.try_recv().is_err());
    dispatch.receive(message(&json!({"jsonrpc":"2.0","id":id.as_str(),"result":{"content":[{"type":"text","text":"complete without form"}]}}))).unwrap();
    assert!(result.try_recv().unwrap().is_ok());
}

#[test]
fn interruption_wakes_waiting_owners_without_erasing_uncertain_delivery_identity() {
    let (mut dispatch, _, _) = dispatcher();
    let (id, _) = dispatch
        .protocol
        .begin(
            McpOperation::CallTool,
            json!({"name":"fixture","arguments":{}}),
        )
        .unwrap();
    let (sender, mut recipient) = oneshot::channel();
    dispatch.pending.insert(id.as_str().to_owned(), sender);
    dispatch.fail();
    assert!(recipient.try_recv().unwrap().is_err());
    assert_eq!(dispatch.protocol.interrupt(), vec![id]);
}

#[test]
fn schema_change_revokes_before_the_owner_drains_its_observation_queue() {
    let (mut dispatch, _, mut observations) = dispatcher();
    assert!(
        dispatch
            .receive(message(
                &json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})
            ))
            .is_err()
    );
    assert!(dispatch.failed);
    assert!(matches!(
        observations.try_recv().unwrap(),
        McpEvent::ToolsChanged
    ));
}

#[test]
fn failed_intent_persistence_revokes_before_network_dispatch_and_never_replays() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (connection, _observer) =
            McpHttpsConnection::new("https://example.invalid/mcp").unwrap();
        let cancelled = AtomicBool::new(false);
        let mut calls = 0;
        let result = connection
            .request(McpOperation::Initialize, json!({}), &cancelled, &mut |_| {
                calls += 1;
                Err("injected durable write failure".into())
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls, 1);
        assert_eq!(connection.interrupt().len(), 1);
        assert!(
            connection
                .request(McpOperation::Initialize, json!({}), &cancelled, &mut |_| {
                    panic!("interrupted request cannot be replayed")
                })
                .await
                .is_err()
        );
    });
}
