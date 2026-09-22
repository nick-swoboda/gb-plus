//! Host requests exercise the production session owner with synthetic loopback peers.
use super::*;
use crate::{PlusLiveIdentity, encode_plus_live_conversation_request};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio_tungstenite::tungstenite::{Message, WebSocket, protocol::Role};

fn owner() -> (PlusLiveWebSocket, WebSocket<std::net::TcpStream>) {
    let (carrier, peer) = session::loopback();
    (
        PlusLiveWebSocket {
            carrier,
            account: None,
        },
        WebSocket::from_raw_socket(peer, Role::Server, Some(config())),
    )
}
fn request(input: &[Value]) -> PlusLiveChatRequest {
    encode_plus_live_conversation_request(
        input,
        "synthetic",
        None,
        &PlusLiveIdentity::from_configured_key("SYNTHETIC_NEVER_AUTHENTICATED").unwrap(),
    )
    .unwrap()
}
fn read(peer: &mut WebSocket<std::net::TcpStream>) -> Value {
    serde_json::from_str(&peer.read().unwrap().into_text().unwrap()).unwrap()
}
fn complete(peer: &mut WebSocket<std::net::TcpStream>, response: &Value) {
    peer.send(Message::text(
        json!({"type":"response.completed","response":response}).to_string(),
    ))
    .unwrap();
}
fn full_capacity() {
    let first = leases::SocketLease::acquire().unwrap();
    let second = leases::SocketLease::acquire().unwrap();
    assert!(leases::SocketLease::acquire().is_err());
    drop((first, second));
}

#[test]
fn host_send_preserves_items_usage_instructions_and_full_local_tool_continuation() {
    let _fixture = leases::TEST_LOCK.lock().unwrap();
    let (mut socket, mut peer) = owner();
    let user = json!({"role":"user","content":"synthetic fact"});
    let reasoning = json!({"type":"reasoning","encrypted_content":"EXACT_OPAQUE"});
    let call =
        json!({"type":"function_call","call_id":"call-1","name":"read_file","arguments":"{}"});
    let result = json!({"type":"function_call_output","call_id":"call-1","output":"EXACT_RESULT"});
    let response = json!({"id":"response-1","status":"completed","output":[reasoning,call],"usage":{"input_tokens":11,"output_tokens":7}});
    let expected = response.clone();
    let server = std::thread::spawn(move || {
        let first = read(&mut peer);
        assert_eq!(first["store"], false);
        assert!(first.get("previous_response_id").is_none());
        assert!(!first.to_string().contains("SYNTHETIC_NEVER_AUTHENTICATED"));
        complete(&mut peer, &expected);
        assert!(
            peer.read().is_err(),
            "Retiring the owner must close the socket"
        );
        first
    });
    let mut events = Vec::new();
    let bytes = socket
        .send(
            &request(std::slice::from_ref(&user)),
            || false,
            |event| events.push(event),
        )
        .unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), response);
    assert!(
        matches!(events.as_slice(), [PlusLiveStreamEvent::Usage(usage)] if usage.input_tokens == Some(11) && usage.output_tokens == Some(7))
    );
    socket.close().unwrap();
    let first = server.join().unwrap();
    // A reconstructed full request uses a fresh connection. The session test
    // below this module proves retirement happens in the production preflight.
    let (mut socket, mut peer) = owner();
    let expected_response = response.clone();
    let expected_result = result.clone();
    let server = std::thread::spawn(move || {
        let second = read(&mut peer);
        assert!(second.get("previous_response_id").is_none());
        assert_eq!(second["instructions"], first["instructions"]);
        assert_eq!(second["input"][0], first["input"][0]);
        assert_eq!(second["input"][1], expected_response["output"][0]);
        assert_eq!(second["input"][2], expected_response["output"][1]);
        assert_eq!(second["input"][3], expected_result);
        complete(
            &mut peer,
            &json!({"id":"response-2","status":"completed","output":[]}),
        );
        assert!(peer.read().is_err());
    });
    socket
        .send(&request(&[user, reasoning, call, result]), || false, |_| {})
        .unwrap();
    drop(socket);
    server.join().unwrap();
    full_capacity();
}

#[test]
fn returned_delegation_closes_parent_socket_before_two_children_can_connect() {
    let _fixture = leases::TEST_LOCK.lock().unwrap();
    let (mut socket, mut peer) = owner();
    let server = std::thread::spawn(move || {
        read(&mut peer);
        complete(
            &mut peer,
            &json!({"id":"delegation","status":"completed","output":[{"type":"function_call","name":"app_agent_spawn","call_id":"child-1","arguments":"{}"}]}),
        );
        assert!(peer.read().is_err());
    });
    socket
        .send(
            &request(&[json!({"role":"user","content":"delegate"})]),
            || false,
            |_| {},
        )
        .unwrap();
    assert!(socket.account.is_none());
    full_capacity();
    server.join().unwrap();
}

#[test]
fn transport_loss_and_midstream_cancellation_close_without_resubmission() {
    let _fixture = leases::TEST_LOCK.lock().unwrap();
    for cancel in [false, true] {
        let (mut socket, mut peer) = owner();
        let seen = Arc::new(AtomicBool::new(false));
        let submitted = seen.clone();
        let server = std::thread::spawn(move || {
            read(&mut peer);
            submitted.store(true, Ordering::Release);
            if cancel {
                assert!(
                    peer.read().is_err(),
                    "Cancellation must close instead of submitting again"
                );
            } else {
                peer.send(Message::text(
                    json!({"type":"response.output_text.delta","delta":"partial"}).to_string(),
                ))
                .unwrap();
                peer.close(None).unwrap();
            }
        });
        let mut events = Vec::new();
        let failure = socket
            .send(
                &request(&[json!({"role":"user","content":"one send"})]),
                || cancel && seen.load(Ordering::Acquire),
                |event| events.push(event),
            )
            .unwrap_err();
        assert!(if cancel {
            matches!(failure, PlusHostError::LiveCancelled)
        } else {
            matches!(failure, PlusHostError::LiveTransport(_))
        });
        assert_eq!(events.len(), usize::from(!cancel));
        server.join().unwrap();
        full_capacity();
    }
}

#[test]
fn credential_change_and_pre_send_cancel_retire_the_old_warm_connection() {
    let _fixture = leases::TEST_LOCK.lock().unwrap();
    let (mut socket, mut peer) = owner();
    socket.account = Some([0; 32]);
    let request = request(&[json!({"role":"user","content":"must not send"})]);
    assert!(matches!(
        socket.send(&request, || true, |_| panic!("No output permitted")),
        Err(PlusHostError::LiveCancelled)
    ));
    assert!(peer.read().is_err());
    full_capacity();
}

#[test]
fn app_blocking_worker_can_create_exchange_and_close_its_connection() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::task::spawn_blocking(
            host_send_preserves_items_usage_instructions_and_full_local_tool_continuation,
        )
        .await
        .unwrap();
    });
}
