use super::{
    chain::Chain,
    exchange::{Failure, bounded, exchange},
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::runtime::Builder;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};
fn body() -> String {
    json!({"model":"synthetic","store":false,"input":[{"role":"user","content":"fixture"}],"tools":[]}).to_string()
}
fn runtime() -> tokio::runtime::Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}
#[test]
fn completed_items_remain_exact_over_actual_websocket_framing() {
    runtime().block_on(async{
    let (client,server)=tokio::io::duplex(4096);
    let mut client=WebSocketStream::from_raw_socket(client,Role::Client,Some(super::config())).await;
    let peer=tokio::spawn(async move{
        let mut peer=WebSocketStream::from_raw_socket(server,Role::Server,Some(super::config())).await;
        let input=peer.next().await.unwrap().unwrap().into_text().unwrap();let request:Value=serde_json::from_str(&input).unwrap();
        assert_eq!(request["type"],"response.create");assert_eq!(request["store"],false);
        let response=json!({"id":"response-fixture","status":"completed","output":[{"type":"reasoning","encrypted_content":"EXACT_OPAQUE_CONTEXT"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"literal <img>"}]}]});
        peer.send(Message::text(json!({"type":"response.output_text.delta","delta":"literal <img>"}).to_string())).await.unwrap();
        peer.send(Message::text(json!({"type":"response.completed","response":response}).to_string())).await.unwrap();response
    });
    let mut chain=Chain::default();let prepared=chain.prepare(&body()).unwrap();let mut events=Vec::new();
    let actual=exchange(&mut client,&mut chain,prepared,&mut||false,&mut|event|{events.push(event.clone());Ok(())}).await.unwrap();
    assert_eq!(actual,peer.await.unwrap());assert_eq!(events.len(),2);
});
}
#[test]
fn loss_after_output_returns_interruption_without_a_second_submission() {
    runtime().block_on(async {
        let (client, server) = tokio::io::duplex(4096);
        let mut client =
            WebSocketStream::from_raw_socket(client, Role::Client, Some(super::config())).await;
        let peer = tokio::spawn(async move {
            let mut peer =
                WebSocketStream::from_raw_socket(server, Role::Server, Some(super::config())).await;
            assert!(peer.next().await.unwrap().is_ok());
            peer.send(Message::text(
                json!({"type":"response.output_text.delta","delta":"partial"}).to_string(),
            ))
            .await
            .unwrap();
            peer.close(None).await.unwrap();
        });
        let mut chain = Chain::default();
        let prepared = chain.prepare(&body()).unwrap();
        let mut count = 0;
        assert_eq!(
            exchange(
                &mut client,
                &mut chain,
                prepared,
                &mut || false,
                &mut |_| {
                    count += 1;
                    Ok(())
                }
            )
            .await
            .unwrap_err(),
            Failure::Closed
        );
        peer.await.unwrap();
        assert_eq!(count, 1);
        assert!(
            !chain
                .prepare(&body())
                .unwrap()
                .wire
                .contains("previous_response_id")
        );
    });
}
#[test]
fn cancellation_and_deadlines_interrupt_even_without_provider_progress() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker = cancelled.clone();
    let flag = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        worker.store(true, Ordering::Release);
    });
    let start = Instant::now();
    let result = runtime().block_on(bounded(
        std::future::pending::<()>(),
        start + Duration::from_secs(5),
        &mut || cancelled.load(Ordering::Acquire),
    ));
    flag.join().unwrap();
    assert_eq!(result, Err(Failure::Cancelled));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(
        runtime().block_on(bounded(
            std::future::pending::<()>(),
            Instant::now() + Duration::from_millis(20),
            &mut || false
        )),
        Err(Failure::Deadline)
    );
}
#[test]
fn a_rejection_is_retry_eligible_only_before_any_response_event() {
    runtime().block_on(async{
    for observed in [false,true]{
        let(client,server)=tokio::io::duplex(4096);let mut client=WebSocketStream::from_raw_socket(client,Role::Client,Some(super::config())).await;
        let peer=tokio::spawn(async move{let mut peer=WebSocketStream::from_raw_socket(server,Role::Server,Some(super::config())).await;peer.next().await.unwrap().unwrap();if observed{peer.send(Message::text(json!({"type":"response.created"}).to_string())).await.unwrap();}peer.send(Message::text(json!({"type":"error","status":429,"error":{"message":"DO_NOT_RETAIN_RAW_PROVIDER_ERROR"}}).to_string())).await.unwrap();});
        let mut chain=Chain::default();let prepared=chain.prepare(&body()).unwrap();let error=exchange(&mut client,&mut chain,prepared,&mut||false,&mut|_|Ok(())).await.unwrap_err();
        assert_eq!(error,if observed{Failure::Protocol}else{Failure::Rejected(429)});assert!(!format!("{error:?}").contains("DO_NOT_RETAIN"));peer.await.unwrap();
    }
});
}
