//! Bounded message exchange. Errors retain classifications, never provider payloads.
use super::chain::{Chain, Prepared};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::{
    future::Future,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

const MAX_RESPONSE: usize = 1024 * 1024;
const MAX_EVENTS: usize = 65_536;
#[derive(Debug, PartialEq)]
pub enum Failure {
    Cancelled,
    Deadline,
    Closed,
    Protocol,
    Io,
    Rejected(u16),
}

pub(super) async fn bounded<T>(
    future: impl Future<Output = T>,
    deadline: Instant,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<T, Failure> {
    let mut future = Box::pin(future);
    loop {
        if cancelled() {
            return Err(Failure::Cancelled);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Deadline);
        }
        if let Ok(value) =
            tokio::time::timeout(remaining.min(Duration::from_millis(100)), &mut future).await
        {
            return Ok(value);
        }
    }
}

pub(super) async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    chain: &mut Chain,
    prepared: Prepared,
    cancelled: &mut impl FnMut() -> bool,
    emit: &mut impl FnMut(&Value) -> Result<(), Failure>,
) -> Result<Value, Failure> {
    let overall = Instant::now() + Duration::from_mins(15);
    // Once sending begins, any transport failure is uncertain. The caller drops
    // the connection and returns interruption; there is no resend loop here.
    bounded(
        socket.send(Message::text(prepared.wire.clone())),
        Instant::now() + Duration::from_secs(10),
        cancelled,
    )
    .await?
    .map_err(|_| Failure::Io)?;
    let mut progress = Instant::now() + Duration::from_mins(2);
    let mut bytes = 0usize;
    let mut observed = false;
    for _ in 0..MAX_EVENTS {
        let message = bounded(socket.next(), overall.min(progress), cancelled)
            .await?
            .ok_or(Failure::Closed)?
            .map_err(|_| Failure::Io)?;
        bytes = bytes.saturating_add(message.len());
        if bytes > MAX_RESPONSE {
            return Err(Failure::Protocol);
        }
        match message {
            Message::Text(text) => {
                let value: Value = serde_json::from_str(&text).map_err(|_| Failure::Protocol)?;
                let kind = value
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or(Failure::Protocol)?;
                if kind == "error" {
                    let status = value.get("status").and_then(Value::as_u64);
                    if !observed && matches!(status, Some(429 | 503)) {
                        return Err(Failure::Rejected(
                            u16::try_from(status.ok_or(Failure::Protocol)?)
                                .map_err(|_| Failure::Protocol)?,
                        ));
                    }
                    return Err(Failure::Protocol);
                }
                if kind == "response.failed" || kind == "response.incomplete" {
                    return Err(Failure::Protocol);
                }
                if !kind.starts_with("response.") {
                    return Err(Failure::Protocol);
                }
                observed = true;
                progress = Instant::now() + Duration::from_mins(2);
                emit(&value)?;
                if kind == "response.completed" {
                    let response = value.get("response").cloned().ok_or(Failure::Protocol)?;
                    chain
                        .completed(prepared, &response)
                        .map_err(|_| Failure::Protocol)?;
                    return Ok(response);
                }
            }
            Message::Ping(_) => {
                bounded(
                    socket.flush(),
                    overall.min(Instant::now() + Duration::from_secs(10)),
                    cancelled,
                )
                .await?
                .map_err(|_| Failure::Io)?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => return Err(Failure::Closed),
            Message::Binary(_) | Message::Frame(_) => return Err(Failure::Protocol),
        }
    }
    Err(Failure::Protocol)
}
