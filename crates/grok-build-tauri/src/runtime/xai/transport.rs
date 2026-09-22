//! Explicit native protocol and shared stream event handling.
use super::{AtomicBool, Mutex, Ordering, RuntimeEvent, RuntimeEventSink, RuntimeUsage};
use crate::runtime::{
    cancel::RuntimeCancelHandle, keychain::XaiCredentialLease, native_protocol::NativeProtocol,
};
use grok_build_plus_host::{
    PlusHostError, PlusLiveChatRequest, PlusLiveStreamEvent, PlusLiveWebSocket,
    post_plus_live_chat_streaming,
};
#[derive(Default)]
pub(super) struct Connection {
    protocol: NativeProtocol,
    websocket: Option<PlusLiveWebSocket>,
}
impl Connection {
    pub(super) fn configure(&mut self, protocol: NativeProtocol) -> Result<(), String> {
        self.close().map_err(|error| error.to_string())?;
        self.protocol = protocol;
        Ok(())
    }
    pub(super) fn close(&mut self) -> Result<(), PlusHostError> {
        self.websocket
            .take()
            .map_or(Ok(()), |mut socket| socket.close())
    }
    fn send(
        &mut self,
        request: &PlusLiveChatRequest,
        cancelled: impl FnMut() -> bool,
        emit: impl FnMut(PlusLiveStreamEvent),
    ) -> Result<Vec<u8>, PlusHostError> {
        match self.protocol {
            NativeProtocol::Http => post_plus_live_chat_streaming(request, cancelled, emit),
            NativeProtocol::WebSocket => {
                if self.websocket.is_none() {
                    self.websocket = Some(PlusLiveWebSocket::new()?);
                }
                self.websocket
                    .as_mut()
                    .ok_or_else(|| {
                        PlusHostError::LiveSecurity("WebSocket owner unavailable.".into())
                    })?
                    .send(request, cancelled, emit)
            }
        }
    }
}
pub(super) struct StreamEvents<'a, 'b> {
    pub(super) events: &'a RuntimeEventSink<'b>,
    pub(super) saw_assistant_delta: &'a AtomicBool,
    pub(super) latest_usage: &'a Mutex<Option<RuntimeUsage>>,
    pub(super) event_error: &'a Mutex<Option<String>>,
}
pub(super) fn checked_transport(
    connection: &mut Connection,
    cancel: &RuntimeCancelHandle,
    credential: &XaiCredentialLease,
    request: &PlusLiveChatRequest,
    progress: &StreamEvents<'_, '_>,
) -> Result<Vec<u8>, PlusHostError> {
    let StreamEvents {
        events,
        saw_assistant_delta,
        latest_usage,
        event_error,
    } = progress;
    if let Err(error) = credential.ensure_active() {
        connection.close()?;
        return Err(PlusHostError::LiveSecurity(error));
    }
    if cancel.cancelled() {
        connection.close()?;
        return Err(PlusHostError::LiveCancelled);
    }
    let response = connection.send(
        request,
        || cancel.cancelled() || !credential.is_active(),
        |event| {
            let emitted = match event {
                PlusLiveStreamEvent::AssistantDelta(delta) => {
                    saw_assistant_delta.store(true, Ordering::Release);
                    events(RuntimeEvent::AssistantDelta(delta))
                }
                PlusLiveStreamEvent::ThoughtDelta(delta) => {
                    events(RuntimeEvent::ThoughtDelta(delta))
                }
                PlusLiveStreamEvent::Usage(usage) => {
                    let usage = RuntimeUsage {
                        input_tokens: usage.input_tokens,
                        output_tokens: usage.output_tokens,
                        thought_tokens: usage.reasoning_tokens,
                        cached_tokens: usage.cached_tokens,
                        context_used: None,
                        context_size: None,
                        cost_amount: None,
                        cost_currency: None,
                    };
                    if let Ok(mut latest) = latest_usage.lock() {
                        *latest = Some(usage.clone());
                    }
                    events(RuntimeEvent::Usage(usage))
                }
            };
            if let Err(error) = emitted {
                if let Ok(mut failure) = event_error.lock()
                    && failure.is_none()
                {
                    *failure = Some(error);
                }
                let _ = cancel.request_cancel();
            }
        },
    );
    if let Some(error) = event_error.lock().ok().and_then(|failure| failure.clone()) {
        connection.close()?;
        return Err(grok_build_plus_host::PlusHostError::LiveSecurity(format!(
            "Activity event persistence failed during xAI streaming: {error}"
        )));
    }
    let response = match response {
        Ok(body) => body,
        Err(error) => {
            connection.close()?;
            return Err(error);
        }
    };
    if cancel.cancelled() {
        connection.close()?;
        return Err(PlusHostError::LiveCancelled);
    }
    if let Err(error) = credential.ensure_active() {
        connection.close()?;
        return Err(PlusHostError::LiveSecurity(error));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_and_explicit_mode_selection_do_not_open_network_connections() {
        let mut connection = Connection::default();
        assert_eq!(connection.protocol, NativeProtocol::Http);
        assert!(connection.websocket.is_none());
        connection.configure(NativeProtocol::WebSocket).unwrap();
        assert!(connection.websocket.is_none());
        connection.close().unwrap();
        assert_eq!(
            connection.protocol,
            NativeProtocol::WebSocket,
            "Closing a socket cannot silently switch protocols"
        );
        connection.configure(NativeProtocol::Http).unwrap();
        assert!(connection.websocket.is_none());
    }
}
