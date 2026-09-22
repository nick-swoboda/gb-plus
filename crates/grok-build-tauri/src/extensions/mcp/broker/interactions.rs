//! Independent peer UI handling while the model's tool call waits for a result.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use grok_build_plus_host::McpEvent;
use serde_json::json;

use super::super::elicitation::{Context, Elicitations};
use super::super::{connection::Connection, service::ServiceAdmission};
use crate::runtime::cancel::RuntimeCancelHandle;

pub(super) struct CallScope {
    pub(super) connection: Arc<Connection>,
    responder: tauri::async_runtime::JoinHandle<()>,
    listener: Option<tauri::async_runtime::JoinHandle<()>>,
    admitted: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    context: Context,
    elicitations: Elicitations,
}

impl CallScope {
    pub(super) async fn new(
        context: Context,
        elicitations: Elicitations,
        cancelled: Arc<AtomicBool>,
        admission: Option<Arc<ServiceAdmission>>,
        authorization: Option<Arc<grok_build_plus_host::McpBearerAuthorization>>,
        cancel: RuntimeCancelHandle,
    ) -> Result<Self, String> {
        let (connection, mut observations) =
            Connection::open(&context.endpoint, admission, authorization, cancel).await?;
        let admitted = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicBool::new(false));
        let handler = PeerHandler {
            connection: Arc::clone(&connection),
            admitted: Arc::clone(&admitted),
            closed: Arc::clone(&closed),
            cancelled,
            context: context.clone(),
            elicitations: elicitations.clone(),
        };
        let responder = tauri::async_runtime::spawn(async move {
            while let Some(event) = observations.recv().await {
                handler.receive(event);
            }
        });
        Ok(Self {
            connection,
            responder,
            listener: None,
            admitted,
            closed,
            context,
            elicitations,
        })
    }

    pub(super) fn listen(&mut self, cancelled: Arc<AtomicBool>) {
        let connection = Arc::clone(&self.connection);
        self.listener = Some(tauri::async_runtime::spawn(async move {
            if connection.listen(&cancelled).await.is_err() {
                connection.interrupt();
            }
        }));
    }

    pub(super) fn admit(&self) {
        self.admitted.store(true, Ordering::Release);
    }

    pub(super) async fn finish(&self) -> Result<(), String> {
        self.closed.store(true, Ordering::Release);
        self.elicitations
            .cancel_connection(&self.context.connection);
        self.connection.finish().await
    }
}

impl Drop for CallScope {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.elicitations
            .cancel_connection(&self.context.connection);
        self.connection.interrupt();
        self.responder.abort();
        if let Some(listener) = &self.listener {
            listener.abort();
        }
    }
}

struct PeerHandler {
    connection: Arc<Connection>,
    admitted: Arc<AtomicBool>,
    closed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    context: Context,
    elicitations: Elicitations,
}

impl PeerHandler {
    fn receive(&self, event: McpEvent) {
        match event {
            McpEvent::ElicitationCancelled(peer) => self
                .elicitations
                .cancel_peer(&self.context.connection, &peer),
            McpEvent::Elicitation { identity, params } => {
                let ticket = if self.admitted.load(Ordering::Acquire)
                    && !self.closed.load(Ordering::Acquire)
                {
                    self.elicitations
                        .begin(self.context.clone(), identity.clone(), &params)
                        .ok()
                } else {
                    None
                };
                let Some(ticket) = ticket else {
                    // Catalog reads cannot collect input. Unsupported form
                    // constraints cancel this interaction, not invent a user answer.
                    let _ = self
                        .connection
                        .answer_elicitation(&identity, &json!({"action":"cancel"}));
                    return;
                };
                let connection = Arc::clone(&self.connection);
                let cancelled = Arc::clone(&self.cancelled);
                let closed = Arc::clone(&self.closed);
                // Eight tickets globally bound these waiting workers. Closing
                // the scope removes their tickets and wakes them immediately.
                let _worker = tauri::async_runtime::spawn_blocking(move || {
                    if let Ok(answer) = ticket.wait(|| {
                        cancelled.load(Ordering::Acquire) || closed.load(Ordering::Acquire)
                    }) && !cancelled.load(Ordering::Acquire)
                        && !closed.load(Ordering::Acquire)
                        && connection.answer_elicitation(&identity, &answer).is_err()
                    {
                        connection.interrupt();
                    }
                });
            }
            _ => {}
        }
    }
}
