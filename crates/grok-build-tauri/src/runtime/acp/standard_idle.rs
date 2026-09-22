//! Keeps the shared agent responsive between app turns without replaying work.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::{RuntimeCancelHandle, RuntimeEvent, RuntimeEventSink, process::AcpProcess};
use crate::runtime::cli_interactions::{CliAnswer, CliInteraction, CliInteractions};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdleSnapshot {
    pub(crate) run_id: String,
    cursor: u64,
    events: Vec<RuntimeEvent>,
    pending: Vec<CliInteraction>,
    truncated: bool,
}

#[derive(Default)]
struct Buffer {
    cursor: u64,
    bytes: usize,
    rows: VecDeque<(u64, usize, RuntimeEvent)>,
}

impl Buffer {
    fn push(&mut self, event: RuntimeEvent) -> Result<(), String> {
        if matches!(event, RuntimeEvent::UnsupportedProviderEvent { .. }) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&event).map_err(|e| e.to_string())?.len();
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or("CLI activity cursor exhausted.")?;
        self.bytes += bytes;
        self.rows.push_back((self.cursor, bytes, event));
        while self.rows.len() > 256 || self.bytes > 8 * 1024 * 1024 {
            if let Some((_, size, _)) = self.rows.pop_front() {
                self.bytes -= size;
            }
        }
        Ok(())
    }
}

pub(super) struct IdleAgent {
    run: String,
    control: Arc<AtomicU8>,
    buffer: Arc<Mutex<Buffer>>,
    interactions: CliInteractions,
    image_input: bool,
    worker: Option<std::thread::JoinHandle<Result<AcpProcess, String>>>,
}

impl IdleAgent {
    pub(super) fn start(mut process: AcpProcess, run: String) -> Result<Self, String> {
        let control = Arc::new(AtomicU8::new(0));
        let buffer = Arc::new(Mutex::new(Buffer::default()));
        let interactions = process.cancel.cli_interactions.clone();
        let mut cancel = RuntimeCancelHandle::new();
        cancel.cli_interactions = interactions.clone();
        process.cancel = cancel;
        let image_input = process
            .initialized
            .as_ref()
            .and_then(|value| value.pointer("/agentCapabilities/promptCapabilities/image"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let flag = Arc::clone(&control);
        let output = Arc::clone(&buffer);
        let worker = std::thread::Builder::new()
            .name("gbplus-cli-idle".into())
            .spawn(move || {
                let session = process.active_session_id.clone().unwrap_or_default();
                let events = |event| {
                    let event = match event {
                        RuntimeEvent::AssistantDelta(text) | RuntimeEvent::ThoughtDelta(text) => RuntimeEvent::CliUpdate {
                            session_id: session.clone(),
                            update: serde_json::json!({"sessionUpdate":"background_message","text":text}),
                        },
                        other => other,
                    };
                    output
                        .lock()
                        .map_err(|_| "CLI activity is unavailable.")?
                        .push(event)
                };
                while flag.load(Ordering::Acquire) == 0 {
                    if let Err(error) = process.pump_native_events(&events) {
                        events(RuntimeEvent::Error(error.clone()))?;
                        return Err(error);
                    }
                }
            if flag.load(Ordering::Acquire) == 2 {
                process.cancel.request_cancel()?;
                process.poll_native_answers(&events)?;
                process.terminate()?;
            }
                Ok(process)
            })
            .map_err(|e| format!("Cannot keep the CLI connection responsive: {e}"))?;
        Ok(Self {
            run,
            control,
            buffer,
            interactions,
            image_input,
            worker: Some(worker),
        })
    }

    pub(super) const fn image_input_supported(&self) -> bool {
        self.image_input
    }

    pub(super) fn matches_run(&self, run: &str) -> bool {
        self.run == run
    }

    pub(super) fn run_id(&self) -> &str {
        &self.run
    }

    pub(super) fn pending(&self) -> Result<Vec<CliInteraction>, String> {
        self.interactions.snapshot()
    }

    pub(super) fn snapshot(&self, after: u64) -> Result<IdleSnapshot, String> {
        let buffer = self
            .buffer
            .lock()
            .map_err(|_| "CLI activity is unavailable.")?;
        Ok(IdleSnapshot {
            run_id: self.run.clone(),
            cursor: buffer.cursor,
            events: buffer
                .rows
                .iter()
                .filter(|(n, _, _)| *n > after)
                .map(|(_, _, event)| event.clone())
                .collect(),
            pending: self.interactions.snapshot()?,
            truncated: buffer
                .rows
                .front()
                .is_some_and(|(n, _, _)| n.saturating_sub(1) > after),
        })
    }

    pub(super) fn answer(&self, id: u64, answer: CliAnswer) -> Result<(), String> {
        self.interactions.answer(id, answer)
    }

    pub(super) fn take(mut self) -> Result<AcpProcess, String> {
        self.control.store(1, Ordering::Release);
        self.join()
    }

    fn join(&mut self) -> Result<AcpProcess, String> {
        self.worker
            .take()
            .ok_or("CLI worker was already claimed.")?
            .join()
            .map_err(|_| "CLI background connection stopped unexpectedly.")?
    }

    pub(super) fn stop(mut self) -> Result<(), String> {
        self.control.store(2, Ordering::Release);
        drop(self.join()?);
        Ok(())
    }
}

impl Drop for IdleAgent {
    fn drop(&mut self) {
        if self.worker.is_some() {
            self.control.store(2, Ordering::Release);
            let _ = self.join();
        }
    }
}

impl AcpProcess {
    pub(super) fn pump_native_events(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        self.poll_native_answers(events)?;
        let Some(message) = self.receive_response_message(super::ACP_CANCEL_POLL)? else {
            return Ok(());
        };
        self.validate_response_frame(&message, &mut 0, 1)?;
        if super::protocol::internal_reload_observation(&message)? {
            return Ok(());
        }
        if let Some(method) = message["method"].as_str() {
            if message.get("id").is_some() {
                return self.handle_agent_request(&message, method, events);
            }
            self.observe_native_family(&message);
            return super::standard::notification(
                &message,
                method,
                self.active_session_id.as_deref(),
                events,
            );
        }
        Err("CLI sent an unexpected response while no app request was pending.".into())
    }
}
