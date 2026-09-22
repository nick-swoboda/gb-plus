//! Shared CLI launch and idle-agent ownership for standard mode.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::standard_idle::IdleAgent;
pub(crate) use super::standard_idle::IdleSnapshot;
use super::{RuntimeEvent, RuntimeEventSink, process::AcpProcess};

#[derive(Clone, Debug)]
pub(crate) struct StandardLaunch {
    pub(crate) home: PathBuf,
    pub(crate) cwd: PathBuf,
    pub(crate) developer: bool,
    pub(crate) permission: crate::runtime::cli_permissions::CliPermissionMode,
    pub(crate) lease: Option<StandardLease>,
}

#[derive(Clone, Default)]
pub(crate) struct StandardAgentPool(Arc<Mutex<PoolState>>);

#[derive(Default)]
struct PoolState {
    generation: u64,
    parked: Option<(PathBuf, IdleAgent)>,
}

#[derive(Clone)]
pub(crate) struct StandardLease {
    pool: StandardAgentPool,
    key: PathBuf,
    generation: u64,
}

impl std::fmt::Debug for StandardLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandardLease")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl StandardAgentPool {
    pub(crate) fn image_input_supported(&self) -> bool {
        self.0.lock().is_ok_and(|pool| {
            pool.parked
                .as_ref()
                .is_some_and(|(_, agent)| agent.image_input_supported())
        })
    }

    pub(crate) fn lease(&self, key: &Path) -> Result<StandardLease, String> {
        Ok(StandardLease {
            pool: self.clone(),
            key: key.to_owned(),
            generation: self
                .0
                .lock()
                .map_err(|_| "CLI agent ownership is unavailable.")?
                .generation,
        })
    }

    pub(crate) fn clear(&self) -> Result<(), String> {
        let parked = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| "CLI agent ownership is unavailable.")?;
            state.generation = state
                .generation
                .checked_add(1)
                .ok_or("CLI agent generation exhausted.")?;
            state.parked.take()
        };
        parked.map_or(Ok(()), |(_, agent)| agent.stop())
    }

    pub(crate) fn idle_snapshot(
        &self,
        key: &Path,
        after: u64,
        run: Option<&str>,
    ) -> Result<Option<IdleSnapshot>, String> {
        let state = self
            .0
            .lock()
            .map_err(|_| "CLI agent ownership is unavailable.")?;
        state
            .parked
            .as_ref()
            .filter(|(owned, _)| owned == key)
            .map(|(_, agent)| {
                agent.snapshot(if run.is_some_and(|id| agent.matches_run(id)) {
                    after
                } else {
                    0
                })
            })
            .transpose()
    }

    pub(crate) fn answer_idle(
        &self,
        key: &Path,
        run: &str,
        id: u64,
        answer: crate::runtime::cli_interactions::CliAnswer,
    ) -> Result<(), String> {
        let state = self
            .0
            .lock()
            .map_err(|_| "CLI agent ownership is unavailable.")?;
        let (_, agent) = state
            .parked
            .as_ref()
            .filter(|(owned, agent)| owned == key && agent.matches_run(run))
            .ok_or("This background CLI request is no longer active in the selected chat.")?;
        agent.answer(id, answer)
    }

    pub(crate) fn stop_idle(&self, key: &Path, run: &str) -> Result<(), String> {
        let agent = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| "CLI agent ownership is unavailable.")?;
            if !state
                .parked
                .as_ref()
                .is_some_and(|(owned, agent)| owned == key && agent.matches_run(run))
            {
                return Err("The background CLI connection changed before Stop.".into());
            }
            state.parked.take().ok_or("CLI connection disappeared.")?.1
        };
        agent.stop()
    }
}

impl StandardLease {
    pub(super) fn take(&self) -> Result<Option<AcpProcess>, String> {
        let parked = {
            let mut state = self
                .pool
                .0
                .lock()
                .map_err(|_| "CLI agent ownership is unavailable.")?;
            if state.generation != self.generation {
                return Err("The active CLI engine changed before this run started.".into());
            }
            if state
                .parked
                .as_ref()
                .is_some_and(|(key, _)| key == &self.key)
                && !state
                    .parked
                    .as_ref()
                    .ok_or("CLI connection disappeared.")?
                    .1
                    .pending()?
                    .is_empty()
            {
                return Err(
                    "Answer or stop the background CLI request before sending another message."
                        .into(),
                );
            }
            state.parked.take()
        };
        if let Some((key, agent)) = parked {
            if key == self.key {
                let run = agent.run_id().to_owned();
                let Ok(process) = agent.take() else {
                    return Ok(None);
                };
                if !process.cancel.cli_interactions.snapshot()?.is_empty() {
                    self.park(process, run)?;
                    return Err("The CLI asked a background question during handoff. Answer it before sending another message.".into());
                }
                return Ok(Some(process));
            }
            agent.stop()?;
        }
        Ok(None)
    }

    pub(super) fn park(&self, process: AcpProcess, run: String) -> Result<(), String> {
        let agent = IdleAgent::start(process, run)?;
        let previous = {
            let mut state = self
                .pool
                .0
                .lock()
                .map_err(|_| "CLI agent ownership is unavailable.")?;
            if state.generation != self.generation {
                drop(state);
                drop(agent);
                return Ok(());
            }
            state.parked.replace((self.key.clone(), agent))
        };
        drop(previous);
        Ok(())
    }
}

pub(super) fn notification(
    message: &Value,
    method: &str,
    active: Option<&str>,
    events: &RuntimeEventSink<'_>,
) -> Result<(), String> {
    if super::native_ui::observation(message, active, events)? {
        return Ok(());
    }
    if let (Some(active), Some(observed)) = (
        active,
        message.pointer("/params/sessionId").and_then(Value::as_str),
    ) && active != observed
    {
        return events(RuntimeEvent::UnsupportedProviderEvent {
            provider: "Grok CLI".into(),
            discriminator: "other_session_update".into(),
            byte_count: serde_json::to_vec(message)
                .map_err(|e| e.to_string())?
                .len(),
        });
    }
    if method == "session/update" {
        if active.is_some() {
            super::protocol::validate_active_session(message, active, "session update")?;
        }
        return AcpProcess::handle_session_update(message, events);
    }
    if matches!(
        method,
        "_x.ai/session_notification" | "_x.ai/session/update"
    ) {
        let kind = message
            .pointer("/params/update/sessionUpdate")
            .and_then(Value::as_str);
        if matches!(kind, Some("usage_update" | "context_usage_update")) {
            return super::protocol::emit_acp_context_usage(&message["params"]["update"], events);
        }
    }
    // Extensions grow independently of the app. Notifications cannot authorize effects.
    events(RuntimeEvent::UnsupportedProviderEvent {
        provider: "Grok CLI".into(),
        discriminator: super::protocol::bounded_event_discriminator(method),
        byte_count: serde_json::to_vec(message)
            .map_err(|e| e.to_string())?
            .len(),
    })
}

pub(super) fn confirm_idle(
    process: &mut AcpProcess,
    session: &str,
    events: &RuntimeEventSink<'_>,
) -> Result<(), String> {
    loop {
        if session_idle(process, session, events)? {
            return Ok(());
        }
        let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < until {
            if process.cancel.cancelled() {
                process.terminate()?;
                return Err("CLI continuation was stopped; it will not be replayed.".into());
            }
            process.pump_native_events(events)?;
        }
    }
}

fn session_idle(
    process: &mut AcpProcess,
    session: &str,
    events: &RuntimeEventSink<'_>,
) -> Result<bool, String> {
    let roster = process.request("_x.ai/sessions/list", &json!({}), events)?;
    let rows = roster
        .get("sessions")
        .and_then(Value::as_array)
        .ok_or("CLI did not report its session state.")?;
    let row = rows
        .iter()
        .find(|row| row.get("sessionId").and_then(Value::as_str) == Some(session))
        .ok_or("CLI session disappeared before idle confirmation.")?;
    if row.get("cwd").and_then(Value::as_str) != process.neutral_cwd.to_str() {
        return Err("The CLI session moved to another workspace before idle confirmation.".into());
    }
    match row.get("activity").and_then(Value::as_str) {
        Some("idle") => Ok(true),
        Some("working" | "needs_input") => Ok(false),
        _ => Err("CLI did not confirm a live resumable session state.".into()),
    }
}

fn settle_prompt(
    process: &mut AcpProcess,
    session: &str,
    text: String,
    events: &RuntimeEventSink<'_>,
) -> Result<String, String> {
    let output = Mutex::new(text);
    confirm_idle(process, session, &|event| {
        if let RuntimeEvent::AssistantDelta(text) = &event {
            let mut output = output
                .lock()
                .map_err(|_| "CLI continuation output is unavailable.")?;
            if output.len().saturating_add(text.len()) > super::ACP_MAX_ASSISTANT_BYTES {
                return Err("CLI continuation exceeded the reply display limit.".into());
            }
            output.push_str(text);
        }
        events(event)
    })?;
    output
        .into_inner()
        .map_err(|_| "CLI continuation output is unavailable.".into())
}

impl super::GrokCliAcpAdapter {
    pub(super) fn send_standard_turn(
        &mut self,
        context: &super::AdapterContext<'_>,
        input: &str,
        image: Option<&super::AdapterImage<'_>>,
        steering: &super::RuntimeSteeringSource<'_>,
        events: &RuntimeEventSink<'_>,
        session: &str,
    ) -> Result<super::AdapterTurn, super::AdapterFailure> {
        if let Some(process) = &self.process {
            process.emit_native_session_options(session, events)?;
        }
        let prompted = self.prompt(input, image, events, Some(steering));
        let mut process = self
            .process
            .take()
            .ok_or_else(|| super::AdapterFailure::protocol("The CLI process is unavailable."))?;
        let settled =
            prompted.and_then(|(_, text)| settle_prompt(&mut process, session, text, events));
        let assistant = match settled {
            Ok(text) => text,
            Err(reason) => {
                process.terminate()?;
                return Err(super::AdapterFailure::from(reason));
            }
        };
        let steps = std::mem::take(&mut process.app_tools.steps);
        let pending = std::mem::take(&mut process.app_tools.pending);
        process.app_tools.revoke();
        let turn = super::tools::finish_acp_app_tool_turn(
            context,
            Some(crate::contracts::ProviderSessionId::new(session)),
            &steps,
            pending,
            Some(assistant),
            None,
            true,
        )?;
        if let Some(lease) = self
            .config
            .standard
            .as_ref()
            .and_then(|launch| launch.lease.as_ref())
        {
            process.release_idle_turn()?;
            lease.park(process, context.scope.run_id.as_str().into())?;
        } else {
            process.terminate()?;
        }
        self.session_id = None;
        Ok(turn)
    }
}
