//! Interjection correlation and terminal reconciliation under the app run lease.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::queue::SteerIntentState;
use crate::runtime::types::{RuntimeSteeringAction, RuntimeSteeringMessage, RuntimeSteeringSource};

use super::process::AcpProcess;

struct Delivery {
    message: RuntimeSteeringMessage,
    state: SteerIntentState,
    terminal: bool,
}

enum Control {
    Interject(usize),
    History,
    Roster,
}

pub(super) struct SteeringPump<'a> {
    source: &'a RuntimeSteeringSource<'a>,
    session_id: String,
    deliveries: Vec<Delivery>,
    requests: BTreeMap<u64, (Control, Instant)>,
    last_reconcile: Option<Instant>,
    idle: bool,
    request_count: usize,
}

impl<'a> SteeringPump<'a> {
    pub(super) fn pause_for_app_tool(&mut self, elapsed: Duration) {
        for (_, sent) in self.requests.values_mut() {
            *sent += elapsed;
        }
        if let Some(last) = &mut self.last_reconcile {
            *last += elapsed;
        }
    }

    pub(super) fn new(source: &'a RuntimeSteeringSource<'a>, session_id: String) -> Self {
        Self {
            source,
            session_id,
            deliveries: Vec::new(),
            requests: BTreeMap::new(),
            last_reconcile: None,
            idle: false,
            request_count: 0,
        }
    }

    pub(super) fn poll(&mut self, process: &mut AcpProcess, terminal: bool) -> Result<(), String> {
        if self
            .requests
            .values()
            .any(|(_, sent)| sent.elapsed() > Duration::from_secs(30))
        {
            return Err(
                "ACP steering control request timed out; delivery remains uncertain.".into(),
            );
        }
        if !terminal {
            for message in (self.source)(RuntimeSteeringAction::SubmitPending)? {
                process.app_tools.transient |= message.transient;
                if self.deliveries.len() >= 128 {
                    return Err("ACP interjection count exceeded this execution's bound.".into());
                }
                let params = json!({"sessionId":self.session_id, "interjectionId":message.id,
                    "text":steering_text(&message)});
                let index = self.deliveries.len();
                self.deliveries.push(Delivery {
                    message,
                    state: SteerIntentState::Submitted,
                    terminal: false,
                });
                self.send(
                    process,
                    "_x.ai/interject",
                    &params,
                    Control::Interject(index),
                )?;
            }
        } else if !self.deliveries.is_empty()
            && self.requests.is_empty()
            && self
                .last_reconcile
                .is_none_or(|last| last.elapsed() >= Duration::from_millis(500))
        {
            self.send(
                process,
                "_x.ai/session/updates",
                &json!({
                    "sessionId":self.session_id,"cwd":process.neutral_cwd,"offset":-512,"limit":512
                }),
                Control::History,
            )?;
            self.send(process, "_x.ai/sessions/list", &json!({}), Control::Roster)?;
            self.last_reconcile = Some(Instant::now());
        }
        Ok(())
    }

    fn send(
        &mut self,
        process: &mut AcpProcess,
        method: &str,
        params: &Value,
        control: Control,
    ) -> Result<(), String> {
        if self.request_count >= 512 {
            return Err("ACP steering reconciliation exceeded its request bound.".into());
        }
        let id = process.next_id;
        process.next_id = id.checked_add(1).ok_or("ACP request identity exhausted.")?;
        self.requests.insert(id, (control, Instant::now()));
        self.request_count += 1;
        process.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
    }

    pub(super) fn response(
        &mut self,
        message: &Value,
        cwd: &std::path::Path,
    ) -> Result<bool, String> {
        let Some(id) = message.get("id").and_then(Value::as_u64) else {
            return Ok(false);
        };
        let Some((control, _)) = self.requests.remove(&id) else {
            return Ok(false);
        };
        if message.get("error").is_some() {
            if let Control::Interject(index) = control {
                // Only invalid-params/method-not-found are definitively rejected.
                // An internal error may follow delivery, so keep it uncertain.
                if matches!(
                    message.pointer("/error/code").and_then(Value::as_i64),
                    Some(-32601 | -32602)
                ) {
                    let delivery = &mut self.deliveries[index];
                    (self.source)(RuntimeSteeringAction::Record(
                        delivery.message.id.clone(),
                        SteerIntentState::Refused,
                    ))?;
                    delivery.state = SteerIntentState::Refused;
                    return Ok(true);
                }
            }
            return Err(
                "ACP could not reconcile the submitted message; delivery remains uncertain.".into(),
            );
        }
        let result = message
            .get("result")
            .ok_or("ACP control response has no result.")?;
        let result = super::protocol::extension_result(
            match control {
                Control::Interject(_) => "_x.ai/interject",
                Control::Roster => "_x.ai/sessions/list",
                Control::History => "_x.ai/session/updates",
            },
            result,
        )?;
        match control {
            Control::Interject(index) => {
                if result.get("status").and_then(Value::as_str) != Some("queued") {
                    return Err("ACP returned an unknown interjection delivery status.".into());
                }
                let delivery = &mut self.deliveries[index];
                (self.source)(RuntimeSteeringAction::Record(
                    delivery.message.id.clone(),
                    SteerIntentState::AcknowledgedByCli,
                ))?;
                delivery.state = SteerIntentState::AcknowledgedByCli;
            }
            Control::History => self.history(result)?,
            Control::Roster => {
                let sessions = result
                    .get("sessions")
                    .and_then(Value::as_array)
                    .ok_or("ACP roster has no sessions.")?;
                if sessions.len() > 128 {
                    return Err("ACP roster exceeded its bound.".into());
                }
                let current = sessions
                    .iter()
                    .find(|session| {
                        session.get("sessionId").and_then(Value::as_str) == Some(&self.session_id)
                    })
                    .ok_or("ACP roster lost the executing session.")?;
                if current.get("cwd").and_then(Value::as_str) != cwd.to_str()
                    || current.get("yolo") == Some(&Value::Bool(true))
                {
                    return Err("ACP roster changed this run's authority.".into());
                }
                self.idle = current.get("activity").and_then(Value::as_str) == Some("idle");
            }
        }
        Ok(true)
    }

    fn history(&mut self, result: &Value) -> Result<(), String> {
        let updates = result
            .get("updates")
            .and_then(Value::as_array)
            .filter(|rows| rows.len() <= 512)
            .ok_or("ACP history response has invalid bounds.")?;
        for delivery in &mut self.deliveries {
            if delivery.state == SteerIntentState::Refused {
                continue;
            }
            let text = steering_text(&delivery.message);
            let position = updates.iter().position(|row| {
                row.get("method").and_then(Value::as_str) == Some("session/update")
                    && row.pointer("/params/sessionId").and_then(Value::as_str)
                        == Some(&self.session_id)
                    && row
                        .pointer("/params/update/sessionUpdate")
                        .and_then(Value::as_str)
                        == Some("user_message_chunk")
                    && (row
                        .pointer("/params/update/content/_meta/displayText")
                        .and_then(Value::as_str)
                        == Some(&text)
                        || row
                            .pointer("/params/update/content/text")
                            .and_then(Value::as_str)
                            == Some(&text))
            });
            if let Some(position) = position {
                if delivery.state != SteerIntentState::ObservedInProviderHistory {
                    (self.source)(RuntimeSteeringAction::Record(
                        delivery.message.id.clone(),
                        SteerIntentState::ObservedInProviderHistory,
                    ))?;
                    delivery.state = SteerIntentState::ObservedInProviderHistory;
                }
                delivery.terminal |= updates.iter().skip(position + 1).any(|row| {
                    row.get("method").and_then(Value::as_str) == Some("_x.ai/session/update")
                        && row.pointer("/params/sessionId").and_then(Value::as_str)
                            == Some(&self.session_id)
                        && row
                            .pointer("/params/update/sessionUpdate")
                            .and_then(Value::as_str)
                            == Some("turn_completed")
                });
            }
        }
        Ok(())
    }

    pub(super) fn settled(&self) -> bool {
        self.deliveries.is_empty()
            || (self.requests.is_empty()
                && (self.idle
                    || self
                        .deliveries
                        .iter()
                        .all(|delivery| delivery.state == SteerIntentState::Refused))
                && self.deliveries.iter().all(|delivery| {
                    delivery.state == SteerIntentState::Refused
                        || (delivery.state == SteerIntentState::ObservedInProviderHistory
                            && delivery.terminal)
                }))
    }
}

fn steering_text(message: &RuntimeSteeringMessage) -> String {
    format!(
        "GB Plus steering [{}]:\n{}",
        message.id.as_str(),
        message.text
    )
}
