//! The same truthful steering states apply to app-owned Grok children.
use super::{Deserialize, Journal, Path, Payload, RunId, Serialize};
use crate::contracts::SteerIntentId;
use crate::queue::SteerIntentState;
use crate::runtime::types::{RuntimeSteeringAction, RuntimeSteeringMessage};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Message {
    pub(super) id: SteerIntentId,
    pub(super) run: RunId,
    agent: RunId,
    pub(super) transient: bool,
    pub(super) text: Option<String>,
    delivery: SteerIntentState,
}
impl Journal {
    pub(super) fn validate_messages(&self) -> Result<(), String> {
        if self.messages.len() > 128 {
            return Err("Child guidance journal exceeds its bound.".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for message in &self.messages {
            if !ids.insert(&message.id)
                || message.id.as_str().len() > 256
                || message.id.as_str().is_empty()
                || message.id.as_str().chars().any(char::is_control)
                || !self.entries.iter().any(|entry| entry.run == message.run)
                || message
                    .text
                    .as_ref()
                    .is_some_and(|text| text.is_empty() || text.len() > 12_000)
                || (message.transient && message.text.is_some())
                || (!message.transient && message.text.is_none())
                || message.delivery == SteerIntentState::Consumed
            {
                return Err(
                    "Child guidance journal changed its scope, privacy or delivery contract."
                        .into(),
                );
            }
        }
        Ok(())
    }
    pub(in crate::collaboration) fn message(
        &mut self,
        state: &Path,
        child: &crate::queue::children::ChildRecord,
        identity: &str,
        text: String,
        transient: bool,
    ) -> Result<SteerIntentId, String> {
        if self.messages.len() >= 128 || text.is_empty() || text.len() > 12_000 {
            return Err("Child guidance exceeded its retained message bound.".into());
        }
        let before = self.clone();
        let id = SteerIntentId::new(format!("child-message-{identity}"));
        if self.messages.iter().any(|message| message.id == id) {
            return Err("Child guidance identity was repeated.".into());
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.run == child.id)
            .ok_or("Child guidance has no admitted result journal.")?;
        if !matches!(entry.payload, Payload::Available { .. }) {
            return Err("Child guidance context is unavailable.".into());
        }
        entry.transient |= transient;
        self.messages.push(Message {
            id: id.clone(),
            run: child.id.clone(),
            agent: child.agent_id.clone(),
            transient,
            text: Some(text),
            delivery: SteerIntentState::Pending,
        });
        self.save_or_restore(state, before)?;
        Ok(id)
    }
    pub(in crate::collaboration) fn steer(
        &mut self,
        state: &Path,
        run: &RunId,
        action: RuntimeSteeringAction,
    ) -> Result<Vec<RuntimeSteeringMessage>, String> {
        use SteerIntentState::{
            AcknowledgedByCli, ObservedInProviderHistory, Refused, Submitted, Uncertain,
        };
        if matches!(&action, RuntimeSteeringAction::SubmitPending)
            && !self
                .messages
                .iter()
                .any(|message| &message.run == run && message.delivery == SteerIntentState::Pending)
        {
            return Ok(Vec::new());
        }
        let before = self.clone();
        let mut result = Vec::new();
        match action {
            RuntimeSteeringAction::SubmitPending => {
                for message in self.messages.iter_mut().filter(|message| {
                    &message.run == run && message.delivery == SteerIntentState::Pending
                }) {
                    let text = message
                        .text
                        .clone()
                        .ok_or("Transient child guidance is unavailable.")?;
                    message.delivery = Submitted;
                    result.push(RuntimeSteeringMessage {
                        id: message.id.clone(),
                        text,
                        transient: message.transient,
                    });
                }
                if result.is_empty() {
                    return Ok(result);
                }
            }
            RuntimeSteeringAction::Record(id, next) => {
                let message = self
                    .messages
                    .iter_mut()
                    .find(|message| &message.run == run && message.id == id)
                    .ok_or("Child delivery does not belong to this invocation.")?;
                if message.delivery == next {
                    return Ok(result);
                }
                if !matches!(
                    (message.delivery, next),
                    (
                        Submitted,
                        AcknowledgedByCli | ObservedInProviderHistory | Refused | Uncertain
                    ) | (AcknowledgedByCli, ObservedInProviderHistory | Uncertain)
                        | (Uncertain, ObservedInProviderHistory)
                ) {
                    return Err("Child delivery would invent or regress provider evidence.".into());
                }
                message.delivery = next;
            }
        }
        self.save_or_restore(state, before)?;
        Ok(result)
    }
    pub(in crate::collaboration) fn finish_messages(
        &mut self,
        state: &Path,
        run: &RunId,
    ) -> Result<(), String> {
        let before = self.clone();
        let mut changed = false;
        for message in self
            .messages
            .iter_mut()
            .filter(|message| &message.run == run)
        {
            if matches!(
                message.delivery,
                SteerIntentState::Submitted | SteerIntentState::AcknowledgedByCli
            ) {
                message.delivery = SteerIntentState::Uncertain;
                changed = true;
            }
        }
        if changed {
            self.save_or_restore(state, before)?;
        }
        Ok(())
    }
    pub(in crate::collaboration) fn pending_guidance(
        &self,
        agent: &RunId,
    ) -> Result<(String, bool), String> {
        let mut text = String::new();
        let mut transient = false;
        for message in self.messages.iter().filter(|message| {
            &message.agent == agent && message.delivery == SteerIntentState::Pending
        }) {
            text.push_str("\n\nPreviously queued child guidance:\n");
            text.push_str(
                message
                    .text
                    .as_deref()
                    .ok_or("Queued transient guidance needs explicit reattachment.")?,
            );
            transient |= message.transient;
            if text.len() > 12_000 {
                return Err("Queued child guidance exceeds one bounded continuation.".into());
            }
        }
        Ok((text, transient))
    }
    pub(in crate::collaboration) fn promote_guidance(
        &mut self,
        state: &Path,
        agent: &RunId,
    ) -> Result<(), String> {
        let before = self.clone();
        let mut changed = false;
        for message in self.messages.iter_mut().filter(|message| {
            &message.agent == agent && message.delivery == SteerIntentState::Pending
        }) {
            message.delivery = SteerIntentState::PromotedToNext;
            changed = true;
        }
        if changed {
            self.save_or_restore(state, before)?;
        }
        Ok(())
    }
}
