//! Native app-tool loop using durable raw Responses items instead of text replay.

use grok_build_plus_host::{
    PLUS_MAX_TOOL_STEPS, PlusExternalToolExecutor, PlusHostError, PlusLiveChatRequest,
    PlusLiveIdentity, PlusSessionMode, PlusToolLifecycleEvent,
    encode_plus_live_conversation_request, plus_tool_request_from_name_and_args,
    run_plus_tool_loop_on_store_in_mode_observed_external,
};
use serde_json::Value;

use crate::contracts::ProviderSessionId;
use crate::queue::SteerIntentState;
use crate::runtime::types::{
    AdapterContext, AdapterTurn, AdapterTurnOutcome, RuntimeEvent, RuntimeEventSink,
    RuntimeSteeringAction, RuntimeSteeringSource,
};

use super::ResponsesJournal;

pub(crate) struct NativeTurn<'a> {
    pub(crate) prompt: &'a str,
    pub(crate) context: &'a AdapterContext<'a>,
    pub(crate) identity: &'a PlusLiveIdentity,
    pub(crate) external: Option<&'a dyn PlusExternalToolExecutor>,
    pub(crate) events: &'a RuntimeEventSink<'a>,
    pub(crate) steering: &'a RuntimeSteeringSource<'a>,
}

impl NativeTurn<'_> {
    #[cfg(test)]
    pub(crate) fn run(
        &self,
        journal: &mut ResponsesJournal,
        mut transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    ) -> Result<AdapterTurn, String> {
        self.run_compacting(journal, &mut transport, |_, _| {
            Err(PlusHostError::Live(
                "This transport has no compaction endpoint.".into(),
            ))
        })
    }

    pub(crate) fn run_compacting(
        &self,
        journal: &mut ResponsesJournal,
        mut transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
        mut compact: impl FnMut(&[Value], &str) -> Result<Value, PlusHostError>,
    ) -> Result<AdapterTurn, String> {
        let mut steps = Vec::new();
        let mut steering_ids = Vec::new();
        let mut rounds = 0;
        let mut calls = 0;
        let result: Result<String, String> = (|| loop {
            if rounds > PLUS_MAX_TOOL_STEPS {
                return Err("Native Responses tool loop reached its execution bound.".into());
            }
            if journal.needs_compaction()? {
                journal.request_intent()?;
                let response =
                    compact(journal.input(), journal.model()).map_err(|error| error.to_string())?;
                journal.complete_compaction(&response)?;
            }
            let mut request = encode_plus_live_conversation_request(
                journal.input(),
                journal.model(),
                journal.reasoning_effort(),
                self.identity,
            )
            .map_err(|error| error.to_string())?;
            super::super::extension_tools::append_to_request(&mut request, self.external)?;
            rounds += 1;
            let bytes = request_with_bounded_retry(journal, &request, &mut transport)?;
            let response: Value = serde_json::from_slice(&bytes)
                .map_err(|_| "Native Responses completion is not valid JSON.")?;
            let output = journal.complete_response(&response)?;
            for id in steering_ids.drain(..) {
                (self.steering)(RuntimeSteeringAction::Record(
                    id,
                    SteerIntentState::ObservedInProviderHistory,
                ))?;
            }
            let response_id = response["id"]
                .as_str()
                .ok_or("Validated response lost its identity.")?;
            let mut called = false;
            let mut assistant = String::new();
            for item in output {
                match item.get("type").and_then(Value::as_str) {
                    Some("function_call") => {
                        called = true;
                        if calls >= PLUS_MAX_TOOL_STEPS {
                            return Err("Native Responses app-tool step bound exceeded.".into());
                        }
                        calls += 1;
                        self.dispatch_call(journal, response_id, &item, &mut steps)?;
                    }
                    Some("message") => append_assistant(&mut assistant, &item)?,

                    _ => {}
                }
            }
            if !called {
                if assistant.trim().is_empty() {
                    return Err(
                        "Native Responses ended without assistant text or a tool call.".into(),
                    );
                }
                return Ok(assistant);
            }
            // Native steering is admitted only between completed tool effects
            // and the next request containing their exact function_call_outputs.
            for message in (self.steering)(RuntimeSteeringAction::SubmitPending)? {
                if message.transient {
                    journal.require_transient_context()?;
                }
                journal.append_steering(&message.text)?;
                steering_ids.push(message.id);
            }
        })();
        let (assistant, outcome) = match result {
            Ok(text) => (text, AdapterTurnOutcome::Completed),
            Err(reason) => {
                journal.interrupt()?;
                for id in steering_ids {
                    (self.steering)(RuntimeSteeringAction::Record(
                        id,
                        SteerIntentState::Uncertain,
                    ))?;
                }
                (
                    format!("Interrupted: {reason}"),
                    AdapterTurnOutcome::Failed(reason),
                )
            }
        };
        self.finish(journal, &steps, &assistant, outcome)
    }

    fn finish(
        &self,
        journal: &ResponsesJournal,
        steps: &[grok_build_plus_host::PlusToolStep],
        assistant: &str,
        outcome: AdapterTurnOutcome,
    ) -> Result<AdapterTurn, String> {
        // Raw Browser results and Desktop arguments are not copied into Chat.
        let summary = super::super::acp::tools::present_acp_tool_steps_for_persistence(steps);
        let assistant_text = if steps.is_empty() {
            format!(
                "Provider: live xAI (XaiKeychain)\nYou: {}\nAssistant: {assistant}",
                self.prompt
            )
        } else {
            format!(
                "Provider: live xAI (XaiKeychain)\nYou: {}\n{summary}\nAssistant: {assistant}",
                self.prompt
            )
        };
        // The family journal owns child results. A second app session store
        // must not persist temporary child guidance, tool text or proposals.
        if super::super::extension_tools::policy(self.external)
            == grok_build_plus_host::PlusRuntimeToolPolicy::Parent
        {
            self.context
                .store
                .append_chat_turn(&assistant_text)
                .map_err(|error| error.to_string())?;
        }
        Ok(AdapterTurn {
            assistant_text,
            pending: journal.pending(),
            provider_session_id: Some(ProviderSessionId::new(journal.context_id())),
            usage: None,
            outcome,
        })
    }
    fn dispatch_call(
        &self,
        journal: &mut ResponsesJournal,
        response_id: &str,
        item: &Value,
        steps: &mut Vec<grok_build_plus_host::PlusToolStep>,
    ) -> Result<(), String> {
        if journal.effect_intent(response_id, item)?.is_some() {
            return Ok(());
        }
        let name = item["name"]
            .as_str()
            .ok_or("Validated tool lost its name.")?;
        let arguments = item["arguments"]
            .as_str()
            .ok_or("Validated tool lost its arguments.")?;
        if let Some(reason) = super::super::extension_tools::policy(self.external).refusal(name) {
            let output = super::super::extension_tools::role_refusal(name, reason, self.events)?;
            journal.complete_effect(
                response_id,
                item,
                &output.to_string(),
                grok_build_plus_host::PendingFileSet::default(),
            )?;
            return Ok(());
        }
        if let Some(hooks) = &self.context.hooks {
            let arguments: Value = serde_json::from_str(arguments)
                .map_err(|_| "Tool arguments are malformed before hook review.")?;
            if let crate::extensions::hooks::HookGateDecision::Refuse(reason) =
                hooks.before_tool(&self.context.scope, name, &arguments)?
            {
                let output =
                    super::super::extension_tools::hook_refusal(name, &reason, self.events)?;
                journal.complete_effect(
                    response_id,
                    item,
                    &output.to_string(),
                    grok_build_plus_host::PendingFileSet::default(),
                )?;
                return Ok(());
            }
        }
        if grok_build_plus_host::PlusCollaborationCommand::recognizes(name) {
            if super::super::collaboration_tools::binding(self.external)?.as_deref()
                != Some(self.context.scope.run_id.as_str())
            {
                return Err(
                    "Native collaboration authority belongs to a different app run.".into(),
                );
            }
            let arguments: Value = serde_json::from_str(arguments)
                .map_err(|_| "Collaboration arguments are malformed.")?;
            let invocation = serde_json::json!([response_id, item["call_id"]]).to_string();
            let output = super::super::collaboration_tools::execute(
                self.external,
                &invocation,
                name,
                &arguments,
                journal.context_is_transient(),
                self.events,
            )?;
            journal.complete_effect(
                response_id,
                item,
                &output.to_string(),
                grok_build_plus_host::PendingFileSet::default(),
            )?;
            return Ok(());
        }
        if name.starts_with("gbext_") {
            let arguments: Value = serde_json::from_str(arguments)
                .map_err(|_| "Extension arguments are not a JSON object.")?;
            let invocation = serde_json::json!([response_id, item["call_id"]]).to_string();
            let output = super::super::extension_tools::execute(
                self.external,
                &invocation,
                name,
                &arguments,
                self.events,
            )?;
            journal.complete_effect(
                response_id,
                item,
                &output.to_string(),
                grok_build_plus_host::PendingFileSet::default(),
            )?;
            return Ok(());
        }
        let request = plus_tool_request_from_name_and_args(name, arguments)
            .map_err(|error| error.to_string())?;
        let mut observer = |event| (self.events)(tool_event(event)).map_err(PlusHostError::Live);
        let report = run_plus_tool_loop_on_store_in_mode_observed_external(
            self.context.bound,
            Some(self.context.store),
            &[request],
            PlusSessionMode::Agent,
            &mut observer,
            self.external,
        )
        .map_err(|error| error.to_string())?;
        let step = report.steps.first().ok_or("App tool returned no result.")?;
        journal.complete_effect(response_id, item, &step.result, report.pending_set)?;
        steps.extend(report.steps);
        Ok(())
    }
}

fn tool_event(event: PlusToolLifecycleEvent) -> RuntimeEvent {
    match event {
        PlusToolLifecycleEvent::Requested { name } => RuntimeEvent::ToolRequest {
            name,
            detail: "App-owned tool invocation durably recorded before dispatch.".into(),
        },
        PlusToolLifecycleEvent::Completed { name } => RuntimeEvent::ToolCompleted {
            name,
            detail: "App-owned tool completed through its existing policy boundary.".into(),
        },
        PlusToolLifecycleEvent::Refused { name } => RuntimeEvent::ToolRefused {
            name,
            reason: "App-owned tool refused or failed through its existing policy boundary.".into(),
        },
    }
}

fn request_with_bounded_retry(
    journal: &mut ResponsesJournal,
    request: &PlusLiveChatRequest,
    transport: &mut impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
) -> Result<Vec<u8>, String> {
    for attempt in 0..3 {
        journal.request_intent()?;
        match transport(request) {
            Ok(bytes) => return Ok(bytes),
            Err(PlusHostError::LiveHttp {
                status: status @ (429 | 503),
            }) if attempt < 2 => {
                journal.rejected_request(status)?;
                std::thread::sleep(std::time::Duration::from_millis(250 << attempt));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("Responses retry bound exhausted.".into())
}

fn append_assistant(assistant: &mut String, item: &Value) -> Result<(), String> {
    if item["role"] != "assistant"
        || item
            .get("status")
            .is_some_and(|status| status != "completed")
    {
        return Err("Provider assistant message has an invalid role or incomplete status.".into());
    }
    if let Some(content) = item.get("content").and_then(Value::as_array) {
        for part in content {
            if part.get("type").and_then(Value::as_str) == Some("output_text") {
                assistant.push_str(
                    part.get("text")
                        .and_then(Value::as_str)
                        .ok_or("Provider output text is malformed.")?,
                );
            }
        }
    }

    Ok(())
}
