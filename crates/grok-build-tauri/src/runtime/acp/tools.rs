//! App-owned tool continuation and authoritative result presentation.

#[cfg(test)]
use super::{
    ACP_APP_TOOL_RESULTS_HEADING, PlusHostError, PlusToolRequest, json, parse_plus_live_tool_reply,
};
use super::{
    AdapterContext, AdapterFailure, AdapterFailureKind, AdapterTurn, AdapterTurnOutcome,
    PendingFileSet, PlusToolLifecycleEvent, PlusToolStep, ProviderSessionId, RuntimeEvent,
    present_plus_tool_steps,
};

pub(super) fn acp_tool_runtime_event(event: PlusToolLifecycleEvent) -> RuntimeEvent {
    match event {
        PlusToolLifecycleEvent::Requested { name } => RuntimeEvent::ToolRequest {
            name,
            detail: "ACP reverse MCP request accepted by the app-owned dispatcher.".into(),
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

#[cfg(test)]
pub(super) enum AcpAppToolReply {
    CompletedResultEcho,
    FinalAssistant,
    Requests(Vec<PlusToolRequest>),
}

#[cfg(test)]
pub(super) fn acp_app_tool_results_envelope(steps: &[PlusToolStep]) -> String {
    let results = steps
        .iter()
        .map(|step| {
            json!({
                "name": step.name.as_str(),
                "status": if step.ok { "completed" } else { "failed" },
                "requestSummary": step.request,
                "result": step.result,
            })
        })
        .collect::<Vec<_>>();
    json!({ "completedAppToolResults": results }).to_string()
}

#[cfg(test)]
pub(super) fn compose_acp_app_tool_follow_up(steps: &[PlusToolStep]) -> String {
    format!(
        "{ACP_APP_TOOL_RESULTS_HEADING}\n{}\n\nThe JSON object above contains completed results, not tool requests. Continue the original turn from those exact results. Reply in prose without a `tool` or `plus_tool` prefix unless requesting a genuinely new app action. Do not repeat a completed tool request. A staged proposal is not written; tell the user that Review and Accept are still required.",
        acp_app_tool_results_envelope(steps)
    )
}

#[cfg(test)]
pub(super) fn exact_completed_app_tool_result_echo(text: &str, steps: &[PlusToolStep]) -> bool {
    if steps.is_empty() {
        return false;
    }
    let actual = text.trim();
    let presentation = present_plus_tool_steps(steps);
    if actual == presentation.trim() {
        return true;
    }
    let envelope = acp_app_tool_results_envelope(steps);
    actual == envelope || actual == format!("{ACP_APP_TOOL_RESULTS_HEADING}\n{envelope}")
}

#[cfg(test)]
pub(super) fn classify_acp_app_tool_reply(
    text: &str,
    steps: &[PlusToolStep],
) -> Result<AcpAppToolReply, PlusHostError> {
    if exact_completed_app_tool_result_echo(text, steps) {
        return Ok(AcpAppToolReply::CompletedResultEcho);
    }
    let requests = parse_plus_live_tool_reply(text, &[])?;
    if requests.is_empty() {
        Ok(AcpAppToolReply::FinalAssistant)
    } else {
        Ok(AcpAppToolReply::Requests(requests))
    }
}

pub(crate) fn present_acp_tool_steps_for_persistence(steps: &[PlusToolStep]) -> String {
    let bounded = steps
        .iter()
        .map(|step| {
            if step.name.is_browser() {
                let mut step = step.clone();
                step.result = if step.ok {
                    "Browser result delivered transiently to the live model; page content is omitted from persisted Chat."
                        .into()
                } else {
                    "Browser action refused; page content is omitted from persisted Chat.".into()
                };
                step
            } else {
                step.clone()
            }
        })
        .collect::<Vec<_>>();
    present_plus_tool_steps(&bounded)
}

pub(super) fn finish_acp_app_tool_turn(
    context: &AdapterContext<'_>,
    provider_session_id: Option<ProviderSessionId>,
    steps: &[PlusToolStep],
    pending: PendingFileSet,
    final_assistant: Option<String>,
    failure: Option<String>,
    persist_transcript: bool,
) -> Result<AdapterTurn, String> {
    let assistant_text = if steps.is_empty() && failure.is_none() {
        present_acp_assistant_boundary(&final_assistant.unwrap_or_default())
    } else {
        let terminal = match (&final_assistant, &failure) {
            (Some(assistant), None) => assistant.trim().to_owned(),
            (_, Some(reason)) => format!("Stopped honestly: {reason}"),
            (None, None) => "Stopped honestly without a final assistant response.".into(),
        };
        if steps.is_empty() {
            present_acp_assistant_boundary(&terminal)
        } else {
            format!(
                "{}\n{}",
                present_acp_tool_steps_for_persistence(steps),
                present_acp_assistant_boundary(&terminal)
            )
        }
    };
    if persist_transcript {
        context
            .store
            .append_chat_turn(&assistant_text)
            .map_err(|error| error.to_string())?;
    }
    Ok(AdapterTurn {
        assistant_text,
        pending,
        provider_session_id,
        usage: None,
        outcome: failure.map_or(AdapterTurnOutcome::Completed, AdapterTurnOutcome::Failed),
    })
}

pub(super) fn present_acp_assistant_boundary(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.starts_with("Assistant:") {
        trimmed.to_owned()
    } else {
        format!("Assistant: {trimmed}")
    }
}

pub(super) fn classify_acp_failure(reason: String, http_status: Option<u16>) -> AdapterFailure {
    if let Some(status) = http_status {
        let kind = match status {
            401 => AdapterFailureKind::Authentication,
            403 => AdapterFailureKind::Authorization,
            429 => AdapterFailureKind::RateLimit,
            500..=599 => AdapterFailureKind::ProviderUnavailable,
            _ => AdapterFailureKind::Protocol,
        };
        return AdapterFailure {
            kind,
            reason,
            http_status: Some(status),
        };
    }
    if reason.starts_with("Grok CLI ACP cached-token authentication failed") {
        AdapterFailure::new(AdapterFailureKind::Authentication, reason)
    } else if reason.contains("timed out") || reason.contains("timeout") {
        AdapterFailure::new(AdapterFailureKind::TransientNetwork, reason)
    } else if reason.contains("stopped") || reason.contains("cancel") {
        AdapterFailure::cancellation(reason)
    } else {
        AdapterFailure::protocol(reason)
    }
}
