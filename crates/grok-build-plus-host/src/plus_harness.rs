//! Live multi-step harness: plan/steps, follow-on completions, continue/retry.
//!
//! Tool results feed a further live completion in the same Send. Continue and
//! retry never fall back to [`super::FakeProvider`].

use super::plus_live::{
    PlusLiveChatRequest, PlusLiveIdentity, PlusLiveImage, decode_plus_live_reply,
    encode_plus_live_chat_request, encode_plus_live_chat_request_with_image,
};
use super::plus_mode::PlusSessionMode;
use super::plus_tools::{
    PLUS_TOOL_LOOP_NOT_RUN, PlusExternalToolExecutor, PlusToolLifecycleEvent, PlusToolLoopReport,
    PlusToolRequest, PlusToolStep, execute_plus_tool, parse_plus_live_tool_reply,
    present_plus_tool_steps, run_plus_tool_loop_on_store_in_mode_observed_external,
};
use super::{
    BoundProject, PLUS_LIVE_PROVIDER_LABEL, PendingFileProposal, PendingFileSet, PlusChatTurn,
    PlusHostError, PlusSessionStore,
};

/// Why a live Send stopped before a finished assistant reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusTurnStuck {
    /// A host tool returned [`super::plus_tools::PLUS_TOOL_FAILED`].
    FailedTool {
        /// Index in [`PlusChatTurn::steps`].
        index: usize,
        /// Host error text.
        detail: String,
    },
    /// A later live completion or parse failed after tools already ran.
    LiveError {
        /// Live / parse detail.
        detail: String,
    },
    /// Tools ran, but the turn never got a final assistant reply.
    Incomplete {
        /// Why the turn is incomplete.
        detail: String,
    },
}

impl PlusTurnStuck {
    /// Short label for the Plan surface.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::FailedTool { .. } => "failed tool",
            Self::LiveError { .. } => "live error",
            Self::Incomplete { .. } => "incomplete after the last step",
        }
    }

    /// Failed-step index when this is a tool failure.
    #[must_use]
    pub fn step_index(&self) -> Option<usize> {
        match self {
            Self::FailedTool { index, .. } => Some(*index),
            Self::LiveError { .. } | Self::Incomplete { .. } => None,
        }
    }
}

/// Hard cap on live `/v1/responses` completions in one Send.
pub const PLUS_MAX_LIVE_COMPLETIONS: usize = 4;

/// Heading for the window Plan surface.
pub const PLUS_PLAN_HEADING: &str = "Plan";

/// Window button: resume a stuck live turn.
pub const PLUS_TURN_CONTINUE: &str = "Continue";

/// Window button: re-run the failed step from its real start.
pub const PLUS_TURN_RETRY: &str = "Retry";

/// Status word when the turn cannot finish on its own.
pub const PLUS_TURN_STUCK: &str = "stuck";

/// Status word when Continue / Retry is not applicable.
pub const PLUS_TURN_NOT_STUCK: &str = "not stuck";

/// Marker placed on the follow-on live `input` so the next completion sees
/// real tool results.
pub const PLUS_LIVE_TOOL_RESULTS_HEADING: &str = "GB Plus tool results:";

/// Composes the follow-on live input from the original user text and the
/// tools that actually ran.
#[must_use]
pub fn compose_plus_live_follow_up(user_text: &str, steps: &[PlusToolStep]) -> String {
    format!(
        "{user_text}\n\n{PLUS_LIVE_TOOL_RESULTS_HEADING}\n{}\n\nContinue this turn from the tool results.",
        present_plus_tool_steps(steps)
    )
}

/// Appends ordered user guidance that arrived while the current run was
/// active. The JSON array preserves exact message boundaries.
#[must_use]
pub fn compose_plus_live_steered_follow_up(base: &str, messages: &[String]) -> String {
    if messages.is_empty() {
        return base.to_owned();
    }
    let messages = serde_json::to_string(messages).unwrap_or_else(|_| "[]".into());
    format!(
        "{base}\n\nGB Plus user guidance sent during this run:\n{messages}\n\nApply this guidance before choosing the next step."
    )
}

/// Plan/steps list the window Plan surface shows. Progress is the
/// `[completed]` / `[failed]` / `[in_progress]` marker on each line.
#[must_use]
pub fn present_plus_turn_plan(steps: &[PlusToolStep], stuck: Option<&PlusTurnStuck>) -> String {
    let mut lines = vec![PLUS_PLAN_HEADING.to_owned()];
    if steps.is_empty() {
        lines.push("1. planning [in_progress]".into());
    } else {
        for (index, step) in steps.iter().enumerate() {
            let status = if step.ok { "completed" } else { "failed" };
            let request = if step.request.is_empty() {
                String::new()
            } else {
                format!(" {}", step.request)
            };
            lines.push(format!(
                "{}. {}{request} [{status}]",
                index + 1,
                step.name.as_str()
            ));
        }
    }
    if let Some(stuck) = stuck {
        lines.push(format!("{PLUS_TURN_STUCK}: {}", stuck.kind_label()));
        lines.push(format!("{PLUS_TURN_CONTINUE} / {PLUS_TURN_RETRY}"));
    }
    lines.join("\n")
}

/// Live Send loop: each tool batch can feed a further completion.
///
/// # Errors
///
/// First-completion transport or parse failures stay [`PlusHostError::Live`]
/// (never Fake). Later-round failures become a stuck turn so Continue can
/// resume.
pub fn run_plus_live_harness(
    bound: &BoundProject,
    user_text: String,
    identity: &PlusLiveIdentity,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    run_plus_live_harness_observed(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        &mut |_| Ok(()),
    )
}

/// Live Send loop with a fallible app-owned tool lifecycle observer.
///
/// # Errors
///
/// Returns transport, parse, or observer failures without Fake fallback.
pub fn run_plus_live_harness_observed(
    bound: &BoundProject,
    user_text: String,
    identity: &PlusLiveIdentity,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    run_plus_live_harness_observed_external(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        None,
    )
}

/// Same observed live harness with a scoped external high-power dispatcher.
///
/// # Errors
///
/// Returns transport, parser, observer, tool-dispatch, or proposal persistence
/// failures without substituting a fake completion.
#[allow(
    clippy::too_many_arguments,
    reason = "the explicit arguments preserve transport, persistence, mode, observer, and capability boundaries"
)]
pub fn run_plus_live_harness_observed_external(
    bound: &BoundProject,
    user_text: String,
    identity: &PlusLiveIdentity,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusChatTurn, PlusHostError> {
    run_plus_live_harness_observed_external_with_image(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        external,
        None,
    )
}

/// Same scoped live harness with one transient image on the first completion.
///
/// # Errors
///
/// Returns transport, parser, observer, tool-dispatch, proposal-persistence, or
/// image-validation failures without substituting a fake completion.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the bounded completion/tool state machine remains one auditable no-fallback transaction"
)]
pub fn run_plus_live_harness_observed_external_with_image(
    bound: &BoundProject,
    user_text: String,
    identity: &PlusLiveIdentity,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
    image: Option<&PlusLiveImage<'_>>,
) -> Result<PlusChatTurn, PlusHostError> {
    run_plus_live_harness_observed_external_with_image_and_steering(
        bound,
        user_text,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        external,
        image,
        &mut || Ok(Vec::new()),
    )
}

/// Same live harness with ordered user guidance consumed only after an
/// app-owned tool effect completes and before the next provider request.
///
/// # Errors
///
/// Returns transport, parse, observer, tool-dispatch, proposal-persistence,
/// image-validation, or steering-source failures without substituting a fake
/// completion.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the bounded completion/tool/steering state machine remains one auditable no-fallback transaction"
)]
pub fn run_plus_live_harness_observed_external_with_image_and_steering(
    bound: &BoundProject,
    user_text: String,
    identity: &PlusLiveIdentity,
    mut transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
    image: Option<&PlusLiveImage<'_>>,
    steering_source: &mut dyn FnMut() -> Result<Vec<String>, PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    let mut live_completions = 0_usize;
    let mut steps = Vec::new();
    let mut pending = None;
    let mut pending_set = PendingFileSet::default();
    let mut failed_request = None;
    let mut follow_up_input = compose_plus_live_follow_up(&user_text, &steps);
    let mut assistant_parts = Vec::new();
    let mut input = user_text.clone();

    loop {
        if live_completions >= PLUS_MAX_LIVE_COMPLETIONS {
            let stuck = PlusTurnStuck::Incomplete {
                detail: "incomplete after the last step: live completion cap reached".into(),
            };
            return Ok(finish_live_turn(
                user_text,
                &assistant_parts,
                steps,
                pending,
                pending_set,
                live_completions,
                Some(stuck),
                failed_request,
                follow_up_input,
            ));
        }

        let request = if live_completions == 0 {
            encode_plus_live_chat_request_with_image(&input, image, identity)?
        } else {
            encode_plus_live_chat_request(&input, identity)?
        };
        let body = match transport(&request) {
            Ok(body) => body,
            Err(error) => {
                if live_completions == 0 && steps.is_empty() {
                    return Err(error);
                }
                let stuck = PlusTurnStuck::LiveError {
                    detail: error.to_string(),
                };
                return Ok(finish_live_turn(
                    user_text,
                    &assistant_parts,
                    steps,
                    pending,
                    pending_set,
                    live_completions,
                    Some(stuck),
                    failed_request,
                    follow_up_input,
                ));
            }
        };
        live_completions += 1;

        let reply = match decode_plus_live_reply(&body) {
            Ok(reply) => reply,
            Err(error) => {
                if live_completions == 1 && steps.is_empty() {
                    return Err(error);
                }
                let stuck = PlusTurnStuck::LiveError {
                    detail: error.to_string(),
                };
                return Ok(finish_live_turn(
                    user_text,
                    &assistant_parts,
                    steps,
                    pending,
                    pending_set,
                    live_completions,
                    Some(stuck),
                    failed_request,
                    follow_up_input,
                ));
            }
        };
        if !reply.assistant_text.is_empty() {
            assistant_parts.push(reply.assistant_text.clone());
        }
        let calls: Vec<(String, String)> = reply
            .function_calls
            .iter()
            .map(|call| (call.name.clone(), call.arguments_json.clone()))
            .collect();
        let requests = match parse_plus_live_tool_reply(&reply.assistant_text, &calls) {
            Ok(requests) => requests,
            Err(error) => {
                if live_completions == 1 && steps.is_empty() {
                    return Err(error);
                }
                let stuck = PlusTurnStuck::LiveError {
                    detail: error.to_string(),
                };
                return Ok(finish_live_turn(
                    user_text,
                    &assistant_parts,
                    steps,
                    pending,
                    pending_set,
                    live_completions,
                    Some(stuck),
                    failed_request,
                    follow_up_input,
                ));
            }
        };

        if requests.is_empty() {
            return Ok(finish_live_turn(
                user_text,
                &assistant_parts,
                steps,
                pending,
                pending_set,
                live_completions,
                None,
                failed_request,
                follow_up_input,
            ));
        }

        let report = run_plus_tool_loop_on_store_in_mode_observed_external(
            bound,
            store,
            &requests,
            mode,
            tool_observer,
            external,
        )?;
        merge_tool_report(
            &mut steps,
            &mut pending,
            &mut pending_set,
            &mut failed_request,
            report,
        );
        follow_up_input = compose_plus_live_follow_up(&user_text, &steps);

        if let Some(request) = failed_request.clone() {
            let index = steps.iter().position(|step| !step.ok).unwrap_or(0);
            let stuck = PlusTurnStuck::FailedTool {
                index,
                detail: format!("failed tool {}", request.name.as_str()),
            };
            return Ok(finish_live_turn(
                user_text,
                &assistant_parts,
                steps,
                pending,
                pending_set,
                live_completions,
                Some(stuck),
                failed_request,
                follow_up_input,
            ));
        }

        let steering = steering_source()?;
        follow_up_input = compose_plus_live_steered_follow_up(&follow_up_input, &steering);

        input.clone_from(&follow_up_input);
    }
}

/// Resume a stuck live turn with another completion. Never Fake.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when the turn is not stuck or live is
/// unconfigured.
pub fn plus_continue_stuck_turn(
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_continue_stuck_turn_observed(bound, turn, identity, transport, store, mode, &mut |_| {
        Ok(())
    })
}

/// Resume a stuck live turn with a fallible tool lifecycle observer.
///
/// # Errors
///
/// Returns live or observer failures without Fake fallback.
pub fn plus_continue_stuck_turn_observed(
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_continue_stuck_turn_observed_external(
        bound,
        turn,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        None,
    )
}

/// Same observed continuation with a scoped external high-power dispatcher.
///
/// # Errors
///
/// Returns when the live identity or stuck state is invalid, or when transport,
/// parsing, observation, dispatch, or persistence fails.
#[allow(
    clippy::too_many_arguments,
    reason = "continuation preserves the original transport, persistence, mode, observer, and capability boundaries"
)]
pub fn plus_continue_stuck_turn_observed_external(
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusChatTurn, PlusHostError> {
    let Some(identity) = identity else {
        return Err(PlusHostError::Live(
            "continue requires a live identity; not a Fake fallback".into(),
        ));
    };
    if turn.stuck.is_none() {
        return Err(PlusHostError::Live(PLUS_TURN_NOT_STUCK.into()));
    }
    let user_text = turn.user_text.clone();
    let follow_up = if turn.follow_up_input.is_empty() {
        compose_plus_live_follow_up(&user_text, &turn.steps)
    } else {
        turn.follow_up_input.clone()
    };
    continue_from_state(
        bound,
        turn,
        user_text,
        &follow_up,
        identity,
        transport,
        store,
        mode,
        tool_observer,
        external,
    )
}

/// Same as [`plus_continue_stuck_turn`], then appends the assistant text.
///
/// # Errors
///
/// Returns [`PlusHostError`] from continue or transcript persist.
pub fn plus_continue_stuck_turn_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    let turn = plus_continue_stuck_turn(bound, turn, identity, transport, Some(store), mode)?;
    store.append_chat_turn(&turn.assistant_text)?;
    Ok(turn)
}

/// Continues the turn with observed tool activity and appends its assistant
/// text to the transcript.
///
/// # Errors
///
/// Returns continue, observer, or transcript persistence failures.
pub fn plus_continue_stuck_turn_and_remember_observed(
    store: &PlusSessionStore,
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
) -> Result<PlusChatTurn, PlusHostError> {
    plus_continue_stuck_turn_and_remember_observed_external(
        store,
        bound,
        turn,
        identity,
        transport,
        mode,
        tool_observer,
        None,
    )
}

/// Same remembered continuation with a scoped external high-power dispatcher.
///
/// # Errors
///
/// Returns continuation, observer, tool-dispatch, or transcript persistence
/// failures.
#[allow(
    clippy::too_many_arguments,
    reason = "remembered continuation preserves every authority boundary of the non-persisting variant"
)]
pub fn plus_continue_stuck_turn_and_remember_observed_external(
    store: &PlusSessionStore,
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusChatTurn, PlusHostError> {
    let turn = plus_continue_stuck_turn_observed_external(
        bound,
        turn,
        identity,
        transport,
        Some(store),
        mode,
        tool_observer,
        external,
    )?;
    store.append_chat_turn(&turn.assistant_text)?;
    Ok(turn)
}

/// Re-run the failed step from its real host function, then continue when
/// live is configured. Never Fake.
///
/// # Errors
///
/// Returns [`PlusHostError::Live`] when there is no failed step to retry.
pub fn plus_retry_stuck_step(
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    let Some(request) = turn.failed_request.clone() else {
        return Err(PlusHostError::Live(
            "retry requires a failed step; not a Fake fallback".into(),
        ));
    };
    let (result, staged, ok) = execute_plus_tool(bound, store, &request, mode);
    let mut turn = turn;
    if let Some(index) = turn
        .stuck
        .as_ref()
        .and_then(PlusTurnStuck::step_index)
        .filter(|index| *index < turn.steps.len())
    {
        turn.steps[index].result.clone_from(&result);
        turn.steps[index].ok = ok;
    } else if let Some(step) = turn.steps.iter_mut().find(|step| !step.ok) {
        step.result.clone_from(&result);
        step.ok = ok;
    } else {
        turn.steps.push(PlusToolStep {
            name: request.name,
            request: request.path.display().to_string(),
            result: result.clone(),
            ok,
        });
    }
    if let Some(proposal) = staged {
        turn.pending_set.upsert(proposal.clone());
        turn.pending = Some(proposal);
    }
    turn.follow_up_input = compose_plus_live_follow_up(&turn.user_text, &turn.steps);
    if ok {
        turn.failed_request = None;
        turn.stuck = None;
        if let Some(identity) = identity {
            let user_text = turn.user_text.clone();
            let follow_up = turn.follow_up_input.clone();
            return continue_from_state(
                bound,
                turn,
                user_text,
                &follow_up,
                identity,
                transport,
                store,
                mode,
                &mut |_| Ok(()),
                None,
            );
        }
        return Ok(rebuild_live_assistant(turn));
    }
    if let PlusTurnStuck::FailedTool { index, .. } =
        turn.stuck.clone().unwrap_or(PlusTurnStuck::FailedTool {
            index: 0,
            detail: "failed tool".into(),
        })
    {
        turn.stuck = Some(PlusTurnStuck::FailedTool {
            index,
            detail: result,
        });
    }
    Ok(rebuild_live_assistant(turn))
}

/// Same as [`plus_retry_stuck_step`], then appends the assistant text.
///
/// # Errors
///
/// Returns [`PlusHostError`] from retry or transcript persist.
pub fn plus_retry_stuck_step_and_remember(
    store: &PlusSessionStore,
    bound: &BoundProject,
    turn: PlusChatTurn,
    identity: Option<&PlusLiveIdentity>,
    transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    mode: PlusSessionMode,
) -> Result<PlusChatTurn, PlusHostError> {
    let turn = plus_retry_stuck_step(bound, turn, identity, transport, Some(store), mode)?;
    store.append_chat_turn(&turn.assistant_text)?;
    Ok(turn)
}

#[allow(
    clippy::too_many_arguments,
    reason = "continue resumes the same Send fields the window already holds"
)]
fn continue_from_state(
    bound: &BoundProject,
    turn: PlusChatTurn,
    user_text: String,
    follow_up: &str,
    identity: &PlusLiveIdentity,
    mut transport: impl FnMut(&PlusLiveChatRequest) -> Result<Vec<u8>, PlusHostError>,
    store: Option<&PlusSessionStore>,
    mode: PlusSessionMode,
    tool_observer: &mut dyn FnMut(PlusToolLifecycleEvent) -> Result<(), PlusHostError>,
    external: Option<&dyn PlusExternalToolExecutor>,
) -> Result<PlusChatTurn, PlusHostError> {
    let request = encode_plus_live_chat_request(follow_up, identity)?;
    let body = transport(&request)?;
    let reply = decode_plus_live_reply(&body)?;
    let live_completions = turn.live_completions.saturating_add(1);
    let mut assistant_parts = vec![strip_live_prefix(&turn.assistant_text)];
    if !reply.assistant_text.is_empty() {
        assistant_parts.push(reply.assistant_text.clone());
    }
    let calls: Vec<(String, String)> = reply
        .function_calls
        .iter()
        .map(|call| (call.name.clone(), call.arguments_json.clone()))
        .collect();
    let requests = parse_plus_live_tool_reply(&reply.assistant_text, &calls)?;
    let mut steps = turn.steps;
    let mut pending = turn.pending;
    let mut pending_set = turn.pending_set;
    let mut failed_request = turn.failed_request;
    if !requests.is_empty() {
        let report = run_plus_tool_loop_on_store_in_mode_observed_external(
            bound,
            store,
            &requests,
            mode,
            tool_observer,
            external,
        )?;
        merge_tool_report(
            &mut steps,
            &mut pending,
            &mut pending_set,
            &mut failed_request,
            report,
        );
    }
    let follow_up_input = compose_plus_live_follow_up(&user_text, &steps);
    let stuck = if let Some(request) = failed_request.clone() {
        let index = steps.iter().position(|step| !step.ok).unwrap_or(0);
        Some(PlusTurnStuck::FailedTool {
            index,
            detail: format!("failed tool {}", request.name.as_str()),
        })
    } else if !requests.is_empty() && live_completions >= PLUS_MAX_LIVE_COMPLETIONS {
        Some(PlusTurnStuck::Incomplete {
            detail: "incomplete after the last step".into(),
        })
    } else {
        None
    };
    Ok(finish_live_turn(
        user_text,
        &assistant_parts,
        steps,
        pending,
        pending_set,
        turn.live_completions.saturating_add(1),
        stuck,
        failed_request,
        follow_up_input,
    ))
}

fn merge_tool_report(
    steps: &mut Vec<PlusToolStep>,
    pending: &mut Option<PendingFileProposal>,
    pending_set: &mut PendingFileSet,
    failed_request: &mut Option<PlusToolRequest>,
    report: PlusToolLoopReport,
) {
    for (step, request) in report.steps.iter().zip(report.requests.iter()) {
        if !step.ok && failed_request.is_none() {
            *failed_request = Some(request.clone());
        }
        steps.push(step.clone());
    }
    pending_set.items.extend(report.pending_set.items);
    if let Some(proposal) = report.pending {
        *pending = Some(proposal);
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "one constructor keeps the live turn fields together"
)]
fn finish_live_turn(
    user_text: String,
    assistant_parts: &[String],
    steps: Vec<PlusToolStep>,
    pending: Option<PendingFileProposal>,
    pending_set: PendingFileSet,
    live_completions: usize,
    stuck: Option<PlusTurnStuck>,
    failed_request: Option<PlusToolRequest>,
    follow_up_input: String,
) -> PlusChatTurn {
    let steps_text = if steps.is_empty() {
        PLUS_TOOL_LOOP_NOT_RUN.to_owned()
    } else {
        present_plus_tool_steps_for_persistence(&steps)
    };
    let assistant = if assistant_parts.is_empty() {
        String::new()
    } else {
        assistant_parts.join("\n")
    };
    PlusChatTurn {
        assistant_text: format!(
            "{PLUS_LIVE_PROVIDER_LABEL}\nYou: {user_text}\n{steps_text}\nAssistant: {assistant}"
        ),
        user_text,
        steps,
        pending,
        pending_set,
        live_completions,
        stuck,
        failed_request,
        follow_up_input,
    }
}

fn present_plus_tool_steps_for_persistence(steps: &[PlusToolStep]) -> String {
    let redacted = steps
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
    present_plus_tool_steps(&redacted)
}

fn rebuild_live_assistant(mut turn: PlusChatTurn) -> PlusChatTurn {
    let steps_text = if turn.steps.is_empty() {
        PLUS_TOOL_LOOP_NOT_RUN.to_owned()
    } else {
        present_plus_tool_steps_for_persistence(&turn.steps)
    };
    let assistant = strip_live_prefix(&turn.assistant_text);
    turn.assistant_text = format!(
        "{PLUS_LIVE_PROVIDER_LABEL}\nYou: {}\n{steps_text}\nAssistant: {assistant}",
        turn.user_text
    );
    turn
}

fn strip_live_prefix(assistant_text: &str) -> String {
    assistant_text
        .rsplit_once("Assistant: ")
        .map(|(_, rest)| rest.to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod browser_tests {
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::plus_tools::PlusToolName;

    struct BrowserFixture;

    impl PlusExternalToolExecutor for BrowserFixture {
        fn execute(&self, request: &PlusToolRequest) -> Option<Result<String, PlusHostError>> {
            if request.name == PlusToolName::BrowserInspect {
                Some(Ok("TRANSIENT_BROWSER_PAGE_SECRET".into()))
            } else {
                None
            }
        }
    }

    fn fixture_bound() -> BoundProject {
        let root = std::env::temp_dir().join(format!(
            "grok-build-browser-harness-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("workspace");
        crate::bind_project_folder(root).expect("bind")
    }

    #[test]
    fn browser_result_is_transient_to_model_and_redacted_from_durable_chat() {
        let bound = fixture_bound();
        let identity =
            PlusLiveIdentity::from_configured_key("browser-harness-test-key-SHOULD-NOT-LEAK")
                .expect("identity");
        let mut round = 0_u8;
        let saw_follow_up = Mutex::new(false);
        let mut events = Vec::new();
        let turn = run_plus_live_harness_observed_external(
            &bound,
            "inspect the armed page".into(),
            &identity,
            |request| {
                round = round.saturating_add(1);
                if round == 1 {
                    return serde_json::to_vec(&serde_json::json!({
                        "object": "response",
                        "output": [{
                            "type": "function_call",
                            "name": "browser_inspect",
                            "arguments": "{}"
                        }]
                    }))
                    .map_err(|error| PlusHostError::Live(error.to_string()));
                }
                assert!(
                    request
                        .json_body()
                        .contains("TRANSIENT_BROWSER_PAGE_SECRET"),
                    "the next live completion must receive the transient Browser result"
                );
                *saw_follow_up.lock().expect("follow-up") = true;
                serde_json::to_vec(&serde_json::json!({
                    "object": "response",
                    "output": [{
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done"}]
                    }]
                }))
                .map_err(|error| PlusHostError::Live(error.to_string()))
            },
            None,
            PlusSessionMode::Agent,
            &mut |event| {
                events.push(event);
                Ok(())
            },
            Some(&BrowserFixture),
        )
        .expect("Browser live harness");
        assert!(*saw_follow_up.lock().expect("follow-up"));
        assert!(
            turn.follow_up_input
                .contains("TRANSIENT_BROWSER_PAGE_SECRET")
        );
        assert!(
            !turn
                .assistant_text
                .contains("TRANSIENT_BROWSER_PAGE_SECRET")
        );
        assert!(
            turn.assistant_text
                .contains("page content is omitted from persisted Chat")
        );
        assert!(matches!(
            events.as_slice(),
            [
                PlusToolLifecycleEvent::Requested { .. },
                PlusToolLifecycleEvent::Completed { .. }
            ]
        ));
    }
}
