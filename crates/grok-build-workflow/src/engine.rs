//! Evaluation and explicit control, adapted from xai-workflow; see NOTICE.md.
use crate::{CancelCheck, HostCall, MAX_HOST_CALLS, WorkflowHost, WorkflowOutcome, validate_value};
use rhai::{Dynamic, EvalAltResult, Position, Scope};
use serde_json::Value;
use std::cell::Cell;
use std::rc::Rc;

#[derive(Clone, Debug)]
pub(super) enum ControlToken {
    Complete(Value),
    Pause(String, String),
    Cancelled,
    Fatal(String),
}
pub(super) type ScriptResult<T> = Result<T, Box<EvalAltResult>>;
pub(super) struct Context {
    sequence: Cell<u64>,
    host: Rc<dyn WorkflowHost>,
    cancel: CancelCheck,
}
impl Context {
    pub(super) fn call(&self, request: HostCall) -> ScriptResult<Dynamic> {
        let reply = self.request(request)?;
        rhai::serde::to_dynamic(&reply.value)
            .map_err(|_| terminated(ControlToken::Fatal("Invalid host result".into())))
    }
    pub(super) fn pause(&self, kind: &str, message: &str) -> ScriptResult<()> {
        let reply = self.request(HostCall::Pause {
            kind: kind.into(),
            message: message.into(),
        })?;
        if reply.replayed {
            Ok(())
        } else {
            Err(terminated(ControlToken::Pause(kind.into(), message.into())))
        }
    }
    fn request(&self, request: HostCall) -> ScriptResult<crate::HostReply> {
        if (self.cancel)() {
            return Err(terminated(ControlToken::Cancelled));
        }
        let sequence = self.sequence.get();
        if sequence >= MAX_HOST_CALLS {
            return Err(terminated(ControlToken::Fatal(
                "Workflow host-call limit reached.".into(),
            )));
        }
        let value =
            serde_json::to_value(&request).map_err(|_| runtime_error("Invalid host request"))?;
        validate_value(&value).map_err(runtime_error)?;
        self.sequence.set(sequence + 1);
        let value = self
            .host
            .call(sequence, request, &self.cancel)
            .map_err(|error| terminated(ControlToken::Fatal(bounded_error(&error))))?;
        if (self.cancel)() {
            return Err(terminated(ControlToken::Cancelled));
        }
        validate_value(&value.value).map_err(|error| terminated(ControlToken::Fatal(error)))?;
        Ok(value)
    }
}

pub(super) fn run(
    script: &str,
    args: &Value,
    host: Rc<dyn WorkflowHost>,
    cancel: CancelCheck,
) -> WorkflowOutcome {
    if cancel() {
        return WorkflowOutcome::Cancelled;
    }
    if script.is_empty() || script.len() > crate::MAX_BYTES || validate_value(args).is_err() {
        return WorkflowOutcome::Failed {
            error: "Workflow input exceeds its fixed bounds.".into(),
        };
    }
    let context = Rc::new(Context {
        sequence: Cell::new(0),
        host,
        cancel: cancel.clone(),
    });
    let mut engine = crate::limits::engine(cancel);
    crate::functions::register(&mut engine, &context);
    let ast = match engine.compile(script) {
        Ok(ast) => ast,
        Err(error) => {
            return WorkflowOutcome::Failed {
                error: bounded_error(&format!("Workflow compile refused: {error}")),
            };
        }
    };
    if (context.cancel)() {
        return WorkflowOutcome::Cancelled;
    }
    let mut scope = Scope::new();
    let Ok(args) = rhai::serde::to_dynamic(args) else {
        return WorkflowOutcome::Failed {
            error: "Invalid workflow args".into(),
        };
    };
    scope.push_dynamic("args", args);
    match engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast) {
        Ok(value) => match dynamic_value(&value) {
            Ok(result) => WorkflowOutcome::Completed { result },
            Err(error) => WorkflowOutcome::Failed {
                error: bounded_error(&error.to_string()),
            },
        },
        Err(error) => match find_control_token(&error) {
            Some(ControlToken::Complete(result)) => WorkflowOutcome::Completed { result },
            Some(ControlToken::Pause(kind, message)) => WorkflowOutcome::Paused { kind, message },
            Some(ControlToken::Cancelled) => WorkflowOutcome::Cancelled,
            Some(ControlToken::Fatal(error)) => WorkflowOutcome::Failed { error },
            None => WorkflowOutcome::Failed {
                error: bounded_error(&error.to_string()),
            },
        },
    }
}

fn find_control_token(error: &EvalAltResult) -> Option<ControlToken> {
    match error {
        EvalAltResult::ErrorTerminated(token, _) => token.clone().try_cast::<ControlToken>(),
        EvalAltResult::ErrorInFunctionCall(_, _, inner, _)
        | EvalAltResult::ErrorInModule(_, inner, _) => find_control_token(inner),
        _ => None,
    }
}
#[allow(
    clippy::unnecessary_box_returns,
    reason = "Rhai native function errors require Box<EvalAltResult>"
)]
pub(super) fn terminated(token: ControlToken) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorTerminated(
        Dynamic::from(token),
        Position::NONE,
    ))
}
#[allow(
    clippy::unnecessary_box_returns,
    reason = "Rhai native function errors require Box<EvalAltResult>"
)]
pub(super) fn runtime_error(message: impl Into<String>) -> Box<EvalAltResult> {
    Box::new(EvalAltResult::ErrorRuntime(
        Dynamic::from(message.into()),
        Position::NONE,
    ))
}
pub(super) fn dynamic_value(value: &Dynamic) -> ScriptResult<Value> {
    let value = rhai::serde::from_dynamic(value)
        .map_err(|_| runtime_error("Workflow value cannot be represented as JSON"))?;
    validate_value(&value).map_err(runtime_error)?;
    Ok(value)
}
fn bounded_error(error: &str) -> String {
    let mut end = error.len().min(4096);
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}
