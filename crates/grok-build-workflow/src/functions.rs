//! Closed host function registrations adapted from xai-workflow; see NOTICE.md.
use crate::engine::{
    Context, ControlToken, ScriptResult, dynamic_value, runtime_error, terminated,
};
use crate::{AgentOptions, HostCall, MAX_PARALLEL};
use rhai::{Dynamic, Engine, Map};
use std::rc::Rc;

fn options(prompt: Option<&str>, map: Map) -> ScriptResult<AgentOptions> {
    let mut value = dynamic_value(&Dynamic::from_map(map))?;
    if let Some(prompt) = prompt {
        value["prompt"] = prompt.into();
    }
    let options: AgentOptions = serde_json::from_value(value)
        .map_err(|_| runtime_error("Unsupported or malformed workflow agent options"))?;
    text(&options.prompt, 12_000)?;
    if let Some(label) = &options.label {
        text(label, 128)?;
    }
    if options
        .agent_type
        .as_deref()
        .is_some_and(|role| !matches!(role, "explore" | "plan" | "worker"))
    {
        return Err(runtime_error("Unknown app-owned workflow role"));
    }
    Ok(options)
}
fn text(value: &str, maximum: usize) -> ScriptResult<()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(runtime_error(
            "Workflow text is empty, invalid or oversized",
        ));
    }
    Ok(())
}
fn name(value: &str) -> ScriptResult<()> {
    if value.is_empty()
        || value.len() > 80
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(runtime_error(
            "Workflow scratch names are simple names, not host paths",
        ));
    }
    Ok(())
}
pub(super) fn register(engine: &mut Engine, context: &Rc<Context>) {
    let c = context.clone();
    engine.register_fn("agent", move |prompt: &str| -> ScriptResult<Dynamic> {
        c.call(HostCall::Agent(options(Some(prompt), Map::new())?))
    });
    let c = context.clone();
    engine.register_fn(
        "agent",
        move |prompt: &str, opts: Map| -> ScriptResult<Dynamic> {
            c.call(HostCall::Agent(options(Some(prompt), opts)?))
        },
    );
    let c = context.clone();
    engine.register_fn(
        "parallel",
        move |items: rhai::Array| -> ScriptResult<Dynamic> {
            if items.is_empty() || items.len() > MAX_PARALLEL {
                return Err(runtime_error(
                    "parallel requires one to eight agent requests",
                ));
            }
            let agents = items
                .into_iter()
                .map(|item| {
                    let map = item
                        .try_cast::<Map>()
                        .ok_or_else(|| runtime_error("parallel items must be option maps"))?;
                    options(None, map)
                })
                .collect::<ScriptResult<Vec<_>>>()?;
            c.call(HostCall::Parallel { agents })
        },
    );
    register_observations(engine, context);
    register_scratch(engine, context);
    register_control(engine, context);
}
fn register_observations(engine: &mut Engine, context: &Rc<Context>) {
    let c = context.clone();
    engine.register_fn("phase", move |message: &str| -> ScriptResult<Dynamic> {
        text(message, 512)?;
        c.call(HostCall::Phase {
            text: message.into(),
        })
    });
    let c = context.clone();
    engine.register_fn("log", move |message: &str| -> ScriptResult<Dynamic> {
        text(message, 4096)?;
        c.call(HostCall::Log {
            text: message.into(),
        })
    });
    let c = context.clone();
    engine.register_fn("budget", move || -> ScriptResult<Dynamic> {
        c.call(HostCall::Budget)
    });
}
fn register_scratch(engine: &mut Engine, context: &Rc<Context>) {
    let c = context.clone();
    engine.register_fn(
        "write_scratch_file",
        move |file: &str, content: &str| -> ScriptResult<Dynamic> {
            name(file)?;
            if content.len() > 32 * 1024 {
                return Err(runtime_error("Scratch value exceeds 32 KiB"));
            }
            c.call(HostCall::WriteScratch {
                name: file.into(),
                content: content.into(),
            })
        },
    );
    let c = context.clone();
    engine.register_fn(
        "read_scratch_file",
        move |file: &str| -> ScriptResult<Dynamic> {
            name(file)?;
            c.call(HostCall::ReadScratch { name: file.into() })
        },
    );
}
fn register_control(engine: &mut Engine, context: &Rc<Context>) {
    engine.register_fn("complete", |value: Dynamic| -> ScriptResult<()> {
        Err(terminated(ControlToken::Complete(dynamic_value(&value)?)))
    });
    let c = context.clone();
    engine.register_fn(
        "pause",
        move |kind: &str, message: &str| -> ScriptResult<()> {
            text(message, 4096)?;
            if !matches!(
                kind,
                "user" | "back_off" | "no_progress" | "verification" | "infra"
            ) {
                return Err(runtime_error("Unknown workflow pause kind"));
            }
            c.pause(kind, message)
        },
    );
}
