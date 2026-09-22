//! Inert admission of a bounded subset of upstream `PreToolUse` command hooks.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::extensions::content::Bundle;
use crate::extensions::mcp::config::LocalSpec;

pub(in crate::extensions) const MAX_HOOKS: usize = 8;

#[derive(Clone)]
pub(in crate::extensions) struct HookSpec {
    pub(super) identity: String,
    pub(super) matcher: Vec<String>,
    pub(super) local: LocalSpec,
    pub(super) timeout_seconds: u64,
}

impl HookSpec {
    pub(super) fn matches(&self, name: &str) -> bool {
        self.matcher.iter().any(|item| item == "*" || item == name)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    #[serde(default = "all_tools")]
    matcher: String,
    hooks: Vec<CommandHook>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandHook {
    #[serde(rename = "type")]
    kind: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout: u64,
}

fn all_tools() -> String {
    "*".into()
}

const fn default_timeout() -> u64 {
    10
}

pub(in crate::extensions) fn parse(
    hooks: &Value,
    content: &str,
    component: &str,
    bundle: &Bundle,
) -> Result<Vec<HookSpec>, String> {
    let events = hooks
        .as_object()
        .ok_or("Hook configuration must be an object.")?;
    if events.len() != 1 || !events.contains_key("PreToolUse") {
        return Err("Only PreToolUse hooks are currently admitted. Other app boundaries remain quarantined.".into());
    }
    let groups: Vec<Group> = serde_json::from_value(events["PreToolUse"].clone())
        .map_err(|_| "Hook configuration has unsupported fields or malformed groups.")?;
    if groups.is_empty() || groups.len() > MAX_HOOKS {
        return Err("A hook component requires one to eight bounded groups.".into());
    }
    let mut specs = Vec::new();
    for group in groups {
        if group.matcher.len() > 512 || group.hooks.is_empty() {
            return Err("Hook matcher or command group is invalid.".into());
        }
        let matcher = group
            .matcher
            .split('|')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if matcher.len() > 32
            || matcher.iter().any(|name| {
                name != "*"
                    && (name.is_empty()
                        || name.len() > 64
                        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            })
        {
            return Err("Hook matchers accept exact tool names separated by |, or *. Regular expressions and shell syntax are unavailable.".into());
        }
        for hook in group.hooks {
            if hook.kind != "command" || !(1..=30).contains(&hook.timeout) {
                return Err(
                    "Hooks require a contained command with a one-to-thirty-second timeout.".into(),
                );
            }
            let config = json!({"type":"stdio","command":hook.command,"args":hook.args});
            let local = crate::extensions::mcp::config::local::parse(&config, content, bundle)?
                .ok_or("Hook executable admission is unavailable.")?;
            let identity = super::super::digest(
                json!([
                    "GB Plus PreToolUse hook v1",
                    content,
                    component,
                    specs.len(),
                    &matcher,
                    config,
                    hook.timeout
                ])
                .to_string()
                .as_bytes(),
            );
            specs.push(HookSpec {
                identity,
                matcher: matcher.clone(),
                local,
                timeout_seconds: hook.timeout,
            });
            if specs.len() > MAX_HOOKS {
                return Err("A hook component exceeds eight command hooks.".into());
            }
        }
    }
    Ok(specs)
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Continue,
    Deny,
    Ask,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HookOutput {
    hook_specific_output: SpecificOutput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpecificOutput {
    hook_event_name: String,
    permission_decision: String,
    #[serde(default)]
    permission_decision_reason: String,
}

/// Hook prose never enters provider history or persistent diagnostics. An Allow
/// result means continue to normal app authority; it is not an authorization.
pub(super) fn decision(output: &[u8], exit_code: Option<i32>) -> Result<Decision, String> {
    if output.len() > 16 * 1024 || exit_code != Some(0) {
        return Err(
            "Enabled hook failed or exceeded its output bound. The tool was refused.".into(),
        );
    }
    if output.iter().all(u8::is_ascii_whitespace) {
        return Ok(Decision::Continue);
    }
    let output: HookOutput = serde_json::from_slice(output)
        .map_err(|_| "Enabled hook returned malformed output. The tool was refused.")?;
    let specific = output.hook_specific_output;
    if specific.hook_event_name != "PreToolUse"
        || specific.permission_decision_reason.len() > 2048
        || specific
            .permission_decision_reason
            .chars()
            .any(|c| c.is_control() && c != '\n')
    {
        return Err("Enabled hook returned an unsupported decision. The tool was refused.".into());
    }
    match specific.permission_decision.as_str() {
        "allow" => Ok(Decision::Continue),
        "deny" => Ok(Decision::Deny),
        "ask" => Ok(Decision::Ask),
        _ => Err("Enabled hook returned an unknown decision. The tool was refused.".into()),
    }
}

#[cfg(test)]
mod tests;
