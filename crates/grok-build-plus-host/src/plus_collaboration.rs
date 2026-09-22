//! Fixed app-owned collaboration contracts. These carry intent, never execution authority.
use crate::PlusChildRole;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A bounded request to the owning app's Grok family controller.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlusCollaborationCommand {
    /// Start one child with the selected tool ceiling.
    Spawn {
        /// Fixed app role.
        role: PlusChildRole,
        /// Child instructions, bounded to 12,000 bytes.
        prompt: String,
    },
    /// Queue an identified message for an existing child.
    Message {
        /// App-issued agent identity.
        agent_id: String,
        /// Child guidance, bounded to 12,000 bytes.
        message: String,
    },
    /// Wait for selected children while yielding the parent's model lease.
    Wait {
        /// One to eight app-issued identities.
        agent_ids: Vec<String>,
        /// Bounded wait, at most 60 seconds.
        timeout_seconds: u16,
    },
    /// Stop one child and retain its lease until transport cleanup is proven.
    Stop {
        /// App-issued agent identity.
        agent_id: String,
    },
    /// Explicit continuation of the latest completed invocation.
    Continue {
        /// App-issued agent identity.
        agent_id: String,
        /// New instructions, bounded to 12,000 bytes.
        prompt: String,
    },
}

impl PlusCollaborationCommand {
    /// Whether a provider name belongs to the reserved app namespace.
    #[must_use]
    pub fn recognizes(name: &str) -> bool {
        name.starts_with("app_agent_")
    }

    /// Decode a fixed tool name and closed argument shape before any effect.
    ///
    /// # Errors
    /// Refuses unknown operations, additional fields, unbounded data or malformed identities.
    pub fn parse(name: &str, arguments: &Value) -> Result<Self, String> {
        let operation = match name {
            "app_agent_spawn" => "spawn",
            "app_agent_message" => "message",
            "app_agent_wait" => "wait",
            "app_agent_stop" => "stop",
            "app_agent_continue" => "continue",
            _ => return Err("Unknown app-owned collaboration tool.".into()),
        };
        let mut object = arguments
            .as_object()
            .cloned()
            .ok_or("Collaboration arguments must be an object.")?;
        if object.contains_key("operation") || arguments.to_string().len() > 16 * 1024 {
            return Err("Collaboration arguments exceed the fixed contract.".into());
        }
        object.insert("operation".into(), json!(operation));
        let command: Self = serde_json::from_value(Value::Object(object))
            .map_err(|_| "Collaboration arguments do not match the fixed contract.")?;
        let identity =
            |id: &str| !id.is_empty() && id.len() <= 256 && !id.chars().any(char::is_control);
        let prompt = |text: &str| {
            !text.trim().is_empty()
                && text.len() <= 12_000
                && !text
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        };
        let valid = match &command {
            Self::Spawn { prompt: text, .. } => prompt(text),
            Self::Message { agent_id, message } => identity(agent_id) && prompt(message),
            Self::Continue {
                agent_id,
                prompt: text,
            } => identity(agent_id) && prompt(text),
            Self::Stop { agent_id } => identity(agent_id),
            Self::Wait {
                agent_ids,
                timeout_seconds,
            } => {
                !agent_ids.is_empty()
                    && agent_ids.len() <= 8
                    && *timeout_seconds <= 60
                    && agent_ids.iter().all(|id| identity(id))
                    && agent_ids
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == agent_ids.len()
            }
        };
        if !valid {
            return Err("Collaboration request contains invalid text, identity or limits.".into());
        }
        Ok(command)
    }
}

/// App-issued authority, scoped at construction to a parent and its project.
pub trait PlusCollaborationExecutor: Send + Sync {
    /// Opaque app family binding, fixed before provider registration.
    fn binding(&self) -> &str;

    /// Execute once, yielding and reacquiring the parent's model lease before return.
    /// `transient` is supplied by the runtime's context journal, never provider arguments.
    ///
    /// # Errors
    /// Refuses disabled, stale, cross-family, duplicate or unsafe operations.
    fn execute(
        &self,
        invocation: &str,
        command: PlusCollaborationCommand,
        transient: bool,
    ) -> Result<Value, String>;
}

/// Identical fixed declarations for both supported Grok transports.
#[must_use]
pub fn plus_collaboration_declarations() -> Vec<Value> {
    let id = json!({"type":"string","minLength":1,"maxLength":256});
    let prompt = json!({"type":"string","minLength":1,"maxLength":12000});
    let schema = |properties: Value, required: &[&str]| json!({"type":"object","properties":properties,"required":required,"additionalProperties":false});
    vec![
        json!({"name":"app_agent_spawn","description":"Delegate to an app-owned Grok child. Explore and Plan read files; Worker may stage separately attributed changes. At most eight child invocations per family; tools and permissions are not inherited.","parameters":schema(json!({"role":{"type":"string","enum":["explore","plan","worker"]},"prompt":prompt}), &["role","prompt"])}),
        json!({"name":"app_agent_message","description":"Send identified guidance to one app-owned child. Delivery status is reported by the app.","parameters":schema(json!({"agent_id":id,"message":prompt}), &["agent_id","message"])}),
        json!({"name":"app_agent_wait","description":"Yield the parent model lease while waiting for children. Results and unfinished statuses remain separately attributable.","parameters":schema(json!({"agent_ids":{"type":"array","items":id,"minItems":1,"maxItems":8,"uniqueItems":true},"timeout_seconds":{"type":"integer","minimum":0,"maximum":60}}), &["agent_ids","timeout_seconds"])}),
        json!({"name":"app_agent_stop","description":"Stop one child; capacity stays reserved until cleanup is proven.","parameters":schema(json!({"agent_id":id}), &["agent_id"])}),
        json!({"name":"app_agent_continue","description":"Continue a completed child in its existing provider context. Consumes another family invocation; uncertain work is not replayed.","parameters":schema(json!({"agent_id":id,"prompt":prompt}), &["agent_id","prompt"])}),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collaboration_wire_shapes_cannot_supply_execution_authority() {
        assert!(
            PlusCollaborationCommand::parse(
                "app_agent_spawn",
                &json!({"role":"worker","prompt":"inspect"})
            )
            .is_ok()
        );
        for arguments in [
            json!({"role":"parent","prompt":"inspect"}),
            json!({"role":"worker","prompt":"inspect","workspace":"/"}),
            json!({"role":"worker","prompt":"inspect","operation":"stop"}),
            json!({"role":"worker","prompt":"x".repeat(12001)}),
        ] {
            assert!(PlusCollaborationCommand::parse("app_agent_spawn", &arguments).is_err());
        }
        assert!(
            PlusCollaborationCommand::parse(
                "app_agent_wait",
                &json!({"agent_ids":["a","a"],"timeout_seconds":1})
            )
            .is_err()
        );
        assert!(
            PlusCollaborationCommand::parse(
                "app_agent_wait",
                &json!({"agent_ids":["a"],"timeout_seconds":61})
            )
            .is_err()
        );
        assert!(PlusCollaborationCommand::parse("app_agent_foreign", &json!({})).is_err());
        assert_eq!(plus_collaboration_declarations().len(), 5);
    }
}
