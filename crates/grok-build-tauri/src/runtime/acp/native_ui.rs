//! Native ACP observations and reverse interactions for standard Chat.

use serde_json::{Value, json};

use super::{RuntimeEvent, RuntimeEventSink, process::AcpProcess};

impl AcpProcess {
    pub(super) fn poll_native_controls(
        &mut self,
        events: &RuntimeEventSink<'_>,
        started: &mut std::time::Instant,
        last_poll: &mut std::time::Instant,
    ) -> Result<(), String> {
        if self.is_standard() && self.cancel.cli_interactions.waiting()? {
            *started += last_poll.elapsed();
        }
        *last_poll = std::time::Instant::now();
        self.poll_native_answers(events)
    }

    pub(super) fn bind_startup_interaction(
        &mut self,
        message: &Value,
        method: &str,
        request: &str,
        provisional: &mut Option<String>,
    ) -> Result<(), String> {
        if self.is_standard()
            && request == "session/new"
            && matches!(
                method,
                "session/request_permission" | "_x.ai/ask_user_question"
            )
        {
            let session = message
                .pointer("/params/sessionId")
                .and_then(Value::as_str)
                .filter(|id| super::protocol::bounded_provider_session_id(id))
                .ok_or("CLI startup request omitted its session identity.")?;
            if provisional.as_deref().is_some_and(|id| id != session) {
                return Err("CLI startup request changed its session identity.".into());
            }
            *provisional = Some(session.to_owned());
            self.active_session_id = Some(session.to_owned());
        }
        Ok(())
    }

    pub(super) fn observe_native_family(&mut self, message: &Value) {
        let update = &message["params"]["update"];
        let parent = message["params"]["sessionId"].as_str();
        if update["sessionUpdate"] == "subagent_spawned"
            && (parent == self.active_session_id.as_deref()
                || parent.is_some_and(|id| self.native_children.contains(id)))
            && update["parent_session_id"].as_str() == parent
            && self.native_children.len() < 4096
            && let Some(child) = update["child_session_id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
        {
            self.native_children.insert(child.into());
        }
    }

    pub(super) fn prepare_native_permission(
        &mut self,
        session: &str,
        mode: crate::runtime::cli_permissions::CliPermissionMode,
    ) -> Result<(), String> {
        if self.applied_permission == Some(mode) {
            return Ok(());
        }
        let roster = self.request("_x.ai/sessions/list", &json!({}), &|_| Ok(()))?;
        if let Some(row) = roster
            .get("sessions")
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter()
                    .find(|row| row["sessionId"] == session && row["resident"] == true)
            })
        {
            if row["cwd"].as_str() != self.neutral_cwd.to_str() || row["activity"] != "idle" {
                return Err("This shared CLI session is active elsewhere. Wait for it to finish before changing its permissions.".into());
            }
            self.request(
                "_x.ai/session/close",
                &json!({"sessionId":session}),
                &|_| Ok(()),
            )?;
        }
        Ok(())
    }

    pub(super) fn emit_native_session_options(
        &self,
        session: &str,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        events(RuntimeEvent::CliUpdate {
            session_id: session.into(),
            update: json!({"sessionUpdate":"session_info_update","permissionMode":self.applied_permission}),
        })?;
        if let Some(commands) = self
            .initialized
            .as_ref()
            .and_then(|value| value.pointer("/_meta/availableCommands"))
        {
            events(RuntimeEvent::CliUpdate {
                session_id: session.into(),
                update: json!({"sessionUpdate":"available_commands_update","availableCommands":commands}),
            })?;
        }
        if let Some(options) = self.session_config.get("configOptions") {
            events(RuntimeEvent::CliUpdate {
                session_id: session.into(),
                update: json!({"sessionUpdate":"config_option_update","configOptions":options}),
            })?;
        }
        Ok(())
    }

    pub(super) fn handle_native_request(
        &self,
        message: &Value,
        method: &str,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        let permitted = matches!(
            method,
            "session/request_permission" | "_x.ai/ask_user_question"
        );
        let session = message.pointer("/params/sessionId").and_then(Value::as_str);
        let result = if permitted
            && session.is_some()
            && (session == self.active_session_id.as_deref()
                || session.is_some_and(|id| self.native_children.contains(id)))
            && !self.cancel.cancelled()
        {
            let mut params = message["params"].clone();
            super::native_edit::preview(self.app_tools.native_preview_bound(), &mut params);
            self.cancel
                .cli_interactions
                .register(method, &message["id"], &params)
        } else {
            Err("The CLI request is unsupported or belongs to another session.".into())
        };
        match result {
            Ok(view) => {
                if self.applied_permission
                    == Some(crate::runtime::cli_permissions::CliPermissionMode::AcceptEdits)
                    && session == self.active_session_id.as_deref()
                    && view.kind == "permission"
                    && view.request["toolCall"]["kind"] == "edit"
                    && view.request["options"].as_array().is_some_and(|options| {
                        options.iter().any(|option| {
                            option["optionId"] == "allow-edits-session"
                                && option["kind"] == "allow_always"
                        })
                    })
                {
                    self.cancel.cli_interactions.answer(
                        view.id,
                        crate::runtime::cli_interactions::CliAnswer::Permission {
                            option_id: "allow-edits-session".into(),
                        },
                    )?;
                    return Ok(());
                }
                events(RuntimeEvent::CliInteraction(
                    serde_json::to_value(view).map_err(|e| e.to_string())?,
                ))
            }
            Err(reason) => {
                let reply = match method {
                    "session/request_permission" => {
                        json!({"result":{"outcome":{"outcome":"cancelled"}}})
                    }
                    "_x.ai/ask_user_question" => json!({"result":{"outcome":"cancelled"}}),
                    _ => json!({"error":{"code":-32601,"message":reason}}),
                };
                let mut frame = json!({"jsonrpc":"2.0","id":message["id"]});
                frame
                    .as_object_mut()
                    .ok_or("Invalid ACP response frame.")?
                    .extend(reply.as_object().ok_or("Invalid ACP reply.")?.clone());
                self.send(&frame)?;
                events(RuntimeEvent::ToolRefused {
                    name: super::protocol::bounded_event_discriminator(method),
                    reason,
                })
            }
        }
    }

    pub(super) fn poll_native_answers(
        &mut self,
        events: &RuntimeEventSink<'_>,
    ) -> Result<(), String> {
        if !self.is_standard() {
            return Ok(());
        }
        for reply in self
            .cancel
            .cli_interactions
            .take_ready(self.cancel.cancelled())?
        {
            if reply
                .response
                .pointer("/outcome/optionId")
                .and_then(Value::as_str)
                == Some("allow-edits-session")
                && Some(reply.session.as_str()) == self.active_session_id.as_deref()
            {
                let mode = crate::runtime::cli_permissions::CliPermissionMode::AcceptEdits;
                crate::runtime::cli_permissions::CliPermissionChoice::save(
                    self.runtime_root
                        .parent()
                        .ok_or("CLI settings root is unavailable.")?,
                    mode,
                )?;
                self.applied_permission = Some(mode);
                events(RuntimeEvent::CliUpdate {
                    session_id: self.active_session_id.clone().unwrap_or_default(),
                    update: json!({"sessionUpdate":"permission_mode_update","mode":mode}),
                })?;
            }
            self.send(&json!({"jsonrpc":"2.0","id":reply.rpc_id,"result":reply.response}))?;
            events(RuntimeEvent::CliInteractionResolved(reply.id))?;
        }
        Ok(())
    }
}

pub(super) fn observation(
    message: &Value,
    active: Option<&str>,
    events: &RuntimeEventSink<'_>,
) -> Result<bool, String> {
    let Some(update) = message.pointer("/params/update") else {
        return Ok(false);
    };
    let Some(kind) = update.get("sessionUpdate").and_then(Value::as_str) else {
        return Ok(false);
    };
    let Some(session) = message
        .pointer("/params/sessionId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256)
    else {
        return Ok(false);
    };
    let displayed = matches!(
        kind,
        "tool_call"
            | "tool_call_update"
            | "plan"
            | "available_commands_update"
            | "current_mode_update"
            | "config_option_update"
            | "session_info_update"
            | "background_tasks"
            | "task_completed"
            | "subagent_spawned"
            | "subagent_progress"
            | "subagent_finished"
            | "retry_state"
            | "auto_compact_started"
            | "auto_compact_completed"
            | "auto_compact_failed"
            | "goal_updated"
    ) || (active != Some(session)
        && matches!(kind, "agent_message_chunk" | "agent_thought_chunk"));
    if !displayed {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(update).map_err(|e| e.to_string())?.len();
    if bytes > 2 * 1024 * 1024 {
        events(RuntimeEvent::CliUpdate {
            session_id: session.into(),
            update: json!({"sessionUpdate":"display_limit","text":"CLI activity exceeded the display limit. Open the CLI session for full output."}),
        })?;
    } else {
        events(RuntimeEvent::CliUpdate {
            session_id: session.into(),
            update: update.clone(),
        })?;
    }
    Ok(true)
}
