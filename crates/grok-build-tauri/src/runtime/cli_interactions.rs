//! Run-owned native CLI questions and permission responses. Payloads stay in memory.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CliInteraction {
    pub(crate) id: u64,
    pub(crate) session_id: String,
    pub(crate) kind: String,
    pub(crate) request: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum CliAnswer {
    Cancel,
    Permission {
        option_id: String,
    },
    Questions {
        answers: BTreeMap<String, Vec<String>>,
        notes: BTreeMap<String, String>,
    },
    ChatAboutThis,
    SkipInterview,
}

struct Pending {
    view: CliInteraction,
    rpc_id: Value,
    response: Option<Value>,
}

pub(crate) struct CliReply {
    pub(crate) id: u64,
    pub(crate) rpc_id: Value,
    pub(crate) response: Value,
    pub(crate) session: String,
}

#[derive(Default)]
struct State {
    closed: bool,
    pending: Vec<Pending>,
}

#[derive(Clone, Default)]
pub(crate) struct CliInteractions(Arc<Mutex<State>>);
static NEXT_INTERACTION: AtomicU64 = AtomicU64::new(1);

impl CliInteractions {
    pub(crate) fn waiting(&self) -> Result<bool, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "CLI interaction state is unavailable.")?
            .pending
            .iter()
            .any(|pending| pending.response.is_none()))
    }

    pub(crate) fn register(
        &self,
        method: &str,
        rpc_id: &Value,
        params: &Value,
    ) -> Result<CliInteraction, String> {
        if serde_json::to_vec(params).map_err(|e| e.to_string())?.len() > 2 * 1024 * 1024 {
            return Err(
                "CLI permission preview exceeds the display limit; request refused.".into(),
            );
        }
        let kind = if method == "session/request_permission" {
            validate_permission(params)?;
            "permission"
        } else {
            validate_questions(params)?;
            "questions"
        };
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 256)
            .ok_or("CLI interaction has no valid session identity.")?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| "CLI interaction state is unavailable.")?;
        if state.closed
            || state.pending.len() >= 16
            || state.pending.iter().any(|p| p.rpc_id == *rpc_id)
        {
            return Err("CLI interaction is stale, duplicated or over capacity.".into());
        }
        let id = NEXT_INTERACTION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| "CLI interaction IDs exhausted.")?;
        let view = CliInteraction {
            id,
            session_id: session_id.into(),
            kind: kind.into(),
            request: params.clone(),
        };
        state.pending.push(Pending {
            view: view.clone(),
            rpc_id: rpc_id.clone(),
            response: None,
        });
        Ok(view)
    }

    pub(crate) fn snapshot(&self) -> Result<Vec<CliInteraction>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "CLI interaction state is unavailable.")?
            .pending
            .iter()
            .filter(|p| p.response.is_none())
            .map(|p| p.view.clone())
            .collect())
    }

    pub(crate) fn answer(&self, id: u64, answer: CliAnswer) -> Result<(), String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "CLI interaction state is unavailable.")?;
        if state.closed {
            return Err("This CLI run has ended.".into());
        }
        let pending = state
            .pending
            .iter_mut()
            .find(|p| p.view.id == id && p.response.is_none())
            .ok_or("This CLI question is no longer waiting for an answer.")?;
        pending.response = Some(response(&pending.view, answer)?);
        Ok(())
    }

    pub(crate) fn take_ready(&self, cancel: bool) -> Result<Vec<CliReply>, String> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| "CLI interaction state is unavailable.")?;
        let mut ready = Vec::new();
        for pending in &mut state.pending {
            if cancel {
                pending.response = Some(response(&pending.view, CliAnswer::Cancel)?);
            }
            if let Some(reply) = pending.response.take() {
                ready.push(CliReply {
                    id: pending.view.id,
                    rpc_id: pending.rpc_id.clone(),
                    response: reply,
                    session: pending.view.session_id.clone(),
                });
            }
        }
        state
            .pending
            .retain(|p| !ready.iter().any(|reply| reply.id == p.view.id));
        Ok(ready)
    }

    pub(crate) fn close(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
            state.pending.clear();
        }
    }
}

fn validate_permission(params: &Value) -> Result<(), String> {
    let choices = params
        .get("options")
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty() && rows.len() <= 16)
        .ok_or("CLI permission options are invalid.")?;
    let mut ids = std::collections::BTreeSet::new();
    for option in choices {
        let id = option
            .get("optionId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() <= 256)
            .ok_or("CLI permission option identity is invalid.")?;
        if (id == "allow-edits-session" && option["kind"] != "allow_always")
            || !ids.insert(id)
            || option
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|v| v.len() > 1024)
            || !matches!(
                option.get("kind").and_then(Value::as_str),
                Some("allow_once" | "allow_always" | "reject_once" | "reject_always")
            )
        {
            return Err("CLI permission options are ambiguous or unsupported.".into());
        }
    }
    Ok(())
}

fn validate_questions(params: &Value) -> Result<(), String> {
    let questions = params
        .get("questions")
        .and_then(Value::as_array)
        .filter(|rows| !rows.is_empty() && rows.len() <= 16)
        .ok_or("CLI questions are invalid.")?;
    let mut names = std::collections::BTreeSet::new();
    for question in questions {
        let title = question
            .get("question")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 8192)
            .ok_or("CLI question text is invalid.")?;
        let options = question
            .get("options")
            .and_then(Value::as_array)
            .filter(|rows| rows.len() <= 32)
            .ok_or("CLI question options are invalid.")?;
        if !names.insert(title)
            || options.iter().any(|option| {
                option
                    .get("label")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.is_empty() || s.len() > 1024)
            })
        {
            return Err("CLI questions are ambiguous or oversized.".into());
        }
    }
    Ok(())
}

fn response(view: &CliInteraction, answer: CliAnswer) -> Result<Value, String> {
    if view.kind == "permission" {
        return match answer {
            CliAnswer::Cancel => Ok(json!({"outcome":{"outcome":"cancelled"}})),
            CliAnswer::Permission { option_id } => {
                if !view.request["options"].as_array().is_some_and(|choices| {
                    choices.iter().any(|choice| choice["optionId"] == option_id)
                }) {
                    return Err("The CLI did not offer that permission choice.".into());
                }
                Ok(json!({"outcome":{"outcome":"selected","optionId":option_id}}))
            }
            _ => Err("A question answer cannot grant a CLI permission.".into()),
        };
    }
    match answer {
        CliAnswer::Cancel => Ok(json!({"outcome":"cancelled"})),
        CliAnswer::Questions { answers, notes } => question_response(view, &answers, &notes),
        CliAnswer::ChatAboutThis | CliAnswer::SkipInterview if view.request["mode"] == "plan" => {
            Ok(
                json!({"outcome":if matches!(answer,CliAnswer::ChatAboutThis) {"chat_about_this"} else {"skip_interview"},"partial_answers":{}}),
            )
        }
        _ => Err("The CLI did not offer that question action.".into()),
    }
}

fn question_response(
    view: &CliInteraction,
    answers: &BTreeMap<String, Vec<String>>,
    notes: &BTreeMap<String, String>,
) -> Result<Value, String> {
    let questions = view.request["questions"]
        .as_array()
        .ok_or("CLI questions disappeared.")?;
    let mut annotations = serde_json::Map::new();
    for (name, values) in answers {
        let question = questions
            .iter()
            .find(|q| q["question"] == *name)
            .ok_or("Answer names an unknown CLI question.")?;
        if values.len() > 32
            || values.is_empty()
            || (values.len() > 1
                && question["multiSelect"] != true
                && question["multi_select"] != true)
        {
            return Err("CLI answer selection is invalid.".into());
        }
        for value in values {
            if value != "Other"
                && !question["options"]
                    .as_array()
                    .is_some_and(|options| options.iter().any(|o| o["label"] == *value))
            {
                return Err("Answer includes a choice the CLI did not offer.".into());
            }
        }
        let preview = (values.len() == 1)
            .then(|| {
                question["options"]
                    .as_array()
                    .and_then(|options| options.iter().find(|o| o["label"] == values[0]))
                    .and_then(|option| option.get("preview"))
                    .cloned()
            })
            .flatten();
        annotations.insert(
            name.clone(),
            json!({"notes":notes.get(name),"preview":preview}),
        );
    }
    if notes
        .iter()
        .any(|(key, value)| !answers.contains_key(key) || value.len() > 16 * 1024)
    {
        return Err("CLI answer notes are invalid or too long.".into());
    }
    Ok(json!({"outcome":"accepted","answers":answers,"annotations":annotations}))
}
