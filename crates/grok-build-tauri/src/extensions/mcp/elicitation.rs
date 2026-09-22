//! User interactions are independent of the model and remain memory-only.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::contracts::ProjectId;

mod form;

static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Default)]
pub(crate) struct Elicitations(Arc<Shared>);
#[derive(Default)]
struct Shared {
    entries: Mutex<BTreeMap<String, Entry>>,
    changed: Condvar,
}

#[derive(Clone)]
pub(super) struct Context {
    pub(super) project: ProjectId,
    pub(super) run: String,
    pub(super) connection: String,
    pub(super) server: String,
    pub(super) endpoint: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct View {
    id: String,
    commitment: String,
    project_id: ProjectId,
    run_id: String,
    server: String,
    endpoint: String,
    message: String,
    request: Request,
    opened: bool,
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Request {
    Form { fields: Vec<form::Field> },
    Url { url: String, host: String },
}

struct Entry {
    context: Context,
    peer: Value,
    view: View,
    form: Option<form::Form>,
    deadline: Instant,
    answer: Option<Value>,
}

impl Elicitations {
    pub(super) fn begin(
        &self,
        context: Context,
        peer: Value,
        params: &Value,
    ) -> Result<Ticket, String> {
        if !super::super::valid_digest(&context.connection)
            || context.project.as_str().is_empty()
            || context.project.as_str().len() > 256
            || context.run.is_empty()
            || context.run.len() > 256
            || params.to_string().len() > 64 * 1024
            || peer.to_string().len() > 256
        {
            return Err("MCP interaction has no bounded app-owned scope.".into());
        }
        let message = params["message"]
            .as_str()
            .filter(|message| !message.trim().is_empty() && message.len() <= 16 * 1024)
            .ok_or("MCP interaction has no bounded message.")?
            .to_owned();
        let (request, form) = parse_request(params)?;
        let commitment = super::super::digest(
            &serde_json::to_vec(&json!([
                context.project,
                context.run,
                context.connection,
                context.endpoint,
                peer,
                params
            ]))
            .map_err(super::super::failure)?,
        );
        let id = super::super::digest(
            format!(
                "{commitment}:{}:{}:{}",
                std::process::id(),
                crate::runtime::types::unix_time_millis(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        let mut entries = self
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        entries.retain(|_, entry| Instant::now() < entry.deadline);
        if entries.len() >= 8
            || entries
                .values()
                .any(|entry| entry.context.connection == context.connection && entry.peer == peer)
        {
            return Err(
                "MCP interaction identity is duplicated or its capacity is occupied.".into(),
            );
        }
        let view = View {
            id: id.clone(),
            commitment: commitment.clone(),
            project_id: context.project.clone(),
            run_id: context.run.clone(),
            server: context.server.clone(),
            endpoint: context.endpoint.clone(),
            message,
            request,
            opened: false,
        };
        entries.insert(
            id.clone(),
            Entry {
                context,
                peer,
                view,
                form,
                deadline: Instant::now() + Duration::from_mins(15),
                answer: None,
            },
        );
        Ok(Ticket {
            owner: self.clone(),
            id,
            commitment,
        })
    }

    pub(crate) fn list(&self, project: &ProjectId) -> Result<Vec<View>, String> {
        let entries = self
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        Ok(entries
            .values()
            .filter(|entry| {
                &entry.context.project == project
                    && entry.answer.is_none()
                    && Instant::now() < entry.deadline
            })
            .map(|entry| entry.view.clone())
            .collect())
    }

    pub(crate) fn answer(
        &self,
        project: &ProjectId,
        id: &str,
        commitment: &str,
        action: &str,
        content: Option<Value>,
    ) -> Result<(), String> {
        let mut entries = self
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        let entry = find(&mut entries, project, id, commitment)?;
        let answer = match action {
            "decline" | "cancel" if content.is_none() => json!({"action":action}),
            "accept" => {
                if let Some(form) = &entry.form {
                    let content = content.ok_or("Review the MCP form values before sending.")?;
                    form.validate(&content)?;
                    json!({"action":"accept","content":content})
                } else if entry.view.opened && content.is_none() {
                    json!({"action":"accept"})
                } else {
                    return Err(
                        "Open the reviewed server link before acknowledging navigation.".into(),
                    );
                }
            }
            _ => {
                return Err(
                    "MCP interaction answer is unsupported or contains unexpected data.".into(),
                );
            }
        };
        entry.answer = Some(answer);
        self.0.changed.notify_all();
        Ok(())
    }

    pub(crate) fn url(
        &self,
        project: &ProjectId,
        id: &str,
        commitment: &str,
    ) -> Result<String, String> {
        let mut entries = self
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        match &find(&mut entries, project, id, commitment)?.view.request {
            Request::Url { url, .. } => Ok(url.clone()),
            Request::Form { .. } => Err("This MCP interaction is not a URL request.".into()),
        }
    }

    pub(crate) fn opened(
        &self,
        project: &ProjectId,
        id: &str,
        commitment: &str,
    ) -> Result<(), String> {
        let mut entries = self
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        let entry = find(&mut entries, project, id, commitment)?;
        if entry.form.is_some() {
            return Err("A form cannot acknowledge browser navigation.".into());
        }
        entry.view.opened = true;
        Ok(())
    }

    pub(super) fn cancel_peer(&self, connection: &str, peer: &Value) {
        if let Ok(mut entries) = self.0.entries.lock() {
            entries
                .retain(|_, entry| entry.context.connection != connection || &entry.peer != peer);
            self.0.changed.notify_all();
        }
    }

    pub(super) fn cancel_connection(&self, connection: &str) {
        if let Ok(mut entries) = self.0.entries.lock() {
            entries.retain(|_, entry| entry.context.connection != connection);
            self.0.changed.notify_all();
        }
    }
}

fn parse_request(params: &Value) -> Result<(Request, Option<form::Form>), String> {
    let mode = match params.get("mode") {
        None => "form",
        Some(Value::String(mode)) => mode.as_str(),
        Some(_) => return Err("MCP interaction mode is malformed.".into()),
    };
    Ok(match mode {
        "form" => {
            let form = form::Form::parse(&params["requestedSchema"])?;
            (
                Request::Form {
                    fields: form.fields.clone(),
                },
                Some(form),
            )
        }
        "url" => {
            let raw = params["url"]
                .as_str()
                .filter(|url| url.len() <= 4096 && !url.chars().any(char::is_control))
                .ok_or("MCP interaction URL is unavailable.")?;
            let url = tauri::Url::parse(raw).map_err(|_| "MCP interaction URL is invalid.")?;
            if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
                return Err(
                    "MCP interaction links require HTTPS without embedded credentials.".into(),
                );
            }
            let host = url
                .host_str()
                .ok_or("MCP interaction URL has no host.")?
                .to_owned();
            (
                Request::Url {
                    url: url.to_string(),
                    host,
                },
                None,
            )
        }
        _ => return Err("Unsupported MCP interaction mode.".into()),
    })
}

fn find<'a>(
    entries: &'a mut BTreeMap<String, Entry>,
    project: &ProjectId,
    id: &str,
    commitment: &str,
) -> Result<&'a mut Entry, String> {
    entries
        .get_mut(id)
        .filter(|entry| {
            &entry.context.project == project
                && entry.view.commitment == commitment
                && entry.answer.is_none()
                && Instant::now() < entry.deadline
        })
        .ok_or(
            "MCP interaction expired, changed, was answered or belongs to another project.".into(),
        )
}

pub(super) struct Ticket {
    owner: Elicitations,
    id: String,
    commitment: String,
}
impl Ticket {
    pub(super) fn wait(self, cancelled: impl Fn() -> bool) -> Result<Value, String> {
        let mut entries = self
            .owner
            .0
            .entries
            .lock()
            .map_err(|_| "MCP interactions are unavailable.")?;
        loop {
            if cancelled() {
                return Err("MCP interaction was cancelled.".into());
            }
            let entry = entries
                .get(&self.id)
                .filter(|entry| {
                    entry.view.commitment == self.commitment && Instant::now() < entry.deadline
                })
                .ok_or("MCP interaction ended or expired.")?;
            if let Some(answer) = &entry.answer {
                return Ok(answer.clone());
            }
            entries = self
                .owner
                .0
                .changed
                .wait_timeout(entries, Duration::from_millis(100))
                .map_err(|_| "MCP interaction wait was interrupted.")?
                .0;
        }
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.owner.0.entries.lock() {
            entries.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(connection: char) -> Context {
        Context {
            project: ProjectId::new("project"),
            run: "run".into(),
            connection: connection.to_string().repeat(64),
            server: "server".into(),
            endpoint: "https://example.test/mcp".into(),
        }
    }
    fn params() -> Value {
        json!({"message":"Choose a name","requestedSchema":{"type":"object","properties":{"name":{"type":"string","minLength":2}},"required":["name"]}})
    }
    #[test]
    fn answers_are_project_bound_one_use_and_cancelled_in_their_own_connection() {
        let book = Elicitations::default();
        let ctx = context('a');
        let first = book.begin(ctx.clone(), json!(1), &params()).unwrap();
        let second = book.begin(context('b'), json!(1), &params()).unwrap();
        assert!(
            book.answer(
                &ProjectId::new("other"),
                &first.id,
                &first.commitment,
                "accept",
                Some(json!({"name":"Alex"}))
            )
            .is_err()
        );
        assert!(
            book.answer(
                &ctx.project,
                &first.id,
                &first.commitment,
                "accept",
                Some(json!({"name":"A"}))
            )
            .is_err()
        );
        book.cancel_peer(&ctx.connection, &json!(1));
        assert!(first.wait(|| false).is_err());
        assert_eq!(book.list(&ctx.project).unwrap().len(), 1);
        book.answer(
            &ctx.project,
            &second.id,
            &second.commitment,
            "accept",
            Some(json!({"name":"Alex"})),
        )
        .unwrap();
        assert!(
            book.answer(&ctx.project, &second.id, &second.commitment, "cancel", None)
                .is_err()
        );
        assert_eq!(
            second.wait(|| false).unwrap(),
            json!({"action":"accept","content":{"name":"Alex"}})
        );
        assert!(book.list(&ctx.project).unwrap().is_empty());
    }
    #[test]
    fn url_requests_require_explicit_open_and_connection_stop_clears_ui() {
        let book = Elicitations::default();
        let ctx = context('a');
        let params = json!({"mode":"url","message":"Review this server link","url":"https://example.test/approve?state=fixture","elicitationId":"remote"});
        let ticket = book.begin(ctx.clone(), json!(1), &params).unwrap();
        assert!(
            book.answer(&ctx.project, &ticket.id, &ticket.commitment, "accept", None)
                .is_err()
        );
        assert_eq!(
            book.url(&ctx.project, &ticket.id, &ticket.commitment)
                .unwrap(),
            "https://example.test/approve?state=fixture"
        );
        book.opened(&ctx.project, &ticket.id, &ticket.commitment)
            .unwrap();
        book.answer(&ctx.project, &ticket.id, &ticket.commitment, "accept", None)
            .unwrap();
        assert_eq!(ticket.wait(|| false).unwrap(), json!({"action":"accept"}));
        let ticket = book.begin(ctx.clone(), json!(2), &params).unwrap();
        book.cancel_connection(&ctx.connection);
        assert!(ticket.wait(|| false).is_err());
        assert!(book.list(&ctx.project).unwrap().is_empty());
        assert!(
            book.begin(
                ctx,
                json!(3),
                &json!({"mode":"url","message":"unsafe","url":"file:///tmp/fixture"})
            )
            .is_err()
        );
    }
}
