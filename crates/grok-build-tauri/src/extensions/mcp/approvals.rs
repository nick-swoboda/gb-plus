//! One-use, memory-only approvals bound to the exact app run and tool arguments.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use crate::contracts::ProjectId;

const MAX_PENDING: usize = 8;
const WAIT_LIMIT: Duration = Duration::from_mins(15);
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Default)]
pub(crate) struct McpApprovals(Arc<Shared>);

#[derive(Default)]
struct Shared {
    pending: Mutex<BTreeMap<String, Pending>>,
    changed: Condvar,
}

struct Pending {
    view: ApprovalView,
    decision: Option<bool>,
    deadline: Instant,
}

/// Only app code constructs this request. None of its authority fields are
/// accepted back from the frontend when the user answers.
pub(crate) struct ApprovalRequest {
    pub(crate) kind: ApprovalKind,
    pub(crate) project: ProjectId,
    pub(crate) run: String,
    pub(crate) server: String,
    pub(crate) endpoint: String,
    pub(crate) tool: grok_build_plus_host::McpTool,
    pub(crate) arguments: Value,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ApprovalKind {
    Mcp,
    Hook,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApprovalView {
    kind: ApprovalKind,
    id: String,
    project_id: ProjectId,
    run_id: String,
    server: String,
    endpoint: String,
    tool: grok_build_plus_host::McpTool,
    arguments: Value,
    commitment: String,
}

impl McpApprovals {
    pub(crate) fn begin(&self, request: ApprovalRequest) -> Result<ApprovalTicket, String> {
        let encoded = serde_json::to_vec(&request.arguments).map_err(super::super::failure)?;
        if request.project.as_str().is_empty()
            || request.project.as_str().len() > 256
            || request.run.is_empty()
            || request.run.len() > 256
            || request.run.chars().any(char::is_control)
            || request.server.len() > 128
            || request.endpoint.len() > 4096
            || !request.arguments.is_object()
            || encoded.len() > 64 * 1024
        {
            return Err("MCP approval has an invalid scope or argument bound.".into());
        }
        let commitment = super::super::digest(
            &serde_json::to_vec(&serde_json::json!([
                "GB Plus MCP call approval v1",
                request.kind,
                request.project,
                request.run,
                request.tool.app_name(),
                request.tool.fingerprint(),
                request.endpoint,
                request.arguments
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
        let mut pending = self
            .0
            .pending
            .lock()
            .map_err(|_| "MCP approvals are unavailable.")?;
        pending.retain(|_, entry| Instant::now() < entry.deadline);
        if pending.len() >= MAX_PENDING {
            return Err("MCP approval capacity is occupied.".into());
        }
        pending.insert(
            id.clone(),
            Pending {
                view: ApprovalView {
                    kind: request.kind,
                    id: id.clone(),
                    project_id: request.project,
                    run_id: request.run,
                    server: request.server,
                    endpoint: request.endpoint,
                    tool: request.tool,
                    arguments: request.arguments,
                    commitment: commitment.clone(),
                },
                decision: None,
                deadline: Instant::now() + WAIT_LIMIT,
            },
        );
        Ok(ApprovalTicket {
            approvals: self.clone(),
            id,
            commitment,
        })
    }

    pub(crate) fn list(&self, project: &ProjectId) -> Result<Vec<ApprovalView>, String> {
        let pending = self
            .0
            .pending
            .lock()
            .map_err(|_| "MCP approvals are unavailable.")?;
        Ok(pending
            .values()
            .filter(|entry| {
                &entry.view.project_id == project
                    && entry.decision.is_none()
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
        allow: bool,
    ) -> Result<(), String> {
        let mut pending = self
            .0
            .pending
            .lock()
            .map_err(|_| "MCP approvals are unavailable.")?;
        let entry = pending
            .get_mut(id)
            .filter(|entry| {
                &entry.view.project_id == project
                    && entry.view.commitment == commitment
                    && entry.decision.is_none()
                    && Instant::now() < entry.deadline
            })
            .ok_or("MCP approval expired, changed or belongs to another project.")?;
        entry.decision = Some(allow);
        self.0.changed.notify_all();
        Ok(())
    }
}

pub(crate) struct ApprovalTicket {
    approvals: McpApprovals,
    id: String,
    commitment: String,
}

impl ApprovalTicket {
    /// Waiting owns no backend mutex. User wait time is separate from the
    /// subsequent server-call deadline; cancellation always wins over approval.
    pub(crate) fn wait(self, cancelled: impl Fn() -> bool) -> Result<bool, String> {
        let mut pending = self
            .approvals
            .0
            .pending
            .lock()
            .map_err(|_| "MCP approvals are unavailable.")?;
        loop {
            if cancelled() {
                return Err("MCP call cancelled before submission.".into());
            }
            let entry = pending
                .get(&self.id)
                .filter(|entry| entry.view.commitment == self.commitment)
                .ok_or("MCP approval is no longer available.")?;
            if Instant::now() >= entry.deadline {
                return Err("MCP call approval expired; no tool was submitted.".into());
            }
            match entry.decision {
                Some(decision) => return Ok(decision),
                None => {
                    pending = self
                        .approvals
                        .0
                        .changed
                        .wait_timeout(pending, Duration::from_millis(100))
                        .map_err(|_| "MCP approval wait was interrupted.")?
                        .0;
                }
            }
        }
    }
}

impl Drop for ApprovalTicket {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.approvals.0.pending.lock() {
            pending.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> ApprovalRequest {
        let mut catalog =
            grok_build_plus_host::McpCatalog::new(ProjectId::new("project"), "a".repeat(64))
                .unwrap();
        catalog.push_page(None, &json!({"tools":[{"name":"write","description":"untrusted", "inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}]})).unwrap();
        let tool = catalog.tools().unwrap().next().unwrap().clone();
        ApprovalRequest {
            kind: ApprovalKind::Mcp,
            project: ProjectId::new("project"),
            run: "run".into(),
            server: "server".into(),
            endpoint: "https://example.test/mcp".into(),
            tool,
            arguments: json!({"value":"PRIVATE FIXTURE"}),
        }
    }

    #[test]
    fn approval_is_one_use_exact_and_project_bound_even_for_read_only_hints() {
        let approvals = McpApprovals::default();
        let ticket = approvals.begin(request()).unwrap();
        let view = approvals
            .list(&ProjectId::new("project"))
            .unwrap()
            .pop()
            .unwrap();
        assert!(approvals.list(&ProjectId::new("other")).unwrap().is_empty());
        assert!(
            approvals
                .answer(&ProjectId::new("other"), &view.id, &view.commitment, true)
                .is_err()
        );
        assert!(
            approvals
                .answer(&view.project_id, &view.id, "changed", true)
                .is_err()
        );
        approvals
            .answer(&view.project_id, &view.id, &view.commitment, true)
            .unwrap();
        assert!(
            approvals
                .answer(&view.project_id, &view.id, &view.commitment, true)
                .is_err()
        );
        ticket.wait(|| false).unwrap();
        assert!(approvals.list(&view.project_id).unwrap().is_empty());
        assert!(
            approvals
                .answer(&view.project_id, &view.id, &view.commitment, true)
                .is_err()
        );
    }

    #[test]
    fn stop_or_dropped_owner_revokes_a_granted_ticket_and_argument_changes_change_identity() {
        let approvals = McpApprovals::default();
        let first = approvals.begin(request()).unwrap();
        let mut changed = request();
        changed.arguments = json!({"value":"different"});
        let second = approvals.begin(changed).unwrap();
        assert_ne!(first.commitment, second.commitment);
        let views = approvals.list(&ProjectId::new("project")).unwrap();
        for view in &views {
            approvals
                .answer(&view.project_id, &view.id, &view.commitment, true)
                .unwrap();
        }
        assert!(first.wait(|| true).is_err());
        drop(second);
        assert!(approvals.0.pending.lock().unwrap().is_empty());
    }
}
