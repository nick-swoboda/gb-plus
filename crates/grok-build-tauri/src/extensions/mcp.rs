//! Explicit metadata inspection; no tool execution or implicit component enablement.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use grok_build_plus_host::{
    McpCatalog, McpEffectClass, McpPermissionBook, McpPermissionDecision, McpPermissionReview,
    McpTool, McpToolPolicy,
};
use serde::Serialize;
#[cfg(test)]
use serde_json::json;

use crate::contracts::ProjectId;

pub(crate) mod accounts;
pub(crate) mod approvals;
pub(crate) mod broker;
pub(in crate::extensions) mod config;
mod connection;
pub(crate) mod elicitation;
mod invocations;
mod permission_store;
pub(crate) mod service;
pub(crate) use config::{ServerSpec, ServerView};
pub(crate) type ServerInventory = Vec<(ServerView, Option<ServerSpec>)>;
pub(super) use config::configuration_available;
pub(super) use config::specs;
use permission_store::PermissionStore;

const MAX_REVIEWS: usize = 8;
static NEXT_REVIEW: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(crate) struct McpReviews {
    root: PathBuf,
    accounts: accounts::Accounts,
    records: Arc<Mutex<Vec<Arc<Review>>>>,
    inspecting: Arc<AtomicBool>,
}

struct Review {
    id: String,
    server: ServerSpec,
    catalog: McpCatalog,
    created: Instant,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewView {
    pub(crate) review_id: String,
    project_id: ProjectId,
    server_name: String,
    endpoint: String,
    revision: u64,
    tools: Vec<ToolView>,
    tool_execution_enabled: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolView {
    tool: McpTool,
    policy: McpToolPolicy,
}

impl McpReviews {
    pub(crate) fn new(root: &Path, accounts: accounts::Accounts) -> Self {
        Self {
            root: root.to_path_buf(),
            accounts,
            records: Arc::new(Mutex::new(Vec::new())),
            inspecting: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The spec comes only from an installed, revalidated immutable capsule.
    pub(crate) async fn inspect(
        &self,
        spec: ServerSpec,
        context: service::ServiceContext,
    ) -> Result<ReviewView, String> {
        if self.inspecting.swap(true, Ordering::AcqRel) {
            return Err("Another MCP catalog inspection is in progress.".into());
        }
        let _slot = InspectionSlot(&self.inspecting);
        {
            let mut records = self
                .records
                .lock()
                .map_err(|_| "MCP review lock is unavailable.")?;
            records.retain(|review| review.created.elapsed() < Duration::from_mins(15));
            if records.len() >= MAX_REVIEWS {
                return Err("Close an MCP review before inspecting another server.".into());
            }
        }
        let cancel = crate::runtime::cancel::RuntimeCancelHandle::new();
        let spec = self
            .accounts
            .authorize(spec, &cancel.cancellation_flag())
            .await?;
        let preparation = spec.clone();
        let preparing_cancel = cancel.clone();
        let admission = tauri::async_runtime::spawn_blocking(move || {
            broker::prepare_service(Some(&context), &preparation, &preparing_cancel)
        })
        .await
        .map_err(|e| e.to_string())??;
        let catalog = broker::inspect_server(&spec, admission, cancel).await?;
        let id = super::digest(
            format!(
                "GB Plus MCP review v1\0{}\0{}\0{}\0{}",
                spec.identity,
                std::process::id(),
                crate::runtime::types::unix_time_millis(),
                NEXT_REVIEW.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        let review = Arc::new(Review {
            id,
            server: spec,
            catalog,
            created: Instant::now(),
        });
        let book = PermissionStore::new(&self.root, &review.server.project).read()?;
        let view = self.present(&review, &book)?;
        self.records
            .lock()
            .map_err(|_| "MCP review lock is unavailable.")?
            .push(review);
        Ok(view)
    }

    pub(crate) fn change_policy(
        &self,
        project: &ProjectId,
        id: &str,
        revision: u64,
        app_name: &str,
        fingerprint: &str,
        policy: McpToolPolicy,
    ) -> Result<ReviewView, String> {
        let review = self.find(project, id)?;
        let book = PermissionStore::new(&self.root, project).change(
            &review.catalog,
            &McpPermissionReview {
                revision,
                app_name,
                fingerprint,
                policy,
                // Neither server hints nor frontend input can choose this value.
                class: McpEffectClass::Unclassified,
            },
        )?;
        self.present(&review, &book)
    }

    pub(crate) fn close(&self, project: &ProjectId, id: &str) -> Result<(), String> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| "MCP review lock is unavailable.")?;
        records.retain(|review| review.id != id || &review.server.project != project);
        Ok(())
    }

    fn find(&self, project: &ProjectId, id: &str) -> Result<Arc<Review>, String> {
        let records = self
            .records
            .lock()
            .map_err(|_| "MCP review lock is unavailable.")?;
        records
            .iter()
            .find(|r| {
                r.id == id
                    && &r.server.project == project
                    && r.created.elapsed() < Duration::from_mins(15)
            })
            .cloned()
            .ok_or(
                "MCP review expired or belongs to another project. Inspect the server again."
                    .into(),
            )
    }

    fn present(&self, review: &Review, book: &McpPermissionBook) -> Result<ReviewView, String> {
        let mut view = present(review, book)?;
        view.tool_execution_enabled = super::ExtensionStore::new(&self.root)
            .enabled_mcp_servers(&review.server.project)?
            .iter()
            .any(|server| server.identity == review.server.identity);
        Ok(view)
    }
}

fn present(review: &Review, book: &McpPermissionBook) -> Result<ReviewView, String> {
    let tools = review
        .catalog
        .tools()?
        .map(|tool| {
            let decision = book.decision(
                &review.catalog,
                tool.app_name(),
                McpEffectClass::Unclassified,
            )?;
            Ok(ToolView {
                tool: tool.clone(),
                policy: if decision == McpPermissionDecision::Denied {
                    McpToolPolicy::Deny
                } else {
                    McpToolPolicy::Ask
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ReviewView {
        review_id: review.id.clone(),
        project_id: review.server.project.clone(),
        server_name: review.server.name.clone(),
        endpoint: review.server.endpoint.clone(),
        revision: book.revision(),
        tools,
        tool_execution_enabled: false,
    })
}

struct InspectionSlot<'a>(&'a AtomicBool);
impl Drop for InspectionSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests;
