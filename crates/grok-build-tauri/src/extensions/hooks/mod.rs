//! Project-enabled hooks add constraints to the ordinary app tool boundary.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use grok_build_plus_host::{McpCatalog, ServiceLimits, ServiceObservation, ServicePurpose};
use serde_json::{Value, json};

use crate::runtime::cancel::RuntimeCancelHandle;
use crate::runtime::types::RuntimeInvocationScope;

use super::mcp::approvals::{ApprovalRequest, McpApprovals};
use super::mcp::service::{ServiceAdmission, ServiceContext};
use config::{Decision, HookSpec};

pub(super) mod config;

#[derive(Debug)]
pub(crate) enum HookGateDecision {
    Proceed,
    Refuse(String),
}

/// The runtime binds this capability from app state. Tool arguments cannot
/// choose a project, installed hook, workspace, process or credential.
pub(crate) trait ToolHookExecutor: Send + Sync {
    fn before_tool(
        &self,
        scope: &RuntimeInvocationScope,
        name: &str,
        arguments: &Value,
    ) -> Result<HookGateDecision, String>;
}

struct HookRunExecutor {
    context: ServiceContext,
    specs: Vec<HookSpec>,
    cancel: RuntimeCancelHandle,
    approvals: McpApprovals,
    calls: Mutex<usize>,
}

/// Frozen restrictions may follow children; this carries no MCP credential or grant.
#[derive(Clone)]
pub(crate) struct FrozenHookPolicy {
    project: crate::contracts::ProjectId,
    state: std::path::PathBuf,
    specs: Vec<HookSpec>,
    approvals: McpApprovals,
}
impl FrozenHookPolicy {
    #[cfg(test)]
    pub(crate) fn fixture(project: crate::contracts::ProjectId, state: std::path::PathBuf) -> Self {
        Self {
            project,
            state,
            approvals: McpApprovals::default(),
            specs: vec![HookSpec {
                identity: "a".repeat(64),
                matcher: vec!["read_file".into()],
                timeout_seconds: 1,
                local: crate::extensions::mcp::config::LocalSpec {
                    content: "b".repeat(64),
                    command: "bin/fixture".into(),
                    arguments: Vec::new(),
                    executable_digest: grok_build_plus_host::Digest::sha256(b"fixture"),
                    executable_bytes: 7,
                    architecture: grok_build_plus_host::ServiceArchitecture::LinuxAarch64,
                },
            }],
        }
    }
    pub(crate) fn freeze(
        context: &ServiceContext,
        approvals: Option<McpApprovals>,
    ) -> Result<Option<Self>, String> {
        let specs = super::ExtensionStore::new(&context.state).enabled_hooks(&context.project)?;
        if specs.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            project: context.project.clone(),
            state: context.state.clone(),
            specs,
            approvals: approvals
                .ok_or("Enabled hook restrictions require the app's review boundary.")?,
        }))
    }
    pub(crate) fn bind(
        &self,
        context: &ServiceContext,
        cancel: RuntimeCancelHandle,
    ) -> Result<Arc<dyn ToolHookExecutor>, String> {
        if self.project != context.project || self.state != context.state {
            return Err(
                "Frozen hook restrictions crossed their owning project or state boundary.".into(),
            );
        }
        prepare_frozen(context, cancel, self.approvals.clone(), self.specs.clone())
    }
}

fn prepare_frozen(
    context: &ServiceContext,
    cancel: RuntimeCancelHandle,
    approvals: McpApprovals,
    specs: Vec<HookSpec>,
) -> Result<Arc<dyn ToolHookExecutor>, String> {
    cancel.ensure_not_cancelled()?;
    super::mcp::service::check_preference(&context.state)?;
    let lifecycle = grok_build_plus_host::probe_plus_guest_lifecycle();
    let grok_build_plus_host::PlusGuestLifecycle::Ready(target) = lifecycle else {
        return Err("The managed guest is unavailable for enabled command hooks.".into());
    };
    let profile = grok_build_plus_host::inspect_contained_service_profile(&target)?;
    if profile.version != grok_build_plus_host::CONTAINED_SERVICE_PROFILE_VERSION
        || specs
            .iter()
            .any(|spec| spec.local.architecture != profile.architecture)
    {
        return Err(
            "Enabled hooks require the admitted service helper and compatible Linux executables."
                .into(),
        );
    }
    Ok(Arc::new(HookRunExecutor {
        context: context.clone(),
        specs,
        cancel,
        approvals,
        calls: Mutex::new(0),
    }))
}

impl ToolHookExecutor for HookRunExecutor {
    fn before_tool(
        &self,
        scope: &RuntimeInvocationScope,
        name: &str,
        arguments: &Value,
    ) -> Result<HookGateDecision, String> {
        scope.validate()?;
        if scope.project_id != self.context.project
            || scope.run_id.as_str() != self.context.operation
            || name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !arguments.is_object()
        {
            return Err("Hook invocation crossed its app-owned run binding.".into());
        }
        if !self.specs.iter().any(|spec| spec.matches(name)) {
            self.cancel.ensure_not_cancelled()?;
            return Ok(HookGateDecision::Proceed);
        }
        let bytes = match hook_input(name, arguments) {
            Ok(bytes) => bytes,
            Err(reason) => return self.refuse_or_interrupt(reason),
        };
        for spec in self.specs.iter().filter(|spec| spec.matches(name)) {
            self.cancel.ensure_not_cancelled()?;
            {
                let mut calls = self
                    .calls
                    .lock()
                    .map_err(|_| "Hook budget is unavailable.")?;
                if *calls >= 64 {
                    return Err("This run reached its 64 hook invocation limit.".into());
                }
                *calls += 1;
            }
            let decision = match self.execute(spec, &bytes) {
                Ok(decision) => decision,
                Err(reason) => return self.refuse_or_interrupt(reason),
            };
            match decision {
                Decision::Continue => {}
                Decision::Deny => {
                    return Ok(HookGateDecision::Refuse("An enabled project hook denied this tool call. No tool effect was dispatched.".into()));
                }
                Decision::Ask => match self.ask(spec, name, arguments) {
                    Ok(true) => {}
                    Ok(false) => return self.refuse_or_interrupt("The user declined the enabled hook's review request. The tool was refused.".into()),
                    Err(reason) => return self.refuse_or_interrupt(reason),
                },
            }
        }
        self.cancel.ensure_not_cancelled()?;
        Ok(HookGateDecision::Proceed)
    }
}

impl HookRunExecutor {
    fn refuse_or_interrupt(&self, reason: String) -> Result<HookGateDecision, String> {
        if self.cancel.cancelled() || !self.cancel.cleanup_proven() {
            Err(reason)
        } else {
            Ok(HookGateDecision::Refuse(reason))
        }
    }
    fn execute(&self, spec: &HookSpec, input: &[u8]) -> Result<Decision, String> {
        let limits = ServiceLimits {
            frame_bytes: 64 * 1024,
            input_bytes: 64 * 1024,
            output_bytes: 64 * 1024,
            readiness_ms: spec.timeout_seconds * 1000,
            lifetime_ms: spec.timeout_seconds * 1000,
            scratch_bytes: 16 * 1024 * 1024,
            processes: 8,
            memory_bytes: 128 * 1024 * 1024,
        };
        let admission = ServiceAdmission::prepare_local(
            &self.context,
            &spec.local,
            ServicePurpose::Hook,
            limits,
            &self.cancel,
        )?;
        let mut service = match admission.open_hook(&self.cancel) {
            Ok(service) => service,
            Err(error) => {
                if !self.cancel.cleanup_proven() {
                    let _ = self.cancel.request_cancel();
                }
                return Err(error);
            }
        };
        let deadline = Instant::now() + Duration::from_secs(spec.timeout_seconds);
        let mut output = Vec::new();
        let mut sent = false;
        let outcome = (|| loop {
            self.cancel.ensure_not_cancelled()?;
            admission.revalidate_authority()?;
            if Instant::now() >= deadline {
                return Err("Enabled hook timed out. The tool was refused.".into());
            }
            match service.poll()? {
                Some(ServiceObservation::Started { .. }) if !sent => {
                    service.ready()?;
                    service.send(input)?;
                    service.close_input()?;
                    sent = true;
                }
                Some(ServiceObservation::Stdout { bytes }) if sent => {
                    if output.len().saturating_add(bytes.len()) > 16 * 1024 {
                        return Err("Enabled hook exceeded its output bound.".into());
                    }
                    output.extend_from_slice(&bytes);
                }
                Some(ServiceObservation::Stderr { .. }) => {}
                Some(ServiceObservation::Terminated {
                    reason,
                    exit_code,
                    cleanup_proven,
                }) => {
                    if !sent
                        || !cleanup_proven
                        || reason != grok_build_plus_host::ServiceTermination::Exited
                    {
                        return Err("Enabled hook did not prove complete cleanup.".into());
                    }
                    return config::decision(&output, exit_code);
                }
                Some(_) => return Err("Enabled hook returned an invalid service event.".into()),
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        })();
        let cleaned = service.stop();
        if cleaned.is_err() && !self.cancel.cleanup_proven() {
            let _ = self.cancel.request_cancel();
        }
        cleaned?;
        outcome
    }

    fn ask(&self, spec: &HookSpec, name: &str, arguments: &Value) -> Result<bool, String> {
        // Reuse the app's one-use exact-argument approval tickets. This is a
        // hook review, and does not mint MCP or built-in tool authority.
        let mut catalog = McpCatalog::new(self.context.project.clone(), spec.identity.clone())?;
        catalog.push_page(None, &json!({"tools":[{"name":name,
            "description":"An enabled project hook requests review before normal app tool permissions are checked.",
            "inputSchema":{"type":"object"}}]}))?;
        let tool = catalog
            .tools()?
            .next()
            .ok_or("Hook review metadata is unavailable.")?
            .clone();
        let ticket = self.approvals.begin(ApprovalRequest {
            kind: super::mcp::approvals::ApprovalKind::Hook,
            project: self.context.project.clone(),
            run: self.context.operation.clone(),
            server: "Enabled project hook".into(),
            endpoint: format!("contained hook · {}", spec.identity),
            tool,
            arguments: arguments.clone(),
        })?;
        ticket.wait(|| self.cancel.cancelled())
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    #[derive(Default)]
    pub(crate) struct Deny(pub(crate) Mutex<usize>);

    impl ToolHookExecutor for Deny {
        fn before_tool(
            &self,
            scope: &RuntimeInvocationScope,
            _: &str,
            _: &Value,
        ) -> Result<HookGateDecision, String> {
            scope.validate()?;
            *self.0.lock().unwrap() += 1;
            Ok(HookGateDecision::Refuse(
                "The fixture hook denied the call.".into(),
            ))
        }
    }

    pub(crate) struct Allow;

    pub(crate) struct Interrupt;

    impl ToolHookExecutor for Interrupt {
        fn before_tool(
            &self,
            _: &RuntimeInvocationScope,
            _: &str,
            _: &Value,
        ) -> Result<HookGateDecision, String> {
            Err("The fixture hook has uncertain cleanup.".into())
        }
    }

    impl ToolHookExecutor for Allow {
        fn before_tool(
            &self,
            scope: &RuntimeInvocationScope,
            _: &str,
            _: &Value,
        ) -> Result<HookGateDecision, String> {
            scope.validate()?;
            Ok(HookGateDecision::Proceed)
        }
    }
}

fn hook_input(name: &str, arguments: &Value) -> Result<Vec<u8>, String> {
    // Raw high-power payloads are not granted to an extension merely by
    // enabling a hook. These hooks can still match and deny the tool name.
    let private = name.starts_with("browser_")
        || name.starts_with("desktop_")
        || name.starts_with("gbext_")
        || name.starts_with("app_agent_")
        || name.starts_with("app_workflow_");
    let input = json!({"hook_event_name":"PreToolUse", "tool_name":name,
        "tool_input":if private { json!({}) } else { arguments.clone() },
        "tool_input_unavailable":private});
    let mut bytes = serde_json::to_vec(&input).map_err(super::failure)?;
    bytes.push(b'\n');
    if bytes.len() > 64 * 1024 {
        return Err("Hook input exceeds 64 KiB. The tool was refused.".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
