//! Resolve a project-owned service admission from frozen app records.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use grok_build_plus_host::{
    ContainedMcpConnection, McpStdioConnection, PlusCommandSecurityPreference, PlusGuestLifecycle,
    PlusSessionStore,
};
use grok_build_plus_host::{
    ContainedServiceRequest, ServiceLimits, ServicePurpose, ServiceScope, ServiceSnapshot,
    ServiceSnapshotFile, service_environment,
};

use crate::contracts::ProjectId;
use crate::runtime::cancel::RuntimeCancelHandle;

use super::config::{LocalSpec, ServerSpec};

#[derive(Clone)]
pub(crate) struct ServiceContext {
    pub(in crate::extensions) project: ProjectId,
    pub(in crate::extensions) operation: String,
    workspace: PathBuf,
    pub(in crate::extensions) state: PathBuf,
}

impl ServiceContext {
    /// Caller has already resolved project/workspace/run identity from app state.
    pub(crate) fn new(
        project: ProjectId,
        operation: String,
        workspace: PathBuf,
        state: PathBuf,
    ) -> Self {
        Self {
            project,
            operation,
            workspace,
            state,
        }
    }

    pub(crate) fn bind_run(&mut self, project: &str, run: &str) -> Result<(), String> {
        if self.project.as_str() != project {
            return Err("Service context belongs to another project.".into());
        }
        run.clone_into(&mut self.operation);
        Ok(())
    }
}

pub(in crate::extensions) struct ServiceAdmission {
    request: ContainedServiceRequest,
    context: ServiceContext,
    workspace: ServiceSnapshot,
    extension: ServiceSnapshot,
    // Drop snapshots before releasing the group ownership lock.
    _views: super::super::service_views::ServiceViews,
}

impl ServiceAdmission {
    pub(in crate::extensions) fn revalidate_authority(&self) -> Result<(), String> {
        check_preference(&self.context.state)
    }
    pub(super) fn prepare(
        context: &ServiceContext,
        spec: &ServerSpec,
        local: &LocalSpec,
        cancel: &RuntimeCancelHandle,
    ) -> Result<Arc<Self>, String> {
        if context.project != spec.project {
            return Err("Local MCP project does not match its app-owned workspace.".into());
        }
        Self::prepare_local(
            context,
            local,
            ServicePurpose::Mcp,
            ServiceLimits::default(),
            cancel,
        )
    }

    pub(in crate::extensions) fn prepare_local(
        context: &ServiceContext,
        local: &LocalSpec,
        purpose: ServicePurpose,
        limits: ServiceLimits,
        cancel: &RuntimeCancelHandle,
    ) -> Result<Arc<Self>, String> {
        cancel.ensure_not_cancelled()?;
        check_preference(&context.state)?;
        let lifecycle = grok_build_plus_host::probe_plus_guest_lifecycle();
        let PlusGuestLifecycle::Ready(target) = &lifecycle else {
            return Err("The managed guest is unavailable for local MCP.".into());
        };
        let profile = grok_build_plus_host::inspect_contained_service_profile(target)?;
        if profile.version != grok_build_plus_host::CONTAINED_SERVICE_PROFILE_VERSION
            || profile.architecture != local.architecture
        {
            return Err("Local MCP requires the admitted staged-service helper and a compatible Linux executable.".into());
        }
        let views = super::super::service_views::ServiceViews::create(&context.state, &|| {
            cancel.cancelled()
        })?;
        let protected = super::super::protected_sources::paths(&context.state)?;
        let workspace = ServiceSnapshot::capture_workspace(
            &context.workspace,
            views.path(),
            "workspace",
            &protected,
            &|| cancel.cancelled(),
        )?;
        let bundle =
            super::super::ExtensionStore::new(&context.state).load_bundle(&local.content)?;
        let files = bundle
            .files
            .iter()
            .map(|(path, blob)| ServiceSnapshotFile {
                path,
                bytes: &blob.bytes,
                executable: blob.executable,
            })
            .collect::<Vec<_>>();
        let extension =
            ServiceSnapshot::from_files(&files, views.path(), "extension", &|| cancel.cancelled())?;
        extension.verify_image(
            Path::new(&local.command),
            local.executable_bytes,
            &local.executable_digest,
            local.architecture,
        )?;
        let request = ContainedServiceRequest {
            schema_version: 1,
            lease_id: "app-admission-pending".into(),
            scope: ServiceScope {
                project_id: context.project.as_str().into(),
                operation_id: context.operation.clone(),
                workspace_digest: workspace.digest().clone(),
                extension_digest: extension.digest().clone(),
                containment_digest: profile.containment_digest,
            },
            purpose,
            executable: format!("/extension/{}", local.command),
            content_root: "/extension".into(),
            executable_digest: local.executable_digest.clone(),
            executable_bytes: local.executable_bytes,
            architecture: local.architecture,
            arguments: local.arguments.clone(),
            environment: service_environment(),
            workspace: "/workspace".into(),
            limits,
        };
        request.validate_shape()?;
        Ok(Arc::new(Self {
            request,
            context: context.clone(),
            workspace,
            extension,
            _views: views,
        }))
    }

    pub(in crate::extensions) fn open_hook(
        &self,
        cancel: &RuntimeCancelHandle,
    ) -> Result<grok_build_plus_host::PlusContainedService, String> {
        if self.request.purpose != ServicePurpose::Hook {
            return Err("Service admission is not a hook lease.".into());
        }
        cancel.ensure_not_cancelled()?;
        check_preference(&self.context.state)?;
        grok_build_plus_host::PlusContainedService::open_tracked(
            self.request.clone(),
            PlusCommandSecurityPreference::Extra,
            &grok_build_plus_host::probe_plus_guest_lifecycle(),
            (&self.workspace, &self.extension),
            &|| cancel.cancelled() || check_preference(&self.context.state).is_err(),
            &mut |proof| cancel.retain_hook_cleanup(proof),
        )
    }

    pub(super) fn open(
        &self,
        cancel: &RuntimeCancelHandle,
    ) -> Result<
        (
            Arc<McpStdioConnection>,
            tauri::async_runtime::Receiver<grok_build_plus_host::McpEvent>,
        ),
        String,
    > {
        cancel.ensure_not_cancelled()?;
        check_preference(&self.context.state)?;
        let lifecycle = grok_build_plus_host::probe_plus_guest_lifecycle();
        let service = ContainedMcpConnection::open_tracked(
            self.request.clone(),
            PlusCommandSecurityPreference::Extra,
            &lifecycle,
            (&self.workspace, &self.extension),
            &|| cancel.cancelled() || check_preference(&self.context.state).is_err(),
            &mut |proof| cancel.retain_hook_cleanup(proof),
        )?;
        let (connection, observations) = McpStdioConnection::from_contained(service)?;
        let connection = Arc::new(connection);
        cancel.retain_service_cleanup(Arc::clone(&connection))?;
        Ok((connection, observations))
    }
}

pub(in crate::extensions) fn check_preference(root: &Path) -> Result<(), String> {
    if PlusSessionStore::from_state_root(root.to_owned()).command_security_preference()
        != PlusCommandSecurityPreference::Extra
    {
        return Err("Turn on Command security before starting a local MCP server.".into());
    }
    Ok(())
}
