//! App-owned MCP tools, frozen per run and approved independently of the model.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use grok_build_plus_host::{
    McpCatalog, McpEffectClass, McpOperation, McpPermissionDecision, PlusExtensionTool,
};
use serde_json::{Value, json};

use crate::contracts::ProjectId;
use crate::runtime::cancel::RuntimeCancelHandle;

use super::approvals::{ApprovalRequest, McpApprovals};
use super::config::ServerSpec;
use super::invocations::InvocationJournal;
use super::permission_store::PermissionStore;
use super::service::{ServiceAdmission, ServiceContext};
mod interactions;
use interactions::CallScope;

#[derive(Clone)]
pub(crate) struct McpBroker {
    root: PathBuf,
    pub(crate) accounts: super::accounts::Accounts,
    pub(crate) approvals: McpApprovals,
    pub(crate) elicitations: super::elicitation::Elicitations,
}

struct FrozenServer {
    spec: ServerSpec,
    catalog: McpCatalog,
    admission: Option<Arc<ServiceAdmission>>,
}

pub(crate) struct McpRunExecutor {
    broker: McpBroker,
    project: ProjectId,
    run: String,
    cancel: RuntimeCancelHandle,
    servers: Vec<FrozenServer>,
    declarations: Vec<PlusExtensionTool>,
    journal: Mutex<InvocationJournal>,
}

impl McpBroker {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            accounts: super::accounts::Accounts::new(root),
            approvals: McpApprovals::default(),
            elicitations: super::elicitation::Elicitations::default(),
        }
    }

    pub(crate) fn prepare(
        &self,
        project: &str,
        run: &str,
        cancel: RuntimeCancelHandle,
        service_context: Option<&ServiceContext>,
    ) -> Result<Option<Arc<McpRunExecutor>>, String> {
        let project = ProjectId::new(project);
        let specs = super::super::ExtensionStore::new(&self.root).enabled_mcp_servers(&project)?;
        if specs.is_empty() {
            return Ok(None);
        }
        cancel.ensure_not_cancelled()?;
        let mut servers = Vec::new();
        let mut declarations = BTreeMap::new();
        for spec in specs {
            let spec = tauri::async_runtime::block_on(
                self.accounts.authorize(spec, &cancel.cancellation_flag()),
            )?;
            let admission = prepare_service(service_context, &spec, &cancel)?;
            let catalog = tauri::async_runtime::block_on(inspect_server(
                &spec,
                admission.clone(),
                cancel.clone(),
            ))?;
            for tool in catalog.tools()? {
                let declaration = PlusExtensionTool {
                    name: tool.app_name().into(),
                    description: tool.description().into(),
                    parameters: tool.input_schema().clone(),
                    fingerprint: tool.fingerprint().into(),
                };
                declaration.validate().map_err(|e| e.to_string())?;
                if declarations
                    .insert(declaration.name.clone(), declaration)
                    .is_some()
                    || declarations.len() > 32
                {
                    return Err(
                        "The enabled MCP catalog is duplicated or exceeds 32 tools per run.".into(),
                    );
                }
            }
            servers.push(FrozenServer {
                spec,
                catalog,
                admission,
            });
        }
        let journal = InvocationJournal::open(&self.root, &project, run)?;
        Ok(Some(Arc::new(McpRunExecutor {
            broker: self.clone(),
            project,
            run: run.into(),
            cancel,
            servers,
            declarations: declarations.into_values().collect(),
            journal: Mutex::new(journal),
        })))
    }
}

impl McpRunExecutor {
    pub(crate) fn declarations(&self) -> Vec<PlusExtensionTool> {
        self.declarations.clone()
    }

    pub(crate) fn execute(
        &self,
        invocation: &str,
        name: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        self.cancel.ensure_not_cancelled()?;
        if invocation.is_empty()
            || invocation.len() > 512
            || !arguments.is_object()
            || serde_json::to_vec(arguments)
                .map_err(super::super::failure)?
                .len()
                > 64 * 1024
        {
            return Err("MCP invocation identity or arguments exceeded their bound.".into());
        }
        let server = self
            .servers
            .iter()
            .find(|server| server.catalog.resolve(name).is_ok())
            .ok_or("MCP tool is outside this run's enabled app catalog.")?;
        let tool = server.catalog.resolve(name)?;
        let id = super::super::digest(invocation.as_bytes());
        let binding = super::super::digest(
            &serde_json::to_vec(&json!([
                &self.project,
                &self.run,
                tool.fingerprint(),
                arguments
            ]))
            .map_err(super::super::failure)?,
        );
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| "MCP run ownership is unavailable.")?;
        if let Some(result) = journal.previous(&id, &binding)? {
            return Ok(result);
        }
        let policy = PermissionStore::new(&self.broker.root, &self.project);
        if policy
            .read()?
            .decision(&server.catalog, name, McpEffectClass::Unclassified)?
            == McpPermissionDecision::Denied
        {
            return Ok(refusal(
                "This MCP tool is blocked in this project. No call was submitted.",
            ));
        }
        let ticket = self.broker.approvals.begin(ApprovalRequest {
            kind: super::approvals::ApprovalKind::Mcp,
            project: self.project.clone(),
            run: self.run.clone(),
            server: server.spec.name.clone(),
            endpoint: server.spec.endpoint.clone(),
            tool: tool.clone(),
            arguments: arguments.clone(),
        })?;
        if !ticket.wait(|| self.cancel.cancelled())? {
            return Ok(refusal(
                "The user declined this MCP call. No call was submitted.",
            ));
        }
        // A fresh connection must reproduce the exact reviewed catalog binding.
        // User approval time never consumes this connection's request deadline.
        tauri::async_runtime::block_on(self.execute_approved(
            server,
            name,
            arguments,
            &id,
            &binding,
            &mut journal,
        ))
    }

    async fn execute_approved(
        &self,
        server: &FrozenServer,
        name: &str,
        arguments: &Value,
        id: &str,
        binding: &str,
        journal: &mut InvocationJournal,
    ) -> Result<Value, String> {
        let flag = self.cancel.cancellation_flag();
        let connection_id = super::super::digest(
            format!("{id}:{}", crate::runtime::types::unix_time_millis()).as_bytes(),
        );
        let mut scope = CallScope::new(
            super::elicitation::Context {
                project: self.project.clone(),
                run: self.run.clone(),
                connection: connection_id.clone(),
                server: server.spec.name.clone(),
                endpoint: server.spec.endpoint.clone(),
            },
            self.broker.elicitations.clone(),
            Arc::clone(&flag),
            server.admission.clone(),
            server.spec.authorization.clone(),
            self.cancel.clone(),
        )
        .await?;
        let connection = Arc::clone(&scope.connection);
        let outcome = async {
        connection.initialize(&flag).await?;
        scope.listen(Arc::clone(&flag));
        let catalog = connection
            .catalog(self.project.clone(), server.spec.catalog_identity().into(), &flag)
            .await?;
        let tool = catalog.resolve(name)?;
        if tool.fingerprint() != server.catalog.resolve(name)?.fingerprint() {
            return Err("MCP schema changed after its run catalog was frozen. Review it again; nothing was submitted.".into());
        }
        let result = connection
            .request(
                McpOperation::CallTool,
                json!({"name":tool.wire_name(),"arguments":arguments}),
                &flag,
                    &mut |request| {
                        self.cancel.ensure_not_cancelled()?;
                        if let Some(admission) = &server.admission {
                            admission.revalidate_authority()?;
                        }
                    if PermissionStore::new(&self.broker.root, &self.project)
                        .read()?
                        .decision(&catalog, name, McpEffectClass::Unclassified)?
                        == McpPermissionDecision::Denied
                    {
                        return Err("MCP policy was revoked before submission.".into());
                    }
                    journal.intent(id, binding, &connection_id, request.as_str())?;
                    scope.admit();
                    Ok(())
                },
            )
            .await?;
        journal.complete(id, &result)?;
        Ok(result)
        }.await;
        scope.finish().await?;
        outcome
    }
}

pub(super) fn prepare_service(
    context: Option<&ServiceContext>,
    spec: &ServerSpec,
    cancel: &RuntimeCancelHandle,
) -> Result<Option<Arc<ServiceAdmission>>, String> {
    spec.local
        .as_ref()
        .map(|local| {
            ServiceAdmission::prepare(
                context.ok_or("Local MCP requires an app-owned project/workspace binding.")?,
                spec,
                local,
                cancel,
            )
        })
        .transpose()
}

pub(super) async fn inspect_server(
    spec: &ServerSpec,
    admission: Option<Arc<ServiceAdmission>>,
    cancel: RuntimeCancelHandle,
) -> Result<McpCatalog, String> {
    let flag = cancel.cancellation_flag();
    let context = super::elicitation::Context {
        project: spec.project.clone(),
        run: "catalog-inspection".into(),
        connection: super::super::digest(
            format!(
                "{}:{}",
                spec.identity,
                crate::runtime::types::unix_time_millis()
            )
            .as_bytes(),
        ),
        server: spec.name.clone(),
        endpoint: spec.endpoint.clone(),
    };
    let mut scope = CallScope::new(
        context,
        super::elicitation::Elicitations::default(),
        Arc::clone(&flag),
        admission,
        spec.authorization.clone(),
        cancel,
    )
    .await?;
    let connection = Arc::clone(&scope.connection);
    let outcome = async {
        connection.initialize(&flag).await?;
        scope.listen(Arc::clone(&flag));
        connection
            .catalog(spec.project.clone(), spec.catalog_identity().into(), &flag)
            .await
    }
    .await;
    scope.finish().await?;
    outcome
}

fn refusal(text: &str) -> Value {
    json!({"isError":true,"content":[{"type":"text","text":text}]})
}

#[cfg(test)]
mod tests;
