//! The app's permission/journal path is shared by both admitted MCP carriers.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use grok_build_plus_host::{
    McpCatalog, McpEvent, McpHttpsConnection, McpOperation, McpRequestIdentity, McpStdioConnection,
};
use serde_json::Value;

use crate::contracts::ProjectId;
use crate::runtime::cancel::RuntimeCancelHandle;

use super::service::ServiceAdmission;

pub(super) enum Connection {
    Https(McpHttpsConnection),
    Stdio {
        client: Arc<McpStdioConnection>,
        admission: Arc<ServiceAdmission>,
    },
}

impl Connection {
    pub(super) async fn open(
        endpoint: &str,
        admission: Option<Arc<ServiceAdmission>>,
        authorization: Option<Arc<grok_build_plus_host::McpBearerAuthorization>>,
        cancel: RuntimeCancelHandle,
    ) -> Result<(Arc<Self>, tauri::async_runtime::Receiver<McpEvent>), String> {
        let Some(admission) = admission else {
            let (client, observer) = match authorization {
                Some(authorization) => McpHttpsConnection::new_authenticated(authorization)?,
                None => McpHttpsConnection::new(endpoint)?,
            };
            return Ok((Arc::new(Self::Https(client)), observer));
        };
        if authorization.is_some() {
            return Err("Contained MCP cannot receive account credentials.".into());
        }
        let mut guard = Opening {
            cancel: cancel.clone(),
            completed: false,
        };
        let preparation = Arc::clone(&admission);
        let (client, observer) =
            tauri::async_runtime::spawn_blocking(move || preparation.open(&cancel))
                .await
                .map_err(|e| e.to_string())??;
        guard.completed = true;
        Ok((Arc::new(Self::Stdio { client, admission }), observer))
    }

    pub(super) async fn initialize(&self, cancelled: &AtomicBool) -> Result<(), String> {
        match self {
            Self::Https(client) => client.initialize(cancelled).await.map(|_| ()),
            Self::Stdio { client, .. } => client.initialize(cancelled).await.map(|_| ()),
        }
    }
    pub(super) async fn catalog(
        &self,
        project: ProjectId,
        identity: String,
        cancelled: &AtomicBool,
    ) -> Result<McpCatalog, String> {
        match self {
            Self::Https(client) => client.catalog(project, identity, cancelled).await,
            Self::Stdio { client, .. } => client.catalog(project, identity, cancelled).await,
        }
    }
    pub(super) async fn request(
        &self,
        operation: McpOperation,
        parameters: Value,
        cancelled: &AtomicBool,
        before_send: &mut (impl FnMut(&McpRequestIdentity) -> Result<(), String> + Send),
    ) -> Result<Value, String> {
        match self {
            Self::Https(client) => {
                client
                    .request(operation, parameters, cancelled, before_send)
                    .await
            }
            Self::Stdio { client, admission } => {
                admission.revalidate_authority()?;
                client
                    .request(operation, parameters, cancelled, before_send)
                    .await
            }
        }
    }
    pub(super) fn answer_elicitation(
        &self,
        identity: &Value,
        result: &Value,
    ) -> Result<bool, String> {
        match self {
            Self::Https(client) => client.answer_elicitation(identity, result),
            Self::Stdio { client, admission } => {
                admission.revalidate_authority()?;
                client.answer_elicitation(identity, result)
            }
        }
    }
    pub(super) async fn listen(&self, cancelled: &AtomicBool) -> Result<(), String> {
        match self {
            Self::Https(client) => client.listen(cancelled).await.map(|_| ()),
            Self::Stdio { client, admission } => {
                client
                    .monitor_authority(cancelled, &|| admission.revalidate_authority())
                    .await
            }
        }
    }
    pub(super) fn interrupt(&self) {
        match self {
            Self::Https(client) => {
                let _ = client.interrupt();
            }
            Self::Stdio { client, .. } => client.interrupt(),
        }
    }
    pub(super) async fn finish(&self) -> Result<(), String> {
        self.interrupt();
        if let Self::Stdio { client, .. } = self {
            let result = client.stop().await;
            if !client.cleanup_proven() {
                return result.and(Err("Contained MCP cleanup has not been proven.".into()));
            }
        }
        Ok(())
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.interrupt();
    }
}

struct Opening {
    cancel: RuntimeCancelHandle,
    completed: bool,
}
impl Drop for Opening {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.cancel.request_cancel();
        }
    }
}
