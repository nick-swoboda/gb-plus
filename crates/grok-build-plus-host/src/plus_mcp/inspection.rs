//! Bounded catalog-only inspection shared by the app and live interoperability probe.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde_json::json;

use super::{McpCatalog, McpEvent, McpHttpsConnection, McpOperation, McpProtocolVersion};
use crate::ProjectId;

/// Read an explicitly selected server's complete tool catalog. This does not
/// invoke tools, request a model, discover credentials, enable an extension,
/// open URLs or collect form inputs. Elicitation is declined during inspection.
/// Project and server identity must come from the app's installed-content state.
///
/// # Errors
/// Refuses malformed metadata, unsupported capabilities/authentication, changed
/// catalogs, cancellation, or the absolute 45-second inspection deadline.
pub async fn inspect_mcp_https_catalog(
    endpoint: &str,
    project: ProjectId,
    server_identity: String,
    cancelled: &AtomicBool,
) -> Result<(McpCatalog, McpProtocolVersion), String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        // Validate app-issued identities before initiating any network traffic.
        let mut catalog = McpCatalog::new(project, server_identity)?;
        let (connection, mut observations) = McpHttpsConnection::new(endpoint)?;
        let connection = Arc::new(connection);
        let responder_connection = Arc::clone(&connection);
        let responder = tokio::spawn(async move {
            while let Some(event) = observations.recv().await {
                if let McpEvent::Elicitation { identity, .. } = event
                    && responder_connection
                        .answer_elicitation(&identity, &json!({"action":"decline"}))
                        .is_err()
                {
                    let _ = responder_connection.interrupt();
                    return;
                }
            }
        });
        let _scope = InspectionScope {
            connection: Arc::clone(&connection),
            responder,
        };
        let version = connection.initialize(cancelled).await?;
        let mut cursor = None;
        loop {
            let parameters = cursor
                .as_ref()
                .map_or_else(|| json!({}), |cursor| json!({"cursor":cursor}));
            let page = connection
                .request(McpOperation::ListTools, parameters, cancelled, &mut |_| {
                    Ok(())
                })
                .await?;
            cursor = catalog.push_page(cursor.as_deref(), &page)?;
            if cursor.is_none() {
                return Ok((catalog, version));
            }
        }
    })
    .await
    .map_err(|_| "MCP catalog inspection exceeded its deadline.")?
}

struct InspectionScope {
    connection: Arc<McpHttpsConnection>,
    responder: tokio::task::JoinHandle<()>,
}
impl Drop for InspectionScope {
    fn drop(&mut self) {
        let _ = self.connection.interrupt();
        self.responder.abort();
    }
}
