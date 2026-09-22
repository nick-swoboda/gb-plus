//! Read-only discovery precedes user review; only declared issuers may be selected.
use super::{auth_contract as contract, challenge, http};
use std::sync::atomic::AtomicBool;

pub(crate) struct Discovery {
    pub(crate) resource: contract::ResourceMetadata,
    pub(crate) scopes: Vec<String>,
}

pub(crate) async fn discover(
    endpoint: &contract::Endpoint,
    cancel: &AtomicBool,
) -> Result<Discovery, String> {
    let initial = http::request(endpoint, None, cancel).await?;
    let challenged = challenge::parse(
        &initial
            .challenges
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    let candidates = match challenged
        .as_ref()
        .and_then(|c| c.resource_metadata.clone())
    {
        Some(endpoint) => vec![endpoint],
        None => contract::resource_discovery(endpoint)?,
    };
    for candidate in candidates {
        let reply = http::request(&candidate, None, cancel).await?;
        if reply.status == 404 || reply.status == 405 {
            continue;
        }
        if reply.status != 200 {
            return Err("MCP protected-resource metadata is unavailable.".into());
        }
        let resource = contract::resource_metadata(endpoint, &reply.body)?;
        let scopes = challenged
            .as_ref()
            .and_then(|c| c.scopes.clone())
            .unwrap_or_else(|| resource.scopes.clone());
        return Ok(Discovery { resource, scopes });
    }
    Err("MCP server did not provide usable protected-resource metadata.".into())
}

pub(crate) async fn select_issuer(
    discovery: &Discovery,
    selected: &str,
    cancel: &AtomicBool,
) -> Result<contract::IssuerMetadata, String> {
    let selected = contract::Endpoint::parse(selected)?;
    let selected = discovery
        .resource
        .issuers
        .iter()
        .find(|known| **known == selected)
        .ok_or("OAuth issuer was not declared by this MCP resource.")?;
    for candidate in contract::issuer_discovery(selected)? {
        let reply = http::request(&candidate, None, cancel).await?;
        if reply.status == 404 || reply.status == 405 {
            continue;
        }
        if reply.status != 200 {
            return Err("OAuth issuer metadata is unavailable.".into());
        }
        return contract::issuer_metadata(selected, &reply.body);
    }
    Err("MCP issuer did not provide supported authorization metadata.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuer_selection_cannot_invent_another_authority() {
        let discovery = Discovery {
            resource: contract::ResourceMetadata {
                resource: contract::Endpoint::parse("https://resource.example/mcp").unwrap(),
                issuers: vec![contract::Endpoint::parse("https://issuer.example/").unwrap()],
                scopes: vec![],
            },
            scopes: vec![],
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(select_issuer(
            &discovery,
            "https://127.0.0.1/",
            &AtomicBool::new(false),
        ));
        assert!(result.err().unwrap().contains("not declared"));
    }
}
