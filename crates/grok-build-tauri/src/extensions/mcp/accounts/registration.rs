//! Public-client registration is an explicit, journaled sign-in effect.
use super::{auth_contract::IssuerMetadata, http};
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;
use tauri::Url;

pub(crate) fn request_body(redirect: &Url) -> Result<Vec<u8>, String> {
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("127.0.0.1")
        || redirect.port().is_none()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.query().is_some()
        || redirect.fragment().is_some()
        || !redirect.path().starts_with("/gbplus/mcp/")
    {
        return Err("MCP registration requires the app's owned loopback redirect.".into());
    }
    serde_json::to_vec(
        &json!({"client_name":"GB Plus","redirect_uris":[redirect.as_str()],
        "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
        "token_endpoint_auth_method":"none"}),
    )
    .map_err(|_| "Cannot encode MCP registration.".into())
}

pub(crate) fn client_id(bytes: &[u8], redirect: &Url) -> Result<String, String> {
    if bytes.len() > 16 * 1024 {
        return Err("MCP registration reply exceeded its bound.".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "MCP registration reply is not valid JSON.")?;
    if value.get("client_secret").is_some()
        || value.get("error").is_some()
        || value
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            != Some("none")
        || value.get("redirect_uris") != Some(&json!([redirect.as_str()]))
    {
        return Err("MCP registration changed the public-client or redirect contract.".into());
    }
    let id = value
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .ok_or("MCP registration did not return a bounded client identity.")?;
    Ok(id.into())
}

pub(crate) async fn register(
    issuer: &IssuerMetadata,
    redirect: &Url,
    cancel: &AtomicBool,
    before_send: &mut impl FnMut() -> Result<(), String>,
) -> Result<String, String> {
    let endpoint = issuer
        .registration
        .as_ref()
        .ok_or("This issuer requires a pre-registered public client ID.")?;
    let body = request_body(redirect)?;
    before_send()?;
    let response = http::request(endpoint, Some(http::RequestBody::Json(body)), cancel).await?;
    if response.status != 201 {
        return Err(
            "MCP client registration was not confirmed; it will not be automatically repeated."
                .into(),
        );
    }
    client_id(&response.body, redirect)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_preserves_the_exact_public_client_and_callback_contract() {
        let redirect = Url::parse("http://127.0.0.1:38127/gbplus/mcp/issuer/callback").unwrap();
        let request: Value = serde_json::from_slice(&request_body(&redirect).unwrap()).unwrap();
        assert_eq!(request["token_endpoint_auth_method"], "none");
        assert!(request.get("client_secret").is_none());
        let valid = json!({"client_id":"registered-public-client","token_endpoint_auth_method":"none","redirect_uris":[redirect.as_str()]});
        assert_eq!(
            client_id(&serde_json::to_vec(&valid).unwrap(), &redirect).unwrap(),
            "registered-public-client"
        );
        for (key, value) in [
            ("client_secret", json!("must-not-store")),
            ("token_endpoint_auth_method", json!("client_secret_basic")),
            ("redirect_uris", json!(["http://127.0.0.1:9/other"])),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(client_id(&serde_json::to_vec(&bad).unwrap(), &redirect).is_err());
        }
    }
}
