//! Draft pure MCP OAuth metadata validation. This module performs no network I/O,
//! browser navigation, Keychain access, registration or token exchange.
use serde_json::Value;
use tauri::Url;

const MAX_METADATA: usize = 64 * 1024;
const MAX_URL: usize = 4096;
const MAX_SCOPES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct Endpoint(Url, String);
impl PartialEq for Endpoint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Endpoint {}
impl Endpoint {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if text.len() > MAX_URL || text.chars().any(char::is_control) {
            return Err("OAuth endpoint exceeded its bound.".into());
        }
        let url = Url::parse(text).map_err(|_| "OAuth endpoint is invalid.")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
        {
            return Err("OAuth discovery endpoints require credential-free HTTPS without query or fragment.".into());
        }
        Ok(Self(url, text.to_owned()))
    }
    pub(crate) fn url(&self) -> &Url {
        &self.0
    }
    pub(crate) fn original(&self) -> &str {
        &self.1
    }
    pub(crate) fn text(&self) -> &str {
        self.0.as_str()
    }
}

pub(crate) struct ResourceMetadata {
    pub(crate) resource: Endpoint,
    pub(crate) issuers: Vec<Endpoint>,
    pub(crate) scopes: Vec<String>,
}
pub(crate) struct IssuerMetadata {
    pub(crate) issuer: Endpoint,
    pub(crate) authorization: Endpoint,
    pub(crate) token: Endpoint,
    pub(crate) registration: Option<Endpoint>,
    pub(crate) response_issuer_required: bool,
}

fn metadata(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_METADATA {
        return Err("OAuth metadata exceeded its byte bound.".into());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "OAuth metadata is not bounded JSON.")?;
    if !value.is_object() {
        return Err("OAuth metadata must be an object.".into());
    }
    let mut nodes = 4096;
    bounded_value(&value, 0, &mut nodes)?;
    Ok(value)
}
fn bounded_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > 16 || *nodes == 0 {
        return Err("OAuth metadata complexity exceeded its bound.".into());
    }
    *nodes -= 1;
    match value {
        Value::Array(values) => {
            for v in values {
                bounded_value(v, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for v in values.values() {
                bounded_value(v, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OAuth metadata omitted {key}."))
}
fn values(v: &Value, key: &str, maximum: usize, required: bool) -> Result<Vec<String>, String> {
    let Some(value) = v.get(key) else {
        return if required {
            Err(format!("OAuth metadata omitted {key}."))
        } else {
            Ok(Vec::new())
        };
    };
    let list = value
        .as_array()
        .ok_or_else(|| format!("OAuth {key} must be an array."))?;
    if list.len() > maximum || (required && list.is_empty()) {
        return Err(format!("OAuth {key} length refused."));
    }
    let mut result = Vec::new();
    for value in list {
        let item = value
            .as_str()
            .ok_or("OAuth list contains a non-string value.")?;
        if item.is_empty()
            || item.len() > MAX_URL
            || item.chars().any(char::is_control)
            || result.iter().any(|known| known == item)
        {
            return Err("OAuth list entry is invalid or duplicated.".into());
        }
        result.push(item.into());
    }
    Ok(result)
}

pub(crate) fn resource_metadata(
    endpoint: &Endpoint,
    bytes: &[u8],
) -> Result<ResourceMetadata, String> {
    let value = metadata(bytes)?;
    let resource = Endpoint::parse(text(&value, "resource")?)?;
    if &resource != endpoint {
        return Err("OAuth protected resource does not match this MCP server.".into());
    }
    let issuers = values(&value, "authorization_servers", 8, true)?
        .iter()
        .map(|s| Endpoint::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    if issuers
        .iter()
        .enumerate()
        .any(|(i, issuer)| issuers[..i].contains(issuer))
    {
        return Err("MCP metadata declared ambiguous issuer aliases.".into());
    }
    let methods = values(&value, "bearer_methods_supported", 8, false)?;
    if !methods.is_empty() && !methods.iter().any(|m| m == "header") {
        return Err("MCP authorization requires header tokens.".into());
    }
    let scopes = validate_scopes(values(&value, "scopes_supported", MAX_SCOPES, false)?)?;
    Ok(ResourceMetadata {
        resource,
        issuers,
        scopes,
    })
}

pub(crate) fn issuer_metadata(expected: &Endpoint, bytes: &[u8]) -> Result<IssuerMetadata, String> {
    let value = metadata(bytes)?;
    let issuer = Endpoint::parse(text(&value, "issuer")?)?;
    if &issuer != expected || issuer.original() != expected.original() {
        return Err("OAuth issuer metadata changed identity.".into());
    }
    if !values(&value, "code_challenge_methods_supported", 8, true)?
        .iter()
        .any(|s| s == "S256")
        || !values(&value, "response_types_supported", 8, true)?
            .iter()
            .any(|s| s == "code")
    {
        return Err("OAuth requires authorization code with PKCE S256.".into());
    }
    let grants = values(&value, "grant_types_supported", 8, false)?;
    if !grants.is_empty() && !grants.iter().any(|s| s == "authorization_code") {
        return Err("OAuth issuer does not support authorization code.".into());
    }
    let methods = values(&value, "token_endpoint_auth_methods_supported", 8, true)?;
    if !methods.iter().any(|s| s == "none") {
        return Err("This MCP sign-in requires an admitted public client.".into());
    }
    let authorization = Endpoint::parse(text(&value, "authorization_endpoint")?)?;
    let token = Endpoint::parse(text(&value, "token_endpoint")?)?;
    let registration = value
        .get("registration_endpoint")
        .map(|v| {
            v.as_str()
                .ok_or("OAuth registration endpoint is invalid.")
                .and_then(|s| {
                    Endpoint::parse(s).map_err(|_| "OAuth registration endpoint is invalid.")
                })
        })
        .transpose()?;
    let response_issuer_required = match value.get("authorization_response_iss_parameter_supported")
    {
        None => false,
        Some(Value::Bool(v)) => *v,
        _ => return Err("OAuth issuer-response metadata is invalid.".into()),
    };
    Ok(IssuerMetadata {
        issuer,
        authorization,
        token,
        registration,
        response_issuer_required,
    })
}

pub(crate) fn validate_scopes(scopes: Vec<String>) -> Result<Vec<String>, String> {
    if scopes.len() > MAX_SCOPES {
        return Err("OAuth scope count exceeded its bound.".into());
    }
    let mut total = 0;
    let mut result = Vec::new();
    for scope in scopes {
        total += scope.len();
        if scope.is_empty()
            || scope.len() > 128
            || total > 2048
            || !scope
                .bytes()
                .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
            || result.contains(&scope)
        {
            return Err("OAuth scope spelling or length refused.".into());
        }
        result.push(scope);
    }
    result.sort();
    Ok(result)
}

// The caller validates and pins every resolved network address independently
// before fetching any of these candidates. Parsed HTTPS alone is not SSRF proof.
pub(crate) fn resource_discovery(endpoint: &Endpoint) -> Result<Vec<Endpoint>, String> {
    let mut rooted = endpoint.0.clone();
    rooted.set_path("/.well-known/oauth-protected-resource");
    let mut path = rooted.clone();
    path.set_path(&format!(
        "/.well-known/oauth-protected-resource{}",
        endpoint.0.path().trim_end_matches('/')
    ));
    let mut urls = vec![Endpoint::parse(path.as_str())?];
    if path != rooted {
        urls.push(Endpoint::parse(rooted.as_str())?);
    }
    Ok(urls)
}
pub(crate) fn issuer_discovery(issuer: &Endpoint) -> Result<Vec<Endpoint>, String> {
    let suffix = issuer.0.path().trim_end_matches('/');
    let mut urls = Vec::new();
    for prefix in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let mut url = issuer.0.clone();
        url.set_path(&format!("{prefix}{suffix}"));
        urls.push(Endpoint::parse(url.as_str())?);
    }
    if !suffix.is_empty() {
        let mut url = issuer.0.clone();
        url.set_path(&format!("{suffix}/.well-known/openid-configuration"));
        urls.push(Endpoint::parse(url.as_str())?);
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }
    #[test]
    fn derived_discovery_paths_follow_the_selected_resource_and_issuer() {
        let endpoint = Endpoint::parse("https://server.example/public/mcp").unwrap();
        assert_eq!(
            resource_discovery(&endpoint)
                .unwrap()
                .iter()
                .map(Endpoint::text)
                .collect::<Vec<_>>(),
            vec![
                "https://server.example/.well-known/oauth-protected-resource/public/mcp",
                "https://server.example/.well-known/oauth-protected-resource"
            ]
        );
        let issuer = Endpoint::parse("https://auth.example/tenant1").unwrap();
        assert_eq!(
            issuer_discovery(&issuer)
                .unwrap()
                .iter()
                .map(Endpoint::text)
                .collect::<Vec<_>>(),
            vec![
                "https://auth.example/.well-known/oauth-authorization-server/tenant1",
                "https://auth.example/.well-known/openid-configuration/tenant1",
                "https://auth.example/tenant1/.well-known/openid-configuration"
            ]
        );
    }
    #[test]
    fn crossed_resources_issuers_and_pkce_downgrades_refuse() {
        let resource = Endpoint::parse("https://server.example/mcp").unwrap();
        assert!(resource_metadata(&resource,&bytes(&json!({"resource":"https://other.example/mcp","authorization_servers":["https://auth.example"]}))).is_err());
        let issuer = Endpoint::parse("https://auth.example").unwrap();
        let valid = json!({"issuer":"https://auth.example","authorization_endpoint":"https://auth.example/authorize","token_endpoint":"https://auth.example/token","code_challenge_methods_supported":["S256"],"response_types_supported":["code"],"token_endpoint_auth_methods_supported":["none"]});
        issuer_metadata(&issuer, &bytes(&valid)).unwrap();
        for (field, value) in [
            ("issuer", json!("https://other.example")),
            ("code_challenge_methods_supported", json!(["plain"])),
            ("response_types_supported", json!(["token"])),
            (
                "token_endpoint_auth_methods_supported",
                json!(["client_secret_basic"]),
            ),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(issuer_metadata(&issuer, &bytes(&bad)).is_err());
        }
    }
    #[test]
    fn credential_bearing_urls_and_ambiguous_scopes_refuse() {
        for url in [
            "http://server.example",
            "https://user:secret@server.example",
            "https://server.example?token=secret",
            "https://server.example/#secret",
        ] {
            assert!(Endpoint::parse(url).is_err());
        }
        for scopes in [
            vec!["read".into(), "read".into()],
            vec!["read write".into()],
            vec!["read\nwrite".into()],
        ] {
            assert!(validate_scopes(scopes).is_err());
        }
        assert_eq!(
            validate_scopes(vec!["write".into(), "read".into()]).unwrap(),
            vec!["read", "write"]
        );
    }
}
