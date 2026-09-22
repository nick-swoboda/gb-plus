//! Memory-only authorization-code custody. Provider input cannot choose endpoints.
use super::auth_contract::{Endpoint, IssuerMetadata, validate_scopes};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::time::{Duration, Instant};
use tauri::Url;

const FLOW_LIFETIME: Duration = Duration::from_mins(5);

pub(crate) struct Secret(Vec<u8>);
impl Secret {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty()
            || bytes.len() > 4096
            || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err("OAuth secret value is empty, invalid or oversized.".into());
        }
        Ok(Self(bytes))
    }
    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
    pub(crate) fn text(&self) -> &str {
        std::str::from_utf8(&self.0).expect("validated ASCII")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuthSecret([redacted])")
    }
}

pub(crate) struct Flow {
    issuer: IssuerMetadata,
    resource: Endpoint,
    scopes: Vec<String>,
    client_id: String,
    redirect: Url,
    state: Secret,
    verifier: Secret,
    started: Instant,
    consumed: bool,
}
pub(crate) struct Exchange {
    pub(crate) endpoint: Endpoint,
    pub(crate) body: Secret,
}
impl Flow {
    pub(crate) fn new(
        issuer: IssuerMetadata,
        resource: Endpoint,
        scopes: Vec<String>,
        client_id: String,
        port: u16,
    ) -> Result<Self, String> {
        let mut entropy = [0u8; 64];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut entropy))
            .map_err(|_| "OAuth entropy is unavailable.")?;
        let result = Self::from_entropy(issuer, resource, scopes, client_id, port, &entropy);
        entropy.fill(0);
        result
    }
    fn from_entropy(
        issuer: IssuerMetadata,
        resource: Endpoint,
        scopes: Vec<String>,
        client_id: String,
        port: u16,
        entropy: &[u8; 64],
    ) -> Result<Self, String> {
        if port == 0
            || client_id.is_empty()
            || client_id.len() > 1024
            || client_id.chars().any(char::is_control)
        {
            return Err("OAuth client or redirect binding is invalid.".into());
        }
        let redirect = redirect_uri(&issuer.issuer, port)?;
        Ok(Self {
            issuer,
            resource,
            scopes: validate_scopes(scopes)?,
            client_id,
            redirect,
            state: Secret::new(URL_SAFE_NO_PAD.encode(&entropy[..32]).into_bytes())?,
            verifier: Secret::new(URL_SAFE_NO_PAD.encode(&entropy[32..]).into_bytes())?,
            started: Instant::now(),
            consumed: false,
        })
    }
    pub(crate) fn consumed(&self) -> bool {
        self.consumed
    }
    pub(crate) fn redirect(&self) -> &Url {
        &self.redirect
    }
    pub(crate) fn authorization_url(&self) -> Result<Url, String> {
        self.live()?;
        let mut url = self.issuer.authorization.url().clone();
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect.as_str()),
            ("resource", self.resource.text()),
            ("state", self.state.text()),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                URL_SAFE_NO_PAD
                    .encode(Sha256::digest(&self.verifier.0))
                    .as_str(),
            ),
        ]);
        if !self.scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &self.scopes.join(" "));
        }
        Ok(url)
    }
    fn live(&self) -> Result<(), String> {
        if self.consumed || self.started.elapsed() >= FLOW_LIFETIME {
            Err("OAuth attempt is completed or expired.".into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn accept_callback(&mut self, request: &[u8]) -> Result<Exchange, String> {
        self.live()?;
        let query = callback_query(request, &self.redirect)?;
        let actual = query.get("state").ok_or("OAuth callback omitted state.")?;
        if actual.len() != self.state.0.len()
            || actual
                .bytes()
                .zip(&self.state.0)
                .fold(0u8, |n, (a, b)| n | (a ^ b))
                != 0
        {
            return Err("OAuth callback state does not match.".into());
        }
        if query
            .get("iss")
            .is_some_and(|s| s != self.issuer.issuer.original())
            || (self.issuer.response_issuer_required && !query.contains_key("iss"))
        {
            return Err("OAuth callback issuer does not match.".into());
        }
        // One valid callback owns this attempt even when authorization was denied.
        self.consumed = true;
        if query.contains_key("error") || !query.contains_key("code") {
            return Err("OAuth authorization was refused; start a new explicit attempt.".into());
        }
        let code = Secret::new(query["code"].as_bytes().to_vec())?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("code", code.text()),
                ("code_verifier", self.verifier.text()),
                ("redirect_uri", self.redirect.as_str()),
                ("resource", self.resource.text()),
            ])
            .finish();
        Ok(Exchange {
            endpoint: self.issuer.token.clone(),
            body: Secret::new(body.into_bytes())?,
        })
    }
}

pub(super) fn redirect_uri(issuer: &Endpoint, port: u16) -> Result<Url, String> {
    if port == 0 {
        return Err("OAuth callback port is absent.".into());
    }
    let binding = URL_SAFE_NO_PAD.encode(Sha256::digest(issuer.original().as_bytes()));
    Url::parse(&format!(
        "http://127.0.0.1:{port}/gbplus/mcp/{binding}/callback"
    ))
    .map_err(|_| "OAuth callback binding failed.".into())
}

fn callback_query(request: &[u8], expected: &Url) -> Result<BTreeMap<String, String>, String> {
    if request.len() > 16 * 1024
        || request.windows(4).position(|part| part == b"\r\n\r\n") != request.len().checked_sub(4)
    {
        return Err("OAuth callback framing refused.".into());
    }
    let request = std::str::from_utf8(request).map_err(|_| "OAuth callback is not UTF-8.")?;
    let mut lines = request.split("\r\n");
    let first = lines.next().ok_or("OAuth callback request is absent.")?;
    let mut parts = first.split(' ');
    if parts.next() != Some("GET") {
        return Err("OAuth callback method refused.".into());
    }
    let target = parts.next().ok_or("OAuth callback target is absent.")?;
    if parts.next() != Some("HTTP/1.1")
        || parts.next().is_some()
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.bytes().any(|b| !(0x21..0x7f).contains(&b))
    {
        return Err("OAuth callback target refused.".into());
    }
    if target.split('?').next() != Some(expected.path()) {
        return Err("OAuth callback path changed.".into());
    }
    let url = expected
        .join(target)
        .map_err(|_| "OAuth callback URL is invalid.")?;
    if url.origin() != expected.origin()
        || url.path() != expected.path()
        || url.fragment().is_some()
    {
        return Err("OAuth callback changed its registered redirect.".into());
    }
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or("OAuth callback header is invalid.")?;
        if headers.len() >= 32
            || name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.chars().any(|c| c.is_control() && c != '\t')
            || headers
                .insert(name.to_ascii_lowercase(), value.trim())
                .is_some()
        {
            return Err("OAuth callback headers refused.".into());
        }
    }
    if headers.get("host")
        != Some(
            &format!(
                "127.0.0.1:{}",
                expected.port().ok_or("OAuth callback port is absent.")?
            )
            .as_str(),
        )
        || headers.contains_key("transfer-encoding")
        || headers.get("content-length").is_some_and(|s| *s != "0")
    {
        return Err("OAuth callback authority or body refused.".into());
    }
    let mut query = BTreeMap::new();
    for (name, value) in url.query_pairs() {
        if query.len() >= 8
            || name.len() > 64
            || value.len() > 4096
            || value.chars().any(char::is_control)
            || query
                .insert(name.into_owned(), value.into_owned())
                .is_some()
        {
            return Err("OAuth callback parameters refused.".into());
        }
    }
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn flow() -> Flow {
        flow_with_issuer("https://issuer.example/")
    }
    fn flow_with_issuer(issuer_text: &str) -> Flow {
        let issuer = Endpoint::parse(issuer_text).unwrap();
        let metadata=super::super::auth_contract::issuer_metadata(&issuer,&serde_json::to_vec(&json!({"issuer":issuer_text,"authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","code_challenge_methods_supported":["S256"],"response_types_supported":["code"],"token_endpoint_auth_methods_supported":["none"],"authorization_response_iss_parameter_supported":true})).unwrap()).unwrap();
        Flow::from_entropy(
            metadata,
            Endpoint::parse("https://mcp.example/service").unwrap(),
            vec!["read".into()],
            "registered-client".into(),
            38127,
            &std::array::from_fn(|i| u8::try_from(i).unwrap()),
        )
        .unwrap()
    }
    fn callback(flow: &Flow, query: &str) -> Vec<u8> {
        format!(
            "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1:38127\r\n\r\n",
            flow.redirect.path(),
            query
        )
        .into_bytes()
    }
    #[test]
    fn pkce_resource_and_single_use_code_are_bound_before_exchange() {
        let mut f = flow();
        let url = f.authorization_url().unwrap();
        let q = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(q["resource"], "https://mcp.example/service");
        assert_eq!(q["code_challenge_method"], "S256");
        assert!(!url.as_str().contains(f.verifier.text()));
        let bytes = callback(
            &f,
            &format!(
                "state={}&iss=https%3A%2F%2Fissuer.example%2F&code=synthetic-code",
                f.state.text()
            ),
        );
        let exchange = f.accept_callback(&bytes).unwrap();
        assert_eq!(exchange.endpoint.text(), "https://issuer.example/token");
        assert!(
            exchange
                .body
                .text()
                .contains("resource=https%3A%2F%2Fmcp.example%2Fservice")
        );
        assert!(!format!("{:?}", exchange.body).contains("synthetic-code"));
        assert!(f.accept_callback(&bytes).is_err());
        assert!(f.authorization_url().is_err());
    }
    #[test]
    fn issuer_without_trailing_slash_is_preserved_from_metadata() {
        let mut f = flow_with_issuer("https://issuer.example");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("state", f.state.text()),
                ("iss", "https://issuer.example"),
                ("code", "synthetic"),
            ])
            .finish();
        let bytes = callback(&f, &query);
        assert!(f.accept_callback(&bytes).is_ok());
    }
    #[test]
    fn callback_issuer_requires_exact_metadata_spelling() {
        for issuer in ["https://issuer.example", "https://ISSUER.example/"] {
            let mut f = flow();
            let query = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("state", f.state.text()),
                    ("iss", issuer),
                    ("code", "synthetic"),
                ])
                .finish();
            let bytes = callback(&f, &query);
            assert!(
                f.accept_callback(&bytes).is_err(),
                "normalized issuer must not match: {issuer}"
            );
        }
    }
    #[test]
    fn invalid_state_issuer_host_duplicate_query_and_body_refuse() {
        for case in 0..6 {
            let mut f = flow();
            let q = format!(
                "state={}&iss=https%3A%2F%2Fissuer.example%2F&code=synthetic-code",
                f.state.text()
            );
            let original = String::from_utf8(callback(&f, &q)).unwrap();
            let changed = match case {
                0 => original.replace(f.state.text(), "wrong"),
                1 => original.replace("issuer.example", "other.example"),
                2 => original.replace("Host: 127.0.0.1:38127", "Host: localhost:38127"),
                3 => original.replace("&code=", "&state=duplicate&code="),
                4 => original.replace("\r\n\r\n", "\r\nContent-Length: 4\r\n\r\nbody"),
                _ => original.replace("GET /", "GET //evil.example/"),
            };
            assert!(
                f.accept_callback(changed.as_bytes()).is_err(),
                "case {case}"
            );
        }
    }
}
