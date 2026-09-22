//! Validate bounded OAuth token responses; only compact credentials enter Keychain.
use super::auth_contract::validate_scopes;
use super::flow::Secret;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) struct Tokens {
    access: Secret,
    refresh: Option<Secret>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) scopes: Vec<String>,
}

impl Tokens {
    pub(crate) fn parse(bytes: &[u8], requested: &[String], now: u64) -> Result<Self, String> {
        if bytes.len() > 16 * 1024 {
            return Err("OAuth token response exceeded its bound.".into());
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "OAuth token response is invalid JSON.")?;
        if value.get("error").is_some()
            || !value
                .get("token_type")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("Bearer"))
        {
            return Err(
                "OAuth token response was refused or uses an unsupported token type.".into(),
            );
        }
        let access = token(value.get("access_token"), true)?;
        let refresh = value
            .get("refresh_token")
            .map(|v| token(Some(v), false))
            .transpose()?;
        let expires_at = value
            .get("expires_in")
            .map(|v| {
                v.as_u64()
                    .filter(|n| *n > 0 && *n <= 31 * 24 * 60 * 60)
                    .and_then(|n| now.checked_add(n))
                    .ok_or("OAuth token lifetime is invalid.")
            })
            .transpose()?;
        let scopes = match value.get("scope") {
            Some(Value::String(s)) => validate_scopes(s.split(' ').map(str::to_owned).collect())?,
            None => validate_scopes(requested.to_vec())?,
            _ => return Err("OAuth granted scopes are invalid.".into()),
        };
        if scopes.iter().any(|s| !requested.contains(s)) {
            return Err("OAuth server returned scopes outside the reviewed request.".into());
        }
        Ok(Self {
            access,
            refresh,
            expires_at,
            scopes,
        })
    }

    pub(crate) fn access(&self, now: u64) -> Result<&str, String> {
        if self
            .expires_at
            .is_some_and(|expires| now.saturating_add(30) >= expires)
        {
            return Err("MCP token needs explicit refresh or sign-in.".into());
        }
        Ok(self.access.text())
    }
    pub(crate) fn refresh(&self) -> Option<&str> {
        self.refresh.as_ref().map(Secret::text)
    }

    pub(crate) fn encode_keychain(&self) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        struct View<'a> {
            version: u8,
            access: &'a str,
            refresh: Option<&'a str>,
            expires: Option<u64>,
            scopes: &'a [String],
        }
        let bytes = serde_json::to_vec(&View {
            version: 1,
            access: self.access.text(),
            refresh: self.refresh(),
            expires: self.expires_at,
            scopes: &self.scopes,
        })
        .map_err(|_| "OAuth Keychain encoding failed.")?;
        if bytes.len() > 8 * 1024 {
            return Err("OAuth credential exceeds the Keychain frame bound.".into());
        }
        Ok(bytes)
    }
    pub(crate) fn restore_keychain(bytes: &[u8], scopes: Vec<String>) -> Result<Self, String> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            version: u8,
            access: String,
            refresh: Option<String>,
            expires: Option<u64>,
            scopes: Vec<String>,
        }
        if bytes.len() > 8 * 1024 {
            return Err("Stored MCP credentials exceed their bound.".into());
        }
        let saved: Stored = serde_json::from_slice(bytes)
            .map_err(|_| "Stored MCP credentials are not a supported frame.")?;
        if saved.version != 1 {
            return Err("Stored MCP credential version is unsupported.".into());
        }
        let access = token(Some(&Value::String(saved.access)), true)?;
        let refresh = saved
            .refresh
            .map(|s| token(Some(&Value::String(s)), false))
            .transpose()?;
        let requested = validate_scopes(scopes)?;
        let granted = validate_scopes(saved.scopes)?;
        if granted.iter().any(|scope| !requested.contains(scope)) {
            return Err("Stored MCP token scopes exceed the reviewed account binding.".into());
        }
        Ok(Self {
            access,
            refresh,
            expires_at: saved.expires,
            scopes: granted,
        })
    }
}

fn token(value: Option<&Value>, bearer: bool) -> Result<Secret, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or("OAuth token is absent or not text.")?;
    if text.len() > 3072 {
        return Err("OAuth token exceeded its bound.".into());
    }
    if bearer {
        let core = text.trim_end_matches('=');
        if core.is_empty()
            || !core
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
        {
            return Err("OAuth access token is not valid Bearer syntax.".into());
        }
    }
    Secret::new(text.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn credentials_round_trip_only_through_the_bounded_keychain_frame() {
        let t=Tokens::parse(&serde_json::to_vec(&json!({"token_type":"Bearer","access_token":"synthetic.access","refresh_token":"synthetic-refresh","expires_in":3600,"scope":"read"})).unwrap(),&["read".into()],100).unwrap();
        let bytes = t.encode_keychain().unwrap();
        let r = Tokens::restore_keychain(&bytes, t.scopes).unwrap();
        assert_eq!(r.access(200).unwrap(), "synthetic.access");
        assert_eq!(r.refresh(), Some("synthetic-refresh"));
        assert!(r.access(3670).is_err());
        let mut bad: Value = serde_json::from_slice(&bytes).unwrap();
        bad["version"] = json!(2);
        assert!(Tokens::restore_keychain(&serde_json::to_vec(&bad).unwrap(), vec![]).is_err());
    }
    #[test]
    fn granted_scope_reduction_survives_keychain_restore() {
        let requested = vec!["read".into(), "write".into()];
        let t = Tokens::parse(
            &serde_json::to_vec(
                &json!({"token_type":"Bearer","access_token":"synthetic","scope":"read"}),
            )
            .unwrap(),
            &requested,
            100,
        )
        .unwrap();
        let restored = Tokens::restore_keychain(&t.encode_keychain().unwrap(), requested).unwrap();
        assert_eq!(restored.scopes, vec!["read"]);
        assert!(Tokens::restore_keychain(&t.encode_keychain().unwrap(), vec![]).is_err());
    }

    #[test]
    fn token_header_injection_scope_expansion_and_invalid_lifetimes_refuse() {
        for (key, value) in [
            ("access_token", json!("secret\r\nX: injected")),
            ("access_token", json!("secret=middle")),
            ("token_type", json!("MAC")),
            ("scope", json!("read write")),
            ("expires_in", json!(-1)),
            ("expires_in", json!(0)),
            ("expires_in", json!(32 * 24 * 60 * 60)),
        ] {
            let mut v = json!({"token_type":"Bearer","access_token":"synthetic","scope":"read"});
            v[key] = value;
            assert!(
                Tokens::parse(&serde_json::to_vec(&v).unwrap(), &["read".into()], 100).is_err(),
                "{key}"
            );
        }
    }
}
