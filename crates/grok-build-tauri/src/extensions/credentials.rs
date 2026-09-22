//! Do not copy embedded transport credentials into immutable plugin content.

use super::content::Bundle;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn validate(bundle: &Bundle, manifest: &Value) -> Result<(), String> {
    let mut budget = 4096;
    inspect(manifest, 0, &mut budget)?;
    let mut configs = BTreeSet::new();
    for path in [".mcp.json", ".lsp.json", "hooks/hooks.json"] {
        if bundle.files.contains_key(path) {
            configs.insert(path.to_owned());
        }
    }
    for key in ["mcpServers", "lspServers", "hooks"] {
        if let Some(path) = manifest.get(key).and_then(Value::as_str) {
            let path = path.strip_prefix("./").unwrap_or(path);
            super::content::validate_path(path)?;
            configs.insert(path.to_owned());
        }
    }
    for path in configs {
        let text = bundle.preview_text(&path, 128 * 1024)?;
        let config: Value = serde_json::from_str(text)
            .map_err(|_| "Extension transport configuration is not valid bounded JSON.")?;
        inspect(&config, 0, &mut budget)?;
    }
    Ok(())
}

fn inspect(value: &Value, depth: usize, budget: &mut usize) -> Result<(), String> {
    if depth > 32 || *budget == 0 {
        return Err("Extension configuration exceeds its inspection bound.".into());
    }
    *budget -= 1;
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if credential_name(name)
                    && !value.is_null()
                    && !value.as_str().is_some_and(placeholder)
                {
                    return Err("Credential fields must be unset or literal references before preview. Inline values and unsupported value shapes cannot be copied into extension content.".into());
                }
                inspect(value, depth + 1, budget)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                inspect(value, depth + 1, budget)?;
            }
        }
        Value::String(text) => {
            if let Ok(url) = tauri::Url::parse(text)
                && url.has_host()
                && (!url.username().is_empty()
                    || url.password().is_some()
                    || url.query_pairs().any(|(key, _)| credential_name(&key))
                    || url.fragment().is_some_and(|fragment| {
                        fragment
                            .split('&')
                            .filter_map(|pair| pair.split_once('='))
                            .any(|(key, _)| credential_name(key))
                    }))
            {
                return Err(
                    "Credential-bearing endpoint URLs cannot be stored in extension content."
                        .into(),
                );
            }
            if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
                return Err("Private-key material cannot be stored in extension content.".into());
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn credential_name(name: &str) -> bool {
    let name: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        name.as_str(),
        "authorization"
            | "proxyauthorization"
            | "passphrase"
            | "awsaccesskeyid"
            | "awssecretaccesskey"
            | "privatekey"
            | "secretkey"
    ) || ["apikey", "token", "password", "secret"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn placeholder(value: &str) -> bool {
    value.is_empty()
        || value
            .strip_prefix("${")
            .and_then(|value| value.strip_suffix('}'))
            .is_some_and(|name| {
                !name.is_empty()
                    && name.len() <= 80
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            })
}
