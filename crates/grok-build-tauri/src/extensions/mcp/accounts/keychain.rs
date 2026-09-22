//! Exact MCP-only helper. Provider credentials never enter this interface.
use super::{store::Binding, tokens::Tokens};
use grok_build_keychain_broker::{BrokerClient, BrokerClientConfig, McpCredentialKey};

fn client() -> Result<BrokerClient, String> {
    BrokerClientConfig::for_current_app_mcp(
        env!("GROK_BUILD_MCP_BROKER_SHA256"),
        env!("GROK_BUILD_MCP_BROKER_CDHASH"),
        env!("GROK_BUILD_SIGNING_IDENTITY"),
    )
    .and_then(BrokerClient::new)
}
fn key(binding: &Binding) -> Result<McpCredentialKey, String> {
    binding.validate()?;
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&binding.key[i * 2..i * 2 + 2], 16)
            .map_err(|_| "Invalid MCP credential key.")?;
    }
    Ok(McpCredentialKey::from_digest(bytes))
}
pub(super) fn load(binding: &Binding) -> Result<Tokens, String> {
    let bytes = client()?
        .load_mcp(key(binding)?, false)?
        .ok_or("MCP account credential is absent. Sign in explicitly.")?;
    Tokens::restore_keychain(bytes.as_slice(), binding.scopes.clone())
}
pub(super) fn store_verified(binding: &Binding, tokens: &Tokens) -> Result<(), String> {
    let client = client()?;
    let key = key(binding)?;
    let mut encoded = tokens.encode_keychain()?;
    let result = (|| {
        client.store_mcp(key, &encoded)?;
        let readback = client
            .load_mcp(key, false)?
            .ok_or("MCP credential storage did not survive readback.")?;
        if readback.as_slice() != encoded.as_slice() {
            return Err("MCP credential readback differed; the account was not activated.".into());
        }
        Ok(())
    })();
    encoded.fill(0);
    result
}
pub(super) fn delete_verified(binding: &Binding) -> Result<(), String> {
    let client = client()?;
    let key = key(binding)?;
    client.delete_mcp(key)?;
    if client.load_mcp(key, false)?.is_some() {
        return Err("MCP credential deletion was not confirmed.".into());
    }
    Ok(())
}
