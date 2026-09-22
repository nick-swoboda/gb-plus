//! Signed fixture against unique test-only MCP items; never a provider account.
use super::{
    BrokerClient, BrokerClientConfig, BrokerNamespace, CredentialVersion, FixtureParentVariant,
    McpCredentialKey, OsString, PathBuf, Sha256, delete_generic_password, fixture_access_summary,
    store_secret, validate_fixture_target,
};
use sha2::Digest as _;

#[allow(
    clippy::too_many_lines,
    reason = "one signed fixture keeps exact-item creation, cross-parent readback and cleanup in a single audited flow"
)]
pub(super) fn run(variant: FixtureParentVariant, values: &[OsString]) -> Result<(), String> {
    const SECRET: &[u8] = b"gbplus-synthetic-mcp-credential";
    let text = |index: usize| {
        values
            .get(index)
            .and_then(|v| v.to_str())
            .ok_or("MCP fixture argument is invalid.")
    };
    let helper = PathBuf::from(text(0)?);
    let (service, account) = text(3)?
        .split_once(',')
        .ok_or("MCP fixture target is invalid.")?;
    validate_fixture_target(service, account)?;
    if !service.starts_with("org.grok-build.desktop.test.mcp-") {
        return Err("MCP fixture requires its distinct test service.".into());
    }
    let signer = text(2)?;
    let cdhash = text(4)?;
    let key = McpCredentialKey::from_digest(
        Sha256::digest(format!("{service},{account}").as_bytes()).into(),
    );
    let unrelated = McpCredentialKey::from_digest(
        Sha256::digest(format!("{service},{account},unrelated").as_bytes()).into(),
    );
    let arguments = vec![
        OsString::from("--fixture-mcp-launchd-once"),
        OsString::from(signer),
        OsString::from(service),
        OsString::from(account),
    ];
    let config = |path: PathBuf, sha: &str, hash: &str| -> Result<BrokerClientConfig, String> {
        let mut c = BrokerClientConfig::for_fixture(path, sha, hash, signer, arguments.clone())?;
        c.namespace = BrokerNamespace::Mcp;
        Ok(c)
    };
    if variant == FixtureParentVariant::A {
        for candidate in [
            config(helper.clone(), &"0".repeat(64), cdhash)?,
            config(helper.clone(), text(1)?, &"0".repeat(40))?,
            config(
                helper.with_file_name("missing-mcp-broker"),
                text(1)?,
                cdhash,
            )?,
        ] {
            if BrokerClient::new(candidate).is_ok() {
                return Err("MCP helper identity control unexpectedly passed.".into());
            }
        }
    }
    let client = BrokerClient::new(config(helper, text(1)?, cdhash)?)?;
    if variant == FixtureParentVariant::Unauthorized {
        if client.load_mcp(key, false).is_ok() {
            return Err("Wrong-identifier MCP parent was accepted.".into());
        }
        return Ok(());
    }
    if client.load(CredentialVersion::BrokerV3, false).is_ok()
        || client.store_v3(SECRET).is_ok()
        || client.delete(CredentialVersion::BrokerV3).is_ok()
    {
        return Err("MCP client crossed into the provider namespace.".into());
    }
    let outcome: Result<(), String> = (|| {
        if variant == FixtureParentVariant::A {
            // This control is owned by the changing parent, so automatic helper
            // access must refuse without presenting a Keychain prompt.
            let control_key = McpCredentialKey::from_digest(
                Sha256::digest(format!("{service},{account},parent-control").as_bytes()).into(),
            );
            let mcp_service = format!("{service}.mcp");
            let parent_cdhash = account
                .split_once(":parent:")
                .map(|(_, hash)| hash)
                .ok_or("MCP fixture omitted its parent control identity.")?;
            super::validated_cdhash(parent_cdhash)?;
            store_secret(&mcp_service, &control_key.account(), SECRET)?;
            let setup = fixture_access_summary(&mcp_service, &control_key.account(), parent_cdhash);
            let denied = if setup.is_ok() {
                client.load_mcp(control_key, false)
            } else {
                Err("Parent control ACL was not proven.".into())
            };
            delete_generic_password(&mcp_service, &control_key.account())
                .map_err(|_| "Cannot remove synthetic parent-owned MCP control.")?;
            setup?;
            match denied {
                Err(reason) if reason.contains("automatic reconnect failed closed") => {}
                Err(reason) => {
                    return Err(format!(
                        "MCP parent-owned control returned a different refusal: {reason}"
                    ));
                }
                Ok(None) => return Err("MCP parent-owned control was unexpectedly absent.".into()),
                Ok(Some(_)) => {
                    return Err("MCP helper unexpectedly read the parent-owned control.".into());
                }
            }
            client.store_mcp(key, SECRET)?;
            fixture_access_summary(&mcp_service, &key.account(), cdhash)?;
        }
        let secret = client
            .load_mcp(key, false)?
            .ok_or("MCP helper item is absent.")?;
        if secret.as_slice() != SECRET {
            return Err("MCP fixture readback changed.".into());
        }
        if client.load_mcp(unrelated, false)?.is_some() {
            return Err("MCP helper returned another binding's item.".into());
        }
        Ok(())
    })();
    if outcome.is_err() || variant == FixtureParentVariant::B {
        let cleanup = client.delete_mcp(key);
        outcome?;
        cleanup?;
        if client.load_mcp(key, false)?.is_some() {
            return Err("MCP fixture deletion readback failed.".into());
        }
    } else {
        outcome?;
    }
    Ok(())
}
