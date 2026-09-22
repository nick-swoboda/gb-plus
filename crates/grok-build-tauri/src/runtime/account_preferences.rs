//! Durable, non-secret Account choices.
//!
//! This record restores an explicit transport selection and a bounded reconnect
//! authorization. Provider credentials and live connection claims are
//! deliberately outside this file.

#[cfg(test)]
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::owner_state::{OwnerStateErrorKind, OwnerStateFile, OwnerStateRoot};

use super::types::RuntimeTransport;

pub(crate) const ACCOUNT_PREFERENCES_FILE: &str = "plus-account-preferences.json";
const ACCOUNT_PREFERENCES_SCHEMA_VERSION: u16 = 4;
const MAX_ACCOUNT_PREFERENCES_BYTES: u64 = 16 * 1024;
pub(crate) const RECONNECT_GRANT_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReconnectGrant {
    pub(crate) transport: RuntimeTransport,
    pub(crate) authorized_at_utc_ms: u64,
    pub(crate) expires_at_utc_ms: u64,
}

impl ReconnectGrant {
    pub(crate) fn fixed(
        transport: RuntimeTransport,
        authorized_at_utc_ms: u64,
    ) -> Result<Self, String> {
        let expires_at_utc_ms = authorized_at_utc_ms
            .checked_add(RECONNECT_GRANT_MILLIS)
            .ok_or_else(|| "Reconnect authorization timestamp overflowed.".to_owned())?;
        Ok(Self {
            transport,
            authorized_at_utc_ms,
            expires_at_utc_ms,
        })
    }

    pub(crate) fn validate(self, now_utc_ms: u64) -> Result<Self, String> {
        let expected_expiry = self
            .authorized_at_utc_ms
            .checked_add(RECONNECT_GRANT_MILLIS)
            .ok_or_else(|| "Reconnect authorization timestamp overflowed.".to_owned())?;
        if self.expires_at_utc_ms != expected_expiry {
            return Err("Reconnect authorization is not an exact fixed seven-day window.".into());
        }
        if self.authorized_at_utc_ms > now_utc_ms {
            return Err(
                "Reconnect authorization was created in the future; clock rollback or record tampering was refused."
                    .into(),
            );
        }
        Ok(self)
    }

    pub(crate) const fn is_unexpired(self, now_utc_ms: u64) -> bool {
        now_utc_ms < self.expires_at_utc_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountPreferences {
    pub(crate) selected_transport: RuntimeTransport,
    pub(crate) onboarding_acknowledged: bool,
    pub(crate) auto_reconnect_enabled: bool,
    pub(crate) reconnect_grant: Option<ReconnectGrant>,
    /// Public SHA-1 certificate fingerprint only. This is an identity binding,
    /// never credential material.
    pub(crate) credential_binding_identity: Option<String>,
    /// Public SHA-256 of the exact stable helper that owns the v3 Keychain
    /// item. Unlike the reconnect grant, this survives an ordinary disconnect
    /// because it describes storage identity, not authorization.
    pub(crate) keychain_broker_sha256: Option<String>,
}

impl Default for AccountPreferences {
    fn default() -> Self {
        Self {
            selected_transport: RuntimeTransport::GrokCliAcp,
            onboarding_acknowledged: false,
            auto_reconnect_enabled: true,
            reconnect_grant: None,
            credential_binding_identity: None,
            keychain_broker_sha256: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountPreferencesWireV4 {
    schema_version: u16,
    selected_transport: RuntimeTransport,
    onboarding_acknowledged: bool,
    auto_reconnect_enabled: bool,
    reconnect_grant: Option<ReconnectGrant>,
    credential_binding_identity: Option<String>,
    keychain_broker_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountPreferencesWireV3 {
    schema_version: u16,
    selected_transport: RuntimeTransport,
    onboarding_acknowledged: bool,
    auto_reconnect_enabled: bool,
    reconnect_grant: Option<ReconnectGrant>,
    credential_binding_identity: Option<String>,
    keychain_acl_binding_identity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountPreferencesWireV2 {
    schema_version: u16,
    selected_transport: RuntimeTransport,
    onboarding_acknowledged: bool,
    auto_reconnect_enabled: bool,
    reconnect_grant: Option<ReconnectGrant>,
    credential_binding_identity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountPreferencesWireV1 {
    schema_version: u16,
    selected_transport: RuntimeTransport,
    onboarding_acknowledged: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AccountPreferenceStore {
    file: OwnerStateFile,
}

impl AccountPreferenceStore {
    pub(crate) fn new(state_root: PathBuf) -> Self {
        Self {
            file: OwnerStateRoot::new(state_root)
                .file(ACCOUNT_PREFERENCES_FILE, MAX_ACCOUNT_PREFERENCES_BYTES)
                .expect("the Account preference name is one static component"),
        }
    }

    pub(crate) fn load(&self) -> Result<Option<AccountPreferences>, String> {
        self.load_at(super::types::unix_time_millis())
    }

    fn load_at(&self, now_utc_ms: u64) -> Result<Option<AccountPreferences>, String> {
        let Some(bytes) = self.file.read().map_err(|error| match error.kind {
            OwnerStateErrorKind::Type => {
                format!("{ACCOUNT_PREFERENCES_FILE} is not an owner-controlled regular file")
            }
            OwnerStateErrorKind::Owner => {
                format!("{ACCOUNT_PREFERENCES_FILE} is not restricted to its owner")
            }
            OwnerStateErrorKind::Oversized => format!(
                "{ACCOUNT_PREFERENCES_FILE} exceeds the {MAX_ACCOUNT_PREFERENCES_BYTES}-byte limit"
            ),
            OwnerStateErrorKind::Read => {
                format!("cannot read {ACCOUNT_PREFERENCES_FILE}: {error}")
            }
            _ => format!("cannot inspect {ACCOUNT_PREFERENCES_FILE}: {error}"),
        })?
        else {
            return Ok(None);
        };
        let header: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot decode {ACCOUNT_PREFERENCES_FILE}: {error}"))?;
        let schema_version = header
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                format!("cannot decode {ACCOUNT_PREFERENCES_FILE}: missing schemaVersion")
            })?;
        let (preferences, migrated) =
            decode_account_preferences(&bytes, schema_version, now_utc_ms)?;
        if migrated {
            self.save(preferences.clone())?;
        }
        Ok(Some(preferences))
    }

    pub(crate) fn save(&self, preferences: AccountPreferences) -> Result<(), String> {
        if let Some(identity) = preferences.credential_binding_identity.as_deref() {
            validate_public_signing_identity(identity)?;
        }
        if let Some(hash) = preferences.keychain_broker_sha256.as_deref() {
            validate_public_sha256(hash)?;
        }
        if preferences.reconnect_grant.is_none()
            && preferences.credential_binding_identity.is_some()
        {
            return Err(
                "Account credential binding cannot be persisted without a reconnect authorization."
                    .into(),
            );
        }
        if let Some(grant) = preferences.reconnect_grant {
            let expected = grant
                .authorized_at_utc_ms
                .checked_add(RECONNECT_GRANT_MILLIS)
                .ok_or_else(|| "Reconnect authorization timestamp overflowed.".to_owned())?;
            if grant.expires_at_utc_ms != expected {
                return Err(
                    "Reconnect authorization is not an exact fixed seven-day window.".into(),
                );
            }
        }
        let wire = AccountPreferencesWireV4 {
            schema_version: ACCOUNT_PREFERENCES_SCHEMA_VERSION,
            selected_transport: preferences.selected_transport,
            onboarding_acknowledged: preferences.onboarding_acknowledged,
            auto_reconnect_enabled: preferences.auto_reconnect_enabled,
            reconnect_grant: preferences.reconnect_grant,
            credential_binding_identity: preferences.credential_binding_identity,
            keychain_broker_sha256: preferences.keychain_broker_sha256,
        };
        let mut bytes = serde_json::to_vec_pretty(&wire)
            .map_err(|error| format!("cannot encode {ACCOUNT_PREFERENCES_FILE}: {error}"))?;
        bytes.push(b'\n');
        self.file
            .replace(&bytes)
            .map_err(|error| format!("cannot persist {ACCOUNT_PREFERENCES_FILE}: {error}"))
    }
}

fn decode_account_preferences(
    bytes: &[u8],
    schema_version: u64,
    now_utc_ms: u64,
) -> Result<(AccountPreferences, bool), String> {
    let (preferences, migrated) = match schema_version {
        1 => {
            let wire: AccountPreferencesWireV1 =
                serde_json::from_slice(bytes).map_err(|error| {
                    format!("cannot decode legacy {ACCOUNT_PREFERENCES_FILE}: {error}")
                })?;
            debug_assert_eq!(wire.schema_version, 1);
            (
                AccountPreferences {
                    selected_transport: wire.selected_transport,
                    onboarding_acknowledged: wire.onboarding_acknowledged,
                    auto_reconnect_enabled: true,
                    reconnect_grant: None,
                    credential_binding_identity: None,
                    keychain_broker_sha256: None,
                },
                true,
            )
        }
        2 => {
            let wire: AccountPreferencesWireV2 = serde_json::from_slice(bytes)
                .map_err(|error| format!("cannot decode {ACCOUNT_PREFERENCES_FILE}: {error}"))?;
            debug_assert_eq!(wire.schema_version, 2);
            (
                validated_preferences(
                    wire.selected_transport,
                    wire.onboarding_acknowledged,
                    wire.auto_reconnect_enabled,
                    wire.reconnect_grant,
                    wire.credential_binding_identity,
                    None,
                    now_utc_ms,
                )?,
                true,
            )
        }
        3 => {
            let wire: AccountPreferencesWireV3 = serde_json::from_slice(bytes)
                .map_err(|error| format!("cannot decode {ACCOUNT_PREFERENCES_FILE}: {error}"))?;
            debug_assert_eq!(wire.schema_version, 3);
            if let Some(identity) = wire.keychain_acl_binding_identity.as_deref() {
                validate_public_signing_identity(identity)?;
            }
            (
                validated_preferences(
                    wire.selected_transport,
                    wire.onboarding_acknowledged,
                    wire.auto_reconnect_enabled,
                    wire.reconnect_grant,
                    wire.credential_binding_identity,
                    None,
                    now_utc_ms,
                )?,
                true,
            )
        }
        4 => {
            let wire: AccountPreferencesWireV4 = serde_json::from_slice(bytes)
                .map_err(|error| format!("cannot decode {ACCOUNT_PREFERENCES_FILE}: {error}"))?;
            debug_assert_eq!(wire.schema_version, ACCOUNT_PREFERENCES_SCHEMA_VERSION);
            (
                validated_preferences(
                    wire.selected_transport,
                    wire.onboarding_acknowledged,
                    wire.auto_reconnect_enabled,
                    wire.reconnect_grant,
                    wire.credential_binding_identity,
                    wire.keychain_broker_sha256,
                    now_utc_ms,
                )?,
                false,
            )
        }
        unsupported => {
            return Err(format!(
                "unsupported {ACCOUNT_PREFERENCES_FILE} schema {unsupported} (expected {ACCOUNT_PREFERENCES_SCHEMA_VERSION})"
            ));
        }
    };
    Ok((preferences, migrated))
}

#[allow(
    clippy::too_many_arguments,
    reason = "mirrors the bounded schema-4 record"
)]
fn validated_preferences(
    selected_transport: RuntimeTransport,
    onboarding_acknowledged: bool,
    auto_reconnect_enabled: bool,
    reconnect_grant: Option<ReconnectGrant>,
    credential_binding_identity: Option<String>,
    keychain_broker_sha256: Option<String>,
    now_utc_ms: u64,
) -> Result<AccountPreferences, String> {
    if let Some(identity) = credential_binding_identity.as_deref() {
        validate_public_signing_identity(identity)?;
    }
    if let Some(hash) = keychain_broker_sha256.as_deref() {
        validate_public_sha256(hash)?;
    }
    let reconnect_grant = reconnect_grant
        .map(|grant| grant.validate(now_utc_ms))
        .transpose()?;
    if reconnect_grant.is_none() && credential_binding_identity.is_some() {
        return Err("Account credential binding exists without a reconnect authorization.".into());
    }
    Ok(AccountPreferences {
        selected_transport,
        onboarding_acknowledged,
        auto_reconnect_enabled,
        reconnect_grant,
        credential_binding_identity,
        keychain_broker_sha256,
    })
}

fn validate_public_signing_identity(identity: &str) -> Result<(), String> {
    if identity.len() == 40 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Account credential binding is not a 40-character certificate fingerprint.".into())
    }
}

fn validate_public_sha256(hash: &str) -> Result<(), String> {
    if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Account Keychain broker binding is not a 64-character SHA-256.".into())
    }
}

#[cfg(test)]
#[path = "account_preferences/tests.rs"]
mod tests;
