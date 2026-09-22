//! macOS Keychain boundary for the direct xAI transport.

use std::sync::{Arc, Mutex};

use grok_build_plus_host::PlusLiveIdentity;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "macos")]
use grok_build_keychain_broker::{
    BrokerClient, BrokerClientConfig, CredentialVersion as BrokerCredentialVersion,
};

/// Maximum accepted API-key length at the native entry and Keychain boundary.
pub(crate) const MAX_XAI_API_KEY_BYTES: usize = 8 * 1024;

/// Non-secret Keychain item status used by Account snapshots.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub(crate) enum KeychainPresence {
    Unchecked,
    Present,
    Absent,
    Unavailable { reason: String },
}

/// Non-secret state inferred from all versioned Keychain identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub(crate) enum KeychainMigrationState {
    Unchecked,
    Absent,
    LegacyOnly,
    StableV2,
    BrokerV3,
    CleanupPending,
    Unavailable { reason: String },
}

impl KeychainPresence {
    pub(crate) fn is_present(&self) -> bool {
        matches!(self, Self::Present)
    }
}

/// Request-scoped secret bytes whose retained buffer is overwritten on drop.
pub(crate) struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, String> {
        validate_key_bytes(&bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn duplicate(&self) -> Result<Self, String> {
        Self::new(self.0.clone())
    }

    pub(crate) fn transient_lease(&self) -> Result<XaiCredentialLease, String> {
        XaiCredentialLease::from_secret(self.duplicate()?)
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes([redacted])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Narrow secret-store contract used by `XaiKeychain`.
pub(crate) trait ProviderSecretStore: Send + Sync {
    /// Broker-owned v3 item used by the stable helper process.
    fn inspect_xai_key(&self) -> KeychainPresence;
    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String>;
    fn load_xai_key_without_ui(&self) -> Result<Option<SecretBytes>, String> {
        self.load_xai_key()
    }
    fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String>;
    fn delete_xai_key(&self) -> Result<(), String>;

    /// Main-app-owned v2 item retained until broker migration succeeds.
    fn inspect_previous_xai_key(&self) -> KeychainPresence {
        KeychainPresence::Absent
    }
    fn load_previous_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        Ok(None)
    }
    fn delete_previous_xai_key(&self) -> Result<(), String> {
        Ok(())
    }

    /// Original v1 item retained only until explicit verified migration.
    fn inspect_legacy_xai_key(&self) -> KeychainPresence {
        KeychainPresence::Absent
    }
    fn load_legacy_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        Ok(None)
    }
    fn delete_legacy_xai_key(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Secret migration material remains opaque outside this module and zeros its
/// retained bytes on every exit path.
#[derive(Debug)]
pub(crate) struct XaiMigrationMaterial {
    broker_v3_was_present: bool,
    secret: SecretBytes,
    lease: XaiCredentialLease,
}

impl XaiMigrationMaterial {
    pub(crate) fn lease(&self) -> XaiCredentialLease {
        self.lease.clone()
    }
}

/// Shared, connection-scoped provider identity. Borrowers can use or inspect
/// the lease but cannot replace its root. Revocation zeros the root identity
/// for every project-run fork at once.
#[derive(Clone)]
pub(crate) struct XaiCredentialLease {
    inner: Arc<XaiCredentialLeaseState>,
}

struct XaiCredentialLeaseState {
    identity: Mutex<Option<PlusLiveIdentity>>,
}

impl std::fmt::Debug for XaiCredentialLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XaiCredentialLease")
            .field("identity", &"[redacted]")
            .field("active", &self.is_active())
            .finish()
    }
}

impl XaiCredentialLease {
    fn from_secret(secret: SecretBytes) -> Result<Self, String> {
        let identity = PlusLiveIdentity::from_configured_key_bytes(secret.into_vec())
            .ok_or_else(|| "The xAI Keychain item is empty or malformed.".to_owned())?;
        Ok(Self {
            inner: Arc::new(XaiCredentialLeaseState {
                identity: Mutex::new(Some(identity)),
            }),
        })
    }

    pub(crate) fn clone_identity(&self) -> Result<PlusLiveIdentity, String> {
        self.inner
            .identity
            .lock()
            .map_err(|_| "The xAI credential lease lock is unavailable.".to_owned())?
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                "The xAI credential lease was revoked; reconnect explicitly from Account."
                    .to_owned()
            })
    }

    pub(crate) fn ensure_active(&self) -> Result<(), String> {
        if self.is_active() {
            Ok(())
        } else {
            Err(
                "The xAI credential lease was revoked; reconnect explicitly from Account."
                    .to_owned(),
            )
        }
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner
            .identity
            .lock()
            .is_ok_and(|identity| identity.is_some())
    }

    pub(crate) fn revoke(&self) {
        let mut identity = self
            .inner
            .identity
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = identity.take();
    }
}

/// Sole owner of Keychain I/O and the revocable connection lease. Snapshots
/// receive only cached [`KeychainPresence`]; adapters receive only lease
/// handles and therefore cannot reopen macOS Keychain implicitly.
pub(crate) struct XaiCredentialBroker {
    store: Arc<dyn ProviderSecretStore>,
    presence: KeychainPresence,
    migration_state: KeychainMigrationState,
    active: Option<XaiCredentialLease>,
}

impl XaiCredentialBroker {
    pub(crate) fn new(store: Arc<dyn ProviderSecretStore>) -> Self {
        Self {
            store,
            presence: KeychainPresence::Unchecked,
            migration_state: KeychainMigrationState::Unchecked,
            active: None,
        }
    }

    pub(crate) fn presence(&self) -> &KeychainPresence {
        &self.presence
    }

    pub(crate) fn migration_state(&self) -> &KeychainMigrationState {
        &self.migration_state
    }

    pub(crate) fn open_explicit(&mut self) -> Result<XaiCredentialLease, String> {
        self.open_current(true)
    }

    pub(crate) fn open_automatic(&mut self) -> Result<XaiCredentialLease, String> {
        self.open_current(false)
    }

    fn open_current(&mut self, allow_interaction: bool) -> Result<XaiCredentialLease, String> {
        if let Some(active) = self.active.as_ref().filter(|lease| lease.is_active()) {
            return Ok(active.clone());
        }
        let was_unchecked = self.migration_state == KeychainMigrationState::Unchecked;
        if !matches!(
            self.migration_state,
            KeychainMigrationState::Unchecked | KeychainMigrationState::BrokerV3
        ) {
            return Err(match self.migration_state {
                KeychainMigrationState::LegacyOnly
                | KeychainMigrationState::StableV2
                | KeychainMigrationState::CleanupPending => {
                    "The saved API key requires one explicit stable-broker migration before reconnecting."
                        .to_owned()
                }
                KeychainMigrationState::Absent => {
                    "No xAI API key is stored in macOS Keychain.".to_owned()
                }
                KeychainMigrationState::Unavailable { ref reason } => reason.clone(),
                KeychainMigrationState::Unchecked | KeychainMigrationState::BrokerV3 => {
                    unreachable!()
                }
            });
        }
        let loaded = if allow_interaction {
            self.store.load_xai_key()
        } else {
            self.store.load_xai_key_without_ui()
        };
        let secret = match loaded {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                if allow_interaction && was_unchecked {
                    self.refresh_predecessor_presence();
                } else {
                    self.presence = KeychainPresence::Absent;
                    self.migration_state = KeychainMigrationState::Absent;
                }
                return Err(match self.migration_state {
                    KeychainMigrationState::LegacyOnly
                    | KeychainMigrationState::StableV2
                    | KeychainMigrationState::CleanupPending => "The saved API key requires one explicit stable-broker migration before reconnecting.".to_owned(),
                    KeychainMigrationState::Unavailable { ref reason } => reason.clone(),
                    _ => "No xAI API key is stored in macOS Keychain.".to_owned(),
                });
            }
            Err(reason) => {
                self.presence = KeychainPresence::Unavailable {
                    reason: reason.clone(),
                };
                return Err(reason);
            }
        };
        let lease = XaiCredentialLease::from_secret(secret)?;
        self.presence = KeychainPresence::Present;
        self.migration_state = KeychainMigrationState::BrokerV3;
        self.active = Some(lease.clone());
        Ok(lease)
    }

    pub(crate) fn store_verified_and_open(
        &mut self,
        secret: &SecretBytes,
    ) -> Result<XaiCredentialLease, String> {
        self.revoke();
        if let Err(reason) = self.store.store_xai_key(secret) {
            self.refresh_presence();
            return Err(reason);
        }
        let verified = match self.store.load_xai_key() {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                self.refresh_presence();
                return Err("The new xAI Keychain item was absent during verification.".to_owned());
            }
            Err(reason) => {
                self.refresh_presence();
                return Err(reason);
            }
        };
        if secret_digest(secret) != secret_digest(&verified) {
            self.refresh_presence();
            return Err(
                "The new xAI Keychain item did not match the entered credential; connection was refused."
                    .into(),
            );
        }
        if let Err(reason) = self.store.delete_previous_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        if let Err(reason) = self.store.delete_legacy_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        let lease = XaiCredentialLease::from_secret(verified)?;
        self.presence = KeychainPresence::Present;
        self.migration_state = KeychainMigrationState::BrokerV3;
        self.active = Some(lease.clone());
        Ok(lease)
    }

    pub(crate) fn begin_migration(&mut self) -> Result<XaiMigrationMaterial, String> {
        self.revoke();
        match self.migration_state {
            KeychainMigrationState::Unchecked => {
                Err("The saved API key has not been checked yet.".into())
            }
            KeychainMigrationState::LegacyOnly
            | KeychainMigrationState::StableV2
            | KeychainMigrationState::CleanupPending => self.load_migration_material(),
            KeychainMigrationState::BrokerV3 => {
                Err("The xAI Keychain item is already broker-owned.".into())
            }
            KeychainMigrationState::Absent => {
                Err("No saved xAI API key is available to migrate.".into())
            }
            KeychainMigrationState::Unavailable { ref reason } => Err(reason.clone()),
        }
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "migration material is a move-only secret capability consumed exactly once"
    )]
    pub(crate) fn finish_migration(
        &mut self,
        material: XaiMigrationMaterial,
    ) -> Result<XaiCredentialLease, String> {
        if !material.broker_v3_was_present
            && let Err(reason) = self.store.store_xai_key(&material.secret)
        {
            self.refresh_presence();
            return Err(reason);
        }
        let verified = match self.store.load_xai_key() {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                self.refresh_presence();
                return Err(
                    "The broker-owned v3 xAI Keychain item was absent during migration verification."
                        .to_owned(),
                );
            }
            Err(reason) => {
                self.refresh_presence();
                return Err(reason);
            }
        };
        if secret_digest(&material.secret) != secret_digest(&verified) {
            self.refresh_presence();
            return Err(
                "Predecessor and broker-owned xAI Keychain items differ after migration; cleanup was refused."
                    .into(),
            );
        }
        if let Err(reason) = self.store.delete_previous_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        if let Err(reason) = self.store.delete_legacy_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        self.presence = KeychainPresence::Present;
        let lease = XaiCredentialLease::from_secret(verified)?;
        self.migration_state = KeychainMigrationState::BrokerV3;
        self.active = Some(lease.clone());
        Ok(lease)
    }

    fn load_migration_material(&mut self) -> Result<XaiMigrationMaterial, String> {
        let (broker_v3, stable_v2, legacy_v1) = match self.migration_state {
            KeychainMigrationState::LegacyOnly => (
                None,
                None,
                self.load_if_present(CredentialGeneration::LegacyV1)?,
            ),
            KeychainMigrationState::StableV2 => (
                None,
                self.load_if_present(CredentialGeneration::StableV2)?,
                None,
            ),
            KeychainMigrationState::CleanupPending => (
                self.load_if_present(CredentialGeneration::BrokerV3)?,
                self.load_if_present(CredentialGeneration::StableV2)?,
                self.load_if_present(CredentialGeneration::LegacyV1)?,
            ),
            _ => return Err("Saved API-key migration state changed before loading.".into()),
        };
        let mut expected_digest = None;
        for candidate in [&broker_v3, &stable_v2, &legacy_v1].into_iter().flatten() {
            let digest = secret_digest(candidate);
            if expected_digest.is_some_and(|expected| expected != digest) {
                return Err(
                    "Saved xAI Keychain generations differ. Automatic cleanup was refused; replace the API key explicitly."
                        .into(),
                );
            }
            expected_digest = Some(digest);
        }
        let broker_v3_was_present = broker_v3.is_some();
        let secret = broker_v3.or(stable_v2).or(legacy_v1).ok_or_else(|| {
            "The saved xAI Keychain item disappeared during migration.".to_owned()
        })?;
        let lease = XaiCredentialLease::from_secret(secret.duplicate()?)?;
        Ok(XaiMigrationMaterial {
            broker_v3_was_present,
            secret,
            lease,
        })
    }

    fn load_if_present(
        &self,
        generation: CredentialGeneration,
    ) -> Result<Option<SecretBytes>, String> {
        match generation {
            CredentialGeneration::BrokerV3 => self.store.load_xai_key(),
            CredentialGeneration::StableV2 => self.store.load_previous_xai_key(),
            CredentialGeneration::LegacyV1 => self.store.load_legacy_xai_key(),
        }
    }

    fn refresh_predecessor_presence(&mut self) {
        let (presence, migration_state) = keychain_states(
            &KeychainPresence::Absent,
            &self.store.inspect_previous_xai_key(),
            &self.store.inspect_legacy_xai_key(),
        );
        self.presence = presence;
        self.migration_state = migration_state;
    }

    pub(crate) fn delete(&mut self) -> Result<(), String> {
        self.revoke();
        if let Err(reason) = self.store.delete_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        if let Err(reason) = self.store.delete_previous_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        if let Err(reason) = self.store.delete_legacy_xai_key() {
            self.refresh_presence();
            return Err(reason);
        }
        self.presence = KeychainPresence::Absent;
        self.migration_state = KeychainMigrationState::Absent;
        Ok(())
    }

    pub(crate) fn revoke(&mut self) {
        if let Some(active) = self.active.take() {
            active.revoke();
        }
    }

    fn refresh_presence(&mut self) {
        let (presence, migration_state) = keychain_states(
            &self.store.inspect_xai_key(),
            &self.store.inspect_previous_xai_key(),
            &self.store.inspect_legacy_xai_key(),
        );
        self.presence = presence;
        self.migration_state = migration_state;
    }
}

#[derive(Clone, Copy)]
enum CredentialGeneration {
    BrokerV3,
    StableV2,
    LegacyV1,
}

fn secret_digest(secret: &SecretBytes) -> [u8; 32] {
    Sha256::digest(secret.as_slice()).into()
}

fn keychain_states(
    broker_v3: &KeychainPresence,
    stable_v2: &KeychainPresence,
    legacy_v1: &KeychainPresence,
) -> (KeychainPresence, KeychainMigrationState) {
    for presence in [broker_v3, stable_v2, legacy_v1] {
        if let KeychainPresence::Unavailable { reason } = presence {
            return (
                KeychainPresence::Unavailable {
                    reason: reason.clone(),
                },
                KeychainMigrationState::Unavailable {
                    reason: reason.clone(),
                },
            );
        }
    }
    if [broker_v3, stable_v2, legacy_v1]
        .iter()
        .any(|presence| matches!(presence, KeychainPresence::Unchecked))
    {
        return (
            KeychainPresence::Unchecked,
            KeychainMigrationState::Unchecked,
        );
    }
    let present = [
        broker_v3.is_present(),
        stable_v2.is_present(),
        legacy_v1.is_present(),
    ];
    match present.iter().filter(|is_present| **is_present).count() {
        0 => (KeychainPresence::Absent, KeychainMigrationState::Absent),
        1 if present[0] => (KeychainPresence::Present, KeychainMigrationState::BrokerV3),
        1 if present[1] => (KeychainPresence::Present, KeychainMigrationState::StableV2),
        1 => (
            KeychainPresence::Present,
            KeychainMigrationState::LegacyOnly,
        ),
        _ => (
            KeychainPresence::Present,
            KeychainMigrationState::CleanupPending,
        ),
    }
}

impl Drop for XaiCredentialBroker {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Production macOS Keychain implementation. The main app never reads secret
/// data directly; all versions are mediated by the exact signed helper.
#[derive(Clone, Debug)]
pub(crate) struct MacOsKeychainStore {
    #[cfg(target_os = "macos")]
    client: Result<BrokerClient, String>,
}

impl MacOsKeychainStore {
    pub(crate) fn production() -> Self {
        #[cfg(target_os = "macos")]
        {
            let client = BrokerClientConfig::for_current_app(
                env!("GROK_BUILD_KEYCHAIN_BROKER_SHA256"),
                env!("GROK_BUILD_KEYCHAIN_BROKER_CDHASH"),
                env!("GROK_BUILD_SIGNING_IDENTITY"),
            )
            .and_then(BrokerClient::new);
            Self { client }
        }

        #[cfg(not(target_os = "macos"))]
        {
            Self {}
        }
    }

    #[cfg(target_os = "macos")]
    fn client(&self) -> Result<&BrokerClient, String> {
        self.client.as_ref().map_err(Clone::clone)
    }

    #[cfg(target_os = "macos")]
    fn inspect_version(&self, version: BrokerCredentialVersion) -> KeychainPresence {
        match self.client().and_then(|client| client.inspect(version)) {
            Ok(true) => KeychainPresence::Present,
            Ok(false) => KeychainPresence::Absent,
            Err(reason) => KeychainPresence::Unavailable { reason },
        }
    }

    #[cfg(target_os = "macos")]
    fn load_version(
        &self,
        version: BrokerCredentialVersion,
        allow_interaction: bool,
    ) -> Result<Option<SecretBytes>, String> {
        self.client()?
            .load(version, allow_interaction)?
            .map(|secret| SecretBytes::new(secret.into_vec()))
            .transpose()
    }

    #[cfg(target_os = "macos")]
    fn delete_version(&self, version: BrokerCredentialVersion) -> Result<(), String> {
        self.client()?.delete(version)
    }
}

impl Default for MacOsKeychainStore {
    fn default() -> Self {
        Self::production()
    }
}

#[cfg(test)]
fn stable_xai_keychain_account() -> String {
    "xai:v2:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b".to_owned()
}

#[cfg(test)]
fn broker_xai_keychain_account() -> String {
    "xai:v3:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b".to_owned()
}

#[cfg(target_os = "macos")]
impl ProviderSecretStore for MacOsKeychainStore {
    fn inspect_xai_key(&self) -> KeychainPresence {
        self.inspect_version(BrokerCredentialVersion::BrokerV3)
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.load_version(BrokerCredentialVersion::BrokerV3, true)
    }

    fn load_xai_key_without_ui(&self) -> Result<Option<SecretBytes>, String> {
        self.load_version(BrokerCredentialVersion::BrokerV3, false)
    }

    fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String> {
        self.client()?.store_v3(key.as_slice())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        self.delete_version(BrokerCredentialVersion::BrokerV3)
    }

    fn inspect_previous_xai_key(&self) -> KeychainPresence {
        self.inspect_version(BrokerCredentialVersion::StableV2)
    }

    fn load_previous_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.load_version(BrokerCredentialVersion::StableV2, true)
    }

    fn delete_previous_xai_key(&self) -> Result<(), String> {
        self.delete_version(BrokerCredentialVersion::StableV2)
    }

    fn inspect_legacy_xai_key(&self) -> KeychainPresence {
        self.inspect_version(BrokerCredentialVersion::LegacyV1)
    }

    fn load_legacy_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.load_version(BrokerCredentialVersion::LegacyV1, true)
    }

    fn delete_legacy_xai_key(&self) -> Result<(), String> {
        self.delete_version(BrokerCredentialVersion::LegacyV1)
    }
}

#[cfg(not(target_os = "macos"))]
impl ProviderSecretStore for MacOsKeychainStore {
    fn inspect_xai_key(&self) -> KeychainPresence {
        KeychainPresence::Unavailable {
            reason: "XaiKeychain is available only on macOS.".into(),
        }
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        Err("XaiKeychain is available only on macOS.".into())
    }

    fn store_xai_key(&self, _key: &SecretBytes) -> Result<(), String> {
        Err("XaiKeychain is available only on macOS.".into())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        Err("XaiKeychain is available only on macOS.".into())
    }
}

fn validate_key_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("The xAI API key is empty; nothing was stored.".into());
    }
    if bytes.len() > MAX_XAI_API_KEY_BYTES {
        return Err(format!(
            "The xAI API key exceeds the {MAX_XAI_API_KEY_BYTES}-byte limit; nothing was stored."
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "The xAI API key is not valid UTF-8; nothing was stored.".to_owned())?;
    if text.trim().is_empty() {
        return Err("The xAI API key is blank; nothing was stored.".into());
    }
    if text.chars().any(char::is_control) {
        return Err("The xAI API key contains control characters; nothing was stored.".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/runtime_keychain.rs"]
mod tests;
