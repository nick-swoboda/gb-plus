use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::{
    KeychainMigrationState, KeychainPresence, MAX_XAI_API_KEY_BYTES, ProviderSecretStore,
    SecretBytes, XaiCredentialBroker, broker_xai_keychain_account, stable_xai_keychain_account,
};
use grok_build_plus_host::{PLUS_KEYCHAIN_SERVICE, plus_keychain_account};

#[derive(Default)]
struct SecretCounts {
    inspect: AtomicUsize,
    load: AtomicUsize,
    load_without_ui: AtomicUsize,
    store: AtomicUsize,
    delete: AtomicUsize,
}

struct CountingSecrets {
    value: Mutex<Option<Vec<u8>>>,
    counts: Arc<SecretCounts>,
}

impl CountingSecrets {
    fn new(value: Option<&[u8]>) -> (Arc<Self>, Arc<SecretCounts>) {
        let counts = Arc::new(SecretCounts::default());
        (
            Arc::new(Self {
                value: Mutex::new(value.map(<[u8]>::to_vec)),
                counts: Arc::clone(&counts),
            }),
            counts,
        )
    }
}

impl ProviderSecretStore for CountingSecrets {
    fn inspect_xai_key(&self) -> KeychainPresence {
        self.counts.inspect.fetch_add(1, Ordering::Relaxed);
        if self.value.lock().expect("secret lock").is_some() {
            KeychainPresence::Present
        } else {
            KeychainPresence::Absent
        }
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.load.fetch_add(1, Ordering::Relaxed);
        self.value
            .lock()
            .expect("secret lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn load_xai_key_without_ui(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.load_without_ui.fetch_add(1, Ordering::Relaxed);
        self.value
            .lock()
            .expect("secret lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String> {
        self.counts.store.fetch_add(1, Ordering::Relaxed);
        *self.value.lock().expect("secret lock") = Some(key.as_slice().to_vec());
        Ok(())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        self.counts.delete.fetch_add(1, Ordering::Relaxed);
        *self.value.lock().expect("secret lock") = None;
        Ok(())
    }
}

#[test]
fn keychain_identity_and_secret_validation_are_stable() {
    assert_eq!(PLUS_KEYCHAIN_SERVICE, "org.grok-build.desktop.provider");
    assert_eq!(
        plus_keychain_account(),
        "xai:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
    );
    assert_eq!(
        stable_xai_keychain_account(),
        "xai:v2:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
    );
    assert_eq!(
        broker_xai_keychain_account(),
        "xai:v3:ebb5dec7d8c69fa5c35a5bfa5ae24d96b7d763c30f68df44bceb7195465ce82b"
    );
    assert!(SecretBytes::new(Vec::new()).is_err());
    assert!(SecretBytes::new(b"   ".to_vec()).is_err());
    assert!(SecretBytes::new(b"xai-key\n".to_vec()).is_err());
    assert!(SecretBytes::new(vec![b'x'; MAX_XAI_API_KEY_BYTES + 1]).is_err());
    let secret = SecretBytes::new(b"xai-test-sentinel".to_vec()).expect("valid key");
    assert_eq!(format!("{secret:?}"), "SecretBytes([redacted])");
}

#[test]
fn explicit_connect_opens_one_shared_revocable_xai_credential_lease() {
    let (store, counts) = CountingSecrets::new(Some(b"fixture-key"));
    let mut broker = XaiCredentialBroker::new(store);
    assert_eq!(broker.presence(), &KeychainPresence::Unchecked);
    assert_eq!(counts.inspect.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);

    let first = broker.open_explicit().expect("first explicit connect");
    let project_a = first.clone();
    let project_b = first.clone();
    let refreshed = broker.open_explicit().expect("refresh reuses lease");
    for lease in [&first, &project_a, &project_b, &refreshed] {
        let identity = lease.clone_identity().expect("active credential");
        assert_eq!(
            format!("{identity:?}"),
            "PlusLiveIdentity { api_key: [redacted] }"
        );
    }
    assert_eq!(
        counts.load.load(Ordering::Relaxed),
        1,
        "one connected lifetime must perform exactly one Keychain secret read"
    );
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 0);

    broker.revoke();
    for lease in [&first, &project_a, &project_b, &refreshed] {
        assert!(lease.ensure_active().is_err());
        assert!(lease.clone_identity().is_err());
    }
}

#[test]
fn entered_key_is_verified_by_one_keychain_readback() {
    let (store, counts) = CountingSecrets::new(None);
    let mut broker = XaiCredentialBroker::new(store);
    let entered = SecretBytes::new(b"newly-entered-key".to_vec()).expect("valid key");
    let lease = broker
        .store_verified_and_open(&entered)
        .expect("store entered key and open lease");
    assert_eq!(broker.presence(), &KeychainPresence::Present);
    assert!(lease.clone_identity().is_ok());
    assert_eq!(counts.store.load(Ordering::Relaxed), 1);
    assert_eq!(
        counts.load.load(Ordering::Relaxed),
        1,
        "the new stable item must be read once and compared before connection"
    );
    broker.delete().expect("delete entered key");
    assert!(lease.ensure_active().is_err());
    assert_eq!(broker.presence(), &KeychainPresence::Absent);
    assert_eq!(counts.delete.load(Ordering::Relaxed), 1);
}

#[test]
fn broker_v3_is_the_only_current_generation_and_automatic_open_is_bounded() {
    let (store, counts) = CountingSecrets::new(Some(b"existing-broker-key"));
    let mut broker = XaiCredentialBroker::new(store);
    assert_eq!(broker.migration_state(), &KeychainMigrationState::Unchecked);
    let lease = broker.open_automatic().expect("no-UI broker open");
    assert_eq!(broker.migration_state(), &KeychainMigrationState::BrokerV3);
    assert!(lease.is_active());
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 1);
    broker.open_explicit().expect("reuse active lease");
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 1);
}

#[derive(Default)]
struct MigrationCounts {
    v3_load: AtomicUsize,
    v3_store: AtomicUsize,
    v2_load: AtomicUsize,
    v2_delete: AtomicUsize,
    v1_load: AtomicUsize,
    v1_delete: AtomicUsize,
}

struct MigrationSecrets {
    v3: Mutex<Option<Vec<u8>>>,
    v2: Mutex<Option<Vec<u8>>>,
    v1: Mutex<Option<Vec<u8>>>,
    counts: Arc<MigrationCounts>,
}

impl MigrationSecrets {
    fn new(
        v3: Option<&[u8]>,
        v2: Option<&[u8]>,
        v1: Option<&[u8]>,
    ) -> (Arc<Self>, Arc<MigrationCounts>) {
        let counts = Arc::new(MigrationCounts::default());
        (
            Arc::new(Self {
                v3: Mutex::new(v3.map(<[u8]>::to_vec)),
                v2: Mutex::new(v2.map(<[u8]>::to_vec)),
                v1: Mutex::new(v1.map(<[u8]>::to_vec)),
                counts: Arc::clone(&counts),
            }),
            counts,
        )
    }
}

impl ProviderSecretStore for MigrationSecrets {
    fn inspect_xai_key(&self) -> KeychainPresence {
        if self.v3.lock().expect("v3 lock").is_some() {
            KeychainPresence::Present
        } else {
            KeychainPresence::Absent
        }
    }

    fn load_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.v3_load.fetch_add(1, Ordering::Relaxed);
        self.v3
            .lock()
            .expect("v3 lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn store_xai_key(&self, key: &SecretBytes) -> Result<(), String> {
        self.counts.v3_store.fetch_add(1, Ordering::Relaxed);
        *self.v3.lock().expect("v3 lock") = Some(key.as_slice().to_vec());
        Ok(())
    }

    fn delete_xai_key(&self) -> Result<(), String> {
        *self.v3.lock().expect("v3 lock") = None;
        Ok(())
    }

    fn inspect_previous_xai_key(&self) -> KeychainPresence {
        if self.v2.lock().expect("v2 lock").is_some() {
            KeychainPresence::Present
        } else {
            KeychainPresence::Absent
        }
    }

    fn load_previous_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.v2_load.fetch_add(1, Ordering::Relaxed);
        self.v2
            .lock()
            .expect("v2 lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn delete_previous_xai_key(&self) -> Result<(), String> {
        self.counts.v2_delete.fetch_add(1, Ordering::Relaxed);
        *self.v2.lock().expect("v2 lock") = None;
        Ok(())
    }

    fn inspect_legacy_xai_key(&self) -> KeychainPresence {
        if self.v1.lock().expect("v1 lock").is_some() {
            KeychainPresence::Present
        } else {
            KeychainPresence::Absent
        }
    }

    fn load_legacy_xai_key(&self) -> Result<Option<SecretBytes>, String> {
        self.counts.v1_load.fetch_add(1, Ordering::Relaxed);
        self.v1
            .lock()
            .expect("v1 lock")
            .clone()
            .map(SecretBytes::new)
            .transpose()
    }

    fn delete_legacy_xai_key(&self) -> Result<(), String> {
        self.counts.v1_delete.fetch_add(1, Ordering::Relaxed);
        *self.v1.lock().expect("v1 lock") = None;
        Ok(())
    }
}

#[test]
fn legacy_key_migration_reads_once_verifies_v3_and_cleans_up() {
    let (store, counts) = MigrationSecrets::new(None, None, Some(b"legacy-key"));
    let mut broker = XaiCredentialBroker::new(store);
    broker.refresh_presence();
    assert_eq!(
        broker.migration_state(),
        &KeychainMigrationState::LegacyOnly
    );
    let material = broker.begin_migration().expect("begin legacy migration");
    assert!(material.lease().is_active());
    let lease = broker.finish_migration(material).expect("finish migration");
    assert!(lease.is_active());
    assert_eq!(broker.migration_state(), &KeychainMigrationState::BrokerV3);
    assert_eq!(counts.v1_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v3_store.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v3_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v1_delete.load(Ordering::Relaxed), 1);
}

#[test]
fn stable_v2_migration_verifies_v3_before_deleting_v2() {
    let (store, counts) = MigrationSecrets::new(None, Some(b"stable-key"), None);
    let mut broker = XaiCredentialBroker::new(store);
    broker.refresh_presence();
    assert_eq!(broker.migration_state(), &KeychainMigrationState::StableV2);
    let material = broker.begin_migration().expect("begin v2 migration");
    broker
        .finish_migration(material)
        .expect("finish v2 migration");
    assert_eq!(counts.v2_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v3_store.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v3_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v2_delete.load(Ordering::Relaxed), 1);
    assert_eq!(broker.migration_state(), &KeychainMigrationState::BrokerV3);
}

#[test]
fn cleanup_pending_mismatch_is_refused_without_deletion() {
    let (store, counts) =
        MigrationSecrets::new(Some(b"broker-key"), Some(b"different-v2-key"), None);
    let mut broker = XaiCredentialBroker::new(store);
    broker.refresh_presence();
    assert_eq!(
        broker.migration_state(),
        &KeychainMigrationState::CleanupPending
    );
    let error = broker.begin_migration().expect_err("mismatch must refuse");
    assert!(error.contains("differ"));
    assert_eq!(counts.v3_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v2_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v2_delete.load(Ordering::Relaxed), 0);
}

#[test]
fn cleanup_pending_equal_values_delete_only_predecessor_items() {
    let (store, counts) =
        MigrationSecrets::new(Some(b"same-key"), Some(b"same-key"), Some(b"same-key"));
    let mut broker = XaiCredentialBroker::new(store);
    broker.refresh_presence();
    let material = broker.begin_migration().expect("resume cleanup");
    broker.finish_migration(material).expect("finish cleanup");
    assert_eq!(counts.v3_store.load(Ordering::Relaxed), 0);
    assert_eq!(counts.v3_load.load(Ordering::Relaxed), 2);
    assert_eq!(counts.v2_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v1_load.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v2_delete.load(Ordering::Relaxed), 1);
    assert_eq!(counts.v1_delete.load(Ordering::Relaxed), 1);
    assert_eq!(broker.migration_state(), &KeychainMigrationState::BrokerV3);
}

#[test]
fn every_keychain_migration_crash_cut_has_one_fail_closed_resume_state() {
    type CrashCut<'a> = (
        Option<&'a [u8]>,
        Option<&'a [u8]>,
        Option<&'a [u8]>,
        KeychainMigrationState,
    );
    let cases: [CrashCut<'_>; 7] = [
        (None, None, None, KeychainMigrationState::Absent),
        (
            None,
            None,
            Some(&b"same-key"[..]),
            KeychainMigrationState::LegacyOnly,
        ),
        (
            None,
            Some(&b"same-key"[..]),
            None,
            KeychainMigrationState::StableV2,
        ),
        (
            Some(&b"same-key"[..]),
            None,
            None,
            KeychainMigrationState::BrokerV3,
        ),
        (
            Some(&b"same-key"[..]),
            Some(&b"same-key"[..]),
            None,
            KeychainMigrationState::CleanupPending,
        ),
        (
            None,
            Some(&b"same-key"[..]),
            Some(&b"same-key"[..]),
            KeychainMigrationState::CleanupPending,
        ),
        (
            Some(&b"same-key"[..]),
            Some(&b"same-key"[..]),
            Some(&b"same-key"[..]),
            KeychainMigrationState::CleanupPending,
        ),
    ];
    for (v3, v2, v1, expected) in cases {
        let (store, _) = MigrationSecrets::new(v3, v2, v1);
        let mut broker = XaiCredentialBroker::new(store);
        broker.refresh_presence();
        assert_eq!(broker.migration_state(), &expected);
    }
}

#[test]
fn startup_constructs_broker_without_keychain_requests() {
    let (store, counts) = CountingSecrets::new(Some(b"fixture-key"));
    let broker = XaiCredentialBroker::new(store);
    assert_eq!(broker.presence(), &KeychainPresence::Unchecked);
    assert_eq!(broker.migration_state(), &KeychainMigrationState::Unchecked);
    assert_eq!(counts.inspect.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 0);
}

#[test]
fn authorized_reconnect_uses_one_no_ui_keychain_query() {
    let (store, counts) = CountingSecrets::new(Some(b"fixture-key"));
    let mut broker = XaiCredentialBroker::new(store);
    let lease = broker.open_automatic().expect("bounded automatic open");
    assert!(lease.is_active());
    assert_eq!(counts.inspect.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load.load(Ordering::Relaxed), 0);
    assert_eq!(counts.load_without_ui.load(Ordering::Relaxed), 1);
}
