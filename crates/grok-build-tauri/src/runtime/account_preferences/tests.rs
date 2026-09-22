use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

static NEXT_TEST: AtomicUsize = AtomicUsize::new(1);

fn fixture_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "grok-build-account-preferences-{label}-{}-{}",
        std::process::id(),
        NEXT_TEST.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn preference_record_is_owner_only_atomic_and_contains_no_connection_claim() {
    let root = fixture_root("owner-only");
    let store = AccountPreferenceStore::new(root.clone());
    store
        .save(AccountPreferences {
            selected_transport: RuntimeTransport::XaiKeychain,
            onboarding_acknowledged: true,
            auto_reconnect_enabled: true,
            reconnect_grant: Some(
                ReconnectGrant::fixed(RuntimeTransport::XaiKeychain, 1_700_000_000_000)
                    .expect("fixed grant"),
            ),
            credential_binding_identity: Some("0123456789ABCDEF0123456789ABCDEF01234567".into()),
            keychain_broker_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        })
        .expect("save preferences");
    let bytes = fs::read(root.join(ACCOUNT_PREFERENCES_FILE)).expect("read preferences");
    let text = String::from_utf8(bytes).expect("UTF-8 preferences");
    assert!(text.contains("XaiKeychain"));
    assert!(!text.contains("Connected"));
    assert!(!text.contains("model"));
    assert!(!text.contains("secret"));
    assert!(!text.contains("apiKey"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(root.join(ACCOUNT_PREFERENCES_FILE))
            .expect("preference metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
    }
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn corrupt_or_future_account_preferences_are_refused() {
    let root = fixture_root("corrupt");
    let store = AccountPreferenceStore::new(root.clone());
    store
        .save(AccountPreferences::default())
        .expect("seed preferences");
    fs::write(
        root.join(ACCOUNT_PREFERENCES_FILE),
        br#"{"schemaVersion":99,"selectedTransport":"XaiKeychain","onboardingAcknowledged":true}"#,
    )
    .expect("write future schema");
    let future = store.load().expect_err("future schema must fail");
    assert!(future.contains("unsupported"));
    fs::write(root.join(ACCOUNT_PREFERENCES_FILE), b"not-json").expect("write corrupt record");
    assert!(
        store
            .load()
            .expect_err("corrupt record must fail")
            .contains("decode")
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn schema_one_migrates_without_fabricating_a_grant() {
    let root = fixture_root("schema-one");
    fs::create_dir_all(&root).expect("fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let path = root.join(ACCOUNT_PREFERENCES_FILE);
    fs::write(
        &path,
        br#"{"schemaVersion":1,"selectedTransport":"XaiKeychain","onboardingAcknowledged":true}"#,
    )
    .expect("legacy preferences");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("record mode");
    }
    let migrated = AccountPreferenceStore::new(root.clone())
        .load_at(1_700_000_000_000)
        .expect("migrate")
        .expect("preferences");
    assert_eq!(migrated.selected_transport, RuntimeTransport::XaiKeychain);
    assert!(migrated.onboarding_acknowledged);
    assert!(migrated.auto_reconnect_enabled);
    assert!(migrated.reconnect_grant.is_none());
    assert!(migrated.credential_binding_identity.is_none());
    assert!(migrated.keychain_broker_sha256.is_none());
    let migrated_text = fs::read_to_string(path).expect("migrated record");
    assert!(migrated_text.contains("\"schemaVersion\": 4"));
    assert!(migrated_text.contains("\"reconnectGrant\": null"));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn schema_two_preserves_grant_but_requires_one_explicit_broker_binding() {
    let root = fixture_root("schema-two-acl");
    fs::create_dir_all(&root).expect("fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let now = 1_700_000_000_000_u64;
    let grant = ReconnectGrant::fixed(RuntimeTransport::XaiKeychain, now).expect("fixed grant");
    let path = root.join(ACCOUNT_PREFERENCES_FILE);
    fs::write(
        &path,
        format!(
            concat!(
                "{{\"schemaVersion\":2,",
                "\"selectedTransport\":\"XaiKeychain\",",
                "\"onboardingAcknowledged\":true,",
                "\"autoReconnectEnabled\":true,",
                "\"reconnectGrant\":{{\"transport\":\"XaiKeychain\",",
                "\"authorizedAtUtcMs\":{},\"expiresAtUtcMs\":{}}},",
                "\"credentialBindingIdentity\":",
                "\"0123456789ABCDEF0123456789ABCDEF01234567\"}}"
            ),
            grant.authorized_at_utc_ms, grant.expires_at_utc_ms
        ),
    )
    .expect("schema-two preferences");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("record mode");
    }
    let migrated = AccountPreferenceStore::new(root.clone())
        .load_at(now)
        .expect("migrate")
        .expect("preferences");
    assert_eq!(migrated.reconnect_grant, Some(grant));
    assert_eq!(
        migrated.credential_binding_identity.as_deref(),
        Some("0123456789ABCDEF0123456789ABCDEF01234567")
    );
    assert!(migrated.keychain_broker_sha256.is_none());
    let migrated_text = fs::read_to_string(path).expect("migrated record");
    assert!(migrated_text.contains("\"schemaVersion\": 4"));
    assert!(migrated_text.contains("\"keychainBrokerSha256\": null"));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn schema_three_drops_unproven_main_app_acl_claim_and_requires_broker_binding() {
    let root = fixture_root("schema-three-broker");
    fs::create_dir_all(&root).expect("fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("root mode");
    }
    let now = 1_700_000_000_000_u64;
    let grant = ReconnectGrant::fixed(RuntimeTransport::XaiKeychain, now).expect("fixed grant");
    let path = root.join(ACCOUNT_PREFERENCES_FILE);
    fs::write(
        &path,
        format!(
            concat!(
                "{{\"schemaVersion\":3,",
                "\"selectedTransport\":\"XaiKeychain\",",
                "\"onboardingAcknowledged\":true,",
                "\"autoReconnectEnabled\":true,",
                "\"reconnectGrant\":{{\"transport\":\"XaiKeychain\",",
                "\"authorizedAtUtcMs\":{},\"expiresAtUtcMs\":{}}},",
                "\"credentialBindingIdentity\":",
                "\"0123456789ABCDEF0123456789ABCDEF01234567\",",
                "\"keychainAclBindingIdentity\":",
                "\"0123456789ABCDEF0123456789ABCDEF01234567\"}}"
            ),
            grant.authorized_at_utc_ms, grant.expires_at_utc_ms
        ),
    )
    .expect("schema-three preferences");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("record mode");
    }
    let migrated = AccountPreferenceStore::new(root.clone())
        .load_at(now)
        .expect("migrate")
        .expect("preferences");
    assert_eq!(migrated.reconnect_grant, Some(grant));
    assert!(migrated.keychain_broker_sha256.is_none());
    let migrated_text = fs::read_to_string(path).expect("migrated record");
    assert!(migrated_text.contains("\"schemaVersion\": 4"));
    assert!(migrated_text.contains("\"keychainBrokerSha256\": null"));
    assert!(!migrated_text.contains("keychainAclBindingIdentity"));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn reconnect_grant_is_exactly_seven_days_and_never_rolls_implicitly() {
    let authorized = 1_700_000_000_000;
    let grant =
        ReconnectGrant::fixed(RuntimeTransport::GrokCliAcp, authorized).expect("fixed grant");
    assert_eq!(grant.expires_at_utc_ms, authorized + RECONNECT_GRANT_MILLIS);
    assert!(grant.is_unexpired(grant.expires_at_utc_ms - 1));
    assert!(!grant.is_unexpired(grant.expires_at_utc_ms));
    assert_eq!(grant.validate(authorized).expect("valid grant"), grant);
}

#[test]
fn future_clock_and_non_fixed_window_are_refused() {
    let authorized = 1_700_000_000_000;
    let grant =
        ReconnectGrant::fixed(RuntimeTransport::GrokCliAcp, authorized).expect("fixed grant");
    assert!(grant.validate(authorized - 1).is_err());
    let malformed = ReconnectGrant {
        expires_at_utc_ms: grant.expires_at_utc_ms + 1,
        ..grant
    };
    assert!(malformed.validate(authorized).is_err());
}
