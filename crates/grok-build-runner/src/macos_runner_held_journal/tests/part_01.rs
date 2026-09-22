use std::fs::{self, OpenOptions as StdOpenOptions};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::{ambient_authority, fs::Dir};

use super::*;
#[cfg(target_os = "macos")]
use crate::macos_native_held_launch::{
    MacosNativeHeldLaunchOutcome, MacosNativeObservedHeldAtCleanupOutcome,
    MacosNativeObservedHeldAtReceiptV1, inert_system_fixture_authority,
    launch_inert_system_fixture,
};
use crate::macos_runner_held_protocol::{
    MacosOrdinaryRunnerHeldEvidence, MacosOrdinaryRunnerReleaseAuthorization,
    MacosOrdinaryRunnerReleaseEvidence,
};

fn digest(label: &str) -> Digest {
    Digest::sha256(label.as_bytes())
}

static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestDurableRoot {
    path: PathBuf,
}

impl TestDurableRoot {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "grok-build-macos-runner-held-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create private service-state root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("set service-state mode");
        let namespaces = path.join(SERVICE_NAMESPACES_DIRECTORY);
        fs::create_dir(&namespaces).expect("create service namespace index");
        fs::set_permissions(&namespaces, fs::Permissions::from_mode(0o700))
            .expect("set service namespace index mode");
        let mut options = StdOpenOptions::new();
        options.read(true).write(true).create_new(true).mode(0o600);
        let index_lock = options
            .open(namespaces.join(SERVICE_NAMESPACE_INDEX_LOCK))
            .expect("create service namespace index lock");
        index_lock
            .sync_all()
            .expect("sync service namespace index lock");
        fs::set_permissions(
            namespaces.join(SERVICE_NAMESPACE_INDEX_LOCK),
            fs::Permissions::from_mode(0o600),
        )
        .expect("set service namespace index-lock mode");
        StdOpenOptions::new()
            .read(true)
            .open(&namespaces)
            .expect("open service namespace index")
            .sync_all()
            .expect("sync service namespace index");
        StdOpenOptions::new()
            .read(true)
            .open(&path)
            .expect("open service-state directory")
            .sync_all()
            .expect("sync service-state directory");
        Self { path }
    }

    fn open(&self) -> Dir {
        Dir::open_ambient_dir(&self.path, ambient_authority())
            .expect("open private service-state root")
    }

    fn journal_path(&self) -> PathBuf {
        self.namespace_path_for(&MacosOrdinaryRunnerLaunchAuthority::test_fixture())
            .join(DURABLE_JOURNAL_DIRECTORY)
    }

    fn namespaces_path(&self) -> PathBuf {
        self.path.join(SERVICE_NAMESPACES_DIRECTORY)
    }

    fn namespace_path_for(&self, authority: &MacosOrdinaryRunnerLaunchAuthority) -> PathBuf {
        self.namespaces_path()
            .join(service_namespace_name(&service_namespace_key(authority)))
    }

    fn namespace_binding_path_for(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
    ) -> PathBuf {
        self.namespace_path_for(authority)
            .join(SERVICE_NAMESPACE_BINDING)
    }

    fn retirement_path_for(&self, authority: &MacosOrdinaryRunnerLaunchAuthority) -> PathBuf {
        self.namespaces_path()
            .join(service_namespace_retirement_name(&service_namespace_key(
                authority,
            )))
    }

    fn retirement_temporary_path_for(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
    ) -> PathBuf {
        self.namespaces_path()
            .join(service_namespace_retirement_temporary_name(
                &service_namespace_key(authority),
            ))
    }

    fn journal_path_for(&self, authority: &MacosOrdinaryRunnerLaunchAuthority) -> PathBuf {
        self.namespace_path_for(authority)
            .join(DURABLE_JOURNAL_DIRECTORY)
    }

    fn generation_path(&self, generation: u32) -> PathBuf {
        self.journal_path().join(generation_name(generation))
    }

    fn temporary_path(&self, generation: u32) -> PathBuf {
        self.journal_path()
            .join(temporary_generation_name(generation))
    }
}

impl Drop for TestDurableRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn mint_store(
    root: &TestDurableRoot,
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> MacosOrdinaryRunnerDurableStoreAuthority {
    MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
        root.open(),
        authority.clone(),
    )
    .expect("mint test service journal authority")
}

fn authority_with_field(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
    field: &str,
    value: &str,
) -> MacosOrdinaryRunnerLaunchAuthority {
    let mut encoded = serde_json::to_value(authority).expect("encode launch authority");
    encoded["attempt"][field] = serde_json::Value::String(value.into());
    let crossed: MacosOrdinaryRunnerLaunchAuthority =
        serde_json::from_value(encoded).expect("decode modified launch authority");
    crossed
        .validate_retained()
        .expect("modified launch authority remains independently well shaped");
    crossed
}

fn preparation_record(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
) -> MacosOrdinaryRunnerJournalRecord {
    MacosOrdinaryRunnerJournalRecord::preparation_intent(authority.clone(), 101)
        .expect("construct preparation record")
}

fn held_record(preparation: &MacosOrdinaryRunnerJournalRecord) -> MacosOrdinaryRunnerJournalRecord {
    let held = MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
        preparation.authority(),
        digest("durable held observation; test contract only"),
        102,
    )
    .expect("construct held evidence");
    record_held_preparation(preparation, held).expect("construct held record")
}

fn retirement_readback(
    authority: &MacosOrdinaryRunnerLaunchAuthority,
    label: &str,
) -> MacosOrdinaryRunnerNamespaceRetirementReadback {
    MacosOrdinaryRunnerNamespaceRetirementReadback::contract_only(
        authority.clone(),
        format!("cleanup terminal evidence:{label}").into_bytes(),
        format!("cleanup terminal readback:{label}").into_bytes(),
        1_000,
    )
    .expect("construct exact contract-only retirement readback")
}

fn copy_private(source: &Path, destination: &Path) {
    let bytes = fs::read(source).expect("read private source");
    write_private(destination, &bytes);
}

fn copy_namespace_tree(source: &Path, destination: &Path) {
    fs::create_dir(destination).expect("create replacement namespace");
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
        .expect("set replacement namespace mode");
    copy_private(
        &source.join(SERVICE_NAMESPACE_BINDING),
        &destination.join(SERVICE_NAMESPACE_BINDING),
    );
    let destination_journal = destination.join(DURABLE_JOURNAL_DIRECTORY);
    fs::create_dir(&destination_journal).expect("create replacement journal");
    fs::set_permissions(&destination_journal, fs::Permissions::from_mode(0o700))
        .expect("set replacement journal mode");
    for entry in
        fs::read_dir(source.join(DURABLE_JOURNAL_DIRECTORY)).expect("read source namespace journal")
    {
        let entry = entry.expect("read source journal entry");
        copy_private(&entry.path(), &destination_journal.join(entry.file_name()));
    }
}

fn write_private(destination: &Path, bytes: &[u8]) {
    let mut options = StdOpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut destination = options.open(destination).expect("create private copy");
    destination.write_all(bytes).expect("write private copy");
    destination.sync_all().expect("sync private copy");
    destination
        .set_permissions(fs::Permissions::from_mode(0o600))
        .expect("set private-copy mode");
}

#[cfg(target_os = "macos")]
fn add_extended_acl(path: &Path, inheritable: bool) {
    let acl = if inheritable {
        "everyone allow read,file_inherit,directory_inherit"
    } else {
        "everyone allow read"
    };
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg(acl)
        .arg(path)
        .status()
        .expect("execute chmod to create an adversarial test ACL");
    assert!(status.success(), "create adversarial test ACL at {path:?}");
}

#[cfg(target_os = "macos")]
fn remove_extended_acl(path: &Path) {
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .expect("execute chmod to remove adversarial test ACL");
    assert!(status.success(), "remove adversarial test ACL at {path:?}");
}

#[cfg(target_os = "macos")]
fn copy_apple_signed_service_image(root: &TestDurableRoot, source: &str, name: &str) -> PathBuf {
    let destination = root.path.join(name);
    fs::copy(source, &destination).expect("copy Apple-signed service image fixture");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
        .expect("set signed service image fixture mode");
    StdOpenOptions::new()
        .read(true)
        .open(&destination)
        .expect("open copied signed service fixture")
        .sync_all()
        .expect("sync copied signed service fixture");
    destination
}

#[cfg(target_os = "macos")]
#[test]
fn path_local_signed_image_observation_round_trips_without_admission_authority() {
    let root = TestDurableRoot::new("signed-service-binding-restart");
    let service_image = copy_apple_signed_service_image(&root, "/usr/bin/true", "signed-service");
    let substrate =
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &service_image,
            )
            .expect("bind exact signed image and retained store root");
    assert!(!MacosOrdinaryRunnerPathLocalSignedImageObservation::permits_execution());
    let mut namespace_entries = fs::read_dir(root.namespaces_path())
        .expect("read untouched namespace index")
        .map(|entry| {
            entry
                .expect("read namespace-index entry")
                .file_name()
                .into_string()
                .expect("namespace-index entry is UTF-8")
        })
        .collect::<Vec<_>>();
    namespace_entries.sort();
    assert_eq!(
        namespace_entries,
        vec![SERVICE_NAMESPACE_INDEX_LOCK.to_owned()],
        "a path-local image observation must not admit a launch namespace"
    );
    substrate
        .revalidate()
        .expect("live retained binding revalidates");
    let binding_path = root.path.join(SIGNED_SERVICE_TRUST_BINDING);
    let first_bytes = fs::read(&binding_path).expect("read first canonical binding");
    drop(substrate);

    let reopened =
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &service_image,
            )
            .expect("restart reopens exact signed image/store binding");
    reopened
        .revalidate()
        .expect("restart readback remains exact");
    assert_eq!(
        fs::read(binding_path).expect("read restarted canonical binding"),
        first_bytes
    );
    assert!(!MacosOrdinaryRunnerPathLocalSignedImageObservation::permits_execution());
}

#[cfg(target_os = "macos")]
#[test]
fn path_local_codesign_observation_requests_all_architectures_but_stays_non_admissible() {
    assert_eq!(
        CODESIGN_VERIFY_ARGUMENTS
            .iter()
            .filter(|argument| **argument == "--all-architectures")
            .count(),
        1
    );
    assert_eq!(
        CODESIGN_DISPLAY_ARGUMENTS
            .iter()
            .filter(|argument| **argument == "--all-architectures")
            .count(),
        1
    );
    assert!(!MacosOrdinaryRunnerPathLocalSignedImageObservation::permits_execution());
}

#[cfg(target_os = "macos")]
#[test]
fn path_local_signed_image_binding_rejects_same_byte_inode_replacement() {
    let root = TestDurableRoot::new("signed-service-same-byte-replacement");
    let service_image = copy_apple_signed_service_image(&root, "/usr/bin/true", "signed-service");
    let substrate =
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &service_image,
            )
            .expect("bind original signed service image");
    let original_bytes = fs::read(&service_image).expect("read original signed service bytes");
    let original_metadata = fs::metadata(&service_image).expect("inspect original signed service");
    let original_inode = std::os::unix::fs::MetadataExt::ino(&original_metadata);
    drop(substrate);

    let displaced = root.path.join("signed-service.displaced");
    fs::rename(&service_image, &displaced).expect("displace original signed service inode");
    fs::copy(&displaced, &service_image).expect("copy exact signed bytes into replacement");
    fs::set_permissions(&service_image, fs::Permissions::from_mode(0o755))
        .expect("set replacement signed service mode");
    let replacement_metadata =
        fs::metadata(&service_image).expect("inspect replacement signed service");
    let replacement_inode = std::os::unix::fs::MetadataExt::ino(&replacement_metadata);
    assert_ne!(replacement_inode, original_inode);
    assert_eq!(
        fs::read(&service_image).expect("read replacement signed service bytes"),
        original_bytes
    );

    let failure =
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &service_image,
            )
            .err()
            .expect("same bytes at a replacement inode must fail closed");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::Substitution
    );
}

#[cfg(target_os = "macos")]
#[test]
fn path_local_signed_image_binding_rejects_crossed_stable_apple_signed_image() {
    let root = TestDurableRoot::new("signed-service-crossed-identity");
    let original = copy_apple_signed_service_image(&root, "/usr/bin/true", "signed-service-true");
    let crossed = copy_apple_signed_service_image(&root, "/usr/bin/false", "signed-service-false");
    drop(
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &original,
            )
            .expect("bind original Apple-signed service identity"),
        );

    let failure =
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                root.open(),
                &crossed,
            )
            .err()
            .expect("different valid Apple-signed identity must not cross the binding");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::Substitution
    );
}

#[cfg(target_os = "macos")]
#[test]
fn path_local_signed_image_binding_rejects_unavailable_and_ad_hoc_signatures() {
    let unsigned_root = TestDurableRoot::new("unsigned-service-image");
    let unsigned = unsigned_root.path.join("unsigned-service");
    write_private(&unsigned, b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(&unsigned, fs::Permissions::from_mode(0o755))
        .expect("set unsigned service executable mode");
    assert!(
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                unsigned_root.open(),
                &unsigned,
            )
            .is_err(),
            "unavailable code signature must fail closed"
        );
    assert!(
        !unsigned_root
            .path
            .join(SIGNED_SERVICE_TRUST_BINDING)
            .exists()
    );

    let ad_hoc_root = TestDurableRoot::new("ad-hoc-service-image");
    let ad_hoc = copy_apple_signed_service_image(&ad_hoc_root, "/usr/bin/true", "ad-hoc-service");
    let status = Command::new("/usr/bin/codesign")
        .env_clear()
        .env("LC_ALL", "C")
        .args(["--force", "--sign", "-"])
        .arg(&ad_hoc)
        .status()
        .expect("create ad-hoc signed service fixture");
    assert!(status.success(), "create ad-hoc signed service fixture");
    assert!(
            MacosOrdinaryRunnerPathLocalSignedImageObservation::from_signed_image_path_and_retained_root(
                ad_hoc_root.open(),
                &ad_hoc,
            )
            .is_err(),
            "ad-hoc code signature must fail closed"
        );
    assert!(!ad_hoc_root.path.join(SIGNED_SERVICE_TRUST_BINDING).exists());
}

fn prepared_harness() -> (
    MacosOrdinaryRunnerJournalHarness,
    MacosOrdinaryRunnerHeldEvidence,
) {
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let held = MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
        &authority,
        digest("host-test setup observation; not native evidence"),
        102,
    )
    .expect("construct held candidate");
    let mut harness =
        MacosOrdinaryRunnerJournalHarness::new(authority, 101).expect("construct journal harness");
    harness
        .append_held(held.clone())
        .expect("append held candidate");
    (harness, held)
}

#[test]
fn exact_four_generation_lifecycle_round_trips_canonically() {
    let (mut harness, held) = prepared_harness();
    let guard = ();
    let authorization = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        harness.head().authority(),
        &held,
        digest("outer preparation envelope"),
        103,
        &guard,
    )
    .expect("construct test live authorization");
    harness
        .append_release_intent_for_test(authorization)
        .expect("append release intent");
    let release = MacosOrdinaryRunnerReleaseEvidence::candidate_from_native_observation(
        harness.head().authority(),
        &held,
        harness
            .head()
            .release_authorization()
            .expect("release authorization"),
        digest("host-test release observation; not native evidence"),
        104,
    )
    .expect("construct release candidate");
    harness
        .append_released(release)
        .expect("append release candidate");

    let expected_authority = harness.expected_authority.clone();
    let history = harness.canonical_history().expect("encode history");
    assert_eq!(history.len(), 4);
    let mut reopened = Vec::new();
    for bytes in history {
        let record = MacosOrdinaryRunnerJournalRecord::decode_canonical(
            &bytes,
            &expected_authority,
            reopened.last(),
        )
        .expect("reopen generation");
        reopened.push(record);
    }
    validate_history(&expected_authority, &reopened).expect("validate reopened history");
    assert_eq!(
        reopened.last().map(MacosOrdinaryRunnerJournalRecord::state),
        Some(MacosOrdinaryRunnerJournalState::Released)
    );
}

#[test]
fn restart_actions_never_replay_prepare_or_release() {
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = MacosOrdinaryRunnerJournalRecord::preparation_intent(authority.clone(), 101)
        .expect("prepare intent");
    assert_eq!(
        recovery_action(&authority, std::slice::from_ref(&preparation)).expect("recovery action"),
        MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
    );

    let (mut harness, held) = prepared_harness();
    assert_eq!(
        recovery_action(&harness.expected_authority, &harness.generations).expect("held recovery"),
        MacosOrdinaryRunnerRecoveryAction::ReconcileOuterPreparation
    );
    let guard = ();
    let authorization = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        harness.head().authority(),
        &held,
        digest("outer evidence"),
        103,
        &guard,
    )
    .expect("authorization");
    harness
        .append_release_intent_for_test(authorization)
        .expect("release intent");
    assert_eq!(
        recovery_action(&harness.expected_authority, &harness.generations)
            .expect("release recovery"),
        MacosOrdinaryRunnerRecoveryAction::ReconcileRelease
    );
}

#[test]
fn duplicate_or_out_of_order_release_is_rejected() {
    let (mut harness, held) = prepared_harness();
    let guard = ();
    let authorization = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        harness.head().authority(),
        &held,
        digest("outer evidence"),
        103,
        &guard,
    )
    .expect("authorization");
    harness
        .append_release_intent_for_test(authorization)
        .expect("first release intent");

    let second = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        harness.head().authority(),
        &held,
        digest("outer evidence"),
        104,
        &guard,
    )
    .expect("second authorization candidate");
    assert!(harness.append_release_intent_for_test(second).is_err());
    assert!(harness.append_held(held).is_err());
}

#[test]
fn substituted_prefix_or_noncanonical_encoding_is_rejected() {
    let (harness, _) = prepared_harness();
    let expected_authority = harness.expected_authority.clone();
    let history = harness.canonical_history().expect("encode history");
    let first =
        MacosOrdinaryRunnerJournalRecord::decode_canonical(&history[0], &expected_authority, None)
            .expect("first generation");
    let mut changed = history[1].clone();
    changed.push(b' ');
    assert!(
        MacosOrdinaryRunnerJournalRecord::decode_canonical(
            &changed,
            &expected_authority,
            Some(&first),
        )
        .is_err()
    );

    let unrelated =
        MacosOrdinaryRunnerJournalRecord::preparation_intent(expected_authority.clone(), 102)
            .expect("unrelated initial generation");
    assert!(
        MacosOrdinaryRunnerJournalRecord::decode_canonical(
            &history[1],
            &expected_authority,
            Some(&unrelated),
        )
        .is_err()
    );
}

#[test]
fn persisted_history_requires_exact_external_authority_and_native_journal() {
    let expected = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let record = MacosOrdinaryRunnerJournalRecord::preparation_intent(expected.clone(), 101)
        .expect("preparation intent");
    let bytes = record.canonical_bytes().expect("canonical record");

    let mut crossed_value = serde_json::to_value(&expected).expect("encode authority");
    crossed_value["attempt"]["native_journal_id"] =
        serde_json::Value::String("journal-macos-ordinary-runner-crossed".into());
    let crossed: MacosOrdinaryRunnerLaunchAuthority =
        serde_json::from_value(crossed_value).expect("decode crossed authority");
    crossed
        .validate_retained()
        .expect("crossed authority is internally valid");

    assert!(MacosOrdinaryRunnerJournalRecord::decode_canonical(&bytes, &crossed, None).is_err());
    assert!(recovery_action(&crossed, std::slice::from_ref(&record)).is_err());
    assert!(validate_history(&crossed, &[record]).is_err());
}

#[test]
fn held_and_release_candidates_bind_exact_authority_and_time() {
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    assert!(
        MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
            &authority,
            digest("setup"),
            99,
        )
        .is_err()
    );
    let held = MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
        &authority,
        digest("setup"),
        102,
    )
    .expect("held");
    let guard = ();
    let authorization = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        &authority,
        &held,
        digest("outer"),
        103,
        &guard,
    )
    .expect("authorization");
    assert!(
        MacosOrdinaryRunnerReleaseEvidence::candidate_from_native_observation(
            &authority,
            &held,
            authorization.record(),
            digest("release"),
            102,
        )
        .is_err()
    );
}

#[test]
fn durable_store_publishes_and_reads_back_one_exact_generation() {
    let root = TestDurableRoot::new("exact-readback");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let record = preparation_record(&authority);
    let mut store = mint_store(&root, &authority);

    let receipt = store
        .append_generation(&record)
        .expect("durably append preparation generation");
    assert!(receipt.matches_operation_readback(&record));
    assert_eq!(
        store.durable_history().expect("read durable history"),
        vec![record]
    );
    assert_eq!(
        store
            .deterministic_restart_action()
            .expect("select restart action"),
        MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
    );
}

#[cfg(target_os = "macos")]
#[test]
fn real_observed_held_at_digest_binds_to_durable_restart_prefix_without_release() {
    let root = TestDurableRoot::new("real-held-restart-prefix");
    let authority = inert_system_fixture_authority().expect("construct exact test authority");
    let preparation = preparation_record(&authority);
    let mut store = mint_store(&root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation intent before native spawn");

    let child = match launch_inert_system_fixture(&authority)
        .expect("launch real cleanup-only observed-held-at child")
    {
        MacosNativeHeldLaunchOutcome::ObservedHeldAt(child) => *child,
        MacosNativeHeldLaunchOutcome::FailedAfterSpawnCleaned { .. } => {
            panic!("native launch failed after spawn and was cleaned")
        }
        MacosNativeHeldLaunchOutcome::ReconciliationRequired(value) => {
            panic!("native launch unexpectedly requires reconciliation: {value:?}")
        }
    };
    let emitted_bytes = child
        .receipt()
        .canonical_bytes()
        .expect("emit exact real observed-held-at receipt bytes");
    let emitted = MacosNativeObservedHeldAtReceiptV1::decode_canonical(&emitted_bytes)
        .expect("reopen emitted real observed-held-at receipt bytes");
    assert_eq!(&emitted, child.receipt());
    assert!(
        emitted
            .matches_launch_authority(&authority)
            .expect("cross observed-held-at receipt to exact launch authority")
    );
    let held_evidence = MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
        &authority,
        child.receipt().receipt_digest().clone(),
        child.receipt().observed_held_at_unix_ms(),
    )
    .expect("bind real observed-held-at digest to ordinary journal evidence");
    let held = record_held_preparation(&preparation, held_evidence)
        .expect("derive held journal successor");
    store
        .append_generation(&held)
        .expect("persist real held receipt join");
    drop(store);

    let mut reopened = mint_store(&root, &authority);
    assert_eq!(
        reopened
            .durable_history()
            .expect("reopen exact real-held journal prefix"),
        vec![preparation, held]
    );
    let action = reopened
        .deterministic_restart_action()
        .expect("derive cleanup-only restart action");
    assert_eq!(
        action,
        MacosOrdinaryRunnerRecoveryAction::ReconcileOuterPreparation
    );
    assert!(
        !action.permits_native_release(),
        "durable observation digest must never manufacture restart release authority"
    );
    drop(reopened);

    assert!(matches!(
        child.terminate_and_reap(),
        MacosNativeObservedHeldAtCleanupOutcome::Cleaned(_)
    ));
}

#[test]
fn crashes_through_the_cut_before_rename_leave_no_committed_successor() {
    for failure_point in [
        TestDurableFailurePoint::BeforeTemporarySync,
        TestDurableFailurePoint::AfterTemporarySync,
        TestDurableFailurePoint::BeforeRename,
    ] {
        let root = TestDurableRoot::new("temporary-crash");
        let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
        let preparation = preparation_record(&authority);
        let held = held_record(&preparation);
        let mut store = mint_store(&root, &authority);
        store
            .append_generation(&preparation)
            .expect("persist preparation");
        store.inject_next_failure(failure_point);
        let failure = store
            .append_generation(&held)
            .expect_err("injected temporary crash must fail");
        assert_eq!(
            failure.class(),
            MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired
        );
        assert!(root.temporary_path(2).exists());
        drop(store);

        let mut reopened = mint_store(&root, &authority);
        assert!(!root.temporary_path(2).exists());
        assert_eq!(
            reopened.durable_history().expect("reopen committed prefix"),
            vec![preparation]
        );
        let action = reopened
            .deterministic_restart_action()
            .expect("recover before publication");
        assert_eq!(
            action,
            MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
        );
        assert!(!action.permits_native_release());
    }
}

#[test]
fn crashes_from_after_rename_through_readback_recover_published_successor() {
    for failure_point in [
        TestDurableFailurePoint::AfterRename,
        TestDurableFailurePoint::BeforeDirectorySync,
        TestDurableFailurePoint::AfterDirectorySync,
        TestDurableFailurePoint::BeforeReadback,
        TestDurableFailurePoint::AfterReadback,
    ] {
        let root = TestDurableRoot::new("publication-crash");
        let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
        let preparation = preparation_record(&authority);
        let held = held_record(&preparation);
        let mut store = mint_store(&root, &authority);
        store
            .append_generation(&preparation)
            .expect("persist preparation");
        store.inject_next_failure(failure_point);
        let failure = store
            .append_generation(&held)
            .expect_err("injected publication crash must fail");
        assert_eq!(
            failure.class(),
            MacosOrdinaryRunnerDurableFailureClass::Ambiguous
        );
        let exact_retry = store
            .append_generation(&held)
            .expect_err("exact retry must observe the published generation");
        assert_eq!(
            exact_retry.class(),
            MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished
        );
        let substituted_held = record_held_preparation(
            &preparation,
            MacosOrdinaryRunnerHeldEvidence::candidate_from_native_observation(
                &authority,
                digest("crossed held observation after ambiguous rename"),
                102,
            )
            .expect("construct substituted held evidence"),
        )
        .expect("construct substituted held generation");
        let substitution = store
            .append_generation(&substituted_held)
            .expect_err("crossed retry must not replace the published generation");
        assert_eq!(
            substitution.class(),
            MacosOrdinaryRunnerDurableFailureClass::Substitution
        );
        drop(store);

        let mut reopened = mint_store(&root, &authority);
        assert_eq!(
            reopened.durable_history().expect("reopen published prefix"),
            vec![preparation, held]
        );
        let action = reopened
            .deterministic_restart_action()
            .expect("recover after publication");
        assert_eq!(
            action,
            MacosOrdinaryRunnerRecoveryAction::ReconcileOuterPreparation
        );
        assert!(!action.permits_native_release());
    }
}

#[test]
fn service_namespaces_separate_ids_and_reject_same_id_authority_reuse() {
    let root = TestDurableRoot::new("crossed-authority");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let mut store = mint_store(&root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation");
    drop(store);

    let distinct = authority_with_field(
        &authority,
        "native_journal_id",
        "journal-macos-ordinary-runner-distinct-store",
    );
    let distinct_preparation = preparation_record(&distinct);
    let mut distinct_store = mint_store(&root, &distinct);
    distinct_store
        .append_generation(&distinct_preparation)
        .expect("persist preparation in disjoint namespace");
    assert_ne!(
        root.namespace_path_for(&authority),
        root.namespace_path_for(&distinct)
    );
    let mut original = mint_store(&root, &authority);
    assert_eq!(
        original.durable_history().expect("reopen original history"),
        vec![preparation]
    );

    let reused_id = authority_with_field(
        &authority,
        "attempt_id",
        "attempt-macos-ordinary-runner-crossed-same-journal",
    );
    let failure = MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
        root.open(),
        reused_id,
    )
    .err()
    .expect("same native journal ID must not bind a second authority");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::Substitution
    );
}

#[test]
fn one_long_lived_service_hosts_two_launches_but_rejects_live_duplicate_admission() {
    let root = TestDurableRoot::new("long-lived-multi-launch-service");
    let first_authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let second_authority = authority_with_field(
        &first_authority,
        "native_journal_id",
        "journal-macos-ordinary-runner-second-live-launch",
    );
    let first_record = preparation_record(&first_authority);
    let second_record = preparation_record(&second_authority);
    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("open long-lived service state");
    let mut first = service
        .admit_launch(first_authority.clone())
        .expect("admit first launch namespace");
    first
        .append_generation(&first_record)
        .expect("append first launch generation");
    let mut second = service
        .admit_launch(second_authority.clone())
        .expect("admit second launch namespace");
    second
        .append_generation(&second_record)
        .expect("append second launch generation");
    let duplicate = service
        .admit_launch(first_authority.clone())
        .err()
        .expect("live duplicate admission must be rejected");
    assert_eq!(
        duplicate.class(),
        MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished
    );
    drop(first);
    drop(second);
    drop(service);

    let mut restarted =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("restart long-lived service state");
    let mut reopened_first = restarted
        .admit_launch(first_authority)
        .expect("reopen first namespace after restart");
    assert_eq!(
        reopened_first
            .durable_history()
            .expect("read first history after restart"),
        vec![first_record]
    );
    let mut reopened_second = restarted
        .admit_launch(second_authority)
        .expect("reopen second namespace after restart");
    assert_eq!(
        reopened_second
            .durable_history()
            .expect("read second history after restart"),
        vec![second_record]
    );
}

#[test]
fn retained_service_rejects_same_byte_namespace_replacement() {
    let root = TestDurableRoot::new("namespace-replacement");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let mut store = mint_store(&root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation before namespace replacement");
    let namespace = root.namespace_path_for(&authority);
    let displaced = root.path.join("displaced-service-namespace");
    fs::rename(&namespace, &displaced).expect("displace retained service namespace");
    copy_namespace_tree(&displaced, &namespace);
    assert!(
        store.durable_history().is_err(),
        "same-byte replacement must not satisfy the retained namespace identity"
    );
}

#[test]
fn restart_reconciles_only_the_exact_complete_namespace_temporary() {
    let root = TestDurableRoot::new("namespace-temporary-restart");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let mut store = mint_store(&root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation before namespace publication replay fixture");
    drop(store);
    let key = service_namespace_key(&authority);
    let final_path = root.namespace_path_for(&authority);
    let temporary_path = root
        .namespaces_path()
        .join(service_namespace_temporary_name(&key));
    fs::rename(&final_path, &temporary_path).expect("restore exact publication temporary");

    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("restart service with one exact namespace temporary");
    let mut reopened = service
        .admit_launch(authority)
        .expect("reconcile exact complete namespace temporary");
    assert_eq!(
        reopened
            .durable_history()
            .expect("read reconciled namespace history"),
        vec![preparation]
    );
    assert!(final_path.exists());
    assert!(!temporary_path.exists());
    let action = reopened
        .deterministic_restart_action()
        .expect("select restart action after namespace reconciliation");
    assert_eq!(
        action,
        MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
    );
    assert!(!action.permits_native_release());
}

#[test]
fn contract_only_retirement_is_append_only_and_permanently_fences_native_journal_reuse() {
    let root = TestDurableRoot::new("namespace-retirement-no-reuse");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("open service-state authority");
    let mut store = service
        .admit_launch(authority.clone())
        .expect("admit exact namespace before retirement");
    store
        .append_generation(&preparation_record(&authority))
        .expect("persist a retained launch journal prefix");
    service
        .record_contract_only_retirement(&retirement_readback(&authority, "exact"))
        .expect("publish exact no-reuse retirement tombstone");
    assert!(root.retirement_path_for(&authority).is_file());
    let Err(duplicate) = service.admit_launch(authority.clone()) else {
        panic!("retired native journal ID cannot be admitted again")
    };
    assert_eq!(
        duplicate.class(),
        MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished
    );
    drop(store);
    drop(service);

    let mut restarted =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("restart retains exact tombstone and namespace identities");
    let Err(replay) = restarted.admit_launch(authority) else {
        panic!("restart cannot reuse a tombstoned native journal ID")
    };
    assert_eq!(
        replay.class(),
        MacosOrdinaryRunnerDurableFailureClass::AlreadyPublished
    );
}

#[test]
fn retirement_rejects_crossed_cleanup_readback_and_retained_tombstone_replacement() {
    let root = TestDurableRoot::new("namespace-retirement-crossed");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let crossed = authority_with_field(&authority, "launch_id", "crossed-retirement-launch");
    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("open service-state authority");
    service
        .admit_launch(authority.clone())
        .expect("admit exact namespace before crossed retirement");
    let failure = service
        .record_contract_only_retirement(&retirement_readback(&crossed, "crossed"))
        .expect_err("crossed cleanup readback cannot retire another namespace");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::Substitution
    );
    let mut cleanup_crossed = retirement_readback(&authority, "cleanup-crossed");
    cleanup_crossed.cleanup_effect_id = "crossed-cleanup-effect".into();
    cleanup_crossed.readback_digest = cleanup_crossed
        .computed_digest()
        .expect("recompute crossed cleanup readback digest");
    assert_eq!(
        service
            .record_contract_only_retirement(&cleanup_crossed)
            .expect_err("crossed cleanup effect cannot retire the exact namespace")
            .class(),
        MacosOrdinaryRunnerDurableFailureClass::Substitution
    );
    service
        .record_contract_only_retirement(&retirement_readback(&authority, "exact"))
        .expect("publish retained retirement tombstone");
    let tombstone = root.retirement_path_for(&authority);
    let displaced = root.namespaces_path().join("displaced-tombstone");
    fs::rename(&tombstone, &displaced).expect("displace retirement tombstone");
    copy_private(&displaced, &tombstone);
    assert!(
        service.admit_launch(authority).is_err(),
        "same-byte retirement replacement must fail retained identity validation"
    );
}

#[test]
fn retirement_temporary_or_missing_namespace_is_reconciliation_only() {
    let root = TestDurableRoot::new("namespace-retirement-ambiguity");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("open service-state authority");
    service
        .admit_launch(authority.clone())
        .expect("admit exact namespace before retirement ambiguity");
    let bytes = retirement_readback(&authority, "temporary")
        .canonical_bytes()
        .expect("encode exact temporary retirement");
    write_private(&root.retirement_temporary_path_for(&authority), &bytes);
    drop(service);
    let mut service =
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .expect("restart retains ambiguous retirement temporary for reconciliation");
    let failure = service
        .record_contract_only_retirement(&retirement_readback(&authority, "temporary"))
        .expect_err("unresolved retirement temporary blocks append");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::RecoveryRequired
    );
    fs::remove_file(root.retirement_temporary_path_for(&authority))
        .expect("remove adversarial temporary outside the boundary");
    service
        .record_contract_only_retirement(&retirement_readback(&authority, "exact"))
        .expect("publish exact retirement after ambiguity is removed");
    fs::remove_dir_all(root.namespace_path_for(&authority))
        .expect("remove retained namespace outside boundary");
    drop(service);
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::test_service_state_authority(root.open())
            .is_err(),
        "tombstone without its exact retained namespace is restart ambiguity, never reuse"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_acl_inspection_accepts_absence_and_refuses_error_or_nonempty_acl() {
    let root = TestDurableRoot::new("darwin-acl-api");
    let retained = root.open();
    require_no_macos_extended_acl(&retained).expect("empty extended ACL is admissible");
    assert!(darwin_acl::inspect_invalid_descriptor_for_test().is_err());
    add_extended_acl(&root.path, true);
    assert!(require_no_macos_extended_acl(&retained).is_err());
    remove_extended_acl(&root.path);
    require_no_macos_extended_acl(&retained).expect("removed extended ACL is absent again");
}

#[cfg(target_os = "macos")]
#[test]
fn production_facing_boundary_rejects_acl_on_every_admitted_state_object() {
    let object_labels = [
        "service-root",
        "namespace-index",
        "namespace-index-lock",
        "launch-namespace",
        "namespace-binding",
        "journal-root",
        "journal-writer-lock",
        "journal-generation",
    ];
    for label in object_labels {
        let root = TestDurableRoot::new(&format!("acl-{label}"));
        let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
        let mut store = mint_store(&root, &authority);
        store
            .append_generation(&preparation_record(&authority))
            .expect("create complete state-object ACL fixture");
        drop(store);
        let target = match label {
            "service-root" => root.path.clone(),
            "namespace-index" => root.namespaces_path(),
            "namespace-index-lock" => root.namespaces_path().join(SERVICE_NAMESPACE_INDEX_LOCK),
            "launch-namespace" => root.namespace_path_for(&authority),
            "namespace-binding" => root.namespace_binding_path_for(&authority),
            "journal-root" => root.journal_path_for(&authority),
            "journal-writer-lock" => root.journal_path_for(&authority).join(DURABLE_WRITER_LOCK),
            "journal-generation" => root.generation_path(1),
            _ => unreachable!("closed state-object ACL fixture"),
        };
        let inheritable = matches!(
            label,
            "service-root" | "namespace-index" | "launch-namespace" | "journal-root"
        );
        add_extended_acl(&target, inheritable);
        let failure = MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            root.open(),
            authority,
        )
        .err()
        .expect("ACL-bearing service-state object must be rejected");
        assert!(
            failure.operation.contains("acl"),
            "{label} failed through {:?}, not ACL inspection: {failure}",
            failure.operation
        );
        remove_extended_acl(&target);
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the source-policy fixture audits the complete closed unsafe allowlist and each bridge's exact symbol surface in one place"
)]
fn source_policy_permits_only_the_closed_target_gated_unsafe_modules() {
    fn raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        if matches!(bytes.get(cursor), Some(b'b' | b'c')) {
            cursor = cursor.saturating_add(1);
        }
        if bytes.get(cursor) != Some(&b'r') {
            return None;
        }
        cursor = cursor.saturating_add(1);
        let hashes_start = cursor;
        while bytes.get(cursor) == Some(&b'#') {
            cursor = cursor.saturating_add(1);
        }
        let hash_count = cursor.saturating_sub(hashes_start);
        if bytes.get(cursor) != Some(&b'"') {
            return None;
        }
        cursor = cursor.saturating_add(1);
        while cursor < bytes.len() {
            if bytes[cursor] == b'"'
                && bytes
                    .get(cursor + 1..cursor + 1 + hash_count)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                return Some(cursor + 1 + hash_count);
            }
            cursor = cursor.saturating_add(1);
        }
        panic!("unterminated raw string in source-policy input");
    }

    fn quoted_literal_end(bytes: &[u8], start: usize, quote: u8) -> usize {
        let mut cursor = start.saturating_add(1);
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'\\' => cursor = cursor.saturating_add(2),
                byte if byte == quote => return cursor.saturating_add(1),
                _ => cursor = cursor.saturating_add(1),
            }
        }
        panic!("unterminated quoted literal in source-policy input");
    }

    fn character_literal_end(contents: &str, quote: usize) -> Option<usize> {
        let bytes = contents.as_bytes();
        let first = *bytes.get(quote + 1)?;
        if first != b'\\' {
            let width = contents[quote + 1..].chars().next()?.len_utf8();
            return (bytes.get(quote + 1 + width) == Some(&b'\'')).then_some(quote + 2 + width);
        }
        let escape = *bytes.get(quote + 2)?;
        let close = match escape {
            b'x' => quote + 5,
            b'u' if bytes.get(quote + 3) == Some(&b'{') => bytes[quote + 4..]
                .iter()
                .position(|byte| *byte == b'}')
                .map(|offset| quote + 5 + offset)?,
            _ => quote + 3,
        };
        (bytes.get(close) == Some(&b'\'')).then_some(close + 1)
    }

    fn rust_policy_tokens(contents: &str) -> Vec<String> {
        let bytes = contents.as_bytes();
        let mut tokens = Vec::new();
        let mut cursor = 0_usize;
        while cursor < bytes.len() {
            if bytes[cursor].is_ascii_whitespace() {
                cursor = cursor.saturating_add(1);
                continue;
            }
            if bytes.get(cursor..cursor + 2) == Some(b"//") {
                cursor = bytes[cursor..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |offset| cursor + offset + 1);
                continue;
            }
            if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                let mut depth = 1_usize;
                cursor = cursor.saturating_add(2);
                while depth > 0 {
                    match bytes.get(cursor..cursor + 2) {
                        Some(b"/*") => {
                            depth = depth.saturating_add(1);
                            cursor = cursor.saturating_add(2);
                        }
                        Some(b"*/") => {
                            depth = depth.saturating_sub(1);
                            cursor = cursor.saturating_add(2);
                        }
                        Some(_) => cursor = cursor.saturating_add(1),
                        None => panic!("unterminated block comment in source-policy input"),
                    }
                }
                continue;
            }
            if let Some(end) = raw_string_end(bytes, cursor) {
                tokens.push(contents[cursor..end].to_owned());
                cursor = end;
                continue;
            }
            let normal_string_start = if matches!(bytes.get(cursor), Some(b'b' | b'c'))
                && bytes.get(cursor + 1) == Some(&b'"')
            {
                Some(cursor + 1)
            } else if bytes[cursor] == b'"' {
                Some(cursor)
            } else {
                None
            };
            if let Some(quote) = normal_string_start {
                let end = quoted_literal_end(bytes, quote, b'"');
                tokens.push(contents[cursor..end].to_owned());
                cursor = end;
                continue;
            }
            let char_start = if bytes[cursor] == b'b' && bytes.get(cursor + 1) == Some(&b'\'') {
                Some(cursor + 1)
            } else if bytes[cursor] == b'\'' {
                Some(cursor)
            } else {
                None
            };
            if let Some(quote) = char_start
                && let Some(candidate_end) = character_literal_end(contents, quote)
            {
                tokens.push(contents[cursor..candidate_end].to_owned());
                cursor = candidate_end;
                continue;
            }
            if bytes.get(cursor..cursor + 2) == Some(b"r#")
                && bytes.get(cursor + 2).is_some_and(u8::is_ascii_alphabetic)
            {
                cursor = cursor.saturating_add(2);
            }
            if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
                let start = cursor;
                cursor = cursor.saturating_add(1);
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    cursor = cursor.saturating_add(1);
                }
                tokens.push(contents[start..cursor].to_owned());
                continue;
            }
            tokens.push(char::from(bytes[cursor]).to_string());
            cursor = cursor.saturating_add(1);
        }
        tokens
    }

    fn matching_delimiter(tokens: &[String], start: usize, open: &str, close: &str) -> usize {
        assert_eq!(tokens[start], open, "delimiter scan must start on {open}");
        let mut depth = 1_usize;
        for (offset, token) in tokens[start + 1..].iter().enumerate() {
            if token == open {
                depth = depth.saturating_add(1);
            } else if token == close {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return start + offset + 1;
                }
            }
        }
        panic!("unclosed {open} delimiter in source-policy input");
    }

    fn unsafe_lint_exceptions(tokens: &[String]) -> Vec<String> {
        let lint = "unsafe_code";
        let mut attributes = Vec::new();
        let mut cursor = 0_usize;
        while cursor < tokens.len() {
            if tokens[cursor] != "#" {
                cursor = cursor.saturating_add(1);
                continue;
            }
            let bracket =
                cursor + usize::from(tokens.get(cursor + 1).is_some_and(|token| token == "!")) + 1;
            if tokens.get(bracket).is_none_or(|token| token != "[") {
                cursor = cursor.saturating_add(1);
                continue;
            }
            let end = matching_delimiter(tokens, bracket, "[", "]");
            attributes.push((bracket + 1, end));
            cursor = end.saturating_add(1);
        }

        let mut recognized = Vec::new();
        for (start, end) in attributes {
            let mut cursor = start;
            while cursor < end {
                let kind = tokens[cursor].as_str();
                if !matches!(kind, "allow" | "expect" | "warn" | "deny" | "forbid")
                    || tokens.get(cursor + 1).is_none_or(|token| token != "(")
                {
                    cursor = cursor.saturating_add(1);
                    continue;
                }
                let close = matching_delimiter(tokens, cursor + 1, "(", ")");
                for (offset, token) in tokens[cursor + 2..close].iter().enumerate() {
                    if token == lint {
                        recognized.push((
                            cursor + offset + 2,
                            matches!(kind, "allow" | "expect").then(|| kind.to_owned()),
                        ));
                    }
                }
                cursor = close.saturating_add(1);
            }
        }
        recognized.sort();
        let all_lint_tokens = tokens
            .iter()
            .enumerate()
            .filter_map(|(index, token)| (token == lint).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(
            recognized
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            all_lint_tokens,
            "every unsafe-code lint token must be inside a recognized lint-level attribute"
        );
        recognized
            .into_iter()
            .filter_map(|(_, kind)| kind)
            .collect()
    }

    fn contains_token_sequence(tokens: &[String], expected: &[&str]) -> bool {
        tokens.windows(expected.len()).any(|window| {
            window
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        })
    }

    fn foreign_declaration_blocks(tokens: &[String]) -> Vec<(bool, String, Vec<String>)> {
        let mut blocks = Vec::new();
        let mut cursor = 0_usize;
        while cursor < tokens.len() {
            if tokens[cursor] != "extern" {
                cursor = cursor.saturating_add(1);
                continue;
            }
            let is_unsafe = cursor > 0 && tokens[cursor - 1] == "unsafe";
            let (abi, brace) = match tokens.get(cursor + 1) {
                Some(token) if token == "{" => ("default-C".to_owned(), cursor + 1),
                Some(token) if token.starts_with('"') => {
                    if tokens.get(cursor + 2).is_none_or(|next| next != "{") {
                        cursor = cursor.saturating_add(1);
                        continue;
                    }
                    (token.clone(), cursor + 2)
                }
                _ => {
                    cursor = cursor.saturating_add(1);
                    continue;
                }
            };
            let end = matching_delimiter(tokens, brace, "{", "}");
            let mut declarations = Vec::new();
            let mut item_start = brace + 1;
            let mut parentheses = 0_usize;
            let mut brackets = 0_usize;
            let mut nested_braces = 0_usize;
            for index in brace + 1..end {
                match tokens[index].as_str() {
                    "(" => parentheses = parentheses.saturating_add(1),
                    ")" => parentheses = parentheses.saturating_sub(1),
                    "[" => brackets = brackets.saturating_add(1),
                    "]" => brackets = brackets.saturating_sub(1),
                    "{" => nested_braces = nested_braces.saturating_add(1),
                    "}" => nested_braces = nested_braces.saturating_sub(1),
                    ";" if parentheses == 0 && brackets == 0 && nested_braces == 0 => {
                        declarations.push(tokens[item_start..=index].concat());
                        item_start = index.saturating_add(1);
                    }
                    _ => {}
                }
            }
            assert!(
                tokens[item_start..end].is_empty(),
                "foreign declaration block has an unterminated declaration"
            );
            blocks.push((is_unsafe, abi, declarations));
            cursor = end.saturating_add(1);
        }
        blocks
    }

    fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).expect("scan source policy directory") {
            let entry = entry.expect("read source policy entry");
            let path = entry.path();
            if path.is_dir() {
                // Hidden directories hold non-policy source copies (agent
                // worktrees, editor state) and must never widen the scan.
                let excluded = path.file_name().is_some_and(|name| {
                    name == "target" || name.to_string_lossy().starts_with('.')
                });
                if !excluded {
                    rust_sources(&path, sources);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("runner crate is nested under workspace/crates");
    for (fixture, expected_kind) in [
        ("#[allow(unsafe_code)] mod fixture {}", "allow"),
        ("#![allow(dead_code, unsafe_code)]", "allow"),
        ("#[expect(unsafe_code)] fn fixture() {}", "expect"),
        (
            "#[cfg_attr(any(), allow(unsafe_code, reason = \"fixture\"))] mod fixture {}",
            "allow",
        ),
        (
            "#[cfg_attr(any(), cfg_attr(all(), expect(r#unsafe_code)))] mod fixture {}",
            "expect",
        ),
    ] {
        assert_eq!(
            unsafe_lint_exceptions(&rust_policy_tokens(fixture)),
            [expected_kind],
            "unsafe-lint escape syntax must remain recognized"
        );
    }
    assert!(
        unsafe_lint_exceptions(&rust_policy_tokens("#![forbid(unsafe_code)]")).is_empty(),
        "a strengthening lint level is not an unsafe-code exception"
    );
    let mut sources = Vec::new();
    rust_sources(&workspace.join("crates"), &mut sources);
    let mut exceptions = Vec::new();
    let mut foreign_blocks = Vec::new();
    for source in sources {
        let contents = fs::read_to_string(&source).expect("read Rust source for unsafe policy");
        let tokens = rust_policy_tokens(&contents);
        for kind in unsafe_lint_exceptions(&tokens) {
            exceptions.push((source.clone(), kind));
        }
        for block in foreign_declaration_blocks(&tokens) {
            foreign_blocks.push((source.clone(), block));
        }
    }
    exceptions.sort();
    let expected = [
        (
            workspace.join("crates/grok-build-keychain-broker/src/macos.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-runner/src/linux_held_launcher/native_release.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_helper_transport.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_native_held_launch.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_runner_held_journal.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_vz_guest.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/bounded_process/darwin_group.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/capture_bridge.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/desktop_bridge.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/session_lifecycle.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/tts_transport.rs"),
            "allow".to_owned(),
        ),
        (
            workspace.join("crates/grok-build-tauri/src/voice_permission.rs"),
            "allow".to_owned(),
        ),
    ];
    assert_eq!(
        exceptions, expected,
        "unsafe exceptions differ from the closed platform allowlist"
    );
    for (source, target_os, module_name) in [
        (
            workspace.join("crates/grok-build-runner/src/linux_held_launcher/native_release.rs"),
            "\"linux\"",
            "linux_release_exec",
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_helper_transport.rs"),
            "\"macos\"",
            "darwin_peer_identity",
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_native_held_launch.rs"),
            "\"macos\"",
            "darwin_spawn",
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_runner_held_journal.rs"),
            "\"macos\"",
            "darwin_acl",
        ),
        (
            workspace.join("crates/grok-build-runner/src/macos_vz_guest.rs"),
            "\"macos\"",
            "darwin_virtualization",
        ),
    ] {
        let exception_source =
            fs::read_to_string(&source).expect("read unsafe-code exception source");
        let exception_tokens = rust_policy_tokens(&exception_source);
        assert!(
            contains_token_sequence(
                &exception_tokens,
                &[
                    "#",
                    "[",
                    "cfg",
                    "(",
                    "target_os",
                    "=",
                    target_os,
                    ")",
                    "]",
                    "#",
                    "[",
                    "allow",
                    "(",
                    "unsafe_code",
                    ")",
                    "]",
                    "mod",
                    module_name,
                ],
            ),
            "unsafe exception must remain on its exact target-gated module"
        );
    }

    foreign_blocks.sort();
    let expected_foreign_blocks = [
            // The credential broker asks Security.framework to refuse any
            // noninteractive Keychain prompt. The constant is the only raw
            // symbol not exposed by the typed framework crate.
            (
                workspace.join("crates/grok-build-keychain-broker/src/macos.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    ["#[link_name=\"kSecUseAuthenticationUIFail\"]staticK_SEC_USE_AUTHENTICATION_UI_FAIL:CFStringRef;"]
                        .map(str::to_owned)
                        .to_vec(),
                ),
            ),
            // The Linux containment release. `execve` is declared here so the
            // held launcher can never reach `execvp`, whose `ENOEXEC` retry
            // through `/bin/sh` (D-0009) put a shell inside the target's
            // identity; `dup2` and `signal` carry the exact stdio and SIGPIPE
            // setup `std`'s exec used to perform. All three are POSIX
            // async-signal-safe.
            (
                workspace.join(
                    "crates/grok-build-runner/src/linux_held_launcher/native_release.rs",
                ),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fndup2(source:c_int,target:c_int)->c_int;",
                        "fnsignal(number:c_int,handler:usize)->usize;",
                        "fnexecve(path:*constc_char,argv:*const*mutc_char,environment:*const*mutc_char,)->c_int;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_helper_transport.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fngetsockopt(socket:c_int,level:c_int,name:c_int,value:*mutc_void,length:*mutu32,)->c_int;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_helper_transport.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "statickCFTypeDictionaryKeyCallBacks:CFDictionaryKeyCallBacks;",
                        "statickCFTypeDictionaryValueCallBacks:CFDictionaryValueCallBacks;",
                        "fnCFRelease(object:CFTypeRef);",
                        "fnCFGetTypeID(object:CFTypeRef)->CFTypeID;",
                        "fnCFDataGetTypeID()->CFTypeID;",
                        "fnCFDataCreate(allocator:CFAllocatorRef,bytes:*constu8,length:CFIndex)->CFTypeRef;",
                        "fnCFDataGetLength(data:CFTypeRef)->CFIndex;",
                        "fnCFDataGetBytePtr(data:CFTypeRef)->*constu8;",
                        "fnCFStringCreateWithBytes(allocator:CFAllocatorRef,bytes:*constu8,length:CFIndex,encoding:u32,external_representation:c_uchar,)->CFTypeRef;",
                        "fnCFDictionaryCreate(allocator:CFAllocatorRef,keys:*constCFTypeRef,values:*constCFTypeRef,count:CFIndex,key_callbacks:*constCFDictionaryKeyCallBacks,value_callbacks:*constCFDictionaryValueCallBacks,)->CFTypeRef;",
                        "fnCFDictionaryGetValue(dictionary:CFTypeRef,key:CFTypeRef)->CFTypeRef;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_helper_transport.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "statickSecGuestAttributeAudit:CFTypeRef;",
                        "statickSecCodeInfoUnique:CFTypeRef;",
                        "fnSecCodeCopyGuestWithAttributes(host:CFTypeRef,attributes:CFTypeRef,flags:CFOptionFlags,guest:*mutCFTypeRef,)->OSStatus;",
                        "fnSecCodeCopySigningInformation(code:CFTypeRef,flags:CFOptionFlags,information:*mutCFTypeRef,)->OSStatus;",
                        "fnSecRequirementCreateWithString(text:CFTypeRef,flags:CFOptionFlags,requirement:*mutCFTypeRef,)->OSStatus;",
                        "fnSecCodeCheckValidity(code:CFTypeRef,flags:CFOptionFlags,requirement:CFTypeRef,)->OSStatus;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            // The fork-apply-exec surface. Every symbol except `sandbox_init`
            // and `sandbox_free_error` is POSIX async-signal-safe; those two
            // may only run in a child forked from a task proved to have exactly
            // one thread, and they are the only public way to apply a Seatbelt
            // profile because `sandbox_compile_string`, `sandbox_apply`, and
            // `sandbox_free_profile` are absent from libSystem on macOS 15.
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_native_held_launch.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fnfork()->c_int;",
                        "fndup2(source:c_int,target:c_int)->c_int;",
                        "fnclose(descriptor:c_int)->c_int;",
                        "fnfchdir(descriptor:c_int)->c_int;",
                        "fnsetsid()->c_int;",
                        "fnraise(signal:c_int)->c_int;",
                        "fnwrite(descriptor:c_int,buffer:*constc_void,count:usize)->isize;",
                        "fnexecve(path:*constc_char,argv:*const*mutc_char,envp:*const*mutc_char)->c_int;",
                        "fn_exit(status:c_int)->!;",
                        "fnsandbox_init(profile:*constc_char,flags:u64,error:*mut*mutc_char)->c_int;",
                        "fnsandbox_free_error(error:*mutc_char);",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_native_held_launch.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fnposix_spawn(pid:*mutc_int,path:*constc_char,file_actions:*constPosixSpawnFileActions,attr:*constPosixSpawnAttr,argv:*const*mutc_char,envp:*const*mutc_char,)->c_int;",
                        "fnposix_spawn_file_actions_init(actions:*mutPosixSpawnFileActions)->c_int;",
                        "fnposix_spawn_file_actions_destroy(actions:*mutPosixSpawnFileActions)->c_int;",
                        "fnposix_spawn_file_actions_adddup2(actions:*mutPosixSpawnFileActions,source:c_int,target:c_int,)->c_int;",
                        "fnposix_spawn_file_actions_addinherit_np(actions:*mutPosixSpawnFileActions,descriptor:c_int,)->c_int;",
                        "fnposix_spawn_file_actions_addfchdir_np(actions:*mutPosixSpawnFileActions,descriptor:c_int,)->c_int;",
                        "fnposix_spawnattr_init(attr:*mutPosixSpawnAttr)->c_int;",
                        "fnposix_spawnattr_destroy(attr:*mutPosixSpawnAttr)->c_int;",
                        "fnposix_spawnattr_setflags(attr:*mutPosixSpawnAttr,flags:c_short)->c_int;",
                        "fnproc_pidinfo(pid:c_int,flavor:c_int,arg:u64,buffer:*mutc_void,buffer_size:c_int,)->c_int;",
                        "fnproc_pidpath(pid:c_int,buffer:*mutc_void,buffer_size:c_uint)->c_int;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            (
                workspace
                    .join("crates/grok-build-runner/src/macos_runner_held_journal.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fnacl_get_fd_np(fd:i32,acl_type:i32)->Acl;",
                        "fnacl_get_entry(acl:Acl,entry_id:i32,entry:*mutAclEntry)->i32;",
                        "fnacl_free(object:*mutc_void)->i32;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            // The Virtualization.framework guest host. Objective-C is the only
            // interface that framework publishes, so the bridge is the
            // Objective-C runtime's three entry points plus the two libSystem
            // globals a capture-free completion-handler block and the main
            // dispatch queue are built from. `objc_msgSend` is declared with no
            // parameters and cast per call site because the arm64 ABI has no
            // single correct signature for it.
            (
                workspace.join("crates/grok-build-runner/src/macos_vz_guest.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fnobjc_getClass(name:*constc_char)->Id;",
                        "fnsel_registerName(name:*constc_char)->Sel;",
                        "fnobjc_msgSend();",
                        "static_NSConcreteGlobalBlock:[*constc_void;32];",
                        "static_dispatch_main_q:[*constc_void;8];",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            // `VZErrorDomain` is the framework's only exported C symbol and is
            // what separates the entitlement refusal from any other
            // configuration error. Linking Virtualization is also what loads
            // its Objective-C classes, and Foundation's, into this process.
            (
                workspace.join("crates/grok-build-runner/src/macos_vz_guest.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    ["staticVZErrorDomain:Id;"].map(str::to_owned).to_vec(),
                ),
            ),
            // The machine is bound to the dispatch queue it was created with;
            // this module uses the main queue, so servicing the main run loop
            // is the only context the framework's callbacks execute in.
            (
                workspace.join("crates/grok-build-runner/src/macos_vz_guest.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "statickCFRunLoopDefaultMode:*constc_void;",
                        "fnCFRunLoopRunInMode(mode:*constc_void,seconds:f64,return_after_source:u8)->i32;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
            // Accessibility trust has one process query, one explicit prompt
            // query, and the documented CoreFoundation prompt key.
            (
                workspace.join("crates/grok-build-tauri/src/desktop_bridge.rs"),
                (
                    true,
                    "\"C\"".to_owned(),
                    [
                        "fnAXIsProcessTrusted()->u8;",
                        "fnAXIsProcessTrustedWithOptions(options:Option<&CFDictionary>)->u8;",
                        "statickAXTrustedCheckOptionPrompt:&'staticCFString;",
                    ]
                    .map(str::to_owned)
                    .to_vec(),
                ),
            ),
        ];
    assert_eq!(
        foreign_blocks, expected_foreign_blocks,
        "foreign declaration blocks differ from the closed platform FFI surface"
    );
    let workspace_manifest =
        fs::read_to_string(workspace.join("Cargo.toml")).expect("read workspace manifest");
    assert!(workspace_manifest.contains("unsafe_code = \"deny\""));
    assert!(workspace_manifest.contains("unsafe_op_in_unsafe_fn = \"deny\""));
}

#[test]
fn retained_authority_rejects_parallel_root_and_fixed_root_replacement() {
    let first = TestDurableRoot::new("retained-first-root");
    let second = TestDurableRoot::new("parallel-second-root");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let mut store = mint_store(&first, &authority);
    store.service_state_root = second.open();
    assert!(store.durable_history().is_err());

    let mut store = mint_store(&first, &authority);
    let displaced = first.path.join("displaced-journal-root");
    fs::rename(first.journal_path(), &displaced).expect("displace fixed journal root");
    fs::create_dir(first.journal_path()).expect("create replacement journal root");
    fs::set_permissions(first.journal_path(), fs::Permissions::from_mode(0o700))
        .expect("set replacement mode");
    let mut options = StdOpenOptions::new();
    options.read(true).write(true).create_new(true).mode(0o600);
    options
        .open(first.journal_path().join(DURABLE_WRITER_LOCK))
        .expect("create replacement writer lock");
    assert!(store.durable_history().is_err());
}

#[test]
fn one_writer_lock_rejects_a_concurrent_service_authority() {
    let root = TestDurableRoot::new("one-writer");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let first = mint_store(&root, &authority);
    let mut second = mint_store(&root, &authority);
    lock_durable_writer(&first.writer_lock).expect("hold first writer lock");
    let failure = second
        .append_generation(&preparation_record(&authority))
        .expect_err("second authority must not acquire writer lock");
    assert_eq!(
        failure.class(),
        MacosOrdinaryRunnerDurableFailureClass::NotPublished
    );
    flock(&first.writer_lock, FlockOperation::Unlock).expect("release first writer lock");
}

#[test]
fn generation_replacement_duplicate_and_missing_prefix_fail_closed() {
    let replacement_root = TestDurableRoot::new("generation-replacement");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let mut replacement_store = mint_store(&replacement_root, &authority);
    replacement_store
        .append_generation(&preparation)
        .expect("persist preparation");
    let generation = replacement_root.generation_path(1);
    let displaced = replacement_root.journal_path().join("displaced-generation");
    fs::rename(&generation, &displaced).expect("displace generation");
    copy_private(&displaced, &generation);
    assert!(replacement_store.durable_history().is_err());

    let duplicate_root = TestDurableRoot::new("duplicate-generation");
    let mut duplicate_store = mint_store(&duplicate_root, &authority);
    duplicate_store
        .append_generation(&preparation)
        .expect("persist preparation for duplicate test");
    copy_private(
        &duplicate_root.generation_path(1),
        &duplicate_root
            .journal_path()
            .join("generation-0000001.record"),
    );
    drop(duplicate_store);
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            duplicate_root.open(),
            authority.clone(),
        )
        .is_err()
    );

    let missing_root = TestDurableRoot::new("missing-generation");
    let held = held_record(&preparation);
    let mut missing_store = mint_store(&missing_root, &authority);
    missing_store
        .append_generation(&preparation)
        .expect("persist first generation");
    missing_store
        .append_generation(&held)
        .expect("persist second generation");
    drop(missing_store);
    fs::remove_file(missing_root.generation_path(1)).expect("remove first generation");
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            missing_root.open(),
            authority,
        )
        .is_err()
    );
}

#[test]
fn durable_scan_rejects_oversized_and_unknown_entries_within_fixed_bounds() {
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let oversized_root = TestDurableRoot::new("oversized-generation");
    drop(mint_store(&oversized_root, &authority));
    write_private(
        &oversized_root.generation_path(1),
        &vec![0_u8; MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES + 1],
    );
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            oversized_root.open(),
            authority.clone(),
        )
        .is_err()
    );

    let unknown_root = TestDurableRoot::new("unknown-entry");
    drop(mint_store(&unknown_root, &authority));
    write_private(
        &unknown_root.journal_path().join("caller-selected-journal"),
        b"not a generation",
    );
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            unknown_root.open(),
            authority,
        )
        .is_err()
    );
}

#[test]
fn exact_next_temporary_is_removed_but_stale_duplicate_temporary_is_rejected() {
    let reconciled_root = TestDurableRoot::new("reconcile-next-temporary");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let held = held_record(&preparation);
    let mut store = mint_store(&reconciled_root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation");
    store.inject_next_failure(TestDurableFailurePoint::AfterTemporarySync);
    assert!(store.append_generation(&held).is_err());
    drop(store);
    let mut reopened = mint_store(&reconciled_root, &authority);
    assert_eq!(
        reopened
            .durable_history()
            .expect("reconcile exact temporary"),
        vec![preparation.clone()]
    );

    let stale_root = TestDurableRoot::new("reject-stale-temporary");
    let mut stale_store = mint_store(&stale_root, &authority);
    stale_store
        .append_generation(&preparation)
        .expect("persist preparation for stale temporary");
    copy_private(
        &stale_root.generation_path(1),
        &stale_root.temporary_path(1),
    );
    drop(stale_store);
    assert!(
        MacosOrdinaryRunnerDurableStoreAuthority::mint_test_service_authority(
            stale_root.open(),
            authority,
        )
        .is_err()
    );
}

#[test]
fn every_durable_restart_state_is_reconciliation_only_and_never_releases() {
    let root = TestDurableRoot::new("restart-never-releases");
    let authority = MacosOrdinaryRunnerLaunchAuthority::test_fixture();
    let preparation = preparation_record(&authority);
    let held = held_record(&preparation);
    let mut store = mint_store(&root, &authority);
    store
        .append_generation(&preparation)
        .expect("persist preparation");
    let action = store
        .deterministic_restart_action()
        .expect("preparation restart action");
    assert_eq!(
        action,
        MacosOrdinaryRunnerRecoveryAction::ReconcilePreparation
    );
    assert!(!action.permits_native_release());

    store
        .append_generation(&held)
        .expect("persist held preparation");
    let action = store
        .deterministic_restart_action()
        .expect("held restart action");
    assert_eq!(
        action,
        MacosOrdinaryRunnerRecoveryAction::ReconcileOuterPreparation
    );
    assert!(!action.permits_native_release());

    let held_evidence = held.held_evidence().expect("held evidence").clone();
    let guard = ();
    let authorization = MacosOrdinaryRunnerReleaseAuthorization::for_test(
        &authority,
        &held_evidence,
        digest("durable outer preparation envelope"),
        103,
        &guard,
    )
    .expect("construct release authorization");
    let transition = intend_release(&held, authorization).expect("construct release intent");
    let (release_intent, _live_authorization) = transition.into_parts();
    store
        .append_generation(&release_intent)
        .expect("persist release intent without releasing");
    let action = store
        .deterministic_restart_action()
        .expect("release-intent restart action");
    assert_eq!(action, MacosOrdinaryRunnerRecoveryAction::ReconcileRelease);
    assert!(!action.permits_native_release());

    let release = MacosOrdinaryRunnerReleaseEvidence::candidate_from_native_observation(
        &authority,
        &held_evidence,
        release_intent
            .release_authorization()
            .expect("release authorization record"),
        digest("durable release observation; test contract only"),
        104,
    )
    .expect("construct release evidence");
    let released = record_released(&release_intent, release).expect("construct released record");
    store
        .append_generation(&released)
        .expect("persist released observation");
    let action = store
        .deterministic_restart_action()
        .expect("released restart action");
    assert_eq!(action, MacosOrdinaryRunnerRecoveryAction::None);
    assert!(!action.permits_native_release());
}
