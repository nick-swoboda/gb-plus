use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{OwnerStateErrorKind, OwnerStateRoot, ReplaceCut};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

fn root(label: &str) -> PathBuf {
    let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "grok-owner-state-{label}-{}-{sequence}",
        std::process::id()
    ))
}

#[test]
fn shared_owner_state_writes_refuse_symlinks_and_enforce_owner_modes() {
    let path = root("owner");
    let file = OwnerStateRoot::new(&path)
        .file("settings.json", 32)
        .expect("bounded file");
    file.replace(b"first").expect("first replace");
    assert_eq!(file.read().expect("read"), Some(b"first".to_vec()));
    assert_eq!(
        fs::metadata(&path)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path.join("settings.json"))
            .expect("file metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::remove_file(path.join("settings.json")).expect("remove file");
    symlink("target", path.join("settings.json")).expect("file symlink");
    assert_eq!(
        file.read().expect_err("symlink refused").kind,
        OwnerStateErrorKind::Open
    );
    fs::remove_dir_all(path).expect("cleanup");
}

#[test]
fn shared_owner_state_crash_cuts_never_expose_torn_bytes() {
    for cut in [
        ReplaceCut::BeforeWrite,
        ReplaceCut::AfterWrite,
        ReplaceCut::AfterFileSync,
        ReplaceCut::AfterRename,
        ReplaceCut::AfterDirectorySync,
    ] {
        let path = root("cut");
        let file = OwnerStateRoot::new(&path)
            .file("settings.json", 32)
            .expect("bounded file");
        file.replace(b"old").expect("seed");
        file.replace_inner(b"new-complete", Some(cut))
            .expect_err("injected cut");
        let observed = file.read().expect("read after cut").expect("record");
        assert!(observed == b"old" || observed == b"new-complete");
        assert!(!observed.is_empty());
        fs::remove_dir_all(path).expect("cleanup");
    }
}

#[test]
fn shared_owner_state_rejects_oversized_records_before_effects() {
    let path = root("bound");
    let file = OwnerStateRoot::new(&path)
        .file("settings.json", 4)
        .expect("bounded file");
    assert_eq!(
        file.replace(b"12345").expect_err("oversized").kind,
        OwnerStateErrorKind::Oversized
    );
    assert!(!path.exists());
}
