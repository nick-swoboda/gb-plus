use super::*;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _, symlink};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gbplus-service-views-{}-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn lease(&self) -> ServiceViews {
        ServiceViews::create(&self.0, &|| false).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn leftover(lease: &ServiceViews) {
    let dir = lease.path().join("workspace");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join("fact.txt"), b"private captured source").unwrap();
    std::fs::set_permissions(dir.join("fact.txt"), std::fs::Permissions::from_mode(0o400)).unwrap();
}

#[test]
fn active_snapshot_owner_is_retained_and_abandoned_views_are_recovered() {
    let f = Fixture::new();
    let first = f.lease();
    leftover(&first);
    let path = first.path().to_owned();
    let second = f.lease();
    assert!(path.join("workspace/fact.txt").exists());
    drop(second);
    drop(first); // Remaining views leave the marker; closing the descriptor models lost ownership.
    assert!(path.exists());
    let third = f.lease();
    assert!(!path.exists());
    let current = third.path().to_owned();
    drop(third);
    assert!(!current.exists());
}

#[test]
fn repeated_interrupted_owners_do_not_exhaust_the_private_view_capacity() {
    let f = Fixture::new();
    for _ in 0..40 {
        let lease = f.lease();
        leftover(&lease);
        drop(lease);
    }
    let final_lease = f.lease();
    assert_eq!(
        std::fs::read_dir(f.0.join("service-views-v2"))
            .unwrap()
            .count(),
        2
    );
    drop(final_lease);
    assert_eq!(
        std::fs::read_dir(f.0.join("service-views-v2"))
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn crash_cuts_before_owner_publication_remove_only_empty_or_partial_owned_records() {
    let f = Fixture::new();
    drop(f.lease());
    let parent = f.0.join("service-views-v2");
    for prefix in [None, Some(&MARKER[..0]), Some(&MARKER[..9])] {
        let path = parent.join(format!("view-{}", "a".repeat(64)));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        if let Some(bytes) = prefix {
            std::fs::write(path.join(OWNER), bytes).unwrap();
            std::fs::set_permissions(path.join(OWNER), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let lease = f.lease();
        assert!(!path.exists());
        drop(lease);
    }
}

#[test]
fn unknown_versions_and_data_remain_recoverable_without_being_deleted() {
    let f = Fixture::new();
    let lease = f.lease();
    leftover(&lease);
    let path = lease.path().to_owned();
    drop(lease);
    std::fs::write(path.join(OWNER), b"GB Plus private service views v9\n").unwrap();
    assert!(ServiceViews::create(&f.0, &|| false).is_err());
    assert!(path.join("workspace/fact.txt").exists());
    std::fs::write(path.join(OWNER), MARKER).unwrap();
    std::fs::write(path.join("unrecognized"), b"keep this").unwrap();
    assert!(ServiceViews::create(&f.0, &|| false).is_err());
    assert_eq!(
        std::fs::read(path.join("unrecognized")).unwrap(),
        b"keep this"
    );
}

#[test]
fn symlinks_hardlinks_and_fifos_cannot_turn_recovery_into_external_deletion_or_a_wait() {
    for kind in ["symlink", "hardlink", "fifo", "oversized"] {
        let f = Fixture::new();
        let outside = f.0.join("outside");
        std::fs::write(&outside, b"preserve").unwrap();
        let lease = f.lease();
        leftover(&lease);
        let path = lease.path().to_owned();
        drop(lease);
        std::fs::remove_file(path.join(OWNER)).unwrap();
        match kind {
            "symlink" => symlink(&outside, path.join(OWNER)).unwrap(),
            "hardlink" => std::fs::hard_link(&outside, path.join(OWNER)).unwrap(),
            "fifo" => nix::unistd::mkfifo(
                &path.join(OWNER),
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
            "oversized" => std::fs::write(path.join(OWNER), vec![0; 4096]).unwrap(),
            _ => unreachable!(),
        }
        let started = std::time::Instant::now();
        assert!(ServiceViews::create(&f.0, &|| false).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(std::fs::read(&outside).unwrap(), b"preserve");
        assert!(path.join("workspace/fact.txt").exists());
    }
}

#[test]
fn replaced_directory_names_do_not_redirect_live_owner_cleanup() {
    let f = Fixture::new();
    let lease = f.lease();
    let path = lease.path().to_owned();
    let retained = f.0.join("retained");
    std::fs::rename(&path, &retained).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(path.join("user-file"), b"keep").unwrap();
    drop(lease);
    assert_eq!(std::fs::read(path.join("user-file")).unwrap(), b"keep");
    assert!(retained.join(OWNER).exists());
}

#[test]
fn legacy_views_are_preserved_and_live_capacity_is_enforced() {
    let f = Fixture::new();
    let legacy = f.0.join("service-views-v1");
    std::fs::create_dir(&legacy).unwrap();
    std::fs::write(legacy.join("workspace-old"), b"legacy").unwrap();
    let live: Vec<_> = (0..MAX_LEASES).map(|_| f.lease()).collect();
    assert!(ServiceViews::create(&f.0, &|| false).is_err());
    drop(live);
    drop(f.lease());
    assert_eq!(
        std::fs::read(legacy.join("workspace-old")).unwrap(),
        b"legacy"
    );
}

#[test]
fn malformed_global_writer_file_refuses_without_waiting_on_a_pipe() {
    let f = Fixture::new();
    drop(f.lease());
    let path = f.0.join("service-views-v2/writer.lock");
    std::fs::remove_file(&path).unwrap();
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert!(ServiceViews::create(&f.0, &|| false).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(
        std::fs::symlink_metadata(path)
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn cancelled_recovery_keeps_unvisited_views_for_the_next_explicit_attempt() {
    let f = Fixture::new();
    assert!(ServiceViews::create(&f.0, &|| true).is_err());
    assert!(!f.0.join("service-views-v2").exists());
    let lease = f.lease();
    leftover(&lease);
    let path = lease.path().to_owned();
    drop(lease);
    let checks = std::cell::Cell::new(0);
    assert!(
        ServiceViews::create(&f.0, &|| {
            checks.set(checks.get() + 1);
            checks.get() > 3
        })
        .is_err()
    );
    assert!(path.join("workspace/fact.txt").exists());
    drop(f.lease());
    assert!(!path.exists());
}
