use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;

struct Fixture {
    path: PathBuf,
    state: Dir,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "gb-service-counter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = Dir::open_ambient_dir(&path, cap_std::ambient_authority()).unwrap();
        Self { path, state }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn counter_survives_reopen_and_rejects_every_prior_or_skipped_identity() {
    let fixture = Fixture::new();
    for sequence in 1..=256 {
        let mut journal = Journal::open(&fixture.state).unwrap();
        assert_eq!(journal.next().unwrap(), sequence);
        assert!(journal.reserve(sequence + 1).is_err());
        journal.reserve(sequence).unwrap();
        assert!(journal.reserve(sequence).is_err());
        assert_eq!(journal.maximum, sequence);
    }
    let mut journal = Journal::open(&fixture.state).unwrap();
    for old in 0..=256 {
        assert!(journal.reserve(old).is_err());
    }
    assert_eq!(journal.next().unwrap(), 257);
    assert_eq!(
        super::super::super::read_entry_names(&journal.records)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_second_writer_cannot_allocate_while_the_first_owns_the_journal() {
    let fixture = Fixture::new();
    let mut first = Journal::open(&fixture.state).unwrap();
    assert!(Journal::open(&fixture.state).is_err());
    first.reserve(1).unwrap();
    drop(first);
    assert_eq!(Journal::open(&fixture.state).unwrap().next().unwrap(), 2);
}

#[test]
fn missing_unknown_corrupt_or_linked_counters_are_preserved_and_never_reset() {
    for kind in [
        "missing",
        "unknown",
        "corrupt",
        "symlink",
        "hardlink",
        "fifo",
        "oversized",
    ] {
        let fixture = Fixture::new();
        let mut journal = Journal::open(&fixture.state).unwrap();
        journal.reserve(1).unwrap();
        drop(journal);
        let path = fixture.path.join(SERVICE_ROOT).join(NAME);
        std::fs::remove_file(&path).unwrap();
        match kind {
            "missing" => {}
            "unknown" => std::fs::write(&path, b"{\"version\":2,\"maximum\":0}").unwrap(),
            "corrupt" => std::fs::write(&path, b"incomplete").unwrap(),
            "symlink" => symlink("elsewhere", &path).unwrap(),
            "hardlink" => {
                let other = fixture.path.join("other");
                std::fs::write(&other, encode(0).unwrap()).unwrap();
                std::fs::hard_link(other, &path).unwrap();
            }
            "fifo" => assert!(
                std::process::Command::new("/usr/bin/mkfifo")
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            ),
            "oversized" => std::fs::write(&path, vec![b'0'; 513]).unwrap(),
            _ => unreachable!(),
        }
        if !matches!(kind, "missing" | "symlink") {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let before = std::fs::symlink_metadata(&path)
            .ok()
            .map(|m| (m.len(), m.file_type()));
        let original_bytes = before
            .as_ref()
            .filter(|(_, kind)| kind.is_file())
            .map(|_| std::fs::read(&path).unwrap());
        let started = std::time::Instant::now();
        assert!(Journal::open(&fixture.state).is_err(), "{kind}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{kind}"
        );
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .ok()
                .map(|m| (m.len(), m.file_type())),
            before
        );
        if let Some(bytes) = original_bytes {
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }
}

#[test]
fn interrupted_publication_never_rolls_back_the_committed_counter() {
    let fixture = Fixture::new();
    let mut journal = Journal::open(&fixture.state).unwrap();
    journal.reserve(1).unwrap();
    super::super::super::write_new_private_file(
        &journal.records,
        NEXT,
        &encode(2).unwrap(),
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    drop(journal);
    let mut recovered = Journal::open(&fixture.state).unwrap();
    assert_eq!(recovered.maximum, 1);
    assert!(recovered.reserve(1).is_err());
    recovered.reserve(2).unwrap();
    assert!(!recovered.records.try_exists(NEXT).unwrap());
    drop(recovered);
    assert_eq!(Journal::open(&fixture.state).unwrap().maximum, 2);
}

#[test]
fn sequence_exhaustion_and_noncanonical_ids_refuse_without_wrapping() {
    let fixture = Fixture::new();
    drop(Journal::open(&fixture.state).unwrap());
    let path = fixture.path.join(SERVICE_ROOT).join(NAME);
    std::fs::write(&path, encode(u64::MAX).unwrap()).unwrap();
    let journal = Journal::open(&fixture.state).unwrap();
    assert!(journal.next().is_err());
    for name in [
        "",
        "lease",
        "gb-service-1",
        "gb-service-00000000000000000000",
        "gb-service-+0000000000000000001",
        "gb-service-18446744073709551616",
    ] {
        assert!(lease_sequence(name).is_err(), "{name}");
    }
    for sequence in [1, 128, u64::MAX] {
        assert_eq!(lease_sequence(&lease_name(sequence)).unwrap(), sequence);
    }
}

#[test]
fn pruning_retains_recent_details_and_cannot_make_a_retired_lease_replayable() {
    let fixture = Fixture::new();
    let mut journal = Journal::open(&fixture.state).unwrap();
    for sequence in 1..=129 {
        journal.reserve(sequence).unwrap();
        let identity = crate::service_contract::service_lease_digest(&lease_name(sequence));
        super::super::super::write_new_private_file(
            &journal.records,
            &format!("lease-{identity}.json"),
            b"validated completed fixture",
            rustix::process::geteuid().as_raw(),
        )
        .unwrap();
    }
    assert!(prune_completed(&journal.records, vec![0], journal.maximum).is_err());
    assert!(prune_completed(&journal.records, vec![130], journal.maximum).is_err());
    assert!(prune_completed(&journal.records, vec![1, 1], journal.maximum).is_err());
    assert_eq!(
        prune_completed(&journal.records, (1..=129).collect(), journal.maximum).unwrap(),
        113
    );
    let names = super::super::super::read_entry_names(&journal.records).unwrap();
    assert_eq!(
        names
            .iter()
            .filter(|name| name.starts_with("lease-"))
            .count(),
        16
    );
    drop(journal);
    let mut recovered = Journal::open(&fixture.state).unwrap();
    for sequence in 1..=129 {
        assert!(recovered.reserve(sequence).is_err());
    }
    recovered.reserve(130).unwrap();
}
