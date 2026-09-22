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
            "gb-service-receipts-{}-{}",
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

fn record(sequence: u64, live: bool) -> Record {
    let identity = crate::service_contract::service_lease_digest(&counter::lease_name(sequence));
    let owner_pid = std::process::id();
    Record {
        version: 4,
        sequence,
        lease_identity: identity.clone(),
        commitment: Digest::sha256(b"fixture"),
        containment: Digest::sha256(b"fixture generation"),
        owner_pid,
        owner_start: process_start(owner_pid).unwrap().unwrap() + u64::from(!live),
        leaf: format!("gb-service-{identity}"),
        identity: None,
        view_identity: None,
        cleaned: false,
    }
}

fn write(directory: &Dir, name: &str, bytes: &[u8]) {
    super::super::super::super::write_new_private_file(
        directory,
        name,
        bytes,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
}

fn clean(journal: &counter::Journal) -> Result<(), String> {
    let names =
        super::super::super::super::read_entry_names(&journal.records).map_err(kernel_failure)?;
    remove_abandoned_temporaries(&journal.records, &names, journal.maximum)
}

#[test]
fn repeated_initial_publication_crashes_do_not_fill_receipts_or_replay_leases() {
    let fixture = Fixture::new();
    for sequence in 1..=140 {
        let mut journal = counter::Journal::open(&fixture.state).unwrap();
        journal.reserve(sequence).unwrap();
        let temporary = format!("next-{}", record_name(&record(sequence, false)));
        write(
            &journal.records,
            &temporary,
            b"{\"version\":4,\"sequence\":",
        );
        drop(journal);
        let mut recovered = counter::Journal::open(&fixture.state).unwrap();
        clean(&recovered).unwrap();
        assert!(!recovered.records.try_exists(&temporary).unwrap());
        assert!(recovered.reserve(sequence).is_err());
        assert_eq!(recovered.next().unwrap(), sequence + 1);
    }
}

#[test]
fn an_active_owner_keeps_its_partial_update_and_dead_owner_cleanup_keeps_the_commit() {
    let fixture = Fixture::new();
    let mut journal = counter::Journal::open(&fixture.state).unwrap();
    journal.reserve(1).unwrap();
    let mut committed = record(1, true);
    persist(&journal.records, &committed).unwrap();
    let name = record_name(&committed);
    let temporary = format!("next-{name}");
    write(&journal.records, &temporary, b"partial live writer");
    clean(&journal).unwrap();
    assert_eq!(
        counter::read_private_metadata(&journal.records, &temporary, 8192).unwrap(),
        b"partial live writer"
    );
    committed.owner_start += 1;
    journal.records.remove_file(&temporary).unwrap();
    persist(&journal.records, &committed).unwrap();
    let original = counter::read_private_metadata(&journal.records, &name, 8192).unwrap();
    write(&journal.records, &temporary, b"partial dead writer");
    clean(&journal).unwrap();
    assert!(!journal.records.try_exists(&temporary).unwrap());
    assert_eq!(
        counter::read_private_metadata(&journal.records, &name, 8192).unwrap(),
        original
    );
}

#[test]
fn unknown_or_inconsistent_completed_temporary_records_remain_recoverable() {
    for change in ["version", "sequence", "identity"] {
        let fixture = Fixture::new();
        let mut journal = counter::Journal::open(&fixture.state).unwrap();
        journal.reserve(1).unwrap();
        let mut candidate = record(1, false);
        let temporary = format!("next-{}", record_name(&candidate));
        match change {
            "version" => candidate.version += 1,
            "sequence" => candidate.sequence += 1,
            "identity" => candidate.lease_identity = Digest::sha256(b"wrong"),
            _ => unreachable!(),
        }
        let bytes = serde_json::to_vec(&candidate).unwrap();
        write(&journal.records, &temporary, &bytes);
        assert!(clean(&journal).is_err(), "{change}");
        assert_eq!(
            counter::read_private_metadata(&journal.records, &temporary, 8192).unwrap(),
            bytes
        );
    }
}

#[test]
fn malformed_temporary_paths_and_special_files_refuse_without_blocking_or_deleting() {
    for kind in ["name", "symlink", "hardlink", "fifo", "oversized"] {
        let fixture = Fixture::new();
        let mut journal = counter::Journal::open(&fixture.state).unwrap();
        journal.reserve(1).unwrap();
        let temporary = if kind == "name" {
            "next-lease-unknown.json".into()
        } else {
            format!("next-{}", record_name(&record(1, false)))
        };
        let path = fixture.path.join(SERVICE_ROOT).join(&temporary);
        match kind {
            "name" => write(&journal.records, &temporary, b"partial"),
            "symlink" => symlink("missing", &path).unwrap(),
            "hardlink" => {
                write(&fixture.state, "other", b"partial");
                std::fs::hard_link(fixture.path.join("other"), &path).unwrap();
            }
            "fifo" => {
                rustix::fs::mknodat(
                    &journal.records,
                    &temporary,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                    0,
                )
                .unwrap();
            }
            "oversized" => write(&journal.records, &temporary, &vec![b'0'; 8193]),
            _ => unreachable!(),
        }
        let started = Instant::now();
        assert!(clean(&journal).is_err(), "{kind}");
        assert!(started.elapsed() < Duration::from_secs(1), "{kind}");
        assert!(std::fs::symlink_metadata(path).is_ok(), "{kind}");
    }
}

#[test]
fn a_forged_non_kernel_leaf_never_grants_cleanup_authority() {
    let fixture = Fixture::new();
    fixture.state.create_dir("leaf").unwrap();
    let leaf = fixture.state.open_dir("leaf").unwrap();
    write(&leaf, "cgroup.events", b"populated 0\nfrozen 0\n");
    write(&leaf, "cgroup.procs", b"");
    write(&leaf, "cgroup.kill", b"unchanged");
    assert!(super::super::remove_uncommitted_leaf(&fixture.state, "leaf", &leaf).is_err());
    assert_eq!(leaf.read("cgroup.kill").unwrap(), b"unchanged");
    assert!(fixture.state.try_exists("leaf").unwrap());
}
