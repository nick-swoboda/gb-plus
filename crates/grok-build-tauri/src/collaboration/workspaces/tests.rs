use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(1);

#[test]
fn large_source_remains_isolated_while_foreign_agent_state_is_excluded() {
    use std::io::Write as _;
    let fixture = Fixture::new();
    let source = fixture.dir("source");
    let state = fixture.dir("state");
    std::fs::create_dir(source.join(".git")).unwrap();
    std::fs::create_dir_all(source.join(".claude/worktrees/foreign")).unwrap();
    std::fs::write(
        source.join(".claude/worktrees/foreign/fact"),
        b"FOREIGN_WORKTREE_NOT_SHARED",
    )
    .unwrap();
    let mut file = std::fs::File::create(source.join("large-source.txt")).unwrap();
    let block = vec![b'x'; 1024 * 1024];
    for _ in 0..80 {
        file.write_all(&block).unwrap();
    }
    drop(file);
    let cancel = RuntimeCancelHandle::new();
    let mut family = Workspaces::capture(
        &state,
        "large-family",
        &bind_project_folder(&source).unwrap(),
        &cancel,
    )
    .unwrap();
    assert!(family.git_ready, "{:?}", family.serial_reason);
    let child = family.create_child(&cancel).unwrap();
    assert!(child.isolated);
    assert_eq!(
        std::fs::metadata(child.bound.folder().join("large-source.txt"))
            .unwrap()
            .len(),
        80 * 1024 * 1024
    );
    assert!(!child.bound.folder().join(".claude").exists());
    assert!(child.excluded_paths.contains(&".claude".into()));
    assert_eq!(
        std::fs::read(source.join(".claude/worktrees/foreign/fact")).unwrap(),
        b"FOREIGN_WORKTREE_NOT_SHARED"
    );
    drop(child);
    drop(family);
    if let Some(root) = std::env::var_os("GROK_BUILD_REAL_WORKSPACE_CAPTURE") {
        let actual = bind_project_folder(Path::new(&root)).unwrap();
        let mut family =
            Workspaces::capture(&state, "explicit-real-workspace", &actual, &cancel).unwrap();
        assert!(family.git_ready, "{:?}", family.serial_reason);
        let first = family.create_child(&cancel).unwrap();
        let second = family.create_child(&cancel).unwrap();
        assert!(first.isolated && second.isolated);
        assert_ne!(first.bound.folder(), second.bound.folder());
        assert_eq!(first.snapshot, second.snapshot);
        eprintln!(
            "Explicit real workspace capture: {} files, {} bytes, digest {}, two isolated children",
            family.snapshot.size().0,
            family.snapshot.size().1,
            first.snapshot
        );
        let owned = family.owner.path().to_owned();
        drop((first, second, family));
        assert!(!owned.exists());
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gbplus-family-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn production_family_uses_dirty_bytes_in_separate_worktrees_without_source_filters() {
    let fixture = Fixture::new();
    let source = fixture.dir("source");
    let state = fixture.dir("state");
    std::fs::create_dir(source.join(".git")).unwrap();
    let hostile = b"[filter \"canary\"]\n clean = /bin/sh -c 'exit 73'\n smudge = /bin/sh -c 'exit 73'\n required = true\n";
    std::fs::write(source.join(".git/config"), hostile).unwrap();
    std::fs::write(source.join(".git/index"), b"private source index").unwrap();
    std::fs::write(source.join("dirty.txt"), b"dirty working content\n$Id$\n").unwrap();
    std::fs::write(
        source.join(".gitattributes"),
        b"* filter=canary ident text eol=crlf\n",
    )
    .unwrap();
    std::fs::create_dir(source.join("empty")).unwrap();
    let bound = bind_project_folder(&source).unwrap();
    let cancel = RuntimeCancelHandle::new();
    let mut family = Workspaces::capture(&state, "family-fixture", &bound, &cancel).unwrap();
    assert!(family.git_ready, "{:?}", family.serial_reason);
    let first = family.create_child(&cancel).unwrap();
    let second = family.create_child(&cancel).unwrap();
    assert!(first.isolated && second.isolated);
    assert_ne!(first.bound.folder(), second.bound.folder());
    assert_eq!(first.snapshot, second.snapshot);
    for child in [&first, &second] {
        assert_eq!(
            std::fs::read(child.bound.folder().join("dirty.txt")).unwrap(),
            b"dirty working content\n$Id$\n"
        );
        assert!(child.bound.folder().join("empty").is_dir());
        assert!(child.bound.folder().join(".git").is_file());
    }
    assert_eq!(std::fs::read(source.join(".git/config")).unwrap(), hostile);
    assert_eq!(
        std::fs::read(source.join(".git/index")).unwrap(),
        b"private source index"
    );
    let root = family.owner.path().to_owned();
    drop(first);
    drop(second);
    drop(family);
    assert!(!root.exists());
}

#[test]
fn non_git_project_gets_distinct_captured_views_and_an_explicit_serial_reason() {
    let fixture = Fixture::new();
    let source = fixture.dir("source");
    let state = fixture.dir("state");
    std::fs::write(source.join("fact"), "original fact").unwrap();
    let bound = bind_project_folder(&source).unwrap();
    let cancel = RuntimeCancelHandle::new();
    let mut family = Workspaces::capture(&state, "serial-family", &bound, &cancel).unwrap();
    let first = family.create_child(&cancel).unwrap();
    std::fs::write(source.join("fact"), "changed after snapshot").unwrap();
    let second = family.create_child(&cancel).unwrap();
    assert!(!first.isolated && !second.isolated);
    assert!(second.serial_reason.is_some());
    assert_eq!(
        std::fs::read(second.bound.folder().join("fact")).unwrap(),
        b"original fact"
    );
    assert_ne!(first.bound.folder(), second.bound.folder());
    let root = family.owner.path().to_owned();
    drop(first);
    drop(second);
    drop(family);
    assert!(!root.exists());
}

#[test]
fn live_family_custody_is_not_recovered_and_changed_names_are_not_removed() {
    let fixture = Fixture::new();
    let state = fixture.dir("state");
    let first = FamilyDirectory::create(&state, "one").unwrap();
    let original = first.path().to_owned();
    let second = FamilyDirectory::create(&state, "two").unwrap();
    assert!(original.exists());
    let renamed = original.with_file_name("retained-test-original");
    std::fs::rename(&original, &renamed).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(original.join("foreign"), "preserve").unwrap();
    assert!(first.revalidate().is_err());
    drop(first);
    assert_eq!(
        std::fs::read(original.join("foreign")).unwrap(),
        b"preserve"
    );
    drop(second);
}
