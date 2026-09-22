//! Populate a fresh app-owned Git worktree without checkout, attributes or filters.
use super::{Capture, ServiceSnapshot, ServiceSnapshotPolicy, canonical_directory, failure};
use cap_fs_ext::OsMetadataExt as _;
use cap_std::fs::Dir;
use std::path::Path;

impl ServiceSnapshot {
    /// Copy captured bytes and empty directories into a fresh app-owned Git
    /// worktree. Its sole existing entry must be the exact `.git` backlink to
    /// the caller's admitted Git administration directory. No Git command runs.
    /// The caller owns admission, journaling and cleanup of this destination.
    ///
    /// # Errors
    /// Refuses non-private, non-canonical, aliased or populated destinations,
    /// changed Git bindings, source drift, cancellation and snapshot bounds.
    /// A failed copy remains incomplete and must never be exposed to a child.
    pub fn materialize_worktree(
        &self,
        worktree: &Path,
        git_directory: &Path,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        if cancelled() {
            return Err("Child worktree materialization cancelled.".into());
        }
        self.revalidate()?;
        let target = canonical_directory(worktree)?;
        let before = target.dir_metadata().map_err(failure)?;
        private(&before)?;
        let administration = canonical_directory(git_directory)?;
        let admin_before = administration.dir_metadata().map_err(failure)?;
        if admin_before.uid() != rustix::process::geteuid().as_raw()
            || git_directory.starts_with(worktree)
            || worktree.starts_with(self.path())
            || self.path().starts_with(worktree)
        {
            return Err("Child worktree overlaps another authority root.".into());
        }
        let mut entries = target.entries().map_err(failure)?;
        if entries
            .next()
            .transpose()
            .map_err(failure)?
            .is_none_or(|e| e.file_name() != ".git")
            || entries.next().is_some()
        {
            return Err("Child worktree must be fresh with only its Git backlink.".into());
        }
        let expected = backlink(git_directory)?;
        let git_before = target.symlink_metadata(".git").map_err(failure)?;
        check_backlink(&target, &git_before, &expected)?;
        let mut capture = Capture {
            policy: ServiceSnapshotPolicy::Extension,
            filter: None,
            cancelled,
            exclusions: Vec::new(),
            exclusion_bytes: 0,
            entries: 0,
            path_bytes: 0,
            files: 0,
            bytes: 0,
            observed: Vec::new(),
        };
        capture.walk(&self.storage.directory, &target, "")?;
        capture.check_cancelled()?;
        self.revalidate()?;
        if capture.files != self.files || capture.bytes != self.bytes {
            return Err("Child worktree content inventory changed.".into());
        }
        let named = canonical_directory(worktree)?
            .dir_metadata()
            .map_err(failure)?;
        private(&named)?;
        let admin_after = canonical_directory(git_directory)?
            .dir_metadata()
            .map_err(failure)?;
        if object(&before) != object(&named) || object(&admin_before) != object(&admin_after) {
            return Err("Child worktree or Git administration identity changed.".into());
        }
        let git_after = target.symlink_metadata(".git").map_err(failure)?;
        if crate::service_tree::identity(&git_before) != crate::service_tree::identity(&git_after) {
            return Err("Child worktree Git backlink changed during capture.".into());
        }
        check_backlink(&target, &git_after, &expected)
    }
}
fn private(metadata: &cap_std::fs::Metadata) -> Result<(), String> {
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err("Child worktree must be owned by the app user with mode 0700.".into());
    }
    Ok(())
}
fn object(metadata: &cap_std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}
fn backlink(directory: &Path) -> Result<Vec<u8>, String> {
    let path = directory
        .to_str()
        .filter(|s| s.len() <= 4096 && !s.chars().any(char::is_control))
        .ok_or("Child worktree Git directory spelling is invalid.")?;
    Ok(format!("gitdir: {path}\n").into_bytes())
}
fn check_backlink(
    directory: &Dir,
    metadata: &cap_std::fs::Metadata,
    expected: &[u8],
) -> Result<(), String> {
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.len() > 8192
        || metadata.mode() & 0o022 != 0
    {
        return Err("Child worktree Git backlink is not a bounded owner file.".into());
    }
    if crate::service_tree::read_file(directory, ".git", metadata)? != expected {
        return Err("Child worktree Git backlink differs from its admitted directory.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::PathBuf;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "gbplus-materialize-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(p.canonicalize().unwrap())
        }
        fn directory(&self, name: &str) -> PathBuf {
            let p = self.0.join(name);
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            p
        }
        fn snapshot(&self) -> ServiceSnapshot {
            let source = self.directory("source");
            let views = self.directory("views");
            std::fs::write(source.join("dirty.txt"), b"$Id: exact working bytes$\r\n").unwrap();
            std::fs::write(
                source.join(".gitattributes"),
                b"* ident text eol=lf filter=unknown\n",
            )
            .unwrap();
            std::fs::create_dir(source.join("empty")).unwrap();
            ServiceSnapshot::capture(
                &source,
                &views,
                "snapshot",
                ServiceSnapshotPolicy::Workspace,
                &|| false,
            )
            .unwrap()
        }
        fn target(&self, name: &str, admin: &Path) -> PathBuf {
            let path = self.directory(name);
            std::fs::write(path.join(".git"), backlink(admin).unwrap()).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn exact_bytes_and_empty_directories_populate_two_distinct_worktrees() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let admin = fixture.directory("admin");
        for name in ["first", "second"] {
            let target = fixture.target(name, &admin);
            snapshot
                .materialize_worktree(&target, &admin, &|| false)
                .unwrap();
            assert_eq!(
                std::fs::read(target.join("dirty.txt")).unwrap(),
                b"$Id: exact working bytes$\r\n"
            );
            assert!(target.join("empty").is_dir());
            assert_eq!(
                std::fs::read(target.join(".git")).unwrap(),
                backlink(&admin).unwrap()
            );
            assert!(
                snapshot
                    .materialize_worktree(&target, &admin, &|| false)
                    .is_err()
            );
        }
        snapshot.remove().unwrap();
    }
    #[test]
    fn populated_private_alias_and_changed_backlink_targets_refuse_without_copying() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let admin = fixture.directory("admin");
        let target = fixture.target("target", &admin);
        std::fs::write(target.join("user-data"), b"preserve").unwrap();
        assert!(
            snapshot
                .materialize_worktree(&target, &admin, &|| false)
                .is_err()
        );
        assert_eq!(
            std::fs::read(target.join("user-data")).unwrap(),
            b"preserve"
        );
        assert!(!target.join("dirty.txt").exists());
        let other = fixture.directory("other-admin");
        let fresh = fixture.target("fresh", &other);
        assert!(
            snapshot
                .materialize_worktree(&fresh, &admin, &|| false)
                .is_err()
        );
        assert!(!fresh.join("dirty.txt").exists());
        let alias = fixture.0.join("alias");
        symlink(&fresh, &alias).unwrap();
        assert!(
            snapshot
                .materialize_worktree(&alias, &other, &|| false)
                .is_err()
        );
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            snapshot
                .materialize_worktree(&fresh, &other, &|| false)
                .is_err()
        );
        snapshot.remove().unwrap();
    }
    #[test]
    fn linked_backlink_and_preexisting_cancel_refuse_before_writes() {
        let fixture = Fixture::new();
        let snapshot = fixture.snapshot();
        let admin = fixture.directory("admin");
        let target = fixture.directory("target");
        let outside = fixture.0.join("outside");
        std::fs::write(&outside, backlink(&admin).unwrap()).unwrap();
        symlink(&outside, target.join(".git")).unwrap();
        assert!(
            snapshot
                .materialize_worktree(&target, &admin, &|| false)
                .is_err()
        );
        assert!(!target.join("dirty.txt").exists());
        let fresh = fixture.target("fresh", &admin);
        assert!(
            snapshot
                .materialize_worktree(&fresh, &admin, &|| true)
                .is_err()
        );
        assert!(!fresh.join("dirty.txt").exists());
        snapshot.remove().unwrap();
    }
}
