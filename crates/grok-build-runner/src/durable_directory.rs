//! The one directory-entry sync used by every durable writer in this crate.
//!
//! A durable rename is only half-durable until the *directory entry* that names
//! the renamed file has itself reached stable storage. Every journal, staging,
//! capture, and apply path in this crate therefore ends in a directory sync.
//!
//! Those paths used to spell it `directory.try_clone()?.into_std_file()
//! .sync_all()`, once per module. That idiom is silently broken on Linux
//! (defect D-0004): `cap-primitives` opens a [`Dir`] with `O_PATH` on Linux and
//! without it on macOS (`src/rustix/fs/dir_utils.rs`), and `fsync(2)` on an
//! `O_PATH` descriptor fails with `EBADF`. Every Linux directory sync returned
//! "Bad file descriptor (os error 9)" while the identical macOS call succeeded,
//! so the directory-entry half of the crash-safety claim was unproven on Linux.
//!
//! The repair may not reopen a path. `linux_cgroup_io` states the rule the whole
//! crate follows — never reopen an ambient delegation path; every operation is
//! relative to the retained capability — and re-deriving the handle by name
//! would trade a durability defect for a traversal-race defect.
//!
//! An `O_PATH` descriptor is still a valid `dirfd` for the `*at()` family, so
//! [`sync_directory_entries`] asks the kernel to reopen the retained descriptor
//! *through itself*: `openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)`. The
//! result is the same filesystem object (same device and inode), reached without
//! naming a single path component, and it is a fully readable descriptor that
//! `fsync(2)` accepts.
//!
//! The literal `"."` is load-bearing: `openat(2)` ignores `dirfd` when the path
//! is absolute, so this function takes no name from a caller and hard-codes the
//! self-reference.
//!
//! Both platforms run this one path, and both finish through
//! [`std::fs::File::sync_all`] rather than a bare `fsync`. That keeps macOS
//! behaviour bit-for-bit what it already was: the standard library issues
//! `F_FULLFSYNC` there, which a direct `fsync(2)` would silently downgrade.

use std::fs::File;
use std::io;

use cap_std::fs::Dir;
use rustix::fs::{Mode, OFlags};

/// Flushes `directory`'s own entries to stable storage.
///
/// The sync is performed on a descriptor derived from `directory` itself, never
/// on a re-resolved path, so it is safe on a delegated capability and immune to
/// a rename or replacement of the directory's name.
///
/// # Errors
///
/// Returns the operating-system error if the syncable descriptor cannot be
/// derived from `directory`, or if the sync itself fails. Failure is always
/// returned; callers wrap it in their own typed error and never discard it.
pub(crate) fn sync_directory_entries(directory: &Dir) -> io::Result<()> {
    let syncable = rustix::fs::openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    File::from(syncable).sync_all()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cap_std::ambient_authority;
    use cap_std::fs::Dir;

    use super::sync_directory_entries;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-durable-directory-{label}-{}-{sequence}",
                std::process::id()
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// D-0004 regression. The crate-wide directory sync must actually reach the
    /// kernel on a capability directory, on every platform.
    ///
    /// Before the fix this failed on Linux with `EBADF`, because
    /// `cap-primitives` opens `Dir` with `O_PATH` there and `fsync(2)` rejects
    /// an `O_PATH` descriptor. It succeeded on macOS, where no such flag is
    /// used, which is why the defect survived every macOS run.
    #[test]
    fn a_capability_directory_sync_reaches_the_kernel_without_reopening_a_path() {
        let top = TestDirectory::new("entry-sync");
        let parent = Dir::open_ambient_dir(&top.0, ambient_authority())
            .expect("open the delegated parent capability");

        // Build the journal directory the way every durable writer here does:
        // descriptor-relatively, from an already-retained capability.
        parent.create_dir("journal").expect("create journal");
        let journal = parent.open_dir("journal").expect("retain journal");

        // Dirty the directory entry so the sync has real work to do.
        journal
            .write("record.json", b"{}")
            .expect("write a journal record");

        // The descriptor the whole crate syncs through really is unsyncable as
        // the raw handle; that is the defect, pinned here so a regression is
        // legible rather than mysterious.
        #[cfg(target_os = "linux")]
        {
            let raw = journal
                .try_clone()
                .expect("clone the retained journal capability")
                .into_std_file()
                .sync_all();
            let errno = raw
                .expect_err("cap-primitives opens Dir with O_PATH on Linux")
                .raw_os_error();
            assert_eq!(
                errno,
                Some(rustix::io::Errno::BADF.raw_os_error()),
                "the pre-D-0004 idiom must still be the EBADF case this module exists to avoid"
            );
            let flags =
                rustix::fs::fcntl_getfl(&journal).expect("read the retained capability's flags");
            assert!(
                flags.contains(rustix::fs::OFlags::PATH),
                "the retained capability is expected to be an O_PATH descriptor on Linux"
            );
        }

        // The product's own code path must succeed.
        sync_directory_entries(&journal).unwrap_or_else(|error| {
            panic!(
                "durable directory sync failed: raw_os_error={:?}: {error}",
                error.raw_os_error()
            )
        });

        // It must have synced *that* directory, not something re-resolved: the
        // derived handle is the same filesystem object.
        let derived = rustix::fs::openat(
            &journal,
            ".",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("derive a syncable handle from the retained capability");
        let retained = rustix::fs::fstat(&journal).expect("stat the retained capability");
        let opened = rustix::fs::fstat(&derived).expect("stat the derived handle");
        assert_eq!(
            (retained.st_dev, retained.st_ino),
            (opened.st_dev, opened.st_ino),
            "the derived handle must name the delegated directory itself"
        );
        #[cfg(target_os = "linux")]
        assert!(
            !rustix::fs::fcntl_getfl(&derived)
                .expect("read the derived handle's flags")
                .contains(rustix::fs::OFlags::PATH),
            "the derived handle must be a real readable descriptor, not another O_PATH"
        );

        // And it must not have gone through the directory's name. Rename the
        // directory out from under the retained capability: a path-reopening
        // implementation would now fail, a descriptor-relative one still works.
        parent
            .rename("journal", &parent, "journal-moved")
            .expect("rename the journal directory away from its original name");
        assert!(
            parent.open_dir("journal").is_err(),
            "the original name must be gone for this assertion to mean anything"
        );
        sync_directory_entries(&journal).unwrap_or_else(|error| {
            panic!(
                "durable directory sync must stay descriptor-relative after a rename: \
                 raw_os_error={:?}: {error}",
                error.raw_os_error()
            )
        });
    }
}
