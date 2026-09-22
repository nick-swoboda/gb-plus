//! Bounded, descriptor-relative digests of the private views supplied to services.

use std::io::Read as _;
use std::path::Path;

use cap_fs_ext::{DirExt as _, OsMetadataExt as _};
use cap_std::fs::Dir;
use grok_build_core::Digest;
use sha2::{Digest as _, Sha256};

/// A service view never includes repository administration or conventional credential files.
#[must_use]
pub fn service_path_component_allowed(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name.len() <= 255
        && !name.chars().any(char::is_control)
        && !matches!(name, "." | "..")
        && !name.contains('/')
        && !matches!(
            lower.as_str(),
            ".git"
                | ".ssh"
                | ".aws"
                | ".azure"
                | ".grok"
                | ".codex"
                | ".gnupg"
                | ".netrc"
                | ".npmrc"
                | ".pypirc"
                | "auth.json"
                | "credentials"
                | "credentials.json"
                | "id_rsa"
                | "id_ed25519"
        )
        && lower != ".env"
        && !lower.starts_with(".env.")
        && !Path::new(&lower).extension().is_some_and(|extension| {
            ["key", "p12", "pfx", "pem"]
                .iter()
                .any(|denied| extension.eq_ignore_ascii_case(denied))
        })
}

/// Digest an already prepared private service view. This does not authorize a view.
///
/// # Errors
/// Refuses symlinks, devices/sockets, credential paths, concurrent file replacement,
/// oversized trees and paths, or any filesystem read failure.
pub fn service_tree_digest(root: &Path) -> Result<Digest, String> {
    if root.canonicalize().map_err(|e| e.to_string())? != root {
        return Err("Service view must be an absolute canonical directory.".into());
    }
    let directory =
        Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(|e| e.to_string())?;
    digest_held(&directory)
}

pub(crate) fn digest_held(directory: &Dir) -> Result<Digest, String> {
    let mut hash = Sha256::new();
    hash.update(b"grok-build/service-view/v1\0");
    let mut budget = Budget {
        entries: 0,
        bytes: 0,
    };
    walk(directory, "", &mut hash, &mut budget)?;
    Ok(Digest::sha256(&hash.finalize()))
}

struct Budget {
    entries: usize,
    bytes: u64,
}

fn walk(
    directory: &Dir,
    prefix: &str,
    hash: &mut Sha256,
    budget: &mut Budget,
) -> Result<(), String> {
    let directory_before = directory.dir_metadata().map_err(|e| e.to_string())?;
    if prefix.len() > 4096 || prefix.matches('/').count() > 32 {
        return Err("Service view path bound exceeded.".into());
    }
    let mut names = Vec::new();
    for entry in directory.entries().map_err(|e| e.to_string())? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .into_string()
            .map_err(|_| "Non-UTF-8 service path.")?;
        if !service_path_component_allowed(&name) {
            return Err("Service view contains an unavailable path.".into());
        }
        budget.entries += 1;
        if budget.entries > 16_384 {
            return Err("Service view entry limit exceeded.".into());
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let path = format!("{prefix}{name}");
        let metadata = directory
            .symlink_metadata(&name)
            .map_err(|e| e.to_string())?;
        hash.update((path.len() as u64).to_be_bytes());
        hash.update(path.as_bytes());
        if metadata.is_dir() {
            hash.update(b"directory\0");
            walk(
                &directory
                    .open_dir_nofollow(&name)
                    .map_err(|e| e.to_string())?,
                &format!("{path}/"),
                hash,
                budget,
            )?;
        } else if metadata.is_file() {
            if metadata.len() > 128 * 1024 * 1024 {
                return Err("Service view file bound exceeded.".into());
            }
            budget.bytes = budget
                .bytes
                .checked_add(metadata.len())
                .ok_or("Service view byte overflow.")?;
            if budget.bytes > 256 * 1024 * 1024 {
                return Err("Service view byte limit exceeded.".into());
            }
            let bytes = read_file(directory, &name, &metadata)?;
            hash.update(b"file\0");
            hash.update([u8::from(metadata.mode() & 0o111 != 0)]);
            hash.update(metadata.len().to_be_bytes());
            hash.update(Digest::sha256(&bytes).as_str().as_bytes());
        } else {
            return Err("Service view contains a symlink, socket or special file.".into());
        }
    }
    if identity(&directory.dir_metadata().map_err(|e| e.to_string())?)
        != identity(&directory_before)
    {
        return Err("Service view directory changed during traversal.".into());
    }
    Ok(())
}

pub(super) fn read_file(
    directory: &Dir,
    name: &str,
    metadata: &cap_std::fs::Metadata,
) -> Result<Vec<u8>, String> {
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > 128 * 1024 * 1024 {
        return Err("Service view contains an unbounded file or hard-link alias.".into());
    }
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut file = cap_std::fs::File::from_std(std::fs::File::from(descriptor));
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.nlink() != 1 || identity(&opened) != identity(metadata) {
        return Err("Service view file changed before read.".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(metadata.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 != metadata.len()
        || identity(&file.metadata().map_err(|e| e.to_string())?) != identity(&opened)
        || identity(
            &directory
                .symlink_metadata(name)
                .map_err(|e| e.to_string())?,
        ) != identity(&opened)
    {
        return Err("Service view changed during read.".into());
    }
    Ok(bytes)
}

pub(super) fn identity(metadata: &cap_std::fs::Metadata) -> (u64, u64, u64, i64, i64, u32, u64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.mode(),
        metadata.nlink(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "gb-service-view-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn digest_survives_copy_but_detects_content_and_executable_changes_and_refuses_links() {
        use std::os::unix::fs::PermissionsExt as _;
        let a = Fixture::new();
        let b = Fixture::new();
        for root in [&a.0, &b.0] {
            std::fs::create_dir(root.join("src")).unwrap();
            std::fs::write(root.join("src/fact.txt"), b"cobalt = 42").unwrap();
            std::fs::set_permissions(
                root.join("src/fact.txt"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let original = service_tree_digest(&a.0).unwrap();
        assert_eq!(original, service_tree_digest(&b.0).unwrap());
        std::fs::write(b.0.join("src/fact.txt"), b"cobalt = 43").unwrap();
        assert_ne!(original, service_tree_digest(&b.0).unwrap());
        std::fs::set_permissions(
            a.0.join("src/fact.txt"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_ne!(original, service_tree_digest(&a.0).unwrap());
        std::os::unix::fs::symlink(b.0.join("src/fact.txt"), a.0.join("link")).unwrap();
        assert!(service_tree_digest(&a.0).is_err());
        std::fs::write(b.0.join(".env.local"), b"fixture only").unwrap();
        assert!(service_tree_digest(&b.0).is_err());
    }

    #[test]
    fn conventional_credentials_and_runtime_sockets_are_not_service_view_components() {
        for path in [
            ".git",
            ".env",
            ".ENV.production",
            ".ssh",
            "auth.json",
            "credentials",
            "private.key",
            "../a",
            "a/b",
        ] {
            assert!(!service_path_component_allowed(path), "{path}");
        }
        for path in ["src", "main.rs", ".gitignore", "README.md", "server"] {
            assert!(service_path_component_allowed(path));
        }
    }

    #[test]
    fn hard_links_and_a_regular_file_replaced_by_a_fifo_are_refused_without_blocking() {
        let fixture = Fixture::new();
        let path = fixture.0.join("file.txt");
        std::fs::write(&path, b"fixture").unwrap();
        std::fs::hard_link(&path, fixture.0.join("alias.txt")).unwrap();
        assert!(service_tree_digest(&fixture.0).is_err());
        std::fs::remove_file(fixture.0.join("alias.txt")).unwrap();
        let directory = Dir::open_ambient_dir(&fixture.0, cap_std::ambient_authority()).unwrap();
        let before = directory.symlink_metadata("file.txt").unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let started = std::time::Instant::now();
        assert!(read_file(&directory, "file.txt", &before).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
