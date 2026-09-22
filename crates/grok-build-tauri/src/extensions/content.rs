//! Bounded local snapshots and inert, content-addressed extension capsules.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;

use cap_fs_ext::{DirExt as _, OsMetadataExt as _};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

use super::{digest, failure, valid_digest};

pub(super) const MAX_FILES: usize = 2048;
pub(super) const MAX_BYTES: usize = 64 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_INDEX_BYTES: usize = 1024 * 1024;
pub(super) const MAX_CAPSULE_BYTES: u64 = (MAX_BYTES + MAX_INDEX_BYTES + 4) as u64;

#[derive(Clone)]
pub(super) struct Blob {
    pub(super) executable: bool,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Bundle {
    pub(super) files: BTreeMap<String, Blob>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u16,
    files: Vec<Entry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    executable: bool,
    bytes: usize,
    sha256: String,
}

impl Bundle {
    pub(super) fn capture(root: &Path) -> Result<Self, String> {
        if !root.is_absolute() || root.canonicalize().map_err(failure)? != root {
            return Err(
                "Select the exact canonical extension directory; linked roots are refused.".into(),
            );
        }
        let directory =
            Dir::open_ambient_dir(root, cap_std::ambient_authority()).map_err(failure)?;
        let mut bundle = Self {
            files: BTreeMap::new(),
        };
        let mut entries = 0;
        walk(&directory, "", &mut bundle, &mut entries)?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 || bytes.len() as u64 > MAX_CAPSULE_BYTES {
            return Err("Extension capsule size is invalid.".into());
        }
        let length = u32::from_be_bytes(bytes[..4].try_into().map_err(failure)?) as usize;
        if length > MAX_INDEX_BYTES || length > bytes.len() - 4 {
            return Err("Extension capsule index exceeded its bound.".into());
        }
        let index: Index = serde_json::from_slice(&bytes[4..4 + length]).map_err(failure)?;
        if index.version != 1 || index.files.len() > MAX_FILES {
            return Err("Unknown extension capsule remains unavailable and recoverable.".into());
        }
        let mut offset = 4 + length;
        let mut bundle = Self {
            files: BTreeMap::new(),
        };
        let mut previous = String::new();
        for entry in index.files {
            if entry.bytes > MAX_FILE_BYTES
                || entry.bytes > bytes.len() - offset
                || entry.path <= previous
                || !valid_digest(&entry.sha256)
            {
                return Err("Extension capsule inventory is inconsistent.".into());
            }
            previous.clone_from(&entry.path);
            let data = &bytes[offset..offset + entry.bytes];
            if digest(data) != entry.sha256 {
                return Err("Extension capsule content changed.".into());
            }
            offset += entry.bytes;
            bundle.files.insert(
                entry.path,
                Blob {
                    executable: entry.executable,
                    bytes: data.to_vec(),
                },
            );
        }
        if offset != bytes.len() {
            return Err("Extension capsule has unlisted trailing content.".into());
        }
        bundle.validate()?;
        Ok(bundle)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let index = Index {
            version: 1,
            files: self
                .files
                .iter()
                .map(|(path, blob)| Entry {
                    path: path.clone(),
                    executable: blob.executable,
                    bytes: blob.bytes.len(),
                    sha256: digest(&blob.bytes),
                })
                .collect(),
        };
        let index = serde_json::to_vec(&index).map_err(failure)?;
        if index.len() > MAX_INDEX_BYTES {
            return Err("Extension inventory is too large.".into());
        }
        let mut bytes = Vec::with_capacity(4 + index.len() + self.byte_len());
        bytes.extend_from_slice(&u32::try_from(index.len()).map_err(failure)?.to_be_bytes());
        bytes.extend_from_slice(&index);
        for blob in self.files.values() {
            bytes.extend_from_slice(&blob.bytes);
        }
        Ok(bytes)
    }

    pub(super) fn byte_len(&self) -> usize {
        self.files.values().map(|file| file.bytes.len()).sum()
    }

    pub(super) fn text(&self, path: &str, maximum: usize) -> Result<&str, String> {
        if self.files.get(path).is_some_and(|file| file.executable) {
            return Err(
                "Executable content cannot become skill instructions or a skill reference.".into(),
            );
        }
        self.preview_text(path, maximum)
    }

    /// Inspection is data-only, including the source text of quarantined scripts.
    pub(super) fn preview_text(&self, path: &str, maximum: usize) -> Result<&str, String> {
        let file = self
            .files
            .get(path)
            .ok_or("Extension reference is not in its frozen inventory.")?;
        if file.bytes.len() > maximum {
            return Err("Extension text exceeds its inspection bound.".into());
        }
        let text = std::str::from_utf8(&file.bytes).map_err(failure)?;
        if text.contains('\0') {
            return Err("Extension text contains NUL.".into());
        }
        Ok(text)
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        if self.files.is_empty() || self.files.len() > MAX_FILES || self.byte_len() > MAX_BYTES {
            return Err("Extension exceeds its file or byte bounds.".into());
        }
        let mut folded = BTreeSet::new();
        for (path, blob) in &self.files {
            validate_path(path)?;
            if blob.bytes.len() > MAX_FILE_BYTES || !folded.insert(path.to_ascii_lowercase()) {
                return Err("Extension has an oversized file or ambiguous path spelling.".into());
            }
            let mut parent = Path::new(path).parent();
            while let Some(path) = parent.filter(|p| !p.as_os_str().is_empty()) {
                if self
                    .files
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case(&path.to_string_lossy()))
                {
                    return Err("Extension file and directory paths overlap.".into());
                }
                parent = path.parent();
            }
        }
        Ok(())
    }
}

pub(super) fn validate_path(path: &str) -> Result<(), String> {
    if path.len() > 1024
        || path.split('/').count() > 16
        || path.split('/').any(|part| {
            part.is_empty()
                || part.len() > 255
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_. ".contains(&b))
                || part.ends_with(['.', ' '])
                || part.starts_with(' ')
                || secret_name(part)
        })
    {
        return Err(
            "Extension path is unsafe, ambiguous, or names credential/configuration data.".into(),
        );
    }
    Ok(())
}

fn secret_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        ".git"
            | ".ssh"
            | ".aws"
            | ".azure"
            | ".gnupg"
            | ".netrc"
            | ".npmrc"
            | ".pypirc"
            | "auth.json"
            | "credentials.json"
            | "credentials"
            | "id_rsa"
            | "id_ed25519"
    ) || name == ".env"
        || name.starts_with(".env.")
        || [".key", ".p12", ".pfx", ".pem"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn identity(metadata: &cap_std::fs::Metadata) -> (u64, u64, u64, i64, i64, u32, u64) {
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

fn walk(
    directory: &Dir,
    prefix: &str,
    bundle: &mut Bundle,
    entries: &mut usize,
) -> Result<(), String> {
    let before = identity(&directory.dir_metadata().map_err(failure)?);
    let mut names = Vec::new();
    for entry in directory.entries().map_err(failure)? {
        let name = entry
            .map_err(failure)?
            .file_name()
            .into_string()
            .map_err(|_| "Extension path is not UTF-8.")?;
        // Git administration is neither plugin content nor an install mechanism.
        if prefix.is_empty() && name == ".git" {
            continue;
        }
        *entries += 1;
        if *entries > MAX_FILES * 2 {
            return Err("Extension directory entry bound exceeded.".into());
        }
        validate_path(&format!("{prefix}{name}"))?;
        names.push(name);
    }
    names.sort();
    for name in names {
        let path = format!("{prefix}{name}");
        let metadata = directory.symlink_metadata(&name).map_err(failure)?;
        if metadata.is_dir() {
            let child = directory.open_dir_nofollow(&name).map_err(failure)?;
            if identity(&child.dir_metadata().map_err(failure)?) != identity(&metadata) {
                return Err("Extension directory changed during preview.".into());
            }
            walk(&child, &format!("{path}/"), bundle, entries)?;
        } else if metadata.is_file() && metadata.nlink() == 1 {
            if metadata.len() > MAX_FILE_BYTES as u64
                || bundle.files.len() >= MAX_FILES
                || bundle
                    .byte_len()
                    .saturating_add(usize::try_from(metadata.len()).map_err(failure)?)
                    > MAX_BYTES
            {
                return Err("Extension content budget exceeded.".into());
            }
            // A replaced FIFO must not block before identity/type readback.
            let descriptor = rustix::fs::openat(
                directory,
                &name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK,
                rustix::fs::Mode::empty(),
            )
            .map_err(failure)?;
            let mut file = cap_std::fs::File::from_std(std::fs::File::from(descriptor));
            if identity(&file.metadata().map_err(failure)?) != identity(&metadata) {
                return Err("Extension file changed before preview.".into());
            }
            let mut bytes = Vec::new();
            (&mut file)
                .take(metadata.len() + 1)
                .read_to_end(&mut bytes)
                .map_err(failure)?;
            if bytes.len() as u64 != metadata.len()
                || identity(&file.metadata().map_err(failure)?) != identity(&metadata)
                || identity(&directory.symlink_metadata(&name).map_err(failure)?)
                    != identity(&metadata)
            {
                return Err("Extension file changed during preview.".into());
            }
            bundle.files.insert(
                path,
                Blob {
                    executable: metadata.mode() & 0o111 != 0,
                    bytes,
                },
            );
        } else {
            return Err(
                "Extension contains a link, socket, device, or unsupported file type.".into(),
            );
        }
    }
    if identity(&directory.dir_metadata().map_err(failure)?) != before {
        return Err("Extension directory changed during preview.".into());
    }
    Ok(())
}
