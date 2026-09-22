//! Exact Chrome-for-Testing download, extraction, and runtime verification.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use zip::{CompressionMethod, ZipArchive};

use crate::asset_download::{AssetManager, AssetSpec};

const CHROME_VERSION: &str = "152.0.7977.54";
const CHROME_ARCHIVE: AssetSpec = AssetSpec {
    id: "chrome-for-testing-152-mac-arm64",
    filename: "chrome-mac-arm64-152.0.7977.54.zip",
    url: "https://storage.googleapis.com/chrome-for-testing-public/152.0.7977.54/mac-arm64/chrome-mac-arm64.zip",
    byte_len: 187_918_859,
    sha256: "0c8741d580076b3a8add518ddbb674183992d005cdee37a4875948c9f2748d2a",
    allowed_hosts: &["storage.googleapis.com"],
};
const ARCHIVE_ENTRY_COUNT: usize = 645;
const ARCHIVE_FILE_COUNT: usize = 330;
const ARCHIVE_DIRECTORY_ENTRY_COUNT: usize = 310;
const ARCHIVE_SYMLINK_COUNT: usize = 5;
const ARCHIVE_UNCOMPRESSED_BYTES: u128 = 372_284_714;
const EXTRACTED_FILE_BYTES: u64 = 372_284_573;
const EXTRACTED_DIRECTORY_COUNT: usize = 314;
const MAX_REGULAR_FILE_BYTES: u64 = 244_000_000;
const MAX_RUNTIME_TREE_BYTES: u64 = 373_000_000;
const ARCHIVE_ROOT: &str = "chrome-mac-arm64";
const RUNTIME_DIRECTORY: &str = "chrome-for-testing-152.0.7977.54";
const CHROME_EXECUTABLE: &str =
    "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing";
const INFO_PLIST: &str = "Google Chrome for Testing.app/Contents/Info.plist";
const EXPECTED_RUNTIME_MANIFEST_SHA256: &str =
    "af5e120f5039728c77022135c34507192ed33c7b277e6f770c107efb19231e63";

const SYMLINKS: [(&str, &str); 5] = [
    (
        "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Resources",
        "Versions/Current/Resources",
    ),
    (
        "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions/Current",
        "152.0.7977.54",
    ),
    (
        "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Libraries",
        "Versions/Current/Libraries",
    ),
    (
        "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Google Chrome for Testing Framework",
        "Versions/Current/Google Chrome for Testing Framework",
    ),
    (
        "Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Helpers",
        "Versions/Current/Helpers",
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BrowserRuntimePhase {
    Idle,
    Downloading,
    Extracting,
    Verifying,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BrowserRuntimeView {
    pub(crate) phase: BrowserRuntimePhase,
    pub(crate) installed: bool,
    pub(crate) verified_this_run: bool,
    pub(crate) detail: String,
    pub(crate) downloaded_bytes: Option<u64>,
    pub(crate) total_bytes: Option<u64>,
    pub(crate) version: &'static str,
    pub(crate) download_bytes: u64,
    pub(crate) source: &'static str,
    pub(crate) terms_url: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BrowserAssetProgress {
    pub(crate) downloaded_bytes: u64,
    pub(crate) total_bytes: u64,
}

#[derive(Clone)]
pub(crate) struct BrowserRuntimeManager {
    inner: Arc<Mutex<BrowserRuntimeInner>>,
    runtime_root: PathBuf,
    archives: AssetManager,
}

struct BrowserRuntimeInner {
    phase: BrowserRuntimePhase,
    verified_this_run: bool,
    detail: String,
    downloaded_bytes: Option<u64>,
    total_bytes: Option<u64>,
}

impl BrowserRuntimeManager {
    pub(crate) fn new(state_root: &Path) -> Self {
        let runtime_root = state_root.join("runtime-assets").join("browser");
        Self {
            inner: Arc::new(Mutex::new(BrowserRuntimeInner {
                phase: BrowserRuntimePhase::Idle,
                verified_this_run: false,
                detail: "Chrome for Testing is installed only after you approve its exact 188 MB Google download."
                    .into(),
                downloaded_bytes: None,
                total_bytes: None,
            })),
            archives: AssetManager::new(runtime_root.join("archives")),
            runtime_root,
        }
    }

    pub(crate) fn status(&self) -> BrowserRuntimeView {
        match self.inner.lock() {
            Ok(inner) => self.view_locked(&inner),
            Err(_) => BrowserRuntimeView {
                phase: BrowserRuntimePhase::Failed,
                installed: false,
                verified_this_run: false,
                detail: "Browser runtime state is unavailable because its lock was poisoned."
                    .into(),
                downloaded_bytes: None,
                total_bytes: None,
                version: CHROME_VERSION,
                download_bytes: CHROME_ARCHIVE.byte_len,
                source: "Google Chrome for Testing",
                terms_url: "https://policies.google.com/terms",
            },
        }
    }

    pub(crate) fn install<F>(&self, mut progress: F) -> Result<BrowserRuntimeView, String>
    where
        F: FnMut(BrowserAssetProgress),
    {
        {
            let mut inner = self.lock()?;
            if inner.phase != BrowserRuntimePhase::Idle
                && inner.phase != BrowserRuntimePhase::Failed
            {
                return Err("Finish the current Browser runtime operation first.".into());
            }
            inner.phase = BrowserRuntimePhase::Downloading;
            inner.verified_this_run = false;
            inner.detail = format!(
                "Downloading exact Chrome for Testing {CHROME_VERSION} from Google over HTTPS…"
            );
            inner.downloaded_bytes = Some(0);
            inner.total_bytes = Some(CHROME_ARCHIVE.byte_len);
        }

        let mut last_emitted = 0_u64;
        let installed = self.archives.install(CHROME_ARCHIVE, |downloaded, total| {
            if let Ok(mut inner) = self.inner.lock() {
                inner.downloaded_bytes = Some(downloaded);
                inner.total_bytes = Some(total);
            }
            if downloaded == total || downloaded.saturating_sub(last_emitted) >= 4 * 1024 * 1024 {
                last_emitted = downloaded;
                progress(BrowserAssetProgress {
                    downloaded_bytes: downloaded,
                    total_bytes: total,
                });
            }
        });
        let result = installed.and_then(|_| self.extract_and_promote());
        match result {
            Ok(()) => {
                let mut inner = self.lock()?;
                inner.phase = BrowserRuntimePhase::Idle;
                inner.verified_this_run = true;
                inner.detail = format!(
                    "Chrome for Testing {CHROME_VERSION} is installed and fully verified. Browser remains Off until armed."
                );
                inner.downloaded_bytes = None;
                inner.total_bytes = None;
                Ok(self.view_locked(&inner))
            }
            Err(error) => self.fail(error),
        }
    }

    pub(crate) fn verified_executable(&self) -> Result<PathBuf, String> {
        {
            let inner = self.lock()?;
            if inner.verified_this_run {
                return checked_executable(&self.final_root());
            }
        }
        let mut inner = self.lock()?;
        inner.phase = BrowserRuntimePhase::Verifying;
        inner.detail = "Verifying the complete Chrome runtime before launch…".into();
        drop(inner);
        let result = validate_extracted_runtime(&self.final_root());
        match result {
            Ok(_) => {
                let mut inner = self.lock()?;
                inner.phase = BrowserRuntimePhase::Idle;
                inner.verified_this_run = true;
                inner.detail = format!(
                    "Chrome for Testing {CHROME_VERSION} is installed and fully verified. Browser remains Off until armed."
                );
                checked_executable(&self.final_root())
            }
            Err(error) => self.fail(error),
        }
    }

    fn extract_and_promote(&self) -> Result<(), String> {
        ensure_private_directory(&self.runtime_root)?;
        let final_root = self.final_root();
        if final_root.exists() {
            if validate_extracted_runtime(&final_root).is_ok() {
                return Ok(());
            }
            remove_exact_runtime_root(&self.runtime_root, &final_root)?;
        }
        {
            let mut inner = self.lock()?;
            inner.phase = BrowserRuntimePhase::Extracting;
            inner.detail = "Validating and extracting the exact bounded Chrome archive…".into();
        }
        let archive_path = self
            .archives
            .verified_path(CHROME_ARCHIVE)?
            .ok_or_else(|| {
                "The verified Chrome archive disappeared before extraction.".to_owned()
            })?;
        let temp_parent = self.runtime_root.join(format!(
            ".chrome-extract-{}-{}",
            std::process::id(),
            nonce()
        ));
        ensure_private_directory(&temp_parent)?;
        let result = (|| {
            let archive_file = self
                .archives
                .open_verified(CHROME_ARCHIVE)?
                .ok_or_else(|| "The verified Chrome archive disappeared before use.".to_owned())?;
            let mut archive = validated_archive(archive_file)?;
            archive
                .extract(&temp_parent)
                .map_err(|error| format!("Bounded Chrome extraction failed: {error}"))?;
            drop(archive);
            let extracted_root = temp_parent.join(ARCHIVE_ROOT);
            validate_extracted_runtime(&extracted_root)?;
            fs::remove_file(&archive_path)
                .map_err(|error| format!("Cannot remove the consumed Chrome archive: {error}"))?;
            sync_directory(
                archive_path
                    .parent()
                    .ok_or_else(|| "Chrome archive has no parent.".to_owned())?,
            )?;
            fs::rename(&extracted_root, &final_root).map_err(|error| {
                format!("Cannot atomically promote the Chrome runtime: {error}")
            })?;
            sync_directory(&self.runtime_root)?;
            fs::remove_dir(&temp_parent).map_err(|error| {
                format!("Cannot remove the empty Chrome extraction root: {error}")
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&temp_parent);
        }
        result
    }

    fn final_root(&self) -> PathBuf {
        self.runtime_root.join(RUNTIME_DIRECTORY)
    }

    fn view_locked(&self, inner: &BrowserRuntimeInner) -> BrowserRuntimeView {
        BrowserRuntimeView {
            phase: inner.phase,
            installed: runtime_shape(&self.final_root()),
            verified_this_run: inner.verified_this_run,
            detail: inner.detail.clone(),
            downloaded_bytes: inner.downloaded_bytes,
            total_bytes: inner.total_bytes,
            version: CHROME_VERSION,
            download_bytes: CHROME_ARCHIVE.byte_len,
            source: "Google Chrome for Testing",
            terms_url: "https://policies.google.com/terms",
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BrowserRuntimeInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "Browser runtime state lock is unavailable.".to_owned())
    }

    fn fail<T>(&self, error: String) -> Result<T, String> {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = BrowserRuntimePhase::Failed;
            inner.verified_this_run = false;
            inner.detail.clone_from(&error);
            inner.downloaded_bytes = None;
            inner.total_bytes = None;
        }
        Err(error)
    }
}

fn runtime_shape(root: &Path) -> bool {
    fs::symlink_metadata(root).is_ok_and(|metadata| {
        metadata.is_dir() && !metadata.file_type().is_symlink() && checked_executable(root).is_ok()
    })
}

fn checked_executable(root: &Path) -> Result<PathBuf, String> {
    let executable = root.join(CHROME_EXECUTABLE);
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|error| format!("Chrome executable is unavailable: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("Chrome executable is not a regular executable file.".into());
    }
    Ok(executable)
}

#[cfg(test)]
fn validate_archive(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect the Chrome archive: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != CHROME_ARCHIVE.byte_len
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Chrome archive identity, size, or owner-only permissions changed.".into());
    }
    let file = File::open(path).map_err(|error| format!("Cannot open Chrome archive: {error}"))?;
    let _ = validated_archive(file)?;
    Ok(())
}

fn validated_archive(file: File) -> Result<ZipArchive<File>, String> {
    let mut archive =
        ZipArchive::new(file).map_err(|error| format!("Chrome ZIP parse failed: {error}"))?;
    if archive.len() != ARCHIVE_ENTRY_COUNT
        || archive.decompressed_size() != Some(ARCHIVE_UNCOMPRESSED_BYTES)
    {
        return Err("Chrome archive entry count or total expanded size changed.".into());
    }
    let mut exact_names = HashSet::new();
    let mut folded_names = HashSet::new();
    let mut files = 0_usize;
    let mut directories = 0_usize;
    let mut symlinks = 0_usize;
    let mut total = 0_u128;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot read Chrome ZIP entry {index}: {error}"))?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(|_| "Chrome archive contains a non-UTF-8 path.".to_owned())?
            .to_owned();
        validate_entry_name(&name, entry.enclosed_name().as_deref())?;
        if !exact_names.insert(name.clone()) || !folded_names.insert(name.to_lowercase()) {
            return Err("Chrome archive contains a duplicate or case-fold-colliding path.".into());
        }
        if entry.encrypted() {
            return Err("Chrome archive contains an encrypted entry.".into());
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err("Chrome archive uses an unadmitted compression method.".into());
        }
        if entry.size() > MAX_REGULAR_FILE_BYTES && !entry.is_dir() {
            return Err("Chrome archive entry exceeds the admitted per-file bound.".into());
        }
        if entry.size() > 0 && entry.compressed_size() == 0 && !entry.is_dir() {
            return Err("Chrome archive reports a non-empty zero-byte compressed entry.".into());
        }
        total = total
            .checked_add(u128::from(entry.size()))
            .ok_or_else(|| "Chrome archive expanded-size sum overflowed.".to_owned())?;
        let mode = entry
            .unix_mode()
            .ok_or_else(|| "Chrome archive entry has no Unix mode.".to_owned())?;
        let kind = mode & 0o170_000;
        if entry.is_symlink() && kind == 0o120_000 {
            symlinks += 1;
            let mut target = Vec::new();
            entry
                .read_to_end(&mut target)
                .map_err(|error| format!("Cannot read Chrome archive symlink: {error}"))?;
            let target = std::str::from_utf8(&target)
                .map_err(|_| "Chrome symlink target is not UTF-8.".to_owned())?;
            let relative = name
                .strip_prefix(&format!("{ARCHIVE_ROOT}/"))
                .ok_or_else(|| "Chrome symlink left the archive root.".to_owned())?;
            if !SYMLINKS.contains(&(relative, target)) {
                return Err("Chrome archive symlink path or target changed.".into());
            }
        } else if entry.is_dir() && kind == 0o040_000 {
            directories += 1;
        } else if entry.is_file() && (kind == 0o100_000 || kind == 0) {
            files += 1;
        } else {
            return Err("Chrome archive contains a special or type-confused entry.".into());
        }
    }
    if files != ARCHIVE_FILE_COUNT
        || directories != ARCHIVE_DIRECTORY_ENTRY_COUNT
        || symlinks != ARCHIVE_SYMLINK_COUNT
        || total != ARCHIVE_UNCOMPRESSED_BYTES
    {
        return Err("Chrome archive file/directory/symlink counts changed.".into());
    }
    Ok(archive)
}

fn validate_entry_name(name: &str, enclosed: Option<&Path>) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 2048
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || !name.starts_with(&format!("{ARCHIVE_ROOT}/"))
        || enclosed.is_none()
        || Path::new(name).is_absolute()
        || Path::new(name).components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Chrome archive contains an unsafe path.".into());
    }
    Ok(())
}

fn validate_extracted_runtime(root: &Path) -> Result<RuntimeManifest, String> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("Chrome runtime is not installed: {error}"))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("Chrome runtime root is not a regular directory.".into());
    }
    let manifest = runtime_manifest(root)?;
    if manifest.files != ARCHIVE_FILE_COUNT
        || manifest.directories != EXTRACTED_DIRECTORY_COUNT
        || manifest.symlinks != ARCHIVE_SYMLINK_COUNT
        || manifest.file_bytes != EXTRACTED_FILE_BYTES
        || manifest.sha256 != EXPECTED_RUNTIME_MANIFEST_SHA256
    {
        return Err(format!(
            "Chrome runtime post-extract manifest changed (observed {}).",
            manifest.sha256
        ));
    }
    validate_plist(root)?;
    validate_macho_inventory(root)?;
    for (relative, expected_target) in SYMLINKS {
        let path = root.join(relative);
        let target = fs::read_link(&path)
            .map_err(|error| format!("Cannot read Chrome framework symlink: {error}"))?;
        if target != Path::new(expected_target) {
            return Err("Chrome framework symlink target changed after extraction.".into());
        }
        let resolved = fs::canonicalize(&path)
            .map_err(|error| format!("Chrome framework symlink is broken: {error}"))?;
        let canonical_root = fs::canonicalize(root)
            .map_err(|error| format!("Cannot canonicalize Chrome runtime: {error}"))?;
        if !resolved.starts_with(canonical_root) {
            return Err("Chrome framework symlink resolves outside the runtime.".into());
        }
    }
    let _ = checked_executable(root)?;
    Ok(manifest)
}

#[derive(Clone, Debug)]
struct RuntimeManifest {
    sha256: String,
    files: usize,
    directories: usize,
    symlinks: usize,
    file_bytes: u64,
}

fn runtime_manifest(root: &Path) -> Result<RuntimeManifest, String> {
    let mut entries = Vec::new();
    collect_runtime_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut aggregate = Sha256::new();
    let mut files = 0_usize;
    let mut directories = 0_usize;
    let mut symlinks = 0_usize;
    let mut file_bytes = 0_u64;
    for (relative, path) in entries {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect Chrome runtime entry: {error}"))?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink() {
            symlinks += 1;
            let target = fs::read_link(&path)
                .map_err(|error| format!("Cannot read Chrome runtime symlink: {error}"))?;
            let target = target
                .to_str()
                .filter(|value| !value.chars().any(char::is_control))
                .ok_or_else(|| "Chrome runtime symlink target is invalid.".to_owned())?;
            aggregate.update(format!("L\t{mode:04o}\t{target}\t{relative}\n").as_bytes());
        } else if metadata.is_dir() {
            directories += 1;
            aggregate.update(format!("D\t{mode:04o}\t{relative}\n").as_bytes());
        } else if metadata.is_file() {
            files += 1;
            file_bytes = file_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| "Chrome runtime byte count overflowed.".to_owned())?;
            if metadata.len() > MAX_REGULAR_FILE_BYTES || file_bytes > MAX_RUNTIME_TREE_BYTES {
                return Err("Chrome runtime exceeds an admitted byte bound.".into());
            }
            let hash = hash_file(&path)?;
            aggregate.update(
                format!("F\t{mode:04o}\t{}\t{hash}\t{relative}\n", metadata.len()).as_bytes(),
            );
        } else {
            return Err("Chrome runtime contains a special file.".into());
        }
    }
    Ok(RuntimeManifest {
        sha256: lowercase_hex(&aggregate.finalize()),
        files,
        directories,
        symlinks,
        file_bytes,
    })
}

fn collect_runtime_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    for item in fs::read_dir(directory)
        .map_err(|error| format!("Cannot read Chrome runtime directory: {error}"))?
    {
        let item = item.map_err(|error| format!("Cannot read Chrome runtime entry: {error}"))?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "Chrome runtime entry escaped its root.".to_owned())?
            .to_str()
            .filter(|value| {
                !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| "Chrome runtime path is invalid.".to_owned())?
            .to_owned();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect Chrome runtime entry: {error}"))?;
        entries.push((relative, path.clone()));
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_runtime_entries(root, &path, entries)?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Cannot open Chrome runtime file for hashing: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash Chrome runtime file: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(lowercase_hex(&hash.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_plist(root: &Path) -> Result<(), String> {
    let path = root.join(INFO_PLIST);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("Chrome Info.plist is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 128 * 1024 {
        return Err("Chrome Info.plist shape is invalid.".into());
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("Cannot read Chrome Info.plist: {error}"))?;
    for exact in [
        "<key>CFBundleIdentifier</key>\n\t<string>com.google.chrome.for.testing</string>",
        "<key>CFBundleShortVersionString</key>\n\t<string>152.0.7977.54</string>",
        "<key>LSMinimumSystemVersion</key>\n\t<string>13.0</string>",
        "<key>SCMRevision</key>\n\t<string>24072c1aa400ec4a89dc738b6b6acd12a8589b6f-refs/branch-heads/7977@{#1831}</string>",
    ] {
        if !text.contains(exact) {
            return Err("Chrome Info.plist identity changed.".into());
        }
    }
    Ok(())
}

fn validate_macho_inventory(root: &Path) -> Result<(), String> {
    let mut entries = Vec::new();
    collect_runtime_entries(root, root, &mut entries)?;
    let mut macho_count = 0_usize;
    for (_, path) in entries {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect Chrome native file: {error}"))?;
        if !metadata.is_file() || metadata.len() < 8 {
            continue;
        }
        let mut header = [0_u8; 8];
        File::open(&path)
            .and_then(|mut file| file.read_exact(&mut header))
            .map_err(|error| format!("Cannot read Chrome native header: {error}"))?;
        if header[..4] == [0xcf, 0xfa, 0xed, 0xfe] {
            let cpu_type = u32::from_le_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| "Chrome native header has an invalid CPU field.".to_owned())?,
            );
            if cpu_type != 0x0100_000c {
                return Err("Chrome runtime contains a non-arm64 Mach-O file.".into());
            }
            macho_count += 1;
        } else if matches!(
            header[..4],
            [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca]
        ) {
            return Err("Chrome runtime contains an unadmitted universal Mach-O file.".into());
        }
    }
    if macho_count != 12 {
        return Err(format!(
            "Chrome native inventory changed; expected 12 arm64 Mach-O files, observed {macho_count}."
        ));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create Browser runtime directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect Browser runtime directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Browser runtime refused a symlink or non-directory root.".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("Cannot secure Browser runtime directory: {error}"))
}

fn remove_exact_runtime_root(parent: &Path, target: &Path) -> Result<(), String> {
    if target.parent() != Some(parent)
        || target.file_name().and_then(|name| name.to_str()) != Some(RUNTIME_DIRECTORY)
    {
        return Err("Browser runtime repair refused an unexpected removal target.".into());
    }
    let metadata = fs::symlink_metadata(target)
        .map_err(|error| format!("Cannot inspect invalid Browser runtime: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Browser runtime repair refused a symlink or non-directory target.".into());
    }
    fs::remove_dir_all(target)
        .map_err(|error| format!("Cannot remove the invalid managed Browser runtime: {error}"))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Cannot sync Browser runtime directory: {error}"))
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_identity_and_central_directory_math_are_exact() {
        assert_eq!(
            ARCHIVE_FILE_COUNT + ARCHIVE_DIRECTORY_ENTRY_COUNT + ARCHIVE_SYMLINK_COUNT,
            ARCHIVE_ENTRY_COUNT
        );
        assert_eq!(CHROME_ARCHIVE.byte_len, 187_918_859);
        assert_eq!(
            CHROME_ARCHIVE.sha256,
            "0c8741d580076b3a8add518ddbb674183992d005cdee37a4875948c9f2748d2a"
        );
        assert!(!CHROME_ARCHIVE.url.contains("latest"));
    }

    #[test]
    fn archive_path_guards_refuse_escape_collision_and_wrong_host() {
        assert!(
            validate_entry_name(
                "chrome-mac-arm64/ok/file",
                Some(Path::new("chrome-mac-arm64/ok/file"))
            )
            .is_ok()
        );
        assert!(validate_entry_name("../escape", None).is_err());
        assert!(validate_entry_name("chrome-mac-arm64/../escape", None).is_err());
        assert!(validate_entry_name("chrome-mac-arm64\\escape", None).is_err());
        assert!(validate_entry_name("chrome-mac-arm64/control\n", None).is_err());
    }

    #[test]
    #[ignore = "requires the exact admitted Chrome archive and extracted audit tree"]
    fn exact_archive_and_extracted_manifest_match_product_validator() {
        let root = std::env::var_os("GROK_BUILD_CHROME_AUDIT_ROOT")
            .map(PathBuf::from)
            .expect("set GROK_BUILD_CHROME_AUDIT_ROOT");
        validate_archive(&root.join("chrome-mac-arm64.zip")).expect("validate exact archive");
        let manifest = runtime_manifest(&root.join("extracted").join(ARCHIVE_ROOT))
            .expect("compute extracted manifest");
        eprintln!(
            "chrome-runtime-manifest sha256={} files={} dirs={} symlinks={} bytes={}",
            manifest.sha256,
            manifest.files,
            manifest.directories,
            manifest.symlinks,
            manifest.file_bytes
        );
        assert_eq!(manifest.files, ARCHIVE_FILE_COUNT);
        assert_eq!(manifest.directories, EXTRACTED_DIRECTORY_COUNT);
        assert_eq!(manifest.symlinks, ARCHIVE_SYMLINK_COUNT);
        assert_eq!(manifest.file_bytes, EXTRACTED_FILE_BYTES);
        validate_plist(&root.join("extracted").join(ARCHIVE_ROOT)).expect("validate plist");
        validate_macho_inventory(&root.join("extracted").join(ARCHIVE_ROOT))
            .expect("validate Mach-O inventory");
    }

    #[test]
    #[ignore = "downloads, extracts, and validates the exact admitted 188 MB Chrome runtime"]
    fn exact_chrome_download_extract_and_atomic_promotion_use_product_path() {
        let state_root = std::env::temp_dir().join(format!(
            "grok-browser-install-test-{}-{}",
            std::process::id(),
            nonce()
        ));
        let manager = BrowserRuntimeManager::new(&state_root);
        let mut progress_updates = 0_usize;
        let view = manager
            .install(|progress| {
                assert!(progress.downloaded_bytes <= progress.total_bytes);
                assert_eq!(progress.total_bytes, CHROME_ARCHIVE.byte_len);
                progress_updates += 1;
            })
            .expect("install exact Chrome runtime");
        assert!(view.installed);
        assert!(view.verified_this_run);
        assert!(progress_updates > 1);
        let executable = manager
            .verified_executable()
            .expect("re-open fully verified Chrome executable");
        assert_eq!(
            executable.file_name().and_then(|name| name.to_str()),
            Some("Google Chrome for Testing")
        );
        assert!(
            !manager
                .archives
                .root()
                .join(CHROME_ARCHIVE.filename)
                .exists()
        );
        fs::remove_dir_all(state_root).expect("cleanup exact Chrome install fixture");
    }
}
