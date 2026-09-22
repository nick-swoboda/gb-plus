//! Bounded, read-once bridge from the CLI-owned browser session to xAI TTS.
//!
//! The Grok CLI remains the only persistent owner of its OAuth/OIDC session.
//! GB Plus reads one owner-only `auth.json` token into a revocable in-memory
//! lease and never writes, refreshes, logs, or forwards it to a child process.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read as _, Take};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use grok_build_plus_host::PlusLiveIdentity;
use serde::Deserialize;

const GROK_AUTH_MAX_BYTES: u64 = 64 * 1024;
const GROK_OAUTH_TOKEN_MAX_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub(crate) struct GrokOAuthTtsLease {
    inner: Arc<Mutex<Option<PlusLiveIdentity>>>,
}

impl std::fmt::Debug for GrokOAuthTtsLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GrokOAuthTtsLease")
            .field("identity", &"[redacted]")
            .field("active", &self.is_active())
            .finish()
    }
}

impl GrokOAuthTtsLease {
    fn from_token(token: String) -> Result<Self, String> {
        let bytes = token.into_bytes();
        validate_token_bytes(&bytes)?;
        let identity = PlusLiveIdentity::from_configured_key_bytes(bytes)
            .ok_or_else(|| "The CLI-owned Grok login token is empty or malformed.".to_owned())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Some(identity))),
        })
    }

    pub(crate) fn clone_identity(&self) -> Result<PlusLiveIdentity, String> {
        self.inner
            .lock()
            .map_err(|_| "The Grok login TTS lease lock is unavailable.".to_owned())?
            .as_ref()
            .cloned()
            .ok_or_else(|| "The Grok login TTS lease was revoked.".to_owned())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner.lock().is_ok_and(|identity| identity.is_some())
    }

    pub(crate) fn revoke(&self) {
        let mut identity = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = identity.take();
    }
}

#[derive(Deserialize)]
struct RelevantAuthEntry {
    auth_mode: String,
    key: String,
}

struct SensitiveFileBytes(Vec<u8>);

impl Drop for SensitiveFileBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Loads the one CLI-owned browser session without copying it into app state.
pub(crate) fn load_cli_oauth_tts_lease() -> Result<GrokOAuthTtsLease, String> {
    load_cli_oauth_tts_lease_at(&grok_auth_path()?)
}

fn grok_auth_path() -> Result<PathBuf, String> {
    super::auth_paths::cli_auth_path()
}

fn load_cli_oauth_tts_lease_at(path: &Path) -> Result<GrokOAuthTtsLease, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "The Grok CLI auth path has no parent directory.".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("Cannot inspect the Grok CLI auth directory: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(
            "The Grok CLI auth directory is not a direct directory; OAuth TTS was refused.".into(),
        );
    }
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("No CLI-owned Grok login token is available: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(
            "The Grok CLI auth file is not a direct regular file; OAuth TTS was refused.".into(),
        );
    }
    if before.len() == 0 || before.len() > GROK_AUTH_MAX_BYTES {
        return Err("The Grok CLI auth file is empty or exceeds the 64 KiB safety bound.".into());
    }
    validate_owner_only_metadata(&before, &parent_metadata)?;

    let file = File::open(path)
        .map_err(|error| format!("Cannot open the owner-only Grok CLI auth file: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("Cannot verify the opened Grok CLI auth file: {error}"))?;
    validate_same_file(&before, &after)?;
    let capacity = usize::try_from(after.len())
        .map_err(|_| "The Grok CLI auth file size cannot fit this platform.".to_owned())?;
    let mut bytes = SensitiveFileBytes(Vec::with_capacity(capacity));
    let mut bounded: Take<File> = file.take(GROK_AUTH_MAX_BYTES + 1);
    bounded
        .read_to_end(&mut bytes.0)
        .map_err(|error| format!("Cannot read the bounded Grok CLI auth file: {error}"))?;
    if bytes.0.len() as u64 > GROK_AUTH_MAX_BYTES {
        return Err("The Grok CLI auth file changed beyond the 64 KiB safety bound.".into());
    }

    let mut accounts: BTreeMap<String, RelevantAuthEntry> = serde_json::from_slice(&bytes.0)
        .map_err(|error| format!("The Grok CLI auth file is malformed: {error}"))?;
    if accounts.len() != 1 {
        return Err("The Grok CLI auth file does not identify exactly one browser login; OAuth TTS was refused.".into());
    }
    let (_, entry) = accounts
        .pop_first()
        .ok_or_else(|| "The Grok CLI auth file contains no browser login.".to_owned())?;
    if !matches!(entry.auth_mode.as_str(), "oauth" | "oidc") {
        return Err("The saved Grok CLI credential is not a browser OAuth/OIDC login; OAuth TTS was refused.".into());
    }
    GrokOAuthTtsLease::from_token(entry.key)
}

#[cfg(unix)]
fn validate_owner_only_metadata(file: &fs::Metadata, parent: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if file.uid() != parent.uid() {
        return Err(
            "The Grok CLI auth file and directory have different owners; OAuth TTS was refused."
                .into(),
        );
    }
    if file.permissions().mode() & 0o777 != 0o600 {
        return Err("The Grok CLI auth file is not mode 0600; OAuth TTS was refused.".into());
    }
    if parent.permissions().mode() & 0o022 != 0 {
        return Err(
            "The Grok CLI auth directory is group/world writable; OAuth TTS was refused.".into(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_only_metadata(
    _file: &fs::Metadata,
    _parent: &fs::Metadata,
) -> Result<(), String> {
    Err("The Grok CLI OAuth TTS bridge is available only on owner-permission platforms.".into())
}

#[cfg(unix)]
fn validate_same_file(before: &fs::Metadata, after: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
        || before.len() != after.len()
    {
        return Err("The Grok CLI auth file changed while opening; OAuth TTS was refused.".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_same_file(_before: &fs::Metadata, _after: &fs::Metadata) -> Result<(), String> {
    Err("The Grok CLI OAuth TTS bridge is unavailable on this platform.".into())
}

fn validate_token_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > GROK_OAUTH_TOKEN_MAX_BYTES {
        return Err(
            "The CLI-owned Grok login token is empty or exceeds the 8 KiB safety bound.".into(),
        );
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "The CLI-owned Grok login token is not valid UTF-8.".to_owned())?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(
            "The CLI-owned Grok login token is blank or contains control characters.".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn fixture_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "grok-oauth-tts-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn write_auth(root: &Path, body: &str) -> PathBuf {
        fs::create_dir_all(root).expect("create auth root");
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("secure root");
        let path = root.join("auth.json");
        fs::write(&path, body).expect("write auth");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure auth");
        path
    }

    #[test]
    fn owner_only_single_browser_token_becomes_revocable_memory_only_lease() {
        let root = fixture_root("valid");
        let path = write_auth(
            &root,
            r#"{"https://auth.x.ai::fixture":{"auth_mode":"oidc","key":"oauth-fixture-token","refresh_token":"never-copied"}}"#,
        );
        let lease = load_cli_oauth_tts_lease_at(&path).expect("load OAuth lease");
        assert!(lease.is_active());
        assert!(!format!("{lease:?}").contains("oauth-fixture-token"));
        assert!(!format!("{lease:?}").contains("never-copied"));
        lease.revoke();
        assert!(!lease.is_active());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn malformed_multiple_or_loose_auth_files_fail_closed_without_token_echo() {
        let root = fixture_root("refuse");
        let path = write_auth(
            &root,
            r#"{"one":{"auth_mode":"oidc","key":"secret-one"},"two":{"auth_mode":"oauth","key":"secret-two"}}"#,
        );
        let reason = load_cli_oauth_tts_lease_at(&path).expect_err("multiple accounts refuse");
        assert!(reason.contains("exactly one"));
        assert!(!reason.contains("secret-one"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen auth");
        let reason = load_cli_oauth_tts_lease_at(&path).expect_err("loose mode refuses");
        assert!(reason.contains("0600"));
        assert!(!reason.contains("secret"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_auth_file_is_refused_before_secret_read() {
        use std::os::unix::fs::symlink;

        let root = fixture_root("symlink");
        fs::create_dir_all(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("secure root");
        let target = root.join("target.json");
        fs::write(
            &target,
            r#"{"one":{"auth_mode":"oidc","key":"secret-target"}}"#,
        )
        .expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("secure target");
        let path = root.join("auth.json");
        symlink(&target, &path).expect("symlink");
        let reason = load_cli_oauth_tts_lease_at(&path).expect_err("symlink refuses");
        assert!(reason.contains("direct regular file"));
        assert!(!reason.contains("secret-target"));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
