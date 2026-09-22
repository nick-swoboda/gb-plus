//! Official xAI Grok Read Aloud state, bounded synthesis, and local preference.

#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
#[cfg(not(target_os = "macos"))]
use grok_build_plus_host::post_plus_live_tts;
use grok_build_plus_host::{
    PLUS_TTS_VOICE, PlusHostError, PlusLiveIdentity, PlusLiveTtsAudio, PlusLiveTtsRequest,
    encode_plus_live_tts_request,
};
use serde::{Deserialize, Serialize};

use crate::owner_state::{OwnerStateErrorKind, OwnerStateRoot};
use crate::runtime::keychain::XaiCredentialLease;
use crate::runtime::oauth_tts::GrokOAuthTtsLease;

const READ_ALOUD_SETTINGS_SCHEMA: u16 = 1;
const READ_ALOUD_SETTINGS_FILE: &str = "read-aloud-settings.json";
const MAX_SETTINGS_BYTES: u64 = 4096;

/// Official xAI endpoint maximum. The manual speaker remains available up to
/// this provider limit.
pub(crate) const READ_ALOUD_MAX_CHARS: usize = 15_000;

/// Auto-read stays concise and never starts a long unsolicited playback. The
/// manual speaker remains available for messages above this limit.
pub(crate) const AUTO_READ_MAX_CHARS: usize = 1_500;

pub(crate) const GROK_OAUTH_TTS_DENIED_REASON: &str =
    "xAI TTS needs an API key; this Grok login does not authorize /v1/tts";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadAloudCredentialSource {
    ApiKey,
    GrokOAuth,
}

impl ReadAloudCredentialSource {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::GrokOAuth => "Grok login · direct TTS, not ACP",
        }
    }
}

#[derive(Clone)]
pub(crate) struct ReadAloudCredential {
    source: ReadAloudCredentialSource,
    identity: ReadAloudCredentialIdentity,
}

#[derive(Clone)]
enum ReadAloudCredentialIdentity {
    ApiKey(XaiCredentialLease),
    GrokOAuth(GrokOAuthTtsLease),
}

impl std::fmt::Debug for ReadAloudCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReadAloudCredential")
            .field("source", &self.source)
            .field("identity", &"[redacted]")
            .field("active", &self.is_active())
            .finish()
    }
}

impl ReadAloudCredential {
    pub(crate) fn api_key(lease: XaiCredentialLease) -> Self {
        Self {
            source: ReadAloudCredentialSource::ApiKey,
            identity: ReadAloudCredentialIdentity::ApiKey(lease),
        }
    }

    pub(crate) fn grok_oauth(lease: GrokOAuthTtsLease) -> Self {
        Self {
            source: ReadAloudCredentialSource::GrokOAuth,
            identity: ReadAloudCredentialIdentity::GrokOAuth(lease),
        }
    }

    pub(crate) const fn source(&self) -> ReadAloudCredentialSource {
        self.source
    }

    pub(crate) fn is_active(&self) -> bool {
        match &self.identity {
            ReadAloudCredentialIdentity::ApiKey(lease) => lease.is_active(),
            ReadAloudCredentialIdentity::GrokOAuth(lease) => lease.is_active(),
        }
    }

    fn ensure_active(&self) -> Result<(), String> {
        if self.is_active() {
            Ok(())
        } else {
            Err("The Grok Read Aloud credential lease was revoked.".into())
        }
    }

    fn clone_identity(&self) -> Result<PlusLiveIdentity, String> {
        match &self.identity {
            ReadAloudCredentialIdentity::ApiKey(lease) => lease.clone_identity(),
            ReadAloudCredentialIdentity::GrokOAuth(lease) => lease.clone_identity(),
        }
    }

    pub(crate) fn revoke_if_oauth(&self) {
        if let ReadAloudCredentialIdentity::GrokOAuth(lease) = &self.identity {
            lease.revoke();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GrokOAuthTtsProbe {
    Authorized,
    Denied,
    Failed(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadAloudView {
    pub(crate) available: bool,
    pub(crate) reason: Option<String>,
    pub(crate) auto_read_enabled: bool,
    pub(crate) voice_id: &'static str,
    pub(crate) credential_source: Option<&'static str>,
    pub(crate) manual_character_limit: usize,
    pub(crate) auto_character_limit: usize,
    pub(crate) settings_issue: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadAloudAudio {
    pub(crate) content_type: String,
    pub(crate) audio_base64: String,
    pub(crate) character_count: usize,
}

#[derive(Clone)]
pub(crate) struct ReadAloudManager {
    inner: Arc<Mutex<ReadAloudInner>>,
    settings_path: PathBuf,
}

struct ReadAloudInner {
    auto_read_enabled: bool,
    settings_issue: Option<String>,
    active_cancel: Option<Arc<AtomicBool>>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadAloudSettings {
    schema_version: u16,
    auto_read_enabled: bool,
}

impl ReadAloudManager {
    pub(crate) fn new(state_root: &Path) -> Self {
        let settings_path = state_root.join(READ_ALOUD_SETTINGS_FILE);
        let (auto_read_enabled, settings_issue) = match read_settings(&settings_path) {
            Ok(Some(settings)) => (settings.auto_read_enabled, None),
            Ok(None) => (false, None),
            Err(reason) => (false, Some(reason)),
        };
        Self {
            inner: Arc::new(Mutex::new(ReadAloudInner {
                auto_read_enabled,
                settings_issue,
                active_cancel: None,
            })),
            settings_path,
        }
    }

    pub(crate) fn view(
        &self,
        available: bool,
        reason: Option<String>,
        source: Option<ReadAloudCredentialSource>,
    ) -> ReadAloudView {
        match self.inner.lock() {
            Ok(inner) => ReadAloudView {
                available,
                reason,
                auto_read_enabled: inner.auto_read_enabled,
                voice_id: PLUS_TTS_VOICE,
                credential_source: source.map(ReadAloudCredentialSource::label),
                manual_character_limit: READ_ALOUD_MAX_CHARS,
                auto_character_limit: AUTO_READ_MAX_CHARS,
                settings_issue: inner.settings_issue.clone(),
            },
            Err(_) => ReadAloudView {
                available: false,
                reason: Some("Grok Read Aloud state is unavailable.".into()),
                auto_read_enabled: false,
                voice_id: PLUS_TTS_VOICE,
                credential_source: None,
                manual_character_limit: READ_ALOUD_MAX_CHARS,
                auto_character_limit: AUTO_READ_MAX_CHARS,
                settings_issue: Some("Read Aloud state lock was poisoned.".into()),
            },
        }
    }

    pub(crate) fn set_auto_read(&self, enabled: bool) -> Result<(), String> {
        write_settings(&self.settings_path, enabled)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Grok Read Aloud state is unavailable.".to_owned())?;
        inner.auto_read_enabled = enabled;
        inner.settings_issue = None;
        Ok(())
    }

    pub(crate) fn stop(&self) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(cancel) = inner.active_cancel.take()
        {
            cancel.store(true, Ordering::Release);
        }
    }

    pub(crate) fn synthesize(
        &self,
        credential: &ReadAloudCredential,
        text: &str,
    ) -> Result<ReadAloudAudio, String> {
        let text = text.trim();
        let character_count = text.chars().count();
        if character_count == 0 {
            return Err("Choose a completed assistant message to read aloud.".into());
        }
        if character_count > READ_ALOUD_MAX_CHARS {
            return Err("This reply exceeds the official 15,000-character xAI TTS limit.".into());
        }
        credential.ensure_active()?;
        let identity = credential.clone_identity()?;
        let request =
            encode_plus_live_tts_request(text, &identity).map_err(|error| error.to_string())?;
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Grok Read Aloud state is unavailable.".to_owned())?;
            if let Some(previous) = inner.active_cancel.replace(Arc::clone(&cancel)) {
                previous.store(true, Ordering::Release);
            }
        }
        let response = post_read_aloud_tts(&request, || {
            cancel.load(Ordering::Acquire) || !credential.is_active()
        })
        .map_err(|error| error.to_string());
        if let Ok(mut inner) = self.inner.lock()
            && inner
                .active_cancel
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &cancel))
        {
            inner.active_cancel = None;
        }
        if cancel.load(Ordering::Acquire) {
            return Err("Grok Read Aloud stopped.".into());
        }
        credential.ensure_active()?;
        let response = response?;
        Ok(ReadAloudAudio {
            content_type: response.content_type,
            audio_base64: base64::engine::general_purpose::STANDARD.encode(response.bytes),
            character_count,
        })
    }
}

/// Performs one separately attributed OAuth authorization check against the
/// exact official TTS endpoint. Returned audio is immediately discarded.
pub(crate) fn probe_grok_oauth_tts(lease: &GrokOAuthTtsLease) -> GrokOAuthTtsProbe {
    let identity = match lease.clone_identity() {
        Ok(identity) => identity,
        Err(reason) => return GrokOAuthTtsProbe::Failed(reason),
    };
    let request = match encode_plus_live_tts_request(
        "GB Plus direct OAuth voice authorization check.",
        &identity,
    ) {
        Ok(request) => request,
        Err(error) => return GrokOAuthTtsProbe::Failed(error.to_string()),
    };
    oauth_probe_outcome(post_read_aloud_tts(&request, || false))
}

#[cfg(target_os = "macos")]
fn post_read_aloud_tts(
    request: &PlusLiveTtsRequest,
    cancelled: impl FnMut() -> bool,
) -> Result<PlusLiveTtsAudio, PlusHostError> {
    crate::tts_transport::post_plus_live_tts_macos(request, cancelled)
}

#[cfg(not(target_os = "macos"))]
fn post_read_aloud_tts(
    request: &PlusLiveTtsRequest,
    cancelled: impl FnMut() -> bool,
) -> Result<PlusLiveTtsAudio, PlusHostError> {
    post_plus_live_tts(request, cancelled)
}

fn oauth_probe_outcome(result: Result<PlusLiveTtsAudio, PlusHostError>) -> GrokOAuthTtsProbe {
    match result {
        Ok(_) => GrokOAuthTtsProbe::Authorized,
        Err(PlusHostError::LiveHttp { status: 401 | 403 }) => GrokOAuthTtsProbe::Denied,
        Err(PlusHostError::LiveHttp { status }) => GrokOAuthTtsProbe::Failed(format!(
            "xAI TTS OAuth check returned HTTP {status}; Grok CLI / ACP Chat remains connected but Read Aloud is disabled."
        )),
        Err(error) => GrokOAuthTtsProbe::Failed(format!(
            "xAI TTS OAuth check failed: {error}; Grok CLI / ACP Chat remains connected but Read Aloud is disabled."
        )),
    }
}

fn read_settings(path: &Path) -> Result<Option<ReadAloudSettings>, String> {
    let file = OwnerStateRoot::new(
        path.parent()
            .ok_or_else(|| "Read Aloud settings path has no parent.".to_owned())?,
    )
    .file(READ_ALOUD_SETTINGS_FILE, MAX_SETTINGS_BYTES)
    .map_err(|error| format!("Cannot inspect Read Aloud settings: {error}"))?;
    let Some(bytes) = file.read().map_err(|error| match error.kind {
        OwnerStateErrorKind::Type | OwnerStateErrorKind::Owner => {
            "Read Aloud settings are not a regular owner-controlled file.".into()
        }
        OwnerStateErrorKind::Oversized => "Read Aloud settings exceeded the 4 KiB bound.".into(),
        OwnerStateErrorKind::Read => format!("Cannot read Read Aloud settings: {error}"),
        _ => format!("Cannot inspect Read Aloud settings: {error}"),
    })?
    else {
        return Ok(None);
    };
    let settings: ReadAloudSettings = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Read Aloud settings are malformed: {error}"))?;
    if settings.schema_version != READ_ALOUD_SETTINGS_SCHEMA {
        return Err(format!(
            "Read Aloud settings schema {} is unsupported.",
            settings.schema_version
        ));
    }
    Ok(Some(settings))
}

fn write_settings(path: &Path, enabled: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Read Aloud settings path has no parent.".to_owned())?;
    let bytes = serde_json::to_vec_pretty(&ReadAloudSettings {
        schema_version: READ_ALOUD_SETTINGS_SCHEMA,
        auto_read_enabled: enabled,
    })
    .map_err(|error| format!("Cannot encode Read Aloud settings: {error}"))?;
    OwnerStateRoot::new(parent)
        .file(READ_ALOUD_SETTINGS_FILE, MAX_SETTINGS_BYTES)
        .and_then(|file| file.replace(&bytes))
        .map_err(|error| format!("Cannot persist Read Aloud settings: {error}"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "grok-read-aloud-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn auto_read_defaults_off_and_persists_owner_only() {
        let root = temp_root("settings");
        let manager = ReadAloudManager::new(&root);
        assert!(!manager.view(true, None, None).auto_read_enabled);
        manager.set_auto_read(true).expect("persist auto-read");
        let path = root.join(READ_ALOUD_SETTINGS_FILE);
        assert_eq!(
            fs::metadata(&path)
                .expect("settings metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let restored = ReadAloudManager::new(&root);
        assert!(restored.view(true, None, None).auto_read_enabled);
        let bytes = fs::read(&path).expect("settings bytes");
        assert!(!bytes.windows(3).any(|window| window == b"key"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn malformed_or_future_settings_fail_closed_to_auto_read_off() {
        let root = temp_root("malformed");
        fs::create_dir_all(&root).expect("root");
        fs::write(
            root.join(READ_ALOUD_SETTINGS_FILE),
            br#"{"schemaVersion":99,"autoReadEnabled":true}"#,
        )
        .expect("future settings");
        let manager = ReadAloudManager::new(&root);
        let view = manager.view(true, None, None);
        assert!(!view.auto_read_enabled);
        assert!(view.settings_issue.is_some());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn stop_cancels_the_current_synthesis_generation() {
        let root = temp_root("cancel");
        let manager = ReadAloudManager::new(&root);
        let first = Arc::new(AtomicBool::new(false));
        {
            let mut inner = manager.inner.lock().expect("state");
            inner.active_cancel = Some(Arc::clone(&first));
        }
        manager.stop();
        assert!(first.load(Ordering::Acquire));
        assert!(manager.inner.lock().expect("state").active_cancel.is_none());
    }

    #[test]
    fn oauth_probe_preserves_structured_denial_and_never_guesses_success() {
        assert_eq!(
            oauth_probe_outcome(Err(PlusHostError::LiveHttp { status: 401 })),
            GrokOAuthTtsProbe::Denied
        );
        assert_eq!(
            oauth_probe_outcome(Err(PlusHostError::LiveHttp { status: 403 })),
            GrokOAuthTtsProbe::Denied
        );
        let rate_limit = oauth_probe_outcome(Err(PlusHostError::LiveHttp { status: 429 }));
        assert!(
            matches!(rate_limit, GrokOAuthTtsProbe::Failed(reason) if reason.contains("HTTP 429"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an installed CLI-owned Grok browser login and performs one live /v1/tts request"]
    fn installed_cli_oauth_session_completes_one_direct_live_tts_probe() {
        let lease = crate::runtime::oauth_tts::load_cli_oauth_tts_lease()
            .expect("load owner-only CLI OAuth token");
        assert_eq!(probe_grok_oauth_tts(&lease), GrokOAuthTtsProbe::Authorized);
        lease.revoke();
    }
}
