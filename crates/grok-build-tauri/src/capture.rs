//! Explicit, run-scoped Screen Capture grants and transient frame ownership.

use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::capture_bridge::MacCapturePlatform;

const GRANT_LIFETIME: Duration = Duration::from_mins(15);
const LOCK_MONITOR_TICK: Duration = Duration::from_secs(1);
const MAX_PNG_BYTES: usize = 6 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapturePhase {
    Off,
    Arming,
    Armed,
    Capturing,
    Ready,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapturePermission {
    Authorized,
    NotDeterminedOrDenied,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureDisplay {
    pub(crate) id: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) label: String,
}

pub(crate) struct CapturedPng {
    pub(crate) bytes: Vec<u8>,
    pub(crate) width: u32,
    pub(crate) height: u32,
}

impl Drop for CapturedPng {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

pub(crate) trait CapturePlatform: Send + Sync {
    fn preflight(&self) -> Result<bool, String>;
    fn request(&self) -> Result<bool, String>;
    fn main_display(&self) -> Result<CaptureDisplay, String>;
    fn capture_display(&self, display: &CaptureDisplay) -> Result<CapturedPng, String>;
    fn screen_locked(&self) -> Result<bool, String>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureView {
    pub(crate) phase: CapturePhase,
    pub(crate) permission: CapturePermission,
    pub(crate) detail: String,
    pub(crate) last_refusal: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) display: Option<CaptureDisplay>,
    pub(crate) armed_at: Option<u64>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) stop_visible: bool,
    pub(crate) frame_data_url: Option<String>,
    pub(crate) frame_width: Option<u32>,
    pub(crate) frame_height: Option<u32>,
    pub(crate) frame_sha256: Option<String>,
    pub(crate) frame_byte_count: Option<usize>,
}

pub(crate) struct CaptureAttachment {
    png: Vec<u8>,
    pub(crate) display_id: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) sha256: String,
}

impl CaptureAttachment {
    pub(crate) fn png(&self) -> &[u8] {
        &self.png
    }
}

impl Debug for CaptureAttachment {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureAttachment")
            .field("png", &format_args!("[redacted; {} bytes]", self.png.len()))
            .field("display_id", &self.display_id)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl Drop for CaptureAttachment {
    fn drop(&mut self) {
        self.png.fill(0);
    }
}

struct CaptureGrant {
    project_id: String,
    run_id: Option<String>,
    display: CaptureDisplay,
    armed_at_epoch: u64,
    expires_at_epoch: u64,
    expires_at: Instant,
}

struct CaptureFrame {
    png: Vec<u8>,
    width: u32,
    height: u32,
    sha256: String,
    display_id: u32,
}

impl Drop for CaptureFrame {
    fn drop(&mut self) {
        self.png.fill(0);
    }
}

struct CaptureInner {
    phase: CapturePhase,
    permission: CapturePermission,
    detail: String,
    last_refusal: Option<String>,
    grant: Option<CaptureGrant>,
    frame: Option<CaptureFrame>,
    generation: u64,
}

impl Default for CaptureInner {
    fn default() -> Self {
        Self {
            phase: CapturePhase::Off,
            permission: CapturePermission::NotDeterminedOrDenied,
            detail:
                "Capture is Off. Arm it explicitly to request macOS Screen Recording permission."
                    .into(),
            last_refusal: None,
            grant: None,
            frame: None,
            generation: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CaptureManager {
    inner: Arc<Mutex<CaptureInner>>,
    platform: Arc<dyn CapturePlatform>,
}

impl CaptureManager {
    pub(crate) fn production() -> Self {
        Self::new(Arc::new(MacCapturePlatform))
    }

    fn new(platform: Arc<dyn CapturePlatform>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CaptureInner::default())),
            platform,
        }
    }

    pub(crate) fn status(&self) -> CaptureView {
        self.reconcile();
        self.inner.lock().map_or_else(
            |_| unavailable_view("Capture state lock is unavailable."),
            |inner| present(&inner),
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the permission request, lock check, display identity, generation revalidation, and grant commit form one fail-closed transaction"
    )]
    pub(crate) fn arm(&self, project_id: String) -> Result<CaptureView, String> {
        if project_id.trim().is_empty() {
            return self.refuse("Capture requires an exact active project identity.");
        }
        let generation = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
            if inner.grant.is_some() || inner.phase == CapturePhase::Arming {
                return Err("Stop the current Capture grant before arming another one.".into());
            }
            inner.generation = inner.generation.wrapping_add(1).max(1);
            inner.phase = CapturePhase::Arming;
            inner.detail = "Waiting for macOS Screen Recording permission…".into();
            inner.last_refusal = None;
            inner.frame = None;
            inner.generation
        };
        let locked = match self.platform.screen_locked() {
            Ok(locked) => locked,
            Err(error) => {
                return self.refuse(&format!(
                    "Capture lock-state validation failed closed during Arm: {error}"
                ));
            }
        };
        if locked {
            return self.refuse("Capture cannot be armed while the screen is locked.");
        }
        let preflight = match self.platform.preflight() {
            Ok(preflight) => preflight,
            Err(error) => {
                return self.refuse(&format!(
                    "Capture permission preflight failed closed: {error}"
                ));
            }
        };
        let authorized = if preflight {
            true
        } else {
            match self.platform.request() {
                Ok(authorized) => authorized,
                Err(error) => {
                    return self.refuse(&format!(
                        "Capture permission request failed closed: {error}"
                    ));
                }
            }
        };
        let verified = match self.platform.preflight() {
            Ok(verified) => verified,
            Err(error) => {
                return self.refuse(&format!(
                    "Capture permission verification failed closed: {error}"
                ));
            }
        };
        if !authorized || !verified {
            return self
                .refuse("macOS Screen Recording permission was not granted. Capture remains Off.");
        }
        let display = match self.platform.main_display() {
            Ok(display) => display,
            Err(error) => {
                return self.refuse(&format!("Capture display validation failed: {error}"));
            }
        };
        if let Err(error) = validate_display(&display) {
            return self.refuse(&error);
        }
        let now_epoch = unix_millis();
        let expires_epoch = now_epoch.saturating_add(duration_millis(GRANT_LIFETIME));
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
            if inner.generation != generation || inner.phase != CapturePhase::Arming {
                return Err(
                    "Capture Arm was superseded by Stop or a project/worktree switch.".into(),
                );
            }
            inner.phase = CapturePhase::Armed;
            inner.permission = CapturePermission::Authorized;
            inner.detail = format!(
                "Capture armed for {} · expires in 15 minutes or when its run ends.",
                display.label
            );
            inner.last_refusal = None;
            inner.frame = None;
            inner.grant = Some(CaptureGrant {
                project_id,
                run_id: None,
                display,
                armed_at_epoch: now_epoch,
                expires_at_epoch: expires_epoch,
                expires_at: Instant::now() + GRANT_LIFETIME,
            });
        }
        spawn_monitor(
            Arc::downgrade(&self.inner),
            Arc::downgrade(&self.platform),
            generation,
        );
        Ok(self.status())
    }

    pub(crate) fn capture_now(&self, project_id: &str) -> Result<CaptureView, String> {
        self.reconcile();
        let (display, generation) = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
            let grant = active_grant(&inner, project_id, None)?;
            let display = grant.display.clone();
            let generation = inner.generation;
            inner.phase = CapturePhase::Capturing;
            inner.detail = format!("Capturing one bounded still from {}…", display.label);
            (display, generation)
        };
        let captured = self.platform.capture_display(&display);
        match captured {
            Ok(mut captured) => {
                validate_captured(&captured)?;
                if self.platform.screen_locked()? || !self.platform.preflight()? {
                    return self.refuse(
                        "Capture permission or screen-lock state changed before the frame completed.",
                    );
                }
                let hash = sha256_hex(&captured.bytes);
                let mut inner = self
                    .inner
                    .lock()
                    .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
                if inner.generation != generation {
                    return Err("Capture completed after its grant was stopped or replaced.".into());
                }
                active_grant(&inner, project_id, None)?;
                inner.frame = Some(CaptureFrame {
                    png: std::mem::take(&mut captured.bytes),
                    width: captured.width,
                    height: captured.height,
                    sha256: hash,
                    display_id: display.id,
                });
                inner.phase = CapturePhase::Ready;
                inner.detail =
                    "Capture ready. It will be attached once to the next eligible Chat run.".into();
                inner.last_refusal = None;
                Ok(present(&inner))
            }
            Err(error) => self.refuse(&format!("Capture failed: {error}")),
        }
    }

    pub(crate) fn take_for_run(
        &self,
        project_id: &str,
        run_id: &str,
    ) -> Result<Option<CaptureAttachment>, String> {
        self.reconcile();
        if run_id.trim().is_empty() {
            return Err("Capture delivery requires an exact run identity.".into());
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
        let Some(grant) = inner.grant.as_mut() else {
            return Ok(None);
        };
        if grant.project_id != project_id {
            return Err("Capture grant belongs to another project.".into());
        }
        match &grant.run_id {
            Some(bound) if bound != run_id => {
                return Err("Capture grant is already bound to another run.".into());
            }
            None => grant.run_id = Some(run_id.to_owned()),
            Some(_) => {}
        }
        let Some(mut frame) = inner.frame.take() else {
            return Ok(None);
        };
        inner.phase = CapturePhase::Armed;
        inner.detail =
            "The transient still was attached to this run and removed from preview.".into();
        Ok(Some(CaptureAttachment {
            png: std::mem::take(&mut frame.png),
            display_id: frame.display_id,
            width: frame.width,
            height: frame.height,
            sha256: std::mem::take(&mut frame.sha256),
        }))
    }

    pub(crate) fn finish_run(&self, run_id: &str) {
        if let Ok(mut inner) = self.inner.lock()
            && inner
                .grant
                .as_ref()
                .and_then(|grant| grant.run_id.as_deref())
                == Some(run_id)
        {
            clear_grant(
                &mut inner,
                "Capture grant cleared because its bound run ended.",
            );
        }
    }

    pub(crate) fn project_switched(&self, project_id: Option<&str>) {
        if let Ok(mut inner) = self.inner.lock()
            && (inner.phase == CapturePhase::Arming
                || inner.grant.as_ref().is_some_and(|grant| {
                    project_id.is_none_or(|project| project != grant.project_id)
                }))
        {
            clear_grant(&mut inner, "Capture grant cleared on project switch.");
        }
    }

    pub(crate) fn stop(&self, detail: &str) -> Result<CaptureView, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Capture state lock is unavailable.".to_owned())?;
        clear_grant(&mut inner, detail);
        Ok(present(&inner))
    }

    fn reconcile(&self) {
        let should_check = self
            .inner
            .lock()
            .ok()
            .is_some_and(|inner| inner.grant.is_some());
        if !should_check {
            if let Ok(permission) = self.platform.preflight()
                && let Ok(mut inner) = self.inner.lock()
            {
                inner.permission = if permission {
                    CapturePermission::Authorized
                } else {
                    CapturePermission::NotDeterminedOrDenied
                };
            }
            return;
        }
        let locked = self.platform.screen_locked();
        let permission = self.platform.preflight();
        if let Ok(mut inner) = self.inner.lock() {
            let expired = inner
                .grant
                .as_ref()
                .is_some_and(|grant| Instant::now() >= grant.expires_at);
            match (expired, locked, permission) {
                (true, _, _) => clear_grant(&mut inner, "Capture grant expired after 15 minutes."),
                (_, Ok(true), _) => clear_grant(
                    &mut inner,
                    "Capture grant cleared because the screen locked.",
                ),
                (_, Err(error), _) => fail_armed(
                    &mut inner,
                    &format!("Capture lock-state validation failed closed: {error}"),
                ),
                (_, _, Ok(false)) => fail_armed(
                    &mut inner,
                    "macOS Screen Recording permission was revoked while Capture was armed.",
                ),
                (_, _, Err(error)) => fail_armed(
                    &mut inner,
                    &format!("Capture permission validation failed closed: {error}"),
                ),
                _ => {}
            }
        }
    }

    fn refuse<T>(&self, reason: &str) -> Result<T, String> {
        if let Ok(mut inner) = self.inner.lock() {
            inner.generation = inner.generation.wrapping_add(1).max(1);
            inner.phase = CapturePhase::Failed;
            reason.clone_into(&mut inner.detail);
            inner.last_refusal = Some(reason.to_owned());
            inner.grant = None;
            inner.frame = None;
        }
        Err(reason.to_owned())
    }

    #[cfg(test)]
    fn expire_for_test(&self) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(grant) = inner.grant.as_mut()
        {
            grant.expires_at = Instant::now();
        }
    }
}

fn active_grant<'a>(
    inner: &'a CaptureInner,
    project_id: &str,
    run_id: Option<&str>,
) -> Result<&'a CaptureGrant, String> {
    let grant = inner
        .grant
        .as_ref()
        .ok_or_else(|| "Capture is Off. Arm it explicitly before taking a still.".to_owned())?;
    if grant.project_id != project_id {
        return Err("Capture grant belongs to another project.".into());
    }
    if Instant::now() >= grant.expires_at {
        return Err("Capture grant expired before the action.".into());
    }
    if let (Some(expected), Some(bound)) = (run_id, grant.run_id.as_deref())
        && expected != bound
    {
        return Err("Capture grant is bound to another run.".into());
    }
    Ok(grant)
}

fn clear_grant(inner: &mut CaptureInner, detail: &str) {
    inner.generation = inner.generation.wrapping_add(1).max(1);
    inner.phase = CapturePhase::Off;
    detail.clone_into(&mut inner.detail);
    inner.last_refusal = None;
    inner.grant = None;
    inner.frame = None;
}

fn fail_armed(inner: &mut CaptureInner, reason: &str) {
    inner.generation = inner.generation.wrapping_add(1).max(1);
    inner.phase = CapturePhase::Failed;
    reason.clone_into(&mut inner.detail);
    inner.last_refusal = Some(reason.to_owned());
    inner.grant = None;
    inner.frame = None;
}

fn present(inner: &CaptureInner) -> CaptureView {
    let frame = inner.frame.as_ref();
    CaptureView {
        phase: inner.phase,
        permission: inner.permission,
        detail: inner.detail.clone(),
        last_refusal: inner.last_refusal.clone(),
        project_id: inner.grant.as_ref().map(|grant| grant.project_id.clone()),
        run_id: inner.grant.as_ref().and_then(|grant| grant.run_id.clone()),
        display: inner.grant.as_ref().map(|grant| grant.display.clone()),
        armed_at: inner.grant.as_ref().map(|grant| grant.armed_at_epoch),
        expires_at: inner.grant.as_ref().map(|grant| grant.expires_at_epoch),
        stop_visible: inner.grant.is_some(),
        frame_data_url: frame.map(|frame| {
            format!(
                "data:image/png;base64,{}",
                base64::engine::general_purpose::STANDARD.encode(&frame.png)
            )
        }),
        frame_width: frame.map(|frame| frame.width),
        frame_height: frame.map(|frame| frame.height),
        frame_sha256: frame.map(|frame| frame.sha256.clone()),
        frame_byte_count: frame.map(|frame| frame.png.len()),
    }
}

fn unavailable_view(detail: &str) -> CaptureView {
    CaptureView {
        phase: CapturePhase::Failed,
        permission: CapturePermission::Unavailable,
        detail: detail.into(),
        last_refusal: Some(detail.into()),
        project_id: None,
        run_id: None,
        display: None,
        armed_at: None,
        expires_at: None,
        stop_visible: false,
        frame_data_url: None,
        frame_width: None,
        frame_height: None,
        frame_sha256: None,
        frame_byte_count: None,
    }
}

fn validate_display(display: &CaptureDisplay) -> Result<(), String> {
    if display.id == 0
        || display.width == 0
        || display.height == 0
        || display.width > 16_384
        || display.height > 16_384
    {
        return Err("Capture refused invalid or oversized display geometry.".into());
    }
    Ok(())
}

fn validate_captured(frame: &CapturedPng) -> Result<(), String> {
    if frame.width == 0
        || frame.height == 0
        || frame.bytes.len() < 32
        || frame.bytes.len() > MAX_PNG_BYTES
        || !frame.bytes.starts_with(b"\x89PNG\r\n\x1a\n")
    {
        return Err("Capture returned an invalid, blank, or oversized PNG frame.".into());
    }
    Ok(())
}

fn spawn_monitor(
    inner: Weak<Mutex<CaptureInner>>,
    platform: Weak<dyn CapturePlatform>,
    generation: u64,
) {
    let _ = std::thread::Builder::new()
        .name("grok-capture-grant-monitor".into())
        .spawn(move || loop {
            std::thread::sleep(LOCK_MONITOR_TICK);
            let (Some(inner), Some(platform)) = (inner.upgrade(), platform.upgrade()) else {
                return;
            };
            let active = inner.lock().ok().is_some_and(|state| {
                state.generation == generation && state.grant.is_some()
            });
            if !active {
                return;
            }
            let locked = platform.screen_locked();
            let permission = platform.preflight();
            if let Ok(mut state) = inner.lock() {
                if state.generation != generation || state.grant.is_none() {
                    return;
                }
                if state
                    .grant
                    .as_ref()
                    .is_some_and(|grant| Instant::now() >= grant.expires_at)
                {
                    clear_grant(&mut state, "Capture grant expired after 15 minutes.");
                    return;
                }
                match (locked, permission) {
                    (Ok(true), _) => {
                        clear_grant(
                            &mut state,
                            "Capture grant cleared because the screen locked.",
                        );
                        return;
                    }
                    (Err(error), _) => {
                        fail_armed(&mut state, &format!(
                            "Capture lock-state validation failed closed: {error}"
                        ));
                        return;
                    }
                    (_, Ok(false)) => {
                        fail_armed(
                            &mut state,
                            "macOS Screen Recording permission was revoked while Capture was armed.",
                        );
                        return;
                    }
                    (_, Err(error)) => {
                        fail_armed(&mut state, &format!(
                            "Capture permission validation failed closed: {error}"
                        ));
                        return;
                    }
                    _ => {}
                }
            }
        });
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    struct FakePlatform {
        authorized: AtomicBool,
        request_grants: AtomicBool,
        locked: AtomicBool,
        captures: AtomicUsize,
        display_hook: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    }

    impl FakePlatform {
        fn allowed() -> Arc<Self> {
            Arc::new(Self {
                authorized: AtomicBool::new(true),
                request_grants: AtomicBool::new(true),
                locked: AtomicBool::new(false),
                captures: AtomicUsize::new(0),
                display_hook: Mutex::new(None),
            })
        }
    }

    impl CapturePlatform for FakePlatform {
        fn preflight(&self) -> Result<bool, String> {
            Ok(self.authorized.load(Ordering::Acquire))
        }

        fn request(&self) -> Result<bool, String> {
            let allowed = self.request_grants.load(Ordering::Acquire);
            self.authorized.store(allowed, Ordering::Release);
            Ok(allowed)
        }

        fn main_display(&self) -> Result<CaptureDisplay, String> {
            if let Some((entered, release)) = self.display_hook.lock().expect("hook").take() {
                entered.wait();
                release.wait();
            }
            Ok(CaptureDisplay {
                id: 7,
                width: 1280,
                height: 800,
                label: "Main display 7".into(),
            })
        }

        fn capture_display(&self, _display: &CaptureDisplay) -> Result<CapturedPng, String> {
            self.captures.fetch_add(1, Ordering::AcqRel);
            let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
            png.resize(64, 1);
            Ok(CapturedPng {
                bytes: png,
                width: 1024,
                height: 640,
            })
        }

        fn screen_locked(&self) -> Result<bool, String> {
            Ok(self.locked.load(Ordering::Acquire))
        }
    }

    #[test]
    fn permission_deny_is_red_refusal_and_unarmed_off_is_neutral() {
        let platform = FakePlatform::allowed();
        platform.authorized.store(false, Ordering::Release);
        platform.request_grants.store(false, Ordering::Release);
        let manager = CaptureManager::new(platform);
        assert_eq!(manager.status().phase, CapturePhase::Off);
        assert!(manager.status().last_refusal.is_none());
        assert!(manager.arm("project-a".into()).is_err());
        let failed = manager.status();
        assert_eq!(failed.phase, CapturePhase::Failed);
        assert!(failed.last_refusal.is_some());
        assert!(!failed.stop_visible);
    }

    #[test]
    fn frame_is_once_only_and_run_project_bound() {
        let platform = FakePlatform::allowed();
        let manager = CaptureManager::new(platform);
        manager.arm("project-a".into()).expect("arm");
        let ready = manager.capture_now("project-a").expect("capture");
        assert_eq!(
            ready.display.as_ref().map(|display| display.width),
            Some(1280)
        );
        assert_eq!(ready.frame_width, Some(1024));
        assert_eq!(ready.frame_height, Some(640));
        assert!(manager.take_for_run("project-b", "run-a").is_err());
        let frame = manager
            .take_for_run("project-a", "run-a")
            .expect("take")
            .expect("frame");
        assert_eq!(frame.width, 1024);
        assert_eq!(frame.height, 640);
        assert!(manager.take_for_run("project-a", "run-b").is_err());
        assert!(
            manager
                .take_for_run("project-a", "run-a")
                .expect("same run")
                .is_none()
        );
        manager.finish_run("run-a");
        assert_eq!(manager.status().phase, CapturePhase::Off);
    }

    #[test]
    fn lock_revoke_expiry_stop_and_project_switch_clear_fail_closed() {
        let platform = FakePlatform::allowed();
        let manager = CaptureManager::new(platform.clone());
        manager.arm("project-a".into()).expect("arm");
        platform.locked.store(true, Ordering::Release);
        assert_eq!(manager.status().phase, CapturePhase::Off);
        assert!(manager.status().last_refusal.is_none());

        platform.locked.store(false, Ordering::Release);
        manager.arm("project-a".into()).expect("rearm");
        platform.authorized.store(false, Ordering::Release);
        assert_eq!(manager.status().phase, CapturePhase::Failed);
        assert!(manager.status().last_refusal.is_some());

        platform.authorized.store(true, Ordering::Release);
        manager.arm("project-a".into()).expect("rearm expiry");
        manager.expire_for_test();
        assert_eq!(manager.status().phase, CapturePhase::Off);

        manager.arm("project-a".into()).expect("rearm switch");
        manager.project_switched(Some("project-b"));
        assert_eq!(manager.status().phase, CapturePhase::Off);

        manager.arm("project-b".into()).expect("rearm stop");
        manager.stop("Visible Stop selected.").expect("stop");
        assert_eq!(manager.status().phase, CapturePhase::Off);
    }

    #[test]
    fn project_switch_during_arm_prevents_old_project_grant_commit() {
        let platform = FakePlatform::allowed();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *platform.display_hook.lock().expect("set hook") =
            Some((Arc::clone(&entered), Arc::clone(&release)));
        let manager = CaptureManager::new(platform);
        let worker = manager.clone();
        let arm = std::thread::spawn(move || worker.arm("project-a".into()));
        entered.wait();
        manager.project_switched(Some("project-b"));
        release.wait();
        assert!(arm.join().expect("arm thread").is_err());
        let view = manager.status();
        assert_eq!(view.phase, CapturePhase::Off);
        assert_eq!(view.project_id, None);
        assert!(!view.stop_visible);
    }
}
