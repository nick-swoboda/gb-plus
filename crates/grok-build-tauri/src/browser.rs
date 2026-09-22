//! Project-bound Chrome `DevTools` Protocol service with an explicit grant.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::browser_assets::{BrowserAssetProgress, BrowserRuntimeManager, BrowserRuntimeView};
use crate::browser_pipe::BrowserLaunchMode;
use crate::child_environment::ChildEnvironmentProfile;

const BROWSER_IDLE_TIMEOUT: Duration = Duration::from_hours(1);
const IDLE_MONITOR_TICK: Duration = Duration::from_secs(15);
const CDP_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const CDP_LOAD_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_GRACE: Duration = Duration::from_secs(2);
const STOP_POLL: Duration = Duration::from_millis(25);
const MAX_CDP_REQUEST_BYTES: usize = 256 * 1024;
const MAX_CDP_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCREENSHOT_BASE64_BYTES: usize = 12 * 1024 * 1024;
const MAX_INSPECTION_BYTES: usize = 96 * 1024;
const MAX_URL_BYTES: usize = 4096;
const MAX_TYPE_BYTES: usize = 4096;
const MAX_TITLE_BYTES: usize = 1024;
const MAX_EVENT_QUEUE: usize = 64;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BrowserMode {
    InApp,
    Headed,
}

impl BrowserMode {
    fn launch_mode(self) -> BrowserLaunchMode {
        match self {
            Self::InApp => BrowserLaunchMode::InApp,
            Self::Headed => BrowserLaunchMode::Headed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BrowserPhase {
    Off,
    Starting,
    Armed,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BrowserView {
    pub(crate) runtime: BrowserRuntimeView,
    pub(crate) phase: BrowserPhase,
    pub(crate) mode: Option<BrowserMode>,
    pub(crate) project_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) armed_at: Option<u64>,
    pub(crate) idle_expires_at: Option<u64>,
    pub(crate) url: String,
    pub(crate) title: String,
    pub(crate) screenshot_data_url: Option<String>,
    pub(crate) interaction_token: Option<String>,
    pub(crate) user_control_active: bool,
    pub(crate) viewport_width: u32,
    pub(crate) viewport_height: u32,
    pub(crate) inspection: Option<String>,
    pub(crate) detail: String,
    pub(crate) last_refusal: Option<String>,
    pub(crate) stop_visible: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BrowserActionView {
    pub(crate) browser: BrowserView,
    pub(crate) result: String,
}

#[derive(Clone)]
pub(crate) struct BrowserManager {
    inner: Arc<Mutex<BrowserInner>>,
    runtime: BrowserRuntimeManager,
    profiles_root: PathBuf,
}

struct BrowserInner {
    phase: BrowserPhase,
    generation: u64,
    grant: Option<BrowserGrant>,
    session: Option<Arc<Mutex<BrowserSession>>>,
    process_control: Option<BrowserProcessControl>,
    url: String,
    title: String,
    screenshot_data_url: Option<String>,
    interaction_token: Option<String>,
    interaction_loader_id: Option<String>,
    user_control_active: bool,
    inspection: Option<String>,
    detail: String,
    last_refusal: Option<String>,
}

struct BrowserGrant {
    project_id: String,
    run_id: Option<String>,
    mode: BrowserMode,
    armed_at_unix_ms: u64,
    last_activity: Instant,
    idle_expires_unix_ms: u64,
}

impl BrowserGrant {
    fn idle_expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= BROWSER_IDLE_TIMEOUT
    }

    fn bind_action(&mut self, project_id: &str, run_id: Option<&str>) -> Result<(), &'static str> {
        if self.project_id != project_id {
            return Err("Browser grant belongs to a different project.");
        }
        if let Some(run_id) = run_id {
            match self.run_id.as_deref() {
                None => self.run_id = Some(run_id.to_owned()),
                Some(bound) if bound == run_id => {}
                Some(_) => {
                    return Err(
                        "Browser grant is already bound to another agent run; Stop and re-arm.",
                    );
                }
            }
        }
        Ok(())
    }

    fn renew(&mut self) {
        self.last_activity = Instant::now();
        self.idle_expires_unix_ms =
            unix_millis().saturating_add(duration_millis(BROWSER_IDLE_TIMEOUT));
    }
}

struct BrowserSession {
    wrapper: Child,
    writer: Option<ChildStdin>,
    receiver: Receiver<Result<Value, String>>,
    next_id: u64,
    page_session_id: String,
    target_id: String,
    pending_events: VecDeque<String>,
    stderr_tail: Arc<Mutex<String>>,
    process_control: BrowserProcessControl,
    inspection_epoch: u32,
    node_bindings: std::collections::HashMap<u64, BrowserNodeBinding>,
    reaped: bool,
}

#[derive(Clone)]
struct BrowserProcessControl {
    process_group: i32,
    stop_requested: Arc<AtomicBool>,
}

impl BrowserProcessControl {
    fn request_stop(&self) -> Result<(), String> {
        self.stop_requested.store(true, Ordering::Release);
        signal_group(Pid::from_raw(self.process_group), Signal::SIGTERM)
    }
}

#[derive(Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag records an independent AX-derived authorization predicate checked before a node effect"
)]
struct BrowserNodeBinding {
    backend_node_id: u64,
    loader_id: String,
    clickable: bool,
    editable: bool,
    disabled: bool,
    link_target_allowed: bool,
}

impl BrowserManager {
    pub(crate) fn new(state_root: &Path) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BrowserInner {
                phase: BrowserPhase::Off,
                generation: 0,
                grant: None,
                session: None,
                process_control: None,
                url: "about:blank".into(),
                title: String::new(),
                screenshot_data_url: None,
                interaction_token: None,
                interaction_loader_id: None,
                user_control_active: false,
                inspection: None,
                detail: "Browser is Off. Install the exact runtime, then arm it explicitly.".into(),
                last_refusal: None,
            })),
            runtime: BrowserRuntimeManager::new(state_root),
            profiles_root: state_root.join("browser-profiles"),
        }
    }

    pub(crate) fn status(&self) -> BrowserView {
        let expired = self.expire_if_needed("Browser grant reached its 60-minute idle timeout.");
        if let Some((generation, session, control)) = expired {
            let _ = control.request_stop();
            let result = session
                .lock()
                .map_err(|_| "Browser session lock failed during status expiry.".to_owned())
                .and_then(|mut session| session.stop());
            self.finish_expired_stop(generation, result);
        }
        match self.inner.lock() {
            Ok(inner) => self.view_locked(&inner),
            Err(_) => BrowserView {
                runtime: self.runtime.status(),
                phase: BrowserPhase::Failed,
                mode: None,
                project_id: None,
                run_id: None,
                armed_at: None,
                idle_expires_at: None,
                url: "about:blank".into(),
                title: String::new(),
                screenshot_data_url: None,
                interaction_token: None,
                user_control_active: false,
                viewport_width: 1280,
                viewport_height: 800,
                inspection: None,
                detail: "Browser state is unavailable because its lock was poisoned.".into(),
                last_refusal: Some("Browser state lock failed.".into()),
                stop_visible: false,
            },
        }
    }

    pub(crate) fn install_runtime<F>(&self, progress: F) -> Result<BrowserView, String>
    where
        F: FnMut(BrowserAssetProgress),
    {
        if self
            .inner
            .lock()
            .map_err(|_| "Browser state lock is unavailable.".to_owned())?
            .session
            .is_some()
        {
            return Err("Stop Browser before repairing or installing its runtime.".into());
        }
        self.runtime.install(progress)?;
        Ok(self.status())
    }

    pub(crate) fn arm(&self, project_id: String, mode: BrowserMode) -> Result<BrowserView, String> {
        validate_identity(&project_id, "project")?;
        let generation = {
            let mut inner = self.lock()?;
            if inner.session.is_some()
                || matches!(inner.phase, BrowserPhase::Starting | BrowserPhase::Stopping)
            {
                return Err("Stop the current Browser context before arming another one.".into());
            }
            inner.generation = inner.generation.wrapping_add(1).max(1);
            inner.phase = BrowserPhase::Starting;
            inner.detail = "Verifying Chrome and establishing the private CDP pipe…".into();
            inner.last_refusal = None;
            inner.generation
        };
        let executable = match self.runtime.verified_executable() {
            Ok(path) => path,
            Err(error) => return self.fail(error),
        };
        let profile = match self.profile_for_project(&project_id) {
            Ok(path) => path,
            Err(error) => return self.fail(error),
        };
        let mut session = match BrowserSession::launch(&executable, &profile, mode.launch_mode()) {
            Ok(session) => session,
            Err(error) => return self.fail(error),
        };
        let snapshot = match session.refresh_page_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = session.stop();
                return self.fail(error);
            }
        };
        let process_control = session.process_control.clone();
        let session = Arc::new(Mutex::new(session));
        let now = unix_millis();
        {
            let mut inner = self.lock()?;
            if inner.generation != generation || inner.phase != BrowserPhase::Starting {
                drop(inner);
                let _ = process_control.request_stop();
                if let Ok(mut session) = session.lock() {
                    let _ = session.stop();
                }
                return Err("Browser arm was superseded before CDP became ready.".into());
            }
            inner.phase = BrowserPhase::Armed;
            inner.grant = Some(BrowserGrant {
                project_id,
                run_id: None,
                mode,
                armed_at_unix_ms: now,
                last_activity: Instant::now(),
                idle_expires_unix_ms: now.saturating_add(duration_millis(BROWSER_IDLE_TIMEOUT)),
            });
            inner.session = Some(session);
            inner.process_control = Some(process_control);
            inner.url = snapshot.url;
            inner.title = snapshot.title;
            inner.screenshot_data_url = Some(snapshot.screenshot_data_url);
            inner.interaction_loader_id = Some(snapshot.loader_id.clone());
            inner.interaction_token = Some(interaction_token(
                generation,
                inner.grant.as_ref(),
                &snapshot.loader_id,
                inner.screenshot_data_url.as_deref().unwrap_or_default(),
                1280,
                800,
            ));
            inner.user_control_active = false;
            inner.inspection = Some(snapshot.inspection);
            inner.detail = if mode == BrowserMode::InApp {
                "Browser is On in the in-app CDP viewport. Stop is always available.".into()
            } else {
                "Browser is On in explicit headed mode for login/debug. Stop is always available."
                    .into()
            };
        }
        spawn_idle_monitor(Arc::downgrade(&self.inner), generation);
        Ok(self.status())
    }

    pub(crate) fn stop(&self, reason: &str) -> Result<BrowserView, String> {
        let (session, process_control) = {
            let mut inner = self.lock()?;
            inner.generation = inner.generation.wrapping_add(1).max(1);
            if inner.session.is_none() {
                inner.phase = BrowserPhase::Off;
                inner.grant = None;
                inner.interaction_token = None;
                inner.interaction_loader_id = None;
                inner.user_control_active = false;
                inner.process_control = None;
                inner.detail = "Browser is Off.".into();
                inner.last_refusal = None;
                return Ok(self.view_locked(&inner));
            }
            inner.phase = BrowserPhase::Stopping;
            inner.detail =
                bounded_detail(reason, "Stopping Browser and its complete process group…");
            (inner.session.take(), inner.process_control.take())
        };
        let process_control = process_control
            .ok_or_else(|| "Browser stop lost its independent process-group control.".to_owned())?;
        let signal_result = process_control.request_stop();
        let stop_result = match session {
            Some(session) => match session.lock() {
                Ok(mut session) => session.stop(),
                Err(_) => Err("Browser session lock failed after process-group Stop.".into()),
            },
            None => Err("Browser stop lost its active process handle.".into()),
        };
        let stop_result = signal_result.and(stop_result);
        let mut inner = self.lock()?;
        inner.grant = None;
        inner.screenshot_data_url = None;
        inner.interaction_token = None;
        inner.interaction_loader_id = None;
        inner.user_control_active = false;
        inner.inspection = None;
        match stop_result {
            Ok(()) => {
                inner.phase = BrowserPhase::Off;
                inner.detail = "Browser is Off. The controlled Chrome process group exited.".into();
                inner.last_refusal = None;
                Ok(self.view_locked(&inner))
            }
            Err(error) => {
                inner.phase = BrowserPhase::Failed;
                inner.detail.clone_from(&error);
                inner.last_refusal = Some(error.clone());
                Err(error)
            }
        }
    }

    pub(crate) fn stop_for_project_change(&self) -> Result<(), String> {
        let active =
            self.inner.lock().ok().is_some_and(|inner| {
                inner.session.is_some() || inner.phase == BrowserPhase::Starting
            });
        if active {
            self.stop("Project/workspace changed; Browser grant was cleared.")?;
        }
        Ok(())
    }

    pub(crate) fn navigate_user(
        &self,
        project_id: &str,
        url: &str,
    ) -> Result<BrowserActionView, String> {
        let url = validate_navigation_url(url)?;
        self.release_user_control(project_id)?;
        self.with_session(project_id, None, |session| {
            session.navigate(&url)?;
            session.refresh_page_snapshot()
        })
        .and_then(|(generation, snapshot)| {
            self.finish_action(generation, snapshot, format!("Navigated to {url}"))
        })
    }

    pub(crate) fn inspect_user(&self, project_id: &str) -> Result<BrowserActionView, String> {
        self.with_session(project_id, None, BrowserSession::refresh_page_snapshot)
            .and_then(|(generation, snapshot)| {
                self.finish_action(
                    generation,
                    snapshot,
                    "Refreshed bounded DOM/action state.".into(),
                )
            })
    }

    pub(crate) fn pointer_user(
        &self,
        project_id: &str,
        interaction_token: &str,
        x: f64,
        y: f64,
    ) -> Result<BrowserActionView, String> {
        validate_viewport_point(x, y)?;
        self.user_viewport_action(
            project_id,
            interaction_token,
            true,
            "Browser viewport focused.",
            |session| session.click_point(x, y),
        )
    }

    pub(crate) fn insert_text_user(
        &self,
        project_id: &str,
        interaction_token: &str,
        text: &str,
    ) -> Result<BrowserActionView, String> {
        validate_type_text(text)?;
        self.user_viewport_action(
            project_id,
            interaction_token,
            false,
            "Typed in Browser.",
            |session| session.insert_text(text),
        )
    }

    pub(crate) fn focused_key_user(
        &self,
        project_id: &str,
        interaction_token: &str,
        key: &str,
    ) -> Result<BrowserActionView, String> {
        let key = validate_key(key)?;
        self.user_viewport_action(
            project_id,
            interaction_token,
            false,
            &format!("Sent Browser key {key}."),
            |session| session.key(key),
        )
    }

    pub(crate) fn focused_scroll_user(
        &self,
        project_id: &str,
        interaction_token: &str,
        x: f64,
        y: f64,
        delta_y: i64,
    ) -> Result<BrowserActionView, String> {
        validate_viewport_point(x, y)?;
        let delta_y = delta_y.clamp(-2000, 2000);
        self.user_viewport_action(
            project_id,
            interaction_token,
            false,
            "Scrolled Browser.",
            |session| session.scroll_at(x, y, delta_y),
        )
    }

    pub(crate) fn release_user_control(&self, project_id: &str) -> Result<BrowserView, String> {
        validate_identity(project_id, "project")?;
        let mut inner = self.lock()?;
        if inner
            .grant
            .as_ref()
            .is_some_and(|grant| grant.project_id != project_id)
        {
            return Self::refuse_locked(
                &mut inner,
                "Browser user control belongs to a different project.",
            );
        }
        inner.user_control_active = false;
        inner.detail = if inner.phase == BrowserPhase::Armed {
            "Browser is ready.".into()
        } else {
            "Browser is Off.".into()
        };
        Ok(self.view_locked(&inner))
    }

    fn begin_user_control(
        &self,
        project_id: &str,
        interaction_token: &str,
    ) -> Result<String, String> {
        validate_identity(project_id, "project")?;
        let mut inner = self.lock()?;
        Self::verify_interaction_locked(&mut inner, project_id, interaction_token)?;
        if inner.grant.as_ref().map(|grant| grant.mode) != Some(BrowserMode::InApp) {
            return Self::refuse_locked(
                &mut inner,
                "The embedded viewport accepts direct input only in Start browser mode.",
            );
        }
        inner.user_control_active = true;
        inner
            .interaction_loader_id
            .clone()
            .ok_or_else(|| "Browser viewport input has no current page identity.".to_owned())
    }

    fn require_user_control(
        &self,
        project_id: &str,
        interaction_token: &str,
    ) -> Result<String, String> {
        validate_identity(project_id, "project")?;
        let mut inner = self.lock()?;
        Self::verify_interaction_locked(&mut inner, project_id, interaction_token)?;
        if !inner.user_control_active {
            return Self::refuse_locked(
                &mut inner,
                "Click the embedded Browser viewport before typing or scrolling.",
            );
        }
        inner
            .interaction_loader_id
            .clone()
            .ok_or_else(|| "Browser viewport input has no current page identity.".to_owned())
    }

    fn user_viewport_action(
        &self,
        project_id: &str,
        interaction_token: &str,
        begin: bool,
        result: &str,
        operation: impl FnOnce(&mut BrowserSession) -> Result<(), String>,
    ) -> Result<BrowserActionView, String> {
        let expected_loader = if begin {
            self.begin_user_control(project_id, interaction_token)?
        } else {
            self.require_user_control(project_id, interaction_token)?
        };
        let action = self.with_session(project_id, None, |session| {
            let current_loader = session.current_loader_id()?;
            validate_interaction_loader(&expected_loader, &current_loader)?;
            operation(session)?;
            session.refresh_page_snapshot()
        });
        match action {
            Ok((generation, snapshot)) => {
                self.finish_action(generation, snapshot, result.to_owned())
            }
            Err(error) => {
                if let Ok(mut inner) = self.inner.lock() {
                    inner.user_control_active = false;
                }
                Err(error)
            }
        }
    }

    fn verify_interaction_locked(
        inner: &mut BrowserInner,
        project_id: &str,
        interaction_token: &str,
    ) -> Result<(), String> {
        if inner.phase != BrowserPhase::Armed
            || inner.grant.as_ref().map(|grant| grant.project_id.as_str()) != Some(project_id)
        {
            return Self::refuse_locked(
                inner,
                "Browser viewport input refused because its project grant is not active.",
            );
        }
        if inner.interaction_token.as_deref() != Some(interaction_token) {
            return Self::refuse_locked(
                inner,
                "Browser viewport input refused a stale screenshot; the page was refreshed.",
            );
        }
        Ok(())
    }

    pub(crate) fn click_user(
        &self,
        project_id: &str,
        node_id: u64,
    ) -> Result<BrowserActionView, String> {
        self.with_session(project_id, None, |session| {
            session.click(node_id)?;
            session.refresh_page_snapshot()
        })
        .and_then(|(generation, snapshot)| {
            self.finish_action(
                generation,
                snapshot,
                format!("Clicked Browser node {node_id}."),
            )
        })
    }

    pub(crate) fn type_user(
        &self,
        project_id: &str,
        node_id: u64,
        text: &str,
    ) -> Result<BrowserActionView, String> {
        validate_type_text(text)?;
        self.with_session(project_id, None, |session| {
            session.type_text(node_id, text)?;
            session.refresh_page_snapshot()
        })
        .and_then(|(generation, snapshot)| {
            self.finish_action(
                generation,
                snapshot,
                format!("Typed into Browser node {node_id}."),
            )
        })
    }

    pub(crate) fn key_user(
        &self,
        project_id: &str,
        key: &str,
    ) -> Result<BrowserActionView, String> {
        let key = validate_key(key)?;
        self.with_session(project_id, None, |session| {
            session.key(key)?;
            session.refresh_page_snapshot()
        })
        .and_then(|(generation, snapshot)| {
            self.finish_action(generation, snapshot, format!("Sent Browser key {key}."))
        })
    }

    pub(crate) fn scroll_user(
        &self,
        project_id: &str,
        delta_y: i64,
    ) -> Result<BrowserActionView, String> {
        let delta_y = delta_y.clamp(-2000, 2000);
        self.with_session(project_id, None, |session| {
            session.scroll(delta_y)?;
            session.refresh_page_snapshot()
        })
        .and_then(|(generation, snapshot)| {
            self.finish_action(
                generation,
                snapshot,
                format!("Scrolled Browser by {delta_y}."),
            )
        })
    }

    pub(crate) fn agent_action(
        &self,
        project_id: &str,
        run_id: &str,
        action: BrowserAgentAction<'_>,
    ) -> Result<String, String> {
        validate_identity(run_id, "run")?;
        {
            let mut inner = self.lock()?;
            if inner.user_control_active {
                return Self::refuse_locked(
                    &mut inner,
                    "Agent Browser action refused while the user controls the in-app viewport; click outside it or press Escape.",
                );
            }
        }
        let (generation, snapshot) =
            self.with_session(project_id, Some(run_id), |session| match action {
                BrowserAgentAction::Navigate(url) => {
                    session.navigate(&validate_navigation_url(url)?)?;
                    session.refresh_page_snapshot()
                }
                BrowserAgentAction::Inspect | BrowserAgentAction::Screenshot => {
                    session.refresh_page_snapshot()
                }
                BrowserAgentAction::Click(node_id) => {
                    session.click(node_id)?;
                    session.refresh_page_snapshot()
                }
                BrowserAgentAction::Type { node_id, text } => {
                    validate_type_text(text)?;
                    session.type_text(node_id, text)?;
                    session.refresh_page_snapshot()
                }
                BrowserAgentAction::Key(key) => {
                    session.key(validate_key(key)?)?;
                    session.refresh_page_snapshot()
                }
                BrowserAgentAction::Scroll(delta_y) => {
                    session.scroll(delta_y.clamp(-2000, 2000))?;
                    session.refresh_page_snapshot()
                }
            })?;
        let model_url = model_safe_url(&snapshot.url);
        let result = match action {
            BrowserAgentAction::Screenshot => format!(
                "Browser screenshot refreshed for {}. Use the visible Browser viewport for pixels; bounded DOM state:\n{}",
                model_url, snapshot.inspection
            ),
            _ => format!(
                "Browser url={} title={}\n{}",
                model_url, snapshot.title, snapshot.inspection
            ),
        };
        self.finish_action(
            generation,
            snapshot,
            "Agent Browser action completed through the armed CDP context.".into(),
        )?;
        Ok(result)
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.stop("Application shutdown cleared Browser control.");
    }

    fn with_session<T>(
        &self,
        project_id: &str,
        run_id: Option<&str>,
        operation: impl FnOnce(&mut BrowserSession) -> Result<T, String>,
    ) -> Result<(u64, T), String> {
        validate_identity(project_id, "project")?;
        if let Some((generation, session, control)) =
            self.expire_if_needed("Browser grant reached its 60-minute idle timeout.")
        {
            let _ = control.request_stop();
            let stopped = session
                .lock()
                .map_err(|_| "Browser session lock failed during expiry.".to_owned())?
                .stop();
            self.finish_expired_stop(generation, stopped);
            return Err(
                "Browser grant expired after 60 idle minutes; arm it again explicitly.".into(),
            );
        }
        let (generation, session) = {
            let mut inner = self.lock()?;
            if inner.phase != BrowserPhase::Armed {
                return Self::refuse_locked(
                    &mut inner,
                    "Browser is Off; arm it explicitly before this action.",
                );
            }
            if run_id.is_some() && inner.user_control_active {
                return Self::refuse_locked(
                    &mut inner,
                    "Agent Browser action refused while the user controls the in-app viewport; click outside it or press Escape.",
                );
            }
            let grant_result = inner
                .grant
                .as_mut()
                .ok_or("Browser is Armed without a grant record; action refused.")
                .and_then(|grant| grant.bind_action(project_id, run_id));
            if let Err(reason) = grant_result {
                return Self::refuse_locked(&mut inner, reason);
            }
            if let Some(grant) = inner.grant.as_mut() {
                grant.renew();
            } else {
                return Self::refuse_locked(
                    &mut inner,
                    "Browser grant disappeared before action dispatch.",
                );
            }
            inner.last_refusal = None;
            (
                inner.generation,
                inner
                    .session
                    .clone()
                    .ok_or_else(|| "Browser grant has no live CDP session.".to_owned())?,
            )
        };
        let mut session_guard = session
            .lock()
            .map_err(|_| "Browser CDP session lock is unavailable.".to_owned())?;
        {
            let mut inner = self.lock()?;
            if inner.generation != generation
                || inner.phase != BrowserPhase::Armed
                || inner
                    .session
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(current, &session))
            {
                return Self::refuse_locked(
                    &mut inner,
                    "Browser action was superseded by Stop, expiry, or project switch before dispatch.",
                );
            }
        }
        let outcome = operation(&mut session_guard);
        let mut inner = self.lock()?;
        if inner.generation != generation || inner.phase != BrowserPhase::Armed {
            return Self::refuse_locked(
                &mut inner,
                "Browser action was interrupted by Stop, expiry, or project switch; success was not recorded.",
            );
        }
        match outcome {
            Ok(value) => Ok((generation, value)),
            Err(error) => {
                inner.last_refusal = Some(bounded_detail(&error, "Browser action failed."));
                Err(error)
            }
        }
    }

    fn finish_action(
        &self,
        generation: u64,
        snapshot: PageSnapshot,
        result: String,
    ) -> Result<BrowserActionView, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Browser state lock failed before action publication.".to_owned())?;
        if inner.generation != generation || inner.phase != BrowserPhase::Armed {
            return Self::refuse_locked(
                &mut inner,
                "Browser action was superseded before publication; success was not recorded.",
            );
        }
        inner.url = snapshot.url;
        inner.title = snapshot.title;
        inner.screenshot_data_url = Some(snapshot.screenshot_data_url);
        inner.interaction_loader_id = Some(snapshot.loader_id.clone());
        inner.interaction_token = Some(interaction_token(
            generation,
            inner.grant.as_ref(),
            &snapshot.loader_id,
            inner.screenshot_data_url.as_deref().unwrap_or_default(),
            1280,
            800,
        ));
        inner.inspection = Some(snapshot.inspection);
        inner.detail.clone_from(&result);
        inner.last_refusal = None;
        Ok(BrowserActionView {
            browser: self.view_locked(&inner),
            result,
        })
    }

    fn profile_for_project(&self, project_id: &str) -> Result<PathBuf, String> {
        ensure_private_directory(&self.profiles_root)?;
        let identity = sha256_hex(project_id.as_bytes());
        let profile = self.profiles_root.join(identity);
        ensure_private_directory(&profile)?;
        fs::canonicalize(&profile)
            .map_err(|error| format!("Cannot canonicalize Browser profile: {error}"))
    }

    fn view_locked(&self, inner: &BrowserInner) -> BrowserView {
        let grant = inner.grant.as_ref();
        BrowserView {
            runtime: self.runtime.status(),
            phase: inner.phase,
            mode: grant.map(|grant| grant.mode),
            project_id: grant.map(|grant| grant.project_id.clone()),
            run_id: grant.and_then(|grant| grant.run_id.clone()),
            armed_at: grant.map(|grant| grant.armed_at_unix_ms),
            idle_expires_at: grant.map(|grant| grant.idle_expires_unix_ms),
            url: inner.url.clone(),
            title: inner.title.clone(),
            screenshot_data_url: inner.screenshot_data_url.clone(),
            interaction_token: inner.interaction_token.clone(),
            user_control_active: inner.user_control_active,
            viewport_width: 1280,
            viewport_height: 800,
            inspection: inner.inspection.clone(),
            detail: inner.detail.clone(),
            last_refusal: inner.last_refusal.clone(),
            stop_visible: inner.session.is_some(),
        }
    }

    fn expire_if_needed(
        &self,
        detail: &str,
    ) -> Option<(u64, Arc<Mutex<BrowserSession>>, BrowserProcessControl)> {
        let mut inner = self.inner.lock().ok()?;
        let expired = inner
            .grant
            .as_ref()
            .is_some_and(|grant| grant.idle_expired_at(Instant::now()));
        if !expired {
            return None;
        }
        inner.generation = inner.generation.wrapping_add(1).max(1);
        let generation = inner.generation;
        inner.phase = BrowserPhase::Stopping;
        inner.grant = None;
        inner.screenshot_data_url = None;
        inner.interaction_token = None;
        inner.interaction_loader_id = None;
        inner.user_control_active = false;
        inner.inspection = None;
        inner.detail = detail.into();
        inner.last_refusal = None;
        let session = inner.session.take()?;
        let control = inner.process_control.take()?;
        Some((generation, session, control))
    }

    fn finish_expired_stop(&self, generation: u64, result: Result<(), String>) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.generation != generation || inner.phase != BrowserPhase::Stopping {
            return;
        }
        match result {
            Ok(()) => {
                inner.phase = BrowserPhase::Off;
                inner.detail =
                    "Browser grant expired after 60 idle minutes and Chrome exited.".into();
                inner.last_refusal = None;
            }
            Err(error) => {
                inner.phase = BrowserPhase::Failed;
                inner.detail.clone_from(&error);
                inner.last_refusal = Some(error);
            }
        }
    }

    fn refuse_locked<T>(inner: &mut BrowserInner, reason: &str) -> Result<T, String> {
        let reason = bounded_detail(reason, "Browser action was refused.");
        inner.last_refusal = Some(reason.clone());
        Err(reason)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, BrowserInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "Browser state lock is unavailable.".to_owned())
    }

    fn fail<T>(&self, error: String) -> Result<T, String> {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = BrowserPhase::Failed;
            inner.grant = None;
            inner.session = None;
            inner.process_control = None;
            inner.screenshot_data_url = None;
            inner.interaction_token = None;
            inner.interaction_loader_id = None;
            inner.user_control_active = false;
            inner.inspection = None;
            inner.detail.clone_from(&error);
            inner.last_refusal = Some(error.clone());
        }
        Err(error)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum BrowserAgentAction<'a> {
    Navigate(&'a str),
    Inspect,
    Click(u64),
    Type { node_id: u64, text: &'a str },
    Key(&'a str),
    Scroll(i64),
    Screenshot,
}

struct PageSnapshot {
    url: String,
    title: String,
    screenshot_data_url: String,
    inspection: String,
    loader_id: String,
}

impl BrowserSession {
    #[allow(
        clippy::too_many_lines,
        reason = "the fail-closed launch transaction keeps pipe setup, process identity, CDP readiness, and cleanup in one auditable boundary"
    )]
    fn launch(executable: &Path, profile: &Path, mode: BrowserLaunchMode) -> Result<Self, String> {
        let launcher = std::env::current_exe()
            .map_err(|error| format!("Cannot resolve the signed Browser launcher: {error}"))?;
        let mut command = Command::new(launcher);
        command
            .arg("--chrome-pipe-launcher")
            .arg(executable)
            .arg(profile)
            .arg(mode.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        ChildEnvironmentProfile::Browser.apply(&mut command);
        let mut wrapper = command
            .spawn()
            .map_err(|error| format!("Cannot start the signed Browser launcher: {error}"))?;
        let Some(writer) = wrapper.stdin.take() else {
            return Err(abort_startup(
                &mut wrapper,
                "Browser launcher did not expose its private CDP input.",
            ));
        };
        let Some(stdout) = wrapper.stdout.take() else {
            return Err(abort_startup(
                &mut wrapper,
                "Browser launcher did not expose its private CDP output.",
            ));
        };
        let Some(stderr) = wrapper.stderr.take() else {
            return Err(abort_startup(
                &mut wrapper,
                "Browser launcher did not expose its readiness marker.",
            ));
        };
        let stderr_tail = Arc::new(Mutex::new(String::new()));
        let stderr_capture = Arc::clone(&stderr_tail);
        if let Err(error) = std::thread::Builder::new()
            .name("grok-browser-stderr-reader".into())
            .spawn(move || capture_stderr(stderr, &stderr_capture))
        {
            return Err(abort_startup(
                &mut wrapper,
                &format!("Cannot start the bounded Browser error reader: {error}"),
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(MAX_EVENT_QUEUE);
        if let Err(error) = std::thread::Builder::new()
            .name("grok-browser-cdp-reader".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                loop {
                    let message = read_cdp_frame(&mut reader).and_then(|bytes| {
                        serde_json::from_slice::<Value>(&bytes)
                            .map_err(|error| format!("Chrome CDP returned invalid JSON: {error}"))
                    });
                    match message {
                        Ok(value) => {
                            #[cfg(debug_assertions)]
                            {
                                let method = value
                                    .get("method")
                                    .and_then(Value::as_str)
                                    .unwrap_or("response");
                                eprintln!(
                                    "BROWSER_CDP_RX id={} method={method}",
                                    value.get("id").and_then(Value::as_u64).map_or(0, |id| id),
                                );
                                if method == "Network.loadingFailed" {
                                    eprintln!(
                                        "BROWSER_CDP_NETWORK_FAILED error={} blocked={}",
                                        value
                                            .pointer("/params/errorText")
                                            .and_then(Value::as_str)
                                            .unwrap_or("unknown"),
                                        value
                                            .pointer("/params/blockedReason")
                                            .and_then(Value::as_str)
                                            .unwrap_or("none")
                                    );
                                }
                            }
                            if value.get("id").is_some() {
                                if sender.send(Ok(value)).is_err() {
                                    break;
                                }
                            } else if value
                                .get("method")
                                .and_then(Value::as_str)
                                .is_some_and(relevant_event)
                            {
                                let _ = sender.try_send(Ok(value));
                            }
                        }
                        Err(error) => {
                            let _ = sender.send(Err(error));
                            break;
                        }
                    }
                }
            })
        {
            return Err(abort_startup(
                &mut wrapper,
                &format!("Cannot start the bounded CDP reader: {error}"),
            ));
        }
        let process_group = i32::try_from(wrapper.id()).map_err(|_| {
            abort_startup(
                &mut wrapper,
                "Browser launcher PID exceeds process-group API.",
            )
        })?;
        let mut session = Self {
            wrapper,
            writer: Some(writer),
            receiver,
            next_id: 1,
            page_session_id: String::new(),
            target_id: String::new(),
            pending_events: VecDeque::new(),
            stderr_tail,
            process_control: BrowserProcessControl {
                process_group,
                stop_requested: Arc::new(AtomicBool::new(false)),
            },
            inspection_epoch: 0,
            node_bindings: std::collections::HashMap::new(),
            reaped: false,
        };
        if let Err(error) = session.initialize(mode) {
            std::thread::sleep(Duration::from_millis(50));
            let startup_error = session.with_stderr(error);
            return match session.stop() {
                Ok(()) => Err(startup_error),
                Err(stop_error) => Err(format!(
                    "{startup_error} Browser startup cleanup also failed: {stop_error}"
                )),
            };
        }
        Ok(session)
    }

    fn initialize(&mut self, mode: BrowserLaunchMode) -> Result<(), String> {
        let version = self.call_browser("Browser.getVersion", json!({}))?;
        let product = version
            .get("product")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !product.contains("152.0.7977.54") {
            return Err(format!(
                "CDP connected to an unexpected Browser version `{}`.",
                bounded_detail(product, "unknown")
            ));
        }
        self.call_browser(
            "Browser.setDownloadBehavior",
            json!({"behavior": "deny", "eventsEnabled": false}),
        )?;
        let targets = self.call_browser("Target.getTargets", json!({}))?;
        let target_id = targets
            .get("targetInfos")
            .and_then(Value::as_array)
            .and_then(|items| {
                items.iter().find_map(|item| {
                    (item.get("type").and_then(Value::as_str) == Some("page"))
                        .then(|| item.get("targetId").and_then(Value::as_str))
                        .flatten()
                })
            })
            .map(str::to_owned)
            .or_else(|| {
                self.call_browser("Target.createTarget", json!({"url": "about:blank"}))
                    .ok()
                    .and_then(|result| {
                        result
                            .get("targetId")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
            })
            .ok_or_else(|| "Chrome CDP exposed no page target.".to_owned())?;
        let attached = self.call_browser(
            "Target.attachToTarget",
            json!({"targetId": target_id, "flatten": true}),
        )?;
        attached
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or_else(|| "Chrome CDP did not return a bounded page session.".to_owned())?
            .clone_into(&mut self.page_session_id);
        self.target_id = target_id;
        self.call_page("Page.enable", json!({}))?;
        self.call_page("DOM.enable", json!({}))?;
        self.call_page("Accessibility.enable", json!({}))?;
        self.call_page(
            "Network.enable",
            json!({
                "maxTotalBufferSize": 1_048_576,
                "maxResourceBufferSize": 262_144,
                "maxPostDataSize": 65_536
            }),
        )?;
        if mode == BrowserLaunchMode::InApp {
            self.call_page(
                "Emulation.setDeviceMetricsOverride",
                json!({
                    "width": 1280,
                    "height": 800,
                    "deviceScaleFactor": 1,
                    "mobile": false,
                    "screenWidth": 1280,
                    "screenHeight": 800
                }),
            )?;
        }
        Ok(())
    }

    fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.pending_events
            .retain(|event| event != "Page.loadEventFired");
        let result = self.call_page("Page.navigate", json!({"url": url}))?;
        if let Some(error) = result.get("errorText").and_then(Value::as_str) {
            return Err(format!(
                "Browser navigation failed: {}",
                bounded_detail(error, "unknown navigation error")
            ));
        }
        self.wait_for_event("Page.loadEventFired", CDP_LOAD_TIMEOUT)?;
        self.wait_for_document_ready(url, CDP_LOAD_TIMEOUT)
    }

    fn click(&mut self, node_id: u64) -> Result<(), String> {
        let binding = self.checked_node_binding(node_id)?;
        if !binding.clickable || binding.disabled || !binding.link_target_allowed {
            return Err(
                "Browser click refused a disabled, non-clickable, or unsafe-link node.".into(),
            );
        }
        let model = self.call_page(
            "DOM.getBoxModel",
            json!({"backendNodeId": binding.backend_node_id}),
        )?;
        let quad = model
            .pointer("/model/border")
            .or_else(|| model.pointer("/model/content"))
            .and_then(Value::as_array)
            .filter(|quad| quad.len() == 8)
            .ok_or_else(|| "Browser click refused a stale node with no box model.".to_owned())?;
        let numbers = quad
            .iter()
            .map(|value| value.as_f64().filter(|value| value.is_finite()))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "Browser click received an invalid node geometry.".to_owned())?;
        let x = (numbers[0] + numbers[2] + numbers[4] + numbers[6]) / 4.0;
        let y = (numbers[1] + numbers[3] + numbers[5] + numbers[7]) / 4.0;
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({"type":"mousePressed","x":x,"y":y,"button":"left","clickCount":1}),
        )?;
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({"type":"mouseReleased","x":x,"y":y,"button":"left","clickCount":1}),
        )?;
        std::thread::sleep(Duration::from_millis(150));
        Ok(())
    }

    fn type_text(&mut self, node_id: u64, text: &str) -> Result<(), String> {
        let binding = self.checked_node_binding(node_id)?;
        if !binding.editable || binding.disabled {
            return Err("Browser type refused a disabled or non-editable node.".into());
        }
        self.call_page(
            "DOM.focus",
            json!({"backendNodeId": binding.backend_node_id}),
        )?;
        self.call_page("Input.insertText", json!({"text": text}))?;
        Ok(())
    }

    fn checked_node_binding(&mut self, node_id: u64) -> Result<BrowserNodeBinding, String> {
        if node_id == 0 {
            return Err("Browser action refused an invalid node identity.".into());
        }
        let binding =
            self.node_bindings.get(&node_id).cloned().ok_or_else(|| {
                "Browser action refused a missing or stale node identity.".to_owned()
            })?;
        if self.current_loader_id()? != binding.loader_id {
            self.node_bindings.clear();
            return Err("Browser action refused a node from an earlier document.".into());
        }
        Ok(binding)
    }

    fn key(&mut self, key: &str) -> Result<(), String> {
        self.call_page(
            "Input.dispatchKeyEvent",
            json!({"type": "keyDown", "key": key}),
        )?;
        self.call_page(
            "Input.dispatchKeyEvent",
            json!({"type": "keyUp", "key": key}),
        )?;
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    fn scroll(&mut self, delta_y: i64) -> Result<(), String> {
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseWheel",
                "x": 640,
                "y": 400,
                "deltaX": 0,
                "deltaY": delta_y
            }),
        )?;
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    fn refresh_page_snapshot(&mut self) -> Result<PageSnapshot, String> {
        let inspection = self.inspect()?;
        let loader_id = self.current_loader_id()?;
        let (url, title) = self.page_identity()?;
        let screenshot = self.call_page(
            "Page.captureScreenshot",
            json!({
                "format": "png",
                "fromSurface": true,
                "captureBeyondViewport": false,
                "optimizeForSpeed": true
            }),
        )?;
        let data = screenshot
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| {
                !data.is_empty()
                    && data.len() <= MAX_SCREENSHOT_BASE64_BYTES
                    && data.starts_with("iVBORw0KGgo")
                    && data.bytes().all(is_base64_byte)
            })
            .ok_or_else(|| "Chrome returned an invalid or oversized PNG screenshot.".to_owned())?;
        Ok(PageSnapshot {
            url,
            title,
            screenshot_data_url: format!("data:image/png;base64,{data}"),
            inspection,
            loader_id,
        })
    }

    fn click_point(&mut self, x: f64, y: f64) -> Result<(), String> {
        validate_viewport_point(x, y)?;
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({"type":"mousePressed","x":x,"y":y,"button":"left","clickCount":1}),
        )?;
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({"type":"mouseReleased","x":x,"y":y,"button":"left","clickCount":1}),
        )?;
        std::thread::sleep(Duration::from_millis(100));
        Ok(())
    }

    fn insert_text(&mut self, text: &str) -> Result<(), String> {
        validate_type_text(text)?;
        self.call_page("Input.insertText", json!({"text": text}))?;
        Ok(())
    }

    fn scroll_at(&mut self, x: f64, y: f64, delta_y: i64) -> Result<(), String> {
        validate_viewport_point(x, y)?;
        self.call_page(
            "Input.dispatchMouseEvent",
            json!({
                "type": "mouseWheel",
                "x": x,
                "y": y,
                "deltaX": 0,
                "deltaY": delta_y.clamp(-2000, 2000)
            }),
        )?;
        std::thread::sleep(Duration::from_millis(80));
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "AX filtering and app-minted node authorization are intentionally co-located so no sibling path can publish an unchecked binding"
    )]
    fn inspect(&mut self) -> Result<String, String> {
        let loader_id = self.current_loader_id()?;
        let tree = self.call_page("Accessibility.getFullAXTree", json!({"depth": 32}))?;
        let nodes = tree
            .get("nodes")
            .and_then(Value::as_array)
            .filter(|nodes| nodes.len() <= 4_096)
            .ok_or_else(|| "Browser accessibility tree was absent or oversized.".to_owned())?;
        self.inspection_epoch = self.inspection_epoch.wrapping_add(1).max(1);
        self.node_bindings.clear();
        let epoch = self.inspection_epoch;
        let (url, title) = self.page_identity()?;
        let mut body_text = String::new();
        let mut output_nodes = Vec::new();
        let mut seen_backend_nodes = std::collections::HashSet::new();
        for node in nodes {
            if node.get("ignored").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let role = node
                .pointer("/role/value")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = bounded_string(
                node.pointer("/name/value")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .trim(),
                240,
            );
            if !name.is_empty() && body_text.len() < 12_000 {
                if !body_text.is_empty() {
                    body_text.push(' ');
                }
                let remaining = 12_000_usize.saturating_sub(body_text.len());
                body_text.push_str(&bounded_string(&name, remaining));
            }
            let clickable = matches!(
                role,
                "button"
                    | "link"
                    | "checkbox"
                    | "radio"
                    | "switch"
                    | "menuitem"
                    | "tab"
                    | "option"
                    | "slider"
                    | "textbox"
                    | "searchbox"
                    | "combobox"
            );
            let editable = matches!(role, "textbox" | "searchbox" | "combobox");
            if !clickable || output_nodes.len() >= 200 {
                continue;
            }
            let Some(backend_node_id) = node.get("backendDOMNodeId").and_then(Value::as_u64) else {
                continue;
            };
            if backend_node_id == 0 || !seen_backend_nodes.insert(backend_node_id) {
                continue;
            }
            let disabled = ax_boolean_property(node, "disabled").unwrap_or(false)
                || ax_boolean_property(node, "readonly").unwrap_or(false);
            let href = ax_string_property(node, "url").unwrap_or_default();
            let link_target_allowed = role != "link"
                || href.is_empty()
                || href.starts_with("http://")
                || href.starts_with("https://");
            let ordinal = u64::try_from(output_nodes.len() + 1)
                .map_err(|_| "Browser node ordinal overflowed.".to_owned())?;
            let node_id = (u64::from(epoch) << 32) | ordinal;
            self.node_bindings.insert(
                node_id,
                BrowserNodeBinding {
                    backend_node_id,
                    loader_id: loader_id.clone(),
                    clickable,
                    editable,
                    disabled,
                    link_target_allowed,
                },
            );
            output_nodes.push(json!({
                "id": node_id,
                "role": bounded_string(role, 40),
                "name": name,
                "href": model_safe_url(&href),
                "disabled": disabled,
                "editable": editable,
            }));
        }
        let value = json!({
            "url": model_safe_url(&url),
            "title": title,
            "bodyText": body_text,
            "nodes": output_nodes,
            "ready": true,
            "documentEpoch": epoch,
        });
        let encoded = serde_json::to_string_pretty(&value)
            .map_err(|error| format!("Cannot encode bounded Browser inspection: {error}"))?;
        if encoded.len() > MAX_INSPECTION_BYTES {
            return Err("Browser inspection exceeded its bounded result size.".into());
        }
        Ok(encoded)
    }

    fn page_identity(&mut self) -> Result<(String, String), String> {
        let target = self.call_browser(
            "Target.getTargetInfo",
            json!({"targetId": self.target_id.clone()}),
        )?;
        let info = target
            .get("targetInfo")
            .and_then(Value::as_object)
            .ok_or_else(|| "Browser target identity was unavailable.".to_owned())?;
        let url = info.get("url").and_then(Value::as_str).map_or_else(
            || "about:blank".into(),
            |value| bounded_string(value, MAX_URL_BYTES),
        );
        let title = info
            .get("title")
            .and_then(Value::as_str)
            .map(|value| bounded_string(value, MAX_TITLE_BYTES))
            .unwrap_or_default();
        Ok((url, title))
    }

    fn current_loader_id(&mut self) -> Result<String, String> {
        self.call_page("Page.getFrameTree", json!({}))?
            .pointer("/frameTree/frame/loaderId")
            .and_then(Value::as_str)
            .filter(|loader| !loader.is_empty() && loader.len() <= 512)
            .map(str::to_owned)
            .ok_or_else(|| "Browser document loader identity was unavailable.".to_owned())
    }

    fn call_browser(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.call(method, params, None)
    }

    fn call_page(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let session = self.page_session_id.clone();
        self.call(method, params, Some(&session))
    }

    fn call(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<Value, String> {
        if !valid_cdp_method(method) {
            return Err("Browser refused an unrecognized CDP method.".into());
        }
        if let Some(status) = self
            .wrapper
            .try_wait()
            .map_err(|error| format!("Cannot inspect Browser launcher status: {error}"))?
        {
            return Err(self.with_stderr(format!(
                "Browser process ended before the CDP action: {status}."
            )));
        }
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).unwrap_or(1);
        let mut request = json!({"id": id, "method": method});
        request["params"] = params;
        if let Some(session_id) = session_id {
            request["sessionId"] = Value::String(session_id.to_owned());
        }
        let mut bytes = serde_json::to_vec(&request)
            .map_err(|error| format!("Cannot encode Browser CDP request: {error}"))?;
        if bytes.len() > MAX_CDP_REQUEST_BYTES || bytes.contains(&0) {
            return Err("Browser CDP request exceeded its bound or contained a NUL byte.".into());
        }
        bytes.push(0);
        #[cfg(debug_assertions)]
        eprintln!("BROWSER_CDP_TX id={id} method={method}");
        self.writer
            .as_mut()
            .ok_or_else(|| "Browser CDP input is closed.".to_owned())?
            .write_all(&bytes)
            .and_then(|()| self.writer.as_mut().expect("writer checked").flush())
            .map_err(|error| format!("Browser CDP request write failed: {error}"))?;
        let deadline = Instant::now() + CDP_COMMAND_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!("Browser CDP method {method} timed out."));
            }
            let message = match self.receiver.recv_timeout(remaining) {
                Ok(message) => message?,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(self.with_stderr(format!("Browser CDP method {method} timed out.")));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(
                        self.with_stderr("Browser CDP output closed before a response.".into())
                    );
                }
            };
            if let Some(event) = message.get("method").and_then(Value::as_str) {
                if self.pending_events.len() == MAX_EVENT_QUEUE {
                    self.pending_events.pop_front();
                }
                self.pending_events.push_back(event.to_owned());
                continue;
            }
            let response_id = message.get("id").and_then(Value::as_u64);
            if response_id != Some(id) {
                return Err("Browser CDP returned an out-of-order response identity.".into());
            }
            if let Some(error) = message.get("error") {
                let detail = error.get("message").and_then(Value::as_str).map_or_else(
                    || "unknown CDP error".into(),
                    |value| bounded_detail(value, "CDP error"),
                );
                return Err(format!("Browser CDP {method} refused: {detail}"));
            }
            return message
                .get("result")
                .cloned()
                .ok_or_else(|| format!("Browser CDP {method} returned no result."));
        }
    }

    fn wait_for_event(&mut self, expected: &str, timeout: Duration) -> Result<(), String> {
        if let Some(position) = self
            .pending_events
            .iter()
            .position(|event| event == expected)
        {
            self.pending_events.remove(position);
            return Ok(());
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!("Browser timed out waiting for {expected}."));
            }
            let message =
                self.receiver
                    .recv_timeout(remaining)
                    .map_err(|error| match error {
                        RecvTimeoutError::Timeout => {
                            format!("Browser timed out waiting for {expected}.")
                        }
                        RecvTimeoutError::Disconnected => {
                            "Browser CDP closed while waiting for page load.".into()
                        }
                    })??;
            if message.get("method").and_then(Value::as_str) == Some(expected) {
                return Ok(());
            }
            if let Some(event) = message.get("method").and_then(Value::as_str) {
                if self.pending_events.len() == MAX_EVENT_QUEUE {
                    self.pending_events.pop_front();
                }
                self.pending_events.push_back(event.to_owned());
            }
        }
    }

    fn wait_for_document_ready(
        &mut self,
        requested_url: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let (current, _) = self.page_identity()?;
            let ready = !self.current_loader_id()?.is_empty();
            let left_initial_blank = requested_url == "about:blank" || current != "about:blank";
            if ready && left_initial_blank {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(
                    "Browser navigation event arrived before a usable document became ready."
                        .into(),
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        self.writer.take();
        self.process_control
            .stop_requested
            .store(true, Ordering::Release);
        let group = Pid::from_raw(self.process_control.process_group);
        signal_group(group, Signal::SIGTERM)?;
        if self.wait_for_process_group_exit(group, STOP_GRACE)? {
            self.reaped = true;
            return Ok(());
        }
        signal_group(group, Signal::SIGKILL)?;
        if self.wait_for_process_group_exit(group, STOP_GRACE)? {
            self.reaped = true;
            Ok(())
        } else {
            Err("Browser process group remained observable after SIGKILL; Stop was not reported as complete.".into())
        }
    }

    fn wait_for_process_group_exit(
        &mut self,
        group: Pid,
        timeout: Duration,
    ) -> Result<bool, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let leader_exited = self
                .wrapper
                .try_wait()
                .map_err(|error| format!("Cannot inspect Browser stop status: {error}"))?
                .is_some();
            let group_alive = process_group_alive(group)?;
            if leader_exited && !group_alive {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(STOP_POLL);
        }
    }

    fn with_stderr(&self, error: String) -> String {
        let tail = self
            .stderr_tail
            .lock()
            .ok()
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        if tail.is_empty() {
            error
        } else {
            format!(
                "{error} Chrome startup detail: {}",
                bounded_detail(&tail, "unavailable")
            )
        }
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        if !self.reaped {
            self.writer.take();
            let _ = killpg(
                Pid::from_raw(self.process_control.process_group),
                Signal::SIGKILL,
            );
            let _ = self.wrapper.kill();
            let _ = self.wrapper.wait();
            self.reaped = true;
        }
    }
}

fn abort_startup(wrapper: &mut Child, reason: &str) -> String {
    if let Ok(group) = i32::try_from(wrapper.id()) {
        let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
    }
    let _ = wrapper.kill();
    match wrapper.wait() {
        Ok(_) => reason.to_owned(),
        Err(error) => format!("{reason} Browser startup cleanup could not reap the child: {error}"),
    }
}

fn capture_stderr(mut stderr: impl Read, output: &Mutex<String>) {
    let mut buffer = [0_u8; 2048];
    loop {
        let Ok(count) = stderr.read(&mut buffer) else {
            return;
        };
        if count == 0 {
            return;
        }
        let chunk = String::from_utf8_lossy(&buffer[..count]);
        let sanitized = chunk
            .chars()
            .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
            .collect::<String>();
        let Ok(mut tail) = output.lock() else {
            return;
        };
        tail.push_str(&sanitized);
        if tail.len() > 8192 {
            let mut start = tail.len() - 8192;
            while !tail.is_char_boundary(start) {
                start += 1;
            }
            tail.drain(..start);
        }
    }
}

fn read_cdp_frame(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("Browser CDP read failed: {error}"))?;
        if available.is_empty() {
            return Err("Browser CDP output reached EOF.".into());
        }
        let delimiter = available.iter().position(|byte| *byte == 0);
        let count = delimiter.unwrap_or(available.len());
        if output.len().saturating_add(count) > MAX_CDP_MESSAGE_BYTES {
            return Err("Browser CDP message exceeded the fixed byte bound.".into());
        }
        output.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(delimiter.is_some()));
        if delimiter.is_some() {
            if output.is_empty() {
                return Err("Browser CDP returned an empty frame.".into());
            }
            return Ok(output);
        }
    }
}

fn relevant_event(method: &str) -> bool {
    matches!(
        method,
        "Page.loadEventFired"
            | "Page.frameNavigated"
            | "Inspector.detached"
            | "Target.detachedFromTarget"
            | "Target.targetCrashed"
            | "Network.loadingFailed"
    )
}

fn valid_cdp_method(method: &str) -> bool {
    matches!(
        method,
        "Browser.getVersion"
            | "Browser.setDownloadBehavior"
            | "Target.getTargets"
            | "Target.createTarget"
            | "Target.attachToTarget"
            | "Target.getTargetInfo"
            | "Page.enable"
            | "Page.getFrameTree"
            | "DOM.enable"
            | "DOM.getBoxModel"
            | "DOM.focus"
            | "Accessibility.enable"
            | "Accessibility.getFullAXTree"
            | "Network.enable"
            | "Emulation.setDeviceMetricsOverride"
            | "Page.navigate"
            | "Page.captureScreenshot"
            | "Input.insertText"
            | "Input.dispatchKeyEvent"
            | "Input.dispatchMouseEvent"
    )
}

fn signal_group(group: Pid, signal: Signal) -> Result<(), String> {
    match killpg(group, signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(error) => Err(format!(
            "Cannot send {signal:?} to the validated Browser process group: {error}"
        )),
    }
}

fn process_group_alive(group: Pid) -> Result<bool, String> {
    match killpg(group, None) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(error) => Err(format!("Cannot verify Browser process-group exit: {error}")),
    }
}

fn spawn_idle_monitor(inner: Weak<Mutex<BrowserInner>>, generation: u64) {
    let _ = std::thread::Builder::new()
        .name("grok-browser-idle-expiry".into())
        .spawn(move || {
            loop {
                std::thread::sleep(IDLE_MONITOR_TICK);
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let (stop_generation, session, control) = {
                    let Ok(mut state) = inner.lock() else {
                        return;
                    };
                    if state.generation != generation || state.phase != BrowserPhase::Armed {
                        return;
                    }
                    if state
                        .grant
                        .as_ref()
                        .is_none_or(|grant| !grant.idle_expired_at(Instant::now()))
                    {
                        continue;
                    }
                    state.generation = state.generation.wrapping_add(1).max(1);
                    let stop_generation = state.generation;
                    state.phase = BrowserPhase::Stopping;
                    state.grant = None;
                    state.screenshot_data_url = None;
                    state.interaction_token = None;
                    state.interaction_loader_id = None;
                    state.user_control_active = false;
                    state.inspection = None;
                    state.detail =
                        "Browser grant expired; stopping the Chrome process group…".into();
                    state.last_refusal = None;
                    (
                        stop_generation,
                        state.session.take(),
                        state.process_control.take(),
                    )
                };
                let result = match (session, control) {
                    (Some(session), Some(control)) => {
                        let signal = control.request_stop();
                        let stopped = session
                            .lock()
                            .map_err(|_| "Browser session lock failed during idle Stop.".to_owned())
                            .and_then(|mut session| session.stop());
                        signal.and(stopped)
                    }
                    (None, None) => Ok(()),
                    _ => Err("Browser idle Stop lost process-group control state.".into()),
                };
                let Ok(mut state) = inner.lock() else {
                    return;
                };
                if state.generation != stop_generation || state.phase != BrowserPhase::Stopping {
                    return;
                }
                match result {
                    Ok(()) => {
                        state.phase = BrowserPhase::Off;
                        state.detail =
                            "Browser grant expired after 60 idle minutes and Chrome exited.".into();
                        state.last_refusal = None;
                    }
                    Err(error) => {
                        state.phase = BrowserPhase::Failed;
                        state.detail.clone_from(&error);
                        state.last_refusal = Some(error);
                    }
                }
                return;
            }
        });
}

fn validate_navigation_url(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err("Browser navigation refused an empty, oversized, or malformed URL.".into());
    }
    let normalized = if value.contains("://") {
        value.to_owned()
    } else if value.contains(':') {
        return Err("Browser refused a non-web address scheme.".into());
    } else {
        format!("https://{value}")
    };
    let (scheme, remainder) = normalized
        .split_once("://")
        .ok_or_else(|| "Browser accepts web addresses only.".to_owned())?;
    if !matches!(scheme, "http" | "https") {
        return Err("Browser refused a non-http(s) URL scheme.".into());
    }
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || authority.starts_with(':')
        || authority.ends_with(':')
        || authority.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']'))
        })
    {
        return Err("Browser navigation refused URL credentials or an invalid authority.".into());
    }
    Ok(normalized)
}

fn validate_viewport_point(x: f64, y: f64) -> Result<(), String> {
    if !x.is_finite() || !y.is_finite() || !(0.0..1280.0).contains(&x) || !(0.0..800.0).contains(&y)
    {
        return Err(
            "Browser viewport input refused coordinates outside the current page image.".into(),
        );
    }
    Ok(())
}

fn interaction_token(
    generation: u64,
    grant: Option<&BrowserGrant>,
    loader_id: &str,
    screenshot_data_url: &str,
    viewport_width: u32,
    viewport_height: u32,
) -> String {
    let mut material = b"grok-build-browser-interaction/v1\0".to_vec();
    material.extend_from_slice(&generation.to_be_bytes());
    material.extend_from_slice(&viewport_width.to_be_bytes());
    material.extend_from_slice(&viewport_height.to_be_bytes());
    let project_id = grant.map_or("", |grant| grant.project_id.as_str());
    let run_id = grant
        .and_then(|grant| grant.run_id.as_deref())
        .unwrap_or("");
    let mode = match grant.map(|grant| grant.mode) {
        Some(BrowserMode::InApp) => "in_app",
        Some(BrowserMode::Headed) => "headed",
        None => "none",
    };
    material.extend_from_slice(
        &grant
            .map_or(0, |grant| grant.armed_at_unix_ms)
            .to_be_bytes(),
    );
    for value in [
        project_id.as_bytes(),
        run_id.as_bytes(),
        mode.as_bytes(),
        loader_id.as_bytes(),
        screenshot_data_url.as_bytes(),
    ] {
        material.extend_from_slice(&(value.len() as u64).to_be_bytes());
        material.extend_from_slice(value);
    }
    sha256_hex(&material)
}

fn validate_interaction_loader(expected: &str, current: &str) -> Result<(), String> {
    if expected.is_empty() || current.is_empty() || expected != current {
        return Err(
            "Browser viewport input refused because the page changed after the displayed still."
                .into(),
        );
    }
    Ok(())
}

fn validate_type_text(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TYPE_BYTES || value.contains('\0') {
        Err("Browser type refused empty, oversized, or NUL-containing text.".into())
    } else {
        Ok(())
    }
}

fn validate_key(value: &str) -> Result<&str, String> {
    const KEYS: &[&str] = &[
        "Enter",
        "Tab",
        "Escape",
        "Backspace",
        "Delete",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "PageUp",
        "PageDown",
        "Home",
        "End",
    ];
    if KEYS.contains(&value) {
        Ok(value)
    } else {
        Err("Browser key is outside the fixed admitted allowlist.".into())
    }
}

fn validate_identity(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(format!("Browser {label} identity is invalid."))
    } else {
        Ok(())
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create Browser profile directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect Browser profile directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Browser profile refused a symlink or non-directory root.".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("Cannot secure Browser profile directory: {error}"))?;
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Cannot sync Browser profile directory: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        output.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn bounded_detail(value: &str, fallback: &str) -> String {
    let normalized = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .take(1024)
        .collect::<String>();
    if normalized.trim().is_empty() {
        fallback.into()
    } else {
        normalized
    }
}

fn bounded_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn ax_property<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.get("properties")?
        .as_array()?
        .iter()
        .find(|property| property.get("name").and_then(Value::as_str) == Some(name))?
        .pointer("/value/value")
}

fn ax_boolean_property(node: &Value, name: &str) -> Option<bool> {
    ax_property(node, name).and_then(Value::as_bool)
}

fn ax_string_property(node: &Value, name: &str) -> Option<String> {
    ax_property(node, name)
        .and_then(Value::as_str)
        .map(|value| bounded_string(value, MAX_URL_BYTES))
}

fn model_safe_url(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value == "about:blank" {
        return value.into();
    }
    let without_private_parts = url_without_query_or_fragment(value);
    let Some((scheme, remainder)) = without_private_parts.split_once("://") else {
        return "non_http_url_redacted".into();
    };
    if !matches!(scheme, "http" | "https") {
        return "non_http_url_redacted".into();
    }
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.contains('@') {
        let path = &remainder[authority_end..];
        return format!("{scheme}://authority-redacted{path}");
    }
    without_private_parts
}

fn url_without_query_or_fragment(value: &str) -> String {
    let end = value.find(['?', '#']).unwrap_or(value.len());
    bounded_string(&value[..end], MAX_URL_BYTES)
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

#[allow(
    clippy::too_many_lines,
    reason = "the release smoke is one sequential end-to-end proof whose ordering and cleanup must remain visibly auditable"
)]
pub(crate) fn smoke_browser(state_root: &Path) -> Result<String, String> {
    if !state_root.is_absolute() {
        return Err("Browser smoke requires an absolute pre-provisioned state root.".into());
    }
    let browser = BrowserManager::new(state_root);
    let result = (|| {
        let armed = browser.arm("browser-smoke-project".into(), BrowserMode::InApp)?;
        if armed.phase != BrowserPhase::Armed || !armed.stop_visible {
            return Err("Browser smoke did not become visibly Armed after CDP readiness.".into());
        }
        let (url, request_observed, fixture_thread) = start_smoke_http_fixture()?;
        browser.agent_action(
            "browser-smoke-project",
            "browser-smoke-run",
            BrowserAgentAction::Navigate(&url),
        )?;
        let served = request_observed
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "Browser smoke HTTP fixture did not observe navigation.".to_owned())?;
        let joined = fixture_thread
            .join()
            .map_err(|_| "Browser smoke HTTP fixture thread panicked.".to_owned());
        served?;
        joined?;
        let navigated = browser.status();
        let inspection: Value = serde_json::from_str(
            navigated
                .inspection
                .as_deref()
                .ok_or_else(|| "Browser smoke produced no inspection.".to_owned())?,
        )
        .map_err(|error| format!("Browser smoke inspection was invalid JSON: {error}"))?;
        let nodes = inspection
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| "Browser smoke inspection had no nodes.".to_owned())?;
        let input = nodes
            .iter()
            .find(|node| node.get("name").and_then(Value::as_str) == Some("Fixture input"))
            .and_then(|node| node.get("id").and_then(Value::as_u64))
            .ok_or_else(|| "Browser smoke could not identify the fixture input.".to_owned())?;
        browser.agent_action(
            "browser-smoke-project",
            "browser-smoke-run",
            BrowserAgentAction::Type {
                node_id: input,
                text: "fixture typed",
            },
        )?;
        if browser
            .agent_action(
                "browser-smoke-project",
                "browser-smoke-run",
                BrowserAgentAction::Type {
                    node_id: input,
                    text: "stale token must not type",
                },
            )
            .is_ok()
        {
            return Err("Browser smoke reused a node token after its inspection epoch.".into());
        }
        let after_type = browser.status();
        let after_type_inspection: Value = serde_json::from_str(
            after_type
                .inspection
                .as_deref()
                .ok_or_else(|| "Browser smoke lost inspection after typing.".to_owned())?,
        )
        .map_err(|error| format!("Browser smoke post-type inspection was invalid JSON: {error}"))?;
        let button = after_type_inspection
            .get("nodes")
            .and_then(Value::as_array)
            .and_then(|nodes| {
                nodes
                    .iter()
                    .find(|node| node.get("name").and_then(Value::as_str) == Some("Apply fixture"))
                    .and_then(|node| node.get("id").and_then(Value::as_u64))
            })
            .ok_or_else(|| {
                "Browser smoke could not identify the fixture button after typing.".to_owned()
            })?;
        browser.agent_action(
            "browser-smoke-project",
            "browser-smoke-run",
            BrowserAgentAction::Click(button),
        )?;
        if browser
            .agent_action(
                "browser-smoke-project",
                "browser-smoke-other-run",
                BrowserAgentAction::Inspect,
            )
            .is_ok()
        {
            return Err("Browser smoke allowed another run to reuse the bound grant.".into());
        }
        browser.agent_action(
            "browser-smoke-project",
            "browser-smoke-run",
            BrowserAgentAction::Screenshot,
        )?;
        let clicked = browser.status();
        if !clicked
            .inspection
            .as_deref()
            .unwrap_or_default()
            .contains("fixture typed")
            || clicked.screenshot_data_url.is_none()
        {
            return Err("Browser smoke agent type/click/screenshot state was incomplete.".into());
        }
        browser.stop("Browser smoke completed.")?;
        let stopped = browser.status();
        if stopped.phase != BrowserPhase::Off || stopped.stop_visible {
            return Err("Browser smoke Stop did not reach terminal Off.".into());
        }
        Ok("BROWSER SMOKE PASSED pipe=true tcp-debugger=false sandbox=true version=152.0.7977.54 http-fixture=true agent-tools=true navigate=true inspect=true type=true click=true screenshot=true stop=true project-bound=true run-bound=true other-run-refused=true".to_owned())
    })();
    if result.is_err() {
        browser.shutdown();
    }
    result
}

pub(crate) fn smoke_browser_network(state_root: &Path) -> Result<String, String> {
    if !state_root.is_absolute() {
        return Err(
            "Browser network smoke requires an absolute pre-provisioned state root.".into(),
        );
    }
    let browser = BrowserManager::new(state_root);
    let result = (|| {
        browser.arm("browser-network-smoke-project".into(), BrowserMode::Headed)?;
        browser.agent_action(
            "browser-network-smoke-project",
            "browser-network-smoke-run",
            BrowserAgentAction::Navigate("https://example.com/"),
        )?;
        let view = browser.status();
        if !view.url.starts_with("https://example.com")
            || view.title.is_empty()
            || view.inspection.is_none()
            || view.screenshot_data_url.is_none()
        {
            return Err(
                "Browser network smoke did not produce a complete HTTPS page state.".into(),
            );
        }
        browser.stop("Browser network smoke completed.")?;
        if browser.status().phase != BrowserPhase::Off {
            return Err("Browser network smoke Stop did not reach terminal Off.".into());
        }
        Ok("BROWSER NETWORK SMOKE PASSED https=true fixed-url=true headed=true agent-tools=true screenshot=true stop=true".into())
    })();
    if result.is_err() {
        browser.shutdown();
    }
    result
}

type SmokeHttpFixture = (
    String,
    Receiver<Result<(), String>>,
    std::thread::JoinHandle<()>,
);

#[allow(
    clippy::too_many_lines,
    reason = "the fixed local server keeps its bounded accept/read/respond lifecycle and terminal evidence in one test-only boundary"
)]
fn start_smoke_http_fixture() -> Result<SmokeHttpFixture, String> {
    const FIXTURE: &str = "<!doctype html><html><head><title>Grok Browser Fixture</title></head><body><label>Fixture input <input aria-label=\"Fixture input\" id=\"fixture-input\"></label><button id=\"apply\" onclick=\"document.getElementById('output').textContent=document.getElementById('fixture-input').value||'clicked'\">Apply fixture</button><div id=\"output\">waiting</div></body></html>";
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("Cannot bind the Browser smoke HTTP fixture: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("Cannot bound the Browser smoke HTTP fixture: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("Cannot read the Browser smoke fixture address: {error}"))?;
    let (sender, receiver) = mpsc::sync_channel(1);
    let server = std::thread::Builder::new()
        .name("grok-browser-smoke-http".into())
        .spawn(move || {
            let result = (|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut accepted = 0_u8;
                let mut connections = Vec::<(std::net::TcpStream, Vec<u8>)>::new();
                loop {
                    if Instant::now() >= deadline || accepted >= 16 {
                        return Err(
                            "Browser smoke HTTP fixture did not receive the exact bounded request."
                                .into(),
                        );
                    }
                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                stream.set_nonblocking(true).map_err(|error| {
                                    format!("Cannot bound fixture connection: {error}")
                                })?;
                                connections.push((stream, Vec::new()));
                                accepted = accepted.saturating_add(1);
                                #[cfg(debug_assertions)]
                                eprintln!("BROWSER_SMOKE_HTTP_ACCEPT count={accepted}");
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) => {
                                return Err(format!(
                                    "Browser smoke HTTP fixture accept failed: {error}"
                                ));
                            }
                        }
                    }
                    let mut index = connections.len();
                    while index > 0 {
                        index -= 1;
                        let (stream, request) = &mut connections[index];
                        let mut chunk = [0_u8; 2048];
                        let remove = match stream.read(&mut chunk) {
                            Ok(0) => true,
                            Ok(count) => {
                                #[cfg(debug_assertions)]
                                eprintln!("BROWSER_SMOKE_HTTP_READ bytes={count}");
                                request.extend_from_slice(&chunk[..count]);
                                if request.len() > 8192 {
                                    true
                                } else if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                    let request_text = String::from_utf8_lossy(request);
                                    if request_text.starts_with("GET /fixture HTTP/1.") {
                                        stream.set_nonblocking(false).map_err(|error| {
                                            format!("Cannot prepare fixture response: {error}")
                                        })?;
                                        stream
                                            .set_write_timeout(Some(Duration::from_secs(2)))
                                            .map_err(|error| {
                                                format!(
                                                    "Cannot bound fixture response write: {error}"
                                                )
                                            })?;
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{FIXTURE}",
                                            FIXTURE.len()
                                        );
                                        stream
                                            .write_all(response.as_bytes())
                                            .and_then(|()| stream.flush())
                                            .map_err(|error| {
                                                format!(
                                                    "Cannot write Browser smoke HTTP response: {error}"
                                                )
                                            })?;
                                        #[cfg(debug_assertions)]
                                        eprintln!("BROWSER_SMOKE_HTTP_SERVED fixture=true");
                                        return Ok(());
                                    }
                                    let _ = stream.set_nonblocking(false);
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    );
                                    true
                                } else {
                                    false
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                            Err(_) => true,
                        };
                        if remove {
                            connections.swap_remove(index);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })();
            let _ = sender.send(result);
        })
        .map_err(|error| format!("Cannot start Browser smoke HTTP fixture: {error}"))?;
    Ok((
        format!("http://localhost:{}/fixture", address.port()),
        receiver,
        server,
    ))
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt as _;

    use super::*;

    #[test]
    fn navigation_and_input_guards_refuse_high_power_shapes() {
        assert!(validate_navigation_url("https://example.test/path?q=1").is_ok());
        assert!(validate_navigation_url("http://127.0.0.1:8080/fixture").is_ok());
        assert_eq!(
            validate_navigation_url("example.test/path").expect("bare host"),
            "https://example.test/path"
        );
        for refused in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "chrome://settings",
            "https://user:password@example.test/",
            "https://example.test/a b",
        ] {
            assert!(
                validate_navigation_url(refused).is_err(),
                "accepted {refused}"
            );
        }
        assert!(validate_type_text("editable text").is_ok());
        assert!(validate_type_text("").is_err());
        assert!(validate_key("Enter").is_ok());
        assert!(validate_key("Meta+L").is_err());
    }

    #[test]
    fn viewport_interaction_tokens_bind_grant_run_page_image_loader_and_dimensions() {
        assert!(validate_viewport_point(0.0, 0.0).is_ok());
        assert!(validate_viewport_point(1279.99, 799.99).is_ok());
        assert!(validate_viewport_point(-1.0, 1.0).is_err());
        assert!(validate_viewport_point(1280.0, 1.0).is_err());
        assert!(validate_interaction_loader("loader-a", "loader-a").is_ok());
        assert!(validate_interaction_loader("loader-a", "loader-b").is_err());
        let grant = BrowserGrant {
            project_id: "project-a".into(),
            run_id: Some("run-a".into()),
            mode: BrowserMode::InApp,
            armed_at_unix_ms: 17,
            last_activity: Instant::now(),
            idle_expires_unix_ms: 18,
        };
        let token = interaction_token(
            4,
            Some(&grant),
            "loader-a",
            "data:image/png;base64,aaa",
            1280,
            800,
        );
        assert_eq!(token.len(), 64);
        assert_ne!(
            token,
            interaction_token(
                4,
                Some(&grant),
                "loader-b",
                "data:image/png;base64,aaa",
                1280,
                800,
            )
        );
        let other_project = BrowserGrant {
            project_id: "project-b".into(),
            run_id: Some("run-a".into()),
            mode: BrowserMode::InApp,
            armed_at_unix_ms: 17,
            last_activity: Instant::now(),
            idle_expires_unix_ms: 18,
        };
        assert_ne!(
            token,
            interaction_token(
                4,
                Some(&other_project),
                "loader-a",
                "data:image/png;base64,aaa",
                1280,
                800,
            )
        );
        assert_ne!(
            token,
            interaction_token(
                5,
                Some(&grant),
                "loader-a",
                "data:image/png;base64,aaa",
                1280,
                800,
            )
        );
        assert_ne!(
            token,
            interaction_token(
                4,
                Some(&grant),
                "loader-a",
                "data:image/png;base64,bbb",
                1280,
                800,
            )
        );
        assert_ne!(
            token,
            interaction_token(
                4,
                Some(&grant),
                "loader-a",
                "data:image/png;base64,aaa",
                1279,
                800,
            )
        );
    }

    #[test]
    fn agent_browser_action_refuses_while_user_controls_viewport() {
        let root = std::env::temp_dir().join(format!(
            "grok-browser-user-agent-exclusion-{}",
            std::process::id()
        ));
        let browser = BrowserManager::new(&root);
        {
            let mut inner = browser.inner.lock().expect("browser state");
            inner.phase = BrowserPhase::Armed;
            inner.user_control_active = true;
        }
        let error = browser
            .agent_action("project-a", "run-a", BrowserAgentAction::Inspect)
            .expect_err("agent input must not overlap user input");
        assert!(error.contains("while the user controls"));
    }

    #[test]
    fn cdp_framing_is_nul_bounded_and_rejects_eof_and_oversize() {
        let mut input = BufReader::new(&b"{\"id\":1}\0tail"[..]);
        assert_eq!(read_cdp_frame(&mut input).expect("frame"), b"{\"id\":1}");
        assert!(read_cdp_frame(&mut BufReader::new(&b""[..])).is_err());
        let oversized = vec![b'a'; MAX_CDP_MESSAGE_BYTES + 1];
        assert!(read_cdp_frame(&mut BufReader::new(oversized.as_slice())).is_err());
    }

    #[test]
    fn profiles_are_opaque_and_do_not_embed_project_identity() {
        let digest = sha256_hex(b"project-secret-looking-name");
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains("project"));
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn cdp_method_surface_is_fixed_and_has_no_network_server_or_file_domain() {
        assert!(valid_cdp_method("Browser.getVersion"));
        assert!(valid_cdp_method("Page.captureScreenshot"));
        assert!(!valid_cdp_method("Browser.setDownloadPath"));
        assert!(!valid_cdp_method("IO.read"));
        assert!(!valid_cdp_method("FileSystem.getDirectory"));
        assert!(!valid_cdp_method("Runtime.evaluate"));
        assert!(valid_cdp_method("Accessibility.getFullAXTree"));
        assert!(valid_cdp_method("DOM.getBoxModel"));
    }

    #[test]
    fn model_urls_omit_query_fragment_credentials_and_non_http_schemes() {
        assert_eq!(
            model_safe_url("https://example.test/path?token=SECRET#fragment"),
            "https://example.test/path"
        );
        assert_eq!(
            model_safe_url("https://user:secret@example.test/path?private=1"),
            "https://authority-redacted/path"
        );
        assert_eq!(
            model_safe_url("javascript:secret()"),
            "non_http_url_redacted"
        );
        assert_eq!(model_safe_url(""), "");
    }

    #[test]
    fn inspection_and_action_source_never_executes_page_main_world_code() {
        let source = include_str!("browser.rs");
        let gesture = ["user", "Gesture"].concat();
        let page_owned_id = ["data-grok-build-", "node"].concat();
        assert!(!source.contains(&gesture));
        assert!(!source.contains(&page_owned_id));
        assert!(source.contains("Accessibility.getFullAXTree"));
        assert!(source.contains("backendNodeId"));
    }

    #[test]
    fn stop_controls_remain_callable_during_other_capability_work() {
        let browser = include_str!("../ui/modules/browser.js");
        let capture = include_str!("../ui/modules/capture.js");
        let desktop = include_str!("../ui/modules/desktop.js");
        let app = include_str!("../ui/app.js");
        for source in [browser, capture, desktop] {
            let stop_guard = source
                .split("async function stop()")
                .nth(1)
                .expect("Stop implementation")
                .lines()
                .take(3)
                .collect::<String>();
            assert!(!stop_guard.contains("localBusy"));
            assert!(stop_guard.contains("stopBusy"));
        }
        assert!(app.contains("Promise.allSettled(stops)"));
        assert!(app.contains("globalCapabilityStop.disabled = false"));
    }

    #[test]
    fn process_group_is_not_gone_merely_because_its_leader_exited() {
        let mut leader = Command::new("/bin/sleep")
            .arg("0.05")
            .process_group(0)
            .spawn()
            .expect("spawn group leader");
        let group_raw = i32::try_from(leader.id()).expect("group id");
        let group = Pid::from_raw(group_raw);
        let mut descendant = Command::new("/bin/sleep")
            .arg("30")
            .process_group(group_raw)
            .spawn()
            .expect("spawn group descendant");
        leader.wait().expect("reap leader");
        assert!(process_group_alive(group).expect("group probe"));
        signal_group(group, Signal::SIGKILL).expect("kill complete group");
        descendant.wait().expect("reap descendant");
        let deadline = Instant::now() + Duration::from_secs(1);
        while process_group_alive(group).expect("post-kill group probe") {
            assert!(Instant::now() < deadline, "process group remained alive");
            std::thread::yield_now();
        }
    }

    #[test]
    fn grant_is_project_bound_run_sticky_and_expires_at_sixty_idle_minutes() {
        let now = Instant::now();
        let mut grant = BrowserGrant {
            project_id: "project-a".into(),
            run_id: None,
            mode: BrowserMode::InApp,
            armed_at_unix_ms: 1,
            last_activity: now
                .checked_sub(Duration::from_secs(30))
                .expect("fixture instant supports a 30-second subtraction"),
            idle_expires_unix_ms: 2,
        };
        assert!(!grant.idle_expired_at(now));
        assert!(grant.bind_action("project-b", Some("run-a")).is_err());
        grant
            .bind_action("project-a", Some("run-a"))
            .expect("first agent action binds the run");
        grant
            .bind_action("project-a", Some("run-a"))
            .expect("same run remains eligible");
        assert!(grant.bind_action("project-a", Some("run-b")).is_err());
        grant.last_activity = now
            .checked_sub(BROWSER_IDLE_TIMEOUT)
            .expect("fixture instant supports the idle-timeout subtraction");
        assert!(grant.idle_expired_at(now));
    }

    #[test]
    fn project_switch_invalidates_browser_start_before_grant_commit() {
        let root = std::env::temp_dir().join(format!(
            "grok-browser-start-generation-{}",
            std::process::id()
        ));
        let browser = BrowserManager::new(&root);
        let starting_generation = {
            let mut inner = browser.inner.lock().expect("browser state");
            inner.generation = 41;
            inner.phase = BrowserPhase::Starting;
            inner.generation
        };
        browser
            .stop_for_project_change()
            .expect("project switch Stop");
        let inner = browser.inner.lock().expect("browser state");
        assert_eq!(inner.phase, BrowserPhase::Off);
        assert_ne!(inner.generation, starting_generation);
        assert!(inner.grant.is_none());
    }
}
