//! Explicit, project/run-scoped Desktop Control grant and target validation.

use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::desktop_bridge::MacDesktopPlatform;

const GRANT_LIFETIME: Duration = Duration::from_mins(10);
const TARGET_LIFETIME: Duration = Duration::from_mins(1);
const LOCK_MONITOR_TICK: Duration = Duration::from_secs(1);
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_TARGET_STRING_BYTES: usize = 512;
const MAX_SCROLL_DELTA: i32 = 2_000;
const GEOMETRY_EPSILON: f64 = 0.01;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DesktopPhase {
    Off,
    Selecting,
    TargetSelected,
    Arming,
    Armed,
    Acting,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DesktopPermission {
    Authorized,
    NotDeterminedOrDenied,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopRect {
    pub(crate) x: f64,
    pub(crate) y: f64,
    pub(crate) width: f64,
    pub(crate) height: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopTarget {
    pub(crate) application: String,
    pub(crate) bundle_id: Option<String>,
    pub(crate) pid: i32,
    pub(crate) window_id: u32,
    pub(crate) window_title: String,
    pub(crate) bounds: DesktopRect,
    pub(crate) display_id: u32,
}

impl DesktopTarget {
    pub(crate) fn same_binding(&self, current: &Self) -> bool {
        self.pid == current.pid
            && self.window_id == current.window_id
            && self.display_id == current.display_id
            && self.bundle_id == current.bundle_id
            && rect_matches(self.bounds, current.bounds)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopMouseButton {
    Left,
    Right,
    Center,
}

impl DesktopMouseButton {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "left" => Ok(Self::Left),
            "right" => Ok(Self::Right),
            "center" => Ok(Self::Center),
            _ => Err("Desktop click button must be left, right, or center.".into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopModifier {
    Command,
    Control,
    Option,
    Shift,
}

impl DesktopModifier {
    pub(crate) fn parse_list(value: &str) -> Result<Vec<Self>, String> {
        if value.is_empty() {
            return Ok(Vec::new());
        }
        let mut parsed = Vec::new();
        for item in value.split(',') {
            let modifier = match item {
                "command" => Self::Command,
                "control" => Self::Control,
                "option" => Self::Option,
                "shift" => Self::Shift,
                _ => {
                    return Err(
                        "Desktop key modifiers must be command, control, option, or shift.".into(),
                    );
                }
            };
            if parsed.contains(&modifier) {
                return Err("Desktop key modifiers cannot contain duplicates.".into());
            }
            parsed.push(modifier);
        }
        if parsed.len() > 4 {
            return Err("Desktop key chord exceeds the four-modifier bound.".into());
        }
        Ok(parsed)
    }
}

pub(crate) enum DesktopAction {
    Click {
        x: f64,
        y: f64,
        button: DesktopMouseButton,
    },
    Type {
        text: String,
    },
    Key {
        key: String,
        modifiers: Vec<DesktopModifier>,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
    },
}

impl DesktopAction {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Click { .. } => "click",
            Self::Type { .. } => "type",
            Self::Key { .. } => "key",
            Self::Scroll { .. } => "scroll",
        }
    }

    fn validate(&self, target: &DesktopTarget) -> Result<(), String> {
        match self {
            Self::Click { x, y, .. } => {
                if !x.is_finite()
                    || !y.is_finite()
                    || *x < 0.0
                    || *y < 0.0
                    || *x >= target.bounds.width
                    || *y >= target.bounds.height
                {
                    return Err(
                        "Desktop click coordinates must be finite and inside the armed window."
                            .into(),
                    );
                }
            }
            Self::Type { text } => {
                if text.is_empty() || text.len() > MAX_TEXT_BYTES || text.contains('\0') {
                    return Err(
                        "Desktop type text must be nonempty, NUL-free, and at most 4 KiB.".into(),
                    );
                }
            }
            Self::Key { key, modifiers } => {
                if !allowed_key(key) {
                    return Err("Desktop key is outside the fixed allowlist.".into());
                }
                if modifiers.len() > 4 {
                    return Err("Desktop key chord exceeds the four-modifier bound.".into());
                }
            }
            Self::Scroll { delta_x, delta_y } => {
                if (*delta_x == 0 && *delta_y == 0)
                    || !(-MAX_SCROLL_DELTA..=MAX_SCROLL_DELTA).contains(delta_x)
                    || !(-MAX_SCROLL_DELTA..=MAX_SCROLL_DELTA).contains(delta_y)
                {
                    return Err(
                        "Desktop scroll requires a nonzero delta within ±2000 pixels per axis."
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }
}

pub(crate) trait DesktopPlatform: Send + Sync {
    fn accessibility_trusted(&self) -> Result<bool, String>;
    fn request_accessibility(&self) -> Result<(), String>;
    fn snapshot_frontmost(&self) -> Result<DesktopTarget, String>;
    fn post_event(&self, target: &DesktopTarget, action: &DesktopAction) -> Result<(), String>;
    fn screen_locked(&self) -> Result<bool, String>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DesktopView {
    pub(crate) phase: DesktopPhase,
    pub(crate) permission: DesktopPermission,
    pub(crate) detail: String,
    pub(crate) last_refusal: Option<String>,
    pub(crate) project_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) pending_target: Option<DesktopTarget>,
    pub(crate) target: Option<DesktopTarget>,
    pub(crate) selected_at: Option<u64>,
    pub(crate) armed_at: Option<u64>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) stop_visible: bool,
    pub(crate) last_action: Option<String>,
}

struct PendingTarget {
    project_id: String,
    target: DesktopTarget,
    selected_at_epoch: u64,
    expires_at: Instant,
    permission_prompted: bool,
}

struct DesktopGrant {
    project_id: String,
    run_id: Option<String>,
    target: DesktopTarget,
    armed_at_epoch: u64,
    expires_at_epoch: u64,
    expires_at: Instant,
}

struct DesktopInner {
    phase: DesktopPhase,
    permission: DesktopPermission,
    detail: String,
    last_refusal: Option<String>,
    pending: Option<PendingTarget>,
    grant: Option<DesktopGrant>,
    last_action: Option<String>,
    generation: u64,
}

impl Default for DesktopInner {
    fn default() -> Self {
        Self {
            phase: DesktopPhase::Off,
            permission: DesktopPermission::NotDeterminedOrDenied,
            detail: "Desktop Control is Off. Select and explicitly arm one frontmost app window."
                .into(),
            last_refusal: None,
            pending: None,
            grant: None,
            last_action: None,
            generation: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct DesktopManager {
    inner: Arc<Mutex<DesktopInner>>,
    platform: Arc<dyn DesktopPlatform>,
    grant_lifetime: Duration,
    target_lifetime: Duration,
}

impl DesktopManager {
    pub(crate) fn production() -> Self {
        Self::new(
            Arc::new(MacDesktopPlatform),
            GRANT_LIFETIME,
            TARGET_LIFETIME,
        )
    }

    fn new(
        platform: Arc<dyn DesktopPlatform>,
        grant_lifetime: Duration,
        target_lifetime: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(DesktopInner::default())),
            platform,
            grant_lifetime,
            target_lifetime,
        }
    }

    pub(crate) fn status(&self) -> DesktopView {
        self.reconcile();
        self.inner.lock().map_or_else(
            |_| unavailable_view("Desktop Control state lock is unavailable."),
            |inner| present(&inner),
        )
    }

    pub(crate) fn select_frontmost(&self, project_id: String) -> Result<DesktopView, String> {
        if project_id.trim().is_empty() {
            return self.refuse("Desktop Control target selection requires an active project.");
        }
        let generation = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
            if inner.grant.is_some()
                || matches!(inner.phase, DesktopPhase::Selecting | DesktopPhase::Arming)
            {
                return Err("Stop Desktop Control before selecting another target.".into());
            }
            inner.generation = inner.generation.wrapping_add(1).max(1);
            inner.phase = DesktopPhase::Selecting;
            inner.detail = "Reading the exact frontmost app/window identity…".into();
            inner.last_refusal = None;
            inner.pending = None;
            inner.last_action = None;
            inner.generation
        };
        let locked = match self.platform.screen_locked() {
            Ok(locked) => locked,
            Err(error) => {
                return self.refuse(&format!(
                    "Desktop Control lock-state validation failed closed during selection: {error}"
                ));
            }
        };
        if locked {
            return self
                .refuse("Desktop Control cannot select a target while the screen is locked.");
        }
        let target = match self.platform.snapshot_frontmost() {
            Ok(target) => target,
            Err(error) => return self.refuse(&error),
        };
        if let Err(error) = validate_target(&target) {
            return self.refuse(&error);
        }
        if target.pid == i32::try_from(std::process::id()).unwrap_or(i32::MAX) {
            return self.refuse(
                "Desktop Control will not target GB Plus itself. Switch to the intended app during the countdown.",
            );
        }
        let selected_at = unix_millis();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
        if inner.generation != generation || inner.phase != DesktopPhase::Selecting {
            return Err(
                "Desktop target selection was superseded by Stop or a project/worktree switch."
                    .into(),
            );
        }
        inner.phase = DesktopPhase::TargetSelected;
        inner.detail = format!(
            "Selected {} · PID {} · window {}. Review it, then arm with the focus countdown.",
            target.application, target.pid, target.window_id
        );
        inner.last_refusal = None;
        inner.last_action = None;
        inner.pending = Some(PendingTarget {
            project_id,
            target,
            selected_at_epoch: selected_at,
            expires_at: Instant::now() + self.target_lifetime,
            permission_prompted: false,
        });
        Ok(present(&inner))
    }

    pub(crate) fn arm_selected(
        &self,
        project_id: &str,
        window_id: u32,
    ) -> Result<DesktopView, String> {
        self.reconcile();
        if self.platform.screen_locked()? {
            return self.refuse("Desktop Control cannot be armed while the screen is locked.");
        }
        let (expected, permission_prompted, generation) =
            self.prepare_arm(project_id, window_id)?;
        let trusted = match self.platform.accessibility_trusted() {
            Ok(trusted) => trusted,
            Err(error) => return self.refuse(&error),
        };
        if !trusted {
            if !permission_prompted && let Err(error) = self.platform.request_accessibility() {
                return self.refuse(&error);
            }
            return self.permission_pending(
                project_id,
                window_id,
                &expected,
                generation,
                !permission_prompted,
            );
        }
        let verified = match self.platform.accessibility_trusted() {
            Ok(verified) => verified,
            Err(error) => return self.refuse(&error),
        };
        if !verified {
            return self.refuse(
                "Desktop Control refused because macOS Accessibility permission changed during Arm.",
            );
        }
        let current = match self.platform.snapshot_frontmost() {
            Ok(current) => current,
            Err(error) => return self.refuse(&error),
        };
        if !expected.same_binding(&current) {
            return self.refuse(
                "Desktop Control refused because the selected PID, frontmost window, display, or geometry changed before Arm.",
            );
        }
        let now_epoch = unix_millis();
        let expires_epoch = now_epoch.saturating_add(duration_millis(self.grant_lifetime));
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
            if inner.generation != generation || inner.phase != DesktopPhase::Arming {
                return Err(
                    "Desktop Control Arm was superseded by Stop or a project/worktree switch."
                        .into(),
                );
            }
            let pending_matches = inner.pending.as_ref().is_some_and(|pending| {
                pending.project_id == project_id
                    && pending.target.window_id == window_id
                    && pending.target.same_binding(&expected)
            });
            if !pending_matches {
                return Err("Desktop Control target changed during Arm; grant refused.".into());
            }
            inner.phase = DesktopPhase::Armed;
            inner.permission = DesktopPermission::Authorized;
            inner.detail = format!(
                "Desktop Control armed for {} · PID {} · window {} · 10-minute maximum.",
                current.application, current.pid, current.window_id
            );
            inner.last_refusal = None;
            inner.pending = None;
            inner.last_action = None;
            inner.grant = Some(DesktopGrant {
                project_id: project_id.to_owned(),
                run_id: None,
                target: current,
                armed_at_epoch: now_epoch,
                expires_at_epoch: expires_epoch,
                expires_at: Instant::now() + self.grant_lifetime,
            });
        }
        spawn_monitor(
            Arc::downgrade(&self.inner),
            Arc::downgrade(&self.platform),
            generation,
        );
        Ok(self.status())
    }

    fn prepare_arm(
        &self,
        project_id: &str,
        window_id: u32,
    ) -> Result<(DesktopTarget, bool, u64), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
        let (expected, permission_prompted) = {
            let pending = inner.pending.as_ref().ok_or_else(|| {
                "Select the exact frontmost app window before arming Desktop Control.".to_owned()
            })?;
            if pending.project_id != project_id || pending.target.window_id != window_id {
                return Err("Desktop Control target selection identity changed before Arm.".into());
            }
            if Instant::now() >= pending.expires_at {
                return Err("Desktop Control target selection expired; select it again.".into());
            }
            (pending.target.clone(), pending.permission_prompted)
        };
        inner.generation = inner.generation.wrapping_add(1).max(1);
        inner.phase = DesktopPhase::Arming;
        inner.detail = "Verifying Accessibility and the exact frontmost target…".into();
        Ok((expected, permission_prompted, inner.generation))
    }

    fn permission_pending(
        &self,
        project_id: &str,
        window_id: u32,
        expected: &DesktopTarget,
        generation: u64,
        prompted_now: bool,
    ) -> Result<DesktopView, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
        if inner.generation != generation || inner.phase != DesktopPhase::Arming {
            return Err(
                "Desktop Control Arm was superseded by Stop or a project/worktree switch.".into(),
            );
        }
        let pending_matches = inner.pending.as_ref().is_some_and(|pending| {
            pending.project_id == project_id
                && pending.target.window_id == window_id
                && pending.target.same_binding(expected)
        });
        if !pending_matches {
            return Err("Desktop Control target changed while requesting permission.".into());
        }
        if let Some(pending) = inner.pending.as_mut() {
            pending.permission_prompted = true;
        }
        inner.phase = DesktopPhase::TargetSelected;
        inner.permission = DesktopPermission::NotDeterminedOrDenied;
        inner.detail = if prompted_now {
            "macOS Accessibility permission was requested. Desktop Control remains Off. Approve GB Plus in System Settings, return to this exact app, then choose Arm again. If macOS already shows it On but permission is still unavailable, quit and reopen this exact app before reselecting."
                .into()
        } else {
            "macOS Accessibility permission is still unavailable. Desktop Control remains Off. Confirm this exact GB Plus app is enabled in System Settings. If it already shows On, quit and reopen this exact app, reselect the target, then choose Arm again."
                .into()
        };
        inner.last_refusal = None;
        inner.grant = None;
        inner.last_action = None;
        Ok(present(&inner))
    }

    pub(crate) fn agent_action(
        &self,
        project_id: &str,
        run_id: &str,
        action: &DesktopAction,
    ) -> Result<String, String> {
        self.reconcile();
        if project_id.is_empty() || run_id.is_empty() {
            let reason = "Desktop Control requires exact project and run identities.";
            return if self
                .inner
                .lock()
                .ok()
                .is_some_and(|inner| inner.grant.is_some())
            {
                self.fail_armed(reason)
            } else {
                Err(reason.into())
            };
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
        let prepared: Result<(DesktopTarget, u64), String> = (|| {
            let grant = inner.grant.as_mut().ok_or_else(|| {
                "Desktop Control is Off. The requested input event was not posted.".to_owned()
            })?;
            if grant.project_id != project_id {
                return Err("Desktop Control grant belongs to another project.".to_owned());
            }
            match &grant.run_id {
                Some(bound) if bound != run_id => {
                    return Err("Desktop Control grant is bound to another run.".to_owned());
                }
                None => grant.run_id = Some(run_id.to_owned()),
                Some(_) => {}
            }
            action.validate(&grant.target)?;
            let target = grant.target.clone();
            let generation = inner.generation;
            inner.phase = DesktopPhase::Acting;
            inner.detail = format!(
                "Validating {} · PID {} · window {} before {}…",
                target.application,
                target.pid,
                target.window_id,
                action.label()
            );
            Ok((target, generation))
        })();
        let (target, generation) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                fail_armed_inner(&mut inner, &error);
                return Err(error);
            }
        };

        if let Err(error) = self.post_validated_action(&target, action) {
            fail_armed_inner(&mut inner, &error);
            return Err(error);
        }
        if inner.generation != generation || inner.grant.is_none() {
            return Err(
                "Desktop Control event returned after its grant was stopped or replaced.".into(),
            );
        }
        inner.phase = DesktopPhase::Armed;
        inner.last_refusal = None;
        inner.last_action = Some(action.label().to_owned());
        inner.detail = format!(
            "{} event posted to PID {} after exact pre/post target validation; target application completion is not asserted.",
            action.label(),
            target.pid
        );
        Ok(format!(
            "Desktop {} event posted to the armed PID/window after exact pre/post validation; target completion is unknown.",
            action.label()
        ))
    }

    fn post_validated_action(
        &self,
        target: &DesktopTarget,
        action: &DesktopAction,
    ) -> Result<(), String> {
        let locked = match self.platform.screen_locked() {
            Ok(locked) => locked,
            Err(error) => {
                return Err(format!(
                    "Desktop Control lock-state validation failed closed: {error}"
                ));
            }
        };
        if locked {
            return Err(
                "Desktop Control refused because the screen locked before the input event.".into(),
            );
        }
        let trusted = match self.platform.accessibility_trusted() {
            Ok(trusted) => trusted,
            Err(error) => {
                return Err(format!(
                    "Desktop Control Accessibility validation failed closed: {error}"
                ));
            }
        };
        if !trusted {
            return Err(
                "Desktop Control refused because macOS Accessibility permission was revoked."
                    .into(),
            );
        }
        let before = match self.platform.snapshot_frontmost() {
            Ok(target) => target,
            Err(error) => {
                return Err(format!(
                    "Desktop Control target validation failed closed before the input event: {error}"
                ));
            }
        };
        if !target.same_binding(&before) {
            return Err(
                "Desktop Control refused because PID, focus, window identity, display, or geometry changed before the input event."
                    .into(),
            );
        }
        if let Err(error) = self.platform.post_event(target, action) {
            return Err(format!(
                "Desktop Control could not post the bounded input event: {error}"
            ));
        }
        let after = match self.platform.snapshot_frontmost() {
            Ok(target) => target,
            Err(error) => {
                return Err(format!(
                    "Desktop Control posted the event but post-target validation failed closed: {error}"
                ));
            }
        };
        if !target.same_binding(&after) {
            return Err(
                "Desktop Control posted the event but refused completion because the target binding changed immediately afterward."
                    .into(),
            );
        }
        Ok(())
    }

    pub(crate) fn bind_run(&self, project_id: &str, run_id: &str) -> Result<(), String> {
        self.reconcile();
        if project_id.is_empty() || run_id.is_empty() {
            let reason = "Desktop Control run binding requires exact identities.";
            return if self
                .inner
                .lock()
                .ok()
                .is_some_and(|inner| inner.grant.is_some())
            {
                self.fail_armed(reason)
            } else {
                Err(reason.into())
            };
        }
        let outcome = {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
            let Some(grant) = inner.grant.as_mut() else {
                return Ok(());
            };
            if grant.project_id == project_id {
                match &grant.run_id {
                    Some(bound) if bound != run_id => {
                        Err("Desktop Control grant is already bound to another run.".to_owned())
                    }
                    Some(_) => Ok(()),
                    None => {
                        grant.run_id = Some(run_id.to_owned());
                        inner.detail = format!(
                            "Desktop Control bound to run {run_id}; it clears when this run ends or at 10 minutes."
                        );
                        Ok(())
                    }
                }
            } else {
                Err("Desktop Control grant belongs to another project.".to_owned())
            }
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(reason) => self.fail_armed(&reason),
        }
    }

    pub(crate) fn finish_run(&self, run_id: &str) {
        if let Ok(mut inner) = self.inner.lock()
            && inner
                .grant
                .as_ref()
                .and_then(|grant| grant.run_id.as_deref())
                == Some(run_id)
        {
            clear_all(
                &mut inner,
                "Desktop Control grant cleared because its bound run ended.",
            );
        }
    }

    pub(crate) fn project_switched(&self, project_id: Option<&str>) {
        if let Ok(mut inner) = self.inner.lock() {
            let grant_changed = inner
                .grant
                .as_ref()
                .is_some_and(|grant| project_id.is_none_or(|project| project != grant.project_id));
            let pending_changed = inner.pending.as_ref().is_some_and(|pending| {
                project_id.is_none_or(|project| project != pending.project_id)
            });
            if grant_changed
                || pending_changed
                || matches!(inner.phase, DesktopPhase::Selecting | DesktopPhase::Arming)
            {
                clear_all(
                    &mut inner,
                    "Desktop Control cleared on project/worktree switch.",
                );
            }
        }
    }

    pub(crate) fn stop(&self, detail: &str) -> Result<DesktopView, String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "Desktop Control state lock is unavailable.".to_owned())?;
        clear_all(&mut inner, detail);
        Ok(present(&inner))
    }

    fn reconcile(&self) {
        let (has_grant, has_pending) = self.inner.lock().map_or((false, false), |inner| {
            (inner.grant.is_some(), inner.pending.is_some())
        });
        if !has_grant {
            if let Ok(permission) = self.platform.accessibility_trusted()
                && let Ok(mut inner) = self.inner.lock()
            {
                inner.permission = if permission {
                    DesktopPermission::Authorized
                } else {
                    DesktopPermission::NotDeterminedOrDenied
                };
                if has_pending
                    && inner
                        .pending
                        .as_ref()
                        .is_some_and(|pending| Instant::now() >= pending.expires_at)
                {
                    clear_all(&mut inner, "Desktop Control target selection expired.");
                }
            }
            return;
        }
        let locked = self.platform.screen_locked();
        let permission = self.platform.accessibility_trusted();
        if let Ok(mut inner) = self.inner.lock() {
            let expired = inner
                .grant
                .as_ref()
                .is_some_and(|grant| Instant::now() >= grant.expires_at);
            match (expired, locked, permission) {
                (true, _, _) => clear_all(
                    &mut inner,
                    "Desktop Control grant expired after 10 minutes.",
                ),
                (_, Ok(true), _) => clear_all(
                    &mut inner,
                    "Desktop Control grant cleared because the screen locked.",
                ),
                (_, Err(error), _) => fail_armed_inner(
                    &mut inner,
                    &format!("Desktop Control lock-state validation failed closed: {error}"),
                ),
                (_, _, Ok(false)) => fail_armed_inner(
                    &mut inner,
                    "macOS Accessibility permission was revoked while Desktop Control was armed.",
                ),
                (_, _, Err(error)) => fail_armed_inner(
                    &mut inner,
                    &format!("Desktop Control permission validation failed closed: {error}"),
                ),
                _ => {}
            }
        }
    }

    fn refuse<T>(&self, reason: &str) -> Result<T, String> {
        if let Ok(mut inner) = self.inner.lock() {
            fail_armed_inner(&mut inner, reason);
        }
        Err(reason.to_owned())
    }

    fn fail_armed<T>(&self, reason: &str) -> Result<T, String> {
        self.refuse(reason)
    }
}

fn present(inner: &DesktopInner) -> DesktopView {
    let grant = inner.grant.as_ref();
    let pending = inner.pending.as_ref();
    DesktopView {
        phase: inner.phase,
        permission: inner.permission,
        detail: inner.detail.clone(),
        last_refusal: inner.last_refusal.clone(),
        project_id: grant
            .map(|grant| grant.project_id.clone())
            .or_else(|| pending.map(|pending| pending.project_id.clone())),
        run_id: grant.and_then(|grant| grant.run_id.clone()),
        pending_target: pending.map(|pending| pending.target.clone()),
        target: grant.map(|grant| grant.target.clone()),
        selected_at: pending.map(|pending| pending.selected_at_epoch),
        armed_at: grant.map(|grant| grant.armed_at_epoch),
        expires_at: grant.map(|grant| grant.expires_at_epoch),
        stop_visible: grant.is_some(),
        last_action: inner.last_action.clone(),
    }
}

fn unavailable_view(detail: &str) -> DesktopView {
    DesktopView {
        phase: DesktopPhase::Failed,
        permission: DesktopPermission::Unavailable,
        detail: detail.into(),
        last_refusal: Some(detail.into()),
        project_id: None,
        run_id: None,
        pending_target: None,
        target: None,
        selected_at: None,
        armed_at: None,
        expires_at: None,
        stop_visible: false,
        last_action: None,
    }
}

fn validate_target(target: &DesktopTarget) -> Result<(), String> {
    if target.pid <= 1 || target.window_id == 0 || target.display_id == 0 {
        return Err(
            "macOS returned an invalid Desktop Control PID/window/display identity.".into(),
        );
    }
    if target.application.is_empty()
        || target.application.len() > MAX_TARGET_STRING_BYTES
        || target.application.chars().any(char::is_control)
        || target.window_title.len() > MAX_TARGET_STRING_BYTES
        || target.window_title.chars().any(char::is_control)
        || target.bundle_id.as_ref().is_some_and(|bundle| {
            bundle.is_empty()
                || bundle.len() > MAX_TARGET_STRING_BYTES
                || bundle.chars().any(char::is_control)
        })
    {
        return Err("macOS returned malformed or oversized Desktop Control target text.".into());
    }
    let bounds = target.bounds;
    if !bounds.x.is_finite()
        || !bounds.y.is_finite()
        || !bounds.width.is_finite()
        || !bounds.height.is_finite()
        || bounds.width < 1.0
        || bounds.height < 1.0
        || bounds.width > 100_000.0
        || bounds.height > 100_000.0
        || bounds.x.abs() > 1_000_000.0
        || bounds.y.abs() > 1_000_000.0
    {
        return Err("macOS returned invalid Desktop Control window geometry.".into());
    }
    Ok(())
}

fn rect_matches(expected: DesktopRect, current: DesktopRect) -> bool {
    (expected.x - current.x).abs() <= GEOMETRY_EPSILON
        && (expected.y - current.y).abs() <= GEOMETRY_EPSILON
        && (expected.width - current.width).abs() <= GEOMETRY_EPSILON
        && (expected.height - current.height).abs() <= GEOMETRY_EPSILON
}

pub(crate) fn allowed_key(key: &str) -> bool {
    matches!(
        key,
        "Enter"
            | "Tab"
            | "Escape"
            | "Backspace"
            | "Delete"
            | "Space"
            | "ArrowUp"
            | "ArrowDown"
            | "ArrowLeft"
            | "ArrowRight"
            | "Home"
            | "End"
            | "PageUp"
            | "PageDown"
    ) || (key.len() == 1
        && key
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric()))
}

fn clear_all(inner: &mut DesktopInner, detail: &str) {
    inner.generation = inner.generation.wrapping_add(1).max(1);
    inner.phase = DesktopPhase::Off;
    detail.clone_into(&mut inner.detail);
    inner.last_refusal = None;
    inner.pending = None;
    inner.grant = None;
    inner.last_action = None;
}

fn fail_armed_inner(inner: &mut DesktopInner, reason: &str) {
    inner.generation = inner.generation.wrapping_add(1).max(1);
    inner.phase = DesktopPhase::Failed;
    reason.clone_into(&mut inner.detail);
    inner.last_refusal = Some(reason.to_owned());
    inner.pending = None;
    inner.grant = None;
    inner.last_action = None;
}

fn spawn_monitor(
    inner: Weak<Mutex<DesktopInner>>,
    platform: Weak<dyn DesktopPlatform>,
    generation: u64,
) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(LOCK_MONITOR_TICK);
            let Some(inner) = inner.upgrade() else {
                break;
            };
            let Some(platform) = platform.upgrade() else {
                break;
            };
            let active = inner
                .lock()
                .ok()
                .is_some_and(|state| state.generation == generation && state.grant.is_some());
            if !active {
                break;
            }
            let locked = platform.screen_locked();
            let permission = platform.accessibility_trusted();
            let Ok(mut state) = inner.lock() else {
                break;
            };
            if state.generation != generation || state.grant.is_none() {
                break;
            }
            let expired = state
                .grant
                .as_ref()
                .is_some_and(|grant| Instant::now() >= grant.expires_at);
            match (expired, locked, permission) {
                (true, _, _) => {
                    clear_all(
                        &mut state,
                        "Desktop Control grant expired after 10 minutes.",
                    );
                    break;
                }
                (_, Ok(true), _) => {
                    clear_all(
                        &mut state,
                        "Desktop Control grant cleared because the screen locked.",
                    );
                    break;
                }
                (_, Err(error), _) => {
                    fail_armed_inner(
                        &mut state,
                        &format!("Desktop Control lock monitor failed closed: {error}"),
                    );
                    break;
                }
                (_, _, Ok(false)) => {
                    fail_armed_inner(
                        &mut state,
                        "macOS Accessibility permission was revoked while Desktop Control was armed.",
                    );
                    break;
                }
                (_, _, Err(error)) => {
                    fail_armed_inner(
                        &mut state,
                        &format!("Desktop Control permission monitor failed closed: {error}"),
                    );
                    break;
                }
                _ => {}
            }
        }
    });
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

    use super::*;

    #[derive(Clone)]
    struct MockState {
        trusted: bool,
        request_grants: bool,
        requests: usize,
        locked: bool,
        target: DesktopTarget,
        post_target: Option<DesktopTarget>,
        post_error: Option<String>,
        posts: usize,
        snapshot_hook: Option<(Arc<Barrier>, Arc<Barrier>)>,
        post_hook: Option<(Arc<Barrier>, Arc<Barrier>)>,
    }

    struct MockPlatform(Mutex<MockState>);

    impl MockPlatform {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(MockState {
                trusted: false,
                request_grants: true,
                requests: 0,
                locked: false,
                target: target(
                    101,
                    501,
                    44,
                    DesktopRect {
                        x: 10.0,
                        y: 20.0,
                        width: 800.0,
                        height: 600.0,
                    },
                ),
                post_target: None,
                post_error: None,
                posts: 0,
                snapshot_hook: None,
                post_hook: None,
            })))
        }
    }

    impl DesktopPlatform for MockPlatform {
        fn accessibility_trusted(&self) -> Result<bool, String> {
            Ok(self.0.lock().expect("mock").trusted)
        }

        fn request_accessibility(&self) -> Result<(), String> {
            let mut state = self.0.lock().expect("mock");
            state.requests += 1;
            if state.request_grants {
                state.trusted = true;
            }
            Ok(())
        }

        fn snapshot_frontmost(&self) -> Result<DesktopTarget, String> {
            let (target, hook) = {
                let mut state = self.0.lock().expect("mock");
                (state.target.clone(), state.snapshot_hook.take())
            };
            if let Some((entered, release)) = hook {
                entered.wait();
                release.wait();
            }
            Ok(target)
        }

        fn post_event(
            &self,
            _target: &DesktopTarget,
            _action: &DesktopAction,
        ) -> Result<(), String> {
            let hook = self.0.lock().expect("mock").post_hook.take();
            if let Some((entered, release)) = hook {
                entered.wait();
                release.wait();
            }
            let mut state = self.0.lock().expect("mock");
            if let Some(error) = &state.post_error {
                return Err(error.clone());
            }
            state.posts += 1;
            if let Some(target) = state.post_target.take() {
                state.target = target;
            }
            Ok(())
        }

        fn screen_locked(&self) -> Result<bool, String> {
            Ok(self.0.lock().expect("mock").locked)
        }
    }

    fn target(pid: i32, window_id: u32, display_id: u32, bounds: DesktopRect) -> DesktopTarget {
        DesktopTarget {
            application: "Fixture App".into(),
            bundle_id: Some("org.example.fixture".into()),
            pid,
            window_id,
            window_title: "Fixture Window".into(),
            bounds,
            display_id,
        }
    }

    fn manager(platform: Arc<MockPlatform>) -> DesktopManager {
        DesktopManager::new(
            platform,
            Duration::from_millis(40),
            Duration::from_millis(40),
        )
    }

    fn armed(platform: Arc<MockPlatform>) -> DesktopManager {
        platform.0.lock().expect("mock").trusted = true;
        let manager = manager(platform);
        let selected = manager
            .select_frontmost("project-a".into())
            .expect("select");
        assert_eq!(selected.phase, DesktopPhase::TargetSelected);
        manager.arm_selected("project-a", 501).expect("arm");
        manager
    }

    #[test]
    fn accessibility_async_prompt_is_pending_not_denied_and_never_arms() {
        let platform = MockPlatform::new();
        platform.0.lock().expect("mock").request_grants = false;
        let manager = manager(Arc::clone(&platform));
        let off = manager.status();
        assert_eq!(off.phase, DesktopPhase::Off);
        assert!(off.last_refusal.is_none());
        manager
            .select_frontmost("project-a".into())
            .expect("select");
        let pending = manager
            .arm_selected("project-a", 501)
            .expect("permission prompt remains pending");
        assert_eq!(pending.phase, DesktopPhase::TargetSelected);
        assert_eq!(pending.permission, DesktopPermission::NotDeterminedOrDenied);
        assert!(pending.detail.contains("permission was requested"));
        assert!(pending.detail.contains("remains Off"));
        assert!(pending.last_refusal.is_none());
        assert!(pending.pending_target.is_some());
        assert!(pending.target.is_none());
        assert!(!pending.stop_visible);
        {
            let state = platform.0.lock().expect("mock");
            assert_eq!(state.requests, 1);
            assert_eq!(state.posts, 0);
        }

        let still_pending = manager
            .arm_selected("project-a", 501)
            .expect("second false preflight remains pending");
        assert_eq!(still_pending.phase, DesktopPhase::TargetSelected);
        assert!(still_pending.detail.contains("still unavailable"));
        assert!(still_pending.last_refusal.is_none());
        assert!(!still_pending.stop_visible);
        assert_eq!(platform.0.lock().expect("mock").requests, 1);
    }

    #[test]
    fn accessibility_second_arm_requires_fresh_trust_before_grant() {
        let platform = MockPlatform::new();
        let manager = manager(Arc::clone(&platform));
        manager
            .select_frontmost("project-a".into())
            .expect("select");

        let first = manager
            .arm_selected("project-a", 501)
            .expect("asynchronous prompt remains pending");
        assert_eq!(first.phase, DesktopPhase::TargetSelected);
        assert!(!first.stop_visible);
        assert!(platform.0.lock().expect("mock").trusted);

        let second = manager
            .arm_selected("project-a", 501)
            .expect("fresh trusted preflight arms");
        assert_eq!(second.phase, DesktopPhase::Armed);
        assert_eq!(second.permission, DesktopPermission::Authorized);
        assert!(second.stop_visible);
        assert!(second.pending_target.is_none());
        assert!(second.target.is_some());
        assert_eq!(platform.0.lock().expect("mock").requests, 1);
    }

    #[test]
    fn action_binds_run_and_reports_only_event_posting() {
        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        let result = manager
            .agent_action(
                "project-a",
                "run-a",
                &DesktopAction::Click {
                    x: 12.0,
                    y: 14.0,
                    button: DesktopMouseButton::Left,
                },
            )
            .expect("click post");
        assert!(result.contains("event posted"));
        assert!(result.contains("completion is unknown"));
        let view = manager.status();
        assert_eq!(view.run_id.as_deref(), Some("run-a"));
        assert_eq!(platform.0.lock().expect("mock").posts, 1);
        let refusal = manager
            .agent_action(
                "project-a",
                "run-b",
                &DesktopAction::Key {
                    key: "Enter".into(),
                    modifiers: Vec::new(),
                },
            )
            .expect_err("second run refused");
        assert!(refusal.contains("another run"));
    }

    #[test]
    fn focus_pid_window_display_and_geometry_drift_fail_closed() {
        for changed in [
            target(
                202,
                501,
                44,
                DesktopRect {
                    x: 10.0,
                    y: 20.0,
                    width: 800.0,
                    height: 600.0,
                },
            ),
            target(
                101,
                777,
                44,
                DesktopRect {
                    x: 10.0,
                    y: 20.0,
                    width: 800.0,
                    height: 600.0,
                },
            ),
            target(
                101,
                501,
                55,
                DesktopRect {
                    x: 10.0,
                    y: 20.0,
                    width: 800.0,
                    height: 600.0,
                },
            ),
            target(
                101,
                501,
                44,
                DesktopRect {
                    x: 10.0,
                    y: 20.0,
                    width: 801.0,
                    height: 600.0,
                },
            ),
        ] {
            let platform = MockPlatform::new();
            let manager = armed(Arc::clone(&platform));
            platform.0.lock().expect("mock").target = changed;
            let error = manager
                .agent_action(
                    "project-a",
                    "run-a",
                    &DesktopAction::Key {
                        key: "Enter".into(),
                        modifiers: Vec::new(),
                    },
                )
                .expect_err("drift refused");
            assert!(error.contains("changed before"));
            assert_eq!(manager.status().phase, DesktopPhase::Failed);
            assert_eq!(platform.0.lock().expect("mock").posts, 0);
        }
    }

    #[test]
    fn post_failure_and_immediate_post_drift_are_not_success() {
        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        platform.0.lock().expect("mock").post_error = Some("fixture post failed".into());
        let error = manager
            .agent_action(
                "project-a",
                "run-a",
                &DesktopAction::Type { text: "x".into() },
            )
            .expect_err("post failure");
        assert!(error.contains("fixture post failed"));
        assert_eq!(manager.status().phase, DesktopPhase::Failed);

        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        platform.0.lock().expect("mock").post_target = Some(target(
            101,
            501,
            44,
            DesktopRect {
                x: 11.0,
                y: 20.0,
                width: 800.0,
                height: 600.0,
            },
        ));
        let error = manager
            .agent_action(
                "project-a",
                "run-a",
                &DesktopAction::Scroll {
                    delta_x: 0,
                    delta_y: 100,
                },
            )
            .expect_err("post drift");
        assert!(error.contains("immediately afterward"));
        assert_eq!(manager.status().phase, DesktopPhase::Failed);
    }

    #[test]
    fn lock_expiry_project_switch_and_run_end_clear_without_red_off() {
        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        platform.0.lock().expect("mock").locked = true;
        let view = manager.status();
        assert_eq!(view.phase, DesktopPhase::Off);
        assert!(view.last_refusal.is_none());

        let platform = MockPlatform::new();
        let manager = armed(platform);
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(manager.status().phase, DesktopPhase::Off);

        let platform = MockPlatform::new();
        let manager = armed(platform);
        manager.project_switched(Some("project-b"));
        assert_eq!(manager.status().phase, DesktopPhase::Off);

        let platform = MockPlatform::new();
        let manager = armed(platform);
        manager.bind_run("project-a", "run-a").expect("bind run");
        manager.finish_run("run-a");
        assert_eq!(manager.status().phase, DesktopPhase::Off);
    }

    #[test]
    fn action_inputs_are_strictly_bounded() {
        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        let outside = manager
            .agent_action(
                "project-a",
                "run-a",
                &DesktopAction::Click {
                    x: 900.0,
                    y: 1.0,
                    button: DesktopMouseButton::Left,
                },
            )
            .expect_err("outside click");
        assert!(outside.contains("inside the armed window"));
        assert_eq!(platform.0.lock().expect("mock").posts, 0);
        assert!(!allowed_key("F12"));
        assert!(allowed_key("a"));
        assert!(allowed_key("Enter"));
    }

    #[test]
    fn project_switch_supersedes_inflight_target_selection_and_arm() {
        let platform = MockPlatform::new();
        let manager = manager(Arc::clone(&platform));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        platform.0.lock().expect("mock").snapshot_hook =
            Some((Arc::clone(&entered), Arc::clone(&release)));
        let worker = manager.clone();
        let selection = std::thread::spawn(move || worker.select_frontmost("project-a".into()));
        entered.wait();
        manager.project_switched(Some("project-b"));
        release.wait();
        assert!(selection.join().expect("selection thread").is_err());
        assert_eq!(manager.status().phase, DesktopPhase::Off);

        manager
            .select_frontmost("project-b".into())
            .expect("fresh selection");
        platform.0.lock().expect("mock").trusted = true;
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        platform.0.lock().expect("mock").snapshot_hook =
            Some((Arc::clone(&entered), Arc::clone(&release)));
        let worker = manager.clone();
        let arm = std::thread::spawn(move || worker.arm_selected("project-b", 501));
        entered.wait();
        manager.project_switched(Some("project-c"));
        release.wait();
        assert!(arm.join().expect("arm thread").is_err());
        let view = manager.status();
        assert_eq!(view.phase, DesktopPhase::Off);
        assert!(!view.stop_visible);
    }

    #[test]
    fn visible_stop_is_serialized_with_the_single_native_event_boundary() {
        let platform = MockPlatform::new();
        let manager = armed(Arc::clone(&platform));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        platform.0.lock().expect("mock").post_hook =
            Some((Arc::clone(&entered), Arc::clone(&release)));
        let action_manager = manager.clone();
        let action = std::thread::spawn(move || {
            action_manager.agent_action(
                "project-a",
                "run-a",
                &DesktopAction::Key {
                    key: "Enter".into(),
                    modifiers: Vec::new(),
                },
            )
        });
        entered.wait();
        let (stopped_tx, stopped_rx) = std::sync::mpsc::sync_channel(1);
        let stop_manager = manager.clone();
        let stop = std::thread::spawn(move || {
            let result = stop_manager.stop("Visible Stop selected during dispatch.");
            let _ = stopped_tx.send(());
            result
        });
        assert!(
            stopped_rx.try_recv().is_err(),
            "Stop must not revoke midway through one native event dispatch"
        );
        release.wait();
        action.join().expect("action thread").expect("action");
        stop.join().expect("stop thread").expect("stop");
        assert_eq!(manager.status().phase, DesktopPhase::Off);
        assert_eq!(platform.0.lock().expect("mock").posts, 1);
    }
}
