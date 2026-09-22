//! Guest lifecycle classification and safe Colima / install-root actions.
//!
//! Status words and action labels are I/O-free. Probes and `colima start`
//! stay separate so tests can drive fixtures without faking a terminal.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use super::PlusSessionStore;

/// Versioned app-managed Colima and Lima runtime below the desktop state root.
pub const PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE: &str =
    "runtime-assets/command-security/colima-0.10.3-lima-2.2.0";
/// Exact app-managed Colima executable relative to the runtime root.
pub const PLUS_MANAGED_COLIMA_RELATIVE: &str = "colima";
/// Exact app-managed Lima executable relative to the runtime root.
pub const PLUS_MANAGED_LIMACTL_RELATIVE: &str = "lima/bin/limactl";
/// App-owned Colima profile created only by an explicit setup action.
pub const PLUS_MANAGED_COLIMA_HOME_RELATIVE: &str = "runtime-assets/command-security/colima-home";

const COLIMA_INHERITED_ENVIRONMENT: &[&str] = &[
    "COLIMA_HOME",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "USER",
    "XDG_CONFIG_HOME",
];
pub(crate) const COLIMA_BASE_PATH: &str =
    "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

static MANAGED_CONTAINER_RUNTIME_VERIFIED: AtomicBool = AtomicBool::new(false);

/// Makes the fixed app-managed runtime discoverable only after its owner has
/// verified the complete tree in this process.
pub fn set_managed_container_runtime_verified(verified: bool) {
    MANAGED_CONTAINER_RUNTIME_VERIFIED.store(verified, Ordering::Release);
}

/// Fixed production location of the optional app-managed container runtime.
#[must_use]
pub fn managed_container_runtime_root() -> PathBuf {
    PlusSessionStore::documented_desktop_state_root().join(PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE)
}

/// Fixed production location of the optional app-managed Colima profile.
#[must_use]
pub fn managed_colima_home() -> PathBuf {
    PlusSessionStore::documented_desktop_state_root().join(PLUS_MANAGED_COLIMA_HOME_RELATIVE)
}

#[doc(hidden)]
pub fn apply_colima_child_environment(command: &mut Command) {
    let managed_binary = managed_container_runtime_root().join(PLUS_MANAGED_COLIMA_RELATIVE);
    let uses_managed_runtime = command.get_program() == managed_binary.as_os_str()
        || fs::canonicalize(&managed_binary)
            .is_ok_and(|path| command.get_program() == path.as_os_str());
    command.env_clear();
    for name in COLIMA_INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut paths = Vec::new();
    if uses_managed_runtime {
        paths.push(managed_container_runtime_root().join("lima/bin"));
        command.env("COLIMA_HOME", managed_colima_home());
    }
    paths.extend(std::env::split_paths(COLIMA_BASE_PATH));
    if let Ok(joined) = std::env::join_paths(paths) {
        command.env("PATH", joined);
    }
}

/// Window / smoke status: Colima (or the Linux guest) is not usable.
pub const PLUS_GUEST_STATUS_DOWN: &str = "guest down";

/// Window / smoke status: guest is up but the installed service is not.
pub const PLUS_GUEST_STATUS_SERVICE_MISSING: &str = "service missing";

/// Window / smoke status: guest + installed service can take a contained Run.
pub const PLUS_GUEST_STATUS_READY: &str = "ready";

/// Window action: start Colima only when that would not clobber a profile.
pub const PLUS_GUEST_ACTION_START_COLIMA: &str = "start Colima (if safe)";

/// Window action: report whether the install-root handoff is present.
pub const PLUS_GUEST_ACTION_VERIFY_INSTALL: &str = "verify install root";

/// Window action: how to repair a down or missing-service guest.
pub const PLUS_GUEST_ACTION_REPAIR_HINTS: &str = "repair hints";

/// One-step prepare: safe Colima start, then verify install root, then repair.
pub const PLUS_GUEST_ACTION_PREPARE: &str = "prepare guest";

/// Observed facts used to classify guest lifecycle without running a command.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each field is an independently observed lifecycle fact retained for exact refusal reasons"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGuestFacts {
    /// This process is already Linux (the guest).
    pub on_linux: bool,
    /// `colima` is on PATH (macOS).
    pub colima_present: bool,
    /// `colima status` reports running.
    pub colima_running: bool,
    /// Install root has `handoff-commitment.v1.json`.
    pub install_root_has_handoff: bool,
    /// Linux `grok-build-runner` is present.
    pub runner_present: bool,
    /// Linux `grok-build --plus-guest-contained` helper is present (macOS).
    pub helper_present: bool,
    /// This process can enter the sibling harness cgroup the installed
    /// service requires (`/gbd-phase1/service`, not `user.slice` and not `svc`).
    pub harness_cgroup_usable: bool,
}

/// One of the three window status words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusGuestLifecycleKind {
    /// Guest VM / Colima is down or missing.
    GuestDown,
    /// Guest is up; installed service / helper / runner is not.
    ServiceMissing,
    /// Guest + service can take a contained Run.
    Ready,
}

/// I/O-free: map observed facts onto **guest down** / **service missing** / **ready**.
#[must_use]
pub fn classify_plus_guest_lifecycle(facts: &PlusGuestFacts) -> PlusGuestLifecycleKind {
    if facts.on_linux {
        if facts.install_root_has_handoff && facts.runner_present && facts.harness_cgroup_usable {
            PlusGuestLifecycleKind::Ready
        } else {
            PlusGuestLifecycleKind::ServiceMissing
        }
    } else if !facts.colima_present || !facts.colima_running {
        PlusGuestLifecycleKind::GuestDown
    } else if facts.install_root_has_handoff
        && facts.runner_present
        && facts.helper_present
        && facts.harness_cgroup_usable
    {
        PlusGuestLifecycleKind::Ready
    } else {
        PlusGuestLifecycleKind::ServiceMissing
    }
}

/// Verbatim status word for one lifecycle kind.
#[must_use]
pub fn present_plus_guest_lifecycle_kind(kind: PlusGuestLifecycleKind) -> &'static str {
    match kind {
        PlusGuestLifecycleKind::GuestDown => PLUS_GUEST_STATUS_DOWN,
        PlusGuestLifecycleKind::ServiceMissing => PLUS_GUEST_STATUS_SERVICE_MISSING,
        PlusGuestLifecycleKind::Ready => PLUS_GUEST_STATUS_READY,
    }
}

/// Facts that decide whether `colima start` is allowed.
#[allow(
    clippy::struct_excessive_bools,
    reason = "start admission preserves each independent preflight fact instead of collapsing them into a lossy state"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColimaStartFacts {
    /// `colima` binary exists.
    pub colima_present: bool,
    /// `colima status` reports running.
    pub colima_running: bool,
    /// `COLIMA_HOME` is set (operator opted into a specific profile).
    pub colima_home_set: bool,
    /// That `COLIMA_HOME` directory already exists.
    pub colima_home_exists: bool,
    /// Start would clobber a foreign / unconfigured profile.
    pub foreign_profile_conflict: bool,
}

/// I/O-free: `colima start` is refused when missing, already running, or unsafe.
///
/// # Errors
///
/// Returns why start is unsafe. The caller must not invoke `colima start`.
pub fn colima_start_is_safe(facts: &ColimaStartFacts) -> Result<(), String> {
    if !facts.colima_present {
        return Err("colima is missing; start Colima (if safe) refuses to invent a binary".into());
    }
    if facts.colima_running {
        return Err("colima is already running; start Colima (if safe) will not restart it".into());
    }
    if !facts.colima_home_set {
        return Err(
            "COLIMA_HOME is unset; start Colima (if safe) refuses to clobber the default profile"
                .into(),
        );
    }
    if !facts.colima_home_exists {
        return Err(
            "COLIMA_HOME does not exist; start Colima (if safe) refuses to create a new profile"
                .into(),
        );
    }
    if facts.foreign_profile_conflict {
        return Err(
            "start Colima (if safe) refuses: start would clobber a foreign Colima profile".into(),
        );
    }
    Ok(())
}

/// Observe `colima` / `COLIMA_HOME` for [`colima_start_is_safe`].
#[must_use]
pub fn observe_colima_start_facts() -> ColimaStartFacts {
    let colima = resolve_colima_binary();
    let colima_present = colima.is_some();
    let colima_running = colima
        .as_ref()
        .is_some_and(|path| colima_status_running(path));
    let colima_home = effective_colima_home(colima.as_deref());
    let colima_home_set = colima_home.is_some();
    let colima_home_exists = colima_home.as_ref().is_some_and(|path| path.is_dir());
    ColimaStartFacts {
        colima_present,
        colima_running,
        colima_home_set,
        colima_home_exists,
        foreign_profile_conflict: false,
    }
}

fn effective_colima_home(colima: Option<&Path>) -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("COLIMA_HOME").map(PathBuf::from) {
        return Some(configured);
    }
    let managed_binary = managed_container_runtime_root().join(PLUS_MANAGED_COLIMA_RELATIVE);
    if colima.is_some_and(|path| {
        path == managed_binary
            || fs::canonicalize(&managed_binary).is_ok_and(|managed| path == managed)
    }) {
        return Some(managed_colima_home());
    }
    None
}

/// Start Colima only when [`colima_start_is_safe`] agrees.
///
/// # Errors
///
/// Returns the safety refusal or the `colima start` failure. Never starts
/// when Colima is missing, already running, or would clobber a profile.
pub fn start_colima_if_safe() -> Result<String, String> {
    let facts = observe_colima_start_facts();
    colima_start_is_safe(&facts)?;
    let colima = resolve_colima_binary().ok_or_else(|| {
        "colima is missing; start Colima (if safe) refuses to invent a binary".to_owned()
    })?;
    let mut command = Command::new(&colima);
    apply_colima_child_environment(&mut command);
    let output = command
        .arg("start")
        .output()
        .map_err(|error| format!("colima start failed to spawn: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut text = format!("{PLUS_GUEST_ACTION_START_COLIMA}\n{stdout}{stderr}");
    if !output.status.success() {
        let _ = writeln!(text, "colima start exited {}", output.status);
        return Err(text);
    }
    Ok(text)
}

/// Result of [`verify_install_root`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusInstallRootReport {
    /// Path that was checked.
    pub root: PathBuf,
    /// `handoff-commitment.v1.json` is present.
    pub handoff_present: bool,
    /// How the check was performed.
    pub via: String,
}

/// I/O-free presentation of an install-root check.
#[must_use]
pub fn present_install_root_report(report: &PlusInstallRootReport) -> String {
    if report.handoff_present {
        format!(
            "{PLUS_GUEST_ACTION_VERIFY_INSTALL}: handoff present at {} ({})",
            report.root.display(),
            report.via
        )
    } else {
        format!(
            "{PLUS_GUEST_ACTION_VERIFY_INSTALL}: missing handoff at {} ({})",
            report.root.display(),
            report.via
        )
    }
}

/// Check that `root/handoff-commitment.v1.json` exists. Missing is honest.
#[must_use]
pub fn verify_install_root(root: &Path) -> PlusInstallRootReport {
    let handoff = root.join("handoff-commitment.v1.json");
    PlusInstallRootReport {
        root: root.to_path_buf(),
        handoff_present: root.is_absolute() && handoff.is_file(),
        via: "local path".into(),
    }
}

/// I/O-free one-step prepare report. Does not start Colima; callers pass the
/// start result (including a safety refusal).
#[must_use]
pub fn present_plus_guest_prepare(
    start: Result<&str, &str>,
    install: &PlusInstallRootReport,
    kind: PlusGuestLifecycleKind,
) -> String {
    let mut lines = vec![PLUS_GUEST_ACTION_PREPARE.to_owned()];
    match start {
        Ok(text) => lines.push(format!("{PLUS_GUEST_ACTION_START_COLIMA}: {text}")),
        Err(text) => lines.push(format!("{PLUS_GUEST_ACTION_START_COLIMA} refused: {text}")),
    }
    lines.push(present_install_root_report(install));
    lines.push(present_plus_guest_lifecycle_kind(kind).to_owned());
    if kind != PlusGuestLifecycleKind::Ready {
        lines.push(present_plus_guest_repair_hints(kind));
    }
    lines.push(format!(
        "{PLUS_GUEST_ACTION_START_COLIMA} / {PLUS_GUEST_ACTION_VERIFY_INSTALL} / {PLUS_GUEST_ACTION_REPAIR_HINTS}"
    ));
    lines.join("\n")
}

/// Repair copy for a non-ready lifecycle. Includes the action labels.
#[must_use]
pub fn present_plus_guest_repair_hints(kind: PlusGuestLifecycleKind) -> String {
    let mut lines = vec![PLUS_GUEST_ACTION_REPAIR_HINTS.to_owned()];
    match kind {
        PlusGuestLifecycleKind::Ready => {
            lines.push("guest is ready; no repair required".into());
        }
        PlusGuestLifecycleKind::GuestDown => {
            lines.push(format!(
                "{PLUS_GUEST_STATUS_DOWN}: Colima is missing or stopped. Use the primary setup action in Checks."
            ));
        }
        PlusGuestLifecycleKind::ServiceMissing => {
            lines.push(format!(
                "{PLUS_GUEST_STATUS_SERVICE_MISSING}: choose Set up container to install and verify the bundled runner."
            ));
        }
    }
    lines.join("\n")
}

#[doc(hidden)]
pub fn resolve_colima_binary() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("GROK_BUILD_COLIMA_BIN") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return path.canonicalize().ok();
        }
    }
    let managed = managed_container_runtime_root().join(PLUS_MANAGED_COLIMA_RELATIVE);
    if MANAGED_CONTAINER_RUNTIME_VERIFIED.load(Ordering::Acquire) && managed.is_file() {
        return managed.canonicalize().ok();
    }
    let mut command = Command::new("which");
    apply_colima_child_environment(&mut command);
    let output = command.arg("colima").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(path.trim());
    path.is_file().then_some(path)
}

#[doc(hidden)]
#[must_use]
pub fn colima_status_running(colima: &Path) -> bool {
    let mut command = Command::new(colima);
    apply_colima_child_environment(&mut command);
    let Ok(output) = command.arg("status").output() else {
        return false;
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output.status.success() && text.contains("is running")
}
