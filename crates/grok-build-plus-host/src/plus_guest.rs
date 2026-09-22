//! Guest health and labeled fallback for plus contained Run.
//!
//! Presentation is I/O-free. Health probes Colima / a local Linux
//! installed-service anchor. The Mac desktop does not mint a permit.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::plus_lifecycle::{
    PLUS_GUEST_ACTION_REPAIR_HINTS, PLUS_GUEST_ACTION_START_COLIMA,
    PLUS_GUEST_ACTION_VERIFY_INSTALL, PLUS_GUEST_STATUS_DOWN, PLUS_GUEST_STATUS_READY,
    PLUS_GUEST_STATUS_SERVICE_MISSING, PlusGuestFacts, PlusGuestLifecycleKind,
    apply_colima_child_environment, classify_plus_guest_lifecycle, colima_start_is_safe,
    observe_colima_start_facts, present_plus_guest_lifecycle_kind, present_plus_guest_prepare,
    present_plus_guest_repair_hints, start_colima_if_safe,
};
#[cfg(target_os = "macos")]
use super::plus_lifecycle::{colima_status_running, resolve_colima_binary};
use super::plus_probe::plus_presentation_is_known_good_terminal;
use super::plus_refusals::present_plus_guest_refusal_prefix;
use super::{CommandOutcomeClass, PresentedCommandOutcome};

/// Env: absolute Linux native-service install root.
pub const PLUS_GUEST_INSTALL_ROOT_ENV: &str = "GROK_BUILD_LINUX_NATIVE_SERVICE_INSTALL_ROOT";

/// Env: Linux `grok-build` helper on the guest (Mac → Colima only).
pub const PLUS_GUEST_HELPER_ENV: &str = "GROK_BUILD_PLUS_GUEST_HELPER";

/// Env: `grok-build-runner` the installed-service session should exec.
pub const PLUS_GUEST_RUNNER_ENV: &str = "GROK_BUILD_RUNNER_BINARY";

/// Default install root used by the Phase 1 12/12 drive on this guest.
pub const PLUS_DEFAULT_INSTALL_ROOT: &str = "/opt/grok-build/phase1/install";

/// Native-only macOS launch (ADR-0011) when the guest path is down.
pub const PLUS_NATIVE_MACOS_ONLY: &str = "native macOS-only: contained launch needs fexecve/execveat, which this Mac does not provide (ADR-0011). /dev/fd is not admitted.";

/// Guest/installed-service path is not usable.
pub const PLUS_GUEST_UNAVAILABLE: &str = "guest/installed-service contained path is unavailable";

/// How to make the Mac → guest contained path work. Not 12/12 on nested Docker.
pub const PLUS_GUEST_HOW_TO_FIX: &str = "How to fix: choose Set up container in Checks. It installs and verifies the bundled Linux runner in Colima. Nested Docker is not supported.";

/// Mac plus Run used `colima ssh -- <helper> --plus-guest-contained`.
pub const PLUS_GUEST_VIA_COLIMA: &str =
    "via Colima guest: colima ssh -- grok-build --plus-guest-contained";

/// Linux helper used the installed-service session launch.
pub const PLUS_GUEST_VIA_INSTALLED_SESSION: &str =
    "via Linux installed-service: launch_linux_installed_service_session";

/// Versioned helper argument that makes process status carry typed authority.
pub const PLUS_GUEST_TYPED_OUTCOME_FLAG: &str = "--plus-typed-outcome-v1";

/// Where the installed-service runner will execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusGuestKind {
    /// This process is already on the qualified Linux host.
    Local,
    /// This process is macOS; exec happens on Colima via SSH.
    Remote,
}

/// Healthy guest/installed-service target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGuestTarget {
    /// Local Linux vs Mac → Colima.
    pub kind: PlusGuestKind,
    /// `--linux-native-service-install-root`.
    pub install_root: PathBuf,
    /// Linux `grok-build-runner` to exec with that flag.
    pub runner: PathBuf,
    /// Linux `grok-build --plus-guest-contained` (remote only).
    pub helper: Option<PathBuf>,
    /// `colima` binary (remote only).
    pub colima: Option<PathBuf>,
}

/// Why the guest path cannot be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGuestUnavailable {
    /// One line per missing piece.
    pub reasons: Vec<String>,
}

/// Probe result. Health is I/O; presentation of a down result is not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusGuestHealth {
    /// Guest (or local Linux service) can take a contained Run.
    Available(PlusGuestTarget),
    /// Use labeled native fallback.
    Unavailable(PlusGuestUnavailable),
}

/// Guest lifecycle with the three window status words.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlusGuestLifecycle {
    /// Colima / guest VM is down or missing.
    GuestDown {
        /// Why the guest is down.
        reasons: Vec<String>,
    },
    /// Guest is up; installed service / helper / runner is not.
    ServiceMissing {
        /// Why the service is missing.
        reasons: Vec<String>,
    },
    /// Guest + installed service can take a contained Run.
    Ready(PlusGuestTarget),
}

impl PlusGuestLifecycle {
    /// The matching status word.
    #[must_use]
    pub fn kind(&self) -> PlusGuestLifecycleKind {
        match self {
            Self::GuestDown { .. } => PlusGuestLifecycleKind::GuestDown,
            Self::ServiceMissing { .. } => PlusGuestLifecycleKind::ServiceMissing,
            Self::Ready(_) => PlusGuestLifecycleKind::Ready,
        }
    }
}

/// Typed reason a guest/installed-service observation is not ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlusGuestFailureKind {
    /// This build target has no supported guest path.
    UnsupportedPlatform,
    /// Colima or the local service runtime is absent.
    RuntimeMissing,
    /// The runtime exists but is not running.
    RuntimeDown,
    /// The service handoff anchor is absent.
    InstallRootMissing,
    /// The Linux Grok Build helper is absent.
    HelperMissing,
    /// The helper lacks the required typed protocol.
    HelperIncompatible,
    /// The runner executable is absent.
    RunnerMissing,
    /// The sibling containment cgroup cannot be used.
    HarnessUnavailable,
    /// Discovery failed outside a recognized predicate.
    DiscoveryFailed,
}

/// One typed guest failure with unchanged user-facing detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGuestFailure {
    /// Machine-readable failed predicate.
    pub kind: PlusGuestFailureKind,
    /// Existing bounded user-facing detail.
    pub detail: String,
}

/// One I/O observation projected into facts, lifecycle, target, and failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlusGuestObservation {
    /// Facts consumed by lifecycle policy.
    pub facts: PlusGuestFacts,
    /// User-facing lifecycle projection.
    pub lifecycle: PlusGuestLifecycle,
    /// Exact ready target, when available.
    pub target: Option<PlusGuestTarget>,
    /// Typed failures, empty only when ready.
    pub failures: Vec<PlusGuestFailure>,
}

/// True when presented text is a real wire command terminal, not a launch
/// refusal and not a fabricated green.
#[must_use]
pub fn plus_outcome_is_real_command_terminal(text: &str) -> bool {
    let has_terminal = text.contains("Command succeeded")
        || text.contains("Command timed out")
        || text.contains("Command failed")
        || text.contains("Command finished")
        || text.contains("CommandCompleted")
        || text.contains("CommandFailed")
        || text.contains("TimedOut")
        || text.contains("Command output abandoned");
    has_terminal && !text.contains("FakeProvider")
}

/// I/O-free: name which guest launch the presented terminal came from.
///
/// Callers must only pass a known-good success or `TimedOut` terminal.
#[must_use]
pub fn present_plus_guest_available_outcome(kind: PlusGuestKind, terminal: &str) -> String {
    match kind {
        PlusGuestKind::Local => {
            format!("{PLUS_GUEST_STATUS_READY}\n{PLUS_GUEST_VIA_INSTALLED_SESSION}\n{terminal}")
        }
        PlusGuestKind::Remote => {
            format!("{PLUS_GUEST_STATUS_READY}\n{PLUS_GUEST_VIA_COLIMA}\n{terminal}")
        }
    }
}

/// Adds the existing guest-path presentation without changing typed authority.
#[must_use]
pub fn present_plus_guest_available_typed(
    kind: PlusGuestKind,
    outcome: PresentedCommandOutcome,
) -> PresentedCommandOutcome {
    let text = present_plus_guest_available_outcome(kind, &outcome.text);
    outcome.with_text(text)
}

/// I/O-free: Ready only for Command succeeded / `TimedOut`. A real Command
/// failed from the installed-service path is **service missing**, not ready.
#[must_use]
pub fn present_plus_guest_contained_result(kind: PlusGuestKind, terminal: &str) -> String {
    if plus_presentation_is_known_good_terminal(terminal) {
        if terminal.contains(PLUS_GUEST_STATUS_READY) {
            return terminal.to_owned();
        }
        return present_plus_guest_available_outcome(kind, terminal);
    }
    if terminal.contains(PLUS_GUEST_STATUS_DOWN)
        || terminal.contains(PLUS_GUEST_STATUS_SERVICE_MISSING)
    {
        return terminal.to_owned();
    }
    present_plus_guest_unavailable_outcome_with_kind(
        PlusGuestLifecycleKind::ServiceMissing,
        "",
        &PlusGuestUnavailable {
            reasons: vec![
                "installed service did not produce a known-good contained terminal".into(),
                terminal.to_owned(),
            ],
        },
    )
}

/// Typed guest-path presentation. Display markers cannot alter authority.
#[must_use]
pub fn present_plus_guest_contained_typed(
    kind: PlusGuestKind,
    outcome: PresentedCommandOutcome,
) -> PresentedCommandOutcome {
    if outcome.class.is_known_good_terminal() {
        return present_plus_guest_available_typed(kind, outcome);
    }
    let text = present_plus_guest_unavailable_outcome_with_kind(
        PlusGuestLifecycleKind::ServiceMissing,
        "",
        &PlusGuestUnavailable {
            reasons: vec![
                "installed service did not produce a known-good contained terminal".into(),
                outcome.text.clone(),
            ],
        },
    );
    let class = if outcome.class == CommandOutcomeClass::Refused {
        CommandOutcomeClass::Refused
    } else {
        CommandOutcomeClass::Error
    };
    outcome.with_text(text).with_class(class)
}

/// I/O-free: label a native/setup refusal when the guest path is down.
#[must_use]
pub fn present_plus_guest_unavailable_outcome(
    native_or_setup: &str,
    report: &PlusGuestUnavailable,
) -> String {
    let kind = infer_unavailable_kind(report);
    present_plus_guest_unavailable_outcome_with_kind(kind, native_or_setup, report)
}

/// I/O-free: same as [`present_plus_guest_unavailable_outcome`] with an explicit status word.
#[must_use]
pub fn present_plus_guest_unavailable_outcome_with_kind(
    kind: PlusGuestLifecycleKind,
    native_or_setup: &str,
    report: &PlusGuestUnavailable,
) -> String {
    if plus_outcome_is_real_command_terminal(native_or_setup)
        && !plus_presentation_is_known_good_terminal(native_or_setup)
    {
        return native_or_setup.to_owned();
    }
    #[cfg(target_os = "macos")]
    let mut lines = vec![
        present_plus_guest_refusal_prefix(kind),
        present_plus_guest_lifecycle_kind(kind).to_owned(),
        PLUS_NATIVE_MACOS_ONLY.to_owned(),
        PLUS_GUEST_UNAVAILABLE.to_owned(),
    ];
    #[cfg(not(target_os = "macos"))]
    let mut lines = vec![
        present_plus_guest_refusal_prefix(kind),
        present_plus_guest_lifecycle_kind(kind).to_owned(),
        PLUS_GUEST_UNAVAILABLE.to_owned(),
    ];
    for reason in &report.reasons {
        if !reason.is_empty() {
            lines.push(reason.clone());
        }
    }
    if !native_or_setup.is_empty() && !plus_presentation_is_known_good_terminal(native_or_setup) {
        lines.push(native_or_setup.to_owned());
    }
    lines.push(format!(
        "{PLUS_GUEST_ACTION_START_COLIMA} / {PLUS_GUEST_ACTION_VERIFY_INSTALL} / {PLUS_GUEST_ACTION_REPAIR_HINTS}"
    ));
    lines.push(present_plus_guest_repair_hints(kind));
    lines.push(PLUS_GUEST_HOW_TO_FIX.to_owned());
    lines.join("\n")
}

/// I/O-free panel for smoke / the window Guest surface.
#[must_use]
pub fn present_plus_guest_lifecycle(lifecycle: &PlusGuestLifecycle) -> String {
    let kind = lifecycle.kind();
    let mut lines = Vec::new();
    if kind != PlusGuestLifecycleKind::Ready {
        lines.push(present_plus_guest_refusal_prefix(kind));
    }
    lines.push(present_plus_guest_lifecycle_kind(kind).to_owned());
    match lifecycle {
        PlusGuestLifecycle::Ready(target) => {
            lines.push(format!("install root {}", target.install_root.display()));
        }
        PlusGuestLifecycle::GuestDown { reasons }
        | PlusGuestLifecycle::ServiceMissing { reasons } => {
            lines.extend(reasons.iter().cloned());
            lines.push(present_plus_guest_repair_hints(kind));
            lines.push(PLUS_GUEST_HOW_TO_FIX.to_owned());
        }
    }
    lines.push(format!(
        "{PLUS_GUEST_ACTION_START_COLIMA} / {PLUS_GUEST_ACTION_VERIFY_INSTALL} / {PLUS_GUEST_ACTION_REPAIR_HINTS}"
    ));
    lines.join("\n")
}

/// Probe Colima / local Linux installed-service as a three-state lifecycle.
#[must_use]
pub fn probe_plus_guest_lifecycle() -> PlusGuestLifecycle {
    observe_plus_guest().lifecycle
}

fn infer_unavailable_kind(report: &PlusGuestUnavailable) -> PlusGuestLifecycleKind {
    let blob = report.reasons.join(" ");
    if blob.contains("colima is not")
        || blob.contains("colima ssh")
        || blob.contains("this compile target")
    {
        PlusGuestLifecycleKind::GuestDown
    } else {
        PlusGuestLifecycleKind::ServiceMissing
    }
}

/// Observe the facts consumed by guest lifecycle policy.
#[must_use]
pub fn observe_plus_guest_facts() -> PlusGuestFacts {
    observe_plus_guest().facts
}

/// Performs exactly one platform guest probe and projects all guest state.
#[must_use]
pub fn observe_plus_guest() -> PlusGuestObservation {
    #[cfg(target_os = "linux")]
    {
        observe_linux_guest()
    }
    #[cfg(target_os = "macos")]
    {
        observe_macos_guest()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        unavailable_observation(
            PlusGuestFacts {
                on_linux: false,
                colima_present: false,
                colima_running: false,
                install_root_has_handoff: false,
                runner_present: false,
                helper_present: false,
                harness_cgroup_usable: false,
            },
            vec![PlusGuestFailure {
                kind: PlusGuestFailureKind::UnsupportedPlatform,
                detail: "this compile target has no guest or Linux installed-service probe".into(),
            }],
        )
    }
}

fn unavailable_observation(
    facts: PlusGuestFacts,
    failures: Vec<PlusGuestFailure>,
) -> PlusGuestObservation {
    project_plus_guest_observation(facts, None, failures)
}

pub(super) fn project_plus_guest_observation(
    facts: PlusGuestFacts,
    target: Option<PlusGuestTarget>,
    failures: Vec<PlusGuestFailure>,
) -> PlusGuestObservation {
    if let Some(target) = target {
        return PlusGuestObservation {
            facts,
            lifecycle: PlusGuestLifecycle::Ready(target.clone()),
            target: Some(target),
            failures: Vec::new(),
        };
    }
    let reasons = failures
        .iter()
        .map(|failure| failure.detail.clone())
        .collect();
    let lifecycle = match classify_plus_guest_lifecycle(&facts) {
        PlusGuestLifecycleKind::GuestDown => PlusGuestLifecycle::GuestDown { reasons },
        PlusGuestLifecycleKind::ServiceMissing | PlusGuestLifecycleKind::Ready => {
            PlusGuestLifecycle::ServiceMissing { reasons }
        }
    };
    PlusGuestObservation {
        facts,
        lifecycle,
        target: None,
        failures,
    }
}

fn ready_observation(facts: PlusGuestFacts, target: PlusGuestTarget) -> PlusGuestObservation {
    project_plus_guest_observation(facts, Some(target), Vec::new())
}

/// Linux helper entry: one contained probe on the local installed service.
///
/// # Errors
///
/// Returns a labeled refusal when this process is not on a healthy local
/// Linux installed-service host, or when the folder cannot be bound.
pub fn run_plus_guest_contained() -> Result<String, String> {
    run_plus_guest_contained_typed().map(|outcome| outcome.text)
}

/// Linux helper entry retaining typed command authority for process status.
///
/// # Errors
///
/// Returns the same setup errors as [`run_plus_guest_contained`].
pub fn run_plus_guest_contained_typed() -> Result<PresentedCommandOutcome, String> {
    #[cfg(target_os = "linux")]
    {
        if let Err(error) = plus_join_sibling_harness_cgroup() {
            return Ok(PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                present_plus_guest_unavailable_outcome_with_kind(
                    PlusGuestLifecycleKind::ServiceMissing,
                    "",
                    &PlusGuestUnavailable {
                        reasons: vec![error],
                    },
                ),
            ));
        }
        super::plus_set_probe_compatible_umask();
    }
    let observation = observe_plus_guest();
    match observation.target {
        Some(target) if target.kind == PlusGuestKind::Local => {
            let folder = std::env::var_os("HOME")
                .map_or_else(std::env::temp_dir, PathBuf::from)
                .join("gbd-plus-guest-ws");
            std::fs::create_dir_all(&folder).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let _ = std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700));
            }
            let folder = folder.canonicalize().map_err(|error| error.to_string())?;
            let bound = super::bind_project_folder(folder).map_err(|error| error.to_string())?;
            Ok(super::plus_gui_contained_command_outcome(&bound))
        }
        Some(_) => Err(format!(
            "{PLUS_GUEST_UNAVAILABLE}\n--plus-guest-contained must run on the Linux guest\n{PLUS_GUEST_HOW_TO_FIX}"
        )),
        None => {
            let kind = observation.lifecycle.kind();
            let report = PlusGuestUnavailable {
                reasons: observation
                    .failures
                    .into_iter()
                    .map(|failure| failure.detail)
                    .collect(),
            };
            Ok(PresentedCommandOutcome::new(
                CommandOutcomeClass::Refused,
                present_plus_guest_unavailable_outcome_with_kind(kind, "", &report),
            ))
        }
    }
}

/// Probe Colima / local Linux installed-service health.
#[must_use]
pub fn probe_plus_guest_health() -> PlusGuestHealth {
    let observation = observe_plus_guest();
    match observation.target {
        Some(target) => PlusGuestHealth::Available(target),
        None => PlusGuestHealth::Unavailable(PlusGuestUnavailable {
            reasons: observation
                .failures
                .into_iter()
                .map(|failure| failure.detail)
                .collect(),
        }),
    }
}

/// SSH the Linux helper and return its presented contained outcome.
#[must_use]
pub fn plus_contained_via_colima_ssh(target: &PlusGuestTarget) -> String {
    plus_contained_via_colima_ssh_typed(target).text
}

/// Runs the versioned guest helper and derives authority only from exit status.
#[must_use]
pub fn plus_contained_via_colima_ssh_typed(target: &PlusGuestTarget) -> PresentedCommandOutcome {
    let (Some(colima), Some(helper)) = (target.colima.as_ref(), target.helper.as_ref()) else {
        return PresentedCommandOutcome::new(
            CommandOutcomeClass::Refused,
            present_plus_guest_unavailable_outcome_with_kind(
                PlusGuestLifecycleKind::ServiceMissing,
                "remote guest target omitted colima or helper",
                &PlusGuestUnavailable {
                    reasons: vec![
                        "Mac guest path requires colima and a Linux grok-build helper".into(),
                    ],
                },
            ),
        );
    };
    let mut command = Command::new(colima);
    apply_colima_child_environment(&mut command);
    apply_remote_target_environment(&mut command, target, helper);
    let output = command
        .arg(helper)
        .arg("--plus-guest-contained")
        .arg(PLUS_GUEST_TYPED_OUTCOME_FLAG)
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if let Some(class) = output
                .status
                .code()
                .and_then(CommandOutcomeClass::from_guest_exit_code)
            {
                return PresentedCommandOutcome::terminal(class, stdout);
            }
            let mut detail = stdout;
            if !stderr.is_empty() {
                if !detail.is_empty() {
                    detail.push('\n');
                }
                detail.push_str(&stderr);
            }
            if detail.is_empty() {
                detail = format!(
                    "guest helper exited {} without a command terminal",
                    output.status
                );
            }
            PresentedCommandOutcome::new(
                CommandOutcomeClass::Error,
                present_plus_guest_unavailable_outcome_with_kind(
                    PlusGuestLifecycleKind::ServiceMissing,
                    &detail,
                    &PlusGuestUnavailable {
                        reasons: vec![
                            "Colima helper did not return the typed command outcome contract"
                                .into(),
                        ],
                    },
                ),
            )
        }
        Err(error) => PresentedCommandOutcome::new(
            CommandOutcomeClass::Error,
            present_plus_guest_unavailable_outcome_with_kind(
                PlusGuestLifecycleKind::GuestDown,
                &format!("colima ssh failed: {error}"),
                &PlusGuestUnavailable {
                    reasons: vec!["could not start colima ssh".into()],
                },
            ),
        ),
    }
}

#[cfg(target_os = "linux")]
fn observe_linux_guest() -> PlusGuestObservation {
    let mut failures = Vec::new();
    let install_root = configured_or_default_install_root();
    let install_root_has_handoff = install_root_looks_installed(&install_root);
    if !install_root_has_handoff {
        failures.push(PlusGuestFailure {
            kind: PlusGuestFailureKind::InstallRootMissing,
            detail: format!(
                "Linux native-service install root is missing or has no handoff: {}",
                install_root.display()
            ),
        });
    }
    let runner = resolve_runner_binary();
    if runner.is_none() {
        failures.push(PlusGuestFailure {
            kind: PlusGuestFailureKind::RunnerMissing,
            detail: "Linux grok-build-runner not found (set GROK_BUILD_RUNNER_BINARY or place it beside this binary)".into(),
        });
    }
    let harness_cgroup_usable = plus_harness_cgroup_can_be_joined();
    if !harness_cgroup_usable {
        failures.push(PlusGuestFailure {
            kind: PlusGuestFailureKind::HarnessUnavailable,
            detail: "installed-service harness cgroup is not usable from this process (need sibling /gbd-phase1/service; user.slice cannot join without sudo -n tee)".into(),
        });
    }
    let facts = PlusGuestFacts {
        on_linux: true,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff,
        runner_present: runner.is_some(),
        helper_present: false,
        harness_cgroup_usable,
    };
    let Some(runner) = runner.filter(|_| failures.is_empty()) else {
        return unavailable_observation(facts, failures);
    };
    ready_observation(
        facts,
        PlusGuestTarget {
            kind: PlusGuestKind::Local,
            install_root,
            runner,
            helper: None,
            colima: None,
        },
    )
}

#[cfg(target_os = "macos")]
fn observe_macos_guest() -> PlusGuestObservation {
    observe_macos_guest_with(
        resolve_colima_binary,
        colima_status_running,
        discover_guest_paths,
    )
}

#[cfg(target_os = "macos")]
pub(super) fn observe_macos_guest_with<Resolve, Status, Discover>(
    resolve: Resolve,
    status: Status,
    discover: Discover,
) -> PlusGuestObservation
where
    Resolve: FnOnce() -> Option<PathBuf>,
    Status: FnOnce(&Path) -> bool,
    Discover: FnOnce(&Path) -> Result<PlusGuestTarget, Vec<PlusGuestFailure>>,
{
    let Some(colima) = resolve() else {
        return unavailable_observation(
            PlusGuestFacts {
                colima_present: false,
                ..empty_macos_guest_facts()
            },
            vec![PlusGuestFailure {
                kind: PlusGuestFailureKind::RuntimeMissing,
                detail: "colima is not on PATH".into(),
            }],
        );
    };
    if !status(&colima) {
        return unavailable_observation(
            PlusGuestFacts {
                colima_present: true,
                ..empty_macos_guest_facts()
            },
            vec![PlusGuestFailure {
                kind: PlusGuestFailureKind::RuntimeDown,
                detail: "colima is not running (`colima start`)".into(),
            }],
        );
    }
    match discover(&colima) {
        Ok(target) => ready_observation(
            PlusGuestFacts {
                on_linux: false,
                colima_present: true,
                colima_running: true,
                install_root_has_handoff: true,
                runner_present: true,
                helper_present: true,
                harness_cgroup_usable: true,
            },
            target,
        ),
        Err(failures) => unavailable_observation(
            PlusGuestFacts {
                on_linux: false,
                colima_present: true,
                colima_running: true,
                install_root_has_handoff: !has_failure(
                    &failures,
                    PlusGuestFailureKind::InstallRootMissing,
                ),
                runner_present: !has_failure(&failures, PlusGuestFailureKind::RunnerMissing),
                helper_present: !has_failure(&failures, PlusGuestFailureKind::HelperMissing)
                    && !has_failure(&failures, PlusGuestFailureKind::HelperIncompatible),
                harness_cgroup_usable: !has_failure(
                    &failures,
                    PlusGuestFailureKind::HarnessUnavailable,
                ),
            },
            failures,
        ),
    }
}

#[cfg(target_os = "macos")]
const fn empty_macos_guest_facts() -> PlusGuestFacts {
    PlusGuestFacts {
        on_linux: false,
        colima_present: false,
        colima_running: false,
        install_root_has_handoff: false,
        runner_present: false,
        helper_present: false,
        harness_cgroup_usable: false,
    }
}

#[cfg(target_os = "macos")]
fn has_failure(failures: &[PlusGuestFailure], kind: PlusGuestFailureKind) -> bool {
    failures.iter().any(|failure| failure.kind == kind)
}

#[cfg(target_os = "linux")]
fn configured_or_default_install_root() -> PathBuf {
    std::env::var_os(PLUS_GUEST_INSTALL_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(PLUS_DEFAULT_INSTALL_ROOT))
}

#[cfg(target_os = "linux")]
fn install_root_looks_installed(root: &Path) -> bool {
    root.is_absolute() && root.join("handoff-commitment.v1.json").is_file()
}

#[cfg(target_os = "linux")]
fn resolve_runner_binary() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os(PLUS_GUEST_RUNNER_ENV).map(PathBuf::from)
        && configured.is_file()
    {
        return configured.canonicalize().ok();
    }
    let current = std::env::current_exe().ok()?;
    let sibling = current.parent()?.join("grok-build-runner");
    if sibling.is_file() {
        return sibling.canonicalize().ok();
    }
    None
}

#[cfg(target_os = "macos")]
pub(super) const DISCOVER_GUEST_PATHS_SCRIPT: &str = r#"
set -e
root="${GROK_BUILD_LINUX_NATIVE_SERVICE_INSTALL_ROOT:-/opt/grok-build/phase1/install}"
helper="${GROK_BUILD_PLUS_GUEST_HELPER:-}"
runner="${GROK_BUILD_RUNNER_BINARY:-}"
current=/opt/grok-build/phase1/current
if [ -f "$current" ] && [ ! -L "$current" ]; then
  owner=$(stat -c %u "$current")
  mode=$(stat -c %a "$current")
  bytes=$(stat -c %s "$current")
  if [ "$owner" != 0 ] || [ "$mode" != 444 ] || [ "$bytes" -gt 4096 ] || [ "$(wc -l < "$current")" -ne 3 ]; then
    echo "reason=installed service selector has unsafe metadata"
    exit 17
  fi
  root=$(sed -n '1p' "$current")
  helper=$(sed -n '2p' "$current")
  runner=$(sed -n '3p' "$current")
fi
if [ -z "$helper" ]; then
  if [ -x /opt/grok-build/phase1/bin/grok-build-linux-helper ]; then
    helper=/opt/grok-build/phase1/bin/grok-build-linux-helper
  elif [ -x "$HOME/gbd-plus-linux-target/debug/grok-build" ]; then
    helper="$HOME/gbd-plus-linux-target/debug/grok-build"
  elif [ -x /usr/local/bin/grok-build ]; then
    helper=/usr/local/bin/grok-build
  fi
fi
if [ -z "$runner" ] && [ -n "$helper" ]; then
  sib="$(dirname "$helper")/grok-build-runner"
  if [ -x "$sib" ]; then
    runner="$sib"
  fi
fi
echo "install=$root"
echo "helper=${helper:-}"
echo "runner=${runner:-}"
if [ ! -f "$root/handoff-commitment.v1.json" ]; then
  echo "reason=install root missing handoff: $root"
  exit 10
fi
if [ ! -x "$helper" ]; then
  echo "reason=Linux grok-build helper missing"
  exit 11
fi
if [ ! -x "$runner" ]; then
  echo "reason=Linux grok-build-runner missing beside helper or GROK_BUILD_RUNNER_BINARY"
  exit 12
fi
if ! grep -a -q -- "--plus-guest-contained" "$helper"; then
  echo "reason=Linux grok-build helper does not support --plus-guest-contained; rebuild it on the guest"
  exit 13
fi
if ! grep -a -q -- "--plus-typed-outcome-v1" "$helper"; then
  echo "reason=Linux grok-build helper does not support typed command outcomes; rebuild it on the guest"
  exit 16
fi
probe="$(dirname "$(dirname "$helper")")/probe/plus-contained-probe"
if [ ! -f "$probe" ] || [ -L "$probe" ] || [ ! -x "$probe" ] \
  || [ "$(stat -c %u "$probe")" != 0 ] || [ "$(stat -c %a "$probe")" != 555 ] \
  || [ "$(stat -c %s "$probe")" != 3160 ] \
  || [ "$(sha256sum "$probe" | cut -d ' ' -f 1)" != d36421faefab9a6acb9c141b5f4400126676eb8ff6c87a5faef8b9aed871178c ]; then
  echo "reason=installed contained probe failed exact verification"
  exit 18
fi
harness="${GROK_BUILD_PLUS_HARNESS_CGROUP_PROCS:-/sys/fs/cgroup/gbd-phase1/service/cgroup.procs}"
if [ ! -f "$harness" ]; then
  echo "reason=sibling harness cgroup is missing: $harness"
  exit 14
fi
if [ ! -w "$harness" ] && ! sudo -n true >/dev/null 2>&1; then
  echo "reason=cannot join sibling harness cgroup from this guest session (user.slice; sudo -n tee required)"
  exit 15
fi
"#;

#[cfg(target_os = "macos")]
fn discover_guest_paths(colima: &Path) -> Result<PlusGuestTarget, Vec<PlusGuestFailure>> {
    let mut command = Command::new(colima);
    apply_colima_child_environment(&mut command);
    let output = command
        .arg("ssh")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(DISCOVER_GUEST_PATHS_SCRIPT)
        .output()
        .map_err(|error| {
            vec![PlusGuestFailure {
                kind: PlusGuestFailureKind::DiscoveryFailed,
                detail: format!("colima ssh discover failed: {error}"),
            }]
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut install = None;
    let mut helper = None;
    let mut runner = None;
    let mut reasons = Vec::new();
    for line in stdout.lines() {
        if let Some(value) = line.strip_prefix("install=") {
            install = Some(PathBuf::from(value));
        } else if let Some(value) = line.strip_prefix("helper=") {
            if !value.is_empty() {
                helper = Some(PathBuf::from(value));
            }
        } else if let Some(value) = line.strip_prefix("runner=") {
            if !value.is_empty() {
                runner = Some(PathBuf::from(value));
            }
        } else if let Some(value) = line.strip_prefix("reason=") {
            reasons.push(value.to_owned());
        }
    }
    if !output.status.success() {
        if reasons.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if stderr.is_empty() {
                reasons.push("guest discovery refused (install root, helper, or runner)".into());
            } else {
                reasons.push(stderr);
            }
        }
        let kind = match output.status.code() {
            Some(10) => PlusGuestFailureKind::InstallRootMissing,
            Some(11) => PlusGuestFailureKind::HelperMissing,
            Some(12) => PlusGuestFailureKind::RunnerMissing,
            Some(13 | 16 | 18) => PlusGuestFailureKind::HelperIncompatible,
            Some(14 | 15) => PlusGuestFailureKind::HarnessUnavailable,
            _ => PlusGuestFailureKind::DiscoveryFailed,
        };
        return Err(reasons
            .into_iter()
            .map(|detail| PlusGuestFailure { kind, detail })
            .collect());
    }
    let (Some(install_root), Some(helper), Some(runner)) = (install, helper, runner) else {
        return Err(vec![PlusGuestFailure {
            kind: PlusGuestFailureKind::DiscoveryFailed,
            detail: "guest discovery omitted install, helper, or runner".into(),
        }]);
    };
    Ok(PlusGuestTarget {
        kind: PlusGuestKind::Remote,
        install_root,
        runner,
        helper: Some(helper),
        colima: Some(colima.to_path_buf()),
    })
}

pub(super) fn apply_remote_target_environment(
    command: &mut Command,
    target: &PlusGuestTarget,
    helper: &Path,
) {
    let root = helper
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("/opt/grok-build/phase1"));
    let probe = root.join("probe");
    let prebuilt = probe.join(super::PLUS_PLAN_VALID_PROBE_NAME);
    command.args(["ssh", "--", "env"]);
    for (name, path) in [
        (PLUS_GUEST_INSTALL_ROOT_ENV, target.install_root.as_path()),
        (PLUS_GUEST_RUNNER_ENV, target.runner.as_path()),
        (PLUS_GUEST_HELPER_ENV, helper),
        (super::PLUS_PROBE_DIR_ENV, probe.as_path()),
        (super::PLUS_PREBUILT_PROBE_ENV, prebuilt.as_path()),
    ] {
        command.arg(format!("{name}={}", path.display()));
    }
}

/// One-step guest prepare: start Colima only when safe, then verify install
/// root, then present lifecycle + repair hints. Never auto-installs Colima.
#[must_use]
pub fn prepare_plus_guest() -> String {
    let start = match colima_start_is_safe(&observe_colima_start_facts()) {
        Ok(()) => start_colima_if_safe(),
        Err(refused) => Err(refused),
    };
    let install = verify_operator_install_root();
    let lifecycle = probe_plus_guest_lifecycle();
    present_plus_guest_prepare(
        start.as_deref().map_err(String::as_str),
        &install,
        lifecycle.kind(),
    )
}

/// Operator-facing install-root check: local on Linux, Colima SSH on macOS.
#[must_use]
pub fn verify_operator_install_root() -> super::PlusInstallRootReport {
    let configured = std::env::var_os(PLUS_GUEST_INSTALL_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(PLUS_DEFAULT_INSTALL_ROOT));
    #[cfg(target_os = "macos")]
    {
        if let Some(colima) = resolve_colima_binary()
            && colima_status_running(&colima)
        {
            return verify_install_root_via_colima(&colima, &configured);
        }
    }
    super::verify_install_root(&configured)
}

#[cfg(target_os = "macos")]
fn verify_install_root_via_colima(colima: &Path, root: &Path) -> super::PlusInstallRootReport {
    let script = format!(
        "if [ -f '{}/handoff-commitment.v1.json' ]; then echo present; else echo missing; fi",
        root.display()
    );
    let mut command = Command::new(colima);
    apply_colima_child_environment(&mut command);
    let output = command
        .arg("ssh")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            super::PlusInstallRootReport {
                root: root.to_path_buf(),
                handoff_present: stdout.contains("present"),
                via: "colima ssh".into(),
            }
        }
        Err(_) => super::PlusInstallRootReport {
            root: root.to_path_buf(),
            handoff_present: false,
            via: "colima ssh failed".into(),
        },
    }
}

/// Env: absolute `cgroup.procs` of the sibling harness (Phase 1 `service`).
pub const PLUS_HARNESS_CGROUP_PROCS_ENV: &str = "GROK_BUILD_PLUS_HARNESS_CGROUP_PROCS";

/// Default sibling harness used by the Phase 1 12/12 drive.
pub const PLUS_DEFAULT_HARNESS_PROCS: &str = "/sys/fs/cgroup/gbd-phase1/service/cgroup.procs";

/// True when this process is already in the sibling harness cgroup.
#[must_use]
pub fn plus_process_is_in_harness_cgroup() -> bool {
    plus_process_is_in_harness_cgroup_at(&plus_harness_cgroup_procs_path())
}

/// True when the harness `cgroup.procs` exists and this process can join it
/// (already in it, writable, or `sudo -n true`).
#[must_use]
pub fn plus_harness_cgroup_can_be_joined() -> bool {
    let procs = plus_harness_cgroup_procs_path();
    if !procs.is_file() {
        return false;
    }
    if plus_process_is_in_harness_cgroup() {
        return true;
    }
    if std::fs::OpenOptions::new().write(true).open(&procs).is_ok() {
        return true;
    }
    Command::new("sudo")
        .arg("-n")
        .arg("true")
        .status()
        .is_ok_and(|status| status.success())
}

/// Move this process into the sibling harness cgroup.
///
/// Direct write from `user.slice` is EIO. Root can move a pid with
/// `sudo -n tee`. A spawned runner child is often pulled back into the
/// SSH session scope; callers must also join that child's pid.
///
/// # Errors
///
/// Returns why the harness could not be joined. The caller must not claim
/// **ready** or present a fake command terminal.
pub fn plus_join_sibling_harness_cgroup() -> Result<(), String> {
    plus_join_pid_into_sibling_harness_cgroup(std::process::id())
}

/// Move `pid` into the sibling harness cgroup.
///
/// # Errors
///
/// Returns why the pid could not be moved.
pub fn plus_join_pid_into_sibling_harness_cgroup(pid: u32) -> Result<(), String> {
    let procs = plus_harness_cgroup_procs_path();
    if !procs.is_file() {
        return Err(format!(
            "sibling harness cgroup is missing: {}",
            procs.display()
        ));
    }
    if plus_pid_is_in_harness_cgroup_at(pid, &procs) {
        return Ok(());
    }
    let encoded = format!("{pid}\n");
    let _ = std::fs::write(&procs, &encoded);
    if plus_pid_is_in_harness_cgroup_at(pid, &procs) {
        return Ok(());
    }
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg("tee")
        .arg(&procs)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot join sibling harness cgroup via sudo tee: {error}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(encoded.as_bytes());
    }
    let status = child
        .wait()
        .map_err(|error| format!("sudo tee wait failed: {error}"))?;
    if plus_pid_is_in_harness_cgroup_at(pid, &procs) {
        return Ok(());
    }
    Err(format!(
        "cannot join pid {pid} into sibling harness cgroup {} (user.slice EIO; sudo -n tee exited {status})",
        procs.display()
    ))
}

fn plus_harness_cgroup_procs_path() -> PathBuf {
    std::env::var_os(PLUS_HARNESS_CGROUP_PROCS_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(PLUS_DEFAULT_HARNESS_PROCS))
}

fn plus_process_is_in_harness_cgroup_at(procs: &Path) -> bool {
    plus_pid_is_in_harness_cgroup_at(std::process::id(), procs)
}

fn plus_pid_is_in_harness_cgroup_at(pid: u32, procs: &Path) -> bool {
    let Some(parent) = procs.parent() else {
        return false;
    };
    let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return false;
    };
    let sysfs = parent.to_string_lossy();
    let relative = sysfs
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(sysfs.as_ref());
    cgroup.lines().any(|line| {
        let path = line.rsplit(':').next().unwrap_or(line);
        path == relative
            || path.ends_with(relative)
            || path == sysfs.as_ref()
            || line.contains(relative)
    })
}
