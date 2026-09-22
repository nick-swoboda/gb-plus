//! GUI-driven 12/12 proof record.
//!
//! Records a sibling-layout contained drive and links its governing proof bar.
//! Mac native and nested Docker are never labeled 12/12.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::plus_guest::{
    PLUS_DEFAULT_INSTALL_ROOT, PLUS_GUEST_HOW_TO_FIX, PlusGuestHealth, PlusGuestKind,
    PlusGuestTarget, probe_plus_guest_health,
};
use super::plus_lifecycle::{
    PLUS_GUEST_STATUS_DOWN, PLUS_GUEST_STATUS_READY, PLUS_GUEST_STATUS_SERVICE_MISSING,
};
use super::plus_probe::plus_presentation_is_known_good_terminal;

/// Security policy this diagnostic must cite.
pub const PLUS_1212_PHASE1_BAR: &str = "SECURITY.md";

/// Mac native is never this product's 12/12 claim.
pub const PLUS_1212_NOT_MAC_NATIVE: &str = "Mac native is not 12/12";

/// Nested Docker remains the 9/12 residual.
pub const PLUS_1212_NOT_NESTED_DOCKER: &str = "nested Docker is not 12/12";

/// Phrase recorded when `CommandCompleted` carries preflight + launch digests.
pub const PLUS_1212_PERMIT_MINTED: &str = "permit minted";

/// One-click helper flag documented for operators.
pub const PLUS_1212_HELPER_FLAG: &str = "--plus-1212-proof";

/// Host class used to decide whether a 12/12 claim is even allowed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plus1212HostKind {
    /// This process is macOS. Never 12/12.
    MacNative,
    /// Nested Docker / container. Never 12/12.
    NestedDocker,
    /// Qualified sibling-layout Linux installed service.
    SiblingLayout,
    /// Linux without the sibling-layout signals.
    UnqualifiedLinux,
}

/// Observed facts for [`classify_plus_1212_host`].
#[allow(
    clippy::struct_excessive_bools,
    reason = "the 12/12 proof reports independent host observations and must not infer one fact from another"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plus1212HostFacts {
    /// This process is macOS.
    pub on_macos: bool,
    /// `/.dockerenv` or a container cgroup.
    pub nested_docker: bool,
    /// Install-root handoff is present.
    pub install_root_has_handoff: bool,
    /// cgroup v2 controllers file exists.
    pub cgroup_v2: bool,
    /// Installer uid ≠ runner uid (handoff / env).
    pub installer_uid_differs: bool,
    /// Parent `cgroup.procs` is delegated (writable by this uid).
    pub parent_cgroup_procs_delegated: bool,
}

/// I/O-free host classification. Conservative: missing signals are not 12/12.
#[must_use]
pub fn classify_plus_1212_host(facts: &Plus1212HostFacts) -> Plus1212HostKind {
    if facts.on_macos {
        Plus1212HostKind::MacNative
    } else if facts.nested_docker {
        Plus1212HostKind::NestedDocker
    } else if facts.install_root_has_handoff
        && facts.cgroup_v2
        && facts.installer_uid_differs
        && facts.parent_cgroup_procs_delegated
    {
        Plus1212HostKind::SiblingLayout
    } else {
        Plus1212HostKind::UnqualifiedLinux
    }
}

/// Durable record shape. `claimed_12_12` is false unless sibling-layout
/// minted a permit and reached `CommandCompleted` / `TimedOut`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Plus1212Record {
    /// Host class for this process (or the guest process that produced it).
    pub host_kind: Plus1212HostKind,
    /// Runner permit mint (`preflight_digest` + `launch_digest`) was observed.
    pub minted_permit: bool,
    /// `CommandCompleted` / `TimedOut` / Command succeeded / refusal text.
    pub terminal: String,
    /// Only true on sibling-layout + minted permit + known-good terminal.
    pub claimed_12_12: bool,
}

/// I/O-free: fill a record from host class + presented terminal.
#[must_use]
pub fn plus_1212_record_from_terminal(
    host_kind: Plus1212HostKind,
    terminal: &str,
) -> Plus1212Record {
    let minted_permit = terminal.contains(PLUS_1212_PERMIT_MINTED)
        && terminal.contains("preflight_digest=")
        && terminal.contains("launch_digest=");
    let known_good = plus_presentation_is_known_good_terminal(terminal)
        || terminal.contains("CommandCompleted")
        || terminal.contains("TimedOut");
    let claimed_12_12 = matches!(host_kind, Plus1212HostKind::SiblingLayout)
        && minted_permit
        && known_good
        && !terminal.contains(PLUS_1212_NOT_MAC_NATIVE)
        && !terminal.contains("9/12 residual");
    Plus1212Record {
        host_kind,
        minted_permit,
        terminal: terminal.to_owned(),
        claimed_12_12,
    }
}

/// Present the record. Never prints a 12/12 slogan on Mac native or Docker.
#[must_use]
pub fn present_plus_1212_record(record: &Plus1212Record) -> String {
    let mut lines = vec![
        format!("12/12 proof record ({PLUS_1212_HELPER_FLAG})"),
        format!("bar: {PLUS_1212_PHASE1_BAR}"),
        PLUS_1212_NOT_MAC_NATIVE.to_owned(),
        PLUS_1212_NOT_NESTED_DOCKER.to_owned(),
        format!("host: {:?}", record.host_kind),
    ];
    match record.host_kind {
        Plus1212HostKind::MacNative => {
            lines.push(PLUS_1212_NOT_MAC_NATIVE.to_owned());
            lines.push("this Mac process cannot claim 12/12".into());
        }
        Plus1212HostKind::NestedDocker => {
            lines.push(PLUS_1212_NOT_NESTED_DOCKER.to_owned());
            lines.push(
                "nested Docker remains a 9/12 residual; linux-verify.sh PASS is not 12/12".into(),
            );
        }
        Plus1212HostKind::UnqualifiedLinux => {
            lines.push("this Linux host is not the sibling-layout service; not 12/12".into());
        }
        Plus1212HostKind::SiblingLayout => {
            lines.push("sibling-layout installed service (Phase 1 bar host class)".into());
        }
    }
    if record.minted_permit {
        lines.push(PLUS_1212_PERMIT_MINTED.to_owned());
    } else {
        lines.push("permit mint not observed on this terminal".into());
    }
    if record.claimed_12_12 {
        lines.push("12/12 recorded on sibling-layout service; see the Phase 1 bar".into());
    } else {
        lines.push("12/12 not claimed on this host".into());
    }
    if !record.terminal.is_empty() {
        lines.push(record.terminal.clone());
    }
    lines.join("\n")
}

/// Observe host facts for this process.
#[must_use]
pub fn observe_plus_1212_host_facts() -> Plus1212HostFacts {
    let on_macos = cfg!(target_os = "macos");
    let nested_docker = Path::new("/.dockerenv").is_file() || cgroup_looks_like_docker();
    let install_root = std::env::var_os("GROK_BUILD_LINUX_NATIVE_SERVICE_INSTALL_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(PLUS_DEFAULT_INSTALL_ROOT));
    let install_root_has_handoff = install_root.join("handoff-commitment.v1.json").is_file();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
    let parent_cgroup_procs_delegated = parent_cgroup_procs_is_delegated();
    let installer_uid_differs = installer_uid_differs_from_runner(&install_root);
    Plus1212HostFacts {
        on_macos,
        nested_docker,
        install_root_has_handoff,
        cgroup_v2,
        installer_uid_differs,
        parent_cgroup_procs_delegated,
    }
}

/// One-click helper: record a 12/12 proof or an honest unavailability.
#[must_use]
pub fn run_plus_1212_proof() -> String {
    let facts = observe_plus_1212_host_facts();
    let host = classify_plus_1212_host(&facts);
    match host {
        Plus1212HostKind::MacNative => run_plus_1212_from_mac(),
        Plus1212HostKind::NestedDocker => {
            present_plus_1212_record(&plus_1212_record_from_terminal(
                host,
                "nested Docker: contained 12/12 is not claimed here",
            ))
        }
        Plus1212HostKind::SiblingLayout | Plus1212HostKind::UnqualifiedLinux => {
            run_plus_1212_on_linux(host)
        }
    }
}

fn run_plus_1212_from_mac() -> String {
    let mac = present_plus_1212_record(&plus_1212_record_from_terminal(
        Plus1212HostKind::MacNative,
        "this Mac process is not 12/12 (ADR-0011; no fexecve/execveat)",
    ));
    match probe_plus_guest_health() {
        PlusGuestHealth::Available(target) if target.kind == PlusGuestKind::Remote => {
            let guest = plus_1212_via_colima_ssh(&target);
            format!("{mac}\n--- guest record ---\n{guest}")
        }
        PlusGuestHealth::Available(_) => {
            format!("{mac}\n{PLUS_GUEST_STATUS_READY}\nunexpected local target on macOS")
        }
        PlusGuestHealth::Unavailable(report) => {
            let status = if report
                .reasons
                .iter()
                .any(|reason| reason.contains("colima"))
            {
                PLUS_GUEST_STATUS_DOWN
            } else {
                PLUS_GUEST_STATUS_SERVICE_MISSING
            };
            format!(
                "{mac}\n{status}\n{}\n{PLUS_GUEST_HOW_TO_FIX}",
                report.reasons.join("\n")
            )
        }
    }
}

fn run_plus_1212_on_linux(host: Plus1212HostKind) -> String {
    if !matches!(host, Plus1212HostKind::SiblingLayout) {
        return present_plus_1212_record(&plus_1212_record_from_terminal(
            host,
            "sibling-layout installed service is not present on this Linux host",
        ));
    }
    match probe_plus_guest_health() {
        PlusGuestHealth::Available(_) => match super::run_plus_guest_contained() {
            Ok(terminal) => {
                present_plus_1212_record(&plus_1212_record_from_terminal(host, &terminal))
            }
            Err(error) => present_plus_1212_record(&plus_1212_record_from_terminal(host, &error)),
        },
        PlusGuestHealth::Unavailable(report) => {
            let detail = format!(
                "{PLUS_GUEST_STATUS_SERVICE_MISSING}\n{}",
                report.reasons.join("\n")
            );
            present_plus_1212_record(&plus_1212_record_from_terminal(host, &detail))
        }
    }
}

fn plus_1212_via_colima_ssh(target: &PlusGuestTarget) -> String {
    let (Some(colima), Some(helper)) = (target.colima.as_ref(), target.helper.as_ref()) else {
        return present_plus_1212_record(&plus_1212_record_from_terminal(
            Plus1212HostKind::MacNative,
            "remote guest target omitted colima or helper",
        ));
    };
    let mut command = Command::new(colima);
    super::plus_lifecycle::apply_colima_child_environment(&mut command);
    let output = command
        .arg("ssh")
        .arg("--")
        .arg(helper)
        .arg(PLUS_1212_HELPER_FLAG)
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if stdout.is_empty() {
                format!(
                    "guest {PLUS_1212_HELPER_FLAG} exited {} without a record\n{stderr}",
                    output.status
                )
            } else if stderr.is_empty() {
                stdout
            } else {
                format!("{stdout}\n{stderr}")
            }
        }
        Err(error) => format!("colima ssh {PLUS_1212_HELPER_FLAG} failed: {error}"),
    }
}

fn cgroup_looks_like_docker() -> bool {
    let Ok(text) = std::fs::read_to_string("/proc/1/cgroup") else {
        return false;
    };
    text.contains("docker") || text.contains("containerd") || text.contains("kubepods")
}

fn parent_cgroup_procs_is_delegated() -> bool {
    let candidates = [
        PathBuf::from("/sys/fs/cgroup/gbd-phase1/cgroup.procs"),
        PathBuf::from("/sys/fs/cgroup/gbd-phase1/cgroup.subtree_control"),
    ];
    candidates
        .iter()
        .any(|path| path.is_file() && std::fs::OpenOptions::new().write(true).open(path).is_ok())
}

fn installer_uid_differs_from_runner(install_root: &Path) -> bool {
    let handoff = install_root.join("handoff-commitment.v1.json");
    let Ok(metadata) = std::fs::metadata(&handoff) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let installer = metadata.uid();
        let runner = rustix::process::geteuid().as_raw();
        installer != runner
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
