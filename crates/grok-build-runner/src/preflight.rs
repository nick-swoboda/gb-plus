//! Static sandbox prerequisite reporting.
//!
//! Detection in this module never proves containment. A successful static report
//! means only that an active, platform-specific escape canary may be attempted.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;

#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Host platform and intended sandbox implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPlatform {
    /// macOS using a Seatbelt profile and launcher.
    MacOsSeatbelt,
    /// Linux using Bubblewrap plus kernel restrictions.
    LinuxBubblewrap,
    /// A platform without a defined runner sandbox.
    Unsupported,
}

/// A prerequisite required by a platform sandbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    /// The macOS Seatbelt launcher is present.
    SeatbeltLauncher,
    /// A non-setuid Bubblewrap launcher is present.
    Bubblewrap,
    /// Linux user and other required namespaces are exposed.
    LinuxNamespaces,
    /// Linux Landlock must be exercised by an active probe.
    Landlock,
    /// Linux seccomp support is visible.
    Seccomp,
    /// `no_new_privs` must be set and verified by an active probe.
    NoNewPrivileges,
    /// No supported platform implementation exists.
    SupportedPlatform,
}

/// Static state of a sandbox prerequisite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityState {
    /// Static host evidence was detected. This is not a containment guarantee.
    Detected(String),
    /// The capability needs an active child-process probe before use.
    ActiveProbeRequired(String),
    /// Required static evidence is absent or invalid.
    Missing(String),
}

/// One named preflight check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityCheck {
    capability: Capability,
    state: CapabilityState,
}

impl CapabilityCheck {
    /// Creates a capability check.
    #[must_use]
    pub fn new(capability: Capability, state: CapabilityState) -> Self {
        Self { capability, state }
    }

    /// Returns the capability being checked.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the static check state.
    #[must_use]
    pub const fn state(&self) -> &CapabilityState {
        &self.state
    }
}

/// Fail-closed disposition of static sandbox preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreflightDisposition {
    /// A required prerequisite is absent; command execution must remain disabled.
    FailClosed,
    /// Static prerequisites exist, but an active escape canary is still required.
    CanaryRequired,
}

/// Static capability report for the current host sandbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPreflight {
    platform: HostPlatform,
    checks: Vec<CapabilityCheck>,
    disposition: PreflightDisposition,
}

impl SandboxPreflight {
    /// Returns the selected host implementation.
    #[must_use]
    pub const fn platform(&self) -> HostPlatform {
        self.platform
    }

    /// Returns all prerequisite checks.
    #[must_use]
    pub fn checks(&self) -> &[CapabilityCheck] {
        &self.checks
    }

    /// Returns the fail-closed static disposition.
    #[must_use]
    pub const fn disposition(&self) -> PreflightDisposition {
        self.disposition
    }

    /// Returns whether this report authorizes command execution.
    ///
    /// Static preflight never authorizes execution. A later runner implementation
    /// must combine this report with a passing active canary.
    #[must_use]
    pub const fn permits_execution(&self) -> bool {
        false
    }

    fn from_checks(platform: HostPlatform, checks: Vec<CapabilityCheck>) -> Self {
        let disposition = if checks
            .iter()
            .any(|check| matches!(check.state, CapabilityState::Missing(_)))
        {
            PreflightDisposition::FailClosed
        } else {
            PreflightDisposition::CanaryRequired
        };

        Self {
            platform,
            checks,
            disposition,
        }
    }
}

/// Inspects static prerequisites for the current host.
///
/// This function performs no installation, privilege change, or sandbox launch.
/// Its result never permits execution without a separate active canary.
#[must_use]
pub fn inspect_host_sandbox() -> SandboxPreflight {
    #[cfg(target_os = "macos")]
    {
        return inspect_macos();
    }

    #[cfg(target_os = "linux")]
    {
        return inspect_linux();
    }

    #[allow(unreachable_code)]
    SandboxPreflight::from_checks(
        HostPlatform::Unsupported,
        vec![CapabilityCheck::new(
            Capability::SupportedPlatform,
            CapabilityState::Missing("no sandbox backend is defined for this platform".into()),
        )],
    )
}

#[cfg(target_os = "macos")]
fn inspect_macos() -> SandboxPreflight {
    let launcher = Path::new("/usr/bin/sandbox-exec");
    let state = regular_file_state(
        launcher,
        "Seatbelt launcher detected; profile enforcement still needs an active escape canary",
    );

    SandboxPreflight::from_checks(
        HostPlatform::MacOsSeatbelt,
        vec![CapabilityCheck::new(Capability::SeatbeltLauncher, state)],
    )
}

#[cfg(target_os = "linux")]
fn inspect_linux() -> SandboxPreflight {
    let bubblewrap = find_non_setuid_bubblewrap();
    let bubblewrap_state = bubblewrap.map_or_else(
        || {
            CapabilityState::Missing(
                "no regular non-setuid Bubblewrap launcher found at /usr/bin/bwrap or /bin/bwrap"
                    .into(),
            )
        },
        |path| {
            CapabilityState::ActiveProbeRequired(format!(
                "{} detected; version and containment canary not yet verified",
                path.display()
            ))
        },
    );

    let namespace_paths = [
        "/proc/self/ns/user",
        "/proc/self/ns/mnt",
        "/proc/self/ns/pid",
        "/proc/self/ns/ipc",
        "/proc/self/ns/uts",
        "/proc/self/ns/net",
    ];
    let missing_namespaces: Vec<_> = namespace_paths
        .iter()
        .filter(|path| !Path::new(path).exists())
        .copied()
        .collect();
    let namespaces_state = if missing_namespaces.is_empty() {
        CapabilityState::ActiveProbeRequired(
            "namespace handles detected; unprivileged creation still needs an active probe".into(),
        )
    } else {
        CapabilityState::Missing(format!(
            "missing namespace handles: {}",
            missing_namespaces.join(", ")
        ))
    };

    let seccomp_state = match fs::read_to_string("/proc/self/status") {
        Ok(status) if status.lines().any(|line| line.starts_with("Seccomp:")) => {
            CapabilityState::ActiveProbeRequired(
                "seccomp status is exposed; filter enforcement still needs an active probe".into(),
            )
        }
        Ok(_) => CapabilityState::Missing("/proc/self/status exposes no seccomp status".into()),
        Err(error) => CapabilityState::Missing(format!(
            "cannot inspect /proc/self/status for seccomp: {error}"
        )),
    };

    SandboxPreflight::from_checks(
        HostPlatform::LinuxBubblewrap,
        vec![
            CapabilityCheck::new(Capability::Bubblewrap, bubblewrap_state),
            CapabilityCheck::new(Capability::LinuxNamespaces, namespaces_state),
            CapabilityCheck::new(
                Capability::Landlock,
                CapabilityState::ActiveProbeRequired(
                    "Landlock ABI and ruleset enforcement require an active syscall probe".into(),
                ),
            ),
            CapabilityCheck::new(Capability::Seccomp, seccomp_state),
            CapabilityCheck::new(
                Capability::NoNewPrivileges,
                CapabilityState::ActiveProbeRequired(
                    "no_new_privs must be set and read back in the sandbox child".into(),
                ),
            ),
        ],
    )
}

#[cfg(target_os = "linux")]
fn find_non_setuid_bubblewrap() -> Option<PathBuf> {
    [Path::new("/usr/bin/bwrap"), Path::new("/bin/bwrap")]
        .into_iter()
        .find(|path| is_regular_non_setuid_file(path))
        .map(Path::to_path_buf)
}

#[cfg(target_os = "linux")]
fn is_regular_non_setuid_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file() && metadata.permissions().mode() & 0o6000 == 0
    })
}

#[cfg(target_os = "macos")]
fn regular_file_state(path: &Path, detected_detail: &str) -> CapabilityState {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            CapabilityState::ActiveProbeRequired(detected_detail.into())
        }
        Ok(_) => CapabilityState::Missing(format!("{} is not a regular file", path.display())),
        Err(error) => {
            CapabilityState::Missing(format!("{} is unavailable: {error}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_prerequisite_fails_closed() {
        let report = SandboxPreflight::from_checks(
            HostPlatform::LinuxBubblewrap,
            vec![
                CapabilityCheck::new(
                    Capability::Bubblewrap,
                    CapabilityState::Missing("not found".into()),
                ),
                CapabilityCheck::new(
                    Capability::Seccomp,
                    CapabilityState::ActiveProbeRequired("probe later".into()),
                ),
            ],
        );

        assert_eq!(report.disposition(), PreflightDisposition::FailClosed);
        assert!(!report.permits_execution());
    }

    #[test]
    fn detected_prerequisites_still_require_canary() {
        let report = SandboxPreflight::from_checks(
            HostPlatform::MacOsSeatbelt,
            vec![CapabilityCheck::new(
                Capability::SeatbeltLauncher,
                CapabilityState::Detected("present".into()),
            )],
        );

        assert_eq!(report.disposition(), PreflightDisposition::CanaryRequired);
        assert!(!report.permits_execution());
    }

    #[test]
    fn host_report_is_nonempty_and_never_authorizes_execution() {
        let report = inspect_host_sandbox();

        assert!(!report.checks().is_empty());
        assert!(!report.permits_execution());
    }
}
