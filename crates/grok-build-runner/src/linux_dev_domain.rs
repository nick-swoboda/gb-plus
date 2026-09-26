//! Development cgroup-v2 canaries. These measurements grant no production
//! execution or cleanup authority.
//!
//! Landlock read/write scopes and seccomp network/namespace filters are built
//! before fork and applied immediately before exec. The target is a sealed
//! `MFD_EXEC` copy of the runner, executed through `/proc/self/fd/<n>`.
//! It receives retained cwd at fd 0, a report pipe at fd 1 and `cgroup.procs`
//! at fd 2, then self-attaches by writing `0\n`; the controller never writes
//! a numeric PID. No Bubblewrap isolation is claimed here.

// The canary domain is instantiated only on Linux; the helper entry point is
// recognized on every target so a non-Linux build fails closed rather than
// silently running an ordinary process. Observations are retained whole so a
// test can assert the numbers behind a verdict, which leaves accessors the
// suite itself does not consume.
#![allow(dead_code)]

use std::process::ExitCode;

use serde::{Deserialize, Serialize};

/// Exact internal mode argument of the Linux canary helper.
pub(crate) const LINUX_CANARY_HELPER_ARGUMENT: &str = "--grok-build-linux-canary-helper-v1";

/// Schema version of the canonical canary report.
pub(crate) const LINUX_CANARY_REPORT_VERSION: u32 = 1;

/// Largest single canonical report line the controller will accept.
///
/// Reports are written with one `write(2)` so several processes in one domain
/// can share the report pipe without interleaving; the bound keeps every
/// report below `PIPE_BUF` where that atomicity is guaranteed.
pub(crate) const MAX_LINUX_CANARY_REPORT_BYTES: usize = 4_096;

/// One environment entry as the contained canary observed it.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCanaryEnvironmentEntryV1 {
    pub(crate) name: String,
    pub(crate) value: String,
}

/// Which process in the domain produced one report.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxCanaryRoleV1 {
    /// The process the controller launched into the reserved leaf.
    Leader,
    /// A process the leader created inside the same leaf.
    Descendant,
}

/// Everything one contained canary process observed about itself.
///
/// Every field is an observation, never a verdict. The controller decides what
/// a control claim requires; this type only carries what the kernel reported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCanaryReportV1 {
    pub(crate) schema_version: u32,
    pub(crate) mode: String,
    pub(crate) role: LinuxCanaryRoleV1,
    /// Whether the exact `0\n` self-attachment write to fd 2 succeeded.
    pub(crate) attached: bool,
    pub(crate) attach_errno: Option<i32>,
    pub(crate) pid: u32,
    pub(crate) process_group: u32,
    pub(crate) session: u32,
    /// `getcwd` after the descriptor-selected `fchdir`, or the empty string.
    pub(crate) working_directory: String,
    /// `readlink("/proc/self/exe")`, which names a memfd for a sealed image.
    pub(crate) executable_link: String,
    /// The complete `/proc/self/cgroup` line.
    pub(crate) cgroup_line: String,
    pub(crate) argv: Vec<String>,
    pub(crate) environment: Vec<LinuxCanaryEnvironmentEntryV1>,
    /// `/proc/self/fd` excluding the transient enumerator descriptor.
    pub(crate) open_descriptors: Vec<u32>,
    pub(crate) requested_children: u32,
    pub(crate) spawned_children: Vec<u32>,
    pub(crate) spawn_failure_errno: Option<i32>,
    /// Whether a write outside every compiled write scope succeeded.
    pub(crate) escape_write_succeeded: Option<bool>,
    pub(crate) escape_write_errno: Option<i32>,
    /// Whether a loopback TCP connection to the controller's listener worked.
    pub(crate) loopback_connect_succeeded: Option<bool>,
    pub(crate) loopback_connect_errno: Option<i32>,
    pub(crate) allocated_bytes: u64,
}

impl LinuxCanaryReportV1 {
    pub(crate) fn new(mode: &str, role: LinuxCanaryRoleV1) -> Self {
        Self {
            schema_version: LINUX_CANARY_REPORT_VERSION,
            mode: mode.to_owned(),
            role,
            attached: false,
            attach_errno: None,
            pid: 0,
            process_group: 0,
            session: 0,
            working_directory: String::new(),
            executable_link: String::new(),
            cgroup_line: String::new(),
            argv: Vec::new(),
            environment: Vec::new(),
            open_descriptors: Vec::new(),
            requested_children: 0,
            spawned_children: Vec::new(),
            spawn_failure_errno: None,
            escape_write_succeeded: None,
            escape_write_errno: None,
            loopback_connect_succeeded: None,
            loopback_connect_errno: None,
            allocated_bytes: 0,
        }
    }

    /// Whether the report is a well-formed observation from this generation.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != LINUX_CANARY_REPORT_VERSION {
            return Err(format!(
                "canary report schema version {} is unsupported",
                self.schema_version
            ));
        }
        if self.mode.is_empty() || self.mode.len() > 64 {
            return Err("canary report mode is empty or unbounded".to_owned());
        }
        if self.pid == 0 || self.process_group == 0 || self.session == 0 {
            return Err("canary report identifiers must be nonzero".to_owned());
        }
        Ok(())
    }
}

/// Runs the fixed Linux canary helper when the exact internal mode argument is
/// present.
///
/// This entry point grants no authority. All Linux authority is the three
/// inherited descriptors and the controller-side retained bindings; a non-Linux
/// build recognizes the argument only so it can fail closed.
#[doc(hidden)]
#[must_use]
pub fn run_linux_command_canary_helper_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(LINUX_CANARY_HELPER_ARGUMENT) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(native::run_canary_helper(arguments))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(arguments);
        Some(ExitCode::from(78))
    }
}

#[cfg(target_os = "linux")]
pub(crate) use native::{
    CanaryExit, CanarySpecification, LINUX_DELEGATION_ROOT_VARIABLE, LINUX_NETWORK_SYSCALLS,
    LINUX_SECCOMP_NETWORK_ERRNO, LINUX_SECCOMP_TARGET_ARCH, LinuxCanaryRunObservation,
    LinuxContainmentEvidence, LinuxContainmentPolicy, LinuxDelegatedCanaryDomain,
    LinuxDevDomainError, LinuxDomainKillObservation, abi_level, canary_image_source,
    delegation_root_from_environment, linux_runtime_read_roots, linux_runtime_write_surfaces,
    named_self_image, observed_landlock_abi, payload_byte, sealed_self_image,
};

#[cfg(target_os = "linux")]
mod native {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::os::fd::{AsFd, AsRawFd as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use rustix::fs::{Mode, OFlags, RawDir, open};
    use rustix::process::{fchdir, getcwd, getpgrp, getpid, getsid, setsid};

    use super::{
        LINUX_CANARY_HELPER_ARGUMENT, LinuxCanaryEnvironmentEntryV1, LinuxCanaryReportV1,
        LinuxCanaryRoleV1, MAX_LINUX_CANARY_REPORT_BYTES,
    };

    /// Exact literal a contained process writes to attach itself.
    const SELF_ATTACH_VALUE: &[u8] = b"0\n";

    /// Longest a held canary may live even if its controller disappears.
    const CANARY_HOLD_LIMIT: Duration = Duration::from_mins(2);
    const HOLD_POLL_INTERVAL: Duration = Duration::from_millis(20);

    /// Exit code a refused canary helper uses. It is deliberately distinct from
    /// every ordinary program exit so a controller cannot confuse the two.
    const CANARY_HELPER_REFUSED: u8 = 79;

    /// Runs the canary helper for one already-validated internal invocation.
    pub(super) fn run_canary_helper(arguments: std::env::ArgsOs) -> ExitCode {
        match canary_helper_main(arguments) {
            Ok(()) => ExitCode::SUCCESS,
            Err(HelperRefusal) => ExitCode::from(CANARY_HELPER_REFUSED),
        }
    }

    /// Deliberately opaque: a helper never reports a reason on a channel the
    /// controller authenticates, so a refusal is a status and nothing more.
    struct HelperRefusal;

    #[allow(
        clippy::too_many_lines,
        reason = "the helper keeps self-attachment, descriptor-selected cwd, each probe, and the single report write in one visible order"
    )]
    fn canary_helper_main(arguments: std::env::ArgsOs) -> Result<(), HelperRefusal> {
        let arguments = arguments.collect::<Vec<OsString>>();
        // Trailing entries are deliberately admitted and ignored: the exact
        // argument vector canary appends them so the report can be compared
        // byte for byte with what the controller asked the kernel to deliver.
        let [role, mode, parameter, ..] = arguments.as_slice() else {
            return Err(HelperRefusal);
        };
        let role = match role.to_str() {
            Some("leader") => LinuxCanaryRoleV1::Leader,
            Some("descendant") => LinuxCanaryRoleV1::Descendant,
            _ => return Err(HelperRefusal),
        };
        let mode = mode.to_str().ok_or(HelperRefusal)?.to_owned();
        let parameter = parameter.to_str().ok_or(HelperRefusal)?.to_owned();
        let mut report = LinuxCanaryReportV1::new(&mode, role);

        // Self-attachment is first and is the only thing fd 2 is ever used
        // for. A descendant is already charged to the leaf by inheritance and
        // holds no `cgroup.procs` descriptor, so it never attempts the write.
        if role == LinuxCanaryRoleV1::Leader {
            match rustix::io::write(std::io::stderr(), SELF_ATTACH_VALUE) {
                Ok(written) if written == SELF_ATTACH_VALUE.len() => report.attached = true,
                Ok(_) => report.attach_errno = Some(0),
                Err(error) => report.attach_errno = Some(error.raw_os_error()),
            }
            // The working directory is selected from the descriptor the
            // controller retained and passed as fd 0; no pathname is resolved.
            if fchdir(std::io::stdin()).is_err() {
                return Err(HelperRefusal);
            }
        }

        if (mode == "setsid" || mode == "descendant-setsid") && setsid().is_err() {
            return Err(HelperRefusal);
        }

        let mut children = Vec::new();
        match mode.as_str() {
            "fork" => {
                let requested = parameter.parse::<u32>().map_err(|_| HelperRefusal)?;
                report.requested_children = requested;
                for _ in 0..requested {
                    match spawn_descendant("descendant-hold", false) {
                        Ok(child) => {
                            report.spawned_children.push(child.id());
                            children.push(child);
                        }
                        Err(error) => {
                            report.spawn_failure_errno = Some(error.raw_os_error().unwrap_or(0));
                            break;
                        }
                    }
                }
            }
            "setsid" => match spawn_descendant("descendant-setsid", true) {
                Ok(child) => {
                    report.spawned_children.push(child.id());
                    children.push(child);
                }
                Err(error) => {
                    report.spawn_failure_errno = Some(error.raw_os_error().unwrap_or(0));
                }
            },
            "escape" => match std::fs::write(&parameter, b"grok-build-linux-canary-escape\n") {
                Ok(()) => report.escape_write_succeeded = Some(true),
                Err(error) => {
                    report.escape_write_succeeded = Some(false);
                    report.escape_write_errno = Some(error.raw_os_error().unwrap_or(0));
                }
            },
            "connect" => {
                let port = parameter.parse::<u16>().map_err(|_| HelperRefusal)?;
                let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
                match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
                    Ok(mut stream) => {
                        let _ignored = stream.write_all(b"grok-build-linux-canary\n");
                        report.loopback_connect_succeeded = Some(true);
                    }
                    Err(error) => {
                        report.loopback_connect_succeeded = Some(false);
                        report.loopback_connect_errno = Some(error.raw_os_error().unwrap_or(0));
                    }
                }
            }
            _ => {}
        }

        fill_self_observation(&mut report)?;
        write_report(&report)?;

        match mode.as_str() {
            "output" => {
                let requested = parameter.parse::<u64>().map_err(|_| HelperRefusal)?;
                write_payload(requested)?;
            }
            "memory" => {
                let mebibytes = parameter.parse::<u64>().map_err(|_| HelperRefusal)?;
                let allocated = allocate_and_touch(mebibytes);
                let mut second = LinuxCanaryReportV1::new("memory-complete", role);
                fill_self_observation(&mut second)?;
                second.attached = report.attached;
                second.allocated_bytes = allocated;
                second.argv.clear();
                second.environment.clear();
                second.open_descriptors.clear();
                write_report(&second)?;
            }
            "hold" | "setsid" | "descendant-hold" | "descendant-setsid" => hold(),
            _ => {}
        }
        drop(children);
        Ok(())
    }

    /// Fills the kernel-reported identity of the running canary.
    fn fill_self_observation(report: &mut LinuxCanaryReportV1) -> Result<(), HelperRefusal> {
        report.pid = u32::try_from(getpid().as_raw_pid()).map_err(|_| HelperRefusal)?;
        report.process_group =
            u32::try_from(getpgrp().as_raw_nonzero().get()).map_err(|_| HelperRefusal)?;
        report.session = u32::try_from(
            getsid(None)
                .map_err(|_| HelperRefusal)?
                .as_raw_nonzero()
                .get(),
        )
        .map_err(|_| HelperRefusal)?;
        if let Ok(directory) = getcwd(Vec::new())
            && let Ok(text) = directory.into_string()
        {
            report.working_directory = text;
        }
        if let Ok(link) = std::fs::read_link("/proc/self/exe") {
            report.executable_link = link.to_string_lossy().into_owned();
        }
        if let Ok(line) = std::fs::read_to_string("/proc/self/cgroup") {
            line.trim_end().clone_into(&mut report.cgroup_line);
        }
        report.argv = std::env::args().collect();
        report.environment = std::env::vars()
            .map(|(name, value)| LinuxCanaryEnvironmentEntryV1 { name, value })
            .collect();
        report.environment.sort();
        report.open_descriptors = enumerate_open_descriptors()?;
        Ok(())
    }

    /// Enumerates `/proc/self/fd`, excluding the transient enumerator itself.
    ///
    /// The exclusion is exact rather than a guess: the enumerating descriptor's
    /// own number is known here, so removing it reports what the process
    /// inherited instead of what the enumeration cost.
    fn enumerate_open_descriptors() -> Result<Vec<u32>, HelperRefusal> {
        let directory = open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| HelperRefusal)?;
        let inspector = u32::try_from(directory.as_fd().as_raw_fd()).map_err(|_| HelperRefusal)?;
        let mut buffer = [MaybeUninit::<u8>::uninit(); 4_096];
        let mut entries = RawDir::new(&directory, &mut buffer);
        let mut descriptors = BTreeSet::new();
        while let Some(entry) = entries.next() {
            let entry = entry.map_err(|_| HelperRefusal)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let descriptor = std::str::from_utf8(name)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or(HelperRefusal)?;
            if descriptor != inspector {
                descriptors.insert(descriptor);
            }
        }
        Ok(descriptors.into_iter().collect())
    }

    fn write_report(report: &LinuxCanaryReportV1) -> Result<(), HelperRefusal> {
        let mut line = serde_json::to_vec(report).map_err(|_| HelperRefusal)?;
        line.push(b'\n');
        if line.len() > MAX_LINUX_CANARY_REPORT_BYTES {
            return Err(HelperRefusal);
        }
        let mut written = 0;
        while written < line.len() {
            written += rustix::io::write(std::io::stdout(), &line[written..])
                .map_err(|_| HelperRefusal)?;
        }
        Ok(())
    }

    /// Streams a deterministic payload so the controller can prove a complete,
    /// bounded drain rather than a truncated one.
    fn write_payload(bytes: u64) -> Result<(), HelperRefusal> {
        const CHUNK: usize = 4_096;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        let mut offset = 0_u64;
        let mut staging = [0_u8; CHUNK];
        while offset < bytes {
            let remaining = bytes - offset;
            let chunk_len = u64::try_from(CHUNK).map_err(|_| HelperRefusal)?;
            let length = usize::try_from(remaining.min(chunk_len)).map_err(|_| HelperRefusal)?;
            for (index, slot) in staging.iter_mut().enumerate().take(length) {
                let position = u64::try_from(index).map_err(|_| HelperRefusal)?;
                *slot = payload_byte(offset + position);
            }
            handle
                .write_all(&staging[..length])
                .map_err(|_| HelperRefusal)?;
            offset += u64::try_from(length).map_err(|_| HelperRefusal)?;
        }
        handle.flush().map_err(|_| HelperRefusal)?;
        Ok(())
    }

    /// Deterministic payload byte so the controller can recompute the digest.
    pub(crate) fn payload_byte(offset: u64) -> u8 {
        b'a'.wrapping_add(u8::try_from(offset % 26).unwrap_or(0))
    }

    /// Allocates and touches memory so a finite `memory.max` can be measured.
    fn allocate_and_touch(mebibytes: u64) -> u64 {
        let mut retained: Vec<Vec<u8>> = Vec::new();
        let mut allocated = 0_u64;
        for _ in 0..mebibytes {
            let mut block = vec![0_u8; 1_024 * 1_024];
            for page in block.chunks_mut(4_096) {
                page[0] = 1;
            }
            allocated += u64::try_from(block.len()).unwrap_or(0);
            retained.push(block);
        }
        allocated
    }

    fn hold() {
        let deadline = Instant::now() + CANARY_HOLD_LIMIT;
        while Instant::now() < deadline {
            std::thread::sleep(HOLD_POLL_INTERVAL);
        }
    }

    /// Creates one descendant of this canary inside the same reserved leaf.
    ///
    /// The descendant inherits cgroup membership from its parent, so it needs
    /// no `cgroup.procs` descriptor and is given none.
    fn spawn_descendant(mode: &str, report_to_controller: bool) -> std::io::Result<Child> {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg(LINUX_CANARY_HELPER_ARGUMENT)
            .arg("descendant")
            .arg(mode)
            .arg("-")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stderr(Stdio::null());
        if report_to_controller {
            command.stdout(Stdio::inherit());
        } else {
            command.stdout(Stdio::null());
        }
        command.spawn()
    }

    use std::collections::BTreeMap;
    use std::os::fd::OwnedFd;
    use std::os::unix::process::ExitStatusExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::fs::{AtFlags, fstatfs, mkdirat, openat, unlinkat};
    use sha2::{Digest as _, Sha256};

    use crate::linux_containment::{CGROUP2_SUPER_MAGIC, parse_cgroup_events, parse_cgroup_procs};

    /// Environment name through which a trusted launcher supplies the already
    /// delegated cgroup-v2 root. It is never accepted from a tool request and is
    /// never handed to a project command.
    pub(crate) const LINUX_DELEGATION_ROOT_VARIABLE: &str = "GROK_BUILD_CGROUP_ROOT";

    static NEXT_CANARY_LEAF: AtomicU64 = AtomicU64::new(1);

    /// Largest single read the controller performs while draining a canary.
    const DRAIN_CHUNK_BYTES: usize = 8 * 1_024;
    const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(5);
    /// Longest the controller waits for `cgroup.events` to report `populated 0`.
    const EMPTY_PROOF_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_CONTROL_FILE_BYTES: usize = 8 * 1_024;
    const CGROUP_KILL_VALUE: &[u8] = b"1\n";

    /// Closed failure from the development canary domain.
    #[derive(Debug)]
    pub(crate) struct LinuxDevDomainError {
        pub(crate) operation: &'static str,
        pub(crate) detail: String,
    }

    impl LinuxDevDomainError {
        fn new(operation: &'static str, detail: impl Into<String>) -> Self {
            Self {
                operation,
                detail: detail.into(),
            }
        }
    }

    impl std::fmt::Display for LinuxDevDomainError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "{}: {}", self.operation, self.detail)
        }
    }

    /// The delegated cgroup-v2 root a trusted launcher supplied, if any.
    pub(crate) fn delegation_root_from_environment() -> Option<PathBuf> {
        let value = std::env::var_os(LINUX_DELEGATION_ROOT_VARIABLE)?;
        let path = PathBuf::from(value);
        if path.is_absolute() { Some(path) } else { None }
    }

    /// How one canary process ended, exactly as the kernel reported it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum CanaryExit {
        Exited(i32),
        Signaled(i32),
    }

    /// One canary the controller runs inside the reserved leaf.
    #[derive(Debug)]
    pub(crate) struct CanarySpecification<'a> {
        pub(crate) mode: &'a str,
        pub(crate) parameter: &'a str,
        /// Extra argv entries the helper ignores and reports verbatim.
        pub(crate) extra_arguments: &'a [String],
        pub(crate) environment: &'a BTreeMap<String, String>,
        pub(crate) working_directory: &'a Path,
        pub(crate) deadline: Duration,
        /// How many canonical report lines precede any raw payload.
        pub(crate) expected_reports: usize,
        /// Kill the whole domain once this many reports have arrived.
        pub(crate) kill_after_reports: Option<usize>,
        /// The path and syscall layers applied after fork and before exec.
        ///
        /// `None` is an explicitly unconfined run, the control half of an
        /// A/B pair, and never a default.
        pub(crate) containment: Option<&'a LinuxContainmentPolicy>,
    }

    /// Everything one canary run produced, as observations only.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct LinuxCanaryRunObservation {
        pub(crate) reports: Vec<LinuxCanaryReportV1>,
        pub(crate) payload_bytes: u64,
        pub(crate) payload_digest: String,
        pub(crate) payload_chunks: u64,
        pub(crate) maximum_chunk_bytes: usize,
        pub(crate) exit: Option<CanaryExit>,
        pub(crate) elapsed_ms: u64,
        pub(crate) deadline_expired: bool,
        pub(crate) root_inode: u64,
        pub(crate) leaf_inode: u64,
        pub(crate) controller_descriptors: usize,
        pub(crate) procs_at_report: Vec<u32>,
        pub(crate) pids_current: String,
        pub(crate) pids_events: String,
        pub(crate) memory_events: String,
        pub(crate) kill: Option<LinuxDomainKillObservation>,
        /// Exactly which containment layers this run installed, and how.
        ///
        /// `None` means the run was deliberately unconfined. No control may
        /// be claimed from a run whose layer was not installed.
        pub(crate) containment: Option<LinuxContainmentEvidence>,
    }

    /// The ordered kernel evidence one whole-domain kill produced.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct LinuxDomainKillObservation {
        pub(crate) kill_value: Vec<u8>,
        pub(crate) events_after_kill: String,
        pub(crate) populated_zero: bool,
        pub(crate) stable_empty_reads: u8,
        pub(crate) pids_current_after_kill: String,
        pub(crate) surviving_processes: u64,
    }

    /// One reserved leaf beneath an already-delegated cgroup-v2 root.
    ///
    /// The leaf is the accounting and kill domain for every canary run through
    /// it. Dropping the value kills and removes the leaf; nothing here can
    /// outlive the controller.
    #[derive(Debug)]
    pub(crate) struct LinuxDelegatedCanaryDomain {
        root_path: PathBuf,
        root: OwnedFd,
        root_inode: u64,
        leaf_name: String,
        leaf: OwnedFd,
        leaf_inode: u64,
        image: File,
        image_path: PathBuf,
        requested_pids_max: Option<u64>,
        read_back_pids_max: Option<String>,
        requested_memory_max: Option<u64>,
        read_back_memory_max: Option<String>,
        removed: bool,
        /// Whether this domain created the leaf and must therefore remove it.
        ///
        /// `true` only for [`LinuxDelegatedCanaryDomain::reserve`], which
        /// mints the name and calls `mkdirat`. An adopted leaf belongs to the
        /// probe journal that created it and whose remove-intent generation
        /// will unlink it, so this domain kills and proves it empty and stops
        /// there. Unlinking it here would destroy the object a durable
        /// generation still describes.
        owns_leaf: bool,
    }

    impl LinuxDelegatedCanaryDomain {
        /// Reserves one leaf and installs the exact requested ceilings.
        ///
        /// # Errors
        ///
        /// Fails when the supplied root is not a cgroup-v2 directory this
        /// process may extend, when the leaf cannot be created, or when a
        /// requested controller file is absent because the delegation's parent
        /// did not enable that controller.
        pub(crate) fn reserve(
            delegation_root: &Path,
            image: File,
            pids_max: Option<u64>,
            memory_max: Option<u64>,
        ) -> Result<Self, LinuxDevDomainError> {
            let root = open(
                delegation_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                LinuxDevDomainError::new(
                    "open-delegated-cgroup-root",
                    format!("{}: {error}", delegation_root.display()),
                )
            })?;
            let filesystem = fstatfs(&root).map_err(|error| {
                LinuxDevDomainError::new("inspect-delegated-cgroup-root", error.to_string())
            })?;
            if u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
                return Err(LinuxDevDomainError::new(
                    "inspect-delegated-cgroup-root",
                    format!(
                        "{} is not a cgroup-v2 filesystem",
                        delegation_root.display()
                    ),
                ));
            }
            let root_inode = rustix::fs::fstat(&root)
                .map_err(|error| {
                    LinuxDevDomainError::new("inspect-delegated-cgroup-root", error.to_string())
                })?
                .st_ino;
            let sequence = NEXT_CANARY_LEAF.fetch_add(1, Ordering::Relaxed);
            let leaf_name = format!("gbd-canary-{}-{sequence}", std::process::id());
            mkdirat(&root, leaf_name.as_str(), Mode::from_bits_truncate(0o755)).map_err(
                |error| {
                    LinuxDevDomainError::new("create-canary-leaf", format!("{leaf_name}: {error}"))
                },
            )?;
            let leaf = match openat(
                &root,
                leaf_name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            ) {
                Ok(leaf) => leaf,
                Err(error) => {
                    let _ignored = unlinkat(&root, leaf_name.as_str(), AtFlags::REMOVEDIR);
                    return Err(LinuxDevDomainError::new(
                        "open-canary-leaf",
                        error.to_string(),
                    ));
                }
            };
            let leaf_inode = rustix::fs::fstat(&leaf)
                .map_err(|error| {
                    LinuxDevDomainError::new("inspect-canary-leaf", error.to_string())
                })?
                .st_ino;
            let image_path = PathBuf::from(format!("/proc/self/fd/{}", image.as_raw_fd()));
            let mut domain = Self {
                root_path: delegation_root.to_path_buf(),
                root,
                root_inode,
                leaf_name,
                leaf,
                leaf_inode,
                image,
                image_path,
                requested_pids_max: pids_max,
                read_back_pids_max: None,
                requested_memory_max: memory_max,
                read_back_memory_max: None,
                removed: false,
                owns_leaf: true,
            };
            if let Err(error) = domain.install_ceilings() {
                domain.remove();
                return Err(error);
            }
            Ok(domain)
        }

        /// Adopts a journal-owned cgroup leaf without creating or removing it.
        /// The held delegation avoids path re-resolution; the opened leaf must match
        /// the journal's device and inode. Set every resource ceiling, including
        /// unlimited values, so prior canaries cannot affect later runs.
        ///
        /// # Errors
        ///
        /// Fails if the delegation cannot be cloned or is not cgroup v2, the leaf
        /// cannot be opened, its identity changed, or a required controller is absent.
        pub(crate) fn adopt(
            delegation: std::os::fd::BorrowedFd<'_>,
            leaf_name: &str,
            identity: (u64, u64),
            image: File,
            pids_max: Option<u64>,
            memory_max: Option<u64>,
        ) -> Result<Self, LinuxDevDomainError> {
            let root = delegation.try_clone_to_owned().map_err(|error| {
                LinuxDevDomainError::new("adopt-delegated-cgroup-root", error.to_string())
            })?;
            let filesystem = fstatfs(&root).map_err(|error| {
                LinuxDevDomainError::new("inspect-delegated-cgroup-root", error.to_string())
            })?;
            if u64::try_from(filesystem.f_type).ok() != Some(CGROUP2_SUPER_MAGIC) {
                return Err(LinuxDevDomainError::new(
                    "inspect-delegated-cgroup-root",
                    "the adopted delegation is not a cgroup-v2 filesystem".to_owned(),
                ));
            }
            let root_inode = rustix::fs::fstat(&root)
                .map_err(|error| {
                    LinuxDevDomainError::new("inspect-delegated-cgroup-root", error.to_string())
                })?
                .st_ino;
            // No `mkdirat`. The leaf must already exist, because the journal
            // created it.
            let leaf = openat(
                &root,
                leaf_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| {
                LinuxDevDomainError::new(
                    "open-adopted-canary-leaf",
                    format!("{leaf_name}: {error}"),
                )
            })?;
            let leaf_status = rustix::fs::fstat(&leaf).map_err(|error| {
                LinuxDevDomainError::new("inspect-adopted-canary-leaf", error.to_string())
            })?;
            let observed = (leaf_status.st_dev, leaf_status.st_ino);
            if observed != identity {
                return Err(LinuxDevDomainError::new(
                    "inspect-adopted-canary-leaf",
                    format!(
                        "{leaf_name} is not the leaf the probe journal observed: kernel reports \
                         {observed:?} and the journal recorded {identity:?}"
                    ),
                ));
            }
            let image_path = PathBuf::from(format!("/proc/self/fd/{}", image.as_raw_fd()));
            let mut domain = Self {
                root_path: PathBuf::new(),
                root,
                root_inode,
                leaf_name: leaf_name.to_owned(),
                leaf,
                leaf_inode: leaf_status.st_ino,
                image,
                image_path,
                requested_pids_max: pids_max,
                read_back_pids_max: None,
                requested_memory_max: memory_max,
                read_back_memory_max: None,
                removed: false,
                owns_leaf: false,
            };
            domain.install_definite_ceilings()?;
            Ok(domain)
        }

        /// Writes every managed ceiling to a definite value and reads it back.
        ///
        /// Used only by [`Self::adopt`]. `reserve` keeps its original
        /// behaviour untouched, because a leaf it created is new and carries
        /// the delegation's inherited defaults by construction; an adopted
        /// leaf is reused across a whole suite and carries whatever the
        /// previous run left, so "unlimited" has to be written rather than
        /// assumed.
        fn install_definite_ceilings(&mut self) -> Result<(), LinuxDevDomainError> {
            let pids = self
                .requested_pids_max
                .map_or_else(|| "max\n".to_owned(), |limit| format!("{limit}\n"));
            self.write_leaf_file("pids.max", pids.as_bytes())?;
            self.read_back_pids_max = Some(self.read_leaf_file("pids.max")?);
            let memory = self
                .requested_memory_max
                .map_or_else(|| "max\n".to_owned(), |limit| format!("{limit}\n"));
            self.write_leaf_file("memory.max", memory.as_bytes())?;
            self.read_back_memory_max = Some(self.read_leaf_file("memory.max")?);
            // A finite aggregate memory ceiling is only a ceiling when the
            // domain cannot page out of it, and an unlimited one must not
            // inherit the previous run's swap ban.
            let swap: &[u8] = if self.requested_memory_max.is_some() {
                b"0\n"
            } else {
                b"max\n"
            };
            self.write_leaf_file("memory.swap.max", swap)?;
            Ok(())
        }

        fn install_ceilings(&mut self) -> Result<(), LinuxDevDomainError> {
            if let Some(limit) = self.requested_pids_max {
                self.write_leaf_file("pids.max", format!("{limit}\n").as_bytes())?;
                self.read_back_pids_max = Some(self.read_leaf_file("pids.max")?);
            }
            if let Some(limit) = self.requested_memory_max {
                self.write_leaf_file("memory.max", format!("{limit}\n").as_bytes())?;
                self.read_back_memory_max = Some(self.read_leaf_file("memory.max")?);
                // A finite aggregate memory ceiling is only a ceiling when the
                // domain cannot page out of it.
                self.write_leaf_file("memory.swap.max", b"0\n")?;
            }
            Ok(())
        }

        pub(crate) fn root_path(&self) -> &Path {
            &self.root_path
        }

        pub(crate) const fn root_inode(&self) -> u64 {
            self.root_inode
        }

        pub(crate) const fn leaf_inode(&self) -> u64 {
            self.leaf_inode
        }

        pub(crate) fn leaf_name(&self) -> &str {
            &self.leaf_name
        }

        pub(crate) fn read_back_pids_max(&self) -> Option<&str> {
            self.read_back_pids_max.as_deref()
        }

        pub(crate) fn read_back_memory_max(&self) -> Option<&str> {
            self.read_back_memory_max.as_deref()
        }

        pub(crate) fn image_path(&self) -> &Path {
            &self.image_path
        }

        fn write_leaf_file(&self, name: &str, bytes: &[u8]) -> Result<(), LinuxDevDomainError> {
            let file = openat(
                &self.leaf,
                name,
                OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                LinuxDevDomainError::new(
                    "open-cgroup-control-file",
                    format!("{name}: {error} (is the controller enabled on the delegation?)"),
                )
            })?;
            rustix::io::write(&file, bytes).map_err(|error| {
                LinuxDevDomainError::new("write-cgroup-control-file", format!("{name}: {error}"))
            })?;
            Ok(())
        }

        fn read_leaf_file(&self, name: &str) -> Result<String, LinuxDevDomainError> {
            let bytes = self.read_leaf_bytes(name)?;
            String::from_utf8(bytes).map_err(|error| {
                LinuxDevDomainError::new("decode-cgroup-control-file", format!("{name}: {error}"))
            })
        }

        fn read_leaf_bytes(&self, name: &str) -> Result<Vec<u8>, LinuxDevDomainError> {
            let file = openat(
                &self.leaf,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                LinuxDevDomainError::new(
                    "open-cgroup-control-file",
                    format!("{name}: {error} (is the controller enabled on the delegation?)"),
                )
            })?;
            let mut file = File::from(file);
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1_024];
            loop {
                let count = file.read(&mut buffer).map_err(|error| {
                    LinuxDevDomainError::new("read-cgroup-control-file", format!("{name}: {error}"))
                })?;
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > MAX_CONTROL_FILE_BYTES {
                    return Err(LinuxDevDomainError::new(
                        "read-cgroup-control-file",
                        format!("{name} exceeded its hard byte bound"),
                    ));
                }
            }
            Ok(bytes)
        }

        /// Processes the operating system currently charges to this leaf.
        pub(crate) fn membership(&self) -> Result<Vec<u32>, LinuxDevDomainError> {
            let bytes = self.read_leaf_bytes("cgroup.procs")?;
            parse_cgroup_procs(&bytes).map_err(|error| {
                LinuxDevDomainError::new("parse-cgroup-procs", format!("{error:?}"))
            })
        }

        fn optional_leaf_file(&self, name: &str) -> String {
            self.read_leaf_file(name).unwrap_or_default()
        }

        /// `pids.current` once every exited task has also been collected.
        ///
        /// The counter is not a liveness signal on its own: a killed process
        /// keeps its PID, and therefore its charge, until its parent reaps it.
        /// `cgroup.procs` and `cgroup.events` go empty immediately; this value
        /// settles a moment later, so it is polled rather than sampled once.
        fn settled_pids_current(&self) -> String {
            let deadline = Instant::now() + EMPTY_PROOF_TIMEOUT;
            let mut observed = self.optional_leaf_file("pids.current");
            while observed.trim() != "0" && Instant::now() < deadline {
                std::thread::sleep(DRAIN_POLL_INTERVAL);
                observed = self.optional_leaf_file("pids.current");
            }
            observed
        }

        /// Kills every process charged to the leaf and proves it empty.
        pub(crate) fn kill_and_prove_empty(
            &self,
        ) -> Result<LinuxDomainKillObservation, LinuxDevDomainError> {
            self.write_leaf_file("cgroup.kill", CGROUP_KILL_VALUE)?;
            let deadline = Instant::now() + EMPTY_PROOF_TIMEOUT;
            let mut events_after_kill = String::new();
            let mut populated_zero = false;
            while Instant::now() < deadline {
                let bytes = self.read_leaf_bytes("cgroup.events")?;
                events_after_kill = String::from_utf8_lossy(&bytes).into_owned();
                let events = parse_cgroup_events(&bytes).map_err(|error| {
                    LinuxDevDomainError::new("parse-cgroup-events", format!("{error:?}"))
                })?;
                if !events.populated {
                    populated_zero = true;
                    break;
                }
                std::thread::sleep(DRAIN_POLL_INTERVAL);
            }
            let mut stable_empty_reads = 0_u8;
            let mut surviving = 0_u64;
            for _ in 0..2_u8 {
                let members = self.membership()?;
                surviving = u64::try_from(members.len()).unwrap_or(u64::MAX);
                if members.is_empty() {
                    stable_empty_reads += 1;
                } else {
                    break;
                }
            }
            Ok(LinuxDomainKillObservation {
                kill_value: CGROUP_KILL_VALUE.to_vec(),
                events_after_kill,
                populated_zero,
                stable_empty_reads,
                pids_current_after_kill: self.optional_leaf_file("pids.current"),
                surviving_processes: surviving,
            })
        }

        /// Runs one canary inside the reserved leaf and drains it completely.
        ///
        /// # Errors
        ///
        /// Fails when the retained image, working directory, or `cgroup.procs`
        /// descriptor cannot be prepared, or when the canary cannot be spawned.
        #[allow(
            clippy::too_many_lines,
            reason = "the spawn, bounded drain, kill trigger, deadline, and terminal accounting of one canary stay in one visible order"
        )]
        pub(crate) fn run(
            &self,
            specification: &CanarySpecification<'_>,
        ) -> Result<LinuxCanaryRunObservation, LinuxDevDomainError> {
            let working_directory =
                File::open(specification.working_directory).map_err(|error| {
                    LinuxDevDomainError::new(
                        "open-canary-working-directory",
                        format!("{}: {error}", specification.working_directory.display()),
                    )
                })?;
            let membership = openat(
                &self.leaf,
                "cgroup.procs",
                OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                LinuxDevDomainError::new("open-canary-cgroup-procs", error.to_string())
            })?;
            // Both layers are built here, in the controller, before the fork:
            // everything that allocates, the ruleset, its rules, the
            // compiled BPF program, happens on this side of it.
            let (containment, containment_evidence) = match specification.containment {
                Some(policy) => {
                    let (containment, evidence) = build_child_containment(policy)?;
                    (containment, Some(evidence))
                }
                None => (
                    ChildContainment::new(None, BpfProgram::new(), BpfProgram::new()),
                    None,
                ),
            };
            let controller_descriptors = controller_descriptor_count();
            let mut command = Command::new(&self.image_path);
            command
                .arg(LINUX_CANARY_HELPER_ARGUMENT)
                .arg("leader")
                .arg(specification.mode)
                .arg(specification.parameter);
            for extra in specification.extra_arguments {
                command.arg(extra);
            }
            command.env_clear();
            for (name, value) in specification.environment {
                command.env(name, value);
            }
            command
                .current_dir("/")
                .stdin(Stdio::from(working_directory))
                .stdout(Stdio::piped())
                .stderr(Stdio::from(File::from(membership)));
            let started = Instant::now();
            // The child applies both layers between `fork` and `execve`; a
            // layer that will not install completely fails the child before
            // the image is replaced, so a canary that reports at all reports
            // from inside the complete policy.
            let mut child = spawn_with_child_containment(&mut command, containment)
                .map_err(|error| LinuxDevDomainError::new("spawn-canary", error.to_string()))?;
            let mut stdout = child.stdout.take().ok_or_else(|| {
                LinuxDevDomainError::new("drain-canary", "the canary pipe was not created")
            })?;

            let mut pending = Vec::new();
            let mut reports: Vec<LinuxCanaryReportV1> = Vec::new();
            let mut hasher = Sha256::new();
            let mut payload_bytes = 0_u64;
            let mut payload_chunks = 0_u64;
            let mut maximum_chunk_bytes = 0_usize;
            let mut procs_at_report = Vec::new();
            let mut kill = None;
            let mut deadline_expired = false;
            let mut buffer = [0_u8; DRAIN_CHUNK_BYTES];
            let deadline = started + specification.deadline;
            // Even a killed domain must not leave the controller draining
            // forever, so the drain has its own terminal bound beyond the
            // canary's deadline.
            let hard_stop = deadline + EMPTY_PROOF_TIMEOUT + EMPTY_PROOF_TIMEOUT;
            loop {
                if Instant::now() >= hard_stop {
                    break;
                }
                if Instant::now() >= deadline {
                    deadline_expired = true;
                    if kill.is_none() {
                        kill = Some(self.kill_and_prove_empty()?);
                    }
                }
                let readable = poll_readable(stdout.as_fd(), DRAIN_POLL_INTERVAL);
                if readable {
                    let count = stdout.read(&mut buffer).map_err(|error| {
                        LinuxDevDomainError::new("drain-canary", error.to_string())
                    })?;
                    if count == 0 {
                        break;
                    }
                    maximum_chunk_bytes = maximum_chunk_bytes.max(count);
                    if reports.len() >= specification.expected_reports {
                        hasher.update(&buffer[..count]);
                        payload_bytes += u64::try_from(count).unwrap_or(0);
                        payload_chunks += 1;
                    } else {
                        pending.extend_from_slice(&buffer[..count]);
                        loop {
                            if reports.len() >= specification.expected_reports {
                                break;
                            }
                            let Some(position) = pending.iter().position(|byte| *byte == b'\n')
                            else {
                                break;
                            };
                            let line = pending.drain(..=position).collect::<Vec<u8>>();
                            let report: LinuxCanaryReportV1 = serde_json::from_slice(
                                &line[..line.len() - 1],
                            )
                            .map_err(|error| {
                                LinuxDevDomainError::new("decode-canary-report", error.to_string())
                            })?;
                            report.validate().map_err(|detail| {
                                LinuxDevDomainError::new("validate-canary-report", detail)
                            })?;
                            reports.push(report);
                        }
                        if reports.len() >= specification.expected_reports && !pending.is_empty() {
                            maximum_chunk_bytes = maximum_chunk_bytes.max(pending.len());
                            hasher.update(&pending);
                            payload_bytes += u64::try_from(pending.len()).unwrap_or(0);
                            payload_chunks += 1;
                            pending.clear();
                        }
                    }
                }
                if let Some(threshold) = specification.kill_after_reports
                    && kill.is_none()
                    && reports.len() >= threshold
                {
                    procs_at_report = self.membership()?;
                    kill = Some(self.kill_and_prove_empty()?);
                }
            }
            if procs_at_report.is_empty() && kill.is_none() {
                procs_at_report = self.membership()?;
            }
            let status = child
                .wait()
                .map_err(|error| LinuxDevDomainError::new("reap-canary", error.to_string()))?;
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let exit = status.code().map_or_else(
                || status.signal().map(CanaryExit::Signaled),
                |code| Some(CanaryExit::Exited(code)),
            );
            Ok(LinuxCanaryRunObservation {
                reports,
                payload_bytes,
                payload_digest: encode_hex(&hasher.finalize()),
                payload_chunks,
                maximum_chunk_bytes,
                exit,
                elapsed_ms,
                deadline_expired,
                root_inode: self.root_inode,
                leaf_inode: self.leaf_inode,
                controller_descriptors,
                procs_at_report,
                pids_current: self.settled_pids_current(),
                pids_events: self.optional_leaf_file("pids.events"),
                memory_events: self.optional_leaf_file("memory.events"),
                kill,
                containment: containment_evidence,
            })
        }

        /// Kills the leaf, proves it empty, and removes it **if it is ours**.
        ///
        /// The unlink is conditional on this domain having created the leaf.
        /// An adopted leaf is the probe journal's: it exists inside a durable
        /// generation that has already recorded the intent to remove it
        /// exactly, and removing it here would leave that generation
        /// describing an object this code destroyed behind its back. Killing
        /// and proving empty is still done in both cases, because leaving live
        /// processes charged to a leaf the journal is about to remove would
        /// make the journal's own empty proof race this domain's drop.
        pub(crate) fn remove(&mut self) {
            if self.removed {
                return;
            }
            self.removed = true;
            let _ignored = self.kill_and_prove_empty();
            if self.owns_leaf {
                let _ignored = unlinkat(&self.root, self.leaf_name.as_str(), AtFlags::REMOVEDIR);
            }
        }
    }

    impl Drop for LinuxDelegatedCanaryDomain {
        fn drop(&mut self) {
            self.remove();
        }
    }

    /// Copies the running runner image into a sealed, executable memfd.
    ///
    /// The result has no pathname anywhere in any filesystem, so the only way
    /// to execute it is through the retained descriptor. That is what makes a
    /// descriptor-exec claim a measurement rather than a convention.
    ///
    /// # Errors
    ///
    /// Fails when procfs is unavailable, the copy is short, or the kernel does
    /// not support `MFD_EXEC`/`F_SEAL_EXEC`. There is no weaker fallback.
    pub(crate) fn sealed_self_image() -> Result<File, LinuxDevDomainError> {
        let source_path = canary_image_source();
        let source = open(
            &source_path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            LinuxDevDomainError::new(
                "open-canary-source-image",
                format!("{}: {error}", source_path.display()),
            )
        })?;
        let mut source = File::from(source);
        let descriptor = rustix::fs::memfd_create(
            "grok-build-linux-canary-image-v1",
            rustix::fs::MemfdFlags::CLOEXEC
                | rustix::fs::MemfdFlags::ALLOW_SEALING
                | rustix::fs::MemfdFlags::EXEC,
        )
        .map_err(|error| {
            LinuxDevDomainError::new("create-canary-sealed-image", error.to_string())
        })?;
        let mut image = File::from(descriptor);
        let mut buffer = [0_u8; 16 * 1_024];
        let mut length = 0_u64;
        loop {
            let count = source.read(&mut buffer).map_err(|error| {
                LinuxDevDomainError::new("copy-canary-sealed-image", error.to_string())
            })?;
            if count == 0 {
                break;
            }
            image.write_all(&buffer[..count]).map_err(|error| {
                LinuxDevDomainError::new("copy-canary-sealed-image", error.to_string())
            })?;
            length += u64::try_from(count).unwrap_or(0);
        }
        if length == 0 {
            return Err(LinuxDevDomainError::new(
                "copy-canary-sealed-image",
                "the runner image copied zero bytes",
            ));
        }
        rustix::fs::fchmod(&image, Mode::from_bits_truncate(0o500)).map_err(|error| {
            LinuxDevDomainError::new("seal-canary-image-mode", error.to_string())
        })?;
        let required = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::FUTURE_WRITE
            | rustix::fs::SealFlags::EXEC;
        rustix::fs::fcntl_add_seals(&image, required)
            .map_err(|error| LinuxDevDomainError::new("seal-canary-image", error.to_string()))?;
        let observed = rustix::fs::fcntl_get_seals(&image).map_err(|error| {
            LinuxDevDomainError::new("read-canary-image-seals", error.to_string())
        })?;
        if observed != required {
            return Err(LinuxDevDomainError::new(
                "read-canary-image-seals",
                "the canary image did not retain the exact required seal set",
            ));
        }
        Ok(image)
    }

    /// Opens the runner image by its ordinary pathname.
    ///
    /// This is the control half of the descriptor-exec comparison: the same
    /// bytes, launched by the same mechanism, but with a name in a filesystem.
    /// It exists so the sealed-memfd observation can be shown to discriminate
    /// rather than to be a constant.
    ///
    /// # Errors
    ///
    /// Fails when the named runner image cannot be opened.
    pub(crate) fn named_self_image() -> Result<File, LinuxDevDomainError> {
        let source_path = canary_image_source();
        let source = open(
            &source_path,
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            LinuxDevDomainError::new(
                "open-canary-named-image",
                format!("{}: {error}", source_path.display()),
            )
        })?;
        Ok(File::from(source))
    }

    /// The image whose sealed copy every canary executes.
    ///
    /// Production copies the running runner from genuine procfs. Under
    /// `cfg(test)` the running image is the test harness rather than a runner,
    /// so the tests locate the ordinary runner binary exactly as the native
    /// held-launcher tests already do; the canary helper mode lives in that
    /// binary's entry point and nowhere else.
    pub(crate) fn canary_image_source() -> PathBuf {
        #[cfg(not(test))]
        {
            PathBuf::from("/proc/self/exe")
        }
        #[cfg(test)]
        {
            if let Some(path) = option_env!("CARGO_BIN_EXE_grok-build-runner") {
                return PathBuf::from(path);
            }
            if let Some(path) = std::env::var_os("CARGO_BIN_EXE_grok-build-runner") {
                return PathBuf::from(path);
            }
            let current = std::env::current_exe().expect("a test executable has a path");
            let profile = current
                .parent()
                .and_then(Path::parent)
                .expect("unit test executable must be under target/<profile>/deps");
            let candidate = profile.join("grok-build-runner");
            assert!(
                candidate.is_file(),
                "Linux canary tests require the regular runner binary; use cargo test --all-targets"
            );
            candidate
        }
    }

    /// Descriptors this controller itself holds right before a spawn.
    ///
    /// A child table of exactly `{0, 1, 2}` is only a shed when the launching
    /// process held more than three at the fork; this is that denominator.
    fn controller_descriptor_count() -> usize {
        let Ok(directory) = open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            return 0;
        };
        let mut buffer = [MaybeUninit::<u8>::uninit(); 4_096];
        let mut entries = RawDir::new(&directory, &mut buffer);
        let mut count = 0_usize;
        while let Some(entry) = entries.next() {
            let Ok(entry) = entry else {
                return count;
            };
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            count += 1;
        }
        // The enumerator itself is not inherited authority.
        count.saturating_sub(1)
    }

    fn poll_readable(descriptor: std::os::fd::BorrowedFd<'_>, timeout: Duration) -> bool {
        let mut fds = [rustix::event::PollFd::new(
            &descriptor,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(0),
            tv_nsec: i64::from(timeout.subsec_nanos()),
        };
        matches!(
            rustix::event::poll(&mut fds, Some(&timeout)),
            Ok(count) if count > 0
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ignored = write!(&mut encoded, "{byte:02x}");
        }
        encoded
    }

    // Build Landlock and both BPF filters in the controller before fork. The
    // child receives the ruleset descriptor and compiled filters, and uses only
    // bounded syscalls without allocation.

    use landlock::{
        ABI, Access as _, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible as _, PathBeneath,
        PathFd, Ruleset, RulesetAttr as _, RulesetCreated, RulesetCreatedAttr as _,
    };
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    use crate::linux_held_launcher::{ChildContainment, spawn_with_child_containment};

    /// The lowest Landlock ABI at which a path policy is installed at all.
    ///
    /// ABI 3 is where `LANDLOCK_ACCESS_FS_TRUNCATE` arrives; below it a
    /// read-only scope is not read-only, because `truncate(2)` on a pathname
    /// is unhooked and a confined program can empty a file it may only read.
    /// ABI 4 is where the kernel first models the TCP-port access set the
    /// architecture document names, so it is the first level at which that
    /// document's Landlock contract exists rather than being approximated.
    ///
    /// A kernel below this level is a **typed refusal**, never a downgrade:
    /// no ruleset is created, no partially-handled access set is installed,
    /// `FilesystemPolicy` is not claimed, and the observed level is reported.
    /// A partially enforced path policy that still named `FilesystemPolicy`
    /// would be exactly the dishonesty this backend exists to avoid.
    pub(crate) const REQUIRED_LANDLOCK_ABI: ABI = ABI::V4;

    /// `EPERM`, the errno the syscall layer returns for a network endpoint.
    ///
    /// It is deliberately *not* the `EACCES` Landlock produces for a denied
    /// path, so the errno a canary reports names which layer refused it.
    pub(crate) const LINUX_SECCOMP_NETWORK_ERRNO: u32 = 1;

    /// The authenticated read-only runtime surfaces a contained target needs
    /// before one instruction of its own code runs.
    ///
    /// The kernel resolves the ELF interpreter and the complete shared-object
    /// closure of the target image *after* Landlock is applied, so a policy
    /// that omits them does not confine the target, it prevents it from
    /// starting, and a program that never started proves nothing. `/proc` is
    /// here for the mirror-image reason: the contained program's own
    /// self-observation and the `/proc/self/fd/<n>` name through which a
    /// sealed memfd image is executed both resolve through it.
    ///
    /// Every entry is read-and-execute only, and an absent entry grants
    /// nothing rather than being silently substituted. The resolved list
    /// travels in the evidence.
    const LINUX_RUNTIME_READ_ROOTS: &[&str] = &[
        "/usr",
        "/lib",
        "/lib64",
        "/proc",
        "/etc/ld.so.cache",
        "/dev/urandom",
        "/dev/zero",
    ];

    /// The one runtime surface a contained target also writes.
    ///
    /// `/dev/null` is not a convenience. `Stdio::null()`, every shell
    /// redirection, and most toolchains open it, and a path policy that omits
    /// it does not confine a workload, it stops one, and a program that
    /// never ran proves nothing. It is named exactly: no directory under
    /// `/dev` is granted, so no other device is reachable through it.
    const LINUX_RUNTIME_WRITE_SURFACES: &[&str] = &["/dev/null"];

    /// The runtime read surfaces that actually exist on this host.
    ///
    /// An absent entry grants nothing and is not substituted; the resolved
    /// list is what the evidence records.
    pub(crate) fn linux_runtime_read_roots() -> Vec<PathBuf> {
        LINUX_RUNTIME_READ_ROOTS
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect()
    }

    /// The runtime read/write surfaces that actually exist on this host.
    pub(crate) fn linux_runtime_write_surfaces() -> Vec<PathBuf> {
        LINUX_RUNTIME_WRITE_SURFACES
            .iter()
            .map(PathBuf::from)
            .filter(|path| path.exists())
            .collect()
    }

    /// Name and number of every syscall a denied-network filter refuses.
    ///
    /// The numbering is this architecture's, taken from its own
    /// `asm/unistd` table; the seccomp program additionally carries
    /// `seccompiler`'s architecture prologue, which kills the process
    /// outright if the audit architecture is not the one these numbers were
    /// compiled for. A host whose architecture has no table here installs no
    /// filter and claims no network control.
    #[cfg(target_arch = "aarch64")]
    pub(crate) const LINUX_NETWORK_SYSCALLS: &[(&str, i64)] = &[
        ("socket", 198),
        ("socketpair", 199),
        ("bind", 200),
        ("listen", 201),
        ("accept", 202),
        ("connect", 203),
        ("getsockname", 204),
        ("getpeername", 205),
        ("sendto", 206),
        ("recvfrom", 207),
        ("setsockopt", 208),
        ("getsockopt", 209),
        ("shutdown", 210),
        ("sendmsg", 211),
        ("recvmsg", 212),
        ("accept4", 242),
        ("recvmmsg", 243),
        ("sendmmsg", 269),
        ("io_uring_setup", 425),
    ];

    #[cfg(target_arch = "x86_64")]
    pub(crate) const LINUX_NETWORK_SYSCALLS: &[(&str, i64)] = &[
        ("socket", 41),
        ("connect", 42),
        ("accept", 43),
        ("sendto", 44),
        ("recvfrom", 45),
        ("sendmsg", 46),
        ("recvmsg", 47),
        ("shutdown", 48),
        ("bind", 49),
        ("listen", 50),
        ("getsockname", 51),
        ("getpeername", 52),
        ("socketpair", 53),
        ("setsockopt", 54),
        ("getsockopt", 55),
        ("accept4", 288),
        ("recvmmsg", 299),
        ("sendmmsg", 307),
        ("io_uring_setup", 425),
    ];

    /// `ENOSYS`, the errno the namespace layer returns.
    ///
    /// This denies `clone3` without breaking
    /// ordinary work. glibc since 2.34 issues `clone3` from `pthread_create`
    /// and falls back to legacy `clone` on `ENOSYS` alone; `EPERM` is not a
    /// fallback trigger and fails thread creation outright, and killing the
    /// process destroys it at its first thread.
    ///
    /// It also identifies which layer refused, as with
    /// [`LINUX_SECCOMP_NETWORK_ERRNO`] above. A container's own seccomp
    /// profile answers `EPERM` for these syscalls, so a canary that accepted
    /// any failure would pass on borrowed protection it does not own. Only
    /// `ENOSYS` is ours.
    pub(crate) const LINUX_SECCOMP_NAMESPACE_ERRNO: u32 = 38;

    #[cfg(target_arch = "aarch64")]
    pub(crate) const LINUX_SECCOMP_TARGET_ARCH: seccompiler::TargetArch =
        seccompiler::TargetArch::aarch64;
    #[cfg(target_arch = "x86_64")]
    pub(crate) const LINUX_SECCOMP_TARGET_ARCH: seccompiler::TargetArch =
        seccompiler::TargetArch::x86_64;

    #[cfg(target_arch = "aarch64")]
    const LINUX_SECCOMP_TARGET_ARCH_NAME: &str = "aarch64";
    #[cfg(target_arch = "x86_64")]
    const LINUX_SECCOMP_TARGET_ARCH_NAME: &str = "x86_64";

    /// The compiled path and syscall scopes one contained target is confined
    /// to, plus which layers this particular run installs.
    ///
    /// The layer switches exist so every canary verdict has a control run that
    /// differs in exactly one input: the filesystem canary's control run keeps
    /// the syscall layers and drops the path layer, the network canary's
    /// control run drops the network filter, and the namespace canary's
    /// control run drops the namespace filter. A flip is then attributable to
    /// one named layer rather than to "containment" in general.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(crate) struct LinuxContainmentPolicy {
        /// Exact roots the target may read from and execute out of.
        pub(crate) read_roots: Vec<PathBuf>,
        /// Exact roots the target may additionally write inside.
        pub(crate) write_roots: Vec<PathBuf>,
        /// Whether the Landlock path layer is installed for this run.
        pub(crate) filesystem_layer: bool,
        /// Whether the seccomp layer denies every network endpoint.
        pub(crate) network_layer: bool,
        /// Whether a second seccomp layer denies every namespace route.
        ///
        /// A separate switch, and a separate filter, because the two answer
        /// different errnos and one `seccompiler` filter carries exactly one
        /// matched action. Keeping them apart also leaves the network filter's
        /// bytes untouched, so its committed digest and the evidence resting on
        /// it stay valid.
        pub(crate) namespace_layer: bool,
    }

    impl LinuxContainmentPolicy {
        /// The same scopes with the path layer removed and nothing else changed.
        pub(crate) fn without_filesystem_layer(&self) -> Self {
            Self {
                filesystem_layer: false,
                ..self.clone()
            }
        }

        /// The same scopes with the syscall layer removed and nothing else changed.
        pub(crate) fn without_network_layer(&self) -> Self {
            Self {
                network_layer: false,
                ..self.clone()
            }
        }

        /// The same scopes with the namespace layer removed, nothing else changed.
        ///
        /// This is the control arm for every namespace verdict: one input
        /// differs, so a flip is attributable to this layer and to nothing else.
        pub(crate) fn without_namespace_layer(&self) -> Self {
            Self {
                namespace_layer: false,
                ..self.clone()
            }
        }
    }

    /// Exactly what the controller negotiated and compiled for one run.
    ///
    /// Every field is an observation. `landlock_installed` and
    /// `seccomp_installed` are the only two facts a control claim may rest
    /// on, and both are false until the corresponding layer was actually
    /// built.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub(crate) struct LinuxContainmentEvidence {
        pub(crate) landlock_installed: bool,
        pub(crate) landlock_required_abi: u8,
        pub(crate) landlock_observed_abi: u8,
        pub(crate) landlock_handled_access_bits: u64,
        pub(crate) landlock_read_roots: Vec<String>,
        pub(crate) landlock_write_roots: Vec<String>,
        pub(crate) landlock_build_micros: u128,
        pub(crate) seccomp_installed: bool,
        pub(crate) seccomp_target_arch: String,
        pub(crate) seccomp_denied_syscalls: Vec<String>,
        pub(crate) seccomp_instructions: usize,
        pub(crate) seccomp_denied_errno: u32,
        pub(crate) seccomp_build_micros: u128,
        pub(crate) namespace_seccomp_installed: bool,
        pub(crate) namespace_denied_syscalls: Vec<String>,
        /// The `CLONE_NEW*` names `clone` is refused for, in listed order.
        pub(crate) namespace_clone_flags: Vec<String>,
        pub(crate) namespace_seccomp_instructions: usize,
        pub(crate) namespace_seccomp_denied_errno: u32,
        pub(crate) namespace_seccomp_build_micros: u128,
    }

    /// The ABI level as the number the kernel and the documentation use.
    pub(crate) const fn abi_level(abi: ABI) -> u8 {
        match abi {
            ABI::V1 => 1,
            ABI::V2 => 2,
            ABI::V3 => 3,
            ABI::V4 => 4,
            ABI::V5 => 5,
            ABI::V6 => 6,
            ABI::V7 => 7,
            // `ABI::Unsupported` and any level a future crate adds.
            _ => 0,
        }
    }

    /// The highest Landlock ABI this host can be *proved* to implement.
    ///
    /// The probe is the crate's own hard-compatibility semantics rather than
    /// a version string: under [`CompatLevel::HardRequirement`] a ruleset
    /// that requests an access right the running kernel does not implement
    /// fails to build, so the highest level that builds is the level the
    /// kernel implements.
    ///
    /// It saturates at ABI 5. That is a property of what is being asked for,
    /// not a gap: ABI 6 and 7 add socket/signal *scoping* and audit flags
    /// rather than filesystem or network access rights, and this backend
    /// requests neither, so nothing it installs could distinguish them. The
    /// residual relation is recorded rather than claimed.
    pub(crate) fn observed_landlock_abi() -> ABI {
        let filesystem_level = |abi: ABI| {
            Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(AccessFs::from_all(abi))
                .and_then(Ruleset::create)
                .is_ok()
        };
        if filesystem_level(ABI::V5) {
            return ABI::V5;
        }
        let network_level = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessNet::from_all(ABI::V4))
            .and_then(Ruleset::create)
            .is_ok();
        // ABI 4 adds no filesystem right over ABI 3; its own addition is the
        // TCP access set, so that is what distinguishes the two levels.
        if filesystem_level(ABI::V3) {
            return if network_level { ABI::V4 } else { ABI::V3 };
        }
        if filesystem_level(ABI::V2) {
            return ABI::V2;
        }
        if filesystem_level(ABI::V1) {
            return ABI::V1;
        }
        ABI::Unsupported
    }

    /// One `path_beneath` rule over an existing scope.
    fn landlock_scope_rule(
        path: &Path,
        access: BitFlags<AccessFs>,
        abi: ABI,
    ) -> Result<PathBeneath<PathFd>, LinuxDevDomainError> {
        let descriptor = PathFd::new(path).map_err(|error| {
            LinuxDevDomainError::new(
                "open-landlock-scope",
                format!("{}: {error}", path.display()),
            )
        })?;
        // A rule on anything that is not a directory may carry only the
        // file-applicable rights; the kernel refuses the rest outright rather
        // than ignoring them. The test is "is a directory", not "is a regular
        // file", because a character device such as `/dev/null` is neither.
        let access = if path.is_dir() {
            access
        } else {
            access & AccessFs::from_file(abi)
        };
        Ok(PathBeneath::new(descriptor, access))
    }

    /// Builds the Landlock ruleset for one run, or says why it did not.
    fn build_landlock_ruleset(
        policy: &LinuxContainmentPolicy,
        evidence: &mut LinuxContainmentEvidence,
    ) -> Result<RulesetCreated, LinuxDevDomainError> {
        let observed = observed_landlock_abi();
        evidence.landlock_observed_abi = abi_level(observed);
        if observed < REQUIRED_LANDLOCK_ABI {
            return Err(LinuxDevDomainError::new(
                "negotiate-landlock-abi",
                format!(
                    "this kernel implements Landlock ABI {} but the contained-command path policy \
                     requires at least ABI {}; no ruleset is created, nothing is partially \
                     enforced, and no filesystem control is claimed",
                    abi_level(observed),
                    abi_level(REQUIRED_LANDLOCK_ABI)
                ),
            ));
        }
        // Handle the complete access set the *observed* level implements, so
        // a newer kernel restricts strictly more rather than leaving its own
        // additions ungoverned. Hard compatibility means a right the kernel
        // does not implement fails the build instead of being dropped.
        let handled = AccessFs::from_all(observed);
        evidence.landlock_handled_access_bits = handled.bits();
        let readable = AccessFs::from_read(observed);
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(handled)
            .and_then(Ruleset::create)
            .map_err(|error| {
                LinuxDevDomainError::new("create-landlock-ruleset", error.to_string())
            })?;
        for root in &policy.read_roots {
            let rule = landlock_scope_rule(root, readable, observed)?;
            created = created.add_rule(rule).map_err(|error| {
                LinuxDevDomainError::new(
                    "add-landlock-read-rule",
                    format!("{}: {error}", root.display()),
                )
            })?;
            evidence
                .landlock_read_roots
                .push(root.display().to_string());
        }
        for root in &policy.write_roots {
            let rule = landlock_scope_rule(root, handled, observed)?;
            created = created.add_rule(rule).map_err(|error| {
                LinuxDevDomainError::new(
                    "add-landlock-write-rule",
                    format!("{}: {error}", root.display()),
                )
            })?;
            evidence
                .landlock_write_roots
                .push(root.display().to_string());
        }
        Ok(created)
    }

    /// Compiles the denied-network filter for this architecture.
    ///
    /// The filter is a **deny list over exactly the network-endpoint
    /// surface**, not the document's default-deny allowlist. That allowlist
    /// is defined against the complete Bubblewrap namespace stack and is
    /// required to pass `cargo test --offline --locked` unchanged; neither
    /// exists here, so generating one would install a filter nobody has
    /// validated against the real workload and then claim a control for it.
    ///
    /// The deny list is nevertheless *complete for the control it names*: on
    /// Linux a process cannot obtain a network endpoint without `socket` or
    /// `socketpair`, cannot receive one without an existing socket to receive
    /// it over, and cannot operate one without the calls listed here.
    /// `io_uring_setup` is included because a ring can perform socket
    /// operations without any of the others.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn build_network_filter(
        evidence: &mut LinuxContainmentEvidence,
    ) -> Result<BpfProgram, LinuxDevDomainError> {
        let rules = LINUX_NETWORK_SYSCALLS
            .iter()
            .map(|(_, number)| (*number, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(LINUX_SECCOMP_NETWORK_ERRNO),
            LINUX_SECCOMP_TARGET_ARCH,
        )
        .map_err(|error| LinuxDevDomainError::new("compile-seccomp-filter", error.to_string()))?;
        let program = BpfProgram::try_from(filter).map_err(|error| {
            LinuxDevDomainError::new("assemble-seccomp-filter", error.to_string())
        })?;
        LINUX_SECCOMP_TARGET_ARCH_NAME.clone_into(&mut evidence.seccomp_target_arch);
        evidence.seccomp_denied_syscalls = LINUX_NETWORK_SYSCALLS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        evidence.seccomp_instructions = program.len();
        evidence.seccomp_denied_errno = LINUX_SECCOMP_NETWORK_ERRNO;
        Ok(program)
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    fn build_network_filter(
        evidence: &mut LinuxContainmentEvidence,
    ) -> Result<BpfProgram, LinuxDevDomainError> {
        evidence.seccomp_target_arch = std::env::consts::ARCH.to_owned();
        Err(LinuxDevDomainError::new(
            "compile-seccomp-filter",
            "no seccomp syscall table is compiled for this architecture; syscall numbering is \
             per-architecture and guessing it would install a filter that denies the wrong \
             calls, so no filter is installed and no network control is claimed",
        ))
    }

    /// Compiles the namespace-denial filter for this architecture.
    ///
    /// A **second** filter rather than more rules in the first one, because a
    /// `seccompiler` filter carries exactly one matched action and these two
    /// layers need different ones: the network surface is killed, while a
    /// namespace route answers [`LINUX_SECCOMP_NAMESPACE_ERRNO`] so that
    /// `clone3`'s legitimate callers can fall back. The kernel evaluates every
    /// installed filter and keeps the highest-precedence action, so stacking
    /// cannot weaken the network layer.
    ///
    /// The committed list and the BPF both come from
    /// `linux_command_plan`: the table helper names the set, and
    /// [`crate::linux_command_plan::assemble_namespace_program`] is the only
    /// assembler. Completeness is the table's: `unshare`, `setns`, `clone3`,
    /// and `clone` with every `CLONE_NEW*` bit.
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    fn build_namespace_filter(
        evidence: &mut LinuxContainmentEvidence,
    ) -> Result<BpfProgram, LinuxDevDomainError> {
        let architecture = match LINUX_SECCOMP_TARGET_ARCH {
            seccompiler::TargetArch::aarch64 => {
                crate::linux_command_plan::LinuxAuditArchitectureV1::Aarch64
            }
            seccompiler::TargetArch::x86_64 => {
                crate::linux_command_plan::LinuxAuditArchitectureV1::X86_64
            }
            seccompiler::TargetArch::riscv64 => {
                return Err(LinuxDevDomainError::new(
                    "compile-namespace-filter",
                    "no namespace syscall table is compiled for riscv64",
                ));
            }
        };
        let denials = crate::linux_command_plan::committed_namespace_denials(architecture);
        let program = crate::linux_command_plan::assemble_namespace_program(&denials, architecture)
            .map_err(|error| LinuxDevDomainError::new("assemble-namespace-filter", error))?;

        evidence.namespace_denied_syscalls =
            denials.iter().map(|denied| denied.name.clone()).collect();
        evidence.namespace_clone_flags = crate::linux_command_plan::LINUX_CLONE_NAMESPACE_FLAGS
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        evidence.namespace_seccomp_instructions = program.len();
        evidence.namespace_seccomp_denied_errno = LINUX_SECCOMP_NAMESPACE_ERRNO;
        Ok(program)
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    fn build_namespace_filter(
        _evidence: &mut LinuxContainmentEvidence,
    ) -> Result<BpfProgram, LinuxDevDomainError> {
        Err(LinuxDevDomainError::new(
            "compile-namespace-filter",
            "no seccomp syscall table is compiled for this architecture; syscall numbering is \
             per-architecture and guessing it would deny the wrong calls, so no filter is \
             installed and no namespace control is claimed",
        ))
    }

    /// Builds the requested layers for one contained run, before any fork.
    ///
    /// # Errors
    ///
    /// Fails when a requested layer cannot be built completely: a kernel
    /// below [`REQUIRED_LANDLOCK_ABI`], a scope that cannot be opened, an
    /// architecture with no compiled syscall table, or a filter that does not
    /// assemble. Every failure leaves both layers uninstalled; there is no
    /// half-confined child.
    pub(crate) fn build_child_containment(
        policy: &LinuxContainmentPolicy,
    ) -> Result<(ChildContainment, LinuxContainmentEvidence), LinuxDevDomainError> {
        let mut evidence = LinuxContainmentEvidence {
            landlock_required_abi: abi_level(REQUIRED_LANDLOCK_ABI),
            ..LinuxContainmentEvidence::default()
        };
        let ruleset = if policy.filesystem_layer {
            let started = Instant::now();
            let created = build_landlock_ruleset(policy, &mut evidence)?;
            evidence.landlock_build_micros = started.elapsed().as_micros();
            evidence.landlock_installed = true;
            Some(created)
        } else {
            None
        };
        let filter = if policy.network_layer {
            let started = Instant::now();
            let program = build_network_filter(&mut evidence)?;
            evidence.seccomp_build_micros = started.elapsed().as_micros();
            evidence.seccomp_installed = true;
            program
        } else {
            BpfProgram::new()
        };
        let namespace_filter = if policy.namespace_layer {
            let started = Instant::now();
            let program = build_namespace_filter(&mut evidence)?;
            evidence.namespace_seccomp_build_micros = started.elapsed().as_micros();
            evidence.namespace_seccomp_installed = true;
            program
        } else {
            BpfProgram::new()
        };
        Ok((
            ChildContainment::new(ruleset, filter, namespace_filter),
            evidence,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canary_report_round_trips_through_its_canonical_encoding() {
        let mut report = LinuxCanaryReportV1::new("report", LinuxCanaryRoleV1::Leader);
        report.pid = 7;
        report.process_group = 7;
        report.session = 7;
        report.attached = true;
        report.open_descriptors = vec![0, 1, 2];
        report.validate().expect("a complete report validates");
        let encoded = serde_json::to_vec(&report).expect("canary reports encode");
        assert!(encoded.len() <= MAX_LINUX_CANARY_REPORT_BYTES);
        let decoded: LinuxCanaryReportV1 =
            serde_json::from_slice(&encoded).expect("canary reports decode");
        assert_eq!(decoded, report);
    }

    #[test]
    fn a_canary_report_without_kernel_identifiers_is_refused() {
        let report = LinuxCanaryReportV1::new("report", LinuxCanaryRoleV1::Descendant);
        assert!(report.validate().is_err());
    }

    /// Live arms for the namespace-denial layer.
    ///
    /// A real process exercises the installed filter. The ordinary-process
    /// control catches BPF offsets that accidentally deny unrelated syscalls.
    #[cfg(target_os = "linux")]
    mod namespace_layer {
        use std::path::Path;
        use std::process::{Command, Stdio};

        use super::super::native::build_child_containment;
        use super::super::{LinuxContainmentPolicy, LinuxDevDomainError};
        use crate::linux_held_launcher::spawn_with_child_containment;

        const UNSHARE: &str = "/usr/bin/unshare";
        const SHELL: &str = "/bin/sh";
        /// `strerror(ENOSYS)`. Ours.
        const ENOSYS_TEXT: &str = "Function not implemented";
        /// `strerror(EPERM)`. What a container's own profile answers, which is
        /// protection this layer does not own and may not claim.
        const EPERM_TEXT: &str = "Operation not permitted";

        /// Only the syscall layer under test; no path rules to confuse a
        /// verdict, and the network layer off so each arm varies one input.
        fn policy() -> LinuxContainmentPolicy {
            LinuxContainmentPolicy {
                read_roots: Vec::new(),
                write_roots: Vec::new(),
                filesystem_layer: false,
                network_layer: false,
                namespace_layer: true,
            }
        }

        fn run(
            policy: &LinuxContainmentPolicy,
            program: &str,
            args: &[&str],
        ) -> Result<(Option<i32>, String), LinuxDevDomainError> {
            let (containment, _evidence) = build_child_containment(policy)?;
            let mut command = Command::new(program);
            command
                .args(args)
                // The arms read `strerror` text, so the locale is pinned rather
                // than inherited.
                .env("LC_ALL", "C")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = spawn_with_child_containment(&mut command, containment)
                .expect("the contained child spawns");
            let output = child
                .wait_with_output()
                .expect("the contained child is reaped");
            Ok((
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ))
        }

        #[test]
        fn the_namespace_layer_answers_enosys_where_the_control_arm_does_not() {
            assert!(
                Path::new(UNSHARE).exists(),
                "{UNSHARE} is the probe this arm drives; a host without it cannot run the arm, \
                 and skipping would report coverage that never executed"
            );

            let (_code, enforced) =
                run(&policy(), UNSHARE, &["--user", "/bin/true"]).expect("the filter builds");
            assert!(
                enforced.contains(ENOSYS_TEXT),
                "the enforced arm must be refused by *this* layer, which is the only one that \
                 answers ENOSYS; stderr was: {enforced}"
            );

            // The control differs in exactly one input. It may still fail --
            // an unprivileged container refuses `unshare` on its own -- but it
            // must not fail the way this layer refuses, or the enforced arm
            // proves nothing but the container's own profile.
            let (_code, control) = run(
                &policy().without_namespace_layer(),
                UNSHARE,
                &["--user", "/bin/true"],
            )
            .expect("the filter builds");
            assert!(
                !control.contains(ENOSYS_TEXT),
                "the control arm answered ENOSYS with the layer removed, so the enforced arm's \
                 refusal is not attributable to it; stderr was: {control}"
            );
            assert!(
                control.is_empty() || control.contains(EPERM_TEXT),
                "the control arm failed for an unexpected reason, so the pair is not a \
                 one-variable comparison; stderr was: {control}"
            );
        }

        #[test]
        fn ordinary_process_creation_still_works_under_the_namespace_layer() {
            // `fork(2)` *is* `clone(2)`. This arm is what makes the conditional
            // denial honest rather than a blanket one, and it is the arm a bad
            // jump offset or an over-broad mask fails first.
            let (code, stderr) =
                run(&policy(), SHELL, &["-c", "/bin/true"]).expect("the filter builds");
            assert_eq!(
                code,
                Some(0),
                "a shell must still fork and exec under the namespace layer; stderr was: {stderr}"
            );
        }

        #[test]
        fn the_namespace_layer_names_exactly_the_routes_it_denies() {
            let (_containment, evidence) =
                build_child_containment(&policy()).expect("the filter builds");
            assert!(evidence.namespace_seccomp_installed);
            assert_eq!(
                evidence.namespace_denied_syscalls,
                vec!["clone", "clone3", "setns", "unshare"],
                "the denied set is the complete namespace surface, sorted"
            );
            assert_eq!(
                evidence.namespace_clone_flags.len(),
                8,
                "one rule per CLONE_NEW* bit; a missing bit is a reachable namespace"
            );
            assert_eq!(evidence.namespace_seccomp_denied_errno, 38);
            assert!(evidence.namespace_seccomp_instructions > 0);
        }

        #[test]
        fn the_layer_is_absent_when_it_is_not_requested() {
            let (_containment, evidence) =
                build_child_containment(&policy().without_namespace_layer())
                    .expect("the empty layer builds");
            assert!(!evidence.namespace_seccomp_installed);
            assert!(evidence.namespace_denied_syscalls.is_empty());
            assert_eq!(evidence.namespace_seccomp_instructions, 0);
        }
    }
}
