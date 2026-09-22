//! Fail-closed bootstrap boundary for the dedicated runner process.
//!
//! The production launcher is expected to create three anonymous pipes, map
//! them to standard input, output, and error, and `exec` this binary before the
//! desktop opens project state or credentials. [`seal_stdio_runner_process`]
//! enumerates the live descriptor table twice and refuses startup unless the
//! exact set is `{0, 1, 2}`. It also verifies that the three descriptors are
//! FIFOs with the access modes required by the stdio protocol.
//!
//! This is a startup invariant, not a sandbox. The caller must invoke it before
//! creating threads or installing signal handlers that can open descriptors.
//! It neither closes descriptors nor prevents later code from opening new
//! ones. Later retained descriptors can be admitted through
//! [`RunnerProcessSeal::admit_owned_descriptor`], which requires kernel
//! `FD_CLOEXEC` evidence without constructing a raw borrowed descriptor.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::{Errno, FdFlags, fcntl_getfd};

const STANDARD_DESCRIPTOR_NUMBERS: [i32; 3] = [0, 1, 2];

/// Validated output from an active launcher canary which enumerated the target
/// process immediately before direct `exec`.
///
/// This value validates the report's shape only. The contained-command backend
/// must authenticate where the report came from and bind it to the exact launch
/// digest. Keeping those two responsibilities separate makes it impossible for
/// a static scan of the runner's descriptor table to masquerade as child-side
/// closure evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosedExecDescriptorSet {
    descriptors: [i32; 3],
}

impl ClosedExecDescriptorSet {
    /// Returns the exact descriptors observed by the active canary.
    #[must_use]
    pub(crate) const fn descriptors(&self) -> &[i32; 3] {
        &self.descriptors
    }
}

/// Validates an authenticated child-side descriptor report.
///
/// The v1 contained-command ABI admits only standard input, output, and error
/// at the final target `exec` boundary. Launcher-private root, cwd, executable,
/// policy, or control descriptors must be consumed or closed before this report
/// is emitted. Duplicate, negative, missing, and additional descriptors all
/// fail closed.
pub(crate) fn validate_closed_exec_descriptor_report(
    reported: &[i32],
) -> Result<ClosedExecDescriptorSet, ExecDescriptorReportError> {
    let mut observed = BTreeSet::new();
    for descriptor in reported {
        if *descriptor < 0 || !observed.insert(*descriptor) {
            return Err(ExecDescriptorReportError::Malformed {
                reported: reported.to_vec(),
            });
        }
    }
    let expected = BTreeSet::from(STANDARD_DESCRIPTOR_NUMBERS);
    if observed != expected {
        return Err(ExecDescriptorReportError::UnexpectedSet {
            expected: STANDARD_DESCRIPTOR_NUMBERS.to_vec(),
            observed: observed.into_iter().collect(),
        });
    }
    Ok(ClosedExecDescriptorSet {
        descriptors: STANDARD_DESCRIPTOR_NUMBERS,
    })
}

/// Invalid output from a child-side descriptor-closure canary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExecDescriptorReportError {
    /// The report contained a negative or duplicate descriptor.
    Malformed {
        /// Exact rejected report.
        reported: Vec<i32>,
    },
    /// The report was well formed but differed from `{0, 1, 2}`.
    UnexpectedSet {
        /// Required target descriptor set.
        expected: Vec<i32>,
        /// Reported target descriptor set.
        observed: Vec<i32>,
    },
}

impl fmt::Display for ExecDescriptorReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { reported } => write!(
                formatter,
                "active exec descriptor report is malformed: {reported:?}"
            ),
            Self::UnexpectedSet { expected, observed } => write!(
                formatter,
                "active exec descriptor report differs from the closed target ABI: expected {expected:?}, observed {observed:?}"
            ),
        }
    }
}

impl std::error::Error for ExecDescriptorReportError {}

/// Access mode observed for an inherited standard descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorAccess {
    /// Read-only access.
    ReadOnly,
    /// Write-only access.
    WriteOnly,
    /// Read/write access.
    ReadWrite,
}

impl fmt::Display for DescriptorAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => formatter.write_str("read-only"),
            Self::WriteOnly => formatter.write_str("write-only"),
            Self::ReadWrite => formatter.write_str("read/write"),
        }
    }
}

/// Kernel object kind observed behind a descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorKind {
    /// A regular file.
    RegularFile,
    /// A directory.
    Directory,
    /// A symbolic link.
    SymbolicLink,
    /// A block device.
    BlockDevice,
    /// A character device.
    CharacterDevice,
    /// A FIFO or anonymous pipe.
    Fifo,
    /// A socket.
    Socket,
    /// A platform object not represented by another variant.
    Other,
}

impl fmt::Display for DescriptorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegularFile => formatter.write_str("regular file"),
            Self::Directory => formatter.write_str("directory"),
            Self::SymbolicLink => formatter.write_str("symbolic link"),
            Self::BlockDevice => formatter.write_str("block device"),
            Self::CharacterDevice => formatter.write_str("character device"),
            Self::Fifo => formatter.write_str("FIFO"),
            Self::Socket => formatter.write_str("socket"),
            Self::Other => formatter.write_str("other"),
        }
    }
}

/// One standard descriptor observation captured by the startup seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorObservation {
    number: i32,
    access: DescriptorAccess,
    kind: DescriptorKind,
    close_on_exec: bool,
}

impl DescriptorObservation {
    /// Returns the descriptor number.
    #[must_use]
    pub const fn number(&self) -> i32 {
        self.number
    }

    /// Returns the kernel access mode.
    #[must_use]
    pub const fn access(&self) -> DescriptorAccess {
        self.access
    }

    /// Returns the observed kernel object kind.
    #[must_use]
    pub const fn kind(&self) -> DescriptorKind {
        self.kind
    }

    /// Returns whether `FD_CLOEXEC` was set at observation time.
    #[must_use]
    pub const fn close_on_exec(&self) -> bool {
        self.close_on_exec
    }
}

/// Non-cloneable evidence that the runner began with only its stdio pipes.
#[derive(Debug)]
pub struct RunnerProcessSeal {
    observations: [DescriptorObservation; 3],
}

impl RunnerProcessSeal {
    /// Returns the exact standard-descriptor observations.
    #[must_use]
    pub const fn observations(&self) -> &[DescriptorObservation; 3] {
        &self.observations
    }

    /// Admits a later runner-owned descriptor only when it is close-on-exec.
    ///
    /// The returned wrapper owns the value and preserves the point-in-time
    /// kernel evidence. The wrapper does not make kernel flags immutable;
    /// callers must revalidate immediately before every child `exec` boundary.
    ///
    /// # Errors
    ///
    /// Returns [`OwnedDescriptorError`] if kernel flags cannot be inspected or
    /// `FD_CLOEXEC` is not set at admission time.
    pub fn admit_owned_descriptor<T: AsFd>(
        &self,
        descriptor: T,
    ) -> Result<RunnerOwnedDescriptor<T>, OwnedDescriptorError> {
        RunnerOwnedDescriptor::admit(descriptor)
    }
}

/// A runner-owned descriptor admitted with `FD_CLOEXEC` set.
#[derive(Debug)]
pub struct RunnerOwnedDescriptor<T> {
    descriptor: T,
    number_at_admission: i32,
}

impl<T: AsFd> RunnerOwnedDescriptor<T> {
    fn admit(descriptor: T) -> Result<Self, OwnedDescriptorError> {
        let borrowed = descriptor.as_fd();
        let number = borrowed.as_raw_fd();
        require_close_on_exec(borrowed)?;
        Ok(Self {
            descriptor,
            number_at_admission: number,
        })
    }

    /// Returns the descriptor number observed during admission.
    #[must_use]
    pub const fn number_at_admission(&self) -> i32 {
        self.number_at_admission
    }

    /// Borrows the admitted value.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.descriptor
    }

    /// Revalidates `FD_CLOEXEC` on the currently owned descriptor.
    ///
    /// Production spawning code must call this while holding the process-wide
    /// open/spawn serialization gate immediately before every `exec` boundary.
    ///
    /// # Errors
    ///
    /// Returns [`OwnedDescriptorError`] if kernel flags cannot be read or the
    /// close-on-exec flag has been cleared since admission.
    pub fn revalidate_close_on_exec(&self) -> Result<(), OwnedDescriptorError> {
        require_close_on_exec(self.descriptor.as_fd())
    }

    /// Consumes the evidence wrapper and returns its value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.descriptor
    }
}

impl<T: AsFd> AsFd for RunnerOwnedDescriptor<T> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

fn require_close_on_exec(
    descriptor: std::os::fd::BorrowedFd<'_>,
) -> Result<(), OwnedDescriptorError> {
    let number = descriptor.as_raw_fd();
    let flags = fcntl_getfd(descriptor).map_err(|source| OwnedDescriptorError::Inspect {
        descriptor: number,
        source: source.into(),
    })?;
    if flags.contains(FdFlags::CLOEXEC) {
        Ok(())
    } else {
        Err(OwnedDescriptorError::Inheritable { descriptor: number })
    }
}

/// Failure to establish the runner's startup descriptor invariant.
#[derive(Debug)]
pub enum ProcessBoundaryError {
    /// This implementation only supports the product's macOS and Linux targets.
    UnsupportedPlatform,
    /// The operating-system descriptor table could not be enumerated.
    Enumerate {
        /// Enumeration root used on this platform.
        root: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The descriptor table contained a malformed entry.
    MalformedDescriptorEntry {
        /// Enumeration root used on this platform.
        root: PathBuf,
        /// Entry name, represented lossily for bounded diagnostics.
        entry: String,
    },
    /// Live descriptors did not exactly equal the stdio allowlist.
    UnexpectedDescriptorSet {
        /// Required descriptor numbers.
        expected: Vec<i32>,
        /// Observed live descriptor numbers.
        observed: Vec<i32>,
    },
    /// The descriptor set changed during the two-pass audit.
    DescriptorTableChanged {
        /// First observed descriptor set.
        first: Vec<i32>,
        /// Second observed descriptor set.
        second: Vec<i32>,
    },
    /// An allowed descriptor could not be inspected.
    InspectDescriptor {
        /// Descriptor number being inspected.
        descriptor: i32,
        /// Inspection operation.
        operation: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A standard descriptor had the wrong access mode.
    AccessMismatch {
        /// Descriptor number being inspected.
        descriptor: i32,
        /// Required access mode.
        expected: DescriptorAccess,
        /// Observed access mode.
        observed: DescriptorAccess,
    },
    /// A standard descriptor was not an anonymous pipe/FIFO.
    KindMismatch {
        /// Descriptor number being inspected.
        descriptor: i32,
        /// Required kernel object kind.
        expected: DescriptorKind,
        /// Observed kernel object kind.
        observed: DescriptorKind,
    },
}

impl fmt::Display for ProcessBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter
                .write_str("runner startup descriptor audit is unsupported on this platform"),
            Self::Enumerate { root, source } => write!(
                formatter,
                "enumerate runner descriptor table {}: {source}",
                root.display()
            ),
            Self::MalformedDescriptorEntry { root, entry } => write!(
                formatter,
                "descriptor table {} contained malformed entry {entry:?}",
                root.display()
            ),
            Self::UnexpectedDescriptorSet { expected, observed } => write!(
                formatter,
                "unexpected inherited descriptor set: expected {expected:?}, observed {observed:?}"
            ),
            Self::DescriptorTableChanged { first, second } => write!(
                formatter,
                "runner descriptor table changed during startup audit: first {first:?}, second {second:?}"
            ),
            Self::InspectDescriptor {
                descriptor,
                operation,
                source,
            } => write!(
                formatter,
                "{operation} for inherited descriptor {descriptor}: {source}"
            ),
            Self::AccessMismatch {
                descriptor,
                expected,
                observed,
            } => write!(
                formatter,
                "inherited descriptor {descriptor} has {observed} access; expected {expected}"
            ),
            Self::KindMismatch {
                descriptor,
                expected,
                observed,
            } => write!(
                formatter,
                "inherited descriptor {descriptor} is a {observed}; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for ProcessBoundaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Enumerate { source, .. } | Self::InspectDescriptor { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Failure to admit a runner-owned descriptor as close-on-exec.
#[derive(Debug)]
pub enum OwnedDescriptorError {
    /// Kernel descriptor flags could not be read.
    Inspect {
        /// Descriptor number being inspected.
        descriptor: i32,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// `FD_CLOEXEC` was not set.
    Inheritable {
        /// Descriptor number that could cross an `exec` boundary.
        descriptor: i32,
    },
}

impl fmt::Display for OwnedDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect { descriptor, source } => {
                write!(
                    formatter,
                    "inspect runner-owned descriptor {descriptor}: {source}"
                )
            }
            Self::Inheritable { descriptor } => write!(
                formatter,
                "runner-owned descriptor {descriptor} is inheritable because FD_CLOEXEC is unset"
            ),
        }
    }
}

impl std::error::Error for OwnedDescriptorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect { source, .. } => Some(source),
            Self::Inheritable { .. } => None,
        }
    }
}

/// Audits and seals a dedicated stdio-pipe runner process.
///
/// This function must be the first substantive action in `main`, before any
/// threads, credential access, project access, or long-lived descriptor opens.
/// The exact allowlist is standard input, output, and error. Standard input must
/// be a read-only FIFO; standard output and error must be write-only FIFOs.
///
/// # Errors
///
/// Returns [`ProcessBoundaryError`] if the platform cannot enumerate its live
/// descriptors or any live descriptor, access-mode, object-kind, or stability
/// check differs from the exact stdio-pipe policy.
pub fn seal_stdio_runner_process() -> Result<RunnerProcessSeal, ProcessBoundaryError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ProcessBoundaryError::UnsupportedPlatform)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        seal_descriptor_root(descriptor_table_root())
    }
}

fn seal_descriptor_root(root: &Path) -> Result<RunnerProcessSeal, ProcessBoundaryError> {
    let expected = BTreeSet::from(STANDARD_DESCRIPTOR_NUMBERS);
    let first = enumerate_live_descriptors(root)?;
    require_exact_set(&expected, &first)?;

    let observations = [
        inspect_standard_descriptor(root, 0, DescriptorAccess::ReadOnly)?,
        inspect_standard_descriptor(root, 1, DescriptorAccess::WriteOnly)?,
        inspect_standard_descriptor(root, 2, DescriptorAccess::WriteOnly)?,
    ];

    let second = enumerate_live_descriptors(root)?;
    if second != first {
        return Err(ProcessBoundaryError::DescriptorTableChanged {
            first: first.into_iter().collect(),
            second: second.into_iter().collect(),
        });
    }
    require_exact_set(&expected, &second)?;

    Ok(RunnerProcessSeal { observations })
}

fn require_exact_set(
    expected: &BTreeSet<i32>,
    observed: &BTreeSet<i32>,
) -> Result<(), ProcessBoundaryError> {
    if expected == observed {
        return Ok(());
    }
    Err(ProcessBoundaryError::UnexpectedDescriptorSet {
        expected: expected.iter().copied().collect(),
        observed: observed.iter().copied().collect(),
    })
}

#[cfg(target_os = "linux")]
fn descriptor_table_root() -> &'static Path {
    Path::new("/proc/self/fd")
}

#[cfg(target_os = "macos")]
fn descriptor_table_root() -> &'static Path {
    Path::new("/dev/fd")
}

fn enumerate_live_descriptors(root: &Path) -> Result<BTreeSet<i32>, ProcessBoundaryError> {
    let entries = fs::read_dir(root).map_err(|source| ProcessBoundaryError::Enumerate {
        root: root.to_path_buf(),
        source,
    })?;
    let mut candidates = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|source| ProcessBoundaryError::Enumerate {
            root: root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(ProcessBoundaryError::MalformedDescriptorEntry {
                root: root.to_path_buf(),
                entry: name.to_string_lossy().into_owned(),
            });
        };
        let descriptor =
            name.parse::<i32>()
                .map_err(|_| ProcessBoundaryError::MalformedDescriptorEntry {
                    root: root.to_path_buf(),
                    entry: name.to_owned(),
                })?;
        if descriptor < 0 {
            return Err(ProcessBoundaryError::MalformedDescriptorEntry {
                root: root.to_path_buf(),
                entry: name.to_owned(),
            });
        }
        candidates.insert(descriptor);
    }

    // `read_dir` itself temporarily owns one descriptor visible in these
    // pseudo-filesystems. The iterator has been consumed and dropped here; a
    // metadata probe removes only that now-closed scanner descriptor.
    let mut live = BTreeSet::new();
    for descriptor in candidates {
        match fs::metadata(root.join(descriptor.to_string())) {
            Ok(_) => {
                live.insert(descriptor);
            }
            Err(source) if descriptor_vanished(&source) => {}
            Err(source) => {
                return Err(ProcessBoundaryError::InspectDescriptor {
                    descriptor,
                    operation: "confirm descriptor remained live after enumeration",
                    source,
                });
            }
        }
    }
    Ok(live)
}

fn descriptor_vanished(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        || error.raw_os_error() == Some(Errno::BADF.raw_os_error())
}

fn inspect_standard_descriptor(
    root: &Path,
    descriptor: i32,
    expected_access: DescriptorAccess,
) -> Result<DescriptorObservation, ProcessBoundaryError> {
    let (flags, descriptor_flags) = match descriptor {
        0 => inspect_flags(std::io::stdin(), descriptor)?,
        1 => inspect_flags(std::io::stdout(), descriptor)?,
        2 => inspect_flags(std::io::stderr(), descriptor)?,
        _ => unreachable!("the startup policy contains only standard descriptors"),
    };
    let access =
        access_from_flags(flags).ok_or_else(|| ProcessBoundaryError::InspectDescriptor {
            descriptor,
            operation: "interpret descriptor access mode",
            source: io::Error::new(io::ErrorKind::InvalidData, "unknown O_ACCMODE value"),
        })?;
    if access != expected_access {
        return Err(ProcessBoundaryError::AccessMismatch {
            descriptor,
            expected: expected_access,
            observed: access,
        });
    }

    let metadata = fs::metadata(root.join(descriptor.to_string())).map_err(|source| {
        ProcessBoundaryError::InspectDescriptor {
            descriptor,
            operation: "inspect descriptor object kind",
            source,
        }
    })?;
    let kind = descriptor_kind(metadata.file_type());
    if kind != DescriptorKind::Fifo {
        return Err(ProcessBoundaryError::KindMismatch {
            descriptor,
            expected: DescriptorKind::Fifo,
            observed: kind,
        });
    }

    Ok(DescriptorObservation {
        number: descriptor,
        access,
        kind,
        close_on_exec: descriptor_flags.contains(FdFlags::CLOEXEC),
    })
}

fn inspect_flags<Fd: AsFd>(
    descriptor: Fd,
    number: i32,
) -> Result<(OFlags, FdFlags), ProcessBoundaryError> {
    let borrowed = descriptor.as_fd();
    let status =
        fcntl_getfl(borrowed).map_err(|source| ProcessBoundaryError::InspectDescriptor {
            descriptor: number,
            operation: "read descriptor access flags",
            source: source.into(),
        })?;
    let flags =
        fcntl_getfd(borrowed).map_err(|source| ProcessBoundaryError::InspectDescriptor {
            descriptor: number,
            operation: "read descriptor flags",
            source: source.into(),
        })?;
    Ok((status, flags))
}

fn access_from_flags(flags: OFlags) -> Option<DescriptorAccess> {
    let access = flags & OFlags::RWMODE;
    if access == OFlags::RDONLY {
        Some(DescriptorAccess::ReadOnly)
    } else if access == OFlags::WRONLY {
        Some(DescriptorAccess::WriteOnly)
    } else if access == OFlags::RDWR {
        Some(DescriptorAccess::ReadWrite)
    } else {
        None
    }
}

#[cfg(unix)]
fn descriptor_kind(file_type: fs::FileType) -> DescriptorKind {
    if file_type.is_file() {
        DescriptorKind::RegularFile
    } else if file_type.is_dir() {
        DescriptorKind::Directory
    } else if file_type.is_symlink() {
        DescriptorKind::SymbolicLink
    } else if file_type.is_block_device() {
        DescriptorKind::BlockDevice
    } else if file_type.is_char_device() {
        DescriptorKind::CharacterDevice
    } else if file_type.is_fifo() {
        DescriptorKind::Fifo
    } else if file_type.is_socket() {
        DescriptorKind::Socket
    } else {
        DescriptorKind::Other
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustix::io::{FdFlags, fcntl_setfd};

    use super::*;

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn runner_owned_descriptor_admission_requires_cloexec() {
        let path = std::env::temp_dir().join(format!(
            "grok-build-runner-owned-descriptor-{}-{}",
            std::process::id(),
            NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create descriptor fixture");
        let admitted = RunnerOwnedDescriptor::admit(file).expect("std file must be CLOEXEC");
        assert!(admitted.number_at_admission() >= 0);
        admitted
            .revalidate_close_on_exec()
            .expect("admitted descriptor remains CLOEXEC");

        fcntl_setfd(admitted.get_ref(), FdFlags::empty())
            .expect("clear CLOEXEC for negative control");
        let revalidation = admitted
            .revalidate_close_on_exec()
            .expect_err("revalidation must detect cleared CLOEXEC");
        assert!(matches!(
            revalidation,
            OwnedDescriptorError::Inheritable { .. }
        ));

        let file = admitted.into_inner();
        let error = RunnerOwnedDescriptor::admit(file)
            .expect_err("inheritable descriptor must be rejected");
        assert!(matches!(error, OwnedDescriptorError::Inheritable { .. }));
        fs::remove_file(path).expect("remove descriptor fixture");
    }

    #[test]
    fn access_flag_mapping_is_exact() {
        assert_eq!(
            access_from_flags(OFlags::RDONLY),
            Some(DescriptorAccess::ReadOnly)
        );
        assert_eq!(
            access_from_flags(OFlags::WRONLY),
            Some(DescriptorAccess::WriteOnly)
        );
        assert_eq!(
            access_from_flags(OFlags::RDWR),
            Some(DescriptorAccess::ReadWrite)
        );
    }

    #[test]
    fn active_exec_descriptor_report_requires_exact_closed_abi() {
        let proof = validate_closed_exec_descriptor_report(&[2, 0, 1])
            .expect("order-independent exact report");
        assert_eq!(proof.descriptors(), &[0, 1, 2]);

        assert!(matches!(
            validate_closed_exec_descriptor_report(&[0, 1, 2, 7]),
            Err(ExecDescriptorReportError::UnexpectedSet { .. })
        ));
        assert!(matches!(
            validate_closed_exec_descriptor_report(&[0, 1, 1, 2]),
            Err(ExecDescriptorReportError::Malformed { .. })
        ));
        assert!(matches!(
            validate_closed_exec_descriptor_report(&[-1, 0, 1, 2]),
            Err(ExecDescriptorReportError::Malformed { .. })
        ));
    }
}
