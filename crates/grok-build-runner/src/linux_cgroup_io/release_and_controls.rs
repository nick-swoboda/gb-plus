// ---------------------------------------------------------------------------
// The controller side: read a stopped child's real descriptor table.
// ---------------------------------------------------------------------------

/// One descriptor as a stopped child's own procfs entry describes it.
///
/// Every field is a kernel answer about the **child's** table. Nothing here is
/// copied from the parent's descriptors, which is the specific defect the
/// test-only child-launch constructor has: it synthesises child observations
/// out of the parent's own retained identities.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxObservedChildDescriptorV1 {
    target_fd: u32,
    identity: ObjectIdentity,
    access: LinuxServiceSetupDescriptorAccessV1,
    close_on_exec: bool,
    kind: LinuxServiceChildDescriptorKindV1,
    mount_id: u64,
}

/// A stopped child's complete descriptor table.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxObservedChildDescriptorTableV1 {
    /// Every descriptor number the child had open, in order. This is the
    /// closure statement: a table with an extra entry is not the planned table.
    open_fds: Vec<u32>,
    descriptors: Vec<LinuxObservedChildDescriptorV1>,
}

/// Opens `/proc` and requires it to be procfs.
///
/// Everything this module reads about a child is read relative to this
/// descriptor, so a `/proc` that was replaced between the open and the read is
/// a refusal rather than a source of observations.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when `/proc` cannot be opened or is not procfs.
#[cfg(target_os = "linux")]
fn open_authenticated_procfs_root() -> Result<Dir, CgroupIoFailure> {
    const OPERATION: &str = "authenticate-procfs-for-child-descriptor-probe";

    let root = Dir::open_ambient_dir("/proc", cap_std::ambient_authority())
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    if filesystem_magic(&root)? != PROC_SUPER_MAGIC {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "/proc is not a procfs filesystem",
        ));
    }
    Ok(root)
}

/// Waits until one process is in the kernel's stopped state.
///
/// A child that has not stopped has not finished placing its table, so reading
/// it early would report a table that is still being built. The wait is bounded
/// and an expiry is a refusal.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the state cannot be read, when the process
/// left a state this probe admits, and when the bound expires.
#[cfg(target_os = "linux")]
fn await_stopped_process(
    procfs: &Dir,
    pid: u32,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let raw = read_procfs_entry(procfs, &format!("{pid}/stat"), operation)?;
        // The process name is parenthesised and may itself contain spaces, so
        // the state is the field after the **last** `)`, not the third token.
        let state = raw
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .ok_or_else(|| {
                failure(
                    operation,
                    EffectCertainty::NotApplied,
                    "the probe process's procfs stat line has no state field",
                )
            })?
            .to_owned();
        match state.as_str() {
            "T" => return Ok(()),
            "R" | "S" | "D" => {}
            other => {
                return Err(failure(
                    operation,
                    EffectCertainty::NotApplied,
                    format!("the probe process reached state {other} without stopping"),
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the probe process did not stop within its bound",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Reads one procfs file completely, relative to the authenticated root.
#[cfg(target_os = "linux")]
fn read_procfs_entry(
    procfs: &Dir,
    relative: &str,
    operation: &'static str,
) -> Result<String, CgroupIoFailure> {
    use std::io::Read as _;

    let descriptor = rustix::fs::openat(
        procfs,
        relative,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let mut text = String::new();
    std::fs::File::from(descriptor)
        .take(64 * 1024)
        .read_to_string(&mut text)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    Ok(text)
}

/// Reads a stopped child's complete descriptor table out of procfs.
///
/// Four reads per descriptor, all of the **child's** entry: `getdents64` on
/// `<pid>/fd` for the closure, `fstatat` through the magic link for the
/// identity, `readlinkat` on the same link for the object class, and
/// `<pid>/fdinfo/<n>` for the access mode, the close-on-exec bit and the unique
/// mount identity. `fs/proc/fd.c` derives the close-on-exec bit from the
/// descriptor table itself, so it is the child's real flag.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the process is not stopped, when any read
/// fails — an error is never read as an absence — when a descriptor names an
/// object class this table has no kind for, and when `fdinfo` cannot be parsed.
#[cfg(target_os = "linux")]
fn observe_stopped_child_descriptor_table(
    pid: u32,
    targets: &[u32],
) -> Result<LinuxObservedChildDescriptorTableV1, CgroupIoFailure> {
    const OPERATION: &str = "observe-linux-service-child-descriptor-table";

    let procfs = open_authenticated_procfs_root()?;
    await_stopped_process(&procfs, pid, OPERATION)?;

    let directory = rustix::fs::openat(
        &procfs,
        format!("{pid}/fd"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let mut open_fds = Vec::new();
    let mut entries = rustix::fs::Dir::read_from(&directory)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    while let Some(entry) = entries.read() {
        let entry =
            entry.map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        // The descriptor this enumeration is running on belongs to *this*
        // process, not the child, so it never appears here.
        open_fds.push(name.parse::<u32>().map_err(|_| {
            failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!("the child's descriptor directory holds a non-numeric entry {name}"),
            )
        })?);
    }
    open_fds.sort_unstable();

    let mut descriptors = Vec::with_capacity(targets.len());
    for target in targets {
        descriptors.push(observe_one_stopped_child_descriptor(
            &procfs, pid, *target, OPERATION,
        )?);
    }
    Ok(LinuxObservedChildDescriptorTableV1 {
        open_fds,
        descriptors,
    })
}

#[cfg(target_os = "linux")]
fn observe_one_stopped_child_descriptor(
    procfs: &Dir,
    pid: u32,
    target: u32,
    operation: &'static str,
) -> Result<LinuxObservedChildDescriptorV1, CgroupIoFailure> {
    let magic_link = format!("{pid}/fd/{target}");
    let stat = rustix::fs::statat(procfs, &magic_link, rustix::fs::AtFlags::empty())
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let link = rustix::fs::readlinkat(procfs, &magic_link, Vec::new())
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let link = link.to_string_lossy().into_owned();
    let file_type = stat.st_mode & SETUP_DESCRIPTOR_FILE_TYPE_MASK;
    let kind = match file_type {
        SETUP_DESCRIPTOR_PIPE_MODE => LinuxServiceChildDescriptorKindV1::Pipe,
        DIRECTORY_FILE_TYPE_MODE => LinuxServiceChildDescriptorKindV1::Directory,
        REGULAR_FILE_TYPE_MODE if link.starts_with("/memfd:") => {
            LinuxServiceChildDescriptorKindV1::SealedRequestMemfd
        }
        _ => {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                format!("child descriptor {target} names {link}, which is no child table kind"),
            ));
        }
    };

    let fdinfo = read_procfs_entry(procfs, &format!("{pid}/fdinfo/{target}"), operation)?;
    let field = |name: &str| -> Option<&str> {
        fdinfo
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let flags = field("flags:")
        .and_then(|value| u32::from_str_radix(value, 8).ok())
        .ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                format!("child descriptor {target} has no readable fdinfo flags"),
            )
        })?;
    let mount_id = field("mnt_id:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                format!("child descriptor {target} has no readable fdinfo mount identity"),
            )
        })?;
    let access = match flags & PROC_FDINFO_ACCMODE {
        0 => LinuxServiceSetupDescriptorAccessV1::ReadOnly,
        1 => LinuxServiceSetupDescriptorAccessV1::WriteOnly,
        2 => LinuxServiceSetupDescriptorAccessV1::ReadWrite,
        _ => {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                format!("child descriptor {target} reports no valid access mode"),
            ));
        }
    };
    Ok(LinuxObservedChildDescriptorV1 {
        target_fd: target,
        identity: ObjectIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        },
        access,
        close_on_exec: flags & PROC_FDINFO_CLOEXEC != 0,
        kind,
        mount_id,
    })
}

/// `S_IFDIR`.
#[cfg(target_os = "linux")]
const DIRECTORY_FILE_TYPE_MODE: u32 = 0o040_000;

/// `S_IFREG`.
#[cfg(target_os = "linux")]
const REGULAR_FILE_TYPE_MODE: u32 = 0o100_000;

/// A started descriptor-table probe: the child, and the socket its placement
/// was sent over.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxServiceChildDescriptorProbe {
    child: std::process::Child,
    controller: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl LinuxServiceChildDescriptorProbe {
    /// The child's process identifier, for the procfs observation.
    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Kills the stopped child and reaps it.
    ///
    /// `SIGKILL` reaches a stopped process without a `SIGCONT` first, which is
    /// why there is no continue step: a probe that had to be resumed to be
    /// killed could run again between the two signals.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the signal or the reap fails.
    fn kill_and_reap(mut self) -> Result<std::process::ExitStatus, CgroupIoFailure> {
        const OPERATION: &str = "reap-linux-service-child-descriptor-probe";

        drop(self.controller);
        self.child
            .kill()
            .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))?;
        self.child
            .wait()
            .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))
    }
}

/// Starts one stopped-child descriptor-table probe.
///
/// `stdio` are the three descriptors the child receives at fds 0, 1 and 2 —
/// except that fd 0 is the placement socket, because a child cannot name any
/// other descriptor without `BorrowedFd::borrow_raw`. That substitution is the
/// measurement, not an oversight: see this file's header.
///
/// `placements` names, for each remaining descriptor, the number the child must
/// place it at. The child performs the identical placement whatever the list
/// says, so a caller obtains a control run by varying only the list.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the socketpair or the spawn fails, when the
/// placement does not fit one atomic control message, and when the send is
/// partial.
#[cfg(target_os = "linux")]
fn spawn_linux_service_child_descriptor_probe(
    image: &Path,
    stdout: std::fs::File,
    stderr: std::fs::File,
    placements: &[(u32, std::os::fd::BorrowedFd<'_>)],
) -> Result<LinuxServiceChildDescriptorProbe, CgroupIoFailure> {
    spawn_child_descriptor_probe_in_mode(
        image,
        CHILD_DESCRIPTOR_PROBE_OBSERVE_MODE,
        stdout,
        stderr,
        placements,
    )
}

/// Starts one child that materialises the plan's complete descriptor table.
///
/// `stdout` and `stderr` are the descriptors the plan puts at fds 1 and 2, and
/// they reach the child through `Stdio`, which is why they arrive without
/// `FD_CLOEXEC` — the state the plan requires of them. `placements` must begin
/// with fd 0 and continue with the strictly increasing run at 3 and above.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] on every refusal
/// [`spawn_linux_service_child_descriptor_probe`] makes.
#[cfg(target_os = "linux")]
fn spawn_linux_service_child_launch_closure_probe(
    image: &Path,
    stdout: std::fs::File,
    stderr: std::fs::File,
    placements: &[(u32, std::os::fd::BorrowedFd<'_>)],
) -> Result<LinuxServiceChildDescriptorProbe, CgroupIoFailure> {
    spawn_child_descriptor_probe_in_mode(
        image,
        CHILD_DESCRIPTOR_PROBE_CLOSURE_MODE,
        stdout,
        stderr,
        placements,
    )
}

/// The one spawn both probe modes use.
#[cfg(target_os = "linux")]
fn spawn_child_descriptor_probe_in_mode(
    image: &Path,
    mode: &str,
    stdout: std::fs::File,
    stderr: std::fs::File,
    placements: &[(u32, std::os::fd::BorrowedFd<'_>)],
) -> Result<LinuxServiceChildDescriptorProbe, CgroupIoFailure> {
    use std::io::IoSlice;
    use std::mem::MaybeUninit;

    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, sendmsg, socketpair,
    };

    const OPERATION: &str = "spawn-linux-service-child-descriptor-probe";

    if placements.is_empty() || placements.len() > MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the child descriptor placement is empty or outside its compiled bound",
        ));
    }
    let (controller, child_end) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;

    let child = std::process::Command::new(image)
        .arg(LINUX_SERVICE_CHILD_DESCRIPTOR_PROBE_ARGUMENT)
        .arg(mode)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::from(std::fs::File::from(child_end)))
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;

    let targets = placements
        .iter()
        .map(|(target, _)| u8::try_from(*target).unwrap_or(u8::MAX))
        .collect::<Vec<_>>();
    let descriptors = placements
        .iter()
        .map(|(_, descriptor)| *descriptor)
        .collect::<Vec<_>>();
    let mut space = [MaybeUninit::uninit();
        rustix::cmsg_space!(ScmRights(MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS))];
    let mut control_message = SendAncillaryBuffer::new(&mut space);
    if !control_message.push(SendAncillaryMessage::ScmRights(&descriptors)) {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the child descriptor placement did not fit one atomic control message",
        ));
    }
    match sendmsg(
        &controller,
        &[IoSlice::new(&targets)],
        &mut control_message,
        SendFlags::NOSIGNAL,
    ) {
        Ok(written) if written == targets.len() => {
            Ok(LinuxServiceChildDescriptorProbe { child, controller })
        }
        Ok(_) => Err(failure(
            OPERATION,
            EffectCertainty::Ambiguous,
            "the placement channel accepted a partial atomic frame",
        )),
        Err(error) => Err(io_failure(OPERATION, EffectCertainty::Ambiguous, error)),
    }
}

// The held helper must expose only fds 0..=6, with CLOEXEC clear on 0..=2
// and set on 3..=6. Receive the latter after exec, then use the admitted
// `dup2` boundary to replace the transport on fd 0. A pre-exec closure cannot
// preserve CLOEXEC-set descriptors through exec. This closed internal mode
// arranges a descriptor table; it accepts no caller-selected executable and
// grants no command-execution permission.

/// Largest child descriptor table this mint will materialise.
///
/// Two of the plan's slots travel as `Stdio` and the rest travel in one atomic
/// `SCM_RIGHTS` message, so the transported count is what the probe's compiled
/// bound applies to. The bound is here so a plan that grew an unbounded table
/// is a refusal rather than a partial send.
#[cfg(target_os = "linux")]
const MAX_LINUX_SERVICE_CHILD_LAUNCH_TABLE_SLOTS: usize = MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS + 2;

/// One planned slot and the retained descriptor that will occupy it.
///
/// The descriptor is held at the access the **child** is required to hold it
/// with, which is not always the access the parent retained it with: the sealed
/// setup request is retained read-write and the plan gives the child a
/// read-only view of the same inode.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxNativeServiceChildLaunchSlot {
    binding: LinuxServiceChildDescriptorBindingV1,
    identity: ObjectIdentity,
    descriptor: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceChildLaunchClosureCapability {
    /// Mints the child-launch closure by materialising the plan's descriptor
    /// table in a real process and reading it back out of that process.
    ///
    /// The sequence, and every step is a kernel answer rather than a claim:
    ///
    /// 1. the setup authority is revalidated and the plan re-projects its own
    ///    child table, so the comparison target is the plan's, not this
    ///    function's;
    /// 2. one retained descriptor is resolved per slot from the **already
    ///    authenticated** setup capability — an endpoint by role, or the
    ///    retained cwd — and, where the plan gives the child a narrower access
    ///    than the parent holds, re-opened through `/proc/self/fd` at that
    ///    access and required to be the same `(device, inode)`;
    /// 3. fds 1 and 2 travel as `Stdio` and the rest in one atomic `SCM_RIGHTS`
    ///    message to a child that places each at the exact number the plan
    ///    names, installs fd 0 with `dup2`, and stops itself;
    /// 4. the parent waits for state `T` and reads the child's own
    ///    `/proc/<pid>/fd` and `/proc/<pid>/fdinfo`; and
    /// 5. the whole table — closure, identities, kinds, access modes and
    ///    close-on-exec bits — is submitted to the **untouched** `validate_for`.
    ///
    /// The child is killed and reaped before the capability is returned, so the
    /// value holds a proof about a process that no longer exists rather than a
    /// live one it could be asked to do something with.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the setup authority no longer
    /// validates, when the plan cannot project its child table, when the table
    /// is outside this mint's compiled bound, when a slot's source is absent or
    /// cannot be re-opened at the child's access, when the child cannot be
    /// started or does not stop, when its table cannot be read, and on every
    /// refusal `validate_for` makes.
    pub(crate) fn open_authenticated(
        setup_authority: &LinuxNativeServiceSetupDescriptorAuthority,
    ) -> Result<Self, CgroupIoFailure> {
        const OPERATION: &str = "mint-linux-native-service-child-launch-closure";

        setup_authority.validate_retained()?;
        let plan = &setup_authority.bootstrapped.journaled.plan;
        let binding = plan
            .service_child_launch_closure_binding()
            .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;
        if binding.inner_launcher_descriptor_table.len() < 3
            || binding.inner_launcher_descriptor_table.len()
                > MAX_LINUX_SERVICE_CHILD_LAUNCH_TABLE_SLOTS
        {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the plan's child descriptor table is outside this mint's compiled bound",
            ));
        }

        let slots = resolve_linux_native_service_child_launch_slots(
            &setup_authority.setup_descriptors,
            &binding.inner_launcher_descriptor_table,
            OPERATION,
        )?;
        let observed = materialise_and_read_linux_native_service_child_table(&slots, OPERATION)?;

        let descriptor_observations = binding
            .inner_launcher_descriptor_table
            .iter()
            .zip(&observed.descriptors)
            .map(
                |(descriptor, slot)| LinuxNativeServiceChildDescriptorObservation {
                    binding: descriptor.clone(),
                    // The child's own reading of the slot, so `validate_for`'s
                    // identity clause compares the child against the parent
                    // instead of the parent against itself.
                    identity: slot.identity,
                },
            )
            .collect::<Vec<_>>();
        let image_mount_observations = binding
            .image_mounts
            .iter()
            .map(|mount| {
                Ok(LinuxNativeServiceChildImageMountObservation {
                    binding: mount.clone(),
                    identity: observe_linux_native_service_child_image_mount(
                        &setup_authority.launch_images,
                        plan,
                        mount,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;

        let capability = Self {
            binding,
            descriptor_observations,
            image_mount_observations,
            child_table: LinuxNativeServiceChildTableEvidence::StoppedChild(observed),
        };
        capability.validate_for(
            plan,
            &setup_authority.launch_images,
            &setup_authority.setup_descriptors,
        )?;
        Ok(capability)
    }
}

/// Resolves one retained descriptor per planned slot, at the child's access.
///
/// The source table is closed by construction: a slot names either a setup
/// endpoint by role or the retained working directory, and
/// `observe_linux_native_service_child_descriptor_source` has already refused
/// anything else. Nothing here opens a path.
#[cfg(target_os = "linux")]
fn resolve_linux_native_service_child_launch_slots(
    setup_descriptors: &LinuxNativeServiceSetupDescriptorCapability,
    table: &[LinuxServiceChildDescriptorBindingV1],
    operation: &'static str,
) -> Result<Vec<LinuxNativeServiceChildLaunchSlot>, CgroupIoFailure> {
    use std::os::fd::AsFd as _;

    let procfs = open_authenticated_procfs_root()?;
    let mut slots = Vec::with_capacity(table.len());
    for binding in table {
        let identity =
            observe_linux_native_service_child_descriptor_source(setup_descriptors, binding)?;
        let retained: std::os::fd::BorrowedFd<'_> = match &binding.source {
            LinuxServiceChildDescriptorSourceV1::Endpoint(role) => setup_descriptors
                .endpoints
                .iter()
                .find(|endpoint| endpoint.binding.role == *role)
                .ok_or_else(|| {
                    failure(
                        operation,
                        EffectCertainty::NotApplied,
                        format!("child descriptor source {role:?} is absent"),
                    )
                })?
                .file
                .as_fd(),
            LinuxServiceChildDescriptorSourceV1::WorkingDirectory { .. } => {
                setup_descriptors.cwd.directory.as_fd()
            }
        };
        let descriptor = if binding.retained_source_access == binding.child_access {
            // `F_DUPFD_CLOEXEC` names the same open file description, so the
            // access mode and the inode are the retained descriptor's by
            // construction and are proved again below.
            rustix::io::fcntl_dupfd_cloexec(retained, 0)
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?
        } else {
            reopen_linux_native_service_child_descriptor_at_child_access(
                &procfs, retained, binding, identity, operation,
            )?
        };
        require_linux_native_service_child_source_state(&descriptor, binding, identity, operation)?;
        slots.push(LinuxNativeServiceChildLaunchSlot {
            binding: binding.clone(),
            identity,
            descriptor,
        });
    }
    Ok(slots)
}

/// Re-opens one retained descriptor at the narrower access the child holds.
///
/// The plan gives the child a read-only view of the sealed setup request the
/// service retains read-write. A duplicate cannot narrow an access mode — it
/// names the same open file description — so the object is re-opened through
/// its own `/proc/self/fd` entry, which reaches the same inode without
/// resolving any name the plan did not already authenticate. The result is then
/// required to be that exact inode.
#[cfg(target_os = "linux")]
fn reopen_linux_native_service_child_descriptor_at_child_access(
    procfs: &Dir,
    retained: std::os::fd::BorrowedFd<'_>,
    binding: &LinuxServiceChildDescriptorBindingV1,
    identity: ObjectIdentity,
    operation: &'static str,
) -> Result<std::os::fd::OwnedFd, CgroupIoFailure> {
    use std::os::fd::AsRawFd as _;

    let mut flags = rustix::fs::OFlags::CLOEXEC
        | match binding.child_access {
            LinuxServiceSetupDescriptorAccessV1::ReadOnly => rustix::fs::OFlags::RDONLY,
            LinuxServiceSetupDescriptorAccessV1::WriteOnly => rustix::fs::OFlags::WRONLY,
            LinuxServiceSetupDescriptorAccessV1::ReadWrite => rustix::fs::OFlags::RDWR,
        };
    if binding.kind == LinuxServiceChildDescriptorKindV1::Directory {
        flags |= rustix::fs::OFlags::DIRECTORY;
    }
    let reopened = rustix::fs::openat(
        procfs,
        format!("self/fd/{}", retained.as_raw_fd()),
        flags,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let stat = rustix::fs::fstat(&reopened)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let reached = ObjectIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
    };
    if reached != identity {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "re-opening child descriptor {} at its child access reached {}:{}, not the retained {}:{}",
                binding.target_fd, stat.st_dev, stat.st_ino, identity.device, identity.inode
            ),
        ));
    }
    Ok(reopened)
}

/// Requires the descriptor about to be handed to the child to be the exact
/// object, at the exact access, with close-on-exec still set in this process.
#[cfg(target_os = "linux")]
fn require_linux_native_service_child_source_state(
    descriptor: &std::os::fd::OwnedFd,
    binding: &LinuxServiceChildDescriptorBindingV1,
    identity: ObjectIdentity,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let stat = rustix::fs::fstat(descriptor)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let status = rustix::fs::fcntl_getfl(descriptor)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let descriptor_flags = rustix::io::fcntl_getfd(descriptor)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let expected_access = match binding.child_access {
        LinuxServiceSetupDescriptorAccessV1::ReadOnly => rustix::fs::OFlags::RDONLY,
        LinuxServiceSetupDescriptorAccessV1::WriteOnly => rustix::fs::OFlags::WRONLY,
        LinuxServiceSetupDescriptorAccessV1::ReadWrite => rustix::fs::OFlags::RDWR,
    };
    if stat.st_dev != identity.device
        || stat.st_ino != identity.inode
        || status & rustix::fs::OFlags::ACCMODE != expected_access
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "the descriptor prepared for child fd {} crossed its identity, access, or retained close-on-exec state",
                binding.target_fd
            ),
        ));
    }
    Ok(())
}

/// Starts one child holding the plan's exact table, reads it, and reaps it.
///
/// Fds 1 and 2 travel as `Stdio`, which is the only mechanism that places an
/// exact number across an `execve`, and is why they arrive without
/// `FD_CLOEXEC`. Every other slot travels in one atomic `SCM_RIGHTS` message
/// and is placed by the child with `F_DUPFD_CLOEXEC`, except fd 0, which the
/// child installs with `dup2` over the transport socket.
#[cfg(target_os = "linux")]
fn materialise_and_read_linux_native_service_child_table(
    slots: &[LinuxNativeServiceChildLaunchSlot],
    operation: &'static str,
) -> Result<LinuxNativeServiceStoppedChildTable, CgroupIoFailure> {
    use std::os::fd::AsFd as _;

    let stdio = |target: u32| -> Result<std::fs::File, CgroupIoFailure> {
        let slot = slots
            .iter()
            .find(|slot| slot.binding.target_fd == target)
            .ok_or_else(|| {
                failure(
                    operation,
                    EffectCertainty::NotApplied,
                    format!("the plan's child table has no slot for fd {target}"),
                )
            })?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&slot.descriptor, 0)
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        Ok(std::fs::File::from(duplicate))
    };
    let stdout = stdio(1)?;
    let stderr = stdio(2)?;
    let placements = slots
        .iter()
        .filter(|slot| slot.binding.target_fd != 1 && slot.binding.target_fd != 2)
        .map(|slot| (slot.binding.target_fd, slot.descriptor.as_fd()))
        .collect::<Vec<_>>();

    let probe = spawn_linux_service_child_launch_closure_probe(
        &service_bootstrap_probe_image(),
        stdout,
        stderr,
        &placements,
    )?;
    let pid = probe.pid();
    let planned = slots
        .iter()
        .map(|slot| slot.binding.target_fd)
        .collect::<Vec<_>>();
    let table = observe_stopped_child_descriptor_table(pid, &planned);
    // The child is killed and reaped whatever the read said, so a refused read
    // never leaves a stopped process behind.
    let reaped = probe.kill_and_reap();
    let table = table?;
    reaped?;
    Ok(LinuxNativeServiceStoppedChildTable {
        pid,
        open_fds: table.open_fds,
        descriptors: table
            .descriptors
            .into_iter()
            .map(|descriptor| LinuxNativeServiceObservedChildDescriptor {
                target_fd: descriptor.target_fd,
                identity: descriptor.identity,
                access: descriptor.access,
                close_on_exec: descriptor.close_on_exec,
                kind: descriptor.kind,
                mount_id: descriptor.mount_id,
            })
            .collect(),
    })
}

/// Compile-time check that the production child-launch-closure constructor
/// remains available with its required signature.
#[cfg(target_os = "linux")]
type LinuxNativeServiceChildLaunchClosureMint =
    fn(
        &LinuxNativeServiceSetupDescriptorAuthority,
    ) -> Result<LinuxNativeServiceChildLaunchClosureCapability, CgroupIoFailure>;

/// See [`LinuxNativeServiceChildLaunchClosureMint`].
#[cfg(target_os = "linux")]
const LINUX_NATIVE_SERVICE_CHILD_LAUNCH_CLOSURE_PRODUCTION_MINT:
    LinuxNativeServiceChildLaunchClosureMint =
    LinuxNativeServiceChildLaunchClosureCapability::open_authenticated;

/// The production route from an authenticated setup authority to the
/// child-launch closure authority, in one place.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] on every refusal the mint or
/// `bind_linux_native_service_child_launch_closure` makes.
#[cfg(target_os = "linux")]
pub(crate) fn open_linux_native_service_child_launch_authority(
    setup_authority: LinuxNativeServiceSetupDescriptorAuthority,
) -> Result<LinuxNativeServiceChildLaunchClosureAuthority, CgroupIoFailure> {
    let child_launch_closure =
        LinuxNativeServiceChildLaunchClosureCapability::open_authenticated(&setup_authority)?;
    bind_linux_native_service_child_launch_closure(setup_authority, child_launch_closure)
}

/// Opens the service-owned backend from authenticated setup custody.
///
/// The route validates child-launch authority and retains mechanics before
/// calling [`LinuxCgroupIo::open_service_owned`]. Opening alone grants no execution.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] for child-launch, mechanics, or backend refusals.
#[cfg(target_os = "linux")]
pub(crate) fn open_linux_native_service_owned_backend(
    setup_authority: LinuxNativeServiceSetupDescriptorAuthority,
) -> Result<LinuxCgroupIo, CgroupIoFailure> {
    let child_authority = open_linux_native_service_child_launch_authority(setup_authority)?;
    let mechanics = retain_linux_native_service_mechanics_authority(child_authority)?;
    LinuxCgroupIo::open_service_owned(mechanics)
}

// Prepare from retained mechanics authority, not a caller-supplied request,
// and compare the binding while holding the delegation lock.

impl LinuxCgroupIo {
    /// Returns this backend's own one-plan-scoped domain request.
    ///
    /// # Errors
    ///
    /// Fails when the retained mechanics authority no longer revalidates, and
    /// under `cfg(test)` when the backend was built through the module's
    /// `mechanics_guard: None` seam, which holds no plan and therefore has no
    /// request to answer with.
    fn retained_prepare_domain_request(&self) -> Result<PrepareDomainRequest, CgroupIoFailure> {
        #[cfg(not(test))]
        {
            self.mechanics_guard.validate_retained(&self.journal)?;
            Ok(self.mechanics_guard.request.clone())
        }
        #[cfg(test)]
        {
            let guard = self.mechanics_guard.as_ref().ok_or_else(|| {
                failure(
                    "retain-service-domain-request",
                    EffectCertainty::NotApplied,
                    "this backend holds no service mechanics authority, so it has no \
                     plan-scoped command-domain request",
                )
            })?;
            guard.validate_retained(&self.journal)?;
            Ok(guard.request.clone())
        }
    }

    /// The grant and policy identities the journal committed this plan under.
    ///
    /// A backend composed around this handoff must be the backend for *this*
    /// command, and a composer that already holds the grant and the policy is
    /// the only party that can check that. The pair is therefore the whole of
    /// what this accessor exposes: not the effect, not the session, not the
    /// delegation identity, and not the ceilings, because a composer has no
    /// legitimate use for any of them and exposing them would let one be
    /// mirrored back as if it had been independently known.
    ///
    /// # Errors
    ///
    /// Fails whenever [`Self::retained_prepare_domain_request`] fails.
    pub(crate) fn retained_command_authority(&self) -> Result<(String, String), CgroupIoFailure> {
        let request = self.retained_prepare_domain_request()?;
        Ok((request.grant_hash, request.policy_hash))
    }

    /// Prepares this plan's one command domain.
    ///
    /// The request is this backend's own retained one, never a caller's. Every
    /// effect below is the production one: the delegation lock, the durable
    /// preflight probe, the freshness admission, the subtree-controller
    /// read-back, the no-replace leaf creation, the four control writes and
    /// their byte-for-byte read-back, and the durable journal transitions that
    /// separate them.
    ///
    /// # Errors
    ///
    /// Returns `CgroupError` for every refusal `prepare_domain` makes, and
    /// for a mechanics authority that no longer revalidates.
    pub(crate) fn prepare_service_domain(
        &mut self,
    ) -> Result<crate::linux_containment::PrepareDomainOutcome, crate::linux_containment::CgroupError>
    {
        let request = self
            .retained_prepare_domain_request()
            .map_err(crate::linux_containment::CgroupError::host_before_leaf)?;
        crate::linux_containment::prepare_domain(self, request)
    }
}

// Build Landlock and BPF artifacts from retained scope identities and
// refuse unsupported kernels. The probe child treats paths as hints and
// checks inodes. Preparation neither installs controls nor grants execution.

/// The object every committed ruleset states it does not grant.
///
/// The filesystem root, which is outside every scope a `path_beneath` rule on a
/// subdirectory can grant. It is chosen because it exists on every host and
/// because being denied it is the strongest single statement a probe can make:
/// a child that cannot open `/` cannot walk to anything it was not granted.
#[cfg(target_os = "linux")]
pub(crate) const LINUX_LANDLOCK_DENIAL_WITNESS_PATH: &str = "/";

/// Reads the kernel's own path for one retained descriptor.
///
/// `/proc/self/fd/<n>` is a symlink the kernel maintains for the open file
/// description, so this is a live read about a descriptor this process holds,
/// not a name reconstructed from components.
#[cfg(target_os = "linux")]
fn retained_descriptor_path(
    directory: &Dir,
    role: &str,
    operation: &'static str,
) -> Result<String, CgroupIoFailure> {
    use std::os::fd::AsRawFd as _;

    let link = format!("/proc/self/fd/{}", directory.as_raw_fd());
    let resolved = std::fs::read_link(&link)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let resolved = resolved.to_str().ok_or_else(|| {
        failure(
            operation,
            EffectCertainty::NotApplied,
            format!("the kernel's path for the retained {role} is not UTF-8"),
        )
    })?;
    if !resolved.starts_with('/') || resolved.ends_with(" (deleted)") {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "the kernel's path for the retained {role} is {resolved}, which is not a live absolute path"
            ),
        ));
    }
    Ok(resolved.to_owned())
}

/// The kernel's device and inode for one retained descriptor.
#[cfg(target_os = "linux")]
fn retained_descriptor_identity(
    directory: &Dir,
    operation: &'static str,
) -> Result<(u64, u64), CgroupIoFailure> {
    let observed = rustix::fs::fstat(directory)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    Ok((observed.st_dev, observed.st_ino))
}

#[cfg(target_os = "linux")]
impl LinuxRetainedPerCommandDirectories {
    /// Creates this command's Landlock ruleset and compiles its seccomp filter.
    ///
    /// The four scopes are the command's own filesystem surface, and their
    /// read/write split is the split the plan's mount table already carries:
    /// the grant's workspace root is readable, and the three directories this
    /// service created for this command — the execution root, the private
    /// temporary directory and the output spool — are writable.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the kernel implements no Landlock ABI
    /// at all, when a retained descriptor has no live path or identity, when
    /// the identity the kernel answers for a held descriptor is not the one the
    /// plan's object table already committed for that role, when the kernel
    /// refuses the handled access set or any rule, when the denial witness
    /// cannot be identified or collapses onto a granted scope, or when the
    /// architecture has no compiled syscall table.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear mint keeps every scope, its kernel answer, and the committed identity it is compared against visible in the order they are read"
    )]
    pub(crate) fn mint_mandatory_control_artefacts(
        &self,
        workspace_root: &Dir,
        audit_architecture: LinuxAuditArchitectureV1,
    ) -> Result<LinuxMandatoryControlArtefactsV1, CgroupIoFailure> {
        use landlock::{
            Access as _, AccessFs, BitFlags, CompatLevel, Compatible as _, PathBeneath, Ruleset,
            RulesetAttr as _, RulesetCreatedAttr as _,
        };

        const OPERATION: &str = "mint-linux-mandatory-control-artefacts";

        let observed = crate::linux_dev_domain::observed_landlock_abi();
        let created_at_kernel_abi = u32::from(crate::linux_dev_domain::abi_level(observed));
        if created_at_kernel_abi == 0 {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "this kernel implements no Landlock ABI, so no ruleset can be created and no filesystem policy can be committed",
            ));
        }
        // Handle every right reported by the observed kernel ABI; silently dropping
        // unsupported rights would weaken the declared policy.
        let handled = AccessFs::from_all(observed);
        let readable = AccessFs::from_read(observed);
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(handled)
            .and_then(Ruleset::create)
            .map_err(|error| {
                failure(
                    OPERATION,
                    EffectCertainty::NotApplied,
                    format!("create this command's Landlock ruleset: {error}"),
                )
            })?;

        let requested: [(&LinuxRetainedObjectIdentityV1, &Dir, BitFlags<AccessFs>); 4] = [
            (self.identities.workspace_root(), workspace_root, readable),
            (
                self.identities.execution_root(),
                &self.execution_root,
                handled,
            ),
            (self.identities.private_temp(), &self.private_temp, handled),
            (self.identities.output_spool(), &self.output_spool, handled),
        ];
        let mut scopes = Vec::with_capacity(requested.len());
        for (committed, directory, access) in requested {
            let role = committed.object_id();
            let (device_id, inode) = retained_descriptor_identity(directory, OPERATION)?;
            let expected = committed.kernel_observation();
            if device_id != expected.device_id || inode != expected.inode {
                return Err(failure(
                    OPERATION,
                    EffectCertainty::NotApplied,
                    format!(
                        "the descriptor held for {role} answers {device_id}/{inode} while the plan's object table committed {}/{}",
                        expected.device_id, expected.inode
                    ),
                ));
            }
            let resolved_path = retained_descriptor_path(directory, role, OPERATION)?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(directory, access))
                .map_err(|error| {
                    failure(
                        OPERATION,
                        EffectCertainty::NotApplied,
                        format!("grant {role} beneath this command's ruleset: {error}"),
                    )
                })?;
            scopes.push(LinuxLandlockScopeV1 {
                object_id: role.to_owned(),
                resolved_path,
                device_id,
                inode,
                access_bits: access.bits(),
            });
        }
        // The ruleset was created and every rule was accepted; the descriptor
        // it lives in is deliberately dropped here. Nothing installs it: this
        // mint produces a description, and `restrict_self` belongs to the probe
        // process and to the launcher, neither of which is this service.
        drop(ruleset);
        scopes.sort_by(|left, right| left.object_id.cmp(&right.object_id));

        let witness_path = Path::new(LINUX_LANDLOCK_DENIAL_WITNESS_PATH);
        let witness = rustix::fs::stat(witness_path)
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        if scopes
            .iter()
            .any(|scope| scope.device_id == witness.st_dev && scope.inode == witness.st_ino)
        {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the denial witness is one of the scopes this ruleset grants, so no denial could be observed",
            ));
        }
        let mut landlock = LinuxLandlockRulesetV1 {
            created_at_kernel_abi,
            handled_access_bits: handled.bits(),
            scopes,
            denial_witness: LinuxLandlockDenialWitnessV1 {
                resolved_path: LINUX_LANDLOCK_DENIAL_WITNESS_PATH.to_owned(),
                device_id: witness.st_dev,
                inode: witness.st_ino,
            },
            ruleset_sha256: Digest::sha256(&[]),
        };
        landlock.ruleset_sha256 = landlock.canonical_digest();

        let seccomp = mint_command_seccomp_filter(audit_architecture, OPERATION)?;
        let seccomp_namespace = mint_command_namespace_filter(audit_architecture, OPERATION)?;
        Ok(LinuxMandatoryControlArtefactsV1 {
            landlock,
            seccomp,
            seccomp_namespace,
        })
    }
}

/// Compiles this command's namespace filter and digests what it assembled.
///
/// The second committed filter. It answers `ENOSYS` where the network filter
/// kills, which is why it cannot be more rules inside that one: a `seccompiler`
/// filter carries exactly one matched action. The network filter's bytes,
/// digest and instruction count are untouched by this.
///
/// The committed list is built from the single namespace table; the BPF is
/// assembled by [`crate::linux_command_plan::assemble_namespace_program`], the
/// same assembler the launcher uses on that list. There is no second walk.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when this architecture has no compiled syscall
/// table, or when the filter does not compile or assemble.
#[cfg(target_os = "linux")]
fn mint_command_namespace_filter(
    audit_architecture: LinuxAuditArchitectureV1,
    operation: &'static str,
) -> Result<LinuxSeccompNamespaceFilterV1, CgroupIoFailure> {
    let denied_syscalls =
        crate::linux_command_plan::committed_namespace_denials(audit_architecture);
    let program =
        crate::linux_command_plan::assemble_namespace_program(&denied_syscalls, audit_architecture)
            .map_err(|error| {
                failure(
                    operation,
                    EffectCertainty::NotApplied,
                    format!("assemble this command's namespace filter: {error}"),
                )
            })?;

    let mut filter = LinuxSeccompNamespaceFilterV1 {
        action: LinuxSeccompNamespaceActionV1::ErrnoNotImplemented,
        denied_syscalls,
        instruction_count: program.len() as u64,
        program_sha256: seccomp_program_digest(&program),
        filter_sha256: Digest::sha256(&[]),
    };
    filter.filter_sha256 = filter.canonical_digest(audit_architecture);
    Ok(filter)
}

/// Compiles this command's seccomp filter and digests the program it assembled.
///
/// The denied set is the network-endpoint surface `LINUX_NETWORK_SYSCALLS`
/// already defines for this architecture, and the matched action is
/// `KillProcess` because that is what the plan's `default_action` has committed
/// to since schema version 2 and what `validate_mandatory_kernel_controls`
/// still requires unchanged. The development domain's own filter answers
/// `EPERM` instead; it is a different filter for a different arm and is not
/// touched here.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when this architecture has no compiled syscall
/// table, or when the filter does not compile or assemble.
#[cfg(target_os = "linux")]
fn mint_command_seccomp_filter(
    audit_architecture: LinuxAuditArchitectureV1,
    operation: &'static str,
) -> Result<LinuxSeccompFilterV1, CgroupIoFailure> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let table = crate::linux_dev_domain::LINUX_NETWORK_SYSCALLS;
    let rules = table
        .iter()
        .map(|(_, number)| (*number, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let compiled = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        crate::linux_dev_domain::LINUX_SECCOMP_TARGET_ARCH,
    )
    .map_err(|error| {
        failure(
            operation,
            EffectCertainty::NotApplied,
            format!("compile this command's seccomp filter: {error}"),
        )
    })?;
    let program = BpfProgram::try_from(compiled).map_err(|error| {
        failure(
            operation,
            EffectCertainty::NotApplied,
            format!("assemble this command's seccomp filter: {error}"),
        )
    })?;
    let mut denied_syscalls = table
        .iter()
        .map(|(name, number)| LinuxSeccompDeniedSyscallV1 {
            name: (*name).to_owned(),
            number: *number,
        })
        .collect::<Vec<_>>();
    denied_syscalls.sort_by(|left, right| left.name.cmp(&right.name));
    let mut filter = LinuxSeccompFilterV1 {
        denied_syscalls,
        instruction_count: program.len() as u64,
        program_sha256: seccomp_program_digest(&program),
        filter_sha256: Digest::sha256(&[]),
    };
    filter.filter_sha256 =
        filter.canonical_digest(audit_architecture, LinuxSeccompDefaultActionV1::KillProcess);
    Ok(filter)
}

// Canary episodes are non-effect control claims bound to the probe journal.

const PROBE_JOURNAL_SUPERSEDED_FORMAT_VERSION: u32 = 1;
/// The generation a canary episode may make a claim about.
///
/// A canary proves a control *on a generation*, never in the abstract, and
/// this is the only value the durable record admits. A canary episode carried
/// forward onto a different backend generation is refused rather than
/// reinterpreted.
const CANARY_EPISODE_GENERATION: &str = "linux-cgroup-v2-v1";
/// Domain separator for the canary suite result digest.
const CANARY_EPISODE_DIGEST_DOMAIN: &[u8] = b"grok-build/linux-canary-episode/v1\0";
/// Hard bound on the outcomes one canary episode may record.
///
/// Twelve controls plus the optional memory ceiling is thirteen; the bound is
/// the closed control vocabulary's size and is not a tuning knob.
const MAX_CANARY_EPISODE_OUTCOMES: usize = 16;
/// The closed compiled vocabulary of control names a canary episode may name.
///
/// This is deliberately a compiled allowlist rather than an open string: a
/// durable record able to name an arbitrary control would let a canary
/// episode invent a capability, which is the fabricated-claim door this
/// project has spent nineteen increments keeping shut. Every entry is the
/// exact `BackendControl` debug name the supervisor's own `required_controls`
/// uses, so a name that reaches `enforced_controls()` is a name that was
/// journaled.
const CANARY_EPISODE_CONTROL_NAMES: &[&str] = &[
    "ActiveCanaries",
    "ClosedInheritedDescriptors",
    "CompleteBoundedOutput",
    "DescendantDomainKill",
    "DescendantLimit",
    "DescriptorExec",
    "DescriptorWorkingDirectory",
    "ExactArgv",
    "ExternalWallClock",
    "FilesystemPolicy",
    "MemoryLimit",
    "NetworkPolicy",
    "ReplacedEnvironment",
];

/// What one probe episode is *about*.
///
/// Both kinds are driven by the same durable machine, live in the same
/// private probe journal directory, and are bounded by the same generation
/// ceiling. Neither is a command effect: a probe episode carries no
/// `effect_id`, is never entered into `created_command_effects` or
/// `command_effect_history`, and its leaf is a sibling of the command's
/// domain rather than the command's domain.
///
/// The distinction between the two kinds is recorded rather than inferred.
/// A delegation probe measures the delegated root's own default behaviour and
/// makes no control claim at all; a canary episode records exactly what live
/// probes proved inside one leaf, on one generation. Reading the kind out of
/// the presence of the evidence would make a record whose evidence failed to
/// persist indistinguishable from a record that never claimed one, so the
/// kind is its own field and the two are cross-checked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeEpisodeKind {
    /// Create, observe, configure, kill, prove empty, remove. No claim.
    DelegationDefaultShape,
    /// The same lifecycle, plus what live probes proved inside the leaf.
    ControlCanary,
}

/// One control, and whether a live probe inside this leaf proved it.
///
/// `proven` is never a summary of intent. A `true` here requires a non-zero
/// `witness_digest`, which only the probe that ran can produce, so a control
/// cannot be recorded as proven by a suite that did not run one.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanaryControlOutcomeV1 {
    control: String,
    probe: String,
    proven: bool,
    witness_digest: String,
}

/// What one canary episode established, durably, inside one leaf.
///
/// `root_identity` is the kernel identity of the leaf every probe ran under,
/// and the record requires it to equal the episode's own authoritative
/// observed identity — so an episode cannot borrow another leaf's results.
/// `suite_result_digest` covers the generation, that identity, and every
/// outcome in order, so a record whose outcome list was edited after the fact
/// no longer decodes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CanaryEpisodeEvidenceV1 {
    generation: String,
    root_identity: CgroupObjectIdentity,
    probe_runs: u32,
    outcomes: Vec<CanaryControlOutcomeV1>,
    suite_result_digest: String,
}

impl CanaryEpisodeEvidenceV1 {
    /// The digest of exactly what this episode says it established.
    ///
    /// Domain-separated, length-framed, and computed over the generation, the
    /// leaf identity, and every outcome in the order the record carries them.
    /// Nothing outside the record contributes, so the digest is recomputable
    /// from the persisted bytes alone at every restart.
    fn canonical_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CANARY_EPISODE_DIGEST_DOMAIN);
        hasher.update((self.generation.len() as u64).to_be_bytes());
        hasher.update(self.generation.as_bytes());
        hasher.update(self.root_identity.device.to_be_bytes());
        hasher.update(self.root_identity.inode.to_be_bytes());
        hasher.update(u64::from(self.probe_runs).to_be_bytes());
        hasher.update((self.outcomes.len() as u64).to_be_bytes());
        for outcome in &self.outcomes {
            hasher.update((outcome.control.len() as u64).to_be_bytes());
            hasher.update(outcome.control.as_bytes());
            hasher.update((outcome.probe.len() as u64).to_be_bytes());
            hasher.update(outcome.probe.as_bytes());
            hasher.update([u8::from(outcome.proven)]);
            hasher.update((outcome.witness_digest.len() as u64).to_be_bytes());
            hasher.update(outcome.witness_digest.as_bytes());
        }
        hex_lower(&hasher.finalize())
    }

    /// Exactly the controls this episode proved, as recorded.
    fn proven_control_names(&self) -> BTreeSet<String> {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.proven)
            .map(|outcome| outcome.control.clone())
            .collect()
    }

    fn validate(&self, observed: Option<CgroupObjectIdentity>) -> Result<(), CgroupIoFailure> {
        let invalid = |detail: &str| {
            failure(
                "validate-canary-episode-evidence",
                EffectCertainty::NotApplied,
                detail.to_owned(),
            )
        };
        if self.generation != CANARY_EPISODE_GENERATION {
            return Err(invalid(
                "a canary episode may only make a claim about generation linux-cgroup-v2-v1",
            ));
        }
        if Some(self.root_identity) != observed
            || self.root_identity.device == 0
            || self.root_identity.inode == 0
        {
            return Err(invalid(
                "canary episode root identity is not this episode's own authoritative leaf",
            ));
        }
        if self.outcomes.len() > MAX_CANARY_EPISODE_OUTCOMES {
            return Err(invalid(
                "canary episode outcome count exceeded its hard bound",
            ));
        }
        let mut previous: Option<&str> = None;
        for outcome in &self.outcomes {
            if !CANARY_EPISODE_CONTROL_NAMES.contains(&outcome.control.as_str()) {
                return Err(invalid(
                    "canary episode named a control outside the closed compiled vocabulary",
                ));
            }
            if previous.is_some_and(|last| last >= outcome.control.as_str()) {
                return Err(invalid(
                    "canary episode outcomes must be unique and bytewise sorted by control",
                ));
            }
            previous = Some(outcome.control.as_str());
            validate_probe_name(&outcome.probe)?;
            if outcome.witness_digest.len() != 64
                || !outcome
                    .witness_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid(
                    "canary episode witness digest is not canonical lowercase SHA-256",
                ));
            }
            // A proven control needs a witness a probe produced. An all-zero
            // digest is what an absent probe would leave behind, and it is the
            // one value that can be written without running anything.
            if outcome.proven && outcome.witness_digest.bytes().all(|byte| byte == b'0') {
                return Err(invalid(
                    "a canary episode may not record a control as proven with an absent witness",
                ));
            }
        }
        if self.suite_result_digest != self.canonical_digest() {
            return Err(invalid(
                "canary episode suite digest is not the digest of the outcomes beside it",
            ));
        }
        // Record one outcome per actual probe in the same cgroup leaf.
        if self
            .outcomes
            .iter()
            .any(|outcome| outcome.control == "ActiveCanaries" && outcome.proven)
            && (self.probe_runs as usize) < self.outcomes.len()
        {
            return Err(invalid(
                "a canary episode may not prove ActiveCanaries with fewer runs than outcomes",
            ));
        }
        Ok(())
    }
}

impl ProbeJournalRecord {
    /// Cross-checks the declared episode kind against the claim it carries.
    ///
    /// Split out of `validate` so the record's state-shape table and the
    /// canary episode's own admissibility stay separately readable; both run
    /// on every persisted generation and every decoded one.
    fn validate_episode_kind_and_claim(&self) -> Result<(), CgroupIoFailure> {
        match (&self.canary, self.episode_kind) {
            // A delegation probe makes no control claim, so carrying one is
            // not a lesser version of a canary episode: it is a record whose
            // own kind contradicts its contents.
            (Some(_), ProbeEpisodeKind::DelegationDefaultShape) => {
                return Err(failure(
                    "validate-probe-journal-record",
                    EffectCertainty::NotApplied,
                    "a delegation default-shape probe may not carry canary episode evidence",
                ));
            }
            (Some(canary), ProbeEpisodeKind::ControlCanary) => {
                canary.validate(self.observed_identity)?;
                // Evidence can only describe a leaf that was authoritative,
                // shape-observed and configured; before that there is nothing
                // for a probe to have run inside.
                if !self.identity_authoritative
                    || self.initial_shape.is_none()
                    || !self.configured_and_read_back
                    || !matches!(
                        self.state,
                        ProbeJournalState::Configured
                            | ProbeJournalState::KillIntended
                            | ProbeJournalState::EmptyProven
                            | ProbeJournalState::RemoveIntended
                            | ProbeJournalState::Removed
                    )
                {
                    return Err(failure(
                        "validate-probe-journal-record",
                        EffectCertainty::NotApplied,
                        "canary episode evidence precedes the configured leaf it claims to describe",
                    ));
                }
            }
            (None, _) => {}
        }
        Ok(())
    }
}

/// One control a live canary suite reported, before the journal admits it.
///
/// This is the suite's own vocabulary, not the record's. It crosses the
/// boundary as plain data and is turned into a [`CanaryControlOutcomeV1`]
/// here, so a suite cannot construct a durable record directly and every
/// closed-vocabulary, ordering, witness and digest rule is applied on this
/// side of the boundary rather than trusted from the other.
pub(crate) struct CanarySuiteControlOutcome {
    pub(crate) control: String,
    pub(crate) probe: String,
    pub(crate) proven: bool,
    pub(crate) witness_digest: String,
}

/// What one live canary suite established inside the leaf it adopted.
pub(crate) struct CanarySuiteOutcome {
    /// How many live canary runs the suite actually completed.
    pub(crate) probe_runs: u32,
    pub(crate) outcomes: Vec<CanarySuiteControlOutcome>,
}

/// The live control suite one canary episode runs inside its journaled leaf.
///
/// The journal calls this exactly once per episode, in the `Configured` state,
/// and hands it the delegation descriptor it already holds plus the name and
/// authoritative identity of the leaf **the journal created**. The suite
/// adopts that leaf; it does not name one, create one, or remove one.
pub(crate) trait LinuxCanarySuite {
    /// Runs every control probe inside the adopted leaf.
    ///
    /// # Errors
    ///
    /// Returns the suite's own bounded reason when the suite could not reach a
    /// definite result. A suite that proved nothing returns an outcome with no
    /// proven control rather than an error.
    fn run_in_adopted_leaf(
        &mut self,
        delegation: std::os::fd::BorrowedFd<'_>,
        leaf_name: &str,
        leaf_identity: (u64, u64),
    ) -> Result<CanarySuiteOutcome, String>;
}

/// Turns one live suite's report into durable evidence, or refuses it.
///
/// This is the whole boundary between what a suite says and what the journal
/// will keep, and it is deliberately a total function of the report plus the
/// episode's own authoritative identity — nothing else contributes, so the
/// same report always yields the same digest.
///
/// The suite's report is canonicalized (sorted by control) and then validated
/// by [`CanaryEpisodeEvidenceV1::validate`], the same validator every
/// persisted generation and every restart runs. Canonicalizing before
/// validating admits nothing: sorting cannot make two equal control names
/// distinct, so a duplicated control still fails the uniqueness rule, and the
/// closed compiled vocabulary, the witness rule, the generation rule, the leaf
/// identity rule and the `ActiveCanaries` run-count rule are all applied here
/// rather than trusted from the suite.
///
/// # Errors
///
/// Fails for every reason [`CanaryEpisodeEvidenceV1::validate`] fails.
fn canary_evidence_from_suite_report(
    identity: CgroupObjectIdentity,
    reported: CanarySuiteOutcome,
) -> Result<CanaryEpisodeEvidenceV1, CgroupIoFailure> {
    let mut outcomes = reported
        .outcomes
        .into_iter()
        .map(|outcome| CanaryControlOutcomeV1 {
            control: outcome.control,
            probe: outcome.probe,
            proven: outcome.proven,
            witness_digest: outcome.witness_digest,
        })
        .collect::<Vec<_>>();
    outcomes.sort_by(|left, right| left.control.cmp(&right.control));
    let mut evidence = CanaryEpisodeEvidenceV1 {
        generation: CANARY_EPISODE_GENERATION.to_owned(),
        root_identity: identity,
        probe_runs: reported.probe_runs,
        outcomes,
        suite_result_digest: String::new(),
    };
    evidence.suite_result_digest = evidence.canonical_digest();
    // The persisted record validates this again on every generation and every
    // restart. Validating it here too means a suite that reported something
    // inadmissible is refused at the point it reported it, rather than one
    // transition later with the leaf already killed.
    evidence.validate(Some(identity))?;
    Ok(evidence)
}

/// Drives the delegation probe's own lifecycle, plus one live control suite.
///
/// Every lifecycle method delegates to [`LinuxProbeEffects`] unchanged, so the
/// leaf a canary episode runs in is created, configured, killed, proven empty
/// and removed by exactly the code that has driven the delegation probe in
/// production since before canary episodes existed. The only additions are the
/// declared episode kind and the suite call.
struct LinuxCanaryEpisodeEffects<'a, S: LinuxCanarySuite> {
    inner: LinuxProbeEffects<'a>,
    suite: &'a mut S,
}

impl<S: LinuxCanarySuite> DurableProbeEffects for LinuxCanaryEpisodeEffects<'_, S> {
    fn episode_kind(&self) -> ProbeEpisodeKind {
        ProbeEpisodeKind::ControlCanary
    }

    fn run_canary_suite(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<Option<CanaryEpisodeEvidenceV1>, CgroupIoFailure> {
        let identity = record.observed_identity.ok_or_else(|| {
            failure(
                "run-canary-suite",
                EffectCertainty::NotApplied,
                "a canary suite may only run inside an authoritative leaf",
            )
        })?;
        let reported = self
            .suite
            .run_in_adopted_leaf(
                std::os::fd::AsFd::as_fd(self.inner.delegation),
                &record.probe_name,
                (identity.device, identity.inode),
            )
            .map_err(|detail| failure("run-canary-suite", EffectCertainty::NotApplied, detail))?;
        canary_evidence_from_suite_report(identity, reported).map(Some)
    }

    fn observe_identity(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<Option<CgroupObjectIdentity>, CgroupIoFailure> {
        self.inner.observe_identity(record)
    }

    fn observe_shape(
        &mut self,
        record: &ProbeJournalRecord,
        identity: CgroupObjectIdentity,
    ) -> Result<Option<ProbeDefaultShape>, CgroupIoFailure> {
        self.inner.observe_shape(record, identity)
    }

    fn create_no_replace(&mut self, name: &str) -> Result<(), CgroupIoFailure> {
        self.inner.create_no_replace(name)
    }

    fn configure_exact(&mut self, record: &ProbeJournalRecord) -> Result<bool, CgroupIoFailure> {
        self.inner.configure_exact(record)
    }

    fn kill_and_prove_empty(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<bool, CgroupIoFailure> {
        self.inner.kill_and_prove_empty(record)
    }

    fn remove_exact_and_prove(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<(), CgroupIoFailure> {
        self.inner.remove_exact_and_prove(record)
    }
}

impl LinuxCgroupIo {
    /// Runs one live canary episode against this service's own delegation.
    ///
    /// This is the production entry point the canary suite reaches, and it is
    /// the whole reason a canary episode had to become journaled first. The
    /// leaf every probe runs inside is created by the probe journal under a
    /// durable create-intent generation, adopted by the suite, and removed by
    /// the journal under its own remove-intent generation. No cgroup domain is
    /// created that a durable generation does not describe.
    ///
    /// It is **not** a command effect and cannot become one: the record this
    /// writes is a `ProbeJournalRecord`, which cannot reach
    /// [`CanonicalCgroupJournalStore::persist`] at all.
    ///
    /// Returns exactly the control names the episode durably journaled as
    /// proven — never the names the suite asked for.
    ///
    /// # Errors
    ///
    /// Fails for every reason the durable probe machine fails, when the suite
    /// itself could not reach a definite result, when what the suite reported
    /// is inadmissible as durable evidence, and when the episode reached its
    /// endpoint with no journaled claim.
    pub(crate) fn run_canary_episode<S: LinuxCanarySuite>(
        &mut self,
        suite: &mut S,
    ) -> Result<BTreeSet<String>, CgroupIoFailure> {
        // The same single-writer discipline every probe generation is written
        // under. A canary episode drives the identical durable machine against
        // the identical delegation, so it takes the identical lock rather than
        // a weaker one.
        let token = self.acquire_delegation_lock()?;
        let driven = {
            let mut effects = LinuxCanaryEpisodeEffects {
                inner: LinuxProbeEffects {
                    delegation: &self.delegation,
                },
                suite,
            };
            drive_canary_episode(&mut self.journal, &mut effects, self.expectation)
        };
        match driven {
            Ok(evidence) => {
                let proven = evidence.proven_control_names();
                self.release_delegation_lock(&token)?;
                Ok(proven)
            }
            Err(error) => {
                // A canary episode drives the same leaf lifecycle the
                // delegation probe does, so a failure leaves the same
                // reconciliation obligation behind — and the writer flock is
                // deliberately retained until it is discharged, exactly as
                // `release_delegation_lock` requires.
                self.probe_reconciliation_required = true;
                Err(error)
            }
        }
    }
}

// Derive release parameters from committed artifacts and the target.
// Preparing them grants no execution permission.

/// How many Landlock scope roles this service holds a descriptor for.
///
/// The roles themselves are the plan's object identifiers, matched in
/// [`LinuxRetainedPerCommandDirectories::retained_scope_descriptor`]. This is
/// the count, kept beside them so a fifth role cannot be added to the match
/// without the bound moving with it.
#[cfg(target_os = "linux")]
const LINUX_CONTAINED_RELEASE_SCOPE_ROLE_COUNT: usize = 4;

#[cfg(target_os = "linux")]
impl LinuxRetainedPerCommandDirectories {
    /// Builds the containment request one contained-command release installs,
    /// from the descriptors this value already holds.
    ///
    /// Every scope descriptor is a `try_clone` — `fcntl(F_DUPFD_CLOEXEC)` — of
    /// a directory this service created and has held open since. The copy names
    /// the same open file description, so there is no window in which a path
    /// could be re-resolved to something else, and close-on-exec stays set. The
    /// live identity of each copy is then required to equal what the plan's own
    /// ruleset committed for that role, so a descriptor that was somehow
    /// substituted refuses here rather than being described.
    ///
    /// The role lookup is a closed match with no path-opening arm, which is the
    /// same discipline the setup-descriptor mint uses: an object identifier this
    /// service did not create or anchor cannot be turned into a grant.
    ///
    /// The two committed digests are the **plan's**, passed through unchanged.
    /// They are inputs to `build_containment_artefact`, which recomposes the
    /// whole artefact from these descriptors' own `fstat` answers and a BPF
    /// program it assembles itself, and then requires the canonical digests to
    /// equal them. So this mint cannot produce a release the plan did not
    /// describe: a substituted scope, an edited access set or an invented
    /// witness is refused by the controller before the helper is told anything.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the committed ruleset grants no scope or
    /// more than the closed role set holds, when a committed scope names a role
    /// this service holds no descriptor for, when a held descriptor cannot be
    /// duplicated, when a duplicate's live identity is not the identity the plan
    /// committed for its role, and when the committed denial witness cannot be
    /// observed or does not answer its committed identity.
    /// Creates one release stdio stream inside this command's private temp,
    /// through the held handle rather than by path.
    ///
    /// The `Dir` is kept instead of a path precisely so a name cannot be
    /// resolved twice with something else substituted in between, and the three
    /// release streams have no reason to be the exception. The file is created
    /// and then reopened with exactly the access its role needs: a read-only
    /// stdin must not also be the descriptor that created or truncated it.
    ///
    /// # Errors
    ///
    /// When the name is not a single safe component, or when the stream cannot
    /// be created or reopened.
    pub(crate) fn mint_release_stream(
        &self,
        name: &str,
        writable: bool,
    ) -> Result<std::fs::File, CgroupIoFailure> {
        const OPERATION: &str = "mint-linux-contained-release-stream";
        validate_component("contained release stream", name)?;
        self.private_temp
            .write(name, b"")
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        let file = self
            .private_temp
            .open_with(
                name,
                cap_std::fs::OpenOptions::new().read(true).write(writable),
            )
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        Ok(file.into_std())
    }

    pub(crate) fn authenticated_containment_request(
        &self,
        workspace_root: &Dir,
        artefacts: &LinuxMandatoryControlArtefactsV1,
        audit_architecture: LinuxAuditArchitectureV1,
    ) -> Result<AuthenticatedContainmentRequest, CgroupIoFailure> {
        const OPERATION: &str = "mint-linux-contained-release-containment-request";

        let committed = &artefacts.landlock;
        if committed.scopes.is_empty()
            || committed.scopes.len() > LINUX_CONTAINED_RELEASE_SCOPE_ROLE_COUNT
        {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!(
                    "the plan committed {} Landlock scopes, which is outside the closed set of \
                     {LINUX_CONTAINED_RELEASE_SCOPE_ROLE_COUNT} roles this service holds \
                     descriptors for",
                    committed.scopes.len()
                ),
            ));
        }

        let mut scopes = Vec::with_capacity(committed.scopes.len());
        for scope in &committed.scopes {
            scopes.push(self.authenticated_scope(workspace_root, scope, OPERATION)?);
        }
        let witness = &committed.denial_witness;
        require_committed_denial_witness(witness, OPERATION)?;

        Ok(AuthenticatedContainmentRequest {
            created_at_kernel_abi: committed.created_at_kernel_abi,
            handled_access_bits: committed.handled_access_bits,
            scopes,
            denial_witness_path: witness.resolved_path.clone(),
            denial_witness_identity: LauncherDescriptorIdentity {
                device: witness.device_id,
                inode: witness.inode,
            },
            committed_ruleset_sha256: committed.ruleset_sha256.as_str().to_owned(),
            audit_architecture: crate::linux_command_plan::audit_architecture_tag(
                audit_architecture,
            )
            .to_owned(),
            denied_syscalls: artefacts
                .seccomp
                .denied_syscalls
                .iter()
                .map(|syscall| (syscall.name.clone(), syscall.number))
                .collect(),
            committed_filter_sha256: artefacts.seccomp.filter_sha256.as_str().to_owned(),
            namespace_denied_syscalls: artefacts.seccomp_namespace.denied_syscalls.clone(),
            committed_namespace_filter_sha256: artefacts
                .seccomp_namespace
                .filter_sha256
                .as_str()
                .to_owned(),
        })
    }

    /// Duplicates one committed scope's held descriptor and proves its identity.
    ///
    /// `try_clone` is `fcntl(F_DUPFD_CLOEXEC)`: the copy names the same open
    /// file description and keeps close-on-exec. The copy travels with the
    /// release; the original stays with this value.
    fn authenticated_scope(
        &self,
        workspace_root: &Dir,
        scope: &LinuxLandlockScopeV1,
        operation: &'static str,
    ) -> Result<AuthenticatedLandlockScope, CgroupIoFailure> {
        let held = self.retained_scope_descriptor(workspace_root, &scope.object_id, operation)?;
        let duplicate = held.try_clone().map_err(|error| {
            io_failure(
                operation,
                EffectCertainty::NotApplied,
                format!(
                    "duplicate the retained descriptor for {}: {error}",
                    scope.object_id
                ),
            )
        })?;
        let (device_id, inode) = retained_descriptor_identity(&duplicate, operation)?;
        if device_id != scope.device_id || inode != scope.inode {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                format!(
                    "the duplicated descriptor for {} answers {device_id}/{inode} while the \
                     plan's ruleset committed {}/{}",
                    scope.object_id, scope.device_id, scope.inode
                ),
            ));
        }
        Ok(AuthenticatedLandlockScope {
            object_id: scope.object_id.clone(),
            resolved_path: scope.resolved_path.clone(),
            access_bits: scope.access_bits,
            descriptor: AuthenticatedReleaseDescriptor::new(
                duplicate.into_std_file(),
                LauncherDescriptorIdentity {
                    device: device_id,
                    inode,
                },
            ),
        })
    }

    /// Answers which held descriptor a committed scope role names.
    ///
    /// There is deliberately no arm that opens a path. That is the whole
    /// property: the closed table is what stops this mint from becoming a way to
    /// grant a contained command any directory at all.
    fn retained_scope_descriptor<'directories>(
        &'directories self,
        workspace_root: &'directories Dir,
        object_id: &str,
        operation: &'static str,
    ) -> Result<&'directories Dir, CgroupIoFailure> {
        match object_id {
            WORKSPACE_ROOT_OBJECT_ID => Ok(workspace_root),
            EXECUTION_ROOT_OBJECT_ID => Ok(&self.execution_root),
            PRIVATE_TEMP_OBJECT_ID => Ok(&self.private_temp),
            OUTPUT_SPOOL_OBJECT_ID => Ok(&self.output_spool),
            other => Err(failure(
                operation,
                EffectCertainty::NotApplied,
                format!(
                    "the plan committed a Landlock scope for {other}, which is not one of the \
                     {LINUX_CONTAINED_RELEASE_SCOPE_ROLE_COUNT} roles this service holds a \
                     descriptor for"
                ),
            )),
        }
    }

    /// The execution root's own retained descriptor, duplicated for a release.
    ///
    /// A contained command's working directory must be one of the scopes its
    /// ruleset grants — `validate_contained_command` refuses otherwise — and the
    /// execution root is the scope that exists for exactly that purpose.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the descriptor cannot be duplicated, and
    /// when the duplicate's identity is not the one the plan's object table
    /// committed for the execution root.
    pub(crate) fn authenticated_execution_root(
        &self,
    ) -> Result<AuthenticatedReleaseDescriptor, CgroupIoFailure> {
        const OPERATION: &str = "mint-linux-contained-release-working-directory";

        let duplicate = self.execution_root.try_clone().map_err(|error| {
            io_failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!("duplicate the retained execution-root descriptor: {error}"),
            )
        })?;
        let (device_id, inode) = retained_descriptor_identity(&duplicate, OPERATION)?;
        let committed = self.identities.execution_root().kernel_observation();
        if device_id != committed.device_id || inode != committed.inode {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!(
                    "the duplicated execution-root descriptor answers {device_id}/{inode} while \
                     the plan's object table committed {}/{}",
                    committed.device_id, committed.inode
                ),
            ));
        }
        Ok(AuthenticatedReleaseDescriptor::new(
            duplicate.into_std_file(),
            LauncherDescriptorIdentity {
                device: device_id,
                inode,
            },
        ))
    }
}

/// Requires the committed denial witness to still be the object it names.
///
/// The witness is what makes the ruleset a policy rather than a formality: the
/// launcher opens it after `restrict_self` and requires `EACCES`. If it were
/// allowed to drift onto a granted scope, or onto an object the compiled runtime
/// allowlist grants, the denial proof would be vacuous — so its identity is
/// checked here against what the plan committed, before the release is built.
#[cfg(target_os = "linux")]
fn require_committed_denial_witness(
    witness: &LinuxLandlockDenialWitnessV1,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let observed = rustix::fs::stat(Path::new(&witness.resolved_path)).map_err(|error| {
        io_failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "observe the committed denial witness {}: {error}",
                witness.resolved_path
            ),
        )
    })?;
    if observed.st_dev != witness.device_id || observed.st_ino != witness.inode {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "the committed denial witness {} answers {}/{} while the plan's ruleset committed \
                 {}/{}",
                witness.resolved_path,
                observed.st_dev,
                observed.st_ino,
                witness.device_id,
                witness.inode
            ),
        ));
    }
    Ok(())
}

/// Seals one command's target binary into an `MFD_EXEC` memfd.
///
/// This is the command-target counterpart of the sealed **service** image.
/// `ExecutableImageType` has exactly one variant, `SealedMemfd`, so a contained
/// command's target cannot be a named file: it is copied under a hash into an
/// anonymous, execute-capable memfd and sealed shut, and the release carries the
/// descriptor rather than any path.
///
/// The sequence is the one the service image and the canary image already use,
/// and it is ordered for a reason: create, copy under the hash, set the mode,
/// apply the exact seal set, then read the seals back and re-hash the sealed
/// bytes. Hashing only while the memfd is still writable would measure something
/// that could still change, and reading the seals back is what makes "sealed" an
/// observation rather than a request.
///
/// The caller passes the digest it expects, which is the plan's commitment to
/// which binary this command runs. A source that changed between the plan's
/// measurement and this seal is refused here — the substitution the whole
/// descriptor discipline exists to catch.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the memfd cannot be created, when the source
/// cannot be read, when it is empty or exceeds the image bound, when the mode or
/// seals cannot be applied, when the kernel does not report back the exact
/// required seal set, when the sealed bytes differ from the copied bytes, and
/// when the sealed digest is not `expected_content_sha256`.
#[cfg(target_os = "linux")]
pub(crate) fn seal_contained_command_target(
    source: &mut std::fs::File,
    expected_content_sha256: &Digest,
) -> Result<AuthenticatedExecutableDescriptor, CgroupIoFailure> {
    const OPERATION: &str = "seal-linux-contained-command-target";
    // The launcher's own hard image bound, restated so an oversized target is
    // refused while it is being copied rather than after the whole image has
    // been pulled into memory.
    const MAX_TARGET_BYTES: u64 = 128 * 1_024 * 1_024;

    let descriptor = rustix::fs::memfd_create(
        "grok-build-linux-contained-command-target-v1",
        rustix::fs::MemfdFlags::CLOEXEC
            | rustix::fs::MemfdFlags::ALLOW_SEALING
            | rustix::fs::MemfdFlags::EXEC,
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let mut image = std::fs::File::from(descriptor);

    let mut streamed = Sha256::new();
    let mut buffer = [0_u8; 16 * 1_024];
    let mut length = 0_u64;
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        if count == 0 {
            break;
        }
        length += u64::try_from(count).unwrap_or(u64::MAX);
        if length > MAX_TARGET_BYTES {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!("the command target exceeds the {MAX_TARGET_BYTES}-byte image bound"),
            ));
        }
        streamed.update(&buffer[..count]);
        image
            .write_all(&buffer[..count])
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    }
    if length == 0 {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the command target copied zero bytes, so there is nothing to seal or execute",
        ));
    }

    rustix::fs::fchmod(&image, rustix::fs::Mode::from_bits_truncate(0o500))
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let required = rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::FUTURE_WRITE
        | rustix::fs::SealFlags::EXEC;
    rustix::fs::fcntl_add_seals(&image, required)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let observed_seals = rustix::fs::fcntl_get_seals(&image)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    if observed_seals != required {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the sealed command target did not retain the exact required seal set",
        ));
    }

    // Re-hash what is now immutable rather than trusting the digest taken while
    // the memfd could still be written. The two must agree, and it is the
    // sealed read that is compared against the plan.
    let sealed = sealed_target_digest(&mut image, length, OPERATION)?;
    let copied = Digest::parse(hex_digest(streamed.finalize().into())).map_err(|error| {
        failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!("the copied command target's digest is not canonical: {error}"),
        )
    })?;
    if sealed != copied {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the sealed command target's bytes differ from the bytes copied into it",
        ));
    }
    if &sealed != expected_content_sha256 {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the sealed command target digests to {sealed} while the plan committed {expected_content_sha256}"
            ),
        ));
    }

    let observed = rustix::fs::fstat(&image)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    Ok(AuthenticatedExecutableDescriptor::new(
        image,
        LauncherDescriptorIdentity {
            device: observed.st_dev,
            inode: observed.st_ino,
        },
        sealed.as_str().to_owned(),
    ))
}

/// Reads a sealed image back from offset zero and digests exactly its length.
#[cfg(target_os = "linux")]
fn sealed_target_digest(
    image: &mut std::fs::File,
    byte_length: u64,
    operation: &'static str,
) -> Result<Digest, CgroupIoFailure> {
    image
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1_024];
    let mut remaining = byte_length;
    while remaining > 0 {
        let want = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        let count = image
            .read(&mut buffer[..want])
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        if count == 0 {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "the sealed command target ended before its own reported length",
            ));
        }
        hasher.update(&buffer[..count]);
        remaining -= u64::try_from(count).unwrap_or(remaining);
    }
    Digest::parse(hex_digest(hasher.finalize().into())).map_err(|error| {
        failure(
            operation,
            EffectCertainty::NotApplied,
            format!("the sealed command target's digest is not canonical: {error}"),
        )
    })
}

/// Canonical lowercase hexadecimal for one SHA-256 result.
#[cfg(target_os = "linux")]
fn hex_digest(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

// Installation writes the external anchor under the installer identity;
// opening independently authenticates it under the distinct runner identity.

/// Exact internal mode argument for the installer half.
pub const LINUX_NATIVE_SERVICE_INSTALL_ARGUMENT: &str = "--grok-build-install-linux-native-service";

/// Exact internal mode argument for the service half.
pub const LINUX_NATIVE_SERVICE_OPEN_ARGUMENT: &str = "--grok-build-open-linux-native-service";

/// Exit code both modes use for a refusal.
///
/// Not zero, and not any code a composed service would produce, so a caller can
/// tell "the installation refused" from "the service refused" from "it worked".
#[cfg(target_os = "linux")]
const LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE: u8 = 78;

/// Installs the native-service handoff when the exact internal mode argument is
/// present.
///
/// This is the host modification a package's post-install step owes: delegate
/// the cgroup, enable `+memory +pids` on it, give the runner its private state
/// root, and commit the resulting identities to a file the runner cannot write.
/// It grants no authority to this process and runs no command.
///
/// Arguments, in order: installer root, service state root, service cgroup
/// parent, delegation name, runner uid, runner gid, delegation mode (octal),
/// and the expected SHA-256 of the runner image being installed.
///
/// The digest is supplied rather than computed here on purpose. The installer
/// is committing to *which* runner image it is installing; computing it from
/// this process would commit the installer to itself.
#[doc(hidden)]
#[must_use]
pub fn run_linux_native_service_installer_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(LINUX_NATIVE_SERVICE_INSTALL_ARGUMENT) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(run_native_service_installer(arguments))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(arguments);
        Some(std::process::ExitCode::from(78))
    }
}

/// Opens the installed native-service handoff when the exact internal mode
/// argument is present.
///
/// Takes one argument: the installer root the anchor was written under. Every
/// identity, mode, link count, mount id and digest in that anchor is
/// re-observed from the live filesystem and required to match what the
/// installer committed; nothing here trusts the file's contents on their own.
///
/// This grants no authority to this process and runs no command. It reports
/// what it authenticated so an operator -- or a measurement -- can see that the
/// installer boundary holds across two identities and two processes.
#[doc(hidden)]
#[must_use]
pub fn run_linux_native_service_open_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(LINUX_NATIVE_SERVICE_OPEN_ARGUMENT) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(run_native_service_open(arguments))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(arguments);
        Some(std::process::ExitCode::from(78))
    }
}

#[cfg(target_os = "linux")]
fn next_argument(
    arguments: &mut std::env::ArgsOs,
    name: &str,
) -> Result<String, std::process::ExitCode> {
    arguments
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            eprintln!("linux native-service mode requires a {name} argument");
            std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE)
        })
}

#[cfg(target_os = "linux")]
fn run_native_service_installer(mut arguments: std::env::ArgsOs) -> std::process::ExitCode {
    let parsed = (|| {
        let installer_root = next_argument(&mut arguments, "installer root")?;
        let service_state_root_path = next_argument(&mut arguments, "service state root")?;
        let service_cgroup_parent_path = next_argument(&mut arguments, "service cgroup parent")?;
        let delegation_name = next_argument(&mut arguments, "delegation name")?;
        let owner_ids = (
            next_argument(&mut arguments, "runner uid")?,
            next_argument(&mut arguments, "runner gid")?,
        );
        let delegation_mode = next_argument(&mut arguments, "delegation mode")?;
        let digest = next_argument(&mut arguments, "runner image digest")?;
        Ok((
            installer_root,
            service_state_root_path,
            service_cgroup_parent_path,
            delegation_name,
            owner_ids,
            delegation_mode,
            digest,
        ))
    })();
    let (
        installer_root,
        service_state_root_path,
        service_cgroup_parent_path,
        delegation_name,
        owner_ids,
        delegation_mode,
        digest,
    ) = match parsed {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };

    // Parsed as a pair so the two never exist as separate look-alike bindings;
    // `runner_uid` and `runner_gid` differ by one character and this is the one
    // place a transposition would be silent.
    let (Ok(owning_user), Ok(owning_group)) =
        (owner_ids.0.parse::<u32>(), owner_ids.1.parse::<u32>())
    else {
        eprintln!("runner uid and gid must both be unsigned integers");
        return std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE);
    };
    let Ok(delegation_mode) = u32::from_str_radix(&delegation_mode, 8) else {
        eprintln!("delegation mode must be octal");
        return std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE);
    };
    let digest = match Digest::parse(digest) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("runner image digest is not a canonical SHA-256: {error}");
            return std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE);
        }
    };

    let request = LinuxNativeServiceInstallRequestV1 {
        installer_root: &installer_root,
        service_state_root_path: &service_state_root_path,
        service_cgroup_parent_path: &service_cgroup_parent_path,
        delegation_name: &delegation_name,
        runner_uid: owning_user,
        runner_gid: owning_group,
        delegation_mode,
        authenticated_platform_service_digest: digest,
    };
    match install_linux_native_service_handoff(&request) {
        Ok(receipt) => {
            println!(
                "installed anchor={} identity={:?} bytes={} sha256={}",
                receipt.anchor_absolute_path,
                receipt.anchor_identity,
                receipt.anchor_byte_length,
                receipt.anchor_sha256.as_str(),
            );
            std::process::ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!(
                "install refused at {} ({:?}): {}",
                failure.operation, failure.certainty, failure.detail
            );
            std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_native_service_open(mut arguments: std::env::ArgsOs) -> std::process::ExitCode {
    let installer_root = match next_argument(&mut arguments, "installer root") {
        Ok(root) => root,
        Err(code) => return code,
    };
    match open_installed_linux_native_service_handoff(&installer_root) {
        Ok((handoff, evidence)) => {
            // The evidence is what the runner re-observed, not what the anchor
            // claimed. Printing both the anchor's own identity and the
            // delegation readback makes the two independently checkable.
            println!(
                "opened anchor={} identity={:?} mount={} owner={} mode={:o} links={} bytes={} sha256={}",
                evidence.anchor_absolute_path,
                evidence.anchor_identity,
                evidence.anchor_mount_id,
                evidence.anchor_owner_uid,
                evidence.anchor_mode,
                evidence.anchor_link_count,
                evidence.anchor_byte_length,
                evidence.anchor_sha256.as_str(),
            );
            println!(
                "delegation subtree_control={:?}",
                evidence.delegation_subtree_control_readback,
            );
            // The handoff itself is deliberately not printed: it holds open
            // descriptors and an installation commitment, and a mode that
            // reports what it authenticated must not also become a way to read
            // that out. Dropping it here also proves the open path leaves no
            // lock or descriptor behind.
            drop(handoff);
            std::process::ExitCode::SUCCESS
        }
        Err(failure) => {
            eprintln!(
                "open refused at {} ({:?}): {}",
                failure.operation, failure.certainty, failure.detail
            );
            std::process::ExitCode::from(LINUX_NATIVE_SERVICE_MODE_REFUSAL_CODE)
        }
    }
}

/// Everything one contained command needs from its caller to be composed onto
/// a live installed native service.
///
/// Every field is something the session path already holds: the installer root
/// it was configured with, the effect authority and identity the desktop's
/// claim carries, and the grant and policy the command was admitted under. The
/// composition invents none of them.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxInstalledServiceCommandInputs<'a> {
    /// The directory the installer wrote its anchor into.
    pub(crate) installer_root: &'a str,
    /// The grant's workspace root, as an absolute path. It is re-walked one
    /// `O_NOFOLLOW` component at a time rather than trusted as a string.
    pub(crate) workspace_root_path: &'a str,
    /// This command's private directory name under the service's per-command
    /// retained root. It must be a domain-leaf-shaped name.
    pub(crate) command_directory_name: &'a str,
    /// The absolute path of the binary this command runs.
    pub(crate) target_executable_path: &'a str,
    pub(crate) authority: crate::wire::CommandEffectAuthorityV1,
    pub(crate) grant: &'a grok_build_core::IssuedWorkspaceGrant,
    pub(crate) policy: &'a grok_build_core::CompiledExecutionPolicy,
    pub(crate) native_launch: crate::linux_containment::LinuxNativeLaunchIdentity,
    pub(crate) role: crate::wire::RunnerRole,
}
