// Clone the held `.git` mask with `open_tree` before unsharing the mount
// namespace; cloning a descriptor retained across unshare returns EINVAL.
// Attach the detached mount by descriptor with `move_mount`, then verify
// its unique mount ID and the original directory's inode and metadata.
// Cloning requires CAP_SYS_ADMIN; missing authority is a refusal.

/// One `.git` mask mount the service has cloned and can hand on.
///
/// The descriptor is the authority. The binding beside it is what a later
/// reader compares a destination against, and it is minted from a read taken
/// **through this descriptor**, not from the directory the clone came from.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct LinuxRetainedGitMaskMount {
    mount: std::os::fd::OwnedFd,
    observation: LinuxGitMaskEmptyDirectoryObservationV1,
    binding: LinuxGitMaskMountBindingV1,
}

#[cfg(target_os = "linux")]
impl LinuxRetainedGitMaskMount {
    /// The binding a destination observation is checked against.
    pub(crate) const fn binding(&self) -> &LinuxGitMaskMountBindingV1 {
        &self.binding
    }

    /// The complete read taken through the detached mount's own descriptor.
    pub(crate) const fn observation(&self) -> &LinuxGitMaskEmptyDirectoryObservationV1 {
        &self.observation
    }

    /// The detached mount descriptor itself.
    pub(crate) const fn descriptor(&self) -> &std::os::fd::OwnedFd {
        &self.mount
    }
}

#[cfg(target_os = "linux")]
impl LinuxRetainedPerCommandDirectories {
    /// Clones the `.git` mask into a detached mount, through the descriptor
    /// this command already holds on it.
    ///
    /// The source of the clone is the held descriptor and the empty path with
    /// `AT_EMPTY_PATH`: there is no name for anything to have changed the
    /// meaning of. What comes back is a real mount, the kernel answers a new
    /// `STATX_MNT_ID_UNIQUE` for it, whose root dentry is the very directory
    /// `mask` digested.
    ///
    /// The clone is then **read through its own descriptor** and that read,
    /// not the directory's, is what the returned binding commits to. That is
    /// the whole point: the thing that will be attached is the thing that was
    /// measured.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when `open_tree` refuses, `EPERM` without
    /// `CAP_SYS_ADMIN` is a refusal, not an absence, when the detached mount
    /// cannot be read completely, and on every refusal
    /// [`LinuxGitMaskMountBindingV1::from_cloned_mount_observation`] makes.
    pub(crate) fn clone_git_mask_mount(
        &self,
        mask: &LinuxGitMaskV1,
    ) -> Result<LinuxRetainedGitMaskMount, CgroupIoFailure> {
        let operation = "clone-linux-git-mask-mount";
        let mount = rustix::mount::open_tree(
            &self.git_mask,
            "",
            rustix::mount::OpenTreeFlags::AT_EMPTY_PATH
                | rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
                | rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )
        .map_err(|error| {
            io_failure(
                operation,
                EffectCertainty::NotApplied,
                format!(
                    "open_tree could not clone the .git mask through its held descriptor: {error}"
                ),
            )
        })?;
        let observation = observe_detached_mount_root(&mount, operation)?;
        let binding = LinuxGitMaskMountBindingV1::from_cloned_mount_observation(
            mask,
            self.identities.git_mask(),
            self.identities.git_mask_observation(),
            &observation,
        )
        .map_err(|error| plan_mint_failure(operation, &error))?;
        Ok(LinuxRetainedGitMaskMount {
            mount,
            observation,
            binding,
        })
    }
}

/// One `.git` mask mount that has been attached and then recognised at its
/// destination.
///
/// It exists only as the result of [`attach_git_mask_mount`], so holding one
/// is the statement that a destination was read after the mount and matched
/// the binding. It carries no descriptor and grants nothing.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub(crate) struct LinuxAttachedGitMaskMount {
    binding: LinuxGitMaskMountBindingV1,
    destination: LinuxGitMaskEmptyDirectoryObservationV1,
}

#[cfg(target_os = "linux")]
impl LinuxAttachedGitMaskMount {
    /// The binding the destination was required to satisfy.
    pub(crate) const fn binding(&self) -> &LinuxGitMaskMountBindingV1 {
        &self.binding
    }

    /// The complete read taken at the destination after the mount.
    pub(crate) const fn destination(&self) -> &LinuxGitMaskEmptyDirectoryObservationV1 {
        &self.destination
    }
}

/// Attaches a cloned `.git` mask through a retained destination directory.
/// `move_mount` uses the source descriptor; readback through the same parent
/// must match the committed unique mount identity and remain empty.
///
/// Consumes the mount because attaching it a second time would move it away
/// from the first destination.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] for a refused mount, incomplete readback or a
/// [`LinuxGitMaskMountBindingV1::require_attached_mount`] mismatch. Failures after
/// `move_mount` succeeds carry [`EffectCertainty::Ambiguous`] because the mount
/// has already changed the namespace.
#[cfg(target_os = "linux")]
pub(crate) fn attach_git_mask_mount(
    mask_mount: LinuxRetainedGitMaskMount,
    destination_parent: &Dir,
) -> Result<LinuxAttachedGitMaskMount, CgroupIoFailure> {
    let operation = "attach-linux-git-mask-mount";
    rustix::mount::move_mount(
        &mask_mount.mount,
        "",
        destination_parent,
        GIT_MASK_DESTINATION_COMPONENT,
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(|error| {
        io_failure(
            operation,
            EffectCertainty::NotApplied,
            format!("move_mount could not attach the cloned .git mask mount: {error}"),
        )
    })?;
    let destination = destination_parent
        .open_dir_nofollow(GIT_MASK_DESTINATION_COMPONENT)
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
        .and_then(|attached| {
            observe_empty_git_mask_directory(&attached, operation).map_err(mounted_and_then_failed)
        })?;
    mask_mount
        .binding
        .require_attached_mount(&destination)
        .map_err(|error| mounted_and_then_failed(plan_mint_failure(operation, &error)))?;
    Ok(LinuxAttachedGitMaskMount {
        binding: mask_mount.binding,
        destination,
    })
}

/// Re-states a refusal that happened **after** the mount was performed.
///
/// The observation helpers report [`EffectCertainty::NotApplied`], which is
/// right when nothing has happened yet and wrong once `move_mount` has
/// returned: at that point a mount really is attached at the destination, and
/// a caller told "not applied" would clean up as if the namespace were
/// untouched.
#[cfg(target_os = "linux")]
fn mounted_and_then_failed(failure: CgroupIoFailure) -> CgroupIoFailure {
    CgroupIoFailure {
        certainty: EffectCertainty::Ambiguous,
        ..failure
    }
}

/// Reads the root of a detached mount completely, through the descriptor
/// `open_tree` returned.
///
/// `open_tree` hands back an `O_PATH`-style descriptor, which cannot be
/// enumerated directly, the same constraint `cap-std`'s directory descriptors
/// impose, and the reason [`chmod_held_directory`] exists. `"."` relative to
/// that descriptor cannot be a symlink and cannot name another object, so
/// reopening it is not a path re-resolution: it is the same mount root, opened
/// readable. Every read after that is the identical five-read observation
/// [`observe_empty_git_mask_directory`] performs on any other directory, which
/// is what lets the clone and the destination be compared byte for byte.
#[cfg(target_os = "linux")]
fn observe_detached_mount_root(
    mount: &std::os::fd::OwnedFd,
    operation: &'static str,
) -> Result<LinuxGitMaskEmptyDirectoryObservationV1, CgroupIoFailure> {
    let readable = rustix::fs::openat(
        mount,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        io_failure(
            operation,
            EffectCertainty::NotApplied,
            format!("the detached .git mask mount root could not be opened readable: {error}"),
        )
    })?;
    let directory = Dir::from_std_file(std::fs::File::from(readable));
    observe_empty_git_mask_directory(&directory, operation)
}

// Execute the retained Bubblewrap descriptor with an empty environment. Its
// bounded self-report is crossed with the independently authenticated image
// and planned package version; it never chooses its own verdict.

/// Longest self-reported version line the probe will accept.
///
/// `bwrap --version` answers one short line. A bound exists so a replaced or
/// wrapped image cannot stream unbounded output into evidence that is then
/// persisted; it is deliberately far above any real answer and far below
/// [`MAX_SERVICE_BOOTSTRAP_BYTES`].
#[cfg(target_os = "linux")]
const MAX_BUBBLEWRAP_VERSION_STDOUT_BYTES: usize = 256;

/// Domain separator for the Bubblewrap probe's result commitment.
///
/// The result digest commits to what this run of the probe actually observed,
/// the exit status and the exact stdout bytes, so it is a measurement of the
/// run rather than a restatement of the contract constant, which is what
/// [`BUBBLEWRAP_BOOTSTRAP_PROBE_CONTRACT`] already commits to separately.
#[cfg(target_os = "linux")]
const BUBBLEWRAP_VERSION_PROBE_RESULT_DOMAIN: &[u8] =
    b"grok-build/linux-bubblewrap-bootstrap-probe-result/v1\0";

/// Executes the retained Bubblewrap image and reports what it says it is.
///
/// `bubblewrap` must be the descriptor a
/// [`LinuxNativeServiceBootstrapCapabilities`] already retains and has
/// validated against the plan's inode identity, mode, length and whole-content
/// digest. The image is executed through that descriptor's own
/// `/proc/self/fd/<n>` name, so no directory component is resolved again
/// between the content check and the execution.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the image cannot be executed at all, when
/// it exits non-zero or is signalled, when it writes anything to stderr, or
/// when its stdout is empty, oversized, not UTF-8, not terminated by exactly
/// one line feed, or carries a byte outside the printable ASCII range the
/// plan's own version bound admits. Every one of those is a refusal: an
/// unreadable answer is not evidence of a good one.
#[cfg(target_os = "linux")]
fn probe_retained_bubblewrap_version(
    bubblewrap: &File,
) -> Result<LinuxBubblewrapBootstrapProbeV1, CgroupIoFailure> {
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::process::{Command, Stdio};

    const OPERATION: &str = "probe-bootstrap-bubblewrap-version";

    let held_name = format!("/proc/self/fd/{}", bubblewrap.as_fd().as_raw_fd());
    let output = Command::new(&held_name)
        .arg("--version")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    if output.status.code() != Some(0) {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the retained Bubblewrap image did not report its version cleanly: {}",
                output.status
            ),
        ));
    }
    if !output.stderr.is_empty() {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained Bubblewrap image wrote to stderr while reporting its version",
        ));
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_BUBBLEWRAP_VERSION_STDOUT_BYTES {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained Bubblewrap image's version output is empty or outside its byte bound",
        ));
    }
    let version_stdout = String::from_utf8(output.stdout).map_err(|_| {
        failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained Bubblewrap image's version output is not UTF-8",
        )
    })?;
    let Some(line) = version_stdout.strip_suffix('\n') else {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained Bubblewrap image's version output is not one line-feed-terminated line",
        ));
    };
    if line.is_empty()
        || !line
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained Bubblewrap image's version output is empty or not printable ASCII text",
        ));
    }
    let mut preimage = Vec::with_capacity(
        BUBBLEWRAP_VERSION_PROBE_RESULT_DOMAIN.len()
            + std::mem::size_of::<u64>()
            + version_stdout.len(),
    );
    preimage.extend_from_slice(BUBBLEWRAP_VERSION_PROBE_RESULT_DOMAIN);
    preimage.extend_from_slice(&(version_stdout.len() as u64).to_be_bytes());
    preimage.extend_from_slice(version_stdout.as_bytes());
    Ok(LinuxBubblewrapBootstrapProbeV1 {
        version_stdout_sha256: Digest::sha256(version_stdout.as_bytes()),
        version_stdout,
        active_probe_contract_digest: Digest::sha256(BUBBLEWRAP_BOOTSTRAP_PROBE_CONTRACT),
        active_probe_result_digest: Digest::sha256(&preimage),
        // The probe completed and the image answered. This is deliberately not
        // "the answer was the planned one": that comparison belongs to
        // `validate_service_bootstrap_evidence` and is left there.
        active_probe_passed: true,
    })
}

// The active probe creates an empty leaf, exercises both resource controllers
// and cgroup.kill, then removes it. Passive control-file reads alone are not
// sufficient evidence that the service can use its delegation.
const CGROUP_BOOTSTRAP_PROBE_RESULT_DOMAIN: &[u8] =
    b"grok-build/linux-cgroup-bootstrap-probe-result/v2\0";

/// Name prefix of the transient leaf the active probe creates.
#[cfg(target_os = "linux")]
const CGROUP_BOOTSTRAP_PROBE_LEAF_PREFIX: &str = "gbd-bootstrap-probe-";

/// The exact `pids.max` value the probe writes and requires back.
///
/// A distinctive small number rather than `max`: `max` is the value a fresh
/// leaf already carries, so writing it and reading it back would pass on a
/// delegation the service cannot write at all. This value is only readable
/// because this probe put it there.
#[cfg(target_os = "linux")]
const CGROUP_BOOTSTRAP_PROBE_PIDS_MAX: &[u8] = b"7\n";

/// The `memory.max` value a freshly created leaf carries.
#[cfg(target_os = "linux")]
const CGROUP_BOOTSTRAP_PROBE_FRESH_MEMORY_MAX: &[u8] = b"max\n";

/// Largest control-file readback the active probe accepts from its leaf.
#[cfg(target_os = "linux")]
const MAX_CGROUP_BOOTSTRAP_PROBE_READBACK_BYTES: usize = 256;

/// Stable measurements plus the transient leaf name used for cleanup.
struct LinuxDelegatedCgroupActiveProbeMeasurement {
    leaf_name: String,
    leaf_controllers: Vec<u8>,
    pids_max_readback: Vec<u8>,
    memory_max_readback: Vec<u8>,
}

fn cgroup_bootstrap_probe_result_digest(
    measurement: &LinuxDelegatedCgroupActiveProbeMeasurement,
) -> Digest {
    let LinuxDelegatedCgroupActiveProbeMeasurement {
        leaf_name: _,
        leaf_controllers,
        pids_max_readback,
        memory_max_readback,
    } = measurement;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(CGROUP_BOOTSTRAP_PROBE_RESULT_DOMAIN);
    // The PID-derived leaf name prevents collision but is not service identity.
    for field in [
        leaf_controllers.as_slice(),
        pids_max_readback.as_slice(),
        memory_max_readback.as_slice(),
    ] {
        preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
        preimage.extend_from_slice(field);
    }
    Digest::sha256(&preimage)
}

/// Reads the retained delegation and proves the service can really use it.
///
/// `delegation`, `controllers`, `subtree_control` and `cgroup_procs` are the
/// descriptors a [`LinuxNativeServiceBootstrapCapabilities`] already retains.
/// Every read here goes through those descriptors or through `delegation`
/// itself; no path is resolved a second time and no ambient cgroup root is
/// consulted.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the retained delegation is not a cgroup-v2
/// directory, when any readback is oversized or not UTF-8, or when the active
/// probe cannot create a leaf, does not find the controllers the leaf must
/// carry, cannot write and read back the limit, cannot exercise `cgroup.kill`,
/// finds a process inside its own leaf, or cannot remove the leaf again. Each
/// of those is a refusal: a delegation that cannot be used is not a delegation.
#[cfg(target_os = "linux")]
fn probe_delegated_cgroup(
    delegation: &Dir,
    delegation_name: &str,
    controllers: &File,
    subtree_control: &File,
    cgroup_procs: &File,
) -> Result<LinuxCgroupBootstrapReadbackV1, CgroupIoFailure> {
    const OPERATION: &str = "probe-bootstrap-delegated-cgroup";

    if filesystem_magic(delegation)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the retained bootstrap delegation is not a cgroup-v2 directory",
        ));
    }

    let identity = |file: &File| -> Result<CgroupObjectIdentity, CgroupIoFailure> {
        let metadata = file
            .metadata()
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        if !metadata.is_file() {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "a retained delegation control file is not a regular file",
            ));
        }
        Ok(cgroup_identity(object_identity(&metadata)))
    };
    let text = |file: &File| -> Result<String, CgroupIoFailure> {
        let bytes = read_retained_bootstrap_file(
            file,
            MAX_BOOTSTRAP_READBACK_BYTES,
            "readback-bootstrap-delegation",
        )?;
        String::from_utf8(bytes).map_err(|_| {
            failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "a retained delegation control readback is not UTF-8",
            )
        })
    };

    let controllers_file_identity = identity(controllers)?;
    let subtree_control_file_identity = identity(subtree_control)?;
    let cgroup_procs_file_identity = identity(cgroup_procs)?;
    let controllers_readback = text(controllers)?;
    let subtree_control_readback = text(subtree_control)?;
    let cgroup_procs_readback = text(cgroup_procs)?;

    let measurement = probe_delegated_cgroup_leaf(delegation)?;

    Ok(LinuxCgroupBootstrapReadbackV1 {
        delegation_component: delegation_name.to_owned(),
        controllers_file_identity,
        subtree_control_file_identity,
        cgroup_procs_file_identity,
        controllers_readback_sha256: Digest::sha256(controllers_readback.as_bytes()),
        controllers_readback,
        subtree_control_readback_sha256: Digest::sha256(subtree_control_readback.as_bytes()),
        subtree_control_readback,
        cgroup_procs_readback_sha256: Digest::sha256(cgroup_procs_readback.as_bytes()),
        cgroup_procs_readback,
        active_probe_contract_digest: Digest::sha256(CGROUP_BOOTSTRAP_PROBE_CONTRACT),
        active_probe_result_digest: cgroup_bootstrap_probe_result_digest(&measurement),
        // The probe completed: a leaf really was created, carried the required
        // controllers, took a limit the kernel echoed back, accepted
        // `cgroup.kill`, held no process, and was removed. Whether those facts
        // bind the *plan* is `validate_service_bootstrap_evidence`'s decision
        // and is deliberately left there.
        active_probe_passed: true,
    })
}

/// The active half: create a leaf, use it, prove it is empty, remove it.
///
/// The leaf is removed on every path, including every refusal, so a probe that
/// fails halfway does not leave a cgroup behind for the next attempt to trip
/// over.
#[cfg(target_os = "linux")]
fn probe_delegated_cgroup_leaf(
    delegation: &Dir,
) -> Result<LinuxDelegatedCgroupActiveProbeMeasurement, CgroupIoFailure> {
    const OPERATION: &str = "probe-bootstrap-delegated-cgroup";

    let leaf_name = format!("{CGROUP_BOOTSTRAP_PROBE_LEAF_PREFIX}{}", std::process::id());
    validate_component("bootstrap cgroup probe leaf", &leaf_name)?;
    match delegation.create_dir(&leaf_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // A leaf left by an earlier attempt of this same process. It is
            // removed rather than reused, so the measurement below is always of
            // a cgroup this call created.
            delegation.remove_dir(&leaf_name).map_err(|removal| {
                failure(
                    OPERATION,
                    EffectCertainty::NotApplied,
                    format!("a stale bootstrap probe leaf could not be removed: {removal}"),
                )
            })?;
            delegation
                .create_dir(&leaf_name)
                .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
        }
        Err(error) => {
            return Err(io_failure(OPERATION, EffectCertainty::NotApplied, error));
        }
    }

    let measured = probe_created_cgroup_leaf(delegation, &leaf_name);
    let removed = delegation.remove_dir(&leaf_name).map_err(|error| {
        failure(
            OPERATION,
            EffectCertainty::Ambiguous,
            format!("the bootstrap probe leaf could not be removed: {error}"),
        )
    });
    match (measured, removed) {
        (Ok(measured), Ok(())) => Ok(measured),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(removal)) => Err(failure(
            OPERATION,
            EffectCertainty::Ambiguous,
            format!(
                "delegated-cgroup probe failed: {}; leaf removal also failed: {}",
                primary.detail, removal.detail
            ),
        )),
    }
}

#[cfg(target_os = "linux")]
fn probe_created_cgroup_leaf(
    delegation: &Dir,
    leaf_name: &str,
) -> Result<LinuxDelegatedCgroupActiveProbeMeasurement, CgroupIoFailure> {
    const OPERATION: &str = "probe-bootstrap-delegated-cgroup";

    let leaf = delegation
        .open_dir_nofollow(leaf_name)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    if filesystem_magic(&leaf)? != CGROUP2_SUPER_MAGIC {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the created bootstrap probe leaf is not a cgroup-v2 directory",
        ));
    }

    // What the delegation's own `cgroup.subtree_control` actually granted its
    // children. An empty file here is the signature of a directory that is a
    // cgroup but not a usable delegation: the parent enabled nothing, so the
    // leaf carries no controller interface files at all.
    let leaf_controllers = read_control_file(
        &leaf,
        DelegationFile::Controllers.name(),
        MAX_CGROUP_BOOTSTRAP_PROBE_READBACK_BYTES,
    )?;
    if leaf_controllers.is_empty() {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the delegated cgroup enables no controller for its children",
        ));
    }
    let available = parse_controller_set(&leaf_controllers, false)?;
    let required = BTreeSet::from([DomainController::Memory, DomainController::Pids]);
    if !required.is_subset(&available) {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "a leaf of the delegated cgroup does not carry the memory and pids controllers",
        ));
    }

    // A write the kernel must echo back. This is the step a merely visible
    // directory cannot pass.
    write_control_file(
        &leaf,
        LeafWriteFile::PidsMax.name(),
        CGROUP_BOOTSTRAP_PROBE_PIDS_MAX,
    )?;
    let pids_max_readback = read_control_file(
        &leaf,
        LeafWriteFile::PidsMax.name(),
        MAX_CGROUP_BOOTSTRAP_PROBE_READBACK_BYTES,
    )?;
    if pids_max_readback != CGROUP_BOOTSTRAP_PROBE_PIDS_MAX {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the delegated cgroup leaf did not read back the exact written pids.max",
        ));
    }

    let memory_max_readback = read_control_file(
        &leaf,
        LeafWriteFile::MemoryMax.name(),
        MAX_CGROUP_BOOTSTRAP_PROBE_READBACK_BYTES,
    )?;
    if memory_max_readback != CGROUP_BOOTSTRAP_PROBE_FRESH_MEMORY_MAX {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "a freshly created delegated cgroup leaf does not report an unbounded memory.max",
        ));
    }

    // `cgroup.kill` is the control the domain teardown depends on. It is
    // exercised here on an empty leaf, where it kills nothing, so that a
    // kernel that does not implement it is found at bootstrap rather than at
    // the first teardown.
    write_control_file(&leaf, LeafWriteFile::CgroupKill.name(), b"1\n")?;

    let procs = read_control_file(&leaf, LeafFile::CgroupProcs.name(), MAX_CGROUP_PROCS_BYTES)?;
    if !procs.is_empty() {
        return Err(failure(
            OPERATION,
            EffectCertainty::Ambiguous,
            "the bootstrap probe leaf is not empty and must not be removed",
        ));
    }

    Ok(LinuxDelegatedCgroupActiveProbeMeasurement {
        leaf_name: leaf_name.to_owned(),
        leaf_controllers,
        pids_max_readback,
        memory_max_readback,
    })
}

// Run closed probe modes in separate children: confinement is irreversible
// and the parent must observe termination. Use committed artifacts for every
// probe; no unenforced production arm is admitted.

/// Exact internal mode argument of the Linux service-bootstrap probe process.
pub(crate) const LINUX_SERVICE_BOOTSTRAP_PROBE_ARGUMENT: &str =
    "--grok-build-linux-service-bootstrap-probe-v1";

/// Schema version of the canonical probe report.
const LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_VERSION: u32 = 2;

/// Largest report the controller will read back from a probe process.
///
/// It grew with the report: a ruleset may grant up to
/// [`MAX_LINUX_LANDLOCK_SCOPES`] scopes and the child reports the kernel's
/// identity for every one of them.
const MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_BYTES: usize = 16_384;

/// Largest committed artefact the controller will hand a probe process.
const MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_ARTEFACT_BYTES: usize = 16_384;

/// The probe process mode that installs a Landlock ruleset on itself.
const LANDLOCK_BOOTSTRAP_PROBE_MODE: &str = "landlock";

/// The probe process mode that installs a seccomp filter on itself.
const SECCOMP_BOOTSTRAP_PROBE_MODE: &str = "seccomp";

/// Invoke the syscall the installed filter kills.
const SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET: &str = "forbidden-syscall";

/// Invoke a syscall the same installed filter allows.
const SECCOMP_BOOTSTRAP_PROBE_PERMITTED_TARGET: &str = "permitted-syscall";

/// The one denied syscall this probe knows how to invoke from safe Rust.
///
/// A filter compiled from a plan denies whatever the plan committed, but the
/// child has to *call* one of those syscalls to prove the filter, and calling
/// an arbitrary number would need a raw `syscall(2)`, new `unsafe` and new
/// FFI, both refused. `socket(2)` is reachable through `rustix::net::socket`,
/// so the controller instead requires the committed filter to deny it: a plan
/// whose filter does not cover `socket` cannot be proven by this probe and is
/// refused rather than admitted unproven.
const SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL: &str = "socket";

/// The syscall the permitted arm invokes, which the committed filter must not
/// deny, otherwise the control run would prove nothing about the filter.
const SECCOMP_BOOTSTRAP_PROBE_SURVIVING_SYSCALL: &str = "getppid";

/// Domain separator for the Landlock probe's result commitment.
///
/// Version 2 because the preimage changed with plan schema version 4: it is no
/// longer the prober's own two paths but the committed ruleset's digest, which
/// is what lets `validate_service_bootstrap_evidence` recompute it from the
/// plan alone.
const LANDLOCK_BOOTSTRAP_PROBE_RESULT_DOMAIN: &[u8] =
    b"grok-build/linux-landlock-bootstrap-probe-result/v2\0";

/// Domain separator for the seccomp probe's result commitment, version 2 for
/// the same reason.
const SECCOMP_BOOTSTRAP_PROBE_RESULT_DOMAIN: &[u8] =
    b"grok-build/linux-seccomp-bootstrap-probe-result/v2\0";

/// The errno a Landlock-confined process must receive for the committed denial
/// witness.
///
/// `EACCES` is 13 on every Linux architecture. It is written as a constant here
/// rather than read from `rustix` because `validate_service_bootstrap_evidence`
/// recomputes this preimage on hosts that have no Linux kernel in front of
/// them; `probe_landlock_full_enforcement` requires the live value to equal it,
/// so the two can never disagree silently.
const LANDLOCK_BOOTSTRAP_PROBE_DENIED_ERRNO: i32 = 13;

/// The signal the kernel must kill a filtered process with.
///
/// `SIGSYS` is 31 on both architectures this build compiles a syscall table
/// for, and `probe_seccomp_forbidden_syscall` requires the live value to equal
/// it for the same reason as the errno above.
const SECCOMP_BOOTSTRAP_PROBE_KILLING_SIGNAL: i32 = 31;

/// The commitment a Landlock probe of one committed ruleset produces.
///
/// Every operand is either a compiled constant, the committed ruleset, or a
/// live kernel answer the controller already refused to accept any other value
/// for. Recomputing it is therefore a statement about what the kernel did, not
/// a comparison of two stored digests: a probe that installed a different
/// ruleset, opened a different object, or was denied by a different errno never
/// produces this value at all, because the controller never mints one.
fn landlock_bootstrap_probe_result_digest(
    ruleset: &LinuxLandlockRulesetV1,
    observed_kernel_abi: u32,
) -> Digest {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(LANDLOCK_BOOTSTRAP_PROBE_RESULT_DOMAIN);
    preimage.extend_from_slice(ruleset.ruleset_sha256.as_str().as_bytes());
    preimage.extend_from_slice(&u64::from(observed_kernel_abi).to_be_bytes());
    preimage.extend_from_slice(&i64::from(LANDLOCK_BOOTSTRAP_PROBE_DENIED_ERRNO).to_be_bytes());
    Digest::sha256(&preimage)
}

/// The commitment a seccomp probe of one committed filter produces, with the
/// same property.
fn seccomp_bootstrap_probe_result_digest(filter: &LinuxSeccompFilterV1) -> Digest {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(SECCOMP_BOOTSTRAP_PROBE_RESULT_DOMAIN);
    preimage.extend_from_slice(filter.filter_sha256.as_str().as_bytes());
    preimage.extend_from_slice(filter.program_sha256.as_str().as_bytes());
    preimage.extend_from_slice(&i64::from(SECCOMP_BOOTSTRAP_PROBE_KILLING_SIGNAL).to_be_bytes());
    let invoked = SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL.as_bytes();
    preimage.extend_from_slice(&(invoked.len() as u64).to_be_bytes());
    preimage.extend_from_slice(invoked);
    Digest::sha256(&preimage)
}

/// One object a probe process opened, as the kernel identified it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxServiceBootstrapProbeObjectIdentityV1 {
    device_id: u64,
    inode: u64,
}

/// Everything one bootstrap probe process observed about itself.
///
/// Every field is an observation, never a verdict. The controller decides what
/// the evidence requires; the child only reports what the kernel did to it.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent kernel observations stay explicit so no single summary boolean can stand in for a control the kernel did not apply"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxServiceBootstrapProbeReportV1 {
    schema_version: u32,
    mode: String,
    /// Landlock ABI the running kernel reported, taken from the same
    /// `restrict_self` call that enforced the ruleset.
    landlock_observed_kernel_abi: u32,
    landlock_ruleset_fully_enforced: bool,
    landlock_no_new_privileges: bool,
    /// The kernel's identity for every scope the child added a rule over, in
    /// the committed order. The controller requires each to equal the identity
    /// the plan committed, so a ruleset built over a substituted directory is
    /// refused even when the path string matched.
    landlock_scope_identities: Vec<LinuxServiceBootstrapProbeObjectIdentityV1>,
    /// Whether every granted scope was still openable after restriction. A
    /// confined process that cannot read anything proves nothing.
    landlock_every_scope_open_succeeded: bool,
    /// The kernel's identity for the committed denial witness, read before
    /// restriction, so the denial afterwards is about a known object.
    landlock_denial_witness_identity: LinuxServiceBootstrapProbeObjectIdentityV1,
    /// Whether the committed denial witness was openable after restriction.
    landlock_denied_open_succeeded: bool,
    landlock_denied_open_errno: i32,
    seccomp_no_new_privileges_read_back: bool,
    seccomp_filter_installed: bool,
    /// The digest of the BPF program the child actually assembled from the
    /// committed rule set, which the controller requires to equal the digest
    /// the plan committed.
    seccomp_program_sha256: String,
    seccomp_instruction_count: u64,
    /// Which of the two syscalls this run invoked after installing the filter.
    seccomp_invoked_target: String,
}

impl LinuxServiceBootstrapProbeReportV1 {
    fn new(mode: &str) -> Self {
        Self {
            schema_version: LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_VERSION,
            mode: mode.to_owned(),
            landlock_observed_kernel_abi: 0,
            landlock_ruleset_fully_enforced: false,
            landlock_no_new_privileges: false,
            landlock_scope_identities: Vec::new(),
            landlock_every_scope_open_succeeded: false,
            landlock_denial_witness_identity: LinuxServiceBootstrapProbeObjectIdentityV1 {
                device_id: 0,
                inode: 0,
            },
            landlock_denied_open_succeeded: false,
            landlock_denied_open_errno: 0,
            seccomp_no_new_privileges_read_back: false,
            seccomp_filter_installed: false,
            seccomp_program_sha256: String::new(),
            seccomp_instruction_count: 0,
            seccomp_invoked_target: String::new(),
        }
    }
}

/// Runs the fixed Linux service-bootstrap probe when the exact internal mode
/// argument is present.
///
/// This entry point grants no authority and performs no command. It confines
/// **itself** and reports what the kernel did, which is the only way the
/// irreversible controls it measures can be measured at all. A non-Linux build
/// recognizes the argument only so it can fail closed.
#[doc(hidden)]
#[must_use]
pub fn run_linux_service_bootstrap_probe_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(LINUX_SERVICE_BOOTSTRAP_PROBE_ARGUMENT) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(run_service_bootstrap_probe(arguments))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(arguments);
        Some(std::process::ExitCode::from(78))
    }
}

/// Exit code every probe-process refusal uses.
///
/// It is deliberately not zero and deliberately not the seccomp arm's expected
/// outcome, so a controller can tell "the child refused" from "the kernel
/// killed the child" from "the child completed".
#[cfg(target_os = "linux")]
const LINUX_SERVICE_BOOTSTRAP_PROBE_REFUSAL_CODE: u8 = 78;

#[cfg(target_os = "linux")]
fn run_service_bootstrap_probe(mut arguments: std::env::ArgsOs) -> std::process::ExitCode {
    let outcome = match arguments
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some(LANDLOCK_BOOTSTRAP_PROBE_MODE) => run_landlock_bootstrap_probe(arguments),
        Some(SECCOMP_BOOTSTRAP_PROBE_MODE) => run_seccomp_bootstrap_probe(arguments),
        _ => Err(
            "the bootstrap probe process requires one of its two compiled modes \
             (Landlock or the network seccomp filter); the namespace filter is \
             not a bootstrap-probe arm"
                .to_owned(),
        ),
    };
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(detail) => {
            eprintln!("bootstrap probe refused: {detail}");
            std::process::ExitCode::from(LINUX_SERVICE_BOOTSTRAP_PROBE_REFUSAL_CODE)
        }
    }
}

/// Decodes one committed artefact out of the probe process's own argument
/// vector.
///
/// The child never reads a file and never resolves a name of its own: the
/// artefact is handed to it, bounded, and refused if it is not exactly the type
/// the mode expects.
#[cfg(target_os = "linux")]
fn decode_bootstrap_probe_artefact<T: serde::de::DeserializeOwned>(
    argument: Option<std::ffi::OsString>,
    what: &str,
) -> Result<T, String> {
    let encoded =
        argument.ok_or_else(|| format!("the bootstrap probe requires the committed {what}"))?;
    let encoded = encoded
        .to_str()
        .ok_or_else(|| format!("the committed {what} is not UTF-8"))?;
    if encoded.len() > MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_ARTEFACT_BYTES {
        return Err(format!("the committed {what} exceeds its byte bound"));
    }
    serde_json::from_str(encoded).map_err(|error| format!("decode the committed {what}: {error}"))
}

/// Emits the canonical report on stdout and flushes it.
///
/// The seccomp mode is killed by the kernel immediately afterwards, so an
/// unflushed report would be lost with the process that produced it.
#[cfg(target_os = "linux")]
fn publish_bootstrap_probe_report(
    report: &LinuxServiceBootstrapProbeReportV1,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(report).map_err(|error| error.to_string())?;
    if encoded.len() > MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_BYTES {
        return Err("the bootstrap probe report exceeds its byte bound".to_owned());
    }
    let mut stdout = io::stdout();
    stdout
        .write_all(&encoded)
        .map_err(|error| error.to_string())?;
    stdout.flush().map_err(|error| error.to_string())
}

/// The kernel's identity for one already-open descriptor.
#[cfg(target_os = "linux")]
fn bootstrap_probe_object_identity(
    descriptor: impl std::os::fd::AsFd,
    what: &str,
) -> Result<LinuxServiceBootstrapProbeObjectIdentityV1, String> {
    let observed =
        rustix::fs::fstat(descriptor).map_err(|error| format!("identify the {what}: {error}"))?;
    Ok(LinuxServiceBootstrapProbeObjectIdentityV1 {
        device_id: observed.st_dev,
        inode: observed.st_ino,
    })
}

// ---------------------------------------------------------------------------
// Landlock: the child installs the plan's ruleset and reports what it did.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn run_landlock_bootstrap_probe(mut arguments: std::env::ArgsOs) -> Result<(), String> {
    use landlock::{
        AccessFs, BitFlags, CompatLevel, Compatible as _, LandlockStatus, PathBeneath, PathFd,
        Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
    };

    let ruleset: LinuxLandlockRulesetV1 =
        decode_bootstrap_probe_artefact(arguments.next(), "Landlock ruleset")?;

    // Hard compatibility means a right the kernel does not implement fails the
    // build rather than being silently dropped, so a `FullyEnforced` answer
    // below is the kernel's own and not the crate's accommodation.
    let handled = BitFlags::<AccessFs>::from_bits(ruleset.handled_access_bits)
        .map_err(|error| format!("the committed handled access set is not Landlock's: {error}"))?;
    let mut created = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .and_then(Ruleset::create)
        .map_err(|error| format!("create the committed Landlock ruleset: {error}"))?;

    let mut report = LinuxServiceBootstrapProbeReportV1::new(LANDLOCK_BOOTSTRAP_PROBE_MODE);
    for scope in &ruleset.scopes {
        let access = BitFlags::<AccessFs>::from_bits(scope.access_bits).map_err(|error| {
            format!(
                "the committed access set for {} is not Landlock's: {error}",
                scope.resolved_path
            )
        })?;
        let descriptor = PathFd::new(&scope.resolved_path)
            .map_err(|error| format!("open the scope {}: {error}", scope.resolved_path))?;
        report
            .landlock_scope_identities
            .push(bootstrap_probe_object_identity(&descriptor, "scope")?);
        created = created
            .add_rule(PathBeneath::new(descriptor, access))
            .map_err(|error| format!("grant the scope {}: {error}", scope.resolved_path))?;
    }
    // Read before restriction, so the denial afterwards is a statement about a
    // known object rather than about a name that might not have resolved.
    let witness = PathFd::new(&ruleset.denial_witness.resolved_path).map_err(|error| {
        format!(
            "open the denial witness {}: {error}",
            ruleset.denial_witness.resolved_path
        )
    })?;
    report.landlock_denial_witness_identity =
        bootstrap_probe_object_identity(&witness, "denial witness")?;
    drop(witness);

    let status = created
        .restrict_self()
        .map_err(|error| format!("restrict this process: {error}"))?;
    report.landlock_ruleset_fully_enforced = status.ruleset == RulesetStatus::FullyEnforced;
    report.landlock_no_new_privileges = status.no_new_privs;
    report.landlock_observed_kernel_abi = match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => kernel_abi
            .and_then(|abi| u32::try_from(abi).ok())
            .unwrap_or(effective_abi as u32),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => 0,
    };
    // Both halves of the boundary, measured after restriction: what the ruleset
    // grants must still work, and what it does not cover must not.
    report.landlock_every_scope_open_succeeded = ruleset
        .scopes
        .iter()
        .all(|scope| std::fs::File::open(&scope.resolved_path).is_ok());
    match std::fs::File::open(&ruleset.denial_witness.resolved_path) {
        Ok(file) => {
            drop(file);
            report.landlock_denied_open_succeeded = true;
        }
        Err(error) => {
            report.landlock_denied_open_errno = error.raw_os_error().unwrap_or(0);
        }
    }
    publish_bootstrap_probe_report(&report)
}

// ---------------------------------------------------------------------------
// seccomp: the child installs the plan's filter, then invokes a syscall.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SECCOMP_BOOTSTRAP_PROBE_TARGET_ARCH: seccompiler::TargetArch =
    seccompiler::TargetArch::aarch64;

/// See the `aarch64` definition.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SECCOMP_BOOTSTRAP_PROBE_TARGET_ARCH: seccompiler::TargetArch =
    seccompiler::TargetArch::x86_64;

/// The canonical digest of one assembled BPF program.
///
/// The instructions are digested field by field in program order rather than by
/// reinterpreting the structure's memory, so the value does not depend on
/// padding or on the host's byte order.
#[cfg(target_os = "linux")]
fn seccomp_program_digest(program: &[seccompiler::sock_filter]) -> Digest {
    let mut preimage = Vec::with_capacity(SECCOMP_PROGRAM_DIGEST_DOMAIN.len() + program.len() * 8);
    preimage.extend_from_slice(SECCOMP_PROGRAM_DIGEST_DOMAIN);
    preimage.extend_from_slice(&(program.len() as u64).to_be_bytes());
    for instruction in program {
        preimage.extend_from_slice(&instruction.code.to_be_bytes());
        preimage.push(instruction.jt);
        preimage.push(instruction.jf);
        preimage.extend_from_slice(&instruction.k.to_be_bytes());
    }
    Digest::sha256(&preimage)
}

/// Domain separator for an assembled BPF program's digest.
///
/// Cross-platform because `validate_service_bootstrap_evidence` and the plan's
/// own validators compare a digest computed with it on hosts that cannot
/// assemble one.
pub(crate) const SECCOMP_PROGRAM_DIGEST_DOMAIN: &[u8] =
    b"grok-build/linux-seccomp-assembled-program/v1\0";

#[cfg(target_os = "linux")]
fn run_seccomp_bootstrap_probe(mut arguments: std::env::ArgsOs) -> Result<(), String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let filter: LinuxSeccompFilterV1 =
        decode_bootstrap_probe_artefact(arguments.next(), "seccomp filter")?;
    let target = arguments
        .next()
        .ok_or_else(|| "the seccomp probe requires a target syscall selector".to_owned())?;
    let target = target
        .to_str()
        .ok_or_else(|| "the seccomp probe's target selector is not UTF-8".to_owned())?
        .to_owned();
    if target != SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET
        && target != SECCOMP_BOOTSTRAP_PROBE_PERMITTED_TARGET
    {
        return Err("the seccomp probe's target selector is not one of its two values".to_owned());
    }

    let mut report = LinuxServiceBootstrapProbeReportV1::new(SECCOMP_BOOTSTRAP_PROBE_MODE);
    report.seccomp_invoked_target.clone_from(&target);

    // The enforced arm ends with the kernel killing this process by `SIGSYS`,
    // whose default action dumps core. The probe wants the signal, not the
    // dump: a bootstrap that littered a core file per start would be a real
    // operational defect, and the core carries this process's memory.
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|error| format!("suppress this probe's core dump: {error}"))?;

    // `PR_SET_NO_NEW_PRIVS` is read back rather than assumed. It is the
    // precondition an unprivileged `seccomp(2)` requires, and a service that
    // could not set it would be installing a filter it could later escape
    // through a set-user-ID image.
    rustix::thread::set_no_new_privs(true)
        .map_err(|error| format!("set no-new-privileges: {error}"))?;
    report.seccomp_no_new_privileges_read_back = rustix::thread::no_new_privs()
        .map_err(|error| format!("read back no-new-privileges: {error}"))?;

    // The committed filter on both arms: everything is allowed except the
    // syscalls the plan named, each of which kills the whole process. Only
    // which syscall the child invokes afterwards differs between an enforced
    // run and a control run, so there is no arm of this binary in which the
    // filter is absent.
    let rules = filter
        .denied_syscalls
        .iter()
        .map(|denied| (denied.number, Vec::new()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let compiled = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        SECCOMP_BOOTSTRAP_PROBE_TARGET_ARCH,
    )
    .map_err(|error| format!("compile the committed seccomp filter: {error}"))?;
    let program =
        BpfProgram::try_from(compiled).map_err(|error| format!("assemble the filter: {error}"))?;
    seccomp_program_digest(&program)
        .as_str()
        .clone_into(&mut report.seccomp_program_sha256);
    report.seccomp_instruction_count = program.len() as u64;
    // Thread-local on purpose: this probe process is a freshly exec'd helper
    // with one thread. `apply_filter_all_threads` (TSYNC) is what the
    // launcher and the development child use. Residual, not a silent miss.
    seccompiler::apply_filter(&program).map_err(|error| format!("apply the filter: {error}"))?;
    report.seccomp_filter_installed = true;

    // The report is published *before* the syscall, because on the enforced arm
    // the kernel destroys this process at the syscall boundary and an unflushed
    // report would die with it.
    publish_bootstrap_probe_report(&report)?;

    if target == SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET {
        // Does not return on a kernel that honors the filter.
        let _killed_here = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            None,
        );
    } else {
        let _survived = rustix::process::getppid();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The controller side: spawn the probe, reap it, and judge nothing the child
// did not measure.
// ---------------------------------------------------------------------------

/// The image the probe process is started from.
///
/// In production it is this running binary, named through procfs so no
/// directory component is resolved. Under `cfg(test)` the running image is a
/// unit-test harness rather than a runner, so the tests locate the ordinary
/// runner binary exactly as the native held-launcher and canary tests already
/// do; the probe mode lives in that binary's entry point and nowhere else.
#[cfg(target_os = "linux")]
fn service_bootstrap_probe_image() -> std::path::PathBuf {
    #[cfg(not(test))]
    {
        std::path::PathBuf::from("/proc/self/exe")
    }
    #[cfg(test)]
    {
        if let Some(path) = option_env!("CARGO_BIN_EXE_grok-build-runner") {
            return std::path::PathBuf::from(path);
        }
        if let Some(path) = std::env::var_os("CARGO_BIN_EXE_grok-build-runner") {
            return std::path::PathBuf::from(path);
        }
        let current = std::env::current_exe().expect("a test executable has a path");
        let profile = current
            .parent()
            .and_then(Path::parent)
            .expect("unit test executable must be under target/<profile>/deps");
        let candidate = profile.join("grok-build-runner");
        assert!(
            candidate.is_file(),
            "Linux bootstrap probe tests require the regular runner binary; use cargo test --all-targets"
        );
        candidate
    }
}

/// Starts one probe process and reaps it.
///
/// The child gets no environment, a working directory it did not choose, and a
/// null stdin, exactly as the Bubblewrap version probe's child does.
#[cfg(target_os = "linux")]
fn run_service_bootstrap_probe_process(
    mode: &str,
    arguments: &[&std::ffi::OsStr],
    operation: &'static str,
) -> Result<std::process::Output, CgroupIoFailure> {
    let mut command = std::process::Command::new(service_bootstrap_probe_image());
    command
        .arg(LINUX_SERVICE_BOOTSTRAP_PROBE_ARGUMENT)
        .arg(mode)
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
        .output()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))
}

/// Encodes one committed artefact for the probe process's argument vector.
#[cfg(target_os = "linux")]
fn encode_bootstrap_probe_artefact<T: Serialize>(
    artefact: &T,
    operation: &'static str,
) -> Result<std::ffi::OsString, CgroupIoFailure> {
    let encoded = serde_json::to_string(artefact)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if encoded.len() > MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_ARTEFACT_BYTES {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the committed artefact exceeds the probe's argument bound",
        ));
    }
    Ok(std::ffi::OsString::from(encoded))
}

/// Decodes and bounds-checks one probe report.
#[cfg(target_os = "linux")]
fn decode_service_bootstrap_probe_report(
    output: &std::process::Output,
    mode: &str,
    operation: &'static str,
) -> Result<LinuxServiceBootstrapProbeReportV1, CgroupIoFailure> {
    if !output.stderr.is_empty() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            format!(
                "the bootstrap probe process wrote to stderr: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    if output.stdout.is_empty()
        || output.stdout.len() > MAX_LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_BYTES
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the bootstrap probe report is empty or outside its byte bound",
        ));
    }
    let report: LinuxServiceBootstrapProbeReportV1 = serde_json::from_slice(&output.stdout)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if report.schema_version != LINUX_SERVICE_BOOTSTRAP_PROBE_REPORT_VERSION || report.mode != mode
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "the bootstrap probe report is not this schema or this mode",
        ));
    }
    Ok(report)
}

/// Proves that the **committed** Landlock ruleset really confines a child of
/// this service, and reports the ABI the kernel answered with.
///
/// The caller varies nothing: the ruleset is the plan's, including the object
/// it states must be denied. A control run is obtained by handing a different
/// ruleset, one whose witness the ruleset actually grants, because the child
/// builds and applies whatever it is given either way.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the probe process cannot be started, exits
/// non-zero or is signalled, writes to stderr, produces an unreadable report,
/// reports anything other than a fully enforced ruleset with no-new-privileges
/// set, **opened a scope or a witness whose kernel identity is not the one the
/// plan committed**, could not read a scope it was granted, or **was able to
/// open the object the plan required to be denied**. An unenforced boundary is
/// a refusal, not a downgrade.
#[cfg(target_os = "linux")]
fn probe_landlock_full_enforcement(
    ruleset: &LinuxLandlockRulesetV1,
) -> Result<LinuxLandlockBootstrapProbeV1, CgroupIoFailure> {
    const OPERATION: &str = "probe-bootstrap-landlock";

    let encoded = encode_bootstrap_probe_artefact(ruleset, OPERATION)?;
    let output = run_service_bootstrap_probe_process(
        LANDLOCK_BOOTSTRAP_PROBE_MODE,
        &[encoded.as_os_str()],
        OPERATION,
    )?;
    if output.status.code() != Some(0) {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the Landlock probe process did not complete cleanly: {}",
                output.status
            ),
        ));
    }
    let report =
        decode_service_bootstrap_probe_report(&output, LANDLOCK_BOOTSTRAP_PROBE_MODE, OPERATION)?;
    if !report.landlock_ruleset_fully_enforced
        || !report.landlock_no_new_privileges
        || report.landlock_observed_kernel_abi == 0
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the Landlock probe process did not report a fully enforced ruleset with no-new-privileges",
        ));
    }
    if report.landlock_scope_identities.len() != ruleset.scopes.len()
        || report
            .landlock_scope_identities
            .iter()
            .zip(&ruleset.scopes)
            .any(|(observed, committed)| {
                observed.device_id != committed.device_id || observed.inode != committed.inode
            })
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the Landlock probe process granted objects that are not the ones the plan committed",
        ));
    }
    if report.landlock_denial_witness_identity.device_id != ruleset.denial_witness.device_id
        || report.landlock_denial_witness_identity.inode != ruleset.denial_witness.inode
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the Landlock probe process was denied an object that is not the committed witness",
        ));
    }
    if !report.landlock_every_scope_open_succeeded {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the Landlock probe process could not read a scope it was granted, so its denial proves nothing",
        ));
    }
    if report.landlock_denied_open_succeeded
        || report.landlock_denied_open_errno != LANDLOCK_BOOTSTRAP_PROBE_DENIED_ERRNO
        || LANDLOCK_BOOTSTRAP_PROBE_DENIED_ERRNO != rustix::io::Errno::ACCESS.raw_os_error()
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the Landlock probe process was not denied {} by the kernel (opened={}, errno={})",
                ruleset.denial_witness.resolved_path,
                report.landlock_denied_open_succeeded,
                report.landlock_denied_open_errno
            ),
        ));
    }

    Ok(LinuxLandlockBootstrapProbeV1 {
        observed_kernel_abi: report.landlock_observed_kernel_abi,
        active_probe_result_digest: landlock_bootstrap_probe_result_digest(
            ruleset,
            report.landlock_observed_kernel_abi,
        ),
        full_enforcement_passed: true,
    })
}

/// Proves that the **committed** seccomp filter installed by a child of this
/// service really kills that child, and that no-new-privileges reads back.
///
/// `target` selects which syscall the child invokes **after** installing the
/// identical filter. The caller varies only that, because the filter, the
/// architecture prologue and the no-new-privileges step are the same on both
/// arms.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the committed filter does not cover the one
/// syscall this probe can invoke, when the probe process cannot be started,
/// writes to stderr, produces an unreadable report, did not read back
/// no-new-privileges, did not install the filter, **assembled a program whose
/// digest is not the committed one**, or **was not killed by `SIGSYS`**. A
/// child that survived its own forbidden syscall is a refusal.
#[cfg(target_os = "linux")]
fn probe_seccomp_forbidden_syscall(
    filter: &LinuxSeccompFilterV1,
    target: &str,
) -> Result<LinuxSeccompBootstrapProbeV1, CgroupIoFailure> {
    use std::os::unix::process::ExitStatusExt as _;

    const OPERATION: &str = "probe-bootstrap-seccomp";

    if !filter
        .denied_syscalls
        .iter()
        .any(|denied| denied.name == SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL)
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the committed seccomp filter does not deny {SECCOMP_BOOTSTRAP_PROBE_INVOKED_SYSCALL}, which is the only denied syscall this probe can invoke without new unsafe or new FFI, so the filter cannot be proven on this host"
            ),
        ));
    }
    if filter
        .denied_syscalls
        .iter()
        .any(|denied| denied.name == SECCOMP_BOOTSTRAP_PROBE_SURVIVING_SYSCALL)
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the committed seccomp filter denies {SECCOMP_BOOTSTRAP_PROBE_SURVIVING_SYSCALL}, so this probe's control run could not distinguish a filter that works from one that kills everything"
            ),
        ));
    }
    let encoded = encode_bootstrap_probe_artefact(filter, OPERATION)?;
    let output = run_service_bootstrap_probe_process(
        SECCOMP_BOOTSTRAP_PROBE_MODE,
        &[encoded.as_os_str(), std::ffi::OsStr::new(target)],
        OPERATION,
    )?;
    let report =
        decode_service_bootstrap_probe_report(&output, SECCOMP_BOOTSTRAP_PROBE_MODE, OPERATION)?;
    if !report.seccomp_no_new_privileges_read_back || !report.seccomp_filter_installed {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the seccomp probe process did not read back no-new-privileges or did not install its filter",
        ));
    }
    if report.seccomp_program_sha256 != filter.program_sha256.as_str()
        || report.seccomp_instruction_count != filter.instruction_count
        || report.seccomp_invoked_target != target
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the seccomp probe process assembled a different program than the plan committed, or invoked a different target",
        ));
    }
    let signal = output.status.signal();
    if signal != Some(SECCOMP_BOOTSTRAP_PROBE_KILLING_SIGNAL)
        || SECCOMP_BOOTSTRAP_PROBE_KILLING_SIGNAL != rustix::process::Signal::SYS.as_raw()
        || output.status.code().is_some()
    {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the seccomp probe process was not killed by SIGSYS after invoking {}: {}",
                report.seccomp_invoked_target, output.status
            ),
        ));
    }

    Ok(LinuxSeccompBootstrapProbeV1 {
        active_probe_result_digest: seccomp_bootstrap_probe_result_digest(filter),
        no_new_privileges_read_back: true,
        forbidden_syscall_killed: true,
    })
}

// Bootstrap evidence authenticates the delegation, pinned Bubblewrap,
// Landlock confinement, and seccomp termination. The bootstrap capability
// itself grants no command-execution authority.

/// Opens the directory that holds the admitted Bubblewrap image, and names it.
///
/// The plan's `resolved_path` is the authority for both halves. The directory
/// is opened by ambient path exactly once here; every subsequent use is through
/// the retained descriptor, and
/// `LinuxNativeServiceBootstrapCapabilities::validate_for` re-proves the named
/// file's identity, mode, length and whole-content digest against the plan
/// before any evidence is published.
#[cfg(target_os = "linux")]
fn open_admitted_bubblewrap_parent(resolved_path: &str) -> Result<(Dir, String), CgroupIoFailure> {
    const OPERATION: &str = "open-bootstrap-bubblewrap-parent";

    let resolved = Path::new(resolved_path);
    let parent = resolved.parent().ok_or_else(|| {
        failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the planned Bubblewrap path has no parent directory",
        )
    })?;
    let name = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the planned Bubblewrap path has no normalized filename",
            )
        })?;
    let directory = Dir::open_ambient_dir(parent, cap_std::ambient_authority())
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    Ok((directory, name.to_owned()))
}

/// Runs all four host probes and assembles the evidence they produce.
///
/// Every field of the returned value is a live kernel read. Nothing here
/// invents a digest, and nothing here decides whether what it measured is what
/// the plan wanted, that is `validate_service_bootstrap_evidence`'s job, and
/// `publish` calls it before the artifact is written.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when any of the four probes refuses. There is no
/// partial evidence: a probe that could not complete is not a probe that
/// passed.
#[cfg(target_os = "linux")]
fn mint_service_bootstrap_evidence(
    plan_binding: LinuxProductionCommandPlanServiceBootstrapBindingV1,
    capabilities: &LinuxNativeServiceBootstrapCapabilities,
) -> Result<LinuxNativeServiceBootstrapEvidenceV1, CgroupIoFailure> {
    let cgroup = probe_delegated_cgroup(
        &capabilities.delegation,
        &capabilities.delegation_name,
        &capabilities.controllers,
        &capabilities.subtree_control,
        &capabilities.cgroup_procs,
    )?;
    let bubblewrap = probe_retained_bubblewrap_version(&capabilities.bubblewrap)?;
    // Use the plan's scopes rather than substitute probe directories.
    let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
        ruleset, ..
    } = &plan_binding.landlock;
    let landlock = probe_landlock_full_enforcement(ruleset)?;
    let LinuxSeccompBootstrapBindingV1::CompiledFilterProvenByLiveBootstrapProbe { filter, .. } =
        &plan_binding.seccomp;
    let seccomp =
        probe_seccomp_forbidden_syscall(filter, SECCOMP_BOOTSTRAP_PROBE_FORBIDDEN_TARGET)?;
    Ok(LinuxNativeServiceBootstrapEvidenceV1 {
        authority_version: SERVICE_BOOTSTRAP_AUTHORITY_VERSION,
        plan_binding,
        cgroup,
        bubblewrap,
        landlock,
        seccomp,
    })
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceBootstrapAuthority {
    /// The production construction, from an authenticated handoff.
    ///
    /// `capability` and `host_roots` are what
    /// `PendingLinuxNativeServiceAuthenticatedHandoff::into_state_root_capability`
    /// produced, so the service state root, the service process image and the
    /// external installer commitment are all already authenticated against the
    /// plan's journal binding. This adds the four host probes and publishes the
    /// canonical evidence artifact under the service's own retained lock.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the plan has no bootstrap binding, when
    /// the journal singleton cannot be opened, when the delegated cgroup or the
    /// admitted Bubblewrap image cannot be retained, when any of the four
    /// probes refuses, or when the evidence the probes produced does not bind
    /// the plan.
    fn open_authenticated(
        journal_authority: &mut LinuxServiceCommandJournalAuthority,
        host_roots: LinuxNativeServiceBootstrapHostRoots,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<Self, CgroupIoFailure> {
        let plan_binding = plan.service_bootstrap_binding().map_err(|error| {
            failure(
                "bind-linux-service-bootstrap-plan",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        let (bubblewrap_parent, bubblewrap_name) =
            open_admitted_bubblewrap_parent(&plan_binding.bubblewrap.resolved_path)?;
        let LinuxNativeServiceBootstrapHostRoots {
            service_parent,
            delegation_name,
        } = host_roots;
        let capabilities = LinuxNativeServiceBootstrapCapabilities::open_retained(
            &journal_authority.journal,
            service_parent,
            &delegation_name,
            bubblewrap_parent,
            &bubblewrap_name,
        )?;
        let evidence = mint_service_bootstrap_evidence(plan_binding, &capabilities)?;
        Self::publish(evidence, capabilities, journal_authority)
    }
}

/// Compile-time check that the production bootstrap constructor remains
/// available with its required signature.
#[cfg(target_os = "linux")]
const LINUX_NATIVE_SERVICE_BOOTSTRAP_PRODUCTION_MINT: fn(
    &mut LinuxServiceCommandJournalAuthority,
    LinuxNativeServiceBootstrapHostRoots,
    &ValidatedLinuxProductionCommandPlanV1,
) -> Result<
    LinuxNativeServiceBootstrapAuthority,
    CgroupIoFailure,
> = LinuxNativeServiceBootstrapAuthority::open_authenticated;

// Build setup descriptors only from anchored, created, or retained objects.
// The sealed request and distinct pipes form a closed table and confer no
// execute capability.

/// Name the sealed setup-channel memfd is created under.
///
/// A memfd name is not an identity, it appears in `/proc/self/fd` as
/// `/memfd:<name> (deleted)` and nothing compares it, so it is here for the
/// operator reading `lsof`, and every actual check below is against the inode,
/// the seals and the bytes.
#[cfg(target_os = "linux")]
const LINUX_SETUP_CHANNEL_MEMFD_NAME: &str = "grok-build-linux-setup-channel-v1";

/// Mode the sealed setup channel is required to carry.
///
/// Owner-read only. `AuthenticatedSetupChannelV1::authenticate_sealed` refuses
/// a set-user-ID, set-group-ID, group-writable or world-writable channel, and
/// the plan's object table then compares the exact mode again, so this constant
/// is the value the kernel is asked for and never the value that is recorded.
#[cfg(target_os = "linux")]
const LINUX_SETUP_CHANNEL_MEMFD_MODE: u32 = 0o400;

/// A sealed setup channel and its authenticated descriptor, retained together
/// because the setup closure requires the descriptor itself.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceSealedSetupChannel {
    authenticated: AuthenticatedSetupChannelV1,
    file: File,
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceSealedSetupChannel {
    /// The authenticated plan component this channel produced.
    pub(crate) const fn authenticated(&self) -> &AuthenticatedSetupChannelV1 {
        &self.authenticated
    }

    /// The retained sealed descriptor, consumed by the setup-descriptor mint.
    pub(crate) fn into_retained_descriptor(self) -> File {
        self.file
    }
}

/// Creates, seals and authenticates one setup channel for an anchored
/// statement.
///
/// The order is the only one that can be evidence: create, write, restrict the
/// mode, seal, **read the seals back out of the kernel**, read the whole
/// content back out of the sealed descriptor, and only then authenticate. The
/// bytes that are authenticated are the bytes a reader gets from the sealed
/// inode, not the bytes this function wrote, and the seal set that is compared
/// is the kernel's answer, not the set that was requested.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the statement cannot be encoded, when any
/// of the memfd calls fails, when the readback is short, and on every refusal
/// [`AuthenticatedSetupChannelV1::authenticate_sealed`] makes, including a
/// readback that differs from a fresh encoding of the same anchored statement.
#[cfg(target_os = "linux")]
pub(crate) fn seal_linux_native_service_setup_channel(
    statement: &LinuxSetupChannelStatementV1<'_>,
) -> Result<LinuxNativeServiceSealedSetupChannel, CgroupIoFailure> {
    const OPERATION: &str = "seal-linux-native-service-setup-channel";

    let content = statement
        .encode()
        .map_err(|error| plan_mint_failure(OPERATION, &error))?;
    let descriptor = rustix::fs::memfd_create(
        LINUX_SETUP_CHANNEL_MEMFD_NAME,
        rustix::fs::MemfdFlags::CLOEXEC
            | rustix::fs::MemfdFlags::ALLOW_SEALING
            | rustix::fs::MemfdFlags::EXEC,
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let mut raw = std::fs::File::from(descriptor);
    raw.write_all(&content)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))?;
    raw.flush()
        .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))?;
    rustix::fs::fchmod(
        &raw,
        rustix::fs::Mode::from_raw_mode(LINUX_SETUP_CHANNEL_MEMFD_MODE),
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))?;
    rustix::fs::fcntl_add_seals(
        &raw,
        rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::FUTURE_WRITE
            | rustix::fs::SealFlags::EXEC,
    )
    .map_err(|error| io_failure(OPERATION, EffectCertainty::Ambiguous, error))?;
    // The kernel's answer, not the request: a seal that did not take is a
    // refusal, and a seal set that gained a bit is one too.
    let observed_seals = rustix::fs::fcntl_get_seals(&raw)
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?
        .bits();
    let file = File::from_std(raw);
    let observed = observe_retained_file_kernel_facts(&file, OPERATION)?;
    let readback = read_retained_bootstrap_file(
        &file,
        usize::try_from(observed.byte_length.unwrap_or_default()).map_err(|_| {
            failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the sealed setup channel is longer than this host can address",
            )
        })?,
        OPERATION,
    )?;
    let authenticated = AuthenticatedSetupChannelV1::authenticate_sealed(
        statement,
        observed,
        observed_seals,
        &readback,
    )
    .map_err(|error| plan_mint_failure(OPERATION, &error))?;
    Ok(LinuxNativeServiceSealedSetupChannel {
        authenticated,
        file,
    })
}

/// Reads one held regular-file or memfd descriptor into the plan's kernel
/// observation shape.
///
/// `metadata` is `fstat` on the descriptor and [`retained_file_mount_id`] is
/// `statx(.., AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE)` on the same one. No name is
/// resolved in either.
#[cfg(target_os = "linux")]
fn observe_retained_file_kernel_facts(
    file: &File,
    operation: &'static str,
) -> Result<LinuxKernelObjectObservationV1, CgroupIoFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_file() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained setup-channel descriptor is not a regular file",
        ));
    }
    Ok(LinuxKernelObjectObservationV1 {
        device_id: PortableMetadataExt::dev(&metadata),
        inode: PortableMetadataExt::ino(&metadata),
        mount_id: retained_file_mount_id(file, operation)?,
        mode: OsMetadataExt::mode(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        owner_gid: OsMetadataExt::gid(&metadata),
        link_count: PortableMetadataExt::nlink(&metadata),
        byte_length: Some(metadata.len()),
    })
}

/// The service's own ends of the five setup pipes.
///
/// The plan commits nothing about them, a pipe's peer is not a plan object,
/// so nothing here is compared against the plan, and that is exactly why they
/// are **not** inside the capability: a capability field no validator reads is
/// how unchecked state gets carried under an authenticated name. They are
/// returned beside it instead, so the caller has to keep them alive and a
/// reviewer can see that they are not part of what was proved.
///
/// Keeping them matters even though nothing writes yet: a closure whose peers
/// were dropped describes five pipes that are already broken.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceRetainedSetupPipePeers {
    peers: Vec<(LinuxServiceSetupEndpointRoleV1, File)>,
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceRetainedSetupPipePeers {
    /// How many peers are retained. One per pipe endpoint, never per endpoint.
    pub(crate) fn len(&self) -> usize {
        self.peers.len()
    }

    /// The roles whose peers this value retains, in closure order.
    pub(crate) fn roles(&self) -> Vec<LinuxServiceSetupEndpointRoleV1> {
        self.peers.iter().map(|(role, _)| *role).collect()
    }
}

/// Creates one service pipe and returns `(endpoint, service peer)`.
///
/// `std::io::pipe` is used rather than a `rustix` pipe wrapper for one reason
/// that matters and one that does not: it creates the pipe with `O_CLOEXEC`,
/// which is what `close_on_exec_while_retained` requires of every retained
/// endpoint, and it needs no `rustix` feature this workspace has not already
/// admitted.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when the pipe cannot be created, and when a
/// caller asks for a read-write pipe endpoint, no canonical role has one, and
/// a pipe end cannot be both.
#[cfg(target_os = "linux")]
fn create_linux_native_service_setup_pipe(
    access: LinuxServiceSetupDescriptorAccessV1,
) -> Result<(File, File), CgroupIoFailure> {
    const OPERATION: &str = "create-linux-native-service-setup-pipe";

    let (reader, writer) = std::io::pipe()
        .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    let reader = File::from_std(std::fs::File::from(std::os::fd::OwnedFd::from(reader)));
    let writer = File::from_std(std::fs::File::from(std::os::fd::OwnedFd::from(writer)));
    match access {
        LinuxServiceSetupDescriptorAccessV1::ReadOnly => Ok((reader, writer)),
        LinuxServiceSetupDescriptorAccessV1::WriteOnly => Ok((writer, reader)),
        LinuxServiceSetupDescriptorAccessV1::ReadWrite => Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "a service pipe endpoint is never read-write; one end of a pipe cannot be both",
        )),
    }
}

/// The closed set of retained directories a production setup closure may name.
///
/// Every member is a descriptor something else already authenticated. There is
/// deliberately no fallback arm that opens a path: an object identifier this
/// service did not anchor or create is a refusal, which is what keeps the mint
/// from becoming a way to hand the setup closure any directory at all.
#[cfg(target_os = "linux")]
struct LinuxNativeServiceSetupDirectorySources<'sources> {
    service_state_root: &'sources Dir,
    singleton_journal_root: &'sources Dir,
    workspace_root: &'sources Dir,
    directories: &'sources LinuxRetainedPerCommandDirectories,
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceSetupDirectorySources<'_> {
    /// Duplicates the already-authenticated descriptor for one plan object.
    ///
    /// `try_clone` is `fcntl(F_DUPFD_CLOEXEC)`, so the copy names the same open
    /// file description and keeps close-on-exec set; the caller then proves the
    /// identity, mount, mode, owner and access of the copy against the plan
    /// rather than trusting that it came from here.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the object identifier is outside the
    /// closed set, and when the descriptor cannot be duplicated.
    fn resolve(&self, object_id: &str, operation: &'static str) -> Result<Dir, CgroupIoFailure> {
        let [
            per_command_root,
            execution_root,
            private_temp,
            output_spool,
            git_mask,
        ] = self.directories.descriptors();
        let source = match object_id {
            SERVICE_STATE_ROOT_OBJECT_ID => self.service_state_root,
            SINGLETON_JOURNAL_ROOT_OBJECT_ID => self.singleton_journal_root,
            WORKSPACE_ROOT_OBJECT_ID => self.workspace_root,
            PER_COMMAND_RETAINED_ROOT_OBJECT_ID => per_command_root,
            EXECUTION_ROOT_OBJECT_ID => execution_root,
            PRIVATE_TEMP_OBJECT_ID => private_temp,
            OUTPUT_SPOOL_OBJECT_ID => output_spool,
            GIT_MASK_OBJECT_ID => git_mask,
            other => {
                return Err(failure(
                    operation,
                    EffectCertainty::NotApplied,
                    format!(
                        "the setup closure names retained object {other}, which this service neither anchored nor created"
                    ),
                ));
            }
        };
        source
            .try_clone()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))
    }
}

#[cfg(target_os = "linux")]
impl LinuxNativeServiceSetupDescriptorCapability {
    /// The production construction, from authenticated capabilities only.
    ///
    /// `launch_authority` is borrowed rather than consumed because
    /// `bind_linux_native_service_setup_descriptors` consumes it immediately
    /// afterwards: the mint needs the plan and the anchored roots the bootstrap
    /// authority already holds, and it must not be able to keep them.
    ///
    /// The sealed setup channel is consumed. It is one of the six endpoints, so
    /// a caller cannot retain a second descriptor on it and hand this one over
    /// as well.
    ///
    /// # Errors
    ///
    /// Returns [`CgroupIoFailure`] when the launch authority no longer
    /// validates, when the plan has no setup-descriptor projection, when the
    /// closure names a retained object outside the closed set above, when the
    /// working directory cannot be reached from the retained execution root by
    /// a no-follow walk, when a pipe cannot be created, and on every refusal
    /// the untouched `validate_for` makes, which is the same validator the
    /// test constructor has always had to satisfy.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear mint keeps every authenticated source, the closed object table and the endpoint order visible in the order the closure is built"
    )]
    pub(crate) fn open_authenticated(
        launch_authority: &LinuxNativeServiceLaunchImageAuthority,
        directories: &LinuxRetainedPerCommandDirectories,
        workspace_root: &Dir,
        setup_channel: LinuxNativeServiceSealedSetupChannel,
    ) -> Result<(Self, LinuxNativeServiceRetainedSetupPipePeers), CgroupIoFailure> {
        const OPERATION: &str = "mint-linux-native-service-setup-descriptors";

        launch_authority.validate_retained()?;
        let plan = &launch_authority.bootstrapped.journaled.plan;
        let binding = plan
            .service_setup_descriptor_binding()
            .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;
        let journal = &launch_authority
            .bootstrapped
            .journaled
            .journal_authority
            .journal;
        let sources = LinuxNativeServiceSetupDirectorySources {
            service_state_root: &journal.parent,
            singleton_journal_root: &journal.directory,
            workspace_root,
            directories,
        };

        let execution_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.cwd.execution_root.clone(),
            sources.resolve(&binding.cwd.execution_root.object_id, OPERATION)?,
            "validate-linux-native-service-setup-execution-root",
        )?;
        let cwd = open_linux_native_service_setup_cwd(
            &execution_root.directory,
            &binding.cwd.root_relative_path,
        )?;
        let private_state_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.private_state_root.clone(),
            sources.resolve(&binding.private_state_root.object_id, OPERATION)?,
            "validate-linux-native-service-setup-private-root",
        )?;
        let singleton_journal_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.singleton_journal_root.clone(),
            sources.resolve(&binding.singleton_journal_root.object_id, OPERATION)?,
            "validate-linux-native-service-setup-journal-root",
        )?;
        let mut read_only_mount_sources = Vec::with_capacity(binding.read_only_mount_sources.len());
        for expected in &binding.read_only_mount_sources {
            read_only_mount_sources.push(LinuxNativeServiceSetupDirectory::from_retained(
                expected.object.clone(),
                sources.resolve(&expected.object.object_id, OPERATION)?,
                "validate-linux-native-service-setup-mount-source",
            )?);
        }

        let mut sealed_request = Some(setup_channel.into_retained_descriptor());
        let mut peers = Vec::new();
        let mut endpoints = Vec::with_capacity(binding.endpoints.len());
        for expected in &binding.endpoints {
            let file = match (&expected.kind, &expected.source) {
                (
                    LinuxServiceSetupEndpointKindV1::SealedRequestMemfd,
                    LinuxServiceSetupEndpointSourceV1::PlanSealedRequest { .. },
                ) => sealed_request.take().ok_or_else(|| {
                    failure(
                        OPERATION,
                        EffectCertainty::NotApplied,
                        "the setup closure requires more than one sealed request, and this service sealed one",
                    )
                })?,
                (
                    LinuxServiceSetupEndpointKindV1::Pipe,
                    LinuxServiceSetupEndpointSourceV1::ServicePipe,
                ) => {
                    let (endpoint, peer) = create_linux_native_service_setup_pipe(expected.access)?;
                    peers.push((expected.role, peer));
                    endpoint
                }
                _ => {
                    return Err(failure(
                        OPERATION,
                        EffectCertainty::NotApplied,
                        "setup endpoint type differs from its canonical semantic source",
                    ));
                }
            };
            endpoints.push(LinuxNativeServiceSetupEndpoint::from_retained(
                expected.clone(),
                file,
            )?);
        }
        if sealed_request.is_some() {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the setup closure has no sealed-request role for the channel this service sealed",
            ));
        }

        let authority = Self {
            binding,
            execution_root,
            cwd,
            private_state_root,
            singleton_journal_root,
            read_only_mount_sources,
            endpoints,
        };
        authority.validate_for(plan)?;
        Ok((
            authority,
            LinuxNativeServiceRetainedSetupPipePeers { peers },
        ))
    }
}

/// Compile-time check that the production setup-descriptor constructor remains
/// available with its required signature.
#[cfg(target_os = "linux")]
type LinuxNativeServiceSetupDescriptorMint = fn(
    &LinuxNativeServiceLaunchImageAuthority,
    &LinuxRetainedPerCommandDirectories,
    &Dir,
    LinuxNativeServiceSealedSetupChannel,
) -> Result<
    (
        LinuxNativeServiceSetupDescriptorCapability,
        LinuxNativeServiceRetainedSetupPipePeers,
    ),
    CgroupIoFailure,
>;

/// See [`LinuxNativeServiceSetupDescriptorMint`].
#[cfg(target_os = "linux")]
const LINUX_NATIVE_SERVICE_SETUP_DESCRIPTOR_PRODUCTION_MINT: LinuxNativeServiceSetupDescriptorMint =
    LinuxNativeServiceSetupDescriptorCapability::open_authenticated;

/// The production route from an authenticated launch-image authority to the
/// setup-descriptor authority, in one place.
///
/// It exists so the join is production code rather than a sequence only tests
/// perform, and so the next state after it has a caller to be reached from.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] on every refusal the mint or
/// `bind_linux_native_service_setup_descriptors` makes.
#[cfg(target_os = "linux")]
pub(crate) fn open_linux_native_service_setup_authority(
    launch_authority: LinuxNativeServiceLaunchImageAuthority,
    directories: &LinuxRetainedPerCommandDirectories,
    workspace_root: &Dir,
    setup_channel: LinuxNativeServiceSealedSetupChannel,
) -> Result<
    (
        LinuxNativeServiceSetupDescriptorAuthority,
        LinuxNativeServiceRetainedSetupPipePeers,
    ),
    CgroupIoFailure,
> {
    let (setup_descriptors, peers) =
        LinuxNativeServiceSetupDescriptorCapability::open_authenticated(
            &launch_authority,
            directories,
            workspace_root,
            setup_channel,
        )?;
    let authority =
        bind_linux_native_service_setup_descriptors(launch_authority, setup_descriptors)?;
    Ok((authority, peers))
}

// Read back exactly seven descriptors from the stopped child: CLOEXEC clear
// on 0..=2 and set on 3..=6. Closure mode replaces the transport on fd 0
// through the admitted `dup2` boundary; observe mode leaves it as a control.
// The parent verifies kernel descriptor state while the child is held. This
// closed internal probe accepts no caller-selected command.

/// Exact internal mode argument of the stopped-child descriptor-table probe.
const LINUX_SERVICE_CHILD_DESCRIPTOR_PROBE_ARGUMENT: &str =
    "--grok-build-linux-service-child-descriptor-probe-v1";

/// The mode that measures what each delivery mechanism can and cannot do.
#[cfg(target_os = "linux")]
const CHILD_DESCRIPTOR_PROBE_OBSERVE_MODE: &str = "observe";

/// The mode that materialises the plan's **complete** child descriptor table.
///
/// It differs from [`CHILD_DESCRIPTOR_PROBE_OBSERVE_MODE`] in exactly one step:
/// after placing every descriptor whose target is 3 or above, it installs the
/// descriptor whose target is 0 **onto fd 0** with `dup2(2)`, which replaces
/// the placement transport with the descriptor the plan puts there and leaves
/// the table closed at 0..=6. That one call is the whole difference between a
/// table that cannot be the planned table and one that is.
#[cfg(target_os = "linux")]
const CHILD_DESCRIPTOR_PROBE_CLOSURE_MODE: &str = "closure";

/// Exit code every probe-process refusal uses, matching the bootstrap probe's.
#[cfg(target_os = "linux")]
const LINUX_SERVICE_CHILD_DESCRIPTOR_PROBE_REFUSAL_CODE: u8 = 78;

/// Largest descriptor table this probe will place.
///
/// The plan's table is seven and three of those arrive as stdio, so four is the
/// working number; the bound is deliberately small and compiled, because an
/// unbounded placement list would be an argument surface.
#[cfg(target_os = "linux")]
const MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS: usize = 8;

/// Where received descriptors are staged before being placed.
///
/// Above every target this probe admits, so placing at an exact number cannot
/// collide with a descriptor waiting to be placed.
#[cfg(target_os = "linux")]
const CHILD_DESCRIPTOR_PROBE_STAGING_FLOOR: std::os::fd::RawFd = 16;

/// `O_CLOEXEC` as `/proc/<pid>/fdinfo` reports it.
///
/// `fs/proc/fd.c` re-derives this bit from the descriptor table rather than
/// echoing the open flags, so it is the child's real close-on-exec state and
/// not the flag its opener asked for.
#[cfg(target_os = "linux")]
const PROC_FDINFO_CLOEXEC: u32 = 0o2_000_000;

/// `O_ACCMODE`.
#[cfg(target_os = "linux")]
const PROC_FDINFO_ACCMODE: u32 = 0o3;

/// Runs the stopped-child descriptor-table probe when the exact internal mode
/// argument is present.
///
/// This entry point grants no authority and performs no command. It receives
/// descriptors its parent already held, places them at the numbers its parent
/// named, and stops so the parent can read the result out of procfs. A
/// non-Linux build recognizes the argument only so it can fail closed.
#[doc(hidden)]
#[must_use]
pub fn run_linux_service_child_descriptor_probe_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(LINUX_SERVICE_CHILD_DESCRIPTOR_PROBE_ARGUMENT) {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        Some(run_child_descriptor_probe(arguments))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(arguments);
        Some(std::process::ExitCode::from(78))
    }
}

#[cfg(target_os = "linux")]
fn run_child_descriptor_probe(mut arguments: std::env::ArgsOs) -> std::process::ExitCode {
    let outcome = match arguments
        .next()
        .as_deref()
        .and_then(std::ffi::OsStr::to_str)
    {
        Some(CHILD_DESCRIPTOR_PROBE_OBSERVE_MODE) => observe_child_descriptor_table(),
        Some(CHILD_DESCRIPTOR_PROBE_CLOSURE_MODE) => materialise_child_launch_closure_table(),
        _ => Err("the child descriptor probe requires one of its compiled modes".to_owned()),
    };
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(detail) => {
            eprintln!("child descriptor probe refused: {detail}");
            std::process::ExitCode::from(LINUX_SERVICE_CHILD_DESCRIPTOR_PROBE_REFUSAL_CODE)
        }
    }
}

/// Receives the placement, performs it, and stops, leaving fd 0 alone.
///
/// Every step is ordinary safe Rust performed by this process on itself, after
/// its own `execve`, and this mode makes **no** `dup2` call. The transport
/// therefore stays at fd 0, which is where the plan puts the target's standard
/// input, and the resulting table cannot be the planned table.
///
/// That is not a defect: this mode is the control that
/// [`materialise_child_launch_closure_table`] is measured against, and keeping
/// it byte-for-byte identical in every other respect is what makes the
/// comparison attributable to the one call.
#[cfg(target_os = "linux")]
fn observe_child_descriptor_table() -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    let (staged, targets) = receive_child_descriptor_placement()?;
    // Never 0, 1 or 2: in this mode those three arrive as stdio and this
    // process cannot replace them. A placement that asked it to would be asking
    // for something this mode does not do, and saying so here is better than
    // discovering it as a silent wrong answer.
    if targets.first().is_none_or(|first| *first < 3) {
        return Err(
            "the placement targets are not a strictly increasing run above stdio".to_owned(),
        );
    }

    let mut placed = Vec::with_capacity(staged.len());
    for (descriptor, target) in staged.iter().zip(&targets) {
        let target = std::os::fd::RawFd::from(*target);
        // `F_DUPFD_CLOEXEC` returns the lowest free descriptor at or above the
        // requested number, and sets close-on-exec on it. Requiring the answer
        // to be exactly the requested number is what turns "something else was
        // already there" into a refusal instead of a table one number out.
        let slot = rustix::io::fcntl_dupfd_cloexec(descriptor, target)
            .map_err(|error| format!("place a descriptor at {target}: {error}"))?;
        if slot.as_raw_fd() != target {
            return Err(format!(
                "descriptor placement asked for {target} and the kernel answered {}",
                slot.as_raw_fd()
            ));
        }
        placed.push(slot);
    }
    drop(staged);

    stop_this_probe_process()?;
    drop(placed);
    Ok(())
}

/// Materialises the plan's complete child descriptor table, then stops.
///
/// The placement's first target is **0**, and that is the whole difference
/// between this mode and the observe mode. Every target of 3 or above is placed
/// with `F_DUPFD_CLOEXEC`, so it carries close-on-exec, the clause inheritance
/// cannot meet. Fd 0 is then installed with `dup2(2)`, which closes the
/// placement transport as a side effect of overwriting it and clears
/// `FD_CLOEXEC` on the result, the clause `SCM_RIGHTS` cannot meet, and the
/// exact state the plan requires of fds 0..=2.
///
/// `dup2` is the one call here that needs `unsafe`, it is already declared and
/// already used by `linux_release_exec`, the single Linux module on the closed
/// unsafe allowlist, and it runs in an ordinary post-`execve` process, not
/// between `fork` and `exec`.
#[cfg(target_os = "linux")]
fn materialise_child_launch_closure_table() -> Result<(), String> {
    use std::os::fd::{AsFd as _, AsRawFd as _};

    let (staged, targets) = receive_child_descriptor_placement()?;
    // Exactly one descriptor may be placed onto stdio, it must be the first,
    // and it must be fd 0: fds 1 and 2 arrive as this process's own stdout and
    // stderr and are already the objects the plan names.
    if targets.first() != Some(&0) || targets.get(1).is_none_or(|second| *second < 3) {
        return Err(
            "the closure placement is not fd 0 followed by a strictly increasing run above stdio"
                .to_owned(),
        );
    }

    let mut placed = Vec::with_capacity(staged.len());
    for (descriptor, target) in staged.iter().zip(&targets).skip(1) {
        let target = std::os::fd::RawFd::from(*target);
        let slot = rustix::io::fcntl_dupfd_cloexec(descriptor, target)
            .map_err(|error| format!("place a descriptor at {target}: {error}"))?;
        if slot.as_raw_fd() != target {
            return Err(format!(
                "descriptor placement asked for {target} and the kernel answered {}",
                slot.as_raw_fd()
            ));
        }
        placed.push(slot);
    }
    // Last, because it destroys the channel every earlier step depended on.
    let stdin_source = staged
        .first()
        .ok_or_else(|| "the closure placement carries no fd 0 descriptor".to_owned())?;
    crate::linux_held_launcher::duplicate_onto(stdin_source.as_fd(), 0)
        .map_err(|error| format!("install the child's standard input at fd 0: {error}"))?;
    drop(staged);

    stop_this_probe_process()?;
    drop(placed);
    Ok(())
}

/// Stops this process so its parent can read a quiescent descriptor table.
///
/// The parent reads the table out of procfs while this process is stopped,
/// which is the only state in which the table is both complete and quiescent.
#[cfg(target_os = "linux")]
fn stop_this_probe_process() -> Result<(), String> {
    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::STOP)
        .map_err(|error| format!("stop this probe process: {error}"))
}

/// Receives one placement message and stages every descriptor it carries.
///
/// Staging happens above every target this probe admits, so placing one
/// descriptor can never be blocked by another that has not been placed yet, and
/// the descriptors the kernel chose numbers for on receipt are released before
/// any exact number is requested.
#[cfg(target_os = "linux")]
fn receive_child_descriptor_placement() -> Result<(Vec<std::os::fd::OwnedFd>, Vec<u8>), String> {
    use std::io::IoSliceMut;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd as _, OwnedFd};

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};

    let mut payload = [0_u8; MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS];
    let mut space = [MaybeUninit::uninit();
        rustix::cmsg_space!(ScmRights(MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        std::io::stdin().as_fd(),
        &mut [IoSliceMut::new(&mut payload)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|error| format!("receive the descriptor placement: {error}"))?;
    if message.flags.contains(ReturnFlags::CTRUNC) {
        return Err("the descriptor placement was truncated before its descriptors".to_owned());
    }
    let mut received: Vec<OwnedFd> = Vec::new();
    for ancillary_message in ancillary.drain() {
        match ancillary_message {
            RecvAncillaryMessage::ScmRights(fds) => received.extend(fds),
            _ => return Err("the placement channel carried a non-descriptor message".to_owned()),
        }
    }
    let targets = &payload[..message.bytes];
    if received.is_empty()
        || received.len() > MAX_CHILD_DESCRIPTOR_PROBE_PLACEMENTS
        || received.len() != targets.len()
    {
        return Err(
            "the placement names a different number of descriptors than it carries".to_owned(),
        );
    }
    // Strictly increasing, and every target below the staging floor.
    if targets
        .windows(2)
        .any(|pair| u32::from(pair[0]) >= u32::from(pair[1]))
        || targets
            .last()
            .is_none_or(|last| usize::from(*last) >= CHILD_DESCRIPTOR_PROBE_STAGING_FLOOR as usize)
    {
        return Err("the placement targets are not a strictly increasing run".to_owned());
    }

    // Stage above every target first, so placing one descriptor can never be
    // blocked by another that has not been placed yet.
    let mut staged = Vec::with_capacity(received.len());
    for descriptor in &received {
        staged.push(
            rustix::io::fcntl_dupfd_cloexec(descriptor, CHILD_DESCRIPTOR_PROBE_STAGING_FLOOR)
                .map_err(|error| format!("stage a received descriptor: {error}"))?,
        );
    }
    let targets = targets.to_vec();
    drop(received);
    Ok((staged, targets))
}
