    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{self, IoSlice, IoSliceMut, Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::path::PathBuf;
    use std::process::{Child, ChildStdout, Command, ExitCode, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use cap_fs_ext::DirExt as _;
    use cap_std::{ambient_authority, fs::Dir};
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use rustix::fs::{FileType, Mode, OFlags, RawDir, SeekFrom, fstat, open, openat, seek, statfs};
    use rustix::net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, Shutdown, SocketFlags, SocketType,
        recvmsg, sendmsg, shutdown, socketpair,
    };
    use rustix::process::{
        Pid, PidfdFlags, Signal, getpid, getppid, pidfd_open, pidfd_send_signal,
        set_parent_process_death_signal,
    };
    use serde::Serialize;
    use sha2::{Digest as _, Sha256};

    use super::{
        AttachmentDisposition, ControlEnvelope, DescriptorIdentity, ExecutableDescriptorBinding,
        ExecutableImageType, HELD_LAUNCHER_ARGUMENT, HELD_LAUNCHER_PROTOCOL_VERSION,
        HeldExecObservation, HeldExecReleaseBinding, HeldLauncherState, LauncherBinding,
        LauncherCommand, LauncherStatus, MAX_CONTROL_FRAME_BYTES, MAX_EXECUTABLE_IMAGE_BYTES,
        MAX_RELEASE_LANDLOCK_SCOPES, MAX_RELEASE_SECCOMP_SYSCALLS, ParentDescriptorBinding,
        PreparedDescriptorTable, ProtocolFailure, REQUIRED_EXECUTABLE_SEAL_BITS,
        ReleaseContainmentArtefact, ReleaseEnvironmentEntry, ReleaseExecSpec,
        ReleaseLandlockRuleset, ReleaseLandlockScope, ReleaseLandlockWitness, ReleaseSeccompFilter,
        ReleaseSeccompNamespaceFilter, ReleaseSeccompSyscall, ReleaseTargetKind, StatusEnvelope,
        decode_frame, encode_frame, validate_identity_text,
    };

    /// Fixed-role descriptors the sequence-2 prepare frame carries over
    /// `SCM_RIGHTS`.
    ///
    /// Fixed order: executable, working directory, target stdin, target
    /// stdout, target stderr, cgroup membership. The helper maps received
    /// descriptors to roles by this position and then authenticates each one
    /// against the release specification's device/inode, type, and access
    /// mode, so the ordering is a convention and never an authority.
    const RELEASE_DESCRIPTOR_COUNT: usize = 6;

    /// Every descriptor the sequence-2 frame may carry: the six fixed roles
    /// plus one per Landlock scope the committed ruleset grants beneath.
    ///
    /// A scope travels as a descriptor and never as a name. The helper is
    /// Landlock-confined by the time it matters and resolves no scope path at
    /// all; it `fstat`s what the controller passed and requires the identity
    /// the committed ruleset already names, which is the same property the
    /// plan-side mint holds over the service's own retained descriptors.
    const MAX_RELEASE_SCM_DESCRIPTOR_COUNT: usize =
        RELEASE_DESCRIPTOR_COUNT + MAX_RELEASE_LANDLOCK_SCOPES;

    const HELPER_TIMEOUT: Duration = Duration::from_secs(2);
    const STOP_POLL_INTERVAL: Duration = Duration::from_millis(1);
    const MAX_PROC_STAT_BYTES: usize = 8_192;
    const HELPER_CGROUP_FD: i32 = 2;
    const MAX_CGROUP_MEMBERSHIP_BYTES: usize = 4_096;
    const INERT_TARGET_STDIN: &[u8] = b"inert-input\n";
    const INERT_TARGET_STDOUT_PREFIX: &[u8] = b"inert-target-ok:";
    const INERT_TARGET_STDERR: &[u8] = b"inert-target-stderr\n";
    const TMPFS_SUPER_MAGIC: u64 = 0x0102_1994;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum HeldLauncherEffectCertainty {
        NotApplied,
        Ambiguous,
    }

    #[derive(Debug)]
    pub(crate) struct HeldLauncherFailure {
        pub(crate) operation: &'static str,
        pub(crate) certainty: HeldLauncherEffectCertainty,
        pub(crate) detail: String,
    }

    impl HeldLauncherFailure {
        fn not_applied(operation: &'static str, detail: impl Into<String>) -> Self {
            Self {
                operation,
                certainty: HeldLauncherEffectCertainty::NotApplied,
                detail: detail.into(),
            }
        }

        fn ambiguous(operation: &'static str, detail: impl Into<String>) -> Self {
            Self {
                operation,
                certainty: HeldLauncherEffectCertainty::Ambiguous,
                detail: detail.into(),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum HeldExecCertainty {
        NotReleased,
        PreparedAndHeld,
        ExecFailedBeforeTarget,
        ReleasedOrUnknown,
    }

    #[derive(Debug)]
    pub(crate) struct HeldExecFailure {
        pub(crate) operation: &'static str,
        pub(crate) certainty: HeldExecCertainty,
        pub(crate) detail: String,
    }

    impl HeldExecFailure {
        fn new(
            operation: &'static str,
            certainty: HeldExecCertainty,
            detail: impl Into<String>,
        ) -> Self {
            Self {
                operation,
                certainty,
                detail: detail.into(),
            }
        }

        fn not_released(operation: &'static str, detail: impl Into<String>) -> Self {
            Self::new(operation, HeldExecCertainty::NotReleased, detail)
        }

        fn prepared(operation: &'static str, detail: impl Into<String>) -> Self {
            Self::new(operation, HeldExecCertainty::PreparedAndHeld, detail)
        }

        fn exec_failed(operation: &'static str, detail: impl Into<String>) -> Self {
            Self::new(operation, HeldExecCertainty::ExecFailedBeforeTarget, detail)
        }

        fn released_unknown(operation: &'static str, detail: impl Into<String>) -> Self {
            Self::new(operation, HeldExecCertainty::ReleasedOrUnknown, detail)
        }
    }

    #[derive(Debug)]
    pub(crate) struct AuthenticatedReleaseDescriptor {
        file: File,
        expected_identity: DescriptorIdentity,
    }

    impl AuthenticatedReleaseDescriptor {
        // The native command service consumes this now: the per-command
        // containment mint in `linux_cgroup_io` passes descriptors it already
        // holds, which is the contract this constructor was kept compiled for.
        pub(crate) fn new(file: File, expected_identity: DescriptorIdentity) -> Self {
            Self {
                file,
                expected_identity,
            }
        }
    }

    #[derive(Debug)]
    pub(crate) struct AuthenticatedExecutableDescriptor {
        file: File,
        expected_identity: DescriptorIdentity,
        expected_content_sha256: String,
    }

    impl AuthenticatedExecutableDescriptor {
        // See `AuthenticatedReleaseDescriptor::new`: the command-target seal in
        // `linux_cgroup_io` is the production consumer.
        pub(crate) fn new(
            file: File,
            expected_identity: DescriptorIdentity,
            expected_content_sha256: String,
        ) -> Self {
            Self {
                file,
                expected_identity,
                expected_content_sha256,
            }
        }
    }

    /// One committed Landlock scope, joined to the descriptor it is installed
    /// through.
    ///
    /// `object_id`, `resolved_path` and `access_bits` are the plan's; the
    /// descriptor is the controller's own retained one. Neither half can stand
    /// in for the other: the digest covers the plan's fields and the install
    /// covers the descriptor, and `build_containment_artefact` refuses unless
    /// the descriptor's live `fstat` identity is what the committed digest was
    /// taken over.
    #[derive(Debug)]
    pub(crate) struct AuthenticatedLandlockScope {
        pub(crate) object_id: String,
        pub(crate) resolved_path: String,
        pub(crate) access_bits: u64,
        pub(crate) descriptor: AuthenticatedReleaseDescriptor,
    }

    /// Everything one contained-command release needs to install its two
    /// kernel-control layers, as the plan committed it.
    ///
    /// The two `committed_*_sha256` fields are **inputs**, not outputs. The
    /// controller recomposes the whole artefact from live descriptors and a
    /// locally assembled BPF program and requires the canonical digests to
    /// equal these, so a scope that has been substituted, a syscall table that
    /// has been edited, or a digest that was invented is refused before the
    /// helper is told anything. That is the property plan schema v4 established
    /// for the bootstrap probes, applied to the release.
    #[derive(Debug)]
    pub(crate) struct AuthenticatedContainmentRequest {
        pub(crate) created_at_kernel_abi: u32,
        pub(crate) handled_access_bits: u64,
        pub(crate) scopes: Vec<AuthenticatedLandlockScope>,
        pub(crate) denial_witness_path: String,
        pub(crate) denial_witness_identity: DescriptorIdentity,
        pub(crate) committed_ruleset_sha256: String,
        pub(crate) audit_architecture: String,
        pub(crate) denied_syscalls: Vec<(String, i64)>,
        pub(crate) committed_filter_sha256: String,
        /// The namespace filter's committed description, added by plan schema
        /// version 5. Carried as the wire type because the controller
        /// recomposes and re-digests it exactly as it does the network filter.
        pub(crate) namespace_denied_syscalls:
            Vec<crate::linux_command_plan::LinuxSeccompNamespaceDenialV1>,
        pub(crate) committed_namespace_filter_sha256: String,
    }

    #[derive(Debug)]
    pub(crate) struct HeldExecRequest {
        pub(crate) executable: AuthenticatedExecutableDescriptor,
        pub(crate) working_directory: AuthenticatedReleaseDescriptor,
        pub(crate) target_stdin: AuthenticatedReleaseDescriptor,
        pub(crate) target_stdout: AuthenticatedReleaseDescriptor,
        pub(crate) target_stderr: AuthenticatedReleaseDescriptor,
        pub(crate) argv: Vec<String>,
        pub(crate) environment: BTreeMap<String, String>,
        /// The containment artefact this release installs, when it is a
        /// contained command rather than the inert internal target.
        pub(crate) containment: Option<AuthenticatedContainmentRequest>,
    }

    #[derive(Debug)]
    pub(crate) struct PlannedHeldExec {
        pid: u32,
        process_start_time_ticks: u64,
        launch_request_hash: String,
        request: HeldExecRequest,
        specification: ReleaseExecSpec,
    }

    impl PlannedHeldExec {
        pub(crate) fn durable_binding(&self) -> HeldExecReleaseBinding {
            HeldExecReleaseBinding::from_specification(&self.specification)
        }
    }

    #[derive(Debug)]
    pub(crate) struct PreparedHeldExec {
        plan: PlannedHeldExec,
    }

    #[derive(Clone, Copy)]
    enum ReleaseDescriptorKind {
        WorkingDirectory,
        ReadableStdio,
        WritableStdio,
        CgroupMembership,
    }

    impl HeldExecRequest {
        fn build_spec(
            &self,
            cgroup_membership: &File,
            expected_cgroup_identity: DescriptorIdentity,
        ) -> Result<ReleaseExecSpec, ProtocolFailure> {
            let executable = executable_binding(&self.executable)?;
            let working_directory = descriptor_binding(
                &self.working_directory,
                ReleaseDescriptorKind::WorkingDirectory,
            )?;
            let target_stdin =
                descriptor_binding(&self.target_stdin, ReleaseDescriptorKind::ReadableStdio)?;
            let target_stdout =
                descriptor_binding(&self.target_stdout, ReleaseDescriptorKind::WritableStdio)?;
            let target_stderr =
                descriptor_binding(&self.target_stderr, ReleaseDescriptorKind::WritableStdio)?;
            let cgroup_membership = binding_for_retained_file(
                cgroup_membership,
                expected_cgroup_identity,
                ReleaseDescriptorKind::CgroupMembership,
            )?;
            let environment = self
                .environment
                .iter()
                .map(|(name, value)| ReleaseEnvironmentEntry {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect();
            let (target_kind, containment) = match &self.containment {
                None => (ReleaseTargetKind::InertInternalTest, None),
                Some(request) => (
                    ReleaseTargetKind::ContainedCommand,
                    Some(build_containment_artefact(request)?),
                ),
            };
            let mut specification = ReleaseExecSpec {
                release_spec_hash: String::new(),
                target_kind,
                executable,
                working_directory,
                target_stdin,
                target_stdout,
                target_stderr,
                cgroup_membership,
                argv: self.argv.clone(),
                environment,
                containment,
            };
            specification.seal_hash()?;
            specification.validate()?;
            Ok(specification)
        }

        /// The scope descriptors this release passes over `SCM_RIGHTS`, in the
        /// committed ruleset's own order.
        fn landlock_scope_descriptors(&self) -> Vec<BorrowedFd<'_>> {
            self.containment.as_ref().map_or_else(Vec::new, |request| {
                request
                    .scopes
                    .iter()
                    .map(|scope| scope.descriptor.file.as_fd())
                    .collect()
            })
        }

        fn revalidate_against_spec(
            &self,
            cgroup_membership: &File,
            expected_cgroup_identity: DescriptorIdentity,
            expected: &ReleaseExecSpec,
        ) -> Result<(), ProtocolFailure> {
            let observed = self.build_spec(cgroup_membership, expected_cgroup_identity)?;
            if &observed != expected {
                return Err(ProtocolFailure::new(
                    "controller-retained release descriptors changed after helper preparation",
                ));
            }
            Ok(())
        }
    }

    /// Recomposes one contained release's artefact from live descriptors and a
    /// locally assembled filter, and requires it to be the artefact the plan
    /// committed.
    ///
    /// Nothing here is copied from the request except the plan's own
    /// non-measurable fields — the object identifiers, the resolved paths, the
    /// access bits, the syscall table, the ABI and the architecture. Every
    /// measurable field is re-measured: each scope identity is this process's
    /// `fstat` of the descriptor it will pass, and `program_sha256` /
    /// `instruction_count` come from a BPF program this function assembles.
    /// The two committed digests are then equalities rather than inputs, so a
    /// substituted scope, an edited syscall table, and an invented digest are
    /// all one refusal.
    #[allow(clippy::too_many_lines, reason = "one artefact joins each measured scope and both independently assembled kernel filters without splitting their equality checks")]
    fn build_containment_artefact(
        request: &AuthenticatedContainmentRequest,
    ) -> Result<ReleaseContainmentArtefact, ProtocolFailure> {
        if request.scopes.is_empty() || request.scopes.len() > MAX_RELEASE_LANDLOCK_SCOPES {
            return Err(ProtocolFailure::new(
                "release containment grants no scope or exceeds its hard scope bound",
            ));
        }
        let mut scopes = Vec::with_capacity(request.scopes.len());
        for scope in &request.scopes {
            let metadata = fstat(&scope.descriptor.file).map_err(|error| {
                ProtocolFailure::new(format!("inspect release containment scope: {error}"))
            })?;
            let identity = descriptor_identity(&scope.descriptor.file).map_err(|error| {
                ProtocolFailure::new(format!(
                    "inspect release containment scope identity: {error}"
                ))
            })?;
            if identity != scope.descriptor.expected_identity {
                return Err(ProtocolFailure::new(
                    "release containment scope descriptor identity differs from authenticated authority",
                ));
            }
            if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
                return Err(ProtocolFailure::new(
                    "release containment scope descriptor is not a directory",
                ));
            }
            scopes.push(ReleaseLandlockScope {
                object_id: scope.object_id.clone(),
                resolved_path: scope.resolved_path.clone(),
                identity,
                access_bits: scope.access_bits,
            });
        }
        let landlock = ReleaseLandlockRuleset {
            created_at_kernel_abi: request.created_at_kernel_abi,
            handled_access_bits: request.handled_access_bits,
            scopes,
            denial_witness: ReleaseLandlockWitness {
                resolved_path: request.denial_witness_path.clone(),
                identity: request.denial_witness_identity,
            },
            ruleset_sha256: request.committed_ruleset_sha256.clone(),
        };
        if landlock.ruleset_sha256 != landlock.canonical_digest() {
            return Err(ProtocolFailure::new(
                "the ruleset composed from live scope descriptors is not the ruleset the plan committed",
            ));
        }
        let denied_syscalls = request
            .denied_syscalls
            .iter()
            .map(|(name, number)| ReleaseSeccompSyscall {
                name: name.clone(),
                number: *number,
            })
            .collect::<Vec<_>>();
        if denied_syscalls.is_empty() || denied_syscalls.len() > MAX_RELEASE_SECCOMP_SYSCALLS {
            return Err(ProtocolFailure::new(
                "release containment denies no syscall or exceeds its hard syscall bound",
            ));
        }
        let program =
            assemble_release_seccomp_program(&denied_syscalls, &request.audit_architecture)?;
        let seccomp = ReleaseSeccompFilter {
            audit_architecture: request.audit_architecture.clone(),
            default_action: "kill-process".to_owned(),
            denied_syscalls,
            instruction_count: u64::try_from(program.len()).map_err(|_| {
                ProtocolFailure::new("assembled release filter length does not fit u64")
            })?,
            program_sha256: seccomp_program_digest(&program),
            filter_sha256: request.committed_filter_sha256.clone(),
        };
        if seccomp.filter_sha256 != seccomp.canonical_digest() {
            return Err(ProtocolFailure::new(
                "the filter assembled from the committed syscall table is not the filter the plan committed",
            ));
        }
        let namespace_program = assemble_release_namespace_program(
            &request.namespace_denied_syscalls,
            &request.audit_architecture,
        )?;
        let seccomp_namespace = ReleaseSeccompNamespaceFilter {
            audit_architecture: request.audit_architecture.clone(),
            action: "errno-not-implemented".to_owned(),
            denied_syscalls: request.namespace_denied_syscalls.clone(),
            instruction_count: u64::try_from(namespace_program.len()).map_err(|_| {
                ProtocolFailure::new("assembled namespace filter length does not fit u64")
            })?,
            program_sha256: seccomp_program_digest(&namespace_program),
            filter_sha256: request.committed_namespace_filter_sha256.clone(),
        };
        if seccomp_namespace.filter_sha256 != seccomp_namespace.canonical_digest() {
            return Err(ProtocolFailure::new(
                "the namespace filter assembled from the committed table is not the filter the plan committed",
            ));
        }
        Ok(ReleaseContainmentArtefact {
            landlock,
            seccomp,
            seccomp_namespace,
        })
    }

    /// Assembles the committed namespace list with the single shared assembler.
    ///
    /// The controller rebuilds the program from the plan's own description and
    /// requires the digest to match, so an edited table or an invented digest
    /// is refused before the helper is told anything. The bytes come from
    /// [`crate::linux_command_plan::assemble_namespace_program`], the same
    /// function the mint used when it sealed the digest.
    fn assemble_release_namespace_program(
        denied: &[crate::linux_command_plan::LinuxSeccompNamespaceDenialV1],
        audit_architecture: &str,
    ) -> Result<seccompiler::BpfProgram, ProtocolFailure> {
        let architecture = crate::linux_command_plan::audit_architecture_from_tag(
            audit_architecture,
        )
        .ok_or_else(|| {
            ProtocolFailure::new(
                "release namespace filter names no audit architecture this launcher can assemble",
            )
        })?;
        crate::linux_command_plan::assemble_namespace_program(denied, architecture)
            .map_err(ProtocolFailure::new)
    }

    /// Assembles the exact BPF program one committed syscall table compiles to.
    ///
    /// The unmatched action is `Allow` and the matched action is
    /// `KillProcess` — the only matched action a plan may commit, unchanged
    /// since schema version 2. Both the controller and the released helper run
    /// this same function over the same table and both require the resulting
    /// digest to equal the plan's `program_sha256`, so the two peers agree
    /// instruction for instruction without exchanging a program.
    fn assemble_release_seccomp_program(
        denied: &[ReleaseSeccompSyscall],
        audit_architecture: &str,
    ) -> Result<seccompiler::BpfProgram, ProtocolFailure> {
        let target = match audit_architecture {
            "audit-arch-aarch64" => seccompiler::TargetArch::aarch64,
            "audit-arch-x86-64" => seccompiler::TargetArch::x86_64,
            _ => {
                return Err(ProtocolFailure::new(
                    "release filter names no audit architecture this launcher can assemble",
                ));
            }
        };
        let rules = denied
            .iter()
            .map(|syscall| (syscall.number, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        if rules.len() != denied.len() {
            return Err(ProtocolFailure::new(
                "release filter denies the same syscall number twice",
            ));
        }
        let filter = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::KillProcess,
            target,
        )
        .map_err(|error| {
            ProtocolFailure::new(format!("compile release seccomp filter: {error}"))
        })?;
        seccompiler::BpfProgram::try_from(filter).map_err(|error| {
            ProtocolFailure::new(format!("assemble release seccomp filter: {error}"))
        })
    }

    /// The digest of one assembled BPF program, over its instructions in order.
    ///
    /// **This must reproduce the plan's preimage exactly**, because the whole
    /// point of `program_sha256` travelling on the wire is that the controller
    /// and the plan agree instruction for instruction without exchanging a
    /// program. The canonical preimage is the domain separator, instruction
    /// count as big-endian `u64`, then each instruction's `code`, `jt`, `jf`,
    /// and `k`. The controller must compare this digest with one independently
    /// minted by the plan; deriving both sides here would not prove agreement.
    fn seccomp_program_digest(program: &seccompiler::BpfProgram) -> String {
        let mut hasher = Sha256::new();
        hasher.update(crate::linux_cgroup_io::SECCOMP_PROGRAM_DIGEST_DOMAIN);
        hasher.update((program.len() as u64).to_be_bytes());
        for instruction in program {
            hasher.update(instruction.code.to_be_bytes());
            hasher.update(instruction.jt.to_be_bytes());
            hasher.update(instruction.jf.to_be_bytes());
            hasher.update(instruction.k.to_be_bytes());
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "{byte:02x}");
        }
        encoded
    }

    fn executable_binding(
        descriptor: &AuthenticatedExecutableDescriptor,
    ) -> Result<ExecutableDescriptorBinding, ProtocolFailure> {
        let metadata = fstat(&descriptor.file)
            .map_err(|error| ProtocolFailure::new(format!("inspect executable: {error}")))?;
        let identity = descriptor_identity(&descriptor.file)
            .map_err(|error| ProtocolFailure::new(format!("inspect executable: {error}")))?;
        if identity != descriptor.expected_identity
            || !FileType::from_raw_mode(metadata.st_mode).is_file()
            || metadata.st_mode & 0o111 == 0
        {
            return Err(ProtocolFailure::new(
                "executable descriptor identity, regular-file type, or execute mode differs from authenticated authority",
            ));
        }
        let byte_len = u64::try_from(metadata.st_size).map_err(|_| {
            ProtocolFailure::new("executable byte length is negative or does not fit u64")
        })?;
        if byte_len == 0 || byte_len > MAX_EXECUTABLE_IMAGE_BYTES {
            return Err(ProtocolFailure::new(
                "executable byte length is zero or exceeds its hard bound",
            ));
        }
        require_memfd_filesystem(&descriptor.file)?;
        let seals = rustix::fs::fcntl_get_seals(&descriptor.file)
            .map_err(|error| ProtocolFailure::new(format!("inspect executable seals: {error}")))?;
        let required = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::FUTURE_WRITE
            | rustix::fs::SealFlags::EXEC;
        if required.bits() != REQUIRED_EXECUTABLE_SEAL_BITS || seals != required {
            return Err(ProtocolFailure::new(
                "executable memfd differs from the exact seal/write/future-write/grow/shrink/exec seal set",
            ));
        }
        let content_sha256 = hash_file_exact(&descriptor.file, byte_len)?;
        if content_sha256 != descriptor.expected_content_sha256 {
            return Err(ProtocolFailure::new(
                "executable content digest differs from authenticated authority",
            ));
        }
        Ok(ExecutableDescriptorBinding {
            authority: parent_descriptor_binding(&descriptor.file, identity)?,
            image_type: ExecutableImageType::SealedMemfd,
            byte_len,
            content_sha256,
            seal_bits: seals.bits(),
        })
    }

    fn descriptor_binding(
        descriptor: &AuthenticatedReleaseDescriptor,
        kind: ReleaseDescriptorKind,
    ) -> Result<ParentDescriptorBinding, ProtocolFailure> {
        binding_for_retained_file(&descriptor.file, descriptor.expected_identity, kind)
    }

    fn binding_for_retained_file(
        file: &File,
        expected_identity: DescriptorIdentity,
        kind: ReleaseDescriptorKind,
    ) -> Result<ParentDescriptorBinding, ProtocolFailure> {
        let metadata = fstat(file).map_err(|error| {
            ProtocolFailure::new(format!("inspect release descriptor: {error}"))
        })?;
        let identity = descriptor_identity(file).map_err(|error| {
            ProtocolFailure::new(format!("inspect release descriptor identity: {error}"))
        })?;
        if identity != expected_identity {
            return Err(ProtocolFailure::new(
                "release descriptor identity differs from authenticated authority",
            ));
        }
        let flags = rustix::fs::fcntl_getfl(file).map_err(|error| {
            ProtocolFailure::new(format!("inspect release descriptor mode: {error}"))
        })?;
        let access = flags & OFlags::ACCMODE;
        let file_type = FileType::from_raw_mode(metadata.st_mode);
        let valid = match kind {
            ReleaseDescriptorKind::WorkingDirectory => file_type.is_dir(),
            ReleaseDescriptorKind::ReadableStdio => {
                !file_type.is_dir() && (access == OFlags::RDONLY || access == OFlags::RDWR)
            }
            ReleaseDescriptorKind::WritableStdio => {
                !file_type.is_dir() && (access == OFlags::WRONLY || access == OFlags::RDWR)
            }
            ReleaseDescriptorKind::CgroupMembership => {
                file_type.is_file() && (access == OFlags::RDONLY || access == OFlags::RDWR)
            }
        };
        if !valid {
            return Err(ProtocolFailure::new(
                "release descriptor type or access mode differs from its typed role",
            ));
        }
        parent_descriptor_binding(file, identity)
    }

    fn parent_descriptor_binding(
        file: &File,
        identity: DescriptorIdentity,
    ) -> Result<ParentDescriptorBinding, ProtocolFailure> {
        let descriptor = u32::try_from(file.as_raw_fd()).map_err(|_| {
            ProtocolFailure::new("parent release descriptor is negative or does not fit u32")
        })?;
        let binding = ParentDescriptorBinding {
            descriptor,
            identity,
        };
        binding.validate("parent release descriptor")?;
        Ok(binding)
    }

    fn require_memfd_filesystem(file: &File) -> Result<(), ProtocolFailure> {
        let filesystem = rustix::fs::fstatfs(file)
            .map_err(|error| ProtocolFailure::new(format!("inspect executable fs: {error}")))?;
        if u64::try_from(filesystem.f_type).ok() != Some(TMPFS_SUPER_MAGIC) {
            return Err(ProtocolFailure::new(
                "executable authority is not a sealed memfd/shmem image",
            ));
        }
        Ok(())
    }

    fn hash_file_exact(file: &File, byte_len: u64) -> Result<String, ProtocolFailure> {
        use std::os::unix::fs::FileExt as _;

        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        // Use a fixed 32 KiB buffer to avoid heap allocation failure while
        // authenticated descriptors are held.
        #[expect(
            clippy::large_stack_arrays,
            reason = "fixed 32 KiB read buffer chosen over a heap allocation inside an authenticated fail-closed path"
        )]
        let mut buffer = [0_u8; 32 * 1_024];
        while offset < byte_len {
            let remaining = byte_len - offset;
            let buffer_len = u64::try_from(buffer.len())
                .map_err(|_| ProtocolFailure::new("hash buffer length does not fit u64"))?;
            let maximum = usize::try_from(remaining.min(buffer_len))
                .map_err(|_| ProtocolFailure::new("executable hash length does not fit usize"))?;
            let count = file
                .read_at(&mut buffer[..maximum], offset)
                .map_err(|error| ProtocolFailure::new(format!("hash executable: {error}")))?;
            if count == 0 {
                return Err(ProtocolFailure::new(
                    "executable ended before its authenticated byte length",
                ));
            }
            hasher.update(&buffer[..count]);
            offset = offset
                .checked_add(u64::try_from(count).map_err(|_| {
                    ProtocolFailure::new("executable hash read count does not fit u64")
                })?)
                .ok_or_else(|| ProtocolFailure::new("executable hash offset overflow"))?;
        }
        Ok(super::encode_hex(&hasher.finalize()))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ProcessRecoveryObservation {
        Absent,
        ExactLive,
        PidReused,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct ProcessObservation {
        pub(super) state: u8,
        pub(super) parent_pid: u32,
        pub(super) start_time_ticks: u64,
    }

    impl ProcessObservation {
        const fn held(self) -> bool {
            self.state == b'T'
        }
    }

    #[derive(Debug)]
    pub(crate) struct LinuxProcfs {
        root: Dir,
        root_identity: DescriptorIdentity,
        self_executable_identity: DescriptorIdentity,
    }

    impl LinuxProcfs {
        pub(crate) fn open_authenticated() -> Result<Self, HeldLauncherFailure> {
            let root = Dir::open_ambient_dir("/proc", ambient_authority()).map_err(|error| {
                HeldLauncherFailure::not_applied("open-procfs", error.to_string())
            })?;
            require_procfs(&root, "authenticate-procfs")?;
            let root_identity = descriptor_identity(&root).map_err(|error| {
                HeldLauncherFailure::not_applied("authenticate-procfs", error.to_string())
            })?;
            let self_executable_identity = open_proc_magic_identity(&root, "self/exe")?;
            Ok(Self {
                root,
                root_identity,
                self_executable_identity,
            })
        }

        fn validate(&self) -> Result<(), HeldLauncherFailure> {
            require_procfs(&self.root, "revalidate-procfs")?;
            let identity = descriptor_identity(&self.root).map_err(|error| {
                HeldLauncherFailure::not_applied("revalidate-procfs", error.to_string())
            })?;
            if identity != self.root_identity {
                return Err(HeldLauncherFailure::not_applied(
                    "revalidate-procfs",
                    "retained procfs root identity drifted",
                ));
            }
            Ok(())
        }

        /// Retains the exact executable image of this authenticated service
        /// process through genuine procfs.
        ///
        /// The returned descriptor is read-only and is rejoined to
        /// `self/exe` by [`Self::require_self_executable`] before native-service
        /// admission or mechanics may rely on it.
        pub(crate) fn retain_self_executable(
            &self,
        ) -> Result<(std::fs::File, DescriptorIdentity), HeldLauncherFailure> {
            self.validate()?;
            let descriptor = openat(
                &self.root,
                "self/exe",
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                HeldLauncherFailure::not_applied(
                    "open-native-service-self-executable",
                    error.to_string(),
                )
            })?;
            let identity = descriptor_identity(&descriptor).map_err(|error| {
                HeldLauncherFailure::not_applied(
                    "inspect-native-service-self-executable",
                    error.to_string(),
                )
            })?;
            if identity != self.self_executable_identity {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-native-service-self-executable",
                    "current process executable changed after procfs authentication",
                ));
            }
            Ok((std::fs::File::from(descriptor), identity))
        }

        /// Revalidates that one retained image is still the executable of this
        /// exact service process.
        pub(crate) fn require_self_executable(
            &self,
            expected: DescriptorIdentity,
        ) -> Result<(), HeldLauncherFailure> {
            self.validate()?;
            let observed = open_proc_magic_identity(&self.root, "self/exe")?;
            if observed != self.self_executable_identity || observed != expected {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-native-service-self-executable",
                    "retained image is not the current authenticated service executable",
                ));
            }
            Ok(())
        }

        /// Returns the kernel-reported absolute name of this exact service
        /// executable while proving that `self/exe` did not cross identities
        /// around the readlink observation.
        ///
        /// The returned name is observation data, not authority. Callers must
        /// open it descriptor-relatively without following links and compare
        /// the resulting descriptor with `expected` before retaining it.
        pub(crate) fn self_executable_path(
            &self,
            expected: DescriptorIdentity,
        ) -> Result<PathBuf, HeldLauncherFailure> {
            self.validate()?;
            let before = open_proc_magic_identity(&self.root, "self/exe")?;
            if before != self.self_executable_identity || before != expected {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-native-service-self-executable-path",
                    "procfs self/exe identity crossed before its name was observed",
                ));
            }
            let path = self.root.read_link_contents("self/exe").map_err(|error| {
                HeldLauncherFailure::not_applied(
                    "observe-native-service-self-executable-path",
                    error.to_string(),
                )
            })?;
            let after = open_proc_magic_identity(&self.root, "self/exe")?;
            if after != before {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-native-service-self-executable-path",
                    "procfs self/exe identity crossed while its name was observed",
                ));
            }
            Ok(path)
        }

        fn process_directory(&self, pid: u32) -> Result<Option<Dir>, HeldLauncherFailure> {
            self.validate()?;
            match self.root.open_dir_nofollow(pid.to_string()) {
                Ok(directory) => Ok(Some(directory)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(HeldLauncherFailure::not_applied(
                    "open-proc-process",
                    error.to_string(),
                )),
            }
        }

        fn observe_process(
            &self,
            pid: u32,
        ) -> Result<Option<ProcessObservation>, HeldLauncherFailure> {
            let Some(directory) = self.process_directory(pid)? else {
                return Ok(None);
            };
            let mut options = cap_std::fs::OpenOptions::new();
            options.read(true);
            let file = directory.open_with("stat", &options).map_err(|error| {
                HeldLauncherFailure::not_applied("open-proc-stat", error.to_string())
            })?;
            let bytes = read_bounded(file.into_std(), MAX_PROC_STAT_BYTES).map_err(|error| {
                HeldLauncherFailure::not_applied("read-proc-stat", error.to_string())
            })?;
            parse_proc_stat(&bytes, pid)
                .map(Some)
                .map_err(|error| HeldLauncherFailure::not_applied("parse-proc-stat", error.detail))
        }

        pub(crate) fn recovery_observation(
            &self,
            pid: u32,
            expected_start_time_ticks: u64,
        ) -> Result<ProcessRecoveryObservation, HeldLauncherFailure> {
            match self.observe_process(pid)? {
                None => Ok(ProcessRecoveryObservation::Absent),
                Some(observation) if observation.start_time_ticks == expected_start_time_ticks => {
                    Ok(ProcessRecoveryObservation::ExactLive)
                }
                Some(_) => Ok(ProcessRecoveryObservation::PidReused),
            }
        }

        fn require_exact_process(
            &self,
            pid: u32,
            expected_start_time_ticks: u64,
        ) -> Result<ProcessObservation, HeldLauncherFailure> {
            let observation = self.observe_process(pid)?.ok_or_else(|| {
                HeldLauncherFailure::not_applied(
                    "authenticate-held-launcher",
                    "launcher process is absent",
                )
            })?;
            if observation.start_time_ticks != expected_start_time_ticks {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-held-launcher",
                    "launcher PID was reused with a different start time",
                ));
            }
            Ok(observation)
        }

        fn require_process_executable(
            &self,
            pid: u32,
            expected: DescriptorIdentity,
        ) -> Result<(), HeldLauncherFailure> {
            let identity = open_proc_magic_identity(&self.root, &format!("{pid}/exe"))?;
            if identity != expected {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-process-executable",
                    "process executable differs from the exact retained image identity",
                ));
            }
            Ok(())
        }

        fn require_process_descriptor(
            &self,
            pid: u32,
            descriptor: i32,
            expected: DescriptorIdentity,
        ) -> Result<(), HeldLauncherFailure> {
            let directory = self.process_directory(pid)?.ok_or_else(|| {
                HeldLauncherFailure::not_applied(
                    "authenticate-launcher-descriptor",
                    "launcher process is absent",
                )
            })?;
            let opened = openat(
                &directory,
                format!("fd/{descriptor}"),
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                HeldLauncherFailure::not_applied(
                    "authenticate-launcher-descriptor",
                    error.to_string(),
                )
            })?;
            let actual = descriptor_identity(&opened).map_err(|error| {
                HeldLauncherFailure::not_applied(
                    "authenticate-launcher-descriptor",
                    error.to_string(),
                )
            })?;
            if actual != expected {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-launcher-descriptor",
                    "process descriptor identity drifted from retained authority",
                ));
            }
            Ok(())
        }

        fn require_process_standard_descriptors(
            &self,
            pid: u32,
            expected: [DescriptorIdentity; 3],
        ) -> Result<(), HeldLauncherFailure> {
            for (descriptor, identity) in expected.into_iter().enumerate() {
                self.require_process_descriptor(
                    pid,
                    i32::try_from(descriptor).map_err(|_| {
                        HeldLauncherFailure::not_applied(
                            "authenticate-target-stdio",
                            "standard descriptor index does not fit i32",
                        )
                    })?,
                    identity,
                )?;
            }
            Ok(())
        }

        fn require_process_descriptor_set(
            &self,
            pid: u32,
            expected: &[i32],
        ) -> Result<(), HeldLauncherFailure> {
            let directory = self.process_directory(pid)?.ok_or_else(|| {
                HeldLauncherFailure::not_applied(
                    "authenticate-process-fd-table",
                    "process disappeared before descriptor-table inspection",
                )
            })?;
            let descriptor_table = openat(
                &directory,
                "fd",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                HeldLauncherFailure::not_applied("authenticate-process-fd-table", error.to_string())
            })?;
            let mut buffer = [MaybeUninit::uninit(); 4_096];
            let mut actual = BTreeSet::new();
            let mut entries = RawDir::new(&descriptor_table, &mut buffer);
            while let Some(entry) = entries.next() {
                let entry = entry.map_err(|error| {
                    HeldLauncherFailure::not_applied(
                        "authenticate-process-fd-table",
                        error.to_string(),
                    )
                })?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let descriptor = std::str::from_utf8(name)
                    .ok()
                    .and_then(|value| value.parse::<i32>().ok())
                    .filter(|value| *value >= 0)
                    .ok_or_else(|| {
                        HeldLauncherFailure::not_applied(
                            "authenticate-process-fd-table",
                            "process fd table contains a noncanonical descriptor name",
                        )
                    })?;
                actual.insert(descriptor);
            }
            let expected = expected.iter().copied().collect::<BTreeSet<_>>();
            if actual != expected {
                return Err(HeldLauncherFailure::not_applied(
                    "authenticate-process-fd-table",
                    format!("process descriptor set was {actual:?}, expected {expected:?}"),
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct HeldLauncherSession {
        child: Child,
        pid: Pid,
        pidfd: rustix::fd::OwnedFd,
        process_start_time_ticks: u64,
        binding: LauncherBinding,
        helper_executable_identity: DescriptorIdentity,
        cgroup_membership: File,
        control_identity: DescriptorIdentity,
        status_identity: DescriptorIdentity,
        control: OwnedFd,
        status: ChildStdout,
        state: HeldLauncherState,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct HeldLauncherExpectation<'a> {
        pub(crate) pid: u32,
        pub(crate) process_start_time_ticks: u64,
        pub(crate) launch_request_hash: &'a str,
        pub(crate) leaf_identity: DescriptorIdentity,
        pub(crate) cgroup_procs_identity: DescriptorIdentity,
    }

    struct AuthenticatedLauncher {
        pid: Pid,
        pidfd: rustix::fd::OwnedFd,
        process_start_time_ticks: u64,
        control_identity: DescriptorIdentity,
        status_identity: DescriptorIdentity,
        control: OwnedFd,
        status: ChildStdout,
    }

    impl HeldLauncherSession {
        fn identity_matches(&self, expected: HeldLauncherExpectation<'_>) -> bool {
            self.child.id() == expected.pid
                && u32::try_from(self.pid.as_raw_pid()).ok() == Some(expected.pid)
                && self.process_start_time_ticks == expected.process_start_time_ticks
                && self.binding.launch_request_hash == expected.launch_request_hash
                && self.binding.leaf_identity == expected.leaf_identity
                && self.binding.cgroup_procs_identity == expected.cgroup_procs_identity
        }

        fn ensure_live_exact(
            &mut self,
            procfs: &LinuxProcfs,
            require_hold: bool,
        ) -> Result<ProcessObservation, HeldLauncherFailure> {
            if pidfd_has_exited(&self.pidfd)? {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "pidfd reports that the held launcher exited",
                ));
            }
            if self
                .child
                .try_wait()
                .map_err(|error| {
                    HeldLauncherFailure::not_applied("inspect-held-launcher", error.to_string())
                })?
                .is_some()
            {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "held launcher has exited",
                ));
            }
            let observation =
                procfs.require_exact_process(self.child.id(), self.process_start_time_ticks)?;
            let controller_pid = u32::try_from(getpid().as_raw_pid()).map_err(|_| {
                HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "controller PID does not fit the protocol",
                )
            })?;
            if observation.parent_pid != controller_pid {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "held launcher is no longer parented by this controller",
                ));
            }
            if require_hold && !observation.held() {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher-hold",
                    "kernel process state does not prove a SIGSTOP hold",
                ));
            }
            procfs.require_process_executable(self.child.id(), self.helper_executable_identity)?;
            procfs.require_process_descriptor(
                self.child.id(),
                HELPER_CGROUP_FD,
                self.binding.cgroup_procs_identity,
            )?;
            let confirmed =
                procfs.require_exact_process(self.child.id(), self.process_start_time_ticks)?;
            if confirmed.parent_pid != controller_pid
                || (require_hold && !confirmed.held())
                || pidfd_has_exited(&self.pidfd)?
            {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "launcher identity, parent, liveness, or hold changed during inspection",
                ));
            }
            Ok(confirmed)
        }

        fn self_attach(
            &mut self,
            procfs: &LinuxProcfs,
            exact_value: &[u8],
        ) -> Result<(), HeldLauncherFailure> {
            let disposition = self.state.attachment_disposition().map_err(|error| {
                HeldLauncherFailure::not_applied("self-attach-held-launcher", error.detail)
            })?;
            self.ensure_live_exact(procfs, true)?;
            if exact_value != b"0\n" {
                return Err(HeldLauncherFailure::not_applied(
                    "self-attach-held-launcher",
                    "only the exact literal 0\\n self-write is permitted",
                ));
            }
            if disposition == AttachmentDisposition::ReconcileAlreadyApplied {
                return Ok(());
            }
            let request = ControlEnvelope {
                protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
                sequence: 1,
                binding: self.binding.clone(),
                command: LauncherCommand::SelfAttach {
                    exact_value: exact_value.to_vec(),
                },
            };
            let bytes = encode_frame(&request).map_err(|error| {
                HeldLauncherFailure::not_applied("encode-launcher-command", error.detail)
            })?;
            if let Err(error) = queue_atomic_frame(&self.control, &bytes) {
                self.terminate_ambiguous();
                return Err(HeldLauncherFailure::ambiguous(
                    "queue-launcher-command",
                    error,
                ));
            }

            if let Err(error) = pidfd_send_signal(&self.pidfd, Signal::CONT) {
                self.terminate_ambiguous();
                return Err(HeldLauncherFailure::ambiguous(
                    "resume-held-launcher",
                    error.to_string(),
                ));
            }
            let post_resume = (|| {
                let response_bytes = read_frame_with_timeout(&mut self.status, HELPER_TIMEOUT)
                    .map_err(|error| {
                        HeldLauncherFailure::ambiguous(
                            "read-launcher-attachment",
                            error.to_string(),
                        )
                    })?;
                let response: StatusEnvelope = decode_frame(&response_bytes).map_err(|error| {
                    HeldLauncherFailure::ambiguous("decode-launcher-attachment", error.detail)
                })?;
                response
                    .validate_attached(&self.binding, self.child.id())
                    .map_err(|error| {
                        HeldLauncherFailure::ambiguous("validate-launcher-attachment", error.detail)
                    })?;
                // Wait for the helper's own SIGSTOP before asserting the controller hold.
                // Otherwise SIGCONT can resume it into a second stop and strand the release.
                // The controller still asserts the hold and verifies kernel process state.
                wait_for_stopped(
                    &mut self.child,
                    &self.pidfd,
                    procfs,
                    self.process_start_time_ticks,
                    HELPER_TIMEOUT,
                )
                .map_err(|error| {
                    HeldLauncherFailure::ambiguous("observe-launcher-self-hold", error.detail)
                })?;
                pidfd_send_signal(&self.pidfd, Signal::STOP).map_err(|error| {
                    HeldLauncherFailure::ambiguous("reassert-launcher-hold", error.to_string())
                })?;
                wait_for_stopped(
                    &mut self.child,
                    &self.pidfd,
                    procfs,
                    self.process_start_time_ticks,
                    HELPER_TIMEOUT,
                )
                .map_err(|error| {
                    HeldLauncherFailure::ambiguous("reestablish-launcher-hold", error.detail)
                })?;
                self.ensure_live_exact(procfs, true).map_err(|error| {
                    HeldLauncherFailure::ambiguous("revalidate-attached-launcher", error.detail)
                })?;
                Ok(())
            })();
            if let Err(error) = post_resume {
                self.terminate_ambiguous();
                return Err(error);
            }
            self.state = HeldLauncherState::attached();
            Ok(())
        }

        fn plan_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            request: HeldExecRequest,
        ) -> Result<PlannedHeldExec, HeldExecFailure> {
            self.state.require_release_plan().map_err(|error| {
                HeldExecFailure::not_released("plan-held-launcher-release", error.detail)
            })?;
            self.ensure_live_exact(procfs, true).map_err(|error| {
                HeldExecFailure::not_released("authenticate-release-plan-hold", error.detail)
            })?;
            require_exact_cgroup_member(
                &mut self.cgroup_membership,
                self.child.id(),
                "revalidate-release-plan-membership",
            )
            .map_err(|error| {
                HeldExecFailure::not_released("revalidate-release-plan-membership", error.detail)
            })?;
            let specification = request
                .build_spec(&self.cgroup_membership, self.binding.cgroup_procs_identity)
                .map_err(|error| {
                    HeldExecFailure::not_released(
                        "authenticate-release-plan-authority",
                        error.detail,
                    )
                })?;
            self.state = HeldLauncherState::ReleasePlannedAndHeld;
            Ok(PlannedHeldExec {
                pid: self.child.id(),
                process_start_time_ticks: self.process_start_time_ticks,
                launch_request_hash: self.binding.launch_request_hash.clone(),
                request,
                specification,
            })
        }

        #[allow(clippy::too_many_lines)]
        fn prepare_planned_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            plan: PlannedHeldExec,
        ) -> Result<PreparedHeldExec, HeldExecFailure> {
            self.state.require_helper_preparation().map_err(|error| {
                HeldExecFailure::not_released("prepare-held-launcher-release", error.detail)
            })?;
            self.require_plan_identity(&plan)?;
            self.ensure_live_exact(procfs, true).map_err(|error| {
                HeldExecFailure::not_released("authenticate-planned-release-hold", error.detail)
            })?;
            plan.request
                .revalidate_against_spec(
                    &self.cgroup_membership,
                    self.binding.cgroup_procs_identity,
                    &plan.specification,
                )
                .map_err(|error| {
                    self.terminate_ambiguous();
                    HeldExecFailure::not_released(
                        "revalidate-planned-release-authority",
                        error.detail,
                    )
                })?;
            let release_spec_hash = plan.specification.release_spec_hash.clone();
            let prepare = ControlEnvelope {
                protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
                sequence: 2,
                binding: self.binding.clone(),
                command: LauncherCommand::PrepareExec {
                    specification: Box::new(plan.specification.clone()),
                },
            };
            let prepare_bytes = encode_frame(&prepare).map_err(|error| {
                HeldExecFailure::not_released("encode-release-preparation", error.detail)
            })?;
            let mut released_descriptors: Vec<BorrowedFd<'_>> = vec![
                plan.request.executable.file.as_fd(),
                plan.request.working_directory.file.as_fd(),
                plan.request.target_stdin.file.as_fd(),
                plan.request.target_stdout.file.as_fd(),
                plan.request.target_stderr.file.as_fd(),
                self.cgroup_membership.as_fd(),
            ];
            // The scope descriptors follow the six fixed roles in the committed
            // ruleset's own order, so the helper's positional mapping stays a
            // convention it authenticates rather than an authority it trusts.
            released_descriptors.extend(plan.request.landlock_scope_descriptors());
            queue_atomic_frame_with_descriptors(
                &self.control,
                &prepare_bytes,
                &released_descriptors,
            )
            .map_err(|error| {
                self.terminate_ambiguous();
                HeldExecFailure::not_released("queue-release-preparation", error)
            })?;
            if let Err(error) = pidfd_send_signal(&self.pidfd, Signal::CONT) {
                self.terminate_ambiguous();
                return Err(HeldExecFailure::prepared(
                    "resume-release-preparation",
                    error.to_string(),
                ));
            }

            let prepared_result = (|| {
                let response_bytes = read_frame_with_timeout(&mut self.status, HELPER_TIMEOUT)
                    .map_err(|error| {
                        HeldExecFailure::prepared("read-release-preparation", error.to_string())
                    })?;
                let response: StatusEnvelope = decode_frame(&response_bytes).map_err(|error| {
                    HeldExecFailure::prepared("decode-release-preparation", error.detail)
                })?;
                let descriptors = response
                    .validate_exec_prepared(&self.binding, self.child.id(), &release_spec_hash)
                    .map_err(|error| {
                        HeldExecFailure::prepared("validate-release-preparation", error.detail)
                    })?;
                // Same self-stop race as the attachment phase above: the helper
                // writes its `ExecPrepared` frame on the setup-status channel
                // and only then self-stops, so the reassert must wait for that
                // hold instead of competing with it.
                wait_for_stopped(
                    &mut self.child,
                    &self.pidfd,
                    procfs,
                    self.process_start_time_ticks,
                    HELPER_TIMEOUT,
                )
                .map_err(|error| {
                    HeldExecFailure::prepared("observe-prepared-self-hold", error.detail)
                })?;
                pidfd_send_signal(&self.pidfd, Signal::STOP).map_err(|error| {
                    HeldExecFailure::prepared("reassert-prepared-hold", error.to_string())
                })?;
                wait_for_stopped(
                    &mut self.child,
                    &self.pidfd,
                    procfs,
                    self.process_start_time_ticks,
                    HELPER_TIMEOUT,
                )
                .map_err(|error| {
                    HeldExecFailure::prepared("observe-prepared-hold", error.detail)
                })?;
                self.ensure_live_exact(procfs, true).map_err(|error| {
                    HeldExecFailure::prepared("authenticate-prepared-helper", error.detail)
                })?;
                self.validate_prepared_descriptor_table(procfs, &descriptors, &plan.specification)?;
                require_exact_cgroup_member(
                    &mut self.cgroup_membership,
                    self.child.id(),
                    "revalidate-prepared-membership",
                )
                .map_err(|error| {
                    HeldExecFailure::prepared("revalidate-prepared-membership", error.detail)
                })?;
                Ok(())
            })();
            if let Err(error) = prepared_result {
                self.terminate_ambiguous();
                return Err(error);
            }
            self.state = HeldLauncherState::ExecPreparedAndHeld;
            Ok(PreparedHeldExec { plan })
        }

        #[allow(clippy::too_many_lines)]
        fn commit_prepared_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            prepared: PreparedHeldExec,
        ) -> Result<HeldExecObservation, HeldExecFailure> {
            self.state.require_release_commit().map_err(|error| {
                HeldExecFailure::not_released("commit-held-launcher-release", error.detail)
            })?;
            self.require_plan_identity(&prepared.plan)?;
            let PreparedHeldExec { plan } = prepared;
            let PlannedHeldExec {
                request,
                specification,
                ..
            } = plan;
            let release_spec_hash = specification.release_spec_hash.clone();
            request
                .revalidate_against_spec(
                    &self.cgroup_membership,
                    self.binding.cgroup_procs_identity,
                    &specification,
                )
                .map_err(|error| {
                    self.terminate_ambiguous();
                    HeldExecFailure::prepared("revalidate-release-authority", error.detail)
                })?;
            require_exact_cgroup_member(
                &mut self.cgroup_membership,
                self.child.id(),
                "final-precommit-membership",
            )
            .map_err(|error| {
                self.terminate_ambiguous();
                HeldExecFailure::prepared("final-precommit-membership", error.detail)
            })?;
            let commit = ControlEnvelope {
                protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
                sequence: 3,
                binding: self.binding.clone(),
                command: LauncherCommand::CommitExec {
                    release_spec_hash: release_spec_hash.clone(),
                },
            };
            // Validate membership while the helper is held; the target may exit
            // immediately after exec.
            if matches!(
                specification.target_kind,
                ReleaseTargetKind::ContainedCommand
            ) {
                require_exact_cgroup_member(
                    &mut self.cgroup_membership,
                    self.child.id(),
                    "revalidate-pre-exec-membership",
                )
                .map_err(|error| {
                    self.terminate_ambiguous();
                    HeldExecFailure::prepared("revalidate-pre-exec-membership", error.detail)
                })?;
            }
            let commit_bytes = encode_frame(&commit)
                .map_err(|error| HeldExecFailure::prepared("encode-exec-commit", error.detail))?;
            queue_atomic_frame(&self.control, &commit_bytes).map_err(|error| {
                self.terminate_ambiguous();
                HeldExecFailure::prepared("queue-exec-commit", error)
            })?;
            if let Err(error) = pidfd_send_signal(&self.pidfd, Signal::CONT) {
                self.terminate_ambiguous();
                return Err(HeldExecFailure::released_unknown(
                    "commit-same-pid-exec",
                    error.to_string(),
                ));
            }

            match read_setup_outcome_with_timeout(&mut self.status, HELPER_TIMEOUT) {
                Ok(SetupStatusOutcome::Frame(bytes)) => {
                    let response: StatusEnvelope = decode_frame(&bytes).map_err(|error| {
                        self.terminate_ambiguous();
                        HeldExecFailure::released_unknown("decode-exec-failure", error.detail)
                    })?;
                    // A pre-exec refusal must not be classified as an attempted image
                    // replacement.
                    match response.exec_refusal(&self.binding, self.child.id()) {
                        Ok(Some(operation)) => {
                            self.terminate_ambiguous();
                            return Err(HeldExecFailure::not_released(
                                "install-release-containment",
                                operation,
                            ));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            self.terminate_ambiguous();
                            return Err(HeldExecFailure::released_unknown(
                                "validate-release-refusal",
                                error.detail,
                            ));
                        }
                    }
                    let operation = response
                        .validate_exec_failed(&self.binding, self.child.id(), &release_spec_hash)
                        .map_err(|error| {
                            self.terminate_ambiguous();
                            HeldExecFailure::released_unknown("validate-exec-failure", error.detail)
                        })?;
                    self.terminate_ambiguous();
                    return Err(HeldExecFailure::exec_failed(
                        "exec-descriptor-target",
                        operation,
                    ));
                }
                Ok(SetupStatusOutcome::Closed) => {}
                Err(error) => {
                    self.terminate_ambiguous();
                    return Err(HeldExecFailure::released_unknown(
                        "observe-exec-handoff",
                        error.to_string(),
                    ));
                }
            }

            // The same process installs confinement and execs the sealed target.
            // After checking refusal and exec-failure frames, CLOEXEC status-pipe closure
            // completes the release protocol. Membership was validated while held; a
            // real target need not implement the inert fixture's post-exec self-stop.
            if matches!(
                specification.target_kind,
                ReleaseTargetKind::ContainedCommand
            ) {
                self.state = HeldLauncherState::Released;
                return Ok(HeldExecObservation {
                    pid: self.child.id(),
                    process_start_time_ticks: self.process_start_time_ticks,
                    release_spec_hash,
                    executable_identity: specification.executable.authority.identity,
                    // Inherent: this pid installed the artefact and this pid
                    // exec'd the sealed image, in that order, without ever
                    // being reparented or replaced.
                    same_pid_exec_observed: true,
                    // Proven before the commit frame was queued, while the
                    // helper was guaranteed alive and held. `execveat` does not
                    // change cgroup membership, so a post-exec read would race
                    // a fast-exiting command for no additional strength.
                    cgroup_membership_revalidated: true,
                    // The target was never stopped, so there is nothing to
                    // continue. This records that it was left running, which is
                    // what the field means for this kind.
                    target_continued: true,
                });
            }

            let post_exec = (|| {
                wait_for_stopped(
                    &mut self.child,
                    &self.pidfd,
                    procfs,
                    self.process_start_time_ticks,
                    HELPER_TIMEOUT,
                )
                .map_err(|error| {
                    HeldExecFailure::released_unknown("observe-inert-target-hold", error.detail)
                })?;
                procfs
                    .require_process_executable(
                        self.child.id(),
                        specification.executable.authority.identity,
                    )
                    .map_err(|error| {
                        HeldExecFailure::released_unknown(
                            "authenticate-same-pid-exec",
                            error.detail,
                        )
                    })?;
                procfs
                    .require_process_standard_descriptors(
                        self.child.id(),
                        [
                            specification.target_stdin.identity,
                            specification.target_stdout.identity,
                            specification.target_stderr.identity,
                        ],
                    )
                    .map_err(|error| {
                        HeldExecFailure::released_unknown("authenticate-target-stdio", error.detail)
                    })?;
                procfs
                    .require_process_descriptor_set(self.child.id(), &[0, 1, 2])
                    .map_err(|error| {
                        HeldExecFailure::released_unknown(
                            "authenticate-target-fd-closure",
                            error.detail,
                        )
                    })?;
                require_exact_cgroup_member(
                    &mut self.cgroup_membership,
                    self.child.id(),
                    "revalidate-post-exec-membership",
                )
                .map_err(|error| {
                    HeldExecFailure::released_unknown(
                        "revalidate-post-exec-membership",
                        error.detail,
                    )
                })?;
                pidfd_send_signal(&self.pidfd, Signal::CONT).map_err(|error| {
                    HeldExecFailure::released_unknown("continue-inert-target", error.to_string())
                })?;
                Ok(())
            })();
            if let Err(error) = post_exec {
                self.terminate_ambiguous();
                return Err(error);
            }
            self.state = HeldLauncherState::Released;
            Ok(HeldExecObservation {
                pid: self.child.id(),
                process_start_time_ticks: self.process_start_time_ticks,
                release_spec_hash,
                executable_identity: specification.executable.authority.identity,
                same_pid_exec_observed: true,
                cgroup_membership_revalidated: true,
                target_continued: true,
            })
        }

        fn require_plan_identity(&self, plan: &PlannedHeldExec) -> Result<(), HeldExecFailure> {
            if plan.pid != self.child.id()
                || plan.process_start_time_ticks != self.process_start_time_ticks
                || plan.launch_request_hash != self.binding.launch_request_hash
            {
                return Err(HeldExecFailure::not_released(
                    "validate-held-release-plan",
                    "release plan differs from the retained pidfd/control session",
                ));
            }
            Ok(())
        }

        fn validate_prepared_descriptor_table(
            &self,
            procfs: &LinuxProcfs,
            descriptors: &PreparedDescriptorTable,
            specification: &ReleaseExecSpec,
        ) -> Result<(), HeldExecFailure> {
            // Require every scope descriptor's exact number and kernel identity.
            let committed_scopes = specification
                .containment
                .as_ref()
                .map_or(&[][..], |containment| &containment.landlock.scopes[..]);
            if committed_scopes.len() != descriptors.landlock_scopes.len() {
                return Err(HeldExecFailure::prepared(
                    "authenticate-prepared-descriptors",
                    "prepared descriptor table names a different number of containment scopes than the release commits",
                ));
            }
            let mut authenticated = descriptors
                .landlock_scopes
                .iter()
                .zip(committed_scopes)
                .map(|(descriptor, scope)| (*descriptor, scope.identity))
                .collect::<Vec<_>>();
            authenticated.extend([
                (0, self.control_identity),
                (1, self.status_identity),
                (2, self.binding.cgroup_procs_identity),
                (
                    descriptors.executable,
                    specification.executable.authority.identity,
                ),
                (
                    descriptors.working_directory,
                    specification.working_directory.identity,
                ),
                (
                    descriptors.target_stdin,
                    specification.target_stdin.identity,
                ),
                (
                    descriptors.target_stdout,
                    specification.target_stdout.identity,
                ),
                (
                    descriptors.target_stderr,
                    specification.target_stderr.identity,
                ),
                (
                    descriptors.cgroup_membership,
                    specification.cgroup_membership.identity,
                ),
                (descriptors.setup_status, self.status_identity),
            ]);
            for (descriptor, identity) in authenticated {
                let descriptor = i32::try_from(descriptor).map_err(|_| {
                    HeldExecFailure::prepared(
                        "authenticate-prepared-descriptors",
                        "prepared descriptor does not fit i32",
                    )
                })?;
                procfs
                    .require_process_descriptor(self.child.id(), descriptor, identity)
                    .map_err(|error| {
                        HeldExecFailure::prepared("authenticate-prepared-descriptors", error.detail)
                    })?;
            }
            let mut exact = vec![0, 1, 2];
            exact.extend(descriptors.all());
            let exact = exact
                .into_iter()
                .map(|descriptor| {
                    i32::try_from(descriptor).map_err(|_| {
                        HeldExecFailure::prepared(
                            "authenticate-prepared-fd-closure",
                            "prepared descriptor does not fit i32",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            procfs
                .require_process_descriptor_set(self.child.id(), &exact)
                .map_err(|error| {
                    HeldExecFailure::prepared("authenticate-prepared-fd-closure", error.detail)
                })
        }

        fn terminate_ambiguous(&mut self) {
            self.state = HeldLauncherState::ambiguous();
            let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
            let _ = bounded_reap(&mut self.child, HELPER_TIMEOUT);
        }
    }

    impl Drop for HeldLauncherSession {
        fn drop(&mut self) {
            let _ = pidfd_send_signal(&self.pidfd, Signal::KILL);
            let _ = bounded_reap(&mut self.child, HELPER_TIMEOUT);
        }
    }

    #[derive(Debug, Default)]
    pub(crate) struct HeldLauncherRegistry {
        sessions: BTreeMap<u32, HeldLauncherSession>,
    }

    impl HeldLauncherRegistry {
        // Every one of these eight is a distinct piece of the authority a
        // staged launch is bound to. Bundling them into a struct would let a
        // caller assemble a binding in one place and stage it in another, which
        // is exactly the separation this signature exists to prevent.
        #[expect(
            clippy::too_many_arguments,
            reason = "each argument is a separate piece of launch authority; bundling them would let a caller assemble a binding away from the stage that checks it"
        )]
        pub(crate) fn stage(
            &mut self,
            procfs: &LinuxProcfs,
            cgroup_procs: File,
            cgroup_membership: File,
            leaf_identity: DescriptorIdentity,
            cgroup_procs_identity: DescriptorIdentity,
            launch_request_hash: &str,
            session_nonce: String,
        ) -> Result<(u32, u64), HeldLauncherFailure> {
            self.stage_with_image(
                procfs,
                cgroup_procs,
                cgroup_membership,
                leaf_identity,
                cgroup_procs_identity,
                launch_request_hash,
                session_nonce,
                None,
            )
        }

        #[cfg(test)]
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn stage_with_test_helper_image(
            &mut self,
            procfs: &LinuxProcfs,
            cgroup_procs: File,
            cgroup_membership: File,
            leaf_identity: DescriptorIdentity,
            cgroup_procs_identity: DescriptorIdentity,
            launch_request_hash: &str,
            session_nonce: String,
            helper_executable: File,
        ) -> Result<(u32, u64), HeldLauncherFailure> {
            self.stage_with_image(
                procfs,
                cgroup_procs,
                cgroup_membership,
                leaf_identity,
                cgroup_procs_identity,
                launch_request_hash,
                session_nonce,
                Some(helper_executable),
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn stage_with_image(
            &mut self,
            procfs: &LinuxProcfs,
            cgroup_procs: File,
            cgroup_membership: File,
            leaf_identity: DescriptorIdentity,
            cgroup_procs_identity: DescriptorIdentity,
            launch_request_hash: &str,
            session_nonce: String,
            helper_executable: Option<File>,
        ) -> Result<(u32, u64), HeldLauncherFailure> {
            self.sessions
                .retain(|_, session| !matches!(session.child.try_wait(), Ok(Some(_))));
            if !self.sessions.is_empty() {
                return Err(HeldLauncherFailure::not_applied(
                    "stage-held-launcher",
                    "a retained held-launcher session is already active",
                ));
            }
            validate_identity_text("launch request hash", launch_request_hash).map_err(
                |error| HeldLauncherFailure::not_applied("stage-held-launcher", error.detail),
            )?;
            let binding = LauncherBinding {
                session_nonce,
                launch_request_hash: launch_request_hash.to_owned(),
                leaf_identity,
                cgroup_procs_identity,
            };
            binding.validate().map_err(|error| {
                HeldLauncherFailure::not_applied("stage-held-launcher", error.detail)
            })?;
            let session = spawn_held_launcher(
                procfs,
                cgroup_procs,
                cgroup_membership,
                binding,
                helper_executable,
            )?;
            let pid = session.child.id();
            let start_time = session.process_start_time_ticks;
            if self.sessions.insert(pid, session).is_some() {
                return Err(HeldLauncherFailure::not_applied(
                    "stage-held-launcher",
                    "launcher PID unexpectedly collided with an active session",
                ));
            }
            Ok((pid, start_time))
        }

        pub(crate) fn self_attach(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
            exact_value: &[u8],
        ) -> Result<(), HeldLauncherFailure> {
            let session = self.sessions.get_mut(&expected.pid).ok_or_else(|| {
                HeldLauncherFailure::not_applied(
                    "self-attach-held-launcher",
                    "no retained control session exists for the staged launcher",
                )
            })?;
            if !session.identity_matches(expected) {
                return Err(HeldLauncherFailure::not_applied(
                    "self-attach-held-launcher",
                    "staged launcher identity or descriptor binding differs from the retained session",
                ));
            }
            session.self_attach(procfs, exact_value)
        }

        pub(crate) fn inspect_held(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
        ) -> Result<bool, HeldLauncherFailure> {
            let session = self.sessions.get_mut(&expected.pid).ok_or_else(|| {
                HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "no retained control session exists; PID-only authority is forbidden",
                )
            })?;
            if !session.identity_matches(expected) {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher",
                    "launcher identity differs from the retained control session",
                ));
            }
            Ok(session.ensure_live_exact(procfs, true)?.held())
        }

        pub(crate) fn plan_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
            request: HeldExecRequest,
        ) -> Result<PlannedHeldExec, HeldExecFailure> {
            let session = self.sessions.get_mut(&expected.pid).ok_or_else(|| {
                HeldExecFailure::not_released(
                    "plan-held-launcher-release",
                    "no retained pidfd/control session exists for the staged launcher",
                )
            })?;
            if !session.identity_matches(expected) {
                return Err(HeldExecFailure::not_released(
                    "plan-held-launcher-release",
                    "staged launcher identity differs from the retained descriptor-bound session",
                ));
            }
            session.plan_inert_target(procfs, request)
        }

        pub(crate) fn prepare_planned_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
            plan: PlannedHeldExec,
        ) -> Result<PreparedHeldExec, HeldExecFailure> {
            let session = self.sessions.get_mut(&expected.pid).ok_or_else(|| {
                HeldExecFailure::not_released(
                    "prepare-held-launcher-release",
                    "no retained pidfd/control session exists for the staged launcher",
                )
            })?;
            if !session.identity_matches(expected) {
                return Err(HeldExecFailure::not_released(
                    "prepare-held-launcher-release",
                    "staged launcher identity differs from the retained descriptor-bound session",
                ));
            }
            session.prepare_planned_inert_target(procfs, plan)
        }

        pub(crate) fn commit_prepared_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
            prepared: PreparedHeldExec,
        ) -> Result<HeldExecObservation, HeldExecFailure> {
            let session = self.sessions.get_mut(&expected.pid).ok_or_else(|| {
                HeldExecFailure::not_released(
                    "commit-held-launcher-release",
                    "no retained pidfd/control session exists for the staged launcher",
                )
            })?;
            if !session.identity_matches(expected) {
                return Err(HeldExecFailure::not_released(
                    "commit-held-launcher-release",
                    "staged launcher identity differs from the retained descriptor-bound session",
                ));
            }
            session.commit_prepared_inert_target(procfs, prepared)
        }

        #[cfg(test)]
        pub(crate) fn release_inert_target(
            &mut self,
            procfs: &LinuxProcfs,
            expected: HeldLauncherExpectation<'_>,
            request: HeldExecRequest,
        ) -> Result<HeldExecObservation, HeldExecFailure> {
            let plan = self.plan_inert_target(procfs, expected, request)?;
            let prepared = self.prepare_planned_inert_target(procfs, expected, plan)?;
            self.commit_prepared_inert_target(procfs, expected, prepared)
        }

        // Keep cancellation and post-release reaping available to the launcher
        // lifecycle even in builds without production callers.
        #[allow(
            dead_code,
            reason = "held-launcher lifecycle operation, proven by canary and intentionally unwired until the native command service exists"
        )]
        pub(crate) fn cancel(
            &mut self,
            expected: HeldLauncherExpectation<'_>,
        ) -> Result<bool, HeldExecFailure> {
            let mut session = self.sessions.remove(&expected.pid).ok_or_else(|| {
                HeldExecFailure::not_released(
                    "cancel-held-launcher",
                    "no retained pidfd authority exists for cancellation",
                )
            })?;
            if !session.identity_matches(expected) {
                self.sessions.insert(expected.pid, session);
                return Err(HeldExecFailure::not_released(
                    "cancel-held-launcher",
                    "cancellation identity differs from the retained session",
                ));
            }
            pidfd_send_signal(&session.pidfd, Signal::KILL).map_err(|error| {
                HeldExecFailure::released_unknown("cancel-held-launcher", error.to_string())
            })?;
            Ok(bounded_reap(&mut session.child, HELPER_TIMEOUT).is_some())
        }

        #[allow(
            dead_code,
            reason = "held-launcher lifecycle operation, proven by canary and intentionally unwired until the native command service exists"
        )]
        /// Nonblocking status for a released target, retaining it until it has
        /// actually been reaped.
        ///
        /// [`Self::reap_released`] is bounded-blocking and removes the session
        /// *before* it waits, so a timeout there drops the `Child` and loses
        /// the zombie. That is acceptable for a caller reaping once at the end
        /// of a release, and wrong for a supervisor polling a running command:
        /// the common answer is "still running", and it must not cost custody.
        ///
        /// So this removes the session only in the branch that produced a
        /// status. `Ok(None)` means the command is still running and the
        /// session is still retained.
        pub(crate) fn observe_released(
            &mut self,
            pid: u32,
        ) -> Result<Option<ExitStatus>, HeldExecFailure> {
            let session = self.sessions.get_mut(&pid).ok_or_else(|| {
                HeldExecFailure::released_unknown(
                    "observe-released-target",
                    "no retained pidfd/child session exists for the released target",
                )
            })?;
            if session.state != HeldLauncherState::Released {
                return Err(HeldExecFailure::not_released(
                    "observe-released-target",
                    "session has not reached an observed same-PID exec",
                ));
            }
            let status = session.child.try_wait().map_err(|error| {
                HeldExecFailure::released_unknown("observe-released-target", error.to_string())
            })?;
            if status.is_some() {
                self.sessions.remove(&pid);
            }
            Ok(status)
        }

        /// Reaps a released target and returns the terminal it observed.
        ///
        /// `None` means the reap did not complete inside `timeout`, which is a
        /// different fact from "exited with no status" and must not be
        /// collapsed into one: the caller owes a kill, not a terminal.
        pub(crate) fn reap_released(
            &mut self,
            pid: u32,
            timeout: Duration,
        ) -> Result<Option<ExitStatus>, HeldExecFailure> {
            let mut session = self.sessions.remove(&pid).ok_or_else(|| {
                HeldExecFailure::released_unknown(
                    "reap-released-target",
                    "no retained pidfd/child session exists for the released target",
                )
            })?;
            if session.state != HeldLauncherState::Released {
                self.sessions.insert(pid, session);
                return Err(HeldExecFailure::not_released(
                    "reap-released-target",
                    "session has not reached an observed same-PID exec",
                ));
            }
            Ok(bounded_reap(&mut session.child, timeout))
        }

        pub(crate) fn retained_state(
            &mut self,
            procfs: &LinuxProcfs,
            pid: u32,
            process_start_time_ticks: u64,
            launch_request_hash: &str,
        ) -> Result<Option<bool>, HeldLauncherFailure> {
            let Some(session) = self.sessions.get_mut(&pid) else {
                return Ok(None);
            };
            if session.process_start_time_ticks != process_start_time_ticks
                || session.binding.launch_request_hash != launch_request_hash
            {
                return Err(HeldLauncherFailure::not_applied(
                    "inspect-held-launcher-recovery",
                    "PID collided with a differently bound retained session",
                ));
            }
            match session.ensure_live_exact(procfs, false) {
                Ok(observation) => Ok(Some(observation.held())),
                Err(_) if session.child.try_wait().ok().flatten().is_some() => Ok(Some(false)),
                Err(error) => Err(error),
            }
        }
    }

    /// Creates the controller/helper control channel and seals its direction.
    ///
    /// The channel is a socketpair rather than a pipe because the sequence-2
    /// prepare frame has to carry the controller's already-open sealed
    /// descriptors as `SCM_RIGHTS` ancillary data. Core-dump suppression marks
    /// the runner non-dumpable before any launch (ADR-0008), which closes
    /// `/proc/<runner>/fd/N` to its own child, so the kernel has to hand the
    /// descriptors over instead of the helper reopening them (D-0010).
    ///
    /// One-way-ness is not lost with the pipe. The controller shuts down its
    /// own receive direction, which the kernel propagates as `SEND_SHUTDOWN`
    /// on the helper's end, so the helper's control descriptor can be read and
    /// never written; the helper proves that with a zero-length send that must
    /// fail `EPIPE`. The helper-side identity is captured here, before the
    /// spawn, so the controller can later prove the live child's fd 0 is this
    /// exact kernel object — a socketpair's two ends carry distinct inodes,
    /// where a pipe's two ends shared one.
    fn open_held_launcher_control()
    -> Result<(OwnedFd, OwnedFd, DescriptorIdentity), HeldLauncherFailure> {
        let (control, helper_control) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| {
            HeldLauncherFailure::not_applied("open-held-launcher-control", error.to_string())
        })?;
        let control_identity = descriptor_identity(&helper_control).map_err(|error| {
            HeldLauncherFailure::not_applied("open-held-launcher-control", error.to_string())
        })?;
        shutdown(&control, Shutdown::Read).map_err(|error| {
            HeldLauncherFailure::not_applied("seal-held-launcher-control", error.to_string())
        })?;
        Ok((control, helper_control, control_identity))
    }

    fn spawn_held_launcher(
        procfs: &LinuxProcfs,
        cgroup_procs: File,
        cgroup_membership: File,
        binding: LauncherBinding,
        helper_executable: Option<File>,
    ) -> Result<HeldLauncherSession, HeldLauncherFailure> {
        procfs.validate()?;
        let external_helper_image = helper_executable.is_some();
        let executable = match helper_executable {
            Some(executable) => executable,
            None => File::from(
                openat(
                    &procfs.root,
                    "self/exe",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| {
                    HeldLauncherFailure::not_applied("open-held-launcher-image", error.to_string())
                })?,
            ),
        };
        let executable_identity = descriptor_identity(&executable).map_err(|error| {
            HeldLauncherFailure::not_applied("open-held-launcher-image", error.to_string())
        })?;
        let executable_metadata = fstat(&executable).map_err(|error| {
            HeldLauncherFailure::not_applied("open-held-launcher-image", error.to_string())
        })?;
        if (!external_helper_image && executable_identity != procfs.self_executable_identity)
            || !FileType::from_raw_mode(executable_metadata.st_mode).is_file()
            || executable_metadata.st_mode & 0o111 == 0
        {
            return Err(HeldLauncherFailure::not_applied(
                "open-held-launcher-image",
                "helper image identity, regular-file type, or execute mode is invalid",
            ));
        }
        let executable_path = PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        let parent_pid = u32::try_from(getpid().as_raw_pid()).map_err(|_| {
            HeldLauncherFailure::not_applied(
                "stage-held-launcher",
                "current process PID does not fit the protocol",
            )
        })?;
        let (control, helper_control, control_identity) = open_held_launcher_control()?;
        let mut command = Command::new(executable_path);
        command
            .arg(HELD_LAUNCHER_ARGUMENT)
            .arg(&binding.session_nonce)
            .arg(&binding.launch_request_hash)
            .arg(parent_pid.to_string())
            .arg(binding.leaf_identity.device.to_string())
            .arg(binding.leaf_identity.inode.to_string())
            .arg(binding.cgroup_procs_identity.device.to_string())
            .arg(binding.cgroup_procs_identity.inode.to_string())
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(helper_control))
            .stdout(Stdio::piped())
            .stderr(Stdio::from(cgroup_procs));
        let mut child = command.spawn().map_err(|error| {
            HeldLauncherFailure::not_applied("spawn-held-launcher", error.to_string())
        })?;
        match authenticate_spawned_child(
            procfs,
            &mut child,
            parent_pid,
            &binding,
            executable_identity,
            control,
            control_identity,
        ) {
            Ok(authenticated) => Ok(HeldLauncherSession {
                child,
                pid: authenticated.pid,
                pidfd: authenticated.pidfd,
                process_start_time_ticks: authenticated.process_start_time_ticks,
                binding,
                helper_executable_identity: executable_identity,
                cgroup_membership,
                control_identity: authenticated.control_identity,
                status_identity: authenticated.status_identity,
                control: authenticated.control,
                status: authenticated.status,
                state: HeldLauncherState::AwaitingSelfAttach,
            }),
            Err(error) => {
                if child.try_wait().ok().flatten().is_none() {
                    // No pidfd was acquired, or the pidfd-authenticated path
                    // already attempted exact termination. An unreaped Child
                    // pins its PID, so this fallback cannot target a reused
                    // process.
                    let _ = child.kill();
                    let _ = bounded_reap(&mut child, HELPER_TIMEOUT);
                }
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticate_spawned_child(
        procfs: &LinuxProcfs,
        child: &mut Child,
        parent_pid: u32,
        binding: &LauncherBinding,
        helper_executable_identity: DescriptorIdentity,
        control: OwnedFd,
        control_identity: DescriptorIdentity,
    ) -> Result<AuthenticatedLauncher, HeldLauncherFailure> {
        let raw_pid = i32::try_from(child.id()).map_err(|_| {
            HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "child PID does not fit the kernel PID type",
            )
        })?;
        let pid = Pid::from_raw(raw_pid).ok_or_else(|| {
            HeldLauncherFailure::not_applied("authenticate-held-launcher", "child PID is invalid")
        })?;
        let before = procfs.observe_process(child.id())?.ok_or_else(|| {
            HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "child disappeared before pidfd acquisition",
            )
        })?;
        let pidfd = pidfd_open(pid, PidfdFlags::NONBLOCK).map_err(|error| {
            HeldLauncherFailure::not_applied(
                "open-held-launcher-pidfd",
                format!("required pidfd API unavailable or refused: {error}"),
            )
        })?;
        let authenticated = authenticate_pidfd_bound_child(
            procfs,
            child,
            parent_pid,
            binding,
            helper_executable_identity,
            &pidfd,
            before,
            &control,
            control_identity,
        );
        match authenticated {
            Ok((status, status_identity)) => Ok(AuthenticatedLauncher {
                pid,
                pidfd,
                process_start_time_ticks: before.start_time_ticks,
                control_identity,
                status_identity,
                control,
                status,
            }),
            Err(error) => {
                let _ = pidfd_send_signal(&pidfd, Signal::KILL);
                let _ = bounded_reap(child, HELPER_TIMEOUT);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn authenticate_pidfd_bound_child(
        procfs: &LinuxProcfs,
        child: &mut Child,
        parent_pid: u32,
        binding: &LauncherBinding,
        helper_executable_identity: DescriptorIdentity,
        pidfd: &rustix::fd::OwnedFd,
        before: ProcessObservation,
        control: &OwnedFd,
        control_identity: DescriptorIdentity,
    ) -> Result<(ChildStdout, DescriptorIdentity), HeldLauncherFailure> {
        let after = procfs.observe_process(child.id())?.ok_or_else(|| {
            HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "child disappeared after pidfd acquisition",
            )
        })?;
        if before.start_time_ticks != after.start_time_ticks
            || before.parent_pid != parent_pid
            || after.parent_pid != parent_pid
        {
            return Err(HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "PID start time or parent binding changed around pidfd acquisition",
            ));
        }
        procfs.require_process_executable(child.id(), helper_executable_identity)?;
        procfs.require_process_descriptor(
            child.id(),
            HELPER_CGROUP_FD,
            binding.cgroup_procs_identity,
        )?;
        if child.stdin.is_some() {
            return Err(HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "control socket was not installed as the helper's own standard input",
            ));
        }
        // Pin the child's socketpair endpoint; the two endpoints have different
        // inodes.
        procfs.require_process_descriptor(child.id(), 0, control_identity)?;
        let mut status = child.stdout.take().ok_or_else(|| {
            HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "child status pipe is absent",
            )
        })?;
        let status_identity = descriptor_identity(&status).map_err(|error| {
            HeldLauncherFailure::not_applied("authenticate-launcher-status", error.to_string())
        })?;
        set_nonblocking(control, "configure-launcher-control")?;
        set_nonblocking(&status, "configure-launcher-status")?;
        let ready_bytes =
            read_frame_with_timeout(&mut status, HELPER_TIMEOUT).map_err(|error| {
                HeldLauncherFailure::not_applied("read-launcher-ready", error.to_string())
            })?;
        let ready: StatusEnvelope = decode_frame(&ready_bytes).map_err(|error| {
            HeldLauncherFailure::not_applied("decode-launcher-ready", error.detail)
        })?;
        ready
            .validate_ready(binding, child.id(), parent_pid)
            .map_err(|error| {
                HeldLauncherFailure::not_applied("validate-launcher-ready", error.detail)
            })?;
        pidfd_send_signal(pidfd, Signal::STOP).map_err(|error| {
            HeldLauncherFailure::not_applied("establish-launcher-hold", error.to_string())
        })?;
        wait_for_stopped(
            child,
            pidfd,
            procfs,
            before.start_time_ticks,
            HELPER_TIMEOUT,
        )?;
        procfs.require_process_executable(child.id(), helper_executable_identity)?;
        procfs.require_process_descriptor(
            child.id(),
            HELPER_CGROUP_FD,
            binding.cgroup_procs_identity,
        )?;
        let final_observation =
            procfs.require_exact_process(child.id(), before.start_time_ticks)?;
        if final_observation.parent_pid != parent_pid
            || !final_observation.held()
            || pidfd_has_exited(pidfd)?
        {
            return Err(HeldLauncherFailure::not_applied(
                "authenticate-held-launcher",
                "launcher identity, parent, liveness, or hold changed after final descriptor validation",
            ));
        }
        Ok((status, status_identity))
    }

    fn wait_for_stopped(
        child: &mut Child,
        pidfd: &rustix::fd::OwnedFd,
        procfs: &LinuxProcfs,
        expected_start_time_ticks: u64,
        timeout: Duration,
    ) -> Result<ProcessObservation, HeldLauncherFailure> {
        let deadline = Instant::now() + timeout;
        loop {
            if pidfd_has_exited(pidfd)? {
                return Err(HeldLauncherFailure::not_applied(
                    "wait-launcher-hold",
                    "pidfd became readable before the launcher hold was observed",
                ));
            }
            if child
                .try_wait()
                .map_err(|error| {
                    HeldLauncherFailure::not_applied("wait-launcher-hold", error.to_string())
                })?
                .is_some()
            {
                return Err(HeldLauncherFailure::not_applied(
                    "wait-launcher-hold",
                    "launcher exited before its host-enforced hold was observed",
                ));
            }
            let observation =
                procfs.require_exact_process(child.id(), expected_start_time_ticks)?;
            if observation.held() {
                let confirmed =
                    procfs.require_exact_process(child.id(), expected_start_time_ticks)?;
                if confirmed.held() {
                    return Ok(confirmed);
                }
            }
            if Instant::now() >= deadline {
                return Err(HeldLauncherFailure::not_applied(
                    "wait-launcher-hold",
                    "timed out before observing two exact stopped-state samples",
                ));
            }
            std::thread::sleep(STOP_POLL_INTERVAL);
        }
    }

    /// Reaps a child within `timeout` and **surrenders the status it observed**.
    ///
    /// This used to answer `bool`, matching `Ok(Some(_))` and discarding the
    /// `ExitStatus`. For the inert fixture that was harmless -- the fixture's
    /// contract is that it exits zero after its handshake, so there was nothing
    /// to learn. For a `ContainedCommand` it is the whole product: the status
    /// this reap observes IS the command's terminal, and a caller that only
    /// learns *that* it exited can never report `CommandFinished`.
    ///
    /// Surrendering the status is not surrendering custody. The registry still
    /// owns the `Child`, still performs the wait, and still hands out no
    /// descriptor, no handle and no process -- only what it saw.
    fn bounded_reap(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Err(_) => return None,
                Ok(None) if Instant::now() >= deadline => return None,
                Ok(None) => std::thread::sleep(STOP_POLL_INTERVAL),
            }
        }
    }

    fn pidfd_has_exited(pidfd: &rustix::fd::OwnedFd) -> Result<bool, HeldLauncherFailure> {
        let mut descriptors = [PollFd::new(
            pidfd,
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
        )];
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut descriptors, Some(&timeout))
            .map_err(|error| {
                HeldLauncherFailure::not_applied("poll-held-launcher-pidfd", error.to_string())
            })
            .map(|ready| ready != 0)
    }

    fn set_nonblocking<Fd: AsFd>(
        descriptor: Fd,
        operation: &'static str,
    ) -> Result<(), HeldLauncherFailure> {
        let flags = rustix::fs::fcntl_getfl(&descriptor)
            .map_err(|error| HeldLauncherFailure::not_applied(operation, error.to_string()))?;
        rustix::fs::fcntl_setfl(descriptor, flags | OFlags::NONBLOCK)
            .map_err(|error| HeldLauncherFailure::not_applied(operation, error.to_string()))
    }

    fn queue_atomic_frame(control: &OwnedFd, bytes: &[u8]) -> Result<(), String> {
        queue_atomic_frame_with_descriptors(control, bytes, &[])
    }

    /// Queues one whole control frame, optionally carrying release descriptors.
    ///
    /// The descriptors travel as one `SCM_RIGHTS` control message attached to
    /// the same `sendmsg` as the frame's bytes, so the kernel duplicates the
    /// controller's exact open file descriptions into the helper. Nothing is
    /// reopened by name or through procfs, which is what lets core-dump
    /// suppression stay ahead of every launch (D-0010): a non-dumpable parent
    /// blocks `/proc/<parent>/fd/N` for its own child, but not `SCM_RIGHTS`.
    fn queue_atomic_frame_with_descriptors(
        control: &OwnedFd,
        bytes: &[u8],
        descriptors: &[BorrowedFd<'_>],
    ) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME_BYTES {
            return Err("control frame is empty or exceeds the atomic protocol bound".into());
        }
        if descriptors.len() > MAX_RELEASE_SCM_DESCRIPTOR_COUNT {
            return Err("control frame carries more descriptors than the protocol admits".into());
        }
        let mut space = [MaybeUninit::uninit();
            rustix::cmsg_space!(ScmRights(MAX_RELEASE_SCM_DESCRIPTOR_COUNT))];
        let mut control_message = SendAncillaryBuffer::new(&mut space);
        if !descriptors.is_empty()
            && !control_message.push(SendAncillaryMessage::ScmRights(descriptors))
        {
            return Err("release descriptors did not fit one atomic control message".into());
        }
        match sendmsg(
            control,
            &[IoSlice::new(bytes)],
            &mut control_message,
            SendFlags::NOSIGNAL,
        ) {
            Ok(written) if written == bytes.len() => Ok(()),
            Ok(_) => Err("control channel accepted a partial atomic frame".into()),
            Err(error) => Err(error.to_string()),
        }
    }
