    fn require_exact_cgroup_member(
        membership: &mut File,
        expected_pid: u32,
        operation: &'static str,
    ) -> Result<(), HeldLauncherFailure> {
        seek(&*membership, SeekFrom::Start(0))
            .map_err(|error| HeldLauncherFailure::not_applied(operation, error.to_string()))?;
        let mut bytes = Vec::with_capacity(64);
        loop {
            if bytes.len() >= MAX_CGROUP_MEMBERSHIP_BYTES {
                return Err(HeldLauncherFailure::not_applied(
                    operation,
                    "cgroup.procs exceeded its hard membership byte bound",
                ));
            }
            let mut chunk = [0_u8; 256];
            let count = rustix::io::read(&*membership, &mut chunk)
                .map_err(|error| HeldLauncherFailure::not_applied(operation, error.to_string()))?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        if bytes.is_empty() || !bytes.ends_with(b"\n") {
            return Err(HeldLauncherFailure::not_applied(
                operation,
                "cgroup.procs is empty or not newline terminated",
            ));
        }
        let mut observed = Vec::new();
        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            let text = std::str::from_utf8(line).map_err(|_| {
                HeldLauncherFailure::not_applied(operation, "cgroup.procs is not UTF-8")
            })?;
            let pid = text.parse::<u32>().map_err(|_| {
                HeldLauncherFailure::not_applied(operation, "cgroup.procs PID is invalid")
            })?;
            if pid == 0 || pid.to_string() != text {
                return Err(HeldLauncherFailure::not_applied(
                    operation,
                    "cgroup.procs PID is zero or noncanonical",
                ));
            }
            observed.push(pid);
        }
        if observed != [expected_pid] {
            return Err(HeldLauncherFailure::not_applied(
                operation,
                format!("cgroup.procs membership was {observed:?}, expected only {expected_pid}"),
            ));
        }
        Ok(())
    }

    enum SetupStatusOutcome {
        Closed,
        Frame(Vec<u8>),
    }

    fn read_setup_outcome_with_timeout(
        reader: &mut ChildStdout,
        timeout: Duration,
    ) -> Result<SetupStatusOutcome, io::Error> {
        let deadline = Instant::now() + timeout;
        let mut bytes = Vec::with_capacity(256);
        loop {
            if bytes.len() >= MAX_CONTROL_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "setup-status frame exceeded its hard byte bound",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for setup-status close or failure",
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let timeout = Timespec {
                tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: remaining.subsec_nanos().into(),
            };
            let mut descriptors = [PollFd::new(
                &*reader,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            )];
            let ready = poll(&mut descriptors, Some(&timeout)).map_err(io::Error::from)?;
            if ready == 0 {
                continue;
            }
            if descriptors[0].revents().contains(PollFlags::ERR) {
                return Err(io::Error::other("setup-status pipe reported an error"));
            }
            let mut chunk = [0_u8; 256];
            let count = match reader.read(&mut chunk) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => result?,
            };
            if count == 0 {
                return if bytes.is_empty() {
                    Ok(SetupStatusOutcome::Closed)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "setup-status pipe closed after a partial frame",
                    ))
                };
            }
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
                if newline + 1 != bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "setup-status pipe contained trailing or duplicate frames",
                    ));
                }
                return Ok(SetupStatusOutcome::Frame(bytes));
            }
        }
    }

    fn read_frame_with_timeout(
        reader: &mut ChildStdout,
        timeout: Duration,
    ) -> Result<Vec<u8>, io::Error> {
        let deadline = Instant::now() + timeout;
        let mut bytes = Vec::with_capacity(256);
        loop {
            if bytes.len() >= MAX_CONTROL_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control frame exceeded its hard byte bound",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out reading held-launcher control frame",
                ));
            }
            let remaining = deadline.saturating_duration_since(now);
            let timeout = Timespec {
                tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: remaining.subsec_nanos().into(),
            };
            let mut descriptors = [PollFd::new(
                reader,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            )];
            let ready = poll(&mut descriptors, Some(&timeout)).map_err(io::Error::from)?;
            if ready == 0 {
                continue;
            }
            let events = descriptors[0].revents();
            if events.contains(PollFlags::ERR) {
                return Err(io::Error::other(
                    "held-launcher status pipe reported an error",
                ));
            }
            let mut chunk = [0u8; 256];
            let count = match reader.read(&mut chunk) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => result?,
            };
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "held-launcher status pipe closed before a complete frame",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.last() == Some(&b'\n') {
                return Ok(bytes);
            }
            if bytes.contains(&b'\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "held-launcher status pipe contained trailing bytes after a frame",
                ));
            }
        }
    }

    fn read_bounded(mut file: File, maximum: usize) -> Result<Vec<u8>, io::Error> {
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "procfs file exceeded its hard byte bound",
            ));
        }
        Ok(bytes)
    }

    pub(super) fn parse_proc_stat(
        bytes: &[u8],
        expected_pid: u32,
    ) -> Result<ProcessObservation, ProtocolFailure> {
        if bytes.is_empty() || bytes.len() > MAX_PROC_STAT_BYTES || !bytes.ends_with(b"\n") {
            return Err(ProtocolFailure::new(
                "proc stat is empty, oversized, or not newline terminated",
            ));
        }
        let closing = bytes
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or_else(|| {
                ProtocolFailure::new("proc stat lacks the final command-name delimiter")
            })?;
        let opening = bytes.iter().position(|byte| *byte == b'(').ok_or_else(|| {
            ProtocolFailure::new("proc stat lacks the command-name opening delimiter")
        })?;
        let pid_text = std::str::from_utf8(&bytes[..opening])
            .map_err(|_| ProtocolFailure::new("proc stat PID is not UTF-8"))?
            .trim_end();
        if pid_text.parse::<u32>().ok() != Some(expected_pid) || closing <= opening {
            return Err(ProtocolFailure::new(
                "proc stat PID or command-name delimiters are invalid",
            ));
        }
        let tail = std::str::from_utf8(&bytes[closing + 1..bytes.len() - 1])
            .map_err(|_| ProtocolFailure::new("proc stat tail is not UTF-8"))?;
        if !tail.starts_with(' ') || tail.contains('\n') || tail.contains('\r') {
            return Err(ProtocolFailure::new("proc stat tail has invalid framing"));
        }
        let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() < 20 || fields[0].len() != 1 {
            return Err(ProtocolFailure::new(
                "proc stat lacks state, parent PID, or start-time fields",
            ));
        }
        let state = fields[0].as_bytes()[0];
        let parent_pid = fields[1]
            .parse::<u32>()
            .map_err(|_| ProtocolFailure::new("proc stat parent PID is invalid"))?;
        let start_time_ticks = fields[19]
            .parse::<u64>()
            .map_err(|_| ProtocolFailure::new("proc stat start time is invalid"))?;
        if parent_pid == 0 || start_time_ticks == 0 || !state.is_ascii_alphabetic() {
            return Err(ProtocolFailure::new(
                "proc stat identity fields must be nonzero and canonical",
            ));
        }
        Ok(ProcessObservation {
            state,
            parent_pid,
            start_time_ticks,
        })
    }

    fn descriptor_identity<Fd: AsFd>(descriptor: Fd) -> Result<DescriptorIdentity, io::Error> {
        let metadata = fstat(descriptor).map_err(io::Error::from)?;
        let identity = DescriptorIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        };
        identity
            .validate("descriptor")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.detail))?;
        Ok(identity)
    }

    fn require_procfs<Fd: AsFd>(
        descriptor: Fd,
        operation: &'static str,
    ) -> Result<(), HeldLauncherFailure> {
        let filesystem = rustix::fs::fstatfs(descriptor)
            .map_err(|error| HeldLauncherFailure::not_applied(operation, error.to_string()))?;
        if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(HeldLauncherFailure::not_applied(
                operation,
                "descriptor is not backed by genuine procfs",
            ));
        }
        Ok(())
    }

    fn open_proc_magic_identity(
        procfs: &Dir,
        path: &str,
    ) -> Result<DescriptorIdentity, HeldLauncherFailure> {
        let descriptor = openat(procfs, path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map_err(|error| {
                HeldLauncherFailure::not_applied("open-proc-magic-link", error.to_string())
            })?;
        descriptor_identity(&descriptor).map_err(|error| {
            HeldLauncherFailure::not_applied("inspect-proc-magic-link", error.to_string())
        })
    }

    pub(super) fn run_helper(arguments: impl Iterator<Item = OsString>) -> ExitCode {
        if helper_main(arguments).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(78)
        }
    }

    pub(super) fn run_inert_target(arguments: impl Iterator<Item = OsString>) -> ExitCode {
        if inert_target_main(arguments).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(79)
        }
    }

    fn inert_target_main(
        mut arguments: impl Iterator<Item = OsString>,
    ) -> Result<(), ProtocolFailure> {
        let token = next_utf8(&mut arguments, "inert token")?;
        let expected_cwd_device = next_u64(&mut arguments, "inert cwd device")?;
        let expected_cwd_inode = next_u64(&mut arguments, "inert cwd inode")?;
        if arguments.next().is_some() {
            return Err(ProtocolFailure::new(
                "inert target received trailing arguments",
            ));
        }
        let environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
        if environment.len() != 3
            || environment.get(std::ffi::OsStr::new("GROK_BUILD_INERT_TOKEN"))
                != Some(&OsString::from(&token))
            || environment.get(std::ffi::OsStr::new("GROK_BUILD_INERT_CWD_DEVICE"))
                != Some(&OsString::from(expected_cwd_device.to_string()))
            || environment.get(std::ffi::OsStr::new("GROK_BUILD_INERT_CWD_INODE"))
                != Some(&OsString::from(expected_cwd_inode.to_string()))
        {
            return Err(ProtocolFailure::new(
                "inert target environment differs from its exact cleared contract",
            ));
        }
        require_exact_current_descriptor_set(&[0, 1, 2])?;
        let cwd = open(".", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map_err(|error| ProtocolFailure::new(format!("open inert cwd: {error}")))?;
        let cwd_identity = descriptor_identity(&cwd)
            .map_err(|error| ProtocolFailure::new(format!("inspect inert cwd: {error}")))?;
        if cwd_identity
            != (DescriptorIdentity {
                device: expected_cwd_device,
                inode: expected_cwd_inode,
            })
        {
            return Err(ProtocolFailure::new(
                "inert target cwd differs from the descriptor-bound release contract",
            ));
        }
        drop(cwd);
        rustix::process::kill_process(getpid(), Signal::STOP)
            .map_err(|error| ProtocolFailure::new(format!("self-stop inert target: {error}")))?;
        let mut input = Vec::new();
        std::io::stdin()
            .take(
                u64::try_from(INERT_TARGET_STDIN.len() + 1)
                    .map_err(|_| ProtocolFailure::new("inert input bound does not fit u64"))?,
            )
            .read_to_end(&mut input)
            .map_err(|error| ProtocolFailure::new(format!("read inert stdin: {error}")))?;
        if input != INERT_TARGET_STDIN {
            return Err(ProtocolFailure::new(
                "inert target stdin differs from the dedicated descriptor contract",
            ));
        }
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(INERT_TARGET_STDOUT_PREFIX)
            .and_then(|()| stdout.write_all(token.as_bytes()))
            .and_then(|()| stdout.write_all(b"\n"))
            .and_then(|()| stdout.flush())
            .map_err(|error| ProtocolFailure::new(format!("write inert stdout: {error}")))?;
        let mut stderr = std::io::stderr().lock();
        stderr
            .write_all(INERT_TARGET_STDERR)
            .and_then(|()| stderr.flush())
            .map_err(|error| ProtocolFailure::new(format!("write inert stderr: {error}")))
    }

    // The helper is one straight-line authenticated transaction: each step
    // consumes descriptors authenticated by the preceding step. Keeping the
    // sequence together makes descriptor custody and effect ordering explicit.
    #[expect(
        clippy::too_many_lines,
        reason = "one ordered authenticated launch sequence; splitting it would hide the ordering and hand descriptors across boundaries"
    )]
    fn helper_main(mut arguments: impl Iterator<Item = OsString>) -> Result<(), ProtocolFailure> {
        let session_nonce = next_utf8(&mut arguments, "session nonce")?;
        let launch_request_hash = next_utf8(&mut arguments, "launch request hash")?;
        let expected_parent_pid = next_u32(&mut arguments, "parent PID")?;
        let binding = LauncherBinding {
            session_nonce,
            launch_request_hash,
            leaf_identity: DescriptorIdentity {
                device: next_u64(&mut arguments, "leaf device")?,
                inode: next_u64(&mut arguments, "leaf inode")?,
            },
            cgroup_procs_identity: DescriptorIdentity {
                device: next_u64(&mut arguments, "cgroup.procs device")?,
                inode: next_u64(&mut arguments, "cgroup.procs inode")?,
            },
        };
        if arguments.next().is_some() {
            return Err(ProtocolFailure::new("helper received trailing arguments"));
        }
        binding.validate()?;
        let parent_before = getppid().and_then(|pid| u32::try_from(pid.as_raw_pid()).ok());
        if parent_before != Some(expected_parent_pid) {
            return Err(ProtocolFailure::new(
                "helper parent changed before death-signal setup",
            ));
        }
        set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(|error| ProtocolFailure::new(format!("arm parent death signal: {error}")))?;
        let parent_after = getppid().and_then(|pid| u32::try_from(pid.as_raw_pid()).ok());
        if parent_after != Some(expected_parent_pid) {
            return Err(ProtocolFailure::new(
                "helper parent changed while death signal was armed",
            ));
        }
        require_exact_helper_descriptors(binding.cgroup_procs_identity, expected_parent_pid)?;
        set_helper_control_nonblocking()?;
        let pid = u32::try_from(getpid().as_raw_pid())
            .map_err(|_| ProtocolFailure::new("helper PID does not fit the protocol"))?;
        let ready = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 0,
            binding: binding.clone(),
            status: LauncherStatus::Ready {
                pid,
                parent_pid: expected_parent_pid,
                parent_death_signal_armed: true,
                descriptor_set_exact: true,
            },
        };
        write_stdout_frame(&ready)?;

        let request_bytes = read_stdin_frame()?;
        let request: ControlEnvelope = decode_frame(&request_bytes)?;
        request.validate_self_attach(&binding)?;
        let LauncherCommand::SelfAttach { exact_value } = request.command else {
            return Err(ProtocolFailure::new(
                "validated self-attachment command changed variant",
            ));
        };
        let written = rustix::io::write(std::io::stderr(), &exact_value);
        let status = match written {
            Ok(bytes_written) if bytes_written == exact_value.len() => {
                LauncherStatus::SelfAttached { pid, bytes_written }
            }
            Ok(_) => LauncherStatus::Refused {
                operation: "partial-cgroup-procs-write".into(),
                effect_may_have_applied: true,
            },
            Err(error) => LauncherStatus::Refused {
                operation: format!("cgroup-procs-write-{error}"),
                effect_may_have_applied: true,
            },
        };
        let attached = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 1,
            binding: binding.clone(),
            status,
        };
        write_stdout_frame(&attached)?;
        rustix::process::kill_process(getpid(), Signal::STOP)
            .map_err(|error| ProtocolFailure::new(format!("self-stop after attach: {error}")))?;

        let (prepare_bytes, released) = read_stdin_frame_with_descriptors().map_err(|error| {
            ProtocolFailure::new(format!(
                "held launcher resumed without one complete release preparation: {}",
                error.detail
            ))
        })?;
        let prepare: ControlEnvelope = decode_frame(&prepare_bytes)?;
        let specification = prepare.validate_prepare_exec(&binding)?.clone();
        let mut prepared =
            prepare_target(pid, binding.cgroup_procs_identity, specification, released)?;
        let prepared_status = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 2,
            binding: binding.clone(),
            status: LauncherStatus::ExecPrepared {
                pid,
                release_spec_hash: prepared.specification.release_spec_hash.clone(),
                descriptors: prepared.descriptors.clone(),
                descriptor_set_exact: true,
                cgroup_membership_exact: true,
            },
        };
        write_file_frame(&mut prepared.setup_status, &prepared_status)?;
        rustix::process::kill_process(getpid(), Signal::STOP)
            .map_err(|error| ProtocolFailure::new(format!("self-stop after prepare: {error}")))?;

        let commit_bytes = read_stdin_frame().map_err(|error| {
            ProtocolFailure::new(format!(
                "prepared launcher resumed without one complete exec commit: {}",
                error.detail
            ))
        })?;
        let commit: ControlEnvelope = decode_frame(&commit_bytes)?;
        commit.validate_commit_exec(&binding, &prepared.specification.release_spec_hash)?;
        exec_prepared_target(&binding, pid, prepared)
    }

    struct PreparedTarget {
        specification: ReleaseExecSpec,
        executable: File,
        working_directory: File,
        target_stdin: File,
        target_stdout: File,
        target_stderr: File,
        cgroup_membership: File,
        setup_status: File,
        descriptors: PreparedDescriptorTable,
        /// One authenticated directory descriptor per committed Landlock
        /// scope, in the committed ruleset's own order.
        ///
        /// They are held rather than named: the release installs each scope's
        /// `path_beneath` rule over the descriptor, so no scope path is ever
        /// resolved inside the helper and a substituted directory is refused by
        /// identity even when the committed path string matched.
        landlock_scopes: Vec<File>,
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_target(
        pid: u32,
        expected_cgroup_identity: DescriptorIdentity,
        specification: ReleaseExecSpec,
        released_descriptors: Vec<OwnedFd>,
    ) -> Result<PreparedTarget, ProtocolFailure> {
        specification.validate()?;
        let setup_status_fd = rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3)
            .map_err(|error| ProtocolFailure::new(format!("duplicate setup status: {error}")))?;
        let setup_status = File::from(setup_status_fd);
        // Require the six fixed descriptor roles and one per scope. Reject missing
        // or extra descriptors.
        let expected_scopes = prepared_landlock_scope_count(&specification);
        if released_descriptors.len() != RELEASE_DESCRIPTOR_COUNT + expected_scopes {
            return Err(ProtocolFailure::new(
                "release preparation did not carry the exact released descriptor set",
            ));
        }
        let mut released_descriptors = released_descriptors;
        let scope_descriptors = released_descriptors.split_off(RELEASE_DESCRIPTOR_COUNT);
        let Ok(released_descriptors): Result<[OwnedFd; RELEASE_DESCRIPTOR_COUNT], _> =
            <[OwnedFd; RELEASE_DESCRIPTOR_COUNT]>::try_from(released_descriptors)
        else {
            return Err(ProtocolFailure::new(
                "release preparation did not carry the exact released descriptor set",
            ));
        };
        let [
            executable,
            working_directory,
            target_stdin,
            target_stdout,
            target_stderr,
            cgroup_membership,
        ] = released_descriptors.map(File::from);
        let landlock_scopes =
            receive_landlock_scope_descriptors(&specification, scope_descriptors)?;
        let executable = receive_parent_descriptor(
            executable,
            specification.executable.authority,
            "executable",
        )?;
        let working_directory = receive_parent_descriptor(
            working_directory,
            specification.working_directory,
            "working directory",
        )?;
        let target_stdin =
            receive_parent_descriptor(target_stdin, specification.target_stdin, "target stdin")?;
        let target_stdout =
            receive_parent_descriptor(target_stdout, specification.target_stdout, "target stdout")?;
        let target_stderr =
            receive_parent_descriptor(target_stderr, specification.target_stderr, "target stderr")?;
        let mut cgroup_membership = receive_parent_descriptor(
            cgroup_membership,
            specification.cgroup_membership,
            "cgroup membership",
        )?;
        validate_opened_target_descriptors(
            &specification,
            &executable,
            &working_directory,
            &target_stdin,
            &target_stdout,
            &target_stderr,
            &cgroup_membership,
            expected_cgroup_identity,
        )?;
        require_exact_cgroup_member(&mut cgroup_membership, pid, "helper-prepare-membership")
            .map_err(|error| ProtocolFailure::new(error.detail))?;
        let descriptors = PreparedDescriptorTable {
            executable: raw_descriptor_u32(&executable, "prepared executable")?,
            working_directory: raw_descriptor_u32(
                &working_directory,
                "prepared working directory",
            )?,
            target_stdin: raw_descriptor_u32(&target_stdin, "prepared target stdin")?,
            target_stdout: raw_descriptor_u32(&target_stdout, "prepared target stdout")?,
            target_stderr: raw_descriptor_u32(&target_stderr, "prepared target stderr")?,
            cgroup_membership: raw_descriptor_u32(
                &cgroup_membership,
                "prepared cgroup membership",
            )?,
            setup_status: raw_descriptor_u32(&setup_status, "prepared setup status")?,
            landlock_scopes: landlock_scopes
                .iter()
                .map(|scope| raw_descriptor_u32(scope, "prepared containment scope"))
                .collect::<Result<Vec<_>, _>>()?,
        };
        descriptors.validate()?;
        require_exact_current_descriptor_set(&expected_descriptor_set(&descriptors)?)?;
        Ok(PreparedTarget {
            specification,
            executable,
            working_directory,
            target_stdin,
            target_stdout,
            target_stderr,
            cgroup_membership,
            setup_status,
            descriptors,
            landlock_scopes,
        })
    }

    /// The complete descriptor set this helper is required to hold, standard
    /// descriptors first, then the seven fixed roles, then one per scope.
    ///
    /// `require_exact_current_descriptor_set` compares against the helper's own
    /// `/proc/self/fd`, so a scope descriptor the controller sent but the
    /// specification did not describe, or one this code forgot to retain,
    /// fails here rather than surviving into the released image.
    fn expected_descriptor_set(
        descriptors: &PreparedDescriptorTable,
    ) -> Result<Vec<i32>, ProtocolFailure> {
        let mut expected = vec![0, 1, 2];
        for value in descriptors.all() {
            expected.push(
                i32::try_from(value)
                    .map_err(|_| ProtocolFailure::new("prepared descriptor does not fit i32"))?,
            );
        }
        Ok(expected)
    }

    /// How many Landlock scope descriptors one specification's frame carries.
    const fn prepared_landlock_scope_count(specification: &ReleaseExecSpec) -> usize {
        match &specification.containment {
            None => 0,
            Some(containment) => containment.landlock.scopes.len(),
        }
    }

    /// Authenticates the scope descriptors positionally against the committed
    /// ruleset.
    ///
    /// Each one must be close-on-exec, a directory, and carry exactly the
    /// `(device, inode)` the committed scope names, the same three proofs
    /// `receive_parent_descriptor` and `validate_opened_target_descriptors`
    /// make of the fixed roles. No scope path is resolved: the identity is the
    /// authority, and the path travels only because the plan's committed digest
    /// covers it.
    fn receive_landlock_scope_descriptors(
        specification: &ReleaseExecSpec,
        received: Vec<OwnedFd>,
    ) -> Result<Vec<File>, ProtocolFailure> {
        let Some(containment) = &specification.containment else {
            if received.is_empty() {
                return Ok(Vec::new());
            }
            return Err(ProtocolFailure::new(
                "release preparation carried scope descriptors for a release that installs no containment",
            ));
        };
        if received.len() != containment.landlock.scopes.len() {
            return Err(ProtocolFailure::new(
                "release preparation did not carry one descriptor per committed Landlock scope",
            ));
        }
        let mut scopes = Vec::with_capacity(received.len());
        for (descriptor, committed) in received.into_iter().zip(&containment.landlock.scopes) {
            let file = File::from(descriptor);
            let identity = descriptor_identity(&file).map_err(|error| {
                ProtocolFailure::new(format!("inspect received containment scope: {error}"))
            })?;
            if identity != committed.identity {
                return Err(ProtocolFailure::new(format!(
                    "received containment scope {} differs from the identity the ruleset commits",
                    committed.object_id
                )));
            }
            let metadata = fstat(&file).map_err(|error| {
                ProtocolFailure::new(format!("inspect received containment scope: {error}"))
            })?;
            if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
                return Err(ProtocolFailure::new(format!(
                    "received containment scope {} is not a directory",
                    committed.object_id
                )));
            }
            let flags = rustix::io::fcntl_getfd(&file).map_err(|error| {
                ProtocolFailure::new(format!("inspect received containment scope: {error}"))
            })?;
            if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
                return Err(ProtocolFailure::new(format!(
                    "received containment scope {} is not close-on-exec",
                    committed.object_id
                )));
            }
            scopes.push(file);
        }
        Ok(scopes)
    }

    /// Authenticates a received `SCM_RIGHTS` descriptor against its release
    /// binding's device and inode, and requires close-on-exec. The following
    /// `validate_opened_target_descriptors` check verifies type, access, seals and
    /// digest. No path is reopened.
    fn receive_parent_descriptor(
        file: File,
        expected: ParentDescriptorBinding,
        role: &'static str,
    ) -> Result<File, ProtocolFailure> {
        let actual = descriptor_identity(&file)
            .map_err(|error| ProtocolFailure::new(format!("inspect received {role}: {error}")))?;
        if actual != expected.identity {
            return Err(ProtocolFailure::new(format!(
                "received {role} identity differs from the release binding"
            )));
        }
        let flags = rustix::io::fcntl_getfd(&file)
            .map_err(|error| ProtocolFailure::new(format!("inspect received {role}: {error}")))?;
        if !flags.contains(rustix::io::FdFlags::CLOEXEC) {
            return Err(ProtocolFailure::new(format!(
                "received {role} is not close-on-exec"
            )));
        }
        Ok(file)
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_opened_target_descriptors(
        specification: &ReleaseExecSpec,
        executable: &File,
        working_directory: &File,
        target_stdin: &File,
        target_stdout: &File,
        target_stderr: &File,
        cgroup_membership: &File,
        expected_cgroup_identity: DescriptorIdentity,
    ) -> Result<(), ProtocolFailure> {
        let executable_authority = AuthenticatedExecutableDescriptor {
            file: executable
                .try_clone()
                .map_err(|error| ProtocolFailure::new(format!("clone executable: {error}")))?,
            expected_identity: specification.executable.authority.identity,
            expected_content_sha256: specification.executable.content_sha256.clone(),
        };
        let executable_observation = executable_binding(&executable_authority)?;
        if executable_observation.image_type != specification.executable.image_type
            || executable_observation.byte_len != specification.executable.byte_len
            || executable_observation.content_sha256 != specification.executable.content_sha256
            || executable_observation.seal_bits != specification.executable.seal_bits
        {
            return Err(ProtocolFailure::new(
                "helper executable type, length, digest, or seals differ from the controller binding",
            ));
        }
        for (file, expected, kind) in [
            (
                working_directory,
                specification.working_directory.identity,
                ReleaseDescriptorKind::WorkingDirectory,
            ),
            (
                target_stdin,
                specification.target_stdin.identity,
                ReleaseDescriptorKind::ReadableStdio,
            ),
            (
                target_stdout,
                specification.target_stdout.identity,
                ReleaseDescriptorKind::WritableStdio,
            ),
            (
                target_stderr,
                specification.target_stderr.identity,
                ReleaseDescriptorKind::WritableStdio,
            ),
            (
                cgroup_membership,
                expected_cgroup_identity,
                ReleaseDescriptorKind::CgroupMembership,
            ),
        ] {
            let observed = binding_for_retained_file(file, expected, kind)?;
            if observed.identity != expected {
                return Err(ProtocolFailure::new(
                    "helper opened a substituted release descriptor",
                ));
            }
        }
        Ok(())
    }

    /// Replaces the held helper with the sealed target using direct `execve`.
    /// There is no fork or C-library shell fallback. The release installs argv,
    /// the replacement environment, retained cwd, stdio and `SIGPIPE`, while
    /// preserving session, process-group and revalidated cgroup membership.
    ///
    /// The close-on-exec status channel closes on success and reports exact
    /// failure otherwise. Contained commands install both kernel-control layers
    /// before exec; those controls survive replacement of this process image.
    fn exec_prepared_target(
        binding: &LauncherBinding,
        pid: u32,
        mut prepared: PreparedTarget,
    ) -> Result<(), ProtocolFailure> {
        validate_opened_target_descriptors(
            &prepared.specification,
            &prepared.executable,
            &prepared.working_directory,
            &prepared.target_stdin,
            &prepared.target_stdout,
            &prepared.target_stderr,
            &prepared.cgroup_membership,
            binding.cgroup_procs_identity,
        )?;
        require_exact_cgroup_member(
            &mut prepared.cgroup_membership,
            pid,
            "helper-preexec-membership",
        )
        .map_err(|error| ProtocolFailure::new(error.detail))?;
        let expected_descriptors = expected_descriptor_set(&prepared.descriptors)?;
        require_exact_current_descriptor_set(&expected_descriptors)?;

        // Every allocation the release needs happens here, before the first
        // descriptor moves, so the sequence from the first `dup2` to `execve`
        // is allocation-free and uses only async-signal-safe operations.
        let image = linux_release_exec::TargetProcessImage::new(
            &format!("/proc/self/fd/{}", prepared.executable.as_raw_fd()),
            prepared.specification.argv.iter().cloned(),
            prepared
                .specification
                .environment
                .iter()
                .map(|entry| format!("{}={}", entry.name, entry.value)),
        )
        .map_err(|error| ProtocolFailure::new(format!("encode release process image: {error}")))?;
        // Install and verify both layers before `dup2` or exec. Any failure stops
        // the release before the target starts.
        if let Some(containment) = prepared.specification.containment.clone()
            && let Err(refusal) =
                install_release_containment(&containment, &prepared.landlock_scopes)
        {
            // The exact reason travels back over the setup-status channel
            // rather than dying silently, and it travels as a *refusal*: no
            // image replacement was attempted, so nothing about this process's
            // identity, cgroup or descriptor set changed.
            let refused = StatusEnvelope {
                protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
                sequence: 3,
                binding: binding.clone(),
                status: LauncherStatus::Refused {
                    operation: format!("install-release-containment: {}", refusal.detail),
                    effect_may_have_applied: false,
                },
            };
            write_file_frame(&mut prepared.setup_status, &refused)?;
            return Err(refusal);
        }
        let failure = linux_release_exec::replace_process_image(
            &image,
            prepared.working_directory.as_fd(),
            prepared.target_stdin.as_fd(),
            prepared.target_stdout.as_fd(),
            prepared.target_stderr.as_fd(),
        );
        let operation = format!(
            "descriptor-exec-{}-{}",
            failure.step.as_str(),
            failure.error
        );
        let failed = StatusEnvelope {
            protocol_version: HELD_LAUNCHER_PROTOCOL_VERSION,
            sequence: 3,
            binding: binding.clone(),
            status: LauncherStatus::ExecFailed {
                pid,
                release_spec_hash: prepared.specification.release_spec_hash,
                operation: operation.clone(),
                exec_was_attempted: failure.reached_image_replacement(),
            },
        };
        write_file_frame(&mut prepared.setup_status, &failed)?;
        Err(ProtocolFailure::new(format!(
            "descriptor-bound release failed: {operation}"
        )))
    }

    /// Fixed runtime read-and-execute allowlist, additional to the plan's scopes.
    /// The protocol cannot add entries. Plan scopes are separately checked against
    /// its retained directories.
    ///
    /// * `/proc` permits exec of the sealed image through `/proc/self/fd/<n>` after
    ///   Landlock has been applied.
    /// * `/usr`, `/lib`, `/lib64` and `/etc/ld.so.cache` permit loading the ELF
    ///   interpreter and shared objects.
    /// * `/dev/urandom` and `/dev/zero` permit runtime initialization without granting
    ///   access to other devices.
    ///
    /// Missing entries grant nothing. No entry permits writes.
    const LINUX_LAUNCHER_RUNTIME_READ_SURFACES: &[&str] = &[
        "/proc",
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/dev/urandom",
        "/dev/zero",
    ];

    /// The one runtime surface a contained release also writes.
    ///
    /// `Stdio::null()`, every shell redirection and most toolchains open it,
    /// and a policy that omits it stops a workload rather than confining one.
    /// Named exactly, for the same reason as the two devices above.
    const LINUX_LAUNCHER_RUNTIME_WRITE_SURFACES: &[&str] = &["/dev/null"];

    /// Installs both kernel-control layers on this process, in order.
    ///
    /// The order is the only one that works and is therefore not a preference:
    ///
    /// 1. the BPF program is assembled from the committed table and its digest
    ///    is required to equal `program_sha256`, a second, independent
    ///    assembly of the same table the controller already assembled, so the
    ///    two peers agree instruction for instruction without exchanging one;
    /// 2. the Landlock ABI this kernel implements is negotiated and required to
    ///    equal the ABI the ruleset was created at, and the handled access set
    ///    is required to be the complete set that ABI implements;
    /// 3. the ruleset is created and populated, one `path_beneath` per
    ///    committed scope over the descriptor the controller passed, then the
    ///    closed compiled runtime surfaces;
    /// 4. `restrict_self`, required to report `FullyEnforced` **and**
    ///    `no_new_privs`, because a partially enforced path policy is exactly
    ///    the silent downgrade this boundary exists to refuse;
    /// 5. the committed denial witness is opened and the kernel is required to
    ///    answer `EACCES`, a ruleset that grants everything would pass step 4
    ///    and fail here, which is what makes step 4 mean something;
    /// 6. the filter is applied, last, so the witness probe in step 5 runs
    ///    under the path policy but not under a filter that might have killed
    ///    the launcher before it could report anything.
    #[allow(
        clippy::too_many_lines,
        reason = "the six numbered steps above are one ordered installation and the order is the contract: scopes, then rebuild-and-compare for both filters, then restrict_self, then the denial witness, then the filters last. Splitting it would put that order in call sites instead of in one readable sequence"
    )]
    fn install_release_containment(
        containment: &ReleaseContainmentArtefact,
        scope_descriptors: &[File],
    ) -> Result<(), ProtocolFailure> {
        use landlock::{
            Access as _, AccessFs, BitFlags, CompatLevel, Compatible as _, PathBeneath, PathFd,
            Ruleset, RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
        };

        if scope_descriptors.len() != containment.landlock.scopes.len() {
            return Err(ProtocolFailure::new(
                "release containment holds a different number of scope descriptors than it commits",
            ));
        }
        let program = assemble_release_seccomp_program(
            &containment.seccomp.denied_syscalls,
            &containment.seccomp.audit_architecture,
        )?;
        if seccomp_program_digest(&program) != containment.seccomp.program_sha256
            || u64::try_from(program.len()).ok() != Some(containment.seccomp.instruction_count)
        {
            return Err(ProtocolFailure::new(
                "the filter this launcher assembled is not the program the plan commits",
            ));
        }
        // The second filter, rebuilt from the plan's own description and held
        // to the same standard: an edited table or an invented digest is
        // refused here, before anything is installed.
        let namespace_program = assemble_release_namespace_program(
            &containment.seccomp_namespace.denied_syscalls,
            &containment.seccomp_namespace.audit_architecture,
        )?;
        if seccomp_program_digest(&namespace_program)
            != containment.seccomp_namespace.program_sha256
            || u64::try_from(namespace_program.len()).ok()
                != Some(containment.seccomp_namespace.instruction_count)
        {
            return Err(ProtocolFailure::new(
                "the namespace filter this launcher assembled is not the program the plan commits",
            ));
        }
        let observed = crate::linux_dev_domain::observed_landlock_abi();
        let observed_level = u32::from(crate::linux_dev_domain::abi_level(observed));
        if observed_level == 0 || observed_level != containment.landlock.created_at_kernel_abi {
            return Err(ProtocolFailure::new(format!(
                "this kernel implements Landlock ABI {observed_level} but the committed ruleset was created at ABI {}; nothing is partially enforced",
                containment.landlock.created_at_kernel_abi
            )));
        }
        let handled = AccessFs::from_all(observed);
        if handled.bits() != containment.landlock.handled_access_bits {
            return Err(ProtocolFailure::new(
                "the access set this kernel implements is not the set the committed ruleset handles",
            ));
        }
        let readable = AccessFs::from_read(observed);
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(handled)
            .and_then(Ruleset::create)
            .map_err(|error| {
                ProtocolFailure::new(format!("create release landlock ruleset: {error}"))
            })?;
        for (committed, descriptor) in containment.landlock.scopes.iter().zip(scope_descriptors) {
            let access = BitFlags::<AccessFs>::from_bits(committed.access_bits).map_err(|_| {
                ProtocolFailure::new(format!(
                    "committed scope {} grants a right this kernel does not model",
                    committed.object_id
                ))
            })?;
            // The rule is built over the descriptor itself, never over a
            // `PathFd` this code opened: a `PathFd` would resolve the committed
            // path a second time and reintroduce exactly the substitution the
            // identity proof exists to close.
            let retained = descriptor.try_clone().map_err(|error| {
                ProtocolFailure::new(format!("retain containment scope: {error}"))
            })?;
            let rule = PathBeneath::new(retained, access);
            created = created.add_rule(rule).map_err(|error| {
                ProtocolFailure::new(format!(
                    "add release landlock rule for {}: {error}",
                    committed.object_id
                ))
            })?;
        }
        for (surfaces, access) in [
            (LINUX_LAUNCHER_RUNTIME_READ_SURFACES, readable),
            (LINUX_LAUNCHER_RUNTIME_WRITE_SURFACES, handled),
        ] {
            for surface in surfaces {
                let Ok(descriptor) = PathFd::new(surface) else {
                    // An absent runtime surface grants nothing and is never
                    // substituted, exactly as the development arm's own
                    // resolved list behaves.
                    continue;
                };
                // A rule on anything that is not a directory may carry only the
                // file-applicable rights; the kernel refuses the rest outright.
                let access = if std::path::Path::new(surface).is_dir() {
                    access
                } else {
                    access & AccessFs::from_file(observed)
                };
                created = created
                    .add_rule(PathBeneath::new(descriptor, access))
                    .map_err(|error| {
                        ProtocolFailure::new(format!(
                            "add release landlock runtime rule for {surface}: {error}"
                        ))
                    })?;
            }
        }
        let status = created
            .restrict_self()
            .map_err(|error| ProtocolFailure::new(format!("restrict release self: {error}")))?;
        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            return Err(ProtocolFailure::new(
                "the release path policy did not fully enforce, or no-new-privileges was not set",
            ));
        }
        require_denial_witness_refused(&containment.landlock.denial_witness)?;
        // TSYNC applies each filter across all threads or fails if synchronization
        // cannot be completed. This prevents an unchecked thread from remaining
        // unfiltered without changing the committed BPF program.
        seccompiler::apply_filter_all_threads(&program).map_err(|error| {
            ProtocolFailure::new(format!("apply release seccomp filter: {error}"))
        })?;
        // Installed as a second filter, never merged into the first: the two
        // carry different matched actions. The kernel evaluates every
        // installed filter and keeps the highest-precedence answer, so this
        // cannot weaken the network denial above.
        seccompiler::apply_filter_all_threads(&namespace_program).map_err(|error| {
            ProtocolFailure::new(format!("apply release namespace filter: {error}"))
        })?;
        Ok(())
    }

    /// Requires the kernel to refuse the committed denial witness.
    ///
    /// `EACCES` exactly, because that is the errno Landlock returns for a
    /// denied path and it is deliberately not the `EPERM` the syscall layer
    /// returns for a network endpoint, the errno names which layer refused.
    /// A witness that opens is a ruleset that proved nothing, and a witness
    /// that fails some other way is an observation this launcher will not read
    /// as enforcement.
    fn require_denial_witness_refused(
        witness: &ReleaseLandlockWitness,
    ) -> Result<(), ProtocolFailure> {
        match open(
            witness.resolved_path.as_str(),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => {
                drop(descriptor);
                Err(ProtocolFailure::new(format!(
                    "the committed denial witness {} was not denied by the kernel after restrict_self",
                    witness.resolved_path
                )))
            }
            Err(rustix::io::Errno::ACCESS) => Ok(()),
            Err(error) => Err(ProtocolFailure::new(format!(
                "the committed denial witness {} was refused with {error} rather than EACCES",
                witness.resolved_path
            ))),
        }
    }

    /// Direct containment exec using POSIX async-signal-safe operations.
    /// `execve` returns `ENOEXEC` for an invalid image instead of invoking the
    /// `execvp` shell fallback. The production gate separately requires a
    /// little-endian ELF64 executable for the host architecture.
    ///
    /// The release replaces this process without forking. `fchdir` uses the
    /// revalidated directory descriptor, and stdio/SIGPIPE setup remains
    /// allocation-free.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    mod linux_release_exec {
        use std::ffi::{CString, NulError, c_char, c_int};
        use std::io;
        use std::os::fd::{AsRawFd as _, BorrowedFd};
        use std::os::unix::process::CommandExt as _;
        use std::process::{Child, Command};

        unsafe extern "C" {
            fn dup2(source: c_int, target: c_int) -> c_int;
            fn signal(number: c_int, handler: usize) -> usize;
            fn execve(
                path: *const c_char,
                argv: *const *mut c_char,
                environment: *const *mut c_char,
            ) -> c_int;
        }

        /// `SIGPIPE` is signal 13 on every Linux ABI this runner builds for,
        /// and `SIG_DFL`/`SIG_ERR` are the POSIX null and all-ones handler
        /// values. `std`'s exec resets exactly this disposition and
        /// deliberately leaves the inherited signal mask alone; so does this.
        const SIGPIPE: c_int = 13;
        const SIG_DFL: usize = 0;
        const SIG_ERR: usize = usize::MAX;
        const EINTR: i32 = 4;
        /// The one errno a refused containment layer reports to the parent.
        ///
        /// It is a raw errno rather than a described error because
        /// constructing a described one would allocate in a forked child.
        const EPERM: i32 = 1;

        /// The exact process image a release replaces this process with.
        ///
        /// It is built before any descriptor is moved: `argv[0]` is the
        /// specification's own argv0, and the environment is the complete
        /// replacement set, already validated unique and sorted.
        pub(super) struct TargetProcessImage {
            executable: CString,
            argv: Vec<CString>,
            environment: Vec<CString>,
        }

        impl TargetProcessImage {
            pub(super) fn new(
                executable: &str,
                argv: impl IntoIterator<Item = String>,
                environment: impl IntoIterator<Item = String>,
            ) -> Result<Self, NulError> {
                Ok(Self {
                    executable: CString::new(executable)?,
                    argv: encode(argv)?,
                    environment: encode(environment)?,
                })
            }
        }

        fn encode(values: impl IntoIterator<Item = String>) -> Result<Vec<CString>, NulError> {
            values.into_iter().map(CString::new).collect()
        }

        fn null_terminated(values: &[CString]) -> Vec<*mut c_char> {
            let mut pointers = values
                .iter()
                .map(|value| value.as_ptr().cast_mut())
                .collect::<Vec<_>>();
            pointers.push(std::ptr::null_mut());
            pointers
        }

        /// The exact operation a release stopped at.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum ReleaseStep {
            TargetStdin,
            TargetStdout,
            TargetStderr,
            WorkingDirectory,
            SignalDisposition,
            ImageReplacement,
        }

        impl ReleaseStep {
            pub(super) const fn as_str(self) -> &'static str {
                match self {
                    Self::TargetStdin => "target-stdin",
                    Self::TargetStdout => "target-stdout",
                    Self::TargetStderr => "target-stderr",
                    Self::WorkingDirectory => "working-directory",
                    Self::SignalDisposition => "sigpipe-disposition",
                    Self::ImageReplacement => "execve",
                }
            }
        }

        /// A release that did not happen, and the exact step that refused it.
        pub(super) struct ReleaseFailure {
            pub(super) step: ReleaseStep,
            pub(super) error: io::Error,
        }

        impl ReleaseFailure {
            /// Whether the kernel was actually asked to replace the image.
            ///
            /// Only then may the controller be told `exec_was_attempted`; a
            /// setup step that refused first is reported honestly and the
            /// controller treats that frame conservatively.
            pub(super) const fn reached_image_replacement(&self) -> bool {
                matches!(self.step, ReleaseStep::ImageReplacement)
            }
        }

        /// Replaces this process with the sealed target image.
        ///
        /// Returning at all means the release did not happen.
        pub(super) fn replace_process_image(
            image: &TargetProcessImage,
            working_directory: BorrowedFd<'_>,
            target_stdin: BorrowedFd<'_>,
            target_stdout: BorrowedFd<'_>,
            target_stderr: BorrowedFd<'_>,
        ) -> ReleaseFailure {
            let argv = null_terminated(&image.argv);
            let environment = null_terminated(&image.environment);
            for (source, target, step) in [
                (target_stdin, 0, ReleaseStep::TargetStdin),
                (target_stdout, 1, ReleaseStep::TargetStdout),
                (target_stderr, 2, ReleaseStep::TargetStderr),
            ] {
                if let Err(error) = duplicate_onto(source, target) {
                    return ReleaseFailure { step, error };
                }
            }
            if let Err(error) = rustix::process::fchdir(working_directory) {
                return ReleaseFailure {
                    step: ReleaseStep::WorkingDirectory,
                    error: error.into(),
                };
            }
            // SAFETY: `signal` is called with the fixed `SIGPIPE` number and
            // the POSIX default-handler value, which owns no memory and needs
            // none to stay valid; the returned previous handler is compared,
            // never called.
            if unsafe { signal(SIGPIPE, SIG_DFL) } == SIG_ERR {
                return ReleaseFailure {
                    step: ReleaseStep::SignalDisposition,
                    error: io::Error::last_os_error(),
                };
            }
            // SAFETY: `image` outlives this call, so the executable name and
            // every argv/environment string stay allocated and NUL-terminated
            // for its duration; both vectors are NUL-pointer terminated and
            // are read, never written, by `execve`. On success this call never
            // returns.
            unsafe {
                execve(
                    image.executable.as_ptr(),
                    argv.as_ptr(),
                    environment.as_ptr(),
                );
            }
            ReleaseFailure {
                step: ReleaseStep::ImageReplacement,
                error: io::Error::last_os_error(),
            }
        }

        /// Installs `source` at the exact descriptor number `target`.
        ///
        /// This is `dup2(2)`: the kernel closes whatever occupied `target`,
        /// duplicates `source` onto it, and clears `FD_CLOEXEC` on the result.
        /// Both halves matter to the callers. The release uses it to place the
        /// target's stdio. The service child-launch closure uses it to put the
        /// descriptor the plan names at fd 0, which **replaces** the transport
        /// socket the child could not otherwise be rid of, safe Rust cannot
        /// close a descriptor it does not own, and this does not close one, it
        /// overwrites it. `FD_CLOEXEC` being cleared is exactly what the plan
        /// requires of fds 0..=2, and is why this cannot serve fds 3..=6.
        ///
        /// `EINTR` is retried; every other errno is returned unchanged.
        ///
        /// # Errors
        ///
        /// Returns the `dup2` errno when the kernel refuses the duplication.
        pub(crate) fn duplicate_onto(
            source: BorrowedFd<'_>,
            target: c_int,
        ) -> Result<(), io::Error> {
            loop {
                // SAFETY: `source` is a live borrowed descriptor for the whole
                // call and `target` is one of the three standard descriptors,
                // which the caller has proved distinct from every retained
                // release descriptor. `dup2` closes `target` and duplicates
                // `source` onto it; it owns no memory.
                if unsafe { dup2(source.as_raw_fd(), target) } >= 0 {
                    return Ok(());
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(EINTR) {
                    return Err(error);
                }
            }
        }

        /// The two containment layers, already built, carried across one fork.
        ///
        /// Every allocating step happens in the controller **before** the
        /// fork: the Landlock ruleset is a kernel object the controller
        /// created, negotiated, and populated with rules, and the seccomp
        /// filter is a BPF program the controller compiled. What crosses the
        /// fork is a descriptor and a byte vector.
        ///
        /// The forked child therefore performs exactly three syscalls,
        /// `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self(2)`, and
        /// `seccomp(SECCOMP_SET_MODE_FILTER)`, and allocates nothing. Both
        /// layers are defined by the kernel to survive `execve(2)`, which is
        /// what makes applying them here, rather than inside the target,
        /// the boundary the target cannot decline.
        pub(crate) struct ChildContainment {
            ruleset: Option<landlock::RulesetCreated>,
            filter: seccompiler::BpfProgram,
            namespace_filter: seccompiler::BpfProgram,
        }

        impl ChildContainment {
            /// Binds an already-created ruleset and the compiled filters.
            ///
            /// `None` and an empty program mean "this layer is deliberately
            /// not installed"; the caller records why, and no control claim
            /// may be derived from a layer that was not installed.
            ///
            /// The two filters stay separate all the way to the child because
            /// they answer different errnos and a `seccompiler` filter carries
            /// exactly one matched action. The kernel keeps the
            /// highest-precedence answer across every installed filter, so the
            /// namespace layer cannot weaken the network layer.
            pub(crate) const fn new(
                ruleset: Option<landlock::RulesetCreated>,
                filter: seccompiler::BpfProgram,
                namespace_filter: seccompiler::BpfProgram,
            ) -> Self {
                Self {
                    ruleset,
                    filter,
                    namespace_filter,
                }
            }
        }

        impl std::fmt::Debug for ChildContainment {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .debug_struct("ChildContainment")
                    .field("landlock_ruleset", &self.ruleset.is_some())
                    .field("seccomp_instructions", &self.filter.len())
                    .field(
                        "namespace_seccomp_instructions",
                        &self.namespace_filter.len(),
                    )
                    .finish()
            }
        }

        /// Spawns `command` with both layers applied after fork, before exec.
        ///
        /// A layer that cannot be applied, or that the kernel reports as
        /// anything other than fully enforced, fails the child before the
        /// image is replaced. There is no partially confined child: `std`
        /// reports the failure to this caller and the child `_exit`s.
        ///
        /// # Errors
        ///
        /// Fails when the spawn itself fails, and when the child could not
        /// install either layer.
        pub(crate) fn spawn_with_child_containment(
            command: &mut Command,
            containment: ChildContainment,
        ) -> io::Result<Child> {
            let ChildContainment {
                mut ruleset,
                filter,
                namespace_filter,
            } = containment;
            // SAFETY: this closure runs in the forked child, between `fork`
            // and `execve`. It performs only the three syscalls named on
            // `ChildContainment`, through the two admitted crates, over a
            // descriptor and a byte vector the controller built before the
            // fork; it allocates nothing on the success path and takes no
            // lock. Every refusal is a raw-errno `io::Error`, which also
            // allocates nothing, and `std` then reports it over its own
            // close-on-exec pipe and `_exit`s the child without unwinding.
            unsafe {
                command.pre_exec(move || {
                    if let Some(created) = ruleset.take() {
                        let status = created
                            .restrict_self()
                            .map_err(|_ignored| io::Error::from_raw_os_error(EPERM))?;
                        // A partially enforced path policy is exactly the
                        // silent downgrade this boundary exists to refuse.
                        if status.ruleset != landlock::RulesetStatus::FullyEnforced
                            || !status.no_new_privs
                        {
                            return Err(io::Error::from_raw_os_error(EPERM));
                        }
                    }
                    if !filter.is_empty() {
                        seccompiler::apply_filter_all_threads(&filter)
                            .map_err(|_ignored| io::Error::from_raw_os_error(EPERM))?;
                    }
                    // Installed after the network filter and never merged into
                    // it: the two carry different matched actions. Order is not
                    // a precedence decision, the kernel evaluates every
                    // installed filter and keeps the highest-precedence answer
                    // regardless of install order.
                    if !namespace_filter.is_empty() {
                        seccompiler::apply_filter_all_threads(&namespace_filter)
                            .map_err(|_ignored| io::Error::from_raw_os_error(EPERM))?;
                    }
                    Ok(())
                });
            }
            command.spawn()
        }
    }

    pub(crate) use linux_release_exec::{
        ChildContainment, duplicate_onto, spawn_with_child_containment,
    };

    fn require_exact_helper_descriptors(
        expected_cgroup_procs: DescriptorIdentity,
        expected_parent_pid: u32,
    ) -> Result<(), ProtocolFailure> {
        let proc_statistics = statfs("/proc/self")
            .map_err(|error| ProtocolFailure::new(format!("inspect helper procfs: {error}")))?;
        if proc_statistics.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(ProtocolFailure::new("helper /proc is not genuine procfs"));
        }
        let directory = open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| ProtocolFailure::new(format!("open helper fd table: {error}")))?;
        if directory.as_raw_fd() != 3 {
            return Err(ProtocolFailure::new(
                "helper inherited a descriptor outside exact fd 0, 1, and 2",
            ));
        }
        let mut buffer = [MaybeUninit::uninit(); 2_048];
        let mut entries = RawDir::new(&directory, &mut buffer);
        let mut descriptors = BTreeSet::new();
        while let Some(entry) = entries.next() {
            let entry = entry
                .map_err(|error| ProtocolFailure::new(format!("enumerate helper fds: {error}")))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let text = std::str::from_utf8(name)
                .map_err(|_| ProtocolFailure::new("helper fd name is not UTF-8"))?;
            let descriptor = text
                .parse::<i32>()
                .map_err(|_| ProtocolFailure::new("helper fd name is not numeric"))?;
            descriptors.insert(descriptor);
        }
        if descriptors != BTreeSet::from([0, 1, 2, 3]) {
            return Err(ProtocolFailure::new(
                "helper descriptor table is not exactly control, status, cgroup.procs, and the transient inspector",
            ));
        }
        drop(directory);
        let actual = descriptor_identity(std::io::stderr())
            .map_err(|error| ProtocolFailure::new(format!("inspect helper cgroup fd: {error}")))?;
        if actual != expected_cgroup_procs {
            return Err(ProtocolFailure::new(
                "helper fd 2 differs from the retained cgroup.procs identity",
            ));
        }
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let stdin_metadata = fstat(&stdin)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper control fd: {error}")))?;
        let stdout_metadata = fstat(&stdout)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper status fd: {error}")))?;
        let stderr_metadata = fstat(&stderr)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper cgroup fd: {error}")))?;
        if !FileType::from_raw_mode(stdin_metadata.st_mode).is_socket()
            || !FileType::from_raw_mode(stdout_metadata.st_mode).is_fifo()
            || !FileType::from_raw_mode(stderr_metadata.st_mode).is_file()
        {
            return Err(ProtocolFailure::new(
                "helper fd 0 is not a control socket, fd 1 is not a pipe, or fd 2 is not a cgroup-style regular file",
            ));
        }
        require_receive_only_control_socket(&stdin, expected_parent_pid)?;
        let stdout_flags = rustix::fs::fcntl_getfl(&stdout)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper status fd: {error}")))?;
        let stderr_flags = rustix::fs::fcntl_getfl(&stderr)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper cgroup fd: {error}")))?;
        if stdout_flags & OFlags::ACCMODE != OFlags::WRONLY
            || stderr_flags & OFlags::ACCMODE != OFlags::WRONLY
        {
            return Err(ProtocolFailure::new(
                "helper descriptor access modes are not write-status/write-cgroup",
            ));
        }
        Ok(())
    }

    /// Verifies that the helper's control socket accepts reads but rejects sends.
    /// The controller shuts down its receive direction, and the helper must observe
    /// `EPIPE` on a zero-length send. `SO_PEERCRED` also binds the socketpair to the
    /// authenticated parent. `SCM_RIGHTS` remains usable with a non-dumpable parent.
    fn require_receive_only_control_socket<Fd: AsFd>(
        control: Fd,
        expected_parent_pid: u32,
    ) -> Result<(), ProtocolFailure> {
        let control = control.as_fd();
        let domain = rustix::net::sockopt::socket_domain(control).map_err(|error| {
            ProtocolFailure::new(format!("inspect helper control domain: {error}"))
        })?;
        let socket_type = rustix::net::sockopt::socket_type(control).map_err(|error| {
            ProtocolFailure::new(format!("inspect helper control type: {error}"))
        })?;
        let listening = rustix::net::sockopt::socket_acceptconn(control).map_err(|error| {
            ProtocolFailure::new(format!("inspect helper control state: {error}"))
        })?;
        if domain != AddressFamily::UNIX || socket_type != SocketType::STREAM || listening {
            return Err(ProtocolFailure::new(
                "helper control descriptor is not a connected AF_UNIX stream socket",
            ));
        }
        let peer = rustix::net::sockopt::socket_peercred(control).map_err(|error| {
            ProtocolFailure::new(format!("inspect helper control peer: {error}"))
        })?;
        if u32::try_from(peer.pid.as_raw_pid()).ok() != Some(expected_parent_pid) {
            return Err(ProtocolFailure::new(
                "helper control socket was not created by the authenticated parent process",
            ));
        }
        match rustix::net::send(control, &[], SendFlags::NOSIGNAL) {
            Err(rustix::io::Errno::PIPE) => Ok(()),
            Ok(_) => Err(ProtocolFailure::new(
                "helper control socket accepted a send; its transmit direction is not shut down",
            )),
            Err(error) => Err(ProtocolFailure::new(format!(
                "probe helper control transmit direction: {error}"
            ))),
        }
    }

    fn require_exact_current_descriptor_set(expected: &[i32]) -> Result<(), ProtocolFailure> {
        let directory = open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| ProtocolFailure::new(format!("open current fd table: {error}")))?;
        let inspector = directory.as_raw_fd();
        let mut expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if !expected.insert(inspector) {
            return Err(ProtocolFailure::new(
                "fd-table inspector collided with an expected live descriptor",
            ));
        }
        let mut buffer = [MaybeUninit::uninit(); 4_096];
        let mut actual = BTreeSet::new();
        let mut entries = RawDir::new(&directory, &mut buffer);
        while let Some(entry) = entries.next() {
            let entry = entry
                .map_err(|error| ProtocolFailure::new(format!("enumerate current fds: {error}")))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let descriptor = std::str::from_utf8(name)
                .ok()
                .and_then(|value| value.parse::<i32>().ok())
                .filter(|value| *value >= 0)
                .ok_or_else(|| {
                    ProtocolFailure::new("current fd table contains a noncanonical descriptor")
                })?;
            actual.insert(descriptor);
        }
        if actual != expected {
            return Err(ProtocolFailure::new(format!(
                "current descriptor set was {actual:?}, expected {expected:?}"
            )));
        }
        Ok(())
    }

    fn raw_descriptor_u32(file: &File, role: &'static str) -> Result<u32, ProtocolFailure> {
        let descriptor = u32::try_from(file.as_raw_fd())
            .map_err(|_| ProtocolFailure::new(format!("{role} descriptor does not fit u32")))?;
        if descriptor <= 2 {
            return Err(ProtocolFailure::new(format!(
                "{role} unexpectedly occupies a standard descriptor"
            )));
        }
        Ok(descriptor)
    }

    fn set_helper_control_nonblocking() -> Result<(), ProtocolFailure> {
        let stdin = std::io::stdin();
        let flags = rustix::fs::fcntl_getfl(&stdin)
            .map_err(|error| ProtocolFailure::new(format!("inspect helper control: {error}")))?;
        rustix::fs::fcntl_setfl(&stdin, flags | OFlags::NONBLOCK).map_err(|error| {
            ProtocolFailure::new(format!("set helper control nonblocking: {error}"))
        })
    }

    /// Reads one control frame that must carry no descriptors at all.
    fn read_stdin_frame() -> Result<Vec<u8>, ProtocolFailure> {
        let (bytes, descriptors) = read_stdin_frame_with_descriptors()?;
        if !descriptors.is_empty() {
            return Err(ProtocolFailure::new(
                "control frame carried descriptors where the protocol admits none",
            ));
        }
        Ok(bytes)
    }

    fn read_stdin_frame_with_descriptors() -> Result<(Vec<u8>, Vec<OwnedFd>), ProtocolFailure> {
        read_control_frame_with_timeout(HELPER_TIMEOUT)
            .map_err(|error| ProtocolFailure::new(format!("read helper control: {error}")))
    }

    /// Receives a bounded control frame and its `SCM_RIGHTS` descriptors.
    /// Use nonblocking `recvmsg` with bounded polling, retry `EAGAIN`, refuse
    /// `POLLERR`, report closure as `UnexpectedEof`, and reject oversized frames,
    /// trailing bytes and truncated ancillary data.
    ///
    /// Consult the deadline only after a poll finds no input. The parent queues
    /// each atomic frame before resuming the helper, so a valid frame remains
    /// readable after a long SIGSTOP hold. Collect descriptors across receives;
    /// the caller checks their count for the exact sequence number.
    fn read_control_frame_with_timeout(
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<OwnedFd>), io::Error> {
        let control = std::io::stdin();
        let deadline = Instant::now() + timeout;
        let expired = || {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out reading held-launcher control frame",
            )
        };
        let mut bytes = Vec::with_capacity(256);
        let mut received = Vec::new();
        loop {
            if bytes.len() >= MAX_CONTROL_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "helper control frame exceeded its hard byte bound",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout = Timespec {
                tv_sec: remaining.as_secs().try_into().unwrap_or(i64::MAX),
                tv_nsec: remaining.subsec_nanos().into(),
            };
            let mut descriptors = [PollFd::new(
                &control,
                PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
            )];
            let ready = poll(&mut descriptors, Some(&timeout)).map_err(io::Error::from)?;
            if ready == 0 {
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                continue;
            }
            if descriptors[0].revents().contains(PollFlags::ERR) {
                return Err(io::Error::other(
                    "held-launcher control channel reported an error",
                ));
            }
            let mut chunk = [0u8; 256];
            let mut space = [MaybeUninit::uninit();
                rustix::cmsg_space!(ScmRights(MAX_RELEASE_SCM_DESCRIPTOR_COUNT))];
            let mut ancillary = RecvAncillaryBuffer::new(&mut space);
            let message = match recvmsg(
                &control,
                &mut [IoSliceMut::new(&mut chunk)],
                &mut ancillary,
                RecvFlags::CMSG_CLOEXEC,
            ) {
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    if Instant::now() >= deadline {
                        return Err(expired());
                    }
                    continue;
                }
                result => result.map_err(io::Error::from)?,
            };
            if message.flags.contains(ReturnFlags::CTRUNC) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "held-launcher control message was truncated before its descriptors",
                ));
            }
            for ancillary_message in ancillary.drain() {
                match ancillary_message {
                    RecvAncillaryMessage::ScmRights(fds) => received.extend(fds),
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "held-launcher control channel carried a non-descriptor control message",
                        ));
                    }
                }
                if received.len() > MAX_RELEASE_SCM_DESCRIPTOR_COUNT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "held-launcher control channel carried more descriptors than the protocol admits",
                    ));
                }
            }
            let count = message.bytes;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "held-launcher control pipe closed before a complete frame",
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.last() == Some(&b'\n') {
                return Ok((bytes, received));
            }
            if bytes.contains(&b'\n') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "held-launcher control pipe contained trailing bytes after a frame",
                ));
            }
        }
    }

    fn write_stdout_frame<T: Serialize>(value: &T) -> Result<(), ProtocolFailure> {
        let bytes = encode_frame(value)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&bytes)
            .and_then(|()| stdout.flush())
            .map_err(|error| ProtocolFailure::new(format!("write helper status: {error}")))
    }

    fn write_file_frame<T: Serialize>(file: &mut File, value: &T) -> Result<(), ProtocolFailure> {
        let bytes = encode_frame(value)?;
        file.write_all(&bytes)
            .and_then(|()| file.flush())
            .map_err(|error| ProtocolFailure::new(format!("write setup status: {error}")))
    }

    fn next_utf8(
        arguments: &mut impl Iterator<Item = OsString>,
        field: &'static str,
    ) -> Result<String, ProtocolFailure> {
        arguments
            .next()
            .ok_or_else(|| ProtocolFailure::new(format!("helper lacks {field}")))?
            .into_string()
            .map_err(|_| ProtocolFailure::new(format!("helper {field} is not UTF-8")))
    }

    fn next_u32(
        arguments: &mut impl Iterator<Item = OsString>,
        field: &'static str,
    ) -> Result<u32, ProtocolFailure> {
        let text = next_utf8(arguments, field)?;
        let value = text
            .parse::<u32>()
            .map_err(|_| ProtocolFailure::new(format!("helper {field} is not u32")))?;
        if value == 0 || value.to_string() != text {
            return Err(ProtocolFailure::new(format!(
                "helper {field} is zero or noncanonical"
            )));
        }
        Ok(value)
    }

    fn next_u64(
        arguments: &mut impl Iterator<Item = OsString>,
        field: &'static str,
    ) -> Result<u64, ProtocolFailure> {
        let text = next_utf8(arguments, field)?;
        let value = text
            .parse::<u64>()
            .map_err(|_| ProtocolFailure::new(format!("helper {field} is not u64")))?;
        if value == 0 || value.to_string() != text {
            return Err(ProtocolFailure::new(format!(
                "helper {field} is zero or noncanonical"
            )));
        }
        Ok(value)
    }
