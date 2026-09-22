fn validate_contained_resource_limits(limits: ResourceLimits) -> Result<(), SupervisorError> {
    if limits.wall_time_ms == 0 || limits.max_output_bytes == 0 || limits.max_processes == 0 {
        return Err(SupervisorError::UnenforceableLimit(
            "contained command limits must all be greater than zero".into(),
        ));
    }
    if limits.max_output_bytes > MAX_CAPTURE_LIMIT {
        return Err(SupervisorError::UnenforceableLimit(format!(
            "max_output_bytes exceeds the bounded {MAX_CAPTURE_LIMIT}-byte contained evidence ceiling"
        )));
    }
    if limits.max_memory_bytes == Some(0) {
        return Err(SupervisorError::UnenforceableLimit(
            "contained memory limit must be greater than zero".into(),
        ));
    }
    Ok(())
}

fn build_contained_environment(
    policy: &CompiledExecutionPolicy,
) -> Result<ScrubbedEnvironment, SupervisorError> {
    let mut environment = EnvironmentPolicy::empty().scrub([] as [(&str, &str); 0]);
    for variable in &policy.contract().environment {
        if is_reserved_policy_environment(&variable.name) {
            return Err(SupervisorError::InvalidCommand(format!(
                "policy environment variable `{}` is a host channel or backend-owned value",
                variable.name
            )));
        }
        environment
            .set_trusted_override(variable.name.clone(), variable.value.clone())
            .map_err(|error| SupervisorError::InvalidCommand(error.to_string()))?;
    }
    Ok(environment)
}

fn validate_contained_execution_root(
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    role: RunnerRole,
    execution_root_manifest: &WorkspaceManifest,
    authenticated_private_state_root: &Path,
    authenticated_execution_root: &Path,
) -> Result<PathBuf, SupervisorError> {
    let live = grant.identity().canonical_root();
    if role != RunnerRole::Worker
        || policy.contract().mutation_mode != MutationMode::ShadowWorkspace
    {
        return Err(SupervisorError::Authority(
            "only an exact Worker shadow execution root is currently supported".into(),
        ));
    }
    let candidate = paths.shadow_root.as_deref().ok_or_else(|| {
        SupervisorError::InvalidCommand(
            "Worker contained command requires a private shadow root".into(),
        )
    })?;
    if paths.private_state_root != authenticated_private_state_root
        || candidate != authenticated_execution_root
    {
        return Err(SupervisorError::Authority(
            "caller command roots differ from the initialized Worker's retained root custody"
                .into(),
        ));
    }
    if execution_root_manifest.root() != candidate {
        return Err(SupervisorError::Authority(
            "execution-root manifest names a different root than the Worker shadow".into(),
        ));
    }
    if !candidate.is_absolute() {
        return Err(SupervisorError::InvalidCommand(
            "contained execution root is not absolute".into(),
        ));
    }
    let named = fs::symlink_metadata(candidate)?;
    if !named.file_type().is_dir() {
        return Err(SupervisorError::InvalidCommand(
            "contained execution root is not a real directory".into(),
        ));
    }
    let canonical = fs::canonicalize(candidate)?;
    if canonical != candidate {
        return Err(SupervisorError::InvalidCommand(
            "contained execution root must already be canonical and cannot be a symlink".into(),
        ));
    }
    if canonical.starts_with(live) || live.starts_with(&canonical) {
        return Err(SupervisorError::InvalidCommand(
            "contained shadow root must be disjoint from the live workspace".into(),
        ));
    }
    let private_state_root = fs::canonicalize(&paths.private_state_root)?;
    if private_state_root != paths.private_state_root
        || private_state_root.starts_with(live)
        || live.starts_with(&private_state_root)
        || canonical == private_state_root
        || !canonical.starts_with(&private_state_root)
    {
        return Err(SupervisorError::InvalidCommand(
            "contained shadow must be a strict child of the exact disjoint private-state root"
                .into(),
        ));
    }
    let private_state_metadata = fs::symlink_metadata(&private_state_root)?;
    if !private_state_metadata.file_type().is_dir()
        || private_state_metadata.permissions().mode() & 0o777 != 0o700
        || private_state_metadata.uid() != rustix::process::geteuid().as_raw()
        || named.permissions().mode() & 0o777 != 0o700
        || named.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(SupervisorError::InvalidCommand(
            "contained private-state and shadow roots must be owner-owned mode 0700 directories"
                .into(),
        ));
    }
    Ok(canonical)
}

fn validate_retained_root_topology(
    private_state_root: &RetainedDirectory,
    execution_root: &RetainedDirectory,
    live_root: &Path,
) -> Result<(), SupervisorError> {
    if private_state_root.path.starts_with(live_root)
        || live_root.starts_with(&private_state_root.path)
        || execution_root.path.starts_with(live_root)
        || live_root.starts_with(&execution_root.path)
        || execution_root.path == private_state_root.path
        || !execution_root.path.starts_with(&private_state_root.path)
        || private_state_root.identity.owner_uid != rustix::process::geteuid().as_raw()
        || execution_root.identity.owner_uid != rustix::process::geteuid().as_raw()
        || private_state_root.identity.mode != 0o700
        || execution_root.identity.mode != 0o700
    {
        return Err(SupervisorError::Capability(
            "retained Worker private-state/shadow custody is no longer an exact owner-private disjoint parent-child pair"
                .into(),
        ));
    }
    Ok(())
}

fn validate_execution_root_manifest(
    manifest: &WorkspaceManifest,
    grant: &IssuedWorkspaceGrant,
    execution_root: &Path,
    expected_snapshot: &Digest,
) -> Result<(), SupervisorError> {
    if manifest.root() != execution_root
        || manifest.snapshot().grant_hash != grant.contract().grant_hash
        || &manifest.snapshot().snapshot_id != expected_snapshot
    {
        return Err(SupervisorError::Authority(
            "execution-root manifest differs from the exact root, grant, or command-effect input snapshot"
                .into(),
        ));
    }
    Ok(())
}

fn validate_retained_execution_snapshot(
    execution_root: &RetainedDirectory,
    grant: &IssuedWorkspaceGrant,
    expected_snapshot: &Digest,
) -> Result<(), SupervisorError> {
    let observed = capture_manifest(
        &execution_root.descriptor,
        execution_root.path.clone(),
        grant.contract().grant_hash.clone(),
        1,
    )
    .map_err(|error| {
        SupervisorError::Capability(format!(
            "cannot descriptor-capture retained command execution root: {error}"
        ))
    })?;
    if observed.root() != execution_root.path
        || &observed.snapshot().snapshot_id != expected_snapshot
    {
        return Err(SupervisorError::Authority(
            "retained command execution root differs from the exact effect input snapshot".into(),
        ));
    }
    Ok(())
}

fn retain_proved_directory(
    path: &Path,
    descriptor: Dir,
) -> Result<RetainedDirectory, SupervisorError> {
    require_descriptor_cloexec(descriptor.as_fd(), "session-proved directory")?;
    let canonical = fs::canonicalize(path)?;
    let identity = DirectoryIdentity::from_capability(&descriptor)?;
    if canonical != path || identity != DirectoryIdentity::from_named(path)? {
        return Err(SupervisorError::Capability(format!(
            "session-proved command directory changed before preparation: {}",
            path.display()
        )));
    }
    Ok(RetainedDirectory {
        path: path.to_path_buf(),
        identity,
        descriptor,
    })
}
fn retain_relative_directory(
    root: &RetainedDirectory,
    relative: &Path,
    root_path: &Path,
) -> Result<RetainedDirectory, SupervisorError> {
    if contains_git_component(relative) {
        return Err(SupervisorError::InvalidCommand(
            "contained working directory cannot enter protected .git metadata".into(),
        ));
    }
    let mut descriptor = root.descriptor.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(SupervisorError::InvalidCommand(
                "contained working directory is not normalized and relative".into(),
            ));
        };
        descriptor = descriptor.open_dir_nofollow(name).map_err(|error| {
            SupervisorError::InvalidCommand(format!(
                "cannot open contained cwd component {} without following links: {error}",
                name.to_string_lossy()
            ))
        })?;
    }
    require_descriptor_cloexec(descriptor.as_fd(), "working directory")?;
    let path = root_path.join(relative);
    let identity = DirectoryIdentity::from_capability(&descriptor)?;
    if identity != DirectoryIdentity::from_named(&path)? {
        return Err(SupervisorError::Capability(
            "contained cwd changed while its descriptor was acquired".into(),
        ));
    }
    Ok(RetainedDirectory {
        path,
        identity,
        descriptor,
    })
}

fn retain_executable(identity: ExecutableIdentity) -> Result<RetainedExecutable, SupervisorError> {
    let descriptor = open(
        &identity.canonical_path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let descriptor = File::from(descriptor);
    let retained = RetainedExecutable {
        identity,
        descriptor,
    };
    retained.revalidate()?;
    Ok(retained)
}

fn require_descriptor_cloexec(
    descriptor: std::os::fd::BorrowedFd<'_>,
    kind: &'static str,
) -> Result<(), SupervisorError> {
    let number = descriptor.as_raw_fd();
    let flags = fcntl_getfd(descriptor).map_err(|error| {
        SupervisorError::Capability(format!(
            "cannot inspect retained {kind} descriptor {number}: {error}"
        ))
    })?;
    if !flags.contains(FdFlags::CLOEXEC) {
        return Err(SupervisorError::Capability(format!(
            "retained {kind} descriptor {number} is inheritable before launcher handoff"
        )));
    }
    Ok(())
}

fn hash_open_file(file: &File) -> Result<Digest, SupervisorError> {
    use std::os::unix::fs::FileExt as _;

    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read_at(&mut buffer, offset)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        offset = offset
            .checked_add(u64::try_from(count).expect("read buffer length fits u64"))
            .ok_or_else(|| {
                SupervisorError::Capability("executable length overflowed u64".into())
            })?;
    }
    Ok(digest_from_sha(hasher.finalize().into()))
}

fn compute_contained_launch_digest(
    prepared: &PreparedContainedCommand,
) -> Result<Digest, SupervisorError> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, CONTAINED_LAUNCH_DIGEST_DOMAIN);
    let authority_bytes = prepared.canonical_authority_bytes()?;
    hash_frame(&mut hasher, &authority_bytes);
    hash_frame(&mut hasher, prepared.execution_snapshot.as_str().as_bytes());
    hash_frame(
        &mut hasher,
        prepared.policy.contract().policy_hash.as_str().as_bytes(),
    );
    hash_frame(
        &mut hasher,
        prepared.detector_policy.policy_digest.as_str().as_bytes(),
    );
    hash_frame(&mut hasher, prepared.command.program.as_bytes());
    hash_frame(
        &mut hasher,
        &u64::try_from(prepared.command.arguments.len())
            .map_err(|_| SupervisorError::InvalidCommand("too many arguments".into()))?
            .to_be_bytes(),
    );
    for argument in &prepared.command.arguments {
        hash_frame(&mut hasher, argument.as_bytes());
    }
    hash_frame(
        &mut hasher,
        prepared.command.working_directory.as_os_str().as_bytes(),
    );
    hash_frame(
        &mut hasher,
        prepared
            .executable
            .identity
            .canonical_path
            .as_os_str()
            .as_bytes(),
    );
    hash_frame(
        &mut hasher,
        prepared
            .executable
            .identity
            .content_digest
            .as_str()
            .as_bytes(),
    );
    hash_contained_directory_authority(&mut hasher, prepared);
    hash_frame(
        &mut hasher,
        &u64::try_from(prepared.environment.variables().len())
            .map_err(|_| SupervisorError::InvalidCommand("too many environment entries".into()))?
            .to_be_bytes(),
    );
    for (name, value) in prepared.environment.variables() {
        hash_frame(&mut hasher, name.as_bytes());
        hash_frame(&mut hasher, value.as_bytes());
    }
    let limits = prepared.policy.contract().resource_limits;
    hash_frame(&mut hasher, &limits.wall_time_ms.to_be_bytes());
    hash_frame(&mut hasher, &limits.max_output_bytes.to_be_bytes());
    hash_frame(&mut hasher, &limits.max_processes.to_be_bytes());
    match limits.max_memory_bytes {
        Some(memory) => {
            hash_frame(&mut hasher, b"memory_some");
            hash_frame(&mut hasher, &memory.to_be_bytes());
        }
        None => hash_frame(&mut hasher, b"memory_none"),
    }
    hash_frame(
        &mut hasher,
        match prepared.policy.contract().network {
            ExecutionNetwork::None => b"network_none",
            ExecutionNetwork::FullForAction => b"network_full_for_action",
        },
    );
    hash_frame(
        &mut hasher,
        match prepared.policy.contract().mutation_mode {
            MutationMode::ReadOnly => b"mutation_read_only",
            MutationMode::ShadowWorkspace => b"mutation_shadow_workspace",
        },
    );
    Ok(digest_from_sha(hasher.finalize().into()))
}

fn hash_contained_directory_authority(hasher: &mut Sha256, prepared: &PreparedContainedCommand) {
    let directories = [
        &prepared.private_state_root,
        &prepared.execution_root,
        &prepared.working_directory,
    ];
    for directory in directories {
        hash_frame(hasher, directory.path.as_os_str().as_bytes());
    }
    for value in [
        prepared.executable.identity.device,
        prepared.executable.identity.inode,
        prepared.private_state_root.identity.device,
        prepared.private_state_root.identity.inode,
        prepared.execution_root.identity.device,
        prepared.execution_root.identity.inode,
        prepared.working_directory.identity.device,
        prepared.working_directory.identity.inode,
    ] {
        hash_frame(hasher, &value.to_be_bytes());
    }
    for directory in directories {
        hash_frame(hasher, &directory.identity.owner_uid.to_be_bytes());
        hash_frame(hasher, &directory.identity.mode.to_be_bytes());
    }
}

fn compute_preflight_digest(
    launch_digest: &Digest,
    backend: &BackendIdentity,
    controls: &BTreeSet<BackendControl>,
    descriptors: &[i32; 3],
    canary_digest: &Digest,
) -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, CONTAINED_PREFLIGHT_DIGEST_DOMAIN);
    hash_frame(&mut hasher, launch_digest.as_str().as_bytes());
    hash_frame(&mut hasher, backend.backend_id.as_bytes());
    hash_frame(
        &mut hasher,
        backend.implementation_digest.as_str().as_bytes(),
    );
    hash_frame(
        &mut hasher,
        command_domain_backend_label(backend.command_domain_backend),
    );
    for control in controls {
        hash_frame(&mut hasher, control.label());
    }
    for descriptor in descriptors {
        hash_frame(&mut hasher, &descriptor.to_be_bytes());
    }
    hash_frame(&mut hasher, canary_digest.as_str().as_bytes());
    digest_from_sha(hasher.finalize().into())
}

const fn command_domain_backend_label(backend: CommandDomainCleanupBackend) -> &'static [u8] {
    match backend {
        CommandDomainCleanupBackend::LinuxCgroupV2 => b"linux_cgroup_v2",
        CommandDomainCleanupBackend::MacOsDedicatedIdentity => b"macos_dedicated_identity",
    }
}
