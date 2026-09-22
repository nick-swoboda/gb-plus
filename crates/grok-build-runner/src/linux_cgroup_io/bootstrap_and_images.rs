impl LinuxNativeServiceBootstrapAuthority {
    /// Test-only construction from already-retained descriptor capabilities.
    ///
    /// This intentionally does not model an authenticated production
    /// bootstrap or claim that a temporary test filesystem is cgroup v2. It
    /// exists only to prove crossing, restart, replacement, and canonical
    /// evidence behavior while production minting remains absent.
    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the test-only constructor keeps every independently retained bootstrap capability and publication boundary explicit"
    )]
    fn open_test_authenticated(
        service_state_root: Dir,
        journal_binding: LinuxServiceCommandJournalBinding,
        service_parent: Dir,
        delegation_name: &str,
        bubblewrap_parent: Dir,
        bubblewrap_name: &str,
        evidence: LinuxNativeServiceBootstrapEvidenceV1,
    ) -> Result<(Self, LinuxServiceCommandJournalAuthority), CgroupIoFailure> {
        validate_service_bootstrap_evidence(&evidence)?;
        if !service_journal_binding_matches_plan(&journal_binding, &evidence.plan_binding.journal) {
            return Err(failure(
                "bind-linux-service-bootstrap",
                EffectCertainty::NotApplied,
                "bootstrap evidence differs from the fixed service state, journal, platform service, or delegated cgroup binding",
            ));
        }
        validate_component("bootstrap delegation", delegation_name)?;
        validate_component("bootstrap Bubblewrap name", bubblewrap_name)?;
        if evidence.cgroup.delegation_component != delegation_name {
            return Err(failure(
                "bind-linux-service-bootstrap",
                EffectCertainty::NotApplied,
                "bootstrap delegation component differs from retained evidence",
            ));
        }
        let expected_bubblewrap_name = Path::new(&evidence.plan_binding.bubblewrap.resolved_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                failure(
                    "bind-linux-service-bootstrap",
                    EffectCertainty::NotApplied,
                    "plan Bubblewrap path has no normalized filename",
                )
            })?;
        if expected_bubblewrap_name != bubblewrap_name {
            return Err(failure(
                "bind-linux-service-bootstrap",
                EffectCertainty::NotApplied,
                "retained Bubblewrap name differs from the canonical plan path",
            ));
        }

        let mut journal_authority =
            LinuxServiceCommandJournalAuthority::open_test_service_singleton(
                service_state_root,
                journal_binding,
            )?;
        let capabilities = LinuxNativeServiceBootstrapCapabilities::open_retained(
            &journal_authority.journal,
            service_parent,
            delegation_name,
            bubblewrap_parent,
            bubblewrap_name,
        )?;
        let authority = Self::publish(evidence, capabilities, &mut journal_authority)?;
        Ok((authority, journal_authority))
    }

    fn publish(
        evidence: LinuxNativeServiceBootstrapEvidenceV1,
        capabilities: LinuxNativeServiceBootstrapCapabilities,
        journal_authority: &mut LinuxServiceCommandJournalAuthority,
    ) -> Result<Self, CgroupIoFailure> {
        let token = journal_authority.journal.acquire_lock()?;
        let prepared = (|| {
            capabilities.validate_for(
                &evidence,
                &journal_authority.residual,
                &journal_authority.journal,
            )?;
            let (canonical_evidence, persisted_identity) =
                persist_or_read_service_bootstrap_evidence(
                    &journal_authority.journal.parent,
                    journal_authority.journal.expected_owner_uid,
                    &evidence,
                )?;
            let (evidence_artifact, evidence_artifact_identity, retained_bytes) =
                open_retained_bootstrap_artifact(
                    &journal_authority.journal.parent,
                    journal_authority.journal.expected_owner_uid,
                )
                .map_err(|error| {
                    failure(
                        "retain-linux-service-bootstrap-artifact",
                        EffectCertainty::Ambiguous,
                        error.detail,
                    )
                })?;
            if evidence_artifact_identity != persisted_identity
                || retained_bytes != canonical_evidence
            {
                return Err(failure(
                    "retain-linux-service-bootstrap-artifact",
                    EffectCertainty::Ambiguous,
                    "retained bootstrap artifact differs from the exact published identity or bytes",
                ));
            }
            Ok((
                canonical_evidence,
                evidence_artifact,
                evidence_artifact_identity,
            ))
        })();
        let release = journal_authority.journal.release_lock(token);
        let (canonical_evidence, evidence_artifact, evidence_artifact_identity) =
            match (prepared, release) {
                (Ok(prepared), Ok(())) => prepared,
                (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
                (Err(primary), Err(release)) => {
                    return Err(failure(
                        primary.operation,
                        EffectCertainty::Ambiguous,
                        format!(
                            "bootstrap evidence failed: {}; retained-lock release also failed: {}",
                            primary.detail, release.detail
                        ),
                    ));
                }
            };

        let authority = Self {
            evidence,
            canonical_evidence,
            evidence_artifact,
            evidence_artifact_identity,
            capabilities,
        };
        authority.validate_retained(&journal_authority.residual, &journal_authority.journal)?;
        Ok(authority)
    }

    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn require_exact_plan(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
        residual: &LinuxServiceJournalAuthenticationResidualV1,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        let expected = plan.service_bootstrap_binding().map_err(|error| {
            failure(
                "bind-linux-service-bootstrap-plan",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if expected != self.evidence.plan_binding {
            return Err(failure(
                "bind-linux-service-bootstrap-plan",
                EffectCertainty::NotApplied,
                "journaled command plan differs from retained service roots, delegation, Bubblewrap version/image, Landlock ABI window, or seccomp contract",
            ));
        }
        self.validate_retained(residual, journal)
    }

    fn validate_retained(
        &self,
        residual: &LinuxServiceJournalAuthenticationResidualV1,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        self.capabilities
            .validate_for(&self.evidence, residual, journal)?;
        let artifact_metadata = self.evidence_artifact.metadata().map_err(|error| {
            io_failure(
                "validate-linux-service-bootstrap-artifact",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_private_file(&artifact_metadata, journal.expected_owner_uid)?;
        let artifact_identity = object_identity(&artifact_metadata);
        require_named_identity(
            &journal.parent,
            SERVICE_BOOTSTRAP_FINAL_NAME,
            artifact_identity,
            "validate-linux-service-bootstrap-artifact",
        )?;
        let artifact_bytes = read_retained_bootstrap_file(
            &self.evidence_artifact,
            MAX_SERVICE_BOOTSTRAP_BYTES,
            "validate-linux-service-bootstrap-artifact",
        )?;
        let decoded = decode_service_bootstrap_envelope(&artifact_bytes)?;
        if artifact_identity != self.evidence_artifact_identity
            || artifact_bytes != self.canonical_evidence
            || !same_service_bootstrap_identity(&decoded.evidence, &self.evidence)
        {
            return Err(failure(
                "validate-linux-service-bootstrap-artifact",
                EffectCertainty::NotApplied,
                "fixed service-bootstrap artifact identity or canonical evidence changed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxRetainedDirectoryObservation {
    identity: ObjectIdentity,
    mount_id: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
}

impl LinuxRetainedDirectoryObservation {
    fn observe(directory: &Dir, operation: &'static str) -> Result<Self, CgroupIoFailure> {
        let metadata = directory
            .dir_metadata()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        if !metadata.is_dir() {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "executable provenance component is not a directory",
            ));
        }
        Ok(Self {
            identity: object_identity(&metadata),
            mount_id: retained_directory_mount_id(directory, operation)?,
            mode: OsMetadataExt::mode(&metadata),
            owner_uid: OsMetadataExt::uid(&metadata),
            owner_gid: OsMetadataExt::gid(&metadata),
        })
    }
}

#[derive(Debug)]
struct LinuxRetainedDirectoryComponent {
    name: String,
    directory: Dir,
    observation: LinuxRetainedDirectoryObservation,
}

/// Retained proof that one normalized absolute executable name still resolves
/// through the same no-follow directory chain, filesystem objects, mounts, and
/// final regular-file descriptor.
///
/// `/` is the only ambient name opened. Every remaining component is opened
/// relative to the preceding retained descriptor. Names are revalidation
/// handles only; the retained descriptors and kernel observations are the
/// authority.
#[derive(Debug)]
struct LinuxRetainedExecutablePathProvenance {
    absolute_path: String,
    root: Dir,
    root_observation: LinuxRetainedDirectoryObservation,
    parents: Vec<LinuxRetainedDirectoryComponent>,
    final_name: String,
    file: File,
    file_identity: ObjectIdentity,
    file_mount_id: u64,
}

impl LinuxRetainedExecutablePathProvenance {
    fn open_absolute(
        absolute_path: &str,
        operation: &'static str,
    ) -> Result<Self, CgroupIoFailure> {
        let components = normalized_executable_provenance_components(absolute_path, operation)?;
        let (final_name, parent_names) = components.split_last().ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                "executable provenance path does not name a file",
            )
        })?;
        let root = Dir::open_ambient_dir("/", cap_std::ambient_authority())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let root_observation = LinuxRetainedDirectoryObservation::observe(&root, operation)?;
        let mut current = root
            .try_clone()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let mut parents = Vec::with_capacity(parent_names.len());
        for name in parent_names {
            let directory = current
                .open_dir_nofollow(name)
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            let observation = LinuxRetainedDirectoryObservation::observe(&directory, operation)?;
            current = directory
                .try_clone()
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            parents.push(LinuxRetainedDirectoryComponent {
                name: name.clone(),
                directory,
                observation,
            });
        }
        let (file, file_identity) =
            open_retained_nofollow_regular_file(&current, final_name, operation)?;
        let file_mount_id = retained_file_mount_id(&file, operation)?;
        let authority = Self {
            absolute_path: absolute_path.to_owned(),
            root,
            root_observation,
            parents,
            final_name: final_name.clone(),
            file,
            file_identity,
            file_mount_id,
        };
        authority.validate_named(operation)?;
        Ok(authority)
    }

    fn validate_named(&self, operation: &'static str) -> Result<(), CgroupIoFailure> {
        let retained_root = LinuxRetainedDirectoryObservation::observe(&self.root, operation)?;
        let named_root = Dir::open_ambient_dir("/", cap_std::ambient_authority())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let named_root_observation =
            LinuxRetainedDirectoryObservation::observe(&named_root, operation)?;
        if retained_root != self.root_observation || named_root_observation != self.root_observation
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "executable provenance root identity, metadata, or mount changed",
            ));
        }

        let mut current = self
            .root
            .try_clone()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        for component in &self.parents {
            let retained =
                LinuxRetainedDirectoryObservation::observe(&component.directory, operation)?;
            let named = current
                .open_dir_nofollow(&component.name)
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
            let named_observation = LinuxRetainedDirectoryObservation::observe(&named, operation)?;
            if retained != component.observation || named_observation != component.observation {
                return Err(failure(
                    operation,
                    EffectCertainty::NotApplied,
                    "executable provenance parent was renamed, replaced, or mount-crossed",
                ));
            }
            current = component
                .directory
                .try_clone()
                .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        }
        require_named_file_mount_identity(
            &current,
            &self.final_name,
            self.file_identity,
            self.file_mount_id,
            operation,
        )
    }
}

fn normalized_executable_provenance_components(
    absolute_path: &str,
    operation: &'static str,
) -> Result<Vec<String>, CgroupIoFailure> {
    let expected_count = executable_provenance_component_count(absolute_path, operation)?;
    let components = Path::new(absolute_path)
        .components()
        .skip(1)
        .map(|component| match component {
            std::path::Component::Normal(name) => {
                name.to_str().map(str::to_owned).ok_or_else(|| {
                    failure(
                        operation,
                        EffectCertainty::NotApplied,
                        "executable provenance requires a bounded normalized absolute UTF-8 path",
                    )
                })
            }
            _ => Err(failure(
                operation,
                EffectCertainty::NotApplied,
                "executable provenance requires a bounded normalized absolute UTF-8 path",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    debug_assert_eq!(components.len(), expected_count);
    Ok(components)
}

fn executable_provenance_component_count(
    absolute_path: &str,
    operation: &'static str,
) -> Result<usize, CgroupIoFailure> {
    let invalid_path = || {
        failure(
            operation,
            EffectCertainty::NotApplied,
            "executable provenance requires a bounded normalized absolute UTF-8 path",
        )
    };
    if absolute_path.is_empty()
        || absolute_path.len() > MAX_EXECUTABLE_PROVENANCE_PATH_BYTES
        || absolute_path.as_bytes().contains(&0)
        || !absolute_path.starts_with('/')
        || absolute_path.ends_with('/')
        || absolute_path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid_path());
    }
    let mut component_count = 0_usize;
    for component in Path::new(absolute_path).components().skip(1) {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid_path());
        };
        let name = name.to_str().ok_or_else(&invalid_path)?;
        if name.is_empty()
            || name.len() > MAX_EXECUTABLE_PROVENANCE_COMPONENT_BYTES
            || name.chars().any(char::is_control)
        {
            return Err(invalid_path());
        }
        component_count = component_count.checked_add(1).ok_or_else(&invalid_path)?;
    }
    if component_count == 0 {
        return Err(invalid_path());
    }
    Ok(component_count)
}

/// One retained, descriptor-relative candidate for an exact planned command
/// image. Its absolute path comes only from the already-validated durable plan;
/// callers cannot select a parent directory or basename.
///
/// The candidate is not authority: only exact-set admission below can consume
/// it after revalidating the complete no-follow parent chain and file.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxSealedExecutableSnapshot {
    file: std::fs::File,
    identity: ObjectIdentity,
}

#[cfg(target_os = "linux")]
impl LinuxSealedExecutableSnapshot {
    // Sealing an executable image is one ordered sequence: create the memfd,
    // copy under a hash, apply every seal, then re-verify. Each step depends on
    // the descriptor state the previous one left behind, so extracting parts of
    // it would replace an auditable order with an implicit contract between
    // helpers.
    #[expect(
        clippy::too_many_lines,
        reason = "one ordered seal-and-verify sequence over a single descriptor; splitting it would make the ordering implicit"
    )]
    fn create(
        source: &File,
        expected: &LinuxServiceExecutableBindingV1,
    ) -> Result<Self, CgroupIoFailure> {
        use std::os::unix::fs::FileExt as _;

        let descriptor = rustix::fs::memfd_create(
            "grok-build-command-image-v1",
            rustix::fs::MemfdFlags::CLOEXEC
                | rustix::fs::MemfdFlags::ALLOW_SEALING
                | rustix::fs::MemfdFlags::EXEC,
        )
        .map_err(|error| {
            io_failure(
                "create-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let mut image = std::fs::File::from(descriptor);
        let source = source.try_clone().map_err(|error| {
            io_failure(
                "copy-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let source = source.into_std();
        let expected_length = expected.file.byte_length;
        let mut offset = 0_u64;
        // See `hash_file_exact` in the held launcher: a fixed stack buffer is
        // preferred to a heap allocation inside an authenticated fail-closed
        // path, and 32 KiB against an 8 MiB default stack is not a risk.
        #[expect(
            clippy::large_stack_arrays,
            reason = "fixed 32 KiB read buffer chosen over a heap allocation inside an authenticated fail-closed path"
        )]
        let mut buffer = [0_u8; 32 * 1_024];
        let mut hasher = Sha256::new();
        while offset < expected_length {
            let remaining = expected_length - offset;
            let maximum = usize::try_from(
                remaining.min(u64::try_from(buffer.len()).expect("buffer length fits u64")),
            )
            .map_err(|_| {
                failure(
                    "copy-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    "planned executable copy length cannot be represented",
                )
            })?;
            let count = source
                .read_at(&mut buffer[..maximum], offset)
                .map_err(|error| {
                    io_failure(
                        "copy-native-service-sealed-executable",
                        EffectCertainty::NotApplied,
                        error,
                    )
                })?;
            if count == 0 {
                return Err(failure(
                    "copy-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    format!(
                        "executable object {} ended before its planned byte length",
                        expected.object_id
                    ),
                ));
            }
            image.write_all(&buffer[..count]).map_err(|error| {
                io_failure(
                    "copy-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
            hasher.update(&buffer[..count]);
            offset = offset
                .checked_add(u64::try_from(count).map_err(|_| {
                    failure(
                        "copy-native-service-sealed-executable",
                        EffectCertainty::NotApplied,
                        "executable copy count cannot be represented",
                    )
                })?)
                .ok_or_else(|| {
                    failure(
                        "copy-native-service-sealed-executable",
                        EffectCertainty::NotApplied,
                        "executable copy offset overflowed",
                    )
                })?;
        }
        let mut extra = [0_u8; 1];
        if source
            .read_at(&mut extra, expected_length)
            .map_err(|error| {
                io_failure(
                    "copy-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?
            != 0
        {
            return Err(failure(
                "copy-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                format!(
                    "executable object {} grew beyond its planned byte length",
                    expected.object_id
                ),
            ));
        }
        let copied_digest = Digest::parse(hex_lower(&hasher.finalize())).map_err(|error| {
            failure(
                "copy-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if copied_digest != expected.file.content_sha256 {
            return Err(failure(
                "copy-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                format!(
                    "executable object {} changed while its immutable snapshot was copied",
                    expected.object_id
                ),
            ));
        }
        image.flush().map_err(|error| {
            io_failure(
                "seal-native-service-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        rustix::fs::fchmod(&image, rustix::fs::Mode::from_raw_mode(0o500)).map_err(|error| {
            io_failure(
                "seal-native-service-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let seals = rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::FUTURE_WRITE
            | rustix::fs::SealFlags::EXEC;
        if seals.bits() != REQUIRED_EXECUTABLE_SNAPSHOT_SEAL_BITS {
            return Err(failure(
                "seal-native-service-executable",
                EffectCertainty::NotApplied,
                "compiled executable memfd seal set differs from the durable admission contract",
            ));
        }
        rustix::fs::fcntl_add_seals(&image, seals).map_err(|error| {
            io_failure(
                "seal-native-service-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let metadata = image.metadata().map_err(|error| {
            io_failure(
                "seal-native-service-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let authority = Self {
            file: image,
            identity: ObjectIdentity {
                device: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
            },
        };
        authority.validate_for(expected)?;
        Ok(authority)
    }

    fn validate_for(
        &self,
        expected: &LinuxServiceExecutableBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        let observed = self.observe()?;
        if observed.identity != self.identity {
            return Err(failure(
                "validate-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                format!(
                    "sealed snapshot descriptor for executable object {} was substituted",
                    expected.object_id
                ),
            ));
        }
        validate_sealed_executable_snapshot_observation(expected, &observed)
    }

    fn validate_launch_image(
        &self,
        expected: &LinuxServiceLaunchImageBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        let observed = self.observe()?;
        if observed.identity != self.identity {
            return Err(failure(
                "validate-native-service-launch-image",
                EffectCertainty::NotApplied,
                format!(
                    "sealed launch-image descriptor for executable object {} was substituted",
                    expected.object_id
                ),
            ));
        }
        validate_launch_image_snapshot_observation(expected, &observed)
    }

    fn observe(&self) -> Result<LinuxSealedExecutableSnapshotObservation, CgroupIoFailure> {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::MetadataExt as _;

        let metadata = self.file.metadata().map_err(|error| {
            io_failure(
                "validate-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let filesystem = rustix::fs::fstatfs(&self.file).map_err(|error| {
            io_failure(
                "validate-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let seals = rustix::fs::fcntl_get_seals(&self.file).map_err(|error| {
            io_failure(
                "validate-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let descriptor_flags = rustix::io::fcntl_getfd(self.file.as_fd()).map_err(|error| {
            io_failure(
                "validate-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let byte_length = metadata.len();
        Ok(LinuxSealedExecutableSnapshotObservation {
            identity: ObjectIdentity {
                device: PortableMetadataExt::dev(&metadata),
                inode: PortableMetadataExt::ino(&metadata),
            },
            regular_file: metadata.is_file(),
            memfd_filesystem: u64::try_from(filesystem.f_type).ok() == Some(TMPFS_SUPER_MAGIC),
            owner_is_effective_identity: metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.gid() == rustix::process::getegid().as_raw(),
            link_count: PortableMetadataExt::nlink(&metadata),
            permissions: metadata.mode() & 0o7_777,
            byte_length,
            content_sha256: hash_sealed_executable_snapshot(&self.file, byte_length)?,
            seal_bits: seals.bits(),
            close_on_exec: descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC),
        })
    }
}

#[cfg(target_os = "linux")]
fn hash_sealed_executable_snapshot(
    file: &std::fs::File,
    byte_length: u64,
) -> Result<Digest, CgroupIoFailure> {
    use std::os::unix::fs::FileExt as _;

    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    // See `hash_file_exact` in the held launcher: a fixed stack buffer is
    // preferred to a heap allocation inside an authenticated fail-closed path,
    // and 32 KiB against an 8 MiB default stack is not a risk.
    #[expect(
        clippy::large_stack_arrays,
        reason = "fixed 32 KiB read buffer chosen over a heap allocation inside an authenticated fail-closed path"
    )]
    let mut buffer = [0_u8; 32 * 1_024];
    while offset < byte_length {
        let remaining = byte_length - offset;
        let maximum = usize::try_from(
            remaining.min(u64::try_from(buffer.len()).expect("buffer length fits u64")),
        )
        .map_err(|_| {
            failure(
                "readback-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                "sealed executable readback length cannot be represented",
            )
        })?;
        let count = file
            .read_at(&mut buffer[..maximum], offset)
            .map_err(|error| {
                io_failure(
                    "readback-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        if count == 0 {
            return Err(failure(
                "readback-native-service-sealed-executable",
                EffectCertainty::NotApplied,
                "sealed executable ended before its retained byte length",
            ));
        }
        hasher.update(&buffer[..count]);
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| {
                failure(
                    "readback-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    "sealed executable read count cannot be represented",
                )
            })?)
            .ok_or_else(|| {
                failure(
                    "readback-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    "sealed executable read offset overflowed",
                )
            })?;
    }
    Digest::parse(hex_lower(&hasher.finalize())).map_err(|error| {
        failure(
            "readback-native-service-sealed-executable",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })
}

#[derive(Debug)]
pub(crate) struct LinuxNativeServiceExecutableDescriptor {
    object_id: String,
    provenance: LinuxRetainedExecutablePathProvenance,
    #[cfg(target_os = "linux")]
    sealed_snapshot: Option<LinuxSealedExecutableSnapshot>,
}

const fn source_role_requires_execute_bit(role: LinuxServiceExecutableRoleV1) -> bool {
    !matches!(role, LinuxServiceExecutableRoleV1::RuntimeObject)
}

impl LinuxNativeServiceExecutableDescriptor {
    fn open_planned(expected: &LinuxServiceExecutableBindingV1) -> Result<Self, CgroupIoFailure> {
        let provenance = LinuxRetainedExecutablePathProvenance::open_absolute(
            &expected.resolved_path,
            "open-native-service-executable",
        )?;
        Ok(Self {
            object_id: expected.object_id.clone(),
            provenance,
            #[cfg(target_os = "linux")]
            sealed_snapshot: None,
        })
    }

    fn validate_source_for(
        &self,
        expected: &LinuxServiceExecutableBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        if self.object_id != expected.object_id {
            return Err(failure(
                "bind-native-service-executable",
                EffectCertainty::NotApplied,
                "retained executable object ID differs from the exact command plan",
            ));
        }
        if self.provenance.absolute_path != expected.resolved_path {
            return Err(failure(
                "bind-native-service-executable",
                EffectCertainty::NotApplied,
                "retained executable parent chain differs from the exact planned image path",
            ));
        }
        if expected.immutability
            != LinuxFileImmutabilityV1::StableIdentityAndFullContentReadbackImmediatelyBeforeRelease
        {
            return Err(failure(
                "bind-native-service-executable",
                EffectCertainty::NotApplied,
                format!(
                    "sealed executable object {} requires a retained memfd/seal admission path that is not implemented",
                    expected.object_id
                ),
            ));
        }
        let metadata = self.provenance.file.metadata().map_err(|error| {
            io_failure(
                "inspect-native-service-executable",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let file = &expected.file;
        if !metadata.is_file()
            || object_identity(&metadata) != self.provenance.file_identity
            || self.provenance.file_identity.device != file.device_id
            || self.provenance.file_identity.inode != file.inode
            || self.provenance.file_mount_id != file.mount_id
            || retained_file_mount_id(&self.provenance.file, "validate-native-service-executable")?
                != self.provenance.file_mount_id
            || OsMetadataExt::mode(&metadata) != file.mode
            || OsMetadataExt::uid(&metadata) != file.owner_uid
            || OsMetadataExt::gid(&metadata) != file.owner_gid
            || file.link_count != 1
            || PortableMetadataExt::nlink(&metadata) != 1
            || metadata.len() != file.byte_length
            || OsMetadataExt::mode(&metadata) & 0o6022 != 0
            || source_role_requires_execute_bit(expected.role)
                && OsMetadataExt::mode(&metadata) & 0o111 == 0
        {
            return Err(failure(
                "validate-native-service-executable",
                EffectCertainty::NotApplied,
                format!(
                    "retained executable object {} identity or metadata differs from the durable plan",
                    expected.object_id
                ),
            ));
        }
        self.provenance
            .validate_named("validate-native-service-executable")?;
        let maximum = usize::try_from(file.byte_length).map_err(|_| {
            failure(
                "validate-native-service-executable",
                EffectCertainty::NotApplied,
                "planned executable byte length cannot be represented on this host",
            )
        })?;
        let bytes = read_retained_bootstrap_file(
            &self.provenance.file,
            maximum,
            "readback-native-service-executable",
        )?;
        if bytes.len() != maximum || Digest::sha256(&bytes) != file.content_sha256 {
            return Err(failure(
                "validate-native-service-executable",
                EffectCertainty::NotApplied,
                format!(
                    "retained executable object {} full-content readback differs from the durable plan",
                    expected.object_id
                ),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn seal_snapshot_for(
        &mut self,
        expected: &LinuxServiceExecutableBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_source_for(expected)?;
        let snapshot = LinuxSealedExecutableSnapshot::create(&self.provenance.file, expected)?;
        self.validate_source_for(expected)?;
        snapshot.validate_for(expected)?;
        self.sealed_snapshot = Some(snapshot);
        Ok(())
    }

    fn validate_for(
        &self,
        expected: &LinuxServiceExecutableBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_source_for(expected)?;
        #[cfg(target_os = "linux")]
        self.sealed_snapshot
            .as_ref()
            .ok_or_else(|| {
                failure(
                    "validate-native-service-sealed-executable",
                    EffectCertainty::NotApplied,
                    format!(
                        "executable object {} lacks its retained immutable snapshot",
                        expected.object_id
                    ),
                )
            })?
            .validate_for(expected)?;
        Ok(())
    }

    fn into_launch_image(
        self,
        source_expected: &LinuxServiceExecutableBindingV1,
        launch_expected: &LinuxServiceLaunchImageBindingV1,
    ) -> Result<LinuxNativeServiceLaunchImage, CgroupIoFailure> {
        if source_expected.role != launch_expected.role
            || source_expected.object_id != launch_expected.object_id
            || source_expected.file.byte_length != launch_expected.byte_length
            || source_expected.file.content_sha256 != launch_expected.content_sha256
        {
            return Err(failure(
                "select-native-service-launch-image",
                EffectCertainty::NotApplied,
                "pathless launch-image expectation crossed its admitted source image",
            ));
        }
        self.validate_for(source_expected)?;

        #[cfg(target_os = "linux")]
        {
            let sealed_snapshot = self.sealed_snapshot.ok_or_else(|| {
                failure(
                    "select-native-service-launch-image",
                    EffectCertainty::NotApplied,
                    format!(
                        "executable object {} has no admission-sealed snapshot to consume",
                        source_expected.object_id
                    ),
                )
            })?;
            sealed_snapshot.validate_launch_image(launch_expected)?;
            Ok(LinuxNativeServiceLaunchImage {
                binding: launch_expected.clone(),
                sealed_snapshot,
            })
        }

        #[cfg(all(test, not(target_os = "linux")))]
        {
            let portable_test_descriptor = LinuxPortableLaunchImageTestDescriptor {
                identity: self.provenance.file_identity,
                file: self.provenance.file,
            };
            portable_test_descriptor.validate_for(launch_expected)?;
            Ok(LinuxNativeServiceLaunchImage {
                binding: launch_expected.clone(),
                portable_test_descriptor,
            })
        }

        #[cfg(all(not(test), not(target_os = "linux")))]
        {
            Err(failure(
                "select-native-service-launch-image",
                EffectCertainty::NotApplied,
                "immutable Linux launch-image selection is unavailable off Linux",
            ))
        }
    }
}

/// Exact, non-cloneable retained command-image set for one durable plan.
#[derive(Debug)]
struct LinuxNativeServiceExecutableSetAuthority {
    plan_digest: Digest,
    expected: Vec<LinuxServiceExecutableBindingV1>,
    descriptors: Vec<LinuxNativeServiceExecutableDescriptor>,
}

/// One immutable, role-bound command image after its mutable source pathname
/// and source descriptor have been consumed.
///
/// The production field is an admission-sealed `MFD_EXEC` snapshot. Portable
/// unit tests retain a genuine descriptor and byte observation only so the
/// pathless role/destination join can be exercised on macOS; that field is
/// absent from non-test, non-Linux builds and never claims native sealing.
#[derive(Debug)]
struct LinuxNativeServiceLaunchImage {
    binding: LinuxServiceLaunchImageBindingV1,
    #[cfg(target_os = "linux")]
    sealed_snapshot: LinuxSealedExecutableSnapshot,
    #[cfg(all(test, not(target_os = "linux")))]
    portable_test_descriptor: LinuxPortableLaunchImageTestDescriptor,
}

#[cfg(all(test, not(target_os = "linux")))]
#[derive(Debug)]
struct LinuxPortableLaunchImageTestDescriptor {
    file: File,
    identity: ObjectIdentity,
}

/// Exact, pathless, non-cloneable immutable image set for one durable plan.
/// No raw descriptor, generic lookup, process callback, or release conversion
/// is exposed from this type.
#[derive(Debug)]
struct LinuxNativeServiceLaunchImageSetAuthority {
    plan_digest: Digest,
    images: Vec<LinuxNativeServiceLaunchImage>,
}

#[derive(Debug)]
enum LinuxNativeServiceProcessImageSource {
    #[cfg(target_os = "linux")]
    CurrentProcess {
        procfs: LinuxProcfs,
        provenance: LinuxRetainedExecutablePathProvenance,
    },
    #[cfg(test)]
    TestNamed(LinuxRetainedExecutablePathProvenance),
    #[cfg(all(not(target_os = "linux"), not(test)))]
    Unsupported,
}

/// Retained identity and full bytes of the authenticated native-service
/// process image.
///
/// Production construction is available only on Linux and obtains the image
/// from authenticated genuine-procfs `self/exe`, then authenticates the
/// kernel-reported name through a retained no-follow chain rooted at `/`.
/// Tests may use an absolute named retained file to exercise portable
/// crossing/replacement behavior, but that constructor is absent from
/// production.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceProcessImageAuthority {
    file: File,
    identity: ObjectIdentity,
    mount_id: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    byte_length: u64,
    content_sha256: Digest,
    source: LinuxNativeServiceProcessImageSource,
}

impl LinuxNativeServiceProcessImageAuthority {
    #[cfg(target_os = "linux")]
    pub(crate) fn observe_current_process() -> Result<Self, CgroupIoFailure> {
        let procfs = LinuxProcfs::open_authenticated().map_err(cgroup_launcher_failure)?;
        let (file, expected) = procfs
            .retain_self_executable()
            .map_err(cgroup_launcher_failure)?;
        let file = File::from_std(file);
        let identity = ObjectIdentity {
            device: expected.device,
            inode: expected.inode,
        };
        let mount_id = retained_file_mount_id(&file, "open-native-service-process-image")?;
        let kernel_path = procfs
            .self_executable_path(expected)
            .map_err(cgroup_launcher_failure)?;
        let kernel_path = kernel_path.to_str().ok_or_else(|| {
            failure(
                "open-native-service-process-image",
                EffectCertainty::NotApplied,
                "procfs self/exe reported a non-UTF-8 executable name",
            )
        })?;
        let provenance = LinuxRetainedExecutablePathProvenance::open_absolute(
            kernel_path,
            "open-native-service-process-image",
        )?;
        if provenance.file_identity != identity || provenance.file_mount_id != mount_id {
            return Err(failure(
                "open-native-service-process-image",
                EffectCertainty::NotApplied,
                "procfs self/exe and its no-follow absolute name differ by inode or mount",
            ));
        }
        Self::from_retained(
            file,
            identity,
            mount_id,
            LinuxNativeServiceProcessImageSource::CurrentProcess { procfs, provenance },
        )
    }

    #[cfg(test)]
    fn open_test_absolute(absolute_path: &str) -> Result<Self, CgroupIoFailure> {
        let provenance = LinuxRetainedExecutablePathProvenance::open_absolute(
            absolute_path,
            "open-test-native-service-process-image",
        )?;
        let file = provenance.file.try_clone().map_err(|error| {
            io_failure(
                "open-test-native-service-process-image",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let identity = provenance.file_identity;
        let mount_id = provenance.file_mount_id;
        Self::from_retained(
            file,
            identity,
            mount_id,
            LinuxNativeServiceProcessImageSource::TestNamed(provenance),
        )
    }

    fn from_retained(
        file: File,
        identity: ObjectIdentity,
        mount_id: u64,
        source: LinuxNativeServiceProcessImageSource,
    ) -> Result<Self, CgroupIoFailure> {
        let metadata = file.metadata().map_err(|error| {
            io_failure(
                "inspect-native-service-process-image",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if !metadata.is_file()
            || object_identity(&metadata) != identity
            || retained_file_mount_id(&file, "inspect-native-service-process-image")? != mount_id
            || metadata.len() == 0
            || metadata.len() > MAX_NATIVE_SERVICE_EXECUTABLE_BYTES as u64
            || PortableMetadataExt::nlink(&metadata) != 1
            || OsMetadataExt::mode(&metadata) & 0o111 == 0
            || OsMetadataExt::mode(&metadata) & 0o6022 != 0
        {
            return Err(failure(
                "validate-native-service-process-image",
                EffectCertainty::NotApplied,
                "native-service process image is not a singly linked, stable, non-setid, non-group/world-writable executable regular file",
            ));
        }
        let byte_length = metadata.len();
        let mode = OsMetadataExt::mode(&metadata);
        let owner_uid = OsMetadataExt::uid(&metadata);
        let owner_group_id = OsMetadataExt::gid(&metadata);
        let bytes = read_retained_bootstrap_file(
            &file,
            usize::try_from(byte_length).map_err(|_| {
                failure(
                    "readback-native-service-process-image",
                    EffectCertainty::NotApplied,
                    "native-service process image length cannot be represented",
                )
            })?,
            "readback-native-service-process-image",
        )?;
        if bytes.len() as u64 != byte_length {
            return Err(failure(
                "readback-native-service-process-image",
                EffectCertainty::NotApplied,
                "native-service process image changed length during readback",
            ));
        }
        let authority = Self {
            file,
            identity,
            mount_id,
            mode,
            owner_uid,
            owner_gid: owner_group_id,
            byte_length,
            content_sha256: Digest::sha256(&bytes),
            source,
        };
        authority.validate_retained()?;
        Ok(authority)
    }

    /// The no-follow-verified absolute name this image was retained through.
    ///
    /// On the production path it is the name procfs reported for `self/exe`,
    /// already required to resolve to the retained inode and mount.
    #[cfg(target_os = "linux")]
    fn retained_absolute_path(&self) -> &str {
        match &self.source {
            LinuxNativeServiceProcessImageSource::CurrentProcess { provenance, .. } => {
                provenance.absolute_path.as_str()
            }
            #[cfg(test)]
            LinuxNativeServiceProcessImageSource::TestNamed(provenance) => {
                provenance.absolute_path.as_str()
            }
        }
    }

    fn validate_for_digest(&self, expected: &Digest) -> Result<(), CgroupIoFailure> {
        self.validate_retained()?;
        if &self.content_sha256 != expected {
            return Err(failure(
                "bind-native-service-process-image",
                EffectCertainty::NotApplied,
                "current native-service executable digest differs from the durable plan",
            ));
        }
        Ok(())
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        let metadata = self.file.metadata().map_err(|error| {
            io_failure(
                "validate-native-service-process-image",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if !metadata.is_file()
            || object_identity(&metadata) != self.identity
            || retained_file_mount_id(&self.file, "validate-native-service-process-image")?
                != self.mount_id
            || OsMetadataExt::mode(&metadata) != self.mode
            || OsMetadataExt::uid(&metadata) != self.owner_uid
            || OsMetadataExt::gid(&metadata) != self.owner_gid
            || metadata.len() != self.byte_length
            || PortableMetadataExt::nlink(&metadata) != 1
            || OsMetadataExt::mode(&metadata) & 0o111 == 0
            || OsMetadataExt::mode(&metadata) & 0o6022 != 0
        {
            return Err(failure(
                "validate-native-service-process-image",
                EffectCertainty::NotApplied,
                "retained native-service executable identity or metadata changed",
            ));
        }
        match &self.source {
            #[cfg(target_os = "linux")]
            LinuxNativeServiceProcessImageSource::CurrentProcess { procfs, provenance } => {
                let expected = LauncherDescriptorIdentity {
                    device: self.identity.device,
                    inode: self.identity.inode,
                };
                procfs
                    .require_self_executable(expected)
                    .map_err(cgroup_launcher_failure)?;
                let kernel_path = procfs
                    .self_executable_path(expected)
                    .map_err(cgroup_launcher_failure)?;
                if kernel_path.to_str() != Some(provenance.absolute_path.as_str())
                    || provenance.file_identity != self.identity
                    || provenance.file_mount_id != self.mount_id
                {
                    return Err(failure(
                        "validate-native-service-process-image",
                        EffectCertainty::NotApplied,
                        "current service executable name, inode, or mount crossed retained provenance",
                    ));
                }
                provenance.validate_named("validate-native-service-process-image")
            }
            #[cfg(test)]
            LinuxNativeServiceProcessImageSource::TestNamed(provenance) => {
                if provenance.file_identity != self.identity
                    || provenance.file_mount_id != self.mount_id
                {
                    return Err(failure(
                        "validate-native-service-process-image",
                        EffectCertainty::NotApplied,
                        "test service executable crossed retained named provenance",
                    ));
                }
                provenance.validate_named("validate-native-service-process-image")
            }
            #[cfg(all(not(target_os = "linux"), not(test)))]
            LinuxNativeServiceProcessImageSource::Unsupported => Err(failure(
                "validate-native-service-process-image",
                EffectCertainty::NotApplied,
                "native-service process-image authority is unsupported off Linux",
            )),
        }?;
        let bytes = read_retained_bootstrap_file(
            &self.file,
            usize::try_from(self.byte_length).map_err(|_| {
                failure(
                    "validate-native-service-process-image",
                    EffectCertainty::NotApplied,
                    "native-service process image length cannot be represented",
                )
            })?,
            "validate-native-service-process-image",
        )?;
        if bytes.len() as u64 != self.byte_length || Digest::sha256(&bytes) != self.content_sha256 {
            return Err(failure(
                "validate-native-service-process-image",
                EffectCertainty::NotApplied,
                "retained native-service executable full-content readback changed",
            ));
        }
        Ok(())
    }
}

impl LinuxNativeServiceExecutableSetAuthority {
    fn admit(plan: &ValidatedLinuxProductionCommandPlanV1) -> Result<Self, CgroupIoFailure> {
        let expected = plan.service_executable_bindings().map_err(|error| {
            failure(
                "bind-native-service-executable-set",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        validate_executable_snapshot_set_preflight(&expected)?;
        let mut retained = Vec::with_capacity(expected.len());
        for binding in &expected {
            #[cfg(target_os = "linux")]
            let descriptor = {
                let mut descriptor = LinuxNativeServiceExecutableDescriptor::open_planned(binding)?;
                descriptor.validate_source_for(binding)?;
                descriptor.seal_snapshot_for(binding)?;
                descriptor
            };
            #[cfg(not(target_os = "linux"))]
            let descriptor = LinuxNativeServiceExecutableDescriptor::open_planned(binding)?;
            descriptor.validate_for(binding)?;
            retained.push(descriptor);
        }
        let authority = Self {
            plan_digest: plan.plan_digest().clone(),
            expected,
            descriptors: retained,
        };
        authority.validate_for(plan)?;
        Ok(authority)
    }

    fn validate_for(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<(), CgroupIoFailure> {
        let expected = plan.service_executable_bindings().map_err(|error| {
            failure(
                "validate-native-service-executable-set",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if self.plan_digest != *plan.plan_digest()
            || self.expected != expected
            || self.descriptors.len() != expected.len()
        {
            return Err(failure(
                "validate-native-service-executable-set",
                EffectCertainty::NotApplied,
                "retained executable authority crossed the durable command plan",
            ));
        }
        let mut kernel_objects = BTreeMap::new();
        for (descriptor, binding) in self.descriptors.iter().zip(&expected) {
            descriptor.validate_for(binding)?;
            require_distinct_executable_kernel_object(
                &mut kernel_objects,
                &descriptor.object_id,
                descriptor.provenance.file_identity,
                descriptor.provenance.file_mount_id,
            )?;
        }
        Ok(())
    }

    fn select_launch_images(
        self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<LinuxNativeServiceLaunchImageSetAuthority, CgroupIoFailure> {
        self.validate_for(plan)?;
        let launch_expected = plan.service_launch_image_bindings().map_err(|error| {
            failure(
                "select-native-service-launch-image-set",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if self.expected.len() != launch_expected.len()
            || self.descriptors.len() != launch_expected.len()
        {
            return Err(failure(
                "select-native-service-launch-image-set",
                EffectCertainty::NotApplied,
                "launch-image selection lost or added an executable role",
            ));
        }
        let LinuxNativeServiceExecutableSetAuthority {
            plan_digest,
            expected,
            descriptors,
        } = self;
        let images = descriptors
            .into_iter()
            .zip(expected.iter())
            .zip(launch_expected)
            .map(|((descriptor, source_expected), launch_expected)| {
                descriptor.into_launch_image(source_expected, &launch_expected)
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;
        let authority = LinuxNativeServiceLaunchImageSetAuthority {
            plan_digest,
            images,
        };
        authority.validate_for(plan)?;
        Ok(authority)
    }
}

#[cfg(all(test, not(target_os = "linux")))]
impl LinuxPortableLaunchImageTestDescriptor {
    fn validate_for(
        &self,
        expected: &LinuxServiceLaunchImageBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        use std::os::fd::AsFd as _;

        let metadata = self.file.metadata().map_err(|error| {
            io_failure(
                "validate-portable-test-launch-image",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let descriptor_flags = rustix::io::fcntl_getfd(self.file.as_fd()).map_err(|error| {
            io_failure(
                "validate-portable-test-launch-image",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let maximum = usize::try_from(expected.byte_length).map_err(|_| {
            failure(
                "validate-portable-test-launch-image",
                EffectCertainty::NotApplied,
                "portable test image byte length cannot be represented",
            )
        })?;
        let bytes = read_retained_bootstrap_file(
            &self.file,
            maximum,
            "validate-portable-test-launch-image",
        )?;
        if !metadata.is_file()
            || object_identity(&metadata) != self.identity
            || metadata.len() != expected.byte_length
            || bytes.len() != maximum
            || Digest::sha256(&bytes) != expected.content_sha256
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(failure(
                "validate-portable-test-launch-image",
                EffectCertainty::NotApplied,
                format!(
                    "portable contract-only descriptor for image {} changed identity, length, bytes, or close-on-exec state",
                    expected.object_id
                ),
            ));
        }
        Ok(())
    }
}

impl LinuxNativeServiceLaunchImage {
    fn validate_for(
        &self,
        expected: &LinuxServiceLaunchImageBindingV1,
    ) -> Result<ObjectIdentity, CgroupIoFailure> {
        if &self.binding != expected {
            return Err(failure(
                "validate-native-service-launch-image",
                EffectCertainty::NotApplied,
                "selected launch image crossed its exact object, role, content, or destination binding",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            self.sealed_snapshot.validate_launch_image(expected)?;
            Ok(self.sealed_snapshot.identity)
        }
        #[cfg(all(test, not(target_os = "linux")))]
        {
            self.portable_test_descriptor.validate_for(expected)?;
            Ok(self.portable_test_descriptor.identity)
        }
        #[cfg(all(not(test), not(target_os = "linux")))]
        Err(failure(
            "validate-native-service-launch-image",
            EffectCertainty::NotApplied,
            "immutable Linux launch-image validation is unavailable off Linux",
        ))
    }
}

impl LinuxNativeServiceLaunchImageSetAuthority {
    fn validate_for(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<(), CgroupIoFailure> {
        let expected = plan.service_launch_image_bindings().map_err(|error| {
            failure(
                "validate-native-service-launch-image-set",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if self.plan_digest != *plan.plan_digest() || self.images.len() != expected.len() {
            return Err(failure(
                "validate-native-service-launch-image-set",
                EffectCertainty::NotApplied,
                "selected launch-image authority crossed its exact durable plan",
            ));
        }
        let mut identities = BTreeSet::new();
        for (image, expected) in self.images.iter().zip(&expected) {
            let identity = image.validate_for(expected)?;
            if !identities.insert((identity.device, identity.inode)) {
                return Err(failure(
                    "validate-native-service-launch-image-set",
                    EffectCertainty::NotApplied,
                    "two selected launch-image roles alias one retained kernel object",
                ));
            }
        }
        Ok(())
    }
}

fn require_distinct_executable_kernel_object(
    observed: &mut BTreeMap<(u64, u64), (String, u64)>,
    object_id: &str,
    identity: ObjectIdentity,
    mount_id: u64,
) -> Result<(), CgroupIoFailure> {
    if let Some((prior_object_id, prior_mount_id)) = observed.insert(
        (identity.device, identity.inode),
        (object_id.to_owned(), mount_id),
    ) {
        return Err(failure(
            "validate-native-service-executable-set",
            EffectCertainty::NotApplied,
            format!(
                "executable objects {prior_object_id} (mount {prior_mount_id}) and {object_id} (mount {mount_id}) alias one kernel inode across roles or bind mounts"
            ),
        ));
    }
    Ok(())
}

/// Cross-process singleton retained for the full lifetime of one admitted
/// native-service command. Dropping the value releases the kernel `flock`.
#[derive(Debug)]
struct LinuxNativeServiceLifetimeLock {
    file: File,
    identity: ObjectIdentity,
    service_state_identity: ObjectIdentity,
    expected_owner_uid: u32,
}

impl LinuxNativeServiceLifetimeLock {
    fn acquire(
        service_state_root: &Dir,
        expected_state_identity: CgroupObjectIdentity,
        expected_owner_uid: u32,
    ) -> Result<Self, CgroupIoFailure> {
        let state_metadata = service_state_root.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-linux-native-service-state",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_private_directory(&state_metadata, expected_owner_uid)?;
        let service_state_identity = object_identity(&state_metadata);
        if cgroup_identity(service_state_identity) != expected_state_identity {
            return Err(failure(
                "bind-linux-native-service-lifetime",
                EffectCertainty::NotApplied,
                "service-state root differs from the durable command plan",
            ));
        }
        let (file, identity) = open_or_create_named_private_lock(
            service_state_root,
            SERVICE_LIFETIME_LOCK_NAME,
            expected_owner_uid,
            "linux-native-service-lifetime",
        )?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            io_failure(
                "lock-linux-native-service-lifetime",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let authority = Self {
            file,
            identity,
            service_state_identity,
            expected_owner_uid,
        };
        if let Err(error) = authority.validate_for(service_state_root, expected_state_identity) {
            let _ = flock(&authority.file, FlockOperation::Unlock);
            return Err(error);
        }
        Ok(authority)
    }

    fn validate_for(
        &self,
        service_state_root: &Dir,
        expected_state_identity: CgroupObjectIdentity,
    ) -> Result<(), CgroupIoFailure> {
        let state = service_state_root.dir_metadata().map_err(|error| {
            io_failure(
                "validate-linux-native-service-lifetime",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let lock = self.file.metadata().map_err(|error| {
            io_failure(
                "validate-linux-native-service-lifetime",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if object_identity(&state) != self.service_state_identity
            || cgroup_identity(self.service_state_identity) != expected_state_identity
            || object_identity(&lock) != self.identity
        {
            return Err(failure(
                "validate-linux-native-service-lifetime",
                EffectCertainty::NotApplied,
                "retained service-state or lifetime-lock identity changed",
            ));
        }
        validate_private_directory(&state, self.expected_owner_uid)?;
        validate_private_file(&lock, self.expected_owner_uid)?;
        require_named_identity(
            service_state_root,
            SERVICE_LIFETIME_LOCK_NAME,
            self.identity,
            "validate-linux-native-service-lifetime",
        )
    }
}

/// Post-journal, post-bootstrap type state. It intentionally has no mechanics
/// callback: native execution remains inadmissible until an authenticated
/// production bootstrap and the remaining containment controls exist.
#[derive(Debug)]
pub(crate) struct BootstrappedLinuxProductionCommandPlanV1 {
    journaled: JournaledLinuxProductionCommandPlanV1,
    bootstrap: LinuxNativeServiceBootstrapAuthority,
}

impl BootstrappedLinuxProductionCommandPlanV1 {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        if !self.journaled.receipt.authenticates(&self.journaled.plan) {
            return Err(failure(
                "bind-linux-service-admission-plan",
                EffectCertainty::Ambiguous,
                "durable command-plan receipt no longer authenticates the canonical plan",
            ));
        }
        self.journaled
            .journal_authority
            .require_exact_command_plan_artifact(&self.journaled.plan, &self.journaled.receipt)?;
        self.bootstrap.require_exact_plan(
            &self.journaled.plan,
            &self.journaled.journal_authority.residual,
            &self.journaled.journal_authority.journal,
        )
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}

/// Non-cloneable, service-lifetime admission for one exact durable command.
///
/// This is the first production-compiled join that simultaneously owns the
/// durable command-plan receipt, authenticated bootstrap/delegation evidence,
/// the current service process image, the complete retained command executable
/// set, and a cross-process singleton lock. It is still containment-pending:
/// no constructor for real Landlock/seccomp release evidence exists and this
/// value exposes no spawn or release method.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceAdmissionAuthority {
    bootstrapped: BootstrappedLinuxProductionCommandPlanV1,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    executables: LinuxNativeServiceExecutableSetAuthority,
    lifetime_lock: LinuxNativeServiceLifetimeLock,
}

impl LinuxNativeServiceAdmissionAuthority {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        self.bootstrapped.validate_retained()?;
        let plan = &self.bootstrapped.journaled.plan;
        self.executables.validate_for(plan)?;
        let binding = plan.journal_binding().map_err(|error| {
            failure(
                "validate-linux-native-service-admission",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        self.service_process_image
            .validate_for_digest(&binding.authenticated_platform_service_digest)?;
        self.lifetime_lock.validate_for(
            &self.bootstrapped.journaled.journal_authority.journal.parent,
            binding.service_state_root_identity,
        )
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}

/// Admits one exact post-journal/post-bootstrap command into the native
/// service lifetime.
///
/// The executable set is derived internally from the exact durable plan and
/// opened through fixed-root, no-follow descriptor chains. This transition
/// retains it only after the exact paths, parent identities/mounts, named
/// inodes, metadata, complete bytes, canonical command-plan artifact,
/// bootstrap artifact, controller readbacks, grant/policy/session/lease joins,
/// and singleton lock all revalidate. Caller-provided paths, parent
/// descriptors, booleans, journal authority, or bootstrap authority alone
/// cannot construct the result.
pub(crate) fn admit_linux_native_service_command(
    bootstrapped: BootstrappedLinuxProductionCommandPlanV1,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
) -> Result<LinuxNativeServiceAdmissionAuthority, CgroupIoFailure> {
    bootstrapped.validate_retained()?;
    let plan = &bootstrapped.journaled.plan;
    let binding = plan.journal_binding().map_err(|error| {
        failure(
            "bind-linux-native-service-admission",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    service_process_image.validate_for_digest(&binding.authenticated_platform_service_digest)?;
    let lifetime_lock = LinuxNativeServiceLifetimeLock::acquire(
        &bootstrapped.bootstrap.capabilities.state_root,
        binding.service_state_root_identity,
        binding.owner_uid,
    )?;
    let executables = LinuxNativeServiceExecutableSetAuthority::admit(plan)?;
    let authority = LinuxNativeServiceAdmissionAuthority {
        bootstrapped,
        service_process_image,
        executables,
        lifetime_lock,
    };
    authority.validate_retained()?;
    Ok(authority)
}

/// One-shot, pathless launch-image selection for one exact admitted command.
///
/// Construction consumes the source-provenance executable set after its final
/// revalidation and retains only role-bound immutable snapshots. The complete
/// durable plan remains available for comparison, but no source descriptor,
/// source pathname accessor, raw descriptor lookup, process callback, or held-
/// release conversion is exposed. The separately minted setup-descriptor
/// capability, native probes, child descriptor table, and final release remain
/// mandatory later states.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceLaunchImageAuthority {
    bootstrapped: BootstrappedLinuxProductionCommandPlanV1,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    launch_images: LinuxNativeServiceLaunchImageSetAuthority,
    lifetime_lock: LinuxNativeServiceLifetimeLock,
}

impl LinuxNativeServiceLaunchImageAuthority {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        self.bootstrapped.validate_retained()?;
        let plan = &self.bootstrapped.journaled.plan;
        self.launch_images.validate_for(plan)?;
        let binding = plan.journal_binding().map_err(|error| {
            failure(
                "validate-linux-native-service-launch-images",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        self.service_process_image
            .validate_for_digest(&binding.authenticated_platform_service_digest)?;
        self.lifetime_lock.validate_for(
            &self.bootstrapped.bootstrap.capabilities.state_root,
            binding.service_state_root_identity,
        )
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}

/// Consumes one admitted source-image set and selects the exact immutable
/// role/destination closure required by the durable command plan.
///
/// This transition performs no cgroup, process, journal, or release effect and
/// cannot authorize execution. On Linux every selected image is the exact
/// admission-created sealed memfd; there is no named-path fallback.
pub(crate) fn select_linux_native_service_launch_images(
    admission: LinuxNativeServiceAdmissionAuthority,
) -> Result<LinuxNativeServiceLaunchImageAuthority, CgroupIoFailure> {
    admission.validate_retained()?;
    let LinuxNativeServiceAdmissionAuthority {
        bootstrapped,
        service_process_image,
        executables,
        lifetime_lock,
    } = admission;
    let launch_images = executables.select_launch_images(&bootstrapped.journaled.plan)?;
    let authority = LinuxNativeServiceLaunchImageAuthority {
        bootstrapped,
        service_process_image,
        launch_images,
        lifetime_lock,
    };
    authority.validate_retained()?;
    Ok(authority)
}

/// One retained directory in the native-service setup closure.
#[derive(Debug)]
struct LinuxNativeServiceSetupDirectory {
    binding: LinuxServiceSetupObjectIdentityV1,
    directory: Dir,
    identity: ObjectIdentity,
    mount_id: u64,
}

#[derive(Debug)]
struct LinuxNativeServiceSetupCwdStep {
    component: String,
    identity: ObjectIdentity,
    mount_id: u64,
}

/// Retained cwd reached only from the retained execution-root descriptor.
#[derive(Debug)]
struct LinuxNativeServiceSetupCwd {
    directory: Dir,
    identity: ObjectIdentity,
    mount_id: u64,
    steps: Vec<LinuxNativeServiceSetupCwdStep>,
}

/// One actual service-minted endpoint bound to its canonical semantic role.
#[derive(Debug)]
struct LinuxNativeServiceSetupEndpoint {
    binding: LinuxServiceSetupEndpointBindingV1,
    file: File,
    identity: ObjectIdentity,
}

/// Non-cloneable native-service capability containing every descriptor needed
/// by the canonical setup closure.
///
/// Production construction remains deliberately absent. A future native
/// service mint must obtain these descriptors from genuine authenticated
/// capabilities and prove the same validation performed here. The sole
/// current constructor is test-only and accepts already-retained descriptors.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceSetupDescriptorCapability {
    binding: LinuxServiceSetupDescriptorBindingV1,
    execution_root: LinuxNativeServiceSetupDirectory,
    cwd: LinuxNativeServiceSetupCwd,
    private_state_root: LinuxNativeServiceSetupDirectory,
    singleton_journal_root: LinuxNativeServiceSetupDirectory,
    read_only_mount_sources: Vec<LinuxNativeServiceSetupDirectory>,
    endpoints: Vec<LinuxNativeServiceSetupEndpoint>,
}

#[cfg(test)]
#[derive(Debug)]
struct LinuxTestNativeServiceSetupDescriptorInputs {
    execution_root: Dir,
    private_state_root: Dir,
    singleton_journal_root: Dir,
    read_only_mount_sources: Vec<Dir>,
    endpoints: Vec<(LinuxServiceSetupEndpointRoleV1, File)>,
}

impl LinuxNativeServiceSetupDirectory {
    fn from_retained(
        binding: LinuxServiceSetupObjectIdentityV1,
        directory: Dir,
        operation: &'static str,
    ) -> Result<Self, CgroupIoFailure> {
        let metadata = directory
            .dir_metadata()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let authority = Self {
            identity: object_identity(&metadata),
            mount_id: retained_directory_mount_id(&directory, operation)?,
            binding,
            directory,
        };
        authority.validate(operation)?;
        Ok(authority)
    }

    fn validate(&self, operation: &'static str) -> Result<(), CgroupIoFailure> {
        use std::os::fd::AsFd as _;

        let metadata = self
            .directory
            .dir_metadata()
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let descriptor_flags = rustix::io::fcntl_getfd(self.directory.as_fd())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        let status_flags = rustix::fs::fcntl_getfl(self.directory.as_fd())
            .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
        if self.binding.kind != crate::linux_command_plan::LinuxRetainedObjectKindV1::Directory
            || object_identity(&metadata) != self.identity
            || self.identity.device != self.binding.device_id
            || self.identity.inode != self.binding.inode
            || retained_directory_mount_id(&self.directory, operation)? != self.mount_id
            || self.mount_id != self.binding.mount_id
            || !metadata.is_dir()
            || OsMetadataExt::mode(&metadata) != self.binding.mode
            || OsMetadataExt::uid(&metadata) != self.binding.owner_uid
            || OsMetadataExt::gid(&metadata) != self.binding.owner_gid
            || PortableMetadataExt::nlink(&metadata) == 0
            || self.binding.link_count == 0
            || self.binding.byte_length.is_some()
            || status_flags & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
            || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(failure(
                operation,
                EffectCertainty::NotApplied,
                format!(
                    "retained setup directory {} changed identity, mount, metadata, access, or close-on-exec state: observed identity {:?}, mount {}, mode {:o}, owner {}:{}, links {}, access {:?}, cloexec {}; expected identity {}:{}, mount {}, mode {:o}, owner {}:{}, links {}",
                    self.binding.object_id,
                    object_identity(&metadata),
                    retained_directory_mount_id(&self.directory, operation)?,
                    OsMetadataExt::mode(&metadata),
                    OsMetadataExt::uid(&metadata),
                    OsMetadataExt::gid(&metadata),
                    PortableMetadataExt::nlink(&metadata),
                    status_flags & rustix::fs::OFlags::ACCMODE,
                    descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC),
                    self.binding.device_id,
                    self.binding.inode,
                    self.binding.mount_id,
                    self.binding.mode,
                    self.binding.owner_uid,
                    self.binding.owner_gid,
                    self.binding.link_count,
                ),
            ));
        }
        Ok(())
    }
}

fn open_linux_native_service_setup_cwd(
    execution_root: &Dir,
    relative_path: &str,
) -> Result<LinuxNativeServiceSetupCwd, CgroupIoFailure> {
    let mut current = execution_root.try_clone().map_err(|error| {
        io_failure(
            "open-linux-native-service-setup-cwd",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let mut steps = Vec::new();
    if !relative_path.is_empty() {
        for component in relative_path.split('/') {
            validate_component("setup cwd component", component)?;
            current = current.open_dir_nofollow(component).map_err(|error| {
                io_failure(
                    "open-linux-native-service-setup-cwd",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
            let metadata = current.dir_metadata().map_err(|error| {
                io_failure(
                    "inspect-linux-native-service-setup-cwd",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
            steps.push(LinuxNativeServiceSetupCwdStep {
                component: component.to_owned(),
                identity: object_identity(&metadata),
                mount_id: retained_directory_mount_id(
                    &current,
                    "inspect-linux-native-service-setup-cwd",
                )?,
            });
        }
    }
    let metadata = current.dir_metadata().map_err(|error| {
        io_failure(
            "inspect-linux-native-service-setup-cwd",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let cwd = LinuxNativeServiceSetupCwd {
        identity: object_identity(&metadata),
        mount_id: retained_directory_mount_id(&current, "inspect-linux-native-service-setup-cwd")?,
        directory: current,
        steps,
    };
    validate_linux_native_service_setup_cwd(execution_root, relative_path, &cwd)?;
    Ok(cwd)
}

fn validate_linux_native_service_setup_cwd(
    execution_root: &Dir,
    relative_path: &str,
    expected: &LinuxNativeServiceSetupCwd,
) -> Result<(), CgroupIoFailure> {
    use std::os::fd::AsFd as _;

    let observed = open_linux_native_service_setup_cwd_observation(execution_root, relative_path)?;
    let metadata = expected.directory.dir_metadata().map_err(|error| {
        io_failure(
            "validate-linux-native-service-setup-cwd",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let descriptor_flags =
        rustix::io::fcntl_getfd(expected.directory.as_fd()).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-cwd",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
    if observed
        != expected
            .steps
            .iter()
            .map(|step| (step.component.clone(), step.identity, step.mount_id))
            .collect::<Vec<_>>()
        || object_identity(&metadata) != expected.identity
        || retained_directory_mount_id(
            &expected.directory,
            "validate-linux-native-service-setup-cwd",
        )? != expected.mount_id
        || !metadata.is_dir()
        || !descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
    {
        return Err(failure(
            "validate-linux-native-service-setup-cwd",
            EffectCertainty::NotApplied,
            "retained cwd or its root-relative no-follow chain changed identity, mount, type, or close-on-exec state",
        ));
    }
    Ok(())
}

fn open_linux_native_service_setup_cwd_observation(
    execution_root: &Dir,
    relative_path: &str,
) -> Result<Vec<(String, ObjectIdentity, u64)>, CgroupIoFailure> {
    let mut current = execution_root.try_clone().map_err(|error| {
        io_failure(
            "validate-linux-native-service-setup-cwd",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let mut observed = Vec::new();
    if relative_path.is_empty() {
        return Ok(observed);
    }
    for component in relative_path.split('/') {
        validate_component("setup cwd component", component)?;
        current = current.open_dir_nofollow(component).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-cwd",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let metadata = current.dir_metadata().map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-cwd",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        observed.push((
            component.to_owned(),
            object_identity(&metadata),
            retained_directory_mount_id(&current, "validate-linux-native-service-setup-cwd")?,
        ));
    }
    Ok(observed)
}

impl LinuxNativeServiceSetupEndpoint {
    fn from_retained(
        binding: LinuxServiceSetupEndpointBindingV1,
        file: File,
    ) -> Result<Self, CgroupIoFailure> {
        let metadata = file.metadata().map_err(|error| {
            io_failure(
                "inspect-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let endpoint = Self {
            binding,
            identity: object_identity(&metadata),
            file,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    fn validate(&self) -> Result<(), CgroupIoFailure> {
        use std::os::fd::AsFd as _;

        let metadata = self.file.metadata().map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let identity = object_identity(&metadata);
        let status_flags = rustix::fs::fcntl_getfl(self.file.as_fd()).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let descriptor_flags = rustix::io::fcntl_getfd(self.file.as_fd()).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let observed_access = status_flags & rustix::fs::OFlags::ACCMODE;
        let expected_access = match self.binding.access {
            LinuxServiceSetupDescriptorAccessV1::ReadOnly => rustix::fs::OFlags::RDONLY,
            LinuxServiceSetupDescriptorAccessV1::WriteOnly => rustix::fs::OFlags::WRONLY,
            LinuxServiceSetupDescriptorAccessV1::ReadWrite => rustix::fs::OFlags::RDWR,
        };
        if identity != self.identity
            || observed_access != expected_access
            || self.binding.close_on_exec_while_retained
                != descriptor_flags.contains(rustix::io::FdFlags::CLOEXEC)
        {
            return Err(failure(
                "validate-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                format!(
                    "setup endpoint {:?} changed identity, access, or close-on-exec state",
                    self.binding.role
                ),
            ));
        }

        match (&self.binding.kind, &self.binding.source) {
            (
                LinuxServiceSetupEndpointKindV1::Pipe,
                LinuxServiceSetupEndpointSourceV1::ServicePipe,
            ) if OsMetadataExt::mode(&metadata) & SETUP_DESCRIPTOR_FILE_TYPE_MASK
                == SETUP_DESCRIPTOR_PIPE_MODE =>
            {
                Ok(())
            }
            (
                LinuxServiceSetupEndpointKindV1::SealedRequestMemfd,
                LinuxServiceSetupEndpointSourceV1::PlanSealedRequest {
                    object,
                    content_sha256,
                    seal_bits,
                    ..
                },
            ) => validate_linux_native_service_setup_request(
                &self.file,
                &metadata,
                object,
                content_sha256,
                *seal_bits,
            ),
            _ => Err(failure(
                "validate-linux-native-service-setup-endpoint",
                EffectCertainty::NotApplied,
                "setup endpoint type differs from its canonical semantic source",
            )),
        }
    }
}

fn validate_linux_native_service_setup_request(
    file: &File,
    metadata: &Metadata,
    object: &LinuxServiceSetupObjectIdentityV1,
    content_sha256: &Digest,
    seal_bits: u32,
) -> Result<(), CgroupIoFailure> {
    let identity = object_identity(metadata);
    let byte_length = usize::try_from(metadata.len()).map_err(|_| {
        failure(
            "validate-linux-native-service-setup-request",
            EffectCertainty::NotApplied,
            "setup request length cannot be represented on this host",
        )
    })?;
    if identity.device != object.device_id
        || identity.inode != object.inode
        || object.kind != crate::linux_command_plan::LinuxRetainedObjectKindV1::SealedMemfd
        || OsMetadataExt::mode(metadata) != object.mode
        || OsMetadataExt::uid(metadata) != object.owner_uid
        || OsMetadataExt::gid(metadata) != object.owner_gid
        || PortableMetadataExt::nlink(metadata) != object.link_count
        || object.byte_length != Some(metadata.len())
        || byte_length == 0
        || byte_length > MAX_SETUP_DESCRIPTOR_REQUEST_BYTES
        || hash_linux_native_service_setup_request(file, byte_length)? != *content_sha256
    {
        return Err(failure(
            "validate-linux-native-service-setup-request",
            EffectCertainty::NotApplied,
            "setup request changed identity, metadata, length, or complete content",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsFd as _;
        let filesystem = rustix::fs::fstatfs(file.as_fd()).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let observed_seals = rustix::fs::fcntl_get_seals(file.as_fd()).map_err(|error| {
            io_failure(
                "validate-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if u64::try_from(filesystem.f_type).ok() != Some(TMPFS_SUPER_MAGIC)
            || observed_seals.bits() != seal_bits
            || seal_bits != REQUIRED_EXECUTABLE_SNAPSHOT_SEAL_BITS
        {
            return Err(failure(
                "validate-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                "setup request is not the exact sealed tmpfs memfd required by the plan",
            ));
        }
    }

    #[cfg(all(not(target_os = "linux"), not(test)))]
    return {
        let _ = seal_bits;
        Err(failure(
            "validate-linux-native-service-setup-request",
            EffectCertainty::NotApplied,
            "native sealed setup-request evidence is unavailable off Linux",
        ))
    };

    #[cfg(all(not(target_os = "linux"), test))]
    return {
        let _ = seal_bits;
        Ok(())
    };

    #[cfg(target_os = "linux")]
    Ok(())
}

fn hash_linux_native_service_setup_request(
    file: &File,
    byte_length: usize,
) -> Result<Digest, CgroupIoFailure> {
    use std::os::unix::fs::FileExt as _;

    let retained = file
        .try_clone()
        .map_err(|error| {
            io_failure(
                "read-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                error,
            )
        })?
        .into_std();
    let mut bytes = vec![0_u8; byte_length];
    let mut offset = 0_usize;
    while offset < byte_length {
        let count = retained
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).map_err(|_| {
                    failure(
                        "read-linux-native-service-setup-request",
                        EffectCertainty::NotApplied,
                        "setup-request read offset cannot be represented",
                    )
                })?,
            )
            .map_err(|error| {
                io_failure(
                    "read-linux-native-service-setup-request",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        if count == 0 {
            return Err(failure(
                "read-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                "setup request ended before its retained byte length",
            ));
        }
        offset = offset.checked_add(count).ok_or_else(|| {
            failure(
                "read-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                "setup-request read offset overflowed",
            )
        })?;
    }
    let mut extra = [0_u8; 1];
    if retained
        .read_at(
            &mut extra,
            u64::try_from(byte_length).map_err(|_| {
                failure(
                    "read-linux-native-service-setup-request",
                    EffectCertainty::NotApplied,
                    "setup-request length cannot be represented as a read offset",
                )
            })?,
        )
        .map_err(|error| {
            io_failure(
                "read-linux-native-service-setup-request",
                EffectCertainty::NotApplied,
                error,
            )
        })?
        != 0
    {
        return Err(failure(
            "read-linux-native-service-setup-request",
            EffectCertainty::NotApplied,
            "setup request grew beyond its retained byte length",
        ));
    }
    Ok(Digest::sha256(&bytes))
}

impl LinuxNativeServiceSetupDescriptorCapability {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    #[cfg(test)]
    fn open_test_authenticated(
        plan: &ValidatedLinuxProductionCommandPlanV1,
        inputs: LinuxTestNativeServiceSetupDescriptorInputs,
    ) -> Result<Self, CgroupIoFailure> {
        let binding = plan.service_setup_descriptor_binding().map_err(|error| {
            failure(
                "mint-test-linux-native-service-setup-descriptors",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if inputs.read_only_mount_sources.len() != binding.read_only_mount_sources.len()
            || inputs.endpoints.len() != binding.endpoints.len()
        {
            return Err(failure(
                "mint-test-linux-native-service-setup-descriptors",
                EffectCertainty::NotApplied,
                "test-only setup capability has a missing or extra mount source or endpoint",
            ));
        }
        let execution_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.cwd.execution_root.clone(),
            inputs.execution_root,
            "validate-linux-native-service-setup-execution-root",
        )?;
        let cwd = open_linux_native_service_setup_cwd(
            &execution_root.directory,
            &binding.cwd.root_relative_path,
        )?;
        let private_state_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.private_state_root.clone(),
            inputs.private_state_root,
            "validate-linux-native-service-setup-private-root",
        )?;
        let singleton_journal_root = LinuxNativeServiceSetupDirectory::from_retained(
            binding.singleton_journal_root.clone(),
            inputs.singleton_journal_root,
            "validate-linux-native-service-setup-journal-root",
        )?;
        let read_only_mount_sources = inputs
            .read_only_mount_sources
            .into_iter()
            .zip(&binding.read_only_mount_sources)
            .map(|(directory, expected)| {
                LinuxNativeServiceSetupDirectory::from_retained(
                    expected.object.clone(),
                    directory,
                    "validate-linux-native-service-setup-mount-source",
                )
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;
        let endpoints = inputs
            .endpoints
            .into_iter()
            .zip(&binding.endpoints)
            .map(|((role, file), expected)| {
                if role != expected.role {
                    return Err(failure(
                        "mint-test-linux-native-service-setup-descriptors",
                        EffectCertainty::NotApplied,
                        "test-only setup endpoint crossed its canonical semantic role",
                    ));
                }
                LinuxNativeServiceSetupEndpoint::from_retained(expected.clone(), file)
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;
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
        Ok(authority)
    }

    fn validate_for(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<(), CgroupIoFailure> {
        let expected = plan.service_setup_descriptor_binding().map_err(|error| {
            failure(
                "validate-linux-native-service-setup-descriptors",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if self.binding != expected
            || self.read_only_mount_sources.len() != expected.read_only_mount_sources.len()
            || self.endpoints.len() != expected.endpoints.len()
        {
            return Err(failure(
                "validate-linux-native-service-setup-descriptors",
                EffectCertainty::NotApplied,
                "retained setup descriptor closure crossed its plan, role set, destination set, or phase-close set",
            ));
        }
        self.execution_root
            .validate("validate-linux-native-service-setup-execution-root")?;
        validate_linux_native_service_setup_cwd(
            &self.execution_root.directory,
            &expected.cwd.root_relative_path,
            &self.cwd,
        )?;
        self.private_state_root
            .validate("validate-linux-native-service-setup-private-root")?;
        self.singleton_journal_root
            .validate("validate-linux-native-service-setup-journal-root")?;
        for (source, binding) in self
            .read_only_mount_sources
            .iter()
            .zip(&expected.read_only_mount_sources)
        {
            if source.binding != binding.object {
                return Err(failure(
                    "validate-linux-native-service-setup-mount-source",
                    EffectCertainty::NotApplied,
                    "retained read-only mount source crossed its object, destination, or access role",
                ));
            }
            source.validate("validate-linux-native-service-setup-mount-source")?;
        }
        let mut endpoint_identities = BTreeMap::new();
        for (endpoint, binding) in self.endpoints.iter().zip(&expected.endpoints) {
            if &endpoint.binding != binding {
                return Err(failure(
                    "validate-linux-native-service-setup-endpoint",
                    EffectCertainty::NotApplied,
                    "retained endpoint crossed its semantic role, type, access, or inheritance rule",
                ));
            }
            endpoint.validate()?;
            if endpoint_identities
                .insert(
                    (endpoint.identity.device, endpoint.identity.inode),
                    endpoint.binding.role,
                )
                .is_some()
            {
                return Err(failure(
                    "validate-linux-native-service-setup-endpoint-aliases",
                    EffectCertainty::NotApplied,
                    "two setup or stdio endpoint roles alias one kernel object",
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn revalidate_for_test(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_for(plan)
    }
}

/// One exact launch-image authority joined to the complete setup-descriptor
/// closure. The value is still inert and cannot expose or release descriptors.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceSetupDescriptorAuthority {
    bootstrapped: BootstrappedLinuxProductionCommandPlanV1,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    launch_images: LinuxNativeServiceLaunchImageSetAuthority,
    setup_descriptors: LinuxNativeServiceSetupDescriptorCapability,
    lifetime_lock: LinuxNativeServiceLifetimeLock,
}

impl LinuxNativeServiceSetupDescriptorAuthority {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        self.bootstrapped.validate_retained()?;
        let plan = &self.bootstrapped.journaled.plan;
        self.launch_images.validate_for(plan)?;
        self.setup_descriptors.validate_for(plan)?;
        let binding = plan.journal_binding().map_err(|error| {
            failure(
                "validate-linux-native-service-setup-authority",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        self.service_process_image
            .validate_for_digest(&binding.authenticated_platform_service_digest)?;
        self.lifetime_lock.validate_for(
            &self.bootstrapped.bootstrap.capabilities.state_root,
            binding.service_state_root_identity,
        )
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}
