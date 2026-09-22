fn remove_matching_duplicate_temporary(
    directory: &Dir,
    temporary_name: &str,
    final_name: &str,
    temporary_bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    let final_bytes = read_private_file(
        directory,
        final_name,
        expected_owner_uid,
        MAX_CANONICAL_JOURNAL_BYTES,
    )?;
    if final_bytes != temporary_bytes {
        return Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "temporary and published generation bytes differ",
        ));
    }
    directory.remove_file(temporary_name).map_err(|error| {
        io_failure(
            "remove-duplicate-journal-temporary",
            EffectCertainty::Ambiguous,
            error,
        )
    })
}

fn validate_orphan_temporary_successor(
    latest: Option<&StoredJournal>,
    command_effect_history: &CommandEffectHistory,
    created_command_effects: &BTreeSet<String>,
    sequence: u64,
    record: &DomainJournalRecord,
    plan_digest: Option<&Digest>,
    require_complete_command_plan: bool,
) -> Result<(), CgroupIoFailure> {
    let expected_sequence = latest.map_or(0, |stored| stored.envelope.sequence + 1);
    if sequence != expected_sequence {
        return Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "orphan temporary is not the exact next generation",
        ));
    }
    if record.state == DomainJournalState::CreateIntended {
        let identity = CommandEffectIdentity::from_record(record);
        let commitment = CommandEffectCommitment::from_record(record, plan_digest.cloned());
        if require_complete_command_plan {
            let first = command_effect_history.get(&identity).ok_or_else(|| {
                failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "orphan CreateIntended has no complete command plan",
                )
            })?;
            if plan_digest.is_none()
                || first != &commitment
                || created_command_effects.contains(&identity.effect_id)
            {
                return Err(reused_command_effect_failure(first != &commitment));
            }
        } else {
            require_unseen_command_effect(command_effect_history, &identity, &commitment)?;
        }
    }
    if let Some(previous) = latest {
        validate_record_successor(&previous.envelope.record, record)
    } else if record.state == DomainJournalState::CreateIntended {
        Ok(())
    } else {
        Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "first orphan temporary is not CreateIntended",
        ))
    }
}

fn validate_orphan_probe_successor(
    latest: Option<&StoredProbeJournal>,
    sequence: u64,
    record: &ProbeJournalRecord,
) -> Result<(), CgroupIoFailure> {
    let expected_sequence = latest.map_or(0, |stored| stored.envelope.sequence + 1);
    if sequence != expected_sequence {
        return Err(failure(
            "recover-probe-journal-temporary",
            EffectCertainty::NotApplied,
            "orphan probe temporary is not the exact next generation",
        ));
    }
    if let Some(previous) = latest {
        validate_probe_record_successor(&previous.envelope.record, record)
    } else if record.state == ProbeJournalState::CreateIntended {
        Ok(())
    } else {
        Err(failure(
            "recover-probe-journal-temporary",
            EffectCertainty::NotApplied,
            "first orphan probe temporary is not CreateIntended",
        ))
    }
}

fn validate_probe_record_successor(
    previous: &ProbeJournalRecord,
    next: &ProbeJournalRecord,
) -> Result<(), CgroupIoFailure> {
    previous.validate()?;
    next.validate()?;
    if previous.state == ProbeJournalState::Removed
        && next.state == ProbeJournalState::CreateIntended
    {
        // Each canary episode uses a fresh name and inherits no prior claim.
        // Command effects still belong to one episode.
        if previous.probe_name == next.probe_name
            || previous.expected_delegation_identity != next.expected_delegation_identity
            || previous.expected_owner_uid != next.expected_owner_uid
            || next.canary.is_some()
        {
            return Err(failure(
                "validate-probe-journal-transition",
                EffectCertainty::NotApplied,
                "a completed probe name cannot be reused, delegation binding cannot drift, and a \
                 fresh episode cannot open holding a canary claim",
            ));
        }
        return Ok(());
    }
    if previous.probe_name != next.probe_name
        || previous.episode_kind != next.episode_kind
        || previous.expected_delegation_identity != next.expected_delegation_identity
        || previous.expected_owner_uid != next.expected_owner_uid
        || previous.observed_identity.is_some()
            && previous.observed_identity != next.observed_identity
        || previous.initial_shape.is_some() && previous.initial_shape != next.initial_shape
        || previous.identity_authoritative && !next.identity_authoritative
        || previous.configured_and_read_back && !next.configured_and_read_back
        || previous.stable_empty_proven && !next.stable_empty_proven
        // Canary evidence is written once and never again. A suite that ran
        // is a fact about a leaf, so a later generation may not restate it
        // differently, and no generation may drop it.
        || previous.canary.is_some() && previous.canary != next.canary
    {
        return Err(failure(
            "validate-probe-journal-transition",
            EffectCertainty::NotApplied,
            "immutable probe binding, episode kind, or monotonic evidence changed",
        ));
    }
    let allowed = match previous.state {
        ProbeJournalState::CreateIntended => matches!(
            next.state,
            ProbeJournalState::OwnershipUnknown
                | ProbeJournalState::IdentityObserved
                | ProbeJournalState::Removed
        ),
        ProbeJournalState::OwnershipUnknown | ProbeJournalState::RemoveIntended => {
            next.state == ProbeJournalState::Removed
        }
        ProbeJournalState::IdentityObserved => matches!(
            next.state,
            ProbeJournalState::ShapeObserved | ProbeJournalState::Removed
        ),
        ProbeJournalState::ShapeObserved => matches!(
            next.state,
            ProbeJournalState::ConfigureIntended
                | ProbeJournalState::KillIntended
                | ProbeJournalState::Removed
        ),
        ProbeJournalState::ConfigureIntended => matches!(
            next.state,
            ProbeJournalState::Configured | ProbeJournalState::Removed
        ),
        ProbeJournalState::Configured => matches!(
            next.state,
            ProbeJournalState::KillIntended | ProbeJournalState::Removed
        ),
        ProbeJournalState::KillIntended => matches!(
            next.state,
            ProbeJournalState::EmptyProven | ProbeJournalState::Removed
        ),
        ProbeJournalState::EmptyProven => matches!(
            next.state,
            ProbeJournalState::RemoveIntended | ProbeJournalState::Removed
        ),
        ProbeJournalState::Removed => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(failure(
            "validate-probe-journal-transition",
            EffectCertainty::NotApplied,
            format!(
                "illegal probe journal transition {:?} -> {:?}",
                previous.state, next.state
            ),
        ))
    }
}

fn validate_record_successor(
    previous: &DomainJournalRecord,
    next: &DomainJournalRecord,
) -> Result<(), CgroupIoFailure> {
    let previous_endpoint = matches!(
        previous.state,
        DomainJournalState::CreateAborted | DomainJournalState::Removed
    );
    if previous_endpoint && next.state == DomainJournalState::CreateIntended {
        // Cross-episode field changes are valid only after the scan/persist
        // layer has rejected any identity already present in full history.
        return Ok(());
    }
    let transition = (previous.state, next.state);
    if record_episode_binding_changed(previous, next)
        || native_episode_evidence_delta_is_invalid(previous, next, transition)
        || release_history_delta_is_invalid(previous, next, transition)
    {
        return Err(failure(
            "validate-journal-transition",
            EffectCertainty::NotApplied,
            "immutable request, delegation, native evidence, launch authority, release history, or limit binding changed within an episode",
        ));
    }
    let allowed = matches!(
        transition,
        (
            DomainJournalState::CreateIntended,
            DomainJournalState::CreateAborted | DomainJournalState::Configuring
        ) | (
            DomainJournalState::Configuring,
            DomainJournalState::Prepared
        ) | (
            DomainJournalState::Prepared,
            DomainJournalState::AttachIntended | DomainJournalState::Killing
        ) | (
            DomainJournalState::AttachIntended,
            DomainJournalState::Attached | DomainJournalState::Killing
        ) | (
            DomainJournalState::Attached,
            DomainJournalState::Held | DomainJournalState::Killing
        ) | (
            DomainJournalState::Held,
            DomainJournalState::ReleaseIntended | DomainJournalState::Killing
        ) | (
            DomainJournalState::ReleaseIntended,
            DomainJournalState::Released | DomainJournalState::Killing
        ) | (DomainJournalState::Released, DomainJournalState::Killing)
            | (DomainJournalState::Killing, DomainJournalState::EmptyProven)
            | (
                DomainJournalState::EmptyProven,
                DomainJournalState::RemoveIntended
            )
            | (
                DomainJournalState::RemoveIntended,
                DomainJournalState::Removed
            )
    );
    if allowed {
        Ok(())
    } else {
        Err(failure(
            "validate-journal-transition",
            EffectCertainty::NotApplied,
            format!(
                "illegal journal transition {:?} -> {:?}",
                previous.state, next.state
            ),
        ))
    }
}

fn require_unseen_command_effect(
    history: &CommandEffectHistory,
    identity: &CommandEffectIdentity,
    commitment: &CommandEffectCommitment,
) -> Result<(), CgroupIoFailure> {
    let Some(first) = history.get(identity) else {
        return Ok(());
    };
    Err(reused_command_effect_failure(first != commitment))
}

fn commit_unseen_command_effect(
    history: &mut CommandEffectHistory,
    identity: CommandEffectIdentity,
    commitment: CommandEffectCommitment,
) -> Result<(), CgroupIoFailure> {
    match history.entry(identity) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(commitment);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(entry) => {
            Err(reused_command_effect_failure(entry.get() != &commitment))
        }
    }
}

fn reused_command_effect_failure(binding_changed: bool) -> CgroupIoFailure {
    let detail = if binding_changed {
        "the service journal already committed this globally unique command effect with a different complete plan, runner session, native launch, grant, policy, command, or request binding"
    } else {
        "the service journal already committed this globally unique command effect in immutable journal history"
    };
    failure(
        "validate-journal-episode-history",
        EffectCertainty::PriorEffectCommitted,
        detail,
    )
}

fn record_episode_binding_changed(
    previous: &DomainJournalRecord,
    next: &DomainJournalRecord,
) -> bool {
    previous.runner_session_id != next.runner_session_id
        || previous.native_launch != next.native_launch
        || previous.effect_id != next.effect_id
        || previous.grant_hash != next.grant_hash
        || previous.policy_hash != next.policy_hash
        || previous.command_hash != next.command_hash
        || previous.request_digest != next.request_digest
        || previous.leaf_name != next.leaf_name
        || previous.expected_delegation_identity != next.expected_delegation_identity
        || previous.expected_owner_uid != next.expected_owner_uid
        || previous.requested_limits != next.requested_limits
}

fn native_episode_evidence_delta_is_invalid(
    previous: &DomainJournalRecord,
    next: &DomainJournalRecord,
    transition: (DomainJournalState, DomainJournalState),
) -> bool {
    once_bound_value_delta_is_invalid(
        previous.leaf_identity.as_ref(),
        next.leaf_identity.as_ref(),
        transition
            == (
                DomainJournalState::CreateIntended,
                DomainJournalState::Configuring,
            ),
    ) || once_bound_value_delta_is_invalid(
        previous.read_back_limits.as_ref(),
        next.read_back_limits.as_ref(),
        transition
            == (
                DomainJournalState::Configuring,
                DomainJournalState::Prepared,
            ),
    ) || once_bound_value_delta_is_invalid(
        previous.staged_launcher.as_ref(),
        next.staged_launcher.as_ref(),
        transition
            == (
                DomainJournalState::Prepared,
                DomainJournalState::AttachIntended,
            ),
    ) || once_bound_value_delta_is_invalid(
        previous.kill_value.as_ref(),
        next.kill_value.as_ref(),
        transition == (DomainJournalState::Killing, DomainJournalState::EmptyProven),
    ) || cleanup_observation_delta_is_invalid(previous, next, transition)
}

fn once_bound_value_delta_is_invalid<T: PartialEq>(
    previous: Option<&T>,
    next: Option<&T>,
    introduction_edge: bool,
) -> bool {
    match (previous, next) {
        (None, None) => false,
        (None, Some(_)) => !introduction_edge,
        (Some(previous), Some(next)) => previous != next,
        (Some(_), None) => true,
    }
}

fn cleanup_observation_delta_is_invalid(
    previous: &DomainJournalRecord,
    next: &DomainJournalRecord,
    transition: (DomainJournalState, DomainJournalState),
) -> bool {
    if !next
        .cleanup_observations
        .starts_with(&previous.cleanup_observations)
    {
        return true;
    }
    previous.cleanup_observations != next.cleanup_observations
        && transition != (DomainJournalState::Killing, DomainJournalState::EmptyProven)
}

fn release_history_delta_is_invalid(
    previous: &DomainJournalRecord,
    next: &DomainJournalRecord,
    transition: (DomainJournalState, DomainJournalState),
) -> bool {
    let adds_release_authorization =
        previous.release_authorization.is_none() && next.release_authorization.is_some();
    let adds_release_binding = previous.release_binding.is_none() && next.release_binding.is_some();
    let adds_release_intent = !previous.release_intent_recorded && next.release_intent_recorded;
    let adds_release_observation =
        previous.release_observation.is_none() && next.release_observation.is_some();
    previous
        .release_authorization
        .as_ref()
        .is_some_and(|authorization| next.release_authorization.as_ref() != Some(authorization))
        || previous
            .release_binding
            .as_ref()
            .is_some_and(|binding| next.release_binding.as_ref() != Some(binding))
        || previous.release_intent_recorded && !next.release_intent_recorded
        || previous
            .release_observation
            .as_ref()
            .is_some_and(|observation| next.release_observation.as_ref() != Some(observation))
        || ((adds_release_authorization || adds_release_binding)
            && transition != (DomainJournalState::Attached, DomainJournalState::Held))
        || (adds_release_authorization != adds_release_binding)
        || (adds_release_intent
            && transition
                != (
                    DomainJournalState::Held,
                    DomainJournalState::ReleaseIntended,
                ))
        || (adds_release_observation
            && transition
                != (
                    DomainJournalState::ReleaseIntended,
                    DomainJournalState::Released,
                ))
}

fn open_or_create_private_lock(
    directory: &Dir,
    expected_owner_uid: u32,
) -> Result<(File, ObjectIdentity), CgroupIoFailure> {
    open_or_create_named_private_lock(directory, JOURNAL_LOCK_NAME, expected_owner_uid, "journal")
}

fn open_or_create_named_private_lock(
    directory: &Dir,
    name: &str,
    expected_owner_uid: u32,
    operation_prefix: &'static str,
) -> Result<(File, ObjectIdentity), CgroupIoFailure> {
    validate_component("private lock", name)?;
    let mut create = OpenOptions::new();
    create
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let file = match directory.open_with(name, &create) {
        Ok(file) => {
            file.sync_all().map_err(|error| {
                io_failure("sync-new-private-lock", EffectCertainty::Ambiguous, error)
            })?;
            sync_directory(directory).map_err(|error| {
                io_failure(
                    "sync-new-private-lock-directory",
                    EffectCertainty::Ambiguous,
                    error,
                )
            })?;
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut open = OpenOptions::new();
            open.read(true).write(true).follow(FollowSymlinks::No);
            directory.open_with(name, &open).map_err(|error| {
                io_failure("open-private-lock", EffectCertainty::NotApplied, error)
            })?
        }
        Err(error) => {
            return Err(io_failure(
                "create-private-lock",
                EffectCertainty::NotApplied,
                error,
            ));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("inspect-private-lock", EffectCertainty::NotApplied, error))?;
    validate_private_file(&metadata, expected_owner_uid)?;
    let identity = object_identity(&metadata);
    let identity_operation = match operation_prefix {
        "journal" => "journal-lock-identity",
        "linux-native-service-lifetime" => "linux-native-service-lifetime-lock-identity",
        _ => "private-lock-identity",
    };
    require_named_identity(directory, name, identity, identity_operation)?;
    Ok((file, identity))
}

fn open_or_create_private_directory(
    parent: &Dir,
    name: &str,
    expected_owner_uid: u32,
) -> Result<(Dir, ObjectIdentity), CgroupIoFailure> {
    validate_component("private journal directory", name)?;
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    let created = match parent.create_dir_with(name, &builder) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(io_failure(
                "create-probe-journal-root",
                EffectCertainty::NotApplied,
                error,
            ));
        }
    };
    let directory = parent.open_dir_nofollow(name).map_err(|error| {
        io_failure(
            "open-probe-journal-root",
            if created {
                EffectCertainty::Ambiguous
            } else {
                EffectCertainty::NotApplied
            },
            error,
        )
    })?;
    if created {
        directory
            .set_permissions(Path::new("."), Permissions::from_mode(0o700))
            .map_err(|error| {
                io_failure(
                    "set-probe-journal-root-mode",
                    EffectCertainty::Ambiguous,
                    error,
                )
            })?;
        sync_directory(&directory).map_err(|error| {
            io_failure("sync-probe-journal-root", EffectCertainty::Ambiguous, error)
        })?;
        sync_directory(parent).map_err(|error| {
            io_failure(
                "sync-probe-journal-parent",
                EffectCertainty::Ambiguous,
                error,
            )
        })?;
    }
    let metadata = directory.dir_metadata().map_err(|error| {
        io_failure(
            "inspect-probe-journal-root",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    validate_private_directory(&metadata, expected_owner_uid)?;
    let identity = object_identity(&metadata);
    require_named_identity(parent, name, identity, "probe-journal-root-identity")?;
    Ok((directory, identity))
}

fn write_new_private_file(
    directory: &Dir,
    name: &str,
    bytes: &[u8],
    expected_owner_uid: u32,
) -> Result<ObjectIdentity, CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let mut file = directory.open_with(name, &options).map_err(|error| {
        io_failure(
            "create-journal-temporary",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io_failure(
            "inspect-journal-temporary",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    validate_private_file(&metadata, expected_owner_uid)?;
    let identity = object_identity(&metadata);
    require_named_identity(directory, name, identity, "journal-temporary-identity")?;
    file.write_all(bytes).map_err(|error| {
        io_failure("write-journal-temporary", EffectCertainty::Ambiguous, error)
    })?;
    file.sync_all()
        .map_err(|error| io_failure("sync-journal-temporary", EffectCertainty::Ambiguous, error))?;
    Ok(identity)
}

fn named_private_file_identity(
    directory: &Dir,
    name: &str,
    expected_owner_uid: u32,
) -> Result<ObjectIdentity, CgroupIoFailure> {
    let metadata = directory.symlink_metadata(name).map_err(|error| {
        io_failure(
            "inspect-journal-generation",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(failure(
            "inspect-journal-generation",
            EffectCertainty::NotApplied,
            "journal generation is a symbolic link",
        ));
    }
    validate_private_file(&metadata, expected_owner_uid)?;
    Ok(object_identity(&metadata))
}

fn read_private_file(
    directory: &Dir,
    name: &str,
    expected_owner_uid: u32,
    max_bytes: usize,
) -> Result<Vec<u8>, CgroupIoFailure> {
    read_private_file_with_identity(directory, name, expected_owner_uid, max_bytes)
        .map(|(bytes, _identity)| bytes)
}

/// Opens one named private file without following symlinks, proves the opened
/// descriptor is still the exact named object both before and after readback,
/// and returns the identity that authenticated those bytes.
fn read_private_file_with_identity(
    directory: &Dir,
    name: &str,
    expected_owner_uid: u32,
    max_bytes: usize,
) -> Result<(Vec<u8>, ObjectIdentity), CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|error| {
        io_failure(
            "open-journal-generation",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        io_failure(
            "inspect-journal-generation",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    validate_private_file(&metadata, expected_owner_uid)?;
    let identity = object_identity(&metadata);
    require_named_identity(directory, name, identity, "journal-generation-identity")?;
    let bytes = read_bounded(file, max_bytes, "read-journal-generation")?;
    require_named_identity(directory, name, identity, "journal-generation-identity")?;
    Ok((bytes, identity))
}

fn read_bounded(
    file: File,
    max_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, CgroupIoFailure> {
    let limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            failure(
                operation,
                EffectCertainty::NotApplied,
                "read byte bound overflowed",
            )
        })?;
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if bytes.len() > max_bytes {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "bounded file read exceeded its maximum",
        ));
    }
    Ok(bytes)
}

fn read_entry_names(directory: &Dir) -> Result<Vec<String>, CgroupIoFailure> {
    let entries = directory.entries().map_err(|error| {
        io_failure("scan-journal-directory", EffectCertainty::NotApplied, error)
    })?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            io_failure("scan-journal-directory", EffectCertainty::NotApplied, error)
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal entry name is not UTF-8",
            )
        })?;
        validate_component("journal entry", &name)?;
        names.push(name);
        if names.len() > MAX_JOURNAL_DIRECTORY_ENTRIES {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal directory entry count exceeded its hard bound",
            ));
        }
    }
    Ok(names)
}

fn validate_private_directory(
    metadata: &Metadata,
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    let mode = OsMetadataExt::mode(metadata) & 0o777;
    if !metadata.is_dir() || mode != 0o700 || OsMetadataExt::uid(metadata) != expected_owner_uid {
        return Err(failure(
            "validate-journal-root",
            EffectCertainty::NotApplied,
            "journal root must be an owner-private 0700 directory",
        ));
    }
    Ok(())
}

fn validate_private_file(
    metadata: &Metadata,
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    let mode = OsMetadataExt::mode(metadata) & 0o777;
    if !metadata.is_file()
        || mode != 0o600
        || OsMetadataExt::uid(metadata) != expected_owner_uid
        || PortableMetadataExt::nlink(metadata) != 1
    {
        return Err(failure(
            "validate-journal-file",
            EffectCertainty::NotApplied,
            "journal files must be owner-private 0600 regular files with one link",
        ));
    }
    Ok(())
}

fn require_named_identity(
    parent: &Dir,
    name: &str,
    expected: ObjectIdentity,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let named = parent
        .symlink_metadata(name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if named.file_type().is_symlink() || object_identity(&named) != expected {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "named entry does not match the retained descriptor identity",
        ));
    }
    Ok(())
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn service_journal_binding_matches_plan(
    binding: &LinuxServiceCommandJournalBinding,
    expected: &LinuxProductionCommandPlanJournalBindingV1,
) -> bool {
    binding.authority_version == SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION
        && binding.authenticated_platform_service_digest
            == expected.authenticated_platform_service_digest
        && binding.service_state_root_identity == expected.service_state_root_identity
        && binding.singleton_journal_root_identity == expected.singleton_journal_root_identity
        && binding.delegation.service_parent_identity == expected.service_parent_identity
        && binding.delegation.delegation_identity == expected.delegation_identity
        && binding.delegation.owner_uid == expected.owner_uid
        && binding.delegation.delegation_mode == expected.delegation_mode
}

fn service_journal_plan_binding(
    binding: &LinuxServiceCommandJournalBinding,
) -> Result<LinuxProductionCommandPlanJournalBindingV1, CgroupIoFailure> {
    if binding.authority_version != SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION {
        return Err(failure(
            "bind-service-command-journal",
            EffectCertainty::NotApplied,
            "service command-journal authority version is unsupported",
        ));
    }
    Ok(LinuxProductionCommandPlanJournalBindingV1 {
        authenticated_platform_service_digest: binding
            .authenticated_platform_service_digest
            .clone(),
        service_state_root_identity: binding.service_state_root_identity,
        singleton_journal_root_identity: binding.singleton_journal_root_identity,
        service_parent_identity: binding.delegation.service_parent_identity,
        delegation_identity: binding.delegation.delegation_identity,
        owner_uid: binding.delegation.owner_uid,
        delegation_mode: binding.delegation.delegation_mode,
    })
}

fn service_journal_binding_from_plan(
    expected: &LinuxProductionCommandPlanJournalBindingV1,
) -> LinuxServiceCommandJournalBinding {
    LinuxServiceCommandJournalBinding {
        authority_version: SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION,
        authenticated_platform_service_digest: expected
            .authenticated_platform_service_digest
            .clone(),
        service_state_root_identity: expected.service_state_root_identity,
        singleton_journal_root_identity: expected.singleton_journal_root_identity,
        delegation: DelegationRootExpectation {
            service_parent_identity: expected.service_parent_identity,
            delegation_identity: expected.delegation_identity,
            owner_uid: expected.owner_uid,
            delegation_mode: expected.delegation_mode,
        },
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear evidence audit keeps every mandatory cgroup, Bubblewrap, Landlock, and seccomp refusal visible"
)]
fn validate_service_bootstrap_evidence(
    evidence: &LinuxNativeServiceBootstrapEvidenceV1,
) -> Result<(), CgroupIoFailure> {
    if evidence.authority_version != SERVICE_BOOTSTRAP_AUTHORITY_VERSION {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "native-service bootstrap authority version is unsupported",
        ));
    }
    let binding = &evidence.plan_binding;
    let journal = &binding.journal;
    if binding.cgroup_filesystem_magic != CGROUP2_SUPER_MAGIC
        || journal.service_state_root_identity.device == 0
        || journal.service_state_root_identity.inode == 0
        || journal.singleton_journal_root_identity.device == 0
        || journal.singleton_journal_root_identity.inode == 0
        || journal.service_parent_identity.device == 0
        || journal.service_parent_identity.inode == 0
        || journal.delegation_identity.device == 0
        || journal.delegation_identity.inode == 0
        || journal.delegation_mode & 0o002 != 0
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "service roots or delegation are not exact nonzero cgroup-v2 identities",
        ));
    }
    validate_component(
        "bootstrap delegation component",
        &evidence.cgroup.delegation_component,
    )?;
    let control_identities = [
        evidence.cgroup.controllers_file_identity,
        evidence.cgroup.subtree_control_file_identity,
        evidence.cgroup.cgroup_procs_file_identity,
    ];
    if control_identities
        .iter()
        .any(|identity| identity.device == 0 || identity.inode == 0)
        || control_identities[0] == control_identities[1]
        || control_identities[0] == control_identities[2]
        || control_identities[1] == control_identities[2]
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "delegation controller readbacks lack distinct retained identities",
        ));
    }
    let controllers = evidence.cgroup.controllers_readback.as_bytes();
    let subtree = evidence.cgroup.subtree_control_readback.as_bytes();
    if evidence.cgroup.controllers_readback_sha256 != Digest::sha256(controllers)
        || evidence.cgroup.subtree_control_readback_sha256 != Digest::sha256(subtree)
        || evidence.cgroup.cgroup_procs_readback_sha256
            != Digest::sha256(evidence.cgroup.cgroup_procs_readback.as_bytes())
        || !evidence.cgroup.cgroup_procs_readback.is_empty()
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "cgroup controller, subtree-control, or no-internal-process readback digest differs",
        ));
    }
    let required = BTreeSet::from([DomainController::Memory, DomainController::Pids]);
    let available = parse_controller_set(controllers, false)?;
    let enabled = parse_controller_set(subtree, true)?;
    if !required.is_subset(&available) || enabled != required {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "bootstrap requires available memory+pids and exact enabled memory+pids controller readback",
        ));
    }
    if evidence.cgroup.active_probe_contract_digest
        != Digest::sha256(CGROUP_BOOTSTRAP_PROBE_CONTRACT)
        || digest_is_zero(&evidence.cgroup.active_probe_result_digest)
        || !evidence.cgroup.active_probe_passed
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "delegated-cgroup active probe contract or result is incomplete",
        ));
    }

    let bubblewrap = &binding.bubblewrap;
    if bubblewrap.resolved_path.is_empty()
        || bubblewrap.version.is_empty()
        || bubblewrap.file.device_id == 0
        || bubblewrap.file.inode == 0
        || bubblewrap.file.mount_id == 0
        || bubblewrap.file.byte_length == 0
        || bubblewrap.file.link_count != 1
        || bubblewrap.file.mode & 0o170_000 != 0o100_000
        || bubblewrap.file.mode & 0o111 == 0
        || bubblewrap.file.mode & 0o6000 != 0
        || digest_is_zero(&bubblewrap.file.content_sha256)
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "Bubblewrap image identity, mode, content, or version is incomplete",
        ));
    }
    // The Debian package version and executable `--version` output are
    // separately pinned facts.
    if bubblewrap.version != ADMITTED_BUBBLEWRAP_IMAGE_V1.version {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "planned Bubblewrap package version is not the admitted one",
        ));
    }
    let expected_version_stdout =
        format!("{}\n", ADMITTED_BUBBLEWRAP_IMAGE_V1.self_reported_version);
    if evidence.bubblewrap.version_stdout != expected_version_stdout
        || evidence.bubblewrap.version_stdout_sha256
            != Digest::sha256(evidence.bubblewrap.version_stdout.as_bytes())
        || evidence.bubblewrap.active_probe_contract_digest
            != Digest::sha256(BUBBLEWRAP_BOOTSTRAP_PROBE_CONTRACT)
        || digest_is_zero(&evidence.bubblewrap.active_probe_result_digest)
        || !evidence.bubblewrap.active_probe_passed
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "Bubblewrap version or active probe does not bind the exact planned image",
        ));
    }

    // Compare the live probe with committed kernel artifacts; a nonzero digest
    // alone proves no correspondence.
    let LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
        minimum_kernel_abi,
        maximum_modeled_kernel_abi,
        ruleset,
    } = &binding.landlock;
    if evidence.landlock.observed_kernel_abi < *minimum_kernel_abi
        || evidence.landlock.observed_kernel_abi > *maximum_modeled_kernel_abi
        || digest_is_zero(&evidence.landlock.active_probe_result_digest)
        || !evidence.landlock.full_enforcement_passed
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "Landlock ABI window or full-enforcement probe is incomplete",
        ));
    }
    if ruleset.ruleset_sha256 != ruleset.canonical_digest() {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "the planned Landlock ruleset digest is not the digest of the ruleset beside it",
        ));
    }
    // Bind the exact scope, retained object, witness, and kernel ABI.
    if evidence.landlock.active_probe_result_digest
        != landlock_bootstrap_probe_result_digest(ruleset, evidence.landlock.observed_kernel_abi)
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "the Landlock probe result was not produced by a probe that installed the exact ruleset this plan commits",
        ));
    }
    let LinuxSeccompBootstrapBindingV1::CompiledFilterProvenByLiveBootstrapProbe {
        audit_architecture,
        default_action,
        filter,
    } = &binding.seccomp;
    if digest_is_zero(&evidence.seccomp.active_probe_result_digest)
        || !evidence.seccomp.no_new_privileges_read_back
        || !evidence.seccomp.forbidden_syscall_killed
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "seccomp no-new-privileges readback or forbidden-syscall probe is incomplete",
        ));
    }
    if filter.filter_sha256 != filter.canonical_digest(*audit_architecture, *default_action) {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "the planned seccomp filter digest is not the digest of the filter beside it",
        ));
    }
    if evidence.seccomp.active_probe_result_digest != seccomp_bootstrap_probe_result_digest(filter)
    {
        return Err(failure(
            "validate-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            "the seccomp probe result was not produced by a probe that installed the exact filter this plan commits",
        ));
    }
    Ok(())
}

fn digest_is_zero(digest: &Digest) -> bool {
    digest.as_str().bytes().all(|byte| byte == b'0')
}

fn same_service_bootstrap_identity(
    left: &LinuxNativeServiceBootstrapEvidenceV1,
    right: &LinuxNativeServiceBootstrapEvidenceV1,
) -> bool {
    left.authority_version == right.authority_version
        && left.plan_binding.journal == right.plan_binding.journal
        && left.plan_binding.cgroup_filesystem_magic == right.plan_binding.cgroup_filesystem_magic
        && left.plan_binding.bubblewrap == right.plan_binding.bubblewrap
        && left.plan_binding.seccomp == right.plan_binding.seccomp
        && left.cgroup == right.cgroup
        && left.bubblewrap == right.bubblewrap
        && left.landlock.observed_kernel_abi == right.landlock.observed_kernel_abi
        && left.landlock.full_enforcement_passed == right.landlock.full_enforcement_passed
        && left.seccomp == right.seccomp
}

fn service_bootstrap_evidence_commitment(bytes: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(
        SERVICE_BOOTSTRAP_COMMITMENT_DOMAIN.len() + std::mem::size_of::<u64>() + bytes.len(),
    );
    preimage.extend_from_slice(SERVICE_BOOTSTRAP_COMMITMENT_DOMAIN);
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(bytes);
    Digest::sha256(&preimage)
}

fn encode_service_bootstrap_envelope(
    evidence: &LinuxNativeServiceBootstrapEvidenceV1,
) -> Result<Vec<u8>, CgroupIoFailure> {
    validate_service_bootstrap_evidence(evidence)?;
    let evidence_bytes = serde_json::to_vec(evidence).map_err(|error| {
        failure(
            "encode-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let envelope = LinuxNativeServiceBootstrapEnvelopeV1 {
        format_version: SERVICE_BOOTSTRAP_FORMAT_VERSION,
        evidence_commitment_sha256: service_bootstrap_evidence_commitment(&evidence_bytes),
        evidence: evidence.clone(),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_SERVICE_BOOTSTRAP_BYTES {
        return Err(failure(
            "encode-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            "canonical native-service bootstrap evidence exceeded its byte bound",
        ));
    }
    Ok(bytes)
}

fn decode_service_bootstrap_envelope(
    bytes: &[u8],
) -> Result<LinuxNativeServiceBootstrapEnvelopeV1, CgroupIoFailure> {
    if bytes.is_empty() || bytes.len() > MAX_SERVICE_BOOTSTRAP_BYTES {
        return Err(failure(
            "decode-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            "native-service bootstrap envelope is empty or oversized",
        ));
    }
    let envelope: LinuxNativeServiceBootstrapEnvelopeV1 =
        serde_json::from_slice(bytes).map_err(|error| {
            failure(
                "decode-linux-service-bootstrap-envelope",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
    if envelope.format_version != SERVICE_BOOTSTRAP_FORMAT_VERSION {
        return Err(failure(
            "classify-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            "native-service bootstrap evidence format version is unsupported",
        ));
    }
    validate_service_bootstrap_evidence(&envelope.evidence)?;
    let evidence_bytes = serde_json::to_vec(&envelope.evidence).map_err(|error| {
        failure(
            "encode-linux-service-bootstrap-evidence",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if envelope.evidence_commitment_sha256 != service_bootstrap_evidence_commitment(&evidence_bytes)
    {
        return Err(failure(
            "authenticate-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            "native-service bootstrap evidence commitment differs from canonical evidence",
        ));
    }
    let canonical = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if canonical != bytes {
        return Err(failure(
            "decode-linux-service-bootstrap-envelope",
            EffectCertainty::NotApplied,
            "native-service bootstrap evidence is not canonical JSON",
        ));
    }
    Ok(envelope)
}

fn persist_or_read_service_bootstrap_evidence(
    service_state_root: &Dir,
    expected_owner_uid: u32,
    evidence: &LinuxNativeServiceBootstrapEvidenceV1,
) -> Result<(Vec<u8>, ObjectIdentity), CgroupIoFailure> {
    let canonical = encode_service_bootstrap_envelope(evidence)?;
    recover_service_bootstrap_temporary(service_state_root, expected_owner_uid)?;
    match service_state_root.symlink_metadata(SERVICE_BOOTSTRAP_FINAL_NAME) {
        Ok(_) => {
            let identity = named_private_file_identity(
                service_state_root,
                SERVICE_BOOTSTRAP_FINAL_NAME,
                expected_owner_uid,
            )?;
            let bytes = read_private_file(
                service_state_root,
                SERVICE_BOOTSTRAP_FINAL_NAME,
                expected_owner_uid,
                MAX_SERVICE_BOOTSTRAP_BYTES,
            )?;
            let decoded = decode_service_bootstrap_envelope(&bytes)?;
            if !same_service_bootstrap_identity(&decoded.evidence, evidence) {
                return Err(failure(
                    "authenticate-linux-service-bootstrap-restart",
                    EffectCertainty::NotApplied,
                    "fixed native-service identity differs across restart",
                ));
            }
            return Ok((bytes, identity));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io_failure(
                "inspect-linux-service-bootstrap-artifact",
                EffectCertainty::NotApplied,
                error,
            ));
        }
    }
    let identity = write_new_private_file(
        service_state_root,
        SERVICE_BOOTSTRAP_TEMP_NAME,
        &canonical,
        expected_owner_uid,
    )?;
    renameat_with(
        service_state_root,
        Path::new(SERVICE_BOOTSTRAP_TEMP_NAME),
        service_state_root,
        Path::new(SERVICE_BOOTSTRAP_FINAL_NAME),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        io_failure(
            "publish-linux-service-bootstrap-artifact",
            EffectCertainty::Ambiguous,
            error,
        )
    })?;
    sync_directory(service_state_root).map_err(|error| {
        io_failure(
            "sync-linux-service-bootstrap-artifact",
            EffectCertainty::Ambiguous,
            error,
        )
    })?;
    let published = named_private_file_identity(
        service_state_root,
        SERVICE_BOOTSTRAP_FINAL_NAME,
        expected_owner_uid,
    )?;
    let readback = read_private_file(
        service_state_root,
        SERVICE_BOOTSTRAP_FINAL_NAME,
        expected_owner_uid,
        MAX_SERVICE_BOOTSTRAP_BYTES,
    )?;
    let decoded = decode_service_bootstrap_envelope(&readback)?;
    if published != identity || readback != canonical || decoded.evidence != *evidence {
        return Err(failure(
            "readback-linux-service-bootstrap-artifact",
            EffectCertainty::Ambiguous,
            "published native-service bootstrap identity or canonical evidence differs",
        ));
    }
    Ok((readback, published))
}

fn recover_service_bootstrap_temporary(
    service_state_root: &Dir,
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    match service_state_root.symlink_metadata(SERVICE_BOOTSTRAP_TEMP_NAME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io_failure(
                "inspect-linux-service-bootstrap-temporary",
                EffectCertainty::Ambiguous,
                error,
            ));
        }
        Ok(_) => {}
    }
    named_private_file_identity(
        service_state_root,
        SERVICE_BOOTSTRAP_TEMP_NAME,
        expected_owner_uid,
    )?;
    match service_state_root.symlink_metadata(SERVICE_BOOTSTRAP_FINAL_NAME) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            service_state_root
                .remove_file(SERVICE_BOOTSTRAP_TEMP_NAME)
                .map_err(|error| {
                    io_failure(
                        "discard-linux-service-bootstrap-temporary",
                        EffectCertainty::NotApplied,
                        error,
                    )
                })?;
        }
        Ok(_) => {
            let temporary = read_private_file(
                service_state_root,
                SERVICE_BOOTSTRAP_TEMP_NAME,
                expected_owner_uid,
                MAX_SERVICE_BOOTSTRAP_BYTES,
            )?;
            let final_bytes = read_private_file(
                service_state_root,
                SERVICE_BOOTSTRAP_FINAL_NAME,
                expected_owner_uid,
                MAX_SERVICE_BOOTSTRAP_BYTES,
            )?;
            if temporary != final_bytes {
                return Err(failure(
                    "recover-linux-service-bootstrap-temporary",
                    EffectCertainty::Ambiguous,
                    "bootstrap temporary differs from the published fixed artifact",
                ));
            }
            service_state_root
                .remove_file(SERVICE_BOOTSTRAP_TEMP_NAME)
                .map_err(|error| {
                    io_failure(
                        "remove-linux-service-bootstrap-temporary",
                        EffectCertainty::Ambiguous,
                        error,
                    )
                })?;
        }
        Err(error) => {
            return Err(io_failure(
                "inspect-linux-service-bootstrap-publication",
                EffectCertainty::Ambiguous,
                error,
            ));
        }
    }
    sync_directory(service_state_root).map_err(|error| {
        io_failure(
            "sync-linux-service-bootstrap-recovery",
            EffectCertainty::Ambiguous,
            error,
        )
    })
}

fn open_retained_bootstrap_artifact(
    service_state_root: &Dir,
    expected_owner_uid: u32,
) -> Result<(File, ObjectIdentity, Vec<u8>), CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let artifact = service_state_root
        .open_with(SERVICE_BOOTSTRAP_FINAL_NAME, &options)
        .map_err(|error| {
            io_failure(
                "open-linux-service-bootstrap-artifact",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
    let metadata = artifact.metadata().map_err(|error| {
        io_failure(
            "inspect-linux-service-bootstrap-artifact",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    validate_private_file(&metadata, expected_owner_uid)?;
    let identity = object_identity(&metadata);
    require_named_identity(
        service_state_root,
        SERVICE_BOOTSTRAP_FINAL_NAME,
        identity,
        "linux-service-bootstrap-artifact-identity",
    )?;
    let bytes = read_retained_bootstrap_file(
        &artifact,
        MAX_SERVICE_BOOTSTRAP_BYTES,
        "read-linux-service-bootstrap-artifact",
    )?;
    Ok((artifact, identity, bytes))
}

fn open_retained_bootstrap_file(
    parent: &Dir,
    name: &str,
    operation: &'static str,
) -> Result<(File, ObjectIdentity), CgroupIoFailure> {
    validate_component("bootstrap retained file", name)?;
    open_retained_nofollow_regular_file(parent, name, operation)
}

fn open_retained_nofollow_regular_file(
    parent: &Dir,
    name: &str,
    operation: &'static str,
) -> Result<(File, ObjectIdentity), CgroupIoFailure> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent
        .open_with(name, &options)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_file() {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained bootstrap object is not a regular file",
        ));
    }
    let identity = object_identity(&metadata);
    require_named_identity(parent, name, identity, operation)?;
    Ok((file, identity))
}

#[cfg(target_os = "linux")]
fn retained_descriptor_mount_id<Descriptor: std::os::fd::AsFd>(
    descriptor: &Descriptor,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    let unique_mount_id = rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_BITS);
    let observation = rustix::fs::statx(
        descriptor,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        unique_mount_id,
    )
    .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    require_unique_mount_id(observation.stx_mask, observation.stx_mnt_id, operation)
}

fn require_unique_mount_id(
    returned_mask: u32,
    mount_id: u64,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    if returned_mask & STATX_MNT_ID_UNIQUE_BITS != STATX_MNT_ID_UNIQUE_BITS || mount_id == 0 {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "kernel statx did not return a nonzero STATX_MNT_ID_UNIQUE; Linux 6.8+ unique mount identity is required",
        ));
    }
    Ok(mount_id)
}

#[cfg(target_os = "linux")]
fn retained_file_mount_id(file: &File, operation: &'static str) -> Result<u64, CgroupIoFailure> {
    retained_descriptor_mount_id(file, operation)
}

#[cfg(target_os = "linux")]
fn retained_directory_mount_id(
    directory: &Dir,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    retained_descriptor_mount_id(directory, operation)
}

#[cfg(all(not(target_os = "linux"), test))]
fn retained_file_mount_id(file: &File, operation: &'static str) -> Result<u64, CgroupIoFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    Ok(PortableMetadataExt::dev(&metadata).max(1))
}

#[cfg(all(not(target_os = "linux"), test))]
fn retained_directory_mount_id(
    directory: &Dir,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    Ok(PortableMetadataExt::dev(&metadata).max(1))
}

#[cfg(all(not(target_os = "linux"), not(test)))]
fn retained_file_mount_id(_file: &File, operation: &'static str) -> Result<u64, CgroupIoFailure> {
    Err(failure(
        operation,
        EffectCertainty::NotApplied,
        "executable mount identity is available only on Linux",
    ))
}

#[cfg(all(not(target_os = "linux"), not(test)))]
fn retained_directory_mount_id(
    _directory: &Dir,
    operation: &'static str,
) -> Result<u64, CgroupIoFailure> {
    Err(failure(
        operation,
        EffectCertainty::NotApplied,
        "directory mount identity is available only on Linux",
    ))
}

fn require_named_file_mount_identity(
    parent: &Dir,
    name: &str,
    expected_identity: ObjectIdentity,
    expected_mount_id: u64,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let (named, identity) = open_retained_nofollow_regular_file(parent, name, operation)?;
    if identity != expected_identity
        || retained_file_mount_id(&named, operation)? != expected_mount_id
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "named executable inode or mount identity differs from retained authority",
        ));
    }
    Ok(())
}

fn read_retained_bootstrap_file(
    file: &File,
    max_bytes: usize,
    operation: &'static str,
) -> Result<Vec<u8>, CgroupIoFailure> {
    let mut retained = file
        .try_clone()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    retained
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    read_bounded(retained, max_bytes, operation)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact named descriptor, evidence identity, and byte readback are intentionally explicit"
)]
fn validate_retained_bootstrap_readback(
    parent: &Dir,
    name: &str,
    file: &File,
    retained_identity: ObjectIdentity,
    evidence_identity: CgroupObjectIdentity,
    expected_bytes: &[u8],
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let metadata = file
        .metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_file()
        || object_identity(&metadata) != retained_identity
        || cgroup_identity(retained_identity) != evidence_identity
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained controller readback identity changed",
        ));
    }
    require_named_identity(parent, name, retained_identity, operation)?;
    let observed = read_retained_bootstrap_file(file, MAX_BOOTSTRAP_READBACK_BYTES, operation)?;
    if observed != expected_bytes {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained controller bytes differ from authenticated bootstrap readback",
        ));
    }
    Ok(())
}

fn final_name(sequence: u64) -> String {
    format!("{JOURNAL_FINAL_PREFIX}{sequence:0JOURNAL_SEQUENCE_DIGITS$}{JOURNAL_FINAL_SUFFIX}")
}

fn temporary_name(sequence: u64) -> String {
    format!("{JOURNAL_FINAL_PREFIX}{sequence:0JOURNAL_SEQUENCE_DIGITS$}{JOURNAL_TEMP_SUFFIX}")
}

fn command_plan_name(plan_digest: &Digest) -> String {
    format!("{COMMAND_PLAN_PREFIX}{plan_digest}{COMMAND_PLAN_SUFFIX}")
}

fn parse_command_plan_name(name: &str) -> Option<&str> {
    parse_command_plan_name_with_suffix(name, COMMAND_PLAN_SUFFIX)
}

fn command_plan_temporary_name(plan_digest: &Digest) -> String {
    format!("{COMMAND_PLAN_PREFIX}{plan_digest}{JOURNAL_TEMP_SUFFIX}")
}

fn parse_command_plan_temporary_name(name: &str) -> Option<&str> {
    parse_command_plan_name_with_suffix(name, JOURNAL_TEMP_SUFFIX)
}

fn parse_command_plan_name_with_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let digest = name
        .strip_prefix(COMMAND_PLAN_PREFIX)?
        .strip_suffix(suffix)?;
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(digest)
}

fn probe_final_name(sequence: u64) -> String {
    format!(
        "{PROBE_JOURNAL_FINAL_PREFIX}{sequence:0JOURNAL_SEQUENCE_DIGITS$}{JOURNAL_FINAL_SUFFIX}"
    )
}

fn probe_temporary_name(sequence: u64) -> String {
    format!("{PROBE_JOURNAL_FINAL_PREFIX}{sequence:0JOURNAL_SEQUENCE_DIGITS$}{JOURNAL_TEMP_SUFFIX}")
}

fn parse_generation_name(name: &str, suffix: &str) -> Option<u64> {
    parse_prefixed_generation_name(name, JOURNAL_FINAL_PREFIX, suffix)
}

fn parse_probe_generation_name(name: &str, suffix: &str) -> Option<u64> {
    parse_prefixed_generation_name(name, PROBE_JOURNAL_FINAL_PREFIX, suffix)
}

fn parse_prefixed_generation_name(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    if digits.len() != JOURNAL_SEQUENCE_DIGITS || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let sequence = digits.parse::<u64>().ok()?;
    (format!("{sequence:0JOURNAL_SEQUENCE_DIGITS$}") == digits).then_some(sequence)
}

fn validate_probe_name(name: &str) -> Result<(), CgroupIoFailure> {
    validate_component("preflight probe", name)?;
    let nonce = name.strip_prefix(".gb-probe-").ok_or_else(|| {
        failure(
            "validate-probe-name",
            EffectCertainty::NotApplied,
            "probe name lacks its fixed prefix",
        )
    })?;
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure(
            "validate-probe-name",
            EffectCertainty::NotApplied,
            "probe nonce is not exactly 128 bits of lowercase hexadecimal",
        ));
    }
    Ok(())
}

fn validate_component(label: &'static str, name: &str) -> Result<(), CgroupIoFailure> {
    if name.is_empty()
        || name.len() > 128
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(failure(
            "validate-component",
            EffectCertainty::NotApplied,
            format!("{label} is not a canonical bounded path component"),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn io_failure(
    operation: &'static str,
    certainty: EffectCertainty,
    error: impl std::fmt::Display,
) -> CgroupIoFailure {
    failure(operation, certainty, error.to_string())
}

fn failure(
    operation: &'static str,
    certainty: EffectCertainty,
    detail: impl Into<String>,
) -> CgroupIoFailure {
    CgroupIoFailure {
        operation,
        certainty,
        detail: detail.into(),
    }
}

fn cgroup_identity(identity: ObjectIdentity) -> CgroupObjectIdentity {
    CgroupObjectIdentity {
        device: identity.device,
        inode: identity.inode,
    }
}

const REQUIRED_DELEGATION_FILES: [&str; 7] = [
    "cgroup.procs",
    "cgroup.subtree_control",
    "pids.max",
    "memory.max",
    "memory.swap.max",
    "memory.oom.group",
    "cgroup.kill",
];
/// Wall-clock separation between the two `cgroup.procs` reads of one cleanup
/// attempt, and therefore between consecutive attempts.
///
/// `std::thread::yield_now()` alone was measured to be no barrier at all here.
/// A process killed by `cgroup.kill` stays charged to the cgroup until its
/// parent reaps it, and the reaper's parent is normally another thread of this
/// process; sixteen yield-only attempts complete in microseconds, so
/// `collect_stable_empty_observations` could exhaust its whole attempt budget
/// and report `CleanupIncomplete` for a domain that was empty milliseconds
/// later. Under a loaded host that happened in **1 of 5** full-suite runs; with
/// this barrier it happened in **0 of 8**.
///
/// This grants the kernel and the reaping thread time; it does not grant the
/// evidence anything. An attempt still ends only on a real `populated 0` read
/// followed by two empty `cgroup.procs` reads, and the endpoint is still
/// required. The added cost is bounded by
/// `MAX_CLEANUP_ATTEMPTS * CLEANUP_POLL_BARRIER` = 160 ms per cleanup, and a
/// domain that drains promptly still finishes on its first attempt.
const CLEANUP_POLL_BARRIER: std::time::Duration = std::time::Duration::from_millis(10);
const MAX_CONTROL_WRITE_BYTES: usize = 128;
const MAX_DELEGATION_SCAN_ENTRIES: usize = 128;

/// Immutable identity expected for the retained service parent and delegated
/// cgroup root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DelegationRootExpectation {
    pub(crate) service_parent_identity: CgroupObjectIdentity,
    pub(crate) delegation_identity: CgroupObjectIdentity,
    pub(crate) owner_uid: u32,
    pub(crate) delegation_mode: u32,
}

/// Native-service binding for the one command journal/effect index associated
/// with an authenticated delegated hierarchy.
///
/// This is identity data, not minting authority. The future native Linux
/// service must construct the non-cloneable authority from its retained state
/// capability and this exact binding; the ordinary runner cannot manufacture
/// either capability from a path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceCommandJournalBinding {
    authority_version: u32,
    authenticated_platform_service_digest: Digest,
    service_state_root_identity: CgroupObjectIdentity,
    singleton_journal_root_identity: CgroupObjectIdentity,
    delegation: DelegationRootExpectation,
}

/// External comparison commitment that a future authenticated installer or
/// native-service handoff must supply outside the replaceable service-state
/// root.
///
/// This value is deliberately not authority and has no production constructor
/// in this crate. Keeping it distinct prevents current-process self-observation
/// or a self-consistent state directory from becoming an installation anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxNativeServiceHandoffCommitmentV1 {
    /// The identity that performed the delegation, as the installer committed
    /// it. `observe_anchored_production_plan_facts` requires the live cgroup
    /// parent to be owned by exactly this uid, which is the only place the
    /// delegator can be identified: a plan carries no such field.
    installer_uid: u32,
    journal: LinuxProductionCommandPlanJournalBindingV1,
}

/// Unwired native-service handoff boundary.
///
/// The fields are private and production construction is intentionally absent
/// until packaging/native-service code can supply an independently anchored
/// installation commitment and these already-open descriptors. Tests alone may
/// create this shape from arbitrary directories.
#[derive(Debug)]
struct PendingLinuxNativeServiceAuthenticatedHandoff {
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    service_state_root: Dir,
    service_parent: Dir,
    delegation_name: String,
    external_commitment: LinuxNativeServiceHandoffCommitmentV1,
}

/// Non-cloneable service-state-root capability derived only by consuming the
/// pending authenticated handoff boundary.
///
/// No raw path, [`Dir`], boolean, bootstrap evidence, or journal binding can
/// construct this value in production. Its only current constructor path is
/// test-only because the repository does not yet own an authenticated Linux
/// installer/native-service handoff.
#[derive(Debug)]
struct LinuxNativeServiceStateRootCapability {
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    service_state_root: Dir,
    external_commitment: LinuxNativeServiceHandoffCommitmentV1,
}

#[derive(Debug)]
struct LinuxNativeServiceBootstrapHostRoots {
    service_parent: Dir,
    delegation_name: String,
}

type LinuxNativeServiceStateRootDerivation = (
    LinuxNativeServiceStateRootCapability,
    LinuxNativeServiceBootstrapHostRoots,
);

impl PendingLinuxNativeServiceAuthenticatedHandoff {
    fn into_state_root_capability(
        self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<LinuxNativeServiceStateRootDerivation, CgroupIoFailure> {
        if self.external_commitment.journal != *expected {
            return Err(failure(
                "bind-linux-native-service-handoff",
                EffectCertainty::NotApplied,
                "external native-service handoff commitment differs from the exact plan journal binding",
            ));
        }
        self.service_process_image
            .validate_for_digest(&expected.authenticated_platform_service_digest)?;
        let state_metadata = self.service_state_root.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-linux-native-service-state-root",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_private_directory(&state_metadata, expected.owner_uid)?;
        if cgroup_identity(object_identity(&state_metadata)) != expected.service_state_root_identity
        {
            return Err(failure(
                "bind-linux-native-service-state-root",
                EffectCertainty::NotApplied,
                "service-state root descriptor differs from the externally committed plan identity",
            ));
        }
        validate_component("native-service delegation", &self.delegation_name)?;
        let parent_metadata = self.service_parent.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-linux-native-service-parent",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if !parent_metadata.is_dir()
            || cgroup_identity(object_identity(&parent_metadata))
                != expected.service_parent_identity
            || OsMetadataExt::mode(&parent_metadata) & 0o002 != 0
        {
            return Err(failure(
                "bind-linux-native-service-parent",
                EffectCertainty::NotApplied,
                "service cgroup parent differs from the external commitment or is world-writable",
            ));
        }
        let delegation = self
            .service_parent
            .open_dir_nofollow(&self.delegation_name)
            .map_err(|error| {
                io_failure(
                    "open-linux-native-service-delegation",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        let delegation_metadata = delegation.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-linux-native-service-delegation",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let expectation = DelegationRootExpectation {
            service_parent_identity: expected.service_parent_identity,
            delegation_identity: expected.delegation_identity,
            owner_uid: expected.owner_uid,
            delegation_mode: expected.delegation_mode,
        };
        validate_delegation_metadata(&delegation_metadata, expectation)?;
        require_named_cgroup_identity(
            &self.service_parent,
            &self.delegation_name,
            expected.delegation_identity,
            "bind-linux-native-service-delegation",
        )?;
        drop(delegation);

        Ok((
            LinuxNativeServiceStateRootCapability {
                service_process_image: self.service_process_image,
                service_state_root: self.service_state_root,
                external_commitment: self.external_commitment,
            },
            LinuxNativeServiceBootstrapHostRoots {
                service_parent: self.service_parent,
                delegation_name: self.delegation_name,
            },
        ))
    }

    #[cfg(test)]
    fn from_test_descriptors(
        service_process_image: LinuxNativeServiceProcessImageAuthority,
        service_state_root: Dir,
        service_parent: Dir,
        delegation_name: &str,
        external_commitment: LinuxNativeServiceHandoffCommitmentV1,
    ) -> Self {
        Self {
            service_process_image,
            service_state_root,
            service_parent,
            delegation_name: delegation_name.to_owned(),
            external_commitment,
        }
    }
}

impl LinuxNativeServiceStateRootCapability {
    fn validate_for(
        &self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        if self.external_commitment.journal != *expected {
            return Err(failure(
                "validate-linux-native-service-state-root",
                EffectCertainty::NotApplied,
                "external handoff commitment no longer matches the exact plan journal binding",
            ));
        }
        self.service_process_image
            .validate_for_digest(&expected.authenticated_platform_service_digest)?;
        let metadata = self.service_state_root.dir_metadata().map_err(|error| {
            io_failure(
                "validate-linux-native-service-state-root",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_private_directory(&metadata, expected.owner_uid)?;
        if cgroup_identity(object_identity(&metadata)) != expected.service_state_root_identity {
            return Err(failure(
                "validate-linux-native-service-state-root",
                EffectCertainty::NotApplied,
                "retained service-state root differs from its external handoff commitment",
            ));
        }
        Ok(())
    }
}

/// Non-cloneable ownership of the singleton command journal and global
/// effect-ID history. Production opening consumes an opaque state-root capability
/// from the authenticated service handoff; raw directories cannot supply it.
#[derive(Debug)]
pub(crate) struct LinuxServiceCommandJournalAuthority {
    residual: LinuxServiceJournalAuthenticationResidualV1,
    journal: CanonicalCgroupJournalStore,
}

/// What survives `into_journal`: the plan binding and the authentication proof,
/// and nothing that can act.
///
/// The runtime guard re-validates every command against an authenticated
/// journal authority, but `into_journal` consumes the full authority to yield
/// the bare store the service runs on -- so before this type existed, the only
/// authority alive at that point was a **second** one the bootstrap owned, and
/// the single-use state-root capability mints exactly one.
///
/// Splitting at consumption resolves that without weakening either property.
/// The residual carries the binding and the authentication proof, so
/// `require_exact_plan_binding` is exactly as strong as it was. It holds **no**
/// `CanonicalCgroupJournalStore`, so it cannot journal, cannot open a store, and
/// cannot mint another authority: there is no method on it that reaches one and
/// no field it could be built from. One capability still yields one authority;
/// that authority now yields one store and one proof.
#[derive(Debug)]
pub(crate) struct LinuxServiceJournalAuthenticationResidualV1 {
    binding: LinuxServiceCommandJournalBinding,
    authentication: LinuxServiceCommandJournalAuthentication,
}

impl LinuxServiceJournalAuthenticationResidualV1 {
    /// The store is a parameter because this check is **not**
    /// authentication-only: it cross-checks the committed binding against the
    /// live journal directory's own identities. Dropping that half to make the
    /// residual self-sufficient would weaken exactly what the guard re-verifies
    /// every command, so the residual carries the proof and the caller supplies
    /// the store it is already running on. No second store is opened, and the
    /// residual still cannot reach one on its own.
    fn require_exact_plan_binding(
        &self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_authentication_for(expected)?;
        let exact = self.binding.authority_version == SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION
            && self.binding.authenticated_platform_service_digest
                == expected.authenticated_platform_service_digest
            && self.binding.service_state_root_identity == expected.service_state_root_identity
            && self.binding.singleton_journal_root_identity
                == expected.singleton_journal_root_identity
            && self.binding.delegation.service_parent_identity == expected.service_parent_identity
            && self.binding.delegation.delegation_identity == expected.delegation_identity
            && self.binding.delegation.owner_uid == expected.owner_uid
            && self.binding.delegation.delegation_mode == expected.delegation_mode
            && cgroup_identity(journal.parent_identity) == self.binding.service_state_root_identity
            && cgroup_identity(journal.directory_identity)
                == self.binding.singleton_journal_root_identity
            && journal.expected_owner_uid == expected.owner_uid
            && journal.leaf_name == SERVICE_COMMAND_JOURNAL_DIRECTORY;
        if !exact {
            return Err(failure(
                "bind-complete-command-plan",
                EffectCertainty::NotApplied,
                "canonical plan differs from the authenticated platform service, service state, singleton journal, cgroup parent, delegation, owner, or mode",
            ));
        }
        journal.validate_retained_roots()
    }

    fn validate_authentication_for(
        &self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        match &self.authentication {
            LinuxServiceCommandJournalAuthentication::AuthenticatedHandoff {
                service_process_image,
                external_commitment,
            } => {
                if external_commitment.journal != *expected {
                    return Err(failure(
                        "bind-service-command-journal-authentication",
                        EffectCertainty::NotApplied,
                        "external native-service commitment differs from the exact plan journal binding",
                    ));
                }
                service_process_image
                    .validate_for_digest(&expected.authenticated_platform_service_digest)
            }
            #[cfg(test)]
            LinuxServiceCommandJournalAuthentication::Synthetic => Ok(()),
        }
    }
}

#[derive(Debug)]
enum LinuxServiceCommandJournalAuthentication {
    AuthenticatedHandoff {
        service_process_image: Box<LinuxNativeServiceProcessImageAuthority>,
        external_commitment: LinuxNativeServiceHandoffCommitmentV1,
    },
    #[cfg(test)]
    Synthetic,
}

impl LinuxServiceCommandJournalAuthority {
    fn open_authenticated_service_singleton(
        capability: LinuxNativeServiceStateRootCapability,
        binding: LinuxServiceCommandJournalBinding,
    ) -> Result<Self, CgroupIoFailure> {
        let expected = service_journal_plan_binding(&binding)?;
        capability.validate_for(&expected)?;
        let LinuxNativeServiceStateRootCapability {
            service_process_image,
            service_state_root,
            external_commitment,
        } = capability;
        let journal = CanonicalCgroupJournalStore::open_service_singleton(
            service_state_root,
            binding.service_state_root_identity,
            binding.singleton_journal_root_identity,
            binding.delegation.owner_uid,
        )?;
        let authority = Self {
            residual: LinuxServiceJournalAuthenticationResidualV1 {
                binding,
                authentication: LinuxServiceCommandJournalAuthentication::AuthenticatedHandoff {
                    service_process_image: Box::new(service_process_image),
                    external_commitment,
                },
            },
            journal,
        };
        authority.require_exact_plan_binding(&expected)?;
        Ok(authority)
    }

    #[cfg(test)]
    fn open_test_service_singleton(
        service_state_root: Dir,
        binding: LinuxServiceCommandJournalBinding,
    ) -> Result<Self, CgroupIoFailure> {
        if binding.authority_version != SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION {
            return Err(failure(
                "bind-service-command-journal",
                EffectCertainty::NotApplied,
                "service command-journal authority version is unsupported",
            ));
        }
        let journal = CanonicalCgroupJournalStore::open_service_singleton(
            service_state_root,
            binding.service_state_root_identity,
            binding.singleton_journal_root_identity,
            binding.delegation.owner_uid,
        )?;
        Ok(Self {
            residual: LinuxServiceJournalAuthenticationResidualV1 {
                binding,
                authentication: LinuxServiceCommandJournalAuthentication::Synthetic,
            },
            journal,
        })
    }

    /// Splits this authority at consumption into the bare store the service
    /// runs on and the authentication residual the runtime guard re-validates
    /// against.
    ///
    /// Before the split, the only authority alive after this point was a second
    /// one the bootstrap owned -- and the single-use state-root capability mints
    /// exactly one. One capability still yields one authority; that authority
    /// now yields one store and one proof, and the proof cannot act.
    fn into_journal(
        self,
        expected_delegation: DelegationRootExpectation,
    ) -> Result<
        (
            CanonicalCgroupJournalStore,
            LinuxServiceJournalAuthenticationResidualV1,
        ),
        CgroupIoFailure,
    > {
        let expected = service_journal_plan_binding(&self.residual.binding)?;
        self.validate_authentication_for(&expected)?;
        if self.residual.binding.authority_version != SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION
            || self.residual.binding.delegation != expected_delegation
            || cgroup_identity(self.journal.parent_identity)
                != self.residual.binding.service_state_root_identity
            || cgroup_identity(self.journal.directory_identity)
                != self.residual.binding.singleton_journal_root_identity
            || self.journal.leaf_name != SERVICE_COMMAND_JOURNAL_DIRECTORY
        {
            return Err(failure(
                "bind-service-command-journal",
                EffectCertainty::NotApplied,
                "singleton journal authority differs from the authenticated service, delegation, owner, or retained root",
            ));
        }
        self.journal.validate_retained_roots()?;
        Ok((self.journal, self.residual))
    }

    /// Delegates to the residual, supplying this authority's own store.
    ///
    /// The full authority is the residual plus the store, so nothing here is a
    /// weaker check than before the split -- it is the same check with both
    /// halves in one place.
    fn require_exact_plan_binding(
        &self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        self.residual
            .require_exact_plan_binding(expected, &self.journal)
    }

    fn validate_authentication_for(
        &self,
        expected: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<(), CgroupIoFailure> {
        self.residual.validate_authentication_for(expected)
    }

    fn require_exact_command_plan_artifact(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
        receipt: &LinuxCommandPlanDurableCommitReceipt,
    ) -> Result<(), CgroupIoFailure> {
        self.journal
            .validate_exact_command_plan_artifact(plan, receipt)
    }
}

#[derive(Debug)]
/// The retained host objects one bootstrap authority holds.
///
/// It deliberately does **not** own the journal authority. The single-use
/// state-root capability mints exactly one, and the composition needs that one
/// for journaling the plan -- so the bootstrap borrows it for the duration of
/// `publish` and never afterwards. What the runtime guard needs later is the
/// residual `into_journal` leaves behind, not a second authority.
struct LinuxNativeServiceBootstrapCapabilities {
    /// The service state root, duplicated from the journal store's retained
    /// parent descriptor. It is a plain retained directory -- it cannot
    /// journal, lock, or mint -- and the lifetime lock genuinely needs it to
    /// revalidate the state-root identity after the authority is consumed.
    state_root: Dir,
    state_root_owner_uid: u32,
    service_parent: Dir,
    service_parent_identity: ObjectIdentity,
    delegation_name: String,
    delegation: Dir,
    delegation_identity: ObjectIdentity,
    controllers: File,
    controllers_identity: ObjectIdentity,
    subtree_control: File,
    subtree_control_identity: ObjectIdentity,
    cgroup_procs: File,
    cgroup_procs_identity: ObjectIdentity,
    bubblewrap_parent: Dir,
    bubblewrap_name: String,
    bubblewrap: File,
    bubblewrap_identity: ObjectIdentity,
}

/// Non-cloneable retained authority for one authenticated Linux native-service
/// bootstrap.
///
/// The value retains every descriptor needed to revalidate the fixed service
/// roots, delegated cgroup, controller readbacks, Bubblewrap image, and durable
/// evidence artifact. It has no production constructor and exposes no spawn,
/// exec, release, kill, or cleanup operation. A future constructor must perform
/// the real authenticated host probes before it may create this type.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceBootstrapAuthority {
    evidence: LinuxNativeServiceBootstrapEvidenceV1,
    canonical_evidence: Vec<u8>,
    evidence_artifact: File,
    evidence_artifact_identity: ObjectIdentity,
    capabilities: LinuxNativeServiceBootstrapCapabilities,
}

impl LinuxNativeServiceBootstrapCapabilities {
    fn open_retained(
        journal: &CanonicalCgroupJournalStore,
        service_parent: Dir,
        delegation_name: &str,
        bubblewrap_parent: Dir,
        bubblewrap_name: &str,
    ) -> Result<Self, CgroupIoFailure> {
        validate_component("bootstrap delegation", delegation_name)?;
        validate_component("bootstrap Bubblewrap name", bubblewrap_name)?;
        let service_parent_identity =
            object_identity(&service_parent.dir_metadata().map_err(|error| {
                io_failure(
                    "inspect-bootstrap-service-parent",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?);
        let delegation = service_parent
            .open_dir_nofollow(delegation_name)
            .map_err(|error| {
                io_failure(
                    "open-bootstrap-delegation",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        let delegation_identity = object_identity(&delegation.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-bootstrap-delegation",
                EffectCertainty::NotApplied,
                error,
            )
        })?);
        let (controllers, controllers_identity) = open_retained_bootstrap_file(
            &delegation,
            DelegationFile::Controllers.name(),
            "open-bootstrap-cgroup-controllers",
        )?;
        let (subtree_control, subtree_control_identity) = open_retained_bootstrap_file(
            &delegation,
            DelegationFile::SubtreeControl.name(),
            "open-bootstrap-subtree-control",
        )?;
        let (cgroup_procs, cgroup_procs_identity) = open_retained_bootstrap_file(
            &delegation,
            DelegationFile::Procs.name(),
            "open-bootstrap-cgroup-procs",
        )?;
        let (bubblewrap, bubblewrap_identity) = open_retained_bootstrap_file(
            &bubblewrap_parent,
            bubblewrap_name,
            "open-bootstrap-bubblewrap",
        )?;
        let state_root = journal.parent.try_clone().map_err(|error| {
            io_failure(
                "retain-linux-service-bootstrap-state-root",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        Ok(Self {
            state_root,
            state_root_owner_uid: journal.expected_owner_uid,
            service_parent,
            service_parent_identity,
            delegation_name: delegation_name.to_owned(),
            delegation,
            delegation_identity,
            controllers,
            controllers_identity,
            subtree_control,
            subtree_control_identity,
            cgroup_procs,
            cgroup_procs_identity,
            bubblewrap_parent,
            bubblewrap_name: bubblewrap_name.to_owned(),
            bubblewrap,
            bubblewrap_identity,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear retained-capability audit keeps every bootstrap substitution check visible"
    )]
    fn validate_for(
        &self,
        evidence: &LinuxNativeServiceBootstrapEvidenceV1,
        residual: &LinuxServiceJournalAuthenticationResidualV1,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        validate_service_bootstrap_evidence(evidence)?;
        residual.require_exact_plan_binding(&evidence.plan_binding.journal, journal)?;

        let service_parent_metadata = self.service_parent.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-bootstrap-service-parent",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if object_identity(&service_parent_metadata) != self.service_parent_identity
            || cgroup_identity(self.service_parent_identity)
                != evidence.plan_binding.journal.service_parent_identity
            || !service_parent_metadata.is_dir()
            || OsMetadataExt::mode(&service_parent_metadata) & 0o002 != 0
        {
            return Err(failure(
                "validate-bootstrap-service-parent",
                EffectCertainty::NotApplied,
                "retained service cgroup parent changed, crossed the plan, or became world-writable",
            ));
        }

        let delegation_metadata = self.delegation.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-bootstrap-delegation",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if object_identity(&delegation_metadata) != self.delegation_identity
            || cgroup_identity(self.delegation_identity)
                != evidence.plan_binding.journal.delegation_identity
            || !delegation_metadata.is_dir()
            || OsMetadataExt::uid(&delegation_metadata) != evidence.plan_binding.journal.owner_uid
            || OsMetadataExt::mode(&delegation_metadata) & 0o7777
                != evidence.plan_binding.journal.delegation_mode
            || OsMetadataExt::mode(&delegation_metadata) & 0o002 != 0
        {
            return Err(failure(
                "validate-bootstrap-delegation",
                EffectCertainty::NotApplied,
                "retained delegation identity, owner, or mode differs from the canonical plan",
            ));
        }
        require_named_identity(
            &self.service_parent,
            &self.delegation_name,
            self.delegation_identity,
            "bootstrap-delegation-identity",
        )?;

        validate_retained_bootstrap_readback(
            &self.delegation,
            DelegationFile::Controllers.name(),
            &self.controllers,
            self.controllers_identity,
            evidence.cgroup.controllers_file_identity,
            evidence.cgroup.controllers_readback.as_bytes(),
            "validate-bootstrap-cgroup-controllers",
        )?;
        validate_retained_bootstrap_readback(
            &self.delegation,
            DelegationFile::SubtreeControl.name(),
            &self.subtree_control,
            self.subtree_control_identity,
            evidence.cgroup.subtree_control_file_identity,
            evidence.cgroup.subtree_control_readback.as_bytes(),
            "validate-bootstrap-subtree-control",
        )?;
        validate_retained_bootstrap_readback(
            &self.delegation,
            DelegationFile::Procs.name(),
            &self.cgroup_procs,
            self.cgroup_procs_identity,
            evidence.cgroup.cgroup_procs_file_identity,
            evidence.cgroup.cgroup_procs_readback.as_bytes(),
            "validate-bootstrap-cgroup-procs",
        )?;

        let bubblewrap_metadata = self.bubblewrap.metadata().map_err(|error| {
            io_failure(
                "inspect-bootstrap-bubblewrap",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        let expected_file = &evidence.plan_binding.bubblewrap.file;
        let bubblewrap_mount_id =
            retained_file_mount_id(&self.bubblewrap, "validate-bootstrap-bubblewrap")?;
        if object_identity(&bubblewrap_metadata) != self.bubblewrap_identity
            || self.bubblewrap_identity.device != expected_file.device_id
            || self.bubblewrap_identity.inode != expected_file.inode
            || bubblewrap_mount_id != expected_file.mount_id
            || !bubblewrap_metadata.is_file()
            || OsMetadataExt::mode(&bubblewrap_metadata) != expected_file.mode
            || OsMetadataExt::uid(&bubblewrap_metadata) != expected_file.owner_uid
            || OsMetadataExt::gid(&bubblewrap_metadata) != expected_file.owner_gid
            || PortableMetadataExt::nlink(&bubblewrap_metadata) != expected_file.link_count
            || bubblewrap_metadata.len() != expected_file.byte_length
            || OsMetadataExt::mode(&bubblewrap_metadata) & 0o6000 != 0
            || OsMetadataExt::mode(&bubblewrap_metadata) & 0o111 == 0
        {
            return Err(failure(
                "validate-bootstrap-bubblewrap",
                EffectCertainty::NotApplied,
                "retained Bubblewrap inode metadata differs from the canonical plan",
            ));
        }
        require_named_file_mount_identity(
            &self.bubblewrap_parent,
            &self.bubblewrap_name,
            self.bubblewrap_identity,
            bubblewrap_mount_id,
            "bootstrap-bubblewrap-identity",
        )?;
        let bubblewrap_bytes = read_retained_bootstrap_file(
            &self.bubblewrap,
            usize::try_from(expected_file.byte_length).map_err(|_| {
                failure(
                    "validate-bootstrap-bubblewrap",
                    EffectCertainty::NotApplied,
                    "Bubblewrap byte length cannot be represented on this host",
                )
            })?,
            "readback-bootstrap-bubblewrap",
        )?;
        if Digest::sha256(&bubblewrap_bytes) != expected_file.content_sha256 {
            return Err(failure(
                "validate-bootstrap-bubblewrap",
                EffectCertainty::NotApplied,
                "retained Bubblewrap full-content readback differs from the canonical plan",
            ));
        }
        Ok(())
    }
}
