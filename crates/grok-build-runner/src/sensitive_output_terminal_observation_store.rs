//! Descriptor-relative, publish-once custody for terminal observations.
//!
//! This module stores one immutable sidecar inside the exact private
//! sensitive-output journal namespace for a capture. It does not infer a
//! terminal branch and grants no launch, replay, cleanup, publication,
//! verification, or completion authority.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, File, OpenOptions};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};

use super::sensitive_output_journal::{JOURNAL_PREFIX, LOCK_FILE};
use super::{
    CapabilityCommandOutputStore, CommandOutputStoreError, SensitiveOutputJournalRecoveryV2,
    SensitiveOutputJournalStageV2, create_private_file, io_error, open_private_file,
    sync_directory, validate_named_file_identity, validate_private_directory,
    validate_private_file,
};
use crate::sensitive_output_terminal_observation::{
    MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1,
    SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1, SensitiveOutputTerminalObservationBranchV1,
    SensitiveOutputTerminalObservationV1,
};

const PENDING_OBSERVATION_FILE_V1: &str = ".pending-sensitive-output-terminal-observation.v1.json";

/// Returns whether `name` is one of the two exact sidecar custody names.
///
/// The sensitive-output journal reader uses this only to reserve these fixed
/// names from its record namespace. It does not discover or trust an
/// observation through enumeration.
pub(super) fn is_reserved_entry_name(name: &str) -> bool {
    matches!(
        name,
        SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1 | PENDING_OBSERVATION_FILE_V1
    )
}

pub(super) fn publish_once(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    observation: &SensitiveOutputTerminalObservationV1,
) -> Result<SensitiveOutputTerminalObservationV1, CommandOutputStoreError> {
    let canonical =
        SensitiveOutputTerminalObservationV1::decode_canonical(observation.canonical_bytes())
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if &canonical != observation {
        return Err(manifest(
            "terminal observation differs from its exact canonical decode",
        ));
    }

    let recovery = super::sensitive_output_journal::read_recovery(store, capture_id)?;
    validate_journal_binding(&canonical, &recovery)?;
    let lease = ObservationJournalLease::open(store, capture_id)?;
    lease.publish_or_reopen(&canonical, &recovery)
}

pub(super) fn reopen(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<Option<SensitiveOutputTerminalObservationV1>, CommandOutputStoreError> {
    let recovery = super::sensitive_output_journal::read_recovery(store, capture_id)?;
    let lease = ObservationJournalLease::open(store, capture_id)?;
    lease.reopen_or_roll_forward(&recovery)
}

struct ObservationJournalLease {
    directory: Dir,
    lock: File,
}

impl Drop for ObservationJournalLease {
    fn drop(&mut self) {
        let _ = flock(&self.lock, FlockOperation::Unlock);
    }
}

impl ObservationJournalLease {
    fn open(
        store: &CapabilityCommandOutputStore,
        capture_id: &str,
    ) -> Result<Self, CommandOutputStoreError> {
        store.validate_root()?;
        let journal_id = format!("{JOURNAL_PREFIX}{capture_id}");
        let directory = store
            .inner
            .root
            .open_dir_nofollow(&journal_id)
            .map_err(|error| {
                io_error(
                    "open terminal-observation journal namespace",
                    Path::new(&journal_id),
                    &error,
                )
            })?;
        let identity =
            validate_private_directory(&directory, "terminal-observation journal namespace")?;
        store.validate_named_directory(&journal_id, identity)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let lock = directory
            .open_with(Path::new(LOCK_FILE), &options)
            .map_err(|error| {
                io_error(
                    "open terminal-observation journal lock",
                    Path::new(LOCK_FILE),
                    &error,
                )
            })?;
        validate_private_file(&lock, Path::new(LOCK_FILE), Some(0), 0)?;
        flock(&lock, FlockOperation::LockExclusive).map_err(|error| {
            CommandOutputStoreError::Io {
                operation: "lock terminal-observation journal",
                path: Path::new(LOCK_FILE).to_path_buf(),
                message: error.to_string(),
            }
        })?;
        store.validate_named_directory(&journal_id, identity)?;
        Ok(Self { directory, lock })
    }

    fn reopen_or_roll_forward(
        &self,
        recovery: &SensitiveOutputJournalRecoveryV2,
    ) -> Result<Option<SensitiveOutputTerminalObservationV1>, CommandOutputStoreError> {
        let final_exists = exact_entry_exists(
            &self.directory,
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
        )?;
        let pending_exists = exact_entry_exists(&self.directory, PENDING_OBSERVATION_FILE_V1)?;

        match (final_exists, pending_exists) {
            (false, false) => Ok(None),
            (true, false) => self.read_final(recovery).map(Some),
            (true, true) => {
                let final_observation = self.read_final(recovery)?;
                remove_safe_pending(&self.directory)?;
                Ok(Some(final_observation))
            }
            (false, true) => {
                if let Ok(pending) = read_exact(&self.directory, PENDING_OBSERVATION_FILE_V1) {
                    // A canonical pending value is evidence-bearing. Crossing
                    // is a hard error and must never be erased or retyped.
                    validate_journal_binding(&pending, recovery)?;
                    self.roll_forward_pending(recovery).map(Some)
                } else {
                    // An empty, truncated, or otherwise noncanonical pending
                    // value never became evidence. Remove it only after exact
                    // descriptor, owner, mode, link-count, bound, and named
                    // inode validation; unsafe objects remain hard errors.
                    remove_safe_pending(&self.directory)?;
                    Ok(None)
                }
            }
        }
    }

    fn publish_or_reopen(
        &self,
        observation: &SensitiveOutputTerminalObservationV1,
        recovery: &SensitiveOutputJournalRecoveryV2,
    ) -> Result<SensitiveOutputTerminalObservationV1, CommandOutputStoreError> {
        let final_exists = exact_entry_exists(
            &self.directory,
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
        )?;
        let pending_exists = exact_entry_exists(&self.directory, PENDING_OBSERVATION_FILE_V1)?;

        if final_exists {
            let existing = self.read_final(recovery)?;
            if existing.canonical_bytes() != observation.canonical_bytes() {
                return Err(manifest(
                    "terminal observation is already published with crossed canonical bytes",
                ));
            }
            if pending_exists {
                remove_safe_pending(&self.directory)?;
            }
            return Ok(existing);
        }

        if pending_exists {
            match read_exact(&self.directory, PENDING_OBSERVATION_FILE_V1) {
                Ok(pending) => {
                    validate_journal_binding(&pending, recovery)?;
                    if pending.canonical_bytes() != observation.canonical_bytes() {
                        return Err(manifest(
                            "pending terminal observation has crossed canonical bytes",
                        ));
                    }
                }
                Err(_) => {
                    // Pending is non-authoritative and secret-free. A crash may
                    // leave it empty or truncated before its file sync. Rewrite
                    // only after exact no-follow ownership, mode, link-count,
                    // length, and named-inode validation succeeds.
                    write_pending_exact(&self.directory, observation, true)?;
                }
            }
        } else {
            write_pending_exact(&self.directory, observation, false)?;
        }

        let reopened = self.roll_forward_pending(recovery)?;
        if reopened.canonical_bytes() != observation.canonical_bytes() {
            return Err(manifest(
                "terminal observation exact readback differs after publication",
            ));
        }
        Ok(reopened)
    }

    fn read_final(
        &self,
        recovery: &SensitiveOutputJournalRecoveryV2,
    ) -> Result<SensitiveOutputTerminalObservationV1, CommandOutputStoreError> {
        let observation = read_exact(
            &self.directory,
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
        )?;
        validate_journal_binding(&observation, recovery)?;
        // Seeing a valid final after a crash is enough to complete a possibly
        // interrupted post-rename namespace sync without mutating final bytes.
        sync_directory(&self.directory).map_err(|error| {
            io_error(
                "sync reopened terminal-observation publication",
                Path::new(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1),
                &error,
            )
        })?;
        Ok(observation)
    }

    fn roll_forward_pending(
        &self,
        recovery: &SensitiveOutputJournalRecoveryV2,
    ) -> Result<SensitiveOutputTerminalObservationV1, CommandOutputStoreError> {
        let pending = read_exact(&self.directory, PENDING_OBSERVATION_FILE_V1)?;
        validate_journal_binding(&pending, recovery)?;
        renameat_with(
            &self.directory,
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &self.directory,
            Path::new(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| CommandOutputStoreError::Io {
            operation: "roll forward terminal-observation publication",
            path: Path::new(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1).to_path_buf(),
            message: error.to_string(),
        })?;
        sync_directory(&self.directory).map_err(|error| {
            io_error(
                "sync terminal-observation roll-forward",
                Path::new(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1),
                &error,
            )
        })?;
        let reopened = read_exact(
            &self.directory,
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
        )?;
        if reopened.canonical_bytes() != pending.canonical_bytes() {
            return Err(manifest(
                "terminal observation changed across pending roll-forward",
            ));
        }
        validate_journal_binding(&reopened, recovery)?;
        Ok(reopened)
    }
}

fn write_pending_exact(
    directory: &Dir,
    observation: &SensitiveOutputTerminalObservationV1,
    rewrite_existing: bool,
) -> Result<(), CommandOutputStoreError> {
    let bytes = observation.canonical_bytes();
    let maximum = maximum_observation_bytes_u64()?;
    let exact_length = u64::try_from(bytes.len())
        .map_err(|_| manifest("terminal observation length does not fit u64"))?;
    if exact_length == 0 || exact_length > maximum {
        return Err(manifest("terminal observation is empty or oversized"));
    }

    let mut pending = if rewrite_existing {
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let file = directory
            .open_with(Path::new(PENDING_OBSERVATION_FILE_V1), &options)
            .map_err(|error| {
                io_error(
                    "open pending terminal observation for crash repair",
                    Path::new(PENDING_OBSERVATION_FILE_V1),
                    &error,
                )
            })?;
        let identity =
            validate_private_file(&file, Path::new(PENDING_OBSERVATION_FILE_V1), None, maximum)?;
        validate_named_file_identity(
            directory,
            Path::new(PENDING_OBSERVATION_FILE_V1),
            identity,
            maximum,
        )?;
        file.set_len(0).map_err(|error| {
            io_error(
                "truncate pending terminal observation after crash",
                Path::new(PENDING_OBSERVATION_FILE_V1),
                &error,
            )
        })?;
        file
    } else {
        create_private_file(directory, Path::new(PENDING_OBSERVATION_FILE_V1))?
    };
    pending.seek(SeekFrom::Start(0)).map_err(|error| {
        io_error(
            "seek pending terminal observation",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })?;
    pending.write_all(bytes).map_err(|error| {
        io_error(
            "write pending terminal observation",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })?;
    pending.flush().map_err(|error| {
        io_error(
            "flush pending terminal observation",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })?;
    pending.sync_all().map_err(|error| {
        io_error(
            "sync pending terminal observation",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })?;
    let pending_identity = validate_private_file(
        &pending,
        Path::new(PENDING_OBSERVATION_FILE_V1),
        Some(exact_length),
        maximum,
    )?;
    validate_named_file_identity(
        directory,
        Path::new(PENDING_OBSERVATION_FILE_V1),
        pending_identity,
        maximum,
    )?;
    sync_directory(directory).map_err(|error| {
        io_error(
            "sync pending terminal-observation namespace",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })?;
    Ok(())
}

fn remove_safe_pending(directory: &Dir) -> Result<(), CommandOutputStoreError> {
    let maximum = maximum_observation_bytes_u64()?;
    let pending = open_private_file(directory, Path::new(PENDING_OBSERVATION_FILE_V1))?;
    let identity = validate_private_file(
        &pending,
        Path::new(PENDING_OBSERVATION_FILE_V1),
        None,
        maximum,
    )?;
    validate_named_file_identity(
        directory,
        Path::new(PENDING_OBSERVATION_FILE_V1),
        identity,
        maximum,
    )?;
    drop(pending);
    directory
        .remove_file(PENDING_OBSERVATION_FILE_V1)
        .map_err(|error| {
            io_error(
                "remove superseded pending terminal observation",
                Path::new(PENDING_OBSERVATION_FILE_V1),
                &error,
            )
        })?;
    sync_directory(directory).map_err(|error| {
        io_error(
            "sync superseded pending terminal-observation removal",
            Path::new(PENDING_OBSERVATION_FILE_V1),
            &error,
        )
    })
}

fn exact_entry_exists(directory: &Dir, name: &str) -> Result<bool, CommandOutputStoreError> {
    match directory.symlink_metadata(Path::new(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(
            "inspect exact terminal-observation name",
            Path::new(name),
            &error,
        )),
    }
}

fn read_exact(
    directory: &Dir,
    name: &str,
) -> Result<SensitiveOutputTerminalObservationV1, CommandOutputStoreError> {
    let maximum = maximum_observation_bytes_u64()?;
    let mut file = open_private_file(directory, Path::new(name))?;
    let identity = validate_private_file(&file, Path::new(name), None, maximum)?;
    if identity.length == 0 {
        return Err(manifest("terminal observation is empty"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seek terminal observation", Path::new(name), &error))?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read terminal observation", Path::new(name), &error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| {
        length == 0 || length > maximum || length != identity.length
    }) {
        return Err(manifest(
            "terminal observation changed, is empty, or exceeds its bound",
        ));
    }
    validate_named_file_identity(directory, Path::new(name), identity, maximum)?;
    SensitiveOutputTerminalObservationV1::decode_canonical(&bytes)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))
}

fn validate_journal_binding(
    observation: &SensitiveOutputTerminalObservationV1,
    recovery: &SensitiveOutputJournalRecoveryV2,
) -> Result<(), CommandOutputStoreError> {
    recovery.validate()?;
    let expected_branch = match recovery.stage() {
        SensitiveOutputJournalStageV2::ScannedClean { .. }
        | SensitiveOutputJournalStageV2::Finished { .. }
        | SensitiveOutputJournalStageV2::Published { .. }
        | SensitiveOutputJournalStageV2::TerminalPrepared { .. } => {
            SensitiveOutputTerminalObservationBranchV1::Clean
        }
        SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
        | SensitiveOutputJournalStageV2::CleanupIntended { .. }
        | SensitiveOutputJournalStageV2::Cleaned { .. }
        | SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. } => {
            SensitiveOutputTerminalObservationBranchV1::Rejection
        }
        SensitiveOutputJournalStageV2::IntentBound
        | SensitiveOutputJournalStageV2::AcquiredBound
        | SensitiveOutputJournalStageV2::WriterAttached { .. }
        | SensitiveOutputJournalStageV2::LaunchIntended { .. } => {
            return Err(manifest(
                "terminal observation requires an exact durable generation-five-or-later branch",
            ));
        }
    };
    let acquired = recovery.acquired().ok_or_else(|| {
        manifest("terminal-observation journal branch has no acquired capture binding")
    })?;
    if observation.capture_id() != recovery.capture_id()
        || observation.capture_id() != acquired.capture_id
        || observation.runner_session_id() != acquired.source.runner_session_id
        || observation.effect_id() != acquired.source.effect_id
        || observation.request_digest() != &acquired.source.request_digest
        || observation.branch() != expected_branch
    {
        return Err(manifest(
            "terminal observation crossed its capture, journal request, or closed branch",
        ));
    }
    match expected_branch {
        SensitiveOutputTerminalObservationBranchV1::Clean => {
            let clean = observation.clean_response().ok_or_else(|| {
                manifest("clean terminal observation has no clean-response backing")
            })?;
            if clean.output_artifacts().source != acquired.source {
                return Err(manifest(
                    "clean terminal observation crossed its acquired output source",
                ));
            }
        }
        SensitiveOutputTerminalObservationBranchV1::Rejection => {
            if observation.clean_response().is_some() {
                return Err(manifest(
                    "rejection terminal observation unexpectedly contains clean output",
                ));
            }
        }
    }
    Ok(())
}

fn maximum_observation_bytes_u64() -> Result<u64, CommandOutputStoreError> {
    u64::try_from(MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1)
        .map_err(|_| manifest("terminal-observation byte bound does not fit u64"))
}

fn manifest(message: &str) -> CommandOutputStoreError {
    CommandOutputStoreError::Manifest(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions as StdOpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CommandOutputArtifactSourceV1, CommandOutputCaptureAcquiredV1,
        CommandOutputCaptureIntentV1, CommandTerminationV1, Digest,
        SensitiveOutputDetectionPolicyReferenceV1,
    };

    use super::super::{CapabilityCommandOutputStore, CommandOutputPublisher};
    use super::*;
    use crate::cleanup_proof::{
        CommandDomainCleanupBackend, CommandDomainCleanupBinding,
        ValidatedCommandDomainCleanupProof,
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        parent: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let requested_parent = std::env::temp_dir().join(format!(
                "grok-build-terminal-observation-store-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let requested_state = requested_parent.join("state");
            fs::create_dir(&requested_parent).expect("create fixture parent");
            fs::create_dir(&requested_state).expect("create fixture state");
            let parent = fs::canonicalize(&requested_parent).expect("canonicalize fixture parent");
            let state = parent.join("state");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("set private-state mode");
            Self { parent, state }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    #[derive(Clone, Copy)]
    enum Branch {
        Rejection,
        Clean,
    }

    struct Prepared {
        publisher: CommandOutputPublisher,
        store: CapabilityCommandOutputStore,
        intent: CommandOutputCaptureIntentV1,
        acquired: CommandOutputCaptureAcquiredV1,
        binding: CommandDomainCleanupBinding,
        native_proof: ValidatedCommandDomainCleanupProof,
        fixture: Fixture,
    }

    fn source(label: &str) -> CommandOutputArtifactSourceV1 {
        CommandOutputArtifactSourceV1 {
            sprint_id: format!("sprint-{label}"),
            runner_launch_id: format!("launch-{label}"),
            runner_session_id: format!("session-{label}"),
            effect_id: format!("effect-{label}"),
            request_digest: Digest::sha256(format!("request-{label}").as_bytes()),
        }
    }

    fn prepare(label: &str, branch: Branch) -> Prepared {
        let fixture = Fixture::new();
        let store = CapabilityCommandOutputStore::open(&fixture.state).expect("open store");
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(format!("capture-{label}").as_bytes()).to_string(),
            source(label),
            crate::service::inspect_private_state_digest(&fixture.state)
                .expect("inspect private state"),
            4_096,
            1,
        )
        .expect("construct capture intent");
        let dispatch = super::super::command_output_journal::expected_dispatch_claim_id(
            &intent.source.effect_id,
        );
        let policy = SensitiveOutputDetectionPolicyReferenceV1::core_v1();
        let acquired = store
            .reserve_anchored_capture_v2(&intent, &dispatch, 2, &policy)
            .expect("reserve v2 capture")
            .into_acquired_anchor_for_handoff()
            .expect("close acquired handoff");
        let capture = store
            .reopen_anchored_capture_v2(&acquired, &policy)
            .expect("attach v2 writer");
        let (stdout, stderr, mut publisher) = capture.split();
        #[cfg(target_os = "linux")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::linux();
        #[cfg(target_os = "macos")]
        let core_dump = grok_build_core::SensitiveOutputCoreDumpSuppressionV1::macos();
        let launch_head = publisher
            .record_launch_intended_v2(
                "terminal-observation-store-test/v1",
                br#"{"fixture":"terminal-observation"}"#.to_vec(),
                &core_dump,
            )
            .expect("record v2 launch boundary");
        match branch {
            Branch::Rejection => {
                publisher
                    .record_sensitive_output_detected_v2(&launch_head, &policy)
                    .expect("record rejection branch");
            }
            Branch::Clean => {
                publisher
                    .record_sensitive_output_scanned_clean_v2()
                    .expect("record clean branch");
            }
        }
        drop(stdout);
        drop(stderr);

        let binding = CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            intent.source.effect_id.clone(),
            intent.source.request_digest.clone(),
        )
        .expect("construct command-domain binding");
        let native_proof = crate::cleanup_proof::tests::validated_linux_cleanup_proof_for(&binding);
        Prepared {
            publisher,
            store,
            intent,
            acquired,
            binding,
            native_proof,
            fixture,
        }
    }

    fn rejection_observation(
        prepared: &Prepared,
        code: i32,
    ) -> SensitiveOutputTerminalObservationV1 {
        SensitiveOutputTerminalObservationV1::try_new_rejection(
            prepared.intent.capture_id.clone(),
            CommandTerminationV1::Exited { code },
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &prepared.binding,
            &prepared.native_proof,
        )
        .expect("construct rejection observation")
    }

    fn journal_directory(prepared: &Prepared) -> PathBuf {
        prepared
            .store
            .root()
            .join(format!("{JOURNAL_PREFIX}{}", prepared.intent.capture_id))
    }

    fn create_file(path: &Path, bytes: &[u8], sync_file: bool) {
        let mut options = StdOpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).expect("create injected private file");
        file.write_all(bytes).expect("write injected private file");
        if sync_file {
            file.sync_all().expect("sync injected private file");
        }
    }

    #[test]
    fn publish_once_is_exact_idempotent_and_rejects_crossed_final_bytes() {
        let prepared = prepare("idempotent", Branch::Rejection);
        assert_eq!(
            prepared
                .publisher
                .sensitive_output_acquired_evidence_v1()
                .expect("reopen exact acquired evidence"),
            prepared.acquired
        );
        let observation = rejection_observation(&prepared, 0);
        let first = prepared
            .publisher
            .publish_sensitive_output_terminal_observation_v1(&observation)
            .expect("publish terminal observation");
        let second = prepared
            .publisher
            .publish_sensitive_output_terminal_observation_v1(&observation)
            .expect("same-byte publication is idempotent");
        assert_eq!(first, observation);
        assert_eq!(second, observation);
        assert_eq!(
            prepared
                .store
                .reopen_sensitive_output_terminal_observation_v1(&prepared.intent.capture_id)
                .expect("reopen exact terminal observation"),
            Some(observation.clone())
        );
        let final_path =
            journal_directory(&prepared).join(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1);
        assert_eq!(
            fs::metadata(&final_path)
                .expect("inspect terminal observation")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        let crossed = rejection_observation(&prepared, 7);
        assert!(
            prepared
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&crossed)
                .is_err()
        );
        assert_eq!(
            fs::read(final_path).expect("read immutable final after crossing"),
            observation.canonical_bytes()
        );
    }

    #[test]
    fn every_pre_rename_pending_cut_converges_without_changing_final() {
        enum Cut {
            Created,
            ModeSet,
            PartialWrite,
            CompleteWrite,
            FileSynced,
        }
        for (index, cut) in [
            Cut::Created,
            Cut::ModeSet,
            Cut::PartialWrite,
            Cut::CompleteWrite,
            Cut::FileSynced,
        ]
        .into_iter()
        .enumerate()
        {
            let prepared = prepare(&format!("pending-cut-{index}"), Branch::Rejection);
            let observation = rejection_observation(&prepared, 0);
            let pending_path = journal_directory(&prepared).join(PENDING_OBSERVATION_FILE_V1);
            match cut {
                Cut::Created => create_file(&pending_path, &[], false),
                Cut::ModeSet => {
                    create_file(&pending_path, &[], false);
                    fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o600))
                        .expect("complete injected chmod cut");
                }
                Cut::PartialWrite => create_file(
                    &pending_path,
                    &observation.canonical_bytes()[..observation.canonical_bytes().len() / 2],
                    false,
                ),
                Cut::CompleteWrite => {
                    create_file(&pending_path, observation.canonical_bytes(), false);
                }
                Cut::FileSynced => {
                    create_file(&pending_path, observation.canonical_bytes(), true);
                }
            }
            let published = prepared
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&observation)
                .expect("retry converges exact pending crash cut");
            assert_eq!(published, observation);
            assert!(!pending_path.exists());
            assert_eq!(
                fs::read(
                    journal_directory(&prepared)
                        .join(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1)
                )
                .expect("read converged final"),
                observation.canonical_bytes()
            );
        }
    }

    #[test]
    fn public_reopen_discards_only_safe_noncanonical_pending_then_returns_none() {
        let prepared = prepare("restart-partial-pending", Branch::Rejection);
        let observation = rejection_observation(&prepared, 0);
        let pending_path = journal_directory(&prepared).join(PENDING_OBSERVATION_FILE_V1);
        create_file(&pending_path, b"{\"truncated\":", true);

        assert_eq!(
            prepared
                .store
                .reopen_sensitive_output_terminal_observation_v1(&prepared.intent.capture_id)
                .expect("safe noncanonical pending is not terminal evidence"),
            None
        );
        assert!(!pending_path.exists());

        assert_eq!(
            prepared
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&observation)
                .expect("publication proceeds after typed-Unknown pending cleanup"),
            observation
        );
    }

    #[test]
    fn post_rename_and_final_plus_pending_cuts_converge_by_exact_readback() {
        let prepared = prepare("post-rename", Branch::Rejection);
        let observation = rejection_observation(&prepared, 0);
        let directory = journal_directory(&prepared);
        let pending = directory.join(PENDING_OBSERVATION_FILE_V1);
        let final_path = directory.join(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1);
        create_file(&pending, observation.canonical_bytes(), true);
        fs::rename(&pending, &final_path).expect("inject cut after rename before directory sync");
        assert_eq!(
            prepared
                .store
                .reopen_sensitive_output_terminal_observation_v1(&prepared.intent.capture_id)
                .expect("reopen and sync post-rename cut"),
            Some(observation.clone())
        );

        create_file(&pending, b"truncated non-authoritative duplicate", true);
        assert_eq!(
            prepared
                .store
                .reopen_sensitive_output_terminal_observation_v1(&prepared.intent.capture_id)
                .expect("valid final closes safe duplicate pending"),
            Some(observation.clone())
        );
        assert!(!pending.exists());
        assert_eq!(
            fs::read(final_path).expect("read immutable final"),
            observation.canonical_bytes()
        );
    }

    #[test]
    fn crossed_branch_pending_names_links_and_permissions_fail_closed() {
        let clean = prepare("crossed-clean-branch", Branch::Clean);
        let rejection = rejection_observation(&clean, 0);
        assert!(
            clean
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&rejection)
                .is_err(),
            "a rejection observation cannot enter the clean journal branch"
        );

        let crossed_capture = prepare("crossed-capture", Branch::Rejection);
        assert!(
            crossed_capture
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&rejection)
                .is_err(),
            "an observation cannot cross into another capture namespace"
        );

        let crossed_pending = prepare("crossed-pending", Branch::Rejection);
        let first = rejection_observation(&crossed_pending, 0);
        let second = rejection_observation(&crossed_pending, 9);
        let pending_path = journal_directory(&crossed_pending).join(PENDING_OBSERVATION_FILE_V1);
        create_file(&pending_path, first.canonical_bytes(), true);
        assert!(
            crossed_pending
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&second)
                .is_err()
        );
        assert_eq!(
            fs::read(&pending_path).expect("crossed pending remains immutable"),
            first.canonical_bytes()
        );

        let linked = prepare("pending-symlink", Branch::Rejection);
        let linked_observation = rejection_observation(&linked, 0);
        let linked_directory = journal_directory(&linked);
        let target = linked.fixture.parent.join("sidecar-symlink-target");
        create_file(&target, linked_observation.canonical_bytes(), true);
        symlink(&target, linked_directory.join(PENDING_OBSERVATION_FILE_V1))
            .expect("inject pending symlink");
        assert!(
            linked
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&linked_observation)
                .is_err()
        );

        let permissive = prepare("pending-permissions", Branch::Rejection);
        let permissive_observation = rejection_observation(&permissive, 0);
        let permissive_pending = journal_directory(&permissive).join(PENDING_OBSERVATION_FILE_V1);
        create_file(&permissive_pending, b"partial", true);
        fs::set_permissions(&permissive_pending, fs::Permissions::from_mode(0o644))
            .expect("inject unsafe pending permissions");
        assert!(
            permissive
                .publisher
                .publish_sensitive_output_terminal_observation_v1(&permissive_observation)
                .is_err()
        );
        assert_eq!(
            fs::metadata(&permissive_pending)
                .expect("unsafe pending remains")
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );

        let unexpected = prepare("unexpected-name", Branch::Rejection);
        create_file(
            &journal_directory(&unexpected).join("unexpected-observation-copy.json"),
            b"{}",
            true,
        );
        assert!(
            unexpected
                .store
                .reopen_sensitive_output_terminal_observation_v1(&unexpected.intent.capture_id)
                .is_err(),
            "journal enumeration rejects every undeclared name"
        );
    }
}
