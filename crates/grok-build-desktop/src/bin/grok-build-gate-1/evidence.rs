//! Structural candidate linter and non-passing diagnostic for Hard Gate 1.
//!
//! Candidate linting checks canonical encoding, internal field consistency, the
//! exact claimed platform case set, and output-artifact digests. It does not
//! independently prove the source checkout, native host, `SQLite` authority, or
//! operating-system observations, so it cannot produce promotion success.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{Mode, OFlags, RenameFlags, mkdirat, open, openat, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const GATE_1_EVIDENCE_SCHEMA_VERSION: u32 = 3;
const GATE_1_FIXTURE_ID: &str = "grok-build-gate-1-production-v3";
const RELEASE_TARGET_MANIFEST_VERSION: u32 = 1;
const GATE_1_EXACT_COMMAND: &str = "cargo run --locked -p grok-build-desktop --bin grok-build-gate-1 -- --evidence-directory gate-evidence";
const PINNED_RUSTC_VERSION: &str = "rustc 1.97.0 (2d8144b78 2026-07-07)";
const PINNED_CARGO_VERSION: &str = "cargo 1.97.0 (c980f4866 2026-06-30)";
const BUNDLE_FILE_NAME: &str = "gate-1-evidence-v3.json";
const DIAGNOSTIC_FILE_NAME: &str = "gate-1-not-completed-v3.json";
const DIAGNOSTIC_STDOUT_FILE_NAME: &str = "diagnostic.stdout";
const DIAGNOSTIC_STDERR_FILE_NAME: &str = "diagnostic.stderr";
const MAX_BUNDLE_BYTES: u64 = 1_048_576;
const MAX_ARTIFACT_BYTES: u64 = 8 * 1_048_576;
const MAX_ALL_ARTIFACT_BYTES: u64 = 64 * 1_048_576;
const MAX_SOURCE_FILE_BYTES: u64 = 16 * 1_048_576;
const MAX_GATE_RUNTIME_MILLISECONDS: u64 = 45 * 60 * 1_000;
const SOURCE_TREE_DIGEST_DOMAIN: &str = "grok-build/gate-1/source-tree/v1";
const SOURCE_BINDING_DIGEST_DOMAIN: &str = "grok-build/gate-1/source-binding/v1";
const OUTPUT_ARTIFACT_DIGEST_DOMAIN: &str = "grok-build/gate-1/output-artifact/v1";

const FIXED_SOURCE_BINDINGS: &[(SourceBindingKind, &str, &[&str])] = &[
    (SourceBindingKind::CargoLock, "Cargo.lock", &["Cargo.lock"]),
    (
        SourceBindingKind::DependencyPolicy,
        "CONTRIBUTING.md",
        &["CONTRIBUTING.md"],
    ),
    (
        SourceBindingKind::DefectSeverityPolicy,
        "SECURITY.md",
        &["SECURITY.md"],
    ),
    (
        SourceBindingKind::WalkingSkeletonFixture,
        "fixtures/walking-skeleton",
        &[
            "fixtures/walking-skeleton/AGENTS.md",
            "fixtures/walking-skeleton/Cargo.lock",
            "fixtures/walking-skeleton/Cargo.toml",
            "fixtures/walking-skeleton/README.md",
            "fixtures/walking-skeleton/src/lib.rs",
        ],
    ),
    (
        SourceBindingKind::ReleaseTargetManifest,
        "fixtures/gate-cases",
        &[
            "fixtures/gate-cases/gate-1-v1.json",
            "fixtures/gate-cases/gate-2-v1.json",
            "fixtures/gate-cases/gate-3-v1.json",
        ],
    ),
    (
        SourceBindingKind::GateCaseManifest,
        "crates/grok-build-desktop/src/bin/grok-build-gate-registry/registry.rs",
        &["crates/grok-build-desktop/src/bin/grok-build-gate-registry/registry.rs"],
    ),
    (
        SourceBindingKind::PerformanceResourceBudget,
        "scripts/code-quality-budget.txt",
        &["scripts/code-quality-budget.txt"],
    ),
];

const COMMON_CASE_IDS: &[&str] = &[
    "native_evidence_only_authority_sealed",
    "walking_skeleton_contract_identity",
    "workspace_root_traversal_denied",
    "workspace_sibling_read_denied",
    "workspace_home_read_denied",
    "workspace_symlink_swap_denied",
    "workspace_rename_swap_denied",
    "workspace_hardlink_escape_denied",
    "workspace_git_case_alias_denied",
    "workspace_special_file_denied",
    "workspace_device_access_denied",
    "command_inherited_descriptors_absent",
    "command_credentials_absent",
    "command_local_network_denied",
    "command_external_network_denied",
    "command_nested_namespace_mount_denied",
    "command_detached_descendant_cleanup",
    "cancellation_zero_descendants",
    "stale_content_blocks_application",
    "launch_cleanup_race_single_live_claim",
    "crash_journal_boundaries_no_uncertain_replay",
    "restart_sqlite_reconstruction",
    "target_only_application",
    "rollback_exact_pre_sprint_snapshot",
    "offline_locked_compiler_succeeds",
];

const MACOS_CASE_IDS: &[&str] = &[
    "macos_signed_helper_identity",
    "macos_dedicated_uid",
    "macos_seatbelt_canary",
    "macos_process_tree_cleanup",
];

const LINUX_CASE_IDS: &[&str] = &[
    "linux_bubblewrap_namespace_canary",
    "linux_landlock_canary",
    "linux_seccomp_canary",
    "linux_capabilities_removed",
    "linux_no_new_privs",
    "linux_cgroup_v2_membership",
    "linux_pidfd_process_tree_cleanup",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum Gate1Platform {
    Macos15AppleSilicon,
    Ubuntu2604X8664,
    Fedora44X8664,
}

impl Gate1Platform {
    fn target_triple(self) -> &'static str {
        match self {
            Self::Macos15AppleSilicon => "aarch64-apple-darwin",
            Self::Ubuntu2604X8664 | Self::Fedora44X8664 => "x86_64-unknown-linux-gnu",
        }
    }

    fn validate_operating_system_image(self, image: &str) -> bool {
        match self {
            Self::Macos15AppleSilicon => {
                image
                    .strip_prefix("macOS ")
                    .and_then(|version| version.split('.').next())
                    .and_then(|major| major.parse::<u32>().ok())
                    == Some(15)
            }
            Self::Ubuntu2604X8664 => image == "Ubuntu 26.04",
            Self::Fedora44X8664 => image == "Fedora 44",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseOutcome {
    Passed,
    Failed,
    Skipped,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SprintTerminalState {
    Completed,
    Failed,
    Canceled,
    Blocked,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Gate1EvidenceBundle {
    schema_version: u32,
    fixture_id: String,
    release_target_manifest_version: u32,
    platform: Gate1Platform,
    source: SourceEvidence,
    execution: ExecutionEvidence,
    commitments: FixtureCommitments,
    workflow: WorkflowEvidence,
    cases: Vec<CaseEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceEvidence {
    revision: String,
    git_tree_object: String,
    source_tree_digest: String,
    repository_dirty: bool,
    untracked_source_count: u64,
    bindings: Vec<SourceBinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceBindingKind {
    CargoLock,
    DependencyPolicy,
    DefectSeverityPolicy,
    WalkingSkeletonFixture,
    ReleaseTargetManifest,
    GateCaseManifest,
    PerformanceResourceBudget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    kind: SourceBindingKind,
    relative_path: String,
    files: Vec<SourceFileArtifact>,
    byte_count: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceFileArtifact {
    relative_path: String,
    byte_count: u64,
    sha256: String,
}

#[derive(Serialize)]
struct SourceBindingDigestPreimage<'a> {
    domain: &'static str,
    kind: SourceBindingKind,
    relative_path: &'a str,
    files: &'a [SourceFileArtifact],
    byte_count: u64,
}

#[derive(Serialize)]
struct SourceTreeDigestPreimage<'a> {
    domain: &'static str,
    revision: &'a str,
    git_tree_object: &'a str,
    bindings: &'a [SourceBinding],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionEvidence {
    target_triple: String,
    operating_system_image: String,
    kernel_release: String,
    rustc_version: String,
    cargo_version: String,
    exact_command: String,
    started_unix_milliseconds: u64,
    finished_unix_milliseconds: u64,
    exit_code: i32,
    complete_output: CompleteOutputEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureCommitments {
    #[serde(rename = "workspace_digest")]
    workspace: String,
    #[serde(rename = "policy_digest")]
    policy: String,
    #[serde(rename = "admitted_snapshot_digest")]
    admitted_snapshot: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct ProofClaim(bool);

impl ProofClaim {
    #[cfg(test)]
    const PRESENT: Self = Self(true);

    const fn is_present(self) -> bool {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkflowEvidence {
    contract_version: u32,
    sprint_id: String,
    graph_id: String,
    task_id: String,
    provider_kind: String,
    max_workers: u8,
    task_graph_node_count: u32,
    terminal_state: SprintTerminalState,
    restart_source: String,
    final_report_id: String,
    verified_snapshot_digest: String,
    applied_snapshot_digest: String,
    verification_receipt_digest: String,
    completion_evidence_digest: String,
    final_report_digest: String,
    application_journal_digest: String,
    rollback_journal_digest: String,
    pre_sprint_snapshot_digest: String,
    post_rollback_snapshot_digest: String,
    restart_projection_digest_before: String,
    restart_projection_digest_after: String,
    restart_receipts_digest_before: String,
    restart_receipts_digest_after: String,
    contained_command_count: u32,
    uncertain_effect_replay_count: u32,
    descendants_after_cleanup: u32,
    worker_lease: WorkerLeaseEvidence,
    production_runner_protocol_used: ProofClaim,
    verification_preceded_application: ProofClaim,
    application_target_only: ProofClaim,
    rollback_proven: ProofClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerLeaseEvidence {
    worker_id: String,
    lease_id: String,
    lease_epoch: u64,
    worker_lease_digest: String,
    acquisition_event_id: String,
    acquisition_event_sequence: u64,
    acquired_at_unix_milliseconds: u64,
    ready_to_leased_atomically_committed: ProofClaim,
    atomic_acquisition: WorkerLeaseStageEvidence,
    runner_launch: WorkerLeaseStageEvidence,
    session_registration: WorkerLeaseStageEvidence,
    all_task_effects: WorkerLeaseStageEvidence,
    integration: WorkerLeaseStageEvidence,
    cleanup: WorkerLeaseStageEvidence,
    terminal_release: WorkerLeaseStageEvidence,
    lease_chain_commitment_digest: String,
    active_worker_leases_after_completion: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerLeaseStageEvidence {
    lease_id: String,
    lease_epoch: u64,
    authoritative_observation_digest: String,
}

#[derive(Serialize)]
struct WorkerLeaseChainCommitmentPreimage<'a> {
    domain: &'static str,
    worker_id: &'a str,
    lease_id: &'a str,
    lease_epoch: u64,
    worker_lease_digest: &'a str,
    acquisition_event_id: &'a str,
    acquisition_event_sequence: u64,
    acquired_at_unix_milliseconds: u64,
    ready_to_leased_atomically_committed: ProofClaim,
    atomic_acquisition: &'a WorkerLeaseStageEvidence,
    runner_launch: &'a WorkerLeaseStageEvidence,
    session_registration: &'a WorkerLeaseStageEvidence,
    all_task_effects: &'a WorkerLeaseStageEvidence,
    integration: &'a WorkerLeaseStageEvidence,
    cleanup: &'a WorkerLeaseStageEvidence,
    terminal_release: &'a WorkerLeaseStageEvidence,
    active_worker_leases_after_completion: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseEvidence {
    case_id: String,
    outcome: CaseOutcome,
    started_unix_milliseconds: u64,
    finished_unix_milliseconds: u64,
    exit_code: i32,
    production_policy: bool,
    workspace_digest: String,
    policy_digest: String,
    snapshot_digest: String,
    authoritative_observation_digest: String,
    complete_output: CompleteOutputEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompleteOutputEvidence {
    stdout: OutputArtifact,
    stderr: OutputArtifact,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OutputArtifact {
    result_id: String,
    stream: OutputStream,
    relative_path: String,
    byte_count: u64,
    sha256: String,
    commitment_sha256: String,
}

#[derive(Serialize)]
struct OutputArtifactCommitmentPreimage<'a> {
    domain: &'static str,
    result_id: &'a str,
    stream: OutputStream,
    relative_path: &'a str,
    byte_count: u64,
    sha256: &'a str,
}

#[derive(Debug)]
pub(crate) struct Gate1EvidenceError(String);

impl fmt::Display for Gate1EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Gate1EvidenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct RetainedFile {
    descriptor: File,
    name: PathBuf,
    identity: FileIdentity,
}

impl RetainedFile {
    fn revalidate(&self, parent: &File, description: &str) -> Result<(), Gate1EvidenceError> {
        let descriptor_identity = FileIdentity::from_metadata(
            &self
                .descriptor
                .metadata()
                .map_err(|error| invalid(format!("cannot restat {description}: {error}")))?,
        );
        if descriptor_identity != self.identity {
            return Err(invalid(format!(
                "{description} was truncated or mutated while retained"
            )));
        }
        let named = open_file_at(parent, &self.name, OFlags::RDONLY, description)?;
        let named_identity = FileIdentity::from_metadata(
            &named
                .metadata()
                .map_err(|error| invalid(format!("cannot stat named {description}: {error}")))?,
        );
        if named_identity != self.identity {
            return Err(invalid(format!(
                "{description} was unlinked, replaced, or crossed after validation"
            )));
        }
        Ok(())
    }
}

struct EvidenceDirectory {
    path: PathBuf,
    descriptor: File,
    identity: DirectoryIdentity,
}

impl EvidenceDirectory {
    fn open(path: &Path) -> Result<Self, Gate1EvidenceError> {
        require_plain_directory(path)?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            invalid(format!(
                "cannot retain evidence directory {} without following links: {error}",
                path.display()
            ))
        })?;
        let opened = descriptor.metadata().map_err(|error| {
            invalid(format!(
                "cannot inspect retained evidence directory {}: {error}",
                path.display()
            ))
        })?;
        let named = fs::symlink_metadata(path).map_err(|error| {
            invalid(format!(
                "cannot re-inspect evidence directory {}: {error}",
                path.display()
            ))
        })?;
        let identity = DirectoryIdentity::from_metadata(&opened);
        if !opened.is_dir()
            || !named.file_type().is_dir()
            || identity != DirectoryIdentity::from_metadata(&named)
        {
            return Err(invalid(
                "evidence directory changed while its descriptor was retained",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            descriptor,
            identity,
        })
    }

    fn open_child_directory(&self, name: &str) -> Result<File, Gate1EvidenceError> {
        let child = open_file_at(
            &self.descriptor,
            Path::new(name),
            OFlags::RDONLY | OFlags::DIRECTORY,
            "evidence child directory",
        )?;
        if !child
            .metadata()
            .map_err(|error| invalid(format!("cannot stat evidence child directory: {error}")))?
            .is_dir()
        {
            return Err(invalid(format!(
                "evidence child {name:?} is not a directory"
            )));
        }
        Ok(child)
    }

    fn revalidate_child_directory(
        &self,
        name: &str,
        expected: DirectoryIdentity,
    ) -> Result<(), Gate1EvidenceError> {
        let child = self.open_child_directory(name)?;
        let observed = DirectoryIdentity::from_metadata(&child.metadata().map_err(|error| {
            invalid(format!("cannot restat evidence child directory: {error}"))
        })?);
        if observed != expected {
            return Err(invalid(format!(
                "evidence child directory {name:?} was replaced"
            )));
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<(), Gate1EvidenceError> {
        let opened = self.descriptor.metadata().map_err(|error| {
            invalid(format!(
                "cannot restat retained evidence directory: {error}"
            ))
        })?;
        let named = fs::symlink_metadata(&self.path).map_err(|error| {
            invalid(format!(
                "cannot re-inspect evidence directory {}: {error}",
                self.path.display()
            ))
        })?;
        if self.identity != DirectoryIdentity::from_metadata(&opened)
            || self.identity != DirectoryIdentity::from_metadata(&named)
        {
            return Err(invalid(
                "evidence directory was renamed or replaced during validation",
            ));
        }
        Ok(())
    }
}

/// Lints the self-contained structure of a candidate Gate 1 evidence directory.
///
/// This function does not independently observe the source checkout, native
/// host, `SQLite` ledger, or operating-system containment state. Consequently a
/// successful return is never promotion evidence. The binary's public
/// validation mode always remains `NotCompleted` until those independent
/// observations are wired into the production fixture.
pub(crate) fn lint_gate1_evidence_candidate_structure(
    directory: &Path,
) -> Result<(), Gate1EvidenceError> {
    let retained_directory = EvidenceDirectory::open(directory)?;
    let (encoded, retained_bundle) = read_retained_file(
        &retained_directory.descriptor,
        Path::new(BUNDLE_FILE_NAME),
        MAX_BUNDLE_BYTES,
        false,
        "evidence bundle",
    )?;
    let bundle: Gate1EvidenceBundle = serde_json::from_slice(&encoded)
        .map_err(|error| invalid(format!("cannot decode evidence bundle: {error}")))?;
    let canonical = serde_json::to_vec(&bundle)
        .map_err(|error| invalid(format!("cannot canonicalize evidence bundle: {error}")))?;
    if canonical != encoded {
        return Err(invalid(
            "evidence bundle is not the exact canonical JSON encoding",
        ));
    }

    validate_bundle(&retained_directory, &bundle)?;
    retained_bundle.revalidate(&retained_directory.descriptor, "evidence bundle")?;
    retained_directory.revalidate()
}

/// Writes an explicit non-passing diagnostic into a fresh, empty directory and
/// returns its path.
pub(crate) fn write_not_completed_diagnostic(
    directory: &Path,
) -> Result<PathBuf, Gate1EvidenceError> {
    ensure_plain_directory(directory)?;
    require_empty_evidence_output_directory(directory)?;
    let retained_directory = EvidenceDirectory::open(directory)?;
    secure_evidence_writer_directory(&retained_directory.descriptor)?;
    let source_before = inspect_immutable_source(directory);
    let generated_unix_milliseconds = unix_milliseconds()?;
    let preflight = grok_build_runner::inspect_host_sandbox();
    mkdirat(
        &retained_directory.descriptor,
        Path::new("outputs"),
        Mode::from_raw_mode(0o700),
    )
    .map_err(|error| {
        invalid(format!(
            "cannot create diagnostic output directory: {error}"
        ))
    })?;
    retained_directory
        .descriptor
        .sync_all()
        .map_err(|error| invalid(format!("cannot sync evidence directory: {error}")))?;
    let outputs = retained_directory.open_child_directory("outputs")?;
    let outputs_identity = DirectoryIdentity::from_metadata(
        &outputs
            .metadata()
            .map_err(|error| invalid(format!("cannot stat diagnostic outputs: {error}")))?,
    );
    let destination = directory.join(DIAGNOSTIC_FILE_NAME);
    let terminal_reason = format!(
        "the production native fixture is not connected; diagnostic={}",
        destination.display()
    );
    let terminal_stderr = format!("GATE 1 NOT COMPLETED: {terminal_reason}\n");
    let (complete_output, retained_outputs) = capture_complete_output(
        &outputs,
        "diagnostic",
        DIAGNOSTIC_STDOUT_FILE_NAME,
        std::io::Cursor::new(Vec::<u8>::new()),
        DIAGNOSTIC_STDERR_FILE_NAME,
        std::io::Cursor::new(terminal_stderr.into_bytes()),
    )?;
    let source_after = inspect_immutable_source(directory);
    let source_admission = combine_source_observations(source_before, source_after);
    let diagnostic = NotCompletedDiagnostic {
        schema_version: GATE_1_EVIDENCE_SCHEMA_VERSION,
        status: "not_completed",
        fixture_id: GATE_1_FIXTURE_ID,
        release_target_manifest_version: RELEASE_TARGET_MANIFEST_VERSION,
        generated_unix_milliseconds,
        source_admission,
        detected_target: detected_target(),
        rustc_version: command_version("rustc"),
        cargo_version: command_version("cargo"),
        static_preflight: format!("{preflight:?}; permits_execution=false"),
        complete_output,
        reasons: vec![
            "the production coordinator does not yet drive the complete one-node fixture",
            "no platform service yet supplies read-back-validated native containment evidence",
            "no independent SQLite verifier has bound the exact worker-lease acquisition and lifecycle chain",
            "the required exact case set has not produced a canonical evidence bundle",
        ],
    };
    let bytes = serde_json::to_vec_pretty(&diagnostic)
        .map_err(|error| invalid(format!("cannot encode diagnostic: {error}")))?;
    for retained in &retained_outputs {
        retained.revalidate(&outputs, "diagnostic output artifact")?;
    }
    retained_directory.revalidate_child_directory("outputs", outputs_identity)?;
    let retained_diagnostic = atomic_publish_new(
        &retained_directory.descriptor,
        DIAGNOSTIC_FILE_NAME,
        &bytes,
        "non-completion diagnostic",
    )?;
    retained_diagnostic.revalidate(&retained_directory.descriptor, "non-completion diagnostic")?;
    for retained in &retained_outputs {
        retained.revalidate(&outputs, "diagnostic output artifact")?;
    }
    retained_directory.revalidate_child_directory("outputs", outputs_identity)?;
    retained_directory.revalidate()?;
    Ok(destination)
}

#[derive(Serialize)]
struct NotCompletedDiagnostic<'a> {
    schema_version: u32,
    status: &'a str,
    fixture_id: &'a str,
    release_target_manifest_version: u32,
    generated_unix_milliseconds: u64,
    source_admission: SourceAdmissionDiagnostic,
    detected_target: &'a str,
    rustc_version: Option<String>,
    cargo_version: Option<String>,
    static_preflight: String,
    complete_output: CompleteOutputEvidence,
    reasons: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SourceAdmissionDiagnostic {
    status: &'static str,
    reason: Option<String>,
    evidence: Option<SourceEvidence>,
}

fn validate_bundle(
    directory: &EvidenceDirectory,
    bundle: &Gate1EvidenceBundle,
) -> Result<(), Gate1EvidenceError> {
    if bundle.schema_version != GATE_1_EVIDENCE_SCHEMA_VERSION {
        return Err(invalid(format!(
            "unsupported Gate 1 evidence schema {}; expected {GATE_1_EVIDENCE_SCHEMA_VERSION}",
            bundle.schema_version
        )));
    }
    if bundle.fixture_id != GATE_1_FIXTURE_ID {
        return Err(invalid(
            "fixture identifier is not the production Gate 1 fixture",
        ));
    }
    if bundle.release_target_manifest_version != RELEASE_TARGET_MANIFEST_VERSION {
        return Err(invalid(format!(
            "release-target manifest version {} does not equal exact required version {RELEASE_TARGET_MANIFEST_VERSION}",
            bundle.release_target_manifest_version
        )));
    }

    validate_source(&bundle.source)?;
    validate_execution(bundle.platform, &bundle.execution)?;
    validate_commitments(&bundle.commitments)?;
    validate_workflow(&bundle.workflow, &bundle.commitments, &bundle.execution)?;

    let expected_cases = required_case_ids(bundle.platform);
    if bundle.cases.len() != expected_cases.len() {
        return Err(invalid(format!(
            "case cardinality {} does not equal exact required cardinality {}",
            bundle.cases.len(),
            expected_cases.len()
        )));
    }

    let mut observed_cases = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut total_artifact_bytes = 0_u64;
    let outputs = directory.open_child_directory("outputs")?;
    let output_identity = DirectoryIdentity::from_metadata(
        &outputs
            .metadata()
            .map_err(|error| invalid(format!("cannot stat outputs directory: {error}")))?,
    );
    let mut retained_artifacts = Vec::with_capacity(bundle.cases.len().saturating_mul(2) + 2);
    validate_complete_output(
        &outputs,
        "fixture",
        &bundle.execution.complete_output,
        &mut artifact_paths,
        &mut total_artifact_bytes,
        &mut retained_artifacts,
    )?;

    for case in &bundle.cases {
        validate_case(
            case,
            &bundle.execution,
            &bundle.commitments,
            &expected_cases,
        )?;
        if !observed_cases.insert(case.case_id.as_str()) {
            return Err(invalid(format!(
                "duplicate required case identifier {}",
                case.case_id
            )));
        }
        validate_complete_output(
            &outputs,
            &case.case_id,
            &case.complete_output,
            &mut artifact_paths,
            &mut total_artifact_bytes,
            &mut retained_artifacts,
        )?;
    }

    if observed_cases != expected_cases {
        let missing: Vec<_> = expected_cases
            .difference(&observed_cases)
            .copied()
            .collect();
        let unexpected: Vec<_> = observed_cases
            .difference(&expected_cases)
            .copied()
            .collect();
        return Err(invalid(format!(
            "case set mismatch; missing={missing:?}; unexpected={unexpected:?}"
        )));
    }

    for retained in &retained_artifacts {
        retained.revalidate(&outputs, "complete output artifact")?;
    }
    let outputs_after = directory.open_child_directory("outputs")?;
    let output_identity_after = DirectoryIdentity::from_metadata(
        &outputs_after
            .metadata()
            .map_err(|error| invalid(format!("cannot restat outputs directory: {error}")))?,
    );
    if output_identity_after != output_identity {
        return Err(invalid(
            "outputs directory was replaced while artifacts were validated",
        ));
    }
    Ok(())
}

fn validate_source(source: &SourceEvidence) -> Result<(), Gate1EvidenceError> {
    if source.repository_dirty {
        return Err(invalid("dirty source cannot produce promotion evidence"));
    }
    if !is_git_revision(&source.revision) {
        return Err(invalid(
            "source revision is not a lowercase 40- or 64-hex Git object id",
        ));
    }
    if !is_git_revision(&source.git_tree_object) {
        return Err(invalid(
            "source Git tree is not a lowercase 40- or 64-hex Git object id",
        ));
    }
    if source.untracked_source_count != 0 {
        return Err(invalid(
            "unbound untracked source cannot produce promotion evidence",
        ));
    }
    if let Ok(expected_revision) = std::env::var("GITHUB_SHA")
        && source.revision != expected_revision
    {
        return Err(invalid(
            "source revision differs from the immutable GitHub workflow revision",
        ));
    }
    if source.bindings.len() != FIXED_SOURCE_BINDINGS.len() {
        return Err(invalid(format!(
            "source binding count {} does not equal exact required count {}",
            source.bindings.len(),
            FIXED_SOURCE_BINDINGS.len()
        )));
    }
    for (binding, (expected_kind, expected_root, expected_files)) in
        source.bindings.iter().zip(FIXED_SOURCE_BINDINGS)
    {
        validate_source_binding(binding, *expected_kind, expected_root, expected_files)?;
    }
    require_digest("source tree", &source.source_tree_digest)?;
    let observed = source_tree_digest(source)?;
    if source.source_tree_digest != observed {
        return Err(invalid(
            "source-tree commitment does not bind the exact revision, Git tree, and fixed inputs",
        ));
    }
    Ok(())
}

fn validate_source_binding(
    binding: &SourceBinding,
    expected_kind: SourceBindingKind,
    expected_root: &str,
    expected_files: &[&str],
) -> Result<(), Gate1EvidenceError> {
    if binding.kind != expected_kind || binding.relative_path != expected_root {
        return Err(invalid(format!(
            "source binding {expected_kind:?} is missing, reordered, or crossed"
        )));
    }
    if binding.files.len() != expected_files.len() {
        return Err(invalid(format!(
            "source binding {expected_root} has {} files; expected {}",
            binding.files.len(),
            expected_files.len()
        )));
    }
    let mut observed_bytes = 0_u64;
    for (file, expected_path) in binding.files.iter().zip(expected_files) {
        if file.relative_path != *expected_path {
            return Err(invalid(format!(
                "source binding {expected_root} has a missing, reordered, or crossed file"
            )));
        }
        require_digest("bound source file", &file.sha256)?;
        if file.byte_count > MAX_SOURCE_FILE_BYTES {
            return Err(invalid(format!(
                "bound source file {} exceeds the source-file byte limit",
                file.relative_path
            )));
        }
        observed_bytes = observed_bytes
            .checked_add(file.byte_count)
            .ok_or_else(|| invalid("bound source byte count overflowed"))?;
    }
    if observed_bytes != binding.byte_count {
        return Err(invalid(format!(
            "source binding {expected_root} byte count does not equal its files"
        )));
    }
    require_digest("source binding", &binding.sha256)?;
    if binding.sha256 != source_binding_digest(binding)? {
        return Err(invalid(format!(
            "source binding {expected_root} digest does not bind its exact files"
        )));
    }
    Ok(())
}

fn validate_execution(
    platform: Gate1Platform,
    execution: &ExecutionEvidence,
) -> Result<(), Gate1EvidenceError> {
    if execution.target_triple != platform.target_triple() {
        return Err(invalid(format!(
            "target triple {} does not match exact platform triple {}",
            execution.target_triple,
            platform.target_triple()
        )));
    }
    if !platform.validate_operating_system_image(&execution.operating_system_image) {
        return Err(invalid(format!(
            "operating-system image {:?} does not match the selected exact platform",
            execution.operating_system_image
        )));
    }
    require_bounded_text("kernel release", &execution.kernel_release, 1, 256)?;
    if execution.rustc_version != PINNED_RUSTC_VERSION {
        return Err(invalid(
            "Rust compiler version does not equal the pinned toolchain",
        ));
    }
    if execution.cargo_version != PINNED_CARGO_VERSION {
        return Err(invalid("Cargo version does not equal the pinned toolchain"));
    }
    if execution.exact_command != GATE_1_EXACT_COMMAND {
        return Err(invalid(
            "recorded command is not the exact promotion fixture command",
        ));
    }
    if execution.exit_code != 0 {
        return Err(invalid("promotion fixture did not exit successfully"));
    }
    validate_time_range(
        "fixture",
        execution.started_unix_milliseconds,
        execution.finished_unix_milliseconds,
    )?;
    if execution
        .finished_unix_milliseconds
        .saturating_sub(execution.started_unix_milliseconds)
        > MAX_GATE_RUNTIME_MILLISECONDS
    {
        return Err(invalid(
            "fixture runtime exceeds the 45-minute promotion bound",
        ));
    }
    Ok(())
}

fn validate_commitments(commitments: &FixtureCommitments) -> Result<(), Gate1EvidenceError> {
    require_digest("workspace", &commitments.workspace)?;
    require_digest("policy", &commitments.policy)?;
    require_digest("admitted snapshot", &commitments.admitted_snapshot)
}

fn validate_workflow(
    workflow: &WorkflowEvidence,
    commitments: &FixtureCommitments,
    execution: &ExecutionEvidence,
) -> Result<(), Gate1EvidenceError> {
    validate_workflow_identity(workflow)?;
    validate_workflow_digests(workflow)?;
    validate_workflow_relationships(workflow, commitments)?;
    validate_worker_lease_evidence(workflow, execution)?;
    validate_workflow_effect_summary(workflow)
}

fn validate_workflow_identity(workflow: &WorkflowEvidence) -> Result<(), Gate1EvidenceError> {
    if workflow.contract_version != grok_build_core::CONTRACT_VERSION {
        return Err(invalid(format!(
            "workflow contract version {} does not equal production contract version {}",
            workflow.contract_version,
            grok_build_core::CONTRACT_VERSION
        )));
    }
    require_identifier("sprint id", &workflow.sprint_id)?;
    require_identifier("graph id", &workflow.graph_id)?;
    require_identifier("task id", &workflow.task_id)?;
    require_identifier("final report id", &workflow.final_report_id)?;
    if workflow.provider_kind != "deterministic_fake_model_provider" {
        return Err(invalid(
            "walking skeleton did not use the exact deterministic fake provider",
        ));
    }
    if workflow.max_workers != 1 || workflow.task_graph_node_count != 1 {
        return Err(invalid(
            "walking skeleton is not the exact one-worker, one-node sprint",
        ));
    }
    if workflow.terminal_state != SprintTerminalState::Completed {
        return Err(invalid("only computed Completed can satisfy Gate 1"));
    }
    if workflow.restart_source != "sqlite_readback" {
        return Err(invalid(
            "restart reconstruction was not sourced from SQLite readback",
        ));
    }
    Ok(())
}

fn validate_workflow_digests(workflow: &WorkflowEvidence) -> Result<(), Gate1EvidenceError> {
    for (name, digest) in [
        ("verified snapshot", &workflow.verified_snapshot_digest),
        ("applied snapshot", &workflow.applied_snapshot_digest),
        (
            "verification receipt",
            &workflow.verification_receipt_digest,
        ),
        ("completion evidence", &workflow.completion_evidence_digest),
        ("final report", &workflow.final_report_digest),
        ("application journal", &workflow.application_journal_digest),
        ("rollback journal", &workflow.rollback_journal_digest),
        ("pre-sprint snapshot", &workflow.pre_sprint_snapshot_digest),
        (
            "post-rollback snapshot",
            &workflow.post_rollback_snapshot_digest,
        ),
        (
            "restart projection before",
            &workflow.restart_projection_digest_before,
        ),
        (
            "restart projection after",
            &workflow.restart_projection_digest_after,
        ),
        (
            "restart receipts before",
            &workflow.restart_receipts_digest_before,
        ),
        (
            "restart receipts after",
            &workflow.restart_receipts_digest_after,
        ),
    ] {
        require_digest(name, digest)?;
    }
    Ok(())
}

fn validate_workflow_relationships(
    workflow: &WorkflowEvidence,
    commitments: &FixtureCommitments,
) -> Result<(), Gate1EvidenceError> {
    if workflow.verified_snapshot_digest != workflow.applied_snapshot_digest {
        return Err(invalid(
            "applied snapshot is not the exact verified snapshot",
        ));
    }
    if workflow.pre_sprint_snapshot_digest != commitments.admitted_snapshot {
        return Err(invalid("pre-sprint snapshot is not the admitted snapshot"));
    }
    if workflow.pre_sprint_snapshot_digest != workflow.post_rollback_snapshot_digest {
        return Err(invalid(
            "rollback did not restore the exact pre-sprint snapshot",
        ));
    }
    if workflow.restart_projection_digest_before != workflow.restart_projection_digest_after {
        return Err(invalid(
            "restart reconstructed a different sprint projection",
        ));
    }
    if workflow.restart_receipts_digest_before != workflow.restart_receipts_digest_after {
        return Err(invalid("restart reconstructed different durable receipts"));
    }
    Ok(())
}

fn validate_workflow_effect_summary(workflow: &WorkflowEvidence) -> Result<(), Gate1EvidenceError> {
    if workflow.contained_command_count != 2 {
        return Err(invalid(
            "walking skeleton did not execute its exact two contained commands",
        ));
    }
    if workflow.uncertain_effect_replay_count != 0 {
        return Err(invalid("an uncertain effect was replayed"));
    }
    if workflow.descendants_after_cleanup != 0 {
        return Err(invalid("one or more command descendants survived cleanup"));
    }
    if !workflow.production_runner_protocol_used.is_present()
        || !workflow.verification_preceded_application.is_present()
        || !workflow.application_target_only.is_present()
        || !workflow.rollback_proven.is_present()
    {
        return Err(invalid(
            "workflow omitted a required production runner, verification, application, or rollback proof",
        ));
    }
    Ok(())
}

fn validate_worker_lease_evidence(
    workflow: &WorkflowEvidence,
    execution: &ExecutionEvidence,
) -> Result<(), Gate1EvidenceError> {
    let lease = &workflow.worker_lease;
    grok_build_core::WorkerLease::validate_worker_id(&lease.worker_id).map_err(|error| {
        invalid(format!(
            "worker lease has an invalid worker identity: {error}"
        ))
    })?;
    if lease.lease_epoch == 0 {
        return Err(invalid("worker lease epoch must be greater than zero"));
    }
    let expected_lease_id = grok_build_core::WorkerLease::derive_lease_id(
        &workflow.sprint_id,
        &workflow.task_id,
        &lease.worker_id,
        lease.lease_epoch,
    )
    .map_err(|error| invalid(format!("worker lease identity cannot be derived: {error}")))?;
    if lease.lease_id != expected_lease_id {
        return Err(invalid(
            "worker lease identifier is not the canonical sprint/task/worker/epoch identity",
        ));
    }
    require_digest("worker lease contract", &lease.worker_lease_digest)?;
    require_identifier(
        "worker lease acquisition event id",
        &lease.acquisition_event_id,
    )?;
    if lease.acquisition_event_sequence == 0 {
        return Err(invalid(
            "worker lease acquisition event sequence must be greater than zero",
        ));
    }
    if lease.acquired_at_unix_milliseconds < execution.started_unix_milliseconds
        || lease.acquired_at_unix_milliseconds > execution.finished_unix_milliseconds
    {
        return Err(invalid(
            "worker lease acquisition timestamp lies outside the fixture time range",
        ));
    }
    if !lease.ready_to_leased_atomically_committed.is_present() {
        return Err(invalid(
            "worker lease acquisition did not prove one atomic Ready-to-Leased commit",
        ));
    }

    let mut observation_digests = BTreeSet::new();
    observation_digests.insert(lease.worker_lease_digest.as_str());
    for (stage_name, stage) in worker_lease_stages(lease) {
        if stage.lease_id != lease.lease_id || stage.lease_epoch != lease.lease_epoch {
            return Err(invalid(format!(
                "worker lease {stage_name} evidence is crossed with a different lease ID or epoch"
            )));
        }
        require_digest(
            &format!("worker lease {stage_name} authoritative observation"),
            &stage.authoritative_observation_digest,
        )?;
        if !observation_digests.insert(stage.authoritative_observation_digest.as_str()) {
            return Err(invalid(format!(
                "worker lease {stage_name} evidence substituted or reused another lease-stage observation"
            )));
        }
    }

    if lease.active_worker_leases_after_completion != 0 {
        return Err(invalid(
            "completion retained one or more active worker leases",
        ));
    }
    require_digest(
        "worker lease chain commitment",
        &lease.lease_chain_commitment_digest,
    )?;
    let expected_chain_digest = worker_lease_chain_commitment_digest(lease)?;
    if lease.lease_chain_commitment_digest != expected_chain_digest {
        return Err(invalid(
            "worker lease chain commitment does not bind the exact acquisition, launch, session, effects, integration, cleanup, release, and zero-active-lease evidence",
        ));
    }
    Ok(())
}

fn worker_lease_stages(
    lease: &WorkerLeaseEvidence,
) -> [(&'static str, &WorkerLeaseStageEvidence); 7] {
    [
        ("atomic acquisition", &lease.atomic_acquisition),
        ("runner launch", &lease.runner_launch),
        ("session registration", &lease.session_registration),
        ("all task effects", &lease.all_task_effects),
        ("integration", &lease.integration),
        ("cleanup", &lease.cleanup),
        ("terminal release", &lease.terminal_release),
    ]
}

fn worker_lease_chain_commitment_digest(
    lease: &WorkerLeaseEvidence,
) -> Result<String, Gate1EvidenceError> {
    let preimage = WorkerLeaseChainCommitmentPreimage {
        domain: "grok-build-gate-1-worker-lease-chain-v1",
        worker_id: &lease.worker_id,
        lease_id: &lease.lease_id,
        lease_epoch: lease.lease_epoch,
        worker_lease_digest: &lease.worker_lease_digest,
        acquisition_event_id: &lease.acquisition_event_id,
        acquisition_event_sequence: lease.acquisition_event_sequence,
        acquired_at_unix_milliseconds: lease.acquired_at_unix_milliseconds,
        ready_to_leased_atomically_committed: lease.ready_to_leased_atomically_committed,
        atomic_acquisition: &lease.atomic_acquisition,
        runner_launch: &lease.runner_launch,
        session_registration: &lease.session_registration,
        all_task_effects: &lease.all_task_effects,
        integration: &lease.integration,
        cleanup: &lease.cleanup,
        terminal_release: &lease.terminal_release,
        active_worker_leases_after_completion: lease.active_worker_leases_after_completion,
    };
    let encoded = serde_json::to_vec(&preimage)
        .map_err(|error| invalid(format!("cannot encode worker lease chain: {error}")))?;
    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn validate_case(
    case: &CaseEvidence,
    execution: &ExecutionEvidence,
    commitments: &FixtureCommitments,
    expected_cases: &BTreeSet<&'static str>,
) -> Result<(), Gate1EvidenceError> {
    if !expected_cases.contains(case.case_id.as_str()) {
        return Err(invalid(format!("unexpected Gate 1 case {}", case.case_id)));
    }
    if case.outcome != CaseOutcome::Passed || case.exit_code != 0 {
        return Err(invalid(format!(
            "required case {} was not an unqualified pass",
            case.case_id
        )));
    }
    if !case.production_policy {
        return Err(invalid(format!(
            "required case {} exercised a weaker-than-production policy",
            case.case_id
        )));
    }
    validate_time_range(
        &format!("case {}", case.case_id),
        case.started_unix_milliseconds,
        case.finished_unix_milliseconds,
    )?;
    if case.started_unix_milliseconds < execution.started_unix_milliseconds
        || case.finished_unix_milliseconds > execution.finished_unix_milliseconds
    {
        return Err(invalid(format!(
            "case {} lies outside the fixture time range",
            case.case_id
        )));
    }
    if case.workspace_digest != commitments.workspace
        || case.policy_digest != commitments.policy
        || case.snapshot_digest != commitments.admitted_snapshot
    {
        return Err(invalid(format!(
            "case {} is crossed with different workspace, policy, or snapshot commitments",
            case.case_id
        )));
    }
    require_digest(
        &format!("case {} authoritative observation", case.case_id),
        &case.authoritative_observation_digest,
    )
}

fn validate_complete_output(
    outputs_directory: &File,
    expected_result_id: &str,
    output: &CompleteOutputEvidence,
    artifact_paths: &mut BTreeSet<PathBuf>,
    total_artifact_bytes: &mut u64,
    retained_artifacts: &mut Vec<RetainedFile>,
) -> Result<(), Gate1EvidenceError> {
    validate_artifact(
        outputs_directory,
        expected_result_id,
        OutputStream::Stdout,
        &output.stdout,
        artifact_paths,
        total_artifact_bytes,
        retained_artifacts,
    )?;
    validate_artifact(
        outputs_directory,
        expected_result_id,
        OutputStream::Stderr,
        &output.stderr,
        artifact_paths,
        total_artifact_bytes,
        retained_artifacts,
    )
}

fn validate_artifact(
    outputs_directory: &File,
    expected_result_id: &str,
    expected_stream: OutputStream,
    artifact: &OutputArtifact,
    artifact_paths: &mut BTreeSet<PathBuf>,
    total_artifact_bytes: &mut u64,
    retained_artifacts: &mut Vec<RetainedFile>,
) -> Result<(), Gate1EvidenceError> {
    if artifact.result_id != expected_result_id || artifact.stream != expected_stream {
        return Err(invalid(format!(
            "complete output artifact {} is crossed with a different result or stream",
            artifact.relative_path
        )));
    }
    require_digest("complete output", &artifact.sha256)?;
    require_digest("complete output commitment", &artifact.commitment_sha256)?;
    if artifact.commitment_sha256 != output_artifact_commitment(artifact)? {
        return Err(invalid(format!(
            "complete output artifact {} has a stale or crossed commitment",
            artifact.relative_path
        )));
    }
    if artifact.byte_count > MAX_ARTIFACT_BYTES {
        return Err(invalid(format!(
            "artifact {} exceeds the per-artifact byte bound",
            artifact.relative_path
        )));
    }
    let relative = safe_relative_path(&artifact.relative_path)?;
    if !artifact_paths.insert(relative.clone()) {
        return Err(invalid(format!(
            "complete output artifact {} was reused by multiple results",
            artifact.relative_path
        )));
    }
    *total_artifact_bytes = total_artifact_bytes
        .checked_add(artifact.byte_count)
        .ok_or_else(|| invalid("total artifact byte count overflowed"))?;
    if *total_artifact_bytes > MAX_ALL_ARTIFACT_BYTES {
        return Err(invalid(
            "evidence artifacts exceed the aggregate byte bound",
        ));
    }

    let file_name = relative
        .file_name()
        .ok_or_else(|| invalid("complete output artifact has no file name"))?;
    let (bytes, retained) = read_retained_file(
        outputs_directory,
        Path::new(file_name),
        MAX_ARTIFACT_BYTES,
        true,
        "complete output artifact",
    )?;
    let observed_length = u64::try_from(bytes.len())
        .map_err(|_| invalid("complete output artifact length does not fit u64"))?;
    if observed_length != artifact.byte_count {
        return Err(invalid(format!(
            "complete output artifact {} length {} does not equal committed length {}",
            artifact.relative_path, observed_length, artifact.byte_count
        )));
    }
    let observed_digest = lowercase_hex(&Sha256::digest(&bytes));
    if observed_digest != artifact.sha256 {
        return Err(invalid(format!(
            "complete output artifact {} does not match its SHA-256 commitment",
            artifact.relative_path
        )));
    }
    retained_artifacts.push(retained);
    Ok(())
}

fn required_case_ids(platform: Gate1Platform) -> BTreeSet<&'static str> {
    let platform_cases = match platform {
        Gate1Platform::Macos15AppleSilicon => MACOS_CASE_IDS,
        Gate1Platform::Ubuntu2604X8664 | Gate1Platform::Fedora44X8664 => LINUX_CASE_IDS,
    };
    COMMON_CASE_IDS
        .iter()
        .chain(platform_cases)
        .copied()
        .collect()
}

fn require_plain_directory(directory: &Path) -> Result<(), Gate1EvidenceError> {
    let metadata = fs::symlink_metadata(directory).map_err(|error| {
        invalid(format!(
            "cannot inspect evidence directory {}: {error}",
            directory.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(invalid("evidence directory is not a plain directory"));
    }
    Ok(())
}

fn ensure_plain_directory(directory: &Path) -> Result<(), Gate1EvidenceError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(invalid("evidence output path is not a plain directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(directory).map_err(|create_error| {
                invalid(format!(
                    "cannot create evidence directory {}: {create_error}",
                    directory.display()
                ))
            })?;
            require_plain_directory(directory)
        }
        Err(error) => Err(invalid(format!(
            "cannot inspect evidence output path {}: {error}",
            directory.display()
        ))),
    }
}

fn require_empty_evidence_output_directory(directory: &Path) -> Result<(), Gate1EvidenceError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        invalid(format!(
            "cannot inspect evidence output directory {}: {error}",
            directory.display()
        ))
    })?;
    let mut unexpected_entry = None;
    for entry in entries {
        let entry = entry.map_err(|error| {
            invalid(format!(
                "cannot inspect an entry in evidence output directory {}: {error}",
                directory.display()
            ))
        })?;
        let name = entry.file_name();
        if name == std::ffi::OsStr::new(BUNDLE_FILE_NAME) {
            return Err(invalid(
                "refusing to write a non-completion diagnostic beside an existing Gate 1 evidence bundle",
            ));
        }
        unexpected_entry.get_or_insert(name);
    }
    if let Some(name) = unexpected_entry {
        return Err(invalid(format!(
            "evidence output directory is not fresh and empty; unexpected entry {:?}",
            name.to_string_lossy()
        )));
    }
    Ok(())
}

fn secure_evidence_writer_directory(directory: &File) -> Result<(), Gate1EvidenceError> {
    let before = directory
        .metadata()
        .map_err(|error| invalid(format!("cannot stat evidence writer directory: {error}")))?;
    if before.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid(
            "evidence writer directory is not owned by the current effective user",
        ));
    }
    rustix::fs::fchmod(directory, Mode::from_raw_mode(0o700)).map_err(|error| {
        invalid(format!(
            "cannot make evidence writer directory private: {error}"
        ))
    })?;
    directory
        .sync_all()
        .map_err(|error| invalid(format!("cannot sync private evidence directory: {error}")))?;
    let after = directory
        .metadata()
        .map_err(|error| invalid(format!("cannot restat evidence writer directory: {error}")))?;
    if after.uid() != rustix::process::geteuid().as_raw() || after.mode() & 0o777 != 0o700 {
        return Err(invalid(
            "evidence writer directory did not become current-user-owned mode 0700",
        ));
    }
    Ok(())
}

fn safe_relative_path(encoded: &str) -> Result<PathBuf, Gate1EvidenceError> {
    require_bounded_text("artifact relative path", encoded, 1, 512)?;
    let path = Path::new(encoded);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "artifact path {encoded:?} is not a normal relative path"
        )));
    }
    let mut components = path.components();
    if components.next() != Some(Component::Normal(std::ffi::OsStr::new("outputs")))
        || components.next().is_none()
        || components.next().is_some()
    {
        return Err(invalid(format!(
            "artifact path {encoded:?} is not one direct child of the outputs directory"
        )));
    }
    Ok(path.to_path_buf())
}

fn open_file_at(
    parent: &File,
    name: &Path,
    flags: OFlags,
    description: &str,
) -> Result<File, Gate1EvidenceError> {
    openat(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| {
        invalid(format!(
            "cannot open {description} {} without following links: {error}",
            name.display()
        ))
    })
}

fn validate_plain_single_link_file(
    metadata: &fs::Metadata,
    description: &str,
) -> Result<(), Gate1EvidenceError> {
    if !metadata.is_file() {
        return Err(invalid(format!("{description} is not a regular file")));
    }
    if metadata.nlink() != 1 {
        return Err(invalid(format!("{description} has aliases or hardlinks")));
    }
    Ok(())
}

fn read_bounded(
    reader: &mut File,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>, Gate1EvidenceError> {
    let capacity = usize::try_from(maximum.min(64 * 1_024))
        .map_err(|_| invalid(format!("{description} read capacity does not fit usize")))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let count = reader
            .read(buffer.as_mut())
            .map_err(|error| invalid(format!("cannot read {description}: {error}")))?;
        if count == 0 {
            break;
        }
        let new_length = bytes
            .len()
            .checked_add(count)
            .ok_or_else(|| invalid(format!("{description} length overflowed")))?;
        if u64::try_from(new_length).map_or(true, |length| length > maximum) {
            return Err(invalid(format!(
                "{description} exceeds the {maximum}-byte bound"
            )));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

fn read_retained_file(
    parent: &File,
    name: &Path,
    maximum: u64,
    allow_empty: bool,
    description: &str,
) -> Result<(Vec<u8>, RetainedFile), Gate1EvidenceError> {
    let mut descriptor = open_file_at(parent, name, OFlags::RDONLY, description)?;
    let before_metadata = descriptor
        .metadata()
        .map_err(|error| invalid(format!("cannot stat {description}: {error}")))?;
    validate_plain_single_link_file(&before_metadata, description)?;
    if before_metadata.len() > maximum || (!allow_empty && before_metadata.len() == 0) {
        return Err(invalid(format!(
            "{description} length {} is outside {}..={maximum}",
            before_metadata.len(),
            u8::from(!allow_empty)
        )));
    }
    let identity = FileIdentity::from_metadata(&before_metadata);
    let bytes = read_bounded(&mut descriptor, maximum, description)?;
    let observed_length = u64::try_from(bytes.len())
        .map_err(|_| invalid(format!("{description} length does not fit u64")))?;
    if observed_length != identity.length {
        return Err(invalid(format!(
            "{description} was truncated or extended while read"
        )));
    }
    let after_identity = FileIdentity::from_metadata(
        &descriptor
            .metadata()
            .map_err(|error| invalid(format!("cannot restat {description}: {error}")))?,
    );
    if after_identity != identity {
        return Err(invalid(format!(
            "{description} was replaced or mutated while read"
        )));
    }
    let retained = RetainedFile {
        descriptor,
        name: name.to_path_buf(),
        identity,
    };
    retained.revalidate(parent, description)?;
    Ok((bytes, retained))
}

fn output_artifact_commitment(artifact: &OutputArtifact) -> Result<String, Gate1EvidenceError> {
    let preimage = OutputArtifactCommitmentPreimage {
        domain: OUTPUT_ARTIFACT_DIGEST_DOMAIN,
        result_id: &artifact.result_id,
        stream: artifact.stream,
        relative_path: &artifact.relative_path,
        byte_count: artifact.byte_count,
        sha256: &artifact.sha256,
    };
    let encoded = serde_json::to_vec(&preimage)
        .map_err(|error| invalid(format!("cannot encode output commitment: {error}")))?;
    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn source_binding_digest(binding: &SourceBinding) -> Result<String, Gate1EvidenceError> {
    let preimage = SourceBindingDigestPreimage {
        domain: SOURCE_BINDING_DIGEST_DOMAIN,
        kind: binding.kind,
        relative_path: &binding.relative_path,
        files: &binding.files,
        byte_count: binding.byte_count,
    };
    let encoded = serde_json::to_vec(&preimage)
        .map_err(|error| invalid(format!("cannot encode source binding: {error}")))?;
    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn source_tree_digest(source: &SourceEvidence) -> Result<String, Gate1EvidenceError> {
    let preimage = SourceTreeDigestPreimage {
        domain: SOURCE_TREE_DIGEST_DOMAIN,
        revision: &source.revision,
        git_tree_object: &source.git_tree_object,
        bindings: &source.bindings,
    };
    let encoded = serde_json::to_vec(&preimage)
        .map_err(|error| invalid(format!("cannot encode source tree binding: {error}")))?;
    Ok(lowercase_hex(&Sha256::digest(encoded)))
}

fn capture_complete_output<Stdout, Stderr>(
    outputs_directory: &File,
    result_id: &str,
    stdout_file_name: &str,
    stdout: Stdout,
    stderr_file_name: &str,
    stderr: Stderr,
) -> Result<(CompleteOutputEvidence, Vec<RetainedFile>), Gate1EvidenceError>
where
    Stdout: Read + Send,
    Stderr: Read + Send,
{
    require_identifier("output result", result_id)?;
    let stdout_directory = outputs_directory
        .try_clone()
        .map_err(|error| invalid(format!("cannot clone stdout directory handle: {error}")))?;
    let stderr_directory = outputs_directory
        .try_clone()
        .map_err(|error| invalid(format!("cannot clone stderr directory handle: {error}")))?;
    let ((stdout_artifact, stdout_retained), (stderr_artifact, stderr_retained)) =
        std::thread::scope(|scope| {
            let stdout_handle = scope.spawn(|| {
                capture_output_stream(
                    &stdout_directory,
                    result_id,
                    OutputStream::Stdout,
                    stdout_file_name,
                    stdout,
                )
            });
            let stderr_handle = scope.spawn(|| {
                capture_output_stream(
                    &stderr_directory,
                    result_id,
                    OutputStream::Stderr,
                    stderr_file_name,
                    stderr,
                )
            });
            let stdout_result = stdout_handle
                .join()
                .map_err(|_| invalid("stdout capture thread panicked"))??;
            let stderr_result = stderr_handle
                .join()
                .map_err(|_| invalid("stderr capture thread panicked"))??;
            Ok::<_, Gate1EvidenceError>((stdout_result, stderr_result))
        })?;
    outputs_directory
        .sync_all()
        .map_err(|error| invalid(format!("cannot sync outputs directory: {error}")))?;
    Ok((
        CompleteOutputEvidence {
            stdout: stdout_artifact,
            stderr: stderr_artifact,
        },
        vec![stdout_retained, stderr_retained],
    ))
}

fn capture_output_stream<Reader: Read>(
    outputs_directory: &File,
    result_id: &str,
    stream: OutputStream,
    file_name: &str,
    mut reader: Reader,
) -> Result<(OutputArtifact, RetainedFile), Gate1EvidenceError> {
    let path = Path::new(file_name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(invalid("output capture name must be one normal component"));
    }
    let opened = openat(
        outputs_directory,
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| {
        invalid(format!(
            "cannot exclusively create output {file_name}: {error}"
        ))
    })?;
    let mut writer = File::from(opened);
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    let mut exceeded_byte_bound = false;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let count = reader
            .read(buffer.as_mut())
            .map_err(|error| invalid(format!("cannot read complete {stream:?} stream: {error}")))?;
        if count == 0 {
            break;
        }
        let chunk_length = u64::try_from(count)
            .map_err(|_| invalid("output stream chunk length does not fit u64"))?;
        let Some(next_byte_count) = byte_count.checked_add(chunk_length) else {
            exceeded_byte_bound = true;
            continue;
        };
        byte_count = next_byte_count;
        if exceeded_byte_bound || byte_count > MAX_ARTIFACT_BYTES {
            exceeded_byte_bound = true;
            continue;
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| invalid(format!("cannot write complete {stream:?}: {error}")))?;
        hasher.update(&buffer[..count]);
    }
    if exceeded_byte_bound {
        return Err(invalid(format!(
            "complete {stream:?} stream exceeds the per-artifact byte bound"
        )));
    }
    writer
        .sync_all()
        .map_err(|error| invalid(format!("cannot durably sync complete {stream:?}: {error}")))?;
    let writer_identity = FileIdentity::from_metadata(
        &writer
            .metadata()
            .map_err(|error| invalid(format!("cannot stat complete {stream:?}: {error}")))?,
    );
    validate_plain_single_link_file(
        &writer
            .metadata()
            .map_err(|error| invalid(format!("cannot restat complete {stream:?}: {error}")))?,
        "captured output stream",
    )?;
    if writer_identity.length != byte_count {
        return Err(invalid(format!(
            "complete {stream:?} length changed before durable capture completed"
        )));
    }
    let (readback, retained) = read_retained_file(
        outputs_directory,
        path,
        MAX_ARTIFACT_BYTES,
        true,
        "captured output stream",
    )?;
    if retained.identity != writer_identity
        || u64::try_from(readback.len()).ok() != Some(byte_count)
        || Sha256::digest(&readback).as_slice() != hasher.finalize().as_slice()
    {
        return Err(invalid(format!(
            "complete {stream:?} failed descriptor-identity and digest readback"
        )));
    }
    let mut artifact = OutputArtifact {
        result_id: result_id.to_owned(),
        stream,
        relative_path: format!("outputs/{file_name}"),
        byte_count,
        sha256: lowercase_hex(&Sha256::digest(&readback)),
        commitment_sha256: String::new(),
    };
    artifact.commitment_sha256 = output_artifact_commitment(&artifact)?;
    Ok((artifact, retained))
}

fn inspect_immutable_source(output_directory: &Path) -> Result<SourceEvidence, Gate1EvidenceError> {
    let current = fs::canonicalize(
        std::env::current_dir()
            .map_err(|error| invalid(format!("cannot identify current directory: {error}")))?,
    )
    .map_err(|error| invalid(format!("cannot canonicalize current directory: {error}")))?;
    let repository_text = git_text(&current, &["rev-parse", "--show-toplevel"])
        .map_err(|error| invalid(format!("source has no immutable Git repository: {error}")))?;
    let repository = fs::canonicalize(&repository_text).map_err(|error| {
        invalid(format!(
            "cannot canonicalize Git repository root {repository_text:?}: {error}"
        ))
    })?;
    if repository != current {
        return Err(invalid(format!(
            "Gate 1 must run at the repository root {}; current directory is {}",
            repository.display(),
            current.display()
        )));
    }
    let allowed_output = allowed_output_prefix(&repository, output_directory)?;
    let revision = git_text(&repository, &["rev-parse", "--verify", "HEAD^{commit}"])
        .map_err(|error| invalid(format!("source has no immutable HEAD commit: {error}")))?;
    let git_tree_object = git_text(&repository, &["rev-parse", "--verify", "HEAD^{tree}"])
        .map_err(|error| invalid(format!("source has no immutable HEAD tree: {error}")))?;
    if !is_git_revision(&revision) || !is_git_revision(&git_tree_object) {
        return Err(invalid(
            "Git returned a noncanonical commit or tree object identifier",
        ));
    }
    require_clean_git_status(&repository, allowed_output.as_deref())?;

    let repository_descriptor = open(
        &repository,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| invalid(format!("cannot retain source repository: {error}")))?;
    let repository_identity = DirectoryIdentity::from_metadata(
        &repository_descriptor
            .metadata()
            .map_err(|error| invalid(format!("cannot stat source repository: {error}")))?,
    );
    let mut bindings = Vec::with_capacity(FIXED_SOURCE_BINDINGS.len());
    for (kind, relative_path, file_paths) in FIXED_SOURCE_BINDINGS {
        let mut files = Vec::with_capacity(file_paths.len());
        let mut byte_count = 0_u64;
        for file_path in *file_paths {
            let bytes = read_stable_source_file(
                &repository_descriptor,
                Path::new(file_path),
                MAX_SOURCE_FILE_BYTES,
            )?;
            let file_byte_count = u64::try_from(bytes.len())
                .map_err(|_| invalid("bound source length does not fit u64"))?;
            byte_count = byte_count
                .checked_add(file_byte_count)
                .ok_or_else(|| invalid("source binding byte count overflowed"))?;
            files.push(SourceFileArtifact {
                relative_path: (*file_path).to_owned(),
                byte_count: file_byte_count,
                sha256: lowercase_hex(&Sha256::digest(&bytes)),
            });
        }
        let mut binding = SourceBinding {
            kind: *kind,
            relative_path: (*relative_path).to_owned(),
            files,
            byte_count,
            sha256: String::new(),
        };
        binding.sha256 = source_binding_digest(&binding)?;
        bindings.push(binding);
    }

    let revision_after = git_text(&repository, &["rev-parse", "--verify", "HEAD^{commit}"])?;
    let tree_after = git_text(&repository, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    require_clean_git_status(&repository, allowed_output.as_deref())?;
    let named_repository = fs::symlink_metadata(&repository)
        .map_err(|error| invalid(format!("cannot restat source repository: {error}")))?;
    if revision_after != revision
        || tree_after != git_tree_object
        || repository_identity != DirectoryIdentity::from_metadata(&named_repository)
    {
        return Err(invalid(
            "source revision, tree, or repository identity changed during admission",
        ));
    }
    let mut source = SourceEvidence {
        revision,
        git_tree_object,
        source_tree_digest: String::new(),
        repository_dirty: false,
        untracked_source_count: 0,
        bindings,
    };
    source.source_tree_digest = source_tree_digest(&source)?;
    validate_source(&source)?;
    Ok(source)
}

fn combine_source_observations(
    before: Result<SourceEvidence, Gate1EvidenceError>,
    after: Result<SourceEvidence, Gate1EvidenceError>,
) -> SourceAdmissionDiagnostic {
    match (before, after) {
        (Ok(before), Ok(after)) if before == after => SourceAdmissionDiagnostic {
            status: "admitted",
            reason: None,
            evidence: Some(before),
        },
        (Ok(_), Ok(_)) => SourceAdmissionDiagnostic {
            status: "rejected",
            reason: Some("source binding changed while diagnostic output was captured".into()),
            evidence: None,
        },
        (Err(before), Err(after)) => SourceAdmissionDiagnostic {
            status: "rejected",
            reason: Some(if before.to_string() == after.to_string() {
                before.to_string()
            } else {
                format!("initial observation: {before}; final observation: {after}")
            }),
            evidence: None,
        },
        (Err(error), Ok(_)) => SourceAdmissionDiagnostic {
            status: "rejected",
            reason: Some(format!(
                "initial source observation was rejected even though final observation succeeded: {error}"
            )),
            evidence: None,
        },
        (Ok(_), Err(error)) => SourceAdmissionDiagnostic {
            status: "rejected",
            reason: Some(format!("final source observation was rejected: {error}")),
            evidence: None,
        },
    }
}

fn allowed_output_prefix(
    repository: &Path,
    output_directory: &Path,
) -> Result<Option<String>, Gate1EvidenceError> {
    let absolute_output = fs::canonicalize(output_directory).map_err(|error| {
        invalid(format!(
            "cannot canonicalize evidence output directory {}: {error}",
            output_directory.display()
        ))
    })?;
    let Ok(relative) = absolute_output.strip_prefix(repository) else {
        return Ok(None);
    };
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(
            "evidence output inside the repository must be a normal descendant",
        ));
    }
    let encoded = relative
        .to_str()
        .ok_or_else(|| invalid("evidence output path is not valid UTF-8 for Git status binding"))?;
    Ok(Some(encoded.replace(std::path::MAIN_SEPARATOR, "/")))
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, Gate1EvidenceError> {
    let bytes = git_bytes(repository, arguments)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        invalid(format!(
            "git {} emitted non-UTF-8 output",
            arguments.join(" ")
        ))
    })?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.contains('\n') {
        return Err(invalid(format!(
            "git {} emitted an empty or multiline identity",
            arguments.join(" ")
        )));
    }
    Ok(trimmed.to_owned())
}

fn git_bytes(repository: &Path, arguments: &[&str]) -> Result<Vec<u8>, Gate1EvidenceError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| invalid("PATH is unavailable for the fixed Git source probe"))?;
    let output = Command::new("git")
        .env_clear()
        .env("PATH", path)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| {
            invalid(format!(
                "cannot execute git {}: {error}",
                arguments.join(" ")
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(invalid(format!(
            "git {} failed with {}: {}",
            arguments.join(" "),
            output.status,
            stderr.trim()
        )));
    }
    if !output.stderr.is_empty() {
        return Err(invalid(format!(
            "git {} emitted unexpected stderr: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn require_clean_git_status(
    repository: &Path,
    allowed_output: Option<&str>,
) -> Result<(), Gate1EvidenceError> {
    let status = git_bytes(
        repository,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignored=matching",
        ],
    )?;
    validate_git_status_bytes(&status, allowed_output)
}

fn validate_git_status_bytes(
    status: &[u8],
    allowed_output: Option<&str>,
) -> Result<(), Gate1EvidenceError> {
    let allowed_prefix = allowed_output.map(|path| format!("{path}/").into_bytes());
    for record in status
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if record.len() < 4 || record[2] != b' ' {
            return Err(invalid("git status emitted a malformed porcelain record"));
        }
        let state = &record[..2];
        let path = &record[3..];
        if state == b"??"
            && allowed_prefix
                .as_deref()
                .is_some_and(|prefix| path.starts_with(prefix))
        {
            continue;
        }
        if state == b"!!"
            && (path == b"target/"
                || path.starts_with(b"target/")
                || allowed_prefix
                    .as_deref()
                    .is_some_and(|prefix| path.starts_with(prefix)))
        {
            continue;
        }
        if state == b"??" {
            return Err(invalid(format!(
                "unbound untracked source is present at {:?}",
                String::from_utf8_lossy(path)
            )));
        }
        return Err(invalid(format!(
            "tracked or ignored source is dirty ({}) at {:?}",
            String::from_utf8_lossy(state),
            String::from_utf8_lossy(path)
        )));
    }
    Ok(())
}

fn open_relative_file_nofollow(root: &File, relative: &Path) -> Result<File, Gate1EvidenceError> {
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(invalid(format!(
            "bound source path {} is not a normal relative path",
            relative.display()
        )));
    }
    let components: Vec<_> = relative.components().collect();
    let (file_component, directory_components) = components
        .split_last()
        .ok_or_else(|| invalid("bound source path is empty"))?;
    let mut parent = root
        .try_clone()
        .map_err(|error| invalid(format!("cannot clone source root handle: {error}")))?;
    for component in directory_components {
        let Component::Normal(name) = component else {
            return Err(invalid("bound source path contains a non-normal component"));
        };
        parent = open_file_at(
            &parent,
            Path::new(name),
            OFlags::RDONLY | OFlags::DIRECTORY,
            "bound source directory",
        )?;
    }
    let Component::Normal(file_name) = file_component else {
        return Err(invalid("bound source file name is not normal"));
    };
    open_file_at(
        &parent,
        Path::new(file_name),
        OFlags::RDONLY,
        "bound source file",
    )
}

fn read_stable_source_file(
    root: &File,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, Gate1EvidenceError> {
    let mut descriptor = open_relative_file_nofollow(root, relative)?;
    let before = descriptor
        .metadata()
        .map_err(|error| invalid(format!("cannot stat bound source file: {error}")))?;
    validate_plain_single_link_file(&before, "bound source file")?;
    if before.len() > maximum {
        return Err(invalid(format!(
            "bound source file {} exceeds the {maximum}-byte limit",
            relative.display()
        )));
    }
    let identity = FileIdentity::from_metadata(&before);
    let bytes = read_bounded(&mut descriptor, maximum, "bound source file")?;
    if u64::try_from(bytes.len()).ok() != Some(identity.length)
        || FileIdentity::from_metadata(
            &descriptor
                .metadata()
                .map_err(|error| invalid(format!("cannot restat bound source file: {error}")))?,
        ) != identity
    {
        return Err(invalid(format!(
            "bound source file {} was truncated or mutated while read",
            relative.display()
        )));
    }
    let named = open_relative_file_nofollow(root, relative)?;
    if FileIdentity::from_metadata(
        &named
            .metadata()
            .map_err(|error| invalid(format!("cannot stat rebound source file: {error}")))?,
    ) != identity
    {
        return Err(invalid(format!(
            "bound source file {} was replaced while read",
            relative.display()
        )));
    }
    Ok(bytes)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn require_digest(name: &str, digest: &str) -> Result<(), Gate1EvidenceError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{name} digest is not lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn is_git_revision(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_identifier(name: &str, value: &str) -> Result<(), Gate1EvidenceError> {
    require_bounded_text(name, value, 1, 128)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid(format!("{name} contains a non-canonical byte")));
    }
    Ok(())
}

fn require_bounded_text(
    name: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), Gate1EvidenceError> {
    if !(minimum..=maximum).contains(&value.len()) || value.contains('\0') {
        return Err(invalid(format!(
            "{name} length is outside {minimum}..={maximum} or contains NUL"
        )));
    }
    Ok(())
}

fn validate_time_range(name: &str, started: u64, finished: u64) -> Result<(), Gate1EvidenceError> {
    if started == 0 || finished < started {
        return Err(invalid(format!("{name} has an invalid time range")));
    }
    Ok(())
}

fn unix_milliseconds() -> Result<u64, Gate1EvidenceError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| invalid(format!("system clock precedes Unix epoch: {error}")))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| invalid("current Unix time does not fit in u64 milliseconds"))
}

fn command_version(program: &str) -> Option<String> {
    let output = Command::new(program).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|version| version.trim().to_owned())
}

const fn detected_target() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "aarch64-apple-darwin";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return "x86_64-unknown-linux-gnu";
    }
    #[allow(unreachable_code)]
    "unsupported"
}

fn atomic_publish_new(
    directory: &File,
    destination_name: &str,
    bytes: &[u8],
    description: &str,
) -> Result<RetainedFile, Gate1EvidenceError> {
    let temporary_name = format!(
        ".gate-1-diagnostic-{}-{}.tmp",
        std::process::id(),
        unix_milliseconds()?
    );
    let opened = openat(
        directory,
        Path::new(&temporary_name),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|error| invalid(format!("cannot create temporary {description}: {error}")))?;
    let mut file = File::from(opened);
    file.write_all(bytes)
        .map_err(|error| invalid(format!("cannot write temporary {description}: {error}")))?;
    file.sync_all()
        .map_err(|error| invalid(format!("cannot sync temporary {description}: {error}")))?;
    validate_plain_single_link_file(
        &file
            .metadata()
            .map_err(|error| invalid(format!("cannot restat temporary {description}: {error}")))?,
        description,
    )?;
    renameat_with(
        directory,
        Path::new(&temporary_name),
        directory,
        Path::new(destination_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        invalid(format!(
            "cannot publish {description} without replacing an existing name: {error}"
        ))
    })?;
    let written_identity = FileIdentity::from_metadata(
        &file
            .metadata()
            .map_err(|error| invalid(format!("cannot stat published {description}: {error}")))?,
    );
    directory
        .sync_all()
        .map_err(|error| invalid(format!("cannot sync published {description}: {error}")))?;
    let (readback, retained) = read_retained_file(
        directory,
        Path::new(destination_name),
        MAX_BUNDLE_BYTES,
        false,
        description,
    )?;
    if retained.identity != written_identity || readback != bytes {
        return Err(invalid(format!(
            "published {description} does not identify the exact durable bytes"
        )));
    }
    Ok(retained)
}

fn invalid(message: impl Into<String>) -> Gate1EvidenceError {
    Gate1EvidenceError(message.into())
}

#[cfg(test)]
mod tests;
