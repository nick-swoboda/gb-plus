//! Retained-descriptor Linux cgroup-v2 host effects and durable journal I/O.
//!
//! The journal implementation is portable across the runner's Unix targets so
//! its canonical-byte and crash-recovery rules can be tested without a live
//! delegated cgroup.  Kernel cgroup operations are compiled only on Linux.
//! They never reopen an ambient delegation path: the caller supplies the
//! authenticated parent capability and every operation is relative to the
//! retained delegation or retained leaf descriptor.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::Permissions;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use grok_build_core::Digest;

use crate::durable_directory::sync_directory_entries as sync_directory;

#[cfg(target_os = "linux")]
use crate::linux_command_plan::LinuxAnchoredServiceFactsV1;
#[cfg(test)]
use crate::linux_command_plan::LinuxBootstrapFileIdentityV1;
#[cfg(any(test, target_os = "linux"))]
use crate::linux_command_plan::LinuxServiceSetupEndpointRoleV1;
use crate::linux_command_plan::{
    ADMITTED_BUBBLEWRAP_IMAGE_V1, LinuxFileImmutabilityV1, LinuxLandlockBootstrapBindingV1,
    LinuxLandlockRulesetV1, LinuxProductionCommandPlanJournalBindingV1,
    LinuxProductionCommandPlanServiceBootstrapBindingV1, LinuxSeccompBootstrapBindingV1,
    LinuxSeccompFilterV1, LinuxServiceChildDescriptorBindingV1, LinuxServiceChildDescriptorKindV1,
    LinuxServiceChildDescriptorSourceV1, LinuxServiceChildImageMountBindingV1,
    LinuxServiceChildLaunchClosureBindingV1, LinuxServiceExecutableBindingV1,
    LinuxServiceExecutableRoleV1, LinuxServiceLaunchImageBindingV1,
    LinuxServiceSetupDescriptorAccessV1, LinuxServiceSetupDescriptorBindingV1,
    LinuxServiceSetupEndpointBindingV1, LinuxServiceSetupEndpointKindV1,
    LinuxServiceSetupEndpointSourceV1, LinuxServiceSetupObjectIdentityV1,
    ValidatedLinuxProductionCommandPlanV1,
};
#[cfg(target_os = "linux")]
use crate::linux_command_plan::{
    AuthenticatedSetupChannelV1, CGROUP_DELEGATION_ROOT_OBJECT_ID, EXECUTION_ROOT_OBJECT_ID,
    GIT_MASK_DESTINATION_COMPONENT, GIT_MASK_OBJECT_ID, LINUX_ELF_HEADER_PREFIX_BYTES,
    LINUX_GIT_MASK_DIRECTORY_MODE, LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE,
    LinuxAuditArchitectureV1, LinuxAuthenticatedFileV1, LinuxCommandDomainControlFileV1,
    LinuxGitMaskEmptyDirectoryObservationV1, LinuxGitMaskMountBindingV1, LinuxGitMaskV1,
    LinuxHostMachineArchitectureFactV1, LinuxKernelObjectObservationV1,
    LinuxLandlockDenialWitnessV1, LinuxLandlockScopeV1, LinuxMandatoryControlArtefactsV1,
    LinuxObservedCommandDomainControlFileV1, LinuxPerCommandDirectoryObservationsV1,
    LinuxPerCommandRetainedDirectoriesV1, LinuxPreparedCommandDomainLeafObservationV1,
    LinuxProductionCommandPlanError, LinuxRetainedObjectIdentityV1, LinuxRetainedObjectKindV1,
    LinuxSeccompDefaultActionV1, LinuxSeccompDeniedSyscallV1, LinuxSeccompNamespaceActionV1,
    LinuxSeccompNamespaceFilterV1, LinuxSetupChannelStatementV1,
    MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES, OUTPUT_SPOOL_OBJECT_ID,
    PER_COMMAND_RETAINED_ROOT_OBJECT_ID, PRIVATE_TEMP_OBJECT_ID, SERVICE_CGROUP_PARENT_OBJECT_ID,
    SERVICE_IMAGE_OBJECT_ID, SERVICE_STATE_ROOT_OBJECT_ID, SINGLETON_JOURNAL_ROOT_OBJECT_ID,
    WORKSPACE_ROOT_OBJECT_ID,
};
#[cfg(target_os = "linux")]
use crate::linux_containment::HeldReleaseIo;
use crate::linux_containment::{
    CGROUP2_SUPER_MAGIC, CgroupIo, CgroupIoFailure, CgroupObjectIdentity, DelegationFile,
    DelegationLockToken, DelegationObservation, DelegationProbeEvidence, DomainController,
    DomainJournalRecord, DomainJournalState, EffectCertainty, LeafFile, LeafWriteFile,
    MAX_CGROUP_EVENTS_BYTES, MAX_CGROUP_PROCS_BYTES, NewLeafObservation, PrepareDomainRequest,
    StagedLauncherIdentity, StagedLauncherObservation, StagedLauncherRecoveryState,
    parse_cgroup_events, parse_cgroup_procs,
};
#[cfg(target_os = "linux")]
use crate::linux_held_launcher::{
    AuthenticatedContainmentRequest, AuthenticatedExecutableDescriptor, AuthenticatedLandlockScope,
    AuthenticatedReleaseDescriptor, DescriptorIdentity as LauncherDescriptorIdentity,
    HeldExecCertainty, HeldExecFailure, HeldExecObservation, HeldExecReleaseBinding,
    HeldExecRequest, HeldLauncherEffectCertainty, HeldLauncherExpectation, HeldLauncherFailure,
    HeldLauncherRegistry, LinuxProcfs, PlannedHeldExec, PreparedHeldExec,
    ProcessRecoveryObservation,
};

const JOURNAL_FORMAT_VERSION: u32 = 2;
const SERVICE_COMMAND_JOURNAL_AUTHORITY_VERSION: u32 = 2;
const SERVICE_COMMAND_JOURNAL_DIRECTORY: &str = "linux-command-journal-v2";
const LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY_V1: &str = "linux-command-journal-v1";
const JOURNAL_RECORD_COMMITMENT_DOMAIN: &[u8] = b"grok-build/linux-command-journal-record/v2\0";
const JOURNAL_LOCK_NAME: &str = "writer.lock";
const JOURNAL_FINAL_PREFIX: &str = "record-";
const JOURNAL_FINAL_SUFFIX: &str = ".json";
const JOURNAL_TEMP_SUFFIX: &str = ".tmp";
const COMMAND_PLAN_PREFIX: &str = "command-plan-";
const COMMAND_PLAN_SUFFIX: &str = ".json";
const JOURNAL_SEQUENCE_DIGITS: usize = 20;
const MAX_CANONICAL_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_GENERATIONS: u64 = 4_096;
const MAX_JOURNAL_DIRECTORY_ENTRIES: usize = 8_195;
const PROBE_JOURNAL_DIRECTORY: &str = "preflight-probe";
/// Format version 2 adds the canary episode: see [`ProbeEpisodeKind`].
///
/// Version 1 records are refused, never migrated, by a message naming both
/// versions. The refusal is only reachable because [`decode_probe_envelope`]
/// peeks this field before the typed decode; `ProbeJournalRecord` denies
/// unknown fields, so serde would otherwise refuse a version-1 record first
/// for a missing `episode_kind` and tell an operator nothing about which
/// version they are holding. Version-first decoding preserves the exact
/// compatibility refusal.
const PROBE_JOURNAL_FORMAT_VERSION: u32 = 2;
const PROBE_JOURNAL_FINAL_PREFIX: &str = "probe-";
const MAX_PROBE_JOURNAL_GENERATIONS: u64 = 4_096;
const MAX_PROBE_JOURNAL_DIRECTORY_ENTRIES: usize = 4_097;
const SERVICE_BOOTSTRAP_FORMAT_VERSION: u32 = 1;
const SERVICE_BOOTSTRAP_AUTHORITY_VERSION: u32 = 1;
const SERVICE_BOOTSTRAP_FINAL_NAME: &str = "linux-native-service-bootstrap-v1.json";
const SERVICE_BOOTSTRAP_TEMP_NAME: &str = "linux-native-service-bootstrap-v1.tmp";
const SERVICE_LIFETIME_LOCK_NAME: &str = "linux-native-service-lifetime-v1.lock";
const SERVICE_BOOTSTRAP_COMMITMENT_DOMAIN: &[u8] =
    b"grok-build/linux-native-service-bootstrap/v1\0";
const CGROUP_BOOTSTRAP_PROBE_CONTRACT: &[u8] = b"grok-build/linux-cgroup-bootstrap-probe/v2\0";
const BUBBLEWRAP_BOOTSTRAP_PROBE_CONTRACT: &[u8] =
    b"grok-build/linux-bubblewrap-bootstrap-probe/v1\0";
const MAX_SERVICE_BOOTSTRAP_BYTES: usize = 128 * 1_024;
const MAX_BOOTSTRAP_READBACK_BYTES: usize = 4_096;
const MAX_NATIVE_SERVICE_EXECUTABLE_BYTES: usize = 128 * 1_024 * 1_024;
const MAX_EXECUTABLE_SNAPSHOT_SET_BYTES: u64 = 512 * 1_024 * 1_024;
// One admitted binding retains its root, every named parent, its source file,
// and its sealed memfd. Keep the complete steady-state set at or below half of
// the common 1,024-descriptor soft limit so traversal clones, journals, procfs,
// setup channels, stdio, and the service itself retain deterministic headroom.
const MAX_EXECUTABLE_SNAPSHOT_RETAINED_DESCRIPTORS: usize = 512;
const MAX_EXECUTABLE_PROVENANCE_PATH_BYTES: usize = 4_096;
const MAX_EXECUTABLE_PROVENANCE_COMPONENT_BYTES: usize = 255;
// Linux F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE |
// F_SEAL_FUTURE_WRITE | F_SEAL_EXEC. Keep this equal to the held-launcher
// protocol requirement; admission must fail rather than downgrade the set.
const REQUIRED_EXECUTABLE_SNAPSHOT_SEAL_BITS: u32 = 0x0000_003f;
const TMPFS_SUPER_MAGIC: u64 = 0x0102_1994;
const SETUP_DESCRIPTOR_FILE_TYPE_MASK: u32 = 0o170_000;
const SETUP_DESCRIPTOR_PIPE_MODE: u32 = 0o010_000;
const MAX_SETUP_DESCRIPTOR_REQUEST_BYTES: usize = 1_024 * 1_024;
// Linux UAPI `STATX_MNT_ID_UNIQUE`, available since Linux 6.8. rustix 1.1.4
// deliberately preserves externally defined `StatxFlags` bits and exposes the
// returned `stx_mask` and `stx_mnt_id`, but does not yet name this flag.
const STATX_MNT_ID_UNIQUE_BITS: u32 = 0x0000_4000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

/// Portable projection of the kernel facts required for one immutable
/// command-image snapshot. Production Linux code is the only source of these
/// observations; the portable representation keeps fail-closed crossing tests
/// runnable on every development host.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent kernel facts stay explicit so no single summary boolean can mint snapshot authority"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxSealedExecutableSnapshotObservation {
    identity: ObjectIdentity,
    regular_file: bool,
    memfd_filesystem: bool,
    owner_is_effective_identity: bool,
    link_count: u64,
    permissions: u32,
    byte_length: u64,
    content_sha256: Digest,
    seal_bits: u32,
    close_on_exec: bool,
}

fn validate_sealed_executable_snapshot_observation(
    expected: &LinuxServiceExecutableBindingV1,
    observed: &LinuxSealedExecutableSnapshotObservation,
) -> Result<(), CgroupIoFailure> {
    validate_sealed_executable_snapshot_observation_fields(
        &expected.object_id,
        expected.file.byte_length,
        &expected.file.content_sha256,
        observed,
    )
}

fn validate_launch_image_snapshot_observation(
    expected: &LinuxServiceLaunchImageBindingV1,
    observed: &LinuxSealedExecutableSnapshotObservation,
) -> Result<(), CgroupIoFailure> {
    validate_sealed_executable_snapshot_observation_fields(
        &expected.object_id,
        expected.byte_length,
        &expected.content_sha256,
        observed,
    )
}

fn validate_sealed_executable_snapshot_observation_fields(
    object_id: &str,
    expected_byte_length: u64,
    expected_content_sha256: &Digest,
    observed: &LinuxSealedExecutableSnapshotObservation,
) -> Result<(), CgroupIoFailure> {
    if observed.identity.device == 0
        || observed.identity.inode == 0
        || !observed.regular_file
        || !observed.memfd_filesystem
        || !observed.owner_is_effective_identity
        || observed.link_count != 0
        || observed.permissions != 0o500
        || observed.byte_length != expected_byte_length
        || &observed.content_sha256 != expected_content_sha256
        || observed.seal_bits != REQUIRED_EXECUTABLE_SNAPSHOT_SEAL_BITS
        || !observed.close_on_exec
    {
        return Err(failure(
            "validate-native-service-sealed-executable",
            EffectCertainty::NotApplied,
            format!(
                "sealed snapshot for executable object {object_id} differs in identity, memfd origin, ownership, mode, length, content, seals, or descriptor flags"
            ),
        ));
    }
    Ok(())
}

fn validate_executable_snapshot_set_preflight(
    expected: &[LinuxServiceExecutableBindingV1],
) -> Result<(), CgroupIoFailure> {
    let total = expected.iter().try_fold(0_u64, |total, binding| {
        total.checked_add(binding.file.byte_length).ok_or_else(|| {
            failure(
                "bind-native-service-sealed-executable-set",
                EffectCertainty::NotApplied,
                "aggregate executable snapshot length overflowed",
            )
        })
    })?;
    if total == 0 || total > MAX_EXECUTABLE_SNAPSHOT_SET_BYTES {
        return Err(failure(
            "bind-native-service-sealed-executable-set",
            EffectCertainty::NotApplied,
            "aggregate executable snapshot length is zero or exceeds 512 MiB",
        ));
    }

    let retained_descriptors = expected.iter().try_fold(0_usize, |total, binding| {
        let component_count = executable_provenance_component_count(
            &binding.resolved_path,
            "preflight-native-service-executable-set",
        )?;
        let parent_count = component_count.checked_sub(1).ok_or_else(|| {
            failure(
                "preflight-native-service-executable-set",
                EffectCertainty::NotApplied,
                "planned executable path has no final component",
            )
        })?;
        // One independently retained `/` root, every parent below it, the
        // source file, and the immutable memfd snapshot.
        let binding_descriptors = parent_count.checked_add(3).ok_or_else(|| {
            failure(
                "preflight-native-service-executable-set",
                EffectCertainty::NotApplied,
                "executable snapshot descriptor budget overflowed",
            )
        })?;
        total.checked_add(binding_descriptors).ok_or_else(|| {
            failure(
                "preflight-native-service-executable-set",
                EffectCertainty::NotApplied,
                "executable snapshot descriptor budget overflowed",
            )
        })
    })?;
    if retained_descriptors > MAX_EXECUTABLE_SNAPSHOT_RETAINED_DESCRIPTORS {
        return Err(failure(
            "preflight-native-service-executable-set",
            EffectCertainty::NotApplied,
            format!(
                "complete executable snapshot set requires {retained_descriptors} retained descriptors, exceeding the hard limit of {MAX_EXECUTABLE_SNAPSHOT_RETAINED_DESCRIPTORS}"
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    format_version: u32,
    sequence: u64,
    plan_digest: Option<Digest>,
    record_commitment_sha256: String,
    record: DomainJournalRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxCgroupBootstrapReadbackV1 {
    delegation_component: String,
    controllers_file_identity: CgroupObjectIdentity,
    subtree_control_file_identity: CgroupObjectIdentity,
    cgroup_procs_file_identity: CgroupObjectIdentity,
    controllers_readback: String,
    controllers_readback_sha256: Digest,
    subtree_control_readback: String,
    subtree_control_readback_sha256: Digest,
    cgroup_procs_readback: String,
    cgroup_procs_readback_sha256: Digest,
    active_probe_contract_digest: Digest,
    active_probe_result_digest: Digest,
    active_probe_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxBubblewrapBootstrapProbeV1 {
    version_stdout: String,
    version_stdout_sha256: Digest,
    active_probe_contract_digest: Digest,
    active_probe_result_digest: Digest,
    active_probe_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxLandlockBootstrapProbeV1 {
    observed_kernel_abi: u32,
    active_probe_result_digest: Digest,
    full_enforcement_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxSeccompBootstrapProbeV1 {
    active_probe_result_digest: Digest,
    no_new_privileges_read_back: bool,
    forbidden_syscall_killed: bool,
}

/// Canonical service-bootstrap evidence retained independently of a command
/// episode. Only an authenticated native service may eventually produce this
/// evidence; the current crate has no production constructor for it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxNativeServiceBootstrapEvidenceV1 {
    authority_version: u32,
    plan_binding: LinuxProductionCommandPlanServiceBootstrapBindingV1,
    cgroup: LinuxCgroupBootstrapReadbackV1,
    bubblewrap: LinuxBubblewrapBootstrapProbeV1,
    landlock: LinuxLandlockBootstrapProbeV1,
    seccomp: LinuxSeccompBootstrapProbeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LinuxNativeServiceBootstrapEnvelopeV1 {
    format_version: u32,
    evidence_commitment_sha256: Digest,
    evidence: LinuxNativeServiceBootstrapEvidenceV1,
}

#[derive(Clone, Debug)]
struct StoredJournal {
    envelope: JournalEnvelope,
    canonical_bytes: Vec<u8>,
    identity: ObjectIdentity,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CommandEffectIdentity {
    effect_id: String,
}

impl CommandEffectIdentity {
    fn from_record(record: &DomainJournalRecord) -> Self {
        Self {
            effect_id: record.effect_id.clone(),
        }
    }

    fn from_request(request: &PrepareDomainRequest) -> Self {
        Self {
            effect_id: request.effect_id.clone(),
        }
    }
}

/// Exact mechanics projection authenticated by complete command history.
///
/// Production v2 obtains this only from a durably retained canonical plan;
/// low-level journal codec tests still derive it from `CreateIntended`. The
/// runner session remains inside the native-launch identity, so a later attempt
/// cannot cross one effect into another session or request.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CommandEffectCommitment {
    plan_digest: Option<Digest>,
    native_launch: crate::linux_containment::LinuxNativeLaunchIdentity,
    grant_hash: String,
    policy_hash: String,
    command_hash: String,
    request_digest: String,
}

impl CommandEffectCommitment {
    fn from_record(record: &DomainJournalRecord, plan_digest: Option<Digest>) -> Self {
        Self {
            plan_digest,
            native_launch: record.native_launch.clone(),
            grant_hash: record.grant_hash.clone(),
            policy_hash: record.policy_hash.clone(),
            command_hash: record.command_hash.clone(),
            request_digest: record.request_digest.clone(),
        }
    }

    fn from_request(request: &PrepareDomainRequest, plan_digest: Option<Digest>) -> Self {
        Self {
            plan_digest,
            native_launch: request.native_launch.clone(),
            grant_hash: request.grant_hash.clone(),
            policy_hash: request.policy_hash.clone(),
            command_hash: request.command_hash.clone(),
            request_digest: request.request_digest.clone(),
        }
    }
}

type CommandEffectHistory = BTreeMap<CommandEffectIdentity, CommandEffectCommitment>;

#[derive(Debug)]
struct StoredCommandPlan {
    plan: ValidatedLinuxProductionCommandPlanV1,
    identity: ObjectIdentity,
}

/// Type-state proof that one exact canonical command plan has been published,
/// directory-synced, and read back from the retained singleton journal.
///
/// Its fields and constructor are private to this module. Consequently a
/// validated plan alone cannot expose the reduced mechanics request.
#[derive(Debug)]
pub(crate) struct LinuxCommandPlanDurableCommitReceipt {
    plan_digest: Digest,
    effect_id: String,
    canonical_bytes_sha256: Digest,
    artifact_identity: ObjectIdentity,
}

impl LinuxCommandPlanDurableCommitReceipt {
    fn from_verified_plan(
        plan: &ValidatedLinuxProductionCommandPlanV1,
        artifact_identity: ObjectIdentity,
    ) -> Self {
        Self {
            plan_digest: plan.plan_digest().clone(),
            effect_id: plan.effect_id().to_owned(),
            canonical_bytes_sha256: Digest::sha256(plan.canonical_bytes()),
            artifact_identity,
        }
    }

    pub(crate) fn authenticates(&self, plan: &ValidatedLinuxProductionCommandPlanV1) -> bool {
        self.plan_digest == *plan.plan_digest()
            && self.effect_id == plan.effect_id()
            && self.canonical_bytes_sha256 == Digest::sha256(plan.canonical_bytes())
    }
}

#[derive(Debug)]
struct DurableCommandPlanCommit {
    receipt: LinuxCommandPlanDurableCommitReceipt,
    request: PrepareDomainRequest,
}

type StoredCommandPlans = BTreeMap<String, StoredCommandPlan>;

#[derive(Debug, Default)]
struct JournalScan {
    latest: Option<StoredJournal>,
    command_effect_history: CommandEffectHistory,
    command_plans: StoredCommandPlans,
    created_command_effects: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProbeJournalState {
    CreateIntended,
    OwnershipUnknown,
    IdentityObserved,
    ShapeObserved,
    ConfigureIntended,
    Configured,
    KillIntended,
    EmptyProven,
    RemoveIntended,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeDefaultShape {
    owner_uid: u32,
    mode: u32,
    events: Vec<u8>,
    procs: Vec<u8>,
    pids_max: Vec<u8>,
    memory_max: Vec<u8>,
    memory_swap_max: Vec<u8>,
    memory_oom_group: Vec<u8>,
    children: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeJournalRecord {
    state: ProbeJournalState,
    episode_kind: ProbeEpisodeKind,
    probe_name: String,
    expected_delegation_identity: CgroupObjectIdentity,
    expected_owner_uid: u32,
    observed_identity: Option<CgroupObjectIdentity>,
    identity_authoritative: bool,
    initial_shape: Option<ProbeDefaultShape>,
    configured_and_read_back: bool,
    stable_empty_proven: bool,
    canary: Option<CanaryEpisodeEvidenceV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeJournalEnvelope {
    format_version: u32,
    sequence: u64,
    record_sha256: String,
    record: ProbeJournalRecord,
}

/// The one field a restart reads before it commits to a record shape.
///
/// Deliberately not `deny_unknown_fields`: its whole job is to decode a
/// document this build does not otherwise understand well enough to name.
#[derive(Clone, Copy, Debug, Deserialize)]
struct ProbeJournalFormatVersionPeek {
    format_version: u32,
}

#[derive(Clone, Debug)]
struct StoredProbeJournal {
    envelope: ProbeJournalEnvelope,
    canonical_bytes: Vec<u8>,
    identity: ObjectIdentity,
}

impl ProbeDefaultShape {
    fn validate_bounded(&self) -> Result<(), CgroupIoFailure> {
        let fields = [
            self.events.as_slice(),
            self.procs.as_slice(),
            self.pids_max.as_slice(),
            self.memory_max.as_slice(),
            self.memory_swap_max.as_slice(),
            self.memory_oom_group.as_slice(),
        ];
        if self.mode & !0o7777 != 0
            || fields.iter().any(|bytes| bytes.len() > 256)
            || self.children.len() > 16
            || self
                .children
                .iter()
                .any(|name| validate_component("probe child", name).is_err())
        {
            return Err(failure(
                "validate-probe-journal-record",
                EffectCertainty::NotApplied,
                "probe default-shape evidence exceeded canonical bounds",
            ));
        }
        Ok(())
    }
}

impl ProbeJournalRecord {
    fn validate(&self) -> Result<(), CgroupIoFailure> {
        validate_probe_name(&self.probe_name)?;
        if self.expected_delegation_identity.device == 0
            || self.expected_delegation_identity.inode == 0
            || self
                .observed_identity
                .is_some_and(|identity| identity.device == 0 || identity.inode == 0)
            || self.initial_shape.is_some() && self.observed_identity.is_none()
            || self.identity_authoritative && self.observed_identity.is_none()
            || self.configured_and_read_back && !self.identity_authoritative
            || self.stable_empty_proven && !self.identity_authoritative
        {
            return Err(failure(
                "validate-probe-journal-record",
                EffectCertainty::NotApplied,
                "probe identity, shape, or monotonic evidence binding is invalid",
            ));
        }
        if let Some(shape) = &self.initial_shape {
            shape.validate_bounded()?;
        }
        self.validate_episode_kind_and_claim()?;
        let valid_state_shape = match self.state {
            ProbeJournalState::CreateIntended => {
                self.observed_identity.is_none()
                    && !self.identity_authoritative
                    && !self.configured_and_read_back
                    && !self.stable_empty_proven
            }
            ProbeJournalState::OwnershipUnknown => {
                self.observed_identity.is_some()
                    && !self.identity_authoritative
                    && !self.configured_and_read_back
                    && !self.stable_empty_proven
            }
            ProbeJournalState::IdentityObserved => {
                self.identity_authoritative
                    && self.initial_shape.is_none()
                    && !self.configured_and_read_back
                    && !self.stable_empty_proven
            }
            ProbeJournalState::ShapeObserved | ProbeJournalState::ConfigureIntended => {
                self.identity_authoritative
                    && self.initial_shape.is_some()
                    && !self.configured_and_read_back
                    && !self.stable_empty_proven
            }
            ProbeJournalState::Configured => {
                self.identity_authoritative
                    && self.initial_shape.is_some()
                    && self.configured_and_read_back
                    && !self.stable_empty_proven
            }
            ProbeJournalState::KillIntended => {
                self.identity_authoritative
                    && self.initial_shape.is_some()
                    && !self.stable_empty_proven
            }
            ProbeJournalState::EmptyProven | ProbeJournalState::RemoveIntended => {
                self.identity_authoritative
                    && self.initial_shape.is_some()
                    && self.stable_empty_proven
            }
            ProbeJournalState::Removed => true,
        };
        if !valid_state_shape {
            return Err(failure(
                "validate-probe-journal-record",
                EffectCertainty::NotApplied,
                "probe journal state has impossible evidence fields",
            ));
        }
        Ok(())
    }
}

/// An immutable-generation journal rooted in retained directory capabilities.
///
/// Each transition is written to a private temporary file, synced, and
/// published with `RENAME_NOREPLACE`.  Recovery accepts only a contiguous
/// sequence of canonical records.  A deterministic temporary generation is
/// either published or compared byte-for-byte with its already-published
/// final generation.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestCommandPlanFailurePoint {
    Write,
    Publish,
    DirectorySync,
    Readback,
}

#[derive(Debug)]
pub(crate) struct CanonicalCgroupJournalStore {
    parent: Dir,
    parent_identity: ObjectIdentity,
    leaf_name: String,
    directory: Dir,
    directory_identity: ObjectIdentity,
    probe_directory: Dir,
    probe_directory_identity: ObjectIdentity,
    expected_owner_uid: u32,
    writer_lock: File,
    writer_lock_identity: ObjectIdentity,
    held_token: Option<u64>,
    next_token: u64,
    latest: Option<StoredJournal>,
    command_effect_history: CommandEffectHistory,
    command_plans: StoredCommandPlans,
    created_command_effects: BTreeSet<String>,
    require_complete_command_plan: bool,
    active_plan_digest: Option<Digest>,
    #[cfg(test)]
    next_command_plan_failure: Option<TestCommandPlanFailurePoint>,
    latest_probe: Option<StoredProbeJournal>,
    pending_directory_sync: bool,
}

impl CanonicalCgroupJournalStore {
    /// Test-only low-level constructor for corrupt-layout and journal codec
    /// fixtures. Production code cannot select a journal root through this
    /// interface.
    #[cfg(test)]
    fn open_test_retained(
        parent: Dir,
        leaf_name: &str,
        expected_owner_uid: u32,
    ) -> Result<Self, CgroupIoFailure> {
        Self::open_retained_inner(parent, leaf_name, expected_owner_uid, false)
    }

    /// Opens the one fixed journal child of an authenticated service-state
    /// capability and verifies both pre-authorized kernel identities.
    fn open_service_singleton(
        parent: Dir,
        expected_parent_identity: CgroupObjectIdentity,
        expected_journal_identity: CgroupObjectIdentity,
        expected_owner_uid: u32,
    ) -> Result<Self, CgroupIoFailure> {
        match parent.symlink_metadata(LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY_V1) {
            Ok(_) => {
                return Err(failure(
                    "classify-service-command-journal",
                    EffectCertainty::NotApplied,
                    "legacy linux-command-journal-v1 is present; v1 is explicitly unsupported and is never interpreted as v2",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_failure(
                    "classify-service-command-journal",
                    EffectCertainty::NotApplied,
                    error,
                ));
            }
        }
        let store = Self::open_retained_inner(
            parent,
            SERVICE_COMMAND_JOURNAL_DIRECTORY,
            expected_owner_uid,
            true,
        )?;
        if cgroup_identity(store.parent_identity) != expected_parent_identity
            || cgroup_identity(store.directory_identity) != expected_journal_identity
        {
            return Err(failure(
                "bind-service-command-journal",
                EffectCertainty::NotApplied,
                "service-state or singleton command-journal identity differs from native service authority",
            ));
        }
        Ok(store)
    }

    fn open_retained_inner(
        parent: Dir,
        leaf_name: &str,
        expected_owner_uid: u32,
        require_complete_command_plan: bool,
    ) -> Result<Self, CgroupIoFailure> {
        validate_component("journal directory", leaf_name)?;
        let parent_metadata = parent.dir_metadata().map_err(|error| {
            io_failure("inspect-journal-parent", EffectCertainty::NotApplied, error)
        })?;
        validate_private_directory(&parent_metadata, expected_owner_uid)?;
        let parent_identity = object_identity(&parent_metadata);
        let directory = parent
            .open_dir_nofollow(leaf_name)
            .map_err(|error| io_failure("open-journal-root", EffectCertainty::NotApplied, error))?;
        let directory_metadata = directory.dir_metadata().map_err(|error| {
            io_failure("inspect-journal-root", EffectCertainty::NotApplied, error)
        })?;
        validate_private_directory(&directory_metadata, expected_owner_uid)?;
        let directory_identity = object_identity(&directory_metadata);
        require_named_identity(
            &parent,
            leaf_name,
            directory_identity,
            "journal-root-identity",
        )?;

        let (probe_directory, probe_directory_identity) = open_or_create_private_directory(
            &directory,
            PROBE_JOURNAL_DIRECTORY,
            expected_owner_uid,
        )?;

        let (writer_lock, writer_lock_identity) =
            open_or_create_private_lock(&directory, expected_owner_uid)?;
        let store = Self {
            parent,
            parent_identity,
            leaf_name: leaf_name.to_owned(),
            directory,
            directory_identity,
            probe_directory,
            probe_directory_identity,
            expected_owner_uid,
            writer_lock,
            writer_lock_identity,
            held_token: None,
            next_token: 1,
            latest: None,
            command_effect_history: BTreeMap::new(),
            command_plans: BTreeMap::new(),
            created_command_effects: BTreeSet::new(),
            require_complete_command_plan,
            active_plan_digest: None,
            #[cfg(test)]
            next_command_plan_failure: None,
            latest_probe: None,
            pending_directory_sync: false,
        };
        store.validate_retained_roots()?;
        Ok(store)
    }

    pub(crate) fn acquire_lock(&mut self) -> Result<u64, CgroupIoFailure> {
        self.validate_retained_roots()?;
        if self.held_token.is_some() {
            return Err(failure(
                "lock-journal",
                EffectCertainty::NotApplied,
                "this host already owns the journal lock",
            ));
        }
        let next_token = self.next_token.checked_add(1).ok_or_else(|| {
            failure(
                "lock-journal",
                EffectCertainty::NotApplied,
                "lock token space exhausted",
            )
        })?;
        flock(&self.writer_lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io_failure("lock-journal", EffectCertainty::NotApplied, error))?;
        let token = self.next_token;
        self.next_token = next_token;
        if let Err(error) = self.refresh_locked() {
            let _ = flock(&self.writer_lock, FlockOperation::Unlock);
            return Err(error);
        }
        self.held_token = Some(token);
        Ok(token)
    }

    pub(crate) fn release_lock(&mut self, token: u64) -> Result<(), CgroupIoFailure> {
        self.require_token(token)?;
        if self.pending_directory_sync {
            return Err(failure(
                "unlock-journal",
                EffectCertainty::NotApplied,
                "journal directory has an unsynchronized publication",
            ));
        }
        flock(&self.writer_lock, FlockOperation::Unlock)
            .map_err(|error| io_failure("unlock-journal", EffectCertainty::Ambiguous, error))?;
        self.held_token = None;
        Ok(())
    }

    /// Reads the latest canonical record under a short exclusive snapshot
    /// lock.  Reconciliation later reacquires and revalidates the cgroup root;
    /// a concurrent new generation therefore fails closed rather than replaying.
    pub(crate) fn read_latest(&mut self) -> Result<Option<DomainJournalRecord>, CgroupIoFailure> {
        if self.held_token.is_some() {
            self.refresh_locked()?;
            return Ok(self
                .latest
                .as_ref()
                .map(|stored| stored.envelope.record.clone()));
        }
        flock(&self.writer_lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| io_failure("lock-journal-read", EffectCertainty::NotApplied, error))?;
        let result = self.refresh_locked().map(|()| {
            self.latest
                .as_ref()
                .map(|stored| stored.envelope.record.clone())
        });
        let unlock = flock(&self.writer_lock, FlockOperation::Unlock)
            .map_err(|error| io_failure("unlock-journal-read", EffectCertainty::Ambiguous, error));
        match (result, unlock) {
            (Ok(record), Ok(())) => Ok(record),
            (Err(error), Ok(())) | (_, Err(error)) => Err(error),
        }
    }

    /// Commits the complete plan before constructing any reduced mechanics
    /// request. The returned receipt is created only after publication,
    /// directory sync, exact readback, canonical decode, and identity readback.
    #[allow(
        clippy::too_many_lines,
        reason = "keeping the atomic plan publication and post-publication certainty boundary linear makes crash review auditable"
    )]
    fn persist_complete_command_plan(
        &mut self,
        token: u64,
        plan: &ValidatedLinuxProductionCommandPlanV1,
    ) -> Result<DurableCommandPlanCommit, CgroupIoFailure> {
        self.require_token(token)?;
        self.validate_retained_roots()?;
        self.verify_latest_generation()?;
        if !self.require_complete_command_plan {
            return Err(failure(
                "persist-command-plan",
                EffectCertainty::NotApplied,
                "complete production plans require the fixed service-owned v2 journal",
            ));
        }
        if let Some(first) = self.command_plans.get(plan.effect_id()) {
            return Err(reused_command_effect_failure(first.plan != *plan));
        }
        if self
            .command_effect_history
            .contains_key(&CommandEffectIdentity {
                effect_id: plan.effect_id().to_owned(),
            })
        {
            return Err(reused_command_effect_failure(true));
        }

        let temporary_name = command_plan_temporary_name(plan.plan_digest());
        let final_name = command_plan_name(plan.plan_digest());

        #[cfg(test)]
        if self.next_command_plan_failure == Some(TestCommandPlanFailurePoint::Write) {
            self.next_command_plan_failure = None;
            write_new_private_file(
                &self.directory,
                &temporary_name,
                b"{",
                self.expected_owner_uid,
            )?;
            return Err(failure(
                "write-command-plan-temporary",
                EffectCertainty::NotApplied,
                "injected crash after a partial command-plan temporary write",
            ));
        }

        let identity = write_new_private_file(
            &self.directory,
            &temporary_name,
            plan.canonical_bytes(),
            self.expected_owner_uid,
        )
        .map_err(|error| {
            failure(
                "write-command-plan-temporary",
                EffectCertainty::NotApplied,
                error.detail,
            )
        })?;

        #[cfg(test)]
        if self.next_command_plan_failure == Some(TestCommandPlanFailurePoint::Publish) {
            self.next_command_plan_failure = None;
            return Err(failure(
                "publish-command-plan",
                EffectCertainty::NotApplied,
                "injected command-plan publication refusal after temporary fsync",
            ));
        }

        renameat_with(
            &self.directory,
            Path::new(&temporary_name),
            &self.directory,
            Path::new(&final_name),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| io_failure("publish-command-plan", EffectCertainty::Ambiguous, error))?;
        self.pending_directory_sync = true;

        #[cfg(test)]
        if self.next_command_plan_failure == Some(TestCommandPlanFailurePoint::DirectorySync) {
            self.next_command_plan_failure = None;
            return Err(failure(
                "sync-command-plan-directory",
                EffectCertainty::Ambiguous,
                "injected command-plan directory-sync refusal after publication",
            ));
        }

        sync_directory(&self.directory).map_err(|error| {
            io_failure(
                "sync-command-plan-directory",
                EffectCertainty::Ambiguous,
                error,
            )
        })?;
        self.pending_directory_sync = false;

        #[cfg(test)]
        if self.next_command_plan_failure == Some(TestCommandPlanFailurePoint::Readback) {
            self.next_command_plan_failure = None;
            return Err(failure(
                "readback-command-plan",
                EffectCertainty::Ambiguous,
                "injected command-plan readback refusal",
            ));
        }

        let (bytes, published_identity) = read_private_file_with_identity(
            &self.directory,
            &final_name,
            self.expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )
        .map_err(|error| {
            failure(
                "readback-command-plan",
                EffectCertainty::Ambiguous,
                error.detail,
            )
        })?;
        if published_identity != identity {
            return Err(failure(
                "readback-command-plan",
                EffectCertainty::Ambiguous,
                "published command-plan identity differs from the synced file",
            ));
        }
        if bytes != plan.canonical_bytes() {
            return Err(failure(
                "readback-command-plan",
                EffectCertainty::Ambiguous,
                "published command-plan bytes differ from the exact validated plan",
            ));
        }
        let readback =
            ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes).map_err(|error| {
                failure(
                    "readback-command-plan",
                    EffectCertainty::Ambiguous,
                    error.to_string(),
                )
            })?;
        if readback != *plan || readback.plan_digest() != plan.plan_digest() {
            return Err(failure(
                "readback-command-plan",
                EffectCertainty::Ambiguous,
                "canonical command-plan readback or plan digest differs",
            ));
        }

        let receipt =
            LinuxCommandPlanDurableCommitReceipt::from_verified_plan(&readback, published_identity);
        let request = readback
            .derive_private_prepare_request_after_durable_commit(&receipt)
            .map_err(|error| {
                failure(
                    "derive-journaled-command-plan",
                    EffectCertainty::Ambiguous,
                    error.to_string(),
                )
            })?;
        commit_unseen_command_effect(
            &mut self.command_effect_history,
            CommandEffectIdentity::from_request(&request),
            CommandEffectCommitment::from_request(&request, Some(readback.plan_digest().clone())),
        )?;
        self.active_plan_digest = Some(readback.plan_digest().clone());
        self.command_plans.insert(
            readback.effect_id().to_owned(),
            StoredCommandPlan {
                plan: readback,
                identity: published_identity,
            },
        );
        Ok(DurableCommandPlanCommit { receipt, request })
    }

    #[cfg(test)]
    fn inject_next_command_plan_readback_failure(&mut self) {
        self.next_command_plan_failure = Some(TestCommandPlanFailurePoint::Readback);
    }

    #[cfg(test)]
    fn inject_next_command_plan_write_failure(&mut self) {
        self.next_command_plan_failure = Some(TestCommandPlanFailurePoint::Write);
    }

    #[cfg(test)]
    fn inject_next_command_plan_publish_failure(&mut self) {
        self.next_command_plan_failure = Some(TestCommandPlanFailurePoint::Publish);
    }

    #[cfg(test)]
    fn inject_next_command_plan_directory_sync_failure(&mut self) {
        self.next_command_plan_failure = Some(TestCommandPlanFailurePoint::DirectorySync);
    }

    /// Proves that this globally unique core effect has never created a domain
    /// in the complete retained history, including under another session or a
    /// changed request.
    ///
    /// The caller must hold the retained writer lock. Preparation invokes
    /// this before nonce generation, initial persistence, or leaf creation;
    /// `persist` repeats the check as a fail-closed defense in depth.
    pub(crate) fn require_fresh_episode(
        &self,
        token: u64,
        request: &PrepareDomainRequest,
    ) -> Result<(), CgroupIoFailure> {
        self.require_token(token)?;
        self.validate_retained_roots()?;
        self.verify_latest_generation()?;
        self.verify_active_command_plan()?;
        let identity = CommandEffectIdentity::from_request(request);
        let commitment =
            CommandEffectCommitment::from_request(request, self.active_plan_digest.clone());
        if self.require_complete_command_plan {
            let first = self.command_effect_history.get(&identity).ok_or_else(|| {
                failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "mechanics request has no durably committed complete command plan",
                )
            })?;
            if first != &commitment || self.created_command_effects.contains(&identity.effect_id) {
                return Err(reused_command_effect_failure(first != &commitment));
            }
            Ok(())
        } else {
            require_unseen_command_effect(&self.command_effect_history, &identity, &commitment)
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear journal transition keeps validation, atomic publication, and effect-history mutation ordering visible"
    )]
    pub(crate) fn persist(&mut self, record: &DomainJournalRecord) -> Result<(), CgroupIoFailure> {
        self.require_any_token()?;
        self.validate_retained_roots()?;
        self.verify_latest_generation()?;
        self.verify_active_command_plan()?;
        record.validate().map_err(|error| {
            failure(
                "validate-journal-record",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        if record.state == DomainJournalState::CreateIntended {
            let identity = CommandEffectIdentity::from_record(record);
            let commitment =
                CommandEffectCommitment::from_record(record, self.active_plan_digest.clone());
            if self.require_complete_command_plan {
                let first = self.command_effect_history.get(&identity).ok_or_else(|| {
                    failure(
                        "authenticate-journal-plan",
                        EffectCertainty::NotApplied,
                        "CreateIntended has no durably committed complete command plan",
                    )
                })?;
                if first != &commitment
                    || self.created_command_effects.contains(&identity.effect_id)
                {
                    return Err(reused_command_effect_failure(first != &commitment));
                }
            } else {
                require_unseen_command_effect(
                    &self.command_effect_history,
                    &identity,
                    &commitment,
                )?;
            }
        } else if self
            .latest
            .as_ref()
            .is_some_and(|latest| latest.envelope.record == *record)
        {
            return Ok(());
        }
        if let Some(latest) = &self.latest {
            validate_record_successor(&latest.envelope.record, record)?;
            if self.require_complete_command_plan
                && record.state != DomainJournalState::CreateIntended
                && latest.envelope.plan_digest != self.active_plan_digest
            {
                return Err(failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "journal transition crosses its durably committed complete plan",
                ));
            }
        } else if record.state != DomainJournalState::CreateIntended {
            return Err(failure(
                "validate-journal-transition",
                EffectCertainty::NotApplied,
                "the first journal generation must be CreateIntended",
            ));
        }

        let sequence = self
            .latest
            .as_ref()
            .map_or(0, |latest| latest.envelope.sequence + 1);
        if sequence >= MAX_JOURNAL_GENERATIONS {
            return Err(failure(
                "persist-journal",
                EffectCertainty::NotApplied,
                "journal generation bound exhausted; endpoint compaction is required",
            ));
        }
        let plan_digest = self.active_plan_digest.clone();
        if self.require_complete_command_plan && plan_digest.is_none() {
            return Err(failure(
                "persist-journal",
                EffectCertainty::NotApplied,
                "production journal transition lacks a durably committed complete command plan",
            ));
        }
        let canonical_bytes = encode_envelope_with_plan(sequence, record, plan_digest.as_ref())?;
        let temporary_name = temporary_name(sequence);
        let final_name = final_name(sequence);
        let temporary_identity = write_new_private_file(
            &self.directory,
            &temporary_name,
            &canonical_bytes,
            self.expected_owner_uid,
        )?;
        renameat_with(
            &self.directory,
            Path::new(&temporary_name),
            &self.directory,
            Path::new(&final_name),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            io_failure(
                "publish-journal-generation",
                EffectCertainty::Ambiguous,
                error,
            )
        })?;
        let published_identity =
            named_private_file_identity(&self.directory, &final_name, self.expected_owner_uid)?;
        if published_identity != temporary_identity {
            return Err(failure(
                "publish-journal-generation",
                EffectCertainty::Ambiguous,
                "published generation identity differs from the synced temporary",
            ));
        }
        self.pending_directory_sync = true;
        self.latest = Some(StoredJournal {
            envelope: decode_envelope(&canonical_bytes)?,
            canonical_bytes,
            identity: published_identity,
        });
        if record.state == DomainJournalState::CreateIntended {
            if self.require_complete_command_plan {
                if !self
                    .created_command_effects
                    .insert(record.effect_id.clone())
                {
                    return Err(failure(
                        "persist-journal",
                        EffectCertainty::Ambiguous,
                        "a reused command effect was published despite the pre-publication plan check",
                    ));
                }
            } else {
                let previous = self.command_effect_history.insert(
                    CommandEffectIdentity::from_record(record),
                    CommandEffectCommitment::from_record(record, plan_digest),
                );
                if previous.is_some() {
                    return Err(failure(
                        "persist-journal",
                        EffectCertainty::Ambiguous,
                        "a reused command effect was published despite the pre-publication history check",
                    ));
                }
            }
        }
        Ok(())
    }

    fn latest_probe_record(&self) -> Option<ProbeJournalRecord> {
        self.latest_probe
            .as_ref()
            .map(|stored| stored.envelope.record.clone())
    }

    fn persist_probe(&mut self, record: &ProbeJournalRecord) -> Result<(), CgroupIoFailure> {
        self.require_any_token()?;
        self.validate_retained_roots()?;
        self.verify_latest_probe_generation()?;
        record.validate()?;
        if let Some(latest) = &self.latest_probe {
            if latest.envelope.record == *record {
                return Ok(());
            }
            validate_probe_record_successor(&latest.envelope.record, record)?;
        } else if record.state != ProbeJournalState::CreateIntended {
            return Err(failure(
                "validate-probe-journal-transition",
                EffectCertainty::NotApplied,
                "the first probe generation must be CreateIntended",
            ));
        }
        let sequence = self
            .latest_probe
            .as_ref()
            .map_or(0, |latest| latest.envelope.sequence + 1);
        if sequence >= MAX_PROBE_JOURNAL_GENERATIONS {
            return Err(failure(
                "persist-probe-journal",
                EffectCertainty::NotApplied,
                "probe journal generation bound exhausted; endpoint compaction is required",
            ));
        }
        let canonical_bytes = encode_probe_envelope(sequence, record)?;
        let temporary_name = probe_temporary_name(sequence);
        let final_name = probe_final_name(sequence);
        let temporary_identity = write_new_private_file(
            &self.probe_directory,
            &temporary_name,
            &canonical_bytes,
            self.expected_owner_uid,
        )?;
        renameat_with(
            &self.probe_directory,
            Path::new(&temporary_name),
            &self.probe_directory,
            Path::new(&final_name),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            io_failure(
                "publish-probe-journal-generation",
                EffectCertainty::Ambiguous,
                error,
            )
        })?;
        let published_identity = named_private_file_identity(
            &self.probe_directory,
            &final_name,
            self.expected_owner_uid,
        )?;
        if published_identity != temporary_identity {
            return Err(failure(
                "publish-probe-journal-generation",
                EffectCertainty::Ambiguous,
                "published probe generation differs from the synced temporary identity",
            ));
        }
        self.pending_directory_sync = true;
        self.latest_probe = Some(StoredProbeJournal {
            envelope: decode_probe_envelope(&canonical_bytes)?,
            canonical_bytes,
            identity: published_identity,
        });
        Ok(())
    }

    pub(crate) fn sync(&mut self) -> Result<(), CgroupIoFailure> {
        self.require_any_token()?;
        self.verify_latest_generation()?;
        self.verify_latest_probe_generation()?;
        sync_directory(&self.probe_directory).map_err(|error| {
            io_failure(
                "sync-probe-journal-directory",
                EffectCertainty::Ambiguous,
                error,
            )
        })?;
        sync_directory(&self.directory).map_err(|error| {
            io_failure("sync-journal-directory", EffectCertainty::Ambiguous, error)
        })?;
        self.pending_directory_sync = false;
        Ok(())
    }

    fn refresh_locked(&mut self) -> Result<(), CgroupIoFailure> {
        self.validate_retained_roots()?;
        recover_temporary_command_plan(&self.directory, self.expected_owner_uid)?;
        recover_temporary_generation(
            &self.directory,
            self.expected_owner_uid,
            self.require_complete_command_plan,
        )?;
        recover_temporary_probe_generation(&self.probe_directory, self.expected_owner_uid)?;
        let scan = scan_final_generations(
            &self.directory,
            self.expected_owner_uid,
            self.require_complete_command_plan,
        )?;
        for (effect_id, retained) in &self.command_plans {
            let Some(observed) = scan.command_plans.get(effect_id) else {
                return Err(failure(
                    "command-plan-artifact-continuity",
                    EffectCertainty::NotApplied,
                    "a previously retained command-plan artifact disappeared during locked refresh",
                ));
            };
            if observed.identity != retained.identity
                || observed.plan.canonical_bytes() != retained.plan.canonical_bytes()
                || observed.plan != retained.plan
            {
                return Err(failure(
                    "command-plan-artifact-continuity",
                    EffectCertainty::NotApplied,
                    "a previously retained command-plan artifact changed identity, canonical bytes, or decoded plan during locked refresh",
                ));
            }
        }
        self.latest = scan.latest;
        self.command_effect_history = scan.command_effect_history;
        self.command_plans = scan.command_plans;
        self.created_command_effects = scan.created_command_effects;
        self.latest_probe =
            scan_final_probe_generations(&self.probe_directory, self.expected_owner_uid)?;
        self.pending_directory_sync = false;
        Ok(())
    }

    fn validate_retained_roots(&self) -> Result<(), CgroupIoFailure> {
        let parent_metadata = self.parent.dir_metadata().map_err(|error| {
            io_failure("inspect-journal-parent", EffectCertainty::NotApplied, error)
        })?;
        validate_private_directory(&parent_metadata, self.expected_owner_uid)?;
        if object_identity(&parent_metadata) != self.parent_identity {
            return Err(failure(
                "journal-parent-identity",
                EffectCertainty::NotApplied,
                "retained service-state directory identity changed",
            ));
        }
        let metadata = self.directory.dir_metadata().map_err(|error| {
            io_failure("inspect-journal-root", EffectCertainty::NotApplied, error)
        })?;
        validate_private_directory(&metadata, self.expected_owner_uid)?;
        if object_identity(&metadata) != self.directory_identity {
            return Err(failure(
                "journal-root-identity",
                EffectCertainty::NotApplied,
                "retained journal directory identity changed",
            ));
        }
        require_named_identity(
            &self.parent,
            &self.leaf_name,
            self.directory_identity,
            "journal-root-identity",
        )?;
        let probe_metadata = self.probe_directory.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-probe-journal-root",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_private_directory(&probe_metadata, self.expected_owner_uid)?;
        if object_identity(&probe_metadata) != self.probe_directory_identity {
            return Err(failure(
                "probe-journal-root-identity",
                EffectCertainty::NotApplied,
                "retained probe journal directory identity changed",
            ));
        }
        require_named_identity(
            &self.directory,
            PROBE_JOURNAL_DIRECTORY,
            self.probe_directory_identity,
            "probe-journal-root-identity",
        )?;
        let lock_metadata = self.writer_lock.metadata().map_err(|error| {
            io_failure("inspect-journal-lock", EffectCertainty::NotApplied, error)
        })?;
        validate_private_file(&lock_metadata, self.expected_owner_uid)?;
        if object_identity(&lock_metadata) != self.writer_lock_identity {
            return Err(failure(
                "journal-lock-identity",
                EffectCertainty::NotApplied,
                "retained writer-lock identity changed",
            ));
        }
        require_named_identity(
            &self.directory,
            JOURNAL_LOCK_NAME,
            self.writer_lock_identity,
            "journal-lock-identity",
        )
    }

    fn verify_latest_generation(&self) -> Result<(), CgroupIoFailure> {
        let Some(latest) = &self.latest else {
            return Ok(());
        };
        let name = final_name(latest.envelope.sequence);
        let identity =
            named_private_file_identity(&self.directory, &name, self.expected_owner_uid)?;
        if identity != latest.identity {
            return Err(failure(
                "journal-generation-identity",
                EffectCertainty::NotApplied,
                "published journal generation identity changed",
            ));
        }
        let bytes = read_private_file(
            &self.directory,
            &name,
            self.expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        if bytes != latest.canonical_bytes {
            return Err(failure(
                "journal-generation-bytes",
                EffectCertainty::NotApplied,
                "published journal generation bytes changed",
            ));
        }
        Ok(())
    }

    fn verify_active_command_plan(&self) -> Result<(), CgroupIoFailure> {
        if !self.require_complete_command_plan {
            return Ok(());
        }
        let digest = self.active_plan_digest.as_ref().ok_or_else(|| {
            failure(
                "authenticate-journal-plan",
                EffectCertainty::NotApplied,
                "no durably committed command plan is active",
            )
        })?;
        let stored = self
            .command_plans
            .values()
            .find(|candidate| candidate.plan.plan_digest() == digest)
            .ok_or_else(|| {
                failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "active plan digest is absent from complete retained history",
                )
            })?;
        let name = command_plan_name(digest);
        let identity =
            named_private_file_identity(&self.directory, &name, self.expected_owner_uid)?;
        if identity != stored.identity {
            return Err(failure(
                "authenticate-journal-plan",
                EffectCertainty::NotApplied,
                "active command-plan artifact identity changed",
            ));
        }
        let bytes = read_private_file(
            &self.directory,
            &name,
            self.expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        if bytes != stored.plan.canonical_bytes() {
            return Err(failure(
                "authenticate-journal-plan",
                EffectCertainty::NotApplied,
                "active command-plan artifact bytes changed",
            ));
        }
        Ok(())
    }

    /// Revalidates the live published object that produced one durable receipt.
    /// A digest-equivalent replacement is not continuity: the exact no-follow
    /// inode, canonical bytes, and decoded plan must all remain unchanged.
    fn validate_exact_command_plan_artifact(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
        receipt: &LinuxCommandPlanDurableCommitReceipt,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_retained_roots()?;
        if !receipt.authenticates(plan) {
            return Err(failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                "durable receipt does not authenticate the exact retained command plan",
            ));
        }
        let retained = self.command_plans.get(plan.effect_id()).ok_or_else(|| {
            failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                "durable receipt has no retained command-plan artifact",
            )
        })?;
        if retained.identity != receipt.artifact_identity || retained.plan != *plan {
            return Err(failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                "cached command-plan identity or decoded plan differs from its durable receipt",
            ));
        }

        let name = command_plan_name(plan.plan_digest());
        let (bytes, identity) = read_private_file_with_identity(
            &self.directory,
            &name,
            self.expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )
        .map_err(|error| {
            failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                error.detail,
            )
        })?;
        if identity != receipt.artifact_identity || bytes != plan.canonical_bytes() {
            return Err(failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                "named command-plan identity or canonical bytes changed after durable publication",
            ));
        }
        let decoded =
            ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes).map_err(|error| {
                failure(
                    "authenticate-command-plan-artifact",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        if decoded != *plan || decoded.plan_digest() != plan.plan_digest() {
            return Err(failure(
                "authenticate-command-plan-artifact",
                EffectCertainty::NotApplied,
                "named command-plan bytes no longer decode to the exact retained plan",
            ));
        }
        require_named_identity(
            &self.directory,
            &name,
            receipt.artifact_identity,
            "authenticate-command-plan-artifact",
        )
    }

    fn verify_latest_probe_generation(&self) -> Result<(), CgroupIoFailure> {
        let Some(latest) = &self.latest_probe else {
            return Ok(());
        };
        let name = probe_final_name(latest.envelope.sequence);
        let identity =
            named_private_file_identity(&self.probe_directory, &name, self.expected_owner_uid)?;
        if identity != latest.identity {
            return Err(failure(
                "probe-journal-generation-identity",
                EffectCertainty::NotApplied,
                "published probe journal generation identity changed",
            ));
        }
        let bytes = read_private_file(
            &self.probe_directory,
            &name,
            self.expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        if bytes != latest.canonical_bytes {
            return Err(failure(
                "probe-journal-generation-bytes",
                EffectCertainty::NotApplied,
                "published probe journal generation bytes changed",
            ));
        }
        Ok(())
    }

    fn require_any_token(&self) -> Result<u64, CgroupIoFailure> {
        self.held_token.ok_or_else(|| {
            failure(
                "journal-lock-required",
                EffectCertainty::NotApplied,
                "journal mutation requires the retained writer lock",
            )
        })
    }

    fn require_token(&self, token: u64) -> Result<(), CgroupIoFailure> {
        if self.held_token == Some(token) {
            Ok(())
        } else {
            Err(failure(
                "journal-lock-token",
                EffectCertainty::NotApplied,
                "delegation lock token is absent or stale",
            ))
        }
    }
}

fn encode_envelope(
    sequence: u64,
    record: &DomainJournalRecord,
) -> Result<Vec<u8>, CgroupIoFailure> {
    encode_envelope_with_plan(sequence, record, None)
}

fn encode_envelope_with_plan(
    sequence: u64,
    record: &DomainJournalRecord,
    plan_digest: Option<&Digest>,
) -> Result<Vec<u8>, CgroupIoFailure> {
    let record_bytes = serde_json::to_vec(record).map_err(|error| {
        failure(
            "encode-journal-record",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let envelope = JournalEnvelope {
        format_version: JOURNAL_FORMAT_VERSION,
        sequence,
        plan_digest: plan_digest.cloned(),
        record_commitment_sha256: journal_record_commitment(plan_digest, &record_bytes),
        record: record.clone(),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_JOURNAL_BYTES {
        return Err(failure(
            "encode-journal-envelope",
            EffectCertainty::NotApplied,
            "canonical journal envelope exceeded its byte bound",
        ));
    }
    Ok(bytes)
}

/// Classifies one raw durable record's held-launcher release binding by the
/// protocol version that wrote it, refusing anything this runner does not
/// speak by a message that names both versions.
///
/// A version-2 binding is recognized by the **absence** of the version field,
/// because version 2 is the one protocol that never wrote one. That is not an
/// inference about content: `HeldExecReleaseBinding` denies unknown fields, so
/// the only documents reaching this classifier with a release binding and no
/// `protocol_version` are the ones version 2 wrote.
///
/// Nothing is migrated. A durable release binding describes a process image an
/// earlier protocol was going to install, and rewriting it into a later
/// protocol's shape would mean inventing the containment artefact the earlier
/// protocol had no channel for, a plan committing nothing while a launcher
/// installs something, which is the contradiction this project has refused
/// since schema version 3.
fn classify_held_launcher_protocol(
    record: Option<&serde_json::Value>,
) -> Result<(), CgroupIoFailure> {
    use crate::linux_held_launcher::{
        HELD_LAUNCHER_UNVERSIONED_PROTOCOL_VERSION, HeldLauncherProtocolPeek,
        held_launcher_protocol_version, held_launcher_protocol_version_peek,
    };

    let Some(record) = record else {
        return Ok(());
    };
    let spoken = held_launcher_protocol_version();
    let observed = match held_launcher_protocol_version_peek(record) {
        HeldLauncherProtocolPeek::NoReleaseBinding => return Ok(()),
        HeldLauncherProtocolPeek::Version(version) if version == u64::from(spoken) => {
            return Ok(());
        }
        HeldLauncherProtocolPeek::Version(version) => version,
        HeldLauncherProtocolPeek::Unversioned => {
            u64::from(HELD_LAUNCHER_UNVERSIONED_PROTOCOL_VERSION)
        }
    };
    Err(failure(
        "classify-held-launcher-release-binding",
        EffectCertainty::NotApplied,
        format!(
            "this durable command journal carries a held-launcher release binding written by \
             protocol version {observed}, and this runner speaks protocol version {spoken}; a \
             version-{observed} binding is refused and never migrated, because version {spoken}'s \
             containment artefact carries a channel version {observed} did not have and no \
             migration can invent one"
        ),
    ))
}

fn decode_envelope(bytes: &[u8]) -> Result<JournalEnvelope, CgroupIoFailure> {
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_JOURNAL_BYTES {
        return Err(failure(
            "decode-journal-envelope",
            EffectCertainty::NotApplied,
            "journal envelope was empty or exceeded its byte bound",
        ));
    }
    let shape: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        failure(
            "decode-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let format_version = shape
        .get("format_version")
        .and_then(serde_json::Value::as_u64);
    if format_version == Some(1) {
        return Err(failure(
            "classify-journal-envelope",
            EffectCertainty::NotApplied,
            "legacy command-journal envelope v1 is explicitly unsupported and cannot be interpreted as v2",
        ));
    }
    if format_version != Some(u64::from(JOURNAL_FORMAT_VERSION)) {
        return Err(failure(
            "classify-journal-envelope",
            EffectCertainty::NotApplied,
            "journal format version is unsupported",
        ));
    }
    // Inspect the version before typed decoding for explicit diagnostics;
    // version inspection does not bypass validation.
    classify_held_launcher_protocol(shape.get("record"))?;
    let envelope: JournalEnvelope = serde_json::from_value(shape).map_err(|error| {
        failure(
            "decode-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    envelope.record.validate().map_err(|error| {
        failure(
            "decode-journal-record",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let record_bytes = serde_json::to_vec(&envelope.record).map_err(|error| {
        failure(
            "encode-journal-record",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if envelope.record_commitment_sha256
        != journal_record_commitment(envelope.plan_digest.as_ref(), &record_bytes)
    {
        return Err(failure(
            "decode-journal-envelope",
            EffectCertainty::NotApplied,
            "journal record commitment does not match its plan digest and canonical record bytes",
        ));
    }
    let canonical = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if canonical != bytes {
        return Err(failure(
            "decode-journal-envelope",
            EffectCertainty::NotApplied,
            "journal bytes are not the single canonical representation",
        ));
    }
    Ok(envelope)
}

fn journal_record_commitment(plan_digest: Option<&Digest>, record_bytes: &[u8]) -> String {
    let plan_bytes = plan_digest.map_or(&[][..], |digest| digest.as_str().as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_RECORD_COMMITMENT_DOMAIN);
    hasher.update([u8::from(plan_digest.is_some())]);
    hasher.update((plan_bytes.len() as u64).to_be_bytes());
    hasher.update(plan_bytes);
    hasher.update((record_bytes.len() as u64).to_be_bytes());
    hasher.update(record_bytes);
    hex_lower(&hasher.finalize())
}

fn encode_probe_envelope(
    sequence: u64,
    record: &ProbeJournalRecord,
) -> Result<Vec<u8>, CgroupIoFailure> {
    record.validate()?;
    let record_bytes = serde_json::to_vec(record).map_err(|error| {
        failure(
            "encode-probe-journal-record",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let envelope = ProbeJournalEnvelope {
        format_version: PROBE_JOURNAL_FORMAT_VERSION,
        sequence,
        record_sha256: sha256_hex(&record_bytes),
        record: record.clone(),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_JOURNAL_BYTES {
        return Err(failure(
            "encode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            "canonical probe journal envelope exceeded its byte bound",
        ));
    }
    Ok(bytes)
}

fn decode_probe_envelope(bytes: &[u8]) -> Result<ProbeJournalEnvelope, CgroupIoFailure> {
    if bytes.is_empty() || bytes.len() > MAX_CANONICAL_JOURNAL_BYTES {
        return Err(failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            "probe journal envelope was empty or exceeded its byte bound",
        ));
    }
    // Inspect the version before typed decoding for explicit diagnostics;
    // version inspection does not bypass validation.
    let peek: ProbeJournalFormatVersionPeek = serde_json::from_slice(bytes).map_err(|error| {
        failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if peek.format_version != PROBE_JOURNAL_FORMAT_VERSION {
        let observed = peek.format_version;
        let superseded = if observed == PROBE_JOURNAL_SUPERSEDED_FORMAT_VERSION {
            " (the superseded format, which predates the canary episode and is refused, never \
             migrated)"
        } else {
            ""
        };
        return Err(failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            format!(
                "probe journal format version {observed}{superseded} is not the supported version \
                 {PROBE_JOURNAL_FORMAT_VERSION}"
            ),
        ));
    }
    let envelope: ProbeJournalEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if envelope.format_version != PROBE_JOURNAL_FORMAT_VERSION {
        return Err(failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            "probe journal format version is unsupported",
        ));
    }
    envelope.record.validate()?;
    let record_bytes = serde_json::to_vec(&envelope.record).map_err(|error| {
        failure(
            "encode-probe-journal-record",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if envelope.record_sha256 != sha256_hex(&record_bytes) {
        return Err(failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            "probe journal record digest does not match canonical record bytes",
        ));
    }
    let canonical = serde_json::to_vec(&envelope).map_err(|error| {
        failure(
            "encode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if canonical != bytes {
        return Err(failure(
            "decode-probe-journal-envelope",
            EffectCertainty::NotApplied,
            "probe journal bytes are not the single canonical representation",
        ));
    }
    Ok(envelope)
}

#[allow(
    clippy::too_many_lines,
    reason = "the full scan validates plan artifacts and record generations as one restart-time history invariant"
)]
fn scan_final_generations(
    directory: &Dir,
    expected_owner_uid: u32,
    require_complete_command_plan: bool,
) -> Result<JournalScan, CgroupIoFailure> {
    let mut names = read_entry_names(directory)?;
    names.sort();
    let mut finals = Vec::new();
    let mut plan_names = Vec::new();
    for name in names {
        if name == JOURNAL_LOCK_NAME || name == PROBE_JOURNAL_DIRECTORY {
            continue;
        }
        if parse_generation_name(&name, JOURNAL_TEMP_SUFFIX).is_some() {
            continue;
        }
        if parse_command_plan_temporary_name(&name).is_some() {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::Ambiguous,
                "unrecovered command-plan temporary remains in the journal",
            ));
        }
        if parse_command_plan_name(&name).is_some() {
            plan_names.push(name);
            continue;
        }
        let sequence = parse_generation_name(&name, JOURNAL_FINAL_SUFFIX).ok_or_else(|| {
            failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                format!("unexpected entry in private journal directory: {name}"),
            )
        })?;
        if sequence >= MAX_JOURNAL_GENERATIONS {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal generation exceeded its hard sequence bound",
            ));
        }
        finals.push((sequence, name));
    }
    let mut command_effect_history = BTreeMap::new();
    let mut command_plans = BTreeMap::new();
    for name in plan_names {
        let filename_digest = parse_command_plan_name(&name).ok_or_else(|| {
            failure(
                "scan-command-plan",
                EffectCertainty::NotApplied,
                "command-plan artifact name is noncanonical",
            )
        })?;
        let (bytes, identity) = read_private_file_with_identity(
            directory,
            &name,
            expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        let plan =
            ValidatedLinuxProductionCommandPlanV1::decode_exact(&bytes).map_err(|error| {
                failure(
                    "decode-command-plan",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        if plan.plan_digest().as_str() != filename_digest {
            return Err(failure(
                "authenticate-command-plan",
                EffectCertainty::NotApplied,
                "command-plan filename digest differs from its exact canonical bytes",
            ));
        }
        let receipt = LinuxCommandPlanDurableCommitReceipt::from_verified_plan(&plan, identity);
        let request = plan
            .derive_private_prepare_request_after_durable_commit(&receipt)
            .map_err(|error| {
                failure(
                    "derive-journaled-command-plan",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        let effect_id = plan.effect_id().to_owned();
        commit_unseen_command_effect(
            &mut command_effect_history,
            CommandEffectIdentity {
                effect_id: effect_id.clone(),
            },
            CommandEffectCommitment::from_request(&request, Some(plan.plan_digest().clone())),
        )?;
        let previous = command_plans.insert(effect_id, StoredCommandPlan { plan, identity });
        if previous.is_some() {
            return Err(failure(
                "scan-command-plan",
                EffectCertainty::NotApplied,
                "multiple complete command plans claim one global effect ID",
            ));
        }
    }
    finals.sort_by_key(|(sequence, _)| *sequence);
    let mut previous: Option<StoredJournal> = None;
    let mut created_command_effects = BTreeSet::new();
    for (index, (sequence, name)) in finals.into_iter().enumerate() {
        if sequence != index as u64 {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal generation sequence is not contiguous from zero",
            ));
        }
        let bytes = read_private_file(
            directory,
            &name,
            expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        let envelope = decode_envelope(&bytes)?;
        if envelope.sequence != sequence {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal filename and envelope sequence differ",
            ));
        }
        let effect_identity = CommandEffectIdentity::from_record(&envelope.record);
        let record_commitment =
            CommandEffectCommitment::from_record(&envelope.record, envelope.plan_digest.clone());
        match envelope.plan_digest.as_ref() {
            Some(plan_digest) => {
                let plan = command_plans
                    .get(&envelope.record.effect_id)
                    .ok_or_else(|| {
                        failure(
                            "authenticate-journal-plan",
                            EffectCertainty::NotApplied,
                            "journal generation references no complete command-plan artifact",
                        )
                    })?;
                if plan.plan.plan_digest() != plan_digest
                    || command_effect_history.get(&effect_identity) != Some(&record_commitment)
                {
                    return Err(failure(
                        "authenticate-journal-plan",
                        EffectCertainty::NotApplied,
                        "journal generation crosses or reduces its complete canonical command plan",
                    ));
                }
            }
            None if require_complete_command_plan => {
                return Err(failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "production journal generation omits its complete command-plan digest",
                ));
            }
            None => {}
        }
        if let Some(prior) = &previous {
            validate_record_successor(&prior.envelope.record, &envelope.record)?;
            if envelope.record.state != DomainJournalState::CreateIntended
                && prior.envelope.plan_digest != envelope.plan_digest
            {
                return Err(failure(
                    "authenticate-journal-plan",
                    EffectCertainty::NotApplied,
                    "one command episode crosses complete-plan digests",
                ));
            }
        } else if envelope.record.state != DomainJournalState::CreateIntended {
            return Err(failure(
                "scan-journal-directory",
                EffectCertainty::NotApplied,
                "journal history does not begin with CreateIntended",
            ));
        }
        if envelope.record.state == DomainJournalState::CreateIntended {
            if !created_command_effects.insert(envelope.record.effect_id.clone()) {
                return Err(reused_command_effect_failure(true));
            }
            if envelope.plan_digest.is_none() {
                commit_unseen_command_effect(
                    &mut command_effect_history,
                    effect_identity,
                    record_commitment,
                )?;
            }
        }
        previous = Some(StoredJournal {
            envelope,
            canonical_bytes: bytes,
            identity: named_private_file_identity(directory, &name, expected_owner_uid)?,
        });
    }
    Ok(JournalScan {
        latest: previous,
        command_effect_history,
        command_plans,
        created_command_effects,
    })
}

fn scan_final_probe_generations(
    directory: &Dir,
    expected_owner_uid: u32,
) -> Result<Option<StoredProbeJournal>, CgroupIoFailure> {
    let mut names = read_entry_names(directory)?;
    if names.len() > MAX_PROBE_JOURNAL_DIRECTORY_ENTRIES {
        return Err(failure(
            "scan-probe-journal-directory",
            EffectCertainty::NotApplied,
            "probe journal directory entry count exceeded its hard bound",
        ));
    }
    names.sort();
    let mut finals = Vec::new();
    for name in names {
        if name.ends_with(JOURNAL_TEMP_SUFFIX) {
            continue;
        }
        let sequence =
            parse_probe_generation_name(&name, JOURNAL_FINAL_SUFFIX).ok_or_else(|| {
                failure(
                    "scan-probe-journal-directory",
                    EffectCertainty::NotApplied,
                    format!("unexpected entry in private probe journal directory: {name}"),
                )
            })?;
        if sequence >= MAX_PROBE_JOURNAL_GENERATIONS {
            return Err(failure(
                "scan-probe-journal-directory",
                EffectCertainty::NotApplied,
                "probe journal generation exceeded its hard sequence bound",
            ));
        }
        finals.push((sequence, name));
    }
    finals.sort_by_key(|(sequence, _)| *sequence);
    let mut previous: Option<StoredProbeJournal> = None;
    for (index, (sequence, name)) in finals.into_iter().enumerate() {
        if sequence != index as u64 {
            return Err(failure(
                "scan-probe-journal-directory",
                EffectCertainty::NotApplied,
                "probe journal sequence is not contiguous from zero",
            ));
        }
        let bytes = read_private_file(
            directory,
            &name,
            expected_owner_uid,
            MAX_CANONICAL_JOURNAL_BYTES,
        )?;
        let envelope = decode_probe_envelope(&bytes)?;
        if envelope.sequence != sequence {
            return Err(failure(
                "scan-probe-journal-directory",
                EffectCertainty::NotApplied,
                "probe journal filename and envelope sequence differ",
            ));
        }
        if let Some(prior) = &previous {
            validate_probe_record_successor(&prior.envelope.record, &envelope.record)?;
        } else if envelope.record.state != ProbeJournalState::CreateIntended {
            return Err(failure(
                "scan-probe-journal-directory",
                EffectCertainty::NotApplied,
                "probe journal history does not begin with CreateIntended",
            ));
        }
        previous = Some(StoredProbeJournal {
            envelope,
            canonical_bytes: bytes,
            identity: named_private_file_identity(directory, &name, expected_owner_uid)?,
        });
    }
    Ok(previous)
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear recovery path makes unpublished deletion and published exact-duplicate handling mutually exclusive for review"
)]
fn recover_temporary_command_plan(
    directory: &Dir,
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    let names = read_entry_names(directory)?;
    let temporaries = names
        .iter()
        .filter(|name| parse_command_plan_temporary_name(name).is_some())
        .collect::<Vec<_>>();
    if temporaries.len() > 1 {
        return Err(failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            "multiple complete command-plan temporaries require operator reconciliation",
        ));
    }
    let Some(temporary_name) = temporaries.first() else {
        return Ok(());
    };
    let filename_digest = parse_command_plan_temporary_name(temporary_name).ok_or_else(|| {
        failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            "command-plan temporary name is noncanonical",
        )
    })?;
    named_private_file_identity(directory, temporary_name, expected_owner_uid).map_err(
        |error| {
            failure(
                "recover-command-plan-temporary",
                EffectCertainty::Ambiguous,
                error.detail,
            )
        },
    )?;
    let final_name = format!("{COMMAND_PLAN_PREFIX}{filename_digest}{COMMAND_PLAN_SUFFIX}");
    match directory.symlink_metadata(&final_name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            directory.remove_file(temporary_name).map_err(|error| {
                io_failure(
                    "discard-unpublished-command-plan-temporary",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
            return sync_directory(directory).map_err(|error| {
                io_failure(
                    "sync-discarded-command-plan-temporary",
                    EffectCertainty::Ambiguous,
                    error,
                )
            });
        }
        Ok(_) => {}
        Err(error) => {
            return Err(io_failure(
                "inspect-command-plan-publication",
                EffectCertainty::Ambiguous,
                error,
            ));
        }
    }
    let temporary_bytes = read_private_file(
        directory,
        temporary_name,
        expected_owner_uid,
        MAX_CANONICAL_JOURNAL_BYTES,
    )
    .map_err(|error| {
        failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            error.detail,
        )
    })?;
    let plan =
        ValidatedLinuxProductionCommandPlanV1::decode_exact(&temporary_bytes).map_err(|error| {
            failure(
                "recover-command-plan-temporary",
                EffectCertainty::Ambiguous,
                error.to_string(),
            )
        })?;
    if plan.plan_digest().as_str() != filename_digest {
        return Err(failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            "command-plan temporary filename digest differs from its exact canonical bytes",
        ));
    }
    let final_bytes = read_private_file(
        directory,
        &final_name,
        expected_owner_uid,
        MAX_CANONICAL_JOURNAL_BYTES,
    )
    .map_err(|error| {
        failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            error.detail,
        )
    })?;
    if final_bytes != temporary_bytes {
        return Err(failure(
            "recover-command-plan-temporary",
            EffectCertainty::Ambiguous,
            "command-plan temporary and published final bytes differ",
        ));
    }
    directory.remove_file(temporary_name).map_err(|error| {
        io_failure(
            "remove-duplicate-command-plan-temporary",
            EffectCertainty::Ambiguous,
            error,
        )
    })?;
    sync_directory(directory).map_err(|error| {
        io_failure(
            "sync-recovered-command-plan-directory",
            EffectCertainty::Ambiguous,
            error,
        )
    })
}

fn recover_temporary_probe_generation(
    directory: &Dir,
    expected_owner_uid: u32,
) -> Result<(), CgroupIoFailure> {
    let names = read_entry_names(directory)?;
    let temporaries = names
        .iter()
        .filter(|name| name.ends_with(JOURNAL_TEMP_SUFFIX))
        .collect::<Vec<_>>();
    if temporaries.len() > 1 {
        return Err(failure(
            "recover-probe-journal-temporary",
            EffectCertainty::NotApplied,
            "multiple probe journal temporaries require operator reconciliation",
        ));
    }
    let Some(temporary_name) = temporaries.first() else {
        return Ok(());
    };
    let sequence =
        parse_probe_generation_name(temporary_name, JOURNAL_TEMP_SUFFIX).ok_or_else(|| {
            failure(
                "recover-probe-journal-temporary",
                EffectCertainty::NotApplied,
                "probe journal temporary name is noncanonical",
            )
        })?;
    if sequence >= MAX_PROBE_JOURNAL_GENERATIONS {
        return Err(failure(
            "recover-probe-journal-temporary",
            EffectCertainty::NotApplied,
            "probe journal temporary exceeded the hard sequence bound",
        ));
    }
    let temporary_bytes = read_private_file(
        directory,
        temporary_name,
        expected_owner_uid,
        MAX_CANONICAL_JOURNAL_BYTES,
    )?;
    let envelope = decode_probe_envelope(&temporary_bytes)?;
    if envelope.sequence != sequence {
        return Err(failure(
            "recover-probe-journal-temporary",
            EffectCertainty::NotApplied,
            "probe temporary filename and envelope sequence differ",
        ));
    }
    let latest = scan_final_probe_generations(directory, expected_owner_uid)?;
    let final_name = probe_final_name(sequence);
    match directory.symlink_metadata(&final_name) {
        Ok(_) => remove_matching_duplicate_temporary(
            directory,
            temporary_name,
            &final_name,
            &temporary_bytes,
            expected_owner_uid,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            validate_orphan_probe_successor(latest.as_ref(), sequence, &envelope.record)?;
            renameat_with(
                directory,
                Path::new(temporary_name),
                directory,
                Path::new(&final_name),
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                io_failure(
                    "recover-probe-journal-publication",
                    EffectCertainty::Ambiguous,
                    error,
                )
            })?;
        }
        Err(error) => {
            return Err(io_failure(
                "inspect-probe-journal-publication",
                EffectCertainty::NotApplied,
                error,
            ));
        }
    }
    sync_directory(directory).map_err(|error| {
        io_failure(
            "sync-recovered-probe-journal-directory",
            EffectCertainty::Ambiguous,
            error,
        )
    })
}

fn recover_temporary_generation(
    directory: &Dir,
    expected_owner_uid: u32,
    require_complete_command_plan: bool,
) -> Result<(), CgroupIoFailure> {
    let names = read_entry_names(directory)?;
    let temporaries = names
        .iter()
        .filter(|name| parse_generation_name(name, JOURNAL_TEMP_SUFFIX).is_some())
        .cloned()
        .collect::<Vec<_>>();
    if temporaries.len() > 1 {
        return Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "multiple journal temporary generations require operator reconciliation",
        ));
    }
    let Some(temporary_name) = temporaries.first() else {
        return Ok(());
    };
    let sequence = parse_generation_name(temporary_name, JOURNAL_TEMP_SUFFIX).ok_or_else(|| {
        failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "journal temporary name is noncanonical",
        )
    })?;
    let temporary_bytes = read_private_file(
        directory,
        temporary_name,
        expected_owner_uid,
        MAX_CANONICAL_JOURNAL_BYTES,
    )?;
    let envelope = decode_envelope(&temporary_bytes)?;
    if envelope.sequence != sequence {
        return Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "temporary filename and envelope sequence differ",
        ));
    }
    if sequence >= MAX_JOURNAL_GENERATIONS {
        return Err(failure(
            "recover-journal-temporary",
            EffectCertainty::NotApplied,
            "temporary generation exceeded the hard sequence bound",
        ));
    }
    let latest_published =
        scan_final_generations(directory, expected_owner_uid, require_complete_command_plan)?;
    let final_name = final_name(sequence);
    match directory.symlink_metadata(&final_name) {
        Ok(_) => remove_matching_duplicate_temporary(
            directory,
            temporary_name,
            &final_name,
            &temporary_bytes,
            expected_owner_uid,
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            validate_orphan_temporary_successor(
                latest_published.latest.as_ref(),
                &latest_published.command_effect_history,
                &latest_published.created_command_effects,
                sequence,
                &envelope.record,
                envelope.plan_digest.as_ref(),
                require_complete_command_plan,
            )?;
            renameat_with(
                directory,
                Path::new(temporary_name),
                directory,
                Path::new(&final_name),
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| {
                io_failure(
                    "recover-journal-publication",
                    EffectCertainty::Ambiguous,
                    error,
                )
            })?;
        }
        Err(error) => {
            return Err(io_failure(
                "inspect-journal-publication",
                EffectCertainty::NotApplied,
                error,
            ));
        }
    }
    sync_directory(directory).map_err(|error| {
        io_failure(
            "sync-recovered-journal-directory",
            EffectCertainty::Ambiguous,
            error,
        )
    })
}

include!("linux_cgroup_io/journal_io_and_handoff.rs");
include!("linux_cgroup_io/bootstrap_and_images.rs");
include!("linux_cgroup_io/child_authority_and_domains.rs");
include!("linux_cgroup_io/installer_and_roots.rs");
include!("linux_cgroup_io/setup_and_probes.rs");
include!("linux_cgroup_io/release_and_controls.rs");
include!("linux_cgroup_io/command_composition.rs");
// Crate-visible so the live delegation harness can be shared rather than
// duplicated. A second copy of the setup that creates a real delegated cgroup
// subtree is exactly the kind of duplication that drifts, and the measurement
// of what the command path installs has to run against the same delegation the
// rest of the Linux suite uses.
#[cfg(test)]
pub(crate) mod tests;

#[cfg(target_os = "linux")]
pub(crate) mod stdio_services;
