//! Fail-closed cgroup-v2 accounting for the Linux command containment domain.
//!
//! This module deliberately contains no process launcher and no ambient path
//! lookup.  It models the cgroup-v2 part of the Linux containment transaction
//! behind [`CgroupIo`], whose production implementation must hold a retained
//! descriptor for the pre-authorized delegation.  All names passed to the
//! interface are normalized leaf names or typed control-file identifiers.
//!
//! A prepared domain is not command-execution authority by itself.  Bubblewrap,
//! Landlock, seccomp, capability, namespace, mount, descriptor, and active
//! canary evidence remain mandatory before a worker may execute.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    CONTRACT_VERSION, Digest, LiveRunnerLaunchReleaseClaim, MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES,
    RunnerLaunchPreparationAttempt, WorkerCleanupBackend,
};
use serde::{Deserialize, Serialize};

use crate::linux_held_launcher::{HeldExecObservation, HeldExecReleaseBinding};
use crate::platform_launch::{
    MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES, PlatformLaunchBinding,
    decode_native_launch_preparation_evidence,
};

/// Linux cgroup-v2 superblock magic (`CGROUP2_SUPER_MAGIC`).
pub(crate) const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// Maximum bytes accepted from `cgroup.events` in one observation.
pub(crate) const MAX_CGROUP_EVENTS_BYTES: usize = 1_024;
/// Maximum bytes accepted from `cgroup.procs` in one observation.
pub(crate) const MAX_CGROUP_PROCS_BYTES: usize = 4_096;
/// Maximum raw cleanup evidence retained for one domain.
pub(crate) const MAX_CLEANUP_EVIDENCE_BYTES: usize = 192 * 1_024;
/// Maximum cleanup poll count accepted from trusted policy.
pub(crate) const MAX_CLEANUP_ATTEMPTS: u8 = 16;
/// Maximum aggregate process ceiling supported by this evidence format.
pub(crate) const MAX_DOMAIN_PROCESSES: u32 = 256;

/// Fixed prefix of every command-domain cgroup leaf name.
///
/// The command plan quotes this constant rather than a second copy of the
/// grammar, so the set of names the plan admits cannot drift from the set
/// `prepare_domain` mints.
pub(crate) const DOMAIN_NAME_PREFIX: &str = "gb-";
/// Hexadecimal characters of unpredictable nonce in every leaf name.
///
/// 64 characters is 256 bits drawn from `/dev/urandom` inside the delegation
/// lock. The name is minted
/// only after the lock and the replay rejection, and is not a value any
/// earlier artefact may choose.
pub(crate) const DOMAIN_NONCE_HEX_CHARS: usize = 64;
const MAX_IDENTITY_TEXT_BYTES: usize = 256;
const MAX_HOST_ERROR_BYTES: usize = 1_024;
const MAX_DELEGATION_CHILDREN: usize = 64;
const MAX_DELEGATION_CHILD_NAME_BYTES: usize = 128;
const REQUIRED_SUBTREE_ENABLE: &[u8] = b"+memory +pids\n";
const CGROUP_KILL_VALUE: &[u8] = b"1\n";
const LAUNCHER_SELF_ATTACH_VALUE: &[u8] = b"0\n";
const MEMORY_OOM_GROUP_VALUE: &[u8] = b"1\n";
const LINUX_HELD_PREPARATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const LINUX_HELD_PREPARATION_EVIDENCE_DOMAIN: &[u8] =
    b"grok-build/linux-held-preparation-evidence/v1\0";

/// Device/inode identity retained for one cgroup directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CgroupObjectIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

impl CgroupObjectIdentity {
    fn validate(self, field: &'static str) -> Result<(), CgroupError> {
        if self.device == 0 || self.inode == 0 {
            return Err(CgroupError::InvalidObservation {
                field,
                reason: "device and inode must both be nonzero".into(),
            });
        }
        Ok(())
    }
}

/// Controllers used by the v0.1 Linux accounting domain.
///
/// There is intentionally no CPU variant: v0.1 declares no aggregate CPU
/// limit and must not write or report `cpu.max`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum DomainController {
    Memory,
    Pids,
}

impl DomainController {
    const REQUIRED: [Self; 2] = [Self::Memory, Self::Pids];

    const fn name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Pids => "pids",
        }
    }
}

/// Typed files that may be read at the fixed delegation root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DelegationFile {
    Controllers,
    Events,
    Procs,
    SubtreeControl,
}

impl DelegationFile {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Controllers => "cgroup.controllers",
            Self::Events => "cgroup.events",
            Self::Procs => "cgroup.procs",
            Self::SubtreeControl => "cgroup.subtree_control",
        }
    }
}

/// Typed files that may be read in a command-domain leaf.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LeafFile {
    CgroupEvents,
    CgroupKill,
    CgroupProcs,
    MemoryMax,
    MemoryOomGroup,
    MemorySwapMax,
    PidsMax,
}

/// Typed files the trusted parent may write in a command-domain leaf.
///
/// `cgroup.procs` is intentionally absent.  A parent-side numeric PID write is
/// vulnerable to PID reuse between authentication and the kernel write.  Only
/// the fixed, held launcher may attach itself through
/// [`CgroupIo::self_attach_held_launcher`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LeafWriteFile {
    CgroupKill,
    MemoryMax,
    MemoryOomGroup,
    MemorySwapMax,
    PidsMax,
}

impl LeafWriteFile {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CgroupKill => "cgroup.kill",
            Self::MemoryMax => "memory.max",
            Self::MemoryOomGroup => "memory.oom.group",
            Self::MemorySwapMax => "memory.swap.max",
            Self::PidsMax => "pids.max",
        }
    }
}

impl LeafFile {
    pub(crate) const ALL: [Self; 7] = [
        Self::CgroupEvents,
        Self::CgroupKill,
        Self::CgroupProcs,
        Self::MemoryMax,
        Self::MemoryOomGroup,
        Self::MemorySwapMax,
        Self::PidsMax,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CgroupEvents => "cgroup.events",
            Self::CgroupKill => "cgroup.kill",
            Self::CgroupProcs => "cgroup.procs",
            Self::MemoryMax => "memory.max",
            Self::MemoryOomGroup => "memory.oom.group",
            Self::MemorySwapMax => "memory.swap.max",
            Self::PidsMax => "pids.max",
        }
    }
}

/// A numeric cgroup limit or the kernel's literal `max` value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LimitValue {
    Max,
    Value(u64),
}

impl LimitValue {
    fn validate(self, field: &'static str) -> Result<(), CgroupError> {
        if self == Self::Value(0) {
            return Err(CgroupError::InvalidRequest {
                field,
                reason: "numeric limits must be greater than zero".into(),
            });
        }
        Ok(())
    }

    fn wire_bytes(self) -> Vec<u8> {
        match self {
            Self::Max => b"max\n".to_vec(),
            Self::Value(value) => format!("{value}\n").into_bytes(),
        }
    }
}

/// Exact cgroup limit values derived from the immutable execution policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub(crate) struct RequestedDomainLimits {
    pub(crate) pids_max: u32,
    pub(crate) memory_max: LimitValue,
    pub(crate) memory_swap_max: LimitValue,
}

impl RequestedDomainLimits {
    /// Derives aggregate cgroup values without inventing a CPU promise.
    ///
    /// A finite memory ceiling disables swap for the leaf so swap cannot make
    /// the effective aggregate limit exceed the request.  An unbounded memory
    /// request writes `max` to both memory controls.
    pub(crate) fn derive(
        max_processes: u32,
        max_memory_bytes: Option<u64>,
    ) -> Result<Self, CgroupError> {
        if max_processes == 0 || max_processes > MAX_DOMAIN_PROCESSES {
            return Err(CgroupError::InvalidRequest {
                field: "max_processes",
                reason: format!("must be in 1..={MAX_DOMAIN_PROCESSES}"),
            });
        }
        if max_memory_bytes == Some(0) {
            return Err(CgroupError::InvalidRequest {
                field: "max_memory_bytes",
                reason: "must be greater than zero when present".into(),
            });
        }
        let (memory_max, memory_swap_max) = match max_memory_bytes {
            Some(value) => (LimitValue::Value(value), LimitValue::Value(0)),
            None => (LimitValue::Max, LimitValue::Max),
        };
        Ok(Self {
            pids_max: max_processes,
            memory_max,
            memory_swap_max,
        })
    }

    fn validate(self) -> Result<(), CgroupError> {
        if self.pids_max == 0 || self.pids_max > MAX_DOMAIN_PROCESSES {
            return Err(CgroupError::InvalidRequest {
                field: "limits.pids_max",
                reason: format!("must be in 1..={MAX_DOMAIN_PROCESSES}"),
            });
        }
        self.memory_max.validate("limits.memory_max")?;
        if self.memory_max == LimitValue::Max {
            if self.memory_swap_max != LimitValue::Max {
                return Err(CgroupError::InvalidRequest {
                    field: "limits.memory_swap_max",
                    reason: "must be `max` when memory.max is `max`".into(),
                });
            }
        } else if self.memory_swap_max != LimitValue::Value(0) {
            return Err(CgroupError::InvalidRequest {
                field: "limits.memory_swap_max",
                reason: "must be zero for a finite aggregate memory request".into(),
            });
        }
        Ok(())
    }
}

/// Values read back from the created cgroup leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadBackDomainLimits {
    pub(crate) pids_max: u32,
    pub(crate) memory_max: LimitValue,
    pub(crate) memory_swap_max: LimitValue,
    pub(crate) memory_oom_group: bool,
}

impl ReadBackDomainLimits {
    fn require_exact(self, requested: RequestedDomainLimits) -> Result<(), CgroupError> {
        if self.pids_max != requested.pids_max {
            return Err(CgroupError::LimitMismatch {
                file: LeafFile::PidsMax,
                requested: requested.pids_max.to_string(),
                observed: self.pids_max.to_string(),
            });
        }
        if self.memory_max != requested.memory_max {
            return Err(CgroupError::LimitMismatch {
                file: LeafFile::MemoryMax,
                requested: display_limit(requested.memory_max),
                observed: display_limit(self.memory_max),
            });
        }
        if self.memory_swap_max != requested.memory_swap_max {
            return Err(CgroupError::LimitMismatch {
                file: LeafFile::MemorySwapMax,
                requested: display_limit(requested.memory_swap_max),
                observed: display_limit(self.memory_swap_max),
            });
        }
        if !self.memory_oom_group {
            return Err(CgroupError::LimitMismatch {
                file: LeafFile::MemoryOomGroup,
                requested: "1".into(),
                observed: "0".into(),
            });
        }
        Ok(())
    }
}

fn display_limit(value: LimitValue) -> String {
    match value {
        LimitValue::Max => "max".into(),
        LimitValue::Value(value) => value.to_string(),
    }
}

/// Exact static and active evidence for the fixed delegation root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DelegationObservation {
    pub(crate) filesystem_magic: u64,
    pub(crate) identity: CgroupObjectIdentity,
    pub(crate) expected_identity: CgroupObjectIdentity,
    pub(crate) owner_uid: u32,
    pub(crate) expected_owner_uid: u32,
    pub(crate) mode: u32,
    pub(crate) named_entry_matches_descriptor: bool,
    pub(crate) descendant_of_authenticated_service: bool,
    pub(crate) world_writable_ancestor: bool,
    pub(crate) available_controllers: BTreeSet<DomainController>,
    pub(crate) enabled_controllers: BTreeSet<DomainController>,
    pub(crate) existing_processes: Vec<u32>,
    pub(crate) existing_children: Vec<String>,
    pub(crate) required_files: BTreeSet<String>,
    pub(crate) negative_probe: DelegationProbeEvidence,
}

impl DelegationObservation {
    #[allow(clippy::too_many_lines)]
    fn validate_common(&self) -> Result<(), CgroupError> {
        if self.filesystem_magic != CGROUP2_SUPER_MAGIC {
            return Err(CgroupError::UnsupportedKernelApi {
                api: "cgroup-v2",
                reason: format!(
                    "filesystem magic was {:#x}, expected {CGROUP2_SUPER_MAGIC:#x}",
                    self.filesystem_magic
                ),
            });
        }
        self.identity.validate("delegation.identity")?;
        self.expected_identity
            .validate("delegation.expected_identity")?;
        if self.identity != self.expected_identity || !self.named_entry_matches_descriptor {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.identity",
                reason: "retained descriptor and authenticated named entry differ".into(),
            });
        }
        if self.owner_uid != self.expected_owner_uid {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.owner_uid",
                reason: "delegation is not owned by the authenticated runner identity".into(),
            });
        }
        if self.mode & 0o002 != 0 || self.world_writable_ancestor {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.mode",
                reason: "delegation or an ancestor is world-writable".into(),
            });
        }
        if !self.descendant_of_authenticated_service {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.service_ancestry",
                reason: "delegation is not beneath the authenticated app-service cgroup".into(),
            });
        }
        for controller in DomainController::REQUIRED {
            if !self.available_controllers.contains(&controller) {
                return Err(CgroupError::UnsupportedKernelApi {
                    api: controller.name(),
                    reason: "required controller is not available to the delegation".into(),
                });
            }
        }
        if self
            .enabled_controllers
            .iter()
            .any(|controller| !DomainController::REQUIRED.contains(controller))
        {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.cgroup.subtree_control",
                reason: "an undeclared controller is already enabled".into(),
            });
        }
        if self.existing_processes.len() > MAX_DOMAIN_PROCESSES as usize {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.cgroup.procs",
                reason: "process observation exceeded its hard count bound".into(),
            });
        }
        if !self.existing_processes.is_empty() {
            return Err(CgroupError::NoInternalProcessViolation {
                processes: self.existing_processes.clone(),
            });
        }
        if self.existing_children.len() > MAX_DELEGATION_CHILDREN
            || self.existing_children.iter().any(|name| {
                name.is_empty()
                    || name.len() > MAX_DELEGATION_CHILD_NAME_BYTES
                    || name == "."
                    || name == ".."
                    || name.contains('/')
                    || name.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
            })
        {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.children",
                reason: "child observation exceeded count/name bounds or was noncanonical".into(),
            });
        }
        for required in required_delegation_files() {
            if !self.required_files.contains(*required) {
                return Err(CgroupError::UnsupportedKernelApi {
                    api: required,
                    reason: "required delegated control file is absent or not writable/readable as required"
                        .into(),
                });
            }
        }
        if self.required_files.len() > 32
            || self.required_files.iter().any(|name| {
                name.is_empty()
                    || name.len() > 64
                    || name.contains('/')
                    || name.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
            })
        {
            return Err(CgroupError::InvalidObservation {
                field: "delegation.required_files",
                reason: "file evidence exceeded its hard bounds or was noncanonical".into(),
            });
        }
        self.negative_probe.validate()
    }

    fn validate_for_prepare(&self) -> Result<(), CgroupError> {
        self.validate_common()?;
        if self.existing_children.is_empty() {
            Ok(())
        } else {
            Err(CgroupError::UnexpectedChildren {
                children: self.existing_children.clone(),
            })
        }
    }

    fn validate_for_recovery(
        &self,
        expected_leaf: &str,
        expectation: RecoveryChildExpectation,
    ) -> Result<(), CgroupError> {
        self.validate_common()?;
        validate_leaf_name(expected_leaf)?;
        let exact = self.existing_children.as_slice() == [expected_leaf];
        let valid = match expectation {
            RecoveryChildExpectation::Absent => self.existing_children.is_empty(),
            RecoveryChildExpectation::Exact => exact,
            RecoveryChildExpectation::AbsentOrExact => self.existing_children.is_empty() || exact,
        };
        if valid {
            Ok(())
        } else {
            Err(CgroupError::UnexpectedChildren {
                children: self.existing_children.clone(),
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryChildExpectation {
    Absent,
    Exact,
    AbsentOrExact,
}

fn required_delegation_files() -> &'static [&'static str] {
    &[
        "cgroup.procs",
        "cgroup.subtree_control",
        "pids.max",
        "memory.max",
        "memory.swap.max",
        "memory.oom.group",
        "cgroup.kill",
    ]
}

/// Active create/configure/readback/kill/remove negative-control result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct DelegationProbeEvidence {
    pub(crate) created_no_replace: bool,
    pub(crate) configured_and_read_back: bool,
    pub(crate) kill_write_accepted: bool,
    pub(crate) populated_zero: bool,
    pub(crate) stable_empty_procs: bool,
    pub(crate) removed_exact_inode: bool,
}

impl DelegationProbeEvidence {
    fn validate(&self) -> Result<(), CgroupError> {
        if self.created_no_replace
            && self.configured_and_read_back
            && self.kill_write_accepted
            && self.populated_zero
            && self.stable_empty_procs
            && self.removed_exact_inode
        {
            Ok(())
        } else {
            Err(CgroupError::UnsupportedKernelApi {
                api: "delegated-cgroup-active-probe",
                reason: "create/configure/readback/kill/stable-empty/remove probe was incomplete"
                    .into(),
            })
        }
    }
}

/// Immutable schema-v13 preparation identity owned by the Linux native
/// launch journal.
///
/// This is a comparison join, not a spawn permit. Construction requires the
/// live core claim's exact attempt and a validated platform binding; the
/// durable cgroup journal then carries the identity through every state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxNativeLaunchIdentity {
    pub(crate) contract_version: u32,
    pub(crate) attempt_id: String,
    pub(crate) native_journal_id: String,
    pub(crate) expected_platform_binding_digest: Digest,
    pub(crate) sprint_id: String,
    pub(crate) launch_id: String,
    pub(crate) session_id: String,
    pub(crate) cleanup_effect_id: String,
    pub(crate) input_snapshot: Digest,
    pub(crate) grant_hash: Digest,
    pub(crate) policy_hash: Digest,
    pub(crate) claimed_at_unix_ms: u64,
}

/// The runner-side state a wire launch preparation is anchored on.
///
/// Every field is something this runner already holds and is executing under,
/// which is the whole point: an identity built from it cannot describe a
/// session, snapshot, grant or policy other than the live one.
pub(crate) struct LinuxRunnerLaunchAnchor<'a> {
    pub(crate) sprint_id: &'a str,
    pub(crate) launch_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) input_snapshot: &'a Digest,
    pub(crate) grant_hash: &'a Digest,
    pub(crate) policy_hash: &'a Digest,
}

impl LinuxNativeLaunchIdentity {
    pub(crate) fn try_from_claim(
        attempt: &RunnerLaunchPreparationAttempt,
        binding: &PlatformLaunchBinding,
    ) -> Result<Self, CgroupError> {
        attempt
            .validate()
            .map_err(|error| CgroupError::InvalidRequest {
                field: "native_launch.attempt",
                reason: error.to_string(),
            })?;
        if binding.platform_backend() != WorkerCleanupBackend::LinuxCgroupV2
            || attempt.contract_version != CONTRACT_VERSION
            || attempt.sprint_id != binding.sprint_id()
            || attempt.launch_id != binding.launch_id()
            || attempt.cleanup_effect_id != binding.cleanup_effect_id()
            || attempt.expected_platform_binding_digest != *binding.binding_digest()
            || attempt.claimed_at_unix_ms < binding.cleanup_admitted_at_unix_ms()
        {
            return Err(CgroupError::InvalidRequest {
                field: "native_launch.claim_join",
                reason: "attempt, launch, cleanup, backend, digest, or timestamp differs from the exact platform binding".into(),
            });
        }
        let identity = Self {
            contract_version: attempt.contract_version,
            attempt_id: attempt.attempt_id.clone(),
            native_journal_id: attempt.native_journal_id.clone(),
            expected_platform_binding_digest: attempt.expected_platform_binding_digest.clone(),
            sprint_id: attempt.sprint_id.clone(),
            launch_id: attempt.launch_id.clone(),
            session_id: binding.session_id().to_owned(),
            cleanup_effect_id: attempt.cleanup_effect_id.clone(),
            input_snapshot: binding.cleanup_intent().input_snapshot.clone(),
            grant_hash: binding.grant_hash().clone(),
            policy_hash: binding.policy_hash().clone(),
            claimed_at_unix_ms: attempt.claimed_at_unix_ms,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Derives launch identity from the received preparation and the runner's
    /// live session, effect context, grant hash and policy hash.
    ///
    /// The desktop's non-serializable `PlatformLaunchBinding` cannot cross this
    /// boundary. Contract version, sprint, launch and binding digest are checked
    /// against the received request. The runner has no independent cleanup-effect
    /// ID or admission timestamp to compare; those fields are protected by the
    /// v15 frame commitment, not by a local ledger readback.
    ///
    /// # Errors
    ///
    /// Fails for an invalid attempt or a mismatched contract version, sprint,
    /// launch or binding digest.
    pub(crate) fn try_from_wire_preparation(
        attempt: &RunnerLaunchPreparationAttempt,
        expected_binding_digest: &Digest,
        anchor: &LinuxRunnerLaunchAnchor<'_>,
    ) -> Result<Self, CgroupError> {
        attempt
            .validate()
            .map_err(|error| CgroupError::InvalidRequest {
                field: "native_launch.attempt",
                reason: error.to_string(),
            })?;
        if attempt.contract_version != CONTRACT_VERSION
            || attempt.sprint_id != anchor.sprint_id
            || attempt.launch_id != anchor.launch_id
            || attempt.expected_platform_binding_digest != *expected_binding_digest
        {
            return Err(CgroupError::InvalidRequest {
                field: "native_launch.wire_preparation_join",
                reason: "attempt contract, sprint, launch, or platform binding digest differs \
                         from the request it arrived with"
                    .into(),
            });
        }
        let identity = Self {
            contract_version: attempt.contract_version,
            attempt_id: attempt.attempt_id.clone(),
            native_journal_id: attempt.native_journal_id.clone(),
            expected_platform_binding_digest: attempt.expected_platform_binding_digest.clone(),
            sprint_id: attempt.sprint_id.clone(),
            launch_id: attempt.launch_id.clone(),
            session_id: anchor.session_id.to_owned(),
            cleanup_effect_id: attempt.cleanup_effect_id.clone(),
            input_snapshot: anchor.input_snapshot.clone(),
            grant_hash: anchor.grant_hash.clone(),
            policy_hash: anchor.policy_hash.clone(),
            claimed_at_unix_ms: attempt.claimed_at_unix_ms,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn validate(&self) -> Result<(), CgroupError> {
        if self.contract_version != CONTRACT_VERSION || self.claimed_at_unix_ms == 0 {
            return Err(CgroupError::InvalidRequest {
                field: "native_launch.contract",
                reason: "contract version must be current and claim timestamp must be nonzero"
                    .into(),
            });
        }
        for (field, value, maximum) in [
            ("attempt_id", self.attempt_id.as_str(), 512_usize),
            (
                "native_journal_id",
                self.native_journal_id.as_str(),
                MAX_RUNNER_NATIVE_JOURNAL_ID_BYTES,
            ),
            ("sprint_id", self.sprint_id.as_str(), 256),
            ("launch_id", self.launch_id.as_str(), 256),
            ("session_id", self.session_id.as_str(), 256),
            ("cleanup_effect_id", self.cleanup_effect_id.as_str(), 256),
        ] {
            if value.trim().is_empty()
                || value.len() > maximum
                || value.chars().any(char::is_control)
            {
                return Err(CgroupError::InvalidRequest {
                    field: "native_launch.identity",
                    reason: format!(
                        "{field} is blank, control-bearing, or exceeds {maximum} bytes"
                    ),
                });
            }
        }
        if self.launch_id == self.session_id
            || self.launch_id == self.cleanup_effect_id
            || self.session_id == self.cleanup_effect_id
        {
            return Err(CgroupError::InvalidRequest {
                field: "native_launch.identity",
                reason: "launch, session, and cleanup effect identities must be distinct".into(),
            });
        }
        Ok(())
    }

    fn validate_domain_join(&self, request: &PrepareDomainRequest) -> Result<(), CgroupError> {
        self.validate()?;
        if self.session_id != request.runner_session_id
            || self.grant_hash.as_str() != request.grant_hash
            || self.policy_hash.as_str() != request.policy_hash
        {
            return Err(CgroupError::InvalidRequest {
                field: "native_launch.domain_join",
                reason: "runner session, grant, or policy differs from schema-v13 launch authority"
                    .into(),
            });
        }
        Ok(())
    }
}

/// Canonical Linux service evidence for one exact attached, pre-exec child.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxHeldPreparationEvidence {
    schema_version: u32,
    attached_journal: DomainJournalRecord,
}

impl LinuxHeldPreparationEvidence {
    pub(crate) fn canonical_native_evidence_bytes(
        record: &DomainJournalRecord,
    ) -> Result<Vec<u8>, CgroupError> {
        record.validate()?;
        if record.state != DomainJournalState::Attached {
            return Err(CgroupError::InvalidState(
                "held preparation evidence requires the exact attached pre-release journal",
            ));
        }
        let evidence = Self {
            schema_version: LINUX_HELD_PREPARATION_EVIDENCE_SCHEMA_VERSION,
            attached_journal: record.clone(),
        };
        let encoded =
            serde_json::to_vec(&evidence).map_err(|error| CgroupError::InvalidObservation {
                field: "linux_held_preparation_evidence.encoding",
                reason: error.to_string(),
            })?;
        let mut bytes =
            Vec::with_capacity(LINUX_HELD_PREPARATION_EVIDENCE_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(LINUX_HELD_PREPARATION_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&encoded);
        if bytes.len() > MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES {
            return Err(CgroupError::InvalidObservation {
                field: "linux_held_preparation_evidence.length",
                reason: format!(
                    "canonical held journal evidence exceeds {MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES} bytes"
                ),
            });
        }
        Ok(bytes)
    }
}

/// Durable proof join required before the held child may be released.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxHeldChildReleaseRecord {
    pub(crate) native_launch: LinuxNativeLaunchIdentity,
    pub(crate) native_evidence_digest: Digest,
    pub(crate) held_preparation_evidence_digest: Digest,
}

impl LinuxHeldChildReleaseRecord {
    fn validate(&self) -> Result<(), CgroupError> {
        self.native_launch.validate()
    }
}

/// Non-cloneable post-readback authorization for one held-child release.
///
/// Construction requires core's fully validated preparation aggregate with a
/// persisted `HeldChildPrepared` outcome. It is never serialized as live
/// authority and recovery has no constructor for it; only its immutable digest
/// join is retained in the native journal.
pub(crate) struct LinuxHeldChildReleaseAuthorization<'claim, 'ledger> {
    _claim: Option<&'claim LiveRunnerLaunchReleaseClaim<'ledger>>,
    record: LinuxHeldChildReleaseRecord,
}

impl<'claim, 'ledger> LinuxHeldChildReleaseAuthorization<'claim, 'ledger> {
    pub(crate) fn try_from_live_claim(
        claim: &'claim LiveRunnerLaunchReleaseClaim<'ledger>,
        binding: &PlatformLaunchBinding,
        domain: &PreparedDomain,
    ) -> Result<Self, CgroupError> {
        if domain.state != DomainJournalState::Attached || domain.release_attempted {
            return Err(CgroupError::InvalidState(
                "release authorization requires one live attached pre-release journal",
            ));
        }
        domain.record.validate()?;
        let native_launch =
            LinuxNativeLaunchIdentity::try_from_claim(&claim.preparation().attempt, binding)?;
        if native_launch != domain.record.native_launch {
            return Err(CgroupError::InvalidRequest {
                field: "release_authorization.native_launch",
                reason: "live release claim differs from the exact attached Linux journal".into(),
            });
        }
        let validated =
            decode_native_launch_preparation_evidence(claim, binding).map_err(|error| {
                CgroupError::InvalidRequest {
                    field: "release_authorization.preparation_envelope",
                    reason: error.to_string(),
                }
            })?;
        let canonical_held =
            LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&domain.record)?;
        if validated.service_evidence_bytes() != canonical_held {
            return Err(CgroupError::InvalidRequest {
                field: "release_authorization.held_journal",
                reason: "core did not persist the canonical evidence for this exact held Linux journal and launcher".into(),
            });
        }
        let record = LinuxHeldChildReleaseRecord {
            native_launch,
            native_evidence_digest: validated.native_evidence_digest().clone(),
            held_preparation_evidence_digest: validated.service_evidence_digest().clone(),
        };
        record.validate()?;
        Ok(Self {
            _claim: Some(claim),
            record,
        })
    }

    pub(crate) fn into_record(self) -> LinuxHeldChildReleaseRecord {
        self.record
    }
}

/// The desktop's contained-command release claim, as carried to the runner.
///
/// This is the claim's *contents*, not the claim: `LiveContainedCommandReleaseClaim`
/// borrows the ledger exclusion that made it true and cannot leave the desktop.
/// The runner gains no ledger writer from receiving this -- it receives a
/// statement, and every field in it is checked against the runner's own journal
/// before it authorizes anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainedCommandReleaseAuthorityV1 {
    /// The command effect this authorizes releasing.
    pub(crate) command_effect_id: String,
    /// Digest of the exact contained-command request admitted.
    pub(crate) request_digest: String,
    /// The desktop's own preparation evidence digest.
    pub(crate) native_evidence_digest: Digest,
}

impl LinuxHeldChildReleaseAuthorization<'static, 'static> {
    /// Authorizes releasing one **contained command**, from the desktop's
    /// admission joined to this runner's own attached journal.
    ///
    /// Distinct from [`Self::try_from_live_claim`] on purpose, and not a
    /// relaxation of it. That constructor authorizes releasing a *runner
    /// process* and takes a `LiveRunnerLaunchReleaseClaim` whose subject is a
    /// launch. This one authorizes releasing a *command*, and it is the reason
    /// schema v38 exists: there was no admission whose subject was a command,
    /// so there was nothing for a command's release to be a claim about.
    ///
    /// Three of the four values are the runner's own and are never taken from
    /// the wire: `native_launch` comes from the attached journal record, the
    /// held-preparation evidence digest is derived from that same record, and
    /// the state preconditions are the journal's. Exactly one value crosses the
    /// boundary -- the desktop's outer evidence digest -- because a runner that
    /// invented it would be authorizing its own release.
    ///
    /// # Errors
    ///
    /// When the domain is not attached or already attempted its release, when
    /// its record does not validate, or when the authority names a different
    /// command effect or a different request than the journal does.
    pub(crate) fn try_from_contained_command_authority(
        authority: &ContainedCommandReleaseAuthorityV1,
        domain: &PreparedDomain,
    ) -> Result<Self, CgroupError> {
        if domain.state != DomainJournalState::Attached || domain.release_attempted {
            return Err(CgroupError::InvalidState(
                "contained command release authorization requires one live attached \
                 pre-release journal",
            ));
        }
        domain.record.validate()?;
        if authority.command_effect_id != domain.record.effect_id {
            return Err(CgroupError::InvalidRequest {
                field: "release_authorization.command_effect_id",
                reason: "the contained-command release admission names a different command \
                         effect than the attached journal"
                    .into(),
            });
        }
        if authority.request_digest != domain.record.request_digest {
            return Err(CgroupError::InvalidRequest {
                field: "release_authorization.request_digest",
                reason: "the contained-command release admission admits a different request \
                         than the attached journal committed"
                    .into(),
            });
        }
        let held_evidence =
            LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&domain.record)?;
        Ok(Self {
            _claim: None,
            record: LinuxHeldChildReleaseRecord {
                native_launch: domain.record.native_launch.clone(),
                native_evidence_digest: authority.native_evidence_digest.clone(),
                held_preparation_evidence_digest: Digest::sha256(&held_evidence),
            },
        })
    }
}

#[cfg(test)]
impl LinuxHeldChildReleaseAuthorization<'static, 'static> {
    pub(crate) fn test_for_record(record: &DomainJournalRecord) -> Self {
        let held_evidence = LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(record)
            .expect("valid test held preparation evidence");
        Self {
            _claim: None,
            record: LinuxHeldChildReleaseRecord {
                native_launch: record.native_launch.clone(),
                native_evidence_digest: Digest::sha256(b"test-outer-preparation-evidence"),
                held_preparation_evidence_digest: Digest::sha256(&held_evidence),
            },
        }
    }
}

/// Immutable request binding one domain to a persisted command effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PrepareDomainRequest {
    pub(crate) native_launch: LinuxNativeLaunchIdentity,
    pub(crate) runner_session_id: String,
    pub(crate) effect_id: String,
    pub(crate) grant_hash: String,
    pub(crate) policy_hash: String,
    pub(crate) command_hash: String,
    pub(crate) request_digest: String,
    pub(crate) expected_delegation_identity: CgroupObjectIdentity,
    pub(crate) expected_owner_uid: u32,
    pub(crate) limits: RequestedDomainLimits,
}

impl PrepareDomainRequest {
    fn validate(&self) -> Result<(), CgroupError> {
        self.native_launch.validate_domain_join(self)?;
        for (field, value) in [
            ("runner_session_id", self.runner_session_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
            ("grant_hash", self.grant_hash.as_str()),
            ("policy_hash", self.policy_hash.as_str()),
            ("command_hash", self.command_hash.as_str()),
        ] {
            if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte <= 0x20) {
                return Err(CgroupError::InvalidRequest {
                    field,
                    reason: "must be nonblank, bounded, and contain no ASCII control/space bytes"
                        .into(),
                });
            }
        }
        validate_sha256_text("request_digest", &self.request_digest)?;
        self.expected_delegation_identity
            .validate("expected_delegation_identity")?;
        self.limits.validate()
    }
}

/// A durable cgroup-domain journal transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DomainJournalState {
    CreateIntended,
    CreateAborted,
    Configuring,
    Prepared,
    AttachIntended,
    Attached,
    Held,
    ReleaseIntended,
    Released,
    Killing,
    EmptyProven,
    RemoveIntended,
    Removed,
}

impl DomainJournalState {
    const ALL: [Self; 13] = [
        Self::CreateIntended,
        Self::CreateAborted,
        Self::Configuring,
        Self::Prepared,
        Self::AttachIntended,
        Self::Attached,
        Self::Held,
        Self::ReleaseIntended,
        Self::Released,
        Self::Killing,
        Self::EmptyProven,
        Self::RemoveIntended,
        Self::Removed,
    ];
}

/// A launcher held before its first untrusted instruction executes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedLauncherIdentity {
    pub(crate) pid: u32,
    pub(crate) process_start_time_ticks: u64,
    pub(crate) launch_request_hash: String,
    pub(crate) held_before_exec: bool,
}

impl StagedLauncherIdentity {
    fn validate(&self) -> Result<(), CgroupError> {
        if self.pid == 0 || self.process_start_time_ticks == 0 || !self.held_before_exec {
            return Err(CgroupError::InvalidRequest {
                field: "staged_launcher",
                reason: "PID/start-time must be nonzero and launcher must be held before exec"
                    .into(),
            });
        }
        validate_identity_text(
            "staged_launcher.launch_request_hash",
            &self.launch_request_hash,
        )
    }
}

/// Typed journal record persisted by the trusted host implementation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainJournalRecord {
    pub(crate) state: DomainJournalState,
    pub(crate) native_launch: LinuxNativeLaunchIdentity,
    pub(crate) runner_session_id: String,
    pub(crate) effect_id: String,
    pub(crate) grant_hash: String,
    pub(crate) policy_hash: String,
    pub(crate) command_hash: String,
    pub(crate) request_digest: String,
    pub(crate) leaf_name: String,
    pub(crate) expected_delegation_identity: CgroupObjectIdentity,
    pub(crate) expected_owner_uid: u32,
    pub(crate) leaf_identity: Option<CgroupObjectIdentity>,
    pub(crate) requested_limits: RequestedDomainLimits,
    pub(crate) read_back_limits: Option<ReadBackDomainLimits>,
    pub(crate) staged_launcher: Option<StagedLauncherIdentity>,
    pub(crate) release_authorization: Option<LinuxHeldChildReleaseRecord>,
    pub(crate) release_binding: Option<HeldExecReleaseBinding>,
    pub(crate) release_intent_recorded: bool,
    pub(crate) release_observation: Option<HeldExecObservation>,
    pub(crate) cleanup_observations: Vec<RawCleanupObservation>,
    pub(crate) kill_value: Option<Vec<u8>>,
}

impl DomainJournalRecord {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn validate(&self) -> Result<(), CgroupError> {
        self.native_launch.validate()?;
        for (field, value) in [
            ("journal.runner_session_id", self.runner_session_id.as_str()),
            ("journal.effect_id", self.effect_id.as_str()),
            ("journal.grant_hash", self.grant_hash.as_str()),
            ("journal.policy_hash", self.policy_hash.as_str()),
            ("journal.command_hash", self.command_hash.as_str()),
        ] {
            validate_identity_text(field, value)?;
        }
        validate_sha256_text("journal.request_digest", &self.request_digest)?;
        validate_leaf_name(&self.leaf_name)?;
        self.expected_delegation_identity
            .validate("journal.expected_delegation_identity")?;
        self.requested_limits.validate()?;
        if let Some(identity) = self.leaf_identity {
            identity.validate("journal.leaf_identity")?;
        }
        if let Some(launcher) = &self.staged_launcher {
            launcher.validate()?;
            if launcher.launch_request_hash
                != self.native_launch.expected_platform_binding_digest.as_str()
            {
                return Err(CgroupError::InvalidObservation {
                    field: "journal.staged_launcher",
                    reason: "held launcher request hash differs from the expected platform binding digest".into(),
                });
            }
        }
        if let Some(authorization) = &self.release_authorization {
            authorization.validate()?;
            if authorization.native_launch != self.native_launch {
                return Err(CgroupError::InvalidObservation {
                    field: "journal.release_authorization",
                    reason: "post-readback release authorization differs from the journal's native launch identity".into(),
                });
            }
        }
        if self.native_launch.session_id != self.runner_session_id
            || self.native_launch.grant_hash.as_str() != self.grant_hash
            || self.native_launch.policy_hash.as_str() != self.policy_hash
        {
            return Err(CgroupError::InvalidObservation {
                field: "journal.native_launch_join",
                reason: "journal session, grant, or policy differs from native launch authority"
                    .into(),
            });
        }
        if let Some(binding) = &self.release_binding {
            binding
                .validate()
                .map_err(|reason| CgroupError::InvalidObservation {
                    field: "journal.release_binding",
                    reason,
                })?;
        }
        if let Some(observation) = &self.release_observation {
            let launcher =
                self.staged_launcher
                    .as_ref()
                    .ok_or_else(|| CgroupError::InvalidObservation {
                        field: "journal.release_observation",
                        reason: "released observation lacks a staged launcher".into(),
                    })?;
            let binding =
                self.release_binding
                    .as_ref()
                    .ok_or_else(|| CgroupError::InvalidObservation {
                        field: "journal.release_observation",
                        reason: "released observation lacks an exact release binding".into(),
                    })?;
            observation
                .validate_against(launcher, binding)
                .map_err(|reason| CgroupError::InvalidObservation {
                    field: "journal.release_observation",
                    reason,
                })?;
        }
        if let Some(read_back) = self.read_back_limits {
            read_back.require_exact(self.requested_limits)?;
        }
        let has_leaf = self.leaf_identity.is_some();
        let has_limits = self.read_back_limits.is_some();
        let has_launcher = self.staged_launcher.is_some();
        let has_release_authorization = self.release_authorization.is_some();
        let has_release_binding = self.release_binding.is_some();
        let has_release_intent = self.release_intent_recorded;
        let has_release_observation = self.release_observation.is_some();
        let has_kill = self.kill_value.is_some();
        let has_observations = !self.cleanup_observations.is_empty();
        let has_coherent_release_history = has_release_authorization == has_release_binding
            && (!has_release_intent || has_release_binding)
            && (!has_release_observation || has_release_intent);
        let exact_shape = match self.state {
            DomainJournalState::CreateIntended | DomainJournalState::CreateAborted => {
                !has_leaf
                    && !has_limits
                    && !has_launcher
                    && !has_release_authorization
                    && !has_release_binding
                    && !has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::Configuring => {
                has_leaf
                    && !has_limits
                    && !has_launcher
                    && !has_release_authorization
                    && !has_release_binding
                    && !has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::Prepared => {
                has_leaf
                    && has_limits
                    && !has_launcher
                    && !has_release_authorization
                    && !has_release_binding
                    && !has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::AttachIntended | DomainJournalState::Attached => {
                has_leaf
                    && has_limits
                    && has_launcher
                    && !has_release_authorization
                    && !has_release_binding
                    && !has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::Held => {
                has_leaf
                    && has_limits
                    && has_launcher
                    && has_release_authorization
                    && has_release_binding
                    && !has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::ReleaseIntended => {
                has_leaf
                    && has_limits
                    && has_launcher
                    && has_release_authorization
                    && has_release_binding
                    && has_release_intent
                    && !has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::Released => {
                has_leaf
                    && has_limits
                    && has_launcher
                    && has_release_authorization
                    && has_release_binding
                    && has_release_intent
                    && has_release_observation
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::Killing => {
                // Historical launcher identity is optional: cleanup may begin
                // before attachment or after an attach state.
                has_leaf
                    && has_limits
                    && (!has_release_authorization || has_launcher)
                    && has_coherent_release_history
                    && !has_kill
                    && !has_observations
            }
            DomainJournalState::EmptyProven
            | DomainJournalState::RemoveIntended
            | DomainJournalState::Removed => {
                // Endpoint records retain a historical launcher when present,
                // but never require an invented one for pre-attach cleanup.
                has_leaf
                    && has_limits
                    && (!has_release_authorization || has_launcher)
                    && has_coherent_release_history
                    && has_kill
                    && has_observations
            }
        };
        if !exact_shape {
            return Err(CgroupError::InvalidObservation {
                field: "journal.state_shape",
                reason: format!("fields are not exact for state {:?}", self.state),
            });
        }
        if matches!(
            self.state,
            DomainJournalState::EmptyProven
                | DomainJournalState::RemoveIntended
                | DomainJournalState::Removed
        ) && self.kill_value.as_deref() != Some(CGROUP_KILL_VALUE)
        {
            return Err(CgroupError::InvalidObservation {
                field: "journal.cleanup_evidence",
                reason: "endpoint state requires exact kill and bounded raw observations".into(),
            });
        }
        validate_observation_sequence(
            &self.cleanup_observations,
            matches!(
                self.state,
                DomainJournalState::EmptyProven
                    | DomainJournalState::RemoveIntended
                    | DomainJournalState::Removed
            ),
        )
    }
}

/// Token proving the production host holds the delegation's single-writer lock.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DelegationLockToken(u64);

impl DelegationLockToken {
    pub(crate) const fn new(value: u64) -> Self {
        Self(value)
    }

    pub(crate) const fn id(&self) -> u64 {
        self.0
    }

    #[cfg(test)]
    const fn test(value: u64) -> Self {
        Self::new(value)
    }
}

/// Identity and initial state observed immediately after no-replace creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NewLeafObservation {
    pub(crate) identity: CgroupObjectIdentity,
    pub(crate) owner_uid: u32,
    pub(crate) mode: u32,
    pub(crate) named_entry_matches_descriptor: bool,
    pub(crate) initial_events: Vec<u8>,
    pub(crate) initial_procs: Vec<u8>,
}

/// Membership read-back for a trusted launcher still held before project exec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StagedLauncherObservation {
    pub(crate) pid: u32,
    pub(crate) process_start_time_ticks: u64,
    pub(crate) held_before_exec: bool,
    pub(crate) cgroup_procs: Vec<u8>,
}

/// Restart-time state of a launcher named by an attach intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StagedLauncherRecoveryState {
    /// Exact PID/start-time no longer exists.
    Absent,
    /// Exact PID/start-time exists and the trusted pre-exec hold remains set.
    HeldBeforeExec,
    /// The process exists but the pre-exec hold cannot be proven.
    ReleasedOrUnknown,
}

impl StagedLauncherObservation {
    fn validate(
        &self,
        expected: &StagedLauncherIdentity,
        max_processes: u32,
    ) -> Result<(), CgroupError> {
        self.validate_membership(expected, max_processes, true)
    }

    fn validate_membership(
        &self,
        expected: &StagedLauncherIdentity,
        max_processes: u32,
        require_hold: bool,
    ) -> Result<(), CgroupError> {
        if self.pid != expected.pid
            || self.process_start_time_ticks != expected.process_start_time_ticks
            || (require_hold && !self.held_before_exec)
        {
            return Err(CgroupError::InvalidObservation {
                field: "staged_launcher.identity",
                reason: "PID/start-time changed or launcher was released before membership proof"
                    .into(),
            });
        }
        let processes = parse_cgroup_procs(&self.cgroup_procs)?;
        if !processes.contains(&expected.pid)
            || u32::try_from(processes.len()).map_or(true, |count| count > max_processes)
        {
            return Err(CgroupError::InvalidObservation {
                field: "staged_launcher.cgroup_procs",
                reason: "launcher PID is absent or read-back exceeds the aggregate process limit"
                    .into(),
            });
        }
        Ok(())
    }
}

impl NewLeafObservation {
    fn validate_identity(&self, expected_owner_uid: u32) -> Result<(), CgroupError> {
        self.identity.validate("leaf.identity")?;
        if self.owner_uid != expected_owner_uid {
            return Err(CgroupError::InvalidObservation {
                field: "leaf.owner_uid",
                reason: "new leaf owner differs from the authenticated runner identity".into(),
            });
        }
        if self.mode & 0o002 != 0 || !self.named_entry_matches_descriptor {
            return Err(CgroupError::InvalidObservation {
                field: "leaf.identity",
                reason: "new leaf is world-writable or named identity changed".into(),
            });
        }
        parse_cgroup_events(&self.initial_events)?;
        parse_cgroup_procs(&self.initial_procs)?;
        Ok(())
    }

    fn validate_new(&self, expected_owner_uid: u32) -> Result<(), CgroupError> {
        self.validate_identity(expected_owner_uid)?;
        let events = parse_cgroup_events(&self.initial_events)?;
        if events.populated {
            return Err(CgroupError::InvalidObservation {
                field: "leaf.cgroup.events",
                reason: "new leaf was unexpectedly populated".into(),
            });
        }
        if !parse_cgroup_procs(&self.initial_procs)?.is_empty() {
            return Err(CgroupError::InvalidObservation {
                field: "leaf.cgroup.procs",
                reason: "new leaf contained an unexpected process".into(),
            });
        }
        Ok(())
    }
}

/// Host-operation certainty used to distinguish safe refusal from ambiguity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectCertainty {
    NotApplied,
    Applied,
    Ambiguous,
    /// This admission attempt performed no new effect, but authoritative
    /// journal history proves that the globally unique core effect was
    /// committed by an earlier episode. Callers must reconcile that episode;
    /// they must never translate this state into a retry-safe refusal.
    PriorEffectCommitted,
}

/// Failure returned by an injected host effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CgroupIoFailure {
    pub(crate) operation: &'static str,
    pub(crate) certainty: EffectCertainty,
    pub(crate) detail: String,
}

/// All cgroup host effects required by preparation and cleanup.
///
/// A production implementation must perform every operation relative to its
/// retained delegation capability and must enforce each supplied byte bound.
pub(crate) trait CgroupIo {
    fn acquire_delegation_lock(&mut self) -> Result<DelegationLockToken, CgroupIoFailure>;
    fn release_delegation_lock(
        &mut self,
        token: &DelegationLockToken,
    ) -> Result<(), CgroupIoFailure>;
    fn inspect_delegation(
        &mut self,
        expected_identity: CgroupObjectIdentity,
        expected_owner_uid: u32,
    ) -> Result<DelegationObservation, CgroupIoFailure>;
    /// Starts or reconciles the separately journaled delegation probe while
    /// the exact delegation lock is held.
    fn run_delegation_probe(
        &mut self,
        token: &DelegationLockToken,
    ) -> Result<DelegationProbeEvidence, CgroupIoFailure>;
    /// Rejects any second domain creation for a globally unique core effect,
    /// including a replay under another runner session or with a changed
    /// request, command, or native launch binding. This read-only admission
    /// check must run while the single-writer lock is held and before the
    /// delegation probe, nonce generation, initial journal persistence, or
    /// leaf creation.
    fn require_fresh_domain_episode(
        &mut self,
        token: &DelegationLockToken,
        request: &PrepareDomainRequest,
    ) -> Result<(), CgroupIoFailure>;
    fn enable_required_subtree_controllers(
        &mut self,
        token: &DelegationLockToken,
        exact_value: &[u8],
    ) -> Result<(), CgroupIoFailure>;
    fn read_enabled_subtree_controllers(
        &mut self,
        token: &DelegationLockToken,
        max_bytes: usize,
    ) -> Result<Vec<u8>, CgroupIoFailure>;
    fn unpredictable_leaf_nonce(&mut self) -> Result<String, CgroupIoFailure>;
    fn create_leaf_no_replace(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
    ) -> Result<NewLeafObservation, CgroupIoFailure>;
    fn inspect_leaf(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        max_events_bytes: usize,
        max_procs_bytes: usize,
    ) -> Result<Option<NewLeafObservation>, CgroupIoFailure>;
    fn write_leaf_file(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        file: LeafWriteFile,
        exact_value: &[u8],
    ) -> Result<(), CgroupIoFailure>;
    /// Causes the already-authenticated launcher to write the literal `0\n`
    /// through its pre-opened descriptor for this exact leaf's
    /// `cgroup.procs`.
    ///
    /// A production implementation must authenticate the fixed launcher by
    /// PID plus start time, prove its host-enforced pre-exec hold is still
    /// active, bind the descriptor to `identity`, and make the launcher itself
    /// perform the write.  It must never translate this operation into a
    /// parent-side numeric PID write.
    fn self_attach_held_launcher(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        exact_self_value: &[u8],
    ) -> Result<(), CgroupIoFailure>;
    fn read_leaf_file(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        file: LeafFile,
        max_bytes: usize,
    ) -> Result<Vec<u8>, CgroupIoFailure>;
    fn inspect_staged_launcher(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        max_procs_bytes: usize,
    ) -> Result<StagedLauncherObservation, CgroupIoFailure>;
    fn inspect_staged_launcher_recovery_state(
        &mut self,
        launcher: &StagedLauncherIdentity,
    ) -> Result<StagedLauncherRecoveryState, CgroupIoFailure>;
    fn persist_journal(&mut self, record: &DomainJournalRecord) -> Result<(), CgroupIoFailure>;
    fn sync_journal(&mut self) -> Result<(), CgroupIoFailure>;
    fn poll_barrier(&mut self) -> Result<(), CgroupIoFailure>;
    fn remove_leaf_exact(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
    ) -> Result<(), CgroupIoFailure>;
    fn prove_leaf_absent(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
    ) -> Result<bool, CgroupIoFailure>;
}

/// Split held-child handoff used to place durable journal transitions around
/// the only release operation.
///
/// Planning authenticates and freezes the complete descriptor-bound process
/// image but must not resume the child. Helper preparation may open the
/// retained descriptors but must return with the same child held. Commit is
/// one-shot and may run only after `ReleaseIntended` is synchronized.
pub(crate) trait HeldReleaseIo: CgroupIo {
    type ReleaseRequest;
    type PlannedRelease;
    type PreparedRelease;

    fn plan_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        request: Self::ReleaseRequest,
    ) -> Result<(Self::PlannedRelease, HeldExecReleaseBinding), CgroupIoFailure>;

    fn prepare_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        plan: Self::PlannedRelease,
    ) -> Result<Self::PreparedRelease, CgroupIoFailure>;

    fn commit_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        prepared: Self::PreparedRelease,
    ) -> Result<HeldExecObservation, CgroupIoFailure>;
}

/// One prepared cgroup leaf.  Possession is not launch authority.
#[derive(Debug)]
pub(crate) struct PreparedDomain {
    lock: Option<DelegationLockToken>,
    record: DomainJournalRecord,
    state: DomainJournalState,
    release_attempted: bool,
}

impl PreparedDomain {
    pub(crate) fn leaf_name(&self) -> &str {
        &self.record.leaf_name
    }

    pub(crate) fn leaf_identity(&self) -> Result<CgroupObjectIdentity, CgroupError> {
        self.record
            .leaf_identity
            .ok_or(CgroupError::InvalidState("domain leaf identity is absent"))
    }

    pub(crate) const fn requested_limits(&self) -> RequestedDomainLimits {
        self.record.requested_limits
    }

    pub(crate) fn read_back_limits(&self) -> Result<ReadBackDomainLimits, CgroupError> {
        self.record
            .read_back_limits
            .ok_or(CgroupError::InvalidState(
                "domain limit read-back is absent",
            ))
    }

    pub(crate) const fn state(&self) -> DomainJournalState {
        self.state
    }

    pub(crate) fn token(&self) -> Result<&DelegationLockToken, CgroupError> {
        self.lock.as_ref().ok_or(CgroupError::InvalidState(
            "domain no longer owns the delegation lock",
        ))
    }

    /// The delegation token, for a test that drives the staging step directly.
    ///
    /// Production code inside this module reaches `token` privately; nothing
    /// outside it needs the lock, and this deliberately does not change that.
    /// It exists because `stage_held_launcher` takes the token by reference and
    /// has no caller anywhere in the crate, so the journaled stage → attach →
    /// release lifecycle could not be driven end to end from any test.
    #[cfg(test)]
    pub(crate) fn test_token(&self) -> Result<&DelegationLockToken, CgroupError> {
        self.token()
    }

    /// The attached journal record.
    ///
    /// Widened from `#[cfg(test)]` to `pub(crate)` when the production launch
    /// path gained a real caller: `try_from_contained_command_authority` joins
    /// the desktop's admission to this record, and it cannot do that without
    /// reading it. The record is returned by shared reference only -- there is
    /// no `&mut` path to it from outside this module, so a caller can read the
    /// journal but cannot rewrite it.
    pub(crate) const fn record(&self) -> &DomainJournalRecord {
        &self.record
    }

    /// The attached journal record, for building a test release authorization.
    ///
    /// Pairs with [`LinuxHeldChildReleaseAuthorization::test_for_record`], whose
    /// only production sibling requires a desktop-side ledger claim no wire
    /// carries to the runner.
    #[cfg(test)]
    pub(crate) const fn test_record(&self) -> &DomainJournalRecord {
        &self.record
    }
}

/// One bounded raw kernel observation retained in cleanup order.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCleanupObservation {
    pub(crate) sequence: u32,
    pub(crate) attempt: u8,
    pub(crate) file: LeafFile,
    pub(crate) bytes: Vec<u8>,
}

/// Kernel-backed zero-descendant evidence candidate.
///
/// Only the coordinator may bind this candidate to the durable cleanup effect
/// and construct a `WorkerCleanupReceipt`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CgroupCleanupEvidence {
    pub(crate) journal_record: DomainJournalRecord,
    pub(crate) request_digest: String,
    pub(crate) leaf_name: String,
    pub(crate) leaf_identity: CgroupObjectIdentity,
    pub(crate) requested_limits: RequestedDomainLimits,
    pub(crate) read_back_limits: ReadBackDomainLimits,
    pub(crate) kill_value: Vec<u8>,
    pub(crate) observations: Vec<RawCleanupObservation>,
    pub(crate) stable_empty_reads: u8,
    pub(crate) leaf_removed: bool,
    pub(crate) surviving_processes: u64,
}

impl CgroupCleanupEvidence {
    pub(crate) fn validate(&self) -> Result<(), CgroupError> {
        self.journal_record.validate()?;
        if self.journal_record.state != DomainJournalState::Removed
            || self.journal_record.request_digest != self.request_digest
            || self.journal_record.leaf_name != self.leaf_name
            || self.journal_record.leaf_identity != Some(self.leaf_identity)
            || self.journal_record.requested_limits != self.requested_limits
            || self.journal_record.read_back_limits != Some(self.read_back_limits)
            || self.journal_record.kill_value.as_deref() != Some(self.kill_value.as_slice())
            || self.journal_record.cleanup_observations != self.observations
        {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.journal_binding",
                reason: "cleanup candidate differs from its exact durable journal record".into(),
            });
        }
        validate_leaf_name(&self.leaf_name)?;
        self.leaf_identity.validate("cleanup.leaf_identity")?;
        if self.kill_value != CGROUP_KILL_VALUE {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.cgroup.kill",
                reason: "cleanup did not record the exact `1` kill write".into(),
            });
        }
        if self.stable_empty_reads != 2 || !self.leaf_removed || self.surviving_processes != 0 {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.endpoint",
                reason:
                    "cleanup lacks two empty process reads, exact leaf removal, or zero survivors"
                        .into(),
            });
        }
        self.read_back_limits.require_exact(self.requested_limits)?;
        let total = self
            .observations
            .iter()
            .try_fold(0usize, |sum, item| sum.checked_add(item.bytes.len()))
            .ok_or(CgroupError::EvidenceLimitExceeded)?;
        if total > MAX_CLEANUP_EVIDENCE_BYTES {
            return Err(CgroupError::EvidenceLimitExceeded);
        }
        validate_observation_sequence(&self.observations, true)?;
        Ok(())
    }
}

/// Parsed `cgroup.events` fields used by the cleanup proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CgroupEvents {
    pub(crate) populated: bool,
    pub(crate) frozen: Option<bool>,
}

/// Exclusive authority retained when a durable leaf effect needs recovery.
///
/// Dropping this value does not unlock the delegated root.  That is
/// deliberately fail-closed: callers must reconcile the exact bound journal
/// record through [`reconcile_persisted_domain_with_lease`].
#[must_use = "a reconciliation lease keeps the delegated root exclusively locked"]
#[derive(Debug)]
pub(crate) struct DelegationReconciliationLease {
    lock: Option<DelegationLockToken>,
    binding: DomainRecoveryBinding,
    expected_delegation_identity: CgroupObjectIdentity,
    expected_owner_uid: u32,
    leaf_name: String,
    cause: CgroupError,
}

impl DelegationReconciliationLease {
    pub(crate) const fn cause(&self) -> &CgroupError {
        &self.cause
    }

    pub(crate) const fn is_active(&self) -> bool {
        self.lock.is_some()
    }

    fn require_exact_record(&self, record: &DomainJournalRecord) -> Result<(), CgroupError> {
        self.binding.require_exact(record)?;
        if self.expected_delegation_identity != record.expected_delegation_identity
            || self.expected_owner_uid != record.expected_owner_uid
            || self.leaf_name != record.leaf_name
        {
            return Err(CgroupError::InvalidRequest {
                field: "recovery.lease_binding",
                reason: "journal delegation or leaf differs from the live exclusive lease".into(),
            });
        }
        Ok(())
    }
}

/// Exclusive authority retained while the independent preflight-probe
/// journal has not reached an authoritative removed/absent endpoint.
///
/// This lease is deliberately distinct from [`DelegationReconciliationLease`]:
/// a probe is not a command domain and has no [`DomainJournalRecord`].
#[must_use = "a probe reconciliation lease keeps the delegated root exclusively locked"]
#[derive(Debug)]
pub(crate) struct ProbeReconciliationLease {
    lock: Option<DelegationLockToken>,
    cause: CgroupError,
}

impl ProbeReconciliationLease {
    pub(crate) const fn cause(&self) -> &CgroupError {
        &self.cause
    }

    pub(crate) const fn is_active(&self) -> bool {
        self.lock.is_some()
    }
}

/// Result of starting a new cgroup domain.
#[must_use]
#[derive(Debug)]
pub(crate) enum PrepareDomainOutcome {
    Prepared(Box<PreparedDomain>),
    /// A leaf effect may have occurred.  The exclusive root lock remains held
    /// until recovery reaches an authoritative endpoint.
    ReconciliationRequired(Box<DelegationReconciliationLease>),
    /// The independent preflight probe may still exist. No command-domain
    /// journal or leaf was created and the exact root lock remains held.
    ProbeReconciliationRequired(Box<ProbeReconciliationLease>),
}

/// Prepares one cgroup-v2 command domain and durably records its exact limits.
///
/// This was `#[cfg(test)]` until a production `LinuxCgroupIo` could exist. It
/// is production code now, and its single production caller is
/// `LinuxCgroupIo::prepare_service_domain`, which supplies the request out of
/// its own retained one-plan-scoped mechanics authority rather than accepting
/// one from a caller.
#[allow(clippy::too_many_lines)]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn prepare_domain<H: CgroupIo>(
    host: &mut H,
    request: PrepareDomainRequest,
) -> Result<PrepareDomainOutcome, CgroupError> {
    request.validate()?;
    let lock = host
        .acquire_delegation_lock()
        .map_err(CgroupError::host_before_leaf)?;
    match prepare_domain_while_locked(host, &lock, &request) {
        Ok(record) => Ok(PrepareDomainOutcome::Prepared(Box::new(PreparedDomain {
            lock: Some(lock),
            state: record.state,
            record,
            release_attempted: false,
        }))),
        Err(CgroupError::ReconciliationRequired {
            phase,
            leaf_name,
            leaf_identity,
            reason,
        }) => {
            let primary = CgroupError::ReconciliationRequired {
                phase,
                leaf_name: leaf_name.clone(),
                leaf_identity,
                reason,
            };
            Ok(PrepareDomainOutcome::ReconciliationRequired(Box::new(
                DelegationReconciliationLease {
                    lock: Some(lock),
                    binding: DomainRecoveryBinding {
                        native_launch: request.native_launch.clone(),
                        runner_session_id: request.runner_session_id.clone(),
                        effect_id: request.effect_id.clone(),
                        request_digest: request.request_digest.clone(),
                    },
                    expected_delegation_identity: request.expected_delegation_identity,
                    expected_owner_uid: request.expected_owner_uid,
                    leaf_name,
                    cause: primary,
                },
            )))
        }
        Err(cause @ CgroupError::ProbeReconciliationRequired { .. }) => Ok(
            PrepareDomainOutcome::ProbeReconciliationRequired(Box::new(ProbeReconciliationLease {
                lock: Some(lock),
                cause,
            })),
        ),
        Err(primary) => release_lock_after_error(host, lock, primary),
    }
}

#[allow(clippy::too_many_lines)]
fn prepare_domain_while_locked<H: CgroupIo>(
    host: &mut H,
    lock: &DelegationLockToken,
    request: &PrepareDomainRequest,
) -> Result<DomainJournalRecord, CgroupError> {
    host.require_fresh_domain_episode(lock, request)
        .map_err(CgroupError::host_before_leaf)?;
    host.run_delegation_probe(lock)
        .map_err(CgroupError::probe_reconciliation)?;
    let delegation = host
        .inspect_delegation(
            request.expected_delegation_identity,
            request.expected_owner_uid,
        )
        .map_err(CgroupError::host_before_leaf)?;
    delegation.validate_for_prepare()?;

    let all_enabled = DomainController::REQUIRED
        .into_iter()
        .collect::<BTreeSet<_>>();
    if delegation.enabled_controllers != all_enabled
        && let Err(failure) =
            host.enable_required_subtree_controllers(lock, REQUIRED_SUBTREE_ENABLE)
    {
        return Err(CgroupError::host_before_leaf(failure));
    }
    let enabled_raw = host
        .read_enabled_subtree_controllers(lock, 128)
        .map_err(CgroupError::host_before_leaf)?;
    let enabled = parse_controller_set(&enabled_raw)?;
    if enabled != all_enabled {
        return Err(CgroupError::InvalidObservation {
            field: "delegation.cgroup.subtree_control",
            reason: format!("required read-back was `memory pids`, observed {enabled:?}"),
        });
    }

    let nonce = host
        .unpredictable_leaf_nonce()
        .map_err(CgroupError::host_before_leaf)?;
    let leaf_name = normalized_leaf_name(&nonce)?;
    let mut record = DomainJournalRecord {
        state: DomainJournalState::CreateIntended,
        native_launch: request.native_launch.clone(),
        runner_session_id: request.runner_session_id.clone(),
        effect_id: request.effect_id.clone(),
        grant_hash: request.grant_hash.clone(),
        policy_hash: request.policy_hash.clone(),
        command_hash: request.command_hash.clone(),
        request_digest: request.request_digest.clone(),
        leaf_name: leaf_name.clone(),
        expected_delegation_identity: request.expected_delegation_identity,
        expected_owner_uid: request.expected_owner_uid,
        leaf_identity: None,
        requested_limits: request.limits,
        read_back_limits: None,
        staged_launcher: None,
        release_authorization: None,
        release_binding: None,
        release_intent_recorded: false,
        release_observation: None,
        cleanup_observations: Vec::new(),
        kill_value: None,
    };
    record.validate()?;
    host.persist_journal(&record)
        .map_err(CgroupError::host_before_leaf)?;
    host.sync_journal().map_err(CgroupError::host_before_leaf)?;
    let leaf = host
        .create_leaf_no_replace(lock, &leaf_name)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, None, failure))?;
    if let Err(error) = leaf.validate_new(request.expected_owner_uid) {
        return Err(CgroupError::ReconciliationRequired {
            phase: "prepare-new-leaf",
            leaf_name,
            leaf_identity: Some(leaf.identity),
            reason: error.to_string(),
        });
    }

    let identity = leaf.identity;
    record.state = DomainJournalState::Configuring;
    record.leaf_identity = Some(identity);
    record
        .validate()
        .map_err(|error| error.into_reconciliation(&leaf_name, identity, "prepare-configuring"))?;
    host.persist_journal(&record)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    host.sync_journal()
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    let read_back = configure_leaf(
        host,
        lock,
        &leaf_name,
        identity,
        request.limits,
        "prepare-readback",
    )?;

    record.state = DomainJournalState::Prepared;
    record.read_back_limits = Some(read_back);
    record
        .validate()
        .map_err(|error| error.into_reconciliation(&leaf_name, identity, "prepare-prepared"))?;
    host.persist_journal(&record)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    host.sync_journal()
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    Ok(record)
}

/// Rewrites this domain's **committed** ceilings onto its leaf and requires the
/// kernel to read them back exactly.
///
/// A canary suite that runs inside the command's own leaf installs its own
/// ceilings to drive its A/B pairs, and leaves the last ones it wrote behind.
/// Left alone that residue would hand the command a leaf whose `pids.max` and
/// `memory.max` are the canary's rather than the journal's -- a containment
/// hole that nothing downstream would notice, because the journal's read-back
/// was recorded at preparation and is not re-read later.
///
/// Calling this after an in-leaf canary is therefore not a repair of something
/// broken; it is what makes an in-leaf canary admissible at all. It is also
/// **stronger** than preparation alone: it proves the committed ceilings are in
/// force at the moment the command is about to be released, rather than only at
/// the moment the domain was prepared.
///
/// # Errors
///
/// When the domain holds no lock or leaf identity, when a ceiling cannot be
/// written, or when the kernel reads back anything other than what the journal
/// committed.
pub(crate) fn reinstall_committed_leaf_limits<H: CgroupIo>(
    host: &mut H,
    domain: &PreparedDomain,
) -> Result<(), CgroupError> {
    let leaf_name = domain.leaf_name().to_owned();
    let identity = domain.leaf_identity()?;
    let requested = domain.record().requested_limits;
    let read_back = configure_leaf(
        host,
        domain.token()?,
        &leaf_name,
        identity,
        requested,
        "reinstall-committed-leaf-limits",
    )?;
    read_back.require_exact(requested)
}

fn configure_leaf<H: CgroupIo>(
    host: &mut H,
    lock: &DelegationLockToken,
    leaf_name: &str,
    identity: CgroupObjectIdentity,
    limits: RequestedDomainLimits,
    readback_phase: &'static str,
) -> Result<ReadBackDomainLimits, CgroupError> {
    let write_result = (|| {
        host.write_leaf_file(
            lock,
            leaf_name,
            identity,
            LeafWriteFile::PidsMax,
            &LimitValue::Value(u64::from(limits.pids_max)).wire_bytes(),
        )?;
        host.write_leaf_file(
            lock,
            leaf_name,
            identity,
            LeafWriteFile::MemoryMax,
            &limits.memory_max.wire_bytes(),
        )?;
        host.write_leaf_file(
            lock,
            leaf_name,
            identity,
            LeafWriteFile::MemorySwapMax,
            &limits.memory_swap_max.wire_bytes(),
        )?;
        host.write_leaf_file(
            lock,
            leaf_name,
            identity,
            LeafWriteFile::MemoryOomGroup,
            MEMORY_OOM_GROUP_VALUE,
        )
    })();
    if let Err(failure) = write_result {
        return Err(CgroupError::reconciliation(
            leaf_name,
            Some(identity),
            failure,
        ));
    }
    let read_back = read_back_limits(host, lock, leaf_name, identity)
        .map_err(|error| error.into_reconciliation(leaf_name, identity, readback_phase))?;
    read_back
        .require_exact(limits)
        .map_err(|error| error.into_reconciliation(leaf_name, identity, readback_phase))?;
    Ok(read_back)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "the non-Copy lock token is consumed after the explicit release attempt"
)]
fn release_lock_after_error<H: CgroupIo, T>(
    host: &mut H,
    lock: DelegationLockToken,
    primary: CgroupError,
) -> Result<T, CgroupError> {
    match host.release_delegation_lock(&lock) {
        Ok(()) => Err(primary),
        Err(release) => Err(CgroupError::LockReleaseFailed {
            primary: Some(Box::new(primary)),
            release: bounded_host_failure(release),
        }),
    }
}

fn finish_local_domain<H: CgroupIo, T>(
    host: &mut H,
    domain: &mut PreparedDomain,
    result: Result<T, CgroupError>,
) -> Result<T, CgroupError> {
    let Some(lock) = domain.lock.as_ref() else {
        return result;
    };
    match (result, host.release_delegation_lock(lock)) {
        (Ok(value), Ok(())) => {
            domain.lock.take();
            Ok(value)
        }
        (Err(primary), Ok(())) => {
            domain.lock.take();
            Err(primary)
        }
        (Ok(_), Err(release)) => Err(CgroupError::LockReleaseFailed {
            primary: None,
            release: bounded_host_failure(release),
        }),
        (Err(primary), Err(release)) => Err(CgroupError::LockReleaseFailed {
            primary: Some(Box::new(primary)),
            release: bounded_host_failure(release),
        }),
    }
}

/// Restart result for the independent durable delegation probe.
#[must_use]
#[derive(Debug)]
pub(crate) enum ProbeRecoveryAttempt {
    Complete(DelegationProbeEvidence),
    ReconciliationRequired(Box<ProbeReconciliationLease>),
}

/// Acquires the root lock and starts or reconciles the durable preflight
/// probe. Any unresolved outcome returns a typed lease without unlocking.
pub(crate) fn reconcile_preflight_probe_on_restart<H: CgroupIo>(
    host: &mut H,
) -> Result<ProbeRecoveryAttempt, CgroupError> {
    let lock = host
        .acquire_delegation_lock()
        .map_err(CgroupError::host_before_leaf)?;
    match host.run_delegation_probe(&lock) {
        Ok(evidence) => match host.release_delegation_lock(&lock) {
            Ok(()) => Ok(ProbeRecoveryAttempt::Complete(evidence)),
            Err(release) => {
                let cause = CgroupError::LockReleaseFailed {
                    primary: None,
                    release: bounded_host_failure(release),
                };
                Ok(ProbeRecoveryAttempt::ReconciliationRequired(Box::new(
                    ProbeReconciliationLease {
                        lock: Some(lock),
                        cause,
                    },
                )))
            }
        },
        Err(failure) => Ok(ProbeRecoveryAttempt::ReconciliationRequired(Box::new(
            ProbeReconciliationLease {
                lock: Some(lock),
                cause: CgroupError::probe_reconciliation(failure),
            },
        ))),
    }
}

/// Retries probe reconciliation with the exact live lock token. The token is
/// restored to the lease on every failure and consumed only after the durable
/// probe reaches removed/absent and unlock succeeds.
pub(crate) fn reconcile_preflight_probe_with_lease<H: CgroupIo>(
    host: &mut H,
    lease: &mut ProbeReconciliationLease,
) -> Result<DelegationProbeEvidence, CgroupError> {
    let lock = lease.lock.take().ok_or(CgroupError::InvalidState(
        "probe reconciliation lease is no longer active",
    ))?;
    let evidence = match host.run_delegation_probe(&lock) {
        Ok(evidence) => evidence,
        Err(failure) => {
            let cause = CgroupError::probe_reconciliation(failure);
            lease.cause = cause.clone();
            lease.lock = Some(lock);
            return Err(cause);
        }
    };
    if let Err(release) = host.release_delegation_lock(&lock) {
        let cause = CgroupError::LockReleaseFailed {
            primary: None,
            release: bounded_host_failure(release),
        };
        lease.cause = cause.clone();
        lease.lock = Some(lock);
        return Err(cause);
    }
    Ok(evidence)
}

/// Restart result for one durably journaled cgroup domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DomainRecoveryOutcome {
    /// The synchronized create intent had no leaf and was durably aborted.
    AbortedBeforeCreate(DomainJournalRecord),
    /// A created or launched domain reached the authoritative removed endpoint.
    Cleaned(CgroupCleanupEvidence),
    /// Containment was cleaned, but the attach hold was already released and
    /// the durable command outcome remains Unknown.
    CleanedCommandOutcomeUnknown(UnknownCommandOutcome),
}

/// Whether a launcher whose pre-exec hold was not proven remained contained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EscapedMembershipStatus {
    /// Exact PID/start-time membership in the journal leaf was read back.
    ProvenInsideDomain,
    /// Exact membership could not be proven.  Completion must remain blocked.
    UnprovenBlockingCompletion,
    /// The unknown outcome came from an unexpectedly populated pre-attach
    /// leaf, so there is no staged-launcher membership claim to make.
    NotApplicable,
}

/// Cleanup proof paired with a deliberately unresolved command outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnknownCommandOutcome {
    pub(crate) cleanup_evidence: CgroupCleanupEvidence,
    pub(crate) escaped_membership: EscapedMembershipStatus,
}

impl UnknownCommandOutcome {
    /// Unknown command execution is never a successful completion endpoint.
    #[allow(
        clippy::unused_self,
        reason = "callers ask whether this concrete recovery outcome permits completion"
    )]
    pub(crate) const fn blocks_completion(&self) -> bool {
        true
    }
}

/// Result of a restart recovery attempt after the journal binding is valid.
#[must_use]
#[derive(Debug)]
pub(crate) enum DomainRecoveryAttempt {
    Complete(Box<DomainRecoveryOutcome>),
    /// Recovery encountered uncertainty while still owning the exclusive root
    /// lock.  Retry with the returned live lease; do not start another domain.
    ReconciliationRequired(Box<DelegationReconciliationLease>),
    /// Restart found an unresolved independent preflight probe before touching
    /// the command-domain journal.
    ProbeReconciliationRequired(Box<ProbeReconciliationLease>),
}

/// Ledger authority required to reopen one persisted OS-domain journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DomainRecoveryBinding {
    pub(crate) native_launch: LinuxNativeLaunchIdentity,
    pub(crate) runner_session_id: String,
    pub(crate) effect_id: String,
    pub(crate) request_digest: String,
}

impl DomainRecoveryBinding {
    fn validate(&self) -> Result<(), CgroupError> {
        self.native_launch.validate()?;
        validate_identity_text("recovery.runner_session_id", &self.runner_session_id)?;
        validate_identity_text("recovery.effect_id", &self.effect_id)?;
        validate_sha256_text("recovery.request_digest", &self.request_digest)
    }

    fn require_exact(&self, record: &DomainJournalRecord) -> Result<(), CgroupError> {
        self.validate()?;
        if self.native_launch != record.native_launch
            || self.runner_session_id != record.runner_session_id
            || self.effect_id != record.effect_id
            || self.request_digest != record.request_digest
        {
            return Err(CgroupError::InvalidRequest {
                field: "recovery.binding",
                reason: "native launch, session, effect, or durable request digest differs from the journal".into(),
            });
        }
        Ok(())
    }
}

/// Reconciles every durable domain state without replaying a project command.
#[allow(clippy::too_many_lines)]
pub(crate) fn reconcile_persisted_domain<H: CgroupIo>(
    host: &mut H,
    record: DomainJournalRecord,
    binding: &DomainRecoveryBinding,
    max_attempts: u8,
) -> Result<DomainRecoveryAttempt, CgroupError> {
    record.validate()?;
    binding.require_exact(&record)?;
    if max_attempts == 0 || max_attempts > MAX_CLEANUP_ATTEMPTS {
        return Err(CgroupError::InvalidRequest {
            field: "recovery.max_attempts",
            reason: format!("must be in 1..={MAX_CLEANUP_ATTEMPTS}"),
        });
    }
    let lock = host
        .acquire_delegation_lock()
        .map_err(CgroupError::host_before_leaf)?;
    if let Err(failure) = host.run_delegation_probe(&lock) {
        return Ok(DomainRecoveryAttempt::ProbeReconciliationRequired(
            Box::new(ProbeReconciliationLease {
                lock: Some(lock),
                cause: CgroupError::probe_reconciliation(failure),
            }),
        ));
    }
    let mut domain = PreparedDomain {
        lock: Some(lock),
        state: record.state,
        record,
        release_attempted: true,
    };
    let result = reconcile_persisted_domain_while_locked(host, &mut domain, max_attempts);
    match result {
        Ok(outcome) => match finish_local_domain(host, &mut domain, Ok(outcome)) {
            Ok(outcome) => Ok(DomainRecoveryAttempt::Complete(Box::new(outcome))),
            Err(cause) => {
                let Some(lock) = domain.lock.take() else {
                    return Err(cause);
                };
                Ok(DomainRecoveryAttempt::ReconciliationRequired(Box::new(
                    lease_from_record(lock, &domain.record, cause),
                )))
            }
        },
        Err(cause) => {
            let Some(lock) = domain.lock.take() else {
                return Err(cause);
            };
            Ok(DomainRecoveryAttempt::ReconciliationRequired(Box::new(
                lease_from_record(lock, &domain.record, cause),
            )))
        }
    }
}

/// Retries recovery without releasing or reacquiring the delegated-root lock.
///
/// On any retryable failure the lock is restored to `lease`, preserving
/// single-writer exclusivity across the entire reconciliation episode.
pub(crate) fn reconcile_persisted_domain_with_lease<H: CgroupIo>(
    host: &mut H,
    lease: &mut DelegationReconciliationLease,
    record: DomainJournalRecord,
    binding: &DomainRecoveryBinding,
    max_attempts: u8,
) -> Result<DomainRecoveryOutcome, CgroupError> {
    record.validate()?;
    binding.require_exact(&record)?;
    lease.require_exact_record(&record)?;
    if max_attempts == 0 || max_attempts > MAX_CLEANUP_ATTEMPTS {
        return Err(CgroupError::InvalidRequest {
            field: "recovery.max_attempts",
            reason: format!("must be in 1..={MAX_CLEANUP_ATTEMPTS}"),
        });
    }
    let lock = lease.lock.take().ok_or(CgroupError::InvalidState(
        "reconciliation lease is no longer active",
    ))?;
    let mut domain = PreparedDomain {
        lock: Some(lock),
        state: record.state,
        record,
        release_attempted: true,
    };
    let result = reconcile_persisted_domain_while_locked(host, &mut domain, max_attempts);
    match result {
        Ok(outcome) => match finish_local_domain(host, &mut domain, Ok(outcome)) {
            Ok(outcome) => Ok(outcome),
            Err(cause) => {
                if let Some(lock) = domain.lock.take() {
                    lease.lock = Some(lock);
                }
                Err(cause)
            }
        },
        Err(cause) => {
            if let Some(lock) = domain.lock.take() {
                lease.lock = Some(lock);
            }
            Err(cause)
        }
    }
}

fn lease_from_record(
    lock: DelegationLockToken,
    record: &DomainJournalRecord,
    cause: CgroupError,
) -> DelegationReconciliationLease {
    DelegationReconciliationLease {
        lock: Some(lock),
        binding: DomainRecoveryBinding {
            native_launch: record.native_launch.clone(),
            runner_session_id: record.runner_session_id.clone(),
            effect_id: record.effect_id.clone(),
            request_digest: record.request_digest.clone(),
        },
        expected_delegation_identity: record.expected_delegation_identity,
        expected_owner_uid: record.expected_owner_uid,
        leaf_name: record.leaf_name.clone(),
        cause,
    }
}

#[allow(clippy::too_many_lines)]
fn reconcile_persisted_domain_while_locked<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    max_attempts: u8,
) -> Result<DomainRecoveryOutcome, CgroupError> {
    let delegation = host
        .inspect_delegation(
            domain.record.expected_delegation_identity,
            domain.record.expected_owner_uid,
        )
        .map_err(CgroupError::host_before_leaf)?;
    let child_expectation = match domain.state {
        DomainJournalState::CreateAborted | DomainJournalState::Removed => {
            RecoveryChildExpectation::Absent
        }
        DomainJournalState::CreateIntended | DomainJournalState::RemoveIntended => {
            RecoveryChildExpectation::AbsentOrExact
        }
        DomainJournalState::Configuring
        | DomainJournalState::Prepared
        | DomainJournalState::AttachIntended
        | DomainJournalState::Attached
        | DomainJournalState::Held
        | DomainJournalState::ReleaseIntended
        | DomainJournalState::Released
        | DomainJournalState::Killing
        | DomainJournalState::EmptyProven => RecoveryChildExpectation::Exact,
    };
    delegation.validate_for_recovery(&domain.record.leaf_name, child_expectation)?;
    let enabled = parse_controller_set(
        &host
            .read_enabled_subtree_controllers(domain.token()?, 128)
            .map_err(CgroupError::host_before_leaf)?,
    )?;
    if enabled != DomainController::REQUIRED.into_iter().collect() {
        return Err(CgroupError::UnsupportedKernelApi {
            api: "cgroup.subtree_control",
            reason: "recovery requires exact memory+pids controller read-back".into(),
        });
    }

    let observed_leaf = host
        .inspect_leaf(
            domain.token()?,
            &domain.record.leaf_name,
            MAX_CGROUP_EVENTS_BYTES,
            MAX_CGROUP_PROCS_BYTES,
        )
        .map_err(|failure| {
            CgroupError::reconciliation(
                &domain.record.leaf_name,
                domain.record.leaf_identity,
                failure,
            )
        })?;
    let child_is_present = delegation.existing_children.len() == 1
        && delegation.existing_children[0] == domain.record.leaf_name;
    if child_is_present != observed_leaf.is_some() {
        return Err(CgroupError::ReconciliationRequired {
            phase: "recover-child-readback",
            leaf_name: domain.record.leaf_name.clone(),
            leaf_identity: observed_leaf.as_ref().map(|leaf| leaf.identity),
            reason: "delegation child enumeration and exact leaf inspection disagree".into(),
        });
    }

    match domain.state {
        DomainJournalState::CreateIntended => match &observed_leaf {
            None => {
                let mut aborted = domain.record.clone();
                aborted.state = DomainJournalState::CreateAborted;
                persist_record_update(host, domain, aborted)?;
                return Ok(DomainRecoveryOutcome::AbortedBeforeCreate(
                    domain.record.clone(),
                ));
            }
            Some(leaf) => {
                // Persist the created leaf identity. Configuring-state recovery must kill
                // and reconcile any unexpected occupants.
                leaf.validate_identity(domain.record.expected_owner_uid)?;
                let mut configuring = domain.record.clone();
                configuring.state = DomainJournalState::Configuring;
                configuring.leaf_identity = Some(leaf.identity);
                persist_record_update(host, domain, configuring)?;
            }
        },
        DomainJournalState::CreateAborted => {
            if observed_leaf.is_some() {
                return Err(CgroupError::ReconciliationRequired {
                    phase: "recover-create-aborted",
                    leaf_name: domain.record.leaf_name.clone(),
                    leaf_identity: observed_leaf.as_ref().map(|leaf| leaf.identity),
                    reason: "aborted create unexpectedly has a live leaf".into(),
                });
            }
            return Ok(DomainRecoveryOutcome::AbortedBeforeCreate(
                domain.record.clone(),
            ));
        }
        DomainJournalState::Removed => {
            if observed_leaf.is_some() {
                return Err(CgroupError::ReconciliationRequired {
                    phase: "recover-removed",
                    leaf_name: domain.record.leaf_name.clone(),
                    leaf_identity: domain.record.leaf_identity,
                    reason: "removed journal state still has a named leaf".into(),
                });
            }
            let evidence = evidence_from_removed_record(&domain.record)?;
            return Ok(recovery_cleanup_outcome(&domain.record, evidence));
        }
        DomainJournalState::RemoveIntended if observed_leaf.is_none() => {
            let mut removed = domain.record.clone();
            removed.state = DomainJournalState::Removed;
            persist_record_update(host, domain, removed)?;
            let evidence = evidence_from_removed_record(&domain.record)?;
            return Ok(recovery_cleanup_outcome(&domain.record, evidence));
        }
        _ => {}
    }

    let leaf = observed_leaf.ok_or_else(|| CgroupError::ReconciliationRequired {
        phase: "recover-missing-leaf",
        leaf_name: domain.record.leaf_name.clone(),
        leaf_identity: domain.record.leaf_identity,
        reason: "journal requires a live leaf but its exact name is absent".into(),
    })?;
    leaf.validate_identity(domain.record.expected_owner_uid)?;
    if domain.record.leaf_identity != Some(leaf.identity) {
        return Err(CgroupError::ReconciliationRequired {
            phase: "recover-leaf-identity",
            leaf_name: domain.record.leaf_name.clone(),
            leaf_identity: Some(leaf.identity),
            reason: "named leaf identity differs from the journal".into(),
        });
    }

    let mut unknown_membership = durable_release_uncertainty(&domain.record);
    if domain.state == DomainJournalState::Configuring {
        let unexpectedly_populated = parse_cgroup_events(&leaf.initial_events)?.populated
            || !parse_cgroup_procs(&leaf.initial_procs)?.is_empty();
        if unexpectedly_populated {
            unknown_membership = Some(EscapedMembershipStatus::NotApplicable);
            host.write_leaf_file(
                domain.token()?,
                &domain.record.leaf_name,
                leaf.identity,
                LeafWriteFile::CgroupKill,
                CGROUP_KILL_VALUE,
            )
            .map_err(|failure| {
                CgroupError::reconciliation(&domain.record.leaf_name, Some(leaf.identity), failure)
            })?;
            let _ = collect_stable_empty_observations(
                host,
                domain,
                &domain.record.leaf_name,
                leaf.identity,
                max_attempts,
            )?;
        }
        let limits = configure_leaf(
            host,
            domain.token()?,
            &domain.record.leaf_name,
            leaf.identity,
            domain.record.requested_limits,
            "recover-configure-readback",
        )?;
        let mut prepared = domain.record.clone();
        prepared.state = DomainJournalState::Prepared;
        prepared.read_back_limits = Some(limits);
        persist_record_update(host, domain, prepared)?;
    }

    if domain.state == DomainJournalState::AttachIntended {
        let launcher = domain
            .record
            .staged_launcher
            .clone()
            .ok_or(CgroupError::InvalidState("attach intent lacks launcher"))?;
        match host
            .inspect_staged_launcher_recovery_state(&launcher)
            .map_err(|failure| {
                CgroupError::reconciliation(
                    &domain.record.leaf_name,
                    domain.record.leaf_identity,
                    failure,
                )
            })? {
            StagedLauncherRecoveryState::Absent => {
                // Absence now cannot prove what happened between the durable
                // attach intent and restart.  Never replay the command.
                unknown_membership = Some(EscapedMembershipStatus::UnprovenBlockingCompletion);
            }
            StagedLauncherRecoveryState::HeldBeforeExec => {
                self_attach_launcher_for_recovery(host, domain, &launcher)?;
            }
            StagedLauncherRecoveryState::ReleasedOrUnknown => {
                // The parent must not write this numeric PID: it may now name
                // an unrelated reused process.  Membership is observation
                // only, followed by cleanup of the known cgroup object.
                unknown_membership = Some(observe_released_launcher_membership(
                    host, domain, &launcher,
                ));
            }
        }
    }

    let evidence = cleanup_domain(host, domain, max_attempts)?;
    if let Some(escaped_membership) = unknown_membership {
        Ok(DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(
            UnknownCommandOutcome {
                cleanup_evidence: evidence,
                escaped_membership,
            },
        ))
    } else {
        Ok(DomainRecoveryOutcome::Cleaned(evidence))
    }
}

fn durable_release_uncertainty(record: &DomainJournalRecord) -> Option<EscapedMembershipStatus> {
    if !record.release_intent_recorded {
        return None;
    }
    Some(if record.release_observation.is_some() {
        EscapedMembershipStatus::ProvenInsideDomain
    } else {
        EscapedMembershipStatus::UnprovenBlockingCompletion
    })
}

fn recovery_cleanup_outcome(
    record: &DomainJournalRecord,
    evidence: CgroupCleanupEvidence,
) -> DomainRecoveryOutcome {
    match durable_release_uncertainty(record) {
        Some(escaped_membership) => {
            DomainRecoveryOutcome::CleanedCommandOutcomeUnknown(UnknownCommandOutcome {
                cleanup_evidence: evidence,
                escaped_membership,
            })
        }
        None => DomainRecoveryOutcome::Cleaned(evidence),
    }
}

fn self_attach_launcher_for_recovery<H: CgroupIo>(
    host: &mut H,
    domain: &PreparedDomain,
    launcher: &StagedLauncherIdentity,
) -> Result<(), CgroupError> {
    let identity = domain.leaf_identity()?;
    host.self_attach_held_launcher(
        domain.token()?,
        &domain.record.leaf_name,
        identity,
        launcher,
        LAUNCHER_SELF_ATTACH_VALUE,
    )
    .map_err(|failure| {
        CgroupError::reconciliation(&domain.record.leaf_name, Some(identity), failure)
    })?;
    let observation = host
        .inspect_staged_launcher(
            domain.token()?,
            &domain.record.leaf_name,
            identity,
            launcher,
            MAX_CGROUP_PROCS_BYTES,
        )
        .map_err(|failure| {
            CgroupError::reconciliation(&domain.record.leaf_name, Some(identity), failure)
        })?;
    observation
        .validate(launcher, domain.record.requested_limits.pids_max)
        .map_err(|error| {
            error.into_reconciliation(
                &domain.record.leaf_name,
                identity,
                "recover-held-launcher-membership",
            )
        })
}

fn observe_released_launcher_membership<H: CgroupIo>(
    host: &mut H,
    domain: &PreparedDomain,
    launcher: &StagedLauncherIdentity,
) -> EscapedMembershipStatus {
    let Ok(identity) = domain.leaf_identity() else {
        return EscapedMembershipStatus::UnprovenBlockingCompletion;
    };
    let Ok(token) = domain.token() else {
        return EscapedMembershipStatus::UnprovenBlockingCompletion;
    };
    let Ok(observation) = host.inspect_staged_launcher(
        token,
        &domain.record.leaf_name,
        identity,
        launcher,
        MAX_CGROUP_PROCS_BYTES,
    ) else {
        return EscapedMembershipStatus::UnprovenBlockingCompletion;
    };
    if observation
        .validate_membership(launcher, domain.record.requested_limits.pids_max, false)
        .is_ok()
    {
        EscapedMembershipStatus::ProvenInsideDomain
    } else {
        EscapedMembershipStatus::UnprovenBlockingCompletion
    }
}

pub(crate) fn evidence_from_removed_record(
    record: &DomainJournalRecord,
) -> Result<CgroupCleanupEvidence, CgroupError> {
    record.validate()?;
    let evidence = CgroupCleanupEvidence {
        journal_record: record.clone(),
        request_digest: record.request_digest.clone(),
        leaf_name: record.leaf_name.clone(),
        leaf_identity: record
            .leaf_identity
            .ok_or(CgroupError::InvalidState("removed leaf identity is absent"))?,
        requested_limits: record.requested_limits,
        read_back_limits: record.read_back_limits.ok_or(CgroupError::InvalidState(
            "removed limit read-back is absent",
        ))?,
        kill_value: record
            .kill_value
            .clone()
            .ok_or(CgroupError::InvalidState("removed kill evidence is absent"))?,
        observations: record.cleanup_observations.clone(),
        stable_empty_reads: 2,
        leaf_removed: true,
        surviving_processes: 0,
    };
    evidence.validate()?;
    Ok(evidence)
}

fn read_back_limits<H: CgroupIo>(
    host: &mut H,
    token: &DelegationLockToken,
    leaf_name: &str,
    identity: CgroupObjectIdentity,
) -> Result<ReadBackDomainLimits, CgroupError> {
    let pids = host
        .read_leaf_file(token, leaf_name, identity, LeafFile::PidsMax, 64)
        .map_err(CgroupError::Host)?;
    let pids_max_u64 =
        parse_limit(&pids, false)?
            .numeric()
            .ok_or(CgroupError::InvalidObservation {
                field: "pids.max",
                reason: "pids.max must be numeric".into(),
            })?;
    let pids_max = u32::try_from(pids_max_u64).map_err(|_| CgroupError::InvalidObservation {
        field: "pids.max",
        reason: "pids.max exceeds u32".into(),
    })?;
    let memory_max = parse_limit(
        &host
            .read_leaf_file(token, leaf_name, identity, LeafFile::MemoryMax, 64)
            .map_err(CgroupError::Host)?,
        true,
    )?;
    let memory_swap_max = parse_limit(
        &host
            .read_leaf_file(token, leaf_name, identity, LeafFile::MemorySwapMax, 64)
            .map_err(CgroupError::Host)?,
        true,
    )?;
    let memory_oom_group = parse_bool01(
        &host
            .read_leaf_file(token, leaf_name, identity, LeafFile::MemoryOomGroup, 8)
            .map_err(CgroupError::Host)?,
        "memory.oom.group",
    )?;
    Ok(ReadBackDomainLimits {
        pids_max,
        memory_max,
        memory_swap_max,
        memory_oom_group,
    })
}

impl LimitValue {
    const fn numeric(self) -> Option<u64> {
        match self {
            Self::Max => None,
            Self::Value(value) => Some(value),
        }
    }
}

/// Attaches a fixed trusted launcher before it may execute project code.
///
/// The launcher must already exist in a host-enforced pre-exec hold.  The host
/// causes that same launcher to write `0` through a pre-opened capability for
/// the exact leaf, then revalidates PID start time, membership, and the hold.
/// The parent never writes a numeric PID.  Only a later launch layer may
/// release the hold, and only after this function returns `Attached`.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn attach_staged_launcher<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    launcher: StagedLauncherIdentity,
) -> Result<(), CgroupError> {
    if domain.state != DomainJournalState::Prepared {
        return Err(CgroupError::InvalidState(
            "launcher attachment requires a prepared domain",
        ));
    }
    launcher.validate()?;
    let leaf_name = domain.record.leaf_name.clone();
    let identity = domain
        .record
        .leaf_identity
        .ok_or(CgroupError::InvalidState(
            "prepared leaf identity is absent",
        ))?;

    let mut intended = domain.record.clone();
    intended.state = DomainJournalState::AttachIntended;
    intended.staged_launcher = Some(launcher.clone());
    persist_record_update(host, domain, intended)?;

    let token = domain.token()?;
    host.self_attach_held_launcher(
        token,
        &leaf_name,
        identity,
        &launcher,
        LAUNCHER_SELF_ATTACH_VALUE,
    )
    .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    let observation = host
        .inspect_staged_launcher(
            token,
            &leaf_name,
            identity,
            &launcher,
            MAX_CGROUP_PROCS_BYTES,
        )
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    observation
        .validate(&launcher, domain.record.requested_limits.pids_max)
        .map_err(|error| {
            error.into_reconciliation(&leaf_name, identity, "attach-membership-readback")
        })?;

    let mut attached = domain.record.clone();
    attached.state = DomainJournalState::Attached;
    persist_record_update(host, domain, attached)
}

/// Performs the inert descriptor-only handoff with durable one-way release
/// fencing.
///
/// This function is intentionally not wired to production `RunCommand`. Its
/// target contract remains the inert internal fixture until the authenticated
/// Bubblewrap plan, inner Landlock/seccomp launcher, and service-owned
/// lifecycle are implemented. Every error after planning leaves the domain in
/// a cleanup-only state; callers must never retry this function.
pub(crate) fn release_attached_inert_target<H: HeldReleaseIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    authorization: LinuxHeldChildReleaseAuthorization<'_, '_>,
    request: H::ReleaseRequest,
) -> Result<HeldExecObservation, CgroupError> {
    if domain.state != DomainJournalState::Attached {
        return Err(CgroupError::InvalidState(
            "release planning requires one attached held launcher",
        ));
    }
    if domain.release_attempted {
        return Err(CgroupError::InvalidState(
            "held launcher release is one-shot and this domain already attempted it",
        ));
    }
    let release_authorization = authorization.into_record();
    release_authorization.validate()?;
    if release_authorization.native_launch != domain.record.native_launch {
        return Err(CgroupError::InvalidRequest {
            field: "release_authorization.native_launch",
            reason: "post-readback release authorization differs from the attached native launch"
                .into(),
        });
    }
    let expected_held_evidence =
        LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(&domain.record)?;
    if release_authorization.held_preparation_evidence_digest
        != Digest::sha256(&expected_held_evidence)
    {
        return Err(CgroupError::InvalidRequest {
            field: "release_authorization.held_journal",
            reason: "release authorization differs from the exact attached journal and launcher"
                .into(),
        });
    }
    domain.release_attempted = true;
    let leaf_name = domain.record.leaf_name.clone();
    let identity = domain.leaf_identity()?;
    let launcher = domain
        .record
        .staged_launcher
        .clone()
        .ok_or(CgroupError::InvalidState(
            "attached domain lacks its held launcher",
        ))?;

    let (plan, release_binding) = host
        .plan_held_release(domain.token()?, &leaf_name, identity, &launcher, request)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    release_binding
        .validate()
        .map_err(|reason| CgroupError::ReconciliationRequired {
            phase: "release-plan-validation",
            leaf_name: leaf_name.clone(),
            leaf_identity: Some(identity),
            reason,
        })?;

    // Planning is already one-shot in the retained pidfd session. Persisting
    // the complete plan before the helper sees it ensures a crash from this
    // point can only clean the domain; it cannot reconstruct or replay release.
    let mut held = domain.record.clone();
    held.state = DomainJournalState::Held;
    held.release_authorization = Some(release_authorization);
    held.release_binding = Some(release_binding.clone());
    persist_record_update(host, domain, held)?;

    let prepared = host
        .prepare_held_release(domain.token()?, &leaf_name, identity, &launcher, plan)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;

    // The commit frame is forbidden until this exact intent is published and
    // synchronized. Recovery from this state kills/reconciles and never sends
    // the commit frame again.
    let mut release_intended = domain.record.clone();
    release_intended.state = DomainJournalState::ReleaseIntended;
    release_intended.release_intent_recorded = true;
    persist_record_update(host, domain, release_intended)?;

    let observation = host
        .commit_held_release(domain.token()?, &leaf_name, identity, &launcher, prepared)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    observation
        .validate_against(&launcher, &release_binding)
        .map_err(|reason| CgroupError::ReconciliationRequired {
            phase: "released-observation-validation",
            leaf_name: leaf_name.clone(),
            leaf_identity: Some(identity),
            reason,
        })?;

    let mut released = domain.record.clone();
    released.state = DomainJournalState::Released;
    released.release_observation = Some(observation.clone());
    persist_record_update(host, domain, released)?;
    Ok(observation)
}

/// Kills every process in a prepared leaf and proves a stable empty endpoint.
pub(crate) fn cleanup_domain<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    max_attempts: u8,
) -> Result<CgroupCleanupEvidence, CgroupError> {
    if max_attempts == 0 || max_attempts > MAX_CLEANUP_ATTEMPTS {
        return Err(CgroupError::InvalidRequest {
            field: "cleanup.max_attempts",
            reason: format!("must be in 1..={MAX_CLEANUP_ATTEMPTS}"),
        });
    }
    if !matches!(
        domain.state,
        DomainJournalState::Prepared
            | DomainJournalState::AttachIntended
            | DomainJournalState::Attached
            | DomainJournalState::Held
            | DomainJournalState::ReleaseIntended
            | DomainJournalState::Released
            | DomainJournalState::Killing
            | DomainJournalState::EmptyProven
            | DomainJournalState::RemoveIntended
    ) {
        return Err(CgroupError::InvalidState(
            "cleanup requires a configured live-domain journal state",
        ));
    }
    let leaf_name = domain.record.leaf_name.clone();
    let identity = domain
        .record
        .leaf_identity
        .ok_or(CgroupError::InvalidState("cleanup leaf identity is absent"))?;

    let mut observations = domain.record.cleanup_observations.clone();
    if matches!(
        domain.state,
        DomainJournalState::EmptyProven | DomainJournalState::RemoveIntended
    ) {
        validate_observation_sequence(&observations, true)?;
    } else {
        if domain.state != DomainJournalState::Killing {
            persist_transition(host, domain, DomainJournalState::Killing)?;
        }
        // `cgroup.kill` is idempotent. Reconciliation of an ambiguous write
        // reissues the exact value rather than trusting the journal state.
        let token = domain.token()?;
        host.write_leaf_file(
            token,
            &leaf_name,
            identity,
            LeafWriteFile::CgroupKill,
            CGROUP_KILL_VALUE,
        )
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;

        observations =
            collect_stable_empty_observations(host, domain, &leaf_name, identity, max_attempts)?;
        let mut empty_record = domain.record.clone();
        empty_record.state = DomainJournalState::EmptyProven;
        empty_record.kill_value = Some(CGROUP_KILL_VALUE.to_vec());
        empty_record.cleanup_observations.clone_from(&observations);
        persist_record_update(host, domain, empty_record)?;
    }

    if domain.state == DomainJournalState::EmptyProven {
        persist_transition(host, domain, DomainJournalState::RemoveIntended)?;
    }
    let token = domain.token()?;
    host.remove_leaf_exact(token, &leaf_name, identity)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    if !host
        .prove_leaf_absent(token, &leaf_name)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?
    {
        return Err(CgroupError::ReconciliationRequired {
            phase: "cleanup-remove-readback",
            leaf_name,
            leaf_identity: Some(identity),
            reason: "removed leaf remained visible".into(),
        });
    }
    persist_transition(host, domain, DomainJournalState::Removed)?;
    let lock = domain.lock.as_ref().ok_or(CgroupError::InvalidState(
        "removed domain lost its lock token",
    ))?;
    host.release_delegation_lock(lock)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    domain.lock.take();

    let evidence = CgroupCleanupEvidence {
        journal_record: domain.record.clone(),
        request_digest: domain.record.request_digest.clone(),
        leaf_name,
        leaf_identity: identity,
        requested_limits: domain.record.requested_limits,
        read_back_limits: domain
            .record
            .read_back_limits
            .ok_or(CgroupError::InvalidState(
                "cleanup limit read-back is absent",
            ))?,
        kill_value: CGROUP_KILL_VALUE.to_vec(),
        observations,
        stable_empty_reads: 2,
        leaf_removed: true,
        surviving_processes: 0,
    };
    evidence.validate()?;
    Ok(evidence)
}

/// Answers whether the kernel currently reports the live domain unpopulated.
///
/// This is the one nonblocking emptiness question a live domain may ask, and
/// the answer is a `cgroup.events` read performed through the retained
/// delegation lock and the exact leaf identity, never a directory listing and
/// never a cached value. It retains no evidence and can therefore never stand
/// in for the reaping proof: `cleanup_domain` still has to establish the
/// canonical `populated 0` plus two empty `cgroup.procs` endpoint before any
/// proof is minted.
pub(crate) fn observe_domain_unpopulated<H: CgroupIo>(
    host: &mut H,
    domain: &PreparedDomain,
) -> Result<bool, CgroupError> {
    let leaf_name = domain.record.leaf_name.clone();
    let identity = domain.leaf_identity()?;
    let token = domain.token()?;
    let raw = host
        .read_leaf_file(
            token,
            &leaf_name,
            identity,
            LeafFile::CgroupEvents,
            MAX_CGROUP_EVENTS_BYTES,
        )
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    let events = parse_cgroup_events(&raw)
        .map_err(|error| error.into_reconciliation(&leaf_name, identity, "live-events"))?;
    Ok(!events.populated)
}

/// Kills every process in a live domain, durably recording the intent first.
///
/// This is the ordered kill half of [`cleanup_domain`], split out so a live
/// domain can be terminated the moment the supervisor asks without also
/// spending the bounded drain budget in the same call. The order is the one
/// `cleanup_domain` already establishes and must not be inverted: `Killing` is
/// persisted and `fsync`ed **before** `cgroup.kill` is written, so a crash
/// between the two leaves an authoritative record that a kill may have landed.
///
/// `cgroup.kill` is idempotent, so a later `cleanup_domain` reissuing the exact
/// same value is a reconciliation rather than a second effect. Nothing here
/// observes emptiness, retains an observation, or advances the record past
/// `Killing`; only `cleanup_domain` can do that, and only from real readbacks.
pub(crate) fn terminate_domain<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
) -> Result<(), CgroupError> {
    if matches!(
        domain.state,
        DomainJournalState::EmptyProven
            | DomainJournalState::RemoveIntended
            | DomainJournalState::Removed
    ) {
        return Ok(());
    }
    if !matches!(
        domain.state,
        DomainJournalState::Prepared
            | DomainJournalState::AttachIntended
            | DomainJournalState::Attached
            | DomainJournalState::Held
            | DomainJournalState::ReleaseIntended
            | DomainJournalState::Released
            | DomainJournalState::Killing
    ) {
        return Err(CgroupError::InvalidState(
            "whole-domain termination requires a configured live-domain journal state",
        ));
    }
    let leaf_name = domain.record.leaf_name.clone();
    let identity = domain.leaf_identity()?;
    if domain.state != DomainJournalState::Killing {
        persist_transition(host, domain, DomainJournalState::Killing)?;
    }
    let token = domain.token()?;
    host.write_leaf_file(
        token,
        &leaf_name,
        identity,
        LeafWriteFile::CgroupKill,
        CGROUP_KILL_VALUE,
    )
    .map_err(|failure| CgroupError::reconciliation(&leaf_name, Some(identity), failure))?;
    Ok(())
}

fn persist_transition<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    state: DomainJournalState,
) -> Result<(), CgroupError> {
    let mut record = domain.record.clone();
    record.state = state;
    persist_record_update(host, domain, record)
}

fn persist_record_update<H: CgroupIo>(
    host: &mut H,
    domain: &mut PreparedDomain,
    record: DomainJournalRecord,
) -> Result<(), CgroupError> {
    let leaf_name = record.leaf_name.clone();
    let identity = record.leaf_identity;
    record.validate().map_err(|error| {
        if let Some(identity) = identity {
            error.into_reconciliation(&leaf_name, identity, "journal-transition-validation")
        } else {
            error
        }
    })?;
    host.persist_journal(&record)
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, identity, failure))?;
    host.sync_journal()
        .map_err(|failure| CgroupError::reconciliation(&leaf_name, identity, failure))?;
    let state = record.state;
    domain.record = record;
    domain.state = state;
    Ok(())
}

fn collect_stable_empty_observations<H: CgroupIo>(
    host: &mut H,
    domain: &PreparedDomain,
    leaf_name: &str,
    identity: CgroupObjectIdentity,
    max_attempts: u8,
) -> Result<Vec<RawCleanupObservation>, CgroupError> {
    let mut observations = Vec::new();
    let mut evidence_bytes = 0usize;
    let mut sequence = 0u32;
    for attempt in 1..=max_attempts {
        let token = domain.token()?;
        let events_raw = host
            .read_leaf_file(
                token,
                leaf_name,
                identity,
                LeafFile::CgroupEvents,
                MAX_CGROUP_EVENTS_BYTES,
            )
            .map_err(|failure| CgroupError::reconciliation(leaf_name, Some(identity), failure))?;
        let events = parse_cgroup_events(&events_raw)
            .map_err(|error| error.into_reconciliation(leaf_name, identity, "cleanup-events"))?;
        append_evidence(
            &mut observations,
            &mut evidence_bytes,
            &mut sequence,
            attempt,
            LeafFile::CgroupEvents,
            events_raw,
        )?;
        let first_raw = host
            .read_leaf_file(
                token,
                leaf_name,
                identity,
                LeafFile::CgroupProcs,
                MAX_CGROUP_PROCS_BYTES,
            )
            .map_err(|failure| CgroupError::reconciliation(leaf_name, Some(identity), failure))?;
        let first = parse_cgroup_procs(&first_raw).map_err(|error| {
            error.into_reconciliation(leaf_name, identity, "cleanup-procs-first")
        })?;
        append_evidence(
            &mut observations,
            &mut evidence_bytes,
            &mut sequence,
            attempt,
            LeafFile::CgroupProcs,
            first_raw,
        )?;
        host.poll_barrier()
            .map_err(|failure| CgroupError::reconciliation(leaf_name, Some(identity), failure))?;
        let second_raw = host
            .read_leaf_file(
                token,
                leaf_name,
                identity,
                LeafFile::CgroupProcs,
                MAX_CGROUP_PROCS_BYTES,
            )
            .map_err(|failure| CgroupError::reconciliation(leaf_name, Some(identity), failure))?;
        let second = parse_cgroup_procs(&second_raw).map_err(|error| {
            error.into_reconciliation(leaf_name, identity, "cleanup-procs-second")
        })?;
        append_evidence(
            &mut observations,
            &mut evidence_bytes,
            &mut sequence,
            attempt,
            LeafFile::CgroupProcs,
            second_raw,
        )?;
        if !events.populated && first.is_empty() && second.is_empty() {
            return Ok(observations);
        }
    }
    Err(CgroupError::CleanupIncomplete {
        leaf_name: leaf_name.into(),
        attempts: max_attempts,
        bounded_observations: observations,
    })
}

fn append_evidence(
    observations: &mut Vec<RawCleanupObservation>,
    total: &mut usize,
    sequence: &mut u32,
    attempt: u8,
    file: LeafFile,
    bytes: Vec<u8>,
) -> Result<(), CgroupError> {
    *total = total
        .checked_add(bytes.len())
        .ok_or(CgroupError::EvidenceLimitExceeded)?;
    if *total > MAX_CLEANUP_EVIDENCE_BYTES {
        return Err(CgroupError::EvidenceLimitExceeded);
    }
    *sequence = sequence
        .checked_add(1)
        .ok_or(CgroupError::EvidenceLimitExceeded)?;
    observations.push(RawCleanupObservation {
        sequence: *sequence,
        attempt,
        file,
        bytes,
    });
    Ok(())
}

fn validate_observation_sequence(
    observations: &[RawCleanupObservation],
    require_endpoint: bool,
) -> Result<(), CgroupError> {
    if observations.is_empty() {
        return if require_endpoint {
            Err(CgroupError::InvalidObservation {
                field: "cleanup.observations",
                reason: "missing endpoint observations".into(),
            })
        } else {
            Ok(())
        };
    }
    if !observations.len().is_multiple_of(3) {
        return Err(CgroupError::InvalidObservation {
            field: "cleanup.observations",
            reason: "every attempt must contain exactly three observations".into(),
        });
    }
    let mut total = 0usize;
    let attempts = observations.len() / 3;
    if attempts > usize::from(MAX_CLEANUP_ATTEMPTS) {
        return Err(CgroupError::EvidenceLimitExceeded);
    }
    for (attempt_index, chunk) in observations.chunks_exact(3).enumerate() {
        let attempt =
            u8::try_from(attempt_index + 1).map_err(|_| CgroupError::EvidenceLimitExceeded)?;
        for (offset, observation) in chunk.iter().enumerate() {
            let expected_sequence = u32::try_from(attempt_index * 3 + offset + 1)
                .map_err(|_| CgroupError::EvidenceLimitExceeded)?;
            if observation.sequence != expected_sequence || observation.attempt != attempt {
                return Err(CgroupError::InvalidObservation {
                    field: "cleanup.observations",
                    reason: "attempts and sequence numbers must be contiguous and canonical".into(),
                });
            }
            total = total
                .checked_add(observation.bytes.len())
                .ok_or(CgroupError::EvidenceLimitExceeded)?;
        }
        if chunk[0].file != LeafFile::CgroupEvents
            || chunk[1].file != LeafFile::CgroupProcs
            || chunk[2].file != LeafFile::CgroupProcs
        {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.observations",
                reason: "each attempt must be events, procs, procs".into(),
            });
        }
        let events = parse_cgroup_events(&chunk[0].bytes)?;
        let first = parse_cgroup_procs(&chunk[1].bytes)?;
        let second = parse_cgroup_procs(&chunk[2].bytes)?;
        let endpoint = !events.populated && first.is_empty() && second.is_empty();
        if endpoint && attempt_index + 1 != attempts {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.observations",
                reason: "observations continued after a proven endpoint".into(),
            });
        }
        if require_endpoint && attempt_index + 1 == attempts && !endpoint {
            return Err(CgroupError::InvalidObservation {
                field: "cleanup.observations",
                reason: "final attempt does not prove populated 0 and two empty process reads"
                    .into(),
            });
        }
    }
    if total > MAX_CLEANUP_EVIDENCE_BYTES {
        return Err(CgroupError::EvidenceLimitExceeded);
    }
    Ok(())
}

fn normalized_leaf_name(nonce: &str) -> Result<String, CgroupError> {
    if nonce.len() != DOMAIN_NONCE_HEX_CHARS
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CgroupError::InvalidRequest {
            field: "leaf_nonce",
            reason: format!(
                "must contain exactly {DOMAIN_NONCE_HEX_CHARS} lowercase hexadecimal characters (256 bits)"
            ),
        });
    }
    Ok(format!("{DOMAIN_NAME_PREFIX}{nonce}"))
}

fn validate_leaf_name(name: &str) -> Result<(), CgroupError> {
    let nonce = name
        .strip_prefix(DOMAIN_NAME_PREFIX)
        .ok_or(CgroupError::InvalidObservation {
            field: "leaf_name",
            reason: "missing fixed domain prefix".into(),
        })?;
    normalized_leaf_name(nonce).map(|_| ())
}

/// Reports whether a directory name is a command-domain leaf name.
///
/// This is the same grammar `validate_leaf_name` enforces, exposed so that an
/// absence observation cannot drift into recognizing a different set of names
/// than the one `prepare_domain` mints. A second copy of the grammar would be
/// exactly the substitution that makes an absence claim meaningless.
pub(crate) fn is_domain_leaf_name(name: &str) -> bool {
    validate_leaf_name(name).is_ok()
}

fn validate_identity_text(field: &'static str, value: &str) -> Result<(), CgroupError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_TEXT_BYTES
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(CgroupError::InvalidRequest {
            field,
            reason: "must be nonblank, bounded, and contain no ASCII control/space bytes".into(),
        });
    }
    Ok(())
}

fn validate_sha256_text(field: &'static str, value: &str) -> Result<(), CgroupError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CgroupError::InvalidRequest {
            field,
            reason: "must be exactly 64 lowercase hexadecimal SHA-256 characters".into(),
        });
    }
    Ok(())
}

/// Parses exact `memory.max`, `memory.swap.max`, or `pids.max` syntax.
pub(crate) fn parse_limit(bytes: &[u8], allow_max: bool) -> Result<LimitValue, CgroupError> {
    let text = exact_kernel_line(bytes, "cgroup limit", 64)?;
    if text == "max" {
        return if allow_max {
            Ok(LimitValue::Max)
        } else {
            Err(CgroupError::InvalidObservation {
                field: "cgroup limit",
                reason: "`max` is not accepted for this control".into(),
            })
        };
    }
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(CgroupError::InvalidObservation {
            field: "cgroup limit",
            reason: "expected canonical unsigned decimal or `max`".into(),
        });
    }
    let value = text
        .parse::<u64>()
        .map_err(|_| CgroupError::InvalidObservation {
            field: "cgroup limit",
            reason: "numeric value overflowed u64".into(),
        })?;
    Ok(LimitValue::Value(value))
}

/// Parses exact `cgroup.events` syntax and rejects unknown/duplicate fields.
pub(crate) fn parse_cgroup_events(bytes: &[u8]) -> Result<CgroupEvents, CgroupError> {
    if bytes.is_empty() || bytes.len() > MAX_CGROUP_EVENTS_BYTES || !bytes.ends_with(b"\n") {
        return Err(CgroupError::InvalidObservation {
            field: "cgroup.events",
            reason: "must be nonempty, bounded, and newline-terminated".into(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CgroupError::InvalidObservation {
        field: "cgroup.events",
        reason: "must contain UTF-8 ASCII fields".into(),
    })?;
    let mut populated = None;
    let mut frozen = None;
    for line in text.lines() {
        let (name, value) = line
            .split_once(' ')
            .ok_or(CgroupError::InvalidObservation {
                field: "cgroup.events",
                reason: "each field must contain exactly one separator".into(),
            })?;
        if value.contains(' ') || value.contains('\t') {
            return Err(CgroupError::InvalidObservation {
                field: "cgroup.events",
                reason: "event values must be canonical".into(),
            });
        }
        let value = match value {
            "0" => false,
            "1" => true,
            _ => {
                return Err(CgroupError::InvalidObservation {
                    field: "cgroup.events",
                    reason: "event values must be 0 or 1".into(),
                });
            }
        };
        match name {
            "populated" if populated.replace(value).is_none() => {}
            "frozen" if frozen.replace(value).is_none() => {}
            "populated" | "frozen" => {
                return Err(CgroupError::InvalidObservation {
                    field: "cgroup.events",
                    reason: "duplicate event field".into(),
                });
            }
            _ => {
                return Err(CgroupError::UnsupportedKernelApi {
                    api: "cgroup.events",
                    reason: format!("unmodeled field `{name}`"),
                });
            }
        }
    }
    Ok(CgroupEvents {
        populated: populated.ok_or(CgroupError::InvalidObservation {
            field: "cgroup.events",
            reason: "missing populated field".into(),
        })?,
        frozen,
    })
}

/// Parses bounded `cgroup.procs` bytes into unique nonzero process IDs.
pub(crate) fn parse_cgroup_procs(bytes: &[u8]) -> Result<Vec<u32>, CgroupError> {
    if bytes.len() > MAX_CGROUP_PROCS_BYTES {
        return Err(CgroupError::InvalidObservation {
            field: "cgroup.procs",
            reason: "observation exceeded its hard byte bound".into(),
        });
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err(CgroupError::InvalidObservation {
            field: "cgroup.procs",
            reason: "nonempty observation must be newline-terminated".into(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CgroupError::InvalidObservation {
        field: "cgroup.procs",
        reason: "must contain canonical ASCII process IDs".into(),
    })?;
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for line in text.lines() {
        if line.is_empty()
            || !line.bytes().all(|byte| byte.is_ascii_digit())
            || (line.len() > 1 && line.starts_with('0'))
        {
            return Err(CgroupError::InvalidObservation {
                field: "cgroup.procs",
                reason: "process IDs must be canonical unsigned decimal".into(),
            });
        }
        let pid = line
            .parse::<u32>()
            .map_err(|_| CgroupError::InvalidObservation {
                field: "cgroup.procs",
                reason: "process ID overflowed u32".into(),
            })?;
        if pid == 0 || !seen.insert(pid) {
            return Err(CgroupError::InvalidObservation {
                field: "cgroup.procs",
                reason: "process IDs must be nonzero and unique".into(),
            });
        }
        result.push(pid);
    }
    Ok(result)
}

fn parse_bool01(bytes: &[u8], field: &'static str) -> Result<bool, CgroupError> {
    match exact_kernel_line(bytes, field, 8)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(CgroupError::InvalidObservation {
            field,
            reason: "expected 0 or 1".into(),
        }),
    }
}

fn parse_controller_set(bytes: &[u8]) -> Result<BTreeSet<DomainController>, CgroupError> {
    let text = exact_kernel_line(bytes, "cgroup.subtree_control", 128)?;
    let mut result = BTreeSet::new();
    for name in text.split(' ') {
        let controller = match name {
            "memory" => DomainController::Memory,
            "pids" => DomainController::Pids,
            "" => {
                return Err(CgroupError::InvalidObservation {
                    field: "cgroup.subtree_control",
                    reason: "controller spacing is not canonical".into(),
                });
            }
            other => {
                return Err(CgroupError::UnsupportedKernelApi {
                    api: "cgroup.subtree_control",
                    reason: format!("unmodeled enabled controller `{other}`"),
                });
            }
        };
        if !result.insert(controller) {
            return Err(CgroupError::InvalidObservation {
                field: "cgroup.subtree_control",
                reason: "duplicate controller".into(),
            });
        }
    }
    Ok(result)
}

fn exact_kernel_line<'a>(
    bytes: &'a [u8],
    field: &'static str,
    max: usize,
) -> Result<&'a str, CgroupError> {
    if bytes.is_empty() || bytes.len() > max || !bytes.ends_with(b"\n") {
        return Err(CgroupError::InvalidObservation {
            field,
            reason: "must be nonempty, bounded, and newline-terminated".into(),
        });
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| {
        CgroupError::InvalidObservation {
            field,
            reason: "must be UTF-8 ASCII".into(),
        }
    })?;
    if text.contains('\n') || text.contains('\r') || text.contains('\t') {
        return Err(CgroupError::InvalidObservation {
            field,
            reason: "contains noncanonical whitespace".into(),
        });
    }
    Ok(text)
}

/// Fail-closed cgroup-domain error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CgroupError {
    InvalidRequest {
        field: &'static str,
        reason: String,
    },
    UnsupportedKernelApi {
        api: &'static str,
        reason: String,
    },
    InvalidObservation {
        field: &'static str,
        reason: String,
    },
    NoInternalProcessViolation {
        processes: Vec<u32>,
    },
    UnexpectedChildren {
        children: Vec<String>,
    },
    LimitMismatch {
        file: LeafFile,
        requested: String,
        observed: String,
    },
    Host(CgroupIoFailure),
    /// Authoritative history proves that an earlier episode already committed
    /// this globally unique core effect. No new effect was attempted by the
    /// rejected request, but the prior episode must be reconciled and the
    /// effect identifier must never be retried.
    PreviouslyCommitted {
        operation: &'static str,
        reason: String,
    },
    ReconciliationRequired {
        phase: &'static str,
        leaf_name: String,
        leaf_identity: Option<CgroupObjectIdentity>,
        reason: String,
    },
    ProbeReconciliationRequired {
        phase: &'static str,
        reason: String,
    },
    CleanupIncomplete {
        leaf_name: String,
        attempts: u8,
        bounded_observations: Vec<RawCleanupObservation>,
    },
    LockReleaseFailed {
        primary: Option<Box<CgroupError>>,
        release: CgroupIoFailure,
    },
    EvidenceLimitExceeded,
    InvalidState(&'static str),
}

impl CgroupError {
    /// Maps a pre-leaf host refusal while preserving an authoritative prior
    /// effect commitment as the distinct non-retryable terminal category.
    pub(crate) fn host_before_leaf(failure: CgroupIoFailure) -> Self {
        let failure = bounded_host_failure(failure);
        if failure.certainty == EffectCertainty::PriorEffectCommitted {
            Self::PreviouslyCommitted {
                operation: failure.operation,
                reason: failure.detail,
            }
        } else {
            Self::Host(failure)
        }
    }

    fn reconciliation(
        leaf_name: &str,
        leaf_identity: Option<CgroupObjectIdentity>,
        failure: CgroupIoFailure,
    ) -> Self {
        let failure = bounded_host_failure(failure);
        Self::ReconciliationRequired {
            phase: failure.operation,
            leaf_name: leaf_name.into(),
            leaf_identity,
            reason: format!("{:?}: {}", failure.certainty, failure.detail),
        }
    }

    fn probe_reconciliation(failure: CgroupIoFailure) -> Self {
        let failure = bounded_host_failure(failure);
        Self::ProbeReconciliationRequired {
            phase: failure.operation,
            reason: format!("{:?}: {}", failure.certainty, failure.detail),
        }
    }

    fn into_reconciliation(
        self,
        leaf_name: &str,
        leaf_identity: CgroupObjectIdentity,
        phase: &'static str,
    ) -> Self {
        Self::ReconciliationRequired {
            phase,
            leaf_name: leaf_name.into(),
            leaf_identity: Some(leaf_identity),
            reason: self.to_string(),
        }
    }
}

fn bounded_host_failure(mut failure: CgroupIoFailure) -> CgroupIoFailure {
    if failure.detail.len() > MAX_HOST_ERROR_BYTES {
        let mut boundary = MAX_HOST_ERROR_BYTES;
        while !failure.detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        failure.detail.truncate(boundary);
    }
    failure
}

impl Display for CgroupError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest { field, reason } => {
                write!(formatter, "invalid cgroup request {field}: {reason}")
            }
            Self::UnsupportedKernelApi { api, reason } => {
                write!(formatter, "unsupported required kernel API {api}: {reason}")
            }
            Self::InvalidObservation { field, reason } => {
                write!(formatter, "invalid cgroup observation {field}: {reason}")
            }
            Self::NoInternalProcessViolation { processes } => write!(
                formatter,
                "delegation violates no-internal-process rule: {processes:?}"
            ),
            Self::UnexpectedChildren { children } => {
                write!(
                    formatter,
                    "delegation has unexpected children: {children:?}"
                )
            }
            Self::LimitMismatch {
                file,
                requested,
                observed,
            } => write!(
                formatter,
                "{} read-back mismatch: requested {requested}, observed {observed}",
                file.name()
            ),
            Self::Host(failure) => write!(
                formatter,
                "cgroup host operation {} failed ({:?}): {}",
                failure.operation, failure.certainty, failure.detail
            ),
            Self::PreviouslyCommitted { operation, reason } => write!(
                formatter,
                "command effect was previously committed according to {operation}: {reason}"
            ),
            Self::ReconciliationRequired {
                phase,
                leaf_name,
                reason,
                ..
            } => write!(
                formatter,
                "cgroup leaf {leaf_name} requires reconciliation after {phase}: {reason}"
            ),
            Self::ProbeReconciliationRequired { phase, reason } => write!(
                formatter,
                "delegation preflight probe requires reconciliation after {phase}: {reason}"
            ),
            Self::CleanupIncomplete {
                leaf_name,
                attempts,
                ..
            } => write!(
                formatter,
                "cgroup leaf {leaf_name} was not stably empty after {attempts} attempts"
            ),
            Self::LockReleaseFailed { primary, release } => {
                if let Some(primary) = primary {
                    write!(
                        formatter,
                        "{primary}; additionally failed to release delegation lock at {}: {}",
                        release.operation, release.detail
                    )
                } else {
                    write!(
                        formatter,
                        "failed to release delegation lock at {}: {}",
                        release.operation, release.detail
                    )
                }
            }
            Self::EvidenceLimitExceeded => {
                formatter.write_str("cgroup cleanup evidence exceeded its hard bound")
            }
            Self::InvalidState(reason) => write!(formatter, "invalid cgroup state: {reason}"),
        }
    }
}

impl std::error::Error for CgroupError {}

#[cfg(test)]
mod tests;
