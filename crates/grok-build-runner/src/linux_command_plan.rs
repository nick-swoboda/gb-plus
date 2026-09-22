//! Canonical, non-admissible production command plan for the future Linux backend.
//!
//! This module deliberately stops before process creation.  It joins a complete
//! durable command-effect authority to independently restored grant/policy
//! contracts and to the identities and mandatory controls a production Linux
//! containment transition would have to consume.  Validation and canonical
//! encoding are not release authority; no value in this module can execute or
//! release a process.

#![allow(
    dead_code,
    missing_docs,
    reason = "Gate-1 semantic contract is intentionally unwired until every native control is implemented"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::path::{Component, Path};

use grok_build_core::{
    CONTRACT_VERSION, CompiledExecutionPolicy, Digest, ExecutionNetwork, ExecutionPolicy,
    IssuedWorkspaceGrant, MutationMode, PathScope, ResourceLimits,
};
use serde::{Deserialize, Serialize};

use crate::linux_cgroup_io::LinuxCommandPlanDurableCommitReceipt;
use crate::linux_containment::{
    CgroupObjectIdentity, DOMAIN_NAME_PREFIX, DOMAIN_NONCE_HEX_CHARS, LinuxNativeLaunchIdentity,
    PrepareDomainRequest, RequestedDomainLimits,
};
use crate::wire::{
    CommandEffectAuthorityV1, RunnerRequest, RunnerRole, WireEnvironmentVariable,
    WireExecutionNetwork, WireExecutionPolicyRequest, WireMutationMode, WirePathScope,
    WireResourceLimits, WireWorkspaceGrant,
};

/// Version of the Linux production command-plan schema.
///
/// Version 5 requires committed Landlock artifacts and both network and namespace
/// seccomp filters. Older layouts are incompatible and have no automatic migration.
/// Journal opening decodes each canonical plan through `decode_exact`; a version
/// refusal reports both the stored and required versions.
const LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION: u32 = 5;
/// Digest domain separator for the canonical plan bytes.
///
/// It moves with the schema version, so digests of two schema versions can
/// never denote the same artefact even if some future document happened to
/// encode identically.
pub(crate) const LINUX_PRODUCTION_COMMAND_PLAN_DOMAIN: &[u8] =
    b"grok-build/linux-production-command-plan/v5\0";
const LINUX_PRODUCTION_HELD_RELEASE_SCHEMA: &str = "grok-build/linux-production-held-release/v1";
const LINUX_SERVICE_SETUP_DESCRIPTOR_SCHEMA: &str = "grok-build/linux-service-setup-descriptors/v1";
const LINUX_SERVICE_CHILD_LAUNCH_CLOSURE_SCHEMA: &str =
    "grok-build/linux-service-child-launch-closure/v1";
const LINUX_COMMAND_RUNTIME_EVIDENCE_SCHEMA: &str = "grok-build/linux-command-runtime-evidence/v1";
const LINUX_COMMAND_CLEANUP_EVIDENCE_SCHEMA: &str = "grok-build/linux-command-cleanup-evidence/v1";
const MAX_CANONICAL_PLAN_BYTES: usize = 512 * 1_024;
const MAX_ID_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_VERSION_BYTES: usize = 256;
const MAX_RETAINED_OBJECTS: usize = 1_024;
const MAX_MOUNTS: usize = 512;
const MAX_RUNTIME_OBJECTS: usize = 256;
const MAX_ENVIRONMENT_ENTRIES: usize = 128;
const MAX_SCOPE_ENTRIES: usize = 256;
const MAX_AUTHENTICATED_FILE_BYTES: u64 = 128 * 1_024 * 1_024;
const MAX_SETUP_CHANNEL_BYTES: u64 = 1_024 * 1_024;
const MAX_LANDLOCK_ABI: u32 = 64;
const MAX_WALL_TIME_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_OUTPUT_BYTES: u64 = 64 * 1_024 * 1_024;
const MAX_PROCESSES: u32 = 256;
const MAX_MEMORY_BYTES: u64 = 1 << 40;
const REQUIRED_SETUP_SEAL_BITS: u32 = 0x0000_003f;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const FILE_TYPE_MASK: u32 = 0o170_000;
const REGULAR_FILE_MODE: u32 = 0o100_000;
const DIRECTORY_MODE: u32 = 0o040_000;
const SET_ID_MODE: u32 = 0o006_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LinuxProductionCommandPlanError {
    Invalid(String),
    Encode(String),
    Decode(String),
    NonCanonical,
    TooLarge { actual: usize },
}

impl Display for LinuxProductionCommandPlanError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Encode(message) => {
                write!(formatter, "cannot encode Linux command plan: {message}")
            }
            Self::Decode(message) => {
                write!(formatter, "cannot decode Linux command plan: {message}")
            }
            Self::NonCanonical => formatter.write_str("Linux command plan is not canonical JSON"),
            Self::TooLarge { actual } => write!(
                formatter,
                "Linux command plan is {actual} bytes; limit is {MAX_CANONICAL_PLAN_BYTES}"
            ),
        }
    }
}

impl std::error::Error for LinuxProductionCommandPlanError {}

fn invalid(message: impl Into<String>) -> LinuxProductionCommandPlanError {
    LinuxProductionCommandPlanError::Invalid(message.into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxWorkspaceIdentityV1 {
    canonical_root: String,
    device_id: u64,
    inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCompiledGrantV1 {
    contract: WireWorkspaceGrant,
    identity: LinuxWorkspaceIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCompiledPolicyV1 {
    grant_hash: Digest,
    workspace_root: String,
    request: WireExecutionPolicyRequest,
    policy_hash: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCompiledAuthorityV1 {
    grant: LinuxCompiledGrantV1,
    policy: LinuxCompiledPolicyV1,
}

impl LinuxCompiledAuthorityV1 {
    fn from_trusted(
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        grant
            .validate_integrity()
            .map_err(|error| invalid(format!("workspace grant integrity failed: {error}")))?;
        policy
            .validate_integrity(grant)
            .map_err(|error| invalid(format!("compiled policy integrity failed: {error}")))?;
        let canonical_root = grant
            .identity()
            .canonical_root()
            .to_str()
            .ok_or_else(|| invalid("workspace root is not normalized UTF-8"))?
            .to_owned();
        let wire_grant = WireWorkspaceGrant::try_from(grant.contract())
            .map_err(|error| invalid(format!("cannot mirror compiled grant: {error}")))?;
        let contract = policy.contract();
        let workspace_root = contract
            .workspace_root
            .to_str()
            .ok_or_else(|| invalid("compiled policy root is not normalized UTF-8"))?
            .to_owned();
        let request = wire_policy_request(contract)?;
        Ok(Self {
            grant: LinuxCompiledGrantV1 {
                contract: wire_grant,
                identity: LinuxWorkspaceIdentityV1 {
                    canonical_root,
                    device_id: grant.identity().device_id(),
                    inode: grant.identity().inode(),
                },
            },
            policy: LinuxCompiledPolicyV1 {
                grant_hash: contract.grant_hash.clone(),
                workspace_root,
                request,
                policy_hash: contract.policy_hash.clone(),
            },
        })
    }

    fn native_contracts(
        &self,
    ) -> Result<(grok_build_core::WorkspaceGrant, ExecutionPolicy), LinuxProductionCommandPlanError>
    {
        let grant = self
            .grant
            .contract
            .clone()
            .into_native()
            .map_err(|error| invalid(format!("compiled grant mirror is invalid: {error}")))?;
        grant
            .validate()
            .map_err(|error| invalid(format!("compiled grant is invalid: {error}")))?;
        validate_absolute_path(
            &self.grant.identity.canonical_root,
            "workspace identity root",
        )?;
        if self.grant.identity.device_id == 0 || self.grant.identity.inode == 0 {
            return Err(invalid(
                "workspace identity device and inode must be nonzero",
            ));
        }
        if grant.canonical_root != Path::new(&self.grant.identity.canonical_root) {
            return Err(invalid(
                "compiled grant root differs from its independently retained identity",
            ));
        }
        validate_absolute_path(&self.policy.workspace_root, "compiled policy root")?;
        let request = self
            .policy
            .request
            .clone()
            .into_native()
            .map_err(|error| invalid(format!("compiled policy mirror is invalid: {error}")))?;
        let policy = ExecutionPolicy {
            policy_id: request.policy_id,
            grant_hash: self.policy.grant_hash.clone(),
            workspace_root: self.policy.workspace_root.clone().into(),
            read_scopes: request.read_scopes,
            write_scopes: request.write_scopes,
            environment: request.environment,
            network: request.network,
            mutation_mode: request.mutation_mode,
            resource_limits: request.resource_limits,
            approval_id: request.approval_id,
            policy_hash: self.policy.policy_hash.clone(),
        };
        policy
            .validate_against(&grant)
            .map_err(|error| invalid(format!("compiled grant/policy crossing failed: {error}")))?;
        let computed = policy
            .computed_hash()
            .map_err(|error| invalid(format!("compiled policy hash failed: {error}")))?;
        if computed != policy.policy_hash {
            return Err(invalid(
                "compiled policy hash differs from its canonical contract",
            ));
        }
        Ok((grant, policy))
    }
}

fn wire_policy_request(
    policy: &ExecutionPolicy,
) -> Result<WireExecutionPolicyRequest, LinuxProductionCommandPlanError> {
    if policy.read_scopes.len() > MAX_SCOPE_ENTRIES
        || policy.write_scopes.len() > MAX_SCOPE_ENTRIES
        || policy.environment.len() > MAX_ENVIRONMENT_ENTRIES
    {
        return Err(invalid(
            "compiled policy collections exceed Linux plan bounds",
        ));
    }
    let read_scopes = policy
        .read_scopes
        .iter()
        .map(wire_path_scope)
        .collect::<Result<Vec<_>, _>>()?;
    let write_scopes = policy
        .write_scopes
        .iter()
        .map(wire_path_scope)
        .collect::<Result<Vec<_>, _>>()?;
    let environment = policy
        .environment
        .iter()
        .map(|entry| WireEnvironmentVariable {
            name: entry.name.clone(),
            value: entry.value.clone(),
        })
        .collect();
    Ok(WireExecutionPolicyRequest {
        policy_id: policy.policy_id.clone(),
        read_scopes,
        write_scopes,
        environment,
        network: match policy.network {
            ExecutionNetwork::None => WireExecutionNetwork::None,
            ExecutionNetwork::FullForAction => WireExecutionNetwork::FullForAction,
        },
        mutation_mode: match policy.mutation_mode {
            MutationMode::ReadOnly => WireMutationMode::ReadOnly,
            MutationMode::ShadowWorkspace => WireMutationMode::ShadowWorkspace,
        },
        resource_limits: WireResourceLimits {
            wall_time_ms: policy.resource_limits.wall_time_ms,
            max_output_bytes: policy.resource_limits.max_output_bytes,
            max_processes: policy.resource_limits.max_processes,
            max_memory_bytes: policy.resource_limits.max_memory_bytes,
        },
        approval_id: policy.approval_id.clone(),
    })
}

fn wire_path_scope(scope: &PathScope) -> Result<WirePathScope, LinuxProductionCommandPlanError> {
    match scope {
        PathScope::Workspace => Ok(WirePathScope::Workspace),
        PathScope::Relative(path) => Ok(WirePathScope::Relative {
            path: path
                .to_str()
                .ok_or_else(|| invalid("compiled policy scope is not UTF-8"))?
                .to_owned(),
        }),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxRetainedObjectKindV1 {
    Directory,
    RegularFile,
    SealedMemfd,
    CgroupDirectory,
    CgroupControlFile,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxRetainedObjectIdentityV1 {
    object_id: String,
    kind: LinuxRetainedObjectKindV1,
    device_id: u64,
    inode: u64,
    mount_id: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    link_count: u64,
    byte_length: Option<u64>,
}

impl LinuxRetainedObjectIdentityV1 {
    fn validate(&self) -> Result<(), LinuxProductionCommandPlanError> {
        validate_identifier(&self.object_id, "retained object ID")?;
        if self.device_id == 0 || self.inode == 0 || self.mount_id == 0 {
            return Err(invalid(format!(
                "retained object {} has a zero device, inode, or mount identity",
                self.object_id
            )));
        }
        let expected_type = match self.kind {
            LinuxRetainedObjectKindV1::Directory | LinuxRetainedObjectKindV1::CgroupDirectory => {
                DIRECTORY_MODE
            }
            LinuxRetainedObjectKindV1::RegularFile
            | LinuxRetainedObjectKindV1::SealedMemfd
            | LinuxRetainedObjectKindV1::CgroupControlFile => REGULAR_FILE_MODE,
        };
        if self.mode & FILE_TYPE_MASK != expected_type {
            return Err(invalid(format!(
                "retained object {} mode differs from its declared kind",
                self.object_id
            )));
        }
        match self.kind {
            LinuxRetainedObjectKindV1::RegularFile
                if self.link_count == 0
                    || self.byte_length.is_none_or(|length| {
                        length == 0 || length > MAX_AUTHENTICATED_FILE_BYTES
                    }) =>
            {
                return Err(invalid(format!(
                    "retained regular file {} requires link and byte-length identity",
                    self.object_id
                )));
            }
            LinuxRetainedObjectKindV1::SealedMemfd
                if self.link_count != 0
                    || self.byte_length.is_none_or(|length| {
                        length == 0 || length > MAX_AUTHENTICATED_FILE_BYTES
                    }) =>
            {
                return Err(invalid(format!(
                    "retained sealed memfd {} requires zero links and nonzero byte length",
                    self.object_id
                )));
            }
            LinuxRetainedObjectKindV1::Directory
            | LinuxRetainedObjectKindV1::CgroupDirectory
            | LinuxRetainedObjectKindV1::CgroupControlFile
                if self.link_count == 0 || self.byte_length.is_some() =>
            {
                return Err(invalid(format!(
                    "retained directory/control {} has invalid link or byte-length identity",
                    self.object_id
                )));
            }
            _ => {}
        }
        Ok(())
    }

    const fn is_directory(&self) -> bool {
        matches!(
            self.kind,
            LinuxRetainedObjectKindV1::Directory | LinuxRetainedObjectKindV1::CgroupDirectory
        )
    }

    const fn is_regular_or_sealed(&self) -> bool {
        matches!(
            self.kind,
            LinuxRetainedObjectKindV1::RegularFile | LinuxRetainedObjectKindV1::SealedMemfd
        )
    }

    /// Production mint for one retained-object identity.
    ///
    /// The caller must already hold the descriptor the observation came from.
    /// Nothing here may be chosen: `observed` carries only kernel answers, and
    /// the same bounds a decoded plan has to satisfy are applied before the
    /// identity exists.
    pub(crate) fn from_kernel_observation(
        object_id: &str,
        kind: LinuxRetainedObjectKindV1,
        observed: LinuxKernelObjectObservationV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let identity = Self {
            object_id: object_id.to_owned(),
            kind,
            device_id: observed.device_id,
            inode: observed.inode,
            mount_id: observed.mount_id,
            mode: observed.mode,
            owner_uid: observed.owner_uid,
            owner_gid: observed.owner_gid,
            link_count: observed.link_count,
            byte_length: observed.byte_length,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub(crate) fn object_id(&self) -> &str {
        &self.object_id
    }

    pub(crate) const fn kind(&self) -> LinuxRetainedObjectKindV1 {
        self.kind
    }

    /// The complete kernel observation this identity was minted from.
    ///
    /// `mount_id`, `mode`, `owner_gid` and `link_count` are deliberately part
    /// of it: none of them appears in the installer's external commitment, so
    /// a caller can show that a minted identity carries information no anchor
    /// could have supplied.
    pub(crate) const fn kernel_observation(&self) -> LinuxKernelObjectObservationV1 {
        LinuxKernelObjectObservationV1 {
            device_id: self.device_id,
            inode: self.inode,
            mount_id: self.mount_id,
            mode: self.mode,
            owner_uid: self.owner_uid,
            owner_gid: self.owner_gid,
            link_count: self.link_count,
            byte_length: self.byte_length,
        }
    }
}

/// Exactly what one live `statx`/`fstat` answered for one retained object.
///
/// Every field is a kernel answer about a descriptor the observer already
/// holds. The type exists so a production mint can hand the plan a live
/// observation where the only existing populator handed it a literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxKernelObjectObservationV1 {
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
    pub(crate) mount_id: u64,
    pub(crate) mode: u32,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) link_count: u64,
    pub(crate) byte_length: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxFileImmutabilityV1 {
    SealedMemfd { seal_bits: u32 },
    StableIdentityAndFullContentReadbackImmediatelyBeforeRelease,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxAuthenticatedFileV1 {
    object_id: String,
    resolved_path: String,
    byte_length: u64,
    content_sha256: Digest,
    immutability: LinuxFileImmutabilityV1,
}

impl LinuxAuthenticatedFileV1 {
    fn validate(
        &self,
        objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
        field: &str,
        executable: bool,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        validate_identifier(&self.object_id, field)?;
        validate_absolute_path(&self.resolved_path, field)?;
        if self.byte_length == 0 || self.byte_length > MAX_AUTHENTICATED_FILE_BYTES {
            return Err(invalid(format!(
                "{field} byte length is zero or exceeds its hard bound"
            )));
        }
        validate_nonzero_digest(&self.content_sha256, field)?;
        let object = object(objects, &self.object_id, field)?;
        if !object.is_regular_or_sealed() {
            return Err(invalid(format!("{field} is not a retained regular image")));
        }
        if object.byte_length != Some(self.byte_length) {
            return Err(invalid(format!(
                "{field} byte length differs from retained inode metadata"
            )));
        }
        match (object.kind, self.immutability) {
            (
                LinuxRetainedObjectKindV1::SealedMemfd,
                LinuxFileImmutabilityV1::SealedMemfd { seal_bits },
            ) if seal_bits == REQUIRED_SETUP_SEAL_BITS => {}
            (
                LinuxRetainedObjectKindV1::RegularFile,
                LinuxFileImmutabilityV1::StableIdentityAndFullContentReadbackImmediatelyBeforeRelease,
            ) => {}
            _ => {
                return Err(invalid(format!(
                    "{field} lacks an exact sealed-image or final pre-release readback requirement"
                )));
            }
        }
        if object.mode & SET_ID_MODE != 0 {
            return Err(invalid(format!(
                "{field} must not have setuid or setgid bits"
            )));
        }
        if executable && object.mode & 0o111 == 0 {
            return Err(invalid(format!("{field} has no executable mode bit")));
        }
        if executable && object.mode & 0o022 != 0 {
            return Err(invalid(format!(
                "{field} is group-writable or world-writable"
            )));
        }
        Ok(())
    }
}

impl LinuxAuthenticatedFileV1 {
    /// Production mint for one authenticated on-disk command image.
    ///
    /// `content_sha256` must be the digest of a complete readback of the exact
    /// retained descriptor, and `resolved_path` the name that descriptor was
    /// proved to still resolve through. A path reopened later is not the same
    /// object and cannot be substituted here.
    pub(crate) fn from_complete_readback(
        object_id: &str,
        resolved_path: &str,
        byte_length: u64,
        content_sha256: Digest,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        validate_identifier(object_id, "authenticated image object ID")?;
        validate_absolute_path(resolved_path, "authenticated image path")?;
        if byte_length == 0 || byte_length > MAX_AUTHENTICATED_FILE_BYTES {
            return Err(invalid(
                "authenticated image byte length is zero or exceeds its hard bound",
            ));
        }
        validate_nonzero_digest(&content_sha256, "authenticated image content")?;
        Ok(Self {
            object_id: object_id.to_owned(),
            resolved_path: resolved_path.to_owned(),
            byte_length,
            content_sha256,
            immutability:
                LinuxFileImmutabilityV1::StableIdentityAndFullContentReadbackImmediatelyBeforeRelease,
        })
    }

    pub(crate) fn resolved_path(&self) -> &str {
        &self.resolved_path
    }

    pub(crate) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(crate) const fn content_sha256(&self) -> &Digest {
        &self.content_sha256
    }
}

/// Stable plan-internal identifiers for the retained objects one installed
/// Linux native service owns.
///
/// These are the plan's own semantic role boundaries, not paths, and they grant
/// nothing. The identity behind each of them is a live kernel read required to
/// equal what the installer externally committed.
pub(crate) const SERVICE_STATE_ROOT_OBJECT_ID: &str = "service-state-root";
pub(crate) const SINGLETON_JOURNAL_ROOT_OBJECT_ID: &str = "singleton-journal-root";
pub(crate) const SERVICE_CGROUP_PARENT_OBJECT_ID: &str = "service-cgroup-parent";
pub(crate) const CGROUP_DELEGATION_ROOT_OBJECT_ID: &str = "cgroup-delegation-root";
pub(crate) const SERVICE_IMAGE_OBJECT_ID: &str = "service-image";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSetupChannelV1 {
    object_id: String,
    byte_length: u64,
    content_sha256: Digest,
    protocol_digest: Digest,
    seal_bits: u32,
}

impl LinuxSetupChannelV1 {
    fn validate(
        &self,
        objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        let object = object(objects, &self.object_id, "setup channel")?;
        if object.kind != LinuxRetainedObjectKindV1::SealedMemfd {
            return Err(invalid("setup channel must be a retained sealed memfd"));
        }
        if self.byte_length == 0
            || self.byte_length > MAX_SETUP_CHANNEL_BYTES
            || self.seal_bits != REQUIRED_SETUP_SEAL_BITS
        {
            return Err(invalid(
                "setup channel must be bounded, nonempty, and carry the exact immutable seal set",
            ));
        }
        if object.byte_length != Some(self.byte_length) {
            return Err(invalid(
                "setup channel byte length differs from retained memfd metadata",
            ));
        }
        validate_nonzero_digest(&self.content_sha256, "setup channel content")?;
        validate_nonzero_digest(&self.protocol_digest, "setup channel protocol")
    }

    /// Production mint for the setup-channel slot of
    /// [`LinuxBinaryIdentitiesV1`].
    ///
    /// `retained` must be the identity of the sealed memfd the caller already
    /// holds, and both digests must have been taken over a complete readback of
    /// that same descriptor. Nothing here may be chosen: the caller supplies
    /// kernel answers and measured digests, and the value then has to satisfy
    /// the **same** [`Self::validate`] a decoded plan satisfies, against an
    /// object table containing exactly the descriptor it was minted from.
    ///
    /// See [`AuthenticatedSetupChannelV1`], which is the only thing that calls
    /// this and which is where the digests are required to be measurements
    /// rather than assignments.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the retained
    /// descriptor is not a sealed memfd, when the length is zero, exceeds
    /// [`MAX_SETUP_CHANNEL_BYTES`] or disagrees with the retained metadata, when
    /// the seal set is not exactly [`REQUIRED_SETUP_SEAL_BITS`], or when either
    /// digest is all zero.
    pub(crate) fn from_sealed_readback(
        retained: &LinuxRetainedObjectIdentityV1,
        byte_length: u64,
        content_sha256: Digest,
        protocol_digest: Digest,
        seal_bits: u32,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let channel = Self {
            object_id: retained.object_id.clone(),
            byte_length,
            content_sha256,
            protocol_digest,
            seal_bits,
        };
        let objects = BTreeMap::from([(retained.object_id.as_str(), retained)]);
        channel.validate(&objects)?;
        Ok(channel)
    }

    pub(crate) const fn content_sha256(&self) -> &Digest {
        &self.content_sha256
    }

    pub(crate) const fn protocol_digest(&self) -> &Digest {
        &self.protocol_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxTargetLinkageV1 {
    StaticElf,
    DynamicElf {
        interpreter: LinuxAuthenticatedFileV1,
        interpreter_format: LinuxElfImageFormatV1,
        runtime_objects: Vec<LinuxAuthenticatedFileV1>,
    },
}

/// Executable format of one image the plan admits.
///
/// Both variants exist because both are real hosts. Neither may be chosen by
/// default: see [`LinuxMachineArchitectureV1`], which is the only thing in this
/// module that produces one, and which can only be produced from a
/// measurement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxElfImageFormatV1 {
    Elf64X86_64,
    Elf64Aarch64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProgramImageV1 {
    requested_program: String,
    executable: LinuxAuthenticatedFileV1,
    image_format: LinuxElfImageFormatV1,
    linkage: LinuxTargetLinkageV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxBinaryIdentitiesV1 {
    bubblewrap: LinuxAuthenticatedFileV1,
    bubblewrap_format: LinuxElfImageFormatV1,
    bubblewrap_version: String,
    inner_launcher: LinuxAuthenticatedFileV1,
    inner_launcher_format: LinuxElfImageFormatV1,
    setup_channel: LinuxSetupChannelV1,
    target: LinuxProgramImageV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxExecutionViewV1 {
    WorkerReadOnly,
    WorkerShadow,
    FinalVerifierSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxRoleSnapshotBindingV1 {
    role: RunnerRole,
    input_snapshot: Digest,
    view: LinuxExecutionViewV1,
    execution_root_object_id: String,
    execution_namespace_root: String,
}

/// The cgroup identities a plan commits to, and the one it deliberately does
/// not.
///
/// The service parent and the delegation root are installed state: they exist
/// before any plan and are anchored by the installer commitment, so the plan
/// names them. The **leaf does not exist when the plan is minted**, and
/// schema version 2 stopped pretending otherwise — see
/// [`LinuxCommandDomainLeafPlanV1`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxCgroupIdentitySetV1 {
    filesystem_magic: u64,
    service_parent_object_id: String,
    delegation_root_object_id: String,
    leaf: LinuxCommandDomainLeafPlanV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxRetainedCapabilitySetV1 {
    workspace_root_object_id: String,
    private_state_root_object_id: String,
    service_owned_journal_index_root_object_id: String,
    objects: Vec<LinuxRetainedObjectIdentityV1>,
    cgroup: LinuxCgroupIdentitySetV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxMountPurposeV1 {
    LiveWorkspace,
    WorkerShadow,
    FinalVerifierSnapshot,
    InnerLauncher,
    TargetExecutable,
    ElfInterpreter,
    RuntimeObject,
    RuntimeRoot,
    PrivateTemp,
    OutputSpool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxRetainedMountV1 {
    source_object_id: String,
    destination: String,
    purpose: LinuxMountPurposeV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxGitMaskV1 {
    workspace_destination: String,
    masked_destination: String,
    empty_directory_object_id: String,
    expected_empty_observation_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxMountPlanV1 {
    read_only: Vec<LinuxRetainedMountV1>,
    read_write: Vec<LinuxRetainedMountV1>,
    git_masks: Vec<LinuxGitMaskV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxNetworkNamespacePolicyV1 {
    NewIsolatedNamespace,
    RetainHostNamespaceForRenewedAction {
        grant_hash: Digest,
        policy_hash: Digest,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxNamespaceRequirementV1 {
    NewAndVerified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxCapabilityRequirementV1 {
    DropAllAndVerifyEverySetEmpty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxNoNewPrivilegesRequirementV1 {
    SetAndReadBackBeforeFilter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxPrivilegeNamespacePlanV1 {
    user: LinuxNamespaceRequirementV1,
    mount: LinuxNamespaceRequirementV1,
    pid: LinuxNamespaceRequirementV1,
    ipc: LinuxNamespaceRequirementV1,
    uts: LinuxNamespaceRequirementV1,
    cgroup: LinuxNamespaceRequirementV1,
    capabilities: LinuxCapabilityRequirementV1,
    no_new_privileges: LinuxNoNewPrivilegesRequirementV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxMandatoryEnforcementV1 {
    FullOrRefuseBeforeTargetExec,
}

/// Seccomp `AUDIT_ARCH_*` the plan's filter is required to be built for.
///
/// A seccomp filter is architecture-specific: the same syscall number means
/// different things under a different audit architecture, so a filter admitted
/// under the wrong one is not a weaker filter but a meaningless one. This value
/// is therefore derived from the same measurement as the image formats and is
/// required to agree with them.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxAuditArchitectureV1 {
    X86_64,
    Aarch64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxSeccompDefaultActionV1 {
    KillProcess,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxEnvironmentPolicyV1 {
    ClearThenInstallExactCompiledEnvironment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxDescriptorPolicyV1 {
    SetupChannelOnlyWhileHeldThenStdioOnlyAtTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxCommandBindingPolicyV1 {
    ExactAuthorityArgvAndRetainedCwd,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProcessSurfaceV1 {
    environment: LinuxEnvironmentPolicyV1,
    descriptors: LinuxDescriptorPolicyV1,
    command: LinuxCommandBindingPolicyV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxResourceLimitsV1 {
    wall_time_ms: u64,
    max_output_bytes: u64,
    max_processes: u32,
    max_memory_bytes: Option<u64>,
    swap_bytes: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxHeldBeforeReleaseV1 {
    RequiredBeforeAnyTargetCode,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxLiveReleaseClaimRequirementV1 {
    NonCloneableLiveClaimConsumedSynchronously,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxReleaseJournalRequirementV1 {
    PersistIntentBeforeSynchronousReleaseAndReconcileOnlyAfterRestart,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxReplayExclusionRequirementV1 {
    GlobalEffectIdOneShotAcrossAllRunnerSessions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxJournalOwnershipRequirementV1 {
    ServiceOwnedSingletonPerAuthenticatedDelegation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProductionReleaseExpectationV1 {
    schema: String,
    authenticated_platform_service_digest: Digest,
    held_before_release: LinuxHeldBeforeReleaseV1,
    live_claim: LinuxLiveReleaseClaimRequirementV1,
    journal: LinuxReleaseJournalRequirementV1,
    replay_exclusion: LinuxReplayExclusionRequirementV1,
    journal_ownership: LinuxJournalOwnershipRequirementV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxCleanupRequirementV1 {
    PersistKillIntent,
    WriteExactCgroupKillValue,
    ObservePopulatedZero,
    ObserveCgroupProcsEmpty,
    RemoveExactLeaf,
    RecordZeroSurvivingProcesses,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxRuntimeEvidenceRequirementV1 {
    CompleteCommandEffectAuthority,
    KernelAndDistributionIdentity,
    CgroupDelegationLeafAndLimitReadback,
    BubblewrapIdentityVersionAndPlanDigest,
    NamespaceIdentitiesAndUserGroupMaps,
    EmptyCapabilitySets,
    ExactMountPlanAndGitMasks,
    ExactNetworkNamespaceMode,
    LandlockCompatibilityRulesAndCanaries,
    SeccompArchitectureFilterReadbackAndCanary,
    NoNewPrivilegesReadback,
    HeldReleaseJournalAndObservation,
    CommandOutputTerminationAndDigest,
}

const REQUIRED_CLEANUP: &[LinuxCleanupRequirementV1] = &[
    LinuxCleanupRequirementV1::PersistKillIntent,
    LinuxCleanupRequirementV1::WriteExactCgroupKillValue,
    LinuxCleanupRequirementV1::ObservePopulatedZero,
    LinuxCleanupRequirementV1::ObserveCgroupProcsEmpty,
    LinuxCleanupRequirementV1::RemoveExactLeaf,
    LinuxCleanupRequirementV1::RecordZeroSurvivingProcesses,
];

const REQUIRED_RUNTIME_EVIDENCE: &[LinuxRuntimeEvidenceRequirementV1] = &[
    LinuxRuntimeEvidenceRequirementV1::CompleteCommandEffectAuthority,
    LinuxRuntimeEvidenceRequirementV1::KernelAndDistributionIdentity,
    LinuxRuntimeEvidenceRequirementV1::CgroupDelegationLeafAndLimitReadback,
    LinuxRuntimeEvidenceRequirementV1::BubblewrapIdentityVersionAndPlanDigest,
    LinuxRuntimeEvidenceRequirementV1::NamespaceIdentitiesAndUserGroupMaps,
    LinuxRuntimeEvidenceRequirementV1::EmptyCapabilitySets,
    LinuxRuntimeEvidenceRequirementV1::ExactMountPlanAndGitMasks,
    LinuxRuntimeEvidenceRequirementV1::ExactNetworkNamespaceMode,
    LinuxRuntimeEvidenceRequirementV1::LandlockCompatibilityRulesAndCanaries,
    LinuxRuntimeEvidenceRequirementV1::SeccompArchitectureFilterReadbackAndCanary,
    LinuxRuntimeEvidenceRequirementV1::NoNewPrivilegesReadback,
    LinuxRuntimeEvidenceRequirementV1::HeldReleaseJournalAndObservation,
    LinuxRuntimeEvidenceRequirementV1::CommandOutputTerminationAndDigest,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxExpectedTerminalEvidenceV1 {
    runtime_schema: String,
    cleanup_schema: String,
    runtime_requirements: Vec<LinuxRuntimeEvidenceRequirementV1>,
    cleanup_requirements_in_order: Vec<LinuxCleanupRequirementV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProductionCommandPlanComponentsV1 {
    role_snapshot: LinuxRoleSnapshotBindingV1,
    binaries: LinuxBinaryIdentitiesV1,
    retained: LinuxRetainedCapabilitySetV1,
    mounts: LinuxMountPlanV1,
    network: LinuxNetworkNamespacePolicyV1,
    privilege_namespaces: LinuxPrivilegeNamespacePlanV1,
    landlock: LinuxLandlockPlanV1,
    seccomp: LinuxSeccompPlanV1,
    process_surface: LinuxProcessSurfaceV1,
    resource_limits: LinuxResourceLimitsV1,
    release: LinuxProductionReleaseExpectationV1,
    terminal_evidence: LinuxExpectedTerminalEvidenceV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProductionCommandPlanV1 {
    schema_version: u32,
    contract_version: u32,
    native_launch: LinuxNativeLaunchIdentity,
    command_effect_authority: CommandEffectAuthorityV1,
    compiled_authority: LinuxCompiledAuthorityV1,
    components: LinuxProductionCommandPlanComponentsV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedLinuxProductionCommandPlanV1 {
    plan: LinuxProductionCommandPlanV1,
    canonical_bytes: Vec<u8>,
    plan_digest: Digest,
}

/// Exact native-service identities retained by the canonical production plan.
///
/// This projection is used only to authenticate the non-cloneable service
/// journal authority before the complete canonical plan is committed. It is
/// not sufficient to prepare a cgroup domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProductionCommandPlanJournalBindingV1 {
    pub(crate) authenticated_platform_service_digest: Digest,
    pub(crate) service_state_root_identity: CgroupObjectIdentity,
    pub(crate) singleton_journal_root_identity: CgroupObjectIdentity,
    pub(crate) service_parent_identity: CgroupObjectIdentity,
    pub(crate) delegation_identity: CgroupObjectIdentity,
    pub(crate) owner_uid: u32,
    pub(crate) delegation_mode: u32,
}

/// Retained inode metadata for one service-bootstrap executable.
///
/// The native service must retain the descriptor represented here. A path or
/// version string alone is never sufficient to authenticate the executable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxBootstrapFileIdentityV1 {
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
    pub(crate) mount_id: u64,
    pub(crate) mode: u32,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) link_count: u64,
    pub(crate) byte_length: u64,
    pub(crate) content_sha256: Digest,
}

/// Role of one executable image that the native Linux service must retain and
/// revalidate before a command can enter cgroup mechanics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxServiceExecutableRoleV1 {
    Bubblewrap,
    InnerLauncher,
    Target,
    ElfInterpreter,
    RuntimeObject,
}

/// Exact descriptor/content identity for one command image admitted by the
/// canonical plan.
///
/// A resolved path is comparison data only. Native-service admission must
/// retain a descriptor and prove the named entry, inode metadata, complete
/// bytes, and immutability requirement again; this value grants no authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxServiceExecutableBindingV1 {
    pub(crate) role: LinuxServiceExecutableRoleV1,
    pub(crate) object_id: String,
    pub(crate) resolved_path: String,
    pub(crate) file: LinuxBootstrapFileIdentityV1,
    pub(crate) immutability: LinuxFileImmutabilityV1,
}

/// How one admission-sealed command image may be consumed by the future
/// native launch transition.
///
/// `HostExecutable` is reserved for the exact Bubblewrap image. Every other
/// image is mounted read-only at the already-validated namespace destination.
/// This is comparison data only: it carries no source pathname or descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LinuxServiceLaunchImageUseV1 {
    HostExecutable,
    ReadOnlyNamespaceMount {
        purpose: LinuxMountPurposeV1,
        destination: String,
    },
}

/// Pathless, role-exact expectation for one immutable launch image.
///
/// Source pathname and source inode provenance deliberately stop at executable
/// admission. A later launch transition may retain only the immutable snapshot
/// described here, while the namespace destination remains exact plan data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceLaunchImageBindingV1 {
    pub(crate) role: LinuxServiceExecutableRoleV1,
    pub(crate) object_id: String,
    pub(crate) byte_length: u64,
    pub(crate) content_sha256: Digest,
    pub(crate) usage: LinuxServiceLaunchImageUseV1,
}

/// Exact retained-object identity required by the setup-descriptor closure.
///
/// This remains comparison data. The native service must separately retain a
/// descriptor and prove every field again before the setup type state exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceSetupObjectIdentityV1 {
    pub(crate) object_id: String,
    pub(crate) kind: LinuxRetainedObjectKindV1,
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
    pub(crate) mount_id: u64,
    pub(crate) mode: u32,
    pub(crate) owner_uid: u32,
    pub(crate) owner_gid: u32,
    pub(crate) link_count: u64,
    pub(crate) byte_length: Option<u64>,
}

/// Access mode required from one service-retained setup endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceSetupDescriptorAccessV1 {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

/// Kernel object type required from one service-retained setup endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceSetupEndpointKindV1 {
    SealedRequestMemfd,
    Pipe,
}

/// Semantic endpoint role in the setup and final-target descriptor tables.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceSetupEndpointRoleV1 {
    SetupRequest,
    SetupControl,
    SetupStatus,
    TargetStdin,
    TargetStdout,
    TargetStderr,
}

/// Source of one endpoint expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LinuxServiceSetupEndpointSourceV1 {
    PlanSealedRequest {
        object: LinuxServiceSetupObjectIdentityV1,
        content_sha256: Digest,
        protocol_digest: Digest,
        seal_bits: u32,
    },
    ServicePipe,
}

/// Exact type/access/inheritance expectation for one setup endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceSetupEndpointBindingV1 {
    pub(crate) role: LinuxServiceSetupEndpointRoleV1,
    pub(crate) kind: LinuxServiceSetupEndpointKindV1,
    pub(crate) access: LinuxServiceSetupDescriptorAccessV1,
    pub(crate) close_on_exec_while_retained: bool,
    pub(crate) source: LinuxServiceSetupEndpointSourceV1,
}

/// Why one non-image source is retained for a read-only namespace mount.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceSetupMountUseV1 {
    PlanReadOnlyMount { purpose: LinuxMountPurposeV1 },
    GitMask,
}

/// Exact non-image read-only mount source and namespace destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceSetupMountSourceBindingV1 {
    pub(crate) object: LinuxServiceSetupObjectIdentityV1,
    pub(crate) destination: String,
    pub(crate) access: LinuxServiceSetupDescriptorAccessV1,
    pub(crate) usage: LinuxServiceSetupMountUseV1,
}

/// Exact execution-root and root-relative cwd expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceSetupCwdBindingV1 {
    pub(crate) execution_root: LinuxServiceSetupObjectIdentityV1,
    pub(crate) root_relative_path: String,
    pub(crate) namespace_path: String,
}

/// Semantic role used to define exact per-phase descriptor closure without
/// exposing numeric file descriptors.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceSetupDescriptorRoleV1 {
    LaunchImage {
        role: LinuxServiceExecutableRoleV1,
        object_id: String,
    },
    ExecutionRoot {
        object_id: String,
    },
    WorkingDirectory {
        execution_root_object_id: String,
        root_relative_path: String,
    },
    PrivateStateRoot {
        object_id: String,
    },
    SingletonJournalRoot {
        object_id: String,
    },
    ReadOnlyMountSource {
        usage: LinuxServiceSetupMountUseV1,
        object_id: String,
        destination: String,
    },
    Endpoint(LinuxServiceSetupEndpointRoleV1),
}

/// Versioned, canonical setup-descriptor projection for one durable plan.
///
/// The projection fixes semantic roles, identities, destinations, endpoint
/// types/access, alias policy, and exact phase closure. It contains no
/// descriptor, pathname lookup authority, spawn callback, or release permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceSetupDescriptorBindingV1 {
    pub(crate) schema: String,
    pub(crate) plan_digest: Digest,
    pub(crate) cwd: LinuxServiceSetupCwdBindingV1,
    pub(crate) private_state_root: LinuxServiceSetupObjectIdentityV1,
    pub(crate) singleton_journal_root: LinuxServiceSetupObjectIdentityV1,
    pub(crate) read_only_mount_sources: Vec<LinuxServiceSetupMountSourceBindingV1>,
    pub(crate) endpoints: Vec<LinuxServiceSetupEndpointBindingV1>,
    pub(crate) endpoint_identities_must_be_pairwise_distinct: bool,
    pub(crate) held_setup_allowed_roles: Vec<LinuxServiceSetupDescriptorRoleV1>,
    pub(crate) close_after_setup_before_target_exec_roles: Vec<LinuxServiceSetupDescriptorRoleV1>,
    pub(crate) target_exec_attempt_allowed_roles: Vec<LinuxServiceSetupDescriptorRoleV1>,
    pub(crate) close_on_successful_target_exec_roles: Vec<LinuxServiceSetupDescriptorRoleV1>,
    pub(crate) post_exec_target_allowed_roles: Vec<LinuxServiceSetupDescriptorRoleV1>,
}

/// Semantic source of one fixed inner-launcher descriptor slot.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceChildDescriptorSourceV1 {
    Endpoint(LinuxServiceSetupEndpointRoleV1),
    WorkingDirectory {
        execution_root_object_id: String,
        root_relative_path: String,
    },
}

/// Kernel object type required in one inner-launcher descriptor slot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceChildDescriptorKindV1 {
    Pipe,
    SealedRequestMemfd,
    Directory,
}

/// Exact lifecycle of one descriptor after the inner launcher completes setup.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LinuxServiceChildDescriptorLifecycleV1 {
    CloseAfterSetup,
    CloseOnSuccessfulExec,
    RetainPostExec,
}

/// Exact source, target slot, access transition, and lifecycle for one child
/// descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceChildDescriptorBindingV1 {
    pub(crate) target_fd: u32,
    pub(crate) source: LinuxServiceChildDescriptorSourceV1,
    pub(crate) kind: LinuxServiceChildDescriptorKindV1,
    pub(crate) retained_source_access: LinuxServiceSetupDescriptorAccessV1,
    pub(crate) child_access: LinuxServiceSetupDescriptorAccessV1,
    pub(crate) retained_source_close_on_exec: bool,
    pub(crate) child_close_on_exec: bool,
    pub(crate) lifecycle: LinuxServiceChildDescriptorLifecycleV1,
}

/// One immutable image mounted into the future child namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceChildImageMountBindingV1 {
    pub(crate) mount_index: u32,
    pub(crate) role: LinuxServiceExecutableRoleV1,
    pub(crate) object_id: String,
    pub(crate) destination: String,
    pub(crate) byte_length: u64,
    pub(crate) content_sha256: Digest,
    pub(crate) read_only: bool,
    pub(crate) retained_source_close_on_exec: bool,
}

/// Static or exact dynamic-loader closure required by the target image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LinuxServiceTargetLoaderClosureV1 {
    Static {
        target_object_id: String,
    },
    Dynamic {
        target_object_id: String,
        interpreter_object_id: String,
        runtime_object_ids_in_order: Vec<String>,
    },
}

/// Versioned comparison contract for the exact inner-launcher descriptor table
/// and pathless image-mount/loader closure.
///
/// It contains no descriptors, namespace handle, mount callback, child process,
/// spawn permit, or release authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxServiceChildLaunchClosureBindingV1 {
    pub(crate) schema: String,
    pub(crate) plan_digest: Digest,
    pub(crate) bubblewrap_host_executable_object_id: String,
    pub(crate) inner_launcher_descriptor_table: Vec<LinuxServiceChildDescriptorBindingV1>,
    pub(crate) child_target_fds_are_contiguous_and_unique: bool,
    pub(crate) image_mounts: Vec<LinuxServiceChildImageMountBindingV1>,
    pub(crate) mount_destinations_must_be_pairwise_distinct: bool,
    pub(crate) loader_closure: LinuxServiceTargetLoaderClosureV1,
}

impl LinuxProductionCommandPlanComponentsV1 {
    fn canonicalize(&mut self) {
        self.retained
            .objects
            .sort_by(|left, right| left.object_id.cmp(&right.object_id));
        self.mounts.read_only.sort_by(mount_order);
        self.mounts.read_write.sort_by(mount_order);
        self.mounts.git_masks.sort_by(|left, right| {
            left.workspace_destination
                .cmp(&right.workspace_destination)
                .then(left.masked_destination.cmp(&right.masked_destination))
        });
        if let LinuxTargetLinkageV1::DynamicElf {
            runtime_objects, ..
        } = &mut self.binaries.target.linkage
        {
            runtime_objects.sort_by(|left, right| {
                left.resolved_path
                    .cmp(&right.resolved_path)
                    .then(left.object_id.cmp(&right.object_id))
            });
        }
    }
}

fn mount_order(left: &LinuxRetainedMountV1, right: &LinuxRetainedMountV1) -> std::cmp::Ordering {
    left.destination
        .cmp(&right.destination)
        .then(left.purpose.cmp(&right.purpose))
        .then(left.source_object_id.cmp(&right.source_object_id))
}

impl LinuxProductionCommandPlanV1 {
    pub(crate) fn build(
        native_launch: LinuxNativeLaunchIdentity,
        command_effect_authority: CommandEffectAuthorityV1,
        grant: &IssuedWorkspaceGrant,
        policy: &CompiledExecutionPolicy,
        mut components: LinuxProductionCommandPlanComponentsV1,
    ) -> Result<ValidatedLinuxProductionCommandPlanV1, LinuxProductionCommandPlanError> {
        command_effect_authority
            .validate_integrity()
            .map_err(|error| invalid(format!("command-effect authority failed: {error}")))?;
        components.canonicalize();
        let plan = Self {
            schema_version: LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION,
            contract_version: CONTRACT_VERSION,
            native_launch,
            command_effect_authority,
            compiled_authority: LinuxCompiledAuthorityV1::from_trusted(grant, policy)?,
            components,
        };
        ValidatedLinuxProductionCommandPlanV1::from_plan(plan)
    }

    fn validate(&self) -> Result<(), LinuxProductionCommandPlanError> {
        if self.schema_version != LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION {
            return Err(schema_version_refusal(self.schema_version));
        }
        if self.contract_version != CONTRACT_VERSION {
            return Err(invalid(
                "Linux production command-plan contract version differs",
            ));
        }
        self.command_effect_authority
            .validate_integrity()
            .map_err(|error| invalid(format!("command-effect authority failed: {error}")))?;
        self.native_launch
            .validate()
            .map_err(|error| invalid(format!("native launch identity failed: {error}")))?;
        let (grant, policy) = self.compiled_authority.native_contracts()?;
        let authority = &self.command_effect_authority;
        let envelope = authority.envelope();
        let effect = envelope
            .effect
            .as_ref()
            .ok_or_else(|| invalid("production command plan requires complete effect context"))?;
        if self.native_launch.sprint_id != effect.sprint_id
            || self.native_launch.launch_id != effect.launch_id
            || self.native_launch.session_id != envelope.session_id
            || self.native_launch.input_snapshot != effect.input_snapshot
            || self.native_launch.grant_hash != *authority.grant_hash()
            || self.native_launch.policy_hash != effect.policy_hash
        {
            return Err(invalid(
                "native launch differs from the exact command session, launch, sprint, snapshot, grant, or policy authority",
            ));
        }
        if envelope.runner_nonce.is_none()
            || envelope.sequence == 0
            || envelope.sequence == u64::MAX
            || effect.transport_commitment_digest
                != envelope
                    .computed_transport_commitment_digest()
                    .map_err(|error| invalid(format!("transport commitment failed: {error}")))?
        {
            return Err(invalid(
                "production plan lost nonce, sequence, request, or transport commitment context",
            ));
        }
        if grant.grant_hash != *authority.grant_hash()
            || policy.grant_hash != *authority.grant_hash()
        {
            return Err(invalid(
                "command-effect authority and independently restored grant/policy differ",
            ));
        }
        if policy.policy_hash != effect.policy_hash {
            return Err(invalid(
                "command-effect policy hash differs from the independently compiled policy",
            ));
        }
        if !grant.permissions.execute_commands {
            return Err(invalid(
                "compiled workspace grant does not authorize commands",
            ));
        }
        validate_role_snapshot(authority, &self.components.role_snapshot, &policy)?;
        validate_resource_limits(&self.components.resource_limits, policy.resource_limits)?;
        validate_network(
            &self.components.network,
            policy.network,
            &grant.grant_hash,
            &policy.policy_hash,
        )?;
        let objects = validate_retained_objects(
            &self.components.retained,
            &self.compiled_authority.grant.identity,
        )?;
        validate_binaries(&self.components.binaries, authority, &objects)?;
        validate_architecture(&self.components.binaries, &self.components.seccomp)?;
        validate_cgroup(&self.components.retained, &objects)?;
        validate_mounts(
            &self.components.mounts,
            &self.components.role_snapshot,
            &self.components.binaries,
            &self.components.retained,
            &objects,
        )?;
        validate_mandatory_kernel_controls(&self.components.landlock, &self.components.seccomp)?;
        validate_mandatory_control_artefacts(
            &self.components.landlock,
            &self.components.seccomp,
            &objects,
        )?;
        validate_release_and_evidence(
            &self.components.release,
            &self.components.terminal_evidence,
            &self.components.retained,
            &objects,
        )?;
        Ok(())
    }
}

impl ValidatedLinuxProductionCommandPlanV1 {
    fn from_plan(
        plan: LinuxProductionCommandPlanV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        plan.validate()?;
        let canonical_bytes = serde_json::to_vec(&plan)
            .map_err(|error| LinuxProductionCommandPlanError::Encode(error.to_string()))?;
        if canonical_bytes.len() > MAX_CANONICAL_PLAN_BYTES {
            return Err(LinuxProductionCommandPlanError::TooLarge {
                actual: canonical_bytes.len(),
            });
        }
        let plan_digest = digest_plan(&canonical_bytes)?;
        Ok(Self {
            plan,
            canonical_bytes,
            plan_digest,
        })
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self, LinuxProductionCommandPlanError> {
        if bytes.len() > MAX_CANONICAL_PLAN_BYTES {
            return Err(LinuxProductionCommandPlanError::TooLarge {
                actual: bytes.len(),
            });
        }
        // Inspect the version before typed decoding for explicit diagnostics;
        // version inspection does not bypass validation.
        let peek: LinuxProductionCommandPlanSchemaVersionV1 = serde_json::from_slice(bytes)
            .map_err(|error| LinuxProductionCommandPlanError::Decode(error.to_string()))?;
        if peek.schema_version != LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION {
            return Err(schema_version_refusal(peek.schema_version));
        }
        let plan: LinuxProductionCommandPlanV1 = serde_json::from_slice(bytes)
            .map_err(|error| LinuxProductionCommandPlanError::Decode(error.to_string()))?;
        let validated = Self::from_plan(plan)?;
        if validated.canonical_bytes != bytes {
            return Err(LinuxProductionCommandPlanError::NonCanonical);
        }
        Ok(validated)
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub(crate) fn effect_id(&self) -> &str {
        self.plan
            .command_effect_authority
            .envelope()
            .effect
            .as_ref()
            .expect("validated production plans always retain effect authority")
            .effect_id
            .as_str()
    }

    pub(crate) fn journal_binding(
        &self,
    ) -> Result<LinuxProductionCommandPlanJournalBindingV1, LinuxProductionCommandPlanError> {
        let retained = &self.plan.components.retained;
        let find = |object_id: &str, field: &str| {
            retained
                .objects
                .iter()
                .find(|candidate| candidate.object_id == object_id)
                .ok_or_else(|| invalid(format!("{field} retained identity is absent")))
        };
        let service_state = find(&retained.private_state_root_object_id, "service-state root")?;
        let journal = find(
            &retained.service_owned_journal_index_root_object_id,
            "singleton journal root",
        )?;
        let service_parent = find(
            &retained.cgroup.service_parent_object_id,
            "service cgroup parent",
        )?;
        let delegation = find(
            &retained.cgroup.delegation_root_object_id,
            "cgroup delegation root",
        )?;
        Ok(LinuxProductionCommandPlanJournalBindingV1 {
            authenticated_platform_service_digest: self
                .plan
                .components
                .release
                .authenticated_platform_service_digest
                .clone(),
            service_state_root_identity: CgroupObjectIdentity {
                device: service_state.device_id,
                inode: service_state.inode,
            },
            singleton_journal_root_identity: CgroupObjectIdentity {
                device: journal.device_id,
                inode: journal.inode,
            },
            service_parent_identity: CgroupObjectIdentity {
                device: service_parent.device_id,
                inode: service_parent.inode,
            },
            delegation_identity: CgroupObjectIdentity {
                device: delegation.device_id,
                inode: delegation.inode,
            },
            owner_uid: delegation.owner_uid,
            delegation_mode: delegation.mode & 0o7777,
        })
    }

    pub(crate) fn service_bootstrap_binding(
        &self,
    ) -> Result<LinuxProductionCommandPlanServiceBootstrapBindingV1, LinuxProductionCommandPlanError>
    {
        let journal = self.journal_binding()?;
        let bubblewrap = &self.plan.components.binaries.bubblewrap;
        let retained = self
            .plan
            .components
            .retained
            .objects
            .iter()
            .find(|candidate| candidate.object_id == bubblewrap.object_id)
            .ok_or_else(|| invalid("Bubblewrap retained identity is absent"))?;
        if retained.kind != LinuxRetainedObjectKindV1::RegularFile {
            return Err(invalid(
                "service bootstrap requires Bubblewrap to be a retained regular file",
            ));
        }
        Ok(LinuxProductionCommandPlanServiceBootstrapBindingV1 {
            journal,
            cgroup_filesystem_magic: self.plan.components.retained.cgroup.filesystem_magic,
            bubblewrap: LinuxBubblewrapBootstrapBindingV1 {
                resolved_path: bubblewrap.resolved_path.clone(),
                version: self.plan.components.binaries.bubblewrap_version.clone(),
                file: LinuxBootstrapFileIdentityV1 {
                    device_id: retained.device_id,
                    inode: retained.inode,
                    mount_id: retained.mount_id,
                    mode: retained.mode,
                    owner_uid: retained.owner_uid,
                    owner_gid: retained.owner_gid,
                    link_count: retained.link_count,
                    byte_length: bubblewrap.byte_length,
                    content_sha256: bubblewrap.content_sha256.clone(),
                },
            },
            landlock: LinuxLandlockBootstrapBindingV1::InstalledRulesetProvenByLiveBootstrapProbe {
                minimum_kernel_abi: self.plan.components.landlock.minimum_kernel_abi(),
                maximum_modeled_kernel_abi: self
                    .plan
                    .components
                    .landlock
                    .maximum_modeled_kernel_abi(),
                ruleset: self.plan.components.landlock.ruleset().clone(),
            },
            seccomp: LinuxSeccompBootstrapBindingV1::CompiledFilterProvenByLiveBootstrapProbe {
                audit_architecture: self.plan.components.seccomp.audit_architecture(),
                default_action: self.plan.components.seccomp.default_action(),
                filter: self.plan.components.seccomp.filter().clone(),
            },
        })
    }

    /// Projects the complete executable/tool set that a native service must
    /// retain before mechanics admission.
    ///
    /// The returned values are identity expectations only. In particular,
    /// canonical plan bytes or paths cannot stand in for retained descriptors.
    pub(crate) fn service_executable_bindings(
        &self,
    ) -> Result<Vec<LinuxServiceExecutableBindingV1>, LinuxProductionCommandPlanError> {
        let retained = &self.plan.components.retained.objects;
        let binding = |role: LinuxServiceExecutableRoleV1,
                       image: &LinuxAuthenticatedFileV1|
         -> Result<
            LinuxServiceExecutableBindingV1,
            LinuxProductionCommandPlanError,
        > {
            let object = retained
                .iter()
                .find(|candidate| candidate.object_id == image.object_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "native-service executable {} retained identity is absent",
                        image.object_id
                    ))
                })?;
            if !object.is_regular_or_sealed() || object.byte_length != Some(image.byte_length) {
                return Err(invalid(format!(
                    "native-service executable {} has crossed kind or byte length",
                    image.object_id
                )));
            }
            Ok(LinuxServiceExecutableBindingV1 {
                role,
                object_id: image.object_id.clone(),
                resolved_path: image.resolved_path.clone(),
                file: LinuxBootstrapFileIdentityV1 {
                    device_id: object.device_id,
                    inode: object.inode,
                    mount_id: object.mount_id,
                    mode: object.mode,
                    owner_uid: object.owner_uid,
                    owner_gid: object.owner_gid,
                    link_count: object.link_count,
                    byte_length: image.byte_length,
                    content_sha256: image.content_sha256.clone(),
                },
                immutability: image.immutability,
            })
        };

        let binaries = &self.plan.components.binaries;
        let mut bindings = vec![
            binding(
                LinuxServiceExecutableRoleV1::Bubblewrap,
                &binaries.bubblewrap,
            )?,
            binding(
                LinuxServiceExecutableRoleV1::InnerLauncher,
                &binaries.inner_launcher,
            )?,
            binding(
                LinuxServiceExecutableRoleV1::Target,
                &binaries.target.executable,
            )?,
        ];
        if let LinuxTargetLinkageV1::DynamicElf {
            interpreter,
            runtime_objects,
            ..
        } = &binaries.target.linkage
        {
            bindings.push(binding(
                LinuxServiceExecutableRoleV1::ElfInterpreter,
                interpreter,
            )?);
            for runtime in runtime_objects {
                bindings.push(binding(
                    LinuxServiceExecutableRoleV1::RuntimeObject,
                    runtime,
                )?);
            }
        }
        bindings.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then(left.resolved_path.cmp(&right.resolved_path))
                .then(left.object_id.cmp(&right.object_id))
        });
        let mut object_ids = BTreeSet::new();
        if bindings
            .iter()
            .any(|binding| !object_ids.insert(binding.object_id.as_str()))
        {
            return Err(invalid(
                "native-service executable projection contains a duplicate object ID",
            ));
        }
        Ok(bindings)
    }

    /// Projects the exact immutable image set that a future native release may
    /// consume after source admission.
    ///
    /// Unlike [`Self::service_executable_bindings`], this projection contains
    /// no host source pathname or source inode. Bubblewrap is the sole host
    /// executable; every other image is tied to one exact read-only namespace
    /// destination from the complete plan. The values remain comparison data,
    /// not descriptor or release authority.
    pub(crate) fn service_launch_image_bindings(
        &self,
    ) -> Result<Vec<LinuxServiceLaunchImageBindingV1>, LinuxProductionCommandPlanError> {
        let source_bindings = self.service_executable_bindings()?;
        let read_only_mounts = &self.plan.components.mounts.read_only;
        let expected_use = |binding: &LinuxServiceExecutableBindingV1| {
            let purpose = match binding.role {
                LinuxServiceExecutableRoleV1::Bubblewrap => {
                    if read_only_mounts
                        .iter()
                        .any(|mount| mount.source_object_id == binding.object_id)
                    {
                        return Err(invalid(
                            "Bubblewrap must remain the sole host executable and cannot also be a namespace mount source",
                        ));
                    }
                    return Ok(LinuxServiceLaunchImageUseV1::HostExecutable);
                }
                LinuxServiceExecutableRoleV1::InnerLauncher => LinuxMountPurposeV1::InnerLauncher,
                LinuxServiceExecutableRoleV1::Target => LinuxMountPurposeV1::TargetExecutable,
                LinuxServiceExecutableRoleV1::ElfInterpreter => LinuxMountPurposeV1::ElfInterpreter,
                LinuxServiceExecutableRoleV1::RuntimeObject => LinuxMountPurposeV1::RuntimeObject,
            };
            let mut matches = read_only_mounts.iter().filter(|mount| {
                mount.purpose == purpose && mount.source_object_id == binding.object_id
            });
            let mount = matches.next().ok_or_else(|| {
                invalid(format!(
                    "launch image {} has no exact read-only namespace destination",
                    binding.object_id
                ))
            })?;
            if matches.next().is_some() || mount.destination != binding.resolved_path {
                return Err(invalid(format!(
                    "launch image {} has duplicate or crossed namespace destination authority",
                    binding.object_id
                )));
            }
            Ok(LinuxServiceLaunchImageUseV1::ReadOnlyNamespaceMount {
                purpose,
                destination: mount.destination.clone(),
            })
        };

        let bindings = source_bindings
            .iter()
            .map(|binding| {
                Ok(LinuxServiceLaunchImageBindingV1 {
                    role: binding.role,
                    object_id: binding.object_id.clone(),
                    byte_length: binding.file.byte_length,
                    content_sha256: binding.file.content_sha256.clone(),
                    usage: expected_use(binding)?,
                })
            })
            .collect::<Result<Vec<_>, LinuxProductionCommandPlanError>>()?;

        let count = |role| {
            bindings
                .iter()
                .filter(|binding| binding.role == role)
                .count()
        };
        if count(LinuxServiceExecutableRoleV1::Bubblewrap) != 1
            || count(LinuxServiceExecutableRoleV1::InnerLauncher) != 1
            || count(LinuxServiceExecutableRoleV1::Target) != 1
        {
            return Err(invalid(
                "launch image authority requires exactly one Bubblewrap, inner-launcher, and target image",
            ));
        }
        match &self.plan.components.binaries.target.linkage {
            LinuxTargetLinkageV1::StaticElf => {
                if count(LinuxServiceExecutableRoleV1::ElfInterpreter) != 0
                    || count(LinuxServiceExecutableRoleV1::RuntimeObject) != 0
                {
                    return Err(invalid(
                        "static target launch authority contains an interpreter or runtime object",
                    ));
                }
            }
            LinuxTargetLinkageV1::DynamicElf {
                runtime_objects, ..
            } => {
                if count(LinuxServiceExecutableRoleV1::ElfInterpreter) != 1
                    || count(LinuxServiceExecutableRoleV1::RuntimeObject) != runtime_objects.len()
                {
                    return Err(invalid(
                        "dynamic target launch authority lost its exact interpreter or runtime-object closure",
                    ));
                }
            }
        }
        Ok(bindings)
    }

    /// Projects the exact descriptor closure required before mechanics may be
    /// retained for this plan.
    ///
    /// Actual descriptors arrive only through a separately authenticated,
    /// non-cloneable native-service capability. This deterministic projection
    /// supplies comparison data and phase closure only.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear canonical projection keeps every descriptor role and phase partition reviewable together"
    )]
    pub(crate) fn service_setup_descriptor_binding(
        &self,
    ) -> Result<LinuxServiceSetupDescriptorBindingV1, LinuxProductionCommandPlanError> {
        let components = &self.plan.components;
        if components.process_surface.descriptors
            != LinuxDescriptorPolicyV1::SetupChannelOnlyWhileHeldThenStdioOnlyAtTarget
            || components.process_surface.command
                != LinuxCommandBindingPolicyV1::ExactAuthorityArgvAndRetainedCwd
        {
            return Err(invalid(
                "setup descriptor projection requires the exact held-setup and retained-cwd policies",
            ));
        }

        let retained_object = |object_id: &str| {
            let object = components
                .retained
                .objects
                .iter()
                .find(|candidate| candidate.object_id == object_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "setup descriptor object {object_id} is absent from the retained table"
                    ))
                })?;
            Ok(LinuxServiceSetupObjectIdentityV1 {
                object_id: object.object_id.clone(),
                kind: object.kind,
                device_id: object.device_id,
                inode: object.inode,
                mount_id: object.mount_id,
                mode: object.mode,
                owner_uid: object.owner_uid,
                owner_gid: object.owner_gid,
                link_count: object.link_count,
                byte_length: object.byte_length,
            })
        };

        let (RunnerRequest::WorkerRunCommand { command, .. }
        | RunnerRequest::FinalVerifierRunCommand { command, .. }) =
            &self.plan.command_effect_authority.envelope().request
        else {
            return Err(invalid(
                "setup descriptor projection requires an exact command request",
            ));
        };
        let root_relative_path = command.working_directory.clone();
        let namespace_path = if root_relative_path.is_empty() {
            components.role_snapshot.execution_namespace_root.clone()
        } else {
            format!(
                "{}/{}",
                components
                    .role_snapshot
                    .execution_namespace_root
                    .trim_end_matches('/'),
                root_relative_path
            )
        };
        validate_absolute_path(&namespace_path, "setup working directory namespace path")?;
        let cwd = LinuxServiceSetupCwdBindingV1 {
            execution_root: retained_object(&components.role_snapshot.execution_root_object_id)?,
            root_relative_path,
            namespace_path,
        };
        if cwd.execution_root.kind != LinuxRetainedObjectKindV1::Directory {
            return Err(invalid("setup execution root must be a retained directory"));
        }

        let private_state_root =
            retained_object(&components.retained.private_state_root_object_id)?;
        let singleton_journal_root = retained_object(
            &components
                .retained
                .service_owned_journal_index_root_object_id,
        )?;

        let launch_images = self.service_launch_image_bindings()?;
        let launch_object_ids = launch_images
            .iter()
            .map(|binding| binding.object_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut read_only_mount_sources = components
            .mounts
            .read_only
            .iter()
            .filter(|mount| !launch_object_ids.contains(mount.source_object_id.as_str()))
            .map(|mount| {
                Ok(LinuxServiceSetupMountSourceBindingV1 {
                    object: retained_object(&mount.source_object_id)?,
                    destination: mount.destination.clone(),
                    access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                    usage: LinuxServiceSetupMountUseV1::PlanReadOnlyMount {
                        purpose: mount.purpose,
                    },
                })
            })
            .collect::<Result<Vec<_>, LinuxProductionCommandPlanError>>()?;
        read_only_mount_sources.extend(
            components
                .mounts
                .git_masks
                .iter()
                .map(|mask| {
                    Ok(LinuxServiceSetupMountSourceBindingV1 {
                        object: retained_object(&mask.empty_directory_object_id)?,
                        destination: mask.masked_destination.clone(),
                        access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                        usage: LinuxServiceSetupMountUseV1::GitMask,
                    })
                })
                .collect::<Result<Vec<_>, LinuxProductionCommandPlanError>>()?,
        );
        read_only_mount_sources.sort_by(|left, right| {
            left.destination
                .cmp(&right.destination)
                .then(left.usage.cmp(&right.usage))
                .then(left.object.object_id.cmp(&right.object.object_id))
        });

        let setup_channel = &components.binaries.setup_channel;
        let endpoints = vec![
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::SetupRequest,
                kind: LinuxServiceSetupEndpointKindV1::SealedRequestMemfd,
                access: LinuxServiceSetupDescriptorAccessV1::ReadWrite,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::PlanSealedRequest {
                    object: retained_object(&setup_channel.object_id)?,
                    content_sha256: setup_channel.content_sha256.clone(),
                    protocol_digest: setup_channel.protocol_digest.clone(),
                    seal_bits: setup_channel.seal_bits,
                },
            },
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::SetupControl,
                kind: LinuxServiceSetupEndpointKindV1::Pipe,
                access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
            },
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::SetupStatus,
                kind: LinuxServiceSetupEndpointKindV1::Pipe,
                access: LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
            },
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::TargetStdin,
                kind: LinuxServiceSetupEndpointKindV1::Pipe,
                access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
            },
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::TargetStdout,
                kind: LinuxServiceSetupEndpointKindV1::Pipe,
                access: LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
            },
            LinuxServiceSetupEndpointBindingV1 {
                role: LinuxServiceSetupEndpointRoleV1::TargetStderr,
                kind: LinuxServiceSetupEndpointKindV1::Pipe,
                access: LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                close_on_exec_while_retained: true,
                source: LinuxServiceSetupEndpointSourceV1::ServicePipe,
            },
        ];

        let mut held_setup_allowed_roles = launch_images
            .iter()
            .map(|image| LinuxServiceSetupDescriptorRoleV1::LaunchImage {
                role: image.role,
                object_id: image.object_id.clone(),
            })
            .collect::<Vec<_>>();
        held_setup_allowed_roles.extend([
            LinuxServiceSetupDescriptorRoleV1::ExecutionRoot {
                object_id: cwd.execution_root.object_id.clone(),
            },
            LinuxServiceSetupDescriptorRoleV1::WorkingDirectory {
                execution_root_object_id: cwd.execution_root.object_id.clone(),
                root_relative_path: cwd.root_relative_path.clone(),
            },
            LinuxServiceSetupDescriptorRoleV1::PrivateStateRoot {
                object_id: private_state_root.object_id.clone(),
            },
            LinuxServiceSetupDescriptorRoleV1::SingletonJournalRoot {
                object_id: singleton_journal_root.object_id.clone(),
            },
        ]);
        held_setup_allowed_roles.extend(read_only_mount_sources.iter().map(|source| {
            LinuxServiceSetupDescriptorRoleV1::ReadOnlyMountSource {
                usage: source.usage.clone(),
                object_id: source.object.object_id.clone(),
                destination: source.destination.clone(),
            }
        }));
        held_setup_allowed_roles.extend(
            endpoints
                .iter()
                .map(|endpoint| LinuxServiceSetupDescriptorRoleV1::Endpoint(endpoint.role)),
        );
        held_setup_allowed_roles.sort();
        if held_setup_allowed_roles
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(invalid(
                "setup descriptor projection contains a duplicate semantic role",
            ));
        }
        let mut post_exec_target_allowed_roles = vec![
            LinuxServiceSetupDescriptorRoleV1::Endpoint(
                LinuxServiceSetupEndpointRoleV1::TargetStdin,
            ),
            LinuxServiceSetupDescriptorRoleV1::Endpoint(
                LinuxServiceSetupEndpointRoleV1::TargetStdout,
            ),
            LinuxServiceSetupDescriptorRoleV1::Endpoint(
                LinuxServiceSetupEndpointRoleV1::TargetStderr,
            ),
        ];
        post_exec_target_allowed_roles.sort();
        let close_on_successful_target_exec_roles =
            vec![LinuxServiceSetupDescriptorRoleV1::Endpoint(
                LinuxServiceSetupEndpointRoleV1::SetupStatus,
            )];
        let mut target_exec_attempt_allowed_roles = post_exec_target_allowed_roles.clone();
        target_exec_attempt_allowed_roles.extend(close_on_successful_target_exec_roles.clone());
        target_exec_attempt_allowed_roles.sort();
        let close_after_setup_before_target_exec_roles = held_setup_allowed_roles
            .iter()
            .filter(|role| !target_exec_attempt_allowed_roles.contains(role))
            .cloned()
            .collect();

        Ok(LinuxServiceSetupDescriptorBindingV1 {
            schema: LINUX_SERVICE_SETUP_DESCRIPTOR_SCHEMA.into(),
            plan_digest: self.plan_digest.clone(),
            cwd,
            private_state_root,
            singleton_journal_root,
            read_only_mount_sources,
            endpoints,
            endpoint_identities_must_be_pairwise_distinct: true,
            held_setup_allowed_roles,
            close_after_setup_before_target_exec_roles,
            target_exec_attempt_allowed_roles,
            close_on_successful_target_exec_roles,
            post_exec_target_allowed_roles,
        })
    }

    /// Projects the complete inner-launcher descriptor table and immutable
    /// image-mount/loader closure required after setup custody is established.
    ///
    /// This is comparison data only. A future native-service mint must prove a
    /// stopped child's actual descriptor table and namespace mount state before
    /// production may create the corresponding capability.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear projection keeps the complete child table and loader closure visibly joined"
    )]
    pub(crate) fn service_child_launch_closure_binding(
        &self,
    ) -> Result<LinuxServiceChildLaunchClosureBindingV1, LinuxProductionCommandPlanError> {
        let setup = self.service_setup_descriptor_binding()?;
        let endpoint_descriptor =
            |target_fd: u32,
             role: LinuxServiceSetupEndpointRoleV1,
             child_access: LinuxServiceSetupDescriptorAccessV1,
             lifecycle: LinuxServiceChildDescriptorLifecycleV1| {
                let endpoint = setup
                    .endpoints
                    .iter()
                    .find(|candidate| candidate.role == role)
                    .ok_or_else(|| {
                        invalid(format!(
                            "child descriptor role {role:?} is absent from the setup closure"
                        ))
                    })?;
                let kind = match endpoint.kind {
                    LinuxServiceSetupEndpointKindV1::Pipe => {
                        LinuxServiceChildDescriptorKindV1::Pipe
                    }
                    LinuxServiceSetupEndpointKindV1::SealedRequestMemfd => {
                        LinuxServiceChildDescriptorKindV1::SealedRequestMemfd
                    }
                };
                if !endpoint.close_on_exec_while_retained {
                    return Err(invalid(format!(
                        "child descriptor source {role:?} is not close-on-exec while retained"
                    )));
                }
                Ok(LinuxServiceChildDescriptorBindingV1 {
                    target_fd,
                    source: LinuxServiceChildDescriptorSourceV1::Endpoint(role),
                    kind,
                    retained_source_access: endpoint.access,
                    child_access,
                    retained_source_close_on_exec: true,
                    child_close_on_exec: lifecycle
                        != LinuxServiceChildDescriptorLifecycleV1::RetainPostExec,
                    lifecycle,
                })
            };

        let mut inner_launcher_descriptor_table = vec![
            endpoint_descriptor(
                0,
                LinuxServiceSetupEndpointRoleV1::TargetStdin,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                LinuxServiceChildDescriptorLifecycleV1::RetainPostExec,
            )?,
            endpoint_descriptor(
                1,
                LinuxServiceSetupEndpointRoleV1::TargetStdout,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                LinuxServiceChildDescriptorLifecycleV1::RetainPostExec,
            )?,
            endpoint_descriptor(
                2,
                LinuxServiceSetupEndpointRoleV1::TargetStderr,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                LinuxServiceChildDescriptorLifecycleV1::RetainPostExec,
            )?,
            endpoint_descriptor(
                3,
                LinuxServiceSetupEndpointRoleV1::SetupRequest,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                LinuxServiceChildDescriptorLifecycleV1::CloseAfterSetup,
            )?,
            endpoint_descriptor(
                4,
                LinuxServiceSetupEndpointRoleV1::SetupControl,
                LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                LinuxServiceChildDescriptorLifecycleV1::CloseAfterSetup,
            )?,
            endpoint_descriptor(
                5,
                LinuxServiceSetupEndpointRoleV1::SetupStatus,
                LinuxServiceSetupDescriptorAccessV1::WriteOnly,
                LinuxServiceChildDescriptorLifecycleV1::CloseOnSuccessfulExec,
            )?,
            LinuxServiceChildDescriptorBindingV1 {
                target_fd: 6,
                source: LinuxServiceChildDescriptorSourceV1::WorkingDirectory {
                    execution_root_object_id: setup.cwd.execution_root.object_id.clone(),
                    root_relative_path: setup.cwd.root_relative_path.clone(),
                },
                kind: LinuxServiceChildDescriptorKindV1::Directory,
                retained_source_access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                child_access: LinuxServiceSetupDescriptorAccessV1::ReadOnly,
                retained_source_close_on_exec: true,
                child_close_on_exec: true,
                lifecycle: LinuxServiceChildDescriptorLifecycleV1::CloseAfterSetup,
            },
        ];
        inner_launcher_descriptor_table.sort_by_key(|descriptor| descriptor.target_fd);
        if inner_launcher_descriptor_table
            .iter()
            .enumerate()
            .any(|(index, descriptor)| u32::try_from(index).ok() != Some(descriptor.target_fd))
        {
            return Err(invalid(
                "child descriptor targets are not the exact contiguous table",
            ));
        }

        let launch_images = self.service_launch_image_bindings()?;
        let bubblewrap = launch_images
            .iter()
            .find(|image| image.role == LinuxServiceExecutableRoleV1::Bubblewrap)
            .ok_or_else(|| invalid("child launch closure lost its Bubblewrap host image"))?;
        if bubblewrap.usage != LinuxServiceLaunchImageUseV1::HostExecutable {
            return Err(invalid(
                "child launch closure crossed the Bubblewrap host executable",
            ));
        }
        let image_mounts = launch_images
            .iter()
            .filter(|image| image.role != LinuxServiceExecutableRoleV1::Bubblewrap)
            .enumerate()
            .map(|(index, image)| {
                let LinuxServiceLaunchImageUseV1::ReadOnlyNamespaceMount { destination, .. } =
                    &image.usage
                else {
                    return Err(invalid(format!(
                        "child image {} lost its namespace mount destination",
                        image.object_id
                    )));
                };
                Ok(LinuxServiceChildImageMountBindingV1 {
                    mount_index: u32::try_from(index)
                        .map_err(|_| invalid("child image mount index cannot be represented"))?,
                    role: image.role,
                    object_id: image.object_id.clone(),
                    destination: destination.clone(),
                    byte_length: image.byte_length,
                    content_sha256: image.content_sha256.clone(),
                    read_only: true,
                    retained_source_close_on_exec: true,
                })
            })
            .collect::<Result<Vec<_>, LinuxProductionCommandPlanError>>()?;
        let mut destinations = BTreeSet::new();
        if image_mounts
            .iter()
            .any(|mount| !destinations.insert(mount.destination.as_str()))
        {
            return Err(invalid(
                "child image mount destinations are not pairwise distinct",
            ));
        }

        let target = &self.plan.components.binaries.target;
        let loader_closure = match &target.linkage {
            LinuxTargetLinkageV1::StaticElf => LinuxServiceTargetLoaderClosureV1::Static {
                target_object_id: target.executable.object_id.clone(),
            },
            LinuxTargetLinkageV1::DynamicElf {
                interpreter,
                runtime_objects,
                ..
            } => LinuxServiceTargetLoaderClosureV1::Dynamic {
                target_object_id: target.executable.object_id.clone(),
                interpreter_object_id: interpreter.object_id.clone(),
                runtime_object_ids_in_order: runtime_objects
                    .iter()
                    .map(|runtime| runtime.object_id.clone())
                    .collect(),
            },
        };
        let actual_roles = image_mounts
            .iter()
            .map(|mount| mount.role)
            .collect::<Vec<_>>();
        let mut expected_roles = vec![
            LinuxServiceExecutableRoleV1::InnerLauncher,
            LinuxServiceExecutableRoleV1::Target,
        ];
        if let LinuxTargetLinkageV1::DynamicElf {
            runtime_objects, ..
        } = &target.linkage
        {
            expected_roles.push(LinuxServiceExecutableRoleV1::ElfInterpreter);
            expected_roles.extend(std::iter::repeat_n(
                LinuxServiceExecutableRoleV1::RuntimeObject,
                runtime_objects.len(),
            ));
        }
        if actual_roles != expected_roles {
            return Err(invalid(
                "child image mounts differ from the exact static or dynamic loader role closure",
            ));
        }

        Ok(LinuxServiceChildLaunchClosureBindingV1 {
            schema: LINUX_SERVICE_CHILD_LAUNCH_CLOSURE_SCHEMA.into(),
            plan_digest: self.plan_digest.clone(),
            bubblewrap_host_executable_object_id: bubblewrap.object_id.clone(),
            inner_launcher_descriptor_table,
            child_target_fds_are_contiguous_and_unique: true,
            image_mounts,
            mount_destinations_must_be_pairwise_distinct: true,
            loader_closure,
        })
    }

    /// Derives the legacy mechanics request from the already-validated full
    /// plan. The service journal bridge is the only production caller, and it
    /// invokes this only after the exact canonical bytes are durably committed.
    pub(crate) fn derive_private_prepare_request_after_durable_commit(
        &self,
        receipt: &LinuxCommandPlanDurableCommitReceipt,
    ) -> Result<PrepareDomainRequest, LinuxProductionCommandPlanError> {
        if !receipt.authenticates(self) {
            return Err(invalid(
                "durable journal receipt does not authenticate this exact canonical plan",
            ));
        }
        let effect = self
            .plan
            .command_effect_authority
            .envelope()
            .effect
            .as_ref()
            .ok_or_else(|| invalid("validated plan lost command effect"))?;
        let binding = self.journal_binding()?;
        let limits = RequestedDomainLimits::derive(
            self.plan.components.resource_limits.max_processes,
            self.plan.components.resource_limits.max_memory_bytes,
        )
        .map_err(|error| invalid(format!("cannot derive cgroup limits: {error}")))?;
        Ok(PrepareDomainRequest {
            native_launch: self.plan.native_launch.clone(),
            runner_session_id: self
                .plan
                .command_effect_authority
                .envelope()
                .session_id
                .clone(),
            effect_id: effect.effect_id.clone(),
            grant_hash: self.plan.command_effect_authority.grant_hash().to_string(),
            policy_hash: effect.policy_hash.to_string(),
            command_hash: effect.request_digest.to_string(),
            request_digest: effect.request_digest.to_string(),
            expected_delegation_identity: binding.delegation_identity,
            expected_owner_uid: binding.owner_uid,
            limits,
        })
    }

    pub(crate) const fn permits_execution() -> bool {
        false
    }

    /// The mode a rebound test plan gives the service cgroup **parent**.
    ///
    /// Traversable by the service, writable only by the delegator — which is
    /// what `/sys/fs/cgroup/<parent>` is on every host this project installs
    /// on, and what `validate_cgroup` requires.
    #[cfg(test)]
    const LINUX_TEST_REBOUND_CGROUP_PARENT_MODE: u32 = 0o755;

    /// The identity a rebound test plan gives the cgroup parent.
    ///
    /// It must not be the service's: delegation leaves the parent with the
    /// delegator, and a parent the service owns is one the service can create
    /// siblings in. Root is the delegator everywhere this project installs; a
    /// binding that names root as its *service* is already refused elsewhere,
    /// and this steps aside rather than silently collapsing the two owners.
    #[cfg(test)]
    const fn rebound_delegator_uid(service_uid: u32) -> u32 {
        if service_uid == 0 { 1 } else { 0 }
    }

    #[cfg(test)]
    pub(crate) fn rebind_test_service_journal(
        mut self,
        binding: &LinuxProductionCommandPlanJournalBindingV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let retained = &mut self.plan.components.retained;
        let mut update = |object_id: &str,
                          identity: CgroupObjectIdentity,
                          mount_id: u64,
                          mode: u32,
                          owner_uid: u32| {
            let object = retained
                .objects
                .iter_mut()
                .find(|candidate| candidate.object_id == object_id)
                .ok_or_else(|| invalid(format!("test object {object_id} is absent")))?;
            object.device_id = identity.device;
            object.inode = identity.inode;
            object.mount_id = mount_id.max(1);
            object.mode = DIRECTORY_MODE | mode;
            object.owner_uid = owner_uid;
            object.owner_gid = owner_uid;
            Ok(())
        };
        let service_mount = binding.service_state_root_identity.device.max(1);
        update(
            &retained.private_state_root_object_id,
            binding.service_state_root_identity,
            service_mount,
            0o700,
            binding.owner_uid,
        )?;
        update(
            &retained.service_owned_journal_index_root_object_id,
            binding.singleton_journal_root_identity,
            service_mount,
            0o700,
            binding.owner_uid,
        )?;
        let cgroup_mount = binding.service_parent_identity.device.max(1);
        // The parent stays the **delegator's**, and its mode is its own rather
        // than the delegation's: cgroup v2 delegation chowns the delegated
        // subtree and leaves the parent alone, so a rebound plan that gave both
        // one owner would describe a host no correct installer produces.
        update(
            &retained.cgroup.service_parent_object_id,
            binding.service_parent_identity,
            cgroup_mount,
            Self::LINUX_TEST_REBOUND_CGROUP_PARENT_MODE,
            Self::rebound_delegator_uid(binding.owner_uid),
        )?;
        update(
            &retained.cgroup.delegation_root_object_id,
            binding.delegation_identity,
            cgroup_mount,
            binding.delegation_mode,
            binding.owner_uid,
        )?;
        // Schema version 1 also invented four leaf identities here, as
        // `delegation_identity.inode + 1..=4`. Nothing ever read them against
        // a leaf that existed, so they are gone: the plan names no leaf, and
        // `bind_prepared_command_domain_leaf` binds one from a live read.
        self.plan
            .components
            .release
            .authenticated_platform_service_digest =
            binding.authenticated_platform_service_digest.clone();
        Self::from_plan(self.plan)
    }

    #[cfg(test)]
    pub(crate) fn rebind_test_bubblewrap_file(
        mut self,
        file: &LinuxBootstrapFileIdentityV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let object_id = self.plan.components.binaries.bubblewrap.object_id.clone();
        let retained = self
            .plan
            .components
            .retained
            .objects
            .iter_mut()
            .find(|candidate| candidate.object_id == object_id)
            .ok_or_else(|| invalid("test Bubblewrap retained identity is absent"))?;
        retained.device_id = file.device_id;
        retained.inode = file.inode;
        retained.mount_id = file.mount_id;
        retained.mode = file.mode;
        retained.owner_uid = file.owner_uid;
        retained.owner_gid = file.owner_gid;
        retained.link_count = file.link_count;
        retained.byte_length = Some(file.byte_length);
        self.plan.components.binaries.bubblewrap.byte_length = file.byte_length;
        self.plan.components.binaries.bubblewrap.content_sha256 = file.content_sha256.clone();
        Self::from_plan(self.plan)
    }

    #[cfg(test)]
    pub(crate) fn rebind_test_setup_object(
        mut self,
        binding: &LinuxServiceSetupObjectIdentityV1,
        content_sha256: Option<&Digest>,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let retained = self
            .plan
            .components
            .retained
            .objects
            .iter_mut()
            .find(|candidate| candidate.object_id == binding.object_id)
            .ok_or_else(|| invalid(format!("test setup object {} is absent", binding.object_id)))?;
        if retained.kind != binding.kind {
            return Err(invalid(format!(
                "test setup object {} crossed its planned kind",
                binding.object_id
            )));
        }
        retained.device_id = binding.device_id;
        retained.inode = binding.inode;
        retained.mount_id = binding.mount_id;
        retained.mode = binding.mode;
        retained.owner_uid = binding.owner_uid;
        retained.owner_gid = binding.owner_gid;
        retained.link_count = binding.link_count;
        retained.byte_length = binding.byte_length;
        if self.plan.components.binaries.setup_channel.object_id == binding.object_id {
            let digest = content_sha256.ok_or_else(|| {
                invalid("test setup-channel rebind requires its complete content digest")
            })?;
            let byte_length = binding.byte_length.ok_or_else(|| {
                invalid("test setup-channel rebind requires its exact byte length")
            })?;
            self.plan.components.binaries.setup_channel.byte_length = byte_length;
            self.plan.components.binaries.setup_channel.content_sha256 = digest.clone();
        } else if content_sha256.is_some() {
            return Err(invalid(
                "only the planned setup request may receive a setup content digest",
            ));
        }
        // Move the Landlock scope with its rebound retained object so the identity
        // and confinement scope remain paired.
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut self.plan.components.landlock;
        if let Some(scope) = ruleset
            .scopes
            .iter_mut()
            .find(|candidate| candidate.object_id == binding.object_id)
        {
            scope.device_id = binding.device_id;
            scope.inode = binding.inode;
            ruleset.ruleset_sha256 = ruleset.canonical_digest();
        }
        Self::from_plan(self.plan)
    }

    #[cfg(test)]
    pub(crate) fn rebind_test_executable_file(
        mut self,
        object_id: &str,
        resolved_path: &str,
        file: &LinuxBootstrapFileIdentityV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let retained = self
            .plan
            .components
            .retained
            .objects
            .iter_mut()
            .find(|candidate| candidate.object_id == object_id)
            .ok_or_else(|| invalid(format!("test executable object {object_id} is absent")))?;
        if !retained.is_regular_or_sealed() {
            return Err(invalid(format!(
                "test executable object {object_id} is not a regular or sealed file"
            )));
        }
        retained.device_id = file.device_id;
        retained.inode = file.inode;
        retained.mount_id = file.mount_id;
        retained.mode = file.mode;
        retained.owner_uid = file.owner_uid;
        retained.owner_gid = file.owner_gid;
        retained.link_count = file.link_count;
        retained.byte_length = Some(file.byte_length);

        let update = |image: &mut LinuxAuthenticatedFileV1| {
            if image.object_id == object_id {
                image.resolved_path = resolved_path.to_owned();
                image.byte_length = file.byte_length;
                image.content_sha256 = file.content_sha256.clone();
                true
            } else {
                false
            }
        };
        let binaries = &mut self.plan.components.binaries;
        let mut found = update(&mut binaries.bubblewrap)
            || update(&mut binaries.inner_launcher)
            || update(&mut binaries.target.executable);
        if let LinuxTargetLinkageV1::DynamicElf {
            interpreter,
            runtime_objects,
            ..
        } = &mut binaries.target.linkage
        {
            found |= update(interpreter);
            for runtime in runtime_objects {
                found |= update(runtime);
            }
        }
        if !found {
            return Err(invalid(format!(
                "test executable object {object_id} is not a planned command image"
            )));
        }
        for retained_mount in &mut self.plan.components.mounts.read_only {
            if retained_mount.source_object_id == object_id
                && matches!(
                    retained_mount.purpose,
                    LinuxMountPurposeV1::InnerLauncher
                        | LinuxMountPurposeV1::TargetExecutable
                        | LinuxMountPurposeV1::ElfInterpreter
                        | LinuxMountPurposeV1::RuntimeObject
                )
            {
                retained_mount.destination = resolved_path.to_owned();
            }
        }
        self.plan.components.canonicalize();
        Self::from_plan(self.plan)
    }

    #[cfg(test)]
    pub(crate) fn substitute_test_same_effect_plan(
        mut self,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        self.plan.components.binaries.bubblewrap_version =
            "bubblewrap 0.11.0+same-effect-substitution".into();
        Self::from_plan(self.plan)
    }

    /// Widens the modeled Landlock ABI window of a test plan by one.
    ///
    /// This replaced a substitution of the Landlock active-probe-suite and
    /// seccomp forbidden-syscall digests, which schema version 3 removed
    /// because nothing could produce them. The window is the honest
    /// substitution subject: it is a real compiled bound that the bootstrap
    /// binding carries and that a live `observed_kernel_abi` is measured
    /// against, so crossing it crosses something that means something.
    #[cfg(test)]
    pub(crate) fn substitute_test_kernel_control_window(
        mut self,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe {
            maximum_modeled_kernel_abi,
            ..
        } = &mut self.plan.components.landlock;
        *maximum_modeled_kernel_abi = maximum_modeled_kernel_abi.saturating_sub(1);
        Self::from_plan(self.plan)
    }

    /// Replaces one committed Landlock scope identity of a test plan with a
    /// different real one, leaving the ruleset digest stale.
    ///
    /// The substitution subject schema version 4 makes available: under version
    /// 3 there was no artefact to substitute, which is why the window above was
    /// the only honest one.
    #[cfg(test)]
    pub(crate) fn substitute_test_landlock_scope_identity(
        mut self,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let LinuxLandlockPlanV1::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } =
            &mut self.plan.components.landlock;
        let scope = ruleset
            .scopes
            .first_mut()
            .expect("a validated ruleset grants at least one scope");
        scope.inode = scope.inode.wrapping_add(1);
        Self::from_plan(self.plan)
    }
}

/// Just enough of a persisted plan to say which schema version wrote it.
///
/// Deliberately not `deny_unknown_fields`: this type exists to read one field
/// out of a document whose other fields belong to a schema this build may not
/// define at all.
#[derive(Deserialize)]
struct LinuxProductionCommandPlanSchemaVersionV1 {
    schema_version: u32,
}

/// The refusal a record from another schema version meets.
///
/// The version-3 message named neither operand — it said only that the schema
/// version "differs" — so a restart against a persisted older record reported
/// a mismatch without saying from what to what. A refusal an operator cannot
/// diagnose is only half a refusal.
fn schema_version_refusal(observed: u32) -> LinuxProductionCommandPlanError {
    invalid(format!(
        "Linux production command-plan schema version {observed} is not the required version \
         {LINUX_PRODUCTION_COMMAND_PLAN_SCHEMA_VERSION}; an older record is refused and never \
         migrated. Version 4 already carried Landlock and network-seccomp artefacts; version 5 \
         adds the namespace-filter channel, which no earlier record can grow"
    ))
}

fn digest_plan(bytes: &[u8]) -> Result<Digest, LinuxProductionCommandPlanError> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| invalid("Linux production command plan length exceeds u64"))?;
    let mut preimage = Vec::with_capacity(
        LINUX_PRODUCTION_COMMAND_PLAN_DOMAIN.len() + std::mem::size_of::<u64>() + bytes.len(),
    );
    preimage.extend_from_slice(LINUX_PRODUCTION_COMMAND_PLAN_DOMAIN);
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(bytes);
    Ok(Digest::sha256(&preimage))
}

fn validate_role_snapshot(
    authority: &CommandEffectAuthorityV1,
    binding: &LinuxRoleSnapshotBindingV1,
    policy: &ExecutionPolicy,
) -> Result<(), LinuxProductionCommandPlanError> {
    let effect = authority
        .envelope()
        .effect
        .as_ref()
        .ok_or_else(|| invalid("role/snapshot binding has no effect context"))?;
    if binding.role != authority.role() || binding.input_snapshot != effect.input_snapshot {
        return Err(invalid(
            "role/snapshot binding differs from the complete command-effect authority",
        ));
    }
    validate_nonzero_digest(&binding.input_snapshot, "input snapshot")?;
    validate_identifier(
        &binding.execution_root_object_id,
        "execution root object ID",
    )?;
    validate_absolute_path(
        &binding.execution_namespace_root,
        "execution namespace root",
    )?;
    let exact_role = matches!(
        (binding.role, binding.view, policy.mutation_mode),
        (
            RunnerRole::Worker,
            LinuxExecutionViewV1::WorkerReadOnly,
            MutationMode::ReadOnly
        ) | (
            RunnerRole::Worker,
            LinuxExecutionViewV1::WorkerShadow,
            MutationMode::ShadowWorkspace
        ) | (
            RunnerRole::FinalVerifier,
            LinuxExecutionViewV1::FinalVerifierSnapshot,
            MutationMode::ReadOnly,
        )
    );
    if !exact_role {
        return Err(invalid(
            "worker/final-verifier execution view differs from compiled mutation policy",
        ));
    }
    match (
        binding.role,
        effect.task_id.as_ref(),
        effect.worker_id.as_ref(),
    ) {
        (RunnerRole::Worker, Some(task), Some(worker)) => {
            validate_identifier(task, "worker task ID")?;
            validate_identifier(worker, "worker ID")?;
        }
        (RunnerRole::FinalVerifier, None, None) => {}
        _ => {
            return Err(invalid(
                "task/worker effect scope differs from exact command role",
            ));
        }
    }
    Ok(())
}

fn validate_resource_limits(
    limits: &LinuxResourceLimitsV1,
    expected: ResourceLimits,
) -> Result<(), LinuxProductionCommandPlanError> {
    if limits.wall_time_ms != expected.wall_time_ms
        || limits.max_output_bytes != expected.max_output_bytes
        || limits.max_processes != expected.max_processes
        || limits.max_memory_bytes != expected.max_memory_bytes
    {
        return Err(invalid(
            "Linux resource limits differ from the independently compiled policy",
        ));
    }
    if limits.wall_time_ms == 0
        || limits.wall_time_ms > MAX_WALL_TIME_MS
        || limits.max_output_bytes == 0
        || limits.max_output_bytes > MAX_OUTPUT_BYTES
        || limits.max_processes == 0
        || limits.max_processes > MAX_PROCESSES
        || limits.max_memory_bytes == Some(0)
        || limits
            .max_memory_bytes
            .is_some_and(|value| value > MAX_MEMORY_BYTES)
        || limits.swap_bytes != 0
    {
        return Err(invalid(
            "Linux resource limits are zero, exceed hard bounds, or permit swap",
        ));
    }
    Ok(())
}

fn validate_network(
    network: &LinuxNetworkNamespacePolicyV1,
    expected: ExecutionNetwork,
    grant_hash: &Digest,
    policy_hash: &Digest,
) -> Result<(), LinuxProductionCommandPlanError> {
    match (network, expected) {
        (LinuxNetworkNamespacePolicyV1::NewIsolatedNamespace, ExecutionNetwork::None) => Ok(()),
        (
            LinuxNetworkNamespacePolicyV1::RetainHostNamespaceForRenewedAction {
                grant_hash: actual_grant,
                policy_hash: actual_policy,
            },
            ExecutionNetwork::FullForAction,
        ) if actual_grant == grant_hash && actual_policy == policy_hash => Ok(()),
        _ => Err(invalid(
            "network namespace mode differs from renewed grant and compiled action policy",
        )),
    }
}

fn validate_retained_objects<'a>(
    retained: &'a LinuxRetainedCapabilitySetV1,
    workspace_identity: &LinuxWorkspaceIdentityV1,
) -> Result<BTreeMap<&'a str, &'a LinuxRetainedObjectIdentityV1>, LinuxProductionCommandPlanError> {
    if retained.objects.is_empty() || retained.objects.len() > MAX_RETAINED_OBJECTS {
        return Err(invalid(
            "retained-object table is empty or exceeds its hard bound",
        ));
    }
    if !retained
        .objects
        .windows(2)
        .all(|pair| pair[0].object_id < pair[1].object_id)
    {
        return Err(invalid(
            "retained-object table must be uniquely sorted by object ID",
        ));
    }
    let mut objects = BTreeMap::new();
    let mut kernel_identities = BTreeSet::new();
    for entry in &retained.objects {
        entry.validate()?;
        if objects.insert(entry.object_id.as_str(), entry).is_some() {
            return Err(invalid("retained-object table contains a duplicate ID"));
        }
        // A bind mount gives the same inode another mount identity without
        // increasing its link count. Object IDs are semantic role boundaries,
        // so mount aliases of one kernel inode must not satisfy two roles.
        if !kernel_identities.insert((entry.device_id, entry.inode)) {
            return Err(invalid(
                "two retained object IDs alias one kernel inode, including across bind mounts",
            ));
        }
    }
    let workspace = object(
        &objects,
        &retained.workspace_root_object_id,
        "workspace root",
    )?;
    if !workspace.is_directory()
        || workspace.device_id != workspace_identity.device_id
        || workspace.inode != workspace_identity.inode
    {
        return Err(invalid(
            "retained workspace object differs from the independently restored grant identity",
        ));
    }
    let private_state = object(
        &objects,
        &retained.private_state_root_object_id,
        "private-state root",
    )?;
    let journal_root = object(
        &objects,
        &retained.service_owned_journal_index_root_object_id,
        "service-owned journal/index root",
    )?;
    if !private_state.is_directory()
        || !journal_root.is_directory()
        || private_state.owner_uid != journal_root.owner_uid
        || private_state.mode & 0o077 != 0
        || journal_root.mode & 0o077 != 0
    {
        return Err(invalid(
            "service-state and journal roots must be distinct private retained directories with one owner",
        ));
    }
    if retained.private_state_root_object_id == retained.service_owned_journal_index_root_object_id
    {
        return Err(invalid(
            "singleton journal/index root must have its own retained directory identity",
        ));
    }
    Ok(objects)
}

fn validate_binaries(
    binaries: &LinuxBinaryIdentitiesV1,
    authority: &CommandEffectAuthorityV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    if binaries.bubblewrap_version.is_empty()
        || binaries.bubblewrap_version.len() > MAX_VERSION_BYTES
        || !binaries
            .bubblewrap_version
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(invalid(
            "Bubblewrap version is empty or outside its text bound",
        ));
    }
    binaries
        .bubblewrap
        .validate(objects, "Bubblewrap image", true)?;
    binaries
        .inner_launcher
        .validate(objects, "inner launcher image", true)?;
    binaries.setup_channel.validate(objects)?;
    binaries
        .target
        .executable
        .validate(objects, "target executable", true)?;
    let (RunnerRequest::WorkerRunCommand { command, .. }
    | RunnerRequest::FinalVerifierRunCommand { command, .. }) = &authority.envelope().request
    else {
        return Err(invalid("Linux plan authority is not a command"));
    };
    if binaries.target.requested_program != command.program {
        return Err(invalid(
            "authenticated target resolution differs from the exact requested program",
        ));
    }
    if binaries.target.requested_program.is_empty()
        || binaries.target.requested_program.len() > MAX_PATH_BYTES
    {
        return Err(invalid("requested program is outside Linux plan bounds"));
    }
    let mut role_ids = BTreeSet::from([
        binaries.bubblewrap.object_id.as_str(),
        binaries.inner_launcher.object_id.as_str(),
        binaries.setup_channel.object_id.as_str(),
        binaries.target.executable.object_id.as_str(),
    ]);
    if role_ids.len() != 4 {
        return Err(invalid(
            "Bubblewrap, inner launcher, setup channel, and target identities must be distinct",
        ));
    }
    match &binaries.target.linkage {
        LinuxTargetLinkageV1::StaticElf => {}
        LinuxTargetLinkageV1::DynamicElf {
            interpreter,
            runtime_objects,
            ..
        } => {
            interpreter.validate(objects, "ELF interpreter", true)?;
            if runtime_objects.len() > MAX_RUNTIME_OBJECTS {
                return Err(invalid("runtime-object count exceeds its hard bound"));
            }
            if !runtime_objects.windows(2).all(|pair| {
                (pair[0].resolved_path.as_str(), pair[0].object_id.as_str())
                    < (pair[1].resolved_path.as_str(), pair[1].object_id.as_str())
            }) {
                return Err(invalid(
                    "runtime objects must be uniquely sorted by path and identity",
                ));
            }
            if !role_ids.insert(interpreter.object_id.as_str()) {
                return Err(invalid("ELF interpreter crosses another executable role"));
            }
            for runtime in runtime_objects {
                runtime.validate(objects, "runtime object", false)?;
                if !role_ids.insert(runtime.object_id.as_str()) {
                    return Err(invalid(
                        "runtime object identity is duplicated or crosses an executable role",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Validates the cgroup v2 delegation boundary. The delegator owns the parent;
/// the service owns only its delegated subtree and control files.
fn validate_cgroup(
    retained: &LinuxRetainedCapabilitySetV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    let cgroup = &retained.cgroup;
    if cgroup.filesystem_magic != CGROUP2_SUPER_MAGIC {
        return Err(invalid("cgroup identity is not bound to cgroup v2"));
    }
    // The identity the service runs as, read off the root it owns rather than
    // named a second time: `validate_retained_objects` has already required the
    // private-state root and the singleton journal root to share one owner, so
    // this is that one owner.
    let service_identity = object(
        objects,
        &retained.private_state_root_object_id,
        "service-state root",
    )?;
    let service_parent = object(
        objects,
        &cgroup.service_parent_object_id,
        "service cgroup parent",
    )?;
    let delegation = object(
        objects,
        &cgroup.delegation_root_object_id,
        "cgroup delegation root",
    )?;
    if service_parent.kind != LinuxRetainedObjectKindV1::CgroupDirectory
        || delegation.kind != LinuxRetainedObjectKindV1::CgroupDirectory
        || service_parent.inode == delegation.inode
        || service_parent.device_id != delegation.device_id
        || service_parent.mount_id != delegation.mount_id
        || delegation.mode & 0o002 != 0
    {
        return Err(invalid(
            "service parent and cgroup delegation identities are crossed or incompatible",
        ));
    }
    // The delegated subtree is the service's. A delegation owned by anyone
    // else — the delegator included — is not a delegation to this service.
    if delegation.owner_uid != service_identity.owner_uid {
        return Err(invalid(
            "the delegated cgroup is not owned by the service identity that owns the state root",
        ));
    }
    // The parent is the delegator's, and the service must not be able to write
    // it: directory write is exactly what creating a sibling delegation, or
    // rmdir-and-recreating this one under the same name, requires. Group write
    // is refused outright because supplementary group membership is not
    // something a plan can read.
    if service_parent.owner_uid == service_identity.owner_uid || service_parent.mode & 0o022 != 0 {
        return Err(invalid(
            "the service cgroup parent is owned by the service it delegates to, or is writable outside its owner",
        ));
    }
    if cgroup.service_parent_object_id == cgroup.delegation_root_object_id {
        return Err(invalid(
            "the delegated cgroup must have its own retained identity",
        ));
    }
    // There is deliberately nothing here about a leaf: the plan names none.
    // `LinuxCommandDomainLeafPlanV1` says why, and
    // `bind_prepared_command_domain_leaf` is where a leaf identity enters,
    // from a live read taken after `prepare_domain` created it.
    cgroup.leaf.validate()
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear validator keeps the complete cross-mount invariant visible for security review"
)]
fn validate_mounts(
    mounts: &LinuxMountPlanV1,
    role: &LinuxRoleSnapshotBindingV1,
    binaries: &LinuxBinaryIdentitiesV1,
    retained: &LinuxRetainedCapabilitySetV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    let total_mounts = mounts
        .read_only
        .len()
        .checked_add(mounts.read_write.len())
        .ok_or_else(|| invalid("mount count overflow"))?;
    if total_mounts == 0 || total_mounts > MAX_MOUNTS {
        return Err(invalid("mount count is empty or exceeds its hard bound"));
    }
    if !mounts
        .read_only
        .windows(2)
        .all(|pair| mount_order(&pair[0], &pair[1]).is_lt())
        || !mounts
            .read_write
            .windows(2)
            .all(|pair| mount_order(&pair[0], &pair[1]).is_lt())
        || !mounts.git_masks.windows(2).all(|pair| {
            (&pair[0].workspace_destination, &pair[0].masked_destination)
                < (&pair[1].workspace_destination, &pair[1].masked_destination)
        })
    {
        return Err(invalid(
            "mount and .git-mask collections must be uniquely sorted",
        ));
    }
    let mut destinations = BTreeSet::new();
    let mut purpose_counts = BTreeMap::<LinuxMountPurposeV1, usize>::new();
    for (read_only, entries) in [(true, &mounts.read_only), (false, &mounts.read_write)] {
        for mount in entries {
            validate_absolute_path(&mount.destination, "mount destination")?;
            if mount.destination == "/" || contains_git_component(&mount.destination) {
                return Err(invalid(
                    "mount destination must not be host root or enter .git",
                ));
            }
            if !destinations.insert(mount.destination.as_str()) {
                return Err(invalid("mount destinations must be globally unique"));
            }
            let source = object(objects, &mount.source_object_id, "mount source")?;
            validate_mount_kind(mount, source)?;
            let access_matches = if read_only {
                !matches!(
                    mount.purpose,
                    LinuxMountPurposeV1::WorkerShadow
                        | LinuxMountPurposeV1::PrivateTemp
                        | LinuxMountPurposeV1::OutputSpool
                )
            } else {
                matches!(
                    mount.purpose,
                    LinuxMountPurposeV1::WorkerShadow
                        | LinuxMountPurposeV1::PrivateTemp
                        | LinuxMountPurposeV1::OutputSpool
                )
            };
            if !access_matches {
                return Err(invalid(
                    "mount purpose is crossed between read-only and read-write sets",
                ));
            }
            *purpose_counts.entry(mount.purpose).or_default() += 1;
        }
    }
    require_purpose_count(&purpose_counts, LinuxMountPurposeV1::LiveWorkspace, 1)?;
    require_purpose_count(&purpose_counts, LinuxMountPurposeV1::InnerLauncher, 1)?;
    require_purpose_count(&purpose_counts, LinuxMountPurposeV1::TargetExecutable, 1)?;
    require_purpose_count(&purpose_counts, LinuxMountPurposeV1::PrivateTemp, 1)?;
    require_purpose_count(&purpose_counts, LinuxMountPurposeV1::OutputSpool, 1)?;
    let live = unique_mount(mounts, LinuxMountPurposeV1::LiveWorkspace)?;
    if live.source_object_id != retained.workspace_root_object_id {
        return Err(invalid(
            "live workspace mount differs from retained grant-root identity",
        ));
    }
    let inner = unique_mount(mounts, LinuxMountPurposeV1::InnerLauncher)?;
    let target = unique_mount(mounts, LinuxMountPurposeV1::TargetExecutable)?;
    if inner.source_object_id != binaries.inner_launcher.object_id
        || inner.destination != binaries.inner_launcher.resolved_path
        || target.source_object_id != binaries.target.executable.object_id
        || target.destination != binaries.target.executable.resolved_path
    {
        return Err(invalid(
            "inner-launcher or target mount crosses its authenticated image",
        ));
    }
    let (execution_purpose, expected_access_read_only) = match role.view {
        LinuxExecutionViewV1::WorkerReadOnly => (LinuxMountPurposeV1::LiveWorkspace, true),
        LinuxExecutionViewV1::WorkerShadow => (LinuxMountPurposeV1::WorkerShadow, false),
        LinuxExecutionViewV1::FinalVerifierSnapshot => {
            (LinuxMountPurposeV1::FinalVerifierSnapshot, true)
        }
    };
    require_purpose_count(&purpose_counts, execution_purpose, 1)?;
    let execution = unique_mount(mounts, execution_purpose)?;
    if execution.source_object_id != role.execution_root_object_id
        || execution.destination != role.execution_namespace_root
        || mounts.read_only.contains(execution) != expected_access_read_only
    {
        return Err(invalid(
            "role-exact execution root crosses mount access, identity, or namespace path",
        ));
    }
    match &binaries.target.linkage {
        LinuxTargetLinkageV1::StaticElf => {
            require_purpose_count(&purpose_counts, LinuxMountPurposeV1::ElfInterpreter, 0)?;
            require_purpose_count(&purpose_counts, LinuxMountPurposeV1::RuntimeObject, 0)?;
        }
        LinuxTargetLinkageV1::DynamicElf {
            interpreter,
            runtime_objects,
            ..
        } => {
            require_purpose_count(&purpose_counts, LinuxMountPurposeV1::ElfInterpreter, 1)?;
            let interpreter_mount = unique_mount(mounts, LinuxMountPurposeV1::ElfInterpreter)?;
            if interpreter_mount.source_object_id != interpreter.object_id
                || interpreter_mount.destination != interpreter.resolved_path
            {
                return Err(invalid(
                    "ELF interpreter mount crosses its authenticated identity",
                ));
            }
            require_purpose_count(
                &purpose_counts,
                LinuxMountPurposeV1::RuntimeObject,
                runtime_objects.len(),
            )?;
            let runtime_mounts = mounts
                .read_only
                .iter()
                .filter(|mount| mount.purpose == LinuxMountPurposeV1::RuntimeObject)
                .collect::<Vec<_>>();
            let expected = runtime_objects
                .iter()
                .map(|runtime| (runtime.object_id.as_str(), runtime.resolved_path.as_str()))
                .collect::<BTreeSet<_>>();
            let actual = runtime_mounts
                .iter()
                .map(|mount| (mount.source_object_id.as_str(), mount.destination.as_str()))
                .collect::<BTreeSet<_>>();
            if actual != expected {
                return Err(invalid(
                    "runtime mounts differ from the complete authenticated runtime identity set",
                ));
            }
        }
    }
    validate_git_masks(mounts, objects)?;
    Ok(())
}

fn validate_mount_kind(
    mount: &LinuxRetainedMountV1,
    source: &LinuxRetainedObjectIdentityV1,
) -> Result<(), LinuxProductionCommandPlanError> {
    let requires_directory = matches!(
        mount.purpose,
        LinuxMountPurposeV1::LiveWorkspace
            | LinuxMountPurposeV1::WorkerShadow
            | LinuxMountPurposeV1::FinalVerifierSnapshot
            | LinuxMountPurposeV1::RuntimeRoot
            | LinuxMountPurposeV1::PrivateTemp
            | LinuxMountPurposeV1::OutputSpool
    );
    if requires_directory != source.is_directory() {
        return Err(invalid(format!(
            "mount {} source kind differs from its semantic purpose",
            mount.destination
        )));
    }
    Ok(())
}

fn validate_git_masks(
    mounts: &LinuxMountPlanV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    let project_destinations = mounts
        .read_only
        .iter()
        .chain(&mounts.read_write)
        .filter(|mount| {
            matches!(
                mount.purpose,
                LinuxMountPurposeV1::LiveWorkspace
                    | LinuxMountPurposeV1::WorkerShadow
                    | LinuxMountPurposeV1::FinalVerifierSnapshot
            )
        })
        .map(|mount| mount.destination.as_str())
        .collect::<BTreeSet<_>>();
    if mounts.git_masks.len() != project_destinations.len() {
        return Err(invalid(
            "every project view requires exactly one explicit .git mask",
        ));
    }
    let mut seen = BTreeSet::new();
    for mask in &mounts.git_masks {
        validate_absolute_path(&mask.workspace_destination, ".git mask workspace")?;
        validate_absolute_path(&mask.masked_destination, ".git mask destination")?;
        if !project_destinations.contains(mask.workspace_destination.as_str())
            || mask.masked_destination
                != format!("{}/.git", mask.workspace_destination.trim_end_matches('/'))
            || !seen.insert(mask.workspace_destination.as_str())
        {
            return Err(invalid(
                ".git mask is missing, duplicated, or crossed to another project view",
            ));
        }
        if !object(
            objects,
            &mask.empty_directory_object_id,
            ".git empty replacement",
        )?
        .is_directory()
        {
            return Err(invalid(
                ".git mask replacement must be a retained directory",
            ));
        }
        validate_nonzero_digest(
            &mask.expected_empty_observation_digest,
            ".git empty observation",
        )?;
    }
    Ok(())
}

/// Validates everything the two mandatory kernel controls still commit to.
///
/// There is deliberately no digest check here any more, and no digest to
/// check: schema version 3 removed the eight `Digest` fields that
/// [`LinuxLandlockPlanV1`] and [`LinuxSeccompPlanV1`] replaced. The only test
/// they ever met was `validate_nonzero_digest`, which rejects an all-zero
/// string and admits every other 64-character value, so for two subsystems
/// that do not exist the fields could carry nothing but invention. Checking
/// them harder was not available — there was no artefact to compare against —
/// so the fields went instead. What is left is real: an ABI window that is a
/// compiled constant and that a live `observed_kernel_abi` is measured against
/// at bootstrap, and two enforcement contracts.
fn validate_mandatory_kernel_controls(
    landlock: &LinuxLandlockPlanV1,
    seccomp: &LinuxSeccompPlanV1,
) -> Result<(), LinuxProductionCommandPlanError> {
    if landlock.minimum_kernel_abi() == 0
        || landlock.maximum_modeled_kernel_abi() > MAX_LANDLOCK_ABI
        || landlock.maximum_modeled_kernel_abi() < landlock.minimum_kernel_abi()
    {
        return Err(invalid("Landlock ABI requirement is empty or inverted"));
    }
    if landlock.enforcement() != LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec
        || seccomp.enforcement() != LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec
        || seccomp.default_action() != LinuxSeccompDefaultActionV1::KillProcess
    {
        return Err(invalid(
            "mandatory kernel-control enforcement or default action is not the required contract",
        ));
    }
    Ok(())
}

/// Validates the two artefacts schema version 4 added, and nothing the
/// function above already checks.
///
/// It is a **separate** function on purpose.
/// `validate_mandatory_kernel_controls` is byte-identical to the version-3
/// build — the ABI window, both enforcement contracts and the `KillProcess`
/// matched action are still required exactly as they were — and every
/// requirement here is an addition to it. Nothing below can make a plan that
/// version 3 refused acceptable: a version-3 plan has no artefact at all and is
/// refused before this runs, by the schema-version clause.
///
/// The refusals are of the artefact's internal consistency and of its
/// relationship to the window the frozen function checks. They are not a
/// substitute for the live proof: the artefact is bound to a kernel that
/// enforced it by `validate_service_bootstrap_evidence`, and a plan that
/// validates here has still proved nothing about any host.
#[allow(
    clippy::too_many_lines,
    reason = "one linear audit keeps every artefact field and the requirement it must meet visible in the order they are checked"
)]
fn validate_mandatory_control_artefacts(
    landlock: &LinuxLandlockPlanV1,
    seccomp: &LinuxSeccompPlanV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    let ruleset = landlock.ruleset();
    if ruleset.created_at_kernel_abi < landlock.minimum_kernel_abi()
        || ruleset.created_at_kernel_abi > landlock.maximum_modeled_kernel_abi()
    {
        return Err(invalid(
            "the committed Landlock ruleset was created outside the plan's own modeled ABI window",
        ));
    }
    if ruleset.handled_access_bits == 0 {
        return Err(invalid(
            "the committed Landlock ruleset handles no access right, so it restricts nothing",
        ));
    }
    if ruleset.scopes.is_empty() || ruleset.scopes.len() > MAX_LINUX_LANDLOCK_SCOPES {
        return Err(invalid(
            "the committed Landlock ruleset grants no scope or exceeds its hard scope bound",
        ));
    }
    let mut previous: Option<&str> = None;
    for scope in &ruleset.scopes {
        validate_identifier(&scope.object_id, "Landlock scope object ID")?;
        validate_absolute_path(&scope.resolved_path, "Landlock scope")?;
        if scope.device_id == 0 || scope.inode == 0 {
            return Err(invalid(
                "a committed Landlock scope carries no live kernel identity",
            ));
        }
        if scope.access_bits == 0 || scope.access_bits & !ruleset.handled_access_bits != 0 {
            return Err(invalid(
                "a committed Landlock scope grants nothing or grants a right the ruleset does not handle",
            ));
        }
        // The scope has to be one of the plan's own retained objects, with the
        // same kernel identity. Without this a ruleset could grant a real
        // directory the rest of the plan never authenticated.
        let retained = object(objects, &scope.object_id, "Landlock scope")?;
        if !retained.is_directory() {
            return Err(invalid(format!(
                "the committed Landlock scope {} is not a retained directory",
                scope.object_id
            )));
        }
        let observed = retained.kernel_observation();
        if observed.device_id != scope.device_id || observed.inode != scope.inode {
            return Err(invalid(format!(
                "the committed Landlock scope {} carries an identity the plan's object table does not",
                scope.object_id
            )));
        }
        if previous.is_some_and(|earlier| earlier >= scope.object_id.as_str()) {
            return Err(invalid(
                "committed Landlock scopes must be unique and bytewise sorted by object ID",
            ));
        }
        previous = Some(scope.object_id.as_str());
    }
    let witness = &ruleset.denial_witness;
    // Admit `/` only as a denial witness. The generic component-path validator
    // continues to reject it.
    if witness.resolved_path != "/" {
        validate_absolute_path(&witness.resolved_path, "Landlock denial witness")?;
    }
    if witness.device_id == 0 || witness.inode == 0 {
        return Err(invalid(
            "the committed Landlock denial witness carries no live kernel identity",
        ));
    }
    if ruleset
        .scopes
        .iter()
        .any(|scope| scope.device_id == witness.device_id && scope.inode == witness.inode)
    {
        return Err(invalid(
            "the committed Landlock denial witness is one of the scopes the ruleset grants, so being denied it would prove nothing",
        ));
    }
    if ruleset.ruleset_sha256 != ruleset.canonical_digest() {
        return Err(invalid(
            "the committed Landlock ruleset digest is not the digest of the ruleset it accompanies",
        ));
    }

    let filter = seccomp.filter();
    if filter.denied_syscalls.is_empty()
        || filter.denied_syscalls.len() > MAX_LINUX_SECCOMP_DENIED_SYSCALLS
    {
        return Err(invalid(
            "the committed seccomp filter denies no syscall or exceeds its hard bound",
        ));
    }
    let mut previous: Option<&str> = None;
    for denied in &filter.denied_syscalls {
        validate_identifier(&denied.name, "seccomp denied syscall")?;
        if denied.number < 0 {
            return Err(invalid(
                "a committed seccomp denial carries no syscall number",
            ));
        }
        if previous.is_some_and(|earlier| earlier >= denied.name.as_str()) {
            return Err(invalid(
                "committed seccomp denials must be unique and bytewise sorted by name",
            ));
        }
        previous = Some(denied.name.as_str());
    }
    if filter.instruction_count == 0 {
        return Err(invalid(
            "the committed seccomp filter assembled to no instruction",
        ));
    }
    validate_nonzero_digest(&filter.program_sha256, "seccomp assembled program")?;
    if filter.filter_sha256
        != filter.canonical_digest(seccomp.audit_architecture(), seccomp.default_action())
    {
        return Err(invalid(
            "the committed seccomp filter digest is not the digest of the filter it accompanies",
        ));
    }

    validate_namespace_filter(seccomp)?;
    Ok(())
}

/// Validates the second committed filter, added by schema version 5.
///
/// The properties mirror the network filter's, plus the one this filter exists
/// for: a denial must say *when* it applies. A conditional denial with no flags
/// would deny nothing while reading as a denial, and an unconditional `clone`
/// would claim the launcher refuses every `fork(2)` while the compiled program
/// refuses only the namespace-carrying use. Neither is admissible: the artefact
/// has to be exactly as wide as the BPF it commits.
fn validate_namespace_filter(
    seccomp: &LinuxSeccompPlanV1,
) -> Result<(), LinuxProductionCommandPlanError> {
    let filter = seccomp.namespace_filter();
    if filter.denied_syscalls.is_empty()
        || filter.denied_syscalls.len() > MAX_LINUX_SECCOMP_DENIED_SYSCALLS
    {
        return Err(invalid(
            "the committed namespace filter denies no syscall or exceeds its hard bound",
        ));
    }
    let mut previous: Option<&str> = None;
    for denied in &filter.denied_syscalls {
        validate_identifier(&denied.name, "namespace denied syscall")?;
        if denied.number < 0 {
            return Err(invalid(
                "a committed namespace denial carries no syscall number",
            ));
        }
        if previous.is_some_and(|earlier| earlier >= denied.name.as_str()) {
            return Err(invalid(
                "committed namespace denials must be unique and bytewise sorted by name",
            ));
        }
        previous = Some(denied.name.as_str());
        match &denied.condition {
            LinuxSeccompDenialConditionV1::Always => {}
            LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { argument, flags } => {
                // `seccomp_data` carries six argument registers.
                if *argument > 5 {
                    return Err(invalid(
                        "a committed namespace denial names an argument index the kernel does not carry",
                    ));
                }
                if flags.is_empty() {
                    return Err(invalid(
                        "a conditional namespace denial lists no flag, so it would deny nothing while reading as a denial",
                    ));
                }
                let mut seen = 0u64;
                for flag in flags {
                    validate_identifier(&flag.name, "namespace denial flag")?;
                    if flag.bit == 0 || flag.bit.count_ones() != 1 {
                        return Err(invalid(
                            "a namespace denial flag is not a single set bit, so the rule it compiles to is not the rule it names",
                        ));
                    }
                    if seen & flag.bit != 0 {
                        return Err(invalid("a namespace denial lists the same flag bit twice"));
                    }
                    seen |= flag.bit;
                }
            }
        }
    }
    validate_required_namespace_set(seccomp.audit_architecture(), &filter.denied_syscalls)
        .map_err(invalid)?;
    if filter.instruction_count == 0 {
        return Err(invalid(
            "the committed namespace filter assembled to no instruction",
        ));
    }
    validate_nonzero_digest(&filter.program_sha256, "namespace assembled program")?;
    if filter.filter_sha256 != filter.canonical_digest(seccomp.audit_architecture()) {
        return Err(invalid(
            "the committed namespace filter digest is not the digest of the filter it accompanies",
        ));
    }
    Ok(())
}

fn validate_release_and_evidence(
    release: &LinuxProductionReleaseExpectationV1,
    evidence: &LinuxExpectedTerminalEvidenceV1,
    retained: &LinuxRetainedCapabilitySetV1,
    objects: &BTreeMap<&str, &LinuxRetainedObjectIdentityV1>,
) -> Result<(), LinuxProductionCommandPlanError> {
    if release.schema != LINUX_PRODUCTION_HELD_RELEASE_SCHEMA {
        return Err(invalid(
            "release expectation is not the distinct production held-release schema",
        ));
    }
    validate_nonzero_digest(
        &release.authenticated_platform_service_digest,
        "authenticated platform service",
    )?;
    let journal_root = object(
        objects,
        &retained.service_owned_journal_index_root_object_id,
        "service-owned singleton journal/index root",
    )?;
    let delegation = object(
        objects,
        &retained.cgroup.delegation_root_object_id,
        "authenticated cgroup delegation",
    )?;
    let service_parent = object(
        objects,
        &retained.cgroup.service_parent_object_id,
        "authenticated service cgroup parent",
    )?;
    let service_state = object(
        objects,
        &retained.private_state_root_object_id,
        "authenticated service-state root",
    )?;
    // The service owns its objects, not the delegator's parent directory.
    if !journal_root.is_directory()
        || delegation.kind != LinuxRetainedObjectKindV1::CgroupDirectory
        || service_parent.kind != LinuxRetainedObjectKindV1::CgroupDirectory
        || journal_root.owner_uid != service_state.owner_uid
        || journal_root.owner_uid != delegation.owner_uid
        || journal_root.owner_uid == service_parent.owner_uid
        || service_parent.mode & 0o022 != 0
    {
        return Err(invalid(
            "release replay exclusion lacks a one-owner service, journal, and delegation, or its cgroup parent is not the delegator's",
        ));
    }
    if evidence.runtime_schema != LINUX_COMMAND_RUNTIME_EVIDENCE_SCHEMA
        || evidence.cleanup_schema != LINUX_COMMAND_CLEANUP_EVIDENCE_SCHEMA
        || evidence.runtime_requirements != REQUIRED_RUNTIME_EVIDENCE
        || evidence.cleanup_requirements_in_order != REQUIRED_CLEANUP
    {
        return Err(invalid(
            "terminal evidence omits, reorders, or substitutes a mandatory runtime/cleanup proof",
        ));
    }
    Ok(())
}

fn require_purpose_count(
    counts: &BTreeMap<LinuxMountPurposeV1, usize>,
    purpose: LinuxMountPurposeV1,
    expected: usize,
) -> Result<(), LinuxProductionCommandPlanError> {
    if counts.get(&purpose).copied().unwrap_or_default() == expected {
        Ok(())
    } else {
        Err(invalid(format!(
            "mount purpose {purpose:?} count differs from {expected}"
        )))
    }
}

fn unique_mount(
    mounts: &LinuxMountPlanV1,
    purpose: LinuxMountPurposeV1,
) -> Result<&LinuxRetainedMountV1, LinuxProductionCommandPlanError> {
    let mut matching = mounts
        .read_only
        .iter()
        .chain(&mounts.read_write)
        .filter(|mount| mount.purpose == purpose);
    let result = matching
        .next()
        .ok_or_else(|| invalid(format!("required mount purpose {purpose:?} is absent")))?;
    if matching.next().is_some() {
        return Err(invalid(format!("mount purpose {purpose:?} is not unique")));
    }
    Ok(result)
}

fn object<'a>(
    objects: &BTreeMap<&'a str, &'a LinuxRetainedObjectIdentityV1>,
    object_id: &str,
    field: &str,
) -> Result<&'a LinuxRetainedObjectIdentityV1, LinuxProductionCommandPlanError> {
    objects.get(object_id).copied().ok_or_else(|| {
        invalid(format!(
            "{field} references unknown retained object {object_id}"
        ))
    })
}

fn validate_identifier(value: &str, field: &str) -> Result<(), LinuxProductionCommandPlanError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(invalid(format!(
            "{field} must be a bounded portable identifier"
        )))
    } else {
        Ok(())
    }
}

fn validate_absolute_path(value: &str, field: &str) -> Result<(), LinuxProductionCommandPlanError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.as_bytes().contains(&0)
        || !value.starts_with('/')
        || (value.len() > 1 && value.ends_with('/'))
        || value
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        Err(invalid(format!(
            "{field} must be bounded normalized absolute UTF-8"
        )))
    } else {
        Ok(())
    }
}

fn contains_git_component(value: &str) -> bool {
    value.split('/').any(|component| component == ".git")
}

fn validate_nonzero_digest(
    digest: &Digest,
    field: &str,
) -> Result<(), LinuxProductionCommandPlanError> {
    if digest.as_str().bytes().all(|byte| byte == b'0') {
        Err(invalid(format!("{field} digest must not be all zero")))
    } else {
        Ok(())
    }
}

// Bind measured architecture, domain identity, and committed kernel
// artifacts rather than accepting self-consistent supplied values.

// ---------------------------------------------------------------------------
// Machine architecture
// ---------------------------------------------------------------------------

/// `e_ident` magic that begins every ELF file.
const ELF_IDENTIFICATION_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// `EI_CLASS` value for a 64-bit ELF object.
const ELF_CLASS_64: u8 = 2;
/// `EI_DATA` value for a two's-complement little-endian ELF object.
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
/// `e_machine` for x86-64.
const ELF_MACHINE_X86_64: u16 = 0x003e;
/// `e_machine` for 64-bit ARM.
const ELF_MACHINE_AARCH64: u16 = 0x00b7;
/// `uname(2)` `machine` for x86-64 Linux.
const UNAME_MACHINE_X86_64: &str = "x86_64";
/// `uname(2)` `machine` for 64-bit ARM Linux.
const UNAME_MACHINE_AARCH64: &str = "aarch64";

/// Bytes of ELF header a measurement must supply.
///
/// `e_ident` is 16 bytes, `e_type` occupies 16..18 and `e_machine` 18..20, so
/// twenty bytes is exactly enough and no more. A caller must not read the whole
/// image to answer this question.
pub(crate) const LINUX_ELF_HEADER_PREFIX_BYTES: usize = 20;

/// Longest `uname(2)` machine string this plan will consider.
const MAX_KERNEL_MACHINE_BYTES: usize = 64;

/// Machine architecture derived from the plan's ELF formats and seccomp audit
/// architecture. Validation requires all fields to agree; no duplicate architecture
/// assertion is stored.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxMachineArchitectureV1 {
    X86_64,
    Aarch64,
}

impl LinuxMachineArchitectureV1 {
    /// Maps an ELF `e_machine` to an architecture, or refuses.
    ///
    /// There is deliberately no fallback arm: an unrecognized machine is a
    /// host this schema cannot describe, and saying so is the correct answer.
    const fn from_elf_machine(machine: u16) -> Option<Self> {
        match machine {
            ELF_MACHINE_X86_64 => Some(Self::X86_64),
            ELF_MACHINE_AARCH64 => Some(Self::Aarch64),
            _ => None,
        }
    }

    /// Maps a `uname(2)` machine string to an architecture, or refuses.
    fn from_kernel_machine(machine: &str) -> Option<Self> {
        match machine {
            UNAME_MACHINE_X86_64 => Some(Self::X86_64),
            UNAME_MACHINE_AARCH64 => Some(Self::Aarch64),
            _ => None,
        }
    }

    pub(crate) const fn elf_image_format(self) -> LinuxElfImageFormatV1 {
        match self {
            Self::X86_64 => LinuxElfImageFormatV1::Elf64X86_64,
            Self::Aarch64 => LinuxElfImageFormatV1::Elf64Aarch64,
        }
    }

    pub(crate) const fn audit_architecture(self) -> LinuxAuditArchitectureV1 {
        match self {
            Self::X86_64 => LinuxAuditArchitectureV1::X86_64,
            Self::Aarch64 => LinuxAuditArchitectureV1::Aarch64,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => UNAME_MACHINE_X86_64,
            Self::Aarch64 => UNAME_MACHINE_AARCH64,
        }
    }
}

impl LinuxElfImageFormatV1 {
    pub(crate) const fn architecture(self) -> LinuxMachineArchitectureV1 {
        match self {
            Self::Elf64X86_64 => LinuxMachineArchitectureV1::X86_64,
            Self::Elf64Aarch64 => LinuxMachineArchitectureV1::Aarch64,
        }
    }
}

impl LinuxAuditArchitectureV1 {
    pub(crate) const fn architecture(self) -> LinuxMachineArchitectureV1 {
        match self {
            Self::X86_64 => LinuxMachineArchitectureV1::X86_64,
            Self::Aarch64 => LinuxMachineArchitectureV1::Aarch64,
        }
    }
}

/// The measured architecture of the host a plan is about to be used on.
///
/// It is constructed from two independent reads that must agree:
///
/// - the ELF header of the **running service image**, which says what the
///   process executing this code actually is, and
/// - the kernel's own `uname(2)` `machine`, which says what the kernel thinks
///   it is running on.
///
/// Neither alone is sufficient and neither is a compile-time constant.
/// `std::env::consts::ARCH` was deliberately not used: it is baked at build
/// time, so it would report the architecture the binary was *compiled* for even
/// when the binary is running somewhere else, which is exactly the assumption
/// this type exists to remove.
///
/// The constructor is pure, so the refusals below are provable on any host,
/// including the ones this project cannot run Linux evidence on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxHostMachineArchitectureFactV1 {
    architecture: LinuxMachineArchitectureV1,
    image_elf_machine: u16,
    image_elf_class: u8,
    image_elf_data: u8,
    kernel_machine: String,
}

impl LinuxHostMachineArchitectureFactV1 {
    /// Derives the host architecture from two live measurements.
    pub(crate) fn from_measurements(
        image_elf_header_prefix: &[u8],
        kernel_machine: &str,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let header = image_elf_header_prefix
            .get(..LINUX_ELF_HEADER_PREFIX_BYTES)
            .ok_or_else(|| {
                invalid(format!(
                    "architecture measurement needs {LINUX_ELF_HEADER_PREFIX_BYTES} ELF header bytes"
                ))
            })?;
        if header[..ELF_IDENTIFICATION_MAGIC.len()] != ELF_IDENTIFICATION_MAGIC {
            return Err(invalid(
                "the measured service image does not begin with the ELF identification magic",
            ));
        }
        let image_elf_class = header[4];
        let image_elf_data = header[5];
        if image_elf_class != ELF_CLASS_64 || image_elf_data != ELF_DATA_LITTLE_ENDIAN {
            return Err(invalid(
                "the measured service image is not a 64-bit little-endian ELF object",
            ));
        }
        let image_elf_machine = u16::from_le_bytes([header[18], header[19]]);
        let from_image =
            LinuxMachineArchitectureV1::from_elf_machine(image_elf_machine).ok_or_else(|| {
                invalid(format!(
                    "the running image's ELF e_machine 0x{image_elf_machine:04x} is not an architecture this plan schema can describe"
                ))
            })?;
        if kernel_machine.is_empty()
            || kernel_machine.len() > MAX_KERNEL_MACHINE_BYTES
            || !kernel_machine
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(invalid(
                "the kernel machine name is empty or outside its text bound",
            ));
        }
        let from_kernel =
            LinuxMachineArchitectureV1::from_kernel_machine(kernel_machine).ok_or_else(|| {
                invalid(format!(
                    "the kernel machine name `{kernel_machine}` is not an architecture this plan schema can describe"
                ))
            })?;
        if from_image != from_kernel {
            return Err(invalid(format!(
                "the running image is {} but the kernel reports {}",
                from_image.as_str(),
                from_kernel.as_str()
            )));
        }
        Ok(Self {
            architecture: from_image,
            image_elf_machine,
            image_elf_class,
            image_elf_data,
            kernel_machine: kernel_machine.to_owned(),
        })
    }

    pub(crate) const fn architecture(&self) -> LinuxMachineArchitectureV1 {
        self.architecture
    }

    pub(crate) const fn image_elf_machine(&self) -> u16 {
        self.image_elf_machine
    }

    pub(crate) fn kernel_machine(&self) -> &str {
        &self.kernel_machine
    }
}

/// Requires every architecture-bearing plan field to denote one architecture,
/// and reports it.
fn validate_architecture(
    binaries: &LinuxBinaryIdentitiesV1,
    seccomp: &LinuxSeccompPlanV1,
) -> Result<LinuxMachineArchitectureV1, LinuxProductionCommandPlanError> {
    let architecture = binaries.bubblewrap_format.architecture();
    let mut observed = vec![
        (
            "Bubblewrap image",
            binaries.bubblewrap_format.architecture(),
        ),
        (
            "inner launcher image",
            binaries.inner_launcher_format.architecture(),
        ),
        (
            "target executable",
            binaries.target.image_format.architecture(),
        ),
        (
            "seccomp audit architecture",
            seccomp.audit_architecture().architecture(),
        ),
    ];
    if let LinuxTargetLinkageV1::DynamicElf {
        interpreter_format, ..
    } = &binaries.target.linkage
    {
        observed.push(("ELF interpreter", interpreter_format.architecture()));
    }
    for (field, candidate) in observed {
        if candidate != architecture {
            return Err(invalid(format!(
                "{field} is {} while the plan's Bubblewrap image is {}",
                candidate.as_str(),
                architecture.as_str()
            )));
        }
    }
    Ok(architecture)
}

// ---------------------------------------------------------------------------
// The two mandatory kernel controls, and the artefacts schema version 4
// requires a plan to commit for them
// ---------------------------------------------------------------------------

/// Domain separator for a committed Landlock ruleset's canonical digest.
pub(crate) const LINUX_LANDLOCK_RULESET_DOMAIN: &[u8] = b"grok-build/linux-landlock-ruleset/v1\0";

/// Domain separator for a committed seccomp filter's canonical digest.
pub(crate) const LINUX_SECCOMP_FILTER_DOMAIN: &[u8] = b"grok-build/linux-seccomp-filter/v1\0";

/// Domain separator for the namespace filter's canonical digest.
///
/// Separate from [`LINUX_SECCOMP_FILTER_DOMAIN`] so a network filter's digest
/// can never be replayed as a namespace filter's, and the reverse.
pub(crate) const LINUX_SECCOMP_NAMESPACE_FILTER_DOMAIN: &[u8] =
    b"grok-build/linux-seccomp-namespace-filter/v1\0";

/// Largest number of scopes one committed ruleset may grant beneath.
///
/// A bound exists because the ruleset travels in a plan, in a persisted
/// bootstrap-evidence artifact, and in one argument vector to the bootstrap
/// probe process; an unbounded list would make all three unbounded.
pub(crate) const MAX_LINUX_LANDLOCK_SCOPES: usize = 32;

/// Largest number of syscalls one committed filter may deny, for the same
/// reason.
pub(crate) const MAX_LINUX_SECCOMP_DENIED_SYSCALLS: usize = 64;

/// The complete Landlock ABI-1 filesystem access set, as the kernel's uapi
/// defines it.
///
/// It is written here as a number because this module compiles on hosts with no
/// Landlock crate in front of them, and it is not left to trust:
/// `the_compiled_landlock_access_sets_are_the_crate_s_own` asserts on Linux
/// that both constants equal what `landlock` answers for `ABI::V1`.
pub(crate) const LINUX_LANDLOCK_ABI_1_HANDLED_ACCESS_BITS: u64 = 0x1fff;

/// The Landlock ABI-1 read subset: execute, read a file, and list a directory.
pub(crate) const LINUX_LANDLOCK_ABI_1_READ_ACCESS_BITS: u64 = 0xd;

/// One `path_beneath` rule of a committed Landlock ruleset.
///
/// `device_id` and `inode` are the kernel's answer for the object the rule was
/// added over, read through the descriptor the ruleset was built from. They are
/// what makes this a measurement rather than a path the plan chose: the
/// bootstrap probe reports the identity of every scope it actually opened, and
/// the controller refuses the probe unless each one equals the value here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxLandlockScopeV1 {
    pub(crate) object_id: String,
    pub(crate) resolved_path: String,
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
    /// The exact `AccessFs` bit set granted beneath this scope.
    pub(crate) access_bits: u64,
}

/// The object a committed ruleset states it does **not** grant.
///
/// A ruleset that grants something proves nothing on its own: a kernel that
/// ignored the whole ruleset would also let the granted scope be read. The
/// witness is the other half, and it is carried by the plan rather than chosen
/// by the prober so that the denial the bootstrap observes is the denial the
/// plan asked for.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxLandlockDenialWitnessV1 {
    pub(crate) resolved_path: String,
    pub(crate) device_id: u64,
    pub(crate) inode: u64,
}

/// The exact Landlock ruleset a plan commits.
///
/// Schema version 3 could not carry this, and said so: it had no ruleset to
/// digest, so every digest-shaped field it had removed was necessarily
/// invented. Version 4 carries it because there is now a mint that *creates*
/// the ruleset — `landlock_create_ruleset` for the handled set, one
/// `path_beneath` per scope over a real descriptor — and digests the
/// specification the kernel accepted. Nothing here is a value this module
/// chose: `handled_access_bits` is the access set the kernel admitted at
/// `created_at_kernel_abi`, and every scope identity is a `statx` answer.
///
/// The digest is not the point on its own; the binding is.
/// `validate_service_bootstrap_evidence` requires the bootstrap's Landlock
/// probe result to be the one a probe **that installed this ruleset** produces,
/// so a plan cannot commit a ruleset whose enforcement was never observed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxLandlockRulesetV1 {
    pub(crate) created_at_kernel_abi: u32,
    pub(crate) handled_access_bits: u64,
    pub(crate) scopes: Vec<LinuxLandlockScopeV1>,
    pub(crate) denial_witness: LinuxLandlockDenialWitnessV1,
    pub(crate) ruleset_sha256: Digest,
}

impl LinuxLandlockRulesetV1 {
    /// The canonical digest of everything above `ruleset_sha256`.
    ///
    /// Length-prefixed and domain-separated so that no two different rulesets
    /// share a preimage, and so that the bootstrap probe's result commitment
    /// can be recomputed from the plan alone.
    pub(crate) fn canonical_digest(&self) -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(LINUX_LANDLOCK_RULESET_DOMAIN);
        preimage.extend_from_slice(&u64::from(self.created_at_kernel_abi).to_be_bytes());
        preimage.extend_from_slice(&self.handled_access_bits.to_be_bytes());
        preimage.extend_from_slice(&(self.scopes.len() as u64).to_be_bytes());
        for scope in &self.scopes {
            push_length_prefixed(&mut preimage, scope.object_id.as_bytes());
            push_length_prefixed(&mut preimage, scope.resolved_path.as_bytes());
            preimage.extend_from_slice(&scope.device_id.to_be_bytes());
            preimage.extend_from_slice(&scope.inode.to_be_bytes());
            preimage.extend_from_slice(&scope.access_bits.to_be_bytes());
        }
        push_length_prefixed(&mut preimage, self.denial_witness.resolved_path.as_bytes());
        preimage.extend_from_slice(&self.denial_witness.device_id.to_be_bytes());
        preimage.extend_from_slice(&self.denial_witness.inode.to_be_bytes());
        Digest::sha256(&preimage)
    }
}

/// One syscall a committed seccomp filter denies, and the number it denies it
/// by on the plan's own audit architecture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSeccompDeniedSyscallV1 {
    pub(crate) name: String,
    pub(crate) number: i64,
}

/// The exact seccomp filter a plan commits.
///
/// Unlike a Landlock ruleset, a filter genuinely has bytes: `program_sha256` is
/// the digest of the assembled BPF instructions, taken from the program the
/// mint really compiled. `instruction_count` is that program's length. Both are
/// measurements of an artefact that exists, which is what version 3 said it did
/// not have.
///
/// The unmatched action is `Allow` and the matched action is the plan's
/// `default_action`, which `validate_mandatory_kernel_controls` has required to
/// be `KillProcess` since version 2 and still requires unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSeccompFilterV1 {
    pub(crate) denied_syscalls: Vec<LinuxSeccompDeniedSyscallV1>,
    pub(crate) instruction_count: u64,
    pub(crate) program_sha256: Digest,
    pub(crate) filter_sha256: Digest,
}

impl LinuxSeccompFilterV1 {
    /// The canonical digest of everything above `filter_sha256`, joined to the
    /// architecture and actions the enclosing plan commits.
    pub(crate) fn canonical_digest(
        &self,
        audit_architecture: LinuxAuditArchitectureV1,
        default_action: LinuxSeccompDefaultActionV1,
    ) -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(LINUX_SECCOMP_FILTER_DOMAIN);
        push_length_prefixed(
            &mut preimage,
            audit_architecture_tag(audit_architecture).as_bytes(),
        );
        push_length_prefixed(
            &mut preimage,
            seccomp_default_action_tag(default_action).as_bytes(),
        );
        preimage.extend_from_slice(&(self.denied_syscalls.len() as u64).to_be_bytes());
        for denied in &self.denied_syscalls {
            push_length_prefixed(&mut preimage, denied.name.as_bytes());
            preimage.extend_from_slice(&denied.number.to_be_bytes());
        }
        preimage.extend_from_slice(&self.instruction_count.to_be_bytes());
        push_length_prefixed(&mut preimage, self.program_sha256.as_str().as_bytes());
        Digest::sha256(&preimage)
    }
}

/// What a namespace denial answers.
///
/// One variant, and it is not `KillProcess`. `ENOSYS` is load-bearing: glibc
/// since 2.34 issues `clone3` from `pthread_create` and falls back to legacy
/// `clone` on `ENOSYS` alone, so any other answer breaks ordinary threading. It also names
/// which layer refused, because a container's own profile answers `EPERM` for
/// these syscalls and a claim resting on that would be resting on borrowed
/// protection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxSeccompNamespaceActionV1 {
    ErrnoNotImplemented,
}

/// One named bit of a syscall argument.
///
/// The name travels with the bit so the artefact says *which* namespace a
/// denial refuses rather than carrying an opaque mask.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSeccompArgumentFlagV1 {
    pub(crate) name: String,
    pub(crate) bit: u64,
}

/// When a denial applies.
///
/// The distinction is the whole reason this type exists. `fork(2)` is
/// `clone(2)`, so a plan that recorded `clone` as unconditionally denied would
/// claim the launcher refuses all process creation while the compiled program
/// refuses only the namespace-carrying use. Recording the condition keeps the
/// artefact exactly as wide as the BPF it commits, and lets the launcher
/// rebuild that BPF instruction for instruction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxSeccompDenialConditionV1 {
    /// Every invocation, whatever its arguments.
    Always,
    /// Only when the named argument carries at least one listed bit.
    ///
    /// Each flag becomes its own rule. `seccompiler` ANDs the conditions inside
    /// one rule and ORs the rules for one syscall, so a rule per bit matches
    /// when *any* is set; a single mask over their union would instead demand
    /// all of them at once and pass a plain `clone(CLONE_NEWUSER)` through.
    AnyArgumentFlagSet {
        argument: u8,
        flags: Vec<LinuxSeccompArgumentFlagV1>,
    },
}

/// One syscall the namespace filter refuses, and the condition it refuses on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSeccompNamespaceDenialV1 {
    pub(crate) name: String,
    pub(crate) number: i64,
    pub(crate) condition: LinuxSeccompDenialConditionV1,
}

/// The second committed filter: every route to a new namespace.
///
/// A separate filter beside [`LinuxSeccompFilterV1`] rather than more rules
/// inside it, because a `seccompiler` filter carries exactly one matched action
/// and these two need different ones. Keeping them apart also leaves the
/// network filter's committed bytes, digest and instruction count untouched, so
/// every measurement resting on them stays valid.
///
/// The kernel evaluates every installed filter and keeps the highest-precedence
/// action, so stacking cannot weaken the network layer — measured, not assumed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxSeccompNamespaceFilterV1 {
    pub(crate) action: LinuxSeccompNamespaceActionV1,
    pub(crate) denied_syscalls: Vec<LinuxSeccompNamespaceDenialV1>,
    pub(crate) instruction_count: u64,
    pub(crate) program_sha256: Digest,
    pub(crate) filter_sha256: Digest,
}

impl LinuxSeccompNamespaceFilterV1 {
    /// The canonical digest of everything above `filter_sha256`.
    ///
    /// `linux_held_launcher`'s `ReleaseSeccompNamespaceFilter` reproduces this
    /// preimage field for field on the other side of the protocol boundary. Any
    /// change here is a change there.
    pub(crate) fn canonical_digest(&self, audit_architecture: LinuxAuditArchitectureV1) -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(LINUX_SECCOMP_NAMESPACE_FILTER_DOMAIN);
        push_length_prefixed(
            &mut preimage,
            audit_architecture_tag(audit_architecture).as_bytes(),
        );
        push_length_prefixed(
            &mut preimage,
            seccomp_namespace_action_tag(self.action).as_bytes(),
        );
        preimage.extend_from_slice(&(self.denied_syscalls.len() as u64).to_be_bytes());
        for denied in &self.denied_syscalls {
            push_length_prefixed(&mut preimage, denied.name.as_bytes());
            preimage.extend_from_slice(&denied.number.to_be_bytes());
            match &denied.condition {
                LinuxSeccompDenialConditionV1::Always => {
                    push_length_prefixed(&mut preimage, b"always");
                    preimage.extend_from_slice(&0u64.to_be_bytes());
                }
                LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { argument, flags } => {
                    push_length_prefixed(&mut preimage, b"any-argument-flag-set");
                    preimage.extend_from_slice(&u64::from(*argument).to_be_bytes());
                    preimage.extend_from_slice(&(flags.len() as u64).to_be_bytes());
                    for flag in flags {
                        push_length_prefixed(&mut preimage, flag.name.as_bytes());
                        preimage.extend_from_slice(&flag.bit.to_be_bytes());
                    }
                }
            }
        }
        preimage.extend_from_slice(&self.instruction_count.to_be_bytes());
        push_length_prefixed(&mut preimage, self.program_sha256.as_str().as_bytes());
        Digest::sha256(&preimage)
    }
}

/// The wire tag of a namespace action, shared with the launcher's preimage.
pub(crate) const fn seccomp_namespace_action_tag(
    action: LinuxSeccompNamespaceActionV1,
) -> &'static str {
    match action {
        LinuxSeccompNamespaceActionV1::ErrnoNotImplemented => "errno-not-implemented",
    }
}

/// The stable canonical tag of one audit architecture.
///
/// It is deliberately not the serde name: a preimage tag that tracked a serde
/// rename would silently change every committed digest.
pub(crate) const fn audit_architecture_tag(value: LinuxAuditArchitectureV1) -> &'static str {
    match value {
        LinuxAuditArchitectureV1::X86_64 => "audit-arch-x86-64",
        LinuxAuditArchitectureV1::Aarch64 => "audit-arch-aarch64",
    }
}

/// The stable canonical tag of one matched-syscall action, for the same reason.
const fn seccomp_default_action_tag(value: LinuxSeccompDefaultActionV1) -> &'static str {
    match value {
        LinuxSeccompDefaultActionV1::KillProcess => "kill-process",
    }
}

/// Appends one length-prefixed field to a canonical preimage.
fn push_length_prefixed(preimage: &mut Vec<u8>, field: &[u8]) {
    preimage.extend_from_slice(&(field.len() as u64).to_be_bytes());
    preimage.extend_from_slice(field);
}

/// The plan's committed Landlock ruleset, production mint, and live probe.
///
/// Unsupported kernels refuse during minting or observed-ABI validation. The plan
/// cannot select an unimplemented control or supply placeholder digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxLandlockPlanV1 {
    InstalledRulesetProvenByLiveBootstrapProbe {
        enforcement: LinuxMandatoryEnforcementV1,
        minimum_kernel_abi: u32,
        maximum_modeled_kernel_abi: u32,
        ruleset: LinuxLandlockRulesetV1,
    },
}

impl LinuxLandlockPlanV1 {
    pub(crate) fn enforcement(&self) -> LinuxMandatoryEnforcementV1 {
        match self {
            Self::InstalledRulesetProvenByLiveBootstrapProbe { enforcement, .. } => *enforcement,
        }
    }

    pub(crate) fn minimum_kernel_abi(&self) -> u32 {
        match self {
            Self::InstalledRulesetProvenByLiveBootstrapProbe {
                minimum_kernel_abi, ..
            } => *minimum_kernel_abi,
        }
    }

    pub(crate) fn maximum_modeled_kernel_abi(&self) -> u32 {
        match self {
            Self::InstalledRulesetProvenByLiveBootstrapProbe {
                maximum_modeled_kernel_abi,
                ..
            } => *maximum_modeled_kernel_abi,
        }
    }

    pub(crate) fn ruleset(&self) -> &LinuxLandlockRulesetV1 {
        match self {
            Self::InstalledRulesetProvenByLiveBootstrapProbe { ruleset, .. } => ruleset,
        }
    }
}

/// What a plan says about seccomp, for the same reason and with the same shape
/// as [`LinuxLandlockPlanV1`].
///
/// Version 2 carried a `filter_digest`, an implementation-contract digest, and
/// a forbidden-syscall probe digest with no filter to digest. Version 3 removed
/// them. Version 4 carries a filter because one is compiled: `program_sha256`
/// is the digest of the assembled BPF instructions, and the audit architecture
/// is still *not* a constant — `validate_architecture` requires it to agree with
/// every other architecture-bearing field of the plan, all of which are derived
/// from live measurements, and now also with the architecture the filter's own
/// syscall numbers were taken from.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxSeccompPlanV1 {
    CompiledFilterProvenByLiveBootstrapProbe {
        enforcement: LinuxMandatoryEnforcementV1,
        audit_architecture: LinuxAuditArchitectureV1,
        default_action: LinuxSeccompDefaultActionV1,
        filter: LinuxSeccompFilterV1,
        /// The second committed filter, added by schema version 5.
        ///
        /// Additive: `filter` above is byte-identical to what version 4
        /// committed, and so is its digest. The variant name still refers to
        /// that network filter being bootstrap-probe-proven. This field is
        /// committed and validator-pinned; it is not a bootstrap-probe arm.
        namespace_filter: LinuxSeccompNamespaceFilterV1,
    },
}

impl LinuxSeccompPlanV1 {
    pub(crate) fn enforcement(&self) -> LinuxMandatoryEnforcementV1 {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe { enforcement, .. } => *enforcement,
        }
    }

    pub(crate) fn audit_architecture(&self) -> LinuxAuditArchitectureV1 {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe {
                audit_architecture, ..
            } => *audit_architecture,
        }
    }

    pub(crate) fn default_action(&self) -> LinuxSeccompDefaultActionV1 {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe { default_action, .. } => {
                *default_action
            }
        }
    }

    pub(crate) fn filter(&self) -> &LinuxSeccompFilterV1 {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe { filter, .. } => filter,
        }
    }

    pub(crate) fn namespace_filter(&self) -> &LinuxSeccompNamespaceFilterV1 {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe {
                namespace_filter, ..
            } => namespace_filter,
        }
    }

    /// Moves a test plan to another audit architecture, **and re-digests the
    /// filter for it**.
    ///
    /// A seccomp filter is architecture-specific, so version 4's filter digest
    /// covers the audit architecture: changing one without the other is exactly
    /// the mismatch `validate_mandatory_control_artefacts` refuses, and this
    /// helper exists to move a plan *consistently* so that the architecture
    /// tests keep varying architecture rather than accidentally varying a
    /// digest.
    #[cfg(test)]
    pub(crate) fn set_test_audit_architecture(&mut self, architecture: LinuxAuditArchitectureV1) {
        match self {
            Self::CompiledFilterProvenByLiveBootstrapProbe {
                audit_architecture,
                default_action,
                filter,
                namespace_filter,
                ..
            } => {
                *audit_architecture = architecture;
                filter.filter_sha256 = filter.canonical_digest(architecture, *default_action);
                // Both syscall filters must use the target architecture's exact syscall
                // numbers.
                namespace_filter.denied_syscalls = committed_namespace_denials(architecture);
                namespace_filter.filter_sha256 = namespace_filter.canonical_digest(architecture);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The cgroup leaf the plan does not name
// ---------------------------------------------------------------------------

/// How a command-domain leaf comes into existence.
///
/// The single variant is the design, restated in the schema so that a plan
/// carries the reason it names no leaf rather than leaving it to a comment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinuxCommandDomainLeafCreationV1 {
    UnpredictableNonceCreatedNoReplaceInsideTheDelegationLock,
}

/// One cgroup control file every prepared leaf must expose.
///
/// The variants share a prefix because the kernel's own file names do; naming
/// them `Procs`/`Events`/`Kill` would lose the correspondence this type exists
/// to keep exact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "each variant is named for the exact kernel control file it denotes"
)]
pub(crate) enum LinuxCommandDomainControlFileV1 {
    CgroupProcs,
    CgroupEvents,
    CgroupKill,
}

impl LinuxCommandDomainControlFileV1 {
    /// The three control files, in the order a plan must list them.
    pub(crate) const REQUIRED: [Self; 3] =
        [Self::CgroupProcs, Self::CgroupEvents, Self::CgroupKill];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::CgroupProcs => "cgroup.procs",
            Self::CgroupEvents => "cgroup.events",
            Self::CgroupKill => "cgroup.kill",
        }
    }
}

/// Describes a cgroup leaf without choosing its name in advance.
///
/// Preparation draws a 256-bit nonce only after locking the delegation,
/// rejecting replay and verifying the delegation is empty. This prevents name
/// prediction and reuse across attempts. The plan binds the naming rules and
/// required control files; the live leaf is bound after preparation through
/// [`ValidatedLinuxProductionCommandPlanV1::bind_prepared_command_domain_leaf`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxCommandDomainLeafPlanV1 {
    NotNamedByThePlanBoundAfterPreparationFromALiveRead {
        name_prefix: String,
        nonce_hexadecimal_characters: u32,
        creation: LinuxCommandDomainLeafCreationV1,
        required_control_files: Vec<LinuxCommandDomainControlFileV1>,
    },
}

impl LinuxCommandDomainLeafPlanV1 {
    /// The only admissible value, quoting the containment module's own
    /// constants so the two cannot drift.
    pub(crate) fn contract() -> Self {
        Self::NotNamedByThePlanBoundAfterPreparationFromALiveRead {
            name_prefix: DOMAIN_NAME_PREFIX.to_owned(),
            nonce_hexadecimal_characters: u32::try_from(DOMAIN_NONCE_HEX_CHARS)
                .unwrap_or(u32::MAX),
            creation:
                LinuxCommandDomainLeafCreationV1::UnpredictableNonceCreatedNoReplaceInsideTheDelegationLock,
            required_control_files: LinuxCommandDomainControlFileV1::REQUIRED.to_vec(),
        }
    }

    fn validate(&self) -> Result<(), LinuxProductionCommandPlanError> {
        let Self::NotNamedByThePlanBoundAfterPreparationFromALiveRead {
            name_prefix,
            nonce_hexadecimal_characters,
            creation,
            required_control_files,
        } = self;
        if name_prefix != DOMAIN_NAME_PREFIX
            || usize::try_from(*nonce_hexadecimal_characters).unwrap_or(usize::MAX)
                != DOMAIN_NONCE_HEX_CHARS
        {
            return Err(invalid(
                "the plan's leaf-name grammar differs from the one prepare_domain mints",
            ));
        }
        if *creation
            != LinuxCommandDomainLeafCreationV1::UnpredictableNonceCreatedNoReplaceInsideTheDelegationLock
        {
            return Err(invalid("unsupported command-domain leaf creation rule"));
        }
        if required_control_files.as_slice() != LinuxCommandDomainControlFileV1::REQUIRED {
            return Err(invalid(
                "a prepared command-domain leaf must expose exactly cgroup.procs, cgroup.events and cgroup.kill",
            ));
        }
        Ok(())
    }

    /// Reports whether a runtime leaf name is one this plan admits.
    ///
    /// It calls the containment module's grammar rather than re-deriving it
    /// from the fields above, because a second copy of the grammar is exactly
    /// the substitution that would let the plan admit a name `prepare_domain`
    /// could never mint.
    fn admits_name(&self, leaf_name: &str) -> bool {
        self.validate().is_ok() && crate::linux_containment::is_domain_leaf_name(leaf_name)
    }
}

/// One live read of a prepared leaf's control file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxObservedCommandDomainControlFileV1 {
    pub(crate) file: LinuxCommandDomainControlFileV1,
    pub(crate) identity: LinuxRetainedObjectIdentityV1,
}

/// A live read of an actually prepared command-domain leaf.
///
/// Only the cgroup backend mints one, and only by opening the leaf and each of
/// its control files through the retained delegation descriptor. It is not
/// constructible from plan data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxPreparedCommandDomainLeafObservationV1 {
    pub(crate) leaf_name: String,
    pub(crate) leaf: LinuxRetainedObjectIdentityV1,
    pub(crate) control_files: Vec<LinuxObservedCommandDomainControlFileV1>,
}

/// The leaf a plan was bound to, after the leaf existed.
///
/// Every value here came from a live read of the prepared leaf and was then
/// required to agree with the durable journal record and with the plan's own
/// delegation identity. There is no constructor that takes a caller's numbers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxBoundCommandDomainLeafV1 {
    plan_digest: Digest,
    leaf_name: String,
    leaf: LinuxRetainedObjectIdentityV1,
    control_files: Vec<LinuxObservedCommandDomainControlFileV1>,
}

impl LinuxBoundCommandDomainLeafV1 {
    pub(crate) fn plan_digest(&self) -> &Digest {
        &self.plan_digest
    }

    pub(crate) fn leaf_name(&self) -> &str {
        &self.leaf_name
    }

    pub(crate) fn leaf_identity(&self) -> CgroupObjectIdentity {
        CgroupObjectIdentity {
            device: self.leaf.device_id,
            inode: self.leaf.inode,
        }
    }

    pub(crate) fn control_files(&self) -> &[LinuxObservedCommandDomainControlFileV1] {
        &self.control_files
    }
}

impl ValidatedLinuxProductionCommandPlanV1 {
    /// The architecture this plan describes, derived from its own fields.
    pub(crate) fn machine_architecture(&self) -> LinuxMachineArchitectureV1 {
        // `validate` already required these to agree, and no constructor
        // bypasses it, so the Bubblewrap image is a sufficient witness.
        self.plan
            .components
            .binaries
            .bubblewrap_format
            .architecture()
    }

    /// Refuses a plan that describes an architecture this host is not.
    ///
    /// This is the whole point of adding the variants: a plan built for one
    /// architecture must be refused against the other, and the refusal must be
    /// driven by a measurement rather than by a build-time constant.
    pub(crate) fn require_measured_host_architecture(
        &self,
        measured: &LinuxHostMachineArchitectureFactV1,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        let planned = self.machine_architecture();
        if planned == measured.architecture() {
            Ok(())
        } else {
            Err(invalid(format!(
                "this plan describes {} but the measured host is {} (ELF e_machine 0x{:04x}, kernel machine `{}`)",
                planned.as_str(),
                measured.architecture().as_str(),
                measured.image_elf_machine(),
                measured.kernel_machine()
            )))
        }
    }

    /// Binds this plan to a leaf that now exists, from a live read of it.
    ///
    /// The plan named no leaf, so this is where a leaf identity enters. Three
    /// independent things must agree: the plan's grammar and delegation
    /// identity, the durable journal record written by `prepare_domain`, and
    /// the observation, which the cgroup backend can only produce by opening
    /// the leaf through the retained delegation descriptor.
    pub(crate) fn bind_prepared_command_domain_leaf(
        &self,
        journal_leaf_name: &str,
        journal_leaf_identity: CgroupObjectIdentity,
        observation: &LinuxPreparedCommandDomainLeafObservationV1,
    ) -> Result<LinuxBoundCommandDomainLeafV1, LinuxProductionCommandPlanError> {
        let cgroup = &self.plan.components.retained.cgroup;
        cgroup.leaf.validate()?;
        if !cgroup.leaf.admits_name(&observation.leaf_name) {
            return Err(invalid(
                "the observed leaf name is not a name prepare_domain could have minted",
            ));
        }
        if observation.leaf_name != journal_leaf_name {
            return Err(invalid(
                "the observed leaf is not the leaf this episode's durable journal record named",
            ));
        }
        observation.leaf.validate()?;
        if observation.leaf.kind != LinuxRetainedObjectKindV1::CgroupDirectory {
            return Err(invalid(
                "the observed command-domain leaf is not a cgroup directory",
            ));
        }
        if observation.leaf.device_id != journal_leaf_identity.device
            || observation.leaf.inode != journal_leaf_identity.inode
        {
            return Err(invalid(
                "the live leaf identity differs from the one the durable journal record committed",
            ));
        }
        let objects = self.retained_objects()?;
        let parent = object(
            &objects,
            &cgroup.service_parent_object_id,
            "service cgroup parent",
        )?;
        let delegation = object(
            &objects,
            &cgroup.delegation_root_object_id,
            "cgroup delegation root",
        )?;
        if observation.leaf.device_id != delegation.device_id
            || observation.leaf.mount_id != delegation.mount_id
        {
            return Err(invalid(
                "the prepared leaf is not on the plan's own delegated cgroup mount",
            ));
        }
        if observation.leaf.owner_uid != delegation.owner_uid
            || observation.leaf.owner_gid != delegation.owner_gid
        {
            return Err(invalid(
                "the prepared leaf is not owned by the delegation's owner",
            ));
        }
        if observation.leaf.mode & 0o002 != 0 {
            return Err(invalid("the prepared leaf is world-writable"));
        }
        if observation.leaf.inode == delegation.inode || observation.leaf.inode == parent.inode {
            return Err(invalid(
                "the prepared leaf resolved to the delegation or the service parent itself",
            ));
        }
        validate_prepared_leaf_control_files(observation, parent, delegation)?;
        Ok(LinuxBoundCommandDomainLeafV1 {
            plan_digest: self.plan_digest.clone(),
            leaf_name: observation.leaf_name.clone(),
            leaf: observation.leaf.clone(),
            control_files: observation.control_files.clone(),
        })
    }

    fn retained_objects(
        &self,
    ) -> Result<BTreeMap<&str, &LinuxRetainedObjectIdentityV1>, LinuxProductionCommandPlanError>
    {
        validate_retained_objects(
            &self.plan.components.retained,
            &self.plan.compiled_authority.grant.identity,
        )
    }
}

fn validate_prepared_leaf_control_files(
    observation: &LinuxPreparedCommandDomainLeafObservationV1,
    parent: &LinuxRetainedObjectIdentityV1,
    delegation: &LinuxRetainedObjectIdentityV1,
) -> Result<(), LinuxProductionCommandPlanError> {
    if observation.control_files.len() != LinuxCommandDomainControlFileV1::REQUIRED.len() {
        return Err(invalid(
            "the observation does not carry exactly the three required control files",
        ));
    }
    let mut seen = BTreeSet::from([parent.inode, delegation.inode, observation.leaf.inode]);
    for (expected, observed) in LinuxCommandDomainControlFileV1::REQUIRED
        .iter()
        .zip(&observation.control_files)
    {
        if observed.file != *expected {
            return Err(invalid(
                "observed control files are not the three required ones in order",
            ));
        }
        observed.identity.validate()?;
        if observed.identity.kind != LinuxRetainedObjectKindV1::CgroupControlFile {
            return Err(invalid(format!(
                "the observed {} is not a cgroup control file",
                expected.name()
            )));
        }
        if observed.identity.device_id != observation.leaf.device_id
            || observed.identity.mount_id != observation.leaf.mount_id
            || observed.identity.owner_uid != observation.leaf.owner_uid
        {
            return Err(invalid(format!(
                "the observed {} is not an owner-matched object on the leaf's own mount",
                expected.name()
            )));
        }
        if !seen.insert(observed.identity.inode) {
            return Err(invalid(format!(
                "the observed {} aliases another cgroup object in this binding",
                expected.name()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
impl ValidatedLinuxProductionCommandPlanV1 {
    /// Rebinds the cgroup roots' unique mount identity.
    ///
    /// `rebind_test_service_journal` can only derive device and inode, because
    /// that is all the installer anchor commits. A live canary that binds a
    /// really prepared leaf must supply the delegation's real
    /// `STATX_MNT_ID_UNIQUE` as well, or the mount-identity check in
    /// `bind_prepared_command_domain_leaf` would be comparing a live read
    /// against a stand-in. The value passed here is a `statx` of the live
    /// delegation, not a number the test chose.
    #[cfg(test)]
    pub(crate) fn rebind_test_cgroup_mount_id(
        mut self,
        mount_id: u64,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let cgroup = self.plan.components.retained.cgroup.clone();
        for object in &mut self.plan.components.retained.objects {
            if object.object_id == cgroup.service_parent_object_id
                || object.object_id == cgroup.delegation_root_object_id
            {
                object.mount_id = mount_id;
            }
        }
        Self::from_plan(self.plan)
    }

    /// Rebinds every architecture-bearing field of a test plan at once.
    ///
    /// It exists so a canary can vary the plan's architecture as one input
    /// against a measured host. It cannot produce a mixed-architecture plan:
    /// `from_plan` runs `validate_architecture` on the result.
    #[cfg(test)]
    pub(crate) fn rebind_test_machine_architecture(
        mut self,
        architecture: LinuxMachineArchitectureV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let format = architecture.elf_image_format();
        let binaries = &mut self.plan.components.binaries;
        binaries.bubblewrap_format = format;
        binaries.inner_launcher_format = format;
        binaries.target.image_format = format;
        if let LinuxTargetLinkageV1::DynamicElf {
            interpreter_format, ..
        } = &mut binaries.target.linkage
        {
            *interpreter_format = format;
        }
        self.plan
            .components
            .seccomp
            .set_test_audit_architecture(architecture.audit_architecture());
        Self::from_plan(self.plan)
    }
}

// ---------------------------------------------------------------------------
// The admitted Bubblewrap image
// ---------------------------------------------------------------------------

/// The exact Bubblewrap image this project admits, by immutable source
/// identity.
///
/// `LinuxBinaryIdentitiesV1::bubblewrap` is not an `Option`, so every complete
/// Linux command plan names a real `bwrap` file. That makes "which `bwrap`" a
/// supply-chain question rather than a deployment detail, and this constant is
/// the answer a reviewed commit gave.
///
/// **It is a pin, not a discovery.** Nothing here searches a `PATH` and nothing
/// accepts whatever happens to be installed: a production mint reads the file
/// at [`Self::resolved_path`], hashes its whole content, and requires the digest
/// to equal [`Self::sha256`]. A host carrying a different `bwrap` — newer,
/// older, patched, or a distribution's own build — is refused rather than
/// admitted, which is the same stance
/// [`crate::macos_vz_guest`]'s `GUEST_IMAGE_PIN_V1` takes towards the kernel.
///
/// **Where the values come from.** All of them are read out of the verified
/// acquisition chain in [`BUBBLEWRAP_ACQUISITION_SCRIPT`], which is the chain
/// the guest kernel already travels: Canonical's pinned archive-signing
/// fingerprint, `gpgv` on the suite's `InRelease`, the index digest taken out of
/// that signed text, and this archive's `Filename`/`Size`/`SHA256` taken out of
/// that index. Bubblewrap is the **third package** on that chain and changes no
/// link of it.
///
/// **The version is a file fact.** [`Self::version`] is the `Version:` field of
/// the archive's own `control` member, cross-checked against the same field in
/// the signed index. It is deliberately not the output of `bwrap --version`:
/// executing a freshly downloaded binary to learn what it is would put the
/// answer outside the signature chain, and the package version additionally
/// identifies the exact build rather than only the upstream release.
///
/// **The self-report is a second, different fact about the same bytes.**
/// [`Self::self_reported_version`] is what this exact image prints when it is
/// asked `--version`. It is not a substitute for [`Self::version`] and does not
/// weaken it: a package version and an upstream release line are different
/// strings by construction, and this admission commits both rather than
/// pretending one answers for the other. Committing it is no weaker than
/// committing [`Self::sha256`], because it is a **property of the pinned
/// bytes** — the same file whose whole content is already pinned. What the
/// admission refused was *learning* the version by execution; recording what
/// the verified image says, and then requiring the running image to say the
/// same, is the opposite of that. It is a liveness binding: the digest proves
/// the bytes on disk are the admitted ones, and the probe proves the thing that
/// executed is that thing.
///
/// **Where it is verified.** Not in [`BUBBLEWRAP_ACQUISITION_SCRIPT`], on
/// purpose: that step must not execute what it just downloaded, which is the
/// whole reason [`Self::version`] is read out of the `control` member. It is
/// verified against the already-verified image instead, by
/// `linux_cgroup_io`'s live probe test, which authenticates
/// `/usr/bin/bwrap` against [`Self::sha256`] *before* executing it through the
/// retained descriptor and requires the resulting stdout to equal this string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmittedBubblewrapImageV1 {
    /// Binary package name, exactly as the signed index spells it.
    pub(crate) package: &'static str,
    /// Package version, exactly as both the signed index and the archive's own
    /// `control` member spell it. This is the string a plan commits as
    /// `LinuxBinaryIdentitiesV1::bubblewrap_version`.
    pub(crate) version: &'static str,
    /// The exact line this image prints on stdout for `--version`, without its
    /// terminating line feed.
    ///
    /// A property of the pinned bytes, not of the archive metadata, and the
    /// value `validate_service_bootstrap_evidence` requires a live bootstrap
    /// probe to have measured. See the type's documentation for why this is a
    /// second commitment rather than a replacement for [`Self::version`].
    pub(crate) self_reported_version: &'static str,
    /// Architecture, pinned so an arm64 admission cannot silently take amd64.
    pub(crate) architecture: &'static str,
    /// Path under the archive root, exactly as the index's `Filename` says.
    pub(crate) pool_path: &'static str,
    /// Lowercase hexadecimal SHA-256 of the `.deb`, as the index's `SHA256`
    /// says.
    pub(crate) archive_sha256: &'static str,
    /// Byte length of the `.deb`, as the index's `Size` says.
    pub(crate) archive_byte_length: u64,
    /// Lowercase hexadecimal SHA-256 of the extracted `usr/bin/bwrap`.
    pub(crate) sha256: &'static str,
    /// Byte length of the extracted `usr/bin/bwrap`.
    pub(crate) byte_length: u64,
    /// Absolute path the image installs the launcher at, and the path a
    /// production mint authenticates.
    pub(crate) resolved_path: &'static str,
    /// ELF image format, measured out of `e_machine` by the acquisition step
    /// rather than inferred from the pool path.
    pub(crate) elf_image_format: LinuxElfImageFormatV1,
}

/// The committed Bubblewrap admission. See [`AdmittedBubblewrapImageV1`].
pub(crate) const ADMITTED_BUBBLEWRAP_IMAGE_V1: AdmittedBubblewrapImageV1 =
    AdmittedBubblewrapImageV1 {
        package: "bubblewrap",
        version: "0.9.0-1ubuntu0.1",
        self_reported_version: "bubblewrap 0.9.0",
        architecture: "arm64",
        pool_path: "pool/main/b/bubblewrap/bubblewrap_0.9.0-1ubuntu0.1_arm64.deb",
        archive_sha256: "3fb4ca3a8d2060444836568ed49d6897a403467e4ba29c93440900093fb96a38",
        archive_byte_length: 49_694,
        sha256: "ae27935781511400c65ebcc0b4669775d602f46251b8707c947a1ac1b160c1c8",
        byte_length: 67_816,
        resolved_path: "/usr/bin/bwrap",
        elf_image_format: LinuxElfImageFormatV1::Elf64Aarch64,
    };

/// The acquisition step that produced the admission above, relative to this
/// crate's manifest directory.
///
/// The product never runs it. It is named here so the in-tree drift test has one
/// place to look, and so a reader of the pin finds the step that produced it.
pub(crate) const BUBBLEWRAP_ACQUISITION_SCRIPT: &str = "guest-image/kernel.sh";

/// Plan-internal role name for the admitted Bubblewrap image.
///
/// It is a role, not a path: `validate_binaries` requires it to be distinct
/// from the inner launcher, the setup channel and the target, and
/// `validate_mounts` never mounts it.
pub(crate) const BUBBLEWRAP_OBJECT_ID: &str = "bubblewrap-image";

/// Authenticates the Bubblewrap slot of [`LinuxBinaryIdentitiesV1`] against
/// [`ADMITTED_BUBBLEWRAP_IMAGE_V1`].
///
/// The caller supplies a held descriptor's kernel observation and complete bytes.
/// Require the admitted path, length, digest, and measured ELF format; the version
/// is pinned from the authenticated archive metadata. This validates the admitted
/// image rather than discovering an arbitrary installed executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedBubblewrapImageV1 {
    retained: LinuxRetainedObjectIdentityV1,
    image: LinuxAuthenticatedFileV1,
    format: LinuxElfImageFormatV1,
    version: String,
}

impl AuthenticatedBubblewrapImageV1 {
    /// Authenticates a live Bubblewrap readback against the committed
    /// admission.
    ///
    /// `observed` must be a kernel observation of the descriptor the caller
    /// holds, and `content` a complete readback of that same descriptor. This
    /// function performs no I/O on purpose: it is the same split
    /// [`LinuxRetainedObjectIdentityV1::from_kernel_observation`] uses, and it
    /// keeps the whole comparison testable on a host that has no `bwrap`.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the readback
    /// differs from [`ADMITTED_BUBBLEWRAP_IMAGE_V1`] in any respect, when the
    /// observation and the readback disagree about length, or when the image's
    /// mode carries a set-user-ID or set-group-ID bit.
    pub(crate) fn authenticate_admitted(
        resolved_path: &str,
        observed: LinuxKernelObjectObservationV1,
        content: &[u8],
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let admitted = ADMITTED_BUBBLEWRAP_IMAGE_V1;
        if resolved_path != admitted.resolved_path {
            return Err(invalid(format!(
                "Bubblewrap was authenticated at {resolved_path}; the admitted image is {}",
                admitted.resolved_path
            )));
        }
        // Reject setuid/setgid Bubblewrap before checking its digest so the refusal
        // identifies the unsafe file mode.
        if observed.mode & SET_ID_MODE != 0 {
            return Err(invalid(
                "the admitted Bubblewrap image must not be setuid or setgid",
            ));
        }
        let readback_length = u64::try_from(content.len())
            .map_err(|_| invalid("Bubblewrap readback length cannot be represented"))?;
        if readback_length != admitted.byte_length {
            return Err(invalid(format!(
                "Bubblewrap at {resolved_path} read back {readback_length} bytes; the admitted image is {} bytes",
                admitted.byte_length
            )));
        }
        // The observation and the readback are two independent answers about
        // the same descriptor. Requiring them to agree is what makes a file
        // that changed between the `statx` and the read a refusal rather than
        // a plan minted from a length that no longer describes the content.
        if observed.byte_length != Some(readback_length) {
            return Err(invalid(
                "Bubblewrap inode length and complete readback length disagree",
            ));
        }
        let content_sha256 = Digest::sha256(content);
        if content_sha256.as_str() != admitted.sha256 {
            return Err(invalid(format!(
                "Bubblewrap at {resolved_path} hashes to {content_sha256}; the admitted image is {}",
                admitted.sha256
            )));
        }
        // Measured from the readback bytes rather than taken from the
        // admission, so the format is a property of the file in front of us.
        // The equality below is then a check rather than an assignment.
        let header = content
            .get(..LINUX_ELF_HEADER_PREFIX_BYTES)
            .ok_or_else(|| invalid("the Bubblewrap readback is shorter than an ELF header"))?;
        if header[..ELF_IDENTIFICATION_MAGIC.len()] != ELF_IDENTIFICATION_MAGIC {
            return Err(invalid(
                "the Bubblewrap readback does not begin with the ELF identification magic",
            ));
        }
        if header[4] != ELF_CLASS_64 || header[5] != ELF_DATA_LITTLE_ENDIAN {
            return Err(invalid(
                "the Bubblewrap readback is not a 64-bit little-endian ELF object",
            ));
        }
        let elf_machine = u16::from_le_bytes([header[18], header[19]]);
        let format = LinuxMachineArchitectureV1::from_elf_machine(elf_machine)
            .ok_or_else(|| {
                invalid(format!(
                    "the Bubblewrap image's ELF e_machine 0x{elf_machine:04x} is not an architecture this plan schema can describe"
                ))
            })?
            .elf_image_format();
        if format != admitted.elf_image_format {
            return Err(invalid(
                "the Bubblewrap image's measured ELF format differs from the admitted image",
            ));
        }
        let retained = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            BUBBLEWRAP_OBJECT_ID,
            LinuxRetainedObjectKindV1::RegularFile,
            observed,
        )?;
        let image = LinuxAuthenticatedFileV1::from_complete_readback(
            BUBBLEWRAP_OBJECT_ID,
            resolved_path,
            readback_length,
            content_sha256,
        )?;
        Ok(Self {
            retained,
            image,
            format,
            version: admitted.version.to_owned(),
        })
    }

    /// The retained identity the plan's object table must carry for this image.
    pub(crate) const fn retained(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.retained
    }

    /// The three `LinuxBinaryIdentitiesV1` Bubblewrap fields, in field order.
    pub(crate) fn binary_identity_fields(
        &self,
    ) -> (&LinuxAuthenticatedFileV1, LinuxElfImageFormatV1, &str) {
        (&self.image, self.format, &self.version)
    }
}

// ---------------------------------------------------------------------------
// The sealed setup channel
// ---------------------------------------------------------------------------

/// The wire contract of the sealed setup request one Linux command plan
/// commits to.
///
/// This is the artefact `LinuxSetupChannelV1::protocol_digest` is the digest
/// of. It exists as a compiled constant **and** as the first line of every
/// setup channel this project mints, and
/// [`AuthenticatedSetupChannelV1::authenticate_sealed`] takes the digest out of
/// the sealed bytes rather than out of this constant, so the commitment is a
/// measurement of a kernel object's content and not a restatement of a literal.
/// A validator holding only the descriptor can re-derive the same digest from
/// the memfd it was handed.
///
/// **Framing.** Line-feed-terminated ASCII lines. Line 0 is this descriptor
/// verbatim, which is why it may not itself contain a line feed — asserted by
/// `the_setup_channel_protocol_descriptor_is_one_ascii_line`. Every other line
/// is `key=value` except the four object lines, which are colon-separated
/// fields, and the terminating `end`.
///
/// **What it deliberately does not carry.** No file descriptor, no pathname, no
/// argv, no environment, no credential and no release permit. The setup channel
/// is a statement of installed state that the future inner launcher must find;
/// it grants nothing, and a reader that treats it as authority is reading it
/// wrongly.
pub(crate) const LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1: &str = "grok-build.linux-setup-channel.v1\
    ;framing=lf-terminated-ascii-lines\
    ;line-0=this-descriptor\
    ;lines=descriptor,format,role,input-snapshot,host-architecture,cgroup-filesystem-magic,authenticated-platform-service-digest,object*4,end\
    ;object=<plan-object-id>:<kind>:<device>:<inode>:<mount>:<mode-octal>:<uid>:<gid>:<link-count>\
    ;objects=service-state-root,singleton-journal-root,service-cgroup-parent,cgroup-delegation-root\
    ;identity-source=installer-anchored-live-kernel-reads\
    ;max-bytes=1048576\
    ;seals=seal,shrink,grow,write,future-write,exec\
    ;no-descriptors;no-paths;no-argv;no-environment;no-credentials;no-release-authority";

/// Format revision of the statement below line 0.
///
/// The descriptor names the line order and the object grammar, so a change to
/// either changes the protocol digest as well as this number. They move
/// together on purpose: one of them is what a reader compares, the other is
/// what a human reads.
const LINUX_SETUP_CHANNEL_STATEMENT_FORMAT_V1: u32 = 1;

/// Plan-internal role name for the sealed setup channel.
///
/// It is a role, not a path — a memfd has no name a plan could use.
/// `validate_binaries` requires it to be distinct from the Bubblewrap image,
/// the inner launcher and the target.
pub(crate) const SETUP_CHANNEL_OBJECT_ID: &str = "setup-channel";

/// The digest of [`LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1`].
///
/// The same shape as `crate::runner_protocol_digest`: one function over one
/// compiled descriptor, so two peers built from this source agree without
/// exchanging anything.
pub(crate) fn linux_setup_channel_protocol_digest() -> Digest {
    Digest::sha256(LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1.as_bytes())
}

/// Wire spelling of one retained-object kind inside a setup-channel statement.
const fn setup_channel_kind_name(kind: LinuxRetainedObjectKindV1) -> &'static str {
    match kind {
        LinuxRetainedObjectKindV1::Directory => "directory",
        LinuxRetainedObjectKindV1::RegularFile => "regular-file",
        LinuxRetainedObjectKindV1::SealedMemfd => "sealed-memfd",
        LinuxRetainedObjectKindV1::CgroupDirectory => "cgroup-directory",
        LinuxRetainedObjectKindV1::CgroupControlFile => "cgroup-control-file",
    }
}

/// Encodes one anchored object line, refusing anything a decoded plan's object
/// table would refuse.
///
/// The identity has to survive the **same** `validate` the plan applies before
/// it may be digested into a channel: an identity that could not appear in an
/// object table must not appear in a commitment about one.
fn encode_anchored_setup_object(
    expected_id: &str,
    expected_kind: LinuxRetainedObjectKindV1,
    object: &LinuxRetainedObjectIdentityV1,
) -> Result<String, LinuxProductionCommandPlanError> {
    object.validate()?;
    if object.object_id != expected_id {
        return Err(invalid(format!(
            "the setup channel's {expected_id} slot carries the identity named {}",
            object.object_id
        )));
    }
    if object.kind != expected_kind {
        return Err(invalid(format!(
            "the setup channel's {expected_id} is not the kernel object kind it must be"
        )));
    }
    // One spelling of the nine-field object line, shared with the `.git`-mask
    // observation contract. The byte length and digest this encoder is pinned
    // to are unchanged by the sharing, which is what proves the two contracts
    // agree about what an identity looks like.
    Ok(encode_retained_object_line(object))
}

/// Exactly what one sealed setup channel states, before it is encoded.
///
/// Every field is either a live kernel read or installed state carried through
/// the installer's external commitment: the four object identities and the
/// platform-service digest are what
/// `LinuxNativeServiceStateRootCapability::observe_anchored_plan_facts` minted
/// and the anchor proved, the cgroup filesystem magic is an `fstatfs`, the host
/// architecture is the running image's ELF header agreeing with `uname(2)`, and
/// the role and input snapshot come from the durable command-effect authority.
/// **Nothing here is a value this process chose**, which is the property that
/// makes a digest over the encoding worth taking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxSetupChannelStatementV1<'a> {
    pub(crate) role: RunnerRole,
    pub(crate) input_snapshot: &'a Digest,
    pub(crate) host_architecture: LinuxMachineArchitectureV1,
    pub(crate) cgroup_filesystem_magic: u64,
    pub(crate) authenticated_platform_service_digest: &'a Digest,
    pub(crate) service_state_root: &'a LinuxRetainedObjectIdentityV1,
    pub(crate) singleton_journal_root: &'a LinuxRetainedObjectIdentityV1,
    pub(crate) service_cgroup_parent: &'a LinuxRetainedObjectIdentityV1,
    pub(crate) cgroup_delegation_root: &'a LinuxRetainedObjectIdentityV1,
}

impl LinuxSetupChannelStatementV1<'_> {
    /// Encodes the exact bytes a setup channel must contain.
    ///
    /// This is the *only* producer of setup-channel content. A service seals
    /// these bytes into a memfd; the mint re-runs this function and requires
    /// the sealed readback to equal it byte for byte, so there is one source of
    /// truth rather than a written copy that can drift from what it describes.
    ///
    /// The encoding is total and deterministic — no map iteration order, no
    /// clock, no locale, no floating point — which is what makes re-derivation
    /// by an independent reader possible at all.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the role runs
    /// no contained command, when either digest is all zero, when the stated
    /// filesystem is not cgroup v2, when any anchored identity fails the same
    /// `validate` a decoded plan applies, when an identity is in the wrong slot
    /// or of the wrong kind, when two anchored objects collapse onto one device
    /// and inode, or when the encoding exceeds [`MAX_SETUP_CHANNEL_BYTES`].
    pub(crate) fn encode(&self) -> Result<Vec<u8>, LinuxProductionCommandPlanError> {
        let role = match self.role {
            RunnerRole::Worker => "worker",
            RunnerRole::FinalVerifier => "final-verifier",
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                return Err(invalid(
                    "the setup channel cannot state a role that runs no contained command",
                ));
            }
        };
        validate_nonzero_digest(self.input_snapshot, "setup channel role input snapshot")?;
        validate_nonzero_digest(
            self.authenticated_platform_service_digest,
            "setup channel platform service",
        )?;
        if self.cgroup_filesystem_magic != CGROUP2_SUPER_MAGIC {
            return Err(invalid(
                "the setup channel's stated cgroup filesystem is not cgroup v2",
            ));
        }

        let anchored = [
            (
                SERVICE_STATE_ROOT_OBJECT_ID,
                LinuxRetainedObjectKindV1::Directory,
                self.service_state_root,
            ),
            (
                SINGLETON_JOURNAL_ROOT_OBJECT_ID,
                LinuxRetainedObjectKindV1::Directory,
                self.singleton_journal_root,
            ),
            (
                SERVICE_CGROUP_PARENT_OBJECT_ID,
                LinuxRetainedObjectKindV1::CgroupDirectory,
                self.service_cgroup_parent,
            ),
            (
                CGROUP_DELEGATION_ROOT_OBJECT_ID,
                LinuxRetainedObjectKindV1::CgroupDirectory,
                self.cgroup_delegation_root,
            ),
        ];
        let mut distinct = BTreeSet::new();
        let mut lines = Vec::with_capacity(8 + anchored.len());
        lines.push(LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1.to_owned());
        lines.push(format!("format={LINUX_SETUP_CHANNEL_STATEMENT_FORMAT_V1}"));
        lines.push(format!("role={role}"));
        lines.push(format!("input-snapshot={}", self.input_snapshot));
        lines.push(format!(
            "host-architecture={}",
            self.host_architecture.as_str()
        ));
        lines.push(format!(
            "cgroup-filesystem-magic=0x{:08x}",
            self.cgroup_filesystem_magic
        ));
        lines.push(format!(
            "authenticated-platform-service-digest={}",
            self.authenticated_platform_service_digest
        ));
        for (expected_id, expected_kind, object) in anchored {
            if !distinct.insert((object.device_id, object.inode)) {
                return Err(invalid(format!(
                    "the setup channel's {expected_id} collapses onto another anchored object's device and inode"
                )));
            }
            lines.push(encode_anchored_setup_object(
                expected_id,
                expected_kind,
                object,
            )?);
        }
        lines.push("end".to_owned());

        let mut encoded = lines.join("\n");
        encoded.push('\n');
        let bytes = encoded.into_bytes();
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| invalid("the setup channel statement length cannot be represented"))?;
        if byte_length == 0 || byte_length > MAX_SETUP_CHANNEL_BYTES {
            return Err(invalid(
                "the setup channel statement is empty or exceeds its hard bound",
            ));
        }
        Ok(bytes)
    }
}

/// The production source for the setup-channel slot of
/// [`LinuxBinaryIdentitiesV1`].
///
/// `LinuxSetupChannelV1::protocol_digest` had no producer anywhere in the
/// workspace, and the only writer of `content_sha256` was a test rebind. This
/// is what produces both, and it produces them the same way
/// [`AuthenticatedBubblewrapImageV1`] produces its ELF format: **measured out
/// of the bytes in front of it, then required to equal what is committed.**
///
/// The caller supplies three independent answers about one sealed memfd it
/// already holds — a `statx`/`fstat` observation, the live `F_GET_SEALS` answer,
/// and a complete readback — plus the [`LinuxSetupChannelStatementV1`] that
/// should be in it. Every one of them has to agree. In particular the readback
/// must equal a fresh encoding of the statement byte for byte, so a channel is
/// never a digest of whatever happened to be in a descriptor: it is a digest of
/// installed state this process re-derived and then found sealed in the kernel.
///
/// It performs no I/O, deliberately, and for the same reason
/// [`AuthenticatedBubblewrapImageV1::authenticate_admitted`] performs none: the
/// whole comparison stays provable on a host with no memfds at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedSetupChannelV1 {
    retained: LinuxRetainedObjectIdentityV1,
    channel: LinuxSetupChannelV1,
}

impl AuthenticatedSetupChannelV1 {
    /// Authenticates one sealed setup channel against the statement it must
    /// carry.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the memfd's
    /// mode carries a set-user-ID, set-group-ID, group-write or other-write
    /// bit; when the live seal set is not exactly
    /// [`REQUIRED_SETUP_SEAL_BITS`]; when the inode length and the readback
    /// length disagree; when the readback carries no line-terminated protocol
    /// descriptor or one this build does not speak; when the readback differs
    /// from a fresh encoding of `statement`; or when the resulting identity or
    /// channel fails the validators a decoded plan applies.
    pub(crate) fn authenticate_sealed(
        statement: &LinuxSetupChannelStatementV1<'_>,
        observed: LinuxKernelObjectObservationV1,
        observed_seal_bits: u32,
        content: &[u8],
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        // Mode first, for the reason the Bubblewrap mint checks it before the
        // digest: it is inode metadata, independent of the bytes, so ordering
        // it later would make it unreachable for exactly the channels whose
        // mode most wants naming.
        if observed.mode & SET_ID_MODE != 0 {
            return Err(invalid(
                "the setup channel memfd must not be setuid or setgid",
            ));
        }
        if observed.mode & 0o022 != 0 {
            return Err(invalid(
                "the setup channel memfd is group-writable or world-writable",
            ));
        }
        // The seal set is checked before the content is looked at, because
        // bytes read out of an unsealed descriptor are not evidence of
        // anything: they can differ from the bytes the reader gets next.
        if observed_seal_bits != REQUIRED_SETUP_SEAL_BITS {
            return Err(invalid(format!(
                "the setup channel carries seals {observed_seal_bits:#06x}; the plan requires exactly {REQUIRED_SETUP_SEAL_BITS:#06x}"
            )));
        }
        let readback_length = u64::try_from(content.len())
            .map_err(|_| invalid("the setup channel readback length cannot be represented"))?;
        // Two independent answers about one descriptor. Requiring them to agree
        // is what turns a channel that changed between the `statx` and the read
        // into a refusal.
        if observed.byte_length != Some(readback_length) {
            return Err(invalid(
                "setup channel inode length and complete readback length disagree",
            ));
        }

        // The protocol digest is taken out of the sealed bytes. This is the
        // whole point: the plan commits a digest of something that exists in a
        // kernel object, and the equality below is a check rather than an
        // assignment.
        let terminator = content
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| {
                invalid("the setup channel readback carries no line-terminated protocol descriptor")
            })?;
        let protocol_digest = Digest::sha256(&content[..terminator]);
        let spoken = linux_setup_channel_protocol_digest();
        if protocol_digest != spoken {
            return Err(invalid(format!(
                "the setup channel declares protocol {protocol_digest}; this build speaks {spoken}"
            )));
        }

        let expected = statement.encode()?;
        if content != expected.as_slice() {
            let offset = content
                .iter()
                .zip(expected.iter())
                .position(|(read, derived)| read != derived)
                .unwrap_or_else(|| content.len().min(expected.len()));
            return Err(invalid(format!(
                "the setup channel readback differs from the anchored statement at byte {offset}"
            )));
        }
        let content_sha256 = Digest::sha256(content);

        let retained = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            SETUP_CHANNEL_OBJECT_ID,
            LinuxRetainedObjectKindV1::SealedMemfd,
            observed,
        )?;
        let channel = LinuxSetupChannelV1::from_sealed_readback(
            &retained,
            readback_length,
            content_sha256,
            protocol_digest,
            observed_seal_bits,
        )?;
        Ok(Self { retained, channel })
    }

    /// The retained identity the plan's object table must carry for this
    /// channel.
    pub(crate) const fn retained(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.retained
    }

    /// The `LinuxBinaryIdentitiesV1::setup_channel` field.
    pub(crate) const fn setup_channel(&self) -> &LinuxSetupChannelV1 {
        &self.channel
    }
}

// Derive static linkage from ELF program headers. Dynamic linkage requires
// an authenticated loader closure and is refused here.

// ---------------------------------------------------------------------------
// ELF64 program header geometry
// ---------------------------------------------------------------------------

/// Bytes in the ELF64 file header.
///
/// The whole header is read because `e_phoff`, `e_phentsize` and `e_phnum` live
/// at 0x20, 0x36 and 0x38 respectively — past the twenty bytes
/// [`LINUX_ELF_HEADER_PREFIX_BYTES`] covers, which is only enough for
/// `e_machine`.
const ELF64_HEADER_BYTES: usize = 64;

/// [`ELF64_HEADER_BYTES`] as a byte count, for comparison against inode lengths.
const ELF64_HEADER_BYTE_COUNT: u64 = 64;

/// Offset of `e_type` in the ELF64 header.
const ELF64_TYPE_OFFSET: usize = 0x10;
/// Offset of `e_machine` in the ELF64 header.
const ELF64_MACHINE_OFFSET: usize = 0x12;
/// Offset of `e_phoff`, the program header table's own file offset.
const ELF64_PROGRAM_HEADER_TABLE_OFFSET: usize = 0x20;
/// Offset of `e_phentsize`, the stride of one program header entry.
const ELF64_PROGRAM_HEADER_ENTRY_SIZE_OFFSET: usize = 0x36;
/// Offset of `e_phnum`, the program header count.
const ELF64_PROGRAM_HEADER_COUNT_OFFSET: usize = 0x38;

/// The only `e_phentsize` an ELF64 program header table may carry.
///
/// A table with any other stride is one this walk cannot index, and an image
/// carrying one is refused rather than walked at the wrong pitch — a wrong
/// stride would read `p_type` out of the middle of a neighbouring field and
/// could report zero `PT_INTERP` for an image that has one.
const ELF64_PROGRAM_HEADER_ENTRY_BYTES: u16 = 56;

/// `e_type` for a fully linked, non-relocatable executable.
const ELF_TYPE_EXECUTABLE: u16 = 2;
/// `e_type` for a shared object, which a position-independent executable is.
const ELF_TYPE_SHARED_OBJECT: u16 = 3;

/// `p_type` of a segment the kernel maps.
const ELF_SEGMENT_LOADABLE: u32 = 1;
/// `p_type` of the dynamic linking table.
const ELF_SEGMENT_DYNAMIC: u32 = 2;
/// `p_type` naming the program interpreter.
const ELF_SEGMENT_INTERPRETER: u32 = 3;

/// The `e_phnum` escape value (`PN_XNUM`).
///
/// It means "the real program header count is `sh_info` of section header 0",
/// which is in the *section* header table this walk does not read. An image
/// carrying it is refused: the count is unknown here, and an unknown count
/// cannot demonstrate the absence of anything.
const ELF_PROGRAM_HEADER_COUNT_ESCAPE: u16 = 0xffff;

/// Hard bound on the program headers this plan will walk.
///
/// Real executables carry well under twenty. The bound exists so a hostile or
/// corrupt `e_phnum` cannot make the walk read an unbounded amount through a
/// descriptor the caller handed over.
const MAX_LINUX_TARGET_PROGRAM_HEADERS: u16 = 256;

// ---------------------------------------------------------------------------
// Bounded positional reads over an image the caller already holds
// ---------------------------------------------------------------------------

/// A bounded, positional source of one executable image's bytes.
///
/// The prover never opens anything. It reads at explicit offsets from something
/// the caller already has, which is what lets the production path read the
/// **held descriptor** `RetainedExecutable` keeps open across
/// `prepare_v12` — the same descriptor the launch would use — rather than
/// reopening a path that may by then resolve somewhere else.
///
/// Every read is exact: a source that cannot supply the requested bytes reports
/// a refusal instead of a short answer, because a short read is indistinguishable
/// from a truncated image and neither is evidence about program headers.
pub(crate) trait LinuxImageByteSourceV1 {
    /// Fills `into` from `offset`, or refuses.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the source
    /// holds fewer bytes than the read requires, when the offset cannot be
    /// represented on this host, or when the underlying read fails.
    fn read_image_bytes_at(
        &self,
        offset: u64,
        into: &mut [u8],
        subject: &str,
    ) -> Result<(), LinuxProductionCommandPlanError>;
}

impl LinuxImageByteSourceV1 for [u8] {
    fn read_image_bytes_at(
        &self,
        offset: u64,
        into: &mut [u8],
        subject: &str,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        let start = usize::try_from(offset).map_err(|_| {
            invalid(format!(
                "{subject} read offset {offset} cannot be represented on this host"
            ))
        })?;
        let end = start.checked_add(into.len()).ok_or_else(|| {
            invalid(format!(
                "{subject} read of {} bytes at offset {offset} overflows this host's address space",
                into.len()
            ))
        })?;
        let window = self.get(start..end).ok_or_else(|| {
            invalid(format!(
                "{subject} is truncated: {} bytes were required at offset {offset} and the image holds {}",
                into.len(),
                self.len()
            ))
        })?;
        into.copy_from_slice(window);
        Ok(())
    }
}

#[cfg(unix)]
impl LinuxImageByteSourceV1 for std::fs::File {
    fn read_image_bytes_at(
        &self,
        offset: u64,
        into: &mut [u8],
        subject: &str,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        use std::os::unix::fs::FileExt as _;

        let required = into.len();
        let mut filled = 0_usize;
        while filled < required {
            let filled_offset = u64::try_from(filled)
                .map_err(|_| invalid(format!("{subject} read progress cannot be represented")))?;
            let read_offset = offset
                .checked_add(filled_offset)
                .ok_or_else(|| invalid(format!("{subject} read offset overflows past {offset}")))?;
            let count = self.read_at(&mut into[filled..], read_offset).map_err(|error| {
                invalid(format!(
                    "{subject} descriptor read of {} bytes at offset {read_offset} failed: {error}",
                    required - filled
                ))
            })?;
            if count == 0 {
                return Err(invalid(format!(
                    "{subject} is truncated: {required} bytes were required at offset {offset} and the descriptor supplied {filled}"
                )));
            }
            filled = filled.checked_add(count).ok_or_else(|| {
                invalid(format!("{subject} read progress overflows past {filled}"))
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The measured target image
// ---------------------------------------------------------------------------

/// The production source for [`LinuxTargetLinkageV1`], for the static case.
///
/// **This measures; it does not assume.** Every value below comes out of the
/// image's own bytes, read through a descriptor the caller holds, and the
/// linkage is produced only after the program header table has been walked in
/// full and found to carry **zero `PT_INTERP` and zero `PT_DYNAMIC`**. That is
/// the property [`validate_mounts`] serves with zero
/// [`LinuxMountPurposeV1::ElfInterpreter`] and zero
/// [`LinuxMountPurposeV1::RuntimeObject`] mounts, so it is what keeps the
/// deferred loader-closure item deferred rather than forcing it.
///
/// **An image it cannot parse is refused, never read as static.** A header
/// table with an unexpected stride, an `e_phnum` of zero, the `PN_XNUM` escape,
/// a count past this walk's bound, or a table extending past the authenticated
/// length are each a refusal. This distinction is the whole point: an ELF
/// relocatable object has no program headers at all, so "no `PT_INTERP` was
/// found" is only evidence when the table it was looked for in was really
/// there and really walked.
///
/// The dynamic case has no producer here on purpose, and the refusal says so.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxMeasuredTargetImageV1 {
    format: LinuxElfImageFormatV1,
    linkage: LinuxTargetLinkageV1,
    byte_length: u64,
    program_headers: usize,
    loadable_segments: usize,
}

impl LinuxMeasuredTargetImageV1 {
    /// Measures one target executable's ELF format and linkage.
    ///
    /// `source` must address the exact image the plan authenticated;
    /// `authenticated_byte_length` must be that image's authenticated length,
    /// so the program header table can be required to lie inside the bytes the
    /// content digest was taken over rather than inside whatever the descriptor
    /// happens to return later. `expected` is the measured host architecture:
    /// a target built for another machine cannot execute under this plan and is
    /// refused here rather than at exec time.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the image is
    /// shorter than an ELF64 header, does not carry the ELF identification
    /// magic, is not a 64-bit little-endian object, names a machine this schema
    /// cannot describe or one other than `expected`, is not a loadable
    /// executable image, carries a program header table this walk cannot index
    /// or that lies outside the authenticated length, maps no loadable segment,
    /// or carries any `PT_INTERP` or `PT_DYNAMIC` header.
    pub(crate) fn measure<Source: LinuxImageByteSourceV1 + ?Sized>(
        source: &Source,
        authenticated_byte_length: u64,
        expected: LinuxMachineArchitectureV1,
        subject: &str,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        if authenticated_byte_length < ELF64_HEADER_BYTE_COUNT {
            return Err(invalid(format!(
                "{subject} is {authenticated_byte_length} bytes, shorter than the {ELF64_HEADER_BYTE_COUNT}-byte ELF64 header"
            )));
        }
        let mut header = [0_u8; ELF64_HEADER_BYTES];
        source.read_image_bytes_at(0, &mut header, subject)?;

        if header[..ELF_IDENTIFICATION_MAGIC.len()] != ELF_IDENTIFICATION_MAGIC {
            return Err(invalid(format!(
                "{subject} does not begin with the ELF identification magic"
            )));
        }
        if header[4] != ELF_CLASS_64 || header[5] != ELF_DATA_LITTLE_ENDIAN {
            return Err(invalid(format!(
                "{subject} is not a 64-bit little-endian ELF object"
            )));
        }

        // Measured out of the bytes, then compared — the same stance the
        // Bubblewrap mint takes towards `e_machine`.
        let elf_machine = read_le_u16(&header, ELF64_MACHINE_OFFSET)
            .ok_or_else(|| unreachable_elf_field(subject, "e_machine"))?;
        let architecture =
            LinuxMachineArchitectureV1::from_elf_machine(elf_machine).ok_or_else(|| {
                invalid(format!(
                    "{subject} ELF e_machine {elf_machine:#06x} is not an architecture this plan schema can describe"
                ))
            })?;
        if architecture != expected {
            return Err(invalid(format!(
                "{subject} is built for {} (ELF e_machine {elf_machine:#06x}); this host is {}",
                architecture.as_str(),
                expected.as_str()
            )));
        }

        let elf_type = read_le_u16(&header, ELF64_TYPE_OFFSET)
            .ok_or_else(|| unreachable_elf_field(subject, "e_type"))?;
        if elf_type != ELF_TYPE_EXECUTABLE && elf_type != ELF_TYPE_SHARED_OBJECT {
            return Err(invalid(format!(
                "{subject} ELF e_type {elf_type:#06x} is neither an executable nor a shared object, so it carries no loadable program image"
            )));
        }

        let extent =
            LinuxProgramHeaderTableExtentV1::read(&header, authenticated_byte_length, subject)?;
        let mut table = vec![0_u8; extent.table_length];
        source.read_image_bytes_at(extent.offset, &mut table, subject)?;
        let counts = extent.walk(&table, subject)?;

        let program_headers = extent.count;
        if counts.loadable == 0 {
            return Err(invalid(format!(
                "{subject} walked {program_headers} program headers and found no PT_LOAD segment, so it maps no executable image"
            )));
        }
        if counts.interpreters != 0 || counts.dynamic != 0 {
            return Err(invalid(format!(
                "{subject} is dynamically linked: {program_headers} program headers carry {} PT_INTERP and {} PT_DYNAMIC. \
                 A dynamic target's linkage additionally requires an authenticated ELF interpreter and the complete runtime-object closure, which this plan has no production source for",
                counts.interpreters, counts.dynamic
            )));
        }

        Ok(Self {
            format: architecture.elf_image_format(),
            linkage: LinuxTargetLinkageV1::StaticElf,
            byte_length: authenticated_byte_length,
            program_headers,
            loadable_segments: counts.loadable,
        })
    }

    /// The `LinuxProgramImageV1::image_format` field, measured out of
    /// `e_machine`.
    pub(crate) const fn image_format(&self) -> LinuxElfImageFormatV1 {
        self.format
    }

    /// The `LinuxProgramImageV1::linkage` field, measured out of the program
    /// header table.
    pub(crate) const fn linkage(&self) -> &LinuxTargetLinkageV1 {
        &self.linkage
    }

    /// The authenticated length the program header table was required to lie
    /// inside.
    pub(crate) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// How many program headers were walked to reach the linkage above.
    ///
    /// It is retained because it is the difference between a measurement and an
    /// assumption: a linkage derived from zero walked headers would be neither.
    pub(crate) const fn program_header_count(&self) -> usize {
        self.program_headers
    }

    /// How many of those headers were `PT_LOAD`.
    pub(crate) const fn loadable_segment_count(&self) -> usize {
        self.loadable_segments
    }
}

impl LinuxProgramImageV1 {
    /// The production source for the `target` slot of
    /// [`LinuxBinaryIdentitiesV1`].
    ///
    /// `requested_program` must be the exact program the command effect
    /// authority asked for — `validate_binaries` requires equality with it and
    /// does not accept a resolution alongside it. `executable` must be the
    /// authenticated readback of the descriptor `measured` was measured
    /// through; the two are required to agree about length here, so a plan
    /// cannot pair one image's digest with another image's program headers.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the requested
    /// program is empty or past [`MAX_PATH_BYTES`], or when the authenticated
    /// readback and the measured image disagree about byte length.
    pub(crate) fn from_measured_image(
        requested_program: &str,
        executable: LinuxAuthenticatedFileV1,
        measured: &LinuxMeasuredTargetImageV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        if requested_program.is_empty() || requested_program.len() > MAX_PATH_BYTES {
            return Err(invalid("requested program is outside Linux plan bounds"));
        }
        if executable.byte_length() != measured.byte_length() {
            return Err(invalid(format!(
                "the target's authenticated readback is {} bytes and its measured image is {} bytes",
                executable.byte_length(),
                measured.byte_length()
            )));
        }
        Ok(Self {
            requested_program: requested_program.to_owned(),
            executable,
            image_format: measured.image_format(),
            linkage: measured.linkage().clone(),
        })
    }
}

/// The file extent of one image's program header table, proved to lie inside
/// the authenticated bytes before any of it is read.
///
/// The bound is taken *before* the read rather than discovered by a short read,
/// so a table declared past the end of an authenticated image is refused by
/// name instead of by whatever the descriptor happened to answer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxProgramHeaderTableExtentV1 {
    offset: u64,
    count: usize,
    entry_size: usize,
    table_length: usize,
}

/// The three `p_type` counts a target's linkage turns on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxProgramHeaderSegmentCountsV1 {
    loadable: usize,
    interpreters: usize,
    dynamic: usize,
}

impl LinuxProgramHeaderTableExtentV1 {
    /// Takes `e_phentsize`, `e_phnum` and `e_phoff` out of an ELF64 header and
    /// bounds them.
    fn read(
        header: &[u8; ELF64_HEADER_BYTES],
        authenticated_byte_length: u64,
        subject: &str,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let entry_size = read_le_u16(header, ELF64_PROGRAM_HEADER_ENTRY_SIZE_OFFSET)
            .ok_or_else(|| unreachable_elf_field(subject, "e_phentsize"))?;
        if entry_size != ELF64_PROGRAM_HEADER_ENTRY_BYTES {
            return Err(invalid(format!(
                "{subject} program header stride is {entry_size} bytes; an ELF64 table this walk can index is {ELF64_PROGRAM_HEADER_ENTRY_BYTES}"
            )));
        }
        let count = read_le_u16(header, ELF64_PROGRAM_HEADER_COUNT_OFFSET)
            .ok_or_else(|| unreachable_elf_field(subject, "e_phnum"))?;
        if count == 0 {
            return Err(invalid(format!(
                "{subject} carries no program headers, so the absence of PT_INTERP and PT_DYNAMIC is not evidence that it is statically linked"
            )));
        }
        if count == ELF_PROGRAM_HEADER_COUNT_ESCAPE {
            return Err(invalid(format!(
                "{subject} defers its program header count to the section header table (PN_XNUM), which this walk does not read"
            )));
        }
        if count > MAX_LINUX_TARGET_PROGRAM_HEADERS {
            return Err(invalid(format!(
                "{subject} declares {count} program headers, past this plan's bound of {MAX_LINUX_TARGET_PROGRAM_HEADERS}"
            )));
        }
        let offset = read_le_u64(header, ELF64_PROGRAM_HEADER_TABLE_OFFSET)
            .ok_or_else(|| unreachable_elf_field(subject, "e_phoff"))?;
        if offset < ELF64_HEADER_BYTE_COUNT {
            return Err(invalid(format!(
                "{subject} places its program header table at offset {offset}, inside its own ELF64 header"
            )));
        }
        let table_bytes = u64::from(count) * u64::from(entry_size);
        let end = offset.checked_add(table_bytes).ok_or_else(|| {
            invalid(format!(
                "{subject} program header table end overflows past offset {offset}"
            ))
        })?;
        if end > authenticated_byte_length {
            return Err(invalid(format!(
                "{subject} program header table spans bytes {offset}..{end} of an authenticated {authenticated_byte_length}-byte image"
            )));
        }
        let table_length = usize::try_from(table_bytes).map_err(|_| {
            invalid(format!(
                "{subject} program header table of {table_bytes} bytes cannot be represented on this host"
            ))
        })?;
        Ok(Self {
            offset,
            count: usize::from(count),
            entry_size: usize::from(entry_size),
            table_length,
        })
    }

    /// Counts the segment kinds in a complete readback of this extent.
    fn walk(
        &self,
        table: &[u8],
        subject: &str,
    ) -> Result<LinuxProgramHeaderSegmentCountsV1, LinuxProductionCommandPlanError> {
        let mut counts = LinuxProgramHeaderSegmentCountsV1 {
            loadable: 0,
            interpreters: 0,
            dynamic: 0,
        };
        for index in 0..self.count {
            let start = index * self.entry_size;
            // A `p_type` this walk cannot reach is a refusal, never a header
            // that "was not PT_INTERP".
            let segment_type = read_le_u32(table, start)
                .ok_or_else(|| unreachable_elf_field(subject, "program header p_type"))?;
            match segment_type {
                ELF_SEGMENT_LOADABLE => counts.loadable += 1,
                ELF_SEGMENT_DYNAMIC => counts.dynamic += 1,
                ELF_SEGMENT_INTERPRETER => counts.interpreters += 1,
                _ => {}
            }
        }
        Ok(counts)
    }
}

/// Reads one little-endian `u16` out of an ELF structure, or reports that the
/// buffer does not reach it.
///
/// It returns `None` rather than zero deliberately. A helper that defaulted a
/// short read to zero would report `PT_NULL` for a header it could not reach,
/// and `PT_NULL` is neither `PT_INTERP` nor `PT_DYNAMIC` — a truncated table
/// would then measure as statically linked. Every caller turns `None` into a
/// refusal.
fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let window = <[u8; 2]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u16::from_le_bytes(window))
}

/// Reads one little-endian `u32` out of an ELF structure. See [`read_le_u16`].
fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let window = <[u8; 4]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u32::from_le_bytes(window))
}

/// Reads one little-endian `u64` out of an ELF structure. See [`read_le_u16`].
fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let window = <[u8; 8]>::try_from(bytes.get(offset..end)?).ok()?;
    Some(u64::from_le_bytes(window))
}

/// Refusal for a field the ELF structure in hand does not reach.
fn unreachable_elf_field(subject: &str, field: &str) -> LinuxProductionCommandPlanError {
    invalid(format!(
        "{subject} does not reach its ELF {field} field, so nothing about its linkage can be measured"
    ))
}

impl LinuxMachineArchitectureV1 {
    /// The architecture this binary was compiled for, when the schema can
    /// describe it.
    ///
    /// This is a compile-time fact about the running image, not a kernel read:
    /// [`LinuxHostMachineArchitectureFactV1`] is what measures a host. It
    /// exists so a caller that is measuring an executable built *for this
    /// build's own target* has something to compare against without a syscall.
    pub(crate) fn compiled_target() -> Option<Self> {
        Self::from_kernel_machine(std::env::consts::ARCH)
    }
}

// Validate kernel observations of per-command directories without I/O, so
// the same checks run on hosts without Linux.

/// Plan-internal role name for the workspace root the grant retained.
pub(crate) const WORKSPACE_ROOT_OBJECT_ID: &str = "workspace-root";

/// Plan-internal role name for the per-command retained root.
///
/// It is the private parent of the other three per-command directories and of
/// the `.git` mask, and it is the only one of the five that is not itself
/// mounted anywhere.
pub(crate) const PER_COMMAND_RETAINED_ROOT_OBJECT_ID: &str = "per-command-root";

/// Plan-internal role name for the service-created execution root.
pub(crate) const EXECUTION_ROOT_OBJECT_ID: &str = "execution-root";

/// Plan-internal role name for the command's private temporary directory.
pub(crate) const PRIVATE_TEMP_OBJECT_ID: &str = "private-temp";

/// Plan-internal role name for the command's output spool.
pub(crate) const OUTPUT_SPOOL_OBJECT_ID: &str = "output-spool";

/// Plan-internal role name for the empty directory that masks `.git`.
///
/// One directory serves every project view: `validate_git_masks` requires one
/// mask per view but does not require the replacements to be distinct, and a
/// second empty directory would carry a second identity to keep honest for no
/// gain.
pub(crate) const GIT_MASK_OBJECT_ID: &str = "git-mask";

/// The exact mode every per-command private directory is required to carry.
///
/// This is a compiled constant compared against a kernel answer, never written
/// into an observation. A directory that a failed `fchmod` left at some other
/// mode is refused rather than described.
pub(crate) const LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE: u32 = 0o700;

/// The exact mode the `.git` mask is required to carry.
///
/// `0o500` rather than `0o700`: the mask must stay empty, and an owner that
/// cannot write to it cannot fill it by accident. This is a barrier, not a
/// proof — the owner may `fchmod` it back — and the record says so. What proves
/// emptiness is the observation below.
pub(crate) const LINUX_GIT_MASK_DIRECTORY_MODE: u32 = 0o500;

/// Hard bound on the entries one `.git`-mask enumeration may carry.
///
/// Reaching the bound is a **refusal**, not a truncation, for the reason
/// `MAX_LINUX_TARGET_PROGRAM_HEADERS` refuses: a partial enumeration cannot
/// demonstrate the absence of anything.
pub(crate) const MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES: usize = 64;

/// Hard bound on the encoded observation.
const MAX_LINUX_GIT_MASK_OBSERVATION_BYTES: u64 = 65_536;

/// Format revision of the observation below line 0.
const LINUX_GIT_MASK_OBSERVATION_FORMAT_V1: u32 = 1;

/// The link count a directory with no subdirectories has: itself and `.`.
///
/// The kernel's own count cross-checks emptiness without trusting the
/// enumeration loop, which is why it is required rather than reported.
const EMPTY_DIRECTORY_LINK_COUNT: u64 = 2;

/// The link count the per-command root has once its four children exist.
const PER_COMMAND_ROOT_LINK_COUNT: u64 = 6;

/// The complete wire contract for one `.git`-mask empty-directory observation.
///
/// `LinuxGitMaskV1::expected_empty_observation_digest` had no producer because
/// **nothing in the repository defined what a complete empty-directory
/// observation was**, so there was no artefact to be a digest of. This is that
/// artefact's contract, and it follows
/// [`LINUX_SETUP_CHANNEL_PROTOCOL_DESCRIPTOR_V1`] exactly: one ASCII line,
/// line-feed-terminated lines, line 0 the descriptor verbatim, so a validator
/// holding only this text can re-derive the digest from the object it was
/// handed.
///
/// The digest binds **identity and emptiness together**. Emptiness alone would
/// make the field a constant, and a constant in a `Digest` field is precisely
/// the fabricated-digest shape schema v3 removed; the object line is what makes
/// it a measurement of one particular directory.
///
/// **What it deliberately does not carry.** No descriptor, no pathname, no
/// mount destination and no release permit. It states what one held descriptor
/// answered, and grants nothing.
pub(crate) const LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1: &str = "grok-build.linux-git-mask-empty-observation.v1\
    ;framing=lf-terminated-ascii-lines\
    ;line-0=this-descriptor\
    ;lines=descriptor,format,object,filesystem-magic,entry-count,entry*,end\
    ;object=<plan-object-id>:<kind>:<device>:<inode>:<mount>:<mode-octal>:<uid>:<gid>:<link-count>\
    ;entry=<name>;entries=sorted-unique-printable-ascii-excluding-dot-and-dotdot\
    ;reads=openat-O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOFOLLOW,statx-STATX_MNT_ID_UNIQUE,fstatfs,complete-getdents64,statx-again-required-equal\
    ;identity-source=held-descriptor-live-kernel-reads\
    ;empty-requires=zero-entries-and-link-count-2\
    ;max-entries=64;max-bytes=65536\
    ;no-descriptors;no-paths;no-argv;no-environment;no-credentials;no-release-authority";

/// The digest of [`LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1`].
///
/// The same shape as [`linux_setup_channel_protocol_digest`]: one function over
/// one compiled descriptor, so two peers built from this source agree without
/// exchanging anything.
pub(crate) fn linux_git_mask_empty_observation_protocol_digest() -> Digest {
    Digest::sha256(LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1.as_bytes())
}

/// Encodes the nine-field object line both wire contracts in this module use.
///
/// There is one spelling of this line in the workspace on purpose. A second
/// copy could drift from the first, and two encoders that disagree about what
/// an identity looks like would let a digest taken under one be compared under
/// the other.
fn encode_retained_object_line(object: &LinuxRetainedObjectIdentityV1) -> String {
    format!(
        "{}:{}:{}:{}:{}:{:o}:{}:{}:{}",
        object.object_id,
        setup_channel_kind_name(object.kind),
        object.device_id,
        object.inode,
        object.mount_id,
        object.mode,
        object.owner_uid,
        object.owner_gid,
        object.link_count,
    )
}

/// Exactly what a complete read of one candidate `.git` mask answered.
///
/// Every field is a kernel answer about a descriptor the observer already
/// holds: `statx` for the object, `fstatfs` for the magic, and a complete
/// `getdents64` loop for the names. Nothing here may be chosen, and there is
/// deliberately no "assume empty on read error" arm anywhere — an errored or
/// short enumeration never reaches this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxGitMaskEmptyDirectoryObservationV1 {
    pub(crate) object: LinuxKernelObjectObservationV1,
    pub(crate) filesystem_magic: u64,
    pub(crate) entry_names: Vec<String>,
}

impl LinuxGitMaskEmptyDirectoryObservationV1 {
    /// Encodes the exact bytes this observation's digest is taken over.
    ///
    /// This is the *only* producer of `.git`-mask observation content, for the
    /// reason `LinuxSetupChannelStatementV1::encode` is the only producer of
    /// setup-channel content: one source of truth cannot drift from a written
    /// copy of itself. The encoding is total and deterministic — no map
    /// iteration order, no clock, no locale — which is what makes independent
    /// re-derivation possible at all.
    ///
    /// The identity is not a parameter the caller may vary freely: `retained`
    /// must be the identity minted from *this* observation, so a digest cannot
    /// be paired with a different object.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when `retained` is
    /// not a directory identity minted from `object`, when the filesystem magic
    /// is zero, when the enumeration reaches its hard bound, when a name is
    /// unsorted, duplicated, `.`, `..`, empty, oversized or not printable
    /// ASCII, or when the encoding exceeds
    /// [`MAX_LINUX_GIT_MASK_OBSERVATION_BYTES`].
    pub(crate) fn encode(
        &self,
        retained: &LinuxRetainedObjectIdentityV1,
    ) -> Result<Vec<u8>, LinuxProductionCommandPlanError> {
        retained.validate()?;
        if retained.kind != LinuxRetainedObjectKindV1::Directory {
            return Err(invalid(
                "a .git mask observation describes a plain retained directory and nothing else",
            ));
        }
        if retained.kernel_observation() != self.object {
            return Err(invalid(
                "the .git mask observation describes a different kernel object than the identity it is encoded with",
            ));
        }
        if self.filesystem_magic == 0 {
            return Err(invalid(
                "the .git mask observation carries no filesystem magic",
            ));
        }
        if self.entry_names.len() >= MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES {
            return Err(invalid(format!(
                "the .git mask enumeration reached its hard bound of {MAX_LINUX_GIT_MASK_OBSERVATION_ENTRIES} entries; a bounded walk cannot demonstrate absence"
            )));
        }
        for pair in self.entry_names.windows(2) {
            if pair[0] >= pair[1] {
                return Err(invalid(
                    "the .git mask enumeration is unsorted or carries a duplicate name",
                ));
            }
        }
        let mut lines = Vec::with_capacity(6 + self.entry_names.len());
        lines.push(LINUX_GIT_MASK_EMPTY_OBSERVATION_DESCRIPTOR_V1.to_owned());
        lines.push(format!("format={LINUX_GIT_MASK_OBSERVATION_FORMAT_V1}"));
        lines.push(encode_retained_object_line(retained));
        lines.push(format!("filesystem-magic=0x{:08x}", self.filesystem_magic));
        lines.push(format!("entry-count={}", self.entry_names.len()));
        for name in &self.entry_names {
            // The names are in the digest, not only the count: a directory
            // holding one entry named `HEAD` and one holding `config` must not
            // digest alike.
            if name.is_empty()
                || name.len() > MAX_ID_BYTES
                || name == "."
                || name == ".."
                || name.contains('/')
                || !name.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(invalid(
                    "a .git mask entry name is empty, oversized, or not a printable ASCII component",
                ));
            }
            lines.push(format!("entry={name}"));
        }
        lines.push("end".to_owned());

        let mut encoded = lines.join("\n");
        encoded.push('\n');
        let bytes = encoded.into_bytes();
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| invalid("the .git mask observation length cannot be represented"))?;
        if byte_length == 0 || byte_length > MAX_LINUX_GIT_MASK_OBSERVATION_BYTES {
            return Err(invalid(
                "the .git mask observation is empty or exceeds its hard bound",
            ));
        }
        Ok(bytes)
    }

    /// The digest of [`Self::encode`].
    ///
    /// # Errors
    ///
    /// Propagates every refusal [`Self::encode`] makes.
    pub(crate) fn digest(
        &self,
        retained: &LinuxRetainedObjectIdentityV1,
    ) -> Result<Digest, LinuxProductionCommandPlanError> {
        Ok(Digest::sha256(&self.encode(retained)?))
    }

    /// Requires this observation to be of a directory that really is empty.
    ///
    /// The enumeration and the kernel's own link count are two independent
    /// answers to the same question, and both must say empty. `link_count != 2`
    /// refuses on its own: a directory with no subdirectories has exactly two
    /// links, so the count cross-checks the walk without trusting it.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the
    /// enumeration is non-empty, when the link count is not
    /// [`EMPTY_DIRECTORY_LINK_COUNT`], when the object carries a byte length, or
    /// when the mode carries a set-id, group-write or other-write bit.
    pub(crate) fn require_empty(&self) -> Result<(), LinuxProductionCommandPlanError> {
        if !self.entry_names.is_empty() {
            return Err(invalid(format!(
                "the .git mask replacement holds {} entries and is not empty",
                self.entry_names.len()
            )));
        }
        if self.object.link_count != EMPTY_DIRECTORY_LINK_COUNT {
            return Err(invalid(format!(
                "the .git mask replacement has link count {}; an empty directory has exactly {EMPTY_DIRECTORY_LINK_COUNT}",
                self.object.link_count
            )));
        }
        if self.object.byte_length.is_some() {
            return Err(invalid(
                "the .git mask replacement carries a byte length, so it is not a directory observation",
            ));
        }
        if self.object.mode & SET_ID_MODE != 0 {
            return Err(invalid(
                "the .git mask replacement must not be setuid or setgid",
            ));
        }
        if self.object.mode & 0o022 != 0 {
            return Err(invalid(
                "the .git mask replacement is group-writable or world-writable",
            ));
        }
        Ok(())
    }
}

impl LinuxGitMaskV1 {
    /// The production source for `expected_empty_observation_digest`.
    ///
    /// The digest is taken over the encoding of an observation the caller read
    /// out of a held descriptor, and the identity that observation describes is
    /// bound into the same bytes. That is what stops the field being a
    /// constant: two commands' masks are two different inodes and therefore two
    /// different digests, and the same directory with one entry in it digests
    /// differently again — and is refused before it can.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the workspace
    /// destination is not a bounded normalized absolute path or already enters
    /// `.git`, when the replacement is not a retained directory identity minted
    /// from `observation`, when the directory is not demonstrably empty, or
    /// when the observation cannot be encoded.
    pub(crate) fn from_empty_directory_observation(
        workspace_destination: &str,
        empty_directory: &LinuxRetainedObjectIdentityV1,
        observation: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        validate_absolute_path(workspace_destination, ".git mask workspace")?;
        if contains_git_component(workspace_destination) {
            return Err(invalid(
                "a .git mask workspace destination must not already enter .git",
            ));
        }
        let masked_destination = format!("{}/.git", workspace_destination.trim_end_matches('/'));
        validate_absolute_path(&masked_destination, ".git mask destination")?;
        observation.require_empty()?;
        let mask = Self {
            workspace_destination: workspace_destination.to_owned(),
            masked_destination,
            empty_directory_object_id: empty_directory.object_id.clone(),
            expected_empty_observation_digest: observation.digest(empty_directory)?,
        };
        validate_nonzero_digest(
            &mask.expected_empty_observation_digest,
            ".git empty observation",
        )?;
        Ok(mask)
    }

    /// The digest this mask committed over its replacement's observation.
    pub(crate) const fn expected_empty_observation_digest(&self) -> &Digest {
        &self.expected_empty_observation_digest
    }

    /// The project view this mask covers.
    pub(crate) fn workspace_destination(&self) -> &str {
        &self.workspace_destination
    }

    /// The namespace path `.git` is replaced at.
    pub(crate) fn masked_destination(&self) -> &str {
        &self.masked_destination
    }

    /// The retained empty directory that replaces `.git`.
    pub(crate) fn empty_directory_object_id(&self) -> &str {
        &self.empty_directory_object_id
    }

    /// Requires a **second**, independently taken observation to reproduce the
    /// digest this mask already committed.
    ///
    /// This is where the field stops being an assignment. The caller reads the
    /// same held descriptor again after the mask exists; a directory that
    /// gained an entry, changed mode, was replaced, or crossed a mount between
    /// the two reads produces different bytes and is refused rather than
    /// described.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the identity
    /// is not the one this mask names, when the second observation is not of an
    /// empty directory, or when the re-derived digest differs.
    pub(crate) fn require_empty_directory_observation(
        &self,
        empty_directory: &LinuxRetainedObjectIdentityV1,
        observation: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        if self.empty_directory_object_id != empty_directory.object_id {
            return Err(invalid(format!(
                "the .git mask names replacement {} and was re-observed through {}",
                self.empty_directory_object_id, empty_directory.object_id
            )));
        }
        observation.require_empty()?;
        let derived = observation.digest(empty_directory)?;
        if derived != self.expected_empty_observation_digest {
            return Err(invalid(format!(
                "the .git mask committed observation {} and the directory now observes as {derived}",
                self.expected_empty_observation_digest
            )));
        }
        Ok(())
    }
}

/// Kernel answers about the six directories one command retains.
///
/// The workspace root is the grant's own; the other five are created by the
/// service for this command and nothing else. Every field is what a `statx`
/// and, for the mask, a complete `getdents64` answered about a descriptor the
/// caller holds open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxPerCommandDirectoryObservationsV1 {
    pub(crate) workspace_root: LinuxKernelObjectObservationV1,
    pub(crate) per_command_root: LinuxKernelObjectObservationV1,
    pub(crate) execution_root: LinuxKernelObjectObservationV1,
    pub(crate) private_temp: LinuxKernelObjectObservationV1,
    pub(crate) output_spool: LinuxKernelObjectObservationV1,
    pub(crate) git_mask: LinuxGitMaskEmptyDirectoryObservationV1,
}

/// Validates retained command identities absent from the installer anchor: the
/// granted workspace root and five command-lifetime objects. Performs no I/O so
/// identity crossing and collapse checks remain portable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxPerCommandRetainedDirectoriesV1 {
    workspace_root: LinuxRetainedObjectIdentityV1,
    per_command_root: LinuxRetainedObjectIdentityV1,
    execution_root: LinuxRetainedObjectIdentityV1,
    private_temp: LinuxRetainedObjectIdentityV1,
    output_spool: LinuxRetainedObjectIdentityV1,
    git_mask: LinuxRetainedObjectIdentityV1,
    git_mask_observation: LinuxGitMaskEmptyDirectoryObservationV1,
}

impl LinuxPerCommandRetainedDirectoriesV1 {
    /// Mints the six retained identities from live kernel observations.
    ///
    /// Every requirement below is a **comparison** between a kernel answer and
    /// either a compiled constant or another kernel answer. Nothing is
    /// assigned:
    ///
    /// - each identity passes the same `validate` a decoded plan's object table
    ///   applies, through [`LinuxRetainedObjectIdentityV1::from_kernel_observation`];
    /// - the four private directories carry exactly
    ///   [`LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE`] and the mask exactly
    ///   [`LINUX_GIT_MASK_DIRECTORY_MODE`], so a mode a failed `fchmod` left
    ///   behind is a refusal;
    /// - every one of the six is owned by `owner_uid`, the identity the
    ///   installer anchor committed the service to;
    /// - the five service-created directories share the per-command root's
    ///   device **and unique mount identity**, so something mounted over one of
    ///   them between creation and observation is a refusal;
    /// - the per-command root's link count is exactly
    ///   [`PER_COMMAND_ROOT_LINK_COUNT`] and the three empty children's is
    ///   exactly [`EMPTY_DIRECTORY_LINK_COUNT`], so the kernel's own count
    ///   states that the root holds these four subdirectories and no others and
    ///   that the children hold none;
    /// - no two of the six collapse onto one device and inode.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] on any of the
    /// above, and on every refusal
    /// [`LinuxGitMaskEmptyDirectoryObservationV1::require_empty`] makes.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear audit keeps every per-command role, its kernel answer, and the constant it is compared against visible in the order they are checked"
    )]
    pub(crate) fn from_kernel_observations(
        observations: &LinuxPerCommandDirectoryObservationsV1,
        owner_uid: u32,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        let workspace_root = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            WORKSPACE_ROOT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.workspace_root,
        )?;
        let per_command_root = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            PER_COMMAND_RETAINED_ROOT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.per_command_root,
        )?;
        let execution_root = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            EXECUTION_ROOT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.execution_root,
        )?;
        let private_temp = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            PRIVATE_TEMP_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.private_temp,
        )?;
        let output_spool = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            OUTPUT_SPOOL_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.output_spool,
        )?;
        let git_mask = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            observations.git_mask.object,
        )?;

        // The workspace root is the grant's, not the service's creation, so it
        // is held to ownership and non-writability rather than to an exact
        // private mode: real project trees are commonly 0755.
        if observations.workspace_root.owner_uid != owner_uid {
            return Err(invalid(format!(
                "the retained workspace root is owned by uid {} rather than the anchored service uid {owner_uid}",
                observations.workspace_root.owner_uid
            )));
        }
        if observations.workspace_root.mode & 0o022 != 0 {
            return Err(invalid(
                "the retained workspace root is group-writable or world-writable",
            ));
        }
        if observations.workspace_root.mode & SET_ID_MODE != 0 {
            return Err(invalid("the retained workspace root is setuid or setgid"));
        }

        let private = [
            (
                PER_COMMAND_RETAINED_ROOT_OBJECT_ID,
                &observations.per_command_root,
                PER_COMMAND_ROOT_LINK_COUNT,
            ),
            (
                EXECUTION_ROOT_OBJECT_ID,
                &observations.execution_root,
                EMPTY_DIRECTORY_LINK_COUNT,
            ),
            (
                PRIVATE_TEMP_OBJECT_ID,
                &observations.private_temp,
                EMPTY_DIRECTORY_LINK_COUNT,
            ),
            (
                OUTPUT_SPOOL_OBJECT_ID,
                &observations.output_spool,
                EMPTY_DIRECTORY_LINK_COUNT,
            ),
        ];
        for (role, observed, expected_links) in private {
            if observed.mode & 0o7777 != LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE {
                return Err(invalid(format!(
                    "per-command directory {role} carries mode {:o}; the plan requires exactly {LINUX_PER_COMMAND_PRIVATE_DIRECTORY_MODE:o}",
                    observed.mode & 0o7777
                )));
            }
            if observed.owner_uid != owner_uid {
                return Err(invalid(format!(
                    "per-command directory {role} is owned by uid {} rather than the anchored service uid {owner_uid}",
                    observed.owner_uid
                )));
            }
            if observed.link_count != expected_links {
                return Err(invalid(format!(
                    "per-command directory {role} has link count {}; the plan requires exactly {expected_links}",
                    observed.link_count
                )));
            }
        }

        if observations.git_mask.object.mode & 0o7777 != LINUX_GIT_MASK_DIRECTORY_MODE {
            return Err(invalid(format!(
                "the .git mask carries mode {:o}; the plan requires exactly {LINUX_GIT_MASK_DIRECTORY_MODE:o}",
                observations.git_mask.object.mode & 0o7777
            )));
        }
        if observations.git_mask.object.owner_uid != owner_uid {
            return Err(invalid(
                "the .git mask is not owned by the anchored service uid",
            ));
        }
        observations.git_mask.require_empty()?;

        // Everything the service created for this command must still be on the
        // filesystem and the mount its private root is on. A child that answers
        // with a different device or unique mount identity had something
        // mounted over it, and a plan that named it would name whatever is on
        // top.
        let root = &observations.per_command_root;
        for (role, observed) in [
            (EXECUTION_ROOT_OBJECT_ID, &observations.execution_root),
            (PRIVATE_TEMP_OBJECT_ID, &observations.private_temp),
            (OUTPUT_SPOOL_OBJECT_ID, &observations.output_spool),
            (GIT_MASK_OBJECT_ID, &observations.git_mask.object),
        ] {
            if observed.device_id != root.device_id || observed.mount_id != root.mount_id {
                return Err(invalid(format!(
                    "per-command directory {role} is not on the per-command root's device and mount"
                )));
            }
        }

        let mut seen = BTreeMap::new();
        for identity in [
            &workspace_root,
            &per_command_root,
            &execution_root,
            &private_temp,
            &output_spool,
            &git_mask,
        ] {
            if let Some(existing) = seen.insert(
                (identity.device_id, identity.inode),
                identity.object_id.as_str(),
            ) {
                return Err(invalid(format!(
                    "retained roles {existing} and {} resolved to one kernel inode",
                    identity.object_id
                )));
            }
        }

        Ok(Self {
            workspace_root,
            per_command_root,
            execution_root,
            private_temp,
            output_spool,
            git_mask,
            git_mask_observation: observations.git_mask.clone(),
        })
    }

    /// The `LinuxRetainedCapabilitySetV1::workspace_root_object_id` identity.
    pub(crate) const fn workspace_root(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.workspace_root
    }

    /// The private parent of the four per-command directories.
    pub(crate) const fn per_command_root(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.per_command_root
    }

    /// The service-created execution root, used by the shadow and snapshot
    /// views.
    pub(crate) const fn execution_root(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.execution_root
    }

    /// The `LinuxMountPurposeV1::PrivateTemp` source.
    pub(crate) const fn private_temp(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.private_temp
    }

    /// The `LinuxMountPurposeV1::OutputSpool` source.
    pub(crate) const fn output_spool(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.output_spool
    }

    /// The empty directory every `.git` mask replaces `.git` with.
    pub(crate) const fn git_mask(&self) -> &LinuxRetainedObjectIdentityV1 {
        &self.git_mask
    }

    /// The observation the mask digests were taken over.
    pub(crate) const fn git_mask_observation(&self) -> &LinuxGitMaskEmptyDirectoryObservationV1 {
        &self.git_mask_observation
    }

    /// The identity `LinuxRoleSnapshotBindingV1::execution_root_object_id` must
    /// name for `view`.
    ///
    /// A read-only worker executes in the live workspace itself, which
    /// `validate_mounts` enforces by requiring the execution mount's source to
    /// be the retained grant root. The shadow and snapshot views execute in the
    /// directory the service created. Returning the wrong one here would be
    /// caught by `validate_mounts`, but it is stated once, here, rather than
    /// left for each caller to rediscover.
    pub(crate) const fn execution_root_for(
        &self,
        view: LinuxExecutionViewV1,
    ) -> &LinuxRetainedObjectIdentityV1 {
        match view {
            LinuxExecutionViewV1::WorkerReadOnly => &self.workspace_root,
            LinuxExecutionViewV1::WorkerShadow | LinuxExecutionViewV1::FinalVerifierSnapshot => {
                &self.execution_root
            }
        }
    }

    /// The complete object-table contribution of one command's retained
    /// directories, sorted by role name so the encoding is deterministic.
    pub(crate) fn retained_objects(&self) -> Vec<LinuxRetainedObjectIdentityV1> {
        let mut objects = vec![
            self.workspace_root.clone(),
            self.per_command_root.clone(),
            self.execution_root.clone(),
            self.private_temp.clone(),
            self.output_spool.clone(),
            self.git_mask.clone(),
        ];
        objects.sort_by(|left, right| left.object_id.cmp(&right.object_id));
        objects
    }

    /// Builds one `.git` mask per project view, all replacing `.git` with the
    /// single observed empty directory.
    ///
    /// The masks are sorted the way `validate_mounts` requires, and the set is
    /// required to be non-empty: a mount plan with a project view and no mask
    /// is exactly what `validate_git_masks` refuses, and producing one here
    /// would only move the refusal later.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the set of
    /// destinations is empty or exceeds [`MAX_MOUNTS`], and on every refusal
    /// [`LinuxGitMaskV1::from_empty_directory_observation`] makes.
    pub(crate) fn git_masks_for(
        &self,
        project_destinations: &BTreeSet<&str>,
    ) -> Result<Vec<LinuxGitMaskV1>, LinuxProductionCommandPlanError> {
        if project_destinations.is_empty() || project_destinations.len() > MAX_MOUNTS {
            return Err(invalid(
                "a .git mask set requires at least one and at most MAX_MOUNTS project views",
            ));
        }
        let mut masks = project_destinations
            .iter()
            .map(|destination| {
                LinuxGitMaskV1::from_empty_directory_observation(
                    destination,
                    &self.git_mask,
                    &self.git_mask_observation,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        masks.sort_by(|left, right| {
            (&left.workspace_destination, &left.masked_destination)
                .cmp(&(&right.workspace_destination, &right.masked_destination))
        });
        Ok(masks)
    }

    /// Requires a second complete read of the same held mask descriptor to
    /// reproduce every mask this set produced.
    ///
    /// # Errors
    ///
    /// Propagates every refusal
    /// [`LinuxGitMaskV1::require_empty_directory_observation`] makes.
    pub(crate) fn require_masks_still_observe(
        &self,
        masks: &[LinuxGitMaskV1],
        observation: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        if masks.is_empty() {
            return Err(invalid(
                "a re-observation with no masks proves nothing about the .git replacement",
            ));
        }
        for mask in masks {
            mask.require_empty_directory_observation(&self.git_mask, observation)?;
        }
        Ok(())
    }
}

// Bind the performed mount in three steps: rederive the mask digest from
// the observed empty directory; require the detached clone to retain its
// directory identity and metadata with a different unique mount ID; require
// the destination to reproduce that detached mount's digest. These checks
// perform no I/O.

/// Plan-internal role name for the **mount** cloned from the `.git` mask.
///
/// It is deliberately not [`GIT_MASK_OBJECT_ID`]. The role name is inside the
/// object line every observation encodes, so the directory-role digest and the
/// mount-role digest are domain-separated by construction: a directory
/// observation can never be replayed as a mount observation, and a mount
/// observation can never satisfy `LinuxGitMaskV1`'s committed digest.
pub(crate) const GIT_MASK_MOUNT_OBJECT_ID: &str = "git-mask-mount";

/// The single directory name a `.git` mask may ever be attached at.
///
/// `validate_git_masks` already requires every `masked_destination` to be
/// exactly `{workspace_destination}/.git`; this is the same fact as one
/// component, so the attach call names one directory entry relative to a held
/// parent descriptor rather than resolving a path.
pub(crate) const GIT_MASK_DESTINATION_COMPONENT: &str = ".git";

/// One performed `.git` mask mount, bound to the directory that was observed.
///
/// The type carries no descriptor and grants nothing. It carries the two
/// digests and the two unique mount identities that make the binding
/// checkable, so a caller that later finds *something* at the destination can
/// ask whether it is *this* mount rather than whether it looks empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxGitMaskMountBindingV1 {
    masked_destination: String,
    directory_observation_digest: Digest,
    mount_observation_digest: Digest,
    source_mount_id: u64,
    detached_mount_id: u64,
}

impl LinuxGitMaskMountBindingV1 {
    /// Binds the mount `open_tree` cloned to the directory the mask digested.
    ///
    /// `directory_observation` is the read the mask's digest was taken over;
    /// `mount_observation` is a read taken **through the descriptor
    /// `open_tree` returned**, so it describes the root of the new mount and
    /// nothing else.
    ///
    /// The order is measure, then compare. The committed digest is re-derived
    /// rather than trusted, the clone's identity is required to equal the
    /// directory's field by field, and the mount identity is required to
    /// *differ* — a caller that handed the same observation twice, having
    /// performed no mount at all, is refused here rather than believed.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the mask does
    /// not name `directory`, when the committed digest cannot be re-derived
    /// from `directory_observation`, when either observation is not of a
    /// demonstrably empty directory, when the clone's device, inode, mode,
    /// owner, link count, filesystem magic or enumeration differs from the
    /// directory's, when either unique mount identity is zero, or when the two
    /// mount identities are equal.
    pub(crate) fn from_cloned_mount_observation(
        mask: &LinuxGitMaskV1,
        directory: &LinuxRetainedObjectIdentityV1,
        directory_observation: &LinuxGitMaskEmptyDirectoryObservationV1,
        mount_observation: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> Result<Self, LinuxProductionCommandPlanError> {
        // Link 1. Not "the caller says this is the mask's directory": the
        // committed digest has to come back out of the observation.
        mask.require_empty_directory_observation(directory, directory_observation)?;
        mount_observation.require_empty()?;

        let directory_object = &directory_observation.object;
        let mount_object = &mount_observation.object;
        if mount_object.device_id != directory_object.device_id {
            return Err(invalid(format!(
                "the cloned .git mask mount is on device {} and the observed directory is on device {}",
                mount_object.device_id, directory_object.device_id
            )));
        }
        if mount_object.inode != directory_object.inode {
            return Err(invalid(format!(
                "the cloned .git mask mount is rooted at inode {} and the observed directory is inode {}",
                mount_object.inode, directory_object.inode
            )));
        }
        if mount_object.mode != directory_object.mode {
            return Err(invalid(
                "the cloned .git mask mount carries a different mode than the observed directory",
            ));
        }
        // Two refusals rather than one disjunction: a single message for both
        // would let one arm's assertion be satisfied by the other's failure.
        if mount_object.owner_uid != directory_object.owner_uid {
            return Err(invalid(format!(
                "the cloned .git mask mount is owned by uid {} and the observed directory by uid {}",
                mount_object.owner_uid, directory_object.owner_uid
            )));
        }
        if mount_object.owner_gid != directory_object.owner_gid {
            return Err(invalid(format!(
                "the cloned .git mask mount is owned by gid {} and the observed directory by gid {}",
                mount_object.owner_gid, directory_object.owner_gid
            )));
        }
        if mount_object.link_count != directory_object.link_count {
            return Err(invalid(format!(
                "the cloned .git mask mount has link count {} and the observed directory has {}",
                mount_object.link_count, directory_object.link_count
            )));
        }
        if mount_observation.filesystem_magic != directory_observation.filesystem_magic {
            return Err(invalid(
                "the cloned .git mask mount is on a different filesystem than the observed directory",
            ));
        }
        if mount_observation.entry_names != directory_observation.entry_names {
            return Err(invalid(
                "the cloned .git mask mount enumerates different entries than the observed directory",
            ));
        }
        if directory_object.mount_id == 0 || mount_object.mount_id == 0 {
            return Err(invalid(
                "a .git mask mount binding requires a unique mount identity for both the directory and the clone",
            ));
        }
        // A clone is a new mount. Equality here is the signature of a caller
        // that performed no mount and handed back the directory's own read.
        if mount_object.mount_id == directory_object.mount_id {
            return Err(invalid(format!(
                "the cloned .git mask mount reports the observed directory's own mount identity {}, so nothing was cloned",
                directory_object.mount_id
            )));
        }

        let mount_identity = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_MOUNT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            *mount_object,
        )?;
        Ok(Self {
            masked_destination: mask.masked_destination().to_owned(),
            directory_observation_digest: mask.expected_empty_observation_digest().clone(),
            mount_observation_digest: mount_observation.digest(&mount_identity)?,
            source_mount_id: directory_object.mount_id,
            detached_mount_id: mount_object.mount_id,
        })
    }

    /// Requires the destination observation to identify this detached mount.
    ///
    /// Recompute the mount-role digest after `move_mount` and compare the unique mount
    /// ID explicitly. A second mount of the same directory has a different unique ID.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] for a nonempty directory,
    /// a different unique mount identity, or a mismatched mount-role digest.
    pub(crate) fn require_attached_mount(
        &self,
        attached: &LinuxGitMaskEmptyDirectoryObservationV1,
    ) -> Result<(), LinuxProductionCommandPlanError> {
        attached.require_empty()?;
        if attached.object.mount_id != self.detached_mount_id {
            return Err(invalid(format!(
                "the .git mask destination carries unique mount identity {} and this binding mounted {}",
                attached.object.mount_id, self.detached_mount_id
            )));
        }
        let attached_identity = LinuxRetainedObjectIdentityV1::from_kernel_observation(
            GIT_MASK_MOUNT_OBJECT_ID,
            LinuxRetainedObjectKindV1::Directory,
            attached.object,
        )?;
        let derived = attached.digest(&attached_identity)?;
        if derived != self.mount_observation_digest {
            return Err(invalid(format!(
                "the .git mask mount observed as {} when it was cloned and observes as {derived} at its destination",
                self.mount_observation_digest
            )));
        }
        Ok(())
    }

    /// The namespace path this mount replaces `.git` at.
    pub(crate) fn masked_destination(&self) -> &str {
        &self.masked_destination
    }

    /// The digest the mask committed over the directory as the service holds
    /// it.
    pub(crate) const fn directory_observation_digest(&self) -> &Digest {
        &self.directory_observation_digest
    }

    /// The digest taken over the detached mount's own observation.
    pub(crate) const fn mount_observation_digest(&self) -> &Digest {
        &self.mount_observation_digest
    }

    /// The unique mount identity the observed directory lives on.
    pub(crate) const fn source_mount_id(&self) -> u64 {
        self.source_mount_id
    }

    /// The unique mount identity `open_tree` minted for the clone.
    pub(crate) const fn detached_mount_id(&self) -> u64 {
        self.detached_mount_id
    }
}

// ---------------------------------------------------------------------------
// The production components mint
// ---------------------------------------------------------------------------

/// Stable plan-internal identifier for the command's target image.
///
/// The other four executable roles already have theirs
/// ([`BUBBLEWRAP_OBJECT_ID`], [`SERVICE_IMAGE_OBJECT_ID`],
/// [`SETUP_CHANNEL_OBJECT_ID`]); the target had none because nothing joined it
/// to an object table.
pub(crate) const TARGET_IMAGE_OBJECT_ID: &str = "target-image";

/// Workspace location inside the command's planned mount namespace.
///
/// Namespace layout paths are chosen names. Mount sources remain measured, held
/// objects; image destinations retain their authenticated resolved paths.
pub(crate) const LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT: &str = "/grok-build/live";

/// Where the role's execution root is visible, for the two views that execute
/// somewhere other than the live workspace.
///
/// `WorkerReadOnly` deliberately has no separate execution root: its execution
/// mount *is* the live workspace mount, which is what `validate_mounts`
/// requires when it crosses `role.execution_root_object_id` against
/// `retained.workspace_root_object_id`.
pub(crate) const LINUX_NAMESPACE_EXECUTION_ROOT: &str = "/grok-build/execution";

/// Where the command's private temporary directory is visible.
pub(crate) const LINUX_NAMESPACE_PRIVATE_TEMP: &str = "/tmp";

/// Where the command's output spool is visible.
pub(crate) const LINUX_NAMESPACE_OUTPUT_SPOOL: &str = "/grok-build/output";

/// The lowest Landlock ABI this build admits.
///
/// One, because ABI 1 is the first version in which Landlock exists at all: a
/// kernel answering 0 has no Landlock, and refusing it is a real requirement
/// with real teeth rather than a restatement.
pub(crate) const LINUX_LANDLOCK_MINIMUM_KERNEL_ABI: u32 = 1;

/// Highest Landlock ABI whose access rights this build models. Newer ABIs
/// refuse rather than silently leaving new rights unrestricted.
pub(crate) const LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI: u32 = MAX_LANDLOCK_ABI;

/// The installer-anchored service facts one production plan is minted against.
///
/// Every field is a live kernel read that was required to equal what the
/// installer externally committed — the anchored half of component 3, plus the
/// running service image, plus the measured host architecture. The type exists
/// so the mint can be *portable*: `LinuxProductionPlanAnchoredFactsV1` is
/// `cfg(target_os = "linux")` and lives in `linux_cgroup_io`, so a mint that
/// took it directly could not be proved on a host with no Linux kernel in front
/// of it. `LinuxProductionPlanAnchoredFactsV1::plan_anchored_facts` is the
/// one-method bridge, exactly as `setup_channel_statement` is for the channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxAnchoredServiceFactsV1<'facts> {
    pub(crate) service_state_root: &'facts LinuxRetainedObjectIdentityV1,
    pub(crate) singleton_journal_root: &'facts LinuxRetainedObjectIdentityV1,
    pub(crate) service_cgroup_parent: &'facts LinuxRetainedObjectIdentityV1,
    pub(crate) cgroup_delegation_root: &'facts LinuxRetainedObjectIdentityV1,
    /// `fstatfs` on the retained delegation descriptor, not a plan constant.
    pub(crate) cgroup_filesystem_magic: u64,
    /// The running service image, which is also the plan's inner launcher
    /// because the held launcher is a mode of this same executable.
    pub(crate) service_image: &'facts LinuxAuthenticatedFileV1,
    pub(crate) service_image_object: &'facts LinuxRetainedObjectIdentityV1,
    pub(crate) authenticated_platform_service_digest: &'facts Digest,
    /// Measured from the running image's ELF header **and** `uname(2)`, which
    /// were required to agree.
    pub(crate) host_architecture: LinuxMachineArchitectureV1,
}

/// Everything one production Linux command plan is joined from.
///
/// Each field is the output of a mint an earlier increment built, and every one
/// of them is a measurement rather than a value this module chose:
///
/// | field | produced by |
/// |---|---|
/// | `authority` | the durable, service-validated command-effect authority |
/// | `grant` / `policy` | the independently restored grant and compiled policy |
/// | `anchored` | `observe_anchored_production_plan_facts` |
/// | `bubblewrap` | `AuthenticatedBubblewrapImageV1::authenticate_admitted` |
/// | `setup_channel` | `AuthenticatedSetupChannelV1::authenticate_sealed` |
/// | `target_image` | `LinuxProgramImageV1::from_measured_image` |
/// | `target_object` | `LinuxRetainedObjectIdentityV1::from_kernel_observation` |
/// | `directories` | `LinuxPerCommandRetainedDirectoriesV1::from_kernel_observations` |
///
/// The mint performs **no I/O**, for the reason every mint since increment 3
/// performs none: the join and its refusals stay provable on a host with no
/// Linux kernel to read.
pub(crate) struct LinuxProductionCommandPlanInputsV1<'facts> {
    pub(crate) authority: CommandEffectAuthorityV1,
    pub(crate) grant: &'facts IssuedWorkspaceGrant,
    pub(crate) policy: &'facts CompiledExecutionPolicy,
    pub(crate) anchored: LinuxAnchoredServiceFactsV1<'facts>,
    pub(crate) bubblewrap: &'facts AuthenticatedBubblewrapImageV1,
    pub(crate) setup_channel: &'facts AuthenticatedSetupChannelV1,
    pub(crate) target_image: &'facts LinuxProgramImageV1,
    pub(crate) target_object: &'facts LinuxRetainedObjectIdentityV1,
    pub(crate) directories: &'facts LinuxPerCommandRetainedDirectoriesV1,
    /// The Landlock ruleset and seccomp filter this command runs under, each
    /// created or compiled by `mint_mandatory_control_artefacts` against a live
    /// kernel before the join begins.
    pub(crate) mandatory_controls: &'facts LinuxMandatoryControlArtefactsV1,
}

/// The two mandatory kernel-control artefacts one plan is minted against.
///
/// Both halves travel together because item E needs both: `required_controls`
/// contains `FilesystemPolicy`, which only Landlock installs, and
/// `NetworkPolicy`, which only the filter installs. A plan carrying one of them
/// would describe half a containment and could not be used for either.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxMandatoryControlArtefactsV1 {
    pub(crate) landlock: LinuxLandlockRulesetV1,
    pub(crate) seccomp: LinuxSeccompFilterV1,
    pub(crate) seccomp_namespace: LinuxSeccompNamespaceFilterV1,
}

impl LinuxProductionCommandPlanInputsV1<'_> {
    /// Joins the twelve components and submits the result to the plan's own
    /// validators.
    ///
    /// This is the function `LinuxProductionCommandPlanComponentsV1` never had.
    /// It assembles nothing it can measure instead, and it deliberately does
    /// **not** re-check what a validator already checks: the object table and
    /// the binary identities are handed over as two independent sets of kernel
    /// answers and `validate_binaries`, `validate_cgroup`, `validate_mounts`,
    /// `validate_git_masks`, `validate_architecture` and
    /// `validate_release_and_evidence` are what cross them. Nothing here is a
    /// relaxed copy of any of them.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the authority
    /// carries no effect context, when the role and the compiled mutation mode
    /// do not name one execution view, when the target's linkage is dynamic
    /// (deferred item D: there is no loader-closure resolver, so the interpreter
    /// and runtime-object mounts `validate_mounts` would demand cannot be
    /// produced), and on every refusal the plan's own validators make.
    pub(crate) fn mint(
        self,
        native_launch: LinuxNativeLaunchIdentity,
    ) -> Result<ValidatedLinuxProductionCommandPlanV1, LinuxProductionCommandPlanError> {
        let components = self.components()?;
        LinuxProductionCommandPlanV1::build(
            native_launch,
            self.authority,
            self.grant,
            self.policy,
            components,
        )
    }

    /// The twelve components, each from the producer named in the type's table.
    ///
    /// # Errors
    ///
    /// See [`Self::mint`].
    pub(crate) fn components(
        &self,
    ) -> Result<LinuxProductionCommandPlanComponentsV1, LinuxProductionCommandPlanError> {
        let effect = self
            .authority
            .envelope()
            .effect
            .as_ref()
            .ok_or_else(|| invalid("a production plan requires complete effect context"))?;
        let contract = self.policy.contract();
        let view = execution_view(self.authority.role(), contract.mutation_mode)?;
        let execution_root = self.directories.execution_root_for(view);
        let (bubblewrap_image, bubblewrap_format, bubblewrap_version) =
            self.bubblewrap.binary_identity_fields();
        Ok(LinuxProductionCommandPlanComponentsV1 {
            role_snapshot: LinuxRoleSnapshotBindingV1 {
                role: self.authority.role(),
                input_snapshot: effect.input_snapshot.clone(),
                view,
                execution_root_object_id: execution_root.object_id().to_owned(),
                execution_namespace_root: execution_namespace_root(view).to_owned(),
            },
            binaries: LinuxBinaryIdentitiesV1 {
                bubblewrap: bubblewrap_image.clone(),
                bubblewrap_format,
                bubblewrap_version: bubblewrap_version.to_owned(),
                inner_launcher: self.anchored.service_image.clone(),
                // The launcher ELF and kernel architecture must agree with Bubblewrap and
                // the target executable formats.
                inner_launcher_format: self.anchored.host_architecture.elf_image_format(),
                setup_channel: self.setup_channel.setup_channel().clone(),
                target: self.target_image.clone(),
            },
            retained: LinuxRetainedCapabilitySetV1 {
                workspace_root_object_id: self.directories.workspace_root().object_id().to_owned(),
                private_state_root_object_id: self
                    .anchored
                    .service_state_root
                    .object_id()
                    .to_owned(),
                service_owned_journal_index_root_object_id: self
                    .anchored
                    .singleton_journal_root
                    .object_id()
                    .to_owned(),
                objects: self.retained_objects(),
                cgroup: LinuxCgroupIdentitySetV1 {
                    filesystem_magic: self.anchored.cgroup_filesystem_magic,
                    service_parent_object_id: self
                        .anchored
                        .service_cgroup_parent
                        .object_id()
                        .to_owned(),
                    delegation_root_object_id: self
                        .anchored
                        .cgroup_delegation_root
                        .object_id()
                        .to_owned(),
                    leaf: LinuxCommandDomainLeafPlanV1::contract(),
                },
            },
            mounts: self.mounts(view)?,
            network: network_policy(
                contract.network,
                self.authority.grant_hash(),
                &contract.policy_hash,
            ),
            privilege_namespaces: LinuxPrivilegeNamespacePlanV1::contract(),
            landlock: LinuxLandlockPlanV1::contract(self.mandatory_controls.landlock.clone()),
            seccomp: LinuxSeccompPlanV1::contract(
                self.anchored.host_architecture.audit_architecture(),
                self.mandatory_controls.seccomp.clone(),
                self.mandatory_controls.seccomp_namespace.clone(),
            ),
            process_surface: LinuxProcessSurfaceV1::contract(),
            resource_limits: LinuxResourceLimitsV1::from_compiled_policy(contract.resource_limits),
            release: LinuxProductionReleaseExpectationV1::contract(
                self.anchored.authenticated_platform_service_digest.clone(),
            ),
            terminal_evidence: LinuxExpectedTerminalEvidenceV1::contract(),
        })
    }

    /// Every retained identity the plan's object table carries, unsorted.
    ///
    /// `canonicalize` sorts it; sorting here as well would only hide a change
    /// to that ordering. The service image appears exactly once even though it
    /// fills two roles — the anchored platform service and the plan's inner
    /// launcher — because it is one inode, and `validate_retained_objects`
    /// refuses two object IDs that alias one.
    fn retained_objects(&self) -> Vec<LinuxRetainedObjectIdentityV1> {
        let mut objects = self.directories.retained_objects();
        objects.extend([
            self.anchored.service_state_root.clone(),
            self.anchored.singleton_journal_root.clone(),
            self.anchored.service_cgroup_parent.clone(),
            self.anchored.cgroup_delegation_root.clone(),
            self.anchored.service_image_object.clone(),
            self.bubblewrap.retained().clone(),
            self.setup_channel.retained().clone(),
            self.target_object.clone(),
        ]);
        objects
    }

    /// The complete mount plan for one execution view.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxProductionCommandPlanError::Invalid`] when the target is
    /// dynamically linked, and on every refusal
    /// [`LinuxPerCommandRetainedDirectoriesV1::git_masks_for`] makes.
    fn mounts(
        &self,
        view: LinuxExecutionViewV1,
    ) -> Result<LinuxMountPlanV1, LinuxProductionCommandPlanError> {
        // A dynamic target needs an authenticated interpreter and DT_NEEDED mount
        // closure. Refuse it while that closure is unsupported.
        if let LinuxTargetLinkageV1::DynamicElf { .. } = self.target_image.linkage {
            return Err(invalid(
                "a dynamically linked target needs the interpreter and the complete transitive runtime-object closure, and no loader-closure resolver exists",
            ));
        }
        let execution_destination = execution_namespace_root(view);
        let mut read_only = vec![
            retained_mount(
                self.directories.workspace_root(),
                LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT,
                LinuxMountPurposeV1::LiveWorkspace,
            ),
            // Both image mounts are attached at the resolved path their image
            // was authenticated through. `validate_mounts` requires exactly
            // that equality, and honouring it here means no second name for an
            // authenticated image exists anywhere to disagree with the first.
            retained_mount(
                self.anchored.service_image_object,
                self.anchored.service_image.resolved_path(),
                LinuxMountPurposeV1::InnerLauncher,
            ),
            retained_mount(
                self.target_object,
                self.target_image.executable.resolved_path(),
                LinuxMountPurposeV1::TargetExecutable,
            ),
        ];
        let mut read_write = vec![
            retained_mount(
                self.directories.private_temp(),
                LINUX_NAMESPACE_PRIVATE_TEMP,
                LinuxMountPurposeV1::PrivateTemp,
            ),
            retained_mount(
                self.directories.output_spool(),
                LINUX_NAMESPACE_OUTPUT_SPOOL,
                LinuxMountPurposeV1::OutputSpool,
            ),
        ];
        let mut project_destinations = BTreeSet::from([LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT]);
        match view {
            // The live workspace mount *is* the execution mount here, so there
            // is no second mount and no second project view.
            LinuxExecutionViewV1::WorkerReadOnly => {}
            LinuxExecutionViewV1::WorkerShadow => {
                read_write.push(retained_mount(
                    self.directories.execution_root_for(view),
                    execution_destination,
                    LinuxMountPurposeV1::WorkerShadow,
                ));
                project_destinations.insert(execution_destination);
            }
            LinuxExecutionViewV1::FinalVerifierSnapshot => {
                read_only.push(retained_mount(
                    self.directories.execution_root_for(view),
                    execution_destination,
                    LinuxMountPurposeV1::FinalVerifierSnapshot,
                ));
                project_destinations.insert(execution_destination);
            }
        }
        Ok(LinuxMountPlanV1 {
            git_masks: self.directories.git_masks_for(&project_destinations)?,
            read_only,
            read_write,
        })
    }
}

impl LinuxProductionCommandPlanComponentsV1 {
    /// The `.git` masks this component set carries.
    pub(crate) fn git_masks(&self) -> &[LinuxGitMaskV1] {
        &self.mounts.git_masks
    }

    /// How many retained identities the object table carries.
    pub(crate) fn retained_object_count(&self) -> usize {
        self.retained.objects.len()
    }

    /// How many read-only mounts the plan carries.
    pub(crate) fn read_only_mount_count(&self) -> usize {
        self.mounts.read_only.len()
    }

    /// How many read-write mounts the plan carries.
    pub(crate) fn read_write_mount_count(&self) -> usize {
        self.mounts.read_write.len()
    }
}

/// The one execution view a role and a compiled mutation mode name together.
///
/// The view is not a plan input and is never chosen: it is read out of the
/// independently compiled policy, and `validate_role_snapshot` then requires
/// the same triple again. A role that runs no contained command has no view and
/// is refused here rather than later.
fn execution_view(
    role: RunnerRole,
    mutation_mode: MutationMode,
) -> Result<LinuxExecutionViewV1, LinuxProductionCommandPlanError> {
    match (role, mutation_mode) {
        (RunnerRole::Worker, MutationMode::ReadOnly) => Ok(LinuxExecutionViewV1::WorkerReadOnly),
        (RunnerRole::Worker, MutationMode::ShadowWorkspace) => {
            Ok(LinuxExecutionViewV1::WorkerShadow)
        }
        (RunnerRole::FinalVerifier, MutationMode::ReadOnly) => {
            Ok(LinuxExecutionViewV1::FinalVerifierSnapshot)
        }
        _ => Err(invalid(
            "the command role and the independently compiled mutation mode name no execution view",
        )),
    }
}

/// Where a view executes inside the command's mount namespace.
const fn execution_namespace_root(view: LinuxExecutionViewV1) -> &'static str {
    match view {
        LinuxExecutionViewV1::WorkerReadOnly => LINUX_NAMESPACE_LIVE_WORKSPACE_ROOT,
        LinuxExecutionViewV1::WorkerShadow | LinuxExecutionViewV1::FinalVerifierSnapshot => {
            LINUX_NAMESPACE_EXECUTION_ROOT
        }
    }
}

/// One mount, whose source is a retained identity rather than a name.
fn retained_mount(
    source: &LinuxRetainedObjectIdentityV1,
    destination: &str,
    purpose: LinuxMountPurposeV1,
) -> LinuxRetainedMountV1 {
    LinuxRetainedMountV1 {
        source_object_id: source.object_id().to_owned(),
        destination: destination.to_owned(),
        purpose,
    }
}

/// The network mode the compiled policy names.
///
/// `validate_network` requires the same two hashes again for the renewed-action
/// arm, so the grant and policy commitments below are crossed rather than
/// trusted.
fn network_policy(
    network: ExecutionNetwork,
    grant_hash: &Digest,
    policy_hash: &Digest,
) -> LinuxNetworkNamespacePolicyV1 {
    match network {
        ExecutionNetwork::None => LinuxNetworkNamespacePolicyV1::NewIsolatedNamespace,
        ExecutionNetwork::FullForAction => {
            LinuxNetworkNamespacePolicyV1::RetainHostNamespaceForRenewedAction {
                grant_hash: grant_hash.clone(),
                policy_hash: policy_hash.clone(),
            }
        }
    }
}

impl LinuxPrivilegeNamespacePlanV1 {
    /// The one privilege-namespace combination the plan admits.
    ///
    /// Every field of this type has exactly one variant, so the contract is
    /// stated by the schema and this constructor only writes it down.
    pub(crate) const fn contract() -> Self {
        Self {
            user: LinuxNamespaceRequirementV1::NewAndVerified,
            mount: LinuxNamespaceRequirementV1::NewAndVerified,
            pid: LinuxNamespaceRequirementV1::NewAndVerified,
            ipc: LinuxNamespaceRequirementV1::NewAndVerified,
            uts: LinuxNamespaceRequirementV1::NewAndVerified,
            cgroup: LinuxNamespaceRequirementV1::NewAndVerified,
            capabilities: LinuxCapabilityRequirementV1::DropAllAndVerifyEverySetEmpty,
            no_new_privileges: LinuxNoNewPrivilegesRequirementV1::SetAndReadBackBeforeFilter,
        }
    }
}

impl LinuxProcessSurfaceV1 {
    /// The one process-surface combination the plan admits.
    pub(crate) const fn contract() -> Self {
        Self {
            environment: LinuxEnvironmentPolicyV1::ClearThenInstallExactCompiledEnvironment,
            descriptors: LinuxDescriptorPolicyV1::SetupChannelOnlyWhileHeldThenStdioOnlyAtTarget,
            command: LinuxCommandBindingPolicyV1::ExactAuthorityArgvAndRetainedCwd,
        }
    }
}

impl LinuxLandlockPlanV1 {
    /// The Landlock contract — an ABI window, an enforcement rule, and the
    /// ruleset a mint created.
    ///
    /// See [`LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI`] for why the window's
    /// upper half refuses nothing today and why narrowing it would be a claim
    /// rather than a control. The ruleset is **not** built here: this module
    /// performs no I/O, and a ruleset that was not created against a live
    /// kernel is the invented artefact version 3 removed. It arrives from
    /// `mint_mandatory_control_artefacts`, exactly as the Bubblewrap image and
    /// the setup channel arrive from their own authenticating mints.
    pub(crate) fn contract(ruleset: LinuxLandlockRulesetV1) -> Self {
        Self::InstalledRulesetProvenByLiveBootstrapProbe {
            enforcement: LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec,
            minimum_kernel_abi: LINUX_LANDLOCK_MINIMUM_KERNEL_ABI,
            maximum_modeled_kernel_abi: LINUX_LANDLOCK_MAXIMUM_MODELED_KERNEL_ABI,
            ruleset,
        }
    }
}

impl LinuxSeccompPlanV1 {
    /// The seccomp contract for one measured audit architecture, and the
    /// filter a mint compiled for it.
    ///
    /// `audit_architecture` is not a constant: it comes from the same
    /// measurement the image formats come from, and `validate_architecture`
    /// requires all of them to denote one value. The filter is not built here,
    /// for the reason given on [`LinuxLandlockPlanV1::contract`].
    pub(crate) fn contract(
        audit_architecture: LinuxAuditArchitectureV1,
        filter: LinuxSeccompFilterV1,
        namespace_filter: LinuxSeccompNamespaceFilterV1,
    ) -> Self {
        Self::CompiledFilterProvenByLiveBootstrapProbe {
            enforcement: LinuxMandatoryEnforcementV1::FullOrRefuseBeforeTargetExec,
            audit_architecture,
            default_action: LinuxSeccompDefaultActionV1::KillProcess,
            filter,
            namespace_filter,
        }
    }
}

impl LinuxResourceLimitsV1 {
    /// The compiled policy's limits, with swap fixed at zero.
    ///
    /// `validate_resource_limits` requires equality with the same compiled
    /// policy and refuses any nonzero `swap_bytes`, so nothing here is assigned
    /// past what that validator checks.
    pub(crate) const fn from_compiled_policy(limits: ResourceLimits) -> Self {
        Self {
            wall_time_ms: limits.wall_time_ms,
            max_output_bytes: limits.max_output_bytes,
            max_processes: limits.max_processes,
            max_memory_bytes: limits.max_memory_bytes,
            swap_bytes: 0,
        }
    }
}

impl LinuxProductionReleaseExpectationV1 {
    /// The release contract, anchored to the running service image's digest.
    pub(crate) fn contract(authenticated_platform_service_digest: Digest) -> Self {
        Self {
            schema: LINUX_PRODUCTION_HELD_RELEASE_SCHEMA.to_owned(),
            authenticated_platform_service_digest,
            held_before_release: LinuxHeldBeforeReleaseV1::RequiredBeforeAnyTargetCode,
            live_claim: LinuxLiveReleaseClaimRequirementV1::NonCloneableLiveClaimConsumedSynchronously,
            journal: LinuxReleaseJournalRequirementV1::PersistIntentBeforeSynchronousReleaseAndReconcileOnlyAfterRestart,
            replay_exclusion: LinuxReplayExclusionRequirementV1::GlobalEffectIdOneShotAcrossAllRunnerSessions,
            journal_ownership: LinuxJournalOwnershipRequirementV1::ServiceOwnedSingletonPerAuthenticatedDelegation,
        }
    }
}

impl LinuxExpectedTerminalEvidenceV1 {
    /// The complete terminal-evidence contract, in the required order.
    pub(crate) fn contract() -> Self {
        Self {
            runtime_schema: LINUX_COMMAND_RUNTIME_EVIDENCE_SCHEMA.to_owned(),
            cleanup_schema: LINUX_COMMAND_CLEANUP_EVIDENCE_SCHEMA.to_owned(),
            runtime_requirements: REQUIRED_RUNTIME_EVIDENCE.to_vec(),
            cleanup_requirements_in_order: REQUIRED_CLEANUP.to_vec(),
        }
    }
}

// The authenticated native service receives only this projection of a
// command plan: no command, release operation, or retained descriptor crosses
// the bootstrap boundary.

/// Exact Bubblewrap image and version required by a canonical command plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxBubblewrapBootstrapBindingV1 {
    pub(crate) resolved_path: String,
    pub(crate) version: String,
    pub(crate) file: LinuxBootstrapFileIdentityV1,
}

/// Exact Landlock window **and ruleset** a plan requires its bootstrap to have
/// observed.
///
/// It is a projection of [`LinuxLandlockPlanV1`] and carries what that type
/// carries — no more. Under schema version 3 that was an ABI window and
/// nothing else, and the doc here said so: a bootstrap could not be handed a
/// Landlock contract to compare, because the plan it came from had none to
/// give. Version 4 gives it one, so the bootstrap is now handed the exact
/// ruleset, and `validate_service_bootstrap_evidence` requires the live probe
/// result to be the one **a probe that installed this ruleset** produces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxLandlockBootstrapBindingV1 {
    InstalledRulesetProvenByLiveBootstrapProbe {
        minimum_kernel_abi: u32,
        maximum_modeled_kernel_abi: u32,
        ruleset: LinuxLandlockRulesetV1,
    },
}

/// Exact seccomp contract **and filter** a plan requires its bootstrap to have
/// observed.
///
/// The projection of [`LinuxSeccompPlanV1`], with the same property.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum LinuxSeccompBootstrapBindingV1 {
    CompiledFilterProvenByLiveBootstrapProbe {
        audit_architecture: LinuxAuditArchitectureV1,
        default_action: LinuxSeccompDefaultActionV1,
        filter: LinuxSeccompFilterV1,
    },
}

/// Complete plan projection consumed by the future authenticated native
/// service bootstrap.
///
/// This projection deliberately contains no command or release operation. It
/// only lets the service prove that its retained roots, delegated cgroup,
/// Bubblewrap image, and mandatory kernel-control probes are the exact values
/// already committed by the complete production plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinuxProductionCommandPlanServiceBootstrapBindingV1 {
    pub(crate) journal: LinuxProductionCommandPlanJournalBindingV1,
    pub(crate) cgroup_filesystem_magic: u64,
    pub(crate) bubblewrap: LinuxBubblewrapBootstrapBindingV1,
    pub(crate) landlock: LinuxLandlockBootstrapBindingV1,
    pub(crate) seccomp: LinuxSeccompBootstrapBindingV1,
}

// Use one namespace-denial table and assembler for minting, launching, and
// canary validation.

/// Syscalls that create or enter a namespace whatever their arguments, on
/// aarch64. `clone3` is here because seccomp cannot read its flags.
pub(crate) const LINUX_NAMESPACE_UNCONDITIONAL_SYSCALLS_AARCH64: &[(&str, i64)] =
    &[("clone3", 435), ("setns", 268), ("unshare", 97)];

/// The same unconditional set on x86-64.
pub(crate) const LINUX_NAMESPACE_UNCONDITIONAL_SYSCALLS_X86_64: &[(&str, i64)] =
    &[("clone3", 435), ("setns", 308), ("unshare", 272)];

/// `clone`, denied only when it carries a namespace flag. `fork(2)` is
/// `clone(2)`, so the number cannot be refused outright.
pub(crate) const LINUX_NAMESPACE_CONDITIONAL_CLONE_AARCH64: (&str, i64) = ("clone", 220);
pub(crate) const LINUX_NAMESPACE_CONDITIONAL_CLONE_X86_64: (&str, i64) = ("clone", 56);

/// Every `CLONE_NEW*` bit, one per namespace type.
///
/// Each becomes its own rule on the `clone` number. `seccompiler` ANDs the
/// conditions within one rule and ORs the rules for one syscall, so a
/// bit-per-rule set matches when *any* namespace bit is present. A single
/// `MaskedEq` over the union would instead match only when every bit was set.
///
/// `CLONE_NEWTIME` overlaps the `CSIGNAL` byte that legacy `clone` uses for
/// the child's termination signal. Signal numbers do not reach `0x80`, so it
/// produces no false denial here.
pub(crate) const LINUX_CLONE_NAMESPACE_FLAGS: &[(&str, u64)] = &[
    ("CLONE_NEWTIME", 0x0000_0080),
    ("CLONE_NEWNS", 0x0002_0000),
    ("CLONE_NEWCGROUP", 0x0200_0000),
    ("CLONE_NEWUTS", 0x0400_0000),
    ("CLONE_NEWIPC", 0x0800_0000),
    ("CLONE_NEWUSER", 0x1000_0000),
    ("CLONE_NEWPID", 0x2000_0000),
    ("CLONE_NEWNET", 0x4000_0000),
];

/// Argument index of the legacy `clone` flags word.
pub(crate) const LINUX_NAMESPACE_CLONE_FLAG_ARGUMENT: u8 = 0;

/// x32 syscall numbers are `0x40000000 | nr` on an x86-64 kernel.
pub(crate) const LINUX_X32_SYSCALL_BIT: i64 = 0x4000_0000;

/// The unconditional namespace syscalls for one audit architecture.
pub(crate) const fn namespace_unconditional_syscalls(
    architecture: LinuxAuditArchitectureV1,
) -> &'static [(&'static str, i64)] {
    match architecture {
        LinuxAuditArchitectureV1::Aarch64 => LINUX_NAMESPACE_UNCONDITIONAL_SYSCALLS_AARCH64,
        LinuxAuditArchitectureV1::X86_64 => LINUX_NAMESPACE_UNCONDITIONAL_SYSCALLS_X86_64,
    }
}

/// The conditional `clone` denial for one audit architecture.
pub(crate) const fn namespace_conditional_clone(
    architecture: LinuxAuditArchitectureV1,
) -> (&'static str, i64) {
    match architecture {
        LinuxAuditArchitectureV1::Aarch64 => LINUX_NAMESPACE_CONDITIONAL_CLONE_AARCH64,
        LinuxAuditArchitectureV1::X86_64 => LINUX_NAMESPACE_CONDITIONAL_CLONE_X86_64,
    }
}

/// Native and, on x86-64, x32 numbers for one logical syscall.
///
/// Exact-number filters with default Allow miss `0x40000000 | nr` unless that
/// number is also denied. aarch64 has no x32 ABI; the native number is the
/// whole set.
pub(crate) fn namespace_filter_syscall_numbers(
    number: i64,
    architecture: LinuxAuditArchitectureV1,
) -> Vec<i64> {
    match architecture {
        LinuxAuditArchitectureV1::Aarch64 => vec![number],
        LinuxAuditArchitectureV1::X86_64 => vec![number, number | LINUX_X32_SYSCALL_BIT],
    }
}

/// The committed namespace denial list for one audit architecture.
///
/// Name-sorted, one `Always` row per unconditional syscall, and `clone` with
/// every `CLONE_NEW*` bit as its own flag. This is the list mint writes and
/// the list the validator requires.
pub(crate) fn committed_namespace_denials(
    architecture: LinuxAuditArchitectureV1,
) -> Vec<LinuxSeccompNamespaceDenialV1> {
    let mut denied = namespace_unconditional_syscalls(architecture)
        .iter()
        .map(|(name, number)| LinuxSeccompNamespaceDenialV1 {
            name: (*name).to_owned(),
            number: *number,
            condition: LinuxSeccompDenialConditionV1::Always,
        })
        .collect::<Vec<_>>();
    let (clone_name, clone_number) = namespace_conditional_clone(architecture);
    denied.push(LinuxSeccompNamespaceDenialV1 {
        name: clone_name.to_owned(),
        number: clone_number,
        condition: LinuxSeccompDenialConditionV1::AnyArgumentFlagSet {
            argument: LINUX_NAMESPACE_CLONE_FLAG_ARGUMENT,
            flags: LINUX_CLONE_NAMESPACE_FLAGS
                .iter()
                .map(|(name, bit)| LinuxSeccompArgumentFlagV1 {
                    name: (*name).to_owned(),
                    bit: *bit,
                })
                .collect(),
        },
    });
    denied.sort_by(|left, right| left.name.cmp(&right.name));
    denied
}

/// Requires `denied` to be exactly [`committed_namespace_denials`].
///
/// Incomplete tables (dropped `unshare`, dropped `clone`, a missing
/// `CLONE_NEW*` bit, an empty flag list) are a refusal, not a shorter filter.
pub(crate) fn validate_required_namespace_set(
    architecture: LinuxAuditArchitectureV1,
    denied: &[LinuxSeccompNamespaceDenialV1],
) -> Result<(), String> {
    let required = committed_namespace_denials(architecture);
    if denied == required.as_slice() {
        return Ok(());
    }
    Err(
        "the committed namespace filter is not the exact required set \
         (unshare, setns, clone3, and clone with every CLONE_NEW* bit)"
            .to_owned(),
    )
}

/// This host's audit architecture, when the crate is built for a modeled Linux.
#[cfg(target_arch = "aarch64")]
pub(crate) const HOST_AUDIT_ARCHITECTURE: LinuxAuditArchitectureV1 =
    LinuxAuditArchitectureV1::Aarch64;
#[cfg(target_arch = "x86_64")]
pub(crate) const HOST_AUDIT_ARCHITECTURE: LinuxAuditArchitectureV1 =
    LinuxAuditArchitectureV1::X86_64;

/// Parses a plan/release audit-architecture tag.
pub(crate) fn audit_architecture_from_tag(tag: &str) -> Option<LinuxAuditArchitectureV1> {
    match tag {
        "audit-arch-aarch64" => Some(LinuxAuditArchitectureV1::Aarch64),
        "audit-arch-x86-64" => Some(LinuxAuditArchitectureV1::X86_64),
        _ => None,
    }
}

/// Assembles the namespace filter for one committed denial list.
///
/// This is the only BPF compiler for that list. On x86-64 it also denies the
/// x32 number for each logical syscall so default-Allow cannot pass
/// `0x40000000 | nr`. Native numbers, masks, and flag rules are unchanged.
///
/// # Errors
///
/// Returns a reason when a condition does not compile, a syscall number is
/// repeated after x32 expansion, or `seccompiler` rejects the filter.
#[cfg(target_os = "linux")]
pub(crate) fn assemble_namespace_program(
    denied: &[LinuxSeccompNamespaceDenialV1],
    architecture: LinuxAuditArchitectureV1,
) -> Result<seccompiler::BpfProgram, String> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };

    let target = match architecture {
        LinuxAuditArchitectureV1::Aarch64 => seccompiler::TargetArch::aarch64,
        LinuxAuditArchitectureV1::X86_64 => seccompiler::TargetArch::x86_64,
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for entry in denied {
        for number in namespace_filter_syscall_numbers(entry.number, architecture) {
            let compiled = match &entry.condition {
                LinuxSeccompDenialConditionV1::Always => Vec::new(),
                LinuxSeccompDenialConditionV1::AnyArgumentFlagSet { argument, flags } => {
                    let mut built = Vec::with_capacity(flags.len());
                    for flag in flags {
                        let condition = SeccompCondition::new(
                            *argument,
                            SeccompCmpArgLen::Qword,
                            SeccompCmpOp::MaskedEq(flag.bit),
                            flag.bit,
                        )
                        .map_err(|error| format!("compile namespace condition: {error}"))?;
                        built.push(
                            SeccompRule::new(vec![condition])
                                .map_err(|error| format!("compile namespace rule: {error}"))?,
                        );
                    }
                    built
                }
            };
            if rules.insert(number, compiled).is_some() {
                return Err("namespace filter denies the same syscall number twice".to_owned());
            }
        }
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(38),
        target,
    )
    .map_err(|error| format!("compile namespace filter: {error}"))?;
    seccompiler::BpfProgram::try_from(filter)
        .map_err(|error| format!("assemble namespace filter: {error}"))
}

#[cfg(test)]
pub(crate) mod tests;
