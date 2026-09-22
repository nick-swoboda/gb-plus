//! Sealed native-admission contract and durable type-state for Hard Gate 1.
//!
//! This module deliberately contains no native fixture executor and no bridge
//! to ordinary runner authority. Production constructors for evidence-only and
//! independent-validator authority remain absent. The contract can therefore
//! be exercised with explicit synthetic roots without allowing a mutable or
//! revisionless checkout to mint production authority.

#![allow(dead_code)] // Activated only after the fixed native fixture is connected.

mod linux_no_new_privs;

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, open, openat};
#[cfg(target_os = "linux")]
use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const NATIVE_ADMISSION_BINDING_SCHEMA: &str = "grok-build/linux-native-admission-binding/v1";
const EVIDENCE_ONLY_RECORD_SCHEMA: &str = "grok-build/linux-evidence-only-record/v1";
const PRODUCTION_ADMISSION_RECORD_SCHEMA: &str = "grok-build/linux-production-admission-record/v1";
const NATIVE_ADMISSION_FIXTURE_SPEC_ID: &str = "gb.fixture.g1.native-admission.v1";
const LINUX_NATIVE_FIXTURE_SPEC_ID: &str = "gb.fixture.g1.linux-native.v1";
const EVIDENCE_ONLY_CAPABILITY_DOMAIN: &[u8] = b"grok-build/linux-evidence-only-capability/v1\0";
const CASE_EVIDENCE_DOMAIN: &[u8] = b"grok-build/linux-native-case-evidence/v1\0";
const PRODUCT_MINT_REJECTION_DOMAIN: &[u8] = b"grok-build/linux-native-product-mint-rejection/v1\0";
const EVIDENCE_ONLY_RECORD_DOMAIN: &[u8] = b"grok-build/linux-evidence-only-record/v1\0";
const NATIVE_POLICY_DOMAIN: &[u8] = b"grok-build/linux-native-policy/v1\0";
const VALIDATOR_CONTRACT_DOMAIN: &[u8] = b"grok-build/linux-native-validator/v1\0";
const PRODUCTION_ADMISSION_DOMAIN: &[u8] = b"grok-build/linux-production-admission-record/v1\0";
const LANDLOCK_RULESET_EXPECTATION_DOMAIN: &[u8] =
    b"grok-build/linux-native-landlock-ruleset-expectation/v1\0";
const SECCOMP_PROGRAM_EXPECTATION_DOMAIN: &[u8] =
    b"grok-build/linux-native-seccomp-program-expectation/v1\0";
const CGROUP_IDENTITY_EXPECTATION_DOMAIN: &[u8] =
    b"grok-build/linux-native-cgroup-identity-expectation/v1\0";
const FORBIDDEN_PRODUCT_PROBE_ID: &str = "grok-build/gate1/forbidden-product-mint/v1";
const SECCOMP_FORBIDDEN_SYSCALL_X86_64: u32 = 101;
const EVIDENCE_ONLY_RECORD_NAME: &str = "evidence-only-record-v1.json";
const PRODUCTION_ADMISSION_RECORD_NAME: &str = "production-admitted-v1.json";
const PRODUCTION_ADMISSION_TEMP_NAME: &str = ".production-admitted-v1.tmp";
const LINUX_NO_NEW_PRIVS_OBSERVATION_NAME: &str = "linux-no-new-privs-observation-v1.json";
const MAX_ARTIFACT_BYTES: u64 = 256 * 1_024 * 1_024;
const MAX_RECORD_BYTES: u64 = 4 * 1_024 * 1_024;

const PRE_ADMISSION_CASES: [(&str, &str); 8] = [
    (
        "native_evidence_only_authority_sealed",
        NATIVE_ADMISSION_FIXTURE_SPEC_ID,
    ),
    (
        "linux_bubblewrap_namespace_canary",
        LINUX_NATIVE_FIXTURE_SPEC_ID,
    ),
    ("linux_landlock_canary", LINUX_NATIVE_FIXTURE_SPEC_ID),
    ("linux_seccomp_canary", LINUX_NATIVE_FIXTURE_SPEC_ID),
    ("linux_capabilities_removed", LINUX_NATIVE_FIXTURE_SPEC_ID),
    ("linux_no_new_privs", LINUX_NATIVE_FIXTURE_SPEC_ID),
    ("linux_cgroup_v2_membership", LINUX_NATIVE_FIXTURE_SPEC_ID),
    (
        "linux_pidfd_process_tree_cleanup",
        LINUX_NATIVE_FIXTURE_SPEC_ID,
    ),
];

const FIXED_INPUT_IDS: [&str; 8] = [
    "forbidden-product-mint-canary",
    "bubblewrap-namespace-canary",
    "landlock-denial-canary",
    "seccomp-denial-canary",
    "capability-empty-canary",
    "no-new-privs-canary",
    "cgroup-membership-canary",
    "pidfd-process-tree-canary",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeAdmissionError(String);

impl Display for NativeAdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for NativeAdmissionError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LinuxGate1TargetV1 {
    Ubuntu2604X8664,
    Fedora44X8664,
}

impl LinuxGate1TargetV1 {
    const fn target_id(self) -> &'static str {
        match self {
            Self::Ubuntu2604X8664 => "ubuntu-26.04-x86_64",
            Self::Fedora44X8664 => "fedora-44-x86_64",
        }
    }

    const fn target_triple() -> &'static str {
        "x86_64-unknown-linux-gnu"
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BoundArtifactKindV1 {
    Executable,
    ReadOnlyInput,
    ImmutableImageAttestation,
    TypedObservation,
    StandardOutput,
    StandardError,
    ValidatorExecutable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum BoundFileTypeV1 {
    Regular,
    Directory,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundFileIdentityV1 {
    device: u64,
    inode: u64,
    mount_id: u64,
    file_type: BoundFileTypeV1,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    link_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundArtifactV1 {
    object_id: String,
    kind: BoundArtifactKindV1,
    file: BoundFileIdentityV1,
    byte_length: u64,
    sha256: String,
    close_on_exec: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ImmutableSourceBindingV1 {
    revision: String,
    tree_object: String,
    source_tree_sha256: String,
    repository_dirty: bool,
    untracked_source_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolchainBindingV1 {
    rustc_version: String,
    cargo_version: String,
    rust_toolchain_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the sealed policy keeps each independently evidenced security predicate explicit"
)]
struct LinuxNativePolicyV1 {
    schema: String,
    fresh_user_mount_pid_network_ipc_uts_cgroup_namespaces: bool,
    landlock_active_denial_required: bool,
    seccomp_active_denial_required: bool,
    effective_permitted_inheritable_ambient_capabilities_empty: bool,
    no_new_privs_required: bool,
    cgroup_v2_exact_membership_required: bool,
    pidfd_and_cgroup_zero_descendants_required: bool,
    provider_credentials_forbidden: bool,
    arbitrary_workspace_objective_forbidden: bool,
    allowed_controllers_in_order: Vec<String>,
}

impl LinuxNativePolicyV1 {
    fn fixed() -> Self {
        Self {
            schema: "grok-build/linux-native-evidence-policy/v1".into(),
            fresh_user_mount_pid_network_ipc_uts_cgroup_namespaces: true,
            landlock_active_denial_required: true,
            seccomp_active_denial_required: true,
            effective_permitted_inheritable_ambient_capabilities_empty: true,
            no_new_privs_required: true,
            cgroup_v2_exact_membership_required: true,
            pidfd_and_cgroup_zero_descendants_required: true,
            provider_credentials_forbidden: true,
            arbitrary_workspace_objective_forbidden: true,
            allowed_controllers_in_order: vec!["memory".into(), "pids".into()],
        }
    }

    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(NATIVE_POLICY_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PlatformImageBindingV1 {
    target: LinuxGate1TargetV1,
    target_id: String,
    target_triple: String,
    immutable_image_sha256: String,
    attestation: BoundArtifactV1,
    live_os_release_sha256: String,
    live_kernel_release: String,
    live_architecture: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeAdmissionBindingV1 {
    schema: String,
    fixture_spec_id: String,
    source: ImmutableSourceBindingV1,
    target: LinuxGate1TargetV1,
    backend_binary: BoundArtifactV1,
    fixture_binary: BoundArtifactV1,
    native_policy: LinuxNativePolicyV1,
    native_policy_sha256: String,
    platform_image: PlatformImageBindingV1,
    release_target_manifest_version: u32,
    release_target_manifest: BoundArtifactV1,
    gate_case_manifest_version: u32,
    gate_case_manifest: BoundArtifactV1,
    cargo_lock: BoundArtifactV1,
    toolchain: ToolchainBindingV1,
    fixed_input_manifest: BoundArtifactV1,
    fixed_inputs_in_order: Vec<BoundArtifactV1>,
}

impl NativeAdmissionBindingV1 {
    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(EVIDENCE_ONLY_CAPABILITY_DOMAIN, self)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one closed validator keeps every fixed native-admission identity adjacent"
    )]
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        if self.schema != NATIVE_ADMISSION_BINDING_SCHEMA
            || self.fixture_spec_id != NATIVE_ADMISSION_FIXTURE_SPEC_ID
            || self.source.repository_dirty
            || self.source.untracked_source_count != 0
            || !is_git_object_id(&self.source.revision)
            || !is_git_object_id(&self.source.tree_object)
        {
            return Err(invalid(
                "native-admission binding is not attached to one immutable clean source revision",
            ));
        }
        require_digest("source tree", &self.source.source_tree_sha256)?;
        if self.native_policy != LinuxNativePolicyV1::fixed()
            || self.native_policy_sha256 != self.native_policy.digest()?
        {
            return Err(invalid("native policy differs from the fixed v1 policy"));
        }
        if self.platform_image.target != self.target
            || self.platform_image.target_id != self.target.target_id()
            || self.platform_image.target_triple != LinuxGate1TargetV1::target_triple()
            || self.platform_image.live_architecture != "x86_64"
            || self.platform_image.live_kernel_release.is_empty()
        {
            return Err(invalid(
                "platform image target, triple, architecture, or live readback crossed",
            ));
        }
        require_digest(
            "immutable platform image",
            &self.platform_image.immutable_image_sha256,
        )?;
        require_digest(
            "live operating-system release",
            &self.platform_image.live_os_release_sha256,
        )?;
        if self.release_target_manifest_version != 1 || self.gate_case_manifest_version != 2 {
            return Err(invalid(
                "native admission requires release-target manifest version 1 and gate-case manifest version 2",
            ));
        }
        require_bounded_text("rustc version", &self.toolchain.rustc_version, 1, 256)?;
        require_bounded_text("cargo version", &self.toolchain.cargo_version, 1, 256)?;
        require_digest("rust toolchain", &self.toolchain.rust_toolchain_sha256)?;

        for (artifact, expected_id, expected_kind) in [
            (
                &self.backend_binary,
                "backend-binary",
                BoundArtifactKindV1::Executable,
            ),
            (
                &self.fixture_binary,
                "fixture-binary",
                BoundArtifactKindV1::Executable,
            ),
            (
                &self.platform_image.attestation,
                "platform-image-attestation",
                BoundArtifactKindV1::ImmutableImageAttestation,
            ),
            (
                &self.release_target_manifest,
                "release-target-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
            ),
            (
                &self.gate_case_manifest,
                "gate-case-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
            ),
            (
                &self.cargo_lock,
                "cargo-lock",
                BoundArtifactKindV1::ReadOnlyInput,
            ),
            (
                &self.fixed_input_manifest,
                "fixed-input-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
            ),
        ] {
            artifact.validate()?;
            if artifact.object_id != expected_id || artifact.kind != expected_kind {
                return Err(invalid(format!(
                    "native-admission artifact role {expected_id} crossed"
                )));
            }
        }
        if self.backend_binary.file == self.fixture_binary.file {
            return Err(invalid("backend and fixture executables alias one object"));
        }
        if self.fixed_inputs_in_order.len() != FIXED_INPUT_IDS.len()
            || self
                .fixed_inputs_in_order
                .iter()
                .zip(FIXED_INPUT_IDS)
                .any(|(artifact, expected)| {
                    artifact.object_id != expected
                        || artifact.kind != BoundArtifactKindV1::ReadOnlyInput
                })
        {
            return Err(invalid(
                "fixed native-admission input IDs are missing, extra, crossed, or reordered",
            ));
        }
        for artifact in &self.fixed_inputs_in_order {
            artifact.validate()?;
        }
        require_pairwise_distinct_artifacts(self.all_artifacts())
    }

    fn all_artifacts(&self) -> Vec<&BoundArtifactV1> {
        let mut artifacts = vec![
            &self.backend_binary,
            &self.fixture_binary,
            &self.platform_image.attestation,
            &self.release_target_manifest,
            &self.gate_case_manifest,
            &self.cargo_lock,
            &self.fixed_input_manifest,
        ];
        artifacts.extend(&self.fixed_inputs_in_order);
        artifacts
    }
}

#[derive(Serialize)]
struct BoundNativeProbeExpectationPreimage<'a> {
    binding_sha256: String,
    native_policy_sha256: &'a str,
    target_id: &'a str,
    fixed_input: &'a BoundArtifactV1,
}

fn expected_bound_probe_digest(
    domain: &[u8],
    binding: &NativeAdmissionBindingV1,
    fixed_input_index: usize,
) -> Result<String, NativeAdmissionError> {
    let fixed_input = binding
        .fixed_inputs_in_order
        .get(fixed_input_index)
        .ok_or_else(|| invalid("bound native probe fixed input is absent"))?;
    if fixed_input.object_id != FIXED_INPUT_IDS[fixed_input_index] {
        return Err(invalid("bound native probe fixed input identity crossed"));
    }
    canonical_digest(
        domain,
        &BoundNativeProbeExpectationPreimage {
            binding_sha256: binding.digest()?,
            native_policy_sha256: &binding.native_policy_sha256,
            target_id: &binding.platform_image.target_id,
            fixed_input,
        },
    )
}

fn expected_landlock_ruleset_digest(
    binding: &NativeAdmissionBindingV1,
) -> Result<String, NativeAdmissionError> {
    expected_bound_probe_digest(LANDLOCK_RULESET_EXPECTATION_DOMAIN, binding, 2)
}

fn expected_seccomp_program_digest(
    binding: &NativeAdmissionBindingV1,
) -> Result<String, NativeAdmissionError> {
    expected_bound_probe_digest(SECCOMP_PROGRAM_EXPECTATION_DOMAIN, binding, 3)
}

fn expected_cgroup_identity_digest(
    binding: &NativeAdmissionBindingV1,
) -> Result<String, NativeAdmissionError> {
    expected_bound_probe_digest(CGROUP_IDENTITY_EXPECTATION_DOMAIN, binding, 6)
}

impl BoundArtifactV1 {
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        require_identifier("artifact object ID", &self.object_id)?;
        require_digest("artifact", &self.sha256)?;
        if self.file.device == 0
            || self.file.inode == 0
            || self.file.mount_id == 0
            || self.file.file_type != BoundFileTypeV1::Regular
            || self.file.link_count != 1
            || self.byte_length == 0
            || self.byte_length > MAX_ARTIFACT_BYTES
            || !self.close_on_exec
            || self.file.mode & !0o7_777 != 0
            || self.file.owner_uid != rustix::process::geteuid().as_raw()
        {
            return Err(invalid(format!(
                "artifact {} has invalid identity, length, link, mode, or CLOEXEC state",
                self.object_id
            )));
        }
        let permissions = self.file.mode & 0o777;
        let expected_permissions = match self.kind {
            BoundArtifactKindV1::Executable | BoundArtifactKindV1::ValidatorExecutable => 0o500,
            BoundArtifactKindV1::ReadOnlyInput
            | BoundArtifactKindV1::ImmutableImageAttestation
            | BoundArtifactKindV1::TypedObservation
            | BoundArtifactKindV1::StandardOutput
            | BoundArtifactKindV1::StandardError => 0o400,
        };
        if permissions != expected_permissions {
            return Err(invalid(format!(
                "artifact {} permissions differ from its exact role",
                self.object_id
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "observation_kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum NativeCaseObservationV1 {
    EvidenceOnlyAuthoritySealed {
        binding_sha256: String,
        fixed_input_ids_in_order: Vec<String>,
        forbidden_shape_sha256: String,
        rejected_before_effect: bool,
        accepted_workspace_objective_or_command_count: u32,
        provider_credential_count: u32,
        ordinary_authority_mint_count: u32,
        native_invocation_count: u32,
    },
    BubblewrapNamespace {
        host_user_namespace_id: u64,
        child_user_namespace_id: u64,
        host_mount_namespace_id: u64,
        child_mount_namespace_id: u64,
        host_pid_namespace_id: u64,
        child_pid_namespace_id: u64,
        host_network_namespace_id: u64,
        child_network_namespace_id: u64,
        host_ipc_namespace_id: u64,
        child_ipc_namespace_id: u64,
        host_uts_namespace_id: u64,
        child_uts_namespace_id: u64,
        host_cgroup_namespace_id: u64,
        child_cgroup_namespace_id: u64,
        forbidden_host_root_visible: bool,
        nested_namespace_mount_denied_errno: i32,
        forbidden_side_effect_count: u32,
    },
    LandlockDenial {
        ruleset_sha256: String,
        probe_id: String,
        denied_errno: i32,
        forbidden_side_effect_count: u32,
    },
    SeccompDenial {
        program_sha256: String,
        forbidden_syscall_number: u32,
        denied_errno: i32,
        forbidden_side_effect_count: u32,
    },
    CapabilitiesRemoved {
        effective: Vec<u32>,
        permitted: Vec<u32>,
        inheritable: Vec<u32>,
        ambient: Vec<u32>,
        bounding: Vec<u32>,
    },
    NoNewPrivs {
        facts: linux_no_new_privs::LinuxNoNewPrivsObservationFactsV1,
    },
    CgroupMembership {
        expected_cgroup_sha256: String,
        observed_cgroup_sha256: String,
        target_membership_count: u32,
        foreign_membership_count: u32,
    },
    PidfdProcessTreeCleanup {
        pidfd_wait_observed: bool,
        cgroup_kill_observed: bool,
        cgroup_events_populated: bool,
        cgroup_procs_member_count: u32,
        proc_descendant_count: u32,
        independent_zero_observation_count: u32,
    },
}

impl NativeCaseObservationV1 {
    #[allow(
        clippy::too_many_lines,
        reason = "closed case-specific validation keeps every independently observed Gate-1 fact explicit"
    )]
    fn validate_for(
        &self,
        expected_case_id: &str,
        binding: &NativeAdmissionBindingV1,
    ) -> Result<(), NativeAdmissionError> {
        let binding_sha256 = binding.digest()?;
        match (expected_case_id, self) {
            (
                "native_evidence_only_authority_sealed",
                Self::EvidenceOnlyAuthoritySealed {
                    binding_sha256: observed_binding,
                    fixed_input_ids_in_order,
                    forbidden_shape_sha256,
                    rejected_before_effect,
                    accepted_workspace_objective_or_command_count,
                    provider_credential_count,
                    ordinary_authority_mint_count,
                    native_invocation_count,
                },
            ) => {
                let expected_inputs = FIXED_INPUT_IDS.map(str::to_owned);
                if observed_binding != &binding_sha256
                    || fixed_input_ids_in_order != &expected_inputs
                    || forbidden_shape_sha256 != &forbidden_product_shape_digest()
                    || !rejected_before_effect
                    || *accepted_workspace_objective_or_command_count != 0
                    || *provider_credential_count != 0
                    || *ordinary_authority_mint_count != 0
                    || *native_invocation_count != 0
                {
                    return Err(invalid(
                        "sealed evidence-only observation accepted product work, credentials, effects, or authority",
                    ));
                }
            }
            (
                "linux_bubblewrap_namespace_canary",
                Self::BubblewrapNamespace {
                    host_user_namespace_id,
                    child_user_namespace_id,
                    host_mount_namespace_id,
                    child_mount_namespace_id,
                    host_pid_namespace_id,
                    child_pid_namespace_id,
                    host_network_namespace_id,
                    child_network_namespace_id,
                    host_ipc_namespace_id,
                    child_ipc_namespace_id,
                    host_uts_namespace_id,
                    child_uts_namespace_id,
                    host_cgroup_namespace_id,
                    child_cgroup_namespace_id,
                    forbidden_host_root_visible,
                    nested_namespace_mount_denied_errno,
                    forbidden_side_effect_count,
                },
            ) => {
                if *host_user_namespace_id == 0
                    || *child_user_namespace_id == 0
                    || host_user_namespace_id == child_user_namespace_id
                    || *host_mount_namespace_id == 0
                    || *child_mount_namespace_id == 0
                    || host_mount_namespace_id == child_mount_namespace_id
                    || *host_pid_namespace_id == 0
                    || *child_pid_namespace_id == 0
                    || host_pid_namespace_id == child_pid_namespace_id
                    || *host_network_namespace_id == 0
                    || *child_network_namespace_id == 0
                    || host_network_namespace_id == child_network_namespace_id
                    || *host_ipc_namespace_id == 0
                    || *child_ipc_namespace_id == 0
                    || host_ipc_namespace_id == child_ipc_namespace_id
                    || *host_uts_namespace_id == 0
                    || *child_uts_namespace_id == 0
                    || host_uts_namespace_id == child_uts_namespace_id
                    || *host_cgroup_namespace_id == 0
                    || *child_cgroup_namespace_id == 0
                    || host_cgroup_namespace_id == child_cgroup_namespace_id
                    || *forbidden_host_root_visible
                    || *nested_namespace_mount_denied_errno != 1
                    || *forbidden_side_effect_count != 0
                {
                    return Err(invalid(
                        "Bubblewrap namespace identities or forbidden-operation readback failed",
                    ));
                }
            }
            (
                "linux_landlock_canary",
                Self::LandlockDenial {
                    ruleset_sha256,
                    probe_id,
                    denied_errno,
                    forbidden_side_effect_count,
                },
            ) => {
                if ruleset_sha256 != &expected_landlock_ruleset_digest(binding)?
                    || probe_id != "landlock-outside-root-write"
                    || *denied_errno != 13
                    || *forbidden_side_effect_count != 0
                {
                    return Err(invalid(
                        "Landlock denial errno, probe, or zero-side-effect readback failed",
                    ));
                }
            }
            (
                "linux_seccomp_canary",
                Self::SeccompDenial {
                    program_sha256,
                    forbidden_syscall_number,
                    denied_errno,
                    forbidden_side_effect_count,
                },
            ) => {
                if program_sha256 != &expected_seccomp_program_digest(binding)?
                    || *forbidden_syscall_number != SECCOMP_FORBIDDEN_SYSCALL_X86_64
                    || *denied_errno != 1
                    || *forbidden_side_effect_count != 0
                {
                    return Err(invalid(
                        "seccomp program, denial errno, or zero-side-effect readback failed",
                    ));
                }
            }
            (
                "linux_capabilities_removed",
                Self::CapabilitiesRemoved {
                    effective,
                    permitted,
                    inheritable,
                    ambient,
                    bounding,
                },
            ) => {
                if !effective.is_empty()
                    || !permitted.is_empty()
                    || !inheritable.is_empty()
                    || !ambient.is_empty()
                    || !bounding.is_empty()
                {
                    return Err(invalid("one or more child capability sets are nonempty"));
                }
            }
            ("linux_no_new_privs", Self::NoNewPrivs { facts }) => {
                let fixed_input = binding.fixed_inputs_in_order.get(5).ok_or_else(|| {
                    invalid("no-new-privs fixed input is absent from the sealed binding")
                })?;
                facts
                    .validate_for(&binding_sha256, &fixed_input.sha256)
                    .map_err(|error| invalid(error.to_string()))?;
            }
            (
                "linux_cgroup_v2_membership",
                Self::CgroupMembership {
                    expected_cgroup_sha256,
                    observed_cgroup_sha256,
                    target_membership_count,
                    foreign_membership_count,
                },
            ) => {
                if expected_cgroup_sha256 != &expected_cgroup_identity_digest(binding)?
                    || expected_cgroup_sha256 != observed_cgroup_sha256
                    || *target_membership_count != 1
                    || *foreign_membership_count != 0
                {
                    return Err(invalid(
                        "target cgroup identity or exact membership readback failed",
                    ));
                }
            }
            (
                "linux_pidfd_process_tree_cleanup",
                Self::PidfdProcessTreeCleanup {
                    pidfd_wait_observed,
                    cgroup_kill_observed,
                    cgroup_events_populated,
                    cgroup_procs_member_count,
                    proc_descendant_count,
                    independent_zero_observation_count,
                },
            ) => {
                if !pidfd_wait_observed
                    || !cgroup_kill_observed
                    || *cgroup_events_populated
                    || *cgroup_procs_member_count != 0
                    || *proc_descendant_count != 0
                    || *independent_zero_observation_count != 2
                {
                    return Err(invalid(
                        "pidfd/cgroup cleanup did not produce two independent zero-survivor observations",
                    ));
                }
            }
            _ => {
                return Err(invalid(format!(
                    "typed observation variant crossed native case {expected_case_id}"
                )));
            }
        }
        Ok(())
    }

    fn product_mint_rejection(&self) -> Result<ProductMintRejectionV1, NativeAdmissionError> {
        let Self::EvidenceOnlyAuthoritySealed {
            forbidden_shape_sha256,
            rejected_before_effect,
            ordinary_authority_mint_count,
            native_invocation_count,
            ..
        } = self
        else {
            return Err(invalid(
                "product-mint rejection must derive from the sealed-authority observation",
            ));
        };
        let mut rejection = ProductMintRejectionV1 {
            probe_id: FORBIDDEN_PRODUCT_PROBE_ID.into(),
            forbidden_shape_sha256: forbidden_shape_sha256.clone(),
            rejected_before_effect: *rejected_before_effect,
            ordinary_authority_mint_count: *ordinary_authority_mint_count,
            native_invocation_count: *native_invocation_count,
            observation_sha256: String::new(),
        };
        rejection.observation_sha256 = rejection.digest()?;
        Ok(rejection)
    }
}

fn decode_case_observation(bytes: &[u8]) -> Result<NativeCaseObservationV1, NativeAdmissionError> {
    if bytes.is_empty() || bytes.len() > 64 * 1_024 {
        return Err(invalid(
            "typed native observation exceeds its exact byte bound",
        ));
    }
    let observation: NativeCaseObservationV1 = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("cannot decode typed native observation: {error}")))?;
    if canonical_bytes(&observation)? != bytes {
        return Err(invalid("typed native observation is not canonical JSON"));
    }
    Ok(observation)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeCaseOutcomeV1 {
    Passed,
    Failed,
    Skipped,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeCaseEvidenceV1 {
    case_id: String,
    fixture_spec_id: String,
    binding_sha256: String,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    exit_code: i32,
    outcome: NativeCaseOutcomeV1,
    typed_observation: BoundArtifactV1,
    stdout: BoundArtifactV1,
    stderr: BoundArtifactV1,
    evidence_sha256: String,
}

#[derive(Serialize)]
struct NativeCaseEvidencePreimage<'a> {
    case_id: &'a str,
    fixture_spec_id: &'a str,
    binding_sha256: &'a str,
    started_unix_ms: u64,
    finished_unix_ms: u64,
    exit_code: i32,
    outcome: NativeCaseOutcomeV1,
    typed_observation: &'a BoundArtifactV1,
    stdout: &'a BoundArtifactV1,
    stderr: &'a BoundArtifactV1,
}

impl NativeCaseEvidenceV1 {
    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(
            CASE_EVIDENCE_DOMAIN,
            &NativeCaseEvidencePreimage {
                case_id: &self.case_id,
                fixture_spec_id: &self.fixture_spec_id,
                binding_sha256: &self.binding_sha256,
                started_unix_ms: self.started_unix_ms,
                finished_unix_ms: self.finished_unix_ms,
                exit_code: self.exit_code,
                outcome: self.outcome,
                typed_observation: &self.typed_observation,
                stdout: &self.stdout,
                stderr: &self.stderr,
            },
        )
    }

    fn validate(
        &self,
        expected_case: (&str, &str),
        binding_sha256: &str,
    ) -> Result<(), NativeAdmissionError> {
        if self.case_id != expected_case.0
            || self.fixture_spec_id != expected_case.1
            || self.binding_sha256 != binding_sha256
            || self.started_unix_ms == 0
            || self.finished_unix_ms < self.started_unix_ms
            || self.exit_code != 0
            || self.outcome != NativeCaseOutcomeV1::Passed
            || self.evidence_sha256 != self.digest()?
        {
            return Err(invalid(format!(
                "native case {} has crossed identity, outcome, timing, or evidence digest",
                expected_case.0
            )));
        }
        for (artifact, kind, suffix) in [
            (
                &self.typed_observation,
                BoundArtifactKindV1::TypedObservation,
                "observation",
            ),
            (&self.stdout, BoundArtifactKindV1::StandardOutput, "stdout"),
            (&self.stderr, BoundArtifactKindV1::StandardError, "stderr"),
        ] {
            artifact.validate()?;
            if artifact.kind != kind
                || artifact.object_id != format!("{}-{suffix}", expected_case.0)
            {
                return Err(invalid(format!(
                    "native case {} crossed its {suffix} artifact",
                    expected_case.0
                )));
            }
        }
        require_pairwise_distinct_artifacts(vec![
            &self.typed_observation,
            &self.stdout,
            &self.stderr,
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductMintRejectionV1 {
    probe_id: String,
    forbidden_shape_sha256: String,
    rejected_before_effect: bool,
    ordinary_authority_mint_count: u32,
    native_invocation_count: u32,
    observation_sha256: String,
}

#[derive(Serialize)]
struct ProductMintRejectionPreimage<'a> {
    probe_id: &'a str,
    forbidden_shape_sha256: &'a str,
    rejected_before_effect: bool,
    ordinary_authority_mint_count: u32,
    native_invocation_count: u32,
}

impl ProductMintRejectionV1 {
    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(
            PRODUCT_MINT_REJECTION_DOMAIN,
            &ProductMintRejectionPreimage {
                probe_id: &self.probe_id,
                forbidden_shape_sha256: &self.forbidden_shape_sha256,
                rejected_before_effect: self.rejected_before_effect,
                ordinary_authority_mint_count: self.ordinary_authority_mint_count,
                native_invocation_count: self.native_invocation_count,
            },
        )
    }

    fn validate_shape(&self) -> Result<(), NativeAdmissionError> {
        if self.probe_id != FORBIDDEN_PRODUCT_PROBE_ID
            || self.forbidden_shape_sha256 != forbidden_product_shape_digest()
            || !self.rejected_before_effect
            || self.ordinary_authority_mint_count != 0
            || self.native_invocation_count != 0
            || self.observation_sha256 != self.digest()?
        {
            return Err(invalid(
                "arbitrary product-work probe was not rejected before every effect and mint",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceOnlyRecordV1 {
    schema: String,
    binding: NativeAdmissionBindingV1,
    binding_sha256: String,
    evidence_only_capability_sha256: String,
    executor_invocation_id: String,
    product_mint_rejection: ProductMintRejectionV1,
    cases_in_order: Vec<NativeCaseEvidenceV1>,
    aggregate_evidence_sha256: String,
}

#[derive(Serialize)]
struct EvidenceOnlyRecordPreimage<'a> {
    schema: &'a str,
    binding: &'a NativeAdmissionBindingV1,
    binding_sha256: &'a str,
    evidence_only_capability_sha256: &'a str,
    executor_invocation_id: &'a str,
    product_mint_rejection: &'a ProductMintRejectionV1,
    cases_in_order: &'a [NativeCaseEvidenceV1],
}

impl EvidenceOnlyRecordV1 {
    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(
            EVIDENCE_ONLY_RECORD_DOMAIN,
            &EvidenceOnlyRecordPreimage {
                schema: &self.schema,
                binding: &self.binding,
                binding_sha256: &self.binding_sha256,
                evidence_only_capability_sha256: &self.evidence_only_capability_sha256,
                executor_invocation_id: &self.executor_invocation_id,
                product_mint_rejection: &self.product_mint_rejection,
                cases_in_order: &self.cases_in_order,
            },
        )
    }

    fn validate(&self) -> Result<(), NativeAdmissionError> {
        self.binding.validate()?;
        let expected_binding = self.binding.digest()?;
        if self.schema != EVIDENCE_ONLY_RECORD_SCHEMA
            || self.binding_sha256 != expected_binding
            || self.evidence_only_capability_sha256 != expected_binding
            || self.aggregate_evidence_sha256 != self.digest()?
        {
            return Err(invalid(
                "evidence-only record schema, binding, capability, or aggregate digest crossed",
            ));
        }
        require_identifier("executor invocation ID", &self.executor_invocation_id)?;
        self.product_mint_rejection.validate_shape()?;
        if self.cases_in_order.len() != PRE_ADMISSION_CASES.len()
            || self
                .cases_in_order
                .iter()
                .zip(PRE_ADMISSION_CASES)
                .any(|(case, expected)| {
                    case.case_id != expected.0 || case.fixture_spec_id != expected.1
                })
        {
            return Err(invalid(
                "pre-admission case IDs/specs are missing, extra, duplicated, crossed, or reordered",
            ));
        }
        for (case, expected) in self.cases_in_order.iter().zip(PRE_ADMISSION_CASES) {
            case.validate(expected, &self.binding_sha256)?;
        }
        let artifacts = self
            .cases_in_order
            .iter()
            .flat_map(|case| [&case.typed_observation, &case.stdout, &case.stderr])
            .collect::<Vec<_>>();
        require_pairwise_distinct_artifacts(artifacts)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidatorIdentityV1 {
    executable: BoundArtifactV1,
    invocation_id: String,
    validator_contract_sha256: String,
}

impl ValidatorIdentityV1 {
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        self.executable.validate()?;
        if self.executable.object_id != "independent-validator"
            || self.executable.kind != BoundArtifactKindV1::ValidatorExecutable
        {
            return Err(invalid("independent validator executable role crossed"));
        }
        require_identifier("validator invocation ID", &self.invocation_id)?;
        let expected = domain_digest(
            VALIDATOR_CONTRACT_DOMAIN,
            b"exact-eight-cases\0raw-artifacts\0live-bindings\0no-replace-readback\0",
        );
        if self.validator_contract_sha256 != expected {
            return Err(invalid("independent validator contract digest crossed"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductionAdmissionRecordV1 {
    schema: String,
    binding: NativeAdmissionBindingV1,
    binding_sha256: String,
    evidence_only_record_sha256: String,
    ordered_case_evidence_sha256: Vec<String>,
    rejected_product_mint_observation_sha256: String,
    validator: ValidatorIdentityV1,
    admitted_at_unix_ms: u64,
    admission_sha256: String,
}

#[derive(Serialize)]
struct ProductionAdmissionRecordPreimage<'a> {
    schema: &'a str,
    binding: &'a NativeAdmissionBindingV1,
    binding_sha256: &'a str,
    evidence_only_record_sha256: &'a str,
    ordered_case_evidence_sha256: &'a [String],
    rejected_product_mint_observation_sha256: &'a str,
    validator: &'a ValidatorIdentityV1,
    admitted_at_unix_ms: u64,
}

impl ProductionAdmissionRecordV1 {
    fn digest(&self) -> Result<String, NativeAdmissionError> {
        canonical_digest(
            PRODUCTION_ADMISSION_DOMAIN,
            &ProductionAdmissionRecordPreimage {
                schema: &self.schema,
                binding: &self.binding,
                binding_sha256: &self.binding_sha256,
                evidence_only_record_sha256: &self.evidence_only_record_sha256,
                ordered_case_evidence_sha256: &self.ordered_case_evidence_sha256,
                rejected_product_mint_observation_sha256: &self
                    .rejected_product_mint_observation_sha256,
                validator: &self.validator,
                admitted_at_unix_ms: self.admitted_at_unix_ms,
            },
        )
    }

    fn validate(&self) -> Result<(), NativeAdmissionError> {
        self.binding.validate()?;
        self.validator.validate()?;
        if self.schema != PRODUCTION_ADMISSION_RECORD_SCHEMA
            || self.binding_sha256 != self.binding.digest()?
            || self.admitted_at_unix_ms == 0
            || self.ordered_case_evidence_sha256.len() != PRE_ADMISSION_CASES.len()
            || self.admission_sha256 != self.digest()?
        {
            return Err(invalid(
                "production-admission record schema, binding, case set, time, or digest crossed",
            ));
        }
        require_digest("evidence-only record", &self.evidence_only_record_sha256)?;
        require_digest(
            "rejected product mint observation",
            &self.rejected_product_mint_observation_sha256,
        )?;
        for digest in &self.ordered_case_evidence_sha256 {
            require_digest("case evidence", digest)?;
        }
        Ok(())
    }
}

fn decode_evidence_only_record(bytes: &[u8]) -> Result<EvidenceOnlyRecordV1, NativeAdmissionError> {
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > MAX_RECORD_BYTES)
    {
        return Err(invalid("evidence-only record exceeds its byte bound"));
    }
    let record: EvidenceOnlyRecordV1 = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("cannot decode evidence-only record: {error}")))?;
    if canonical_bytes(&record)? != bytes {
        return Err(invalid("evidence-only record is not exact canonical JSON"));
    }
    record.validate()?;
    Ok(record)
}

fn decode_production_admission_record(
    bytes: &[u8],
) -> Result<ProductionAdmissionRecordV1, NativeAdmissionError> {
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > MAX_RECORD_BYTES)
    {
        return Err(invalid(
            "production-admission record exceeds its byte bound",
        ));
    }
    let record: ProductionAdmissionRecordV1 = serde_json::from_slice(bytes).map_err(|error| {
        invalid(format!(
            "cannot decode production-admission record: {error}"
        ))
    })?;
    let canonical = canonical_bytes(&record)?;
    if canonical != bytes {
        return Err(invalid(
            "production-admission record is not exact canonical JSON",
        ));
    }
    record.validate()?;
    Ok(record)
}

struct RetainedArtifact {
    root: File,
    name: PathBuf,
    binding: BoundArtifactV1,
    descriptor: File,
}

impl RetainedArtifact {
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        self.binding.validate()?;
        let observed =
            observe_artifact(&self.descriptor, &self.binding.object_id, self.binding.kind)?;
        if observed != self.binding {
            return Err(invalid(format!(
                "retained artifact {} changed after admission",
                self.binding.object_id
            )));
        }
        let named = openat(
            &self.root,
            &self.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            invalid(format!(
                "cannot reopen named artifact {}: {error}",
                self.binding.object_id
            ))
        })?;
        let named_observation =
            observe_artifact(&named, &self.binding.object_id, self.binding.kind)?;
        if named_observation != self.binding {
            return Err(invalid(format!(
                "named artifact {} was replaced or crossed",
                self.binding.object_id
            )));
        }
        Ok(())
    }
}

struct RetainedArtifactSet {
    artifacts: Vec<RetainedArtifact>,
}

impl RetainedArtifactSet {
    fn validate_exact(&self, expected: Vec<&BoundArtifactV1>) -> Result<(), NativeAdmissionError> {
        if self.artifacts.len() != expected.len() {
            return Err(invalid("retained artifact set is missing or extra"));
        }
        for (retained, binding) in self.artifacts.iter().zip(expected) {
            if &retained.binding != binding {
                return Err(invalid("retained artifact role or identity crossed"));
            }
            retained.validate()?;
        }
        require_pairwise_distinct_artifacts(
            self.artifacts.iter().map(|item| &item.binding).collect(),
        )
    }

    fn validate_all(&self) -> Result<(), NativeAdmissionError> {
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        require_pairwise_distinct_artifacts(
            self.artifacts.iter().map(|item| &item.binding).collect(),
        )
    }
}

struct EvidenceOnlyCasePermit {
    case_id: String,
    fixture_spec_id: String,
    binding_sha256: String,
    fixed_input: BoundArtifactV1,
}

impl EvidenceOnlyCasePermit {
    fn validate_for(
        &self,
        binding: &NativeAdmissionBindingV1,
        index: usize,
    ) -> Result<(), NativeAdmissionError> {
        let expected_case = PRE_ADMISSION_CASES
            .get(index)
            .ok_or_else(|| invalid("evidence-only case permit index is outside the closed set"))?;
        let expected_input = binding.fixed_inputs_in_order.get(index).ok_or_else(|| {
            invalid("evidence-only case permit fixed input is outside the closed set")
        })?;
        if self.case_id != expected_case.0
            || self.fixture_spec_id != expected_case.1
            || self.binding_sha256 != binding.digest()?
            || self.fixed_input != *expected_input
        {
            return Err(invalid(format!(
                "evidence-only case permit {} crossed its sealed binding or fixed input",
                expected_case.0
            )));
        }
        Ok(())
    }
}

struct EvidenceOnlyCasePermitSet {
    permits_in_order: [Option<EvidenceOnlyCasePermit>; PRE_ADMISSION_CASES.len()],
}

impl EvidenceOnlyCasePermitSet {
    fn sealed(binding: &NativeAdmissionBindingV1) -> Result<Self, NativeAdmissionError> {
        binding.validate()?;
        let binding_sha256 = binding.digest()?;
        let permits = PRE_ADMISSION_CASES
            .iter()
            .zip(&binding.fixed_inputs_in_order)
            .map(|((case_id, fixture_spec_id), fixed_input)| {
                Some(EvidenceOnlyCasePermit {
                    case_id: (*case_id).into(),
                    fixture_spec_id: (*fixture_spec_id).into(),
                    binding_sha256: binding_sha256.clone(),
                    fixed_input: fixed_input.clone(),
                })
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| invalid("evidence-only case permit set length crossed"))?;
        Ok(Self {
            permits_in_order: permits,
        })
    }

    fn validate_remaining(
        &self,
        binding: &NativeAdmissionBindingV1,
    ) -> Result<(), NativeAdmissionError> {
        for (index, permit) in self.permits_in_order.iter().enumerate() {
            if let Some(permit) = permit {
                permit.validate_for(binding, index)?;
            }
        }
        Ok(())
    }

    fn take(
        &mut self,
        binding: &NativeAdmissionBindingV1,
        index: usize,
    ) -> Result<EvidenceOnlyCasePermit, NativeAdmissionError> {
        self.validate_remaining(binding)?;
        self.permits_in_order
            .get_mut(index)
            .and_then(Option::take)
            .ok_or_else(|| invalid("evidence-only case permit is absent or already consumed"))
    }

    fn all_present(&self) -> bool {
        self.permits_in_order.iter().all(Option::is_some)
    }
}

struct EvidenceOnlyAuthority {
    binding: NativeAdmissionBindingV1,
    retained_inputs: RetainedArtifactSet,
    case_permits: EvidenceOnlyCasePermitSet,
}

impl EvidenceOnlyAuthority {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.binding.validate()?;
        self.retained_inputs
            .validate_exact(self.binding.all_artifacts())?;
        self.case_permits.validate_remaining(&self.binding)
    }

    fn observe_linux_no_new_privs(
        &mut self,
        store: LinuxNoNewPrivsObservationStore,
    ) -> Result<EvidenceOnlyNoNewPrivsObserved, NativeAdmissionError> {
        self.validate_retained()?;
        let permit = self.case_permits.take(&self.binding, 5)?;
        permit.validate_for(&self.binding, 5)?;
        let facts = linux_no_new_privs::collect(&permit.binding_sha256, &permit.fixed_input.sha256)
            .map_err(|error| invalid(error.to_string()))?;
        let observation = NativeCaseObservationV1::NoNewPrivs { facts };
        observation.validate_for("linux_no_new_privs", &self.binding)?;
        let canonical_observation_bytes = canonical_bytes(&observation)?;
        let retained = store.publish(&canonical_observation_bytes)?;
        let observed = EvidenceOnlyNoNewPrivsObserved {
            binding: self.binding.clone(),
            permit,
            observation,
            canonical_observation_bytes,
            retained,
        };
        observed.validate_retained()?;
        Ok(observed)
    }
}

struct LinuxNoNewPrivsObservationStore {
    path: PathBuf,
    directory: File,
    identity: BoundFileIdentityV1,
}

impl LinuxNoNewPrivsObservationStore {
    fn open(path: &Path) -> Result<Self, NativeAdmissionError> {
        let named = fs::symlink_metadata(path)
            .map_err(|error| invalid(format!("cannot inspect no-new-privs store: {error}")))?;
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot open no-new-privs store: {error}")))?;
        let identity = directory_identity(&directory)?;
        if !named.is_dir()
            || directory_identity_from_metadata(&named) != identity
            || identity.mode & 0o777 != 0o700
            || identity.owner_uid != rustix::process::geteuid().as_raw()
        {
            return Err(invalid(
                "no-new-privs store identity, owner, or mode is invalid",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            directory,
            identity,
        })
    }

    fn publish(
        self,
        canonical_observation_bytes: &[u8],
    ) -> Result<RetainedLinuxNoNewPrivsObservation, NativeAdmissionError> {
        let decoded = decode_case_observation(canonical_observation_bytes)?;
        if !matches!(decoded, NativeCaseObservationV1::NoNewPrivs { .. }) {
            return Err(invalid(
                "no-new-privs store received another case observation",
            ));
        }
        let opened = openat(
            &self.directory,
            Path::new(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o400),
        )
        .map_err(|error| {
            invalid(format!(
                "cannot no-replace publish no-new-privs observation: {error}"
            ))
        })?;
        let mut writer = File::from(opened);
        rustix::fs::fchmod(&writer, Mode::from_raw_mode(0o400)).map_err(|error| {
            invalid(format!(
                "cannot set exact no-new-privs observation mode: {error}"
            ))
        })?;
        writer
            .write_all(canonical_observation_bytes)
            .map_err(|error| invalid(format!("cannot write no-new-privs observation: {error}")))?;
        writer
            .sync_all()
            .map_err(|error| invalid(format!("cannot sync no-new-privs observation: {error}")))?;
        drop(writer);
        self.directory
            .sync_all()
            .map_err(|error| invalid(format!("cannot sync no-new-privs store: {error}")))?;
        let descriptor = openat(
            &self.directory,
            Path::new(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot reopen no-new-privs observation: {error}")))?;
        let binding = observe_artifact(
            &descriptor,
            "linux_no_new_privs-observation",
            BoundArtifactKindV1::TypedObservation,
        )?;
        if read_bounded(&descriptor, 64 * 1_024)? != canonical_observation_bytes {
            return Err(invalid(
                "no-new-privs observation exact reopen bytes differ",
            ));
        }
        let artifact = RetainedArtifact {
            root: self
                .directory
                .try_clone()
                .map_err(|error| invalid(format!("cannot retain no-new-privs store: {error}")))?,
            name: LINUX_NO_NEW_PRIVS_OBSERVATION_NAME.into(),
            binding,
            descriptor,
        };
        let retained = RetainedLinuxNoNewPrivsObservation {
            root_path: self.path,
            root: self.directory,
            root_identity: self.identity,
            artifact,
        };
        retained.validate()?;
        Ok(retained)
    }
}

struct RetainedLinuxNoNewPrivsObservation {
    root_path: PathBuf,
    root: File,
    root_identity: BoundFileIdentityV1,
    artifact: RetainedArtifact,
}

impl RetainedLinuxNoNewPrivsObservation {
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        if directory_identity(&self.root)? != self.root_identity
            || directory_identity_from_path(&self.root_path)? != self.root_identity
        {
            return Err(invalid("no-new-privs observation root was replaced"));
        }
        self.artifact.validate()
    }
}

struct EvidenceOnlyNoNewPrivsObserved {
    binding: NativeAdmissionBindingV1,
    permit: EvidenceOnlyCasePermit,
    observation: NativeCaseObservationV1,
    canonical_observation_bytes: Vec<u8>,
    retained: RetainedLinuxNoNewPrivsObservation,
}

impl EvidenceOnlyNoNewPrivsObserved {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.binding.validate()?;
        self.permit.validate_for(&self.binding, 5)?;
        self.observation
            .validate_for("linux_no_new_privs", &self.binding)?;
        let decoded = decode_case_observation(&self.canonical_observation_bytes)?;
        if decoded != self.observation
            || self.retained.artifact.binding.object_id != "linux_no_new_privs-observation"
            || self.retained.artifact.binding.kind != BoundArtifactKindV1::TypedObservation
            || read_bounded(&self.retained.artifact.descriptor, 64 * 1_024)?
                != self.canonical_observation_bytes
        {
            return Err(invalid(
                "retained genuine no-new-privs observation bytes or role crossed",
            ));
        }
        self.retained.validate()
    }
}

struct RetainedEvidenceOnlyCandidate {
    record: EvidenceOnlyRecordV1,
    canonical_record_bytes: Vec<u8>,
    record_artifact: RetainedArtifact,
    retained_inputs: RetainedArtifactSet,
    retained_evidence: RetainedArtifactSet,
}

impl RetainedEvidenceOnlyCandidate {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.record.validate()?;
        let decoded = decode_evidence_only_record(&self.canonical_record_bytes)?;
        if decoded != self.record
            || canonical_bytes(&decoded)? != self.canonical_record_bytes
            || self.record_artifact.binding.byte_length
                != u64::try_from(self.canonical_record_bytes.len())
                    .map_err(|_| invalid("evidence-only record length overflow"))?
            || self.record_artifact.binding.sha256
                != lowercase_hex(&Sha256::digest(&self.canonical_record_bytes))
        {
            return Err(invalid(
                "retained evidence-only record bytes or identity crossed",
            ));
        }
        self.record_artifact.validate()?;
        self.retained_inputs
            .validate_exact(self.record.binding.all_artifacts())?;
        let expected = self
            .record
            .cases_in_order
            .iter()
            .flat_map(|case| [&case.typed_observation, &case.stdout, &case.stderr])
            .collect::<Vec<_>>();
        self.retained_evidence.validate_exact(expected)
    }
}

struct IndependentValidatorAuthority {
    expected_binding: NativeAdmissionBindingV1,
    identity: ValidatorIdentityV1,
    retained_executable: RetainedArtifact,
}

impl IndependentValidatorAuthority {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.expected_binding.validate()?;
        self.identity.validate()?;
        if self.identity.executable != self.retained_executable.binding {
            return Err(invalid("validator retained executable identity crossed"));
        }
        self.retained_executable.validate()?;
        if self
            .expected_binding
            .all_artifacts()
            .iter()
            .any(|artifact| artifact.file == self.identity.executable.file)
        {
            return Err(invalid(
                "independent validator aliases a fixture input or executable",
            ));
        }
        Ok(())
    }
}

struct IndependentlyValidatedNativeAdmission {
    record: ProductionAdmissionRecordV1,
    evidence_only_record_bytes: Vec<u8>,
    retained_evidence_only_record: RetainedArtifact,
    retained_inputs: RetainedArtifactSet,
    retained_evidence: RetainedArtifactSet,
    retained_validator: RetainedArtifact,
}

impl IndependentlyValidatedNativeAdmission {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.record.validate()?;
        self.retained_evidence_only_record.validate()?;
        let evidence_only = decode_evidence_only_record(&self.evidence_only_record_bytes)?;
        if self.record.evidence_only_record_sha256
            != domain_digest(
                EVIDENCE_ONLY_RECORD_DOMAIN,
                &self.evidence_only_record_bytes,
            )
            || evidence_only.binding != self.record.binding
            || evidence_only.binding_sha256 != self.record.binding_sha256
            || evidence_only
                .cases_in_order
                .iter()
                .map(|case| case.evidence_sha256.clone())
                .collect::<Vec<_>>()
                != self.record.ordered_case_evidence_sha256
            || evidence_only.product_mint_rejection.observation_sha256
                != self.record.rejected_product_mint_observation_sha256
        {
            return Err(invalid(
                "evidence-only record digest or independently admitted identity changed",
            ));
        }
        self.retained_inputs
            .validate_exact(self.record.binding.all_artifacts())?;
        let expected_evidence = evidence_only
            .cases_in_order
            .iter()
            .flat_map(|case| [&case.typed_observation, &case.stdout, &case.stderr])
            .collect::<Vec<_>>();
        self.retained_evidence.validate_exact(expected_evidence)?;
        let independently_derived_rejection =
            independently_validate_case_observations(&evidence_only, &self.retained_evidence)?;
        if independently_derived_rejection != evidence_only.product_mint_rejection {
            return Err(invalid(
                "sealed-authority product rejection no longer matches typed observation bytes",
            ));
        }
        if self.retained_validator.binding != self.record.validator.executable {
            return Err(invalid("retained independent validator identity crossed"));
        }
        self.retained_validator.validate()
    }
}

fn independently_validate_native_admission(
    candidate: RetainedEvidenceOnlyCandidate,
    validator: IndependentValidatorAuthority,
    admitted_at_unix_ms: u64,
) -> Result<IndependentlyValidatedNativeAdmission, NativeAdmissionError> {
    candidate.validate_retained()?;
    validator.validate_retained()?;
    if candidate.record.binding != validator.expected_binding
        || candidate.record.executor_invocation_id == validator.identity.invocation_id
    {
        return Err(invalid(
            "candidate binding crossed the independent validator or reused its invocation",
        ));
    }
    let independently_derived_rejection =
        independently_validate_case_observations(&candidate.record, &candidate.retained_evidence)?;
    if independently_derived_rejection != candidate.record.product_mint_rejection {
        return Err(invalid(
            "product-mint rejection was not derived from the reopened sealed-authority observation",
        ));
    }
    let evidence_only_record_sha256 = domain_digest(
        EVIDENCE_ONLY_RECORD_DOMAIN,
        &candidate.canonical_record_bytes,
    );
    let ordered_case_evidence_sha256 = candidate
        .record
        .cases_in_order
        .iter()
        .map(|case| case.evidence_sha256.clone())
        .collect();
    let mut record = ProductionAdmissionRecordV1 {
        schema: PRODUCTION_ADMISSION_RECORD_SCHEMA.into(),
        binding: candidate.record.binding.clone(),
        binding_sha256: candidate.record.binding_sha256.clone(),
        evidence_only_record_sha256,
        ordered_case_evidence_sha256,
        rejected_product_mint_observation_sha256: candidate
            .record
            .product_mint_rejection
            .observation_sha256
            .clone(),
        validator: validator.identity.clone(),
        admitted_at_unix_ms,
        admission_sha256: String::new(),
    };
    record.admission_sha256 = record.digest()?;
    record.validate()?;
    let admission = IndependentlyValidatedNativeAdmission {
        record,
        evidence_only_record_bytes: candidate.canonical_record_bytes,
        retained_evidence_only_record: candidate.record_artifact,
        retained_inputs: candidate.retained_inputs,
        retained_evidence: candidate.retained_evidence,
        retained_validator: validator.retained_executable,
    };
    admission.validate_retained()?;
    Ok(admission)
}

fn independently_validate_case_observations(
    record: &EvidenceOnlyRecordV1,
    retained_evidence: &RetainedArtifactSet,
) -> Result<ProductMintRejectionV1, NativeAdmissionError> {
    if retained_evidence.artifacts.len() != PRE_ADMISSION_CASES.len() * 3 {
        return Err(invalid(
            "independent validator did not receive every exact case artifact",
        ));
    }
    let mut sealed_rejection = None;
    for (index, (case, expected)) in record
        .cases_in_order
        .iter()
        .zip(PRE_ADMISSION_CASES)
        .enumerate()
    {
        let observation_artifact = retained_evidence
            .artifacts
            .get(index * 3)
            .ok_or_else(|| invalid("typed observation artifact is absent"))?;
        if observation_artifact.binding != case.typed_observation {
            return Err(invalid(format!(
                "typed observation artifact crossed case {}",
                expected.0
            )));
        }
        observation_artifact.validate()?;
        let bytes = read_bounded(&observation_artifact.descriptor, 64 * 1_024)?;
        let observation = decode_case_observation(&bytes)?;
        observation.validate_for(expected.0, &record.binding)?;
        if index == 0 {
            sealed_rejection = Some(observation.product_mint_rejection()?);
        }
    }
    sealed_rejection.ok_or_else(|| invalid("sealed-authority observation is absent"))
}

struct RetainedPublishedRecord {
    root: File,
    root_path: PathBuf,
    root_identity: BoundFileIdentityV1,
    descriptor: File,
    identity: BoundFileIdentityV1,
    bytes: Vec<u8>,
}

impl RetainedPublishedRecord {
    fn validate(&self) -> Result<(), NativeAdmissionError> {
        let root_descriptor_identity = directory_identity(&self.root)?;
        let root_named_identity = directory_identity_from_path(&self.root_path)?;
        if root_descriptor_identity != self.root_identity
            || root_named_identity != self.root_identity
        {
            return Err(invalid("production-admission root was replaced"));
        }
        let descriptor_identity = file_identity(&self.descriptor)?;
        if descriptor_identity != self.identity {
            return Err(invalid("retained production-admission record changed"));
        }
        let named = openat(
            &self.root,
            Path::new(PRODUCTION_ADMISSION_RECORD_NAME),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| {
            invalid(format!(
                "cannot reopen production-admission record: {error}"
            ))
        })?;
        if file_identity(&named)? != self.identity
            || read_bounded(&named, MAX_RECORD_BYTES)? != self.bytes
        {
            return Err(invalid(
                "published production-admission record was replaced or changed",
            ));
        }
        Ok(())
    }
}

struct ProductionAdmitted {
    record: ProductionAdmissionRecordV1,
    record_sha256: String,
    published: RetainedPublishedRecord,
    validated: IndependentlyValidatedNativeAdmission,
}

impl ProductionAdmitted {
    const fn permits_ordinary_execution() -> bool {
        false
    }

    const fn permits_ordinary_authority_mint() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), NativeAdmissionError> {
        self.record.validate()?;
        self.validated.validate_retained()?;
        if self.record != self.validated.record
            || self.record_sha256
                != domain_digest(PRODUCTION_ADMISSION_DOMAIN, &self.published.bytes)
        {
            return Err(invalid(
                "production-admitted authority crossed its validated record",
            ));
        }
        self.published.validate()?;
        let decoded = decode_production_admission_record(&self.published.bytes)?;
        if decoded != self.record {
            return Err(invalid(
                "production-admission readback decoded to a crossed record",
            ));
        }
        Ok(())
    }
}

struct ProductionAdmissionStore {
    path: PathBuf,
    directory: File,
    identity: BoundFileIdentityV1,
}

impl ProductionAdmissionStore {
    fn open(path: &Path) -> Result<Self, NativeAdmissionError> {
        let named = fs::symlink_metadata(path).map_err(|error| {
            invalid(format!("cannot inspect production-admission root: {error}"))
        })?;
        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot open production-admission root: {error}")))?;
        let identity = directory_identity(&directory)?;
        if !named.is_dir()
            || directory_identity_from_metadata(&named) != identity
            || identity.mode & 0o777 != 0o700
            || identity.owner_uid != rustix::process::geteuid().as_raw()
        {
            return Err(invalid(
                "production-admission root identity, owner, or mode is invalid",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            directory,
            identity,
        })
    }

    fn publish(
        self,
        validated: IndependentlyValidatedNativeAdmission,
    ) -> Result<ProductionAdmitted, NativeAdmissionError> {
        validated.validate_retained()?;
        let bytes = canonical_bytes(&validated.record)?;
        #[cfg(target_os = "linux")]
        {
            self.publish_linux(validated, bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, validated, bytes);
            Err(invalid(
                "production native-admission publication is supported only by the Linux no-replace store",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn publish_linux(
        self,
        validated: IndependentlyValidatedNativeAdmission,
        bytes: Vec<u8>,
    ) -> Result<ProductionAdmitted, NativeAdmissionError> {
        let opened = openat(
            &self.directory,
            Path::new(PRODUCTION_ADMISSION_TEMP_NAME),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| invalid(format!("cannot create admission temporary: {error}")))?;
        let mut temporary = File::from(opened);
        temporary
            .write_all(&bytes)
            .map_err(|error| invalid(format!("cannot write admission temporary: {error}")))?;
        temporary
            .sync_all()
            .map_err(|error| invalid(format!("cannot sync admission temporary: {error}")))?;
        let temporary_identity = file_identity(&temporary)?;
        if temporary_identity.mode & 0o777 != 0o600 || temporary_identity.link_count != 1 {
            return Err(invalid("admission temporary identity or mode is invalid"));
        }
        renameat_with(
            &self.directory,
            Path::new(PRODUCTION_ADMISSION_TEMP_NAME),
            &self.directory,
            Path::new(PRODUCTION_ADMISSION_RECORD_NAME),
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            invalid(format!(
                "cannot publish production admission without replacement: {error}"
            ))
        })?;
        self.directory
            .sync_all()
            .map_err(|error| invalid(format!("cannot sync admission root: {error}")))?;
        let named = openat(
            &self.directory,
            Path::new(PRODUCTION_ADMISSION_RECORD_NAME),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot read back production admission: {error}")))?;
        if file_identity(&named)? != temporary_identity
            || read_bounded(&named, MAX_RECORD_BYTES)? != bytes
        {
            return Err(invalid("production-admission exact readback failed"));
        }
        let published = RetainedPublishedRecord {
            root: self
                .directory
                .try_clone()
                .map_err(|error| invalid(format!("cannot retain admission root: {error}")))?,
            root_path: self.path,
            root_identity: self.identity,
            descriptor: named,
            identity: temporary_identity,
            bytes,
        };
        let record = validated.record.clone();
        let record_sha256 = domain_digest(PRODUCTION_ADMISSION_DOMAIN, &published.bytes);
        let authority = ProductionAdmitted {
            record,
            record_sha256,
            published,
            validated,
        };
        authority.validate_retained()?;
        Ok(authority)
    }
}

fn require_pairwise_distinct_artifacts(
    artifacts: Vec<&BoundArtifactV1>,
) -> Result<(), NativeAdmissionError> {
    let mut object_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for artifact in artifacts {
        if !object_ids.insert(artifact.object_id.as_str())
            || !identities.insert((
                artifact.file.device,
                artifact.file.inode,
                artifact.file.mount_id,
            ))
        {
            return Err(invalid(
                "two native-admission artifact roles alias one object or object ID",
            ));
        }
    }
    Ok(())
}

fn observe_artifact(
    file: &File,
    object_id: &str,
    kind: BoundArtifactKindV1,
) -> Result<BoundArtifactV1, NativeAdmissionError> {
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("cannot inspect artifact {object_id}: {error}")))?;
    if !metadata.is_file() {
        return Err(invalid(format!(
            "artifact {object_id} is not one regular file"
        )));
    }
    let flags = rustix::io::fcntl_getfd(file.as_fd())
        .map_err(|error| invalid(format!("cannot inspect artifact CLOEXEC: {error}")))?;
    Ok(BoundArtifactV1 {
        object_id: object_id.into(),
        kind,
        file: file_identity_from_metadata(&metadata),
        byte_length: metadata.len(),
        sha256: lowercase_hex(&digest_file(file, metadata.len())?),
        close_on_exec: flags.contains(rustix::io::FdFlags::CLOEXEC),
    })
}

fn file_identity(file: &File) -> Result<BoundFileIdentityV1, NativeAdmissionError> {
    file.metadata()
        .map(|metadata| file_identity_from_metadata(&metadata))
        .map_err(|error| invalid(format!("cannot inspect retained file identity: {error}")))
}

fn file_identity_from_metadata(metadata: &fs::Metadata) -> BoundFileIdentityV1 {
    BoundFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
        // Synthetic and comparison-only records use the filesystem device as
        // the portable mount identity. The future Linux fixture mint must
        // replace this with its already-modeled unique statx mount ID.
        mount_id: metadata.dev(),
        file_type: if metadata.is_file() {
            BoundFileTypeV1::Regular
        } else if metadata.is_dir() {
            BoundFileTypeV1::Directory
        } else {
            BoundFileTypeV1::Other
        },
        mode: metadata.mode() & 0o7_777,
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        link_count: metadata.nlink(),
    }
}

fn directory_identity(directory: &File) -> Result<BoundFileIdentityV1, NativeAdmissionError> {
    directory
        .metadata()
        .map(|metadata| directory_identity_from_metadata(&metadata))
        .map_err(|error| invalid(format!("cannot inspect directory identity: {error}")))
}

fn directory_identity_from_path(path: &Path) -> Result<BoundFileIdentityV1, NativeAdmissionError> {
    fs::symlink_metadata(path)
        .map(|metadata| directory_identity_from_metadata(&metadata))
        .map_err(|error| invalid(format!("cannot inspect named directory identity: {error}")))
}

fn directory_identity_from_metadata(metadata: &fs::Metadata) -> BoundFileIdentityV1 {
    let mut identity = file_identity_from_metadata(metadata);
    // APFS may expose a child-count-like directory link count. File creation
    // must not look like replacement of the retained directory itself.
    identity.link_count = 0;
    identity
}

fn digest_file(file: &File, length: u64) -> Result<Vec<u8>, NativeAdmissionError> {
    if length == 0 || length > MAX_ARTIFACT_BYTES {
        return Err(invalid("artifact length is outside its exact bound"));
    }
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024];
    while offset < length {
        let remaining = length - offset;
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| invalid("artifact read length overflow"))?;
        let read = file
            .read_at(&mut buffer[..requested], offset)
            .map_err(|error| invalid(format!("cannot read artifact bytes: {error}")))?;
        if read == 0 {
            return Err(invalid("artifact truncated during digest readback"));
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| invalid("artifact offset overflow"))?)
            .ok_or_else(|| invalid("artifact offset overflow"))?;
    }
    Ok(hasher.finalize().to_vec())
}

fn read_bounded(file: &File, maximum: u64) -> Result<Vec<u8>, NativeAdmissionError> {
    let length = file
        .metadata()
        .map_err(|error| invalid(format!("cannot inspect bounded file: {error}")))?
        .len();
    if length == 0 || length > maximum {
        return Err(invalid("bounded file length is invalid"));
    }
    let capacity = usize::try_from(length).map_err(|_| invalid("bounded file is too large"))?;
    let mut bytes = vec![0_u8; capacity];
    let mut offset = 0_u64;
    while offset < length {
        let index = usize::try_from(offset).map_err(|_| invalid("bounded read offset overflow"))?;
        let read = file
            .read_at(&mut bytes[index..], offset)
            .map_err(|error| invalid(format!("cannot read bounded file: {error}")))?;
        if read == 0 {
            return Err(invalid("bounded file truncated during readback"));
        }
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| invalid("bounded read overflow"))?)
            .ok_or_else(|| invalid("bounded read overflow"))?;
    }
    Ok(bytes)
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, NativeAdmissionError> {
    serde_json::to_vec(value)
        .map_err(|error| invalid(format!("cannot encode canonical native admission: {error}")))
}

fn canonical_digest(domain: &[u8], value: &impl Serialize) -> Result<String, NativeAdmissionError> {
    Ok(domain_digest(domain, &canonical_bytes(value)?))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
    lowercase_hex(&hasher.finalize())
}

fn forbidden_product_shape_digest() -> String {
    domain_digest(
        b"grok-build/gate1/forbidden-product-shape/v1\0",
        b"workspace\0objective\0command\0provider-credential\0",
    )
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

fn require_digest(name: &str, digest: &str) -> Result<(), NativeAdmissionError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || digest.bytes().all(|byte| byte == b'0')
    {
        return Err(invalid(format!(
            "{name} digest is not one nonzero lowercase SHA-256 value"
        )));
    }
    Ok(())
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_identifier(name: &str, value: &str) -> Result<(), NativeAdmissionError> {
    require_bounded_text(name, value, 1, 160)?;
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
) -> Result<(), NativeAdmissionError> {
    if !(minimum..=maximum).contains(&value.len()) || value.contains('\0') {
        return Err(invalid(format!(
            "{name} length is outside {minimum}..={maximum} or contains NUL"
        )));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> NativeAdmissionError {
    NativeAdmissionError(message.into())
}

#[cfg(test)]
mod tests {
    include!("native_admission/tests/part_01.rs");
}
