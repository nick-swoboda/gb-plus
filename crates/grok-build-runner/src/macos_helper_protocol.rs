//! Strict, effect-free protocol contracts for the macOS dedicated-identity helper.
//!
//! This module validates the authenticated session, immutable launch request,
//! fixed three-account pool, and durable lifecycle records. It intentionally
//! contains no XPC, Service Management, credential-drop, Seatbelt, process
//! enumeration, signalling, or launch implementation. A request that passes
//! these checks is data suitable for the signed helper to consider; it is not
//! command-execution authority and is not containment evidence.

#![allow(dead_code)] // Integrated only after the signed helper transport exists.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
#[cfg(test)]
use std::marker::PhantomData;
use std::path::{Component, Path};

use crate::environment::is_secret_environment_name;
#[cfg(test)]
use grok_build_core::RunnerLaunchPreparationDisposition;
use grok_build_core::{
    CONTRACT_VERSION, Digest, LiveRunnerLaunchReleaseClaim, PersistedRunnerLaunchPreparation,
    RunnerLaunchPreparationAttempt, WorkerCleanupBackend,
};
use serde::{Deserialize, Serialize};

use crate::platform_launch::{
    MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES, PlatformLaunchBinding,
    decode_native_launch_preparation_evidence,
};

/// Protocol version that binds schema-v13 outer preparation and journaled release.
pub(crate) const MACOS_HELPER_PROTOCOL_VERSION: u32 = 2;
/// The v0.1 helper owns exactly the coordinator's maximum worker count.
pub(crate) const MACOS_EXECUTION_IDENTITY_COUNT: usize = 3;
/// Maximum canonical request size admitted by the helper.
pub(crate) const MAX_MACOS_HELPER_REQUEST_BYTES: usize = 64 * 1024;
/// Maximum argument count for one launch request.
pub(crate) const MAX_MACOS_HELPER_ARGV: usize = 256;
/// Maximum environment entry count for one launch request.
pub(crate) const MAX_MACOS_HELPER_ENVIRONMENT: usize = 128;
/// Maximum aggregate retained command output admitted by this protocol.
pub(crate) const MAX_MACOS_HELPER_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum processes admitted for one otherwise-unused execution identity.
pub(crate) const MAX_MACOS_HELPER_PROCESSES: u32 = 256;
/// Maximum raw process observations retained in one journal record.
pub(crate) const MAX_MACOS_PROCESS_OBSERVATIONS: usize = 64;
/// Maximum process identifiers retained in one observation.
pub(crate) const MAX_MACOS_OBSERVED_PROCESSES: usize = 256;
/// Maximum inherited child descriptors described by one immutable request.
pub(crate) const MAX_MACOS_HELPER_DESCRIPTORS: usize = 16;

const REQUEST_DOMAIN: &[u8] = b"grok-build.macos-helper-launch.v2\0";
const POOL_DOMAIN: &[u8] = b"grok-build.macos-helper-pool.v1\0";
const PROCESS_OBSERVATION_DOMAIN: &[u8] = b"grok-build.macos-process-observation.v1\0";
const DESCRIPTOR_BINDING_DOMAIN: &[u8] = b"grok-build.macos-helper-descriptors.v1\0";
const HELD_PREPARATION_EVIDENCE_DOMAIN: &[u8] =
    b"grok-build.macos-helper-held-preparation-evidence.v1\0";
const HELD_PREPARATION_NATIVE_BYTES_DOMAIN: &[u8] =
    b"grok-build.macos-helper-held-preparation-native-bytes.v1\0";
const RELEASE_EVIDENCE_DOMAIN: &[u8] = b"grok-build.macos-helper-release-evidence.v1\0";
const MAX_ID_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_TOTAL_ARGV_BYTES: usize = 32 * 1024;
const MAX_TOTAL_ENVIRONMENT_BYTES: usize = 16 * 1024;
const MIN_MACOS_LOCAL_UID: u32 = 501;

/// Network authority applied by the helper's immutable Seatbelt policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosHelperNetwork {
    Denied,
    Allowed,
}

/// An executable admitted by fixed helper policy rather than ambient lookup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "source")]
pub(crate) enum MacosExecutableIdentity {
    /// A verified regular file below the authenticated staged workspace.
    StagedWorkspace {
        relative_path: String,
        binary_digest: Digest,
    },
    /// One exact system toolchain binary compiled into the helper policy.
    SystemToolchain {
        policy_entry_id: String,
        binary_digest: Digest,
    },
}

impl MacosExecutableIdentity {
    fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        match self {
            Self::StagedWorkspace {
                relative_path,
                binary_digest: _,
            } => validate_relative_path("executable_identity.relative_path", relative_path),
            Self::SystemToolchain {
                policy_entry_id,
                binary_digest: _,
            } => validate_identifier("executable_identity.policy_entry_id", policy_entry_id),
        }
    }
}

/// Immutable join from the live core preparation claim to the native helper.
///
/// This value is expected state. Constructing it does not create a native
/// domain, prepare a held child, authorize release, or prove containment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperPreparationBinding {
    pub(crate) contract_version: u32,
    pub(crate) attempt_id: String,
    pub(crate) sprint_id: String,
    pub(crate) launch_id: String,
    pub(crate) runner_session_id: String,
    pub(crate) cleanup_effect_id: String,
    pub(crate) input_snapshot: Digest,
    pub(crate) native_journal_id: String,
    pub(crate) expected_platform_binding_digest: Digest,
    pub(crate) claimed_at_unix_ms: u64,
}

impl MacosHelperPreparationBinding {
    /// Derives the only admitted outer identity from a live claim's immutable
    /// attempt and the independently reconstructed platform expectation.
    pub(crate) fn try_from_authority(
        attempt: &RunnerLaunchPreparationAttempt,
        expected: &PlatformLaunchBinding,
    ) -> Result<Self, MacosHelperProtocolError> {
        attempt.validate().map_err(|_| {
            invalid(
                "preparation.attempt",
                "core preparation attempt failed contract validation",
            )
        })?;
        if attempt.sprint_id != expected.sprint_id()
            || attempt.launch_id != expected.launch_id()
            || attempt.cleanup_effect_id != expected.cleanup_effect_id()
            || attempt.expected_platform_binding_digest != *expected.binding_digest()
            || expected.platform_backend() != WorkerCleanupBackend::MacOsDedicatedIdentity
            || attempt.claimed_at_unix_ms < expected.cleanup_admitted_at_unix_ms()
        {
            return Err(invalid(
                "preparation.authority",
                "attempt and expected macOS platform launch binding differ",
            ));
        }
        let binding = Self {
            contract_version: attempt.contract_version,
            attempt_id: attempt.attempt_id.clone(),
            sprint_id: attempt.sprint_id.clone(),
            launch_id: attempt.launch_id.clone(),
            runner_session_id: expected.session_id().to_owned(),
            cleanup_effect_id: attempt.cleanup_effect_id.clone(),
            input_snapshot: expected.cleanup_intent().input_snapshot.clone(),
            native_journal_id: attempt.native_journal_id.clone(),
            expected_platform_binding_digest: attempt.expected_platform_binding_digest.clone(),
            claimed_at_unix_ms: attempt.claimed_at_unix_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(invalid(
                "preparation.contract_version",
                "outer preparation uses an unsupported contract version",
            ));
        }
        for (field, value) in [
            ("preparation.attempt_id", self.attempt_id.as_str()),
            ("preparation.sprint_id", self.sprint_id.as_str()),
            ("preparation.launch_id", self.launch_id.as_str()),
            (
                "preparation.runner_session_id",
                self.runner_session_id.as_str(),
            ),
            (
                "preparation.cleanup_effect_id",
                self.cleanup_effect_id.as_str(),
            ),
            (
                "preparation.native_journal_id",
                self.native_journal_id.as_str(),
            ),
        ] {
            validate_identifier(field, value)?;
        }
        if self.claimed_at_unix_ms == 0 {
            return Err(invalid(
                "preparation.claimed_at_unix_ms",
                "preparation claim time must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Fixed semantic role of one descriptor inherited by the held child setup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosChildDescriptorPurpose {
    StandardInput,
    StandardOutput,
    StandardError,
    HoldControl,
    SetupReport,
}

/// Exact descriptor slot and object identity admitted for child setup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosChildDescriptorBinding {
    pub(crate) target_fd: u32,
    pub(crate) purpose: MacosChildDescriptorPurpose,
    pub(crate) object_digest: Digest,
    pub(crate) inherited_through_exec: bool,
}

fn validate_descriptor_bindings(
    descriptors: &[MacosChildDescriptorBinding],
) -> Result<(), MacosHelperProtocolError> {
    if descriptors.len() != 5 || descriptors.len() > MAX_MACOS_HELPER_DESCRIPTORS {
        return Err(invalid(
            "request.descriptor_bindings",
            "held setup requires exactly the three standard and two control descriptors",
        ));
    }
    if descriptors
        .windows(2)
        .any(|pair| pair[0].target_fd >= pair[1].target_fd)
    {
        return Err(invalid(
            "request.descriptor_bindings",
            "descriptor targets must be strictly increasing and unique",
        ));
    }
    let expected = [
        (0, MacosChildDescriptorPurpose::StandardInput, true),
        (1, MacosChildDescriptorPurpose::StandardOutput, true),
        (2, MacosChildDescriptorPurpose::StandardError, true),
    ];
    for (index, (target_fd, purpose, inherited)) in expected.into_iter().enumerate() {
        let actual = &descriptors[index];
        if actual.target_fd != target_fd
            || actual.purpose != purpose
            || actual.inherited_through_exec != inherited
        {
            return Err(invalid(
                "request.descriptor_bindings.standard",
                "standard descriptor targets, roles, or exec inheritance differ",
            ));
        }
    }
    let controls = &descriptors[3..];
    if controls[0].target_fd < 3
        || controls[1].target_fd < 3
        || controls[0].purpose != MacosChildDescriptorPurpose::HoldControl
        || controls[1].purpose != MacosChildDescriptorPurpose::SetupReport
        || controls
            .iter()
            .any(|descriptor| descriptor.inherited_through_exec)
    {
        return Err(invalid(
            "request.descriptor_bindings.control",
            "held-control and setup-report descriptors must be distinct close-on-exec controls",
        ));
    }
    Ok(())
}

pub(crate) fn descriptor_bindings_digest(
    descriptors: &[MacosChildDescriptorBinding],
) -> Result<Digest, MacosHelperProtocolError> {
    validate_descriptor_bindings(descriptors)?;
    let canonical = serde_json::to_vec(descriptors).map_err(|error| {
        MacosHelperProtocolError::Encoding(format!("descriptor binding encoding failed: {error}"))
    })?;
    let mut bytes = Vec::with_capacity(DESCRIPTOR_BINDING_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(DESCRIPTOR_BINDING_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(Digest::sha256(&bytes))
}

/// Ownership and permission audit of one installed helper binary.
///
/// This is the half of local attestation the code-directory pin cannot supply.
/// A `cdhash` requirement proves that the running helper is byte-for-byte the
/// image the pin was recorded over; it says nothing about who was able to write
/// that image in the first place. The audit answers that: the installed binary
/// and the directory holding it must be owned by root or by the auditing user
/// and must deny write access to group and other, so the only principals who
/// can substitute the helper are principals who can already run code as the
/// installation's owner.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperInstallAudit {
    /// Real UID that performed the audit.
    pub(crate) auditing_uid: u32,
    /// Owning UID of the installed helper binary.
    pub(crate) binary_owner_uid: u32,
    /// Permission bits of the installed helper binary.
    pub(crate) binary_mode: u32,
    /// Owning UID of the directory the helper binary is installed in.
    pub(crate) directory_owner_uid: u32,
    /// Permission bits of that directory.
    pub(crate) directory_mode: u32,
}

/// Write bits that must be absent from an installed helper path.
const FOREIGN_WRITE_BITS: u32 = 0o022;

impl MacosHelperInstallAudit {
    /// Validates the install path against the local-attestation predicate.
    ///
    /// # Errors
    ///
    /// Fails when the binary or its directory is owned by a third party or
    /// grants write access to group or other.
    pub(crate) const fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        if self.binary_owner_uid != 0 && self.binary_owner_uid != self.auditing_uid {
            return Err(invalid(
                "session.attestation.binary_owner_uid",
                "the installed helper binary is owned by neither root nor the auditing user",
            ));
        }
        if self.binary_mode & FOREIGN_WRITE_BITS != 0 {
            return Err(invalid(
                "session.attestation.binary_mode",
                "the installed helper binary is writable by group or other",
            ));
        }
        if self.directory_owner_uid != 0 && self.directory_owner_uid != self.auditing_uid {
            return Err(invalid(
                "session.attestation.directory_owner_uid",
                "the helper install directory is owned by neither root nor the auditing user",
            ));
        }
        if self.directory_mode & FOREIGN_WRITE_BITS != 0 {
            return Err(invalid(
                "session.attestation.directory_mode",
                "the helper install directory is writable by group or other",
            ));
        }
        Ok(())
    }
}

/// Code identity verified at helper admission.
///
/// * [`Self::LocalCodeIdentity`]: an install-time `cdhash` requirement and a
///   successful [`MacosHelperInstallAudit::validate`] check.
/// * [`Self::PublisherCodeIdentity`]: local identity plus an Apple-anchored chain.
/// * [`Self::Unattested`]: no admissible identity.
///
/// Both attested kinds permit runtime admission. Durable records preserve which
/// kind was verified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub(crate) enum MacosHelperAttestation {
    /// No code identity was established for the helper. Never admitted.
    Unattested,
    /// `cdhash`-pinned local code identity with a verified install path.
    LocalCodeIdentity {
        /// Ownership and permission audit of the installed helper binary.
        install_audit: MacosHelperInstallAudit,
    },
    /// Local code identity plus an Apple-anchored publisher chain.
    PublisherCodeIdentity {
        /// Ownership and permission audit of the installed helper binary.
        install_audit: MacosHelperInstallAudit,
    },
}

impl MacosHelperAttestation {
    /// Whether this attestation claims Apple publisher attestation.
    ///
    /// The transport refuses such a claim unless the authenticated peer really
    /// is Apple-anchored; nothing else in the runtime predicate consults it.
    pub(crate) const fn claims_publisher(&self) -> bool {
        matches!(self, Self::PublisherCodeIdentity { .. })
    }

    /// The install audit this attestation rests on, when it has one.
    pub(crate) const fn install_audit(&self) -> Option<&MacosHelperInstallAudit> {
        match self {
            Self::Unattested => None,
            Self::LocalCodeIdentity { install_audit }
            | Self::PublisherCodeIdentity { install_audit } => Some(install_audit),
        }
    }

    /// Validates the attestation against the runtime admission predicate.
    ///
    /// # Errors
    ///
    /// Fails when nothing was attested, or when the install audit does not
    /// exclude untrusted writers.
    pub(crate) const fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        match self {
            Self::Unattested => Err(invalid(
                "session.attestation",
                "an unattested helper is never admitted: its loaded image was not pinned to an install-time code requirement",
            )),
            Self::LocalCodeIdentity { install_audit }
            | Self::PublisherCodeIdentity { install_audit } => install_audit.validate(),
        }
    }
}

/// Authenticated, immutable context returned for one single-request XPC session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperSession {
    pub(crate) protocol_version: u32,
    pub(crate) policy_version: u32,
    pub(crate) session_nonce: Digest,
    pub(crate) helper_binary_digest: Digest,
    pub(crate) helper_requirement_digest: Digest,
    pub(crate) client_binary_digest: Digest,
    pub(crate) client_requirement_digest: Digest,
    pub(crate) pool_record_digest: Digest,
    pub(crate) workspace_grant_hash: Digest,
    pub(crate) execution_policy_hash: Digest,
    pub(crate) command_network: MacosHelperNetwork,
    pub(crate) authenticated_at_unix_ms: u64,
    pub(crate) peer_requirement_matched: bool,
    /// What was actually verified about the helper's code identity.
    ///
    /// Both [`MacosHelperAttestation::LocalCodeIdentity`] and
    /// [`MacosHelperAttestation::PublisherCodeIdentity`] are admitted at
    /// runtime; only [`MacosHelperAttestation::Unattested`] is refused.
    pub(crate) attestation: MacosHelperAttestation,
}

impl MacosHelperSession {
    /// Validates local code identity and an install path protected from untrusted
    /// writers. Publisher attestation is optional and records additional provenance.
    ///
    /// # Errors
    ///
    /// Fails for invalid versions or timestamps, an unsatisfied peer requirement,
    /// an unattested helper or an unsafe install path.
    pub(crate) fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        if self.protocol_version != MACOS_HELPER_PROTOCOL_VERSION {
            return Err(invalid(
                "session.protocol_version",
                "unsupported helper protocol version",
            ));
        }
        if self.policy_version == 0 {
            return Err(invalid(
                "session.policy_version",
                "policy version must be nonzero",
            ));
        }
        if self.authenticated_at_unix_ms == 0 {
            return Err(invalid(
                "session.authenticated_at_unix_ms",
                "authenticated time must be nonzero",
            ));
        }
        if !self.peer_requirement_matched {
            return Err(invalid(
                "session.peer_identity",
                "the pinned helper code requirement was not satisfied",
            ));
        }
        self.attestation.validate()?;
        Ok(())
    }

    /// Compares durable signed authority while deliberately excluding the
    /// per-connection nonce and authentication timestamp.
    pub(crate) fn same_durable_authority(&self, other: &Self) -> bool {
        self.protocol_version == other.protocol_version
            && self.policy_version == other.policy_version
            && self.helper_binary_digest == other.helper_binary_digest
            && self.helper_requirement_digest == other.helper_requirement_digest
            && self.client_binary_digest == other.client_binary_digest
            && self.client_requirement_digest == other.client_requirement_digest
            && self.pool_record_digest == other.pool_record_digest
            && self.workspace_grant_hash == other.workspace_grant_hash
            && self.execution_policy_hash == other.execution_policy_hash
            && self.command_network == other.command_network
            && self.peer_requirement_matched == other.peer_requirement_matched
            && self.attestation == other.attestation
    }
}

/// Exact immutable launch request admitted by the signed helper.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperLaunchRequest {
    pub(crate) protocol_version: u32,
    pub(crate) policy_version: u32,
    pub(crate) session_nonce: Digest,
    pub(crate) request_id: String,
    pub(crate) preparation: MacosHelperPreparationBinding,
    pub(crate) runner_session_id: String,
    /// Exact command effect within the outer runner session.
    pub(crate) effect_id: String,
    pub(crate) workspace_grant_hash: Digest,
    pub(crate) execution_policy_hash: Digest,
    pub(crate) staged_workspace_id: String,
    pub(crate) executable_identity: MacosExecutableIdentity,
    pub(crate) descriptor_bindings: Vec<MacosChildDescriptorBinding>,
    pub(crate) argv: Vec<String>,
    pub(crate) relative_working_directory: String,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) deadline_unix_ms: u64,
    pub(crate) max_output_bytes: u64,
    pub(crate) max_processes: u32,
    pub(crate) max_memory_bytes: Option<u64>,
    pub(crate) command_network: MacosHelperNetwork,
    pub(crate) seatbelt_profile_digest: Digest,
    pub(crate) request_digest: Digest,
}

#[derive(Serialize)]
struct RequestDigestPreimage<'a> {
    protocol_version: u32,
    policy_version: u32,
    session_nonce: &'a Digest,
    request_id: &'a str,
    preparation: &'a MacosHelperPreparationBinding,
    runner_session_id: &'a str,
    effect_id: &'a str,
    workspace_grant_hash: &'a Digest,
    execution_policy_hash: &'a Digest,
    staged_workspace_id: &'a str,
    executable_identity: &'a MacosExecutableIdentity,
    descriptor_bindings: &'a [MacosChildDescriptorBinding],
    argv: &'a [String],
    relative_working_directory: &'a str,
    environment: &'a BTreeMap<String, String>,
    deadline_unix_ms: u64,
    max_output_bytes: u64,
    max_processes: u32,
    max_memory_bytes: Option<u64>,
    command_network: MacosHelperNetwork,
    seatbelt_profile_digest: &'a Digest,
}

impl MacosHelperLaunchRequest {
    /// Computes the domain-separated digest over every field except itself.
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosHelperProtocolError> {
        let preimage = RequestDigestPreimage {
            protocol_version: self.protocol_version,
            policy_version: self.policy_version,
            session_nonce: &self.session_nonce,
            request_id: &self.request_id,
            preparation: &self.preparation,
            runner_session_id: &self.runner_session_id,
            effect_id: &self.effect_id,
            workspace_grant_hash: &self.workspace_grant_hash,
            execution_policy_hash: &self.execution_policy_hash,
            staged_workspace_id: &self.staged_workspace_id,
            executable_identity: &self.executable_identity,
            descriptor_bindings: &self.descriptor_bindings,
            argv: &self.argv,
            relative_working_directory: &self.relative_working_directory,
            environment: &self.environment,
            deadline_unix_ms: self.deadline_unix_ms,
            max_output_bytes: self.max_output_bytes,
            max_processes: self.max_processes,
            max_memory_bytes: self.max_memory_bytes,
            command_network: self.command_network,
            seatbelt_profile_digest: &self.seatbelt_profile_digest,
        };
        let canonical = serde_json::to_vec(&preimage).map_err(|error| {
            MacosHelperProtocolError::Encoding(format!(
                "canonical request encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(REQUEST_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(REQUEST_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    /// Validates the complete retained request without making a current-time,
    /// authenticated-session, native-effect, or containment claim.
    pub(crate) fn validate_retained(&self) -> Result<(), MacosHelperProtocolError> {
        if self.protocol_version != MACOS_HELPER_PROTOCOL_VERSION {
            return Err(invalid(
                "request.protocol_version",
                "request uses an unsupported helper protocol version",
            ));
        }
        if self.policy_version == 0 {
            return Err(invalid(
                "request.policy_version",
                "policy version must be nonzero",
            ));
        }
        self.preparation.validate()?;
        if self.preparation.runner_session_id != self.runner_session_id {
            return Err(invalid(
                "request.runner_session_id",
                "command and outer preparation sessions differ",
            ));
        }
        for (field, value) in [
            ("request.request_id", self.request_id.as_str()),
            ("request.runner_session_id", self.runner_session_id.as_str()),
            ("request.effect_id", self.effect_id.as_str()),
            (
                "request.staged_workspace_id",
                self.staged_workspace_id.as_str(),
            ),
        ] {
            validate_identifier(field, value)?;
        }
        if !self
            .staged_workspace_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid(
                "request.staged_workspace_id",
                "workspace identity cannot contain path syntax",
            ));
        }
        self.executable_identity.validate()?;
        validate_descriptor_bindings(&self.descriptor_bindings)?;
        validate_relative_path(
            "request.relative_working_directory",
            &self.relative_working_directory,
        )?;
        validate_argv(&self.argv)?;
        validate_environment(&self.environment)?;
        if self.deadline_unix_ms == 0
            || self.deadline_unix_ms <= self.preparation.claimed_at_unix_ms
        {
            return Err(invalid(
                "request.deadline_unix_ms",
                "deadline must follow the durable outer preparation claim",
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_MACOS_HELPER_OUTPUT_BYTES {
            return Err(invalid(
                "request.max_output_bytes",
                "retained output limit is outside the admitted range",
            ));
        }
        if self.max_processes == 0 || self.max_processes > MAX_MACOS_HELPER_PROCESSES {
            return Err(invalid(
                "request.max_processes",
                "process limit is outside the admitted range",
            ));
        }
        if self.max_memory_bytes.is_some() {
            return Err(invalid(
                "request.max_memory_bytes",
                "native v0.1 cannot prove a finite aggregate memory ceiling",
            ));
        }
        if self.request_digest != self.computed_digest()? {
            return Err(invalid(
                "request.request_digest",
                "request digest does not bind the canonical complete preimage",
            ));
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            MacosHelperProtocolError::Encoding(format!("request encoding failed: {error}"))
        })?;
        if encoded.len() > MAX_MACOS_HELPER_REQUEST_BYTES {
            return Err(MacosHelperProtocolError::RequestTooLarge {
                bytes: encoded.len(),
            });
        }
        Ok(())
    }

    /// Validates the complete request against one authenticated helper session.
    pub(crate) fn validate_archived_session_binding(
        &self,
        session: &MacosHelperSession,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate_retained()?;
        session.validate()?;
        if self.protocol_version != session.protocol_version
            || self.policy_version != session.policy_version
            || self.session_nonce != session.session_nonce
            || self.workspace_grant_hash != session.workspace_grant_hash
            || self.execution_policy_hash != session.execution_policy_hash
            || self.command_network != session.command_network
        {
            return Err(invalid(
                "request.session_binding",
                "request differs from its authenticated admission session",
            ));
        }
        Ok(())
    }

    /// Validates the complete request against one authenticated helper session.
    pub(crate) fn validate_for_session(
        &self,
        session: &MacosHelperSession,
        now_unix_ms: u64,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate_archived_session_binding(session)?;
        if now_unix_ms == 0
            || self.deadline_unix_ms <= now_unix_ms
            || self.deadline_unix_ms <= session.authenticated_at_unix_ms
        {
            return Err(invalid(
                "request.deadline_unix_ms",
                "deadline must be unexpired and after session authentication",
            ));
        }
        Ok(())
    }

    /// Requires exact expected preparation state in addition to the signed
    /// session. This remains input validation, not native launch authority.
    pub(crate) fn validate_for_preparation(
        &self,
        session: &MacosHelperSession,
        expected: &MacosHelperPreparationBinding,
        now_unix_ms: u64,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate_for_session(session, now_unix_ms)?;
        expected.validate()?;
        if &self.preparation != expected {
            return Err(invalid(
                "request.preparation",
                "request substituted outer preparation authority",
            ));
        }
        Ok(())
    }
}

/// Decodes one byte-for-byte canonical request and validates its complete
/// authenticated session binding before any helper effect.
///
/// Structural decoding rejects duplicate and unknown fields. Exact
/// re-encoding additionally rejects alternate whitespace and field order, so
/// one request has only one admitted byte representation.
pub(crate) fn decode_canonical_launch_request(
    bytes: &[u8],
    session: &MacosHelperSession,
    expected: &MacosHelperPreparationBinding,
    now_unix_ms: u64,
) -> Result<MacosHelperLaunchRequest, MacosHelperProtocolError> {
    if bytes.len() > MAX_MACOS_HELPER_REQUEST_BYTES {
        return Err(MacosHelperProtocolError::RequestTooLarge { bytes: bytes.len() });
    }
    let request: MacosHelperLaunchRequest = serde_json::from_slice(bytes).map_err(|error| {
        MacosHelperProtocolError::Decoding(format!("request decoding failed: {error}"))
    })?;
    let canonical = serde_json::to_vec(&request).map_err(|error| {
        MacosHelperProtocolError::Encoding(format!("request encoding failed: {error}"))
    })?;
    if canonical != bytes {
        return Err(MacosHelperProtocolError::NonCanonicalRequest);
    }
    request.validate_for_preparation(session, expected, now_unix_ms)?;
    Ok(request)
}

/// One fixed, otherwise-unused local execution account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosExecutionIdentityRecord {
    pub(crate) account_name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) record_digest: Digest,
    pub(crate) login_shell: String,
    pub(crate) home_directory: String,
    pub(crate) supplementary_groups: Vec<u32>,
    pub(crate) password_locked: bool,
    pub(crate) interactive_session_count: u32,
}

impl MacosExecutionIdentityRecord {
    fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        validate_identifier("identity.account_name", &self.account_name)?;
        if self.uid < MIN_MACOS_LOCAL_UID || self.gid == 0 {
            return Err(invalid(
                "identity.numeric_ids",
                "execution UID/GID must be non-root local identities",
            ));
        }
        if !self.password_locked
            || self.interactive_session_count != 0
            || !self.supplementary_groups.is_empty()
        {
            return Err(invalid(
                "identity.login_authority",
                "execution account must be locked, unused, and groupless",
            ));
        }
        if !matches!(self.login_shell.as_str(), "/usr/bin/false" | "/bin/false") {
            return Err(invalid(
                "identity.login_shell",
                "execution account must have a non-login shell",
            ));
        }
        if self.home_directory.is_empty()
            || self.home_directory == "/"
            || self.home_directory.bytes().any(|byte| byte <= 0x20)
        {
            return Err(invalid(
                "identity.home_directory",
                "execution account must have one fixed non-root inert home identity",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct PoolDigestPreimage<'a> {
    records: &'a [MacosExecutionIdentityRecord],
}

/// Active observation of the exact fixed three-account pool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosIdentityPoolObservation {
    pub(crate) records: Vec<MacosExecutionIdentityRecord>,
    pub(crate) pool_record_digest: Digest,
}

impl MacosIdentityPoolObservation {
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosHelperProtocolError> {
        let mut records = self.records.clone();
        records.sort_by_key(|record| record.uid);
        let canonical =
            serde_json::to_vec(&PoolDigestPreimage { records: &records }).map_err(|error| {
                MacosHelperProtocolError::Encoding(format!(
                    "canonical pool encoding failed: {error}"
                ))
            })?;
        let mut bytes = Vec::with_capacity(POOL_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(POOL_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    pub(crate) fn validate_for_session(
        &self,
        session: &MacosHelperSession,
    ) -> Result<(), MacosHelperProtocolError> {
        session.validate()?;
        if self.records.len() != MACOS_EXECUTION_IDENTITY_COUNT {
            return Err(invalid(
                "identity_pool.records",
                "v0.1 requires exactly three execution identities",
            ));
        }
        let mut uids = BTreeSet::new();
        let mut gids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut record_digests = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !uids.insert(record.uid)
                || !gids.insert(record.gid)
                || !names.insert(record.account_name.as_str())
                || !record_digests.insert(record.record_digest.clone())
            {
                return Err(invalid(
                    "identity_pool.distinctness",
                    "account names, UIDs, GIDs, and record digests must be distinct",
                ));
            }
        }
        let computed = self.computed_digest()?;
        if self.pool_record_digest != computed || session.pool_record_digest != computed {
            return Err(invalid(
                "identity_pool.pool_record_digest",
                "active pool differs from the authenticated fixed pool",
            ));
        }
        Ok(())
    }
}

/// Durable helper request lifecycle. Transitions are monotonic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosHelperJournalState {
    Prepared,
    CleanupAgentIntended,
    LaunchIntended,
    HeldPrepared,
    ReleaseIntended,
    Released,
    Cleaning,
    EmptyProven,
    Cleaned,
    RejectedBeforeEffect,
}

impl MacosHelperJournalState {
    /// Returns whether one synchronized lifecycle record may be followed by
    /// `next` without skipping a pre-effect intent or cleanup proof.
    pub(crate) const fn allows_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::CleanupAgentIntended)
                | (Self::CleanupAgentIntended, Self::LaunchIntended)
                | (Self::LaunchIntended, Self::HeldPrepared | Self::Cleaning)
                | (Self::HeldPrepared, Self::ReleaseIntended | Self::Cleaning)
                | (Self::ReleaseIntended, Self::Released | Self::Cleaning)
                | (Self::Released, Self::Cleaning)
                | (Self::Cleaning, Self::EmptyProven)
                | (Self::EmptyProven, Self::Cleaned)
        )
    }
}

/// Why a launched identity domain entered irreversible cleanup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosTerminationReason {
    Exited,
    Canceled,
    TimedOut,
    OutputLimit,
    ClientDisconnected,
    HelperShutdown,
    SetupFailed,
    Recovery,
}

/// One process enumeration made by the privileged controller for an exact UID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosProcessObservation {
    pub(crate) sequence: u32,
    pub(crate) observed_at_unix_ms: u64,
    pub(crate) uid: u32,
    pub(crate) process_ids: Vec<u32>,
    pub(crate) enumeration_digest: Digest,
    pub(crate) creation_sealed: bool,
}

#[derive(Serialize)]
struct ProcessObservationDigestPreimage<'a> {
    sequence: u32,
    observed_at_unix_ms: u64,
    uid: u32,
    process_ids: &'a [u32],
    creation_sealed: bool,
}

impl MacosProcessObservation {
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosHelperProtocolError> {
        let canonical = serde_json::to_vec(&ProcessObservationDigestPreimage {
            sequence: self.sequence,
            observed_at_unix_ms: self.observed_at_unix_ms,
            uid: self.uid,
            process_ids: &self.process_ids,
            creation_sealed: self.creation_sealed,
        })
        .map_err(|error| {
            MacosHelperProtocolError::Encoding(format!(
                "process observation encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(PROCESS_OBSERVATION_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(PROCESS_OBSERVATION_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    pub(crate) fn validate(&self, expected_uid: u32) -> Result<(), MacosHelperProtocolError> {
        if self.sequence == 0 || self.observed_at_unix_ms == 0 || self.uid != expected_uid {
            return Err(invalid(
                "journal.process_observation",
                "sequence/time/UID does not identify the assigned domain",
            ));
        }
        if self.process_ids.len() > MAX_MACOS_OBSERVED_PROCESSES {
            return Err(invalid(
                "journal.process_observation.process_ids",
                "process observation exceeds the hard count bound",
            ));
        }
        if self.process_ids.contains(&0)
            || self.process_ids.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "journal.process_observation.process_ids",
                "process identifiers must be nonzero, sorted, and unique",
            ));
        }
        if self.enumeration_digest != self.computed_digest()? {
            return Err(invalid(
                "journal.process_observation.enumeration_digest",
                "enumeration digest differs from the canonical raw observation",
            ));
        }
        Ok(())
    }
}

/// Exact assigned account identity bound into a request journal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosAssignedIdentity {
    pub(crate) account_name: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) account_record_digest: Digest,
}

impl MacosAssignedIdentity {
    fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        validate_identifier("journal.assigned_identity.account_name", &self.account_name)?;
        if self.uid < MIN_MACOS_LOCAL_UID || self.gid == 0 {
            return Err(invalid(
                "journal.assigned_identity.numeric_ids",
                "assigned execution identity is invalid",
            ));
        }
        Ok(())
    }
}

/// Authenticated-session-bound candidate emitted after native setup readback
/// while the child is still held. Validation does not itself inspect macOS.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHeldPreparationEvidence {
    pub(crate) authenticated_session: MacosHelperSession,
    pub(crate) request_digest: Digest,
    pub(crate) preparation: MacosHelperPreparationBinding,
    pub(crate) assigned_identity: MacosAssignedIdentity,
    pub(crate) descriptor_bindings_digest: Digest,
    pub(crate) setup_readback_digest: Digest,
    pub(crate) held_at_unix_ms: u64,
    pub(crate) evidence_digest: Digest,
}

#[derive(Serialize)]
struct HeldPreparationEvidencePreimage<'a> {
    authenticated_session: &'a MacosHelperSession,
    request_digest: &'a Digest,
    preparation: &'a MacosHelperPreparationBinding,
    assigned_identity: &'a MacosAssignedIdentity,
    descriptor_bindings_digest: &'a Digest,
    setup_readback_digest: &'a Digest,
    held_at_unix_ms: u64,
}

impl MacosHeldPreparationEvidence {
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosHelperProtocolError> {
        let canonical = serde_json::to_vec(&HeldPreparationEvidencePreimage {
            authenticated_session: &self.authenticated_session,
            request_digest: &self.request_digest,
            preparation: &self.preparation,
            assigned_identity: &self.assigned_identity,
            descriptor_bindings_digest: &self.descriptor_bindings_digest,
            setup_readback_digest: &self.setup_readback_digest,
            held_at_unix_ms: self.held_at_unix_ms,
        })
        .map_err(|error| {
            MacosHelperProtocolError::Encoding(format!(
                "held-preparation evidence encoding failed: {error}"
            ))
        })?;
        let mut bytes =
            Vec::with_capacity(HELD_PREPARATION_EVIDENCE_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(HELD_PREPARATION_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    /// Exact bounded bytes the native preparation callback must return to
    /// core before release can become eligible.
    pub(crate) fn canonical_native_evidence_bytes(
        &self,
    ) -> Result<Vec<u8>, MacosHelperProtocolError> {
        let canonical = serde_json::to_vec(self).map_err(|error| {
            MacosHelperProtocolError::Encoding(format!(
                "held native evidence encoding failed: {error}"
            ))
        })?;
        let mut bytes =
            Vec::with_capacity(HELD_PREPARATION_NATIVE_BYTES_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(HELD_PREPARATION_NATIVE_BYTES_DOMAIN);
        bytes.extend_from_slice(&canonical);
        if bytes.len() > MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES {
            return Err(
                MacosHelperProtocolError::NativePreparationEvidenceTooLarge { bytes: bytes.len() },
            );
        }
        Ok(bytes)
    }

    fn validate_retained_for(
        &self,
        request: &MacosHelperLaunchRequest,
        assigned: &MacosAssignedIdentity,
    ) -> Result<(), MacosHelperProtocolError> {
        self.authenticated_session.validate()?;
        request.validate_archived_session_binding(&self.authenticated_session)?;
        assigned.validate()?;
        if self.request_digest != request.request_digest
            || self.preparation != request.preparation
            || &self.assigned_identity != assigned
            || self.descriptor_bindings_digest
                != descriptor_bindings_digest(&request.descriptor_bindings)?
            || self.held_at_unix_ms < self.authenticated_session.authenticated_at_unix_ms
            || self.held_at_unix_ms < self.preparation.claimed_at_unix_ms
            || self.held_at_unix_ms >= request.deadline_unix_ms
            || self.evidence_digest != self.computed_digest()?
        {
            return Err(invalid(
                "held_preparation_evidence.binding",
                "held preparation evidence differs from authenticated expected state",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_for(
        &self,
        session: &MacosHelperSession,
        request: &MacosHelperLaunchRequest,
        assigned: &MacosAssignedIdentity,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate_retained_for(request, assigned)?;
        request.validate_for_preparation(session, &self.preparation, self.held_at_unix_ms)?;
        if &self.authenticated_session != session {
            return Err(invalid(
                "held_preparation_evidence.binding",
                "held preparation evidence differs from authenticated expected state",
            ));
        }
        Ok(())
    }
}

/// Exact post-readback outer authorization required before release intent.
///
/// This is the durable audit record produced by callback-scoped live release
/// authority. Re-reading it does not recreate authority to release, and it is
/// not a claim that release or containment has occurred.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOuterReleaseAuthorizationRecord {
    pub(crate) contract_version: u32,
    pub(crate) preparation: MacosHelperPreparationBinding,
    /// Digest of the complete shared runner preparation envelope.
    pub(crate) outer_native_preparation_evidence_digest: Digest,
    /// Digest of the exact raw macOS helper evidence inside that envelope.
    pub(crate) held_service_evidence_digest: Digest,
    pub(crate) preparation_finished_at_unix_ms: u64,
    /// Trusted wall-clock observation made while the live core release claim
    /// was still held. The helper refuses authorization at the request
    /// deadline rather than treating the boundary as usable time.
    pub(crate) authorized_at_unix_ms: u64,
}

/// Callback-scoped, non-cloneable release authority tied to core's live
/// launch/cleanup exclusion.
pub(crate) struct MacosOuterReleaseAuthorization<'claim, 'ledger> {
    _claim: MacosReleaseAuthorityAnchor<'claim, 'ledger>,
    record: MacosOuterReleaseAuthorizationRecord,
}

enum MacosReleaseAuthorityAnchor<'claim, 'ledger> {
    Live(&'claim LiveRunnerLaunchReleaseClaim<'ledger>),
    #[cfg(test)]
    Test(&'claim (), PhantomData<&'ledger ()>),
}

impl<'claim, 'ledger> MacosOuterReleaseAuthorization<'claim, 'ledger> {
    /// Derives release authority only while core's non-cloneable live release
    /// exclusion proves the admission is still open.
    pub(crate) fn try_from_live_claim(
        claim: &'claim LiveRunnerLaunchReleaseClaim<'ledger>,
        binding: &PlatformLaunchBinding,
        expected: &MacosHelperPreparationBinding,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
        assigned: &MacosAssignedIdentity,
        now_unix_ms: u64,
    ) -> Result<Self, MacosHelperProtocolError> {
        let reconstructed = MacosHelperPreparationBinding::try_from_authority(
            &claim.preparation().attempt,
            binding,
        )?;
        if &reconstructed != expected {
            return Err(invalid(
                "release_authorization.live_claim",
                "live release claim or platform binding differs from the exact macOS request",
            ));
        }
        let validated =
            decode_native_launch_preparation_evidence(claim, binding).map_err(|_| {
                invalid(
                    "release_authorization.outer_evidence",
                    "core native preparation envelope failed shared validation",
                )
            })?;
        let canonical_held = held.canonical_native_evidence_bytes()?;
        if validated.service_evidence_bytes() != canonical_held.as_slice()
            || validated.service_evidence_digest() != &Digest::sha256(&canonical_held)
        {
            return Err(invalid(
                "release_authorization.outer_evidence",
                "validated core envelope contains substituted macOS helper evidence",
            ));
        }
        MacosOuterReleaseAuthorizationRecord::validate_preparation_identity(
            claim.preparation(),
            expected,
            request,
            held,
            assigned,
        )?;
        let record = MacosOuterReleaseAuthorizationRecord {
            contract_version: CONTRACT_VERSION,
            preparation: expected.clone(),
            outer_native_preparation_evidence_digest: validated.native_evidence_digest().clone(),
            held_service_evidence_digest: validated.service_evidence_digest().clone(),
            preparation_finished_at_unix_ms: validated.finished_at_unix_ms(),
            authorized_at_unix_ms: now_unix_ms,
        };
        record.validate_for(request, held)?;
        Ok(Self {
            _claim: MacosReleaseAuthorityAnchor::Live(claim),
            record,
        })
    }

    pub(crate) const fn record(&self) -> &MacosOuterReleaseAuthorizationRecord {
        &self.record
    }
}

impl MacosOuterReleaseAuthorizationRecord {
    #[cfg(test)]
    pub(crate) fn try_from_persisted_for_test(
        persisted: &PersistedRunnerLaunchPreparation,
        expected: &MacosHelperPreparationBinding,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
        assigned: &MacosAssignedIdentity,
    ) -> Result<Self, MacosHelperProtocolError> {
        Self::validate_preparation_identity(persisted, expected, request, held, assigned)?;
        let outcome = persisted.outcome.as_ref().ok_or_else(|| {
            invalid(
                "release_authorization.outcome",
                "preparation outcome is absent or commit-ambiguous",
            )
        })?;
        let canonical_held = held.canonical_native_evidence_bytes()?;
        if outcome.disposition != RunnerLaunchPreparationDisposition::HeldChildPrepared
            || outcome.native_evidence_bytes != canonical_held
            || outcome.finished_at_unix_ms < persisted.attempt.claimed_at_unix_ms
            || outcome.finished_at_unix_ms < held.held_at_unix_ms
        {
            return Err(invalid(
                "release_authorization.outcome",
                "test preparation did not retain the exact raw held-child evidence",
            ));
        }
        let authorization = Self {
            contract_version: CONTRACT_VERSION,
            preparation: expected.clone(),
            // Unit lifecycle tests do not own a live core release claim. Shared
            // envelope construction/readback is tested in `platform_launch`;
            // production construction above always retains that outer digest.
            outer_native_preparation_evidence_digest: Digest::sha256(&canonical_held),
            held_service_evidence_digest: Digest::sha256(&canonical_held),
            preparation_finished_at_unix_ms: outcome.finished_at_unix_ms,
            authorized_at_unix_ms: outcome.finished_at_unix_ms,
        };
        authorization.validate_for(request, held)?;
        Ok(authorization)
    }

    #[cfg(test)]
    pub(crate) fn retain_test_live(self, guard: &()) -> MacosOuterReleaseAuthorization<'_, '_> {
        MacosOuterReleaseAuthorization {
            _claim: MacosReleaseAuthorityAnchor::Test(guard, PhantomData),
            record: self,
        }
    }

    fn validate_preparation_identity(
        persisted: &PersistedRunnerLaunchPreparation,
        expected: &MacosHelperPreparationBinding,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
        assigned: &MacosAssignedIdentity,
    ) -> Result<(), MacosHelperProtocolError> {
        persisted.attempt.validate().map_err(|_| {
            invalid(
                "release_authorization.attempt",
                "persisted preparation attempt failed contract validation",
            )
        })?;
        expected.validate()?;
        request.validate_retained()?;
        held.validate_retained_for(request, assigned)?;
        let attempt = &persisted.attempt;
        if attempt.contract_version != expected.contract_version
            || attempt.attempt_id != expected.attempt_id
            || attempt.sprint_id != expected.sprint_id
            || attempt.launch_id != expected.launch_id
            || attempt.cleanup_effect_id != expected.cleanup_effect_id
            || attempt.native_journal_id != expected.native_journal_id
            || attempt.expected_platform_binding_digest != expected.expected_platform_binding_digest
            || attempt.claimed_at_unix_ms != expected.claimed_at_unix_ms
            || request.preparation != *expected
            || held.preparation != *expected
        {
            return Err(invalid(
                "release_authorization.authority",
                "persisted preparation, request, or held evidence identity differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_for(
        &self,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
    ) -> Result<(), MacosHelperProtocolError> {
        let held_bytes = held.canonical_native_evidence_bytes()?;
        if self.contract_version != CONTRACT_VERSION
            || self.preparation != request.preparation
            || self.preparation != held.preparation
            || self.held_service_evidence_digest != Digest::sha256(&held_bytes)
            || self.preparation_finished_at_unix_ms < self.preparation.claimed_at_unix_ms
            || self.preparation_finished_at_unix_ms < held.held_at_unix_ms
            || self.preparation_finished_at_unix_ms >= request.deadline_unix_ms
            || self.authorized_at_unix_ms < self.preparation_finished_at_unix_ms
            || self.authorized_at_unix_ms < held.held_at_unix_ms
            || self.authorized_at_unix_ms >= request.deadline_unix_ms
        {
            return Err(invalid(
                "release_authorization.binding",
                "outer release authorization differs from exact held evidence",
            ));
        }
        Ok(())
    }
}

/// Authenticated-session-bound candidate emitted only after reconciliation
/// positively observes the one attempted release. It is not a containment
/// proof and cannot authorize another release attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosReleaseEvidence {
    pub(crate) authenticated_session: MacosHelperSession,
    pub(crate) request_digest: Digest,
    pub(crate) preparation: MacosHelperPreparationBinding,
    pub(crate) held_preparation_evidence_digest: Digest,
    pub(crate) release_observation_digest: Digest,
    pub(crate) released_at_unix_ms: u64,
    pub(crate) evidence_digest: Digest,
}

#[derive(Serialize)]
struct ReleaseEvidencePreimage<'a> {
    authenticated_session: &'a MacosHelperSession,
    request_digest: &'a Digest,
    preparation: &'a MacosHelperPreparationBinding,
    held_preparation_evidence_digest: &'a Digest,
    release_observation_digest: &'a Digest,
    released_at_unix_ms: u64,
}

impl MacosReleaseEvidence {
    pub(crate) fn computed_digest(&self) -> Result<Digest, MacosHelperProtocolError> {
        let canonical = serde_json::to_vec(&ReleaseEvidencePreimage {
            authenticated_session: &self.authenticated_session,
            request_digest: &self.request_digest,
            preparation: &self.preparation,
            held_preparation_evidence_digest: &self.held_preparation_evidence_digest,
            release_observation_digest: &self.release_observation_digest,
            released_at_unix_ms: self.released_at_unix_ms,
        })
        .map_err(|error| {
            MacosHelperProtocolError::Encoding(format!("release evidence encoding failed: {error}"))
        })?;
        let mut bytes = Vec::with_capacity(RELEASE_EVIDENCE_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(RELEASE_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(Digest::sha256(&bytes))
    }

    fn validate_retained_for(
        &self,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
        admission_session: &MacosHelperSession,
    ) -> Result<(), MacosHelperProtocolError> {
        request.validate_retained()?;
        held.validate_retained_for(request, &held.assigned_identity)?;
        admission_session.validate()?;
        self.authenticated_session.validate()?;
        if !self
            .authenticated_session
            .same_durable_authority(admission_session)
            || !self
                .authenticated_session
                .same_durable_authority(&held.authenticated_session)
            || self.request_digest != request.request_digest
            || self.preparation != request.preparation
            || self.held_preparation_evidence_digest != held.evidence_digest
            || self.released_at_unix_ms < self.authenticated_session.authenticated_at_unix_ms
            || self.released_at_unix_ms <= held.held_at_unix_ms
            || self.released_at_unix_ms >= request.deadline_unix_ms
            || self.evidence_digest != self.computed_digest()?
        {
            return Err(invalid(
                "release_evidence.binding",
                "release evidence differs from the authenticated held preparation",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_for(
        &self,
        session: &MacosHelperSession,
        request: &MacosHelperLaunchRequest,
        held: &MacosHeldPreparationEvidence,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate_retained_for(request, held, &held.authenticated_session)?;
        if &self.authenticated_session != session {
            return Err(invalid(
                "release_evidence.binding",
                "release evidence differs from the authenticated held preparation",
            ));
        }
        Ok(())
    }
}

/// Durable record whose exact shape determines what recovery is allowed to do.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosHelperJournalRecord {
    pub(crate) state: MacosHelperJournalState,
    pub(crate) admission_session: MacosHelperSession,
    pub(crate) request: MacosHelperLaunchRequest,
    pub(crate) assigned_identity: Option<MacosAssignedIdentity>,
    pub(crate) cleanup_agent_digest: Option<Digest>,
    pub(crate) held_preparation_evidence: Option<MacosHeldPreparationEvidence>,
    pub(crate) release_authorization: Option<MacosOuterReleaseAuthorizationRecord>,
    pub(crate) release_evidence: Option<MacosReleaseEvidence>,
    pub(crate) termination_reason: Option<MacosTerminationReason>,
    pub(crate) observations: Vec<MacosProcessObservation>,
    pub(crate) identity_released: bool,
}

impl MacosHelperJournalRecord {
    #[allow(
        clippy::too_many_lines,
        reason = "the exact state-shape validator keeps every durable field combination in one auditable match"
    )]
    pub(crate) fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        self.admission_session.validate()?;
        self.request
            .validate_archived_session_binding(&self.admission_session)?;
        if self.observations.len() > MAX_MACOS_PROCESS_OBSERVATIONS {
            return Err(invalid(
                "journal.observations",
                "observation sequence exceeds its hard bound",
            ));
        }
        let assigned = self.assigned_identity.as_ref();
        if let Some(identity) = assigned {
            identity.validate()?;
            for (index, observation) in self.observations.iter().enumerate() {
                observation.validate(identity.uid)?;
                if index > 0
                    && self.observations[index - 1].observed_at_unix_ms
                        >= observation.observed_at_unix_ms
                {
                    return Err(invalid(
                        "journal.observations",
                        "process observation times must be strictly increasing",
                    ));
                }
                let expected = u32::try_from(index)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| invalid("journal.observations", "sequence overflow"))?;
                if observation.sequence != expected {
                    return Err(invalid(
                        "journal.observations",
                        "process observations must be contiguous from one",
                    ));
                }
            }
        } else if !self.observations.is_empty() {
            return Err(invalid(
                "journal.observations",
                "process observations require an assigned identity",
            ));
        }

        if let Some(held) = &self.held_preparation_evidence {
            let Some(assigned) = assigned else {
                return Err(invalid(
                    "journal.held_preparation_evidence",
                    "held evidence requires an assigned identity",
                ));
            };
            held.validate_retained_for(&self.request, assigned)?;
            if held.authenticated_session != self.admission_session {
                return Err(invalid(
                    "journal.held_preparation_evidence",
                    "held evidence was not authenticated by the admission session",
                ));
            }
        }
        if let Some(release) = &self.release_evidence {
            let Some(held) = &self.held_preparation_evidence else {
                return Err(invalid(
                    "journal.release_evidence",
                    "release evidence requires held-preparation evidence",
                ));
            };
            release.validate_retained_for(&self.request, held, &self.admission_session)?;
        }
        if let Some(authorization) = &self.release_authorization {
            let Some(held) = &self.held_preparation_evidence else {
                return Err(invalid(
                    "journal.release_authorization",
                    "outer release authorization requires held evidence",
                ));
            };
            authorization.validate_for(&self.request, held)?;
        }
        if let (Some(authorization), Some(release)) =
            (&self.release_authorization, &self.release_evidence)
            && release.released_at_unix_ms < authorization.authorized_at_unix_ms
        {
            return Err(invalid(
                "journal.release_evidence",
                "release evidence predates the live outer authorization",
            ));
        }

        let has_identity = assigned.is_some();
        let has_cleanup_agent = self.cleanup_agent_digest.is_some();
        let has_held = self.held_preparation_evidence.is_some();
        let has_release_authorization = self.release_authorization.is_some();
        let has_release = self.release_evidence.is_some();
        let has_termination = self.termination_reason.is_some();
        let exact_shape = match self.state {
            MacosHelperJournalState::Prepared | MacosHelperJournalState::CleanupAgentIntended => {
                has_identity
                    && !has_cleanup_agent
                    && !has_held
                    && !has_release_authorization
                    && !has_release
                    && !has_termination
                    && !self.identity_released
                    && has_two_stable_empty(&self.observations, false)
            }
            MacosHelperJournalState::LaunchIntended => {
                has_identity
                    && has_cleanup_agent
                    && !has_held
                    && !has_release_authorization
                    && !has_release
                    && !has_termination
                    && !self.identity_released
                    && has_two_stable_empty(&self.observations, false)
            }
            MacosHelperJournalState::HeldPrepared => {
                has_identity
                    && has_cleanup_agent
                    && has_held
                    && !has_release_authorization
                    && !has_release
                    && !has_termination
                    && !self.identity_released
            }
            MacosHelperJournalState::ReleaseIntended => {
                has_identity
                    && has_cleanup_agent
                    && has_held
                    && has_release_authorization
                    && !has_release
                    && !has_termination
                    && !self.identity_released
            }
            MacosHelperJournalState::Released => {
                has_identity
                    && has_cleanup_agent
                    && has_held
                    && has_release_authorization
                    && has_release
                    && !has_termination
                    && !self.identity_released
            }
            MacosHelperJournalState::Cleaning => {
                has_identity
                    && has_cleanup_agent
                    && has_termination
                    && (!has_release_authorization || has_held)
                    && (!has_release || has_release_authorization)
                    && !self.identity_released
            }
            MacosHelperJournalState::EmptyProven => {
                has_identity
                    && has_cleanup_agent
                    && has_termination
                    && (!has_release_authorization || has_held)
                    && (!has_release || has_release_authorization)
                    && !self.identity_released
                    && has_two_stable_empty(&self.observations, true)
            }
            MacosHelperJournalState::Cleaned => {
                has_identity
                    && has_cleanup_agent
                    && has_termination
                    && (!has_release_authorization || has_held)
                    && (!has_release || has_release_authorization)
                    && self.identity_released
                    && has_two_stable_empty(&self.observations, true)
            }
            MacosHelperJournalState::RejectedBeforeEffect => {
                !has_identity
                    && !has_cleanup_agent
                    && !has_held
                    && !has_release_authorization
                    && !has_release
                    && !has_termination
                    && self.observations.is_empty()
                    && !self.identity_released
            }
        };
        if !exact_shape {
            return Err(invalid(
                "journal.state_shape",
                "fields are not exact for the durable lifecycle state",
            ));
        }
        Ok(())
    }

    /// Revalidates retained evidence against one exact authenticated helper
    /// session. This does not inspect the operating system or prove release.
    pub(crate) fn validate_for_session(
        &self,
        session: &MacosHelperSession,
    ) -> Result<(), MacosHelperProtocolError> {
        self.validate()?;
        session.validate()?;
        if !session.same_durable_authority(&self.admission_session) {
            return Err(invalid(
                "journal.session_binding",
                "retained request differs from the authenticated helper session",
            ));
        }
        Ok(())
    }

    pub(crate) const fn request_digest(&self) -> &Digest {
        &self.request.request_digest
    }

    pub(crate) fn runner_session_id(&self) -> &str {
        &self.request.runner_session_id
    }

    pub(crate) fn effect_id(&self) -> &str {
        &self.request.effect_id
    }
}

/// Bounded final evidence candidate; core still binds it to the cleanup effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosCleanupEvidence {
    pub(crate) journal_record: MacosHelperJournalRecord,
    pub(crate) request_digest: Digest,
    pub(crate) assigned_identity: MacosAssignedIdentity,
    pub(crate) surviving_processes: u64,
    pub(crate) stable_empty_observations: u8,
}

impl MacosCleanupEvidence {
    pub(crate) fn validate(&self) -> Result<(), MacosHelperProtocolError> {
        self.journal_record.validate()?;
        if self.journal_record.state != MacosHelperJournalState::Cleaned
            || self.journal_record.request_digest() != &self.request_digest
            || self.journal_record.assigned_identity.as_ref() != Some(&self.assigned_identity)
            || self.surviving_processes != 0
            || self.stable_empty_observations != 2
            || !self.journal_record.identity_released
        {
            return Err(invalid(
                "cleanup.journal_binding",
                "cleanup candidate differs from the exact durable cleaned record",
            ));
        }
        Ok(())
    }
}

fn has_two_stable_empty(observations: &[MacosProcessObservation], require_sealed: bool) -> bool {
    let Some((penultimate, last)) = observations
        .len()
        .checked_sub(2)
        .map(|index| (&observations[index], &observations[index + 1]))
    else {
        return false;
    };
    penultimate.process_ids.is_empty()
        && last.process_ids.is_empty()
        && penultimate.observed_at_unix_ms < last.observed_at_unix_ms
        && (!require_sealed || (penultimate.creation_sealed && last.creation_sealed))
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), MacosHelperProtocolError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(invalid(
            field,
            "must be nonblank, bounded, and contain no ASCII space/control bytes",
        ));
    }
    Ok(())
}

fn validate_relative_path(
    field: &'static str,
    value: &str,
) -> Result<(), MacosHelperProtocolError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(invalid(field, "relative path is empty or oversized"));
    }
    if value == "." {
        return Ok(());
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(invalid(field, "absolute paths are forbidden"));
    }
    let mut count = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                count += 1;
                if name == ".git" || name.to_string_lossy().eq_ignore_ascii_case(".git") {
                    return Err(invalid(field, ".git is outside command authority"));
                }
            }
            _ => return Err(invalid(field, "path is not normalized")),
        }
    }
    if count == 0 {
        return Err(invalid(field, "path contains no normal component"));
    }
    Ok(())
}

fn validate_argv(argv: &[String]) -> Result<(), MacosHelperProtocolError> {
    if argv.is_empty() || argv.len() > MAX_MACOS_HELPER_ARGV {
        return Err(invalid(
            "request.argv",
            "argument vector is empty or exceeds its count bound",
        ));
    }
    let mut total = 0_usize;
    for value in argv {
        if value.is_empty() || value.contains('\0') || value.len() > MAX_TEXT_BYTES {
            return Err(invalid(
                "request.argv",
                "arguments must be nonempty, NUL-free, and bounded",
            ));
        }
        total = total
            .checked_add(value.len())
            .ok_or_else(|| invalid("request.argv", "argument byte count overflow"))?;
    }
    if total > MAX_TOTAL_ARGV_BYTES {
        return Err(invalid(
            "request.argv",
            "aggregate argument bytes exceed the hard bound",
        ));
    }
    Ok(())
}

fn validate_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), MacosHelperProtocolError> {
    if environment.len() > MAX_MACOS_HELPER_ENVIRONMENT {
        return Err(invalid(
            "request.environment",
            "environment entry count exceeds the hard bound",
        ));
    }
    let mut total = 0_usize;
    for (name, value) in environment {
        if name.is_empty()
            || name.len() > MAX_ID_BYTES
            || name.contains('=')
            || name.contains('\0')
            || value.contains('\0')
            || value.len() > MAX_TEXT_BYTES
            || is_secret_environment_name(OsStr::new(name))
        {
            return Err(invalid(
                "request.environment",
                "environment names/values are malformed or oversized",
            ));
        }
        total = total
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(|| invalid("request.environment", "environment byte count overflow"))?;
    }
    if total > MAX_TOTAL_ENVIRONMENT_BYTES {
        return Err(invalid(
            "request.environment",
            "aggregate environment bytes exceed the hard bound",
        ));
    }
    Ok(())
}

const fn invalid(field: &'static str, reason: &'static str) -> MacosHelperProtocolError {
    MacosHelperProtocolError::Invalid { field, reason }
}

/// Fail-closed protocol validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosHelperProtocolError {
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    Decoding(String),
    Encoding(String),
    NonCanonicalRequest,
    RequestTooLarge {
        bytes: usize,
    },
    NativePreparationEvidenceTooLarge {
        bytes: usize,
    },
}

impl Display for MacosHelperProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, reason } => write!(formatter, "{field}: {reason}"),
            Self::Decoding(message) | Self::Encoding(message) => formatter.write_str(message),
            Self::NonCanonicalRequest => {
                formatter.write_str("request bytes are not the unique canonical encoding")
            }
            Self::RequestTooLarge { bytes } => write!(
                formatter,
                "request uses {bytes} bytes; maximum is {MAX_MACOS_HELPER_REQUEST_BYTES}"
            ),
            Self::NativePreparationEvidenceTooLarge { bytes } => write!(
                formatter,
                "native preparation service evidence uses {bytes} bytes; maximum is {MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES}"
            ),
        }
    }
}

impl std::error::Error for MacosHelperProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::sha256(&[byte])
    }

    /// A root-installed helper binary audited by an ordinary local user.
    const fn install_audit() -> MacosHelperInstallAudit {
        MacosHelperInstallAudit {
            auditing_uid: 501,
            binary_owner_uid: 0,
            binary_mode: 0o755,
            directory_owner_uid: 0,
            directory_mode: 0o755,
        }
    }

    fn session() -> MacosHelperSession {
        MacosHelperSession {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 7,
            session_nonce: digest(1),
            helper_binary_digest: digest(2),
            helper_requirement_digest: digest(3),
            client_binary_digest: digest(4),
            client_requirement_digest: digest(5),
            pool_record_digest: digest(6),
            workspace_grant_hash: digest(7),
            execution_policy_hash: digest(8),
            command_network: MacosHelperNetwork::Denied,
            authenticated_at_unix_ms: 10,
            peer_requirement_matched: true,
            attestation: MacosHelperAttestation::LocalCodeIdentity {
                install_audit: install_audit(),
            },
        }
    }

    fn preparation(suffix: u8) -> MacosHelperPreparationBinding {
        MacosHelperPreparationBinding {
            contract_version: CONTRACT_VERSION,
            attempt_id: format!("attempt-{suffix}"),
            sprint_id: "sprint-1".into(),
            launch_id: "launch-1".into(),
            runner_session_id: "runner-1".into(),
            cleanup_effect_id: "cleanup-effect-1".into(),
            input_snapshot: digest(19),
            native_journal_id: format!("native-journal-{suffix}"),
            expected_platform_binding_digest: digest(20 + suffix),
            claimed_at_unix_ms: 11,
        }
    }

    fn descriptors() -> Vec<MacosChildDescriptorBinding> {
        [
            (0, MacosChildDescriptorPurpose::StandardInput, true),
            (1, MacosChildDescriptorPurpose::StandardOutput, true),
            (2, MacosChildDescriptorPurpose::StandardError, true),
            (3, MacosChildDescriptorPurpose::HoldControl, false),
            (4, MacosChildDescriptorPurpose::SetupReport, false),
        ]
        .into_iter()
        .map(
            |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
                target_fd,
                purpose,
                object_digest: digest(30 + u8::try_from(target_fd).unwrap()),
                inherited_through_exec,
            },
        )
        .collect()
    }

    fn request() -> MacosHelperLaunchRequest {
        let session = session();
        let mut request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: session.policy_version,
            session_nonce: session.session_nonce,
            request_id: "request-1".into(),
            preparation: preparation(1),
            runner_session_id: "runner-1".into(),
            effect_id: "effect-1".into(),
            workspace_grant_hash: session.workspace_grant_hash,
            execution_policy_hash: session.execution_policy_hash,
            staged_workspace_id: "shadow_1".into(),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(9),
            },
            descriptor_bindings: descriptors(),
            argv: vec!["cargo".into(), "test".into(), "--locked".into()],
            relative_working_directory: "project".into(),
            environment: BTreeMap::from([("PATH".into(), "/usr/bin".into())]),
            deadline_unix_ms: 1_000,
            max_output_bytes: 1024,
            max_processes: 32,
            max_memory_bytes: None,
            command_network: MacosHelperNetwork::Denied,
            seatbelt_profile_digest: digest(10),
            request_digest: digest(0),
        };
        request.request_digest = request.computed_digest().unwrap();
        request
    }

    fn identity(uid: u32) -> MacosExecutionIdentityRecord {
        MacosExecutionIdentityRecord {
            account_name: format!("_grokbuild{uid}"),
            uid,
            gid: uid,
            record_digest: Digest::sha256(&uid.to_be_bytes()),
            login_shell: "/usr/bin/false".into(),
            home_directory: format!("/var/empty/grok-build/{uid}"),
            supplementary_groups: Vec::new(),
            password_locked: true,
            interactive_session_count: 0,
        }
    }

    fn observation(
        sequence: u32,
        time: u64,
        uid: u32,
        process_ids: Vec<u32>,
    ) -> MacosProcessObservation {
        let mut observation = MacosProcessObservation {
            sequence,
            observed_at_unix_ms: time,
            uid,
            process_ids,
            enumeration_digest: digest(0),
            creation_sealed: true,
        };
        observation.enumeration_digest = observation.computed_digest().unwrap();
        observation
    }

    fn empty_observation(sequence: u32, time: u64, uid: u32) -> MacosProcessObservation {
        observation(sequence, time, uid, Vec::new())
    }

    #[test]
    fn canonical_request_is_session_bound() {
        let session = session();
        let request = request();
        request.validate_for_session(&session, 20).unwrap();

        let mut replay = request.clone();
        replay.session_nonce = digest(99);
        replay.request_digest = replay.computed_digest().unwrap();
        assert!(replay.validate_for_session(&session, 20).is_err());
    }

    #[test]
    fn decoder_requires_the_single_canonical_byte_representation() {
        let session = session();
        let request = request();
        let expected_preparation = request.preparation.clone();
        let canonical = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            decode_canonical_launch_request(&canonical, &session, &expected_preparation, 20)
                .unwrap(),
            request
        );

        let mut alternate = canonical;
        alternate.push(b'\n');
        assert_eq!(
            decode_canonical_launch_request(&alternate, &session, &expected_preparation, 20),
            Err(MacosHelperProtocolError::NonCanonicalRequest)
        );
    }

    #[test]
    fn any_request_mutation_invalidates_digest() {
        let session = session();
        let mut request = request();
        request.argv.push("--all-targets".into());
        assert!(request.validate_for_session(&session, 20).is_err());
    }

    #[test]
    fn outer_preparation_and_descriptor_substitution_fail_closed() {
        let session = session();
        let request = request();
        let mut substituted = request.preparation.clone();
        substituted.native_journal_id = "native-journal-substituted".into();
        assert!(
            request
                .validate_for_preparation(&session, &substituted, 20)
                .is_err()
        );

        let mut descriptor_substitution = request;
        descriptor_substitution.descriptor_bindings[4].target_fd = 3;
        descriptor_substitution.request_digest = descriptor_substitution.computed_digest().unwrap();
        assert!(
            descriptor_substitution
                .validate_for_session(&session, 20)
                .is_err()
        );
    }

    #[test]
    fn finite_memory_and_path_syntax_fail_before_effect() {
        let session = session();
        let mut memory_request = request();
        memory_request.max_memory_bytes = Some(1024);
        memory_request.request_digest = memory_request.computed_digest().unwrap();
        assert!(memory_request.validate_for_session(&session, 20).is_err());

        let mut path_request = request();
        path_request.relative_working_directory = "../outside".into();
        path_request.request_digest = path_request.computed_digest().unwrap();
        assert!(path_request.validate_for_session(&session, 20).is_err());
    }

    #[test]
    fn root_working_directory_is_explicit_and_secret_environment_is_rejected() {
        let session = session();
        let mut root_request = request();
        root_request.relative_working_directory = ".".into();
        root_request.request_digest = root_request.computed_digest().unwrap();
        root_request.validate_for_session(&session, 20).unwrap();

        root_request
            .environment
            .insert("XAI_API_KEY".into(), "must-not-cross-helper".into());
        root_request.request_digest = root_request.computed_digest().unwrap();
        assert!(root_request.validate_for_session(&session, 20).is_err());
    }

    #[test]
    fn unattested_or_wrong_requirement_session_is_rejected() {
        let mut session = session();
        session.attestation = MacosHelperAttestation::Unattested;
        assert!(request().validate_for_session(&session, 20).is_err());
        session.attestation = MacosHelperAttestation::LocalCodeIdentity {
            install_audit: install_audit(),
        };
        session.peer_requirement_matched = false;
        assert!(request().validate_for_session(&session, 20).is_err());
    }

    /// Both local and publisher attestation permit admission. Unattested helpers
    /// and install paths writable by untrusted users fail on their exact fields.
    #[test]
    fn local_and_publisher_attestation_are_both_admitted_and_unattested_is_not() {
        let mut session = session();
        session.validate().expect("local attestation is admitted");

        session.attestation = MacosHelperAttestation::PublisherCodeIdentity {
            install_audit: install_audit(),
        };
        session
            .validate()
            .expect("publisher attestation is admitted by the same clauses");
        assert!(session.attestation.claims_publisher());

        session.attestation = MacosHelperAttestation::Unattested;
        assert!(!session.attestation.claims_publisher());
        assert_eq!(session.attestation.install_audit(), None);
        assert_eq!(
            session.validate(),
            Err(MacosHelperProtocolError::Invalid {
                field: "session.attestation",
                reason: "an unattested helper is never admitted: its loaded image was not pinned to an install-time code requirement",
            })
        );
    }

    #[test]
    fn an_install_path_that_admits_an_untrusted_writer_is_refused() {
        let cases: [(MacosHelperInstallAudit, &str); 4] = [
            (
                MacosHelperInstallAudit {
                    binary_owner_uid: 502,
                    ..install_audit()
                },
                "session.attestation.binary_owner_uid",
            ),
            (
                MacosHelperInstallAudit {
                    binary_mode: 0o775,
                    ..install_audit()
                },
                "session.attestation.binary_mode",
            ),
            (
                MacosHelperInstallAudit {
                    directory_owner_uid: 502,
                    ..install_audit()
                },
                "session.attestation.directory_owner_uid",
            ),
            (
                MacosHelperInstallAudit {
                    directory_mode: 0o757,
                    ..install_audit()
                },
                "session.attestation.directory_mode",
            ),
        ];
        for (audit, field) in cases {
            let mut session = session();
            session.attestation = MacosHelperAttestation::LocalCodeIdentity {
                install_audit: audit,
            };
            let failure = session
                .validate()
                .expect_err("an untrusted writer must refuse admission");
            assert!(
                matches!(
                    failure,
                    MacosHelperProtocolError::Invalid { field: actual, .. } if actual == field
                ),
                "expected a refusal on {field}, got {failure:?}"
            );
        }
        // The auditing user owning its own installation is the ordinary
        // build-from-source shape and must be admitted.
        let mut session = session();
        session.attestation = MacosHelperAttestation::LocalCodeIdentity {
            install_audit: MacosHelperInstallAudit {
                auditing_uid: 501,
                binary_owner_uid: 501,
                binary_mode: 0o755,
                directory_owner_uid: 501,
                directory_mode: 0o700,
            },
        };
        session
            .validate()
            .expect("a user-owned installation is a first-class local attestation");
    }

    #[test]
    fn pool_requires_three_distinct_locked_accounts_and_exact_digest() {
        let mut session = session();
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().unwrap();
        session.pool_record_digest = pool.pool_record_digest.clone();
        pool.validate_for_session(&session).unwrap();

        pool.records[2].uid = pool.records[1].uid;
        pool.pool_record_digest = pool.computed_digest().unwrap();
        session.pool_record_digest = pool.pool_record_digest.clone();
        assert!(pool.validate_for_session(&session).is_err());
    }

    #[test]
    fn prepared_record_requires_two_stable_empty_observations() {
        let assigned = MacosAssignedIdentity {
            account_name: "_grokbuild601".into(),
            uid: 601,
            gid: 601,
            account_record_digest: digest(11),
        };
        let record = MacosHelperJournalRecord {
            state: MacosHelperJournalState::Prepared,
            admission_session: session(),
            request: request(),
            assigned_identity: Some(assigned),
            cleanup_agent_digest: None,
            held_preparation_evidence: None,
            release_authorization: None,
            release_evidence: None,
            termination_reason: None,
            observations: vec![empty_observation(1, 20, 601), empty_observation(2, 21, 601)],
            identity_released: false,
        };
        record.validate().unwrap();

        let mut forged = record;
        forged.observations[1].process_ids.push(42);
        assert!(forged.validate().is_err());
    }

    #[test]
    fn process_observations_reject_forged_digest_and_noncanonical_pid_order() {
        let mut forged = observation(1, 20, 601, vec![42]);
        forged.process_ids.push(43);
        assert!(forged.validate(601).is_err());

        let mut unordered = observation(1, 20, 601, vec![42, 43]);
        unordered.process_ids = vec![43, 42];
        unordered.enumeration_digest = unordered.computed_digest().unwrap();
        assert!(unordered.validate(601).is_err());
    }

    #[test]
    fn cleaned_evidence_requires_exact_final_journal_binding() {
        let assigned = MacosAssignedIdentity {
            account_name: "_grokbuild601".into(),
            uid: 601,
            gid: 601,
            account_record_digest: digest(11),
        };
        let record = MacosHelperJournalRecord {
            state: MacosHelperJournalState::Cleaned,
            admission_session: session(),
            request: request(),
            assigned_identity: Some(assigned.clone()),
            cleanup_agent_digest: Some(digest(12)),
            held_preparation_evidence: None,
            release_authorization: None,
            release_evidence: None,
            termination_reason: Some(MacosTerminationReason::Exited),
            observations: vec![
                observation(1, 20, 601, vec![44]),
                empty_observation(2, 21, 601),
                empty_observation(3, 22, 601),
            ],
            identity_released: true,
        };
        let evidence = MacosCleanupEvidence {
            request_digest: record.request_digest().clone(),
            journal_record: record,
            assigned_identity: assigned,
            surviving_processes: 0,
            stable_empty_observations: 2,
        };
        evidence.validate().unwrap();

        let mut forged = evidence;
        forged.surviving_processes = 1;
        assert!(forged.validate().is_err());
    }

    #[test]
    fn identity_cannot_be_released_before_cleaned() {
        let assigned = MacosAssignedIdentity {
            account_name: "_grokbuild601".into(),
            uid: 601,
            gid: 601,
            account_record_digest: digest(11),
        };
        let record = MacosHelperJournalRecord {
            state: MacosHelperJournalState::EmptyProven,
            admission_session: session(),
            request: request(),
            assigned_identity: Some(assigned),
            cleanup_agent_digest: Some(digest(12)),
            held_preparation_evidence: None,
            release_authorization: None,
            release_evidence: None,
            termination_reason: Some(MacosTerminationReason::Recovery),
            observations: vec![empty_observation(1, 20, 601), empty_observation(2, 21, 601)],
            identity_released: true,
        };
        assert!(record.validate().is_err());
    }

    #[test]
    fn lifecycle_never_skips_intent_or_cleanup_states() {
        assert!(
            MacosHelperJournalState::Prepared
                .allows_transition_to(MacosHelperJournalState::CleanupAgentIntended)
        );
        assert!(
            MacosHelperJournalState::HeldPrepared
                .allows_transition_to(MacosHelperJournalState::Cleaning)
        );
        assert!(
            !MacosHelperJournalState::Prepared
                .allows_transition_to(MacosHelperJournalState::Released)
        );
        assert!(
            !MacosHelperJournalState::HeldPrepared
                .allows_transition_to(MacosHelperJournalState::Cleaned)
        );
        assert!(
            !MacosHelperJournalState::Cleaned
                .allows_transition_to(MacosHelperJournalState::Prepared)
        );
    }
}
