//! Effect-free contract for an ordinary macOS runner held-launch service.
//!
//! This module is intentionally distinct from `macos_helper_protocol`: that
//! protocol describes one contained `RunCommand` domain, while this protocol
//! describes the direct ordinary runner process before its session exists.
//!
//! No native adapter is implemented here. In particular, constructing or
//! validating these values proves no XPC peer, code signature, executable
//! image, held process, dedicated UID, Seatbelt profile, or descendant cleanup.
//! The only current assurance level makes that limitation part of the encoded
//! contract so host tests cannot be promoted as native evidence.

#![allow(dead_code)] // Activated by the future signed macOS runner-launch adapter.

use std::fmt::{self, Display, Formatter};
#[cfg(test)]
use std::marker::PhantomData;

use grok_build_core::{
    CONTRACT_VERSION, Digest, LiveRunnerLaunchReleaseClaim, RunnerLaunchPreparationAttempt,
    WorkerCleanupBackend,
};
use serde::{Deserialize, Serialize};

use crate::{
    MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES, MAX_PLATFORM_LAUNCH_BINDING_BYTES,
    PlatformLaunchBinding, WireBinaryIdentity, decode_native_launch_preparation_evidence,
};

pub(crate) const MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION: u32 = 1;
pub(crate) const MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES: usize = 64 * 1024;
const MAX_RETAINED_RUNNER_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const HELD_EVIDENCE_DOMAIN: &[u8] = b"grok-build.macos-ordinary-runner-held-preparation.v1\0";
const RELEASE_EVIDENCE_DOMAIN: &[u8] = b"grok-build.macos-ordinary-runner-release-observation.v1\0";

/// Closed assurance level of the current contract-only tranche.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MacosOrdinaryRunnerAssurance {
    /// Host-testable validation only; no native launch or containment claim.
    ContractOnlyNoNativeAdapter,
}

/// Expected retained file-description identity supplied by trusted desktop code.
///
/// This is comparison state, not executable-image evidence. macOS 15 offers no
/// safe Rust `fexecve`/`execveat` bridge, so a future native adapter must add a
/// signed immutable-image mechanism before this expectation can authorize exec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosRetainedRunnerExecutableExpectation {
    binary_digest: Digest,
    descriptor_identity: WireBinaryIdentity,
}

impl MacosRetainedRunnerExecutableExpectation {
    pub(crate) fn try_new(
        binary_digest: Digest,
        descriptor_identity: WireBinaryIdentity,
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        let expectation = Self {
            binary_digest,
            descriptor_identity,
        };
        expectation.validate()?;
        Ok(expectation)
    }

    pub(crate) const fn binary_digest(&self) -> &Digest {
        &self.binary_digest
    }

    pub(crate) const fn descriptor_identity(&self) -> WireBinaryIdentity {
        self.descriptor_identity
    }

    fn validate(&self) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        let identity = self.descriptor_identity;
        let is_regular = identity.mode & 0o170_000 == 0o100_000;
        if identity.device_id == 0
            || identity.inode == 0
            || identity.byte_length == 0
            || identity.byte_length > MAX_RETAINED_RUNNER_BINARY_BYTES
            || !is_regular
            || identity.mode & 0o7_000 != 0
            || identity.mode & 0o022 != 0
            || identity.mode & 0o100 == 0
            || identity.link_count != 1
        {
            return Err(invalid(
                "executable_expectation.descriptor_identity",
                "retained runner expectation must be one bounded, non-setid, owner-executable, non-writable regular file identity",
            ));
        }
        Ok(())
    }
}

/// Immutable expected state for one ordinary macOS runner preparation.
///
/// Construction joins the exact persisted preparation attempt, complete
/// `PlatformLaunchBinding`, and retained executable expectation. It remains
/// cloneable expected state and grants no native effect authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerLaunchAuthority {
    protocol_version: u32,
    assurance: MacosOrdinaryRunnerAssurance,
    attempt: RunnerLaunchPreparationAttempt,
    platform_binding_bytes: Vec<u8>,
    platform_binding_digest: Digest,
    executable: MacosRetainedRunnerExecutableExpectation,
}

impl MacosOrdinaryRunnerLaunchAuthority {
    pub(crate) fn try_from_expected_state(
        attempt: &RunnerLaunchPreparationAttempt,
        binding: &PlatformLaunchBinding,
        executable: MacosRetainedRunnerExecutableExpectation,
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        let authority = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            assurance: MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter,
            attempt: attempt.clone(),
            platform_binding_bytes: binding.canonical_bytes().to_vec(),
            platform_binding_digest: binding.binding_digest().clone(),
            executable,
        };
        authority.validate_against(binding)?;
        Ok(authority)
    }

    pub(crate) const fn attempt(&self) -> &RunnerLaunchPreparationAttempt {
        &self.attempt
    }

    pub(crate) const fn platform_binding_digest(&self) -> &Digest {
        &self.platform_binding_digest
    }

    pub(crate) const fn executable(&self) -> &MacosRetainedRunnerExecutableExpectation {
        &self.executable
    }

    pub(crate) fn validate_against(
        &self,
        binding: &PlatformLaunchBinding,
    ) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        self.validate_retained()?;
        if self.platform_binding_bytes != binding.canonical_bytes()
            || self.platform_binding_digest != *binding.binding_digest()
            || self.attempt.sprint_id != binding.sprint_id()
            || self.attempt.launch_id != binding.launch_id()
            || self.attempt.cleanup_effect_id != binding.cleanup_effect_id()
            || self.attempt.expected_platform_binding_digest != *binding.binding_digest()
            || self.attempt.claimed_at_unix_ms < binding.cleanup_admitted_at_unix_ms()
            || self.executable.binary_digest != *binding.runner_binary_digest()
            || binding.platform_backend() != WorkerCleanupBackend::MacOsDedicatedIdentity
        {
            return Err(invalid(
                "launch_authority.platform_binding",
                "attempt, complete platform binding, cleanup backend, or retained executable expectation differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_retained(&self) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        self.attempt.validate().map_err(|_| {
            invalid(
                "launch_authority.attempt",
                "runner preparation attempt failed core validation",
            )
        })?;
        self.executable.validate()?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.assurance != MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter
            || self.platform_binding_bytes.is_empty()
            || self.platform_binding_bytes.len() > MAX_PLATFORM_LAUNCH_BINDING_BYTES
            || Digest::sha256(&self.platform_binding_bytes) != self.platform_binding_digest
            || self.attempt.expected_platform_binding_digest != self.platform_binding_digest
            || self.attempt.contract_version != CONTRACT_VERSION
        {
            return Err(invalid(
                "launch_authority.retained",
                "ordinary runner authority is unsupported, oversized, noncanonical, or internally crossed",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_fixture() -> Self {
        let platform_binding_bytes = b"test-only-complete-platform-binding".to_vec();
        let platform_binding_digest = Digest::sha256(&platform_binding_bytes);
        let executable_digest = Digest::sha256(b"test runner executable");
        Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            assurance: MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter,
            attempt: RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: "attempt-macos-ordinary-runner-1".into(),
                sprint_id: "sprint-macos-ordinary-runner-1".into(),
                launch_id: "launch-macos-ordinary-runner-1".into(),
                cleanup_effect_id: "cleanup-macos-ordinary-runner-1".into(),
                native_journal_id: "journal-macos-ordinary-runner-1".into(),
                expected_platform_binding_digest: platform_binding_digest.clone(),
                claimed_at_unix_ms: 100,
            },
            platform_binding_bytes,
            platform_binding_digest,
            executable: MacosRetainedRunnerExecutableExpectation {
                binary_digest: executable_digest,
                descriptor_identity: WireBinaryIdentity {
                    device_id: 7,
                    inode: 11,
                    byte_length: 4_096,
                    mode: 0o100_500,
                    owner_uid: 501,
                    link_count: 1,
                },
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fixture_with_executable(
        executable: MacosRetainedRunnerExecutableExpectation,
    ) -> Self {
        let mut authority = Self::test_fixture();
        authority.executable = executable;
        authority
            .validate_retained()
            .expect("test executable must preserve retained authority shape");
        authority
    }
}

/// Contract candidate for native setup readback while the runner is still held.
///
/// A reviewed native adapter must eventually supply the opaque setup digest;
/// this type neither manufactures nor authenticates that observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerHeldEvidence {
    protocol_version: u32,
    assurance: MacosOrdinaryRunnerAssurance,
    attempt_id: String,
    native_journal_id: String,
    platform_binding_digest: Digest,
    executable: MacosRetainedRunnerExecutableExpectation,
    setup_observation_digest: Digest,
    held_at_unix_ms: u64,
    evidence_digest: Digest,
}

#[derive(Serialize)]
struct HeldEvidencePreimage<'a> {
    protocol_version: u32,
    assurance: MacosOrdinaryRunnerAssurance,
    attempt_id: &'a str,
    native_journal_id: &'a str,
    platform_binding_digest: &'a Digest,
    executable: &'a MacosRetainedRunnerExecutableExpectation,
    setup_observation_digest: &'a Digest,
    held_at_unix_ms: u64,
}

impl MacosOrdinaryRunnerHeldEvidence {
    pub(crate) fn candidate_from_native_observation(
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        setup_observation_digest: Digest,
        held_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        authority.validate_retained()?;
        let mut evidence = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            assurance: MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter,
            attempt_id: authority.attempt.attempt_id.clone(),
            native_journal_id: authority.attempt.native_journal_id.clone(),
            platform_binding_digest: authority.platform_binding_digest.clone(),
            executable: authority.executable.clone(),
            setup_observation_digest,
            held_at_unix_ms,
            evidence_digest: Digest::sha256(&[]),
        };
        evidence.evidence_digest = evidence.computed_digest()?;
        evidence.validate_for(authority)?;
        Ok(evidence)
    }

    pub(crate) const fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub(crate) const fn held_at_unix_ms(&self) -> u64 {
        self.held_at_unix_ms
    }

    pub(crate) fn canonical_service_evidence_bytes(
        &self,
    ) -> Result<Vec<u8>, MacosOrdinaryRunnerHeldProtocolError> {
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosOrdinaryRunnerHeldProtocolError::Encoding(format!(
                "held evidence encoding failed: {error}"
            ))
        })?;
        let mut bytes = Vec::with_capacity(HELD_EVIDENCE_DOMAIN.len() + json.len());
        bytes.extend_from_slice(HELD_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&json);
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES {
            return Err(MacosOrdinaryRunnerHeldProtocolError::TooLarge {
                field: "held service evidence",
                bytes: bytes.len(),
                maximum: MAX_NATIVE_LAUNCH_SERVICE_EVIDENCE_BYTES,
            });
        }
        Ok(bytes)
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerHeldProtocolError> {
        let preimage = HeldEvidencePreimage {
            protocol_version: self.protocol_version,
            assurance: self.assurance,
            attempt_id: &self.attempt_id,
            native_journal_id: &self.native_journal_id,
            platform_binding_digest: &self.platform_binding_digest,
            executable: &self.executable,
            setup_observation_digest: &self.setup_observation_digest,
            held_at_unix_ms: self.held_at_unix_ms,
        };
        let bytes = serde_json::to_vec(&preimage).map_err(|error| {
            MacosOrdinaryRunnerHeldProtocolError::Encoding(format!(
                "held evidence preimage encoding failed: {error}"
            ))
        })?;
        let mut domain = Vec::with_capacity(HELD_EVIDENCE_DOMAIN.len() + bytes.len());
        domain.extend_from_slice(HELD_EVIDENCE_DOMAIN);
        domain.extend_from_slice(&bytes);
        Ok(Digest::sha256(&domain))
    }

    pub(crate) fn validate_for(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
    ) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        authority.validate_retained()?;
        self.executable.validate()?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.assurance != MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter
            || self.attempt_id != authority.attempt.attempt_id
            || self.native_journal_id != authority.attempt.native_journal_id
            || self.platform_binding_digest != authority.platform_binding_digest
            || self.executable != authority.executable
            || self.held_at_unix_ms < authority.attempt.claimed_at_unix_ms
            || self.evidence_digest != self.computed_digest()?
        {
            return Err(invalid(
                "held_evidence.binding",
                "held candidate differs from its exact ordinary runner authority",
            ));
        }
        self.canonical_service_evidence_bytes()?;
        Ok(())
    }
}

/// Durable release authorization reconstructed only from a live core claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerReleaseAuthorizationRecord {
    contract_version: u32,
    attempt_id: String,
    native_journal_id: String,
    platform_binding_digest: Digest,
    held_evidence_digest: Digest,
    outer_preparation_evidence_digest: Digest,
    authorized_at_unix_ms: u64,
}

/// Non-cloneable live release authority anchored to core's exclusion callback.
pub(crate) struct MacosOrdinaryRunnerReleaseAuthorization<'claim, 'ledger> {
    _anchor: ReleaseAnchor<'claim, 'ledger>,
    record: MacosOrdinaryRunnerReleaseAuthorizationRecord,
}

enum ReleaseAnchor<'claim, 'ledger> {
    Live(&'claim LiveRunnerLaunchReleaseClaim<'ledger>),
    #[cfg(test)]
    Test(&'claim (), PhantomData<&'ledger ()>),
}

impl<'claim, 'ledger> MacosOrdinaryRunnerReleaseAuthorization<'claim, 'ledger> {
    pub(crate) fn try_from_live_claim(
        claim: &'claim LiveRunnerLaunchReleaseClaim<'ledger>,
        binding: &PlatformLaunchBinding,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        held: &MacosOrdinaryRunnerHeldEvidence,
        authorized_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        authority.validate_against(binding)?;
        held.validate_for(authority)?;
        let preparation = claim.preparation();
        let validated =
            decode_native_launch_preparation_evidence(claim, binding).map_err(|_| {
                invalid(
                    "release_authorization.outer_preparation",
                    "shared native preparation envelope failed live-claim validation",
                )
            })?;
        let held_bytes = held.canonical_service_evidence_bytes()?;
        if preparation.attempt != authority.attempt
            || validated.service_evidence_bytes() != held_bytes
            || validated.service_evidence_digest() != &Digest::sha256(&held_bytes)
            || authorized_at_unix_ms < validated.finished_at_unix_ms()
            || authorized_at_unix_ms < held.held_at_unix_ms
        {
            return Err(invalid(
                "release_authorization.live_claim",
                "live release claim, held bytes, or authorization time differs",
            ));
        }
        let record = MacosOrdinaryRunnerReleaseAuthorizationRecord {
            contract_version: CONTRACT_VERSION,
            attempt_id: authority.attempt.attempt_id.clone(),
            native_journal_id: authority.attempt.native_journal_id.clone(),
            platform_binding_digest: authority.platform_binding_digest.clone(),
            held_evidence_digest: held.evidence_digest.clone(),
            outer_preparation_evidence_digest: validated.native_evidence_digest().clone(),
            authorized_at_unix_ms,
        };
        record.validate_for(authority, held)?;
        Ok(Self {
            _anchor: ReleaseAnchor::Live(claim),
            record,
        })
    }

    pub(crate) const fn record(&self) -> &MacosOrdinaryRunnerReleaseAuthorizationRecord {
        &self.record
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        held: &MacosOrdinaryRunnerHeldEvidence,
        outer_preparation_evidence_digest: Digest,
        authorized_at_unix_ms: u64,
        guard: &'claim (),
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        let record = MacosOrdinaryRunnerReleaseAuthorizationRecord {
            contract_version: CONTRACT_VERSION,
            attempt_id: authority.attempt.attempt_id.clone(),
            native_journal_id: authority.attempt.native_journal_id.clone(),
            platform_binding_digest: authority.platform_binding_digest.clone(),
            held_evidence_digest: held.evidence_digest.clone(),
            outer_preparation_evidence_digest,
            authorized_at_unix_ms,
        };
        record.validate_for(authority, held)?;
        Ok(Self {
            _anchor: ReleaseAnchor::Test(guard, PhantomData),
            record,
        })
    }
}

impl MacosOrdinaryRunnerReleaseAuthorizationRecord {
    pub(crate) fn validate_for(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        held: &MacosOrdinaryRunnerHeldEvidence,
    ) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        authority.validate_retained()?;
        held.validate_for(authority)?;
        if self.contract_version != CONTRACT_VERSION
            || self.attempt_id != authority.attempt.attempt_id
            || self.native_journal_id != authority.attempt.native_journal_id
            || self.platform_binding_digest != authority.platform_binding_digest
            || self.held_evidence_digest != held.evidence_digest
            || self.authorized_at_unix_ms < held.held_at_unix_ms
        {
            return Err(invalid(
                "release_authorization.binding",
                "release authorization differs from the exact held preparation",
            ));
        }
        Ok(())
    }
}

/// Contract candidate produced after positive same-launcher release readback.
///
/// A digest supplied by a future native adapter is required. The candidate is
/// not direct-child, signing, XPC, or containment evidence by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosOrdinaryRunnerReleaseEvidence {
    protocol_version: u32,
    assurance: MacosOrdinaryRunnerAssurance,
    attempt_id: String,
    native_journal_id: String,
    held_evidence_digest: Digest,
    release_authorization_digest: Digest,
    release_observation_digest: Digest,
    released_at_unix_ms: u64,
    evidence_digest: Digest,
}

#[derive(Serialize)]
struct ReleaseEvidencePreimage<'a> {
    protocol_version: u32,
    assurance: MacosOrdinaryRunnerAssurance,
    attempt_id: &'a str,
    native_journal_id: &'a str,
    held_evidence_digest: &'a Digest,
    release_authorization_digest: &'a Digest,
    release_observation_digest: &'a Digest,
    released_at_unix_ms: u64,
}

impl MacosOrdinaryRunnerReleaseEvidence {
    pub(crate) fn candidate_from_native_observation(
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        held: &MacosOrdinaryRunnerHeldEvidence,
        authorization: &MacosOrdinaryRunnerReleaseAuthorizationRecord,
        release_observation_digest: Digest,
        released_at_unix_ms: u64,
    ) -> Result<Self, MacosOrdinaryRunnerHeldProtocolError> {
        authorization.validate_for(authority, held)?;
        let release_authorization_digest = canonical_digest(authorization)?;
        let mut evidence = Self {
            protocol_version: MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION,
            assurance: MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter,
            attempt_id: authority.attempt.attempt_id.clone(),
            native_journal_id: authority.attempt.native_journal_id.clone(),
            held_evidence_digest: held.evidence_digest.clone(),
            release_authorization_digest,
            release_observation_digest,
            released_at_unix_ms,
            evidence_digest: Digest::sha256(&[]),
        };
        evidence.evidence_digest = evidence.computed_digest()?;
        evidence.validate_for(authority, held, authorization)?;
        Ok(evidence)
    }

    pub(crate) const fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    fn computed_digest(&self) -> Result<Digest, MacosOrdinaryRunnerHeldProtocolError> {
        let preimage = ReleaseEvidencePreimage {
            protocol_version: self.protocol_version,
            assurance: self.assurance,
            attempt_id: &self.attempt_id,
            native_journal_id: &self.native_journal_id,
            held_evidence_digest: &self.held_evidence_digest,
            release_authorization_digest: &self.release_authorization_digest,
            release_observation_digest: &self.release_observation_digest,
            released_at_unix_ms: self.released_at_unix_ms,
        };
        let bytes = serde_json::to_vec(&preimage).map_err(|error| {
            MacosOrdinaryRunnerHeldProtocolError::Encoding(format!(
                "release evidence preimage encoding failed: {error}"
            ))
        })?;
        let mut domain = Vec::with_capacity(RELEASE_EVIDENCE_DOMAIN.len() + bytes.len());
        domain.extend_from_slice(RELEASE_EVIDENCE_DOMAIN);
        domain.extend_from_slice(&bytes);
        Ok(Digest::sha256(&domain))
    }

    pub(crate) fn validate_for(
        &self,
        authority: &MacosOrdinaryRunnerLaunchAuthority,
        held: &MacosOrdinaryRunnerHeldEvidence,
        authorization: &MacosOrdinaryRunnerReleaseAuthorizationRecord,
    ) -> Result<(), MacosOrdinaryRunnerHeldProtocolError> {
        authorization.validate_for(authority, held)?;
        if self.protocol_version != MACOS_ORDINARY_RUNNER_HELD_PROTOCOL_VERSION
            || self.assurance != MacosOrdinaryRunnerAssurance::ContractOnlyNoNativeAdapter
            || self.attempt_id != authority.attempt.attempt_id
            || self.native_journal_id != authority.attempt.native_journal_id
            || self.held_evidence_digest != held.evidence_digest
            || self.release_authorization_digest != canonical_digest(authorization)?
            || self.released_at_unix_ms < authorization.authorized_at_unix_ms
            || self.released_at_unix_ms <= held.held_at_unix_ms
            || self.evidence_digest != self.computed_digest()?
        {
            return Err(invalid(
                "release_evidence.binding",
                "release candidate differs from the held preparation or one-shot authorization",
            ));
        }
        let json = serde_json::to_vec(self).map_err(|error| {
            MacosOrdinaryRunnerHeldProtocolError::Encoding(format!(
                "release evidence encoding failed: {error}"
            ))
        })?;
        if json.len() > MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES {
            return Err(MacosOrdinaryRunnerHeldProtocolError::TooLarge {
                field: "release evidence",
                bytes: json.len(),
                maximum: MAX_MACOS_ORDINARY_RUNNER_JOURNAL_RECORD_BYTES,
            });
        }
        Ok(())
    }
}

pub(crate) fn canonical_digest<T: Serialize>(
    value: &T,
) -> Result<Digest, MacosOrdinaryRunnerHeldProtocolError> {
    serde_json::to_vec(value)
        .map(|bytes| Digest::sha256(&bytes))
        .map_err(|error| {
            MacosOrdinaryRunnerHeldProtocolError::Encoding(format!(
                "canonical digest encoding failed: {error}"
            ))
        })
}

/// Fail-closed ordinary-runner held-launch contract error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MacosOrdinaryRunnerHeldProtocolError {
    Invalid {
        field: &'static str,
        detail: String,
    },
    Encoding(String),
    TooLarge {
        field: &'static str,
        bytes: usize,
        maximum: usize,
    },
}

impl Display for MacosOrdinaryRunnerHeldProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, detail } => {
                write!(
                    formatter,
                    "ordinary macOS runner {field} rejected: {detail}"
                )
            }
            Self::Encoding(detail) => {
                write!(formatter, "ordinary macOS runner encoding failed: {detail}")
            }
            Self::TooLarge {
                field,
                bytes,
                maximum,
            } => write!(
                formatter,
                "ordinary macOS runner {field} has {bytes} bytes; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for MacosOrdinaryRunnerHeldProtocolError {}

fn invalid(field: &'static str, detail: impl Into<String>) -> MacosOrdinaryRunnerHeldProtocolError {
    MacosOrdinaryRunnerHeldProtocolError::Invalid {
        field,
        detail: detail.into(),
    }
}
