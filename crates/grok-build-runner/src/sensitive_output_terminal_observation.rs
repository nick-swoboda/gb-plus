//! Immutable restart observation for one sensitive-output command termination.
//!
//! This record closes the process-local knowledge gap between native command
//! termination and the generation-five-through-eight sensitive-output branch
//! journals. It is a separate, one-per-capture input: it is not generation
//! nine, does not reinterpret an existing journal head, and grants no launch,
//! cleanup, publication, retry, verification, or completion authority.
//!
//! The rejection variant is deliberately fieldless. In particular, its
//! canonical bytes cannot contain output length, output digest, retained
//! bytes, stream, matcher, elapsed-time, or wall-clock fields. The clean
//! variant may retain only the clean stream summaries and response fields
//! already admitted by the eventual command terminal. Its `duration_ms` is an
//! elapsed response value, not a wall-clock timestamp. No variant contains a
//! wall-clock timestamp.
//!
//! # Proposed integration API
//!
//! The command supervisor should construct this value immediately after it
//! knows the closed branch and an independently validated command-domain proof
//! shows zero survivors. The descriptor-relative output store should publish
//! [`canonical_bytes`](SensitiveOutputTerminalObservationV1::canonical_bytes)
//! once under [`SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1`] using a private
//! temporary file, file sync, no-replace rename, directory sync, exact reopen,
//! and [`decode_canonical`](SensitiveOutputTerminalObservationV1::decode_canonical).
//! Restart recovery must then call
//! [`validate_expected`](SensitiveOutputTerminalObservationV1::validate_expected)
//! with the current journal-derived branch, core-selected backend and binding,
//! and a freshly reopened native proof. It must separately perform fresh
//! descriptor-relative output-custody readback before continuing a branch.
//! Neither canonical decode nor `validate_expected` represents that custody
//! check, so neither can authorize continuation by itself.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use grok_build_core::{
    CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1, CommandTerminationV1,
    Digest,
};
use serde::{Deserialize, Serialize};

use crate::cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, ValidatedCommandDomainCleanupProof,
};
use crate::command_output_store::MAX_COMMAND_OUTPUT_ARTIFACT_BYTES;
use crate::wire::{
    MAX_INLINE_COMMAND_RETAINED_BYTES, ValidatedCommandCaptureLaunchBindingV12,
    WireCommandBackendIdentity, WireCommandStreamEvidence, command_stream_output_digest,
    command_stream_output_evidence_bytes,
};

/// Immutable schema version for a sensitive-output terminal observation.
pub const SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FORMAT_VERSION_V1: u32 = 1;

/// Domain used to authenticate the exact observation preimage.
pub const SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_DIGEST_DOMAIN_V1: &[u8] =
    b"grok-build/sensitive-output-terminal-observation/v1\0";

/// Fixed filename reserved inside one private capture namespace.
pub const SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1: &str =
    "sensitive-output-terminal-observation.v1.json";

// A retained byte is serialized by serde_json as at most three decimal digits
// plus one delimiter. The fixed allowance covers both arrays, their brackets,
// every identity field, and future-compatible error-free canonical readback.
const JSON_U8_WORST_CASE_BYTES_PER_ELEMENT: usize = 4;
const TERMINAL_OBSERVATION_FIXED_CANONICAL_ALLOWANCE_BYTES_V1: usize = 256 * 1024;

/// Maximum canonical observation bytes, including worst-case JSON expansion of
/// the complete permitted retained-output budget.
pub const MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1: usize =
    MAX_INLINE_COMMAND_RETAINED_BYTES * JSON_U8_WORST_CASE_BYTES_PER_ELEMENT
        + TERMINAL_OBSERVATION_FIXED_CANONICAL_ALLOWANCE_BYTES_V1;

const MAX_BINDING_ID_BYTES: usize = 256;
const MAX_BACKEND_ID_BYTES: usize = 128;

/// Closed branch named by one terminal observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveOutputTerminalObservationBranchV1 {
    /// The scanner selected the zero-first rejection branch.
    Rejection,
    /// The scanner selected the clean publication branch.
    Clean,
}

/// Clean-only data needed to reconstruct the eventual exact command response.
///
/// This value has no cleanup proof, output-capture terminal, or journal head.
/// Those remain independently reopened inputs to restart recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputCleanTerminalResponseV1 {
    stdout: WireCommandStreamEvidence,
    stderr: WireCommandStreamEvidence,
    output_artifacts: CommandOutputArtifactSetReferenceV1,
    output_digest: Digest,
    launch_digest: Digest,
    preflight_digest: Digest,
    backend: WireCommandBackendIdentity,
    duration_ms: u64,
}

impl SensitiveOutputCleanTerminalResponseV1 {
    /// Constructs and validates the clean-only response reconstruction fields.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed streams, crossed artifact/source data,
    /// invalid backend identity, output-bound overflow, or digest mismatch.
    #[allow(
        clippy::too_many_arguments,
        reason = "the exact clean response fields are intentionally visible at the one construction boundary"
    )]
    pub(crate) fn try_new(
        stdout: WireCommandStreamEvidence,
        stderr: WireCommandStreamEvidence,
        output_artifacts: CommandOutputArtifactSetReferenceV1,
        output_digest: Digest,
        launch_digest: Digest,
        preflight_digest: Digest,
        backend: WireCommandBackendIdentity,
        duration_ms: u64,
    ) -> Result<Self, SensitiveOutputTerminalObservationError> {
        let response = Self {
            stdout,
            stderr,
            output_artifacts,
            output_digest,
            launch_digest,
            preflight_digest,
            backend,
            duration_ms,
        };
        response.validate_shape()?;
        Ok(response)
    }

    /// Clean stdout summary and bounded retained bytes.
    #[must_use]
    pub const fn stdout(&self) -> &WireCommandStreamEvidence {
        &self.stdout
    }

    /// Clean stderr summary and bounded retained bytes.
    #[must_use]
    pub const fn stderr(&self) -> &WireCommandStreamEvidence {
        &self.stderr
    }

    /// Immutable complete-stream artifact commitment.
    #[must_use]
    pub const fn output_artifacts(&self) -> &CommandOutputArtifactSetReferenceV1 {
        &self.output_artifacts
    }

    /// Framed digest of the complete stdout and stderr commitments.
    #[must_use]
    pub const fn output_digest(&self) -> &Digest {
        &self.output_digest
    }

    /// Exact contained-launch digest carried by the eventual response.
    #[must_use]
    pub const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    /// Exact native-preflight digest carried by the eventual response.
    #[must_use]
    pub const fn preflight_digest(&self) -> &Digest {
        &self.preflight_digest
    }

    /// Exact containment implementation identity for response reconstruction.
    #[must_use]
    pub const fn backend(&self) -> &WireCommandBackendIdentity {
        &self.backend
    }

    /// Elapsed command duration carried by the eventual clean response.
    #[must_use]
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    fn validate_shape(&self) -> Result<(), SensitiveOutputTerminalObservationError> {
        validate_stream(&self.stdout)?;
        validate_stream(&self.stderr)?;
        self.output_artifacts
            .validate()
            .map_err(|_| SensitiveOutputTerminalObservationError::InvalidCleanResponse)?;
        if self.output_artifacts.stdout.byte_length != self.stdout.complete_length
            || self.output_artifacts.stdout.content_digest != self.stdout.complete_digest
            || self.output_artifacts.stderr.byte_length != self.stderr.complete_length
            || self.output_artifacts.stderr.content_digest != self.stderr.complete_digest
            || self
                .output_artifacts
                .output_evidence_bytes()
                .map_err(|_| SensitiveOutputTerminalObservationError::InvalidCleanResponse)?
                != command_stream_output_evidence_bytes(&self.stdout, &self.stderr)
        {
            return Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse);
        }

        let retained_length = self
            .stdout
            .retained_bytes
            .len()
            .checked_add(self.stderr.retained_bytes.len())
            .ok_or(SensitiveOutputTerminalObservationError::InvalidCleanResponse)?;
        let complete_length = self
            .stdout
            .complete_length
            .checked_add(self.stderr.complete_length)
            .ok_or(SensitiveOutputTerminalObservationError::InvalidCleanResponse)?;
        if retained_length > MAX_INLINE_COMMAND_RETAINED_BYTES
            || complete_length > MAX_COMMAND_OUTPUT_ARTIFACT_BYTES
            || self.backend.backend_id.is_empty()
            || self.backend.backend_id.len() > MAX_BACKEND_ID_BYTES
            || self.backend.backend_id.trim().is_empty()
            || self.backend.backend_id.chars().any(char::is_control)
            || self.output_digest != command_stream_output_digest(&self.stdout, &self.stderr)
        {
            return Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse);
        }
        Ok(())
    }

    fn validate_for_observation(
        &self,
        runner_session_id: &str,
        effect_id: &str,
        request_digest: &Digest,
        termination: CommandTerminationV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
    ) -> Result<(), SensitiveOutputTerminalObservationError> {
        self.validate_shape()?;
        let source = &self.output_artifacts.source;
        if source.runner_session_id != runner_session_id
            || source.effect_id != effect_id
            || &source.request_digest != request_digest
            || self.backend.command_domain_backend != expected_cleanup_backend
            || matches!(termination, CommandTerminationV1::OutputLimitExceeded)
                && !self.stdout.truncated
                && !self.stderr.truncated
        {
            return Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCommandDomainBindingV1 {
    runner_session_id: String,
    command_effect_id: String,
    command_request_digest: Digest,
}

impl StoredCommandDomainBindingV1 {
    fn from_binding(binding: &CommandDomainCleanupBinding) -> Self {
        Self {
            runner_session_id: binding.runner_session_id().to_owned(),
            command_effect_id: binding.command_effect_id().to_owned(),
            command_request_digest: binding.command_request_digest().clone(),
        }
    }

    fn validated(
        &self,
    ) -> Result<CommandDomainCleanupBinding, SensitiveOutputTerminalObservationError> {
        CommandDomainCleanupBinding::try_new(
            self.runner_session_id.clone(),
            self.command_effect_id.clone(),
            self.command_request_digest.clone(),
        )
        .map_err(|_| SensitiveOutputTerminalObservationError::InvalidCommandDomainBinding)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StoredObservationBranchV1 {
    Rejection,
    Clean {
        response: Box<SensitiveOutputCleanTerminalResponseV1>,
    },
}

impl StoredObservationBranchV1 {
    const fn kind(&self) -> SensitiveOutputTerminalObservationBranchV1 {
        match self {
            Self::Rejection => SensitiveOutputTerminalObservationBranchV1::Rejection,
            Self::Clean { .. } => SensitiveOutputTerminalObservationBranchV1::Clean,
        }
    }

    const fn clean_response(&self) -> Option<&SensitiveOutputCleanTerminalResponseV1> {
        match self {
            Self::Rejection => None,
            Self::Clean { response } => Some(response),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSensitiveOutputTerminalObservationV1 {
    format_version: u32,
    capture_id: String,
    runner_session_id: String,
    effect_id: String,
    request_digest: Digest,
    branch: StoredObservationBranchV1,
    termination: CommandTerminationV1,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    cleanup_proof_digest: Digest,
    command_domain_binding: StoredCommandDomainBindingV1,
    observation_digest: Digest,
}

#[derive(Serialize)]
struct ObservationDigestPreimageV1<'a> {
    format_version: u32,
    capture_id: &'a str,
    runner_session_id: &'a str,
    effect_id: &'a str,
    request_digest: &'a Digest,
    branch: &'a StoredObservationBranchV1,
    termination: CommandTerminationV1,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    cleanup_proof_digest: &'a Digest,
    command_domain_binding: &'a StoredCommandDomainBindingV1,
}

/// Strict canonical, immutable observation of one closed command termination.
///
/// Fields remain private and this wrapper does not implement `Deserialize`.
/// Arbitrary JSON therefore cannot manufacture a validated instance; callers
/// must use strict canonical decode. Even a decoded instance is only one input
/// to branch recovery and carries no authority by itself.
#[must_use = "a terminal observation must be crossed with journal state, fresh native proof, and fresh output custody"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputTerminalObservationV1 {
    record: StoredSensitiveOutputTerminalObservationV1,
    canonical_bytes: Vec<u8>,
}

impl SensitiveOutputTerminalObservationV1 {
    /// Constructs a rejection observation with no output- or timing-bearing fields.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, termination, backend, proof, or
    /// canonical encoding.
    pub(crate) fn try_new_rejection(
        capture_id: impl Into<String>,
        termination: CommandTerminationV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<Self, SensitiveOutputTerminalObservationError> {
        Self::try_new(
            capture_id.into(),
            StoredObservationBranchV1::Rejection,
            termination,
            expected_cleanup_backend,
            expected_binding,
            native_cleanup_proof,
        )
    }

    /// Constructs a clean observation from exact eventual-response fields.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, termination, backend, proof,
    /// clean output, source crossing, output bounds, or canonical encoding.
    pub(crate) fn try_new_clean(
        capture_id: impl Into<String>,
        termination: CommandTerminationV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
        clean_response: SensitiveOutputCleanTerminalResponseV1,
    ) -> Result<Self, SensitiveOutputTerminalObservationError> {
        Self::try_new(
            capture_id.into(),
            StoredObservationBranchV1::Clean {
                response: Box::new(clean_response),
            },
            termination,
            expected_cleanup_backend,
            expected_binding,
            native_cleanup_proof,
        )
    }

    fn try_new(
        capture_id: String,
        branch: StoredObservationBranchV1,
        termination: CommandTerminationV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<Self, SensitiveOutputTerminalObservationError> {
        let command_domain_binding = StoredCommandDomainBindingV1::from_binding(expected_binding);
        let mut record = StoredSensitiveOutputTerminalObservationV1 {
            format_version: SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FORMAT_VERSION_V1,
            capture_id,
            runner_session_id: expected_binding.runner_session_id().to_owned(),
            effect_id: expected_binding.command_effect_id().to_owned(),
            request_digest: expected_binding.command_request_digest().clone(),
            branch,
            termination,
            expected_cleanup_backend,
            cleanup_proof_digest: native_cleanup_proof.os_evidence_digest().clone(),
            command_domain_binding,
            observation_digest: Digest::sha256(&[]),
        };
        record.observation_digest = compute_observation_digest(&record)?;
        let observation = Self::from_record(record)?;
        observation.validate_expected(
            observation.capture_id(),
            observation.branch(),
            expected_cleanup_backend,
            expected_binding,
            native_cleanup_proof,
        )?;
        Ok(observation)
    }

    /// Strictly decodes exact canonical bytes and validates the self-contained shape.
    ///
    /// This operation does not reopen native cleanup evidence or output
    /// custody and therefore grants no branch-continuation authority.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, malformed, alternate, unknown,
    /// unsupported, digest-crossed, or semantically invalid bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, SensitiveOutputTerminalObservationError> {
        if bytes.is_empty() {
            return Err(SensitiveOutputTerminalObservationError::EmptyBytes);
        }
        if bytes.len() > MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1 {
            return Err(
                SensitiveOutputTerminalObservationError::ObservationTooLarge { bytes: bytes.len() },
            );
        }
        let record: StoredSensitiveOutputTerminalObservationV1 = serde_json::from_slice(bytes)
            .map_err(|_| SensitiveOutputTerminalObservationError::Decoding)?;
        let observation = Self::from_record(record)?;
        if observation.canonical_bytes != bytes {
            return Err(SensitiveOutputTerminalObservationError::NonCanonical);
        }
        Ok(observation)
    }

    fn from_record(
        record: StoredSensitiveOutputTerminalObservationV1,
    ) -> Result<Self, SensitiveOutputTerminalObservationError> {
        validate_record(&record)?;
        let canonical_bytes = serde_json::to_vec(&record)
            .map_err(|_| SensitiveOutputTerminalObservationError::Encoding)?;
        if canonical_bytes.len() > MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1 {
            return Err(
                SensitiveOutputTerminalObservationError::ObservationTooLarge {
                    bytes: canonical_bytes.len(),
                },
            );
        }
        Ok(Self {
            record,
            canonical_bytes,
        })
    }

    /// Revalidates identity against current branch state and fresh native proof.
    ///
    /// This still does not validate descriptor-relative output custody. The
    /// caller must perform that independent readback before continuing a
    /// generation-five-through-seven branch.
    ///
    /// # Errors
    ///
    /// Returns an error when capture, branch, backend, binding, proof bytes,
    /// proof digest, or canonical self-validation differs.
    pub fn validate_expected(
        &self,
        expected_capture_id: &str,
        expected_branch: SensitiveOutputTerminalObservationBranchV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        freshly_reopened_native_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<(), SensitiveOutputTerminalObservationError> {
        validate_record(&self.record)?;
        if serde_json::to_vec(&self.record)
            .map_err(|_| SensitiveOutputTerminalObservationError::Encoding)?
            != self.canonical_bytes
        {
            return Err(SensitiveOutputTerminalObservationError::ReadbackMismatch);
        }
        if self.record.capture_id != expected_capture_id {
            return Err(SensitiveOutputTerminalObservationError::ExpectedCaptureMismatch);
        }
        if self.branch() != expected_branch {
            return Err(SensitiveOutputTerminalObservationError::ExpectedBranchMismatch);
        }
        if self.record.expected_cleanup_backend != expected_cleanup_backend {
            return Err(SensitiveOutputTerminalObservationError::ExpectedBackendMismatch);
        }
        let recorded_binding = self.record.command_domain_binding.validated()?;
        if &recorded_binding != expected_binding {
            return Err(SensitiveOutputTerminalObservationError::ExpectedBindingMismatch);
        }
        freshly_reopened_native_proof
            .validate_expected(
                &self.record.cleanup_proof_digest,
                expected_cleanup_backend,
                expected_binding,
            )
            .map_err(|_| SensitiveOutputTerminalObservationError::InvalidNativeCleanupProof)?;
        Ok(())
    }

    /// Revalidates a clean observation against the exact reopened V12 launch
    /// binding and physical acquisition that independently authorize its
    /// response identities.
    ///
    /// This method still grants no publication or completion authority. The
    /// caller must separately reopen the clean branch journal and exact output
    /// artifacts before reconstructing a terminal response.
    ///
    /// # Errors
    ///
    /// Returns an error for any ordinary observation/proof mismatch or when the
    /// acquired source, full backend generation, launch digest, or preflight
    /// digest differs from the exact durable launch binding.
    #[allow(
        clippy::too_many_arguments,
        reason = "each independently reopened clean-response authority remains explicit at the rejoin boundary"
    )]
    pub fn validate_expected_clean(
        &self,
        expected_capture_id: &str,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        freshly_reopened_native_proof: &ValidatedCommandDomainCleanupProof,
        launch_binding: &ValidatedCommandCaptureLaunchBindingV12,
        acquired: &CommandOutputCaptureAcquiredV1,
    ) -> Result<(), SensitiveOutputTerminalObservationError> {
        self.validate_expected(
            expected_capture_id,
            SensitiveOutputTerminalObservationBranchV1::Clean,
            expected_cleanup_backend,
            expected_binding,
            freshly_reopened_native_proof,
        )?;
        acquired
            .validate()
            .map_err(|_| SensitiveOutputTerminalObservationError::InvalidAcquiredCapture)?;
        let response = self
            .clean_response()
            .ok_or(SensitiveOutputTerminalObservationError::ExpectedCleanAuthorityMismatch)?;
        if acquired.capture_id != expected_capture_id
            || acquired.source != response.output_artifacts.source
            || launch_binding.command_domain_binding() != expected_binding
            || launch_binding.launch_digest() != response.launch_digest()
            || launch_binding.preflight_digest() != response.preflight_digest()
            || launch_binding.backend() != response.backend()
        {
            return Err(SensitiveOutputTerminalObservationError::ExpectedCleanAuthorityMismatch);
        }
        Ok(())
    }

    /// Revalidates a newly constructed clean observation against the exact
    /// live launch authority immediately before immutable publication.
    ///
    /// Restart uses [`Self::validate_expected_clean`] with its decoded durable
    /// V12 launch binding. The live supervisor already owns the same values as
    /// move-only validated authority, so it crosses them directly rather than
    /// decoding its own just-produced bytes and treating that decode as an
    /// independent authority source.
    ///
    /// This operation still grants no output publication or completion
    /// authority. It only proves that the sidecar about to be written names
    /// the exact acquisition, launch, preflight, backend, binding, and native
    /// cleanup proof held by the live supervisor.
    #[allow(
        clippy::too_many_arguments,
        reason = "every independent live clean-response authority remains explicit at the immutable sidecar boundary"
    )]
    pub(crate) fn validate_expected_clean_live(
        &self,
        expected_capture_id: &str,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
        validated_native_proof: &ValidatedCommandDomainCleanupProof,
        acquired: &CommandOutputCaptureAcquiredV1,
        expected_launch_digest: &Digest,
        expected_preflight_digest: &Digest,
        expected_backend: &WireCommandBackendIdentity,
    ) -> Result<(), SensitiveOutputTerminalObservationError> {
        self.validate_expected(
            expected_capture_id,
            SensitiveOutputTerminalObservationBranchV1::Clean,
            expected_cleanup_backend,
            expected_binding,
            validated_native_proof,
        )?;
        acquired
            .validate()
            .map_err(|_| SensitiveOutputTerminalObservationError::InvalidAcquiredCapture)?;
        let response = self
            .clean_response()
            .ok_or(SensitiveOutputTerminalObservationError::ExpectedCleanAuthorityMismatch)?;
        if acquired.capture_id != expected_capture_id
            || acquired.source != response.output_artifacts.source
            || response.launch_digest() != expected_launch_digest
            || response.preflight_digest() != expected_preflight_digest
            || response.backend() != expected_backend
        {
            return Err(SensitiveOutputTerminalObservationError::ExpectedCleanAuthorityMismatch);
        }
        Ok(())
    }

    /// Exact canonical bytes to publish once in the private capture namespace.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Exact capture identity.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        &self.record.capture_id
    }

    /// Exact runner session named by the command-domain binding.
    #[must_use]
    pub fn runner_session_id(&self) -> &str {
        &self.record.runner_session_id
    }

    /// Exact command effect named by the command-domain binding.
    #[must_use]
    pub fn effect_id(&self) -> &str {
        &self.record.effect_id
    }

    /// Exact canonical command-request digest.
    #[must_use]
    pub const fn request_digest(&self) -> &Digest {
        &self.record.request_digest
    }

    /// Closed clean or rejection branch.
    #[must_use]
    pub const fn branch(&self) -> SensitiveOutputTerminalObservationBranchV1 {
        self.record.branch.kind()
    }

    /// Typed command termination observed after the domain became empty.
    #[must_use]
    pub const fn termination(&self) -> CommandTerminationV1 {
        self.record.termination
    }

    /// Core-selected cleanup backend expected by this observation.
    #[must_use]
    pub const fn expected_cleanup_backend(&self) -> CommandDomainCleanupBackend {
        self.record.expected_cleanup_backend
    }

    /// Digest identity of the independently retained native cleanup proof.
    #[must_use]
    pub const fn cleanup_proof_digest(&self) -> &Digest {
        &self.record.cleanup_proof_digest
    }

    /// Clean response reconstruction fields, absent on rejection.
    #[must_use]
    pub const fn clean_response(&self) -> Option<&SensitiveOutputCleanTerminalResponseV1> {
        self.record.branch.clean_response()
    }

    /// Domain-separated identity of the exact observation preimage.
    #[must_use]
    pub const fn observation_digest(&self) -> &Digest {
        &self.record.observation_digest
    }
}

fn validate_record(
    record: &StoredSensitiveOutputTerminalObservationV1,
) -> Result<(), SensitiveOutputTerminalObservationError> {
    if record.format_version != SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FORMAT_VERSION_V1 {
        return Err(
            SensitiveOutputTerminalObservationError::UnsupportedVersion {
                version: record.format_version,
            },
        );
    }
    validate_capture_id(&record.capture_id)?;
    validate_binding_id(&record.runner_session_id)?;
    validate_binding_id(&record.effect_id)?;
    record
        .termination
        .validate()
        .map_err(|_| SensitiveOutputTerminalObservationError::InvalidTermination)?;
    let binding = record.command_domain_binding.validated()?;
    if binding.runner_session_id() != record.runner_session_id
        || binding.command_effect_id() != record.effect_id
        || binding.command_request_digest() != &record.request_digest
    {
        return Err(SensitiveOutputTerminalObservationError::CrossedCommandDomainBinding);
    }
    match &record.branch {
        StoredObservationBranchV1::Rejection => {}
        StoredObservationBranchV1::Clean { response } => response.validate_for_observation(
            &record.runner_session_id,
            &record.effect_id,
            &record.request_digest,
            record.termination,
            record.expected_cleanup_backend,
        )?,
    }
    if compute_observation_digest(record)? != record.observation_digest {
        return Err(SensitiveOutputTerminalObservationError::ObservationDigestMismatch);
    }
    Ok(())
}

fn compute_observation_digest(
    record: &StoredSensitiveOutputTerminalObservationV1,
) -> Result<Digest, SensitiveOutputTerminalObservationError> {
    let canonical = serde_json::to_vec(&ObservationDigestPreimageV1 {
        format_version: record.format_version,
        capture_id: &record.capture_id,
        runner_session_id: &record.runner_session_id,
        effect_id: &record.effect_id,
        request_digest: &record.request_digest,
        branch: &record.branch,
        termination: record.termination,
        expected_cleanup_backend: record.expected_cleanup_backend,
        cleanup_proof_digest: &record.cleanup_proof_digest,
        command_domain_binding: &record.command_domain_binding,
    })
    .map_err(|_| SensitiveOutputTerminalObservationError::Encoding)?;
    let length = u64::try_from(canonical.len())
        .map_err(|_| SensitiveOutputTerminalObservationError::Encoding)?;
    let mut preimage = Vec::with_capacity(
        SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_DIGEST_DOMAIN_V1.len()
            + std::mem::size_of::<u64>()
            + canonical.len(),
    );
    preimage.extend_from_slice(SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_DIGEST_DOMAIN_V1);
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

fn validate_capture_id(value: &str) -> Result<(), SensitiveOutputTerminalObservationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SensitiveOutputTerminalObservationError::InvalidCaptureId);
    }
    Ok(())
}

fn validate_binding_id(value: &str) -> Result<(), SensitiveOutputTerminalObservationError> {
    if value.is_empty()
        || value.len() > MAX_BINDING_ID_BYTES
        || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err(SensitiveOutputTerminalObservationError::InvalidCommandDomainBinding);
    }
    Ok(())
}

fn validate_stream(
    stream: &WireCommandStreamEvidence,
) -> Result<(), SensitiveOutputTerminalObservationError> {
    let retained_length = u64::try_from(stream.retained_bytes.len())
        .map_err(|_| SensitiveOutputTerminalObservationError::InvalidCleanResponse)?;
    if retained_length > stream.complete_length
        || stream.truncated != (retained_length < stream.complete_length)
        || !stream.truncated && Digest::sha256(&stream.retained_bytes) != stream.complete_digest
    {
        return Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse);
    }
    Ok(())
}

/// Closed failures for terminal-observation construction and readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensitiveOutputTerminalObservationError {
    /// No bytes were supplied.
    EmptyBytes,
    /// Canonical bytes exceeded the fixed observation bound.
    ObservationTooLarge {
        /// Observed byte count.
        bytes: usize,
    },
    /// Strict JSON decoding failed.
    Decoding,
    /// Canonical JSON encoding failed.
    Encoding,
    /// Valid JSON used alternate bytes.
    NonCanonical,
    /// The immutable format version differs.
    UnsupportedVersion {
        /// Observed version.
        version: u32,
    },
    /// Capture identity was not canonical lowercase SHA-256 text.
    InvalidCaptureId,
    /// Typed command termination was malformed.
    InvalidTermination,
    /// Command-domain identity was malformed.
    InvalidCommandDomainBinding,
    /// Redundant session/effect/request fields crossed the command binding.
    CrossedCommandDomainBinding,
    /// Clean response reconstruction fields were malformed or crossed.
    InvalidCleanResponse,
    /// The independently reopened physical acquisition was malformed.
    InvalidAcquiredCapture,
    /// Clean response identities differed from exact durable launch authority.
    ExpectedCleanAuthorityMismatch,
    /// The domain-separated observation digest differed.
    ObservationDigestMismatch,
    /// Retained wrapper fields differed from exact canonical re-encoding.
    ReadbackMismatch,
    /// Current journal capture differs from the observation.
    ExpectedCaptureMismatch,
    /// Current journal branch differs from the observation.
    ExpectedBranchMismatch,
    /// Core-selected cleanup backend differs from the observation.
    ExpectedBackendMismatch,
    /// Current command-domain binding differs from the observation.
    ExpectedBindingMismatch,
    /// Fresh native proof failed canonical, backend, binding, or digest validation.
    InvalidNativeCleanupProof,
}

impl Display for SensitiveOutputTerminalObservationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBytes => formatter.write_str("terminal-observation bytes are empty"),
            Self::ObservationTooLarge { bytes } => write!(
                formatter,
                "terminal-observation bytes have length {bytes}; maximum is {MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1}"
            ),
            Self::Decoding => formatter.write_str("terminal-observation decoding failed"),
            Self::Encoding => formatter.write_str("terminal-observation encoding failed"),
            Self::NonCanonical => {
                formatter.write_str("terminal-observation bytes are not canonical")
            }
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "unsupported terminal-observation version {version}"
                )
            }
            Self::InvalidCaptureId => {
                formatter.write_str("terminal-observation capture identity is invalid")
            }
            Self::InvalidTermination => {
                formatter.write_str("terminal-observation termination is invalid")
            }
            Self::InvalidCommandDomainBinding => {
                formatter.write_str("terminal-observation command-domain binding is invalid")
            }
            Self::CrossedCommandDomainBinding => formatter
                .write_str("terminal-observation redundant command-domain fields are crossed"),
            Self::InvalidCleanResponse => {
                formatter.write_str("terminal-observation clean response is invalid")
            }
            Self::InvalidAcquiredCapture => {
                formatter.write_str("terminal-observation acquired capture is invalid")
            }
            Self::ExpectedCleanAuthorityMismatch => formatter.write_str(
                "terminal-observation clean response differs from durable launch authority",
            ),
            Self::ObservationDigestMismatch => formatter
                .write_str("terminal-observation digest differs from its canonical preimage"),
            Self::ReadbackMismatch => {
                formatter.write_str("terminal-observation wrapper differs from canonical readback")
            }
            Self::ExpectedCaptureMismatch => {
                formatter.write_str("terminal-observation capture differs from current state")
            }
            Self::ExpectedBranchMismatch => {
                formatter.write_str("terminal-observation branch differs from current state")
            }
            Self::ExpectedBackendMismatch => {
                formatter.write_str("terminal-observation backend differs from durable expectation")
            }
            Self::ExpectedBindingMismatch => {
                formatter.write_str("terminal-observation binding differs from durable expectation")
            }
            Self::InvalidNativeCleanupProof => formatter
                .write_str("terminal-observation native cleanup proof failed fresh readback"),
        }
    }
}

impl Error for SensitiveOutputTerminalObservationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use grok_build_core::{
        CommandOutputArtifactSourceV1, CommandOutputStreamArtifactV1, CommandOutputStreamV1,
    };
    use serde_json::{Map, Value};

    use super::*;
    use crate::cleanup_proof::tests::{
        alternate_validated_linux_cleanup_proof_for, surviving_linux_cleanup_proof_for,
        tampered_linux_cleanup_proof_for, validated_linux_cleanup_proof_for,
    };

    fn capture_id() -> String {
        "a".repeat(64)
    }

    fn binding() -> CommandDomainCleanupBinding {
        CommandDomainCleanupBinding::try_new(
            "runner-session-observation-1",
            "command-effect-observation-1",
            Digest::sha256(b"request-observation-1"),
        )
        .expect("valid observation binding")
    }

    fn stream(bytes: &[u8]) -> WireCommandStreamEvidence {
        WireCommandStreamEvidence {
            retained_bytes: bytes.to_vec(),
            complete_digest: Digest::sha256(bytes),
            complete_length: u64::try_from(bytes.len()).expect("fixture length fits u64"),
            truncated: false,
        }
    }

    fn clean_response_for(
        binding: &CommandDomainCleanupBinding,
    ) -> SensitiveOutputCleanTerminalResponseV1 {
        let stdout = stream(b"clean stdout\n");
        let stderr = stream(b"clean stderr\n");
        clean_response_with_streams(binding, stdout, stderr)
    }

    fn clean_response_with_streams(
        binding: &CommandDomainCleanupBinding,
        stdout: WireCommandStreamEvidence,
        stderr: WireCommandStreamEvidence,
    ) -> SensitiveOutputCleanTerminalResponseV1 {
        let output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-observation-1".into(),
                runner_launch_id: "launch-observation-1".into(),
                runner_session_id: binding.runner_session_id().into(),
                effect_id: binding.command_effect_id().into(),
                request_digest: binding.command_request_digest().clone(),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: stdout.complete_length,
                content_digest: stdout.complete_digest.clone(),
            },
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stderr,
                byte_length: stderr.complete_length,
                content_digest: stderr.complete_digest.clone(),
            },
        )
        .expect("valid clean artifact reference");
        let output_digest = command_stream_output_digest(&stdout, &stderr);
        SensitiveOutputCleanTerminalResponseV1::try_new(
            stdout,
            stderr,
            output_artifacts,
            output_digest,
            Digest::sha256(b"launch-observation-1"),
            Digest::sha256(b"preflight-observation-1"),
            WireCommandBackendIdentity {
                command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "linux-cgroup-v2-observation-1".into(),
                implementation_digest: Digest::sha256(b"linux-backend-observation-1"),
            },
            27,
        )
        .expect("valid clean response")
    }

    fn object_keys(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .expect("expected JSON object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    fn rejection() -> (
        SensitiveOutputTerminalObservationV1,
        CommandDomainCleanupBinding,
        ValidatedCommandDomainCleanupProof,
    ) {
        let binding = binding();
        let proof = validated_linux_cleanup_proof_for(&binding);
        let observation = SensitiveOutputTerminalObservationV1::try_new_rejection(
            capture_id(),
            CommandTerminationV1::Exited { code: 1 },
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &binding,
            &proof,
        )
        .expect("valid rejection observation");
        (observation, binding, proof)
    }

    fn clean() -> (
        SensitiveOutputTerminalObservationV1,
        CommandDomainCleanupBinding,
        ValidatedCommandDomainCleanupProof,
    ) {
        let binding = binding();
        let proof = validated_linux_cleanup_proof_for(&binding);
        let response = clean_response_for(&binding);
        let observation = SensitiveOutputTerminalObservationV1::try_new_clean(
            capture_id(),
            CommandTerminationV1::Exited { code: 0 },
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &binding,
            &proof,
            response,
        )
        .expect("valid clean observation");
        (observation, binding, proof)
    }

    fn reseal(
        record: &mut StoredSensitiveOutputTerminalObservationV1,
    ) -> SensitiveOutputTerminalObservationV1 {
        record.observation_digest = compute_observation_digest(record).expect("reseal digest");
        SensitiveOutputTerminalObservationV1::from_record(record.clone())
            .expect("resealed fixture remains valid")
    }

    #[test]
    fn rejection_is_canonical_and_contains_no_output_or_timing_fields() {
        let (observation, binding, proof) = rejection();
        let reopened =
            SensitiveOutputTerminalObservationV1::decode_canonical(observation.canonical_bytes())
                .expect("canonical rejection reopens");
        assert_eq!(reopened, observation);
        assert_eq!(
            reopened.branch(),
            SensitiveOutputTerminalObservationBranchV1::Rejection
        );
        assert_eq!(reopened.clean_response(), None);
        reopened
            .validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Rejection,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &proof,
            )
            .expect("rejection rejoins fresh proof");

        let json = String::from_utf8(observation.canonical_bytes().to_vec())
            .expect("canonical observation is UTF-8 JSON");
        for forbidden in [
            "stdout",
            "stderr",
            "output_artifacts",
            "output_digest",
            "retained_bytes",
            "complete_digest",
            "complete_length",
            "truncated",
            "duration_ms",
            "at_unix_ms",
            "match",
            "stream",
        ] {
            assert!(
                !json.contains(forbidden),
                "rejection leaked field {forbidden}"
            );
        }
        assert_eq!(
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_DIGEST_DOMAIN_V1,
            b"grok-build/sensitive-output-terminal-observation/v1\0"
        );
        assert_eq!(
            SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1,
            "sensitive-output-terminal-observation.v1.json"
        );

        let value: Value = serde_json::from_slice(observation.canonical_bytes()).expect("JSON");
        assert_eq!(
            object_keys(&value),
            BTreeSet::from([
                "branch",
                "capture_id",
                "cleanup_proof_digest",
                "command_domain_binding",
                "effect_id",
                "expected_cleanup_backend",
                "format_version",
                "observation_digest",
                "request_digest",
                "runner_session_id",
                "termination",
            ])
        );
        assert_eq!(
            object_keys(&value["branch"]),
            BTreeSet::from(["kind"]),
            "the rejection branch has exactly one non-output discriminator"
        );
        assert_eq!(
            object_keys(&value["command_domain_binding"]),
            BTreeSet::from([
                "command_effect_id",
                "command_request_digest",
                "runner_session_id",
            ])
        );
        assert_eq!(
            object_keys(&value["termination"]),
            BTreeSet::from(["code", "kind"])
        );
    }

    #[test]
    fn clean_roundtrip_preserves_only_exact_response_reconstruction_fields() {
        let (observation, binding, proof) = clean();
        let reopened =
            SensitiveOutputTerminalObservationV1::decode_canonical(observation.canonical_bytes())
                .expect("canonical clean observation reopens");
        assert_eq!(reopened, observation);
        assert_eq!(
            reopened.branch(),
            SensitiveOutputTerminalObservationBranchV1::Clean
        );
        let response = reopened.clean_response().expect("clean response present");
        assert_eq!(response.stdout().retained_bytes, b"clean stdout\n");
        assert_eq!(response.stderr().retained_bytes, b"clean stderr\n");
        assert_eq!(response.duration_ms(), 27);
        assert_eq!(
            response.output_artifacts().source.runner_session_id,
            binding.runner_session_id()
        );
        assert_eq!(
            response.output_digest(),
            &command_stream_output_digest(response.stdout(), response.stderr())
        );
        reopened
            .validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Clean,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &proof,
            )
            .expect("clean observation rejoins fresh proof");
        let json = String::from_utf8(reopened.canonical_bytes().to_vec()).expect("UTF-8 JSON");
        assert!(json.contains("duration_ms"));
        assert!(!json.contains("at_unix_ms"));
    }

    #[test]
    fn canonical_decoder_rejects_empty_oversized_truncated_alternate_and_unknown_bytes() {
        let (observation, _, _) = rejection();
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(&[]),
            Err(SensitiveOutputTerminalObservationError::EmptyBytes)
        );
        let oversized = vec![b'x'; MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1 + 1];
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(&oversized),
            Err(
                SensitiveOutputTerminalObservationError::ObservationTooLarge {
                    bytes: oversized.len(),
                }
            )
        );
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &observation.canonical_bytes()[..observation.canonical_bytes().len() - 1],
            ),
            Err(SensitiveOutputTerminalObservationError::Decoding)
        );
        let mut whitespace = observation.canonical_bytes().to_vec();
        whitespace.push(b'\n');
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(&whitespace),
            Err(SensitiveOutputTerminalObservationError::NonCanonical)
        );

        let mut value: Value = serde_json::from_slice(observation.canonical_bytes()).expect("JSON");
        value
            .as_object_mut()
            .expect("record object")
            .insert("unknown".into(), Value::Bool(true));
        let unknown = serde_json::to_vec(&value).expect("unknown JSON");
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(&unknown),
            Err(SensitiveOutputTerminalObservationError::Decoding)
        );

        let canonical = String::from_utf8(observation.canonical_bytes().to_vec()).expect("UTF-8");
        let duplicate = canonical.replacen(
            "{\"format_version\":1,",
            "{\"format_version\":1,\"format_version\":1,",
            1,
        );
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(duplicate.as_bytes()),
            Err(SensitiveOutputTerminalObservationError::Decoding)
        );
    }

    #[test]
    fn unsupported_version_and_digest_or_field_tampering_are_rejected_after_reseal_attempts() {
        let (observation, _, _) = rejection();
        let mut unsupported = observation.record.clone();
        unsupported.format_version = 2;
        unsupported.observation_digest = compute_observation_digest(&unsupported).expect("digest");
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &serde_json::to_vec(&unsupported).expect("encode unsupported"),
            ),
            Err(SensitiveOutputTerminalObservationError::UnsupportedVersion { version: 2 })
        );

        let mut crossed_digest = observation.record.clone();
        crossed_digest.observation_digest = Digest::sha256(b"forged-observation-digest");
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &serde_json::to_vec(&crossed_digest).expect("encode crossed digest"),
            ),
            Err(SensitiveOutputTerminalObservationError::ObservationDigestMismatch)
        );

        let mut crossed_binding = observation.record.clone();
        crossed_binding.runner_session_id = "runner-session-crossed".into();
        crossed_binding.observation_digest =
            compute_observation_digest(&crossed_binding).expect("reseal crossed binding");
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &serde_json::to_vec(&crossed_binding).expect("encode crossed binding"),
            ),
            Err(SensitiveOutputTerminalObservationError::CrossedCommandDomainBinding)
        );

        let mut invalid_termination = observation.record.clone();
        invalid_termination.termination = CommandTerminationV1::Exited { code: -1 };
        invalid_termination.observation_digest =
            compute_observation_digest(&invalid_termination).expect("reseal termination");
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &serde_json::to_vec(&invalid_termination).expect("encode termination"),
            ),
            Err(SensitiveOutputTerminalObservationError::InvalidTermination)
        );
    }

    #[test]
    fn expected_capture_branch_backend_binding_and_fresh_proof_cannot_cross() {
        let (observation, binding, proof) = rejection();
        assert_eq!(
            observation.validate_expected(
                &"b".repeat(64),
                SensitiveOutputTerminalObservationBranchV1::Rejection,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &proof,
            ),
            Err(SensitiveOutputTerminalObservationError::ExpectedCaptureMismatch)
        );
        assert_eq!(
            observation.validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Clean,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &proof,
            ),
            Err(SensitiveOutputTerminalObservationError::ExpectedBranchMismatch)
        );
        assert_eq!(
            observation.validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Rejection,
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                &binding,
                &proof,
            ),
            Err(SensitiveOutputTerminalObservationError::ExpectedBackendMismatch)
        );
        let crossed_binding = CommandDomainCleanupBinding::try_new(
            binding.runner_session_id(),
            "command-effect-crossed",
            binding.command_request_digest().clone(),
        )
        .expect("valid crossed binding");
        assert_eq!(
            observation.validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Rejection,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &crossed_binding,
                &proof,
            ),
            Err(SensitiveOutputTerminalObservationError::ExpectedBindingMismatch)
        );

        let alternate_proof = alternate_validated_linux_cleanup_proof_for(&binding);
        assert_ne!(
            alternate_proof.os_evidence_digest(),
            proof.os_evidence_digest()
        );
        assert_eq!(
            observation.validate_expected(
                &capture_id(),
                SensitiveOutputTerminalObservationBranchV1::Rejection,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &alternate_proof,
            ),
            Err(SensitiveOutputTerminalObservationError::InvalidNativeCleanupProof)
        );
        for invalid_proof in [
            tampered_linux_cleanup_proof_for(&binding),
            surviving_linux_cleanup_proof_for(&binding),
        ] {
            assert_eq!(
                observation.validate_expected(
                    &capture_id(),
                    SensitiveOutputTerminalObservationBranchV1::Rejection,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    &binding,
                    &invalid_proof,
                ),
                Err(SensitiveOutputTerminalObservationError::InvalidNativeCleanupProof)
            );
        }
    }

    #[test]
    fn rejection_variant_rejects_injected_output_and_timing_fields() {
        let (observation, _, _) = rejection();
        for (field, value) in [
            ("duration_ms", Value::from(1_u64)),
            ("complete_length", Value::from(1_u64)),
            (
                "output_digest",
                Value::String(Digest::sha256(b"output").as_str().into()),
            ),
            ("stdout", Value::Object(Map::new())),
            ("matched", Value::Bool(true)),
        ] {
            let mut root: Value =
                serde_json::from_slice(observation.canonical_bytes()).expect("record JSON");
            root.as_object_mut()
                .and_then(|object| object.get_mut("branch"))
                .and_then(Value::as_object_mut)
                .expect("branch object")
                .insert(field.into(), value);
            assert!(
                matches!(
                    SensitiveOutputTerminalObservationV1::decode_canonical(
                        &serde_json::to_vec(&root).expect("encode injected field"),
                    ),
                    Err(SensitiveOutputTerminalObservationError::Decoding
                        | SensitiveOutputTerminalObservationError::NonCanonical)
                ),
                "rejection admitted injected field {field}"
            );
        }
    }

    #[test]
    fn clean_source_backend_stream_and_output_commitments_cannot_cross() {
        let (observation, _, _) = clean();

        let mutate_clean = |mutator: &dyn Fn(&mut SensitiveOutputCleanTerminalResponseV1)| {
            let mut record = observation.record.clone();
            let StoredObservationBranchV1::Clean { response } = &mut record.branch else {
                panic!("clean fixture branch");
            };
            mutator(response);
            record.observation_digest =
                compute_observation_digest(&record).expect("reseal invalid clean record");
            SensitiveOutputTerminalObservationV1::decode_canonical(
                &serde_json::to_vec(&record).expect("encode invalid clean record"),
            )
        };

        assert_eq!(
            mutate_clean(&|response| response.output_artifacts.source.effect_id = "crossed".into()),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
        assert_eq!(
            mutate_clean(&|response| {
                response.backend.command_domain_backend =
                    CommandDomainCleanupBackend::MacOsDedicatedIdentity;
            }),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
        assert_eq!(
            mutate_clean(&|response| response.output_digest = Digest::sha256(b"crossed")),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
        assert_eq!(
            mutate_clean(&|response| response.stdout.complete_length += 1),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
        assert_eq!(
            mutate_clean(&|response| response.stdout.complete_digest = Digest::sha256(b"crossed")),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
        assert_eq!(
            mutate_clean(&|response| response.backend.backend_id = "   ".into()),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );
    }

    #[test]
    fn clean_output_limit_requires_omitted_bytes_and_allows_bounded_truncation() {
        let binding = binding();
        let proof = validated_linux_cleanup_proof_for(&binding);
        let response = clean_response_for(&binding);
        assert_eq!(
            SensitiveOutputTerminalObservationV1::try_new_clean(
                capture_id(),
                CommandTerminationV1::OutputLimitExceeded,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                &binding,
                &proof,
                response,
            ),
            Err(SensitiveOutputTerminalObservationError::InvalidCleanResponse)
        );

        let mut response = clean_response_for(&binding);
        response.stdout.complete_length += 1;
        response.stdout.complete_digest = Digest::sha256(b"complete stdout with omitted byte");
        response.stdout.truncated = true;
        response.output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            response.output_artifacts.source.clone(),
            CommandOutputStreamArtifactV1 {
                stream: CommandOutputStreamV1::Stdout,
                byte_length: response.stdout.complete_length,
                content_digest: response.stdout.complete_digest.clone(),
            },
            response.output_artifacts.stderr.clone(),
        )
        .expect("truncated artifact reference");
        response.output_digest = command_stream_output_digest(&response.stdout, &response.stderr);
        response
            .validate_shape()
            .expect("bounded truncation remains valid");
        let _observation = SensitiveOutputTerminalObservationV1::try_new_clean(
            capture_id(),
            CommandTerminationV1::OutputLimitExceeded,
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &binding,
            &proof,
            response,
        )
        .expect("truncated output-limit observation is valid");
    }

    #[test]
    fn exact_maximum_retained_bytes_fit_the_canonical_observation_bound() {
        let binding = binding();
        let proof = validated_linux_cleanup_proof_for(&binding);
        let retained = vec![u8::MAX; MAX_INLINE_COMMAND_RETAINED_BYTES];
        let response = clean_response_with_streams(&binding, stream(&retained), stream(&[]));
        let observation = SensitiveOutputTerminalObservationV1::try_new_clean(
            capture_id(),
            CommandTerminationV1::Exited { code: 0 },
            CommandDomainCleanupBackend::LinuxCgroupV2,
            &binding,
            &proof,
            response,
        )
        .expect("the complete admitted retained-output budget must remain encodable");
        assert!(
            observation.canonical_bytes().len() > 512 * 1024,
            "fixture must exercise the former undersized ceiling"
        );
        assert!(
            observation.canonical_bytes().len()
                <= MAX_SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_BYTES_V1
        );
        assert_eq!(
            SensitiveOutputTerminalObservationV1::decode_canonical(observation.canonical_bytes())
                .expect("maximum canonical observation reopens"),
            observation
        );
    }

    #[test]
    fn canonical_identity_is_domain_separated_and_changes_with_every_bound_axis() {
        let (observation, binding, proof) = rejection();
        assert_ne!(
            observation.observation_digest(),
            &Digest::sha256(observation.canonical_bytes())
        );

        let variants = [
            SensitiveOutputTerminalObservationV1::try_new_rejection(
                "b".repeat(64),
                observation.termination(),
                observation.expected_cleanup_backend(),
                &binding,
                &proof,
            )
            .expect("capture variant"),
            SensitiveOutputTerminalObservationV1::try_new_rejection(
                capture_id(),
                CommandTerminationV1::TimedOut,
                observation.expected_cleanup_backend(),
                &binding,
                &proof,
            )
            .expect("termination variant"),
            SensitiveOutputTerminalObservationV1::try_new_clean(
                capture_id(),
                CommandTerminationV1::Exited { code: 1 },
                observation.expected_cleanup_backend(),
                &binding,
                &proof,
                clean_response_for(&binding),
            )
            .expect("branch variant"),
        ];
        for variant in variants {
            assert_ne!(
                variant.observation_digest(),
                observation.observation_digest()
            );
        }

        let mut request_variant = observation.record.clone();
        request_variant.request_digest = Digest::sha256(b"crossed-request");
        request_variant
            .command_domain_binding
            .command_request_digest = request_variant.request_digest.clone();
        let request_variant = reseal(&mut request_variant);
        assert_ne!(
            request_variant.observation_digest(),
            observation.observation_digest()
        );
    }
}
