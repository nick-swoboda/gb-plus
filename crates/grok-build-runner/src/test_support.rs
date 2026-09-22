//! Feature-gated production-path proof boxes for cross-crate tests.
//!
//! This module is absent unless `test-support` is explicitly enabled. Its
//! outputs are ordinary validated runner contracts, but its native Linux and
//! macOS cleanup observations are runner-owned fixtures and are never
//! promotion evidence. The runner crate is non-publishable and the desktop's
//! product dependency does not enable this feature; release-artifact evidence
//! must additionally prove that `test-support` was absent because a Cargo
//! feature is not itself a security boundary.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use grok_build_core::{
    CONTRACT_VERSION, CommandOutputArtifactSetReferenceV1, CommandOutputCaptureAcquiredV1,
    CommandOutputCaptureStoreHeadV1, CommandSpec, CommandTerminationV1, Digest,
    SensitiveOutputCoreDumpSuppressionV1, SensitiveOutputDetectionPolicyReferenceV1,
    SensitiveOutputStagingNeutralizationReceiptV1,
};

use crate::cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, ValidatedCommandDomainCleanupProof,
};
use crate::command_output_store::{
    CapabilityCommandOutputStore, CommandOutputStreamCapture, SensitiveOutputCleanJournalReceiptV2,
    SensitiveOutputJournalRecoveryV2, SensitiveOutputJournalStageV2,
    SensitiveOutputRejectionJournalReceiptV2, SensitiveOutputRejectionNativeProofRejoinV1,
};
use crate::linux_containment::{
    CgroupCleanupEvidence, CgroupObjectIdentity, DomainJournalRecord, DomainJournalState, LeafFile,
    LimitValue, LinuxNativeLaunchIdentity, RawCleanupObservation, ReadBackDomainLimits,
    RequestedDomainLimits,
};
use crate::macos_helper_protocol::{
    MACOS_HELPER_PROTOCOL_VERSION, MacosAssignedIdentity, MacosChildDescriptorBinding,
    MacosChildDescriptorPurpose, MacosCleanupEvidence, MacosExecutableIdentity,
    MacosHelperAttestation, MacosHelperInstallAudit, MacosHelperJournalRecord,
    MacosHelperJournalState, MacosHelperLaunchRequest, MacosHelperNetwork,
    MacosHelperPreparationBinding, MacosHelperSession, MacosProcessObservation,
    MacosTerminationReason,
};
use crate::sensitive_output::{ScreenedSensitiveOutputChunkV1, SensitiveOutputStreamScannerV1};
use crate::sensitive_output_terminal_observation::{
    SensitiveOutputCleanTerminalResponseV1, SensitiveOutputTerminalObservationV1,
};
use crate::wire::{
    CONTAINED_CAPTURE_LAUNCH_SCHEMA, RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest,
    RunnerRequestEnvelopeV12, RunnerResponseEnvelopeV12, RunnerResponseV12,
    WireCommandBackendIdentity, WireCommandCleanupProof, WireCommandOutputCaptureAnchorV1,
    WireCommandOutputCaptureTerminalV1, WireCommandStreamEvidence, WireCommandTerminalEvidence,
    WireContainmentRefusalEvidenceV12, command_stream_output_digest, command_terminal_record_bytes,
    encode_contained_capture_launch_binding_v12_for_test_support, encode_request_frame_v12,
    encode_response_frame_v12,
};

const REJECTION_PROBE: &[u8] = b"gb-secret-canary-runner-owned-proof-box-v1";

/// Closed failure returned by the feature-gated proof-box builders.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutputV2TestProofBoxError {
    detail: String,
}

impl Display for CommandOutputV2TestProofBoxError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runner v2 test proof-box failed: {}",
            self.detail
        )
    }
}

impl Error for CommandOutputV2TestProofBoxError {}

fn proof_box_error(context: &str, error: impl Display) -> CommandOutputV2TestProofBoxError {
    CommandOutputV2TestProofBoxError {
        detail: format!("{context}: {error}"),
    }
}

fn invalid(detail: impl Into<String>) -> CommandOutputV2TestProofBoxError {
    CommandOutputV2TestProofBoxError {
        detail: detail.into(),
    }
}

/// Exact already-claimed command authority supplied by a cross-crate test
/// before the runner creates physical output custody.
///
/// The caller first reserves `acquired`, binds `request`, durably claims the
/// core dispatch, and validates the exact transport. This type cannot mint any
/// of those authorities; it only drives runner output custody afterward.
#[allow(
    missing_docs,
    reason = "public fields are the explicit test-only claimed-authority inputs"
)]
#[derive(Debug)]
pub struct ClaimedCommandOutputV2TestProofBoxInput {
    pub private_state_root: PathBuf,
    pub grant_hash: Digest,
    pub acquired: CommandOutputCaptureAcquiredV1,
    pub request: RunnerRequestEnvelopeV12,
    pub termination: CommandTerminationV1,
    pub backend: WireCommandBackendIdentity,
}

/// Real clean v2 store/journal result built by the feature-gated proof box.
pub struct SensitiveOutputCleanTestProofBoxV1 {
    store: CapabilityCommandOutputStore,
    acquired: CommandOutputCaptureAcquiredV1,
    request: RunnerRequestEnvelopeV12,
    response: RunnerResponseEnvelopeV12,
    receipt: SensitiveOutputCleanJournalReceiptV2,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputCleanTestProofBoxV1 {
    /// Reopenable private output store containing the exact final journal.
    #[must_use]
    pub const fn store(&self) -> &CapabilityCommandOutputStore {
        &self.store
    }

    /// Physical acquisition created by the store.
    #[must_use]
    pub const fn acquired(&self) -> &CommandOutputCaptureAcquiredV1 {
        &self.acquired
    }

    /// Exact v12 command request containing that acquisition.
    #[must_use]
    pub const fn request(&self) -> &RunnerRequestEnvelopeV12 {
        &self.request
    }

    /// Exact correlated clean v12 response.
    #[must_use]
    pub const fn response(&self) -> &RunnerResponseEnvelopeV12 {
        &self.response
    }

    /// Exact terminal clean-scan journal receipt.
    #[must_use]
    pub const fn receipt(&self) -> &SensitiveOutputCleanJournalReceiptV2 {
        &self.receipt
    }

    /// Runner-owned native-validating cleanup fixture used by this proof box.
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }
}

/// Real rejected v2 store/journal result built by the feature-gated proof box.
pub struct SensitiveOutputRejectionTestProofBoxV1 {
    store: CapabilityCommandOutputStore,
    acquired: CommandOutputCaptureAcquiredV1,
    request: RunnerRequestEnvelopeV12,
    response: RunnerResponseEnvelopeV12,
    receipt: SensitiveOutputRejectionJournalReceiptV2,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
    staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
}

impl SensitiveOutputRejectionTestProofBoxV1 {
    /// Reopenable private output store containing the exact final journal.
    #[must_use]
    pub const fn store(&self) -> &CapabilityCommandOutputStore {
        &self.store
    }

    /// Physical acquisition created by the store.
    #[must_use]
    pub const fn acquired(&self) -> &CommandOutputCaptureAcquiredV1 {
        &self.acquired
    }

    /// Exact v12 command request containing that acquisition.
    #[must_use]
    pub const fn request(&self) -> &RunnerRequestEnvelopeV12 {
        &self.request
    }

    /// Exact correlated output-abandoned v12 response.
    #[must_use]
    pub const fn response(&self) -> &RunnerResponseEnvelopeV12 {
        &self.response
    }

    /// Exact terminal rejection journal receipt.
    #[must_use]
    pub const fn receipt(&self) -> &SensitiveOutputRejectionJournalReceiptV2 {
        &self.receipt
    }

    /// Runner-owned native-validating cleanup fixture used by this proof box.
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }

    /// Exact constant-zero staging receipt persisted before object cleanup.
    #[must_use]
    pub const fn staging_neutralization(&self) -> &SensitiveOutputStagingNeutralizationReceiptV1 {
        &self.staging_neutralization
    }
}

/// Exact clean-branch boundary at which test support simulates process loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveOutputCleanTestCutV1 {
    /// Native launch intent and generation four are durable, but no output
    /// classification has been persisted.
    LaunchIntended,
    /// Both scanners reached clean EOF and generation five is durable.
    ScannedClean,
    /// Both streams and the v1/v2 generation-six records are durable.
    Finished,
    /// The immutable artifact and v1/v2 generation-seven records are durable.
    Published,
}

/// Exact rejection-branch boundary at which test support simulates process loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveOutputRejectionTestCutV1 {
    /// The runner-owned detector matched and generation five is durable.
    SensitiveOutputDetected,
    /// Staging is neutralized and generation six is durable.
    CleanupIntended,
    /// Physical v1 cleanup and v2 generation seven are durable.
    Cleaned,
}

/// Reopenable result of one real production-journal test cut.
pub struct SensitiveOutputJournalCutTestProofBoxV1 {
    store: CapabilityCommandOutputStore,
    acquired: CommandOutputCaptureAcquiredV1,
    request: RunnerRequestEnvelopeV12,
    recovery: SensitiveOutputJournalRecoveryV2,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
    staging_neutralization: Option<SensitiveOutputStagingNeutralizationReceiptV1>,
}

impl SensitiveOutputJournalCutTestProofBoxV1 {
    /// Reopenable private output store stopped at the requested real boundary.
    #[must_use]
    pub const fn store(&self) -> &CapabilityCommandOutputStore {
        &self.store
    }

    /// Exact acquisition created and claimed before test support was invoked.
    #[must_use]
    pub const fn acquired(&self) -> &CommandOutputCaptureAcquiredV1 {
        &self.acquired
    }

    /// Exact already-bound v12 request used for the launch journal record.
    #[must_use]
    pub const fn request(&self) -> &RunnerRequestEnvelopeV12 {
        &self.request
    }

    /// Typed production-journal readback at the requested cut.
    #[must_use]
    pub const fn recovery(&self) -> &SensitiveOutputJournalRecoveryV2 {
        &self.recovery
    }

    /// Runner-owned native-validating cleanup fixture used by this proof box.
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }

    /// Zero-state staging receipt, present only after rejection neutralization.
    #[must_use]
    pub const fn staging_neutralization(
        &self,
    ) -> Option<&SensitiveOutputStagingNeutralizationReceiptV1> {
        self.staging_neutralization.as_ref()
    }
}

struct PreparedProofBox {
    store: CapabilityCommandOutputStore,
    grant_hash: Digest,
    acquired: CommandOutputCaptureAcquiredV1,
    anchor: WireCommandOutputCaptureAnchorV1,
    request: RunnerRequestEnvelopeV12,
    request_frame: Vec<u8>,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
    termination: CommandTerminationV1,
    backend: WireCommandBackendIdentity,
}

fn prepare(
    input: ClaimedCommandOutputV2TestProofBoxInput,
) -> Result<PreparedProofBox, CommandOutputV2TestProofBoxError> {
    let ClaimedCommandOutputV2TestProofBoxInput {
        private_state_root,
        grant_hash,
        acquired,
        request,
        termination,
        backend,
    } = input;
    termination
        .validate()
        .map_err(|error| proof_box_error("validate termination", error))?;
    let request_frame = encode_request_frame_v12(&request)
        .map_err(|error| proof_box_error("validate exact claimed v12 request", error))?;
    let detector_policy = request.detector_policy().clone();
    crate::sensitive_output::validate_matcher_policy_v1(&detector_policy)
        .map_err(|_| invalid("validate runner-owned detector policy: policy mismatch"))?;
    if detector_policy != SensitiveOutputDetectionPolicyReferenceV1::core_v1() {
        return Err(invalid(
            "claimed v12 request detector policy differs from runner-owned core_v1",
        ));
    }
    let anchor = match request.request.command_request() {
        RunnerRequest::WorkerRunCommand { output_capture, .. }
        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => output_capture.clone(),
        _ => return Err(invalid("claimed v12 request lost its command shape")),
    };
    if anchor.acquired() != &acquired {
        return Err(invalid(
            "claimed v12 request carries a different acquired capture anchor",
        ));
    }
    if request.session_id != acquired.source.runner_session_id
        || request.effect.launch_id != acquired.source.runner_launch_id
        || request.effect.sprint_id != acquired.source.sprint_id
        || request.effect.effect_id != acquired.source.effect_id
        || request.effect.request_digest != acquired.source.request_digest
    {
        return Err(invalid(
            "claimed v12 request differs from the acquired capture source authority",
        ));
    }
    let store = CapabilityCommandOutputStore::open(&private_state_root)
        .map_err(|error| proof_box_error("open private output store", error))?;
    let binding = CommandDomainCleanupBinding::try_new(
        request.session_id.clone(),
        request.effect.effect_id.clone(),
        request.effect.request_digest.clone(),
    )
    .map_err(|error| proof_box_error("construct cleanup binding", error))?;
    let native_cleanup_proof = match backend.command_domain_backend {
        CommandDomainCleanupBackend::LinuxCgroupV2 => validated_linux_cleanup_proof_for(&binding)?,
        CommandDomainCleanupBackend::MacOsDedicatedIdentity => {
            validated_macos_cleanup_proof_for(&binding, &request, &grant_hash, termination)?
        }
    };
    Ok(PreparedProofBox {
        store,
        grant_hash,
        acquired,
        anchor,
        request,
        request_frame,
        detector_policy,
        native_cleanup_proof,
        termination,
        backend,
    })
}

fn fixture_core_dump_profile(
    backend: CommandDomainCleanupBackend,
) -> Result<SensitiveOutputCoreDumpSuppressionV1, CommandOutputV2TestProofBoxError> {
    let profile = match backend {
        // This non-promotion fixture proves contract wiring only. It does not
        // claim that the live host installed or read back these settings.
        CommandDomainCleanupBackend::LinuxCgroupV2 => SensitiveOutputCoreDumpSuppressionV1::linux(),
        CommandDomainCleanupBackend::MacOsDedicatedIdentity => {
            SensitiveOutputCoreDumpSuppressionV1::macos()
        }
    };
    profile
        .validate()
        .map_err(|error| proof_box_error("validate runner-owned core-dump profile", error))?;
    Ok(profile)
}

fn launch_capture(
    prepared: &PreparedProofBox,
) -> Result<
    (
        CommandOutputStreamCapture,
        CommandOutputStreamCapture,
        crate::CommandOutputPublisher,
        CommandOutputCaptureStoreHeadV1,
    ),
    CommandOutputV2TestProofBoxError,
> {
    let capture = prepared
        .store
        .reopen_anchored_capture_v2(&prepared.acquired, &prepared.detector_policy)
        .map_err(|error| proof_box_error("attach v2 capture writer", error))?;
    let (stdout, stderr, mut publisher) = capture.split();
    let launch_digest = Digest::sha256(&prepared.request_frame);
    let preflight_digest = Digest::sha256(prepared.native_cleanup_proof.os_evidence_bytes());
    let launch_binding = encode_contained_capture_launch_binding_v12_for_test_support(
        &prepared.request,
        &prepared.grant_hash,
        &prepared.acquired,
        &launch_digest,
        &preflight_digest,
        &prepared.backend,
    )
    .map_err(|error| proof_box_error("encode production-shaped v12 launch binding", error))?;
    let launch_head = publisher
        .record_launch_intended_v2(
            CONTAINED_CAPTURE_LAUNCH_SCHEMA,
            launch_binding,
            &fixture_core_dump_profile(prepared.native_cleanup_proof.backend())?,
        )
        .map_err(|error| proof_box_error("persist v2 launch boundary", error))?;
    Ok((stdout, stderr, publisher, launch_head))
}

/// Injects the exact non-atomic launch crash cut after the v1
/// `LaunchIntended` append and before the v2 generation-four append.
///
/// The returned production journals therefore contain exact v2
/// `WriterAttached` joined to exact v1 `LaunchIntended`. The optional prefix
/// bytes model already released clean output held in private staging; they are
/// not classification evidence and must be zeroed by split-launch quarantine.
///
/// # Errors
///
/// Returns a closed test-support error if the supplied authority, v12 request,
/// capture custody, launch binding, staged output, or exact split readback is
/// invalid.
pub fn cut_sensitive_output_split_launch_test_proof_box_v1(
    input: ClaimedCommandOutputV2TestProofBoxInput,
    stdout_prefix: &[u8],
    stderr_prefix: &[u8],
) -> Result<SensitiveOutputJournalCutTestProofBoxV1, CommandOutputV2TestProofBoxError> {
    let prepared = prepare(input)?;
    let capture = prepared
        .store
        .reopen_anchored_capture_v2(&prepared.acquired, &prepared.detector_policy)
        .map_err(|error| proof_box_error("attach split-launch v2 capture writer", error))?;
    let (mut stdout, mut stderr, mut publisher) = capture.split();
    let launch_digest = Digest::sha256(&prepared.request_frame);
    let preflight_digest = Digest::sha256(prepared.native_cleanup_proof.os_evidence_bytes());
    let launch_binding = encode_contained_capture_launch_binding_v12_for_test_support(
        &prepared.request,
        &prepared.grant_hash,
        &prepared.acquired,
        &launch_digest,
        &preflight_digest,
        &prepared.backend,
    )
    .map_err(|error| proof_box_error("encode split-launch v12 binding", error))?;
    let launch_head = publisher
        .record_launch_intended(CONTAINED_CAPTURE_LAUNCH_SCHEMA, launch_binding)
        .map_err(|error| proof_box_error("persist split-cut v1 LaunchIntended", error))?;
    stdout
        .append(stdout_prefix)
        .map_err(|error| proof_box_error("stage split-cut stdout prefix", error))?;
    stderr
        .append(stderr_prefix)
        .map_err(|error| proof_box_error("stage split-cut stderr prefix", error))?;
    drop(stdout);
    drop(stderr);
    drop(publisher);

    let recovery = prepared
        .store
        .reopen_sensitive_output_journal_v2(&prepared.acquired.capture_id)
        .map_err(|error| proof_box_error("read back split-cut v2 prefix", error))?;
    if recovery.head().generation != 3
        || !matches!(
            recovery.stage(),
            SensitiveOutputJournalStageV2::WriterAttached { .. }
        )
    {
        return Err(invalid(
            "split launch cut did not retain exact v2 WriterAttached generation three",
        ));
    }
    let v1 = prepared
        .store
        .reopen_capture(&prepared.acquired.capture_id)
        .map_err(|error| proof_box_error("read back split-cut v1 launch", error))?;
    if v1.state() != crate::CommandOutputCaptureJournalStateV1::LaunchIntended
        || v1.launch_intended_store_head() != Some(&launch_head)
        || v1.acquired() != Some(&prepared.acquired)
    {
        return Err(invalid(
            "split launch cut did not retain exact v1 LaunchIntended custody",
        ));
    }
    Ok(SensitiveOutputJournalCutTestProofBoxV1 {
        store: prepared.store,
        acquired: prepared.acquired,
        request: prepared.request,
        recovery,
        native_cleanup_proof: prepared.native_cleanup_proof,
        staging_neutralization: None,
    })
}

fn append_scanned_clean(
    stream: &mut CommandOutputStreamCapture,
    bytes: &[u8],
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
) -> Result<(), CommandOutputV2TestProofBoxError> {
    let mut scanner = SensitiveOutputStreamScannerV1::try_new(detector_policy, bytes.len().max(1))
        .map_err(|_| invalid("construct clean stream scanner: detector setup failed"))?;
    if !bytes.is_empty() {
        match scanner.screen(bytes) {
            ScreenedSensitiveOutputChunkV1::CleanPrefix(prefix) => stream
                .append(prefix)
                .map_err(|error| proof_box_error("append scanner-released clean prefix", error))?,
            ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => {
                return Err(invalid(
                    "clean proof-box input matched sensitive-output policy",
                ));
            }
            ScreenedSensitiveOutputChunkV1::ChunkTooLarge
            | ScreenedSensitiveOutputChunkV1::Closed => {
                return Err(invalid("clean proof-box scanner entered an illegal state"));
            }
        }
    }
    let suffix = scanner
        .finish()
        .ok_or_else(|| invalid("clean proof-box scanner did not reach clean EOF"))?;
    stream
        .append(suffix)
        .map_err(|error| proof_box_error("append scanner-released clean suffix", error))
}

/// Drives the production clean-output path to one exact durable boundary and
/// then drops all live writer custody to model process loss after core claim.
///
/// # Errors
///
/// Returns a closed test-support error if authority, policy, capture custody,
/// scanning, persistence, or exact stage readback fails.
#[allow(
    clippy::too_many_lines,
    reason = "the crash-cut fixture keeps clean observation, exact raw artifacts, and each real journal boundary in one auditable driver"
)]
pub fn cut_sensitive_output_clean_test_proof_box_v1(
    input: ClaimedCommandOutputV2TestProofBoxInput,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
    cut: SensitiveOutputCleanTestCutV1,
) -> Result<SensitiveOutputJournalCutTestProofBoxV1, CommandOutputV2TestProofBoxError> {
    let prepared = prepare(input)?;
    let (mut stdout, mut stderr, publisher, _launch_head) = launch_capture(&prepared)?;
    if cut == SensitiveOutputCleanTestCutV1::LaunchIntended {
        drop(stdout);
        drop(stderr);
        drop(publisher);
    } else {
        append_scanned_clean(&mut stdout, stdout_bytes, &prepared.detector_policy)?;
        append_scanned_clean(&mut stderr, stderr_bytes, &prepared.detector_policy)?;
        publisher
            .record_sensitive_output_scanned_clean_v2()
            .map_err(|error| proof_box_error("persist ScannedClean test cut", error))?;
        let stdout = stdout
            .finish()
            .map_err(|error| proof_box_error("finish clean-cut stdout", error))?;
        let stderr = stderr
            .finish()
            .map_err(|error| proof_box_error("finish clean-cut stderr", error))?;
        let output_artifacts = CommandOutputArtifactSetReferenceV1::try_new(
            prepared.acquired.source.clone(),
            stdout.artifact(),
            stderr.artifact(),
        )
        .map_err(|error| proof_box_error("construct clean-cut artifact reference", error))?;
        let stdout_evidence = WireCommandStreamEvidence {
            retained_bytes: stdout_bytes.to_vec(),
            complete_digest: Digest::sha256(stdout_bytes),
            complete_length: u64::try_from(stdout_bytes.len())
                .map_err(|_| invalid("clean-cut stdout length exceeds u64"))?,
            truncated: false,
        };
        let stderr_evidence = WireCommandStreamEvidence {
            retained_bytes: stderr_bytes.to_vec(),
            complete_digest: Digest::sha256(stderr_bytes),
            complete_length: u64::try_from(stderr_bytes.len())
                .map_err(|_| invalid("clean-cut stderr length exceeds u64"))?,
            truncated: false,
        };
        let launch_digest = Digest::sha256(&prepared.request_frame);
        let preflight_digest = Digest::sha256(prepared.native_cleanup_proof.os_evidence_bytes());
        let cleanup_binding = CommandDomainCleanupBinding::try_new(
            prepared.request.session_id.clone(),
            prepared.request.effect.effect_id.clone(),
            prepared.request.effect.request_digest.clone(),
        )
        .map_err(|error| proof_box_error("construct clean-cut cleanup binding", error))?;
        let clean_response = SensitiveOutputCleanTerminalResponseV1::try_new(
            stdout_evidence.clone(),
            stderr_evidence.clone(),
            output_artifacts,
            command_stream_output_digest(&stdout_evidence, &stderr_evidence),
            launch_digest.clone(),
            preflight_digest.clone(),
            prepared.backend.clone(),
            1,
        )
        .map_err(|error| proof_box_error("construct clean-cut terminal response", error))?;
        let observation = SensitiveOutputTerminalObservationV1::try_new_clean(
            prepared.acquired.capture_id.clone(),
            prepared.termination,
            prepared.backend.command_domain_backend,
            &cleanup_binding,
            &prepared.native_cleanup_proof,
            clean_response,
        )
        .map_err(|error| proof_box_error("construct clean-cut terminal observation", error))?;
        observation
            .validate_expected_clean_live(
                &prepared.acquired.capture_id,
                prepared.backend.command_domain_backend,
                &cleanup_binding,
                &prepared.native_cleanup_proof,
                &prepared.acquired,
                &launch_digest,
                &preflight_digest,
                &prepared.backend,
            )
            .map_err(|error| proof_box_error("validate clean-cut terminal observation", error))?;
        let persisted_observation = publisher
            .publish_sensitive_output_terminal_observation_v1(&observation)
            .map_err(|error| proof_box_error("publish clean-cut terminal observation", error))?;
        if persisted_observation != observation {
            return Err(invalid(
                "clean-cut terminal observation changed across publication",
            ));
        }
        match cut {
            SensitiveOutputCleanTestCutV1::LaunchIntended => unreachable!(),
            SensitiveOutputCleanTestCutV1::ScannedClean => {
                drop(stdout);
                drop(stderr);
                drop(publisher);
            }
            SensitiveOutputCleanTestCutV1::Finished => {
                publisher
                    .stop_after_sensitive_output_finished_v2_for_test(stdout, stderr)
                    .map_err(|error| proof_box_error("persist Finished test cut", error))?;
            }
            SensitiveOutputCleanTestCutV1::Published => {
                let published_artifact = publisher
                    .publish(stdout, stderr)
                    .map_err(|error| proof_box_error("persist Published test cut", error))?;
                drop(published_artifact);
            }
        }
    }
    let recovery = prepared
        .store
        .reopen_sensitive_output_journal_v2(&prepared.acquired.capture_id)
        .map_err(|error| proof_box_error("read back clean test cut", error))?;
    let stage_matches = matches!(
        (cut, recovery.stage()),
        (
            SensitiveOutputCleanTestCutV1::LaunchIntended,
            SensitiveOutputJournalStageV2::LaunchIntended { .. }
        ) | (
            SensitiveOutputCleanTestCutV1::ScannedClean,
            SensitiveOutputJournalStageV2::ScannedClean { .. }
        ) | (
            SensitiveOutputCleanTestCutV1::Finished,
            SensitiveOutputJournalStageV2::Finished { .. }
        ) | (
            SensitiveOutputCleanTestCutV1::Published,
            SensitiveOutputJournalStageV2::Published { .. }
        )
    );
    if !stage_matches {
        return Err(invalid(
            "clean test cut read back a different journal stage",
        ));
    }
    Ok(SensitiveOutputJournalCutTestProofBoxV1 {
        store: prepared.store,
        acquired: prepared.acquired,
        request: prepared.request,
        recovery,
        native_cleanup_proof: prepared.native_cleanup_proof,
        staging_neutralization: None,
    })
}

/// Drives the production rejection path to one exact durable boundary and
/// then drops all live writer custody to model process loss after core claim.
///
/// # Errors
///
/// Returns a closed test-support error if authority, policy, capture custody,
/// detection, neutralization, cleanup, persistence, or readback fails.
#[allow(
    clippy::too_many_lines,
    reason = "the crash-cut fixture keeps rejection observation, zero-first cleanup, and each real journal boundary in one auditable driver"
)]
pub fn cut_sensitive_output_rejection_test_proof_box_v1(
    input: ClaimedCommandOutputV2TestProofBoxInput,
    cut: SensitiveOutputRejectionTestCutV1,
) -> Result<SensitiveOutputJournalCutTestProofBoxV1, CommandOutputV2TestProofBoxError> {
    let prepared = prepare(input)?;
    let (mut stdout, mut stderr, publisher, launch_head) = launch_capture(&prepared)?;
    let mut scanner =
        SensitiveOutputStreamScannerV1::try_new(&prepared.detector_policy, REJECTION_PROBE.len())
            .map_err(|_| invalid("construct rejection-cut scanner: detector setup failed"))?;
    if !matches!(
        scanner.screen(REJECTION_PROBE),
        ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected
    ) {
        return Err(invalid(
            "runner-owned rejection-cut probe did not match the fixed policy",
        ));
    }
    publisher
        .record_sensitive_output_detected_v2(&launch_head, &prepared.detector_policy)
        .map_err(|error| proof_box_error("persist SensitiveOutputDetected test cut", error))?;
    let cleanup_binding = CommandDomainCleanupBinding::try_new(
        prepared.request.session_id.clone(),
        prepared.request.effect.effect_id.clone(),
        prepared.request.effect.request_digest.clone(),
    )
    .map_err(|error| proof_box_error("construct rejection-cut cleanup binding", error))?;
    let observation = SensitiveOutputTerminalObservationV1::try_new_rejection(
        prepared.acquired.capture_id.clone(),
        prepared.termination,
        prepared.backend.command_domain_backend,
        &cleanup_binding,
        &prepared.native_cleanup_proof,
    )
    .map_err(|error| proof_box_error("construct rejection-cut terminal observation", error))?;
    observation
        .validate_expected(
            &prepared.acquired.capture_id,
            crate::SensitiveOutputTerminalObservationBranchV1::Rejection,
            prepared.backend.command_domain_backend,
            &cleanup_binding,
            &prepared.native_cleanup_proof,
        )
        .map_err(|error| proof_box_error("validate rejection-cut terminal observation", error))?;
    let persisted_observation = publisher
        .publish_sensitive_output_terminal_observation_v1(&observation)
        .map_err(|error| proof_box_error("publish rejection-cut terminal observation", error))?;
    if persisted_observation != observation {
        return Err(invalid(
            "rejection-cut terminal observation changed across publication",
        ));
    }
    let staging_neutralization = match cut {
        SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected => {
            drop(stdout);
            drop(stderr);
            drop(publisher);
            None
        }
        SensitiveOutputRejectionTestCutV1::CleanupIntended
        | SensitiveOutputRejectionTestCutV1::Cleaned => {
            let receipt = publisher
                .neutralize_sensitive_output_staging_v2(&mut stdout, &mut stderr)
                .map_err(|error| proof_box_error("neutralize rejection test cut", error))?;
            let proof_id = prepared.native_cleanup_proof.os_evidence_digest().as_str();
            match cut {
                SensitiveOutputRejectionTestCutV1::CleanupIntended => publisher
                    .stop_after_sensitive_output_cleanup_intended_v2_for_test(
                        stdout.into_custody(),
                        stderr.into_custody(),
                        proof_id,
                        &receipt,
                    )
                    .map_err(|error| proof_box_error("persist CleanupIntended test cut", error))?,
                SensitiveOutputRejectionTestCutV1::Cleaned => publisher
                    .stop_after_sensitive_output_cleaned_v2_for_test(
                        stdout.into_custody(),
                        stderr.into_custody(),
                        proof_id,
                        &receipt,
                    )
                    .map_err(|error| proof_box_error("persist Cleaned test cut", error))?,
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected => unreachable!(),
            }
            Some(receipt)
        }
    };
    let recovery = prepared
        .store
        .reopen_sensitive_output_journal_v2(&prepared.acquired.capture_id)
        .map_err(|error| proof_box_error("read back rejection test cut", error))?;
    let stage_matches = matches!(
        (cut, recovery.stage()),
        (
            SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
        ) | (
            SensitiveOutputRejectionTestCutV1::CleanupIntended,
            SensitiveOutputJournalStageV2::CleanupIntended { .. }
        ) | (
            SensitiveOutputRejectionTestCutV1::Cleaned,
            SensitiveOutputJournalStageV2::Cleaned { .. }
        )
    );
    if !stage_matches {
        return Err(invalid(
            "rejection test cut read back a different journal stage",
        ));
    }
    Ok(SensitiveOutputJournalCutTestProofBoxV1 {
        store: prepared.store,
        acquired: prepared.acquired,
        request: prepared.request,
        recovery,
        native_cleanup_proof: prepared.native_cleanup_proof,
        staging_neutralization,
    })
}

/// Builds a complete clean v2 publication through the production output store,
/// scanners, journals, terminal readback, and response validators.
///
/// # Errors
///
/// Returns a closed test-support error if any authority, custody, scanner,
/// journal, artifact, cleanup-proof, terminal, or response validation fails.
#[allow(
    clippy::too_many_lines,
    reason = "the test seam keeps the complete production custody and terminal join auditable"
)]
pub fn complete_sensitive_output_clean_test_proof_box_v1(
    input: ClaimedCommandOutputV2TestProofBoxInput,
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
) -> Result<SensitiveOutputCleanTestProofBoxV1, CommandOutputV2TestProofBoxError> {
    let prepared = prepare(input)?;
    let (mut stdout, mut stderr, publisher, _launch_head) = launch_capture(&prepared)?;
    append_scanned_clean(&mut stdout, stdout_bytes, &prepared.detector_policy)?;
    append_scanned_clean(&mut stderr, stderr_bytes, &prepared.detector_policy)?;
    publisher
        .record_sensitive_output_scanned_clean_v2()
        .map_err(|error| proof_box_error("persist ScannedClean", error))?;
    let stdout = stdout
        .finish()
        .map_err(|error| proof_box_error("finish clean stdout", error))?;
    let stderr = stderr
        .finish()
        .map_err(|error| proof_box_error("finish clean stderr", error))?;
    let published_artifact = publisher
        .publish(stdout, stderr)
        .map_err(|error| proof_box_error("publish clean output", error))?;
    let finished_store_head = published_artifact
        .capture_finished_store_head()
        .cloned()
        .ok_or_else(|| invalid("clean publication omitted Finished head"))?;
    let published_store_head = published_artifact
        .capture_published_store_head()
        .cloned()
        .ok_or_else(|| invalid("clean publication omitted Published head"))?;
    let output_artifacts = published_artifact.reference().clone();
    let stdout_evidence = WireCommandStreamEvidence {
        retained_bytes: stdout_bytes.to_vec(),
        complete_digest: Digest::sha256(stdout_bytes),
        complete_length: u64::try_from(stdout_bytes.len())
            .map_err(|_| invalid("clean stdout length exceeds u64"))?,
        truncated: false,
    };
    let stderr_evidence = WireCommandStreamEvidence {
        retained_bytes: stderr_bytes.to_vec(),
        complete_digest: Digest::sha256(stderr_bytes),
        complete_length: u64::try_from(stderr_bytes.len())
            .map_err(|_| invalid("clean stderr length exceeds u64"))?,
        truncated: false,
    };
    let provisional_terminal_head = CommandOutputCaptureStoreHeadV1 {
        generation: published_store_head
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("terminal generation overflow"))?,
        record_digest: Digest::sha256(b"runner-test-support-provisional-terminal-head"),
    };
    let terminal_capture = WireCommandOutputCaptureTerminalV1::try_new(
        prepared.acquired.capture_id.clone(),
        prepared.acquired.acquired_anchor_digest.clone(),
        finished_store_head,
        published_store_head.clone(),
        provisional_terminal_head,
        output_artifacts.clone(),
        Digest::sha256(b"runner-test-support-provisional-terminal-record"),
    )
    .map_err(|error| proof_box_error("construct provisional clean terminal", error))?;
    let mut terminal = WireCommandTerminalEvidence {
        output_capture: terminal_capture,
        termination: prepared.termination,
        stdout: stdout_evidence.clone(),
        stderr: stderr_evidence.clone(),
        output_artifacts,
        output_digest: command_stream_output_digest(&stdout_evidence, &stderr_evidence),
        launch_digest: Digest::sha256(&prepared.request_frame),
        preflight_digest: Digest::sha256(prepared.native_cleanup_proof.os_evidence_bytes()),
        backend: prepared.backend,
        cleanup_proof: WireCommandCleanupProof::try_from(&prepared.native_cleanup_proof)
            .map_err(|error| proof_box_error("adapt clean native proof", error))?,
        duration_ms: 1,
    };
    terminal
        .bind_terminal_record_digest()
        .map_err(|error| proof_box_error("bind clean terminal digest", error))?;
    let terminal_record = command_terminal_record_bytes(&terminal)
        .map_err(|error| proof_box_error("encode clean terminal record", error))?;
    let recovery = prepared
        .store
        .prepare_capture_terminal(
            &prepared.acquired.capture_id,
            &published_store_head,
            crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
            terminal_record,
        )
        .map_err(|error| proof_box_error("persist clean TerminalPrepared", error))?;
    terminal.output_capture.terminal_prepared_store_head = recovery
        .terminal_prepared_store_head()
        .cloned()
        .ok_or_else(|| invalid("clean terminal readback omitted TerminalPrepared head"))?;
    terminal
        .validate_for_output_capture(&prepared.anchor)
        .map_err(|error| proof_box_error("validate clean terminal against acquisition", error))?;
    let receipt = prepared
        .store
        .record_sensitive_output_clean_terminal_prepared_v2(
            &prepared.acquired.capture_id,
            &terminal.output_capture.terminal_prepared_store_head,
            &terminal.output_capture.terminal_record_digest,
            prepared.termination,
        )
        .map_err(|error| proof_box_error("persist clean v2 terminal receipt", error))?;
    let response = RunnerResponseV12::CommandCompleted {
        detector_policy: prepared.detector_policy.clone(),
        evidence: terminal,
        scan_receipt: receipt.clone(),
    };
    let response = correlated_response(&prepared.request, response)?;
    Ok(SensitiveOutputCleanTestProofBoxV1 {
        store: prepared.store,
        acquired: prepared.acquired,
        request: prepared.request,
        response,
        receipt,
        native_cleanup_proof: prepared.native_cleanup_proof,
    })
}

/// Builds a complete sensitive-output rejection through the production
/// scanner, zero-state staging cleanup, v1/v2 journals, native-proof rejoin,
/// and v12 response validators. No matched byte reaches output staging.
///
/// # Errors
///
/// Returns a closed test-support error if any authority, detector, custody,
/// neutralization, cleanup-proof, journal, rejoin, or response validation fails.
pub fn complete_sensitive_output_rejection_test_proof_box_v1(
    input: ClaimedCommandOutputV2TestProofBoxInput,
) -> Result<SensitiveOutputRejectionTestProofBoxV1, CommandOutputV2TestProofBoxError> {
    let prepared = prepare(input)?;
    let (mut stdout, mut stderr, publisher, launch_head) = launch_capture(&prepared)?;
    let mut scanner =
        SensitiveOutputStreamScannerV1::try_new(&prepared.detector_policy, REJECTION_PROBE.len())
            .map_err(|_| invalid("construct rejection scanner: detector setup failed"))?;
    if !matches!(
        scanner.screen(REJECTION_PROBE),
        ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected
    ) {
        return Err(invalid(
            "runner-owned rejection probe did not match the fixed policy",
        ));
    }
    publisher
        .record_sensitive_output_detected_v2(&launch_head, &prepared.detector_policy)
        .map_err(|error| proof_box_error("persist SensitiveOutputDetected", error))?;
    let staging_neutralization = publisher
        .neutralize_sensitive_output_staging_v2(&mut stdout, &mut stderr)
        .map_err(|error| proof_box_error("neutralize rejected staging", error))?;
    let abandonment = publisher
        .abandon_sensitive_output_v2(
            stdout.into_custody(),
            stderr.into_custody(),
            prepared.termination,
            prepared.native_cleanup_proof.os_evidence_digest().as_str(),
            &prepared.detector_policy,
            &staging_neutralization,
        )
        .map_err(|error| proof_box_error("persist rejected cleanup and terminal", error))?;
    let receipt = abandonment.journal_receipt;
    let binding = CommandDomainCleanupBinding::try_new(
        prepared.request.session_id.clone(),
        prepared.request.effect.effect_id.clone(),
        prepared.request.effect.request_digest.clone(),
    )
    .map_err(|error| proof_box_error("reconstruct rejection authority", error))?;
    let rejoined = SensitiveOutputRejectionNativeProofRejoinV1::try_new(
        receipt.clone(),
        Some(prepared.native_cleanup_proof.clone()),
        prepared.backend.command_domain_backend,
        &binding,
    )
    .map_err(|error| proof_box_error("join rejection to reopened native proof", error))?;
    let response = RunnerResponseV12::command_output_abandoned_rejoined(rejoined)
        .map_err(|error| proof_box_error("reconstruct rejected v12 response", error))?;
    let response = correlated_response(&prepared.request, response)?;
    Ok(SensitiveOutputRejectionTestProofBoxV1 {
        store: prepared.store,
        acquired: prepared.acquired,
        request: prepared.request,
        response,
        receipt,
        native_cleanup_proof: prepared.native_cleanup_proof,
        staging_neutralization,
    })
}

fn correlated_response(
    request: &RunnerRequestEnvelopeV12,
    response: RunnerResponseV12,
) -> Result<RunnerResponseEnvelopeV12, CommandOutputV2TestProofBoxError> {
    let envelope = RunnerResponseEnvelopeV12 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
        session_id: request.session_id.clone(),
        runner_nonce: request.runner_nonce.clone(),
        sequence: request.sequence,
        request_id: request.request_id.clone(),
        effect: request.effect.clone(),
        response,
    };
    envelope
        .validate_correlation(request)
        .map_err(|error| proof_box_error("validate response correlation", error))?;
    encode_response_frame_v12(&envelope)
        .map_err(|error| proof_box_error("encode exact v12 response", error))?;
    Ok(envelope)
}

fn validated_linux_cleanup_proof_for(
    binding: &CommandDomainCleanupBinding,
) -> Result<ValidatedCommandDomainCleanupProof, CommandOutputV2TestProofBoxError> {
    let requested_limits = RequestedDomainLimits {
        pids_max: 8,
        memory_max: LimitValue::Max,
        memory_swap_max: LimitValue::Max,
    };
    let read_back_limits = ReadBackDomainLimits {
        pids_max: 8,
        memory_max: LimitValue::Max,
        memory_swap_max: LimitValue::Max,
        memory_oom_group: true,
    };
    let leaf_identity = CgroupObjectIdentity {
        device: 41,
        inode: 42,
    };
    let observations = vec![
        RawCleanupObservation {
            sequence: 1,
            attempt: 1,
            file: LeafFile::CgroupEvents,
            bytes: b"populated 0\nfrozen 0\n".to_vec(),
        },
        RawCleanupObservation {
            sequence: 2,
            attempt: 1,
            file: LeafFile::CgroupProcs,
            bytes: Vec::new(),
        },
        RawCleanupObservation {
            sequence: 3,
            attempt: 1,
            file: LeafFile::CgroupProcs,
            bytes: Vec::new(),
        },
    ];
    let leaf_name = format!("gb-{}", "a".repeat(64));
    let journal_record = DomainJournalRecord {
        state: DomainJournalState::Removed,
        native_launch: LinuxNativeLaunchIdentity {
            contract_version: CONTRACT_VERSION,
            attempt_id: "test-support-linux-preparation-attempt-1".into(),
            native_journal_id: "test-support-linux-native-journal-1".into(),
            expected_platform_binding_digest: Digest::sha256(b"test-platform-binding"),
            sprint_id: "test-support-sprint".into(),
            launch_id: "test-support-launch".into(),
            session_id: binding.runner_session_id().into(),
            cleanup_effect_id: "test-support-cleanup-effect".into(),
            input_snapshot: Digest::sha256(b"test-input-snapshot"),
            grant_hash: Digest::sha256(b"test-grant"),
            policy_hash: Digest::sha256(b"test-policy"),
            claimed_at_unix_ms: 1,
        },
        runner_session_id: binding.runner_session_id().into(),
        effect_id: binding.command_effect_id().into(),
        grant_hash: Digest::sha256(b"test-grant").to_string(),
        policy_hash: Digest::sha256(b"test-policy").to_string(),
        command_hash: Digest::sha256(b"test-command").to_string(),
        request_digest: binding.command_request_digest().to_string(),
        leaf_name: leaf_name.clone(),
        expected_delegation_identity: CgroupObjectIdentity {
            device: 11,
            inode: 12,
        },
        expected_owner_uid: 501,
        leaf_identity: Some(leaf_identity),
        requested_limits,
        read_back_limits: Some(read_back_limits),
        staged_launcher: None,
        release_authorization: None,
        release_binding: None,
        release_intent_recorded: false,
        release_observation: None,
        cleanup_observations: observations.clone(),
        kill_value: Some(b"1\n".to_vec()),
    };
    let candidate = CgroupCleanupEvidence {
        journal_record,
        request_digest: binding.command_request_digest().to_string(),
        leaf_name,
        leaf_identity,
        requested_limits,
        read_back_limits,
        kill_value: b"1\n".to_vec(),
        observations,
        stable_empty_reads: 2,
        leaf_removed: true,
        surviving_processes: 0,
    };
    candidate
        .validate()
        .map_err(|error| proof_box_error("validate runner-owned Linux cleanup fixture", error))?;
    ValidatedCommandDomainCleanupProof::from_linux_candidate(&candidate)
        .map_err(|error| proof_box_error("construct canonical Linux cleanup proof", error))
}

fn macos_test_observation(
    sequence: u32,
    observed_at_unix_ms: u64,
    process_ids: Vec<u32>,
) -> Result<MacosProcessObservation, CommandOutputV2TestProofBoxError> {
    let mut observation = MacosProcessObservation {
        sequence,
        observed_at_unix_ms,
        uid: 601,
        process_ids,
        enumeration_digest: Digest::sha256(b"test-support-macos-observation-placeholder"),
        creation_sealed: true,
    };
    observation.enumeration_digest = observation
        .computed_digest()
        .map_err(|error| proof_box_error("encode macOS process observation", error))?;
    Ok(observation)
}

#[allow(
    clippy::too_many_lines,
    reason = "the test-only proof box keeps every signed-helper request and cleanup-journal field explicit so the canonical outer-command join remains auditable"
)]
fn validated_macos_cleanup_proof_for(
    binding: &CommandDomainCleanupBinding,
    request: &RunnerRequestEnvelopeV12,
    grant_hash: &Digest,
    termination: CommandTerminationV1,
) -> Result<ValidatedCommandDomainCleanupProof, CommandOutputV2TestProofBoxError> {
    let (RunnerRequest::WorkerRunCommand { command, .. }
    | RunnerRequest::FinalVerifierRunCommand { command, .. }) = request.request.command_request()
    else {
        return Err(invalid("macOS cleanup fixture lost its command request"));
    };
    let canonical_command = CommandSpec {
        program: command.program.clone(),
        arguments: command.arguments.clone(),
        working_directory: PathBuf::from(&command.working_directory),
    };
    canonical_command
        .validate()
        .map_err(|error| proof_box_error("validate canonical macOS command", error))?;
    let canonical_command_bytes = serde_json::to_vec(&canonical_command)
        .map_err(|error| proof_box_error("encode canonical macOS command", error))?;
    if binding.command_request_digest() != &Digest::sha256(&canonical_command_bytes) {
        return Err(invalid(
            "macOS cleanup binding differs from the canonical Core CommandSpec digest",
        ));
    }

    let assigned_identity = MacosAssignedIdentity {
        account_name: "_grokbuild601".into(),
        uid: 601,
        gid: 601,
        account_record_digest: Digest::sha256(b"test-support-macos-account-record"),
    };
    let preparation = MacosHelperPreparationBinding {
        contract_version: CONTRACT_VERSION,
        attempt_id: "test-support-macos-preparation-attempt-1".into(),
        sprint_id: request.effect.sprint_id.clone(),
        launch_id: request.effect.launch_id.clone(),
        runner_session_id: request.session_id.clone(),
        cleanup_effect_id: "test-support-macos-cleanup-effect-1".into(),
        input_snapshot: request.effect.input_snapshot.clone(),
        native_journal_id: "test-support-macos-native-journal-1".into(),
        expected_platform_binding_digest: Digest::sha256(b"test-support-macos-platform-binding"),
        claimed_at_unix_ms: 900,
    };
    let descriptor_bindings = [
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
            object_digest: Digest::sha256(
                format!("test-support-macos-descriptor-{target_fd}").as_bytes(),
            ),
            inherited_through_exec,
        },
    )
    .collect();
    let relative_working_directory = if command.working_directory.is_empty() {
        ".".into()
    } else {
        command.working_directory.clone()
    };
    let mut helper_request = MacosHelperLaunchRequest {
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: 1,
        session_nonce: request.runner_nonce.clone(),
        request_id: "test-support-macos-request-1".into(),
        preparation,
        runner_session_id: request.session_id.clone(),
        effect_id: request.effect.effect_id.clone(),
        workspace_grant_hash: grant_hash.clone(),
        execution_policy_hash: request.effect.policy_hash.clone(),
        staged_workspace_id: "test-support-macos-shadow-1".into(),
        executable_identity: MacosExecutableIdentity::SystemToolchain {
            policy_entry_id: "test-support-system-toolchain-1".into(),
            binary_digest: Digest::sha256(b"test-support-macos-system-toolchain"),
        },
        descriptor_bindings,
        argv: std::iter::once(command.program.clone())
            .chain(command.arguments.iter().cloned())
            .collect(),
        relative_working_directory,
        environment: BTreeMap::new(),
        deadline_unix_ms: 2_000,
        max_output_bytes: 1_024,
        max_processes: 8,
        max_memory_bytes: None,
        command_network: MacosHelperNetwork::Denied,
        seatbelt_profile_digest: Digest::sha256(b"test-support-macos-seatbelt-profile"),
        request_digest: Digest::sha256(b"test-support-macos-request-placeholder"),
    };
    helper_request.request_digest = helper_request
        .computed_digest()
        .map_err(|error| proof_box_error("encode signed-helper launch request", error))?;
    let admission_session = MacosHelperSession {
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: 1,
        session_nonce: request.runner_nonce.clone(),
        helper_binary_digest: Digest::sha256(b"test-support-macos-helper-binary"),
        helper_requirement_digest: Digest::sha256(b"test-support-macos-helper-requirement"),
        client_binary_digest: Digest::sha256(b"test-support-macos-client-binary"),
        client_requirement_digest: Digest::sha256(b"test-support-macos-client-requirement"),
        pool_record_digest: Digest::sha256(b"test-support-macos-pool-record"),
        workspace_grant_hash: grant_hash.clone(),
        execution_policy_hash: request.effect.policy_hash.clone(),
        command_network: MacosHelperNetwork::Denied,
        authenticated_at_unix_ms: 800,
        peer_requirement_matched: true,
        attestation: MacosHelperAttestation::LocalCodeIdentity {
            install_audit: MacosHelperInstallAudit {
                auditing_uid: 501,
                binary_owner_uid: 0,
                binary_mode: 0o755,
                directory_owner_uid: 0,
                directory_mode: 0o755,
            },
        },
    };
    let termination_reason = match termination {
        CommandTerminationV1::Exited { .. } | CommandTerminationV1::Signaled { .. } => {
            MacosTerminationReason::Exited
        }
        CommandTerminationV1::TimedOut => MacosTerminationReason::TimedOut,
        CommandTerminationV1::Canceled => MacosTerminationReason::Canceled,
        CommandTerminationV1::OutputLimitExceeded => MacosTerminationReason::OutputLimit,
    };
    let journal_record = MacosHelperJournalRecord {
        state: MacosHelperJournalState::Cleaned,
        admission_session,
        request: helper_request,
        assigned_identity: Some(assigned_identity.clone()),
        cleanup_agent_digest: Some(Digest::sha256(b"test-support-macos-cleanup-agent")),
        held_preparation_evidence: None,
        release_authorization: None,
        release_evidence: None,
        termination_reason: Some(termination_reason),
        observations: vec![
            macos_test_observation(1, 1_000, vec![71])?,
            macos_test_observation(2, 1_001, Vec::new())?,
            macos_test_observation(3, 1_002, Vec::new())?,
        ],
        identity_released: true,
    };
    let candidate = MacosCleanupEvidence {
        request_digest: journal_record.request_digest().clone(),
        journal_record,
        assigned_identity,
        surviving_processes: 0,
        stable_empty_observations: 2,
    };
    candidate
        .validate()
        .map_err(|error| proof_box_error("validate runner-owned macOS cleanup fixture", error))?;
    let proof = ValidatedCommandDomainCleanupProof::from_macos_candidate(&candidate)
        .map_err(|error| proof_box_error("construct canonical macOS cleanup proof", error))?;
    proof
        .validate_expected(
            proof.os_evidence_digest(),
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            binding,
        )
        .map_err(|error| proof_box_error("join macOS cleanup proof to outer command", error))?;
    Ok(proof)
}

/// Mints one containment-refusal attachment from *live* kernel reads.
///
/// This is not a fixture in the usual sense and deliberately cannot become one:
/// it calls the same production observation the runner service calls, so it
/// returns `None` on any host that cannot answer the absence question, and it
/// mints nothing at all when the answers are not the absence answers. Its only
/// test-support role is choosing which command effect and capture head the live
/// reads are bound to, so a cross-crate test can drive the desktop's validation
/// boundary against evidence the desktop did not author.
#[must_use]
pub fn live_containment_refusal_evidence_v12(
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &Digest,
    capture_id: &str,
    untouched_store_head: CommandOutputCaptureStoreHeadV1,
) -> Option<WireContainmentRefusalEvidenceV12> {
    let observation = crate::command_domain_absence::observe_linux_command_domain_absence(
        runner_session_id,
        effect_id,
        request_digest.as_str(),
    )
    .ok()?;
    let proof =
        ValidatedCommandDomainCleanupProof::from_linux_absence_observation(&observation).ok()?;
    let evidence = WireContainmentRefusalEvidenceV12 {
        capture_id: capture_id.to_owned(),
        untouched_store_head,
        command_domain_backend: proof.backend(),
        no_domain_proof_bytes: proof.os_evidence_bytes().to_vec(),
        no_domain_proof_digest: proof.os_evidence_digest().clone(),
    };
    evidence.validate().ok()?;
    Some(evidence)
}

/// What the Linux plan's linkage prover measured out of one executable's ELF
/// program headers.
///
/// Every field is a count or a length taken from the image's own bytes. There
/// is no `is_static` flag: the measurement exists **only** when the prover
/// produced `LinuxTargetLinkageV1::StaticElf`, so possessing one of these is
/// the claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticElfLinkageMeasurementV1 {
    /// Length the held descriptor's own `fstat` reported.
    pub byte_length: u64,
    /// Program headers the prover walked in full.
    pub program_headers: usize,
    /// How many of those were `PT_LOAD`.
    pub loadable_segments: usize,
    /// Machine architecture measured out of `e_machine`.
    pub architecture: &'static str,
}

/// Measures one on-disk executable's ELF linkage through a descriptor this
/// function holds open, and requires the answer to be static.
///
/// This exists so a cross-crate test proves the *same* linkage the Linux plan
/// would commit, using the *same* parser. A second hand-written program header
/// walk in a test could disagree with the production one, and a test that
/// disagrees with the code it guards is worse than no test — so there is
/// exactly one walk in this workspace and this is the door to it.
///
/// The path is opened `O_RDONLY | O_CLOEXEC | O_NOFOLLOW`, its length comes
/// from `fstat` on that descriptor, and every byte the walk reads is read
/// positionally from it. Nothing is reopened between the length and the bytes.
///
/// # Errors
///
/// Returns the production refusal's own text when the image is not a static
/// ELF for this build's architecture, and an open/stat description when the
/// descriptor cannot be obtained.
#[cfg(unix)]
pub fn measure_static_elf_linkage_v1(
    path: &std::path::Path,
) -> Result<StaticElfLinkageMeasurementV1, String> {
    use rustix::fs::{Mode, OFlags, open};

    let expected = crate::linux_command_plan::LinuxMachineArchitectureV1::compiled_target()
        .ok_or_else(|| {
            format!(
                "this build targets {}, which the Linux plan schema cannot describe",
                std::env::consts::ARCH
            )
        })?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| format!("cannot open {} for measurement: {error}", path.display()))?;
    let descriptor = std::fs::File::from(descriptor);
    let byte_length = descriptor
        .metadata()
        .map_err(|error| {
            format!(
                "cannot stat the held descriptor for {}: {error}",
                path.display()
            )
        })?
        .len();
    let measured = crate::linux_command_plan::LinuxMeasuredTargetImageV1::measure(
        &descriptor,
        byte_length,
        expected,
        "the measured executable",
    )
    .map_err(|error| error.to_string())?;
    Ok(StaticElfLinkageMeasurementV1 {
        byte_length: measured.byte_length(),
        program_headers: measured.program_header_count(),
        loadable_segments: measured.loadable_segment_count(),
        architecture: expected.as_str(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CommandOutputArtifactSourceV1, CommandOutputCaptureIntentV1, CommandSpec, PathScope,
        WorkerLease,
    };
    use serde::Serialize;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        parent: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let requested_parent = std::env::temp_dir().join(format!(
                "grok-build-runner-test-support-{label}-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let requested_state = requested_parent.join("state");
            fs::create_dir(&requested_parent).expect("create proof-box fixture parent");
            fs::create_dir(&requested_state).expect("create proof-box private state");
            let parent = fs::canonicalize(requested_parent).expect("canonicalize fixture parent");
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

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps the exact worker lease, request, transport commitment, capture anchor, and backend authority adjacent"
    )]
    fn externally_prepared_input(
        fixture: &Fixture,
        label: &str,
    ) -> ClaimedCommandOutputV2TestProofBoxInput {
        let command = CommandSpec {
            program: "true".into(),
            arguments: Vec::new(),
            working_directory: PathBuf::new(),
        };
        let request_digest = Digest::sha256(
            &serde_json::to_vec(&command).expect("encode exact core command request"),
        );
        let source = CommandOutputArtifactSourceV1 {
            sprint_id: format!("sprint-{label}"),
            runner_launch_id: format!("launch-{label}"),
            runner_session_id: format!("session-{label}"),
            effect_id: format!("effect-{label}"),
            request_digest: request_digest.clone(),
        };
        let intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(format!("capture-{label}").as_bytes()).to_string(),
            source.clone(),
            crate::service::inspect_private_state_digest(&fixture.state)
                .expect("inspect exact private-state identity"),
            4_096,
            1,
        )
        .expect("construct exact capture intent");
        let mut claim_preimage =
            Vec::with_capacity(b"grok-build/runner-effect-dispatch-claim/v1\0".len() + 64);
        claim_preimage.extend_from_slice(b"grok-build/runner-effect-dispatch-claim/v1\0");
        claim_preimage.extend_from_slice(source.effect_id.as_bytes());
        let dispatch_claim_id = Digest::sha256(&claim_preimage).to_string();
        let store =
            CapabilityCommandOutputStore::open(&fixture.state).expect("open proof-box store");
        let reservation = store
            .reserve_anchored_capture_v2(
                &intent,
                &dispatch_claim_id,
                2,
                &SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            )
            .expect("reserve externally prepared v2 capture");
        let acquired = reservation
            .into_acquired_anchor_for_handoff()
            .expect("synchronize externally prepared v2 acquisition");
        let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("adapt exact acquired capture");
        let task_id = format!("task-{label}");
        let worker_id = format!("worker-{label}");
        let worker_lease = WorkerLease::new(
            source.sprint_id.clone(),
            1,
            task_id.clone(),
            worker_id.clone(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("construct exact worker lease");
        let mut request = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: source.runner_session_id,
            runner_nonce: Digest::sha256(format!("nonce-{label}").as_bytes()),
            sequence: 1,
            request_id: format!("request-{label}"),
            effect: crate::WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: source.runner_launch_id,
                effect_id: source.effect_id,
                idempotency_key: format!("idempotency-{label}"),
                sprint_id: source.sprint_id,
                task_id: Some(task_id),
                worker_id: Some(worker_id),
                worker_lease: Some(worker_lease),
                policy_hash: Digest::sha256(b"policy"),
                input_snapshot: Digest::sha256(b"input"),
                request_digest,
                transport_commitment_digest: Digest::sha256(b"placeholder"),
            },
            request: crate::RunnerRequestV12::RunCommand {
                request: RunnerRequest::WorkerRunCommand {
                    command: crate::WireCommandSpec {
                        program: command.program,
                        arguments: command.arguments,
                        working_directory: String::new(),
                    },
                    output_capture,
                },
                detector_policy: SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
            },
        };
        request
            .bind_transport_commitment_digest()
            .expect("bind exact externally prepared v12 request");
        encode_request_frame_v12(&request).expect("validate exact v12 request frame");
        ClaimedCommandOutputV2TestProofBoxInput {
            private_state_root: fixture.state.clone(),
            grant_hash: Digest::sha256(b"test-grant"),
            acquired,
            request,
            termination: CommandTerminationV1::Exited { code: 0 },
            backend: WireCommandBackendIdentity {
                command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "runner-test-support-linux-cgroup-v2".into(),
                implementation_digest: Digest::sha256(b"runner-test-support-linux-backend"),
            },
        }
    }

    fn intent_from_cut(
        fixture: &Fixture,
        cut: &SensitiveOutputJournalCutTestProofBoxV1,
    ) -> CommandOutputCaptureIntentV1 {
        let acquired = cut.acquired();
        let intent = CommandOutputCaptureIntentV1::try_new(
            acquired.capture_id.clone(),
            acquired.source.clone(),
            crate::service::inspect_private_state_digest(&fixture.state)
                .expect("inspect recovery private state"),
            acquired.max_aggregate_output_bytes,
            1,
        )
        .expect("reconstruct exact capture intent");
        assert_eq!(intent.intent_digest, acquired.intent_digest);
        intent
    }

    #[derive(Serialize)]
    struct CanonicalRecoveryClaim<'a> {
        contract_version: u32,
        claim_id: &'a str,
        capture_id: &'a str,
        owner_id: &'a str,
        claim_epoch: u64,
        previous_claim_id: Option<&'a str>,
        fencing_token: &'a Digest,
        acquired_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    fn framed_digest(domain: &[u8], value: &[u8]) -> Digest {
        let mut bytes = Vec::with_capacity(domain.len() + 8 + value.len());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(
            &u64::try_from(value.len())
                .expect("claim bytes fit u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
        Digest::sha256(&bytes)
    }

    fn recovery_claim(
        capture_id: &str,
        epoch: u64,
        previous_claim_id: Option<String>,
    ) -> grok_build_core::CommandOutputCaptureReconciliationClaimV1 {
        let claim_id =
            Digest::sha256(format!("test-support-recovery-{capture_id}-{epoch}").as_bytes())
                .to_string();
        let owner_id = "test-support-recovery-owner".to_string();
        let mut token = Vec::new();
        for value in [
            capture_id.as_bytes(),
            claim_id.as_bytes(),
            owner_id.as_bytes(),
        ] {
            token.extend_from_slice(
                &u64::try_from(value.len())
                    .expect("claim component fits u64")
                    .to_be_bytes(),
            );
            token.extend_from_slice(value);
        }
        token.extend_from_slice(&epoch.to_be_bytes());
        let fencing_token = framed_digest(
            b"grok-build/command-output-capture-reconciliation-fencing-token/v1\0",
            &token,
        );
        let acquired_at_unix_ms = 20 + epoch;
        let expires_at_unix_ms = acquired_at_unix_ms + 1_000;
        let canonical = serde_json::to_vec(&CanonicalRecoveryClaim {
            contract_version: CONTRACT_VERSION,
            claim_id: &claim_id,
            capture_id,
            owner_id: &owner_id,
            claim_epoch: epoch,
            previous_claim_id: previous_claim_id.as_deref(),
            fencing_token: &fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
        })
        .expect("encode recovery claim");
        let claim = grok_build_core::CommandOutputCaptureReconciliationClaimV1 {
            contract_version: CONTRACT_VERSION,
            claim_id,
            capture_id: capture_id.to_owned(),
            owner_id,
            claim_epoch: epoch,
            previous_claim_id,
            fencing_token,
            acquired_at_unix_ms,
            expires_at_unix_ms,
            claim_digest: framed_digest(
                b"grok-build/command-output-capture-reconciliation-claim/v1\0",
                &canonical,
            ),
        };
        claim.validate().expect("validate recovery claim");
        claim
    }

    fn launch_binding_from_cut(
        cut: &SensitiveOutputJournalCutTestProofBoxV1,
    ) -> crate::ValidatedCommandCaptureLaunchBindingV12 {
        let request = cut.request();
        let (command, output_capture) = match &request.request {
            crate::RunnerRequestV12::RunCommand {
                request:
                    RunnerRequest::WorkerRunCommand {
                        command,
                        output_capture,
                    },
                ..
            } => (command.clone(), output_capture.clone()),
            crate::RunnerRequestV12::RunCommand { .. } => {
                panic!("recovery fixture must retain a worker command")
            }
        };
        let task_id = request.effect.task_id.clone().expect("task id");
        let worker_id = request.effect.worker_id.clone().expect("worker id");
        let worker_lease = request.effect.worker_lease.clone().expect("worker lease");
        let effect = grok_build_core::EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: request.effect.effect_id.clone(),
            idempotency_key: request.effect.idempotency_key.clone(),
            sprint_id: request.effect.sprint_id.clone(),
            task_id: Some(task_id),
            worker_id: Some(worker_id.clone()),
            worker_lease: Some(worker_lease.clone()),
            causation_event_id: None,
            correlation_id: format!("correlation-{}", request.request_id),
            kind: grok_build_core::EffectKind::RunCommand,
            request_digest: request.effect.request_digest.clone(),
            policy_hash: request.effect.policy_hash.clone(),
            input_snapshot: request.effect.input_snapshot.clone(),
            created_at_unix_ms: 2,
        };
        effect.validate().expect("validate restart effect");
        let grant_hash = Digest::sha256(b"test-grant");
        let session = grok_build_core::RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: request.effect.sprint_id.clone(),
            launch_id: request.effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            purpose: grok_build_core::RunnerSessionPurpose::TaskWorker,
            worker_id: Some(worker_id),
            worker_lease: Some(worker_lease),
            policy_hash: request.effect.policy_hash.clone(),
            session_nonce: request.runner_nonce.clone(),
            runner_binary_digest: Digest::sha256(b"test-runner-binary"),
            protocol_digest: Digest::sha256(b"test-runner-protocol"),
            private_state_digest: cut.acquired().private_state_digest.clone(),
            grant_hash: grant_hash.clone(),
            policy_version: 1,
            registered_at_unix_ms: 2,
        };
        session.validate().expect("validate restart session");
        let running_boundary_id = format!("running-{}", request.request_id);
        let dispatch = grok_build_core::PersistedRunnerEffectDispatchClaim {
            dispatch_claim_id: cut.acquired().dispatch_claim_id.clone(),
            effect_id: request.effect.effect_id.clone(),
            sprint_id: request.effect.sprint_id.clone(),
            launch_id: request.effect.launch_id.clone(),
            session_id: request.session_id.clone(),
            running_boundary_id: Some(running_boundary_id.clone()),
            authority: grok_build_core::RunnerEffectRequestAuthority::TaskRunning {
                running_boundary_id,
            },
            request_digest: request.effect.request_digest.clone(),
            opaque_transport_request_digest: Digest::sha256(
                &encode_request_frame_v12(request).expect("encode restart request"),
            ),
            policy_hash: request.effect.policy_hash.clone(),
            input_snapshot: request.effect.input_snapshot.clone(),
            contract_version: CONTRACT_VERSION,
        };
        let v1 = cut
            .store()
            .reopen_capture(&cut.acquired().capture_id)
            .expect("reopen launch payload");
        let launch = v1.launch_intended().expect("retained launch payload");
        crate::decode_contained_capture_launch_binding_v12(
            &launch.canonical_bytes,
            v1.launch_intended_store_head().expect("launch head"),
            &effect,
            &dispatch,
            &session,
            &command,
            &output_capture,
            request.detector_policy(),
            &grant_hash,
        )
        .expect("decode exact V12 launch binding")
    }

    fn wire_terminal_for_recovered_clean(
        cut: &SensitiveOutputJournalCutTestProofBoxV1,
        clean: &crate::SensitiveOutputCleanPublicationRecoveryV1,
        stdout_bytes: &[u8],
        stderr_bytes: &[u8],
    ) -> (
        WireCommandTerminalEvidence,
        Vec<u8>,
        WireCommandOutputCaptureAnchorV1,
    ) {
        let acquired = cut.acquired();
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
            .expect("construct exact output-capture anchor");
        let stdout = WireCommandStreamEvidence {
            retained_bytes: stdout_bytes.to_vec(),
            complete_digest: Digest::sha256(stdout_bytes),
            complete_length: u64::try_from(stdout_bytes.len()).expect("stdout length fits u64"),
            truncated: false,
        };
        let stderr = WireCommandStreamEvidence {
            retained_bytes: stderr_bytes.to_vec(),
            complete_digest: Digest::sha256(stderr_bytes),
            complete_length: u64::try_from(stderr_bytes.len()).expect("stderr length fits u64"),
            truncated: false,
        };
        let finished_store_head = clean
            .fenced_v1_recovery()
            .finished_store_head()
            .cloned()
            .expect("clean publication retains Finished head");
        let published_store_head = clean
            .fenced_v1_recovery()
            .published_store_head()
            .cloned()
            .expect("clean publication retains Published head");
        let provisional_terminal_head = CommandOutputCaptureStoreHeadV1 {
            generation: published_store_head
                .generation
                .checked_add(1)
                .expect("terminal generation fits u64"),
            record_digest: Digest::sha256(b"test-support-terminal-head-placeholder"),
        };
        let output_capture = WireCommandOutputCaptureTerminalV1::try_new(
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            finished_store_head,
            published_store_head,
            provisional_terminal_head,
            clean.artifact_reference().clone(),
            Digest::sha256(b"test-support-terminal-digest-placeholder"),
        )
        .expect("construct provisional terminal capture");
        let mut terminal = WireCommandTerminalEvidence {
            output_capture,
            termination: CommandTerminationV1::Exited { code: 0 },
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            output_artifacts: clean.artifact_reference().clone(),
            output_digest: command_stream_output_digest(&stdout, &stderr),
            launch_digest: Digest::sha256(
                &encode_request_frame_v12(cut.request()).expect("encode exact request"),
            ),
            preflight_digest: Digest::sha256(cut.native_cleanup_proof().os_evidence_bytes()),
            backend: WireCommandBackendIdentity {
                command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
                backend_id: "runner-test-support-linux-cgroup-v2".into(),
                implementation_digest: Digest::sha256(b"runner-test-support-linux-backend"),
            },
            cleanup_proof: WireCommandCleanupProof::try_from(cut.native_cleanup_proof())
                .expect("adapt cleanup proof"),
            duration_ms: 1,
        };
        terminal
            .bind_terminal_record_digest()
            .expect("bind canonical wire terminal digest");
        let bytes = command_terminal_record_bytes(&terminal)
            .expect("encode canonical wire terminal record");
        (terminal, bytes, anchor)
    }

    #[test]
    fn clean_stage_driver_stops_at_each_real_generation() {
        for (label, cut) in [
            (
                "launch-intended",
                SensitiveOutputCleanTestCutV1::LaunchIntended,
            ),
            ("scanned-clean", SensitiveOutputCleanTestCutV1::ScannedClean),
            ("finished", SensitiveOutputCleanTestCutV1::Finished),
            ("published", SensitiveOutputCleanTestCutV1::Published),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                b"clean stdout\n",
                b"clean stderr\n",
                cut,
            )
            .expect("drive exact clean journal cut");
            assert!(matches!(
                (cut, proof_box.recovery().stage()),
                (
                    SensitiveOutputCleanTestCutV1::LaunchIntended,
                    SensitiveOutputJournalStageV2::LaunchIntended { .. }
                ) | (
                    SensitiveOutputCleanTestCutV1::ScannedClean,
                    SensitiveOutputJournalStageV2::ScannedClean { .. }
                ) | (
                    SensitiveOutputCleanTestCutV1::Finished,
                    SensitiveOutputJournalStageV2::Finished { .. }
                ) | (
                    SensitiveOutputCleanTestCutV1::Published,
                    SensitiveOutputJournalStageV2::Published { .. }
                )
            ));
        }
    }

    #[test]
    fn rejection_stage_driver_stops_at_each_real_generation() {
        for (label, cut) in [
            (
                "detected",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "cleanup-intended",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            ("cleaned", SensitiveOutputRejectionTestCutV1::Cleaned),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                cut,
            )
            .expect("drive exact rejection journal cut");
            assert!(matches!(
                (cut, proof_box.recovery().stage()),
                (
                    SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
                    SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
                ) | (
                    SensitiveOutputRejectionTestCutV1::CleanupIntended,
                    SensitiveOutputJournalStageV2::CleanupIntended { .. }
                ) | (
                    SensitiveOutputRejectionTestCutV1::Cleaned,
                    SensitiveOutputJournalStageV2::Cleaned { .. }
                )
            ));
            assert_eq!(
                proof_box.staging_neutralization().is_some(),
                cut != SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix test keeps all six branch generations and their higher-fence idempotence checks visibly symmetric"
    )]
    fn partial_terminal_exact_continuation_covers_every_generation() {
        for (label, cut) in [
            (
                "exact-clean-g5",
                SensitiveOutputCleanTestCutV1::ScannedClean,
            ),
            ("exact-clean-g6", SensitiveOutputCleanTestCutV1::Finished),
            ("exact-clean-g7", SensitiveOutputCleanTestCutV1::Published),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                b"clean recovery stdout\n",
                b"clean recovery stderr\n",
                cut,
            )
            .expect("create exact clean recovery cut");
            assert!(
                proof_box
                    .store()
                    .reopen_sensitive_output_terminal_observation_v1(
                        &proof_box.acquired().capture_id,
                    )
                    .expect("reopen clean cut observation")
                    .is_some(),
                "every post-classification clean cut must carry its sidecar"
            );
            let intent = intent_from_cut(&fixture, &proof_box);
            let launch_binding = launch_binding_from_cut(&proof_box);
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let result = proof_box
                .store()
                .resume_sensitive_output_clean_publication_v1(
                    &intent,
                    &claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                    &launch_binding,
                )
                .expect("continue exact clean partial branch");
            result.validate().expect("validate clean recovery result");
            assert_eq!(result.v2_published().head().generation, 7);
            let second_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
            proof_box
                .store()
                .resume_sensitive_output_clean_publication_v1(
                    &intent,
                    &second_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                    &launch_binding,
                )
                .expect("clean recovery is idempotent under a fresh higher fence")
                .validate()
                .expect("validate idempotent clean recovery");
        }

        for (label, cut) in [
            (
                "exact-rejection-g5",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "exact-rejection-g6",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            (
                "exact-rejection-g7",
                SensitiveOutputRejectionTestCutV1::Cleaned,
            ),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                cut,
            )
            .expect("create exact rejection recovery cut");
            assert!(
                proof_box
                    .store()
                    .reopen_sensitive_output_terminal_observation_v1(
                        &proof_box.acquired().capture_id,
                    )
                    .expect("reopen rejection cut observation")
                    .is_some(),
                "every rejection cut must carry its sidecar"
            );
            let intent = intent_from_cut(&fixture, &proof_box);
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let result = proof_box
                .store()
                .resume_sensitive_output_rejection_from_observation_v1(
                    &intent,
                    &claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                )
                .expect("continue exact rejection partial branch");
            result
                .validate()
                .expect("validate rejection recovery result");
            assert_eq!(
                result.receipt().rejected_terminal_journal_head.generation,
                8
            );
            let second_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
            proof_box
                .store()
                .resume_sensitive_output_rejection_from_observation_v1(
                    &intent,
                    &second_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                )
                .expect("rejection recovery is idempotent under a fresh higher fence")
                .validate()
                .expect("validate idempotent rejection recovery");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the terminal crash matrix keeps all pending-publication cuts, idempotence, wire digest, and v2 readback symmetric"
    )]
    fn claim_fenced_clean_terminal_preparation_recovers_every_crash_cut() {
        const STDOUT: &[u8] = b"terminal recovery stdout\n";
        const STDERR: &[u8] = b"terminal recovery stderr\n";
        for (label, record_cut) in [
            (
                "terminal-torn",
                crate::command_output_store::SensitiveOutputCleanTerminalPreparationTestCut::TempTorn,
            ),
            (
                "terminal-valid",
                crate::command_output_store::SensitiveOutputCleanTerminalPreparationTestCut::TempValid,
            ),
            (
                "terminal-synced",
                crate::command_output_store::SensitiveOutputCleanTerminalPreparationTestCut::TempSynced,
            ),
            (
                "terminal-final",
                crate::command_output_store::SensitiveOutputCleanTerminalPreparationTestCut::Final,
            ),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                STDOUT,
                STDERR,
                SensitiveOutputCleanTestCutV1::ScannedClean,
            )
            .expect("create terminal crash-cut publication");
            let intent = intent_from_cut(&fixture, &proof_box);
            let launch_binding = launch_binding_from_cut(&proof_box);
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let clean = proof_box
                .store()
                .resume_sensitive_output_clean_publication_v1(
                    &intent,
                    &claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                    &launch_binding,
                )
                .expect("recover exact clean publication");
            let published_head = clean
                .fenced_v1_recovery()
                .published_store_head()
                .cloned()
                .expect("published head");
            let (mut wire_terminal, terminal_bytes, anchor) =
                wire_terminal_for_recovered_clean(&proof_box, &clean, STDOUT, STDERR);
            proof_box
                .store()
                .inject_sensitive_output_clean_terminal_preparation_cut(
                    &intent,
                    &claim,
                    &published_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    terminal_bytes.clone(),
                    record_cut,
                )
                .expect("inject exact claim-fenced terminal publication cut");
            let prepared = proof_box
                .store()
                .prepare_sensitive_output_clean_terminal_under_claim_v1(
                    &intent,
                    &claim,
                    &clean,
                    &published_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    terminal_bytes.clone(),
                )
                .expect("recover claim-fenced terminal preparation");
            prepared.validate().expect("validate terminal preparation");
            let physical = prepared
                .physical_reconciliation_evidence(
                    &intent,
                    &claim,
                    claim.acquired_at_unix_ms + 1,
                )
                .expect("materialize claim-fenced terminal physical evidence");
            assert_eq!(physical.reconciliation_claim, claim);
            assert_eq!(
                prepared.terminal_record_digest(),
                &wire_terminal.output_capture.terminal_record_digest,
                "v1 retained payload digest must be the exact wire terminal digest"
            );
            assert_ne!(
                prepared.terminal_record_digest(),
                &prepared.terminal_prepared_store_head().record_digest,
                "wire terminal digest and v1 journal-record digest are distinct identities"
            );
            let repeated = proof_box
                .store()
                .prepare_sensitive_output_clean_terminal_under_claim_v1(
                    &intent,
                    &claim,
                    &clean,
                    &published_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    terminal_bytes,
                )
                .expect("terminal preparation is idempotent under the same fence");
            assert_eq!(repeated, prepared);
            wire_terminal.output_capture.terminal_prepared_store_head =
                prepared.terminal_prepared_store_head().clone();
            wire_terminal
                .validate_for_output_capture(&anchor)
                .expect("wire terminal validates against exact prepared capture");
            let receipt = proof_box
                .store()
                .record_sensitive_output_clean_terminal_prepared_v2(
                    prepared.capture_id(),
                    prepared.terminal_prepared_store_head(),
                    prepared.terminal_record_digest(),
                    CommandTerminationV1::Exited { code: 0 },
                )
                .expect("append clean v2 terminal");
            assert_eq!(
                receipt.terminal_record_digest,
                wire_terminal.output_capture.terminal_record_digest
            );
            assert_ne!(
                receipt.terminal_record_digest,
                receipt.terminal_prepared_store_head.record_digest
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the negative terminal matrix keeps claim lineage, head, payload, and physical-evidence crossings adjacent"
    )]
    fn claim_fenced_clean_terminal_preparation_rejects_crossed_authority_and_bytes() {
        let fixture = Fixture::new("terminal-crossing");
        let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&fixture, "terminal-crossing"),
            b"stdout\n",
            b"stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create primary clean cut");
        let intent = intent_from_cut(&fixture, &proof_box);
        let launch_binding = launch_binding_from_cut(&proof_box);
        let claim = recovery_claim(&intent.capture_id, 1, None);
        let clean = proof_box
            .store()
            .resume_sensitive_output_clean_publication_v1(
                &intent,
                &claim,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                proof_box.native_cleanup_proof(),
                &launch_binding,
            )
            .expect("recover primary clean publication");
        let published_head = clean
            .fenced_v1_recovery()
            .published_store_head()
            .cloned()
            .expect("published head");
        let (_, terminal_bytes, _) =
            wire_terminal_for_recovered_clean(&proof_box, &clean, b"stdout\n", b"stderr\n");
        let unrelated_claim = recovery_claim(
            &intent.capture_id,
            2,
            Some(Digest::sha256(b"unrelated-claim").to_string()),
        );
        assert!(
            proof_box
                .store()
                .prepare_sensitive_output_clean_terminal_under_claim_v1(
                    &intent,
                    &unrelated_claim,
                    &clean,
                    &published_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    terminal_bytes.clone(),
                )
                .is_err(),
            "higher claim must name the exact publication claim"
        );
        let crossed_head = CommandOutputCaptureStoreHeadV1 {
            generation: published_head.generation,
            record_digest: Digest::sha256(b"crossed-published-head"),
        };
        assert!(
            proof_box
                .store()
                .prepare_sensitive_output_clean_terminal_under_claim_v1(
                    &intent,
                    &claim,
                    &clean,
                    &crossed_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    terminal_bytes.clone(),
                )
                .is_err(),
            "crossed Published head cannot append a terminal"
        );
        let higher_claim = recovery_claim(&intent.capture_id, 2, Some(claim.claim_id.clone()));
        let prepared = proof_box
            .store()
            .prepare_sensitive_output_clean_terminal_under_claim_v1(
                &intent,
                &higher_claim,
                &clean,
                &published_head,
                crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                terminal_bytes,
            )
            .expect("prepare exact terminal");
        assert!(
            prepared
                .physical_reconciliation_evidence(
                    &intent,
                    &unrelated_claim,
                    unrelated_claim.acquired_at_unix_ms + 1,
                )
                .is_err(),
            "terminal physical evidence cannot cross the durable claim"
        );
        let crossed_intent = CommandOutputCaptureIntentV1::try_new(
            Digest::sha256(b"crossed-terminal-evidence-capture").to_string(),
            intent.source.clone(),
            intent.private_state_digest.clone(),
            intent.max_aggregate_output_bytes,
            intent.created_at_unix_ms,
        )
        .expect("construct crossed terminal intent");
        assert!(
            prepared
                .physical_reconciliation_evidence(
                    &crossed_intent,
                    &higher_claim,
                    higher_claim.acquired_at_unix_ms + 1,
                )
                .is_err(),
            "terminal physical evidence cannot cross the capture intent"
        );
        assert!(
            proof_box
                .store()
                .prepare_sensitive_output_clean_terminal_under_claim_v1(
                    &intent,
                    &higher_claim,
                    &clean,
                    &published_head,
                    crate::COMMAND_TERMINAL_CAPTURE_SCHEMA,
                    b"different canonical terminal bytes".to_vec(),
                )
                .is_err(),
            "idempotent terminal preparation cannot cross exact payload bytes"
        );
    }

    fn terminal_observation_path(fixture: &Fixture, capture_id: &str) -> PathBuf {
        fixture
            .state
            .join(format!("sensitive-output-journal-v2-{capture_id}"))
            .join(crate::SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1)
    }

    fn remove_terminal_observation(fixture: &Fixture, capture_id: &str) {
        fs::remove_file(terminal_observation_path(fixture, capture_id))
            .expect("remove terminal observation to model pre-sidecar crash");
    }

    fn assert_retained_tree_excludes(path: &std::path::Path, forbidden: &[&[u8]]) {
        for entry in fs::read_dir(path).expect("enumerate retained private state") {
            let entry = entry.expect("read retained private-state entry");
            let file_type = entry.file_type().expect("inspect retained entry type");
            if file_type.is_dir() {
                assert_retained_tree_excludes(&entry.path(), forbidden);
            } else if file_type.is_file() {
                let bytes = fs::read(entry.path()).expect("read retained private-state bytes");
                for rejected in forbidden {
                    assert!(
                        !bytes
                            .windows(rejected.len())
                            .any(|window| window == *rejected),
                        "retained Unknown custody contains secret-derived bytes"
                    );
                }
            }
        }
    }

    fn assert_rejection_unknown_has_no_secret_custody(
        fixture: &Fixture,
        proof_box: &SensitiveOutputJournalCutTestProofBoxV1,
        result: &crate::SensitiveOutputPartialTerminalUnknownV1,
    ) {
        assert_eq!(
            result.reason(),
            crate::SensitiveOutputPartialTerminalUnknownReasonV1::UnbackedObservation
        );
        assert_eq!(
            result.custody(),
            crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned
        );
        assert!(result.retained_immutable_artifact_reference().is_none());
        assert_eq!(result.v2_head(), proof_box.recovery().head());
        assert_eq!(
            proof_box
                .store()
                .reopen_sensitive_output_journal_v2(&proof_box.acquired().capture_id)
                .expect("reopen unchanged rejection v2 prefix"),
            *proof_box.recovery()
        );
        let v1 = proof_box
            .store()
            .reopen_capture(&proof_box.acquired().capture_id)
            .expect("reopen rejection Unknown v1 custody");
        assert_eq!(
            v1.state(),
            crate::CommandOutputCaptureJournalStateV1::Cleaned
        );
        assert!(v1.expected_reference().is_none());
        assert!(
            !fixture
                .state
                .join(format!(
                    ".command-output-capture-{}",
                    proof_box.acquired().capture_id
                ))
                .exists(),
            "rejection Unknown must remove mutable staging custody"
        );
        let rejection_probe_digest = Digest::sha256(REJECTION_PROBE).to_string();
        assert_retained_tree_excludes(
            &fixture.state,
            &[REJECTION_PROBE, rejection_probe_digest.as_bytes()],
        );
        result
            .validate()
            .expect("validate rejection Unknown without secret custody");
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one matrix test keeps all six absent-observation generations and immutable generation-seven retention visibly symmetric"
    )]
    fn partial_terminal_missing_observation_is_unknown_at_every_generation() {
        const CLEAN_STDOUT: &[u8] = b"unknown clean stdout\n";
        const CLEAN_STDERR: &[u8] = b"unknown clean stderr\n";
        for (label, cut, expected_custody) in [
            (
                "missing-clean-g5",
                SensitiveOutputCleanTestCutV1::ScannedClean,
                crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned,
            ),
            (
                "missing-clean-g6",
                SensitiveOutputCleanTestCutV1::Finished,
                crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned,
            ),
            (
                "missing-clean-g7",
                SensitiveOutputCleanTestCutV1::Published,
                crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained,
            ),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_clean_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                CLEAN_STDOUT,
                CLEAN_STDERR,
                cut,
            )
            .expect("create missing-observation clean cut");
            let intent = intent_from_cut(&fixture, &proof_box);
            let immutable_before = proof_box
                .store()
                .reopen_capture(&intent.capture_id)
                .expect("reopen clean cut before Unknown")
                .expected_reference()
                .cloned()
                .filter(|_| {
                    expected_custody
                        == crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained
                });
            remove_terminal_observation(&fixture, &intent.capture_id);
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let result = proof_box
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &intent,
                    &claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                    None,
                )
                .expect("close missing clean observation as Unknown");
            assert_eq!(
                result.reason(),
                crate::SensitiveOutputPartialTerminalUnknownReasonV1::MissingObservation
            );
            assert_eq!(result.custody(), expected_custody);
            assert_eq!(
                result.retained_immutable_artifact_reference().is_some(),
                expected_custody
                    == crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained
            );
            result.validate().expect("validate clean Unknown");
            if let Some(reference) = immutable_before {
                assert_eq!(
                    result.retained_immutable_artifact_reference(),
                    Some(&reference),
                    "generation-seven Unknown must retain the exact immutable reference"
                );
                let artifact = proof_box
                    .store()
                    .reopen(&reference)
                    .expect("generation-seven Unknown keeps immutable artifact readable");
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                artifact
                    .copy_stdout_to(&mut stdout)
                    .expect("read retained immutable stdout");
                artifact
                    .copy_stderr_to(&mut stderr)
                    .expect("read retained immutable stderr");
                assert_eq!(stdout, CLEAN_STDOUT);
                assert_eq!(stderr, CLEAN_STDERR);
            }
            result
                .physical_reconciliation_evidence(&intent, &claim, claim.acquired_at_unix_ms + 1)
                .unwrap_or_else(|error| {
                    panic!("materialize {label} Unknown physical evidence: {error}")
                });
        }

        for (label, cut) in [
            (
                "missing-rejection-g5",
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (
                "missing-rejection-g6",
                SensitiveOutputRejectionTestCutV1::CleanupIntended,
            ),
            (
                "missing-rejection-g7",
                SensitiveOutputRejectionTestCutV1::Cleaned,
            ),
        ] {
            let fixture = Fixture::new(label);
            let proof_box = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&fixture, label),
                cut,
            )
            .expect("create missing-observation rejection cut");
            let intent = intent_from_cut(&fixture, &proof_box);
            remove_terminal_observation(&fixture, &intent.capture_id);
            let claim = recovery_claim(&intent.capture_id, 1, None);
            let result = proof_box
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &intent,
                    &claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    proof_box.native_cleanup_proof(),
                    None,
                )
                .expect("close missing rejection observation as Unknown");
            assert_eq!(
                result.reason(),
                crate::SensitiveOutputPartialTerminalUnknownReasonV1::MissingObservation
            );
            assert_eq!(
                result.custody(),
                crate::SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned
            );
            assert!(result.retained_immutable_artifact_reference().is_none());
            result.validate().expect("validate rejection Unknown");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the three-generation matrix proves exact, missing, and crossed launch backing without collapsing any custody assertion"
    )]
    fn partial_terminal_rejection_requires_exact_launch_backing_to_forbid_unknown() {
        for (generation, cut) in [
            (
                5,
                SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
            ),
            (6, SensitiveOutputRejectionTestCutV1::CleanupIntended),
            (7, SensitiveOutputRejectionTestCutV1::Cleaned),
        ] {
            let exact_label = format!("rejection-exact-launch-g{generation}");
            let exact_fixture = Fixture::new(&exact_label);
            let exact = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&exact_fixture, &exact_label),
                cut,
            )
            .expect("create exact-launch rejection cut");
            let exact_intent = intent_from_cut(&exact_fixture, &exact);
            let exact_claim = recovery_claim(&exact_intent.capture_id, 1, None);
            let exact_launch = launch_binding_from_cut(&exact);
            let v1_before = exact
                .store()
                .reopen_capture(&exact_intent.capture_id)
                .expect("reopen exact-launch v1 prefix");
            assert!(
                exact
                    .store()
                    .quarantine_sensitive_output_partial_terminal_unknown_v1(
                        &exact_intent,
                        &exact_claim,
                        CommandDomainCleanupBackend::LinuxCgroupV2,
                        exact.native_cleanup_proof(),
                        Some(&exact_launch),
                    )
                    .is_err(),
                "generation {generation} exact rejection and launch backing cannot be downgraded"
            );
            assert_eq!(
                exact
                    .store()
                    .reopen_sensitive_output_journal_v2(&exact_intent.capture_id)
                    .expect("reopen exact-launch v2 prefix"),
                *exact.recovery()
            );
            assert_eq!(
                exact
                    .store()
                    .reopen_capture(&exact_intent.capture_id)
                    .expect("reopen exact-launch v1 prefix after refusal"),
                v1_before
            );

            let missing_label = format!("rejection-missing-launch-g{generation}");
            let missing_fixture = Fixture::new(&missing_label);
            let missing = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&missing_fixture, &missing_label),
                cut,
            )
            .expect("create missing-launch rejection cut");
            let missing_intent = intent_from_cut(&missing_fixture, &missing);
            let missing_claim = recovery_claim(&missing_intent.capture_id, 1, None);
            let missing_result = missing
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &missing_intent,
                    &missing_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    missing.native_cleanup_proof(),
                    None,
                )
                .expect("missing rejection launch backing converges to Unknown");
            assert_rejection_unknown_has_no_secret_custody(
                &missing_fixture,
                &missing,
                &missing_result,
            );

            let crossed_label = format!("rejection-crossed-launch-g{generation}");
            let crossed_fixture = Fixture::new(&crossed_label);
            let crossed = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&crossed_fixture, &crossed_label),
                cut,
            )
            .expect("create crossed-launch rejection target");
            let donor_label = format!("rejection-launch-donor-g{generation}");
            let donor_fixture = Fixture::new(&donor_label);
            let donor = cut_sensitive_output_rejection_test_proof_box_v1(
                externally_prepared_input(&donor_fixture, &donor_label),
                cut,
            )
            .expect("create crossed-launch rejection donor");
            let crossed_launch = launch_binding_from_cut(&donor);
            let crossed_intent = intent_from_cut(&crossed_fixture, &crossed);
            let crossed_claim = recovery_claim(&crossed_intent.capture_id, 1, None);
            let crossed_result = crossed
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &crossed_intent,
                    &crossed_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    crossed.native_cleanup_proof(),
                    Some(&crossed_launch),
                )
                .expect("crossed rejection launch backing converges to Unknown");
            assert_rejection_unknown_has_no_secret_custody(
                &crossed_fixture,
                &crossed,
                &crossed_result,
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the negative matrix keeps exact downgrade refusal, corrupt/crossed sidecars, and crossed native proof in one boundary audit"
    )]
    fn partial_terminal_unknown_refuses_exact_backing_and_types_unusable_input() {
        let clean_fixture = Fixture::new("unbacked-clean");
        let clean = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&clean_fixture, "unbacked-clean"),
            b"clean stdout\n",
            b"clean stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create unbacked clean cut");
        let clean_intent = intent_from_cut(&clean_fixture, &clean);
        let clean_claim = recovery_claim(&clean_intent.capture_id, 1, None);
        let exact_launch_binding = launch_binding_from_cut(&clean);
        assert!(
            clean
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &clean_intent,
                    &clean_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    clean.native_cleanup_proof(),
                    Some(&exact_launch_binding),
                )
                .is_err(),
            "exact clean observation plus exact launch backing cannot be downgraded"
        );
        let unbacked = clean
            .store()
            .quarantine_sensitive_output_partial_terminal_unknown_v1(
                &clean_intent,
                &clean_claim,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                clean.native_cleanup_proof(),
                None,
            )
            .expect("missing clean launch backing yields typed Unknown");
        assert_eq!(
            unbacked.reason(),
            crate::SensitiveOutputPartialTerminalUnknownReasonV1::UnbackedObservation
        );

        let rejection_fixture = Fixture::new("refuse-exact-rejection");
        let rejection = cut_sensitive_output_rejection_test_proof_box_v1(
            externally_prepared_input(&rejection_fixture, "refuse-exact-rejection"),
            SensitiveOutputRejectionTestCutV1::SensitiveOutputDetected,
        )
        .expect("create exact rejection cut");
        let rejection_intent = intent_from_cut(&rejection_fixture, &rejection);
        let rejection_claim = recovery_claim(&rejection_intent.capture_id, 1, None);
        assert!(
            rejection
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &rejection_intent,
                    &rejection_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    rejection.native_cleanup_proof(),
                    Some(&launch_binding_from_cut(&rejection)),
                )
                .is_err(),
            "an exact rejection observation plus exact launch backing cannot be downgraded"
        );

        let unusable_fixture = Fixture::new("unusable-clean-sidecar");
        let unusable = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&unusable_fixture, "unusable-clean-sidecar"),
            b"clean stdout\n",
            b"clean stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create unusable-sidecar cut");
        let unusable_intent = intent_from_cut(&unusable_fixture, &unusable);
        fs::write(
            unusable_fixture
                .state
                .join(format!(
                    "sensitive-output-journal-v2-{}",
                    unusable_intent.capture_id
                ))
                .join(crate::SENSITIVE_OUTPUT_TERMINAL_OBSERVATION_FILE_V1),
            b"{}",
        )
        .expect("cross terminal observation bytes");
        let unusable_claim = recovery_claim(&unusable_intent.capture_id, 1, None);
        let result = unusable
            .store()
            .quarantine_sensitive_output_partial_terminal_unknown_v1(
                &unusable_intent,
                &unusable_claim,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                unusable.native_cleanup_proof(),
                None,
            )
            .expect("unusable sidecar yields typed Unknown");
        assert_eq!(
            result.reason(),
            crate::SensitiveOutputPartialTerminalUnknownReasonV1::UnusableObservation
        );

        let crossed_sidecar_fixture = Fixture::new("crossed-clean-sidecar");
        let crossed_sidecar = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&crossed_sidecar_fixture, "crossed-clean-sidecar"),
            b"target stdout\n",
            b"target stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create crossed-sidecar target");
        let donor_fixture = Fixture::new("crossed-clean-sidecar-donor");
        let donor = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&donor_fixture, "crossed-clean-sidecar-donor"),
            b"donor stdout\n",
            b"donor stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create crossed-sidecar donor");
        let crossed_sidecar_intent = intent_from_cut(&crossed_sidecar_fixture, &crossed_sidecar);
        fs::copy(
            terminal_observation_path(&donor_fixture, &donor.acquired().capture_id),
            terminal_observation_path(&crossed_sidecar_fixture, &crossed_sidecar_intent.capture_id),
        )
        .expect("replace target with a canonical observation for another capture");
        let crossed_sidecar_claim = recovery_claim(&crossed_sidecar_intent.capture_id, 1, None);
        let crossed_sidecar_result = crossed_sidecar
            .store()
            .quarantine_sensitive_output_partial_terminal_unknown_v1(
                &crossed_sidecar_intent,
                &crossed_sidecar_claim,
                CommandDomainCleanupBackend::LinuxCgroupV2,
                crossed_sidecar.native_cleanup_proof(),
                None,
            )
            .expect("crossed canonical sidecar yields typed Unknown");
        assert_eq!(
            crossed_sidecar_result.reason(),
            crate::SensitiveOutputPartialTerminalUnknownReasonV1::UnusableObservation
        );

        let crossed_fixture = Fixture::new("crossed-clean-proof");
        let crossed = cut_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&crossed_fixture, "crossed-clean-proof"),
            b"clean stdout\n",
            b"clean stderr\n",
            SensitiveOutputCleanTestCutV1::ScannedClean,
        )
        .expect("create crossed-proof cut");
        let crossed_intent = intent_from_cut(&crossed_fixture, &crossed);
        let crossed_claim = recovery_claim(&crossed_intent.capture_id, 1, None);
        let crossed_binding = CommandDomainCleanupBinding::try_new(
            crossed_intent.source.runner_session_id.clone(),
            "different-effect",
            crossed_intent.source.request_digest.clone(),
        )
        .expect("construct crossed cleanup binding");
        let crossed_proof = validated_linux_cleanup_proof_for(&crossed_binding)
            .expect("construct crossed native proof");
        assert!(
            crossed
                .store()
                .quarantine_sensitive_output_partial_terminal_unknown_v1(
                    &crossed_intent,
                    &crossed_claim,
                    CommandDomainCleanupBackend::LinuxCgroupV2,
                    &crossed_proof,
                    None,
                )
                .is_err(),
            "a crossed native proof cannot authorize even Unknown cleanup"
        );
    }

    #[test]
    fn terminal_proof_boxes_emit_exact_correlated_v12_responses() {
        let clean_fixture = Fixture::new("terminal-clean");
        let clean = complete_sensitive_output_clean_test_proof_box_v1(
            externally_prepared_input(&clean_fixture, "terminal-clean"),
            b"clean stdout\n",
            b"clean stderr\n",
        )
        .expect("complete clean proof box");
        assert!(matches!(
            clean.response().response,
            RunnerResponseV12::CommandCompleted { .. }
        ));
        clean
            .response()
            .validate_correlation(clean.request())
            .expect("revalidate exact clean response");

        let rejected_fixture = Fixture::new("terminal-rejected");
        let rejected = complete_sensitive_output_rejection_test_proof_box_v1(
            externally_prepared_input(&rejected_fixture, "terminal-rejected"),
        )
        .expect("complete rejected proof box");
        assert!(matches!(
            rejected.response().response,
            RunnerResponseV12::CommandOutputAbandoned { .. }
        ));
        rejected
            .response()
            .validate_correlation(rejected.request())
            .expect("revalidate exact rejected response");
    }

    #[test]
    fn macos_clean_proof_box_joins_canonical_outer_command_to_helper_journal() {
        let fixture = Fixture::new("macos-clean-outer-join");
        let mut input = externally_prepared_input(&fixture, "macos-clean-outer-join");
        let expected_binding = CommandDomainCleanupBinding::try_new(
            input.request.session_id.clone(),
            input.request.effect.effect_id.clone(),
            input.request.effect.request_digest.clone(),
        )
        .expect("construct exact outer command cleanup binding");
        input.backend = WireCommandBackendIdentity {
            command_domain_backend: CommandDomainCleanupBackend::MacOsDedicatedIdentity,
            backend_id: "runner-test-support-macos-dedicated-identity".into(),
            implementation_digest: Digest::sha256(b"runner-test-support-macos-backend"),
        };

        let proof_box = complete_sensitive_output_clean_test_proof_box_v1(
            input,
            b"clean stdout\n",
            b"clean stderr\n",
        )
        .expect("complete native-validating macOS contract proof box");

        assert_eq!(
            proof_box.native_cleanup_proof().backend(),
            CommandDomainCleanupBackend::MacOsDedicatedIdentity
        );
        proof_box
            .native_cleanup_proof()
            .validate_expected(
                proof_box.native_cleanup_proof().os_evidence_digest(),
                CommandDomainCleanupBackend::MacOsDedicatedIdentity,
                &expected_binding,
            )
            .expect("macOS helper journal rejoins the canonical outer command");
        proof_box
            .response()
            .validate_correlation(proof_box.request())
            .expect("macOS proof-box response remains exactly correlated");
        assert!(matches!(
            proof_box.response().response,
            RunnerResponseV12::CommandCompleted { .. }
        ));
    }
}
