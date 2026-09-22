//! Immutable, source-bound storage for complete command stdout and stderr.
//!
//! The store has no execution authority. A caller reserves one bounded capture
//! before starting an effect. The v2 sensitive-output path appends only bytes
//! released clean by its authenticated streaming scanner; matched or
//! still-undecided bytes never enter the store. Publication occurs only after
//! both streams and command-domain cleanup complete, using one no-replace
//! directory rename below an already-acquired private-state capability.
//! Reopening revalidates the root, final name, canonical manifest, exact
//! directory entries, file identities, lengths, and SHA-256 commitments.

#[path = "command_output_journal.rs"]
mod command_output_journal;
#[path = "sensitive_output_journal.rs"]
mod sensitive_output_journal;
#[path = "sensitive_output_terminal_observation_store.rs"]
mod sensitive_output_terminal_observation_store;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use cap_std::{ambient_authority, fs::Permissions};
use grok_build_core::{
    COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION, CommandOutputArtifactSetReferenceV1,
    CommandOutputArtifactSourceV1, CommandOutputCaptureAcquiredV1, CommandOutputCaptureIntentV1,
    CommandOutputCaptureReconciliationClaimV1, CommandOutputCaptureStoreHeadV1,
    CommandOutputStreamArtifactV1, CommandOutputStreamV1, CommandTerminationV1, Digest,
    SensitiveOutputDetectionPolicyReferenceV1, SensitiveOutputJournalHeadV1,
};
use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::capability_apply::DirectoryPathAnchor;
use crate::cleanup_proof::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, ValidatedCommandDomainCleanupProof,
};
use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::sensitive_output::SensitiveOutputCoreDumpSuppressionV1;

#[allow(
    unused_imports,
    reason = "the crate root reexports this complete recovery surface for external restart coordinators"
)]
pub use command_output_journal::{
    CommandOutputCaptureCanonicalPayloadV1, CommandOutputCaptureFencedResolution,
    CommandOutputCaptureId, CommandOutputCaptureJournalStateV1,
    CommandOutputCapturePendingRecordClassV1, CommandOutputCapturePendingRecordV1,
    CommandOutputCaptureRecovery, CommandOutputCaptureReservation,
};
pub use grok_build_core::SensitiveOutputStagingNeutralizationReceiptV1;
pub use sensitive_output_journal::{
    SensitiveOutputCleanJournalReceiptV2, SensitiveOutputJournalRecoveryV2,
    SensitiveOutputJournalStageV2, SensitiveOutputRejectionJournalReceiptV2,
};

/// Exact join between a terminal sensitive-output journal and independently
/// reopened native command-domain cleanup evidence.
///
/// The v2 output journal deliberately retains only the native proof digest.
/// Construction therefore requires the complete native proof from a separate
/// durable authority and revalidates its canonical bytes, platform backend,
/// command-effect binding, and digest before any restart path may reconstruct
/// terminal rejection evidence.
#[must_use = "a native-proof rejoin must be consumed by terminal rejection reconstruction"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputRejectionNativeProofRejoinV1 {
    receipt: SensitiveOutputRejectionJournalReceiptV2,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
    expected_cleanup_backend: CommandDomainCleanupBackend,
}

impl SensitiveOutputRejectionNativeProofRejoinV1 {
    /// Joins one exact terminal v2 receipt to independently reopened native
    /// cleanup evidence.
    ///
    /// `None` is an explicit missing-evidence state, never permission to infer
    /// the proof from its digest. `expected_cleanup_backend` and
    /// `expected_binding` must come from cleanup admission reconstructed
    /// independently of both the terminal journal and the reopened proof.
    ///
    /// # Errors
    ///
    /// Returns an error when the native proof is missing, either input is
    /// invalid, or the digest, backend, request, session, or effect is crossed.
    pub fn try_new(
        receipt: SensitiveOutputRejectionJournalReceiptV2,
        reopened_native_cleanup_proof: Option<ValidatedCommandDomainCleanupProof>,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<Self, CommandOutputStoreError> {
        receipt.validate()?;
        if expected_binding.runner_session_id() != receipt.runner_session_id
            || expected_binding.command_effect_id() != receipt.effect_id
            || expected_binding.command_request_digest() != &receipt.request_digest
        {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output native-proof authority crossed the terminal journal".into(),
            ));
        }
        let native_cleanup_proof = reopened_native_cleanup_proof.ok_or_else(|| {
            CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(receipt.capture_id.clone()),
                source: Box::new(receipt.acquired.source.clone()),
                expected_reference: None,
                reason: "terminal sensitive-output journal retains only a native cleanup-proof digest; exact proof bytes must be reopened independently"
                    .into(),
            }
        })?;
        let expected_digest = Digest::parse(receipt.command_domain_cleanup_proof_id.clone())
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        native_cleanup_proof
            .validate_expected(&expected_digest, expected_cleanup_backend, expected_binding)
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if native_cleanup_proof.surviving_processes() != 0 {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output native cleanup proof retains survivors".into(),
            ));
        }
        Ok(Self {
            receipt,
            native_cleanup_proof,
            expected_cleanup_backend,
        })
    }

    /// Returns the exact terminal v2 rejection receipt.
    #[must_use]
    pub const fn receipt(&self) -> &SensitiveOutputRejectionJournalReceiptV2 {
        &self.receipt
    }

    /// Returns the independently reopened and fully revalidated native proof.
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }

    /// Returns the independently selected native accounting backend.
    #[must_use]
    pub const fn expected_cleanup_backend(&self) -> CommandDomainCleanupBackend {
        self.expected_cleanup_backend
    }

    /// Consumes the join into its three exact validated inputs.
    pub fn into_parts(
        self,
    ) -> (
        SensitiveOutputRejectionJournalReceiptV2,
        ValidatedCommandDomainCleanupProof,
        CommandDomainCleanupBackend,
    ) {
        (
            self.receipt,
            self.native_cleanup_proof,
            self.expected_cleanup_backend,
        )
    }
}

/// Read-only exact join of one policy-bound v2 journal, its terminal v1
/// custody, and independently reopened native zero-survivor evidence.
///
/// This value grants no transition, cleanup, publication, replay,
/// verification, or completion authority. Its private fields can be
/// constructed only by a fresh descriptor-relative readback through
/// [`CapabilityCommandOutputStore::reopen_sensitive_output_unknown_terminal_join_v2`].
#[must_use = "a policy-bound Unknown terminal join must be consumed as read-only recovery evidence"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputUnknownTerminalJoinV2 {
    v2_recovery: SensitiveOutputJournalRecoveryV2,
    v1_terminal: CommandOutputCaptureRecovery,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputUnknownTerminalJoinV2 {
    /// Exact current v2 journal head joined to v1 terminal custody.
    #[must_use]
    pub const fn v2_head(&self) -> &SensitiveOutputJournalHeadV1 {
        self.v2_recovery.head()
    }

    /// Complete exact current v2 recovery joined to v1 terminal custody.
    #[must_use]
    pub const fn v2_recovery(&self) -> &SensitiveOutputJournalRecoveryV2 {
        &self.v2_recovery
    }

    /// Exact current v2 stage; this carries no resume authority.
    #[must_use]
    pub const fn v2_stage(&self) -> &SensitiveOutputJournalStageV2 {
        self.v2_recovery.stage()
    }

    /// Exact read-only v1 terminal recovery.
    #[must_use]
    pub const fn v1_terminal(&self) -> &CommandOutputCaptureRecovery {
        &self.v1_terminal
    }

    /// Independently selected native cleanup backend.
    #[must_use]
    pub const fn expected_cleanup_backend(&self) -> CommandDomainCleanupBackend {
        self.expected_cleanup_backend
    }

    /// Independently reopened and fully revalidated native cleanup proof.
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the terminal validator visibly joins every independently reopened authority"
)]
fn validate_sensitive_output_unknown_clean_terminal_join(
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    v2_recovery: &SensitiveOutputJournalRecoveryV2,
    v1_terminal: &CommandOutputCaptureRecovery,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    expected_binding: &CommandDomainCleanupBinding,
) -> Result<(), CommandOutputStoreError> {
    if v1_terminal.state() != CommandOutputCaptureJournalStateV1::TerminalPrepared {
        return Ok(());
    }
    let payload = v1_terminal.terminal().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "policy-bound Unknown clean terminal lost its canonical payload".into(),
        )
    })?;
    if payload.schema != crate::wire::COMMAND_TERMINAL_CAPTURE_SCHEMA {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown clean terminal uses a non-command schema".into(),
        ));
    }
    let terminal_prepared_store_head =
        v1_terminal.terminal_prepared_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "policy-bound Unknown clean terminal lost its v1 terminal head".into(),
            )
        })?;
    let terminal = crate::wire::decode_command_terminal_record_bytes(
        &payload.canonical_bytes,
        terminal_prepared_store_head,
    )
    .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
    let output_anchor = crate::wire::WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
    terminal
        .validate_for_output_capture(&output_anchor)
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
    let output_capture = &terminal.output_capture;
    let finished_store_head = v1_terminal.finished_store_head().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "policy-bound Unknown clean terminal lost its Finished head".into(),
        )
    })?;
    let published_store_head = v1_terminal.published_store_head().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "policy-bound Unknown clean terminal lost its Published head".into(),
        )
    })?;
    let output_artifacts = v1_terminal.expected_reference().ok_or_else(|| {
        CommandOutputStoreError::Manifest(
            "policy-bound Unknown clean terminal lost its artifact reference".into(),
        )
    })?;
    if output_capture.capture_id != intent.capture_id
        || output_capture.acquired_anchor_digest != acquired.acquired_anchor_digest
        || &output_capture.finished_store_head != finished_store_head
        || &output_capture.published_store_head != published_store_head
        || &output_capture.terminal_prepared_store_head != terminal_prepared_store_head
        || &output_capture.expected_output_artifacts != output_artifacts
        || output_capture.terminal_record_digest != payload.canonical_bytes_digest
        || &terminal.output_artifacts != output_artifacts
        || terminal.backend.command_domain_backend != expected_cleanup_backend
    {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown clean terminal crossed acquisition, heads, artifacts, bytes, or backend"
                .into(),
        ));
    }
    match v2_recovery.stage() {
        SensitiveOutputJournalStageV2::TerminalPrepared {
            terminal_prepared_store_head: v2_terminal_head,
            terminal_record_digest,
            termination,
            ..
        } => {
            if v2_terminal_head != terminal_prepared_store_head
                || terminal_record_digest != &payload.canonical_bytes_digest
                || termination != &terminal.termination
            {
                return Err(CommandOutputStoreError::Reference(
                    "policy-bound Unknown clean terminal crossed its v2 terminal record".into(),
                ));
            }
        }
        SensitiveOutputJournalStageV2::Published { .. } => {
            // Exact crash split: v1 terminal bytes are durable while v2
            // remains at its already-validated Published predecessor.
        }
        _ => {
            return Err(CommandOutputStoreError::Reference(
                "policy-bound Unknown v1 terminal is incompatible with its v2 stage".into(),
            ));
        }
    }
    let embedded_cleanup = terminal
        .cleanup_proof
        .readback(expected_cleanup_backend, expected_binding)
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
    // Terminal and later cleanup observations can have different timestamps
    // and digests. Each must independently prove exact identity and zero survivors.
    if embedded_cleanup.surviving_processes() != 0 {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown clean terminal embedded cleanup proof retains survivors".into(),
        ));
    }
    Ok(())
}

/// Derived, secret-free proof that a v2 command never crossed its durable
/// launch boundary and that v1 output custody is exactly cleaned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputPreLaunchAbortedV2 {
    intent: CommandOutputCaptureIntentV1,
    v2_prefix: Option<SensitiveOutputJournalRecoveryV2>,
    v1_cleaned: CommandOutputCaptureRecovery,
}

impl SensitiveOutputPreLaunchAbortedV2 {
    /// Zero for a physically absent v2 journal, otherwise the exact durable
    /// prefix generation. A valid pre-launch disposition is never above three.
    #[must_use]
    pub fn v2_generation(&self) -> u64 {
        self.v2_prefix
            .as_ref()
            .map_or(0, |prefix| prefix.head().generation)
    }

    /// Exact core capture identity.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        &self.intent.capture_id
    }

    /// Validated final v1 `Cleaned` head.
    ///
    /// # Panics
    ///
    /// Panics only if this private-field disposition somehow bypassed its
    /// constructor/readback invariant and no longer contains a cleaned head.
    #[must_use]
    pub fn v1_cleaned_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        self.v1_cleaned
            .cleaned_store_head()
            .expect("validated pre-launch disposition always has a Cleaned head")
    }

    /// Revalidates all in-memory joins. Construction additionally performs a
    /// fresh descriptor-relative filesystem readback of both journals.
    ///
    /// # Errors
    ///
    /// Returns an error when the intent, v1 cleanup, or optional v2 prefix no
    /// longer form the exact pre-launch disposition.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if self.v1_cleaned.capture_id().as_str() != self.intent.capture_id
            || self.v1_cleaned.source() != &self.intent.source
            || self.v1_cleaned.authenticated_maximum_bytes()
                != self.intent.max_aggregate_output_bytes
            || self.v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || self.v1_cleaned.expected_reference().is_some()
            || self.v1_cleaned.launch_intended_store_head().is_some()
            || self.v1_cleaned.cleaned_store_head().is_none()
        {
            return Err(CommandOutputStoreError::Manifest(
                "pre-launch disposition is not exact non-launched v1 Cleaned custody".into(),
            ));
        }
        let Some(prefix) = &self.v2_prefix else {
            return Ok(());
        };
        prefix.validate()?;
        prefix.validate_intent_binding(&self.intent)?;
        if prefix.head().generation > 3 || prefix.launch_intended_store_head().is_some() {
            return Err(CommandOutputStoreError::Manifest(
                "pre-launch disposition crossed the v2 LaunchIntended boundary".into(),
            ));
        }
        match prefix.stage() {
            SensitiveOutputJournalStageV2::IntentBound => {
                if prefix.acquired().is_some() {
                    return Err(CommandOutputStoreError::Manifest(
                        "generation-one pre-launch prefix unexpectedly has acquisition".into(),
                    ));
                }
            }
            SensitiveOutputJournalStageV2::AcquiredBound => {
                if prefix.acquired() != self.v1_cleaned.acquired() {
                    return Err(CommandOutputStoreError::Manifest(
                        "generation-two pre-launch prefix crossed v1 acquisition".into(),
                    ));
                }
            }
            SensitiveOutputJournalStageV2::WriterAttached {
                writer_attached_store_head,
            } => {
                if prefix.acquired() != self.v1_cleaned.acquired()
                    || Some(writer_attached_store_head)
                        != self.v1_cleaned.writer_attached_store_head()
                {
                    return Err(CommandOutputStoreError::Manifest(
                        "generation-three pre-launch prefix crossed v1 writer custody".into(),
                    ));
                }
            }
            _ => {
                return Err(CommandOutputStoreError::Manifest(
                    "pre-launch disposition has an illegal v2 stage".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Fresh core-claim-fenced resolution of one exact prelaunch v2 disposition.
///
/// The diagnostic disposition proves the immutable v2 prefix and final v1
/// state. The separate recovery preserves the physical reconciliation context
/// created under the supplied core claim; callers must use that recovery for
/// core evidence rather than reopening the terminal capture.
#[must_use = "prelaunch resolution carries the only fresh claim-fenced physical recovery"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputPreLaunchAbortResolutionV2 {
    disposition: SensitiveOutputPreLaunchAbortedV2,
    fenced_v1_recovery: CommandOutputCaptureRecovery,
    reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
}

impl SensitiveOutputPreLaunchAbortResolutionV2 {
    /// Immutable diagnostic readback of the unchanged v2 prefix and cleaned v1 state.
    #[must_use]
    pub const fn disposition(&self) -> &SensitiveOutputPreLaunchAbortedV2 {
        &self.disposition
    }

    /// Exact v1 recovery retaining the fresh physical-reconciliation context.
    ///
    /// Reopening the capture produces diagnostic state only and cannot replace
    /// this claim-fenced value when constructing core evidence.
    #[must_use]
    pub const fn fenced_v1_recovery(&self) -> &CommandOutputCaptureRecovery {
        &self.fenced_v1_recovery
    }

    /// Exact core claim durably admitted by the returned physical recovery.
    #[must_use]
    pub const fn reconciliation_claim(&self) -> &CommandOutputCaptureReconciliationClaimV1 {
        &self.reconciliation_claim
    }

    /// Zero for a physically absent v2 journal, otherwise generation one to three.
    #[must_use]
    pub fn v2_generation(&self) -> u64 {
        self.disposition.v2_generation()
    }

    /// Exact core capture identity.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        self.disposition.capture_id()
    }

    /// Validated final v1 `Cleaned` head shared by both result halves.
    #[must_use]
    pub fn v1_cleaned_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        self.disposition.v1_cleaned_store_head()
    }

    /// Revalidates the immutable disposition and exact fenced-recovery join.
    ///
    /// # Errors
    ///
    /// Returns an error when either half is invalid, their durable capture
    /// fields differ, or the recovery no longer carries the exact supplied
    /// reconciliation claim.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.disposition.validate()?;
        self.reconciliation_claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        let diagnostic = &self.disposition.v1_cleaned;
        if self.reconciliation_claim.capture_id != self.disposition.intent.capture_id
            || self.fenced_v1_recovery.physical_reconciliation_claim()
                != Some(&self.reconciliation_claim)
            || self.fenced_v1_recovery.capture_id() != diagnostic.capture_id()
            || self.fenced_v1_recovery.source() != diagnostic.source()
            || self.fenced_v1_recovery.authenticated_maximum_bytes()
                != diagnostic.authenticated_maximum_bytes()
            || self.fenced_v1_recovery.state() != diagnostic.state()
            || self.fenced_v1_recovery.store_head() != diagnostic.store_head()
            || self.fenced_v1_recovery.acquired() != diagnostic.acquired()
            || self.fenced_v1_recovery.launch_intended_store_head()
                != diagnostic.launch_intended_store_head()
            || self.fenced_v1_recovery.expected_reference() != diagnostic.expected_reference()
            || self.fenced_v1_recovery.cleaned_store_head() != diagnostic.cleaned_store_head()
        {
            return Err(CommandOutputStoreError::Manifest(
                "prelaunch resolution crossed its diagnostic disposition, fenced recovery, or core claim"
                    .into(),
            ));
        }
        Ok(())
    }
}

fn validate_prelaunch_core_acquisition_v2(
    prefix: Option<&SensitiveOutputJournalRecoveryV2>,
    core_acquired: Option<&CommandOutputCaptureAcquiredV1>,
) -> Result<(), CommandOutputStoreError> {
    match prefix.map(SensitiveOutputJournalRecoveryV2::stage) {
        None | Some(SensitiveOutputJournalStageV2::IntentBound) => {
            if core_acquired.is_some() {
                return Err(CommandOutputStoreError::Reference(
                    "generation-zero/one prelaunch state cannot bind a core acquisition absent from the exact v2 prefix"
                        .into(),
                ));
            }
        }
        Some(SensitiveOutputJournalStageV2::AcquiredBound) => {
            let physical_acquired = prefix
                .and_then(SensitiveOutputJournalRecoveryV2::acquired)
                .ok_or_else(|| {
                    CommandOutputStoreError::Manifest(
                        "generation-two prelaunch prefix lost physical acquisition".into(),
                    )
                })?;
            if core_acquired.is_some_and(|acquired| acquired != physical_acquired) {
                return Err(CommandOutputStoreError::Reference(
                    "generation-two prelaunch prefix crossed the exact core acquisition".into(),
                ));
            }
        }
        Some(SensitiveOutputJournalStageV2::WriterAttached { .. }) => {
            let physical_acquired = prefix
                .and_then(SensitiveOutputJournalRecoveryV2::acquired)
                .ok_or_else(|| {
                    CommandOutputStoreError::Manifest(
                        "generation-three prelaunch prefix lost physical acquisition".into(),
                    )
                })?;
            if core_acquired != Some(physical_acquired) {
                return Err(CommandOutputStoreError::Reference(
                    "generation-three writer attachment requires the exact durable core acquisition"
                        .into(),
                ));
            }
        }
        _ => {
            return Err(CommandOutputStoreError::Manifest(
                "pre-launch cleanup received an illegal v2 prefix".into(),
            ));
        }
    }
    Ok(())
}

/// Exact zero-first cleanup result for a policy-bound command whose durable
/// v2 journal stopped at `LaunchIntended` before either terminal branch was
/// classified.
///
/// This value deliberately carries no clean, rejected, or replay authority.
/// The command remains semantically `Unknown`; the result proves only that an
/// independently validated native command-domain cleanup preceded constant-zero
/// output neutralization and exact v1 object cleanup under the supplied fence.
#[must_use = "generation-four quarantine remains Unknown and must be joined to core reconciliation"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputUnknownQuarantineV2 {
    v2_launch_intended: SensitiveOutputJournalRecoveryV2,
    v1_cleaned: CommandOutputCaptureRecovery,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputUnknownQuarantineV2 {
    /// Exact unchanged generation-four v2 readback.
    #[must_use]
    pub const fn v2_launch_intended(&self) -> &SensitiveOutputJournalRecoveryV2 {
        &self.v2_launch_intended
    }

    /// Exact claim-fenced v1 `Cleaned` recovery after zero-first quarantine.
    #[must_use]
    pub const fn v1_cleaned(&self) -> &CommandOutputCaptureRecovery {
        &self.v1_cleaned
    }

    /// Digest of the independently validated native zero-survivor proof that
    /// authorized quarantine cleanup. This digest does not classify output.
    #[must_use]
    pub const fn command_domain_cleanup_proof_id(&self) -> &Digest {
        self.native_cleanup_proof.os_evidence_digest()
    }

    /// Independently selected native accounting backend required by core
    /// cleanup admission.
    #[must_use]
    pub const fn expected_cleanup_backend(&self) -> CommandDomainCleanupBackend {
        self.expected_cleanup_backend
    }

    /// Complete canonical zero-survivor proof revalidated by construction and
    /// by [`Self::validate`].
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }

    /// Revalidates the complete generation-four/v1-zero-cleanup/native-proof
    /// join without projecting it into either terminal branch.
    ///
    /// # Errors
    ///
    /// Returns an error when any v2 launch identity, v1 custody anchor, zero-
    /// survivor proof, expected backend, request binding, or final cleanup
    /// state differs.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.v2_launch_intended.validate()?;
        let SensitiveOutputJournalStageV2::LaunchIntended {
            launch_intended_store_head,
            ..
        } = self.v2_launch_intended.stage()
        else {
            return Err(CommandOutputStoreError::Manifest(
                "unclassified quarantine does not retain exact v2 LaunchIntended state".into(),
            ));
        };
        let acquired = self.v2_launch_intended.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "unclassified quarantine lost its acquired capture anchor".into(),
            )
        })?;
        if self.v2_launch_intended.head().generation != 4
            || self.v1_cleaned.capture_id().as_str() != self.v2_launch_intended.capture_id()
            || self.v1_cleaned.source() != &acquired.source
            || self.v1_cleaned.authenticated_maximum_bytes() != acquired.max_aggregate_output_bytes
            || self.v1_cleaned.acquired() != Some(acquired)
            || self.v1_cleaned.launch_intended_store_head() != Some(launch_intended_store_head)
            || self.v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || self.v1_cleaned.cleaned_store_head().is_none()
            || self.v1_cleaned.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::Manifest(
                "unclassified quarantine crossed v2 launch, acquisition, source, or exact v1 Cleaned custody"
                    .into(),
            ));
        }
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        self.native_cleanup_proof
            .validate_expected(
                self.native_cleanup_proof.os_evidence_digest(),
                self.expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        Ok(())
    }
}

/// Exact zero-first cleanup result for the split launch boundary where the v1
/// `LaunchIntended` record is durable but the v2 journal remains at
/// `WriterAttached`.
///
/// This state is launch-bearing `Unknown`, never prelaunch authority. The
/// immutable v2 prefix and independently read v1 launch head remain distinct
/// so recovery cannot invent the missing v2 generation-four record. Like the
/// ordinary generation-four quarantine, this value carries neither output
/// classification nor replay authority.
#[must_use = "split-launch quarantine remains Unknown and must be joined to core reconciliation"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputSplitLaunchUnknownQuarantineV2 {
    v2_writer_attached: SensitiveOutputJournalRecoveryV2,
    v1_launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    v1_cleaned: CommandOutputCaptureRecovery,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputSplitLaunchUnknownQuarantineV2 {
    /// Exact unchanged generation-three v2 readback.
    #[must_use]
    pub const fn v2_writer_attached(&self) -> &SensitiveOutputJournalRecoveryV2 {
        &self.v2_writer_attached
    }

    /// Exact immutable v1 launch head that makes this prefix launch-bearing.
    #[must_use]
    pub const fn v1_launch_intended_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.v1_launch_intended_store_head
    }

    /// Exact claim-fenced v1 `Cleaned` recovery after zero-first quarantine.
    #[must_use]
    pub const fn v1_cleaned(&self) -> &CommandOutputCaptureRecovery {
        &self.v1_cleaned
    }

    /// Digest of the independently validated native zero-survivor proof that
    /// authorized quarantine cleanup. This digest does not classify output.
    #[must_use]
    pub const fn command_domain_cleanup_proof_id(&self) -> &Digest {
        self.native_cleanup_proof.os_evidence_digest()
    }

    /// Independently selected native accounting backend required by core
    /// cleanup admission.
    #[must_use]
    pub const fn expected_cleanup_backend(&self) -> CommandDomainCleanupBackend {
        self.expected_cleanup_backend
    }

    /// Complete canonical zero-survivor proof revalidated by construction and
    /// by [`Self::validate`].
    pub const fn native_cleanup_proof(&self) -> &ValidatedCommandDomainCleanupProof {
        &self.native_cleanup_proof
    }

    /// Revalidates the generation-three/v1-launch/v1-zero-cleanup/native-proof
    /// join without filling the missing v2 record or granting replay.
    ///
    /// # Errors
    ///
    /// Returns an error when the v2 writer prefix, v1 launch head, acquisition,
    /// source, writer custody, native backend, request binding, or final cleanup
    /// state differs.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.v2_writer_attached.validate()?;
        let SensitiveOutputJournalStageV2::WriterAttached {
            writer_attached_store_head,
        } = self.v2_writer_attached.stage()
        else {
            return Err(CommandOutputStoreError::Manifest(
                "split-launch quarantine does not retain exact v2 WriterAttached state".into(),
            ));
        };
        let acquired = self.v2_writer_attached.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "split-launch quarantine lost its acquired capture anchor".into(),
            )
        })?;
        if self.v2_writer_attached.head().generation != 3
            || self.v1_launch_intended_store_head.generation
                != writer_attached_store_head
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| {
                        CommandOutputStoreError::Manifest(
                            "split-launch v1 store generation overflowed".into(),
                        )
                    })?
            || self.v1_cleaned.capture_id().as_str() != self.v2_writer_attached.capture_id()
            || self.v1_cleaned.source() != &acquired.source
            || self.v1_cleaned.authenticated_maximum_bytes() != acquired.max_aggregate_output_bytes
            || self.v1_cleaned.acquired() != Some(acquired)
            || self.v1_cleaned.writer_attached_store_head() != Some(writer_attached_store_head)
            || self.v1_cleaned.launch_intended_store_head()
                != Some(&self.v1_launch_intended_store_head)
            || self.v1_cleaned.launch_intended().is_none()
            || self.v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || self.v1_cleaned.cleaned_store_head().is_none()
            || self.v1_cleaned.expected_reference().is_some()
            || self.v1_cleaned.finished_store_head().is_some()
            || self.v1_cleaned.published_store_head().is_some()
            || self.v1_cleaned.terminal_prepared_store_head().is_some()
        {
            return Err(CommandOutputStoreError::Manifest(
                "split-launch quarantine crossed v2 writer custody, v1 launch, acquisition, source, or exact v1 Cleaned custody"
                    .into(),
            ));
        }
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        self.native_cleanup_proof
            .validate_expected(
                self.native_cleanup_proof.os_evidence_digest(),
                self.expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        Ok(())
    }
}

/// Exact observation-backed recovery of a partial clean branch through
/// immutable v1/v2 publication.
///
/// This is not terminal command success: generation eight and the canonical
/// terminal response remain a later coordinator responsibility. The value
/// proves only that the exact clean observation, fresh native zero-survivor
/// proof, exact launch authority, descriptor-relative stream readback, and
/// claim-fenced publication all joined without crossing identities.
#[must_use = "clean partial-terminal recovery must be consumed by terminal reconstruction"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputCleanPublicationRecoveryV1 {
    observation: crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1,
    artifact_reference: CommandOutputArtifactSetReferenceV1,
    launch_binding: crate::wire::ValidatedCommandCaptureLaunchBindingV12,
    v2_published: SensitiveOutputJournalRecoveryV2,
    fenced_v1_recovery: CommandOutputCaptureRecovery,
    reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputCleanPublicationRecoveryV1 {
    /// Exact immutable terminal observation that authorized continuation.
    pub const fn observation(
        &self,
    ) -> &crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1 {
        &self.observation
    }

    /// Exact complete-stream reference revalidated and published by recovery.
    #[must_use]
    pub const fn artifact_reference(&self) -> &CommandOutputArtifactSetReferenceV1 {
        &self.artifact_reference
    }

    /// Exact fully validated V12 launch authority retained so later
    /// validation never relies on construction-time checking alone.
    #[must_use]
    pub const fn launch_binding(&self) -> &crate::wire::ValidatedCommandCaptureLaunchBindingV12 {
        &self.launch_binding
    }

    /// Exact generation-seven clean v2 readback.
    #[must_use]
    pub const fn v2_published(&self) -> &SensitiveOutputJournalRecoveryV2 {
        &self.v2_published
    }

    /// Claim-fenced v1 publication/readback carrying physical reconciliation.
    #[must_use]
    pub const fn fenced_v1_recovery(&self) -> &CommandOutputCaptureRecovery {
        &self.fenced_v1_recovery
    }

    /// Core-issued claim durably admitted by physical recovery.
    #[must_use]
    pub const fn reconciliation_claim(&self) -> &CommandOutputCaptureReconciliationClaimV1 {
        &self.reconciliation_claim
    }

    /// Revalidates the complete observation/v2/v1/native-proof join.
    ///
    /// # Errors
    ///
    /// Returns an error when any capture, request, branch, proof, reference,
    /// lifecycle head, or core fence differs.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.v2_published.validate()?;
        let SensitiveOutputJournalStageV2::Published {
            published_store_head,
            ..
        } = self.v2_published.stage()
        else {
            return Err(CommandOutputStoreError::Manifest(
                "clean partial recovery is not exact v2 Published state".into(),
            ));
        };
        let acquired = self.v2_published.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean partial recovery lost its acquired anchor".into(),
            )
        })?;
        let binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        self.observation
            .validate_expected_clean(
                self.v2_published.capture_id(),
                self.expected_cleanup_backend,
                &binding,
                &self.native_cleanup_proof,
                &self.launch_binding,
                acquired,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        let response = self.observation.clean_response().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean partial recovery observation lost its response".into(),
            )
        })?;
        let SensitiveOutputJournalStageV2::Published {
            published_store_head: v2_published_head,
            ..
        } = self.v2_published.stage()
        else {
            unreachable!("stage was matched above")
        };
        if self.v2_published.head().generation != 7
            || response.output_artifacts() != &self.artifact_reference
            || self.artifact_reference.source != acquired.source
            || self.launch_binding.launch_intended_store_head()
                != self
                    .v2_published
                    .launch_intended_store_head()
                    .ok_or_else(|| {
                        CommandOutputStoreError::Manifest(
                            "clean partial recovery lost its launch head".into(),
                        )
                    })?
            || self.launch_binding.command_domain_binding() != &binding
            || self.launch_binding.request().detector_policy()
                != self.v2_published.detector_policy()
            || self.launch_binding.backend().command_domain_backend != self.expected_cleanup_backend
            || self.fenced_v1_recovery.physical_reconciliation_claim()
                != Some(&self.reconciliation_claim)
            || self.reconciliation_claim.capture_id != self.v2_published.capture_id()
            || self.fenced_v1_recovery.capture_id().as_str() != self.v2_published.capture_id()
            || self.fenced_v1_recovery.acquired() != Some(acquired)
            || self.fenced_v1_recovery.expected_reference() != Some(&self.artifact_reference)
            || self.fenced_v1_recovery.published_store_head() != Some(v2_published_head)
            || !matches!(
                self.fenced_v1_recovery.state(),
                CommandOutputCaptureJournalStateV1::Published
                    | CommandOutputCaptureJournalStateV1::TerminalPrepared
            )
            || published_store_head != v2_published_head
        {
            return Err(CommandOutputStoreError::Manifest(
                "clean partial recovery crossed its observation, v2 publication, v1 custody, or core fence"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Claim-fenced exact v1 terminal preparation for a validated partial clean
/// publication.
///
/// This value carries evidence only. It deliberately exposes no generic
/// capture recovery handle or mutation capability; callers receive only the
/// exact terminal head and record digest needed to append the corresponding
/// clean v2 terminal record.
#[must_use = "clean terminal preparation must be joined to the v2 terminal record"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputCleanTerminalPreparationV1 {
    clean_publication: SensitiveOutputCleanPublicationRecoveryV1,
    v2_published: SensitiveOutputJournalRecoveryV2,
    terminal: CommandOutputCaptureCanonicalPayloadV1,
    terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
    fenced_v1_recovery: CommandOutputCaptureRecovery,
    reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    expected_published_head: CommandOutputCaptureStoreHeadV1,
}

#[cfg(all(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum SensitiveOutputCleanTerminalPreparationTestCut {
    TempTorn,
    TempValid,
    TempSynced,
    Final,
}

impl SensitiveOutputCleanTerminalPreparationV1 {
    /// Exact capture identity whose clean terminal was prepared.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        self.clean_publication.v2_published().capture_id()
    }

    /// Exact v1 `TerminalPrepared` head for the subsequent v2 append.
    #[must_use]
    pub const fn terminal_prepared_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.terminal_prepared_store_head
    }

    /// SHA-256 digest of the exact retained canonical terminal payload.
    ///
    /// This is the `terminal_record_digest` required by the clean v2 journal
    /// and wire response. The distinct v1 journal-record digest remains
    /// available only through [`Self::terminal_prepared_store_head`].
    #[must_use]
    pub const fn terminal_record_digest(&self) -> &Digest {
        &self.terminal.canonical_bytes_digest
    }

    /// Versioned schema of the exact retained terminal bytes.
    #[must_use]
    pub fn terminal_schema(&self) -> &str {
        &self.terminal.schema
    }

    /// Exact recovery claim durably admitted for terminal preparation.
    #[must_use]
    pub const fn reconciliation_claim(&self) -> &CommandOutputCaptureReconciliationClaimV1 {
        &self.reconciliation_claim
    }

    /// Builds the canonical core physical-reconciliation receipt from the
    /// retained claim-fenced terminal readback without exposing the generic
    /// recovery handle.
    ///
    /// # Errors
    ///
    /// Returns an error if this preparation is invalid, the supplied intent or
    /// claim differs from its exact durable authority, or the timestamp cannot
    /// form valid core evidence.
    pub fn physical_reconciliation_evidence(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        reconciled_at_unix_ms: u64,
    ) -> Result<
        grok_build_core::CommandOutputCapturePhysicalReconciliationV1,
        CommandOutputStoreError,
    > {
        self.validate()?;
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim != &self.reconciliation_claim
            || intent.capture_id != self.capture_id()
            || &intent.source != self.fenced_v1_recovery.source()
        {
            return Err(CommandOutputStoreError::Reference(
                "clean terminal physical evidence crossed intent or claim".into(),
            ));
        }
        self.fenced_v1_recovery.physical_reconciliation_evidence(
            intent,
            claim,
            reconciled_at_unix_ms,
        )
    }

    /// Revalidates the clean publication, unchanged v2 prefix, claim lineage,
    /// terminal bytes, and exact claim-fenced v1 readback.
    ///
    /// # Errors
    ///
    /// Returns an error for any crossed publication, claim, capture, artifact,
    /// lifecycle head, terminal payload, or v2 branch.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.clean_publication.validate()?;
        self.v2_published.validate()?;
        self.reconciliation_claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        let publication_claim = self.clean_publication.reconciliation_claim();
        let claim_is_same = self.reconciliation_claim == *publication_claim;
        let claim_is_higher_successor = self.reconciliation_claim.claim_epoch
            > publication_claim.claim_epoch
            && self.reconciliation_claim.previous_claim_id.as_deref()
                == Some(publication_claim.claim_id.as_str());
        let SensitiveOutputJournalStageV2::Published {
            published_store_head,
            ..
        } = self.v2_published.stage()
        else {
            return Err(CommandOutputStoreError::Manifest(
                "clean terminal preparation lost exact v2 Published state".into(),
            ));
        };
        let acquired = self.v2_published.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean terminal preparation lost its acquired anchor".into(),
            )
        })?;
        if (!claim_is_same && !claim_is_higher_successor)
            || self.v2_published != *self.clean_publication.v2_published()
            || self.expected_published_head != *published_store_head
            || self.fenced_v1_recovery.physical_reconciliation_claim()
                != Some(&self.reconciliation_claim)
            || self.fenced_v1_recovery.capture_id().as_str() != self.capture_id()
            || self.fenced_v1_recovery.acquired() != Some(acquired)
            || self.fenced_v1_recovery.expected_reference()
                != Some(self.clean_publication.artifact_reference())
            || self.fenced_v1_recovery.published_store_head() != Some(&self.expected_published_head)
            || self.fenced_v1_recovery.state()
                != CommandOutputCaptureJournalStateV1::TerminalPrepared
            || self.fenced_v1_recovery.terminal() != Some(&self.terminal)
            || self.fenced_v1_recovery.terminal_prepared_store_head()
                != Some(&self.terminal_prepared_store_head)
            || self.terminal_prepared_store_head.generation
                != self
                    .expected_published_head
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| {
                        CommandOutputStoreError::Manifest(
                            "clean terminal preparation head generation overflowed".into(),
                        )
                    })?
        {
            return Err(CommandOutputStoreError::Manifest(
                "clean terminal preparation crossed publication, terminal, v2 state, or recovery fence"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Exact observation-backed closure of a partial rejection branch.
#[must_use = "rejection recovery must be consumed as output abandonment, never verification"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputRejectionRecoveryV1 {
    observation: crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1,
    receipt: SensitiveOutputRejectionJournalReceiptV2,
    fenced_v1_recovery: CommandOutputCaptureRecovery,
    reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputRejectionRecoveryV1 {
    /// Exact immutable rejection observation.
    pub const fn observation(
        &self,
    ) -> &crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1 {
        &self.observation
    }

    /// Exact terminal generation-eight rejection receipt.
    #[must_use]
    pub const fn receipt(&self) -> &SensitiveOutputRejectionJournalReceiptV2 {
        &self.receipt
    }

    /// Claim-fenced exact v1 `Cleaned` recovery.
    #[must_use]
    pub const fn fenced_v1_recovery(&self) -> &CommandOutputCaptureRecovery {
        &self.fenced_v1_recovery
    }

    /// Exact core-issued reconciliation claim.
    #[must_use]
    pub const fn reconciliation_claim(&self) -> &CommandOutputCaptureReconciliationClaimV1 {
        &self.reconciliation_claim
    }

    /// Revalidates the rejection observation, native proof, terminal receipt,
    /// v1 cleanup, and durable core fence.
    ///
    /// # Errors
    ///
    /// Returns an error for any crossed or missing authority.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.receipt.validate()?;
        let binding = CommandDomainCleanupBinding::try_new(
            self.receipt.runner_session_id.clone(),
            self.receipt.effect_id.clone(),
            self.receipt.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        self.observation
            .validate_expected(
                &self.receipt.capture_id,
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection,
                self.expected_cleanup_backend,
                &binding,
                &self.native_cleanup_proof,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if self.observation.termination() != self.receipt.termination
            || self.reconciliation_claim.capture_id != self.receipt.capture_id
            || self.fenced_v1_recovery.physical_reconciliation_claim()
                != Some(&self.reconciliation_claim)
            || self.fenced_v1_recovery.capture_id().as_str() != self.receipt.capture_id
            || self.fenced_v1_recovery.acquired() != Some(&self.receipt.acquired)
            || self.fenced_v1_recovery.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || self.fenced_v1_recovery.cleaned_store_head()
                != Some(&self.receipt.v1_cleaned_store_head)
        {
            return Err(CommandOutputStoreError::Manifest(
                "rejection recovery crossed its observation, terminal receipt, v1 cleanup, or core fence"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Stable schema version for partial-terminal `Unknown` dispositions.
pub const SENSITIVE_OUTPUT_PARTIAL_TERMINAL_UNKNOWN_FORMAT_VERSION_V1: u32 = 1;

/// Why exact generation-five-through-seven continuation was unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveOutputPartialTerminalUnknownReasonV1 {
    /// No immutable terminal-observation sidecar was present.
    MissingObservation,
    /// A present sidecar could not be safely decoded or joined to the branch.
    UnusableObservation,
    /// A decoded sidecar lacked exact proof/launch backing.
    UnbackedObservation,
}

/// Physical custody retained by a terminal `Unknown` disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveOutputPartialTerminalUnknownCustodyV1 {
    /// Mutable staging was zeroed and exact v1 cleanup completed.
    ZeroedAndCleaned,
    /// An already-immutable clean artifact was retained without success.
    ImmutableArtifactRetained,
}

/// Versioned terminal `Unknown` result for a known partial branch that cannot
/// be backed by its exact terminal observation.
///
/// The zeroed variant deliberately exposes no pre-zero length, digest,
/// reference, or stream summary. The immutable-retained variant exposes the
/// already-published reference only through an explicitly named getter so
/// callers cannot mistake retention for verification or completion.
#[must_use = "partial-terminal Unknown grants no success or replay authority"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveOutputPartialTerminalUnknownV1 {
    format_version: u32,
    reason: SensitiveOutputPartialTerminalUnknownReasonV1,
    custody: SensitiveOutputPartialTerminalUnknownCustodyV1,
    v2_partial: SensitiveOutputJournalRecoveryV2,
    fenced_v1_recovery: CommandOutputCaptureRecovery,
    reconciliation_claim: CommandOutputCaptureReconciliationClaimV1,
    expected_cleanup_backend: CommandDomainCleanupBackend,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
}

impl SensitiveOutputPartialTerminalUnknownV1 {
    /// Fixed version of this closed disposition schema.
    #[must_use]
    pub const fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Typed reason exact continuation was unavailable.
    #[must_use]
    pub const fn reason(&self) -> SensitiveOutputPartialTerminalUnknownReasonV1 {
        self.reason
    }

    /// Whether mutable staging was removed or an immutable clean artifact remains.
    #[must_use]
    pub const fn custody(&self) -> SensitiveOutputPartialTerminalUnknownCustodyV1 {
        self.custody
    }

    /// Exact unchanged generation-five-through-seven v2 head.
    #[must_use]
    pub const fn v2_head(&self) -> &SensitiveOutputJournalHeadV1 {
        self.v2_partial.head()
    }

    /// Exact final v1 head, without exposing any pre-zero output commitment.
    #[must_use]
    pub const fn v1_final_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        self.fenced_v1_recovery.store_head()
    }

    /// Already-immutable clean reference retained by `Unknown`, or `None`
    /// after zero-first cleanup. Presence never means verified or completed.
    #[must_use]
    pub const fn retained_immutable_artifact_reference(
        &self,
    ) -> Option<&CommandOutputArtifactSetReferenceV1> {
        match self.custody {
            SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned => None,
            SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained => {
                self.fenced_v1_recovery.expected_reference()
            }
        }
    }

    /// Digest of the fresh zero-survivor proof. This does not classify output.
    #[must_use]
    pub const fn command_domain_cleanup_proof_id(&self) -> &Digest {
        self.native_cleanup_proof.os_evidence_digest()
    }

    /// Builds the exact core physical-reconciliation receipt from the retained
    /// claim-fenced v1 recovery.
    ///
    /// The zeroed form does not expose the runner recovery object itself; this
    /// method emits only the already-canonical core receipt required to record
    /// terminal `Unknown`. Immutable-retained custody remains explicitly
    /// represented by that receipt and never becomes success.
    ///
    /// # Errors
    ///
    /// Returns an error if this disposition is invalid, the supplied intent or
    /// claim differs from its durable identities, or the timestamp cannot form
    /// valid core evidence.
    pub fn physical_reconciliation_evidence(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        reconciled_at_unix_ms: u64,
    ) -> Result<
        grok_build_core::CommandOutputCapturePhysicalReconciliationV1,
        CommandOutputStoreError,
    > {
        self.validate()?;
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim != &self.reconciliation_claim
            || intent.capture_id != self.v2_partial.capture_id()
            || &intent.source != self.fenced_v1_recovery.source()
        {
            return Err(CommandOutputStoreError::Reference(
                "partial-terminal Unknown physical evidence crossed intent or claim".into(),
            ));
        }
        self.fenced_v1_recovery.physical_reconciliation_evidence(
            intent,
            claim,
            reconciled_at_unix_ms,
        )
    }

    /// Revalidates the closed Unknown/custody/native-proof/core-fence join.
    ///
    /// # Errors
    ///
    /// Returns an error if the partial generation, branch, proof, capture,
    /// final custody, unchanged v2 head, or core fence differs.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        if self.format_version != SENSITIVE_OUTPUT_PARTIAL_TERMINAL_UNKNOWN_FORMAT_VERSION_V1 {
            return Err(CommandOutputStoreError::Manifest(
                "partial-terminal Unknown format version differs".into(),
            ));
        }
        self.v2_partial.validate()?;
        if !(5..=7).contains(&self.v2_partial.head().generation) {
            return Err(CommandOutputStoreError::Manifest(
                "partial-terminal Unknown requires generation five through seven".into(),
            ));
        }
        let branch_is_clean = matches!(
            self.v2_partial.stage(),
            SensitiveOutputJournalStageV2::ScannedClean { .. }
                | SensitiveOutputJournalStageV2::Finished { .. }
                | SensitiveOutputJournalStageV2::Published { .. }
        );
        let branch_is_rejection = matches!(
            self.v2_partial.stage(),
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
                | SensitiveOutputJournalStageV2::CleanupIntended { .. }
                | SensitiveOutputJournalStageV2::Cleaned { .. }
        );
        if !branch_is_clean && !branch_is_rejection {
            return Err(CommandOutputStoreError::Manifest(
                "partial-terminal Unknown has no known partial branch".into(),
            ));
        }
        let acquired = self.v2_partial.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "partial-terminal Unknown lost its acquired anchor".into(),
            )
        })?;
        let binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        self.native_cleanup_proof
            .validate_expected(
                self.native_cleanup_proof.os_evidence_digest(),
                self.expected_cleanup_backend,
                &binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if self.reconciliation_claim.capture_id != self.v2_partial.capture_id()
            || self.fenced_v1_recovery.physical_reconciliation_claim()
                != Some(&self.reconciliation_claim)
            || self.fenced_v1_recovery.capture_id().as_str() != self.v2_partial.capture_id()
            || self.fenced_v1_recovery.acquired() != Some(acquired)
            || self.fenced_v1_recovery.launch_intended_store_head()
                != self.v2_partial.launch_intended_store_head()
        {
            return Err(CommandOutputStoreError::Manifest(
                "partial-terminal Unknown crossed capture, launch custody, or core fence".into(),
            ));
        }
        match self.custody {
            SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned => {
                if self.fenced_v1_recovery.state() != CommandOutputCaptureJournalStateV1::Cleaned
                    || self.fenced_v1_recovery.cleaned_store_head().is_none()
                {
                    return Err(CommandOutputStoreError::Manifest(
                        "partial-terminal Unknown did not read back exact v1 Cleaned custody"
                            .into(),
                    ));
                }
            }
            SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained => {
                if !branch_is_clean
                    || !matches!(
                        self.fenced_v1_recovery.state(),
                        CommandOutputCaptureJournalStateV1::Published
                            | CommandOutputCaptureJournalStateV1::TerminalPrepared
                    )
                    || self.fenced_v1_recovery.expected_reference().is_none()
                {
                    return Err(CommandOutputStoreError::Manifest(
                        "partial-terminal Unknown immutable retention is not exact clean publication"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

const SOURCE_NAME_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-artifact-source/v1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] = b"grok-build/command-output-artifact-set/v1\0";
const MANIFEST_FILE: &str = "manifest.json";
const STDOUT_FILE: &str = "stdout.raw";
const STDERR_FILE: &str = "stderr.raw";
const FINAL_PREFIX: &str = "command-output-";
const TEMP_PREFIX: &str = ".command-output-tmp-";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const TEMP_ATTEMPTS: usize = 128;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Hard aggregate ceiling for one complete stdout/stderr artifact set.
///
/// Each reservation supplies its smaller authenticated effect-specific bound.
/// The 128-MiB safety ceiling is deliberately above the current 64-MiB command
/// policy ceiling: complete evidence also includes bounded chunks drained after
/// output-limit termination. The store never silently truncates at either
/// boundary.
pub const MAX_COMMAND_OUTPUT_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);
static NEXT_CAPTURE: AtomicU64 = AtomicU64::new(1);

/// Fail-closed command-output capture, publication, or verification error.
#[derive(Debug)]
pub enum CommandOutputStoreError {
    /// The private-state root was not exact, owner-private, or identity-stable.
    Root(String),
    /// The source authority or reservation bound was malformed.
    Source(String),
    /// A typed reference was malformed or differed from stored content.
    Reference(String),
    /// The manifest was malformed, noncanonical, oversized, or incomplete.
    Manifest(String),
    /// A raw stream file was unsafe, changed, oversized, or digest-mismatched.
    Artifact(String),
    /// Capture or publication failed after command effects may have started.
    /// Callers must reconcile the effect and any expected final artifact.
    ReconciliationRequired {
        /// Exact capture ID when the failure belongs to the journaled path.
        capture_id: Option<String>,
        /// Exact source whose raw output can no longer be assumed complete.
        source: Box<CommandOutputArtifactSourceV1>,
        /// Exact final reference when both stream commitments were completed.
        expected_reference: Option<Box<CommandOutputArtifactSetReferenceV1>>,
        /// Failed proof or persistence operation.
        reason: String,
    },
    /// A descriptor-relative filesystem operation failed.
    Io {
        /// Failed operation.
        operation: &'static str,
        /// Redacted path relative to the private-state root.
        path: PathBuf,
        /// Operating-system error text.
        message: String,
    },
}

impl Display for CommandOutputStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(message) => write!(formatter, "command-output root rejected: {message}"),
            Self::Source(message) => write!(formatter, "command-output source rejected: {message}"),
            Self::Reference(message) => {
                write!(formatter, "command-output reference rejected: {message}")
            }
            Self::Manifest(message) => {
                write!(formatter, "command-output manifest rejected: {message}")
            }
            Self::Artifact(message) => {
                write!(formatter, "command-output artifact rejected: {message}")
            }
            Self::ReconciliationRequired {
                capture_id,
                source,
                expected_reference,
                reason,
            } => {
                let identity = capture_id.as_deref().unwrap_or_else(|| {
                    expected_reference.as_ref().map_or_else(
                        || source.effect_id.as_str(),
                        |reference| reference.manifest_digest.as_str(),
                    )
                });
                write!(
                    formatter,
                    "command output {identity} requires effect reconciliation: {reason}"
                )
            }
            Self::Io {
                operation,
                path,
                message,
            } => write!(
                formatter,
                "{operation} failed for private command-output path {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CommandOutputStoreError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateDirectoryIdentity {
    object: ObjectIdentity,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateFileIdentity {
    object: ObjectIdentity,
    uid: u32,
    mode: u32,
    length: u64,
}

struct StoreInner {
    root: Dir,
    root_parent: Dir,
    root_leaf: OsString,
    root_identity: PrivateDirectoryIdentity,
    path_anchor: DirectoryPathAnchor,
    root_path: PathBuf,
}

/// Retained capability for immutable complete command-output artifacts.
#[derive(Clone)]
pub struct CapabilityCommandOutputStore {
    inner: Arc<StoreInner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationCheckpoint {
    DirectoryCreated,
    DirectoryOpened,
    DirectoryModeSet,
    DirectoryMetadataValidated,
    StdoutOpened,
    StdoutModeSet,
    StdoutMetadataValidated,
    StderrOpened,
    StderrModeSet,
    StderrMetadataValidated,
}

struct PendingReservationFile {
    file: File,
    object: Option<ObjectIdentity>,
}

struct PendingCaptureReservation {
    store: CapabilityCommandOutputStore,
    source: CommandOutputArtifactSourceV1,
    temp_name: String,
    temp: Dir,
    temp_identity: PrivateDirectoryIdentity,
    stdout: Option<PendingReservationFile>,
    stderr: Option<PendingReservationFile>,
}

impl PendingCaptureReservation {
    fn fail(self, primary: CommandOutputStoreError) -> CommandOutputStoreError {
        let source = self.source.clone();
        let primary_reason = primary.to_string();
        match self.abandon_exact() {
            Ok(()) => primary,
            Err(cleanup) => reconciliation_error(
                &source,
                None,
                format!(
                    "temporary reservation failed: {primary_reason}; exact fixed-entry cleanup also failed: {cleanup}"
                ),
            ),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "reservation rollback keeps retained objects, fixed names, unlink ordering, and both durability syncs in one auditable exact-cleanup sequence"
    )]
    fn abandon_exact(self) -> Result<(), CommandOutputStoreError> {
        self.store.validate_root()?;
        let retained_identity = validate_private_directory(
            &self.temp,
            "retained command-output reservation directory",
        )?;
        if retained_identity != self.temp_identity {
            return Err(CommandOutputStoreError::Root(
                "retained temporary reservation directory changed before cleanup".into(),
            ));
        }
        let named_directory = self
            .store
            .inner
            .root
            .open_dir_nofollow(&self.temp_name)
            .map_err(|error| {
                io_error(
                    "open named command-output reservation for cleanup",
                    Path::new(&self.temp_name),
                    &error,
                )
            })?;
        if validate_private_directory(
            &named_directory,
            "named command-output reservation directory",
        )? != self.temp_identity
        {
            return Err(CommandOutputStoreError::Root(
                "temporary reservation name changed before cleanup".into(),
            ));
        }

        let entry_names = directory_entry_names(&named_directory, &self.temp_name)?;
        let mut expected_names = BTreeSet::new();
        if self.stdout.is_some() {
            expected_names.insert(STDOUT_FILE.to_string());
        }
        if self.stderr.is_some() {
            expected_names.insert(STDERR_FILE.to_string());
        }
        if entry_names != expected_names {
            return Err(CommandOutputStoreError::Artifact(
                "temporary reservation has a missing, ambiguous, or unexpected entry".into(),
            ));
        }

        for (name, pending) in [
            (STDOUT_FILE, self.stdout.as_ref()),
            (STDERR_FILE, self.stderr.as_ref()),
        ] {
            let Some(pending) = pending else {
                continue;
            };
            let held = validate_private_file(&pending.file, Path::new(name), Some(0), 0)?;
            if pending.object.is_some_and(|object| object != held.object) {
                return Err(CommandOutputStoreError::Artifact(format!(
                    "retained {name} object changed before reservation cleanup"
                )));
            }
            let named_file = open_private_file(&named_directory, Path::new(name))?;
            let named_identity = validate_private_file(&named_file, Path::new(name), Some(0), 0)?;
            if named_identity.object != held.object {
                return Err(CommandOutputStoreError::Artifact(format!(
                    "named {name} differs from retained reservation object"
                )));
            }
        }

        drop(self.stdout);
        drop(self.stderr);
        for name in [STDOUT_FILE, STDERR_FILE] {
            if entry_names.contains(name) {
                named_directory.remove_file(name).map_err(|error| {
                    io_error(
                        "unlink failed command-output reservation file",
                        Path::new(name),
                        &error,
                    )
                })?;
            }
        }
        sync_directory(&named_directory).map_err(|error| {
            io_error(
                "sync failed command-output reservation directory",
                Path::new(&self.temp_name),
                &error,
            )
        })?;
        drop(named_directory);
        drop(self.temp);
        self.store
            .validate_named_directory(&self.temp_name, self.temp_identity)?;
        self.store
            .inner
            .root
            .remove_dir(&self.temp_name)
            .map_err(|error| {
                io_error(
                    "remove failed command-output reservation directory",
                    Path::new(&self.temp_name),
                    &error,
                )
            })?;
        sync_directory(&self.store.inner.root).map_err(|error| {
            io_error(
                "sync failed command-output reservation removal",
                Path::new(&self.temp_name),
                &error,
            )
        })
    }

    fn into_ready_parts(self) -> (String, Dir, PrivateDirectoryIdentity, File, File) {
        (
            self.temp_name,
            self.temp,
            self.temp_identity,
            self.stdout
                .expect("ready reservation has stdout custody")
                .file,
            self.stderr
                .expect("ready reservation has stderr custody")
                .file,
        )
    }
}

impl CapabilityCommandOutputStore {
    /// Opens an existing canonical, effective-user-owned `0700` private-state root.
    ///
    /// # Errors
    ///
    /// Returns an error for an inexact path, link, wrong owner/mode, unstable
    /// path identity, or I/O failure.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CommandOutputStoreError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(CommandOutputStoreError::Root(
                "private-state root must be absolute".into(),
            ));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| io_error("canonicalize private-state root", Path::new("."), &error))?;
        if canonical != path {
            return Err(CommandOutputStoreError::Root(
                "private-state root must use its exact canonical path".into(),
            ));
        }
        let parent_path = canonical.parent().ok_or_else(|| {
            CommandOutputStoreError::Root("private-state root has no parent".into())
        })?;
        let root_leaf = canonical
            .file_name()
            .ok_or_else(|| CommandOutputStoreError::Root("private-state root has no leaf".into()))?
            .to_os_string();
        let root_parent = Dir::open_ambient_dir(parent_path, ambient_authority())
            .map_err(|error| io_error("open private-state parent", Path::new("."), &error))?;
        let root = root_parent.open_dir_nofollow(&root_leaf).map_err(|error| {
            io_error(
                "open private-state root without links",
                Path::new("."),
                &error,
            )
        })?;
        let root_identity = validate_private_directory(&root, "private-state root")?;
        let path_anchor = DirectoryPathAnchor::acquire(&canonical, "command-output store")
            .map_err(|error| CommandOutputStoreError::Root(error.to_string()))?;
        if path_anchor.final_device_inode()
            != (root_identity.object.device, root_identity.object.inode)
        {
            return Err(CommandOutputStoreError::Root(
                "private-state path anchor differs from the retained store descriptor".into(),
            ));
        }
        let store = Self {
            inner: Arc::new(StoreInner {
                root,
                root_parent,
                root_leaf,
                root_identity,
                path_anchor,
                root_path: canonical,
            }),
        };
        store.validate_root()?;
        Ok(store)
    }

    /// Returns the fixed canonical private-state root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.root_path
    }

    /// Creates and durably anchors one caller-intended, capture-ID-derived
    /// empty reservation without granting command execution authority.
    ///
    /// The returned custody must be consumed through
    /// [`CommandOutputCaptureReservation::into_acquired_anchor_for_handoff`]
    /// before transport. Dropping it deliberately leaves the exact anchored
    /// reservation intact for restart reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error for a crossed core Intent, private-state identity,
    /// dispatch claim, timestamp, existing capture ID, or any durability or
    /// filesystem-identity failure.
    pub fn reserve_anchored_capture(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        dispatch_claim_id: &str,
        acquired_at_unix_ms: u64,
    ) -> Result<CommandOutputCaptureReservation, CommandOutputStoreError> {
        command_output_journal::reserve_capture(
            self,
            intent,
            dispatch_claim_id,
            acquired_at_unix_ms,
        )
    }

    /// Creates the v2 Intent before physical acquisition and appends the exact
    /// Acquired binding only after the v1 reservation is durable.
    ///
    /// # Errors
    ///
    /// Returns the same reservation errors as [`Self::reserve_anchored_capture`]
    /// and rejects any detector-policy or v2-journal persistence mismatch.
    pub fn reserve_anchored_capture_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        dispatch_claim_id: &str,
        acquired_at_unix_ms: u64,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<CommandOutputCaptureReservation, CommandOutputStoreError> {
        sensitive_output_journal::record_intent(self, intent, detector_policy)?;
        let reservation = command_output_journal::reserve_capture(
            self,
            intent,
            dispatch_claim_id,
            acquired_at_unix_ms,
        )?;
        sensitive_output_journal::record_acquired(self, reservation.acquired_anchor())?;
        Ok(reservation)
    }

    /// Reopens the one exact acquired capture, acquires its cross-process
    /// writer fence, revalidates all source/store/object bindings, and appends
    /// `WriterAttached` before yielding move-only stream/publisher custody.
    ///
    /// This is the sole journaled path that can mint live output writers from
    /// a core [`CommandOutputCaptureAcquiredV1`] anchor.
    ///
    /// # Errors
    ///
    /// Returns reconciliation-required for an occupied writer fence, stale or
    /// crossed anchor, changed object/name, or non-`Acquired` journal head.
    pub fn reopen_anchored_capture(
        &self,
        acquired: &CommandOutputCaptureAcquiredV1,
    ) -> Result<CommandOutputCapture, CommandOutputStoreError> {
        self.reopen_anchored_capture_inner(acquired, false)
    }

    /// Reopens an exact v2 reservation and records `WriterAttached` at the
    /// actual v1 writer-fence boundary.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::reopen_anchored_capture`] and rejects
    /// a detector-policy or v2-journal mismatch.
    pub fn reopen_anchored_capture_v2(
        &self,
        acquired: &CommandOutputCaptureAcquiredV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<CommandOutputCapture, CommandOutputStoreError> {
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
        self.reopen_anchored_capture_inner(acquired, true)
    }

    fn reopen_anchored_capture_inner(
        &self,
        acquired: &CommandOutputCaptureAcquiredV1,
        sensitive_output_v2: bool,
    ) -> Result<CommandOutputCapture, CommandOutputStoreError> {
        let opened = command_output_journal::reopen_working(self, acquired)?;
        let writer_attached_store_head = opened.lease.head();
        if sensitive_output_v2 {
            sensitive_output_journal::record_writer_attached(
                self,
                acquired,
                &writer_attached_store_head,
            )?;
        }
        let shared = Arc::new(CaptureShared {
            source: opened.source,
            source_digest: opened.source_digest,
            capture_id: NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed),
            journal_capture_id: Some(acquired.capture_id.clone()),
            authenticated_maximum_bytes: opened.authenticated_maximum_bytes,
            reserved_bytes: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        });
        Ok(CommandOutputCapture {
            stdout: CommandOutputStreamCapture::new(
                Arc::clone(&shared),
                CommandOutputStreamV1::Stdout,
                opened.stdout,
                opened.stdout_identity,
            ),
            stderr: CommandOutputStreamCapture::new(
                Arc::clone(&shared),
                CommandOutputStreamV1::Stderr,
                opened.stderr,
                opened.stderr_identity,
            ),
            publisher: CommandOutputPublisher {
                store: self.clone(),
                shared,
                temp_name: opened.working_name,
                temp: opened.directory,
                temp_identity: opened.directory_identity,
                journal: Some(opened.lease),
                finished_store_head: None,
                sensitive_output_v2,
            },
        })
    }

    /// Reconstructs one exact capture by its caller-preallocated ID.
    ///
    /// No source or temporary-directory scan is performed. The immutable
    /// record chain and the physical state implied by its head are both
    /// revalidated before a state is returned.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed/unknown ID, active writer, torn or
    /// crossed chain, or physical namespace mismatch.
    pub fn reopen_capture(
        &self,
        capture_id: &str,
    ) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
        let capture_id = CommandOutputCaptureId::parse(capture_id.to_owned())?;
        command_output_journal::reopen_capture(self, &capture_id)
    }

    /// Reopens and returns only the exact validated lifecycle state for one
    /// capture ID. This performs the same full chain and physical validation
    /// as [`Self::reopen_capture`].
    ///
    /// # Errors
    ///
    /// Returns the same fail-closed errors as [`Self::reopen_capture`].
    pub fn capture_state(
        &self,
        capture_id: &str,
    ) -> Result<CommandOutputCaptureJournalStateV1, CommandOutputStoreError> {
        self.reopen_capture(capture_id)
            .map(|capture| capture.state())
    }

    /// Reopens and validates the additive secret-free v2 rejection journal.
    ///
    /// `Ok(None)` means generations 7 and 8 are not both durable yet. No v1
    /// record is reinterpreted or upgraded by this readback.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID or malformed, crossed, torn,
    /// or physically inconsistent v2 journal.
    pub fn reopen_sensitive_output_rejection_v2(
        &self,
        capture_id: &str,
    ) -> Result<Option<SensitiveOutputRejectionJournalReceiptV2>, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::read_rejection(self, capture_id)
    }

    /// Reopens the exact terminal clean v2 scan/publication chain.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID or malformed, crossed, torn,
    /// or physically inconsistent v2 journal.
    pub fn reopen_sensitive_output_clean_v2(
        &self,
        capture_id: &str,
    ) -> Result<Option<SensitiveOutputCleanJournalReceiptV2>, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::read_clean(self, capture_id)
    }

    /// Returns a typed current state for every durable v2 generation, including
    /// both partial branches, without inferring or replaying a transition.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID or malformed, crossed, torn,
    /// or physically inconsistent v2 journal.
    pub fn reopen_sensitive_output_journal_v2(
        &self,
        capture_id: &str,
    ) -> Result<SensitiveOutputJournalRecoveryV2, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::read_recovery(self, capture_id)
    }

    /// Returns `None` only when the exact v2 journal name is physically
    /// absent. A present but malformed, crossed, unsafe, or unreadable journal
    /// remains an error and can never be interpreted as legacy custody. This
    /// recovery-oriented reopen rolls a valid pending record forward; callers
    /// requiring byte- and name-stable inspection must use
    /// [`Self::reopen_optional_sensitive_output_journal_v2_diagnostic`].
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID or a present journal that
    /// fails exact path, chain, policy, or physical-state validation.
    pub fn reopen_optional_sensitive_output_journal_v2(
        &self,
        capture_id: &str,
    ) -> Result<Option<SensitiveOutputJournalRecoveryV2>, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::read_optional_recovery(self, capture_id)
    }

    /// Diagnostically reopens an optional v2 journal without changing its
    /// namespace or completing an interrupted record publication.
    ///
    /// `Ok(None)` means only that the exact journal name is absent. A present
    /// pending record is rejected rather than renamed, synchronized, or
    /// interpreted as the current head. The returned recovery carries no
    /// cleanup, launch, replay, verification, or completion authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID, a pending record, or any
    /// malformed, crossed, unsafe, or physically inconsistent journal.
    pub fn reopen_optional_sensitive_output_journal_v2_diagnostic(
        &self,
        capture_id: &str,
    ) -> Result<Option<SensitiveOutputJournalRecoveryV2>, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::read_optional_recovery_read_only(self, capture_id)
    }

    /// Reopens one exact policy-bound v2/v1 terminal join without mutating
    /// either journal.
    ///
    /// The join validates the exact intent, detector policy, acquired anchor,
    /// independently selected native backend and zero-survivor proof, caller-
    /// selected final v1 head, and every v1 store state represented by the
    /// current v2 prefix. The expected final head must come from an independent
    /// current v1 reopen (or a durable resolution's final store head), never
    /// from the pre-resolution core `Unknown` terminal anchor. Split v1/v2
    /// launch custody remains explicitly supported, but no missing v2 record
    /// is invented. The returned value is evidence only and carries no
    /// mutation or replay authority.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed or crossed intent, policy,
    /// acquisition, cleanup proof, backend, terminal head, shared state,
    /// branch, or physical custody state.
    #[allow(
        clippy::too_many_arguments,
        reason = "the read-only seam keeps every independently selected authority input explicit"
    )]
    pub fn reopen_sensitive_output_unknown_terminal_join_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        expected_final_v1_store_head: &CommandOutputCaptureStoreHeadV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<SensitiveOutputUnknownTerminalJoinV2, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        acquired
            .validate_against(intent)
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        expected_final_v1_store_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            intent.source.runner_session_id.clone(),
            intent.source.effect_id.clone(),
            intent.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        native_cleanup_proof
            .validate_expected(
                native_cleanup_proof.os_evidence_digest(),
                expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if native_cleanup_proof.surviving_processes() != 0 {
            return Err(CommandOutputStoreError::Reference(
                "policy-bound Unknown terminal join retains native survivors".into(),
            ));
        }
        let (v2_recovery, v1_terminal) = sensitive_output_journal::read_unknown_terminal_join(
            self,
            intent,
            acquired,
            expected_final_v1_store_head,
            detector_policy,
            native_cleanup_proof.os_evidence_digest(),
        )?;
        validate_sensitive_output_unknown_clean_terminal_join(
            intent,
            acquired,
            &v2_recovery,
            &v1_terminal,
            expected_cleanup_backend,
            &expected_binding,
        )?;
        Ok(SensitiveOutputUnknownTerminalJoinV2 {
            v2_recovery,
            v1_terminal,
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        })
    }

    /// Reopens the one exact immutable terminal-observation sidecar for a
    /// policy-bound capture.
    ///
    /// A fully synchronized pending sidecar is rolled forward through one
    /// no-replace rename. Absence returns `None`; a torn, crossed, linked,
    /// permission-unsafe, noncanonical, or branch-inconsistent sidecar remains
    /// an error. The returned observation is evidence only and grants no
    /// launch, replay, cleanup, publication, verification, or completion
    /// authority.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID, malformed journal, or any
    /// unsafe/crossed sidecar custody.
    pub fn reopen_sensitive_output_terminal_observation_v1(
        &self,
        capture_id: &str,
    ) -> Result<
        Option<crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1>,
        CommandOutputStoreError,
    > {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_terminal_observation_store::reopen(self, capture_id)
    }

    fn reject_generic_sensitive_output_mutation(
        &self,
        capture_id: &str,
        operation: &'static str,
    ) -> Result<(), CommandOutputStoreError> {
        let Some(recovery) = sensitive_output_journal::read_optional_recovery(self, capture_id)?
        else {
            return Ok(());
        };
        let Some(acquired) = recovery.acquired() else {
            return Err(CommandOutputStoreError::Reference(format!(
                "generic v1 {operation} cannot mutate a policy-bound pre-acquisition v2 capture; use the exact v2 pre-launch recovery API"
            )));
        };
        Err(CommandOutputStoreError::ReconciliationRequired {
            capture_id: Some(capture_id.to_owned()),
            source: Box::new(acquired.source.clone()),
            expected_reference: None,
            reason: format!(
                "generic v1 {operation} cannot mutate a policy-bound v2 capture; use the exact v2 branch-specific recovery API"
            ),
        })
    }

    /// Derives `PreLaunchAborted` only from an exact v2 generation-zero to
    /// generation-three prefix and independently reopened v1 `Cleaned`
    /// custody with no historical `LaunchIntended` record.
    ///
    /// # Errors
    ///
    /// Returns an error for a crossed intent or any malformed, torn, unsafe,
    /// or physically inconsistent v1/v2 readback.
    pub fn reopen_sensitive_output_prelaunch_aborted_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
    ) -> Result<Option<SensitiveOutputPreLaunchAbortedV2>, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        let prefix = sensitive_output_journal::read_optional_recovery(self, &intent.capture_id)?;
        if let Some(prefix) = &prefix {
            prefix.validate_intent_binding(intent)?;
            if prefix.head().generation >= 4 {
                return Ok(None);
            }
        }
        let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
        if !command_output_journal::capture_journal_exists(self, &capture_id)? {
            return Ok(None);
        }
        let v1_cleaned = self.reopen_capture(&intent.capture_id)?;
        if v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned {
            return Ok(None);
        }
        let disposition = SensitiveOutputPreLaunchAbortedV2 {
            intent: intent.clone(),
            v2_prefix: prefix,
            v1_cleaned,
        };
        disposition.validate()?;
        Ok(Some(disposition))
    }

    /// Idempotently completes only pre-launch v1 cleanup under the supplied
    /// core recovery fence, then returns both the exact `PreLaunchAborted`
    /// readback and the still-fenced v1 recovery. `core_acquired` is explicit
    /// because physical/v2 acquisition cannot manufacture durable core
    /// acquisition. Generation four or any historical v1 launch intent is
    /// rejected as post-launch `Unknown`; this method never dispatches.
    ///
    /// # Errors
    ///
    /// Returns an error for a crossed intent/acquisition/claim, stale fence,
    /// any launch evidence, failed exact cleanup, or inconsistent v1/v2
    /// readback.
    pub fn resume_sensitive_output_prelaunch_abort_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        core_acquired: Option<&CommandOutputCaptureAcquiredV1>,
        claim: &CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<SensitiveOutputPreLaunchAbortResolutionV2, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if let Some(acquired) = core_acquired {
            acquired
                .validate_against(intent)
                .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        }
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "pre-launch cleanup claim crossed the capture intent".into(),
            ));
        }
        let prefix = sensitive_output_journal::read_optional_recovery(self, &intent.capture_id)?;
        if let Some(prefix) = &prefix {
            prefix.validate_intent_binding(intent)?;
            if prefix.head().generation >= 4 {
                return Err(CommandOutputStoreError::ReconciliationRequired {
                    capture_id: Some(intent.capture_id.clone()),
                    source: Box::new(intent.source.clone()),
                    expected_reference: None,
                    reason: "v2 LaunchIntended is durable; pre-launch cleanup cannot classify the command and effect reconciliation is required"
                        .into(),
                });
            }
        }
        validate_prelaunch_core_acquisition_v2(prefix.as_ref(), core_acquired)?;
        let parsed_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
        if command_output_journal::capture_journal_exists(self, &parsed_id)? {
            let current = self.reopen_capture(&intent.capture_id)?;
            if current.launch_intended_store_head().is_some() {
                return Err(CommandOutputStoreError::ReconciliationRequired {
                    capture_id: Some(intent.capture_id.clone()),
                    source: Box::new(intent.source.clone()),
                    expected_reference: current.expected_reference().cloned().map(Box::new),
                    reason: "v1 LaunchIntended is durable without the v2 launch boundary; launch status is Unknown"
                        .into(),
                });
            }
        }
        let recovery = command_output_journal::reconcile_capture_restart(
            self,
            intent,
            claim,
            core_acquired.map(|acquired| &acquired.store_head),
        )?;
        if recovery.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || recovery.launch_intended_store_head().is_some()
            || recovery.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(intent.capture_id.clone()),
                source: Box::new(intent.source.clone()),
                expected_reference: recovery.expected_reference().cloned().map(Box::new),
                reason:
                    "pre-launch cleanup did not read back exact non-launched v1 Cleaned custody"
                        .into(),
            });
        }
        let disposition = self
            .reopen_sensitive_output_prelaunch_aborted_v2(intent)?
            .ok_or_else(|| CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(intent.capture_id.clone()),
                source: Box::new(intent.source.clone()),
                expected_reference: None,
                reason: "pre-launch cleanup completed but joined v1/v2 readback was not derivable"
                    .into(),
            })?;
        if disposition.v2_prefix != prefix
            || disposition.v1_cleaned.store_head() != recovery.store_head()
        {
            return Err(CommandOutputStoreError::Manifest(
                "pre-launch cleanup changed its exact v2 prefix or crossed final v1 readback"
                    .into(),
            ));
        }
        let resolution = SensitiveOutputPreLaunchAbortResolutionV2 {
            disposition,
            fenced_v1_recovery: recovery,
            reconciliation_claim: claim.clone(),
        };
        resolution.validate()?;
        Ok(resolution)
    }

    /// Quarantines an unclassified post-launch v2 capture without claiming
    /// that its output was clean or rejected.
    ///
    /// The exact v2 journal must remain at generation-four `LaunchIntended`.
    /// Independent native cleanup evidence is revalidated against the captured
    /// request and the separately selected expected platform backend before
    /// both staging objects are replaced with synchronized empty objects. Only
    /// then may the frozen v1 recovery transition persist its constant-zero
    /// cleanup plan under the supplied core fence. The v2 journal is never
    /// advanced, so this result carries no terminal or replay authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, crossed, classified, or non-generation-
    /// four v2 journal; invalid native zero-survivor evidence; a stale claim;
    /// nonzero or changed staging custody; or inexact final readback.
    #[allow(
        clippy::too_many_lines,
        reason = "the generation-four boundary keeps v2 identity, independent native proof, zero-first staging, private v1 fencing, and unchanged readback adjacent"
    )]
    pub fn quarantine_unclassified_sensitive_output_after_launch_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<SensitiveOutputUnknownQuarantineV2, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "unclassified quarantine claim crossed the capture intent".into(),
            ));
        }

        let v2_launch_intended = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        v2_launch_intended.validate_intent_binding(intent)?;
        let SensitiveOutputJournalStageV2::LaunchIntended {
            launch_intended_store_head,
            ..
        } = v2_launch_intended.stage()
        else {
            return Err(CommandOutputStoreError::Reference(
                "unclassified quarantine requires exact generation-four v2 LaunchIntended state"
                    .into(),
            ));
        };
        if v2_launch_intended.head().generation != 4 {
            return Err(CommandOutputStoreError::Manifest(
                "v2 LaunchIntended quarantine generation is not exactly four".into(),
            ));
        }
        let acquired = v2_launch_intended.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "unclassified quarantine lost its acquired capture anchor".into(),
            )
        })?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        native_cleanup_proof
            .validate_expected(
                native_cleanup_proof.os_evidence_digest(),
                expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;

        let v1_before = self.reopen_capture(&intent.capture_id)?;
        if v1_before.acquired() != Some(acquired)
            || v1_before.launch_intended_store_head() != Some(launch_intended_store_head)
        {
            return Err(CommandOutputStoreError::Reference(
                "unclassified quarantine crossed the exact v1 launch custody".into(),
            ));
        }
        match v1_before.state() {
            CommandOutputCaptureJournalStateV1::LaunchIntended => {
                command_output_journal::neutralize_sensitive_working(
                    self,
                    acquired,
                    launch_intended_store_head,
                )?;
            }
            CommandOutputCaptureJournalStateV1::CleanupIntended
            | CommandOutputCaptureJournalStateV1::Cleaned => {
                command_output_journal::validate_sensitive_cleanup_plan_zero(
                    self,
                    acquired,
                    launch_intended_store_head,
                )?;
            }
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "unclassified quarantine found an incompatible v1 lifecycle state".into(),
                ));
            }
        }

        let v1_cleaned = command_output_journal::reconcile_capture_restart(
            self,
            intent,
            claim,
            Some(&acquired.store_head),
        )?;
        if v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || v1_cleaned.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(intent.capture_id.clone()),
                source: Box::new(intent.source.clone()),
                expected_reference: v1_cleaned.expected_reference().cloned().map(Box::new),
                reason: "unclassified quarantine did not read back exact v1 Cleaned custody".into(),
            });
        }
        command_output_journal::validate_sensitive_cleanup_plan_zero(
            self,
            acquired,
            launch_intended_store_head,
        )?;
        let v2_after = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        if v2_after != v2_launch_intended {
            return Err(CommandOutputStoreError::Manifest(
                "unclassified quarantine changed the v2 LaunchIntended journal".into(),
            ));
        }
        let quarantine = SensitiveOutputUnknownQuarantineV2 {
            v2_launch_intended,
            v1_cleaned,
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        };
        quarantine.validate()?;
        Ok(quarantine)
    }

    /// Quarantines the exact split launch cut where v1 `LaunchIntended` is
    /// durable and v2 remains at generation-three `WriterAttached`.
    ///
    /// Independent native cleanup evidence is validated against the captured
    /// request and separately selected backend before either stream is
    /// neutralized. Only after both exact stream objects read back at constant
    /// zero may frozen-v1 cleanup persist its claim-fenced plan. The v2 prefix
    /// is never advanced or rewritten, and the result grants no replay.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or non-generation-three v2 prefix, a v1
    /// state without its exact launch record, crossed acquisition/writer
    /// custody, invalid native zero-survivor evidence, stale claim, nonzero
    /// prior cleanup plan, or changed final readback.
    #[allow(
        clippy::too_many_lines,
        reason = "the split-launch boundary keeps both immutable heads, independent native proof, zero-first staging, private v1 fencing, and unchanged v2 readback adjacent"
    )]
    pub fn quarantine_split_sensitive_output_launch_v2(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<SensitiveOutputSplitLaunchUnknownQuarantineV2, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "split-launch quarantine claim crossed the capture intent".into(),
            ));
        }

        let v2_writer_attached = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        v2_writer_attached.validate_intent_binding(intent)?;
        let SensitiveOutputJournalStageV2::WriterAttached {
            writer_attached_store_head,
        } = v2_writer_attached.stage()
        else {
            return Err(CommandOutputStoreError::Reference(
                "split-launch quarantine requires exact generation-three v2 WriterAttached state"
                    .into(),
            ));
        };
        if v2_writer_attached.head().generation != 3 {
            return Err(CommandOutputStoreError::Manifest(
                "split-launch v2 WriterAttached generation is not exactly three".into(),
            ));
        }
        let acquired = v2_writer_attached.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "split-launch quarantine lost its acquired capture anchor".into(),
            )
        })?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        native_cleanup_proof
            .validate_expected(
                native_cleanup_proof.os_evidence_digest(),
                expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;

        let v1_before = self.reopen_capture(&intent.capture_id)?;
        let launch_intended_store_head = v1_before
            .launch_intended_store_head()
            .ok_or_else(|| {
                CommandOutputStoreError::Reference(
                    "split-launch quarantine requires exact durable v1 LaunchIntended state".into(),
                )
            })?
            .clone();
        if v1_before.acquired() != Some(acquired)
            || v1_before.writer_attached_store_head() != Some(writer_attached_store_head)
            || v1_before.launch_intended().is_none()
            || launch_intended_store_head.generation
                != writer_attached_store_head
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| {
                        CommandOutputStoreError::Manifest(
                            "split-launch v1 store generation overflowed".into(),
                        )
                    })?
        {
            return Err(CommandOutputStoreError::Reference(
                "split-launch quarantine crossed the exact v2 writer and v1 launch custody".into(),
            ));
        }
        match v1_before.state() {
            CommandOutputCaptureJournalStateV1::LaunchIntended => {
                command_output_journal::neutralize_sensitive_working(
                    self,
                    acquired,
                    &launch_intended_store_head,
                )?;
            }
            CommandOutputCaptureJournalStateV1::CleanupIntended
            | CommandOutputCaptureJournalStateV1::Cleaned => {
                command_output_journal::validate_sensitive_cleanup_plan_zero(
                    self,
                    acquired,
                    &launch_intended_store_head,
                )?;
            }
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "split-launch quarantine found an incompatible v1 lifecycle state".into(),
                ));
            }
        }

        let v1_cleaned = command_output_journal::reconcile_capture_restart(
            self,
            intent,
            claim,
            Some(&acquired.store_head),
        )?;
        if v1_cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || v1_cleaned.expected_reference().is_some()
            || v1_cleaned.launch_intended_store_head() != Some(&launch_intended_store_head)
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(intent.capture_id.clone()),
                source: Box::new(intent.source.clone()),
                expected_reference: v1_cleaned.expected_reference().cloned().map(Box::new),
                reason: "split-launch quarantine did not read back exact v1 Cleaned launch custody"
                    .into(),
            });
        }
        command_output_journal::validate_sensitive_cleanup_plan_zero(
            self,
            acquired,
            &launch_intended_store_head,
        )?;
        let v2_after = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        if v2_after != v2_writer_attached {
            return Err(CommandOutputStoreError::Manifest(
                "split-launch quarantine changed the v2 WriterAttached prefix".into(),
            ));
        }
        let quarantine = SensitiveOutputSplitLaunchUnknownQuarantineV2 {
            v2_writer_attached,
            v1_launch_intended_store_head: launch_intended_store_head,
            v1_cleaned,
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        };
        quarantine.validate()?;
        Ok(quarantine)
    }

    /// Idempotently resumes only the post-detection staging-neutralization
    /// boundary. This method never launches or replays a command. The caller
    /// must supply the independently retained command-domain cleanup proof
    /// identity and observation time because generation five predates them.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed proof identity, a non-detected stage,
    /// changed staging objects, or failed neutralization/persistence readback.
    pub fn resume_sensitive_output_neutralization_v2(
        &self,
        capture_id: &str,
        command_domain_cleanup_proof_id: &str,
    ) -> Result<SensitiveOutputStagingNeutralizationReceiptV1, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        let recovery = sensitive_output_journal::read_recovery(self, capture_id)?;
        let acquired = recovery.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output restart lost its acquired anchor".into(),
            )
        })?;
        let launch_intended_store_head =
            recovery.launch_intended_store_head().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "sensitive-output restart lost its v1 LaunchIntended head".into(),
                )
            })?;
        match recovery.stage() {
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. } => {
                command_output_journal::neutralize_sensitive_working(
                    self,
                    acquired,
                    launch_intended_store_head,
                )?;
                let receipt = SensitiveOutputStagingNeutralizationReceiptV1::try_new(acquired)
                    .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
                sensitive_output_journal::record_cleanup_intended(
                    self,
                    capture_id,
                    command_domain_cleanup_proof_id,
                    &receipt,
                )?;
                Ok(receipt)
            }
            SensitiveOutputJournalStageV2::CleanupIntended {
                command_domain_cleanup_proof_id: recorded_proof_id,
                staging_neutralization,
            } => {
                if recorded_proof_id != command_domain_cleanup_proof_id {
                    return Err(CommandOutputStoreError::Reference(
                        "idempotent sensitive-output neutralization crossed command cleanup proof"
                            .into(),
                    ));
                }
                staging_neutralization
                    .validate_against(acquired)
                    .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
                command_output_journal::validate_sensitive_working_neutralized(
                    self,
                    acquired,
                    launch_intended_store_head,
                )?;
                Ok(staging_neutralization.clone())
            }
            _ => Err(CommandOutputStoreError::Reference(
                "sensitive-output neutralization restart requires exact Detected or CleanupIntended state"
                    .into(),
            )),
        }
    }

    /// Resumes v1 cleanup and the v2 rejection terminal from an exact
    /// `CleanupIntended`, `Cleaned`, or already-rejected state. It never
    /// launches, dispatches, or reconstructs command authority.
    ///
    /// # Errors
    ///
    /// Returns an error for crossed policy, claim, termination, capture, or
    /// cleanup state, or when exact v1/v2 cleanup cannot be proven.
    #[allow(
        clippy::too_many_lines,
        reason = "restart closure keeps exact v1 custody, v2 stages, fencing, and terminal readback visibly joined"
    )]
    pub fn resume_sensitive_output_rejection_v2(
        &self,
        capture_id: &str,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        termination: CommandTerminationV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<SensitiveOutputRejectionJournalReceiptV2, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        termination
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
        let recovery = sensitive_output_journal::read_recovery(self, capture_id)?;
        if recovery.detector_policy() != detector_policy || claim.capture_id != capture_id {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output rejection restart crossed policy or capture claim".into(),
            ));
        }
        if matches!(
            recovery.stage(),
            SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. }
        ) {
            let receipt =
                sensitive_output_journal::read_rejection(self, capture_id)?.ok_or_else(|| {
                    CommandOutputStoreError::Manifest(
                        "rejected v2 state lost its terminal receipt".into(),
                    )
                })?;
            if receipt.termination != termination {
                return Err(CommandOutputStoreError::Reference(
                    "idempotent rejection restart crossed termination".into(),
                ));
            }
            return Ok(receipt);
        }
        let acquired = recovery.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output rejection restart lost its acquired anchor".into(),
            )
        })?;
        let launch_intended_store_head =
            recovery.launch_intended_store_head().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "sensitive-output rejection restart lost its v1 LaunchIntended head".into(),
                )
            })?;
        let v1 = self.reopen_capture(capture_id)?;
        if v1.acquired() != Some(acquired)
            || v1.launch_intended_store_head() != Some(launch_intended_store_head)
        {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output rejection restart crossed the v1 custody chain".into(),
            ));
        }
        let v1 = match recovery.stage() {
            SensitiveOutputJournalStageV2::CleanupIntended {
                staging_neutralization,
                ..
            } => {
                staging_neutralization
                    .validate_against(acquired)
                    .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
                match v1.state() {
                    CommandOutputCaptureJournalStateV1::LaunchIntended => {
                        command_output_journal::validate_sensitive_working_neutralized(
                            self,
                            acquired,
                            launch_intended_store_head,
                        )?;
                    }
                    CommandOutputCaptureJournalStateV1::CleanupIntended
                    | CommandOutputCaptureJournalStateV1::Cleaned => {
                        command_output_journal::validate_sensitive_cleanup_plan_zero(
                            self,
                            acquired,
                            launch_intended_store_head,
                        )?;
                    }
                    _ => {
                        return Err(CommandOutputStoreError::Reference(
                            "v2 CleanupIntended has an incompatible v1 lifecycle state".into(),
                        ));
                    }
                }
                if v1.state() == CommandOutputCaptureJournalStateV1::Cleaned {
                    v1
                } else {
                    command_output_journal::cleanup_capture(
                        self,
                        claim,
                        launch_intended_store_head,
                    )?
                }
            }
            SensitiveOutputJournalStageV2::Cleaned { .. } => {
                if v1.state() != CommandOutputCaptureJournalStateV1::Cleaned {
                    return Err(CommandOutputStoreError::Reference(
                        "v2 Cleaned differs from the v1 lifecycle state".into(),
                    ));
                }
                command_output_journal::validate_sensitive_cleanup_plan_zero(
                    self,
                    acquired,
                    launch_intended_store_head,
                )?;
                v1
            }
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "rejection restart requires exact CleanupIntended, Cleaned, or rejected state"
                        .into(),
                ));
            }
        };
        if v1.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || v1.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id.to_owned()),
                source: Box::new(v1.source().clone()),
                expected_reference: v1.expected_reference().cloned().map(Box::new),
                reason: "sensitive-output restart did not prove exact v1 Cleaned custody".into(),
            });
        }
        let cleaned_store_head = v1.cleaned_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output restart lost its v1 Cleaned head".into(),
            )
        })?;
        sensitive_output_journal::complete_rejection(
            self,
            capture_id,
            cleaned_store_head,
            termination,
        )
    }

    /// Continues a generation-five-through-seven clean branch only from its
    /// exact immutable terminal observation, fresh native zero-survivor proof,
    /// exact V12 launch authority, and descriptor-relative stream readback.
    ///
    /// The result stops at v2 `Published`; it does not manufacture terminal
    /// response bytes or claim command success. Existing v1
    /// `TerminalPrepared` custody is retained unchanged for the coordinator to
    /// finish through its ordinary exact terminal path.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for an absent/crossed observation, branch,
    /// launch authority, proof, claim, stream identity/commitment, v1 head, or
    /// v2 transition. Callers lacking exact observation backing must use the
    /// explicitly typed partial-terminal `Unknown` quarantine API.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "clean restart keeps every independent observation, launch, proof, custody, fence, and v2 transition visibly joined"
    )]
    pub fn resume_sensitive_output_clean_publication_v1(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
        launch_binding: &crate::wire::ValidatedCommandCaptureLaunchBindingV12,
    ) -> Result<SensitiveOutputCleanPublicationRecoveryV1, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "clean partial recovery claim crossed its capture intent".into(),
            ));
        }
        let v2_before = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        v2_before.validate_intent_binding(intent)?;
        if !(5..=7).contains(&v2_before.head().generation)
            || !matches!(
                v2_before.stage(),
                SensitiveOutputJournalStageV2::ScannedClean { .. }
                    | SensitiveOutputJournalStageV2::Finished { .. }
                    | SensitiveOutputJournalStageV2::Published { .. }
            )
        {
            return Err(CommandOutputStoreError::Reference(
                "clean partial recovery requires exact generation-five-through-seven clean state"
                    .into(),
            ));
        }
        let acquired = v2_before.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean partial recovery lost its acquired anchor".into(),
            )
        })?;
        let launch_intended_store_head =
            v2_before.launch_intended_store_head().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "clean partial recovery lost its launch head".into(),
                )
            })?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if launch_binding.launch_intended_store_head() != launch_intended_store_head
            || launch_binding.command_domain_binding() != &expected_binding
            || launch_binding.request().detector_policy() != v2_before.detector_policy()
            || launch_binding.backend().command_domain_backend != expected_cleanup_backend
        {
            return Err(CommandOutputStoreError::Reference(
                "clean partial recovery crossed V12 launch, detector, backend, or command-domain authority"
                    .into(),
            ));
        }
        let observation = sensitive_output_terminal_observation_store::reopen(
            self,
            &intent.capture_id,
        )?
        .ok_or_else(|| CommandOutputStoreError::ReconciliationRequired {
            capture_id: Some(intent.capture_id.clone()),
            source: Box::new(acquired.source.clone()),
            expected_reference: None,
            reason: "clean partial branch has no immutable terminal observation; exact continuation is forbidden"
                .into(),
        })?;
        observation
            .validate_expected_clean(
                &intent.capture_id,
                expected_cleanup_backend,
                &expected_binding,
                native_cleanup_proof,
                launch_binding,
                acquired,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        let artifact_reference = observation
            .clean_response()
            .ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "clean terminal observation lost its clean response".into(),
                )
            })?
            .output_artifacts()
            .clone();

        let fenced_v1_recovery =
            command_output_journal::resume_sensitive_clean_publication_under_claim(
                self,
                intent,
                claim,
                acquired,
                launch_intended_store_head,
                &artifact_reference,
            )?;
        let finished_store_head = fenced_v1_recovery.finished_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean partial recovery lost the exact v1 Finished head".into(),
            )
        })?;
        let published_store_head = fenced_v1_recovery.published_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean partial recovery lost the exact v1 Published head".into(),
            )
        })?;

        let mut v2_current = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        match v2_current.stage() {
            SensitiveOutputJournalStageV2::ScannedClean { .. } => {
                sensitive_output_journal::record_finished(
                    self,
                    &intent.capture_id,
                    finished_store_head,
                )?;
                v2_current = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
            }
            SensitiveOutputJournalStageV2::Finished {
                finished_store_head: recorded,
                ..
            } if recorded == finished_store_head => {}
            SensitiveOutputJournalStageV2::Published {
                published_store_head: recorded,
                ..
            } if recorded == published_store_head => {}
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "clean partial recovery crossed its v2 Finished boundary".into(),
                ));
            }
        }
        match v2_current.stage() {
            SensitiveOutputJournalStageV2::Finished { .. } => {
                sensitive_output_journal::record_published(
                    self,
                    &intent.capture_id,
                    published_store_head,
                )?;
            }
            SensitiveOutputJournalStageV2::Published {
                published_store_head: recorded,
                ..
            } if recorded == published_store_head => {}
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "clean partial recovery crossed its v2 Published boundary".into(),
                ));
            }
        }
        let v2_published = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        let result = SensitiveOutputCleanPublicationRecoveryV1 {
            observation,
            artifact_reference,
            launch_binding: launch_binding.clone(),
            v2_published,
            fenced_v1_recovery,
            reconciliation_claim: claim.clone(),
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    /// Continues a generation-five-through-seven rejection branch only from
    /// its exact immutable rejection observation and a fresh matching native
    /// zero-survivor proof, then returns the inseparable claim-fenced v1
    /// cleanup and terminal v2 receipt.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for any missing/crossed observation, proof,
    /// backend, branch, claim, neutralization, cleanup, or terminal readback.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "rejection restart keeps observation, proof, zero-first cleanup, v2 terminal, and fresh core fence adjacent"
    )]
    pub fn resume_sensitive_output_rejection_from_observation_v1(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    ) -> Result<SensitiveOutputRejectionRecoveryV1, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "rejection recovery claim crossed its capture intent".into(),
            ));
        }
        let recovery = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        recovery.validate_intent_binding(intent)?;
        if !(5..=8).contains(&recovery.head().generation)
            || !matches!(
                recovery.stage(),
                SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
                    | SensitiveOutputJournalStageV2::CleanupIntended { .. }
                    | SensitiveOutputJournalStageV2::Cleaned { .. }
                    | SensitiveOutputJournalStageV2::SensitiveOutputRejected { .. }
            )
        {
            return Err(CommandOutputStoreError::Reference(
                "rejection observation recovery requires exact generation-five-through-seven rejection state"
                    .into(),
            ));
        }
        let acquired = recovery.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "rejection observation recovery lost its acquired anchor".into(),
            )
        })?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        let observation = sensitive_output_terminal_observation_store::reopen(
            self,
            &intent.capture_id,
        )?
        .ok_or_else(|| CommandOutputStoreError::ReconciliationRequired {
            capture_id: Some(intent.capture_id.clone()),
            source: Box::new(acquired.source.clone()),
            expected_reference: None,
            reason: "rejection branch has no immutable terminal observation; exact continuation is forbidden"
                .into(),
        })?;
        observation
            .validate_expected(
                &intent.capture_id,
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection,
                expected_cleanup_backend,
                &expected_binding,
                native_cleanup_proof,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if matches!(
            recovery.stage(),
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
                | SensitiveOutputJournalStageV2::CleanupIntended { .. }
        ) {
            self.resume_sensitive_output_neutralization_v2(
                &intent.capture_id,
                native_cleanup_proof.os_evidence_digest().as_str(),
            )?;
        }
        let receipt = self.resume_sensitive_output_rejection_v2(
            &intent.capture_id,
            claim,
            observation.termination(),
            recovery.detector_policy(),
        )?;
        let fenced_v1_recovery = command_output_journal::reconcile_capture_restart(
            self,
            intent,
            claim,
            Some(&acquired.store_head),
        )?;
        let result = SensitiveOutputRejectionRecoveryV1 {
            observation,
            receipt,
            fenced_v1_recovery,
            reconciliation_claim: claim.clone(),
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    /// Conservatively closes an unbacked generation-five-through-seven branch
    /// as a versioned terminal `Unknown` without advancing its v2 journal.
    ///
    /// A matching exact observation is never downgraded when its exact V12
    /// launch binding is supplied and validates. Missing, crossed, unusable,
    /// or otherwise unbacked observation/launch input authorizes only
    /// zero/cleanup (or truthful immutable artifact retention), never branch
    /// inference, retry, verification, or completion.
    ///
    /// # Errors
    ///
    /// Returns an error for a nonpartial branch, crossed intent/claim/proof,
    /// an exact observation that should use its branch continuation, unsafe
    /// staging, cleanup failure, changed v2 prefix, or invalid final custody.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "Unknown quarantine keeps observation classification, proof, zero-first custody, immutable retention, and unchanged v2 readback together"
    )]
    pub fn quarantine_sensitive_output_partial_terminal_unknown_v1(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_cleanup_backend: CommandDomainCleanupBackend,
        native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
        launch_binding: Option<&crate::wire::ValidatedCommandCaptureLaunchBindingV12>,
    ) -> Result<SensitiveOutputPartialTerminalUnknownV1, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if claim.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "partial-terminal Unknown claim crossed its capture intent".into(),
            ));
        }
        let v2_partial = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        v2_partial.validate_intent_binding(intent)?;
        if !(5..=7).contains(&v2_partial.head().generation) {
            return Err(CommandOutputStoreError::Reference(
                "partial-terminal Unknown requires generation five through seven".into(),
            ));
        }
        let expected_branch = match v2_partial.stage() {
            SensitiveOutputJournalStageV2::ScannedClean { .. }
            | SensitiveOutputJournalStageV2::Finished { .. }
            | SensitiveOutputJournalStageV2::Published { .. } => {
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Clean
            }
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
            | SensitiveOutputJournalStageV2::CleanupIntended { .. }
            | SensitiveOutputJournalStageV2::Cleaned { .. } => {
                crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection
            }
            _ => {
                return Err(CommandOutputStoreError::Reference(
                    "partial-terminal Unknown requires a known clean or rejection branch".into(),
                ));
            }
        };
        let acquired = v2_partial.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "partial-terminal Unknown lost its acquired anchor".into(),
            )
        })?;
        let launch_intended_store_head =
            v2_partial.launch_intended_store_head().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "partial-terminal Unknown lost its launch head".into(),
                )
            })?;
        let expected_binding = CommandDomainCleanupBinding::try_new(
            acquired.source.runner_session_id.clone(),
            acquired.source.effect_id.clone(),
            acquired.source.request_digest.clone(),
        )
        .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        native_cleanup_proof
            .validate_expected(
                native_cleanup_proof.os_evidence_digest(),
                expected_cleanup_backend,
                &expected_binding,
            )
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;

        let reason = match sensitive_output_terminal_observation_store::reopen(
            self,
            &intent.capture_id,
        ) {
            Ok(None) => SensitiveOutputPartialTerminalUnknownReasonV1::MissingObservation,
            Err(_) => SensitiveOutputPartialTerminalUnknownReasonV1::UnusableObservation,
            Ok(Some(observation)) => {
                let generic_exact = observation.validate_expected(
                    &intent.capture_id,
                    expected_branch,
                    expected_cleanup_backend,
                    &expected_binding,
                    native_cleanup_proof,
                );
                if generic_exact.is_err() {
                    SensitiveOutputPartialTerminalUnknownReasonV1::UnbackedObservation
                } else if launch_binding.is_some_and(|launch_binding| match expected_branch {
                    crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Clean => observation
                        .validate_expected_clean(
                            &intent.capture_id,
                            expected_cleanup_backend,
                            &expected_binding,
                            native_cleanup_proof,
                            launch_binding,
                            acquired,
                        )
                        .is_ok(),
                    crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationBranchV1::Rejection => {
                        launch_binding.launch_intended_store_head()
                            == launch_intended_store_head
                            && launch_binding.command_domain_binding() == &expected_binding
                            && launch_binding.request().detector_policy()
                                == v2_partial.detector_policy()
                            && launch_binding.backend().command_domain_backend
                                == expected_cleanup_backend
                    }
                }) {
                    return Err(CommandOutputStoreError::Reference(
                        "exact terminal observation and launch backing are present; terminal Unknown downgrade is forbidden"
                            .into(),
                    ));
                } else {
                    SensitiveOutputPartialTerminalUnknownReasonV1::UnbackedObservation
                }
            }
        };

        let fenced_v1_recovery =
            command_output_journal::quarantine_sensitive_partial_terminal_unknown_under_claim(
                self,
                intent,
                claim,
                acquired,
                launch_intended_store_head,
            )?;
        let custody = match fenced_v1_recovery.state() {
            CommandOutputCaptureJournalStateV1::Cleaned => {
                SensitiveOutputPartialTerminalUnknownCustodyV1::ZeroedAndCleaned
            }
            CommandOutputCaptureJournalStateV1::Published
            | CommandOutputCaptureJournalStateV1::TerminalPrepared => {
                SensitiveOutputPartialTerminalUnknownCustodyV1::ImmutableArtifactRetained
            }
            _ => {
                return Err(CommandOutputStoreError::Manifest(
                    "partial-terminal Unknown returned an open v1 custody state".into(),
                ));
            }
        };
        let v2_after = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        if v2_after != v2_partial {
            return Err(CommandOutputStoreError::Manifest(
                "partial-terminal Unknown changed its immutable v2 branch prefix".into(),
            ));
        }
        let result = SensitiveOutputPartialTerminalUnknownV1 {
            format_version: SENSITIVE_OUTPUT_PARTIAL_TERMINAL_UNKNOWN_FORMAT_VERSION_V1,
            reason,
            custody,
            v2_partial,
            fenced_v1_recovery,
            reconciliation_claim: claim.clone(),
            expected_cleanup_backend,
            native_cleanup_proof: native_cleanup_proof.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    /// Appends clean v2 `TerminalPrepared` only after the v1 terminal record
    /// and exact record digest are durable.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture ID, crossed terminal fields, an
    /// illegal generation, or persistence/readback failure.
    pub fn record_sensitive_output_clean_terminal_prepared_v2(
        &self,
        capture_id: &str,
        terminal_prepared_store_head: &CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: &Digest,
        termination: CommandTerminationV1,
    ) -> Result<SensitiveOutputCleanJournalReceiptV2, CommandOutputStoreError> {
        CommandOutputCaptureId::parse(capture_id.to_owned())?;
        sensitive_output_journal::record_terminal_prepared(
            self,
            capture_id,
            terminal_prepared_store_head,
            terminal_record_digest,
            termination,
        )
    }

    /// Appends the exact v1 clean terminal under the recovery fence that owns
    /// an observation-backed generation-five-through-seven publication.
    ///
    /// The claim may be the publication claim itself or a higher successor
    /// that names it as predecessor. This boundary reopens and compares the
    /// exact v2 `Published` prefix and immutable observation, revalidates the
    /// retained V12 launch/native-proof/publication result, resolves only an
    /// interrupted copy of the same terminal record, and returns a narrow
    /// terminal evidence value rather than generic mutation authority.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for any crossed intent, claim lineage,
    /// publication result, v1/v2 head, artifact, observation, launch, proof,
    /// terminal bytes, or interrupted-record successor.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the branch-specific seam keeps publication evidence, sidecar/v2 readback, claim lineage, exact terminal append, and final readback visibly joined"
    )]
    pub fn prepare_sensitive_output_clean_terminal_under_claim_v1(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        clean_publication: &SensitiveOutputCleanPublicationRecoveryV1,
        expected_published_head: &CommandOutputCaptureStoreHeadV1,
        schema: impl Into<String>,
        canonical_terminal_bytes: Vec<u8>,
    ) -> Result<SensitiveOutputCleanTerminalPreparationV1, CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        expected_published_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        clean_publication.validate()?;
        if claim.capture_id != intent.capture_id
            || clean_publication.v2_published().capture_id() != intent.capture_id
        {
            return Err(CommandOutputStoreError::Reference(
                "clean terminal preparation crossed capture intent or publication".into(),
            ));
        }
        let SensitiveOutputJournalStageV2::Published {
            published_store_head,
            ..
        } = clean_publication.v2_published().stage()
        else {
            return Err(CommandOutputStoreError::Manifest(
                "clean terminal preparation requires exact v2 Published evidence".into(),
            ));
        };
        if published_store_head != expected_published_head {
            return Err(CommandOutputStoreError::Reference(
                "clean terminal preparation expected a different published head".into(),
            ));
        }
        let current_v2 = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        if &current_v2 != clean_publication.v2_published() {
            return Err(CommandOutputStoreError::Reference(
                "clean terminal preparation v2 Published prefix changed".into(),
            ));
        }
        let current_observation =
            sensitive_output_terminal_observation_store::reopen(self, &intent.capture_id)?
                .ok_or_else(|| CommandOutputStoreError::ReconciliationRequired {
                    capture_id: Some(intent.capture_id.clone()),
                    source: Box::new(intent.source.clone()),
                    expected_reference: Some(Box::new(
                        clean_publication.artifact_reference().clone(),
                    )),
                    reason: "clean terminal preparation lost its immutable terminal observation"
                        .into(),
                })?;
        if current_observation != *clean_publication.observation() {
            return Err(CommandOutputStoreError::Reference(
                "clean terminal preparation observation changed or crossed".into(),
            ));
        }
        let terminal = CommandOutputCaptureCanonicalPayloadV1::try_new(
            schema,
            canonical_terminal_bytes,
            command_output_journal::MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES,
        )?;
        let acquired = clean_publication.v2_published().acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "clean terminal preparation lost its acquired anchor".into(),
            )
        })?;
        let launch_intended_store_head = clean_publication
            .v2_published()
            .launch_intended_store_head()
            .ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "clean terminal preparation lost its launch head".into(),
                )
            })?;
        let fenced_v1_recovery =
            command_output_journal::prepare_sensitive_clean_terminal_under_claim(
                self,
                intent,
                claim,
                clean_publication.reconciliation_claim(),
                acquired,
                launch_intended_store_head,
                clean_publication.artifact_reference(),
                expected_published_head,
                &terminal,
            )?;
        let terminal_prepared_store_head = fenced_v1_recovery
            .terminal_prepared_store_head()
            .cloned()
            .ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "clean terminal preparation lost exact TerminalPrepared head".into(),
                )
            })?;
        let v2_after = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        let observation_after =
            sensitive_output_terminal_observation_store::reopen(self, &intent.capture_id)?
                .ok_or_else(|| {
                    CommandOutputStoreError::Manifest(
                        "clean terminal preparation lost its observation after append".into(),
                    )
                })?;
        if v2_after != current_v2 || observation_after != current_observation {
            return Err(CommandOutputStoreError::Manifest(
                "clean terminal preparation changed v2 or observation custody".into(),
            ));
        }
        let result = SensitiveOutputCleanTerminalPreparationV1 {
            clean_publication: clean_publication.clone(),
            v2_published: current_v2,
            terminal,
            terminal_prepared_store_head,
            fenced_v1_recovery,
            reconciliation_claim: claim.clone(),
            expected_published_head: expected_published_head.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    #[cfg(all(test, feature = "test-support"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the test-only crash seam mirrors every authority input of the production terminal boundary"
    )]
    pub(crate) fn inject_sensitive_output_clean_terminal_preparation_cut(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_published_head: &CommandOutputCaptureStoreHeadV1,
        schema: &str,
        canonical_bytes: Vec<u8>,
        cut: SensitiveOutputCleanTerminalPreparationTestCut,
    ) -> Result<(), CommandOutputStoreError> {
        let cut = match cut {
            SensitiveOutputCleanTerminalPreparationTestCut::TempTorn => {
                command_output_journal::InjectedRecordPublicationCut::TempTorn
            }
            SensitiveOutputCleanTerminalPreparationTestCut::TempValid => {
                command_output_journal::InjectedRecordPublicationCut::TempValid
            }
            SensitiveOutputCleanTerminalPreparationTestCut::TempSynced => {
                command_output_journal::InjectedRecordPublicationCut::TempSynced
            }
            SensitiveOutputCleanTerminalPreparationTestCut::Final => {
                command_output_journal::InjectedRecordPublicationCut::Final
            }
        };
        command_output_journal::inject_sensitive_clean_terminal_prepared_record_cut_under_claim(
            self,
            intent,
            claim,
            expected_published_head,
            schema,
            canonical_bytes,
            cut,
        )
    }

    /// Appends bounded exact terminal-response bytes after verifying the
    /// expected `Published` store head and immutable artifact again.
    ///
    /// # Errors
    ///
    /// Returns reconciliation-required for a stale head, non-published state,
    /// changed artifact/name, active writer, or persistence failure.
    pub fn prepare_capture_terminal(
        &self,
        capture_id: &str,
        expected_published_head: &CommandOutputCaptureStoreHeadV1,
        schema: impl Into<String>,
        canonical_terminal_bytes: Vec<u8>,
    ) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
        expected_published_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        let capture_id = CommandOutputCaptureId::parse(capture_id.to_owned())?;
        let terminal = CommandOutputCaptureCanonicalPayloadV1::try_new(
            schema,
            canonical_terminal_bytes,
            command_output_journal::MAX_CAPTURE_TERMINAL_PAYLOAD_BYTES,
        )?;
        command_output_journal::prepare_terminal(
            self,
            &capture_id,
            expected_published_head,
            terminal,
        )
    }

    /// Resolves an exact clean-v2 Unknown terminal under a core-issued fence.
    ///
    /// Unlike the generic v1 API, this boundary requires the current terminal
    /// v2 clean receipt, detector policy, acquisition, and v1
    /// `TerminalPrepared` head to agree before the private fenced transition is
    /// invoked. The core-requested head remains the original `Acquired` head,
    /// while the independently observed current head remains the exact
    /// `TerminalPrepared` head. It rereads the unchanged clean receipt after
    /// resolution.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for a missing v2 journal, a rejection or
    /// partial branch, crossed policy/request/acquisition, a noncurrent v1
    /// terminal head, stale claim or observed fence, changed clean receipt, or
    /// any underlying physical-resolution failure.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the clean-v2 boundary joins independent policy, terminal, claim, and observed-head authority explicitly"
    )]
    pub fn resolve_sensitive_output_clean_unknown_capture_v2<F>(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal_store_head: &CommandOutputCaptureStoreHeadV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        observed_store_head: &CommandOutputCaptureStoreHeadV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
        reconciled_at: F,
    ) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>
    where
        F: FnOnce() -> Result<u64, CommandOutputStoreError>,
    {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        acquired
            .validate_against(intent)
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        terminal_store_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        observed_store_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
        if claim.capture_id != intent.capture_id || acquired.capture_id != intent.capture_id {
            return Err(CommandOutputStoreError::Reference(
                "clean-v2 Unknown resolution crossed the capture intent".into(),
            ));
        }

        let clean_before = sensitive_output_journal::read_clean(self, &intent.capture_id)?
            .ok_or_else(|| {
                CommandOutputStoreError::ReconciliationRequired {
                    capture_id: Some(intent.capture_id.clone()),
                    source: Box::new(intent.source.clone()),
                    expected_reference: None,
                    reason: "clean-v2 Unknown resolution requires a complete current TerminalPrepared receipt"
                        .into(),
                }
            })?;
        clean_before.validate_request_binding(
            &intent.source.runner_session_id,
            &intent.source.effect_id,
            &intent.source.request_digest,
            acquired,
        )?;
        if clean_before.detector_policy != *detector_policy
            || clean_before.terminal_prepared_store_head != *terminal_store_head
        {
            return Err(CommandOutputStoreError::Reference(
                "clean-v2 Unknown resolution crossed detector policy or terminal head".into(),
            ));
        }
        let v2_before = sensitive_output_journal::read_recovery(self, &intent.capture_id)?;
        let SensitiveOutputJournalStageV2::TerminalPrepared {
            terminal_prepared_store_head,
            terminal_record_digest,
            termination,
            terminal_prepared_at_unix_ms,
        } = v2_before.stage()
        else {
            return Err(CommandOutputStoreError::Reference(
                "clean-v2 Unknown resolution requires exact v2 TerminalPrepared state".into(),
            ));
        };
        if v2_before.head() != &clean_before.terminal_prepared_journal_head
            || terminal_prepared_store_head != &clean_before.terminal_prepared_store_head
            || terminal_record_digest != &clean_before.terminal_record_digest
            || termination != &clean_before.termination
            || terminal_prepared_at_unix_ms != &clean_before.terminal_prepared_at_unix_ms
        {
            return Err(CommandOutputStoreError::Manifest(
                "clean-v2 TerminalPrepared stage differs from its current receipt".into(),
            ));
        }
        let v1_before = self.reopen_capture(&intent.capture_id)?;
        if v1_before.state() != CommandOutputCaptureJournalStateV1::TerminalPrepared
            || v1_before.acquired() != Some(acquired)
            || v1_before.terminal_prepared_store_head() != Some(terminal_store_head)
            || v1_before.store_head() != observed_store_head
            || observed_store_head != terminal_store_head
            || v1_before.expected_reference().is_none()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(intent.capture_id.clone()),
                source: Box::new(intent.source.clone()),
                expected_reference: v1_before.expected_reference().cloned().map(Box::new),
                reason:
                    "clean-v2 Unknown resolution lacks exact current v1 TerminalPrepared custody"
                        .into(),
            });
        }

        let resolved = command_output_journal::resolve_core_acquired_terminal_restart(
            self,
            intent,
            acquired,
            terminal_store_head,
            claim,
            observed_store_head,
            reconciled_at,
        )?;
        let clean_after = sensitive_output_journal::read_clean(self, &intent.capture_id)?
            .ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "clean-v2 receipt disappeared after fenced Unknown resolution".into(),
                )
            })?;
        if clean_after != clean_before {
            return Err(CommandOutputStoreError::Manifest(
                "clean-v2 receipt changed during fenced Unknown resolution".into(),
            ));
        }
        Ok(resolved)
    }

    /// Reconciles one exact capture after restart under a core-issued
    /// monotonic fencing claim, without recreating execution authority.
    ///
    /// `expected_head` is absent only when core has no physical acquisition:
    /// this atomically creates an `Intent -> CleanupIntended -> Cleaned`
    /// tombstone if the journal is physically absent, or cleans an exact
    /// pre-existing intent-only journal. Every acquired-or-later capture must
    /// supply its exact durable store head. A valid interrupted record is
    /// rolled forward and a torn record is removed while the same claim fence
    /// and writer lease are held. Published, terminal-prepared, and cleaned
    /// lifecycle heads are idempotent readbacks.
    ///
    /// # Errors
    ///
    /// Returns reconciliation-required or a contract error for a crossed
    /// Intent, claim, source, private-state root, lifecycle head, recovery
    /// fence, pending record, active writer, or physical object identity.
    pub fn reconcile_capture_restart(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_head: Option<&CommandOutputCaptureStoreHeadV1>,
    ) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
        self.reject_generic_sensitive_output_mutation(
            &intent.capture_id,
            "restart reconciliation",
        )?;
        command_output_journal::reconcile_capture_restart(self, intent, claim, expected_head)
    }

    /// Performs exact restart cleanup under a core-issued monotonic fencing
    /// claim and one expected immutable lifecycle head.
    ///
    /// The claim is durably appended to a separate recovery-fence chain before
    /// any working-name mutation. A higher epoch permanently rejects every
    /// stale owner even after its wall-clock claim expires.
    ///
    /// # Errors
    ///
    /// Returns reconciliation-required for a crossed/stale claim or head,
    /// partial/changed namespace, published capture, or any unlink/durability
    /// proof failure. `Cleaned` is appended only after held descriptors prove
    /// every original object has link count zero.
    pub fn cleanup_capture(
        &self,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        expected_head: &CommandOutputCaptureStoreHeadV1,
    ) -> Result<CommandOutputCaptureRecovery, CommandOutputStoreError> {
        self.reject_generic_sensitive_output_mutation(&claim.capture_id, "restart cleanup")?;
        command_output_journal::cleanup_capture(self, claim, expected_head)
    }

    /// Resolves an immutable Unknown terminal under one exact physical fence
    /// and returns the final recovery joined to its full core receipt.
    ///
    /// `observed_store_head` must still be the exact stable head seen by the
    /// caller when this method acquires the journal lease. The requested
    /// `terminal_store_head` may be that head or an exact historical head when
    /// a prior runner/core cut already advanced physical resolution. The
    /// method never returns a bare recovery after mutating or reading through
    /// the claim fence. `reconciled_at` is invoked only after the lease-held
    /// physical transition and final readback complete, so the receipt cannot
    /// be stamped with a time sampled before slow cleanup work.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for any crossed Intent, acquisition,
    /// Unknown terminal, claim, observed head, physical object, pending record,
    /// final readback, timestamp, or receipt field.
    #[allow(
        clippy::too_many_arguments,
        reason = "the public boundary joins every independent Unknown-resolution authority explicitly"
    )]
    pub fn resolve_unknown_capture<F>(
        &self,
        intent: &CommandOutputCaptureIntentV1,
        acquired: &CommandOutputCaptureAcquiredV1,
        terminal_store_head: &CommandOutputCaptureStoreHeadV1,
        claim: &CommandOutputCaptureReconciliationClaimV1,
        observed_store_head: &CommandOutputCaptureStoreHeadV1,
        reconciled_at: F,
    ) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>
    where
        F: FnOnce() -> Result<u64, CommandOutputStoreError>,
    {
        self.reject_generic_sensitive_output_mutation(&intent.capture_id, "Unknown resolution")?;
        command_output_journal::resolve_unknown_capture(
            self,
            intent,
            acquired,
            terminal_store_head,
            claim,
            observed_store_head,
            reconciled_at,
        )
    }

    /// Reserves two separate raw stream files under one authenticated byte bound.
    ///
    /// The returned stream writers can be moved to separate scoped threads.
    /// Their append calls share one atomic aggregate quota, but compute their
    /// content commitments independently. A caller should update its inline
    /// command evidence from the same chunk before or after each successful
    /// append; this API deliberately does not mint inline evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid source, a bound above the hard ceiling,
    /// a stale root, or failure to create private temporary custody.
    pub fn reserve_capture(
        &self,
        source: CommandOutputArtifactSourceV1,
        authenticated_maximum_bytes: u64,
    ) -> Result<CommandOutputCapture, CommandOutputStoreError> {
        self.reserve_capture_with_probe(source, authenticated_maximum_bytes, |_| Ok(()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "reservation keeps every file-creation checkpoint under one exact rollback custody before releasing stream writers"
    )]
    fn reserve_capture_with_probe(
        &self,
        source: CommandOutputArtifactSourceV1,
        authenticated_maximum_bytes: u64,
        mut probe: impl FnMut(ReservationCheckpoint) -> Result<(), String>,
    ) -> Result<CommandOutputCapture, CommandOutputStoreError> {
        self.validate_root()?;
        source.validate().map_err(|error| {
            CommandOutputStoreError::Source(format!("core source validation failed: {error}"))
        })?;
        if authenticated_maximum_bytes > MAX_COMMAND_OUTPUT_ARTIFACT_BYTES {
            return Err(CommandOutputStoreError::Source(format!(
                "authenticated maximum {authenticated_maximum_bytes} exceeds hard ceiling {MAX_COMMAND_OUTPUT_ARTIFACT_BYTES}"
            )));
        }
        let source_digest = source_name_digest(&source)?;
        let capture_id = NEXT_CAPTURE.fetch_add(1, Ordering::Relaxed);
        let (temp_name, temp, temp_identity) = self.create_temp_directory(&source, &mut probe)?;
        let mut reservation = PendingCaptureReservation {
            store: self.clone(),
            source: source.clone(),
            temp_name,
            temp,
            temp_identity,
            stdout: None,
            stderr: None,
        };

        let stdout =
            match create_private_file_unconfigured(&reservation.temp, Path::new(STDOUT_FILE)) {
                Ok(file) => file,
                Err(error) => return Err(reservation.fail(error)),
            };
        reservation.stdout = Some(PendingReservationFile {
            file: stdout,
            object: None,
        });
        let stdout_object = match reservation
            .stdout
            .as_ref()
            .expect("stdout custody was just installed")
            .file
            .metadata()
        {
            Ok(metadata) => object_identity(&metadata),
            Err(error) => {
                let error = io_error(
                    "inspect newly opened stdout reservation",
                    Path::new(STDOUT_FILE),
                    &error,
                );
                return Err(reservation.fail(error));
            }
        };
        reservation
            .stdout
            .as_mut()
            .expect("stdout custody was just installed")
            .object = Some(stdout_object);
        if let Err(reason) = probe(ReservationCheckpoint::StdoutOpened) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StdoutOpened,
                &reason,
            )));
        }
        if let Err(error) = reservation
            .stdout
            .as_ref()
            .expect("stdout custody remains installed")
            .file
            .set_permissions(Permissions::from_mode(0o600))
        {
            let error = io_error(
                "set private stdout reservation mode",
                Path::new(STDOUT_FILE),
                &error,
            );
            return Err(reservation.fail(error));
        }
        if let Err(reason) = probe(ReservationCheckpoint::StdoutModeSet) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StdoutModeSet,
                &reason,
            )));
        }
        let stdout_identity = match validate_private_file(
            &reservation
                .stdout
                .as_ref()
                .expect("stdout custody remains installed")
                .file,
            Path::new(STDOUT_FILE),
            Some(0),
            0,
        ) {
            Ok(identity) => identity,
            Err(error) => return Err(reservation.fail(error)),
        };
        if let Err(reason) = probe(ReservationCheckpoint::StdoutMetadataValidated) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StdoutMetadataValidated,
                &reason,
            )));
        }

        let stderr =
            match create_private_file_unconfigured(&reservation.temp, Path::new(STDERR_FILE)) {
                Ok(file) => file,
                Err(error) => return Err(reservation.fail(error)),
            };
        reservation.stderr = Some(PendingReservationFile {
            file: stderr,
            object: None,
        });
        let stderr_object = match reservation
            .stderr
            .as_ref()
            .expect("stderr custody was just installed")
            .file
            .metadata()
        {
            Ok(metadata) => object_identity(&metadata),
            Err(error) => {
                let error = io_error(
                    "inspect newly opened stderr reservation",
                    Path::new(STDERR_FILE),
                    &error,
                );
                return Err(reservation.fail(error));
            }
        };
        reservation
            .stderr
            .as_mut()
            .expect("stderr custody was just installed")
            .object = Some(stderr_object);
        if let Err(reason) = probe(ReservationCheckpoint::StderrOpened) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StderrOpened,
                &reason,
            )));
        }
        if let Err(error) = reservation
            .stderr
            .as_ref()
            .expect("stderr custody remains installed")
            .file
            .set_permissions(Permissions::from_mode(0o600))
        {
            let error = io_error(
                "set private stderr reservation mode",
                Path::new(STDERR_FILE),
                &error,
            );
            return Err(reservation.fail(error));
        }
        if let Err(reason) = probe(ReservationCheckpoint::StderrModeSet) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StderrModeSet,
                &reason,
            )));
        }
        let stderr_identity = match validate_private_file(
            &reservation
                .stderr
                .as_ref()
                .expect("stderr custody remains installed")
                .file,
            Path::new(STDERR_FILE),
            Some(0),
            0,
        ) {
            Ok(identity) => identity,
            Err(error) => return Err(reservation.fail(error)),
        };
        if let Err(reason) = probe(ReservationCheckpoint::StderrMetadataValidated) {
            return Err(reservation.fail(reservation_probe_error(
                ReservationCheckpoint::StderrMetadataValidated,
                &reason,
            )));
        }
        if stdout_identity.object == stderr_identity.object {
            return Err(reservation.fail(CommandOutputStoreError::Artifact(
                "stdout.raw and stderr.raw must be distinct filesystem objects".into(),
            )));
        }
        let (temp_name, temp, temp_identity, stdout, stderr) = reservation.into_ready_parts();
        let shared = Arc::new(CaptureShared {
            source,
            source_digest,
            capture_id,
            journal_capture_id: None,
            authenticated_maximum_bytes,
            reserved_bytes: AtomicU64::new(0),
            poisoned: AtomicBool::new(false),
        });
        Ok(CommandOutputCapture {
            stdout: CommandOutputStreamCapture::new(
                Arc::clone(&shared),
                CommandOutputStreamV1::Stdout,
                stdout,
                stdout_identity,
            ),
            stderr: CommandOutputStreamCapture::new(
                Arc::clone(&shared),
                CommandOutputStreamV1::Stderr,
                stderr,
                stderr_identity,
            ),
            publisher: CommandOutputPublisher {
                store: self.clone(),
                shared,
                temp_name,
                temp,
                temp_identity,
                journal: None,
                finished_store_head: None,
                sensitive_output_v2: false,
            },
        })
    }

    /// Reopens and fully verifies one exact path-free artifact reference.
    ///
    /// This operation never creates, removes, renames, or repairs an entry.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale root, malformed reference, wrong derived
    /// name, unsafe file, noncanonical manifest, missing/extra entry, crossed
    /// role/source, content mismatch, or replacement during verification.
    #[allow(
        clippy::too_many_lines,
        reason = "exact reopen keeps the manifest, three fixed entries, identities, commitments, and root/name revalidation in one auditable sequence"
    )]
    pub fn reopen(
        &self,
        reference: &CommandOutputArtifactSetReferenceV1,
    ) -> Result<ValidatedCommandOutputArtifactSet, CommandOutputStoreError> {
        self.validate_root()?;
        validate_reference_bound(reference)?;
        let source_digest = source_name_digest(&reference.source)?;
        let directory_name = final_directory_name(&source_digest);
        let directory = self
            .inner
            .root
            .open_dir_nofollow(&directory_name)
            .map_err(|error| {
                io_error(
                    "open referenced command-output artifact",
                    Path::new(&directory_name),
                    &error,
                )
            })?;
        let directory_identity =
            validate_private_directory(&directory, "command-output artifact directory")?;

        let mut manifest_file = open_private_file(&directory, Path::new(MANIFEST_FILE))?;
        let manifest_identity = validate_private_file(
            &manifest_file,
            Path::new(MANIFEST_FILE),
            None,
            MAX_MANIFEST_BYTES,
        )?;
        let manifest_bytes = read_file_twice_stable(
            &mut manifest_file,
            Path::new(MANIFEST_FILE),
            MAX_MANIFEST_BYTES,
        )?;
        let stored: StoredCommandOutputManifestV1 = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        let canonical = canonical_manifest(&stored)?;
        if canonical != manifest_bytes {
            return Err(CommandOutputStoreError::Manifest(
                "manifest is not the exact canonical JSON encoding".into(),
            ));
        }
        let reconstructed = stored.into_reference()?;
        if &reconstructed != reference {
            return Err(CommandOutputStoreError::Reference(
                "typed reference differs from the canonical stored manifest".into(),
            ));
        }

        let mut stdout = open_private_file(&directory, Path::new(STDOUT_FILE))?;
        let stdout_identity = validate_private_file(
            &stdout,
            Path::new(STDOUT_FILE),
            Some(reference.stdout.byte_length),
            reference.stdout.byte_length,
        )?;
        verify_stream_file(&mut stdout, Path::new(STDOUT_FILE), &reference.stdout)?;

        let mut stderr = open_private_file(&directory, Path::new(STDERR_FILE))?;
        let stderr_identity = validate_private_file(
            &stderr,
            Path::new(STDERR_FILE),
            Some(reference.stderr.byte_length),
            reference.stderr.byte_length,
        )?;
        verify_stream_file(&mut stderr, Path::new(STDERR_FILE), &reference.stderr)?;
        if stdout_identity.object == stderr_identity.object {
            return Err(CommandOutputStoreError::Artifact(
                "stdout.raw and stderr.raw resolve to the same filesystem object".into(),
            ));
        }

        let names = directory_entry_names(&directory, &directory_name)?;
        let expected_names = BTreeSet::from([
            MANIFEST_FILE.to_string(),
            STDOUT_FILE.to_string(),
            STDERR_FILE.to_string(),
        ]);
        if names != expected_names {
            return Err(CommandOutputStoreError::Manifest(
                "artifact directory contains missing or unexpected entries".into(),
            ));
        }
        validate_named_file_identity(
            &directory,
            Path::new(MANIFEST_FILE),
            manifest_identity,
            MAX_MANIFEST_BYTES,
        )?;
        validate_named_file_identity(
            &directory,
            Path::new(STDOUT_FILE),
            stdout_identity,
            reference.stdout.byte_length,
        )?;
        validate_named_file_identity(
            &directory,
            Path::new(STDERR_FILE),
            stderr_identity,
            reference.stderr.byte_length,
        )?;
        self.validate_named_directory(&directory_name, directory_identity)?;
        self.validate_root()?;

        Ok(ValidatedCommandOutputArtifactSet {
            store: self.clone(),
            reference: reference.clone(),
            directory_name,
            directory,
            directory_identity,
            manifest_file,
            manifest_identity,
            stdout,
            stdout_identity,
            stderr,
            stderr_identity,
            capture_id: None,
            capture_store_head: None,
            capture_finished_store_head: None,
            capture_published_store_head: None,
        })
    }

    /// Reconciles a publication whose final durability proof was interrupted.
    ///
    /// The exact reference must reopen before and after a root-directory sync.
    /// No reference is minted and no stored bytes are modified.
    ///
    /// # Errors
    ///
    /// Returns a typed reconciliation error unless both complete validations
    /// and the namespace durability operation succeed.
    pub fn reconcile(
        &self,
        expected: &CommandOutputArtifactSetReferenceV1,
    ) -> Result<ValidatedCommandOutputArtifactSet, CommandOutputStoreError> {
        self.reopen(expected).map_err(|error| {
            reconciliation_error(
                &expected.source,
                Some(expected),
                format!("initial exact reopen failed: {error}"),
            )
        })?;
        sync_directory(&self.inner.root).map_err(|error| {
            reconciliation_error(
                &expected.source,
                Some(expected),
                format!("reconciled namespace sync failed: {error}"),
            )
        })?;
        self.reopen(expected).map_err(|error| {
            reconciliation_error(
                &expected.source,
                Some(expected),
                format!("post-sync exact reopen failed: {error}"),
            )
        })
    }

    fn validate_root(&self) -> Result<(), CommandOutputStoreError> {
        self.inner
            .path_anchor
            .validate("command-output store")
            .map_err(|error| CommandOutputStoreError::Root(error.to_string()))?;
        if validate_private_directory(&self.inner.root, "retained private-state root")?
            != self.inner.root_identity
        {
            return Err(CommandOutputStoreError::Root(
                "retained private-state identity, owner, or mode changed".into(),
            ));
        }
        let named = self
            .inner
            .root_parent
            .open_dir_nofollow(&self.inner.root_leaf)
            .map_err(|error| {
                CommandOutputStoreError::Root(format!(
                    "private-state root name no longer resolves without a link: {error}"
                ))
            })?;
        if validate_private_directory(&named, "named private-state root")?
            != self.inner.root_identity
        {
            return Err(CommandOutputStoreError::Root(
                "private-state root name was replaced".into(),
            ));
        }
        Ok(())
    }

    fn validate_named_directory(
        &self,
        name: &str,
        expected: PrivateDirectoryIdentity,
    ) -> Result<(), CommandOutputStoreError> {
        let named = self.inner.root.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "revalidate command-output artifact name",
                Path::new(name),
                &error,
            )
        })?;
        if validate_private_directory(&named, "named command-output artifact")? != expected {
            return Err(CommandOutputStoreError::Root(
                "command-output artifact name changed during validation".into(),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "directory reservation keeps create/open/mode/metadata cuts and exact rollback visibly ordered"
    )]
    fn create_temp_directory(
        &self,
        source: &CommandOutputArtifactSourceV1,
        probe: &mut impl FnMut(ReservationCheckpoint) -> Result<(), String>,
    ) -> Result<(String, Dir, PrivateDirectoryIdentity), CommandOutputStoreError> {
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let name = format!("{TEMP_PREFIX}{}-{sequence}", std::process::id());
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match self.inner.root.create_dir_with(&name, &builder) {
                Ok(()) => {
                    if let Err(reason) = probe(ReservationCheckpoint::DirectoryCreated) {
                        return Err(reconciliation_error(
                            source,
                            None,
                            format!(
                                "{}; the directory was created before a stable object identity could be retained",
                                reservation_probe_error(
                                    ReservationCheckpoint::DirectoryCreated,
                                    &reason
                                )
                            ),
                        ));
                    }
                    let directory = match self.inner.root.open_dir_nofollow(&name) {
                        Ok(directory) => directory,
                        Err(error) => {
                            return Err(reconciliation_error(
                                source,
                                None,
                                format!(
                                    "temporary directory was created but exact open failed: {}",
                                    io_error(
                                        "open command-output temporary directory",
                                        Path::new(&name),
                                        &error,
                                    )
                                ),
                            ));
                        }
                    };
                    let object = match validate_owned_directory_object(
                        &directory,
                        "new command-output temporary directory",
                    ) {
                        Ok(object) => object,
                        Err(error) => {
                            return Err(reconciliation_error(
                                source,
                                None,
                                format!(
                                    "temporary directory was created and opened but no cleanup identity could be retained: {error}"
                                ),
                            ));
                        }
                    };
                    if let Err(reason) = probe(ReservationCheckpoint::DirectoryOpened) {
                        let primary = reservation_probe_error(
                            ReservationCheckpoint::DirectoryOpened,
                            &reason,
                        );
                        return Err(
                            self.fail_created_empty_temp(source, &name, directory, object, primary)
                        );
                    }
                    if let Err(error) =
                        directory.set_permissions(Path::new("."), Permissions::from_mode(0o700))
                    {
                        let primary = io_error(
                            "set command-output temporary mode",
                            Path::new(&name),
                            &error,
                        );
                        return Err(
                            self.fail_created_empty_temp(source, &name, directory, object, primary)
                        );
                    }
                    if let Err(reason) = probe(ReservationCheckpoint::DirectoryModeSet) {
                        let primary = reservation_probe_error(
                            ReservationCheckpoint::DirectoryModeSet,
                            &reason,
                        );
                        return Err(
                            self.fail_created_empty_temp(source, &name, directory, object, primary)
                        );
                    }
                    let identity = match validate_private_directory(
                        &directory,
                        "command-output temporary directory",
                    ) {
                        Ok(identity) => identity,
                        Err(primary) => {
                            return Err(self.fail_created_empty_temp(
                                source, &name, directory, object, primary,
                            ));
                        }
                    };
                    if let Err(reason) = probe(ReservationCheckpoint::DirectoryMetadataValidated) {
                        let primary = reservation_probe_error(
                            ReservationCheckpoint::DirectoryMetadataValidated,
                            &reason,
                        );
                        return Err(
                            self.fail_created_empty_temp(source, &name, directory, object, primary)
                        );
                    }
                    return Ok((name, directory, identity));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(io_error(
                        "create command-output temporary directory",
                        Path::new(&name),
                        &error,
                    ));
                }
            }
        }
        Err(CommandOutputStoreError::Root(
            "could not allocate a unique command-output temporary directory".into(),
        ))
    }

    fn fail_created_empty_temp(
        &self,
        source: &CommandOutputArtifactSourceV1,
        name: &str,
        directory: Dir,
        expected: ObjectIdentity,
        primary: CommandOutputStoreError,
    ) -> CommandOutputStoreError {
        let primary_reason = primary.to_string();
        match self.cleanup_created_empty_temp(name, directory, expected) {
            Ok(()) => primary,
            Err(cleanup) => reconciliation_error(
                source,
                None,
                format!(
                    "temporary directory setup failed: {primary_reason}; exact empty-directory cleanup also failed: {cleanup}"
                ),
            ),
        }
    }

    fn cleanup_created_empty_temp(
        &self,
        name: &str,
        directory: Dir,
        expected: ObjectIdentity,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate_root()?;
        if validate_owned_directory_object(&directory, "retained failed temporary directory")?
            != expected
        {
            return Err(CommandOutputStoreError::Root(
                "retained failed temporary directory changed before cleanup".into(),
            ));
        }
        let named = self.inner.root.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "open failed temporary directory name for cleanup",
                Path::new(name),
                &error,
            )
        })?;
        if validate_owned_directory_object(&named, "named failed temporary directory")? != expected
        {
            return Err(CommandOutputStoreError::Root(
                "failed temporary directory name was replaced before cleanup".into(),
            ));
        }
        if named
            .entries()
            .map_err(|error| {
                io_error(
                    "enumerate failed temporary directory",
                    Path::new(name),
                    &error,
                )
            })?
            .next()
            .is_some()
        {
            return Err(CommandOutputStoreError::Root(
                "failed temporary directory is not empty; refusing recursive cleanup".into(),
            ));
        }
        sync_directory(&named).map_err(|error| {
            io_error(
                "sync failed empty temporary directory",
                Path::new(name),
                &error,
            )
        })?;
        drop(named);
        drop(directory);
        let revalidated = self.inner.root.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "revalidate failed temporary directory name",
                Path::new(name),
                &error,
            )
        })?;
        if validate_owned_directory_object(&revalidated, "revalidated failed temporary directory")?
            != expected
        {
            return Err(CommandOutputStoreError::Root(
                "failed temporary directory name changed before removal".into(),
            ));
        }
        drop(revalidated);
        self.inner.root.remove_dir(name).map_err(|error| {
            io_error(
                "remove failed empty temporary directory",
                Path::new(name),
                &error,
            )
        })?;
        sync_directory(&self.inner.root).map_err(|error| {
            io_error(
                "sync failed temporary-directory removal",
                Path::new(name),
                &error,
            )
        })
    }
}

#[derive(Debug)]
struct CaptureShared {
    source: CommandOutputArtifactSourceV1,
    source_digest: Digest,
    capture_id: u64,
    journal_capture_id: Option<String>,
    authenticated_maximum_bytes: u64,
    reserved_bytes: AtomicU64,
    poisoned: AtomicBool,
}

impl CaptureShared {
    fn reserve_append(&self, additional: usize) -> Result<(), CommandOutputStoreError> {
        let additional = u64::try_from(additional).map_err(|_| {
            self.reconciliation("append length cannot be represented as u64".into(), None)
        })?;
        loop {
            let current = self.reserved_bytes.load(Ordering::Acquire);
            let Some(next) = current.checked_add(additional) else {
                self.poisoned.store(true, Ordering::Release);
                return Err(self.reconciliation("aggregate output length overflowed".into(), None));
            };
            if next > self.authenticated_maximum_bytes {
                self.poisoned.store(true, Ordering::Release);
                return Err(self.reconciliation(
                    format!(
                        "raw output would exceed authenticated maximum {} (attempted {next}); no bytes were silently truncated",
                        self.authenticated_maximum_bytes
                    ),
                    None,
                ));
            }
            if self
                .reserved_bytes
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    fn reconciliation(
        &self,
        reason: String,
        expected: Option<&CommandOutputArtifactSetReferenceV1>,
    ) -> CommandOutputStoreError {
        reconciliation_error_for_capture(
            &self.source,
            self.journal_capture_id.as_deref(),
            expected,
            reason,
        )
    }
}

/// Unsplit custody for one source-bound stdout/stderr capture.
pub struct CommandOutputCapture {
    stdout: CommandOutputStreamCapture,
    stderr: CommandOutputStreamCapture,
    publisher: CommandOutputPublisher,
}

impl CommandOutputCapture {
    /// Splits the reservation into independently movable stdout/stderr writers
    /// and the only publisher capable of consuming their finished custody.
    #[must_use]
    pub fn split(
        self,
    ) -> (
        CommandOutputStreamCapture,
        CommandOutputStreamCapture,
        CommandOutputPublisher,
    ) {
        (self.stdout, self.stderr, self.publisher)
    }

    /// Safely abandons this never-published reservation.
    ///
    /// # Errors
    ///
    /// Returns a reconciliation error rather than deleting anything if the
    /// private temporary name or either file no longer has its captured identity.
    pub fn abandon(self) -> Result<(), CommandOutputStoreError> {
        self.publisher
            .abandon_unpublished(self.stdout.into_custody(), self.stderr.into_custody())
    }

    /// Closes only the exact policy-bound writer-attached prefix before any
    /// durable native-launch boundary exists.
    pub(crate) fn abandon_sensitive_output_prelaunch_v2(
        self,
    ) -> Result<(), CommandOutputStoreError> {
        self.publisher.abandon_sensitive_output_prelaunch_v2(
            self.stdout.into_custody(),
            self.stderr.into_custody(),
        )
    }
}

/// Streaming custody for exactly one raw command-output role.
pub struct CommandOutputStreamCapture {
    shared: Arc<CaptureShared>,
    stream: CommandOutputStreamV1,
    file: File,
    identity: PrivateFileIdentity,
    byte_length: u64,
    hasher: Sha256,
}

impl CommandOutputStreamCapture {
    fn new(
        shared: Arc<CaptureShared>,
        stream: CommandOutputStreamV1,
        file: File,
        identity: PrivateFileIdentity,
    ) -> Self {
        Self {
            shared,
            stream,
            file,
            identity,
            byte_length: 0,
            hasher: Sha256::new(),
        }
    }

    /// Returns the fixed role of this writer.
    #[must_use]
    pub const fn stream(&self) -> CommandOutputStreamV1 {
        self.stream
    }

    /// Returns bytes successfully appended by this writer.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Appends one exact raw chunk without truncation.
    ///
    /// The aggregate quota is atomically reserved before the write. Any quota
    /// or I/O failure poisons the whole capture and is reconciliation-required.
    ///
    /// # Errors
    ///
    /// Returns [`CommandOutputStoreError::ReconciliationRequired`] after a
    /// quota, storage, overflow, or prior-capture failure.
    pub fn append(&mut self, bytes: &[u8]) -> Result<(), CommandOutputStoreError> {
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(self.shared.reconciliation(
                "capture was already poisoned by a stream failure".into(),
                None,
            ));
        }
        self.shared.reserve_append(bytes.len())?;
        if let Err(error) = self.file.write_all(bytes) {
            self.shared.poisoned.store(true, Ordering::Release);
            return Err(self.shared.reconciliation(
                format!("writing {:?} raw bytes failed: {error}", self.stream),
                None,
            ));
        }
        let additional = u64::try_from(bytes.len()).map_err(|_| {
            self.shared.poisoned.store(true, Ordering::Release);
            self.shared.reconciliation(
                "stream output length cannot be represented as u64".into(),
                None,
            )
        })?;
        self.byte_length = self.byte_length.checked_add(additional).ok_or_else(|| {
            self.shared.poisoned.store(true, Ordering::Release);
            self.shared
                .reconciliation("stream output length overflowed".into(), None)
        })?;
        self.hasher.update(bytes);
        Ok(())
    }

    /// Flushes and synchronizes this complete stream, yielding unforgeable
    /// finished custody for publication.
    ///
    /// # Errors
    ///
    /// Returns a failure that retains cleanup custody when the capture was
    /// poisoned, file synchronization fails, or metadata changed.
    pub fn finish(
        mut self,
    ) -> Result<FinishedCommandOutputStream, CommandOutputStreamFinishFailure> {
        let result = (|| {
            if self.shared.poisoned.load(Ordering::Acquire) {
                return Err(self.shared.reconciliation(
                    "cannot finish a capture poisoned by an earlier stream failure".into(),
                    None,
                ));
            }
            self.file.flush().map_err(|error| {
                self.shared.poisoned.store(true, Ordering::Release);
                self.shared.reconciliation(
                    format!("flushing {:?} raw bytes failed: {error}", self.stream),
                    None,
                )
            })?;
            self.file.sync_all().map_err(|error| {
                self.shared.poisoned.store(true, Ordering::Release);
                self.shared.reconciliation(
                    format!("synchronizing {:?} raw bytes failed: {error}", self.stream),
                    None,
                )
            })?;
            let path = stream_path(self.stream);
            let observed =
                validate_private_file(&self.file, path, Some(self.byte_length), self.byte_length)
                    .map_err(|error| {
                    self.shared.reconciliation(
                        format!(
                            "{:?} metadata validation failed at finish: {error}",
                            self.stream
                        ),
                        None,
                    )
                })?;
            if observed.object != self.identity.object {
                return Err(self.shared.reconciliation(
                    format!("{:?} raw file identity changed before finish", self.stream),
                    None,
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.shared.poisoned.store(true, Ordering::Release);
            return Err(CommandOutputStreamFinishFailure {
                error,
                custody: self.into_custody(),
            });
        }
        let digest = digest_from_hasher(self.hasher.clone());
        Ok(FinishedCommandOutputStream {
            shared: self.shared,
            stream: self.stream,
            file: self.file,
            identity: self.identity,
            byte_length: self.byte_length,
            content_digest: digest,
        })
    }

    /// Closes the stream and returns the token required for safe temp cleanup.
    #[must_use]
    pub fn into_custody(self) -> CommandOutputStreamCustody {
        let custody = CommandOutputStreamCustody {
            shared: self.shared,
            stream: self.stream,
            identity: self.identity,
        };
        drop(self.file);
        custody
    }

    fn neutralize_sensitive_output_v2(&mut self) -> Result<(), CommandOutputStoreError> {
        self.file.set_len(0).map_err(|error| {
            self.shared.poisoned.store(true, Ordering::Release);
            self.shared.reconciliation(
                format!(
                    "truncating rejected {:?} staging failed: {error}",
                    self.stream
                ),
                None,
            )
        })?;
        self.file.sync_all().map_err(|error| {
            self.shared.poisoned.store(true, Ordering::Release);
            self.shared.reconciliation(
                format!(
                    "synchronizing rejected {:?} zero length failed: {error}",
                    self.stream
                ),
                None,
            )
        })?;
        let observed = validate_private_file(&self.file, stream_path(self.stream), Some(0), 0)?;
        if observed.object != self.identity.object {
            self.shared.poisoned.store(true, Ordering::Release);
            return Err(self.shared.reconciliation(
                format!("rejected {:?} staging identity changed", self.stream),
                None,
            ));
        }
        self.byte_length = 0;
        self.hasher = Sha256::new();
        Ok(())
    }
}

/// A finish failure that preserves the stream's cleanup custody.
#[derive(Debug)]
pub struct CommandOutputStreamFinishFailure {
    error: CommandOutputStoreError,
    custody: CommandOutputStreamCustody,
}

impl CommandOutputStreamFinishFailure {
    /// Returns the reconciliation failure.
    #[must_use]
    pub const fn error(&self) -> &CommandOutputStoreError {
        &self.error
    }

    /// Separates the error from the token needed to abandon the temp safely.
    #[must_use]
    pub fn into_parts(self) -> (CommandOutputStoreError, CommandOutputStreamCustody) {
        (self.error, self.custody)
    }
}

impl Display for CommandOutputStreamFinishFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for CommandOutputStreamFinishFailure {}

/// Finished, synchronized custody for one complete stream.
pub struct FinishedCommandOutputStream {
    shared: Arc<CaptureShared>,
    stream: CommandOutputStreamV1,
    file: File,
    identity: PrivateFileIdentity,
    byte_length: u64,
    content_digest: Digest,
}

impl FinishedCommandOutputStream {
    /// Returns the exact complete stream commitment.
    #[must_use]
    pub fn artifact(&self) -> CommandOutputStreamArtifactV1 {
        CommandOutputStreamArtifactV1 {
            stream: self.stream,
            byte_length: self.byte_length,
            content_digest: self.content_digest.clone(),
        }
    }

    /// Closes the file and yields custody required for safe temp cleanup.
    #[must_use]
    pub fn into_custody(self) -> CommandOutputStreamCustody {
        let custody = CommandOutputStreamCustody {
            shared: self.shared,
            stream: self.stream,
            identity: self.identity,
        };
        drop(self.file);
        custody
    }
}

/// Unforgeable closed-file custody used only to abandon an unpublished temp.
#[derive(Debug)]
pub struct CommandOutputStreamCustody {
    shared: Arc<CaptureShared>,
    stream: CommandOutputStreamV1,
    identity: PrivateFileIdentity,
}

/// Sole publication capability for one temporary command-output capture.
pub struct CommandOutputPublisher {
    store: CapabilityCommandOutputStore,
    shared: Arc<CaptureShared>,
    temp_name: String,
    temp: Dir,
    temp_identity: PrivateDirectoryIdentity,
    journal: Option<command_output_journal::CaptureJournalLease>,
    finished_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    sensitive_output_v2: bool,
}

/// Exact secret-free result of rejected-output staging cleanup.
pub(crate) struct SensitiveOutputAbandonmentV2 {
    pub(crate) recovery: CommandOutputCaptureRecovery,
    pub(crate) journal_receipt: SensitiveOutputRejectionJournalReceiptV2,
}

impl CommandOutputPublisher {
    /// Returns the exact capture ID for journaled current-path custody.
    #[must_use]
    pub fn capture_id(&self) -> Option<&str> {
        self.journal
            .as_ref()
            .map(|journal| journal.capture_id().as_str())
    }

    /// Returns the current immutable journal head for current-path custody.
    #[must_use]
    pub fn journal_head(&self) -> Option<CommandOutputCaptureStoreHeadV1> {
        self.journal
            .as_ref()
            .map(command_output_journal::CaptureJournalLease::head)
    }

    /// Reopens and returns the exact acquired anchor for this v2 capture.
    ///
    /// This crate-private getter is evidence-only. It reads the current v2
    /// journal instead of trusting a caller field and grants no execution,
    /// cleanup, retry, publication, verification, or completion authority.
    pub(crate) fn sensitive_output_acquired_evidence_v1(
        &self,
    ) -> Result<CommandOutputCaptureAcquiredV1, CommandOutputStoreError> {
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output acquired evidence requires a v2 capture".into(),
            ));
        }
        let capture_id = self.capture_id().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "sensitive-output acquired evidence requires journaled capture identity".into(),
            )
        })?;
        let recovery = sensitive_output_journal::read_recovery(&self.store, capture_id)?;
        let acquired = recovery.acquired().cloned().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output journal has no acquired evidence".into(),
            )
        })?;
        if acquired.source != self.shared.source {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output acquired evidence crossed publisher custody".into(),
            ));
        }
        Ok(acquired)
    }

    /// Publishes one crate-authenticated terminal observation exactly once in
    /// this capture's private sensitive-output journal namespace.
    ///
    /// This custody operation is deliberately crate-private: external callers
    /// cannot manufacture terminal observations. Exact same-byte repetition
    /// is idempotent; crossed bytes fail without overwrite or deletion. The
    /// sidecar grants no lifecycle authority by itself.
    pub(crate) fn publish_sensitive_output_terminal_observation_v1(
        &self,
        observation: &crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1,
    ) -> Result<
        crate::sensitive_output_terminal_observation::SensitiveOutputTerminalObservationV1,
        CommandOutputStoreError,
    > {
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "terminal-observation custody requires a v2 sensitive-output capture".into(),
            ));
        }
        let capture_id = self.capture_id().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "terminal-observation custody requires journaled capture identity".into(),
            )
        })?;
        sensitive_output_terminal_observation_store::publish_once(
            &self.store,
            capture_id,
            observation,
        )
    }

    /// Returns a secret-free reconciliation requirement without mutating or
    /// deleting the retained staging objects. This is the only safe fallback
    /// after the streaming detector has observed a policy match but cleanup
    /// proof or neutralization has not completed.
    pub(crate) fn sensitive_output_reconciliation_required(&self) -> CommandOutputStoreError {
        reconciliation_error_for_capture(
            &self.shared.source,
            self.capture_id(),
            None,
            "sensitive output was detected; exact staging remains private until command-domain cleanup and descriptor-held neutralization can be proven"
                .into(),
        )
    }

    /// Returns the secret-free typed disposition for a command whose durable
    /// launch boundary exists but whose output branch and native cleanup are
    /// not proven. Dropping the live custody after constructing this value
    /// deliberately retains both private staging objects for zero-first
    /// generation-four quarantine; it never appends a v1 cleanup plan.
    pub(crate) fn unclassified_sensitive_output_reconciliation_required(
        &self,
    ) -> CommandOutputStoreError {
        reconciliation_error_for_capture(
            &self.shared.source,
            self.capture_id(),
            None,
            "policy-bound LaunchIntended output remains unclassified; retain private staging until independently proven native cleanup can authorize generation-four zero-first quarantine"
                .into(),
        )
    }

    /// Durably appends only v2 generation 5, `SensitiveOutputDetected`, before
    /// whole-domain termination is requested. Generations 1--4 must already
    /// have been appended at their real boundaries.
    pub(crate) fn record_sensitive_output_detected_v2(
        &self,
        launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
        let journal = self.journal.as_ref().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "sensitive-output detection requires journaled capture custody".into(),
            )
        })?;
        if self.journal_head().as_ref() != Some(launch_intended_store_head) {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output detection crossed the exact LaunchIntended v1 head".into(),
            ));
        }
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output detection requires a v2 reservation".into(),
            ));
        }
        crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
            .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
        sensitive_output_journal::record_detected(&self.store, journal.capture_id().as_str())
    }

    /// Persists the exact bounded native-launch binding before a backend may
    /// cross its launch boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for legacy custody, a noncanonical/bounded payload, a
    /// stale journal head, or failure to durably append `LaunchIntended`.
    pub fn record_launch_intended(
        &mut self,
        schema: impl Into<String>,
        canonical_binding_bytes: Vec<u8>,
    ) -> Result<CommandOutputCaptureStoreHeadV1, CommandOutputStoreError> {
        let payload = CommandOutputCaptureCanonicalPayloadV1::try_new(
            schema,
            canonical_binding_bytes,
            command_output_journal::MAX_CAPTURE_BINDING_PAYLOAD_BYTES,
        )?;
        let journal = self.journal.as_mut().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "legacy output custody cannot authorize a current native launch".into(),
            )
        })?;
        journal.append_launch_intended(payload)?;
        Ok(journal.head())
    }

    /// Appends the existing v1 launch record and then the independently
    /// chained v2 generation-4 launch boundary.
    pub(crate) fn record_launch_intended_v2(
        &mut self,
        schema: impl Into<String>,
        canonical_binding_bytes: Vec<u8>,
        core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
    ) -> Result<CommandOutputCaptureStoreHeadV1, CommandOutputStoreError> {
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "v2 launch requires v2 writer custody".into(),
            ));
        }
        let store = self.store.clone();
        let capture_id = self
            .capture_id()
            .ok_or_else(|| CommandOutputStoreError::Source("v2 capture ID is absent".into()))?
            .to_owned();
        let head = self.record_launch_intended(schema, canonical_binding_bytes)?;
        sensitive_output_journal::record_launch_intended(
            &store,
            &capture_id,
            &head,
            core_dump_suppression,
        )?;
        Ok(head)
    }

    /// Appends the v2 clean scan decision only after both stream scanners
    /// reached EOF without a policy match.
    pub(crate) fn record_sensitive_output_scanned_clean_v2(
        &self,
    ) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "clean v2 scan record requires v2 capture custody".into(),
            ));
        }
        let capture_id = self
            .capture_id()
            .ok_or_else(|| CommandOutputStoreError::Source("v2 capture ID is absent".into()))?;
        sensitive_output_journal::record_scanned_clean(&self.store, capture_id)
    }

    /// Replaces both rejected staging streams with synchronized, exact empty
    /// objects before frozen-v1 cleanup is permitted to inspect file identity.
    /// A failure leaves v2 at `SensitiveOutputDetected` and emits no v1
    /// cleanup record, so restart must resume neutralization rather than infer
    /// a length-derived cleanup identity.
    pub(crate) fn neutralize_sensitive_output_staging_v2(
        &self,
        stdout: &mut CommandOutputStreamCapture,
        stderr: &mut CommandOutputStreamCapture,
    ) -> Result<SensitiveOutputStagingNeutralizationReceiptV1, CommandOutputStoreError> {
        if !self.sensitive_output_v2
            || !Arc::ptr_eq(&self.shared, &stdout.shared)
            || !Arc::ptr_eq(&self.shared, &stderr.shared)
            || stdout.stream != CommandOutputStreamV1::Stdout
            || stderr.stream != CommandOutputStreamV1::Stderr
        {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output neutralization received crossed capture custody".into(),
            ));
        }
        let capture_id = self
            .capture_id()
            .ok_or_else(|| CommandOutputStoreError::Source("v2 capture ID is absent".into()))?;
        let recovery = sensitive_output_journal::read_recovery(&self.store, capture_id)?;
        if !matches!(
            recovery.stage(),
            SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
        ) {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output neutralization requires exact Detected journal state".into(),
            ));
        }
        stdout.neutralize_sensitive_output_v2()?;
        stderr.neutralize_sensitive_output_v2()?;
        self.shared.reserved_bytes.store(0, Ordering::Release);
        let acquired = recovery.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "Detected sensitive-output journal lost its acquired anchor".into(),
            )
        })?;
        SensitiveOutputStagingNeutralizationReceiptV1::try_new(acquired)
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))
    }

    #[cfg(feature = "test-support")]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the crash-cut seam must consume and drop exact finished-stream custody"
    )]
    pub(crate) fn stop_after_sensitive_output_finished_v2_for_test(
        mut self,
        stdout: FinishedCommandOutputStream,
        stderr: FinishedCommandOutputStream,
    ) -> Result<(), CommandOutputStoreError> {
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "test-support Finished cut requires v2 capture custody".into(),
            ));
        }
        self.validate_finished_pair(&stdout, &stderr)?;
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(self
                .shared
                .reconciliation("cannot cut at Finished after a stream failure".into(), None));
        }
        let reference = CommandOutputArtifactSetReferenceV1::try_new(
            self.shared.source.clone(),
            stdout.artifact(),
            stderr.artifact(),
        )
        .map_err(|error| {
            self.shared.reconciliation(
                format!("completed stream reference is invalid: {error}"),
                None,
            )
        })?;
        validate_reference_bound(&reference).map_err(|error| {
            self.shared.reconciliation(
                format!("completed stream reference exceeds the store bound: {error}"),
                Some(&reference),
            )
        })?;
        let journal = self.journal.as_mut().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "test-support Finished cut requires journaled capture custody".into(),
            )
        })?;
        journal
            .append_finished(reference.stdout.clone(), reference.stderr.clone())
            .map_err(|error| {
                reconciliation_error_for_capture(
                    &reference.source,
                    Some(journal.capture_id().as_str()),
                    Some(&reference),
                    format!("durable Finished capture record failed: {error}"),
                )
            })?;
        let capture_id = journal.capture_id().to_string();
        let finished_store_head = journal.head();
        sensitive_output_journal::record_finished(&self.store, &capture_id, &finished_store_head)?;
        Ok(())
    }

    /// Publishes both finished streams and returns a completely reopened view.
    ///
    /// The manifest and directory are synchronized before one atomic
    /// no-replace rename. An existing source-derived name is idempotent only
    /// when a complete reopen proves the exact same reference.
    ///
    /// # Errors
    ///
    /// Returns a typed reconciliation error for any failure after capture,
    /// including an ambiguous rename, failed durability proof, or source-name
    /// collision with different content.
    pub fn publish(
        self,
        stdout: FinishedCommandOutputStream,
        stderr: FinishedCommandOutputStream,
    ) -> Result<ValidatedCommandOutputArtifactSet, CommandOutputStoreError> {
        self.publish_with_post_rename_probe(stdout, stderr, || Ok(()))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publication keeps pre-rename preparation, no-replace effect classification, durability proof, and idempotent collision validation visibly ordered"
    )]
    fn publish_with_post_rename_probe(
        mut self,
        mut stdout: FinishedCommandOutputStream,
        mut stderr: FinishedCommandOutputStream,
        post_rename_probe: impl FnOnce() -> Result<(), String>,
    ) -> Result<ValidatedCommandOutputArtifactSet, CommandOutputStoreError> {
        let journal_capture_id = self.shared.journal_capture_id.clone();
        self.validate_finished_pair(&stdout, &stderr)?;
        if self.shared.poisoned.load(Ordering::Acquire) {
            return Err(self.shared.reconciliation(
                "cannot publish a capture poisoned by a stream failure".into(),
                None,
            ));
        }
        let reference = CommandOutputArtifactSetReferenceV1::try_new(
            self.shared.source.clone(),
            stdout.artifact(),
            stderr.artifact(),
        )
        .map_err(|error| {
            self.shared.reconciliation(
                format!("completed stream reference is invalid: {error}"),
                None,
            )
        })?;
        validate_reference_bound(&reference).map_err(|error| {
            self.shared.reconciliation(
                format!("completed stream reference exceeds the store bound: {error}"),
                Some(&reference),
            )
        })?;
        let stored = StoredCommandOutputManifestV1::from_reference(&reference);
        let manifest = canonical_manifest(&stored).map_err(|error| {
            self.shared.reconciliation(
                format!("canonical manifest construction failed: {error}"),
                Some(&reference),
            )
        })?;
        if manifest_digest(&manifest) != reference.manifest_digest {
            return Err(self.shared.reconciliation(
                "runner canonical manifest differs from the core V1 digest".into(),
                Some(&reference),
            ));
        }
        if let Some(journal) = self.journal.as_mut() {
            journal
                .append_finished(reference.stdout.clone(), reference.stderr.clone())
                .map_err(|error| {
                    reconciliation_error_for_capture(
                        &reference.source,
                        journal_capture_id.as_deref(),
                        Some(&reference),
                        format!("durable Finished capture record failed: {error}"),
                    )
                })?;
            self.finished_store_head = Some(journal.head());
        }
        if self.sensitive_output_v2 {
            let capture_id = self.capture_id().ok_or_else(|| {
                self.shared
                    .reconciliation("v2 capture ID is absent".into(), None)
            })?;
            let finished_store_head = self.finished_store_head.as_ref().ok_or_else(|| {
                self.shared
                    .reconciliation("v2 Finished store head is absent".into(), None)
            })?;
            sensitive_output_journal::record_finished(&self.store, capture_id, finished_store_head)
                .map_err(|error| {
                    self.shared.reconciliation(
                        format!("durable v2 Finished record failed: {error}"),
                        Some(&reference),
                    )
                })?;
        }

        let preparation = (|| {
            self.store.validate_root()?;
            let named_temp = self
                .store
                .inner
                .root
                .open_dir_nofollow(&self.temp_name)
                .map_err(|error| {
                    io_error(
                        "reopen command-output temporary name",
                        Path::new(&self.temp_name),
                        &error,
                    )
                })?;
            if validate_private_directory(&named_temp, "named command-output temporary directory")?
                != self.temp_identity
            {
                return Err(CommandOutputStoreError::Root(
                    "command-output temporary name was replaced before publication".into(),
                ));
            }
            let stdout_observed = validate_private_file(
                &stdout.file,
                Path::new(STDOUT_FILE),
                Some(stdout.byte_length),
                stdout.byte_length,
            )?;
            let stderr_observed = validate_private_file(
                &stderr.file,
                Path::new(STDERR_FILE),
                Some(stderr.byte_length),
                stderr.byte_length,
            )?;
            if stdout_observed.object != stdout.identity.object
                || stderr_observed.object != stderr.identity.object
                || stdout_observed.object == stderr_observed.object
            {
                return Err(CommandOutputStoreError::Artifact(
                    "finished stream identities changed or crossed before publication".into(),
                ));
            }
            verify_stream_file(&mut stdout.file, Path::new(STDOUT_FILE), &reference.stdout)?;
            verify_stream_file(&mut stderr.file, Path::new(STDERR_FILE), &reference.stderr)?;
            write_private_file(&self.temp, Path::new(MANIFEST_FILE), &manifest)?;
            let names = directory_entry_names(&self.temp, &self.temp_name)?;
            let expected_names = BTreeSet::from([
                MANIFEST_FILE.to_string(),
                STDOUT_FILE.to_string(),
                STDERR_FILE.to_string(),
            ]);
            if names != expected_names {
                return Err(CommandOutputStoreError::Manifest(
                    "temporary artifact contains missing or unexpected entries".into(),
                ));
            }
            sync_directory(&self.temp).map_err(|error| {
                io_error(
                    "sync command-output temporary directory",
                    Path::new(&self.temp_name),
                    &error,
                )
            })?;
            Ok(())
        })();
        if let Err(error) = preparation {
            let reason = format!("pre-publication persistence failed: {error}");
            let cleanup = self.abandon_unpublished(stdout.into_custody(), stderr.into_custody());
            return Err(match cleanup {
                Ok(()) => reconciliation_error_for_capture(
                    &reference.source,
                    journal_capture_id.as_deref(),
                    Some(&reference),
                    reason,
                ),
                Err(cleanup_error) => reconciliation_error_for_capture(
                    &reference.source,
                    journal_capture_id.as_deref(),
                    Some(&reference),
                    format!("{reason}; safe temp abandonment also failed: {cleanup_error}"),
                ),
            });
        }

        let target_name = final_directory_name(&self.shared.source_digest);
        let store = self.store.clone();
        let temp_identity = self.temp_identity;
        match renameat_with(
            &store.inner.root,
            Path::new(&self.temp_name),
            &store.inner.root,
            Path::new(&target_name),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {
                let proof = sync_directory(&store.inner.root)
                    .map_err(|error| format!("published-name root sync failed: {error}"))
                    .and_then(|()| {
                        store
                            .inner
                            .root
                            .open_dir_nofollow(&target_name)
                            .map_err(|error| format!("cannot reopen published name: {error}"))
                    })
                    .and_then(|named| {
                        validate_private_directory(&named, "published command-output artifact")
                            .map_err(|error| error.to_string())
                    })
                    .and_then(|identity| {
                        if identity == temp_identity {
                            Ok(())
                        } else {
                            Err("published name does not identify the captured directory".into())
                        }
                    })
                    .and_then(|()| post_rename_probe());
                if let Err(reason) = proof {
                    return Err(reconciliation_error_for_capture(
                        &reference.source,
                        journal_capture_id.as_deref(),
                        Some(&reference),
                        reason,
                    ));
                }
                let mut validated = store.reopen(&reference).map_err(|error| {
                    reconciliation_error_for_capture(
                        &reference.source,
                        journal_capture_id.as_deref(),
                        Some(&reference),
                        format!("published artifact failed exact reopen: {error}"),
                    )
                })?;
                if let Some(journal) = self.journal.as_mut() {
                    journal
                        .append_published(reference.clone(), &validated.directory)
                        .map_err(|error| {
                            reconciliation_error_for_capture(
                                &reference.source,
                                journal_capture_id.as_deref(),
                                Some(&reference),
                                format!("durable Published capture record failed: {error}"),
                            )
                        })?;
                    let capture_id = journal.capture_id().to_string();
                    let head = journal.head();
                    let reopened = store.reopen(&reference).map_err(|error| {
                        reconciliation_error_for_capture(
                            &reference.source,
                            journal_capture_id.as_deref(),
                            Some(&reference),
                            format!(
                                "artifact changed after durable Published capture record: {error}"
                            ),
                        )
                    })?;
                    validated = reopened;
                    validated.capture_id = Some(capture_id.clone());
                    validated
                        .capture_finished_store_head
                        .clone_from(&self.finished_store_head);
                    validated.capture_published_store_head = Some(head.clone());
                    validated.capture_store_head = Some(head);
                    if self.sensitive_output_v2 {
                        let published_store_head = validated
                            .capture_published_store_head
                            .as_ref()
                            .expect("journaled publication installs Published head");
                        sensitive_output_journal::record_published(
                            &store,
                            &capture_id,
                            published_store_head,
                        )
                        .map_err(|error| {
                            reconciliation_error_for_capture(
                                &reference.source,
                                journal_capture_id.as_deref(),
                                Some(&reference),
                                format!("durable v2 Published record failed: {error}"),
                            )
                        })?;
                    }
                }
                Ok(validated)
            }
            Err(error) if error == rustix::io::Errno::EXIST => {
                let journaled = self.journal.is_some();
                self.abandon_unpublished(stdout.into_custody(), stderr.into_custody())
                    .map_err(|error| {
                        reconciliation_error_for_capture(
                            &reference.source,
                            journal_capture_id.as_deref(),
                            Some(&reference),
                            format!("concurrent publication temp cleanup failed: {error}"),
                        )
                    })?;
                if journaled {
                    return Err(reconciliation_error_for_capture(
                        &reference.source,
                        journal_capture_id.as_deref(),
                        Some(&reference),
                        "capture-ID publication found an existing source-derived artifact; replay cannot be treated as a new Published capture".into(),
                    ));
                }
                store.reopen(&reference).map_err(|error| {
                    reconciliation_error_for_capture(
                        &reference.source,
                        journal_capture_id.as_deref(),
                        Some(&reference),
                        format!(
                            "existing source-derived name is not the complete exact artifact: {error}"
                        ),
                    )
                })
            }
            Err(error) => Err(reconciliation_error_for_capture(
                &reference.source,
                journal_capture_id.as_deref(),
                Some(&reference),
                format!("atomic no-replace publication could not be proven: {error}"),
            )),
        }
    }

    /// Consumes both stream custody tokens and removes only the exact retained
    /// temporary directory, never a published artifact.
    ///
    /// # Errors
    ///
    /// Returns an error without recursive deletion if the tokens are crossed,
    /// the temp/fixed files changed identity, or any extra entry is present.
    #[allow(
        clippy::too_many_lines,
        reason = "safe abandonment deliberately verifies consuming custody, exact temp identity, fixed entries, unlink order, and directory durability without recursive deletion"
    )]
    pub fn abandon_unpublished(
        self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate_custody_pair(&stdout, &stderr)?;
        if let Some(capture_id) = self.capture_id() {
            self.store
                .reject_generic_sensitive_output_mutation(capture_id, "unpublished abandonment")?;
        }
        self.abandon_unpublished_inner(stdout, stderr)
    }

    /// Branch-specific cleanup for the exact generation-three
    /// `WriterAttached` prefix. This is the only live v2 path permitted to use
    /// ordinary unpublished cleanup because no launch record exists in either
    /// journal yet.
    pub(crate) fn abandon_sensitive_output_prelaunch_v2(
        self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate_custody_pair(&stdout, &stderr)?;
        let capture_id = self.capture_id().ok_or_else(|| {
            CommandOutputStoreError::Source(
                "sensitive-output prelaunch cleanup requires journaled capture custody".into(),
            )
        })?;
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output prelaunch cleanup requires a v2 reservation".into(),
            ));
        }
        let recovery = sensitive_output_journal::read_recovery(&self.store, capture_id)?;
        if recovery.head().generation != 3
            || !matches!(
                recovery.stage(),
                SensitiveOutputJournalStageV2::WriterAttached { .. }
            )
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id.to_owned()),
                source: Box::new(self.shared.source.clone()),
                expected_reference: None,
                reason: "policy-bound prelaunch cleanup requires exact generation-three WriterAttached state; any durable launch or other branch must use typed v2 reconciliation"
                    .into(),
            });
        }
        self.abandon_unpublished_inner(stdout, stderr)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "exact abandonment keeps descriptor identity, fixed-entry validation, ordered unlink, journal transition, and durability readback in one auditable transaction"
    )]
    fn abandon_unpublished_inner(
        mut self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate_custody_pair(&stdout, &stderr)?;
        let source = self.shared.source.clone();
        let cleanup = (|| {
            self.store.validate_root()?;
            let cleanup_directory = self
                .store
                .inner
                .root
                .open_dir_nofollow(&self.temp_name)
                .map_err(|error| {
                    io_error(
                        "open command-output temporary cleanup target",
                        Path::new(&self.temp_name),
                        &error,
                    )
                })?;
            if validate_private_directory(
                &cleanup_directory,
                "command-output temporary cleanup target",
            )? != self.temp_identity
            {
                return Err(CommandOutputStoreError::Root(
                    "temporary directory identity changed before abandonment".into(),
                ));
            }
            let names = directory_entry_names(&cleanup_directory, &self.temp_name)?;
            let without_manifest =
                BTreeSet::from([STDOUT_FILE.to_string(), STDERR_FILE.to_string()]);
            let with_manifest = BTreeSet::from([
                MANIFEST_FILE.to_string(),
                STDOUT_FILE.to_string(),
                STDERR_FILE.to_string(),
            ]);
            if names != without_manifest && names != with_manifest {
                return Err(CommandOutputStoreError::Manifest(
                    "temporary cleanup target has missing or unexpected entries".into(),
                ));
            }
            let stdout_named = open_private_file(&cleanup_directory, Path::new(STDOUT_FILE))?;
            let stdout_identity = validate_private_file(
                &stdout_named,
                Path::new(STDOUT_FILE),
                None,
                self.shared.authenticated_maximum_bytes,
            )?;
            let stderr_named = open_private_file(&cleanup_directory, Path::new(STDERR_FILE))?;
            let stderr_identity = validate_private_file(
                &stderr_named,
                Path::new(STDERR_FILE),
                None,
                self.shared.authenticated_maximum_bytes,
            )?;
            if stdout_identity.object != stdout.identity.object
                || stderr_identity.object != stderr.identity.object
                || stdout_identity.object == stderr_identity.object
            {
                return Err(CommandOutputStoreError::Artifact(
                    "temporary stream identities changed before abandonment".into(),
                ));
            }
            drop(stdout);
            drop(stderr);
            let manifest_named = if names.contains(MANIFEST_FILE) {
                let manifest = open_private_file(&cleanup_directory, Path::new(MANIFEST_FILE))?;
                let identity = validate_private_file(
                    &manifest,
                    Path::new(MANIFEST_FILE),
                    None,
                    MAX_MANIFEST_BYTES,
                )?;
                Some((manifest, identity))
            } else {
                None
            };
            if let Some(journal) = self.journal.as_mut() {
                journal.append_cleanup_intended()?;
            }
            if let Some((manifest, identity)) = manifest_named.as_ref() {
                cleanup_directory
                    .remove_file(MANIFEST_FILE)
                    .map_err(|error| {
                        io_error(
                            "unlink command-output temporary manifest",
                            Path::new(MANIFEST_FILE),
                            &error,
                        )
                    })?;
                validate_unlinked_private_file(manifest, Path::new(MANIFEST_FILE), *identity)?;
            }
            cleanup_directory
                .remove_file(STDOUT_FILE)
                .map_err(|error| {
                    io_error(
                        "unlink command-output temporary stdout",
                        Path::new(STDOUT_FILE),
                        &error,
                    )
                })?;
            validate_unlinked_private_file(&stdout_named, Path::new(STDOUT_FILE), stdout_identity)?;
            cleanup_directory
                .remove_file(STDERR_FILE)
                .map_err(|error| {
                    io_error(
                        "unlink command-output temporary stderr",
                        Path::new(STDERR_FILE),
                        &error,
                    )
                })?;
            validate_unlinked_private_file(&stderr_named, Path::new(STDERR_FILE), stderr_identity)?;
            sync_directory(&cleanup_directory).map_err(|error| {
                io_error(
                    "sync abandoned command-output temporary directory",
                    Path::new(&self.temp_name),
                    &error,
                )
            })?;
            self.store
                .validate_named_directory(&self.temp_name, self.temp_identity)?;
            self.store
                .inner
                .root
                .remove_dir(&self.temp_name)
                .map_err(|error| {
                    io_error(
                        "remove abandoned command-output temporary directory",
                        Path::new(&self.temp_name),
                        &error,
                    )
                })?;
            sync_directory(&self.store.inner.root).map_err(|error| {
                io_error(
                    "sync abandoned command-output namespace",
                    Path::new(&self.temp_name),
                    &error,
                )
            })?;
            validate_unlinked_private_directory(
                &cleanup_directory,
                self.temp_identity,
                &self.store.inner.root,
                Path::new(&self.temp_name),
                "named abandoned command-output directory",
            )?;
            validate_unlinked_private_directory(
                &self.temp,
                self.temp_identity,
                &self.store.inner.root,
                Path::new(&self.temp_name),
                "retained abandoned command-output directory",
            )?;
            self.store.validate_root()?;
            if let Some(journal) = self.journal.as_mut() {
                journal.append_cleaned_from_unlinked(
                    &cleanup_directory,
                    &stdout_named,
                    &stderr_named,
                    manifest_named.as_ref().map(|(file, _)| file),
                )?;
            }
            Ok(())
        })();
        cleanup.map_err(|error| {
            reconciliation_error(
                &source,
                None,
                format!("never-published temp could not be safely abandoned: {error}"),
            )
        })
    }

    #[cfg(feature = "test-support")]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the crash-cut seam must consume and drop exact neutralized-stream custody"
    )]
    pub(crate) fn stop_after_sensitive_output_cleanup_intended_v2_for_test(
        self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
        command_domain_cleanup_proof_id: &str,
        staging_neutralization: &SensitiveOutputStagingNeutralizationReceiptV1,
    ) -> Result<(), CommandOutputStoreError> {
        let capture_id = self
            .capture_id()
            .ok_or_else(|| {
                CommandOutputStoreError::Source(
                    "sensitive-output test cut requires journaled capture custody".into(),
                )
            })?
            .to_owned();
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output test cut requires a v2 reservation".into(),
            ));
        }
        self.validate_custody_pair(&stdout, &stderr)?;
        sensitive_output_journal::record_cleanup_intended(
            &self.store,
            &capture_id,
            command_domain_cleanup_proof_id,
            staging_neutralization,
        )?;
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn stop_after_sensitive_output_cleaned_v2_for_test(
        self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
        command_domain_cleanup_proof_id: &str,
        staging_neutralization: &SensitiveOutputStagingNeutralizationReceiptV1,
    ) -> Result<(), CommandOutputStoreError> {
        let store = self.store.clone();
        let capture_id = self
            .capture_id()
            .ok_or_else(|| {
                CommandOutputStoreError::Source(
                    "sensitive-output test cut requires journaled capture custody".into(),
                )
            })?
            .to_owned();
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output test cut requires a v2 reservation".into(),
            ));
        }
        sensitive_output_journal::record_cleanup_intended(
            &store,
            &capture_id,
            command_domain_cleanup_proof_id,
            staging_neutralization,
        )?;
        self.abandon_unpublished_inner(stdout, stderr)?;
        let recovery = store.reopen_capture(&capture_id)?;
        if recovery.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || recovery.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id),
                source: Box::new(recovery.source().clone()),
                expected_reference: recovery.expected_reference().cloned().map(Box::new),
                reason: "sensitive-output test cut did not prove exact v1 Cleaned custody".into(),
            });
        }
        let cleaned_store_head = recovery.cleaned_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output test cut lost its exact v1 Cleaned head".into(),
            )
        })?;
        sensitive_output_journal::record_cleaned_test_cut(&store, &capture_id, cleaned_store_head)?;
        Ok(())
    }

    /// Exactly removes a rejected journaled reservation and proves the
    /// immutable `Cleaned` readback used by the separate v2 rejection path.
    pub(crate) fn abandon_sensitive_output_v2(
        self,
        stdout: CommandOutputStreamCustody,
        stderr: CommandOutputStreamCustody,
        termination: CommandTerminationV1,
        command_domain_cleanup_proof_id: &str,
        detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
        staging_neutralization: &SensitiveOutputStagingNeutralizationReceiptV1,
    ) -> Result<SensitiveOutputAbandonmentV2, CommandOutputStoreError> {
        let store = self.store.clone();
        let capture_id = self
            .capture_id()
            .ok_or_else(|| {
                CommandOutputStoreError::Source(
                    "sensitive-output rejection requires journaled capture custody".into(),
                )
            })?
            .to_owned();
        if !self.sensitive_output_v2 {
            return Err(CommandOutputStoreError::Source(
                "sensitive-output cleanup requires a v2 reservation".into(),
            ));
        }
        self.validate_custody_pair(&stdout, &stderr)?;
        let detected = sensitive_output_journal::read_recovery(&store, &capture_id)?;
        if detected.detector_policy() != detector_policy
            || !matches!(
                detected.stage(),
                SensitiveOutputJournalStageV2::SensitiveOutputDetected { .. }
            )
        {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output abandonment requires the exact detected policy branch".into(),
            ));
        }
        let acquired = detected.acquired().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output abandonment lost its acquired capture anchor".into(),
            )
        })?;
        let launch_intended_store_head =
            detected.launch_intended_store_head().ok_or_else(|| {
                CommandOutputStoreError::Manifest(
                    "sensitive-output abandonment lost its v1 LaunchIntended head".into(),
                )
            })?;
        staging_neutralization
            .validate_against(acquired)
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.validate_sensitive_output_zero_custody(
            &stdout,
            &stderr,
            acquired,
            launch_intended_store_head,
        )
        .map_err(|error| {
            reconciliation_error_for_capture(
                &acquired.source,
                Some(&capture_id),
                None,
                format!(
                    "sensitive-output staging was not exact zero custody after writer closure: {error}"
                ),
            )
        })?;
        sensitive_output_journal::record_cleanup_intended(
            &store,
            &capture_id,
            command_domain_cleanup_proof_id,
            staging_neutralization,
        )?;
        self.abandon_unpublished_inner(stdout, stderr)?;
        let recovery = store.reopen_capture(&capture_id)?;
        if recovery.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || recovery.cleaned_store_head().is_none()
            || recovery.expected_reference().is_some()
        {
            return Err(CommandOutputStoreError::ReconciliationRequired {
                capture_id: Some(capture_id),
                source: Box::new(recovery.source().clone()),
                expected_reference: None,
                reason: "sensitive-output abandonment did not prove exact Cleaned custody with no retained artifact"
                    .into(),
            });
        }
        let cleaned_store_head = recovery.cleaned_store_head().ok_or_else(|| {
            CommandOutputStoreError::Manifest(
                "sensitive-output cleanup lost its exact v1 Cleaned head".into(),
            )
        })?;
        let journal_receipt = sensitive_output_journal::complete_rejection(
            &store,
            &capture_id,
            cleaned_store_head,
            termination,
        )?;
        if &journal_receipt.detector_policy != detector_policy
            || journal_receipt.command_domain_cleanup_proof_id != command_domain_cleanup_proof_id
        {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output cleanup crossed its policy or command-domain proof".into(),
            ));
        }
        Ok(SensitiveOutputAbandonmentV2 {
            recovery,
            journal_receipt,
        })
    }

    fn validate_finished_pair(
        &self,
        stdout: &FinishedCommandOutputStream,
        stderr: &FinishedCommandOutputStream,
    ) -> Result<(), CommandOutputStoreError> {
        if !Arc::ptr_eq(&self.shared, &stdout.shared)
            || !Arc::ptr_eq(&self.shared, &stderr.shared)
            || stdout.shared.capture_id != self.shared.capture_id
            || stderr.shared.capture_id != self.shared.capture_id
            || stdout.stream != CommandOutputStreamV1::Stdout
            || stderr.stream != CommandOutputStreamV1::Stderr
        {
            return Err(CommandOutputStoreError::Artifact(
                "publisher received crossed source, capture, or stream-role custody".into(),
            ));
        }
        if stdout.identity.object == stderr.identity.object {
            return Err(CommandOutputStoreError::Artifact(
                "stdout and stderr custody identify the same file".into(),
            ));
        }
        Ok(())
    }

    fn validate_custody_pair(
        &self,
        stdout: &CommandOutputStreamCustody,
        stderr: &CommandOutputStreamCustody,
    ) -> Result<(), CommandOutputStoreError> {
        if !Arc::ptr_eq(&self.shared, &stdout.shared)
            || !Arc::ptr_eq(&self.shared, &stderr.shared)
            || stdout.shared.capture_id != self.shared.capture_id
            || stderr.shared.capture_id != self.shared.capture_id
            || stdout.stream != CommandOutputStreamV1::Stdout
            || stderr.stream != CommandOutputStreamV1::Stderr
        {
            return Err(CommandOutputStoreError::Artifact(
                "publisher received crossed source, capture, or stream-role cleanup custody".into(),
            ));
        }
        if stdout.identity.object == stderr.identity.object {
            return Err(CommandOutputStoreError::Artifact(
                "stdout and stderr cleanup custody identify the same file".into(),
            ));
        }
        Ok(())
    }

    fn validate_sensitive_output_zero_custody(
        &self,
        stdout: &CommandOutputStreamCustody,
        stderr: &CommandOutputStreamCustody,
        acquired: &CommandOutputCaptureAcquiredV1,
        launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate_custody_pair(stdout, stderr)?;
        acquired
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        launch_intended_store_head
            .validate()
            .map_err(|error| CommandOutputStoreError::Reference(error.to_string()))?;
        if self.capture_id() != Some(acquired.capture_id.as_str())
            || self.shared.source != acquired.source
            || self.shared.authenticated_maximum_bytes != acquired.max_aggregate_output_bytes
            || self.journal_head().as_ref() != Some(launch_intended_store_head)
        {
            return Err(CommandOutputStoreError::Reference(
                "sensitive-output zero custody crossed acquisition or v1 LaunchIntended head"
                    .into(),
            ));
        }
        self.store.validate_root()?;
        self.store
            .validate_named_directory(&self.temp_name, self.temp_identity)?;
        if validate_private_directory(&self.temp, "sensitive-output zero custody")?
            != self.temp_identity
            || self.temp_identity.object.device != acquired.working_directory.device_id
            || self.temp_identity.object.inode != acquired.working_directory.inode
            || self.temp_identity.uid != acquired.working_directory.owner_uid
            || self.temp_identity.mode != acquired.working_directory.mode
        {
            return Err(CommandOutputStoreError::Root(
                "sensitive-output zero custody changed its acquired directory identity".into(),
            ));
        }
        if directory_entry_names(&self.temp, &self.temp_name)?
            != BTreeSet::from([STDOUT_FILE.to_owned(), STDERR_FILE.to_owned()])
        {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output zero custody contains missing or unexpected entries".into(),
            ));
        }
        let stdout_file = open_private_file(&self.temp, Path::new(STDOUT_FILE))?;
        let stderr_file = open_private_file(&self.temp, Path::new(STDERR_FILE))?;
        let stdout_observed =
            validate_private_file(&stdout_file, Path::new(STDOUT_FILE), Some(0), 0)?;
        let stderr_observed =
            validate_private_file(&stderr_file, Path::new(STDERR_FILE), Some(0), 0)?;
        if stdout_observed != stdout.identity
            || stderr_observed != stderr.identity
            || stdout_observed.object.device != acquired.stdout.device_id
            || stdout_observed.object.inode != acquired.stdout.inode
            || stdout_observed.uid != acquired.stdout.owner_uid
            || stdout_observed.mode != acquired.stdout.mode
            || stderr_observed.object.device != acquired.stderr.device_id
            || stderr_observed.object.inode != acquired.stderr.inode
            || stderr_observed.uid != acquired.stderr.owner_uid
            || stderr_observed.mode != acquired.stderr.mode
        {
            return Err(CommandOutputStoreError::Artifact(
                "sensitive-output zero custody changed an acquired stream identity".into(),
            ));
        }
        Ok(())
    }
}

/// Fully validated read-only custody for one immutable artifact set.
///
/// The type is not deserializable and can be created only by [`reopen`](CapabilityCommandOutputStore::reopen)
/// or successful publication. Every read revalidates all named bytes and
/// identities before and after copying.
pub struct ValidatedCommandOutputArtifactSet {
    store: CapabilityCommandOutputStore,
    reference: CommandOutputArtifactSetReferenceV1,
    directory_name: String,
    directory: Dir,
    directory_identity: PrivateDirectoryIdentity,
    manifest_file: File,
    manifest_identity: PrivateFileIdentity,
    stdout: File,
    stdout_identity: PrivateFileIdentity,
    stderr: File,
    stderr_identity: PrivateFileIdentity,
    capture_id: Option<String>,
    capture_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    capture_finished_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    capture_published_store_head: Option<CommandOutputCaptureStoreHeadV1>,
}

impl ValidatedCommandOutputArtifactSet {
    /// Returns the exact independently verified path-free reference.
    #[must_use]
    pub const fn reference(&self) -> &CommandOutputArtifactSetReferenceV1 {
        &self.reference
    }

    /// Returns the exact capture ID when this value came from current-path
    /// journaled publication rather than legacy reference-only reopen.
    #[must_use]
    pub fn capture_id(&self) -> Option<&str> {
        self.capture_id.as_deref()
    }

    /// Returns the synchronized `Published` store head needed to append
    /// `TerminalPrepared` without accepting a stale writer.
    #[must_use]
    pub const fn capture_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.capture_store_head.as_ref()
    }

    /// Returns the exact durable `Finished` head for journaled publication.
    #[must_use]
    pub const fn capture_finished_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.capture_finished_store_head.as_ref()
    }

    /// Returns the exact durable `Published` head for journaled publication.
    #[must_use]
    pub const fn capture_published_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.capture_published_store_head.as_ref()
    }

    /// Copies complete verified stdout to a caller-owned destination.
    ///
    /// # Errors
    ///
    /// Returns an error if any artifact byte/name/identity changes during the
    /// read or if the destination rejects bytes.
    pub fn copy_stdout_to(
        &self,
        destination: &mut impl Write,
    ) -> Result<u64, CommandOutputStoreError> {
        self.copy_stream_to(CommandOutputStreamV1::Stdout, destination)
    }

    /// Copies complete verified stderr to a caller-owned destination.
    ///
    /// # Errors
    ///
    /// Returns an error if any artifact byte/name/identity changes during the
    /// read or if the destination rejects bytes.
    pub fn copy_stderr_to(
        &self,
        destination: &mut impl Write,
    ) -> Result<u64, CommandOutputStoreError> {
        self.copy_stream_to(CommandOutputStreamV1::Stderr, destination)
    }

    fn copy_stream_to(
        &self,
        stream: CommandOutputStreamV1,
        destination: &mut impl Write,
    ) -> Result<u64, CommandOutputStoreError> {
        self.verify_complete_set()?;
        let (file, expected, path) = match stream {
            CommandOutputStreamV1::Stdout => {
                (&self.stdout, &self.reference.stdout, Path::new(STDOUT_FILE))
            }
            CommandOutputStreamV1::Stderr => {
                (&self.stderr, &self.reference.stderr, Path::new(STDERR_FILE))
            }
        };
        let mut first = file
            .try_clone()
            .map_err(|error| io_error("clone immutable stream", path, &error))?;
        first
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind immutable stream", path, &error))?;
        let first_commitment =
            scan_stream(&mut first, path, expected.byte_length, Some(destination))?;
        let mut second = file
            .try_clone()
            .map_err(|error| io_error("clone immutable stream", path, &error))?;
        second
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("rewind immutable stream", path, &error))?;
        let second_commitment =
            scan_stream::<io::Sink>(&mut second, path, expected.byte_length, None)?;
        if first_commitment != second_commitment
            || first_commitment.0 != expected.byte_length
            || first_commitment.1 != expected.content_digest
        {
            return Err(CommandOutputStoreError::Artifact(format!(
                "{} changed or differs from its complete commitment during read",
                path.display()
            )));
        }
        self.verify_complete_set()?;
        Ok(first_commitment.0)
    }

    fn verify_complete_set(&self) -> Result<(), CommandOutputStoreError> {
        self.store.validate_root()?;
        if validate_private_directory(&self.directory, "retained command-output artifact")?
            != self.directory_identity
        {
            return Err(CommandOutputStoreError::Root(
                "retained command-output directory identity or mode changed".into(),
            ));
        }
        self.store
            .validate_named_directory(&self.directory_name, self.directory_identity)?;
        let names = directory_entry_names(&self.directory, &self.directory_name)?;
        if names
            != BTreeSet::from([
                MANIFEST_FILE.to_string(),
                STDOUT_FILE.to_string(),
                STDERR_FILE.to_string(),
            ])
        {
            return Err(CommandOutputStoreError::Manifest(
                "artifact entries changed after reopen".into(),
            ));
        }

        validate_named_file_identity(
            &self.directory,
            Path::new(MANIFEST_FILE),
            self.manifest_identity,
            MAX_MANIFEST_BYTES,
        )?;
        let mut manifest = self.manifest_file.try_clone().map_err(|error| {
            io_error("clone immutable manifest", Path::new(MANIFEST_FILE), &error)
        })?;
        let bytes =
            read_file_twice_stable(&mut manifest, Path::new(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
        let stored: StoredCommandOutputManifestV1 = serde_json::from_slice(&bytes)
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        if canonical_manifest(&stored)? != bytes || stored.into_reference()? != self.reference {
            return Err(CommandOutputStoreError::Manifest(
                "manifest bytes changed after reopen".into(),
            ));
        }

        for (file, identity, path, expected) in [
            (
                &self.stdout,
                self.stdout_identity,
                Path::new(STDOUT_FILE),
                &self.reference.stdout,
            ),
            (
                &self.stderr,
                self.stderr_identity,
                Path::new(STDERR_FILE),
                &self.reference.stderr,
            ),
        ] {
            validate_named_file_identity(&self.directory, path, identity, expected.byte_length)?;
            let retained = validate_private_file(
                file,
                path,
                Some(expected.byte_length),
                expected.byte_length,
            )?;
            if retained != identity {
                return Err(CommandOutputStoreError::Artifact(format!(
                    "retained {} metadata changed after reopen",
                    path.display()
                )));
            }
            let mut clone = file
                .try_clone()
                .map_err(|error| io_error("clone immutable stream", path, &error))?;
            verify_stream_file(&mut clone, path, expected)?;
        }
        self.store.validate_root()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCommandOutputManifestV1 {
    format_version: u32,
    source: CommandOutputArtifactSourceV1,
    stdout: CommandOutputStreamArtifactV1,
    stderr: CommandOutputStreamArtifactV1,
}

impl StoredCommandOutputManifestV1 {
    fn from_reference(reference: &CommandOutputArtifactSetReferenceV1) -> Self {
        Self {
            format_version: reference.format_version,
            source: reference.source.clone(),
            stdout: reference.stdout.clone(),
            stderr: reference.stderr.clone(),
        }
    }

    fn into_reference(
        self,
    ) -> Result<CommandOutputArtifactSetReferenceV1, CommandOutputStoreError> {
        if self.format_version != COMMAND_OUTPUT_ARTIFACT_FORMAT_VERSION {
            return Err(CommandOutputStoreError::Manifest(format!(
                "unsupported command-output manifest version {}",
                self.format_version
            )));
        }
        CommandOutputArtifactSetReferenceV1::try_new(self.source, self.stdout, self.stderr).map_err(
            |error| {
                CommandOutputStoreError::Manifest(format!(
                    "core manifest validation failed: {error}"
                ))
            },
        )
    }
}

fn canonical_manifest(
    stored: &StoredCommandOutputManifestV1,
) -> Result<Vec<u8>, CommandOutputStoreError> {
    let bytes = serde_json::to_vec(stored)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_MANIFEST_BYTES) {
        return Err(CommandOutputStoreError::Manifest(format!(
            "canonical manifest exceeds {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn manifest_digest(manifest: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(MANIFEST_DIGEST_DOMAIN.len() + 8 + manifest.len());
    preimage.extend_from_slice(MANIFEST_DIGEST_DOMAIN);
    preimage.extend_from_slice(
        &u64::try_from(manifest.len())
            .expect("usize manifest length fits u64")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(manifest);
    Digest::sha256(&preimage)
}

fn source_name_digest(
    source: &CommandOutputArtifactSourceV1,
) -> Result<Digest, CommandOutputStoreError> {
    source.validate().map_err(|error| {
        CommandOutputStoreError::Source(format!("core source validation failed: {error}"))
    })?;
    let canonical = serde_json::to_vec(source).map_err(|error| {
        CommandOutputStoreError::Source(format!("cannot encode canonical source: {error}"))
    })?;
    let mut preimage = Vec::with_capacity(SOURCE_NAME_DIGEST_DOMAIN.len() + 8 + canonical.len());
    preimage.extend_from_slice(SOURCE_NAME_DIGEST_DOMAIN);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("usize source length fits u64")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(&canonical);
    Ok(Digest::sha256(&preimage))
}

fn final_directory_name(source_digest: &Digest) -> String {
    format!("{FINAL_PREFIX}{source_digest}")
}

fn validate_reference_bound(
    reference: &CommandOutputArtifactSetReferenceV1,
) -> Result<(), CommandOutputStoreError> {
    reference.validate().map_err(|error| {
        CommandOutputStoreError::Reference(format!("core reference validation failed: {error}"))
    })?;
    let total = reference
        .stdout
        .byte_length
        .checked_add(reference.stderr.byte_length)
        .ok_or_else(|| {
            CommandOutputStoreError::Reference("aggregate output length overflowed".into())
        })?;
    if total > MAX_COMMAND_OUTPUT_ARTIFACT_BYTES {
        return Err(CommandOutputStoreError::Reference(format!(
            "aggregate output length {total} exceeds hard ceiling {MAX_COMMAND_OUTPUT_ARTIFACT_BYTES}"
        )));
    }
    Ok(())
}

fn stream_path(stream: CommandOutputStreamV1) -> &'static Path {
    match stream {
        CommandOutputStreamV1::Stdout => Path::new(STDOUT_FILE),
        CommandOutputStreamV1::Stderr => Path::new(STDERR_FILE),
    }
}

fn validate_private_directory(
    directory: &Dir,
    label: &str,
) -> Result<PrivateDirectoryIdentity, CommandOutputStoreError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| CommandOutputStoreError::Root(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} is not a directory"
        )));
    }
    let uid = OsMetadataExt::uid(&metadata);
    let mode = OsMetadataExt::mode(&metadata) & 0o7777;
    if uid != rustix::process::geteuid().as_raw() || mode != 0o700 {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} must be effective-user owned with exact mode 0700"
        )));
    }
    Ok(PrivateDirectoryIdentity {
        object: object_identity(&metadata),
        uid,
        mode,
    })
}

fn validate_owned_directory_object(
    directory: &Dir,
    label: &str,
) -> Result<ObjectIdentity, CommandOutputStoreError> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| CommandOutputStoreError::Root(format!("inspect {label}: {error}")))?;
    if !metadata.is_dir() || OsMetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw() {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} is not an effective-user-owned directory"
        )));
    }
    Ok(object_identity(&metadata))
}

fn object_identity(metadata: &Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn create_private_file(directory: &Dir, name: &Path) -> Result<File, CommandOutputStoreError> {
    let file = create_private_file_unconfigured(directory, name)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| io_error("set private command-output file mode", name, &error))?;
    validate_private_file(&file, name, Some(0), 0)?;
    Ok(file)
}

fn create_private_file_unconfigured(
    directory: &Dir,
    name: &Path,
) -> Result<File, CommandOutputStoreError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    directory
        .open_with(name, &options)
        .map_err(|error| io_error("create private command-output file", name, &error))
}

fn write_private_file(
    directory: &Dir,
    name: &Path,
    bytes: &[u8],
) -> Result<(), CommandOutputStoreError> {
    let mut file = create_private_file(directory, name)?;
    file.write_all(bytes)
        .map_err(|error| io_error("write private command-output file", name, &error))?;
    file.flush()
        .map_err(|error| io_error("flush private command-output file", name, &error))?;
    file.sync_all()
        .map_err(|error| io_error("sync private command-output file", name, &error))?;
    validate_private_file(
        &file,
        name,
        Some(u64::try_from(bytes.len()).expect("usize fits u64")),
        u64::try_from(bytes.len()).expect("usize fits u64"),
    )?;
    Ok(())
}

fn open_private_file(directory: &Dir, name: &Path) -> Result<File, CommandOutputStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(name, &options)
        .map_err(|error| io_error("open private command-output file", name, &error))
}

fn validate_private_file(
    file: &File,
    name: &Path,
    exact_length: Option<u64>,
    maximum_length: u64,
) -> Result<PrivateFileIdentity, CommandOutputStoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect private command-output file", name, &error))?;
    validate_private_file_metadata(name, &metadata, exact_length, maximum_length)
}

fn validate_private_file_metadata(
    name: &Path,
    metadata: &Metadata,
    exact_length: Option<u64>,
    maximum_length: u64,
) -> Result<PrivateFileIdentity, CommandOutputStoreError> {
    let uid = OsMetadataExt::uid(metadata);
    let mode = OsMetadataExt::mode(metadata) & 0o7777;
    let length = metadata.len();
    if !metadata.is_file()
        || OsMetadataExt::nlink(metadata) != 1
        || uid != rustix::process::geteuid().as_raw()
        || mode != 0o600
        || length > maximum_length
        || exact_length.is_some_and(|expected| length != expected)
    {
        return Err(CommandOutputStoreError::Artifact(format!(
            "{} is not a singly-linked effective-user-owned regular file with exact mode 0600 and admitted length",
            name.display()
        )));
    }
    Ok(PrivateFileIdentity {
        object: object_identity(metadata),
        uid,
        mode,
        length,
    })
}

fn validate_unlinked_private_file(
    file: &File,
    name: &Path,
    expected: PrivateFileIdentity,
) -> Result<(), CommandOutputStoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect unlinked command-output file", name, &error))?;
    let observed = PrivateFileIdentity {
        object: object_identity(&metadata),
        uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o7777,
        length: metadata.len(),
    };
    if !metadata.is_file() || OsMetadataExt::nlink(&metadata) != 0 || observed != expected {
        return Err(CommandOutputStoreError::Artifact(format!(
            "{} was not proven to be the exact unlinked retained file",
            name.display()
        )));
    }
    Ok(())
}

fn validate_unlinked_private_directory(
    directory: &Dir,
    expected: PrivateDirectoryIdentity,
    former_parent: &Dir,
    former_name: &Path,
    label: &str,
) -> Result<(), CommandOutputStoreError> {
    let before = directory
        .dir_metadata()
        .map_err(|error| CommandOutputStoreError::Root(format!("inspect {label}: {error}")))?;
    let observed = PrivateDirectoryIdentity {
        object: object_identity(&before),
        uid: OsMetadataExt::uid(&before),
        mode: OsMetadataExt::mode(&before) & 0o7777,
    };
    if !before.is_dir() || observed != expected {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} changed before its unlink proof"
        )));
    }
    #[cfg(not(target_os = "macos"))]
    if OsMetadataExt::nlink(&before) != 0 {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} retained a live directory link after removal"
        )));
    }
    #[cfg(target_os = "macos")]
    let retained_path = rustix::fs::getpath(directory).map_err(|error| {
        CommandOutputStoreError::Root(format!("inspect retained path for {label}: {error}"))
    })?;
    #[cfg(target_os = "macos")]
    {
        let parent_path = rustix::fs::getpath(former_parent).map_err(|error| {
            CommandOutputStoreError::Root(format!("inspect former parent for {label}: {error}"))
        })?;
        let mut expected_path = parent_path.to_bytes().to_vec();
        if !expected_path.ends_with(b"/") {
            expected_path.push(b'/');
        }
        expected_path.extend_from_slice(former_name.as_os_str().as_bytes());
        if retained_path.to_bytes() != expected_path {
            return Err(CommandOutputStoreError::Root(format!(
                "{label} moved instead of being removed"
            )));
        }
    }
    match former_parent.symlink_metadata(former_name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(CommandOutputStoreError::Root(format!(
                "{label} former name exists after removal"
            )));
        }
        Err(error) => {
            return Err(io_error(
                "verify removed directory name",
                former_name,
                &error,
            ));
        }
    }
    if directory
        .entries()
        .map_err(|error| CommandOutputStoreError::Root(format!("enumerate {label}: {error}")))?
        .next()
        .is_some()
    {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} is not empty after file unlink proofs"
        )));
    }
    let after = directory
        .dir_metadata()
        .map_err(|error| CommandOutputStoreError::Root(format!("reinspect {label}: {error}")))?;
    if object_identity(&after) != expected.object
        || OsMetadataExt::uid(&after) != expected.uid
        || OsMetadataExt::mode(&after) & 0o7777 != expected.mode
        || OsMetadataExt::nlink(&after) != OsMetadataExt::nlink(&before)
    {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} changed during its unlink proof"
        )));
    }
    #[cfg(target_os = "macos")]
    if rustix::fs::getpath(directory).map_err(|error| {
        CommandOutputStoreError::Root(format!("reinspect retained path for {label}: {error}"))
    })? != retained_path
    {
        return Err(CommandOutputStoreError::Root(format!(
            "{label} moved during its unlink proof"
        )));
    }
    Ok(())
}

fn validate_named_file_identity(
    directory: &Dir,
    name: &Path,
    expected: PrivateFileIdentity,
    maximum_length: u64,
) -> Result<(), CommandOutputStoreError> {
    let named = open_private_file(directory, name)?;
    let observed = validate_private_file(
        &named,
        name,
        Some(expected.length),
        maximum_length.max(expected.length),
    )?;
    if observed != expected {
        return Err(CommandOutputStoreError::Artifact(format!(
            "{} name was replaced or metadata changed",
            name.display()
        )));
    }
    Ok(())
}

fn verify_stream_file(
    file: &mut File,
    name: &Path,
    expected: &CommandOutputStreamArtifactV1,
) -> Result<(), CommandOutputStoreError> {
    let first_metadata = file
        .metadata()
        .map_err(|error| io_error("inspect immutable raw stream", name, &error))?;
    let first_identity = validate_private_file_metadata(
        name,
        &first_metadata,
        Some(expected.byte_length),
        expected.byte_length,
    )?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable raw stream", name, &error))?;
    let first = scan_stream::<io::Sink>(file, name, expected.byte_length, None)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable raw stream", name, &error))?;
    let second = scan_stream::<io::Sink>(file, name, expected.byte_length, None)?;
    let second_metadata = file
        .metadata()
        .map_err(|error| io_error("reinspect immutable raw stream", name, &error))?;
    let second_identity = validate_private_file_metadata(
        name,
        &second_metadata,
        Some(expected.byte_length),
        expected.byte_length,
    )?;
    if first_identity != second_identity
        || first != second
        || first.0 != expected.byte_length
        || first.1 != expected.content_digest
    {
        return Err(CommandOutputStoreError::Artifact(format!(
            "{} changed during stable read or differs from its commitment",
            name.display()
        )));
    }
    Ok(())
}

fn scan_stream<W: Write>(
    file: &mut File,
    name: &Path,
    limit: u64,
    mut destination: Option<&mut W>,
) -> Result<(u64, Digest), CommandOutputStoreError> {
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("read immutable raw stream", name, &error))?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read).expect("buffer length fits u64");
        total = total.checked_add(read_u64).ok_or_else(|| {
            CommandOutputStoreError::Artifact(format!(
                "{} length overflowed during read",
                name.display()
            ))
        })?;
        if total > limit {
            return Err(CommandOutputStoreError::Artifact(format!(
                "{} grew beyond its {limit}-byte commitment during read",
                name.display()
            )));
        }
        hasher.update(&buffer[..read]);
        if let Some(writer) = destination.as_deref_mut() {
            writer
                .write_all(&buffer[..read])
                .map_err(|error| io_error("copy immutable raw stream", name, &error))?;
        }
    }
    Ok((total, digest_from_hasher(hasher)))
}

fn digest_from_hasher(hasher: Sha256) -> Digest {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(encoded).expect("SHA-256 encoding is canonical lowercase hex")
}

fn read_file_twice_stable(
    file: &mut File,
    name: &Path,
    limit: u64,
) -> Result<Vec<u8>, CommandOutputStoreError> {
    let first_metadata = file
        .metadata()
        .map_err(|error| io_error("inspect immutable manifest", name, &error))?;
    let first_identity = validate_private_file_metadata(name, &first_metadata, None, limit)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable manifest", name, &error))?;
    let first = read_bounded(file, name, limit)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("rewind immutable manifest", name, &error))?;
    let second = read_bounded(file, name, limit)?;
    let second_metadata = file
        .metadata()
        .map_err(|error| io_error("reinspect immutable manifest", name, &error))?;
    let second_identity = validate_private_file_metadata(name, &second_metadata, None, limit)?;
    if first_identity != second_identity
        || first != second
        || u64::try_from(first.len()).expect("usize fits u64") != first_identity.length
    {
        return Err(CommandOutputStoreError::Manifest(format!(
            "{} changed during stable read",
            name.display()
        )));
    }
    Ok(first)
}

fn read_bounded(
    file: &mut File,
    name: &Path,
    limit: u64,
) -> Result<Vec<u8>, CommandOutputStoreError> {
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read immutable command-output file", name, &error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err(CommandOutputStoreError::Manifest(format!(
            "{} grew beyond its {limit}-byte bound during read",
            name.display()
        )));
    }
    Ok(bytes)
}

fn directory_entry_names(
    directory: &Dir,
    label: &str,
) -> Result<BTreeSet<String>, CommandOutputStoreError> {
    let mut names = BTreeSet::new();
    for entry in directory.entries().map_err(|error| {
        io_error(
            "enumerate command-output directory",
            Path::new(label),
            &error,
        )
    })? {
        if names.len() > 3 {
            return Err(CommandOutputStoreError::Manifest(
                "command-output directory contains too many entries".into(),
            ));
        }
        let entry = entry.map_err(|error| {
            io_error(
                "read command-output directory entry",
                Path::new(label),
                &error,
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            CommandOutputStoreError::Manifest(
                "command-output directory contains a non-UTF-8 entry".into(),
            )
        })?;
        if !names.insert(name) {
            return Err(CommandOutputStoreError::Manifest(
                "command-output directory contains duplicate entry names".into(),
            ));
        }
    }
    Ok(names)
}

fn reconciliation_error(
    source: &CommandOutputArtifactSourceV1,
    expected: Option<&CommandOutputArtifactSetReferenceV1>,
    reason: String,
) -> CommandOutputStoreError {
    reconciliation_error_for_capture(source, None, expected, reason)
}

fn reconciliation_error_for_capture(
    source: &CommandOutputArtifactSourceV1,
    capture_id: Option<&str>,
    expected: Option<&CommandOutputArtifactSetReferenceV1>,
    reason: String,
) -> CommandOutputStoreError {
    CommandOutputStoreError::ReconciliationRequired {
        capture_id: capture_id.map(str::to_owned),
        source: Box::new(source.clone()),
        expected_reference: expected.cloned().map(Box::new),
        reason,
    }
}

fn reservation_probe_error(
    checkpoint: ReservationCheckpoint,
    reason: &str,
) -> CommandOutputStoreError {
    CommandOutputStoreError::Artifact(format!(
        "reservation checkpoint {checkpoint:?} failed: {reason}"
    ))
}

fn io_error(operation: &'static str, path: &Path, error: &impl Display) -> CommandOutputStoreError {
    CommandOutputStoreError::Io {
        operation,
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests;
