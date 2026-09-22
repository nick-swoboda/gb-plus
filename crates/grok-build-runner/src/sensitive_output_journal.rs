//! Additive, secret-free version-2 command-output lifecycle journal.
//!
//! Version 1 remains owned by `command_output_journal.rs` and is never
//! reinterpreted here. A v2 command appends exactly one record at each real
//! boundary. Generations 1--4 are common; generations 5--8 are one of two
//! closed branches:
//!
//! * `ScannedClean -> Finished -> Published -> TerminalPrepared`
//! * `SensitiveOutputDetected -> CleanupIntended -> Cleaned -> SensitiveOutputRejected`

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions};
use grok_build_core::{
    CommandOutputCaptureAcquiredV1, CommandOutputCaptureIntentV1, CommandOutputCaptureStoreHeadV1,
    CommandTerminationV1, Digest, SensitiveOutputDetectionPolicyReferenceV1,
    SensitiveOutputJournalHeadV1, SensitiveOutputStagingNeutralizationReceiptV1,
};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};

use super::{
    CapabilityCommandOutputStore, CommandOutputCaptureId, CommandOutputCaptureJournalStateV1,
    CommandOutputCaptureRecovery, CommandOutputStoreError, create_private_file, io_error,
    open_private_file, sync_directory, validate_private_directory, validate_private_file,
};
use crate::sensitive_output::SensitiveOutputCoreDumpSuppressionV1;

const FORMAT_VERSION: u32 = 2;
pub(super) const JOURNAL_PREFIX: &str = "sensitive-output-journal-v2-";
pub(super) const LOCK_FILE: &str = "writer.lock";
const RECORD_DIGEST_DOMAIN: &[u8] = b"grok-build/sensitive-output-journal/v2\0";
const CLEANUP_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"grok-build/sensitive-output-runner-cleanup-receipt/v2\0";
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const TERMINAL_GENERATION: u64 = 8;
#[allow(
    clippy::large_enum_variant,
    reason = "the closed durable JSON schema keeps every generation payload directly typed"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum RecordDataV2 {
    IntentBound {
        runner_session_id: String,
        effect_id: String,
        request_digest: Digest,
        intent_digest: Digest,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    },
    AcquiredBound {
        acquired: CommandOutputCaptureAcquiredV1,
    },
    WriterAttached {
        writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    },
    LaunchIntended {
        launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
        core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    },
    ScannedClean {
        scanned_clean_at_unix_ms: u64,
    },
    SensitiveOutputDetected {},
    Finished {
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        finished_at_unix_ms: u64,
    },
    CleanupIntended {
        command_domain_cleanup_proof_id: String,
        staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    },
    Published {
        published_store_head: CommandOutputCaptureStoreHeadV1,
        published_at_unix_ms: u64,
    },
    Cleaned {
        v1_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
    TerminalPrepared {
        terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: Digest,
        termination: CommandTerminationV1,
        terminal_prepared_at_unix_ms: u64,
    },
    SensitiveOutputRejected {
        termination: CommandTerminationV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecordV2 {
    format_version: u32,
    generation: u64,
    journal_id: String,
    capture_id: String,
    predecessor_digest: Option<Digest>,
    data: RecordDataV2,
    record_digest: Digest,
}

#[derive(Serialize)]
struct RecordDigestPreimage<'a> {
    format_version: u32,
    generation: u64,
    journal_id: &'a str,
    capture_id: &'a str,
    predecessor_digest: Option<&'a Digest>,
    data: &'a RecordDataV2,
}

impl RecordV2 {
    fn new(
        generation: u64,
        journal_id: String,
        capture_id: String,
        predecessor_digest: Option<Digest>,
        data: RecordDataV2,
    ) -> Result<Self, CommandOutputStoreError> {
        let canonical = serde_json::to_vec(&RecordDigestPreimage {
            format_version: FORMAT_VERSION,
            generation,
            journal_id: &journal_id,
            capture_id: &capture_id,
            predecessor_digest: predecessor_digest.as_ref(),
            data: &data,
        })
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        let record_digest = domain_digest(RECORD_DIGEST_DOMAIN, &canonical);
        Ok(Self {
            format_version: FORMAT_VERSION,
            generation,
            journal_id,
            capture_id,
            predecessor_digest,
            data,
            record_digest,
        })
    }

    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        if self.format_version != FORMAT_VERSION
            || self.generation == 0
            || self.generation > TERMINAL_GENERATION
        {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output journal record has unsupported version or generation".into(),
            ));
        }
        let expected = Self::new(
            self.generation,
            self.journal_id.clone(),
            self.capture_id.clone(),
            self.predecessor_digest.clone(),
            self.data.clone(),
        )?;
        if expected.record_digest != self.record_digest {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output journal record digest differs from secret-free fields".into(),
            ));
        }
        Ok(())
    }

    fn head(&self) -> SensitiveOutputJournalHeadV1 {
        SensitiveOutputJournalHeadV1 {
            generation: self.generation,
            record_digest: self.record_digest.clone(),
        }
    }
}

/// Exact, secret-free readback of a rejected v2 capture lifecycle.
#[allow(
    missing_docs,
    reason = "public fields are the exact closed v2 rejection readback"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputRejectionJournalReceiptV2 {
    pub journal_id: String,
    pub capture_id: String,
    pub runner_session_id: String,
    pub effect_id: String,
    pub request_digest: Digest,
    pub intent_digest: Digest,
    pub acquired: CommandOutputCaptureAcquiredV1,
    pub acquired_anchor_digest: Digest,
    pub acquired_store_head: CommandOutputCaptureStoreHeadV1,
    pub writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub writer_attached_journal_head: SensitiveOutputJournalHeadV1,
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    pub detected_journal_head: SensitiveOutputJournalHeadV1,
    pub cleanup_intended_journal_head: SensitiveOutputJournalHeadV1,
    pub cleaned_journal_head: SensitiveOutputJournalHeadV1,
    pub rejected_terminal_journal_head: SensitiveOutputJournalHeadV1,
    pub v1_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    pub command_domain_cleanup_proof_id: String,
    pub staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    pub termination: CommandTerminationV1,
    pub cleanup_receipt_id: String,
    pub cleanup_receipt_digest: Digest,
}

impl SensitiveOutputRejectionJournalReceiptV2 {
    /// Validates the complete rejection receipt and its exact request and
    /// acquired-capture binding.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed receipt or crossed request,
    /// acquisition, capture, journal, policy, cleanup, or terminal identity.
    pub fn validate_request_binding(
        &self,
        runner_session_id: &str,
        effect_id: &str,
        request_digest: &Digest,
        acquired: &CommandOutputCaptureAcquiredV1,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate()?;
        acquired
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if self.runner_session_id != runner_session_id
            || self.effect_id != effect_id
            || &self.request_digest != request_digest
            || &self.acquired != acquired
            || self.capture_id != acquired.capture_id
            || self.intent_digest != acquired.intent_digest
            || self.acquired_anchor_digest != acquired.acquired_anchor_digest
            || self.acquired_store_head != acquired.store_head
        {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output rejection readback crossed its request or acquisition".into(),
            ));
        }
        Ok(())
    }

    /// Recomputes and validates every public field, journal generation, store
    /// head, cleanup identity, and secret-free rejection commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed field, crossed identity, invalid
    /// generation chain, cleanup mismatch, or noncanonical commitment.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.acquired
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.detector_policy
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.core_dump_suppression.validate().map_err(|_| {
            CommandOutputStoreError::Source("core-dump suppression is invalid".into())
        })?;
        self.termination
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.staging_neutralization
            .validate_against(&self.acquired)
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        for head in [
            &self.acquired_store_head,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.v1_cleaned_store_head,
        ] {
            head.validate()
                .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        }
        validate_journal_identity(&self.journal_id, &self.capture_id)?;
        validate_bounded_id("runner_session_id", &self.runner_session_id)?;
        validate_bounded_id("effect_id", &self.effect_id)?;
        validate_bounded_id("cleanup_receipt_id", &self.cleanup_receipt_id)?;
        if self.capture_id != self.acquired.capture_id
            || self.runner_session_id != self.acquired.source.runner_session_id
            || self.effect_id != self.acquired.source.effect_id
            || self.request_digest != self.acquired.source.request_digest
            || self.intent_digest != self.acquired.intent_digest
            || self.acquired_anchor_digest != self.acquired.acquired_anchor_digest
            || self.acquired_store_head != self.acquired.store_head
            || self.acquired_store_head.generation >= self.writer_attached_store_head.generation
            || self.writer_attached_store_head.generation
                >= self.launch_intended_store_head.generation
            || !all_digests_distinct(&[
                &self.acquired_store_head.record_digest,
                &self.writer_attached_store_head.record_digest,
                &self.launch_intended_store_head.record_digest,
                &self.v1_cleaned_store_head.record_digest,
            ])
        {
            return Err(CommandOutputStoreError::Manifest(
                "sensitive-output rejection heads or boundary times are non-monotonic".into(),
            ));
        }
        Digest::parse(self.command_domain_cleanup_proof_id.clone())
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        validate_rejection_receipt_chain(self)?;
        Ok(())
    }
}

/// Exact readback of the clean v2 scan/publication branch.
#[allow(
    missing_docs,
    reason = "public fields are the exact closed v2 clean readback"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputCleanJournalReceiptV2 {
    pub journal_id: String,
    pub capture_id: String,
    pub runner_session_id: String,
    pub effect_id: String,
    pub request_digest: Digest,
    pub intent_digest: Digest,
    pub acquired: CommandOutputCaptureAcquiredV1,
    pub acquired_anchor_digest: Digest,
    pub acquired_store_head: CommandOutputCaptureStoreHeadV1,
    pub writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    pub intent_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub acquired_bound_journal_head: SensitiveOutputJournalHeadV1,
    pub writer_attached_journal_head: SensitiveOutputJournalHeadV1,
    pub launch_intended_journal_head: SensitiveOutputJournalHeadV1,
    pub scanned_clean_journal_head: SensitiveOutputJournalHeadV1,
    pub finished_journal_head: SensitiveOutputJournalHeadV1,
    pub published_journal_head: SensitiveOutputJournalHeadV1,
    pub terminal_prepared_journal_head: SensitiveOutputJournalHeadV1,
    pub finished_store_head: CommandOutputCaptureStoreHeadV1,
    pub published_store_head: CommandOutputCaptureStoreHeadV1,
    pub terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
    pub terminal_record_digest: Digest,
    pub termination: CommandTerminationV1,
    pub scanned_clean_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub published_at_unix_ms: u64,
    pub terminal_prepared_at_unix_ms: u64,
}

/// Exact current stage of one partial or terminal v2 journal.
#[allow(
    missing_docs,
    reason = "variant fields mirror one closed secret-free journal state"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SensitiveOutputJournalStageV2 {
    IntentBound,
    AcquiredBound,
    WriterAttached {
        writer_attached_store_head: CommandOutputCaptureStoreHeadV1,
    },
    LaunchIntended {
        launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
        core_dump_suppression: SensitiveOutputCoreDumpSuppressionV1,
    },
    ScannedClean {
        scanned_clean_at_unix_ms: u64,
    },
    SensitiveOutputDetected {},
    Finished {
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        finished_at_unix_ms: u64,
    },
    CleanupIntended {
        command_domain_cleanup_proof_id: String,
        staging_neutralization: SensitiveOutputStagingNeutralizationReceiptV1,
    },
    Published {
        published_store_head: CommandOutputCaptureStoreHeadV1,
        published_at_unix_ms: u64,
    },
    Cleaned {
        v1_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
    TerminalPrepared {
        terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_record_digest: Digest,
        termination: CommandTerminationV1,
        terminal_prepared_at_unix_ms: u64,
    },
    SensitiveOutputRejected {
        termination: CommandTerminationV1,
        cleanup_receipt_id: String,
        cleanup_receipt_digest: Digest,
    },
}

impl SensitiveOutputJournalStageV2 {
    const fn generation(&self) -> u64 {
        match self {
            Self::IntentBound => 1,
            Self::AcquiredBound => 2,
            Self::WriterAttached { .. } => 3,
            Self::LaunchIntended { .. } => 4,
            Self::ScannedClean { .. } | Self::SensitiveOutputDetected { .. } => 5,
            Self::Finished { .. } | Self::CleanupIntended { .. } => 6,
            Self::Published { .. } | Self::Cleaned { .. } => 7,
            Self::TerminalPrepared { .. } | Self::SensitiveOutputRejected { .. } => 8,
        }
    }
}

/// Typed restart readback for every durable v2 generation.
#[allow(
    missing_docs,
    reason = "public fields are the complete secret-free partial readback"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SensitiveOutputJournalRecoveryV2 {
    journal_id: String,
    capture_id: String,
    runner_session_id: String,
    effect_id: String,
    request_digest: Digest,
    intent_digest: Digest,
    detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    core_dump_suppression: Option<SensitiveOutputCoreDumpSuppressionV1>,
    launch_intended_journal_head: Option<SensitiveOutputJournalHeadV1>,
    launch_intended_store_head: Option<CommandOutputCaptureStoreHeadV1>,
    acquired: Option<CommandOutputCaptureAcquiredV1>,
    head: SensitiveOutputJournalHeadV1,
    stage: SensitiveOutputJournalStageV2,
}

impl SensitiveOutputJournalRecoveryV2 {
    /// Exact current journal stage. This diagnostic view grants no resume
    /// authority; every transition reopens the private canonical record chain.
    #[must_use]
    pub const fn stage(&self) -> &SensitiveOutputJournalStageV2 {
        &self.stage
    }

    /// Exact authenticated current journal head.
    #[must_use]
    pub const fn head(&self) -> &SensitiveOutputJournalHeadV1 {
        &self.head
    }

    /// Exact capture identity named by the private journal.
    #[must_use]
    pub fn capture_id(&self) -> &str {
        &self.capture_id
    }

    /// Full acquired anchor once generation two is durable.
    #[must_use]
    pub const fn acquired(&self) -> Option<&CommandOutputCaptureAcquiredV1> {
        self.acquired.as_ref()
    }

    /// Exact admitted detector policy from generation one.
    #[must_use]
    pub const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        &self.detector_policy
    }

    /// Exact v1 `LaunchIntended` head once generation four is durable.
    #[must_use]
    pub const fn launch_intended_store_head(&self) -> Option<&CommandOutputCaptureStoreHeadV1> {
        self.launch_intended_store_head.as_ref()
    }

    /// Validates that this prefix belongs to the exact core capture intent.
    /// This grants no execution or cleanup authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed intent or crossed capture, session,
    /// effect, request, or intent digest.
    pub fn validate_intent_binding(
        &self,
        intent: &CommandOutputCaptureIntentV1,
    ) -> Result<(), CommandOutputStoreError> {
        intent
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if self.capture_id != intent.capture_id
            || self.runner_session_id != intent.source.runner_session_id
            || self.effect_id != intent.source.effect_id
            || self.request_digest != intent.source.request_digest
            || self.intent_digest != intent.intent_digest
        {
            return Err(manifest(
                "sensitive-output journal prefix crossed its core capture intent",
            ));
        }
        Ok(())
    }

    /// Validates the self-contained current-stage identity.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identities, policy, acquisition, stage,
    /// journal head, launch profile, or generation-dependent presence fields.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        validate_journal_identity(&self.journal_id, &self.capture_id)?;
        validate_bounded_id("runner_session_id", &self.runner_session_id)?;
        validate_bounded_id("effect_id", &self.effect_id)?;
        self.detector_policy
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if let Some(profile) = &self.core_dump_suppression {
            profile.validate().map_err(|_| {
                CommandOutputStoreError::Source("core-dump suppression is invalid".into())
            })?;
        }
        self.head
            .validate()
            .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        if let Some(head) = &self.launch_intended_journal_head {
            head.validate()
                .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
            if head.generation != 4 {
                return Err(manifest(
                    "partial readback has a non-generation-four launch head",
                ));
            }
        }
        if let Some(head) = &self.launch_intended_store_head {
            head.validate()
                .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        }
        if self.head.generation != self.stage.generation()
            || self.head.generation >= 2 && self.acquired.is_none()
            || self.head.generation == 1 && self.acquired.is_some()
            || self.head.generation >= 4 && self.core_dump_suppression.is_none()
            || self.head.generation < 4 && self.core_dump_suppression.is_some()
            || self.head.generation >= 4 && self.launch_intended_journal_head.is_none()
            || self.head.generation < 4 && self.launch_intended_journal_head.is_some()
            || self.head.generation >= 4 && self.launch_intended_store_head.is_none()
            || self.head.generation < 4 && self.launch_intended_store_head.is_some()
        {
            return Err(manifest(
                "sensitive-output partial readback stage, head, or acquisition presence differs",
            ));
        }
        if let Some(acquired) = &self.acquired {
            acquired
                .validate()
                .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
            if acquired.capture_id != self.capture_id
                || acquired.source.runner_session_id != self.runner_session_id
                || acquired.source.effect_id != self.effect_id
                || acquired.source.request_digest != self.request_digest
                || acquired.intent_digest != self.intent_digest
            {
                return Err(manifest(
                    "sensitive-output partial readback crossed its acquired request binding",
                ));
            }
        }
        Ok(())
    }
}

impl SensitiveOutputCleanJournalReceiptV2 {
    /// Validates the complete clean receipt and its exact request and
    /// acquired-capture binding.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed receipt or crossed request,
    /// acquisition, capture, journal, policy, publication, or terminal identity.
    pub fn validate_request_binding(
        &self,
        runner_session_id: &str,
        effect_id: &str,
        request_digest: &Digest,
        acquired: &CommandOutputCaptureAcquiredV1,
    ) -> Result<(), CommandOutputStoreError> {
        self.validate()?;
        acquired
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if self.runner_session_id != runner_session_id
            || self.effect_id != effect_id
            || &self.request_digest != request_digest
            || &self.acquired != acquired
            || self.capture_id != acquired.capture_id
            || self.intent_digest != acquired.intent_digest
            || self.acquired_anchor_digest != acquired.acquired_anchor_digest
            || self.acquired_store_head != acquired.store_head
        {
            return Err(CommandOutputStoreError::Manifest(
                "clean sensitive-output readback crossed its request or acquisition".into(),
            ));
        }
        Ok(())
    }

    /// Recomputes and validates every public field, journal generation, store
    /// head, publication identity, and terminal commitment.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed field, crossed identity, invalid
    /// generation chain, publication mismatch, or noncanonical commitment.
    pub fn validate(&self) -> Result<(), CommandOutputStoreError> {
        self.acquired
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.detector_policy
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        self.core_dump_suppression.validate().map_err(|_| {
            CommandOutputStoreError::Source("core-dump suppression is invalid".into())
        })?;
        for head in [
            &self.acquired_store_head,
            &self.writer_attached_store_head,
            &self.launch_intended_store_head,
            &self.finished_store_head,
            &self.published_store_head,
            &self.terminal_prepared_store_head,
        ] {
            head.validate()
                .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
        }
        validate_journal_identity(&self.journal_id, &self.capture_id)?;
        validate_bounded_id("runner_session_id", &self.runner_session_id)?;
        validate_bounded_id("effect_id", &self.effect_id)?;
        self.termination
            .validate()
            .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
        if self.capture_id != self.acquired.capture_id
            || self.runner_session_id != self.acquired.source.runner_session_id
            || self.effect_id != self.acquired.source.effect_id
            || self.request_digest != self.acquired.source.request_digest
            || self.intent_digest != self.acquired.intent_digest
            || self.acquired_anchor_digest != self.acquired.acquired_anchor_digest
            || self.acquired_store_head != self.acquired.store_head
            || self.acquired_store_head.generation >= self.writer_attached_store_head.generation
            || self.writer_attached_store_head.generation
                >= self.launch_intended_store_head.generation
            || self.launch_intended_store_head.generation >= self.finished_store_head.generation
            || self.finished_store_head.generation >= self.published_store_head.generation
            || self.published_store_head.generation >= self.terminal_prepared_store_head.generation
            || self.scanned_clean_journal_head.generation != 5
            || self.finished_journal_head.generation != 6
            || self.published_journal_head.generation != 7
            || self.terminal_prepared_journal_head.generation != 8
            || self.scanned_clean_at_unix_ms < self.acquired.acquired_at_unix_ms
            || self.scanned_clean_at_unix_ms > self.finished_at_unix_ms
            || self.finished_at_unix_ms > self.published_at_unix_ms
            || self.published_at_unix_ms > self.terminal_prepared_at_unix_ms
            || !all_digests_distinct(&[
                &self.scanned_clean_journal_head.record_digest,
                &self.finished_journal_head.record_digest,
                &self.published_journal_head.record_digest,
                &self.terminal_prepared_journal_head.record_digest,
            ])
            || !all_digests_distinct(&[
                &self.acquired_store_head.record_digest,
                &self.writer_attached_store_head.record_digest,
                &self.launch_intended_store_head.record_digest,
                &self.finished_store_head.record_digest,
                &self.published_store_head.record_digest,
                &self.terminal_prepared_store_head.record_digest,
            ])
        {
            return Err(CommandOutputStoreError::Manifest(
                "clean sensitive-output journal or v1 store heads are non-monotonic".into(),
            ));
        }
        validate_clean_receipt_chain(self)?;
        Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the validator visibly joins every independently named durable receipt field"
)]
fn validate_common_receipt_chain(
    journal_id: &str,
    capture_id: &str,
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &Digest,
    intent_digest: &Digest,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    writer_attached_store_head: &CommandOutputCaptureStoreHeadV1,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
    expected_heads: [&SensitiveOutputJournalHeadV1; 4],
) -> Result<Digest, CommandOutputStoreError> {
    let intent_bound = RecordV2::new(
        1,
        journal_id.to_owned(),
        capture_id.to_owned(),
        None,
        RecordDataV2::IntentBound {
            runner_session_id: runner_session_id.to_owned(),
            effect_id: effect_id.to_owned(),
            request_digest: request_digest.clone(),
            intent_digest: intent_digest.clone(),
            detector_policy: detector_policy.clone(),
        },
    )?;
    let acquired_bound = RecordV2::new(
        2,
        journal_id.to_owned(),
        capture_id.to_owned(),
        Some(intent_bound.record_digest.clone()),
        RecordDataV2::AcquiredBound {
            acquired: acquired.clone(),
        },
    )?;
    let writer_attached = RecordV2::new(
        3,
        journal_id.to_owned(),
        capture_id.to_owned(),
        Some(acquired_bound.record_digest.clone()),
        RecordDataV2::WriterAttached {
            writer_attached_store_head: writer_attached_store_head.clone(),
        },
    )?;
    let launch_intended = RecordV2::new(
        4,
        journal_id.to_owned(),
        capture_id.to_owned(),
        Some(writer_attached.record_digest.clone()),
        RecordDataV2::LaunchIntended {
            launch_intended_store_head: launch_intended_store_head.clone(),
            core_dump_suppression: core_dump_suppression.clone(),
        },
    )?;
    let actual = [
        intent_bound.head(),
        acquired_bound.head(),
        writer_attached.head(),
        launch_intended.head(),
    ];
    if actual
        .iter()
        .zip(expected_heads)
        .any(|(actual, expected)| actual != expected)
    {
        return Err(manifest(
            "sensitive-output receipt common journal chain is not self-authenticating",
        ));
    }
    Ok(launch_intended.record_digest)
}

fn validate_rejection_receipt_chain(
    receipt: &SensitiveOutputRejectionJournalReceiptV2,
) -> Result<(), CommandOutputStoreError> {
    let launch_digest = validate_common_receipt_chain(
        &receipt.journal_id,
        &receipt.capture_id,
        &receipt.runner_session_id,
        &receipt.effect_id,
        &receipt.request_digest,
        &receipt.intent_digest,
        &receipt.detector_policy,
        &receipt.acquired,
        &receipt.writer_attached_store_head,
        &receipt.launch_intended_store_head,
        &receipt.core_dump_suppression,
        [
            &receipt.intent_bound_journal_head,
            &receipt.acquired_bound_journal_head,
            &receipt.writer_attached_journal_head,
            &receipt.launch_intended_journal_head,
        ],
    )?;
    let detected = RecordV2::new(
        5,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(launch_digest),
        RecordDataV2::SensitiveOutputDetected {},
    )?;
    let cleanup_intended = RecordV2::new(
        6,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(detected.record_digest.clone()),
        RecordDataV2::CleanupIntended {
            command_domain_cleanup_proof_id: receipt.command_domain_cleanup_proof_id.clone(),
            staging_neutralization: receipt.staging_neutralization.clone(),
        },
    )?;
    let cleaned = RecordV2::new(
        7,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(cleanup_intended.record_digest.clone()),
        RecordDataV2::Cleaned {
            v1_cleaned_store_head: receipt.v1_cleaned_store_head.clone(),
            cleanup_receipt_id: receipt.cleanup_receipt_id.clone(),
            cleanup_receipt_digest: receipt.cleanup_receipt_digest.clone(),
        },
    )?;
    let rejected = RecordV2::new(
        8,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(cleaned.record_digest.clone()),
        RecordDataV2::SensitiveOutputRejected {
            termination: receipt.termination,
            cleanup_receipt_id: receipt.cleanup_receipt_id.clone(),
            cleanup_receipt_digest: receipt.cleanup_receipt_digest.clone(),
        },
    )?;
    if detected.head() != receipt.detected_journal_head
        || cleanup_intended.head() != receipt.cleanup_intended_journal_head
        || cleaned.head() != receipt.cleaned_journal_head
        || rejected.head() != receipt.rejected_terminal_journal_head
    {
        return Err(manifest(
            "sensitive-output rejection receipt branch is not self-authenticating",
        ));
    }
    Ok(())
}

fn validate_clean_receipt_chain(
    receipt: &SensitiveOutputCleanJournalReceiptV2,
) -> Result<(), CommandOutputStoreError> {
    let launch_digest = validate_common_receipt_chain(
        &receipt.journal_id,
        &receipt.capture_id,
        &receipt.runner_session_id,
        &receipt.effect_id,
        &receipt.request_digest,
        &receipt.intent_digest,
        &receipt.detector_policy,
        &receipt.acquired,
        &receipt.writer_attached_store_head,
        &receipt.launch_intended_store_head,
        &receipt.core_dump_suppression,
        [
            &receipt.intent_bound_journal_head,
            &receipt.acquired_bound_journal_head,
            &receipt.writer_attached_journal_head,
            &receipt.launch_intended_journal_head,
        ],
    )?;
    let scanned = RecordV2::new(
        5,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(launch_digest),
        RecordDataV2::ScannedClean {
            scanned_clean_at_unix_ms: receipt.scanned_clean_at_unix_ms,
        },
    )?;
    let finished = RecordV2::new(
        6,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(scanned.record_digest.clone()),
        RecordDataV2::Finished {
            finished_store_head: receipt.finished_store_head.clone(),
            finished_at_unix_ms: receipt.finished_at_unix_ms,
        },
    )?;
    let published = RecordV2::new(
        7,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(finished.record_digest.clone()),
        RecordDataV2::Published {
            published_store_head: receipt.published_store_head.clone(),
            published_at_unix_ms: receipt.published_at_unix_ms,
        },
    )?;
    let terminal = RecordV2::new(
        8,
        receipt.journal_id.clone(),
        receipt.capture_id.clone(),
        Some(published.record_digest.clone()),
        RecordDataV2::TerminalPrepared {
            terminal_prepared_store_head: receipt.terminal_prepared_store_head.clone(),
            terminal_record_digest: receipt.terminal_record_digest.clone(),
            termination: receipt.termination,
            terminal_prepared_at_unix_ms: receipt.terminal_prepared_at_unix_ms,
        },
    )?;
    if scanned.head() != receipt.scanned_clean_journal_head
        || finished.head() != receipt.finished_journal_head
        || published.head() != receipt.published_journal_head
        || terminal.head() != receipt.terminal_prepared_journal_head
    {
        return Err(manifest(
            "sensitive-output clean receipt branch is not self-authenticating",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct CleanupReceiptPreimage<'a> {
    journal_id: &'a str,
    capture_id: &'a str,
    runner_session_id: &'a str,
    effect_id: &'a str,
    request_digest: &'a Digest,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    detected_journal_head: &'a SensitiveOutputJournalHeadV1,
    v1_cleaned_store_head: &'a CommandOutputCaptureStoreHeadV1,
    command_domain_cleanup_proof_id: &'a str,
    staging_neutralization: &'a SensitiveOutputStagingNeutralizationReceiptV1,
    cleanup_receipt_id: &'a str,
}

pub(super) fn record_intent(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    intent
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
        .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
    let mut journal = JournalLease::open_or_create(store, &intent.capture_id)?;
    journal.append_at(
        1,
        RecordDataV2::IntentBound {
            runner_session_id: intent.source.runner_session_id.clone(),
            effect_id: intent.source.effect_id.clone(),
            request_digest: intent.source.request_digest.clone(),
            intent_digest: intent.intent_digest.clone(),
            detector_policy: detector_policy.clone(),
        },
    )?;
    journal.head()
}

pub(super) fn record_acquired(
    store: &CapabilityCommandOutputStore,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    acquired
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    let mut journal = JournalLease::open_existing(store, &acquired.capture_id)?;
    validate_intent_binding(&journal, acquired)?;
    journal.append_at(
        2,
        RecordDataV2::AcquiredBound {
            acquired: acquired.clone(),
        },
    )?;
    journal.head()
}

pub(super) fn record_writer_attached(
    store: &CapabilityCommandOutputStore,
    acquired: &CommandOutputCaptureAcquiredV1,
    writer_attached_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, &acquired.capture_id)?;
    validate_acquired_binding(&journal, acquired)?;
    require_forward_store_head(
        &acquired.store_head,
        writer_attached_store_head,
        "WriterAttached",
    )?;
    journal.append_at(
        3,
        RecordDataV2::WriterAttached {
            writer_attached_store_head: writer_attached_store_head.clone(),
        },
    )?;
    journal.head()
}

pub(super) fn record_launch_intended(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    launch_intended_store_head: &CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: &SensitiveOutputCoreDumpSuppressionV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_generation(&journal, 3, "WriterAttached")?;
    let RecordDataV2::WriterAttached {
        writer_attached_store_head,
    } = &journal.record(3)?.data
    else {
        return Err(manifest("v2 generation 3 is not WriterAttached"));
    };
    require_forward_store_head(
        writer_attached_store_head,
        launch_intended_store_head,
        "LaunchIntended",
    )?;
    core_dump_suppression
        .validate()
        .map_err(|_| CommandOutputStoreError::Source("core-dump suppression is invalid".into()))?;
    journal.append_at(
        4,
        RecordDataV2::LaunchIntended {
            launch_intended_store_head: launch_intended_store_head.clone(),
            core_dump_suppression: core_dump_suppression.clone(),
        },
    )?;
    journal.head()
}

pub(super) fn record_detected(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_generation(&journal, 4, "LaunchIntended")?;
    journal.append_at(5, RecordDataV2::SensitiveOutputDetected {})?;
    journal.head()
}

pub(super) fn record_scanned_clean(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_generation(&journal, 4, "LaunchIntended")?;
    let scanned_clean_at_unix_ms = unix_time_ms_at_least(acquired_time(&journal)?)?;
    journal.append_at(
        5,
        RecordDataV2::ScannedClean {
            scanned_clean_at_unix_ms,
        },
    )?;
    journal.head()
}

pub(super) fn record_finished(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    finished_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_state(
        &journal,
        5,
        |data| matches!(data, RecordDataV2::ScannedClean { .. }),
        "ScannedClean",
    )?;
    let base = base_fields(&journal)?;
    require_forward_store_head(
        base.launch_intended_store_head,
        finished_store_head,
        "Finished",
    )?;
    let finished_at_unix_ms = unix_time_ms_at_least(scanned_clean_time(&journal)?)?;
    journal.append_at(
        6,
        RecordDataV2::Finished {
            finished_store_head: finished_store_head.clone(),
            finished_at_unix_ms,
        },
    )?;
    journal.head()
}

pub(super) fn record_published(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    published_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_state(
        &journal,
        6,
        |data| matches!(data, RecordDataV2::Finished { .. }),
        "Finished",
    )?;
    let RecordDataV2::Finished {
        finished_store_head,
        finished_at_unix_ms,
    } = &journal.record(6)?.data
    else {
        unreachable!("required Finished state");
    };
    require_forward_store_head(finished_store_head, published_store_head, "Published")?;
    let published_at_unix_ms = unix_time_ms_at_least(*finished_at_unix_ms)?;
    journal.append_at(
        7,
        RecordDataV2::Published {
            published_store_head: published_store_head.clone(),
            published_at_unix_ms,
        },
    )?;
    journal.head()
}

pub(super) fn record_terminal_prepared(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    terminal_prepared_store_head: &CommandOutputCaptureStoreHeadV1,
    terminal_record_digest: &Digest,
    termination: CommandTerminationV1,
) -> Result<SensitiveOutputCleanJournalReceiptV2, CommandOutputStoreError> {
    termination
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    require_state(
        &journal,
        7,
        |data| matches!(data, RecordDataV2::Published { .. }),
        "Published",
    )?;
    let RecordDataV2::Published {
        published_store_head,
        published_at_unix_ms,
    } = &journal.record(7)?.data
    else {
        unreachable!("required Published state");
    };
    require_forward_store_head(
        published_store_head,
        terminal_prepared_store_head,
        "TerminalPrepared",
    )?;
    let terminal_prepared_at_unix_ms = unix_time_ms_at_least(*published_at_unix_ms)?;
    journal.append_at(
        8,
        RecordDataV2::TerminalPrepared {
            terminal_prepared_store_head: terminal_prepared_store_head.clone(),
            terminal_record_digest: terminal_record_digest.clone(),
            termination,
            terminal_prepared_at_unix_ms,
        },
    )?;
    clean_receipt(&journal)
}

pub(super) fn record_cleanup_intended(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    command_domain_cleanup_proof_id: &str,
    staging_neutralization: &SensitiveOutputStagingNeutralizationReceiptV1,
) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
    Digest::parse(command_domain_cleanup_proof_id.to_owned())
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    let base = base_fields(&journal)?;
    staging_neutralization
        .validate_against(base.acquired)
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    journal.append_at(
        6,
        RecordDataV2::CleanupIntended {
            command_domain_cleanup_proof_id: command_domain_cleanup_proof_id.to_owned(),
            staging_neutralization: staging_neutralization.clone(),
        },
    )?;
    journal.head()
}

pub(super) fn complete_rejection(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    v1_cleaned_store_head: &CommandOutputCaptureStoreHeadV1,
    termination: CommandTerminationV1,
) -> Result<SensitiveOutputRejectionJournalReceiptV2, CommandOutputStoreError> {
    termination
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    if journal.head()?.generation == 8 {
        let receipt = rejection_receipt(&journal)?;
        if receipt.termination != termination
            || receipt.v1_cleaned_store_head != *v1_cleaned_store_head
        {
            return Err(manifest(
                "idempotent rejection completion crossed termination or v1 cleanup",
            ));
        }
        return Ok(receipt);
    }
    record_cleaned_if_needed(&mut journal, capture_id, v1_cleaned_store_head)?;
    let RecordDataV2::Cleaned {
        cleanup_receipt_id,
        cleanup_receipt_digest,
        ..
    } = &journal.record(7)?.data
    else {
        return Err(manifest("v2 generation 7 is not Cleaned"));
    };
    journal.append_at(
        8,
        RecordDataV2::SensitiveOutputRejected {
            termination,
            cleanup_receipt_id: cleanup_receipt_id.clone(),
            cleanup_receipt_digest: cleanup_receipt_digest.clone(),
        },
    )?;
    rejection_receipt(&journal)
}

fn record_cleaned_if_needed(
    journal: &mut JournalLease,
    capture_id: &str,
    v1_cleaned_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<(), CommandOutputStoreError> {
    if !matches!(journal.head()?.generation, 6 | 7) {
        return Err(manifest(
            "rejection completion requires CleanupIntended or Cleaned",
        ));
    }
    {
        let base = base_fields(journal)?;
        require_forward_store_head(
            base.launch_intended_store_head,
            v1_cleaned_store_head,
            "Cleaned",
        )?;
    }
    if journal.head()?.generation == 6 {
        let (command_domain_cleanup_proof_id, staging_neutralization) =
            rejection_boundary_fields(journal)?;
        let cleanup_receipt_id = format!("sensitive-output-cleanup-{capture_id}");
        let cleanup_receipt_digest = {
            let base = base_fields(journal)?;
            domain_json_digest(
                CLEANUP_RECEIPT_DIGEST_DOMAIN,
                &CleanupReceiptPreimage {
                    journal_id: &journal.journal_id,
                    capture_id,
                    runner_session_id: base.runner_session_id,
                    effect_id: base.effect_id,
                    request_digest: base.request_digest,
                    detector_policy: base.detector_policy,
                    detected_journal_head: &journal.record(5)?.head(),
                    v1_cleaned_store_head,
                    command_domain_cleanup_proof_id,
                    staging_neutralization,
                    cleanup_receipt_id: &cleanup_receipt_id,
                },
            )?
        };
        journal.append_at(
            7,
            RecordDataV2::Cleaned {
                v1_cleaned_store_head: v1_cleaned_store_head.clone(),
                cleanup_receipt_id,
                cleanup_receipt_digest,
            },
        )?;
    }
    let RecordDataV2::Cleaned {
        v1_cleaned_store_head: recorded_v1_cleaned_store_head,
        ..
    } = &journal.record(7)?.data
    else {
        return Err(manifest("v2 generation 7 is not Cleaned"));
    };
    if recorded_v1_cleaned_store_head != v1_cleaned_store_head {
        return Err(manifest("v2 Cleaned crossed its exact v1 cleanup head"));
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(super) fn record_cleaned_test_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
    v1_cleaned_store_head: &CommandOutputCaptureStoreHeadV1,
) -> Result<(), CommandOutputStoreError> {
    let mut journal = JournalLease::open_existing(store, capture_id)?;
    record_cleaned_if_needed(&mut journal, capture_id, v1_cleaned_store_head)
}

pub(super) fn read_rejection(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<Option<SensitiveOutputRejectionJournalReceiptV2>, CommandOutputStoreError> {
    let journal = JournalLease::open_existing(store, capture_id)?;
    if journal.records.len() < usize::try_from(TERMINAL_GENERATION).expect("eight fits usize") {
        return Ok(None);
    }
    match journal.record(8)?.data {
        RecordDataV2::SensitiveOutputRejected { .. } => rejection_receipt(&journal).map(Some),
        RecordDataV2::TerminalPrepared { .. } => Err(CommandOutputStoreError::Manifest(
            "requested rejection readback from the clean v2 branch".into(),
        )),
        _ => Err(CommandOutputStoreError::Manifest(
            "sensitive-output v2 generation 8 is not terminal".into(),
        )),
    }
}

pub(super) fn read_clean(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<Option<SensitiveOutputCleanJournalReceiptV2>, CommandOutputStoreError> {
    let journal = JournalLease::open_existing(store, capture_id)?;
    if journal.records.len() < usize::try_from(TERMINAL_GENERATION).expect("eight fits usize") {
        return Ok(None);
    }
    match journal.record(8)?.data {
        RecordDataV2::TerminalPrepared { .. } => clean_receipt(&journal).map(Some),
        RecordDataV2::SensitiveOutputRejected { .. } => Err(CommandOutputStoreError::Manifest(
            "requested clean readback from the rejected v2 branch".into(),
        )),
        _ => Err(CommandOutputStoreError::Manifest(
            "sensitive-output v2 generation 8 is not terminal".into(),
        )),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one decoder keeps the closed generation-to-stage projection exhaustive and auditable"
)]
pub(super) fn read_recovery(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<SensitiveOutputJournalRecoveryV2, CommandOutputStoreError> {
    let journal = JournalLease::open_existing(store, capture_id)?;
    recovery_from_journal(&journal)
}

#[allow(
    clippy::too_many_lines,
    reason = "the single-lock projection keeps the closed generation-to-stage mapping exhaustive"
)]
fn recovery_from_journal(
    journal: &JournalLease,
) -> Result<SensitiveOutputJournalRecoveryV2, CommandOutputStoreError> {
    let RecordDataV2::IntentBound {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
    } = &journal.record(1)?.data
    else {
        return Err(manifest("v2 generation 1 is not IntentBound"));
    };
    let acquired = if journal.records.len() >= 2 {
        let RecordDataV2::AcquiredBound { acquired } = &journal.record(2)?.data else {
            return Err(manifest("v2 generation 2 is not AcquiredBound"));
        };
        Some(acquired.clone())
    } else {
        None
    };
    let current = journal
        .records
        .last()
        .ok_or_else(|| manifest("empty sensitive-output journal"))?;
    let stage = match &current.data {
        RecordDataV2::IntentBound { .. } => SensitiveOutputJournalStageV2::IntentBound,
        RecordDataV2::AcquiredBound { .. } => SensitiveOutputJournalStageV2::AcquiredBound,
        RecordDataV2::WriterAttached {
            writer_attached_store_head,
        } => SensitiveOutputJournalStageV2::WriterAttached {
            writer_attached_store_head: writer_attached_store_head.clone(),
        },
        RecordDataV2::LaunchIntended {
            launch_intended_store_head,
            core_dump_suppression,
        } => SensitiveOutputJournalStageV2::LaunchIntended {
            launch_intended_store_head: launch_intended_store_head.clone(),
            core_dump_suppression: core_dump_suppression.clone(),
        },
        RecordDataV2::ScannedClean {
            scanned_clean_at_unix_ms,
        } => SensitiveOutputJournalStageV2::ScannedClean {
            scanned_clean_at_unix_ms: *scanned_clean_at_unix_ms,
        },
        RecordDataV2::SensitiveOutputDetected {} => {
            SensitiveOutputJournalStageV2::SensitiveOutputDetected {}
        }
        RecordDataV2::Finished {
            finished_store_head,
            finished_at_unix_ms,
        } => SensitiveOutputJournalStageV2::Finished {
            finished_store_head: finished_store_head.clone(),
            finished_at_unix_ms: *finished_at_unix_ms,
        },
        RecordDataV2::CleanupIntended {
            command_domain_cleanup_proof_id,
            staging_neutralization,
        } => SensitiveOutputJournalStageV2::CleanupIntended {
            command_domain_cleanup_proof_id: command_domain_cleanup_proof_id.clone(),
            staging_neutralization: staging_neutralization.clone(),
        },
        RecordDataV2::Published {
            published_store_head,
            published_at_unix_ms,
        } => SensitiveOutputJournalStageV2::Published {
            published_store_head: published_store_head.clone(),
            published_at_unix_ms: *published_at_unix_ms,
        },
        RecordDataV2::Cleaned {
            v1_cleaned_store_head,
            cleanup_receipt_id,
            cleanup_receipt_digest,
        } => SensitiveOutputJournalStageV2::Cleaned {
            v1_cleaned_store_head: v1_cleaned_store_head.clone(),
            cleanup_receipt_id: cleanup_receipt_id.clone(),
            cleanup_receipt_digest: cleanup_receipt_digest.clone(),
        },
        RecordDataV2::TerminalPrepared {
            terminal_prepared_store_head,
            terminal_record_digest,
            termination,
            terminal_prepared_at_unix_ms,
        } => SensitiveOutputJournalStageV2::TerminalPrepared {
            terminal_prepared_store_head: terminal_prepared_store_head.clone(),
            terminal_record_digest: terminal_record_digest.clone(),
            termination: *termination,
            terminal_prepared_at_unix_ms: *terminal_prepared_at_unix_ms,
        },
        RecordDataV2::SensitiveOutputRejected {
            termination,
            cleanup_receipt_id,
            cleanup_receipt_digest,
        } => SensitiveOutputJournalStageV2::SensitiveOutputRejected {
            termination: *termination,
            cleanup_receipt_id: cleanup_receipt_id.clone(),
            cleanup_receipt_digest: cleanup_receipt_digest.clone(),
        },
    };
    let recovery = SensitiveOutputJournalRecoveryV2 {
        journal_id: journal.journal_id.clone(),
        capture_id: journal.capture_id()?.to_owned(),
        runner_session_id: runner_session_id.clone(),
        effect_id: effect_id.clone(),
        request_digest: request_digest.clone(),
        intent_digest: intent_digest.clone(),
        detector_policy: detector_policy.clone(),
        core_dump_suppression: if journal.records.len() >= 4 {
            let RecordDataV2::LaunchIntended {
                core_dump_suppression,
                ..
            } = &journal.record(4)?.data
            else {
                return Err(manifest("v2 generation 4 is not LaunchIntended"));
            };
            Some(core_dump_suppression.clone())
        } else {
            None
        },
        launch_intended_journal_head: if journal.records.len() >= 4 {
            Some(journal.record(4)?.head())
        } else {
            None
        },
        launch_intended_store_head: if journal.records.len() >= 4 {
            let RecordDataV2::LaunchIntended {
                launch_intended_store_head,
                ..
            } = &journal.record(4)?.data
            else {
                return Err(manifest("v2 generation 4 is not LaunchIntended"));
            };
            Some(launch_intended_store_head.clone())
        } else {
            None
        },
        acquired,
        head: current.head(),
        stage,
    };
    recovery.validate()?;
    Ok(recovery)
}

pub(super) fn read_optional_recovery(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<Option<SensitiveOutputJournalRecoveryV2>, CommandOutputStoreError> {
    store.validate_root()?;
    let journal_id = format!("{JOURNAL_PREFIX}{capture_id}");
    validate_journal_identity(&journal_id, capture_id)?;
    match store.inner.root.symlink_metadata(&journal_id) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) => read_recovery(store, capture_id).map(Some),
        Err(error) => Err(io_error(
            "inspect optional sensitive-output journal",
            Path::new(&journal_id),
            &error,
        )),
    }
}

pub(super) fn read_optional_recovery_read_only(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<Option<SensitiveOutputJournalRecoveryV2>, CommandOutputStoreError> {
    store.validate_root()?;
    let journal_id = format!("{JOURNAL_PREFIX}{capture_id}");
    validate_journal_identity(&journal_id, capture_id)?;
    match store.inner.root.symlink_metadata(&journal_id) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(_) => {
            let journal = JournalLease::open_existing_read_only(store, capture_id)?;
            recovery_from_journal(&journal).map(Some)
        }
        Err(error) => Err(io_error(
            "inspect optional read-only sensitive-output journal",
            Path::new(&journal_id),
            &error,
        )),
    }
}

#[cfg(all(test, feature = "test-support"))]
pub(super) fn inject_current_record_pending_test_cut(
    store: &CapabilityCommandOutputStore,
    capture_id: &str,
) -> Result<(), CommandOutputStoreError> {
    let journal = JournalLease::open_existing(store, capture_id)?;
    let current = journal
        .records
        .last()
        .ok_or_else(|| manifest("cannot inject a pending cut into an empty v2 journal"))?;
    let final_name = final_record_name(current);
    let pending_name = pending_record_name(current);
    renameat_with(
        &journal.directory,
        Path::new(&final_name),
        &journal.directory,
        Path::new(&pending_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| CommandOutputStoreError::Io {
        operation: "inject pending sensitive-output test cut",
        path: Path::new(&pending_name).to_path_buf(),
        message: error.to_string(),
    })?;
    sync_directory(&journal.directory).map_err(|error| {
        io_error(
            "sync pending sensitive-output test cut",
            Path::new(&pending_name),
            &error,
        )
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the read-only join keeps every independently selected v2/v1 authority input explicit"
)]
pub(super) fn read_unknown_terminal_join(
    store: &CapabilityCommandOutputStore,
    intent: &CommandOutputCaptureIntentV1,
    acquired: &CommandOutputCaptureAcquiredV1,
    expected_final_v1_store_head: &CommandOutputCaptureStoreHeadV1,
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    native_cleanup_proof_id: &Digest,
) -> Result<
    (
        SensitiveOutputJournalRecoveryV2,
        CommandOutputCaptureRecovery,
    ),
    CommandOutputStoreError,
> {
    let capture_id = CommandOutputCaptureId::parse(intent.capture_id.clone())?;
    let journal = JournalLease::open_existing_read_only(store, &intent.capture_id)?;
    let first = journal.record(1)?;
    let RecordDataV2::IntentBound {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy: recorded_detector_policy,
    } = &first.data
    else {
        return Err(manifest("v2 generation 1 is not IntentBound"));
    };
    let second = journal.record(2).map_err(|_| {
        CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal join lacks exact v2 acquisition".into(),
        )
    })?;
    let RecordDataV2::AcquiredBound {
        acquired: recorded_acquired,
    } = &second.data
    else {
        return Err(manifest("v2 generation 2 is not AcquiredBound"));
    };
    if journal.capture_id()? != intent.capture_id
        || runner_session_id != &intent.source.runner_session_id
        || effect_id != &intent.source.effect_id
        || request_digest != &intent.source.request_digest
        || intent_digest != &intent.intent_digest
        || recorded_detector_policy != detector_policy
        || recorded_acquired != acquired
    {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal join crossed intent, policy, or acquisition".into(),
        ));
    }

    let v1_terminal = super::command_output_journal::reopen_capture(store, &capture_id)?;
    if v1_terminal.capture_id().as_str() != intent.capture_id
        || v1_terminal.source() != &intent.source
        || v1_terminal.authenticated_maximum_bytes() != intent.max_aggregate_output_bytes
        || v1_terminal.acquired() != Some(acquired)
        || v1_terminal.store_head() != expected_final_v1_store_head
        || v1_terminal.pending_record().is_some()
        || !matches!(
            v1_terminal.state(),
            CommandOutputCaptureJournalStateV1::Published
                | CommandOutputCaptureJournalStateV1::TerminalPrepared
                | CommandOutputCaptureJournalStateV1::Cleaned
        )
    {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal join crossed exact v1 terminal custody".into(),
        ));
    }

    let writer_attached_store_head = journal.records.get(2).map(|record| {
        let RecordDataV2::WriterAttached {
            writer_attached_store_head,
        } = &record.data
        else {
            unreachable!("validated v2 chain fixes generation three")
        };
        writer_attached_store_head
    });
    if let Some(writer_attached_store_head) = writer_attached_store_head {
        if v1_terminal.writer_attached_store_head() != Some(writer_attached_store_head) {
            return Err(CommandOutputStoreError::Reference(
                "policy-bound Unknown terminal join crossed WriterAttached custody".into(),
            ));
        }
    } else if v1_terminal.launch_intended_store_head().is_some()
        || v1_terminal.finished_store_head().is_some()
        || v1_terminal.published_store_head().is_some()
        || v1_terminal.terminal_prepared_store_head().is_some()
    {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal v1 custody advanced beyond a missing v2 writer boundary"
                .into(),
        ));
    }

    let launch_intended_store_head = journal.records.get(3).map(|record| {
        let RecordDataV2::LaunchIntended {
            launch_intended_store_head,
            ..
        } = &record.data
        else {
            unreachable!("validated v2 chain fixes generation four")
        };
        launch_intended_store_head
    });
    if let Some(launch_intended_store_head) = launch_intended_store_head {
        if v1_terminal.launch_intended_store_head() != Some(launch_intended_store_head) {
            return Err(CommandOutputStoreError::Reference(
                "policy-bound Unknown terminal join crossed LaunchIntended custody".into(),
            ));
        }
    } else if v1_terminal.launch_intended_store_head().is_some() && journal.records.len() != 3 {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal has an untyped v1/v2 launch split".into(),
        ));
    }

    let fifth = journal.records.get(4);
    let branch_is_clean =
        fifth.is_some_and(|record| matches!(record.data, RecordDataV2::ScannedClean { .. }));
    let branch_is_rejection = fifth
        .is_some_and(|record| matches!(record.data, RecordDataV2::SensitiveOutputDetected { .. }));
    if let Some(sixth) = journal.records.get(5) {
        match &sixth.data {
            RecordDataV2::Finished {
                finished_store_head,
                ..
            } => {
                if v1_terminal.finished_store_head() != Some(finished_store_head) {
                    return Err(CommandOutputStoreError::Reference(
                        "policy-bound Unknown terminal join crossed Finished custody".into(),
                    ));
                }
            }
            RecordDataV2::CleanupIntended {
                command_domain_cleanup_proof_id,
                ..
            } => {
                if command_domain_cleanup_proof_id != native_cleanup_proof_id.as_str() {
                    return Err(CommandOutputStoreError::Reference(
                        "policy-bound Unknown terminal join crossed native cleanup proof".into(),
                    ));
                }
            }
            _ => unreachable!("validated v2 chain fixes generation six"),
        }
    }
    if let Some(seventh) = journal.records.get(6) {
        match &seventh.data {
            RecordDataV2::Published {
                published_store_head,
                ..
            } => {
                if v1_terminal.published_store_head() != Some(published_store_head) {
                    return Err(CommandOutputStoreError::Reference(
                        "policy-bound Unknown terminal join crossed Published custody".into(),
                    ));
                }
            }
            RecordDataV2::Cleaned {
                v1_cleaned_store_head,
                ..
            } => {
                if v1_terminal.cleaned_store_head() != Some(v1_cleaned_store_head) {
                    return Err(CommandOutputStoreError::Reference(
                        "policy-bound Unknown terminal join crossed Cleaned custody".into(),
                    ));
                }
            }
            _ => unreachable!("validated v2 chain fixes generation seven"),
        }
    }
    if let Some(eighth) = journal.records.get(7) {
        match &eighth.data {
            RecordDataV2::TerminalPrepared {
                terminal_prepared_store_head,
                terminal_record_digest,
                ..
            } => {
                if v1_terminal.terminal_prepared_store_head() != Some(terminal_prepared_store_head)
                    || v1_terminal.terminal_payload_digest() != Some(terminal_record_digest)
                {
                    return Err(CommandOutputStoreError::Reference(
                        "policy-bound Unknown terminal join crossed TerminalPrepared custody"
                            .into(),
                    ));
                }
            }
            RecordDataV2::SensitiveOutputRejected { .. } => {}
            _ => unreachable!("validated v2 chain fixes generation eight"),
        }
    }

    let exact_terminal_shape = match v1_terminal.state() {
        CommandOutputCaptureJournalStateV1::Cleaned => {
            v1_terminal.cleaned_store_head() == Some(v1_terminal.store_head())
                && v1_terminal.terminal_prepared_store_head().is_none()
                && v1_terminal.published_store_head().is_none()
                && (journal.records.len() <= 4
                    || branch_is_rejection
                    || branch_is_clean && journal.records.len() <= 6)
        }
        CommandOutputCaptureJournalStateV1::Published => {
            branch_is_clean
                && (6..=7).contains(&journal.records.len())
                && v1_terminal.published_store_head() == Some(v1_terminal.store_head())
                && v1_terminal.terminal_prepared_store_head().is_none()
                && v1_terminal.cleaned_store_head().is_none()
        }
        CommandOutputCaptureJournalStateV1::TerminalPrepared => {
            branch_is_clean
                && (7..=8).contains(&journal.records.len())
                && v1_terminal.terminal_prepared_store_head() == Some(v1_terminal.store_head())
                && v1_terminal.published_store_head().is_some()
                && v1_terminal.cleaned_store_head().is_none()
                && v1_terminal.terminal().is_some()
        }
        _ => false,
    };
    if !exact_terminal_shape {
        return Err(CommandOutputStoreError::Reference(
            "policy-bound Unknown terminal v1 state is incompatible with the exact v2 branch"
                .into(),
        ));
    }
    if v1_terminal.state() == CommandOutputCaptureJournalStateV1::Cleaned
        && let Some(launch_intended_store_head) = v1_terminal.launch_intended_store_head()
    {
        super::command_output_journal::validate_sensitive_cleanup_plan_zero(
            store,
            acquired,
            launch_intended_store_head,
        )?;
    }

    let v2_recovery = recovery_from_journal(&journal)?;
    Ok((v2_recovery, v1_terminal))
}

struct BaseFields<'a> {
    runner_session_id: &'a str,
    effect_id: &'a str,
    request_digest: &'a Digest,
    intent_digest: &'a Digest,
    detector_policy: &'a SensitiveOutputDetectionPolicyReferenceV1,
    acquired: &'a CommandOutputCaptureAcquiredV1,
    acquired_anchor_digest: &'a Digest,
    acquired_store_head: &'a CommandOutputCaptureStoreHeadV1,
    writer_attached_store_head: &'a CommandOutputCaptureStoreHeadV1,
    launch_intended_store_head: &'a CommandOutputCaptureStoreHeadV1,
    core_dump_suppression: &'a SensitiveOutputCoreDumpSuppressionV1,
}

fn base_fields(journal: &JournalLease) -> Result<BaseFields<'_>, CommandOutputStoreError> {
    let RecordDataV2::IntentBound {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
    } = &journal.record(1)?.data
    else {
        return Err(manifest("v2 generation 1 is not IntentBound"));
    };
    let RecordDataV2::AcquiredBound { acquired } = &journal.record(2)?.data else {
        return Err(manifest("v2 generation 2 is not AcquiredBound"));
    };
    let RecordDataV2::WriterAttached {
        writer_attached_store_head,
    } = &journal.record(3)?.data
    else {
        return Err(manifest("v2 generation 3 is not WriterAttached"));
    };
    let RecordDataV2::LaunchIntended {
        launch_intended_store_head,
        core_dump_suppression,
    } = &journal.record(4)?.data
    else {
        return Err(manifest("v2 generation 4 is not LaunchIntended"));
    };
    Ok(BaseFields {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
        acquired,
        acquired_anchor_digest: &acquired.acquired_anchor_digest,
        acquired_store_head: &acquired.store_head,
        writer_attached_store_head,
        launch_intended_store_head,
        core_dump_suppression,
    })
}

fn rejection_boundary_fields(
    journal: &JournalLease,
) -> Result<(&str, &SensitiveOutputStagingNeutralizationReceiptV1), CommandOutputStoreError> {
    let RecordDataV2::SensitiveOutputDetected {} = &journal.record(5)?.data else {
        return Err(manifest("v2 generation 5 is not SensitiveOutputDetected"));
    };
    let RecordDataV2::CleanupIntended {
        command_domain_cleanup_proof_id,
        staging_neutralization,
    } = &journal.record(6)?.data
    else {
        return Err(manifest("v2 generation 6 is not CleanupIntended"));
    };
    Ok((command_domain_cleanup_proof_id, staging_neutralization))
}

fn rejection_receipt(
    journal: &JournalLease,
) -> Result<SensitiveOutputRejectionJournalReceiptV2, CommandOutputStoreError> {
    let base = base_fields(journal)?;
    let (command_domain_cleanup_proof_id, staging_neutralization) =
        rejection_boundary_fields(journal)?;
    let RecordDataV2::Cleaned {
        v1_cleaned_store_head,
        cleanup_receipt_id,
        cleanup_receipt_digest,
    } = &journal.record(7)?.data
    else {
        return Err(manifest("v2 generation 7 is not Cleaned"));
    };
    let RecordDataV2::SensitiveOutputRejected {
        termination,
        cleanup_receipt_id: terminal_cleanup_receipt_id,
        cleanup_receipt_digest: terminal_cleanup_receipt_digest,
    } = &journal.record(8)?.data
    else {
        return Err(manifest("v2 generation 8 is not SensitiveOutputRejected"));
    };
    if terminal_cleanup_receipt_id != cleanup_receipt_id
        || terminal_cleanup_receipt_digest != cleanup_receipt_digest
    {
        return Err(manifest(
            "v2 Cleaned and SensitiveOutputRejected cleanup identities differ",
        ));
    }
    let expected_cleanup_digest = domain_json_digest(
        CLEANUP_RECEIPT_DIGEST_DOMAIN,
        &CleanupReceiptPreimage {
            journal_id: &journal.journal_id,
            capture_id: journal.capture_id()?,
            runner_session_id: base.runner_session_id,
            effect_id: base.effect_id,
            request_digest: base.request_digest,
            detector_policy: base.detector_policy,
            detected_journal_head: &journal.record(5)?.head(),
            v1_cleaned_store_head,
            command_domain_cleanup_proof_id,
            staging_neutralization,
            cleanup_receipt_id,
        },
    )?;
    if &expected_cleanup_digest != cleanup_receipt_digest {
        return Err(manifest("v2 cleanup receipt digest is crossed"));
    }
    let receipt = SensitiveOutputRejectionJournalReceiptV2 {
        journal_id: journal.journal_id.clone(),
        capture_id: journal.capture_id()?.to_owned(),
        runner_session_id: base.runner_session_id.to_owned(),
        effect_id: base.effect_id.to_owned(),
        request_digest: base.request_digest.clone(),
        intent_digest: base.intent_digest.clone(),
        acquired: base.acquired.clone(),
        acquired_anchor_digest: base.acquired_anchor_digest.clone(),
        acquired_store_head: base.acquired_store_head.clone(),
        writer_attached_store_head: base.writer_attached_store_head.clone(),
        launch_intended_store_head: base.launch_intended_store_head.clone(),
        core_dump_suppression: base.core_dump_suppression.clone(),
        detector_policy: base.detector_policy.clone(),
        intent_bound_journal_head: journal.record(1)?.head(),
        acquired_bound_journal_head: journal.record(2)?.head(),
        writer_attached_journal_head: journal.record(3)?.head(),
        launch_intended_journal_head: journal.record(4)?.head(),
        detected_journal_head: journal.record(5)?.head(),
        cleanup_intended_journal_head: journal.record(6)?.head(),
        cleaned_journal_head: journal.record(7)?.head(),
        rejected_terminal_journal_head: journal.record(8)?.head(),
        v1_cleaned_store_head: v1_cleaned_store_head.clone(),
        command_domain_cleanup_proof_id: command_domain_cleanup_proof_id.to_owned(),
        staging_neutralization: staging_neutralization.clone(),
        termination: *termination,
        cleanup_receipt_id: cleanup_receipt_id.clone(),
        cleanup_receipt_digest: cleanup_receipt_digest.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

fn clean_receipt(
    journal: &JournalLease,
) -> Result<SensitiveOutputCleanJournalReceiptV2, CommandOutputStoreError> {
    let base = base_fields(journal)?;
    let RecordDataV2::ScannedClean {
        scanned_clean_at_unix_ms,
    } = &journal.record(5)?.data
    else {
        return Err(manifest("v2 generation 5 is not ScannedClean"));
    };
    let RecordDataV2::Finished {
        finished_store_head,
        finished_at_unix_ms,
    } = &journal.record(6)?.data
    else {
        return Err(manifest("v2 generation 6 is not Finished"));
    };
    let RecordDataV2::Published {
        published_store_head,
        published_at_unix_ms,
    } = &journal.record(7)?.data
    else {
        return Err(manifest("v2 generation 7 is not Published"));
    };
    let RecordDataV2::TerminalPrepared {
        terminal_prepared_store_head,
        terminal_record_digest,
        termination,
        terminal_prepared_at_unix_ms,
    } = &journal.record(8)?.data
    else {
        return Err(manifest("v2 generation 8 is not TerminalPrepared"));
    };
    let receipt = SensitiveOutputCleanJournalReceiptV2 {
        journal_id: journal.journal_id.clone(),
        capture_id: journal.capture_id()?.to_owned(),
        runner_session_id: base.runner_session_id.to_owned(),
        effect_id: base.effect_id.to_owned(),
        request_digest: base.request_digest.clone(),
        intent_digest: base.intent_digest.clone(),
        acquired: base.acquired.clone(),
        acquired_anchor_digest: base.acquired_anchor_digest.clone(),
        acquired_store_head: base.acquired_store_head.clone(),
        writer_attached_store_head: base.writer_attached_store_head.clone(),
        launch_intended_store_head: base.launch_intended_store_head.clone(),
        core_dump_suppression: base.core_dump_suppression.clone(),
        detector_policy: base.detector_policy.clone(),
        intent_bound_journal_head: journal.record(1)?.head(),
        acquired_bound_journal_head: journal.record(2)?.head(),
        writer_attached_journal_head: journal.record(3)?.head(),
        launch_intended_journal_head: journal.record(4)?.head(),
        scanned_clean_journal_head: journal.record(5)?.head(),
        finished_journal_head: journal.record(6)?.head(),
        published_journal_head: journal.record(7)?.head(),
        terminal_prepared_journal_head: journal.record(8)?.head(),
        finished_store_head: finished_store_head.clone(),
        published_store_head: published_store_head.clone(),
        terminal_prepared_store_head: terminal_prepared_store_head.clone(),
        terminal_record_digest: terminal_record_digest.clone(),
        termination: *termination,
        scanned_clean_at_unix_ms: *scanned_clean_at_unix_ms,
        finished_at_unix_ms: *finished_at_unix_ms,
        published_at_unix_ms: *published_at_unix_ms,
        terminal_prepared_at_unix_ms: *terminal_prepared_at_unix_ms,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn validate_intent_binding(
    journal: &JournalLease,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), CommandOutputStoreError> {
    let RecordDataV2::IntentBound {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        ..
    } = &journal.record(1)?.data
    else {
        return Err(manifest("v2 generation 1 is not IntentBound"));
    };
    if journal.capture_id()? != acquired.capture_id
        || runner_session_id != &acquired.source.runner_session_id
        || effect_id != &acquired.source.effect_id
        || request_digest != &acquired.source.request_digest
        || intent_digest != &acquired.intent_digest
    {
        return Err(manifest("v2 IntentBound crossed the acquired capture"));
    }
    Ok(())
}

fn validate_acquired_binding(
    journal: &JournalLease,
    acquired: &CommandOutputCaptureAcquiredV1,
) -> Result<(), CommandOutputStoreError> {
    validate_intent_binding(journal, acquired)?;
    let RecordDataV2::AcquiredBound {
        acquired: recorded_acquired,
    } = &journal.record(2)?.data
    else {
        return Err(manifest("v2 generation 2 is not AcquiredBound"));
    };
    if recorded_acquired != acquired {
        return Err(manifest("v2 AcquiredBound crossed the acquired capture"));
    }
    Ok(())
}

fn acquired_time(journal: &JournalLease) -> Result<u64, CommandOutputStoreError> {
    let RecordDataV2::AcquiredBound { ref acquired } = journal.record(2)?.data else {
        return Err(manifest("v2 generation 2 is not AcquiredBound"));
    };
    Ok(acquired.acquired_at_unix_ms)
}

fn scanned_clean_time(journal: &JournalLease) -> Result<u64, CommandOutputStoreError> {
    let RecordDataV2::ScannedClean {
        scanned_clean_at_unix_ms,
    } = journal.record(5)?.data
    else {
        return Err(manifest("v2 generation 5 is not ScannedClean"));
    };
    Ok(scanned_clean_at_unix_ms)
}

fn require_generation(
    journal: &JournalLease,
    generation: u64,
    label: &str,
) -> Result<(), CommandOutputStoreError> {
    if journal.head()?.generation != generation {
        return Err(manifest(&format!(
            "v2 {label} boundary requires exact generation {generation}"
        )));
    }
    Ok(())
}

fn require_state(
    journal: &JournalLease,
    generation: u64,
    predicate: impl FnOnce(&RecordDataV2) -> bool,
    label: &str,
) -> Result<(), CommandOutputStoreError> {
    require_generation(journal, generation, label)?;
    if !predicate(&journal.record(generation)?.data) {
        return Err(manifest(&format!(
            "v2 generation {generation} is not {label}"
        )));
    }
    Ok(())
}

struct JournalLease {
    store: CapabilityCommandOutputStore,
    journal_id: String,
    directory: Dir,
    lock: cap_std::fs::File,
    records: Vec<RecordV2>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingRecordReadPolicy {
    RollForward,
    Reject,
}

impl Drop for JournalLease {
    fn drop(&mut self) {
        let _ = flock(&self.lock, FlockOperation::Unlock);
    }
}

impl JournalLease {
    fn open_or_create(
        store: &CapabilityCommandOutputStore,
        capture_id: &str,
    ) -> Result<Self, CommandOutputStoreError> {
        store.validate_root()?;
        let journal_id = format!("{JOURNAL_PREFIX}{capture_id}");
        match store.inner.root.open_dir_nofollow(&journal_id) {
            Ok(_) => Self::open_existing(store, capture_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                match store.inner.root.create_dir_with(&journal_id, &builder) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Self::open_existing(store, capture_id);
                    }
                    Err(error) => {
                        return Err(io_error(
                            "create sensitive-output journal directory",
                            Path::new(&journal_id),
                            &error,
                        ));
                    }
                }
                sync_directory(&store.inner.root).map_err(|error| {
                    io_error(
                        "sync sensitive-output journal namespace",
                        Path::new(&journal_id),
                        &error,
                    )
                })?;
                let directory =
                    store
                        .inner
                        .root
                        .open_dir_nofollow(&journal_id)
                        .map_err(|error| {
                            io_error(
                                "open created sensitive-output journal",
                                Path::new(&journal_id),
                                &error,
                            )
                        })?;
                validate_private_directory(&directory, "sensitive-output journal")?;
                match create_private_file(&directory, Path::new(LOCK_FILE)) {
                    Ok(_) | Err(CommandOutputStoreError::Io { .. }) => {
                        // A racing creator may already have published the lock;
                        // the no-follow open below authenticates it.
                    }
                    Err(error) => return Err(error),
                }
                sync_directory(&directory).map_err(|error| {
                    io_error(
                        "sync sensitive-output journal lock",
                        Path::new(LOCK_FILE),
                        &error,
                    )
                })?;
                Self::open_locked(
                    store,
                    capture_id,
                    true,
                    PendingRecordReadPolicy::RollForward,
                )
            }
            Err(error) => Err(io_error(
                "open sensitive-output journal directory",
                Path::new(&journal_id),
                &error,
            )),
        }
    }

    fn open_existing(
        store: &CapabilityCommandOutputStore,
        capture_id: &str,
    ) -> Result<Self, CommandOutputStoreError> {
        Self::open_locked(
            store,
            capture_id,
            false,
            PendingRecordReadPolicy::RollForward,
        )
    }

    fn open_existing_read_only(
        store: &CapabilityCommandOutputStore,
        capture_id: &str,
    ) -> Result<Self, CommandOutputStoreError> {
        Self::open_locked(store, capture_id, false, PendingRecordReadPolicy::Reject)
    }

    fn open_locked(
        store: &CapabilityCommandOutputStore,
        capture_id: &str,
        allow_just_created_empty: bool,
        pending_record_policy: PendingRecordReadPolicy,
    ) -> Result<Self, CommandOutputStoreError> {
        store.validate_root()?;
        let journal_id = format!("{JOURNAL_PREFIX}{capture_id}");
        let directory = store
            .inner
            .root
            .open_dir_nofollow(&journal_id)
            .map_err(|error| {
                io_error(
                    "open sensitive-output journal directory",
                    Path::new(&journal_id),
                    &error,
                )
            })?;
        validate_private_directory(&directory, "sensitive-output journal")?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).follow(FollowSymlinks::No);
        let lock = directory
            .open_with(Path::new(LOCK_FILE), &options)
            .map_err(|error| {
                io_error(
                    "open sensitive-output writer lock",
                    Path::new(LOCK_FILE),
                    &error,
                )
            })?;
        validate_private_file(&lock, Path::new(LOCK_FILE), Some(0), 0)?;
        flock(&lock, FlockOperation::LockExclusive).map_err(|error| {
            CommandOutputStoreError::Io {
                operation: "lock sensitive-output journal",
                path: Path::new(LOCK_FILE).to_path_buf(),
                message: error.to_string(),
            }
        })?;
        let mut lease = Self {
            store: store.clone(),
            journal_id,
            directory,
            lock,
            records: Vec::new(),
        };
        lease.read_records_with_pending_policy(allow_just_created_empty, pending_record_policy)?;
        Ok(lease)
    }

    fn append_at(
        &mut self,
        generation: u64,
        data: RecordDataV2,
    ) -> Result<(), CommandOutputStoreError> {
        if let Some(existing) = self.records.get(
            usize::try_from(generation.saturating_sub(1))
                .map_err(|_| manifest("v2 generation does not fit usize"))?,
        ) {
            if existing.data != data {
                return Err(manifest(
                    "sensitive-output journal successor data is crossed",
                ));
            }
            return Ok(());
        }
        let expected = u64::try_from(self.records.len())
            .expect("bounded v2 record count fits u64")
            .saturating_add(1);
        if generation != expected || generation > TERMINAL_GENERATION {
            return Err(manifest(
                "sensitive-output journal stage was appended out of order",
            ));
        }
        let record = RecordV2::new(
            generation,
            self.journal_id.clone(),
            self.capture_id()?.to_owned(),
            self.records
                .last()
                .map(|record| record.record_digest.clone()),
            data,
        )?;
        validate_record_successor(&self.records, &record, &self.journal_id, self.capture_id()?)?;
        let mut candidate = self.records.clone();
        candidate.push(record.clone());
        validate_chain_semantics(&candidate)?;
        persist_record(&self.directory, &record)?;
        self.records.push(record);
        Ok(())
    }

    fn capture_id(&self) -> Result<&str, CommandOutputStoreError> {
        self.journal_id
            .strip_prefix(JOURNAL_PREFIX)
            .ok_or_else(|| manifest("invalid sensitive-output journal identity"))
    }

    fn head(&self) -> Result<SensitiveOutputJournalHeadV1, CommandOutputStoreError> {
        self.records
            .last()
            .map(RecordV2::head)
            .ok_or_else(|| manifest("empty sensitive-output journal"))
    }

    fn record(&self, generation: u64) -> Result<&RecordV2, CommandOutputStoreError> {
        let index = usize::try_from(generation.saturating_sub(1))
            .map_err(|_| manifest("sensitive-output generation does not fit usize"))?;
        self.records.get(index).ok_or_else(|| {
            manifest(&format!(
                "sensitive-output journal is missing generation {generation}"
            ))
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one locked enumeration validates final and pending namespaces before the selected explicit policy"
    )]
    fn read_records_with_pending_policy(
        &mut self,
        allow_just_created_empty: bool,
        pending_record_policy: PendingRecordReadPolicy,
    ) -> Result<(), CommandOutputStoreError> {
        let mut finals = BTreeMap::new();
        let mut pending = BTreeMap::new();
        for entry in self.directory.entries().map_err(|error| {
            io_error(
                "enumerate sensitive-output journal",
                Path::new(&self.journal_id),
                &error,
            )
        })? {
            let entry = entry.map_err(|error| {
                io_error(
                    "read sensitive-output journal entry",
                    Path::new(&self.journal_id),
                    &error,
                )
            })?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or_else(|| manifest("journal entry name is not UTF-8"))?
                .to_owned();
            if name == LOCK_FILE {
                continue;
            }
            if super::sensitive_output_terminal_observation_store::is_reserved_entry_name(&name) {
                continue;
            }
            if let Some(generation) = parse_record_name(&name, false) {
                if finals.insert(generation, name).is_some() {
                    return Err(manifest("duplicate final sensitive-output generation"));
                }
            } else if let Some(generation) = parse_record_name(&name, true) {
                if pending.insert(generation, name).is_some() {
                    return Err(manifest("duplicate pending sensitive-output generation"));
                }
            } else {
                return Err(manifest(
                    "sensitive-output journal contains an unexpected entry",
                ));
            }
        }
        if pending_record_policy == PendingRecordReadPolicy::Reject && !pending.is_empty() {
            return Err(CommandOutputStoreError::Reference(
                "read-only sensitive-output journal join refuses pending record roll-forward"
                    .into(),
            ));
        }
        for (generation, name) in pending {
            if finals.contains_key(&generation) {
                return Err(manifest(
                    "sensitive-output journal retains both pending and final generation",
                ));
            }
            let record = read_record(&self.directory, &name)?;
            if record.generation != generation || pending_record_name(&record) != name {
                return Err(manifest("pending sensitive-output filename is crossed"));
            }
            let final_name = final_record_name(&record);
            renameat_with(
                &self.directory,
                Path::new(&name),
                &self.directory,
                Path::new(&final_name),
                RenameFlags::NOREPLACE,
            )
            .map_err(|error| CommandOutputStoreError::Io {
                operation: "roll forward sensitive-output journal record",
                path: Path::new(&name).to_path_buf(),
                message: error.to_string(),
            })?;
            sync_directory(&self.directory).map_err(|error| {
                io_error(
                    "sync sensitive-output record roll-forward",
                    Path::new(&final_name),
                    &error,
                )
            })?;
            finals.insert(generation, final_name);
        }
        for (expected_index, (generation, name)) in finals.into_iter().enumerate() {
            let expected_generation = u64::try_from(expected_index)
                .expect("bounded v2 record index fits u64")
                .saturating_add(1);
            if generation != expected_generation || generation > TERMINAL_GENERATION {
                return Err(manifest(
                    "sensitive-output journal generations are not contiguous",
                ));
            }
            let record = read_record(&self.directory, &name)?;
            if final_record_name(&record) != name {
                return Err(manifest("final sensitive-output filename is crossed"));
            }
            validate_record_successor(
                &self.records,
                &record,
                &self.journal_id,
                self.capture_id()?,
            )?;
            self.records.push(record);
        }
        if !allow_just_created_empty || !self.records.is_empty() {
            validate_chain_semantics(&self.records)?;
        }
        self.store.validate_root()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the validator keeps every closed generation transition and branch invariant together"
)]
fn validate_chain_semantics(records: &[RecordV2]) -> Result<(), CommandOutputStoreError> {
    let Some(first) = records.first() else {
        return Err(manifest("empty sensitive-output journal"));
    };
    let RecordDataV2::IntentBound {
        runner_session_id,
        effect_id,
        request_digest,
        intent_digest,
        detector_policy,
    } = &first.data
    else {
        return Err(manifest("v2 generation 1 is not IntentBound"));
    };
    validate_journal_identity(&first.journal_id, &first.capture_id)?;
    validate_bounded_id("runner_session_id", runner_session_id)?;
    validate_bounded_id("effect_id", effect_id)?;
    detector_policy
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    crate::sensitive_output::validate_matcher_policy_v1(detector_policy)
        .map_err(|_| CommandOutputStoreError::Source("detector policy mismatch".into()))?;
    let Some(second) = records.get(1) else {
        return Ok(());
    };
    let RecordDataV2::AcquiredBound { acquired } = &second.data else {
        return Err(manifest("v2 generation 2 is not AcquiredBound"));
    };
    acquired
        .validate()
        .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
    if acquired.capture_id != first.capture_id
        || acquired.source.runner_session_id != *runner_session_id
        || acquired.source.effect_id != *effect_id
        || acquired.source.request_digest != *request_digest
        || acquired.intent_digest != *intent_digest
    {
        return Err(manifest("v2 acquisition crossed its IntentBound record"));
    }
    let Some(third) = records.get(2) else {
        return Ok(());
    };
    let RecordDataV2::WriterAttached {
        writer_attached_store_head,
    } = &third.data
    else {
        return Err(manifest("v2 generation 3 is not WriterAttached"));
    };
    require_forward_store_head(
        &acquired.store_head,
        writer_attached_store_head,
        "WriterAttached",
    )?;
    let Some(fourth) = records.get(3) else {
        return Ok(());
    };
    let RecordDataV2::LaunchIntended {
        launch_intended_store_head,
        core_dump_suppression,
    } = &fourth.data
    else {
        return Err(manifest("v2 generation 4 is not LaunchIntended"));
    };
    require_forward_store_head(
        writer_attached_store_head,
        launch_intended_store_head,
        "LaunchIntended",
    )?;
    core_dump_suppression
        .validate()
        .map_err(|_| CommandOutputStoreError::Source("core-dump suppression is invalid".into()))?;
    let Some(fifth) = records.get(4) else {
        return Ok(());
    };
    match &fifth.data {
        RecordDataV2::ScannedClean {
            scanned_clean_at_unix_ms,
        } => {
            if *scanned_clean_at_unix_ms < acquired.acquired_at_unix_ms {
                return Err(manifest("v2 ScannedClean time precedes acquisition"));
            }
            let Some(sixth) = records.get(5) else {
                return Ok(());
            };
            let RecordDataV2::Finished {
                finished_store_head,
                finished_at_unix_ms,
            } = &sixth.data
            else {
                return Err(manifest("clean v2 branch crossed at generation 6"));
            };
            require_forward_store_head(
                launch_intended_store_head,
                finished_store_head,
                "Finished",
            )?;
            if finished_at_unix_ms < scanned_clean_at_unix_ms {
                return Err(manifest("v2 Finished time precedes ScannedClean"));
            }
            let Some(seventh) = records.get(6) else {
                return Ok(());
            };
            let RecordDataV2::Published {
                published_store_head,
                published_at_unix_ms,
            } = &seventh.data
            else {
                return Err(manifest("clean v2 branch crossed at generation 7"));
            };
            require_forward_store_head(finished_store_head, published_store_head, "Published")?;
            if published_at_unix_ms < finished_at_unix_ms {
                return Err(manifest("v2 Published time precedes Finished"));
            }
            let Some(eighth) = records.get(7) else {
                return Ok(());
            };
            let RecordDataV2::TerminalPrepared {
                terminal_prepared_store_head,
                termination,
                terminal_prepared_at_unix_ms,
                ..
            } = &eighth.data
            else {
                return Err(manifest("clean v2 branch crossed at generation 8"));
            };
            require_forward_store_head(
                published_store_head,
                terminal_prepared_store_head,
                "TerminalPrepared",
            )?;
            termination
                .validate()
                .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
            if terminal_prepared_at_unix_ms < published_at_unix_ms {
                return Err(manifest("v2 TerminalPrepared time precedes Published"));
            }
        }
        RecordDataV2::SensitiveOutputDetected {} => {
            let Some(sixth) = records.get(5) else {
                return Ok(());
            };
            let RecordDataV2::CleanupIntended {
                command_domain_cleanup_proof_id,
                staging_neutralization,
            } = &sixth.data
            else {
                return Err(manifest("rejection v2 branch crossed at generation 6"));
            };
            Digest::parse(command_domain_cleanup_proof_id.clone())
                .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
            staging_neutralization
                .validate_against(acquired)
                .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
            let Some(seventh) = records.get(6) else {
                return Ok(());
            };
            let RecordDataV2::Cleaned {
                v1_cleaned_store_head,
                cleanup_receipt_id,
                ..
            } = &seventh.data
            else {
                return Err(manifest("rejection v2 branch crossed at generation 7"));
            };
            require_forward_store_head(
                launch_intended_store_head,
                v1_cleaned_store_head,
                "Cleaned",
            )?;
            validate_bounded_id("cleanup_receipt_id", cleanup_receipt_id)?;
            let Some(eighth) = records.get(7) else {
                return Ok(());
            };
            let RecordDataV2::SensitiveOutputRejected {
                termination,
                cleanup_receipt_id: terminal_cleanup_id,
                ..
            } = &eighth.data
            else {
                return Err(manifest("rejection v2 branch crossed at generation 8"));
            };
            termination
                .validate()
                .map_err(|error| CommandOutputStoreError::Source(error.to_string()))?;
            if terminal_cleanup_id != cleanup_receipt_id {
                return Err(manifest("v2 rejection terminal crossed cleanup identity"));
            }
        }
        _ => return Err(manifest("v2 generation 5 has an illegal branch state")),
    }
    Ok(())
}

fn validate_record_successor(
    records: &[RecordV2],
    record: &RecordV2,
    journal_id: &str,
    capture_id: &str,
) -> Result<(), CommandOutputStoreError> {
    record.validate()?;
    let expected_generation = u64::try_from(records.len())
        .expect("bounded v2 record count fits u64")
        .saturating_add(1);
    if record.generation != expected_generation
        || record.journal_id != journal_id
        || record.capture_id != capture_id
        || record.predecessor_digest != records.last().map(|record| record.record_digest.clone())
        || !allowed_state(records.last().map(|record| &record.data), &record.data)
    {
        return Err(manifest(
            "sensitive-output journal record is crossed or has an illegal branch successor",
        ));
    }
    Ok(())
}

fn allowed_state(previous: Option<&RecordDataV2>, next: &RecordDataV2) -> bool {
    matches!(
        (previous, next),
        (None, RecordDataV2::IntentBound { .. })
            | (
                Some(RecordDataV2::IntentBound { .. }),
                RecordDataV2::AcquiredBound { .. }
            )
            | (
                Some(RecordDataV2::AcquiredBound { .. }),
                RecordDataV2::WriterAttached { .. }
            )
            | (
                Some(RecordDataV2::WriterAttached { .. }),
                RecordDataV2::LaunchIntended { .. }
            )
            | (
                Some(RecordDataV2::LaunchIntended { .. }),
                RecordDataV2::ScannedClean { .. }
            )
            | (
                Some(RecordDataV2::LaunchIntended { .. }),
                RecordDataV2::SensitiveOutputDetected { .. }
            )
            | (
                Some(RecordDataV2::ScannedClean { .. }),
                RecordDataV2::Finished { .. }
            )
            | (
                Some(RecordDataV2::Finished { .. }),
                RecordDataV2::Published { .. }
            )
            | (
                Some(RecordDataV2::Published { .. }),
                RecordDataV2::TerminalPrepared { .. }
            )
            | (
                Some(RecordDataV2::SensitiveOutputDetected { .. }),
                RecordDataV2::CleanupIntended { .. }
            )
            | (
                Some(RecordDataV2::CleanupIntended { .. }),
                RecordDataV2::Cleaned { .. }
            )
            | (
                Some(RecordDataV2::Cleaned { .. }),
                RecordDataV2::SensitiveOutputRejected { .. }
            )
    )
}

fn persist_record(directory: &Dir, record: &RecordV2) -> Result<(), CommandOutputStoreError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_RECORD_BYTES) {
        return Err(manifest(
            "sensitive-output journal record exceeds its bound",
        ));
    }
    let pending_name = pending_record_name(record);
    let mut file = create_private_file(directory, Path::new(&pending_name))?;
    file.write_all(&bytes).map_err(|error| {
        io_error(
            "write sensitive-output pending record",
            Path::new(&pending_name),
            &error,
        )
    })?;
    file.flush().map_err(|error| {
        io_error(
            "flush sensitive-output pending record",
            Path::new(&pending_name),
            &error,
        )
    })?;
    file.sync_all().map_err(|error| {
        io_error(
            "sync sensitive-output pending record",
            Path::new(&pending_name),
            &error,
        )
    })?;
    validate_private_file(
        &file,
        Path::new(&pending_name),
        Some(u64::try_from(bytes.len()).expect("record length fits u64")),
        MAX_RECORD_BYTES,
    )?;
    sync_directory(directory).map_err(|error| {
        io_error(
            "sync sensitive-output pending namespace",
            Path::new(&pending_name),
            &error,
        )
    })?;
    let final_name = final_record_name(record);
    renameat_with(
        directory,
        Path::new(&pending_name),
        directory,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| CommandOutputStoreError::Io {
        operation: "publish sensitive-output journal record",
        path: Path::new(&final_name).to_path_buf(),
        message: error.to_string(),
    })?;
    sync_directory(directory).map_err(|error| {
        io_error(
            "sync sensitive-output journal record",
            Path::new(&final_name),
            &error,
        )
    })
}

fn read_record(directory: &Dir, name: &str) -> Result<RecordV2, CommandOutputStoreError> {
    let mut file = open_private_file(directory, Path::new(name))?;
    validate_private_file(&file, Path::new(name), None, MAX_RECORD_BYTES)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seek sensitive-output record", Path::new(name), &error))?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read sensitive-output record", Path::new(name), &error))?;
    if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > MAX_RECORD_BYTES) {
        return Err(manifest("sensitive-output record is empty or oversized"));
    }
    let record: RecordV2 = serde_json::from_slice(&bytes)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    let canonical = serde_json::to_vec(&record)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if canonical != bytes {
        return Err(manifest("sensitive-output record is noncanonical"));
    }
    record.validate()?;
    Ok(record)
}

fn pending_record_name(record: &RecordV2) -> String {
    format!(
        ".pending-record-{:02}-{}.json",
        record.generation, record.record_digest
    )
}

fn final_record_name(record: &RecordV2) -> String {
    format!(
        "record-{:02}-{}.json",
        record.generation, record.record_digest
    )
}

fn parse_record_name(name: &str, pending: bool) -> Option<u64> {
    let prefix = if pending {
        ".pending-record-"
    } else {
        "record-"
    };
    let rest = name.strip_prefix(prefix)?;
    let (generation, digest_and_suffix) = rest.split_once('-')?;
    let digest = digest_and_suffix.strip_suffix(".json")?;
    if generation.len() != 2 || Digest::parse(digest.to_owned()).is_err() {
        return None;
    }
    generation.parse().ok()
}

fn unix_time_ms_at_least(minimum: u64) -> Result<u64, CommandOutputStoreError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        CommandOutputStoreError::Source("system clock precedes the Unix epoch".into())
    })?;
    let now = u64::try_from(duration.as_millis())
        .map_err(|_| CommandOutputStoreError::Source("system time does not fit u64".into()))?;
    if now == 0 || now < minimum {
        return Err(CommandOutputStoreError::Source(
            "system wall clock regressed behind the authenticated lifecycle boundary".into(),
        ));
    }
    Ok(now)
}

fn validate_journal_identity(
    journal_id: &str,
    capture_id: &str,
) -> Result<(), CommandOutputStoreError> {
    Digest::parse(capture_id.to_owned())
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if journal_id != format!("{JOURNAL_PREFIX}{capture_id}") {
        return Err(manifest(
            "sensitive-output journal identity differs from its exact capture ID",
        ));
    }
    Ok(())
}

fn validate_bounded_id(label: &str, value: &str) -> Result<(), CommandOutputStoreError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(manifest(&format!(
            "sensitive-output {label} is blank, oversized, or contains whitespace/control bytes"
        )));
    }
    Ok(())
}

fn all_digests_distinct(digests: &[&Digest]) -> bool {
    digests.iter().enumerate().all(|(index, digest)| {
        digests[index.saturating_add(1)..]
            .iter()
            .all(|other| digest != other)
    })
}

fn require_forward_store_head(
    previous: &CommandOutputCaptureStoreHeadV1,
    next: &CommandOutputCaptureStoreHeadV1,
    label: &str,
) -> Result<(), CommandOutputStoreError> {
    previous
        .validate()
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    next.validate()
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    if next.generation <= previous.generation || next.record_digest == previous.record_digest {
        return Err(manifest(&format!(
            "sensitive-output {label} store head is not a strict successor"
        )));
    }
    Ok(())
}

fn domain_json_digest(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<Digest, CommandOutputStoreError> {
    let canonical = serde_json::to_vec(value)
        .map_err(|error| CommandOutputStoreError::Manifest(error.to_string()))?;
    Ok(domain_digest(domain, &canonical))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

fn manifest(message: &str) -> CommandOutputStoreError {
    CommandOutputStoreError::Manifest(message.to_owned())
}

#[cfg(test)]
mod tests {
    use grok_build_core::{
        CommandOutputArtifactSourceV1, CommandOutputCaptureDirectoryIdentityV1,
        CommandOutputCaptureFileIdentityV1,
    };

    use super::*;

    fn fixed_acquisition_prefix_vector() -> (
        String,
        CommandOutputCaptureAcquiredV1,
        SensitiveOutputDetectionPolicyReferenceV1,
    ) {
        const DISPATCH_CLAIM_ID: &str =
            "40c29436c71bffe6a01f2d81545cded98f50d149db8554c8ca187b3fca2c5cc7";
        let capture_id = Digest::sha256(b"v36-golden-capture").to_string();
        let intent = CommandOutputCaptureIntentV1::try_new(
            capture_id.clone(),
            CommandOutputArtifactSourceV1 {
                sprint_id: "sprint-v36-golden".into(),
                runner_launch_id: "launch-v36-golden".into(),
                runner_session_id: "session-v36-golden".into(),
                effect_id: "effect-v36-golden".into(),
                request_digest: Digest::sha256(b"request-v36-golden"),
            },
            Digest::sha256(b"private-state-v36-golden"),
            4_096,
            100,
        )
        .expect("construct fixed runner golden capture intent");
        let acquired = CommandOutputCaptureAcquiredV1::try_new(
            &intent,
            DISPATCH_CLAIM_ID,
            CommandOutputCaptureStoreHeadV1 {
                generation: 2,
                record_digest: Digest::sha256(b"store-head-v36-golden"),
            },
            CommandOutputCaptureDirectoryIdentityV1 {
                device_id: 42,
                inode: 100,
                owner_uid: 501,
                mode: 0o700,
                link_count: 2,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 42,
                inode: 101,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            CommandOutputCaptureFileIdentityV1 {
                device_id: 42,
                inode: 102,
                owner_uid: 501,
                mode: 0o600,
                link_count: 1,
                byte_length: 0,
            },
            200,
        )
        .expect("construct fixed runner golden capture acquisition");
        (
            format!("{JOURNAL_PREFIX}{capture_id}"),
            acquired,
            SensitiveOutputDetectionPolicyReferenceV1::core_v1(),
        )
    }

    #[test]
    fn acquisition_prefix_golden_vector_uses_actual_runner_records() {
        let (journal_id, acquired, detector_policy) = fixed_acquisition_prefix_vector();
        let intent_bound = RecordV2::new(
            1,
            journal_id.clone(),
            acquired.capture_id.clone(),
            None,
            RecordDataV2::IntentBound {
                runner_session_id: acquired.source.runner_session_id.clone(),
                effect_id: acquired.source.effect_id.clone(),
                request_digest: acquired.source.request_digest.clone(),
                intent_digest: acquired.intent_digest.clone(),
                detector_policy,
            },
        )
        .expect("derive actual runner IntentBound record");
        let acquired_bound = RecordV2::new(
            2,
            journal_id,
            acquired.capture_id.clone(),
            Some(intent_bound.record_digest.clone()),
            RecordDataV2::AcquiredBound { acquired },
        )
        .expect("derive actual runner AcquiredBound record");
        assert_eq!(
            intent_bound.record_digest.as_str(),
            "fd3c3f145698503cf029b3f28b032ffb49b920a9451189384ecaaaa58be7d8fe",
        );
        assert_eq!(
            acquired_bound.record_digest.as_str(),
            "eb57c8422e32309ddaeafca8de7bdb89cede5266ea7b65d4482c04a852c9312a",
        );
    }
}
