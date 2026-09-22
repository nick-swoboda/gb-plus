/// Closed response set emitted by the runner.
#[allow(
    missing_docs,
    reason = "variant fields are the normative runner response schema"
)]
#[allow(
    clippy::large_enum_variant,
    reason = "the closed wire DTO remains directly inspectable and under the fixed frame bound"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerResponse {
    Initialized {
        receipt: InitializationReceipt,
    },
    InitializationRejected {
        code: String,
        message: String,
    },
    WorkspaceCaptured {
        capture: WireWorkspaceCapture,
    },
    LiveWorkspaceCaptured {
        manifest: Box<DescriptorRelativeWorkspaceManifest>,
    },
    ShadowCreated {
        base_snapshot: Digest,
    },
    FileRead {
        path: String,
        digest: Digest,
        bytes: Vec<u8>,
    },
    LiteralSearch {
        path: String,
        file_digest: Digest,
        file_length: u64,
        matches: Vec<WireLiteralMatch>,
    },
    FileMutated {
        path: String,
        input_snapshot: Digest,
        result_snapshot: Digest,
        previous_digest: Option<Digest>,
        result_digest: Option<Digest>,
    },
    FileReconciled {
        path: String,
        expected_matches: bool,
        actual_digest: Option<Digest>,
    },
    StagePrepared {
        change_set: Box<ChangeSet>,
        expected_bundle: StageBundleReference,
    },
    StageBundlePersisted {
        bundle: StageBundleReference,
    },
    StageBundleReconciled {
        bundle: StageBundleReference,
    },
    RecoveryCompleted {
        recovered_change_sets: Vec<String>,
        abandoned_preparations: Vec<String>,
    },
    ApplicationApplied {
        evidence: WireApplicationEvidence,
    },
    TargetsRestored {
        evidence: WireRollbackEvidence,
    },
    RollbackCompleted {
        evidence: WireRollbackEvidence,
    },
    RollbackCompletedWithEvidence {
        evidence: WireExplicitRollbackEvidence,
    },
    RollbackLiveConflict {
        conflict: WireRollbackLiveConflict,
    },
    CommandCompleted {
        evidence: WireCommandTerminalEvidence,
    },
    CancellationPrepared {
        acknowledgement: ShutdownPreparedAcknowledgement,
    },
    ShutdownPrepared {
        acknowledgement: ShutdownPreparedAcknowledgement,
    },
    Failed {
        code: String,
        class: WireFailureClass,
        reconciliation: Option<WireReconciliationReference>,
        message: String,
    },
}

impl RunnerResponse {
    #[allow(
        dead_code,
        reason = "ordinary command dispatch uses this lossless adapter when a native backend is admitted"
    )]
    pub(crate) fn command_completed(
        evidence: &ContainedExecutionEvidence,
        output_capture: WireCommandOutputCaptureTerminalV1,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self::CommandCompleted {
            evidence: WireCommandTerminalEvidence::try_from_contained(evidence, output_capture)?,
        })
    }

    pub(crate) fn initialization_rejected(message: impl Display) -> Self {
        let message = bounded_error_message(message);
        Self::InitializationRejected {
            code: "initialization_rejected".into(),
            message,
        }
    }

    pub(crate) fn live_workspace_captured(
        captured: &WorkspaceManifest,
        capture_started_at_unix_ms: u64,
        captured_at_unix_ms: u64,
    ) -> Result<Self, WireProtocolError> {
        let entries = captured
            .entries()
            .iter()
            .map(|(path, entry)| {
                Ok(DescriptorRelativeManifestEntry {
                    path: portable_path(path)?,
                    content_digest: entry.digest().clone(),
                    byte_length: entry.length(),
                    unix_mode: entry.mode(),
                })
            })
            .collect::<Result<Vec<_>, WireProtocolError>>()?;
        let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
            captured.snapshot().grant_hash.clone(),
            capture_started_at_unix_ms,
            captured_at_unix_ms,
            entries,
        )
        .map_err(|error| invalid(error.to_string()))?;
        if manifest.manifest_digest != captured.snapshot().snapshot_id {
            return Err(invalid(
                "canonical core manifest digest differs from descriptor capture",
            ));
        }
        let response = Self::LiveWorkspaceCaptured {
            manifest: Box::new(manifest),
        };
        validate_response(&response)?;
        let encoded = serde_json::to_vec(&response)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if encoded.len() > MAX_WIRE_FRAME_BYTES.saturating_sub(64 * 1024) {
            return Err(invalid(
                "complete live-workspace manifest exceeds the bounded runner response frame",
            ));
        }
        Ok(response)
    }

    pub(crate) fn file_read(result: FileReadResult) -> Result<Self, WireProtocolError> {
        let path = portable_path(&result.path)?;
        Ok(Self::FileRead {
            path,
            digest: result.digest,
            bytes: result.bytes,
        })
    }

    pub(crate) fn literal_search(result: LiteralSearchResult) -> Result<Self, WireProtocolError> {
        let path = portable_path(&result.path)?;
        Ok(Self::LiteralSearch {
            path,
            file_digest: result.file_digest,
            file_length: result.file_length,
            matches: result
                .matches
                .into_iter()
                .map(|item| WireLiteralMatch {
                    byte_offset: item.byte_offset,
                    line: item.line,
                    column: item.column,
                })
                .collect(),
        })
    }

    pub(crate) fn mutation(
        result: FileMutationReceipt,
        input_snapshot: Digest,
        result_snapshot: Digest,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self::FileMutated {
            path: portable_path(&result.path)?,
            input_snapshot,
            result_snapshot,
            previous_digest: result.previous_digest,
            result_digest: result.result_digest,
        })
    }

    pub(crate) fn stage_prepared(
        change_set: ChangeSet,
        expected_bundle: StageBundleReference,
    ) -> Result<Self, WireProtocolError> {
        let _durable_request = RunnerRequest::WorkerStageChanges {
            change_set: Box::new(change_set.clone()),
            expected_bundle: expected_bundle.clone(),
        }
        .to_core_task_integration_request()?;
        let response = Self::StagePrepared {
            change_set: Box::new(change_set),
            expected_bundle,
        };
        validate_response(&response)?;
        let encoded = serde_json::to_vec(&response)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if encoded.len() > MAX_WIRE_FRAME_BYTES.saturating_sub(64 * 1024) {
            return Err(invalid(
                "exact stage preparation exceeds the bounded runner response frame",
            ));
        }
        Ok(response)
    }

    pub(crate) fn recovery(result: &CapabilityRecoveryReport) -> Result<Self, WireProtocolError> {
        if result.recovered_change_sets().len() > MAX_RECOVERY_IDENTITIES {
            return Err(invalid("recovery identity count exceeds the wire bound"));
        }
        if result.abandoned_preparations().len() > MAX_RECOVERY_IDENTITIES {
            return Err(invalid(
                "abandoned preparation identity count exceeds the wire bound",
            ));
        }
        let response = Self::RecoveryCompleted {
            recovered_change_sets: result.recovered_change_sets().to_vec(),
            abandoned_preparations: result.abandoned_preparations().to_vec(),
        };
        let encoded = serde_json::to_vec(&response)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if encoded.len() > MAX_WIRE_FRAME_BYTES.saturating_sub(64 * 1024) {
            return Err(invalid(
                "complete recovery report exceeds the bounded runner response frame",
            ));
        }
        Ok(response)
    }

    pub(crate) fn failed_before_effect(code: &str, message: impl Display) -> Self {
        let message = bounded_error_message(message);
        Self::Failed {
            code: code.into(),
            class: WireFailureClass::BeforeEffect,
            reconciliation: None,
            message,
        }
    }

    pub(crate) fn failed_after_known_effect(code: &str, message: impl Display) -> Self {
        let message = bounded_error_message(message);
        Self::Failed {
            code: code.into(),
            class: WireFailureClass::AfterKnownEffect,
            reconciliation: None,
            message,
        }
    }

    pub(crate) fn failed_requiring_reconciliation(
        code: &str,
        reference: WireReconciliationReference,
        message: impl Display,
    ) -> Self {
        let message = bounded_error_message(message);
        Self::Failed {
            code: code.into(),
            class: WireFailureClass::ReconciliationRequired,
            reconciliation: Some(reference),
            message,
        }
    }
}

/// Secret-free v12 rejection evidence. No output bytes, length, offset,
/// fingerprint, output digest, message, or artifact reference is representable.
#[allow(
    missing_docs,
    reason = "public fields are the exact closed v12 rejection schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandOutputSensitiveRejectionV12 {
    pub detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    pub capture_id: String,
    pub acquired_anchor_digest: Digest,
    pub launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub output_capture_cleaned_store_head: CommandOutputCaptureStoreHeadV1,
    pub reason: CommandOutputAbandonmentReasonV2,
    pub termination: CommandTerminationV1,
    pub journal_receipt: SensitiveOutputRejectionJournalReceiptV2,
    pub command_domain_cleanup_proof_id: String,
    pub backend: CommandDomainCleanupBackend,
    pub cleanup_proof: WireCommandCleanupProof,
}

impl WireCommandOutputSensitiveRejectionV12 {
    fn try_from_contained(
        evidence: &ContainedSensitiveOutputRejectionEvidence,
    ) -> Result<Self, WireProtocolError> {
        let termination = match evidence.termination() {
            CommandTermination::Exited(code) => CommandTerminationV1::Exited { code },
            CommandTermination::Signaled(signal) => CommandTerminationV1::Signaled { signal },
            CommandTermination::TimedOut => CommandTerminationV1::TimedOut,
            CommandTermination::Cancelled => CommandTerminationV1::Canceled,
            CommandTermination::OutputLimitExceeded => CommandTerminationV1::OutputLimitExceeded,
        };
        let rejection = Self {
            detector_policy: evidence.detector_policy().clone(),
            capture_id: evidence.output_capture_id().to_owned(),
            acquired_anchor_digest: evidence.output_capture_acquired_anchor_digest().clone(),
            launch_intended_store_head: evidence
                .output_capture_launch_intended_store_head()
                .clone(),
            output_capture_cleaned_store_head: evidence.output_capture_cleaned_store_head().clone(),
            reason: CommandOutputAbandonmentReasonV2::SensitiveOutputRejected,
            termination,
            journal_receipt: evidence.journal_receipt().clone(),
            command_domain_cleanup_proof_id: evidence
                .cleanup_proof()
                .os_evidence_digest()
                .as_str()
                .to_owned(),
            backend: evidence.backend().command_domain_backend(),
            cleanup_proof: WireCommandCleanupProof::try_from(evidence.cleanup_proof())
                .map_err(|error| invalid(error.to_string()))?,
        };
        rejection.validate()?;
        Ok(rejection)
    }

    fn try_from_rejoined(
        rejoined: SensitiveOutputRejectionNativeProofRejoinV1,
    ) -> Result<Self, WireProtocolError> {
        let (journal_receipt, cleanup_proof, expected_cleanup_backend) = rejoined.into_parts();
        if expected_cleanup_backend != cleanup_proof.backend() {
            return Err(invalid(
                "rejoined sensitive-output proof differs from the reconstructed backend authority",
            ));
        }
        let rejection = Self {
            detector_policy: journal_receipt.detector_policy.clone(),
            capture_id: journal_receipt.capture_id.clone(),
            acquired_anchor_digest: journal_receipt.acquired_anchor_digest.clone(),
            launch_intended_store_head: journal_receipt.launch_intended_store_head.clone(),
            output_capture_cleaned_store_head: journal_receipt.v1_cleaned_store_head.clone(),
            reason: CommandOutputAbandonmentReasonV2::SensitiveOutputRejected,
            termination: journal_receipt.termination,
            command_domain_cleanup_proof_id: cleanup_proof.os_evidence_digest().as_str().to_owned(),
            cleanup_proof: WireCommandCleanupProof::try_from(&cleanup_proof)
                .map_err(|error| invalid(error.to_string()))?,
            journal_receipt,
            backend: expected_cleanup_backend,
        };
        rejection.validate()?;
        Ok(rejection)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        self.detector_policy
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        crate::sensitive_output::validate_matcher_policy_v1(&self.detector_policy)
            .map_err(|_| invalid("v12 rejection policy differs from compiled matcher"))?;
        Digest::parse(self.capture_id.clone())
            .map_err(|_| invalid("v12 rejection capture ID is not canonical"))?;
        self.launch_intended_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.output_capture_cleaned_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if self.reason != CommandOutputAbandonmentReasonV2::SensitiveOutputRejected {
            return Err(invalid(
                "v12 rejection carries the wrong abandonment reason",
            ));
        }
        self.termination
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.journal_receipt
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        Digest::parse(self.command_domain_cleanup_proof_id.clone())
            .map_err(|_| invalid("v12 command-domain cleanup proof ID is not canonical"))?;
        if self.cleanup_proof.os_evidence_bytes.is_empty()
            || self.cleanup_proof.os_evidence_bytes.len()
                > MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES
            || Digest::sha256(&self.cleanup_proof.os_evidence_bytes)
                != self.cleanup_proof.os_evidence_digest
            || self.command_domain_cleanup_proof_id
                != self.cleanup_proof.os_evidence_digest.as_str()
            || self.detector_policy != self.journal_receipt.detector_policy
            || self.capture_id != self.journal_receipt.capture_id
            || self.acquired_anchor_digest != self.journal_receipt.acquired_anchor_digest
            || self.launch_intended_store_head != self.journal_receipt.launch_intended_store_head
            || self.output_capture_cleaned_store_head != self.journal_receipt.v1_cleaned_store_head
            || self.termination != self.journal_receipt.termination
            || self.command_domain_cleanup_proof_id
                != self.journal_receipt.command_domain_cleanup_proof_id
        {
            return Err(invalid(
                "v12 rejection journal, cleanup, policy, capture, or termination identities differ",
            ));
        }
        Ok(())
    }

    fn validate_bound(
        &self,
        request: &RunnerRequestEnvelopeV12,
        anchor: &WireCommandOutputCaptureAnchorV1,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        let acquired = anchor.acquired();
        self.journal_receipt
            .validate_request_binding(
                &request.session_id,
                &request.effect.effect_id,
                &request.effect.request_digest,
                acquired,
            )
            .map_err(|error| invalid(error.to_string()))?;
        if self.capture_id != acquired.capture_id
            || self.acquired_anchor_digest != acquired.acquired_anchor_digest
            || self.journal_receipt.acquired_store_head != acquired.store_head
        {
            return Err(invalid(
                "v12 rejection capture or acquisition differs from the exact request anchor",
            ));
        }
        let binding = CommandDomainCleanupBinding::try_new(
            request.session_id.clone(),
            request.effect.effect_id.clone(),
            request.effect.request_digest.clone(),
        )
        .map_err(|error| invalid(error.to_string()))?;
        let proof = self
            .cleanup_proof
            .readback(self.backend, &binding)
            .map_err(|error| invalid(error.to_string()))?;
        if proof.surviving_processes() != 0 {
            return Err(invalid("v12 rejection cleanup proof retains survivors"));
        }
        Ok(())
    }
}

/// Secret-free evidence attached to one pre-launch containment refusal.
///
/// The refusal itself is a claim about something that did not happen. Without
/// this the desktop can only take the runner's word for it; with it the desktop
/// can re-derive the same conclusion from retained kernel bytes and one exact
/// capture-journal head.
///
/// It deliberately carries no output byte, length, digest, or artifact
/// reference. Nothing here is derived from command output, because on this path
/// there is none: the runner proves the capture is still its untouched
/// `Acquired` reservation with no launch record and no v2 journal, and refuses
/// to attach any evidence at all otherwise. A refusal therefore cannot become a
/// channel that carries bytes past the detection policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireContainmentRefusalEvidenceV12 {
    /// Exact capture this refusal left untouched.
    pub capture_id: String,
    /// Exact untouched `Acquired` journal head read back from the store.
    pub untouched_store_head: CommandOutputCaptureStoreHeadV1,
    /// Platform accounting backend the absent domain would have used.
    pub command_domain_backend: CommandDomainCleanupBackend,
    /// Canonical no-domain proof bytes minted from kernel reads.
    pub no_domain_proof_bytes: Vec<u8>,
    /// SHA-256 of those exact bytes.
    pub no_domain_proof_digest: Digest,
}

impl WireContainmentRefusalEvidenceV12 {
    /// Validates self-consistency without consulting the request envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed capture identity, an empty or oversized
    /// proof, a digest that does not commit to the retained bytes, or a head
    /// that is not a valid journal generation.
    pub fn validate(&self) -> Result<(), WireProtocolError> {
        validate_capture_id(&self.capture_id)?;
        self.untouched_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if self.no_domain_proof_bytes.is_empty()
            || self.no_domain_proof_bytes.len() > MAX_COMMAND_DOMAIN_CLEANUP_EVIDENCE_BYTES
        {
            return Err(invalid(
                "v12 containment refusal proof is empty or oversized",
            ));
        }
        if Digest::sha256(&self.no_domain_proof_bytes) != self.no_domain_proof_digest {
            return Err(invalid(
                "v12 containment refusal proof digest does not commit to its bytes",
            ));
        }
        Ok(())
    }

    /// Reopens the retained proof against one exact command-effect binding and
    /// requires the `NoDomainCreatedBeforeEffect` disposition.
    ///
    /// # Errors
    ///
    /// Returns an error when the proof is crossed, non-canonical, describes a
    /// reaped domain rather than an absent one, or retains any survivor.
    pub fn readback(
        &self,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<ValidatedCommandDomainCleanupProof, WireProtocolError> {
        self.validate()?;
        let proof = ValidatedCommandDomainCleanupProof::readback_with_disposition(
            &self.no_domain_proof_bytes,
            &self.no_domain_proof_digest,
            self.command_domain_backend,
            expected_binding,
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
        )
        .map_err(|error| invalid(error.to_string()))?;
        if proof.surviving_processes() != 0 {
            return Err(invalid("v12 containment refusal proof retains survivors"));
        }
        Ok(proof)
    }
}

/// Closed, message-free v12 command failure reasons.
#[allow(
    missing_docs,
    reason = "variant names are the closed message-free failure vocabulary"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireCommandFailureCodeV12 {
    InvalidAuthority,
    DetectorPolicyMismatch,
    ContainmentUnavailable,
    CaptureStorageFailure,
    CleanupUnproven,
    ReconciliationRequired,
    InternalFailure,
}

/// Closed response set for one v12 command request.
#[allow(
    missing_docs,
    clippy::large_enum_variant,
    reason = "variant fields are the normative direct v12 wire schema and each response is consumed once"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RunnerResponseV12 {
    CommandCompleted {
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        evidence: WireCommandTerminalEvidence,
        scan_receipt: SensitiveOutputCleanJournalReceiptV2,
    },
    CommandOutputAbandoned {
        rejection: WireCommandOutputSensitiveRejectionV12,
    },
    CommandFailed {
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        class: WireFailureClass,
        code: WireCommandFailureCodeV12,
        reconciliation: Option<WireReconciliationReference>,
        #[serde(default)]
        containment_refusal: Option<Box<WireContainmentRefusalEvidenceV12>>,
    },
}

impl RunnerResponseV12 {
    pub(crate) fn command_completed(
        evidence: &ContainedExecutionEvidence,
        output_capture: WireCommandOutputCaptureTerminalV1,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        scan_receipt: SensitiveOutputCleanJournalReceiptV2,
    ) -> Result<Self, WireProtocolError> {
        detector_policy
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        scan_receipt
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let evidence = WireCommandTerminalEvidence::try_from_contained(evidence, output_capture)?;
        validate_clean_scan_receipt(&detector_policy, &evidence, &scan_receipt)?;
        Ok(Self::CommandCompleted {
            detector_policy,
            evidence,
            scan_receipt,
        })
    }

    pub(crate) fn command_output_abandoned(
        evidence: &ContainedSensitiveOutputRejectionEvidence,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self::CommandOutputAbandoned {
            rejection: WireCommandOutputSensitiveRejectionV12::try_from_contained(evidence)?,
        })
    }

    /// Reconstructs a restart response only from an independently validated
    /// native-proof rejoin. Output-journal state alone cannot call this path.
    ///
    /// # Errors
    ///
    /// Returns an error if the validated native-proof rejoin cannot be adapted
    /// to the exact secret-free rejection wire contract.
    pub fn command_output_abandoned_rejoined(
        rejoined: SensitiveOutputRejectionNativeProofRejoinV1,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self::CommandOutputAbandoned {
            rejection: WireCommandOutputSensitiveRejectionV12::try_from_rejoined(rejoined)?,
        })
    }

    pub(crate) fn command_failed(
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        class: WireFailureClass,
        code: WireCommandFailureCodeV12,
        reconciliation: Option<WireReconciliationReference>,
    ) -> Result<Self, WireProtocolError> {
        Self::command_failed_with_containment_refusal(
            detector_policy,
            class,
            code,
            reconciliation,
            None,
        )
    }

    pub(crate) fn command_failed_with_containment_refusal(
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
        class: WireFailureClass,
        code: WireCommandFailureCodeV12,
        reconciliation: Option<WireReconciliationReference>,
        containment_refusal: Option<Box<WireContainmentRefusalEvidenceV12>>,
    ) -> Result<Self, WireProtocolError> {
        let response = Self::CommandFailed {
            detector_policy,
            class,
            code,
            reconciliation,
            containment_refusal,
        };
        validate_v12_response_shape(&response)?;
        Ok(response)
    }

    const fn detector_policy(&self) -> &SensitiveOutputDetectionPolicyReferenceV1 {
        match self {
            Self::CommandOutputAbandoned { rejection } => &rejection.detector_policy,
            Self::CommandCompleted {
                detector_policy, ..
            }
            | Self::CommandFailed {
                detector_policy, ..
            } => detector_policy,
        }
    }
}

pub(super) fn validate_v12_response_shape(
    response: &RunnerResponseV12,
) -> Result<(), WireProtocolError> {
    response
        .detector_policy()
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    crate::sensitive_output::validate_matcher_policy_v1(response.detector_policy())
        .map_err(|_| invalid("v12 response policy differs from compiled matcher"))?;
    match response {
        RunnerResponseV12::CommandCompleted {
            detector_policy,
            evidence,
            scan_receipt,
        } => validate_clean_scan_receipt(detector_policy, evidence, scan_receipt),
        RunnerResponseV12::CommandOutputAbandoned { rejection } => rejection.validate(),
        RunnerResponseV12::CommandFailed {
            class,
            code,
            reconciliation,
            containment_refusal,
            ..
        } => {
            // Absence evidence belongs to exactly one failure: a pre-launch
            // refusal to contain. Any other class or code that carried it would
            // be claiming an absent domain for a command that may have run.
            if let Some(refusal) = containment_refusal {
                if *class != WireFailureClass::BeforeEffect
                    || *code != WireCommandFailureCodeV12::ContainmentUnavailable
                {
                    return Err(invalid(
                        "v12 containment refusal evidence requires the exact pre-launch containment failure",
                    ));
                }
                refusal.validate()?;
            }
            match (class, reconciliation) {
                (WireFailureClass::BeforeEffect | WireFailureClass::AfterKnownEffect, None) => {
                    if *code == WireCommandFailureCodeV12::ReconciliationRequired {
                        Err(invalid(
                            "v12 non-reconciliation failure carries reconciliation code",
                        ))
                    } else {
                        Ok(())
                    }
                }
                (WireFailureClass::ReconciliationRequired, Some(reference)) => {
                    if *code != WireCommandFailureCodeV12::ReconciliationRequired {
                        return Err(invalid("v12 reconciliation failure carries the wrong code"));
                    }
                    validate_reconciliation_reference(reference)
                }
                _ => Err(invalid(
                    "v12 command failure class and reconciliation reference disagree",
                )),
            }
        }
    }
}

pub(super) fn validate_clean_scan_receipt(
    detector_policy: &SensitiveOutputDetectionPolicyReferenceV1,
    evidence: &WireCommandTerminalEvidence,
    receipt: &SensitiveOutputCleanJournalReceiptV2,
) -> Result<(), WireProtocolError> {
    receipt
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if detector_policy != &receipt.detector_policy
        || receipt.capture_id != evidence.output_capture.capture_id
        || receipt.acquired_anchor_digest != evidence.output_capture.acquired_anchor_digest
        || receipt.finished_store_head != evidence.output_capture.finished_store_head
        || receipt.published_store_head != evidence.output_capture.published_store_head
        || receipt.terminal_prepared_store_head
            != evidence.output_capture.terminal_prepared_store_head
        || receipt.terminal_record_digest != evidence.output_capture.terminal_record_digest
        || receipt.termination != evidence.termination
    {
        return Err(invalid(
            "v12 clean scan receipt differs from the exact command terminal",
        ));
    }
    Ok(())
}

/// Correlation envelope for either v12 command terminal.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory v12 response correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerResponseEnvelopeV12 {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub effect: WireEffectContext,
    pub response: RunnerResponseV12,
}

impl RunnerResponseEnvelopeV12 {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION_V12 {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V12,
                actual: self.protocol_version,
            });
        }
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(invalid("v12 response sequence must be positive and finite"));
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        self.effect.validate_shape()?;
        validate_v12_response_shape(&self.response)?;
        match &self.response {
            RunnerResponseV12::CommandCompleted { evidence, .. } => {
                let binding = CommandDomainCleanupBinding::try_new(
                    self.session_id.clone(),
                    self.effect.effect_id.clone(),
                    self.effect.request_digest.clone(),
                )
                .map_err(|error| invalid(error.to_string()))?;
                validate_command_terminal_bound(evidence, &binding, &self.session_id, &self.effect)
            }
            RunnerResponseV12::CommandOutputAbandoned { rejection } => rejection.validate(),
            RunnerResponseV12::CommandFailed { .. } => Ok(()),
        }
    }

    /// Proves exact v12 correlation and policy echo for either terminal branch.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed request/response or mismatch in
    /// version, session, nonce, ordering, effect, policy, capture, or terminal.
    pub fn validate_correlation(
        &self,
        request: &RunnerRequestEnvelopeV12,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        request.validate()?;
        if self.protocol_version != request.protocol_version
            || self.session_id != request.session_id
            || self.runner_nonce != request.runner_nonce
            || self.sequence != request.sequence
            || self.request_id != request.request_id
            || self.effect != request.effect
            || self.response.detector_policy() != request.detector_policy()
        {
            return Err(invalid(
                "v12 response correlation or detector policy differs from its exact request",
            ));
        }
        let (RunnerRequest::WorkerRunCommand { output_capture, .. }
        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. }) =
            request.request.command_request()
        else {
            return Err(invalid("v12 request lost its command shape"));
        };
        match &self.response {
            RunnerResponseV12::CommandCompleted {
                evidence,
                scan_receipt,
                ..
            } => {
                evidence.validate_for_output_capture(output_capture)?;
                scan_receipt
                    .validate_request_binding(
                        &request.session_id,
                        &request.effect.effect_id,
                        &request.effect.request_digest,
                        output_capture.acquired(),
                    )
                    .map_err(|error| invalid(error.to_string()))?;
            }
            RunnerResponseV12::CommandOutputAbandoned { rejection } => {
                rejection.validate_bound(request, output_capture)?;
            }
            RunnerResponseV12::CommandFailed { .. } => {}
        }
        Ok(())
    }
}

/// Common version/session/request envelope for every runner response.
#[allow(
    missing_docs,
    reason = "public fields are the mandatory correlation envelope"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerResponseEnvelope {
    pub protocol_version: u32,
    pub session_id: String,
    pub runner_nonce: Digest,
    pub sequence: u64,
    pub request_id: String,
    pub effect: Option<WireEffectContext>,
    pub response: RunnerResponse,
}

impl RunnerResponseEnvelope {
    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        if self.protocol_version != RUNNER_WIRE_PROTOCOL_VERSION {
            return Err(WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        validate_identifier("session_id", &self.session_id)?;
        validate_identifier("request_id", &self.request_id)?;
        validate_response(&self.response)?;
        match (&self.response, &self.effect) {
            (RunnerResponse::Initialized { receipt }, None) if self.sequence == 0 => {
                if receipt.runner_nonce != self.runner_nonce {
                    return Err(invalid(
                        "initialization envelope nonce differs from its receipt",
                    ));
                }
                Ok(())
            }
            (RunnerResponse::InitializationRejected { .. }, None) if self.sequence == 0 => Ok(()),
            (
                RunnerResponse::Initialized { .. } | RunnerResponse::InitializationRejected { .. },
                _,
            ) => Err(invalid(
                "initialization response requires sequence zero and no effect context",
            )),
            (RunnerResponse::CommandCompleted { evidence }, Some(effect))
                if self.sequence > 0 && self.sequence < u64::MAX =>
            {
                effect.validate_shape()?;
                let expected_binding = CommandDomainCleanupBinding::try_new(
                    self.session_id.clone(),
                    effect.effect_id.clone(),
                    effect.request_digest.clone(),
                )
                .map_err(|error| invalid(error.to_string()))?;
                validate_command_terminal_bound(
                    evidence,
                    &expected_binding,
                    &self.session_id,
                    effect,
                )
            }
            (RunnerResponse::CommandCompleted { .. }, None) => Err(invalid(
                "command completion requires durable effect context for cleanup binding",
            )),
            (_, Some(effect)) if self.sequence > 0 && self.sequence < u64::MAX => {
                effect.validate_shape()
            }
            (_, None) if self.sequence > 0 && self.sequence < u64::MAX => Ok(()),
            _ => Err(invalid(
                "every non-initialization response requires a positive sequence",
            )),
        }
    }

    /// Proves that this response belongs to one exact request envelope.
    ///
    /// # Errors
    ///
    /// Returns an error if protocol version, session identity, or request
    /// identity differs. Clients must call this before using response evidence.
    pub fn validate_correlation(
        &self,
        request: &RunnerRequestEnvelope,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        request.validate()?;
        if self.protocol_version != request.protocol_version
            || self.session_id != request.session_id
            || self.sequence != request.sequence
            || self.request_id != request.request_id
            || self.effect != request.effect
        {
            return Err(invalid(
                "response version, session, sequence, request, or effect identity does not exactly correlate",
            ));
        }
        match &request.runner_nonce {
            None if matches!(request.request, RunnerRequest::InitializeSession { .. }) => {
                match &self.response {
                    RunnerResponse::Initialized { receipt }
                        if receipt.runner_nonce == self.runner_nonce => {}
                    RunnerResponse::InitializationRejected { .. } => {}
                    _ => {
                        return Err(invalid(
                            "initialization response is neither authenticated evidence nor a before-effect refusal",
                        ));
                    }
                }
            }
            Some(nonce) if nonce == &self.runner_nonce => {}
            None | Some(_) => {
                return Err(invalid(
                    "response runner nonce does not exactly correlate with the request",
                ));
            }
        }
        validate_stage_response_correlation(&request.request, &self.response)?;
        validate_live_workspace_response_correlation(&request.request, &self.response)?;
        validate_command_response_correlation(&request.request, &self.response)?;
        match (&request.request, &self.response) {
            (
                RunnerRequest::ApplierApplyBundle { bundle }
                | RunnerRequest::ApplierReconcile { bundle },
                RunnerResponse::ApplicationApplied { evidence },
            ) if &evidence.bundle == bundle => {}
            (
                RunnerRequest::ApplierReconcile { bundle },
                RunnerResponse::TargetsRestored { evidence },
            ) if &evidence.bundle == bundle => {}
            (
                RunnerRequest::ApplierRollback { bundle, rollback },
                RunnerResponse::RollbackCompleted { evidence },
            ) if &evidence.bundle == bundle
                && evidence.transaction_id == rollback.transaction_id
                && evidence.change_set_id == rollback.change_set_id
                && evidence.touched_target_set_digest == rollback.touched_target_set_digest => {}
            (
                RunnerRequest::ApplierRollback { bundle, rollback },
                RunnerResponse::RollbackCompletedWithEvidence { evidence },
            ) if &evidence.bundle == bundle && &evidence.rollback == rollback => {}
            (
                RunnerRequest::ApplierRollback { bundle, rollback },
                RunnerResponse::RollbackLiveConflict { conflict },
            ) if &conflict.bundle == bundle && &conflict.rollback == rollback => {}
            (
                RunnerRequest::ApplierApplyBundle { .. },
                RunnerResponse::ApplicationApplied { .. },
            )
            | (RunnerRequest::ApplierReconcile { .. }, RunnerResponse::ApplicationApplied { .. })
            | (RunnerRequest::ApplierReconcile { .. }, RunnerResponse::TargetsRestored { .. })
            | (RunnerRequest::ApplierRollback { .. }, RunnerResponse::RollbackCompleted { .. })
            | (
                RunnerRequest::ApplierRollback { .. },
                RunnerResponse::RollbackCompletedWithEvidence { .. },
            )
            | (
                RunnerRequest::ApplierRollback { .. },
                RunnerResponse::RollbackLiveConflict { .. },
            ) => {
                return Err(invalid(
                    "application response evidence does not match the exact request reference",
                ));
            }
            _ => {}
        }
        if let RunnerResponse::Failed {
            reconciliation: Some(reference),
            ..
        } = &self.response
        {
            validate_failure_reference_correlation(&request.request, reference)?;
        }
        Ok(())
    }
}

pub(super) fn validate_live_workspace_response_correlation(
    request: &RunnerRequest,
    response: &RunnerResponse,
) -> Result<(), WireProtocolError> {
    let exact = match (request, response) {
        (
            RunnerRequest::LiveStateVerifierCapture { request },
            RunnerResponse::LiveWorkspaceCaptured { manifest },
        ) => {
            request
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
            manifest
                .validate()
                .map_err(|error| invalid(error.to_string()))?;
            manifest.grant_hash == request.plan.grant_hash
                && manifest.capture_started_at_unix_ms >= request.plan.planned_at_unix_ms
                && manifest.captured_at_unix_ms >= manifest.capture_started_at_unix_ms
        }
        (RunnerRequest::LiveStateVerifierCapture { .. }, RunnerResponse::Failed { .. }) => true,
        (RunnerRequest::LiveStateVerifierCapture { .. }, _)
        | (_, RunnerResponse::LiveWorkspaceCaptured { .. }) => false,
        _ => return Ok(()),
    };
    if exact {
        Ok(())
    } else {
        Err(invalid(
            "live-workspace response does not match the exact correlated capture request",
        ))
    }
}

pub(super) fn validate_command_response_correlation(
    request: &RunnerRequest,
    response: &RunnerResponse,
) -> Result<(), WireProtocolError> {
    match (request, response) {
        (
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. },
            RunnerResponse::CommandCompleted { evidence },
        ) => validate_command_terminal_capture_bound(output_capture, evidence),
        (
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. },
            RunnerResponse::Failed { .. },
        ) => Ok(()),
        (
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. },
            _,
        )
        | (_, RunnerResponse::CommandCompleted { .. }) => Err(invalid(
            "command response does not match the exact role-specific command request",
        )),
        _ => Ok(()),
    }
}

pub(super) fn validate_stage_response_correlation(
    request: &RunnerRequest,
    response: &RunnerResponse,
) -> Result<(), WireProtocolError> {
    let exact = match (request, response) {
        (
            RunnerRequest::WorkerPrepareStage { change_set_id, .. },
            RunnerResponse::StagePrepared {
                change_set,
                expected_bundle,
            },
        ) => {
            &change_set.change_set_id == change_set_id
                && &expected_bundle.change_set_id == change_set_id
        }
        (
            RunnerRequest::WorkerStageChanges {
                expected_bundle, ..
            },
            RunnerResponse::StageBundlePersisted { bundle },
        )
        | (
            RunnerRequest::WorkerReconcileStage { expected_bundle }
            | RunnerRequest::ApplierReconcileStageBundle { expected_bundle },
            RunnerResponse::StageBundleReconciled { bundle },
        ) => bundle == expected_bundle,
        (
            RunnerRequest::WorkerPrepareStage { .. }
            | RunnerRequest::WorkerStageChanges { .. }
            | RunnerRequest::WorkerReconcileStage { .. }
            | RunnerRequest::ApplierReconcileStageBundle { .. },
            RunnerResponse::Failed { .. },
        ) => true,
        (
            RunnerRequest::WorkerPrepareStage { .. }
            | RunnerRequest::WorkerStageChanges { .. }
            | RunnerRequest::WorkerReconcileStage { .. }
            | RunnerRequest::ApplierReconcileStageBundle { .. },
            _,
        )
        | (
            _,
            RunnerResponse::StagePrepared { .. }
            | RunnerResponse::StageBundlePersisted { .. }
            | RunnerResponse::StageBundleReconciled { .. },
        ) => false,
        _ => return Ok(()),
    };
    if exact {
        Ok(())
    } else {
        Err(invalid(
            "stage response does not match the exact correlated request contract",
        ))
    }
}

/// Strict frame or canonical-contract failure.
#[derive(Debug)]
pub enum WireProtocolError {
    /// Fewer than four prefix bytes arrived before EOF.
    TruncatedPrefix,
    /// The declared payload was not completely received.
    TruncatedPayload {
        /// Declared payload length.
        expected: usize,
        /// Bytes received before EOF.
        actual: usize,
    },
    /// Frame length was zero or exceeded [`MAX_WIRE_FRAME_BYTES`].
    InvalidLength(u32),
    /// JSON was malformed, duplicated a field, or violated a strict DTO.
    InvalidJson(String),
    /// A typed JSON preimage differed from its canonical re-encoding.
    NonCanonical,
    /// A request or response violated a semantic bound.
    InvalidContract(String),
    /// The protocol version was not exact.
    Version {
        /// Only admitted protocol version.
        expected: u32,
        /// Version found in the decoded envelope.
        actual: u32,
    },
    /// JSON serialization failed.
    Encode(String),
    /// Framed I/O failed.
    Io(io::Error),
    /// A complete frame buffer contained trailing bytes.
    TrailingFrameBytes,
}

impl Display for WireProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedPrefix => formatter.write_str("truncated runner frame prefix"),
            Self::TruncatedPayload { expected, actual } => write!(
                formatter,
                "truncated runner payload: expected {expected} bytes, received {actual}"
            ),
            Self::InvalidLength(length) => {
                write!(formatter, "invalid runner frame length {length}")
            }
            Self::InvalidJson(message) => {
                write!(formatter, "invalid strict runner JSON: {message}")
            }
            Self::NonCanonical => formatter.write_str("runner JSON is not canonically encoded"),
            Self::InvalidContract(message) => {
                write!(formatter, "invalid runner contract: {message}")
            }
            Self::Version { expected, actual } => {
                write!(
                    formatter,
                    "runner protocol version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::Encode(message) => write!(formatter, "cannot encode runner JSON: {message}"),
            Self::Io(error) => write!(formatter, "runner frame I/O failed: {error}"),
            Self::TrailingFrameBytes => {
                formatter.write_str("trailing bytes follow the runner frame")
            }
        }
    }
}

impl std::error::Error for WireProtocolError {}

impl From<io::Error> for WireProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Encodes one validated request into its complete canonical length-prefixed frame.
///
/// # Errors
///
/// Returns an error for invalid contract data, serialization failure, or an
/// encoded payload outside the frame bound.
pub fn encode_request_frame(request: &RunnerRequestEnvelope) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete request frame and rejects trailing bytes.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_request_frame(frame: &[u8]) -> Result<RunnerRequestEnvelope, WireProtocolError> {
    decode_complete_frame(frame, decode_request_payload)
}

/// Encodes one validated response into its complete canonical length-prefixed frame.
///
/// # Errors
///
/// Returns an error for invalid contract data, serialization failure, or an
/// encoded payload outside the frame bound.
pub fn encode_response_frame(
    response: &RunnerResponseEnvelope,
) -> Result<Vec<u8>, WireProtocolError> {
    response.validate()?;
    encode_frame(response)
}

/// Decodes one complete response frame and rejects trailing bytes.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_response_frame(frame: &[u8]) -> Result<RunnerResponseEnvelope, WireProtocolError> {
    decode_complete_frame(frame, decode_response_payload)
}

/// Encodes one strictly validated additive v12 command request.
///
/// # Errors
///
/// Returns an error for invalid v12 authority, canonical serialization
/// failure, or a payload outside the fixed frame bound.
pub fn encode_request_frame_v12(
    request: &RunnerRequestEnvelopeV12,
) -> Result<Vec<u8>, WireProtocolError> {
    request.validate()?;
    encode_frame(request)
}

/// Decodes one complete additive v12 command request frame.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_request_frame_v12(
    frame: &[u8],
) -> Result<RunnerRequestEnvelopeV12, WireProtocolError> {
    // Inspect the version before typed decoding for explicit diagnostics;
    // version inspection does not bypass validation.
    let found = classify_request_frame_version(frame)?;
    if found != RUNNER_WIRE_PROTOCOL_VERSION_V12 {
        return Err(WireProtocolError::Version {
            expected: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            actual: found,
        });
    }
    decode_complete_frame(frame, decode_request_payload_v12)
}

/// Encodes either strict v12 command terminal branch.
///
/// # Errors
///
/// Returns an error for invalid v12 correlation/evidence, canonical
/// serialization failure, or a payload outside the fixed frame bound.
pub fn encode_response_frame_v12(
    response: &RunnerResponseEnvelopeV12,
) -> Result<Vec<u8>, WireProtocolError> {
    response.validate()?;
    encode_frame(response)
}

/// Decodes one complete additive v12 command response frame.
///
/// # Errors
///
/// Returns an error for framing, strict JSON, canonical encoding, version, or
/// semantic-contract failures.
pub fn decode_response_frame_v12(
    frame: &[u8],
) -> Result<RunnerResponseEnvelopeV12, WireProtocolError> {
    decode_complete_frame(frame, decode_response_payload_v12)
}

pub(crate) fn read_request<R: Read>(
    reader: &mut R,
) -> Result<Option<RunnerRequestEnvelope>, WireProtocolError> {
    let Some(payload) = read_payload(reader)? else {
        return Ok(None);
    };
    decode_request_payload(&payload).map(Some)
}

pub(crate) fn write_response<W: Write>(
    writer: &mut W,
    response: &RunnerResponseEnvelope,
) -> Result<(), WireProtocolError> {
    let frame = encode_response_frame(response)?;
    writer.write_all(&frame)?;
    writer.flush()?;
    Ok(())
}

pub(crate) fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, WireProtocolError> {
    let payload =
        serde_json::to_vec(value).map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_WIRE_FRAME_BYTES {
        return Err(WireProtocolError::InvalidLength(
            u32::try_from(payload.len()).unwrap_or(u32::MAX),
        ));
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| WireProtocolError::InvalidLength(u32::MAX))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub(crate) fn decode_complete_frame<T>(
    frame: &[u8],
    decoder: fn(&[u8]) -> Result<T, WireProtocolError>,
) -> Result<T, WireProtocolError> {
    let mut cursor = Cursor::new(frame);
    let payload = read_payload(&mut cursor)?.ok_or(WireProtocolError::TruncatedPrefix)?;
    if cursor.position() != u64::try_from(frame.len()).unwrap_or(u64::MAX) {
        return Err(WireProtocolError::TrailingFrameBytes);
    }
    decoder(&payload)
}

pub(super) fn read_payload<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, WireProtocolError> {
    let mut prefix = [0_u8; 4];
    let mut prefix_read = 0_usize;
    while prefix_read < prefix.len() {
        match reader.read(&mut prefix[prefix_read..]) {
            Ok(0) if prefix_read == 0 => return Ok(None),
            Ok(0) => return Err(WireProtocolError::TruncatedPrefix),
            Ok(count) => prefix_read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WireProtocolError::Io(error)),
        }
    }
    let length = u32::from_be_bytes(prefix);
    let length_usize =
        usize::try_from(length).map_err(|_| WireProtocolError::InvalidLength(length))?;
    if length_usize == 0 || length_usize > MAX_WIRE_FRAME_BYTES {
        return Err(WireProtocolError::InvalidLength(length));
    }
    let mut payload = vec![0_u8; length_usize];
    let mut received = 0_usize;
    while received < length_usize {
        match reader.read(&mut payload[received..]) {
            Ok(0) => {
                return Err(WireProtocolError::TruncatedPayload {
                    expected: length_usize,
                    actual: received,
                });
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WireProtocolError::Io(error)),
        }
    }
    Ok(Some(payload))
}

pub(super) fn decode_request_payload(
    payload: &[u8],
) -> Result<RunnerRequestEnvelope, WireProtocolError> {
    let value: RunnerRequestEnvelope = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

pub(super) fn decode_request_payload_v12(
    payload: &[u8],
) -> Result<RunnerRequestEnvelopeV12, WireProtocolError> {
    let value: RunnerRequestEnvelopeV12 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

pub(super) fn decode_response_payload(
    payload: &[u8],
) -> Result<RunnerResponseEnvelope, WireProtocolError> {
    let value: RunnerResponseEnvelope = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

pub(super) fn decode_response_payload_v12(
    payload: &[u8],
) -> Result<RunnerResponseEnvelopeV12, WireProtocolError> {
    let value: RunnerResponseEnvelopeV12 = serde_json::from_slice(payload)
        .map_err(|error| WireProtocolError::InvalidJson(error.to_string()))?;
    require_canonical(payload, &value)?;
    value.validate()?;
    Ok(value)
}

pub(crate) fn require_canonical<T: Serialize>(
    payload: &[u8],
    value: &T,
) -> Result<(), WireProtocolError> {
    let canonical =
        serde_json::to_vec(value).map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if canonical != payload {
        return Err(WireProtocolError::NonCanonical);
    }
    Ok(())
}
