//! Restart reconciliation and unknown command-capture recovery.

use super::{
    AdaptedCommandTerminal, AgentEvent, AgentEventKind, COMMAND_TERMINAL_CAPTURE_SCHEMA,
    CONTAINED_CAPTURE_LAUNCH_SCHEMA, CONTRACT_VERSION, CapabilityCommandOutputStore,
    CommandDomainBackend, CommandDomainCleanupDisposition, CommandDomainCleanupProof,
    CommandDomainEffectBinding, CommandDomainEffectState, CommandOutputArtifactSetReferenceV1,
    CommandOutputCaptureFencedResolution, CommandOutputCaptureJournalStateV1,
    CommandOutputCaptureLaunchHistoryV1, CommandOutputCapturePhysicalReconciliationV1,
    CommandOutputCaptureReconciliationAdmission, CommandOutputCaptureReconciliationResolutionV1,
    CommandOutputCaptureRecovery, CommandOutputCaptureRestartStateV1,
    CommandOutputCaptureStoreHeadV1, CommandOutputCaptureTerminalDispositionV1,
    CommandOutputCleanScanResolutionReceiptV1, CommandOutputPublicationAuthorityV1,
    CommandOutputSensitiveRejectionAnchorV1, CommandOutputSensitiveRejectionCleanupReceiptV1,
    CommandOutputStoreError, Digest, DurableCoordinatorError, EffectKind, EffectObservation,
    EffectOutcome, EventLedger, LedgerError, MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS,
    NativeCommandDomainCleanupRequest, NativeLaunchCleanupReopener, Path, PersistedEffect,
    PersistedFinishReceipt, PersistedRunnerEffectDispatchClaim, ProviderCommandTermination,
    ProviderToolCall, ProviderToolIntent, ProviderToolOutput, ProviderToolResult,
    RunnerCommandCleanupBackend, RunnerCommandCleanupBinding,
    SensitiveOutputCleanPublicationRecoveryV1, SensitiveOutputJournalStageV2,
    SensitiveOutputRejectionJournalReceiptV2, SensitiveOutputRejectionNativeProofRejoinV1,
    ValidatedCommandCaptureLaunchBindingV12, ValidatedCommandDomainCleanupProof,
    WalkingSkeletonTaskCommandRestart, WalkingSkeletonTaskCommandRestartOutcome,
    WireCommandCleanupProof, WireCommandOutputCaptureAnchorV1, WireCommandOutputCaptureTerminalV1,
    WireCommandSpec, WireCommandTerminalEvidence, WorkerCleanupBackend, WorkerLease,
    command_terminal_record_bytes, core_clean_runner_reference, core_rejection_runner_reference,
    current_unix_ms, decode_contained_capture_launch_binding_v12, fresh_command_output_capture_id,
    protocol, task_unknown_command_backends,
};

#[derive(Debug)]
pub(super) enum UnknownCommandCaptureResolutionOutcome {
    Resolved,
    CleanupRequired { reason: String },
}

pub(super) enum UnknownPhysicalResolutionProducerOutcome {
    Produced(Box<CommandOutputCaptureFencedResolution>),
    CleanupRequired(UnknownCommandCaptureResolutionOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct UnknownCommandCaptureResolutionMaterial {
    pub(super) disposition: CommandOutputCaptureTerminalDispositionV1,
    pub(super) store_head: grok_build_core::CommandOutputCaptureStoreHeadV1,
    pub(super) resolution_record_digest: Digest,
    pub(super) artifact_reference: Option<CommandOutputArtifactSetReferenceV1>,
}

pub(super) fn unknown_capture_cleanup_required(
    reason: impl Into<String>,
) -> UnknownCommandCaptureResolutionOutcome {
    UnknownCommandCaptureResolutionOutcome::CleanupRequired {
        reason: reason.into(),
    }
}

#[derive(Clone, Copy)]
pub(super) enum UnknownCommandRunnerOwner<'a> {
    FinalVerifier,
    TaskWorker(&'a WorkerLease),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum UnknownCommandCaptureTerminalFamily {
    LiveAmbiguousTransport,
    RestartPhysical(Box<CommandOutputCapturePhysicalReconciliationV1>),
}

pub(super) fn validate_unknown_command_terminal_family(
    effect: &PersistedEffect,
    capture: &grok_build_core::PersistedCommandOutputCapture,
    acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
    terminal: &grok_build_core::CommandOutputCaptureTerminalAnchorV1,
) -> Result<UnknownCommandCaptureTerminalFamily, DurableCoordinatorError> {
    let evidence_bytes = effect.evidence_bytes.as_deref().ok_or_else(|| {
        protocol("Unknown command-output reconciliation lacks exact effect evidence")
    })?;
    if let Ok(physical) =
        serde_json::from_slice::<CommandOutputCapturePhysicalReconciliationV1>(evidence_bytes)
    {
        let canonical = physical.canonical_evidence_bytes()?;
        physical.validate_against(
            &capture.intent,
            &physical.reconciliation_claim,
            Some(acquired),
        )?;
        if canonical != evidence_bytes
            || !matches!(
                physical.launch_history,
                CommandOutputCaptureLaunchHistoryV1::ExactLaunchEvidence { .. }
            )
            || physical.requested_store_head.as_ref() != Some(&acquired.store_head)
            || physical.physical_acquired.as_ref() != Some(acquired)
            || terminal.store_head != physical.final_store_head
            || terminal.terminal_record_digest != physical.reconciliation_digest
            || terminal.anchored_at_unix_ms != physical.reconciled_at_unix_ms
            || terminal.artifact_reference.is_some()
        {
            return Err(protocol(
                "restart Unknown command terminal differs from its exact launch-bearing physical receipt",
            ));
        }
        return Ok(UnknownCommandCaptureTerminalFamily::RestartPhysical(
            Box::new(physical),
        ));
    }
    if terminal.store_head != acquired.store_head
        || terminal.terminal_record_digest != Digest::sha256(evidence_bytes)
        || terminal.artifact_reference.is_some()
    {
        return Err(protocol(
            "live Unknown command terminal differs from its exact acquired head or unresolved evidence",
        ));
    }
    Ok(UnknownCommandCaptureTerminalFamily::LiveAmbiguousTransport)
}

pub(super) fn validate_unknown_command_capture_authority(
    effect: &PersistedEffect,
    capture: &grok_build_core::PersistedCommandOutputCapture,
    command_cleanup: &grok_build_core::PersistedCommandDomainCleanup,
    runner_cleanup: &grok_build_core::WorkerCleanupEvidence,
    owner: UnknownCommandRunnerOwner<'_>,
) -> Result<UnknownCommandCaptureTerminalFamily, DurableCoordinatorError> {
    let dispatch_claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        protocol("Unknown command-output reconciliation lacks its durable dispatch claim")
    })?;
    let observation = effect.observation.as_ref().ok_or_else(|| {
        protocol("Unknown command-output reconciliation lacks its durable observation")
    })?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        protocol("Unknown command-output reconciliation lacks its acquired capture anchor")
    })?;
    let terminal = capture.terminal.as_ref().ok_or_else(|| {
        protocol("Unknown command-output reconciliation lacks its immutable terminal anchor")
    })?;
    let expected_command_backend = match runner_cleanup.receipt.platform_backend {
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(protocol(
                "Unknown final-verifier command reconciliation cannot use trusted-Applier cleanup authority",
            ));
        }
    };

    let exact_worker_owner = match owner {
        UnknownCommandRunnerOwner::FinalVerifier => {
            effect.intent.worker_lease.is_none() && runner_cleanup.receipt.worker_lease.is_none()
        }
        UnknownCommandRunnerOwner::TaskWorker(worker_lease) => {
            effect.intent.worker_lease.as_ref() == Some(worker_lease)
                && runner_cleanup.receipt.worker_lease.as_ref() == Some(worker_lease)
        }
    };
    let terminal_family =
        validate_unknown_command_terminal_family(effect, capture, acquired, terminal)?;

    if effect.intent.kind != EffectKind::RunCommand
        || !matches!(observation.outcome, EffectOutcome::Unknown { .. })
        || !matches!(effect.finish_receipt, PersistedFinishReceipt::NotRequired)
        || capture.intent.source.sprint_id != effect.intent.sprint_id
        || capture.intent.source.runner_launch_id != dispatch_claim.launch_id
        || capture.intent.source.runner_session_id != dispatch_claim.session_id
        || capture.intent.source.effect_id != effect.intent.effect_id
        || capture.intent.source.request_digest != effect.intent.request_digest
        || acquired.source != capture.intent.source
        || acquired.dispatch_claim_id != dispatch_claim.dispatch_claim_id
        || terminal.capture_id != capture.intent.capture_id
        || terminal.effect_id != effect.intent.effect_id
        || terminal.observation_id != observation.observation_id
        || terminal.dispatch_claim_id.as_deref() != Some(dispatch_claim.dispatch_claim_id.as_str())
        || terminal.acquired_anchor_digest.as_ref() != Some(&acquired.acquired_anchor_digest)
        || terminal.observation_class
            != grok_build_core::CommandOutputCaptureObservationClassV1::Unknown
        || terminal.disposition != CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired
        || terminal.artifact_reference.is_some()
        || command_cleanup.binding.sprint_id != effect.intent.sprint_id
        || command_cleanup.binding.launch_id != dispatch_claim.launch_id
        || command_cleanup.binding.session_id != dispatch_claim.session_id
        || command_cleanup.binding.effect_id != effect.intent.effect_id
        || command_cleanup.binding.request_digest != effect.intent.request_digest
        || command_cleanup.binding.observation_id.as_deref()
            != Some(observation.observation_id.as_str())
        || command_cleanup.binding.state != CommandDomainEffectState::Unknown
        || command_cleanup.proof.sprint_id != effect.intent.sprint_id
        || command_cleanup.proof.launch_id != dispatch_claim.launch_id
        || command_cleanup.proof.session_id != dispatch_claim.session_id
        || command_cleanup.proof.effect_id != effect.intent.effect_id
        || command_cleanup.proof.request_digest != effect.intent.request_digest
        || command_cleanup.proof.observation_id.as_deref()
            != Some(observation.observation_id.as_str())
        || command_cleanup.proof.backend != expected_command_backend
        || command_cleanup.proof.disposition != CommandDomainCleanupDisposition::ReapedZeroSurvivors
        || command_cleanup.proof.surviving_processes != 0
        || runner_cleanup.receipt.sprint_id != effect.intent.sprint_id
        || runner_cleanup.receipt.launch_id != dispatch_claim.launch_id
        || runner_cleanup.receipt.session_id != dispatch_claim.session_id
        || !exact_worker_owner
        || runner_cleanup.receipt.surviving_processes != 0
    {
        return Err(protocol(
            "Unknown command-output reconciliation crossed effect, capture, command cleanup, or runner cleanup authority",
        ));
    }
    Ok(terminal_family)
}

pub(super) fn validate_unknown_capture_recovery_binding(
    capture: &grok_build_core::PersistedCommandOutputCapture,
    recovery: &grok_build_runner::CommandOutputCaptureRecovery,
) -> Result<(), DurableCoordinatorError> {
    let acquired = capture
        .acquired
        .as_ref()
        .ok_or_else(|| protocol("Unknown capture recovery lacks its exact core acquisition"))?;
    if recovery.capture_id().as_str() != capture.intent.capture_id
        || recovery.source() != &capture.intent.source
        || recovery.authenticated_maximum_bytes() != capture.intent.max_aggregate_output_bytes
        || recovery.acquired() != Some(acquired)
    {
        return Err(protocol(
            "Unknown capture recovery crossed its exact capture ID, source, limit, or acquisition",
        ));
    }
    Ok(())
}

pub(super) fn unknown_capture_resolution_material(
    capture: &grok_build_core::PersistedCommandOutputCapture,
    recovery: &grok_build_runner::CommandOutputCaptureRecovery,
    terminal_family: &UnknownCommandCaptureTerminalFamily,
) -> Result<Option<UnknownCommandCaptureResolutionMaterial>, DurableCoordinatorError> {
    validate_unknown_capture_recovery_binding(capture, recovery)?;
    if recovery.pending_record().is_some() {
        return Ok(None);
    }
    let terminal = capture
        .terminal
        .as_ref()
        .ok_or_else(|| protocol("Unknown capture recovery lacks its immutable core terminal"))?;
    match terminal_family {
        UnknownCommandCaptureTerminalFamily::LiveAmbiguousTransport => {
            if recovery.store_head().generation <= terminal.store_head.generation {
                return Err(protocol(
                    "live Unknown capture storage terminal did not advance its immutable core terminal head",
                ));
            }
        }
        UnknownCommandCaptureTerminalFamily::RestartPhysical(physical) => {
            if recovery.store_head().generation < terminal.store_head.generation
                || (recovery.store_head() == &terminal.store_head
                    && (physical.final_store_head != terminal.store_head
                        || !restart_physical_state_matches_recovery(
                            physical.final_state,
                            recovery.state(),
                        )))
            {
                return Err(protocol(
                    "restart Unknown capture recovery regressed or crossed its exact physical terminal cut",
                ));
            }
        }
    }
    let material = match recovery.state() {
        CommandOutputCaptureJournalStateV1::Published => {
            let artifact_reference = recovery.expected_reference().cloned().ok_or_else(|| {
                protocol("Published Unknown capture recovery lacks its exact artifact reference")
            })?;
            if recovery.published_store_head() != Some(recovery.store_head())
                || recovery.terminal_prepared_store_head().is_some()
                || recovery.cleaned_store_head().is_some()
            {
                return Err(protocol(
                    "Published Unknown capture recovery has crossed terminal journal heads",
                ));
            }
            UnknownCommandCaptureResolutionMaterial {
                disposition: CommandOutputCaptureTerminalDispositionV1::Published,
                store_head: recovery.store_head().clone(),
                resolution_record_digest: recovery.head_digest().clone(),
                artifact_reference: Some(artifact_reference),
            }
        }
        CommandOutputCaptureJournalStateV1::TerminalPrepared => {
            let artifact_reference = recovery.expected_reference().cloned().ok_or_else(|| {
                protocol(
                    "TerminalPrepared Unknown capture recovery lacks its exact artifact reference",
                )
            })?;
            if recovery.published_store_head().is_none()
                || recovery.terminal_prepared_store_head() != Some(recovery.store_head())
                || recovery.terminal().is_none()
                || recovery.terminal_record_digest() != Some(recovery.head_digest())
                || recovery.cleaned_store_head().is_some()
            {
                return Err(protocol(
                    "TerminalPrepared Unknown capture recovery has crossed terminal material",
                ));
            }
            UnknownCommandCaptureResolutionMaterial {
                disposition: CommandOutputCaptureTerminalDispositionV1::Published,
                store_head: recovery.store_head().clone(),
                resolution_record_digest: recovery.head_digest().clone(),
                artifact_reference: Some(artifact_reference),
            }
        }
        CommandOutputCaptureJournalStateV1::Cleaned => {
            if recovery.cleaned_store_head() != Some(recovery.store_head())
                || recovery.cleaned_record_digest() != Some(recovery.head_digest())
            {
                return Err(protocol(
                    "Cleaned Unknown capture recovery lacks its exact immutable unlink record",
                ));
            }
            UnknownCommandCaptureResolutionMaterial {
                disposition: CommandOutputCaptureTerminalDispositionV1::Abandoned,
                store_head: recovery.store_head().clone(),
                resolution_record_digest: recovery.head_digest().clone(),
                artifact_reference: None,
            }
        }
        CommandOutputCaptureJournalStateV1::Intent
        | CommandOutputCaptureJournalStateV1::Acquired
        | CommandOutputCaptureJournalStateV1::WriterAttached
        | CommandOutputCaptureJournalStateV1::LaunchIntended
        | CommandOutputCaptureJournalStateV1::Finished
        | CommandOutputCaptureJournalStateV1::CleanupIntended => return Ok(None),
    };
    Ok(Some(material))
}

pub(super) const fn restart_physical_state_matches_recovery(
    physical: CommandOutputCaptureRestartStateV1,
    recovery: CommandOutputCaptureJournalStateV1,
) -> bool {
    matches!(
        (physical, recovery),
        (
            CommandOutputCaptureRestartStateV1::Intent,
            CommandOutputCaptureJournalStateV1::Intent
        ) | (
            CommandOutputCaptureRestartStateV1::Acquired,
            CommandOutputCaptureJournalStateV1::Acquired
        ) | (
            CommandOutputCaptureRestartStateV1::WriterAttached,
            CommandOutputCaptureJournalStateV1::WriterAttached
        ) | (
            CommandOutputCaptureRestartStateV1::LaunchIntended,
            CommandOutputCaptureJournalStateV1::LaunchIntended
        ) | (
            CommandOutputCaptureRestartStateV1::Finished,
            CommandOutputCaptureJournalStateV1::Finished
        ) | (
            CommandOutputCaptureRestartStateV1::Published,
            CommandOutputCaptureJournalStateV1::Published
        ) | (
            CommandOutputCaptureRestartStateV1::TerminalPrepared,
            CommandOutputCaptureJournalStateV1::TerminalPrepared
        ) | (
            CommandOutputCaptureRestartStateV1::CleanupIntended,
            CommandOutputCaptureJournalStateV1::CleanupIntended
        ) | (
            CommandOutputCaptureRestartStateV1::Cleaned,
            CommandOutputCaptureJournalStateV1::Cleaned
        )
    )
}

pub(super) fn exact_unknown_capture_resolution_is_durable(
    ledger: &EventLedger,
    capture: &grok_build_core::PersistedCommandOutputCapture,
    material: &UnknownCommandCaptureResolutionMaterial,
) -> Result<bool, DurableCoordinatorError> {
    let Some(terminal) = capture.terminal.as_ref() else {
        return Err(protocol(
            "resolved Unknown capture lost its immutable terminal anchor",
        ));
    };
    let Some(resolution) = capture.reconciliation_resolution.as_ref() else {
        return Ok(false);
    };
    resolution.validate()?;
    let exact_resolution = capture.reconciliation_obligation_closure.as_ref()
        == Some(&terminal.terminal_anchor_digest)
        && resolution.capture_id == capture.intent.capture_id
        && resolution.effect_id == capture.intent.source.effect_id
        && resolution.observation_id == terminal.observation_id
        && resolution.terminal_anchor_digest == terminal.terminal_anchor_digest
        && resolution.disposition == material.disposition
        && resolution.store_head == material.store_head
        && resolution.resolution_record_digest == material.resolution_record_digest
        && resolution.artifact_reference == material.artifact_reference;
    if !exact_resolution
        || material.disposition != CommandOutputCaptureTerminalDispositionV1::Published
    {
        return Ok(exact_resolution);
    }
    let publication = ledger
        .load_command_output_publication_authority_for_effect(&capture.intent.source.effect_id)?;
    Ok(match publication {
        CommandOutputPublicationAuthorityV1::PreV29Exemption {
            capture_id,
            effect_id,
            intent_digest,
        } => {
            capture_id == capture.intent.capture_id
                && effect_id == capture.intent.source.effect_id
                && intent_digest == capture.intent.intent_digest
        }
        CommandOutputPublicationAuthorityV1::CurrentPolicyResolution {
            detector_policy,
            clean_scan_resolution_receipt,
        } => {
            clean_scan_resolution_receipt.detector_policy == detector_policy
                && clean_scan_resolution_receipt.intent == capture.intent
                && clean_scan_resolution_receipt.unknown_terminal == *terminal
                && clean_scan_resolution_receipt.resolution == *resolution
        }
        CommandOutputPublicationAuthorityV1::CurrentPolicy { .. } => false,
    })
}

pub(super) fn release_unknown_capture_reconciliation_claim(
    ledger: &mut EventLedger,
    permit: grok_build_core::CommandOutputCaptureReconciliationPermit,
) -> Result<UnknownCommandCaptureResolutionOutcome, DurableCoordinatorError> {
    let claim = permit.claim().clone();
    let released_at_unix_ms = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(claim.acquired_at_unix_ms);
    match ledger.release_command_output_capture_reconciliation(permit, released_at_unix_ms) {
        Ok(released) if released == claim => Ok(unknown_capture_cleanup_required(
            "Unknown command-output capture storage reconciliation remains pending",
        )),
        Ok(_) => Err(protocol(
            "Unknown command-output capture released a crossed reconciliation claim",
        )),
        Err(error) => Ok(unknown_capture_cleanup_required(format!(
            "Unknown command-output capture claim release is uncertain: {error}"
        ))),
    }
}

pub(super) fn produce_unknown_capture_physical_resolution(
    ledger: &mut EventLedger,
    resolution_permit: &mut Option<grok_build_core::CommandOutputCaptureReconciliationPermit>,
    producer: impl FnOnce(
        &grok_build_core::CommandOutputCaptureReconciliationClaimV1,
    ) -> Result<CommandOutputCaptureFencedResolution, CommandOutputStoreError>,
) -> Result<UnknownPhysicalResolutionProducerOutcome, DurableCoordinatorError> {
    let exact_claim = resolution_permit
        .as_ref()
        .expect("physical producer retains the exact Unknown reconciliation claim")
        .claim()
        .clone();
    match producer(&exact_claim) {
        Ok(fenced) => Ok(UnknownPhysicalResolutionProducerOutcome::Produced(
            Box::new(fenced),
        )),
        Err(producer_error) => {
            let pending = release_unknown_capture_reconciliation_claim(
                ledger,
                resolution_permit
                    .take()
                    .expect("physical producer failure releases the exact Unknown claim"),
            )?;
            match pending {
                UnknownCommandCaptureResolutionOutcome::Resolved => {
                    unreachable!("claim release never resolves capture storage")
                }
                UnknownCommandCaptureResolutionOutcome::CleanupRequired { .. } => {
                    Ok(UnknownPhysicalResolutionProducerOutcome::CleanupRequired(
                        unknown_capture_cleanup_required(format!(
                            "Unknown command-output fenced physical resolution remains pending: {producer_error}"
                        )),
                    ))
                }
            }
        }
    }
}

pub(super) fn commit_unknown_capture_resolution(
    ledger: &mut EventLedger,
    resolution_permit: &mut Option<grok_build_core::CommandOutputCaptureReconciliationPermit>,
    resolution: &CommandOutputCaptureReconciliationResolutionV1,
    resolution_physical: Option<&CommandOutputCapturePhysicalReconciliationV1>,
    clean_scan_resolution_receipt: Option<&CommandOutputCleanScanResolutionReceiptV1>,
    command_cleanup: &CommandDomainCleanupProof,
    runner_cleanup_receipt_id: &str,
) -> Result<grok_build_core::PersistedCommandOutputCapture, LedgerError> {
    let permit = resolution_permit
        .take()
        .expect("Unknown capture core commit consumes the exact reconciliation claim");
    match ledger.resolve_claimed_command_output_capture_unknown(
        permit,
        resolution,
        resolution_physical,
        clean_scan_resolution_receipt,
        command_cleanup,
        runner_cleanup_receipt_id,
    ) {
        Ok(resolved) => Ok(resolved),
        Err(failure) => {
            let (error, retry_permit) = failure.into_parts();
            *resolution_permit = retry_permit;
            Err(error)
        }
    }
}

#[cfg(test)]
pub(in crate::runner_client) fn fail_unknown_physical_resolution_producer_for_test(
    ledger: &mut EventLedger,
    permit: grok_build_core::CommandOutputCaptureReconciliationPermit,
) -> Result<(), DurableCoordinatorError> {
    let mut permit = Some(permit);
    match produce_unknown_capture_physical_resolution(ledger, &mut permit, |_| {
        Err(CommandOutputStoreError::Reference(
            "injected deterministic physical producer failure".into(),
        ))
    })? {
        UnknownPhysicalResolutionProducerOutcome::CleanupRequired(_) => Ok(()),
        UnknownPhysicalResolutionProducerOutcome::Produced(_) => Err(protocol(
            "injected Unknown physical producer unexpectedly returned a receipt",
        )),
    }
}

#[cfg(test)]
pub(in crate::runner_client) fn fail_unknown_core_resolution_precommit_for_test(
    ledger: &mut EventLedger,
    permit: grok_build_core::CommandOutputCaptureReconciliationPermit,
    capture: &grok_build_core::PersistedCommandOutputCapture,
) -> Result<(), DurableCoordinatorError> {
    let claim = permit.claim().clone();
    let terminal = capture.terminal.as_ref().ok_or_else(|| {
        protocol("injected core precommit failure requires an immutable Unknown terminal")
    })?;
    let invalid_record_digest = Digest::sha256(b"injected invalid core resolution record");
    let invalid_resolution = CommandOutputCaptureReconciliationResolutionV1 {
        contract_version: capture.intent.contract_version,
        layout_version: capture.intent.layout_version,
        capture_id: capture.intent.capture_id.clone(),
        effect_id: capture.intent.source.effect_id.clone(),
        observation_id: terminal.observation_id.clone(),
        terminal_anchor_digest: terminal.terminal_anchor_digest.clone(),
        reconciliation_claim_id: claim.claim_id.clone(),
        reconciliation_fencing_token: claim.fencing_token.clone(),
        disposition: CommandOutputCaptureTerminalDispositionV1::Abandoned,
        store_head: grok_build_core::CommandOutputCaptureStoreHeadV1 {
            generation: terminal.store_head.generation.saturating_add(1),
            record_digest: invalid_record_digest.clone(),
        },
        resolution_record_digest: invalid_record_digest,
        artifact_reference: None,
        resolved_at_unix_ms: 0,
        resolution_anchor_digest: Digest::sha256(b"injected invalid core resolution anchor"),
    };
    let proof_bytes = b"injected core precommit cleanup proof".to_vec();
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: "injected-core-precommit-cleanup-proof".into(),
        sprint_id: capture.intent.source.sprint_id.clone(),
        launch_id: capture.intent.source.runner_launch_id.clone(),
        session_id: capture.intent.source.runner_session_id.clone(),
        effect_id: capture.intent.source.effect_id.clone(),
        observation_id: Some(terminal.observation_id.clone()),
        request_digest: capture.intent.source.request_digest.clone(),
        backend: CommandDomainBackend::LinuxCgroupV2,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: Digest::sha256(&proof_bytes),
        platform_proof_bytes: proof_bytes,
        cleaned_at_unix_ms: terminal.anchored_at_unix_ms,
    };
    let mut resolution_permit = Some(permit);
    let error = commit_unknown_capture_resolution(
        ledger,
        &mut resolution_permit,
        &invalid_resolution,
        None,
        None,
        &command_cleanup,
        "injected-missing-runner-cleanup-receipt",
    )
    .expect_err("invalid zero-time resolution must fail definitely before commit");
    let retry_permit = resolution_permit.take().ok_or_else(|| {
        protocol("definite core precommit failure did not return its exact retry permit")
    })?;
    let original_error = DurableCoordinatorError::from(error);
    let expected_error = original_error.to_string();
    let release_result: Result<(), DurableCoordinatorError> =
        release_uncommitted_command_capture_claim(ledger, retry_permit, Err(original_error));
    match release_result {
        Err(released_error) if released_error.to_string() == expected_error => Ok(()),
        Err(released_error) => Err(protocol(format!(
            "core precommit claim release changed the original failure: {released_error}"
        ))),
        Ok(()) => Err(protocol(
            "invalid core resolution unexpectedly committed after claim release",
        )),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Unknown capture closure joins exact immutable effect, fenced storage, command cleanup, and worker cleanup authority"
)]
pub(super) fn resolve_terminal_unknown_command_capture(
    ledger: &mut EventLedger,
    private_state_root: &Path,
    effect: &PersistedEffect,
    completed_cleanup: &PersistedEffect,
    requested_at_unix_ms: u64,
    owner: UnknownCommandRunnerOwner<'_>,
) -> Result<UnknownCommandCaptureResolutionOutcome, DurableCoordinatorError> {
    let PersistedFinishReceipt::WorkerCleanup(expected_runner_cleanup) =
        &completed_cleanup.finish_receipt
    else {
        return Err(protocol(
            "Unknown command-output resolution requires the exact worker cleanup receipt",
        ));
    };
    let runner_cleanup =
        ledger.load_worker_cleanup_evidence(&expected_runner_cleanup.receipt.receipt_id)?;
    if &runner_cleanup != expected_runner_cleanup {
        return Err(protocol(
            "Unknown command-output resolution worker cleanup readback differs",
        ));
    }
    let command_cleanup = ledger.load_command_domain_cleanup_proof(&effect.intent.effect_id)?;
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let terminal_family = validate_unknown_command_capture_authority(
        effect,
        &capture,
        &command_cleanup,
        &runner_cleanup,
        owner,
    )?;

    let store = match CapabilityCommandOutputStore::open(private_state_root) {
        Ok(store) => store,
        Err(error) => {
            return Ok(unknown_capture_cleanup_required(format!(
                "Unknown command-output capture store cannot be opened exactly: {error}"
            )));
        }
    };
    let initially_reopened = match store.reopen_capture(&capture.intent.capture_id) {
        Ok(recovery) => recovery,
        Err(error) => {
            return Ok(unknown_capture_cleanup_required(format!(
                "Unknown command-output capture exact reopen remains uncertain: {error}"
            )));
        }
    };
    validate_unknown_capture_recovery_binding(&capture, &initially_reopened)?;
    let detector_policy =
        match ledger.load_sensitive_output_detection_policy_for_effect(&effect.intent.effect_id) {
            Ok(policy) => Some(policy),
            Err(LedgerError::ArtifactNotFound {
                entity: "sensitive output detection policy",
                ref id,
            }) if id == &effect.intent.effect_id => None,
            Err(error) => return Err(error.into()),
        };
    let sensitive_output_v2 = store
        .reopen_optional_sensitive_output_journal_v2(&capture.intent.capture_id)
        .map_err(|error| {
            protocol(format!(
                "Unknown command additive-v2 journal presence/readback is not exact: {error}"
            ))
        })?;
    match (detector_policy.as_ref(), sensitive_output_v2.as_ref()) {
        (Some(_), Some(recovery)) => recovery
            .validate_intent_binding(&capture.intent)
            .map_err(|error| protocol(error.to_string()))?,
        (Some(_), None) => {
            return Err(protocol(
                "policy-bound Unknown command capture lacks its exact additive-v2 journal",
            ));
        }
        (None, Some(_)) => {
            return Err(protocol(
                "additive-v2 Unknown command journal exists without persisted detector-policy authority",
            ));
        }
        (None, None) => {}
    }
    let current_policy_native_cleanup = detector_policy
        .as_ref()
        .map(|_| {
            let (_, expected_runner_backend) =
                task_unknown_command_backends(runner_cleanup.receipt.platform_backend)?;
            let runner_binding = RunnerCommandCleanupBinding::try_new(
                capture.intent.source.runner_session_id.clone(),
                effect.intent.effect_id.clone(),
                effect.intent.request_digest.clone(),
            )
            .map_err(|error| protocol(error.to_string()))?;
            let native_cleanup_proof = ValidatedCommandDomainCleanupProof::readback(
                &command_cleanup.proof.platform_proof_bytes,
                &command_cleanup.proof.platform_proof_digest,
                expected_runner_backend,
                &runner_binding,
            )
            .map_err(|error| {
                protocol(format!(
                    "policy-bound Unknown cleanup proof cannot be reopened exactly: {error}"
                ))
            })?;
            Ok::<_, DurableCoordinatorError>((expected_runner_backend, native_cleanup_proof))
        })
        .transpose()?;
    let join_policy_terminal_recovery =
        |recovery: CommandOutputCaptureRecovery| -> Result<_, DurableCoordinatorError> {
            let Some(detector_policy) = detector_policy.as_ref() else {
                if sensitive_output_v2.is_some() {
                    return Err(protocol(
                        "legacy Unknown terminal recovery unexpectedly retained an additive-v2 journal",
                    ));
                }
                return Ok(recovery);
            };
            if !matches!(
                recovery.state(),
                CommandOutputCaptureJournalStateV1::Published
                    | CommandOutputCaptureJournalStateV1::TerminalPrepared
                    | CommandOutputCaptureJournalStateV1::Cleaned
            ) {
                return Err(protocol(
                    "policy-bound Unknown read-only join requires exact v1 terminal custody",
                ));
            }
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                protocol("policy-bound Unknown read-only join lacks exact core acquisition")
            })?;
            let (expected_backend, native_cleanup_proof) =
                current_policy_native_cleanup.as_ref().ok_or_else(|| {
                    protocol("policy-bound Unknown read-only join lacks native cleanup authority")
                })?;
            let joined = store
                .reopen_sensitive_output_unknown_terminal_join_v2(
                    &capture.intent,
                    acquired,
                    recovery.store_head(),
                    detector_policy,
                    *expected_backend,
                    native_cleanup_proof,
                )
                .map_err(|error| {
                    protocol(format!(
                        "policy-bound Unknown v2/v1 terminal join failed: {error}"
                    ))
                })?;
            if joined.v1_terminal() != &recovery {
                return Err(protocol(
                    "policy-bound Unknown v2/v1 terminal join crossed its selected v1 readback",
                ));
            }
            Ok(joined.v1_terminal().clone())
        };

    if capture.reconciliation_resolution.is_some()
        || capture.reconciliation_obligation_closure.is_some()
    {
        let exactly_joined = join_policy_terminal_recovery(initially_reopened)?;
        let Some(material) =
            unknown_capture_resolution_material(&capture, &exactly_joined, &terminal_family)?
        else {
            return Ok(unknown_capture_cleanup_required(
                "resolved Unknown command-output capture no longer has an exact physical terminal",
            ));
        };
        return if exact_unknown_capture_resolution_is_durable(ledger, &capture, &material)? {
            Ok(UnknownCommandCaptureResolutionOutcome::Resolved)
        } else {
            Err(protocol(
                "resolved Unknown command-output capture differs from exact physical storage",
            ))
        };
    }

    let terminal = capture
        .terminal
        .as_ref()
        .expect("authority validation requires it");
    let claimed_at_unix_ms = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(requested_at_unix_ms)
        .max(terminal.anchored_at_unix_ms)
        .max(command_cleanup.proof.cleaned_at_unix_ms)
        .max(runner_cleanup.receipt.cleaned_at_unix_ms);
    let expires_at_unix_ms = claimed_at_unix_ms
        .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
        .ok_or_else(|| protocol("Unknown command-output reconciliation claim time overflow"))?;
    let claim_id =
        fresh_command_output_capture_id().map_err(|error| protocol(error.to_string()))?;
    let admission = match ledger.claim_command_output_capture_reconciliation(
        &capture.intent.capture_id,
        &claim_id,
        "desktop-terminal-unknown-command-capture-resolution-v1",
        claimed_at_unix_ms,
        expires_at_unix_ms,
    ) {
        Ok(admission) => admission,
        Err(LedgerError::PostCommitStateUncertain { .. }) => {
            let uncertain_capture =
                ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
            let reopened = match store.reopen_capture(&uncertain_capture.intent.capture_id) {
                Ok(recovery) => recovery,
                Err(error) => {
                    return Ok(unknown_capture_cleanup_required(format!(
                        "Unknown command-output claim and exact store readback are uncertain: {error}"
                    )));
                }
            };
            let reopened = if matches!(
                reopened.state(),
                CommandOutputCaptureJournalStateV1::Published
                    | CommandOutputCaptureJournalStateV1::TerminalPrepared
                    | CommandOutputCaptureJournalStateV1::Cleaned
            ) {
                join_policy_terminal_recovery(reopened)?
            } else {
                reopened
            };
            let Some(material) = unknown_capture_resolution_material(
                &uncertain_capture,
                &reopened,
                &terminal_family,
            )?
            else {
                return Ok(unknown_capture_cleanup_required(
                    "Unknown command-output reconciliation claim outcome is uncertain",
                ));
            };
            return if exact_unknown_capture_resolution_is_durable(
                ledger,
                &uncertain_capture,
                &material,
            )? {
                Ok(UnknownCommandCaptureResolutionOutcome::Resolved)
            } else {
                Ok(unknown_capture_cleanup_required(
                    "Unknown command-output reconciliation claim outcome is uncertain",
                ))
            };
        }
        Err(error) => return Err(error.into()),
    };
    let permit = match admission {
        CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
        CommandOutputCaptureReconciliationAdmission::Busy(_) => {
            return Ok(unknown_capture_cleanup_required(
                "Unknown command-output capture is owned by another live reconciliation claim",
            ));
        }
        CommandOutputCaptureReconciliationAdmission::Terminal(terminal_capture) => {
            let reopened = match store.reopen_capture(&terminal_capture.intent.capture_id) {
                Ok(recovery) => recovery,
                Err(error) => {
                    return Ok(unknown_capture_cleanup_required(format!(
                        "terminal Unknown command-output capture cannot be reopened exactly: {error}"
                    )));
                }
            };
            let reopened = join_policy_terminal_recovery(reopened)?;
            let Some(material) = unknown_capture_resolution_material(
                &terminal_capture,
                &reopened,
                &terminal_family,
            )?
            else {
                return Ok(unknown_capture_cleanup_required(
                    "terminal Unknown command-output capture lacks an exact physical terminal",
                ));
            };
            return if exact_unknown_capture_resolution_is_durable(
                ledger,
                &terminal_capture,
                &material,
            )? {
                Ok(UnknownCommandCaptureResolutionOutcome::Resolved)
            } else {
                Err(protocol(
                    "terminal Unknown command-output capture differs from exact resolution readback",
                ))
            };
        }
    };
    let mut resolution_permit = Some(permit);
    let resolution_result = (|| {
        let exact_claim = resolution_permit
            .as_ref()
            .expect("fresh Unknown resolution claim remains in custody before core commit")
            .claim()
            .clone();

        let requires_fenced_storage_transition = initially_reopened.store_head()
            != &terminal.store_head
            || initially_reopened.pending_record().is_some()
            || !matches!(
                initially_reopened.state(),
                CommandOutputCaptureJournalStateV1::Published
                    | CommandOutputCaptureJournalStateV1::TerminalPrepared
                    | CommandOutputCaptureJournalStateV1::Cleaned
            );
        let physical_reconciled_at_unix_ms = current_unix_ms()
            .map_err(|error| protocol(error.to_string()))?
            .max(claimed_at_unix_ms)
            .max(command_cleanup.proof.cleaned_at_unix_ms)
            .max(runner_cleanup.receipt.cleaned_at_unix_ms);
        if physical_reconciled_at_unix_ms >= exact_claim.expires_at_unix_ms {
            return release_unknown_capture_reconciliation_claim(
                ledger,
                resolution_permit
                    .take()
                    .expect("expired physical producer releases the exact Unknown claim"),
            );
        }
        let (reconciled, resolution_physical) = if requires_fenced_storage_transition {
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                protocol("advancing Unknown capture resolution lacks its exact acquisition")
            })?;
            if matches!(
                sensitive_output_v2
                    .as_ref()
                    .map(grok_build_runner::SensitiveOutputJournalRecoveryV2::stage),
                Some(SensitiveOutputJournalStageV2::WriterAttached { .. })
            ) && initially_reopened.launch_intended_store_head().is_some()
            {
                let (expected_runner_backend, native_cleanup_proof) =
                    current_policy_native_cleanup.as_ref().ok_or_else(|| {
                        protocol("policy-bound split-launch Unknown lacks native cleanup authority")
                    })?;
                let quarantine = store
                    .quarantine_split_sensitive_output_launch_v2(
                        &capture.intent,
                        &exact_claim,
                        *expected_runner_backend,
                        native_cleanup_proof,
                    )
                    .map_err(|error| {
                        protocol(format!(
                            "policy-bound split-launch Unknown quarantine failed: {error}"
                        ))
                    })?;
                quarantine
                    .validate()
                    .map_err(|error| protocol(error.to_string()))?;
                if quarantine.v1_launch_intended_store_head()
                    != initially_reopened
                        .launch_intended_store_head()
                        .expect("split-launch selector requires the exact v1 launch head")
                {
                    return Err(protocol(
                        "policy-bound split-launch Unknown quarantine crossed the selected v1 launch head",
                    ));
                }
                let reconciled_at_unix_ms = current_unix_ms()
                    .map_err(|error| protocol(error.to_string()))?
                    .max(physical_reconciled_at_unix_ms);
                if reconciled_at_unix_ms >= exact_claim.expires_at_unix_ms {
                    return release_unknown_capture_reconciliation_claim(
                        ledger,
                        resolution_permit.take().expect(
                            "expired split-launch resolution releases the exact Unknown claim",
                        ),
                    );
                }
                let recovery = quarantine.v1_cleaned().clone();
                let physical = recovery
                    .physical_reconciliation_evidence(
                        &capture.intent,
                        &exact_claim,
                        reconciled_at_unix_ms,
                    )
                    .map_err(|error| protocol(error.to_string()))?;
                (recovery, Some(physical))
            } else {
                let fenced = match produce_unknown_capture_physical_resolution(
                    ledger,
                    &mut resolution_permit,
                    |claim| {
                        if let Some(detector_policy) = detector_policy.as_ref() {
                            if !matches!(
                                sensitive_output_v2.as_ref().map(
                                    grok_build_runner::SensitiveOutputJournalRecoveryV2::stage,
                                ),
                                Some(SensitiveOutputJournalStageV2::TerminalPrepared { .. })
                            ) {
                                return Err(CommandOutputStoreError::Reference(
                                    "policy-bound live Unknown capture requires its exact stage-specific recovery branch"
                                        .into(),
                                ));
                            }
                            let terminal_prepared_store_head = initially_reopened
                            .terminal_prepared_store_head()
                            .ok_or_else(|| {
                                CommandOutputStoreError::Reference(
                                    "policy-bound live Unknown resolution requires exact v1 TerminalPrepared custody"
                                        .into(),
                                )
                            })?;
                            store.resolve_sensitive_output_clean_unknown_capture_v2(
                                &capture.intent,
                                acquired,
                                terminal_prepared_store_head,
                                claim,
                                initially_reopened.store_head(),
                                detector_policy,
                                || {
                                    current_unix_ms().map_err(|error| {
                                    CommandOutputStoreError::Reference(format!(
                                        "cannot sample post-reconciliation receipt time: {error}"
                                    ))
                                })
                                },
                            )
                        } else {
                            store.resolve_unknown_capture(
                                &capture.intent,
                                acquired,
                                &terminal.store_head,
                                claim,
                                initially_reopened.store_head(),
                                || {
                                    current_unix_ms().map_err(|error| {
                                        CommandOutputStoreError::Reference(format!(
                                            "cannot sample post-reconciliation receipt time: {error}"
                                        ))
                                    })
                                },
                            )
                        }
                    },
                )? {
                    UnknownPhysicalResolutionProducerOutcome::Produced(fenced) => *fenced,
                    UnknownPhysicalResolutionProducerOutcome::CleanupRequired(pending) => {
                        return Ok(pending);
                    }
                };
                let (recovery, physical) = fenced.into_parts();
                physical.validate_against(&capture.intent, &exact_claim, Some(acquired))?;
                validate_unknown_capture_recovery_binding(&capture, &recovery)?;
                (recovery, Some(physical))
            }
        } else {
            (join_policy_terminal_recovery(initially_reopened)?, None)
        };
        let Some(material) =
            unknown_capture_resolution_material(&capture, &reconciled, &terminal_family)?
        else {
            return release_unknown_capture_reconciliation_claim(
                ledger,
                resolution_permit
                    .take()
                    .expect("pending storage releases the exact Unknown claim"),
            );
        };
        let resolved_at_unix_ms = if let Some(physical) = resolution_physical.as_ref() {
            physical.reconciled_at_unix_ms
        } else {
            current_unix_ms()
                .map_err(|error| protocol(error.to_string()))?
                .max(physical_reconciled_at_unix_ms)
                .max(command_cleanup.proof.cleaned_at_unix_ms)
                .max(runner_cleanup.receipt.cleaned_at_unix_ms)
        };
        if resolved_at_unix_ms >= exact_claim.expires_at_unix_ms {
            return release_unknown_capture_reconciliation_claim(
                ledger,
                resolution_permit
                    .take()
                    .expect("expired resolution releases the exact Unknown claim"),
            );
        }
        let resolution = if material.store_head == terminal.store_head {
            if resolution_physical.is_some() {
                return Err(protocol(
                    "same-head restart Unknown resolution unexpectedly carried advancing physical evidence",
                ));
            }
            let UnknownCommandCaptureTerminalFamily::RestartPhysical(physical) = &terminal_family
            else {
                return Err(protocol(
                    "live Unknown command capture cannot resolve without strict store-head advancement",
                ));
            };
            let acquired = capture.acquired.as_ref().ok_or_else(|| {
                protocol("same-head restart Unknown resolution lacks its exact acquisition")
            })?;
            CommandOutputCaptureReconciliationResolutionV1::try_new_restart_same_head(
                &capture.intent,
                acquired,
                terminal,
                &exact_claim,
                physical,
                material.disposition,
                resolved_at_unix_ms,
            )?
        } else {
            let physical = resolution_physical.as_ref().ok_or_else(|| {
                protocol("head-advancing Unknown resolution lacks its fenced physical receipt")
            })?;
            if physical.requested_store_head.as_ref() != Some(&terminal.store_head)
                || physical.final_store_head != material.store_head
                || physical.final_store_head.record_digest != material.resolution_record_digest
                || physical.artifact_reference != material.artifact_reference
                || physical.reconciled_at_unix_ms != resolved_at_unix_ms
            {
                return Err(protocol(
                    "head-advancing Unknown resolution material differs from its fenced physical receipt",
                ));
            }
            CommandOutputCaptureReconciliationResolutionV1::try_new(
                &capture.intent,
                terminal,
                &exact_claim,
                material.disposition,
                material.store_head,
                material.resolution_record_digest,
                material.artifact_reference,
                resolved_at_unix_ms,
            )?
        };
        let clean_scan_resolution_receipt = match detector_policy.as_ref() {
            Some(detector_policy)
                if material.disposition == CommandOutputCaptureTerminalDispositionV1::Published =>
            {
                let Some(clean_receipt) = store
                    .reopen_sensitive_output_clean_v2(&capture.intent.capture_id)
                    .map_err(|error| protocol(error.to_string()))?
                else {
                    return release_unknown_capture_reconciliation_claim(
                        ledger,
                        resolution_permit.take().expect(
                            "missing current clean receipt releases the exact Unknown claim",
                        ),
                    );
                };
                let clean_runner = core_clean_runner_reference(&clean_receipt)
                    .map_err(|error| protocol(error.to_string()))?;
                let restart_same_head_receipt = (resolution.store_head == terminal.store_head)
                    .then(|| {
                        let UnknownCommandCaptureTerminalFamily::RestartPhysical(physical) =
                            &terminal_family
                        else {
                            unreachable!(
                                "same-head resolution was already confined to restart evidence"
                            );
                        };
                        physical.as_ref()
                    });
                Some(
                    CommandOutputCleanScanResolutionReceiptV1::try_new_from_runner_reference(
                        &capture.intent,
                        capture.acquired.as_ref().ok_or_else(|| {
                            protocol("current clean Unknown resolution lacks its exact acquisition")
                        })?,
                        terminal,
                        &exact_claim,
                        &resolution,
                        restart_same_head_receipt,
                        detector_policy.clone(),
                        &clean_runner,
                    )?,
                )
            }
            Some(_) | None => None,
        };
        match commit_unknown_capture_resolution(
            ledger,
            &mut resolution_permit,
            &resolution,
            resolution_physical.as_ref(),
            clean_scan_resolution_receipt.as_ref(),
            &command_cleanup.proof,
            &runner_cleanup.receipt.receipt_id,
        ) {
            Ok(resolved)
                if resolved.reconciliation_resolution.as_ref() == Some(&resolution)
                    && resolved.reconciliation_obligation_closure.as_ref()
                        == resolved
                            .terminal
                            .as_ref()
                            .map(|terminal| &terminal.terminal_anchor_digest) =>
            {
                Ok(UnknownCommandCaptureResolutionOutcome::Resolved)
            }
            Ok(_) => Err(protocol(
                "Unknown command-output resolution exact post-commit readback differs",
            )),
            Err(error) => {
                if resolution_permit.is_some() {
                    return Err(error.into());
                }
                let reloaded =
                    ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
                let reopened = match store.reopen_capture(&capture.intent.capture_id) {
                    Ok(recovery) => recovery,
                    Err(reopen_error) => {
                        return Ok(unknown_capture_cleanup_required(format!(
                            "Unknown command-output resolution commit and store readback are uncertain: commit={error}; reopen={reopen_error}"
                        )));
                    }
                };
                let reopened = join_policy_terminal_recovery(reopened)?;
                let Some(readback_material) =
                    unknown_capture_resolution_material(&reloaded, &reopened, &terminal_family)?
                else {
                    return Ok(unknown_capture_cleanup_required(format!(
                        "Unknown command-output resolution commit remains uncertain: {error}"
                    )));
                };
                if reloaded.reconciliation_resolution.as_ref() == Some(&resolution)
                    && exact_unknown_capture_resolution_is_durable(
                        ledger,
                        &reloaded,
                        &readback_material,
                    )?
                {
                    Ok(UnknownCommandCaptureResolutionOutcome::Resolved)
                } else if matches!(error, LedgerError::PostCommitStateUncertain { .. }) {
                    Ok(unknown_capture_cleanup_required(format!(
                        "Unknown command-output resolution commit remains uncertain: {error}"
                    )))
                } else {
                    Err(error.into())
                }
            }
        }
    })();
    match resolution_permit {
        Some(permit) => {
            release_uncommitted_command_capture_claim(ledger, permit, resolution_result)
        }
        None => resolution_result,
    }
}

#[cfg(test)]
pub(in crate::runner_client) fn repeat_task_unknown_capture_resolution_for_test(
    ledger: &mut EventLedger,
    private_state_root: &Path,
    effect: &PersistedEffect,
    completed_cleanup: &PersistedEffect,
    requested_at_unix_ms: u64,
    worker_lease: &WorkerLease,
) -> Result<(), DurableCoordinatorError> {
    match resolve_terminal_unknown_command_capture(
        ledger,
        private_state_root,
        effect,
        completed_cleanup,
        requested_at_unix_ms,
        UnknownCommandRunnerOwner::TaskWorker(worker_lease),
    )? {
        UnknownCommandCaptureResolutionOutcome::Resolved => Ok(()),
        UnknownCommandCaptureResolutionOutcome::CleanupRequired { reason } => Err(protocol(
            format!("repeat task Unknown capture resolution remains cleanup-required: {reason}"),
        )),
    }
}

pub(super) fn build_restarted_command_observation(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    outcome: EffectOutcome,
    observed_at_unix_ms: u64,
) -> Result<(EffectObservation, AgentEvent), DurableCoordinatorError> {
    let intent = &effect.intent;
    let observation = EffectObservation {
        contract_version: CONTRACT_VERSION,
        observation_id: format!("{}:observation", intent.effect_id),
        effect_id: intent.effect_id.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        sprint_id: intent.sprint_id.clone(),
        task_id: intent.task_id.clone(),
        worker_id: intent.worker_id.clone(),
        worker_lease: intent.worker_lease.clone(),
        correlation_id: intent.correlation_id.clone(),
        kind: intent.kind,
        request_digest: intent.request_digest.clone(),
        policy_hash: intent.policy_hash.clone(),
        input_snapshot: intent.input_snapshot.clone(),
        outcome,
        observed_at_unix_ms,
    };
    let event = AgentEvent {
        contract_version: CONTRACT_VERSION,
        sequence: ledger.next_sequence(&intent.sprint_id)?,
        event_id: format!("{}:finished", intent.effect_id),
        sprint_id: intent.sprint_id.clone(),
        task_id: intent.task_id.clone(),
        worker_id: intent.worker_id.clone(),
        causation_id: Some(effect.proposed_event.event_id.clone()),
        correlation_id: intent.correlation_id.clone(),
        policy_hash: Some(intent.policy_hash.clone()),
        occurred_at_unix_ms: observed_at_unix_ms,
        payload: AgentEventKind::ToolFinished {
            tool_call_id: intent.idempotency_key.clone(),
            succeeded: observation.outcome.succeeded(),
        },
    };
    observation.validate()?;
    event.validate()?;
    Ok((observation, event))
}

#[allow(
    clippy::large_enum_variant,
    reason = "the ready branch transfers the exact command-domain binding and validated cleanup proof by value at one authority handoff"
)]
pub(super) enum RestartNativeCommandCleanupProgress {
    Ready {
        binding: CommandDomainEffectBinding,
        proof: ValidatedCommandDomainCleanupProof,
        cleaned_at_unix_ms: u64,
    },
    CleanupRequired {
        reason: String,
    },
}

pub(super) fn exact_unobserved_restart_command_binding(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    launch_id: &str,
    session_id: &str,
) -> Result<CommandDomainEffectBinding, DurableCoordinatorError> {
    let mut matching = ledger
        .load_command_domain_effect_bindings(&effect.intent.sprint_id, launch_id, session_id)?
        .into_iter()
        .filter(|binding| binding.effect_id == effect.intent.effect_id);
    let binding = matching.next().ok_or_else(|| {
        protocol("command restart lacks its exact durable command-domain binding")
    })?;
    if matching.next().is_some()
        || binding.sprint_id != effect.intent.sprint_id
        || binding.launch_id != launch_id
        || binding.session_id != session_id
        || binding.request_digest != effect.intent.request_digest
        || binding.observation_id.is_some()
        || binding.finalized_at_unix_ms.is_some()
        || binding.state != CommandDomainEffectState::AwaitingObservation
    {
        return Err(protocol(
            "command restart crossed its exact unobserved command-domain binding",
        ));
    }
    binding.validate()?;
    Ok(binding)
}

pub(super) fn reopen_restart_native_command_cleanup(
    native_cleanup_reopener: &mut Option<Box<dyn NativeLaunchCleanupReopener>>,
    ledger: &EventLedger,
    effect: &PersistedEffect,
    launch_id: &str,
    session_id: &str,
    expected_backend: RunnerCommandCleanupBackend,
    not_before_unix_ms: u64,
) -> Result<RestartNativeCommandCleanupProgress, DurableCoordinatorError> {
    let binding = exact_unobserved_restart_command_binding(ledger, effect, launch_id, session_id)?;
    let runner_binding = RunnerCommandCleanupBinding::try_new(
        binding.session_id.clone(),
        binding.effect_id.clone(),
        binding.request_digest.clone(),
    )
    .map_err(|error| protocol(error.to_string()))?;
    let Some(reopener) = native_cleanup_reopener.as_mut() else {
        return Ok(RestartNativeCommandCleanupProgress::CleanupRequired {
            reason: format!(
                "command restart requires an independently authenticated native command-domain cleanup reopener for effect {}",
                binding.effect_id
            ),
        });
    };
    let observation = match reopener.cleanup_command_domain(NativeCommandDomainCleanupRequest {
        effect_binding: &binding,
        runner_binding: &runner_binding,
        expected_backend,
        requested_at_unix_ms: not_before_unix_ms,
    }) {
        Ok(observation) => observation,
        Err(error) => {
            return Ok(RestartNativeCommandCleanupProgress::CleanupRequired {
                reason: format!(
                    "native command-domain cleanup remains required for effect {}: {error}",
                    binding.effect_id
                ),
            });
        }
    };
    if observation.effect_binding != binding {
        return Err(protocol(
            "native command cleanup observation crossed the exact restart effect binding",
        ));
    }
    observation
        .proof
        .validate_expected(
            observation.proof.os_evidence_digest(),
            expected_backend,
            &runner_binding,
        )
        .map_err(|error| {
            protocol(format!(
                "native command cleanup proof crossed restart backend or request authority: {error}"
            ))
        })?;
    if observation.proof.surviving_processes() != 0 {
        return Err(protocol(
            "native command cleanup proof retained surviving processes",
        ));
    }
    if observation.cleaned_at_unix_ms < not_before_unix_ms {
        return Ok(RestartNativeCommandCleanupProgress::CleanupRequired {
            reason: "native command cleanup completed before the immutable restart lower bound"
                .into(),
        });
    }
    Ok(RestartNativeCommandCleanupProgress::Ready {
        binding,
        proof: observation.proof,
        cleaned_at_unix_ms: observation.cleaned_at_unix_ms,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "restart launch validation keeps each independently persisted command authority explicit"
)]
pub(super) fn validate_current_policy_restarted_launch(
    recovery: &CommandOutputCaptureRecovery,
    effect: &PersistedEffect,
    dispatch_claim: &PersistedRunnerEffectDispatchClaim,
    runner_session: &grok_build_core::RunnerSessionPolicyRecord,
    command: &grok_build_core::CommandSpec,
    acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
    detector_policy: &grok_build_core::SensitiveOutputDetectionPolicyReferenceV1,
    expected_grant_hash: &Digest,
    expected_backend: RunnerCommandCleanupBackend,
) -> Result<ValidatedCommandCaptureLaunchBindingV12, DurableCoordinatorError> {
    let launch = recovery.launch_intended().ok_or_else(|| {
        protocol("current-policy restart lost its exact v1 LaunchIntended payload")
    })?;
    let launch_head = recovery
        .launch_intended_store_head()
        .ok_or_else(|| protocol("current-policy restart lost its exact v1 LaunchIntended head"))?;
    if launch.schema != CONTAINED_CAPTURE_LAUNCH_SCHEMA {
        return Err(protocol(
            "current-policy restart launch evidence uses an unsupported runner schema",
        ));
    }
    let working_directory = command
        .working_directory
        .to_str()
        .ok_or_else(|| protocol("recovered command working directory is not exact UTF-8"))?;
    let wire_command = WireCommandSpec {
        program: command.program.clone(),
        arguments: command.arguments.clone(),
        working_directory: working_directory.to_owned(),
    };
    let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
        .map_err(|error| protocol(error.to_string()))?;
    let binding = decode_contained_capture_launch_binding_v12(
        &launch.canonical_bytes,
        launch_head,
        &effect.intent,
        dispatch_claim,
        runner_session,
        &wire_command,
        &output_capture,
        detector_policy,
        expected_grant_hash,
    )
    .map_err(|error| protocol(error.to_string()))?;
    if binding.canonical_bytes_digest() != &launch.canonical_bytes_digest
        || binding.launch_intended_store_head() != launch_head
        || *binding.closed_exec_descriptors() != [0, 1, 2]
        || binding.backend().command_domain_backend != expected_backend
    {
        return Err(protocol(
            "current-policy restart launch crossed retained payload, head, descriptors, or backend",
        ));
    }
    Ok(binding)
}

/// Reconstructs and durably appends the exact clean terminal that follows an
/// observation-backed generation-five-through-seven publication recovery.
///
/// The immutable observation supplies only eventual response material. This
/// join independently retains the freshly reopened native cleanup proof and
/// exact V12 launch binding, then lets the ordinary v1 terminal journal mint
/// the real successor head before generation eight is appended to v2.
#[allow(
    clippy::too_many_lines,
    reason = "terminal reconstruction keeps every observation, launch, proof, stream, and journal identity visibly joined"
)]
pub(super) fn prepare_restarted_partial_clean_terminal(
    store: &CapabilityCommandOutputStore,
    intent: &grok_build_core::CommandOutputCaptureIntentV1,
    acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
    recovery: &SensitiveOutputCleanPublicationRecoveryV1,
    native_cleanup_proof: &ValidatedCommandDomainCleanupProof,
    reconciled_not_before_unix_ms: u64,
) -> Result<
    (
        CommandOutputCaptureRecovery,
        CommandOutputCapturePhysicalReconciliationV1,
    ),
    DurableCoordinatorError,
> {
    recovery
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    acquired.validate_against(intent)?;
    if recovery.reconciliation_claim().capture_id != intent.capture_id
        || recovery.fenced_v1_recovery().acquired() != Some(acquired)
        || recovery.artifact_reference().source != acquired.source
    {
        return Err(protocol(
            "partial clean terminal reconstruction crossed intent, acquisition, or recovery fence",
        ));
    }
    let clean_response = recovery
        .observation()
        .clean_response()
        .ok_or_else(|| protocol("partial clean recovery lost its exact response material"))?;
    let v1 = recovery.fenced_v1_recovery();
    let finished_store_head = v1
        .finished_store_head()
        .cloned()
        .ok_or_else(|| protocol("partial clean recovery lost its v1 Finished head"))?;
    let published_store_head = v1
        .published_store_head()
        .cloned()
        .ok_or_else(|| protocol("partial clean recovery lost its v1 Published head"))?;

    // The payload digest excludes the successor-generation placeholder. Replace
    // it with the durable head before validation.
    let terminal_generation = published_store_head
        .generation
        .checked_add(1)
        .ok_or_else(|| protocol("partial clean terminal generation overflow"))?;
    let mut provisional_preimage =
        b"grok-build/desktop-partial-clean-provisional-terminal-head/v1\0".to_vec();
    provisional_preimage.extend_from_slice(intent.capture_id.as_bytes());
    provisional_preimage.extend_from_slice(
        recovery
            .observation()
            .observation_digest()
            .as_str()
            .as_bytes(),
    );
    let provisional_digest = Digest::sha256(&provisional_preimage);
    if provisional_digest == finished_store_head.record_digest
        || provisional_digest == published_store_head.record_digest
    {
        return Err(protocol(
            "partial clean provisional terminal identity collided with an immutable predecessor",
        ));
    }
    let provisional_terminal_head = CommandOutputCaptureStoreHeadV1 {
        generation: terminal_generation,
        record_digest: provisional_digest,
    };
    let terminal_capture = WireCommandOutputCaptureTerminalV1::try_new(
        acquired.capture_id.clone(),
        acquired.acquired_anchor_digest.clone(),
        finished_store_head,
        published_store_head.clone(),
        provisional_terminal_head,
        recovery.artifact_reference().clone(),
        Digest::sha256(b"grok-build/desktop-partial-clean-provisional-record/v1"),
    )
    .map_err(|error| protocol(error.to_string()))?;
    let mut terminal = WireCommandTerminalEvidence {
        output_capture: terminal_capture,
        termination: recovery.observation().termination(),
        stdout: clean_response.stdout().clone(),
        stderr: clean_response.stderr().clone(),
        output_artifacts: recovery.artifact_reference().clone(),
        output_digest: clean_response.output_digest().clone(),
        launch_digest: clean_response.launch_digest().clone(),
        preflight_digest: clean_response.preflight_digest().clone(),
        backend: clean_response.backend().clone(),
        cleanup_proof: WireCommandCleanupProof::try_from(native_cleanup_proof)
            .map_err(|error| protocol(error.to_string()))?,
        duration_ms: clean_response.duration_ms(),
    };
    terminal
        .bind_terminal_record_digest()
        .map_err(|error| protocol(error.to_string()))?;
    let terminal_record =
        command_terminal_record_bytes(&terminal).map_err(|error| protocol(error.to_string()))?;
    let terminal_preparation = store
        .prepare_sensitive_output_clean_terminal_under_claim_v1(
            intent,
            recovery.reconciliation_claim(),
            recovery,
            &published_store_head,
            COMMAND_TERMINAL_CAPTURE_SCHEMA,
            terminal_record,
        )
        .map_err(|error| protocol(error.to_string()))?;
    terminal_preparation
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    if terminal_preparation.capture_id() != intent.capture_id
        || terminal_preparation.reconciliation_claim() != recovery.reconciliation_claim()
        || terminal_preparation.terminal_schema() != COMMAND_TERMINAL_CAPTURE_SCHEMA
        || terminal_preparation.terminal_record_digest()
            != &terminal.output_capture.terminal_record_digest
    {
        return Err(protocol(
            "partial clean terminal preparation crossed capture, claim, schema, or payload digest",
        ));
    }
    terminal.output_capture.terminal_prepared_store_head =
        terminal_preparation.terminal_prepared_store_head().clone();
    let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
        .map_err(|error| protocol(error.to_string()))?;
    terminal
        .validate_for_output_capture(&output_capture)
        .map_err(|error| protocol(error.to_string()))?;
    let receipt = store
        .record_sensitive_output_clean_terminal_prepared_v2(
            &intent.capture_id,
            &terminal.output_capture.terminal_prepared_store_head,
            &terminal.output_capture.terminal_record_digest,
            terminal.termination,
        )
        .map_err(|error| protocol(error.to_string()))?;
    let readback = store
        .reopen_sensitive_output_clean_v2(&intent.capture_id)
        .map_err(|error| protocol(error.to_string()))?
        .ok_or_else(|| protocol("partial clean generation-eight receipt disappeared"))?;
    if readback != receipt {
        return Err(protocol(
            "partial clean generation-eight receipt changed across exact readback",
        ));
    }
    let reconciled_at_unix_ms = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(reconciled_not_before_unix_ms)
        .max(receipt.terminal_prepared_at_unix_ms);
    if reconciled_at_unix_ms >= recovery.reconciliation_claim().expires_at_unix_ms {
        return Err(protocol(
            "partial clean terminal recovery exceeded its core claim lease after durable terminal preparation",
        ));
    }
    let terminal_recovery = store
        .reopen_capture(&intent.capture_id)
        .map_err(|error| protocol(error.to_string()))?;
    if terminal_recovery.state() != CommandOutputCaptureJournalStateV1::TerminalPrepared
        || terminal_recovery.terminal_prepared_store_head()
            != Some(terminal_preparation.terminal_prepared_store_head())
        || terminal_recovery
            .terminal()
            .map(|payload| &payload.canonical_bytes_digest)
            != Some(terminal_preparation.terminal_record_digest())
    {
        return Err(protocol(
            "partial clean terminal recovery changed after generation-eight readback",
        ));
    }
    let physical = terminal_preparation
        .physical_reconciliation_evidence(
            intent,
            recovery.reconciliation_claim(),
            reconciled_at_unix_ms,
        )
        .map_err(|error| protocol(error.to_string()))?;
    Ok((terminal_recovery, physical))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the rejection commit keeps the runner receipt, independently reopened native proof, core claim, and abandonment transaction explicit"
)]
pub(super) fn commit_restarted_sensitive_output_rejection(
    ledger: &mut EventLedger,
    effect: &PersistedEffect,
    restart: &WalkingSkeletonTaskCommandRestart<'_>,
    capture_intent: &grok_build_core::CommandOutputCaptureIntentV1,
    acquired: &grok_build_core::CommandOutputCaptureAcquiredV1,
    claim: &grok_build_core::CommandOutputCaptureReconciliationClaimV1,
    reconciliation_permit: &mut Option<grok_build_core::CommandOutputCaptureReconciliationPermit>,
    rejection: SensitiveOutputRejectionJournalReceiptV2,
    binding: CommandDomainEffectBinding,
    native_cleanup_proof: ValidatedCommandDomainCleanupProof,
    cleaned_at_unix_ms: u64,
    expected_runner_backend: RunnerCommandCleanupBackend,
    core_cleanup_backend: CommandDomainBackend,
) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
    rejection
        .validate_request_binding(
            &restart.runner_session.session_id,
            &effect.intent.effect_id,
            &effect.intent.request_digest,
            acquired,
        )
        .map_err(|error| protocol(error.to_string()))?;
    let expected_proof_id = Digest::parse(rejection.command_domain_cleanup_proof_id.clone())
        .map_err(|error| protocol(error.to_string()))?;
    if native_cleanup_proof.os_evidence_digest() != &expected_proof_id {
        return Err(protocol(
            "terminal v2 rejection crossed its independently reopened native proof",
        ));
    }
    let runner_binding = RunnerCommandCleanupBinding::try_new(
        binding.session_id,
        binding.effect_id,
        binding.request_digest,
    )
    .map_err(|error| protocol(error.to_string()))?;
    let rejoin = SensitiveOutputRejectionNativeProofRejoinV1::try_new(
        rejection,
        Some(native_cleanup_proof),
        expected_runner_backend,
        &runner_binding,
    )
    .map_err(|error| {
        protocol(format!(
            "terminal sensitive-output native-proof rejoin failed: {error}"
        ))
    })?;
    let (rejection, proof, rejoined_backend) = rejoin.into_parts();
    if rejoined_backend != expected_runner_backend
        || proof.os_evidence_digest() != &expected_proof_id
    {
        return Err(protocol(
            "terminal sensitive-output rejoin crossed backend or proof identity",
        ));
    }
    let observed_at_unix_ms = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(claim.acquired_at_unix_ms)
        .max(cleaned_at_unix_ms);
    if observed_at_unix_ms >= claim.expires_at_unix_ms {
        return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
            reason: "terminal sensitive-output rejection rejoin exceeded its core claim lease"
                .into(),
        });
    }
    let runner_cleanup =
        core_rejection_runner_reference(&rejection).map_err(|error| protocol(error.to_string()))?;
    let observation_id = format!("{}:observation", effect.intent.effect_id);
    let rejection_anchor = CommandOutputSensitiveRejectionAnchorV1::try_new(
        capture_intent,
        acquired,
        observation_id,
        runner_cleanup.clone(),
    )?;
    let anchor_evidence = rejection_anchor.canonical_evidence_bytes()?;
    let (observation, event) = build_restarted_command_observation(
        ledger,
        effect,
        EffectOutcome::FailedAfterKnownEffect {
            evidence_digest: Digest::sha256(&anchor_evidence),
        },
        observed_at_unix_ms,
    )?;
    let rejection_cleanup = CommandOutputSensitiveRejectionCleanupReceiptV1::try_new(
        &rejection_anchor,
        rejection.cleanup_receipt_id.clone(),
        runner_cleanup,
        rejection.command_domain_cleanup_proof_id.clone(),
    )?;
    let command_cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: rejection.command_domain_cleanup_proof_id,
        sprint_id: effect.intent.sprint_id.clone(),
        launch_id: restart.runner_launch.launch_id.clone(),
        session_id: restart.runner_session.session_id.clone(),
        effect_id: effect.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: effect.intent.request_digest.clone(),
        backend: core_cleanup_backend,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: proof.os_evidence_digest().clone(),
        platform_proof_bytes: proof.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms,
    };
    command_cleanup.validate()?;
    let terminal_permit = reconciliation_permit
        .take()
        .expect("terminal sensitive-output rejection consumes the exact restart claim");
    let committed = ledger.record_reconciled_command_sensitive_output_rejection(
        terminal_permit,
        &observation,
        &event,
        &rejection_anchor,
        &rejection_cleanup,
        &command_cleanup,
    );
    restarted_command_commit_result(ledger, effect, committed)
}

pub(super) fn recovered_provider_command_result(
    call: &ProviderToolCall,
    adapted: &AdaptedCommandTerminal,
) -> Result<ProviderToolResult, DurableCoordinatorError> {
    if !matches!(call.intent, ProviderToolIntent::RunCommand { .. }) {
        return Err(protocol(
            "recovered command result requires the exact RunCommand provider call",
        ));
    }
    let termination = match adapted.termination {
        grok_build_core::CommandTerminationV1::Exited { code } => {
            ProviderCommandTermination::Exit(code)
        }
        grok_build_core::CommandTerminationV1::Signaled { .. } => {
            ProviderCommandTermination::Signaled
        }
        grok_build_core::CommandTerminationV1::TimedOut => ProviderCommandTermination::TimedOut,
        grok_build_core::CommandTerminationV1::Canceled
        | grok_build_core::CommandTerminationV1::OutputLimitExceeded => {
            ProviderCommandTermination::Cancelled
        }
    };
    Ok(ProviderToolResult {
        result_id: format!("{}:result", call.call_id),
        call: call.clone(),
        output: ProviderToolOutput::CommandFinished {
            termination,
            stdout: adapted.stdout.retained_bytes.clone(),
            stdout_total_bytes: adapted.stdout.complete_length,
            stdout_digest: adapted.stdout.complete_digest.clone(),
            stdout_truncated: adapted.stdout.truncated,
            stderr: adapted.stderr.retained_bytes.clone(),
            stderr_total_bytes: adapted.stderr.complete_length,
            stderr_digest: adapted.stderr.complete_digest.clone(),
            stderr_truncated: adapted.stderr.truncated,
        },
    })
}

pub(super) fn recovered_command_cleanup_proof(
    effect: &PersistedEffect,
    observation: &EffectObservation,
    adapted: &AdaptedCommandTerminal,
    physical: &CommandOutputCapturePhysicalReconciliationV1,
    expected_worker_backend: WorkerCleanupBackend,
) -> Result<CommandDomainCleanupProof, DurableCoordinatorError> {
    let closure = adapted.command_terminal();
    let acquired = physical.physical_acquired.as_ref().ok_or_else(|| {
        protocol("recovered successful command lacks its exact physical acquisition")
    })?;
    let binding = RunnerCommandCleanupBinding::try_new(
        acquired.source.runner_session_id.clone(),
        effect.intent.effect_id.clone(),
        effect.intent.request_digest.clone(),
    )
    .map_err(|error| protocol(error.to_string()))?;
    let cleanup = closure
        .cleanup_proof()
        .readback(closure.backend().command_domain_backend, &binding)
        .map_err(|error| protocol(error.to_string()))?;
    if cleanup.surviving_processes() != 0 {
        return Err(protocol(
            "recovered command terminal cleanup proof retained surviving processes",
        ));
    }
    let backend = match cleanup.backend() {
        RunnerCommandCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        RunnerCommandCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
    };
    let worker_backend = match expected_worker_backend {
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(protocol(
                "ordinary recovered command cannot use trusted-Applier cleanup authority",
            ));
        }
    };
    if backend != worker_backend
        || physical.effect_id != effect.intent.effect_id
        || acquired.source.sprint_id != effect.intent.sprint_id
        || acquired.source.runner_session_id != binding.runner_session_id()
        || acquired.source.effect_id != effect.intent.effect_id
        || acquired.source.request_digest != effect.intent.request_digest
        || observation.effect_id != effect.intent.effect_id
        || !matches!(observation.outcome, EffectOutcome::Succeeded { .. })
    {
        return Err(protocol(
            "recovered command cleanup crossed backend, session, effect, or terminal outcome",
        ));
    }
    let proof = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: format!(
            "command-capture-restart-cleanup-{}",
            physical.reconciliation_digest
        ),
        sprint_id: effect.intent.sprint_id.clone(),
        launch_id: acquired.source.runner_launch_id.clone(),
        session_id: acquired.source.runner_session_id.clone(),
        effect_id: effect.intent.effect_id.clone(),
        observation_id: Some(observation.observation_id.clone()),
        request_digest: effect.intent.request_digest.clone(),
        backend,
        disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        surviving_processes: 0,
        platform_proof_digest: cleanup.os_evidence_digest().clone(),
        platform_proof_bytes: cleanup.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms: physical.reconciled_at_unix_ms,
    };
    proof.validate()?;
    Ok(proof)
}

pub(super) fn commit_restarted_command_unknown(
    ledger: &mut EventLedger,
    effect: &PersistedEffect,
    physical: &CommandOutputCapturePhysicalReconciliationV1,
    reconciliation_permit: &mut Option<grok_build_core::CommandOutputCaptureReconciliationPermit>,
) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
    let evidence_digest = physical.effect_evidence_digest()?;
    let (observation, event) = build_restarted_command_observation(
        ledger,
        effect,
        EffectOutcome::Unknown { evidence_digest },
        physical.reconciled_at_unix_ms,
    )?;
    let terminal_permit = reconciliation_permit
        .take()
        .expect("launch-bearing Unknown commit consumes the exact restart claim");
    let committed = ledger.record_reconciled_claimed_command_output_capture_unknown(
        terminal_permit,
        &observation,
        &event,
        physical,
    );
    restarted_command_commit_result(ledger, effect, committed)
}

pub(super) fn restarted_command_commit_result(
    ledger: &EventLedger,
    effect: &PersistedEffect,
    result: Result<PersistedEffect, LedgerError>,
) -> Result<WalkingSkeletonTaskCommandRestartOutcome, DurableCoordinatorError> {
    match result {
        Ok(completed) => Ok(WalkingSkeletonTaskCommandRestartOutcome::Terminal(
            Box::new(completed),
        )),
        Err(error) => {
            let readback = ledger.load_effect(&effect.intent.effect_id)?;
            if readback.observation.is_some() {
                return Ok(WalkingSkeletonTaskCommandRestartOutcome::Terminal(
                    Box::new(readback),
                ));
            }
            if matches!(error, LedgerError::PostCommitStateUncertain { .. }) {
                return Ok(WalkingSkeletonTaskCommandRestartOutcome::CleanupRequired {
                    reason: format!(
                        "command restart terminal commit remains uncertain for {}: {error}",
                        effect.intent.effect_id
                    ),
                });
            }
            Err(error.into())
        }
    }
}

pub(super) fn release_uncommitted_command_capture_claim<T>(
    ledger: &mut EventLedger,
    permit: grok_build_core::CommandOutputCaptureReconciliationPermit,
    result: Result<T, DurableCoordinatorError>,
) -> Result<T, DurableCoordinatorError> {
    let claim = permit.claim().clone();
    let released_at_unix_ms = current_unix_ms()
        .unwrap_or(claim.acquired_at_unix_ms)
        .max(claim.acquired_at_unix_ms);
    match ledger.release_command_output_capture_reconciliation(permit, released_at_unix_ms) {
        Ok(released) if released == claim => result,
        Ok(_) => Err(protocol(
            "uncommitted command restart released a crossed reconciliation claim",
        )),
        Err(error) => Err(error.into()),
    }
}
