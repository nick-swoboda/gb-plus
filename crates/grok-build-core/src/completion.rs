//! Coordinator-computed sprint completion.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AcceptanceKind, ApplicationEvidence, ApplicationValidationMode, CompletionApplication,
    CompletionReceipt, CriterionEvidenceReceiptV2, Digest, HumanAcceptanceBackingV1,
    HumanAcceptanceDecisionOutcomeV1, HumanAcceptanceDecisionV1, HumanAcceptancePromptV1,
    RollbackReferenceEvidence, RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
    SprintSpec, TaskGraph, TaskIntegrationReceipt, VerificationEffectEvidence, VerificationReceipt,
    VerifiedNoOpReceipt, WorkerCleanupEvidence,
};

/// Current coordinator evidence used to calculate, never infer, completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionEvidence {
    /// Exact typed evidence receipts satisfying sprint criteria.
    pub criterion_evidence_receipts: Vec<CriterionEvidenceReceiptV2>,
    /// Immutable prompts referenced by accepted-by-you criterion evidence.
    pub human_acceptance_prompts: Vec<HumanAcceptancePromptV1>,
    /// Immutable decisions referenced by accepted-by-you criterion evidence.
    pub human_acceptance_decisions: Vec<HumanAcceptanceDecisionV1>,
    /// Exact typed task-integration receipts read back from persistence.
    pub task_integration_receipts: Vec<TaskIntegrationReceipt>,
    /// Exact effect-bound task, criterion, and final verification evidence.
    pub verification_effect_evidence: Vec<VerificationEffectEvidence>,
    /// Exact candidate final snapshot.
    pub final_snapshot: Digest,
    /// Repository-wide verification against `final_snapshot`.
    pub final_verification: Option<VerificationReceipt>,
    /// Exact durable final/criterion verification receipt identifier set read
    /// from persistence.
    pub verification_receipt_ids: Vec<String>,
    /// Durable runner session bound to the final verification receipt.
    pub final_verification_session_id: Option<String>,
    /// Exact durable runner-session/policy registrations from which cleanup is
    /// derived.
    pub runner_sessions: Vec<RunnerSessionPolicyRecord>,
    /// Exact durable pre-spawn launch attempts from which cleanup obligations
    /// are derived, including initialization failures.
    pub runner_launches: Vec<RunnerLaunchIntent>,
    /// Effect-bound successful application receipt plus exact direct or
    /// recovery validation provenance read from persistence.
    pub application_evidence: Option<ApplicationEvidence>,
    /// Successful no-op evidence, mutually exclusive with application.
    pub verified_no_op_receipt: Option<VerifiedNoOpReceipt>,
    /// Exact effect-bound zero-descendant proofs read from persistence.
    pub worker_cleanup_evidence: Vec<WorkerCleanupEvidence>,
    /// Reopened and validated one-click rollback artifacts.
    pub rollback_reference: Option<RollbackReferenceEvidence>,
    /// Number of unresolved integration or live-workspace conflicts.
    pub unresolved_conflicts: usize,
    /// Number of side effects whose outcome cannot be proven.
    pub unknown_side_effects: usize,
    /// Number of durable worker leases that have not yet been released by
    /// exact zero-descendant cleanup evidence.
    pub active_worker_leases: usize,
    /// Exact canonical leases whose durable cleanup-bound release rows were
    /// read back from persistence.
    pub released_worker_leases: Vec<crate::WorkerLease>,
    /// Completion receipt read back from durable storage.
    pub completion_receipt: Option<CompletionReceipt>,
    /// Whether persistence acknowledged the completion receipt transaction.
    pub completion_receipt_persisted: bool,
    /// Durable final-report identifier.
    pub final_report_id: Option<String>,
}

/// One independently checkable condition of successful completion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompletionRequirement {
    /// The sprint and graph contracts are valid.
    ContractsValid,
    /// Every and only declared criteria have exact same-snapshot typed backing.
    AllCriteriaSatisfiedByTypedBacking,
    /// Every required graph task is integrated.
    AllRequiredTasksIntegrated,
    /// Repository-wide verification passed against the exact final snapshot.
    FinalSnapshotVerified,
    /// The exact verified snapshot was applied.
    FinalSnapshotApplied,
    /// Touched live paths match their expected final digests.
    LiveHashesMatch,
    /// No-op completion has typed runner/effect-bound live-manifest capture authority.
    VerifiedNoOpLiveManifestCaptureAuthorized,
    /// No unresolved conflict remains.
    NoUnresolvedConflicts,
    /// No ambiguous side effect remains.
    NoUnknownSideEffects,
    /// No worker or descendant process remains alive.
    NoSurvivingProcesses,
    /// Every durable task-worker lease has an exact cleanup-bound release.
    NoActiveWorkerLeases,
    /// The completion receipt is valid and consistent with the evidence.
    CompletionReceiptConsistent,
    /// The completion receipt was durably persisted and read back.
    CompletionReceiptPersisted,
    /// A valid rollback snapshot is available.
    RollbackAvailable,
    /// A durable final report is available.
    FinalReportAvailable,
}

/// Mutually exclusive terminal branch represented by a completion assessment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionApplicationAssessment {
    /// A successful application and rollback chain is the terminal branch.
    Applied,
    /// A verified unchanged live workspace is the terminal branch.
    VerifiedNoOp,
}

/// Complete result of applying the deterministic finish predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionAssessment {
    application: Option<CompletionApplicationAssessment>,
    unmet: Vec<CompletionRequirement>,
}

impl CompletionAssessment {
    /// Returns `true` only when every finish requirement is met.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.application.is_some() && self.unmet.is_empty()
    }

    /// Returns the sole evidence-selected terminal branch, if one exists.
    #[must_use]
    pub const fn application(&self) -> Option<CompletionApplicationAssessment> {
        self.application
    }

    /// Returns all unmet requirements in stable evaluation order.
    #[must_use]
    pub fn unmet_requirements(&self) -> &[CompletionRequirement] {
        &self.unmet
    }

    #[cfg(test)]
    pub(crate) fn from_unmet(
        application: CompletionApplicationAssessment,
        unmet: Vec<CompletionRequirement>,
    ) -> Self {
        Self {
            application: Some(application),
            unmet,
        }
    }
}

/// Calculates sprint completion from contract and runtime evidence.
///
/// This advisory function returns every unmet invariant so the UI can render
/// an exact non-completion reason. It never trusts a provider's claim that work
/// is finished and does not authorize durable completion; the event ledger's
/// atomic completion record remains the sole persistence authority.
#[must_use]
#[allow(clippy::too_many_lines)] // Keeping the finish checklist linear makes each unmet predicate auditable.
pub fn assess_completion(
    sprint: &SprintSpec,
    graph: &TaskGraph,
    evidence: &CompletionEvidence,
) -> CompletionAssessment {
    let mut unmet = Vec::new();
    let application = match (
        evidence.application_evidence.as_ref(),
        evidence.verified_no_op_receipt.as_ref(),
    ) {
        (Some(_), None) => Some(CompletionApplicationAssessment::Applied),
        (None, Some(_)) => Some(CompletionApplicationAssessment::VerifiedNoOp),
        (Some(_), Some(_)) | (None, None) => None,
    };
    let contracts_valid = sprint.validate().is_ok() && graph.validate_for_sprint(sprint).is_ok();
    require(
        &mut unmet,
        contracts_valid,
        CompletionRequirement::ContractsValid,
    );

    let criteria_satisfied = criterion_evidence_is_complete(sprint, evidence);
    require(
        &mut unmet,
        criteria_satisfied,
        CompletionRequirement::AllCriteriaSatisfiedByTypedBacking,
    );

    let required_tasks_ok = task_integrations_are_complete(sprint, graph, evidence);
    require(
        &mut unmet,
        required_tasks_ok,
        CompletionRequirement::AllRequiredTasksIntegrated,
    );

    let final_verification_ok = evidence.final_verification.as_ref().is_some_and(|receipt| {
        receipt.validate().is_ok()
            && receipt.passed()
            && receipt.sprint_id == sprint.sprint_id
            && receipt.task_id.is_none()
            && receipt.snapshot_id == evidence.final_snapshot
            && evidence.verification_effect_evidence.iter().any(|effect| {
                effect.validate().is_ok()
                    && effect.verification == *receipt
                    && effect.verification.receipt_id == receipt.receipt_id
            })
    });
    require(
        &mut unmet,
        final_verification_ok,
        CompletionRequirement::FinalSnapshotVerified,
    );
    let session_policy_ok = session_policies_are_valid(sprint, evidence);
    let cleanup_ok = session_policy_ok && cleanup_set_is_complete(sprint, evidence);
    // `VerifiedNoOpReceipt` currently carries only caller-populated manifest
    // bytes. Until a typed runner/session/effect-bound capture is represented
    // here, metadata equality cannot authorize no-op completion.
    let no_op_capture_authorized =
        application != Some(CompletionApplicationAssessment::VerifiedNoOp);
    if application == Some(CompletionApplicationAssessment::VerifiedNoOp) {
        require(
            &mut unmet,
            no_op_capture_authorized,
            CompletionRequirement::VerifiedNoOpLiveManifestCaptureAuthorized,
        );
    }
    let application_ok =
        live_application_is_valid(sprint, evidence, cleanup_ok) && no_op_capture_authorized;
    require(
        &mut unmet,
        application_ok && final_verification_ok,
        CompletionRequirement::FinalSnapshotApplied,
    );
    require(
        &mut unmet,
        application_ok,
        CompletionRequirement::LiveHashesMatch,
    );
    require(
        &mut unmet,
        evidence.unresolved_conflicts == 0,
        CompletionRequirement::NoUnresolvedConflicts,
    );
    require(
        &mut unmet,
        evidence.unknown_side_effects == 0,
        CompletionRequirement::NoUnknownSideEffects,
    );
    require(
        &mut unmet,
        cleanup_ok,
        CompletionRequirement::NoSurvivingProcesses,
    );
    let worker_leases_closed = worker_lease_evidence_is_complete(evidence);
    require(
        &mut unmet,
        evidence.active_worker_leases == 0 && worker_leases_closed,
        CompletionRequirement::NoActiveWorkerLeases,
    );

    let rollback_ok = rollback_is_available(sprint, evidence);
    require(
        &mut unmet,
        rollback_ok,
        CompletionRequirement::RollbackAvailable,
    );
    let report_ok = evidence
        .final_report_id
        .as_deref()
        .is_some_and(|id| !id.trim().is_empty());
    require(
        &mut unmet,
        report_ok,
        CompletionRequirement::FinalReportAvailable,
    );

    let receipt_consistent = completion_receipt_is_consistent(sprint, graph, evidence);
    require(
        &mut unmet,
        receipt_consistent,
        CompletionRequirement::CompletionReceiptConsistent,
    );
    require(
        &mut unmet,
        evidence.completion_receipt_persisted && receipt_consistent,
        CompletionRequirement::CompletionReceiptPersisted,
    );

    CompletionAssessment { application, unmet }
}

fn task_integrations_are_complete(
    sprint: &SprintSpec,
    graph: &TaskGraph,
    evidence: &CompletionEvidence,
) -> bool {
    let graph_tasks: BTreeSet<&str> = graph
        .tasks
        .iter()
        .map(|task| task.task_id.as_str())
        .collect();
    let required_tasks: BTreeSet<&str> = graph
        .tasks
        .iter()
        .filter(|task| task.required)
        .map(|task| task.task_id.as_str())
        .collect();
    let mut receipt_ids = BTreeSet::new();
    let mut task_ids = BTreeSet::new();
    let mut ordered = evidence
        .task_integration_receipts
        .iter()
        .collect::<Vec<_>>();
    ordered.sort_by_key(|receipt| receipt.integration_ordinal);
    let mut expected_input = &sprint.base_snapshot;
    for (ordinal, receipt) in ordered.into_iter().enumerate() {
        let Ok(ordinal) = u32::try_from(ordinal) else {
            return false;
        };
        let session_matches = evidence.runner_sessions.iter().any(|session| {
            session.session_id == receipt.worker_session_id
                && session.launch_id == receipt.worker_launch_id
                && session.purpose == RunnerSessionPurpose::TaskWorker
                && session.worker_id.as_deref() == Some(receipt.worker_id.as_str())
                && session.worker_lease == receipt.worker_lease
                && session.policy_hash == receipt.worker_policy_hash
                && evidence.runner_launches.iter().any(|launch| {
                    launch.launch_id == receipt.worker_launch_id
                        && launch.session_id == receipt.worker_session_id
                        && launch.worker_lease == receipt.worker_lease
                })
        });
        let verification_ids: BTreeSet<&str> = receipt
            .task_verification_receipt_ids
            .iter()
            .map(String::as_str)
            .collect();
        let matching_verifications: BTreeSet<&str> = evidence
            .verification_effect_evidence
            .iter()
            .filter(|evidence| {
                let verification = &evidence.verification;
                evidence.validate().is_ok()
                    && evidence.runner_launch_id == receipt.worker_launch_id
                    && evidence.runner_session_id == receipt.worker_session_id
                    && verification.passed()
                    && verification.sprint_id == sprint.sprint_id
                    && verification.task_id.as_deref() == Some(receipt.task_id.as_str())
                    && verification.snapshot_id == receipt.result_snapshot
                    && verification.policy_hash == receipt.worker_policy_hash
                    && verification.finished_at_unix_ms <= receipt.integrated_at_unix_ms
            })
            .map(|evidence| evidence.verification.receipt_id.as_str())
            .filter(|receipt_id| verification_ids.contains(receipt_id))
            .collect();
        if receipt.validate().is_err()
            || receipt.sprint_id != sprint.sprint_id
            || receipt.integration_ordinal != ordinal
            || receipt.input_snapshot != *expected_input
            || !graph_tasks.contains(receipt.task_id.as_str())
            || !receipt_ids.insert(receipt.receipt_id.as_str())
            || !task_ids.insert(receipt.task_id.as_str())
            || !session_matches
            || matching_verifications != verification_ids
        {
            return false;
        }
        expected_input = &receipt.result_snapshot;
    }
    required_tasks.is_subset(&task_ids) && expected_input == &evidence.final_snapshot
}

fn session_policies_are_valid(sprint: &SprintSpec, evidence: &CompletionEvidence) -> bool {
    let mut launch_ids = BTreeSet::new();
    let mut launched_session_ids = BTreeSet::new();
    for launch in &evidence.runner_launches {
        if launch.validate().is_err()
            || launch.sprint_id != sprint.sprint_id
            || launch.grant_hash != sprint.workspace_grant.grant_hash
            || launch.policy_version != sprint.workspace_grant.policy_version
            || !launch_ids.insert(launch.launch_id.as_str())
            || !launched_session_ids.insert(launch.session_id.as_str())
        {
            return false;
        }
    }
    let mut session_ids = BTreeSet::new();
    for session in &evidence.runner_sessions {
        if session.validate().is_err()
            || session.sprint_id != sprint.sprint_id
            || session.grant_hash != sprint.workspace_grant.grant_hash
            || session.policy_version != sprint.workspace_grant.policy_version
            || !session_ids.insert(session.session_id.as_str())
        {
            return false;
        }
        let Some(launch) = evidence
            .runner_launches
            .iter()
            .find(|launch| launch.launch_id == session.launch_id)
        else {
            return false;
        };
        if launch.session_id != session.session_id
            || launch.purpose != session.purpose
            || launch.worker_id != session.worker_id
            || launch.worker_lease != session.worker_lease
            || launch.policy_hash != session.policy_hash
            || launch.runner_binary_digest != session.runner_binary_digest
            || launch.protocol_digest != session.protocol_digest
            || launch.private_state_digest != session.private_state_digest
            || launch.created_at_unix_ms > session.registered_at_unix_ms
        {
            return false;
        }
    }
    !launch_ids.is_empty()
        && evidence
            .final_verification
            .as_ref()
            .zip(evidence.final_verification_session_id.as_deref())
            .is_some_and(|(verification, session_id)| {
                evidence.runner_sessions.iter().any(|session| {
                    session.session_id == session_id
                        && session.purpose == RunnerSessionPurpose::FinalVerifier
                        && session.policy_hash == verification.policy_hash
                        && session.registered_at_unix_ms <= verification.finished_at_unix_ms
                        && evidence.verification_effect_evidence.iter().any(|effect| {
                            effect.verification == *verification
                                && effect.runner_session_id == session.session_id
                                && effect.runner_launch_id == session.launch_id
                        })
                })
            })
}

fn cleanup_set_is_complete(sprint: &SprintSpec, evidence: &CompletionEvidence) -> bool {
    let mut cleanup_by_launch = BTreeMap::new();
    for cleanup in &evidence.worker_cleanup_evidence {
        let receipt = &cleanup.receipt;
        if cleanup.validate().is_err()
            || receipt.sprint_id != sprint.sprint_id
            || cleanup_by_launch
                .insert(receipt.launch_id.as_str(), cleanup)
                .is_some()
        {
            return false;
        }
    }
    if cleanup_by_launch.len() != evidence.runner_launches.len() {
        return false;
    }
    evidence.runner_launches.iter().all(|launch| {
        cleanup_by_launch
            .get(launch.launch_id.as_str())
            .is_some_and(|cleanup| {
                let receipt = &cleanup.receipt;
                let selected_final_session = evidence
                    .final_verification_session_id
                    .as_deref()
                    .and_then(|session_id| {
                        evidence
                            .runner_sessions
                            .iter()
                            .find(|session| session.session_id == session_id)
                    });
                receipt.session_id == launch.session_id
                    && receipt.worker_lease == launch.worker_lease
                    && evidence.runner_sessions.iter().any(|session| {
                        session.launch_id == launch.launch_id
                            && session.session_id == launch.session_id
                            && session.worker_lease == launch.worker_lease
                    })
                    && receipt.policy_hash == launch.policy_hash
                    && receipt.grant_hash == launch.grant_hash
                    && receipt.policy_version == launch.policy_version
                    && launch.created_at_unix_ms <= receipt.cleaned_at_unix_ms
                    && (selected_final_session.map(|session| session.launch_id.as_str())
                        != Some(launch.launch_id.as_str())
                        || evidence
                            .final_verification
                            .as_ref()
                            .is_some_and(|verification| {
                                verification.finished_at_unix_ms <= receipt.cleaned_at_unix_ms
                            }))
            })
    })
}

fn worker_lease_evidence_is_complete(evidence: &CompletionEvidence) -> bool {
    let mut expected = BTreeMap::new();
    for launch in &evidence.runner_launches {
        match (launch.purpose, launch.worker_lease.as_ref()) {
            (RunnerSessionPurpose::TaskWorker, Some(lease)) => {
                if lease.validate().is_err()
                    || expected.insert(lease.lease_id.as_str(), lease).is_some()
                {
                    return false;
                }
            }
            (RunnerSessionPurpose::FinalVerifier | RunnerSessionPurpose::Applier, None) => {}
            _ => return false,
        }
    }
    let released = evidence
        .released_worker_leases
        .iter()
        .map(|lease| (lease.lease_id.as_str(), lease))
        .collect::<BTreeMap<_, _>>();
    if released.len() != evidence.released_worker_leases.len() || released != expected {
        return false;
    }
    evidence.task_integration_receipts.iter().all(|receipt| {
        receipt
            .worker_lease
            .as_ref()
            .is_some_and(|lease| expected.get(lease.lease_id.as_str()).copied() == Some(lease))
    }) && evidence.worker_cleanup_evidence.iter().all(|cleanup| {
        cleanup
            .receipt
            .worker_lease
            .as_ref()
            .is_none_or(|lease| expected.get(lease.lease_id.as_str()).copied() == Some(lease))
    })
}

fn live_application_is_valid(
    sprint: &SprintSpec,
    evidence: &CompletionEvidence,
    cleanup_ok: bool,
) -> bool {
    if !cleanup_ok {
        return false;
    }
    match (
        evidence.application_evidence.as_ref(),
        evidence.verified_no_op_receipt.as_ref(),
    ) {
        (Some(application_evidence), None) => {
            applied_application_is_valid(sprint, evidence, application_evidence)
        }
        (None, Some(no_op)) => verified_no_op_is_valid(sprint, evidence, no_op),
        (Some(_), Some(_)) | (None, None) => false,
    }
}

fn applied_application_is_valid(
    sprint: &SprintSpec,
    evidence: &CompletionEvidence,
    application_evidence: &ApplicationEvidence,
) -> bool {
    let application = &application_evidence.receipt;
    application_evidence.validate().is_ok()
        && application_validation_authority_is_valid(evidence, application_evidence)
        && application.sprint_id == sprint.sprint_id
        && application.base_snapshot == sprint.base_snapshot
        && application.result_snapshot == evidence.final_snapshot
        && application.grant_hash == sprint.workspace_grant.grant_hash
        && application.policy_version == sprint.workspace_grant.policy_version
        && evidence
            .final_verification
            .as_ref()
            .is_some_and(|verification| {
                verification.finished_at_unix_ms <= application.applied_at_unix_ms
            })
        && application_cleanup_is_ordered(evidence, application_evidence)
}

fn application_validation_authority_is_valid(
    evidence: &CompletionEvidence,
    application_evidence: &ApplicationEvidence,
) -> bool {
    let application = &application_evidence.receipt;
    let validation = &application_evidence.validation;
    let executor = evidence
        .runner_sessions
        .iter()
        .find(|session| session.session_id == application.applier_session_id);
    let validator = evidence
        .runner_sessions
        .iter()
        .find(|session| session.session_id == validation.runner_session_id);
    executor
        .zip(validator)
        .is_some_and(|(executor, validator)| {
            let lifecycle_shape = match validation.mode {
                ApplicationValidationMode::DirectEffectResponse => {
                    validator.launch_id == executor.launch_id
                        && validator.session_id == executor.session_id
                }
                ApplicationValidationMode::RecoveryApplierReconciliation => {
                    validator.launch_id != executor.launch_id
                        && validator.session_id != executor.session_id
                }
            };
            executor.purpose == RunnerSessionPurpose::Applier
                && executor.policy_hash == application.policy_hash
                && validator.purpose == RunnerSessionPurpose::Applier
                && validator.launch_id == validation.runner_launch_id
                && validator.policy_hash == validation.policy_hash
                && validator.grant_hash == validation.grant_hash
                && validator.policy_version == validation.policy_version
                && validator.private_state_digest == validation.private_state_digest
                && validator.policy_hash == executor.policy_hash
                && validator.grant_hash == executor.grant_hash
                && validator.policy_version == executor.policy_version
                && validator.private_state_digest == executor.private_state_digest
                && validator.runner_binary_digest == executor.runner_binary_digest
                && validator.protocol_digest == executor.protocol_digest
                && lifecycle_shape
        })
}

fn application_cleanup_is_ordered(
    evidence: &CompletionEvidence,
    application_evidence: &ApplicationEvidence,
) -> bool {
    let application = &application_evidence.receipt;
    let Some(executor) = evidence
        .runner_sessions
        .iter()
        .find(|session| session.session_id == application.applier_session_id)
    else {
        return false;
    };
    let Some(validator) = evidence
        .runner_sessions
        .iter()
        .find(|session| session.session_id == application_evidence.validation.runner_session_id)
    else {
        return false;
    };
    evidence.worker_cleanup_evidence.iter().all(|cleanup| {
        evidence
            .runner_launches
            .iter()
            .find(|launch| launch.launch_id == cleanup.receipt.launch_id)
            .is_some_and(|launch| {
                application_cleanup_time_is_ordered(
                    evidence,
                    application,
                    executor,
                    validator,
                    launch,
                    cleanup.receipt.cleaned_at_unix_ms,
                )
            })
    })
}

fn application_cleanup_time_is_ordered(
    evidence: &CompletionEvidence,
    application: &crate::ApplicationReceipt,
    executor: &RunnerSessionPolicyRecord,
    validator: &RunnerSessionPolicyRecord,
    launch: &RunnerLaunchIntent,
    cleaned_at_unix_ms: u64,
) -> bool {
    if evidence
        .completion_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.completed_at_unix_ms < cleaned_at_unix_ms)
    {
        return false;
    }
    match launch.purpose {
        RunnerSessionPurpose::TaskWorker
        | RunnerSessionPurpose::FinalVerifier
        | RunnerSessionPurpose::LiveStateVerifier => {
            cleaned_at_unix_ms <= application.applied_at_unix_ms
        }
        RunnerSessionPurpose::Applier if launch.launch_id == validator.launch_id => evidence
            .rollback_reference
            .as_ref()
            .is_some_and(|rollback| {
                application.applied_at_unix_ms <= cleaned_at_unix_ms
                    && rollback.reference.validated_at_unix_ms <= cleaned_at_unix_ms
            }),
        RunnerSessionPurpose::Applier if launch.launch_id == executor.launch_id => {
            application.applied_at_unix_ms <= cleaned_at_unix_ms
        }
        RunnerSessionPurpose::Applier => cleaned_at_unix_ms <= application.applied_at_unix_ms,
    }
}

fn verified_no_op_is_valid(
    sprint: &SprintSpec,
    evidence: &CompletionEvidence,
    no_op: &VerifiedNoOpReceipt,
) -> bool {
    no_op.validate().is_ok()
        && no_op.sprint_id == sprint.sprint_id
        && no_op.base_snapshot == sprint.base_snapshot
        && evidence.final_snapshot == sprint.base_snapshot
        && no_op.grant_hash == sprint.workspace_grant.grant_hash
        && no_op.policy_version == sprint.workspace_grant.policy_version
        && evidence
            .final_verification
            .as_ref()
            .is_some_and(|verification| {
                no_op.final_verification_receipt_id == verification.receipt_id
                    && verification.finished_at_unix_ms <= no_op.observed_at_unix_ms
            })
        && evidence
            .worker_cleanup_evidence
            .iter()
            .all(|cleanup| cleanup.receipt.cleaned_at_unix_ms <= no_op.observed_at_unix_ms)
}

fn rollback_is_available(sprint: &SprintSpec, evidence: &CompletionEvidence) -> bool {
    match (
        evidence.application_evidence.as_ref(),
        evidence.verified_no_op_receipt.as_ref(),
        evidence.rollback_reference.as_ref(),
    ) {
        (Some(application_evidence), None, Some(rollback)) => {
            let application = &application_evidence.receipt;
            let validator_cleaned_at = evidence
                .worker_cleanup_evidence
                .iter()
                .find(|cleanup| {
                    cleanup.receipt.session_id == application_evidence.validation.runner_session_id
                })
                .map(|cleanup| cleanup.receipt.cleaned_at_unix_ms);
            application_evidence.validate().is_ok()
                && rollback.validate().is_ok()
                && rollback.reference.sprint_id == sprint.sprint_id
                && rollback.reference.base_snapshot == sprint.base_snapshot
                && rollback.reference.application_receipt_id == application.receipt_id
                && rollback.reference.transaction_id == application.transaction_id
                && application.applied_at_unix_ms <= rollback.reference.validated_at_unix_ms
                && validator_cleaned_at.is_some_and(|cleaned_at| {
                    application.applied_at_unix_ms <= cleaned_at
                        && rollback.reference.validated_at_unix_ms <= cleaned_at
                })
        }
        (None, Some(_), None) => true,
        _ => false,
    }
}

fn criterion_evidence_is_complete(sprint: &SprintSpec, evidence: &CompletionEvidence) -> bool {
    let mut by_criterion = BTreeMap::new();
    let mut receipt_ids = BTreeSet::new();
    for receipt in &evidence.criterion_evidence_receipts {
        if receipt.validate().is_err()
            || !receipt_ids.insert(receipt.receipt_id())
            || by_criterion
                .insert(receipt.criterion_id(), receipt)
                .is_some()
            || receipt.sprint_id() != sprint.sprint_id
            || receipt.snapshot_digest() != &evidence.final_snapshot
        {
            return false;
        }
    }
    if by_criterion.len() != sprint.acceptance_criteria.len() {
        return false;
    }

    let mut prompt_ids = BTreeSet::new();
    let prompts = evidence
        .human_acceptance_prompts
        .iter()
        .map(|prompt| {
            (prompt.validate().is_ok() && prompt_ids.insert(prompt.prompt_id.as_str()))
                .then_some((prompt.prompt_id.as_str(), prompt))
        })
        .collect::<Option<BTreeMap<_, _>>>();
    let mut decision_ids = BTreeSet::new();
    let mut decided_prompts = BTreeSet::new();
    let decisions = evidence
        .human_acceptance_decisions
        .iter()
        .map(|decision| {
            (decision.validate().is_ok()
                && decision_ids.insert(decision.decision_id.as_str())
                && decided_prompts.insert(decision.prompt_id.as_str()))
            .then_some((decision.decision_id.as_str(), decision))
        })
        .collect::<Option<BTreeMap<_, _>>>();
    let (Some(prompts), Some(decisions)) = (prompts, decisions) else {
        return false;
    };

    sprint.acceptance_criteria.iter().all(|criterion| {
        let Some(receipt) = by_criterion.get(criterion.criterion_id.as_str()) else {
            return false;
        };
        match (receipt, &criterion.kind) {
            (
                CriterionEvidenceReceiptV2::Verified {
                    verification_receipt_id,
                    recorded_at,
                    ..
                },
                AcceptanceKind::Automated(expected_command),
            ) => evidence
                .verification_effect_evidence
                .iter()
                .any(|verification| {
                    verification.validate().is_ok()
                        && verification.verification.receipt_id == *verification_receipt_id
                        && verification.verification.sprint_id == sprint.sprint_id
                        && verification.verification.snapshot_id == evidence.final_snapshot
                        && verification.verification.command == *expected_command
                        && verification.verification.passed()
                        && verification.verification.finished_at_unix_ms <= *recorded_at
                }),
            (
                CriterionEvidenceReceiptV2::AcceptedByYou {
                    human_decision_id,
                    prompt_id,
                    backing,
                    recorded_at,
                    ..
                },
                AcceptanceKind::HumanJudgment,
            ) => {
                let Some(prompt) = prompts.get(prompt_id.as_str()) else {
                    return false;
                };
                let Some(decision) = decisions.get(human_decision_id.as_str()) else {
                    return false;
                };
                *backing == HumanAcceptanceBackingV1::OneToOne
                    && prompt.sprint_id == sprint.sprint_id
                    && prompt.criterion_id == criterion.criterion_id
                    && prompt.criterion_text_digest
                        == Digest::sha256(criterion.description.as_bytes())
                    && prompt.snapshot_digest == evidence.final_snapshot
                    && prompt.workspace_grant_hash == sprint.workspace_grant.grant_hash
                    && prompt.backing == *backing
                    && decision.prompt_id == *prompt_id
                    && decision.outcome == HumanAcceptanceDecisionOutcomeV1::AcceptedByYou
                    && decision.consumed_event_sequence == prompt.issued_event_sequence
                    && decision.decided_at <= *recorded_at
            }
            (CriterionEvidenceReceiptV2::Verified { .. }, AcceptanceKind::HumanJudgment)
            | (CriterionEvidenceReceiptV2::AcceptedByYou { .. }, AcceptanceKind::Automated(_)) => {
                false
            }
        }
    })
}

#[allow(clippy::too_many_lines)] // One fail-closed comparison over the complete receipt authority.
fn completion_receipt_is_consistent(
    sprint: &SprintSpec,
    graph: &TaskGraph,
    evidence: &CompletionEvidence,
) -> bool {
    let Some(receipt) = &evidence.completion_receipt else {
        return false;
    };
    if receipt.validate().is_err()
        || receipt.sprint_id != sprint.sprint_id
        || receipt.final_snapshot != evidence.final_snapshot
        || receipt.grant_hash != sprint.workspace_grant.grant_hash
        || receipt.policy_version != sprint.workspace_grant.policy_version
        || receipt.provider_backend != sprint.provider.backend_id
        || receipt.provider_model != sprint.provider.model_id
        || evidence.final_report_id.as_deref() != Some(receipt.final_report_id.as_str())
    {
        return false;
    }
    let Some(final_verification) = &evidence.final_verification else {
        return false;
    };
    if receipt.final_verification_receipt_id != final_verification.receipt_id
        || !receipt
            .verification_receipts
            .contains(&final_verification.receipt_id)
    {
        return false;
    }
    let application_matches = match (
        &receipt.application,
        evidence.application_evidence.as_ref(),
        evidence.verified_no_op_receipt.as_ref(),
        evidence.rollback_reference.as_ref(),
    ) {
        (
            CompletionApplication::Applied {
                application_receipt_id,
                rollback_reference_id,
            },
            Some(application_evidence),
            None,
            Some(rollback),
        ) => {
            let application = &application_evidence.receipt;
            application_receipt_id == &application.receipt_id
                && application_evidence.validate().is_ok()
                && rollback_reference_id == &rollback.reference.reference_id
                && rollback.reference.application_receipt_id == application.receipt_id
                && rollback.reference.transaction_id == application.transaction_id
                && rollback.reference.base_snapshot == sprint.base_snapshot
        }
        (
            CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id,
            },
            None,
            Some(no_op),
            None,
        ) => verified_no_op_receipt_id == &no_op.receipt_id,
        _ => false,
    };
    let mut cleanup_ids: Vec<&str> = evidence
        .worker_cleanup_evidence
        .iter()
        .map(|cleanup| cleanup.receipt.receipt_id.as_str())
        .collect();
    cleanup_ids.sort_unstable();
    if !application_matches
        || cleanup_ids
            != receipt
                .worker_cleanup_receipt_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
    {
        return false;
    }
    let receipt_criterion_evidence: BTreeSet<&str> = receipt
        .criterion_evidence_receipt_ids
        .iter()
        .map(String::as_str)
        .collect();
    let expected_criterion_evidence: BTreeSet<&str> = evidence
        .criterion_evidence_receipts
        .iter()
        .map(CriterionEvidenceReceiptV2::receipt_id)
        .collect();
    if expected_criterion_evidence.len() != evidence.criterion_evidence_receipts.len()
        || expected_criterion_evidence != receipt_criterion_evidence
    {
        return false;
    }
    let expected_verifications: BTreeSet<&str> = evidence
        .verification_receipt_ids
        .iter()
        .map(String::as_str)
        .collect();
    let receipt_verifications: BTreeSet<&str> = receipt
        .verification_receipts
        .iter()
        .map(String::as_str)
        .collect();
    if expected_verifications.len() != evidence.verification_receipt_ids.len()
        || !expected_verifications.contains(final_verification.receipt_id.as_str())
        || receipt_verifications != expected_verifications
    {
        return false;
    }

    let receipt_criteria: BTreeSet<&str> = receipt
        .satisfied_criterion_ids
        .iter()
        .map(String::as_str)
        .collect();
    let expected_criteria: BTreeSet<&str> = sprint
        .acceptance_criteria
        .iter()
        .map(|criterion| criterion.criterion_id.as_str())
        .collect();
    if receipt_criteria != expected_criteria {
        return false;
    }

    let mut ordered_integrations = evidence
        .task_integration_receipts
        .iter()
        .collect::<Vec<_>>();
    ordered_integrations.sort_by_key(|integration| integration.integration_ordinal);
    receipt
        .task_integration_receipt_ids
        .iter()
        .map(String::as_str)
        .eq(ordered_integrations
            .into_iter()
            .map(|integration| integration.receipt_id.as_str()))
        && task_integrations_are_complete(sprint, graph, evidence)
}

fn require(
    unmet: &mut Vec<CompletionRequirement>,
    condition: bool,
    requirement: CompletionRequirement,
) {
    if !condition {
        unmet.push(requirement);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        AcceptanceCriterion, AcceptanceKind, ApplicationReceipt, CommandSpec, CommandTerminationV1,
        CompletionReceipt, ExecutionOrigin, PathScope, ProviderProfile, RollbackReference,
        RunnerSessionPurpose, SprintBudget, TaskSpec, WorkerCleanupBackend, WorkerCleanupReceipt,
        WorkerLease, WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
    };

    fn digest(character: char) -> Digest {
        Digest::parse(character.to_string().repeat(64)).expect("valid digest")
    }

    #[allow(clippy::too_many_lines)] // Complete authority fixtures are intentionally explicit.
    fn fixture() -> (SprintSpec, TaskGraph, CompletionEvidence) {
        let sprint = SprintSpec {
            sprint_id: "sprint-1".into(),
            objective: "Finish safely".into(),
            acceptance_criteria: vec![AcceptanceCriterion {
                criterion_id: "tests".into(),
                description: "Tests pass".into(),
                kind: AcceptanceKind::Automated(CommandSpec {
                    program: "cargo".into(),
                    arguments: vec!["test".into()],
                    working_directory: PathBuf::new(),
                }),
            }],
            provider: ProviderProfile {
                backend_id: "fake".into(),
                model_id: "deterministic".into(),
                execution_origin: ExecutionOrigin::HostIsolated,
            },
            budget: SprintBudget {
                max_tasks: 3,
                max_attempts_per_task: 3,
                max_tool_calls: 20,
                max_duration_ms: 60_000,
            },
            max_workers: 1,
            workspace_grant: WorkspaceGrant {
                grant_id: "grant".into(),
                canonical_root: PathBuf::from("/work/project"),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                grant_hash: digest('a'),
            },
            base_snapshot: digest('b'),
        };
        let graph = TaskGraph {
            graph_id: "graph".into(),
            tasks: vec![TaskSpec {
                task_id: "task-1".into(),
                goal: "Make tests pass".into(),
                dependencies: Vec::new(),
                path_scopes: vec![PathScope::Workspace],
                acceptance_checks: vec!["tests".into()],
                base_snapshot: digest('b'),
                required: true,
            }],
        };
        let final_output = b"final verification passed".to_vec();
        let verification = VerificationReceipt {
            receipt_id: "verify-final".into(),
            sprint_id: "sprint-1".into(),
            task_id: None,
            snapshot_id: digest('c'),
            command: CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            },
            policy_hash: digest('d'),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: Digest::sha256(&final_output),
            duration_ms: 100,
            finished_at_unix_ms: 4,
        };
        let final_verification_evidence = VerificationEffectEvidence {
            contract_version: crate::CONTRACT_VERSION,
            verification: verification.clone(),
            effect_id: "verify-final-effect".into(),
            observation_id: "verify-final-observation".into(),
            runner_launch_id: "launch-final".into(),
            runner_session_id: "session-final".into(),
            output_artifacts: None,
            output_evidence_bytes: final_output,
        };
        let task_output = b"task verification passed".to_vec();
        let task_verification = VerificationReceipt {
            receipt_id: "verify-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-1".into()),
            snapshot_id: digest('c'),
            command: CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into()],
                working_directory: PathBuf::new(),
            },
            policy_hash: digest('1'),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: Digest::sha256(&task_output),
            duration_ms: 100,
            finished_at_unix_ms: 2,
        };
        let task_verification_evidence = VerificationEffectEvidence {
            contract_version: crate::CONTRACT_VERSION,
            verification: task_verification,
            effect_id: "verify-task-effect".into(),
            observation_id: "verify-task-observation".into(),
            runner_launch_id: "launch-worker".into(),
            runner_session_id: "session-worker".into(),
            output_artifacts: None,
            output_evidence_bytes: task_output,
        };
        let worker_lease = WorkerLease::new(
            "sprint-1".into(),
            1,
            "task-1".into(),
            "worker-1".into(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("canonical worker lease");
        let task_integration = TaskIntegrationReceipt {
            contract_version: crate::CONTRACT_VERSION,
            receipt_id: "integration-task-1".into(),
            sprint_id: "sprint-1".into(),
            task_id: "task-1".into(),
            worker_id: "worker-1".into(),
            worker_lease: Some(worker_lease.clone()),
            worker_launch_id: "launch-worker".into(),
            worker_session_id: "session-worker".into(),
            worker_policy_hash: digest('1'),
            effect_id: "integration-task-effect".into(),
            observation_id: "integration-task-observation".into(),
            change_set_id: "aggregate-change".into(),
            input_snapshot: digest('b'),
            result_snapshot: digest('c'),
            task_verification_receipt_ids: vec!["verify-task-1".into()],
            integration_ordinal: 0,
            integrated_at_unix_ms: 3,
        };
        let receipt = CompletionReceipt {
            contract_version: crate::CONTRACT_VERSION,
            receipt_id: "complete-1".into(),
            sprint_id: "sprint-1".into(),
            grant_hash: digest('a'),
            policy_version: 1,
            final_snapshot: digest('c'),
            final_verification_receipt_id: "verify-final".into(),
            application: CompletionApplication::Applied {
                application_receipt_id: "application-1".into(),
                rollback_reference_id: "rollback-reference-1".into(),
            },
            worker_cleanup_receipt_ids: vec![
                "cleanup-applier".into(),
                "cleanup-final".into(),
                "cleanup-worker".into(),
            ],
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec!["criterion-evidence-tests".into()],
            task_integration_receipt_ids: vec!["integration-task-1".into()],
            verification_receipts: vec!["verify-final".into(), "verify-task-1".into()],
            provider_backend: "fake".into(),
            provider_model: "deterministic".into(),
            final_report_id: "report-1".into(),
            completed_at_unix_ms: 9,
        };
        let application = ApplicationReceipt {
            contract_version: crate::CONTRACT_VERSION,
            receipt_id: "application-1".into(),
            sprint_id: "sprint-1".into(),
            effect_id: "apply-effect".into(),
            observation_id: "apply-observation".into(),
            applier_session_id: "session-applier".into(),
            transaction_id: "apply-transaction".into(),
            change_set_id: "aggregate-change".into(),
            base_snapshot: digest('b'),
            result_snapshot: digest('c'),
            policy_hash: digest('f'),
            grant_hash: digest('a'),
            policy_version: 1,
            applied_operations_digest: digest('f'),
            touched_path_endpoints_digest: digest('1'),
            live_manifest_digest: digest('9'),
            applied_at_unix_ms: 6,
        };
        let application_evidence = ApplicationEvidence {
            contract_version: crate::CONTRACT_VERSION,
            validation: crate::ApplicationValidationEvidence {
                mode: ApplicationValidationMode::DirectEffectResponse,
                runner_launch_id: "launch-applier".into(),
                runner_session_id: "session-applier".into(),
                policy_hash: digest('f'),
                grant_hash: digest('a'),
                policy_version: 1,
                private_state_digest: digest('5'),
            },
            receipt: application,
        };
        let cleanup_evidence = |receipt_id: &str,
                                effect_id: &str,
                                observation_id: &str,
                                session_id: &str,
                                policy_hash: Digest,
                                platform_backend: WorkerCleanupBackend,
                                cleaned_at_unix_ms: u64| {
            let os_evidence_bytes =
                format!("authoritative cleanup evidence for {session_id}").into_bytes();
            WorkerCleanupEvidence {
                receipt: WorkerCleanupReceipt {
                    contract_version: crate::CONTRACT_VERSION,
                    receipt_id: receipt_id.into(),
                    sprint_id: "sprint-1".into(),
                    launch_id: format!("launch-{}", session_id.trim_start_matches("session-")),
                    effect_id: effect_id.into(),
                    observation_id: observation_id.into(),
                    session_id: session_id.into(),
                    worker_lease: (session_id == "session-worker").then(|| worker_lease.clone()),
                    policy_hash,
                    grant_hash: digest('a'),
                    policy_version: 1,
                    platform_backend,
                    os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                    surviving_processes: 0,
                    cleaned_at_unix_ms,
                },
                os_evidence_bytes,
            }
        };
        let cleanups = vec![
            cleanup_evidence(
                "cleanup-worker",
                "cleanup-worker-effect",
                "cleanup-worker-observation",
                "session-worker",
                digest('1'),
                WorkerCleanupBackend::MacOsDedicatedIdentity,
                5,
            ),
            cleanup_evidence(
                "cleanup-final",
                "cleanup-final-effect",
                "cleanup-final-observation",
                "session-final",
                digest('d'),
                WorkerCleanupBackend::MacOsDedicatedIdentity,
                5,
            ),
            cleanup_evidence(
                "cleanup-applier",
                "cleanup-applier-effect",
                "cleanup-applier-observation",
                "session-applier",
                digest('f'),
                WorkerCleanupBackend::TrustedApplierDirectChildWait,
                8,
            ),
        ];
        let session = |session_id: &str,
                       purpose: RunnerSessionPurpose,
                       worker_id: Option<&str>,
                       policy_hash: Digest| RunnerSessionPolicyRecord {
            contract_version: crate::CONTRACT_VERSION,
            sprint_id: "sprint-1".into(),
            launch_id: format!("launch-{}", session_id.trim_start_matches("session-")),
            session_id: session_id.into(),
            purpose,
            worker_id: worker_id.map(str::to_owned),
            worker_lease: (purpose == RunnerSessionPurpose::TaskWorker)
                .then(|| worker_lease.clone()),
            policy_hash,
            session_nonce: digest('2'),
            runner_binary_digest: digest('3'),
            protocol_digest: digest('4'),
            private_state_digest: digest('5'),
            grant_hash: digest('a'),
            policy_version: 1,
            registered_at_unix_ms: 1,
        };
        let launch = |session_id: &str,
                      purpose: RunnerSessionPurpose,
                      worker_id: Option<&str>,
                      policy_hash: Digest| RunnerLaunchIntent {
            contract_version: crate::CONTRACT_VERSION,
            launch_id: format!("launch-{}", session_id.trim_start_matches("session-")),
            sprint_id: "sprint-1".into(),
            session_id: session_id.into(),
            purpose,
            worker_id: worker_id.map(str::to_owned),
            worker_lease: (purpose == RunnerSessionPurpose::TaskWorker)
                .then(|| worker_lease.clone()),
            policy_hash,
            runner_binary_digest: digest('3'),
            protocol_digest: digest('4'),
            private_state_digest: digest('5'),
            grant_hash: digest('a'),
            policy_version: 1,
            created_at_unix_ms: 1,
        };
        let rollback_bytes = b"reopened immutable rollback artifacts".to_vec();
        let rollback = RollbackReferenceEvidence {
            reference: RollbackReference {
                contract_version: crate::CONTRACT_VERSION,
                reference_id: "rollback-reference-1".into(),
                sprint_id: "sprint-1".into(),
                application_receipt_id: "application-1".into(),
                transaction_id: "apply-transaction".into(),
                journal_binding_digest: digest('3'),
                base_snapshot: digest('b'),
                touched_target_set_digest: digest('4'),
                reopened_artifacts_digest: Digest::sha256(&rollback_bytes),
                validated_at_unix_ms: 7,
            },
            reopened_artifacts_bytes: rollback_bytes,
        };
        let evidence = CompletionEvidence {
            criterion_evidence_receipts: vec![CriterionEvidenceReceiptV2::Verified {
                receipt_id: "criterion-evidence-tests".into(),
                sprint_id: "sprint-1".into(),
                criterion_id: "tests".into(),
                snapshot_digest: digest('c'),
                verification_receipt_id: "verify-task-1".into(),
                recorded_at: 3,
            }],
            human_acceptance_prompts: Vec::new(),
            human_acceptance_decisions: Vec::new(),
            task_integration_receipts: vec![task_integration],
            verification_effect_evidence: vec![
                final_verification_evidence,
                task_verification_evidence,
            ],
            final_snapshot: digest('c'),
            final_verification: Some(verification),
            verification_receipt_ids: vec!["verify-final".into(), "verify-task-1".into()],
            final_verification_session_id: Some("session-final".into()),
            runner_sessions: vec![
                session(
                    "session-worker",
                    RunnerSessionPurpose::TaskWorker,
                    Some("worker-1"),
                    digest('1'),
                ),
                session(
                    "session-final",
                    RunnerSessionPurpose::FinalVerifier,
                    None,
                    digest('d'),
                ),
                session(
                    "session-applier",
                    RunnerSessionPurpose::Applier,
                    None,
                    digest('f'),
                ),
            ],
            runner_launches: vec![
                launch(
                    "session-worker",
                    RunnerSessionPurpose::TaskWorker,
                    Some("worker-1"),
                    digest('1'),
                ),
                launch(
                    "session-final",
                    RunnerSessionPurpose::FinalVerifier,
                    None,
                    digest('d'),
                ),
                launch(
                    "session-applier",
                    RunnerSessionPurpose::Applier,
                    None,
                    digest('f'),
                ),
            ],
            application_evidence: Some(application_evidence),
            verified_no_op_receipt: None,
            worker_cleanup_evidence: cleanups,
            rollback_reference: Some(rollback),
            unresolved_conflicts: 0,
            unknown_side_effects: 0,
            active_worker_leases: 0,
            released_worker_leases: vec![worker_lease.clone()],
            completion_receipt: Some(receipt),
            completion_receipt_persisted: true,
            final_report_id: Some("report-1".into()),
        };
        (sprint, graph, evidence)
    }

    #[allow(clippy::too_many_lines)] // One coherent fixture must bind every optional-task evidence edge.
    fn add_valid_optional_integration(
        sprint: &mut SprintSpec,
        graph: &mut TaskGraph,
        evidence: &mut CompletionEvidence,
    ) {
        sprint.acceptance_criteria[0].kind = AcceptanceKind::HumanJudgment;
        graph.tasks.push(TaskSpec {
            task_id: "task-2".into(),
            goal: "Integrate optional work".into(),
            dependencies: Vec::new(),
            path_scopes: vec![PathScope::Workspace],
            acceptance_checks: vec!["tests".into()],
            base_snapshot: sprint.base_snapshot.clone(),
            required: false,
        });
        let lease = WorkerLease::new(
            sprint.sprint_id.clone(),
            2,
            "task-2".into(),
            "worker-2".into(),
            vec![PathScope::Workspace],
            1,
        )
        .expect("canonical optional-task lease");
        let mut launch = evidence
            .runner_launches
            .iter()
            .find(|launch| launch.session_id == "session-worker")
            .expect("fixture worker launch")
            .clone();
        launch.launch_id = "launch-worker-2".into();
        launch.session_id = "session-worker-2".into();
        launch.worker_id = Some("worker-2".into());
        launch.worker_lease = Some(lease.clone());
        let mut session = evidence
            .runner_sessions
            .iter()
            .find(|session| session.session_id == "session-worker")
            .expect("fixture worker session")
            .clone();
        session.launch_id = launch.launch_id.clone();
        session.session_id = launch.session_id.clone();
        session.worker_id = launch.worker_id.clone();
        session.worker_lease = launch.worker_lease.clone();
        session.session_nonce = digest('6');

        let prior_final = evidence.final_snapshot.clone();
        let new_final = digest('e');
        let mut integration = evidence.task_integration_receipts[0].clone();
        // Ordinal order is intentionally the reverse of lexical receipt-ID
        // order: `integration-task-1` then `a-integration-task-2`.
        integration.receipt_id = "a-integration-task-2".into();
        integration.task_id = "task-2".into();
        integration.worker_id = "worker-2".into();
        integration.worker_lease = Some(lease.clone());
        integration.worker_launch_id = launch.launch_id.clone();
        integration.worker_session_id = session.session_id.clone();
        integration.effect_id = "integration-task-2-effect".into();
        integration.observation_id = "integration-task-2-observation".into();
        integration.change_set_id = "change-task-2".into();
        integration.input_snapshot = prior_final;
        integration.result_snapshot = new_final.clone();
        integration.task_verification_receipt_ids.clear();
        integration.integration_ordinal = 1;
        integration.integrated_at_unix_ms = 3;

        let mut cleanup = evidence
            .worker_cleanup_evidence
            .iter()
            .find(|cleanup| cleanup.receipt.session_id == "session-worker")
            .expect("fixture worker cleanup")
            .clone();
        cleanup.receipt.receipt_id = "cleanup-worker-2".into();
        cleanup.receipt.launch_id = launch.launch_id.clone();
        cleanup.receipt.effect_id = "cleanup-worker-2-effect".into();
        cleanup.receipt.observation_id = "cleanup-worker-2-observation".into();
        cleanup.receipt.session_id = session.session_id.clone();
        cleanup.receipt.worker_lease = Some(lease.clone());
        cleanup.os_evidence_bytes = b"authoritative cleanup evidence for session-worker-2".to_vec();
        cleanup.receipt.os_evidence_digest = Digest::sha256(&cleanup.os_evidence_bytes);

        evidence.final_snapshot = new_final.clone();
        evidence.criterion_evidence_receipts[0] = CriterionEvidenceReceiptV2::AcceptedByYou {
            receipt_id: "criterion-evidence-tests".into(),
            sprint_id: sprint.sprint_id.clone(),
            criterion_id: "tests".into(),
            snapshot_digest: new_final.clone(),
            human_decision_id: "human-decision-tests".into(),
            prompt_id: "human-prompt-tests".into(),
            backing: HumanAcceptanceBackingV1::OneToOne,
            recorded_at: 4,
        };
        evidence.human_acceptance_prompts = vec![HumanAcceptancePromptV1 {
            prompt_id: "human-prompt-tests".into(),
            ui_session_id: "ui-session-tests".into(),
            sprint_id: sprint.sprint_id.clone(),
            criterion_id: "tests".into(),
            criterion_text_digest: Digest::sha256(
                sprint.acceptance_criteria[0].description.as_bytes(),
            ),
            snapshot_digest: new_final.clone(),
            workspace_grant_hash: sprint.workspace_grant.grant_hash.clone(),
            rendered_claim_digest: Digest::sha256(b"rendered one-to-one tests claim"),
            backing: HumanAcceptanceBackingV1::OneToOne,
            issued_event_sequence: 1,
        }];
        evidence.human_acceptance_decisions = vec![HumanAcceptanceDecisionV1 {
            decision_id: "human-decision-tests".into(),
            prompt_id: "human-prompt-tests".into(),
            outcome: HumanAcceptanceDecisionOutcomeV1::AcceptedByYou,
            consumed_event_sequence: 1,
            decided_at: 3,
        }];
        evidence
            .final_verification
            .as_mut()
            .expect("fixture final verification")
            .snapshot_id = new_final.clone();
        evidence
            .verification_effect_evidence
            .iter_mut()
            .find(|effect| effect.verification.task_id.is_none())
            .expect("fixture final verification evidence")
            .verification
            .snapshot_id = new_final.clone();
        evidence
            .application_evidence
            .as_mut()
            .expect("fixture application evidence")
            .receipt
            .result_snapshot = new_final.clone();
        let completion = evidence
            .completion_receipt
            .as_mut()
            .expect("fixture completion receipt");
        completion.final_snapshot = new_final;
        completion
            .task_integration_receipt_ids
            .push(integration.receipt_id.clone());
        completion
            .worker_cleanup_receipt_ids
            .push(cleanup.receipt.receipt_id.clone());
        completion.worker_cleanup_receipt_ids.sort();

        evidence.task_integration_receipts.push(integration);
        evidence.runner_launches.push(launch);
        evidence.runner_sessions.push(session);
        evidence.worker_cleanup_evidence.push(cleanup);
        evidence.released_worker_leases.push(lease);
    }

    fn use_untrusted_verified_no_op_claim(evidence: &mut CompletionEvidence) {
        let base_snapshot = digest('b');
        evidence.final_snapshot = base_snapshot.clone();
        match &mut evidence.criterion_evidence_receipts[0] {
            CriterionEvidenceReceiptV2::Verified {
                snapshot_digest, ..
            }
            | CriterionEvidenceReceiptV2::AcceptedByYou {
                snapshot_digest, ..
            } => snapshot_digest.clone_from(&base_snapshot),
        }
        evidence.task_integration_receipts[0].result_snapshot = base_snapshot.clone();
        evidence
            .verification_effect_evidence
            .iter_mut()
            .for_each(|effect| effect.verification.snapshot_id = base_snapshot.clone());
        evidence
            .final_verification
            .as_mut()
            .expect("fixture final verification")
            .snapshot_id = base_snapshot.clone();
        evidence.application_evidence = None;
        evidence.rollback_reference = None;
        evidence.verified_no_op_receipt = Some(VerifiedNoOpReceipt {
            contract_version: crate::CONTRACT_VERSION,
            receipt_id: "verified-no-op-1".into(),
            sprint_id: "sprint-1".into(),
            final_verification_receipt_id: "verify-final".into(),
            base_snapshot: base_snapshot.clone(),
            live_manifest_digest: base_snapshot.clone(),
            grant_hash: digest('a'),
            policy_version: 1,
            observed_at_unix_ms: 6,
        });
        evidence
            .runner_launches
            .retain(|launch| launch.purpose != RunnerSessionPurpose::Applier);
        evidence
            .runner_sessions
            .retain(|session| session.purpose != RunnerSessionPurpose::Applier);
        evidence
            .worker_cleanup_evidence
            .retain(|cleanup| cleanup.receipt.session_id != "session-applier");
        let completion = evidence
            .completion_receipt
            .as_mut()
            .expect("fixture completion receipt");
        completion.final_snapshot = base_snapshot;
        completion.application = CompletionApplication::VerifiedNoOp {
            verified_no_op_receipt_id: "verified-no-op-1".into(),
        };
        completion
            .worker_cleanup_receipt_ids
            .retain(|receipt_id| receipt_id != "cleanup-applier");
    }

    fn use_application_recovery(
        evidence: &mut CompletionEvidence,
        recovery_cleaned_at_unix_ms: u64,
    ) {
        let mut recovery_session = evidence
            .runner_sessions
            .iter()
            .find(|session| session.session_id == "session-applier")
            .expect("fixture application executor session")
            .clone();
        recovery_session.launch_id = "launch-application-recovery".into();
        recovery_session.session_id = "session-application-recovery".into();
        recovery_session.session_nonce = digest('6');
        recovery_session.registered_at_unix_ms = 5;

        let mut recovery_launch = evidence
            .runner_launches
            .iter()
            .find(|launch| launch.launch_id == "launch-applier")
            .expect("fixture application executor launch")
            .clone();
        recovery_launch.launch_id = recovery_session.launch_id.clone();
        recovery_launch.session_id = recovery_session.session_id.clone();
        recovery_launch.created_at_unix_ms = 5;

        let mut recovery_cleanup = evidence
            .worker_cleanup_evidence
            .iter()
            .find(|cleanup| cleanup.receipt.session_id == "session-applier")
            .expect("fixture application executor cleanup")
            .clone();
        recovery_cleanup.receipt.receipt_id = "cleanup-application-recovery".into();
        recovery_cleanup.receipt.launch_id = recovery_launch.launch_id.clone();
        recovery_cleanup.receipt.session_id = recovery_session.session_id.clone();
        recovery_cleanup.receipt.effect_id = "cleanup-application-recovery-effect".into();
        recovery_cleanup.receipt.observation_id = "cleanup-application-recovery-observation".into();
        recovery_cleanup.receipt.cleaned_at_unix_ms = recovery_cleaned_at_unix_ms;
        recovery_cleanup.os_evidence_bytes =
            b"authoritative cleanup evidence for session-application-recovery".to_vec();
        recovery_cleanup.receipt.os_evidence_digest =
            Digest::sha256(&recovery_cleanup.os_evidence_bytes);

        let validation = &mut evidence
            .application_evidence
            .as_mut()
            .expect("fixture application evidence")
            .validation;
        validation.mode = ApplicationValidationMode::RecoveryApplierReconciliation;
        validation.runner_launch_id = recovery_launch.launch_id.clone();
        validation.runner_session_id = recovery_session.session_id.clone();
        validation.policy_hash = recovery_session.policy_hash.clone();
        validation.grant_hash = recovery_session.grant_hash.clone();
        validation.policy_version = recovery_session.policy_version;
        validation.private_state_digest = recovery_session.private_state_digest.clone();

        evidence.runner_sessions.push(recovery_session);
        evidence.runner_launches.push(recovery_launch);
        evidence.worker_cleanup_evidence.push(recovery_cleanup);
        let receipt = evidence
            .completion_receipt
            .as_mut()
            .expect("fixture completion receipt");
        receipt.worker_cleanup_receipt_ids = evidence
            .worker_cleanup_evidence
            .iter()
            .map(|cleanup| cleanup.receipt.receipt_id.clone())
            .collect();
        receipt.worker_cleanup_receipt_ids.sort();
    }

    #[test]
    fn complete_evidence_satisfies_every_requirement() {
        let (sprint, graph, evidence) = fixture();
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(assessment.is_complete());
        assert_eq!(
            assessment.application(),
            Some(CompletionApplicationAssessment::Applied)
        );
        assert!(assessment.unmet_requirements().is_empty());
    }

    #[test]
    fn advisory_accepts_valid_optional_integration_in_ordinal_not_lexical_order() {
        let (mut sprint, mut graph, mut evidence) = fixture();
        add_valid_optional_integration(&mut sprint, &mut graph, &mut evidence);
        let receipt = evidence
            .completion_receipt
            .as_ref()
            .expect("fixture completion receipt");
        assert_eq!(
            receipt.task_integration_receipt_ids,
            ["integration-task-1", "a-integration-task-2"]
        );
        assert!(receipt.validate().is_ok());
        assert!(task_integrations_are_complete(&sprint, &graph, &evidence));
        assert!(assess_completion(&sprint, &graph, &evidence).is_complete());

        let mut swapped = evidence;
        swapped
            .completion_receipt
            .as_mut()
            .expect("fixture completion receipt")
            .task_integration_receipt_ids
            .swap(0, 1);
        assert!(
            swapped
                .completion_receipt
                .as_ref()
                .expect("swapped completion receipt")
                .validate()
                .is_ok(),
            "the envelope checks identity uniqueness; ordinal authority checks order"
        );
        let assessment = assess_completion(&sprint, &graph, &swapped);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::CompletionReceiptConsistent)
        );
    }

    #[test]
    fn advisory_rejects_missing_required_unknown_duplicate_and_broken_optional_chains() {
        let (mut sprint, mut graph, mut evidence) = fixture();
        add_valid_optional_integration(&mut sprint, &mut graph, &mut evidence);
        assert!(task_integrations_are_complete(&sprint, &graph, &evidence));

        let mut missing_required = evidence.clone();
        missing_required
            .task_integration_receipts
            .retain(|receipt| receipt.task_id == "task-2");
        assert!(!task_integrations_are_complete(
            &sprint,
            &graph,
            &missing_required
        ));

        let mut unknown_graph_task = graph.clone();
        unknown_graph_task
            .tasks
            .retain(|task| task.task_id != "task-2");
        assert!(!task_integrations_are_complete(
            &sprint,
            &unknown_graph_task,
            &evidence
        ));

        let mut duplicate = evidence.clone();
        duplicate
            .task_integration_receipts
            .push(duplicate.task_integration_receipts[1].clone());
        assert!(!task_integrations_are_complete(&sprint, &graph, &duplicate));

        let mut broken_chain = evidence;
        broken_chain.task_integration_receipts[1].input_snapshot = sprint.base_snapshot.clone();
        assert!(!task_integrations_are_complete(
            &sprint,
            &graph,
            &broken_chain
        ));
    }

    #[test]
    fn caller_populated_no_op_manifest_is_explicitly_ineligible_without_capture_authority() {
        let (sprint, graph, mut evidence) = fixture();
        use_untrusted_verified_no_op_claim(&mut evidence);
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert_eq!(
            assessment.application(),
            Some(CompletionApplicationAssessment::VerifiedNoOp)
        );
        assert!(!assessment.is_complete());
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::VerifiedNoOpLiveManifestCaptureAuthorized)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotApplied)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::LiveHashesMatch)
        );
        assert_eq!(
            crate::SprintState::FinalVerification.complete(&assessment),
            Err(crate::StateTransitionError::CompletionIncomplete)
        );
        assert!(matches!(
            crate::SprintState::Applying.complete(&assessment),
            Err(crate::StateTransitionError::InvalidSprint { .. })
        ));
    }

    #[test]
    fn recovery_application_requires_both_validator_and_executor_cleanup_ordering() {
        let (sprint, graph, mut evidence) = fixture();
        use_application_recovery(&mut evidence, 8);
        assert!(assess_completion(&sprint, &graph, &evidence).is_complete());

        let (_, _, mut early_validator) = fixture();
        use_application_recovery(&mut early_validator, 6);
        let assessment = assess_completion(&sprint, &graph, &early_validator);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotApplied)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::RollbackAvailable)
        );

        let (_, _, mut early_executor) = fixture();
        use_application_recovery(&mut early_executor, 8);
        early_executor
            .worker_cleanup_evidence
            .iter_mut()
            .find(|cleanup| cleanup.receipt.session_id == "session-applier")
            .expect("fixture executor cleanup")
            .receipt
            .cleaned_at_unix_ms = 5;
        assert!(
            assess_completion(&sprint, &graph, &early_executor)
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotApplied)
        );

        let (_, _, mut after_completion) = fixture();
        use_application_recovery(&mut after_completion, 10);
        assert!(
            assess_completion(&sprint, &graph, &after_completion)
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotApplied)
        );
    }

    #[test]
    fn predicate_reports_all_independent_missing_evidence() {
        let (sprint, graph, mut evidence) = fixture();
        evidence.criterion_evidence_receipts.clear();
        evidence.task_integration_receipts.clear();
        evidence.final_verification = None;
        evidence.application_evidence = None;
        evidence.worker_cleanup_evidence.clear();
        evidence.rollback_reference = None;
        evidence.unresolved_conflicts = 1;
        evidence.unknown_side_effects = 1;
        evidence.active_worker_leases = 1;
        evidence.completion_receipt = None;
        evidence.completion_receipt_persisted = false;
        evidence.final_report_id = None;

        let assessment = assess_completion(&sprint, &graph, &evidence);
        let unmet: BTreeSet<_> = assessment.unmet_requirements().iter().copied().collect();
        assert_eq!(unmet.len(), 13);
        assert!(unmet.contains(&CompletionRequirement::AllCriteriaSatisfiedByTypedBacking));
        assert!(unmet.contains(&CompletionRequirement::AllRequiredTasksIntegrated));
        assert!(unmet.contains(&CompletionRequirement::FinalSnapshotVerified));
        assert!(unmet.contains(&CompletionRequirement::FinalSnapshotApplied));
        assert!(unmet.contains(&CompletionRequirement::LiveHashesMatch));
        assert!(unmet.contains(&CompletionRequirement::NoUnresolvedConflicts));
        assert!(unmet.contains(&CompletionRequirement::NoUnknownSideEffects));
        assert!(unmet.contains(&CompletionRequirement::NoSurvivingProcesses));
        assert!(unmet.contains(&CompletionRequirement::NoActiveWorkerLeases));
        assert!(unmet.contains(&CompletionRequirement::CompletionReceiptConsistent));
        assert!(unmet.contains(&CompletionRequirement::CompletionReceiptPersisted));
        assert!(unmet.contains(&CompletionRequirement::RollbackAvailable));
        assert!(unmet.contains(&CompletionRequirement::FinalReportAvailable));
    }

    #[test]
    fn failed_or_wrong_snapshot_verification_cannot_finish() {
        let (sprint, graph, mut evidence) = fixture();
        let verification = evidence
            .final_verification
            .as_mut()
            .expect("fixture receipt");
        verification.exit_status = Some(1);
        verification.termination = Some(CommandTerminationV1::Exited { code: 1 });
        assert!(
            assess_completion(&sprint, &graph, &evidence)
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotVerified)
        );

        let (_, _, mut evidence) = fixture();
        evidence
            .final_verification
            .as_mut()
            .expect("fixture receipt")
            .snapshot_id = digest('9');
        assert!(
            assess_completion(&sprint, &graph, &evidence)
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotVerified)
        );
    }

    #[test]
    fn duplicate_or_extra_evidence_is_not_completion() {
        let (sprint, graph, mut evidence) = fixture();
        evidence
            .criterion_evidence_receipts
            .push(evidence.criterion_evidence_receipts[0].clone());
        let duplicate_integration = evidence.task_integration_receipts[0].clone();
        evidence
            .task_integration_receipts
            .push(duplicate_integration);
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::AllCriteriaSatisfiedByTypedBacking)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::AllRequiredTasksIntegrated)
        );
    }

    #[test]
    fn receipt_rejects_unknown_integrations_and_unlinked_criterion_evidence() {
        let (sprint, graph, mut evidence) = fixture();
        evidence
            .completion_receipt
            .as_mut()
            .expect("fixture completion receipt")
            .task_integration_receipt_ids
            .push("unknown-integration".into());
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::CompletionReceiptConsistent)
        );

        let (_, _, mut evidence) = fixture();
        let CriterionEvidenceReceiptV2::Verified { receipt_id, .. } =
            &mut evidence.criterion_evidence_receipts[0]
        else {
            panic!("automated fixture must use machine-verified criterion evidence")
        };
        *receipt_id = "unlinked-criterion-evidence-receipt".into();
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(
            !assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::AllCriteriaSatisfiedByTypedBacking)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::CompletionReceiptConsistent)
        );
    }

    #[test]
    fn integration_identifier_alone_or_missing_task_worker_cannot_finish() {
        let (sprint, graph, mut evidence) = fixture();
        evidence.task_integration_receipts.clear();
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::AllRequiredTasksIntegrated)
        );
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::CompletionReceiptConsistent)
        );

        let (_, _, mut evidence) = fixture();
        evidence
            .runner_sessions
            .retain(|session| session.purpose != RunnerSessionPurpose::TaskWorker);
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert!(
            assessment
                .unmet_requirements()
                .contains(&CompletionRequirement::AllRequiredTasksIntegrated)
        );
    }

    #[test]
    fn retained_verification_output_is_required_authority() {
        let (sprint, graph, mut evidence) = fixture();
        evidence
            .verification_effect_evidence
            .iter_mut()
            .find(|effect| effect.verification.receipt_id == "verify-final")
            .expect("final verification evidence")
            .output_evidence_bytes
            .push(b'!');
        assert!(
            assess_completion(&sprint, &graph, &evidence)
                .unmet_requirements()
                .contains(&CompletionRequirement::FinalSnapshotVerified)
        );

        let (_, _, mut evidence) = fixture();
        evidence
            .verification_effect_evidence
            .iter_mut()
            .find(|effect| effect.verification.receipt_id == "verify-task-1")
            .expect("task verification evidence")
            .output_evidence_bytes
            .push(b'!');
        assert!(
            assess_completion(&sprint, &graph, &evidence)
                .unmet_requirements()
                .contains(&CompletionRequirement::AllRequiredTasksIntegrated)
        );
    }

    #[test]
    fn completed_state_requires_the_computed_assessment() {
        let (sprint, graph, evidence) = fixture();
        let assessment = assess_completion(&sprint, &graph, &evidence);
        assert_eq!(
            crate::SprintState::Applying.complete(&assessment),
            Ok(crate::SprintState::Completed)
        );
        assert!(matches!(
            crate::SprintState::FinalVerification.complete(&assessment),
            Err(crate::StateTransitionError::InvalidSprint { .. })
        ));
    }
}
