//! Recovery-safe transition engine for the macOS dedicated-identity helper.
//!
//! The signed helper performs privileged operating-system work, but it may do so
//! only after persisting the corresponding state returned here.  Initial calls
//! and restart calls are intentionally distinct: once an effect intent has been
//! persisted, recovery asks the host to reconcile that effect and never simply
//! invokes it again.

#![allow(dead_code)] // Activated with the signed Service Management helper.

use grok_build_core::Digest;

use crate::macos_helper_protocol::{
    MacosAssignedIdentity, MacosCleanupEvidence, MacosHeldPreparationEvidence,
    MacosHelperJournalRecord, MacosHelperJournalState, MacosHelperLaunchRequest,
    MacosHelperPreparationBinding, MacosHelperProtocolError, MacosHelperSession,
    MacosIdentityPoolObservation, MacosOuterReleaseAuthorization,
    MacosOuterReleaseAuthorizationRecord, MacosProcessObservation, MacosReleaseEvidence,
    MacosTerminationReason,
};

/// Host operation permitted immediately after the returned record is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacosPostPersistAction {
    /// No operating-system action remains.
    None,
    /// Install the fixed, request-bound cleanup agent exactly once.
    InstallCleanupAgent,
    /// Spawn the fixed launcher in its pre-exec hold exactly once.
    SpawnHeldLauncher,
    /// Seal process creation, terminate the identity domain, and enumerate it.
    SealTerminateAndObserve,
    /// Release the still-exclusive account reservation.
    ReleaseIdentityReservation,
}

/// Non-cloneable release-intent transition which retains core's live release
/// exclusion. It can only be consumed by the journal's synchronous
/// persist-and-release operation; recovery and generic persistence never
/// receive this type.
#[must_use = "live release authority must be consumed synchronously or dropped"]
pub(crate) struct MacosLiveReleaseTransition<'claim, 'ledger> {
    record: MacosHelperJournalRecord,
    authorization: MacosOuterReleaseAuthorization<'claim, 'ledger>,
}

impl<'claim, 'ledger> MacosLiveReleaseTransition<'claim, 'ledger> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        MacosHelperJournalRecord,
        MacosOuterReleaseAuthorization<'claim, 'ledger>,
    ) {
        (self.record, self.authorization)
    }
}

/// Ephemeral capability passed only to the synchronous native hold-control
/// callback after `ReleaseIntended` is durable and the deadline is rechecked.
/// A returned callback value cannot borrow this locally-owned permit.
pub(crate) struct MacosLiveReleasePermit<'authorization, 'claim, 'ledger> {
    authorization: &'authorization MacosOuterReleaseAuthorization<'claim, 'ledger>,
    release_started_at_unix_ms: u64,
}

impl<'authorization, 'claim, 'ledger> MacosLiveReleasePermit<'authorization, 'claim, 'ledger> {
    pub(crate) const fn new(
        authorization: &'authorization MacosOuterReleaseAuthorization<'claim, 'ledger>,
        release_started_at_unix_ms: u64,
    ) -> Self {
        Self {
            authorization,
            release_started_at_unix_ms,
        }
    }

    pub(crate) const fn authorization(&self) -> &MacosOuterReleaseAuthorizationRecord {
        self.authorization.record()
    }

    pub(crate) const fn release_started_at_unix_ms(&self) -> u64 {
        self.release_started_at_unix_ms
    }
}

/// Recovery work selected solely from one validated durable record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacosRecoveryAction {
    /// Persist the cleanup-agent intent; no host effect occurred yet.
    PersistCleanupAgentIntent,
    /// Inspect the fixed cleanup-agent label and exact request binding.
    ReconcileCleanupAgent,
    /// Inspect the UID domain and held-launch identity; never respawn blindly.
    ReconcileHeldLaunch,
    /// Reconcile core's persisted preparation outcome; helper state alone can
    /// never authorize release.
    ReconcileOuterPreparationOutcome,
    /// Determine whether the one attempted release occurred, remained held, or died.
    ReconcileHeldRelease,
    /// Persist recovery cleanup before signalling the identity domain.
    PersistRecoveryCleaning,
    /// Reissue idempotent termination while the account remains exclusively held.
    SealTerminateAndObserve,
    /// Reconcile reservation release without making the account available early.
    ReconcileIdentityRelease,
    /// The record is already terminal.
    None,
}

/// One validated journal transition and the only action it authorizes next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosLifecycleTransition {
    record: MacosHelperJournalRecord,
    post_persist_action: MacosPostPersistAction,
}

impl MacosLifecycleTransition {
    /// Returns the exact next record that must be synchronized first.
    pub(crate) const fn record(&self) -> &MacosHelperJournalRecord {
        &self.record
    }

    /// Returns the action authorized only after `record` is durable.
    pub(crate) const fn post_persist_action(&self) -> MacosPostPersistAction {
        self.post_persist_action
    }

    pub(crate) fn into_record(self) -> MacosHelperJournalRecord {
        self.record
    }
}

/// Constructs the first identity-bound record after two stable empty reads.
///
/// Account reservation and both observations are privileged helper operations.
/// The helper must retain its exclusive pool lease until this record is durable;
/// a persistence failure is recovery work, not permission to release/reassign.
pub(crate) fn prepare_identity_record(
    session: &MacosHelperSession,
    request: &MacosHelperLaunchRequest,
    expected_preparation: &MacosHelperPreparationBinding,
    pool: &MacosIdentityPoolObservation,
    assigned: MacosAssignedIdentity,
    observations: [MacosProcessObservation; 2],
    now_unix_ms: u64,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    request.validate_for_preparation(session, expected_preparation, now_unix_ms)?;
    pool.validate_for_session(session)?;
    let matching = pool.records.iter().any(|record| {
        record.account_name == assigned.account_name
            && record.uid == assigned.uid
            && record.gid == assigned.gid
            && record.record_digest == assigned.account_record_digest
    });
    if !matching {
        return Err(lifecycle_error(
            "lifecycle.assigned_identity",
            "assigned account is not an exact member of the authenticated pool",
        ));
    }
    if observations.iter().any(|observation| {
        observation.observed_at_unix_ms < session.authenticated_at_unix_ms
            || observation.observed_at_unix_ms > now_unix_ms
    }) {
        return Err(lifecycle_error(
            "lifecycle.observations",
            "identity observations must fall within the authenticated session interval",
        ));
    }
    let record = MacosHelperJournalRecord {
        state: MacosHelperJournalState::Prepared,
        admission_session: session.clone(),
        request: request.clone(),
        assigned_identity: Some(assigned),
        cleanup_agent_digest: None,
        held_preparation_evidence: None,
        release_authorization: None,
        release_evidence: None,
        termination_reason: None,
        observations: observations.into(),
        identity_released: false,
    };
    checked_transition(record, MacosPostPersistAction::None)
}

/// Persists intent before cleanup-agent installation can begin.
pub(crate) fn intend_cleanup_agent(
    current: &MacosHelperJournalRecord,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::Prepared)?;
    transition_record(
        current,
        MacosHelperJournalState::CleanupAgentIntended,
        |_: &mut MacosHelperJournalRecord| {},
        MacosPostPersistAction::InstallCleanupAgent,
    )
}

/// Records a reconciled, exact cleanup-agent installation and persists launch intent.
pub(crate) fn record_cleanup_agent(
    current: &MacosHelperJournalRecord,
    cleanup_agent_digest: Digest,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::CleanupAgentIntended)?;
    transition_record(
        current,
        MacosHelperJournalState::LaunchIntended,
        |record| record.cleanup_agent_digest = Some(cleanup_agent_digest),
        MacosPostPersistAction::SpawnHeldLauncher,
    )
}

/// Re-authorizes cleanup-agent installation only after reconciliation proved
/// that the prior intended installation never created its fixed label.
///
/// The durable record does not change: it already contains the exact intent.
/// Callers must not use this path for an I/O error, an identity mismatch, or an
/// unknown observation.
pub(crate) fn cleanup_agent_retry_after_proven_absent(
    current: &MacosHelperJournalRecord,
) -> Result<MacosPostPersistAction, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::CleanupAgentIntended)?;
    Ok(MacosPostPersistAction::InstallCleanupAgent)
}

/// Records exact held-launch evidence before the launcher may be released.
pub(crate) fn record_held_launcher(
    current: &MacosHelperJournalRecord,
    session: &MacosHelperSession,
    evidence: MacosHeldPreparationEvidence,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::LaunchIntended)?;
    evidence.validate_for(
        session,
        &current.request,
        current.assigned_identity.as_ref().ok_or_else(|| {
            lifecycle_error(
                "lifecycle.assigned_identity",
                "held preparation requires an assigned identity",
            )
        })?,
    )?;
    transition_record(
        current,
        MacosHelperJournalState::HeldPrepared,
        |record| record.held_preparation_evidence = Some(evidence),
        MacosPostPersistAction::None,
    )
}

/// Persists the only release intent before the held-control operation may run.
pub(crate) fn intend_launcher_release<'claim, 'ledger>(
    current: &MacosHelperJournalRecord,
    authorization: MacosOuterReleaseAuthorization<'claim, 'ledger>,
) -> Result<MacosLiveReleaseTransition<'claim, 'ledger>, MacosHelperProtocolError> {
    let transition = release_intent_transition(current, authorization.record().clone())?;
    Ok(MacosLiveReleaseTransition {
        record: transition.into_record(),
        authorization,
    })
}

#[cfg(test)]
pub(crate) fn intend_launcher_release_for_test(
    current: &MacosHelperJournalRecord,
    authorization: MacosOuterReleaseAuthorizationRecord,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    release_intent_transition(current, authorization)
}

/// Reconstructs an already-durable successor without returning release
/// authority. Used only by append-only journal validation.
pub(crate) fn reconstruct_launcher_release_intent(
    current: &MacosHelperJournalRecord,
    authorization: MacosOuterReleaseAuthorizationRecord,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    release_intent_transition(current, authorization)
}

fn release_intent_transition(
    current: &MacosHelperJournalRecord,
    authorization: MacosOuterReleaseAuthorizationRecord,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::HeldPrepared)?;
    authorization.validate_for(
        &current.request,
        current.held_preparation_evidence.as_ref().ok_or_else(|| {
            lifecycle_error(
                "lifecycle.held_preparation_evidence",
                "outer release authorization requires held evidence",
            )
        })?,
    )?;
    transition_record(
        current,
        MacosHelperJournalState::ReleaseIntended,
        |record| record.release_authorization = Some(authorization),
        MacosPostPersistAction::None,
    )
}

/// Records positive proof that the authenticated held launcher was released.
pub(crate) fn record_launcher_released(
    current: &MacosHelperJournalRecord,
    session: &MacosHelperSession,
    evidence: MacosReleaseEvidence,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::ReleaseIntended)?;
    evidence.validate_for(
        session,
        &current.request,
        current.held_preparation_evidence.as_ref().ok_or_else(|| {
            lifecycle_error(
                "lifecycle.held_preparation_evidence",
                "release requires exact held-preparation evidence",
            )
        })?,
    )?;
    transition_record(
        current,
        MacosHelperJournalState::Released,
        |record| record.release_evidence = Some(evidence),
        MacosPostPersistAction::None,
    )
}

/// Persists irreversible cleanup intent before any signal or creation seal.
pub(crate) fn begin_cleaning(
    current: &MacosHelperJournalRecord,
    reason: MacosTerminationReason,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    if !matches!(
        current.state,
        MacosHelperJournalState::LaunchIntended
            | MacosHelperJournalState::HeldPrepared
            | MacosHelperJournalState::ReleaseIntended
            | MacosHelperJournalState::Released
    ) {
        return Err(lifecycle_error(
            "lifecycle.state",
            "cleanup can begin only after the cleanup agent is durably installed",
        ));
    }
    transition_record(
        current,
        MacosHelperJournalState::Cleaning,
        |record| record.termination_reason = Some(reason),
        MacosPostPersistAction::SealTerminateAndObserve,
    )
}

/// Records two consecutive, creation-sealed empty observations.
pub(crate) fn record_empty_domain(
    current: &MacosHelperJournalRecord,
    observations: [MacosProcessObservation; 2],
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::Cleaning)?;
    transition_record(
        current,
        MacosHelperJournalState::EmptyProven,
        |record| record.observations.extend(observations),
        MacosPostPersistAction::ReleaseIdentityReservation,
    )
}

/// Records positive proof that the account reservation was released.
pub(crate) fn record_identity_released(
    current: &MacosHelperJournalRecord,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    require_state(current, MacosHelperJournalState::EmptyProven)?;
    transition_record(
        current,
        MacosHelperJournalState::Cleaned,
        |record| record.identity_released = true,
        MacosPostPersistAction::None,
    )
}

/// Builds final cleanup evidence only from the validated `Cleaned` record.
pub(crate) fn cleanup_evidence(
    record: MacosHelperJournalRecord,
) -> Result<MacosCleanupEvidence, MacosHelperProtocolError> {
    record.validate()?;
    let assigned = record.assigned_identity.clone().ok_or_else(|| {
        lifecycle_error(
            "lifecycle.assigned_identity",
            "cleaned record has no assigned identity",
        )
    })?;
    let evidence = MacosCleanupEvidence {
        request_digest: record.request_digest().clone(),
        journal_record: record,
        assigned_identity: assigned,
        surviving_processes: 0,
        stable_empty_observations: 2,
    };
    evidence.validate()?;
    Ok(evidence)
}

/// Selects restart behavior without granting replay authority.
pub(crate) fn recovery_action(
    record: &MacosHelperJournalRecord,
    session: &MacosHelperSession,
) -> Result<MacosRecoveryAction, MacosHelperProtocolError> {
    record.validate_for_session(session)?;
    Ok(match record.state {
        MacosHelperJournalState::Prepared => MacosRecoveryAction::PersistCleanupAgentIntent,
        MacosHelperJournalState::CleanupAgentIntended => MacosRecoveryAction::ReconcileCleanupAgent,
        MacosHelperJournalState::LaunchIntended => MacosRecoveryAction::ReconcileHeldLaunch,
        MacosHelperJournalState::HeldPrepared => {
            MacosRecoveryAction::ReconcileOuterPreparationOutcome
        }
        MacosHelperJournalState::ReleaseIntended => MacosRecoveryAction::ReconcileHeldRelease,
        MacosHelperJournalState::Released => MacosRecoveryAction::PersistRecoveryCleaning,
        MacosHelperJournalState::Cleaning => MacosRecoveryAction::SealTerminateAndObserve,
        MacosHelperJournalState::EmptyProven => MacosRecoveryAction::ReconcileIdentityRelease,
        MacosHelperJournalState::Cleaned | MacosHelperJournalState::RejectedBeforeEffect => {
            MacosRecoveryAction::None
        }
    })
}

fn transition_record<F>(
    current: &MacosHelperJournalRecord,
    next_state: MacosHelperJournalState,
    update: F,
    action: MacosPostPersistAction,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError>
where
    F: FnOnce(&mut MacosHelperJournalRecord),
{
    current.validate()?;
    if !current.state.allows_transition_to(next_state) {
        return Err(lifecycle_error(
            "lifecycle.transition",
            "durable state transition skips a required intent or proof",
        ));
    }
    let mut next = current.clone();
    next.state = next_state;
    update(&mut next);
    checked_transition(next, action)
}

fn checked_transition(
    record: MacosHelperJournalRecord,
    action: MacosPostPersistAction,
) -> Result<MacosLifecycleTransition, MacosHelperProtocolError> {
    record.validate()?;
    Ok(MacosLifecycleTransition {
        record,
        post_persist_action: action,
    })
}

fn require_state(
    record: &MacosHelperJournalRecord,
    expected: MacosHelperJournalState,
) -> Result<(), MacosHelperProtocolError> {
    record.validate()?;
    if record.state != expected {
        return Err(lifecycle_error(
            "lifecycle.state",
            "record is not in the required exact state",
        ));
    }
    Ok(())
}

fn lifecycle_error(field: &'static str, reason: &'static str) -> MacosHelperProtocolError {
    MacosHelperProtocolError::Invalid { field, reason }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::macos_helper_protocol::{
        MACOS_HELPER_PROTOCOL_VERSION, MacosChildDescriptorBinding, MacosChildDescriptorPurpose,
        MacosExecutableIdentity, MacosExecutionIdentityRecord, MacosHelperAttestation,
        MacosHelperInstallAudit, MacosHelperNetwork,
    };
    use grok_build_core::{
        CONTRACT_VERSION, PersistedRunnerLaunchPreparation, RunnerLaunchPreparationAttempt,
        RunnerLaunchPreparationDisposition, RunnerLaunchPreparationOutcome,
    };

    fn digest(value: u8) -> Digest {
        Digest::sha256(&[value])
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

    fn preparation() -> MacosHelperPreparationBinding {
        MacosHelperPreparationBinding {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-1".into(),
            sprint_id: "sprint-1".into(),
            launch_id: "launch-1".into(),
            runner_session_id: "runner-1".into(),
            cleanup_effect_id: "cleanup-effect-1".into(),
            input_snapshot: digest(19),
            native_journal_id: "native-journal-1".into(),
            expected_platform_binding_digest: digest(20),
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

    fn session_and_request() -> (MacosHelperSession, MacosHelperLaunchRequest) {
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().unwrap();
        let session = MacosHelperSession {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 1,
            session_nonce: digest(1),
            helper_binary_digest: digest(2),
            helper_requirement_digest: digest(3),
            client_binary_digest: digest(4),
            client_requirement_digest: digest(5),
            pool_record_digest: pool.pool_record_digest,
            workspace_grant_hash: digest(6),
            execution_policy_hash: digest(7),
            command_network: MacosHelperNetwork::Denied,
            authenticated_at_unix_ms: 10,
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
        let mut request = MacosHelperLaunchRequest {
            protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
            policy_version: 1,
            session_nonce: session.session_nonce.clone(),
            request_id: "request-1".into(),
            preparation: preparation(),
            runner_session_id: "runner-1".into(),
            effect_id: "effect-1".into(),
            workspace_grant_hash: session.workspace_grant_hash.clone(),
            execution_policy_hash: session.execution_policy_hash.clone(),
            staged_workspace_id: "shadow-1".into(),
            executable_identity: MacosExecutableIdentity::SystemToolchain {
                policy_entry_id: "cargo-1.97.0".into(),
                binary_digest: digest(8),
            },
            descriptor_bindings: descriptors(),
            argv: vec!["cargo".into(), "test".into()],
            relative_working_directory: ".".into(),
            environment: BTreeMap::new(),
            deadline_unix_ms: 1_000,
            max_output_bytes: 1_024,
            max_processes: 8,
            max_memory_bytes: None,
            command_network: MacosHelperNetwork::Denied,
            seatbelt_profile_digest: digest(9),
            request_digest: digest(0),
        };
        request.request_digest = request.computed_digest().unwrap();
        (session, request)
    }

    fn held_evidence(
        session: &MacosHelperSession,
        record: &MacosHelperJournalRecord,
        held_at_unix_ms: u64,
    ) -> MacosHeldPreparationEvidence {
        let mut evidence = MacosHeldPreparationEvidence {
            authenticated_session: session.clone(),
            request_digest: record.request.request_digest.clone(),
            preparation: record.request.preparation.clone(),
            assigned_identity: record.assigned_identity.clone().unwrap(),
            descriptor_bindings_digest:
                super::super::macos_helper_protocol::descriptor_bindings_digest(
                    &record.request.descriptor_bindings,
                )
                .unwrap(),
            setup_readback_digest: digest(40),
            held_at_unix_ms,
            evidence_digest: digest(0),
        };
        evidence.evidence_digest = evidence.computed_digest().unwrap();
        evidence
    }

    fn release_evidence(
        session: &MacosHelperSession,
        record: &MacosHelperJournalRecord,
        released_at_unix_ms: u64,
    ) -> MacosReleaseEvidence {
        let held = record.held_preparation_evidence.as_ref().unwrap();
        let mut evidence = MacosReleaseEvidence {
            authenticated_session: session.clone(),
            request_digest: record.request.request_digest.clone(),
            preparation: record.request.preparation.clone(),
            held_preparation_evidence_digest: held.evidence_digest.clone(),
            release_observation_digest: digest(41),
            released_at_unix_ms,
            evidence_digest: digest(0),
        };
        evidence.evidence_digest = evidence.computed_digest().unwrap();
        evidence
    }

    fn release_authorization(
        record: &MacosHelperJournalRecord,
    ) -> MacosOuterReleaseAuthorizationRecord {
        let expected = &record.request.preparation;
        let held = record.held_preparation_evidence.as_ref().unwrap();
        let native_evidence_bytes = held.canonical_native_evidence_bytes().unwrap();
        let persisted = PersistedRunnerLaunchPreparation {
            attempt: RunnerLaunchPreparationAttempt {
                contract_version: expected.contract_version,
                attempt_id: expected.attempt_id.clone(),
                sprint_id: expected.sprint_id.clone(),
                launch_id: expected.launch_id.clone(),
                cleanup_effect_id: expected.cleanup_effect_id.clone(),
                native_journal_id: expected.native_journal_id.clone(),
                expected_platform_binding_digest: expected.expected_platform_binding_digest.clone(),
                claimed_at_unix_ms: expected.claimed_at_unix_ms,
            },
            outcome: Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes,
                finished_at_unix_ms: held.held_at_unix_ms + 1,
            }),
        };
        MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
            &persisted,
            expected,
            &record.request,
            held,
            record.assigned_identity.as_ref().unwrap(),
        )
        .unwrap()
    }

    fn observation(sequence: u32, time: u64, uid: u32, sealed: bool) -> MacosProcessObservation {
        let mut value = MacosProcessObservation {
            sequence,
            observed_at_unix_ms: time,
            uid,
            process_ids: Vec::new(),
            enumeration_digest: digest(0),
            creation_sealed: sealed,
        };
        value.enumeration_digest = value.computed_digest().unwrap();
        value
    }

    fn prepared() -> MacosHelperJournalRecord {
        let (session, request) = session_and_request();
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().unwrap();
        let assigned = MacosAssignedIdentity {
            account_name: "_grokbuild601".into(),
            uid: 601,
            gid: 601,
            account_record_digest: identity(601).record_digest,
        };
        prepare_identity_record(
            &session,
            &request,
            &request.preparation,
            &pool,
            assigned,
            [
                observation(1, 20, 601, false),
                observation(2, 21, 601, false),
            ],
            22,
        )
        .unwrap()
        .into_record()
    }

    #[test]
    fn happy_lifecycle_persists_every_intent_before_effect() {
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap();
        assert_eq!(
            cleanup_intent.post_persist_action(),
            MacosPostPersistAction::InstallCleanupAgent
        );
        let launch_intent = record_cleanup_agent(cleanup_intent.record(), digest(10)).unwrap();
        assert_eq!(
            launch_intent.post_persist_action(),
            MacosPostPersistAction::SpawnHeldLauncher
        );
        let (session, _) = session_and_request();
        let held = record_held_launcher(
            launch_intent.record(),
            &session,
            held_evidence(&session, launch_intent.record(), 23),
        )
        .unwrap();
        assert_eq!(held.post_persist_action(), MacosPostPersistAction::None);
        let authorization = release_authorization(held.record());
        let release_intent =
            intend_launcher_release_for_test(held.record(), authorization).unwrap();
        assert_eq!(
            release_intent.post_persist_action(),
            MacosPostPersistAction::None
        );
        let released = record_launcher_released(
            release_intent.record(),
            &session,
            release_evidence(&session, release_intent.record(), 24),
        )
        .unwrap();
        let cleaning = begin_cleaning(released.record(), MacosTerminationReason::Exited).unwrap();
        let empty = record_empty_domain(
            cleaning.record(),
            [observation(3, 30, 601, true), observation(4, 31, 601, true)],
        )
        .unwrap();
        assert_eq!(
            empty.post_persist_action(),
            MacosPostPersistAction::ReleaseIdentityReservation
        );
        let cleaned = record_identity_released(empty.record()).unwrap();
        cleanup_evidence(cleaned.into_record()).unwrap();
    }

    #[test]
    fn restart_never_blindly_replays_install_or_launch() {
        let prepared = prepared();
        assert_eq!(
            recovery_action(&prepared, &session_and_request().0).unwrap(),
            MacosRecoveryAction::PersistCleanupAgentIntent
        );
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        assert_eq!(
            recovery_action(&cleanup_intent, &session_and_request().0).unwrap(),
            MacosRecoveryAction::ReconcileCleanupAgent
        );
        assert_eq!(
            cleanup_agent_retry_after_proven_absent(&cleanup_intent).unwrap(),
            MacosPostPersistAction::InstallCleanupAgent
        );
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        assert_eq!(
            recovery_action(&launch_intent, &session_and_request().0).unwrap(),
            MacosRecoveryAction::ReconcileHeldLaunch
        );
        let (session, _) = session_and_request();
        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();
        assert_eq!(
            recovery_action(&held, &session).unwrap(),
            MacosRecoveryAction::ReconcileOuterPreparationOutcome
        );
        let authorization = release_authorization(&held);
        let release_intent = intend_launcher_release_for_test(&held, authorization)
            .unwrap()
            .into_record();
        assert_eq!(
            recovery_action(&release_intent, &session).unwrap(),
            MacosRecoveryAction::ReconcileHeldRelease
        );
    }

    #[test]
    fn unsealed_or_noncontiguous_empty_proof_is_rejected() {
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        let cleaning = begin_cleaning(&launch_intent, MacosTerminationReason::SetupFailed)
            .unwrap()
            .into_record();
        assert!(
            record_empty_domain(
                &cleaning,
                [
                    observation(3, 30, 601, true),
                    observation(4, 31, 601, false)
                ]
            )
            .is_err()
        );
        assert!(
            record_empty_domain(
                &cleaning,
                [observation(4, 30, 601, true), observation(5, 31, 601, true)]
            )
            .is_err()
        );
        assert!(
            record_empty_domain(
                &cleaning,
                [observation(3, 5, 601, true), observation(4, 6, 601, true)]
            )
            .is_err()
        );
    }

    #[test]
    fn release_is_one_shot_and_cleanup_first_permanently_refuses_it() {
        let (session, _) = session_and_request();
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();

        let cleaning = begin_cleaning(&held, MacosTerminationReason::Canceled)
            .unwrap()
            .into_record();
        assert!(
            intend_launcher_release_for_test(&cleaning, release_authorization(&cleaning)).is_err()
        );

        let release_intent = intend_launcher_release_for_test(&held, release_authorization(&held))
            .unwrap()
            .into_record();
        assert!(
            intend_launcher_release_for_test(
                &release_intent,
                release_authorization(&release_intent)
            )
            .is_err()
        );
        let release = release_evidence(&session, &release_intent, 24);
        let released = record_launcher_released(&release_intent, &session, release)
            .unwrap()
            .into_record();
        assert!(
            record_launcher_released(
                &released,
                &session,
                release_evidence(&session, &release_intent, 25)
            )
            .is_err()
        );
    }

    #[test]
    fn release_authorization_and_evidence_refuse_the_deadline_boundary() {
        let (session, _) = session_and_request();
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();

        let mut at_deadline = release_authorization(&held);
        at_deadline.authorized_at_unix_ms = held.request.deadline_unix_ms;
        assert!(intend_launcher_release_for_test(&held, at_deadline).is_err());

        let mut just_before = release_authorization(&held);
        just_before.authorized_at_unix_ms = held.request.deadline_unix_ms - 1;
        let release_intent = intend_launcher_release_for_test(&held, just_before)
            .unwrap()
            .into_record();
        assert!(
            record_launcher_released(
                &release_intent,
                &session,
                release_evidence(&session, &release_intent, held.request.deadline_unix_ms),
            )
            .is_err()
        );
        record_launcher_released(
            &release_intent,
            &session,
            release_evidence(&session, &release_intent, held.request.deadline_unix_ms - 1),
        )
        .unwrap();
    }

    #[test]
    fn helper_or_outer_binding_substitution_cannot_create_held_or_release_state() {
        let (session, _) = session_and_request();
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();

        let mut wrong_helper = held_evidence(&session, &launch_intent, 23);
        wrong_helper.authenticated_session.helper_binary_digest = digest(99);
        wrong_helper.evidence_digest = wrong_helper.computed_digest().unwrap();
        assert!(record_held_launcher(&launch_intent, &session, wrong_helper).is_err());

        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();
        let release_intent = intend_launcher_release_for_test(&held, release_authorization(&held))
            .unwrap()
            .into_record();
        let mut substituted = release_evidence(&session, &release_intent, 24);
        substituted.preparation.native_journal_id = "native-journal-substituted".into();
        substituted.evidence_digest = substituted.computed_digest().unwrap();
        assert!(record_launcher_released(&release_intent, &session, substituted).is_err());
    }

    #[test]
    fn release_reconciliation_accepts_only_fresh_equivalent_signed_authority() {
        let (session, _) = session_and_request();
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();
        let release_intent = intend_launcher_release_for_test(&held, release_authorization(&held))
            .unwrap()
            .into_record();

        let mut renewed = session.clone();
        renewed.session_nonce = digest(70);
        renewed.authenticated_at_unix_ms = 24;
        record_launcher_released(
            &release_intent,
            &renewed,
            release_evidence(&renewed, &release_intent, 25),
        )
        .unwrap();

        let mut drifted = renewed;
        drifted.client_requirement_digest = digest(71);
        assert!(
            record_launcher_released(
                &release_intent,
                &drifted,
                release_evidence(&drifted, &release_intent, 26)
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial table keeps every non-authorizing core outcome and substitution adjacent"
    )]
    fn absent_refused_ambiguous_or_substituted_core_outcome_never_authorizes_release() {
        let (session, _) = session_and_request();
        let prepared = prepared();
        let cleanup_intent = intend_cleanup_agent(&prepared).unwrap().into_record();
        let launch_intent = record_cleanup_agent(&cleanup_intent, digest(10))
            .unwrap()
            .into_record();
        let held = record_held_launcher(
            &launch_intent,
            &session,
            held_evidence(&session, &launch_intent, 23),
        )
        .unwrap()
        .into_record();
        let expected = &held.request.preparation;
        let held_evidence = held.held_preparation_evidence.as_ref().unwrap();
        let attempt = RunnerLaunchPreparationAttempt {
            contract_version: expected.contract_version,
            attempt_id: expected.attempt_id.clone(),
            sprint_id: expected.sprint_id.clone(),
            launch_id: expected.launch_id.clone(),
            cleanup_effect_id: expected.cleanup_effect_id.clone(),
            native_journal_id: expected.native_journal_id.clone(),
            expected_platform_binding_digest: expected.expected_platform_binding_digest.clone(),
            claimed_at_unix_ms: expected.claimed_at_unix_ms,
        };
        let exact_bytes = held_evidence.canonical_native_evidence_bytes().unwrap();
        let assigned = held.assigned_identity.as_ref().unwrap();

        let absent = PersistedRunnerLaunchPreparation {
            attempt: attempt.clone(),
            outcome: None,
        };
        assert!(
            MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
                &absent,
                expected,
                &held.request,
                held_evidence,
                assigned
            )
            .is_err()
        );

        for disposition in [
            RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
            RunnerLaunchPreparationDisposition::NativeEffectUncertain,
        ] {
            let closed = PersistedRunnerLaunchPreparation {
                attempt: attempt.clone(),
                outcome: Some(RunnerLaunchPreparationOutcome {
                    disposition,
                    native_evidence_bytes: exact_bytes.clone(),
                    finished_at_unix_ms: 24,
                }),
            };
            assert!(
                MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
                    &closed,
                    expected,
                    &held.request,
                    held_evidence,
                    assigned
                )
                .is_err()
            );
        }

        let substituted = PersistedRunnerLaunchPreparation {
            attempt,
            outcome: Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: b"substituted-held-evidence".to_vec(),
                finished_at_unix_ms: 24,
            }),
        };
        assert!(
            MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
                &substituted,
                expected,
                &held.request,
                held_evidence,
                assigned
            )
            .is_err()
        );

        let mut wrong_snapshot = expected.clone();
        wrong_snapshot.input_snapshot = digest(99);
        let valid = PersistedRunnerLaunchPreparation {
            attempt: RunnerLaunchPreparationAttempt {
                contract_version: expected.contract_version,
                attempt_id: expected.attempt_id.clone(),
                sprint_id: expected.sprint_id.clone(),
                launch_id: expected.launch_id.clone(),
                cleanup_effect_id: expected.cleanup_effect_id.clone(),
                native_journal_id: expected.native_journal_id.clone(),
                expected_platform_binding_digest: expected.expected_platform_binding_digest.clone(),
                claimed_at_unix_ms: expected.claimed_at_unix_ms,
            },
            outcome: Some(RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: exact_bytes,
                finished_at_unix_ms: 24,
            }),
        };
        assert!(
            MacosOuterReleaseAuthorizationRecord::try_from_persisted_for_test(
                &valid,
                &wrong_snapshot,
                &held.request,
                held_evidence,
                assigned
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_pool_identity_and_skipped_states_fail_closed() {
        let (session, request) = session_and_request();
        let mut pool = MacosIdentityPoolObservation {
            records: vec![identity(601), identity(602), identity(603)],
            pool_record_digest: digest(0),
        };
        pool.pool_record_digest = pool.computed_digest().unwrap();
        let wrong = MacosAssignedIdentity {
            account_name: "_grokbuild999".into(),
            uid: 999,
            gid: 999,
            account_record_digest: digest(99),
        };
        assert!(
            prepare_identity_record(
                &session,
                &request,
                &request.preparation,
                &pool,
                wrong,
                [
                    observation(1, 20, 999, false),
                    observation(2, 21, 999, false)
                ],
                22,
            )
            .is_err()
        );
        let (session, _) = session_and_request();
        let prepared = prepared();
        assert!(
            record_held_launcher(&prepared, &session, held_evidence(&session, &prepared, 23))
                .is_err()
        );
    }
}
