//! Durable launch registration and recovery transitions.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PreparedWorkerStage {
    pub(super) change_set: ChangeSet,
    pub(super) expected_bundle: StageBundleReference,
}

pub(super) enum RunnerLaunchLedger<'a> {
    Ordinary(&'a mut EventLedger),
    PostCompletionRollback {
        ledger: &'a mut EventLedger,
        operation_id: &'a str,
        role: PostCompletionRollbackApplierRole,
    },
}

pub(super) enum DurableRunnerLaunch {
    Ordinary {
        admission: Box<PersistedRunnerLaunchCleanupAdmission>,
        platform_binding: Box<PlatformLaunchBinding>,
    },
    PostCompletionRollback,
}

pub(super) struct RunnerLaunchPersistenceFailure {
    pub(super) error: RunnerClientError,
    pub(super) cleanup_admission: Option<Box<PersistedRunnerLaunchCleanupAdmission>>,
}

pub(super) fn durable_integration_head(
    persisted: &PersistedSprint,
) -> Result<Digest, RunnerClientError> {
    let mut integrations = persisted
        .effects
        .iter()
        .filter_map(|effect| match &effect.finish_receipt {
            PersistedFinishReceipt::TaskIntegration(receipt) => Some(receipt),
            _ => None,
        })
        .collect::<Vec<_>>();
    integrations.sort_by_key(|receipt| receipt.integration_ordinal);
    let mut head = persisted.spec.base_snapshot.clone();
    for (expected_ordinal, receipt) in integrations.iter().enumerate() {
        receipt
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        let expected_ordinal = u32::try_from(expected_ordinal).map_err(|_| {
            RunnerClientError::InvalidLifecycle(
                "durable integration count exceeds the canonical u32 ordinal".into(),
            )
        })?;
        if receipt.sprint_id != persisted.spec.sprint_id
            || receipt.integration_ordinal != expected_ordinal
            || receipt.input_snapshot != head
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "durable task-integration receipts are not one exact contiguous snapshot chain"
                    .into(),
            ));
        }
        head = receipt.result_snapshot.clone();
    }
    Ok(head)
}

pub(super) fn durable_role_input_snapshot(
    persisted: &PersistedSprint,
    role: RunnerRole,
) -> Result<Digest, RunnerClientError> {
    match role {
        RunnerRole::Worker | RunnerRole::FinalVerifier => durable_integration_head(persisted),
        RunnerRole::Applier => Ok(persisted.spec.base_snapshot.clone()),
        RunnerRole::LiveStateVerifier => Err(RunnerClientError::InvalidLifecycle(
            "live-state verifier input must come from one exact core-derived finalization plan"
                .into(),
        )),
    }
}

pub(super) fn ordinary_role_input_authority(
    role: RunnerRole,
) -> Result<RunnerRoleInputAuthority, RunnerClientError> {
    match role {
        RunnerRole::Worker | RunnerRole::FinalVerifier => {
            Ok(RunnerRoleInputAuthority::IntegrationHead)
        }
        RunnerRole::Applier => Ok(RunnerRoleInputAuthority::PlanningBase),
        RunnerRole::LiveStateVerifier => Err(RunnerClientError::InvalidLifecycle(
            "live-state verifier launch requires explicit finalization-plan authority".into(),
        )),
    }
}

pub(super) fn validate_durable_role_input(
    ledger: &EventLedger,
    persisted: &PersistedSprint,
    request: &RunnerClientLaunch,
) -> Result<(), RunnerClientError> {
    let expected_role_input = durable_role_input_snapshot(persisted, request.role)?;
    if request.expected_base_snapshot != expected_role_input {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner role input snapshot differs from the exact durable integration head or application base"
                .into(),
        ));
    }
    validate_durable_snapshot_authority(ledger, persisted, request)
}

pub(super) fn validate_durable_snapshot_authority(
    ledger: &EventLedger,
    persisted: &PersistedSprint,
    request: &RunnerClientLaunch,
) -> Result<(), RunnerClientError> {
    let snapshot = ledger
        .load_workspace_snapshot(&persisted.spec.sprint_id, &request.expected_base_snapshot)?;
    if snapshot.snapshot_id != request.expected_base_snapshot
        || snapshot.grant_hash != persisted.spec.workspace_grant.grant_hash
        || snapshot.created_at_unix_ms > request.created_at_unix_ms
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner role input snapshot differs from its durable sprint/grant authority or postdates launch intent"
                .into(),
        ));
    }
    Ok(())
}

impl RunnerLaunchLedger<'_> {
    pub(super) const fn post_completion_role(&self) -> Option<PostCompletionRollbackApplierRole> {
        match self {
            Self::Ordinary(_) => None,
            Self::PostCompletionRollback { role, .. } => Some(*role),
        }
    }

    pub(super) fn post_completion_operation_id(&self) -> Option<&str> {
        match self {
            Self::Ordinary(_) => None,
            Self::PostCompletionRollback { operation_id, .. } => Some(operation_id),
        }
    }

    pub(super) fn validate_exact_sprint_authority(
        &self,
        request: &RunnerClientLaunch,
        explicit_role_input_authority: Option<RunnerRoleInputAuthority>,
    ) -> Result<RunnerRoleInputAuthority, RunnerClientError> {
        let ledger = match self {
            Self::Ordinary(ledger) | Self::PostCompletionRollback { ledger, .. } => ledger,
        };
        let persisted = ledger.load_sprint(&request.sprint_spec.sprint_id)?;
        if persisted.spec != request.sprint_spec {
            return Err(RunnerClientError::InvalidLifecycle(
                "runner launch SprintSpec differs from the exact durable sprint contract".into(),
            ));
        }

        match self {
            Self::Ordinary(_) => {
                if let Some(authority) = explicit_role_input_authority {
                    let RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest } =
                        &authority
                    else {
                        return Err(RunnerClientError::InvalidLifecycle(
                            "explicit ordinary role-input authority is reserved for live-state finalization"
                                .into(),
                        ));
                    };
                    if request.role != RunnerRole::LiveStateVerifier
                        || plan.validate().is_err()
                        || plan.plan_digest().ok().as_ref() != Some(plan_digest)
                        || plan.sprint_id != request.sprint_id
                        || plan.expected_snapshot != request.expected_base_snapshot
                        || plan.grant_hash != persisted.spec.workspace_grant.grant_hash
                        || plan.policy_version != persisted.spec.workspace_grant.policy_version
                    {
                        return Err(RunnerClientError::InvalidLifecycle(
                            "live-state role-input authority differs from the exact durable plan, sprint, snapshot, or grant"
                                .into(),
                        ));
                    }
                    validate_durable_snapshot_authority(ledger, &persisted, request)?;
                    Ok(authority)
                } else {
                    validate_durable_role_input(ledger, &persisted, request)?;
                    ordinary_role_input_authority(request.role)
                }
            }
            Self::PostCompletionRollback { operation_id, .. } => {
                if explicit_role_input_authority.is_some() {
                    return Err(RunnerClientError::InvalidLifecycle(
                        "post-completion rollback cannot accept live-state role-input authority"
                            .into(),
                    ));
                }
                let operation = ledger.load_post_completion_rollback(operation_id)?;
                let PostCompletionRollbackApplicationArtifactAuthorityState::Authoritative {
                    authority,
                    authority_digest,
                } = operation.application_artifact_authority
                else {
                    return Err(RunnerClientError::MissingDurableApplicationArtifactAuthority);
                };
                if operation.intent.sprint_id != persisted.spec.sprint_id
                    || request.role != RunnerRole::Applier
                    || authority.sprint_id != persisted.spec.sprint_id
                    || authority.artifact.base_snapshot != persisted.spec.base_snapshot
                    || request.expected_base_snapshot != authority.artifact.result_snapshot
                {
                    return Err(RunnerClientError::InvalidLifecycle(
                        "post-completion rollback input differs from the exact applied artifact result snapshot"
                            .into(),
                    ));
                }
                validate_durable_snapshot_authority(ledger, &persisted, request)?;
                Ok(RunnerRoleInputAuthority::PostCompletionAppliedResult {
                    authority,
                    authority_digest,
                })
            }
        }
    }

    #[allow(clippy::too_many_lines)] // Keeps each durable launch branch visibly transactional.
    pub(super) fn record_launch(
        &mut self,
        launch: &RunnerLaunchIntent,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        input_snapshot: &Digest,
        role_input_authority: &RunnerRoleInputAuthority,
    ) -> Result<DurableRunnerLaunch, RunnerLaunchPersistenceFailure> {
        match self {
            Self::Ordinary(ledger) => {
                let cleanup = prepare_ordinary_launch_cleanup(ledger, launch, input_snapshot)
                    .map_err(|error| RunnerLaunchPersistenceFailure {
                        error,
                        cleanup_admission: None,
                    })?;
                let admitted = match role_input_authority {
                    RunnerRoleInputAuthority::LiveStateFinalization { plan, .. } => ledger
                        .admit_live_state_verifier_launch_with_cleanup(
                            plan,
                            launch,
                            compiled_policy,
                            &cleanup.intent,
                            &cleanup.request_bytes,
                            &cleanup.event,
                        ),
                    _ => ledger.admit_runner_launch_with_cleanup(
                        launch,
                        compiled_policy,
                        &cleanup.intent,
                        &cleanup.request_bytes,
                        &cleanup.event,
                    ),
                };
                match admitted {
                    Ok(admission) => {
                        if !launch_cleanup_admission_matches(
                            &admission,
                            launch,
                            &cleanup.request,
                            &cleanup.request_bytes,
                            &cleanup.intent,
                            &cleanup.event,
                        ) {
                            return Err(RunnerLaunchPersistenceFailure {
                                error: RunnerClientError::InvalidLifecycle(
                                    "atomic launch/cleanup admission readback differs from every supplied preimage"
                                        .into(),
                                ),
                                cleanup_admission: None,
                            });
                        }
                        let platform_binding = match PlatformLaunchBinding::try_from_admission(
                            &admission,
                            authority,
                            compiled_policy,
                        ) {
                            Ok(binding) => binding,
                            Err(error) => {
                                return Err(RunnerLaunchPersistenceFailure {
                                    error: RunnerClientError::InvalidLifecycle(format!(
                                        "canonical platform launch binding rejected the atomic admission: {error}"
                                    )),
                                    cleanup_admission: Some(Box::new(admission)),
                                });
                            }
                        };
                        Ok(DurableRunnerLaunch::Ordinary {
                            admission: Box::new(admission),
                            platform_binding: Box::new(platform_binding),
                        })
                    }
                    Err(error @ LedgerError::PostCommitStateUncertain { .. }) => {
                        let exact = ledger
                            .load_runner_launch_cleanup_admission(
                                &launch.sprint_id,
                                &launch.launch_id,
                            )
                            .ok()
                            .filter(|admission| {
                                launch_cleanup_admission_matches(
                                    admission,
                                    launch,
                                    &cleanup.request,
                                    &cleanup.request_bytes,
                                    &cleanup.intent,
                                    &cleanup.event,
                                )
                            })
                            .map(Box::new);
                        Err(RunnerLaunchPersistenceFailure {
                            error: error.into(),
                            cleanup_admission: exact,
                        })
                    }
                    Err(error) => Err(RunnerLaunchPersistenceFailure {
                        error: error.into(),
                        cleanup_admission: None,
                    }),
                }
            }
            Self::PostCompletionRollback {
                ledger,
                operation_id,
                role,
            } => ledger
                .record_post_completion_rollback_applier_launch(
                    operation_id,
                    *role,
                    launch,
                    compiled_policy,
                )
                .map(|_| DurableRunnerLaunch::PostCompletionRollback)
                .map_err(|error| RunnerLaunchPersistenceFailure {
                    error: error.into(),
                    cleanup_admission: None,
                }),
        }
    }

    pub(super) fn register_session(
        &mut self,
        session: &RunnerSessionPolicyRecord,
        compiled_policy: &CompiledExecutionPolicy,
        role_input_authority: &RunnerRoleInputAuthority,
    ) -> Result<(), LedgerError> {
        match self {
            Self::Ordinary(ledger) => match role_input_authority {
                RunnerRoleInputAuthority::LiveStateFinalization { plan, .. } => {
                    ledger.register_live_state_verifier_session(plan, session, compiled_policy)
                }
                _ => ledger.register_runner_session(session, compiled_policy),
            },
            Self::PostCompletionRollback {
                ledger,
                operation_id,
                ..
            } => ledger
                .register_post_completion_rollback_applier_session(
                    operation_id,
                    session,
                    compiled_policy,
                )
                .map(|_| ()),
        }
    }

    pub(super) fn start_worker_attempt(
        &mut self,
        launch: &RunnerLaunchIntent,
        session: &RunnerSessionPolicyRecord,
    ) -> Result<Option<TaskAttemptRunningBoundary>, RunnerClientError> {
        if launch.purpose != RunnerSessionPurpose::TaskWorker {
            return Ok(None);
        }
        let Self::Ordinary(ledger) = self else {
            return Err(RunnerClientError::InvalidLifecycle(
                "post-completion rollback authority cannot start a task-worker attempt".into(),
            ));
        };
        let lease = launch.worker_lease.as_ref().ok_or_else(|| {
            RunnerClientError::InvalidLifecycle(
                "task-worker launch is missing its exact worker lease".into(),
            )
        })?;
        let attempt = ledger.load_task_attempt(&lease.lease_id)?;
        if attempt.worker_lease != *lease
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.worker_lease.as_ref() != Some(lease)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "task attempt, launch, registered session, or worker lease authority is crossed"
                    .into(),
            ));
        }

        let mut identity_preimage = Vec::new();
        identity_preimage.extend_from_slice(b"grok-build/task-attempt-running/v1\0");
        identity_preimage.extend_from_slice(attempt.attempt_id.as_bytes());
        identity_preimage.push(0);
        identity_preimage.extend_from_slice(launch.launch_id.as_bytes());
        identity_preimage.push(0);
        identity_preimage.extend_from_slice(session.session_id.as_bytes());
        let identity = Digest::sha256(&identity_preimage);
        let event_id = format!("task-attempt-running-event-{identity}");
        let boundary = TaskAttemptRunningBoundary {
            contract_version: CONTRACT_VERSION,
            boundary_id: format!("task-attempt-running-boundary-{identity}"),
            attempt,
            runner_launch_id: launch.launch_id.clone(),
            runner_session_id: session.session_id.clone(),
            transition_event_id: event_id.clone(),
            started_at_unix_ms: session.registered_at_unix_ms,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger.next_sequence(&launch.sprint_id)?,
            event_id,
            sprint_id: launch.sprint_id.clone(),
            task_id: Some(lease.task_id.clone()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(boundary.attempt.opening_event_id.clone()),
            correlation_id: format!("task-attempt-running-{identity}"),
            policy_hash: Some(session.policy_hash.clone()),
            occurred_at_unix_ms: session.registered_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: "Running".into(),
            },
        };
        let stored = ledger.start_task_attempt(&boundary, &event)?;
        if stored != boundary {
            return Err(RunnerClientError::InvalidLifecycle(
                "task-attempt Running readback differs from the exact launch/session boundary"
                    .into(),
            ));
        }
        Ok(Some(stored))
    }

    pub(super) fn registration_state_after_error(
        &self,
        candidate: &RunnerSessionPolicyRecord,
    ) -> RunnerSessionRegistrationState {
        let loaded = match self {
            Self::Ordinary(ledger) => ledger
                .load_runner_session(&candidate.sprint_id, &candidate.session_id)
                .map(Some),
            Self::PostCompletionRollback {
                ledger,
                operation_id,
                ..
            } => ledger
                .load_post_completion_rollback(operation_id)
                .map(|operation| {
                    operation
                        .appliers
                        .into_iter()
                        .filter_map(|applier| applier.session)
                        .find(|session| {
                            session.session_id == candidate.session_id
                                || session.launch_id == candidate.launch_id
                        })
                }),
        };
        match loaded {
            Ok(Some(stored)) if stored == *candidate => {
                RunnerSessionRegistrationState::Registered(stored)
            }
            Ok(None)
            | Err(LedgerError::ArtifactNotFound {
                entity: "runner session policy",
                ..
            }) => RunnerSessionRegistrationState::NotRegistered,
            Ok(Some(_)) => RunnerSessionRegistrationState::RegistrationUncertain {
                candidate: candidate.clone(),
                detail:
                    "durable session readback exists but differs from the initialized candidate"
                        .into(),
            },
            Err(error) => RunnerSessionRegistrationState::RegistrationUncertain {
                candidate: candidate.clone(),
                detail: error.to_string(),
            },
        }
    }
}
