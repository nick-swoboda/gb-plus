//! Lifecycle-owner state, configuration, and live custody.

use super::*;

/// Immutable process-path configuration for one runner lifecycle owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerLifecycleOwnerConfig {
    /// Exact canonical runner binary path passed to the fail-closed production
    /// launch boundary.
    pub runner_binary: PathBuf,
    /// Exact private runner-state directory.
    pub private_state_root: PathBuf,
}

/// Complete immutable identity retained with live-client or cleanup custody.
pub struct RunnerLifecycleBindingView<'a> {
    /// Owning sprint.
    pub sprint_id: &'a str,
    /// Exact task attempt.
    pub attempt_id: &'a str,
    /// Exact worker launch.
    pub launch_id: &'a str,
    /// Exact initialized session.
    pub session_id: &'a str,
    /// Exact task `Running` boundary, when initialization succeeded.
    pub running: Option<&'a TaskAttemptRunningBoundary>,
}

/// Complete immutable identity retained with a live final-verifier client or
/// its mandatory cleanup handoff.
pub struct FinalVerifierLifecycleBindingView<'a> {
    /// Owning sprint.
    pub sprint_id: &'a str,
    /// Exact final-verifier launch.
    pub launch_id: &'a str,
    /// Exact initialized final-verifier session.
    pub session_id: &'a str,
    /// Exact integrated snapshot admitted for repository-wide verification.
    pub final_snapshot: &'a Digest,
}

/// Complete immutable identity retained with a live trusted-Applier client or
/// its mandatory cleanup handoff.
pub struct ApplicationLifecycleBindingView<'a> {
    /// Owning sprint.
    pub sprint_id: &'a str,
    /// Exact trusted-Applier launch.
    pub launch_id: &'a str,
    /// Exact initialized trusted-Applier session.
    pub session_id: &'a str,
    /// Exact canonical application request.
    pub request: &'a ApplicationRequest,
    /// Exact immutable stage bundle.
    pub stage_bundle: &'a StageBundleReference,
}

/// Complete immutable identity retained with a live-state verifier or its
/// mandatory cleanup handoff.
pub struct LiveStateVerifierLifecycleBindingView<'a> {
    /// Owning sprint.
    pub sprint_id: &'a str,
    /// Exact live-state-verifier launch.
    pub launch_id: &'a str,
    /// Exact initialized verifier session.
    pub session_id: &'a str,
    /// Exact core-derived finalization plan.
    pub plan: &'a SprintLiveStateCapturePlan,
}

/// Why the owner cannot authorize another launch or effect.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the public reconciliation view retains complete exact recovery evidence for inspection"
)]
pub enum RunnerLifecycleReconciliation {
    /// Restart found an attempt with durable launch, session, or unresolved
    /// authority but no live client handle.
    RecoveredDurableAuthority {
        /// Exact active attempt.
        attempt: TaskAttempt,
        /// Exact durable running boundary, when present.
        running: Option<TaskAttemptRunningBoundary>,
        /// Ledger-derived recovery facts. These are comparison evidence only.
        facts: TaskAttemptRecoveryFacts,
        /// Exact unresolved effect when the recovery evidence identifier names
        /// a worker effect. This preserves an unobserved dispatch claim rather
        /// than reducing it to a string identifier.
        unresolved_effect: Option<Box<PersistedEffect>>,
    },
    /// Transport succeeded and the live client remains in custody until the
    /// exact claimed terminal effect is durably acknowledged.
    AwaitingTerminalObservation {
        /// Exact claimed, still-unobserved effect read back after transport.
        effect: Box<PersistedEffect>,
    },
    /// A consuming send failed. The effect remains reconciliation-only even if
    /// transport claim persistence did not complete.
    EffectDispatchFailed {
        /// Exact persisted effect state read back after the failure.
        effect: Box<PersistedEffect>,
        /// Bounded client failure diagnostic.
        detail: String,
    },
    /// The runner explicitly requires a separate reconciliation control after
    /// the exact terminal observation was acknowledged.
    RunnerRequestedReconciliation {
        /// Exact terminal effect that requested reconciliation.
        effect: Box<PersistedEffect>,
    },
    /// Conservative placeholder installed before consuming a live client.
    OwnershipTransition {
        /// Operation whose unwind or incomplete transition requires review.
        operation: &'static str,
        /// Effect involved in the transition, when applicable.
        effect_id: Option<String>,
    },
}

/// Read-only projection of the closed custody nested inside reconciliation.
pub enum ReconciliationCustodyView<'a> {
    /// Only durable evidence remains; there is no process handle to reuse.
    DurableOnly,
    /// The exact initialized client is still owned but cannot dispatch.
    LiveClient {
        /// Exact live-client binding.
        binding: RunnerLifecycleBindingView<'a>,
    },
    /// The client was consumed and its mandatory cleanup handoff is retained.
    Cleanup {
        /// Exact binding whose process domain requires cleanup proof.
        binding: RunnerLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// The exact initialized final-verifier client is still owned but fenced.
    LiveFinalVerifier {
        /// Exact final-verifier binding.
        binding: FinalVerifierLifecycleBindingView<'a>,
    },
    /// Final-verifier transport consumed the client and retained cleanup.
    FinalVerifierCleanup {
        /// Exact final-verifier binding.
        binding: FinalVerifierLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// The exact initialized live-state verifier is still owned but fenced.
    LiveStateVerifier {
        /// Exact live-state binding.
        binding: LiveStateVerifierLifecycleBindingView<'a>,
    },
    /// Live-state transport consumed the client and retained cleanup custody.
    LiveStateVerifierCleanup {
        /// Exact live-state binding.
        binding: LiveStateVerifierLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// The exact initialized trusted-Applier client is still owned but fenced.
    LiveApplicationApplier {
        /// Exact application binding.
        binding: ApplicationLifecycleBindingView<'a>,
    },
    /// Application transport consumed the client and retained cleanup.
    ApplicationCleanup {
        /// Exact application binding.
        binding: ApplicationLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
}

/// Read-only projection of the owner's mutually exclusive top-level states.
pub enum DesktopRunnerLifecycleStateView<'a> {
    /// No launch boundary has been entered by this owner.
    Idle,
    /// One exact initialized client may accept a fresh effect.
    ActiveClient {
        /// Exact live-client binding.
        binding: RunnerLifecycleBindingView<'a>,
    },
    /// One exact initialized final verifier may consume the fresh sprint
    /// final-verification dispatch permit.
    ActiveFinalVerifier {
        /// Exact final-verifier binding.
        binding: FinalVerifierLifecycleBindingView<'a>,
    },
    /// One exact initialized live-state verifier may consume a fresh capture
    /// permit.
    ActiveLiveStateVerifier {
        /// Exact live-state-verifier binding.
        binding: LiveStateVerifierLifecycleBindingView<'a>,
    },
    /// No further execution is allowed until platform cleanup is proven.
    CleanupRequired {
        /// Exact binding whose process domain requires cleanup proof.
        binding: RunnerLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// No further final-verifier execution is allowed until platform cleanup
    /// is durably proven.
    FinalVerifierCleanupRequired {
        /// Exact final-verifier binding.
        binding: FinalVerifierLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// No further live-state execution is allowed until platform cleanup is
    /// durably proven.
    LiveStateVerifierCleanupRequired {
        /// Exact live-state-verifier binding.
        binding: LiveStateVerifierLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// One exact initialized trusted Applier may consume the fresh application
    /// dispatch permit.
    ActiveApplicationApplier {
        /// Exact live application binding.
        binding: ApplicationLifecycleBindingView<'a>,
    },
    /// No further application execution is allowed until trusted-Applier
    /// direct-child cleanup is durably proven.
    ApplicationCleanupRequired {
        /// Exact application binding.
        binding: ApplicationLifecycleBindingView<'a>,
        /// Mandatory cleanup handoff.
        cleanup: &'a RunnerCleanupRequired,
    },
    /// Execution is fenced pending explicit reconciliation.
    ReconciliationRequired {
        /// Exact reason and durable evidence.
        requirement: &'a RunnerLifecycleReconciliation,
        /// Exclusive durable, live, or cleanup custody.
        custody: ReconciliationCustodyView<'a>,
    },
}

/// Production-shaped, non-clone owner of one task-worker or final-verifier
/// runner lifecycle.
///
/// ```compile_fail
/// use grok_build_desktop::DesktopRunnerLifecycleOwner;
///
/// fn duplicate(owner: DesktopRunnerLifecycleOwner) {
///     let _second = owner.clone();
/// }
/// ```
#[must_use = "the lifecycle owner retains live runner or mandatory cleanup custody"]
pub struct DesktopRunnerLifecycleOwner {
    pub(super) config: RunnerLifecycleOwnerConfig,
    pub(super) state: DesktopRunnerLifecycleState,
    pub(super) native_cleanup_reopener: Option<Box<dyn NativeLaunchCleanupReopener>>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "each variant owns one mutually exclusive authority object; indirection would obscure the custody audit"
)]
pub(super) enum DesktopRunnerLifecycleState {
    Idle,
    ActiveClient {
        binding: ActiveRunnerBinding,
        client: RunnerLifecycleClient,
    },
    ActiveFinalVerifier {
        binding: ActiveFinalVerifierBinding,
        client: RunnerLifecycleClient,
    },
    ActiveLiveStateVerifier {
        binding: ActiveLiveStateVerifierBinding,
        client: RunnerLifecycleClient,
    },
    ActiveApplicationApplier {
        binding: ActiveApplicationBinding,
        client: RunnerLifecycleClient,
    },
    CleanupRequired {
        binding: RunnerLifecycleBinding,
        cleanup: RunnerCleanupRequired,
    },
    FinalVerifierCleanupRequired {
        binding: FinalVerifierBinding,
        cleanup: RunnerCleanupRequired,
    },
    LiveStateVerifierCleanupRequired {
        binding: LiveStateVerifierBinding,
        cleanup: RunnerCleanupRequired,
    },
    ApplicationCleanupRequired {
        binding: ApplicationBinding,
        cleanup: RunnerCleanupRequired,
    },
    ReconciliationRequired {
        requirement: RunnerLifecycleReconciliation,
        custody: ReconciliationCustody,
    },
}

#[allow(
    clippy::large_enum_variant,
    reason = "the closed variants deliberately retain exactly one live client or cleanup handoff without nullable custody"
)]
pub(super) enum ReconciliationCustody {
    DurableOnly,
    LiveClient {
        binding: ActiveRunnerBinding,
        client: RunnerLifecycleClient,
    },
    Cleanup {
        binding: RunnerLifecycleBinding,
        cleanup: RunnerCleanupRequired,
    },
    LiveFinalVerifier {
        binding: ActiveFinalVerifierBinding,
        client: RunnerLifecycleClient,
    },
    FinalVerifierCleanup {
        binding: FinalVerifierBinding,
        cleanup: RunnerCleanupRequired,
    },
    LiveStateVerifier {
        binding: ActiveLiveStateVerifierBinding,
        client: RunnerLifecycleClient,
    },
    LiveStateVerifierCleanup {
        binding: LiveStateVerifierBinding,
        cleanup: RunnerCleanupRequired,
    },
    LiveApplicationApplier {
        binding: ActiveApplicationBinding,
        client: RunnerLifecycleClient,
    },
    ApplicationCleanup {
        binding: ApplicationBinding,
        cleanup: RunnerCleanupRequired,
    },
}

pub(super) struct RunnerLifecycleBinding {
    pub(super) sprint: String,
    pub(super) attempt: String,
    pub(super) launch: String,
    pub(super) session: String,
}

pub(super) struct ActiveRunnerBinding {
    pub(super) identity: RunnerLifecycleBinding,
    pub(super) launch_request: RunnerClientLaunch,
    pub(super) running: TaskAttemptRunningBoundary,
}

pub(super) struct FinalVerifierBinding {
    pub(super) sprint: String,
    pub(super) launch: String,
    pub(super) session: String,
    pub(super) final_snapshot: Digest,
}

pub(super) struct ActiveFinalVerifierBinding {
    pub(super) identity: FinalVerifierBinding,
    pub(super) launch_request: RunnerClientLaunch,
}

pub(super) struct LiveStateVerifierBinding {
    pub(super) sprint: String,
    pub(super) launch: String,
    pub(super) session: String,
    pub(super) plan: SprintLiveStateCapturePlan,
}

pub(super) struct ActiveLiveStateVerifierBinding {
    pub(super) identity: LiveStateVerifierBinding,
    pub(super) launch_request: RunnerClientLaunch,
}

pub(super) struct ApplicationBinding {
    pub(super) sprint: String,
    pub(super) launch: String,
    pub(super) session: String,
    pub(super) request: ApplicationRequest,
    pub(super) stage_bundle: StageBundleReference,
}

pub(super) struct ActiveApplicationBinding {
    pub(super) identity: ApplicationBinding,
    pub(super) launch_request: RunnerClientLaunch,
}

impl RunnerLifecycleBinding {
    pub(super) fn view(&self) -> RunnerLifecycleBindingView<'_> {
        RunnerLifecycleBindingView {
            sprint_id: &self.sprint,
            attempt_id: &self.attempt,
            launch_id: &self.launch,
            session_id: &self.session,
            running: None,
        }
    }
}

impl ActiveRunnerBinding {
    pub(super) fn view(&self) -> RunnerLifecycleBindingView<'_> {
        RunnerLifecycleBindingView {
            sprint_id: &self.identity.sprint,
            attempt_id: &self.identity.attempt,
            launch_id: &self.identity.launch,
            session_id: &self.identity.session,
            running: Some(&self.running),
        }
    }

    pub(super) fn into_identity(self) -> RunnerLifecycleBinding {
        self.identity
    }
}

impl FinalVerifierBinding {
    pub(super) fn view(&self) -> FinalVerifierLifecycleBindingView<'_> {
        FinalVerifierLifecycleBindingView {
            sprint_id: &self.sprint,
            launch_id: &self.launch,
            session_id: &self.session,
            final_snapshot: &self.final_snapshot,
        }
    }
}

impl ActiveFinalVerifierBinding {
    pub(super) fn view(&self) -> FinalVerifierLifecycleBindingView<'_> {
        self.identity.view()
    }

    pub(super) fn into_identity(self) -> FinalVerifierBinding {
        self.identity
    }
}

impl LiveStateVerifierBinding {
    pub(super) fn view(&self) -> LiveStateVerifierLifecycleBindingView<'_> {
        LiveStateVerifierLifecycleBindingView {
            sprint_id: &self.sprint,
            launch_id: &self.launch,
            session_id: &self.session,
            plan: &self.plan,
        }
    }
}

impl ActiveLiveStateVerifierBinding {
    pub(super) fn view(&self) -> LiveStateVerifierLifecycleBindingView<'_> {
        self.identity.view()
    }

    pub(super) fn into_identity(self) -> LiveStateVerifierBinding {
        self.identity
    }
}

impl ApplicationBinding {
    pub(super) fn view(&self) -> ApplicationLifecycleBindingView<'_> {
        ApplicationLifecycleBindingView {
            sprint_id: &self.sprint,
            launch_id: &self.launch,
            session_id: &self.session,
            request: &self.request,
            stage_bundle: &self.stage_bundle,
        }
    }
}

impl ActiveApplicationBinding {
    pub(super) fn view(&self) -> ApplicationLifecycleBindingView<'_> {
        self.identity.view()
    }

    pub(super) fn into_identity(self) -> ApplicationBinding {
        self.identity
    }
}

impl DesktopRunnerLifecycleOwner {
    /// Creates an idle owner. This does not inspect, persist, or launch the
    /// configured executable.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerClientError::InvalidLifecycle`] for non-absolute or
    /// overlapping binary/private-state paths.
    pub fn new(config: RunnerLifecycleOwnerConfig) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::Idle,
            native_cleanup_reopener: None,
        })
    }

    #[allow(
        dead_code,
        reason = "admitted macOS and Linux cleanup-service clients are the next production callers; focused tests inject the same cleanup-only seam"
    )]
    pub(in crate::runner_client) fn with_native_cleanup_reopener(
        config: RunnerLifecycleOwnerConfig,
        native_cleanup_reopener: Box<dyn NativeLaunchCleanupReopener>,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::Idle,
            native_cleanup_reopener: Some(native_cleanup_reopener),
        })
    }

    #[cfg(test)]
    pub(in crate::runner_client) fn from_custody_free_worker_cleanup_with_reopener_for_test(
        config: RunnerLifecycleOwnerConfig,
        cleanup: RunnerCleanupRequired,
        native_cleanup_reopener: Box<dyn NativeLaunchCleanupReopener>,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        let launch = cleanup.launch();
        let Some(worker_lease) = launch.worker_lease.as_ref() else {
            return Err(RunnerClientError::InvalidLifecycle(
                "test custody-free worker cleanup requires an exact worker lease".into(),
            ));
        };
        let Some(session) = cleanup.session() else {
            return Err(RunnerClientError::InvalidLifecycle(
                "test custody-free worker cleanup requires an exact registered session".into(),
            ));
        };
        if cleanup.has_native_cleanup_custody()
            || launch.purpose != grok_build_core::RunnerSessionPurpose::TaskWorker
            || session.sprint_id != launch.sprint_id
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.worker_lease.as_ref() != Some(worker_lease)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test custody-free worker cleanup crossed launch, session, or native-domain authority"
                    .into(),
            ));
        }
        let binding = RunnerLifecycleBinding {
            sprint: launch.sprint_id.clone(),
            attempt: worker_lease.lease_id.clone(),
            launch: launch.launch_id.clone(),
            session: launch.session_id.clone(),
        };
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::CleanupRequired { binding, cleanup },
            native_cleanup_reopener: Some(native_cleanup_reopener),
        })
    }

    #[cfg(test)]
    pub(in crate::runner_client) fn from_custody_free_final_verifier_cleanup_with_reopener_for_test(
        config: RunnerLifecycleOwnerConfig,
        cleanup: RunnerCleanupRequired,
        final_snapshot: Digest,
        native_cleanup_reopener: Box<dyn NativeLaunchCleanupReopener>,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        let launch = cleanup.launch();
        let Some(session) = cleanup.session() else {
            return Err(RunnerClientError::InvalidLifecycle(
                "test custody-free final-verifier cleanup requires an exact registered session"
                    .into(),
            ));
        };
        if cleanup.has_native_cleanup_custody()
            || launch.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
            || launch.worker_id.is_some()
            || launch.worker_lease.is_some()
            || session.sprint_id != launch.sprint_id
            || session.launch_id != launch.launch_id
            || session.session_id != launch.session_id
            || session.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
            || session.worker_id.is_some()
            || session.worker_lease.is_some()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test custody-free final-verifier cleanup crossed launch, session, role, or native-domain authority"
                    .into(),
            ));
        }
        let binding = FinalVerifierBinding {
            sprint: launch.sprint_id.clone(),
            launch: launch.launch_id.clone(),
            session: launch.session_id.clone(),
            final_snapshot,
        };
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { binding, cleanup },
            native_cleanup_reopener: Some(native_cleanup_reopener),
        })
    }

    /// Test-only injection of one exact initialized `FinalVerifier` client.
    /// Production callers can enter this state only through the durable
    /// final-verifier launch and base-capture path.
    #[cfg(test)]
    pub(in crate::runner_client) fn from_active_final_verifier_for_test(
        config: RunnerLifecycleOwnerConfig,
        launch_request: RunnerClientLaunch,
        client: RunnerLifecycleClient,
        final_snapshot: Digest,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        if launch_request.role != grok_build_runner::RunnerRole::FinalVerifier
            || launch_request.worker_id.is_some()
            || launch_request.worker_lease.is_some()
            || launch_request.sprint_id != launch_request.sprint_spec.sprint_id
            || launch_request.expected_base_snapshot != final_snapshot
            || client.role != grok_build_runner::RunnerRole::FinalVerifier
            || client.expected_base_snapshot != final_snapshot
            || client.task_attempt_running_boundary().is_some()
            || client.launch.sprint_id != launch_request.sprint_id
            || client.launch.launch_id != launch_request.launch_id
            || client.launch.session_id != launch_request.session_id
            || client.launch.purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
            || client.launch.worker_id.is_some()
            || client.launch.worker_lease.is_some()
            || client.session().sprint_id != launch_request.sprint_id
            || client.session().launch_id != launch_request.launch_id
            || client.session().session_id != launch_request.session_id
            || client.session().purpose != grok_build_core::RunnerSessionPurpose::FinalVerifier
            || client.session().worker_id.is_some()
            || client.session().worker_lease.is_some()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test active final-verifier injection crossed sprint, launch, session, role, worker, or snapshot authority"
                    .into(),
            ));
        }
        let binding = ActiveFinalVerifierBinding {
            identity: FinalVerifierBinding {
                sprint: launch_request.sprint_id.clone(),
                launch: launch_request.launch_id.clone(),
                session: launch_request.session_id.clone(),
                final_snapshot,
            },
            launch_request,
        };
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client },
            native_cleanup_reopener: None,
        })
    }

    /// Test-only injection of one exact initialized `LiveStateVerifier`
    /// client. Production callers can enter this state only through the
    /// core-derived finalization-plan launch path.
    #[cfg(test)]
    pub(in crate::runner_client) fn from_active_live_state_verifier_for_test(
        config: RunnerLifecycleOwnerConfig,
        launch_request: RunnerClientLaunch,
        client: RunnerLifecycleClient,
        plan: SprintLiveStateCapturePlan,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        let binding = ActiveLiveStateVerifierBinding {
            identity: LiveStateVerifierBinding {
                sprint: launch_request.sprint_id.clone(),
                launch: launch_request.launch_id.clone(),
                session: launch_request.session_id.clone(),
                plan,
            },
            launch_request,
        };
        if binding
            .launch_request
            .sprint_spec
            .workspace_grant
            .grant_hash
            != binding.identity.plan.grant_hash
            || binding
                .launch_request
                .sprint_spec
                .workspace_grant
                .policy_version
                != binding.identity.plan.policy_version
            || !live_state_client_matches_internal_binding(&binding, &client)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test active live-state-verifier injection crossed sprint, plan, launch, session, role, policy, grant, or cleanup authority"
                    .into(),
            ));
        }
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client },
            native_cleanup_reopener: None,
        })
    }

    /// Test-only injection of one exact initialized and startup-prepared
    /// ordinary trusted-Applier client.
    #[cfg(test)]
    pub(in crate::runner_client) fn from_active_application_applier_for_test(
        config: RunnerLifecycleOwnerConfig,
        launch_request: RunnerClientLaunch,
        client: RunnerLifecycleClient,
        request: ApplicationRequest,
        stage_bundle: StageBundleReference,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        validate_application_request_bundle(&request, &stage_bundle)
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        if launch_request.role != grok_build_runner::RunnerRole::Applier
            || launch_request.worker_id.is_some()
            || launch_request.worker_lease.is_some()
            || launch_request.shadow_root.is_some()
            || launch_request.sprint_id != launch_request.sprint_spec.sprint_id
            || launch_request.expected_base_snapshot != request.change_set.base_snapshot
            || request.change_set.base_snapshot != launch_request.sprint_spec.base_snapshot
            || client.role != grok_build_runner::RunnerRole::Applier
            || client.expected_base_snapshot != request.change_set.base_snapshot
            || client.task_attempt_running_boundary().is_some()
            || client.post_completion_role.is_some()
            || client.post_completion_operation_id.is_some()
            || !client.applier_recovery_complete
            || client.launch.sprint_id != launch_request.sprint_id
            || client.launch.launch_id != launch_request.launch_id
            || client.launch.session_id != launch_request.session_id
            || client.launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
            || client.launch.worker_id.is_some()
            || client.launch.worker_lease.is_some()
            || client.session().sprint_id != launch_request.sprint_id
            || client.session().launch_id != launch_request.launch_id
            || client.session().session_id != launch_request.session_id
            || client.session().purpose != grok_build_core::RunnerSessionPurpose::Applier
            || client.session().worker_id.is_some()
            || client.session().worker_lease.is_some()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test active application-Applier injection crossed sprint, launch, session, role, preparation, or application authority"
                    .into(),
            ));
        }
        let binding = ActiveApplicationBinding {
            identity: ApplicationBinding {
                sprint: launch_request.sprint_id.clone(),
                launch: launch_request.launch_id.clone(),
                session: launch_request.session_id.clone(),
                request,
                stage_bundle,
            },
            launch_request,
        };
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client },
            native_cleanup_reopener: None,
        })
    }

    /// Test-only injection of one retained trusted-Applier cleanup handoff.
    /// Production callers enter this state only through launch or shutdown.
    #[cfg(test)]
    pub(in crate::runner_client) fn from_application_cleanup_with_reopener_for_test(
        config: RunnerLifecycleOwnerConfig,
        cleanup: RunnerCleanupRequired,
        request: ApplicationRequest,
        stage_bundle: StageBundleReference,
        native_cleanup_reopener: Box<dyn NativeLaunchCleanupReopener>,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        validate_application_request_bundle(&request, &stage_bundle)
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        let launch = cleanup.launch();
        let admission = cleanup.launch_cleanup_admission().ok_or_else(|| {
            RunnerClientError::InvalidLifecycle(
                "test trusted-Applier cleanup requires exact launch/cleanup admission".into(),
            )
        })?;
        if launch.purpose != grok_build_core::RunnerSessionPurpose::Applier
            || launch.worker_id.is_some()
            || launch.worker_lease.is_some()
            || launch != &admission.launch
            || admission.cleanup_request.platform_backend
                != WorkerCleanupBackend::TrustedApplierDirectChildWait
            || request.change_set.base_snapshot != admission.cleanup_effect.intent.input_snapshot
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test trusted-Applier cleanup crossed launch, role, backend, or application authority"
                    .into(),
            ));
        }
        let binding = ApplicationBinding {
            sprint: launch.sprint_id.clone(),
            launch: launch.launch_id.clone(),
            session: launch.session_id.clone(),
            request,
            stage_bundle,
        };
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::ApplicationCleanupRequired { binding, cleanup },
            native_cleanup_reopener: Some(native_cleanup_reopener),
        })
    }

    /// Exact immutable owner configuration.
    #[must_use]
    pub const fn config(&self) -> &RunnerLifecycleOwnerConfig {
        &self.config
    }

    /// Projects the current state without transferring process or cleanup
    /// authority.
    #[must_use]
    pub fn state(&self) -> DesktopRunnerLifecycleStateView<'_> {
        match &self.state {
            DesktopRunnerLifecycleState::Idle => DesktopRunnerLifecycleStateView::Idle,
            DesktopRunnerLifecycleState::ActiveClient { binding, .. } => {
                DesktopRunnerLifecycleStateView::ActiveClient {
                    binding: binding.view(),
                }
            }
            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, .. } => {
                DesktopRunnerLifecycleStateView::ActiveFinalVerifier {
                    binding: binding.view(),
                }
            }
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, .. } => {
                DesktopRunnerLifecycleStateView::ActiveLiveStateVerifier {
                    binding: binding.view(),
                }
            }
            DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, .. } => {
                DesktopRunnerLifecycleStateView::ActiveApplicationApplier {
                    binding: binding.view(),
                }
            }
            DesktopRunnerLifecycleState::CleanupRequired { binding, cleanup } => {
                DesktopRunnerLifecycleStateView::CleanupRequired {
                    binding: binding.view(),
                    cleanup,
                }
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { binding, cleanup } => {
                DesktopRunnerLifecycleStateView::FinalVerifierCleanupRequired {
                    binding: binding.view(),
                    cleanup,
                }
            }
            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { binding, cleanup } => {
                DesktopRunnerLifecycleStateView::LiveStateVerifierCleanupRequired {
                    binding: binding.view(),
                    cleanup,
                }
            }
            DesktopRunnerLifecycleState::ApplicationCleanupRequired { binding, cleanup } => {
                DesktopRunnerLifecycleStateView::ApplicationCleanupRequired {
                    binding: binding.view(),
                    cleanup,
                }
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody,
            } => DesktopRunnerLifecycleStateView::ReconciliationRequired {
                requirement,
                custody: custody.view(),
            },
        }
    }

    /// Test-only injection of an already initialized and startup-prepared
    /// client. No public constructor can bypass the production launch gate.
    #[cfg(test)]
    pub(in crate::runner_client) fn from_active_client(
        config: RunnerLifecycleOwnerConfig,
        launch_request: RunnerClientLaunch,
        client: RunnerLifecycleClient,
    ) -> Result<Self, RunnerClientError> {
        validate_config(&config)?;
        let running = client
            .task_attempt_running_boundary()
            .cloned()
            .ok_or_else(|| {
                RunnerClientError::InvalidLifecycle(
                    "test owner injection requires an exact worker Running boundary".into(),
                )
            })?;
        if client.session().launch_id != launch_request.launch_id
            || client.session().session_id != launch_request.session_id
            || client.session().sprint_id != launch_request.sprint_id
            || launch_request.worker_lease.as_ref() != Some(&running.attempt.worker_lease)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "test owner injection crossed launch, session, sprint, or attempt authority".into(),
            ));
        }
        Ok(Self {
            config,
            state: DesktopRunnerLifecycleState::ActiveClient {
                binding: ActiveRunnerBinding {
                    identity: RunnerLifecycleBinding {
                        sprint: launch_request.sprint_id.clone(),
                        attempt: running.attempt.attempt_id.clone(),
                        launch: launch_request.launch_id.clone(),
                        session: launch_request.session_id.clone(),
                    },
                    launch_request,
                    running,
                },
                client,
            },
            native_cleanup_reopener: None,
        })
    }

    /// Consumes the active client through its orderly shutdown exchange and
    /// retains the resulting cleanup obligation.
    ///
    /// # Errors
    ///
    /// Returns an error when the owner is not active or shutdown fails. A
    /// consuming failure still retains exact cleanup custody.
    pub fn shutdown_active(&mut self) -> Result<(), RunnerClientError> {
        let placeholder = transition_state("shutdown", None);
        let previous = mem::replace(&mut self.state, placeholder);
        let DesktopRunnerLifecycleState::ActiveClient { binding, client } = previous else {
            self.state = previous;
            return Err(RunnerClientError::InvalidLifecycle(
                "only an active runner client may begin orderly shutdown".into(),
            ));
        };
        let identity = binding.into_identity();
        match client.shutdown() {
            Ok(cleanup) => {
                self.state = DesktopRunnerLifecycleState::CleanupRequired {
                    binding: identity,
                    cleanup,
                };
                Ok(())
            }
            Err(failure) => {
                let detail = failure.error().to_string();
                let cleanup = failure.into_cleanup_required();
                self.state = DesktopRunnerLifecycleState::CleanupRequired {
                    binding: identity,
                    cleanup,
                };
                Err(RunnerClientError::InvalidLifecycle(format!(
                    "orderly shutdown failed and cleanup remains required: {detail}"
                )))
            }
        }
    }

    /// Converts reconciliation-held live-client custody into a cleanup handoff
    /// while preserving the reconciliation requirement.
    ///
    /// # Errors
    ///
    /// Returns an error unless reconciliation currently owns a live client, or
    /// when orderly shutdown fails. Cleanup custody is retained on failure.
    #[allow(
        clippy::too_many_lines,
        reason = "worker and final-verifier bindings retain distinct closed cleanup custody variants"
    )]
    pub fn prepare_reconciliation_cleanup(&mut self) -> Result<(), RunnerClientError> {
        let placeholder = transition_state("reconciliation-shutdown", None);
        let previous = mem::replace(&mut self.state, placeholder);
        match previous {
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveClient { binding, client },
            } => {
                let identity = binding.into_identity();
                match client.shutdown() {
                    Ok(cleanup) => {
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::Cleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Ok(())
                    }
                    Err(failure) => {
                        let detail = failure.error().to_string();
                        let cleanup = failure.into_cleanup_required();
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::Cleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Err(RunnerClientError::InvalidLifecycle(format!(
                            "reconciliation shutdown failed and cleanup remains required: {detail}"
                        )))
                    }
                }
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveFinalVerifier { binding, client },
            } => {
                let identity = binding.into_identity();
                match client.shutdown() {
                    Ok(cleanup) => {
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::FinalVerifierCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Ok(())
                    }
                    Err(failure) => {
                        let detail = failure.error().to_string();
                        let cleanup = failure.into_cleanup_required();
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::FinalVerifierCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Err(RunnerClientError::InvalidLifecycle(format!(
                            "final-verifier reconciliation shutdown failed and cleanup remains required: {detail}"
                        )))
                    }
                }
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveStateVerifier { binding, client },
            } => {
                if !live_state_client_matches_internal_binding(&binding, &client) {
                    self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                        requirement,
                        custody: ReconciliationCustody::LiveStateVerifier { binding, client },
                    };
                    return Err(RunnerClientError::InvalidLifecycle(
                        "live-state reconciliation shutdown crossed its exact internal client binding"
                            .into(),
                    ));
                }
                let identity = binding.into_identity();
                match client.shutdown() {
                    Ok(cleanup) => {
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::LiveStateVerifierCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Ok(())
                    }
                    Err(failure) => {
                        let detail = failure.error().to_string();
                        let cleanup = failure.into_cleanup_required();
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::LiveStateVerifierCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Err(RunnerClientError::InvalidLifecycle(format!(
                            "live-state reconciliation shutdown failed and cleanup remains required: {detail}"
                        )))
                    }
                }
            }
            DesktopRunnerLifecycleState::ReconciliationRequired {
                requirement,
                custody: ReconciliationCustody::LiveApplicationApplier { binding, client },
            } => {
                let identity = binding.into_identity();
                match client.shutdown() {
                    Ok(cleanup) => {
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::ApplicationCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Ok(())
                    }
                    Err(failure) => {
                        let detail = failure.error().to_string();
                        let cleanup = failure.into_cleanup_required();
                        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
                            requirement,
                            custody: ReconciliationCustody::ApplicationCleanup {
                                binding: identity,
                                cleanup,
                            },
                        };
                        Err(RunnerClientError::InvalidLifecycle(format!(
                            "application reconciliation shutdown failed and cleanup remains required: {detail}"
                        )))
                    }
                }
            }
            other => {
                self.state = other;
                Err(RunnerClientError::InvalidLifecycle(
                    "reconciliation cleanup requires exact live-client custody".into(),
                ))
            }
        }
    }

    pub(super) fn enter_recovered_reconciliation(
        &mut self,
        attempt: &TaskAttempt,
        running: Option<TaskAttemptRunningBoundary>,
        facts: TaskAttemptRecoveryFacts,
        unresolved_effect: Option<Box<PersistedEffect>>,
    ) {
        self.state = DesktopRunnerLifecycleState::ReconciliationRequired {
            requirement: RunnerLifecycleReconciliation::RecoveredDurableAuthority {
                attempt: attempt.clone(),
                running,
                facts,
                unresolved_effect,
            },
            custody: ReconciliationCustody::DurableOnly,
        };
    }
}

impl DesktopRunnerLifecycleOwner {
    #[allow(clippy::too_many_lines)] // One state-machine transition owns launch, recovery, and custody checks.
    pub(super) fn ensure_sprint_final_verifier_with_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonFinalVerifierStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        match &self.state {
            DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client } => {
                validate_repeated_final_verifier_start(binding, client, start)?;
                return Ok(final_verifier_boundary(binding, client));
            }
            DesktopRunnerLifecycleState::Idle => {}
            DesktopRunnerLifecycleState::ActiveClient { .. }
            | DesktopRunnerLifecycleState::CleanupRequired { .. } => {
                return Err(protocol(
                    "task-worker custody forbids launching the sprint final verifier",
                ));
            }
            DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "final-verifier cleanup is required before another launch",
                ));
            }
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { .. }
            | DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "live-state-verifier custody forbids launching the sprint final verifier",
                ));
            }
            DesktopRunnerLifecycleState::ActiveApplicationApplier { .. }
            | DesktopRunnerLifecycleState::ApplicationCleanupRequired { .. } => {
                return Err(protocol(
                    "application Applier custody forbids launching the sprint final verifier",
                ));
            }
            DesktopRunnerLifecycleState::ReconciliationRequired { .. } => {
                return Err(protocol(
                    "runner reconciliation is required before final-verifier launch",
                ));
            }
        }

        let request = final_verifier_launch_request(&self.config, start);
        let prospective = FinalVerifierBinding {
            sprint: request.sprint_id.clone(),
            launch: request.launch_id.clone(),
            session: request.session_id.clone(),
            final_snapshot: start.final_snapshot.clone(),
        };
        let client = match launch(ledger, request.clone()) {
            Ok(client) => client,
            Err(failure) => {
                let detail = failure.error().to_string();
                let (_error, cleanup) = failure.into_parts();
                if let Some(cleanup) = cleanup {
                    self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                        binding: prospective,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                return Err(protocol(format!("final-verifier launch failed: {detail}")));
            }
        };
        if client.task_attempt_running_boundary().is_some() {
            return retain_crossed_final_verifier_launch_cleanup(
                self,
                prospective,
                client,
                "final-verifier launch returned task-running authority",
            );
        }
        let durable_launch = match load_launch(
            ledger,
            &start.sprint_spec.sprint_id,
            &request.launch_id,
        ) {
            Ok(durable_launch) => durable_launch,
            Err(error) => {
                let detail = format!(
                    "final-verifier post-launch durable readback failed and cleanup remains required: {error}"
                );
                return retain_crossed_final_verifier_launch_cleanup(
                    self,
                    prospective,
                    client,
                    &detail,
                );
            }
        };
        if client.launch != durable_launch
            || client.session().session_id != request.session_id
            || client.session().launch_id != request.launch_id
        {
            return retain_crossed_final_verifier_launch_cleanup(
                self,
                prospective,
                client,
                "final-verifier launch returned crossed role, launch, or session authority",
            );
        }
        let binding = ActiveFinalVerifierBinding {
            identity: prospective,
            launch_request: request,
        };
        let capture_at = client.session().registered_at_unix_ms;
        let (client, _capture) = match client.send_control(RunnerRequest::FinalVerifierCapture {
            created_at_unix_ms: capture_at,
        }) {
            Ok(captured) => captured,
            Err(failure) => {
                let detail = failure.error().to_string();
                let cleanup = failure.into_cleanup_required();
                self.state = DesktopRunnerLifecycleState::FinalVerifierCleanupRequired {
                    binding: binding.into_identity(),
                    cleanup,
                };
                return Err(protocol(format!(
                    "final-verifier base capture failed and cleanup remains required: {detail}"
                )));
            }
        };
        let boundary = final_verifier_boundary(&binding, &client);
        self.state = DesktopRunnerLifecycleState::ActiveFinalVerifier { binding, client };
        Ok(boundary)
    }

    #[cfg(test)]
    pub(in crate::runner_client) fn ensure_sprint_final_verifier_with_test_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonFinalVerifierStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        self.ensure_sprint_final_verifier_with_io(ledger, start, launch, load_launch)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the live-state launch keeps role gating, fail-closed launch, fallible readback custody, and exact active-state admission contiguous"
    )]
    pub(super) fn ensure_sprint_live_state_verifier_with_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonLiveStateVerifierStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        match &self.state {
            DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client } => {
                validate_repeated_live_state_verifier_start(binding, client, start)?;
                return Ok(live_state_verifier_boundary(binding, client));
            }
            DesktopRunnerLifecycleState::Idle => {}
            DesktopRunnerLifecycleState::ActiveClient { .. }
            | DesktopRunnerLifecycleState::CleanupRequired { .. } => {
                return Err(protocol(
                    "task-worker custody forbids launching the live-state verifier",
                ));
            }
            DesktopRunnerLifecycleState::ActiveFinalVerifier { .. }
            | DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "final-verifier custody forbids launching the live-state verifier",
                ));
            }
            DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "live-state-verifier cleanup is required before another launch",
                ));
            }
            DesktopRunnerLifecycleState::ActiveApplicationApplier { .. }
            | DesktopRunnerLifecycleState::ApplicationCleanupRequired { .. } => {
                return Err(protocol(
                    "application Applier custody forbids launching the live-state verifier",
                ));
            }
            DesktopRunnerLifecycleState::ReconciliationRequired { .. } => {
                return Err(protocol(
                    "runner reconciliation is required before live-state-verifier launch",
                ));
            }
        }

        let request = live_state_verifier_launch_request(&self.config, start);
        let prospective = LiveStateVerifierBinding {
            sprint: request.sprint_id.clone(),
            launch: request.launch_id.clone(),
            session: request.session_id.clone(),
            plan: start.plan.clone(),
        };
        let client = match launch(ledger, request.clone()) {
            Ok(client) => client,
            Err(failure) => {
                let detail = failure.error().to_string();
                let (_error, cleanup) = failure.into_parts();
                if let Some(cleanup) = cleanup {
                    self.state = DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired {
                        binding: prospective,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                return Err(protocol(format!(
                    "live-state-verifier launch failed: {detail}"
                )));
            }
        };
        if client.task_attempt_running_boundary().is_some() {
            return retain_crossed_live_state_verifier_launch_cleanup(
                self,
                prospective,
                client,
                "live-state-verifier launch returned task-running authority",
            );
        }
        let durable_launch = match load_launch(
            ledger,
            &start.sprint_spec.sprint_id,
            &request.launch_id,
        ) {
            Ok(durable_launch) => durable_launch,
            Err(error) => {
                let detail = format!(
                    "live-state-verifier post-launch durable readback failed and cleanup remains required: {error}"
                );
                return retain_crossed_live_state_verifier_launch_cleanup(
                    self,
                    prospective,
                    client,
                    &detail,
                );
            }
        };
        if client.launch != durable_launch
            || client.session().session_id != request.session_id
            || client.session().launch_id != request.launch_id
        {
            return retain_crossed_live_state_verifier_launch_cleanup(
                self,
                prospective,
                client,
                "live-state-verifier launch returned crossed role, launch, session, or task authority",
            );
        }
        let binding = ActiveLiveStateVerifierBinding {
            identity: prospective,
            launch_request: request,
        };
        let boundary = live_state_verifier_boundary(&binding, &client);
        self.state = DesktopRunnerLifecycleState::ActiveLiveStateVerifier { binding, client };
        Ok(boundary)
    }

    #[cfg(test)]
    pub(in crate::runner_client) fn ensure_sprint_live_state_verifier_with_test_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonLiveStateVerifierStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        self.ensure_sprint_live_state_verifier_with_io(ledger, start, launch, load_launch)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one linear transition validates the application request, immutable bundle, Applier launch, recovery handshake, and retained cleanup custody"
    )]
    pub(super) fn ensure_sprint_application_applier_with_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonApplicationStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        match &self.state {
            DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client } => {
                validate_repeated_application_start(binding, client, start)?;
                return Ok(application_boundary(binding, client));
            }
            DesktopRunnerLifecycleState::Idle => {}
            DesktopRunnerLifecycleState::ActiveClient { .. }
            | DesktopRunnerLifecycleState::CleanupRequired { .. }
            | DesktopRunnerLifecycleState::ActiveFinalVerifier { .. }
            | DesktopRunnerLifecycleState::FinalVerifierCleanupRequired { .. }
            | DesktopRunnerLifecycleState::ActiveLiveStateVerifier { .. }
            | DesktopRunnerLifecycleState::LiveStateVerifierCleanupRequired { .. } => {
                return Err(protocol(
                    "worker, final-verifier, or live-state-verifier custody forbids launching the application Applier",
                ));
            }
            DesktopRunnerLifecycleState::ApplicationCleanupRequired { .. } => {
                return Err(protocol(
                    "application Applier cleanup is required before another launch",
                ));
            }
            DesktopRunnerLifecycleState::ReconciliationRequired { .. } => {
                return Err(protocol(
                    "runner reconciliation is required before application launch",
                ));
            }
        }

        validate_application_request_bundle(start.request, start.stage_bundle)?;
        let request = application_launch_request(&self.config, start);
        let prospective = ApplicationBinding {
            sprint: request.sprint_id.clone(),
            launch: request.launch_id.clone(),
            session: request.session_id.clone(),
            request: start.request.clone(),
            stage_bundle: start.stage_bundle.clone(),
        };
        let client = match launch(ledger, request.clone()) {
            Ok(client) => client,
            Err(failure) => {
                let detail = failure.error().to_string();
                let (_error, cleanup) = failure.into_parts();
                if let Some(cleanup) = cleanup {
                    self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                        binding: prospective,
                        cleanup,
                    };
                } else {
                    self.state = DesktopRunnerLifecycleState::Idle;
                }
                return Err(protocol(format!(
                    "application Applier launch failed: {detail}"
                )));
            }
        };
        if client.task_attempt_running_boundary().is_some() {
            return retain_crossed_application_launch_cleanup(
                self,
                prospective,
                client,
                "application Applier launch returned task-running authority",
            );
        }
        let durable_launch = match load_launch(
            ledger,
            &start.sprint_spec.sprint_id,
            &request.launch_id,
        ) {
            Ok(durable_launch) => durable_launch,
            Err(error) => {
                let detail = format!(
                    "application Applier post-launch durable readback failed and cleanup remains required: {error}"
                );
                return retain_crossed_application_launch_cleanup(
                    self,
                    prospective,
                    client,
                    &detail,
                );
            }
        };
        if client.launch != durable_launch
            || client.session().session_id != request.session_id
            || client.session().launch_id != request.launch_id
        {
            return retain_crossed_application_launch_cleanup(
                self,
                prospective,
                client,
                "application Applier launch returned crossed role, launch, or session authority",
            );
        }
        let binding = ActiveApplicationBinding {
            identity: prospective,
            launch_request: request,
        };
        let (client, _recovery) = match client.send_control(RunnerRequest::ApplierRecoverPending) {
            Ok(recovered) => recovered,
            Err(failure) => {
                let detail = failure.error().to_string();
                let cleanup = failure.into_cleanup_required();
                self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                    binding: binding.into_identity(),
                    cleanup,
                };
                return Err(protocol(format!(
                    "application Applier startup recovery failed and cleanup remains required: {detail}"
                )));
            }
        };
        let capture_at = client.session().registered_at_unix_ms;
        let (client, _capture) = match client.send_control(RunnerRequest::ApplierCaptureLive {
            created_at_unix_ms: capture_at,
        }) {
            Ok(captured) => captured,
            Err(failure) => {
                let detail = failure.error().to_string();
                let cleanup = failure.into_cleanup_required();
                self.state = DesktopRunnerLifecycleState::ApplicationCleanupRequired {
                    binding: binding.into_identity(),
                    cleanup,
                };
                return Err(protocol(format!(
                    "application Applier live capture failed and cleanup remains required: {detail}"
                )));
            }
        };
        let boundary = application_boundary(&binding, &client);
        self.state = DesktopRunnerLifecycleState::ActiveApplicationApplier { binding, client };
        Ok(boundary)
    }

    #[cfg(test)]
    pub(in crate::runner_client) fn ensure_sprint_application_applier_with_test_io<L, R>(
        &mut self,
        ledger: &mut EventLedger,
        start: &WalkingSkeletonApplicationStart<'_>,
        launch: L,
        load_launch: R,
    ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError>
    where
        L: FnOnce(
            &mut EventLedger,
            RunnerClientLaunch,
        ) -> Result<RunnerLifecycleClient, RunnerLaunchFailure>,
        R: FnOnce(&EventLedger, &str, &str) -> Result<RunnerLaunchIntent, LedgerError>,
    {
        self.ensure_sprint_application_applier_with_io(ledger, start, launch, load_launch)
    }
}

impl ReconciliationCustody {
    pub(super) fn view(&self) -> ReconciliationCustodyView<'_> {
        match self {
            Self::DurableOnly => ReconciliationCustodyView::DurableOnly,
            Self::LiveClient { binding, .. } => ReconciliationCustodyView::LiveClient {
                binding: binding.view(),
            },
            Self::Cleanup { binding, cleanup } => ReconciliationCustodyView::Cleanup {
                binding: binding.view(),
                cleanup,
            },
            Self::LiveFinalVerifier { binding, .. } => {
                ReconciliationCustodyView::LiveFinalVerifier {
                    binding: binding.view(),
                }
            }
            Self::FinalVerifierCleanup { binding, cleanup } => {
                ReconciliationCustodyView::FinalVerifierCleanup {
                    binding: binding.view(),
                    cleanup,
                }
            }
            Self::LiveStateVerifier { binding, .. } => {
                ReconciliationCustodyView::LiveStateVerifier {
                    binding: binding.view(),
                }
            }
            Self::LiveStateVerifierCleanup { binding, cleanup } => {
                ReconciliationCustodyView::LiveStateVerifierCleanup {
                    binding: binding.view(),
                    cleanup,
                }
            }
            Self::LiveApplicationApplier { binding, .. } => {
                ReconciliationCustodyView::LiveApplicationApplier {
                    binding: binding.view(),
                }
            }
            Self::ApplicationCleanup { binding, cleanup } => {
                ReconciliationCustodyView::ApplicationCleanup {
                    binding: binding.view(),
                    cleanup,
                }
            }
        }
    }
}

#[derive(Serialize)]
pub(super) struct NoRequestCommandDomainEvidenceV1<'a> {
    pub(super) schema: &'static str,
    pub(super) sprint_id: &'a str,
    pub(super) launch_id: &'a str,
    pub(super) session_id: &'a str,
    pub(super) effect_id: &'a str,
    pub(super) request_digest: &'a Digest,
    pub(super) capture_id: &'a str,
    pub(super) acquired_anchor_digest: &'a Digest,
    pub(super) dispatch_claim_id: &'a str,
    pub(super) cleanup_claim_id: &'a str,
    pub(super) cleanup_fencing_token: &'a Digest,
    pub(super) cleaned_store_head: &'a grok_build_core::CommandOutputCaptureStoreHeadV1,
    pub(super) backend: CommandDomainBackend,
    pub(super) accepted_request_bytes: u8,
}

#[allow(
    clippy::too_many_lines,
    reason = "zero-byte refusal must fence physical cleanup, release the core claim, and retain one exact no-domain proof"
)]
pub(super) fn clean_zero_byte_command_capture<F>(
    ledger: &mut EventLedger,
    private_state_root: &Path,
    effect: &PersistedEffect,
    take_post_cleanup_timestamp: F,
) -> Result<(ValidatedCommandCaptureAbandonment, u64), DurableCoordinatorError>
where
    F: FnOnce(u64) -> Result<u64, DurableCoordinatorError>,
{
    let capture = ledger.load_command_output_capture_for_effect(&effect.intent.effect_id)?;
    let acquired = capture.acquired.as_ref().ok_or_else(|| {
        protocol("zero-byte command refusal lacks its atomically acquired capture")
    })?;
    let claim = effect.dispatch_claim.as_ref().ok_or_else(|| {
        protocol("zero-byte command refusal lacks its exact durable dispatch claim")
    })?;
    if effect.observation.is_some()
        || capture.terminal.is_some()
        || acquired.dispatch_claim_id != claim.dispatch_claim_id
        || acquired.source.effect_id != effect.intent.effect_id
        || acquired.source.request_digest != effect.intent.request_digest
    {
        return Err(protocol(
            "zero-byte command refusal crossed effect, acquisition, or dispatch authority",
        ));
    }

    let store = CapabilityCommandOutputStore::open(private_state_root)
        .map_err(|error| protocol(error.to_string()))?;
    let recovery = store
        .reopen_capture(&capture.intent.capture_id)
        .map_err(|error| protocol(error.to_string()))?;
    if recovery.state() != CommandOutputCaptureJournalStateV1::Acquired
        || recovery.acquired() != Some(acquired)
        || recovery.store_head() != &acquired.store_head
    {
        return Err(protocol(
            "zero-byte command refusal capture is not the exact untouched Acquired reservation",
        ));
    }

    let claimed_at_unix_ms = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(acquired.acquired_at_unix_ms);
    let expires_at_unix_ms = claimed_at_unix_ms
        .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
        .ok_or_else(|| protocol("command capture cleanup claim timestamp overflow"))?;
    let cleanup_claim_id =
        fresh_command_output_capture_id().map_err(|error| protocol(error.to_string()))?;
    let reconciliation = ledger.claim_command_output_capture_reconciliation(
        &capture.intent.capture_id,
        &cleanup_claim_id,
        "desktop-zero-byte-command-capture-cleanup-v1",
        claimed_at_unix_ms,
        expires_at_unix_ms,
    )?;
    let reconciliation_permit = match reconciliation {
        CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
        CommandOutputCaptureReconciliationAdmission::Busy(_) => {
            return Err(protocol(
                "zero-byte command capture cleanup is owned by another reconciliation claimant",
            ));
        }
        CommandOutputCaptureReconciliationAdmission::Terminal(_) => {
            return Err(protocol(
                "zero-byte command capture unexpectedly became terminal before cleanup",
            ));
        }
    };
    let exact_claim = reconciliation_permit.claim().clone();
    let cleaned = store
        .cleanup_capture(&exact_claim, recovery.store_head())
        .map_err(|error| protocol(error.to_string()))?;
    if cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
        || cleaned.acquired() != Some(acquired)
        || cleaned.cleaned_store_head() != Some(cleaned.store_head())
        || cleaned.cleaned_record_digest() != Some(cleaned.head_digest())
    {
        return Err(protocol(
            "zero-byte command capture cleanup lacks exact immutable Cleaned readback",
        ));
    }
    let post_cleanup_minimum = current_unix_ms()
        .map_err(|error| protocol(error.to_string()))?
        .max(claimed_at_unix_ms);
    let released_at_unix_ms = take_post_cleanup_timestamp(post_cleanup_minimum)?;
    if released_at_unix_ms >= exact_claim.expires_at_unix_ms {
        return Err(protocol(
            "zero-byte command capture cleanup exceeded its reconciliation lease",
        ));
    }
    let released = ledger.release_command_output_capture_reconciliation(
        reconciliation_permit,
        released_at_unix_ms,
    )?;
    if released != exact_claim {
        return Err(protocol(
            "zero-byte command capture cleanup released a crossed reconciliation claim",
        ));
    }

    let launch_cleanup =
        ledger.load_runner_launch_cleanup_admission(&effect.intent.sprint_id, &claim.launch_id)?;
    let command_domain_backend = match launch_cleanup.cleanup_request.platform_backend {
        WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
        WorkerCleanupBackend::MacOsDedicatedIdentity => {
            CommandDomainBackend::MacOsDedicatedIdentity
        }
        WorkerCleanupBackend::TrustedApplierDirectChildWait => {
            return Err(protocol(
                "RunCommand zero-byte cleanup cannot use the trusted-Applier backend",
            ));
        }
    };
    let cleaned_store_head = cleaned.store_head().clone();
    let cleanup_record_digest = cleaned
        .cleaned_record_digest()
        .expect("validated Cleaned recovery has its record digest")
        .clone();
    let no_domain_proof_bytes = serde_json::to_vec(&NoRequestCommandDomainEvidenceV1 {
        schema: "grok-build.desktop.no-request-command-domain-evidence.v1",
        sprint_id: &effect.intent.sprint_id,
        launch_id: &claim.launch_id,
        session_id: &claim.session_id,
        effect_id: &effect.intent.effect_id,
        request_digest: &effect.intent.request_digest,
        capture_id: &capture.intent.capture_id,
        acquired_anchor_digest: &acquired.acquired_anchor_digest,
        dispatch_claim_id: &claim.dispatch_claim_id,
        cleanup_claim_id: &exact_claim.claim_id,
        cleanup_fencing_token: &exact_claim.fencing_token,
        cleaned_store_head: &cleaned_store_head,
        backend: command_domain_backend,
        accepted_request_bytes: 0,
    })
    .map_err(|error| protocol(format!("no-domain proof encode failed: {error}")))?;
    let abandonment = ValidatedCommandCaptureAbandonment::try_new(
        acquired.clone(),
        cleaned_store_head,
        cleanup_record_digest,
        command_domain_backend,
        no_domain_proof_bytes,
        released_at_unix_ms,
    )?;
    Ok((abandonment, released_at_unix_ms))
}
