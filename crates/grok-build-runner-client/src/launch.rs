//! Retained executable admission and authenticated runner launch.

use super::*;

impl RunnerLifecycleClient {
    /// Authenticates, records, launches and initializes one runner session.
    ///
    /// Linux hashes the retained binary, seals a memfd copy and executes that image.
    /// Targets without an admitted descriptor-exec bridge refuse before persistence.
    /// Launch requires durable role authority, atomic launch/cleanup admission,
    /// initialization evidence, a fresh nonce and session registration before the
    /// `Leased -> Running` boundary. A direct child proves no command containment;
    /// that requires the runner's separate backend checks.
    ///
    /// # Errors
    ///
    /// Returns a failure for invalid authority, identity drift, persistence, spawn,
    /// initialization, evidence or registration errors. Failures after durable
    /// launch admission carry a mandatory cleanup handoff, even if no child starts.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "launch consumes its identity to prevent caller reuse; pre-spawn durability and initialization remain one auditable boundary"
    )]
    pub fn launch(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
    ) -> Result<Self, RunnerLaunchFailure> {
        ensure_native_ordinary_platform_launch_binding_available(request.role)
            .map_err(|error| launch_failure(error, None))?;
        Self::launch_as_direct_child(
            ledger,
            authority,
            compiled_policy,
            request,
            None,
            "ordinary",
        )
    }

    /// Shared ordinary launch body for the direct-child spawn boundary.
    ///
    /// Both public ordinary entry points reach the same
    /// [`Self::launch_with_ledger_and_spawner`] authority chain; they differ
    /// only in the role-input authority they supply. The spawn callback runs
    /// after the atomic launch/cleanup admission commits, so its refusals carry
    /// the mandatory cleanup handoff.
    fn launch_as_direct_child(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
        explicit_role_input_authority: Option<RunnerRoleInputAuthority>,
        boundary: &'static str,
    ) -> Result<Self, RunnerLaunchFailure> {
        Self::launch_with_ledger_and_spawner(
            RunnerLaunchLedger::Ordinary(ledger),
            authority,
            compiled_policy,
            request,
            explicit_role_input_authority,
            move |launch_ledger, executable, admission, binding, input_snapshot| {
                let RunnerLaunchLedger::Ordinary(_) = launch_ledger else {
                    return Err(Box::new(RunnerLaunchBoundaryFailure {
                        error: RunnerClientError::InvalidLifecycle(format!(
                            "{boundary} direct-child launch received operation-local authority"
                        )),
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                        platform_binding: None,
                        native_cleanup_custody: None,
                        cleanup_required: false,
                    }));
                };
                let admission = admission.expect("ordinary durable launch has an admission");
                let binding = binding.expect("ordinary durable launch has a platform binding");
                spawn_ordinary_direct_child(admission, binding, input_snapshot, executable)
            },
        )
    }

    /// Launches one fresh read-only live-state verifier initialized from an
    /// exact core-derived finalization plan.
    ///
    /// Like [`Self::launch`], this reaches the shared direct-child spawn
    /// boundary only where the descriptor-exec bridge exists. The explicit plan
    /// is required at this boundary so no generic role-input snapshot can
    /// initialize a live-state verifier, and it becomes the launch's exact
    /// [`RunnerRoleInputAuthority::LiveStateFinalization`] authority.
    ///
    /// # Errors
    ///
    /// Returns a launch failure for a crossed role, plan digest, durable plan,
    /// snapshot, policy, grant, or unavailable native service.
    #[allow(clippy::needless_pass_by_value)] // Mirrors `launch`: the request is consumed so a caller cannot reuse one identity.
    pub fn launch_live_state_verifier(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        plan: &grok_build_core::SprintLiveStateCapturePlan,
        request: RunnerClientLaunch,
    ) -> Result<Self, RunnerLaunchFailure> {
        if request.role != RunnerRole::LiveStateVerifier
            || request.expected_base_snapshot != plan.expected_snapshot
        {
            return Err(launch_failure(
                RunnerClientError::InvalidLifecycle(
                    "live-state verifier launch request differs from its finalization plan".into(),
                ),
                None,
            ));
        }
        plan.validate().map_err(|error| {
            launch_failure(RunnerClientError::InvalidLifecycle(error.to_string()), None)
        })?;
        ensure_native_ordinary_platform_launch_binding_available(request.role)
            .map_err(|error| launch_failure(error, None))?;
        let role_input_authority = RunnerRoleInputAuthority::LiveStateFinalization {
            plan: Box::new(plan.clone()),
            plan_digest: plan.plan_digest().map_err(|error| {
                launch_failure(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            })?,
        };
        Self::launch_as_direct_child(
            ledger,
            authority,
            compiled_policy,
            request,
            Some(role_input_authority),
            "live-state verifier",
        )
    }

    /// Launches one fresh executor or recovery validator for an already
    /// committed post-completion rollback operation.
    ///
    /// This follows the ordinary authority, retained-executable, initialization,
    /// and nonce checks, but commits the launch and session only through the
    /// schema-v12 post-completion operation tables. It never writes the ordinary
    /// launch/session tables and never changes the completed sprint state.
    ///
    /// # Errors
    ///
    /// Returns a launch failure for any preflight, persistence, spawn,
    /// initialization, or registration failure. Once the post-completion launch
    /// commits, every failure carries a mandatory cleanup handoff, including a
    /// descriptor refusal or an uninitialized child.
    #[allow(
        clippy::too_many_lines,
        reason = "post-completion launch reuses the auditable shared launch boundary"
    )]
    pub fn launch_post_completion_rollback(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        operation: &PostCompletionRollbackIntent,
        role: PostCompletionRollbackApplierRole,
        request: RunnerClientLaunch,
    ) -> Result<Self, RunnerLaunchFailure> {
        ensure_descriptor_execution_supported().map_err(|error| launch_failure(error, None))?;
        validate_post_completion_launch_request(operation, compiled_policy, &request)
            .map_err(|error| launch_failure(error, None))?;
        Self::launch_post_completion_rollback_with_spawner(
            ledger,
            authority,
            compiled_policy,
            operation,
            role,
            request,
            |executable, expected_binding| {
                debug_assert!(expected_binding.is_none());
                RunnerProcess::spawn(executable).map(|process| RunnerSpawnOutcome {
                    process: Box::new(process) as Box<dyn RunnerTransport>,
                    platform_binding: None,
                    native_cleanup_custody: None,
                })
            },
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the test-injectable launch preserves one auditable persistence/spawn/session boundary"
    )]
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn launch_with_spawner<F>(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
        spawn: F,
    ) -> Result<Self, RunnerLaunchFailure>
    where
        F: FnOnce(
            &mut RetainedRunnerExecutable,
            Option<&PlatformLaunchBinding>,
        ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError>,
    {
        Self::launch_with_native_service(
            ledger,
            authority,
            compiled_policy,
            request,
            Box::new(SpawnerBackedNativeLaunchService::new(spawn)),
        )
    }

    #[allow(
        dead_code,
        reason = "production ordinary launch remains fail-closed until a target native service is admitted"
    )]
    pub(super) fn launch_with_native_service<'service>(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
        service: Box<dyn NativeLaunchService + 'service>,
    ) -> Result<Self, RunnerLaunchFailure> {
        Self::launch_with_ledger_and_spawner(
            RunnerLaunchLedger::Ordinary(ledger),
            authority,
            compiled_policy,
            request,
            None,
            move |launch_ledger, executable, admission, binding, input_snapshot| {
                let RunnerLaunchLedger::Ordinary(ledger) = launch_ledger else {
                    return Err(Box::new(RunnerLaunchBoundaryFailure {
                        error: RunnerClientError::InvalidLifecycle(
                            "ordinary native launch service received operation-local authority"
                                .into(),
                        ),
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                        platform_binding: None,
                        native_cleanup_custody: None,
                        cleanup_required: false,
                    }));
                };
                let admission = admission.expect("ordinary durable launch has an admission");
                let binding = binding.expect("ordinary durable launch has a platform binding");
                prepare_and_release_ordinary_launch(
                    ledger,
                    admission,
                    binding,
                    input_snapshot,
                    executable,
                    service,
                )
            },
        )
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn launch_live_state_verifier_with_native_service<'service>(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        plan: &SprintLiveStateCapturePlan,
        request: RunnerClientLaunch,
        service: Box<dyn NativeLaunchService + 'service>,
    ) -> Result<Self, RunnerLaunchFailure> {
        if request.role != RunnerRole::LiveStateVerifier
            || request.expected_base_snapshot != plan.expected_snapshot
        {
            return Err(launch_failure(
                RunnerClientError::InvalidLifecycle(
                    "live-state verifier launch request differs from its finalization plan".into(),
                ),
                None,
            ));
        }
        plan.validate().map_err(|error| {
            launch_failure(RunnerClientError::InvalidLifecycle(error.to_string()), None)
        })?;
        let role_input_authority = RunnerRoleInputAuthority::LiveStateFinalization {
            plan: Box::new(plan.clone()),
            plan_digest: plan.plan_digest().map_err(|error| {
                launch_failure(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            })?,
        };
        Self::launch_with_ledger_and_spawner(
            RunnerLaunchLedger::Ordinary(ledger),
            authority,
            compiled_policy,
            request,
            Some(role_input_authority),
            move |launch_ledger, executable, admission, binding, input_snapshot| {
                let RunnerLaunchLedger::Ordinary(ledger) = launch_ledger else {
                    return Err(Box::new(RunnerLaunchBoundaryFailure {
                        error: RunnerClientError::InvalidLifecycle(
                            "live-state native launch service received operation-local authority"
                                .into(),
                        ),
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                        platform_binding: None,
                        native_cleanup_custody: None,
                        cleanup_required: false,
                    }));
                };
                let admission = admission.expect("live-state launch has a cleanup admission");
                let binding = binding.expect("live-state launch has a platform binding");
                prepare_and_release_ordinary_launch(
                    ledger,
                    admission,
                    binding,
                    input_snapshot,
                    executable,
                    service,
                )
            },
        )
    }

    pub(super) fn launch_post_completion_rollback_with_spawner<F>(
        ledger: &mut EventLedger,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        operation: &PostCompletionRollbackIntent,
        role: PostCompletionRollbackApplierRole,
        request: RunnerClientLaunch,
        spawn: F,
    ) -> Result<Self, RunnerLaunchFailure>
    where
        F: FnOnce(
            &mut RetainedRunnerExecutable,
            Option<&PlatformLaunchBinding>,
        ) -> Result<RunnerSpawnOutcome, RunnerProcessSpawnError>,
    {
        validate_post_completion_launch_request(operation, compiled_policy, &request)
            .map_err(|error| launch_failure(error, None))?;
        Self::launch_with_ledger_and_spawner(
            RunnerLaunchLedger::PostCompletionRollback {
                ledger,
                operation_id: &operation.operation_id,
                role,
            },
            authority,
            compiled_policy,
            request,
            None,
            move |_, executable, admission, binding, _| {
                debug_assert!(admission.is_none());
                debug_assert!(binding.is_none());
                spawn(executable, None).map_err(|failure| Box::new(failure.into()))
            },
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "pre-spawn durability and post-spawn initialization remain one auditable authority boundary"
    )]
    pub(super) fn launch_with_ledger_and_spawner<F>(
        mut launch_ledger: RunnerLaunchLedger<'_>,
        authority: &IssuedWorkspaceGrant,
        compiled_policy: &CompiledExecutionPolicy,
        request: RunnerClientLaunch,
        explicit_role_input_authority: Option<RunnerRoleInputAuthority>,
        spawn: F,
    ) -> Result<Self, RunnerLaunchFailure>
    where
        F: FnOnce(
            &mut RunnerLaunchLedger<'_>,
            &mut RetainedRunnerExecutable,
            Option<&PersistedRunnerLaunchCleanupAdmission>,
            Option<&PlatformLaunchBinding>,
            &Digest,
        ) -> RunnerLaunchBoundaryResult,
    {
        let post_completion_role = launch_ledger.post_completion_role();
        let post_completion_operation_id = launch_ledger
            .post_completion_operation_id()
            .map(str::to_owned);
        let role_input_authority = launch_ledger
            .validate_exact_sprint_authority(&request, explicit_role_input_authority)
            .map_err(|error| launch_failure(error, None))?;
        let mut preflight =
            prepare_launch_with_context(authority, compiled_policy, &request, role_input_authority)
                .map_err(|error| launch_failure(error, None))?;
        let initialization = initialization_envelope(&request, &preflight);
        encode_request_frame(&initialization)
            .map_err(|error| launch_failure(error.into(), None))?;
        let durable_launch = match launch_ledger.record_launch(
            &preflight.intent,
            authority,
            compiled_policy,
            &request.expected_base_snapshot,
            &preflight.role_input_authority,
        ) {
            Ok(durable_launch) => durable_launch,
            Err(failure) => {
                let RunnerLaunchPersistenceFailure {
                    mut error,
                    cleanup_admission,
                } = failure;
                let cleanup = cleanup_admission.map(|admission| {
                    let platform_launch_binding =
                        match PlatformLaunchBinding::try_from_admission(
                            &admission,
                            authority,
                            compiled_policy,
                        ) {
                            Ok(binding) => Some(Box::new(binding)),
                            Err(binding_error) => {
                                error = RunnerClientError::InvalidLifecycle(format!(
                                    "{error}; exact post-commit cleanup admission could not reconstruct its platform binding: {binding_error}"
                                ));
                                None
                            }
                        };
                    RunnerCleanupRequired {
                        launch: admission.launch.clone(),
                        launch_cleanup_admission: Some(admission),
                        platform_launch_binding,
                        native_cleanup_custody: None,
                        session_registration: RunnerSessionRegistrationState::NotRegistered,
                        direct_child: DirectChildOutcome::LaunchRefusedBeforeSpawn,
                        shutdown_prepared: None,
                    }
                });
                return Err(launch_failure(error, cleanup));
            }
        };
        let (launch_cleanup_admission, expected_platform_binding) = match durable_launch {
            DurableRunnerLaunch::Ordinary {
                admission,
                platform_binding,
            } => (Some(admission), Some(platform_binding)),
            DurableRunnerLaunch::PostCompletionRollback => (None, None),
        };

        let spawned = match spawn(
            &mut launch_ledger,
            &mut preflight.executable,
            launch_cleanup_admission.as_deref(),
            expected_platform_binding.as_deref(),
            &request.expected_base_snapshot,
        ) {
            Ok(spawned) => spawned,
            Err(error) => {
                let error = *error;
                let returned_binding = error.platform_binding;
                let binding_matches = spawn_failure_binding_matches(
                    &error.direct_child,
                    expected_platform_binding.as_deref(),
                    returned_binding.as_deref(),
                );
                let retained_binding = binding_matches.then_some(returned_binding).flatten();
                let cleanup = error.cleanup_required.then_some(RunnerCleanupRequired {
                    launch: preflight.intent,
                    launch_cleanup_admission,
                    platform_launch_binding: retained_binding,
                    native_cleanup_custody: error.native_cleanup_custody,
                    session_registration: RunnerSessionRegistrationState::NotRegistered,
                    direct_child: error.direct_child,
                    shutdown_prepared: None,
                });
                let error = if binding_matches {
                    error.error
                } else {
                    RunnerClientError::InvalidLifecycle(
                        "spawn boundary did not return the exact expected platform launch state"
                            .into(),
                    )
                };
                return Err(launch_failure(error, cleanup));
            }
        };
        let RunnerSpawnOutcome {
            mut process,
            platform_binding,
            native_cleanup_custody,
        } = spawned;
        if platform_binding != expected_platform_binding {
            let cleanup = finish_transport(
                process,
                preflight.intent,
                launch_cleanup_admission,
                None,
                native_cleanup_custody,
                RunnerSessionRegistrationState::NotRegistered,
                None,
            );
            return Err(launch_failure(
                RunnerClientError::InvalidLifecycle(
                    "spawn boundary returned substituted expected platform launch state".into(),
                ),
                Some(cleanup),
            ));
        }
        let platform_launch_binding = platform_binding;

        let response = match process.exchange(&initialization) {
            Ok(response) => response,
            Err(error) => {
                let cleanup = finish_transport(
                    process,
                    preflight.intent,
                    launch_cleanup_admission,
                    platform_launch_binding,
                    native_cleanup_custody,
                    RunnerSessionRegistrationState::NotRegistered,
                    None,
                );
                return Err(launch_failure(error, Some(cleanup)));
            }
        };
        if let Err(error) = response.validate_correlation(&initialization) {
            let cleanup = finish_transport(
                process,
                preflight.intent,
                launch_cleanup_admission,
                platform_launch_binding,
                native_cleanup_custody,
                RunnerSessionRegistrationState::NotRegistered,
                None,
            );
            return Err(launch_failure(error.into(), Some(cleanup)));
        }
        let receipt = match response.response {
            RunnerResponse::Initialized { receipt } => receipt,
            RunnerResponse::InitializationRejected { code, message } => {
                let cleanup = finish_transport(
                    process,
                    preflight.intent,
                    launch_cleanup_admission,
                    platform_launch_binding,
                    native_cleanup_custody,
                    RunnerSessionRegistrationState::NotRegistered,
                    None,
                );
                return Err(launch_failure(
                    RunnerClientError::InitializationRejected { code, message },
                    Some(cleanup),
                ));
            }
            _ => {
                let cleanup = finish_transport(
                    process,
                    preflight.intent,
                    launch_cleanup_admission,
                    platform_launch_binding,
                    native_cleanup_custody,
                    RunnerSessionRegistrationState::NotRegistered,
                    None,
                );
                return Err(launch_failure(
                    RunnerClientError::UnexpectedResponse("Initialized or InitializationRejected"),
                    Some(cleanup),
                ));
            }
        };
        if let Err(error) = validate_initialization_receipt(&receipt, &request, &preflight) {
            let cleanup = finish_transport(
                process,
                preflight.intent,
                launch_cleanup_admission,
                platform_launch_binding,
                native_cleanup_custody,
                RunnerSessionRegistrationState::NotRegistered,
                None,
            );
            return Err(launch_failure(error, Some(cleanup)));
        }
        if let Err(error) = admit_fresh_nonce(&receipt.runner_nonce) {
            let cleanup = finish_transport(
                process,
                preflight.intent,
                launch_cleanup_admission,
                platform_launch_binding,
                native_cleanup_custody,
                RunnerSessionRegistrationState::NotRegistered,
                None,
            );
            return Err(launch_failure(error, Some(cleanup)));
        }

        let registered_at_unix_ms =
            match current_unix_ms().map(|timestamp| timestamp.max(request.created_at_unix_ms)) {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    let cleanup = finish_transport(
                        process,
                        preflight.intent,
                        launch_cleanup_admission,
                        platform_launch_binding,
                        native_cleanup_custody,
                        RunnerSessionRegistrationState::NotRegistered,
                        None,
                    );
                    return Err(launch_failure(error, Some(cleanup)));
                }
            };
        let session = RunnerSessionPolicyRecord {
            contract_version: CONTRACT_VERSION,
            sprint_id: request.sprint_id,
            launch_id: request.launch_id,
            session_id: request.session_id,
            purpose: preflight.intent.purpose,
            worker_id: request.worker_id,
            worker_lease: preflight.intent.worker_lease.clone(),
            policy_hash: compiled_policy.contract().policy_hash.clone(),
            session_nonce: receipt.runner_nonce.clone(),
            runner_binary_digest: preflight.binary_digest,
            protocol_digest: preflight.protocol_digest,
            private_state_digest: preflight.private_state_digest,
            grant_hash: authority.contract().grant_hash.clone(),
            policy_version: authority.contract().policy_version,
            registered_at_unix_ms,
        };
        if let Err(error) = launch_ledger.register_session(
            &session,
            compiled_policy,
            &preflight.role_input_authority,
        ) {
            let registration = launch_ledger.registration_state_after_error(&session);
            let cleanup = finish_transport(
                process,
                preflight.intent,
                launch_cleanup_admission,
                platform_launch_binding,
                native_cleanup_custody,
                registration,
                None,
            );
            return Err(launch_failure(error.into(), Some(cleanup)));
        }
        let task_attempt_running =
            match launch_ledger.start_worker_attempt(&preflight.intent, &session) {
                Ok(boundary) => boundary,
                Err(error) => {
                    let registration = launch_ledger.registration_state_after_error(&session);
                    let cleanup = finish_transport(
                        process,
                        preflight.intent,
                        launch_cleanup_admission,
                        platform_launch_binding,
                        native_cleanup_custody,
                        registration,
                        None,
                    );
                    return Err(launch_failure(error, Some(cleanup)));
                }
            };

        let private_state_root = PathBuf::from(&preflight.private_state_root_text);
        let mut seen_request_ids = BTreeSet::new();
        seen_request_ids.insert(initialization.request_id);
        let role = request.role;
        Ok(Self {
            launch: preflight.intent,
            private_state_root,
            launch_cleanup_admission,
            platform_launch_binding,
            native_cleanup_custody,
            session,
            task_attempt_running,
            role,
            role_input_authority: preflight.role_input_authority,
            post_completion_role,
            post_completion_operation_id,
            runner_nonce: receipt.runner_nonce,
            next_sequence: 1,
            worker_commands_dispatched: 0,
            seen_request_ids,
            seen_effect_ids: BTreeSet::new(),
            seen_idempotency_keys: BTreeSet::new(),
            expected_base_snapshot: request.expected_base_snapshot,
            grant_hash: preflight.wire_grant.grant_hash,
            captured_base: false,
            shadow_created: false,
            shadow_snapshot: None,
            prepared_stage: None,
            applier_recovery_complete: false,
            pending_reconciliation: None,
            process,
            installed_service_command_release: false,
        })
    }

    fn encode_installed_service_command_frame(
        &self,
        envelope: &RunnerRequestEnvelopeV12,
    ) -> Result<Vec<u8>, RunnerClientError> {
        let (binding_canonical_bytes, binding_digest) =
            if let Some(binding) = self.platform_launch_binding.as_ref() {
                (
                    binding.canonical_bytes().to_vec(),
                    binding.binding_digest().clone(),
                )
            } else {
                let bytes = b"grok-build-plus-installed-service-binding-v1".to_vec();
                let digest = Digest::sha256(&bytes);
                (bytes, digest)
            };
        let cleanup_effect_id = self
            .launch_cleanup_admission
            .as_ref()
            .map(|admission| admission.cleanup_effect.intent.effect_id.clone())
            .or_else(|| {
                self.platform_launch_binding
                    .as_ref()
                    .map(|binding| binding.cleanup_effect_id().to_owned())
            })
            .unwrap_or_else(|| format!("{}-cleanup", envelope.effect.launch_id));
        let native_journal_id = format!("{}-installed-service-journal", envelope.effect.launch_id);
        let preparation = WireRunnerLaunchPreparationV1 {
            attempt: RunnerLaunchPreparationAttempt {
                contract_version: envelope.effect.contract_version,
                attempt_id: format!("{}-installed-service-prep", envelope.effect.launch_id),
                sprint_id: envelope.effect.sprint_id.clone(),
                launch_id: envelope.effect.launch_id.clone(),
                cleanup_effect_id,
                native_journal_id,
                expected_platform_binding_digest: binding_digest.clone(),
                claimed_at_unix_ms: self.session.registered_at_unix_ms,
            },
            binding_canonical_bytes,
            binding_digest,
        };
        let release = WireContainedCommandReleaseAuthorityV1 {
            command_effect_id: envelope.effect.effect_id.clone(),
            request_digest: envelope.effect.request_digest.clone(),
            native_evidence_digest: preparation.binding_digest.clone(),
        };
        let mut v15 = RunnerRequestEnvelopeV15 {
            protocol_version: 15,
            session_id: envelope.session_id.clone(),
            runner_nonce: envelope.runner_nonce.clone(),
            sequence: envelope.sequence,
            request_id: envelope.request_id.clone(),
            effect: envelope.effect.clone(),
            request: envelope.request.clone(),
            contained_command_release: Some(release),
            runner_launch_preparation: Some(preparation),
        };
        v15.bind_transport_commitment_digest()
            .map_err(RunnerClientError::from)?;
        encode_request_frame_v15(&v15).map_err(RunnerClientError::from)
    }

    /// Drained runner-process stderr (containment refusals are printed there).
    #[must_use]
    pub fn runner_stderr_diagnostics(&self) -> String {
        String::from_utf8_lossy(self.process.stderr_diagnostics()).into_owned()
    }

    /// Operating-system pid of the live runner child, if this is a process transport.
    #[must_use]
    pub fn runner_os_pid(&self) -> Option<u32> {
        self.process.os_pid()
    }

    /// Durable registered runner session.
    #[must_use]
    pub const fn session(&self) -> &RunnerSessionPolicyRecord {
        &self.session
    }

    /// Exact launch intent committed before this session initialized.
    #[must_use]
    pub const fn launch_intent(&self) -> &grok_build_core::RunnerLaunchIntent {
        &self.launch
    }

    /// Exact canonical lifecycle private-state root authenticated at launch.
    #[must_use]
    pub fn private_state_root(&self) -> &Path {
        &self.private_state_root
    }

    /// Exact durable `Leased -> Running` authority for a task-worker session.
    /// Final-verifier, applier, and post-completion sessions return `None`.
    #[must_use]
    pub const fn task_attempt_running_boundary(&self) -> Option<&TaskAttemptRunningBoundary> {
        self.task_attempt_running.as_ref()
    }

    /// Exact durable authority selecting the initialized role input snapshot.
    #[must_use]
    pub const fn role_input_authority(&self) -> &RunnerRoleInputAuthority {
        &self.role_input_authority
    }

    /// Exact atomic ordinary launch/cleanup authority retained for the full
    /// process lifetime. Post-completion operation-local sessions return
    /// `None` because their authority remains in the rollback tables.
    #[must_use]
    pub fn launch_cleanup_admission(&self) -> Option<&PersistedRunnerLaunchCleanupAdmission> {
        self.launch_cleanup_admission.as_deref()
    }

    /// Exact expected platform-launch state retained across the private fake
    /// service. This value is neither a live spawn claim nor containment
    /// evidence.
    #[cfg(test)]
    #[must_use]
    #[allow(dead_code)]
    pub(super) fn expected_platform_launch_binding(&self) -> Option<&PlatformLaunchBinding> {
        self.platform_launch_binding.as_deref()
    }

    /// Sends one exact effect only after its intent, request preimage, proposal
    /// event, and session binding commit atomically in the core ledger.
    ///
    /// The method consumes and returns the client. Therefore any ambiguous I/O
    /// or correlation failure cannot accidentally reuse the same session or
    /// launch through this value.
    ///
    /// # Errors
    ///
    /// Returns a fatal session failure with the mandatory cleanup handoff.
    #[allow(
        clippy::too_many_arguments,
        reason = "the effect transport keeps every exact core persistence input explicit"
    )]
    pub fn send_effect(
        self,
        ledger: &mut EventLedger,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        proposal: &AgentEvent,
        request: RunnerRequest,
    ) -> Result<(Self, ClaimedRunnerEffectResponse), RunnerEffectSessionFailure> {
        if matches!(
            &request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ) {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "generic v11 send_effect rejects RunCommand before any durable intent or claim write"
                        .into(),
                ),
                None,
            ));
        }
        let dispatch_class = RunnerTaskEffectDispatchClass::TaskRunning;
        if let Err(error) = validate_task_dispatch_request(dispatch_class, &request) {
            return Err(self.fail_effect(error, None));
        }
        if let Err(error) = self.validate_effect_request(intent, core_request_bytes, &request) {
            return Err(self.fail_effect(error, None));
        }
        let (_, dispatch_permit) = match ledger.record_runner_effect_intent_for_dispatch(
            intent,
            core_request_bytes,
            proposal,
            &self.session.session_id,
        ) {
            Ok(committed) => committed,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };

        self.send_effect_with_dispatch_permit(
            ledger,
            dispatch_permit,
            dispatch_class,
            intent,
            core_request_bytes,
            request,
        )
    }

    /// Sends one already committed effect by consuming the fresh, non-reloadable
    /// capability minted with that exact intent and runner-session binding.
    ///
    /// Unlike [`Self::send_effect`], this method does not insert a second
    /// intent. It performs only the short immutable dispatch-claim transaction
    /// immediately before transport. It exists for coordinators that committed
    /// the intent before transferring ownership of the initialized client.
    /// Recovered durable state cannot construct the required fresh capability.
    ///
    /// The method consumes both client and permit. Every command request must
    /// arrive through a role-specific adapter that prevalidates the canonical
    /// core command and injects its freshly reserved v27 capture anchor.
    ///
    /// # Errors
    ///
    /// Returns a fatal session failure with the mandatory cleanup handoff when
    /// the request is forbidden, client state is crossed, permit authority is
    /// crossed, or the exchange cannot be proven exact.
    pub fn send_precommitted_effect(
        self,
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        request: RunnerRequest,
    ) -> Result<(Self, ClaimedRunnerEffectResponse), RunnerEffectSessionFailure> {
        let dispatch_class = match task_dispatch_class(&dispatch_permit) {
            Ok(class) => class,
            Err(error) => return Err(self.fail_effect(error, None)),
        };
        if dispatch_class == RunnerTaskEffectDispatchClass::SprintLiveStateCapture {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "live-state capture requires the sealed specialized dispatch boundary".into(),
                ),
                None,
            ));
        }
        if matches!(
            &request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ) {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "RunCommand requires the policy-bound additive-v12 command boundary".into(),
                ),
                None,
            ));
        }
        if let Err(error) = validate_task_dispatch_request(dispatch_class, &request) {
            return Err(self.fail_effect(error, None));
        }
        if let Err(error) = self.validate_effect_request(intent, core_request_bytes, &request) {
            return Err(self.fail_effect(error, None));
        }
        self.send_effect_with_dispatch_permit(
            ledger,
            dispatch_permit,
            dispatch_class,
            intent,
            core_request_bytes,
            request,
        )
    }

    fn reserve_command_output_capture_anchor(
        &self,
        dispatch_permit: &FreshRunnerEffectDispatchPermit,
    ) -> Result<
        (
            WireCommandOutputCaptureAnchorV1,
            SensitiveOutputDetectionPolicyReferenceV1,
        ),
        RunnerClientError,
    > {
        let capture_intent = dispatch_permit.output_capture_intent().ok_or_else(|| {
            RunnerClientError::InvalidLifecycle(
                "RunCommand dispatch lacks its atomically committed output-capture intent".into(),
            )
        })?;
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .ok_or_else(|| {
                RunnerClientError::InvalidLifecycle(
                    "RunCommand capture permit omitted its deterministic dispatch claim identity"
                        .into(),
                )
            })?;
        let detector_policy = dispatch_permit
            .sensitive_output_detection_policy()
            .ok_or_else(|| {
                RunnerClientError::InvalidLifecycle(
                    "RunCommand capture permit omitted its atomically admitted sensitive-output detector policy"
                        .into(),
                )
            })?;
        detector_policy
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        if capture_intent.source.sprint_id != self.launch.sprint_id
            || capture_intent.source.runner_launch_id != self.launch.launch_id
            || capture_intent.source.runner_session_id != self.session.session_id
            || capture_intent.private_state_digest != self.launch.private_state_digest
            || capture_intent.private_state_digest != self.session.private_state_digest
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "output-capture intent differs from the active runner lifecycle or private-state root"
                    .into(),
            ));
        }
        let acquired_at_unix_ms = current_unix_ms()?.max(capture_intent.created_at_unix_ms);
        let store = CapabilityCommandOutputStore::open(&self.private_state_root)?;
        let reservation = store.reserve_anchored_capture_v2(
            capture_intent,
            &dispatch_claim_id,
            acquired_at_unix_ms,
            detector_policy,
        )?;
        let acquired = reservation.into_acquired_anchor_for_handoff()?;
        let anchor = WireCommandOutputCaptureAnchorV1::try_new(acquired)?;
        Ok((anchor, detector_policy.clone()))
    }

    /// Sends one ordinary provider `RunCommand` through its exact task-Running
    /// authority and atomically admitted v27 output-capture lifecycle.
    ///
    /// The canonical provider tool call remains the core request preimage. The
    /// command is projected to a no-shell wire argv only after exact
    /// sprint/task/idempotency/effect validation, then the capture is reserved
    /// immediately before the dispatch claim. No uncaptured command request is
    /// constructible through this method.
    ///
    /// # Errors
    ///
    /// Returns a consuming session failure for a non-command provider call,
    /// crossed task authority, invalid UTF-8 working directory, failed capture
    /// reservation, claim failure, transport ambiguity, or rejected response.
    pub fn send_precommitted_task_command(
        self,
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        provider_call: &ProviderToolCall,
    ) -> Result<(Self, ClaimedRunnerCommandEffectResponse), RunnerEffectSessionFailure> {
        if let Err(error) = validate_worker_provider_call_context(provider_call, intent) {
            return Err(self.fail_effect(error, None));
        }
        let ProviderToolIntent::RunCommand { command } = &provider_call.intent else {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "ordinary command dispatch requires exact ProviderToolIntent::RunCommand"
                        .into(),
                ),
                None,
            ));
        };
        let canonical_command = match serde_json::to_vec(command) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "ordinary command cannot be canonically encoded: {error}"
                    )),
                    None,
                ));
            }
        };
        if canonical_command != core_request_bytes {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "ordinary command core request differs from its exact provider command".into(),
                ),
                None,
            ));
        }
        if let Err(error) = command.validate() {
            return Err(
                self.fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            );
        }
        let working_directory = match command.working_directory.to_str() {
            Some(path) => path.to_owned(),
            None => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "ordinary command working directory is not exact UTF-8".into(),
                    ),
                    None,
                ));
            }
        };
        if let Err(error) = self.validate_command_effect_before_output_capture(
            intent,
            core_request_bytes,
            RunnerRole::Worker,
        ) {
            return Err(self.fail_effect(error, None));
        }
        let (output_capture, detector_policy) =
            match self.reserve_command_output_capture_anchor(&dispatch_permit) {
                Ok(capture) => capture,
                Err(error) => return Err(self.fail_effect(error, None)),
            };
        self.send_command_with_dispatch_permit(
            ledger,
            dispatch_permit,
            RunnerTaskEffectDispatchClass::TaskRunning,
            intent,
            core_request_bytes,
            RunnerRequest::WorkerRunCommand {
                command: WireCommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory,
                },
                output_capture,
            },
            detector_policy,
        )
    }

    /// Sends one freshly admitted formal-check command through its exact
    /// `TaskFormalCheck` authority and policy-bound v12 output-capture path.
    ///
    /// The exact canonical command frame is committed by the core claim and
    /// validated with `TaskFormalCheck` authority and no borrowed
    /// task-`Running` boundary. Output custody is reserved before the claim;
    /// the correlated response therefore carries either the exact claimed
    /// command terminal or typed failure custody for durable terminalization.
    ///
    /// # Errors
    ///
    /// Returns a consuming session failure for invalid command authority,
    /// non-UTF-8 working-directory bytes, failed output reservation, claim or
    /// transport failure, or a rejected correlated response. A claimed failure
    /// retains exact terminalization authority; a pre-claim validation failure
    /// does not.
    pub fn send_precommitted_formal_check(
        self,
        ledger: &mut EventLedger,
        permit: FreshTaskFormalCheckDispatchPermit,
        intent: &EffectIntent,
        command: &CommandSpec,
    ) -> Result<(Self, ClaimedRunnerCommandEffectResponse), RunnerEffectSessionFailure> {
        if let Err(error) = command.validate() {
            return Err(
                self.fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            );
        }
        let working_directory = match command.working_directory.to_str() {
            Some(path) => path.to_owned(),
            None => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "formal-check working directory is not exact UTF-8".into(),
                    ),
                    None,
                ));
            }
        };
        let core_request_bytes = match serde_json::to_vec(command) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "formal-check command cannot be canonically encoded: {error}"
                    )),
                    None,
                ));
            }
        };
        let dispatch_permit = FreshRunnerEffectDispatchPermit::TaskFormalCheck(permit);
        if let Err(error) = self.validate_command_effect_before_output_capture(
            intent,
            &core_request_bytes,
            RunnerRole::Worker,
        ) {
            return Err(self.fail_effect(error, None));
        }
        let (output_capture, detector_policy) =
            match self.reserve_command_output_capture_anchor(&dispatch_permit) {
                Ok(capture) => capture,
                Err(error) => return Err(self.fail_effect(error, None)),
            };
        self.send_command_with_dispatch_permit(
            ledger,
            dispatch_permit,
            RunnerTaskEffectDispatchClass::TaskFormalCheck,
            intent,
            &core_request_bytes,
            RunnerRequest::WorkerRunCommand {
                command: WireCommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory,
                },
                output_capture,
            },
            detector_policy,
        )
    }

    /// Sends one freshly admitted candidate publication through the exact
    /// typed integration request and `WorkerStageChanges` wire mapping.
    ///
    /// Core claim and transport validation use `TaskIntegration` authority and
    /// deliberately pass no task-`Running` boundary. The worker must already
    /// retain the exact `WorkerPrepareStage` result selected by `request`.
    ///
    /// # Errors
    ///
    /// Returns a consuming failure for a crossed admission/request, absent
    /// stage preparation, claim failure, transport ambiguity, or rejected
    /// correlated response.
    pub fn send_precommitted_task_integration(
        self,
        ledger: &mut EventLedger,
        permit: FreshTaskIntegrationDispatchPermit,
        intent: &EffectIntent,
        request: &TaskIntegrationRequest,
    ) -> Result<(Self, ClaimedRunnerEffectResponse), RunnerEffectSessionFailure> {
        let core_request_bytes = match serde_json::to_vec(request) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "task-integration request cannot be canonically encoded: {error}"
                    )),
                    None,
                ));
            }
        };
        let wire_request = match RunnerRequest::try_from(request) {
            Ok(request) => request,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        self.send_precommitted_effect(
            ledger,
            FreshRunnerEffectDispatchPermit::TaskIntegration(permit),
            intent,
            &core_request_bytes,
            wire_request,
        )
    }

    /// Sends one freshly admitted repository-wide command through the exact
    /// `SprintFinalVerification` authority and final-verifier wire request.
    ///
    /// The canonical core command is the request-digest preimage; the wire
    /// command is only its UTF-8 transport mapping. The move-only permit is
    /// consumed immediately before transport, so recovered admissions cannot
    /// redispatch after restart.
    ///
    /// # Errors
    ///
    /// Returns a consuming failure for invalid command encoding, crossed
    /// launch/session role, claim failure, transport ambiguity, or rejected
    /// correlated response.
    pub fn send_precommitted_final_verification(
        self,
        ledger: &mut EventLedger,
        permit: FreshFinalVerificationDispatchPermit,
        intent: &EffectIntent,
        command: &CommandSpec,
    ) -> Result<(Self, ClaimedRunnerCommandEffectResponse), RunnerEffectSessionFailure> {
        if let Err(error) = command.validate() {
            return Err(
                self.fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            );
        }
        let working_directory = match command.working_directory.to_str() {
            Some(path) => path.to_owned(),
            None => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "final-verification working directory is not exact UTF-8".into(),
                    ),
                    None,
                ));
            }
        };
        let core_request_bytes = match serde_json::to_vec(command) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "final-verification command cannot be canonically encoded: {error}"
                    )),
                    None,
                ));
            }
        };
        let dispatch_permit = FreshRunnerEffectDispatchPermit::SprintFinalVerification(permit);
        if let Err(error) = self.validate_command_effect_before_output_capture(
            intent,
            &core_request_bytes,
            RunnerRole::FinalVerifier,
        ) {
            return Err(self.fail_effect(error, None));
        }
        let (output_capture, detector_policy) =
            match self.reserve_command_output_capture_anchor(&dispatch_permit) {
                Ok(capture) => capture,
                Err(error) => return Err(self.fail_effect(error, None)),
            };
        self.send_command_with_dispatch_permit(
            ledger,
            dispatch_permit,
            RunnerTaskEffectDispatchClass::SprintFinalVerification,
            intent,
            &core_request_bytes,
            RunnerRequest::FinalVerifierRunCommand {
                command: WireCommandSpec {
                    program: command.program.clone(),
                    arguments: command.arguments.clone(),
                    working_directory,
                },
                output_capture,
            },
            detector_policy,
        )
    }

    /// Sends one freshly admitted application through the exact typed request
    /// and immutable stage-bundle mapping.
    ///
    /// The move-only permit is the only ordinary application dispatch
    /// authority. The canonical [`ApplicationRequest`] bytes remain the core
    /// request-digest preimage; `bundle` is accepted only when every artifact
    /// field is identical to `request.artifact`. Recovered admissions cannot
    /// call this method because they cannot reconstruct the permit.
    ///
    /// # Errors
    ///
    /// Returns a consuming failure for an invalid or crossed request/bundle,
    /// launch/session role mismatch, claim failure, ambiguous transport, or a
    /// correlated response that does not close the exact requested bundle.
    pub fn send_precommitted_application(
        self,
        ledger: &mut EventLedger,
        permit: FreshApplicationDispatchPermit,
        intent: &EffectIntent,
        request: &ApplicationRequest,
        bundle: &StageBundleReference,
    ) -> Result<(Self, ClaimedRunnerEffectResponse), RunnerEffectSessionFailure> {
        if self.role != RunnerRole::Applier {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "ordinary application dispatch requires the trusted Applier role".into(),
                ),
                None,
            ));
        }
        if let Err(error) = request.validate() {
            return Err(
                self.fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
            );
        }
        let artifact = match bundle.to_core_integration_artifact() {
            Ok(artifact) => artifact,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "application bundle cannot map to the core artifact: {error}"
                    )),
                    None,
                ));
            }
        };
        if artifact != request.artifact
            || bundle.change_set_id != request.change_set.change_set_id
            || bundle.base_snapshot != request.change_set.base_snapshot
            || bundle.result_snapshot != request.change_set.result_snapshot
        {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "application request differs from the exact immutable stage bundle".into(),
                ),
                None,
            ));
        }
        let core_request_bytes = match serde_json::to_vec(request) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(format!(
                        "application request cannot be canonically encoded: {error}"
                    )),
                    None,
                ));
            }
        };
        self.send_precommitted_effect(
            ledger,
            FreshRunnerEffectDispatchPermit::SprintApplication(permit),
            intent,
            &core_request_bytes,
            RunnerRequest::ApplierApplyBundle {
                bundle: bundle.clone(),
            },
        )
    }

    /// Sends one freshly admitted descriptor-relative live-workspace capture.
    ///
    /// The canonical core request is both the effect request-digest preimage
    /// and the exact request embedded in the runner frame. The initialized
    /// role must retain the same plan and plan digest, so neither a recovered
    /// admission nor a verifier initialized for another finalization cut can
    /// reach the transport claim boundary.
    ///
    /// # Errors
    ///
    /// Returns a consuming failure for crossed plan, role, claim, transport,
    /// or manifest evidence. The caller retains mandatory cleanup custody on
    /// every failure path through [`RunnerEffectSessionFailure`].
    pub fn send_precommitted_live_state_capture(
        self,
        ledger: &mut EventLedger,
        permit: FreshLiveStateCaptureDispatchPermit,
        intent: &EffectIntent,
        request: &SprintLiveStateCaptureRequest,
    ) -> Result<(Self, ClaimedLiveStateCaptureResponse), LiveStateCaptureSessionFailure> {
        if self.role != RunnerRole::LiveStateVerifier {
            return Err(self
                .fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "live-state capture dispatch requires the read-only LiveStateVerifier role"
                            .into(),
                    ),
                    None,
                )
                .into());
        }
        if let Err(error) = request.validate() {
            return Err(self
                .fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
                .into());
        }
        let plan_digest = match request.plan.plan_digest() {
            Ok(digest) => digest,
            Err(error) => {
                return Err(self
                    .fail_effect(RunnerClientError::InvalidLifecycle(error.to_string()), None)
                    .into());
            }
        };
        if self.role_input_authority
            != (RunnerRoleInputAuthority::LiveStateFinalization {
                plan: Box::new(request.plan.clone()),
                plan_digest,
            })
            || request.plan.expected_snapshot != self.expected_base_snapshot
            || request.plan.grant_hash != self.grant_hash
        {
            return Err(self
                .fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "capture request differs from the verifier's exact initialized finalization plan, snapshot, or grant"
                        .into(),
                ),
                None,
            )
                .into());
        }
        let core_request_bytes = match serde_json::to_vec(request) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Err(self
                    .fail_effect(
                        RunnerClientError::InvalidLifecycle(format!(
                            "live-state capture request cannot be canonically encoded: {error}"
                        )),
                        None,
                    )
                    .into());
            }
        };
        if let Err(error) = self.validate_effect_request(
            intent,
            &core_request_bytes,
            &RunnerRequest::LiveStateVerifierCapture {
                request: Box::new(request.clone()),
            },
        ) {
            return Err(self.fail_effect(error, None).into());
        }
        self.send_effect_with_dispatch_permit(
            ledger,
            FreshRunnerEffectDispatchPermit::SprintLiveStateCapture(permit),
            RunnerTaskEffectDispatchClass::SprintLiveStateCapture,
            intent,
            &core_request_bytes,
            RunnerRequest::LiveStateVerifierCapture {
                request: Box::new(request.clone()),
            },
        )
        .map(|(client, claimed)| (client, ClaimedLiveStateCaptureResponse { inner: claimed }))
        .map_err(Into::into)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the v12 command boundary keeps policy-bearing frame construction, durable claim, one-use permit validation, transport, and correlation linear"
    )]
    fn send_command_with_dispatch_permit(
        mut self,
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        dispatch_class: RunnerTaskEffectDispatchClass,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        request: RunnerRequest,
        detector_policy: SensitiveOutputDetectionPolicyReferenceV1,
    ) -> Result<(Self, ClaimedRunnerCommandEffectResponse), RunnerEffectSessionFailure> {
        let exact_class = match task_dispatch_class(&dispatch_permit) {
            Ok(class) => class,
            Err(error) => return Err(self.fail_effect(error, None)),
        };
        if exact_class != dispatch_class {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "v12 command dispatch class differs from its fresh move-only permit".into(),
                ),
                None,
            ));
        }
        if let Err(error) = validate_task_dispatch_request(dispatch_class, &request) {
            return Err(self.fail_effect(error, None));
        }
        if let Err(error) = self.validate_effect_request(intent, core_request_bytes, &request) {
            return Err(self.fail_effect(error, None));
        }
        if let Err(error) = self.process.precheck_effect_exchange() {
            return Err(self.fail_effect(error, None));
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle("request sequence overflow".into()),
                None,
            ));
        };
        // The runner builds exactly one command job per admitted
        // `WorkerRunCommand` and none for any other request, so this is the
        // local half of the exact admission correlation the shutdown
        // acknowledgement is checked against.
        let worker_commands_dispatched =
            if matches!(&request, RunnerRequest::WorkerRunCommand { .. }) {
                match self.worker_commands_dispatched.checked_add(1) {
                    Some(count) => count,
                    None => {
                        return Err(self.fail_effect(
                            RunnerClientError::InvalidLifecycle(
                                "dispatched worker command count overflow".into(),
                            ),
                            None,
                        ));
                    }
                }
            } else {
                self.worker_commands_dispatched
            };
        let request_id = self.request_id("command-effect-v12");
        let mut envelope = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: self.session.session_id.clone(),
            runner_nonce: self.runner_nonce.clone(),
            sequence: self.next_sequence,
            request_id: request_id.clone(),
            effect: WireEffectContext {
                contract_version: intent.contract_version,
                launch_id: self.launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: intent.task_id.clone(),
                worker_id: intent.worker_id.clone(),
                worker_lease: intent.worker_lease.clone(),
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            },
            request: RunnerRequestV12::RunCommand {
                request,
                detector_policy,
            },
        };
        if let Err(error) = envelope.bind_transport_commitment_digest() {
            return Err(self.fail_effect(error.into(), None));
        }
        let outbound = if self.installed_service_command_release {
            match self.encode_installed_service_command_frame(&envelope) {
                Ok(outbound) => outbound,
                Err(error) => return Err(self.fail_effect(error, None)),
            }
        } else {
            match encode_request_frame_v12(&envelope) {
                Ok(outbound) => outbound,
                Err(error) => return Err(self.fail_effect(error.into(), None)),
            }
        };
        let acquired = match envelope.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired().clone()
            }
            _ => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "v12 command envelope lost its role-exact RunCommand shape".into(),
                    ),
                    None,
                ));
            }
        };
        let (claimed_effect, transport_permit) = match ledger.claim_command_output_capture_dispatch(
            dispatch_permit,
            acquired,
            &outbound,
        ) {
            Ok(claimed) => claimed,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        if claimed_effect.dispatch_claim.is_none() {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "claimed v12 command readback omitted its immutable dispatch claim".into(),
                ),
                None,
            ));
        }
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("checked claimed v12 command above");
        if !claim_matches_task_dispatch_class(claim, dispatch_class) {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "durable v12 command claim authority differs from the desktop request class"
                        .into(),
                ),
                None,
            ));
        }
        if transport_permit.sensitive_output_detection_policy() != Some(envelope.detector_policy())
        {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "post-claim command transport policy differs from the exact v12 envelope"
                        .into(),
                ),
                None,
            ));
        }
        let running_boundary = match dispatch_class {
            RunnerTaskEffectDispatchClass::TaskRunning => self.task_attempt_running.as_ref(),
            RunnerTaskEffectDispatchClass::TaskFormalCheck
            | RunnerTaskEffectDispatchClass::SprintFinalVerification => None,
            RunnerTaskEffectDispatchClass::TaskIntegration
            | RunnerTaskEffectDispatchClass::SprintApplication
            | RunnerTaskEffectDispatchClass::SprintLiveStateCapture => {
                return Err(self.fail_effect(
                    RunnerClientError::InvalidLifecycle(
                        "non-command dispatch class cannot consume v12 command transport".into(),
                    ),
                    None,
                ));
            }
        };
        let observation_authority = match transport_permit.validate_transport_request(
            intent,
            core_request_bytes,
            &self.launch,
            &self.session,
            running_boundary,
            &outbound,
        ) {
            Ok(authority) => authority,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        self.seen_request_ids.insert(request_id);
        self.seen_effect_ids.insert(intent.effect_id.clone());
        self.seen_idempotency_keys
            .insert(intent.idempotency_key.clone());

        let transported = match if self.installed_service_command_release {
            self.process.exchange_encoded_command_frame_with_deadline(
                &outbound,
                Instant::now() + INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE,
            )
        } else {
            self.process
                .exchange_encoded_command_frame_with_progress(&outbound)
        } {
            Ok(response) => response,
            Err(failure) => {
                return Err(self.fail_claimed_command_effect(
                    failure.error,
                    intent,
                    claimed_effect,
                    &outbound,
                    failure_phase(failure.progress),
                    None,
                    None,
                    observation_authority,
                ));
            }
        };
        let response = transported.response;
        if let Err(error) = response.validate_correlation(&envelope) {
            let exchange = RunnerCommandEffectResponse {
                request: envelope,
                response,
            };
            return Err(self.fail_claimed_command_effect(
                error.into(),
                intent,
                claimed_effect,
                &outbound,
                RunnerEffectFailurePhase::CorrelatedResponseRejected,
                Some(exchange),
                Some(&transported.response_frame_digest),
                observation_authority,
            ));
        }
        self.next_sequence = next_sequence;
        self.worker_commands_dispatched = worker_commands_dispatched;
        Ok((
            self,
            ClaimedRunnerCommandEffectResponse {
                exchange: RunnerCommandEffectResponse {
                    request: envelope,
                    response,
                },
                request_frame: outbound,
                response_frame_digest: transported.response_frame_digest,
                claimed_effect,
                observation_authority,
            },
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "claim, exact-frame transport, phase evidence, correlation, and semantic acceptance remain one auditable linear boundary"
    )]
    fn send_effect_with_dispatch_permit(
        mut self,
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        dispatch_class: RunnerTaskEffectDispatchClass,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        request: RunnerRequest,
    ) -> Result<(Self, ClaimedRunnerEffectResponse), RunnerEffectSessionFailure> {
        if matches!(
            &request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ) {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "frozen v11 effect transport rejects all RunCommand requests".into(),
                ),
                None,
            ));
        }
        if let Err(error) = self.process.precheck_effect_exchange() {
            return Err(self.fail_effect(error, None));
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle("request sequence overflow".into()),
                None,
            ));
        };
        let request_id = self.request_id("effect");
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: self.session.session_id.clone(),
            runner_nonce: Some(self.runner_nonce.clone()),
            sequence: self.next_sequence,
            request_id: request_id.clone(),
            effect: Some(WireEffectContext {
                contract_version: intent.contract_version,
                launch_id: self.launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                idempotency_key: intent.idempotency_key.clone(),
                sprint_id: intent.sprint_id.clone(),
                task_id: intent.task_id.clone(),
                worker_id: intent.worker_id.clone(),
                worker_lease: intent.worker_lease.clone(),
                policy_hash: intent.policy_hash.clone(),
                input_snapshot: intent.input_snapshot.clone(),
                request_digest: intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            }),
            request,
        };
        if let Err(error) = envelope.bind_transport_commitment_digest() {
            return Err(self.fail_effect(error.into(), None));
        }
        let outbound = match encode_request_frame(&envelope) {
            Ok(outbound) => outbound,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        let output_capture_acquired = match &envelope.request {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                Some(output_capture.acquired().clone())
            }
            _ => None,
        };
        let claim_result = match output_capture_acquired {
            Some(acquired) => {
                ledger.claim_command_output_capture_dispatch(dispatch_permit, acquired, &outbound)
            }
            None => ledger.claim_runner_effect_dispatch(dispatch_permit, &outbound),
        };
        let (claimed_effect, transport_permit) = match claim_result {
            Ok(claimed) => claimed,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        if claimed_effect.dispatch_claim.is_none() {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "claimed effect readback omitted its immutable dispatch claim".into(),
                ),
                None,
            ));
        }
        let claim = claimed_effect
            .dispatch_claim
            .as_ref()
            .expect("checked claimed effect above");
        if !claim_matches_task_dispatch_class(claim, dispatch_class) {
            return Err(self.fail_effect(
                RunnerClientError::InvalidLifecycle(
                    "durable dispatch claim authority differs from the desktop request class"
                        .into(),
                ),
                None,
            ));
        }
        let running_boundary = match dispatch_class {
            RunnerTaskEffectDispatchClass::TaskRunning => self.task_attempt_running.as_ref(),
            RunnerTaskEffectDispatchClass::TaskFormalCheck
            | RunnerTaskEffectDispatchClass::TaskIntegration
            | RunnerTaskEffectDispatchClass::SprintFinalVerification
            | RunnerTaskEffectDispatchClass::SprintApplication
            | RunnerTaskEffectDispatchClass::SprintLiveStateCapture => None,
        };
        let observation_authority = match transport_permit.validate_transport_request(
            intent,
            core_request_bytes,
            &self.launch,
            &self.session,
            running_boundary,
            &outbound,
        ) {
            Ok(authority) => authority,
            Err(error) => return Err(self.fail_effect(error.into(), None)),
        };
        self.seen_request_ids.insert(request_id);
        self.seen_effect_ids.insert(intent.effect_id.clone());
        self.seen_idempotency_keys
            .insert(intent.idempotency_key.clone());

        if dispatch_class == RunnerTaskEffectDispatchClass::TaskFormalCheck {
            return Err(self.fail_claimed_effect(
                RunnerClientError::CommandExecutionDisabled,
                intent,
                claimed_effect,
                &outbound,
                RunnerEffectFailurePhase::NoRequestBytesWritten,
                None,
                None,
                observation_authority,
            ));
        }

        let transported = match if self.installed_service_command_release {
            self.process.exchange_encoded_frame_with_deadline(
                &outbound,
                Instant::now() + INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE,
            )
        } else {
            self.process.exchange_encoded_frame_with_progress(&outbound)
        } {
            Ok(response) => response,
            Err(failure) => {
                return Err(self.fail_claimed_effect(
                    failure.error,
                    intent,
                    claimed_effect,
                    &outbound,
                    failure_phase(failure.progress),
                    None,
                    None,
                    observation_authority,
                ));
            }
        };
        let response = transported.response;
        if let Err(error) = response.validate_correlation(&envelope) {
            return Err(self.fail_claimed_effect(
                error.into(),
                intent,
                claimed_effect,
                &outbound,
                RunnerEffectFailurePhase::RequestWriteStarted {
                    written_request_bytes: NonZeroUsize::new(outbound.len())
                        .expect("encoded request frame is nonempty"),
                    total_request_bytes: NonZeroUsize::new(outbound.len())
                        .expect("encoded request frame is nonempty"),
                },
                None,
                None,
                observation_authority,
            ));
        }
        if let Err(error) =
            self.validate_and_apply_effect_response(intent, &envelope.request, &response.response)
        {
            let exchange = RunnerEffectResponse {
                request: envelope,
                response,
            };
            return Err(self.fail_claimed_effect(
                error,
                intent,
                claimed_effect,
                &outbound,
                RunnerEffectFailurePhase::CorrelatedResponseRejected,
                Some(exchange),
                Some(&transported.response_frame_digest),
                observation_authority,
            ));
        }
        self.next_sequence = next_sequence;
        Ok((
            self,
            ClaimedRunnerEffectResponse {
                exchange: RunnerEffectResponse {
                    request: envelope,
                    response,
                },
                request_frame: outbound,
                response_frame_digest: transported.response_frame_digest,
                claimed_effect,
                observation_authority,
            },
        ))
    }

    /// Reloads and validates the schema-v12 rollback operation and returns the
    /// fresh applier's mandatory cleanup handoff.
    ///
    /// The method does not accept an ordinary [`EffectIntent`] or proposal
    /// event and never writes the terminal-fenced ordinary effect tables. It
    /// reloads the complete operation and its application-artifact authority
    /// from `ledger`, then exact-compares every caller-supplied preimage before
    /// writing at most one `ApplierRollback` request.
    ///
    /// # Errors
    ///
    /// Returns a consuming failure with cleanup responsibility when operation,
    /// session, bundle, artifact, request, durable application-artifact
    /// authority, exchange, correlation, or orderly shutdown validation fails.
    /// A response retained before a shutdown failure remains available for
    /// evidence adaptation; an ambiguous effect exchange has no response and
    /// must be reconciled by a distinct fresh applier.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the complete durable authorization preimages, single-effect dispatch, and mandatory shutdown form one fail-closed boundary"
    )]
    pub fn send_post_completion_rollback(
        mut self,
        ledger: &EventLedger,
        operation: &PostCompletionRollbackIntent,
        application: &ApplicationEvidence,
        rollback_reference: &RollbackReferenceEvidence,
        change_set: &ChangeSet,
        bundle: StageBundleReference,
        rollback: WireRollbackArtifactReference,
    ) -> Result<PostCompletionRollbackTransportOutcome, PostCompletionRollbackTransportFailure>
    {
        if let Err(error) = self.validate_post_completion_rollback_request(
            ledger,
            operation,
            application,
            rollback_reference,
            change_set,
            &bundle,
            &rollback,
        ) {
            return Err(self.fail_post_completion(error, None, false));
        }
        let request = RunnerRequest::ApplierRollback { bundle, rollback };
        let request_id = self.request_id("post-completion-rollback");
        let mut envelope = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: self.session.session_id.clone(),
            runner_nonce: Some(self.runner_nonce.clone()),
            sequence: self.next_sequence,
            request_id: request_id.clone(),
            effect: Some(WireEffectContext {
                contract_version: CONTRACT_VERSION,
                launch_id: self.launch.launch_id.clone(),
                effect_id: operation.rollback_effect_id.clone(),
                idempotency_key: operation.idempotency_key.clone(),
                sprint_id: operation.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                policy_hash: operation.policy_hash.clone(),
                input_snapshot: self.expected_base_snapshot.clone(),
                request_digest: operation.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            }),
            request,
        };
        if let Err(error) = envelope.bind_transport_commitment_digest() {
            return Err(self.fail_post_completion(error.into(), None, false));
        }
        self.seen_request_ids.insert(request_id);
        self.seen_effect_ids
            .insert(operation.rollback_effect_id.clone());
        self.seen_idempotency_keys
            .insert(operation.idempotency_key.clone());

        let response = match self.process.exchange(&envelope) {
            Ok(response) => response,
            Err(error) => return Err(self.fail_post_completion(error, None, true)),
        };
        if let Err(error) = response.validate_correlation(&envelope) {
            return Err(self.fail_post_completion(error.into(), None, true));
        }
        if !matches!(
            response.response,
            RunnerResponse::RollbackCompleted { .. }
                | RunnerResponse::RollbackCompletedWithEvidence { .. }
                | RunnerResponse::RollbackLiveConflict { .. }
                | RunnerResponse::Failed { .. }
        ) {
            return Err(self.fail_post_completion(
                RunnerClientError::UnexpectedResponse(
                    "evidence-bearing or legacy RollbackCompleted, typed RollbackLiveConflict, or typed Failed",
                ),
                None,
                true,
            ));
        }
        if let Err(error) = self.advance_sequence() {
            return Err(self.fail_post_completion(error, None, true));
        }
        let exchange = RunnerEffectResponse {
            request: envelope,
            response,
        };

        let shutdown = self.control_envelope("shutdown", RunnerRequest::Shutdown);
        let shutdown_response = match self.process.exchange(&shutdown) {
            Ok(response) => response,
            Err(error) => return Err(self.fail_post_completion(error, Some(exchange), true)),
        };
        if let Err(error) = shutdown_response.validate_correlation(&shutdown) {
            return Err(self.fail_post_completion(error.into(), Some(exchange), true));
        }
        let RunnerResponse::ShutdownPrepared { acknowledgement } = shutdown_response.response
        else {
            return Err(self.fail_post_completion(
                RunnerClientError::UnexpectedResponse("ShutdownPrepared"),
                Some(exchange),
                true,
            ));
        };
        if let Err(error) = self.validate_shutdown_acknowledgement(&acknowledgement) {
            return Err(self.fail_post_completion(error, Some(exchange), true));
        }
        Ok(PostCompletionRollbackTransportOutcome {
            exchange,
            cleanup_required: finish_transport(
                self.process,
                self.launch,
                self.launch_cleanup_admission,
                self.platform_launch_binding,
                self.native_cleanup_custody,
                RunnerSessionRegistrationState::Registered(self.session),
                Some(acknowledgement),
            ),
        })
    }

    /// Sends one closed context-free session control. No fabricated core
    /// effect context is attached and no file tool, command, apply, or
    /// rollback request is admitted through this path.
    ///
    /// Reconciliation controls resolve existing uncertain state; they do not
    /// create a false new [`EffectKind`]. Cancellation and shutdown are
    /// terminal and use their dedicated consuming methods. In particular, a
    /// fresh-applier stage reconciliation remains transport evidence only; a
    /// coordinator must durably retain that distinct reconciliation session
    /// before claiming restart recovery.
    ///
    /// # Errors
    ///
    /// Returns a fatal session failure on role/state confusion, a request that
    /// is not in the runner protocol's closed session-control set, framing,
    /// EOF, deadline, correlation, or response-shape failure.
    pub fn send_control(
        mut self,
        request: RunnerRequest,
    ) -> Result<(Self, RunnerControlResponse), RunnerSessionFailure> {
        if !request.is_session_control()
            || matches!(
                request,
                RunnerRequest::WorkerCancel | RunnerRequest::Shutdown
            )
        {
            return Err(self.fail(
                RunnerClientError::InvalidLifecycle(
                    "request is not an admitted nonterminal session control".into(),
                ),
                None,
            ));
        }
        if let Err(error) = self.validate_control_request(&request) {
            return Err(self.fail(error, None));
        }
        let envelope = self.control_envelope(control_label(&request), request);
        let outbound = match encode_request_frame(&envelope) {
            Ok(outbound) => outbound,
            Err(error) => return Err(self.fail(error.into(), None)),
        };
        let deadline = if self.installed_service_command_release {
            Instant::now() + INSTALLED_SERVICE_COMMAND_EXCHANGE_DEADLINE
        } else {
            Instant::now() + RUNNER_EXCHANGE_DEADLINE
        };
        let response = match self
            .process
            .exchange_encoded_frame_with_deadline(&outbound, deadline)
        {
            Ok(transported) => transported.response,
            Err(failure) => return Err(self.fail(failure.error, None)),
        };
        if let Err(error) = response.validate_correlation(&envelope) {
            return Err(self.fail(error.into(), None));
        }
        if let Err(error) =
            self.validate_and_apply_control_response(&envelope.request, &response.response)
        {
            return Err(self.fail(error, None));
        }
        if let Err(error) = self.advance_sequence() {
            return Err(self.fail(error, None));
        }
        Ok((
            self,
            RunnerControlResponse {
                request: envelope,
                response,
            },
        ))
    }

    /// Requests worker cancellation, validates the non-authoritative
    /// acknowledgement, waits for direct-child exit, and returns a mandatory
    /// platform-cleanup handoff.
    ///
    /// # Errors
    ///
    /// Returns a fatal session failure for a non-worker role or any ambiguous,
    /// uncorrelated, malformed, or mismatched cancellation exchange.
    pub fn cancel_worker(mut self) -> Result<RunnerCleanupRequired, RunnerSessionFailure> {
        if self.role != RunnerRole::Worker {
            return Err(self.fail(
                RunnerClientError::InvalidLifecycle(
                    "only a worker session admits WorkerCancel".into(),
                ),
                None,
            ));
        }
        let envelope = self.control_envelope("cancel", RunnerRequest::WorkerCancel);
        let response = match self.process.exchange(&envelope) {
            Ok(response) => response,
            Err(error) => return Err(self.fail(error, None)),
        };
        if let Err(error) = response.validate_correlation(&envelope) {
            return Err(self.fail(error.into(), None));
        }
        let RunnerResponse::CancellationPrepared { acknowledgement } = response.response else {
            return Err(self.fail(
                RunnerClientError::UnexpectedResponse("CancellationPrepared"),
                None,
            ));
        };
        if let Err(error) = self.validate_shutdown_acknowledgement(&acknowledgement) {
            return Err(self.fail(error, None));
        }
        Ok(finish_transport(
            self.process,
            self.launch,
            self.launch_cleanup_admission,
            self.platform_launch_binding,
            self.native_cleanup_custody,
            RunnerSessionRegistrationState::Registered(self.session),
            Some(acknowledgement),
        ))
    }

    /// Requests orderly runner shutdown, validates the non-authoritative
    /// acknowledgement, waits for direct-child exit, and returns the mandatory
    /// platform-cleanup handoff.
    ///
    /// # Errors
    ///
    /// Returns a fatal session failure on framing, EOF, correlation, response,
    /// or acknowledgement mismatch. The error still owns the cleanup handoff.
    pub fn shutdown(mut self) -> Result<RunnerCleanupRequired, RunnerSessionFailure> {
        let envelope = self.control_envelope("shutdown", RunnerRequest::Shutdown);
        let response = match self.process.exchange(&envelope) {
            Ok(response) => response,
            Err(error) => return Err(self.fail(error, None)),
        };
        if let Err(error) = response.validate_correlation(&envelope) {
            return Err(self.fail(error.into(), None));
        }
        let RunnerResponse::ShutdownPrepared { acknowledgement } = response.response else {
            return Err(self.fail(
                RunnerClientError::UnexpectedResponse("ShutdownPrepared"),
                None,
            ));
        };
        if let Err(error) = self.validate_shutdown_acknowledgement(&acknowledgement) {
            return Err(self.fail(error, None));
        }
        Ok(finish_transport(
            self.process,
            self.launch,
            self.launch_cleanup_admission,
            self.platform_launch_binding,
            self.native_cleanup_custody,
            RunnerSessionRegistrationState::Registered(self.session),
            Some(acknowledgement),
        ))
    }

    pub(super) fn validate_effect_request(
        &self,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        request: &RunnerRequest,
    ) -> Result<(), RunnerClientError> {
        if self.post_completion_role.is_some() {
            return Err(RunnerClientError::InvalidLifecycle(
                "post-completion rollback appliers forbid ordinary effect dispatch; the executor must use the ledger-backed operation-bound rollback method and a recovery validator may only reconcile"
                    .into(),
            ));
        }
        if self.pending_reconciliation.is_some() {
            return Err(RunnerClientError::InvalidLifecycle(
                "an exact reconciliation control is required before any new effect".into(),
            ));
        }
        if self.prepared_stage.is_some()
            && !matches!(request, RunnerRequest::WorkerStageChanges { .. })
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "an exact prepared stage effect must run before any other worker effect".into(),
            ));
        }
        intent
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        let expected_kind = exact_effect_kind(request)?;
        if intent.kind != expected_kind
            || intent.sprint_id != self.session.sprint_id
            || intent.policy_hash != self.session.policy_hash
            || intent.created_at_unix_ms < self.session.registered_at_unix_ms
            || intent.request_digest != Digest::sha256(core_request_bytes)
            || self.seen_effect_ids.contains(&intent.effect_id)
            || self.seen_idempotency_keys.contains(&intent.idempotency_key)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "effect kind, sprint, policy, timestamp, request digest, or unique identity differs"
                    .into(),
            ));
        }
        let scope_matches = match self.role {
            RunnerRole::Worker => {
                intent.task_id.is_some()
                    && intent.worker_id.as_deref() == self.session.worker_id.as_deref()
                    && intent.worker_lease == self.session.worker_lease
                    && match request {
                        RunnerRequest::WorkerStageChanges { change_set, .. } => {
                            intent.input_snapshot == change_set.base_snapshot
                                && self.shadow_snapshot.as_ref()
                                    == Some(&change_set.result_snapshot)
                        }
                        _ => self.shadow_snapshot.as_ref() == Some(&intent.input_snapshot),
                    }
            }
            RunnerRole::FinalVerifier | RunnerRole::Applier | RunnerRole::LiveStateVerifier => {
                intent.task_id.is_none()
                    && intent.worker_id.is_none()
                    && intent.worker_lease.is_none()
            }
        };
        if !scope_matches {
            return Err(RunnerClientError::InvalidLifecycle(
                "effect task/worker scope differs from the immutable runner role".into(),
            ));
        }
        self.validate_worker_stage_effect(intent, core_request_bytes, request)?;
        validate_worker_provider_tool_request(intent, core_request_bytes, request)?;
        validate_applier_application_request(
            intent,
            core_request_bytes,
            request,
            &self.expected_base_snapshot,
        )?;
        if matches!(
            request,
            RunnerRequest::ApplierApplyBundle { .. } | RunnerRequest::ApplierRollback { .. }
        ) && !self.applier_recovery_complete
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "applier recovery must complete before apply or rollback".into(),
            ));
        }
        validate_applier_input_snapshot(intent, request)?;
        Ok(())
    }

    /// Exhausts every deterministic desktop and transport precondition that
    /// does not require the physical acquisition itself. Once this returns,
    /// reservation is the next state-changing step; the generic path repeats
    /// these checks after the exact acquired anchor is present.
    fn validate_command_effect_before_output_capture(
        &self,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        expected_role: RunnerRole,
    ) -> Result<(), RunnerClientError> {
        self.process.precheck_effect_exchange()?;
        if self.next_sequence.checked_add(1).is_none() {
            return Err(RunnerClientError::InvalidLifecycle(
                "request sequence overflow".into(),
            ));
        }
        if self.post_completion_role.is_some()
            || self.pending_reconciliation.is_some()
            || self.prepared_stage.is_some()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "command reservation requires an ordinary unreconciled session with no prepared stage"
                    .into(),
            ));
        }
        intent
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        if self.role != expected_role
            || intent.kind != EffectKind::RunCommand
            || intent.sprint_id != self.session.sprint_id
            || intent.policy_hash != self.session.policy_hash
            || intent.created_at_unix_ms < self.session.registered_at_unix_ms
            || intent.request_digest != Digest::sha256(core_request_bytes)
            || self.seen_effect_ids.contains(&intent.effect_id)
            || self.seen_idempotency_keys.contains(&intent.idempotency_key)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "command role, lifecycle, policy, request, or unique identity differs before output reservation"
                    .into(),
            ));
        }
        let scope_matches = match expected_role {
            RunnerRole::Worker => {
                intent.task_id.is_some()
                    && intent.worker_id.as_deref() == self.session.worker_id.as_deref()
                    && intent.worker_lease == self.session.worker_lease
                    && self.shadow_snapshot.as_ref() == Some(&intent.input_snapshot)
            }
            RunnerRole::FinalVerifier => {
                intent.task_id.is_none()
                    && intent.worker_id.is_none()
                    && intent.worker_lease.is_none()
            }
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => false,
        };
        if !scope_matches {
            return Err(RunnerClientError::InvalidLifecycle(
                "command task/worker scope differs before output reservation".into(),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the complete operation, application, change-set, journal, artifact, session, and one-effect authorization chain remains visible at one pre-transport boundary"
    )]
    pub(super) fn validate_post_completion_rollback_request(
        &self,
        ledger: &EventLedger,
        operation: &PostCompletionRollbackIntent,
        application: &ApplicationEvidence,
        rollback_reference: &RollbackReferenceEvidence,
        change_set: &ChangeSet,
        bundle: &StageBundleReference,
        rollback: &WireRollbackArtifactReference,
    ) -> Result<(), RunnerClientError> {
        operation
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        application
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        rollback_reference
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        change_set
            .validate()
            .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
        let bundle_artifact = bundle.to_core_integration_artifact().map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "post-completion rollback bundle is not a durable integration artifact: {error}"
            ))
        })?;
        let persisted = ledger
            .load_post_completion_rollback(&operation.operation_id)
            .map_err(map_post_completion_ledger_error)?;
        let authority_state = ledger
            .load_post_completion_rollback_application_artifact_authority(&operation.operation_id)
            .map_err(map_post_completion_ledger_error)?;
        if persisted.intent != *operation
            || persisted.application_artifact_authority != authority_state
            || persisted.observation.is_some()
            || persisted.launch_failure.is_some()
            || persisted.terminal.is_some()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "post-completion rollback operation differs from durable authority or already has an immutable outcome"
                    .into(),
            ));
        }
        let authority = require_post_completion_application_artifact_authority(&authority_state)?;
        let [executor] = persisted.appliers.as_slice() else {
            return Err(RunnerClientError::InvalidLifecycle(
                "durable operation must have exactly one executor and no recovery launch".into(),
            ));
        };
        if executor.role != PostCompletionRollbackApplierRole::Executor
            || executor.launch != self.launch
            || executor.session.as_ref() != Some(&self.session)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "durable executor launch/session differs from the dispatching client".into(),
            ));
        }
        let durable_application = ledger
            .load_application_evidence(&operation.request.application_receipt_id)
            .map_err(RunnerClientError::Ledger)?;
        let durable_reference = ledger
            .load_rollback_reference(&operation.request.rollback_reference_id)
            .map_err(RunnerClientError::Ledger)?;
        let durable_change_set = ledger
            .load_change_set(&operation.sprint_id, &application.receipt.change_set_id)
            .map_err(RunnerClientError::Ledger)?;
        let application_effect = ledger
            .load_effect(&authority.application_effect_id)
            .map_err(RunnerClientError::Ledger)?;
        let application_request = ledger
            .load_application_request_artifact_authority(&authority.application_effect_id)
            .map_err(RunnerClientError::Ledger)?;
        let ApplicationRequestArtifactAuthority::ArtifactBound(application_request) =
            application_request
        else {
            return Err(RunnerClientError::MissingDurableApplicationArtifactAuthority);
        };
        let request_bytes = serde_json::to_vec(&operation.request).map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "post-completion rollback request cannot be canonically encoded: {error}"
            ))
        })?;
        let application_bytes = serde_json::to_vec(application).map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "application evidence cannot be canonically encoded: {error}"
            ))
        })?;
        let rollback_reference_bytes = serde_json::to_vec(rollback_reference).map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "rollback reference evidence cannot be canonically encoded: {error}"
            ))
        })?;
        let applied_operations_digest =
            change_set.applied_operations_digest().map_err(|error| {
                RunnerClientError::InvalidLifecycle(format!(
                    "application change-set operations cannot be authenticated: {error}"
                ))
            })?;
        let touched_path_endpoints_digest =
            change_set
                .touched_path_endpoints_digest()
                .map_err(|error| {
                    RunnerClientError::InvalidLifecycle(format!(
                        "application change-set endpoints cannot be authenticated: {error}"
                    ))
                })?;
        let touched_target_set_digest =
            change_set.touched_target_set_digest().map_err(|error| {
                RunnerClientError::InvalidLifecycle(format!(
                    "application change-set targets cannot be authenticated: {error}"
                ))
            })?;
        let receipt = &application.receipt;
        let reference = &rollback_reference.reference;
        let reopened_wire_bytes = rollback.reopened_artifacts_bytes();
        if durable_application != *application
            || durable_reference != *rollback_reference
            || durable_change_set != *change_set
            || authority.operation_id != operation.operation_id
            || authority.sprint_id != operation.sprint_id
            || authority.application_receipt_id != receipt.receipt_id
            || authority.application_effect_id != receipt.effect_id
            || authority.application_request_digest != application_effect.intent.request_digest
            || authority.artifact != bundle_artifact
            || application_request.change_set != *change_set
            || application_request.artifact != bundle_artifact
            || application_effect.intent.effect_id != receipt.effect_id
            || application_effect.intent.kind != EffectKind::ApplyChangeSet
            || self.role != RunnerRole::Applier
            || self.post_completion_role != Some(PostCompletionRollbackApplierRole::Executor)
            || self.post_completion_operation_id.as_deref() != Some(operation.operation_id.as_str())
            || self.session.purpose != RunnerSessionPurpose::Applier
            || self.session.worker_id.is_some()
            || self.session.sprint_id != operation.sprint_id
            || self.session.policy_hash != operation.policy_hash
            || self.session.grant_hash != operation.grant_hash
            || self.session.policy_version != operation.policy_version
            || self.session.registered_at_unix_ms < operation.created_at_unix_ms
            || self.launch.launch_id != self.session.launch_id
            || self.expected_base_snapshot != bundle.result_snapshot
            || Digest::sha256(&application_bytes) != operation.application_evidence_digest
            || Digest::sha256(&rollback_reference_bytes)
                != operation.rollback_reference_evidence_digest
            || receipt.receipt_id != operation.request.application_receipt_id
            || receipt.sprint_id != operation.sprint_id
            || receipt.transaction_id != operation.request.application_transaction_id
            || receipt.change_set_id != change_set.change_set_id
            || receipt.base_snapshot != change_set.base_snapshot
            || receipt.result_snapshot != change_set.result_snapshot
            || receipt.policy_hash != operation.policy_hash
            || receipt.grant_hash != operation.grant_hash
            || receipt.policy_version != operation.policy_version
            || receipt.applied_operations_digest != applied_operations_digest
            || receipt.touched_path_endpoints_digest != touched_path_endpoints_digest
            || reference.reference_id != operation.request.rollback_reference_id
            || reference.sprint_id != operation.sprint_id
            || reference.application_receipt_id != receipt.receipt_id
            || reference.transaction_id != receipt.transaction_id
            || reference.journal_binding_digest
                != receipt.journal_binding_digest().map_err(|error| {
                    RunnerClientError::InvalidLifecycle(format!(
                        "application journal binding cannot be authenticated: {error}"
                    ))
                })?
            || reference.base_snapshot != change_set.base_snapshot
            || reference.touched_target_set_digest != touched_target_set_digest
            || reference.reopened_artifacts_digest != rollback.artifacts_digest
            || rollback_reference.reopened_artifacts_bytes != reopened_wire_bytes
            || bundle.change_set_id != change_set.change_set_id
            || bundle.base_snapshot != change_set.base_snapshot
            || bundle.result_snapshot != change_set.result_snapshot
            || rollback.transaction_id != operation.request.application_transaction_id
            || rollback.change_set_id != bundle.change_set_id
            || rollback.base_snapshot != bundle.base_snapshot
            || rollback.touched_target_set_digest != touched_target_set_digest
            || Digest::sha256(&request_bytes) != operation.request_digest
            || !self.applier_recovery_complete
            || self.pending_reconciliation.is_some()
            || !self.seen_effect_ids.is_empty()
            || !self.seen_idempotency_keys.is_empty()
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "post-completion rollback differs from the exact fresh applier, operation, applied input, artifact transaction, recovery state, or one-effect lifecycle"
                    .into(),
            ));
        }
        Ok(())
    }

    fn validate_worker_stage_effect(
        &self,
        intent: &EffectIntent,
        core_request_bytes: &[u8],
        request: &RunnerRequest,
    ) -> Result<(), RunnerClientError> {
        let RunnerRequest::WorkerStageChanges {
            change_set,
            expected_bundle,
        } = request
        else {
            return Ok(());
        };
        let prepared = self.prepared_stage.as_ref().ok_or_else(|| {
            RunnerClientError::InvalidLifecycle(
                "worker staging requires one exact prepared change set and bundle".into(),
            )
        })?;
        let core_request: TaskIntegrationRequest = serde_json::from_slice(core_request_bytes)
            .map_err(|error| {
                RunnerClientError::InvalidLifecycle(format!(
                    "worker stage core request is not the typed integration contract: {error}"
                ))
            })?;
        core_request.validate().map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "worker stage core request contract is invalid: {error}"
            ))
        })?;
        let canonical = serde_json::to_vec(&core_request).map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "worker stage core request cannot be canonically encoded: {error}"
            ))
        })?;
        let expected_core_request =
            request
                .to_core_task_integration_request()
                .map_err(|error| {
                    RunnerClientError::InvalidLifecycle(format!(
                        "prepared wire stage cannot map to the core integration request: {error}"
                    ))
                })?;
        if &prepared.change_set != change_set.as_ref()
            || &prepared.expected_bundle != expected_bundle
            || canonical != core_request_bytes
            || core_request != expected_core_request
            || change_set.base_snapshot != self.expected_base_snapshot
            || intent.input_snapshot != core_request.change_set.base_snapshot
            || self.shadow_snapshot.as_ref() != Some(&change_set.result_snapshot)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "worker stage effect differs from the exact prepared change set, bundle, canonical core request, base, or known shadow result"
                    .into(),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed effect response match keeps every admitted runner effect shape visible"
    )]
    pub(super) fn validate_and_apply_effect_response(
        &mut self,
        intent: &EffectIntent,
        request: &RunnerRequest,
        response: &RunnerResponse,
    ) -> Result<(), RunnerClientError> {
        if self.apply_failure_response(response)? {
            return Ok(());
        }
        match (request, response) {
            (
                RunnerRequest::WorkerReadFile { path, max_bytes },
                RunnerResponse::FileRead {
                    path: returned,
                    digest,
                    bytes,
                },
            ) if returned == path
                && u64::try_from(bytes.len()).is_ok_and(|length| length <= *max_bytes)
                && digest == &Digest::sha256(bytes) =>
            {
                Ok(())
            }
            (
                RunnerRequest::WorkerSearchLiteral { path, .. },
                RunnerResponse::LiteralSearch { path: returned, .. },
            ) if returned == path => Ok(()),
            (
                RunnerRequest::WorkerCreateFile { path, contents },
                RunnerResponse::FileMutated {
                    path: returned,
                    input_snapshot,
                    result_snapshot,
                    previous_digest,
                    result_digest,
                },
            ) if returned == path
                && input_snapshot == &intent.input_snapshot
                && previous_digest.is_none()
                && result_digest.as_ref() == Some(&Digest::sha256(contents)) =>
            {
                self.shadow_snapshot = Some(result_snapshot.clone());
                Ok(())
            }
            (
                RunnerRequest::WorkerReplaceFile {
                    path,
                    expected_digest,
                    contents,
                },
                RunnerResponse::FileMutated {
                    path: returned,
                    input_snapshot,
                    result_snapshot,
                    previous_digest,
                    result_digest,
                },
            ) if returned == path
                && input_snapshot == &intent.input_snapshot
                && previous_digest.as_ref() == Some(expected_digest)
                && result_digest.as_ref() == Some(&Digest::sha256(contents)) =>
            {
                self.shadow_snapshot = Some(result_snapshot.clone());
                Ok(())
            }
            (
                RunnerRequest::WorkerDeleteFile {
                    path,
                    expected_digest,
                },
                RunnerResponse::FileMutated {
                    path: returned,
                    input_snapshot,
                    result_snapshot,
                    previous_digest,
                    result_digest,
                },
            ) if returned == path
                && input_snapshot == &intent.input_snapshot
                && previous_digest.as_ref() == Some(expected_digest)
                && result_digest.is_none() =>
            {
                self.shadow_snapshot = Some(result_snapshot.clone());
                Ok(())
            }
            (
                RunnerRequest::WorkerStageChanges {
                    change_set,
                    expected_bundle,
                },
                RunnerResponse::StageBundlePersisted { bundle },
            ) => self.apply_worker_stage_success(change_set, expected_bundle, bundle),
            (
                RunnerRequest::FinalVerifierRunCommand { .. },
                RunnerResponse::CommandCompleted { .. },
            ) => Ok(()),
            (
                RunnerRequest::ApplierApplyBundle { bundle: requested },
                RunnerResponse::ApplicationApplied { evidence },
            ) if &evidence.bundle == requested => Ok(()),
            (
                RunnerRequest::LiveStateVerifierCapture { request },
                RunnerResponse::LiveWorkspaceCaptured { manifest },
            ) if self.role == RunnerRole::LiveStateVerifier
                && manifest.validate().is_ok()
                && manifest.grant_hash == request.plan.grant_hash
                && manifest.grant_hash == self.grant_hash
                && manifest.capture_started_at_unix_ms >= request.plan.planned_at_unix_ms
                && manifest.captured_at_unix_ms >= manifest.capture_started_at_unix_ms =>
            {
                Ok(())
            }
            (
                RunnerRequest::ApplierRollback {
                    bundle: requested,
                    rollback,
                },
                RunnerResponse::RollbackCompleted { evidence },
            ) if &evidence.bundle == requested
                && evidence.transaction_id == rollback.transaction_id
                && evidence.change_set_id == rollback.change_set_id =>
            {
                Ok(())
            }
            _ => Err(RunnerClientError::UnexpectedResponse(
                "the exact successful response for this durable effect",
            )),
        }
    }

    fn apply_worker_stage_success(
        &mut self,
        change_set: &ChangeSet,
        expected_bundle: &StageBundleReference,
        bundle: &StageBundleReference,
    ) -> Result<(), RunnerClientError> {
        if bundle != expected_bundle
            || change_set.change_set_id != bundle.change_set_id
            || change_set.base_snapshot != bundle.base_snapshot
            || change_set.result_snapshot != bundle.result_snapshot
        {
            return Err(RunnerClientError::UnexpectedResponse(
                "the exact persisted bundle for the prepared worker stage",
            ));
        }
        bundle.to_core_integration_artifact().map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "persisted stage bundle cannot map to core integration evidence: {error}"
            ))
        })?;
        self.prepared_stage = None;
        self.pending_reconciliation = None;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed control-state match keeps every role and reconciliation gate visible"
    )]
    pub(super) fn validate_control_request(
        &self,
        request: &RunnerRequest,
    ) -> Result<(), RunnerClientError> {
        if control_role(request) != Some(self.role) {
            return Err(RunnerClientError::InvalidLifecycle(
                "session-control request differs from the immutable runner role".into(),
            ));
        }
        if let Some(post_completion_role) = self.post_completion_role {
            let admitted = match post_completion_role {
                PostCompletionRollbackApplierRole::Executor
                | PostCompletionRollbackApplierRole::RecoveryValidator => {
                    matches!(request, RunnerRequest::ApplierRecoverPending)
                }
            };
            if !admitted {
                return Err(RunnerClientError::InvalidLifecycle(
                    "post-completion roles admit startup recovery only until an operation-local durable application-artifact authority authenticates rollback or reconciliation"
                        .into(),
                ));
            }
        }
        if self.prepared_stage.is_some()
            && !matches!(request, RunnerRequest::WorkerReconcileStage { .. })
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "a prepared worker stage forbids unrelated controls until staging or exact reconciliation completes"
                    .into(),
            ));
        }
        if let Some(reference) = &self.pending_reconciliation
            && !control_resolves_reconciliation(request, reference)
        {
            return Err(RunnerClientError::InvalidLifecycle(
                "control does not exactly resolve the pending typed reconciliation reference"
                    .into(),
            ));
        }
        match request {
            RunnerRequest::WorkerCaptureLive { created_at_unix_ms }
            | RunnerRequest::FinalVerifierCapture { created_at_unix_ms }
            | RunnerRequest::ApplierCaptureLive { created_at_unix_ms }
                if *created_at_unix_ms < self.session.registered_at_unix_ms =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "capture timestamp predates the durable session registration".into(),
                ))
            }
            RunnerRequest::WorkerCreateShadow { base_snapshot }
                if !self.captured_base
                    || self.shadow_created
                    || base_snapshot != &self.expected_base_snapshot =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "worker shadow creation requires the exact captured base and no prior shadow"
                        .into(),
                ))
            }
            RunnerRequest::WorkerReconcileFile { .. } if !self.shadow_created => {
                Err(RunnerClientError::InvalidLifecycle(
                    "worker reconciliation requires the fixed initialized shadow".into(),
                ))
            }
            RunnerRequest::WorkerPrepareStage { .. }
                if self.shadow_snapshot.is_none() || self.prepared_stage.is_some() =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "worker stage preparation requires one exact known shadow and no existing preparation"
                        .into(),
                ))
            }
            RunnerRequest::WorkerPrepareStage {
                created_at_unix_ms, ..
            } if *created_at_unix_ms < self.session.registered_at_unix_ms => {
                Err(RunnerClientError::InvalidLifecycle(
                    "stage preparation timestamp predates the durable session registration".into(),
                ))
            }
            RunnerRequest::WorkerReconcileStage { .. }
                if self.pending_reconciliation.is_none() =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "worker stage reconciliation requires an exact uncertain stage effect".into(),
                ))
            }
            RunnerRequest::WorkerReconcileStage { expected_bundle }
                if self
                    .prepared_stage
                    .as_ref()
                    .is_none_or(|prepared| &prepared.expected_bundle != expected_bundle) =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "worker stage reconciliation differs from the exact retained preparation"
                        .into(),
                ))
            }
            RunnerRequest::ApplierRecoverPending if self.applier_recovery_complete => {
                Err(RunnerClientError::InvalidLifecycle(
                    "applier startup recovery already completed in this session".into(),
                ))
            }
            RunnerRequest::ApplierReconcileStageBundle { .. }
            | RunnerRequest::ApplierReconcile { .. }
            | RunnerRequest::ApplierCaptureLive { .. }
                if !self.applier_recovery_complete =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "applier recovery must complete before reconciliation or capture".into(),
                ))
            }
            RunnerRequest::ApplierReconcileStageBundle { expected_bundle }
                if expected_bundle.to_core_integration_artifact().is_err() =>
            {
                Err(RunnerClientError::InvalidLifecycle(
                    "applier stage reconciliation bundle cannot map to the durable core artifact"
                        .into(),
                ))
            }
            _ => Ok(()),
        }
    }
}
/// One canonical runner source bound to the exact executable image used by the
/// kernel. Linux retains a sealed anonymous copy; unsupported targets retain
/// the inspected source only until their typed pre-ledger refusal.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "unsupported targets retain and inspect the descriptor before the typed launch refusal"
    )
)]
#[doc(hidden)]
pub struct RetainedRunnerExecutable {
    pub(super) file: fs::File,
    pub(super) canonical_path: PathBuf,
    pub(super) digest: Digest,
    pub(super) identity: grok_build_runner::WireBinaryIdentity,
}

impl RetainedRunnerExecutable {
    pub(super) fn inspect(path: &Path) -> Result<Self, io::Error> {
        let canonical_path = fs::canonicalize(path)?;
        if canonical_path != path {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runner binary path must be exact and canonical",
            ));
        }
        let named_before = fs::symlink_metadata(path)?;
        if named_before.file_type().is_symlink() || !named_before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runner binary must be one real regular file",
            ));
        }
        validate_retained_binary_admission(&named_before)?;

        let opened = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let retained = rustix::io::fcntl_dupfd_cloexec(&opened, MIN_RUNNER_EXECUTABLE_FD)
            .map_err(io::Error::from)?;
        drop(opened);
        let mut file = fs::File::from(retained);
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared)
            .map_err(io::Error::from)?;
        ensure_retained_descriptor_flags(&file)?;

        let descriptor_before = file.metadata()?;
        if !same_retained_binary_metadata(&named_before, &descriptor_before) {
            return Err(io::Error::other(
                "runner binary changed while its retained descriptor was acquired",
            ));
        }
        let source_identity = retained_binary_identity(&descriptor_before);
        let (digest, executable_header) =
            digest_retained_binary(&mut file, descriptor_before.len())?;
        // The header is admission evidence only where a native descriptor exec
        // is possible. It was read under an underscore name that the Linux arm
        // then used, which reads as an accident; naming it plainly and
        // discarding it explicitly elsewhere says what actually happens.
        #[cfg(target_os = "linux")]
        validate_native_linux_elf(&executable_header)?;
        #[cfg(not(target_os = "linux"))]
        let _ = executable_header;
        let descriptor_after = file.metadata()?;
        let named_after = fs::symlink_metadata(path)?;
        if !same_retained_binary_metadata(&descriptor_before, &descriptor_after)
            || !same_retained_binary_metadata(&descriptor_after, &named_after)
        {
            return Err(io::Error::other(
                "runner binary changed while its retained bytes were hashed",
            ));
        }

        let (reference_digest, reference_identity) = inspect_runner_binary(path)?;
        if reference_digest != digest || reference_identity != source_identity {
            return Err(io::Error::other(
                "retained runner executable differs from the runner's canonical inspector",
            ));
        }
        let descriptor_final = file.metadata()?;
        if !same_retained_binary_metadata(&descriptor_after, &descriptor_final) {
            return Err(io::Error::other(
                "runner binary changed after canonical inspection",
            ));
        }

        #[cfg(target_os = "linux")]
        let (file, identity) = if INSTALLED_SERVICE_NAMED_EXEC.load(Ordering::SeqCst) {
            (file, source_identity)
        } else {
            create_sealed_linux_executable(
                &mut file,
                &digest,
                source_identity,
                descriptor_final.len(),
            )?
        };
        #[cfg(not(target_os = "linux"))]
        let identity = source_identity;

        #[cfg(target_os = "linux")]
        {
            let named_after_sealing = fs::symlink_metadata(path)?;
            if !same_retained_binary_metadata(&descriptor_final, &named_after_sealing) {
                return Err(io::Error::other(
                    "runner binary changed while its sealed executable image was created",
                ));
            }
        }
        Ok(Self {
            file,
            canonical_path,
            digest,
            identity,
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn revalidate(&mut self) -> Result<(), io::Error> {
        ensure_retained_descriptor_flags(&self.file)?;
        let before = self.file.metadata()?;
        validate_sealed_linux_executable(&self.file, &before)?;
        if retained_binary_identity(&before) != self.identity {
            return Err(io::Error::other(
                "sealed runner executable identity changed before spawn",
            ));
        }
        let (digest, executable_header) = digest_retained_binary(&mut self.file, before.len())?;
        validate_native_linux_elf(&executable_header)?;
        let after = self.file.metadata()?;
        validate_sealed_linux_executable(&self.file, &after)?;
        if !same_retained_binary_metadata(&before, &after) || digest != self.digest {
            return Err(io::Error::other(
                "sealed runner executable changed before spawn",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn descriptor_number(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

pub(super) struct PreparedLaunch {
    pub(super) executable: RetainedRunnerExecutable,
    pub(super) intent: RunnerLaunchIntent,
    binary_digest: Digest,
    binary_identity: grok_build_runner::WireBinaryIdentity,
    private_state_digest: Digest,
    protocol_digest: Digest,
    sprint_spec_digest: Digest,
    role_input_authority: RunnerRoleInputAuthority,
    wire_grant: WireWorkspaceGrant,
    workspace_identity: WireRootIdentity,
    wire_policy: WireExecutionPolicyRequest,
    private_state_root_text: String,
    shadow_root_text: Option<String>,
}

#[cfg(test)]
#[allow(dead_code)]
pub(super) fn prepare_launch(
    authority: &IssuedWorkspaceGrant,
    compiled_policy: &CompiledExecutionPolicy,
    request: &RunnerClientLaunch,
) -> Result<PreparedLaunch, RunnerClientError> {
    prepare_launch_with_context(
        authority,
        compiled_policy,
        request,
        ordinary_role_input_authority(request.role)?,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "preflight keeps the complete SprintSpec, role-input, filesystem, binary, policy, and launch commitments in one audit boundary"
)]
pub(super) fn prepare_launch_with_context(
    authority: &IssuedWorkspaceGrant,
    compiled_policy: &CompiledExecutionPolicy,
    request: &RunnerClientLaunch,
    role_input_authority: RunnerRoleInputAuthority,
) -> Result<PreparedLaunch, RunnerClientError> {
    authority
        .validate_integrity()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    compiled_policy
        .validate_integrity(authority)
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    let sprint_spec_digest = sprint_spec_digest(&request.sprint_spec)
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    let role_input_is_valid = match (&role_input_authority, request.role) {
        (
            RunnerRoleInputAuthority::IntegrationHead,
            RunnerRole::Worker | RunnerRole::FinalVerifier,
        ) => true,
        (RunnerRoleInputAuthority::PlanningBase, RunnerRole::Applier) => {
            request.sprint_spec.base_snapshot == request.expected_base_snapshot
        }
        (
            RunnerRoleInputAuthority::PostCompletionAppliedResult {
                authority,
                authority_digest,
            },
            RunnerRole::Applier,
        ) => {
            authority.validate().is_ok()
                && serde_json::to_vec(authority)
                    .ok()
                    .is_some_and(|canonical| Digest::sha256(&canonical) == *authority_digest)
                && authority.sprint_id == request.sprint_id
                && authority.artifact.base_snapshot == request.sprint_spec.base_snapshot
                && authority.artifact.result_snapshot == request.expected_base_snapshot
        }
        (
            RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest },
            RunnerRole::LiveStateVerifier,
        ) => {
            plan.validate().is_ok()
                && plan
                    .plan_digest()
                    .is_ok_and(|computed| computed == *plan_digest)
                && plan.sprint_id == request.sprint_id
                && plan.expected_snapshot == request.expected_base_snapshot
                && plan.grant_hash == authority.contract().grant_hash
                && plan.policy_hash == compiled_policy.contract().policy_hash
                && plan.policy_version == authority.contract().policy_version
        }
        _ => false,
    };
    if request.sprint_spec.sprint_id != request.sprint_id
        || request.sprint_spec.workspace_grant != *authority.contract()
        || request.sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated
        || !role_input_is_valid
        || compiled_policy.contract().resource_limits.wall_time_ms
            > request.sprint_spec.budget.max_duration_ms
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "launch sprint specification differs from sprint, grant, base snapshot, provider origin, or execution budget"
                .into(),
        ));
    }
    validate_role_shape(request)?;
    if request.created_at_unix_ms == 0 {
        return Err(RunnerClientError::InvalidLifecycle(
            "launch timestamp must be nonzero".into(),
        ));
    }
    let executable = RetainedRunnerExecutable::inspect(&request.runner_binary)?;
    let binary_digest = executable.digest.clone();
    let binary_identity = executable.identity;
    let private_state_digest = inspect_private_state_digest(&request.private_state_root)?;
    let protocol_digest = runner_protocol_digest();
    let purpose = runner_purpose(request.role);
    let policy = compiled_policy.contract();
    exact_path_text(
        &authority.contract().canonical_root,
        "workspace grant canonical root",
    )?;
    let private_state_root_text =
        exact_path_text(&request.private_state_root, "private-state root")?;
    let shadow_root_text = request
        .shadow_root
        .as_deref()
        .map(|path| exact_path_text(path, "fixed shadow root"))
        .transpose()?;
    let wire_grant = WireWorkspaceGrant::try_from(authority.contract())?;
    let wire_policy = wire_policy_request(policy)?;
    Ok(PreparedLaunch {
        executable,
        intent: RunnerLaunchIntent {
            contract_version: CONTRACT_VERSION,
            launch_id: request.launch_id.clone(),
            sprint_id: request.sprint_id.clone(),
            session_id: request.session_id.clone(),
            purpose,
            worker_id: request.worker_id.clone(),
            worker_lease: request.worker_lease.clone(),
            policy_hash: policy.policy_hash.clone(),
            runner_binary_digest: binary_digest.clone(),
            protocol_digest: protocol_digest.clone(),
            private_state_digest: private_state_digest.clone(),
            grant_hash: authority.contract().grant_hash.clone(),
            policy_version: authority.contract().policy_version,
            created_at_unix_ms: request.created_at_unix_ms,
        },
        binary_digest,
        binary_identity,
        private_state_digest,
        protocol_digest,
        sprint_spec_digest,
        role_input_authority,
        wire_grant,
        workspace_identity: WireRootIdentity {
            device_id: authority.identity().device_id(),
            inode: authority.identity().inode(),
        },
        wire_policy,
        private_state_root_text,
        shadow_root_text,
    })
}

pub(super) fn validate_retained_binary_admission(metadata: &fs::Metadata) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt as _;

    let mode = metadata.mode();
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_RETAINED_RUNNER_BINARY_BYTES
        || mode & 0o7_000 != 0
        || mode & 0o022 != 0
        || mode & 0o100 == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runner binary must be bounded, nonempty, singly linked, owned by the execution user, owner-executable, non-setid, and not group/world writable",
        ));
    }
    Ok(())
}

pub(super) fn retained_binary_identity(
    metadata: &fs::Metadata,
) -> grok_build_runner::WireBinaryIdentity {
    use std::os::unix::fs::MetadataExt as _;

    grok_build_runner::WireBinaryIdentity {
        device_id: metadata.dev(),
        inode: metadata.ino(),
        byte_length: metadata.len(),
        mode: metadata.mode(),
        owner_uid: metadata.uid(),
        link_count: metadata.nlink(),
    }
}

pub(super) fn same_retained_binary_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(super) fn ensure_retained_descriptor_flags(file: &fs::File) -> Result<(), io::Error> {
    let descriptor = file.as_raw_fd();
    let flags = rustix::io::fcntl_getfd(file).map_err(io::Error::from)?;
    if descriptor < MIN_RUNNER_EXECUTABLE_FD || !flags.contains(rustix::io::FdFlags::CLOEXEC) {
        return Err(io::Error::other(
            "retained runner descriptor must be at least three and close-on-exec",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn required_executable_memfd_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL
        | rustix::fs::SealFlags::SHRINK
        | rustix::fs::SealFlags::GROW
        | rustix::fs::SealFlags::WRITE
        | rustix::fs::SealFlags::FUTURE_WRITE
        | rustix::fs::SealFlags::EXEC
}

#[cfg(target_os = "linux")]
pub(super) fn validate_sealed_linux_executable(
    file: &fs::File,
    metadata: &fs::Metadata,
) -> Result<(), io::Error> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 0
        || metadata.len() == 0
        || metadata.len() > MAX_RETAINED_RUNNER_BINARY_BYTES
        || metadata.mode() & 0o7_777 != 0o500
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sealed runner image must be a bounded anonymous owner-read-executable regular file",
        ));
    }
    let seals = rustix::fs::fcntl_get_seals(file).map_err(io::Error::from)?;
    if seals != required_executable_memfd_seals() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sealed runner image does not have the exact immutable executable memfd seal set",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn create_sealed_linux_executable(
    source: &mut fs::File,
    expected_digest: &Digest,
    expected_source_identity: grok_build_runner::WireBinaryIdentity,
    expected_length: u64,
) -> Result<(fs::File, grok_build_runner::WireBinaryIdentity), io::Error> {
    let source_before = source.metadata()?;
    if retained_binary_identity(&source_before) != expected_source_identity
        || source_before.len() != expected_length
    {
        return Err(io::Error::other(
            "runner source identity changed before sealed-image creation",
        ));
    }

    let created = rustix::fs::memfd_create(
        SEALED_RUNNER_MEMFD_NAME,
        rustix::fs::MemfdFlags::CLOEXEC
            | rustix::fs::MemfdFlags::ALLOW_SEALING
            | rustix::fs::MemfdFlags::EXEC,
    )
    .map_err(io::Error::from)?;
    let retained = rustix::io::fcntl_dupfd_cloexec(&created, MIN_RUNNER_EXECUTABLE_FD)
        .map_err(io::Error::from)?;
    drop(created);
    let mut sealed = fs::File::from(retained);
    ensure_retained_descriptor_flags(&sealed)?;
    rustix::fs::fchmod(&sealed, rustix::fs::Mode::RUSR | rustix::fs::Mode::XUSR)
        .map_err(io::Error::from)?;

    source.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut executable_header = [0_u8; 20];
    let mut header_length = 0_usize;
    let mut observed_length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(u64::try_from(count).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "runner copy length overflow")
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "runner copy length overflow")
            })?;
        if observed_length > MAX_RETAINED_RUNNER_BINARY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runner source exceeded the sealed-image admission bound",
            ));
        }
        if header_length < executable_header.len() {
            let copied = (executable_header.len() - header_length).min(count);
            executable_header[header_length..header_length + copied]
                .copy_from_slice(&buffer[..copied]);
            header_length += copied;
        }
        digest.update(&buffer[..count]);
        sealed.write_all(&buffer[..count])?;
    }
    source.seek(SeekFrom::Start(0))?;
    sealed.flush()?;
    sealed.sync_all()?;

    let copied_digest = finish_sha256_digest(digest)?;
    let source_after = source.metadata()?;
    if observed_length != expected_length
        || copied_digest != *expected_digest
        || !same_retained_binary_metadata(&source_before, &source_after)
    {
        return Err(io::Error::other(
            "runner source changed while its sealed executable image was copied",
        ));
    }
    validate_native_linux_elf(&executable_header)?;

    rustix::fs::fcntl_add_seals(&sealed, required_executable_memfd_seals())
        .map_err(io::Error::from)?;
    let sealed_before = sealed.metadata()?;
    validate_sealed_linux_executable(&sealed, &sealed_before)?;
    let (sealed_digest, sealed_header) = digest_retained_binary(&mut sealed, sealed_before.len())?;
    validate_native_linux_elf(&sealed_header)?;
    let sealed_after = sealed.metadata()?;
    validate_sealed_linux_executable(&sealed, &sealed_after)?;
    if sealed_digest != *expected_digest
        || !same_retained_binary_metadata(&sealed_before, &sealed_after)
    {
        return Err(io::Error::other(
            "sealed runner executable readback differs from its authenticated source",
        ));
    }
    Ok((sealed, retained_binary_identity(&sealed_after)))
}

pub(super) fn finish_sha256_digest(digest: Sha256) -> Result<Digest, io::Error> {
    let digest_bytes = digest.finalize();
    let mut digest_text = String::with_capacity(64);
    for byte in digest_bytes {
        use std::fmt::Write as _;
        let _ = write!(digest_text, "{byte:02x}");
    }
    Digest::parse(digest_text).map_err(io::Error::other)
}

pub(super) fn digest_retained_binary(
    file: &mut fs::File,
    expected_length: u64,
) -> Result<(Digest, [u8; 20]), io::Error> {
    if expected_length == 0 || expected_length > MAX_RETAINED_RUNNER_BINARY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "retained runner binary length is outside the admitted bound",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut executable_header = [0_u8; 20];
    let mut header_length = 0_usize;
    let mut observed_length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(u64::try_from(read).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "runner read length overflow")
            })?)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "runner byte length overflow")
            })?;
        if observed_length > MAX_RETAINED_RUNNER_BINARY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained runner binary exceeded its admitted bound while reading",
            ));
        }
        if header_length < executable_header.len() {
            let copied = (executable_header.len() - header_length).min(read);
            executable_header[header_length..header_length + copied]
                .copy_from_slice(&buffer[..copied]);
            header_length += copied;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))?;
    if observed_length != expected_length {
        return Err(io::Error::other(
            "retained runner binary length changed while it was read",
        ));
    }
    let digest = finish_sha256_digest(digest)?;
    Ok((digest, executable_header))
}

/// Descriptor execution through `/proc/self/fd` is a property of procfs, not of
/// any instruction set, so the Linux bridge is admitted on every architecture
/// whose native ELF machine code this build can name. The image must still be
/// proved native: [`NATIVE_ELF_MACHINE`] is the host's own `e_machine`, and an
/// image carrying any other one is refused by [`validate_native_linux_elf`].
#[cfg(target_os = "linux")]
pub(super) fn ensure_descriptor_execution_supported() -> Result<(), RunnerClientError> {
    if NATIVE_ELF_MACHINE.is_none() {
        return Err(RunnerClientError::DescriptorExecutionUnavailable {
            target: NATIVE_LAUNCH_TARGET,
            reason:
                "no native ELF machine code is admitted for this architecture, so a descriptor-executed image cannot be authenticated"
                    .into(),
        });
    }
    authenticate_linux_procfs().map_err(|error| RunnerClientError::DescriptorExecutionUnavailable {
        target: NATIVE_LAUNCH_TARGET,
        reason: super::transport::bounded_error(&error),
    })
}

#[cfg(not(target_os = "linux"))]
pub(super) fn ensure_descriptor_execution_supported() -> Result<(), RunnerClientError> {
    #[cfg(target_os = "macos")]
    let reason =
        "macOS 15 exposes neither fexecve nor execveat, and /dev/fd execution is not admitted";
    #[cfg(not(target_os = "macos"))]
    let reason = "no audited retained-descriptor execution bridge is implemented";
    Err(RunnerClientError::DescriptorExecutionUnavailable {
        target: NATIVE_LAUNCH_TARGET,
        reason: reason.into(),
    })
}

#[cfg(target_os = "linux")]
pub(super) fn authenticate_linux_procfs() -> Result<(), io::Error> {
    let descriptor_directory = Path::new("/proc/self/fd");
    let filesystem = rustix::fs::statfs(descriptor_directory).map_err(io::Error::from)?;
    if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc/self/fd is not backed by genuine procfs",
        ));
    }
    if !fs::metadata(descriptor_directory)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc/self/fd is not an accessible procfs descriptor directory",
        ));
    }
    Ok(())
}

/// Admits only an ELF64 little-endian executable whose `e_machine` is exactly
/// the host architecture's own code.
///
/// The header prefix pins `ELFCLASS64`, `ELFDATA2LSB`, and `EV_CURRENT`; the
/// type must be `ET_EXEC` or `ET_DYN`; and the machine must equal
/// [`NATIVE_ELF_MACHINE`]. Widening the descriptor-exec gate beyond x86-64 does
/// not widen this check: a foreign-architecture image is refused here, before
/// any sealed copy is created and long before any exec.
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "ELF admission is compiled on macOS so its pure parser remains type-checked"
    )
)]
pub(super) fn validate_native_linux_elf(bytes: &[u8]) -> Result<(), io::Error> {
    let Some(native_machine) = NATIVE_ELF_MACHINE else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no native ELF machine code is admitted for this architecture",
        ));
    };
    let executable_type = bytes.get(16..18);
    let machine = bytes.get(18..20);
    if bytes.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || !matches!(executable_type, Some([2 | 3, 0]))
        || machine != Some(native_machine.to_le_bytes().as_slice())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runner descriptor is not a little-endian ELF64 executable image for this host architecture",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn authenticated_proc_descriptor_path(
    executable: &RetainedRunnerExecutable,
) -> Result<PathBuf, io::Error> {
    authenticate_linux_procfs()?;
    ensure_retained_descriptor_flags(&executable.file)?;
    validate_sealed_linux_executable(&executable.file, &executable.file.metadata()?)?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", executable.descriptor_number()));
    if !fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "procfs descriptor entry is not a magic symbolic link",
        ));
    }
    let proc_identity = retained_binary_identity(&fs::metadata(&path)?);
    let descriptor_identity = retained_binary_identity(&executable.file.metadata()?);
    if proc_identity != executable.identity || descriptor_identity != executable.identity {
        return Err(io::Error::other(
            "procfs descriptor entry differs from the retained runner executable",
        ));
    }
    Ok(path)
}

pub(super) fn validate_role_shape(request: &RunnerClientLaunch) -> Result<(), RunnerClientError> {
    let worker_shape = match (
        request.role,
        request.worker_id.as_deref(),
        request.worker_lease.as_ref(),
    ) {
        (RunnerRole::Worker, Some(worker_id), Some(lease)) => {
            lease
                .validate_assignment(&request.sprint_id, &lease.task_id, worker_id)
                .is_ok()
                && request.created_at_unix_ms >= lease.acquired_at_unix_ms
        }
        _ => false,
    };
    let non_worker_shape = request.role != RunnerRole::Worker
        && request.worker_id.is_none()
        && request.worker_lease.is_none();
    let shadow_shape = match request.role {
        RunnerRole::Worker | RunnerRole::FinalVerifier => request.shadow_root.is_some(),
        RunnerRole::Applier | RunnerRole::LiveStateVerifier => request.shadow_root.is_none(),
    };
    if !(worker_shape || non_worker_shape) || !shadow_shape {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner role, logical worker, active lease, and fixed shadow shape disagree".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_post_completion_launch_request(
    operation: &PostCompletionRollbackIntent,
    compiled_policy: &CompiledExecutionPolicy,
    request: &RunnerClientLaunch,
) -> Result<(), RunnerClientError> {
    operation
        .validate()
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    let policy = compiled_policy.contract();
    if request.role != RunnerRole::Applier
        || request.worker_id.is_some()
        || request.worker_lease.is_some()
        || request.shadow_root.is_some()
        || request.sprint_id != operation.sprint_id
        || request.created_at_unix_ms < operation.created_at_unix_ms
        || policy.policy_hash != operation.policy_hash
        || policy.grant_hash != operation.grant_hash
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "post-completion launch must be a fresh applier bound to the exact completed sprint, operation ordering, policy, and grant"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn initialization_envelope(
    request: &RunnerClientLaunch,
    prepared: &PreparedLaunch,
) -> RunnerRequestEnvelope {
    RunnerRequestEnvelope {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
        session_id: request.session_id.clone(),
        runner_nonce: None,
        sequence: 0,
        request_id: format!("{}:initialize", request.session_id),
        effect: None,
        request: RunnerRequest::InitializeSession {
            launch_id: request.launch_id.clone(),
            sprint_id: request.sprint_id.clone(),
            sprint_spec: Box::new(request.sprint_spec.clone()),
            expected_sprint_spec_digest: prepared.sprint_spec_digest.clone(),
            logical_worker_id: request.worker_id.clone(),
            worker_lease: request.worker_lease.clone(),
            role: request.role,
            role_input_authority: prepared.role_input_authority.clone(),
            workspace_grant: Box::new(prepared.wire_grant.clone()),
            execution_policy_request: Box::new(prepared.wire_policy.clone()),
            expected_policy_hash: prepared.intent.policy_hash.clone(),
            expected_base_snapshot: request.expected_base_snapshot.clone(),
            expected_private_state_digest: prepared.private_state_digest.clone(),
            expected_binary_digest: prepared.binary_digest.clone(),
            expected_binary_identity: prepared.binary_identity,
            private_state_root: prepared.private_state_root_text.clone(),
            shadow_root: prepared.shadow_root_text.clone(),
        },
    }
}

pub(super) fn validate_initialization_receipt(
    receipt: &InitializationReceipt,
    request: &RunnerClientLaunch,
    prepared: &PreparedLaunch,
) -> Result<(), RunnerClientError> {
    let policy = &prepared.wire_policy;
    if receipt.launch_id != request.launch_id
        || receipt.sprint_id != request.sprint_id
        || receipt.sprint_spec_digest != prepared.sprint_spec_digest
        || receipt.logical_worker_id != request.worker_id
        || receipt.worker_lease != request.worker_lease
        || receipt.role != request.role
        || receipt.role_input_authority != prepared.role_input_authority
        || receipt.grant_id != prepared.wire_grant.grant_id
        || receipt.canonical_root != prepared.wire_grant.canonical_root
        || receipt.grant_hash != prepared.wire_grant.grant_hash
        || receipt.policy_id != policy.policy_id
        || receipt.policy_hash != prepared.intent.policy_hash
        || receipt.expected_base_snapshot != request.expected_base_snapshot
        || receipt.workspace_identity != prepared.workspace_identity
        || receipt.private_state_digest != prepared.private_state_digest
        || receipt.binary_digest != prepared.binary_digest
        || receipt.binary_identity != prepared.binary_identity
        || receipt.protocol_digest != prepared.protocol_digest
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "initialization receipt differs from launch, policy, base, binary, private state, or protocol evidence"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn admit_fresh_nonce(nonce: &Digest) -> Result<(), RunnerClientError> {
    let seen = SEEN_RUNNER_NONCES.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut guard = seen.lock().map_err(|_| {
        RunnerClientError::InvalidLifecycle("runner nonce registry is poisoned".into())
    })?;
    admit_nonce_into(&mut guard, nonce, MAX_SEEN_RUNNER_NONCES)
}

pub(super) fn admit_nonce_into(
    seen: &mut BTreeSet<String>,
    nonce: &Digest,
    capacity: usize,
) -> Result<(), RunnerClientError> {
    if seen.contains(nonce.as_str()) {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner nonce was already observed by this desktop process".into(),
        ));
    }
    if seen.len() >= capacity {
        return Err(RunnerClientError::InvalidLifecycle(
            "runner nonce registry reached its fail-closed lifetime bound".into(),
        ));
    }
    seen.insert(nonce.as_str().to_owned());
    Ok(())
}

pub(super) fn validate_applier_input_snapshot(
    intent: &EffectIntent,
    request: &RunnerRequest,
) -> Result<(), RunnerClientError> {
    match request {
        RunnerRequest::ApplierApplyBundle { bundle }
            if intent.input_snapshot != bundle.base_snapshot =>
        {
            Err(RunnerClientError::InvalidLifecycle(
                "applier apply input differs from the exact bundle base snapshot".into(),
            ))
        }
        RunnerRequest::ApplierRollback { bundle, .. }
            if intent.input_snapshot != bundle.result_snapshot =>
        {
            Err(RunnerClientError::InvalidLifecycle(
                "applier rollback input differs from the exact applied bundle result snapshot"
                    .into(),
            ))
        }
        _ => Ok(()),
    }
}

pub(super) fn validate_applier_application_request(
    intent: &EffectIntent,
    core_request_bytes: &[u8],
    request: &RunnerRequest,
    expected_base_snapshot: &Digest,
) -> Result<(), RunnerClientError> {
    let RunnerRequest::ApplierApplyBundle { bundle } = request else {
        return Ok(());
    };
    let application: ApplicationRequest =
        serde_json::from_slice(core_request_bytes).map_err(|error| {
            RunnerClientError::InvalidLifecycle(format!(
                "applier core request is not the typed application contract: {error}"
            ))
        })?;
    application.validate().map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "applier core application request is invalid: {error}"
        ))
    })?;
    let canonical = serde_json::to_vec(&application).map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "applier core application request cannot be canonically encoded: {error}"
        ))
    })?;
    let bundle_artifact = bundle.to_core_integration_artifact().map_err(|error| {
        RunnerClientError::InvalidLifecycle(format!(
            "applier bundle cannot map to an immutable application artifact: {error}"
        ))
    })?;
    if canonical != core_request_bytes
        || application.artifact != bundle_artifact
        || application.change_set.change_set_id != bundle.change_set_id
        || application.change_set.base_snapshot != bundle.base_snapshot
        || application.change_set.result_snapshot != bundle.result_snapshot
        || intent.input_snapshot != application.change_set.base_snapshot
        || expected_base_snapshot != &application.change_set.base_snapshot
    {
        return Err(RunnerClientError::InvalidLifecycle(
            "applier effect differs from the exact canonical application request, immutable stage bundle, or admitted base snapshot"
                .into(),
        ));
    }
    Ok(())
}

pub(super) fn wire_policy_request(
    policy: &grok_build_core::ExecutionPolicy,
) -> Result<WireExecutionPolicyRequest, RunnerClientError> {
    Ok(WireExecutionPolicyRequest {
        policy_id: policy.policy_id.clone(),
        read_scopes: policy
            .read_scopes
            .iter()
            .map(wire_scope)
            .collect::<Result<Vec<_>, _>>()?,
        write_scopes: policy
            .write_scopes
            .iter()
            .map(wire_scope)
            .collect::<Result<Vec<_>, _>>()?,
        environment: policy.environment.iter().map(wire_environment).collect(),
        network: match policy.network {
            ExecutionNetwork::None => WireExecutionNetwork::None,
            ExecutionNetwork::FullForAction => WireExecutionNetwork::FullForAction,
        },
        mutation_mode: match policy.mutation_mode {
            MutationMode::ReadOnly => WireMutationMode::ReadOnly,
            MutationMode::ShadowWorkspace => WireMutationMode::ShadowWorkspace,
        },
        resource_limits: wire_limits(policy.resource_limits),
        approval_id: policy.approval_id.clone(),
    })
}

pub(super) fn wire_scope(scope: &PathScope) -> Result<WirePathScope, RunnerClientError> {
    match scope {
        PathScope::Workspace => Ok(WirePathScope::Workspace),
        PathScope::Relative(path) => Ok(WirePathScope::Relative {
            path: exact_path_text(path, "execution-policy path scope")?,
        }),
    }
}

pub(super) fn wire_environment(variable: &EnvironmentVariable) -> WireEnvironmentVariable {
    WireEnvironmentVariable {
        name: variable.name.clone(),
        value: variable.value.clone(),
    }
}

pub(super) const fn wire_limits(limits: ResourceLimits) -> WireResourceLimits {
    WireResourceLimits {
        wall_time_ms: limits.wall_time_ms,
        max_output_bytes: limits.max_output_bytes,
        max_processes: limits.max_processes,
        max_memory_bytes: limits.max_memory_bytes,
    }
}

pub(super) fn exact_path_text(
    path: &Path,
    field: &'static str,
) -> Result<String, RunnerClientError> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        RunnerClientError::InvalidLifecycle(format!(
            "{field} is not exactly representable as UTF-8"
        ))
    })
}

/// Reads the current Unix time in milliseconds with overflow refusal.
#[doc(hidden)]
pub fn current_unix_ms() -> Result<u64, RunnerClientError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RunnerClientError::InvalidLifecycle(error.to_string()))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| RunnerClientError::InvalidLifecycle("system time exceeds u64".into()))
}

pub(super) fn launch_failure(
    error: RunnerClientError,
    cleanup_required: Option<RunnerCleanupRequired>,
) -> RunnerLaunchFailure {
    RunnerLaunchFailure {
        error,
        cleanup_required: cleanup_required.map(Box::new),
    }
}
