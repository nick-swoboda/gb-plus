    /// Clock the strict fake stamps its registered session and its
    /// `Leased -> Running` boundary from.
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum StrictFakeRunningClock {
        /// Deterministic fixture time: exactly one unit after the attempt
        /// opened, which is always at or before the coordinator's request.
        OneUnitAfterAttemptOpening,
        /// The host wall clock, exactly as the production
        /// `RunnerLifecycleClient` stamps `registered_at_unix_ms =
        /// max(current_unix_ms(), request.created_at_unix_ms)` after a real
        /// spawn and wire handshake. It lands far past the fixture cursor.
        HostWallClock,
    }

    fn host_wall_clock_unix_ms() -> Result<u64, DurableCoordinatorError> {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "host wall clock predates the Unix epoch: {error}"
                ))
            })?
            .as_millis();
        u64::try_from(millis).map_err(|_| {
            DurableCoordinatorError::Protocol(
                "host wall clock exceeds the durable timestamp range".into(),
            )
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the strict fake keeps the complete production-shaped launch, cleanup, preparation, session, and Running chain explicit"
    )]
    fn strict_fake_ensure_task_attempt_running(
        ledger: &mut EventLedger,
        start: &WalkingSkeletonRunnerStart<'_>,
        clock: StrictFakeRunningClock,
    ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            validate_exact_authority(start.authority, start.sprint_spec)?;
            start.policy.validate_integrity(start.authority)?;
            start.attempt.validate()?;
            start.attempt.worker_lease.validate_assignment(
                &start.sprint_spec.sprint_id,
                &start.task.task_id,
                WORKER_ID,
            )?;
            if start.attempt.worker_lease.path_scopes != start.task.path_scopes
                || start.input_snapshot != &start.sprint_spec.base_snapshot
                || !start.shadow_root.is_absolute()
                || start.requested_at_unix_ms < start.attempt.opened_at_unix_ms
            {
                return Err(DurableCoordinatorError::Protocol(
                    "fake runner received crossed task, snapshot, shadow, or timestamp authority"
                        .into(),
                ));
            }

            let history = ledger
                .load_task_attempt_history(&start.sprint_spec.sprint_id, &start.task.task_id)?;
            let active = history.active_attempt().ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "fake runner received an attempt that is not durably active".into(),
                )
            })?;
            if active.attempt != *start.attempt {
                return Err(DurableCoordinatorError::Protocol(
                    "fake runner received a substituted active attempt".into(),
                ));
            }
            if let Some(boundary) = &active.running_boundary {
                if history.task_state != TaskState::Running {
                    return Err(DurableCoordinatorError::Protocol(
                        "fake runner found a Running boundary outside Running task state".into(),
                    ));
                }
                return Ok(boundary.clone());
            }
            if history.task_state != TaskState::Leased {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "fake runner cannot initialize attempt {} from {:?}",
                    start.attempt.attempt_id, history.task_state
                )));
            }

            let lifecycle_at = start
                .attempt
                .opened_at_unix_ms
                .checked_add(1)
                .ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "fake runner lifecycle timestamp overflow".into(),
                    )
                })?;
            if start.requested_at_unix_ms < lifecycle_at {
                return Err(DurableCoordinatorError::Protocol(
                    "fake runner lifecycle request predates its deterministic launch time".into(),
                ));
            }
            // The launch side keeps its deterministic time. Only the session
            // registration and the boundary it authorizes move, exactly as
            // production does: the launch intent is stamped by the coordinator's
            // cursor and `registered_at_unix_ms` by the host clock afterwards.
            let registered_at = match clock {
                StrictFakeRunningClock::OneUnitAfterAttemptOpening => lifecycle_at,
                StrictFakeRunningClock::HostWallClock => host_wall_clock_unix_ms()?
                    .max(start.requested_at_unix_ms)
                    .max(lifecycle_at),
            };

            let launch_id = fake_runner_identity("launch", start.attempt);
            let session_id = fake_runner_identity("session", start.attempt);
            let (_, _, private_state_digest) =
                strict_fake_command_output_store(start.authority, &launch_id)?;
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: launch_id.clone(),
                sprint_id: start.sprint_spec.sprint_id.clone(),
                session_id: session_id.clone(),
                purpose: RunnerSessionPurpose::TaskWorker,
                worker_id: Some(WORKER_ID.into()),
                worker_lease: Some(start.attempt.worker_lease.clone()),
                policy_hash: start.policy.contract().policy_hash.clone(),
                runner_binary_digest: fake_runner_digest("binary", start.attempt),
                protocol_digest: runner_protocol_digest(),
                private_state_digest,
                grant_hash: start.authority.contract().grant_hash.clone(),
                policy_version: start.authority.contract().policy_version,
                created_at_unix_ms: lifecycle_at,
            };
            let cleanup_request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: strict_fake_command_runner_cleanup_backend(),
            };
            let cleanup_bytes = serde_json::to_vec(&cleanup_request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "fake cleanup request could not be encoded: {error}"
                ))
            })?;
            let cleanup_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: fake_runner_identity("cleanup-effect", start.attempt),
                idempotency_key: fake_runner_identity("cleanup-key", start.attempt),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: Some(start.attempt.worker_lease.clone()),
                causation_event_id: None,
                correlation_id: fake_runner_identity("cleanup-correlation", start.attempt),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&cleanup_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: start.input_snapshot.clone(),
                created_at_unix_ms: lifecycle_at,
            };
            let cleanup_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&launch.sprint_id)?,
                event_id: fake_runner_identity("cleanup-proposed", start.attempt),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: cleanup_intent.correlation_id.clone(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: lifecycle_at,
                payload: AgentEventKind::ToolProposed {
                    tool_call_id: cleanup_intent.idempotency_key.clone(),
                    tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
                },
            };
            let admission = match ledger.admit_runner_launch_with_cleanup(
                &launch,
                start.policy,
                &cleanup_intent,
                &cleanup_bytes,
                &cleanup_event,
            ) {
                Ok(admission) => admission,
                Err(LedgerError::ArtifactAlreadyExists { .. }) => {
                    let existing = ledger.load_runner_launch_cleanup_admission(
                        &launch.sprint_id,
                        &launch.launch_id,
                    )?;
                    if existing.launch != launch
                        || existing.cleanup_request != cleanup_request
                        || existing.cleanup_effect.intent != cleanup_intent
                        || existing.cleanup_effect.request_bytes != cleanup_bytes
                        || existing.cleanup_effect.proposed_event != cleanup_event
                        || existing.cleanup_effect.observation.is_some()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "fake runner found a crossed durable launch/cleanup admission".into(),
                        ));
                    }
                    existing
                }
                Err(error) => return Err(error.into()),
            };
            let preparation_attempt = RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: fake_runner_identity("native-preparation", start.attempt),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                cleanup_effect_id: cleanup_intent.effect_id.clone(),
                native_journal_id: fake_runner_identity("native-journal", start.attempt),
                expected_platform_binding_digest: fake_runner_digest(
                    "platform-binding",
                    start.attempt,
                ),
                claimed_at_unix_ms: lifecycle_at,
            };
            let preparation_outcome = RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: format!(
                    "strict-fake-held-child:{}",
                    preparation_attempt.native_journal_id
                )
                .into_bytes(),
                finished_at_unix_ms: lifecycle_at,
            };
            match ledger.load_runner_launch_preparation(&launch.sprint_id, &launch.launch_id) {
                Ok(existing)
                    if existing.attempt == preparation_attempt
                        && existing.outcome.as_ref() == Some(&preparation_outcome) => {}
                Ok(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "fake runner found crossed or incomplete durable native preparation".into(),
                    ));
                }
                Err(LedgerError::ArtifactNotFound { .. }) => {
                    let expected_outcome = preparation_outcome.clone();
                    let prepared = ledger.with_runner_launch_preparation_claim(
                        &admission,
                        &preparation_attempt,
                        |_| expected_outcome,
                    )?;
                    if prepared.attempt != preparation_attempt
                        || prepared.outcome.as_ref() != Some(&preparation_outcome)
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "fake runner native preparation readback was crossed".into(),
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }

            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                purpose: launch.purpose,
                worker_id: launch.worker_id.clone(),
                worker_lease: launch.worker_lease.clone(),
                policy_hash: launch.policy_hash.clone(),
                session_nonce: fake_runner_digest("session-nonce", start.attempt),
                runner_binary_digest: launch.runner_binary_digest.clone(),
                protocol_digest: launch.protocol_digest.clone(),
                private_state_digest: launch.private_state_digest.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                registered_at_unix_ms: registered_at,
            };
            match ledger.load_runner_session(&launch.sprint_id, &session.session_id) {
                Ok(existing) if existing == session => {}
                Ok(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "fake runner found a crossed durable session registration".into(),
                    ));
                }
                Err(LedgerError::ArtifactNotFound { .. }) => {
                    ledger.register_runner_session(&session, start.policy)?;
                    if ledger.load_runner_session(&launch.sprint_id, &session.session_id)?
                        != session
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "fake runner session registration readback was crossed".into(),
                        ));
                    }
                }
                Err(error) => return Err(error.into()),
            }

            let boundary_identity = fake_runner_digest("running-boundary", start.attempt);
            let running_event_id = format!("fake-runner-running-event-{boundary_identity}");
            let boundary = TaskAttemptRunningBoundary {
                contract_version: CONTRACT_VERSION,
                boundary_id: format!("fake-runner-running-boundary-{boundary_identity}"),
                attempt: start.attempt.clone(),
                runner_launch_id: launch_id,
                runner_session_id: session_id,
                transition_event_id: running_event_id.clone(),
                started_at_unix_ms: registered_at,
            };
            let running_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&start.sprint_spec.sprint_id)?,
                event_id: running_event_id,
                sprint_id: start.sprint_spec.sprint_id.clone(),
                task_id: Some(start.task.task_id.clone()),
                worker_id: Some(WORKER_ID.into()),
                causation_id: Some(start.attempt.opening_event_id.clone()),
                correlation_id: fake_runner_identity("running-correlation", start.attempt),
                policy_hash: Some(start.policy.contract().policy_hash.clone()),
                occurred_at_unix_ms: registered_at,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Leased".into(),
                    to: "Running".into(),
                },
            };
            Ok(ledger.start_task_attempt(&boundary, &running_event)?)
    }

    impl WalkingSkeletonRunnerLifecycle for StrictFakeRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            strict_fake_ensure_task_attempt_running(
                ledger,
                &start,
                StrictFakeRunningClock::OneUnitAfterAttemptOpening,
            )
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict fake mirrors claim validation, exact file execution, and complete mutation-receipt retention in one auditable seam"
        )]
        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            let WalkingSkeletonTaskEffectDispatch {
                sprint_spec,
                workspace_grant,
                policy,
                running_boundary,
                runner_launch,
                runner_session,
                intent,
                request_bytes,
                provider_call,
                post_response_timestamps,
                shadow,
                dispatch_permit,
            } = dispatch;
            validate_task_effect_dispatch_authority(
                sprint_spec,
                workspace_grant,
                policy,
                running_boundary,
                intent,
                request_bytes,
            )?;
            if shadow.root() == workspace_grant.contract().canonical_root {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake runner refuses the live workspace as its private shadow".into(),
                ));
            }
            validate_provider_call_for_effect(provider_call, intent, request_bytes)?;
            let call = provider_call.clone();
            if let ProviderToolIntent::RunCommand { command } = &call.intent {
                let capture_intent = dispatch_permit
                    .output_capture_intent()
                    .cloned()
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "strict fake ordinary command omitted v27 capture intent".into(),
                        )
                    })?;
                let detector_policy = dispatch_permit
                    .sensitive_output_detection_policy()
                    .cloned()
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "strict fake ordinary command omitted its persisted detector policy"
                                .into(),
                        )
                    })?;
                let dispatch_claim_id = dispatch_permit
                    .expected_output_capture_dispatch_claim_id()
                    .ok_or_else(|| {
                        DurableCoordinatorError::Protocol(
                            "strict fake ordinary command omitted deterministic capture claim"
                                .into(),
                        )
                    })?;
                let (_, store, private_state_digest) =
                    strict_fake_command_output_store(workspace_grant, &runner_launch.launch_id)?;
                if private_state_digest != runner_launch.private_state_digest
                    || private_state_digest != runner_session.private_state_digest
                    || capture_intent.private_state_digest != private_state_digest
                    || capture_intent.source.effect_id != intent.effect_id
                    || capture_intent.source.request_digest != intent.request_digest
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake ordinary command capture crossed launch, session, effect, or private root"
                            .into(),
                    ));
                }
                let acquired = store
                    .reserve_anchored_capture_v2(
                        &capture_intent,
                        &dispatch_claim_id,
                        intent.created_at_unix_ms,
                        &detector_policy,
                    )
                    .and_then(CommandOutputCaptureReservation::into_acquired_anchor_for_handoff)
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake ordinary policy-bound command acquisition failed: {error}"
                        ))
                    })?;
                let output_capture = WireCommandOutputCaptureAnchorV1::try_new(acquired.clone())
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake ordinary command anchor is invalid: {error}"
                        ))
                    })?;
                let working_directory = command.working_directory.to_str().ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake ordinary command working directory is not exact UTF-8".into(),
                    )
                })?;
                let mut request = RunnerRequestEnvelope {
                    protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                    session_id: runner_session.session_id.clone(),
                    runner_nonce: Some(runner_session.session_nonce.clone()),
                    sequence: 1,
                    request_id: format!("{}:strict-fake-wire-request", intent.effect_id),
                    effect: Some(WireEffectContext {
                        contract_version: intent.contract_version,
                        launch_id: runner_launch.launch_id.clone(),
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
                    request: RunnerRequest::WorkerRunCommand {
                        command: WireCommandSpec {
                            program: command.program.clone(),
                            arguments: command.arguments.clone(),
                            working_directory: working_directory.into(),
                        },
                        output_capture,
                    },
                };
                request
                    .bind_transport_commitment_digest()
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake ordinary command commitment failed: {error}"
                        ))
                    })?;
                let request_frame = encode_request_frame(&request).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake ordinary command request frame failed: {error}"
                    ))
                })?;
                let (claimed_effect, transport_permit) = ledger
                    .claim_command_output_capture_dispatch(
                        dispatch_permit,
                        acquired.clone(),
                        &request_frame,
                    )?;
                let observation_authority = transport_permit.validate_transport_request(
                    intent,
                    request_bytes,
                    runner_launch,
                    runner_session,
                    Some(running_boundary),
                    &request_frame,
                )?;
                let abandoned_at_unix_ms =
                    post_response_timestamps.take_at_least(acquired.acquired_at_unix_ms)?;
                let command_abandonment = strict_fake_abandon_unexecuted_command_capture(
                    ledger,
                    &claimed_effect,
                    &acquired,
                    &store,
                    abandoned_at_unix_ms,
                )?;
                return WalkingSkeletonClaimedTaskEffectResponse::new_with_command_abandonment(
                    task_effect_response_for_dispatch(
                        sprint_spec,
                        workspace_grant,
                        running_boundary,
                        intent,
                        request_bytes,
                        None,
                        WalkingSkeletonTaskEffectOutcome::ContainmentNotReady,
                    ),
                    observation_authority,
                    command_abandonment,
                )
                .bind_command_observed_at(abandoned_at_unix_ms);
            }
            let prepared_file_tools =
                if matches!(call.intent, ProviderToolIntent::RunCommand { .. }) {
                    None
                } else {
                    let max_file_bytes = u64::try_from(MAX_PROVIDER_FILE_BYTES).map_err(|_| {
                        DurableCoordinatorError::Protocol(
                            "provider file bound does not fit u64".into(),
                        )
                    })?;
                    let limits = FileToolLimits::new(
                        max_file_bytes,
                        max_file_bytes,
                        usize::try_from(MAX_PROVIDER_LITERAL_MATCHES).map_err(|_| {
                            DurableCoordinatorError::Protocol(
                                "provider match bound does not fit usize".into(),
                            )
                        })?,
                    )?;
                    Some((
                        ShadowFileTools::acquire(workspace_grant, policy, shadow, limits)?,
                        max_file_bytes,
                    ))
                };
            let (_claimed, transport_permit) =
                ledger.claim_runner_effect_dispatch(dispatch_permit, request_bytes)?;
            let observation_authority = transport_permit.validate_transport_request(
                intent,
                request_bytes,
                runner_launch,
                runner_session,
                Some(running_boundary),
                request_bytes,
            )?;
            let (outcome, mutation_receipt) = if let Some((tools, max_file_bytes)) =
                prepared_file_tools
            {
                match execute_file_tool(&tools, workspace_grant, policy, &call, max_file_bytes) {
                    Ok(output) => {
                        let result = ProviderToolResult {
                            result_id: format!("{}:result", call.call_id),
                            call,
                            output,
                        };
                        let receipt = if is_mutating_tool(intent.kind) {
                            let poststate = capture_shadow_effect_state(
                                sprint_spec,
                                shadow,
                                format!("{}:strict-fake-receipt", intent.effect_id),
                                intent.created_at_unix_ms,
                            )?;
                            let operation = mutation_operation(&result)?;
                            Some(WalkingSkeletonMutationReceipt {
                                path: operation.path().to_path_buf(),
                                input_snapshot: intent.input_snapshot.clone(),
                                result_snapshot: poststate.snapshot,
                                previous_digest: match &operation {
                                    FileOperation::Create { .. } => None,
                                    FileOperation::Modify { base_hash, .. }
                                    | FileOperation::Delete { base_hash, .. } => {
                                        Some(base_hash.clone())
                                    }
                                },
                                result_digest: match &operation {
                                    FileOperation::Create { result_hash, .. }
                                    | FileOperation::Modify { result_hash, .. } => {
                                        Some(result_hash.clone())
                                    }
                                    FileOperation::Delete { .. } => None,
                                },
                            })
                        } else {
                            None
                        };
                        (
                            WalkingSkeletonTaskEffectOutcome::Succeeded(Box::new(result)),
                            receipt,
                        )
                    }
                    Err(error @ FileToolError::EffectAppliedButUnverified { .. }) => (
                        WalkingSkeletonTaskEffectOutcome::UnknownAfterDispatch {
                            reason: error.to_string(),
                        },
                        None,
                    ),
                    Err(error) => (
                        WalkingSkeletonTaskEffectOutcome::FailedBeforeEffect {
                            reason: error.to_string(),
                        },
                        None,
                    ),
                }
            } else {
                (WalkingSkeletonTaskEffectOutcome::ContainmentNotReady, None)
            };
            Ok(WalkingSkeletonClaimedTaskEffectResponse::new(
                task_effect_response_for_dispatch(
                    sprint_spec,
                    workspace_grant,
                    running_boundary,
                    intent,
                    request_bytes,
                    mutation_receipt,
                    outcome,
                ),
                observation_authority,
            ))
        }

        fn dispatch_task_formal_check(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError>
        {
            strict_fake_dispatch_task_formal_check(
                ledger,
                dispatch,
                CommandTerminationV1::Exited { code: 0 },
            )
        }

        fn prepare_task_integration_artifact(
            &mut self,
            preparation: WalkingSkeletonTaskIntegrationPreparation<'_>,
        ) -> Result<TaskIntegrationArtifactReference, DurableCoordinatorError> {
            preparation.candidate_boundary.validate()?;
            preparation.change_set.validate()?;
            if preparation.workspace_grant.contract() != &preparation.sprint_spec.workspace_grant
                || preparation.policy.contract().policy_hash
                    != preparation.runner_session.policy_hash
                || preparation.candidate_boundary.change_set_id
                    != preparation.change_set.change_set_id
                || preparation.candidate_boundary.sealed_snapshot
                    != preparation.change_set.result_snapshot
                || preparation.runner_launch.launch_id != preparation.runner_session.launch_id
                || preparation.prepared_at_unix_ms
                    < preparation.candidate_boundary.admitted_at_unix_ms
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake integration preparation received crossed authority".into(),
                ));
            }
            let canonical = serde_json::to_vec(preparation.change_set).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake integration change set cannot be encoded: {error}"
                ))
            })?;
            Ok(TaskIntegrationArtifactReference {
                format_version: 1,
                artifact_digest: Digest::sha256(&canonical),
                change_set_id: preparation.change_set.change_set_id.clone(),
                base_snapshot: preparation.change_set.base_snapshot.clone(),
                result_snapshot: preparation.change_set.result_snapshot.clone(),
            })
        }

        fn dispatch_task_integration(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskIntegrationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskIntegrationResponse, DurableCoordinatorError>
        {
            let request_bytes = serde_json::to_vec(dispatch.request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake integration request cannot be encoded: {error}"
                ))
            })?;
            let (_claimed, transport_permit) = ledger.claim_task_attempt_integration_dispatch(
                dispatch.dispatch_permit,
                &request_bytes,
            )?;
            let observation_authority = transport_permit.validate_transport_request(
                dispatch.intent,
                &request_bytes,
                dispatch.runner_launch,
                dispatch.runner_session,
                None,
                &request_bytes,
            )?;
            let evidence = TaskIntegrationEvidence {
                contract_version: CONTRACT_VERSION,
                receipt: grok_build_core::TaskIntegrationReceipt {
                    contract_version: CONTRACT_VERSION,
                    receipt_id: dispatch.receipt_id.into(),
                    sprint_id: dispatch.sprint_spec.sprint_id.clone(),
                    task_id: dispatch
                        .candidate_boundary
                        .attempt
                        .worker_lease
                        .task_id
                        .clone(),
                    worker_id: dispatch
                        .candidate_boundary
                        .attempt
                        .worker_lease
                        .worker_id
                        .clone(),
                    worker_lease: Some(dispatch.candidate_boundary.attempt.worker_lease.clone()),
                    worker_launch_id: dispatch.runner_launch.launch_id.clone(),
                    worker_session_id: dispatch.runner_session.session_id.clone(),
                    worker_policy_hash: dispatch.runner_session.policy_hash.clone(),
                    effect_id: dispatch.intent.effect_id.clone(),
                    observation_id: dispatch.observation_id.into(),
                    change_set_id: dispatch.request.change_set.change_set_id.clone(),
                    input_snapshot: dispatch.request.change_set.base_snapshot.clone(),
                    result_snapshot: dispatch.request.change_set.result_snapshot.clone(),
                    task_verification_receipt_ids: dispatch
                        .candidate_boundary
                        .verification_receipt_ids
                        .clone(),
                    integration_ordinal: dispatch.integration_ordinal,
                    integrated_at_unix_ms: dispatch.observed_at_unix_ms,
                },
                artifact: dispatch.request.artifact.clone(),
                validation: grok_build_core::TaskIntegrationValidationEvidence {
                    mode: TaskIntegrationValidationMode::WorkerPublication,
                    runner_launch_id: dispatch.runner_launch.launch_id.clone(),
                    runner_session_id: dispatch.runner_session.session_id.clone(),
                    policy_hash: dispatch.runner_session.policy_hash.clone(),
                    grant_hash: dispatch.runner_session.grant_hash.clone(),
                    private_state_digest: dispatch.runner_session.private_state_digest.clone(),
                },
            };
            evidence.validate()?;
            Ok(WalkingSkeletonClaimedTaskIntegrationResponse::new(
                WalkingSkeletonTaskIntegrationResponse {
                    contract_version: CONTRACT_VERSION,
                    sprint_spec: dispatch.sprint_spec.clone(),
                    workspace_grant: dispatch.workspace_grant.contract().clone(),
                    candidate_boundary: dispatch.candidate_boundary.clone(),
                    admission: dispatch.admission.clone(),
                    intent: dispatch.intent.clone(),
                    request: dispatch.request.clone(),
                    outcome: WalkingSkeletonTaskIntegrationOutcome::Succeeded(evidence),
                },
                observation_authority,
            ))
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict fake proves the complete command, worker, lease-release, and readback cleanup chain in one atomic test boundary"
        )]
        fn cleanup_integrated_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonIntegratedTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonIntegratedTaskCleanupOutcome, DurableCoordinatorError> {
            let TaskAttemptDisposition::Integrated(integrated) = cleanup.disposition else {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake cleanup requires an Integrated disposition".into(),
                ));
            };
            if integrated.metadata.attempt.worker_lease.sprint_id != cleanup.sprint_spec.sprint_id {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake cleanup crossed the integration sprint".into(),
                ));
            }
            let launch = ledger.load_runner_launch_intent(
                &cleanup.sprint_spec.sprint_id,
                &integrated.integration_receipt.worker_launch_id,
            )?;
            let session = ledger.load_runner_session(
                &cleanup.sprint_spec.sprint_id,
                &integrated.integration_receipt.worker_session_id,
            )?;
            let backend = match strict_fake_command_runner_cleanup_backend() {
                WorkerCleanupBackend::MacOsDedicatedIdentity => {
                    CommandDomainBackend::MacOsDedicatedIdentity
                }
                WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
                WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                    return Err(DurableCoordinatorError::Protocol(
                        "task-worker cleanup cannot use the trusted-applier backend".into(),
                    ));
                }
            };
            for binding in ledger.load_command_domain_effect_bindings(
                &cleanup.sprint_spec.sprint_id,
                &launch.launch_id,
                &session.session_id,
            )? {
                match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
                    Ok(existing)
                        if existing.binding == binding
                            && existing.proof.disposition
                                == CommandDomainCleanupDisposition::ReapedZeroSurvivors
                            && existing.proof.surviving_processes == 0 => {}
                    Ok(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake found a crossed command-domain cleanup proof".into(),
                        ));
                    }
                    Err(LedgerError::ArtifactNotFound { .. }) => {
                        let platform_proof_bytes =
                            format!("strict-fake-zero-command-survivors:{}", binding.effect_id)
                                .into_bytes();
                        ledger.record_command_domain_cleanup_proof(&CommandDomainCleanupProof {
                            contract_version: CONTRACT_VERSION,
                            proof_id: format!("{}:strict-fake-command-cleanup", binding.effect_id),
                            sprint_id: binding.sprint_id,
                            launch_id: binding.launch_id,
                            session_id: binding.session_id,
                            effect_id: binding.effect_id,
                            observation_id: binding.observation_id,
                            request_digest: binding.request_digest,
                            backend,
                            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                            surviving_processes: 0,
                            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
                            platform_proof_bytes,
                            cleaned_at_unix_ms: cleanup.cleanup_at_unix_ms,
                        })?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let cleaned_at_unix_ms =
                cleanup.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake cleanup timestamp overflow".into(),
                    )
                })?;
            let disposition_id = integrated.metadata.disposition_id.clone();
            let persisted = ledger.with_integrated_task_attempt_cleanup_exclusion(
                &disposition_id,
                |claim| {
                    let admission = claim.admission();
                    let cleanup_effect = &admission.cleanup_effect;
                    let os_evidence_bytes = format!(
                        "strict-fake-zero-worker-survivors:{}",
                        admission.launch.launch_id
                    )
                    .into_bytes();
                    let evidence = WorkerCleanupEvidence {
                        receipt: WorkerCleanupReceipt {
                            contract_version: CONTRACT_VERSION,
                            receipt_id: format!(
                                "{}:strict-fake-cleanup-receipt",
                                admission.launch.launch_id
                            ),
                            sprint_id: admission.launch.sprint_id.clone(),
                            launch_id: admission.launch.launch_id.clone(),
                            effect_id: cleanup_effect.intent.effect_id.clone(),
                            observation_id: format!(
                                "{}:observation",
                                cleanup_effect.intent.effect_id
                            ),
                            session_id: admission.launch.session_id.clone(),
                            worker_lease: admission.launch.worker_lease.clone(),
                            policy_hash: admission.launch.policy_hash.clone(),
                            grant_hash: admission.launch.grant_hash.clone(),
                            policy_version: admission.launch.policy_version,
                            platform_backend: admission.cleanup_request.platform_backend,
                            os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                            surviving_processes: 0,
                            cleaned_at_unix_ms,
                        },
                        os_evidence_bytes,
                    };
                    let canonical_evidence =
                        serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
                            entity: "strict fake worker cleanup evidence",
                            detail: error.to_string(),
                        })?;
                    let observation = EffectObservation {
                        contract_version: CONTRACT_VERSION,
                        observation_id: evidence.receipt.observation_id.clone(),
                        effect_id: cleanup_effect.intent.effect_id.clone(),
                        idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: cleanup_effect.intent.task_id.clone(),
                        worker_id: cleanup_effect.intent.worker_id.clone(),
                        worker_lease: cleanup_effect.intent.worker_lease.clone(),
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        kind: cleanup_effect.intent.kind,
                        request_digest: cleanup_effect.intent.request_digest.clone(),
                        policy_hash: cleanup_effect.intent.policy_hash.clone(),
                        input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
                        outcome: EffectOutcome::Succeeded {
                            evidence_digest: Digest::sha256(&canonical_evidence),
                        },
                        observed_at_unix_ms: cleaned_at_unix_ms,
                    };
                    let event = AgentEvent {
                        contract_version: CONTRACT_VERSION,
                        sequence: claim.next_event_sequence(),
                        event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: None,
                        worker_id: None,
                        causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
                        occurred_at_unix_ms: cleaned_at_unix_ms,
                        payload: AgentEventKind::ToolFinished {
                            tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                            succeeded: true,
                        },
                    };
                    Ok(RunnerCleanupTerminalRecord {
                        observation,
                        event,
                        evidence,
                    })
                },
            )?;
            Ok(WalkingSkeletonIntegratedTaskCleanupOutcome::Completed(
                persisted,
            ))
        }

        fn cleanup_sensitive_output_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonSensitiveOutputTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonSensitiveOutputTaskCleanupOutcome, DurableCoordinatorError>
        {
            let rejection = ledger.load_command_output_sensitive_rejection_for_effect(
                &cleanup.completed.intent.effect_id,
            )?;
            if rejection.anchor.effect_id != cleanup.completed.intent.effect_id
                || cleanup.completed.intent.worker_lease.as_ref()
                    != Some(&cleanup.attempt.worker_lease)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake sensitive-output cleanup crossed rejection or attempt authority"
                        .into(),
                ));
            }
            let plan = ledger.plan_task_attempt_cleanup_disposition(cleanup.attempt)?;
            let cleaned_at_unix_ms = cleanup
                .cleanup_at_unix_ms
                .max(plan.minimum_terminal_at_unix_ms());
            let disposition =
                ledger.with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleaned_at_unix_ms,
                        "sensitive-output-task",
                    )
                })?;
            Ok(WalkingSkeletonSensitiveOutputTaskCleanupOutcome::Completed(
                Box::new(disposition),
            ))
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict fake audits replay, exact cleanup, disposition, and capture closure in one lifecycle seam"
        )]
        fn cleanup_unknown_task_command_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonTaskCommandUnknownCleanup<'_>,
        ) -> Result<WalkingSkeletonTaskCommandUnknownCleanupOutcome, DurableCoordinatorError>
        {
            let stored_disposition = ledger
                .load_task_attempt_history(
                    &cleanup.sprint_spec.sprint_id,
                    &cleanup.attempt.worker_lease.task_id,
                )?
                .attempts
                .into_iter()
                .filter_map(|entry| entry.disposition)
                .find(|disposition| {
                    disposition.metadata().disposition_id == cleanup.disposition_id
                });
            if let Some(disposition) = stored_disposition {
                let TaskAttemptDisposition::UnknownCleaned(unknown) = &disposition else {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake task-command Unknown replay found another disposition".into(),
                    ));
                };
                if unknown.metadata.disposition_id != cleanup.disposition_id
                    || unknown.metadata.attempt != *cleanup.attempt
                    || unknown.metadata.from_state != cleanup.from_state
                    || unknown.metadata.state_transition_event_id != cleanup.transition_event_id
                    || unknown.unknown_evidence != *cleanup.unknown_evidence
                    || unknown.cleanup_release.release_id != cleanup.cleanup_release_id
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake task-command Unknown replay crossed exact disposition".into(),
                    ));
                }
                let runner_cleanup =
                    ledger.load_effect(&unknown.cleanup_release.cleanup_receipt.effect_id)?;
                let mut capture = ledger
                    .load_command_output_capture_for_effect(&cleanup.completed.intent.effect_id)?;
                if capture.reconciliation_resolution.is_none()
                    || capture.reconciliation_obligation_closure.is_none()
                {
                    strict_fake_resolve_unknown_final_verification_capture(
                        ledger,
                        &cleanup.sprint_spec.workspace_grant.canonical_root,
                        cleanup.completed,
                        &runner_cleanup,
                        &cleanup.runner_launch.launch_id,
                        cleanup.not_before_unix_ms,
                    )
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake task-command successor capture resolution failed: {error}"
                        ))
                    })?;
                    capture = ledger.load_command_output_capture_for_effect(
                        &cleanup.completed.intent.effect_id,
                    )?;
                    if capture.reconciliation_resolution.is_none()
                        || capture.reconciliation_obligation_closure.is_none()
                    {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake task-command successor resolution returned without exact Core closure"
                                .into(),
                        ));
                    }
                }
                return Ok(WalkingSkeletonTaskCommandUnknownCleanupOutcome::Completed {
                    disposition: Box::new(disposition),
                    runner_cleanup: Box::new(runner_cleanup),
                    capture: Box::new(capture),
                });
            }

            strict_fake_record_ordinary_command_cleanup(
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.runner_launch.launch_id,
                &cleanup.runner_session.session_id,
                cleanup.not_before_unix_ms,
                "task-command-unknown",
            )
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake task-command command cleanup failed: {error}"
                ))
            })?;
            let command_cleanup = ledger
                .load_command_domain_cleanup_proof(&cleanup.completed.intent.effect_id)?
                .proof;
            let disposition = ledger
                .with_task_command_unknown_cleaned_disposition_derived_timestamps(
                    &command_cleanup,
                    cleanup.attempt,
                    cleanup.from_state,
                    cleanup.disposition_id,
                    cleanup.unknown_evidence,
                    cleanup.cleanup_release_id,
                    cleanup.marker_id,
                    cleanup.transition_event_id,
                    cleanup.not_before_unix_ms,
                    |claim| {
                        strict_fake_ordinary_runner_cleanup_terminal(
                            claim,
                            cleanup
                                .not_before_unix_ms
                                .max(command_cleanup.cleaned_at_unix_ms)
                                .max(claim.minimum_terminal_at_unix_ms()),
                            "task-command-unknown",
                        )
                    },
                )
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake task-command specialized disposition failed: {error}"
                    ))
                })?;
            let TaskAttemptDisposition::UnknownCleaned(unknown) = &disposition else {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake task-command cleanup returned another disposition".into(),
                ));
            };
            let runner_cleanup =
                ledger.load_effect(&unknown.cleanup_release.cleanup_receipt.effect_id)?;
            strict_fake_resolve_unknown_final_verification_capture(
                ledger,
                &cleanup.sprint_spec.workspace_grant.canonical_root,
                cleanup.completed,
                &runner_cleanup,
                &cleanup.runner_launch.launch_id,
                cleanup.not_before_unix_ms,
            )
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake task-command capture resolution failed: {error}"
                ))
            })?;
            let capture = ledger
                .load_command_output_capture_for_effect(&cleanup.completed.intent.effect_id)?;
            Ok(WalkingSkeletonTaskCommandUnknownCleanupOutcome::Completed {
                disposition: Box::new(disposition),
                runner_cleanup: Box::new(runner_cleanup),
                capture: Box::new(capture),
            })
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict final-verifier fake persists the complete launch, cleanup admission, native preparation, and initialized session chain"
        )]
        fn ensure_sprint_final_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonFinalVerifierStart<'_>,
        ) -> Result<WalkingSkeletonFinalVerifierBoundary, DurableCoordinatorError> {
            validate_exact_authority(start.workspace_grant, start.sprint_spec)?;
            start.policy.validate_integrity(start.workspace_grant)?;
            if !start.shadow_root.is_absolute()
                || start.policy.contract().mutation_mode != MutationMode::ReadOnly
                || !start.policy.contract().write_scopes.is_empty()
                || start.policy.contract().network != ExecutionNetwork::None
                || ledger
                    .load_workspace_snapshot(&start.sprint_spec.sprint_id, start.final_snapshot)?
                    .snapshot_id
                    != *start.final_snapshot
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake final verifier received crossed snapshot, shadow, or read-only policy authority"
                        .into(),
                ));
            }
            let launch_id = final_verification_identity(&start.sprint_spec.sprint_id, "launch");
            let session_id = final_verification_identity(&start.sprint_spec.sprint_id, "session");
            let (_, _, private_state_digest) =
                strict_fake_command_output_store(start.workspace_grant, &launch_id)?;
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: launch_id.clone(),
                sprint_id: start.sprint_spec.sprint_id.clone(),
                session_id: session_id.clone(),
                purpose: RunnerSessionPurpose::FinalVerifier,
                worker_id: None,
                worker_lease: None,
                policy_hash: start.policy.contract().policy_hash.clone(),
                runner_binary_digest: fake_final_verifier_digest(
                    "binary",
                    &start.sprint_spec.sprint_id,
                ),
                protocol_digest: runner_protocol_digest(),
                private_state_digest,
                grant_hash: start.workspace_grant.contract().grant_hash.clone(),
                policy_version: start.workspace_grant.contract().policy_version,
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: strict_fake_command_runner_cleanup_backend(),
            };
            let cleanup_bytes = serde_json::to_vec(&cleanup_request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake final cleanup request cannot be encoded: {error}"
                ))
            })?;
            let cleanup_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-effect",
                ),
                idempotency_key: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-key",
                ),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                causation_event_id: None,
                correlation_id: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-correlation",
                ),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&cleanup_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: start.final_snapshot.clone(),
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&launch.sprint_id)?,
                event_id: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-proposed",
                ),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: cleanup_intent.correlation_id.clone(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: start.requested_at_unix_ms,
                payload: AgentEventKind::ToolProposed {
                    tool_call_id: cleanup_intent.idempotency_key.clone(),
                    tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
                },
            };
            let cleanup_admission = ledger.admit_runner_launch_with_cleanup(
                &launch,
                start.policy,
                &cleanup_intent,
                &cleanup_bytes,
                &cleanup_event,
            )?;
            let preparation_attempt = RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "native-preparation",
                ),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                cleanup_effect_id: cleanup_intent.effect_id.clone(),
                native_journal_id: final_verification_identity(
                    &start.sprint_spec.sprint_id,
                    "native-journal",
                ),
                expected_platform_binding_digest: fake_final_verifier_digest(
                    "platform-binding",
                    &start.sprint_spec.sprint_id,
                ),
                claimed_at_unix_ms: start.requested_at_unix_ms,
            };
            let preparation_outcome = RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: format!(
                    "strict-fake-final-held-child:{}",
                    preparation_attempt.native_journal_id
                )
                .into_bytes(),
                finished_at_unix_ms: start.requested_at_unix_ms,
            };
            let expected_outcome = preparation_outcome.clone();
            let prepared = ledger.with_runner_launch_preparation_claim(
                &cleanup_admission,
                &preparation_attempt,
                |_| expected_outcome,
            )?;
            if prepared.attempt != preparation_attempt
                || prepared.outcome.as_ref() != Some(&preparation_outcome)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake final-verifier native preparation readback crossed authority"
                        .into(),
                ));
            }
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                purpose: RunnerSessionPurpose::FinalVerifier,
                worker_id: None,
                worker_lease: None,
                policy_hash: launch.policy_hash.clone(),
                session_nonce: fake_final_verifier_digest(
                    "session-nonce",
                    &start.sprint_spec.sprint_id,
                ),
                runner_binary_digest: launch.runner_binary_digest.clone(),
                protocol_digest: launch.protocol_digest.clone(),
                private_state_digest: launch.private_state_digest.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                registered_at_unix_ms: start.requested_at_unix_ms,
            };
            ledger.register_runner_session(&session, start.policy)?;
            Ok(WalkingSkeletonFinalVerifierBoundary {
                runner_launch: launch,
                runner_session: session,
                final_snapshot: start.final_snapshot.clone(),
            })
        }

        fn cleanup_unadmitted_sprint_final_verifier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedFinalVerifierCleanup<'_>,
        ) -> Result<WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome, DurableCoordinatorError>
        {
            let admission = ledger.load_runner_launch_cleanup_admission(
                &cleanup.sprint_spec.sprint_id,
                cleanup.launch_id,
            )?;
            if admission.launch.purpose != RunnerSessionPurpose::FinalVerifier
                || admission.launch.worker_id.is_some()
                || admission.launch.worker_lease.is_some()
                || admission.cleanup_effect.intent.input_snapshot != *cleanup.final_snapshot
                || !ledger
                    .load_command_domain_effect_bindings(
                        &cleanup.sprint_spec.sprint_id,
                        cleanup.launch_id,
                        &admission.launch.session_id,
                    )?
                    .is_empty()
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake unadmitted final-verifier cleanup crossed exact launch authority"
                        .into(),
                ));
            }
            let persisted = ledger.with_unadmitted_final_verifier_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                cleanup.launch_id,
                |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleanup
                            .cleanup_at_unix_ms
                            .max(claim.minimum_terminal_at_unix_ms()),
                        "unadmitted-final-verifier",
                    )
                },
            )?;
            Ok(WalkingSkeletonUnadmittedFinalVerifierCleanupOutcome::Completed(persisted))
        }

        fn dispatch_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError>
        {
            strict_fake_dispatch_sprint_final_verification(
                ledger,
                dispatch,
                CommandTerminationV1::Exited { code: 0 },
            )
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict fake proves final-verifier command cleanup and zero-survivor runner cleanup with exact durable readback"
        )]
        fn cleanup_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            if cleanup.evidence.verification.task_id.is_some()
                || cleanup.evidence.verification.snapshot_id != cleanup.admission.final_snapshot
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake final cleanup requires exact sprint verification evidence".into(),
                ));
            }
            let launch = ledger.load_runner_launch_intent(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
            )?;
            let session = ledger.load_runner_session(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_session_id,
            )?;
            let backend = match strict_fake_command_runner_cleanup_backend() {
                WorkerCleanupBackend::MacOsDedicatedIdentity => {
                    CommandDomainBackend::MacOsDedicatedIdentity
                }
                WorkerCleanupBackend::LinuxCgroupV2 => CommandDomainBackend::LinuxCgroupV2,
                WorkerCleanupBackend::TrustedApplierDirectChildWait => {
                    return Err(DurableCoordinatorError::Protocol(
                        "final-verifier cleanup cannot use trusted-applier backend".into(),
                    ));
                }
            };
            for binding in ledger.load_command_domain_effect_bindings(
                &cleanup.sprint_spec.sprint_id,
                &launch.launch_id,
                &session.session_id,
            )? {
                match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
                    Ok(existing)
                        if existing.binding == binding
                            && existing.proof.disposition
                                == CommandDomainCleanupDisposition::ReapedZeroSurvivors
                            && existing.proof.surviving_processes == 0 => {}
                    Ok(_) => {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake found a crossed final-verification command cleanup proof"
                                .into(),
                        ));
                    }
                    Err(LedgerError::ArtifactNotFound { .. }) => {
                        let platform_proof_bytes = format!(
                            "strict-fake-final-zero-command-survivors:{}",
                            binding.effect_id
                        )
                        .into_bytes();
                        ledger.record_command_domain_cleanup_proof(&CommandDomainCleanupProof {
                            contract_version: CONTRACT_VERSION,
                            proof_id: format!(
                                "{}:strict-fake-final-command-cleanup",
                                binding.effect_id
                            ),
                            sprint_id: binding.sprint_id,
                            launch_id: binding.launch_id,
                            session_id: binding.session_id,
                            effect_id: binding.effect_id,
                            observation_id: binding.observation_id,
                            request_digest: binding.request_digest,
                            backend,
                            disposition: CommandDomainCleanupDisposition::ReapedZeroSurvivors,
                            surviving_processes: 0,
                            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
                            platform_proof_bytes,
                            cleaned_at_unix_ms: cleanup.cleanup_at_unix_ms,
                        })?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let cleaned_at_unix_ms =
                cleanup.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake final cleanup timestamp overflow".into(),
                    )
                })?;
            let persisted = ledger.with_runner_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                &launch.launch_id,
                |claim| {
                    let admission = claim.admission();
                    let cleanup_effect = &admission.cleanup_effect;
                    let os_evidence_bytes = format!(
                        "strict-fake-final-zero-runner-survivors:{}",
                        admission.launch.launch_id
                    )
                    .into_bytes();
                    let evidence = WorkerCleanupEvidence {
                        receipt: WorkerCleanupReceipt {
                            contract_version: CONTRACT_VERSION,
                            receipt_id: format!(
                                "{}:strict-fake-final-cleanup-receipt",
                                admission.launch.launch_id
                            ),
                            sprint_id: admission.launch.sprint_id.clone(),
                            launch_id: admission.launch.launch_id.clone(),
                            effect_id: cleanup_effect.intent.effect_id.clone(),
                            observation_id: format!(
                                "{}:observation",
                                cleanup_effect.intent.effect_id
                            ),
                            session_id: admission.launch.session_id.clone(),
                            worker_lease: None,
                            policy_hash: admission.launch.policy_hash.clone(),
                            grant_hash: admission.launch.grant_hash.clone(),
                            policy_version: admission.launch.policy_version,
                            platform_backend: admission.cleanup_request.platform_backend,
                            os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                            surviving_processes: 0,
                            cleaned_at_unix_ms,
                        },
                        os_evidence_bytes,
                    };
                    let canonical =
                        serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
                            entity: "strict fake final cleanup evidence",
                            detail: error.to_string(),
                        })?;
                    let observation = EffectObservation {
                        contract_version: CONTRACT_VERSION,
                        observation_id: evidence.receipt.observation_id.clone(),
                        effect_id: cleanup_effect.intent.effect_id.clone(),
                        idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: None,
                        worker_id: None,
                        worker_lease: None,
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        kind: EffectKind::CleanupWorkerDomain,
                        request_digest: cleanup_effect.intent.request_digest.clone(),
                        policy_hash: cleanup_effect.intent.policy_hash.clone(),
                        input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
                        outcome: EffectOutcome::Succeeded {
                            evidence_digest: Digest::sha256(&canonical),
                        },
                        observed_at_unix_ms: cleaned_at_unix_ms,
                    };
                    let event = AgentEvent {
                        contract_version: CONTRACT_VERSION,
                        sequence: claim.next_event_sequence(),
                        event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: None,
                        worker_id: None,
                        causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
                        occurred_at_unix_ms: cleaned_at_unix_ms,
                        payload: AgentEventKind::ToolFinished {
                            tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                            succeeded: true,
                        },
                    };
                    Ok(RunnerCleanupTerminalRecord {
                        observation,
                        event,
                        evidence,
                    })
                },
            )?;
            Ok(WalkingSkeletonFinalVerificationCleanupOutcome::Completed(
                persisted,
            ))
        }

        fn cleanup_terminal_sprint_final_verification(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonFinalVerificationTerminalCleanup<'_>,
        ) -> Result<WalkingSkeletonFinalVerificationCleanupOutcome, DurableCoordinatorError>
        {
            let outcome_matches = match cleanup.outcome {
                WalkingSkeletonFinalVerificationTerminalOutcome::FailedBeforeEffect => matches!(
                    cleanup
                        .completed
                        .observation
                        .as_ref()
                        .map(|observation| &observation.outcome),
                    Some(EffectOutcome::FailedBeforeEffect { .. })
                ),
                WalkingSkeletonFinalVerificationTerminalOutcome::SensitiveOutputRejected => {
                    let Some(observation) = cleanup.completed.observation.as_ref() else {
                        return Err(DurableCoordinatorError::Protocol(
                            "strict fake sensitive final cleanup lacks its exact observation"
                                .into(),
                        ));
                    };
                    let rejection = ledger.load_command_output_sensitive_rejection_for_effect(
                        &cleanup.completed.intent.effect_id,
                    )?;
                    let command_cleanup = ledger
                        .load_command_domain_cleanup_proof(&cleanup.completed.intent.effect_id)?;
                    matches!(
                        observation.outcome,
                        EffectOutcome::FailedAfterKnownEffect { .. }
                    ) && rejection.anchor.effect_id == cleanup.completed.intent.effect_id
                        && rejection.anchor.observation_id == observation.observation_id
                        && rejection.cleanup.command_domain_cleanup_proof_id
                            == command_cleanup.proof.proof_id
                        && command_cleanup.proof.disposition
                            == CommandDomainCleanupDisposition::ReapedZeroSurvivors
                        && command_cleanup.proof.surviving_processes == 0
                }
                WalkingSkeletonFinalVerificationTerminalOutcome::Unknown => matches!(
                    cleanup
                        .completed
                        .observation
                        .as_ref()
                        .map(|observation| &observation.outcome),
                    Some(EffectOutcome::Unknown { .. })
                ),
            };
            if cleanup.completed.intent.effect_id != cleanup.admission.effect_id
                || cleanup.completed.intent.sprint_id != cleanup.admission.sprint_id
                || cleanup.completed.intent.kind != EffectKind::RunCommand
                || cleanup.completed.dispatch_claim.is_none()
                || !outcome_matches
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake terminal final cleanup requires the exact claimed non-success effect"
                        .into(),
                ));
            }
            strict_fake_terminal_final_verification_cleanup(ledger, &cleanup)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict live-state fake persists the exact plan-bound launch, cleanup admission, native preparation, and semantic session"
        )]
        fn ensure_sprint_live_state_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonLiveStateVerifierStart<'_>,
        ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
            validate_exact_authority(start.workspace_grant, start.sprint_spec)?;
            start.policy.validate_integrity(start.workspace_grant)?;
            start.plan.validate()?;
            if start.plan.sprint_id != start.sprint_spec.sprint_id
                || start.plan.policy_hash != start.policy.contract().policy_hash
                || start.plan.grant_hash != start.workspace_grant.contract().grant_hash
                || start.policy.contract().mutation_mode != MutationMode::ReadOnly
                || !start.policy.contract().write_scopes.is_empty()
                || start.policy.contract().network != ExecutionNetwork::None
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake live-state verifier received crossed plan or read-only policy authority"
                        .into(),
                ));
            }
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: live_state_capture_identity(&start.sprint_spec.sprint_id, "launch"),
                sprint_id: start.sprint_spec.sprint_id.clone(),
                session_id: live_state_capture_identity(&start.sprint_spec.sprint_id, "session"),
                purpose: RunnerSessionPurpose::LiveStateVerifier,
                worker_id: None,
                worker_lease: None,
                policy_hash: start.policy.contract().policy_hash.clone(),
                runner_binary_digest: fake_live_state_digest(
                    "binary",
                    &start.sprint_spec.sprint_id,
                ),
                protocol_digest: runner_protocol_digest(),
                private_state_digest: fake_live_state_digest(
                    "private-state",
                    &start.sprint_spec.sprint_id,
                ),
                grant_hash: start.workspace_grant.contract().grant_hash.clone(),
                policy_version: start.workspace_grant.contract().policy_version,
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: fake_worker_cleanup_backend(),
            };
            let cleanup_bytes = serde_json::to_vec(&cleanup_request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake live-state cleanup request cannot be encoded: {error}"
                ))
            })?;
            let cleanup_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-effect",
                ),
                idempotency_key: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-key",
                ),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                causation_event_id: None,
                correlation_id: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-correlation",
                ),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&cleanup_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: start.plan.expected_snapshot.clone(),
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&launch.sprint_id)?,
                event_id: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-proposed",
                ),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: cleanup_intent.correlation_id.clone(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: start.requested_at_unix_ms,
                payload: AgentEventKind::ToolProposed {
                    tool_call_id: cleanup_intent.idempotency_key.clone(),
                    tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
                },
            };
            let cleanup_admission = ledger.admit_live_state_verifier_launch_with_cleanup(
                start.plan,
                &launch,
                start.policy,
                &cleanup_intent,
                &cleanup_bytes,
                &cleanup_event,
            )?;
            let preparation_attempt = RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "native-preparation",
                ),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                cleanup_effect_id: cleanup_intent.effect_id.clone(),
                native_journal_id: live_state_capture_identity(
                    &start.sprint_spec.sprint_id,
                    "native-journal",
                ),
                expected_platform_binding_digest: fake_live_state_digest(
                    "platform-binding",
                    &start.sprint_spec.sprint_id,
                ),
                claimed_at_unix_ms: start.requested_at_unix_ms,
            };
            let preparation_outcome = RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: format!(
                    "strict-fake-live-state-held-child:{}",
                    preparation_attempt.native_journal_id
                )
                .into_bytes(),
                finished_at_unix_ms: start.requested_at_unix_ms,
            };
            let expected_outcome = preparation_outcome.clone();
            let prepared = ledger.with_runner_launch_preparation_claim(
                &cleanup_admission,
                &preparation_attempt,
                |_| expected_outcome,
            )?;
            if prepared.attempt != preparation_attempt
                || prepared.outcome.as_ref() != Some(&preparation_outcome)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake live-state native preparation readback crossed authority".into(),
                ));
            }
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                purpose: RunnerSessionPurpose::LiveStateVerifier,
                worker_id: None,
                worker_lease: None,
                policy_hash: launch.policy_hash.clone(),
                session_nonce: fake_live_state_digest(
                    "session-nonce",
                    &start.sprint_spec.sprint_id,
                ),
                runner_binary_digest: launch.runner_binary_digest.clone(),
                protocol_digest: launch.protocol_digest.clone(),
                private_state_digest: launch.private_state_digest.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                registered_at_unix_ms: start.requested_at_unix_ms,
            };
            ledger.register_live_state_verifier_session(start.plan, &session, start.policy)?;
            Ok(WalkingSkeletonLiveStateVerifierBoundary {
                runner_launch: launch,
                runner_session: session,
                plan: start.plan.clone(),
            })
        }

        fn cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
        ) -> Result<WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, DurableCoordinatorError>
        {
            let cleaned_at_unix_ms =
                cleanup.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake unadmitted live-state cleanup timestamp overflow".into(),
                    )
                })?;
            let persisted = ledger.with_unadmitted_live_state_verifier_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                cleanup.launch_id,
                &cleanup.plan.plan_id,
                |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleaned_at_unix_ms,
                        "unadmitted-live-state",
                    )
                },
            )?;
            Ok(WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::Completed(persisted))
        }

        #[allow(clippy::too_many_lines)] // One application scenario fake owns the complete claimed verifier wire exchange.
        fn dispatch_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonLiveStateCaptureDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedLiveStateCaptureResponse, DurableCoordinatorError>
        {
            let core_request_bytes =
                serde_json::to_vec(&dispatch.admission.request).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake capture request cannot be encoded: {error}"
                    ))
                })?;
            let mut request = RunnerRequestEnvelope {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                session_id: dispatch.verifier.runner_session.session_id.clone(),
                runner_nonce: Some(dispatch.verifier.runner_session.session_nonce.clone()),
                sequence: 1,
                request_id: live_state_capture_identity(
                    &dispatch.sprint_spec.sprint_id,
                    "wire-request",
                ),
                effect: Some(WireEffectContext {
                    contract_version: dispatch.intent.contract_version,
                    launch_id: dispatch.verifier.runner_launch.launch_id.clone(),
                    effect_id: dispatch.intent.effect_id.clone(),
                    idempotency_key: dispatch.intent.idempotency_key.clone(),
                    sprint_id: dispatch.intent.sprint_id.clone(),
                    task_id: None,
                    worker_id: None,
                    worker_lease: None,
                    policy_hash: dispatch.intent.policy_hash.clone(),
                    input_snapshot: dispatch.intent.input_snapshot.clone(),
                    request_digest: dispatch.intent.request_digest.clone(),
                    transport_commitment_digest: Digest::sha256(&[]),
                }),
                request: RunnerRequest::LiveStateVerifierCapture {
                    request: Box::new(dispatch.admission.request.clone()),
                },
            };
            request
                .bind_transport_commitment_digest()
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake request commitment failed: {error}"
                    ))
                })?;
            let request_frame = encode_request_frame(&request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake request frame failed: {error}"
                ))
            })?;
            let (claimed_effect, transport_permit) = ledger
                .claim_sprint_live_state_capture_dispatch(
                    dispatch.dispatch_permit,
                    &request_frame,
                )?;
            let observation_authority = transport_permit.validate_transport_request(
                dispatch.intent,
                &core_request_bytes,
                &dispatch.verifier.runner_launch,
                &dispatch.verifier.runner_session,
                None,
                &request_frame,
            )?;
            let capture_started_at_unix_ms = dispatch
                .admission
                .admitted_at_unix_ms
                .checked_add(1)
                .ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake capture timestamp overflow".into(),
                    )
                })?;
            let captured_at_unix_ms =
                capture_started_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake capture timestamp overflow".into(),
                    )
                })?;
            let manifest = DescriptorRelativeWorkspaceManifest::from_captured_entries(
                dispatch.workspace_grant.contract().grant_hash.clone(),
                capture_started_at_unix_ms,
                captured_at_unix_ms,
                Vec::new(),
            )?;
            let response = RunnerResponseEnvelope {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                session_id: request.session_id.clone(),
                runner_nonce: dispatch.verifier.runner_session.session_nonce.clone(),
                sequence: request.sequence,
                request_id: request.request_id.clone(),
                effect: request.effect.clone(),
                response: RunnerResponse::LiveWorkspaceCaptured {
                    manifest: Box::new(manifest),
                },
            };
            let response_frame = encode_response_frame(&response).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake response frame failed: {error}"
                ))
            })?;
            let claimed = claimed_live_state_capture_response_for_test(
                RunnerEffectResponse { request, response },
                request_frame,
                Digest::sha256(&response_frame),
                claimed_effect,
                observation_authority,
            );
            let terminal = claimed
                .into_terminal(LiveStateCaptureEvidenceInput {
                    intent: dispatch.intent,
                    admission: dispatch.admission,
                    runner_session: &dispatch.verifier.runner_session,
                    authority: dispatch.workspace_grant,
                    receipt_id: dispatch.receipt_id,
                    observation_id: dispatch.observation_id,
                })
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake sealed capture adaptation failed: {}",
                        error.error()
                    ))
                })?;
            let evidence = terminal.evidence().clone();
            Ok(WalkingSkeletonClaimedLiveStateCaptureResponse::new_success(
                WalkingSkeletonLiveStateCaptureResponse {
                    contract_version: CONTRACT_VERSION,
                    sprint_spec: dispatch.sprint_spec.clone(),
                    workspace_grant: dispatch.workspace_grant.contract().clone(),
                    verifier: dispatch.verifier.clone(),
                    admission: dispatch.admission.clone(),
                    intent: dispatch.intent.clone(),
                    outcome: WalkingSkeletonLiveStateCaptureOutcome::Succeeded(Box::new(evidence)),
                },
                terminal,
            ))
        }

        fn cleanup_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonLiveStateCaptureCleanup<'_>,
        ) -> Result<WalkingSkeletonLiveStateCaptureCleanupOutcome, DurableCoordinatorError>
        {
            strict_fake_record_ordinary_command_cleanup(
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                &cleanup.admission.runner_session_id,
                cleanup.cleanup_at_unix_ms,
                "live-state",
            )?;
            let cleaned_at_unix_ms =
                cleanup.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake live-state cleanup timestamp overflow".into(),
                    )
                })?;
            let persisted = ledger.with_runner_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleaned_at_unix_ms,
                        "live-state",
                    )
                },
            )?;
            Ok(WalkingSkeletonLiveStateCaptureCleanupOutcome::Completed(
                persisted,
            ))
        }

        fn reconcile_claimed_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            recovery: WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
        ) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError>
        {
            strict_fake_record_ordinary_command_cleanup(
                ledger,
                &recovery.sprint_spec.sprint_id,
                &recovery.admission.runner_launch_id,
                &recovery.admission.runner_session_id,
                recovery.cleanup_at_unix_ms,
                "live-state",
            )?;
            let cleaned_at_unix_ms =
                recovery.cleanup_at_unix_ms.checked_add(1).ok_or_else(|| {
                    DurableCoordinatorError::Protocol(
                        "strict fake recovery cleanup timestamp overflow".into(),
                    )
                })?;
            let (capture, cleanup) = ledger
                .with_claimed_live_state_capture_reconciliation_cleanup_exclusion(
                    &recovery.sprint_spec.sprint_id,
                    &recovery.admission.runner_launch_id,
                    recovery.observation,
                    recovery.evidence_bytes,
                    recovery.event,
                    |claim| {
                        strict_fake_ordinary_runner_cleanup_terminal(
                            claim,
                            cleaned_at_unix_ms,
                            "live-state",
                        )
                    },
                )?;
            Ok(
                WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome::Completed {
                    capture,
                    cleanup,
                },
            )
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict application fake persists the full Applier launch, cleanup admission, native preparation, and initialized session chain"
        )]
        fn ensure_sprint_application_applier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonApplicationStart<'_>,
        ) -> Result<WalkingSkeletonApplicationBoundary, DurableCoordinatorError> {
            validate_exact_authority(start.workspace_grant, start.sprint_spec)?;
            start.policy.validate_integrity(start.workspace_grant)?;
            validate_application_request_bundle(start.request, start.stage_bundle)?;
            if start.policy.contract().mutation_mode != MutationMode::ReadOnly
                || !start.policy.contract().write_scopes.is_empty()
                || start.policy.contract().network != ExecutionNetwork::None
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake application Applier requires the dedicated read-only process policy"
                        .into(),
                ));
            }
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: application_identity(&start.sprint_spec.sprint_id, "launch"),
                sprint_id: start.sprint_spec.sprint_id.clone(),
                session_id: application_identity(&start.sprint_spec.sprint_id, "session"),
                purpose: RunnerSessionPurpose::Applier,
                worker_id: None,
                worker_lease: None,
                policy_hash: start.policy.contract().policy_hash.clone(),
                runner_binary_digest: fake_application_digest(
                    "binary",
                    &start.sprint_spec.sprint_id,
                ),
                protocol_digest: fake_application_digest("protocol", &start.sprint_spec.sprint_id),
                private_state_digest: fake_application_digest(
                    "private-state",
                    &start.sprint_spec.sprint_id,
                ),
                grant_hash: start.workspace_grant.contract().grant_hash.clone(),
                policy_version: start.workspace_grant.contract().policy_version,
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
            };
            let cleanup_bytes = serde_json::to_vec(&cleanup_request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake application cleanup request cannot be encoded: {error}"
                ))
            })?;
            let cleanup_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: application_identity(&start.sprint_spec.sprint_id, "cleanup-effect"),
                idempotency_key: application_identity(&start.sprint_spec.sprint_id, "cleanup-key"),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: None,
                causation_event_id: None,
                correlation_id: application_identity(
                    &start.sprint_spec.sprint_id,
                    "cleanup-correlation",
                ),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&cleanup_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: start.request.change_set.base_snapshot.clone(),
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&launch.sprint_id)?,
                event_id: application_identity(&start.sprint_spec.sprint_id, "cleanup-proposed"),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                causation_id: None,
                correlation_id: cleanup_intent.correlation_id.clone(),
                policy_hash: Some(launch.policy_hash.clone()),
                occurred_at_unix_ms: start.requested_at_unix_ms,
                payload: AgentEventKind::ToolProposed {
                    tool_call_id: cleanup_intent.idempotency_key.clone(),
                    tool_name: EffectKind::CleanupWorkerDomain.tool_name().into(),
                },
            };
            let cleanup_admission = ledger.admit_runner_launch_with_cleanup(
                &launch,
                start.policy,
                &cleanup_intent,
                &cleanup_bytes,
                &cleanup_event,
            )?;
            let preparation_attempt = RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: application_identity(
                    &start.sprint_spec.sprint_id,
                    "native-preparation",
                ),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                cleanup_effect_id: cleanup_intent.effect_id.clone(),
                native_journal_id: application_identity(
                    &start.sprint_spec.sprint_id,
                    "native-journal",
                ),
                expected_platform_binding_digest: fake_application_digest(
                    "platform-binding",
                    &start.sprint_spec.sprint_id,
                ),
                claimed_at_unix_ms: start.requested_at_unix_ms,
            };
            let preparation_outcome = RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::HeldChildPrepared,
                native_evidence_bytes: format!(
                    "strict-fake-application-held-child:{}",
                    preparation_attempt.native_journal_id
                )
                .into_bytes(),
                finished_at_unix_ms: start.requested_at_unix_ms,
            };
            let expected_outcome = preparation_outcome.clone();
            let prepared = ledger.with_runner_launch_preparation_claim(
                &cleanup_admission,
                &preparation_attempt,
                |_| expected_outcome,
            )?;
            if prepared.attempt != preparation_attempt
                || prepared.outcome.as_ref() != Some(&preparation_outcome)
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake application native preparation readback crossed authority".into(),
                ));
            }
            let session = RunnerSessionPolicyRecord {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                purpose: RunnerSessionPurpose::Applier,
                worker_id: None,
                worker_lease: None,
                policy_hash: launch.policy_hash.clone(),
                session_nonce: fake_application_digest(
                    "session-nonce",
                    &start.sprint_spec.sprint_id,
                ),
                runner_binary_digest: launch.runner_binary_digest.clone(),
                protocol_digest: launch.protocol_digest.clone(),
                private_state_digest: launch.private_state_digest.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                registered_at_unix_ms: start.requested_at_unix_ms,
            };
            ledger.register_runner_session(&session, start.policy)?;
            Ok(WalkingSkeletonApplicationBoundary {
                runner_launch: launch,
                runner_session: session,
                request: start.request.clone(),
                stage_bundle: start.stage_bundle.clone(),
            })
        }

        fn cleanup_unadmitted_sprint_application_applier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedApplicationApplierCleanup<'_>,
        ) -> Result<
            WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome,
            DurableCoordinatorError,
        > {
            let admission = ledger.load_runner_launch_cleanup_admission(
                &cleanup.sprint_spec.sprint_id,
                cleanup.launch_id,
            )?;
            if cleanup.cleanup_at_unix_ms == 0
                || cleanup.final_verification_receipt_id
                    != final_verification_identity(&cleanup.sprint_spec.sprint_id, "receipt")
                || admission.launch.purpose != RunnerSessionPurpose::Applier
                || admission.launch.worker_id.is_some()
                || admission.launch.worker_lease.is_some()
                || admission.cleanup_request.platform_backend
                    != WorkerCleanupBackend::TrustedApplierDirectChildWait
                || admission.cleanup_effect.intent.input_snapshot != *cleanup.base_snapshot
            {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake unadmitted trusted-Applier cleanup crossed exact launch authority"
                        .into(),
                ));
            }
            let persisted = ledger.with_unadmitted_application_applier_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                cleanup.launch_id,
                cleanup.final_verification_receipt_id,
                |claim| {
                    strict_fake_ordinary_runner_cleanup_terminal(
                        claim,
                        cleanup
                            .cleanup_at_unix_ms
                            .max(claim.minimum_terminal_at_unix_ms()),
                        "unadmitted-application-applier",
                    )
                },
            )?;
            Ok(WalkingSkeletonUnadmittedApplicationApplierCleanupOutcome::Completed(persisted))
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the strict fake constructs a complete exact application, validation, rollback, and canonical-evidence response"
        )]
        fn dispatch_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonApplicationDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedApplicationResponse, DurableCoordinatorError> {
            let request_bytes = serde_json::to_vec(dispatch.request).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake application request cannot be encoded: {error}"
                ))
            })?;
            let (_claimed, transport_permit) = ledger
                .claim_sprint_application_dispatch(dispatch.dispatch_permit, &request_bytes)?;
            let observation_authority = transport_permit.validate_transport_request(
                dispatch.intent,
                &request_bytes,
                &dispatch.applier.runner_launch,
                &dispatch.applier.runner_session,
                None,
                &request_bytes,
            )?;
            let transaction_id =
                application_identity(&dispatch.sprint_spec.sprint_id, "test-transaction");
            let receipt = ApplicationReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: dispatch.application_receipt_id.into(),
                sprint_id: dispatch.sprint_spec.sprint_id.clone(),
                effect_id: dispatch.intent.effect_id.clone(),
                observation_id: dispatch.observation_id.into(),
                applier_session_id: dispatch.applier.runner_session.session_id.clone(),
                transaction_id: transaction_id.clone(),
                change_set_id: dispatch.request.change_set.change_set_id.clone(),
                base_snapshot: dispatch.request.change_set.base_snapshot.clone(),
                result_snapshot: dispatch.request.change_set.result_snapshot.clone(),
                policy_hash: dispatch.intent.policy_hash.clone(),
                grant_hash: dispatch.workspace_grant.contract().grant_hash.clone(),
                policy_version: dispatch.workspace_grant.contract().policy_version,
                applied_operations_digest: dispatch
                    .request
                    .change_set
                    .applied_operations_digest()?,
                touched_path_endpoints_digest: dispatch
                    .request
                    .change_set
                    .touched_path_endpoints_digest()?,
                live_manifest_digest: dispatch.request.change_set.result_snapshot.clone(),
                applied_at_unix_ms: dispatch.observed_at_unix_ms,
            };
            let application_evidence = ApplicationEvidence {
                contract_version: CONTRACT_VERSION,
                receipt,
                validation: ApplicationValidationEvidence {
                    mode: ApplicationValidationMode::DirectEffectResponse,
                    runner_launch_id: dispatch.applier.runner_launch.launch_id.clone(),
                    runner_session_id: dispatch.applier.runner_session.session_id.clone(),
                    policy_hash: dispatch.intent.policy_hash.clone(),
                    grant_hash: dispatch.workspace_grant.contract().grant_hash.clone(),
                    policy_version: dispatch.workspace_grant.contract().policy_version,
                    private_state_digest: dispatch
                        .applier
                        .runner_session
                        .private_state_digest
                        .clone(),
                },
            };
            let reopened_artifacts_bytes =
                format!("strict-fake-reopened-rollback-artifacts:{transaction_id}").into_bytes();
            let rollback_reference = RollbackReferenceEvidence {
                reference: RollbackReference {
                    contract_version: CONTRACT_VERSION,
                    reference_id: dispatch.rollback_reference_id.into(),
                    sprint_id: dispatch.sprint_spec.sprint_id.clone(),
                    application_receipt_id: dispatch.application_receipt_id.into(),
                    transaction_id,
                    journal_binding_digest: application_evidence
                        .receipt
                        .journal_binding_digest()?,
                    base_snapshot: dispatch.request.change_set.base_snapshot.clone(),
                    touched_target_set_digest: dispatch
                        .request
                        .change_set
                        .touched_target_set_digest()?,
                    reopened_artifacts_digest: Digest::sha256(&reopened_artifacts_bytes),
                    validated_at_unix_ms: dispatch.rollback_validated_at_unix_ms,
                },
                reopened_artifacts_bytes,
            };
            let canonical_evidence =
                crate::canonical_application_evidence(&application_evidence)
                    .map_err(|error| DurableCoordinatorError::Protocol(error.to_string()))?;
            Ok(WalkingSkeletonClaimedApplicationResponse::new(
                WalkingSkeletonApplicationResponse {
                    contract_version: CONTRACT_VERSION,
                    sprint_spec: dispatch.sprint_spec.clone(),
                    workspace_grant: dispatch.workspace_grant.contract().clone(),
                    applier: dispatch.applier.clone(),
                    admission: dispatch.admission.clone(),
                    intent: dispatch.intent.clone(),
                    outcome: WalkingSkeletonApplicationOutcome::Succeeded(Box::new(
                        AdaptedApplicationEvidence {
                            application_evidence,
                            rollback_reference,
                            canonical_evidence,
                        },
                    )),
                },
                observation_authority,
            ))
        }

        fn cleanup_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonApplicationCleanup<'_>,
        ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
            let launch = ledger.load_runner_launch_intent(
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
            )?;
            let cleaned_at_unix_ms = cleanup.cleanup_at_unix_ms;
            let persisted = ledger.with_runner_launch_cleanup_exclusion(
                &cleanup.sprint_spec.sprint_id,
                &launch.launch_id,
                |claim| {
                    let admission = claim.admission();
                    let cleanup_effect = &admission.cleanup_effect;
                    let os_evidence_bytes = format!(
                        "strict-fake-application-zero-direct-child-survivors:{}",
                        admission.launch.launch_id
                    )
                    .into_bytes();
                    let evidence = WorkerCleanupEvidence {
                        receipt: WorkerCleanupReceipt {
                            contract_version: CONTRACT_VERSION,
                            receipt_id: application_identity(
                                &admission.launch.sprint_id,
                                "cleanup-receipt",
                            ),
                            sprint_id: admission.launch.sprint_id.clone(),
                            launch_id: admission.launch.launch_id.clone(),
                            effect_id: cleanup_effect.intent.effect_id.clone(),
                            observation_id: format!(
                                "{}:observation",
                                cleanup_effect.intent.effect_id
                            ),
                            session_id: admission.launch.session_id.clone(),
                            worker_lease: None,
                            policy_hash: admission.launch.policy_hash.clone(),
                            grant_hash: admission.launch.grant_hash.clone(),
                            policy_version: admission.launch.policy_version,
                            platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
                            os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                            surviving_processes: 0,
                            cleaned_at_unix_ms,
                        },
                        os_evidence_bytes,
                    };
                    let canonical =
                        serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
                            entity: "strict fake application cleanup evidence",
                            detail: error.to_string(),
                        })?;
                    let observation = EffectObservation {
                        contract_version: CONTRACT_VERSION,
                        observation_id: evidence.receipt.observation_id.clone(),
                        effect_id: cleanup_effect.intent.effect_id.clone(),
                        idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: None,
                        worker_id: None,
                        worker_lease: None,
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        kind: EffectKind::CleanupWorkerDomain,
                        request_digest: cleanup_effect.intent.request_digest.clone(),
                        policy_hash: cleanup_effect.intent.policy_hash.clone(),
                        input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
                        outcome: EffectOutcome::Succeeded {
                            evidence_digest: Digest::sha256(&canonical),
                        },
                        observed_at_unix_ms: cleaned_at_unix_ms,
                    };
                    let event = AgentEvent {
                        contract_version: CONTRACT_VERSION,
                        sequence: claim.next_event_sequence(),
                        event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
                        sprint_id: cleanup_effect.intent.sprint_id.clone(),
                        task_id: None,
                        worker_id: None,
                        causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
                        correlation_id: cleanup_effect.intent.correlation_id.clone(),
                        policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
                        occurred_at_unix_ms: cleaned_at_unix_ms,
                        payload: AgentEventKind::ToolFinished {
                            tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                            succeeded: true,
                        },
                    };
                    Ok(RunnerCleanupTerminalRecord {
                        observation,
                        event,
                        evidence,
                    })
                },
            )?;
            Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
                persisted,
            ))
        }

        fn cleanup_terminal_sprint_application(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonApplicationTerminalCleanup<'_>,
        ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
            strict_fake_terminal_application_cleanup(
                ledger,
                &cleanup.sprint_spec.sprint_id,
                &cleanup.admission.runner_launch_id,
                cleanup.cleanup_at_unix_ms,
            )
        }
    }

    fn strict_fake_terminal_application_cleanup(
        ledger: &mut EventLedger,
        sprint_id: &str,
        launch_id: &str,
        cleaned_at_unix_ms: u64,
    ) -> Result<WalkingSkeletonApplicationCleanupOutcome, DurableCoordinatorError> {
        let launch = ledger.load_runner_launch_intent(sprint_id, launch_id)?;
        let persisted =
            ledger.with_runner_launch_cleanup_exclusion(sprint_id, &launch.launch_id, |claim| {
                let admission = claim.admission();
                let cleanup_effect = &admission.cleanup_effect;
                let os_evidence_bytes = format!(
                    "strict-fake-terminal-application-zero-direct-child-survivors:{}",
                    admission.launch.launch_id
                )
                .into_bytes();
                let evidence = WorkerCleanupEvidence {
                    receipt: WorkerCleanupReceipt {
                        contract_version: CONTRACT_VERSION,
                        receipt_id: application_identity(
                            &admission.launch.sprint_id,
                            "cleanup-receipt",
                        ),
                        sprint_id: admission.launch.sprint_id.clone(),
                        launch_id: admission.launch.launch_id.clone(),
                        effect_id: cleanup_effect.intent.effect_id.clone(),
                        observation_id: format!("{}:observation", cleanup_effect.intent.effect_id),
                        session_id: admission.launch.session_id.clone(),
                        worker_lease: None,
                        policy_hash: admission.launch.policy_hash.clone(),
                        grant_hash: admission.launch.grant_hash.clone(),
                        policy_version: admission.launch.policy_version,
                        platform_backend: WorkerCleanupBackend::TrustedApplierDirectChildWait,
                        os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                        surviving_processes: 0,
                        cleaned_at_unix_ms,
                    },
                    os_evidence_bytes,
                };
                let canonical =
                    serde_json::to_vec(&evidence).map_err(|error| LedgerError::Corrupt {
                        entity: "strict fake terminal application cleanup evidence",
                        detail: error.to_string(),
                    })?;
                let observation = EffectObservation {
                    contract_version: CONTRACT_VERSION,
                    observation_id: evidence.receipt.observation_id.clone(),
                    effect_id: cleanup_effect.intent.effect_id.clone(),
                    idempotency_key: cleanup_effect.intent.idempotency_key.clone(),
                    sprint_id: cleanup_effect.intent.sprint_id.clone(),
                    task_id: None,
                    worker_id: None,
                    worker_lease: None,
                    correlation_id: cleanup_effect.intent.correlation_id.clone(),
                    kind: EffectKind::CleanupWorkerDomain,
                    request_digest: cleanup_effect.intent.request_digest.clone(),
                    policy_hash: cleanup_effect.intent.policy_hash.clone(),
                    input_snapshot: cleanup_effect.intent.input_snapshot.clone(),
                    outcome: EffectOutcome::Succeeded {
                        evidence_digest: Digest::sha256(&canonical),
                    },
                    observed_at_unix_ms: cleaned_at_unix_ms,
                };
                let event = AgentEvent {
                    contract_version: CONTRACT_VERSION,
                    sequence: claim.next_event_sequence(),
                    event_id: format!("{}:finished", cleanup_effect.intent.effect_id),
                    sprint_id: cleanup_effect.intent.sprint_id.clone(),
                    task_id: None,
                    worker_id: None,
                    causation_id: Some(cleanup_effect.proposed_event.event_id.clone()),
                    correlation_id: cleanup_effect.intent.correlation_id.clone(),
                    policy_hash: Some(cleanup_effect.intent.policy_hash.clone()),
                    occurred_at_unix_ms: cleaned_at_unix_ms,
                    payload: AgentEventKind::ToolFinished {
                        tool_call_id: cleanup_effect.intent.idempotency_key.clone(),
                        succeeded: true,
                    },
                };
                Ok(RunnerCleanupTerminalRecord {
                    observation,
                    event,
                    evidence,
                })
            })?;
        Ok(WalkingSkeletonApplicationCleanupOutcome::Completed(
            persisted,
        ))
    }

    fn task_effect_response_for_dispatch(
        sprint_spec: &SprintSpec,
        workspace_grant: &IssuedWorkspaceGrant,
        running_boundary: &TaskAttemptRunningBoundary,
        intent: &EffectIntent,
        request_bytes: &[u8],
        mutation_receipt: Option<WalkingSkeletonMutationReceipt>,
        outcome: WalkingSkeletonTaskEffectOutcome,
    ) -> WalkingSkeletonTaskEffectResponse {
        WalkingSkeletonTaskEffectResponse {
            contract_version: CONTRACT_VERSION,
            sprint_spec: sprint_spec.clone(),
            workspace_grant: workspace_grant.contract().clone(),
            running_boundary: running_boundary.clone(),
            intent: intent.clone(),
            request_digest: Digest::sha256(request_bytes),
            mutation_receipt,
            outcome,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ScriptedDispatchBehavior {
        Exact,
        SuccessfulCommand,
        SuccessfulCommandUnknownAfterDispatch,
        SensitiveOutputRejected,
        SensitiveOutputRejectedOnce,
        SubstituteAttempt,
        SubstituteSession,
        SubstituteIntent,
        SubstituteRequest,
        SubstituteSnapshot,
        SubstituteLease,
        CrossPreviousResponse,
        ClaimedFailedBeforeEffect,
        ClaimedUnknownAfterDispatch,
        ExtraShadowFileAfterMutation,
        WrongShadowBytesAfterMutation,
        CrossMutationResultSnapshot,
        ErrorAfterDispatch,
    }

    struct ScriptedRunnerLifecycle {
        strict: StrictFakeRunnerLifecycle,
        behavior: ScriptedDispatchBehavior,
        dispatch_count: Rc<Cell<u32>>,
        sensitive_cleanup_count: Rc<Cell<u32>>,
        sensitive_rejection_injected: bool,
        previous_response: Option<WalkingSkeletonTaskEffectResponse>,
    }

    impl ScriptedRunnerLifecycle {
        fn new(behavior: ScriptedDispatchBehavior, dispatch_count: Rc<Cell<u32>>) -> Self {
            Self {
                strict: StrictFakeRunnerLifecycle,
                behavior,
                dispatch_count,
                sensitive_cleanup_count: Rc::new(Cell::new(0)),
                sensitive_rejection_injected: false,
                previous_response: None,
            }
        }

        fn sensitive_cleanup_count(&self) -> Rc<Cell<u32>> {
            Rc::clone(&self.sensitive_cleanup_count)
        }
    }
