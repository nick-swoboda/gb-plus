    use super::*;

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn core_id(label: &str) -> String {
        digest(label).as_str().to_owned()
    }

    #[derive(Clone, Copy)]
    enum TestReachedFrontier {
        LaunchCommitted,
        CaptureAcquired,
        V13Initialized,
        Dispatched,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixed complete 49-reservation fixture is intentionally auditable in one place"
    )]
    fn spine_with(suffix: &str) -> CurrentFinalVerificationIdentitySpineV2 {
        let lifecycle_reservations = CurrentFinalVerificationLifecycleReservationSetV2::new(
            CurrentFinalVerificationLifecycleReservationFieldsV2 {
                reservation_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
                runner_launch_id: core_id(&format!("launch-{suffix}")),
                runner_session_id: core_id(&format!("session-{suffix}")),
                effect_id: core_id(&format!("effect-{suffix}")),
                capture_id: core_id(&format!("capture-{suffix}")),
                capture_intent_id: core_id(&format!("capture-intent-{suffix}")),
                dispatch_id: core_id(&format!("dispatch-{suffix}")),
                command_request_id: core_id(&format!("command-{suffix}")),
                effect_idempotency_key: core_id(&format!("effect-idempotency-{suffix}")),
                native_launch_preparation_attempt_id: core_id(&format!(
                    "native-launch-preparation-attempt-{suffix}"
                )),
                native_launch_journal_id: core_id(&format!("native-launch-journal-{suffix}")),
                native_launch_cleanup_effect_id: core_id(&format!(
                    "native-launch-cleanup-effect-{suffix}"
                )),
                native_launch_preparation_receipt_id: core_id(&format!(
                    "native-launch-preparation-receipt-{suffix}"
                )),
                native_launch_release_receipt_id: core_id(&format!(
                    "native-launch-release-receipt-{suffix}"
                )),
                native_launch_cleanup_receipt_id: core_id(&format!(
                    "native-launch-cleanup-receipt-{suffix}"
                )),
                capture_acquired_event_id: core_id(&format!("capture-acquired-{suffix}")),
                v13_initialized_event_id: core_id(&format!("initialized-{suffix}")),
                command_dispatched_event_id: core_id(&format!("dispatched-{suffix}")),
                control_issued_event_id: core_id(&format!("control-issued-{suffix}")),
                control_observed_event_id: core_id(&format!("control-observed-{suffix}")),
                control_reconciled_event_id: core_id(&format!("control-reconciled-{suffix}")),
                terminal_event_id: core_id(&format!("terminal-event-{suffix}")),
                effect_cut_event_id: core_id(&format!("effect-cut-event-{suffix}")),
                output_custody_event_id: core_id(&format!("custody-event-{suffix}")),
                command_cleanup_event_id: core_id(&format!("command-cleanup-event-{suffix}")),
                runner_direct_child_observed_event_id: core_id(&format!(
                    "runner-direct-child-event-{suffix}"
                )),
                runner_domain_observed_event_id: core_id(&format!("runner-domain-event-{suffix}")),
                runner_cleanup_event_id: core_id(&format!("runner-cleanup-event-{suffix}")),
                evidence_closure_event_id: core_id(&format!("evidence-closure-event-{suffix}")),
                outcome_derived_event_id: core_id(&format!("outcome-derived-event-{suffix}")),
                initialization_request_id: core_id(&format!("initialization-request-{suffix}")),
                initialization_receipt_id: core_id(&format!("initialization-receipt-{suffix}")),
                control_id: core_id(&format!("control-{suffix}")),
                control_reconciliation_id: core_id(&format!("control-reconciliation-{suffix}")),
                terminal_observation_id: core_id(&format!("terminal-observation-{suffix}")),
                effect_cut_observation_id: core_id(&format!("effect-cut-observation-{suffix}")),
                shutdown_request_id: core_id(&format!("shutdown-request-{suffix}")),
                shutdown_receipt_id: core_id(&format!("shutdown-receipt-{suffix}")),
                command_accounting_domain_id: core_id(&format!("command-domain-{suffix}")),
                command_cleanup_observation_id: core_id(&format!(
                    "command-cleanup-observation-{suffix}"
                )),
                runner_accounting_domain_id: core_id(&format!("runner-domain-{suffix}")),
                runner_direct_child_observer_id: core_id(&format!(
                    "runner-direct-child-observer-{suffix}"
                )),
                runner_direct_child_observation_id: core_id(&format!(
                    "runner-direct-child-observation-{suffix}"
                )),
                runner_domain_observer_id: core_id(&format!("runner-domain-observer-{suffix}")),
                runner_domain_observation_id: core_id(&format!(
                    "runner-domain-observation-{suffix}"
                )),
                output_custody_closure_receipt_id: core_id(&format!(
                    "output-custody-closure-{suffix}"
                )),
                runner_cleanup_proof_id: core_id(&format!("runner-cleanup-proof-{suffix}")),
                evidence_closure_id: core_id(&format!("evidence-closure-{suffix}")),
                outcome_id: core_id(&format!("outcome-{suffix}")),
                verification_receipt_id: core_id(&format!("verification-receipt-{suffix}")),
            },
        )
        .expect("valid lifecycle reservations");
        let launch = CurrentFinalVerificationLaunchCommittedFrontierV2 {
            lifecycle_reservations,
            containment_backend:
                CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt,
            target_identity_digest: digest(&format!("target-identity-{suffix}")),
            native_policy_digest: digest(&format!("native-containment-policy-{suffix}")),
            launch_preparation_digest: digest(&format!("launch-preparation-{suffix}")),
            launch_authority_digest: digest(&format!("launch-authority-{suffix}")),
            runner_binary_digest: digest(&format!("binary-{suffix}")),
            private_state_digest: digest(&format!("private-state-{suffix}")),
            capture_intent_digest: digest(&format!("capture-intent-digest-{suffix}")),
            detector_policy_digest: digest(&format!("detector-{suffix}")),
            runner_protocol_digest: digest(&format!("protocol-{suffix}")),
            committed_event_id: core_id(&format!("launch-committed-{suffix}")),
            committed_event_sequence: 11,
        };
        let acquired_event_id = launch
            .lifecycle_reservations
            .fields
            .capture_acquired_event_id
            .clone();
        let capture = CurrentFinalVerificationCaptureAcquiredFrontierV2 {
            launch: Box::new(launch),
            output_capture_anchor_digest: digest(&format!("capture-anchor-{suffix}")),
            acquired_event_id,
            acquired_event_sequence: 12,
        };
        let initialized_event_id = capture
            .launch
            .lifecycle_reservations
            .fields
            .v13_initialized_event_id
            .clone();
        let initialized = CurrentFinalVerificationV13InitializedFrontierV2 {
            capture: Box::new(capture),
            initialization_request_commitment_digest: digest(&format!(
                "initialization-request-{suffix}"
            )),
            initialization_receipt_commitment_digest: digest(&format!(
                "initialization-receipt-{suffix}"
            )),
            v13_embedded_v32_attempt_payload_digest: digest(&format!(
                "v13-v32-attempt-payload-{suffix}"
            )),
            runner_nonce: digest(&format!("nonce-{suffix}")),
            initialized_event_id,
            initialized_event_sequence: 13,
        };
        let dispatched_event_id = initialized
            .capture
            .launch
            .lifecycle_reservations
            .fields
            .command_dispatched_event_id
            .clone();
        let dispatched = CurrentFinalVerificationDispatchedFrontierV2 {
            initialized: Box::new(initialized),
            command_request_digest: digest(&format!("command-digest-{suffix}")),
            command_transport_commitment_digest: digest(&format!("transport-{suffix}")),
            dispatched_event_id,
            dispatched_event_sequence: 20,
        };
        CurrentFinalVerificationIdentitySpineV2::new(
            CurrentFinalVerificationIdentitySpineFieldsV2 {
                spine_version: CURRENT_FINAL_VERIFICATION_EVIDENCE_VERSION_V2,
                sprint_id: format!("sprint-{suffix}"),
                task_graph_id: format!("graph-{suffix}"),
                attempt_id: format!("attempt-{suffix}"),
                admission_id: format!("admission-{suffix}"),
                sprint_spec_digest: digest(&format!("spec-{suffix}")),
                task_graph_digest: digest(&format!("graph-digest-{suffix}")),
                task_graph_payload_digest: digest(&format!("graph-payload-{suffix}")),
                repair_slot_reserve_digest: digest(&format!("reserve-{suffix}")),
                operational_attempt_authority_digest: digest(&format!(
                    "operational-attempt-authority-{suffix}"
                )),
                complete_task_done_set_digest: digest(&format!("task-done-{suffix}")),
                complete_criterion_evidence_set_digest: digest(&format!("criteria-{suffix}")),
                workspace_grant_hash: digest(&format!("grant-{suffix}")),
                input_snapshot_digest: digest(&format!("snapshot-{suffix}")),
                execution_policy_digest: digest(&format!("policy-{suffix}")),
                verification_command_digest: digest(&format!("verification-command-{suffix}")),
                authority_admitted_event_id: core_id(&format!("authority-admitted-{suffix}")),
                authority_admitted_event_sequence: 10,
                reached_frontier: CurrentFinalVerificationReachedFrontierV2::Dispatched {
                    frontier: dispatched,
                },
            },
        )
        .expect("valid identity spine")
    }

    fn spine_at(
        suffix: &str,
        reached: TestReachedFrontier,
    ) -> CurrentFinalVerificationIdentitySpineV2 {
        let complete = spine_with(suffix);
        let reached_frontier = match reached {
            TestReachedFrontier::LaunchCommitted => {
                CurrentFinalVerificationReachedFrontierV2::LaunchCommitted {
                    frontier: Box::new(complete.fields.reached_frontier.launch().clone()),
                }
            }
            TestReachedFrontier::CaptureAcquired => {
                CurrentFinalVerificationReachedFrontierV2::CaptureAcquired {
                    frontier: complete
                        .fields
                        .reached_frontier
                        .capture()
                        .expect("complete fixture has capture")
                        .clone(),
                }
            }
            TestReachedFrontier::V13Initialized => {
                CurrentFinalVerificationReachedFrontierV2::V13Initialized {
                    frontier: complete
                        .fields
                        .reached_frontier
                        .initialized()
                        .expect("complete fixture has initialization")
                        .clone(),
                }
            }
            TestReachedFrontier::Dispatched => complete.fields.reached_frontier.clone(),
        };
        let mut fields = complete.fields;
        fields.reached_frontier = reached_frontier;
        CurrentFinalVerificationIdentitySpineV2::new(fields).expect("valid truncated frontier")
    }

    fn terminal(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        sequence: u64,
        mut observation: CurrentFinalVerificationTerminalObservationV2,
    ) -> CurrentFinalVerificationTerminalSourceV2 {
        let reservations = lifecycle_reservations(spine);
        match &mut observation {
            CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect { proof_id, .. } => {
                proof_id.clone_from(&reservations.terminal_observation_id);
            }
            CurrentFinalVerificationTerminalObservationV2::Unknown {
                reconciliation_id, ..
            } => reconciliation_id.clone_from(&reservations.terminal_observation_id),
            CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                claimed_control_id,
            } => claimed_control_id.clone_from(&reservations.control_id),
            CurrentFinalVerificationTerminalObservationV2::Exited { .. }
            | CurrentFinalVerificationTerminalObservationV2::Signaled { .. }
            | CurrentFinalVerificationTerminalObservationV2::TimedOut
            | CurrentFinalVerificationTerminalObservationV2::OutputLimitExceeded { .. } => {}
        }
        CurrentFinalVerificationTerminalSourceV2::new(
            spine.clone(),
            reservations.terminal_observation_id.clone(),
            reservations.terminal_event_id.clone(),
            sequence,
            observation,
        )
        .expect("valid terminal")
    }

    fn effect_cut(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        sequence: u64,
        mut observation: CurrentFinalVerificationEffectCutObservationV2,
    ) -> CurrentFinalVerificationEffectCutSourceV2 {
        let reservations = lifecycle_reservations(spine);
        match &mut observation {
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect { proof_id, .. } => {
                proof_id.clone_from(&reservations.effect_cut_observation_id);
            }
            CurrentFinalVerificationEffectCutObservationV2::EffectStarted {
                start_observation_id,
            } => start_observation_id.clone_from(&reservations.effect_cut_observation_id),
            CurrentFinalVerificationEffectCutObservationV2::Unknown {
                reconciliation_id, ..
            } => reconciliation_id.clone_from(&reservations.effect_cut_observation_id),
        }
        CurrentFinalVerificationEffectCutSourceV2::new(
            spine.clone(),
            reservations.effect_cut_observation_id.clone(),
            reservations.effect_cut_event_id.clone(),
            sequence,
            observation,
        )
        .expect("valid effect cut")
    }

    fn custody(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        sequence: u64,
        mut observation: CurrentFinalVerificationOutputCustodyObservationV2,
    ) -> CurrentFinalVerificationOutputCustodySourceV2 {
        let reservations = lifecycle_reservations(spine);
        let closure_id = reservations.output_custody_closure_receipt_id.clone();
        match &mut observation {
            CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean {
                publication_receipt_id,
                ..
            } => publication_receipt_id.clone_from(&closure_id),
            CurrentFinalVerificationOutputCustodyObservationV2::AbandonedSensitive {
                rejection_closure_id,
                ..
            } => rejection_closure_id.clone_from(&closure_id),
            CurrentFinalVerificationOutputCustodyObservationV2::AbandonedBeforeEffect {
                abandonment_receipt_id,
                ..
            } => abandonment_receipt_id.clone_from(&closure_id),
            CurrentFinalVerificationOutputCustodyObservationV2::ClosedBeforeCapture {
                closure_receipt_id,
                ..
            } => closure_receipt_id.clone_from(&closure_id),
            CurrentFinalVerificationOutputCustodyObservationV2::Unknown {
                reconciliation_id,
                ..
            } => reconciliation_id.clone_from(&closure_id),
        }
        CurrentFinalVerificationOutputCustodySourceV2::new(
            spine.clone(),
            reservations.output_custody_event_id.clone(),
            sequence,
            observation,
        )
        .expect("valid custody")
    }

    fn command_cleanup(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        sequence: u64,
        mut observation: CurrentCommandDomainCleanupObservationV2,
    ) -> CurrentCommandDomainCleanupSourceV2 {
        let reservations = lifecycle_reservations(spine);
        if let CurrentCommandDomainCleanupObservationV2::Unknown {
            reconciliation_id, ..
        } = &mut observation
        {
            reconciliation_id.clone_from(&reservations.command_cleanup_observation_id);
        }
        CurrentCommandDomainCleanupSourceV2::new(
            spine.clone(),
            CurrentCommandDomainBackendV2::MacOsDedicatedIdentity,
            reservations.command_accounting_domain_id.clone(),
            reservations.command_cleanup_observation_id.clone(),
            reservations.command_cleanup_event_id.clone(),
            sequence,
            observation,
        )
        .expect("valid command cleanup")
    }

    fn runner_cleanup(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        direct_sequence: u64,
        domain_sequence: u64,
        cleanup_sequence: u64,
        direct_child: CurrentIndependentDirectChildObservationV2,
        accounting_domain: CurrentIndependentRunnerDomainObservationV2,
        shutdown_transcript: Option<CurrentRunnerShutdownTranscriptV2>,
    ) -> CurrentRunnerCleanupSourceV2 {
        let reservations = lifecycle_reservations(spine);
        CurrentRunnerCleanupSourceV2::new(
            spine.clone(),
            spine.fields.reached_frontier.launch().containment_backend,
            reservations.runner_accounting_domain_id.clone(),
            reservations.runner_cleanup_proof_id.clone(),
            reservations.runner_cleanup_event_id.clone(),
            cleanup_sequence,
            rewrite_direct_sequence(direct_child, direct_sequence, reservations),
            rewrite_domain_sequence(accounting_domain, domain_sequence, reservations),
            shutdown_transcript,
        )
        .expect("valid runner cleanup")
    }

    fn rewrite_direct_sequence(
        observation: CurrentIndependentDirectChildObservationV2,
        sequence: u64,
        reservations: &CurrentFinalVerificationLifecycleReservationFieldsV2,
    ) -> CurrentIndependentDirectChildObservationV2 {
        match observation {
            CurrentIndependentDirectChildObservationV2::Reaped {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                process_id,
                evidence_digest,
                ..
            } => CurrentIndependentDirectChildObservationV2::Reaped {
                observer_id: reservations.runner_direct_child_observer_id.clone(),
                observation_id: reservations.runner_direct_child_observation_id.clone(),
                observed_event_id: reservations.runner_direct_child_observed_event_id.clone(),
                process_id,
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentDirectChildObservationV2::NotSpawned {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                evidence_digest,
                ..
            } => CurrentIndependentDirectChildObservationV2::NotSpawned {
                observer_id: reservations.runner_direct_child_observer_id.clone(),
                observation_id: reservations.runner_direct_child_observation_id.clone(),
                observed_event_id: reservations.runner_direct_child_observed_event_id.clone(),
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentDirectChildObservationV2::StillPresent {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                process_id,
                evidence_digest,
                ..
            } => CurrentIndependentDirectChildObservationV2::StillPresent {
                observer_id: reservations.runner_direct_child_observer_id.clone(),
                observation_id: reservations.runner_direct_child_observation_id.clone(),
                observed_event_id: reservations.runner_direct_child_observed_event_id.clone(),
                process_id,
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentDirectChildObservationV2::Unknown {
                observer_id: _,
                reconciliation_id: _,
                observed_event_id: _,
                evidence_digest,
                ..
            } => CurrentIndependentDirectChildObservationV2::Unknown {
                observer_id: reservations.runner_direct_child_observer_id.clone(),
                reconciliation_id: reservations.runner_direct_child_observation_id.clone(),
                observed_event_id: reservations.runner_direct_child_observed_event_id.clone(),
                observed_event_sequence: sequence,
                evidence_digest,
            },
        }
    }

    fn rewrite_domain_sequence(
        observation: CurrentIndependentRunnerDomainObservationV2,
        sequence: u64,
        reservations: &CurrentFinalVerificationLifecycleReservationFieldsV2,
    ) -> CurrentIndependentRunnerDomainObservationV2 {
        match observation {
            CurrentIndependentRunnerDomainObservationV2::Empty {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                observed_members,
                evidence_digest,
                ..
            } => CurrentIndependentRunnerDomainObservationV2::Empty {
                observer_id: reservations.runner_domain_observer_id.clone(),
                observation_id: reservations.runner_domain_observation_id.clone(),
                observed_event_id: reservations.runner_domain_observed_event_id.clone(),
                observed_members,
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentRunnerDomainObservationV2::NotCreated {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                observed_members,
                evidence_digest,
                ..
            } => CurrentIndependentRunnerDomainObservationV2::NotCreated {
                observer_id: reservations.runner_domain_observer_id.clone(),
                observation_id: reservations.runner_domain_observation_id.clone(),
                observed_event_id: reservations.runner_domain_observed_event_id.clone(),
                observed_members,
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentRunnerDomainObservationV2::SurvivorsPresent {
                observer_id: _,
                observation_id: _,
                observed_event_id: _,
                observed_members,
                evidence_digest,
                ..
            } => CurrentIndependentRunnerDomainObservationV2::SurvivorsPresent {
                observer_id: reservations.runner_domain_observer_id.clone(),
                observation_id: reservations.runner_domain_observation_id.clone(),
                observed_event_id: reservations.runner_domain_observed_event_id.clone(),
                observed_members,
                observed_event_sequence: sequence,
                evidence_digest,
            },
            CurrentIndependentRunnerDomainObservationV2::Unknown {
                observer_id: _,
                reconciliation_id: _,
                observed_event_id: _,
                evidence_digest,
                ..
            } => CurrentIndependentRunnerDomainObservationV2::Unknown {
                observer_id: reservations.runner_domain_observer_id.clone(),
                reconciliation_id: reservations.runner_domain_observation_id.clone(),
                observed_event_id: reservations.runner_domain_observed_event_id.clone(),
                observed_event_sequence: sequence,
                evidence_digest,
            },
        }
    }

    fn clean_direct() -> CurrentIndependentDirectChildObservationV2 {
        CurrentIndependentDirectChildObservationV2::Reaped {
            observer_id: "desktop-child-observer".into(),
            observation_id: "direct-child-observation".into(),
            observed_event_id: core_id("placeholder-direct-child-event"),
            process_id: 4242,
            observed_event_sequence: 27,
            evidence_digest: digest("direct-child-evidence"),
        }
    }

    fn clean_domain() -> CurrentIndependentRunnerDomainObservationV2 {
        CurrentIndependentRunnerDomainObservationV2::Empty {
            observer_id: "desktop-domain-observer".into(),
            observation_id: "runner-domain-observation".into(),
            observed_event_id: core_id("placeholder-runner-domain-event"),
            observed_members: 0,
            observed_event_sequence: 28,
            evidence_digest: digest("runner-domain-evidence"),
        }
    }

    fn child_not_spawned() -> CurrentIndependentDirectChildObservationV2 {
        CurrentIndependentDirectChildObservationV2::NotSpawned {
            observer_id: "desktop-child-observer".into(),
            observation_id: "direct-child-not-spawned".into(),
            observed_event_id: core_id("placeholder-direct-child-not-spawned-event"),
            observed_event_sequence: 27,
            evidence_digest: digest("direct-child-not-spawned-evidence"),
        }
    }

    fn runner_domain_not_created() -> CurrentIndependentRunnerDomainObservationV2 {
        CurrentIndependentRunnerDomainObservationV2::NotCreated {
            observer_id: "desktop-domain-observer".into(),
            observation_id: "runner-domain-not-created".into(),
            observed_event_id: core_id("placeholder-runner-domain-not-created-event"),
            observed_members: 0,
            observed_event_sequence: 28,
            evidence_digest: digest("runner-domain-not-created-evidence"),
        }
    }

    fn published() -> CurrentFinalVerificationOutputCustodyObservationV2 {
        CurrentFinalVerificationOutputCustodyObservationV2::PublishedClean {
            publication_receipt_id: "publication-receipt".into(),
            publication_receipt_digest: digest("publication-receipt"),
            output_artifact_set_digest: digest("output-artifact-set"),
            stdout_artifact_digest: digest("stdout"),
            stderr_artifact_digest: digest("stderr"),
        }
    }

    fn pre_effect_abandoned(
        reason: CurrentFinalVerificationPreEffectAbandonmentReasonV2,
    ) -> CurrentFinalVerificationOutputCustodyObservationV2 {
        CurrentFinalVerificationOutputCustodyObservationV2::AbandonedBeforeEffect {
            abandonment_receipt_id: "pre-effect-abandonment".into(),
            abandonment_receipt_digest: digest("pre-effect-abandonment"),
            neutralization_receipt_digest: digest("pre-effect-neutralization"),
            reason,
        }
    }

    fn closed_before_capture() -> CurrentFinalVerificationOutputCustodyObservationV2 {
        CurrentFinalVerificationOutputCustodyObservationV2::ClosedBeforeCapture {
            closure_receipt_id: "closed-before-capture".into(),
            closure_receipt_digest: digest("closed-before-capture"),
        }
    }

    fn terminal_proven_no_effect() -> CurrentFinalVerificationTerminalObservationV2 {
        CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect {
            proof_id: "no-effect-proof".into(),
            proof_digest: digest("no-effect-proof"),
        }
    }

    fn cut_proven_no_effect() -> CurrentFinalVerificationEffectCutObservationV2 {
        CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
            proof_id: "no-effect-proof".into(),
            proof_digest: digest("no-effect-proof"),
        }
    }

    fn authenticated_resolution(
        spine: &CurrentFinalVerificationIdentitySpineV2,
        _control_id: &str,
        action: CurrentFinalVerificationControlActionKindV2,
    ) -> CurrentFinalVerificationControlResolutionSourceV2 {
        let reservations = lifecycle_reservations(spine);
        CurrentFinalVerificationControlResolutionSourceV2::Authenticated {
            source: Box::new(
                AuthenticatedCurrentFinalVerificationControlActionV2::new(
                    spine.clone(),
                    reservations.control_id.clone(),
                    action,
                    reservations.control_issued_event_id.clone(),
                    21,
                    reservations.control_observed_event_id.clone(),
                    22,
                )
                .expect("valid control"),
            ),
        }
    }

    fn clean_command_domain() -> CurrentCommandDomainCleanupObservationV2 {
        CurrentCommandDomainCleanupObservationV2::ReapedEmpty {
            observed_processes: 0,
            platform_proof_digest: digest("command-platform-proof"),
        }
    }

    fn command_domain_not_created() -> CurrentCommandDomainCleanupObservationV2 {
        CurrentCommandDomainCleanupObservationV2::NoDomainCreatedBeforeEffect {
            observed_processes: 0,
            platform_proof_digest: digest("command-domain-not-created"),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "fixture mirrors the five independently sourced terminal domains"
    )]
    fn complete_inputs_for_spine(
        spine: CurrentFinalVerificationIdentitySpineV2,
        terminal_observation: CurrentFinalVerificationTerminalObservationV2,
        effect_observation: CurrentFinalVerificationEffectCutObservationV2,
        custody_observation: CurrentFinalVerificationOutputCustodyObservationV2,
        command_observation: CurrentCommandDomainCleanupObservationV2,
        direct_child: CurrentIndependentDirectChildObservationV2,
        accounting_domain: CurrentIndependentRunnerDomainObservationV2,
    ) -> NonAuthorizingCurrentFinalVerificationEvidenceInputsV2 {
        let terminal = terminal(&spine, 24, terminal_observation);
        let effect_cut = effect_cut(&spine, 23, effect_observation);
        let output_custody = custody(&spine, 25, custody_observation);
        let command_domain_cleanup = command_cleanup(&spine, 26, command_observation);
        let runner_cleanup =
            runner_cleanup(&spine, 27, 28, 29, direct_child, accounting_domain, None);
        NonAuthorizingCurrentFinalVerificationEvidenceInputsV2 {
            identity_spine: spine,
            terminal: Some(terminal),
            effect_cut: Some(effect_cut),
            output_custody: Some(output_custody),
            command_domain_cleanup: Some(command_domain_cleanup),
            runner_cleanup: Some(runner_cleanup),
            control_resolution: None,
        }
    }

    fn complete_inputs(
        terminal_observation: CurrentFinalVerificationTerminalObservationV2,
        effect_observation: CurrentFinalVerificationEffectCutObservationV2,
        custody_observation: CurrentFinalVerificationOutputCustodyObservationV2,
    ) -> NonAuthorizingCurrentFinalVerificationEvidenceInputsV2 {
        complete_inputs_for_spine(
            spine_with("one"),
            terminal_observation,
            effect_observation,
            custody_observation,
            clean_command_domain(),
            clean_direct(),
            clean_domain(),
        )
    }

    fn started() -> CurrentFinalVerificationEffectCutObservationV2 {
        CurrentFinalVerificationEffectCutObservationV2::EffectStarted {
            start_observation_id: "effect-started".into(),
        }
    }

    fn derived_kind(
        inputs: &NonAuthorizingCurrentFinalVerificationEvidenceInputsV2,
    ) -> NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2 {
        match derive_non_authorizing_current_final_verification_evidence_v2(inputs)
            .expect("derivation succeeds")
        {
            NonAuthorizingCurrentFinalVerificationDerivationV2::Derived { outcome, .. } => {
                outcome.outcome
            }
            NonAuthorizingCurrentFinalVerificationDerivationV2::NotReady {
                missing_sources,
                ..
            } => {
                panic!("unexpected NotReady: {missing_sources:?}")
            }
        }
    }

    #[test]
    fn closed_terminal_matrix_derives_every_non_control_variant() {
        let cases = [
            (
                CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Verified,
            ),
            (
                CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 7 },
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::NonzeroExit {
                    exit_code: 7,
                },
            ),
            (
                CurrentFinalVerificationTerminalObservationV2::Signaled {
                    signal: 15,
                    core_dumped: false,
                },
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Signaled { signal: 15 },
            ),
            (
                CurrentFinalVerificationTerminalObservationV2::TimedOut,
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::TimedOut,
            ),
            (
                CurrentFinalVerificationTerminalObservationV2::OutputLimitExceeded {
                    limit_bytes: 1024,
                    observed_at_least_bytes: 1024,
                },
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::OutputLimitExceeded,
            ),
        ];
        for (terminal_observation, expected) in cases {
            let inputs = complete_inputs(terminal_observation, started(), published());
            assert_eq!(derived_kind(&inputs), expected);
        }

        let proof_digest = digest("no-effect-proof");
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect {
                proof_id: "no-effect-proof".into(),
                proof_digest: proof_digest.clone(),
            },
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                proof_id: "no-effect-proof".into(),
                proof_digest,
            },
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
        );
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::FailedBeforeEffect
        );

        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Unknown {
                reconciliation_id: "terminal-reconciliation".into(),
                evidence_digest: digest("terminal-unknown"),
            },
            started(),
            published(),
        );
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::TerminalSourceUnknown,
            }
        );
    }

    #[test]
    fn sensitive_abandonment_is_never_verification() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            CurrentFinalVerificationOutputCustodyObservationV2::AbandonedSensitive {
                rejection_closure_id: "sensitive-rejection".into(),
                rejection_closure_digest: digest("sensitive-rejection"),
                neutralization_receipt_digest: digest("neutralized-empty"),
            },
        );
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::SensitiveOutputRejected
        );
    }

    #[test]
    fn every_clean_frontier_cleanup_shape_derives_exactly() {
        let expected =
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::FailedBeforeEffect;

        let launch = complete_inputs_for_spine(
            spine_at("launch", TestReachedFrontier::LaunchCommitted),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            closed_before_capture(),
            command_domain_not_created(),
            child_not_spawned(),
            runner_domain_not_created(),
        );
        assert_eq!(derived_kind(&launch), expected);

        let captured_without_spawn = complete_inputs_for_spine(
            spine_at("capture-no-spawn", TestReachedFrontier::CaptureAcquired),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            child_not_spawned(),
            runner_domain_not_created(),
        );
        assert_eq!(derived_kind(&captured_without_spawn), expected);

        let captured_after_spawn_attempt = complete_inputs_for_spine(
            spine_at("capture-spawn", TestReachedFrontier::CaptureAcquired),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            clean_direct(),
            clean_domain(),
        );
        assert_eq!(derived_kind(&captured_after_spawn_attempt), expected);

        let initialized = complete_inputs_for_spine(
            spine_at("initialized", TestReachedFrontier::V13Initialized),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            clean_direct(),
            clean_domain(),
        );
        assert_eq!(derived_kind(&initialized), expected);

        for command_cleanup in [command_domain_not_created(), clean_command_domain()] {
            let dispatched = complete_inputs_for_spine(
                spine_at("dispatched", TestReachedFrontier::Dispatched),
                terminal_proven_no_effect(),
                cut_proven_no_effect(),
                pre_effect_abandoned(
                    CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
                ),
                command_cleanup,
                clean_direct(),
                clean_domain(),
            );
            assert_eq!(derived_kind(&dispatched), expected);
        }
    }

    #[test]
    fn crossed_frontier_cleanup_shapes_are_typed_unknown() {
        let expected = NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
            reason: CurrentFinalVerificationUnknownReasonV2::CleanupEffectContradiction,
        };

        let launch_with_spawn = complete_inputs_for_spine(
            spine_at("launch-cross", TestReachedFrontier::LaunchCommitted),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            closed_before_capture(),
            command_domain_not_created(),
            clean_direct(),
            clean_domain(),
        );
        assert_eq!(derived_kind(&launch_with_spawn), expected);

        for (suffix, direct_child, runner_domain) in [
            (
                "capture-cross-child",
                clean_direct(),
                runner_domain_not_created(),
            ),
            ("capture-cross-domain", child_not_spawned(), clean_domain()),
        ] {
            let crossed_capture = complete_inputs_for_spine(
                spine_at(suffix, TestReachedFrontier::CaptureAcquired),
                terminal_proven_no_effect(),
                cut_proven_no_effect(),
                pre_effect_abandoned(
                    CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
                ),
                command_domain_not_created(),
                direct_child,
                runner_domain,
            );
            assert_eq!(derived_kind(&crossed_capture), expected);
        }

        let initialized_without_spawn = complete_inputs_for_spine(
            spine_at("initialized-cross", TestReachedFrontier::V13Initialized),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            child_not_spawned(),
            runner_domain_not_created(),
        );
        assert_eq!(derived_kind(&initialized_without_spawn), expected);

        let dispatched_without_spawn = complete_inputs_for_spine(
            spine_at("dispatch-cross", TestReachedFrontier::Dispatched),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            child_not_spawned(),
            runner_domain_not_created(),
        );
        assert_eq!(derived_kind(&dispatched_without_spawn), expected);
    }

    #[test]
    fn proven_no_effect_cut_may_follow_terminal_before_custody() {
        let mut inputs = complete_inputs_for_spine(
            spine_at("late-no-effect", TestReachedFrontier::Dispatched),
            terminal_proven_no_effect(),
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
            command_domain_not_created(),
            clean_direct(),
            clean_domain(),
        );
        let spine = inputs.identity_spine.clone();
        inputs.terminal = Some(terminal(&spine, 23, terminal_proven_no_effect()));
        inputs.effect_cut = Some(effect_cut(&spine, 24, cut_proven_no_effect()));
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::FailedBeforeEffect
        );
    }

    #[test]
    fn missing_sources_are_deterministic_not_ready_and_never_form_a_closure() {
        let mut inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Unknown {
                reconciliation_id: "known-unknown".into(),
                evidence_digest: digest("known-unknown"),
            },
            started(),
            published(),
        );
        inputs.output_custody = None;
        inputs.runner_cleanup = None;
        let result = derive_non_authorizing_current_final_verification_evidence_v2(&inputs)
            .expect("missing inputs are not malformed");
        assert_eq!(
            result,
            NonAuthorizingCurrentFinalVerificationDerivationV2::NotReady {
                identity_spine: Box::new(inputs.identity_spine),
                missing_sources: vec![
                    CurrentFinalVerificationMissingSourceV2::OutputCustody,
                    CurrentFinalVerificationMissingSourceV2::RunnerCleanup,
                ],
            }
        );
    }

    #[test]
    fn canceled_requires_exact_authenticated_control_and_orders_it_against_effect() {
        let proof_digest = digest("no-effect-proof");
        for action in [
            CurrentFinalVerificationControlActionKindV2::Pause,
            CurrentFinalVerificationControlActionKindV2::SteeringInterruption,
            CurrentFinalVerificationControlActionKindV2::Cancel,
        ] {
            let mut inputs = complete_inputs(
                CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                    claimed_control_id: "control-one".into(),
                },
                CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                    proof_id: "no-effect-proof".into(),
                    proof_digest: proof_digest.clone(),
                },
                pre_effect_abandoned(
                    CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
                ),
            );
            inputs.control_resolution = Some(authenticated_resolution(
                &inputs.identity_spine,
                "control-one",
                action,
            ));
            let control_id = lifecycle_reservations(&inputs.identity_spine)
                .control_id
                .clone();
            let expected = match action {
                CurrentFinalVerificationControlActionKindV2::Pause
                | CurrentFinalVerificationControlActionKindV2::SteeringInterruption => {
                    NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::ControlInterruptedBeforeEffect {
                        control_id,
                        action,
                    }
                }
                CurrentFinalVerificationControlActionKindV2::Cancel => {
                    NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Canceled {
                        control_id,
                    }
                }
            };
            assert_eq!(derived_kind(&inputs), expected);
        }

        let missing = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                claimed_control_id: "control-one".into(),
            },
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                proof_id: "no-effect-proof".into(),
                proof_digest,
            },
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
            ),
        );
        let result = derive_non_authorizing_current_final_verification_evidence_v2(&missing)
            .expect("missing control is not malformed");
        assert!(matches!(
            result,
            NonAuthorizingCurrentFinalVerificationDerivationV2::NotReady {
                missing_sources,
                ..
            } if missing_sources == vec![CurrentFinalVerificationMissingSourceV2::ControlResolution]
        ));

        let reservations = lifecycle_reservations(&missing.identity_spine);
        assert_eq!(
            AuthenticatedCurrentFinalVerificationControlActionV2::new(
                missing.identity_spine.clone(),
                core_id("different-control"),
                CurrentFinalVerificationControlActionKindV2::Pause,
                reservations.control_issued_event_id.clone(),
                21,
                reservations.control_observed_event_id.clone(),
                22,
            ),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "control_action.control_id",
                }
            )
        );
    }

    #[test]
    fn canceled_terminal_requires_bounded_control_reconciliation() {
        let mut inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                claimed_control_id: "claimed-control".into(),
            },
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
            ),
        );
        let reservations = lifecycle_reservations(&inputs.identity_spine).clone();
        inputs.control_resolution = Some(
            CurrentFinalVerificationControlResolutionSourceV2::unmatched_after_reconciliation(
                inputs.identity_spine.clone(),
                reservations.control_id.clone(),
                reservations.control_reconciliation_id.clone(),
                digest("control-reconciliation-receipt"),
                digest("event-stream-head"),
                23,
                reservations.control_reconciled_event_id.clone(),
                30,
            )
            .expect("valid reconciliation below terminal cut"),
        );
        assert!(matches!(
            derive_non_authorizing_current_final_verification_evidence_v2(&inputs)
                .expect("unfinished reconciliation is not malformed"),
            NonAuthorizingCurrentFinalVerificationDerivationV2::NotReady {
                missing_sources,
                ..
            } if missing_sources == vec![CurrentFinalVerificationMissingSourceV2::ControlResolution]
        ));

        inputs.control_resolution = Some(
            CurrentFinalVerificationControlResolutionSourceV2::unmatched_after_reconciliation(
                inputs.identity_spine.clone(),
                reservations.control_id,
                reservations.control_reconciliation_id,
                digest("control-reconciliation-receipt"),
                digest("event-stream-head"),
                24,
                reservations.control_reconciled_event_id,
                30,
            )
            .expect("valid complete reconciliation"),
        );
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::ControlIdentityContradiction,
            }
        );
    }

    #[test]
    fn pause_or_steer_after_effect_is_unknown_but_explicit_cancel_is_canceled() {
        for action in [
            CurrentFinalVerificationControlActionKindV2::Pause,
            CurrentFinalVerificationControlActionKindV2::SteeringInterruption,
        ] {
            let mut inputs = complete_inputs(
                CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                    claimed_control_id: "control-after-effect".into(),
                },
                started(),
                published(),
            );
            inputs.control_resolution = Some(authenticated_resolution(
                &inputs.identity_spine,
                "control-after-effect",
                action,
            ));
            assert_eq!(
                derived_kind(&inputs),
                NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                    reason:
                        CurrentFinalVerificationUnknownReasonV2::ControlEffectOrderingContradiction,
                }
            );
        }

        let mut canceled = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                claimed_control_id: "explicit-cancel".into(),
            },
            started(),
            published(),
        );
        canceled.control_resolution = Some(authenticated_resolution(
            &canceled.identity_spine,
            "explicit-cancel",
            CurrentFinalVerificationControlActionKindV2::Cancel,
        ));
        assert_eq!(
            derived_kind(&canceled),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Canceled {
                control_id: lifecycle_reservations(&canceled.identity_spine)
                    .control_id
                    .clone(),
            }
        );
    }

    #[test]
    fn shutdown_transcript_alone_never_closes_runner_cleanup() {
        let mut inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let spine = inputs.identity_spine.clone();
        let reservations = lifecycle_reservations(&spine).clone();
        inputs.runner_cleanup = Some(runner_cleanup(
            &spine,
            27,
            28,
            29,
            CurrentIndependentDirectChildObservationV2::Unknown {
                observer_id: "desktop-child-observer".into(),
                reconciliation_id: "child-unknown".into(),
                observed_event_id: core_id("placeholder-child-unknown-event"),
                observed_event_sequence: 27,
                evidence_digest: digest("child-unknown"),
            },
            CurrentIndependentRunnerDomainObservationV2::Unknown {
                observer_id: "desktop-domain-observer".into(),
                reconciliation_id: "domain-unknown".into(),
                observed_event_id: core_id("placeholder-domain-unknown-event"),
                observed_event_sequence: 28,
                evidence_digest: digest("domain-unknown"),
            },
            Some(CurrentRunnerShutdownTranscriptV2 {
                request_id: reservations.shutdown_request_id,
                receipt_id: reservations.shutdown_receipt_id,
                request_digest: digest("shutdown-request"),
                receipt_digest: digest("shutdown-receipt"),
                acknowledged_event_sequence: 26,
            }),
        ));
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::RunnerDirectChildUnknown,
            }
        );
    }

    #[test]
    fn positive_cleanup_unknown_and_survivors_dominate_success() {
        let mut inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let spine = inputs.identity_spine.clone();
        inputs.command_domain_cleanup = Some(command_cleanup(
            &spine,
            26,
            CurrentCommandDomainCleanupObservationV2::SurvivorsPresent {
                observed_processes: 1,
                evidence_digest: digest("command-survivor"),
            },
        ));
        assert_eq!(
            derived_kind(&inputs),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::CommandDomainSurvivorsPresent,
            }
        );
    }

    #[test]
    fn cross_source_order_and_no_effect_proof_digest_mismatch_are_typed_unknown() {
        let mut ordering = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let spine = ordering.identity_spine.clone();
        ordering.output_custody = Some(custody(&spine, 27, published()));
        ordering.command_domain_cleanup = Some(command_cleanup(&spine, 26, clean_command_domain()));
        assert_eq!(
            derived_kind(&ordering),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::SourceEventOrderingContradiction,
            }
        );

        let distinct_source_receipts = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect {
                proof_id: "proof-a".into(),
                proof_digest: digest("same-proof-bytes"),
            },
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                proof_id: "proof-b".into(),
                proof_digest: digest("same-proof-bytes"),
            },
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
        );
        assert_ne!(
            distinct_source_receipts
                .terminal
                .as_ref()
                .expect("terminal")
                .terminal_observation_id,
            distinct_source_receipts
                .effect_cut
                .as_ref()
                .expect("effect cut")
                .effect_cut_observation_id,
        );
        assert_eq!(
            derived_kind(&distinct_source_receipts),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::FailedBeforeEffect,
        );

        let proof_digest_mismatch = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::ProvenNoEffect {
                proof_id: "same-proof-id".into(),
                proof_digest: digest("proof-a"),
            },
            CurrentFinalVerificationEffectCutObservationV2::ProvenNoEffect {
                proof_id: "same-proof-id".into(),
                proof_digest: digest("proof-b"),
            },
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::FailedBeforeEffect,
            ),
        );
        assert_eq!(
            derived_kind(&proof_digest_mismatch),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::TerminalEffectContradiction,
            }
        );
    }

    #[test]
    fn core_dump_and_effect_cleanup_contradictions_are_unknown() {
        let core_dump = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Signaled {
                signal: 11,
                core_dumped: true,
            },
            started(),
            published(),
        );
        assert_eq!(
            derived_kind(&core_dump),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::CoreDumpObserved,
            }
        );

        let mut no_domain = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let spine = no_domain.identity_spine.clone();
        no_domain.command_domain_cleanup = Some(command_cleanup(
            &spine,
            26,
            CurrentCommandDomainCleanupObservationV2::NoDomainCreatedBeforeEffect {
                observed_processes: 0,
                platform_proof_digest: digest("no-domain"),
            },
        ));
        assert_eq!(
            derived_kind(&no_domain),
            NonAuthorizingCurrentFinalVerificationDerivedOutcomeKindV2::Unknown {
                reason: CurrentFinalVerificationUnknownReasonV2::CleanupEffectContradiction,
            }
        );
    }

    #[test]
    fn crossed_spine_and_tampered_source_digest_fail_integrity() {
        let mut crossed = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let other = spine_with("other");
        crossed.output_custody = Some(custody(&other, 25, published()));
        assert_eq!(
            derive_non_authorizing_current_final_verification_evidence_v2(&crossed),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::CrossedIdentity {
                    source: "output_custody",
                }
            )
        );

        let mut tampered = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        tampered.terminal.as_mut().expect("terminal").source_digest = digest("forged");
        assert_eq!(
            derive_non_authorizing_current_final_verification_evidence_v2(&tampered),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch {
                    field: "terminal_source.source_digest",
                }
            )
        );
    }

    #[test]
    fn control_identity_and_event_id_cannot_be_reused() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let reservations = lifecycle_reservations(&inputs.identity_spine);
        let error = AuthenticatedCurrentFinalVerificationControlActionV2::new(
            inputs.identity_spine.clone(),
            reservations.control_id.clone(),
            CurrentFinalVerificationControlActionKindV2::Pause,
            reservations.control_id.clone(),
            21,
            reservations.control_observed_event_id.clone(),
            22,
        )
        .expect_err("control and event identities must be distinct");
        assert_eq!(
            error,
            NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                field: "control_action.issued_event_id",
            }
        );
    }

    #[test]
    fn whitespace_only_and_cross_role_frontier_identities_fail_closed() {
        let mut whitespace = spine_with("whitespace").fields;
        whitespace.reached_frontier = match whitespace.reached_frontier {
            CurrentFinalVerificationReachedFrontierV2::Dispatched { mut frontier } => {
                frontier
                    .initialized
                    .capture
                    .launch
                    .lifecycle_reservations
                    .fields
                    .runner_launch_id = " \t".into();
                CurrentFinalVerificationReachedFrontierV2::Dispatched { frontier }
            }
            _ => unreachable!("fixture is dispatched"),
        };
        assert!(matches!(
            CurrentFinalVerificationIdentitySpineV2::new(whitespace),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidIdentifier {
                    field: "identity_spine.frontier.lifecycle_reservations.runner_launch_id",
                }
            )
        ));

        let mut crossed = spine_with("cross-role").fields;
        crossed.reached_frontier = match crossed.reached_frontier {
            CurrentFinalVerificationReachedFrontierV2::Dispatched { mut frontier } => {
                frontier
                    .initialized
                    .capture
                    .launch
                    .lifecycle_reservations
                    .fields
                    .effect_id = frontier
                    .initialized
                    .capture
                    .launch
                    .lifecycle_reservations
                    .fields
                    .runner_launch_id
                    .clone();
                CurrentFinalVerificationReachedFrontierV2::Dispatched { frontier }
            }
            _ => unreachable!("fixture is dispatched"),
        };
        assert!(matches!(
            CurrentFinalVerificationIdentitySpineV2::new(crossed),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "identity_spine.frontier.lifecycle_reservations.identifiers",
                }
            )
        ));
    }

    #[test]
    fn lifecycle_reservations_are_exact_hex_pairwise_and_schema_closed() {
        let spine = spine_with("reservation-shape");
        let original = lifecycle_reservations(&spine).clone();

        let mut uppercase = original.clone();
        uppercase.native_launch_preparation_receipt_id = "A".repeat(64);
        assert!(matches!(
            CurrentFinalVerificationLifecycleReservationSetV2::new(uppercase),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidIdentifier {
                    field: "identity_spine.frontier.lifecycle_reservations.native_launch_preparation_receipt_id",
                }
            )
        ));

        let mut collided = original.clone();
        collided.native_launch_cleanup_receipt_id =
            collided.native_launch_release_receipt_id.clone();
        assert_eq!(
            CurrentFinalVerificationLifecycleReservationSetV2::new(collided),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "identity_spine.frontier.lifecycle_reservations.identifiers",
                }
            )
        );

        for cross_to_launch_commit in [false, true] {
            let mut fields = spine_with(if cross_to_launch_commit {
                "launch-event-cross"
            } else {
                "t0-event-cross"
            })
            .fields;
            let crossed_event_id = if cross_to_launch_commit {
                fields.reached_frontier.launch().committed_event_id.clone()
            } else {
                fields.authority_admitted_event_id.clone()
            };
            let launch = match &mut fields.reached_frontier {
                CurrentFinalVerificationReachedFrontierV2::Dispatched { frontier } => {
                    &mut frontier.initialized.capture.launch
                }
                _ => unreachable!("fixture is dispatched"),
            };
            let mut reservations = launch.lifecycle_reservations.fields.clone();
            reservations.runner_launch_id = crossed_event_id;
            launch.lifecycle_reservations =
                CurrentFinalVerificationLifecycleReservationSetV2::new(reservations)
                    .expect("cross is outside the reservation set");
            assert_eq!(
                CurrentFinalVerificationIdentitySpineV2::new(fields),
                Err(
                    NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                        field: "identity_spine.frontier.all_identity_ids",
                    }
                )
            );
        }

        let set = spine
            .fields
            .reached_frontier
            .launch()
            .lifecycle_reservations
            .clone();
        let mut omitted = serde_json::to_value(&set).expect("reservation JSON");
        omitted["fields"]
            .as_object_mut()
            .expect("reservation fields")
            .remove("native_launch_release_receipt_id");
        assert!(
            serde_json::from_value::<CurrentFinalVerificationLifecycleReservationSetV2>(omitted)
                .is_err()
        );

        let mut unknown = serde_json::to_value(&set).expect("reservation JSON");
        unknown["fields"]
            .as_object_mut()
            .expect("reservation fields")
            .insert(
                "future_unreviewed_id".into(),
                serde_json::json!(core_id("future")),
            );
        assert!(
            serde_json::from_value::<CurrentFinalVerificationLifecycleReservationSetV2>(unknown)
                .is_err()
        );
    }

    #[test]
    fn source_identities_and_backend_must_match_launch_reservations() {
        let spine = spine_with("source-reservations");
        let reservations = lifecycle_reservations(&spine).clone();

        assert_eq!(
            CurrentFinalVerificationTerminalSourceV2::new(
                spine.clone(),
                reservations.terminal_observation_id.clone(),
                core_id("substituted-terminal-event"),
                24,
                CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            ),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "terminal_source.terminal_event_id",
                }
            )
        );

        assert_eq!(
            CurrentCommandDomainCleanupSourceV2::new(
                spine.clone(),
                CurrentCommandDomainBackendV2::LinuxCgroupV2,
                reservations.command_accounting_domain_id.clone(),
                reservations.command_cleanup_observation_id.clone(),
                reservations.command_cleanup_event_id.clone(),
                26,
                clean_command_domain(),
            ),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "command_domain_cleanup.backend",
                }
            )
        );

        let mut direct =
            rewrite_direct_sequence(clean_direct(), 27, lifecycle_reservations(&spine));
        match &mut direct {
            CurrentIndependentDirectChildObservationV2::Reaped { observer_id, .. } => {
                *observer_id = core_id("late-arbitrary-observer");
            }
            _ => unreachable!("clean fixture is reaped"),
        }
        assert_eq!(
            CurrentRunnerCleanupSourceV2::new(
                spine.clone(),
                CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt,
                reservations.runner_accounting_domain_id.clone(),
                reservations.runner_cleanup_proof_id.clone(),
                reservations.runner_cleanup_event_id.clone(),
                29,
                direct,
                rewrite_domain_sequence(clean_domain(), 28, lifecycle_reservations(&spine),),
                None,
            ),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "runner_cleanup.direct_child.observer_id",
                }
            )
        );
    }

    #[test]
    fn derived_closure_and_outcome_retain_reserved_future_identities() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let reservations = lifecycle_reservations(&inputs.identity_spine).clone();
        let NonAuthorizingCurrentFinalVerificationDerivationV2::Derived { closure, outcome } =
            derive_non_authorizing_current_final_verification_evidence_v2(&inputs)
                .expect("complete derivation")
        else {
            panic!("complete inputs derive");
        };
        assert_eq!(
            closure.evidence_closure_id,
            reservations.evidence_closure_id
        );
        assert_eq!(
            closure.reserved_evidence_closure_event_id,
            reservations.evidence_closure_event_id
        );
        assert_eq!(outcome.outcome_id, reservations.outcome_id);
        assert_eq!(
            outcome.reserved_outcome_derived_event_id,
            reservations.outcome_derived_event_id
        );
    }

    #[test]
    fn launch_containment_mapping_is_explicit_and_digest_bound() {
        let spine = spine_with("containment-mapping");
        let launch = spine.fields.reached_frontier.launch();
        assert_eq!(
            launch.containment_backend,
            CurrentFinalVerificationNativeContainmentBackendV2::MacOsDedicatedIdentitySeatbelt
        );
        let json = serde_json::to_value(launch).expect("launch JSON");
        assert_eq!(
            json["containment_backend"],
            "mac_os_dedicated_identity_seatbelt"
        );
        assert!(json.get("target_identity_digest").is_some());
        assert!(json.get("native_policy_digest").is_some());
        assert!(json.get("target_manifest_digest").is_none());
        assert!(json.get("native_containment_policy_digest").is_none());
    }

    #[test]
    fn control_must_follow_the_exact_reached_frontier() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let reservations = lifecycle_reservations(&inputs.identity_spine).clone();
        let error = AuthenticatedCurrentFinalVerificationControlActionV2::new(
            inputs.identity_spine,
            reservations.control_id,
            CurrentFinalVerificationControlActionKindV2::Pause,
            reservations.control_issued_event_id,
            19,
            reservations.control_observed_event_id,
            22,
        )
        .expect_err("a control issued before the reached frontier cannot explain its terminal");
        assert_eq!(
            error,
            NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidEventOrder {
                field: "control_action.event_sequence",
            }
        );
    }

    #[test]
    fn control_identity_cannot_alias_a_later_lifecycle_event() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let reservations = lifecycle_reservations(&inputs.identity_spine);
        let result = AuthenticatedCurrentFinalVerificationControlActionV2::new(
            inputs.identity_spine.clone(),
            reservations.terminal_event_id.clone(),
            CurrentFinalVerificationControlActionKindV2::Cancel,
            reservations.control_issued_event_id.clone(),
            21,
            reservations.control_observed_event_id.clone(),
            22,
        );
        assert_eq!(
            result,
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::ReservationMismatch {
                    field: "control_action.control_id",
                }
            )
        );
    }

    #[test]
    fn unknown_fields_and_omitted_optional_fields_are_rejected() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let mut value = serde_json::to_value(inputs).expect("encode inputs");
        value.as_object_mut().expect("input object").insert(
            "caller_classification".into(),
            serde_json::json!("verified"),
        );
        assert!(
            serde_json::from_value::<NonAuthorizingCurrentFinalVerificationEvidenceInputsV2>(value)
                .is_err()
        );

        let mut omitted = serde_json::to_value(complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        ))
        .expect("encode inputs");
        omitted
            .as_object_mut()
            .expect("input object")
            .remove("runner_cleanup");
        assert!(
            serde_json::from_value::<NonAuthorizingCurrentFinalVerificationEvidenceInputsV2>(
                omitted
            )
            .is_err()
        );

        let mut missing_shutdown_option = serde_json::to_value(complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        ))
        .expect("encode inputs");
        missing_shutdown_option["runner_cleanup"]
            .as_object_mut()
            .expect("runner cleanup object")
            .remove("shutdown_transcript");
        assert!(
            serde_json::from_value::<NonAuthorizingCurrentFinalVerificationEvidenceInputsV2>(
                missing_shutdown_option,
            )
            .is_err()
        );
    }

    #[test]
    fn identifier_and_closed_variant_bounds_fail_closed() {
        let mut fields = spine_with("bounded").fields;
        fields.sprint_id = "x".repeat(MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2 + 1);
        assert_eq!(
            CurrentFinalVerificationIdentitySpineV2::new(fields),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidIdentifier {
                    field: "identity_spine.sprint_id",
                }
            )
        );

        let spine = spine_with("invalid-domain-count");
        let reservations = lifecycle_reservations(&spine).clone();
        let invalid_domain = CurrentIndependentRunnerDomainObservationV2::Empty {
            observer_id: reservations.runner_domain_observer_id.clone(),
            observation_id: reservations.runner_domain_observation_id.clone(),
            observed_event_id: reservations.runner_domain_observed_event_id.clone(),
            observed_members: 1,
            observed_event_sequence: 28,
            evidence_digest: digest("runner-domain-evidence"),
        };
        assert_eq!(
            CurrentRunnerCleanupSourceV2::new(
                spine.clone(),
                spine.fields.reached_frontier.launch().containment_backend,
                reservations.runner_accounting_domain_id,
                reservations.runner_cleanup_proof_id,
                reservations.runner_cleanup_event_id,
                29,
                rewrite_direct_sequence(clean_direct(), 27, lifecycle_reservations(&spine),),
                invalid_domain,
                None,
            ),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::InvalidObservation {
                    field: "runner_cleanup.domain.observed_members",
                }
            )
        );
    }

    #[test]
    fn complete_closure_and_outcome_digests_detect_mutation() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let result = derive_non_authorizing_current_final_verification_evidence_v2(&inputs)
            .expect("derive verified");
        let NonAuthorizingCurrentFinalVerificationDerivationV2::Derived {
            mut closure,
            mut outcome,
        } = result
        else {
            panic!("complete inputs must derive");
        };
        closure.validate_integrity().expect("closure integrity");
        outcome.validate_integrity().expect("outcome integrity");
        closure.terminal_source_digest = digest("different-terminal");
        assert!(matches!(
            closure.validate_integrity(),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch {
                    field: "evidence_closure.closure_digest"
                }
            )
        ));
        outcome.evidence_closure_digest = digest("different-closure");
        assert!(matches!(
            outcome.validate_integrity(),
            Err(
                NonAuthorizingCurrentFinalVerificationEvidenceErrorV2::DigestMismatch {
                    field: "derived_outcome.outcome_digest"
                }
            )
        ));
    }

    #[test]
    fn source_domains_and_complete_spine_are_digest_bound() {
        let inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::Exited { exit_code: 0 },
            started(),
            published(),
        );
        let source_digests = [
            &inputs.terminal.as_ref().expect("terminal").source_digest,
            &inputs.effect_cut.as_ref().expect("effect").source_digest,
            &inputs
                .output_custody
                .as_ref()
                .expect("custody")
                .source_digest,
            &inputs
                .command_domain_cleanup
                .as_ref()
                .expect("command cleanup")
                .source_digest,
            &inputs
                .runner_cleanup
                .as_ref()
                .expect("runner cleanup")
                .source_digest,
        ];
        for (index, digest) in source_digests.iter().enumerate() {
            assert!(!source_digests[..index].contains(digest));
        }
        let json = serde_json::to_string(&inputs.identity_spine).expect("spine JSON");
        for field in [
            "operational_attempt_authority_digest",
            "initialization_request_commitment_digest",
            "initialization_receipt_commitment_digest",
            "v13_embedded_v32_attempt_payload_digest",
            "command_transport_commitment_digest",
            "runner_nonce",
            "launch_preparation_digest",
            "launch_authority_digest",
            "capture_intent_id",
            "capture_intent_digest",
            "effect_idempotency_key",
            "native_launch_preparation_receipt_id",
            "native_launch_release_receipt_id",
            "native_launch_cleanup_receipt_id",
            "target_identity_digest",
            "native_policy_digest",
        ] {
            assert!(json.contains(field), "missing {field}");
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "fixed literal goldens stay together so contract drift is reviewed atomically"
    )]
    fn current_v2_digest_and_canonical_json_goldens_are_fixed() {
        let mut inputs = complete_inputs(
            CurrentFinalVerificationTerminalObservationV2::RunnerCanceled {
                claimed_control_id: "golden-control".into(),
            },
            cut_proven_no_effect(),
            pre_effect_abandoned(
                CurrentFinalVerificationPreEffectAbandonmentReasonV2::CanceledBeforeEffect,
            ),
        );
        inputs.control_resolution = Some(authenticated_resolution(
            &inputs.identity_spine,
            "golden-control",
            CurrentFinalVerificationControlActionKindV2::Cancel,
        ));
        let result = derive_non_authorizing_current_final_verification_evidence_v2(&inputs)
            .expect("derive golden fixture");
        let NonAuthorizingCurrentFinalVerificationDerivationV2::Derived { closure, outcome } =
            result
        else {
            panic!("golden fixture must derive");
        };
        assert_eq!(
            inputs.identity_spine.spine_digest.as_str(),
            "39f5975fe2ff7270df333dac1c28678c28965a3948f428c01dc01b29cc634d38"
        );
        for (observed, expected) in [
            (
                &inputs.terminal.as_ref().expect("terminal").source_digest,
                "3543469a0f337ca3e184a27891f4d9eb75283bc86945f99abb42177cf2ac2718",
            ),
            (
                &inputs.effect_cut.as_ref().expect("effect").source_digest,
                "e26baf65eb586f81ac28c5a36fbe27721c413ed133a8c7804e71928eb0be2fd5",
            ),
            (
                &inputs
                    .output_custody
                    .as_ref()
                    .expect("custody")
                    .source_digest,
                "a9b66c0723d89f1ff4f567e9b19e8a8f634528a7d90911d7ef4d05d3a14e0f32",
            ),
            (
                &inputs
                    .command_domain_cleanup
                    .as_ref()
                    .expect("command")
                    .source_digest,
                "7475547c7740f31860526dae30829c03fb59e6bf769af530386d1fb1cb97ddab",
            ),
            (
                &inputs
                    .runner_cleanup
                    .as_ref()
                    .expect("runner")
                    .source_digest,
                "1d01a496a1f3c3537ff0253f82d78bcd2a3de7cc5b3a0d656b14a9c86ca04186",
            ),
            (
                inputs
                    .control_resolution
                    .as_ref()
                    .expect("control")
                    .source_digest(),
                "1ba83584d7049971f974f715aa40aee685cb114e0888ef3dff6dc569f0e8a5e6",
            ),
        ] {
            assert_eq!(observed.as_str(), expected);
        }
        assert_eq!(
            closure.closure_digest.as_str(),
            "91e30a656face817a6b93db7ef5746617106b30224623e9f4f0167f94b7d8d75"
        );
        assert_eq!(
            outcome.outcome_digest.as_str(),
            "c5e389a828b70ea1caa701da3330c89bc7bd3149440ade8c4f8ab9f1e4a36ef3"
        );
        assert_eq!(
            serde_json::to_string(&outcome.outcome).expect("canonical outcome kind"),
            r#"{"kind":"canceled","control_id":"63c7fe96da015358c2b4ac85b489da3df8fed27da8b5abe0efcd9521b6a56e12"}"#
        );

        let input_json = serde_json::to_vec(&inputs).expect("canonical inputs");
        assert_eq!(
            Digest::sha256(&input_json).as_str(),
            "964761b498709804377f35bfb59e29d6a467cbf3403b34d96e9c0c3dc66e29a3"
        );
        let input_readback: NonAuthorizingCurrentFinalVerificationEvidenceInputsV2 =
            serde_json::from_slice(&input_json).expect("read canonical inputs");
        assert_eq!(input_readback, inputs);
        assert_eq!(
            serde_json::to_vec(&input_readback).expect("re-encode canonical inputs"),
            input_json
        );

        let derivation =
            NonAuthorizingCurrentFinalVerificationDerivationV2::Derived { closure, outcome };
        let derivation_json = serde_json::to_vec(&derivation).expect("canonical derivation");
        assert_eq!(
            Digest::sha256(&derivation_json).as_str(),
            "581b8f159e57045c3fb6df4b7881de8135f3e7848c09f71903634e8e18cf6d0d"
        );
        let derivation_readback: NonAuthorizingCurrentFinalVerificationDerivationV2 =
            serde_json::from_slice(&derivation_json).expect("read canonical derivation");
        assert_eq!(derivation_readback, derivation);
        assert_eq!(
            serde_json::to_vec(&derivation_readback).expect("re-encode canonical derivation"),
            derivation_json
        );

        let mut unknown_nested = serde_json::to_value(&input_readback).expect("encode inputs");
        unknown_nested["terminal"]["observation"]
            .as_object_mut()
            .expect("terminal observation object")
            .insert("caller_before_effect".into(), serde_json::json!(true));
        assert!(
            serde_json::from_value::<NonAuthorizingCurrentFinalVerificationEvidenceInputsV2>(
                unknown_nested,
            )
            .is_err()
        );
    }
