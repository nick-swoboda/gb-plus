    #[test]
    #[allow(clippy::too_many_lines)]
    fn claimed_integration_terminal_is_atomic_retryable_and_claim_bound() {
        let mut fixture = prepare_claimed_integration_terminal_fixture(true);
        let claim_id = fixture
            .authority
            .as_ref()
            .expect("claimed integration authority")
            .claim
            .dispatch_claim_id
            .clone();
        let request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: fixture.candidate.change_set.clone(),
            artifact: fixture.evidence.artifact.clone(),
        };
        match fixture
            .candidate
            .ledger
            .admit_task_attempt_integration_for_dispatch(
                &fixture.admission,
                &fixture.intent,
                &request,
                &fixture.proposal,
            )
            .expect("claimed integration admission exact replay")
        {
            TaskIntegrationDispatchAdmission::Existing { admission, effect } => {
                assert_eq!(admission, fixture.admission);
                assert_eq!(
                    effect
                        .dispatch_claim
                        .as_ref()
                        .map(|claim| claim.dispatch_claim_id.as_str()),
                    Some(claim_id.as_str())
                );
            }
            TaskIntegrationDispatchAdmission::Fresh { .. } => {
                panic!("claimed integration admission cannot remint fresh authority")
            }
        }

        assert!(matches!(
            fixture.candidate.ledger.integrate_task_attempt(
                &fixture.disposition,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                &fixture.transition,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task attempt integration disposition",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.candidate.ledger, "effect_observations"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "task_attempt_dispositions"),
            0
        );

        let mut premature_transition = fixture.transition.clone();
        premature_transition.sequence = fixture
            .candidate
            .ledger
            .next_sequence(&fixture.intent.sprint_id)
            .expect("premature integration transition sequence");
        premature_transition.event_id = "event-claimed-integration-premature".into();
        premature_transition.causation_id =
            Some(fixture.candidate.candidate.transition_event_id.clone());
        let transaction = fixture
            .candidate
            .ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("start premature integration transition");
        let error = insert_agent_event(&transaction, &premature_transition)
            .expect_err("unobserved integration claim must fence Integrated transition");
        assert!(
            error
                .to_string()
                .contains("unobserved task dispatch claim blocks known task phase transition")
        );
        transaction
            .rollback()
            .expect("roll back premature integration transition");

        let authority = fixture
            .authority
            .take()
            .expect("take integration authority");
        let mut crossed_evidence = fixture.evidence.clone();
        crossed_evidence.validation.mode =
            TaskIntegrationValidationMode::RecoveryApplierReconciliation;
        let failure = fixture
            .candidate
            .ledger
            .integrate_claimed_task_attempt(
                authority,
                &fixture.disposition,
                &fixture.observation,
                &fixture.terminal,
                &crossed_evidence,
                &fixture.transition,
            )
            .expect_err("recovery evidence cannot cross the direct claimed boundary");
        assert!(failure.has_retry_authority());
        let (_, retry_authority) = failure.into_parts();
        assert_eq!(
            row_count(&fixture.candidate.ledger, "effect_observations"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "task_attempt_dispositions"),
            0
        );

        assert_eq!(
            fixture
                .candidate
                .ledger
                .integrate_claimed_task_attempt(
                    retry_authority.expect("precommit failure returns exact integration authority"),
                    &fixture.disposition,
                    &fixture.observation,
                    &fixture.terminal,
                    &fixture.evidence,
                    &fixture.transition,
                )
                .expect("commit claimed integration terminal boundary"),
            fixture.disposition
        );
        assert_eq!(
            fixture.terminal.causation_id.as_deref(),
            Some(fixture.proposal.event_id.as_str())
        );
        let effect = fixture
            .candidate
            .ledger
            .load_effect(&fixture.intent.effect_id)
            .expect("load claimed integration effect");
        assert_eq!(effect.observation.as_ref(), Some(&fixture.observation));
        assert_eq!(
            effect
                .dispatch_claim
                .as_ref()
                .map(|claim| claim.dispatch_claim_id.as_str()),
            Some(claim_id.as_str())
        );
        let history = fixture
            .candidate
            .ledger
            .load_task_attempt_history(
                &fixture.intent.sprint_id,
                fixture
                    .intent
                    .task_id
                    .as_deref()
                    .expect("task-scoped effect"),
            )
            .expect("load claimed Integrated history");
        assert_eq!(history.task_state, TaskState::Integrated);
        assert_eq!(history.attempts[0].disposition, Some(fixture.disposition));
        let replay_request = TaskIntegrationRequest {
            contract_version: CONTRACT_VERSION,
            change_set: fixture.candidate.change_set.clone(),
            artifact: fixture.evidence.artifact.clone(),
        };
        match fixture
            .candidate
            .ledger
            .admit_task_attempt_integration_for_dispatch(
                &fixture.admission,
                &fixture.intent,
                &replay_request,
                &fixture.proposal,
            )
            .expect("observed integration admission exact replay")
        {
            TaskIntegrationDispatchAdmission::Existing { admission, effect } => {
                assert_eq!(admission, fixture.admission);
                assert_eq!(effect.observation.as_ref(), Some(&fixture.observation));
            }
            TaskIntegrationDispatchAdmission::Fresh { .. } => {
                panic!("observed integration admission cannot remint fresh authority")
            }
        }
    }

    #[test]
    fn fresh_integration_admission_with_discarded_permit_rejects_claimless_terminals() {
        let mut fixture = prepare_claimed_integration_terminal_fixture(false);
        let evidence_bytes = encode("task integration evidence", &fixture.evidence)
            .expect("encode unclaimed integration evidence");
        assert!(matches!(
            fixture.candidate.ledger.record_effect_observation(
                &fixture.observation,
                &evidence_bytes,
                &fixture.terminal,
            ),
            Err(LedgerError::FinishReceiptRequired {
                kind: EffectKind::IntegrateChangeSet,
                ..
            })
        ));
        assert!(matches!(
            fixture
                .candidate
                .ledger
                .record_task_integration_effect_observation(
                    &fixture.observation,
                    &fixture.terminal,
                    &fixture.evidence,
                ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task integration effect observation",
                ..
            })
        ));
        assert!(matches!(
            fixture.candidate.ledger.integrate_task_attempt(
                &fixture.disposition,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                &fixture.transition,
            ),
            Err(LedgerError::ReferenceMismatch {
                entity: "task attempt integration disposition",
                ..
            })
        ));
        assert_eq!(
            row_count(&fixture.candidate.ledger, "effect_observations"),
            0
        );
        assert_eq!(
            row_count(&fixture.candidate.ledger, "task_attempt_dispositions"),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn claimed_integration_terminal_postcommit_uncertainty_has_no_retry_custody() {
        let mut fixture = prepare_claimed_integration_terminal_fixture(true);
        let hardlink = fixture
            .candidate
            .database
            .directory
            .join("claimed-integration-terminal-postcommit-hardlink.sqlite3");
        fs::hard_link(&fixture.candidate.database.path, &hardlink)
            .expect("inject claimed integration post-commit hardening fault");
        let failure = fixture
            .candidate
            .ledger
            .integrate_claimed_task_attempt(
                fixture
                    .authority
                    .take()
                    .expect("take integration authority"),
                &fixture.disposition,
                &fixture.observation,
                &fixture.terminal,
                &fixture.evidence,
                &fixture.transition,
            )
            .expect_err("post-commit integration uncertainty is reconciliation-only");
        fs::remove_file(&hardlink).expect("remove claimed integration hardening fault");
        assert!(matches!(
            failure.error(),
            LedgerError::PostCommitStateUncertain {
                operation: "claimed task attempt integration disposition",
                recovery_id,
                ..
            } if recovery_id == &fixture.intent.effect_id
        ));
        assert!(!failure.has_retry_authority());
        assert!(failure.into_parts().1.is_none());
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_task_attempt_disposition(&fixture.disposition.metadata().disposition_id,)
                .expect("read back committed integration after hardening uncertainty"),
            fixture.disposition
        );
        assert_eq!(
            fixture
                .candidate
                .ledger
                .load_task_integration_evidence(&fixture.evidence.receipt.receipt_id)
                .expect("read back integration evidence after hardening uncertainty"),
            fixture.evidence
        );
    }

    fn expected_v15_integrated_history(
        fixture: &V15CandidateFixture,
        disposition: &TaskAttemptDisposition,
    ) -> TaskAttemptHistory {
        TaskAttemptHistory {
            contract_version: CONTRACT_VERSION,
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: fixture.attempt.worker_lease.task_id.clone(),
            task_state: TaskState::Integrated,
            sprint_state: SprintState::Running,
            attempts: vec![TaskAttemptHistoryEntry {
                attempt: fixture.attempt.clone(),
                running_boundary: Some(fixture.running.clone()),
                verification_boundary: Some(fixture.verification.clone()),
                formal_checks: fixture.formal_checks.clone(),
                candidate_boundary: Some(fixture.candidate.clone()),
                disposition: Some(disposition.clone()),
                legacy_classification: None,
                lease_state: TaskAttemptLeaseState::Active,
            }],
            budget_classification: TaskAttemptBudgetClassification::WithinBudget,
            unknown_terminalization_pending: None,
        }
    }

    #[test]
    fn v15_automated_formal_path_integrates_and_replays_exactly() {
        let mut fixture = prepare_v15_candidate_fixture(true);
        assert_eq!(fixture.candidate.formal_check_ids, ["formal-check-v15"]);
        assert_eq!(
            fixture.candidate.verification_receipt_ids,
            ["receipt-v15-formal"]
        );
        let (admission, evidence, disposition) =
            integrate_v15_candidate(&mut fixture, "automated", false);
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_integration_admission(&admission.admission_id)
                .expect("load exact integration admission"),
            admission
        );
        assert_eq!(
            fixture
                .ledger
                .load_task_integration_evidence(&evidence.receipt.receipt_id)
                .expect("load exact integration evidence"),
            evidence
        );
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_disposition(&disposition.metadata().disposition_id)
                .expect("load exact Integrated disposition"),
            disposition
        );
        let expected_history = expected_v15_integrated_history(&fixture, &disposition);
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_history(&fixture.spec.sprint_id, "task-1")
                .expect("load exact automated Integrated history"),
            expected_history
        );
        let not_done = fixture
            .ledger
            .assess_task_done(&fixture.spec.sprint_id, "task-1")
            .expect("assess integrated attempt before cleanup");
        assert!(!not_done.is_done());
        assert_eq!(not_done.proof, None);
        for requirement in [
            TaskDoneRequirement::EveryTaskEffectTerminalNonUnknown,
            TaskDoneRequirement::RunnerDomainCleanupProven,
            TaskDoneRequirement::CommandDomainCleanupProven,
            TaskDoneRequirement::OriginatingWorkerLeaseReleased,
            TaskDoneRequirement::NoActiveTaskLeases,
        ] {
            assert!(not_done.unmet_requirements.contains(&requirement));
        }
        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reader = EventLedger::open_read_only(&database_path)
            .expect("reopen automated v15 history read-only");
        assert_eq!(
            reader
                .load_task_attempt_history("sprint-1", "task-1")
                .expect("reload exact automated Integrated history"),
            expected_history
        );
        drop(reader);

        let corrupted =
            EventLedger::open(&database_path).expect("open integrated corruption ledger");
        corrupted
            .connection
            .execute_batch(
                "DROP TRIGGER task_attempt_integrated_result_coverage_no_delete;
                 DELETE FROM task_attempt_integrated_result_coverage;",
            )
            .expect("remove integrated coverage through corruption bypass");
        assert!(matches!(
            corrupted.load_task_attempt_disposition(&disposition.metadata().disposition_id),
            Err(LedgerError::Corrupt {
                entity: "task attempt integrated-result coverage",
                ..
            })
        ));
    }

    #[test]
    fn v15_human_only_empty_formal_set_rejects_bypasses_and_reopens_read_only() {
        let mut fixture = prepare_v15_candidate_fixture(false);
        assert!(fixture.candidate.formal_check_ids.is_empty());
        assert!(fixture.candidate.verification_receipt_ids.is_empty());
        let (admission, evidence, disposition) =
            integrate_v15_candidate(&mut fixture, "human", true);
        let expected_history = expected_v15_integrated_history(&fixture, &disposition);
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_history(&fixture.spec.sprint_id, "task-1")
                .expect("load exact human-only Integrated history"),
            expected_history
        );
        let candidate_id = fixture.candidate.boundary_id.clone();
        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reader = EventLedger::open_read_only(&database_path).expect("reopen v15 read-only");
        assert_eq!(
            reader
                .load_task_attempt_candidate_boundary(&candidate_id)
                .expect("reload empty candidate boundary")
                .formal_check_ids,
            Vec::<String>::new()
        );
        assert_eq!(
            reader
                .load_task_attempt_integration_admission(&admission.admission_id)
                .expect("reload integration admission"),
            admission
        );
        assert_eq!(
            reader
                .load_task_integration_evidence(&evidence.receipt.receipt_id)
                .expect("reload integration evidence"),
            evidence
        );
        assert_eq!(
            reader
                .load_task_attempt_disposition(&disposition.metadata().disposition_id)
                .expect("reload Integrated disposition"),
            disposition
        );
        assert_eq!(
            reader
                .load_task_attempt_history("sprint-1", "task-1")
                .expect("reload exact human-only Integrated history"),
            expected_history
        );
    }

    fn complete_v15_retry_candidate() -> (V15CandidateFixture, TaskAttemptDisposition) {
        let mut fixture = prepare_v15_candidate_fixture_with_retry();
        let (_, _, winning_disposition) =
            integrate_v15_candidate(&mut fixture, "retry-winner", false);
        let command = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &fixture.launch.launch_id,
                &fixture.launch.session_id,
            )
            .expect("load retry-winner command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find retry-winner formal command");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &command,
            "command-cleanup-v15-retry-winner",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        let cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-v15-retry-winner",
            1_450,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &winning_disposition.metadata().disposition_id,
                |_| Ok(cleanup),
            )
            .expect("cleanup and release retry winner");
        (fixture, winning_disposition)
    }

    #[test]
    fn task_done_universally_closes_retry_history_and_prior_effects() {
        let (fixture, winning_disposition) = complete_v15_retry_candidate();
        let prior_attempt = fixture
            .prior_attempt
            .as_ref()
            .expect("retry fixture prior attempt");
        let prior_disposition = fixture
            .prior_disposition
            .as_ref()
            .expect("retry fixture prior disposition");
        let prior_launch = fixture
            .prior_launch
            .as_ref()
            .expect("retry fixture prior launch");

        let assessment = fixture
            .ledger
            .assess_task_done(&fixture.spec.sprint_id, "task-1")
            .expect("assess universally closed retry history");
        assert!(assessment.is_done());
        let proof = assessment.proof.expect("retry TaskDone proof");
        assert_eq!(proof.attempt.attempt_ordinal, 2);
        assert_eq!(
            proof.integration_disposition_id,
            winning_disposition.metadata().disposition_id
        );
        assert_eq!(proof.non_winning_attempts.len(), 1);
        let prior = &proof.non_winning_attempts[0];
        assert_eq!(&prior.attempt, prior_attempt);
        assert_eq!(&prior.disposition, prior_disposition);
        assert_eq!(
            prior
                .runner_cleanup
                .as_ref()
                .expect("prior runner cleanup")
                .receipt
                .launch_id,
            prior_launch.launch_id
        );
        assert!(
            prior
                .command_domain_cleanup
                .as_ref()
                .expect("prior empty command-domain closure")
                .entries
                .is_empty()
        );
        assert!(matches!(
            prior.lease_release,
            TaskAttemptLeaseState::Released { .. }
        ));
        assert!(prior.terminal_effects.iter().any(|effect| {
            effect.effect_id == "effect-v15-prior-retry-provider"
                && effect.observation_id == "observation-v15-prior-retry-provider"
        }));
        assert!(
            proof
                .terminal_effects
                .iter()
                .any(|effect| { effect.effect_id == "effect-v15-prior-retry-provider" })
        );

        fixture
            .ledger
            .connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER effect_evidence_payloads_no_delete;
                 DROP TRIGGER effect_observations_no_delete;
                 DELETE FROM effect_evidence_payloads
                  WHERE effect_id = 'effect-v15-prior-retry-provider';
                 DELETE FROM effect_observations
                  WHERE effect_id = 'effect-v15-prior-retry-provider';",
            )
            .expect("remove prior terminal observation through corruption bypass");
        let incomplete = fixture
            .ledger
            .assess_task_done(&fixture.spec.sprint_id, "task-1")
            .expect("missing prior result is incomplete rather than done");
        assert!(!incomplete.is_done());
        assert_eq!(incomplete.proof, None);
        for requirement in [
            TaskDoneRequirement::EveryTaskEffectTerminalNonUnknown,
            TaskDoneRequirement::EveryNonWinningAttemptDurablyClosed,
            TaskDoneRequirement::NoTaskReplayOrDispatchAuthority,
        ] {
            assert!(incomplete.unmet_requirements.contains(&requirement));
        }
    }

    #[test]
    fn task_done_rejects_effect_session_crossed_between_retry_attempts() {
        let (fixture, _) = complete_v15_retry_candidate();
        let prior_launch = fixture
            .prior_launch
            .as_ref()
            .expect("retry fixture prior launch");
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER effect_session_bindings_no_update;")
            .expect("disable binding immutability for crossed-attempt attack");
        let crossed = fixture.ledger.connection.execute(
            "UPDATE effect_session_bindings
                 SET launch_id = ?1, session_id = ?2
                 WHERE effect_id = 'effect-v15-formal'",
            params![prior_launch.launch_id, prior_launch.session_id],
        );
        if let Err(error) = crossed {
            assert!(
                error.to_string().contains("FOREIGN KEY constraint failed"),
                "unexpected schema-level crossed-attempt rejection: {error:?}"
            );
        } else {
            let error = fixture
                .ledger
                .assess_task_done("sprint-1", "task-1")
                .expect_err("cross-attempt effect session must not authorize TaskDone");
            assert!(
                matches!(
                    &error,
                    LedgerError::Corrupt { .. } | LedgerError::ReferenceMismatch { .. }
                ),
                "unexpected crossed-attempt rejection: {error:?}"
            );
        }
    }

    #[test]
    fn v16_explicit_empty_change_set_can_become_task_done() {
        let mut fixture = prepare_v15_candidate_fixture_with_result(true, true);
        assert!(fixture.change_set.operations.is_empty());
        assert_eq!(
            fixture.change_set.base_snapshot,
            fixture.change_set.result_snapshot
        );
        let (_, evidence, disposition) =
            integrate_v15_candidate(&mut fixture, "verified-noop", false);
        assert_eq!(
            evidence.receipt.input_snapshot,
            evidence.receipt.result_snapshot
        );

        let binding = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &fixture.launch.launch_id,
                &fixture.launch.session_id,
            )
            .expect("load verified-no-op command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find verified-no-op formal command");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &binding,
            "command-cleanup-v16-verified-noop",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );

        let cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-v16-verified-noop",
            1_450,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |claim| {
                    assert_eq!(claim.next_event_sequence(), cleanup.event.sequence);
                    Ok(cleanup)
                },
            )
            .expect("cleanup and release verified-no-op attempt");

        let assessment = fixture
            .ledger
            .assess_task_done(&fixture.spec.sprint_id, "task-1")
            .expect("assess explicit verified no-op");
        assert!(assessment.is_done());
        let proof = assessment.proof.expect("verified-no-op TaskDone proof");
        assert!(proof.change_set.operations.is_empty());
        assert_eq!(
            proof.change_set.base_snapshot,
            proof.change_set.result_snapshot
        );

        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reader = EventLedger::open_read_only(&database_path)
            .expect("reopen verified-no-op ledger read-only");
        assert!(
            reader
                .assess_task_done("sprint-1", "task-1")
                .expect("recompute verified-no-op TaskDone")
                .is_done()
        );
    }

    #[test]
    fn task_done_rejects_missing_binding_for_terminal_non_command_effect() {
        let mut fixture = prepare_v15_candidate_fixture_with_options(true, true, true, false);
        let (_, _, disposition) =
            integrate_v15_candidate(&mut fixture, "binding-corruption", false);

        let command = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &fixture.launch.launch_id,
                &fixture.launch.session_id,
            )
            .expect("load command binding before corruption")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find formal command binding");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &command,
            "command-cleanup-task-done-binding-corruption",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );

        let cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-task-done-binding-corruption",
            1_450,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |_| Ok(cleanup),
            )
            .expect("cleanup attempt before binding corruption");
        assert!(
            fixture
                .ledger
                .assess_task_done(&fixture.spec.sprint_id, "task-1")
                .expect("assess complete bound task")
                .is_done()
        );

        fixture
            .ledger
            .connection
            .execute_batch(
                "DROP TRIGGER effect_session_bindings_no_delete;
                 DELETE FROM effect_session_bindings
                  WHERE effect_id = 'effect-v15-bound-read';",
            )
            .expect("simulate retained-ledger binding corruption");
        assert!(matches!(
            fixture
                .ledger
                .assess_task_done(&fixture.spec.sprint_id, "task-1"),
            Err(LedgerError::ArtifactNotFound {
                entity: "effect session binding",
                ref id,
            }) if id == "effect-v15-bound-read"
        ));
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v16_verified_no_op_completion() -> (
        V15CandidateFixture,
        FinalReport,
        CompletionReceipt,
        AgentEvent,
    ) {
        prepare_v16_verified_no_op_completion_with_retry(false)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v16_verified_no_op_completion_with_retry(
        include_retry: bool,
    ) -> (
        V15CandidateFixture,
        FinalReport,
        CompletionReceipt,
        AgentEvent,
    ) {
        let fixture = prepare_v15_candidate_fixture_with_graph_options_at_generation(
            true,
            true,
            false,
            include_retry,
            CandidateTaskRequirement::Required,
            None,
            true,
        );
        prepare_v16_verified_no_op_completion_from_candidate(fixture)
    }

    #[allow(clippy::too_many_lines)]
    fn prepare_v16_verified_no_op_completion_from_candidate(
        mut fixture: V15CandidateFixture,
    ) -> (
        V15CandidateFixture,
        FinalReport,
        CompletionReceipt,
        AgentEvent,
    ) {
        let include_retry = fixture.prior_attempt.is_some();
        let integration_suffix = if include_retry {
            "verified-noop-retry-completion"
        } else {
            "verified-noop-completion"
        };
        let (_, integration, disposition) =
            integrate_v15_candidate(&mut fixture, integration_suffix, false);

        let task_command = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &fixture.launch.launch_id,
                &fixture.launch.session_id,
            )
            .expect("load no-op task command binding")
            .into_iter()
            .find(|binding| binding.effect_id == "effect-v15-formal")
            .expect("find no-op task command binding");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &task_command,
            "command-cleanup-v16-noop-completion-task",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_400,
        );
        let task_cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "cleanup-v16-noop-completion-task",
            1_450,
        );
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |_| Ok(task_cleanup),
            )
            .expect("cleanup no-op task attempt");
        assert!(
            fixture
                .ledger
                .assess_task_done(&fixture.spec.sprint_id, "task-1")
                .expect("compute no-op TaskDone before sprint finish")
                .is_done()
        );

        let final_policy = compiled_test_policy("v16-noop-final-policy");
        let final_launch = runner_launch(
            "launch-v16-noop-final",
            "session-v16-noop-final",
            RunnerSessionPurpose::FinalVerifier,
            None,
            &final_policy,
            1_500,
        );
        admit_test_runner_launch(&mut fixture.ledger, &final_launch, &final_policy);
        fixture
            .ledger
            .register_runner_session(&runner_session(&final_launch, 1_510), &final_policy)
            .expect("register no-op final verifier");
        let command = match &fixture.spec.acceptance_criteria[0].kind {
            AcceptanceKind::Automated(command) => command.clone(),
            AcceptanceKind::HumanJudgment => unreachable!("automated no-op fixture"),
        };
        let final_verification = VerificationReceipt {
            receipt_id: "verify-final-v16-noop".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: None,
            snapshot_id: fixture.spec.base_snapshot.clone(),
            command,
            policy_hash: final_policy.contract().policy_hash.clone(),
            exit_status: Some(0),
            termination: Some(CommandTerminationV1::Exited { code: 0 }),
            output_digest: digest('0'),
            duration_ms: 10,
            finished_at_unix_ms: 1_540,
        };
        let final_evidence = persist_verification_evidence(
            &mut fixture.ledger,
            &final_launch,
            final_verification,
            b"v16 no-op final verification passed".to_vec(),
            1_520,
        );
        let final_command = fixture
            .ledger
            .load_command_domain_effect_bindings(
                &fixture.spec.sprint_id,
                &final_launch.launch_id,
                &final_launch.session_id,
            )
            .expect("load no-op final command binding")
            .into_iter()
            .find(|binding| binding.effect_id == final_evidence.effect_id)
            .expect("find no-op final command binding");
        ensure_test_command_domain_cleanup(
            &mut fixture.ledger,
            &final_command,
            "command-cleanup-v16-noop-completion-final",
            CommandDomainBackend::LinuxCgroupV2,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
            1_550,
        );
        persist_cleanup_evidence(
            &mut fixture.ledger,
            &final_launch,
            &fixture.spec.base_snapshot,
            "cleanup-v16-noop-completion-final",
            WorkerCleanupBackend::LinuxCgroupV2,
            1_560,
            1_580,
        );

        let acceptance = AcceptanceReceipt {
            receipt_id: "acceptance-v16-noop".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            criterion_id: "tests".into(),
            snapshot_id: fixture.spec.base_snapshot.clone(),
            evidence: AcceptanceEvidence::Automated {
                verification_receipt_id: final_evidence.verification.receipt_id.clone(),
            },
            accepted_at_unix_ms: 1_600,
        };
        fixture
            .ledger
            .persist_acceptance_receipt(&acceptance)
            .expect("persist no-op acceptance");
        let no_op = VerifiedNoOpReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "verified-noop-v16-completion".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            final_verification_receipt_id: final_evidence.verification.receipt_id.clone(),
            base_snapshot: fixture.spec.base_snapshot.clone(),
            live_manifest_digest: fixture.spec.base_snapshot.clone(),
            grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.spec.workspace_grant.policy_version,
            observed_at_unix_ms: 1_620,
        };
        fixture
            .ledger
            .persist_verified_no_op_receipt(&no_op)
            .expect("persist sprint verified-no-op proof");

        let body = "The sprint produced an explicit verified no-op.".to_owned();
        let report = FinalReport {
            report_id: "report-v16-noop".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            final_snapshot: fixture.spec.base_snapshot.clone(),
            content_digest: FinalReport::digest_body(&body),
            body,
            created_at_unix_ms: 1_700,
        };
        let mut worker_cleanup_receipt_ids = vec![
            "cleanup-v16-noop-completion-final".into(),
            "cleanup-v16-noop-completion-task".into(),
        ];
        if include_retry {
            worker_cleanup_receipt_ids.push("excluded-cleanup-receipt-v15-prior-retry".into());
        }
        let task_integration_receipt_ids = if fixture.candidate_required {
            vec![integration.receipt.receipt_id]
        } else {
            Vec::new()
        };
        let verification_receipts = if fixture.candidate_required {
            vec![
                "receipt-v15-formal".into(),
                final_evidence.verification.receipt_id.clone(),
            ]
        } else {
            vec![final_evidence.verification.receipt_id.clone()]
        };
        let receipt = CompletionReceipt {
            contract_version: CONTRACT_VERSION,
            receipt_id: "completion-v16-noop".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
            policy_version: fixture.spec.workspace_grant.policy_version,
            final_snapshot: fixture.spec.base_snapshot.clone(),
            final_verification_receipt_id: final_evidence.verification.receipt_id.clone(),
            application: CompletionApplication::VerifiedNoOp {
                verified_no_op_receipt_id: no_op.receipt_id,
            },
            worker_cleanup_receipt_ids,
            satisfied_criterion_ids: vec!["tests".into()],
            criterion_evidence_receipt_ids: vec![acceptance.receipt_id],
            task_integration_receipt_ids,
            verification_receipts,
            provider_backend: fixture.spec.provider.backend_id.clone(),
            provider_model: fixture.spec.provider.model_id.clone(),
            final_report_id: report.report_id.clone(),
            completed_at_unix_ms: 1_800,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: fixture
                .ledger
                .next_sequence(&fixture.spec.sprint_id)
                .expect("no-op completion event sequence"),
            event_id: "event-v16-noop-completed".into(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: None,
            worker_id: None,
            causation_id: None,
            correlation_id: "v16-noop-completion".into(),
            policy_hash: None,
            occurred_at_unix_ms: receipt.completed_at_unix_ms,
            payload: AgentEventKind::CompletionRecorded(receipt.receipt_id.clone()),
        };
        (fixture, report, receipt, event)
    }

    fn prepare_v18_completion_with_unattempted_optional() -> (
        V15CandidateFixture,
        FinalReport,
        CompletionReceipt,
        AgentEvent,
    ) {
        let fixture = prepare_v15_candidate_fixture_with_graph_options_at_generation(
            true,
            true,
            false,
            false,
            CandidateTaskRequirement::Required,
            Some(optional_task("task-optional", digest('b'))),
            true,
        );
        prepare_v16_verified_no_op_completion_from_candidate(fixture)
    }

    fn acquire_optional_no_launch_attempt(
        ledger: &mut EventLedger,
        lease_epoch: u64,
        suffix: &str,
        acquired_at_unix_ms: u64,
        ready_causation_id: Option<&str>,
    ) -> TaskAttempt {
        let causation_id = if let Some(causation_id) = ready_causation_id {
            causation_id.to_owned()
        } else {
            let ready = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger
                    .next_sequence("sprint-1")
                    .expect("optional Ready sequence"),
                event_id: format!("event-optional-{suffix}-ready"),
                sprint_id: "sprint-1".into(),
                task_id: Some("task-optional".into()),
                worker_id: None,
                causation_id: None,
                correlation_id: format!("optional-{suffix}"),
                policy_hash: None,
                occurred_at_unix_ms: acquired_at_unix_ms - 1,
                payload: AgentEventKind::TaskStateChanged {
                    from: "Planned".into(),
                    to: "Ready".into(),
                },
            };
            ledger.append_event(&ready).expect("enter optional Ready");
            ready.event_id
        };
        let lease = WorkerLease::new(
            "sprint-1".into(),
            lease_epoch,
            "task-optional".into(),
            format!("worker-optional-{suffix}"),
            vec![PathScope::Workspace],
            acquired_at_unix_ms,
        )
        .expect("construct optional no-launch lease");
        let acquisition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence("sprint-1")
                .expect("optional acquisition sequence"),
            event_id: format!("event-optional-{suffix}-acquired"),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-optional".into()),
            worker_id: Some(lease.worker_id.clone()),
            causation_id: Some(causation_id),
            correlation_id: format!("optional-{suffix}"),
            policy_hash: None,
            occurred_at_unix_ms: acquired_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Ready".into(),
                to: "Leased".into(),
            },
        };
        ledger
            .acquire_task_attempt(&lease, &acquisition)
            .expect("acquire optional no-launch attempt")
    }

    fn close_optional_no_launch_attempt(
        ledger: &mut EventLedger,
        attempt: &TaskAttempt,
        suffix: &str,
        to_state: TaskState,
        disposed_at_unix_ms: u64,
    ) -> TaskAttemptDisposition {
        let evidence = crate::TaskAttemptEvidence::new(
            format!("evidence-optional-{suffix}"),
            crate::TaskAttemptEvidenceKind::NeverLaunched,
            format!("no launch authority for optional attempt {suffix}").into_bytes(),
        )
        .expect("construct optional no-launch evidence");
        let release = WorkerLeaseNeverLaunchedRelease {
            contract_version: CONTRACT_VERSION,
            release_id: format!("release-optional-{suffix}"),
            attempt: attempt.clone(),
            absence_evidence: evidence,
            released_at_unix_ms: disposed_at_unix_ms,
        };
        let metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: format!("disposition-optional-{suffix}"),
            attempt: attempt.clone(),
            from_state: TaskState::Leased,
            state_transition_event_id: format!("event-optional-{suffix}-disposed"),
            disposed_at_unix_ms,
        };
        let event = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: ledger
                .next_sequence("sprint-1")
                .expect("optional disposition sequence"),
            event_id: metadata.state_transition_event_id.clone(),
            sprint_id: "sprint-1".into(),
            task_id: Some("task-optional".into()),
            worker_id: Some(attempt.worker_lease.worker_id.clone()),
            causation_id: Some(attempt.opening_event_id.clone()),
            correlation_id: format!("optional-{suffix}"),
            policy_hash: None,
            occurred_at_unix_ms: disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Leased".into(),
                to: format!("{to_state:?}"),
            },
        };
        ledger
            .close_never_launched_task_attempt(&release, &metadata, &event)
            .expect("close optional no-launch attempt")
    }

    fn refresh_completion_event_sequence(ledger: &EventLedger, event: &mut AgentEvent) {
        event.sequence = ledger
            .next_sequence(&event.sprint_id)
            .expect("refresh completion event sequence");
    }

    fn close_optional_known_cleanup_attempt(
        fixture: &mut V15CandidateFixture,
        kind: V15KnownCleanupKind,
    ) -> (TaskAttemptDisposition, String) {
        let suffix = kind.suffix();
        let policy = compiled_shadow_test_policy(&format!("optional-{suffix}-policy"));
        let lease = WorkerLease::new(
            fixture.spec.sprint_id.clone(),
            2,
            "task-optional".into(),
            format!("worker-optional-{suffix}"),
            vec![PathScope::Workspace],
            1_460,
        )
        .expect("construct optional terminal lease");
        let mut launch = runner_launch(
            &format!("launch-optional-{suffix}"),
            &format!("session-optional-{suffix}"),
            RunnerSessionPurpose::TaskWorker,
            Some(&lease.worker_id),
            &policy,
            1_462,
        );
        launch.worker_lease = Some(lease);
        admit_test_runner_launch(&mut fixture.ledger, &launch, &policy);
        fixture
            .ledger
            .register_runner_session(&runner_session(&launch, 1_463), &policy)
            .expect("register optional terminal runner");
        let running = enter_test_task_attempt_running(&mut fixture.ledger, &launch, 1_464);
        let outcome = v15_known_cleanup_outcome(kind, &launch);
        fixture
            .ledger
            .record_task_attempt_cleanup_outcome_authority(&running.attempt, &outcome, 1_470)
            .expect("record optional terminal outcome authority");
        let cleanup_receipt_id = format!("cleanup-optional-{suffix}");
        let terminal =
            cleanup_terminal_record(&fixture.ledger, &launch, &cleanup_receipt_id, 1_480);
        let metadata = TaskAttemptDispositionMetadata {
            contract_version: CONTRACT_VERSION,
            disposition_id: format!("disposition-optional-{suffix}"),
            attempt: running.attempt.clone(),
            from_state: TaskState::Running,
            state_transition_event_id: format!("event-optional-{suffix}-disposed"),
            disposed_at_unix_ms: 1_490,
        };
        let transition = AgentEvent {
            contract_version: CONTRACT_VERSION,
            sequence: terminal.event.sequence + 1,
            event_id: metadata.state_transition_event_id.clone(),
            sprint_id: fixture.spec.sprint_id.clone(),
            task_id: Some("task-optional".into()),
            worker_id: Some(running.attempt.worker_lease.worker_id.clone()),
            causation_id: Some(running.transition_event_id),
            correlation_id: format!("optional-{suffix}"),
            policy_hash: Some(launch.policy_hash.clone()),
            occurred_at_unix_ms: metadata.disposed_at_unix_ms,
            payload: AgentEventKind::TaskStateChanged {
                from: "Running".into(),
                to: format!("{:?}", kind.resulting_state()),
            },
        };
        let disposition = fixture
            .ledger
            .with_task_attempt_cleanup_disposition_exclusion(
                &metadata,
                &outcome,
                &format!("release-optional-{suffix}"),
                &transition,
                |_| Ok(terminal),
            )
            .expect("close optional terminal outcome");
        (disposition, cleanup_receipt_id)
    }

    #[test]
    fn v18_completion_ignores_unattempted_optional_task() {
        let (mut fixture, report, receipt, event) =
            prepare_v18_completion_with_unattempted_optional();
        let optional = fixture
            .ledger
            .load_task_attempt_history("sprint-1", "task-optional")
            .expect("load unattempted optional history");
        assert!(optional.attempts.is_empty());
        assert_eq!(optional.task_state, TaskState::Planned);

        let completed = record_pre_v24_successful_completion_for_test(
            &mut fixture.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("unattempted optional task must not block completion");
        assert_eq!(completed.receipt, receipt);
    }

    #[test]
    fn v18_optional_integrated_no_op_completes_outside_required_receipt_set() {
        let fixture = prepare_v15_candidate_fixture_with_graph_options_at_generation(
            true,
            true,
            false,
            false,
            CandidateTaskRequirement::Optional,
            None,
            true,
        );
        let (mut fixture, report, receipt, event) =
            prepare_v16_verified_no_op_completion_from_candidate(fixture);
        assert!(receipt.task_integration_receipt_ids.is_empty());
        assert_eq!(
            receipt.verification_receipts,
            vec![receipt.final_verification_receipt_id.clone()]
        );

        let completed = record_pre_v24_successful_completion_for_test(
            &mut fixture.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("optional integrated no-op may remain outside required links");
        assert!(matches!(
            completed.receipt.application,
            CompletionApplication::VerifiedNoOp { .. }
        ));
    }

    #[test]
    fn v18_attempted_optional_attempts_exhausted_completes_after_release() {
        let (mut fixture, report, receipt, mut event) =
            prepare_v18_completion_with_unattempted_optional();
        let first =
            acquire_optional_no_launch_attempt(&mut fixture.ledger, 2, "retry", 1_630, None);
        let retry = close_optional_no_launch_attempt(
            &mut fixture.ledger,
            &first,
            "retry",
            TaskState::Ready,
            1_640,
        );
        assert!(matches!(retry, TaskAttemptDisposition::Retryable(_)));
        let retry_event = retry.metadata().state_transition_event_id.clone();
        let second = acquire_optional_no_launch_attempt(
            &mut fixture.ledger,
            3,
            "exhausted",
            1_650,
            Some(&retry_event),
        );
        let exhausted = close_optional_no_launch_attempt(
            &mut fixture.ledger,
            &second,
            "exhausted",
            TaskState::Failed,
            1_660,
        );
        assert!(matches!(
            exhausted,
            TaskAttemptDisposition::AttemptsExhausted(_)
        ));
        refresh_completion_event_sequence(&fixture.ledger, &mut event);

        record_pre_v24_successful_completion_for_test(
            &mut fixture.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("released optional AttemptsExhausted history may complete");
    }

    #[test]
    fn v18_attempted_optional_known_terminal_matrix_completes_after_cleanup_release() {
        for kind in [
            V15KnownCleanupKind::PermanentFailure,
            V15KnownCleanupKind::Blocked,
            V15KnownCleanupKind::Canceled,
        ] {
            let (mut fixture, report, mut receipt, mut event) =
                prepare_v18_completion_with_unattempted_optional();
            let (disposition, cleanup_receipt_id) =
                close_optional_known_cleanup_attempt(&mut fixture, kind);
            assert!(kind.matches(&disposition));
            receipt.worker_cleanup_receipt_ids.push(cleanup_receipt_id);
            receipt.worker_cleanup_receipt_ids.sort();
            refresh_completion_event_sequence(&fixture.ledger, &mut event);

            record_pre_v24_successful_completion_for_test(
                &mut fixture.ledger,
                &report,
                &receipt,
                &event,
            )
            .unwrap_or_else(|error| {
                panic!("safely closed optional {kind:?} must complete: {error:?}")
            });
        }
    }

    #[test]
    fn v18_attempted_optional_retryable_ready_blocks_completion() {
        let (mut fixture, report, receipt, mut event) =
            prepare_v18_completion_with_unattempted_optional();
        let attempt = acquire_optional_no_launch_attempt(
            &mut fixture.ledger,
            2,
            "retryable-blocked",
            1_630,
            None,
        );
        let retry = close_optional_no_launch_attempt(
            &mut fixture.ledger,
            &attempt,
            "retryable-blocked",
            TaskState::Ready,
            1_640,
        );
        assert!(matches!(retry, TaskAttemptDisposition::Retryable(_)));
        refresh_completion_event_sequence(&fixture.ledger, &mut event);

        let error = fixture
            .ledger
            .record_successful_completion(&report, &receipt, &event)
            .expect_err("optional Retryable/Ready is unfinished authority");
        assert!(matches!(
            error,
            LedgerError::ReferenceMismatch {
                entity: "attempted optional task closure",
                ..
            }
        ));
        assert_no_completion_writes(&fixture.ledger);
    }

    #[test]
    fn v16_explicit_empty_task_result_completes_as_verified_no_op_and_reopens() {
        let (mut fixture, report, receipt, event) = prepare_v16_verified_no_op_completion();
        let expected = record_pre_v24_successful_completion_for_test(
            &mut fixture.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("record historical v21 verified-no-op completion");
        assert!(matches!(
            &expected.receipt.application,
            CompletionApplication::VerifiedNoOp { .. }
        ));
        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);

        let reader = EventLedger::open(&database_path)
            .expect("migrate historical verified-no-op completion to current schema");
        let completed = load_migrated_pre_v24_completion(&reader, &expected);
        assert_eq!(row_count(&reader, "application_artifact_assemblies"), 0);
        assert_eq!(row_count(&reader, "sprint_application_admissions"), 0);
        assert_eq!(
            reader
                .connection
                .query_row(
                    "SELECT completion_receipt_id
                     FROM pre_v22_completion_authority_exemptions
                     WHERE sprint_id = 'sprint-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("load migrated historical no-op exemption"),
            completed.receipt.receipt_id
        );
        assert_eq!(
            reader
                .load_completion("sprint-1")
                .expect("reload verified-no-op completion"),
            Some(completed)
        );
        assert!(
            reader
                .assess_task_done("sprint-1", "task-1")
                .expect("recompute TaskDone after no-op completion restart")
                .is_done()
        );
    }

    #[test]
    fn completion_consumes_exact_task_done_winner_after_closed_retry() {
        let (mut fixture, report, receipt, event) =
            prepare_v16_verified_no_op_completion_with_retry(true);
        let before = fixture
            .ledger
            .assess_task_done("sprint-1", "task-1")
            .expect("assess retry TaskDone before completion");
        let proof = before.proof.as_ref().expect("closed retry TaskDone proof");
        assert_eq!(proof.non_winning_attempts.len(), 1);
        assert_eq!(
            receipt.task_integration_receipt_ids.as_slice(),
            std::slice::from_ref(&proof.integration_receipt.receipt_id)
        );

        let expected = record_pre_v24_successful_completion_for_test(
            &mut fixture.ledger,
            &report,
            &receipt,
            &event,
        )
        .expect("complete from exact universal TaskDone proof");
        let database_path = fixture.database.path.clone();
        drop(fixture.ledger);
        let reader = EventLedger::open(&database_path)
            .expect("migrate historical retry completion to current schema");
        let completed = load_migrated_pre_v24_completion(&reader, &expected);
        assert_eq!(row_count(&reader, "sprint_application_admissions"), 0);
        assert_eq!(
            reader
                .load_completion("sprint-1")
                .expect("reload retry completion"),
            Some(completed)
        );
        assert_eq!(
            reader
                .assess_task_done("sprint-1", "task-1")
                .expect("recompute retry TaskDone after completion"),
            before
        );
    }

    #[test]
    fn v16_completion_rejects_corrupt_empty_different_task_result_without_writes() {
        let (mut fixture, report, receipt, event) = prepare_v16_verified_no_op_completion();
        let alternate = WorkspaceSnapshot {
            snapshot_id: digest('9'),
            grant_hash: fixture.spec.workspace_grant.grant_hash.clone(),
            created_at_unix_ms: 1_650,
        };
        fixture
            .ledger
            .persist_workspace_snapshot(&fixture.spec.sprint_id, &alternate)
            .expect("persist corruption target snapshot");
        let mut malformed = fixture.change_set.clone();
        malformed.result_snapshot = alternate.snapshot_id.clone();
        assert!(malformed.operations.is_empty());
        assert_ne!(malformed.base_snapshot, malformed.result_snapshot);
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER change_sets_no_update;")
            .expect("open corruption bypass");
        fixture
            .ledger
            .connection
            .execute(
                "UPDATE change_sets
                 SET result_snapshot = ?1, change_set_json = ?2
                 WHERE sprint_id = ?3 AND change_set_id = ?4",
                params![
                    malformed.result_snapshot.as_str(),
                    encode("malformed no-op change set", &malformed).expect("encode corruption"),
                    fixture.spec.sprint_id,
                    malformed.change_set_id,
                ],
            )
            .expect("inject empty/different change set");

        let error = fixture
            .ledger
            .record_successful_completion(&report, &receipt, &event)
            .expect_err("corrupt empty/different result must not complete");
        assert!(
            matches!(
                &error,
                LedgerError::Corrupt {
                    entity: "task integration receipt",
                    detail,
                } if detail.contains(
                    "must be empty exactly when base and result snapshots are identical"
                )
            ),
            "unexpected rejection: {error:?}"
        );
        assert_no_completion_writes(&fixture.ledger);
    }

    #[test]
    fn v15_running_boundary_readback_and_history_reject_crossed_transition_event() {
        let fixture = prepare_v15_candidate_fixture(false);
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_running_boundary(&fixture.running.boundary_id)
                .expect("load exact Running boundary before corruption"),
            fixture.running
        );
        fixture
            .ledger
            .load_task_attempt_history(&fixture.spec.sprint_id, "task-1")
            .expect("load exact Candidate history before corruption");

        let mut crossed = load_event_by_id(
            &fixture.ledger.connection,
            &fixture.running.transition_event_id,
        )
        .expect("load Running transition event for corruption");
        crossed.payload = AgentEventKind::TaskStateChanged {
            from: "Running".into(),
            to: "Verifying".into(),
        };
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER agent_events_no_update;")
            .expect("disable event immutability for Running corruption");
        fixture
            .ledger
            .connection
            .execute(
                "UPDATE agent_events SET event_json = ?1 WHERE event_id = ?2",
                params![
                    encode("agent event", &crossed).expect("encode crossed Running event"),
                    crossed.event_id,
                ],
            )
            .expect("cross the Running transition event payload");

        assert!(matches!(
            fixture
                .ledger
                .load_task_attempt_running_boundary(&fixture.running.boundary_id),
            Err(LedgerError::Corrupt {
                entity: "task attempt Running boundary",
                ..
            })
        ));
        assert!(matches!(
            fixture
                .ledger
                .load_task_attempt_history(&fixture.spec.sprint_id, "task-1"),
            Err(LedgerError::Corrupt {
                entity: "task attempt Running boundary",
                ..
            })
        ));
    }

    #[test]
    fn v15_running_boundary_readback_rejoins_initialized_session_time() {
        let fixture = prepare_v15_candidate_fixture(false);
        let mut crossed_session = fixture
            .ledger
            .load_runner_session(&fixture.spec.sprint_id, &fixture.running.runner_session_id)
            .expect("load initialized task-worker session");
        crossed_session.registered_at_unix_ms = fixture.running.started_at_unix_ms + 1;
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER runner_session_policies_no_update;")
            .expect("disable session immutability for Running corruption");
        fixture
            .ledger
            .connection
            .execute(
                "UPDATE runner_session_policies
                 SET registered_at_unix_ms = ?1, record_json = ?2
                 WHERE session_id = ?3",
                params![
                    sqlite_integer(
                        "crossed session registered_at_unix_ms",
                        crossed_session.registered_at_unix_ms,
                    )
                    .expect("crossed session timestamp fits SQLite"),
                    encode("runner session policy", &crossed_session)
                        .expect("encode crossed session"),
                    crossed_session.session_id,
                ],
            )
            .expect("move session initialization after Running boundary");
        assert_eq!(
            fixture
                .ledger
                .load_runner_session(&fixture.spec.sprint_id, &fixture.running.runner_session_id)
                .expect("crossed session remains internally canonical"),
            crossed_session
        );
        assert!(matches!(
            fixture
                .ledger
                .load_task_attempt_running_boundary(&fixture.running.boundary_id),
            Err(LedgerError::Corrupt {
                entity: "task attempt Running boundary",
                ..
            })
        ));
    }

    fn assert_static_cleanup_admission_corruption_rejected(
        suffix: &str,
        corrupt: impl FnOnce(&mut EventLedger, &RunnerLaunchIntent, &EffectIntent, &AgentEvent),
    ) {
        let database = TestDatabase::new();
        let mut ledger = EventLedger::open(&database.path).expect("open static-admission ledger");
        let (policy, launch, cleanup, _, request_bytes, proposal) = prepare_test_launch_admission(
            &mut ledger,
            suffix,
            RunnerSessionPurpose::TaskWorker,
            Some("worker-1"),
            WorkerCleanupBackend::LinuxCgroupV2,
        );
        ledger
            .admit_runner_launch_with_cleanup(&launch, &policy, &cleanup, &request_bytes, &proposal)
            .expect("admit static cleanup authority");
        ledger
            .register_runner_session(&runner_session(&launch, 1_150), &policy)
            .expect("register task-worker session for binding corruption coverage");
        let exact = runner_launch_cleanup_admission::load_static_authoritative_record(
            &ledger.connection,
            &launch.sprint_id,
            &launch.launch_id,
        )
        .expect("load exact static cleanup authority before corruption");
        assert_eq!(exact.cleanup_effect_id, cleanup.effect_id);
        assert_eq!(exact.proposal_event_id, proposal.event_id);

        corrupt(&mut ledger, &launch, &cleanup, &proposal);
        assert!(
            runner_launch_cleanup_admission::load_static_authoritative_record(
                &ledger.connection,
                &launch.sprint_id,
                &launch.launch_id,
            )
            .is_err(),
            "static cleanup admission accepted injected {suffix} corruption"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn static_cleanup_admission_rejects_record_index_launch_effect_request_event_and_binding_crosses()
     {
        assert_static_cleanup_admission_corruption_rejected(
            "static-record",
            |ledger, launch, _, _| {
                let mut record = runner_launch_cleanup_admission::load_static_authoritative_record(
                    &ledger.connection,
                    &launch.sprint_id,
                    &launch.launch_id,
                )
                .expect("load record for canonical corruption");
                record.admitted_at_unix_ms += 1;
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER runner_launch_cleanup_admissions_no_update;")
                    .expect("open cleanup-admission record corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE runner_launch_cleanup_admissions
                         SET admission_json = ?1 WHERE launch_id = ?2",
                        params![
                            encode("crossed cleanup admission", &record)
                                .expect("encode crossed cleanup admission"),
                            launch.launch_id,
                        ],
                    )
                    .expect("cross canonical cleanup-admission record");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-index",
            |ledger, launch, _, _| {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER runner_launch_cleanup_admissions_no_update;")
                    .expect("open cleanup-admission index corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE runner_launch_cleanup_admissions
                         SET request_digest = ?1 WHERE launch_id = ?2",
                        params![digest('f').as_str(), launch.launch_id],
                    )
                    .expect("cross cleanup-admission request index");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-launch",
            |ledger, launch, _, _| {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER runner_launch_intents_no_update;")
                    .expect("open launch corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE runner_launch_intents
                         SET policy_hash = ?1 WHERE launch_id = ?2",
                        params![digest('e').as_str(), launch.launch_id],
                    )
                    .expect("cross cleanup launch index");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-effect",
            |ledger, _, cleanup, _| {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER effect_intents_no_update;")
                    .expect("open cleanup-effect corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE effect_intents
                         SET request_digest = ?1 WHERE effect_id = ?2",
                        params![digest('d').as_str(), cleanup.effect_id],
                    )
                    .expect("cross cleanup-effect request index");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-request",
            |ledger, _, cleanup, _| {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER effect_request_payloads_no_update;")
                    .expect("open cleanup-request corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE effect_request_payloads
                         SET request_bytes = X'7B7D' WHERE effect_id = ?1",
                        [&cleanup.effect_id],
                    )
                    .expect("cross cleanup request bytes");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-event",
            |ledger, _, _, proposal| {
                let mut crossed = proposal.clone();
                crossed.payload = AgentEventKind::ToolProposed {
                    tool_call_id: match &proposal.payload {
                        AgentEventKind::ToolProposed { tool_call_id, .. } => tool_call_id.clone(),
                        _ => panic!("cleanup proposal must be ToolProposed"),
                    },
                    tool_name: EffectKind::RunCommand.tool_name().into(),
                };
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER agent_events_no_update;")
                    .expect("open cleanup-event corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE agent_events SET event_json = ?1 WHERE event_id = ?2",
                        params![
                            encode("crossed cleanup proposal", &crossed)
                                .expect("encode crossed cleanup proposal"),
                            proposal.event_id,
                        ],
                    )
                    .expect("cross cleanup proposal payload");
            },
        );
        assert_static_cleanup_admission_corruption_rejected(
            "static-binding",
            |ledger, launch, cleanup, _| {
                ledger
                    .connection
                    .execute_batch("DROP TRIGGER effect_session_bindings_no_update;")
                    .expect("open cleanup-binding corruption fence");
                ledger
                    .connection
                    .execute(
                        "UPDATE effect_session_bindings
                         SET session_id = ?1 WHERE effect_id = ?2",
                        params![launch.session_id, cleanup.effect_id],
                    )
                    .expect("initialize forbidden cleanup-effect session binding");
            },
        );
    }

    #[test]
    fn running_boundary_readback_is_independent_of_terminal_cleanup_receipt_lifecycle() {
        let mut fixture = prepare_v15_candidate_fixture(false);
        let (_, _, disposition) =
            integrate_v15_candidate(&mut fixture, "running-static-cleanup", false);
        let cleanup = cleanup_terminal_record(
            &fixture.ledger,
            &fixture.launch,
            "running-static-cleanup",
            1_450,
        );
        let cleanup_receipt_id = cleanup.evidence.receipt.receipt_id.clone();
        fixture
            .ledger
            .with_integrated_task_attempt_cleanup_exclusion(
                &disposition.metadata().disposition_id,
                |_| Ok(cleanup),
            )
            .expect("terminalize managed task cleanup through its atomic exclusion");
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_running_boundary(&fixture.running.boundary_id)
                .expect("terminal cleanup does not erase static Running authority"),
            fixture.running
        );
        fixture
            .ledger
            .connection
            .execute_batch("DROP TRIGGER worker_cleanup_receipts_no_update;")
            .expect("open terminal cleanup receipt corruption fence");
        fixture
            .ledger
            .connection
            .execute(
                "UPDATE worker_cleanup_receipts
                 SET evidence_json = X'7B7D' WHERE receipt_id = ?1",
                [&cleanup_receipt_id],
            )
            .expect("corrupt only post-admission cleanup receipt lifecycle");
        assert!(
            fixture
                .ledger
                .load_runner_launch_cleanup_admission(
                    &fixture.launch.sprint_id,
                    &fixture.launch.launch_id,
                )
                .is_err(),
            "full cleanup lifecycle loader must still reject corrupt terminal evidence"
        );
        assert_eq!(
            fixture
                .ledger
                .load_task_attempt_running_boundary(&fixture.running.boundary_id)
                .expect("Running authority must not recursively load terminal cleanup evidence"),
            fixture.running
        );
    }

    fn persist_command_domain_intent(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        effect_id: &str,
        created_at_unix_ms: u64,
    ) -> (
        EffectIntent,
        AgentEvent,
        Option<FreshRunnerEffectDispatchPermit>,
    ) {
        let mut intent = effect_intent(
            effect_id,
            &format!("idempotency-{effect_id}"),
            created_at_unix_ms,
        );
        intent.kind = EffectKind::RunCommand;
        intent.task_id = launch
            .worker_lease
            .as_ref()
            .map(|lease| lease.task_id.clone());
        intent.worker_id = launch.worker_id.clone();
        intent.worker_lease = launch.worker_lease.clone();
        intent.policy_hash = launch.policy_hash.clone();
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("command proposal sequence"),
            &format!("event-{effect_id}-proposed"),
        );
        let permit = if command_output_capture_authority::schema_is_installed(&ledger.connection)
            .expect("inspect command-domain capture schema")
        {
            let session = ledger
                .load_runner_session(&intent.sprint_id, &launch.session_id)
                .expect("load command-domain session");
            let capture = v27_test_capture_intent(&intent, launch, &session, effect_id);
            let admission = ledger
                .admit_runner_command_output_capture_intent_for_dispatch(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &proposal,
                    &launch.session_id,
                    &capture,
                )
                .expect("persist exact command-domain capture intent");
            match admission {
                CommandOutputCaptureIntentAdmission::Fresh { permit, .. } => Some(permit),
                other => panic!("new command-domain capture admission returned {other:?}"),
            }
        } else {
            ledger
                .record_runner_effect_intent(
                    &intent,
                    EFFECT_REQUEST_BYTES,
                    &proposal,
                    &launch.session_id,
                )
                .expect("persist historical command-domain intent");
            None
        };
        (intent, proposal, permit)
    }

    #[allow(clippy::too_many_lines)] // Current and historical fixture terminals intentionally meet at one compatibility helper.
    fn persist_command_domain_observation(
        ledger: &mut EventLedger,
        intent: &EffectIntent,
        proposal: &AgentEvent,
        permit: Option<FreshRunnerEffectDispatchPermit>,
        outcome: EffectOutcome,
        observed_at_unix_ms: u64,
    ) -> EffectObservation {
        let observation = effect_observation(
            intent,
            &format!("observation-{}", intent.effect_id),
            outcome,
            observed_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("command terminal sequence"),
            &format!("event-{}-finished", intent.effect_id),
        );
        if let Some(permit) = permit {
            let capture = permit
                .output_capture_intent()
                .cloned()
                .expect("current command-domain permit carries capture intent");
            let binding = load_effect_runner_binding(&ledger.connection, intent)
                .expect("load current command-domain runner binding");
            let session = binding
                .session
                .expect("current command-domain binding has initialized session");
            let running =
                load_runner_effect_dispatch_running_boundary(&ledger.connection, &session)
                    .expect("load command-domain Running boundary")
                    .expect("task-worker command has Running boundary");
            let acquired = v27_test_capture_acquired(
                &capture,
                permit
                    .expected_output_capture_dispatch_claim_id()
                    .expect("current command-domain capture claim identity"),
                &intent.effect_id,
                intent.created_at_unix_ms + 1,
            );
            let (_, transport) = ledger
                .claim_command_output_capture_dispatch(
                    permit,
                    acquired.clone(),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("claim current command-domain capture dispatch");
            let authority = transport
                .validate_transport_request(
                    intent,
                    EFFECT_REQUEST_BYTES,
                    &binding.launch,
                    &session,
                    Some(&running),
                    OPAQUE_RUNNER_TRANSPORT_REQUEST_BYTES,
                )
                .expect("validate current command-domain transport");
            if matches!(observation.outcome, EffectOutcome::Unknown { .. }) {
                let capture_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
                    &capture,
                    Some(&acquired),
                    &observation,
                    CommandOutputCaptureTerminalDispositionV1::ReconciliationRequired,
                    acquired.store_head.clone(),
                    observation.outcome.evidence_digest().clone(),
                    None,
                    observed_at_unix_ms + 2,
                )
                .expect("construct current Unknown capture terminal");
                ledger
                    .record_claimed_command_unknown_with_capture_reconciliation_required(
                        authority,
                        &observation,
                        EFFECT_EVIDENCE_BYTES,
                        &terminal,
                        &capture_terminal,
                    )
                    .expect("persist current Unknown command-domain observation");
            } else {
                let before_effect = matches!(
                    observation.outcome,
                    EffectOutcome::FailedBeforeEffect { .. }
                        | EffectOutcome::CancelledBeforeEffect { .. }
                );
                let disposition = if before_effect {
                    CommandOutputCaptureTerminalDispositionV1::Abandoned
                } else {
                    CommandOutputCaptureTerminalDispositionV1::Published
                };
                let artifacts = (!before_effect).then(|| {
                    CommandOutputArtifactSetReferenceV1::try_new(
                        capture.source.clone(),
                        CommandOutputStreamArtifactV1 {
                            stream: CommandOutputStreamV1::Stdout,
                            byte_length: 0,
                            content_digest: Digest::sha256(&[]),
                        },
                        CommandOutputStreamArtifactV1 {
                            stream: CommandOutputStreamV1::Stderr,
                            byte_length: 0,
                            content_digest: Digest::sha256(&[]),
                        },
                    )
                    .expect("construct current command-domain output reference")
                });
                let capture_terminal = CommandOutputCaptureTerminalAnchorV1::try_new(
                    &capture,
                    Some(&acquired),
                    &observation,
                    disposition,
                    CommandOutputCaptureStoreHeadV1 {
                        generation: if before_effect {
                            acquired.store_head.generation + 1
                        } else {
                            acquired.store_head.generation + 5
                        },
                        record_digest: Digest::sha256(
                            format!("terminal-head:{}", intent.effect_id).as_bytes(),
                        ),
                    },
                    Digest::sha256(format!("terminal-record:{}", intent.effect_id).as_bytes()),
                    artifacts,
                    observed_at_unix_ms + 2,
                )
                .expect("construct current command-domain capture terminal");
                let mut cleanup = v27_test_command_cleanup(
                    intent,
                    &observation,
                    &binding.launch,
                    &session,
                    &intent.effect_id,
                    observed_at_unix_ms + 1,
                );
                if before_effect {
                    cleanup.disposition =
                        CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect;
                }
                let clean_scan = (!before_effect).then(|| {
                    let termination = match observation.outcome {
                        EffectOutcome::Succeeded { .. } => CommandTerminationV1::Exited { code: 0 },
                        _ => CommandTerminationV1::Exited { code: 1 },
                    };
                    v29_test_clean_scan_receipt(
                        &capture,
                        &acquired,
                        &capture_terminal,
                        termination,
                        &intent.effect_id,
                    )
                });
                ledger
                    .record_claimed_command_effect_observation_with_output_capture(
                        authority,
                        &observation,
                        EFFECT_EVIDENCE_BYTES,
                        &terminal,
                        &capture_terminal,
                        clean_scan.as_ref(),
                        &cleanup,
                    )
                    .expect("persist current command-domain observation with capture closure");
            }
        } else {
            ledger
                .record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal)
                .expect("persist historical command-domain observation");
        }
        observation
    }

    fn command_domain_proof(
        binding: &CommandDomainEffectBinding,
        proof_id: &str,
        backend: CommandDomainBackend,
        disposition: CommandDomainCleanupDisposition,
        cleaned_at_unix_ms: u64,
    ) -> CommandDomainCleanupProof {
        let platform_proof_bytes = format!("validated-native-proof:{proof_id}").into_bytes();
        CommandDomainCleanupProof {
            contract_version: CONTRACT_VERSION,
            proof_id: proof_id.into(),
            sprint_id: binding.sprint_id.clone(),
            launch_id: binding.launch_id.clone(),
            session_id: binding.session_id.clone(),
            effect_id: binding.effect_id.clone(),
            observation_id: binding.observation_id.clone(),
            request_digest: binding.request_digest.clone(),
            backend,
            disposition,
            surviving_processes: 0,
            platform_proof_digest: Digest::sha256(&platform_proof_bytes),
            platform_proof_bytes,
            cleaned_at_unix_ms,
        }
    }

    fn ensure_test_command_domain_cleanup(
        ledger: &mut EventLedger,
        binding: &CommandDomainEffectBinding,
        proof_id: &str,
        backend: CommandDomainBackend,
        disposition: CommandDomainCleanupDisposition,
        cleaned_at_unix_ms: u64,
    ) {
        match ledger.load_command_domain_cleanup_proof(&binding.effect_id) {
            Ok(existing) => {
                assert_eq!(existing.binding, *binding);
                assert_eq!(existing.proof.backend, backend);
                assert_eq!(existing.proof.disposition, disposition);
                assert_eq!(existing.proof.surviving_processes, 0);
            }
            Err(LedgerError::ArtifactNotFound { .. }) => {
                ledger
                    .record_command_domain_cleanup_proof(&command_domain_proof(
                        binding,
                        proof_id,
                        backend,
                        disposition,
                        cleaned_at_unix_ms,
                    ))
                    .expect("persist exact test command cleanup");
            }
            Err(error) => panic!("load test command cleanup: {error:?}"),
        }
    }

    fn test_application_artifact(
        change_set: &ChangeSet,
        label: &str,
    ) -> TaskIntegrationArtifactReference {
        TaskIntegrationArtifactReference {
            format_version: 1,
            artifact_digest: Digest::sha256(format!("application-artifact:{label}").as_bytes()),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
        }
    }

    fn application_request_bytes(
        ledger: &EventLedger,
        change_set: &ChangeSet,
        artifact: &TaskIntegrationArtifactReference,
    ) -> Vec<u8> {
        if application_artifact_authority::schema_is_installed(&ledger.connection)
            .expect("inspect application authority schema")
        {
            encode(
                "application request",
                &ApplicationRequest {
                    contract_version: CONTRACT_VERSION,
                    change_set: change_set.clone(),
                    artifact: artifact.clone(),
                },
            )
            .expect("encode artifact-bound application request")
        } else {
            encode("legacy application request", change_set)
                .expect("encode historical bare ChangeSet request")
        }
    }

    fn insert_command_domain_proof_row(
        connection: &Connection,
        proof: &CommandDomainCleanupProof,
    ) -> rusqlite::Result<usize> {
        let backend = match proof.backend {
            CommandDomainBackend::MacOsDedicatedIdentity => "MacOsDedicatedIdentity",
            CommandDomainBackend::LinuxCgroupV2 => "LinuxCgroupV2",
        };
        let disposition = match proof.disposition {
            CommandDomainCleanupDisposition::ReapedZeroSurvivors => "ReapedZeroSurvivors",
            CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect => {
                "NoDomainCreatedBeforeEffect"
            }
        };
        connection.execute(
            "INSERT INTO command_domain_cleanup_proofs (
                proof_id, sprint_id, launch_id, session_id, effect_id,
                observation_id, request_digest, backend, disposition,
                surviving_processes, platform_proof_digest, contract_version,
                cleaned_at_unix_ms, platform_proof_bytes, proof_json
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15
             )",
            params![
                proof.proof_id,
                proof.sprint_id,
                proof.launch_id,
                proof.session_id,
                proof.effect_id,
                proof.observation_id,
                proof.request_digest.as_str(),
                backend,
                disposition,
                i64::try_from(proof.surviving_processes).expect("survivor count fits SQLite"),
                proof.platform_proof_digest.as_str(),
                i64::from(proof.contract_version),
                i64::try_from(proof.cleaned_at_unix_ms).expect("cleanup time fits SQLite"),
                proof.platform_proof_bytes,
                encode("command-domain cleanup proof", proof).expect("encode proof"),
            ],
        )
    }

    fn prepare_legacy_opaque_application(
        ledger: &mut EventLedger,
        suffix: &str,
        outcome: Option<EffectOutcome>,
    ) -> (EffectIntent, Vec<u8>) {
        let (spec, graph) = sprint_fixture();
        ledger
            .create_sprint(&spec, &graph, 1_000)
            .expect("persist legacy application sprint");
        let (base, _, _, _, _, _, _, _) = completion_artifacts();
        ledger
            .persist_workspace_snapshot(&spec.sprint_id, &base)
            .expect("persist legacy application input");
        let policy = compiled_test_policy(&format!("legacy-opaque-policy-{suffix}"));
        let launch = runner_launch(
            &format!("launch-legacy-opaque-{suffix}"),
            &format!("session-legacy-opaque-{suffix}"),
            RunnerSessionPurpose::Applier,
            None,
            &policy,
            1_210,
        );
        ledger
            .record_runner_launch_intent(&launch, &policy)
            .expect("persist legacy application launch");
        ledger
            .register_runner_session(&runner_session(&launch, 1_250), &policy)
            .expect("persist legacy application session");
        let request_bytes = format!("opaque-v11-application-request:{suffix}").into_bytes();
        let intent = EffectIntent {
            contract_version: CONTRACT_VERSION,
            effect_id: format!("effect-legacy-opaque-{suffix}"),
            idempotency_key: format!("key-legacy-opaque-{suffix}"),
            sprint_id: spec.sprint_id,
            task_id: None,
            worker_id: None,
            worker_lease: None,
            causation_event_id: None,
            correlation_id: format!("correlation-legacy-opaque-{suffix}"),
            kind: EffectKind::ApplyChangeSet,
            request_digest: Digest::sha256(&request_bytes),
            policy_hash: launch.policy_hash,
            input_snapshot: base.snapshot_id,
            created_at_unix_ms: 1_300,
        };
        let proposal = effect_proposal_event(
            &intent,
            ledger
                .next_sequence(&intent.sprint_id)
                .expect("legacy application proposal sequence"),
            &format!("event-legacy-opaque-{suffix}-proposed"),
        );
        ledger
            .record_runner_effect_intent(&intent, &request_bytes, &proposal, &launch.session_id)
            .expect("v11 accepts digest-bound opaque application request");
        if let Some(outcome) = outcome {
            let observation = effect_observation(
                &intent,
                &format!("observation-legacy-opaque-{suffix}"),
                outcome,
                1_350,
            );
            let terminal = effect_terminal_event(
                &intent,
                &proposal.event_id,
                &observation,
                ledger
                    .next_sequence(&intent.sprint_id)
                    .expect("legacy application terminal sequence"),
                &format!("event-legacy-opaque-{suffix}-finished"),
            );
            ledger
                .record_effect_observation(&observation, EFFECT_EVIDENCE_BYTES, &terminal)
                .expect("persist non-successful legacy application observation");
        }
        (intent, request_bytes)
    }

    #[allow(clippy::too_many_lines)] // Builds the complete typed cleanup lifecycle used across tests.
    fn persist_cleanup_evidence(
        ledger: &mut EventLedger,
        launch: &RunnerLaunchIntent,
        input_snapshot: &Digest,
        receipt_id: &str,
        backend: WorkerCleanupBackend,
        created_at_unix_ms: u64,
        cleaned_at_unix_ms: u64,
    ) -> WorkerCleanupEvidence {
        let authoritative =
            runner_launch_cleanup_admission::schema_is_installed(&ledger.connection)
                .expect("inspect launch cleanup schema");
        let (intent, proposal) = if authoritative {
            let admission = ledger
                .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
                .expect("load atomically admitted cleanup");
            assert_eq!(admission.launch, *launch);
            assert_eq!(admission.cleanup_request.platform_backend, backend);
            assert!(admission.cleanup_effect.observation.is_none());
            assert!(admission.cleanup_effect.intent.created_at_unix_ms <= created_at_unix_ms);
            (
                admission.cleanup_effect.intent,
                admission.cleanup_effect.proposed_event,
            )
        } else {
            let request = WorkerCleanupRequest {
                contract_version: CONTRACT_VERSION,
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                session_id: launch.session_id.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: backend,
            };
            let request_bytes =
                encode("worker cleanup request", &request).expect("encode legacy cleanup");
            let intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("effect-{receipt_id}"),
                idempotency_key: format!("key-{receipt_id}"),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: launch.worker_lease.clone(),
                causation_event_id: None,
                correlation_id: format!("correlation-{receipt_id}"),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&request_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: input_snapshot.clone(),
                created_at_unix_ms,
            };
            let proposal = effect_proposal_event(
                &intent,
                ledger
                    .next_sequence(&launch.sprint_id)
                    .expect("legacy cleanup proposal sequence"),
                &format!("event-{receipt_id}-proposed"),
            );
            ledger
                .record_cleanup_effect_intent_for_launch(
                    &intent,
                    &request_bytes,
                    &proposal,
                    &launch.launch_id,
                )
                .expect("persist legacy cleanup intent");
            (intent, proposal)
        };

        let os_evidence_bytes = format!("zero descendants for {}", launch.launch_id).into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: receipt_id.into(),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("observation-{receipt_id}"),
                session_id: launch.session_id.clone(),
                worker_lease: launch.worker_lease.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let evidence_bytes =
            encode("worker cleanup evidence", &evidence).expect("encode cleanup evidence");
        let observation = effect_observation(
            &intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            cleaned_at_unix_ms,
        );
        let terminal = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence("sprint-1")
                .expect("cleanup terminal sequence"),
            &format!("event-{receipt_id}-finished"),
        );
        if authoritative {
            ledger
                .with_runner_launch_cleanup_exclusion(
                    &launch.sprint_id,
                    &launch.launch_id,
                    |claim| {
                        assert_eq!(claim.next_event_sequence(), terminal.sequence);
                        Ok(RunnerCleanupTerminalRecord {
                            observation: observation.clone(),
                            event: terminal.clone(),
                            evidence: evidence.clone(),
                        })
                    },
                )
                .expect("execute and persist authoritative cleanup evidence");
        } else {
            ledger
                .record_worker_cleanup_effect_observation(&observation, &terminal, &evidence)
                .expect("persist legacy cleanup evidence");
        }
        evidence
    }

    fn cleanup_terminal_record(
        ledger: &EventLedger,
        launch: &RunnerLaunchIntent,
        receipt_id: &str,
        cleaned_at_unix_ms: u64,
    ) -> RunnerCleanupTerminalRecord {
        let admission = ledger
            .load_runner_launch_cleanup_admission(&launch.sprint_id, &launch.launch_id)
            .expect("load cleanup admission");
        let intent = admission.cleanup_effect.intent;
        let proposal = admission.cleanup_effect.proposed_event;
        let os_evidence_bytes = format!("zero descendants for {}", launch.launch_id).into_bytes();
        let evidence = WorkerCleanupEvidence {
            receipt: WorkerCleanupReceipt {
                contract_version: CONTRACT_VERSION,
                receipt_id: receipt_id.into(),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                effect_id: intent.effect_id.clone(),
                observation_id: format!("observation-{receipt_id}"),
                session_id: launch.session_id.clone(),
                worker_lease: launch.worker_lease.clone(),
                policy_hash: launch.policy_hash.clone(),
                grant_hash: launch.grant_hash.clone(),
                policy_version: launch.policy_version,
                platform_backend: admission.cleanup_request.platform_backend,
                os_evidence_digest: Digest::sha256(&os_evidence_bytes),
                surviving_processes: 0,
                cleaned_at_unix_ms,
            },
            os_evidence_bytes,
        };
        let evidence_bytes =
            encode("worker cleanup evidence", &evidence).expect("encode cleanup evidence");
        let observation = effect_observation(
            &intent,
            &evidence.receipt.observation_id,
            EffectOutcome::Succeeded {
                evidence_digest: Digest::sha256(&evidence_bytes),
            },
            cleaned_at_unix_ms,
        );
        let event = effect_terminal_event(
            &intent,
            &proposal.event_id,
            &observation,
            ledger
                .next_sequence(&launch.sprint_id)
                .expect("cleanup terminal sequence"),
            &format!("event-{receipt_id}-finished"),
        );
        RunnerCleanupTerminalRecord {
            observation,
            event,
            evidence,
        }
    }

