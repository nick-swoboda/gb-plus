    #[test]
    fn v32_exhaustion_and_unknown_precedence_are_typed_terminal_and_nonreplayable() {
        let (_database, mut exhausted, _, _) =
            create_current_ledger("exhausted", "sprint-exhausted", 1);
        let attempt = exhausted
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-exhausted",
                "admit-only",
                task_set("sprint-exhausted", 'c', None, 20),
                criterion_set("sprint-exhausted", 'c', 1, 21),
                30,
            ))
            .expect("admit only attempt");
        let failure = exhausted
            .close_current_final_verification_attempt_v32(&clean_capture(
                &attempt.authority,
                "closure-exhausted",
                CurrentFinalVerificationTerminationV1::TimedOut,
                40,
            ))
            .expect("close exhausted attempt");
        let terminal = exhausted
            .load_current_sprint_terminal_outcome_v32("sprint-exhausted")
            .expect("load failed terminal")
            .expect("terminal exists");
        assert_eq!(terminal.terminal_state, "Failed");
        assert_eq!(
            terminal.terminal_reason,
            CurrentSprintTerminalReasonV1::FinalVerificationAttemptsExhausted
        );
        assert!(matches!(
            exhausted.activate_current_final_verification_repair_v32(&failure.outcome_id, 50),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));

        let (_database, mut unknown, _, _) = create_current_ledger("unknown", "sprint-unknown", 3);
        let attempt = unknown
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-unknown",
                "admit-unknown",
                task_set("sprint-unknown", 'c', None, 20),
                criterion_set("sprint-unknown", 'c', 1, 21),
                30,
            ))
            .expect("admit unknown fixture");
        let mut capture = clean_capture(
            &attempt.authority,
            "closure-unknown",
            CurrentFinalVerificationTerminationV1::Exited { code: 0 },
            40,
        );
        capture.runner_cleanup_proof_id = None;
        let outcome = unknown
            .close_current_final_verification_attempt_v32(&capture)
            .expect("ambiguity closes as Unknown");
        assert_eq!(
            outcome.outcome,
            CurrentFinalVerificationOutcomeKindV1::Unknown
        );
        let terminal = unknown
            .load_current_sprint_terminal_outcome_v32("sprint-unknown")
            .expect("load Unknown terminal")
            .expect("Unknown terminal exists");
        assert_eq!(terminal.terminal_state, "Unknown");
        assert!(matches!(
            unknown.admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-unknown",
                "admit-after-unknown",
                task_set("sprint-unknown", 'c', None, 20),
                criterion_set("sprint-unknown", 'c', 1, 21),
                50,
            )),
            Err(LedgerError::SprintAlreadyTerminal(_))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The closed matrix is intentionally enumerated without a lossy generic outcome fixture.
    fn v32_closed_outcome_matrix_preserves_every_variant_and_control_terminal() {
        let cases = vec![
            (
                "verified",
                CurrentFinalVerificationTerminationV1::Exited { code: 0 },
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-verified".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::Verified,
            ),
            (
                "nonzero",
                CurrentFinalVerificationTerminationV1::Exited { code: 9 },
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-nonzero".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::NonzeroExit { code: 9 },
            ),
            (
                "signaled",
                CurrentFinalVerificationTerminationV1::Signaled { signal: 15 },
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-signaled".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::Signaled { signal: 15 },
            ),
            (
                "timed-out",
                CurrentFinalVerificationTerminationV1::TimedOut,
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-timeout".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::TimedOut,
            ),
            (
                "output-limit",
                CurrentFinalVerificationTerminationV1::OutputLimitExceeded,
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-output-limit".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::OutputLimitExceeded,
            ),
            (
                "sensitive",
                CurrentFinalVerificationTerminationV1::Exited { code: 7 },
                CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive {
                    rejection_closure_id: "sensitive-closure".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::SensitiveOutputRejected,
            ),
            (
                "failed-before-effect",
                CurrentFinalVerificationTerminationV1::FailedBeforeEffect,
                CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                    closure_receipt_id: "closed-before-effect".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::FailedBeforeEffect,
            ),
            (
                "after-effect-unknown",
                CurrentFinalVerificationTerminationV1::InterruptedAfterEffect {
                    control_id: "unmatched-after-effect-control".into(),
                },
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "published-after-effect".into(),
                },
                CurrentFinalVerificationOutcomeKindV1::Unknown,
            ),
        ];
        for (label, termination, custody, expected) in cases {
            let sprint_id = format!("sprint-matrix-{label}");
            let (_database, mut ledger, _, _) = create_current_ledger(label, &sprint_id, 3);
            let tasks = task_set(&sprint_id, 'c', None, 20);
            let criteria = criterion_set(&sprint_id, 'c', 1, 21);
            let attempt = ledger
                .admit_current_final_verification_attempt_v32(&admission_request(
                    &sprint_id,
                    &format!("admit-{label}"),
                    tasks.clone(),
                    criteria.clone(),
                    30,
                ))
                .expect("admit matrix attempt");
            let mut capture = clean_capture(
                &attempt.authority,
                &format!("closure-{label}"),
                termination,
                40,
            );
            capture.output_custody = custody;
            let outcome = ledger
                .close_current_final_verification_attempt_v32(&capture)
                .expect("close matrix attempt");
            assert_eq!(outcome.outcome, expected, "case {label}");
            if label == "failed-before-effect" {
                let retry = ledger
                    .admit_current_final_verification_attempt_v32(&admission_request(
                        &sprint_id,
                        "admit-failed-before-retry",
                        tasks,
                        criteria,
                        50,
                    ))
                    .expect("exact same-snapshot retry after pre-effect closure");
                assert!(matches!(
                    retry.authority.predecessor,
                    FinalVerificationAttemptPredecessorV1::SameSnapshotAfterFailedBeforeEffect { .. }
                ));
            }
        }

        let (_database, mut canceled, _, _) =
            create_current_ledger("canceled", "sprint-canceled", 3);
        let attempt = canceled
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-canceled",
                "admit-canceled",
                task_set("sprint-canceled", 'c', None, 20),
                criterion_set("sprint-canceled", 'c', 1, 21),
                30,
            ))
            .expect("admit canceled attempt");
        let control = canceled
            .record_current_final_verification_control_v32(
                &attempt.authority.attempt_id,
                CurrentFinalVerificationControlKindV1::Cancel,
                true,
                35,
            )
            .expect("record cancel");
        let capture = CurrentFinalVerificationCaptureClosureV1 {
            closure_version: CURRENT_OUTCOME_VERSION_V1,
            closure_id: "closure-canceled".into(),
            sprint_id: "sprint-canceled".into(),
            attempt_id: attempt.authority.attempt_id,
            termination: CurrentFinalVerificationTerminationV1::Canceled {
                control_id: control.control_id,
            },
            output_custody: CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                closure_receipt_id: "cancel-capture-closed".into(),
            },
            runner_cleanup_proof_id: Some("cancel-runner-clean".into()),
            command_domain_cleanup_proof_id: Some("cancel-domain-clean".into()),
            terminal_at_unix_ms: 40,
        };
        let outcome = canceled
            .close_current_final_verification_attempt_v32(&capture)
            .expect("close canceled attempt");
        assert!(matches!(
            outcome.outcome,
            CurrentFinalVerificationOutcomeKindV1::Canceled { .. }
        ));
        assert_eq!(
            canceled
                .load_current_sprint_terminal_outcome_v32("sprint-canceled")
                .expect("load canceled terminal")
                .expect("canceled terminal exists")
                .terminal_state,
            "Canceled"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The authenticated cancellation matrix deliberately covers every custody/effect combination and restart.
    fn v32_authenticated_cancel_requires_known_custody_cut_and_restarts_exactly() {
        let cases = vec![
            (
                "cancel-before-closed",
                true,
                CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                    closure_receipt_id: "cancel-before-capture-closed".into(),
                },
                true,
                true,
            ),
            (
                "cancel-after-published",
                false,
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "cancel-after-published".into(),
                },
                true,
                true,
            ),
            (
                "cancel-after-sensitive",
                false,
                CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive {
                    rejection_closure_id: "cancel-after-sensitive".into(),
                },
                true,
                true,
            ),
            (
                "cancel-before-published-mismatch",
                true,
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "cancel-before-published".into(),
                },
                true,
                false,
            ),
            (
                "cancel-after-closed-mismatch",
                false,
                CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                    closure_receipt_id: "cancel-after-capture-closed".into(),
                },
                true,
                false,
            ),
            (
                "cancel-after-missing-cleanup",
                false,
                CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                    publication_receipt_id: "cancel-after-missing-cleanup".into(),
                },
                false,
                false,
            ),
            (
                "cancel-after-unknown-custody",
                false,
                CurrentFinalVerificationOutputCustodyV1::Unknown {
                    evidence_digest: digest('f'),
                },
                true,
                false,
            ),
        ];

        for (label, before_effect, custody, cleanup_complete, expected_canceled) in cases {
            let sprint_id = format!("sprint-{label}");
            let (database, mut ledger, _, _) = create_current_ledger(label, &sprint_id, 3);
            let attempt = ledger
                .admit_current_final_verification_attempt_v32(&admission_request(
                    &sprint_id,
                    &format!("admit-{label}"),
                    task_set(&sprint_id, 'c', None, 20),
                    criterion_set(&sprint_id, 'c', 1, 21),
                    30,
                ))
                .expect("admit cancellation fixture");
            let attempt_id = attempt.authority.attempt_id.clone();
            let control = ledger
                .record_current_final_verification_control_v32(
                    &attempt_id,
                    CurrentFinalVerificationControlKindV1::Cancel,
                    before_effect,
                    35,
                )
                .expect("record exact cancellation control");
            let capture = CurrentFinalVerificationCaptureClosureV1 {
                closure_version: CURRENT_OUTCOME_VERSION_V1,
                closure_id: format!("closure-{label}"),
                sprint_id: sprint_id.clone(),
                attempt_id: attempt_id.clone(),
                termination: CurrentFinalVerificationTerminationV1::Canceled {
                    control_id: control.control_id,
                },
                output_custody: custody,
                runner_cleanup_proof_id: cleanup_complete
                    .then(|| format!("runner-cleanup-{label}")),
                command_domain_cleanup_proof_id: Some(format!("domain-cleanup-{label}")),
                terminal_at_unix_ms: 40,
            };
            let outcome = ledger
                .close_current_final_verification_attempt_v32(&capture)
                .expect("classify cancellation fixture");
            if expected_canceled {
                assert!(matches!(
                    outcome.outcome,
                    CurrentFinalVerificationOutcomeKindV1::Canceled { .. }
                ));
            } else {
                assert_eq!(
                    outcome.outcome,
                    CurrentFinalVerificationOutcomeKindV1::Unknown
                );
            }
            let expected_terminal = if expected_canceled {
                "Canceled"
            } else {
                "Unknown"
            };
            assert_eq!(
                ledger
                    .load_current_sprint_terminal_outcome_v32(&sprint_id)
                    .expect("load cancellation terminal")
                    .expect("cancellation terminal exists")
                    .terminal_state,
                expected_terminal
            );

            drop(ledger);
            let reopened = EventLedger::open(&database.path).expect("reopen cancellation ledger");
            assert_eq!(
                reopened
                    .load_current_final_verification_attempt_v32(&attempt_id)
                    .expect("read cancellation after restart")
                    .outcome,
                Some(outcome)
            );
        }
    }

    #[test]
    fn v32_direct_sql_rejects_outcome_substitution_and_false_exhaustion() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("raw-outcome", "sprint-raw-outcome", 1);
        let attempt = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-raw-outcome",
                "admit-raw-outcome",
                task_set("sprint-raw-outcome", 'c', None, 20),
                criterion_set("sprint-raw-outcome", 'c', 1, 21),
                30,
            ))
            .expect("admit raw outcome fixture");
        let capture = clean_capture(
            &attempt.authority,
            "closure-raw-outcome",
            CurrentFinalVerificationTerminationV1::Exited { code: 0 },
            40,
        );
        let transaction = ledger
            .connection
            .transaction()
            .expect("start capture transaction");
        insert_current_capture(&transaction, &capture).expect("insert exact capture");
        transaction.commit().expect("commit exact capture");
        let capture_bytes = encode_ledger("raw outcome capture", &capture).expect("encode capture");
        let forged = CurrentFinalVerificationOutcomeV1 {
            outcome_version: CURRENT_OUTCOME_VERSION_V1,
            outcome_id: mint_identity(OUTCOME_ID_DOMAIN, &capture_bytes),
            sprint_id: capture.sprint_id.clone(),
            attempt_id: capture.attempt_id.clone(),
            closure_id: capture.closure_id.clone(),
            outcome: CurrentFinalVerificationOutcomeKindV1::Unknown,
            terminal_at_unix_ms: capture.terminal_at_unix_ms,
        };
        let crossed_projection = ledger.connection.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, 'Verified', NULL, ?5, ?6)",
            params![
                forged.outcome_id,
                forged.sprint_id,
                forged.attempt_id,
                forged.closure_id,
                i64::try_from(forged.terminal_at_unix_ms).expect("timestamp fits"),
                encode_ledger("forged outcome", &forged).expect("encode forged outcome"),
            ],
        );
        assert!(crossed_projection.is_err());
        let substituted_unknown = ledger.connection.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, 'Unknown', NULL, ?5, ?6)",
            params![
                forged.outcome_id,
                forged.sprint_id,
                forged.attempt_id,
                forged.closure_id,
                i64::try_from(forged.terminal_at_unix_ms).expect("timestamp fits"),
                encode_ledger("forged outcome", &forged).expect("encode forged outcome"),
            ],
        );
        assert!(substituted_unknown.is_err());

        let (_database, mut verified, _, _) =
            create_current_ledger("raw-terminal", "sprint-raw-terminal", 1);
        let attempt = verified
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-raw-terminal",
                "admit-raw-terminal",
                task_set("sprint-raw-terminal", 'c', None, 20),
                criterion_set("sprint-raw-terminal", 'c', 1, 21),
                30,
            ))
            .expect("admit raw terminal fixture");
        let outcome = verified
            .close_current_final_verification_attempt_v32(&clean_capture(
                &attempt.authority,
                "closure-raw-terminal",
                CurrentFinalVerificationTerminationV1::Exited { code: 0 },
                40,
            ))
            .expect("close verified fixture");
        let false_exhaustion = verified.connection.execute(
            "INSERT INTO current_sprint_terminal_outcomes_v32 (
                sprint_id, terminal_state, source_attempt_id, source_outcome_id,
                terminal_reason, terminal_at_unix_ms
             ) VALUES (?1, 'Failed', ?2, ?3,
                       'FinalVerificationAttemptsExhausted', ?4)",
            params![
                attempt.authority.sprint_id,
                attempt.authority.attempt_id,
                outcome.outcome_id,
                i64::try_from(outcome.terminal_at_unix_ms).expect("timestamp fits"),
            ],
        );
        assert!(false_exhaustion.is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // The direct-SQL matrix preserves every exact control, custody, and outcome projection inline.
    fn v32_direct_sql_cancel_classification_matches_the_authenticated_effect_cut() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("raw-cancel-known", "sprint-raw-cancel-known", 3);
        let attempt = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-raw-cancel-known",
                "admit-raw-cancel-known",
                task_set("sprint-raw-cancel-known", 'c', None, 20),
                criterion_set("sprint-raw-cancel-known", 'c', 1, 21),
                30,
            ))
            .expect("admit known cancellation fixture");
        let control = ledger
            .record_current_final_verification_control_v32(
                &attempt.authority.attempt_id,
                CurrentFinalVerificationControlKindV1::Cancel,
                false,
                35,
            )
            .expect("record after-effect cancellation");
        let capture = CurrentFinalVerificationCaptureClosureV1 {
            closure_version: CURRENT_OUTCOME_VERSION_V1,
            closure_id: "closure-raw-cancel-known".into(),
            sprint_id: "sprint-raw-cancel-known".into(),
            attempt_id: attempt.authority.attempt_id.clone(),
            termination: CurrentFinalVerificationTerminationV1::Canceled {
                control_id: control.control_id.clone(),
            },
            output_custody: CurrentFinalVerificationOutputCustodyV1::AbandonedSensitive {
                rejection_closure_id: "raw-cancel-sensitive-closure".into(),
            },
            runner_cleanup_proof_id: Some("raw-cancel-runner-clean".into()),
            command_domain_cleanup_proof_id: Some("raw-cancel-domain-clean".into()),
            terminal_at_unix_ms: 40,
        };
        let transaction = ledger
            .connection
            .transaction()
            .expect("start known cancel capture transaction");
        insert_current_capture(&transaction, &capture).expect("insert known cancel capture");
        transaction.commit().expect("commit known cancel capture");
        let capture_bytes =
            encode_ledger("raw known cancel capture", &capture).expect("encode cancel capture");
        let mut outcome = CurrentFinalVerificationOutcomeV1 {
            outcome_version: CURRENT_OUTCOME_VERSION_V1,
            outcome_id: mint_identity(OUTCOME_ID_DOMAIN, &capture_bytes),
            sprint_id: capture.sprint_id.clone(),
            attempt_id: capture.attempt_id.clone(),
            closure_id: capture.closure_id.clone(),
            outcome: CurrentFinalVerificationOutcomeKindV1::SensitiveOutputRejected,
            terminal_at_unix_ms: capture.terminal_at_unix_ms,
        };
        let sensitive_substitution = ledger.connection.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, 'SensitiveOutputRejected', NULL, ?5, ?6)",
            params![
                outcome.outcome_id,
                outcome.sprint_id,
                outcome.attempt_id,
                outcome.closure_id,
                i64::try_from(outcome.terminal_at_unix_ms).expect("timestamp fits"),
                encode_ledger("sensitive cancel substitution", &outcome)
                    .expect("encode sensitive substitution"),
            ],
        );
        assert!(sensitive_substitution.is_err());

        outcome.outcome = CurrentFinalVerificationOutcomeKindV1::Unknown;
        let unknown_substitution = ledger.connection.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, 'Unknown', NULL, ?5, ?6)",
            params![
                outcome.outcome_id,
                outcome.sprint_id,
                outcome.attempt_id,
                outcome.closure_id,
                i64::try_from(outcome.terminal_at_unix_ms).expect("timestamp fits"),
                encode_ledger("unknown cancel substitution", &outcome)
                    .expect("encode unknown substitution"),
            ],
        );
        assert!(unknown_substitution.is_err());

        outcome.outcome = CurrentFinalVerificationOutcomeKindV1::Canceled {
            control_id: control.control_id,
        };
        ledger
            .connection
            .execute(
                "INSERT INTO current_final_verification_outcomes_v32 (
                    outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                    outcome_code, terminal_at_unix_ms, outcome_json
                 ) VALUES (?1, ?2, ?3, ?4, 'Canceled', NULL, ?5, ?6)",
                params![
                    outcome.outcome_id,
                    outcome.sprint_id,
                    outcome.attempt_id,
                    outcome.closure_id,
                    i64::try_from(outcome.terminal_at_unix_ms).expect("timestamp fits"),
                    encode_ledger("exact canceled outcome", &outcome)
                        .expect("encode canceled outcome"),
                ],
            )
            .expect("SQL accepts the exact typed canceled outcome");
        assert_eq!(
            ledger
                .load_current_final_verification_attempt_v32(&attempt.authority.attempt_id)
                .expect("load exact direct-SQL canceled outcome")
                .outcome,
            Some(outcome)
        );

        let (_database, mut mismatched, _, _) =
            create_current_ledger("raw-cancel-mismatch", "sprint-raw-cancel-mismatch", 3);
        let attempt = mismatched
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-raw-cancel-mismatch",
                "admit-raw-cancel-mismatch",
                task_set("sprint-raw-cancel-mismatch", 'c', None, 20),
                criterion_set("sprint-raw-cancel-mismatch", 'c', 1, 21),
                30,
            ))
            .expect("admit mismatched cancellation fixture");
        let control = mismatched
            .record_current_final_verification_control_v32(
                &attempt.authority.attempt_id,
                CurrentFinalVerificationControlKindV1::Cancel,
                true,
                35,
            )
            .expect("record before-effect cancellation");
        let capture = CurrentFinalVerificationCaptureClosureV1 {
            closure_version: CURRENT_OUTCOME_VERSION_V1,
            closure_id: "closure-raw-cancel-mismatch".into(),
            sprint_id: "sprint-raw-cancel-mismatch".into(),
            attempt_id: attempt.authority.attempt_id,
            termination: CurrentFinalVerificationTerminationV1::Canceled {
                control_id: control.control_id.clone(),
            },
            output_custody: CurrentFinalVerificationOutputCustodyV1::PublishedClean {
                publication_receipt_id: "raw-before-effect-published".into(),
            },
            runner_cleanup_proof_id: Some("raw-mismatch-runner-clean".into()),
            command_domain_cleanup_proof_id: Some("raw-mismatch-domain-clean".into()),
            terminal_at_unix_ms: 40,
        };
        let transaction = mismatched
            .connection
            .transaction()
            .expect("start mismatched cancel transaction");
        insert_current_capture(&transaction, &capture).expect("insert mismatched cancel capture");
        transaction
            .commit()
            .expect("commit mismatched cancel capture");
        let forged = CurrentFinalVerificationOutcomeV1 {
            outcome_version: CURRENT_OUTCOME_VERSION_V1,
            outcome_id: mint_identity(
                OUTCOME_ID_DOMAIN,
                &encode_ledger("raw mismatched cancel capture", &capture)
                    .expect("encode mismatched capture"),
            ),
            sprint_id: capture.sprint_id,
            attempt_id: capture.attempt_id,
            closure_id: capture.closure_id,
            outcome: CurrentFinalVerificationOutcomeKindV1::Canceled {
                control_id: control.control_id,
            },
            terminal_at_unix_ms: capture.terminal_at_unix_ms,
        };
        let false_canceled = mismatched.connection.execute(
            "INSERT INTO current_final_verification_outcomes_v32 (
                outcome_id, sprint_id, attempt_id, closure_id, outcome_kind,
                outcome_code, terminal_at_unix_ms, outcome_json
             ) VALUES (?1, ?2, ?3, ?4, 'Canceled', NULL, ?5, ?6)",
            params![
                forged.outcome_id,
                forged.sprint_id,
                forged.attempt_id,
                forged.closure_id,
                i64::try_from(forged.terminal_at_unix_ms).expect("timestamp fits"),
                encode_ledger("false canceled outcome", &forged)
                    .expect("encode false canceled outcome"),
            ],
        );
        assert!(false_canceled.is_err());
    }

    #[test]
    fn v32_control_cause_is_exact_and_direct_sql_cannot_skip_attempt_or_forge_repair() {
        let (_database, mut ledger, _, _) = create_current_ledger("control", "sprint-control", 3);
        let tasks = task_set("sprint-control", 'c', None, 20);
        let criteria = criterion_set("sprint-control", 'c', 1, 21);
        let first = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-control",
                "admit-control-1",
                tasks.clone(),
                criteria.clone(),
                30,
            ))
            .expect("admit controlled attempt");
        let control = ledger
            .record_current_final_verification_control_v32(
                &first.authority.attempt_id,
                CurrentFinalVerificationControlKindV1::Pause,
                true,
                35,
            )
            .expect("record authenticated pre-effect pause");
        let capture = CurrentFinalVerificationCaptureClosureV1 {
            closure_version: CURRENT_OUTCOME_VERSION_V1,
            closure_id: "closure-control".into(),
            sprint_id: "sprint-control".into(),
            attempt_id: first.authority.attempt_id.clone(),
            termination: CurrentFinalVerificationTerminationV1::InterruptedBeforeEffect {
                control_id: control.control_id.clone(),
            },
            output_custody: CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                closure_receipt_id: "pre-effect-capture-closed".into(),
            },
            runner_cleanup_proof_id: Some("runner-clean-control".into()),
            command_domain_cleanup_proof_id: Some("domain-clean-control".into()),
            terminal_at_unix_ms: 40,
        };
        let outcome = ledger
            .close_current_final_verification_attempt_v32(&capture)
            .expect("close authenticated pre-effect interruption");
        assert!(matches!(
            outcome.outcome,
            CurrentFinalVerificationOutcomeKindV1::ControlInterruptedBeforeEffect {
                ref control_id
            } if control_id == &control.control_id
        ));
        let second = ledger
            .admit_current_final_verification_attempt_v32(&admission_request(
                "sprint-control",
                "admit-control-2",
                tasks,
                criteria,
                50,
            ))
            .expect("same-snapshot continuation");
        assert_eq!(second.authority.attempt_ordinal, 2);

        let raw_skip = ledger.connection.execute(
            "INSERT INTO current_final_verification_attempts_v32 (
                attempt_id, request_id, request_digest, request_json, sprint_id,
                attempt_ordinal, max_final_verification_attempts,
                final_verification_admission_id, input_snapshot,
                complete_task_done_set_digest,
                complete_criterion_evidence_set_digest, predecessor_kind,
                authority_digest, admitted_at_unix_ms, authority_json
             ) SELECT 'raw-skip', 'raw-skip-request', request_digest, request_json, sprint_id,
                      3, max_final_verification_attempts, 'raw-skip-admission',
                      input_snapshot, complete_task_done_set_digest,
                      complete_criterion_evidence_set_digest, 'Initial',
                      authority_digest, admitted_at_unix_ms, authority_json
               FROM current_final_verification_attempts_v32 WHERE attempt_id = ?1",
            [second.authority.attempt_id.as_str()],
        );
        assert!(raw_skip.is_err());

        let raw_repair = ledger.connection.execute(
            "INSERT INTO current_final_verification_repair_completions_v32 (
                completion_id, request_id, request_digest, sprint_id,
                activation_id, failed_attempt_id, repair_task_id,
                repair_task_done_proof_id, integration_receipt_id,
                input_snapshot, result_snapshot, change_set_id, operation_count,
                complete_task_done_set_digest,
                complete_criterion_evidence_set_digest,
                completed_at_unix_ms, completion_json
             ) VALUES (
                'raw-repair', 'raw-repair-request', ?1, 'sprint-control',
                'missing-activation', ?2, 'repair-1', 'raw-proof',
                'raw-integration', ?3, ?4, 'raw-change', 1, ?5, ?6, 60, x'7b7d'
             )",
            params![
                digest('1').as_str(),
                second.authority.attempt_id,
                digest('c').as_str(),
                digest('d').as_str(),
                second.authority.complete_task_done_set_digest.as_str(),
                second
                    .authority
                    .complete_criterion_evidence_set_digest
                    .as_str(),
            ],
        );
        assert!(raw_repair.is_err());
    }

    #[test]
    fn v34_t0_admission_replays_and_ignores_later_diagnostic_outcome() {
        let (database, mut ledger, _, _) = create_current_ledger("v34-t0", "sprint-v34-t0", 3);
        let request = admission_request(
            "sprint-v34-t0",
            "request-v34-t0",
            task_set("sprint-v34-t0", 'c', None, 20),
            criterion_set("sprint-v34-t0", 'c', 1, 21),
            30,
        );
        let admitted = ledger
            .admit_operational_current_final_verification_attempt_v34(&request)
            .expect("admit one exact operational attempt");
        assert_eq!(admitted.attempt.authority.attempt_ordinal, 1);
        assert_eq!(admitted.admission_event.event_sequence, 1);
        assert_eq!(
            admitted.admission_event.event_kind,
            CurrentFinalVerificationAuthorityEventKindV1::AttemptAdmitted
        );
        assert_ne!(
            admitted.admission_event.event_id,
            admitted.attempt.authority.provenance.admission_event_id
        );
        assert_eq!(
            admitted,
            ledger
                .admit_operational_current_final_verification_attempt_v34(&request)
                .expect("exact request replay is readback only")
        );
        for table in [
            "current_final_verification_attempts_v32",
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = ledger
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count exact admission rows");
            assert_eq!(count, 1, "{table}");
        }

        ledger
            .close_current_final_verification_attempt_v32(&clean_capture(
                &admitted.attempt.authority,
                "diagnostic-v32-closure",
                CurrentFinalVerificationTerminationV1::Exited { code: 7 },
                40,
            ))
            .expect("close later diagnostic v32 outcome");
        assert_eq!(
            admitted,
            ledger
                .load_operational_current_final_verification_attempt_v34(
                    &admitted.attempt.authority.attempt_id,
                )
                .expect("operational readback excludes diagnostic outcome")
        );
        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path).expect("reopen v34 read-only");
        assert_eq!(
            admitted,
            reader
                .load_operational_current_final_verification_attempt_v34(
                    &admitted.attempt.authority.attempt_id,
                )
                .expect("read operational admission after restart")
        );
    }

    #[test]
    fn v34_rejects_currently_unlaunchable_commands_before_creating_any_row() {
        for (ordinal, program) in ["./cargo", "nu"].into_iter().enumerate() {
            let diagnostic_sprint = format!("sprint-v32-diagnostic-command-{ordinal}");
            let (_database, mut diagnostic, _, _) = create_current_ledger(
                &format!("v32-diagnostic-command-{ordinal}"),
                &diagnostic_sprint,
                3,
            );
            let mut diagnostic_request = admission_request(
                &diagnostic_sprint,
                &format!("request-v32-diagnostic-command-{ordinal}"),
                task_set(&diagnostic_sprint, 'c', None, 20),
                criterion_set(&diagnostic_sprint, 'c', 1, 21),
                30,
            );
            diagnostic_request.final_verification_check.program = program.into();
            diagnostic
                .admit_current_final_verification_attempt_v32(&diagnostic_request)
                .expect(
                    "schema-v32 diagnostic contract retains its exact historical command shape",
                );
            assert_eq!(
                diagnostic
                    .connection
                    .query_row(
                        "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("count diagnostic attempt"),
                1,
            );

            let operational_sprint = format!("sprint-v34-current-command-{ordinal}");
            let (_database, mut operational, _, _) = create_current_ledger(
                &format!("v34-current-command-{ordinal}"),
                &operational_sprint,
                3,
            );
            let mut operational_request = admission_request(
                &operational_sprint,
                &format!("request-v34-current-command-{ordinal}"),
                task_set(&operational_sprint, 'c', None, 20),
                criterion_set(&operational_sprint, 'c', 1, 21),
                30,
            );
            operational_request.final_verification_check.program = program.into();
            assert!(
                operational
                    .admit_operational_current_final_verification_attempt_v34(&operational_request,)
                    .is_err(),
                "operational v34 admitted command {program} that native/V13 cannot represent",
            );
            assert_v34_admission_row_count(
                &operational.connection,
                0,
                "unlaunchable command must fail before mutation",
            );
        }
    }

    #[test]
    fn v34_rejects_diagnostic_backfill_and_keeps_successors_dormant() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("v34-no-backfill", "sprint-v34-no-backfill", 3);
        let request = admission_request(
            "sprint-v34-no-backfill",
            "request-v34-diagnostic",
            task_set("sprint-v34-no-backfill", 'c', None, 20),
            criterion_set("sprint-v34-no-backfill", 'c', 1, 21),
            30,
        );
        ledger
            .admit_current_final_verification_attempt_v32(&request)
            .expect("create source-only diagnostic parent");
        let error = ledger
            .admit_operational_current_final_verification_attempt_v34(&request)
            .expect_err("schema-v32 attempt cannot be operationally backfilled");
        assert!(
            error
                .to_string()
                .contains("cannot be operationally backfilled")
        );
        for table in [
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = ledger
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count no-backfill rows");
            assert_eq!(count, 0, "{table}");
        }

        let (_database, mut ledger, _, _) =
            create_current_ledger("v34-successor", "sprint-v34-successor", 3);
        let first_request = admission_request(
            "sprint-v34-successor",
            "request-v34-first",
            task_set("sprint-v34-successor", 'c', None, 20),
            criterion_set("sprint-v34-successor", 'c', 1, 21),
            30,
        );
        let first = ledger
            .admit_operational_current_final_verification_attempt_v34(&first_request)
            .expect("admit first operational attempt");
        ledger
            .close_current_final_verification_attempt_v32(&clean_capture(
                &first.attempt.authority,
                "diagnostic-successor-closure",
                CurrentFinalVerificationTerminationV1::Exited { code: 9 },
                40,
            ))
            .expect("record caller-facing diagnostic v32 outcome");
        let second_request = admission_request(
            "sprint-v34-successor",
            "request-v34-second",
            task_set("sprint-v34-successor", 'c', None, 20),
            criterion_set("sprint-v34-successor", 'c', 1, 21),
            50,
        );
        let error = ledger
            .admit_operational_current_final_verification_attempt_v34(&second_request)
            .expect_err("diagnostic outcome cannot authorize successor");
        assert!(error.to_string().contains("successor admission is dormant"));
        let attempt_count = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count first-only attempts");
        assert_eq!(attempt_count, 1);
    }

    #[test]
    fn v34_gap_oversize_and_crash_cuts_roll_back_every_admission_row() {
        let (database, mut ledger, _, _) =
            create_current_ledger("v34-rollback", "sprint-v34-rollback", 3);
        let request = admission_request(
            "sprint-v34-rollback",
            "request-v34-rollback",
            task_set("sprint-v34-rollback", 'c', None, 20),
            criterion_set("sprint-v34-rollback", 'c', 1, 21),
            30,
        );
        {
            let request_bytes = request.canonical_bytes().expect("canonical request");
            let request_digest = request.canonical_digest().expect("request digest");
            let transaction = ledger
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin crash-cut transaction");
            let current = load_current_sprint_authority(&transaction, &request.sprint_id)
                .expect("load current authority");
            let admitted = admit_current_final_verification_attempt_in_transaction_v32(
                &transaction,
                &request,
                &request_bytes,
                &request_digest,
            )
            .expect("create transactional v32 parent");
            let gap_event = CurrentFinalVerificationAuthorityEventV1::try_new(
                &admitted.persisted,
                request_digest,
                2,
            )
            .expect("derive deliberately gapped event");
            let operational = OperationalCurrentFinalVerificationAttemptV1::try_new(
                &request,
                &current,
                &admitted.persisted,
                &gap_event,
            )
            .expect("derive deliberately gapped overlay");
            let error = with_operational_admission_write_guard(
                OperationalAdmissionWriteGuardV1 {
                    attempt_id: admitted.persisted.authority.attempt_id.clone(),
                    event_digest: gap_event.event_digest.clone(),
                    operational_attempt_digest: operational.operational_attempt_digest,
                },
                || insert_operational_event_v34(&transaction, &gap_event),
            )
            .expect_err("gapped sequence must fail inside SQL");
            assert!(error.to_string().contains("contiguous"));
        }
        for table in [
            "current_final_verification_attempts_v32",
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = ledger
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count crash rollback rows");
            assert_eq!(count, 0, "{table}");
        }

        let mut oversized = request;
        oversized.request_id = "x".repeat(MAX_CURRENT_FINAL_VERIFICATION_IDENTIFIER_BYTES_V2 + 1);
        ledger
            .admit_operational_current_final_verification_attempt_v34(&oversized)
            .expect_err("oversized downstream identity must fail closed");
        let attempt_count = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_attempts_v32",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count oversized rollback rows");
        assert_eq!(attempt_count, 0);
        drop(ledger);
        let reader = EventLedger::open_read_only(&database.path)
            .expect("reopen rolled-back operational database read-only");
        for table in [
            "current_final_verification_attempts_v32",
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = reader
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("read rolled-back rows after restart");
            assert_eq!(count, 0, "{table}");
        }
    }

    #[test]
    fn v34_event_and_overlay_precommit_crash_cuts_leave_no_partial_admission() {
        run_v34_event_only_precommit_crash_cut();
        run_v34_overlay_precommit_crash_cut();
    }

    #[test]
    fn v34_no_replace_guards_cover_every_declared_identity_independently() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("v34-no-replace", "sprint-v34-no-replace", 3);
        let admitted = ledger
            .admit_operational_current_final_verification_attempt_v34(&admission_request(
                "sprint-v34-no-replace",
                "request-v34-no-replace",
                task_set("sprint-v34-no-replace", 'c', None, 20),
                criterion_set("sprint-v34-no-replace", 'c', 1, 21),
                30,
            ))
            .expect("admit replacement fixture");
        assert_v34_no_replace_trigger_declares_every_identity(&ledger.connection);
        ledger
            .connection
            .execute_batch(
                "PRAGMA recursive_triggers = OFF;
                 DROP TRIGGER current_final_verification_events_v34_validate_insert;",
            )
            .expect("isolate no-replace triggers for adversarial replacement");
        for target in V34EventIdentity::ALL {
            assert_v34_event_identity_replacement_blocked(&ledger.connection, &admitted, target);
            assert_eq!(
                admitted,
                ledger
                    .load_operational_current_final_verification_attempt_v34(
                        &admitted.attempt.authority.attempt_id,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{target:?}: event replacement changed readback: {error}")
                    })
            );
        }
        for target in V34OperationalIdentity::ALL {
            assert_v34_operational_identity_replacement_blocked(
                &ledger.connection,
                &admitted,
                target,
            );
            assert_eq!(
                admitted,
                ledger
                    .load_operational_current_final_verification_attempt_v34(
                        &admitted.attempt.authority.attempt_id,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{target:?}: overlay replacement changed readback: {error}")
                    })
            );
        }
        assert_v34_admission_row_count(&ledger.connection, 1, "all no-replace cases");
    }

    #[test]
    fn v34_private_writer_guard_still_rejects_a_diagnostic_successor() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("v34-direct-successor", "sprint-v34-direct-successor", 3);
        let tasks = task_set("sprint-v34-direct-successor", 'c', None, 20);
        let criteria = criterion_set("sprint-v34-direct-successor", 'c', 1, 21);
        let first = ledger
            .admit_operational_current_final_verification_attempt_v34(&admission_request(
                "sprint-v34-direct-successor",
                "request-v34-direct-first",
                tasks.clone(),
                criteria.clone(),
                30,
            ))
            .expect("admit first operational attempt");
        let control = ledger
            .record_current_final_verification_control_v32(
                &first.attempt.authority.attempt_id,
                CurrentFinalVerificationControlKindV1::Pause,
                true,
                35,
            )
            .expect("record diagnostic pre-effect pause");
        ledger
            .close_current_final_verification_attempt_v32(
                &CurrentFinalVerificationCaptureClosureV1 {
                    closure_version: CURRENT_OUTCOME_VERSION_V1,
                    closure_id: "v34-direct-first-closure".into(),
                    sprint_id: "sprint-v34-direct-successor".into(),
                    attempt_id: first.attempt.authority.attempt_id,
                    termination: CurrentFinalVerificationTerminationV1::InterruptedBeforeEffect {
                        control_id: control.control_id,
                    },
                    output_custody: CurrentFinalVerificationOutputCustodyV1::ClosedBeforeCapture {
                        closure_receipt_id: "v34-direct-first-custody".into(),
                    },
                    runner_cleanup_proof_id: Some("v34-direct-first-runner-clean".into()),
                    command_domain_cleanup_proof_id: Some("v34-direct-first-domain-clean".into()),
                    terminal_at_unix_ms: 40,
                },
            )
            .expect("close diagnostic pre-effect pause");
        let second_request = admission_request(
            "sprint-v34-direct-successor",
            "request-v34-direct-second",
            tasks,
            criteria,
            50,
        );
        let second = ledger
            .admit_current_final_verification_attempt_v32(&second_request)
            .expect("legacy source-only path can still create diagnostic successor");
        assert_eq!(second.authority.attempt_ordinal, 2);

        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin adversarial direct transaction");
        let current = load_current_sprint_authority(&transaction, &second_request.sprint_id)
            .expect("load current successor authority");
        let event = CurrentFinalVerificationAuthorityEventV1::try_new(
            &second,
            second_request
                .canonical_digest()
                .expect("second request digest"),
            2,
        )
        .expect("derive second event");
        let operational = OperationalCurrentFinalVerificationAttemptV1::try_new(
            &second_request,
            &current,
            &second,
            &event,
        )
        .expect("derive second overlay");
        let error = with_operational_admission_write_guard(
            OperationalAdmissionWriteGuardV1 {
                attempt_id: second.authority.attempt_id,
                event_digest: event.event_digest.clone(),
                operational_attempt_digest: operational.operational_attempt_digest.clone(),
            },
            || {
                insert_operational_event_v34(&transaction, &event)?;
                insert_operational_attempt_v34(&transaction, &operational)
            },
        )
        .expect_err("SQL first-only fence rejects even a privately admitted successor");
        assert!(error.to_string().contains("first-only T0 admission"));
        drop(transaction);
        for table in [
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = ledger
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count first-only rows");
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn v34_concurrent_exact_request_has_one_atomic_admission_and_one_readback() {
        let (database, ledger, _, _) =
            create_current_ledger("v34-concurrent", "sprint-v34-concurrent", 3);
        drop(ledger);
        let request = Arc::new(admission_request(
            "sprint-v34-concurrent",
            "request-v34-concurrent",
            task_set("sprint-v34-concurrent", 'c', None, 20),
            criterion_set("sprint-v34-concurrent", 'c', 1, 21),
            30,
        ));
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = database.path.clone();
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut ledger = EventLedger::open(path).expect("open concurrent v34 writer");
                barrier.wait();
                ledger.admit_operational_current_final_verification_attempt_v34(&request)
            }));
        }
        let first = handles
            .remove(0)
            .join()
            .expect("join first writer")
            .expect("first writer succeeds");
        let second = handles
            .remove(0)
            .join()
            .expect("join second writer")
            .expect("second writer returns exact replay");
        assert_eq!(first, second);
        let reader = EventLedger::open_read_only(&database.path).expect("reopen concurrency DB");
        for table in [
            "current_final_verification_attempts_v32",
            "current_final_verification_events_v34",
            "current_final_verification_operational_attempts_v34",
        ] {
            let count = reader
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("count concurrent rows");
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn v34_reserves_future_event_kinds_but_writer_accepts_only_attempt_admitted() {
        let (_database, mut ledger, _, _) =
            create_current_ledger("v34-event-kinds", "sprint-v34-event-kinds", 3);
        let admitted = ledger
            .admit_operational_current_final_verification_attempt_v34(&admission_request(
                "sprint-v34-event-kinds",
                "request-v34-event-kinds",
                task_set("sprint-v34-event-kinds", 'c', None, 20),
                criterion_set("sprint-v34-event-kinds", 'c', 1, 21),
                30,
            ))
            .expect("admit event-kind fixture");
        let table_sql = ledger
            .connection
            .query_row(
                "SELECT sql FROM sqlite_schema
                 WHERE type = 'table' AND name = 'current_final_verification_events_v34'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read event table schema");
        assert!(table_sql.contains("'LaunchCommitted'"));
        assert!(!table_sql.contains("'UnknownEventKind'"));

        let mut future = admitted.admission_event.clone();
        future.event_sequence = 2;
        future.event_kind = CurrentFinalVerificationAuthorityEventKindV1::LaunchCommitted;
        future.event_id = future.computed_event_id().expect("derive future event id");
        future.event_digest = future
            .computed_event_digest()
            .expect("derive future event digest");
        future
            .validate_integrity()
            .expect("future kind is schema-valid");
        let transaction = ledger
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin future-kind transaction");
        let error = with_operational_admission_write_guard(
            OperationalAdmissionWriteGuardV1 {
                attempt_id: future.attempt_id.clone(),
                event_digest: future.event_digest.clone(),
                operational_attempt_digest: admitted
                    .operational_attempt
                    .operational_attempt_digest
                    .clone(),
            },
            || insert_operational_event_v34(&transaction, &future),
        )
        .expect_err("v34 T0 writer rejects reserved future kinds");
        assert!(
            error
                .to_string()
                .contains("event kind lacks exact current writer authority"),
            "reserved event kind escaped the current closed writer frontier: {error}"
        );
        drop(transaction);

        let mut unknown: serde_json::Value = serde_json::from_slice(
            &admitted
                .admission_event
                .canonical_bytes()
                .expect("canonical admission event"),
        )
        .expect("decode event value");
        unknown["event_kind"] = serde_json::Value::String("unknown_event_kind".into());
        let unknown_bytes = serde_json::to_vec(&unknown).expect("encode unknown-kind bytes");
        assert!(sqlite_operational_event_canonical(&unknown_bytes).is_err());
        unknown["event_kind"] = serde_json::Value::String("attempt_admitted".into());
        unknown["unexpected"] = serde_json::Value::Bool(true);
        let unknown_field_bytes = serde_json::to_vec(&unknown).expect("encode unknown-field bytes");
        assert!(sqlite_operational_event_canonical(&unknown_field_bytes).is_err());

        let event_count = ledger
            .connection
            .query_row(
                "SELECT COUNT(*) FROM current_final_verification_events_v34",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count retained admission event");
        assert_eq!(event_count, 1);
    }
