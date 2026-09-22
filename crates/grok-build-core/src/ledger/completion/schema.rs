/// Fails before a schema-text migration can mutate a divergent source image.
///
/// This is stronger than checking the edited DDL after the fact: the complete
/// ordered source schema must equal a pristine repository-built schema at the
/// exact preceding generation.
pub(super) fn validate_schema_matches_migrations_through(
    connection: &Connection,
    migration_count: usize,
) -> Result<(), LedgerError> {
    let actual = load_schema_objects(connection)?;
    let expected = build_expected_schema_objects_through(migration_count)?;
    compare_schema_objects_to_migration_source(&actual, &expected, migration_count)
}

/// Builds the pristine expected schema-object inventory produced by applying
/// the first `migration_count` migrations (with the v32 module interleavings)
/// to an empty in-memory database.
pub(super) fn build_expected_schema_objects_through(
    migration_count: usize,
) -> Result<Vec<SchemaObject>, LedgerError> {
    let expected_connection = Connection::open_in_memory()?;
    register_schema_functions(&expected_connection)?;
    for (index, migration) in MIGRATIONS.iter().take(migration_count).enumerate() {
        expected_connection.execute_batch(migration)?;
        if index == 31 {
            expected_connection.execute_batch(current_criterion_evidence_v32::MIGRATION_V32)?;
            expected_connection.execute_batch(current_task_done_source_v32::MIGRATION_V32)?;
            expected_connection.execute_batch(current_repair_task_authority_v32::MIGRATION_V32)?;
        }
    }
    load_schema_objects(&expected_connection)
}

/// Compares a loaded schema inventory against the expected pristine image at
/// `migration_count`, failing with the exact migration-source error.
pub(super) fn compare_schema_objects_to_migration_source(
    actual: &[SchemaObject],
    expected: &[SchemaObject],
    migration_count: usize,
) -> Result<(), LedgerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LedgerError::Corrupt {
            entity: "ledger schema migration source",
            detail: format!(
                "schema objects differ from the exact version {migration_count} source image"
            ),
        })
    }
}

#[allow(clippy::too_many_lines)] // Exact deterministic SQL validators are registered in one auditable boundary.
pub(super) fn register_schema_functions(connection: &Connection) -> Result<(), LedgerError> {
    for (name, validate) in [
        (
            "grok_sprint_spec_v32_canonical",
            final_verification_authority_v32::sqlite_sprint_spec_canonical
                as fn(&[u8]) -> Result<i64, String>,
        ),
        (
            "grok_task_done_set_v32_canonical",
            final_verification_authority_v32::sqlite_task_done_set_canonical,
        ),
        (
            "grok_criterion_evidence_set_v32_canonical",
            final_verification_authority_v32::sqlite_criterion_evidence_set_canonical,
        ),
        (
            "grok_final_verification_admission_request_v32_canonical",
            final_verification_authority_v32::sqlite_admission_request_canonical,
        ),
        (
            "grok_final_verification_attempt_v32_canonical",
            final_verification_authority_v32::sqlite_attempt_canonical,
        ),
        (
            "grok_final_verification_capture_v32_canonical",
            final_verification_authority_v32::sqlite_capture_canonical,
        ),
        (
            "grok_final_verification_control_v32_canonical",
            final_verification_authority_v32::sqlite_control_canonical,
        ),
        (
            "grok_final_verification_outcome_v32_canonical",
            final_verification_authority_v32::sqlite_outcome_canonical,
        ),
        (
            "grok_final_verification_repair_activation_v32_canonical",
            final_verification_authority_v32::sqlite_repair_activation_canonical,
        ),
        (
            "grok_final_verification_repair_completion_v32_canonical",
            final_verification_authority_v32::sqlite_repair_completion_canonical,
        ),
        (
            "grok_current_final_verification_event_v34_canonical",
            final_verification_authority_v32::sqlite_operational_event_canonical,
        ),
        (
            "grok_current_final_verification_operational_attempt_v34_canonical",
            final_verification_authority_v32::sqlite_operational_attempt_canonical,
        ),
        (
            "grok_current_final_verification_launch_request_v35_canonical",
            current_final_verification_launch_v35::sqlite_launch_request_canonical,
        ),
        (
            "grok_current_final_verification_reservations_v35_canonical",
            current_final_verification_launch_v35::sqlite_reservations_canonical,
        ),
        (
            "grok_current_final_verification_launch_v35_canonical",
            current_final_verification_launch_v35::sqlite_launch_canonical,
        ),
        (
            "grok_current_final_verification_capture_request_v36_canonical",
            current_final_verification_capture_v36::sqlite_capture_request_canonical,
        ),
        (
            "grok_command_output_capture_acquired_v36_canonical",
            current_final_verification_capture_v36::sqlite_acquired_canonical,
        ),
        (
            "grok_current_final_verification_capture_v36_canonical",
            current_final_verification_capture_v36::sqlite_capture_canonical,
        ),
    ] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let bytes = context.get::<Vec<u8>>(0)?;
                validate(&bytes).map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
            },
        )?;
    }
    for (name, digest) in [
        (
            "grok_sprint_spec_v32_digest",
            final_verification_authority_v32::sqlite_sprint_spec_digest
                as fn(&[u8]) -> Result<String, String>,
        ),
        (
            "grok_task_done_set_v32_digest",
            final_verification_authority_v32::sqlite_task_done_set_digest,
        ),
        (
            "grok_criterion_evidence_set_v32_digest",
            final_verification_authority_v32::sqlite_criterion_evidence_set_digest,
        ),
        (
            "grok_final_verification_admission_request_v32_digest",
            final_verification_authority_v32::sqlite_admission_request_digest,
        ),
        (
            "grok_final_verification_attempt_v32_digest",
            final_verification_authority_v32::sqlite_attempt_digest,
        ),
        (
            "grok_current_final_verification_event_v34_digest",
            final_verification_authority_v32::sqlite_operational_event_digest,
        ),
        (
            "grok_current_final_verification_operational_attempt_v34_digest",
            final_verification_authority_v32::sqlite_operational_attempt_digest,
        ),
        (
            "grok_current_final_verification_launch_request_v35_digest",
            current_final_verification_launch_v35::sqlite_launch_request_digest,
        ),
        (
            "grok_current_final_verification_reservations_v35_digest",
            current_final_verification_launch_v35::sqlite_reservations_digest,
        ),
        (
            "grok_current_final_verification_launch_v35_digest",
            current_final_verification_launch_v35::sqlite_launch_digest,
        ),
        (
            "grok_current_final_verification_capture_request_v36_digest",
            current_final_verification_capture_v36::sqlite_capture_request_digest,
        ),
        (
            "grok_command_output_capture_acquired_v36_digest",
            current_final_verification_capture_v36::sqlite_acquired_digest,
        ),
        (
            "grok_current_final_verification_capture_v36_digest",
            current_final_verification_capture_v36::sqlite_capture_digest,
        ),
    ] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let bytes = context.get::<Vec<u8>>(0)?;
                digest(&bytes).map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
            },
        )?;
    }
    connection.create_scalar_function(
        "grok_final_verification_attempt_request_matches_v32",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let request = context.get::<Vec<u8>>(0)?;
            let authority = context.get::<Vec<u8>>(1)?;
            let request_id = context.get::<String>(2)?;
            final_verification_authority_v32::sqlite_attempt_matches_request(
                &request,
                &authority,
                &request_id,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_task_graph_v32_pair_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let graph = context.get::<Vec<u8>>(0)?;
            let sprint = context.get::<Vec<u8>>(1)?;
            final_verification_authority_v32::sqlite_task_graph_pair_canonical(&graph, &sprint)
                .map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_operational_attempt_v34_matches",
        6,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let operational = context.get::<Vec<u8>>(0)?;
            let event = context.get::<Vec<u8>>(1)?;
            let authority = context.get::<Vec<u8>>(2)?;
            let request = context.get::<Vec<u8>>(3)?;
            let sprint = context.get::<Vec<u8>>(4)?;
            let graph = context.get::<Vec<u8>>(5)?;
            final_verification_authority_v32::sqlite_operational_attempt_matches(
                &operational,
                &event,
                &authority,
                &request,
                &sprint,
                &graph,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_operational_write_admitted_v34",
        3,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(
                final_verification_authority_v32::sqlite_operational_write_admitted(
                    context.get::<String>(0)?.as_str(),
                    context.get::<String>(1)?.as_str(),
                    context.get::<String>(2)?.as_str(),
                ),
            )
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_launch_write_admitted_v35",
        3,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(
                current_final_verification_launch_v35::sqlite_launch_write_admitted(
                    context.get::<String>(0)?.as_str(),
                    context.get::<String>(1)?.as_str(),
                    context.get::<String>(2)?.as_str(),
                ),
            )
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_capture_write_admitted_v36",
        3,
        FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(
                current_final_verification_capture_v36::sqlite_capture_write_admitted(
                    context.get::<String>(0)?.as_str(),
                    context.get::<String>(1)?.as_str(),
                    context.get::<String>(2)?.as_str(),
                ),
            )
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_reservation_member_v35",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            current_final_verification_launch_v35::sqlite_reservation_member(
                &context.get::<Vec<u8>>(0)?,
                context.get::<String>(1)?.as_str(),
                context.get::<String>(2)?.as_str(),
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_launch_v35_matches",
        5,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            current_final_verification_launch_v35::sqlite_launch_matches(
                &context.get::<Vec<u8>>(0)?,
                &context.get::<Vec<u8>>(1)?,
                &context.get::<Vec<u8>>(2)?,
                &context.get::<Vec<u8>>(3)?,
                &context.get::<Vec<u8>>(4)?,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_current_final_verification_capture_v36_matches",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            current_final_verification_capture_v36::sqlite_capture_matches(
                &context.get::<Vec<u8>>(0)?,
                &context.get::<Vec<u8>>(1)?,
                &context.get::<Vec<u8>>(2)?,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_task_graph_v32_digest",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let graph = context.get::<Vec<u8>>(0)?;
            let sprint = context.get::<Vec<u8>>(1)?;
            final_verification_authority_v32::sqlite_task_graph_digest(&graph, &sprint).map_err(
                |detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                },
            )
        },
    )?;
    connection.create_scalar_function(
        "grok_task_done_set_v32_matches_authority",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let set = context.get::<Vec<u8>>(0)?;
            let sprint = context.get::<Vec<u8>>(1)?;
            let graph = context.get::<Vec<u8>>(2)?;
            final_verification_authority_v32::sqlite_task_done_set_matches_authority(
                &set, &sprint, &graph,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    connection.create_scalar_function(
        "grok_criterion_evidence_set_v32_matches_sprint",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let set = context.get::<Vec<u8>>(0)?;
            let sprint = context.get::<Vec<u8>>(1)?;
            final_verification_authority_v32::sqlite_criterion_evidence_set_matches_sprint(
                &set, &sprint,
            )
            .map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    for (name, validate) in [
        (
            "grok_sensitive_output_policy_v29_canonical",
            sensitive_output_rejection::sqlite_policy_canonical
                as fn(&[u8]) -> Result<String, String>,
        ),
        (
            "grok_sensitive_output_rejection_anchor_v29_digest",
            sensitive_output_rejection::sqlite_anchor_digest,
        ),
        (
            "grok_sensitive_output_clean_scan_v29_digest",
            sensitive_output_rejection::sqlite_clean_scan_digest,
        ),
        (
            "grok_sensitive_output_clean_scan_resolution_v29_digest",
            sensitive_output_rejection::sqlite_clean_scan_resolution_digest,
        ),
        (
            "grok_sensitive_output_cleanup_v29_digest",
            sensitive_output_rejection::sqlite_cleanup_digest,
        ),
        (
            "grok_sensitive_output_closure_v29_digest",
            sensitive_output_rejection::sqlite_closure_digest,
        ),
    ] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let bytes = context.get::<Vec<u8>>(0)?;
                validate(&bytes).map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
            },
        )?;
    }
    connection.create_scalar_function(
        "grok_human_acceptance_prompt_v28_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<HumanAcceptancePromptV1>(&bytes)
                .ok()
                .filter(|prompt| prompt.validate().is_ok())
                .and_then(|prompt| serde_json::to_vec(&prompt).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_human_acceptance_decision_v28_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<HumanAcceptanceDecisionV1>(&bytes)
                .ok()
                .filter(|decision| decision.validate().is_ok())
                .and_then(|decision| serde_json::to_vec(&decision).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_human_acceptance_decision_v28_identity_matches",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let prompt_bytes = context.get::<Vec<u8>>(0)?;
            let decision_bytes = context.get::<Vec<u8>>(1)?;
            let identity_matches = serde_json::from_slice::<HumanAcceptancePromptV1>(&prompt_bytes)
                .ok()
                .zip(serde_json::from_slice::<HumanAcceptanceDecisionV1>(&decision_bytes).ok())
                .filter(|(prompt, decision)| {
                    prompt.validate().is_ok()
                        && decision.validate().is_ok()
                        && serde_json::to_vec(prompt).ok().as_deref()
                            == Some(prompt_bytes.as_slice())
                        && serde_json::to_vec(decision).ok().as_deref()
                            == Some(decision_bytes.as_slice())
                })
                .is_some_and(|(prompt, decision)| {
                    decision.prompt_id == prompt.prompt_id
                        && human_acceptance_decision_id(
                            &prompt,
                            decision.outcome,
                            decision.consumed_event_sequence,
                            decision.decided_at,
                        )
                        .is_ok_and(|expected| expected == decision.decision_id)
                });
            Ok(i64::from(identity_matches))
        },
    )?;
    connection.create_scalar_function(
        "grok_criterion_evidence_receipt_v28_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<CriterionEvidenceReceiptV2>(&bytes)
                .ok()
                .filter(|receipt| receipt.validate().is_ok())
                .and_then(|receipt| serde_json::to_vec(&receipt).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_sprint_spec_v27_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<SprintSpec>(&bytes)
                .ok()
                .filter(|spec| spec.validate().is_ok())
                .and_then(|spec| serde_json::to_vec(&spec).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_effect_intent_v27_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<EffectIntent>(&bytes)
                .ok()
                .filter(|intent| intent.validate().is_ok())
                .and_then(|intent| serde_json::to_vec(&intent).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_runner_launch_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let intent_bytes = context.get::<Vec<u8>>(0)?;
            let policy_bytes = context.get::<Vec<u8>>(1)?;
            let canonical = serde_json::from_slice::<RunnerLaunchIntent>(&intent_bytes)
                .ok()
                .zip(serde_json::from_slice::<ExecutionPolicy>(&policy_bytes).ok())
                .is_some_and(|(intent, policy)| {
                    intent.validate().is_ok()
                        && serde_json::to_vec(&intent).is_ok_and(|value| value == intent_bytes)
                        && serde_json::to_vec(&policy).is_ok_and(|value| value == policy_bytes)
                        && policy
                            .computed_hash()
                            .is_ok_and(|digest| digest == policy.policy_hash)
                        && policy.policy_hash == intent.policy_hash
                        && policy.grant_hash == intent.grant_hash
                        && runner_role_policy_matches(intent.purpose, &policy)
                });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_runner_session_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let record_bytes = context.get::<Vec<u8>>(0)?;
            let policy_bytes = context.get::<Vec<u8>>(1)?;
            let canonical = serde_json::from_slice::<RunnerSessionPolicyRecord>(&record_bytes)
                .ok()
                .zip(serde_json::from_slice::<ExecutionPolicy>(&policy_bytes).ok())
                .is_some_and(|(record, policy)| {
                    record.validate().is_ok()
                        && serde_json::to_vec(&record).is_ok_and(|value| value == record_bytes)
                        && serde_json::to_vec(&policy).is_ok_and(|value| value == policy_bytes)
                        && policy
                            .computed_hash()
                            .is_ok_and(|digest| digest == policy.policy_hash)
                        && policy.policy_hash == record.policy_hash
                        && policy.grant_hash == record.grant_hash
                        && runner_role_policy_matches(record.purpose, &policy)
                });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_task_running_authority_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let attempt_bytes = context.get::<Vec<u8>>(0)?;
            let boundary_bytes = context.get::<Vec<u8>>(1)?;
            let canonical = serde_json::from_slice::<TaskAttempt>(&attempt_bytes)
                .ok()
                .zip(serde_json::from_slice::<TaskAttemptRunningBoundary>(&boundary_bytes).ok())
                .is_some_and(|(attempt, boundary)| {
                    attempt.validate().is_ok()
                        && boundary.validate().is_ok()
                        && boundary.attempt == attempt
                        && serde_json::to_vec(&attempt).is_ok_and(|value| value == attempt_bytes)
                        && serde_json::to_vec(&boundary).is_ok_and(|value| value == boundary_bytes)
                });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_final_verification_admission_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let admission_bytes = context.get::<Vec<u8>>(0)?;
            let command_bytes = context.get::<Vec<u8>>(1)?;
            let canonical =
                serde_json::from_slice::<SprintFinalVerificationAdmission>(&admission_bytes)
                    .ok()
                    .zip(serde_json::from_slice::<CommandSpec>(&command_bytes).ok())
                    .is_some_and(|(admission, command)| {
                        admission.validate().is_ok()
                            && command.validate().is_ok()
                            && admission.command == command
                            && serde_json::to_vec(&admission)
                                .is_ok_and(|value| value == admission_bytes)
                            && serde_json::to_vec(&command)
                                .is_ok_and(|value| value == command_bytes)
                    });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_formal_check_admission_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let admission_bytes = context.get::<Vec<u8>>(0)?;
            let command_bytes = context.get::<Vec<u8>>(1)?;
            let canonical =
                serde_json::from_slice::<TaskAttemptFormalCheckAdmission>(&admission_bytes)
                    .ok()
                    .zip(serde_json::from_slice::<CommandSpec>(&command_bytes).ok())
                    .is_some_and(|(admission, command)| {
                        admission.validate().is_ok()
                            && command.validate().is_ok()
                            && admission.command == command
                            && serde_json::to_vec(&admission)
                                .is_ok_and(|value| value == admission_bytes)
                            && serde_json::to_vec(&command)
                                .is_ok_and(|value| value == command_bytes)
                    });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_effect_proposal_v27_canonical",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let intent_bytes = context.get::<Vec<u8>>(0)?;
            let event_bytes = context.get::<Vec<u8>>(1)?;
            let canonical = serde_json::from_slice::<EffectIntent>(&intent_bytes)
                .ok()
                .zip(serde_json::from_slice::<AgentEvent>(&event_bytes).ok())
                .is_some_and(|(intent, event)| {
                    intent.validate().is_ok()
                        && event.validate().is_ok()
                        && validate_effect_proposal_event_shape(&intent, &event).is_ok()
                        && serde_json::to_vec(&intent).is_ok_and(|value| value == intent_bytes)
                        && serde_json::to_vec(&event).is_ok_and(|value| value == event_bytes)
                });
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_agent_event_v27_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let canonical = serde_json::from_slice::<AgentEvent>(&bytes)
                .ok()
                .filter(|event| event.validate().is_ok())
                .and_then(|event| serde_json::to_vec(&event).ok())
                .is_some_and(|canonical| canonical == bytes);
            Ok(i64::from(canonical))
        },
    )?;
    connection.create_scalar_function(
        "grok_sha256",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            Ok(Digest::sha256(&bytes).as_str().to_owned())
        },
    )?;
    for (name, digest) in [
        (
            "grok_command_output_capture_intent_digest",
            command_output_capture_authority::sqlite_intent_digest
                as fn(&[u8]) -> Result<String, String>,
        ),
        (
            "grok_command_output_capture_acquired_digest",
            command_output_capture_authority::sqlite_acquired_digest,
        ),
        (
            "grok_command_output_capture_terminal_digest",
            command_output_capture_authority::sqlite_terminal_digest,
        ),
        (
            "grok_command_output_capture_reconciliation_claim_digest",
            command_output_capture_authority::sqlite_reconciliation_claim_digest,
        ),
        (
            "grok_command_output_capture_reconciliation_resolution_digest",
            command_output_capture_authority::sqlite_reconciliation_resolution_digest,
        ),
        (
            "grok_command_output_capture_restart_recovery_receipt_digest",
            command_output_capture_authority::sqlite_restart_recovery_receipt_digest,
        ),
    ] {
        connection.create_scalar_function(
            name,
            1,
            FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
            move |context| {
                let bytes = context.get::<Vec<u8>>(0)?;
                digest(&bytes).map_err(|detail| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        detail,
                    )))
                })
            },
        )?;
    }
    connection.create_scalar_function(
        "grok_command_output_artifact_reference_matches",
        12,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let format_version = context.get::<i64>(1)?;
            let sprint_id = context.get::<String>(2)?;
            let runner_launch_id = context.get::<String>(3)?;
            let runner_session_id = context.get::<String>(4)?;
            let effect_id = context.get::<String>(5)?;
            let request_digest = context.get::<String>(6)?;
            let manifest_digest = context.get::<String>(7)?;
            let stdout_byte_length = context.get::<i64>(8)?;
            let stdout_content_digest = context.get::<String>(9)?;
            let stderr_byte_length = context.get::<i64>(10)?;
            let stderr_content_digest = context.get::<String>(11)?;
            let reference: CommandOutputArtifactSetReferenceV1 = serde_json::from_slice(&bytes)
                .map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid command output artifact reference: {error}"),
                    )))
                })?;
            reference.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&reference).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize command output artifact reference: {error}"),
                )))
            })?;
            let stdout_byte_length = u64::try_from(stdout_byte_length).ok();
            let stderr_byte_length = u64::try_from(stderr_byte_length).ok();
            if canonical != bytes
                || i64::from(reference.format_version) != format_version
                || reference.source.sprint_id != sprint_id
                || reference.source.runner_launch_id != runner_launch_id
                || reference.source.runner_session_id != runner_session_id
                || reference.source.effect_id != effect_id
                || reference.source.request_digest.as_str() != request_digest
                || reference.manifest_digest.as_str() != manifest_digest
                || Some(reference.stdout.byte_length) != stdout_byte_length
                || reference.stdout.content_digest.as_str() != stdout_content_digest
                || Some(reference.stderr.byte_length) != stderr_byte_length
                || reference.stderr.content_digest.as_str() != stderr_content_digest
            {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "command output artifact reference is noncanonical or crossed with indexed columns",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_current_verification_output_artifact_matches",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let evidence_bytes = context.get::<Vec<u8>>(0)?;
            let reference_bytes = context.get::<Vec<u8>>(1)?;
            let evidence: VerificationEffectEvidence = serde_json::from_slice(&evidence_bytes)
                .map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid current verification evidence: {error}"),
                    )))
                })?;
            evidence.validate_current().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let reference: CommandOutputArtifactSetReferenceV1 =
                serde_json::from_slice(&reference_bytes).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid command output artifact reference: {error}"),
                    )))
                })?;
            reference.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical_evidence = serde_json::to_vec(&evidence).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize current verification evidence: {error}"),
                )))
            })?;
            let canonical_reference = serde_json::to_vec(&reference).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize command output artifact reference: {error}"),
                )))
            })?;
            if canonical_evidence != evidence_bytes
                || canonical_reference != reference_bytes
                || evidence.output_artifacts.as_ref() != Some(&reference)
            {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "current verification evidence is noncanonical or crosses its output artifact reference",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_live_state_drift_blocked_proof_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let proof: LiveStateDriftBlockedProof =
                serde_json::from_slice(&bytes).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid live-state drift Blocked proof: {error}"),
                    )))
                })?;
            proof.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&proof).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize live-state drift Blocked proof: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "live-state drift Blocked proof is not canonical JSON",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_live_state_capture_manifest_digest",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let evidence: LiveStateCaptureEvidence =
                serde_json::from_slice(&bytes).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid live-state capture evidence: {error}"),
                    )))
                })?;
            evidence.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&evidence).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize live-state capture evidence: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "live-state capture evidence is not canonical JSON",
                    ),
                )));
            }
            Ok(evidence.manifest.manifest_digest.as_str().to_owned())
        },
    )?;
    connection.create_scalar_function(
        "grok_live_state_capture_admission_matches",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let expected_plan_digest = context.get::<String>(1)?;
            let expected_request_digest = context.get::<String>(2)?;
            let admission: SprintLiveStateCaptureAdmission = serde_json::from_slice(&bytes)
                .map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid live-state capture admission: {error}"),
                    )))
                })?;
            admission.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&admission).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize live-state capture admission: {error}"),
                )))
            })?;
            if canonical != bytes
                || admission
                    .plan
                    .plan_digest()
                    .map_err(|error| {
                        rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            error.to_string(),
                        )))
                    })?
                    .as_str()
                    != expected_plan_digest
                || admission
                    .request
                    .request_digest()
                    .map_err(|error| {
                        rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                            io::ErrorKind::InvalidData,
                            error.to_string(),
                        )))
                    })?
                    .as_str()
                    != expected_request_digest
            {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "live-state capture admission is noncanonical or its digests are crossed",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_canonical_completion_receipt_digest",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let receipt: CompletionReceipt = serde_json::from_slice(&bytes).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid completion receipt: {error}"),
                )))
            })?;
            receipt.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let digest = canonical_stored_completion_receipt_digest(&receipt, &bytes)
                .map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error.to_string(),
                    )))
                })?
                .ok_or_else(|| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completion receipt is not canonical JSON",
                    )))
                })?;
            Ok(digest.as_str().to_owned())
        },
    )?;
    connection.create_scalar_function(
        "grok_completion_live_state_capture_link_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let link: CompletionLiveStateCaptureLink =
                serde_json::from_slice(&bytes).map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid completion capture link: {error}"),
                    )))
                })?;
            link.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&link).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize completion capture link: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "completion capture link is not canonical JSON",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_verified_no_op_receipt_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let receipt: VerifiedNoOpReceipt = serde_json::from_slice(&bytes).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid verified no-op receipt: {error}"),
                )))
            })?;
            receipt.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&receipt).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize verified no-op receipt: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "verified no-op receipt is not canonical JSON",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_agent_event_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let event: AgentEvent = serde_json::from_slice(&bytes).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid agent event: {error}"),
                )))
            })?;
            event.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&event).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize agent event: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "agent event is not canonical JSON",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_final_report_canonical",
        1,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let report: FinalReport = serde_json::from_slice(&bytes).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid final report: {error}"),
                )))
            })?;
            report.validate().map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error.to_string(),
                )))
            })?;
            let canonical = serde_json::to_vec(&report).map_err(|error| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot canonicalize final report: {error}"),
                )))
            })?;
            if canonical != bytes {
                return Err(rusqlite::Error::UserFunctionError(Box::new(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "final report is not canonical JSON",
                    ),
                )));
            }
            Ok(1_i64)
        },
    )?;
    connection.create_scalar_function(
        "grok_task_attempt_disposition_index",
        2,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let bytes = context.get::<Vec<u8>>(0)?;
            let max_attempts = context.get::<i64>(1)?;
            let max_attempts = u8::try_from(max_attempts)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "task attempt budget must be an integer in 1..=255",
                    )))
                })?;
            task_attempt_authority::disposition_sql_index(&bytes, max_attempts).map_err(|detail| {
                rusqlite::Error::UserFunctionError(Box::new(io::Error::new(
                    io::ErrorKind::InvalidData,
                    detail,
                )))
            })
        },
    )?;
    current_criterion_evidence_v32::register_schema_functions(connection)?;
    current_task_done_source_v32::register_schema_functions(connection)?;
    current_repair_task_authority_v32::register_schema_functions(connection)?;
    current_final_verification_native_preparation_v37::register_schema_functions(connection)?;
    Ok(())
}

pub(super) fn require_current_schema(connection: &Connection) -> Result<(), LedgerError> {
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(LedgerError::UnsupportedSchemaVersion(current))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct SchemaObject {
    pub(super) object_type: String,
    pub(super) name: String,
    pub(super) table_name: String,
    pub(super) sql: String,
}

pub(super) fn verify_exact_schema(connection: &Connection) -> Result<(), LedgerError> {
    let actual = load_schema_objects(connection)?;
    let expected = expected_current_schema()?;
    if actual.as_slice() == expected.as_ref() {
        Ok(())
    } else {
        Err(LedgerError::Corrupt {
            entity: "ledger schema",
            detail: format!(
                "schema objects differ from the exact version {SCHEMA_VERSION} migration"
            ),
        })
    }
}

/// Only the immutable reference constructed from this executable's migration
/// constants is cached. The supplied database is read and compared on EVERY
/// verification. No connection, observed schema, version check or integrity
/// result is cached. Failed construction remains retryable.
fn expected_current_schema() -> Result<std::sync::Arc<[SchemaObject]>, LedgerError> {
    type Inventory = std::sync::Arc<[SchemaObject]>;
    static EXPECTED: std::sync::OnceLock<std::sync::Mutex<Option<Inventory>>> =
        std::sync::OnceLock::new();
    let mut cached = EXPECTED
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .map_err(|_| LedgerError::Corrupt {
            entity: "expected ledger schema",
            detail: "immutable schema reference construction was interrupted".into(),
        })?;
    if let Some(expected) = cached.as_ref() {
        return Ok(std::sync::Arc::clone(expected));
    }
    let expected: Inventory = build_expected_schema_objects_through(MIGRATIONS.len())?.into();
    *cached = Some(std::sync::Arc::clone(&expected));
    Ok(expected)
}

pub(super) fn load_schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, LedgerError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql
         FROM sqlite_schema
         WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'
         ORDER BY type, name, tbl_name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok(SchemaObject {
            object_type: row.get(0)?,
            name: row.get(1)?,
            table_name: row.get(2)?,
            sql: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub(super) fn verify_database_integrity(connection: &Connection) -> Result<(), LedgerError> {
    let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result == "ok" {
        Ok(())
    } else {
        Err(LedgerError::IntegrityCheckFailed(result))
    }
}
