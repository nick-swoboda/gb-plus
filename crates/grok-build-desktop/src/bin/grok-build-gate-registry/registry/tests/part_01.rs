    use super::*;

    const GATE_1: RegistryGateSelectionV1 = RegistryGateSelectionV1::Gate1;
    const GATE_2: RegistryGateSelectionV1 = RegistryGateSelectionV1::Gate2;
    const GATE_3: RegistryGateSelectionV1 = RegistryGateSelectionV1::Gate3;

    #[test]
    fn checked_in_registries_are_canonical_and_projection_equivalent() {
        let gate_1 = checked_in_registry(GATE_1).expect("decode Gate 1 canonical registry");
        assert_eq!(gate_1, manifest_v2_projection(GATE_1));
        assert_eq!(gate_1.specifications.len(), 93);
        assert_eq!(
            gate_1.digest().unwrap(),
            "4e15d2c5b7567f33fb9fed85afaadf227300453b572245f598f35443a15b08d2"
        );

        let gate_2 = checked_in_registry(GATE_2).expect("decode Gate 2 canonical registry");
        assert_eq!(gate_2, manifest_v2_projection(GATE_2));
        assert_eq!(gate_2.specifications.len(), 615);
        assert_eq!(
            gate_2.digest().unwrap(),
            "1b14986386d7f92506a61980a170019b33e98acd7dac2710e6c4713ff6104450"
        );

        let gate_3 = checked_in_registry(GATE_3).expect("decode Gate 3 canonical registry");
        assert_eq!(gate_3, manifest_v2_projection(GATE_3));
        assert_eq!(gate_3.specifications.len(), 136);
        assert_eq!(
            gate_3.digest().unwrap(),
            "66448a23a48826dcd953e5659f2eb6e0cea2c839a75ab4912b742c764c671b89"
        );
    }

    #[test]
    fn exact_target_counts_and_result_id_uniqueness_are_locked_for_all_gates() {
        for (gate, expected_counts) in [(GATE_1, [29, 32, 32]), (GATE_2, [207, 204, 204])] {
            let registry = manifest_v2_projection(gate);
            registry.validate().unwrap();
            let mut counts = BTreeMap::new();
            let mut result_ids = BTreeSet::new();
            for specification in &registry.specifications {
                *counts.entry(specification.target).or_insert(0_usize) += 1;
                assert!(result_ids.insert(&specification.result_id));
            }
            for (target, expected_count) in TARGETS.into_iter().zip(expected_counts) {
                assert_eq!(counts[&target], expected_count);
            }
        }
        let gate_3 = manifest_v2_projection(GATE_3);
        let mut counts = BTreeMap::new();
        let mut result_ids = BTreeSet::new();
        for specification in &gate_3.specifications {
            *counts.entry(specification.target).or_insert(0_usize) += 1;
            assert!(result_ids.insert(&specification.result_id));
        }
        assert_eq!(counts[&GateTargetV1::Macos15AppleSilicon], 39);
        assert_eq!(counts[&GateTargetV1::Ubuntu2604X8664], 48);
        assert_eq!(counts[&GateTargetV1::Fedora44X8664], 48);
        assert_eq!(counts[&GateTargetV1::Global], 1);
    }

    #[test]
    fn all_runtime_execution_is_explicitly_unavailable() {
        for gate in [GATE_1, GATE_2, GATE_3] {
            let registry = manifest_v2_projection(gate);
            assert!(registry.specifications.iter().all(|specification| {
                specification.execution.availability == ExecutionAvailabilityV1::Unavailable
                    && specification.execution.missing_capability
                        == ExecutionMissingCapabilityV1::ProductionFixtureExecutor
            }));
        }
        let gate_1 = manifest_v2_projection(GATE_1);
        let contract_only = gate_1
            .specifications
            .iter()
            .filter(|specification| {
                specification.validator.availability == ValidatorAvailabilityV1::ContractOnly
            })
            .count();
        assert_eq!(contract_only, 16);
        assert_eq!(gate_1.specifications.len() - contract_only, 77);
        for gate in [GATE_2, GATE_3] {
            assert!(
                manifest_v2_projection(gate)
                    .specifications
                    .iter()
                    .all(|specification| specification.validator.availability
                        == ValidatorAvailabilityV1::Unavailable)
            );
        }
    }

    #[test]
    fn gate_2_exact_manifest_arithmetic_is_585_plus_9_plus_3_plus_6_plus_9_plus_3() {
        let registry = manifest_v2_projection(GATE_2);
        let base_ids = GATE_2_BASE_CASES
            .iter()
            .map(|definition| definition.case_id)
            .collect::<BTreeSet<_>>();
        let known_ids = GATE_2_KNOWN_OUTCOME_CASES
            .iter()
            .map(|definition| definition.case_id)
            .collect::<BTreeSet<_>>();
        let count = |ids: &BTreeSet<&str>| {
            registry
                .specifications
                .iter()
                .filter(|specification| ids.contains(specification.case_id.as_str()))
                .count()
        };
        assert_eq!(count(&base_ids), 315);
        assert_eq!(count(&known_ids), 270);
        assert_eq!(
            registry
                .specifications
                .iter()
                .filter(|specification| specification.case_id == GATE_2_REPAIR_CASE.case_id)
                .count(),
            9
        );
        assert_eq!(
            registry
                .specifications
                .iter()
                .filter(|specification| specification.case_id == GATE_2_RUN_CONTROL_CASE.case_id)
                .count(),
            3
        );
        assert_eq!(
            registry
                .specifications
                .iter()
                .filter(|specification| matches!(
                    specification.axes.repository_shape,
                    Some(RepositoryShapeV1::DirtyGit | RepositoryShapeV1::NonGit)
                ))
                .count(),
            6
        );
        assert_eq!(
            registry
                .specifications
                .iter()
                .filter(|specification| specification.axes.provider_mode
                    == Some(ProviderModeV1::NormalizedContract))
                .count(),
            9
        );
        assert_eq!(
            registry
                .specifications
                .iter()
                .filter(|specification| specification.axes.provider_mode
                    == Some(ProviderModeV1::LiveCompletedSprint))
                .count(),
            3
        );
    }

    #[test]
    fn gate_2_unknown_rows_stop_before_known_outcome_cases() {
        let registry = manifest_v2_projection(GATE_2);
        let known_ids = GATE_2_KNOWN_OUTCOME_CASES
            .iter()
            .map(|definition| definition.case_id)
            .collect::<BTreeSet<_>>();
        let unknown_rows = registry.specifications.iter().filter(|specification| {
            matches!(
                specification.axes.crash_cut,
                Some(CrashCutV1::AfterCommandWrite | CrashCutV1::AfterMutation)
            )
        });
        let mut count = 0;
        for specification in unknown_rows {
            count += 1;
            assert_eq!(
                specification.axes.expected_outcome_class,
                Some(ExpectedOutcomeClassV1::TruthfulSprintUnknown)
            );
            assert!(
                GATE_2_BASE_CASES
                    .iter()
                    .any(|definition| definition.case_id == specification.case_id)
            );
            assert!(!known_ids.contains(specification.case_id.as_str()));
        }
        assert_eq!(count, 90);
    }

    #[test]
    fn gate_2_provider_target_policy_is_exact() {
        let registry = manifest_v2_projection(GATE_2);
        let normalized = registry.specifications.iter().filter(|specification| {
            specification.axes.provider_mode == Some(ProviderModeV1::NormalizedContract)
        });
        let mut normalized_targets = BTreeMap::new();
        for specification in normalized {
            *normalized_targets
                .entry(specification.target)
                .or_insert(0_usize) += 1;
        }
        assert_eq!(normalized_targets.len(), 3);
        assert!(normalized_targets.values().all(|count| *count == 3));
        assert!(
            registry
                .specifications
                .iter()
                .filter(|specification| {
                    specification.axes.provider_mode == Some(ProviderModeV1::LiveCompletedSprint)
                })
                .all(|specification| specification.target == GateTargetV1::Macos15AppleSilicon)
        );
    }

    #[test]
    fn gate_3_exact_manifest_arithmetic_is_20_plus_70_plus_45_plus_one() {
        let registry = manifest_v2_projection(GATE_3);
        let count_group = |group| {
            registry
                .specifications
                .iter()
                .filter(|specification| specification.axes.gate_3_group == Some(group))
                .count()
        };
        assert_eq!(count_group(Gate3CaseGroupV1::PackageLifecycle), 20);
        assert_eq!(count_group(Gate3CaseGroupV1::UiAccessibility), 70);
        assert_eq!(count_group(Gate3CaseGroupV1::RuntimeResilience), 45);
        assert_eq!(
            count_group(Gate3CaseGroupV1::RequirementsEvidenceBaseClosure),
            1
        );
        assert_eq!(20 + 70 + 45, 135);
        assert_eq!(93 + 615 + registry.specifications.len(), 844);
    }

    #[test]
    fn gate_3_rows_are_not_cross_multiplied() {
        let registry = manifest_v2_projection(GATE_3);
        for row in GATE_3_PACKAGE_ROWS {
            assert_eq!(
                registry
                    .specifications
                    .iter()
                    .filter(|specification| specification.axes.gate_3_row_id == Some(row.row_id))
                    .count(),
                5
            );
        }
        for row in GATE_3_UI_ROWS {
            assert_eq!(
                registry
                    .specifications
                    .iter()
                    .filter(|specification| specification.axes.gate_3_row_id == Some(row.row_id))
                    .count(),
                14
            );
        }
        for row in GATE_3_RUNTIME_ROWS {
            assert_eq!(
                registry
                    .specifications
                    .iter()
                    .filter(|specification| specification.axes.gate_3_row_id == Some(row.row_id))
                    .count(),
                15
            );
        }
    }

    #[test]
    fn gate_3_ui_contains_exactly_the_legal_terminal_disposition_pairs() {
        let registry = manifest_v2_projection(GATE_3);
        for row in GATE_3_UI_ROWS {
            for terminal in GATE_3_TERMINAL_CASES {
                let observed = registry
                    .specifications
                    .iter()
                    .filter(|specification| {
                        specification.axes.gate_3_row_id == Some(row.row_id)
                            && specification.axes.terminal_state == Some(terminal.terminal_state)
                    })
                    .map(|specification| {
                        specification
                            .axes
                            .application_disposition
                            .expect("terminal specification has a disposition")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(observed, terminal.dispositions.iter().copied().collect());
            }
        }

        let mut illegal = manifest_v2_projection(GATE_3);
        let completed = illegal
            .specifications
            .iter_mut()
            .find(|specification| {
                specification.axes.terminal_state == Some(Gate3TerminalStateV1::Completed)
            })
            .unwrap();
        completed.axes.application_disposition =
            Some(Gate3ApplicationDispositionV1::NoApplicationNotApplicable);
        assert!(illegal.validate().is_err());
    }

    #[test]
    fn gate_3_phase_a_closure_is_one_global_acyclic_case_and_phase_b_is_absent() {
        let registry = manifest_v2_projection(GATE_3);
        let closures = registry
            .specifications
            .iter()
            .filter(|specification| {
                specification.axes.gate_3_group
                    == Some(Gate3CaseGroupV1::RequirementsEvidenceBaseClosure)
            })
            .collect::<Vec<_>>();
        assert_eq!(closures.len(), 1);
        let closure = closures[0];
        assert_eq!(closure.target, GateTargetV1::Global);
        assert_eq!(closure.case_id, GATE_3_REQUIREMENTS_CLOSURE_CASE.case_id);
        assert!(closure.shared_evidence_ids.is_empty());
        assert_eq!(
            closure.isolation,
            gate_3_isolation_requirement(Gate3CaseGroupV1::RequirementsEvidenceBaseClosure)
        );
        assert!(
            closure
                .bound_inputs
                .contains(&BoundInputIdentityV1::Gate3NonClosureCaseResults)
        );
        assert!(
            closure
                .bound_inputs
                .contains(&BoundInputIdentityV1::ReleaseMatrixR1)
        );
        assert!(
            closure
                .bound_inputs
                .contains(&BoundInputIdentityV1::ReleaseMatrixR2)
        );
        assert!(registry.specifications.iter().all(|specification| {
            !specification.case_id.contains("gate3_finish")
                && !specification.case_id.contains("phase_b")
                && !specification.result_id.contains("derived:gate3-finish-v1")
        }));
    }

    #[test]
    fn shared_evidence_is_explicit_and_never_singleton() {
        for gate in [GATE_1, GATE_2, GATE_3] {
            let registry = manifest_v2_projection(gate);
            let mut counts = BTreeMap::new();
            for specification in &registry.specifications {
                for shared_id in &specification.shared_evidence_ids {
                    *counts.entry(shared_id).or_insert(0_usize) += 1;
                }
            }
            assert!(counts.values().all(|count| *count >= 2));
        }
    }

    #[test]
    fn noncanonical_unknown_and_open_ended_json_are_rejected() {
        for gate in [GATE_1, GATE_2, GATE_3] {
            let registry = manifest_v2_projection(gate);
            let pretty = serde_json::to_vec_pretty(&registry).unwrap();
            assert!(decode_registry(&pretty, gate).is_err());

            let mut value = serde_json::to_value(&registry).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), serde_json::Value::Bool(true));
            assert!(decode_registry(&serde_json::to_vec(&value).unwrap(), gate).is_err());

            let canonical = serde_json::to_string(&registry).unwrap();
            let unknown_status = canonical.replacen(
                "\"non-authoritative-projection\"",
                "\"future-authority\"",
                1,
            );
            assert!(decode_registry(unknown_status.as_bytes(), gate).is_err());
        }
    }

    #[test]
    fn missing_duplicate_or_crossed_specification_fails_projection_validation() {
        let mut missing = manifest_v2_projection(GATE_2);
        missing.specifications.pop();
        assert!(missing.validate().is_err());

        let mut duplicate = manifest_v2_projection(GATE_2);
        duplicate.specifications[1] = duplicate.specifications[0].clone();
        assert!(duplicate.validate().is_err());

        let mut crossed = manifest_v2_projection(GATE_2);
        crossed.specifications[0].target = GateTargetV1::Fedora44X8664;
        assert!(crossed.validate().is_err());

        let gate_1_bytes = serde_json::to_vec(&manifest_v2_projection(GATE_1)).unwrap();
        assert!(decode_registry(&gate_1_bytes, GATE_2).is_err());
    }

    #[test]
    fn artifact_validator_and_isolation_substitution_fails() {
        let mut artifact = manifest_v2_projection(GATE_2);
        artifact.specifications[0].expected_artifacts.pop();
        assert!(artifact.validate().is_err());

        let mut validator = manifest_v2_projection(GATE_2);
        validator.specifications[0].validator.validator_id = ValidatorIdV1::OfflineBuild;
        assert!(validator.validate().is_err());

        let mut sharing = manifest_v2_projection(GATE_2);
        sharing.specifications[1]
            .shared_evidence_ids
            .push("g2.shared.singleton".into());
        assert!(sharing.validate().is_err());

        let mut axis = manifest_v2_projection(GATE_2);
        axis.specifications[0].axes.worker_ceiling = Some(4);
        assert!(axis.validate().is_err());

        let mut gate_3_isolation = manifest_v2_projection(GATE_3);
        gate_3_isolation.specifications[0].isolation = isolation_requirement();
        assert!(gate_3_isolation.validate().is_err());

        let mut crossed_group = manifest_v2_projection(GATE_3);
        crossed_group.specifications[0].axes.gate_3_group =
            Some(Gate3CaseGroupV1::RuntimeResilience);
        assert!(crossed_group.validate().is_err());
    }

    #[test]
    fn markdown_renderer_emits_one_review_row_per_specification() {
        for (gate, prefix, expected) in [
            (GATE_1, "| `g1.", 93),
            (GATE_2, "| `g2.", 615),
            (GATE_3, "| `g3.", 136),
        ] {
            let markdown = manifest_v2_projection(gate).render_markdown();
            assert!(markdown.contains("non-authoritative projection"));
            assert_eq!(
                markdown
                    .lines()
                    .filter(|line| line.starts_with(prefix))
                    .count(),
                expected
            );
        }
    }
