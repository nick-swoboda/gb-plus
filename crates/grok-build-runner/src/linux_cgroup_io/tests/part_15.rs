    // Split out of `tests/part_02.rs` under the 3,000-line rule when the frozen
    // protocol-v2 restart record's test pushed that file over it. Test parts
    // are fragments included by `tests/mod.rs`, so this file is written
    // indented and `rustfmt` must not be pointed at it.
    #[test]
    fn retained_service_bootstrap_detects_root_tool_and_controller_replacement() {
        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        fs::rename(
            fixture.journal_path(),
            fixture.path.join("displaced-bootstrap-journal"),
        )
        .unwrap();
        fs::create_dir(fixture.journal_path()).unwrap();
        fs::set_permissions(fixture.journal_path(), fs::Permissions::from_mode(0o700)).unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "journal-root-identity");

        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let service_parent = fixture.path.join("service-cgroup");
        fs::rename(
            service_parent.join("delegation"),
            service_parent.join("displaced-delegation"),
        )
        .unwrap();
        fs::create_dir(service_parent.join("delegation")).unwrap();
        fs::set_permissions(
            service_parent.join("delegation"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "bootstrap-delegation-identity");

        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        fs::write(
            fixture
                .path
                .join("service-cgroup/delegation/cgroup.subtree_control"),
            b"memory\n",
        )
        .unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "validate-bootstrap-subtree-control");

        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let tool_root = fixture.path.join("authenticated-tools");
        fs::rename(tool_root.join("bwrap"), tool_root.join("displaced-bwrap")).unwrap();
        fs::write(tool_root.join("bwrap"), b"replacement-bwrap\n").unwrap();
        fs::set_permissions(tool_root.join("bwrap"), fs::Permissions::from_mode(0o700)).unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "bootstrap-bubblewrap-identity");

        let fixture = Fixture::new();
        let expectation = fixture.bootstrap_expectation();
        let plan = fixture.bootstrap_plan(crate::wire::RunnerRole::Worker);
        let bootstrap = fixture.open_bootstrap_authority(&plan);
        let journaled = journal_linux_production_command_plan(
            plan,
            fixture.open_service_journal_authority(expectation),
        )
        .unwrap();
        let bubblewrap_path = fixture.path.join("authenticated-tools/bwrap");
        let mut crossed_content = fs::read(&bubblewrap_path).unwrap();
        crossed_content[0] ^= 1;
        fs::write(&bubblewrap_path, crossed_content).unwrap();
        let error = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)
            .unwrap_err();
        assert_eq!(error.operation, "validate-bootstrap-bubblewrap");
        assert!(error.detail.contains("full-content"));
    }

    #[test]
    fn restart_rejects_complete_plan_field_loss_and_same_effect_artifact_crossing() {
        for cross_to_valid_substitution in [false, true] {
            let fixture = Fixture::new();
            let expected = probe_expectation(&fixture);
            let plan = fixture.command_plan(crate::wire::RunnerRole::Worker, expected);
            let artifact = fixture
                .journal_path()
                .join(command_plan_name(plan.plan_digest()));
            let authority = fixture.open_service_journal_authority(expected);
            let bridge = journal_linux_production_command_plan(plan.clone(), authority).unwrap();
            assert!(!JournaledLinuxProductionCommandPlanV1::permits_execution());
            drop(bridge);

            let crossed = if cross_to_valid_substitution {
                plan.clone()
                    .substitute_test_same_effect_plan()
                    .unwrap()
                    .canonical_bytes()
                    .to_vec()
            } else {
                let mut value: serde_json::Value =
                    serde_json::from_slice(plan.canonical_bytes()).unwrap();
                value.as_object_mut().unwrap().remove("native_launch");
                serde_json::to_vec(&value).unwrap()
            };
            fs::write(&artifact, crossed).unwrap();

            let restart_authority = fixture.open_service_journal_authority(expected);
            let error = journal_linux_production_command_plan(plan, restart_authority).unwrap_err();
            assert_eq!(error.certainty, EffectCertainty::NotApplied);
            assert!(matches!(
                error.operation,
                "decode-command-plan" | "authenticate-command-plan"
            ));
        }
    }

    #[test]
    fn v2_record_commitment_binds_complete_plan_digest_under_new_domain() {
        let record = create_intent();
        let first_digest = Digest::sha256(b"complete-plan-a");
        let second_digest = Digest::sha256(b"complete-plan-b");
        let first = encode_envelope_with_plan(0, &record, Some(&first_digest)).unwrap();
        let second = encode_envelope_with_plan(0, &record, Some(&second_digest)).unwrap();
        assert_ne!(first, second);
        let first = decode_envelope(&first).unwrap();
        let second = decode_envelope(&second).unwrap();
        assert_eq!(first.format_version, 2);
        assert_eq!(second.format_version, 2);
        assert_eq!(first.plan_digest, Some(first_digest));
        assert_eq!(second.plan_digest, Some(second_digest));
        assert_ne!(
            first.record_commitment_sha256,
            second.record_commitment_sha256
        );
    }

    #[test]
    fn full_scan_rejects_a_second_create_for_one_command_effect() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        persist_removed_episode(&mut store, &create);
        let sequence = store.latest.as_ref().unwrap().envelope.sequence + 1;
        store.release_lock(token).unwrap();

        let mut crossed = create;
        crossed.request_digest = "e".repeat(64);
        crossed.command_hash = "crossed-command-hash".into();
        crossed.leaf_name = format!("gb-{}", "b".repeat(64));
        let bytes = encode_envelope(sequence, &crossed).unwrap();
        write_new_private_file(
            &store.directory,
            &final_name(sequence),
            &bytes,
            fixture.expected_uid,
        )
        .unwrap();
        sync_directory(&store.directory).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let error = reopened.read_latest().unwrap_err();
        assert_eq!(error.operation, "validate-journal-episode-history");
    }

    #[test]
    fn orphan_temporary_cannot_publish_a_rebound_command_effect() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        persist_removed_episode(&mut store, &create);
        let sequence = store.latest.as_ref().unwrap().envelope.sequence + 1;
        store.release_lock(token).unwrap();

        let mut crossed = create;
        crossed.request_digest = "e".repeat(64);
        crossed.command_hash = "crossed-command-hash".into();
        crossed.leaf_name = format!("gb-{}", "b".repeat(64));
        let bytes = encode_envelope(sequence, &crossed).unwrap();
        write_new_private_file(
            &store.directory,
            &temporary_name(sequence),
            &bytes,
            fixture.expected_uid,
        )
        .unwrap();
        sync_directory(&store.directory).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let error = reopened.read_latest().unwrap_err();
        assert_eq!(error.operation, "validate-journal-episode-history");
        assert!(
            fixture
                .journal_path()
                .join(temporary_name(sequence))
                .is_file()
        );
        assert!(!fixture.journal_path().join(final_name(sequence)).exists());
    }

    #[test]
    fn successor_freezes_native_evidence_and_cleanup_prefixes() {
        let create = create_intent();
        let configuring = configuring(create.clone());
        let prepared = prepared(configuring.clone());
        let attach_intended = attach_intended(prepared.clone());
        let attached = attached(attach_intended.clone());
        validate_record_successor(&attach_intended, &attached).unwrap();

        let mut crossed_leaf = attached.clone();
        crossed_leaf.leaf_identity = Some(CgroupObjectIdentity {
            device: 7,
            inode: 999,
        });
        assert!(validate_record_successor(&attach_intended, &crossed_leaf).is_err());

        let mut crossed_limits = attached.clone();
        crossed_limits.read_back_limits.as_mut().unwrap().pids_max = 3;
        assert!(validate_record_successor(&attach_intended, &crossed_limits).is_err());

        let mut crossed_launcher = attached.clone();
        crossed_launcher
            .staged_launcher
            .as_mut()
            .unwrap()
            .process_start_time_ticks += 1;
        assert!(validate_record_successor(&attach_intended, &crossed_launcher).is_err());

        let held = held(attached.clone());
        validate_record_successor(&attached, &held).unwrap();
        let mut crossed_held_launcher = held.clone();
        crossed_held_launcher.staged_launcher.as_mut().unwrap().pid += 1;
        assert!(validate_record_successor(&attached, &crossed_held_launcher).is_err());

        let killing = killing(prepared);
        let empty = empty_proven(killing.clone());
        validate_record_successor(&killing, &empty).unwrap();
        let remove_intended = remove_intended(empty.clone());
        validate_record_successor(&empty, &remove_intended).unwrap();

        let mut crossed_kill = remove_intended.clone();
        crossed_kill.kill_value = Some(b"0\n".to_vec());
        assert!(validate_record_successor(&empty, &crossed_kill).is_err());

        let mut crossed_observation = remove_intended.clone();
        crossed_observation.cleanup_observations[0].bytes = b"populated 1\nfrozen 0\n".to_vec();
        assert!(validate_record_successor(&empty, &crossed_observation).is_err());

        let mut appended_observation = remove_intended;
        appended_observation
            .cleanup_observations
            .extend(empty.cleanup_observations.clone());
        assert!(validate_record_successor(&empty, &appended_observation).is_err());
    }

    #[test]
    fn durable_release_generations_bind_outer_claim_and_reopen_at_intent() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        let configuring = configuring(create.clone());
        let prepared = prepared(configuring.clone());
        let attach_intended = attach_intended(prepared.clone());
        let attached = attached(attach_intended.clone());
        let held = held(attached.clone());
        let intended = release_intended(held.clone());
        for record in [
            &create,
            &configuring,
            &prepared,
            &attach_intended,
            &attached,
            &held,
            &intended,
        ] {
            store.persist(record).unwrap();
            store.sync().unwrap();
        }
        store.release_lock(token).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        assert_eq!(reopened.read_latest().unwrap(), Some(intended.clone()));
        assert_eq!(intended.native_launch.attempt_id, "attempt-1");
        assert_eq!(intended.native_launch.native_journal_id, "native-journal-1");
        assert_eq!(
            intended.native_launch.input_snapshot,
            Digest::sha256(b"journal-test-input-snapshot")
        );
        assert_eq!(
            intended
                .release_authorization
                .as_ref()
                .unwrap()
                .native_launch,
            intended.native_launch
        );
        assert_eq!(
            intended
                .release_authorization
                .as_ref()
                .unwrap()
                .native_evidence_digest,
            Digest::sha256(b"test-outer-preparation-evidence")
        );
        assert_eq!(
            intended
                .release_authorization
                .as_ref()
                .unwrap()
                .held_preparation_evidence_digest,
            Digest::sha256(
                &crate::linux_containment::LinuxHeldPreparationEvidence::canonical_native_evidence_bytes(
                    &attached,
                )
                .unwrap(),
            )
        );
        assert!(intended.release_intent_recorded);
        assert!(intended.release_observation.is_none());

        let token = reopened.acquire_lock().unwrap();
        assert!(reopened.persist(&held).is_err());
        let released = released(intended);
        reopened.persist(&released).unwrap();
        reopened.sync().unwrap();
        reopened.release_lock(token).unwrap();
    }

    #[test]
    fn cleanup_first_and_identity_or_release_substitution_cannot_cross_journal() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        let configuring = configuring(create.clone());
        let prepared = prepared(configuring.clone());
        let attach_intended = attach_intended(prepared.clone());
        let attached = attached(attach_intended.clone());
        for record in [
            &create,
            &configuring,
            &prepared,
            &attach_intended,
            &attached,
        ] {
            store.persist(record).unwrap();
            store.sync().unwrap();
        }

        let mut crossed_identity = held(attached.clone());
        crossed_identity.native_launch.attempt_id = "substituted-attempt".into();
        assert!(store.persist(&crossed_identity).is_err());

        let mut crossed_snapshot = held(attached.clone());
        crossed_snapshot.native_launch.input_snapshot = Digest::sha256(b"crossed-snapshot");
        assert!(store.persist(&crossed_snapshot).is_err());

        let mut crossed_release = held(attached.clone());
        let mut value = serde_json::to_value(&crossed_release).unwrap();
        value["release_binding"]["specification"]["argv"][0] =
            serde_json::Value::String("substituted-image".into());
        crossed_release = serde_json::from_value(value).unwrap();
        assert!(store.persist(&crossed_release).is_err());

        let canonical_held = held(attached.clone());
        store.persist(&canonical_held).unwrap();
        store.sync().unwrap();
        let mut crossed_authorization = release_intended(canonical_held.clone());
        crossed_authorization
            .release_authorization
            .as_mut()
            .unwrap()
            .native_evidence_digest = Digest::sha256(b"crossed-held-child-evidence");
        assert!(store.persist(&crossed_authorization).is_err());

        let mut killing = canonical_held;
        killing.state = DomainJournalState::Killing;
        store.persist(&killing).unwrap();
        store.sync().unwrap();
        assert!(store.persist(&held(attached)).is_err());
        store.release_lock(token).unwrap();
    }

    #[test]
    fn durable_probe_journal_drives_every_intent_to_removed() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let mut effects = MockProbeEffects::new(expectation);

        let evidence = drive_durable_probe(&mut store, &mut effects, expectation).unwrap();
        assert!(evidence.created_no_replace);
        assert!(evidence.configured_and_read_back);
        assert!(evidence.kill_write_accepted);
        assert!(evidence.stable_empty_procs);
        assert!(evidence.removed_exact_inode);
        assert_eq!(effects.create_calls, 1);
        assert_eq!(effects.configure_calls, 1);
        assert_eq!(effects.kill_calls, 1);
        assert_eq!(effects.remove_calls, 1);
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::Removed
        );
        let mut drifted_epoch = new_probe_intent(expectation, ProbeEpisodeKind::DelegationDefaultShape).unwrap();
        drifted_epoch.expected_owner_uid = expectation.owner_uid.saturating_add(1);
        assert!(store.persist_probe(&drifted_epoch).is_err());
        store.release_lock(token).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let token = reopened.acquire_lock().unwrap();
        assert_eq!(
            reopened.latest_probe_record().unwrap().state,
            ProbeJournalState::Removed
        );
        reopened.release_lock(token).unwrap();
    }

    #[test]
    fn nondefault_authoritative_probe_is_cleaned_without_success_evidence() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let mut effects = MockProbeEffects::new(expectation);
        effects.shape.pids_max = b"2\n".to_vec();
        effects.fail_once = Some("remove");

        let error = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
        assert_eq!(error.operation, "remove");
        let cleanup = store.latest_probe_record().unwrap();
        assert_eq!(cleanup.state, ProbeJournalState::RemoveIntended);
        assert!(!cleanup.configured_and_read_back);
        assert!(cleanup.stable_empty_proven);
        assert_eq!(effects.configure_calls, 0);
        assert_eq!(effects.kill_calls, 1);

        effects.fail_once = None;
        effects.shape = default_probe_shape(expectation);
        let evidence = drive_durable_probe(&mut store, &mut effects, expectation).unwrap();
        assert!(evidence.configured_and_read_back);
        assert_eq!(effects.create_calls, 2);
        assert_eq!(effects.configure_calls, 1);
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::Removed
        );
        store.release_lock(token).unwrap();
    }

    #[test]
    fn post_shape_probe_states_require_the_durable_initial_shape() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut record = new_probe_intent(expectation, ProbeEpisodeKind::DelegationDefaultShape).unwrap();
        record.observed_identity = Some(CgroupObjectIdentity {
            device: expectation.delegation_identity.device,
            inode: 12,
        });
        record.identity_authoritative = true;

        for state in [
            ProbeJournalState::Configured,
            ProbeJournalState::KillIntended,
            ProbeJournalState::EmptyProven,
            ProbeJournalState::RemoveIntended,
        ] {
            record.state = state;
            record.configured_and_read_back = state == ProbeJournalState::Configured;
            record.stable_empty_proven = matches!(
                state,
                ProbeJournalState::EmptyProven | ProbeJournalState::RemoveIntended
            );
            assert!(record.validate().is_err(), "state {state:?}");
        }
    }

    #[test]
    fn every_probe_effect_boundary_recovers_without_blind_create_replay() {
        for (operation, expected_state) in [
            ("create", ProbeJournalState::CreateIntended),
            ("shape", ProbeJournalState::IdentityObserved),
            ("configure", ProbeJournalState::ConfigureIntended),
            ("kill", ProbeJournalState::KillIntended),
            ("remove", ProbeJournalState::RemoveIntended),
        ] {
            let fixture = Fixture::new();
            let expectation = probe_expectation(&fixture);
            let mut store = fixture.open_store();
            let token = store.acquire_lock().unwrap();
            let mut effects = MockProbeEffects::new(expectation);
            effects.fail_once = Some(operation);

            let error = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
            assert_eq!(error.operation, operation);
            assert_eq!(store.latest_probe_record().unwrap().state, expected_state);
            let creates_before_retry = effects.create_calls;
            effects.fail_once = None;
            drive_durable_probe(&mut store, &mut effects, expectation).unwrap();
            if operation != "create" {
                assert_eq!(effects.create_calls, creates_before_retry);
            }
            assert_eq!(
                store.latest_probe_record().unwrap().state,
                ProbeJournalState::Removed
            );
            store.release_lock(token).unwrap();
        }
    }

    #[test]
    fn every_post_effect_pre_persist_crash_is_reconciled_without_blind_replay() {
        for (operation, expected_state) in [
            ("create-after", ProbeJournalState::CreateIntended),
            ("configure-after", ProbeJournalState::ConfigureIntended),
            ("kill-after", ProbeJournalState::KillIntended),
            ("remove-after", ProbeJournalState::RemoveIntended),
        ] {
            let fixture = Fixture::new();
            let expectation = probe_expectation(&fixture);
            let mut store = fixture.open_store();
            let token = store.acquire_lock().unwrap();
            let mut effects = MockProbeEffects::new(expectation);
            effects.fail_once = Some(operation);
            let error = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
            assert_eq!(error.operation, operation);
            assert_eq!(store.latest_probe_record().unwrap().state, expected_state);
            effects.fail_once = None;

            if operation == "create-after" {
                let unknown =
                    drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
                assert_eq!(unknown.operation, "preflight-probe-ownership-unknown");
                assert_eq!(effects.remove_calls, 0);
                effects.present_identity = None;
            }
            drive_durable_probe(&mut store, &mut effects, expectation).unwrap();
            assert_eq!(
                store.latest_probe_record().unwrap().state,
                ProbeJournalState::Removed
            );
            store.release_lock(token).unwrap();
        }
    }

    #[test]
    fn restart_reopens_and_recovers_every_durable_probe_intent() {
        for operation in ["create", "shape", "configure", "kill", "remove"] {
            let fixture = Fixture::new();
            let expectation = probe_expectation(&fixture);
            let mut store = fixture.open_store();
            let token = store.acquire_lock().unwrap();
            let mut effects = MockProbeEffects::new(expectation);
            effects.fail_once = Some(operation);
            drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
            let state_before_restart = store.latest_probe_record().unwrap().state;
            store.release_lock(token).unwrap();
            drop(store);

            let mut reopened = fixture.open_store();
            let token = reopened.acquire_lock().unwrap();
            assert_eq!(
                reopened.latest_probe_record().unwrap().state,
                state_before_restart
            );
            effects.fail_once = None;
            drive_durable_probe(&mut reopened, &mut effects, expectation).unwrap();
            assert_eq!(
                reopened.latest_probe_record().unwrap().state,
                ProbeJournalState::Removed
            );
            reopened.release_lock(token).unwrap();
        }
    }

    #[test]
    fn orphan_probe_journal_publication_recovers_canonically() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let store = fixture.open_store();
        let record = new_probe_intent(expectation, ProbeEpisodeKind::DelegationDefaultShape).unwrap();
        let bytes = encode_probe_envelope(0, &record).unwrap();
        write_new_private_file(
            &store.probe_directory,
            &probe_temporary_name(0),
            &bytes,
            fixture.expected_uid,
        )
        .unwrap();
        sync_directory(&store.probe_directory).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let token = reopened.acquire_lock().unwrap();
        assert_eq!(reopened.latest_probe_record(), Some(record));
        assert!(
            fixture
                .probe_journal_path()
                .join(probe_final_name(0))
                .is_file()
        );
        assert!(
            !fixture
                .probe_journal_path()
                .join(probe_temporary_name(0))
                .exists()
        );
        reopened.release_lock(token).unwrap();
    }

    #[test]
    fn create_before_identity_crash_preserves_unknown_until_name_is_absent() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let mut effects = MockProbeEffects::new(expectation);
        effects.fail_observe_after_create = true;

        let first = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
        assert_eq!(first.operation, "mock-observe-after-create");
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::CreateIntended
        );
        let second = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
        assert_eq!(second.operation, "preflight-probe-ownership-unknown");
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::OwnershipUnknown
        );
        assert_eq!(effects.remove_calls, 0);

        effects.present_identity = None;
        drive_durable_probe(&mut store, &mut effects, expectation).unwrap();
        assert_eq!(effects.create_calls, 2);
        assert_eq!(effects.remove_calls, 1);
        store.release_lock(token).unwrap();
    }

    #[test]
    fn authoritative_probe_identity_substitution_is_never_removed() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let mut effects = MockProbeEffects::new(expectation);
        effects.fail_once = Some("configure");
        drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::ConfigureIntended
        );
        effects.fail_once = None;
        effects.present_identity = Some(CgroupObjectIdentity {
            device: expectation.delegation_identity.device,
            inode: 999,
        });

        let error = drive_durable_probe(&mut store, &mut effects, expectation).unwrap_err();
        assert_eq!(error.operation, "mock-probe-identity-substitution");
        assert_eq!(effects.remove_calls, 0);
        assert_eq!(
            store.latest_probe_record().unwrap().state,
            ProbeJournalState::ConfigureIntended
        );
        store.release_lock(token).unwrap();
    }

    #[test]
    fn probe_symlink_and_journal_hardlink_forgery_fail_closed() {
        let fixture = Fixture::new();
        let parent = fixture.parent();
        let parent_identity = cgroup_identity(object_identity(&parent.dir_metadata().unwrap()));
        let record = ProbeJournalRecord {
            state: ProbeJournalState::CreateIntended,
            episode_kind: ProbeEpisodeKind::DelegationDefaultShape,
            probe_name: format!(".gb-probe-{}", "a".repeat(32)),
            expected_delegation_identity: parent_identity,
            expected_owner_uid: fixture.expected_uid,
            observed_identity: None,
            identity_authoritative: false,
            initial_shape: None,
            configured_and_read_back: false,
            stable_empty_proven: false,
            canary: None,
        };
        symlink("journal", fixture.path.join(&record.probe_name)).unwrap();
        assert!(open_named_probe(&parent, &record).is_err());
        assert!(fixture.path.join(&record.probe_name).is_symlink());

        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        store.persist_probe(&record).unwrap();
        store.sync().unwrap();
        store.release_lock(token).unwrap();
        fs::hard_link(
            fixture.probe_journal_path().join(probe_final_name(0)),
            fixture.probe_journal_path().join("forged-hardlink"),
        )
        .unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        assert!(reopened.read_latest().is_err());
    }

    #[test]
    fn writer_lock_is_cross_instance_and_release_token_is_exact() {
        let fixture = Fixture::new();
        let mut first = fixture.open_store();
        let mut second = fixture.open_store();
        let token = first.acquire_lock().unwrap();
        assert!(second.acquire_lock().is_err());
        assert!(first.require_token(token + 1).is_err());
        assert!(first.release_lock(token + 1).is_err());
        first.release_lock(token).unwrap();
        assert!(first.require_token(token).is_err());
        let second_token = second.acquire_lock().unwrap();
        second.release_lock(second_token).unwrap();
    }

    #[test]
    fn unresolved_post_create_probe_failure_retains_the_internal_flock() {
        let fixture = Fixture::new();
        let service_parent = fixture.parent();
        let metadata = service_parent.dir_metadata().unwrap();
        let identity = cgroup_identity(object_identity(&metadata));
        let journal = fixture.open_store();
        let mut contender = fixture.open_store();
        let mut backend = LinuxCgroupIo {
            service_parent: service_parent.try_clone().unwrap(),
            delegation_name: "unused-in-this-test".into(),
            delegation: service_parent,
            expectation: DelegationRootExpectation {
                service_parent_identity: identity,
                delegation_identity: identity,
                owner_uid: fixture.expected_uid,
                delegation_mode: OsMetadataExt::mode(&metadata) & 0o7777,
            },
            journal,
            mechanics_guard: None,
            helper_image_override: None,
            leaves: BTreeMap::new(),
            active_probe: None,
            probe_reconciliation_required: true,
            #[cfg(target_os = "linux")]
            procfs: LinuxProcfs::open_authenticated().unwrap(),
            #[cfg(target_os = "linux")]
            held_launchers: HeldLauncherRegistry::default(),
        };
        let raw_token = backend.journal.acquire_lock().unwrap();
        let token = DelegationLockToken::new(raw_token);

        let error = backend.release_delegation_lock(&token).unwrap_err();
        assert_eq!(error.operation, "release-delegation-lock");
        assert_eq!(error.certainty, EffectCertainty::Ambiguous);
        assert!(contender.acquire_lock().is_err());

        backend.probe_reconciliation_required = false;
        backend.release_delegation_lock(&token).unwrap();
        let contender_token = contender.acquire_lock().unwrap();
        contender.release_lock(contender_token).unwrap();
    }

    #[test]
    fn completed_probe_cache_does_not_consume_generations_across_repeated_leases() {
        let fixture = Fixture::new();
        let probe_expectation = probe_expectation(&fixture);
        let mut journal = fixture.open_store();
        let token = journal.acquire_lock().unwrap();
        let mut effects = MockProbeEffects::new(probe_expectation);
        let evidence = drive_durable_probe(&mut journal, &mut effects, probe_expectation).unwrap();
        journal.release_lock(token).unwrap();
        let initial_generations = fs::read_dir(fixture.probe_journal_path())
            .unwrap()
            .filter_map(Result::ok)
            .count();

        let service_parent = fixture.parent();
        let metadata = service_parent.dir_metadata().unwrap();
        let identity = cgroup_identity(object_identity(&metadata));
        let mut backend = LinuxCgroupIo {
            service_parent: service_parent.try_clone().unwrap(),
            delegation_name: "unused-in-this-test".into(),
            delegation: service_parent,
            expectation: DelegationRootExpectation {
                service_parent_identity: identity,
                delegation_identity: identity,
                owner_uid: fixture.expected_uid,
                delegation_mode: OsMetadataExt::mode(&metadata) & 0o7777,
            },
            journal,
            mechanics_guard: None,
            helper_image_override: None,
            leaves: BTreeMap::new(),
            active_probe: Some(evidence),
            probe_reconciliation_required: false,
            #[cfg(target_os = "linux")]
            procfs: LinuxProcfs::open_authenticated().unwrap(),
            #[cfg(target_os = "linux")]
            held_launchers: HeldLauncherRegistry::default(),
        };
        for _ in 0..600 {
            let raw = backend.journal.acquire_lock().unwrap();
            let token = DelegationLockToken::new(raw);
            backend.run_delegation_probe(&token).unwrap();
            backend.release_delegation_lock(&token).unwrap();
        }
        let final_generations = fs::read_dir(fixture.probe_journal_path())
            .unwrap()
            .filter_map(Result::ok)
            .count();
        assert_eq!(final_generations, initial_generations);
    }

    #[test]
    fn exact_directory_removal_never_unlinks_a_replacement_name() {
        let fixture = Fixture::new();
        let parent = fixture.parent();
        parent.create_dir("victim").unwrap();
        let retained = parent.open_dir_nofollow("victim").unwrap();
        let retained_identity = cgroup_identity(object_identity(&retained.dir_metadata().unwrap()));

        fs::rename(
            fixture.path.join("victim"),
            fixture.path.join("retained-original"),
        )
        .unwrap();
        fs::create_dir(fixture.path.join("victim")).unwrap();

        let error = remove_and_prove_named_directory_exact(
            &parent,
            "victim",
            &retained,
            retained_identity,
            "test-remove-exact",
        )
        .unwrap_err();
        assert_eq!(error.operation, "test-remove-exact");
        assert!(fixture.path.join("victim").is_dir());
        assert!(fixture.path.join("retained-original").is_dir());
    }

    #[test]
    fn exact_probe_cleanup_proves_absence() {
        let fixture = Fixture::new();
        let parent = fixture.parent();
        parent.create_dir("probe").unwrap();
        let retained = parent.open_dir_nofollow("probe").unwrap();
        let identity = cgroup_identity(object_identity(&retained.dir_metadata().unwrap()));
        remove_and_prove_named_directory_exact(
            &parent,
            "probe",
            &retained,
            identity,
            "test-probe-cleanup",
        )
        .unwrap();
        assert!(!fixture.path.join("probe").exists());
    }

    #[test]
    fn orphan_temporary_is_canonically_published_on_reopen() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let record = create_intent();
        store.persist(&record).unwrap();
        store.sync().unwrap();
        store.release_lock(token).unwrap();
        store
            .directory
            .rename(final_name(0), &store.directory, temporary_name(0))
            .unwrap();
        sync_directory(&store.directory).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        assert_eq!(reopened.read_latest().unwrap(), Some(record));
        assert!(fixture.journal_path().join(final_name(0)).is_file());
        assert!(!fixture.journal_path().join(temporary_name(0)).exists());
    }

    #[test]
    fn orphan_temporary_must_be_the_exact_valid_successor_before_publication() {
        let fixture = Fixture::new();
        let store = fixture.open_store();
        let bytes = encode_envelope(1, &create_intent()).unwrap();
        write_new_private_file(
            &store.directory,
            &temporary_name(1),
            &bytes,
            fixture.expected_uid,
        )
        .unwrap();
        sync_directory(&store.directory).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let error = reopened.read_latest().unwrap_err();
        assert_eq!(error.operation, "recover-journal-temporary");
        assert!(fixture.journal_path().join(temporary_name(1)).is_file());
        assert!(!fixture.journal_path().join(final_name(1)).exists());
    }

    #[test]
    fn noncanonical_or_digest_mutated_generation_fails_closed() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        store.persist(&create_intent()).unwrap();
        store.sync().unwrap();
        store.release_lock(token).unwrap();
        let mut options = CapOpenOptions::new();
        options.append(true).follow(FollowSymlinks::No);
        let mut file = store.directory.open_with(final_name(0), &options).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        drop(file);
        drop(store);

        let mut reopened = fixture.open_store();
        assert!(reopened.read_latest().is_err());

        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let mut record = create_intent();
        record.request_digest = "not-a-digest".into();
        assert!(store.persist(&record).is_err());
        store.release_lock(token).unwrap();
    }

    #[test]
    fn retained_store_rejects_same_byte_generation_inode_substitution() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        store.persist(&create_intent()).unwrap();
        store.sync().unwrap();

        let generation_name = final_name(0);
        let staging_name = temporary_name(0);
        let canonical_bytes = store.latest.as_ref().unwrap().canonical_bytes.clone();
        let original_identity = store.latest.as_ref().unwrap().identity;
        // The substituted object is created while the original is still linked,
        // then renamed over it. Unlinking first and recreating under the same
        // name -- what this test used to do -- only produces a distinguishable
        // object on a filesystem that does not immediately recycle inode
        // numbers. tmpfs allocates them from a monotonic counter and satisfied
        // it by accident; ext4 and overlayfs hand the number straight back, so
        // the replacement arrived with `device: 42, inode: 538891` on both
        // sides and the test failed in its own setup, before reaching the
        // assertion it exists to make. Holding the original link open across
        // the create makes the distinct inode a property of the kernel's
        // allocator contract rather than of the host's filesystem, so what is
        // asserted below is the store's rejection and nothing else.
        //
        // What that accident exposed about the product is recorded rather than
        // repaired here: `verify_latest_generation` proves custody with a
        // dev/ino pair plus a full canonical-byte comparison, and on an
        // inode-recycling filesystem the dev/ino half cannot distinguish a
        // byte-identical, mode-identical, single-link recreate from the
        // original object. The byte comparison and `validate_private_file`
        // still hold; object identity alone does not.
        let replacement_identity = write_new_private_file(
            &store.directory,
            &staging_name,
            &canonical_bytes,
            fixture.expected_uid,
        )
        .unwrap();
        assert_ne!(replacement_identity, original_identity);
        store
            .directory
            .rename(&staging_name, &store.directory, &generation_name)
            .unwrap();
        sync_directory(&store.directory).unwrap();

        let error = store.sync().unwrap_err();
        assert_eq!(error.operation, "journal-generation-identity");
        store.release_lock(token).unwrap();
    }

    #[test]
    fn journal_root_and_named_entry_identity_are_fail_closed() {
        let fixture = Fixture::new();
        fs::set_permissions(fixture.journal_path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            CanonicalCgroupJournalStore::open_test_retained(
                fixture.parent(),
                &fixture.journal_name,
                fixture.expected_uid,
            )
            .is_err()
        );

        let fixture = Fixture::new();
        fs::remove_dir(fixture.journal_path()).unwrap();
        symlink("outside", fixture.journal_path()).unwrap();
        assert!(
            CanonicalCgroupJournalStore::open_test_retained(
                fixture.parent(),
                &fixture.journal_name,
                fixture.expected_uid,
            )
            .is_err()
        );
    }

    #[test]
    fn immutable_binding_and_transition_order_cannot_change() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();
        let create = create_intent();
        store.persist(&create).unwrap();
        store.sync().unwrap();

        let mut forged = configuring(create.clone());
        forged.request_digest = "e".repeat(64);
        assert!(store.persist(&forged).is_err());
        assert!(store.persist(&prepared(configuring(create))).is_err());
        store.release_lock(token).unwrap();
    }

    #[test]
    fn controller_parser_rejects_unmodeled_enabled_state() {
        assert_eq!(
            parse_controller_set(b"memory pids\n", true).unwrap(),
            [DomainController::Memory, DomainController::Pids]
                .into_iter()
                .collect()
        );
        assert!(parse_controller_set(b"cpu memory pids\n", true).is_err());
        assert!(parse_controller_set(b"memory memory pids\n", true).is_err());
        assert!(parse_controller_set(b"memory pids\r\n", true).is_err());
        assert!(parse_controller_set(b"memory\tpids\n", true).is_err());
        assert!(parse_controller_set(b"memory\x0cpids\n", true).is_err());
        assert!(parse_controller_set(b"memory  pids\n", true).is_err());
        assert!(parse_controller_set(b" memory pids\n", true).is_err());
        assert!(parse_controller_set(b"memory pids \n", true).is_err());
        assert!(parse_controller_set(b"_memory pids\n", false).is_err());
        assert!(parse_controller_set(b"2cpu memory pids\n", false).is_err());
        assert!(parse_controller_set(b"cpu cpu memory pids\n", false).is_err());
        assert_eq!(
            parse_controller_set(b"cpu io memory pids\n", false).unwrap(),
            [DomainController::Memory, DomainController::Pids]
                .into_iter()
                .collect()
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_backend_refuses_before_opening_a_cgroup() {
        assert!(ensure_linux_host().is_err());
    }

    /// The frozen real version-1 probe journal envelope.
    ///
    /// Produced by the version-1 probe machine itself — the `configured`
    /// generation of a complete `drive_durable_probe` run — and committed
    /// rather than recorded, so restart validation is driven by bytes that
    /// really existed rather than by a hand-written document.
    const PROBE_JOURNAL_V1_RECORD: &str =
        "fixtures/linux-probe-journal/probe-journal-format-v1-configured-record.json";

    /// A canary suite that runs inside a journaled probe leaf.
    ///
    /// It delegates the entire lifecycle to the delegation probe's own mock,
    /// so the only difference between the two episode kinds under test is the
    /// declared kind and the suite that runs in the configured leaf.
    struct MockCanaryEffects {
        inner: MockProbeEffects,
        outcomes: Vec<CanaryControlOutcomeV1>,
        probe_runs: u32,
        suite_calls: usize,
        observed_root: Option<CgroupObjectIdentity>,
    }

    impl MockCanaryEffects {
        fn new(expectation: DelegationRootExpectation) -> Self {
            Self {
                inner: MockProbeEffects::new(expectation),
                outcomes: vec![
                    CanaryControlOutcomeV1 {
                        control: "DescendantDomainKill".into(),
                        probe: format!(".gb-probe-{}", "1".repeat(32)),
                        proven: true,
                        witness_digest: sha256_hex(b"domain-kill-witness"),
                    },
                    CanaryControlOutcomeV1 {
                        control: "DescendantLimit".into(),
                        probe: format!(".gb-probe-{}", "2".repeat(32)),
                        proven: true,
                        witness_digest: sha256_hex(b"descendant-limit-witness"),
                    },
                ],
                probe_runs: 2,
                suite_calls: 0,
                observed_root: None,
            }
        }

        fn evidence(&self, root: CgroupObjectIdentity) -> CanaryEpisodeEvidenceV1 {
            let mut evidence = CanaryEpisodeEvidenceV1 {
                generation: CANARY_EPISODE_GENERATION.to_owned(),
                root_identity: root,
                probe_runs: self.probe_runs,
                outcomes: self.outcomes.clone(),
                suite_result_digest: String::new(),
            };
            evidence.suite_result_digest = evidence.canonical_digest();
            evidence
        }
    }

    impl DurableProbeEffects for MockCanaryEffects {
        fn episode_kind(&self) -> ProbeEpisodeKind {
            ProbeEpisodeKind::ControlCanary
        }

        fn run_canary_suite(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<Option<CanaryEpisodeEvidenceV1>, CgroupIoFailure> {
            self.suite_calls += 1;
            let root = record
                .observed_identity
                .expect("a canary suite only runs inside an authoritative leaf");
            self.observed_root = Some(root);
            Ok(Some(self.evidence(root)))
        }

        fn observe_identity(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<Option<CgroupObjectIdentity>, CgroupIoFailure> {
            self.inner.observe_identity(record)
        }

        fn observe_shape(
            &mut self,
            record: &ProbeJournalRecord,
            identity: CgroupObjectIdentity,
        ) -> Result<Option<ProbeDefaultShape>, CgroupIoFailure> {
            self.inner.observe_shape(record, identity)
        }

        fn create_no_replace(&mut self, name: &str) -> Result<(), CgroupIoFailure> {
            self.inner.create_no_replace(name)
        }

        fn configure_exact(&mut self, record: &ProbeJournalRecord) -> Result<bool, CgroupIoFailure> {
            self.inner.configure_exact(record)
        }

        fn kill_and_prove_empty(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<bool, CgroupIoFailure> {
            self.inner.kill_and_prove_empty(record)
        }

        fn remove_exact_and_prove(
            &mut self,
            record: &ProbeJournalRecord,
        ) -> Result<(), CgroupIoFailure> {
            self.inner.remove_exact_and_prove(record)
        }
    }

    /// A canary episode is durable, repeatable, and is not a command effect.
    ///
    /// This is the increment's central claim, and it is asserted in both
    /// directions rather than argued. Three canary episodes run to their
    /// endpoints and every one of them is journaled — the claim survives a
    /// restart and is readable from the reopened store — while the command
    /// journal's one-episode-per-effect invariant is untouched throughout:
    /// the effect is still fresh after three canaries, still refused after the
    /// command's own `CreateIntended`, and a fourth canary still runs after
    /// the effect is spent.
    ///
    /// The last of those is the property the whole correction exists for. The
    /// command journal refuses a repeated effect **durably**, which is right
    /// for an effect and was wrong for a canary; a canary that could not
    /// repeat could only ever run after the permit it was supposed to justify.
    #[test]
    fn a_canary_episode_is_durably_journaled_and_never_becomes_a_command_effect() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let mut store = fixture.open_store();
        let token = store.acquire_lock().unwrap();

        let mut names = BTreeSet::new();
        for _ in 0..3 {
            let mut effects = MockCanaryEffects::new(expectation);
            let evidence = drive_canary_episode(&mut store, &mut effects, expectation).unwrap();
            assert_eq!(effects.suite_calls, 1);
            assert_eq!(evidence.generation, CANARY_EPISODE_GENERATION);
            assert_eq!(evidence.suite_result_digest, evidence.canonical_digest());
            assert_eq!(
                evidence.proven_control_names(),
                BTreeSet::from([
                    "DescendantDomainKill".to_owned(),
                    "DescendantLimit".to_owned(),
                ])
            );
            let record = store.latest_probe_record().unwrap();
            assert_eq!(record.state, ProbeJournalState::Removed);
            assert_eq!(record.episode_kind, ProbeEpisodeKind::ControlCanary);
            assert_eq!(record.canary.as_ref(), Some(&evidence));
            // Each episode is its own leaf; a name is never reused.
            assert!(names.insert(record.probe_name.clone()));
        }

        // The command effect the canaries share a delegation with is still
        // completely fresh: no canary episode entered its history.
        let create = create_intent();
        let request = request_for_record(&create);
        store.require_fresh_episode(token, &request).unwrap();
        store.persist(&create).unwrap();
        store.sync().unwrap();
        let spent = store.require_fresh_episode(token, &request).unwrap_err();
        assert_eq!(spent.certainty, EffectCertainty::PriorEffectCommitted);

        // And a canary still runs after the effect is spent, which is exactly
        // what one episode per effect forbids and one leaf per canary allows.
        let mut effects = MockCanaryEffects::new(expectation);
        let after = drive_canary_episode(&mut store, &mut effects, expectation).unwrap();
        assert_eq!(after.proven_control_names().len(), 2);
        assert!(names.insert(store.latest_probe_record().unwrap().probe_name));
        store.release_lock(token).unwrap();
        drop(store);

        let mut reopened = fixture.open_store();
        let token = reopened.acquire_lock().unwrap();
        let restored = reopened.latest_probe_record().unwrap();
        assert_eq!(restored.episode_kind, ProbeEpisodeKind::ControlCanary);
        assert_eq!(restored.canary, Some(after));
        let still_spent = reopened.require_fresh_episode(token, &request).unwrap_err();
        assert_eq!(still_spent.certainty, EffectCertainty::PriorEffectCommitted);
        reopened.release_lock(token).unwrap();
    }

    /// The command's own leaf cannot host the canary episode that would prove
    /// it, and the journal says so three separate times.
    ///
    /// The proposal this measures is: prepare the command's domain first, run
    /// the canary suite **inside that same leaf**, produce the control report,
    /// mint the permit, then launch the command into the leaf the canaries just
    /// proved. It would make "proven on the command's own leaf" satisfiable
    /// without weakening a validator, which is why it is worth measuring rather
    /// than assuming.
    ///
    /// It is inadmissible, and each clause below is independently sufficient.
    /// None of them is a policy: they are the single-writer discipline, the
    /// one-episode-per-effect rule and the linear record chain that this
    /// journal already had.
    #[test]
    fn the_command_leaf_cannot_host_the_canary_episode_that_would_prove_it() {
        let fixture = Fixture::new();
        let mut store = fixture.open_store();

        // 1. The lock. `prepare_domain` acquires the delegation lock and
        //    retains it inside the `PreparedDomain` for the domain's whole
        //    life; `run_canary_episode` opens by acquiring the same lock. A
        //    second acquisition is refused by name, so a canary episode is
        //    unreachable from the moment the command's leaf exists — and the
        //    leaf's name is an unpredictable nonce minted inside that same
        //    locked section, so there is no earlier moment at which the leaf
        //    exists to prove anything about.
        let token = store.acquire_lock().unwrap();
        let contended = store.acquire_lock().unwrap_err();
        assert_eq!(contended.operation, "lock-journal");
        assert_eq!(contended.certainty, EffectCertainty::NotApplied);
        assert!(
            contended.detail.contains("already owns the journal lock"),
            "the second acquisition must refuse by name, got {}",
            contended.detail
        );

        // 2. One episode per effect, durably. The production entry point reads
        //    its request out of the retained one-plan-scoped mechanics guard
        //    and therefore answers with the *same* request every time, so
        //    "prepare a throwaway domain for the canary, then prepare the
        //    command's" is one effect asked for twice.
        let create = create_intent();
        let request = request_for_record(&create);
        store.require_fresh_episode(token, &request).unwrap();
        store.persist(&create).unwrap();
        store.sync().unwrap();
        let second_domain = store.require_fresh_episode(token, &request).unwrap_err();
        assert_eq!(
            second_domain.certainty,
            EffectCertainty::PriorEffectCommitted
        );
        store.release_lock(token).unwrap();

        // 3. And if a canary were released into the command's own domain, it
        //    would spend the one release the episode has and leave the record
        //    somewhere the command can no longer be launched from: the only
        //    successor of `Released` is `Killing`.
        let configuring = configuring(create);
        let prepared = prepared(configuring);
        let attach_intended = attach_intended(prepared);
        let attached = attached(attach_intended);
        let held = held(attached);
        let release_intended = release_intended(held);
        let released = released(release_intended);
        validate_record_successor(&released, &killing(released.clone())).unwrap();
        for state in [
            DomainJournalState::CreateIntended,
            DomainJournalState::CreateAborted,
            DomainJournalState::Configuring,
            DomainJournalState::Prepared,
            DomainJournalState::AttachIntended,
            DomainJournalState::Attached,
            DomainJournalState::Held,
            DomainJournalState::ReleaseIntended,
            DomainJournalState::Released,
            DomainJournalState::EmptyProven,
            DomainJournalState::RemoveIntended,
            DomainJournalState::Removed,
        ] {
            let mut next = released.clone();
            next.state = state;
            assert!(
                validate_record_successor(&released, &next).is_err(),
                "a released command domain must admit no successor but Killing, \
                 and it admitted {state:?}"
            );
        }

        // The same rule read from the other side: the release binding an
        // episode committed is frozen, and a second one cannot replace it.
        let mut second_release = released.clone();
        second_release.state = DomainJournalState::Killing;
        second_release.release_observation = None;
        assert!(validate_record_successor(&released, &second_release).is_err());
    }

    /// The frozen real protocol-version-3 command-journal record.
    ///
    /// Written by the version-3 journal machine itself, six `persist`
    /// generations driven to `Held`, and committed at `ada11a4` before the
    /// version-4 bump — because after it no tree can emit one.
    const HELD_LAUNCHER_PROTOCOL_V3_RECORD: &str =
        "fixtures/linux-held-launcher/held-launcher-protocol-v3-held-record.json";

    /// A persisted protocol-version-3 release binding is refused, and named.
    ///
    /// Version 3 differs from version 2 in a way worth stating: it *did* carry
    /// a containment artefact. What version 4 adds is a second filter beside
    /// the first, so the refusal cannot say version 3 had no artefact — only
    /// that it had no channel for this one. The classifier says exactly that.
    #[test]
    fn a_persisted_protocol_v3_release_binding_is_refused_by_a_message_naming_both_versions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(HELD_LAUNCHER_PROTOCOL_V3_RECORD);
        let bytes = std::fs::read(&path).expect("the frozen version-3 record is checked in");
        assert_eq!(bytes.len(), 3_643, "the frozen record changed size");
        assert_eq!(
            sha256_hex(&bytes),
            "ef14faf2e35a79ee6399217e26cc1188632b3380593922fe2a953f648baf5d7b",
            "the frozen record is not the bytes this test was written against"
        );
        // The envelope framing is unchanged again; only the held-launcher
        // protocol inside it moved.
        assert!(
            bytes.starts_with(br#"{"format_version":2,"#),
            "the frozen record is not a version-2 envelope"
        );
        let shape: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            shape["record"]["release_binding"]["protocol_version"],
            serde_json::json!(3),
            "the frozen record is not a version-3 binding"
        );

        let refusal = decode_envelope(&bytes)
            .expect_err("a protocol-version-3 release binding must be refused rather than upgraded");
        for expected in [
            "protocol version 3",
            "protocol version 4",
            "never migrated",
            "no migration can invent one",
        ] {
            assert!(
                refusal.detail.contains(expected),
                "the refusal does not name {expected}: {}",
                refusal.detail
            );
        }
        assert_eq!(refusal.certainty, EffectCertainty::NotApplied);
    }

    /// The frozen real protocol-version-2 command-journal record.
    ///
    /// Written by the version-2 journal machine itself — six `persist`
    /// generations driven to `Held`, so the file carries a genuine version-2
    /// `HeldExecReleaseBinding` rather than a document composed to look like
    /// one — and committed rather than recorded, so restart validation is
    /// driven by bytes that really existed.
    const HELD_LAUNCHER_PROTOCOL_V2_RECORD: &str =
        "fixtures/linux-held-launcher/held-launcher-protocol-v2-held-record.json";

    /// A persisted protocol-version-2 release binding is refused, and named,
    /// never migrated.
    ///
    /// The envelope's own `format_version` is **2 on both sides** and stays
    /// there: the command journal's framing did not change, the held-launcher
    /// protocol inside it did. That is exactly why the refusal needs its own
    /// classifier — a reader that only checked the envelope version would
    /// admit this document and then meet the release binding as a serde
    /// missing-field error naming neither protocol version.
    #[test]
    fn a_persisted_protocol_v2_release_binding_is_refused_by_a_message_naming_both_versions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(HELD_LAUNCHER_PROTOCOL_V2_RECORD);
        let bytes = std::fs::read(&path).expect("the frozen version-2 record is checked in");
        assert_eq!(bytes.len(), 3_605, "the frozen record changed size");
        assert_eq!(
            sha256_hex(&bytes),
            "5d263d58c42b41b6c3ef406770bd7b1efa0e1021836578e3e4a8ad92ff74f942",
            "the frozen record is not the bytes this test was written against"
        );
        // The envelope framing is unchanged, and the release binding it
        // carries has no protocol version at all, because version 2 never
        // wrote one. Both facts are what the classifier reads.
        assert!(
            bytes.starts_with(br#"{"format_version":2,"#),
            "the frozen record is not a version-2 envelope"
        );
        let shape: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            shape["record"]["release_binding"]
                .get("protocol_version")
                .is_none(),
            "the frozen record already carries a protocol version"
        );

        let refusal = decode_envelope(&bytes)
            .expect_err("a protocol-version-2 release binding must be refused rather than upgraded");
        for expected in [
            "protocol version 2",
            // The spoken version, which moved to 4 with the namespace-filter
            // channel. A version-2 binding is still refused; the message now
            // names the version that refuses it.
            "protocol version 4",
            "never migrated",
            "no migration can invent one",
        ] {
            assert!(
                refusal.detail.contains(expected),
                "the refusal does not name {expected}: {}",
                refusal.detail
            );
        }
        assert_eq!(refusal.certainty, EffectCertainty::NotApplied);

        // The same bytes with only the version number written in. If version 3
        // were version 2 with a number added, this would now be admitted.
        //
        // It is not, and the mechanism is worth naming: `release_spec_hash` is
        // a digest of the whole specification, so version 3's new field is
        // inside the preimage of a hash the record itself carries. A version-2
        // specification therefore cannot hash to a version-3 one, and the
        // refusal is a digest equality rather than a missing-field message.
        let renumbered = String::from_utf8(bytes)
            .expect("the frozen record is UTF-8")
            .replacen(
                r#""release_binding":{"specification""#,
                // The *current* spoken version: renumbering to a version that
                // is also stale would be refused by the version classifier
                // before reaching the content check this arm is about.
                r#""release_binding":{"protocol_version":4,"specification""#,
                1,
            );
        let renumbered_refusal = decode_envelope(renumbered.as_bytes())
            .expect_err("a renumbered version-2 binding must still be refused");
        assert!(
            renumbered_refusal
                .detail
                .contains("release specification hash does not match"),
            "a renumbered record was not refused on the field the bump added: {}",
            renumbered_refusal.detail
        );
        // And the shape a forger could reach by recomputing that digest is the
        // inert internal target, which both versions express identically and
        // which installs nothing. A contained command was **inexpressible** in
        // version 2, so no version-2 record can be rewritten into one.
        assert_eq!(
            shape["record"]["release_binding"]["specification"]["target_kind"],
            serde_json::json!("inert_internal_test")
        );

        // And a record with no release binding at all — the normal shape of
        // every generation before one is planned — is not touched by any of
        // this. The classifier must not turn an absence into a stale version.
        let unplanned = serde_json::json!({ "state": "prepared" });
        classify_held_launcher_protocol(Some(&unplanned)).unwrap();
        classify_held_launcher_protocol(None).unwrap();
    }

    /// A persisted version-1 probe record is refused, and named, never migrated.
    ///
    /// Driven by the real bytes the version-1 machine wrote. The refusal has
    /// to name both versions to be diagnosable at all, and reaching it
    /// required reading the format version before the typed decode: version 2
    /// added two required fields to a `deny_unknown_fields` record, so serde
    /// otherwise refuses first with a missing-field message that tells an
    /// operator nothing about which version they are holding. Plan schema v4
    /// paid for that lesson; this is the same hazard in a different journal.
    #[test]
    fn a_persisted_probe_journal_v1_record_is_refused_by_a_message_naming_both_versions() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(PROBE_JOURNAL_V1_RECORD);
        let bytes = std::fs::read(&path).expect("the frozen version-1 record is checked in");
        assert_eq!(bytes.len(), 691, "the frozen record changed size");
        assert_eq!(
            sha256_hex(&bytes),
            "1cee72c1611fcbc9c7ffec2c9b431827efc7f8bcbc85b3d356e290ae3641960b",
            "the frozen record is not the bytes this test was written against"
        );
        assert!(
            bytes.starts_with(br#"{"format_version":1,"#),
            "the frozen record is not a version-1 document"
        );

        let refusal = decode_probe_envelope(&bytes)
            .expect_err("a version-1 probe record must be refused rather than upgraded");
        let message = refusal.detail.clone();
        for expected in [
            "format version 1",
            &format!("version {PROBE_JOURNAL_FORMAT_VERSION}"),
            "never migrated",
        ] {
            assert!(
                message.contains(expected),
                "the refusal does not name {expected}: {message}"
            );
        }

        // The same bytes with only the version number rewritten. If version 2
        // were version 1 with a different number, this would now be admitted.
        let renumbered = String::from_utf8(bytes)
            .expect("the frozen record is UTF-8")
            .replacen(r#"{"format_version":1,"#, r#"{"format_version":2,"#, 1);
        let renumbered_refusal = decode_probe_envelope(renumbered.as_bytes())
            .expect_err("a renumbered version-1 record must still be refused");
        assert!(
            renumbered_refusal.detail.contains("episode_kind"),
            "a renumbered record was not refused on the field version 2 added: {}",
            renumbered_refusal.detail
        );
    }

    /// Every way of writing a canary claim that no probe produced is refused.
    ///
    /// Nine control arms, each varying exactly one thing about an otherwise
    /// admitted episode. The point of the closed compiled control vocabulary
    /// and the self-covering suite digest is that a durable record cannot
    /// invent a capability, and the point of the write-once rule is that a
    /// later generation cannot restate what an earlier one established.
    #[test]
    fn a_canary_episode_claim_cannot_be_invented_forged_or_restated() {
        let fixture = Fixture::new();
        let expectation = probe_expectation(&fixture);
        let root = CgroupObjectIdentity {
            device: expectation.delegation_identity.device,
            inode: 12,
        };
        let admitted = MockCanaryEffects::new(expectation).evidence(root);
        let mut authoritative = new_probe_intent(expectation, ProbeEpisodeKind::ControlCanary)
            .unwrap();
        authoritative.state = ProbeJournalState::KillIntended;
        authoritative.observed_identity = Some(root);
        authoritative.identity_authoritative = true;
        authoritative.initial_shape = Some(default_probe_shape(expectation));
        authoritative.configured_and_read_back = true;
        authoritative.canary = Some(admitted.clone());
        authoritative.validate().expect("the admitted shape validates");

        // 1. A delegation probe may not carry a control claim at all.
        let mut wrong_kind = authoritative.clone();
        wrong_kind.episode_kind = ProbeEpisodeKind::DelegationDefaultShape;
        assert!(wrong_kind.validate().is_err());

        // 2. A claim about a leaf this episode never observed.
        let mut foreign_leaf = authoritative.clone();
        foreign_leaf.canary.as_mut().unwrap().root_identity = CgroupObjectIdentity {
            device: root.device,
            inode: root.inode + 1,
        };
        assert!(foreign_leaf.validate().is_err());

        // 3. A control outside the closed compiled vocabulary.
        let mut invented = authoritative.clone();
        invented.canary.as_mut().unwrap().outcomes[0].control = "TotalIsolation".into();
        assert!(invented.validate().is_err());

        // 4. A proven control whose witness is the one value an absent probe
        //    leaves behind.
        let mut absent_witness = authoritative.clone();
        {
            let canary = absent_witness.canary.as_mut().unwrap();
            canary.outcomes[0].witness_digest = "0".repeat(64);
            canary.suite_result_digest = canary.canonical_digest();
        }
        assert!(absent_witness.validate().is_err());

        // 5. Outcomes edited after the suite digest was taken.
        let mut stale_digest = authoritative.clone();
        stale_digest.canary.as_mut().unwrap().outcomes[1].proven = false;
        assert!(stale_digest.validate().is_err());

        // 6. A claim about a generation this backend is not.
        let mut wrong_generation = authoritative.clone();
        {
            let canary = wrong_generation.canary.as_mut().unwrap();
            canary.generation = "linux-cgroup-v2-v2".into();
            canary.suite_result_digest = canary.canonical_digest();
        }
        assert!(wrong_generation.validate().is_err());

        // 7. `ActiveCanaries` claimed by a suite that ran fewer probes than it
        //    recorded outcomes: the control is about the suite itself.
        let mut short_suite = authoritative.clone();
        {
            let canary = short_suite.canary.as_mut().unwrap();
            canary.outcomes.insert(
                0,
                CanaryControlOutcomeV1 {
                    control: "ActiveCanaries".into(),
                    probe: format!(".gb-probe-{}", "3".repeat(32)),
                    proven: true,
                    witness_digest: sha256_hex(b"suite-witness"),
                },
            );
            canary.probe_runs = 1;
            canary.suite_result_digest = canary.canonical_digest();
        }
        assert!(short_suite.validate().is_err());

        // 8. A claim written before the leaf it describes was configured.
        let mut premature = authoritative.clone();
        premature.state = ProbeJournalState::IdentityObserved;
        premature.initial_shape = None;
        premature.configured_and_read_back = false;
        assert!(premature.validate().is_err());

        // 9. A later generation restating what an earlier one established, and
        //    a fresh episode opening with an inherited claim.
        let mut restated = authoritative.clone();
        restated.state = ProbeJournalState::EmptyProven;
        restated.stable_empty_proven = true;
        {
            let canary = restated.canary.as_mut().unwrap();
            canary.probe_runs += 1;
            canary.suite_result_digest = canary.canonical_digest();
        }
        assert!(validate_probe_record_successor(&authoritative, &restated).is_err());
        let mut honest_endpoint = authoritative.clone();
        honest_endpoint.state = ProbeJournalState::Removed;
        let mut inherited = new_probe_intent(expectation, ProbeEpisodeKind::ControlCanary).unwrap();
        inherited.canary = Some(admitted);
        assert!(validate_probe_record_successor(&honest_endpoint, &inherited).is_err());
    }
