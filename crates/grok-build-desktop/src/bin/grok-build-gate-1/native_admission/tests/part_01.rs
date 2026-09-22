    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_SYNTHETIC_ROOT: AtomicU64 = AtomicU64::new(1);

    struct SyntheticTestRoot {
        path: PathBuf,
        directory: File,
    }

    impl SyntheticTestRoot {
        fn new(label: &str) -> Self {
            let serial = NEXT_SYNTHETIC_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-synthetic-native-admission-{label}-{}-{serial}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create explicit synthetic native-admission root");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure synthetic native-admission root");
            let directory = open(
                &path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .expect("retain synthetic native-admission root");
            Self { path, directory }
        }

        fn write_artifact(
            &self,
            file_name: &str,
            object_id: &str,
            kind: BoundArtifactKindV1,
            bytes: &[u8],
        ) -> RetainedArtifact {
            write_synthetic_artifact(&self.directory, file_name, object_id, kind, bytes)
        }
    }

    impl Drop for SyntheticTestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_synthetic_artifact(
        root: &File,
        file_name: &str,
        object_id: &str,
        kind: BoundArtifactKindV1,
        bytes: &[u8],
    ) -> RetainedArtifact {
        let permissions = match kind {
            BoundArtifactKindV1::Executable | BoundArtifactKindV1::ValidatorExecutable => 0o500,
            BoundArtifactKindV1::ReadOnlyInput
            | BoundArtifactKindV1::ImmutableImageAttestation
            | BoundArtifactKindV1::TypedObservation
            | BoundArtifactKindV1::StandardOutput
            | BoundArtifactKindV1::StandardError => 0o400,
        };
        let opened = openat(
            root,
            Path::new(file_name),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(permissions),
        )
        .expect("create synthetic retained artifact");
        let mut writer = File::from(opened);
        rustix::fs::fchmod(&writer, Mode::from_raw_mode(permissions))
            .expect("set exact synthetic artifact mode");
        writer.write_all(bytes).expect("write synthetic artifact");
        writer.sync_all().expect("sync synthetic artifact");
        drop(writer);
        let descriptor = openat(
            root,
            Path::new(file_name),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .expect("reopen synthetic retained artifact");
        let binding = observe_artifact(&descriptor, object_id, kind)
            .expect("observe synthetic retained artifact");
        RetainedArtifact {
            root: root.try_clone().expect("retain synthetic artifact root"),
            name: file_name.into(),
            binding,
            descriptor,
        }
    }

    fn synthetic_observation(
        case_id: &str,
        binding: &NativeAdmissionBindingV1,
    ) -> NativeCaseObservationV1 {
        match case_id {
            "native_evidence_only_authority_sealed" => {
                NativeCaseObservationV1::EvidenceOnlyAuthoritySealed {
                    binding_sha256: binding.digest().unwrap(),
                    fixed_input_ids_in_order: FIXED_INPUT_IDS.map(str::to_owned).to_vec(),
                    forbidden_shape_sha256: forbidden_product_shape_digest(),
                    rejected_before_effect: true,
                    accepted_workspace_objective_or_command_count: 0,
                    provider_credential_count: 0,
                    ordinary_authority_mint_count: 0,
                    native_invocation_count: 0,
                }
            }
            "linux_bubblewrap_namespace_canary" => NativeCaseObservationV1::BubblewrapNamespace {
                host_user_namespace_id: 101,
                child_user_namespace_id: 201,
                host_mount_namespace_id: 102,
                child_mount_namespace_id: 202,
                host_pid_namespace_id: 103,
                child_pid_namespace_id: 203,
                host_network_namespace_id: 104,
                child_network_namespace_id: 204,
                host_ipc_namespace_id: 105,
                child_ipc_namespace_id: 205,
                host_uts_namespace_id: 106,
                child_uts_namespace_id: 206,
                host_cgroup_namespace_id: 107,
                child_cgroup_namespace_id: 207,
                forbidden_host_root_visible: false,
                nested_namespace_mount_denied_errno: 1,
                forbidden_side_effect_count: 0,
            },
            "linux_landlock_canary" => NativeCaseObservationV1::LandlockDenial {
                ruleset_sha256: expected_landlock_ruleset_digest(binding).unwrap(),
                probe_id: "landlock-outside-root-write".into(),
                denied_errno: 13,
                forbidden_side_effect_count: 0,
            },
            "linux_seccomp_canary" => NativeCaseObservationV1::SeccompDenial {
                program_sha256: expected_seccomp_program_digest(binding).unwrap(),
                forbidden_syscall_number: SECCOMP_FORBIDDEN_SYSCALL_X86_64,
                denied_errno: 1,
                forbidden_side_effect_count: 0,
            },
            "linux_capabilities_removed" => NativeCaseObservationV1::CapabilitiesRemoved {
                effective: Vec::new(),
                permitted: Vec::new(),
                inheritable: Vec::new(),
                ambient: Vec::new(),
                bounding: Vec::new(),
            },
            "linux_no_new_privs" => {
                let tid = 42;
                let status = |value| {
                    format!(
                        "Name:\tgrok-build\nPid:\t{tid}\nPPid:\t1\nNoNewPrivs:\t{value}\nSeccomp:\t0\n"
                    )
                };
                NativeCaseObservationV1::NoNewPrivs {
                    facts: linux_no_new_privs::LinuxNoNewPrivsObservationFactsV1 {
                        binding_sha256: binding.digest().unwrap(),
                        fixed_input_sha256: binding.fixed_inputs_in_order[5].sha256.clone(),
                        probe_contract_sha256: linux_no_new_privs::probe_contract_sha256(),
                        proc_filesystem_magic: 0x0000_9fa0,
                        probe_thread_tid: tid,
                        pre_prctl_value: 0,
                        pre_proc_status_raw: status(0),
                        set_result_errno: 0,
                        post_set_prctl_value: 1,
                        post_set_proc_status_raw: status(1),
                        clear_result_errno: 22,
                        post_clear_prctl_value: 1,
                        post_clear_proc_status_raw: status(1),
                    },
                }
            }
            "linux_cgroup_v2_membership" => {
                let identity = expected_cgroup_identity_digest(binding).unwrap();
                NativeCaseObservationV1::CgroupMembership {
                    expected_cgroup_sha256: identity.clone(),
                    observed_cgroup_sha256: identity,
                    target_membership_count: 1,
                    foreign_membership_count: 0,
                }
            }
            "linux_pidfd_process_tree_cleanup" => {
                NativeCaseObservationV1::PidfdProcessTreeCleanup {
                    pidfd_wait_observed: true,
                    cgroup_kill_observed: true,
                    cgroup_events_populated: false,
                    cgroup_procs_member_count: 0,
                    proc_descendant_count: 0,
                    independent_zero_observation_count: 2,
                }
            }
            _ => panic!("unknown synthetic native case {case_id}"),
        }
    }

    struct SyntheticFixture {
        root: SyntheticTestRoot,
        evidence_only: Option<EvidenceOnlyAuthority>,
        validator: Option<IndependentValidatorAuthority>,
    }

    impl SyntheticFixture {
        #[allow(
            clippy::too_many_lines,
            reason = "the synthetic fixture makes every exact source and native input identity explicit"
        )]
        fn new(target: LinuxGate1TargetV1) -> Self {
            let root = SyntheticTestRoot::new(target.target_id());
            let backend = root.write_artifact(
                "backend",
                "backend-binary",
                BoundArtifactKindV1::Executable,
                b"synthetic exact backend binary\n",
            );
            let fixture = root.write_artifact(
                "fixture",
                "fixture-binary",
                BoundArtifactKindV1::Executable,
                b"synthetic fixed native fixture binary\n",
            );
            let attestation = root.write_artifact(
                "platform-image",
                "platform-image-attestation",
                BoundArtifactKindV1::ImmutableImageAttestation,
                b"synthetic immutable platform image attestation\n",
            );
            let target_manifest = root.write_artifact(
                "release-target-manifest",
                "release-target-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
                b"synthetic exact release target manifest v1\n",
            );
            let case_manifest = root.write_artifact(
                "gate-case-manifest",
                "gate-case-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
                b"synthetic exact gate case manifest v2\n",
            );
            let cargo_lock = root.write_artifact(
                "cargo-lock",
                "cargo-lock",
                BoundArtifactKindV1::ReadOnlyInput,
                b"synthetic exact Cargo.lock\n",
            );
            let input_manifest = root.write_artifact(
                "fixed-input-manifest",
                "fixed-input-manifest",
                BoundArtifactKindV1::ReadOnlyInput,
                b"synthetic exact ordered native input manifest\n",
            );
            let fixed_inputs = FIXED_INPUT_IDS
                .iter()
                .enumerate()
                .map(|(index, object_id)| {
                    root.write_artifact(
                        &format!("fixed-input-{index}"),
                        object_id,
                        BoundArtifactKindV1::ReadOnlyInput,
                        format!("synthetic fixed native input {object_id}\n").as_bytes(),
                    )
                })
                .collect::<Vec<_>>();
            let policy = LinuxNativePolicyV1::fixed();
            let binding = NativeAdmissionBindingV1 {
                schema: NATIVE_ADMISSION_BINDING_SCHEMA.into(),
                fixture_spec_id: NATIVE_ADMISSION_FIXTURE_SPEC_ID.into(),
                source: ImmutableSourceBindingV1 {
                    revision: "a".repeat(40),
                    tree_object: "b".repeat(40),
                    source_tree_sha256: domain_digest(
                        b"synthetic-source-tree\0",
                        b"synthetic clean source tree",
                    ),
                    repository_dirty: false,
                    untracked_source_count: 0,
                },
                target,
                backend_binary: backend.binding.clone(),
                fixture_binary: fixture.binding.clone(),
                native_policy_sha256: policy.digest().unwrap(),
                native_policy: policy,
                platform_image: PlatformImageBindingV1 {
                    target,
                    target_id: target.target_id().into(),
                    target_triple: LinuxGate1TargetV1::target_triple().into(),
                    immutable_image_sha256: domain_digest(
                        b"synthetic-platform-image\0",
                        target.target_id().as_bytes(),
                    ),
                    attestation: attestation.binding.clone(),
                    live_os_release_sha256: domain_digest(
                        b"synthetic-os-release\0",
                        target.target_id().as_bytes(),
                    ),
                    live_kernel_release: "synthetic-kernel-v1".into(),
                    live_architecture: "x86_64".into(),
                },
                release_target_manifest_version: 1,
                release_target_manifest: target_manifest.binding.clone(),
                gate_case_manifest_version: 2,
                gate_case_manifest: case_manifest.binding.clone(),
                cargo_lock: cargo_lock.binding.clone(),
                toolchain: ToolchainBindingV1 {
                    rustc_version: "rustc synthetic exact".into(),
                    cargo_version: "cargo synthetic exact".into(),
                    rust_toolchain_sha256: domain_digest(
                        b"synthetic-toolchain\0",
                        b"rustc+cargo synthetic exact",
                    ),
                },
                fixed_input_manifest: input_manifest.binding.clone(),
                fixed_inputs_in_order: fixed_inputs
                    .iter()
                    .map(|input| input.binding.clone())
                    .collect(),
            };
            binding.validate().unwrap();
            let mut retained_inputs = vec![
                backend,
                fixture,
                attestation,
                target_manifest,
                case_manifest,
                cargo_lock,
                input_manifest,
            ];
            retained_inputs.extend(fixed_inputs);
            let case_permits = EvidenceOnlyCasePermitSet::sealed(&binding).unwrap();
            let evidence_only = EvidenceOnlyAuthority {
                binding: binding.clone(),
                retained_inputs: RetainedArtifactSet {
                    artifacts: retained_inputs,
                },
                case_permits,
            };
            evidence_only.validate_retained().unwrap();

            let validator_executable = root.write_artifact(
                "validator",
                "independent-validator",
                BoundArtifactKindV1::ValidatorExecutable,
                b"synthetic independent validator binary\n",
            );
            let validator_identity = ValidatorIdentityV1 {
                executable: validator_executable.binding.clone(),
                invocation_id: format!("validator-{}", target.target_id()),
                validator_contract_sha256: domain_digest(
                    VALIDATOR_CONTRACT_DOMAIN,
                    b"exact-eight-cases\0raw-artifacts\0live-bindings\0no-replace-readback\0",
                ),
            };
            let validator = IndependentValidatorAuthority {
                expected_binding: binding,
                identity: validator_identity,
                retained_executable: validator_executable,
            };
            validator.validate_retained().unwrap();
            Self {
                root,
                evidence_only: Some(evidence_only),
                validator: Some(validator),
            }
        }

        fn draft(&mut self) -> SyntheticCandidateDraft {
            let authority = self
                .evidence_only
                .take()
                .expect("use evidence authority once");
            authority.into_synthetic_draft_for_test()
        }

        fn validator(&mut self) -> IndependentValidatorAuthority {
            self.validator.take().expect("use validator authority once")
        }

        fn exact_candidate(&mut self) -> RetainedEvidenceOnlyCandidate {
            self.draft().publish()
        }

        fn exact_validated(&mut self) -> IndependentlyValidatedNativeAdmission {
            let candidate = self.exact_candidate();
            let validator = self.validator();
            independently_validate_native_admission(candidate, validator, 10_000).unwrap()
        }
    }

    struct SyntheticCandidateDraft {
        root: File,
        record: EvidenceOnlyRecordV1,
        retained_inputs: RetainedArtifactSet,
        retained_evidence: RetainedArtifactSet,
    }

    impl SyntheticCandidateDraft {
        fn recommit(&mut self) {
            let binding = self.record.binding.digest().unwrap();
            self.record.binding_sha256 = binding.clone();
            self.record.evidence_only_capability_sha256 = binding.clone();
            for case in &mut self.record.cases_in_order {
                case.binding_sha256 = binding.clone();
                case.evidence_sha256 = case.digest().unwrap();
            }
            self.record.aggregate_evidence_sha256 = self.record.digest().unwrap();
        }

        fn replace_observation_bytes_for_test(&mut self, index: usize, bytes: &[u8]) {
            let case_id = PRE_ADMISSION_CASES[index].0;
            let retained = write_synthetic_artifact(
                &self.root,
                &format!("mutated-case-{index}-observation"),
                &format!("{case_id}-observation"),
                BoundArtifactKindV1::TypedObservation,
                bytes,
            );
            self.record.cases_in_order[index].typed_observation = retained.binding.clone();
            self.retained_evidence.artifacts[index * 3] = retained;
            self.recommit();
        }

        fn replace_observation_for_test(
            &mut self,
            index: usize,
            observation: &NativeCaseObservationV1,
        ) {
            self.replace_observation_bytes_for_test(index, &canonical_bytes(observation).unwrap());
        }

        fn publish(mut self) -> RetainedEvidenceOnlyCandidate {
            self.recommit();
            self.record
                .validate()
                .expect("synthetic candidate contract");
            let canonical_record_bytes = canonical_bytes(&self.record).unwrap();
            let record_artifact = write_synthetic_artifact(
                &self.root,
                EVIDENCE_ONLY_RECORD_NAME,
                "evidence-only-record",
                BoundArtifactKindV1::ReadOnlyInput,
                &canonical_record_bytes,
            );
            RetainedEvidenceOnlyCandidate {
                record: self.record,
                canonical_record_bytes,
                record_artifact,
                retained_inputs: self.retained_inputs,
                retained_evidence: self.retained_evidence,
            }
        }
    }

    impl EvidenceOnlyAuthority {
        fn into_synthetic_draft_for_test(self) -> SyntheticCandidateDraft {
            self.validate_retained().unwrap();
            assert!(
                self.case_permits.all_present(),
                "synthetic all-case draft requires every unconsumed case permit"
            );
            let binding_sha256 = self.binding.digest().unwrap();
            let root = self.retained_inputs.artifacts[0].root.try_clone().unwrap();
            let mut cases = Vec::with_capacity(PRE_ADMISSION_CASES.len());
            let mut retained_evidence = Vec::with_capacity(PRE_ADMISSION_CASES.len() * 3);
            let mut product_mint_rejection = None;
            for (index, (case_id, fixture_spec_id)) in PRE_ADMISSION_CASES.iter().enumerate() {
                let observation_value = synthetic_observation(case_id, &self.binding);
                observation_value
                    .validate_for(case_id, &self.binding)
                    .unwrap();
                if index == 0 {
                    product_mint_rejection =
                        Some(observation_value.product_mint_rejection().unwrap());
                }
                let observation_bytes = canonical_bytes(&observation_value).unwrap();
                let observation = write_synthetic_artifact(
                    &root,
                    &format!("case-{index}-observation"),
                    &format!("{case_id}-observation"),
                    BoundArtifactKindV1::TypedObservation,
                    &observation_bytes,
                );
                let stdout = write_synthetic_artifact(
                    &root,
                    &format!("case-{index}-stdout"),
                    &format!("{case_id}-stdout"),
                    BoundArtifactKindV1::StandardOutput,
                    format!("synthetic complete stdout for {case_id}\n").as_bytes(),
                );
                let stderr = write_synthetic_artifact(
                    &root,
                    &format!("case-{index}-stderr"),
                    &format!("{case_id}-stderr"),
                    BoundArtifactKindV1::StandardError,
                    format!("synthetic complete stderr for {case_id}\n").as_bytes(),
                );
                let mut case = NativeCaseEvidenceV1 {
                    case_id: (*case_id).into(),
                    fixture_spec_id: (*fixture_spec_id).into(),
                    binding_sha256: binding_sha256.clone(),
                    started_unix_ms: 1_000 + u64::try_from(index).unwrap(),
                    finished_unix_ms: 1_001 + u64::try_from(index).unwrap(),
                    exit_code: 0,
                    outcome: NativeCaseOutcomeV1::Passed,
                    typed_observation: observation.binding.clone(),
                    stdout: stdout.binding.clone(),
                    stderr: stderr.binding.clone(),
                    evidence_sha256: String::new(),
                };
                case.evidence_sha256 = case.digest().unwrap();
                cases.push(case);
                retained_evidence.extend([observation, stdout, stderr]);
            }
            let mut record = EvidenceOnlyRecordV1 {
                schema: EVIDENCE_ONLY_RECORD_SCHEMA.into(),
                binding: self.binding,
                binding_sha256: binding_sha256.clone(),
                evidence_only_capability_sha256: binding_sha256,
                executor_invocation_id: "synthetic-fixed-evidence-executor".into(),
                product_mint_rejection: product_mint_rejection.unwrap(),
                cases_in_order: cases,
                aggregate_evidence_sha256: String::new(),
            };
            record.aggregate_evidence_sha256 = record.digest().unwrap();
            SyntheticCandidateDraft {
                root,
                record,
                retained_inputs: self.retained_inputs,
                retained_evidence: RetainedArtifactSet {
                    artifacts: retained_evidence,
                },
            }
        }
    }

    impl ProductionAdmissionStore {
        fn publish_synthetic_for_test(
            self,
            validated: IndependentlyValidatedNativeAdmission,
        ) -> Result<ProductionAdmitted, NativeAdmissionError> {
            validated.validate_retained()?;
            let bytes = canonical_bytes(&validated.record)?;
            let opened = openat(
                &self.directory,
                Path::new(PRODUCTION_ADMISSION_RECORD_NAME),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| invalid(format!("synthetic no-replace publish failed: {error}")))?;
            let mut writer = File::from(opened);
            rustix::fs::fchmod(&writer, Mode::from_raw_mode(0o600))
                .map_err(|error| invalid(format!("cannot set synthetic record mode: {error}")))?;
            writer
                .write_all(&bytes)
                .map_err(|error| invalid(format!("cannot write synthetic record: {error}")))?;
            writer
                .sync_all()
                .map_err(|error| invalid(format!("cannot sync synthetic record: {error}")))?;
            let written_identity = file_identity(&writer)?;
            drop(writer);
            self.directory
                .sync_all()
                .map_err(|error| invalid(format!("cannot sync synthetic store: {error}")))?;
            let descriptor = openat(
                &self.directory,
                Path::new(PRODUCTION_ADMISSION_RECORD_NAME),
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(|error| invalid(format!("cannot read synthetic record: {error}")))?;
            if file_identity(&descriptor)? != written_identity
                || read_bounded(&descriptor, MAX_RECORD_BYTES)? != bytes
            {
                return Err(invalid("synthetic exact admission readback failed"));
            }
            let published = RetainedPublishedRecord {
                root: self.directory.try_clone().map_err(|error| {
                    invalid(format!("cannot retain synthetic store root: {error}"))
                })?,
                root_path: self.path,
                root_identity: self.identity,
                descriptor,
                identity: written_identity,
                bytes,
            };
            let record = validated.record.clone();
            let authority = ProductionAdmitted {
                record,
                record_sha256: domain_digest(PRODUCTION_ADMISSION_DOMAIN, &published.bytes),
                published,
                validated,
            };
            authority.validate_retained()?;
            Ok(authority)
        }
    }

    fn assert_all_permits_false() {
        assert!(!EvidenceOnlyAuthority::permits_ordinary_execution());
        assert!(!EvidenceOnlyAuthority::permits_ordinary_authority_mint());
        assert!(!RetainedEvidenceOnlyCandidate::permits_ordinary_execution());
        assert!(!RetainedEvidenceOnlyCandidate::permits_ordinary_authority_mint());
        assert!(!IndependentValidatorAuthority::permits_ordinary_execution());
        assert!(!IndependentValidatorAuthority::permits_ordinary_authority_mint());
        assert!(!EvidenceOnlyNoNewPrivsObserved::permits_ordinary_execution());
        assert!(!EvidenceOnlyNoNewPrivsObserved::permits_ordinary_authority_mint());
        assert!(!IndependentlyValidatedNativeAdmission::permits_ordinary_execution());
        assert!(!IndependentlyValidatedNativeAdmission::permits_ordinary_authority_mint());
        assert!(!ProductionAdmitted::permits_ordinary_execution());
        assert!(!ProductionAdmitted::permits_ordinary_authority_mint());
    }

    #[test]
    fn native_admission_exact_chain_is_nonclone_one_shot_and_all_permits_false() {
        let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        fixture
            .evidence_only
            .as_ref()
            .unwrap()
            .validate_retained()
            .unwrap();
        let candidate = fixture.exact_candidate();
        candidate.validate_retained().unwrap();
        let validator = fixture.validator();
        validator.validate_retained().unwrap();
        let validated =
            independently_validate_native_admission(candidate, validator, 10_000).unwrap();
        validated.validate_retained().unwrap();

        let store = SyntheticTestRoot::new("exact-store");
        let production_store = ProductionAdmissionStore::open(&store.path).unwrap();
        let admitted = production_store
            .publish_synthetic_for_test(validated)
            .unwrap();
        admitted.validate_retained().unwrap();
        assert_eq!(
            admitted.record.ordered_case_evidence_sha256.len(),
            PRE_ADMISSION_CASES.len()
        );
        assert_all_permits_false();

        let join: fn(
            RetainedEvidenceOnlyCandidate,
            IndependentValidatorAuthority,
            u64,
        )
            -> Result<IndependentlyValidatedNativeAdmission, NativeAdmissionError> =
            independently_validate_native_admission;
        let publish: fn(
            ProductionAdmissionStore,
            IndependentlyValidatedNativeAdmission,
        ) -> Result<ProductionAdmitted, NativeAdmissionError> = ProductionAdmissionStore::publish;
        let _ = (join, publish);
    }

    #[test]
    fn native_admission_no_new_privs_case_permit_is_once_only_and_retains_all_other_cases() {
        let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let first_store_root = SyntheticTestRoot::new("no-new-privs-genuine-first");
        let first_store = LinuxNoNewPrivsObservationStore::open(&first_store_root.path).unwrap();
        let authority = fixture.evidence_only.as_mut().unwrap();
        let first = authority.observe_linux_no_new_privs(first_store);
        #[cfg(target_os = "linux")]
        {
            let observed = first.expect("Linux host must produce exact no-new-privs evidence");
            observed.validate_retained().unwrap();
            assert!(
                first_store_root
                    .path
                    .join(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME)
                    .is_file()
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(first.is_err());
            assert!(
                !first_store_root
                    .path
                    .join(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME)
                    .exists()
            );
        }
        assert!(authority.case_permits.permits_in_order[5].is_none());
        assert!(
            authority
                .case_permits
                .permits_in_order
                .iter()
                .enumerate()
                .all(|(index, permit)| index == 5 || permit.is_some())
        );
        authority.validate_retained().unwrap();

        let second_store_root = SyntheticTestRoot::new("no-new-privs-genuine-second");
        let second_store = LinuxNoNewPrivsObservationStore::open(&second_store_root.path).unwrap();
        assert!(authority.observe_linux_no_new_privs(second_store).is_err());
        assert!(
            !second_store_root
                .path
                .join(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME)
                .exists()
        );
        authority.case_permits.permits_in_order.swap(0, 1);
        assert!(authority.validate_retained().is_err());
        assert_all_permits_false();
    }

    #[test]
    fn native_admission_no_new_privs_observation_store_is_exact_no_replace() {
        let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let draft = fixture.draft();
        let observation = synthetic_observation("linux_no_new_privs", &draft.record.binding);
        let bytes = canonical_bytes(&observation).unwrap();
        let store_root = SyntheticTestRoot::new("no-new-privs-store");
        let retained = LinuxNoNewPrivsObservationStore::open(&store_root.path)
            .unwrap()
            .publish(&bytes)
            .unwrap();
        retained.validate().unwrap();

        let error = LinuxNoNewPrivsObservationStore::open(&store_root.path)
            .unwrap()
            .publish(&bytes)
            .err()
            .expect("second no-new-privs observation publication must fail");
        assert!(error.to_string().contains("no-replace"));

        let path = store_root.path.join(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME);
        fs::remove_file(&path).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(retained.validate().is_err());

        let cloexec_root = SyntheticTestRoot::new("no-new-privs-cloexec");
        let retained = LinuxNoNewPrivsObservationStore::open(&cloexec_root.path)
            .unwrap()
            .publish(&bytes)
            .unwrap();
        rustix::io::fcntl_setfd(
            retained.artifact.descriptor.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert!(retained.validate().is_err());

        let nonregular_root = SyntheticTestRoot::new("no-new-privs-nonregular");
        fs::create_dir(
            nonregular_root
                .path
                .join(LINUX_NO_NEW_PRIVS_OBSERVATION_NAME),
        )
        .unwrap();
        assert!(
            LinuxNoNewPrivsObservationStore::open(&nonregular_root.path)
                .unwrap()
                .publish(&bytes)
                .is_err()
        );

        let insecure_root = SyntheticTestRoot::new("no-new-privs-insecure-root");
        fs::set_permissions(&insecure_root.path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(LinuxNoNewPrivsObservationStore::open(&insecure_root.path).is_err());
    }

    #[test]
    fn native_admission_no_new_privs_nested_schema_rejects_candidate_fields() {
        let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let draft = fixture.draft();
        let observation = synthetic_observation("linux_no_new_privs", &draft.record.binding);
        let mut value = serde_json::to_value(observation).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .get_mut("facts")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .insert(
                "candidate_claimed_pass".into(),
                serde_json::Value::Bool(true),
            );
        let error = decode_case_observation(&serde_json::to_vec(&value).unwrap())
            .expect_err("unknown nested no-new-privs field must fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn native_admission_pass_status_never_substitutes_for_objective_case_facts() {
        for (index, &(case_id, _)) in PRE_ADMISSION_CASES.iter().enumerate() {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
            let mut draft = fixture.draft();
            let mut observation = synthetic_observation(case_id, &draft.record.binding);
            match &mut observation {
                NativeCaseObservationV1::EvidenceOnlyAuthoritySealed {
                    provider_credential_count,
                    ..
                } => *provider_credential_count = 1,
                NativeCaseObservationV1::BubblewrapNamespace {
                    child_user_namespace_id,
                    host_user_namespace_id,
                    ..
                } => *child_user_namespace_id = *host_user_namespace_id,
                NativeCaseObservationV1::LandlockDenial {
                    forbidden_side_effect_count,
                    ..
                } => *forbidden_side_effect_count = 1,
                NativeCaseObservationV1::SeccompDenial { denied_errno, .. } => {
                    *denied_errno = 13;
                }
                NativeCaseObservationV1::CapabilitiesRemoved { effective, .. } => {
                    effective.push(1);
                }
                NativeCaseObservationV1::NoNewPrivs { facts } => {
                    facts.pre_prctl_value = 1;
                }
                NativeCaseObservationV1::CgroupMembership {
                    target_membership_count,
                    ..
                } => *target_membership_count = 0,
                NativeCaseObservationV1::PidfdProcessTreeCleanup {
                    proc_descendant_count,
                    ..
                } => *proc_descendant_count = 1,
            }
            assert!(
                observation
                    .validate_for(case_id, &draft.record.binding)
                    .is_err()
            );
            draft.replace_observation_for_test(index, &observation);
            assert_eq!(
                draft.record.cases_in_order[index].outcome,
                NativeCaseOutcomeV1::Passed
            );
            assert_eq!(draft.record.cases_in_order[index].exit_code, 0);
            let candidate = draft.publish();
            let validator = fixture.validator();
            assert!(
                independently_validate_native_admission(candidate, validator, 10_000).is_err(),
                "case {case_id} was admitted from pass/exit alone"
            );
        }
    }

    #[test]
    fn native_admission_requires_all_seven_fresh_linux_namespace_identities() {
        for namespace in ["user", "mount", "pid", "network", "ipc", "uts", "cgroup"] {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
            let mut draft = fixture.draft();
            let mut observation =
                synthetic_observation("linux_bubblewrap_namespace_canary", &draft.record.binding);
            let NativeCaseObservationV1::BubblewrapNamespace {
                host_user_namespace_id,
                child_user_namespace_id,
                host_mount_namespace_id,
                child_mount_namespace_id,
                host_pid_namespace_id,
                child_pid_namespace_id,
                host_network_namespace_id,
                child_network_namespace_id,
                host_ipc_namespace_id,
                child_ipc_namespace_id,
                host_uts_namespace_id,
                child_uts_namespace_id,
                host_cgroup_namespace_id,
                child_cgroup_namespace_id,
                ..
            } = &mut observation
            else {
                unreachable!();
            };
            match namespace {
                "user" => *child_user_namespace_id = *host_user_namespace_id,
                "mount" => *child_mount_namespace_id = *host_mount_namespace_id,
                "pid" => *child_pid_namespace_id = *host_pid_namespace_id,
                "network" => *child_network_namespace_id = *host_network_namespace_id,
                "ipc" => *child_ipc_namespace_id = *host_ipc_namespace_id,
                "uts" => *child_uts_namespace_id = *host_uts_namespace_id,
                "cgroup" => *child_cgroup_namespace_id = *host_cgroup_namespace_id,
                _ => unreachable!(),
            }
            draft.replace_observation_for_test(1, &observation);
            let candidate = draft.publish();
            let validator = fixture.validator();
            assert!(
                independently_validate_native_admission(candidate, validator, 10_000).is_err(),
                "unchanged {namespace} namespace was admitted"
            );
        }
    }

    #[test]
    fn native_admission_rejects_candidate_chosen_probe_digests_and_syscall_numbers() {
        for mutation in [
            "landlock-valid-wrong-digest",
            "seccomp-valid-wrong-digest",
            "seccomp-wrong-nonzero-syscall",
            "cgroup-self-consistent-wrong-digest",
        ] {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
            let mut draft = fixture.draft();
            let index = match mutation {
                "landlock-valid-wrong-digest" => 2,
                "seccomp-valid-wrong-digest" | "seccomp-wrong-nonzero-syscall" => 3,
                "cgroup-self-consistent-wrong-digest" => 6,
                _ => unreachable!(),
            };
            let mut observation =
                synthetic_observation(PRE_ADMISSION_CASES[index].0, &draft.record.binding);
            match (mutation, &mut observation) {
                (
                    "landlock-valid-wrong-digest",
                    NativeCaseObservationV1::LandlockDenial { ruleset_sha256, .. },
                ) => *ruleset_sha256 = "d".repeat(64),
                (
                    "seccomp-valid-wrong-digest",
                    NativeCaseObservationV1::SeccompDenial { program_sha256, .. },
                ) => *program_sha256 = "e".repeat(64),
                (
                    "seccomp-wrong-nonzero-syscall",
                    NativeCaseObservationV1::SeccompDenial {
                        forbidden_syscall_number,
                        ..
                    },
                ) => *forbidden_syscall_number = SECCOMP_FORBIDDEN_SYSCALL_X86_64 + 1,
                (
                    "cgroup-self-consistent-wrong-digest",
                    NativeCaseObservationV1::CgroupMembership {
                        expected_cgroup_sha256,
                        observed_cgroup_sha256,
                        ..
                    },
                ) => {
                    *expected_cgroup_sha256 = "f".repeat(64);
                    *observed_cgroup_sha256 = "f".repeat(64);
                }
                _ => unreachable!(),
            }
            assert!(
                observation
                    .validate_for(PRE_ADMISSION_CASES[index].0, &draft.record.binding)
                    .is_err()
            );
            draft.replace_observation_for_test(index, &observation);
            let candidate = draft.publish();
            let validator = fixture.validator();
            assert!(
                independently_validate_native_admission(candidate, validator, 10_000).is_err(),
                "mutation {mutation} passed"
            );
        }
    }

    #[test]
    fn native_admission_rejects_unknown_and_noncanonical_observation_bytes() {
        let mut unknown = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let mut unknown_draft = unknown.draft();
        let observation =
            synthetic_observation("linux_landlock_canary", &unknown_draft.record.binding);
        let mut value = serde_json::to_value(observation).unwrap();
        value.as_object_mut().unwrap().insert(
            "candidate_supplied_verdict".into(),
            serde_json::Value::Bool(true),
        );
        let bytes = serde_json::to_vec(&value).unwrap();
        unknown_draft.replace_observation_bytes_for_test(2, &bytes);
        let candidate = unknown_draft.publish();
        let validator = unknown.validator();
        let error = independently_validate_native_admission(candidate, validator, 10_000)
            .err()
            .expect("unknown typed-observation field must fail");
        assert!(error.to_string().contains("unknown field"));

        let mut noncanonical = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let mut noncanonical_draft = noncanonical.draft();
        let observation =
            synthetic_observation("linux_seccomp_canary", &noncanonical_draft.record.binding);
        let mut bytes = canonical_bytes(&observation).unwrap();
        bytes.push(b'\n');
        noncanonical_draft.replace_observation_bytes_for_test(3, &bytes);
        let candidate = noncanonical_draft.publish();
        let validator = noncanonical.validator();
        let error = independently_validate_native_admission(candidate, validator, 10_000)
            .err()
            .expect("noncanonical typed-observation bytes must fail");
        assert!(error.to_string().contains("not canonical JSON"));
    }

    #[test]
    fn native_admission_candidate_cannot_supply_validator_identity() {
        let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let draft = fixture.draft();
        let mut value = serde_json::to_value(&draft.record).unwrap();
        value.as_object_mut().unwrap().insert(
            "validator".into(),
            serde_json::json!({
                "invocation_id": "candidate-chosen-validator",
                "validator_contract_sha256": "a".repeat(64)
            }),
        );
        let error = decode_evidence_only_record(&serde_json::to_vec(&value).unwrap())
            .expect_err("candidate-supplied validator identity must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn native_admission_rejects_nonregular_and_declared_nonregular_artifacts() {
        let root = SyntheticTestRoot::new("nonregular-file-kind");
        let error = observe_artifact(
            &root.directory,
            "directory-as-artifact",
            BoundArtifactKindV1::ReadOnlyInput,
        )
        .expect_err("directory must not become a bound artifact");
        assert!(error.to_string().contains("not one regular file"));

        for declared_kind in [BoundFileTypeV1::Directory, BoundFileTypeV1::Other] {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
            let mut draft = fixture.draft();
            draft.record.binding.backend_binary.file.file_type = declared_kind;
            draft.recommit();
            assert!(draft.record.validate().is_err());
        }
    }

    #[test]
    fn native_admission_production_source_has_no_authority_constructor_or_execution_bridge() {
        let source = include_str!("../../native_admission.rs");
        let no_new_privs_source = include_str!("../linux_no_new_privs.rs");
        let production_source = source
            .split_once(concat!("#[cfg(test)]", "\nmod tests {"))
            .expect("native-admission test boundary")
            .0;
        assert_eq!(
            production_source.matches("EvidenceOnlyAuthority {").count(),
            2,
            "only the private type declaration and impl may exist in production"
        );
        assert_eq!(
            production_source
                .matches("IndependentValidatorAuthority {")
                .count(),
            2,
            "only the private type declaration and impl may exist in production"
        );
        assert_eq!(
            production_source
                .matches("EvidenceOnlyNoNewPrivsObserved {")
                .count(),
            3,
            "genuine no-new-privs state may have only its private declaration, impl, and host-observer construction"
        );
        for forbidden_bridge in [
            "WorkspaceGrant",
            "SprintSpec",
            "RunnerLaunchIntent",
            "serve_runner_session",
            "std::process::Command",
            "std::process::Stdio",
        ] {
            assert!(
                !production_source.contains(forbidden_bridge),
                "production native admission contains forbidden bridge {forbidden_bridge}"
            );
        }
        for forbidden_probe_bridge in [
            "WorkspaceGrant",
            "SprintSpec",
            "RunnerLaunchIntent",
            "ProductionAdmitted",
            "std::process::Command",
            "std::process::Stdio",
        ] {
            assert!(
                !no_new_privs_source.contains(forbidden_probe_bridge),
                "no-new-privs probe contains forbidden bridge {forbidden_probe_bridge}"
            );
        }

        for source_mutation in ["revisionless", "dirty", "untracked"] {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
            let mut draft = fixture.draft();
            match source_mutation {
                "revisionless" => draft.record.binding.source.revision.clear(),
                "dirty" => draft.record.binding.source.repository_dirty = true,
                "untracked" => draft.record.binding.source.untracked_source_count = 1,
                _ => unreachable!(),
            }
            draft.recommit();
            assert!(
                draft.record.validate().is_err(),
                "mutable source mutation {source_mutation} reached a candidate contract"
            );
        }
    }

    #[test]
    fn native_admission_requires_exact_ordered_eight_case_id_and_spec_pairs() {
        for mutation in ["missing", "extra", "duplicate", "reordered", "crossed-spec"] {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
            let mut draft = fixture.draft();
            match mutation {
                "missing" => {
                    draft.record.cases_in_order.pop();
                }
                "extra" => {
                    let extra = draft.record.cases_in_order[0].clone();
                    draft.record.cases_in_order.push(extra);
                }
                "duplicate" => {
                    draft.record.cases_in_order[1] = draft.record.cases_in_order[0].clone();
                }
                "reordered" => draft.record.cases_in_order.swap(1, 2),
                "crossed-spec" => {
                    draft.record.cases_in_order[1].fixture_spec_id =
                        NATIVE_ADMISSION_FIXTURE_SPEC_ID.into();
                }
                _ => unreachable!(),
            }
            draft.recommit();
            assert!(
                draft.record.validate().is_err(),
                "mutation {mutation} passed"
            );
        }
    }

    #[test]
    fn native_admission_rejects_source_backend_policy_platform_manifest_and_input_crossing() {
        let mutations: &[fn(&mut NativeAdmissionBindingV1)] = &[
            |binding| binding.source.repository_dirty = true,
            |binding| binding.source.revision = String::new(),
            |binding| binding.backend_binary.sha256 = "1".repeat(64),
            |binding| binding.backend_binary.file = binding.fixture_binary.file,
            |binding| binding.native_policy.no_new_privs_required = false,
            |binding| binding.platform_image.immutable_image_sha256 = "2".repeat(64),
            |binding| binding.platform_image.target_id = "fedora-44-x86_64".into(),
            |binding| binding.release_target_manifest_version = 2,
            |binding| binding.gate_case_manifest.sha256 = "3".repeat(64),
            |binding| {
                binding.fixed_inputs_in_order.swap(0, 1);
            },
        ];
        for mutate in mutations {
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
            let mut draft = fixture.draft();
            mutate(&mut draft.record.binding);
            draft.recommit();
            if draft.record.validate().is_ok() {
                let candidate = draft.publish();
                let validator = fixture.validator();
                assert!(
                    independently_validate_native_admission(candidate, validator, 10_000).is_err()
                );
            }
        }
    }

    #[test]
    fn native_admission_rejects_product_mint_case_evidence_and_artifact_crossing() {
        let mut product = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let mut product_draft = product.draft();
        product_draft
            .record
            .product_mint_rejection
            .ordinary_authority_mint_count = 1;
        product_draft.recommit();
        assert!(product_draft.record.validate().is_err());

        let mut outcome = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let mut outcome_draft = outcome.draft();
        outcome_draft.record.cases_in_order[2].outcome = NativeCaseOutcomeV1::Unknown;
        outcome_draft.recommit();
        assert!(outcome_draft.record.validate().is_err());

        let mut stream = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let mut stream_draft = stream.draft();
        stream_draft.record.cases_in_order[3].stdout =
            stream_draft.record.cases_in_order[3].stderr.clone();
        stream_draft.recommit();
        assert!(stream_draft.record.validate().is_err());

        let mut evidence = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let mut evidence_draft = evidence.draft();
        evidence_draft.record.cases_in_order[4].evidence_sha256 = "4".repeat(64);
        evidence_draft.record.aggregate_evidence_sha256 = evidence_draft.record.digest().unwrap();
        assert!(evidence_draft.record.validate().is_err());
    }

    #[test]
    fn native_admission_independent_validator_rejects_crossed_and_same_invocation_identity() {
        let mut ubuntu = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let candidate = ubuntu.exact_candidate();
        let mut fedora = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let crossed_validator = fedora.validator();
        assert!(
            independently_validate_native_admission(candidate, crossed_validator, 10_000).is_err()
        );

        let mut same = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let candidate = same.exact_candidate();
        let mut validator = same.validator();
        validator.identity.invocation_id = candidate.record.executor_invocation_id.clone();
        assert!(independently_validate_native_admission(candidate, validator, 10_000).is_err());

        let mut replaced = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let candidate = replaced.exact_candidate();
        let validator = replaced.validator();
        rustix::io::fcntl_setfd(
            validator.retained_executable.descriptor.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert!(independently_validate_native_admission(candidate, validator, 10_000).is_err());
    }

    #[test]
    fn native_admission_retained_candidate_rejects_cloexec_loss_and_same_byte_replacement() {
        let mut cloexec = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let candidate = cloexec.exact_candidate();
        rustix::io::fcntl_setfd(
            candidate.retained_evidence.artifacts[0].descriptor.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert!(candidate.validate_retained().is_err());

        let mut replacement = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let candidate = replacement.exact_candidate();
        let artifact = &candidate.retained_evidence.artifacts[1];
        let bytes = read_bounded(&artifact.descriptor, MAX_ARTIFACT_BYTES).unwrap();
        let path = replacement.root.path.join(&artifact.name);
        fs::remove_file(&path).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(candidate.validate_retained().is_err());

        let mut input_cloexec = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let candidate = input_cloexec.exact_candidate();
        rustix::io::fcntl_setfd(
            candidate.retained_inputs.artifacts[0].descriptor.as_fd(),
            rustix::io::FdFlags::empty(),
        )
        .unwrap();
        assert!(candidate.validate_retained().is_err());

        let mut changed_evidence = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let candidate = changed_evidence.exact_candidate();
        let artifact = &candidate.retained_evidence.artifacts[2];
        let path = changed_evidence.root.path.join(&artifact.name);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"changed retained evidence bytes\n").unwrap();
        assert!(candidate.validate_retained().is_err());

        let mut replaced_input = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
        let candidate = replaced_input.exact_candidate();
        let artifact = &candidate.retained_inputs.artifacts[7];
        let bytes = read_bounded(&artifact.descriptor, MAX_ARTIFACT_BYTES).unwrap();
        let path = replaced_input.root.path.join(&artifact.name);
        fs::remove_file(&path).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(candidate.validate_retained().is_err());
    }

    #[test]
    fn native_admission_store_is_no_replace_and_decoded_bytes_never_construct_authority() {
        let store_root = SyntheticTestRoot::new("no-replace-store");
        let mut first_fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let first = ProductionAdmissionStore::open(&store_root.path)
            .unwrap()
            .publish_synthetic_for_test(first_fixture.exact_validated())
            .unwrap();
        first.validate_retained().unwrap();
        let decoded = decode_production_admission_record(&first.published.bytes).unwrap();
        assert_eq!(decoded, first.record);

        let mut second_fixture = SyntheticFixture::new(LinuxGate1TargetV1::Ubuntu2604X8664);
        let error = ProductionAdmissionStore::open(&store_root.path)
            .unwrap()
            .publish_synthetic_for_test(second_fixture.exact_validated())
            .err()
            .expect("second synthetic publication must fail");
        assert!(error.to_string().contains("no-replace"));

        let exact_bytes = first.published.bytes.clone();
        fs::remove_file(store_root.path.join(PRODUCTION_ADMISSION_RECORD_NAME)).unwrap();
        fs::write(
            store_root.path.join(PRODUCTION_ADMISSION_RECORD_NAME),
            exact_bytes,
        )
        .unwrap();
        fs::set_permissions(
            store_root.path.join(PRODUCTION_ADMISSION_RECORD_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(first.validate_retained().is_err());
    }

    #[test]
    fn native_admission_production_publication_is_linux_only_and_never_mints_ordinary_authority() {
        assert_all_permits_false();
        #[cfg(not(target_os = "linux"))]
        {
            let store_root = SyntheticTestRoot::new("non-linux-production-store");
            let mut fixture = SyntheticFixture::new(LinuxGate1TargetV1::Fedora44X8664);
            let error = ProductionAdmissionStore::open(&store_root.path)
                .unwrap()
                .publish(fixture.exact_validated())
                .err()
                .expect("non-Linux production publication must fail");
            assert!(
                error
                    .to_string()
                    .contains("only by the Linux no-replace store")
            );
            assert!(
                !store_root
                    .path
                    .join(PRODUCTION_ADMISSION_RECORD_NAME)
                    .exists()
            );
        }
    }
