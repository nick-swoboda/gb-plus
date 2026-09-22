    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, ApplicationReceipt, ApplicationValidationEvidence,
        ApplicationValidationMode, CommandDomainBackend, CommandDomainCleanupDisposition,
        CommandDomainCleanupProof, CommandOutputCaptureIntentV1,
        CommandOutputCaptureReconciliationAdmission, CommandOutputCaptureReconciliationClaimV1,
        CommandOutputCaptureReconciliationResolutionV1, CommandOutputCleanScanResolutionReceiptV1,
        CommandSpec, DescriptorRelativeWorkspaceManifest, ExecutionNetwork,
        ExecutionPolicyCompiler, ExecutionPolicyRequest, LiveWorkspaceUnchangedReceipt,
        MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS, MutationMode, NonSuccessTerminalState,
        PathScope, ResourceLimits, RollbackReference, RunnerCleanupTerminalRecord,
        RunnerLaunchPreparationAttempt, RunnerLaunchPreparationDisposition,
        RunnerLaunchPreparationOutcome, RunnerSessionPurpose, SprintBudget, SprintTerminalEvidence,
        SprintTerminalProof, WorkerCleanupBackend, WorkerCleanupEvidence, WorkerCleanupReceipt,
        WorkerCleanupRequest, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };
    use grok_build_providers::{
        FakeProvider, ProviderResponse, ProviderTurn, decode_planning_request, decode_tool_call,
    };
    use grok_build_runner::{
        CapabilityCommandOutputStore, ClaimedCommandOutputV2TestProofBoxInput,
        CommandDomainCleanupBackend, CommandOutputCaptureJournalStateV1,
        CommandOutputCaptureReservation, RUNNER_WIRE_PROTOCOL_VERSION,
        RUNNER_WIRE_PROTOCOL_VERSION_V12, RunnerRequest, RunnerRequestEnvelope,
        RunnerRequestEnvelopeV12, RunnerRequestV12, RunnerResponse, RunnerResponseEnvelope,
        WireCommandBackendIdentity, WireCommandOutputCaptureAnchorV1, WireCommandSpec,
        WireEffectContext, WorkspaceManifest, complete_sensitive_output_clean_test_proof_box_v1,
        complete_sensitive_output_rejection_test_proof_box_v1, encode_request_frame,
        encode_request_frame_v12, encode_response_frame, inspect_private_state_digest,
        runner_protocol_digest,
    };

    use super::*;
    use crate::runner_client::{
        RunnerCommandEffectResponse, RunnerEffectResponse,
        claimed_live_state_capture_response_for_test,
    };
    use crate::verification_evidence::{
        AdaptedCommandResponseV12, AdaptedCommandTerminal, AdaptedSensitiveOutputRejection,
        AdaptedVerificationResponseV12, CommandV12ResponseInput, adapt_command_response_v12,
        adapt_verification_response_v12,
    };
    use crate::{
        AdaptedVerificationEvidence, DurableUiEvent, DurableUiEventKind, DurableUiProjection,
        LiveStateCaptureEvidenceInput, UiProjectionError, UiSafeNextAction, UiTerminalCause,
        UiUnknownReason,
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[derive(Default)]
    struct StrictFakeUnknownResolutionProbe {
        armed: bool,
        fail_before_core_commit_once: bool,
        observations: Vec<(
            CommandOutputCaptureReconciliationClaimV1,
            CommandOutputCapturePhysicalReconciliationV1,
        )>,
    }

    std::thread_local! {
        static STRICT_FAKE_UNKNOWN_RESOLUTION_PROBE: RefCell<StrictFakeUnknownResolutionProbe> =
            RefCell::new(StrictFakeUnknownResolutionProbe::default());
    }

    fn arm_strict_fake_unknown_resolution_precommit_failure() {
        STRICT_FAKE_UNKNOWN_RESOLUTION_PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            probe.armed = true;
            probe.fail_before_core_commit_once = true;
            probe.observations.clear();
        });
    }

    fn observe_strict_fake_unknown_resolution_precommit(
        claim: &CommandOutputCaptureReconciliationClaimV1,
        physical: &CommandOutputCapturePhysicalReconciliationV1,
    ) -> Result<(), DurableCoordinatorError> {
        STRICT_FAKE_UNKNOWN_RESOLUTION_PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            if !probe.armed {
                return Ok(());
            }
            probe.observations.push((claim.clone(), physical.clone()));
            if std::mem::take(&mut probe.fail_before_core_commit_once) {
                return Err(DurableCoordinatorError::Protocol(
                    "injected strict-fake Unknown resolution failure after physical fencing and before core commit"
                        .into(),
                ));
            }
            Ok(())
        })
    }

    fn take_strict_fake_unknown_resolution_observations() -> Vec<(
        CommandOutputCaptureReconciliationClaimV1,
        CommandOutputCapturePhysicalReconciliationV1,
    )> {
        STRICT_FAKE_UNKNOWN_RESOLUTION_PROBE.with(|probe| {
            let mut probe = probe.borrow_mut();
            probe.armed = false;
            probe.fail_before_core_commit_once = false;
            std::mem::take(&mut probe.observations)
        })
    }

    const FIXTURE_AGENTS: &str = include_str!("../../../../../fixtures/walking-skeleton/AGENTS.md");
    const FIXTURE_SOURCE: &str = include_str!("../../../../../fixtures/walking-skeleton/src/lib.rs");
    const FIXTURE_MANIFEST: &str = include_str!("../../../../../fixtures/walking-skeleton/Cargo.toml");
    const FIXTURE_LOCK: &str = include_str!("../../../../../fixtures/walking-skeleton/Cargo.lock");
    const FIXTURE_README: &str = include_str!("../../../../../fixtures/walking-skeleton/README.md");

    const fn strict_fake_command_runner_cleanup_backend() -> WorkerCleanupBackend {
        // The canonical cleanup fixture below is a native-valid Linux cgroup-v2
        // proof. The strict lifecycle is a contract fake rather than a host
        // backend probe, so its launch cleanup authority must name that same
        // simulated backend on both supported desktop targets.
        WorkerCleanupBackend::LinuxCgroupV2
    }

    fn strict_fake_command_output_store(
        workspace_grant: &IssuedWorkspaceGrant,
        runner_launch_id: &str,
    ) -> Result<(PathBuf, CapabilityCommandOutputStore, Digest), DurableCoordinatorError> {
        strict_fake_command_output_store_for_workspace_root(
            &workspace_grant.contract().canonical_root,
            runner_launch_id,
        )
    }

    fn strict_fake_command_output_store_for_workspace_root(
        workspace_root: &Path,
        runner_launch_id: &str,
    ) -> Result<(PathBuf, CapabilityCommandOutputStore, Digest), DurableCoordinatorError> {
        let parent = workspace_root.parent().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake workspace has no harness-owned parent".into(),
            )
        })?;
        let leaf = format!(
            ".strict-fake-command-output-{}",
            Digest::sha256(runner_launch_id.as_bytes())
        );
        let root = parent.join(leaf);
        match fs::create_dir(&root) {
            Ok(()) => {
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake cannot make command-output root private: {error}"
                    ))
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(DurableCoordinatorError::Protocol(format!(
                    "strict fake cannot create command-output root: {error}"
                )));
            }
        }
        let canonical = fs::canonicalize(&root).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake cannot canonicalize command-output root: {error}"
            ))
        })?;
        if canonical != root {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake command-output root crossed its exact canonical path".into(),
            ));
        }
        let store = CapabilityCommandOutputStore::open(&root).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake cannot open command-output store: {error}"
            ))
        })?;
        let private_state_digest = inspect_private_state_digest(&root).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake cannot authenticate command-output root: {error}"
            ))
        })?;
        Ok((root, store, private_state_digest))
    }

    #[allow(
        clippy::large_enum_variant,
        reason = "the strict fake keeps each exact adapted terminal inline for direct contract comparison"
    )]
    enum StrictFakeAdaptedCommand {
        Ordinary(AdaptedCommandTerminal),
        Verification(AdaptedVerificationEvidence),
    }

    struct StrictFakeClaimedV12Command {
        private_state_root: PathBuf,
        capture_intent: CommandOutputCaptureIntentV1,
        acquired: CommandOutputCaptureAcquiredV1,
        request: RunnerRequestEnvelopeV12,
        backend: WireCommandBackendIdentity,
        observation_authority: RunnerEffectObservationAuthority,
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the test boundary preserves policy borrow, v2 acquisition, exact frame claim, and transport validation in production order"
    )]
    fn strict_fake_claim_v12_command(
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        workspace_grant: &IssuedWorkspaceGrant,
        runner_launch: &RunnerLaunchIntent,
        runner_session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        command: &CommandSpec,
        running_boundary: Option<&TaskAttemptRunningBoundary>,
    ) -> Result<StrictFakeClaimedV12Command, DurableCoordinatorError> {
        let command_bytes = serde_json::to_vec(command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake v12 command cannot be canonically encoded: {error}"
            ))
        })?;
        let capture_intent = dispatch_permit
            .output_capture_intent()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake v12 command omitted its atomic capture intent".into(),
                )
            })?;
        let detector_policy = dispatch_permit
            .sensitive_output_detection_policy()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake v12 command omitted its persisted detector policy".into(),
                )
            })?;
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake v12 command omitted its deterministic capture claim".into(),
                )
            })?;
        let (private_state_root, store, private_state_digest) =
            strict_fake_command_output_store(workspace_grant, &runner_launch.launch_id)?;
        if private_state_digest != runner_launch.private_state_digest
            || private_state_digest != runner_session.private_state_digest
            || capture_intent.private_state_digest != private_state_digest
            || capture_intent.source.sprint_id != intent.sprint_id
            || capture_intent.source.runner_launch_id != runner_launch.launch_id
            || capture_intent.source.runner_session_id != runner_session.session_id
            || capture_intent.source.effect_id != intent.effect_id
            || capture_intent.source.request_digest != intent.request_digest
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake v12 capture crossed its launch, session, effect, or private root"
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
                    "strict fake cannot durably acquire v12 command output: {error}"
                ))
            })?;
        let output_capture =
            WireCommandOutputCaptureAnchorV1::try_new(acquired.clone()).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake acquired v12 command output is invalid: {error}"
                ))
            })?;
        let working_directory = command.working_directory.to_str().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake v12 command working directory is not exact UTF-8".into(),
            )
        })?;
        let wire_command = WireCommandSpec {
            program: command.program.clone(),
            arguments: command.arguments.clone(),
            working_directory: working_directory.into(),
        };
        let role_request = match runner_session.purpose {
            RunnerSessionPurpose::TaskWorker => RunnerRequest::WorkerRunCommand {
                command: wire_command,
                output_capture,
            },
            RunnerSessionPurpose::FinalVerifier => RunnerRequest::FinalVerifierRunCommand {
                command: wire_command,
                output_capture,
            },
            RunnerSessionPurpose::Applier | RunnerSessionPurpose::LiveStateVerifier => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake v12 command requires worker or final-verifier authority".into(),
                ));
            }
        };
        let mut request = RunnerRequestEnvelopeV12 {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            session_id: runner_session.session_id.clone(),
            runner_nonce: runner_session.session_nonce.clone(),
            sequence: 1,
            request_id: format!("{}:strict-fake-v12-request", intent.effect_id),
            effect: WireEffectContext {
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
            },
            request: RunnerRequestV12::RunCommand {
                request: role_request,
                detector_policy: detector_policy.clone(),
            },
        };
        request
            .bind_transport_commitment_digest()
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake v12 command commitment failed: {error}"
                ))
            })?;
        let request_frame = encode_request_frame_v12(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake v12 command frame failed: {error}"
            ))
        })?;
        let (claimed_effect, transport_permit) = ledger.claim_command_output_capture_dispatch(
            dispatch_permit,
            acquired.clone(),
            &request_frame,
        )?;
        if claimed_effect.intent != *intent
            || claimed_effect.dispatch_claim.is_none()
            || transport_permit.sensitive_output_detection_policy() != Some(&detector_policy)
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake v12 command claim crossed effect or detector-policy authority".into(),
            ));
        }
        let observation_authority = transport_permit.validate_transport_request(
            intent,
            &command_bytes,
            runner_launch,
            runner_session,
            running_boundary,
            &request_frame,
        )?;
        let backend = WireCommandBackendIdentity {
            command_domain_backend: CommandDomainCleanupBackend::LinuxCgroupV2,
            backend_id: "strict-fake-v12-linux-cgroup-v2".into(),
            implementation_digest: Digest::sha256(b"strict-fake-v12-linux-cgroup-v2/v1"),
        };
        Ok(StrictFakeClaimedV12Command {
            private_state_root,
            capture_intent,
            acquired,
            request,
            backend,
            observation_authority,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the clean proof box must retain exact core, role, snapshot, and receipt identities"
    )]
    fn strict_fake_complete_clean_v12_command(
        claimed: StrictFakeClaimedV12Command,
        workspace_grant: &IssuedWorkspaceGrant,
        runner_session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        command: &CommandSpec,
        task_id: Option<&str>,
        verification_identity: Option<(&str, &str)>,
        post_response_timestamps: &mut TimestampCursor,
        termination: CommandTerminationV1,
        stdout_bytes: &[u8],
    ) -> Result<
        (
            StrictFakeAdaptedCommand,
            RunnerEffectObservationAuthority,
            u64,
        ),
        DurableCoordinatorError,
    > {
        let StrictFakeClaimedV12Command {
            private_state_root,
            capture_intent,
            acquired,
            request,
            backend,
            observation_authority,
        } = claimed;
        let proof_box = complete_sensitive_output_clean_test_proof_box_v1(
            ClaimedCommandOutputV2TestProofBoxInput {
                private_state_root: private_state_root.clone(),
                grant_hash: workspace_grant.contract().grant_hash.clone(),
                acquired,
                request,
                termination,
                backend,
            },
            stdout_bytes,
            &[],
        )
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake clean v12 proof box failed: {error}"
            ))
        })?;
        let exchange = RunnerCommandEffectResponse {
            request: proof_box.request().clone(),
            response: proof_box.response().clone(),
        };
        let command_bytes = serde_json::to_vec(command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake clean v12 command encode failed: {error}"
            ))
        })?;
        let provisional_input = CommandV12ResponseInput {
            exchange: &exchange,
            intent,
            runner_session,
            private_state_root: &private_state_root,
            authority: workspace_grant,
            command,
            capture_intent: &capture_intent,
            core_request_bytes: &command_bytes,
            task_id,
            observation_id: verification_identity.map_or(
                "strict-fake-ordinary-v12-observation",
                |(_, observation_id)| observation_id,
            ),
            observed_at_unix_ms: intent.created_at_unix_ms,
        };
        let minimum = match verification_identity {
            Some((receipt_id, _)) => match adapt_verification_response_v12(
                provisional_input,
                receipt_id,
            )
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake provisional clean v12 verification adaptation failed: {error}"
                ))
            })? {
                AdaptedVerificationResponseV12::Completed(adapted) => adapted
                    .command_terminal()
                    .clean_runner()
                    .map_or(intent.created_at_unix_ms, |receipt| {
                        receipt.terminal_prepared_at_unix_ms
                    }),
                AdaptedVerificationResponseV12::SensitiveOutputRejected(_)
                | AdaptedVerificationResponseV12::Failed(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake provisional clean v12 verification returned a non-clean branch"
                            .into(),
                    ));
                }
            },
            None => match adapt_command_response_v12(provisional_input).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake provisional clean v12 command adaptation failed: {error}"
                ))
            })? {
                AdaptedCommandResponseV12::Completed(adapted) => adapted
                    .command_terminal()
                    .clean_runner()
                    .map_or(intent.created_at_unix_ms, |receipt| {
                        receipt.terminal_prepared_at_unix_ms
                    }),
                AdaptedCommandResponseV12::SensitiveOutputRejected(_)
                | AdaptedCommandResponseV12::Failed(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake provisional clean v12 command returned a non-clean branch"
                            .into(),
                    ));
                }
            },
        };
        let observed_at_unix_ms =
            post_response_timestamps.take_at_least(minimum.max(intent.created_at_unix_ms))?;
        let input = CommandV12ResponseInput {
            observed_at_unix_ms,
            ..provisional_input
        };
        let adapted = match verification_identity {
            Some((receipt_id, _)) => match adapt_verification_response_v12(input, receipt_id)
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake clean v12 verification adaptation failed: {error}"
                    ))
                })? {
                AdaptedVerificationResponseV12::Completed(adapted) => {
                    StrictFakeAdaptedCommand::Verification(adapted)
                }
                AdaptedVerificationResponseV12::SensitiveOutputRejected(_)
                | AdaptedVerificationResponseV12::Failed(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake clean v12 proof box returned a non-clean verification branch"
                            .into(),
                    ));
                }
            },
            None => match adapt_command_response_v12(input).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake clean v12 command adaptation failed: {error}"
                ))
            })? {
                AdaptedCommandResponseV12::Completed(adapted) => {
                    StrictFakeAdaptedCommand::Ordinary(adapted)
                }
                AdaptedCommandResponseV12::SensitiveOutputRejected(_)
                | AdaptedCommandResponseV12::Failed(_) => {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake clean v12 proof box returned a non-clean command branch"
                            .into(),
                    ));
                }
            },
        };
        Ok((adapted, observation_authority, observed_at_unix_ms))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the rejection proof box retains exact core, role, capture, and observation identities"
    )]
    fn strict_fake_complete_rejected_v12_command(
        claimed: StrictFakeClaimedV12Command,
        workspace_grant: &IssuedWorkspaceGrant,
        runner_session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        command: &CommandSpec,
        task_id: Option<&str>,
        observation_id: &str,
        post_response_timestamps: &mut TimestampCursor,
    ) -> Result<
        (
            AdaptedSensitiveOutputRejection,
            RunnerEffectObservationAuthority,
            u64,
        ),
        DurableCoordinatorError,
    > {
        let StrictFakeClaimedV12Command {
            private_state_root,
            capture_intent,
            acquired,
            request,
            backend,
            observation_authority,
        } = claimed;
        let proof_box = complete_sensitive_output_rejection_test_proof_box_v1(
            ClaimedCommandOutputV2TestProofBoxInput {
                private_state_root: private_state_root.clone(),
                grant_hash: workspace_grant.contract().grant_hash.clone(),
                acquired,
                request,
                termination: CommandTerminationV1::Canceled,
                backend,
            },
        )
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake rejected v12 proof box failed: {error}"
            ))
        })?;
        let exchange = RunnerCommandEffectResponse {
            request: proof_box.request().clone(),
            response: proof_box.response().clone(),
        };
        let command_bytes = serde_json::to_vec(command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake rejected v12 command encode failed: {error}"
            ))
        })?;
        let observed_at_unix_ms =
            post_response_timestamps.take_at_least(intent.created_at_unix_ms)?;
        let adapted = adapt_command_response_v12(CommandV12ResponseInput {
            exchange: &exchange,
            intent,
            runner_session,
            private_state_root: &private_state_root,
            authority: workspace_grant,
            command,
            capture_intent: &capture_intent,
            core_request_bytes: &command_bytes,
            task_id,
            observation_id,
            observed_at_unix_ms,
        })
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake rejected v12 adaptation failed: {error}"
            ))
        })?;
        let AdaptedCommandResponseV12::SensitiveOutputRejected(rejection) = adapted else {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake rejected v12 proof box returned a non-rejection branch".into(),
            ));
        };
        Ok((rejection, observation_authority, observed_at_unix_ms))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the compatibility-shaped fixture wrapper preserves every exact command and verification identity"
    )]
    fn strict_fake_claimed_verification_v12(
        ledger: &mut EventLedger,
        dispatch_permit: FreshRunnerEffectDispatchPermit,
        workspace_grant: &IssuedWorkspaceGrant,
        runner_launch: &RunnerLaunchIntent,
        runner_session: &RunnerSessionPolicyRecord,
        intent: &EffectIntent,
        command: &CommandSpec,
        task_id: Option<&str>,
        running_boundary: Option<&TaskAttemptRunningBoundary>,
        verification_identity: Option<(&str, &str)>,
        post_response_timestamps: &mut TimestampCursor,
        termination: CommandTerminationV1,
        stdout_bytes: &[u8],
    ) -> Result<
        (
            StrictFakeAdaptedCommand,
            RunnerEffectObservationAuthority,
            u64,
        ),
        DurableCoordinatorError,
    > {
        let claimed = strict_fake_claim_v12_command(
            ledger,
            dispatch_permit,
            workspace_grant,
            runner_launch,
            runner_session,
            intent,
            command,
            running_boundary,
        )?;
        strict_fake_complete_clean_v12_command(
            claimed,
            workspace_grant,
            runner_session,
            intent,
            command,
            task_id,
            verification_identity,
            post_response_timestamps,
            termination,
            stdout_bytes,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the formal-check proof box keeps the command terminal, verification evidence, and claimed observation authority on one exact typed path"
    )]
    fn strict_fake_dispatch_task_formal_check(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        termination: CommandTerminationV1,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        validate_formal_check_dispatch_authority(
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            dispatch.verification_boundary,
            dispatch.admission,
            dispatch.intent,
            &serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake formal command encode failed: {error}"
                ))
            })?,
            dispatch.runner_launch,
            dispatch.runner_session,
        )?;
        let command_bytes = serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake formal command encode failed: {error}"
            ))
        })?;
        let stdout = format!(
            "strict-fake formal output for {}\n",
            dispatch.admission.criterion_id
        )
        .into_bytes();
        let (adapted, observation_authority, observed_at_unix_ms) =
            strict_fake_claimed_verification_v12(
                ledger,
                FreshRunnerEffectDispatchPermit::TaskFormalCheck(dispatch.dispatch_permit),
                dispatch.workspace_grant,
                dispatch.runner_launch,
                dispatch.runner_session,
                dispatch.intent,
                &dispatch.admission.command,
                Some(&dispatch.admission.attempt.worker_lease.task_id),
                None,
                Some((dispatch.receipt_id, dispatch.observation_id)),
                dispatch.post_response_timestamps,
                termination,
                &stdout,
            )?;
        let StrictFakeAdaptedCommand::Verification(adapted) = adapted else {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake formal command returned ordinary evidence".into(),
            ));
        };
        let command_terminal = adapted.command_terminal().clone();
        let termination = adapted.evidence.verification.termination.ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake adapted formal evidence omitted typed termination".into(),
            )
        })?;
        let output_artifacts = adapted.evidence.output_artifacts.ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake adapted formal evidence omitted output artifacts".into(),
            )
        })?;
        WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_command_terminal(
            WalkingSkeletonTaskFormalCheckResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                verification_boundary: dispatch.verification_boundary.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                request_digest: Digest::sha256(&command_bytes),
                outcome: WalkingSkeletonTaskFormalCheckOutcome::Succeeded(Box::new(
                    WalkingSkeletonFormalCheckCommandResult {
                        termination,
                        output_artifacts,
                        output_evidence_bytes: adapted.evidence.output_evidence_bytes,
                        duration_ms: adapted.evidence.verification.duration_ms,
                    },
                )),
            },
            observation_authority,
            command_terminal,
        )
        .bind_observed_at(observed_at_unix_ms)
    }

    struct StrictFakeSensitiveTaskCommandClaim {
        response: WalkingSkeletonTaskEffectResponse,
        observation_authority: RunnerEffectObservationAuthority,
        rejection: AdaptedSensitiveOutputRejection,
        observed_at_unix_ms: u64,
    }

    fn strict_fake_claim_sensitive_task_command_v12(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
    ) -> Result<StrictFakeSensitiveTaskCommandClaim, DurableCoordinatorError> {
        let ProviderToolIntent::RunCommand { command } = &dispatch.provider_call.intent else {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake sensitive task fixture requires RunCommand".into(),
            ));
        };
        validate_task_effect_dispatch_authority(
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            dispatch.running_boundary,
            dispatch.intent,
            dispatch.request_bytes,
        )?;
        validate_provider_call_for_effect(
            dispatch.provider_call,
            dispatch.intent,
            dispatch.request_bytes,
        )?;
        let claimed = strict_fake_claim_v12_command(
            ledger,
            dispatch.dispatch_permit,
            dispatch.workspace_grant,
            dispatch.runner_launch,
            dispatch.runner_session,
            dispatch.intent,
            command,
            Some(dispatch.running_boundary),
        )?;
        let observation_id = format!("{}:observation", dispatch.intent.effect_id);
        let (rejection, observation_authority, observed_at_unix_ms) =
            strict_fake_complete_rejected_v12_command(
                claimed,
                dispatch.workspace_grant,
                dispatch.runner_session,
                dispatch.intent,
                command,
                Some(&dispatch.provider_call.task_id),
                &observation_id,
                dispatch.post_response_timestamps,
            )?;
        let termination = rejection.termination();
        Ok(StrictFakeSensitiveTaskCommandClaim {
            response: task_effect_response_for_dispatch(
                dispatch.sprint_spec,
                dispatch.workspace_grant,
                dispatch.running_boundary,
                dispatch.intent,
                dispatch.request_bytes,
                None,
                WalkingSkeletonTaskEffectOutcome::SensitiveOutputRejected { termination },
            ),
            observation_authority,
            rejection,
            observed_at_unix_ms,
        })
    }

    struct StrictFakeUnexecutedFormalClaim {
        response: WalkingSkeletonTaskFormalCheckResponse,
        observation_authority: RunnerEffectObservationAuthority,
        claimed_effect: PersistedEffect,
        acquired: CommandOutputCaptureAcquiredV1,
        store: CapabilityCommandOutputStore,
        observed_at_unix_ms: u64,
    }

    fn strict_fake_claim_sensitive_formal_v12(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedTaskFormalCheckResponse, DurableCoordinatorError> {
        let command_bytes = serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake sensitive formal command encode failed: {error}"
            ))
        })?;
        validate_formal_check_dispatch_authority(
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            dispatch.verification_boundary,
            dispatch.admission,
            dispatch.intent,
            &command_bytes,
            dispatch.runner_launch,
            dispatch.runner_session,
        )?;
        let claimed = strict_fake_claim_v12_command(
            ledger,
            FreshRunnerEffectDispatchPermit::TaskFormalCheck(dispatch.dispatch_permit),
            dispatch.workspace_grant,
            dispatch.runner_launch,
            dispatch.runner_session,
            dispatch.intent,
            &dispatch.admission.command,
            None,
        )?;
        let (rejection, observation_authority, observed_at_unix_ms) =
            strict_fake_complete_rejected_v12_command(
                claimed,
                dispatch.workspace_grant,
                dispatch.runner_session,
                dispatch.intent,
                &dispatch.admission.command,
                Some(&dispatch.admission.attempt.worker_lease.task_id),
                dispatch.observation_id,
                dispatch.post_response_timestamps,
            )?;
        WalkingSkeletonClaimedTaskFormalCheckResponse::new_with_sensitive_output_rejection(
            WalkingSkeletonTaskFormalCheckResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                verification_boundary: dispatch.verification_boundary.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                request_digest: Digest::sha256(&command_bytes),
                outcome: WalkingSkeletonTaskFormalCheckOutcome::SensitiveOutputRejected {
                    termination: rejection.termination(),
                },
            },
            observation_authority,
            rejection,
        )
        .bind_observed_at(observed_at_unix_ms)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the failure fixture must stop after the real v27 acquisition/wire claim and before every output writer or native launch"
    )]
    fn strict_fake_claim_formal_without_execution(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonTaskFormalCheckDispatch<'_>,
        outcome: WalkingSkeletonTaskFormalCheckOutcome,
    ) -> Result<StrictFakeUnexecutedFormalClaim, DurableCoordinatorError> {
        let command_bytes = serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake unexecuted formal command encode failed: {error}"
            ))
        })?;
        validate_formal_check_dispatch_authority(
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            dispatch.verification_boundary,
            dispatch.admission,
            dispatch.intent,
            &command_bytes,
            dispatch.runner_launch,
            dispatch.runner_session,
        )?;
        let dispatch_permit =
            FreshRunnerEffectDispatchPermit::TaskFormalCheck(dispatch.dispatch_permit);
        let capture_intent = dispatch_permit
            .output_capture_intent()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted formal claim omitted capture intent".into(),
                )
            })?;
        let detector_policy = dispatch_permit
            .sensitive_output_detection_policy()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted formal claim omitted its persisted detector policy"
                        .into(),
                )
            })?;
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted formal claim omitted capture claim identity".into(),
                )
            })?;
        let (_, store, private_state_digest) = strict_fake_command_output_store(
            dispatch.workspace_grant,
            &dispatch.runner_launch.launch_id,
        )?;
        if private_state_digest != dispatch.runner_launch.private_state_digest
            || private_state_digest != dispatch.runner_session.private_state_digest
            || capture_intent.private_state_digest != private_state_digest
            || capture_intent.source.effect_id != dispatch.intent.effect_id
            || capture_intent.source.request_digest != dispatch.intent.request_digest
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake unexecuted formal capture crossed exact authority".into(),
            ));
        }
        let acquired = store
            .reserve_anchored_capture_v2(
                &capture_intent,
                &dispatch_claim_id,
                dispatch.intent.created_at_unix_ms,
                &detector_policy,
            )
            .and_then(CommandOutputCaptureReservation::into_acquired_anchor_for_handoff)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted formal policy-bound acquisition failed: {error}"
                ))
            })?;
        let output_capture =
            WireCommandOutputCaptureAnchorV1::try_new(acquired.clone()).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted formal anchor is invalid: {error}"
                ))
            })?;
        let working_directory = dispatch
            .admission
            .command
            .working_directory
            .to_str()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted formal cwd is not exact UTF-8".into(),
                )
            })?;
        let mut request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: dispatch.runner_session.session_id.clone(),
            runner_nonce: Some(dispatch.runner_session.session_nonce.clone()),
            sequence: 1,
            request_id: format!(
                "{}:strict-fake-unexecuted-wire-request",
                dispatch.intent.effect_id
            ),
            effect: Some(WireEffectContext {
                contract_version: dispatch.intent.contract_version,
                launch_id: dispatch.runner_launch.launch_id.clone(),
                effect_id: dispatch.intent.effect_id.clone(),
                idempotency_key: dispatch.intent.idempotency_key.clone(),
                sprint_id: dispatch.intent.sprint_id.clone(),
                task_id: dispatch.intent.task_id.clone(),
                worker_id: dispatch.intent.worker_id.clone(),
                worker_lease: dispatch.intent.worker_lease.clone(),
                policy_hash: dispatch.intent.policy_hash.clone(),
                input_snapshot: dispatch.intent.input_snapshot.clone(),
                request_digest: dispatch.intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            }),
            request: RunnerRequest::WorkerRunCommand {
                command: WireCommandSpec {
                    program: dispatch.admission.command.program.clone(),
                    arguments: dispatch.admission.command.arguments.clone(),
                    working_directory: working_directory.into(),
                },
                output_capture,
            },
        };
        request
            .bind_transport_commitment_digest()
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted formal commitment failed: {error}"
                ))
            })?;
        let request_frame = encode_request_frame(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake unexecuted formal request frame failed: {error}"
            ))
        })?;
        let (claimed_effect, transport_permit) = ledger.claim_command_output_capture_dispatch(
            dispatch_permit,
            acquired.clone(),
            &request_frame,
        )?;
        let observation_authority = transport_permit.validate_transport_request(
            dispatch.intent,
            &command_bytes,
            dispatch.runner_launch,
            dispatch.runner_session,
            None,
            &request_frame,
        )?;
        if claimed_effect.intent != *dispatch.intent
            || claimed_effect.dispatch_claim.is_none()
            || claimed_effect.observation.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake unexecuted formal claim readback crossed effect authority".into(),
            ));
        }
        let observed_at_unix_ms = dispatch
            .post_response_timestamps
            .take_at_least(dispatch.intent.created_at_unix_ms)?;
        Ok(StrictFakeUnexecutedFormalClaim {
            response: WalkingSkeletonTaskFormalCheckResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                verification_boundary: dispatch.verification_boundary.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                request_digest: Digest::sha256(&command_bytes),
                outcome,
            },
            observation_authority,
            claimed_effect,
            acquired,
            store,
            observed_at_unix_ms,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the zero-byte fixture must exercise core fencing and exact physical Cleaned readback before minting abandonment custody"
    )]
    fn strict_fake_abandon_unexecuted_command_capture(
        ledger: &mut EventLedger,
        claimed_effect: &PersistedEffect,
        expected_acquired: &CommandOutputCaptureAcquiredV1,
        store: &CapabilityCommandOutputStore,
        observed_at_unix_ms: u64,
    ) -> Result<ValidatedCommandCaptureAbandonment, DurableCoordinatorError> {
        let capture =
            ledger.load_command_output_capture_for_effect(&claimed_effect.intent.effect_id)?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake zero-byte formal cleanup omitted acquired capture".into(),
            )
        })?;
        if acquired != expected_acquired
            || capture.terminal.is_some()
            || claimed_effect.observation.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte formal cleanup crossed capture authority".into(),
            ));
        }
        let recovery = store
            .reopen_capture(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake zero-byte formal reopen failed: {error}"
                ))
            })?;
        if recovery.state() != CommandOutputCaptureJournalStateV1::Acquired
            || recovery.acquired() != Some(acquired)
            || recovery.store_head() != &acquired.store_head
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte formal cleanup did not reopen exact Acquired state".into(),
            ));
        }
        let detector_policy = match ledger
            .load_sensitive_output_detection_policy_for_effect(&claimed_effect.intent.effect_id)
        {
            Ok(policy) => Some(policy),
            Err(LedgerError::ArtifactNotFound {
                entity: "sensitive output detection policy",
                ref id,
            }) if id == &claimed_effect.intent.effect_id => None,
            Err(error) => return Err(error.into()),
        };
        let v2_recovery = store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake zero-byte formal v2 reopen failed: {error}"
                ))
            })?;
        match (detector_policy.as_ref(), v2_recovery.as_ref()) {
            (Some(policy), Some(v2))
                if v2.detector_policy() == policy
                    && v2.acquired() == Some(acquired)
                    && v2.head().generation == 2 => {}
            (None, None) => {}
            (Some(_), Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte formal cleanup crossed its exact policy-bound Acquired custody"
                        .into(),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte formal cleanup found unpaired detector policy and v2 custody"
                        .into(),
                ));
            }
        }
        let claimed_at_unix_ms = observed_at_unix_ms.max(acquired.acquired_at_unix_ms);
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake zero-byte cleanup claim timestamp overflow".into(),
                )
            })?;
        let cleanup_claim_id = Digest::sha256(
            format!(
                "{}:strict-fake-zero-byte-cleanup-claim",
                claimed_effect.intent.effect_id
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let reconciliation = ledger.claim_command_output_capture_reconciliation(
            &capture.intent.capture_id,
            &cleanup_claim_id,
            "strict-fake-zero-byte-formal-cleanup-v1",
            claimed_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let reconciliation_permit = match reconciliation {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            CommandOutputCaptureReconciliationAdmission::Busy(_)
            | CommandOutputCaptureReconciliationAdmission::Terminal(_) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte formal cleanup could not acquire fresh fencing".into(),
                ));
            }
        };
        let exact_claim = reconciliation_permit.claim().clone();
        let cleaned = match (detector_policy.as_ref(), v2_recovery.as_ref()) {
            (Some(_), Some(_)) => {
                let prelaunch = store
                    .resume_sensitive_output_prelaunch_abort_v2(
                        &capture.intent,
                        Some(acquired),
                        &exact_claim,
                    )
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake zero-byte formal policy-bound prelaunch cleanup failed: {error}"
                        ))
                    })?;
                prelaunch.validate().map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake zero-byte formal prelaunch cleanup is invalid: {error}"
                    ))
                })?;
                if prelaunch.reconciliation_claim() != &exact_claim
                    || prelaunch.v2_generation() != 2
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake zero-byte formal prelaunch cleanup crossed its exact Core claim or v2 generation"
                            .into(),
                    ));
                }
                prelaunch.fenced_v1_recovery().clone()
            }
            (None, None) => store
                .cleanup_capture(&exact_claim, recovery.store_head())
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake zero-byte formal legacy physical cleanup failed: {error}"
                    ))
                })?,
            (Some(_), None) | (None, Some(_)) => unreachable!(
                "strict fake validated exact detector-policy/v2 pairing before acquiring the Core claim"
            ),
        };
        if cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || cleaned.acquired() != Some(acquired)
            || cleaned.cleaned_store_head() != Some(cleaned.store_head())
            || cleaned.cleaned_record_digest() != Some(cleaned.head_digest())
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte formal cleanup omitted exact Cleaned readback".into(),
            ));
        }
        let released_at_unix_ms = claimed_at_unix_ms.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake zero-byte cleanup release timestamp overflow".into(),
            )
        })?;
        if released_at_unix_ms >= exact_claim.expires_at_unix_ms {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte cleanup exceeded its fencing lease".into(),
            ));
        }
        let released = ledger.release_command_output_capture_reconciliation(
            reconciliation_permit,
            released_at_unix_ms,
        )?;
        if released != exact_claim {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte formal cleanup released crossed fencing".into(),
            ));
        }
        let cleaned_store_head = cleaned.store_head().clone();
        let cleanup_record_digest = cleaned
            .cleaned_record_digest()
            .expect("validated Cleaned state has record digest")
            .clone();
        let no_domain_proof_bytes = serde_json::to_vec(&serde_json::json!({
            "accepted_request_bytes": 0,
            "capture_id": capture.intent.capture_id,
            "cleanup_claim_id": exact_claim.claim_id,
            "dispatch_claim_id": claimed_effect
                .dispatch_claim
                .as_ref()
                .expect("checked claimed effect")
                .dispatch_claim_id,
            "effect_id": claimed_effect.intent.effect_id,
            "schema": "grok-build.strict-fake.no-command-domain.v1",
        }))
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake no-domain proof encoding failed: {error}"
            ))
        })?;
        ValidatedCommandCaptureAbandonment::try_new(
            acquired.clone(),
            cleaned_store_head,
            cleanup_record_digest,
            CommandDomainBackend::LinuxCgroupV2,
            no_domain_proof_bytes,
            released_at_unix_ms,
        )
    }

    struct StrictFakeUnexecutedFinalVerificationClaim {
        response: WalkingSkeletonFinalVerificationResponse,
        observation_authority: RunnerEffectObservationAuthority,
        claimed_effect: PersistedEffect,
        acquired: CommandOutputCaptureAcquiredV1,
        store: CapabilityCommandOutputStore,
        observed_at_unix_ms: u64,
    }

    fn strict_fake_claim_sensitive_final_verification_v12(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        let command_bytes = serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake sensitive final-verification command encode failed: {error}"
            ))
        })?;
        validate_final_verifier_boundary(
            ledger,
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            &dispatch.admission.final_snapshot,
            dispatch.final_verifier,
        )?;
        if dispatch.admission.effect_id != dispatch.intent.effect_id
            || dispatch.admission.runner_launch_id
                != dispatch.final_verifier.runner_launch.launch_id
            || dispatch.admission.runner_session_id
                != dispatch.final_verifier.runner_session.session_id
            || dispatch.intent.request_digest != Digest::sha256(&command_bytes)
            || dispatch.intent.task_id.is_some()
            || dispatch.intent.worker_id.is_some()
            || dispatch.intent.worker_lease.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake sensitive final-verification authority is crossed".into(),
            ));
        }
        let claimed = strict_fake_claim_v12_command(
            ledger,
            FreshRunnerEffectDispatchPermit::SprintFinalVerification(dispatch.dispatch_permit),
            dispatch.workspace_grant,
            &dispatch.final_verifier.runner_launch,
            &dispatch.final_verifier.runner_session,
            dispatch.intent,
            &dispatch.admission.command,
            None,
        )?;
        let (rejection, observation_authority, observed_at_unix_ms) =
            strict_fake_complete_rejected_v12_command(
                claimed,
                dispatch.workspace_grant,
                &dispatch.final_verifier.runner_session,
                dispatch.intent,
                &dispatch.admission.command,
                None,
                dispatch.observation_id,
                dispatch.post_response_timestamps,
            )?;
        WalkingSkeletonClaimedFinalVerificationResponse::new_with_sensitive_output_rejection(
            WalkingSkeletonFinalVerificationResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                final_verifier: dispatch.final_verifier.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                outcome: WalkingSkeletonFinalVerificationOutcome::SensitiveOutputRejected {
                    termination: rejection.termination(),
                },
            },
            observation_authority,
            rejection,
        )
        .bind_observed_at(observed_at_unix_ms)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the final-verification failure fixture must stop after exact v27 acquisition/wire claim and before output writers or native launch"
    )]
    fn strict_fake_claim_final_verification_without_execution(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        outcome: WalkingSkeletonFinalVerificationOutcome,
    ) -> Result<StrictFakeUnexecutedFinalVerificationClaim, DurableCoordinatorError> {
        let command_bytes = serde_json::to_vec(&dispatch.admission.command).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake unexecuted final-verification command encode failed: {error}"
            ))
        })?;
        validate_final_verifier_boundary(
            ledger,
            dispatch.sprint_spec,
            dispatch.workspace_grant,
            dispatch.policy,
            &dispatch.admission.final_snapshot,
            dispatch.final_verifier,
        )?;
        if dispatch.admission.effect_id != dispatch.intent.effect_id
            || dispatch.admission.runner_launch_id
                != dispatch.final_verifier.runner_launch.launch_id
            || dispatch.admission.runner_session_id
                != dispatch.final_verifier.runner_session.session_id
            || dispatch.intent.request_digest != Digest::sha256(&command_bytes)
            || dispatch.intent.task_id.is_some()
            || dispatch.intent.worker_id.is_some()
            || dispatch.intent.worker_lease.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake unexecuted final-verification authority is crossed".into(),
            ));
        }
        let dispatch_permit =
            FreshRunnerEffectDispatchPermit::SprintFinalVerification(dispatch.dispatch_permit);
        let capture_intent = dispatch_permit
            .output_capture_intent()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted final-verification claim omitted capture intent".into(),
                )
            })?;
        let detector_policy = dispatch_permit
            .sensitive_output_detection_policy()
            .cloned()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted final-verification claim omitted its persisted detector policy"
                        .into(),
                )
            })?;
        let dispatch_claim_id = dispatch_permit
            .expected_output_capture_dispatch_claim_id()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted final-verification claim omitted capture claim identity"
                        .into(),
                )
            })?;
        let (_, store, private_state_digest) = strict_fake_command_output_store(
            dispatch.workspace_grant,
            &dispatch.final_verifier.runner_launch.launch_id,
        )?;
        if private_state_digest != dispatch.final_verifier.runner_launch.private_state_digest
            || private_state_digest != dispatch.final_verifier.runner_session.private_state_digest
            || capture_intent.private_state_digest != private_state_digest
            || capture_intent.source.sprint_id != dispatch.intent.sprint_id
            || capture_intent.source.runner_launch_id
                != dispatch.final_verifier.runner_launch.launch_id
            || capture_intent.source.runner_session_id
                != dispatch.final_verifier.runner_session.session_id
            || capture_intent.source.effect_id != dispatch.intent.effect_id
            || capture_intent.source.request_digest != dispatch.intent.request_digest
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake unexecuted final-verification capture crossed exact authority".into(),
            ));
        }
        let acquired = store
            .reserve_anchored_capture_v2(
                &capture_intent,
                &dispatch_claim_id,
                dispatch.intent.created_at_unix_ms,
                &detector_policy,
            )
            .and_then(CommandOutputCaptureReservation::into_acquired_anchor_for_handoff)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted final-verification policy-bound acquisition failed: {error}"
                ))
            })?;
        let output_capture =
            WireCommandOutputCaptureAnchorV1::try_new(acquired.clone()).map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted final-verification anchor is invalid: {error}"
                ))
            })?;
        let working_directory = dispatch
            .admission
            .command
            .working_directory
            .to_str()
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake unexecuted final-verification cwd is not exact UTF-8".into(),
                )
            })?;
        let mut request = RunnerRequestEnvelope {
            protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
            session_id: dispatch.final_verifier.runner_session.session_id.clone(),
            runner_nonce: Some(dispatch.final_verifier.runner_session.session_nonce.clone()),
            sequence: 1,
            request_id: format!(
                "{}:strict-fake-unexecuted-wire-request",
                dispatch.intent.effect_id
            ),
            effect: Some(WireEffectContext {
                contract_version: dispatch.intent.contract_version,
                launch_id: dispatch.final_verifier.runner_launch.launch_id.clone(),
                effect_id: dispatch.intent.effect_id.clone(),
                idempotency_key: dispatch.intent.idempotency_key.clone(),
                sprint_id: dispatch.intent.sprint_id.clone(),
                task_id: dispatch.intent.task_id.clone(),
                worker_id: dispatch.intent.worker_id.clone(),
                worker_lease: dispatch.intent.worker_lease.clone(),
                policy_hash: dispatch.intent.policy_hash.clone(),
                input_snapshot: dispatch.intent.input_snapshot.clone(),
                request_digest: dispatch.intent.request_digest.clone(),
                transport_commitment_digest: Digest::sha256(&[]),
            }),
            request: RunnerRequest::FinalVerifierRunCommand {
                command: WireCommandSpec {
                    program: dispatch.admission.command.program.clone(),
                    arguments: dispatch.admission.command.arguments.clone(),
                    working_directory: working_directory.into(),
                },
                output_capture,
            },
        };
        request
            .bind_transport_commitment_digest()
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake unexecuted final-verification commitment failed: {error}"
                ))
            })?;
        let request_frame = encode_request_frame(&request).map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake unexecuted final-verification request frame failed: {error}"
            ))
        })?;
        let (claimed_effect, transport_permit) = ledger.claim_command_output_capture_dispatch(
            dispatch_permit,
            acquired.clone(),
            &request_frame,
        )?;
        let observation_authority = transport_permit.validate_transport_request(
            dispatch.intent,
            &command_bytes,
            &dispatch.final_verifier.runner_launch,
            &dispatch.final_verifier.runner_session,
            None,
            &request_frame,
        )?;
        if claimed_effect.intent != *dispatch.intent
            || claimed_effect.dispatch_claim.is_none()
            || claimed_effect.observation.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake unexecuted final-verification claim readback crossed effect authority"
                    .into(),
            ));
        }
        let observed_at_unix_ms = dispatch
            .post_response_timestamps
            .take_at_least(dispatch.intent.created_at_unix_ms)?;
        Ok(StrictFakeUnexecutedFinalVerificationClaim {
            response: WalkingSkeletonFinalVerificationResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                final_verifier: dispatch.final_verifier.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                outcome,
            },
            observation_authority,
            claimed_effect,
            acquired,
            store,
            observed_at_unix_ms,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the zero-byte final-verification fixture must fence exact physical cleanup before minting abandonment custody"
    )]
    fn strict_fake_abandon_unexecuted_final_verification_capture(
        ledger: &mut EventLedger,
        claim: &StrictFakeUnexecutedFinalVerificationClaim,
        observed_at_unix_ms: u64,
    ) -> Result<ValidatedCommandCaptureAbandonment, DurableCoordinatorError> {
        let capture = ledger
            .load_command_output_capture_for_effect(&claim.claimed_effect.intent.effect_id)?;
        let acquired = capture.acquired.as_ref().ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup omitted acquired capture".into(),
            )
        })?;
        if acquired != &claim.acquired
            || capture.terminal.is_some()
            || claim.claimed_effect.observation.is_some()
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup crossed capture authority".into(),
            ));
        }
        let recovery = claim
            .store
            .reopen_capture(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake zero-byte final-verification reopen failed: {error}"
                ))
            })?;
        if recovery.state() != CommandOutputCaptureJournalStateV1::Acquired
            || recovery.acquired() != Some(acquired)
            || recovery.store_head() != &acquired.store_head
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup did not reopen exact Acquired state"
                    .into(),
            ));
        }
        let detector_policy = match ledger.load_sensitive_output_detection_policy_for_effect(
            &claim.claimed_effect.intent.effect_id,
        ) {
            Ok(policy) => Some(policy),
            Err(LedgerError::ArtifactNotFound {
                entity: "sensitive output detection policy",
                ref id,
            }) if id == &claim.claimed_effect.intent.effect_id => None,
            Err(error) => return Err(error.into()),
        };
        let v2_recovery = claim
            .store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&capture.intent.capture_id)
            .map_err(|error| {
                DurableCoordinatorError::Protocol(format!(
                    "strict fake zero-byte final-verification v2 reopen failed: {error}"
                ))
            })?;
        match (detector_policy.as_ref(), v2_recovery.as_ref()) {
            (Some(policy), Some(v2))
                if v2.detector_policy() == policy
                    && v2.acquired() == Some(acquired)
                    && v2.head().generation == 2 => {}
            (None, None) => {}
            (Some(_), Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte final-verification cleanup crossed its exact policy-bound Acquired custody"
                        .into(),
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte final-verification cleanup found unpaired detector policy and v2 custody"
                        .into(),
                ));
            }
        }
        let claimed_at_unix_ms = observed_at_unix_ms.max(acquired.acquired_at_unix_ms);
        let expires_at_unix_ms = claimed_at_unix_ms
            .checked_add(MAX_COMMAND_OUTPUT_CAPTURE_RECONCILIATION_TTL_MS)
            .ok_or_else(|| {
                DurableCoordinatorError::Protocol(
                    "strict fake zero-byte final-verification claim timestamp overflow".into(),
                )
            })?;
        let cleanup_claim_id = Digest::sha256(
            format!(
                "{}:strict-fake-zero-byte-final-verification-cleanup-claim",
                claim.claimed_effect.intent.effect_id
            )
            .as_bytes(),
        )
        .as_str()
        .to_owned();
        let reconciliation = ledger.claim_command_output_capture_reconciliation(
            &capture.intent.capture_id,
            &cleanup_claim_id,
            "strict-fake-zero-byte-final-verification-cleanup-v1",
            claimed_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let reconciliation_permit = match reconciliation {
            CommandOutputCaptureReconciliationAdmission::Fresh { permit, .. } => permit,
            CommandOutputCaptureReconciliationAdmission::Busy(_)
            | CommandOutputCaptureReconciliationAdmission::Terminal(_) => {
                return Err(DurableCoordinatorError::Protocol(
                    "strict fake zero-byte final-verification cleanup could not acquire fresh fencing"
                        .into(),
                ));
            }
        };
        let exact_claim = reconciliation_permit.claim().clone();
        let cleaned = match (detector_policy.as_ref(), v2_recovery.as_ref()) {
            (Some(_), Some(_)) => {
                let prelaunch = claim
                    .store
                    .resume_sensitive_output_prelaunch_abort_v2(
                        &capture.intent,
                        Some(acquired),
                        &exact_claim,
                    )
                    .map_err(|error| {
                        DurableCoordinatorError::Protocol(format!(
                            "strict fake zero-byte final-verification policy-bound prelaunch cleanup failed: {error}"
                        ))
                    })?;
                prelaunch.validate().map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake zero-byte final-verification prelaunch cleanup is invalid: {error}"
                    ))
                })?;
                if prelaunch.reconciliation_claim() != &exact_claim
                    || prelaunch.v2_generation() != 2
                {
                    return Err(DurableCoordinatorError::Protocol(
                        "strict fake zero-byte final-verification prelaunch cleanup crossed its exact Core claim or v2 generation"
                            .into(),
                    ));
                }
                prelaunch.fenced_v1_recovery().clone()
            }
            (None, None) => claim
                .store
                .cleanup_capture(&exact_claim, recovery.store_head())
                .map_err(|error| {
                    DurableCoordinatorError::Protocol(format!(
                        "strict fake zero-byte final-verification legacy physical cleanup failed: {error}"
                    ))
                })?,
            (Some(_), None) | (None, Some(_)) => unreachable!(
                "strict fake validated exact detector-policy/v2 pairing before acquiring the Core claim"
            ),
        };
        if cleaned.state() != CommandOutputCaptureJournalStateV1::Cleaned
            || cleaned.acquired() != Some(acquired)
            || cleaned.cleaned_store_head() != Some(cleaned.store_head())
            || cleaned.cleaned_record_digest() != Some(cleaned.head_digest())
        {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup omitted exact Cleaned readback"
                    .into(),
            ));
        }
        let released_at_unix_ms = claimed_at_unix_ms.checked_add(1).ok_or_else(|| {
            DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification release timestamp overflow".into(),
            )
        })?;
        if released_at_unix_ms >= exact_claim.expires_at_unix_ms {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup exceeded its fencing lease"
                    .into(),
            ));
        }
        let released = ledger.release_command_output_capture_reconciliation(
            reconciliation_permit,
            released_at_unix_ms,
        )?;
        if released != exact_claim {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake zero-byte final-verification cleanup released crossed fencing".into(),
            ));
        }
        let cleaned_store_head = cleaned.store_head().clone();
        let cleanup_record_digest = cleaned
            .cleaned_record_digest()
            .expect("validated Cleaned state has record digest")
            .clone();
        let no_domain_proof_bytes = serde_json::to_vec(&serde_json::json!({
            "accepted_request_bytes": 0,
            "capture_id": capture.intent.capture_id,
            "cleanup_claim_id": exact_claim.claim_id,
            "dispatch_claim_id": claim
                .claimed_effect
                .dispatch_claim
                .as_ref()
                .expect("checked claimed effect")
                .dispatch_claim_id,
            "effect_id": claim.claimed_effect.intent.effect_id,
            "schema": "grok-build.strict-fake.no-command-domain.v1",
        }))
        .map_err(|error| {
            DurableCoordinatorError::Protocol(format!(
                "strict fake final-verification no-domain proof encoding failed: {error}"
            ))
        })?;
        ValidatedCommandCaptureAbandonment::try_new(
            acquired.clone(),
            cleaned_store_head,
            cleanup_record_digest,
            CommandDomainBackend::LinuxCgroupV2,
            no_domain_proof_bytes,
            released_at_unix_ms,
        )
    }

    #[test]
    fn terminal_projection_preserves_legacy_exits_and_current_typed_nonexits() {
        let mut receipt = VerificationReceipt {
            receipt_id: "termination-projection-receipt".into(),
            sprint_id: "termination-projection-sprint".into(),
            task_id: None,
            snapshot_id: Digest::sha256(b"termination-projection-snapshot"),
            command: CommandSpec {
                program: "verify".into(),
                arguments: Vec::new(),
                working_directory: PathBuf::new(),
            },
            policy_hash: Digest::sha256(b"termination-projection-policy"),
            exit_status: Some(17),
            termination: None,
            output_digest: Digest::sha256(b"termination-projection-output"),
            duration_ms: 1,
            finished_at_unix_ms: 1,
        };
        assert_eq!(receipt.validate(), Ok(()));
        assert_eq!(
            verification_receipt_termination(&receipt)
                .expect("validated historical exit projects exactly"),
            CommandTerminationV1::Exited { code: 17 }
        );

        receipt.exit_status = None;
        receipt.termination = Some(CommandTerminationV1::TimedOut);
        assert_eq!(receipt.validate_current(), Ok(()));
        assert_eq!(
            verification_receipt_termination(&receipt)
                .expect("current typed non-exit projects exactly"),
            CommandTerminationV1::TimedOut
        );

        receipt.termination = None;
        assert!(verification_receipt_termination(&receipt).is_err());
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct StrictFakeRunnerLifecycle;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum LiveStateScriptBehavior {
        Exact,
        LaunchThenError,
        FailBeforeClaim,
        ClaimThenLoseResponse,
        CleanupRequired,
    }

    struct LiveStateScriptRunnerLifecycle {
        behavior: LiveStateScriptBehavior,
        launch_count: Rc<Cell<u32>>,
        dispatch_count: Rc<Cell<u32>>,
        cleanup_count: Rc<Cell<u32>>,
    }

    impl LiveStateScriptRunnerLifecycle {
        fn new(
            behavior: LiveStateScriptBehavior,
            launch_count: Rc<Cell<u32>>,
            dispatch_count: Rc<Cell<u32>>,
            cleanup_count: Rc<Cell<u32>>,
        ) -> Self {
            Self {
                behavior,
                launch_count,
                dispatch_count,
                cleanup_count,
            }
        }
    }

    impl WalkingSkeletonRunnerLifecycle for LiveStateScriptRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            let mut strict = StrictFakeRunnerLifecycle;
            strict.ensure_task_attempt_running(ledger, start)
        }

        fn dispatch_task_effect(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            let mut strict = StrictFakeRunnerLifecycle;
            strict.dispatch_task_effect(ledger, dispatch)
        }

        fn ensure_sprint_live_state_verifier(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonLiveStateVerifierStart<'_>,
        ) -> Result<WalkingSkeletonLiveStateVerifierBoundary, DurableCoordinatorError> {
            self.launch_count
                .set(self.launch_count.get().saturating_add(1));
            let mut strict = StrictFakeRunnerLifecycle;
            let boundary = strict.ensure_sprint_live_state_verifier(ledger, start)?;
            if self.behavior == LiveStateScriptBehavior::LaunchThenError {
                return Err(DurableCoordinatorError::Protocol(
                    "injected stop after durable live-state verifier launch".into(),
                ));
            }
            Ok(boundary)
        }

        fn cleanup_unadmitted_sprint_live_state_verifier_launch(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonUnadmittedLiveStateVerifierCleanup<'_>,
        ) -> Result<WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if self.behavior == LiveStateScriptBehavior::CleanupRequired {
                return Ok(
                    WalkingSkeletonUnadmittedLiveStateVerifierCleanupOutcome::CleanupRequired {
                        reason: "injected unadmitted live-state verifier cleanup pause".into(),
                    },
                );
            }
            let mut strict = StrictFakeRunnerLifecycle;
            strict.cleanup_unadmitted_sprint_live_state_verifier_launch(ledger, cleanup)
        }

        #[allow(clippy::too_many_lines)] // One adversarial fake owns the complete claimed verifier wire exchange.
        fn dispatch_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            dispatch: WalkingSkeletonLiveStateCaptureDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedLiveStateCaptureResponse, DurableCoordinatorError>
        {
            self.dispatch_count
                .set(self.dispatch_count.get().saturating_add(1));
            match self.behavior {
                LiveStateScriptBehavior::FailBeforeClaim => {
                    drop(dispatch.dispatch_permit);
                    Err(DurableCoordinatorError::Protocol(
                        "injected definite failure before live-state dispatch claim".into(),
                    ))
                }
                LiveStateScriptBehavior::ClaimThenLoseResponse => {
                    let opaque_frame = format!(
                        "strict-fake-live-state-lost-response:{}",
                        dispatch.intent.effect_id
                    )
                    .into_bytes();
                    let (_claimed, transport_permit) = ledger
                        .claim_sprint_live_state_capture_dispatch(
                            dispatch.dispatch_permit,
                            &opaque_frame,
                        )?;
                    drop(transport_permit);
                    Err(DurableCoordinatorError::Protocol(
                        "injected process loss after durable live-state dispatch claim".into(),
                    ))
                }
                LiveStateScriptBehavior::Exact
                | LiveStateScriptBehavior::CleanupRequired
                | LiveStateScriptBehavior::LaunchThenError => {
                    let mut strict = StrictFakeRunnerLifecycle;
                    strict.dispatch_sprint_live_state_capture(ledger, dispatch)
                }
            }
        }

        fn cleanup_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonLiveStateCaptureCleanup<'_>,
        ) -> Result<WalkingSkeletonLiveStateCaptureCleanupOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            if self.behavior == LiveStateScriptBehavior::CleanupRequired {
                return Ok(
                    WalkingSkeletonLiveStateCaptureCleanupOutcome::CleanupRequired {
                        reason: "injected live-state verifier cleanup pause".into(),
                    },
                );
            }
            let mut strict = StrictFakeRunnerLifecycle;
            strict.cleanup_sprint_live_state_capture(ledger, cleanup)
        }

        fn reconcile_claimed_sprint_live_state_capture(
            &mut self,
            ledger: &mut EventLedger,
            recovery: WalkingSkeletonClaimedLiveStateCaptureRecovery<'_>,
        ) -> Result<WalkingSkeletonClaimedLiveStateCaptureRecoveryOutcome, DurableCoordinatorError>
        {
            self.cleanup_count
                .set(self.cleanup_count.get().saturating_add(1));
            let mut strict = StrictFakeRunnerLifecycle;
            strict.reconcile_claimed_sprint_live_state_capture(ledger, recovery)
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct UnpersistedRunnerLifecycle;

    #[derive(Clone)]
    struct PreSessionRetryScriptLifecycle {
        trace: Rc<RefCell<Vec<String>>>,
    }

    impl PreSessionRetryScriptLifecycle {
        fn new(trace: Rc<RefCell<Vec<String>>>) -> Self {
            Self { trace }
        }
    }

    impl WalkingSkeletonRunnerLifecycle for PreSessionRetryScriptLifecycle {
        #[allow(
            clippy::too_many_lines,
            reason = "the test fixture keeps one complete sessionless launch admission and durable refusal chain explicit"
        )]
        fn ensure_task_attempt_running(
            &mut self,
            ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            self.trace
                .borrow_mut()
                .push(format!("ensure:{}", start.attempt.attempt_id));
            validate_exact_authority(start.authority, start.sprint_spec)?;
            start.policy.validate_integrity(start.authority)?;
            let launch_id = format!("scripted-pre-session-launch:{}", start.attempt.attempt_id);
            let session_id = format!("scripted-pre-session-session:{}", start.attempt.attempt_id);
            let launch = RunnerLaunchIntent {
                contract_version: CONTRACT_VERSION,
                launch_id: launch_id.clone(),
                sprint_id: start.sprint_spec.sprint_id.clone(),
                session_id: session_id.clone(),
                purpose: RunnerSessionPurpose::TaskWorker,
                worker_id: Some(WORKER_ID.into()),
                worker_lease: Some(start.attempt.worker_lease.clone()),
                policy_hash: start.policy.contract().policy_hash.clone(),
                runner_binary_digest: fake_runner_digest(
                    "pre-session-script-binary",
                    start.attempt,
                ),
                protocol_digest: fake_runner_digest("pre-session-script-protocol", start.attempt),
                private_state_digest: fake_runner_digest(
                    "pre-session-script-private",
                    start.attempt,
                ),
                grant_hash: start.authority.contract().grant_hash.clone(),
                policy_version: start.authority.contract().policy_version,
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
                    "scripted pre-session cleanup request encoding failed: {error}"
                ))
            })?;
            let cleanup_intent = EffectIntent {
                contract_version: CONTRACT_VERSION,
                effect_id: format!("{launch_id}:cleanup-effect"),
                idempotency_key: format!("{launch_id}:cleanup-key"),
                sprint_id: launch.sprint_id.clone(),
                task_id: None,
                worker_id: None,
                worker_lease: Some(start.attempt.worker_lease.clone()),
                causation_event_id: None,
                correlation_id: format!("{launch_id}:cleanup-correlation"),
                kind: EffectKind::CleanupWorkerDomain,
                request_digest: Digest::sha256(&cleanup_bytes),
                policy_hash: launch.policy_hash.clone(),
                input_snapshot: start.input_snapshot.clone(),
                created_at_unix_ms: start.requested_at_unix_ms,
            };
            let cleanup_event = AgentEvent {
                contract_version: CONTRACT_VERSION,
                sequence: ledger.next_sequence(&launch.sprint_id)?,
                event_id: format!("{launch_id}:cleanup-proposed"),
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
            let admission = ledger.admit_runner_launch_with_cleanup(
                &launch,
                start.policy,
                &cleanup_intent,
                &cleanup_bytes,
                &cleanup_event,
            )?;
            let preparation_attempt = RunnerLaunchPreparationAttempt {
                contract_version: CONTRACT_VERSION,
                attempt_id: format!("{launch_id}:refusal-attempt"),
                sprint_id: launch.sprint_id.clone(),
                launch_id: launch.launch_id.clone(),
                cleanup_effect_id: cleanup_intent.effect_id.clone(),
                native_journal_id: format!("{launch_id}:native-journal"),
                expected_platform_binding_digest: fake_runner_digest(
                    "pre-session-script-binding",
                    start.attempt,
                ),
                claimed_at_unix_ms: start.requested_at_unix_ms,
            };
            let expected_outcome = RunnerLaunchPreparationOutcome {
                disposition: RunnerLaunchPreparationDisposition::RefusedBeforeNativeEffect,
                native_evidence_bytes: format!("scripted-refusal:{launch_id}").into_bytes(),
                finished_at_unix_ms: start.requested_at_unix_ms,
            };
            ledger.with_runner_launch_preparation_claim(
                &admission,
                &preparation_attempt,
                |_| expected_outcome,
            )?;
            Err(DurableCoordinatorError::Protocol(format!(
                "scripted task-worker launch refusal for {launch_id}"
            )))
        }

        fn cleanup_pre_session_task_attempt(
            &mut self,
            ledger: &mut EventLedger,
            cleanup: WalkingSkeletonPreSessionTaskCleanup<'_>,
        ) -> Result<WalkingSkeletonPreSessionTaskCleanupOutcome, DurableCoordinatorError> {
            let plan = ledger.plan_task_attempt_cleanup_disposition(cleanup.attempt)?;
            let cleaned_at_unix_ms = cleanup
                .requested_at_unix_ms
                .max(plan.minimum_terminal_at_unix_ms());
            let disposition = ledger
                .with_planned_task_attempt_cleanup_disposition_exclusion(&plan, |claim| {
                    scripted_pre_session_cleanup_terminal(claim, cleaned_at_unix_ms)
                })?;
            let kind = match disposition {
                TaskAttemptDisposition::Retryable(_) => "Retryable",
                TaskAttemptDisposition::AttemptsExhausted(_) => "AttemptsExhausted",
                _ => "Unexpected",
            };
            self.trace.borrow_mut().push(format!(
                "cleanup:{}:{kind}",
                disposition.metadata().attempt.attempt_id
            ));
            Ok(WalkingSkeletonPreSessionTaskCleanupOutcome::Completed(
                Box::new(disposition),
            ))
        }

        fn dispatch_task_effect(
            &mut self,
            _ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            Err(DurableCoordinatorError::Protocol(format!(
                "scripted pre-session lifecycle must stop before task effect {}",
                dispatch.intent.effect_id
            )))
        }
    }

    impl WalkingSkeletonRunnerLifecycle for UnpersistedRunnerLifecycle {
        fn ensure_task_attempt_running(
            &mut self,
            _ledger: &mut EventLedger,
            start: WalkingSkeletonRunnerStart<'_>,
        ) -> Result<TaskAttemptRunningBoundary, DurableCoordinatorError> {
            let identity = fake_runner_digest("unpersisted-running", start.attempt);
            Ok(TaskAttemptRunningBoundary {
                contract_version: CONTRACT_VERSION,
                boundary_id: format!("unpersisted-running-boundary-{identity}"),
                attempt: start.attempt.clone(),
                runner_launch_id: format!("unpersisted-launch-{identity}"),
                runner_session_id: format!("unpersisted-session-{identity}"),
                transition_event_id: format!("unpersisted-running-event-{identity}"),
                started_at_unix_ms: start.requested_at_unix_ms,
            })
        }

        fn dispatch_task_effect(
            &mut self,
            _ledger: &mut EventLedger,
            dispatch: WalkingSkeletonTaskEffectDispatch<'_>,
        ) -> Result<WalkingSkeletonClaimedTaskEffectResponse, DurableCoordinatorError> {
            Err(DurableCoordinatorError::Protocol(format!(
                "unpersisted fake boundary cannot dispatch effect {}",
                dispatch.intent.effect_id
            )))
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the strict final-verification fixture constructs one exact typed command proof box for both passing and known-nonpassing terminals"
    )]
    fn strict_fake_dispatch_sprint_final_verification(
        ledger: &mut EventLedger,
        dispatch: WalkingSkeletonFinalVerificationDispatch<'_>,
        termination: CommandTerminationV1,
    ) -> Result<WalkingSkeletonClaimedFinalVerificationResponse, DurableCoordinatorError> {
        let output = b"strict-fake repository-wide final verification passed\n".to_vec();
        let (adapted, observation_authority, observed_at_unix_ms) =
            strict_fake_claimed_verification_v12(
                ledger,
                FreshRunnerEffectDispatchPermit::SprintFinalVerification(dispatch.dispatch_permit),
                dispatch.workspace_grant,
                &dispatch.final_verifier.runner_launch,
                &dispatch.final_verifier.runner_session,
                dispatch.intent,
                &dispatch.admission.command,
                None,
                None,
                Some((dispatch.receipt_id, dispatch.observation_id)),
                dispatch.post_response_timestamps,
                termination,
                &output,
            )?;
        let StrictFakeAdaptedCommand::Verification(adapted) = adapted else {
            return Err(DurableCoordinatorError::Protocol(
                "strict fake final command returned ordinary evidence".into(),
            ));
        };
        let command_terminal = adapted.command_terminal().clone();
        WalkingSkeletonClaimedFinalVerificationResponse::new_with_command_terminal(
            WalkingSkeletonFinalVerificationResponse {
                contract_version: CONTRACT_VERSION,
                sprint_spec: dispatch.sprint_spec.clone(),
                workspace_grant: dispatch.workspace_grant.contract().clone(),
                final_verifier: dispatch.final_verifier.clone(),
                admission: dispatch.admission.clone(),
                intent: dispatch.intent.clone(),
                outcome: WalkingSkeletonFinalVerificationOutcome::Succeeded(adapted.evidence),
            },
            observation_authority,
            command_terminal,
        )
        .bind_observed_at(observed_at_unix_ms)
    }
