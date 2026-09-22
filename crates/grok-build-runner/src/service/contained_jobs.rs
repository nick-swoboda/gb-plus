/// Session-minted custody for exactly one contained command dispatch.
///
/// Every field is authority the initialized `Worker` session already owns and
/// has already validated. The value is built inside [`RunnerService`], moved
/// once into the command job, and is deliberately **never** handed to the
/// [`CommandJobFactory`] seam.
///
/// That last point is a measured design decision rather than a preference.
/// `prepare_v12` consumes [`SessionValidatedWorkerExecutionRoot`] by value and
/// that type is not `Clone`, so widening `create` to carry custody forces the
/// service to mint it *before* asking whether a job is wanted -- on every v12
/// command dispatch, including the ones that are refused, and including the
/// session shapes (`FinalVerifier`, `Applier`, `LiveStateVerifier`) that own no
/// such custody at all. A probe measured exactly that: the widened signature
/// compiled, and the existing containment-refusal test then panicked inside the
/// eager mint. Keeping the custody inside the service costs a private job
/// builder and buys a factory seam that can never obtain live private-state or
/// shadow descriptors.
struct SessionMintedCommandCustody {
    authority: CommandEffectAuthorityV2,
    /// The desktop's release admission, when the request arrived on v14.
    release_authority: Option<WireContainedCommandReleaseAuthorityV1>,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    execution_root_authority: SessionValidatedWorkerExecutionRoot,
    paths: SupervisorPaths,
    execution_root_manifest: WorkspaceManifest,
    /// This runner's own launch preparation, when the desktop sent one.
    ///
    /// Carried per command because the composition needs it to mint the plan's
    /// launch identity, and `None` composes no installed service rather than
    /// an identity the runner made up.
    launch_preparation: Option<WireRunnerLaunchPreparationV1>,
}

/// What the session could mint for one admitted `WorkerRunCommand`.
///
/// Every arm produces a job, so "a job exists" is exactly "an admitted worker
/// command effect", which is what makes the coordinator's admission count
/// locally knowable by the desktop client rather than merely bounded.
enum ProductionCommandJobPlan {
    /// Full custody: the command reaches `prepare_v12` and the backend.
    Contained(Box<SessionMintedCommandCustody>),
    /// Custody could not be minted; the command is refused before any launch.
    RefusedBeforeLaunch(WireCommandFailureCodeV12),
    /// The shadow no longer equals the durable effect input snapshot.
    ReconciliationRequired(WireReconciliationReference),
}

/// What one contained dispatch established, before projection onto the
/// coordinator's closed outcome set.
///
/// The supervisor error is retained rather than immediately collapsed to a wire
/// code so the runner's own tests can read the backend's exact refusal string.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "one contained dispatch produces exactly one of these and it is consumed once"
)]
pub(crate) enum ContainedCommandRun {
    /// `prepare_v12` or backend composition refused; nothing was launched.
    PreparationRefused(SupervisorError),
    /// A real `PreparedContainedCommand` reached `execute_classified`.
    Executed(crate::command::contained_boundary::ContainedExecutionOutcome),
}

/// Prepares and executes one contained command from session-minted custody.
///
/// This is the whole production command arc that exists today: exact v12
/// authority in, a real `PreparedContainedCommand`, and the platform backend's
/// own answer. Nothing here decides whether containment is adequate -- that
/// judgement belongs to `validate_preflight`, which requires the backend's
/// reported control set to equal `required_controls` exactly.
fn run_contained_command(
    custody: SessionMintedCommandCustody,
    cancellation: &CancellationToken,
) -> ContainedCommandRun {
    let SessionMintedCommandCustody {
        authority,
        release_authority,
        grant,
        policy,
        execution_root_authority,
        paths,
        execution_root_manifest,
        launch_preparation,
    } = custody;
    let prepared = match crate::command::contained_boundary::prepare_v12(
        authority,
        grant.clone(),
        policy.clone(),
        execution_root_authority,
        &paths,
        &execution_root_manifest,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return ContainedCommandRun::PreparationRefused(error),
    };
    // The admission is attached here and nowhere else, from the decoded v14
    // envelope this command arrived in. The runner never constructs one.
    let prepared = match release_authority {
        Some(authority) => prepared.with_contained_command_release(
            crate::linux_containment::ContainedCommandReleaseAuthorityV1 {
                command_effect_id: authority.command_effect_id,
                request_digest: authority.request_digest.to_string(),
                native_evidence_digest: authority.native_evidence_digest,
            },
        ),
        None => prepared,
    };
    execute_prepared_contained_command(
        prepared,
        grant,
        policy,
        &paths,
        launch_preparation.as_ref(),
        cancellation,
    )
}

/// Reports one contained-command refusal on the runner's stderr diagnostic
/// channel.
///
/// The wire answer for a refused-before-launch command is a failure code with
/// no text, so without this an operator learns *that* containment was
/// unavailable and never *which* requirement failed -- across a route with
/// dozens of distinct refusals, that is the difference between a diagnosable
/// system and an opaque one.
///
/// This is the one point where both refusal kinds converge: a preparation
/// refusal and the backend's own pre-launch refusal are the same fact on the
/// wire, and reporting here rather than at each producer means no future
/// refusal path can be added that is silent by omission.
///
/// stderr is the right channel and not a second-best one. It is where this
/// process already explains fatal refusals, it grants nothing and carries no
/// authority, and it is read by whoever launched the runner rather than by
/// whoever sent the request. Nothing here decides anything -- the refusal is
/// unchanged and this only makes its existing reason legible.
///
/// The message is bounded and control-stripped for the same reason the process
/// entry point bounds its own diagnostics: a refusal detail can quote a path or
/// a kernel message, and neither is trusted to be short or printable.
fn report_contained_refusal(error: &SupervisorError) {
    const LIMIT: usize = 2_048;
    let detail = error.to_string();
    let mut bounded = detail
        .chars()
        .map(|character| {
            if character.is_control() && character != '\t' {
                ' '
            } else {
                character
            }
        })
        .take(LIMIT)
        .collect::<String>();
    if detail.chars().count() > LIMIT {
        bounded.push('\u{2026}');
    }
    eprintln!("contained command refused before launch: {bounded}");
}

/// Composes the host's contained backend and runs the prepared command on it.
#[cfg(target_os = "linux")]
pub(crate) fn execute_prepared_contained_command(
    prepared: crate::command::contained_boundary::PreparedContainedCommand,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    launch_preparation: Option<&crate::wire::WireRunnerLaunchPreparationV1>,
    cancellation: &CancellationToken,
) -> ContainedCommandRun {
    // The installed service is composed only when this runner was told where
    // one is *and* the desktop sent it a launch preparation. Absent either, the
    // in-process backend is composed exactly as before -- which refuses at its
    // service-unavailable preflight rather than running anything less contained.
    let composed = crate::command::linux_backend::compose_on_installed_service(
        &prepared,
        &grant,
        &policy,
        paths,
        launch_preparation,
    );
    let backend = match composed {
        Ok(Some(io)) => crate::command::linux_backend::LinuxCgroupV2Backend::service_owned(
            grant, policy, paths, io,
        ),
        Ok(None) => crate::command::linux_backend::LinuxCgroupV2Backend::new(grant, policy, paths),
        Err(error) => return ContainedCommandRun::PreparationRefused(error),
    };
    match backend {
        Ok(backend) => ContainedCommandRun::Executed(
            crate::command::contained_boundary::execute_classified(backend, prepared, cancellation),
        ),
        Err(error) => ContainedCommandRun::PreparationRefused(error),
    }
}

/// Composes the host's contained backend and runs the prepared command on it.
#[cfg(target_os = "macos")]
pub(crate) fn execute_prepared_contained_command(
    prepared: crate::command::contained_boundary::PreparedContainedCommand,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    _launch_preparation: Option<&crate::wire::WireRunnerLaunchPreparationV1>,
    cancellation: &CancellationToken,
) -> ContainedCommandRun {
    match crate::command::macos_backend::MacosDedicatedIdentityBackend::new(grant, policy, paths) {
        Ok(backend) => ContainedCommandRun::Executed(
            crate::command::contained_boundary::execute_classified(backend, prepared, cancellation),
        ),
        Err(error) => ContainedCommandRun::PreparationRefused(error),
    }
}

/// Refuses on any target with no compiled contained backend.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn execute_prepared_contained_command(
    prepared: crate::command::contained_boundary::PreparedContainedCommand,
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    paths: &SupervisorPaths,
    _launch_preparation: Option<&crate::wire::WireRunnerLaunchPreparationV1>,
    cancellation: &CancellationToken,
) -> ContainedCommandRun {
    drop(prepared);
    drop(grant);
    drop(policy);
    let _ = paths;
    let _ = cancellation;
    ContainedCommandRun::PreparationRefused(SupervisorError::Capability(
        "no contained command backend is compiled for this target".into(),
    ))
}

/// Projects a contained run onto the coordinator's closed outcome set.
fn contained_command_job_outcome(run: ContainedCommandRun) -> CommandJobOutcome {
    use crate::command::contained_boundary::ContainedExecutionOutcome;
    match run {
        // Preparation and the backend's own pre-launch refusal are the same
        // fact on the wire -- nothing was launched -- and both carry only the
        // supervisor error that names why.
        ContainedCommandRun::PreparationRefused(error)
        | ContainedCommandRun::Executed(ContainedExecutionOutcome::RefusedBeforeLaunch(error)) => {
            report_contained_refusal(&error);
            CommandJobOutcome::RefusedBeforeLaunch {
                code: contained_command_failure_code(&error),
            }
        }
        ContainedCommandRun::Executed(ContainedExecutionOutcome::Terminal(evidence)) => {
            CommandJobOutcome::Terminal(Box::new(CommandTerminalOutcome::Contained(evidence)))
        }
        ContainedCommandRun::Executed(ContainedExecutionOutcome::SensitiveOutputRejected(
            evidence,
        )) => CommandJobOutcome::Terminal(Box::new(
            CommandTerminalOutcome::SensitiveOutputRejected(evidence),
        )),
        ContainedCommandRun::Executed(ContainedExecutionOutcome::UnprovenAfterLaunch(_)) => {
            CommandJobOutcome::UnprovenAfterLaunch
        }
    }
}

/// Maps one supervisor refusal onto the closed v12 failure code set.
///
/// Every containment-shaped refusal -- a missing host capability, an
/// unprovable ceiling, a failed canary, or the Linux block -- collapses to
/// `ContainmentUnavailable`, which is what the production backends' own
/// service/transport-unavailable errors are. Nothing here widens the set or
/// invents a success shape.
const fn contained_command_failure_code(error: &SupervisorError) -> WireCommandFailureCodeV12 {
    match error {
        SupervisorError::Authority(_) | SupervisorError::InvalidCommand(_) => {
            WireCommandFailureCodeV12::InvalidAuthority
        }
        SupervisorError::Capability(_)
        | SupervisorError::UnenforceableLimit(_)
        | SupervisorError::Canary(_)
        | SupervisorError::LinuxBlocked(_) => WireCommandFailureCodeV12::ContainmentUnavailable,
        SupervisorError::CommandDomainCleanupProof(_) => WireCommandFailureCodeV12::CleanupUnproven,
        SupervisorError::CommandOutputStore(_) | SupervisorError::CommandOutputCleanup { .. } => {
            WireCommandFailureCodeV12::CaptureStorageFailure
        }
        SupervisorError::Io(_) => WireCommandFailureCodeV12::InternalFailure,
    }
}

impl RunnerService {
    /// Builds the production command job for one admitted `WorkerRunCommand`.
    ///
    /// Returns `None` only for request/session shapes the contained boundary
    /// cannot describe at all -- a `FinalVerifierRunCommand`, or any
    /// non-`Worker` session -- which keeps their existing evidence-backed
    /// `ContainmentUnavailable` refusal byte-identical. For an admitted worker
    /// command a job is always produced, so the coordinator's
    /// `command_effects_admitted` counter stays exactly the number of worker
    /// commands the client dispatched.
    fn production_command_job(
        &mut self,
        envelope: &RunnerRequestEnvelopeV12,
        authority: &CommandEffectAuthorityV2,
        release_authority: Option<WireContainedCommandReleaseAuthorityV1>,
    ) -> Option<CommandJob> {
        if !matches!(
            envelope.request.command_request(),
            RunnerRequest::WorkerRunCommand { .. }
        ) {
            // Same reasoning as `report_contained_refusal`: the wire answer
            // for "no job" is a bare `ContainmentUnavailable`, so without this
            // the two quite different causes below are indistinguishable to
            // whoever ran the runner.
            eprintln!(
                "contained command not dispatched: this request is not a WorkerRunCommand, so the \
                 contained boundary has nothing to describe"
            );
            return None;
        }
        // Read off the service before the session is borrowed mutably. Both
        // state who this runner is rather than what this request asks for.
        let install_root = self.linux_native_service_install_root.clone();
        let launch_preparation = self.retained_launch_preparation.clone();
        let Some(InitializedSession::Worker(worker)) = self.session.as_mut() else {
            eprintln!(
                "contained command not dispatched: this session is not an initialized worker \
                 session, so no worker command custody can be minted"
            );
            return None;
        };
        Some(
            match worker.contained_command_plan(
                envelope,
                authority,
                release_authority,
                install_root,
                launch_preparation,
            ) {
                ProductionCommandJobPlan::Contained(custody) => Box::new(move |cancellation| {
                    contained_command_job_outcome(run_contained_command(*custody, &cancellation))
                }),
                ProductionCommandJobPlan::RefusedBeforeLaunch(code) => {
                    Box::new(move |_| CommandJobOutcome::RefusedBeforeLaunch { code })
                }
                ProductionCommandJobPlan::ReconciliationRequired(reference) => {
                    Box::new(move |_| CommandJobOutcome::ReconciliationRequired { reference })
                }
            },
        )
    }
}

impl WorkerSession {
    /// Mints this session's custody for one admitted contained command.
    ///
    /// The shadow manifest is **re-captured here, at dispatch**, and the
    /// capture is required to equal the durable effect's input snapshot before
    /// any custody is handed over. The session retains only a snapshot digest
    /// between requests, and `prepare_v12` needs the manifest itself; deriving
    /// one from the digest is impossible and asserting one would be exactly the
    /// substitution the boundary exists to prevent. A drifted shadow is a
    /// reconciliation requirement, not a containment refusal.
    fn contained_command_plan(
        &mut self,
        envelope: &RunnerRequestEnvelopeV12,
        authority: &CommandEffectAuthorityV2,
        release_authority: Option<WireContainedCommandReleaseAuthorityV1>,
        install_root: Option<std::path::PathBuf>,
        launch_preparation: Option<WireRunnerLaunchPreparationV1>,
    ) -> ProductionCommandJobPlan {
        let Ok(command_effect_authority) = authority.v11_execution_projection() else {
            return ProductionCommandJobPlan::RefusedBeforeLaunch(
                WireCommandFailureCodeV12::InvalidAuthority,
            );
        };
        let Ok(execution_root_manifest) = self.prove_shadow_input(&envelope.effect.input_snapshot)
        else {
            return ProductionCommandJobPlan::ReconciliationRequired(
                WireReconciliationReference::SessionPrivateState {
                    state_id: self.shadow_leaf.clone(),
                },
            );
        };
        let Ok(execution_root_authority) =
            self.command_execution_root_authority(&command_effect_authority)
        else {
            return ProductionCommandJobPlan::RefusedBeforeLaunch(
                WireCommandFailureCodeV12::InvalidAuthority,
            );
        };
        let Some(shadow) = self.shadow.as_ref() else {
            return ProductionCommandJobPlan::RefusedBeforeLaunch(
                WireCommandFailureCodeV12::InvalidAuthority,
            );
        };
        ProductionCommandJobPlan::Contained(Box::new(SessionMintedCommandCustody {
            authority: authority.clone(),
            release_authority,
            grant: self.grant.clone(),
            policy: self.policy.clone(),
            execution_root_authority,
            paths: {
                let paths = SupervisorPaths::shadow(
                    self.shadow_store.root().to_path_buf(),
                    shadow.root().to_path_buf(),
                );
                match install_root {
                    Some(root) => paths.with_linux_native_service_install_root(root),
                    None => paths,
                }
            },
            execution_root_manifest,
            launch_preparation,
        }))
    }
}

