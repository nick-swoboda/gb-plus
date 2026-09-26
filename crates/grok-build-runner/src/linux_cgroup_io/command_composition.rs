/// Composes an installed native service into one contained-command backend.
///
/// Authenticate the handoff, derive its state-root capability, observe anchored
/// facts and consume the capability into journal authority. Create retained
/// command directories, authenticate binaries and controls, then mint the plan.
/// Bootstrap and journal binding precede admission and backend creation.
///
/// The journal, bootstrap and plan must share the handoff's authenticated
/// service binding. Retained capabilities keep filesystem operations bound to
/// that service.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] at the first failed step. Missing controls or
/// invalid ownership never produce a reduced-control backend.
#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_lines,
    reason = "one linear composition keeps every authenticated source and the order the ownership rules require visible in the order it happens"
)]
pub(crate) fn open_installed_linux_service_for_command(
    inputs: LinuxInstalledServiceCommandInputs<'_>,
) -> Result<LinuxCgroupIo, CgroupIoFailure> {
    use crate::linux_command_plan::{
        ADMITTED_BUBBLEWRAP_IMAGE_V1, AuthenticatedBubblewrapImageV1, LinuxAuthenticatedFileV1,
        LinuxMeasuredTargetImageV1, LinuxProductionCommandPlanInputsV1, LinuxProgramImageV1,
        LinuxRetainedObjectIdentityV1, LinuxRetainedObjectKindV1, TARGET_IMAGE_OBJECT_ID,
    };

    const OPERATION: &str = "open-installed-linux-service-for-command";
    /// The launcher's own image bound, restated so an oversized target is
    /// refused before its bytes are pulled in to be measured.
    const MAX_TARGET_IMAGE_BYTES: usize = 128 * 1_024 * 1_024;

    let LinuxInstalledServiceCommandInputs {
        installer_root,
        workspace_root_path,
        command_directory_name,
        target_executable_path,
        authority,
        grant,
        policy,
        native_launch,
        role,
    } = inputs;

    // ---- step 3: the installed handoff --------------------------------
    let (handoff, _anchor_evidence) = open_installed_linux_native_service_handoff(installer_root)?;
    let expected = handoff.external_commitment.journal.clone();

    // ---- step 4: the single state-root capability ----------------------
    let (capability, host_roots) = handoff.into_state_root_capability(&expected)?;

    // ---- step 5: anchored facts, observed before the capability is spent
    let facts = capability.observe_anchored_plan_facts(&host_roots)?;
    let anchored = facts.plan_anchored_facts();

    // ---- step 6: the one journal authority this capability can mint ----
    let mut journal_authority =
        LinuxServiceCommandJournalAuthority::open_authenticated_service_singleton(
            capability,
            service_journal_binding_from_plan(&expected),
        )?;

    // ---- step 7: this command's retained directories -------------------
    // Opened from the authority's own retained state-root descriptor. The
    // workspace root is re-walked from its absolute name because the grant
    // carries a path, not a descriptor; every component is `O_NOFOLLOW`.
    let workspace =
        LinuxRetainedDirectoryPathProvenance::open_absolute(workspace_root_path, OPERATION)?;
    let directories = create_per_command_retained_directories(
        &journal_authority.journal.parent,
        &workspace.directory,
        command_directory_name,
        expected.owner_uid,
    )?;

    // ---- step 8: the authenticated component sources -------------------
    let bubblewrap_path = ADMITTED_BUBBLEWRAP_IMAGE_V1.resolved_path;
    let bubblewrap_provenance =
        LinuxRetainedExecutablePathProvenance::open_absolute(bubblewrap_path, OPERATION)?;
    let bubblewrap_bytes = read_retained_bootstrap_file(
        &bubblewrap_provenance.file,
        MAX_TARGET_IMAGE_BYTES,
        OPERATION,
    )?;
    let bubblewrap = AuthenticatedBubblewrapImageV1::authenticate_admitted(
        bubblewrap_path,
        observe_retained_file_kernel_facts(&bubblewrap_provenance.file, OPERATION)?,
        &bubblewrap_bytes,
    )
    .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;

    let mandatory_controls = directories.mint_mandatory_control_artefacts(
        &workspace.directory,
        facts.host_architecture.architecture().audit_architecture(),
    )?;

    let target =
        LinuxRetainedExecutablePathProvenance::open_absolute(target_executable_path, OPERATION)?;
    let target_bytes =
        read_retained_bootstrap_file(&target.file, MAX_TARGET_IMAGE_BYTES, OPERATION)?;
    let target_length = u64::try_from(target_bytes.len()).map_err(|_| {
        failure(
            OPERATION,
            EffectCertainty::NotApplied,
            "the command target's length does not fit a u64",
        )
    })?;
    // Measured from the complete readback taken through the retained
    // descriptor above, not from a second read of the path.
    let measured = LinuxMeasuredTargetImageV1::measure(
        target_bytes.as_slice(),
        target_length,
        anchored.host_architecture,
        "the command target",
    )
    .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;
    let target_image = LinuxProgramImageV1::from_measured_image(
        target_executable_path,
        LinuxAuthenticatedFileV1::from_complete_readback(
            TARGET_IMAGE_OBJECT_ID,
            target_executable_path,
            target_length,
            Digest::sha256(&target_bytes),
        )
        .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?,
        &measured,
    )
    .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;
    let target_object = LinuxRetainedObjectIdentityV1::from_kernel_observation(
        TARGET_IMAGE_OBJECT_ID,
        LinuxRetainedObjectKindV1::RegularFile,
        observe_retained_file_kernel_facts(&target.file, OPERATION)?,
    )
    .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;

    let input_snapshot = authority
        .envelope()
        .effect
        .as_ref()
        .ok_or_else(|| {
            failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the command effect authority carries no effect context, so no setup channel can be anchored",
            )
        })?
        .input_snapshot
        .clone();
    let statement = facts.setup_channel_statement(role, &input_snapshot);
    let sealed = seal_linux_native_service_setup_channel(&statement)?;

    // ---- step 9: the twelve-component plan -----------------------------
    let plan = LinuxProductionCommandPlanInputsV1 {
        authority,
        grant,
        policy,
        anchored,
        bubblewrap: &bubblewrap,
        setup_channel: sealed.authenticated(),
        target_image: &target_image,
        target_object: &target_object,
        directories: directories.identities(),
        mandatory_controls: &mandatory_controls,
    }
    .mint(native_launch)
    .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?;

    // The command's working directory is created under the retained execution
    // root only now: the directory observation above is of a freshly created
    // empty tree and its link count is evidence about that. The plan is reached
    // through the retained descriptor, one component at a time.
    let cwd_component = plan
        .service_setup_descriptor_binding()
        .map_err(|error| failure(OPERATION, EffectCertainty::NotApplied, error.to_string()))?
        .cwd
        .root_relative_path;
    if !cwd_component.is_empty() {
        directories.descriptors()[1]
            .create_dir(&cwd_component)
            .map_err(|error| io_failure(OPERATION, EffectCertainty::NotApplied, error))?;
    }

    // ---- step 10: bootstrap, journal, bind ------------------------------
    // The bootstrap borrows the one authority for the duration of `publish`;
    // the journaled plan then owns it. There is no second capability and no
    // second store.
    let bootstrap = LinuxNativeServiceBootstrapAuthority::open_authenticated(
        &mut journal_authority,
        host_roots,
        &plan,
    )?;
    let journaled = journal_linux_production_command_plan(plan, journal_authority)?;
    let bootstrapped = bind_journaled_plan_to_linux_native_service_bootstrap(journaled, bootstrap)?;

    // ---- step 11: admit, launch images, setup, backend ------------------
    let admission = admit_linux_native_service_command(
        bootstrapped,
        LinuxNativeServiceProcessImageAuthority::observe_current_process()?,
    )?;
    let launch_authority = select_linux_native_service_launch_images(admission)?;
    let (setup_authority, _peers) = open_linux_native_service_setup_authority(
        launch_authority,
        &directories,
        &workspace.directory,
        sealed,
    )?;
    open_linux_native_service_owned_backend(setup_authority)
}

/// Standing proof that the production composition exists and keeps its shape.
///
/// The composition has no caller yet: the session path cannot name an installed
/// service, because nothing in `SupervisorPaths`, the grant, or the v14 release
/// envelope carries an installer root. Naming it here from ordinary production
/// code means a build in which it became test-only, changed shape, or
/// disappeared fails to compile, rather than the composition quietly rotting
/// while it waits for that input.
#[cfg(target_os = "linux")]
const LINUX_INSTALLED_SERVICE_COMMAND_COMPOSITION: fn(
    LinuxInstalledServiceCommandInputs<'_>,
) -> Result<LinuxCgroupIo, CgroupIoFailure> = open_installed_linux_service_for_command;
