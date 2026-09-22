/// Side-effect-free, one-shot join of exact launch images and a separately
/// authenticated service setup capability.
///
/// The function performs validation reads only: it has no cgroup, journal,
/// filesystem-mutation, process, callback, spawn, or release effect.
/// Production cannot call it successfully until a genuine native service
/// descriptor mint exists.
pub(crate) fn bind_linux_native_service_setup_descriptors(
    launch_authority: LinuxNativeServiceLaunchImageAuthority,
    setup_descriptors: LinuxNativeServiceSetupDescriptorCapability,
) -> Result<LinuxNativeServiceSetupDescriptorAuthority, CgroupIoFailure> {
    launch_authority.validate_retained()?;
    setup_descriptors.validate_for(&launch_authority.bootstrapped.journaled.plan)?;
    let LinuxNativeServiceLaunchImageAuthority {
        bootstrapped,
        service_process_image,
        launch_images,
        lifetime_lock,
    } = launch_authority;
    let authority = LinuxNativeServiceSetupDescriptorAuthority {
        bootstrapped,
        service_process_image,
        launch_images,
        setup_descriptors,
        lifetime_lock,
    };
    authority.validate_retained()?;
    Ok(authority)
}

#[derive(Clone, Debug)]
struct LinuxNativeServiceChildDescriptorObservation {
    binding: LinuxServiceChildDescriptorBindingV1,
    identity: ObjectIdentity,
}

#[derive(Clone, Debug)]
struct LinuxNativeServiceChildImageMountObservation {
    binding: LinuxServiceChildImageMountBindingV1,
    identity: ObjectIdentity,
}

/// One descriptor exactly as a **stopped child's own** procfs entry reported it.
///
/// Every field is a kernel answer about the child's descriptor table:
/// `fstatat` through `/proc/<pid>/fd/<n>` for the identity, `readlinkat` on the
/// same magic link for the object class, and `/proc/<pid>/fdinfo/<n>` for the
/// access mode, the close-on-exec bit and the unique mount identity. Nothing
/// here is copied from the parent's own descriptors, which is the whole
/// difference between this and the plan projection the test constructor holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxNativeServiceObservedChildDescriptor {
    target_fd: u32,
    identity: ObjectIdentity,
    access: LinuxServiceSetupDescriptorAccessV1,
    close_on_exec: bool,
    kind: LinuxServiceChildDescriptorKindV1,
    mount_id: u64,
}

/// A stopped child's complete descriptor table, and the process it was read
/// from.
///
/// `open_fds` is the closure statement: it is every descriptor number the child
/// had open, enumerated with `getdents64` on `/proc/<pid>/fd`, so a table with
/// one extra entry is not the planned table.
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxNativeServiceStoppedChildTable {
    pid: u32,
    open_fds: Vec<u32>,
    descriptors: Vec<LinuxNativeServiceObservedChildDescriptor>,
}

/// Where a child-launch closure's descriptor facts came from.
///
/// The distinction is the reason this type exists. A capability built from
/// [`Self::PlanProjectionOnly`] has compared the plan against the **parent's**
/// retained descriptors and has never seen a child; only the test constructor
/// produces it, and it claims nothing about any process. A capability built
/// from [`Self::StoppedChild`] carries one real child's own table, and
/// `validate_for` then re-derives every clause of the plan's child contract
/// against it.
#[derive(Clone, Debug, Eq, PartialEq)]
enum LinuxNativeServiceChildTableEvidence {
    /// No child was started; the facts are the plan's own projection.
    PlanProjectionOnly,
    /// One real stopped child's `/proc/<pid>/fd` and `/proc/<pid>/fdinfo`.
    StoppedChild(LinuxNativeServiceStoppedChildTable),
}

/// Non-cloneable proof token for one exact child descriptor-table and sealed
/// image-mount/loader closure.
///
/// There are two constructors and they differ in exactly one thing: whether a
/// child was ever started. `open_authenticated` (Linux, production) materialises
/// the plan's table in a real process, stops it, and reads the table back out of
/// that process's own procfs entries; `child_table` is then
/// [`LinuxNativeServiceChildTableEvidence::StoppedChild`]. The test-only
/// constructor exercises the same comparison and custody contract against the
/// plan's own projection and claims no child, mount, or containment effect.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceChildLaunchClosureCapability {
    binding: LinuxServiceChildLaunchClosureBindingV1,
    descriptor_observations: Vec<LinuxNativeServiceChildDescriptorObservation>,
    image_mount_observations: Vec<LinuxNativeServiceChildImageMountObservation>,
    child_table: LinuxNativeServiceChildTableEvidence,
}

impl LinuxNativeServiceChildLaunchClosureCapability {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    #[cfg(test)]
    fn open_test_authenticated(
        setup_authority: &LinuxNativeServiceSetupDescriptorAuthority,
    ) -> Result<Self, CgroupIoFailure> {
        setup_authority.validate_retained()?;
        let plan = &setup_authority.bootstrapped.journaled.plan;
        let binding = plan
            .service_child_launch_closure_binding()
            .map_err(|error| {
                failure(
                    "mint-test-linux-native-service-child-launch-closure",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        let descriptor_observations = binding
            .inner_launcher_descriptor_table
            .iter()
            .map(|descriptor| {
                Ok(LinuxNativeServiceChildDescriptorObservation {
                    binding: descriptor.clone(),
                    identity: observe_linux_native_service_child_descriptor_source(
                        &setup_authority.setup_descriptors,
                        descriptor,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;
        let image_mount_observations = binding
            .image_mounts
            .iter()
            .map(|mount| {
                Ok(LinuxNativeServiceChildImageMountObservation {
                    binding: mount.clone(),
                    identity: observe_linux_native_service_child_image_mount(
                        &setup_authority.launch_images,
                        plan,
                        mount,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, CgroupIoFailure>>()?;
        let capability = Self {
            binding,
            descriptor_observations,
            image_mount_observations,
            child_table: LinuxNativeServiceChildTableEvidence::PlanProjectionOnly,
        };
        capability.validate_for(
            plan,
            &setup_authority.launch_images,
            &setup_authority.setup_descriptors,
        )?;
        Ok(capability)
    }

    fn validate_for(
        &self,
        plan: &ValidatedLinuxProductionCommandPlanV1,
        launch_images: &LinuxNativeServiceLaunchImageSetAuthority,
        setup_descriptors: &LinuxNativeServiceSetupDescriptorCapability,
    ) -> Result<(), CgroupIoFailure> {
        let expected = plan
            .service_child_launch_closure_binding()
            .map_err(|error| {
                failure(
                    "validate-linux-native-service-child-launch-closure",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        if self.binding != expected
            || self.descriptor_observations.len() != expected.inner_launcher_descriptor_table.len()
            || self.image_mount_observations.len() != expected.image_mounts.len()
        {
            return Err(failure(
                "validate-linux-native-service-child-launch-closure",
                EffectCertainty::NotApplied,
                "child descriptor table or image-mount/loader closure crossed its exact plan",
            ));
        }
        setup_descriptors.validate_for(plan)?;
        launch_images.validate_for(plan)?;

        let mut descriptor_identities = BTreeSet::new();
        for (observation, binding) in self
            .descriptor_observations
            .iter()
            .zip(&expected.inner_launcher_descriptor_table)
        {
            if &observation.binding != binding {
                return Err(failure(
                    "validate-linux-native-service-child-descriptor-table",
                    EffectCertainty::NotApplied,
                    "child descriptor crossed its slot, source, access, close-on-exec, or lifecycle role",
                ));
            }
            let identity =
                observe_linux_native_service_child_descriptor_source(setup_descriptors, binding)?;
            if identity != observation.identity
                || !descriptor_identities.insert((identity.device, identity.inode))
            {
                return Err(failure(
                    "validate-linux-native-service-child-descriptor-table",
                    EffectCertainty::NotApplied,
                    "child descriptor source identity changed or aliases another table role",
                ));
            }
        }

        let mut image_identities = BTreeSet::new();
        let mut destinations = BTreeSet::new();
        for (observation, binding) in self
            .image_mount_observations
            .iter()
            .zip(&expected.image_mounts)
        {
            if &observation.binding != binding {
                return Err(failure(
                    "validate-linux-native-service-child-image-mounts",
                    EffectCertainty::NotApplied,
                    "child image mount crossed its index, role, object, destination, content, or access",
                ));
            }
            let identity =
                observe_linux_native_service_child_image_mount(launch_images, plan, binding)?;
            if identity != observation.identity
                || !image_identities.insert((identity.device, identity.inode))
                || !destinations.insert(binding.destination.as_str())
            {
                return Err(failure(
                    "validate-linux-native-service-child-image-mounts",
                    EffectCertainty::NotApplied,
                    "child image mount source or destination aliases another loader role",
                ));
            }
        }

        if let LinuxNativeServiceChildTableEvidence::StoppedChild(observed) = &self.child_table {
            validate_observed_child_descriptor_table(
                observed,
                &expected.inner_launcher_descriptor_table,
                setup_descriptors,
            )?;
        }
        Ok(())
    }

    /// The real child table this closure was read from, when there is one.
    ///
    /// `None` means the capability holds the plan's own projection and has seen
    /// no process, which is what the test-only constructor produces.
    #[cfg(test)]
    const fn observed_child_table(&self) -> Option<&LinuxNativeServiceStoppedChildTable> {
        match &self.child_table {
            LinuxNativeServiceChildTableEvidence::PlanProjectionOnly => None,
            LinuxNativeServiceChildTableEvidence::StoppedChild(table) => Some(table),
        }
    }

    #[cfg(test)]
    fn revalidate_for_test(
        &self,
        setup_authority: &LinuxNativeServiceSetupDescriptorAuthority,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_for(
            &setup_authority.bootstrapped.journaled.plan,
            &setup_authority.launch_images,
            &setup_authority.setup_descriptors,
        )
    }
}

/// Re-derives every clause of the plan's child descriptor contract against one
/// stopped child's own table.
///
/// Four independent things are required, and each is a kernel answer about the
/// child rather than about the parent:
///
///   * the table is **closed** — the child's `/proc/<pid>/fd` enumerates the
///     plan's exact contiguous target set and nothing else;
///   * every slot holds the exact kernel object the plan's source names, proved
///     by `(device, inode)` against the retained descriptor and required to be
///     pairwise distinct;
///   * every slot's access mode is the plan's `child_access`, not the access
///     the parent happened to hold the source with; and
///   * every slot's close-on-exec bit is the plan's `child_close_on_exec`,
///     read from `/proc/<pid>/fdinfo`, which the kernel derives from the
///     child's descriptor table rather than echoing any open flag.
///
/// # Errors
///
/// Returns [`CgroupIoFailure`] when any clause fails.
fn validate_observed_child_descriptor_table(
    observed: &LinuxNativeServiceStoppedChildTable,
    expected: &[LinuxServiceChildDescriptorBindingV1],
    setup_descriptors: &LinuxNativeServiceSetupDescriptorCapability,
) -> Result<(), CgroupIoFailure> {
    const OPERATION: &str = "validate-linux-native-service-observed-child-descriptor-table";

    let planned_fds = expected
        .iter()
        .map(|binding| binding.target_fd)
        .collect::<Vec<_>>();
    if observed.open_fds != planned_fds || observed.descriptors.len() != expected.len() {
        return Err(failure(
            OPERATION,
            EffectCertainty::NotApplied,
            format!(
                "the stopped child's descriptor table is {:?}, not the plan's closed table {planned_fds:?}",
                observed.open_fds
            ),
        ));
    }
    let mut identities = BTreeSet::new();
    for (slot, binding) in observed.descriptors.iter().zip(expected) {
        if slot.target_fd != binding.target_fd {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                "the stopped child's observed slots are not the plan's slots in order",
            ));
        }
        let source =
            observe_linux_native_service_child_descriptor_source(setup_descriptors, binding)?;
        if slot.identity != source
            || !identities.insert((slot.identity.device, slot.identity.inode))
        {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!(
                    "the stopped child's fd {} names {}:{}, not the retained {}:{}, or aliases another slot",
                    binding.target_fd,
                    slot.identity.device,
                    slot.identity.inode,
                    source.device,
                    source.inode,
                ),
            ));
        }
        if slot.kind != binding.kind || slot.access != binding.child_access {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!(
                    "the stopped child's fd {} is {:?}/{:?}, not the planned {:?}/{:?}",
                    binding.target_fd, slot.kind, slot.access, binding.kind, binding.child_access,
                ),
            ));
        }
        if slot.close_on_exec != binding.child_close_on_exec {
            return Err(failure(
                OPERATION,
                EffectCertainty::NotApplied,
                format!(
                    "the stopped child's fd {} reports close-on-exec {}, and the plan requires {}",
                    binding.target_fd, slot.close_on_exec, binding.child_close_on_exec,
                ),
            ));
        }
    }
    Ok(())
}

fn observe_linux_native_service_child_descriptor_source(
    setup_descriptors: &LinuxNativeServiceSetupDescriptorCapability,
    binding: &LinuxServiceChildDescriptorBindingV1,
) -> Result<ObjectIdentity, CgroupIoFailure> {
    match &binding.source {
        LinuxServiceChildDescriptorSourceV1::Endpoint(role) => setup_descriptors
            .endpoints
            .iter()
            .find(|endpoint| endpoint.binding.role == *role)
            .map(|endpoint| endpoint.identity)
            .ok_or_else(|| {
                failure(
                    "validate-linux-native-service-child-descriptor-table",
                    EffectCertainty::NotApplied,
                    format!("child descriptor source {role:?} is absent"),
                )
            }),
        LinuxServiceChildDescriptorSourceV1::WorkingDirectory {
            execution_root_object_id,
            root_relative_path,
        } => {
            if execution_root_object_id != &setup_descriptors.binding.cwd.execution_root.object_id
                || root_relative_path != &setup_descriptors.binding.cwd.root_relative_path
            {
                return Err(failure(
                    "validate-linux-native-service-child-descriptor-table",
                    EffectCertainty::NotApplied,
                    "child working-directory descriptor crossed its execution root or root-relative path",
                ));
            }
            Ok(setup_descriptors.cwd.identity)
        }
    }
}

fn observe_linux_native_service_child_image_mount(
    launch_images: &LinuxNativeServiceLaunchImageSetAuthority,
    plan: &ValidatedLinuxProductionCommandPlanV1,
    binding: &LinuxServiceChildImageMountBindingV1,
) -> Result<ObjectIdentity, CgroupIoFailure> {
    let expected = plan.service_launch_image_bindings().map_err(|error| {
        failure(
            "validate-linux-native-service-child-image-mounts",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let expected = expected
        .iter()
        .find(|image| image.object_id == binding.object_id && image.role == binding.role)
        .ok_or_else(|| {
            failure(
                "validate-linux-native-service-child-image-mounts",
                EffectCertainty::NotApplied,
                "child image mount has no exact selected launch-image role",
            )
        })?;
    launch_images
        .images
        .iter()
        .find(|image| {
            image.binding.object_id == binding.object_id && image.binding.role == binding.role
        })
        .ok_or_else(|| {
            failure(
                "validate-linux-native-service-child-image-mounts",
                EffectCertainty::NotApplied,
                "selected launch-image set lost a child image mount source",
            )
        })?
        .validate_for(expected)
}

/// Exact setup custody joined to the complete child table and loader closure.
/// The value is still inert and contains no child, namespace, mount, spawn, or
/// release operation.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceChildLaunchClosureAuthority {
    setup_authority: LinuxNativeServiceSetupDescriptorAuthority,
    child_launch_closure: LinuxNativeServiceChildLaunchClosureCapability,
}

impl LinuxNativeServiceChildLaunchClosureAuthority {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        self.setup_authority.validate_retained()?;
        self.child_launch_closure.validate_for(
            &self.setup_authority.bootstrapped.journaled.plan,
            &self.setup_authority.launch_images,
            &self.setup_authority.setup_descriptors,
        )
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}

/// Side-effect-free one-shot join of setup custody and the complete child
/// descriptor-table/loader-closure proof token.
pub(crate) fn bind_linux_native_service_child_launch_closure(
    setup_authority: LinuxNativeServiceSetupDescriptorAuthority,
    child_launch_closure: LinuxNativeServiceChildLaunchClosureCapability,
) -> Result<LinuxNativeServiceChildLaunchClosureAuthority, CgroupIoFailure> {
    setup_authority.validate_retained()?;
    child_launch_closure.validate_for(
        &setup_authority.bootstrapped.journaled.plan,
        &setup_authority.launch_images,
        &setup_authority.setup_descriptors,
    )?;
    let authority = LinuxNativeServiceChildLaunchClosureAuthority {
        setup_authority,
        child_launch_closure,
    };
    authority.validate_retained()?;
    Ok(authority)
}

/// One-plan-scoped retained authority for entering the Linux cgroup mechanics
/// layer.
///
/// This value can be produced only by consuming the exact durable-plan and
/// authenticated-bootstrap join. It is intentionally non-cloneable and does
/// not provide a service-global capability: a later command requires its own
/// exact journaled plan receipt and a newly retained authority. Production
/// bootstrap and setup-capability minting remain absent, so this type exposes
/// no production execution route.
#[derive(Debug)]
pub(crate) struct LinuxNativeServiceMechanicsAuthority {
    plan: ValidatedLinuxProductionCommandPlanV1,
    receipt: LinuxCommandPlanDurableCommitReceipt,
    request: PrepareDomainRequest,
    journal_authority: LinuxServiceCommandJournalAuthority,
    bootstrap: LinuxNativeServiceBootstrapAuthority,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    launch_images: LinuxNativeServiceLaunchImageSetAuthority,
    setup_descriptors: LinuxNativeServiceSetupDescriptorCapability,
    child_launch_closure: LinuxNativeServiceChildLaunchClosureCapability,
    lifetime_lock: LinuxNativeServiceLifetimeLock,
}

impl LinuxNativeServiceMechanicsAuthority {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    fn validate_retained(&self) -> Result<(), CgroupIoFailure> {
        if !self.receipt.authenticates(&self.plan) {
            return Err(failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::Ambiguous,
                "durable command-plan receipt no longer authenticates the retained canonical plan",
            ));
        }
        let journal_binding = self.plan.journal_binding().map_err(|error| {
            failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        self.journal_authority
            .require_exact_plan_binding(&journal_binding)?;
        self.journal_authority
            .require_exact_command_plan_artifact(&self.plan, &self.receipt)?;
        self.bootstrap.require_exact_plan(
            &self.plan,
            &self.journal_authority.residual,
            &self.journal_authority.journal,
        )?;
        self.service_process_image
            .validate_for_digest(&journal_binding.authenticated_platform_service_digest)?;
        self.launch_images.validate_for(&self.plan)?;
        self.setup_descriptors.validate_for(&self.plan)?;
        self.child_launch_closure.validate_for(
            &self.plan,
            &self.launch_images,
            &self.setup_descriptors,
        )?;
        self.lifetime_lock.validate_for(
            &self.bootstrap.capabilities.state_root,
            journal_binding.service_state_root_identity,
        )?;
        let expected_request = self
            .plan
            .derive_private_prepare_request_after_durable_commit(&self.receipt)
            .map_err(|error| {
                failure(
                    "bind-linux-service-mechanics-plan",
                    EffectCertainty::Ambiguous,
                    error.to_string(),
                )
            })?;
        if self.request != expected_request {
            return Err(failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::Ambiguous,
                "retained mechanics request differs from the exact durably committed command plan",
            ));
        }
        Ok(())
    }

    fn require_exact_request(&self, request: &PrepareDomainRequest) -> Result<(), CgroupIoFailure> {
        self.validate_retained()?;
        if request != &self.request {
            return Err(failure(
                "bind-linux-service-mechanics-request",
                EffectCertainty::NotApplied,
                "domain request differs from this one-plan-scoped retained mechanics authority",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn revalidate_for_test(&self) -> Result<(), CgroupIoFailure> {
        self.validate_retained()
    }
}

#[derive(Debug)]
struct LinuxNativeServiceRuntimeGuard {
    /// The authentication proof that survived `into_journal`.
    ///
    /// This is what lets the guard re-validate every command without a second
    /// full authority: the proof travels here, and the store it is checked
    /// against is the one `LinuxCgroupIo` already holds.
    residual: LinuxServiceJournalAuthenticationResidualV1,
    plan: ValidatedLinuxProductionCommandPlanV1,
    receipt: LinuxCommandPlanDurableCommitReceipt,
    request: PrepareDomainRequest,
    bootstrap: LinuxNativeServiceBootstrapAuthority,
    service_process_image: LinuxNativeServiceProcessImageAuthority,
    launch_images: LinuxNativeServiceLaunchImageSetAuthority,
    setup_descriptors: LinuxNativeServiceSetupDescriptorCapability,
    child_launch_closure: LinuxNativeServiceChildLaunchClosureCapability,
    lifetime_lock: LinuxNativeServiceLifetimeLock,
}

impl LinuxNativeServiceRuntimeGuard {
    /// Re-validates every retained authority against the store the service is
    /// running on.
    ///
    /// The store is a parameter rather than a field because `LinuxCgroupIo`
    /// already owns it and this guard lives inside that same value; taking it
    /// here is what lets the check keep both halves -- the residual's
    /// authentication proof and the live journal's identities -- without a
    /// second authority existing anywhere.
    fn validate_retained(
        &self,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        if !self.receipt.authenticates(&self.plan) {
            return Err(failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::Ambiguous,
                "durable command-plan receipt no longer authenticates the retained canonical plan",
            ));
        }
        self.bootstrap
            .require_exact_plan(&self.plan, &self.residual, journal)?;
        let binding = self.plan.journal_binding().map_err(|error| {
            failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        self.service_process_image
            .validate_for_digest(&binding.authenticated_platform_service_digest)?;
        self.launch_images.validate_for(&self.plan)?;
        self.setup_descriptors.validate_for(&self.plan)?;
        self.child_launch_closure.validate_for(
            &self.plan,
            &self.launch_images,
            &self.setup_descriptors,
        )?;
        self.lifetime_lock
            .validate_for(&journal.parent, binding.service_state_root_identity)?;
        let expected_request = self
            .plan
            .derive_private_prepare_request_after_durable_commit(&self.receipt)
            .map_err(|error| {
                failure(
                    "bind-linux-service-mechanics-plan",
                    EffectCertainty::Ambiguous,
                    error.to_string(),
                )
            })?;
        if self.request != expected_request {
            return Err(failure(
                "bind-linux-service-mechanics-plan",
                EffectCertainty::Ambiguous,
                "retained mechanics request differs from the exact durably committed command plan",
            ));
        }
        Ok(())
    }

    fn require_exact_request(
        &self,
        request: &PrepareDomainRequest,
        journal: &CanonicalCgroupJournalStore,
    ) -> Result<(), CgroupIoFailure> {
        self.validate_retained(journal)?;
        if request != &self.request {
            return Err(failure(
                "bind-linux-service-mechanics-request",
                EffectCertainty::NotApplied,
                "domain request differs from this one-plan-scoped retained mechanics authority",
            ));
        }
        Ok(())
    }
}

/// Non-admissible type state produced only after the service-owned singleton
/// journal durably commits and reads back one exact complete command plan.
#[derive(Debug)]
pub(crate) struct JournaledLinuxProductionCommandPlanV1 {
    plan: ValidatedLinuxProductionCommandPlanV1,
    receipt: LinuxCommandPlanDurableCommitReceipt,
    request: PrepareDomainRequest,
    journal_authority: LinuxServiceCommandJournalAuthority,
}

impl JournaledLinuxProductionCommandPlanV1 {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    /// Test-only entry into the private cgroup mechanics layer. The callback
    /// receives no release or spawn capability, and no bridge value can be
    /// constructed before exact plan persistence/readback succeeds.
    #[cfg(test)]
    fn with_private_mechanics<R>(
        self,
        callback: impl FnOnce(&PrepareDomainRequest, LinuxServiceCommandJournalAuthority) -> R,
    ) -> R {
        debug_assert!(self.receipt.authenticates(&self.plan));
        callback(&self.request, self.journal_authority)
    }
}

/// Lossless, still-non-admissible bridge into the service-owned v2 journal.
/// No cgroup host effect is attempted by this function.
pub(crate) fn journal_linux_production_command_plan(
    plan: ValidatedLinuxProductionCommandPlanV1,
    mut journal_authority: LinuxServiceCommandJournalAuthority,
) -> Result<JournaledLinuxProductionCommandPlanV1, CgroupIoFailure> {
    let expected = plan.journal_binding().map_err(|error| {
        failure(
            "bind-complete-command-plan",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    journal_authority.require_exact_plan_binding(&expected)?;
    let token = journal_authority.journal.acquire_lock()?;
    let commit = journal_authority
        .journal
        .persist_complete_command_plan(token, &plan);
    let release = journal_authority.journal.release_lock(token);
    let committed = match (commit, release) {
        (Ok(committed), Ok(())) => committed,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(primary), Err(release)) => {
            return Err(failure(
                primary.operation,
                EffectCertainty::Ambiguous,
                format!(
                    "command-plan commit failed: {}; retained-lock release also failed: {}",
                    primary.detail, release.detail
                ),
            ));
        }
    };
    Ok(JournaledLinuxProductionCommandPlanV1 {
        plan,
        receipt: committed.receipt,
        request: committed.request,
        journal_authority,
    })
}

/// Consumes the already-journaled complete plan and the independently retained
/// native-service bootstrap authority, then proves their exact join.
///
/// The result remains non-admissible and exposes no cgroup, process, or cleanup
/// operation. Only a further consuming transition that retains this exact
/// plan receipt and bootstrap authority can satisfy the mechanics constructor.
pub(crate) fn bind_journaled_plan_to_linux_native_service_bootstrap(
    journaled: JournaledLinuxProductionCommandPlanV1,
    bootstrap: LinuxNativeServiceBootstrapAuthority,
) -> Result<BootstrappedLinuxProductionCommandPlanV1, CgroupIoFailure> {
    if !journaled.receipt.authenticates(&journaled.plan) {
        return Err(failure(
            "bind-linux-service-bootstrap-plan",
            EffectCertainty::Ambiguous,
            "journaled command-plan receipt no longer authenticates its canonical plan",
        ));
    }
    journaled
        .journal_authority
        .require_exact_command_plan_artifact(&journaled.plan, &journaled.receipt)?;
    bootstrap.require_exact_plan(
        &journaled.plan,
        &journaled.journal_authority.residual,
        &journaled.journal_authority.journal,
    )?;
    Ok(BootstrappedLinuxProductionCommandPlanV1 {
        journaled,
        bootstrap,
    })
}

/// Consumes the exact child-launch closure authority and retains its one-plan-
/// scoped custody for the mechanics entry point.
///
/// No caller path, delegation expectation, or singleton journal authority can
/// construct the result. This transition performs no cgroup or process effect
/// and remains non-admissible while production bootstrap, setup-capability,
/// and stopped-child proof minting are absent.
pub(crate) fn retain_linux_native_service_mechanics_authority(
    child_authority: LinuxNativeServiceChildLaunchClosureAuthority,
) -> Result<LinuxNativeServiceMechanicsAuthority, CgroupIoFailure> {
    child_authority.validate_retained()?;
    let LinuxNativeServiceChildLaunchClosureAuthority {
        setup_authority,
        child_launch_closure,
    } = child_authority;
    let LinuxNativeServiceSetupDescriptorAuthority {
        bootstrapped,
        service_process_image,
        launch_images,
        setup_descriptors,
        lifetime_lock,
    } = setup_authority;
    let BootstrappedLinuxProductionCommandPlanV1 {
        journaled,
        bootstrap,
    } = bootstrapped;
    let JournaledLinuxProductionCommandPlanV1 {
        plan,
        receipt,
        request,
        journal_authority,
    } = journaled;
    let authority = LinuxNativeServiceMechanicsAuthority {
        plan,
        receipt,
        request,
        journal_authority,
        bootstrap,
        service_process_image,
        launch_images,
        setup_descriptors,
        child_launch_closure,
        lifetime_lock,
    };
    authority.validate_retained()?;
    Ok(authority)
}

#[derive(Debug)]
struct RetainedLeaf {
    directory: Dir,
    identity: CgroupObjectIdentity,
}

/// Concrete descriptor-relative cgroup-v2 host backend.
///
/// Construction fails on non-Linux hosts. On Linux, the backend also retains
/// a genuine-procfs capability and pidfd-backed held-launcher sessions. A
/// restart never reconstructs launcher authority from a numeric PID.
#[derive(Debug)]
pub(crate) struct LinuxCgroupIo {
    service_parent: Dir,
    delegation_name: String,
    delegation: Dir,
    expectation: DelegationRootExpectation,
    journal: CanonicalCgroupJournalStore,
    #[cfg(not(test))]
    mechanics_guard: LinuxNativeServiceRuntimeGuard,
    #[cfg(test)]
    mechanics_guard: Option<LinuxNativeServiceRuntimeGuard>,
    /// The helper image `stage_held_launcher` should run instead of
    /// `/proc/self/exe`, when a test supplies one.
    ///
    /// Exists only under `#[cfg(test)]`, exactly like `mechanics_guard` above.
    /// A production build has no such field and no branch that reads it.
    #[cfg(test)]
    helper_image_override: Option<std::fs::File>,
    leaves: BTreeMap<String, RetainedLeaf>,
    active_probe: Option<DelegationProbeEvidence>,
    /// Fail-closed until a dedicated durable preflight-probe recovery journal
    /// and reconciliation lease are implemented.
    probe_reconciliation_required: bool,
    #[cfg(target_os = "linux")]
    procfs: LinuxProcfs,
    #[cfg(target_os = "linux")]
    held_launchers: HeldLauncherRegistry,
}

impl LinuxCgroupIo {
    /// Consumes one exact post-journal, post-bootstrap retained capability.
    ///
    /// No constructor accepts a caller path, delegation expectation, singleton
    /// journal authority, or bootstrap authority by itself. The capability is
    /// one-plan-scoped and must retain that plan's exact durable receipt. Until
    /// the native service can mint the authenticated bootstrap authority, this
    /// production backend remains deliberately unconstructible.
    #[allow(
        clippy::too_many_lines,
        reason = "one linear constructor audit keeps the post-bootstrap capability and every retained identity check visible"
    )]
    pub(crate) fn open_service_owned(
        mechanics_authority: LinuxNativeServiceMechanicsAuthority,
    ) -> Result<Self, CgroupIoFailure> {
        ensure_linux_host()?;
        mechanics_authority.validate_retained()?;
        let journal_binding = mechanics_authority
            .plan
            .journal_binding()
            .map_err(|error| {
                failure(
                    "bind-linux-service-mechanics-plan",
                    EffectCertainty::NotApplied,
                    error.to_string(),
                )
            })?;
        let expectation = DelegationRootExpectation {
            service_parent_identity: journal_binding.service_parent_identity,
            delegation_identity: journal_binding.delegation_identity,
            owner_uid: journal_binding.owner_uid,
            delegation_mode: journal_binding.delegation_mode,
        };
        let delegation_name = mechanics_authority
            .bootstrap
            .capabilities
            .delegation_name
            .clone();
        validate_component("delegation name", &delegation_name)?;
        let service_parent = mechanics_authority
            .bootstrap
            .capabilities
            .service_parent
            .try_clone()
            .map_err(|error| {
                io_failure(
                    "retain-mechanics-service-parent",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        let delegation = mechanics_authority
            .bootstrap
            .capabilities
            .delegation
            .try_clone()
            .map_err(|error| {
                io_failure(
                    "retain-mechanics-delegation",
                    EffectCertainty::NotApplied,
                    error,
                )
            })?;
        let parent_metadata = service_parent.dir_metadata().map_err(|error| {
            io_failure("inspect-service-cgroup", EffectCertainty::NotApplied, error)
        })?;
        if cgroup_identity(object_identity(&parent_metadata)) != expectation.service_parent_identity
            || !parent_metadata.is_dir()
            || OsMetadataExt::mode(&parent_metadata) & 0o002 != 0
        {
            return Err(failure(
                "validate-service-cgroup",
                EffectCertainty::NotApplied,
                "service parent identity changed, is not a directory, or is world-writable",
            ));
        }
        let metadata = delegation.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-delegation-cgroup",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_delegation_metadata(&metadata, expectation)?;
        require_named_cgroup_identity(
            &service_parent,
            &delegation_name,
            expectation.delegation_identity,
            "delegation-cgroup-identity",
        )?;
        if filesystem_magic(&delegation)? != CGROUP2_SUPER_MAGIC {
            return Err(failure(
                "validate-cgroup2-filesystem",
                EffectCertainty::NotApplied,
                "retained delegation is not on a cgroup-v2 filesystem",
            ));
        }
        let LinuxNativeServiceMechanicsAuthority {
            plan,
            receipt,
            request,
            journal_authority,
            bootstrap,
            service_process_image,
            launch_images,
            setup_descriptors,
            child_launch_closure,
            lifetime_lock,
        } = mechanics_authority;
        let (journal, residual) = journal_authority.into_journal(expectation)?;
        journal.validate_exact_command_plan_artifact(&plan, &receipt)?;
        let mechanics_guard = LinuxNativeServiceRuntimeGuard {
            residual,
            plan,
            receipt,
            request,
            bootstrap,
            service_process_image,
            launch_images,
            setup_descriptors,
            child_launch_closure,
            lifetime_lock,
        };
        mechanics_guard.validate_retained(&journal)?;
        #[cfg(target_os = "linux")]
        let procfs = LinuxProcfs::open_authenticated().map_err(cgroup_launcher_failure)?;
        Ok(Self {
            service_parent,
            delegation_name,
            delegation,
            expectation,
            journal,
            #[cfg(not(test))]
            mechanics_guard,
            #[cfg(test)]
            helper_image_override: None,
            #[cfg(test)]
            mechanics_guard: Some(mechanics_guard),
            leaves: BTreeMap::new(),
            active_probe: None,
            probe_reconciliation_required: false,
            #[cfg(target_os = "linux")]
            procfs,
            #[cfg(target_os = "linux")]
            held_launchers: HeldLauncherRegistry::default(),
        })
    }

    pub(crate) fn read_latest_journal(
        &mut self,
    ) -> Result<Option<DomainJournalRecord>, CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        self.journal.read_latest()
    }

    fn validate_mechanics_guard(&self) -> Result<(), CgroupIoFailure> {
        #[cfg(not(test))]
        {
            self.mechanics_guard.validate_retained(&self.journal)?;
            self.journal.validate_exact_command_plan_artifact(
                &self.mechanics_guard.plan,
                &self.mechanics_guard.receipt,
            )
        }
        #[cfg(test)]
        {
            let Some(guard) = self.mechanics_guard.as_ref() else {
                return Ok(());
            };
            guard.validate_retained(&self.journal)?;
            self.journal
                .validate_exact_command_plan_artifact(&guard.plan, &guard.receipt)
        }
    }

    fn require_exact_mechanics_request(
        &self,
        request: &PrepareDomainRequest,
    ) -> Result<(), CgroupIoFailure> {
        #[cfg(not(test))]
        {
            self.mechanics_guard
                .require_exact_request(request, &self.journal)
        }
        #[cfg(test)]
        {
            self.mechanics_guard.as_ref().map_or(Ok(()), |guard| {
                guard.require_exact_request(request, &self.journal)
            })
        }
    }

    fn validate_delegation(&self) -> Result<(Metadata, Metadata), CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        let parent_metadata = self.service_parent.dir_metadata().map_err(|error| {
            io_failure("inspect-service-cgroup", EffectCertainty::NotApplied, error)
        })?;
        if cgroup_identity(object_identity(&parent_metadata))
            != self.expectation.service_parent_identity
            || !parent_metadata.is_dir()
            || OsMetadataExt::mode(&parent_metadata) & 0o002 != 0
        {
            return Err(failure(
                "validate-service-cgroup",
                EffectCertainty::NotApplied,
                "retained service parent identity changed, is not a directory, or became world-writable",
            ));
        }
        let metadata = self.delegation.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-delegation-cgroup",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        validate_delegation_metadata(&metadata, self.expectation)?;
        require_named_cgroup_identity(
            &self.service_parent,
            &self.delegation_name,
            self.expectation.delegation_identity,
            "delegation-cgroup-identity",
        )?;
        if filesystem_magic(&self.delegation)? != CGROUP2_SUPER_MAGIC {
            return Err(failure(
                "validate-cgroup2-filesystem",
                EffectCertainty::NotApplied,
                "retained delegation filesystem identity changed",
            ));
        }
        Ok((parent_metadata, metadata))
    }

    fn retained_leaf(
        &self,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
    ) -> Result<Dir, CgroupIoFailure> {
        validate_component("cgroup leaf", leaf_name)?;
        let leaf = self.leaves.get(leaf_name).ok_or_else(|| {
            failure(
                "retain-cgroup-leaf",
                EffectCertainty::NotApplied,
                "exact leaf descriptor has not been retained",
            )
        })?;
        if leaf.identity != identity {
            return Err(failure(
                "retain-cgroup-leaf",
                EffectCertainty::NotApplied,
                "requested leaf identity differs from the retained descriptor",
            ));
        }
        let metadata = leaf.directory.dir_metadata().map_err(|error| {
            io_failure(
                "inspect-retained-cgroup-leaf",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if cgroup_identity(object_identity(&metadata)) != identity {
            return Err(failure(
                "inspect-retained-cgroup-leaf",
                EffectCertainty::NotApplied,
                "retained leaf descriptor identity changed",
            ));
        }
        require_named_cgroup_identity(
            &self.delegation,
            leaf_name,
            identity,
            "cgroup-leaf-identity",
        )?;
        leaf.directory.try_clone().map_err(|error| {
            io_failure(
                "clone-retained-cgroup-leaf",
                EffectCertainty::NotApplied,
                error,
            )
        })
    }

    fn ensure_active_probe(&mut self) -> Result<DelegationProbeEvidence, CgroupIoFailure> {
        if let Some(evidence) = &self.active_probe {
            return Ok(evidence.clone());
        }
        let mut effects = LinuxProbeEffects {
            delegation: &self.delegation,
        };
        match drive_durable_probe(&mut self.journal, &mut effects, self.expectation) {
            Ok(evidence) => {
                self.probe_reconciliation_required = false;
                self.active_probe = Some(evidence.clone());
                Ok(evidence)
            }
            Err(error) => {
                self.probe_reconciliation_required = true;
                Err(error)
            }
        }
    }

    fn require_delegation_token(&self, token: &DelegationLockToken) -> Result<(), CgroupIoFailure> {
        // This is the shared precondition for every token-bearing cgroup,
        // launcher, cleanup, and held-release boundary. Keep the complete
        // service authority validation ahead of the journal-token check so a
        // retained token cannot outlive an image, artifact, or lock binding.
        self.validate_mechanics_guard()?;
        self.journal.require_token(token.id())
    }

    /// Creates the fixed helper in a pidfd-directed kernel stop with exactly
    /// the retained leaf's `cgroup.procs` descriptor as fd 2.
    ///
    /// The returned identity is not sufficient authority by itself: all
    /// subsequent operations require the matching retained control session.
    #[cfg(target_os = "linux")]
    pub(crate) fn stage_held_launcher(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launch_request_hash: &str,
    ) -> Result<StagedLauncherIdentity, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        let (cgroup_procs, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
        let cgroup_membership =
            open_control_file(&directory, LeafFile::CgroupProcs.name(), true, false)?;
        let membership_metadata = cgroup_membership.metadata().map_err(|error| {
            io_failure(
                "inspect-launcher-cgroup-membership",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if launcher_identity(cgroup_identity(object_identity(&membership_metadata)))
            != cgroup_procs_identity
        {
            return Err(failure(
                "inspect-launcher-cgroup-membership",
                EffectCertainty::NotApplied,
                "read and write cgroup.procs capabilities differ in object identity",
            ));
        }
        let session_nonce = random_hex(32)?;
        // Tests override the launcher because their executable is not the service
        // runner. Production has no override.
        #[cfg(test)]
        let staged = match self.helper_image_override.take() {
            Some(helper_executable) => self.held_launchers.stage_with_test_helper_image(
                &self.procfs,
                cgroup_procs.into_std(),
                cgroup_membership.into_std(),
                launcher_identity(identity),
                cgroup_procs_identity,
                launch_request_hash,
                session_nonce,
                helper_executable,
            ),
            None => self.held_launchers.stage(
                &self.procfs,
                cgroup_procs.into_std(),
                cgroup_membership.into_std(),
                launcher_identity(identity),
                cgroup_procs_identity,
                launch_request_hash,
                session_nonce,
            ),
        };
        #[cfg(not(test))]
        let staged = self.held_launchers.stage(
            &self.procfs,
            cgroup_procs.into_std(),
            cgroup_membership.into_std(),
            launcher_identity(identity),
            cgroup_procs_identity,
            launch_request_hash,
            session_nonce,
        );
        let (pid, process_start_time_ticks) = staged.map_err(cgroup_launcher_failure)?;
        Ok(StagedLauncherIdentity {
            pid,
            process_start_time_ticks,
            launch_request_hash: launch_request_hash.to_owned(),
            held_before_exec: true,
        })
    }

    /// [`Self::stage_held_launcher`] with an explicit helper image.
    ///
    /// Production `stage` re-executes `/proc/self/exe`, which is correct for a
    /// service whose own image is the launcher. Under `cargo test` that path is
    /// the **test harness** binary, whose `main` never dispatches
    /// `HELD_LAUNCHER_ARGUMENT`, so the helper exits without writing a status
    /// frame and staging fails with "status pipe closed before a complete
    /// frame". That is a property of the test process, not of the launcher.
    ///
    /// Every cgroup mechanic, descriptor proof and identity check below is the
    /// production one; the single varied input is which executable the helper
    /// runs. This is the same seam `HeldLauncherRegistry::stage_with_test_helper_image`
    /// already exists to provide.
    ///
    /// # Errors
    ///
    /// The same set [`Self::stage_held_launcher`] returns.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn stage_held_launcher_with_test_helper_image(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launch_request_hash: &str,
        helper_executable: std::fs::File,
    ) -> Result<StagedLauncherIdentity, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        let (cgroup_procs, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
        let cgroup_membership =
            open_control_file(&directory, LeafFile::CgroupProcs.name(), true, false)?;
        let membership_metadata = cgroup_membership.metadata().map_err(|error| {
            io_failure(
                "inspect-launcher-cgroup-membership",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if launcher_identity(cgroup_identity(object_identity(&membership_metadata)))
            != cgroup_procs_identity
        {
            return Err(failure(
                "inspect-launcher-cgroup-membership",
                EffectCertainty::NotApplied,
                "read and write cgroup.procs capabilities differ in object identity",
            ));
        }
        let session_nonce = random_hex(32)?;
        let (pid, process_start_time_ticks) = self
            .held_launchers
            .stage_with_test_helper_image(
                &self.procfs,
                cgroup_procs.into_std(),
                cgroup_membership.into_std(),
                launcher_identity(identity),
                cgroup_procs_identity,
                launch_request_hash,
                session_nonce,
                helper_executable,
            )
            .map_err(cgroup_launcher_failure)?;
        Ok(StagedLauncherIdentity {
            pid,
            process_start_time_ticks,
            launch_request_hash: launch_request_hash.to_owned(),
            held_before_exec: true,
        })
    }
    /// This service's delegated cgroup root, borrowed.
    ///
    /// A canary suite adopts a leaf by `(delegation, name, identity)` and
    /// nothing else -- `LinuxCanarySuite::run_in_adopted_leaf` takes exactly
    /// those three -- so handing out the delegation descriptor is what lets a
    /// suite be pointed at the **command's own** leaf rather than only at the
    /// probe journal's. It is a borrow, not custody: the caller cannot outlive
    /// this service or close its root.
    #[cfg(target_os = "linux")]
    pub(crate) fn delegation_descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;

        self.delegation.as_fd()
    }

    /// Nonblocking terminal for a released target this service still retains.
    ///
    /// The registry keeps the `Child` and does the waiting; this reports only
    /// the status it saw. A domain that owns this `LinuxCgroupIo` outright can
    /// therefore observe its leader without any raw handle crossing the
    /// boundary -- which is the property ADR-0014 is about, and it is not
    /// spent here.
    ///
    /// # Errors
    ///
    /// When no released session is retained for `pid`, or the session has not
    /// reached an observed same-PID exec.
    #[cfg(target_os = "linux")]
    pub(crate) fn observe_released_leader(
        &mut self,
        pid: u32,
    ) -> Result<Option<std::process::ExitStatus>, CgroupIoFailure> {
        self.held_launchers
            .observe_released(pid)
            .map_err(cgroup_exec_failure)
    }

    /// Blocking-bounded terminal for a released target, valid once the
    /// whole-domain kill has been issued.
    ///
    /// # Errors
    ///
    /// The same set [`Self::observe_released_leader`] returns.
    #[cfg(target_os = "linux")]
    pub(crate) fn reap_released_leader(
        &mut self,
        pid: u32,
        timeout: std::time::Duration,
    ) -> Result<Option<std::process::ExitStatus>, CgroupIoFailure> {
        self.held_launchers
            .reap_released(pid, timeout)
            .map_err(cgroup_exec_failure)
    }
}

impl CgroupIo for LinuxCgroupIo {
    fn acquire_delegation_lock(&mut self) -> Result<DelegationLockToken, CgroupIoFailure> {
        let token = self.journal.acquire_lock()?;
        if let Err(error) = self.validate_delegation() {
            let _ = self.journal.release_lock(token);
            return Err(error);
        }
        Ok(DelegationLockToken::new(token))
    }

    fn release_delegation_lock(
        &mut self,
        token: &DelegationLockToken,
    ) -> Result<(), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        if self.probe_reconciliation_required {
            return Err(failure(
                "release-delegation-lock",
                EffectCertainty::Ambiguous,
                "an active-probe inode may remain; the internal writer flock is retained pending durable probe reconciliation",
            ));
        }
        self.journal.release_lock(token.id())
    }

    fn inspect_delegation(
        &mut self,
        expected_identity: CgroupObjectIdentity,
        expected_owner_uid: u32,
    ) -> Result<DelegationObservation, CgroupIoFailure> {
        self.journal.require_any_token()?;
        if expected_identity != self.expectation.delegation_identity
            || expected_owner_uid != self.expectation.owner_uid
        {
            return Err(failure(
                "inspect-delegation",
                EffectCertainty::NotApplied,
                "request delegation identity or owner differs from retained authority",
            ));
        }
        let (parent_metadata, metadata) = self.validate_delegation()?;
        let negative_probe = self.active_probe.clone().ok_or_else(|| {
            failure(
                "inspect-delegation",
                EffectCertainty::NotApplied,
                "the separately journaled active probe has not completed",
            )
        })?;
        let available_raw =
            read_control_file(&self.delegation, DelegationFile::Controllers.name(), 256)?;
        let enabled_raw =
            read_control_file(&self.delegation, DelegationFile::SubtreeControl.name(), 256)?;
        let available_controllers = parse_controller_set(&available_raw, false)?;
        let enabled_controllers = parse_controller_set(&enabled_raw, true)?;
        let existing_processes = parse_cgroup_procs(&read_control_file(
            &self.delegation,
            DelegationFile::Procs.name(),
            MAX_CGROUP_PROCS_BYTES,
        )?)
        .map_err(|error| {
            failure(
                "parse-delegation-procs",
                EffectCertainty::NotApplied,
                error.to_string(),
            )
        })?;
        let existing_children = enumerate_child_cgroups(&self.delegation)?;
        let mut required_files = BTreeSet::new();
        for file in REQUIRED_DELEGATION_FILES {
            validate_control_entry(&self.delegation, file)?;
            required_files.insert(file.to_owned());
        }
        Ok(DelegationObservation {
            filesystem_magic: filesystem_magic(&self.delegation)?,
            identity: cgroup_identity(object_identity(&metadata)),
            expected_identity: self.expectation.delegation_identity,
            owner_uid: OsMetadataExt::uid(&metadata),
            expected_owner_uid: self.expectation.owner_uid,
            mode: OsMetadataExt::mode(&metadata) & 0o777,
            named_entry_matches_descriptor: true,
            descendant_of_authenticated_service: cgroup_identity(object_identity(&parent_metadata))
                == self.expectation.service_parent_identity,
            world_writable_ancestor: OsMetadataExt::mode(&parent_metadata) & 0o002 != 0,
            available_controllers,
            enabled_controllers,
            existing_processes,
            existing_children,
            required_files,
            negative_probe,
        })
    }

    fn run_delegation_probe(
        &mut self,
        token: &DelegationLockToken,
    ) -> Result<DelegationProbeEvidence, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        self.ensure_active_probe()
    }

    fn require_fresh_domain_episode(
        &mut self,
        token: &DelegationLockToken,
        request: &PrepareDomainRequest,
    ) -> Result<(), CgroupIoFailure> {
        self.require_exact_mechanics_request(request)?;
        self.journal.require_fresh_episode(token.id(), request)
    }

    fn enable_required_subtree_controllers(
        &mut self,
        token: &DelegationLockToken,
        exact_value: &[u8],
    ) -> Result<(), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        if exact_value != b"+memory +pids\n" {
            return Err(failure(
                "enable-subtree-controllers",
                EffectCertainty::NotApplied,
                "only the exact memory+pids controller write is permitted",
            ));
        }
        self.validate_delegation()?;
        write_control_file(
            &self.delegation,
            DelegationFile::SubtreeControl.name(),
            exact_value,
        )
    }

    fn read_enabled_subtree_controllers(
        &mut self,
        token: &DelegationLockToken,
        max_bytes: usize,
    ) -> Result<Vec<u8>, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        self.validate_delegation()?;
        read_control_file(
            &self.delegation,
            DelegationFile::SubtreeControl.name(),
            max_bytes,
        )
    }

    fn unpredictable_leaf_nonce(&mut self) -> Result<String, CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        random_hex(32)
    }

    fn create_leaf_no_replace(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
    ) -> Result<NewLeafObservation, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        self.validate_delegation()?;
        validate_component("cgroup leaf", leaf_name)?;
        self.delegation.create_dir(leaf_name).map_err(|error| {
            io_failure("create-cgroup-leaf", EffectCertainty::NotApplied, error)
        })?;
        let directory = self
            .delegation
            .open_dir_nofollow(leaf_name)
            .map_err(|error| {
                io_failure(
                    "open-created-cgroup-leaf",
                    EffectCertainty::Ambiguous,
                    error,
                )
            })?;
        let observation = observe_leaf(
            &self.delegation,
            leaf_name,
            &directory,
            MAX_CGROUP_EVENTS_BYTES,
            MAX_CGROUP_PROCS_BYTES,
        )?;
        self.leaves.insert(
            leaf_name.to_owned(),
            RetainedLeaf {
                directory,
                identity: observation.identity,
            },
        );
        Ok(observation)
    }

    fn inspect_leaf(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        max_events_bytes: usize,
        max_procs_bytes: usize,
    ) -> Result<Option<NewLeafObservation>, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        self.validate_delegation()?;
        validate_component("cgroup leaf", leaf_name)?;
        match self.delegation.symlink_metadata(leaf_name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.leaves.remove(leaf_name);
                Ok(None)
            }
            Err(error) => Err(io_failure(
                "inspect-cgroup-leaf",
                EffectCertainty::NotApplied,
                error,
            )),
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(failure(
                        "inspect-cgroup-leaf",
                        EffectCertainty::NotApplied,
                        "named cgroup leaf is not a no-follow directory",
                    ));
                }
                let directory = self
                    .delegation
                    .open_dir_nofollow(leaf_name)
                    .map_err(|error| {
                        io_failure("open-cgroup-leaf", EffectCertainty::NotApplied, error)
                    })?;
                let observation = observe_leaf(
                    &self.delegation,
                    leaf_name,
                    &directory,
                    max_events_bytes,
                    max_procs_bytes,
                )?;
                self.leaves.insert(
                    leaf_name.to_owned(),
                    RetainedLeaf {
                        directory,
                        identity: observation.identity,
                    },
                );
                Ok(Some(observation))
            }
        }
    }

    fn write_leaf_file(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        file: LeafWriteFile,
        exact_value: &[u8],
    ) -> Result<(), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        write_control_file(&directory, file.name(), exact_value)
    }

    fn self_attach_held_launcher(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        exact_self_value: &[u8],
    ) -> Result<(), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        #[cfg(target_os = "linux")]
        {
            let directory = self.retained_leaf(leaf_name, identity)?;
            let (_, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
            self.held_launchers
                .self_attach(
                    &self.procfs,
                    launcher_expectation(launcher, identity, cgroup_procs_identity),
                    exact_self_value,
                )
                .map_err(cgroup_launcher_failure)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (leaf_name, identity, launcher, exact_self_value);
            Err(failure(
                "self-attach-held-launcher",
                EffectCertainty::NotApplied,
                "pidfd held-launcher attachment is available only on Linux",
            ))
        }
    }

    fn read_leaf_file(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        file: LeafFile,
        max_bytes: usize,
    ) -> Result<Vec<u8>, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        read_control_file(&directory, file.name(), max_bytes)
    }

    fn inspect_staged_launcher(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        max_procs_bytes: usize,
    ) -> Result<StagedLauncherObservation, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        #[cfg(target_os = "linux")]
        {
            let directory = self.retained_leaf(leaf_name, identity)?;
            let (_, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
            let held_before_read = self
                .held_launchers
                .inspect_held(
                    &self.procfs,
                    launcher_expectation(launcher, identity, cgroup_procs_identity),
                )
                .map_err(cgroup_launcher_failure)?;
            let cgroup_procs =
                read_control_file(&directory, LeafFile::CgroupProcs.name(), max_procs_bytes)?;
            let held_after_read = self
                .held_launchers
                .inspect_held(
                    &self.procfs,
                    launcher_expectation(launcher, identity, cgroup_procs_identity),
                )
                .map_err(cgroup_launcher_failure)?;
            if !held_before_read || !held_after_read {
                return Err(failure(
                    "inspect-staged-launcher",
                    EffectCertainty::NotApplied,
                    "kernel hold was not continuously proven around membership readback",
                ));
            }
            Ok(StagedLauncherObservation {
                pid: launcher.pid,
                process_start_time_ticks: launcher.process_start_time_ticks,
                held_before_exec: true,
                cgroup_procs,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (leaf_name, identity, launcher, max_procs_bytes);
            Err(failure(
                "inspect-staged-launcher",
                EffectCertainty::NotApplied,
                "pidfd held-launcher inspection is available only on Linux",
            ))
        }
    }

    fn inspect_staged_launcher_recovery_state(
        &mut self,
        launcher: &StagedLauncherIdentity,
    ) -> Result<StagedLauncherRecoveryState, CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        #[cfg(target_os = "linux")]
        {
            if let Some(held) = self
                .held_launchers
                .retained_state(
                    &self.procfs,
                    launcher.pid,
                    launcher.process_start_time_ticks,
                    &launcher.launch_request_hash,
                )
                .map_err(cgroup_launcher_failure)?
            {
                return Ok(if held {
                    StagedLauncherRecoveryState::HeldBeforeExec
                } else {
                    StagedLauncherRecoveryState::ReleasedOrUnknown
                });
            }
            Ok(
                match self
                    .procfs
                    .recovery_observation(launcher.pid, launcher.process_start_time_ticks)
                    .map_err(cgroup_launcher_failure)?
                {
                    ProcessRecoveryObservation::Absent => StagedLauncherRecoveryState::Absent,
                    ProcessRecoveryObservation::ExactLive
                    | ProcessRecoveryObservation::PidReused => {
                        // A PID/start-time observation after process restart is
                        // never upgraded into control authority without the
                        // original pidfd and pipes.
                        StagedLauncherRecoveryState::ReleasedOrUnknown
                    }
                },
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = launcher;
            Err(failure(
                "inspect-staged-launcher-recovery",
                EffectCertainty::NotApplied,
                "pidfd held-launcher recovery inspection is available only on Linux",
            ))
        }
    }

    fn persist_journal(&mut self, record: &DomainJournalRecord) -> Result<(), CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        self.journal.persist(record)
    }

    fn sync_journal(&mut self) -> Result<(), CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        self.journal.sync()
    }

    fn poll_barrier(&mut self) -> Result<(), CgroupIoFailure> {
        self.validate_mechanics_guard()?;
        std::thread::yield_now();
        std::thread::sleep(CLEANUP_POLL_BARRIER);
        Ok(())
    }

    fn remove_leaf_exact(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
    ) -> Result<(), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let retained = self.retained_leaf(leaf_name, identity)?;
        remove_named_directory_exact(
            &self.delegation,
            leaf_name,
            &retained,
            identity,
            "remove-cgroup-leaf",
        )?;
        self.leaves.remove(leaf_name);
        Ok(())
    }

    fn prove_leaf_absent(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
    ) -> Result<bool, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        validate_component("cgroup leaf", leaf_name)?;
        match self.delegation.symlink_metadata(leaf_name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Ok(_) => Ok(false),
            Err(error) => Err(io_failure(
                "prove-cgroup-leaf-absent",
                EffectCertainty::NotApplied,
                error,
            )),
        }
    }
}

#[cfg(target_os = "linux")]
impl HeldReleaseIo for LinuxCgroupIo {
    type ReleaseRequest = HeldExecRequest;
    type PlannedRelease = PlannedHeldExec;
    type PreparedRelease = PreparedHeldExec;

    fn plan_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        request: Self::ReleaseRequest,
    ) -> Result<(Self::PlannedRelease, HeldExecReleaseBinding), CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        let (_, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
        let plan = self
            .held_launchers
            .plan_inert_target(
                &self.procfs,
                launcher_expectation(launcher, identity, cgroup_procs_identity),
                request,
            )
            .map_err(cgroup_exec_failure)?;
        let binding = plan.durable_binding();
        binding.validate().map_err(|detail| {
            failure(
                "validate-held-release-binding",
                EffectCertainty::NotApplied,
                detail,
            )
        })?;
        Ok((plan, binding))
    }

    fn prepare_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        plan: Self::PlannedRelease,
    ) -> Result<Self::PreparedRelease, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        let (_, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
        self.held_launchers
            .prepare_planned_inert_target(
                &self.procfs,
                launcher_expectation(launcher, identity, cgroup_procs_identity),
                plan,
            )
            .map_err(cgroup_exec_failure)
    }

    fn commit_held_release(
        &mut self,
        token: &DelegationLockToken,
        leaf_name: &str,
        identity: CgroupObjectIdentity,
        launcher: &StagedLauncherIdentity,
        prepared: Self::PreparedRelease,
    ) -> Result<HeldExecObservation, CgroupIoFailure> {
        self.require_delegation_token(token)?;
        let directory = self.retained_leaf(leaf_name, identity)?;
        let (_, cgroup_procs_identity) = open_launcher_cgroup_procs(&directory)?;
        self.held_launchers
            .commit_prepared_inert_target(
                &self.procfs,
                launcher_expectation(launcher, identity, cgroup_procs_identity),
                prepared,
            )
            .map_err(cgroup_exec_failure)
    }
}

fn validate_delegation_metadata(
    metadata: &Metadata,
    expectation: DelegationRootExpectation,
) -> Result<(), CgroupIoFailure> {
    if !metadata.is_dir()
        || cgroup_identity(object_identity(metadata)) != expectation.delegation_identity
        || OsMetadataExt::uid(metadata) != expectation.owner_uid
        || expectation.delegation_mode & !0o7777 != 0
        || OsMetadataExt::mode(metadata) & 0o7777 != expectation.delegation_mode
        || expectation.delegation_mode & 0o002 != 0
    {
        return Err(failure(
            "validate-delegation-cgroup",
            EffectCertainty::NotApplied,
            "delegation identity, owner, directory type, or mode is invalid",
        ));
    }
    Ok(())
}

fn require_named_cgroup_identity(
    parent: &Dir,
    name: &str,
    expected: CgroupObjectIdentity,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || cgroup_identity(object_identity(&metadata)) != expected
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "named cgroup directory differs from the retained descriptor",
        ));
    }
    Ok(())
}

fn remove_named_directory_exact(
    parent: &Dir,
    name: &str,
    retained: &Dir,
    expected: CgroupObjectIdentity,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    validate_component("cgroup directory", name)?;
    let retained_metadata = retained
        .dir_metadata()
        .map_err(|error| io_failure(operation, EffectCertainty::NotApplied, error))?;
    if !retained_metadata.is_dir()
        || cgroup_identity(object_identity(&retained_metadata)) != expected
    {
        return Err(failure(
            operation,
            EffectCertainty::NotApplied,
            "retained cgroup directory identity changed before removal",
        ));
    }
    require_named_cgroup_identity(parent, name, expected, operation)?;
    parent
        .remove_dir(name)
        .map_err(|error| io_failure(operation, EffectCertainty::Ambiguous, error))
}

fn remove_and_prove_named_directory_exact(
    parent: &Dir,
    name: &str,
    retained: &Dir,
    expected: CgroupObjectIdentity,
    operation: &'static str,
) -> Result<(), CgroupIoFailure> {
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Ok(_) => {}
        Err(error) => {
            return Err(io_failure(operation, EffectCertainty::Ambiguous, error));
        }
    }
    remove_named_directory_exact(parent, name, retained, expected, operation).map_err(|error| {
        failure(
            operation,
            EffectCertainty::Ambiguous,
            format!(
                "exact removal failed at {} ({:?}): {}",
                error.operation, error.certainty, error.detail
            ),
        )
    })?;
    match parent.symlink_metadata(name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(failure(
            operation,
            EffectCertainty::Ambiguous,
            "removed cgroup name remained present or was recreated",
        )),
        Err(error) => Err(io_failure(operation, EffectCertainty::Ambiguous, error)),
    }
}

fn observe_leaf(
    parent: &Dir,
    leaf_name: &str,
    directory: &Dir,
    max_events_bytes: usize,
    max_procs_bytes: usize,
) -> Result<NewLeafObservation, CgroupIoFailure> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| io_failure("inspect-cgroup-leaf", EffectCertainty::NotApplied, error))?;
    let identity = cgroup_identity(object_identity(&metadata));
    require_named_cgroup_identity(parent, leaf_name, identity, "cgroup-leaf-identity")?;
    Ok(NewLeafObservation {
        identity,
        owner_uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o777,
        named_entry_matches_descriptor: true,
        initial_events: read_control_file(
            directory,
            LeafFile::CgroupEvents.name(),
            max_events_bytes,
        )?,
        initial_procs: read_control_file(directory, LeafFile::CgroupProcs.name(), max_procs_bytes)?,
    })
}

fn validate_control_entry(directory: &Dir, name: &str) -> Result<(), CgroupIoFailure> {
    validate_component("cgroup control file", name)?;
    let metadata = directory.symlink_metadata(name).map_err(|error| {
        io_failure("inspect-cgroup-control", EffectCertainty::NotApplied, error)
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(failure(
            "inspect-cgroup-control",
            EffectCertainty::NotApplied,
            "cgroup control entry is not a no-follow regular file",
        ));
    }
    Ok(())
}

fn open_control_file(
    directory: &Dir,
    name: &str,
    read: bool,
    write: bool,
) -> Result<File, CgroupIoFailure> {
    validate_control_entry(directory, name)?;
    let mut options = OpenOptions::new();
    options.read(read).write(write).follow(FollowSymlinks::No);
    let file = directory
        .open_with(name, &options)
        .map_err(|error| io_failure("open-cgroup-control", EffectCertainty::NotApplied, error))?;
    let opened = file.metadata().map_err(|error| {
        io_failure(
            "inspect-open-cgroup-control",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let named = directory.symlink_metadata(name).map_err(|error| {
        io_failure(
            "inspect-named-cgroup-control",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    if object_identity(&opened) != object_identity(&named) || named.file_type().is_symlink() {
        return Err(failure(
            "cgroup-control-identity",
            EffectCertainty::NotApplied,
            "opened control file differs from its no-follow named entry",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_launcher_cgroup_procs(
    directory: &Dir,
) -> Result<(File, LauncherDescriptorIdentity), CgroupIoFailure> {
    let file = open_control_file(directory, LeafFile::CgroupProcs.name(), false, true)?;
    let metadata = file.metadata().map_err(|error| {
        io_failure(
            "inspect-launcher-cgroup-procs",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let identity = object_identity(&metadata);
    if identity.device == 0 || identity.inode == 0 {
        return Err(failure(
            "inspect-launcher-cgroup-procs",
            EffectCertainty::NotApplied,
            "retained cgroup.procs descriptor has a zero object identity",
        ));
    }
    Ok((
        file,
        LauncherDescriptorIdentity {
            device: identity.device,
            inode: identity.inode,
        },
    ))
}

#[cfg(target_os = "linux")]
const fn launcher_identity(identity: CgroupObjectIdentity) -> LauncherDescriptorIdentity {
    LauncherDescriptorIdentity {
        device: identity.device,
        inode: identity.inode,
    }
}

#[cfg(target_os = "linux")]
fn launcher_expectation(
    launcher: &StagedLauncherIdentity,
    leaf_identity: CgroupObjectIdentity,
    cgroup_procs_identity: LauncherDescriptorIdentity,
) -> HeldLauncherExpectation<'_> {
    HeldLauncherExpectation {
        pid: launcher.pid,
        process_start_time_ticks: launcher.process_start_time_ticks,
        launch_request_hash: &launcher.launch_request_hash,
        leaf_identity: launcher_identity(leaf_identity),
        cgroup_procs_identity,
    }
}

#[cfg(target_os = "linux")]
fn cgroup_launcher_failure(error: HeldLauncherFailure) -> CgroupIoFailure {
    CgroupIoFailure {
        operation: error.operation,
        certainty: match error.certainty {
            HeldLauncherEffectCertainty::NotApplied => EffectCertainty::NotApplied,
            HeldLauncherEffectCertainty::Ambiguous => EffectCertainty::Ambiguous,
        },
        detail: error.detail,
    }
}

#[cfg(target_os = "linux")]
fn cgroup_exec_failure(error: HeldExecFailure) -> CgroupIoFailure {
    CgroupIoFailure {
        operation: error.operation,
        certainty: match error.certainty {
            HeldExecCertainty::NotReleased | HeldExecCertainty::PreparedAndHeld => {
                EffectCertainty::NotApplied
            }
            HeldExecCertainty::ExecFailedBeforeTarget => EffectCertainty::Applied,
            HeldExecCertainty::ReleasedOrUnknown => EffectCertainty::Ambiguous,
        },
        detail: error.detail,
    }
}

fn read_control_file(
    directory: &Dir,
    name: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, CgroupIoFailure> {
    let file = open_control_file(directory, name, true, false)?;
    read_bounded(file, max_bytes, "read-cgroup-control")
}

fn write_control_file(
    directory: &Dir,
    name: &str,
    exact_value: &[u8],
) -> Result<(), CgroupIoFailure> {
    if exact_value.is_empty()
        || exact_value.len() > MAX_CONTROL_WRITE_BYTES
        || !exact_value.ends_with(b"\n")
        || exact_value[..exact_value.len() - 1]
            .iter()
            .any(|byte| *byte == 0 || *byte == b'\n' || *byte == b'\r')
    {
        return Err(failure(
            "write-cgroup-control",
            EffectCertainty::NotApplied,
            "control write must be one bounded NUL-free newline-terminated value",
        ));
    }
    let mut file = open_control_file(directory, name, false, true)?;
    let written = file
        .write(exact_value)
        .map_err(|error| io_failure("write-cgroup-control", EffectCertainty::Ambiguous, error))?;
    if written != exact_value.len() {
        return Err(failure(
            "write-cgroup-control",
            EffectCertainty::Ambiguous,
            "kernel accepted only a partial control-file write",
        ));
    }
    Ok(())
}

fn enumerate_child_cgroups(directory: &Dir) -> Result<Vec<String>, CgroupIoFailure> {
    let entries = directory.entries().map_err(|error| {
        io_failure(
            "enumerate-cgroup-children",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    let mut children = Vec::new();
    let mut observed = 0usize;
    for entry in entries {
        let entry = entry.map_err(|error| {
            io_failure(
                "enumerate-cgroup-children",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        observed = observed.checked_add(1).ok_or_else(|| {
            failure(
                "enumerate-cgroup-children",
                EffectCertainty::NotApplied,
                "cgroup entry count overflowed",
            )
        })?;
        if observed > MAX_DELEGATION_SCAN_ENTRIES {
            return Err(failure(
                "enumerate-cgroup-children",
                EffectCertainty::NotApplied,
                "cgroup entry scan exceeded its hard bound",
            ));
        }
        let file_type = entry.file_type().map_err(|error| {
            io_failure(
                "inspect-cgroup-child-type",
                EffectCertainty::NotApplied,
                error,
            )
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|_| {
            failure(
                "enumerate-cgroup-children",
                EffectCertainty::NotApplied,
                "cgroup child name is not UTF-8",
            )
        })?;
        validate_component("cgroup child", &name)?;
        children.push(name);
    }
    children.sort();
    Ok(children)
}

fn parse_controller_set(
    bytes: &[u8],
    reject_unmodeled: bool,
) -> Result<BTreeSet<DomainController>, CgroupIoFailure> {
    if bytes.len() > 256 || !bytes.ends_with(b"\n") {
        return Err(failure(
            "parse-cgroup-controllers",
            EffectCertainty::NotApplied,
            "controller list is oversized or not newline-terminated",
        ));
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|error| {
        io_failure(
            "parse-cgroup-controllers",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    if text.contains("  ")
        || text.starts_with(' ')
        || text.ends_with(' ')
        || !text.bytes().all(|byte| {
            byte == b' ' || byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
        })
    {
        return Err(failure(
            "parse-cgroup-controllers",
            EffectCertainty::NotApplied,
            "controller list has noncanonical whitespace or token bytes",
        ));
    }
    let mut controllers = BTreeSet::new();
    let mut seen_tokens = BTreeSet::new();
    for token in text.split(' ').filter(|token| !token.is_empty()) {
        let mut token_bytes = token.bytes();
        if token_bytes
            .next()
            .is_none_or(|byte| !byte.is_ascii_lowercase())
            || token_bytes
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'_')
        {
            return Err(failure(
                "parse-cgroup-controllers",
                EffectCertainty::NotApplied,
                format!("noncanonical controller token: {token}"),
            ));
        }
        if !seen_tokens.insert(token) {
            return Err(failure(
                "parse-cgroup-controllers",
                EffectCertainty::NotApplied,
                format!("duplicate controller: {token}"),
            ));
        }
        match token {
            "memory" => {
                controllers.insert(DomainController::Memory);
            }
            "pids" => {
                controllers.insert(DomainController::Pids);
            }
            _ if reject_unmodeled => {
                return Err(failure(
                    "parse-cgroup-controllers",
                    EffectCertainty::NotApplied,
                    format!("unmodeled enabled controller: {token}"),
                ));
            }
            _ => {}
        }
    }
    Ok(controllers)
}

fn persist_probe_transition(
    journal: &mut CanonicalCgroupJournalStore,
    record: &ProbeJournalRecord,
) -> Result<(), CgroupIoFailure> {
    journal.persist_probe(record)?;
    journal.sync()
}

fn new_probe_intent(
    expectation: DelegationRootExpectation,
    episode_kind: ProbeEpisodeKind,
) -> Result<ProbeJournalRecord, CgroupIoFailure> {
    Ok(ProbeJournalRecord {
        state: ProbeJournalState::CreateIntended,
        episode_kind,
        probe_name: format!(".gb-probe-{}", random_hex(16)?),
        expected_delegation_identity: expectation.delegation_identity,
        expected_owner_uid: expectation.owner_uid,
        observed_identity: None,
        identity_authoritative: false,
        initial_shape: None,
        configured_and_read_back: false,
        stable_empty_proven: false,
        canary: None,
    })
}

fn open_named_probe(
    delegation: &Dir,
    record: &ProbeJournalRecord,
) -> Result<Option<(Dir, CgroupObjectIdentity)>, CgroupIoFailure> {
    match delegation.symlink_metadata(&record.probe_name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io_failure(
                "inspect-preflight-probe",
                EffectCertainty::Ambiguous,
                error,
            ));
        }
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(failure(
                "inspect-preflight-probe",
                EffectCertainty::Ambiguous,
                "durable probe name is not a no-follow directory",
            ));
        }
        Ok(_) => {}
    }
    let directory = delegation
        .open_dir_nofollow(&record.probe_name)
        .map_err(|error| io_failure("open-preflight-probe", EffectCertainty::Ambiguous, error))?;
    let metadata = directory.dir_metadata().map_err(|error| {
        io_failure("inspect-preflight-probe", EffectCertainty::Ambiguous, error)
    })?;
    let identity = cgroup_identity(object_identity(&metadata));
    require_named_cgroup_identity(
        delegation,
        &record.probe_name,
        identity,
        "preflight-probe-identity",
    )?;
    if identity.device != record.expected_delegation_identity.device {
        return Err(failure(
            "preflight-probe-filesystem",
            EffectCertainty::Ambiguous,
            "probe directory is not on the retained delegation device",
        ));
    }
    Ok(Some((directory, identity)))
}

fn open_exact_probe(
    delegation: &Dir,
    record: &ProbeJournalRecord,
) -> Result<Option<Dir>, CgroupIoFailure> {
    let Some(expected) = record.observed_identity else {
        return Err(failure(
            "open-exact-preflight-probe",
            EffectCertainty::NotApplied,
            "probe journal has no authoritative identity",
        ));
    };
    match open_named_probe(delegation, record)? {
        None => Ok(None),
        Some((directory, identity)) if identity == expected => Ok(Some(directory)),
        Some(_) => Err(failure(
            "preflight-probe-identity-substitution",
            EffectCertainty::Ambiguous,
            "durable probe name no longer denotes the authoritative identity",
        )),
    }
}

fn observe_probe_shape(directory: &Dir) -> Result<ProbeDefaultShape, CgroupIoFailure> {
    for file in REQUIRED_DELEGATION_FILES {
        if file != DelegationFile::SubtreeControl.name() {
            validate_control_entry(directory, file)?;
        }
    }
    let metadata = directory.dir_metadata().map_err(|error| {
        io_failure(
            "inspect-preflight-probe-shape",
            EffectCertainty::NotApplied,
            error,
        )
    })?;
    Ok(ProbeDefaultShape {
        owner_uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o7777,
        events: read_control_file(directory, LeafFile::CgroupEvents.name(), 256)?,
        procs: read_control_file(directory, LeafFile::CgroupProcs.name(), 256)?,
        pids_max: read_control_file(directory, LeafFile::PidsMax.name(), 64)?,
        memory_max: read_control_file(directory, LeafFile::MemoryMax.name(), 64)?,
        memory_swap_max: read_control_file(directory, LeafFile::MemorySwapMax.name(), 64)?,
        memory_oom_group: read_control_file(directory, LeafFile::MemoryOomGroup.name(), 64)?,
        children: enumerate_child_cgroups(directory)?,
    })
}

fn validate_strict_probe_default_shape(
    shape: &ProbeDefaultShape,
    expectation: DelegationRootExpectation,
) -> Result<(), CgroupIoFailure> {
    shape.validate_bounded()?;
    let events = parse_cgroup_events(&shape.events).map_err(|error| {
        failure(
            "validate-preflight-probe-defaults",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    let procs = parse_cgroup_procs(&shape.procs).map_err(|error| {
        failure(
            "validate-preflight-probe-defaults",
            EffectCertainty::NotApplied,
            error.to_string(),
        )
    })?;
    if shape.owner_uid != expectation.owner_uid
        || shape.mode != expectation.delegation_mode
        || events.populated
        || !procs.is_empty()
        || !shape.children.is_empty()
        || shape.pids_max != b"max\n"
        || shape.memory_max != b"max\n"
        || shape.memory_swap_max != b"max\n"
        || shape.memory_oom_group != b"0\n"
    {
        return Err(failure(
            "validate-preflight-probe-defaults",
            EffectCertainty::NotApplied,
            "probe candidate is not an empty owner-bound default-shape cgroup",
        ));
    }
    Ok(())
}

fn persist_probe_removed(
    journal: &mut CanonicalCgroupJournalStore,
    record: &mut ProbeJournalRecord,
) -> Result<(), CgroupIoFailure> {
    record.state = ProbeJournalState::Removed;
    persist_probe_transition(journal, record)
}

fn configure_probe(directory: &Dir) -> Result<(), CgroupIoFailure> {
    for (file, value) in [
        (LeafWriteFile::PidsMax, b"1\n".as_slice()),
        (LeafWriteFile::MemoryMax, b"max\n".as_slice()),
        (LeafWriteFile::MemorySwapMax, b"max\n".as_slice()),
        (LeafWriteFile::MemoryOomGroup, b"1\n".as_slice()),
    ] {
        write_control_file(directory, file.name(), value)?;
        if read_control_file(directory, file.name(), 64)? != value {
            return Err(failure(
                "preflight-probe-configure-readback",
                EffectCertainty::Ambiguous,
                format!("{} did not read back exactly", file.name()),
            ));
        }
    }
    Ok(())
}

fn kill_and_prove_probe_empty(directory: &Dir) -> Result<(), CgroupIoFailure> {
    write_control_file(directory, LeafWriteFile::CgroupKill.name(), b"1\n")?;
    let events = read_control_file(directory, LeafFile::CgroupEvents.name(), 256)?;
    let first = read_control_file(directory, LeafFile::CgroupProcs.name(), 256)?;
    std::thread::yield_now();
    let second = read_control_file(directory, LeafFile::CgroupProcs.name(), 256)?;
    let populated = parse_cgroup_events(&events)
        .map_err(|error| {
            failure(
                "preflight-probe-empty",
                EffectCertainty::Ambiguous,
                error.to_string(),
            )
        })?
        .populated;
    let first = parse_cgroup_procs(&first).map_err(|error| {
        failure(
            "preflight-probe-empty",
            EffectCertainty::Ambiguous,
            error.to_string(),
        )
    })?;
    let second = parse_cgroup_procs(&second).map_err(|error| {
        failure(
            "preflight-probe-empty",
            EffectCertainty::Ambiguous,
            error.to_string(),
        )
    })?;
    if populated || !first.is_empty() || !second.is_empty() {
        return Err(failure(
            "preflight-probe-empty",
            EffectCertainty::Ambiguous,
            "probe did not reach two stable empty process observations",
        ));
    }
    Ok(())
}

trait DurableProbeEffects {
    /// Which kind of episode this effects implementation drives.
    ///
    /// The default is the delegation default-shape probe, which is what every
    /// caller before the canary episode existed drives, so no existing caller
    /// changes meaning by omission.
    fn episode_kind(&self) -> ProbeEpisodeKind {
        ProbeEpisodeKind::DelegationDefaultShape
    }

    /// Runs the live control suite inside this episode's configured leaf.
    ///
    /// Called exactly once per canary episode, in the `Configured` state,
    /// with the durable record whose `observed_identity` is the leaf every
    /// probe must run under. Returning `None` means the suite established
    /// nothing, and the episode is then journaled with no claim rather than
    /// with an empty one.
    ///
    /// The default runs nothing, so a delegation probe cannot acquire a
    /// control claim by inheriting this method.
    fn run_canary_suite(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<Option<CanaryEpisodeEvidenceV1>, CgroupIoFailure> {
        let _ = record;
        Ok(None)
    }

    fn observe_identity(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<Option<CgroupObjectIdentity>, CgroupIoFailure>;
    fn observe_shape(
        &mut self,
        record: &ProbeJournalRecord,
        identity: CgroupObjectIdentity,
    ) -> Result<Option<ProbeDefaultShape>, CgroupIoFailure>;
    fn create_no_replace(&mut self, name: &str) -> Result<(), CgroupIoFailure>;
    fn configure_exact(&mut self, record: &ProbeJournalRecord) -> Result<bool, CgroupIoFailure>;
    fn kill_and_prove_empty(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<bool, CgroupIoFailure>;
    fn remove_exact_and_prove(
        &mut self,
        record: &ProbeJournalRecord,
    ) -> Result<(), CgroupIoFailure>;
}

struct LinuxProbeEffects<'a> {
    delegation: &'a Dir,
}
