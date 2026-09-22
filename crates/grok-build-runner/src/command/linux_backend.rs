use super::contained_boundary::{
    BackendCanaryStatus, BackendControl, BackendIdentity, BackendPreflightReport,
    BackendTermination, ContainedCommandBackend, ContainedDescendantDomain, DomainObservation,
    DomainTerminationRequest, DurablyAnchoredCapture, PreparedContainedCommand,
    ValidatedBackendPermit, required_controls,
};
#[allow(
    clippy::wildcard_imports,
    reason = "the nested Linux backend intentionally shares only this parent module's private audited primitives"
)]
use super::*;
use cap_std::{ambient_authority, fs::Dir};

use crate::linux_cgroup_io::{
    LinuxCanarySuite as _, LinuxCgroupIo, LinuxRetainedPerCommandDirectories,
    create_per_command_retained_directories, seal_contained_command_target,
};
use crate::linux_command_plan::{LinuxAuditArchitectureV1, LinuxMandatoryControlArtefactsV1};
use crate::linux_containment::{
    CgroupError, CgroupIoFailure, DomainJournalState, LinuxHeldChildReleaseAuthorization,
    MAX_CLEANUP_ATTEMPTS, PrepareDomainOutcome, PreparedDomain, attach_staged_launcher,
    cleanup_domain, observe_domain_unpopulated, reinstall_committed_leaf_limits,
    release_attached_inert_target, terminate_domain,
};
use crate::linux_dev_domain::{
    CanaryExit, CanarySpecification, LINUX_CANARY_HELPER_ARGUMENT, LINUX_DELEGATION_ROOT_VARIABLE,
    LINUX_SECCOMP_NETWORK_ERRNO, LinuxCanaryReportV1, LinuxCanaryRoleV1, LinuxCanaryRunObservation,
    LinuxContainmentEvidence, LinuxContainmentPolicy, LinuxDelegatedCanaryDomain,
    LinuxDevDomainError, LinuxDomainKillObservation, canary_image_source,
    delegation_root_from_environment, linux_runtime_read_roots, linux_runtime_write_surfaces,
    named_self_image, payload_byte, sealed_self_image,
};
use crate::linux_held_launcher::{
    AuthenticatedReleaseDescriptor, DescriptorIdentity as LauncherDescriptorIdentity,
    HeldExecRequest,
};

/// Immutable identifier of the production backend generation.
pub(crate) const LINUX_CGROUP_V2_BACKEND_ID: &str = "linux-cgroup-v2-v1";

const LINUX_CGROUP_V2_IMPLEMENTATION_DOMAIN: &[u8] = b"grok-build/linux-cgroup-v2-backend/v1";

/// Exact reason the production arm cannot authorize a contained launch.
///
/// The authenticated native service mints a durable command plan, a
/// bootstrap authority, an admission authority, a launch-image selection,
/// setup descriptors, and a child-launch closure before
/// `LinuxCgroupIo::open_service_owned` will hand over any mechanics
/// authority. No repository-owned installer supplies that handoff, so the
/// production arm holds no delegated cgroup, no sealed launch image, and no
/// journal receipt, and therefore enforces nothing.
pub(crate) const LINUX_CGROUP_V2_SERVICE_UNAVAILABLE: &str = "the Linux native command service is not installed; this backend holds no delegated cgroup-v2 domain, no journaled command plan, and no admitted launch image, and therefore enforces none of the mandatory contained-execution controls";

/// Exact reason a **service-owned** production backend still enforces
/// nothing.
///
/// This backend does hold a real `LinuxCgroupIo`: a delegated cgroup-v2
/// subtree, a durably journaled command plan, an admitted launch image, an
/// authenticated child-launch closure — and now a live canary episode, run
/// in a leaf the **probe** journal creates and removes, which is why it no
/// longer costs the one domain `prepare_service_domain` is scoped to.
///
/// What it still does not hold is a launcher that installs Landlock,
/// seccomp or the descriptor exec around the command itself. So the canary
/// proves those controls about the probe journal's leaf, which is not the
/// leaf a command would run in, and a control may be named only when
/// something on the command's own path installs it.
pub(crate) const LINUX_CGROUP_V2_SERVICE_ENFORCES_NOTHING: &str = "this Linux cgroup-v2 backend holds a service-owned delegated domain and a live canary episode, but no contained launcher: nothing on the command's own path installs Landlock, seccomp, the descriptor exec or the closed descriptor table, so every control the canary proved, it proved about the probe journal's leaf rather than about the leaf a command would run in";

/// Why a development run cannot mint contained terminal evidence.
///
/// Linux cleanup evidence requires the service-owned journal's durable Removed
/// record, exact leaf identity, limits, and ordered observations. Development
/// canaries cannot substitute their kill and empty-set observations for it.
pub(crate) const LINUX_CGROUP_V2_CLEANUP_PROOF_UNAVAILABLE: &str = "a development Linux cgroup-v2 run cannot mint a command-domain cleanup proof: the only Linux constructor requires the service-owned durable domain journal record, and no production mint for that journal exists";

/// Composed Linux cgroup-v2 containment backend for one contained command.
pub(crate) struct LinuxCgroupV2Backend {
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    live_root: PathBuf,
    private_state_root: PathBuf,
    execution_root: PathBuf,
    mode: LinuxCgroupV2Mode,
    /// Authenticated service handoff supplied by [`LinuxCgroupV2Backend::service_owned`].
    ///
    /// A live domain takes sole custody of the backend and clears this field,
    /// preserving single ownership of the delegation lock.
    service: Option<LinuxCgroupIo>,
    /// Controls a live probe proved on **this** generation.
    ///
    /// It is a separate field from [`Self::service`] on purpose: handing
    /// the handoff to a domain must not silently retract a claim that was
    /// already measured.
    ///
    /// `prove_service_controls` is the only thing that writes it, and what
    /// it writes is the intersection of what a **live canary episode**
    /// durably journaled on this generation with the controls the
    /// production command path actually installs. Neither half is a
    /// constant: drop the episode and the set is empty, and prove a
    /// control nothing installs around a command and it stays out.
    service_proven: BTreeSet<BackendControl>,
    /// Every control the last live canary episode durably journaled.
    ///
    /// This is deliberately a **superset** of [`Self::service_proven`] and
    /// is never consulted by any decision. It exists so a run can report
    /// what the suite proved on this generation separately from what this
    /// generation enforces, because those are two different facts and
    /// collapsing them is exactly how a canary-leaf result would come to
    /// stand in for a command-leaf one.
    service_canary_journaled: BTreeSet<String>,
    /// The domain `active_preflight` prepared, held for `launch`.
    ///
    /// This is what makes "proven on the command's own leaf" mean what it
    /// says. The preflight prepares the domain, runs the live canary suite
    /// inside **that** leaf, and keeps it; `launch` then releases the
    /// command into the same leaf rather than preparing a second one.
    ///
    /// Preparing twice would be two things at once: a second effect the
    /// journal refuses, and a canary that proved its controls about a leaf
    /// the command never runs in -- which is exactly the substitution the
    /// installed-control list exists to prevent.
    prepared_command_domain: Option<PreparedDomain>,
    /// Why the last in-leaf canary declined a control, verbatim.
    ///
    /// A refusal set is the reason a preflight refuses, so it travels into
    /// that refusal rather than being summarised. An absent measurement is
    /// never evidence of confinement, and the suite says so in its own
    /// words.
    service_canary_refusals: Vec<String>,
    /// The generation digest the last in-leaf canary episode produced.
    service_canary_generation_digest: Option<Digest>,
}

impl fmt::Debug for LinuxCgroupV2Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxCgroupV2Backend")
            .field("backend_id", &self.backend_id())
            .field("grant_hash", &self.grant.contract().grant_hash)
            .field("policy_hash", &self.policy.contract().policy_hash)
            .field("live_root", &self.live_root)
            .field("private_state_root", &self.private_state_root)
            .field("execution_root", &self.execution_root)
            .field("mode", &self.mode)
            .field("service_handoff", &self.service.is_some())
            .field("service_proven", &self.service_proven)
            .field("service_canary_journaled", &self.service_canary_journaled)
            // The prepared domain is reported as presence rather than
            // contents: it owns a delegation lock token and a durable
            // journal record, and a `Debug` that printed those would put
            // custody state into a log line.
            .field(
                "prepared_command_domain",
                &self.prepared_command_domain.is_some(),
            )
            .field("service_canary_refusals", &self.service_canary_refusals)
            .field(
                "service_canary_generation_digest",
                &self.service_canary_generation_digest,
            )
            .finish()
    }
}

impl LinuxCgroupV2Backend {
    /// Composes the production backend from the same authority that
    /// prepared the command.
    ///
    /// # Errors
    ///
    /// Fails for stale grant/policy authority, a non-private state or
    /// shadow root, or a shadow root that is not disjoint from the live
    /// workspace.
    pub(crate) fn new(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
    ) -> Result<Self, SupervisorError> {
        validate_authority(&grant, &policy)?;
        let live_root = grant.identity().canonical_root().to_path_buf();
        let (private_state_root, shadow_root) =
            validate_supervisor_paths(paths, &live_root, &policy)?;
        let execution_root = shadow_root.ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "the Linux cgroup-v2 backend requires a private shadow execution root".into(),
            )
        })?;
        Ok(Self {
            grant,
            policy,
            live_root,
            private_state_root,
            execution_root,
            mode: LinuxCgroupV2Mode::Production,
            service: None,
            service_proven: BTreeSet::new(),
            service_canary_journaled: BTreeSet::new(),
            prepared_command_domain: None,
            service_canary_refusals: Vec::new(),
            service_canary_generation_digest: None,
        })
    }

    /// Composes the production backend **with** the native service's own
    /// handoff.
    ///
    /// The `io` is the value
    /// `open_linux_native_service_owned_backend` returns: a
    /// `LinuxCgroupIo` whose retained mechanics authority was derived by
    /// the singleton journal when it durably committed this command's
    /// plan. It is moved in and never borrowed, so this backend is the sole
    /// owner of the delegation until a domain takes it.
    ///
    /// **Composing this grants nothing.** The generation identifier, the
    /// implementation digest and `enforced_controls()` are unchanged by it:
    /// a handoff is custody, and a control is a probe result. What changes
    /// is that the domain this backend can now prepare is *its own*, on
    /// generation [`LINUX_CGROUP_V2_BACKEND_ID`], rather than one a canary
    /// built beside it.
    ///
    /// # Errors
    ///
    /// Fails for every reason [`Self::new`] fails, when the retained
    /// mechanics authority no longer revalidates, and when the handoff was
    /// journaled under a different grant or policy than this backend was
    /// composed from.
    pub(crate) fn service_owned(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
        io: LinuxCgroupIo,
    ) -> Result<Self, SupervisorError> {
        // The join comes first and takes the handoff by reference, so a
        // refusal never destroys the service's custody of a live
        // delegation — and so the same clause can be exercised against a
        // real crossed authority without spending the handoff.
        require_service_handoff_authority(&grant, &policy, &io)?;
        let mut backend = Self::new(grant, policy, paths)?;
        backend.service = Some(io);
        Ok(backend)
    }

    /// Whether this backend holds the native service's handoff.
    pub(crate) const fn holds_service_handoff(&self) -> bool {
        self.service.is_some()
    }

    /// Prepares **this plan's** one command domain, through the retained
    /// handoff.
    ///
    /// The request is never a caller's: `prepare_service_domain` reads it
    /// out of the mechanics guard the journal derived, and
    /// `require_fresh_domain_episode` compares it against that same
    /// retained authority while the delegation lock is held.
    ///
    /// # Errors
    ///
    /// Fails when this backend holds no service handoff, and for every
    /// refusal `prepare_domain` makes.
    pub(crate) fn prepare_service_domain(&mut self) -> Result<PreparedDomain, SupervisorError> {
        let io = self.service.as_mut().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        match io
            .prepare_service_domain()
            .map_err(|error| linux_command_domain_error(&error))?
        {
            PrepareDomainOutcome::Prepared(prepared) => Ok(*prepared),
            // Both leases mean an effect may exist and the exclusive root
            // lock is still held. Neither is rounded to a failure that
            // would let a caller retry into a second effect.
            PrepareDomainOutcome::ReconciliationRequired(lease) => {
                Err(SupervisorError::Capability(format!(
                    "the Linux cgroup-v2 command domain requires delegation reconciliation \
                     before it can be prepared: {}",
                    lease.cause()
                )))
            }
            PrepareDomainOutcome::ProbeReconciliationRequired(lease) => {
                Err(SupervisorError::Capability(format!(
                    "the Linux cgroup-v2 command domain requires probe reconciliation before \
                     it can be prepared: {}",
                    lease.cause()
                )))
            }
        }
    }

    /// Hands the retained service handoff to one live domain.
    ///
    /// The handoff leaves this backend here, which is the point: a domain
    /// owns its backend, and while a domain exists nothing else may read
    /// the leaf, kill it, or reap its leader. A second call therefore
    /// refuses rather than producing a second owner.
    ///
    /// # Errors
    ///
    /// Fails when this backend holds no service handoff, and for every
    /// refusal [`LinuxCgroupV2Domain::open_service_owned`] makes.
    pub(crate) fn open_service_domain(
        &mut self,
        prepared: PreparedDomain,
        leader: Child,
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    ) -> Result<LinuxCgroupV2Domain, SupervisorError> {
        let io = self.service.take().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        LinuxCgroupV2Domain::open_service_owned(io, prepared, leader, stdout, stderr)
    }

    /// Takes custody of a domain whose leader is a **released launcher**.
    ///
    /// The sibling of [`Self::open_service_domain`], for the one case where
    /// there is no separate `Child` to own: the held launcher became the
    /// command through `execveat`, so its `Child` lives in the registry
    /// inside the `LinuxCgroupIo` this domain is about to own outright.
    ///
    /// # Errors
    ///
    /// When no service handoff is held, or the prepared domain is not in a
    /// live state.
    pub(crate) fn open_released_service_domain(
        &mut self,
        prepared: PreparedDomain,
        leader_pid: u32,
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    ) -> Result<LinuxCgroupV2Domain, SupervisorError> {
        let io = self.service.take().ok_or_else(|| {
            SupervisorError::Capability(LINUX_CGROUP_V2_SERVICE_UNAVAILABLE.into())
        })?;
        LinuxCgroupV2Domain::open_released(io, prepared, leader_pid, stdout, stderr)
    }

    /// Identifier of the exact backend generation this instance is.
    pub(crate) const fn backend_id(&self) -> &'static str {
        match self.mode {
            LinuxCgroupV2Mode::Production => LINUX_CGROUP_V2_BACKEND_ID,
            LinuxCgroupV2Mode::Development(_) => LINUX_CGROUP_V2_DEV_BACKEND_ID,
        }
    }

    /// Returns exactly the controls this backend generation truly enforces.
    ///
    /// For the production arm the answer is `service_proven`, which is the
    /// empty set on every path that exists today. That is now a
    /// *measurement* rather than a construction: a production backend can
    /// hold a real service handoff, so "empty" no longer follows from the
    /// type. What it follows from is that nothing installs Landlock,
    /// seccomp or the descriptor exec on this generation, and that the
    /// production arm has no preflight probe suite — the one plan the
    /// journal committed describes one domain, and spending it on a probe
    /// would leave the command none.
    ///
    /// For the development arm the set is whatever the live canary suite
    /// established inside the reserved cgroup domain, and is empty until
    /// that suite has run. Nothing here is a compiled-in list: every
    /// element was put there by a probe that observed the control working
    /// on this host.
    pub(crate) fn enforced_controls(&self) -> BTreeSet<BackendControl> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => self.service_proven.clone(),
            LinuxCgroupV2Mode::Development(state) => state.proven.clone(),
        }
    }

    /// Exactly what the last live canary episode durably journaled.
    ///
    /// Reporting only. A name here is a statement that a live probe proved
    /// that control **inside the probe journal's canary leaf** on this
    /// generation; it is not a statement that anything installs it around
    /// a command, which is what [`Self::enforced_controls`] answers.
    pub(crate) fn service_canary_journaled(&self) -> &BTreeSet<String> {
        &self.service_canary_journaled
    }

    /// Builds the typed refusal naming every control that is still missing.
    ///
    /// The prefix distinguishes the two production shapes, because they
    /// are different facts: a backend with no handoff at all, and a backend
    /// that holds the service's delegated domain but no launcher able to
    /// install a control in it.
    fn service_unavailable(&self) -> SupervisorError {
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
        let reason = if self.service.is_some() {
            LINUX_CGROUP_V2_SERVICE_ENFORCES_NOTHING
        } else {
            LINUX_CGROUP_V2_SERVICE_UNAVAILABLE
        };
        SupervisorError::Capability(format!("{reason}: cannot enforce {missing:?}"))
    }
}

/// One live command stream, drained nonblocking in bounded chunks.
///
/// The domain owns the read end and the parent keeps no copy of the write
/// end, so end-of-file here is the kernel's own statement that every
/// writer — the leader and every descendant that inherited the
/// descriptor — is gone. `closed` is therefore an observation and never a
/// decision, which is what lets the supervisor's monotonicity check mean
/// something.
#[derive(Debug)]
struct LinuxDomainStream {
    pipe: std::os::fd::OwnedFd,
    closed: bool,
}

impl LinuxDomainStream {
    /// Retains one read end and requires it to be nonblocking.
    ///
    /// The trait's whole contract is that every domain operation is
    /// nonblocking; a blocking read end would satisfy the type and violate
    /// the contract, so the flag is set here rather than assumed of the
    /// caller.
    fn retain(pipe: std::os::fd::OwnedFd) -> Result<Self, SupervisorError> {
        let flags = rustix::fs::fcntl_getfl(&pipe).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not inspect a command stream: {error}"
            ))
        })?;
        rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK).map_err(|error| {
            SupervisorError::Capability(format!(
                "the Linux command domain could not make a command stream nonblocking: \
                     {error}"
            ))
        })?;
        Ok(Self {
            pipe,
            closed: false,
        })
    }

    /// Performs exactly one bounded read.
    ///
    /// `EAGAIN` means "nothing yet", not "closed", and the two are kept
    /// apart deliberately: only a zero-length read is end-of-file.
    fn drain_once(&mut self, maximum_chunk_bytes: usize) -> Result<Vec<u8>, SupervisorError> {
        if self.closed || maximum_chunk_bytes == 0 {
            return Ok(Vec::new());
        }
        let mut buffer = vec![0_u8; maximum_chunk_bytes];
        match rustix::io::read(&self.pipe, &mut buffer) {
            Ok(0) => {
                self.closed = true;
                Ok(Vec::new())
            }
            Ok(read) => {
                buffer.truncate(read);
                Ok(buffer)
            }
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(Vec::new()),
            Err(error) => Err(SupervisorError::Capability(format!(
                "the Linux command domain could not drain a command stream: {error}"
            ))),
        }
    }
}

/// The one process the domain launched, and the only one it may reap.
///
/// Reaping matters to the evidence and not only to hygiene: a process
/// killed by `cgroup.kill` stays charged to its cgroup until its parent
/// reaps it, so a domain that never waits on its own leader can never
/// observe itself empty.
/// Carries one `LinuxCgroupIo` failure into the supervisor's shape.
///
/// The operation and the certainty both travel: a caller deciding whether
/// a command may be retried needs to know whether the effect may have
/// applied, and flattening that into a message would lose it.
fn linux_command_io_error(error: &CgroupIoFailure) -> SupervisorError {
    SupervisorError::Capability(format!(
        "the Linux command domain failed at {} ({:?}): {}",
        error.operation, error.certainty, error.detail
    ))
}

/// Bounded wait for a released leader after the whole-domain kill.
///
/// A `cgroup.kill` write reaches every process in the leaf, so this bound
/// is generous relative to what it waits for: the leader is already
/// signalled and the wait exists only to collect the zombie. It is bounded
/// rather than blocking because an unbounded wait inside the supervisor's
/// cleanup path would turn one stuck process into a stuck runner.
const HELD_RELEASE_REAP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]

/// The one process whose termination is this domain's terminal.
///
/// Two shapes, because a contained command is not spawned the way an
/// ordinary child is. `Direct` is a child this domain owns outright.
/// `HeldRelease` is a held launcher that *became* the command through
/// `execveat`, whose `Child` lives in the registry inside the domain's own
/// `LinuxCgroupIo`. That is not a shared owner: the domain owns the
/// `LinuxCgroupIo` outright, so the registry doing the waiting is this
/// domain waiting. Nothing hands out a descriptor, a handle or a process --
/// only the status the registry observed.
enum LinuxDomainLeader {
    Direct {
        child: Child,
        terminal: Option<BackendTermination>,
    },
    HeldRelease {
        pid: u32,
        terminal: Option<BackendTermination>,
    },
}

impl LinuxDomainLeader {
    const fn retain(child: Child) -> Self {
        Self::Direct {
            child,
            terminal: None,
        }
    }

    /// Retains a launcher that has reached an observed same-PID exec.
    const fn retain_released(pid: u32) -> Self {
        Self::HeldRelease {
            pid,
            terminal: None,
        }
    }

    /// Nonblocking status, reaping the leader the first time it answers.
    fn observe(
        &mut self,
        io: &mut LinuxCgroupIo,
    ) -> Result<Option<BackendTermination>, SupervisorError> {
        let status = match self {
            Self::Direct { child, terminal } => {
                if let Some(terminal) = *terminal {
                    return Ok(Some(terminal));
                }
                child.try_wait().map_err(|error| {
                    SupervisorError::Capability(format!(
                        "the Linux command domain could not observe its leader: {error}"
                    ))
                })?
            }
            Self::HeldRelease { pid, terminal } => {
                if let Some(terminal) = *terminal {
                    return Ok(Some(terminal));
                }
                io.observe_released_leader(*pid)
                    .map_err(|error| linux_command_io_error(&error))?
            }
        };
        let Some(status) = status else {
            return Ok(None);
        };
        let observed = backend_termination_of(status)?;
        match self {
            Self::Direct { terminal, .. } | Self::HeldRelease { terminal, .. } => {
                *terminal = Some(observed);
            }
        }
        Ok(Some(observed))
    }

    /// Blocking reap, valid only once the whole-domain kill was issued.
    fn reap(&mut self, io: &mut LinuxCgroupIo) -> Result<BackendTermination, SupervisorError> {
        let status = match self {
            Self::Direct { child, terminal } => {
                if let Some(terminal) = *terminal {
                    return Ok(terminal);
                }
                child.wait().map_err(|error| {
                    SupervisorError::Capability(format!(
                        "the Linux command domain could not reap its leader: {error}"
                    ))
                })?
            }
            Self::HeldRelease { pid, terminal } => {
                if let Some(terminal) = *terminal {
                    return Ok(terminal);
                }
                // A deadline after termination is a failure while the leader remains alive;
                // it must not synthesize a successful exit observation.
                io.reap_released_leader(*pid, HELD_RELEASE_REAP_TIMEOUT)
                    .map_err(|error| linux_command_io_error(&error))?
                    .ok_or_else(|| {
                        SupervisorError::Capability(
                            "the Linux command domain could not reap its released leader                                  within the bounded wait"
                                .to_owned(),
                        )
                    })?
            }
        };
        let observed = backend_termination_of(status)?;
        match self {
            Self::Direct { terminal, .. } | Self::HeldRelease { terminal, .. } => {
                *terminal = Some(observed);
            }
        }
        Ok(observed)
    }
}

/// Converts one reaped wait status into the boundary's termination shape.
fn backend_termination_of(status: ExitStatus) -> Result<BackendTermination, SupervisorError> {
    if let Some(signal) = ExitStatusExt::signal(&status) {
        return Ok(BackendTermination::Signaled(signal));
    }
    status
        .code()
        .map(BackendTermination::Exited)
        .ok_or_else(|| {
            SupervisorError::Capability(
                "the Linux command domain leader ended without an exit code or a signal".into(),
            )
        })
}

/// Maps one cgroup-domain refusal without flattening away its detail.
fn linux_command_domain_error(error: &CgroupError) -> SupervisorError {
    SupervisorError::Capability(format!("the Linux cgroup-v2 command domain: {error}"))
}

/// Requires a service handoff to have been journaled under exactly the
/// command authority a backend is being composed from.
///
/// The handoff carries a delegated cgroup subtree, a durably committed
/// plan, and the ceilings that plan derived. A backend composed from a
/// different grant or a different compiled policy would still produce a
/// `BackendIdentity`, a `ValidatedBackendPermit` and, eventually, a piece
/// of contained evidence — all of them describing a command the durable
/// plan never described. The hash pair is the whole of what the handoff is
/// asked for, and it is compared against the composer's own contracts
/// rather than against anything the handoff also supplied.
///
/// It deliberately takes the handoff by reference: a refusal must leave the
/// service holding its own live delegation, not drop it.
///
/// # Errors
///
/// Fails when the retained mechanics authority no longer revalidates, and
/// when either hash differs.
pub(crate) fn require_service_handoff_authority(
    grant: &IssuedWorkspaceGrant,
    policy: &CompiledExecutionPolicy,
    io: &LinuxCgroupIo,
) -> Result<(), SupervisorError> {
    let (journaled_grant, journaled_policy) =
        io.retained_command_authority().map_err(|failure| {
            SupervisorError::Capability(format!(
                "the Linux cgroup-v2 service handoff could not restate its own command \
                 authority: {} ({:?}) {}",
                failure.operation, failure.certainty, failure.detail
            ))
        })?;
    if journaled_grant != grant.contract().grant_hash.to_string()
        || journaled_policy != policy.contract().policy_hash.to_string()
    {
        return Err(SupervisorError::Authority(
            "the Linux cgroup-v2 service handoff was journaled under a different grant or \
             execution policy than this backend was composed from"
                .into(),
        ));
    }
    Ok(())
}

/// Live Linux command domain: the service-owned backend, prepared leaf and
/// journal record, leader process, and command streams.
///
/// Production preflight proves controls inside this leaf before the contained
/// launcher installs them and releases the target.
#[derive(Debug)]
pub(crate) struct LinuxCgroupV2Domain {
    io: LinuxCgroupIo,
    prepared: PreparedDomain,
    leader: LinuxDomainLeader,
    stdout: LinuxDomainStream,
    stderr: LinuxDomainStream,
    termination: Option<DomainTerminationRequest>,
}

impl LinuxCgroupV2Domain {
    /// Takes custody of one live service-owned command domain.
    ///
    /// Every part is moved in, never borrowed: the domain is the sole
    /// owner of the backend, the delegation lock inside `prepared`, the
    /// leader, and both read ends, so nothing else can read the leaf, kill
    /// the domain, reap the leader, or steal an output byte.
    ///
    /// # Errors
    ///
    /// Fails when the prepared domain is not in a live state, when its
    /// leaf identity is absent, or when a stream cannot be made
    /// nonblocking.
    pub(crate) fn open_service_owned(
        io: LinuxCgroupIo,
        prepared: PreparedDomain,
        leader: Child,
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    ) -> Result<Self, SupervisorError> {
        if !matches!(
            prepared.state(),
            DomainJournalState::Prepared
                | DomainJournalState::AttachIntended
                | DomainJournalState::Attached
                | DomainJournalState::Held
                | DomainJournalState::ReleaseIntended
                | DomainJournalState::Released
        ) {
            return Err(SupervisorError::Capability(format!(
                "a live Linux command domain requires a configured live-domain journal \
                 state, not {:?}",
                prepared.state()
            )));
        }
        prepared
            .leaf_identity()
            .map_err(|error| linux_command_domain_error(&error))?;
        Ok(Self {
            io,
            prepared,
            leader: LinuxDomainLeader::retain(leader),
            stdout: LinuxDomainStream::retain(stdout)?,
            stderr: LinuxDomainStream::retain(stderr)?,
            termination: None,
        })
    }

    /// Takes custody of a domain whose leader is a **released launcher**.
    ///
    /// Identical to [`Self::open_service_owned`] except for where the
    /// leader lives. There is no separate `Child` here: the held launcher
    /// became the command through `execveat`, so its `Child` is retained by
    /// the registry inside the `LinuxCgroupIo` being moved in. The domain
    /// still owns everything outright -- owning the `LinuxCgroupIo` is
    /// owning that registry.
    ///
    /// # Errors
    ///
    /// Fails when the prepared domain is not in a live state, when its leaf
    /// identity is absent, or when a stream cannot be made nonblocking.
    pub(crate) fn open_released(
        io: LinuxCgroupIo,
        prepared: PreparedDomain,
        leader_pid: u32,
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    ) -> Result<Self, SupervisorError> {
        if !matches!(
            prepared.state(),
            DomainJournalState::Released | DomainJournalState::ReleaseIntended
        ) {
            return Err(SupervisorError::Capability(format!(
                "a released Linux command domain requires a released journal state, not {:?}",
                prepared.state()
            )));
        }
        prepared
            .leaf_identity()
            .map_err(|error| linux_command_domain_error(&error))?;
        Ok(Self {
            io,
            prepared,
            leader: LinuxDomainLeader::retain_released(leader_pid),
            stdout: LinuxDomainStream::retain(stdout)?,
            stderr: LinuxDomainStream::retain(stderr)?,
            termination: None,
        })
    }

    /// Polls this domain until its leader reports a terminal, for a live
    /// measurement.
    ///
    /// Uses the same `poll` the supervisor uses -- nothing here is a
    /// shortcut around the domain's own observation path; it only supplies
    /// the loop the supervisor would otherwise run.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn await_terminal_for_measurement(&mut self) -> Option<BackendTermination> {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            match ContainedDescendantDomain::poll(self, 64 * 1024) {
                Ok(observation) => {
                    if let Some(terminal) = observation.leader {
                        return Some(terminal);
                    }
                }
                Err(error) => {
                    eprintln!("GBDTERMINAL poll-error={error}");
                    return None;
                }
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The leaf this domain owns, for a canary that must read it
    /// independently of the code under test.
    pub(crate) fn leaf_name(&self) -> &str {
        self.prepared.leaf_name()
    }

    /// The durable journal state this domain has reached.
    pub(crate) const fn journal_state(&self) -> DomainJournalState {
        self.prepared.state()
    }
}

impl ContainedDescendantDomain for LinuxCgroupV2Domain {
    /// One nonblocking observation, in the only order that is sound.
    ///
    /// The leader is observed first, then the streams, then the kernel's
    /// own `cgroup.events`. `domain_empty` is the **conjunction** of the
    /// kernel's `populated 0`, a reaped leader, and both streams at
    /// end-of-file. That is deliberately stronger than the kernel read
    /// alone: an unread byte still in a pipe belongs to this command, and
    /// reporting the domain complete while one is outstanding would let
    /// the supervisor finish a command whose output it never saw. Reporting
    /// `false` for an instant longer than strictly necessary is never a
    /// false claim; reporting `true` early would be.
    fn poll(&mut self, maximum_chunk_bytes: usize) -> Result<DomainObservation, SupervisorError> {
        let leader = self.leader.observe(&mut self.io)?;
        let stdout = self.stdout.drain_once(maximum_chunk_bytes)?;
        let stderr = self.stderr.drain_once(maximum_chunk_bytes)?;
        let unpopulated = observe_domain_unpopulated(&mut self.io, &self.prepared)
            .map_err(|error| linux_command_domain_error(&error))?;
        let stdout_closed = self.stdout.closed;
        let stderr_closed = self.stderr.closed;
        Ok(DomainObservation {
            stdout,
            stderr,
            leader,
            stdout_closed,
            stderr_closed,
            domain_empty: unpopulated && leader.is_some() && stdout_closed && stderr_closed,
        })
    }

    /// Kills the complete domain, durably recording the intent first.
    ///
    /// One `cgroup.kill` write reaches every process in the leaf whether or
    /// not it shares a process group, a session, or a parent with the
    /// leader, which is the property ADR-0006 requires of an accounting
    /// domain. The first reason is retained; a later call re-issues the
    /// idempotent kill rather than rewriting history.
    fn terminate_all(&mut self, reason: DomainTerminationRequest) -> Result<(), SupervisorError> {
        terminate_domain(&mut self.io, &mut self.prepared)
            .map_err(|error| linux_command_domain_error(&error))?;
        self.termination.get_or_insert(reason);
        Ok(())
    }

    /// Reaps the domain and mints the real cleanup proof.
    ///
    /// Nothing here can round a domain down to empty. `cleanup_domain`
    /// drives the durable journal from `Killing` to `Removed` and accepts
    /// an endpoint only from a real `populated 0` followed by two empty
    /// `cgroup.procs` reads, and `from_linux_candidate` re-derives that
    /// whole record before minting. The proof is
    /// `ReapedZeroSurvivors` or there is no proof.
    fn into_cleanup_proof(self) -> Result<ValidatedCommandDomainCleanupProof, SupervisorError> {
        let Self {
            mut io,
            mut prepared,
            mut leader,
            stdout,
            stderr,
            termination,
        } = self;
        // The read ends go first: a domain being reaped has nothing left to
        // say, and holding them open past the kill would keep this process
        // in the way of nothing but itself.
        drop(stdout);
        drop(stderr);
        if termination.is_none() {
            terminate_domain(&mut io, &mut prepared)
                .map_err(|error| linux_command_domain_error(&error))?;
        }
        // Safe to block: the kill has been issued, so this wait cannot
        // outlive the leader. Skipping it would leave a zombie charged to
        // the leaf and the drain below would time out against it.
        leader.reap(&mut io)?;
        let evidence = cleanup_domain(&mut io, &mut prepared, MAX_CLEANUP_ATTEMPTS)
            .map_err(|error| linux_command_domain_error(&error))?;
        Ok(ValidatedCommandDomainCleanupProof::from_linux_candidate(
            &evidence,
        )?)
    }
}

impl ContainedCommandBackend for LinuxCgroupV2Backend {
    type Domain = LinuxCgroupV2Domain;

    fn identity(&self) -> Result<BackendIdentity, SupervisorError> {
        validate_authority(&self.grant, &self.policy)?;
        let implementation_digest = match self.mode {
            LinuxCgroupV2Mode::Production => linux_cgroup_v2_implementation_digest(),
            LinuxCgroupV2Mode::Development(_) => {
                linux_cgroup_v2_development_implementation_digest()
            }
        };
        Ok(BackendIdentity::new(
            CommandDomainCleanupBackend::LinuxCgroupV2,
            self.backend_id(),
            implementation_digest,
        ))
    }

    fn active_preflight(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<BackendPreflightReport, SupervisorError> {
        command.revalidate()?;
        validate_authority(&self.grant, &self.policy)?;
        if command.policy().contract().policy_hash != self.policy.contract().policy_hash
            || command.command_effect_authority().grant_hash() != &self.grant.contract().grant_hash
        {
            return Err(SupervisorError::Authority(
                "Linux cgroup-v2 backend was composed from different command authority".into(),
            ));
        }
        if command.execution_root_path() != self.execution_root {
            return Err(SupervisorError::Authority(
                "Linux cgroup-v2 backend was composed for a different execution root".into(),
            ));
        }
        match self.mode {
            // With a service handoff, prepare this command's domain, run live canaries
            // inside its leaf, and reinstall the committed ceilings. Report only proven
            // controls; without a handoff, refuse preparation.
            LinuxCgroupV2Mode::Production => {
                if self.service.is_some() {
                    self.production_preflight(command)
                } else {
                    Err(self.service_unavailable())
                }
            }
            // The development arm reserves one delegated cgroup leaf per
            // probe beneath the launcher-supplied delegation, runs the live
            // canary suite inside it, and reports exactly what it proved.
            LinuxCgroupV2Mode::Development(_) => self.development_preflight(command),
        }
    }

    fn launch(
        &mut self,
        command: PreparedContainedCommand,
        permit: ValidatedBackendPermit,
        output_capture: &DurablyAnchoredCapture,
    ) -> Result<Self::Domain, SupervisorError> {
        // The development arm lacks the durable service journal required to mint
        // a cleanup proof.
        if matches!(self.mode, LinuxCgroupV2Mode::Development(_)) {
            drop(command);
            drop(permit);
            let _ = output_capture;
            return Err(SupervisorError::Capability(
                LINUX_CGROUP_V2_CLEANUP_PROOF_UNAVAILABLE.into(),
            ));
        }
        // Consume the permit at this boundary. The supervisor owns output capture;
        // the lower release path receives only the inputs it uses.
        let _ = output_capture;
        let domain = self.launch_contained(&command)?;
        drop(permit);
        Ok(domain)
    }
}

fn linux_cgroup_v2_implementation_digest() -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, LINUX_CGROUP_V2_IMPLEMENTATION_DOMAIN);
    hash_frame(&mut hasher, LINUX_CGROUP_V2_BACKEND_ID.as_bytes());
    digest_from_sha(hasher.finalize().into())
}
/// Immutable identifier of the *development* backend generation.
///
/// It is deliberately a different string from
/// [`LINUX_CGROUP_V2_BACKEND_ID`]. The backend identity travels into every
/// permit, every piece of contained evidence, and every terminal response,
/// so a development run is distinguishable from a production run at each of
/// those points without reading a flag.
pub(crate) const LINUX_CGROUP_V2_DEV_BACKEND_ID: &str = "linux-cgroup-v2-development-v1";

const LINUX_CGROUP_V2_DEVELOPMENT_IMPLEMENTATION_DOMAIN: &[u8] =
    b"grok-build/linux-cgroup-v2-development-backend/v1";
const LINUX_CGROUP_V2_CANARY_DOMAIN: &[u8] = b"grok-build/linux-cgroup-v2-development-canaries/v1";

/// Generous allowance for a canary that is expected to finish on its own.
const LINUX_CANARY_WALL_TIME: Duration = Duration::from_secs(20);
/// Deliberately short allowance used only by the wall-clock canary.
const LINUX_WALL_CLOCK_CANARY: Duration = Duration::from_millis(400);
/// Bytes the bounded-output canary streams through the report pipe.
const LINUX_BOUNDED_OUTPUT_BYTES: u64 = 40 * 1_024;
/// Children the fork canary asks for under both ceilings.
const LINUX_FORK_CANARY_CHILDREN: u32 = 6;
/// Ceiling the domain-kill probe installs.
///
/// It is deliberately larger than the command's own ceiling: proving that
/// one kill covers a *complete* domain requires the domain to contain a
/// descendant that has left the leader's process group and session. The
/// command's own leaf still carries the compiled ceiling; this is a
/// mechanism probe and every refusal it produces says so.
const LINUX_DOMAIN_KILL_PROBE_PIDS_MAX: u64 = 8;
/// `EAGAIN`, the exact refusal an exhausted `pids.max` produces.
const LINUX_EAGAIN_ERRNO: i32 = 11;
/// The three errno values a real policy denial produces. Any other failure
/// is an inconclusive probe, and an inconclusive probe never proves a
/// control.
const LINUX_EPERM_ERRNO: i32 = 1;
const LINUX_EACCES_ERRNO: i32 = 13;
const LINUX_EROFS_ERRNO: i32 = 30;
/// Exact number of contained runs one complete canary suite performs.
///
/// Eleven rather than step 1's nine: the filesystem and network controls
/// each gained a control half that removes exactly one containment layer
/// and changes nothing else.
const EXPECTED_LINUX_CANARY_RUNS: usize = 11;
/// Two further runs exist only when the policy requests a memory ceiling.
const EXPECTED_LINUX_MEMORY_CANARY_RUNS: usize = 2;

/// Which topology one composed backend belongs to.
pub(crate) enum LinuxCgroupV2Mode {
    /// The authenticated native command service. Absent.
    Production,
    /// The delegated development domain from the architecture document.
    Development(Box<LinuxCgroupV2DevelopmentState>),
}

impl fmt::Debug for LinuxCgroupV2Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => formatter.write_str("Production"),
            Self::Development(state) => formatter
                .debug_struct("Development")
                .field("delegation_root", &state.delegation_root)
                .field("proven_controls", &state.proven)
                .field("refusals", &state.refusals)
                .finish(),
        }
    }
}

/// Everything the development arm learns at run time.
///
/// `proven` starts empty and is only ever replaced by the exact set the
/// live canary suite established inside reserved cgroup leaves. No code
/// path inserts a control without a canary having returned a definite
/// result for it.
pub(crate) struct LinuxCgroupV2DevelopmentState {
    delegation_root: PathBuf,
    proven: BTreeSet<BackendControl>,
    refusals: Vec<String>,
    canary_digest: Option<Digest>,
    descendant_domain: Option<LinuxDevelopmentDescendantDomain>,
    descriptor_closure: Option<LinuxDevelopmentDescriptorClosure>,
    exec_source: Option<LinuxDevelopmentExecSource>,
    unconfined_surface: Option<LinuxDevelopmentUnconfinedSurface>,
    containment: Option<LinuxContainmentEvidence>,
}

/// Everything behind this host's two descendant verdicts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxDevelopmentDescendantDomain {
    /// The ceiling the command's own compiled policy configures.
    pub(crate) configured_max_processes: u32,
    /// The exact `pids.max` the kernel read back for the restricted leaf.
    pub(crate) read_back_pids_max: String,
    /// Children the same argument vector created with no ceiling.
    pub(crate) control_spawned: u32,
    /// Children it created under the configured ceiling.
    pub(crate) restricted_spawned: u32,
    /// `errno` of the first refused creation under the ceiling.
    pub(crate) restricted_spawn_errno: Option<i32>,
    /// The leaf's `pids.events` after the restricted run.
    pub(crate) restricted_pids_events: String,
    pub(crate) leader_pid: u32,
    pub(crate) leader_process_group: u32,
    pub(crate) leader_session: u32,
    /// A descendant that took its own process group *and* session.
    pub(crate) descendant_pid: u32,
    pub(crate) descendant_process_group: u32,
    pub(crate) descendant_session: u32,
    /// `cgroup.procs` while both processes were alive.
    pub(crate) membership_before_kill: Vec<u32>,
    /// Ordered kill, `cgroup.events`, and `cgroup.procs` evidence.
    pub(crate) kill: Option<LinuxDomainKillObservation>,
    /// `pids.current` once every killed task had also been collected.
    pub(crate) settled_pids_current: String,
    /// Reported PIDs still running anywhere on the host afterwards.
    pub(crate) host_wide_survivors: Vec<u32>,
}

impl LinuxDevelopmentDescendantDomain {
    fn empty(configured_max_processes: u32) -> Self {
        Self {
            configured_max_processes,
            read_back_pids_max: String::new(),
            control_spawned: 0,
            restricted_spawned: 0,
            restricted_spawn_errno: None,
            restricted_pids_events: String::new(),
            leader_pid: 0,
            leader_process_group: 0,
            leader_session: 0,
            descendant_pid: 0,
            descendant_process_group: 0,
            descendant_session: 0,
            membership_before_kill: Vec::new(),
            kill: None,
            settled_pids_current: String::new(),
            host_wide_survivors: Vec::new(),
        }
    }
}

/// The complete observation behind the descriptor-closure verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxDevelopmentDescriptorClosure {
    /// Descriptors the controller itself held at the spawn.
    pub(crate) controller_descriptors: usize,
    /// The target's own `/proc/self/fd` after exec.
    pub(crate) target_table: Vec<u32>,
}

/// The two exec sources one A/B pair compared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LinuxDevelopmentExecSource {
    /// `/proc/self/exe` when the image was a sealed anonymous memfd.
    pub(crate) sealed_image_link: String,
    /// `/proc/self/exe` when the identical bytes had a pathname.
    pub(crate) named_image_link: String,
}

/// Both halves of the filesystem and network A/B pairs.
///
/// The unprefixed fields are the **control** halves: the same canary,
/// launched by the same mechanism into the same kind of leaf, with
/// exactly one containment layer removed — the path layer for the escape
/// pair, the syscall layer for the loopback pair. The `confined_` fields
/// are the same runs with the complete compiled policy installed.
///
/// Keeping both halves is what makes each verdict a measurement: a
/// refusal observed only under containment says nothing unless the
/// identical run without that one layer succeeded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is one kernel observation from one named half of an A/B pair; collapsing them into an enum would discard exactly the measurements a verdict has to be checked against"
)]
pub(crate) struct LinuxDevelopmentUnconfinedSurface {
    pub(crate) escape_write_succeeded: Option<bool>,
    pub(crate) escape_write_errno: Option<i32>,
    pub(crate) escape_file_created: bool,
    pub(crate) loopback_connect_succeeded: Option<bool>,
    pub(crate) loopback_connect_errno: Option<i32>,
    pub(crate) loopback_listener_accepted: bool,
    pub(crate) network_mode_allows: bool,
    /// The escape write with the Landlock path layer installed.
    pub(crate) confined_escape_write_succeeded: Option<bool>,
    pub(crate) confined_escape_write_errno: Option<i32>,
    pub(crate) confined_escape_file_created: bool,
    /// Whether that confined run really installed the path layer.
    pub(crate) confined_escape_landlock_installed: bool,
    /// The loopback connect with the seccomp syscall layer installed.
    pub(crate) confined_loopback_connect_succeeded: Option<bool>,
    pub(crate) confined_loopback_connect_errno: Option<i32>,
    pub(crate) confined_loopback_listener_accepted: bool,
    /// Whether that confined run really installed the syscall layer.
    pub(crate) confined_loopback_seccomp_installed: bool,
}

/// One loopback run and everything the controller observed around it.
struct LinuxLoopbackProbe {
    report: Option<LinuxCanaryReportV1>,
    /// Whether the controller's own listener accepted the connection.
    listener_accepted: bool,
    /// Whether this controller reaches an equivalent listener it binds.
    controller_reachable: bool,
    /// Whether this run really installed the syscall layer.
    seccomp_installed: bool,
}

impl LinuxCgroupV2Backend {
    /// Composes the **development** Linux cgroup-v2 backend.
    ///
    /// The delegated cgroup-v2 root comes only from the trusted launcher's
    /// `GROK_BUILD_CGROUP_ROOT`. It is never
    /// accepted in a tool request and is never handed to a project command.
    ///
    /// # Errors
    ///
    /// Fails for the same authority, private-root, and shadow-root reasons
    /// as the production constructor, and when no delegation was supplied.
    pub(crate) fn development(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
    ) -> Result<Self, SupervisorError> {
        let delegation_root = delegation_root_from_environment().ok_or_else(|| {
            SupervisorError::Capability(format!(
                "the development Linux backend requires an absolute delegated cgroup-v2 root in {LINUX_DELEGATION_ROOT_VARIABLE}"
            ))
        })?;
        Self::development_with_delegation(grant, policy, paths, &delegation_root)
    }

    /// Composes the development backend against an explicit delegation.
    ///
    /// # Errors
    ///
    /// Fails for the same reasons as [`Self::development`].
    pub(crate) fn development_with_delegation(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
        delegation_root: &Path,
    ) -> Result<Self, SupervisorError> {
        let mut backend = Self::new(grant, policy, paths)?;
        backend.mode = LinuxCgroupV2Mode::Development(Box::new(LinuxCgroupV2DevelopmentState {
            delegation_root: delegation_root.to_path_buf(),
            proven: BTreeSet::new(),
            refusals: Vec::new(),
            canary_digest: None,
            descendant_domain: None,
            descriptor_closure: None,
            exec_source: None,
            unconfined_surface: None,
            containment: None,
        }));
        Ok(backend)
    }

    /// Whether this backend is the development arm.
    pub(crate) const fn development_mode(&self) -> bool {
        matches!(self.mode, LinuxCgroupV2Mode::Development(_))
    }

    /// Exact bounded reasons the development canaries refused a control.
    pub(crate) fn development_refusals(&self) -> &[String] {
        match &self.mode {
            LinuxCgroupV2Mode::Production => &[],
            LinuxCgroupV2Mode::Development(state) => &state.refusals,
        }
    }

    /// The exact observation behind this generation's `DescendantLimit`
    /// and `DescendantDomainKill` verdicts.
    pub(crate) fn development_descendant_domain(
        &self,
    ) -> Option<&LinuxDevelopmentDescendantDomain> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.descendant_domain.as_ref(),
        }
    }

    /// The exact observation behind the `ClosedInheritedDescriptors` verdict.
    pub(crate) fn development_descriptor_closure(
        &self,
    ) -> Option<&LinuxDevelopmentDescriptorClosure> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.descriptor_closure.as_ref(),
        }
    }

    /// The exec-source A/B behind the `DescriptorExec` verdict.
    pub(crate) fn development_exec_source(&self) -> Option<&LinuxDevelopmentExecSource> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.exec_source.as_ref(),
        }
    }

    /// Both halves of the filesystem and network A/B pairs.
    pub(crate) fn development_unconfined_surface(
        &self,
    ) -> Option<&LinuxDevelopmentUnconfinedSurface> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.unconfined_surface.as_ref(),
        }
    }

    /// Exactly which containment layers this generation negotiated.
    pub(crate) fn development_containment(&self) -> Option<&LinuxContainmentEvidence> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.containment.as_ref(),
        }
    }

    /// The exact path and syscall scopes one contained run is confined to.
    ///
    /// The read scopes are the compiled read scopes resolved against the
    /// live workspace root, plus the execution root the shadow mutation
    /// mode makes the target's own project view, plus the read-only
    /// runtime surfaces the kernel resolves before the target's first
    /// instruction. The write scopes are the compiled write scopes
    /// resolved against that execution root, and nothing else — in
    /// particular no temporary directory, which is where the escape
    /// canary aims.
    fn development_containment_policy(
        &self,
        command: &PreparedContainedCommand,
    ) -> LinuxContainmentPolicy {
        let contract = self.policy.contract();
        let mut read_roots = linux_runtime_read_roots();
        read_roots.extend(scope_paths(&self.live_root, &contract.read_scopes));
        read_roots.push(command.execution_root_path().to_path_buf());
        // The exact authenticated target image is a read-and-execute
        // scope. In production it is a sealed memfd with no pathname
        // anywhere, which needs no rule; the development suite also runs
        // one named-image control half, and the kernel resolves that name
        // after the ruleset is installed.
        read_roots.push(command.executable_path().to_path_buf());
        read_roots.push(canary_image_source());
        let mut write_roots = linux_runtime_write_surfaces();
        write_roots.extend(scope_paths(
            command.execution_root_path(),
            &contract.write_scopes,
        ));
        LinuxContainmentPolicy {
            read_roots,
            write_roots,
            filesystem_layer: true,
            network_layer: contract.network == ExecutionNetwork::None,
            // Unconditional: no contract setting turns namespace creation
            // on, and nothing in a build command legitimately reaches for
            // a new namespace.
            namespace_layer: true,
        }
    }

    fn development_delegation_root(&self) -> Result<PathBuf, SupervisorError> {
        match &self.mode {
            LinuxCgroupV2Mode::Production => Err(SupervisorError::Capability(
                "development canaries require the development backend arm".into(),
            )),
            LinuxCgroupV2Mode::Development(state) => Ok(state.delegation_root.clone()),
        }
    }

    /// Runs the live canary suite and records exactly what it established.
    fn prove_development_controls(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<(), SupervisorError> {
        let delegation_root = self.development_delegation_root()?;
        let environment = development_environment(command)?;
        let containment = self.development_containment_policy(command);
        let mut suite = LinuxDevelopmentCanarySuite {
            leaf: CanaryLeafSource::SelfCreated(delegation_root),
            policy: self.policy.clone(),
            environment,
            working_directory: command.working_directory_path().to_path_buf(),
            containment,
            runs: 0,
            run_frames: Vec::new(),
            root_inodes: BTreeSet::new(),
            proven: BTreeSet::new(),
            refusals: Vec::new(),
            descendant_domain: None,
            descriptor_closure: None,
            exec_source: None,
            unconfined_surface: None,
            containment_evidence: None,
        };
        let outcome = suite.run();
        let digest = suite.generation_digest();
        if let LinuxCgroupV2Mode::Development(state) = &mut self.mode {
            // Retain whatever the suite established even when a later probe
            // could not complete: a diagnostic must never be discarded.
            state.proven = suite.proven;
            state.refusals = suite.refusals;
            state.descendant_domain = suite.descendant_domain;
            state.descriptor_closure = suite.descriptor_closure;
            state.exec_source = suite.exec_source;
            state.unconfined_surface = suite.unconfined_surface;
            state.containment = suite.containment_evidence;
            if outcome.is_ok() {
                state.canary_digest = Some(digest);
            }
        }
        outcome
    }

    fn development_preflight(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<BackendPreflightReport, SupervisorError> {
        self.prove_development_controls(command)?;
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        if !required.is_subset(&enforced) {
            return Err(self.development_unenforceable());
        }
        let identity = ContainedCommandBackend::identity(self)?;
        let canary_digest = match &self.mode {
            LinuxCgroupV2Mode::Production => None,
            LinuxCgroupV2Mode::Development(state) => state.canary_digest.clone(),
        }
        .ok_or_else(|| {
            SupervisorError::Canary(
                "the development Linux canary suite produced no generation digest".into(),
            )
        })?;
        Ok(BackendPreflightReport::new(
            command.launch_digest().clone(),
            identity,
            enforced,
            vec![0, 1, 2],
            BackendCanaryStatus::Passed(canary_digest),
        ))
    }

    /// Builds the development refusal naming every unproven control.
    pub(crate) fn development_unenforceable(&self) -> SupervisorError {
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
        let reasons = self.development_refusals().join("; ");
        SupervisorError::Capability(format!(
            "the development Linux cgroup-v2 domain enforces {enforced:?} but cannot enforce \
             {missing:?}: {reasons}"
        ))
    }
}

/// Where the leaf one canary run happens inside comes from.
///
/// This is the whole ownership question the production arm turned on. The
/// development arm mints its own leaf names and removes them, outside any
/// journal, which is exactly the unaudited domain creation the production
/// arm may not perform. The production arm therefore adopts a leaf the
/// probe journal created under a durable create-intent generation and will
/// remove under its own remove-intent generation.
///
/// The development arm keeps its own creation because it **cannot** have a
/// journal: `CanonicalCgroupJournalStore`'s only non-test constructor is
/// `open_service_singleton`, which requires the authenticated
/// service-state capability the development arm is defined never to hold.
enum CanaryLeafSource {
    /// The suite creates each leaf, names it, and removes it. Development
    /// only, and never reachable from the production arm.
    SelfCreated(PathBuf),
    /// One leaf the probe journal created, owns, and will remove.
    ///
    /// Every canary in the suite adopts this same leaf in turn — the suite
    /// reserves, runs and drops strictly sequentially — and the adoption
    /// re-checks the kernel's identity against `identity` every time, so a
    /// leaf substituted mid-suite is refused rather than used.
    Journaled {
        delegation: std::os::fd::OwnedFd,
        leaf_name: String,
        identity: (u64, u64),
    },
}

/// One live canary suite execution against one delegated cgroup-v2 root.
struct LinuxDevelopmentCanarySuite {
    leaf: CanaryLeafSource,
    policy: CompiledExecutionPolicy,
    environment: BTreeMap<String, String>,
    working_directory: PathBuf,
    /// The complete compiled path and syscall policy every canary but the
    /// two named control halves runs inside.
    containment: LinuxContainmentPolicy,
    runs: usize,
    run_frames: Vec<String>,
    root_inodes: BTreeSet<u64>,
    proven: BTreeSet<BackendControl>,
    refusals: Vec<String>,
    descendant_domain: Option<LinuxDevelopmentDescendantDomain>,
    descriptor_closure: Option<LinuxDevelopmentDescriptorClosure>,
    exec_source: Option<LinuxDevelopmentExecSource>,
    unconfined_surface: Option<LinuxDevelopmentUnconfinedSurface>,
    containment_evidence: Option<LinuxContainmentEvidence>,
}

impl LinuxDevelopmentCanarySuite {
    fn run(&mut self) -> Result<(), SupervisorError> {
        self.identity_and_exec_source()?;
        self.descendant_ceiling()?;
        self.domain_kill()?;
        self.external_wall_clock()?;
        self.complete_bounded_output()?;
        self.filesystem_policy()?;
        self.network_policy()?;
        self.memory_ceiling()?;
        // `ActiveCanaries` is the one control about the suite itself: every
        // probe above returned a definite result, and every one of them ran
        // beneath the same delegated cgroup root. Both halves are checked.
        let expected = self.expected_runs();
        if self.runs >= expected && self.root_inodes.len() == 1 {
            self.proven.insert(BackendControl::ActiveCanaries);
        } else {
            self.refusals.push(format!(
                "the development Linux canary suite completed {} of {expected} runs across {} \
                 delegated cgroup roots",
                self.runs,
                self.root_inodes.len()
            ));
        }
        Ok(())
    }

    fn expected_runs(&self) -> usize {
        if self
            .policy
            .contract()
            .resource_limits
            .max_memory_bytes
            .is_some()
        {
            EXPECTED_LINUX_CANARY_RUNS + EXPECTED_LINUX_MEMORY_CANARY_RUNS
        } else {
            EXPECTED_LINUX_CANARY_RUNS
        }
    }

    fn generation_digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        hash_frame(&mut hasher, LINUX_CGROUP_V2_CANARY_DOMAIN);
        for inode in &self.root_inodes {
            hash_frame(&mut hasher, &inode.to_be_bytes());
        }
        for frame in &self.run_frames {
            hash_frame(&mut hasher, frame.as_bytes());
        }
        digest_from_sha(hasher.finalize().into())
    }

    fn reserve(
        &self,
        pids_max: Option<u64>,
        memory_max: Option<u64>,
        sealed: bool,
    ) -> Result<LinuxDelegatedCanaryDomain, SupervisorError> {
        let image = if sealed {
            sealed_self_image()
        } else {
            named_self_image()
        }
        .map_err(|error| linux_dev_domain_error(&error))?;
        match &self.leaf {
            CanaryLeafSource::SelfCreated(delegation_root) => {
                LinuxDelegatedCanaryDomain::reserve(delegation_root, image, pids_max, memory_max)
            }
            CanaryLeafSource::Journaled {
                delegation,
                leaf_name,
                identity,
            } => LinuxDelegatedCanaryDomain::adopt(
                std::os::fd::AsFd::as_fd(delegation),
                leaf_name,
                *identity,
                image,
                pids_max,
                memory_max,
            ),
        }
        .map_err(|error| linux_dev_domain_error(&error))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every canary states its mode, parameter, extra vector, deadline, report count, and kill trigger explicitly rather than defaulting any of them"
    )]
    fn run_canary(
        &mut self,
        domain: &LinuxDelegatedCanaryDomain,
        mode: &str,
        parameter: &str,
        extra_arguments: &[String],
        deadline: Duration,
        expected_reports: usize,
        kill_after_reports: Option<usize>,
        containment: Option<&LinuxContainmentPolicy>,
    ) -> Result<LinuxCanaryRunObservation, SupervisorError> {
        let observation = {
            let specification = CanarySpecification {
                mode,
                parameter,
                extra_arguments,
                environment: &self.environment,
                working_directory: &self.working_directory,
                deadline,
                expected_reports,
                kill_after_reports,
                containment,
            };
            domain
                .run(&specification)
                .map_err(|error| linux_dev_domain_error(&error))?
        };
        self.runs += 1;
        self.root_inodes.insert(observation.root_inode);
        // Retain the first complete negotiation as this generation's
        // containment evidence: both layers installed, nothing dropped.
        if self.containment_evidence.is_none()
            && observation
                .containment
                .as_ref()
                .is_some_and(|evidence| evidence.landlock_installed && evidence.seccomp_installed)
        {
            self.containment_evidence
                .clone_from(&observation.containment);
        }
        self.run_frames.push(format!(
            "{mode}:{}:{}:{}:{}",
            observation.leaf_inode,
            observation.reports.len(),
            observation.payload_digest,
            observation
                .containment
                .as_ref()
                .map_or_else(String::new, |evidence| format!(
                    "{}/{}",
                    evidence.landlock_installed, evidence.seccomp_installed
                ))
        ));
        Ok(observation)
    }

    /// One `report` run establishes the four vector and descriptor
    /// controls, and its A/B partner establishes the exec source.
    #[allow(
        clippy::too_many_lines,
        reason = "each control's observation and verdict stay adjacent to the run that produced them"
    )]
    fn identity_and_exec_source(&mut self) -> Result<(), SupervisorError> {
        let extra = vec![
            "grok-build-argv".to_owned(),
            "alpha beta".to_owned(),
            "--%weird$(argument)".to_owned(),
        ];
        let confined = self.containment.clone();
        let domain = self.reserve(None, None, true)?;
        let image_path = domain.image_path().to_path_buf();
        let sealed = self.run_canary(
            &domain,
            "report",
            "-",
            &extra,
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined),
        )?;
        drop(domain);
        let Some(report) = sealed.reports.first().cloned() else {
            self.refusals.push(
                "the identity canary produced no report inside the reserved cgroup leaf".to_owned(),
            );
            return Ok(());
        };
        if !report.attached {
            self.refusals.push(format!(
                "the canary could not attach itself to the reserved leaf: errno {:?}",
                report.attach_errno
            ));
        }

        // ExactArgv: the kernel delivered the complete vector, including
        // the trailing entries the helper is required to ignore.
        let mut expected_argv = vec![
            image_path.to_string_lossy().into_owned(),
            LINUX_CANARY_HELPER_ARGUMENT.to_owned(),
            "leader".to_owned(),
            "report".to_owned(),
            "-".to_owned(),
        ];
        expected_argv.extend(extra.iter().cloned());
        if report.argv == expected_argv {
            self.proven.insert(BackendControl::ExactArgv);
        } else {
            self.refusals.push(format!(
                "the exact argument vector did not reach the contained program: {:?}",
                report.argv
            ));
        }

        // ReplacedEnvironment: exactly the compiled set, nothing inherited.
        let observed = report
            .environment
            .iter()
            .map(|entry| (entry.name.clone(), entry.value.clone()))
            .collect::<BTreeMap<_, _>>();
        if observed == self.environment {
            self.proven.insert(BackendControl::ReplacedEnvironment);
        } else {
            self.refusals.push(format!(
                "the contained environment was {} entries rather than the exact compiled set of {}",
                observed.len(),
                self.environment.len()
            ));
        }

        // ClosedInheritedDescriptors: the target's own table is exactly the
        // standard three, and the controller held more than three at the
        // spawn, which is what makes that a shed rather than a coincidence.
        self.descriptor_closure = Some(LinuxDevelopmentDescriptorClosure {
            controller_descriptors: sealed.controller_descriptors,
            target_table: report.open_descriptors.clone(),
        });
        if report.open_descriptors == vec![0, 1, 2] && sealed.controller_descriptors > 3 {
            self.proven
                .insert(BackendControl::ClosedInheritedDescriptors);
        } else {
            self.refusals.push(format!(
                "the controller held {} descriptors and the target enumerated {:?}: that is \
                 not the exact standard set shed from a larger table",
                sealed.controller_descriptors, report.open_descriptors
            ));
        }

        // DescriptorWorkingDirectory: the child started at `/` and selected
        // its directory from the descriptor it was handed.
        if Path::new(&report.working_directory) == self.working_directory.as_path() {
            self.proven
                .insert(BackendControl::DescriptorWorkingDirectory);
        } else {
            self.refusals.push(format!(
                "the retained working-directory descriptor selected {} rather than {}",
                report.working_directory,
                self.working_directory.display()
            ));
        }

        // Control half of the wall clock: a canary that exits on its own
        // under the same generous deadline must not be reported as expired.
        if sealed.deadline_expired {
            self.refusals.push(
                "the wall-clock control canary expired even though it exited on its own".to_owned(),
            );
        }

        // DescriptorExec A/B: identical launch mechanism, one variable
        // changed. A sealed anonymous memfd has no pathname anywhere, so a
        // successful exec cannot have reopened a name; the named-image run
        // shows the observation is discriminating rather than constant.
        let named_domain = self.reserve(None, None, false)?;
        let named = self.run_canary(
            &named_domain,
            "report",
            "-",
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined),
        )?;
        drop(named_domain);
        let named_link = named
            .reports
            .first()
            .map(|entry| entry.executable_link.clone())
            .unwrap_or_default();
        self.exec_source = Some(LinuxDevelopmentExecSource {
            sealed_image_link: report.executable_link.clone(),
            named_image_link: named_link.clone(),
        });
        let sealed_is_anonymous = is_anonymous_image(&report.executable_link);
        let named_is_a_pathname = named_link.starts_with('/') && !is_anonymous_image(&named_link);
        if sealed_is_anonymous && named_is_a_pathname {
            self.proven.insert(BackendControl::DescriptorExec);
        } else {
            self.refusals.push(format!(
                "descriptor exec was not established: the sealed image executed as {} and the \
                 named image executed as {named_link}",
                report.executable_link
            ));
        }
        Ok(())
    }

    /// Two runs of the same argument vector under two ceilings.
    fn descendant_ceiling(&mut self) -> Result<(), SupervisorError> {
        let configured_processes = self.policy.contract().resource_limits.max_processes;
        let configured = u64::from(configured_processes);
        let parameter = LINUX_FORK_CANARY_CHILDREN.to_string();
        let confined = self.containment.clone();
        let control_domain = self.reserve(None, None, true)?;
        let control = self.run_canary(
            &control_domain,
            "fork",
            &parameter,
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined),
        )?;
        drop(control_domain);

        let restricted_domain = match self.reserve(Some(configured), None, true) {
            Ok(domain) => domain,
            Err(error) => {
                self.refusals.push(format!(
                    "the delegated cgroup could not install pids.max = {configured}: {error}"
                ));
                return Ok(());
            }
        };
        let read_back_pids_max = restricted_domain
            .read_back_pids_max()
            .unwrap_or_default()
            .to_owned();
        let restricted = self.run_canary(
            &restricted_domain,
            "fork",
            &parameter,
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined),
        )?;
        drop(restricted_domain);

        let control_spawned = control.reports.first().map_or(0, |entry| {
            u32::try_from(entry.spawned_children.len()).unwrap_or(0)
        });
        let restricted_report = restricted.reports.first().cloned();
        let restricted_spawned = restricted_report.as_ref().map_or(0, |entry| {
            u32::try_from(entry.spawned_children.len()).unwrap_or(0)
        });
        let restricted_errno = restricted_report
            .as_ref()
            .and_then(|entry| entry.spawn_failure_errno);
        let mut domain = LinuxDevelopmentDescendantDomain::empty(configured_processes);
        domain.read_back_pids_max.clone_from(&read_back_pids_max);
        domain.control_spawned = control_spawned;
        domain.restricted_spawned = restricted_spawned;
        domain.restricted_spawn_errno = restricted_errno;
        domain
            .restricted_pids_events
            .clone_from(&restricted.pids_events);

        // The ceiling charges the leader itself, so a request of N admits
        // exactly N - 1 descendants and refuses the rest with EAGAIN.
        let expected_restricted = configured_processes
            .saturating_sub(1)
            .min(LINUX_FORK_CANARY_CHILDREN);
        let ceiling_read_back = read_back_pids_max.trim() == configured.to_string();
        let refused_exactly = restricted_spawned == LINUX_FORK_CANARY_CHILDREN
            || restricted_errno == Some(LINUX_EAGAIN_ERRNO);
        if control_spawned == LINUX_FORK_CANARY_CHILDREN
            && ceiling_read_back
            && restricted_spawned == expected_restricted
            && refused_exactly
        {
            self.proven.insert(BackendControl::DescendantLimit);
        } else {
            self.refusals.push(format!(
                "the configured descendant ceiling of {configured_processes} was not kernel \
                 enforced: an unbounded leaf created {control_spawned} of \
                 {LINUX_FORK_CANARY_CHILDREN} children, the restricted leaf read pids.max back \
                 as {read_back_pids_max:?}, and the same vector created {restricted_spawned} \
                 with errno {restricted_errno:?} and pids.events {:?}",
                restricted.pids_events
            ));
        }
        self.descendant_domain = Some(domain);
        Ok(())
    }

    /// One kill against a domain that contains a session-escaped descendant.
    #[allow(
        clippy::too_many_lines,
        reason = "the escape observation, the membership read, the kill evidence, and the verdict stay in one visible order"
    )]
    fn domain_kill(&mut self) -> Result<(), SupervisorError> {
        let configured_processes = self.policy.contract().resource_limits.max_processes;
        let domain = match self.reserve(Some(LINUX_DOMAIN_KILL_PROBE_PIDS_MAX), None, true) {
            Ok(domain) => domain,
            Err(error) => {
                self.refusals.push(format!(
                    "the domain-kill probe could not reserve a leaf with pids.max = \
                     {LINUX_DOMAIN_KILL_PROBE_PIDS_MAX}: {error}"
                ));
                return Ok(());
            }
        };
        let confined = self.containment.clone();
        let observation = self.run_canary(
            &domain,
            "setsid",
            "-",
            &[],
            LINUX_CANARY_WALL_TIME,
            2,
            Some(2),
            Some(&confined),
        )?;
        drop(domain);

        let leader = observation
            .reports
            .iter()
            .find(|entry| entry.role == LinuxCanaryRoleV1::Leader)
            .cloned();
        let descendant = observation
            .reports
            .iter()
            .find(|entry| entry.role == LinuxCanaryRoleV1::Descendant)
            .cloned();
        let (Some(leader), Some(descendant)) = (leader, descendant) else {
            self.refusals.push(format!(
                "the domain-kill probe observed {} of 2 processes",
                observation.reports.len()
            ));
            return Ok(());
        };
        let survivors = host_wide_survivors(&[leader.pid, descendant.pid]);
        let escaped = descendant.process_group != leader.process_group
            && descendant.session != leader.session
            && descendant.process_group == descendant.pid
            && descendant.session == descendant.pid;
        let both_charged = observation.procs_at_report.contains(&leader.pid)
            && observation.procs_at_report.contains(&descendant.pid);
        let kill = observation.kill.clone();
        // `cgroup.procs` and `cgroup.events` are the immediate OS-owned
        // emptiness proof; `pids.current` settles to zero only once every
        // killed task has also been collected, so it is read separately.
        let emptied = kill.as_ref().is_some_and(|observed| {
            observed.populated_zero
                && observed.stable_empty_reads == 2
                && observed.surviving_processes == 0
        }) && observation.pids_current.trim() == "0";
        let mut retained = self
            .descendant_domain
            .take()
            .unwrap_or_else(|| LinuxDevelopmentDescendantDomain::empty(configured_processes));
        retained.leader_pid = leader.pid;
        retained.leader_process_group = leader.process_group;
        retained.leader_session = leader.session;
        retained.descendant_pid = descendant.pid;
        retained.descendant_process_group = descendant.process_group;
        retained.descendant_session = descendant.session;
        retained
            .membership_before_kill
            .clone_from(&observation.procs_at_report);
        retained.kill = kill;
        retained
            .settled_pids_current
            .clone_from(&observation.pids_current);
        retained.host_wide_survivors.clone_from(&survivors);
        if escaped && both_charged && emptied && survivors.is_empty() {
            self.proven.insert(BackendControl::DescendantDomainKill);
        } else {
            self.refusals.push(format!(
                "whole-domain emptiness was not proved: the descendant took process group {} \
                 and session {} against the leader's {}/{}, cgroup.procs held {:?}, the kill \
                 evidence was {:?}, pids.current settled at {:?}, and {} reported process(es) \
                 were still running afterwards",
                descendant.process_group,
                descendant.session,
                leader.process_group,
                leader.session,
                observation.procs_at_report,
                retained.kill,
                retained.settled_pids_current,
                survivors.len()
            ));
        }
        self.descendant_domain = Some(retained);
        Ok(())
    }

    /// A program that would never exit on its own, ended by the deadline.
    fn external_wall_clock(&mut self) -> Result<(), SupervisorError> {
        let confined = self.containment.clone();
        let domain = self.reserve(None, None, true)?;
        let observation = self.run_canary(
            &domain,
            "hold",
            "-",
            &[],
            LINUX_WALL_CLOCK_CANARY,
            1,
            None,
            Some(&confined),
        )?;
        drop(domain);
        let ended = match observation.exit {
            Some(CanaryExit::Exited(code)) => code != 0,
            Some(CanaryExit::Signaled(_)) | None => true,
        };
        if observation.deadline_expired && ended && observation.elapsed_ms < 20_000 {
            self.proven.insert(BackendControl::ExternalWallClock);
        } else {
            self.refusals.push(format!(
                "a {} ms deadline did not terminate a held canary: expired={} exit={:?} \
                 elapsed={} ms",
                LINUX_WALL_CLOCK_CANARY.as_millis(),
                observation.deadline_expired,
                observation.exit,
                observation.elapsed_ms
            ));
        }
        Ok(())
    }

    /// A payload larger than one poll chunk, drained completely.
    fn complete_bounded_output(&mut self) -> Result<(), SupervisorError> {
        let confined = self.containment.clone();
        let domain = self.reserve(None, None, true)?;
        let parameter = LINUX_BOUNDED_OUTPUT_BYTES.to_string();
        let observation = self.run_canary(
            &domain,
            "output",
            &parameter,
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined),
        )?;
        drop(domain);
        let expected = expected_payload_digest(LINUX_BOUNDED_OUTPUT_BYTES);
        if observation.payload_bytes == LINUX_BOUNDED_OUTPUT_BYTES
            && observation.payload_digest == expected
            && observation.payload_chunks > 1
            && observation.maximum_chunk_bytes <= CONTAINED_BACKEND_POLL_CHUNK_LIMIT
        {
            self.proven.insert(BackendControl::CompleteBoundedOutput);
        } else {
            self.refusals.push(format!(
                "bounded draining returned {} of {LINUX_BOUNDED_OUTPUT_BYTES} bytes in {} \
                 chunks with a largest chunk of {}",
                observation.payload_bytes,
                observation.payload_chunks,
                observation.maximum_chunk_bytes
            ));
        }
        Ok(())
    }

    /// The Landlock path layer, measured against its own control half.
    ///
    /// Two runs of the same canary against the same absolute path, in the
    /// same kind of leaf, differing in exactly one input: whether the
    /// Landlock ruleset is installed between the fork and the exec. If
    /// the path layer were not what refuses the write, the two runs could
    /// not differ at all.
    #[allow(
        clippy::too_many_lines,
        reason = "the vacuity control, the layer-removed control run, the confined run, and the verdict stay in one visible order"
    )]
    fn filesystem_policy(&mut self) -> Result<(), SupervisorError> {
        let escape = std::env::temp_dir().join(format!(
            "grok-build-linux-canary-escape-{}-{}",
            std::process::id(),
            self.runs
        ));
        remove_if_present(&escape)?;
        let escape_argument = escape
            .to_str()
            .ok_or_else(|| {
                SupervisorError::InvalidCommand("the Linux canary escape path must be UTF-8".into())
            })?
            .to_owned();
        // Vacuity control: without a writer that can reach this path at
        // all, a canary failing to reach it would prove nothing.
        let control_can_write =
            fs::write(&escape, b"grok-build-linux-canary-control\n").is_ok() && escape.is_file();
        remove_if_present(&escape)?;

        // Control half: the identical run with only the path layer removed.
        let control_policy = self.containment.without_filesystem_layer();
        let control_domain = self.reserve(None, None, true)?;
        let control_run = self.run_canary(
            &control_domain,
            "escape",
            &escape_argument,
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&control_policy),
        )?;
        drop(control_domain);
        let control_report = control_run.reports.first().cloned();
        let control_created = escape.is_file();
        remove_if_present(&escape)?;

        // Restricted half: the complete compiled path policy.
        let confined_policy = self.containment.clone();
        let confined_domain = self.reserve(None, None, true)?;
        let confined_run = self.run_canary(
            &confined_domain,
            "escape",
            &escape_argument,
            &[],
            LINUX_CANARY_WALL_TIME,
            1,
            None,
            Some(&confined_policy),
        )?;
        drop(confined_domain);
        let confined_report = confined_run.reports.first().cloned();
        let confined_created = escape.is_file();
        remove_if_present(&escape)?;

        let mut surface = self.unconfined_surface.take().unwrap_or_default();
        surface.escape_write_succeeded = control_report
            .as_ref()
            .and_then(|entry| entry.escape_write_succeeded);
        surface.escape_write_errno = control_report
            .as_ref()
            .and_then(|entry| entry.escape_write_errno);
        surface.escape_file_created = control_created;
        surface.confined_escape_write_succeeded = confined_report
            .as_ref()
            .and_then(|entry| entry.escape_write_succeeded);
        surface.confined_escape_write_errno = confined_report
            .as_ref()
            .and_then(|entry| entry.escape_write_errno);
        surface.confined_escape_file_created = confined_created;
        surface.confined_escape_landlock_installed = confined_run
            .containment
            .as_ref()
            .is_some_and(|evidence| evidence.landlock_installed);
        let control_layer_absent = !control_run
            .containment
            .as_ref()
            .is_some_and(|evidence| evidence.landlock_installed);

        let denied_by_policy = surface.confined_escape_write_succeeded == Some(false)
            && matches!(
                surface.confined_escape_write_errno,
                Some(LINUX_EPERM_ERRNO | LINUX_EACCES_ERRNO | LINUX_EROFS_ERRNO)
            );
        if !control_can_write {
            self.refusals.push(format!(
                "the filesystem escape probe was vacuous: this controller could not itself \
                 create {} outside every compiled write scope, so a canary failing to do so \
                 would prove nothing",
                escape.display()
            ));
        } else if !surface.confined_escape_landlock_installed || !control_layer_absent {
            self.refusals.push(format!(
                "the filesystem A/B pair did not vary the path layer alone: the control run \
                 reported landlock installed {:?} and the confined run reported {}",
                control_run
                    .containment
                    .as_ref()
                    .map(|evidence| evidence.landlock_installed),
                surface.confined_escape_landlock_installed
            ));
        } else if surface.escape_write_succeeded != Some(true) || !surface.escape_file_created {
            self.refusals.push(format!(
                "the filesystem control half did not reach the escape path either (write \
                 succeeded {:?}, errno {:?}, file present {}), so a refusal under the path \
                 layer would not be attributable to it",
                surface.escape_write_succeeded,
                surface.escape_write_errno,
                surface.escape_file_created
            ));
        } else if surface.confined_escape_write_succeeded.is_none() {
            self.refusals.push(
                "the confined filesystem escape canary produced no observation, and an absent \
                 measurement is never evidence of confinement"
                    .to_owned(),
            );
        } else if denied_by_policy && !surface.confined_escape_file_created {
            self.proven.insert(BackendControl::FilesystemPolicy);
        } else {
            self.refusals.push(format!(
                "the compiled filesystem policy is not enforced: with the Landlock ruleset \
                 installed a canary still reached {} outside every compiled write scope \
                 (write succeeded {:?}, errno {:?}, file present {})",
                escape.display(),
                surface.confined_escape_write_succeeded,
                surface.confined_escape_write_errno,
                surface.confined_escape_file_created
            ));
        }
        self.unconfined_surface = Some(surface);
        Ok(())
    }

    /// The seccomp syscall layer, measured against its own control half.
    ///
    /// Two runs against two equivalent controller-owned loopback
    /// listeners, differing in exactly one input: whether the compiled
    /// BPF filter is installed between the fork and the exec.
    #[allow(
        clippy::too_many_lines,
        reason = "the layer-removed control run, the confined run, and both directions of the compiled network mode stay in one visible order"
    )]
    fn network_policy(&mut self) -> Result<(), SupervisorError> {
        let network_mode_allows = self.policy.contract().network == ExecutionNetwork::FullForAction;
        // Control half: the identical run with only the syscall layer
        // removed. Under a compiled mode that grants the network there is
        // no syscall layer to remove and the two halves coincide.
        let control_policy = self.containment.without_network_layer();
        let control = self.loopback_probe(&control_policy)?;
        let confined_policy = self.containment.clone();
        let confined = self.loopback_probe(&confined_policy)?;

        let mut surface = self.unconfined_surface.take().unwrap_or_default();
        surface.network_mode_allows = network_mode_allows;
        surface.loopback_connect_succeeded = control
            .report
            .as_ref()
            .and_then(|entry| entry.loopback_connect_succeeded);
        surface.loopback_connect_errno = control
            .report
            .as_ref()
            .and_then(|entry| entry.loopback_connect_errno);
        surface.loopback_listener_accepted = control.listener_accepted;
        surface.confined_loopback_connect_succeeded = confined
            .report
            .as_ref()
            .and_then(|entry| entry.loopback_connect_succeeded);
        surface.confined_loopback_connect_errno = confined
            .report
            .as_ref()
            .and_then(|entry| entry.loopback_connect_errno);
        surface.confined_loopback_listener_accepted = confined.listener_accepted;
        surface.confined_loopback_seccomp_installed = confined.seccomp_installed;

        let control_reached =
            surface.loopback_connect_succeeded == Some(true) && control.listener_accepted;
        let confined_reached =
            surface.confined_loopback_connect_succeeded == Some(true) && confined.listener_accepted;
        // The filter was compiled to return exactly this errno, and it is
        // deliberately not the `EACCES` a denied path produces, so the
        // number a canary reports names the layer that refused it.
        let expected_network_errno =
            i32::try_from(LINUX_SECCOMP_NETWORK_ERRNO).unwrap_or(LINUX_EPERM_ERRNO);
        let denied_by_policy = surface.confined_loopback_connect_succeeded == Some(false)
            && surface.confined_loopback_connect_errno == Some(expected_network_errno)
            && matches!(
                surface.confined_loopback_connect_errno,
                Some(LINUX_EPERM_ERRNO | LINUX_EACCES_ERRNO)
            );
        if !control.controller_reachable {
            self.refusals.push(
                "the loopback probe was vacuous: this controller could not reach its own \
                 listener, so a canary failing to reach it would prove nothing"
                    .to_owned(),
            );
        } else if network_mode_allows {
            // The compiled mode grants the network, so the control is the
            // deny direction: reaching the listener is the claim itself.
            if confined_reached {
                self.proven.insert(BackendControl::NetworkPolicy);
            } else {
                self.refusals.push(format!(
                    "the compiled network mode grants action network but a canary could not \
                     reach the controller's listener (connect {:?}, errno {:?})",
                    surface.confined_loopback_connect_succeeded,
                    surface.confined_loopback_connect_errno
                ));
            }
        } else if !surface.confined_loopback_seccomp_installed || control.seccomp_installed {
            self.refusals.push(format!(
                "the network A/B pair did not vary the syscall layer alone: the control run \
                 reported seccomp installed {} and the confined run reported {}",
                control.seccomp_installed, surface.confined_loopback_seccomp_installed
            ));
        } else if !control_reached {
            self.refusals.push(format!(
                "the network control half did not reach the listener either (connect {:?}, \
                 errno {:?}, listener accepted {}), so a refusal under the syscall layer \
                 would not be attributable to it",
                surface.loopback_connect_succeeded,
                surface.loopback_connect_errno,
                surface.loopback_listener_accepted
            ));
        } else if surface.confined_loopback_connect_succeeded.is_none() {
            self.refusals.push(
                "the confined loopback canary produced no observation, and an absent \
                 measurement is never evidence of a network boundary"
                    .to_owned(),
            );
        } else if denied_by_policy && !surface.confined_loopback_listener_accepted {
            self.proven.insert(BackendControl::NetworkPolicy);
        } else {
            self.refusals.push(format!(
                "the compiled network mode denies the network but a canary with the seccomp \
                 filter installed still observed reachability {confined_reached} (connect \
                 {:?}, errno {:?}, listener accepted {})",
                surface.confined_loopback_connect_succeeded,
                surface.confined_loopback_connect_errno,
                surface.confined_loopback_listener_accepted
            ));
        }
        self.unconfined_surface = Some(surface);
        Ok(())
    }

    /// One loopback run against one controller-owned listener.
    fn loopback_probe(
        &mut self,
        containment: &LinuxContainmentPolicy,
    ) -> Result<LinuxLoopbackProbe, SupervisorError> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_for_thread = Arc::clone(&accepted);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let deadline = Instant::now() + LINUX_CANARY_WALL_TIME;
            while Instant::now() < deadline && !stop_for_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        accepted_for_thread.store(true, Ordering::Release);
                        let mut request = [0_u8; 64];
                        let _ignored = stream.read(&mut request);
                        return;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(_) => return,
                }
            }
        });
        // Vacuity control: this controller reaches an equivalent listener
        // it binds itself, so the canary still meets one that accepted
        // nothing.
        let controller_reachable = control_loopback_reachable();
        let parameter = port.to_string();
        let outcome = self.reserve(None, None, true).and_then(|domain| {
            let observation = self.run_canary(
                &domain,
                "connect",
                &parameter,
                &[],
                LINUX_CANARY_WALL_TIME,
                1,
                None,
                Some(containment),
            )?;
            drop(domain);
            Ok(observation)
        });
        // A connection can complete through the listen backlog before the
        // accept loop returns it, and the canary exits as soon as it has
        // connected. Without this bounded grace the server can be stopped
        // between those two moments, which would report a completed
        // connection as unaccepted.
        let grace = Instant::now() + Duration::from_secs(2);
        while !accepted.load(Ordering::Acquire) && Instant::now() < grace {
            thread::sleep(POLL_INTERVAL);
        }
        stop.store(true, Ordering::Release);
        server.join().map_err(|_ignored| {
            SupervisorError::Canary("the Linux canary loopback server panicked".into())
        })?;
        let observation = outcome?;
        Ok(LinuxLoopbackProbe {
            report: observation.reports.first().cloned(),
            listener_accepted: accepted.load(Ordering::Acquire),
            controller_reachable,
            seccomp_installed: observation
                .containment
                .as_ref()
                .is_some_and(|evidence| evidence.seccomp_installed),
        })
    }

    /// A finite aggregate memory ceiling, when the policy asks for one.
    fn memory_ceiling(&mut self) -> Result<(), SupervisorError> {
        let Some(limit) = self.policy.contract().resource_limits.max_memory_bytes else {
            return Ok(());
        };
        let mebibytes = (limit / (1_024 * 1_024)).saturating_mul(4).max(8);
        let parameter = mebibytes.to_string();
        let confined = self.containment.clone();
        let control_domain = self.reserve(None, None, true)?;
        let control = self.run_canary(
            &control_domain,
            "memory",
            &parameter,
            &[],
            LINUX_CANARY_WALL_TIME,
            2,
            None,
            Some(&confined),
        )?;
        drop(control_domain);

        let restricted_domain = match self.reserve(None, Some(limit), true) {
            Ok(domain) => domain,
            Err(error) => {
                self.refusals.push(format!(
                    "the delegated cgroup could not install memory.max = {limit}: {error}"
                ));
                return Ok(());
            }
        };
        let read_back = restricted_domain
            .read_back_memory_max()
            .unwrap_or_default()
            .to_owned();
        let restricted = self.run_canary(
            &restricted_domain,
            "memory",
            &parameter,
            &[],
            LINUX_CANARY_WALL_TIME,
            2,
            None,
            Some(&confined),
        )?;
        drop(restricted_domain);

        let control_completed = control.reports.len() == 2;
        let restricted_stopped = restricted.reports.len() < 2;
        let oom_killed = restricted
            .memory_events
            .lines()
            .filter_map(|line| line.strip_prefix("oom_kill "))
            .filter_map(|value| value.trim().parse::<u64>().ok())
            .any(|count| count > 0);
        if control_completed
            && restricted_stopped
            && oom_killed
            && read_back.trim() == limit.to_string()
        {
            self.proven.insert(BackendControl::MemoryLimit);
        } else {
            self.refusals.push(format!(
                "the finite memory ceiling of {limit} was not proved for the whole domain: the \
                 unbounded leaf completed {control_completed}, the bounded leaf read \
                 memory.max back as {read_back:?}, produced {} reports, and its memory.events \
                 were {:?}",
                restricted.reports.len(),
                restricted.memory_events
            ));
        }
        Ok(())
    }
}

fn development_environment(
    command: &PreparedContainedCommand,
) -> Result<BTreeMap<String, String>, SupervisorError> {
    let mut environment = BTreeMap::new();
    for (name, value) in command.environment() {
        let name = name.to_str().ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "a contained environment name must be UTF-8 for the Linux canary domain".into(),
            )
        })?;
        let value = value.to_str().ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "a contained environment value must be UTF-8 for the Linux canary domain".into(),
            )
        })?;
        environment.insert(name.to_owned(), value.to_owned());
    }
    Ok(environment)
}

/// Whether this process can reach a loopback listener it binds itself.
///
/// The probe is deliberately independent of the canary's listener so the
/// canary still meets one that has accepted nothing.
fn control_loopback_reachable() -> bool {
    let Ok(listener) = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let Ok(address) = listener.local_addr() else {
        return false;
    };
    let connected = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2));
    connected.is_ok() && listener.accept().is_ok()
}

fn linux_dev_domain_error(error: &LinuxDevDomainError) -> SupervisorError {
    SupervisorError::Capability(format!("development Linux cgroup-v2 domain: {error}"))
}

/// Whether `/proc/self/exe` named an anonymous in-memory image.
fn is_anonymous_image(link: &str) -> bool {
    link.starts_with("/memfd:") || link.starts_with("memfd:")
}

fn expected_payload_digest(bytes: u64) -> String {
    let mut hasher = Sha256::new();
    let mut chunk = Vec::with_capacity(4_096);
    let mut offset = 0_u64;
    while offset < bytes {
        chunk.clear();
        let remaining = bytes - offset;
        let length = remaining.min(4_096);
        for index in 0..length {
            chunk.push(payload_byte(offset + index));
        }
        hasher.update(&chunk);
        offset += length;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ignored = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

/// Reported PIDs that are still running processes anywhere on the host.
///
/// A reaped or zombie process is not a survivor: it holds no cgroup
/// membership and cannot run code. Everything else is counted.
fn host_wide_survivors(pids: &[u32]) -> Vec<u32> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut survivors = pids.to_vec();
    loop {
        survivors.retain(|pid| is_live_process(*pid));
        if survivors.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    survivors
}

fn is_live_process(pid: u32) -> bool {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // The kernel writes the process state immediately after the last `)`,
    // which is the only parse position the comm field cannot forge.
    let Some(position) = status.rfind(')') else {
        return false;
    };
    status[position + 1..]
        .split_whitespace()
        .next()
        .is_some_and(|state| state != "Z" && state != "X")
}

fn linux_cgroup_v2_development_implementation_digest() -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(
        &mut hasher,
        LINUX_CGROUP_V2_DEVELOPMENT_IMPLEMENTATION_DOMAIN,
    );
    hash_frame(&mut hasher, LINUX_CGROUP_V2_DEV_BACKEND_ID.as_bytes());
    digest_from_sha(hasher.finalize().into())
}

include!("linux_backend/production.rs");
