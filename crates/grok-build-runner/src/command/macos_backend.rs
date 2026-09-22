use super::contained_boundary::{
    BackendCanaryStatus, BackendControl, BackendIdentity, BackendPreflightReport,
    ContainedCommandBackend, ContainedDescendantDomain, DomainObservation,
    DomainTerminationRequest, DurablyAnchoredCapture, PreparedContainedCommand,
    ValidatedBackendPermit, required_controls,
};
#[allow(
    clippy::wildcard_imports,
    reason = "the nested macOS backend intentionally shares only this parent module's private audited primitives"
)]
use super::*;
use crate::macos_dev_helper::{
    MACOS_DEVELOPMENT_PROFILE_APPLIER, MAX_MACOS_DEVELOPMENT_CHUNK_BYTES,
    MacosDevelopmentHelperClient, MacosDevelopmentHelperError, MacosDevelopmentHelperPlan,
    MacosDevelopmentHelperSession, MacosDevelopmentProfileApplier, MacosDevelopmentRunOutcome,
    MacosDevelopmentRunPurpose, MacosDevelopmentRunSpecification,
    available_development_helper_topology,
};
use crate::macos_helper_protocol::{MACOS_HELPER_PROTOCOL_VERSION, MacosHelperNetwork};

/// Immutable identifier of this backend implementation generation.
pub(crate) const MACOS_DEDICATED_IDENTITY_BACKEND_ID: &str = "macos-dedicated-identity-v1";

const MACOS_DEDICATED_IDENTITY_IMPLEMENTATION_DOMAIN: &[u8] =
    b"grok-build/macos-dedicated-identity-backend/v1";

/// Exact reason this backend cannot yet authorize a contained launch.
///
/// ADR-0006 selects the signed dedicated-identity helper as the only macOS
/// launch bridge. Until that transport exists the backend holds no reserved
/// identity, cannot perform a held descriptor-exec, cannot install a
/// kernel-enforced descendant limit, and cannot prove a whole-domain kill.
/// Reporting anything other than a refusal here would be a false control
/// claim, so every launch-path method returns this typed capability error.
pub(crate) const MACOS_DEDICATED_IDENTITY_TRANSPORT_UNAVAILABLE: &str = "the macOS dedicated-identity helper transport is not installed; this backend holds no reserved execution identity and therefore enforces none of the mandatory contained-execution controls";

/// Why an unprivileged run cannot mint contained terminal evidence.
///
/// This used to be a signing obstruction: `from_macos_candidate` validated
/// an admission session that had to be `production_signed`, so no
/// build-from-source installation could ever reach terminal evidence.
/// ADR-0012 removed that; a locally attested session now closes the chain,
/// which is proved in `cleanup_proof`'s
/// `a_locally_attested_admission_session_closes_the_macos_terminal_evidence_chain`.
///
/// What remains is host authority, and it is not repairable by any
/// certificate. `MacosCleanupEvidence` requires a `MacosAssignedIdentity`:
/// a named, non-root, locked local account whose real UID the helper
/// enumerates to prove the domain empty. Creating such an account needs
/// root, so the unprivileged pool has none — `dedicated_account` is
/// validated to be `false` on every record it issues — and nothing in that
/// module produces the production identity type. Constructing one anyway
/// would be the exact substitution the contract exists to prevent.
pub(crate) const MACOS_DEVELOPMENT_CLEANUP_PROOF_UNAVAILABLE: &str = "an unprivileged dedicated-identity run cannot mint a command-domain cleanup proof: the only macOS constructor requires an assigned local execution account, whose creation needs root, and the unprivileged identity pool is validated to own none";

/// Composed macOS containment backend for one contained command.
///
/// Every field is authority the supervisor already validated. The backend
/// derives its Seatbelt profile from that authority with the audited
/// [`render_seatbelt_profile`] renderer, and refuses the launch path with
/// [`MACOS_DEDICATED_IDENTITY_TRANSPORT_UNAVAILABLE`] because the helper
/// transport that would enforce the remaining controls does not exist yet.
pub(crate) struct MacosDedicatedIdentityBackend {
    grant: IssuedWorkspaceGrant,
    policy: CompiledExecutionPolicy,
    live_root: PathBuf,
    private_state_root: PathBuf,
    execution_root: PathBuf,
    mode: MacosDedicatedIdentityMode,
}

impl fmt::Debug for MacosDedicatedIdentityBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosDedicatedIdentityBackend")
            .field("backend_id", &self.backend_id())
            .field("grant_hash", &self.grant.contract().grant_hash)
            .field("policy_hash", &self.policy.contract().policy_hash)
            .field("live_root", &self.live_root)
            .field("private_state_root", &self.private_state_root)
            .field("execution_root", &self.execution_root)
            .field("mode", &self.mode)
            .finish()
    }
}

impl MacosDedicatedIdentityBackend {
    /// Composes the backend from the same authority that prepared the command.
    ///
    /// Resource ceilings are deliberately not re-validated here. The
    /// legacy [`validate_resource_limits`] check encodes what the
    /// path-based Seatbelt adapter alone can prove (`max_processes == 1`
    /// via `deny process-fork`); the contained boundary owns the ceiling
    /// contract for this backend and has already applied it during
    /// preparation. This backend must not borrow the other adapter's
    /// proof by assertion either: its development arm re-establishes the
    /// same fact with its own three-run canary before claiming anything,
    /// and claims a descendant ceiling only for the one value that
    /// mechanism can express.
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
                "the macOS dedicated-identity backend requires a private shadow execution root"
                    .into(),
            )
        })?;
        Ok(Self {
            grant,
            policy,
            live_root,
            private_state_root,
            execution_root,
            mode: MacosDedicatedIdentityMode::Production,
        })
    }

    /// Identifier of the exact backend generation this instance is.
    pub(crate) const fn backend_id(&self) -> &'static str {
        match self.mode {
            MacosDedicatedIdentityMode::Production => MACOS_DEDICATED_IDENTITY_BACKEND_ID,
            MacosDedicatedIdentityMode::Development(_) => MACOS_DEDICATED_IDENTITY_DEV_BACKEND_ID,
        }
    }

    /// Returns the exact Seatbelt profile this backend would install.
    ///
    /// The profile is compiled from the authority's retained roots with the
    /// audited renderer: only the resolved executable may be executed, only
    /// compiled read scopes are readable, only compiled write scopes are
    /// writable, credential roots and every `.git` path are denied, and the
    /// network follows the compiled execution-network mode.
    ///
    /// Rendering succeeding proves the profile compiles; it does not prove
    /// the profile is installed, so it never authorizes a control claim on
    /// its own.
    ///
    /// # Errors
    ///
    /// Fails when a retained path is not UTF-8 or contains control bytes.
    pub(crate) fn render_profile_for(&self, program: &Path) -> Result<String, SupervisorError> {
        let executables = BTreeSet::from([program.to_path_buf()]);
        let readable = scope_paths(&self.execution_root, &self.policy.contract().read_scopes);
        let writable = scope_paths(&self.execution_root, &self.policy.contract().write_scopes);
        let mut denied = credential_roots();
        push_denied_root(&mut denied, self.live_root.join(".git"));
        push_denied_root(&mut denied, self.execution_root.join(".git"));
        push_denied_root(&mut denied, self.private_state_root.join(".git"));
        render_seatbelt_profile(
            &executables,
            &readable,
            &writable,
            &denied,
            &self.live_root,
            self.policy.contract().network == ExecutionNetwork::FullForAction,
        )
    }

    /// Returns exactly the controls this backend generation truly enforces.
    ///
    /// For the production arm the set is empty and stays empty: the signed
    /// helper transport does not exist, so with no reserved identity and no
    /// held launch there is nothing enforcing descriptor-exec,
    /// descriptor-relative cwd, closed inherited descriptors, the
    /// filesystem or network policy, an external wall clock, bounded output
    /// drain, the descendant limit, whole-domain kill, or same-generation
    /// escape canaries.
    ///
    /// For the development arm the set is whatever the live canary suite
    /// established inside the reserved development identity generation,
    /// and is empty until that suite has run. Nothing here is a static
    /// capability detection or a compiled-in list: every element was put
    /// there by a probe that observed the control working on this host.
    pub(crate) fn enforced_controls(&self) -> BTreeSet<BackendControl> {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => BTreeSet::new(),
            MacosDedicatedIdentityMode::Development(state) => state.proven.clone(),
        }
    }

    /// Builds the typed refusal naming every control that is still missing.
    fn transport_unavailable(&self) -> SupervisorError {
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
        SupervisorError::Capability(format!(
            "{MACOS_DEDICATED_IDENTITY_TRANSPORT_UNAVAILABLE}: cannot enforce {missing:?}"
        ))
    }
}

/// Live descendant domain owned by a launched dedicated identity.
///
/// The signed helper transport is the only value source for this type, so
/// the enumeration is deliberately empty until that transport lands. Every
/// method is total over the inhabitants that exist, which is none; the
/// backend can therefore refuse honestly without `todo!`, `unimplemented!`,
/// or a fabricated observation.
pub(crate) enum MacosDedicatedIdentityDomain {}

impl ContainedDescendantDomain for MacosDedicatedIdentityDomain {
    fn poll(&mut self, _maximum_chunk_bytes: usize) -> Result<DomainObservation, SupervisorError> {
        match *self {}
    }

    fn terminate_all(&mut self, _reason: DomainTerminationRequest) -> Result<(), SupervisorError> {
        match *self {}
    }

    fn into_cleanup_proof(self) -> Result<ValidatedCommandDomainCleanupProof, SupervisorError> {
        match self {}
    }
}

impl ContainedCommandBackend for MacosDedicatedIdentityBackend {
    type Domain = MacosDedicatedIdentityDomain;

    fn identity(&self) -> Result<BackendIdentity, SupervisorError> {
        validate_authority(&self.grant, &self.policy)?;
        let implementation_digest = match self.mode {
            MacosDedicatedIdentityMode::Production => {
                macos_dedicated_identity_implementation_digest()
            }
            MacosDedicatedIdentityMode::Development(_) => {
                macos_development_identity_implementation_digest()
            }
        };
        Ok(BackendIdentity::new(
            CommandDomainCleanupBackend::MacOsDedicatedIdentity,
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
                "macOS dedicated-identity backend was composed from different command authority"
                    .into(),
            ));
        }
        if command.execution_root_path() != self.execution_root {
            return Err(SupervisorError::Authority(
                "macOS dedicated-identity backend was composed for a different execution root"
                    .into(),
            ));
        }
        // Real composed work: the profile this backend would install must
        // compile from the retained authority before anything else is
        // considered. It is deliberately not treated as evidence.
        let _profile = self.render_profile_for(command.executable_path())?;
        match self.mode {
            // No reserved identity exists, so no same-generation canary
            // suite can run and no control can be claimed truthfully.
            MacosDedicatedIdentityMode::Production => Err(self.transport_unavailable()),
            // The development helper reserves an identity generation, runs
            // the live canary suite inside it, and reports exactly what
            // those canaries proved.
            MacosDedicatedIdentityMode::Development(_) => self.development_preflight(command),
        }
    }

    fn launch(
        &mut self,
        command: PreparedContainedCommand,
        permit: ValidatedBackendPermit,
        output_capture: &DurablyAnchoredCapture,
    ) -> Result<Self::Domain, SupervisorError> {
        // The supervisor never reaches this arm because `active_preflight`
        // refuses first; the single-use permit and the moved authority are
        // still dropped here rather than retained or partially consumed.
        drop(command);
        drop(permit);
        let _ = output_capture;
        match self.mode {
            MacosDedicatedIdentityMode::Production => Err(self.transport_unavailable()),
            MacosDedicatedIdentityMode::Development(_) => Err(SupervisorError::Capability(
                MACOS_DEVELOPMENT_CLEANUP_PROOF_UNAVAILABLE.into(),
            )),
        }
    }
}

fn macos_dedicated_identity_implementation_digest() -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, MACOS_DEDICATED_IDENTITY_IMPLEMENTATION_DOMAIN);
    hash_frame(&mut hasher, MACOS_DEDICATED_IDENTITY_BACKEND_ID.as_bytes());
    hash_frame(&mut hasher, &MACOS_HELPER_PROTOCOL_VERSION.to_be_bytes());
    digest_from_sha(hasher.finalize().into())
}
/// Immutable identifier of the *development* backend generation.
///
/// It is deliberately a different string from
/// [`MACOS_DEDICATED_IDENTITY_BACKEND_ID`]. The backend identity travels
/// into every permit, every piece of contained evidence, and every
/// terminal response, so a development run is distinguishable from a
/// production run at every one of those points without reading a flag.
pub(crate) const MACOS_DEDICATED_IDENTITY_DEV_BACKEND_ID: &str =
    "macos-dedicated-identity-development-v1";

const MACOS_DEVELOPMENT_IMPLEMENTATION_DOMAIN: &[u8] =
    b"grok-build/macos-dedicated-identity-development-backend/v1";
const MACOS_DEVELOPMENT_CANARY_DOMAIN: &[u8] =
    b"grok-build/macos-dedicated-identity-development-canaries/v1";

/// Canary wall-clock allowance, generous enough for a cold `curl`.
const DEVELOPMENT_CANARY_WALL_TIME_MS: u64 = 8_000;
/// Deliberately short allowance used only by the wall-clock canary.
const DEVELOPMENT_WALL_CLOCK_CANARY_MS: u64 = 400;
/// Output ceiling for one canary run.
const DEVELOPMENT_CANARY_OUTPUT_BYTES: u64 = 256 * 1_024;
/// Bytes the bounded-output canary streams through the helper.
const DEVELOPMENT_BOUNDED_OUTPUT_BYTES: usize = 40 * 1_024;
/// Exact number of contained runs one complete canary suite performs.
const EXPECTED_DEVELOPMENT_CANARY_RUNS: usize = 13;

/// Which topology one composed backend belongs to.
///
/// Production is the default and is unchanged by the development arm: it
/// holds no client, runs no canary, claims no control, and refuses every
/// launch-path method exactly as it did before this mode existed.
pub(crate) enum MacosDedicatedIdentityMode {
    /// The signed, notarized, `SMAppService`-registered helper. Absent.
    Production,
    /// The separately named development helper from the architecture doc.
    Development(Box<MacosDevelopmentBackendState>),
}

impl fmt::Debug for MacosDedicatedIdentityMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => formatter.write_str("Production"),
            Self::Development(state) => formatter
                .debug_struct("Development")
                .field("proven_controls", &state.proven)
                .field("refusals", &state.refusals)
                .finish(),
        }
    }
}

/// Everything the development arm learns at run time.
///
/// `proven` starts empty and is only ever replaced by the exact set the
/// live canary suite established in the reserved identity generation. No
/// code path inserts a control without a canary having returned a definite
/// result for it.
pub(crate) struct MacosDevelopmentBackendState {
    plan: MacosDevelopmentCanaryPlan,
    client: Option<MacosDevelopmentHelperClient>,
    proven: BTreeSet<BackendControl>,
    refusals: Vec<String>,
    canary_digest: Option<Digest>,
    /// How the helper applied the profile for the runs in this generation,
    /// observed from the evidence rather than configured.
    profile_applier: Option<MacosDevelopmentProfileApplier>,
    /// The exact descriptor observation behind the
    /// `ClosedInheritedDescriptors` verdict.
    descriptor_closure: Option<MacosDevelopmentDescriptorClosure>,
    /// The exact observation behind the `DescendantLimit` and
    /// `DescendantDomainKill` verdicts.
    descendant_domain: Option<MacosDevelopmentDescendantDomain>,
}

/// Three-point isolation of the Seatbelt profile's own fork refusal.
///
/// One run is not evidence: a restrictive profile denies many things at
/// once, so a failure under it could be a denied read, a denied exec, or a
/// denied fork. These three runs of the *same* program vary exactly one
/// thing at a time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MacosDevelopmentForkDenial {
    /// A permissive profile ran the forking argv to success.
    pub(crate) control_forked: bool,
    /// The restrictive profile still ran the same program when the argv
    /// asked it to create no child, so the profile is otherwise viable.
    pub(crate) restricted_ran_without_forking: bool,
    /// The restrictive profile ran the forking argv to success. This must
    /// be false, and it is the only variable that changed between the two
    /// restrictive runs.
    pub(crate) restricted_forked: bool,
}

impl MacosDevelopmentForkDenial {
    /// Whether the profile alone refused process creation.
    pub(crate) const fn refuses_process_creation(self) -> bool {
        self.control_forked && self.restricted_ran_without_forking && !self.restricted_forked
    }
}

/// What one real cancellation did to one domain, as the kernel reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosDevelopmentCancellation {
    pub(crate) leader_pid: u32,
    pub(crate) leader_process_group: u32,
    /// Whether the leader was its own session leader while still held. A
    /// session leader cannot leave its own process group: `setsid` and
    /// `setpgid` both fail `EPERM` for it.
    pub(crate) leader_session_leader: bool,
    /// Whether the external deadline, not the program, ended the run.
    pub(crate) terminated_by_deadline: bool,
    /// Processes the operating system still charged to the domain after
    /// termination.
    pub(crate) survivors: Vec<u32>,
}

/// Everything behind this host's descendant-limit and domain-kill verdicts.
///
/// Retained whole so a test can assert the numbers that produced a verdict
/// rather than infer the verdict from set membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosDevelopmentDescendantDomain {
    /// The ceiling the command's own compiled policy configures.
    pub(crate) configured_max_processes: u32,
    /// Whether the assigned identity was an otherwise-unused account, which
    /// is the only mechanism that makes `RLIMIT_NPROC` a domain ceiling.
    pub(crate) dedicated_account: bool,
    /// Whether a per-UID `RLIMIT_NPROC` equal to the request was installed.
    pub(crate) rlimit_nproc_applied: bool,
    /// Processes the shared real UID already owns.
    pub(crate) real_uid_process_count: u32,
    /// That UID's current soft `RLIMIT_NPROC`.
    pub(crate) rlimit_nproc_soft: u64,
    /// The Seatbelt profile's own fork verdict, or `None` if the probe
    /// could not complete.
    pub(crate) fork_denial: Option<MacosDevelopmentForkDenial>,
    /// The cancellation observation, or `None` if that probe did not run.
    pub(crate) cancellation: Option<MacosDevelopmentCancellation>,
}

/// The complete observation one descriptor-closure canary produced.
///
/// Retained so a test can assert the exact numbers rather than infer them
/// from whether a control ended up in the proven set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MacosDevelopmentDescriptorClosure {
    /// Descriptors the launching component itself held at the fork.
    pub(crate) launcher_descriptors: u32,
    /// Threads the launching component had at the fork.
    pub(crate) launcher_threads: u32,
    /// The child's complete descriptor table at its `execve` boundary.
    pub(crate) boundary_table: Vec<u32>,
    /// What the target itself enumerated from `/dev/fd` after exec.
    pub(crate) target_listing: Vec<u32>,
}

/// Fixed inputs the development canary suite needs before it can run.
#[derive(Clone, Debug)]
struct MacosDevelopmentCanaryPlan {
    canary_root: PathBuf,
    runner_session_id: String,
}

/// One canary program the development manifest admits.
#[derive(Clone, Copy, Debug)]
struct DevelopmentCanaryProgram {
    entry: &'static str,
    path: &'static str,
}

/// The complete, fixed development canary program table.
///
/// A caller cannot add an executable search root: the development helper
/// admits exactly these entries plus the one command executable the
/// backend resolved from validated authority.
const DEVELOPMENT_CANARY_PROGRAMS: [DevelopmentCanaryProgram; 10] = [
    DevelopmentCanaryProgram {
        entry: "system-touch",
        path: CANARY_TOUCH,
    },
    DevelopmentCanaryProgram {
        entry: "system-find",
        path: CANARY_FIND,
    },
    DevelopmentCanaryProgram {
        entry: "system-cat",
        path: CANARY_CAT,
    },
    DevelopmentCanaryProgram {
        entry: "system-curl",
        path: CANARY_CURL,
    },
    DevelopmentCanaryProgram {
        entry: "system-echo",
        path: "/bin/echo",
    },
    DevelopmentCanaryProgram {
        entry: "system-env",
        path: "/usr/bin/env",
    },
    DevelopmentCanaryProgram {
        entry: "system-ls",
        path: "/bin/ls",
    },
    DevelopmentCanaryProgram {
        entry: "system-pwd",
        path: "/bin/pwd",
    },
    DevelopmentCanaryProgram {
        entry: "system-sleep",
        path: "/bin/sleep",
    },
    DevelopmentCanaryProgram {
        entry: "system-true",
        path: CANARY_TRUE,
    },
];

/// Policy-entry identifier of the one command executable.
const DEVELOPMENT_COMMAND_ENTRY: &str = "command-executable";

impl MacosDedicatedIdentityBackend {
    /// Composes the **development** dedicated-identity backend.
    ///
    /// This constructor is the architecture document's sanctioned
    /// development build and nothing more. It shares every authority check
    /// with [`MacosDedicatedIdentityBackend::new`] and differs afterwards
    /// in exactly three ways: it reports a development backend identity, it
    /// starts the separately named development helper on first preflight,
    /// and it claims only the controls that helper's live canaries proved
    /// inside the reserved development identity generation.
    ///
    /// It can never become the production path, and after ADR-0012 the
    /// reason is host authority rather than signing. The helper publishes a
    /// `MacosDevelopmentHelperSession`, a different type whose validator
    /// requires `dedicated_account_pool == false`, and the terminal
    /// evidence chain requires a `MacosAssignedIdentity` naming a real
    /// local execution account that only root can create. No unprivileged
    /// artifact can therefore be read as Gate-1 evidence.
    ///
    /// # Errors
    ///
    /// Fails for the same authority, private-root, and shadow-root reasons
    /// as the production constructor.
    pub(crate) fn development(
        grant: IssuedWorkspaceGrant,
        policy: CompiledExecutionPolicy,
        paths: &SupervisorPaths,
        runner_session_id: &str,
    ) -> Result<Self, SupervisorError> {
        let mut backend = Self::new(grant, policy, paths)?;
        let canary_root = create_private_instance(&backend.private_state_root)?;
        backend.mode =
            MacosDedicatedIdentityMode::Development(Box::new(MacosDevelopmentBackendState {
                plan: MacosDevelopmentCanaryPlan {
                    canary_root,
                    runner_session_id: runner_session_id.to_owned(),
                },
                client: None,
                proven: BTreeSet::new(),
                refusals: Vec::new(),
                canary_digest: None,
                profile_applier: None,
                descriptor_closure: None,
                descendant_domain: None,
            }));
        Ok(backend)
    }

    /// Whether this backend is the development arm.
    pub(crate) const fn development_mode(&self) -> bool {
        matches!(self.mode, MacosDedicatedIdentityMode::Development(_))
    }

    /// Exact bounded reasons the development canaries refused a control.
    pub(crate) fn development_refusals(&self) -> &[String] {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => &[],
            MacosDedicatedIdentityMode::Development(state) => &state.refusals,
        }
    }

    /// How the development helper applied the Seatbelt profile, as observed
    /// in this generation's run evidence.
    pub(crate) fn development_profile_applier(&self) -> Option<MacosDevelopmentProfileApplier> {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => None,
            MacosDedicatedIdentityMode::Development(state) => state.profile_applier,
        }
    }

    /// The exact descriptor observation behind this generation's
    /// `ClosedInheritedDescriptors` verdict.
    pub(crate) fn development_descriptor_closure(
        &self,
    ) -> Option<&MacosDevelopmentDescriptorClosure> {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => None,
            MacosDedicatedIdentityMode::Development(state) => state.descriptor_closure.as_ref(),
        }
    }

    /// The exact observation behind this generation's `DescendantLimit`
    /// and `DescendantDomainKill` verdicts.
    pub(crate) fn development_descendant_domain(
        &self,
    ) -> Option<&MacosDevelopmentDescendantDomain> {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => None,
            MacosDedicatedIdentityMode::Development(state) => state.descendant_domain.as_ref(),
        }
    }

    /// The authenticated development session, once one exists.
    pub(crate) fn development_session(&self) -> Option<&MacosDevelopmentHelperSession> {
        match &self.mode {
            MacosDedicatedIdentityMode::Production => None,
            MacosDedicatedIdentityMode::Development(state) => state
                .client
                .as_ref()
                .map(MacosDevelopmentHelperClient::session),
        }
    }

    /// Renders one canary profile with additional readable scopes.
    ///
    /// Every rule comes from the same audited renderer the command profile
    /// uses; only the executable literal and the extra readable subpaths
    /// differ, which is what makes a canary's denial evidence about the
    /// command's own policy rather than about a different policy.
    fn render_canary_profile(
        &self,
        program: &Path,
        extra_readable: &[PathBuf],
    ) -> Result<String, SupervisorError> {
        self.render_canary_profile_for(std::slice::from_ref(&program), extra_readable)
    }

    /// Renders one canary profile admitting several executables.
    ///
    /// The fork canary needs this: to attribute a refusal to the profile's
    /// `process-fork` rule rather than to its `process-exec` rule, the
    /// program the canary would fork *and* the program it would then exec
    /// must both be executable under the restrictive profile, leaving the
    /// fork as the only denied operation.
    fn render_canary_profile_for(
        &self,
        programs: &[&Path],
        extra_readable: &[PathBuf],
    ) -> Result<String, SupervisorError> {
        let executables = programs
            .iter()
            .map(|program| (*program).to_path_buf())
            .collect::<BTreeSet<_>>();
        let mut readable = scope_paths(&self.execution_root, &self.policy.contract().read_scopes);
        readable.extend_from_slice(extra_readable);
        let writable = scope_paths(&self.execution_root, &self.policy.contract().write_scopes);
        let mut denied = credential_roots();
        push_denied_root(&mut denied, self.live_root.join(".git"));
        push_denied_root(&mut denied, self.execution_root.join(".git"));
        push_denied_root(&mut denied, self.private_state_root.join(".git"));
        render_seatbelt_profile(
            &executables,
            &readable,
            &writable,
            &denied,
            &self.live_root,
            self.policy.contract().network == ExecutionNetwork::FullForAction,
        )
    }

    /// Starts the development helper and proves the enforceable controls.
    ///
    /// The helper is started once per backend, immediately reserves one
    /// development identity generation, and serves every canary plus the
    /// command that follows from inside that same generation. That is the
    /// `ActiveCanaries` requirement stated exactly: escape canaries ran
    /// inside the same backend generation used to launch.
    fn prove_development_controls(
        &mut self,
        command: &PreparedContainedCommand,
    ) -> Result<(), SupervisorError> {
        let command_profile = self.render_profile_for(command.executable_path())?;
        let environment = development_environment(command)?;
        let plan = match &self.mode {
            MacosDedicatedIdentityMode::Production => {
                return Err(SupervisorError::Capability(
                    "development canaries require the development backend arm".into(),
                ));
            }
            MacosDedicatedIdentityMode::Development(state) => state.plan.clone(),
        };
        let mut executables = BTreeMap::new();
        for program in DEVELOPMENT_CANARY_PROGRAMS {
            executables.insert(
                program.entry.to_owned(),
                canonical_existing_path(Path::new(program.path))?,
            );
        }
        executables.insert(
            DEVELOPMENT_COMMAND_ENTRY.to_owned(),
            command.executable_path().to_path_buf(),
        );
        let helper_plan = MacosDevelopmentHelperPlan {
            policy_version: 1,
            workspace_grant_hash: self.grant.contract().grant_hash.clone(),
            execution_policy_hash: self.policy.contract().policy_hash.clone(),
            command_network: if self.policy.contract().network == ExecutionNetwork::FullForAction {
                MacosHelperNetwork::Allowed
            } else {
                MacosHelperNetwork::Denied
            },
            staged_workspace_id: "development-execution-root".to_owned(),
            staged_workspace_path: self.execution_root.clone(),
            executables,
        };
        let endpoint = available_development_helper_topology();
        let mut client = MacosDevelopmentHelperClient::start(&helper_plan, endpoint)
            .map_err(|error| development_error(&error))?;
        let mut suite = MacosDevelopmentCanarySuite {
            backend: self,
            plan: &plan,
            environment,
            command_profile,
            evidence_digests: Vec::new(),
            generations: Vec::new(),
            proven: BTreeSet::new(),
            refusals: Vec::new(),
            profile_applier: None,
            descriptor_closure: None,
            fork_denial: None,
            cancellation: None,
            descendant_domain: None,
        };
        let outcome = suite.run(&mut client);
        let (proven, refusals, digests, applier, closure, domain) = (
            suite.proven,
            suite.refusals,
            suite.evidence_digests,
            suite.profile_applier,
            suite.descriptor_closure,
            suite.descendant_domain,
        );
        if let Err(error) = outcome {
            // Retain the authenticated session and whatever the suite did
            // establish before the failure: a diagnostic must never be
            // discarded just because a later probe could not complete.
            if let MacosDedicatedIdentityMode::Development(state) = &mut self.mode {
                state.proven = proven;
                state.refusals = refusals;
                state.profile_applier = applier;
                state.descriptor_closure = closure;
                state.descendant_domain = domain;
                state.client = Some(client);
            }
            return Err(error);
        }
        let mut hasher = Sha256::new();
        hash_frame(&mut hasher, MACOS_DEVELOPMENT_CANARY_DOMAIN);
        hash_frame(
            &mut hasher,
            client.session().session_nonce.as_str().as_bytes(),
        );
        for digest in &digests {
            hash_frame(&mut hasher, digest.as_str().as_bytes());
        }
        let canary_digest = digest_from_sha(hasher.finalize().into());
        match &mut self.mode {
            MacosDedicatedIdentityMode::Production => Ok(()),
            MacosDedicatedIdentityMode::Development(state) => {
                state.proven = proven;
                state.refusals = refusals;
                state.canary_digest = Some(canary_digest);
                state.profile_applier = applier;
                state.descriptor_closure = closure;
                state.descendant_domain = domain;
                state.client = Some(client);
                Ok(())
            }
        }
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
            MacosDedicatedIdentityMode::Production => None,
            MacosDedicatedIdentityMode::Development(state) => state.canary_digest.clone(),
        }
        .ok_or_else(|| {
            SupervisorError::Canary(
                "the development canary suite produced no generation digest".into(),
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
    ///
    /// The missing set is computed as `required − proven`, and every
    /// element of `proven` came from a canary. The reasons appended are the
    /// live measurements that made each refusal necessary, so the message
    /// cannot drift from what the helper actually observed.
    fn development_unenforceable(&self) -> SupervisorError {
        let required = required_controls(self.policy.contract().resource_limits);
        let enforced = self.enforced_controls();
        let missing = required.difference(&enforced).copied().collect::<Vec<_>>();
        let reasons = self.development_refusals().join("; ");
        SupervisorError::Capability(format!(
            "the development macOS dedicated-identity helper enforces {enforced:?} but \
             cannot enforce {missing:?}: {reasons}"
        ))
    }
}

/// One live canary suite execution inside one reserved dev generation.
struct MacosDevelopmentCanarySuite<'a> {
    backend: &'a MacosDedicatedIdentityBackend,
    plan: &'a MacosDevelopmentCanaryPlan,
    environment: BTreeMap<String, String>,
    command_profile: String,
    evidence_digests: Vec<Digest>,
    generations: Vec<String>,
    proven: BTreeSet<BackendControl>,
    refusals: Vec<String>,
    profile_applier: Option<MacosDevelopmentProfileApplier>,
    descriptor_closure: Option<MacosDevelopmentDescriptorClosure>,
    fork_denial: Option<MacosDevelopmentForkDenial>,
    cancellation: Option<MacosDevelopmentCancellation>,
    descendant_domain: Option<MacosDevelopmentDescendantDomain>,
}

impl MacosDevelopmentCanarySuite<'_> {
    #[allow(
        clippy::too_many_lines,
        reason = "each control's control run, restrictive run, and verdict stay adjacent so a reviewer can check the claim against the probe that established it"
    )]
    fn run(&mut self, client: &mut MacosDevelopmentHelperClient) -> Result<(), SupervisorError> {
        self.filesystem_policy(client)?;
        self.network_policy(client)?;
        self.exact_argv(client)?;
        self.replaced_environment(client)?;
        self.closed_inherited_descriptors(client)?;
        self.descriptor_working_directory(client)?;
        self.external_wall_clock(client)?;
        self.complete_bounded_output(client)?;
        self.fork_denial(client)?;
        self.measured_platform_limits(client)?;
        // `ActiveCanaries` is the one control that is about the suite
        // itself: every canary above returned a definite result, and every
        // one of them ran inside this exact reserved identity generation.
        // Both halves are checked, not assumed.
        let generations = self.generations.iter().collect::<BTreeSet<_>>();
        if self.evidence_digests.len() >= EXPECTED_DEVELOPMENT_CANARY_RUNS && generations.len() == 1
        {
            self.proven.insert(BackendControl::ActiveCanaries);
        } else {
            self.refusals.push(format!(
                "the development canary suite completed {} of {EXPECTED_DEVELOPMENT_CANARY_RUNS} \
                 probes across {} identity generations",
                self.evidence_digests.len(),
                generations.len()
            ));
        }
        Ok(())
    }

    fn record(&mut self, outcome: &MacosDevelopmentRunOutcome) {
        self.evidence_digests
            .push(outcome.evidence.evidence_digest.clone());
        self.generations
            .push(outcome.evidence.identity.generation_id.clone());
        self.profile_applier = Some(outcome.evidence.profile_applier);
    }

    fn specification<'spec>(
        &'spec self,
        entry: &'spec str,
        executable_digest: Digest,
        argv: &'spec [String],
        profile: &'spec str,
        wall_time_ms: u64,
    ) -> MacosDevelopmentRunSpecification<'spec> {
        MacosDevelopmentRunSpecification {
            runner_session_id: &self.plan.runner_session_id,
            effect_id: "development-canary-effect",
            sprint_id: "development-canary-sprint",
            launch_id: "development-canary-launch",
            input_snapshot: hash_bytes(b"development-canary-input-snapshot"),
            policy_entry_id: entry,
            executable_digest,
            argv,
            environment: self.environment.clone(),
            relative_working_directory: ".",
            seatbelt_profile: profile,
            wall_time_ms,
            max_output_bytes: DEVELOPMENT_CANARY_OUTPUT_BYTES,
            max_processes: 1,
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every canary run states its purpose, policy entry, program, arguments, profile, deadline, and probe explicitly rather than defaulting any of them"
    )]
    fn execute(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
        purpose: MacosDevelopmentRunPurpose,
        entry: &str,
        program: &Path,
        arguments: &[String],
        profile: &str,
        wall_time_ms: u64,
        probe_descriptor_exec: bool,
    ) -> Result<MacosDevelopmentRunOutcome, SupervisorError> {
        let executable_digest = hash_file(program)?;
        let mut argv = vec![
            program
                .to_str()
                .ok_or_else(|| {
                    SupervisorError::InvalidCommand(
                        "a development canary program path must be UTF-8".into(),
                    )
                })?
                .to_owned(),
        ];
        argv.extend(arguments.iter().cloned());
        let specification =
            self.specification(entry, executable_digest, &argv, profile, wall_time_ms);
        let request = client
            .build_request(&specification)
            .map_err(|error| development_error(&error))?;
        let outcome = client
            .run(purpose, &request, profile, probe_descriptor_exec)
            .map_err(|error| development_error(&error))?;
        self.record(&outcome);
        Ok(outcome)
    }

    fn filesystem_policy(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let escape = self.plan.canary_root.join("escape-created");
        remove_if_present(&escape)?;
        let escape_argument = escape
            .to_str()
            .ok_or_else(|| {
                SupervisorError::InvalidCommand("the development canary root must be UTF-8".into())
            })?
            .to_owned();
        let control = self.execute(
            client,
            MacosDevelopmentRunPurpose::CanaryControl,
            "system-touch",
            Path::new(CANARY_TOUCH),
            std::slice::from_ref(&escape_argument),
            DEVELOPMENT_CONTROL_PROFILE,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        if !control.exited_zero() || !escape.is_file() {
            return Err(SupervisorError::Canary(
                "the development escape control could not create its private sentinel".into(),
            ));
        }
        fs::remove_file(&escape)?;
        let profile = self
            .backend
            .render_canary_profile(Path::new(CANARY_TOUCH), &[])?;
        let restricted = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-touch",
            Path::new(CANARY_TOUCH),
            std::slice::from_ref(&escape_argument),
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            // One probe per suite is enough; attach it here.
            true,
        )?;
        if restricted.exited_zero() || escape.exists() {
            self.refusals
                .push("Seatbelt permitted a write outside the compiled write scopes".to_owned());
        } else {
            self.proven.insert(BackendControl::FilesystemPolicy);
        }
        if restricted.evidence.descriptor_exec.supported {
            self.proven.insert(BackendControl::DescriptorExec);
        } else {
            self.refusals.push(format!(
                "descriptor exec is unavailable on this platform: spawning /dev/fd of the \
                 resolved executable failed with errno {} (macOS provides no fexecve and the \
                 fdesc node is not executable)",
                restricted.evidence.descriptor_exec.errno
            ));
        }
        Ok(())
    }

    fn network_policy(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let expected = self.backend.policy.contract().network == ExecutionNetwork::FullForAction;
        let control = self.loopback_probe(client, DEVELOPMENT_CONTROL_PROFILE, true)?;
        if !control {
            return Err(SupervisorError::Canary(
                "the development network control could not reach its loopback listener".into(),
            ));
        }
        let profile = self
            .backend
            .render_canary_profile(Path::new(CANARY_CURL), &[])?;
        let restricted = self.loopback_probe(client, &profile, false)?;
        if restricted == expected {
            self.proven.insert(BackendControl::NetworkPolicy);
        } else {
            self.refusals.push(format!(
                "the compiled network mode expected loopback reachability {expected} but the \
                 restrictive profile observed {restricted}"
            ));
        }
        Ok(())
    }

    fn loopback_probe(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
        profile: &str,
        control: bool,
    ) -> Result<bool, SupervisorError> {
        use std::net::TcpListener;

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_for_thread = Arc::clone(&accepted);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let deadline = Instant::now()
                + Duration::from_millis(DEVELOPMENT_CANARY_WALL_TIME_MS.saturating_add(2_000));
            while Instant::now() < deadline && !stop_for_thread.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        accepted_for_thread.store(true, Ordering::Release);
                        let mut request = [0_u8; 512];
                        let _ignored = stream.read(&mut request);
                        let _ignored = stream.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(POLL_INTERVAL);
                    }
                    Err(_) => return,
                }
            }
        });
        let arguments = [
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "2".to_owned(),
            "--output".to_owned(),
            "/dev/null".to_owned(),
            format!("http://127.0.0.1:{port}/"),
        ];
        let purpose = if control {
            MacosDevelopmentRunPurpose::CanaryControl
        } else {
            MacosDevelopmentRunPurpose::Canary
        };
        let outcome = self.execute(
            client,
            purpose,
            "system-curl",
            Path::new(CANARY_CURL),
            &arguments,
            profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        );
        stop.store(true, Ordering::Release);
        server.join().map_err(|_ignored| {
            SupervisorError::Canary("the development network canary server panicked".into())
        })?;
        let outcome = outcome?;
        Ok(outcome.exited_zero() && accepted.load(Ordering::Acquire))
    }

    fn exact_argv(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let profile = self
            .backend
            .render_canary_profile(Path::new(DEVELOPMENT_ECHO), &[])?;
        let arguments = [
            "grok-build-argv".to_owned(),
            "alpha beta".to_owned(),
            "--%weird$(argument)".to_owned(),
        ];
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-echo",
            Path::new(DEVELOPMENT_ECHO),
            &arguments,
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let expected = format!("{}\n", arguments.join(" "));
        if outcome.exited_zero() && outcome.stdout_text() == expected {
            self.proven.insert(BackendControl::ExactArgv);
        } else {
            self.refusals
                .push("the exact argument vector did not reach the contained program".to_owned());
        }
        Ok(())
    }

    fn replaced_environment(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let profile = self
            .backend
            .render_canary_profile(Path::new(DEVELOPMENT_ENV), &[])?;
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-env",
            Path::new(DEVELOPMENT_ENV),
            &[],
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let observed = outcome
            .stdout_text()
            .lines()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let expected = self
            .environment
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<BTreeSet<_>>();
        if outcome.exited_zero() && observed == expected {
            self.proven.insert(BackendControl::ReplacedEnvironment);
        } else {
            self.refusals.push(format!(
                "the contained environment was {} entries rather than the exact compiled set",
                observed.len()
            ));
        }
        Ok(())
    }

    fn closed_inherited_descriptors(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let descriptor_root = PathBuf::from("/dev/fd");
        let profile = self.backend.render_canary_profile(
            Path::new(DEVELOPMENT_LS),
            std::slice::from_ref(&descriptor_root),
        )?;
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-ls",
            Path::new(DEVELOPMENT_LS),
            &["/dev/fd".to_owned()],
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let listed = outcome
            .stdout_text()
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect::<BTreeSet<_>>();

        // Read the inherited descriptor table with libproc at the stopped pre-exec
        // boundary. A separate applier would leave an observation gap.
        let applied_in_process = outcome.evidence.applied_profile_in_process();
        let boundary_table = &outcome.evidence.held_child_descriptors;
        let launcher_held = outcome.evidence.launcher_state.descriptor_count;
        // The child began as a copy of the launcher's table, so a launcher
        // holding more than the standard three is what makes a child table
        // of exactly {0, 1, 2} a shed rather than a coincidence.
        let shed_from_launcher = launcher_held > 3;
        let boundary_closed = boundary_table == &vec![0, 1, 2];

        // `/dev/fd` includes the enumerator's own descriptors. Authority comes from
        // the boundary readback, not the listing count.
        let target_ran = outcome.exited_zero()
            && listed.contains(&0)
            && listed.contains(&1)
            && listed.contains(&2);
        let observed_stopped_leader = outcome.evidence.held_session_leader;
        self.descriptor_closure = Some(MacosDevelopmentDescriptorClosure {
            launcher_descriptors: launcher_held,
            launcher_threads: outcome.evidence.launcher_state.thread_count,
            boundary_table: boundary_table.clone(),
            target_listing: listed.iter().copied().collect(),
        });

        if applied_in_process
            && shed_from_launcher
            && boundary_closed
            && observed_stopped_leader
            && target_ran
        {
            self.proven
                .insert(BackendControl::ClosedInheritedDescriptors);
        } else if applied_in_process {
            self.refusals.push(format!(
                "the forked launch component held {launcher_held} descriptors and handed the \
                 target {boundary_table:?} at its exec boundary, and the target enumerated \
                 {listed:?}: that is not the exact standard set"
            ));
        } else {
            self.refusals.push(format!(
                "this helper is not a single-threaded launch component ({} threads), so it \
                 applied the profile through the separate \
                 {MACOS_DEVELOPMENT_PROFILE_APPLIER} program instead of forking; that program \
                 runs its own code after the launcher's last observation of it, so there is no \
                 observation point at the target's exec and the inherited table cannot be \
                 proved",
                outcome.evidence.launcher_state.thread_count
            ));
        }
        Ok(())
    }

    fn descriptor_working_directory(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let profile = self
            .backend
            .render_canary_profile(Path::new(DEVELOPMENT_PWD), &[])?;
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-pwd",
            Path::new(DEVELOPMENT_PWD),
            &[],
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let expected = format!("{}\n", self.backend.execution_root.display());
        if outcome.exited_zero() && outcome.stdout_text() == expected {
            self.proven
                .insert(BackendControl::DescriptorWorkingDirectory);
        } else {
            self.refusals.push(
                "the retained execution-root descriptor did not select the working directory"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn external_wall_clock(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let profile = self
            .backend
            .render_canary_profile(Path::new(DEVELOPMENT_SLEEP), &[])?;
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-sleep",
            Path::new(DEVELOPMENT_SLEEP),
            &["30".to_owned()],
            &profile,
            DEVELOPMENT_WALL_CLOCK_CANARY_MS,
            false,
        )?;
        let elapsed = outcome
            .evidence
            .finished_at_unix_ms
            .saturating_sub(outcome.evidence.started_at_unix_ms);
        // Deadline expiry uses the same domain termination as cancellation.
        // Classify the subsequent kernel observation separately.
        self.cancellation = Some(MacosDevelopmentCancellation {
            leader_pid: outcome.evidence.launch_pid,
            leader_process_group: outcome.evidence.process_group_id,
            leader_session_leader: outcome.evidence.held_session_leader,
            terminated_by_deadline: outcome.evidence.wall_clock_terminated,
            survivors: outcome.evidence.domain_survivors.clone(),
        });
        if outcome.evidence.wall_clock_terminated && !outcome.exited_zero() && elapsed < 20_000 {
            self.proven.insert(BackendControl::ExternalWallClock);
        } else {
            self.refusals.push(format!(
                "a {DEVELOPMENT_WALL_CLOCK_CANARY_MS} ms deadline did not terminate a 30 s \
                 sleep: terminated={} elapsed={elapsed} ms",
                outcome.evidence.wall_clock_terminated
            ));
        }
        Ok(())
    }

    fn complete_bounded_output(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let payload = (0..DEVELOPMENT_BOUNDED_OUTPUT_BYTES)
            .map(|index| b'a'.wrapping_add(u8::try_from(index % 26).unwrap_or(0)))
            .collect::<Vec<_>>();
        let source = self.plan.canary_root.join("bounded-output");
        fs::write(&source, &payload)?;
        let profile = self.backend.render_canary_profile(
            Path::new(CANARY_CAT),
            std::slice::from_ref(&self.plan.canary_root),
        )?;
        let argument = source
            .to_str()
            .ok_or_else(|| {
                SupervisorError::InvalidCommand("the development canary root must be UTF-8".into())
            })?
            .to_owned();
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-cat",
            Path::new(CANARY_CAT),
            std::slice::from_ref(&argument),
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let complete = outcome.exited_zero()
            && outcome.stdout == payload
            && outcome.evidence.stdout.complete_digest == hash_bytes(&payload)
            && outcome.evidence.stdout.complete_length
                == u64::try_from(payload.len()).unwrap_or(u64::MAX)
            && outcome.evidence.stdout.chunk_count > 1
            && outcome.evidence.stdout.maximum_chunk_bytes
                <= u64::try_from(MAX_MACOS_DEVELOPMENT_CHUNK_BYTES).unwrap_or(u64::MAX);
        fs::remove_file(&source)?;
        if complete {
            self.proven.insert(BackendControl::CompleteBoundedOutput);
        } else {
            self.refusals.push(format!(
                "bounded draining returned {} of {} bytes in {} chunks",
                outcome.evidence.stdout.complete_length,
                payload.len(),
                outcome.evidence.stdout.chunk_count
            ));
        }
        Ok(())
    }

    /// Measures whether the Seatbelt profile itself refuses process creation.
    ///
    /// The rendered profile has carried `(deny process-fork)` since the
    /// path-based adapter, but nothing ever measured it, so no control
    /// could rest on it. Three runs of `/usr/bin/find` isolate exactly one
    /// variable:
    ///
    /// 1. the forking argv under a permissive profile must succeed, or the
    ///    argv does not actually create a process and proves nothing;
    /// 2. the same program under the restrictive profile with a
    ///    non-forking argv must succeed, or a later failure could be a
    ///    denied read or a denied exec rather than a denied fork;
    /// 3. the forking argv under the restrictive profile must fail.
    ///
    /// The restrictive profile admits both `/usr/bin/find` and the program
    /// it would exec, so `process-exec` cannot be the cause of (3).
    fn fork_denial(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let root = self
            .plan
            .canary_root
            .to_str()
            .ok_or_else(|| {
                SupervisorError::InvalidCommand("the development canary root must be UTF-8".into())
            })?
            .to_owned();
        let quiet_argv = vec![root.clone(), "-maxdepth".to_owned(), "0".to_owned()];
        let mut forking_argv = quiet_argv.clone();
        forking_argv.extend([
            "-exec".to_owned(),
            CANARY_TRUE.to_owned(),
            "{}".to_owned(),
            ";".to_owned(),
        ]);
        let restrictive = self.backend.render_canary_profile_for(
            &[Path::new(CANARY_FIND), Path::new(CANARY_TRUE)],
            std::slice::from_ref(&self.plan.canary_root),
        )?;
        let control = self.execute(
            client,
            MacosDevelopmentRunPurpose::CanaryControl,
            "system-find",
            Path::new(CANARY_FIND),
            &forking_argv,
            DEVELOPMENT_CONTROL_PROFILE,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let viable = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-find",
            Path::new(CANARY_FIND),
            &quiet_argv,
            &restrictive,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let restricted = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-find",
            Path::new(CANARY_FIND),
            &forking_argv,
            &restrictive,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        self.fork_denial = Some(MacosDevelopmentForkDenial {
            control_forked: control.exited_zero(),
            restricted_ran_without_forking: viable.exited_zero(),
            restricted_forked: restricted.exited_zero(),
        });
        Ok(())
    }

    /// Turns the measured platform state into the two domain verdicts.
    ///
    /// Neither control is decided by a constant, and each has exactly two
    /// admissible proofs.
    ///
    /// `DescendantLimit` is claimed when the helper installed a per-UID
    /// `RLIMIT_NPROC` equal to the request — which needs an otherwise-unused
    /// execution account — **or** when the profile itself refuses process
    /// creation *and* the compiled policy configures a ceiling of exactly
    /// one. The second proof is not an approximation of the first: a kernel
    /// that refuses `fork` and `posix_spawn` outright bounds the domain at
    /// one process by prevention. It is also narrow by construction,
    /// because the Seatbelt profile language has no counted form of
    /// `process-fork`, so it can express one and only one finite ceiling.
    ///
    /// `DescendantDomainKill` is claimed when the run's identity was an
    /// otherwise-unused account whose domain enumerated empty, **or** when
    /// three measured facts compose: process creation is refused, so no
    /// descendant can exist; the leader was its own session leader, which
    /// makes `setsid` and `setpgid` fail `EPERM` for it, so it cannot leave
    /// the enumerated group either; and a real deadline termination left
    /// the enumerated domain empty. Together those make the process-group
    /// enumeration a complete domain view rather than a partial one.
    fn measured_platform_limits(
        &mut self,
        client: &mut MacosDevelopmentHelperClient,
    ) -> Result<(), SupervisorError> {
        let profile = self
            .backend
            .render_canary_profile(Path::new(CANARY_TRUE), &[])?;
        let outcome = self.execute(
            client,
            MacosDevelopmentRunPurpose::Canary,
            "system-true",
            Path::new(CANARY_TRUE),
            &[],
            &profile,
            DEVELOPMENT_CANARY_WALL_TIME_MS,
            false,
        )?;
        let ceiling = outcome.evidence.descendant_ceiling;
        let configured = self.backend.policy.contract().resource_limits.max_processes;
        let domain = MacosDevelopmentDescendantDomain {
            configured_max_processes: configured,
            dedicated_account: outcome.evidence.identity.dedicated_account,
            rlimit_nproc_applied: ceiling.rlimit_nproc_applied,
            real_uid_process_count: ceiling.real_uid_process_count,
            rlimit_nproc_soft: ceiling.rlimit_nproc_soft,
            fork_denial: self.fork_denial,
            cancellation: self.cancellation.clone(),
        };
        let creation_refused = domain
            .fork_denial
            .is_some_and(MacosDevelopmentForkDenial::refuses_process_creation);
        let singleton_domain = creation_refused && configured == 1;

        // The two admissible proofs, named so neither can be mistaken for
        // the other: a dedicated account turns `RLIMIT_NPROC` into a domain
        // ceiling of any finite value, and a profile-level refusal of
        // process creation is a domain ceiling of exactly one.
        if domain.rlimit_nproc_applied || singleton_domain {
            self.proven.insert(BackendControl::DescendantLimit);
        } else if creation_refused {
            self.refusals.push(format!(
                "the configured descendant ceiling is {configured}, and the only root-free \
                 ceiling this host offers is the Seatbelt profile's own refusal of process \
                 creation, which expresses exactly 1 because the profile language has no \
                 counted form of process-fork; RLIMIT_NPROC is per-UID and this domain shares \
                 the invoking user's UID, which already owns {} processes against a soft limit \
                 of {}",
                domain.real_uid_process_count, domain.rlimit_nproc_soft
            ));
        } else {
            self.refusals.push(format!(
                "no descendant ceiling was installed: RLIMIT_NPROC is a per-UID limit and the \
                 development domain shares the invoking user's UID, which already owns {} \
                 processes against a soft limit of {}, so a ceiling of {} is unrepresentable \
                 without an otherwise-unused execution account, and the profile's own fork \
                 refusal did not measure as {:?}",
                domain.real_uid_process_count,
                domain.rlimit_nproc_soft,
                ceiling.requested_max_processes,
                domain.fork_denial
            ));
        }

        let sealed_leader = domain.cancellation.as_ref().is_some_and(|cancellation| {
            cancellation.terminated_by_deadline
                && cancellation.leader_session_leader
                && cancellation.leader_process_group == cancellation.leader_pid
                && cancellation.survivors.is_empty()
        });
        let dedicated_domain_emptied =
            domain.dedicated_account && outcome.evidence.domain_survivors.is_empty();
        if dedicated_domain_emptied || (singleton_domain && sealed_leader) {
            self.proven.insert(BackendControl::DescendantDomainKill);
        } else {
            self.refusals.push(format!(
                "the development domain is process group {} under shared UID {}, not an \
                 otherwise-unused execution identity, so a descendant that calls setsid leaves \
                 the enumerated domain and whole-domain emptiness cannot be proved; the \
                 root-free alternative needs a configured ceiling of 1 with process creation \
                 refused and a sealed leader, measured here as configured={configured} \
                 creation_refused={creation_refused} sealed_leader={sealed_leader}",
                outcome.evidence.process_group_id, outcome.evidence.identity.real_uid
            ));
        }
        self.descendant_domain = Some(domain);
        Ok(())
    }
}

/// Permissive control profile used only to prove a canary can succeed.
const DEVELOPMENT_CONTROL_PROFILE: &str = "(version 1) (allow default)";
const DEVELOPMENT_ECHO: &str = "/bin/echo";
const DEVELOPMENT_ENV: &str = "/usr/bin/env";
const DEVELOPMENT_LS: &str = "/bin/ls";
const DEVELOPMENT_PWD: &str = "/bin/pwd";
const DEVELOPMENT_SLEEP: &str = "/bin/sleep";

fn development_environment(
    command: &PreparedContainedCommand,
) -> Result<BTreeMap<String, String>, SupervisorError> {
    let mut environment = BTreeMap::new();
    for (name, value) in command.environment() {
        let name = name.to_str().ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "a contained environment name must be UTF-8 for the development helper".into(),
            )
        })?;
        let value = value.to_str().ok_or_else(|| {
            SupervisorError::InvalidCommand(
                "a contained environment value must be UTF-8 for the development helper".into(),
            )
        })?;
        environment.insert(name.to_owned(), value.to_owned());
    }
    Ok(environment)
}

fn development_error(error: &MacosDevelopmentHelperError) -> SupervisorError {
    SupervisorError::Capability(format!("development dedicated-identity helper: {error}"))
}

fn macos_development_identity_implementation_digest() -> Digest {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, MACOS_DEVELOPMENT_IMPLEMENTATION_DOMAIN);
    hash_frame(
        &mut hasher,
        MACOS_DEDICATED_IDENTITY_DEV_BACKEND_ID.as_bytes(),
    );
    hash_frame(&mut hasher, &MACOS_HELPER_PROTOCOL_VERSION.to_be_bytes());
    digest_from_sha(hasher.finalize().into())
}
