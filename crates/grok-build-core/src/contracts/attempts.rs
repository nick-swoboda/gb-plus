//! Task-attempt lifecycle, recovery facts, and durable disposition history.

use super::{
    AcceptanceKind, BTreeSet, CONTRACT_VERSION, CommandSpec, ContractError, Deserialize, Digest,
    MAX_TASK_ATTEMPT_EVIDENCE_BYTES, MAX_TASK_ATTEMPT_ID_BYTES, Serialize, SprintSpec, SprintState,
    TaskIntegrationReceipt, TaskSpec, TaskState, VerificationReceipt, WorkerCleanupReceipt,
    WorkerLease, require_nonblank, require_nonzero_timestamp, require_strict_lexical_order,
    require_unique_nonblank,
};

/// One durable execution attempt, opened by exactly one worker-lease acquisition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttempt {
    /// Wire-contract version used to encode the attempt.
    pub contract_version: u32,
    /// Stable attempt identity, exactly equal to `worker_lease.lease_id`.
    pub attempt_id: String,
    /// Complete canonical lease that opened this attempt.
    pub worker_lease: WorkerLease,
    /// Positive contiguous task-local attempt number.
    pub attempt_ordinal: u32,
    /// Exact durable `Ready -> Leased` opening event.
    pub opening_event_id: String,
    /// Opening time, exactly equal to the lease acquisition time.
    pub opened_at_unix_ms: u64,
}

impl TaskAttempt {
    /// Constructs an attempt from its exact opening lease and event.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid lease, zero ordinal, or blank
    /// event identity.
    pub fn new(
        worker_lease: WorkerLease,
        attempt_ordinal: u32,
        opening_event_id: String,
    ) -> Result<Self, ContractError> {
        let attempt = Self {
            contract_version: CONTRACT_VERSION,
            attempt_id: worker_lease.lease_id.clone(),
            opened_at_unix_ms: worker_lease.acquired_at_unix_ms,
            worker_lease,
            attempt_ordinal,
            opening_event_id,
        };
        attempt.validate()?;
        Ok(attempt)
    }

    /// Validates the exact attempt-to-lease authority relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, substituted
    /// identity, zero ordinal, blank event, or mismatched opening timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "task_attempt.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.worker_lease.validate()?;
        if self.attempt_id != self.worker_lease.lease_id {
            return Err(ContractError::new(
                "task_attempt.attempt_id",
                "must exactly equal worker_lease.lease_id",
            ));
        }
        if self.attempt_ordinal == 0 {
            return Err(ContractError::new(
                "task_attempt.attempt_ordinal",
                "must be greater than zero",
            ));
        }
        require_task_attempt_identity("task_attempt.opening_event_id", &self.opening_event_id)?;
        require_nonzero_timestamp("task_attempt.opened_at_unix_ms", self.opened_at_unix_ms)?;
        if self.opened_at_unix_ms != self.worker_lease.acquired_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt.opened_at_unix_ms",
                "must exactly equal worker lease acquisition time",
            ));
        }
        Ok(())
    }
}

/// One known-terminal non-cleanup effect referenced by a phase boundary.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptTerminalEffect {
    /// Exact effect identity.
    pub effect_id: String,
    /// Exact terminal observation identity.
    pub observation_id: String,
}

impl TaskAttemptTerminalEffect {
    fn validate(&self) -> Result<(), ContractError> {
        require_task_attempt_identity("task_attempt_terminal_effect.effect_id", &self.effect_id)?;
        require_task_attempt_identity(
            "task_attempt_terminal_effect.observation_id",
            &self.observation_id,
        )
    }
}

/// Immutable `Leased -> Running` boundary for one exact attempt authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptRunningBoundary {
    /// Wire-contract version used to encode the boundary.
    pub contract_version: u32,
    /// Stable boundary identity.
    pub boundary_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Exact admitted task-worker launch.
    pub runner_launch_id: String,
    /// Exact initialized task-worker session.
    pub runner_session_id: String,
    /// Exact `Leased -> Running` event.
    pub transition_event_id: String,
    /// Time at which the attempt entered Running.
    pub started_at_unix_ms: u64,
}

impl TaskAttemptRunningBoundary {
    /// Validates the boundary's complete identity and opening-time ordering.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid identity,
    /// invalid nested attempt, or a timestamp before attempt opening.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_running_boundary.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "task_attempt_running_boundary.boundary_id",
            &self.boundary_id,
        )?;
        self.attempt.validate()?;
        require_task_attempt_identity(
            "task_attempt_running_boundary.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_running_boundary.runner_session_id",
            &self.runner_session_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_running_boundary.transition_event_id",
            &self.transition_event_id,
        )?;
        require_nonzero_timestamp(
            "task_attempt_running_boundary.started_at_unix_ms",
            self.started_at_unix_ms,
        )?;
        if self.started_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_running_boundary.started_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// Immutable `Running -> Verifying` boundary for one exact attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptVerificationBoundary {
    /// Wire-contract version used to encode the boundary.
    pub contract_version: u32,
    /// Stable boundary identity.
    pub boundary_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Exact task-worker launch.
    pub runner_launch_id: String,
    /// Exact task-worker session.
    pub runner_session_id: String,
    /// Exact change set sealed by this boundary.
    pub change_set_id: String,
    /// Immutable candidate snapshot sealed for formal checks.
    pub sealed_snapshot: Digest,
    /// Exact `Running -> Verifying` event.
    pub transition_event_id: String,
    /// Canonically ordered proof links for every earlier non-cleanup effect.
    pub terminal_non_cleanup_effects: Vec<TaskAttemptTerminalEffect>,
    /// Time at which the snapshot was sealed.
    pub sealed_at_unix_ms: u64,
}

impl TaskAttemptVerificationBoundary {
    /// Validates the boundary's complete identity and canonical effect set.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid identity, duplicate or unordered
    /// effect links, or a timestamp before attempt opening.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_verification_boundary.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "task_attempt_verification_boundary.boundary_id",
            &self.boundary_id,
        )?;
        self.attempt.validate()?;
        require_task_attempt_identity(
            "task_attempt_verification_boundary.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_verification_boundary.runner_session_id",
            &self.runner_session_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_verification_boundary.change_set_id",
            &self.change_set_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_verification_boundary.transition_event_id",
            &self.transition_event_id,
        )?;
        let mut previous_effect_id: Option<&str> = None;
        let mut observations = BTreeSet::new();
        for link in &self.terminal_non_cleanup_effects {
            link.validate()?;
            if previous_effect_id.is_some_and(|previous| previous >= link.effect_id.as_str()) {
                return Err(ContractError::new(
                    "task_attempt_verification_boundary.terminal_non_cleanup_effects",
                    "must be in strict effect-id order with no duplicates",
                ));
            }
            if !observations.insert(link.observation_id.as_str()) {
                return Err(ContractError::new(
                    "task_attempt_verification_boundary.terminal_non_cleanup_effects",
                    "must not reuse an observation identity",
                ));
            }
            previous_effect_id = Some(&link.effect_id);
        }
        require_nonzero_timestamp(
            "task_attempt_verification_boundary.sealed_at_unix_ms",
            self.sealed_at_unix_ms,
        )?;
        if self.sealed_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_verification_boundary.sealed_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// One criterion-specific automated formal check under a sealed attempt snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptFormalCheck {
    /// Wire-contract version used to encode the check.
    pub contract_version: u32,
    /// Stable formal-check identity.
    pub formal_check_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Zero-based position in the task's declared automated criterion set.
    pub criterion_ordinal: u32,
    /// Exact acceptance-criterion identity.
    pub criterion_id: String,
    /// Exact command effect.
    pub effect_id: String,
    /// Exact terminal command observation.
    pub observation_id: String,
    /// Complete command verification receipt.
    pub verification_receipt: VerificationReceipt,
    /// Exact task-worker session.
    pub runner_session_id: String,
    /// Exact snapshot sealed by the verification boundary.
    pub sealed_snapshot: Digest,
}

impl TaskAttemptFormalCheck {
    /// Validates the formal check's exact attempt, receipt, and snapshot links.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for crossed identity, snapshot, task, sprint,
    /// or timestamp data.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_formal_check.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "task_attempt_formal_check.formal_check_id",
            &self.formal_check_id,
        )?;
        self.attempt.validate()?;
        require_task_attempt_identity(
            "task_attempt_formal_check.criterion_id",
            &self.criterion_id,
        )?;
        require_task_attempt_identity("task_attempt_formal_check.effect_id", &self.effect_id)?;
        require_task_attempt_identity(
            "task_attempt_formal_check.observation_id",
            &self.observation_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_formal_check.runner_session_id",
            &self.runner_session_id,
        )?;
        self.verification_receipt.validate()?;
        let lease = &self.attempt.worker_lease;
        if self.verification_receipt.sprint_id != lease.sprint_id
            || self.verification_receipt.task_id.as_deref() != Some(lease.task_id.as_str())
        {
            return Err(ContractError::new(
                "task_attempt_formal_check.verification_receipt",
                "must exactly match the attempt sprint and task",
            ));
        }
        if self.verification_receipt.snapshot_id != self.sealed_snapshot {
            return Err(ContractError::new(
                "task_attempt_formal_check.sealed_snapshot",
                "must exactly match the verification receipt snapshot",
            ));
        }
        if self.verification_receipt.finished_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_formal_check.verification_receipt",
                "must not predate attempt opening",
            ));
        }
        Ok(())
    }
}

/// Immutable `Verifying -> Candidate` boundary for one exact formal-check set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptCandidateBoundary {
    /// Wire-contract version used to encode the boundary.
    pub contract_version: u32,
    /// Stable candidate-boundary identity.
    pub boundary_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Exact preceding verification boundary.
    pub verification_boundary_id: String,
    /// Exact sealed change set.
    pub change_set_id: String,
    /// Exact sealed candidate snapshot.
    pub sealed_snapshot: Digest,
    /// Formal-check identities in declared automated-criterion order.
    pub formal_check_ids: Vec<String>,
    /// Verification-receipt identities in the same declared criterion order.
    pub verification_receipt_ids: Vec<String>,
    /// Exact `Verifying -> Candidate` event.
    pub transition_event_id: String,
    /// Time at which candidate state became durable.
    pub admitted_at_unix_ms: u64,
}

impl TaskAttemptCandidateBoundary {
    /// Validates boundary identity, ordering, and timestamp metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for blank or duplicate identities, an invalid
    /// attempt, or a timestamp before attempt opening.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_candidate_boundary.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "task_attempt_candidate_boundary.boundary_id",
            &self.boundary_id,
        )?;
        self.attempt.validate()?;
        require_task_attempt_identity(
            "task_attempt_candidate_boundary.verification_boundary_id",
            &self.verification_boundary_id,
        )?;
        require_task_attempt_identity(
            "task_attempt_candidate_boundary.change_set_id",
            &self.change_set_id,
        )?;
        require_unique_nonblank(
            "task_attempt_candidate_boundary.formal_check_ids",
            &self.formal_check_ids,
        )?;
        require_task_attempt_identity_list(
            "task_attempt_candidate_boundary.formal_check_ids",
            &self.formal_check_ids,
        )?;
        require_unique_nonblank(
            "task_attempt_candidate_boundary.verification_receipt_ids",
            &self.verification_receipt_ids,
        )?;
        require_task_attempt_identity_list(
            "task_attempt_candidate_boundary.verification_receipt_ids",
            &self.verification_receipt_ids,
        )?;
        if self.formal_check_ids.len() != self.verification_receipt_ids.len() {
            return Err(ContractError::new(
                "task_attempt_candidate_boundary.verification_receipt_ids",
                "must contain one exact verification receipt per formal check",
            ));
        }
        require_task_attempt_identity(
            "task_attempt_candidate_boundary.transition_event_id",
            &self.transition_event_id,
        )?;
        require_nonzero_timestamp(
            "task_attempt_candidate_boundary.admitted_at_unix_ms",
            self.admitted_at_unix_ms,
        )?;
        if self.admitted_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_candidate_boundary.admitted_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// Closed semantic category for retained task-attempt evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskAttemptEvidenceKind {
    /// Successful integration evidence.
    Integrated,
    /// Proof that no launch was admitted.
    NeverLaunched,
    /// Runner launch was refused before native effects.
    LaunchRefusedBeforeNativeEffect,
    /// Known worker process exit evidence.
    KnownWorkerExit,
    /// Failed automated formal verification.
    FormalVerificationFailed,
    /// Known candidate rejection.
    CandidateRejectedKnown,
    /// Command output was rejected by the admitted sensitive-output policy.
    SensitiveOutputRejected,
    /// Permanent contract violation.
    PermanentContractViolation,
    /// Proof that a criterion is unsatisfiable.
    CriterionProvenUnsatisfiable,
    /// Additional user authority is required.
    AuthorityExpansionRequired,
    /// A verified dependency is unavailable.
    VerifiedDependencyUnavailable,
    /// Operator cancellation evidence.
    OperatorCanceled,
    /// Terminal unknown-effect evidence followed by known cleanup.
    UnknownTerminalEffect,
    /// Uncertain effect, process-survival, or cleanup evidence.
    UncertainAuthority,
}

/// Bounded exact evidence bytes and their authenticated digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptEvidence {
    /// Stable evidence identity.
    pub evidence_id: String,
    /// Closed semantic evidence category.
    pub kind: TaskAttemptEvidenceKind,
    /// Complete canonical evidence bytes.
    ///
    /// These bytes are retained evidence, not self-authenticating proof. The
    /// ledger must join every typed cause reference to its authoritative
    /// launch, preparation, effect, observation, check, policy, or cleanup row.
    pub canonical_bytes: Vec<u8>,
    /// SHA-256 of `canonical_bytes`.
    pub digest: Digest,
}

impl TaskAttemptEvidence {
    /// Constructs bounded evidence and its exact digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a blank identity or empty/oversized bytes.
    pub fn new(
        evidence_id: String,
        kind: TaskAttemptEvidenceKind,
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let digest = Digest::sha256(&canonical_bytes);
        let evidence = Self {
            evidence_id,
            kind,
            canonical_bytes,
            digest,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Validates identity, byte bounds, and the exact evidence digest.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when evidence is missing, oversized, or has a
    /// substituted digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_task_attempt_identity("task_attempt_evidence.evidence_id", &self.evidence_id)?;
        if self.canonical_bytes.is_empty()
            || self.canonical_bytes.len() > MAX_TASK_ATTEMPT_EVIDENCE_BYTES
        {
            return Err(ContractError::new(
                "task_attempt_evidence.canonical_bytes",
                format!("must contain 1..={MAX_TASK_ATTEMPT_EVIDENCE_BYTES} retained bytes"),
            ));
        }
        if Digest::sha256(&self.canonical_bytes) != self.digest {
            return Err(ContractError::new(
                "task_attempt_evidence.digest",
                "must equal the SHA-256 of the retained canonical bytes",
            ));
        }
        Ok(())
    }

    fn validate_kind(&self, expected: TaskAttemptEvidenceKind) -> Result<(), ContractError> {
        self.validate()?;
        if self.kind != expected {
            return Err(ContractError::new(
                "task_attempt_evidence.kind",
                format!("expected {expected:?}, got {:?}", self.kind),
            ));
        }
        Ok(())
    }
}

/// Proof that a lease was released before any launch authority existed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerLeaseNeverLaunchedRelease {
    /// Wire-contract version used to encode the release.
    pub contract_version: u32,
    /// Stable append-only release identity.
    pub release_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Exact retained absence proof.
    pub absence_evidence: TaskAttemptEvidence,
    /// Release time.
    pub released_at_unix_ms: u64,
}

impl WorkerLeaseNeverLaunchedRelease {
    /// Validates exact attempt, evidence category, and release time.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for invalid identity, evidence, or ordering.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "worker_lease_never_launched_release.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "worker_lease_never_launched_release.release_id",
            &self.release_id,
        )?;
        self.attempt.validate()?;
        self.absence_evidence
            .validate_kind(TaskAttemptEvidenceKind::NeverLaunched)?;
        require_nonzero_timestamp(
            "worker_lease_never_launched_release.released_at_unix_ms",
            self.released_at_unix_ms,
        )?;
        if self.released_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "worker_lease_never_launched_release.released_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// Exact zero-survivor cleanup release for one launched attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptCleanupRelease {
    /// Wire-contract version used to encode the release.
    pub contract_version: u32,
    /// Stable append-only release identity.
    pub release_id: String,
    /// Complete attempt identity.
    pub attempt: TaskAttempt,
    /// Exact zero-survivor worker cleanup receipt.
    pub cleanup_receipt: WorkerCleanupReceipt,
    /// Release time, equal to cleanup observation time.
    pub released_at_unix_ms: u64,
}

impl TaskAttemptCleanupRelease {
    /// Validates the exact lease-to-cleanup release relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for crossed identity or timestamp data.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_cleanup_release.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity("task_attempt_cleanup_release.release_id", &self.release_id)?;
        self.attempt.validate()?;
        self.cleanup_receipt.validate()?;
        if self.cleanup_receipt.worker_lease.as_ref() != Some(&self.attempt.worker_lease) {
            return Err(ContractError::new(
                "task_attempt_cleanup_release.cleanup_receipt",
                "must carry the exact attempt worker lease",
            ));
        }
        if self.released_at_unix_ms != self.cleanup_receipt.cleaned_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_cleanup_release.released_at_unix_ms",
                "must exactly equal cleanup observation time",
            ));
        }
        Ok(())
    }
}

/// Closed typed release proof for one non-integrated attempt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptReleaseProof {
    /// A launched worker domain was cleaned to zero survivors.
    Cleanup(TaskAttemptCleanupRelease),
    /// No launch or native authority was ever admitted.
    NeverLaunched(WorkerLeaseNeverLaunchedRelease),
}

impl TaskAttemptReleaseProof {
    pub(super) fn validate_against(&self, attempt: &TaskAttempt) -> Result<(), ContractError> {
        match self {
            Self::Cleanup(release) => {
                release.validate()?;
                if &release.attempt != attempt {
                    return Err(ContractError::new(
                        "task_attempt_release_proof.attempt",
                        "cleanup release must carry the exact disposition attempt",
                    ));
                }
            }
            Self::NeverLaunched(release) => {
                release.validate()?;
                if &release.attempt != attempt {
                    return Err(ContractError::new(
                        "task_attempt_release_proof.attempt",
                        "no-launch release must carry the exact disposition attempt",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns the stable release identity.
    #[must_use]
    pub fn release_id(&self) -> &str {
        match self {
            Self::Cleanup(release) => &release.release_id,
            Self::NeverLaunched(release) => &release.release_id,
        }
    }

    /// Returns the exact release timestamp.
    #[must_use]
    pub const fn released_at_unix_ms(&self) -> u64 {
        match self {
            Self::Cleanup(release) => release.released_at_unix_ms,
            Self::NeverLaunched(release) => release.released_at_unix_ms,
        }
    }
}

/// Retry-eligible failure causes. The ledger alone selects retry vs exhaustion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptRetryableCause {
    /// No task-worker launch was admitted.
    NeverLaunched {
        /// Exact no-launch absence evidence, identical to the release proof.
        evidence: TaskAttemptEvidence,
    },
    /// A named launch was refused before any native effect.
    LaunchRefusedBeforeNativeEffect {
        /// Exact launch identity.
        launch_id: String,
        /// Exact refusal evidence.
        evidence: TaskAttemptEvidence,
    },
    /// A known worker exit was observed.
    KnownWorkerExit {
        /// Exact launch identity.
        launch_id: String,
        /// Exact session identity.
        session_id: String,
        /// Exact exit evidence.
        evidence: TaskAttemptEvidence,
    },
    /// One exact formal check failed.
    FormalVerificationFailed {
        /// Exact formal-check identity.
        formal_check_id: String,
        /// Exact failed-check evidence.
        evidence: TaskAttemptEvidence,
    },
    /// An exact candidate was rejected with known evidence.
    CandidateRejectedKnown {
        /// Exact candidate-boundary identity.
        candidate_boundary_id: String,
        /// Exact rejection evidence.
        evidence: TaskAttemptEvidence,
    },
    /// One exact command effect was rejected after sensitive output was
    /// detected and its capture obligation was fully cleaned and closed.
    SensitiveOutputRejected {
        /// Exact rejected command effect identity.
        effect_id: String,
        /// Exact secret-free rejection-anchor bytes, identified by the
        /// rejected effect observation.
        evidence: TaskAttemptEvidence,
    },
}

impl TaskAttemptRetryableCause {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::NeverLaunched { evidence } => {
                evidence.validate_kind(TaskAttemptEvidenceKind::NeverLaunched)
            }
            Self::LaunchRefusedBeforeNativeEffect {
                launch_id,
                evidence,
            } => {
                require_task_attempt_identity("task_attempt_cause.launch_id", launch_id)?;
                evidence.validate_kind(TaskAttemptEvidenceKind::LaunchRefusedBeforeNativeEffect)
            }
            Self::KnownWorkerExit {
                launch_id,
                session_id,
                evidence,
            } => {
                require_task_attempt_identity("task_attempt_cause.launch_id", launch_id)?;
                require_task_attempt_identity("task_attempt_cause.session_id", session_id)?;
                evidence.validate_kind(TaskAttemptEvidenceKind::KnownWorkerExit)
            }
            Self::FormalVerificationFailed {
                formal_check_id,
                evidence,
            } => {
                require_task_attempt_identity(
                    "task_attempt_cause.formal_check_id",
                    formal_check_id,
                )?;
                evidence.validate_kind(TaskAttemptEvidenceKind::FormalVerificationFailed)
            }
            Self::CandidateRejectedKnown {
                candidate_boundary_id,
                evidence,
            } => {
                require_task_attempt_identity(
                    "task_attempt_cause.candidate_boundary_id",
                    candidate_boundary_id,
                )?;
                evidence.validate_kind(TaskAttemptEvidenceKind::CandidateRejectedKnown)
            }
            Self::SensitiveOutputRejected {
                effect_id,
                evidence,
            } => {
                require_task_attempt_identity("task_attempt_cause.effect_id", effect_id)?;
                evidence.validate_kind(TaskAttemptEvidenceKind::SensitiveOutputRejected)
            }
        }
    }

    fn validate_release_coupling(
        &self,
        release_proof: &TaskAttemptReleaseProof,
    ) -> Result<(), ContractError> {
        match (self, release_proof) {
            (Self::NeverLaunched { evidence }, TaskAttemptReleaseProof::NeverLaunched(release))
                if evidence == &release.absence_evidence =>
            {
                Ok(())
            }
            (
                Self::LaunchRefusedBeforeNativeEffect { .. }
                | Self::KnownWorkerExit { .. }
                | Self::FormalVerificationFailed { .. }
                | Self::CandidateRejectedKnown { .. }
                | Self::SensitiveOutputRejected { .. },
                TaskAttemptReleaseProof::Cleanup(_),
            ) => Ok(()),
            (Self::NeverLaunched { .. }, TaskAttemptReleaseProof::NeverLaunched(_)) => {
                Err(ContractError::new(
                    "task_attempt_disposition.release_proof",
                    "NeverLaunched cause evidence must exactly equal the no-launch absence evidence",
                ))
            }
            _ => Err(ContractError::new(
                "task_attempt_disposition.release_proof",
                "NeverLaunched requires a no-launch release; every other retryable cause requires cleanup",
            )),
        }
    }
}

/// Proven non-retryable failure causes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptPermanentFailureCause {
    /// A permanent contract violation was proven.
    PermanentContractViolation {
        /// Stable violation identity.
        violation_id: String,
        /// Exact violation evidence.
        evidence: TaskAttemptEvidence,
    },
    /// One criterion was proven unsatisfiable.
    CriterionProvenUnsatisfiable {
        /// Exact criterion identity.
        criterion_id: String,
        /// Exact proof evidence.
        evidence: TaskAttemptEvidence,
    },
}

impl TaskAttemptPermanentFailureCause {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::PermanentContractViolation {
                violation_id,
                evidence,
            } => {
                require_task_attempt_identity("task_attempt_cause.violation_id", violation_id)?;
                evidence.validate_kind(TaskAttemptEvidenceKind::PermanentContractViolation)
            }
            Self::CriterionProvenUnsatisfiable {
                criterion_id,
                evidence,
            } => {
                require_task_attempt_identity("task_attempt_cause.criterion_id", criterion_id)?;
                evidence.validate_kind(TaskAttemptEvidenceKind::CriterionProvenUnsatisfiable)
            }
        }
    }
}

/// Causes that require additional external authority before progress.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptBlockedCause {
    /// The requested work exceeds current authority.
    AuthorityExpansionRequired {
        /// Stable authority request identity.
        authority_request_id: String,
        /// Exact policy evidence.
        evidence: TaskAttemptEvidence,
    },
    /// A verified dependency is unavailable.
    VerifiedDependencyUnavailable {
        /// Exact dependency task identity.
        dependency_task_id: String,
        /// Exact unavailability evidence.
        evidence: TaskAttemptEvidence,
    },
}

impl TaskAttemptBlockedCause {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::AuthorityExpansionRequired {
                authority_request_id,
                evidence,
            } => {
                require_task_attempt_identity(
                    "task_attempt_cause.authority_request_id",
                    authority_request_id,
                )?;
                evidence.validate_kind(TaskAttemptEvidenceKind::AuthorityExpansionRequired)
            }
            Self::VerifiedDependencyUnavailable {
                dependency_task_id,
                evidence,
            } => {
                require_task_attempt_identity(
                    "task_attempt_cause.dependency_task_id",
                    dependency_task_id,
                )?;
                evidence.validate_kind(TaskAttemptEvidenceKind::VerifiedDependencyUnavailable)
            }
        }
    }
}

/// Exact operator cancellation cause.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptCanceledCause {
    /// Stable cancellation decision identity.
    pub cancellation_id: String,
    /// Exact cancellation evidence.
    pub evidence: TaskAttemptEvidence,
}

impl TaskAttemptCanceledCause {
    fn validate(&self) -> Result<(), ContractError> {
        require_task_attempt_identity("task_attempt_cause.cancellation_id", &self.cancellation_id)?;
        self.evidence
            .validate_kind(TaskAttemptEvidenceKind::OperatorCanceled)
    }
}

/// Exact terminal unknown-effect evidence followed by known cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptUnknownEvidence {
    /// Exact effect whose outcome remained unknown.
    pub effect_id: String,
    /// Exact unknown observation.
    pub observation_id: String,
    /// Complete retained unknown evidence.
    pub evidence: TaskAttemptEvidence,
}

impl TaskAttemptUnknownEvidence {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        require_task_attempt_identity("task_attempt_unknown_evidence.effect_id", &self.effect_id)?;
        require_task_attempt_identity(
            "task_attempt_unknown_evidence.observation_id",
            &self.observation_id,
        )?;
        self.evidence
            .validate_kind(TaskAttemptEvidenceKind::UnknownTerminalEffect)
    }
}

/// Exact evidence that effect, process-survival, or cleanup state is uncertain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptUncertainEvidence {
    /// Stable uncertainty identity.
    pub uncertainty_id: String,
    /// Exact involved authority identities in strict lexical order.
    pub authority_reference_ids: Vec<String>,
    /// Complete retained uncertainty evidence.
    pub evidence: TaskAttemptEvidence,
}

impl TaskAttemptUncertainEvidence {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        require_task_attempt_identity(
            "task_attempt_uncertain_evidence.uncertainty_id",
            &self.uncertainty_id,
        )?;
        require_unique_nonblank(
            "task_attempt_uncertain_evidence.authority_reference_ids",
            &self.authority_reference_ids,
        )?;
        require_task_attempt_identity_list(
            "task_attempt_uncertain_evidence.authority_reference_ids",
            &self.authority_reference_ids,
        )?;
        if self.authority_reference_ids.is_empty() {
            return Err(ContractError::new(
                "task_attempt_uncertain_evidence.authority_reference_ids",
                "must retain at least one uncertain authority identity",
            ));
        }
        require_strict_lexical_order(
            "task_attempt_uncertain_evidence.authority_reference_ids",
            &self.authority_reference_ids,
        )?;
        self.evidence
            .validate_kind(TaskAttemptEvidenceKind::UncertainAuthority)
    }
}

/// Identity and transition metadata shared by every attempt disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptDispositionMetadata {
    /// Wire-contract version used to encode the disposition.
    pub contract_version: u32,
    /// Stable disposition identity.
    pub disposition_id: String,
    /// Complete attempt identity and ordinal.
    pub attempt: TaskAttempt,
    /// Attempted phase from which the disposition transitioned.
    pub from_state: TaskState,
    /// Exact task-state transition event.
    pub state_transition_event_id: String,
    /// Durable disposition time.
    pub disposed_at_unix_ms: u64,
}

impl TaskAttemptDispositionMetadata {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_disposition.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "task_attempt_disposition.disposition_id",
            &self.disposition_id,
        )?;
        self.attempt.validate()?;
        if !is_attempted_task_phase(self.from_state) {
            return Err(ContractError::new(
                "task_attempt_disposition.from_state",
                "must be Leased, Running, Verifying, or Candidate",
            ));
        }
        require_task_attempt_identity(
            "task_attempt_disposition.state_transition_event_id",
            &self.state_transition_event_id,
        )?;
        require_nonzero_timestamp(
            "task_attempt_disposition.disposed_at_unix_ms",
            self.disposed_at_unix_ms,
        )?;
        if self.disposed_at_unix_ms < self.attempt.opened_at_unix_ms {
            return Err(ContractError::new(
                "task_attempt_disposition.disposed_at_unix_ms",
                "must not precede attempt opening",
            ));
        }
        Ok(())
    }
}

/// Successful integrated disposition evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptIntegratedDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Exact candidate boundary.
    pub candidate_boundary: TaskAttemptCandidateBoundary,
    /// Exact successful task-integration receipt.
    pub integration_receipt: TaskIntegrationReceipt,
    /// Retained canonical integration evidence.
    pub evidence: TaskAttemptEvidence,
}

/// Safely failed disposition with budget remaining.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptRetryableDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Closed retry-eligible cause.
    pub cause: TaskAttemptRetryableCause,
    /// Exact append-only release proof.
    pub release_proof: TaskAttemptReleaseProof,
}

/// Safely failed disposition at the immutable attempt limit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptAttemptsExhaustedDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Closed retry-eligible cause.
    pub cause: TaskAttemptRetryableCause,
    /// Exact append-only release proof.
    pub release_proof: TaskAttemptReleaseProof,
}

/// Proven permanent-failure disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptPermanentFailureDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Closed permanent-failure cause.
    pub cause: TaskAttemptPermanentFailureCause,
    /// Exact append-only release proof.
    pub release_proof: TaskAttemptReleaseProof,
}

/// Authority-blocked disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptBlockedDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Closed blocking cause.
    pub cause: TaskAttemptBlockedCause,
    /// Exact append-only release proof.
    pub release_proof: TaskAttemptReleaseProof,
}

/// Operator-canceled disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptCanceledDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Exact operator cancellation cause.
    pub cause: TaskAttemptCanceledCause,
    /// Exact append-only release proof.
    pub release_proof: TaskAttemptReleaseProof,
}

/// Cleaned unknown-effect disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptUnknownCleanedDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Exact terminal unknown-effect evidence.
    pub unknown_evidence: TaskAttemptUnknownEvidence,
    /// Exact zero-survivor cleanup release.
    pub cleanup_release: TaskAttemptCleanupRelease,
}

/// Quarantined uncertain-authority disposition.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptUnknownQuarantinedDisposition {
    /// Shared attempt and transition identity.
    pub metadata: TaskAttemptDispositionMetadata,
    /// Exact retained uncertainty evidence.
    pub uncertain_evidence: TaskAttemptUncertainEvidence,
}

/// Closed typed outcome for one exact task attempt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptDisposition {
    /// Candidate and integration evidence succeeded atomically.
    Integrated(TaskAttemptIntegratedDisposition),
    /// Known safe failure with another attempt available.
    Retryable(TaskAttemptRetryableDisposition),
    /// Known safe failure on the final permitted attempt.
    AttemptsExhausted(TaskAttemptAttemptsExhaustedDisposition),
    /// Proven non-retryable failure.
    PermanentFailure(TaskAttemptPermanentFailureDisposition),
    /// Progress requires new authority or a verified dependency.
    Blocked(TaskAttemptBlockedDisposition),
    /// Operator cancellation completed with cleanup.
    Canceled(TaskAttemptCanceledDisposition),
    /// Unknown effect was cleaned to zero survivors.
    UnknownCleaned(TaskAttemptUnknownCleanedDisposition),
    /// Uncertain authority remains actively quarantined.
    UnknownQuarantined(TaskAttemptUnknownQuarantinedDisposition),
}

impl TaskAttemptDisposition {
    /// Validates the closed cause matrix and immutable attempt budget result.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for crossed evidence, release, transition,
    /// identity, or caller-selected retry/exhaustion state.
    #[allow(clippy::too_many_lines)]
    pub fn validate_for_budget(&self, max_attempts_per_task: u8) -> Result<(), ContractError> {
        if max_attempts_per_task == 0 {
            return Err(ContractError::new(
                "task_attempt_disposition.max_attempts_per_task",
                "must be greater than zero",
            ));
        }
        let metadata = self.metadata();
        metadata.validate()?;
        if metadata.attempt.attempt_ordinal > u32::from(max_attempts_per_task) {
            return Err(ContractError::new(
                "task_attempt_disposition.attempt_ordinal",
                "must not exceed the immutable task attempt budget",
            ));
        }
        match self {
            Self::Integrated(disposition) => {
                if disposition.metadata.from_state != TaskState::Candidate {
                    return Err(invalid_disposition_transition("Candidate", "Integrated"));
                }
                disposition.candidate_boundary.validate()?;
                disposition.integration_receipt.validate()?;
                disposition
                    .evidence
                    .validate_kind(TaskAttemptEvidenceKind::Integrated)?;
                validate_nested_attempt(
                    &disposition.metadata.attempt,
                    &disposition.candidate_boundary.attempt,
                )?;
                validate_integration_disposition(disposition)?;
            }
            Self::Retryable(disposition) => {
                if disposition.metadata.attempt.attempt_ordinal >= u32::from(max_attempts_per_task)
                {
                    return Err(ContractError::new(
                        "task_attempt_disposition",
                        "Retryable is permitted only before the immutable attempt limit",
                    ));
                }
                disposition.cause.validate()?;
                disposition
                    .release_proof
                    .validate_against(&disposition.metadata.attempt)?;
                disposition
                    .cause
                    .validate_release_coupling(&disposition.release_proof)?;
            }
            Self::AttemptsExhausted(disposition) => {
                if disposition.metadata.attempt.attempt_ordinal != u32::from(max_attempts_per_task)
                {
                    return Err(ContractError::new(
                        "task_attempt_disposition",
                        "AttemptsExhausted is required exactly at the immutable attempt limit",
                    ));
                }
                disposition.cause.validate()?;
                disposition
                    .release_proof
                    .validate_against(&disposition.metadata.attempt)?;
                disposition
                    .cause
                    .validate_release_coupling(&disposition.release_proof)?;
            }
            Self::PermanentFailure(disposition) => {
                disposition.cause.validate()?;
                disposition
                    .release_proof
                    .validate_against(&disposition.metadata.attempt)?;
            }
            Self::Blocked(disposition) => {
                disposition.cause.validate()?;
                disposition
                    .release_proof
                    .validate_against(&disposition.metadata.attempt)?;
            }
            Self::Canceled(disposition) => {
                disposition.cause.validate()?;
                disposition
                    .release_proof
                    .validate_against(&disposition.metadata.attempt)?;
            }
            Self::UnknownCleaned(disposition) => {
                disposition.unknown_evidence.validate()?;
                disposition.cleanup_release.validate()?;
                validate_nested_attempt(
                    &disposition.metadata.attempt,
                    &disposition.cleanup_release.attempt,
                )?;
            }
            Self::UnknownQuarantined(disposition) => {
                disposition.uncertain_evidence.validate()?;
            }
        }
        let latest_evidence_time = match self {
            Self::Integrated(disposition) => Some(
                disposition
                    .candidate_boundary
                    .admitted_at_unix_ms
                    .max(disposition.integration_receipt.integrated_at_unix_ms),
            ),
            Self::Retryable(disposition) => Some(disposition.release_proof.released_at_unix_ms()),
            Self::AttemptsExhausted(disposition) => {
                Some(disposition.release_proof.released_at_unix_ms())
            }
            Self::PermanentFailure(disposition) => {
                Some(disposition.release_proof.released_at_unix_ms())
            }
            Self::Blocked(disposition) => Some(disposition.release_proof.released_at_unix_ms()),
            Self::Canceled(disposition) => Some(disposition.release_proof.released_at_unix_ms()),
            Self::UnknownCleaned(disposition) => {
                Some(disposition.cleanup_release.released_at_unix_ms)
            }
            Self::UnknownQuarantined(_) => None,
        };
        if latest_evidence_time.is_some_and(|timestamp| timestamp > metadata.disposed_at_unix_ms) {
            return Err(ContractError::new(
                "task_attempt_disposition.disposed_at_unix_ms",
                "must not precede candidate, integration, cleanup, or release evidence",
            ));
        }
        Ok(())
    }

    /// Returns the shared exact disposition metadata.
    #[must_use]
    pub const fn metadata(&self) -> &TaskAttemptDispositionMetadata {
        match self {
            Self::Integrated(value) => &value.metadata,
            Self::Retryable(value) => &value.metadata,
            Self::AttemptsExhausted(value) => &value.metadata,
            Self::PermanentFailure(value) => &value.metadata,
            Self::Blocked(value) => &value.metadata,
            Self::Canceled(value) => &value.metadata,
            Self::UnknownCleaned(value) => &value.metadata,
            Self::UnknownQuarantined(value) => &value.metadata,
        }
    }

    /// Returns the task state committed by this disposition.
    #[must_use]
    pub const fn resulting_task_state(&self) -> TaskState {
        match self {
            Self::Integrated(_) => TaskState::Integrated,
            Self::Retryable(_) => TaskState::Ready,
            Self::AttemptsExhausted(_) | Self::PermanentFailure(_) => TaskState::Failed,
            Self::Blocked(_) => TaskState::Blocked,
            Self::Canceled(_) => TaskState::Canceled,
            Self::UnknownCleaned(_) | Self::UnknownQuarantined(_) => TaskState::Unknown,
        }
    }

    /// Returns whether the disposition requires an append-only lease release.
    #[must_use]
    pub const fn requires_release(&self) -> bool {
        !matches!(self, Self::Integrated(_) | Self::UnknownQuarantined(_))
    }

    /// Returns the release proof for a non-integrated known disposition.
    #[must_use]
    pub const fn release_proof(&self) -> Option<&TaskAttemptReleaseProof> {
        match self {
            Self::Retryable(value) => Some(&value.release_proof),
            Self::AttemptsExhausted(value) => Some(&value.release_proof),
            Self::PermanentFailure(value) => Some(&value.release_proof),
            Self::Blocked(value) => Some(&value.release_proof),
            Self::Canceled(value) => Some(&value.release_proof),
            Self::Integrated(_) | Self::UnknownCleaned(_) | Self::UnknownQuarantined(_) => None,
        }
    }
}

pub(super) fn validate_integration_disposition(
    disposition: &TaskAttemptIntegratedDisposition,
) -> Result<(), ContractError> {
    let attempt = &disposition.metadata.attempt;
    let lease = &attempt.worker_lease;
    let boundary = &disposition.candidate_boundary;
    let receipt = &disposition.integration_receipt;
    if receipt.worker_lease.as_ref() != Some(lease)
        || receipt.sprint_id != lease.sprint_id
        || receipt.task_id != lease.task_id
        || receipt.worker_id != lease.worker_id
        || receipt.change_set_id != boundary.change_set_id
        || receipt.result_snapshot != boundary.sealed_snapshot
        || receipt.task_verification_receipt_ids != boundary.verification_receipt_ids
    {
        return Err(ContractError::new(
            "task_attempt_disposition.integration",
            "candidate and integration evidence must exactly match the disposition attempt",
        ));
    }
    Ok(())
}

pub(super) fn validate_nested_attempt(
    expected: &TaskAttempt,
    actual: &TaskAttempt,
) -> Result<(), ContractError> {
    if expected != actual {
        return Err(ContractError::new(
            "task_attempt_disposition.attempt",
            "nested evidence must carry the exact disposition attempt",
        ));
    }
    Ok(())
}

pub(super) fn invalid_disposition_transition(from: &str, to: &str) -> ContractError {
    ContractError::new(
        "task_attempt_disposition.from_state",
        format!("{to} disposition requires exact {from} source state"),
    )
}

pub(super) const fn is_attempted_task_phase(state: TaskState) -> bool {
    matches!(
        state,
        TaskState::Leased | TaskState::Running | TaskState::Verifying | TaskState::Candidate
    )
}

/// Immutable classification of one schema-v14 attempt backfill.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LegacyTaskAttemptClassification {
    /// Lease was released without a current typed disposition.
    LegacyReleased,
    /// Lease remains open and cannot resume as a current attempt.
    LegacyOpen,
    /// Integration is durable but cleanup and release remain pending.
    LegacyIntegratedCleanupPending,
    /// Integration and cleanup are both durably complete.
    LegacyIntegratedReleased,
    /// Lease was released while the historical task state remained active.
    LegacyReleasedActiveState,
    /// Historical unknown authority remains actively quarantined.
    LegacyUnknownQuarantine,
}

/// Orthogonal immutable attempt-budget classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskAttemptBudgetClassification {
    /// Acquisition count is within the immutable sprint maximum.
    WithinBudget,
    /// Historical acquisition count exceeds the immutable sprint maximum.
    OverBudget,
}

/// Durable active/released projection for one attempt lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptLeaseState {
    /// Lease still consumes worker capacity and scopes.
    Active,
    /// Append-only release exists.
    Released {
        /// Exact release identity.
        release_id: String,
        /// Exact release time.
        released_at_unix_ms: u64,
    },
}

impl TaskAttemptLeaseState {
    fn validate_for_attempt(&self, attempt: &TaskAttempt) -> Result<(), ContractError> {
        if let Self::Released {
            release_id,
            released_at_unix_ms,
        } = self
        {
            require_task_attempt_identity("task_attempt_lease_state.release_id", release_id)?;
            require_nonzero_timestamp(
                "task_attempt_lease_state.released_at_unix_ms",
                *released_at_unix_ms,
            )?;
            if *released_at_unix_ms < attempt.opened_at_unix_ms {
                return Err(ContractError::new(
                    "task_attempt_lease_state.released_at_unix_ms",
                    "must not precede attempt opening",
                ));
            }
        }
        Ok(())
    }

    /// Returns whether the lease remains active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Durable marker that freezes a sprint while unknown domains terminalize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintUnknownTerminalizationPending {
    /// Wire-contract version used to encode the marker.
    pub contract_version: u32,
    /// Stable marker identity.
    pub marker_id: String,
    /// Frozen sprint identity.
    pub sprint_id: String,
    /// First attempt that forced unknown terminalization.
    pub first_attempt_id: String,
    /// Exact unknown disposition that opened the marker.
    pub first_disposition_id: String,
    /// Marker creation time.
    pub created_at_unix_ms: u64,
}

impl SprintUnknownTerminalizationPending {
    /// Validates marker identity and timestamp metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "sprint_unknown_terminalization_pending.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_pending.marker_id",
            &self.marker_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_pending.sprint_id",
            &self.sprint_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_pending.first_attempt_id",
            &self.first_attempt_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_pending.first_disposition_id",
            &self.first_disposition_id,
        )?;
        require_nonzero_timestamp(
            "sprint_unknown_terminalization_pending.created_at_unix_ms",
            self.created_at_unix_ms,
        )
    }
}

/// Durable closure joining a pending unknown marker to sprint `Unknown`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SprintUnknownTerminalizationClosure {
    /// Stable pending-marker identity being closed.
    pub marker_id: String,
    /// Frozen sprint identity.
    pub sprint_id: String,
    /// Exact sprint-terminal evidence identity.
    pub terminal_evidence_id: String,
    /// Exact normalized sprint-terminal event identity.
    pub terminal_event_id: String,
    /// Wire-contract version shared by the marker and terminal evidence.
    pub contract_version: u32,
    /// Time at which all domains reached an exact terminal shape.
    pub closed_at_unix_ms: u64,
}

impl SprintUnknownTerminalizationClosure {
    /// Validates closure identities, version, and timestamp metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_version(
            "sprint_unknown_terminalization_closure.contract_version",
            self.contract_version,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_closure.marker_id",
            &self.marker_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_closure.sprint_id",
            &self.sprint_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_closure.terminal_evidence_id",
            &self.terminal_evidence_id,
        )?;
        require_task_attempt_identity(
            "sprint_unknown_terminalization_closure.terminal_event_id",
            &self.terminal_event_id,
        )?;
        require_nonzero_timestamp(
            "sprint_unknown_terminalization_closure.closed_at_unix_ms",
            self.closed_at_unix_ms,
        )
    }
}

/// One ordered attempt and all of its current phase/outcome evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptHistoryEntry {
    /// Exact attempt opened by the lease acquisition.
    pub attempt: TaskAttempt,
    /// Optional immutable `Leased -> Running` boundary.
    pub running_boundary: Option<TaskAttemptRunningBoundary>,
    /// Optional immutable `Running -> Verifying` boundary.
    pub verification_boundary: Option<TaskAttemptVerificationBoundary>,
    /// Formal checks in exact automated-criterion order.
    pub formal_checks: Vec<TaskAttemptFormalCheck>,
    /// Optional immutable `Verifying -> Candidate` boundary.
    pub candidate_boundary: Option<TaskAttemptCandidateBoundary>,
    /// Current typed disposition, absent only while an attempt is open.
    pub disposition: Option<TaskAttemptDisposition>,
    /// Immutable pre-v15 classification, mutually exclusive with disposition.
    pub legacy_classification: Option<LegacyTaskAttemptClassification>,
    /// Exact active/released lease projection.
    pub lease_state: TaskAttemptLeaseState,
}
impl TaskAttemptHistoryEntry {
    fn validate(&self, max_attempts_per_task: u8) -> Result<(), ContractError> {
        self.attempt.validate()?;
        self.lease_state.validate_for_attempt(&self.attempt)?;
        if self.disposition.is_some() && self.legacy_classification.is_some() {
            return Err(ContractError::new(
                "task_attempt_history.entry",
                "current disposition and legacy classification are mutually exclusive",
            ));
        }
        if let Some(boundary) = &self.running_boundary {
            boundary.validate()?;
            validate_nested_attempt(&self.attempt, &boundary.attempt)?;
        }
        if let Some(boundary) = &self.verification_boundary {
            boundary.validate()?;
            validate_nested_attempt(&self.attempt, &boundary.attempt)?;
            let running = self.running_boundary.as_ref().ok_or_else(|| {
                ContractError::new(
                    "task_attempt_history.verification_boundary",
                    "requires the exact preceding Running boundary",
                )
            })?;
            if boundary.runner_launch_id != running.runner_launch_id
                || boundary.runner_session_id != running.runner_session_id
            {
                return Err(ContractError::new(
                    "task_attempt_history.verification_boundary",
                    "must retain the exact Running-boundary launch and session",
                ));
            }
            if boundary.sealed_at_unix_ms < running.started_at_unix_ms {
                return Err(ContractError::new(
                    "task_attempt_history.verification_boundary",
                    "must not precede the Running boundary",
                ));
            }
        }
        for check in &self.formal_checks {
            check.validate()?;
            validate_nested_attempt(&self.attempt, &check.attempt)?;
        }
        if let Some(boundary) = &self.candidate_boundary {
            boundary.validate()?;
            validate_nested_attempt(&self.attempt, &boundary.attempt)?;
        }
        if let Some(disposition) = &self.disposition {
            disposition.validate_for_budget(max_attempts_per_task)?;
            validate_nested_attempt(&self.attempt, &disposition.metadata().attempt)?;
        }
        validate_legacy_lease_shape(self)?;
        validate_disposition_lease_shape(self)?;
        Ok(())
    }
}

/// Complete ordered task-attempt projection for one graph task.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAttemptHistory {
    /// Wire-contract version used to encode the projection.
    pub contract_version: u32,
    /// Owning sprint identity.
    pub sprint_id: String,
    /// Exact graph task identity.
    pub task_id: String,
    /// Current durable task state.
    pub task_state: TaskState,
    /// Current durable sprint state, repeated exactly in every task history.
    pub sprint_state: SprintState,
    /// Attempts in contiguous task-local ordinal order.
    pub attempts: Vec<TaskAttemptHistoryEntry>,
    /// Orthogonal immutable budget classification.
    pub budget_classification: TaskAttemptBudgetClassification,
    /// Present while unknown terminalization freezes scheduler proposals.
    pub unknown_terminalization_pending: Option<SprintUnknownTerminalizationPending>,
}

impl TaskAttemptHistory {
    /// Validates task-local identity, ordering, budget, phase, and active state.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for ordinal gaps, crossed identities,
    /// over-budget mismatch, impossible phase shapes, or invalid active state.
    pub fn validate_for_task(
        &self,
        sprint: &SprintSpec,
        task: &TaskSpec,
    ) -> Result<(), ContractError> {
        require_contract_version(
            "task_attempt_history.contract_version",
            self.contract_version,
        )?;
        if self.sprint_id != sprint.sprint_id || self.task_id != task.task_id {
            return Err(ContractError::new(
                "task_attempt_history.identity",
                "must exactly match the owning sprint and graph task",
            ));
        }
        if let Some(marker) = &self.unknown_terminalization_pending {
            marker.validate()?;
            if marker.sprint_id != self.sprint_id {
                return Err(ContractError::new(
                    "task_attempt_history.unknown_terminalization_pending",
                    "must belong to the history sprint",
                ));
            }
            if self.sprint_state.is_terminal() {
                return Err(ContractError::new(
                    "task_attempt_history.unknown_terminalization_pending",
                    "pending marker must be closed before sprint terminal state is durable",
                ));
            }
        }
        let expected_budget =
            if self.attempts.len() > usize::from(sprint.budget.max_attempts_per_task) {
                TaskAttemptBudgetClassification::OverBudget
            } else {
                TaskAttemptBudgetClassification::WithinBudget
            };
        if self.budget_classification != expected_budget {
            return Err(ContractError::new(
                "task_attempt_history.budget_classification",
                "must exactly reflect immutable acquisition count versus budget",
            ));
        }
        let mut previous_epoch = None;
        for (index, entry) in self.attempts.iter().enumerate() {
            entry.validate(sprint.budget.max_attempts_per_task)?;
            let expected_ordinal = u32::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| {
                    ContractError::new(
                        "task_attempt_history.attempts",
                        "attempt count exceeds canonical u32 ordinal range",
                    )
                })?;
            if entry.attempt.attempt_ordinal != expected_ordinal {
                return Err(ContractError::new(
                    "task_attempt_history.attempts",
                    "attempt ordinals must be contiguous from one",
                ));
            }
            let lease = &entry.attempt.worker_lease;
            if lease.sprint_id != self.sprint_id
                || lease.task_id != self.task_id
                || lease.path_scopes != task.path_scopes
            {
                return Err(ContractError::new(
                    "task_attempt_history.attempts",
                    "every attempt lease must exactly match sprint, task, and graph scopes",
                ));
            }
            if previous_epoch.is_some_and(|epoch| epoch >= lease.lease_epoch) {
                return Err(ContractError::new(
                    "task_attempt_history.attempts",
                    "lease epochs must increase strictly with task-local ordinals",
                ));
            }
            previous_epoch = Some(lease.lease_epoch);
        }
        validate_history_phase_shape(self, sprint, task)
    }

    /// Returns the sole active attempt, when one exists.
    #[must_use]
    pub fn active_attempt(&self) -> Option<&TaskAttemptHistoryEntry> {
        self.attempts
            .iter()
            .find(|entry| entry.lease_state.is_active())
    }
}

/// Closed recovery action for one exact task attempt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskAttemptRecoveryDecision {
    /// Current attempt may continue under its exact active authority.
    ContinueActive,
    /// Integrated attempt still needs native cleanup and release.
    IntegratedCleanupPending,
    /// Close a never-launched attempt and return the task to Ready.
    CloseNeverLaunchedThenRetry,
    /// Close a never-launched attempt and fail at the budget limit.
    CloseNeverLaunchedThenFail,
    /// Obtain cleanup, release, and return the task to Ready.
    CleanupThenRetry,
    /// Obtain cleanup, release, and enter a known terminal state.
    CleanupThenFail,
    /// Reconcile a pre-v15 open attempt without resuming it.
    RecoverPreV15Open,
    /// Finish sprint Unknown after all domains reach terminal evidence shapes.
    TerminalizeSprintUnknown,
    /// Terminalize this task/attempt as Unknown.
    TerminalizeUnknown,
    /// Exact disposition is already durable.
    AlreadyDisposed,
}

/// Exact ledger-observed authority facts used for one recovery projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptRecoveryFacts {
    /// Disposition or legacy classification already determines recovery.
    DurableHistoryOnly,
    /// Current launch authority is exact and may continue without replay.
    CurrentAuthority {
        /// Exact admitted launch identity.
        launch_id: String,
        /// Exact initialized session, absent only before initialization.
        session_id: Option<String>,
    },
    /// No launch, session, effect, preparation, or native authority exists.
    NeverLaunched,
    /// Known launched authority must be cleaned before disposition.
    KnownCleanupRequired {
        /// Exact admitted launch identity.
        launch_id: String,
        /// Exact initialized session, absent only when initialization failed.
        session_id: Option<String>,
        /// Exact known outcome authority to persist after cleanup.
        outcome: TaskAttemptKnownCleanupOutcome,
    },
    /// Effect, process-survival, or cleanup authority remains uncertain.
    UncertainAuthority {
        /// Exact retained reconciliation evidence identity.
        evidence_id: String,
    },
    /// Ledger proved every sprint domain has a cleaned or quarantined unknown shape.
    AllDomainsUnknownTerminalReady {
        /// Exact pending marker being closed.
        marker_id: String,
        /// Exact ledger-wide terminal-shape evidence identity.
        evidence_id: String,
    },
}

/// Closed known outcome authority available after zero-survivor cleanup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum TaskAttemptKnownCleanupOutcome {
    /// One retry-eligible cause; budget selects retry versus exhaustion.
    Retryable(TaskAttemptRetryableCause),
    /// Proven non-retryable failure.
    PermanentFailure(TaskAttemptPermanentFailureCause),
    /// Progress requires external authority.
    Blocked(TaskAttemptBlockedCause),
    /// Exact operator cancellation.
    Canceled(TaskAttemptCanceledCause),
}

impl TaskAttemptKnownCleanupOutcome {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Retryable(cause) => {
                cause.validate()?;
                if matches!(cause, TaskAttemptRetryableCause::NeverLaunched { .. }) {
                    return Err(ContractError::new(
                        "task_attempt_recovery_facts.outcome",
                        "NeverLaunched must use the separate no-launch recovery path",
                    ));
                }
            }
            Self::PermanentFailure(cause) => cause.validate()?,
            Self::Blocked(cause) => cause.validate()?,
            Self::Canceled(cause) => cause.validate()?,
        }
        Ok(())
    }

    const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }

    fn validate_context(
        &self,
        launch_id: &str,
        session_id: Option<&str>,
    ) -> Result<(), ContractError> {
        if let Self::Retryable(cause) = self {
            match cause {
                TaskAttemptRetryableCause::LaunchRefusedBeforeNativeEffect {
                    launch_id: cause_launch_id,
                    ..
                } if cause_launch_id != launch_id => {
                    return Err(ContractError::new(
                        "task_attempt_recovery_facts.outcome",
                        "launch-refusal cause must match the exact cleanup launch",
                    ));
                }
                TaskAttemptRetryableCause::KnownWorkerExit {
                    launch_id: cause_launch_id,
                    session_id: cause_session_id,
                    ..
                } if cause_launch_id != launch_id
                    || session_id != Some(cause_session_id.as_str()) =>
                {
                    return Err(ContractError::new(
                        "task_attempt_recovery_facts.outcome",
                        "worker-exit cause must match the exact cleanup launch and session",
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl TaskAttemptRecoveryFacts {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::CurrentAuthority {
                launch_id,
                session_id,
            }
            | Self::KnownCleanupRequired {
                launch_id,
                session_id,
                ..
            } => {
                require_task_attempt_identity("task_attempt_recovery_facts.launch_id", launch_id)?;
                if let Some(session_id) = session_id {
                    require_task_attempt_identity(
                        "task_attempt_recovery_facts.session_id",
                        session_id,
                    )?;
                }
            }
            Self::UncertainAuthority { evidence_id } => {
                require_task_attempt_identity(
                    "task_attempt_recovery_facts.evidence_id",
                    evidence_id,
                )?;
            }
            Self::AllDomainsUnknownTerminalReady {
                marker_id,
                evidence_id,
            } => {
                require_task_attempt_identity("task_attempt_recovery_facts.marker_id", marker_id)?;
                require_task_attempt_identity(
                    "task_attempt_recovery_facts.evidence_id",
                    evidence_id,
                )?;
            }
            Self::DurableHistoryOnly | Self::NeverLaunched => {}
        }
        if let Self::KnownCleanupRequired {
            launch_id,
            session_id,
            outcome,
        } = self
        {
            outcome.validate()?;
            outcome.validate_context(launch_id, session_id.as_deref())?;
        }
        Ok(())
    }
}

impl TaskAttemptHistory {
    /// Computes the sole closed recovery action for one exact attempt.
    ///
    /// This is a pure projection. The ledger must derive `facts` from exact
    /// launch/session/effect/native-journal readback; callers cannot use the
    /// projection itself as execution authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid history, unknown attempt,
    /// crossed fact shape, or a recovery action incompatible with durable
    /// disposition, legacy, active-release, budget, or unknown-marker state.
    #[allow(clippy::too_many_lines)]
    pub fn project_recovery_decision(
        &self,
        sprint: &SprintSpec,
        task: &TaskSpec,
        attempt_id: &str,
        facts: &TaskAttemptRecoveryFacts,
    ) -> Result<TaskAttemptRecoveryDecision, ContractError> {
        self.validate_for_task(sprint, task)?;
        require_task_attempt_identity("task_attempt_recovery.attempt_id", attempt_id)?;
        facts.validate()?;
        let entry = self
            .attempts
            .iter()
            .find(|entry| entry.attempt.attempt_id == attempt_id)
            .ok_or_else(|| {
                ContractError::new(
                    "task_attempt_recovery.attempt_id",
                    "must resolve exactly one attempt in the typed history",
                )
            })?;
        if let Some(classification) = entry.legacy_classification {
            if let TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { marker_id, .. } =
                facts
                && classification == LegacyTaskAttemptClassification::LegacyUnknownQuarantine
            {
                require_exact_pending_marker(self, marker_id)?;
                return Ok(TaskAttemptRecoveryDecision::TerminalizeSprintUnknown);
            }
            require_history_only_recovery_facts(facts)?;
            return Ok(match classification {
                LegacyTaskAttemptClassification::LegacyOpen => {
                    TaskAttemptRecoveryDecision::RecoverPreV15Open
                }
                LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending => {
                    TaskAttemptRecoveryDecision::IntegratedCleanupPending
                }
                LegacyTaskAttemptClassification::LegacyReleased
                | LegacyTaskAttemptClassification::LegacyIntegratedReleased
                | LegacyTaskAttemptClassification::LegacyReleasedActiveState
                | LegacyTaskAttemptClassification::LegacyUnknownQuarantine => {
                    TaskAttemptRecoveryDecision::AlreadyDisposed
                }
            });
        }
        if let Some(disposition) = &entry.disposition {
            if let TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { marker_id, .. } =
                facts
                && matches!(
                    disposition,
                    TaskAttemptDisposition::UnknownCleaned(_)
                        | TaskAttemptDisposition::UnknownQuarantined(_)
                )
            {
                require_exact_pending_marker(self, marker_id)?;
                return Ok(TaskAttemptRecoveryDecision::TerminalizeSprintUnknown);
            }
            require_history_only_recovery_facts(facts)?;
            return Ok(match disposition {
                TaskAttemptDisposition::Integrated(_) if entry.lease_state.is_active() => {
                    TaskAttemptRecoveryDecision::IntegratedCleanupPending
                }
                _ => TaskAttemptRecoveryDecision::AlreadyDisposed,
            });
        }
        if !entry.lease_state.is_active() {
            return Err(ContractError::new(
                "task_attempt_recovery.lease_state",
                "undisposed current attempt must retain exact active authority",
            ));
        }
        validate_recovery_facts_against_running_boundary(entry, facts)?;
        let another_attempt_remains =
            entry.attempt.attempt_ordinal < u32::from(sprint.budget.max_attempts_per_task);
        match facts {
            TaskAttemptRecoveryFacts::CurrentAuthority { .. }
                if self.unknown_terminalization_pending.is_none() =>
            {
                Ok(TaskAttemptRecoveryDecision::ContinueActive)
            }
            TaskAttemptRecoveryFacts::CurrentAuthority { .. } => Err(ContractError::new(
                "task_attempt_recovery.facts",
                "pending unknown terminalization requires known cleanup or actual uncertainty",
            )),
            TaskAttemptRecoveryFacts::NeverLaunched if another_attempt_remains => {
                Ok(TaskAttemptRecoveryDecision::CloseNeverLaunchedThenRetry)
            }
            TaskAttemptRecoveryFacts::NeverLaunched => {
                Ok(TaskAttemptRecoveryDecision::CloseNeverLaunchedThenFail)
            }
            TaskAttemptRecoveryFacts::KnownCleanupRequired { outcome, .. }
                if outcome.is_retryable() && another_attempt_remains =>
            {
                Ok(TaskAttemptRecoveryDecision::CleanupThenRetry)
            }
            TaskAttemptRecoveryFacts::KnownCleanupRequired { .. } => {
                Ok(TaskAttemptRecoveryDecision::CleanupThenFail)
            }
            TaskAttemptRecoveryFacts::UncertainAuthority { .. } => {
                Ok(TaskAttemptRecoveryDecision::TerminalizeUnknown)
            }
            TaskAttemptRecoveryFacts::AllDomainsUnknownTerminalReady { .. } => {
                Err(ContractError::new(
                    "task_attempt_recovery.facts",
                    "ledger-wide terminal readiness requires an exact unknown disposition",
                ))
            }
            TaskAttemptRecoveryFacts::DurableHistoryOnly => Err(ContractError::new(
                "task_attempt_recovery.facts",
                "open current attempt requires exact live recovery facts",
            )),
        }
    }
}

pub(super) fn validate_recovery_facts_against_running_boundary(
    entry: &TaskAttemptHistoryEntry,
    facts: &TaskAttemptRecoveryFacts,
) -> Result<(), ContractError> {
    let Some(boundary) = &entry.running_boundary else {
        return Ok(());
    };
    match facts {
        TaskAttemptRecoveryFacts::CurrentAuthority {
            launch_id,
            session_id,
        }
        | TaskAttemptRecoveryFacts::KnownCleanupRequired {
            launch_id,
            session_id,
            ..
        } if launch_id != &boundary.runner_launch_id
            || session_id.as_deref() != Some(boundary.runner_session_id.as_str()) =>
        {
            Err(ContractError::new(
                "task_attempt_recovery.facts",
                "live recovery facts must match the exact Running-boundary launch and session",
            ))
        }
        TaskAttemptRecoveryFacts::NeverLaunched => Err(ContractError::new(
            "task_attempt_recovery.facts",
            "NeverLaunched contradicts the durable Running boundary",
        )),
        _ => Ok(()),
    }
}

pub(super) fn require_exact_pending_marker(
    history: &TaskAttemptHistory,
    marker_id: &str,
) -> Result<(), ContractError> {
    if history
        .unknown_terminalization_pending
        .as_ref()
        .is_none_or(|marker| marker.marker_id != marker_id)
    {
        return Err(ContractError::new(
            "task_attempt_recovery.facts",
            "all-domains-ready fact must name the exact pending marker",
        ));
    }
    Ok(())
}

pub(super) fn require_history_only_recovery_facts(
    facts: &TaskAttemptRecoveryFacts,
) -> Result<(), ContractError> {
    if !matches!(facts, TaskAttemptRecoveryFacts::DurableHistoryOnly) {
        return Err(ContractError::new(
            "task_attempt_recovery.facts",
            "disposed or legacy attempt recovery is determined only by durable history",
        ));
    }
    Ok(())
}

pub(super) fn validate_history_phase_shape(
    history: &TaskAttemptHistory,
    sprint: &SprintSpec,
    task: &TaskSpec,
) -> Result<(), ContractError> {
    let active_entries = history
        .attempts
        .iter()
        .filter(|entry| entry.lease_state.is_active())
        .collect::<Vec<_>>();
    if active_entries.len() > 1 {
        return Err(ContractError::new(
            "task_attempt_history.lease_state",
            "at most one task-local attempt lease may remain active",
        ));
    }
    for entry in history
        .attempts
        .iter()
        .take(history.attempts.len().saturating_sub(1))
    {
        let released_current_retry = matches!(
            entry.disposition,
            Some(TaskAttemptDisposition::Retryable(_))
        ) && !entry.lease_state.is_active();
        let released_legacy_retry_gap = entry.legacy_classification
            == Some(LegacyTaskAttemptClassification::LegacyReleased)
            && !entry.lease_state.is_active();
        if !released_current_retry && !released_legacy_retry_gap {
            return Err(ContractError::new(
                "task_attempt_history.attempts",
                "earlier attempts must be released Retryable or exact LegacyReleased backfills",
            ));
        }
    }
    for entry in &history.attempts {
        validate_formal_check_bijection(entry, sprint, task)?;
        validate_disposed_attempt_phase(entry)?;
    }
    let latest = history.attempts.last();
    if let Some(entry) = latest
        && let Some(classification) = entry.legacy_classification
    {
        return validate_legacy_history_state(history, entry, classification);
    }
    match history.task_state {
        TaskState::Planned => {
            if latest.is_some() {
                return Err(invalid_history_state("Planned tasks cannot have attempts"));
            }
        }
        TaskState::Ready => validate_ready_history(history)?,
        TaskState::Leased | TaskState::Running | TaskState::Verifying | TaskState::Candidate => {
            let Some(entry) = latest else {
                return Err(invalid_history_state("attempted phase requires an attempt"));
            };
            if entry.disposition.is_some()
                || entry.legacy_classification.is_some()
                || !entry.lease_state.is_active()
            {
                return Err(invalid_history_state(
                    "attempted phase requires one active undisposed current attempt",
                ));
            }
            validate_open_attempt_phase(entry, history.task_state)?;
        }
        TaskState::Integrated => validate_integrated_history(latest)?,
        TaskState::Blocked | TaskState::Failed | TaskState::Canceled | TaskState::Unknown => {
            validate_terminal_history(history, latest)?;
        }
    }
    Ok(())
}

pub(super) fn validate_ready_history(history: &TaskAttemptHistory) -> Result<(), ContractError> {
    if history
        .attempts
        .iter()
        .any(|entry| entry.lease_state.is_active())
    {
        return Err(invalid_history_state("Ready cannot retain an active lease"));
    }
    if let Some(latest) = history.attempts.last()
        && !matches!(
            latest.disposition,
            Some(TaskAttemptDisposition::Retryable(_))
        )
    {
        return Err(invalid_history_state(
            "Ready after an attempt requires an exact Retryable disposition",
        ));
    }
    Ok(())
}

pub(super) fn validate_open_attempt_phase(
    entry: &TaskAttemptHistoryEntry,
    task_state: TaskState,
) -> Result<(), ContractError> {
    match task_state {
        TaskState::Leased => {
            if entry.running_boundary.is_some()
                || entry.verification_boundary.is_some()
                || !entry.formal_checks.is_empty()
                || entry.candidate_boundary.is_some()
            {
                return Err(invalid_history_state(
                    "Leased attempts cannot carry Running or later phase boundaries",
                ));
            }
        }
        TaskState::Running => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_some()
                || !entry.formal_checks.is_empty()
                || entry.candidate_boundary.is_some()
            {
                return Err(invalid_history_state(
                    "Running requires its exact boundary and no later phase boundaries",
                ));
            }
        }
        TaskState::Verifying => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_none()
                || entry.candidate_boundary.is_some()
            {
                return Err(invalid_history_state(
                    "Verifying requires exact Running and verification boundaries and no candidate boundary",
                ));
            }
        }
        TaskState::Candidate => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_none()
                || entry.candidate_boundary.is_none()
            {
                return Err(invalid_history_state(
                    "Candidate requires exact Running, verification, and candidate boundaries",
                ));
            }
            if entry
                .formal_checks
                .iter()
                .any(|check| !check.verification_receipt.passed())
            {
                return Err(invalid_history_state(
                    "Candidate requires every automated formal check to pass",
                ));
            }
        }
        _ => unreachable!("caller limits open-attempt states"),
    }
    Ok(())
}

pub(super) fn validate_integrated_history(
    latest: Option<&TaskAttemptHistoryEntry>,
) -> Result<(), ContractError> {
    let Some(entry) = latest else {
        return Err(invalid_history_state(
            "Integrated requires an exact integrated disposition",
        ));
    };
    let current_integrated = matches!(
        entry.disposition,
        Some(TaskAttemptDisposition::Integrated(_))
    );
    let legacy_integrated = matches!(
        entry.legacy_classification,
        Some(
            LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending
                | LegacyTaskAttemptClassification::LegacyIntegratedReleased
        )
    );
    if !current_integrated && !legacy_integrated {
        return Err(invalid_history_state(
            "Integrated requires current or accepted legacy integration evidence",
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_history(
    history: &TaskAttemptHistory,
    latest: Option<&TaskAttemptHistoryEntry>,
) -> Result<(), ContractError> {
    let Some(entry) = latest else {
        return Ok(());
    };
    let disposition_matches = entry
        .disposition
        .as_ref()
        .is_some_and(|disposition| disposition.resulting_task_state() == history.task_state);
    let legacy_unknown = history.task_state == TaskState::Unknown
        && entry.legacy_classification
            == Some(LegacyTaskAttemptClassification::LegacyUnknownQuarantine)
        && entry.lease_state.is_active();
    if !disposition_matches && !legacy_unknown {
        return Err(invalid_history_state(
            "terminal task state requires its exact typed disposition",
        ));
    }
    if entry.lease_state.is_active()
        && !matches!(
            entry.disposition,
            Some(TaskAttemptDisposition::UnknownQuarantined(_))
        )
        && !legacy_unknown
    {
        return Err(invalid_history_state(
            "known terminal and UnknownCleaned attempts cannot retain active leases",
        ));
    }
    if matches!(
        entry.disposition,
        Some(
            TaskAttemptDisposition::UnknownCleaned(_)
                | TaskAttemptDisposition::UnknownQuarantined(_)
        )
    ) && history.unknown_terminalization_pending.is_none()
        && history.sprint_state != SprintState::Unknown
    {
        return Err(invalid_history_state(
            "every unknown disposition requires pending or completed sprint Unknown terminalization",
        ));
    }
    Ok(())
}

pub(super) fn validate_legacy_history_state(
    history: &TaskAttemptHistory,
    entry: &TaskAttemptHistoryEntry,
    classification: LegacyTaskAttemptClassification,
) -> Result<(), ContractError> {
    let allowed = match classification {
        LegacyTaskAttemptClassification::LegacyReleased => matches!(
            history.task_state,
            TaskState::Ready
                | TaskState::Blocked
                | TaskState::Failed
                | TaskState::Canceled
                | TaskState::Unknown
        ),
        LegacyTaskAttemptClassification::LegacyOpen => {
            is_attempted_task_phase(history.task_state) && entry.lease_state.is_active()
        }
        LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending => {
            history.task_state == TaskState::Integrated && entry.lease_state.is_active()
        }
        LegacyTaskAttemptClassification::LegacyIntegratedReleased => {
            history.task_state == TaskState::Integrated && !entry.lease_state.is_active()
        }
        LegacyTaskAttemptClassification::LegacyReleasedActiveState => {
            is_attempted_task_phase(history.task_state) && !entry.lease_state.is_active()
        }
        LegacyTaskAttemptClassification::LegacyUnknownQuarantine => {
            history.task_state == TaskState::Unknown && entry.lease_state.is_active()
        }
    };
    if !allowed {
        return Err(invalid_history_state(
            "legacy classification does not match its exact diagnostic state/release matrix",
        ));
    }
    // Schema-v14 did not persist v15 phase-boundary rows. Legacy attempted
    // states remain diagnostic/recovery-readable without fabricating them.
    if classification == LegacyTaskAttemptClassification::LegacyUnknownQuarantine
        && history.unknown_terminalization_pending.is_none()
        && history.sprint_state != SprintState::Unknown
    {
        return Err(invalid_history_state(
            "legacy unknown quarantine requires pending or completed sprint Unknown terminalization",
        ));
    }
    Ok(())
}

pub(super) fn validate_formal_check_bijection(
    entry: &TaskAttemptHistoryEntry,
    sprint: &SprintSpec,
    task: &TaskSpec,
) -> Result<(), ContractError> {
    let referenced = task
        .acceptance_checks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let canonical_automated = sprint
        .acceptance_criteria
        .iter()
        .filter(|criterion| referenced.contains(criterion.criterion_id.as_str()))
        .filter_map(|criterion| match &criterion.kind {
            AcceptanceKind::Automated(command) => Some((criterion.criterion_id.as_str(), command)),
            AcceptanceKind::HumanJudgment => None,
        })
        .collect::<Vec<_>>();
    // Histories committed before schema v21 used TaskSpec reference order.
    // Readers accept one complete prefix of either historical ordering, but a
    // mixed sequence matches neither. New admissions are fenced separately by
    // the v21 SQL trigger to SprintSpec declaration order only.
    let legacy_automated = task
        .acceptance_checks
        .iter()
        .filter_map(|criterion_id| {
            sprint
                .acceptance_criteria
                .iter()
                .find(|criterion| criterion.criterion_id == *criterion_id)
                .and_then(|criterion| match &criterion.kind {
                    AcceptanceKind::Automated(command) => Some((criterion_id.as_str(), command)),
                    AcceptanceKind::HumanJudgment => None,
                })
        })
        .collect::<Vec<_>>();
    if entry.formal_checks.len() > canonical_automated.len() {
        return Err(ContractError::new(
            "task_attempt_history.formal_checks",
            "formal-check count exceeds the declared automated criterion set",
        ));
    }
    let Some(verification_boundary) = &entry.verification_boundary else {
        if entry.formal_checks.is_empty() && entry.candidate_boundary.is_none() {
            return Ok(());
        }
        return Err(ContractError::new(
            "task_attempt_history.formal_checks",
            "formal checks and candidate boundary require a verification boundary",
        ));
    };
    let sequence_matches = |order: &[(&str, &CommandSpec)]| {
        entry.formal_checks.iter().zip(order).enumerate().all(
            |(index, (check, (criterion_id, command)))| {
                check.criterion_ordinal == u32::try_from(index).unwrap_or(u32::MAX)
                    && check.criterion_id == *criterion_id
                    && &check.verification_receipt.command == *command
                    && check.sealed_snapshot == verification_boundary.sealed_snapshot
                    && check.runner_session_id == verification_boundary.runner_session_id
            },
        )
    };
    if !sequence_matches(&canonical_automated) && !sequence_matches(&legacy_automated) {
        return Err(ContractError::new(
            "task_attempt_history.formal_checks",
            "must follow one unmixed SprintSpec-canonical or pre-v21 legacy automated-criterion order",
        ));
    }
    let mut previous_finished_at = verification_boundary.sealed_at_unix_ms;
    for check in &entry.formal_checks {
        if check.verification_receipt.finished_at_unix_ms < previous_finished_at {
            return Err(ContractError::new(
                "task_attempt_history.formal_checks",
                "serialized formal-check completion times must not move backward",
            ));
        }
        previous_finished_at = check.verification_receipt.finished_at_unix_ms;
    }
    if let Some(candidate) = &entry.candidate_boundary {
        let expected_ids = entry
            .formal_checks
            .iter()
            .map(|check| check.formal_check_id.clone())
            .collect::<Vec<_>>();
        let expected_receipt_ids = entry
            .formal_checks
            .iter()
            .map(|check| check.verification_receipt.receipt_id.clone())
            .collect::<Vec<_>>();
        if entry.formal_checks.len() != canonical_automated.len()
            || candidate.formal_check_ids != expected_ids
            || candidate.verification_receipt_ids != expected_receipt_ids
            || candidate.verification_boundary_id != verification_boundary.boundary_id
            || candidate.change_set_id != verification_boundary.change_set_id
            || candidate.sealed_snapshot != verification_boundary.sealed_snapshot
            || candidate.admitted_at_unix_ms < previous_finished_at
        {
            return Err(ContractError::new(
                "task_attempt_history.candidate_boundary",
                "must be an exact bijection over the declared automated formal-check set",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn validate_disposed_attempt_phase(
    entry: &TaskAttemptHistoryEntry,
) -> Result<(), ContractError> {
    let Some(disposition) = &entry.disposition else {
        return Ok(());
    };
    if entry.running_boundary.as_ref().is_some_and(|boundary| {
        disposition.metadata().disposed_at_unix_ms < boundary.started_at_unix_ms
    }) {
        return Err(ContractError::new(
            "task_attempt_history.disposition_phase",
            "disposition must not precede the Running boundary",
        ));
    }
    match disposition.metadata().from_state {
        TaskState::Leased => {
            if entry.running_boundary.is_some()
                || entry.verification_boundary.is_some()
                || !entry.formal_checks.is_empty()
                || entry.candidate_boundary.is_some()
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_phase",
                    "Leased disposition cannot carry Running or later phase boundaries",
                ));
            }
        }
        TaskState::Running => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_some()
                || !entry.formal_checks.is_empty()
                || entry.candidate_boundary.is_some()
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_phase",
                    "Running disposition requires its exact boundary and no later phase boundaries",
                ));
            }
        }
        TaskState::Verifying => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_none()
                || entry.candidate_boundary.is_some()
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_phase",
                    "Verifying disposition requires Running and verification boundaries and no candidate boundary",
                ));
            }
        }
        TaskState::Candidate => {
            if entry.running_boundary.is_none()
                || entry.verification_boundary.is_none()
                || entry.candidate_boundary.is_none()
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_phase",
                    "Candidate disposition requires exact Running, verification, and candidate boundaries",
                ));
            }
            if entry
                .formal_checks
                .iter()
                .any(|check| !check.verification_receipt.passed())
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_phase",
                    "Candidate disposition requires every automated formal check to pass",
                ));
            }
        }
        _ => unreachable!("disposition metadata validates attempted source phases"),
    }
    if let TaskAttemptDisposition::Integrated(integrated) = disposition {
        let verification = entry
            .verification_boundary
            .as_ref()
            .expect("Candidate phase requires verification boundary");
        if entry.candidate_boundary.as_ref() != Some(&integrated.candidate_boundary)
            || integrated.integration_receipt.worker_launch_id != verification.runner_launch_id
            || integrated.integration_receipt.worker_session_id != verification.runner_session_id
        {
            return Err(ContractError::new(
                "task_attempt_history.candidate_boundary",
                "Integrated disposition must match the exact history candidate, launch, and session",
            ));
        }
    }
    let retryable_cause = match disposition {
        TaskAttemptDisposition::Retryable(value) => Some(&value.cause),
        TaskAttemptDisposition::AttemptsExhausted(value) => Some(&value.cause),
        _ => None,
    };
    let failed_check_ids = entry
        .formal_checks
        .iter()
        .filter(|check| !check.verification_receipt.passed())
        .map(|check| check.formal_check_id.as_str())
        .collect::<Vec<_>>();
    if failed_check_ids.len() > 1 {
        return Err(ContractError::new(
            "task_attempt_history.formal_checks",
            "serialized failed-check fencing permits at most one failed formal check",
        ));
    }
    if let Some(failed_check_id) = failed_check_ids.first()
        && !matches!(
            retryable_cause,
            Some(TaskAttemptRetryableCause::FormalVerificationFailed {
                formal_check_id,
                ..
            }) if formal_check_id == failed_check_id
        )
    {
        return Err(ContractError::new(
            "task_attempt_history.disposition_cause",
            "a failed formal receipt requires its exact FormalVerificationFailed cause",
        ));
    }
    match retryable_cause {
        Some(TaskAttemptRetryableCause::FormalVerificationFailed {
            formal_check_id, ..
        }) => {
            if disposition.metadata().from_state != TaskState::Verifying
                || !entry.formal_checks.iter().any(|check| {
                    check.formal_check_id == *formal_check_id
                        && !check.verification_receipt.passed()
                })
            {
                return Err(ContractError::new(
                    "task_attempt_history.disposition_cause",
                    "FormalVerificationFailed must resolve one exact failed Verifying check",
                ));
            }
        }
        Some(TaskAttemptRetryableCause::CandidateRejectedKnown {
            candidate_boundary_id,
            ..
        }) if disposition.metadata().from_state != TaskState::Candidate
            || entry
                .candidate_boundary
                .as_ref()
                .is_none_or(|boundary| boundary.boundary_id != *candidate_boundary_id) =>
        {
            return Err(ContractError::new(
                "task_attempt_history.disposition_cause",
                "CandidateRejectedKnown must resolve the exact Candidate boundary",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn validate_legacy_lease_shape(
    entry: &TaskAttemptHistoryEntry,
) -> Result<(), ContractError> {
    let Some(classification) = entry.legacy_classification else {
        return Ok(());
    };
    let expects_active = matches!(
        classification,
        LegacyTaskAttemptClassification::LegacyOpen
            | LegacyTaskAttemptClassification::LegacyIntegratedCleanupPending
            | LegacyTaskAttemptClassification::LegacyUnknownQuarantine
    );
    if entry.lease_state.is_active() != expects_active {
        return Err(ContractError::new(
            "task_attempt_history.legacy_classification",
            "legacy classification and active-release state disagree",
        ));
    }
    Ok(())
}

pub(super) fn validate_disposition_lease_shape(
    entry: &TaskAttemptHistoryEntry,
) -> Result<(), ContractError> {
    let Some(disposition) = &entry.disposition else {
        return Ok(());
    };
    match disposition {
        TaskAttemptDisposition::Integrated(_) => {}
        TaskAttemptDisposition::UnknownQuarantined(_) => {
            if !entry.lease_state.is_active() {
                return Err(ContractError::new(
                    "task_attempt_history.lease_state",
                    "UnknownQuarantined must retain its active lease",
                ));
            }
        }
        TaskAttemptDisposition::UnknownCleaned(disposition) => {
            validate_history_release(
                &entry.lease_state,
                &disposition.cleanup_release.release_id,
                disposition.cleanup_release.released_at_unix_ms,
            )?;
        }
        _ => {
            let release = disposition.release_proof().ok_or_else(|| {
                ContractError::new(
                    "task_attempt_history.lease_state",
                    "released disposition lacks its exact release proof",
                )
            })?;
            validate_history_release(
                &entry.lease_state,
                release.release_id(),
                release.released_at_unix_ms(),
            )?;
        }
    }
    Ok(())
}

pub(super) fn validate_history_release(
    lease_state: &TaskAttemptLeaseState,
    expected_release_id: &str,
    expected_released_at_unix_ms: u64,
) -> Result<(), ContractError> {
    if !matches!(
        lease_state,
        TaskAttemptLeaseState::Released {
            release_id,
            released_at_unix_ms,
        } if release_id == expected_release_id
            && *released_at_unix_ms == expected_released_at_unix_ms
    ) {
        return Err(ContractError::new(
            "task_attempt_history.lease_state",
            "must exactly match the disposition release proof",
        ));
    }
    Ok(())
}

pub(super) fn invalid_history_state(message: &'static str) -> ContractError {
    ContractError::new("task_attempt_history.task_state", message)
}

pub(super) fn require_contract_version(
    field: &'static str,
    version: u32,
) -> Result<(), ContractError> {
    if version != CONTRACT_VERSION {
        return Err(ContractError::new(
            field,
            format!("expected version {CONTRACT_VERSION}, got {version}"),
        ));
    }
    Ok(())
}

pub(super) fn require_task_attempt_identity(
    field: &'static str,
    value: &str,
) -> Result<(), ContractError> {
    require_nonblank(field, value)?;
    if value.len() > MAX_TASK_ATTEMPT_ID_BYTES {
        return Err(ContractError::new(
            field,
            format!("must not exceed {MAX_TASK_ATTEMPT_ID_BYTES} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub(super) fn require_task_attempt_identity_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ContractError> {
    for value in values {
        require_task_attempt_identity(field, value)?;
    }
    Ok(())
}
