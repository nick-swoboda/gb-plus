//! Application, rollback, completion, effect, and event contracts.

use super::{
    BTreeSet, CONTRACT_VERSION, ChangeSet, Component, ContractError, Deserialize, Digest,
    MAX_APPLICATION_REQUEST_BYTES, MAX_TASK_INTEGRATION_REQUEST_BYTES, NonSuccessTerminalState,
    Path, PathBuf, Serialize, TaskIntegrationArtifactReference, TaskIntegrationReceipt,
    WorkerLease, digest_canonical_contract,
};

/// Exact request committed before an immutable aggregate artifact may be
/// applied to the trusted workspace.
///
/// The artifact is path-free runner authority. Binding it into the request
/// digest prevents a coordinator restart from substituting a different bundle
/// that happens to describe the same logical [`ChangeSet`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationRequest {
    /// Wire-contract version used to encode the request.
    pub contract_version: u32,
    /// Exact durable aggregate change set authorized for application.
    pub change_set: ChangeSet,
    /// Exact immutable artifact that carries `change_set`.
    pub artifact: TaskIntegrationArtifactReference,
}

impl ApplicationRequest {
    /// Validates the request and its exact change-set/artifact relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid child,
    /// relationship substitution, or an oversized canonical request.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "application_request.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.change_set.validate()?;
        if self.change_set.operations.is_empty() {
            return Err(ContractError::new(
                "application_request.change_set",
                "live application requires a nonempty change set; use VerifiedNoOp completion",
            ));
        }
        self.artifact.validate()?;
        if self.change_set.change_set_id != self.artifact.change_set_id
            || self.change_set.base_snapshot != self.artifact.base_snapshot
            || self.change_set.result_snapshot != self.artifact.result_snapshot
        {
            return Err(ContractError::new(
                "application_request.artifact",
                "must identify the exact requested change set and snapshot transition",
            ));
        }
        let canonical = serde_json::to_vec(self).map_err(|error| {
            ContractError::new(
                "application_request",
                format!("cannot encode canonically: {error}"),
            )
        })?;
        if canonical.len() > MAX_APPLICATION_REQUEST_BYTES {
            return Err(ContractError::new(
                "application_request",
                format!("canonical request exceeds {MAX_APPLICATION_REQUEST_BYTES} bytes"),
            ));
        }
        Ok(())
    }
}

/// Closed way in which a runner validated an immutable task-integration
/// artifact before its successful observation was committed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TaskIntegrationValidationMode {
    /// The original task-worker session validated the artifact while
    /// publishing it.
    WorkerPublication,
    /// A distinct trusted applier session reopened and validated the expected
    /// artifact after the worker or coordinator lost the publication result.
    RecoveryApplierReconciliation,
}

/// Exact registered runner authority that validated one immutable
/// task-integration artifact.
///
/// These claims are retained inside the successful effect's canonical
/// evidence preimage. Core persistence resolves the session and launch from
/// the ledger, authenticates the claimed role-specific policy, and requires
/// the original grant and private-state authority before accepting it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrationValidationEvidence {
    /// Whether validation happened during worker publication or by recovery
    /// reconciliation in a distinct applier session.
    pub mode: TaskIntegrationValidationMode,
    /// Exact durable pre-spawn launch behind the validating session.
    pub runner_launch_id: String,
    /// Exact initialized runner session that validated the artifact.
    pub runner_session_id: String,
    /// Exact compiler-produced policy used by the validating session.
    pub policy_hash: Digest,
    /// Exact authenticated workspace grant used by the validating session.
    pub grant_hash: Digest,
    /// Exact private runner-state identity in which the artifact was
    /// published and reopened.
    pub private_state_digest: Digest,
}

impl TaskIntegrationValidationEvidence {
    /// Validates the path-free validation authority claims.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a launch or session identity is blank.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank(
            "task_integration_validation_evidence.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_nonblank(
            "task_integration_validation_evidence.runner_session_id",
            &self.runner_session_id,
        )
    }
}

/// Exact request committed before an immutable task-integration artifact may
/// be published.
///
/// A read-only runner preparation step computes both children. Persisting this
/// envelope before the publication syscall means a fresh coordinator can
/// reconstruct the one admissible artifact reference even when the original
/// runner dies before returning a response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrationRequest {
    /// Wire-contract version used to encode the request.
    pub contract_version: u32,
    /// Exact canonical task change set authorized for integration.
    pub change_set: ChangeSet,
    /// Deterministic immutable artifact expected from publication.
    pub artifact: TaskIntegrationArtifactReference,
}

impl TaskIntegrationRequest {
    /// Validates the request and its exact change-set/artifact relationship.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported contract version, invalid
    /// child contract, or disagreement between the change set and artifact.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "task_integration_request.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.change_set.validate()?;
        self.artifact.validate()?;
        if self.change_set.change_set_id != self.artifact.change_set_id
            || self.change_set.base_snapshot != self.artifact.base_snapshot
            || self.change_set.result_snapshot != self.artifact.result_snapshot
        {
            return Err(ContractError::new(
                "task_integration_request.artifact",
                "must identify the exact requested change set and snapshot transition",
            ));
        }
        let canonical = serde_json::to_vec(self).map_err(|error| {
            ContractError::new(
                "task_integration_request",
                format!("cannot encode canonically: {error}"),
            )
        })?;
        if canonical.len() > MAX_TASK_INTEGRATION_REQUEST_BYTES {
            return Err(ContractError::new(
                "task_integration_request",
                format!("canonical request exceeds {MAX_TASK_INTEGRATION_REQUEST_BYTES} bytes"),
            ));
        }
        Ok(())
    }
}

/// Exact successful evidence for one task-integration effect.
///
/// The receipt proves task, worker, session, verification, and ordered
/// snapshot identity. `artifact` proves which immutable private bundle can be
/// reopened after a crash to apply or reconcile the exact same change set;
/// `validation` proves the registered worker or recovery-applier authority
/// that checked it. The complete envelope is the effect observation's
/// canonical evidence preimage and is committed atomically with the receipt
/// and observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskIntegrationEvidence {
    /// Wire-contract version used to encode the evidence.
    pub contract_version: u32,
    /// Exact typed task-integration receipt.
    pub receipt: TaskIntegrationReceipt,
    /// Exact immutable runner artifact carrying the receipt's change set.
    pub artifact: TaskIntegrationArtifactReference,
    /// Exact registered runner authority that validated `artifact`.
    pub validation: TaskIntegrationValidationEvidence,
}

impl TaskIntegrationEvidence {
    /// Validates the evidence envelope and its exact cross-reference.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported contract version, an
    /// invalid child contract, or disagreement between the receipt and the
    /// immutable artifact identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "task_integration_evidence.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.receipt.validate()?;
        self.artifact.validate()?;
        self.validation.validate()?;
        if self.receipt.change_set_id != self.artifact.change_set_id
            || self.receipt.input_snapshot != self.artifact.base_snapshot
            || self.receipt.result_snapshot != self.artifact.result_snapshot
        {
            return Err(ContractError::new(
                "task_integration_evidence.artifact",
                "must carry the receipt's exact change set and snapshot transition",
            ));
        }
        match self.validation.mode {
            TaskIntegrationValidationMode::WorkerPublication => {
                if self.validation.runner_launch_id != self.receipt.worker_launch_id
                    || self.validation.runner_session_id != self.receipt.worker_session_id
                    || self.validation.policy_hash != self.receipt.worker_policy_hash
                {
                    return Err(ContractError::new(
                        "task_integration_evidence.validation",
                        "worker publication must name the receipt's exact worker launch, session, and policy",
                    ));
                }
            }
            TaskIntegrationValidationMode::RecoveryApplierReconciliation => {
                if self.validation.runner_launch_id == self.receipt.worker_launch_id
                    || self.validation.runner_session_id == self.receipt.worker_session_id
                {
                    return Err(ContractError::new(
                        "task_integration_evidence.validation",
                        "recovery reconciliation requires a distinct applier launch and session",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Durable result of the one successful live-workspace application effect.
///
/// Persistence accepts this receipt only as the indexed child of an
/// [`ApplicationEvidence`] envelope committed with the matching successful
/// [`EffectObservation`]. The observation binds the whole envelope's canonical
/// encoding, not this compact receipt alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact successful `ApplyChangeSet` effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Exact trusted applier runner session that executed the transaction.
    pub applier_session_id: String,
    /// Capability-applier journal transaction.
    pub transaction_id: String,
    /// Exact aggregate change set applied to the live workspace.
    pub change_set_id: String,
    /// Exact live workspace state required before application.
    pub base_snapshot: Digest,
    /// Exact live workspace state produced by application.
    pub result_snapshot: Digest,
    /// Immutable runner policy authorizing application.
    pub policy_hash: Digest,
    /// Authenticated workspace grant from which the application policy was
    /// compiled.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version used for compilation.
    pub policy_version: u32,
    /// Canonical digest of all ordered applied operations.
    pub applied_operations_digest: Digest,
    /// Canonical digest of every ordered touched-path endpoint.
    pub touched_path_endpoints_digest: Digest,
    /// Complete descriptor-relative live manifest observed after commit.
    pub live_manifest_digest: Digest,
    /// Successful application observation time.
    pub applied_at_unix_ms: u64,
}

impl ApplicationReceipt {
    /// Validates the receipt envelope independently of ledger relationships.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// a no-op snapshot claim, an invalid policy version, or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "application_receipt.contract_version",
            self.contract_version,
            "application_receipt.receipt_id",
            &self.receipt_id,
            "application_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank("application_receipt.effect_id", &self.effect_id)?;
        require_nonblank("application_receipt.observation_id", &self.observation_id)?;
        require_nonblank(
            "application_receipt.applier_session_id",
            &self.applier_session_id,
        )?;
        require_nonblank("application_receipt.transaction_id", &self.transaction_id)?;
        require_nonblank("application_receipt.change_set_id", &self.change_set_id)?;
        if self.base_snapshot == self.result_snapshot {
            return Err(ContractError::new(
                "application_receipt.result_snapshot",
                "must differ from the base snapshot",
            ));
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "application_receipt.policy_version",
                "must be greater than zero",
            ));
        }
        require_nonzero_timestamp(
            "application_receipt.applied_at_unix_ms",
            self.applied_at_unix_ms,
        )
    }

    /// Computes the canonical journal-binding digest that a reopened rollback
    /// reference must carry.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] only if this fixed UTF-8/digest envelope
    /// cannot be canonically encoded.
    pub fn journal_binding_digest(&self) -> Result<Digest, ContractError> {
        #[derive(Serialize)]
        struct JournalBinding<'a> {
            receipt_id: &'a str,
            sprint_id: &'a str,
            applier_session_id: &'a str,
            transaction_id: &'a str,
            change_set_id: &'a str,
            base_snapshot: &'a Digest,
            result_snapshot: &'a Digest,
            applied_operations_digest: &'a Digest,
            touched_path_endpoints_digest: &'a Digest,
            grant_hash: &'a Digest,
            policy_version: u32,
        }

        digest_canonical_contract(
            b"grok-build.application-journal-binding.v1\0",
            &JournalBinding {
                receipt_id: &self.receipt_id,
                sprint_id: &self.sprint_id,
                applier_session_id: &self.applier_session_id,
                transaction_id: &self.transaction_id,
                change_set_id: &self.change_set_id,
                base_snapshot: &self.base_snapshot,
                result_snapshot: &self.result_snapshot,
                applied_operations_digest: &self.applied_operations_digest,
                touched_path_endpoints_digest: &self.touched_path_endpoints_digest,
                grant_hash: &self.grant_hash,
                policy_version: self.policy_version,
            },
            "application_receipt",
        )
    }
}

/// Closed source of durable validation for one successful live-workspace
/// application.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApplicationValidationMode {
    /// The effect-bound applier returned the successful application evidence
    /// directly.
    DirectEffectResponse,
    /// A distinct applier reopened the journal and reconciled the exact
    /// committed application after the original response was lost.
    RecoveryApplierReconciliation,
}

/// Exact registered applier authority that validated one successful
/// application outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationValidationEvidence {
    /// Direct effect response or distinct recovery reconciliation.
    pub mode: ApplicationValidationMode,
    /// Exact durable launch behind the validating applier session.
    pub runner_launch_id: String,
    /// Exact initialized applier session that validated the journal state.
    pub runner_session_id: String,
    /// Exact compiler-produced applier policy.
    pub policy_hash: Digest,
    /// Exact authenticated workspace grant.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Exact private journal-state identity.
    pub private_state_digest: Digest,
}

impl ApplicationValidationEvidence {
    /// Validates the path-free application-validation authority claims.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for blank lifecycle identities or a zero
    /// policy version.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank(
            "application_validation_evidence.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_nonblank(
            "application_validation_evidence.runner_session_id",
            &self.runner_session_id,
        )?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "application_validation_evidence.policy_version",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Exact successful evidence preimage for one live-workspace application.
///
/// `receipt` permanently names the effect-bound applier that executed the
/// transaction. `validation` names either that exact lifecycle or a distinct
/// applier that only reconciled the committed journal state after a crash.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationEvidence {
    /// Wire-contract version used to encode the evidence.
    pub contract_version: u32,
    /// Exact typed successful application receipt.
    pub receipt: ApplicationReceipt,
    /// Exact registered authority that validated the committed outcome.
    pub validation: ApplicationValidationEvidence,
}

impl ApplicationEvidence {
    /// Validates the application envelope and direct/recovery identity shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, invalid child,
    /// authority disagreement, or a recovery claim that reuses the executor
    /// session.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "application_evidence.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.receipt.validate()?;
        self.validation.validate()?;
        if self.validation.policy_hash != self.receipt.policy_hash
            || self.validation.grant_hash != self.receipt.grant_hash
            || self.validation.policy_version != self.receipt.policy_version
        {
            return Err(ContractError::new(
                "application_evidence.validation",
                "must retain the receipt's exact policy and workspace grant authority",
            ));
        }
        match self.validation.mode {
            ApplicationValidationMode::DirectEffectResponse => {
                if self.validation.runner_session_id != self.receipt.applier_session_id {
                    return Err(ContractError::new(
                        "application_evidence.validation",
                        "direct validation must name the receipt's executing applier session",
                    ));
                }
            }
            ApplicationValidationMode::RecoveryApplierReconciliation => {
                if self.validation.runner_session_id == self.receipt.applier_session_id {
                    return Err(ContractError::new(
                        "application_evidence.validation",
                        "recovery validation requires a distinct applier session",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Closed operating-system accounting backends accepted as zero-descendant
/// authority for v0.1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WorkerCleanupBackend {
    /// macOS runner executed under a dedicated operating-system identity.
    MacOsDedicatedIdentity,
    /// Linux runner executed in a delegated cgroup-v2 accounting domain.
    LinuxCgroupV2,
    /// Trusted applier direct-child wait plus synchronized journal proof.
    TrustedApplierDirectChildWait,
}

/// Closed purpose of one registered runner session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RunnerSessionPurpose {
    /// A task worker that may run commands or mutate only a private shadow.
    TaskWorker,
    /// A dedicated session that performs repository-wide final verification.
    FinalVerifier,
    /// A dedicated read-only session that captures the descriptor-relative
    /// live workspace manifest after prior runner cleanup.
    LiveStateVerifier,
    /// Trusted capability applier with exclusive live-workspace journal
    /// authority.
    Applier,
}

/// Durable pre-spawn runner launch attempt from which cleanup obligations are
/// derived even when initialization never succeeds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerLaunchIntent {
    /// Wire-contract version used to encode the launch intent.
    pub contract_version: u32,
    /// Globally unique launch-attempt identity.
    pub launch_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Expected immutable runner session identity.
    pub session_id: String,
    /// Expected session purpose.
    pub purpose: RunnerSessionPurpose,
    /// Logical worker identity, present exactly for task-worker attempts.
    pub worker_id: Option<String>,
    /// Exact active assignment, present exactly for task-worker attempts.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// Exact compiler-produced execution policy digest.
    pub policy_hash: Digest,
    /// Exact admitted runner binary identity.
    pub runner_binary_digest: Digest,
    /// Exact runner wire-protocol schema identity.
    pub protocol_digest: Digest,
    /// Exact private runner-state identity.
    pub private_state_digest: Digest,
    /// Authenticated workspace grant behind the compiled policy.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Durable time before the operating-system spawn may begin.
    pub created_at_unix_ms: u64,
}

impl RunnerLaunchIntent {
    /// Validates the pre-spawn launch envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// role/worker mismatch, invalid policy version, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        let session = RunnerSessionPolicyRecord {
            contract_version: self.contract_version,
            launch_id: self.launch_id.clone(),
            sprint_id: self.sprint_id.clone(),
            session_id: self.session_id.clone(),
            purpose: self.purpose,
            worker_id: self.worker_id.clone(),
            worker_lease: self.worker_lease.clone(),
            policy_hash: self.policy_hash.clone(),
            session_nonce: self.policy_hash.clone(),
            runner_binary_digest: self.runner_binary_digest.clone(),
            protocol_digest: self.protocol_digest.clone(),
            private_state_digest: self.private_state_digest.clone(),
            grant_hash: self.grant_hash.clone(),
            policy_version: self.policy_version,
            registered_at_unix_ms: self.created_at_unix_ms,
        };
        session.validate()?;
        require_nonblank("runner_launch_intent.launch_id", &self.launch_id)
    }
}

/// Durable session-to-compiled-policy registration used to derive the exact
/// worker cleanup set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerSessionPolicyRecord {
    /// Wire-contract version used to encode the registration.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact durable pre-spawn attempt authenticated by initialization.
    pub launch_id: String,
    /// Immutable runner session identity.
    pub session_id: String,
    /// Session purpose.
    pub purpose: RunnerSessionPurpose,
    /// Logical worker identity, present exactly for task-worker sessions.
    pub worker_id: Option<String>,
    /// Exact active assignment, present exactly for task-worker sessions.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// Exact compiler-produced execution policy digest.
    pub policy_hash: Digest,
    /// Fresh runner-generated nonce that makes this lifecycle unreplayable.
    pub session_nonce: Digest,
    /// Exact admitted runner binary identity.
    pub runner_binary_digest: Digest,
    /// Exact runner wire-protocol schema identity.
    pub protocol_digest: Digest,
    /// Exact private runner-state identity.
    pub private_state_digest: Digest,
    /// Authenticated workspace grant from which the policy was compiled.
    pub grant_hash: Digest,
    /// Exact grant policy version used for compilation.
    pub policy_version: u32,
    /// Registration time, before the session may execute work.
    pub registered_at_unix_ms: u64,
}

impl RunnerSessionPolicyRecord {
    /// Validates the closed session registration envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// role/worker mismatch, invalid policy version, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "runner_session_policy.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("runner_session_policy.sprint_id", &self.sprint_id)?;
        require_nonblank("runner_session_policy.launch_id", &self.launch_id)?;
        require_nonblank("runner_session_policy.session_id", &self.session_id)?;
        match (
            self.purpose,
            self.worker_id.as_deref(),
            self.worker_lease.as_ref(),
        ) {
            (RunnerSessionPurpose::TaskWorker, Some(worker_id), Some(lease)) => {
                lease.validate()?;
                if lease.sprint_id != self.sprint_id || lease.worker_id != worker_id {
                    return Err(ContractError::new(
                        "runner_session_policy.worker_lease",
                        "must exactly match the session sprint and worker",
                    ));
                }
                if self.registered_at_unix_ms < lease.acquired_at_unix_ms {
                    return Err(ContractError::new(
                        "runner_session_policy.registered_at_unix_ms",
                        "must not precede lease acquisition",
                    ));
                }
            }
            (
                RunnerSessionPurpose::FinalVerifier
                | RunnerSessionPurpose::LiveStateVerifier
                | RunnerSessionPurpose::Applier,
                None,
                None,
            ) => {}
            (RunnerSessionPurpose::TaskWorker, _, _) => {
                return Err(ContractError::new(
                    "runner_session_policy.worker_lease",
                    "task-worker sessions require one exact worker and lease identity",
                ));
            }
            (
                RunnerSessionPurpose::FinalVerifier
                | RunnerSessionPurpose::LiveStateVerifier
                | RunnerSessionPurpose::Applier,
                _,
                _,
            ) => {
                return Err(ContractError::new(
                    "runner_session_policy.worker_lease",
                    "verifier and applier sessions must not claim a worker lease",
                ));
            }
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "runner_session_policy.policy_version",
                "must be greater than zero",
            ));
        }
        require_nonzero_timestamp(
            "runner_session_policy.registered_at_unix_ms",
            self.registered_at_unix_ms,
        )
    }
}

/// Exact canonical request preimage for `CleanupWorkerDomain`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCleanupRequest {
    /// Wire-contract version used to encode the request.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn launch attempt being reaped.
    pub launch_id: String,
    /// Immutable runner session whose accounting domain must be inspected.
    pub session_id: String,
    /// Immutable policy used by that runner session.
    pub policy_hash: Digest,
    /// Authenticated workspace grant behind the compiled policy.
    pub grant_hash: Digest,
    /// Exact grant policy version behind the compiled policy.
    pub policy_version: u32,
    /// Required operating-system accounting backend.
    pub platform_backend: WorkerCleanupBackend,
}

impl WorkerCleanupRequest {
    /// Validates the strict cleanup request envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version or blank identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "worker_cleanup_request.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("worker_cleanup_request.sprint_id", &self.sprint_id)?;
        require_nonblank("worker_cleanup_request.launch_id", &self.launch_id)?;
        require_nonblank("worker_cleanup_request.session_id", &self.session_id)?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "worker_cleanup_request.policy_version",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Durable zero-descendant proof bound to one cleanup effect lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCleanupReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn launch attempt whose process domain was reaped.
    pub launch_id: String,
    /// Exact successful `CleanupWorkerDomain` effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Immutable runner session whose accounting domain was inspected.
    pub session_id: String,
    /// Exact task-worker assignment being released, absent for non-worker
    /// runner roles.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// Immutable runner policy used for the worker domain.
    pub policy_hash: Digest,
    /// Authenticated workspace grant behind the compiled policy.
    pub grant_hash: Digest,
    /// Exact grant policy version behind the compiled policy.
    pub policy_version: u32,
    /// Platform accounting backend that produced the evidence.
    pub platform_backend: WorkerCleanupBackend,
    /// SHA-256 of the exact operating-system evidence bytes.
    pub os_evidence_digest: Digest,
    /// Observed surviving worker and descendant process count; always zero for
    /// an authoritative cleanup receipt.
    pub surviving_processes: u64,
    /// Cleanup observation time.
    pub cleaned_at_unix_ms: u64,
}

impl WorkerCleanupReceipt {
    /// Validates the cleanup envelope and zero-survivor invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// a nonzero survivor count, or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "worker_cleanup_receipt.contract_version",
            self.contract_version,
            "worker_cleanup_receipt.receipt_id",
            &self.receipt_id,
            "worker_cleanup_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank("worker_cleanup_receipt.effect_id", &self.effect_id)?;
        require_nonblank("worker_cleanup_receipt.launch_id", &self.launch_id)?;
        require_nonblank(
            "worker_cleanup_receipt.observation_id",
            &self.observation_id,
        )?;
        require_nonblank("worker_cleanup_receipt.session_id", &self.session_id)?;
        if let Some(lease) = &self.worker_lease {
            lease.validate()?;
            if lease.sprint_id != self.sprint_id {
                return Err(ContractError::new(
                    "worker_cleanup_receipt.worker_lease",
                    "must belong to the cleanup sprint",
                ));
            }
            if self.cleaned_at_unix_ms < lease.acquired_at_unix_ms {
                return Err(ContractError::new(
                    "worker_cleanup_receipt.cleaned_at_unix_ms",
                    "must not precede lease acquisition",
                ));
            }
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "worker_cleanup_receipt.policy_version",
                "must be greater than zero",
            ));
        }
        if self.surviving_processes != 0 {
            return Err(ContractError::new(
                "worker_cleanup_receipt.surviving_processes",
                "must be zero",
            ));
        }
        require_nonzero_timestamp(
            "worker_cleanup_receipt.cleaned_at_unix_ms",
            self.cleaned_at_unix_ms,
        )
    }
}

/// Maximum raw operating-system cleanup evidence retained in one atomic
/// effect envelope.
pub const MAX_WORKER_CLEANUP_EVIDENCE_BYTES: usize = 1_048_576;

/// Atomic evidence envelope for one worker-domain cleanup observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCleanupEvidence {
    /// Indexed zero-descendant receipt.
    pub receipt: WorkerCleanupReceipt,
    /// Exact bounded operating-system accounting evidence authenticated by
    /// `receipt.os_evidence_digest`.
    pub os_evidence_bytes: Vec<u8>,
}

impl WorkerCleanupEvidence {
    /// Validates the receipt and its exact retained evidence preimage.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the receipt is invalid, evidence is
    /// empty or oversized, or the digest does not authenticate the bytes.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.receipt.validate()?;
        if self.os_evidence_bytes.is_empty() {
            return Err(ContractError::new(
                "worker_cleanup_evidence.os_evidence_bytes",
                "must retain the authoritative operating-system evidence",
            ));
        }
        if self.os_evidence_bytes.len() > MAX_WORKER_CLEANUP_EVIDENCE_BYTES {
            return Err(ContractError::new(
                "worker_cleanup_evidence.os_evidence_bytes",
                format!("must not exceed {MAX_WORKER_CLEANUP_EVIDENCE_BYTES} bytes"),
            ));
        }
        if Digest::sha256(&self.os_evidence_bytes) != self.receipt.os_evidence_digest {
            return Err(ContractError::new(
                "worker_cleanup_evidence.os_evidence_bytes",
                "digest does not match the retained operating-system evidence",
            ));
        }
        Ok(())
    }
}

/// Durable proof that rollback artifacts for an application transaction were
/// reopened and validated after commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackReference {
    /// Wire-contract version used to encode the reference.
    pub contract_version: u32,
    /// Globally unique reference identity.
    pub reference_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact application receipt whose journal was reopened.
    pub application_receipt_id: String,
    /// Exact capability-applier transaction.
    pub transaction_id: String,
    /// Digest binding immutable journal identity and contents.
    pub journal_binding_digest: Digest,
    /// Snapshot restored by one-click rollback.
    pub base_snapshot: Digest,
    /// Canonical ordered set of all application targets.
    pub touched_target_set_digest: Digest,
    /// Digest of the exact reopened rollback artifacts.
    pub reopened_artifacts_digest: Digest,
    /// Validation time.
    pub validated_at_unix_ms: u64,
}

impl RollbackReference {
    /// Validates the reference envelope independently of its application.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "rollback_reference.contract_version",
            self.contract_version,
            "rollback_reference.reference_id",
            &self.reference_id,
            "rollback_reference.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank(
            "rollback_reference.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_nonblank("rollback_reference.transaction_id", &self.transaction_id)?;
        require_nonzero_timestamp(
            "rollback_reference.validated_at_unix_ms",
            self.validated_at_unix_ms,
        )
    }
}

/// Maximum reopened rollback-artifact evidence retained with one reference.
pub const MAX_ROLLBACK_REFERENCE_EVIDENCE_BYTES: usize = 8 * 1_048_576;

/// Durable rollback-reference envelope with the exact reopened artifact
/// preimage retained by the ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackReferenceEvidence {
    /// Indexed rollback reference.
    pub reference: RollbackReference,
    /// Exact bounded canonical bytes reopened from immutable rollback storage.
    pub reopened_artifacts_bytes: Vec<u8>,
}

impl RollbackReferenceEvidence {
    /// Validates the reference and retained rollback-artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the reference is invalid, evidence is
    /// empty or oversized, or its digest is incorrect.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.reference.validate()?;
        if self.reopened_artifacts_bytes.is_empty() {
            return Err(ContractError::new(
                "rollback_reference_evidence.reopened_artifacts_bytes",
                "must retain the reopened rollback artifacts",
            ));
        }
        if self.reopened_artifacts_bytes.len() > MAX_ROLLBACK_REFERENCE_EVIDENCE_BYTES {
            return Err(ContractError::new(
                "rollback_reference_evidence.reopened_artifacts_bytes",
                format!("must not exceed {MAX_ROLLBACK_REFERENCE_EVIDENCE_BYTES} bytes"),
            ));
        }
        if Digest::sha256(&self.reopened_artifacts_bytes)
            != self.reference.reopened_artifacts_digest
        {
            return Err(ContractError::new(
                "rollback_reference_evidence.reopened_artifacts_bytes",
                "digest does not match the retained reopened artifacts",
            ));
        }
        Ok(())
    }
}

/// Exact canonical request preimage for `RollbackChangeSet`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    /// Wire-contract version used to encode the request.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact application receipt being reversed.
    pub application_receipt_id: String,
    /// Exact application journal transaction being reversed.
    pub application_transaction_id: String,
    /// Reopened rollback artifacts authorizing the operation.
    pub rollback_reference_id: String,
}

impl RollbackRequest {
    /// Validates the strict rollback request envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version or blank identity.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "rollback_request.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("rollback_request.sprint_id", &self.sprint_id)?;
        require_nonblank(
            "rollback_request.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_nonblank(
            "rollback_request.application_transaction_id",
            &self.application_transaction_id,
        )?;
        require_nonblank(
            "rollback_request.rollback_reference_id",
            &self.rollback_reference_id,
        )
    }
}

/// Durable proof that this sprint never began a live-workspace application.
///
/// Persistence derives the no-application condition from the complete effect
/// ledger; this envelope contains no caller-supplied substitute boolean.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveWorkspaceUnchangedReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Immutable sprint base snapshot.
    pub base_snapshot: Digest,
    /// Complete descriptor-relative live manifest at terminalization.
    pub live_manifest_digest: Digest,
    /// Workspace grant used to authorize the descriptor-relative capture.
    pub grant_hash: Digest,
    /// Capture time.
    pub captured_at_unix_ms: u64,
}

/// Durable successful no-op proof for an already-satisfied sprint objective.
///
/// This is deliberately not an empty change set or application receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedNoOpReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact sprint-wide verification that passed on the base snapshot.
    pub final_verification_receipt_id: String,
    /// Immutable sprint base snapshot.
    pub base_snapshot: Digest,
    /// Complete live manifest observed after all worker cleanup.
    pub live_manifest_digest: Digest,
    /// Authenticated workspace grant used for the capture and all policies.
    pub grant_hash: Digest,
    /// Exact grant policy version.
    pub policy_version: u32,
    /// Capture time.
    pub observed_at_unix_ms: u64,
}

impl VerifiedNoOpReceipt {
    /// Validates the no-op receipt envelope and exact live/base equality.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid envelope, a mismatched live
    /// manifest, invalid policy version, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "verified_no_op_receipt.contract_version",
            self.contract_version,
            "verified_no_op_receipt.receipt_id",
            &self.receipt_id,
            "verified_no_op_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank(
            "verified_no_op_receipt.final_verification_receipt_id",
            &self.final_verification_receipt_id,
        )?;
        if self.live_manifest_digest != self.base_snapshot {
            return Err(ContractError::new(
                "verified_no_op_receipt.live_manifest_digest",
                "must equal the verified sprint base snapshot",
            ));
        }
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "verified_no_op_receipt.policy_version",
                "must be greater than zero",
            ));
        }
        require_nonzero_timestamp(
            "verified_no_op_receipt.observed_at_unix_ms",
            self.observed_at_unix_ms,
        )
    }
}

impl LiveWorkspaceUnchangedReceipt {
    /// Validates the unchanged-workspace receipt envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "live_workspace_unchanged_receipt.contract_version",
            self.contract_version,
            "live_workspace_unchanged_receipt.receipt_id",
            &self.receipt_id,
            "live_workspace_unchanged_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonzero_timestamp(
            "live_workspace_unchanged_receipt.captured_at_unix_ms",
            self.captured_at_unix_ms,
        )
    }
}

/// Durable proof that a successful application was rolled back without a
/// touched-target conflict.
///
/// Persistence accepts this receipt only as the indexed child of a
/// [`RollbackEvidence`] envelope. The successful effect observation binds the
/// whole envelope's canonical encoding, not this compact receipt alone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact successful `RollbackChangeSet` effect.
    pub effect_id: String,
    /// Exact successful effect observation.
    pub observation_id: String,
    /// Application being reversed.
    pub application_receipt_id: String,
    /// Exact application journal transaction being reversed.
    pub application_transaction_id: String,
    /// Restored sprint base snapshot.
    pub restored_base_snapshot: Digest,
    /// Canonical ordered digest of restored application endpoints.
    pub restored_endpoints_digest: Digest,
    /// Complete live manifest after rollback; unrelated external edits may
    /// make this differ from `restored_base_snapshot`.
    pub live_manifest_digest: Digest,
    /// Unresolved touched-target conflicts; always zero for this receipt.
    pub unresolved_conflicts: u64,
    /// Rollback completion time.
    pub completed_at_unix_ms: u64,
}

impl RollbackReceipt {
    /// Validates the rollback envelope and zero-conflict invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// a nonzero conflict count, or a zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "rollback_receipt.contract_version",
            self.contract_version,
            "rollback_receipt.receipt_id",
            &self.receipt_id,
            "rollback_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank("rollback_receipt.effect_id", &self.effect_id)?;
        require_nonblank("rollback_receipt.observation_id", &self.observation_id)?;
        require_nonblank(
            "rollback_receipt.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_nonblank(
            "rollback_receipt.application_transaction_id",
            &self.application_transaction_id,
        )?;
        if self.unresolved_conflicts != 0 {
            return Err(ContractError::new(
                "rollback_receipt.unresolved_conflicts",
                "must be zero",
            ));
        }
        require_nonzero_timestamp(
            "rollback_receipt.completed_at_unix_ms",
            self.completed_at_unix_ms,
        )
    }
}

/// Closed source of durable validation for one successful rollback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RollbackValidationMode {
    /// The effect-bound applier returned the successful rollback evidence
    /// directly.
    DirectEffectResponse,
    /// A distinct applier reopened the journal and reconciled the exact
    /// restored state after the original response was lost.
    RecoveryApplierReconciliation,
}

/// Exact registered applier authority that validated one successful rollback
/// outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackValidationEvidence {
    /// Direct effect response or distinct recovery reconciliation.
    pub mode: RollbackValidationMode,
    /// Exact durable launch behind the validating applier session.
    pub runner_launch_id: String,
    /// Exact initialized applier session that validated restored journal state.
    pub runner_session_id: String,
    /// Exact compiler-produced applier policy.
    pub policy_hash: Digest,
    /// Exact authenticated workspace grant.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Exact private journal-state identity.
    pub private_state_digest: Digest,
}

impl RollbackValidationEvidence {
    /// Validates the path-free rollback-validation authority claims.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for blank lifecycle identities or a zero
    /// policy version.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank(
            "rollback_validation_evidence.runner_launch_id",
            &self.runner_launch_id,
        )?;
        require_nonblank(
            "rollback_validation_evidence.runner_session_id",
            &self.runner_session_id,
        )?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "rollback_validation_evidence.policy_version",
                "must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Exact successful evidence preimage for one live-workspace rollback.
///
/// The immutable effect binding remains the executor identity. A recovery
/// validator can attest the exact restored journal state but cannot replace
/// that executor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackEvidence {
    /// Wire-contract version used to encode the evidence.
    pub contract_version: u32,
    /// Exact typed successful rollback receipt.
    pub receipt: RollbackReceipt,
    /// Exact registered authority that validated the restored outcome.
    pub validation: RollbackValidationEvidence,
}

impl RollbackEvidence {
    /// Validates the rollback evidence envelope.
    ///
    /// Ledger validation resolves the effect executor because the compact
    /// receipt deliberately does not duplicate runner lifecycle identities.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version or invalid child.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "rollback_evidence.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        self.receipt.validate()?;
        self.validation.validate()
    }
}

/// One exactly observed live-workspace endpoint conflict.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LivePathConflict {
    /// Normalized workspace-relative regular-file target.
    pub path: PathBuf,
    /// Endpoint digest the applier required for safe reconciliation.
    pub expected_endpoint_digest: Digest,
    /// Endpoint digest observed in the live workspace.
    pub observed_endpoint_digest: Digest,
}

impl LivePathConflict {
    fn validate(&self) -> Result<(), ContractError> {
        require_normalized_relative("live_conflict_receipt.conflicts.path", &self.path)?;
        if self.expected_endpoint_digest == self.observed_endpoint_digest {
            return Err(ContractError::new(
                "live_conflict_receipt.conflicts",
                "expected and observed endpoints must differ",
            ));
        }
        Ok(())
    }
}

/// Closed user decision required to leave a known post-application conflict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LiveConflictUserDecision {
    /// Choose whether external bytes or the sprint result should be preserved
    /// and authorize an explicit reconciliation attempt.
    ChoosePreservedEndpointAndReconcile,
}

/// Durable post-application conflict evidence that deliberately makes no
/// unchanged-workspace claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveConflictReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Globally unique receipt identity.
    pub receipt_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact application receipt whose endpoints now conflict.
    pub application_receipt_id: String,
    /// Exact capability-applier application transaction.
    pub transaction_id: String,
    /// Every exactly observed conflicting target.
    pub conflicts: Vec<LivePathConflict>,
    /// Complete current descriptor-relative live manifest.
    pub live_manifest_digest: Digest,
    /// Exact class of user direction required.
    pub required_user_decision: LiveConflictUserDecision,
    /// Observation time.
    pub observed_at_unix_ms: u64,
}

impl LiveConflictReceipt {
    /// Validates conflict identity, endpoints, uniqueness, and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for unsupported versions, blank identities,
    /// an empty, duplicate, invalid, or non-conflicting path set, or a zero
    /// timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "live_conflict_receipt.contract_version",
            self.contract_version,
            "live_conflict_receipt.receipt_id",
            &self.receipt_id,
            "live_conflict_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank(
            "live_conflict_receipt.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_nonblank("live_conflict_receipt.transaction_id", &self.transaction_id)?;
        if self.conflicts.is_empty() {
            return Err(ContractError::new(
                "live_conflict_receipt.conflicts",
                "must contain at least one conflict",
            ));
        }
        let mut paths = BTreeSet::new();
        for conflict in &self.conflicts {
            conflict.validate()?;
            if !paths.insert(conflict.path.as_path()) {
                return Err(ContractError::new(
                    "live_conflict_receipt.conflicts",
                    "must not contain duplicate paths",
                ));
            }
        }
        require_nonzero_timestamp(
            "live_conflict_receipt.observed_at_unix_ms",
            self.observed_at_unix_ms,
        )
    }
}

/// Exact live-application branch selected by a successful completion.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum CompletionApplication {
    /// A verified aggregate change set was applied and has usable rollback
    /// artifacts.
    Applied {
        /// Exact effect-bound application receipt.
        application_receipt_id: String,
        /// Exact reopened and validated rollback reference.
        rollback_reference_id: String,
    },
    /// The objective was already satisfied at the sprint base and no live
    /// application intent exists.
    VerifiedNoOp {
        /// Exact successful no-op proof.
        verified_no_op_receipt_id: String,
    },
}

impl CompletionApplication {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Applied {
                application_receipt_id,
                rollback_reference_id,
            } => {
                require_nonblank(
                    "completion_receipt.application_receipt_id",
                    application_receipt_id,
                )?;
                require_nonblank(
                    "completion_receipt.rollback_reference_id",
                    rollback_reference_id,
                )
            }
            Self::VerifiedNoOp {
                verified_no_op_receipt_id,
            } => require_nonblank(
                "completion_receipt.verified_no_op_receipt_id",
                verified_no_op_receipt_id,
            ),
        }
    }
}

/// Durable proof that a sprint met the computed finish contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionReceipt {
    /// Wire-contract version used to encode the receipt.
    pub contract_version: u32,
    /// Stable receipt identifier.
    pub receipt_id: String,
    /// Completed sprint identifier.
    pub sprint_id: String,
    /// Authenticated workspace grant shared by every compiled execution policy.
    pub grant_hash: Digest,
    /// Exact workspace-grant policy version.
    pub policy_version: u32,
    /// Exact final verified and applied snapshot.
    pub final_snapshot: Digest,
    /// Exact sprint-wide final verification receipt.
    pub final_verification_receipt_id: String,
    /// Exact applied or verified-no-op live-state branch.
    pub application: CompletionApplication,
    /// Canonically ordered exact zero-descendant receipt set, one for every
    /// durable worker, final-verifier, and applier session registration.
    pub worker_cleanup_receipt_ids: Vec<String>,
    /// Criterion identifiers with exact typed backing.
    #[serde(alias = "passed_acceptance_criteria")]
    pub satisfied_criterion_ids: Vec<String>,
    /// One current typed evidence receipt for each exact sprint criterion.
    #[serde(alias = "acceptance_receipts")]
    pub criterion_evidence_receipt_ids: Vec<String>,
    /// Exact task-integration receipts in contiguous `integration_ordinal`
    /// order. Task identity, worker/session provenance, snapshot ordering, and
    /// task verification are derived from these typed receipts rather than
    /// coordinator-supplied IDs.
    pub task_integration_receipt_ids: Vec<String>,
    /// Final and criterion verification receipt identifiers.
    pub verification_receipts: Vec<String>,
    /// Backend identifier used for the sprint.
    pub provider_backend: String,
    /// Model identifier used for the sprint.
    pub provider_model: String,
    /// Durable final-report identifier.
    pub final_report_id: String,
    /// Completion time in Unix milliseconds.
    pub completed_at_unix_ms: u64,
}

impl CompletionReceipt {
    /// Computes SHA-256 over this binary's current canonical wire encoding.
    ///
    /// This method serializes the in-memory value and therefore must not be used
    /// as the identity of a receipt loaded from historical storage. Callers
    /// validating durable evidence must use
    /// [`crate::PersistedCompletion::completion_receipt_wire_digest`], which is
    /// derived from the exact stored `receipt_json` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when this receipt is invalid or cannot be
    /// encoded as canonical JSON.
    pub fn receipt_digest(&self) -> Result<Digest, ContractError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|error| {
            ContractError::new(
                "completion_receipt",
                format!("cannot encode canonical receipt bytes: {error}"),
            )
        })?;
        Ok(Digest::sha256(&canonical))
    }

    /// Validates receipt identity and evidence references.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for missing, blank, or duplicate evidence
    /// references and invalid completion metadata.
    #[allow(clippy::too_many_lines)] // Every completion authority field is validated in one pass.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_contract_envelope(
            "completion_receipt.contract_version",
            self.contract_version,
            "completion_receipt.receipt_id",
            &self.receipt_id,
            "completion_receipt.sprint_id",
            &self.sprint_id,
        )?;
        require_nonblank(
            "completion_receipt.final_verification_receipt_id",
            &self.final_verification_receipt_id,
        )?;
        if self.policy_version == 0 {
            return Err(ContractError::new(
                "completion_receipt.policy_version",
                "must be greater than zero",
            ));
        }
        self.application.validate()?;
        require_unique_nonblank(
            "completion_receipt.worker_cleanup_receipt_ids",
            &self.worker_cleanup_receipt_ids,
        )?;
        if self.worker_cleanup_receipt_ids.is_empty() {
            return Err(ContractError::new(
                "completion_receipt.worker_cleanup_receipt_ids",
                "must contain every registered worker/final-verifier/applier session receipt",
            ));
        }
        if !self
            .worker_cleanup_receipt_ids
            .windows(2)
            .all(|ids| ids[0] < ids[1])
        {
            return Err(ContractError::new(
                "completion_receipt.worker_cleanup_receipt_ids",
                "must be in strict canonical lexical order",
            ));
        }
        require_unique_nonblank(
            "completion_receipt.satisfied_criterion_ids",
            &self.satisfied_criterion_ids,
        )?;
        if self.satisfied_criterion_ids.is_empty() {
            return Err(ContractError::new(
                "completion_receipt.satisfied_criterion_ids",
                "must contain at least one criterion",
            ));
        }
        require_strict_lexical_order(
            "completion_receipt.satisfied_criterion_ids",
            &self.satisfied_criterion_ids,
        )?;
        require_unique_nonblank(
            "completion_receipt.criterion_evidence_receipt_ids",
            &self.criterion_evidence_receipt_ids,
        )?;
        if self.criterion_evidence_receipt_ids.is_empty() {
            return Err(ContractError::new(
                "completion_receipt.criterion_evidence_receipt_ids",
                "must contain at least one receipt",
            ));
        }
        require_strict_lexical_order(
            "completion_receipt.criterion_evidence_receipt_ids",
            &self.criterion_evidence_receipt_ids,
        )?;
        require_unique_nonblank(
            "completion_receipt.task_integration_receipt_ids",
            &self.task_integration_receipt_ids,
        )?;
        require_unique_nonblank(
            "completion_receipt.verification_receipts",
            &self.verification_receipts,
        )?;
        if self.verification_receipts.is_empty() {
            return Err(ContractError::new(
                "completion_receipt.verification_receipts",
                "must contain at least one receipt",
            ));
        }
        require_strict_lexical_order(
            "completion_receipt.verification_receipts",
            &self.verification_receipts,
        )?;
        if !self
            .verification_receipts
            .contains(&self.final_verification_receipt_id)
        {
            return Err(ContractError::new(
                "completion_receipt.final_verification_receipt_id",
                "must also appear in verification_receipts",
            ));
        }
        require_nonblank(
            "completion_receipt.provider_backend",
            &self.provider_backend,
        )?;
        require_nonblank("completion_receipt.provider_model", &self.provider_model)?;
        require_nonblank("completion_receipt.final_report_id", &self.final_report_id)?;
        require_nonzero_timestamp(
            "completion_receipt.completed_at_unix_ms",
            self.completed_at_unix_ms,
        )
    }
}

pub(super) fn require_strict_lexical_order(
    field: &'static str,
    values: &[String],
) -> Result<(), ContractError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(ContractError::new(
            field,
            "must be in strict canonical lexical order",
        ))
    }
}

pub(super) fn require_contract_envelope(
    version_field: &'static str,
    version: u32,
    id_field: &'static str,
    id: &str,
    sprint_field: &'static str,
    sprint_id: &str,
) -> Result<(), ContractError> {
    if version != CONTRACT_VERSION {
        return Err(ContractError::new(
            version_field,
            format!("expected version {CONTRACT_VERSION}, got {version}"),
        ));
    }
    require_nonblank(id_field, id)?;
    require_nonblank(sprint_field, sprint_id)
}

/// Immutable, content-addressed user-facing result of a completed sprint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FinalReport {
    /// Stable report identifier referenced by the completion receipt.
    pub report_id: String,
    /// Owning sprint identifier.
    pub sprint_id: String,
    /// Exact applied and verified snapshot described by the report.
    pub final_snapshot: Digest,
    /// SHA-256 digest of the exact UTF-8 report body.
    pub content_digest: Digest,
    /// Durable report body shown to the user.
    pub body: String,
    /// Report creation time in Unix milliseconds.
    pub created_at_unix_ms: u64,
}

impl FinalReport {
    /// Calculates the canonical SHA-256 content digest for a report body.
    #[must_use]
    pub fn digest_body(body: &str) -> Digest {
        Digest::sha256(body.as_bytes())
    }

    /// Validates report identity, content integrity, and timestamp metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when an identifier or body is blank, the body
    /// does not match `content_digest`, or the creation timestamp is zero.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_nonblank("final_report.report_id", &self.report_id)?;
        require_nonblank("final_report.sprint_id", &self.sprint_id)?;
        require_nonblank("final_report.body", &self.body)?;
        if Self::digest_body(&self.body) != self.content_digest {
            return Err(ContractError::new(
                "final_report.content_digest",
                "does not match the exact UTF-8 report body",
            ));
        }
        require_nonzero_timestamp("final_report.created_at_unix_ms", self.created_at_unix_ms)
    }
}

/// Closed set of side-effect boundaries understood by the coordinator.
///
/// A provider cannot add authority by inventing a tool name: every durable
/// effect intent must select one of these coordinator-owned kinds. The
/// canonical tool name is persisted in the matching [`AgentEventKind`] and is
/// therefore part of the audit record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EffectKind {
    /// A potentially billable or externally visible model-provider request.
    ProviderRequest,
    /// Read one regular file from an isolated workspace.
    ReadRelativeFile,
    /// Capture one complete descriptor-relative live workspace manifest.
    CaptureWorkspaceState,
    /// Search one regular file for an exact literal.
    SearchLiteral,
    /// Execute an exact argv-vector command without a shell.
    RunCommand,
    /// Create one regular file in a private worker workspace.
    CreateRegularFile,
    /// Replace one regular file in a private worker workspace.
    ReplaceRegularFile,
    /// Delete one regular file in a private worker workspace.
    DeleteRegularFile,
    /// Integrate a staged worker change into a private sprint snapshot.
    IntegrateChangeSet,
    /// Apply a verified change set to the live trusted workspace.
    ApplyChangeSet,
    /// Prove that the immutable worker accounting domain has no surviving
    /// worker or descendant processes.
    CleanupWorkerDomain,
    /// Roll back one previously applied change set through its durable
    /// capability-applier journal.
    RollbackChangeSet,
}

impl EffectKind {
    /// Returns the stable registered tool name recorded in agent events.
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::ProviderRequest => "provider_request",
            Self::ReadRelativeFile => "read_relative_file",
            Self::CaptureWorkspaceState => "capture_workspace_state",
            Self::SearchLiteral => "search_literal",
            Self::RunCommand => "run_command",
            Self::CreateRegularFile => "create_regular_file",
            Self::ReplaceRegularFile => "replace_regular_file",
            Self::DeleteRegularFile => "delete_regular_file",
            Self::IntegrateChangeSet => "integrate_change_set",
            Self::ApplyChangeSet => "apply_change_set",
            Self::CleanupWorkerDomain => "cleanup_worker_domain",
            Self::RollbackChangeSet => "rollback_change_set",
        }
    }

    /// Returns whether success must atomically persist mutation artifacts.
    #[must_use]
    pub const fn is_regular_file_mutation(self) -> bool {
        matches!(
            self,
            Self::CreateRegularFile | Self::ReplaceRegularFile | Self::DeleteRegularFile
        )
    }

    pub(crate) const fn storage_name(self) -> &'static str {
        match self {
            Self::ProviderRequest => "ProviderRequest",
            Self::ReadRelativeFile => "ReadRelativeFile",
            Self::CaptureWorkspaceState => "CaptureWorkspaceState",
            Self::SearchLiteral => "SearchLiteral",
            Self::RunCommand => "RunCommand",
            Self::CreateRegularFile => "CreateRegularFile",
            Self::ReplaceRegularFile => "ReplaceRegularFile",
            Self::DeleteRegularFile => "DeleteRegularFile",
            Self::IntegrateChangeSet => "IntegrateChangeSet",
            Self::ApplyChangeSet => "ApplyChangeSet",
            Self::CleanupWorkerDomain => "CleanupWorkerDomain",
            Self::RollbackChangeSet => "RollbackChangeSet",
        }
    }

    /// Returns whether a successful observation requires an atomic typed
    /// finish receipt instead of the generic effect-observation API.
    #[must_use]
    pub const fn requires_typed_finish_receipt(self) -> bool {
        matches!(
            self,
            Self::IntegrateChangeSet
                | Self::ApplyChangeSet
                | Self::CleanupWorkerDomain
                | Self::RollbackChangeSet
                | Self::CaptureWorkspaceState
        )
    }
}

/// Immutable authorization context committed before a side effect may start.
///
/// `request_digest` is the SHA-256 digest of the caller's canonical request
/// bytes. The request itself remains in the owning boundary's typed protocol;
/// this contract binds its exact identity to policy and input state without
/// giving the ledger execution authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntent {
    /// Wire-contract version used to encode the intent.
    pub contract_version: u32,
    /// Globally unique identity for this one attempted effect.
    pub effect_id: String,
    /// Stable deduplication key unique within the owning sprint.
    pub idempotency_key: String,
    /// Owning sprint identifier.
    pub sprint_id: String,
    /// Owning task, absent only for a sprint-scoped coordinator effect.
    pub task_id: Option<String>,
    /// Owning worker, present exactly when `task_id` is present.
    pub worker_id: Option<String>,
    /// Exact active task-worker assignment. Cleanup effects may carry a lease
    /// while remaining sprint-scoped.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// Event that caused the proposal, when one exists.
    pub causation_event_id: Option<String>,
    /// End-to-end correlation identifier.
    pub correlation_id: String,
    /// Closed coordinator-owned effect category.
    pub kind: EffectKind,
    /// Digest of the exact canonical request bytes.
    pub request_digest: Digest,
    /// Hash of the coordinator-owned policy authorizing this effect.
    ///
    /// Runner effects bind a [`crate::CompiledExecutionPolicy`]. Provider requests
    /// bind their separate transport/provider policy and must never infer
    /// command-network authority from the workspace grant.
    pub policy_hash: Digest,
    /// Exact immutable snapshot against which the request was authorized.
    pub input_snapshot: Digest,
    /// Intent timestamp in Unix milliseconds, shared with its proposal event.
    pub created_at_unix_ms: u64,
}

impl EffectIntent {
    /// Validates the immutable effect identity and execution context.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when identity, scope, correlation, version,
    /// or timestamp metadata is incomplete.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "effect_intent.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("effect_intent.effect_id", &self.effect_id)?;
        require_nonblank("effect_intent.idempotency_key", &self.idempotency_key)?;
        require_nonblank("effect_intent.sprint_id", &self.sprint_id)?;
        require_scoped_task_and_worker(
            "effect_intent",
            self.task_id.as_deref(),
            self.worker_id.as_deref(),
        )?;
        validate_effect_worker_lease(
            "effect_intent.worker_lease",
            self.kind,
            &self.sprint_id,
            self.task_id.as_deref(),
            self.worker_id.as_deref(),
            self.worker_lease.as_ref(),
            self.created_at_unix_ms,
        )?;
        if let Some(causation_event_id) = &self.causation_event_id {
            require_nonblank("effect_intent.causation_event_id", causation_event_id)?;
        }
        require_nonblank("effect_intent.correlation_id", &self.correlation_id)?;
        require_nonzero_timestamp("effect_intent.created_at_unix_ms", self.created_at_unix_ms)
    }
}

/// Durable terminal knowledge about an attempted effect.
///
/// Every outcome carries a digest of the exact boundary-owned receipt,
/// failure, cancellation proof, or reconciliation evidence. Missing terminal
/// evidence is represented by the absence of an [`EffectObservation`], never
/// by manufacturing a failure result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EffectOutcome {
    /// The requested effect completed and its result is known.
    Succeeded {
        /// Digest of the exact result receipt.
        evidence_digest: Digest,
    },
    /// Evidence proves the effect did not begin; a new intent may be created.
    FailedBeforeEffect {
        /// Digest of the exact failure proof.
        evidence_digest: Digest,
    },
    /// The effect occurred and a later, known failure was observed.
    FailedAfterKnownEffect {
        /// Digest of the exact effect and failure evidence.
        evidence_digest: Digest,
    },
    /// Cancellation completed before the effect began.
    CancelledBeforeEffect {
        /// Digest of the exact cancellation and cleanup proof.
        evidence_digest: Digest,
    },
    /// Available evidence cannot prove whether or how the effect completed.
    Unknown {
        /// Digest of the exact reconciliation evidence available so far.
        evidence_digest: Digest,
    },
}

impl EffectOutcome {
    /// Returns the immutable evidence digest carried by this outcome.
    #[must_use]
    pub const fn evidence_digest(&self) -> &Digest {
        match self {
            Self::Succeeded { evidence_digest }
            | Self::FailedBeforeEffect { evidence_digest }
            | Self::FailedAfterKnownEffect { evidence_digest }
            | Self::CancelledBeforeEffect { evidence_digest }
            | Self::Unknown { evidence_digest } => evidence_digest,
        }
    }

    /// Returns whether the effect completed successfully.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    pub(crate) const fn storage_name(&self) -> &'static str {
        match self {
            Self::Succeeded { .. } => "Succeeded",
            Self::FailedBeforeEffect { .. } => "FailedBeforeEffect",
            Self::FailedAfterKnownEffect { .. } => "FailedAfterKnownEffect",
            Self::CancelledBeforeEffect { .. } => "CancelledBeforeEffect",
            Self::Unknown { .. } => "Unknown",
        }
    }
}

/// Terminal observation bound to the exact identity of an [`EffectIntent`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectObservation {
    /// Wire-contract version used to encode the observation.
    pub contract_version: u32,
    /// Globally unique observation identifier.
    pub observation_id: String,
    /// Exact attempted effect being observed.
    pub effect_id: String,
    /// Idempotency key copied from the intent.
    pub idempotency_key: String,
    /// Owning sprint copied from the intent.
    pub sprint_id: String,
    /// Owning task copied from the intent.
    pub task_id: Option<String>,
    /// Owning worker copied from the intent.
    pub worker_id: Option<String>,
    /// Exact worker lease copied from the intent.
    #[serde(default)]
    pub worker_lease: Option<WorkerLease>,
    /// End-to-end correlation identifier copied from the intent.
    pub correlation_id: String,
    /// Effect category copied from the intent.
    pub kind: EffectKind,
    /// Exact canonical request digest copied from the intent.
    pub request_digest: Digest,
    /// Exact effect-authorization policy hash copied from the intent.
    pub policy_hash: Digest,
    /// Exact input snapshot copied from the intent.
    pub input_snapshot: Digest,
    /// Terminal outcome and its boundary-owned evidence digest.
    pub outcome: EffectOutcome,
    /// Observation timestamp in Unix milliseconds, shared with its event.
    pub observed_at_unix_ms: u64,
}

impl EffectObservation {
    /// Validates the observation's structural identity and timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a required field is missing or the wire
    /// version is unsupported.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "effect_observation.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_nonblank("effect_observation.observation_id", &self.observation_id)?;
        require_nonblank("effect_observation.effect_id", &self.effect_id)?;
        require_nonblank("effect_observation.idempotency_key", &self.idempotency_key)?;
        require_nonblank("effect_observation.sprint_id", &self.sprint_id)?;
        require_scoped_task_and_worker(
            "effect_observation",
            self.task_id.as_deref(),
            self.worker_id.as_deref(),
        )?;
        validate_effect_worker_lease(
            "effect_observation.worker_lease",
            self.kind,
            &self.sprint_id,
            self.task_id.as_deref(),
            self.worker_id.as_deref(),
            self.worker_lease.as_ref(),
            self.observed_at_unix_ms,
        )?;
        require_nonblank("effect_observation.correlation_id", &self.correlation_id)?;
        require_nonzero_timestamp(
            "effect_observation.observed_at_unix_ms",
            self.observed_at_unix_ms,
        )
    }

    /// Validates that every execution-identity field exactly matches `intent`.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a cross-effect, cross-context, stale, or
    /// otherwise mismatched terminal observation.
    pub fn validate_against(&self, intent: &EffectIntent) -> Result<(), ContractError> {
        self.validate()?;
        intent.validate()?;
        if self.effect_id != intent.effect_id
            || self.idempotency_key != intent.idempotency_key
            || self.sprint_id != intent.sprint_id
            || self.task_id != intent.task_id
            || self.worker_id != intent.worker_id
            || self.worker_lease != intent.worker_lease
            || self.correlation_id != intent.correlation_id
            || self.kind != intent.kind
            || self.request_digest != intent.request_digest
            || self.policy_hash != intent.policy_hash
            || self.input_snapshot != intent.input_snapshot
        {
            return Err(ContractError::new(
                "effect_observation.intent_identity",
                "must exactly match effect, idempotency, context, request, policy, and input snapshot",
            ));
        }
        if self.observed_at_unix_ms < intent.created_at_unix_ms {
            return Err(ContractError::new(
                "effect_observation.observed_at_unix_ms",
                "must not precede the durable intent",
            ));
        }
        Ok(())
    }
}

pub(super) fn validate_effect_worker_lease(
    field: &'static str,
    kind: EffectKind,
    sprint_id: &str,
    task_id: Option<&str>,
    worker_id: Option<&str>,
    lease: Option<&WorkerLease>,
    occurred_at_unix_ms: u64,
) -> Result<(), ContractError> {
    match (task_id, worker_id, lease) {
        (Some(task_id), Some(worker_id), Some(lease)) => {
            lease.validate_assignment(sprint_id, task_id, worker_id)?;
            if occurred_at_unix_ms < lease.acquired_at_unix_ms {
                return Err(ContractError::new(
                    field,
                    "must not predate lease acquisition",
                ));
            }
            Ok(())
        }
        (None, None, Some(lease)) if kind == EffectKind::CleanupWorkerDomain => {
            lease.validate()?;
            if lease.sprint_id != sprint_id || occurred_at_unix_ms < lease.acquired_at_unix_ms {
                return Err(ContractError::new(
                    field,
                    "cleanup lease must match the sprint and precede cleanup admission",
                ));
            }
            Ok(())
        }
        (None, None, None) => Ok(()),
        _ => Err(ContractError::new(
            field,
            "task-scoped effects require one exact lease; only cleanup may carry a sprint-scoped lease",
        )),
    }
}

/// Coordinator action permitted by the durable evidence currently available.
///
/// This deliberately has no `ReplaySafe` state. Even when evidence proves an
/// effect never began, another attempt must receive a new intent and a new
/// idempotency key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EffectReconciliation {
    /// The effect has a known terminal outcome and must not be rerun.
    TerminalKnown,
    /// Evidence proves no effect occurred; a distinct new intent is allowed.
    NewIntentRequired,
    /// Effect-specific evidence or explicit user reconciliation is required.
    EvidenceRequired,
}

pub(super) fn require_scoped_task_and_worker(
    entity: &'static str,
    task_id: Option<&str>,
    worker_id: Option<&str>,
) -> Result<(), ContractError> {
    match (task_id, worker_id) {
        (Some(task_id), Some(worker_id)) => {
            let task_field = if entity == "effect_intent" {
                "effect_intent.task_id"
            } else {
                "effect_observation.task_id"
            };
            let worker_field = if entity == "effect_intent" {
                "effect_intent.worker_id"
            } else {
                "effect_observation.worker_id"
            };
            require_nonblank(task_field, task_id)?;
            require_nonblank(worker_field, worker_id)
        }
        (None, None) => Ok(()),
        _ => Err(ContractError::new(
            if entity == "effect_intent" {
                "effect_intent.scope"
            } else {
                "effect_observation.scope"
            },
            "task_id and worker_id must either both be present or both be absent",
        )),
    }
}

/// Normalized payload carried by an [`AgentEvent`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AgentEventKind {
    /// A sprint changed state.
    SprintStateChanged {
        /// Previous state name.
        from: String,
        /// New state name.
        to: String,
    },
    /// A task changed state.
    TaskStateChanged {
        /// Previous state name.
        from: String,
        /// New state name.
        to: String,
    },
    /// A worker changed state.
    WorkerStateChanged {
        /// Previous state name.
        from: String,
        /// New state name.
        to: String,
    },
    /// Provider-generated text delta.
    AssistantDelta(String),
    /// A tool call was proposed.
    ToolProposed {
        /// Stable idempotency key.
        tool_call_id: String,
        /// Registered tool name.
        tool_name: String,
    },
    /// A tool call reached a terminal result.
    ToolFinished {
        /// Stable idempotency key.
        tool_call_id: String,
        /// Whether the result was successful.
        succeeded: bool,
    },
    /// A staged change set was produced.
    ChangeSetStaged(String),
    /// A verification receipt was persisted.
    VerificationRecorded(String),
    /// A completion receipt was persisted.
    CompletionRecorded(String),
    /// An unsuccessful sprint terminal outcome was persisted atomically.
    SprintTerminalRecorded {
        /// Stable terminal evidence and event identity.
        record_id: String,
        /// Exact unsuccessful terminal state.
        state: NonSuccessTerminalState,
        /// SHA-256 of the exact canonical terminal-evidence bytes.
        evidence_digest: Digest,
    },
    /// A visible diagnostic was emitted.
    Diagnostic(String),
}

impl AgentEventKind {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::SprintStateChanged { from, to }
            | Self::TaskStateChanged { from, to }
            | Self::WorkerStateChanged { from, to } => {
                require_nonblank("agent_event.payload.from", from)?;
                require_nonblank("agent_event.payload.to", to)
            }
            Self::AssistantDelta(delta) => {
                if delta.is_empty() {
                    Err(ContractError::new(
                        "agent_event.payload.assistant_delta",
                        "must not be empty",
                    ))
                } else {
                    Ok(())
                }
            }
            Self::ToolProposed {
                tool_call_id,
                tool_name,
            } => {
                require_nonblank("agent_event.payload.tool_call_id", tool_call_id)?;
                require_nonblank("agent_event.payload.tool_name", tool_name)
            }
            Self::ToolFinished { tool_call_id, .. } => {
                require_nonblank("agent_event.payload.tool_call_id", tool_call_id)
            }
            Self::ChangeSetStaged(id)
            | Self::VerificationRecorded(id)
            | Self::CompletionRecorded(id) => {
                require_nonblank("agent_event.payload.reference_id", id)
            }
            Self::SprintTerminalRecorded { record_id, .. } => {
                require_nonblank("agent_event.payload.record_id", record_id)
            }
            Self::Diagnostic(message) => {
                require_nonblank("agent_event.payload.diagnostic", message)
            }
        }
    }
}

/// Versioned append-only event envelope shared by UI and persistence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentEvent {
    /// Wire-contract version used to encode this event.
    pub contract_version: u32,
    /// Monotonic sequence within the sprint.
    pub sequence: u64,
    /// Globally unique event identifier.
    pub event_id: String,
    /// Owning sprint identifier.
    pub sprint_id: String,
    /// Optional task identifier.
    pub task_id: Option<String>,
    /// Optional worker identifier.
    pub worker_id: Option<String>,
    /// Event that directly caused this event.
    pub causation_id: Option<String>,
    /// End-to-end correlation identifier.
    pub correlation_id: String,
    /// Active execution policy, when the event concerns execution.
    pub policy_hash: Option<Digest>,
    /// Event timestamp in Unix milliseconds.
    pub occurred_at_unix_ms: u64,
    /// Normalized event data.
    pub payload: AgentEventKind,
}

impl AgentEvent {
    /// Validates event identity, version, sequence, and payload.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an incompatible version, invalid envelope
    /// identity, self-causation, zero sequence/timestamp, or invalid payload.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ContractError::new(
                "agent_event.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        if self.sequence == 0 {
            return Err(ContractError::new(
                "agent_event.sequence",
                "must be greater than zero",
            ));
        }
        require_nonblank("agent_event.event_id", &self.event_id)?;
        require_nonblank("agent_event.sprint_id", &self.sprint_id)?;
        require_nonblank("agent_event.correlation_id", &self.correlation_id)?;
        if let Some(task_id) = &self.task_id {
            require_nonblank("agent_event.task_id", task_id)?;
        }
        if let Some(worker_id) = &self.worker_id {
            require_nonblank("agent_event.worker_id", worker_id)?;
        }
        if let Some(causation_id) = &self.causation_id {
            require_nonblank("agent_event.causation_id", causation_id)?;
            if causation_id == &self.event_id {
                return Err(ContractError::new(
                    "agent_event.causation_id",
                    "an event cannot cause itself",
                ));
            }
        }
        require_nonzero_timestamp("agent_event.occurred_at_unix_ms", self.occurred_at_unix_ms)?;
        self.payload.validate()
    }
}

pub(super) fn require_nonblank(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::new(field, "must not be blank"))
    } else {
        Ok(())
    }
}

pub(super) fn require_bounded_nonblank(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    require_nonblank(field, value)?;
    if value.len() > max_bytes {
        return Err(ContractError::new(
            field,
            format!("must not exceed {max_bytes} UTF-8 bytes"),
        ));
    }
    Ok(())
}

pub(super) fn require_unique_nonblank(
    field: &'static str,
    values: &[String],
) -> Result<(), ContractError> {
    let mut unique = BTreeSet::new();
    for value in values {
        require_nonblank(field, value)?;
        if !unique.insert(value.as_str()) {
            return Err(ContractError::new(
                field,
                format!("duplicate identifier `{value}`"),
            ));
        }
    }
    Ok(())
}

pub(super) fn require_normalized_absolute(
    field: &'static str,
    path: &Path,
) -> Result<(), ContractError> {
    if path.to_str().is_none() {
        return Err(ContractError::new(
            field,
            "must be exactly representable as UTF-8",
        ));
    }
    if !path.is_absolute() {
        return Err(ContractError::new(field, "must be absolute"));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ContractError::new(
            field,
            "must be lexically normalized without `.` or `..`",
        ));
    }
    Ok(())
}

pub(super) fn require_normalized_relative(
    field: &'static str,
    path: &Path,
) -> Result<(), ContractError> {
    if path.to_str().is_none() {
        return Err(ContractError::new(
            field,
            "must be exactly representable as UTF-8",
        ));
    }
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ContractError::new(
            field,
            "must be a non-empty workspace-relative path",
        ));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ContractError::new(
            field,
            "must contain only normalized relative components",
        ));
    }
    Ok(())
}

pub(super) fn require_nonzero_timestamp(
    field: &'static str,
    value: u64,
) -> Result<(), ContractError> {
    if value == 0 {
        Err(ContractError::new(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}
