/// Exact live workspace device/inode receipt.
#[allow(
    missing_docs,
    reason = "public fields are the complete Unix root identity"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRootIdentity {
    pub device_id: u64,
    pub inode: u64,
}

/// Evidence produced only after all initialization authority is independently restored.
#[allow(
    missing_docs,
    reason = "public fields are the complete initialization evidence schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitializationReceipt {
    pub runner_nonce: Digest,
    pub launch_id: String,
    pub sprint_id: String,
    pub sprint_spec_digest: Digest,
    pub logical_worker_id: Option<String>,
    pub worker_lease: Option<WorkerLease>,
    pub role: RunnerRole,
    pub role_input_authority: RunnerRoleInputAuthority,
    pub grant_id: String,
    pub canonical_root: String,
    pub grant_hash: Digest,
    pub policy_id: String,
    pub policy_hash: Digest,
    pub expected_base_snapshot: Digest,
    pub workspace_identity: WireRootIdentity,
    pub private_state_digest: Digest,
    pub binary_digest: Digest,
    pub binary_identity: WireBinaryIdentity,
    pub protocol_digest: Digest,
}

/// Bounded receipt for one complete descriptor-captured workspace manifest.
#[allow(
    missing_docs,
    reason = "public fields are the exact bounded capture schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireWorkspaceCapture {
    pub snapshot_id: Digest,
    pub grant_hash: Digest,
    pub created_at_unix_ms: u64,
    pub entry_count: u64,
    pub capture_digest: Digest,
}

impl WireWorkspaceCapture {
    pub(crate) fn from_native(manifest: &WorkspaceManifest) -> Result<Self, WireProtocolError> {
        let entry_count = u64::try_from(manifest.entries().len())
            .map_err(|_| invalid("workspace capture entry count exceeds u64"))?;
        let mut capture = Self {
            snapshot_id: manifest.snapshot().snapshot_id.clone(),
            grant_hash: manifest.snapshot().grant_hash.clone(),
            created_at_unix_ms: manifest.snapshot().created_at_unix_ms,
            entry_count,
            capture_digest: Digest::sha256(b"uninitialized"),
        };
        capture.capture_digest = capture.computed_digest();
        capture.validate()?;
        Ok(capture)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        require_nonzero(self.created_at_unix_ms, "capture timestamp")?;
        if self.capture_digest != self.computed_digest() {
            return Err(invalid(
                "workspace capture digest differs from its exact bounded fields",
            ));
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        let mut preimage = Vec::with_capacity(WORKSPACE_CAPTURE_DOMAIN.len() + 64 * 2 + 16);
        preimage.extend_from_slice(WORKSPACE_CAPTURE_DOMAIN);
        preimage.extend_from_slice(self.snapshot_id.as_str().as_bytes());
        preimage.extend_from_slice(self.grant_hash.as_str().as_bytes());
        preimage.extend_from_slice(&self.created_at_unix_ms.to_be_bytes());
        preimage.extend_from_slice(&self.entry_count.to_be_bytes());
        Digest::sha256(&preimage)
    }
}

/// One exact literal match in a complete search response.
#[allow(
    missing_docs,
    reason = "public fields are the complete literal-match schema"
)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireLiteralMatch {
    pub byte_offset: u64,
    pub line: u64,
    pub column: u64,
}

/// Outcome class used to prevent unsafe replay after an operation error.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFailureClass {
    /// No effect syscall was reached.
    BeforeEffect,
    /// The requested read effect completed, but producing its complete bounded
    /// typed evidence failed. The known effect is not replay-safe and has no
    /// mutable endpoint to reconcile.
    AfterKnownEffect,
    /// An effect may have occurred and must be reconciled, never replayed.
    ReconciliationRequired,
}

/// Path-free or workspace-relative identity for an effect that must be reconciled.
#[allow(
    missing_docs,
    reason = "variant fields are the normative reconciliation schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireReconciliationReference {
    File {
        path: String,
    },
    StageBundle {
        bundle: StageBundleReference,
    },
    Application {
        bundle: StageBundleReference,
    },
    ApplicationRecovery,
    SessionPrivateState {
        state_id: String,
    },
    /// Exact path-free journal endpoint for one command-output capture.
    CommandOutputCapture {
        capture_id: String,
        acquired_anchor_digest: Digest,
        last_known_store_head: CommandOutputCaptureStoreHeadV1,
        expected_output_artifacts: Option<Box<CommandOutputArtifactSetReferenceV1>>,
    },
}

/// Bounded retained bytes plus a commitment to one complete command stream.
#[allow(
    missing_docs,
    reason = "public fields are the complete stream-separated command-output schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandStreamEvidence {
    pub retained_bytes: Vec<u8>,
    pub complete_digest: Digest,
    pub complete_length: u64,
    pub truncated: bool,
}

/// Immutable identity of the containment backend generation behind a command.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror the contained backend identity"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandBackendIdentity {
    pub command_domain_backend: CommandDomainCleanupBackend,
    pub backend_id: String,
    pub implementation_digest: Digest,
}

/// Strictly validated restart reconstruction of one durable contained-command
/// `LaunchIntended` binding.
///
/// Fields remain private so callers cannot turn decoded JSON into launch
/// authority. Construction is available only through
/// [`decode_contained_capture_launch_binding`], which joins the retained bytes
/// to exact core dispatch, session, request, grant, capture, and transport
/// commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCommandCaptureLaunchBinding {
    pub(super) request: RunnerRequestEnvelope,
    pub(super) launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) canonical_bytes_digest: Digest,
    pub(super) launch_digest: Digest,
    pub(super) preflight_digest: Digest,
    pub(super) backend: WireCommandBackendIdentity,
    pub(super) command_domain_binding: CommandDomainCleanupBinding,
    pub(super) closed_exec_descriptors: [i32; 3],
}

impl ValidatedCommandCaptureLaunchBinding {
    /// Exact reconstructed and fully validated worker command request.
    #[must_use]
    pub const fn request(&self) -> &RunnerRequestEnvelope {
        &self.request
    }

    /// Exact immutable `LaunchIntended` journal head supplied by readback.
    #[must_use]
    pub const fn launch_intended_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.launch_intended_store_head
    }

    /// SHA-256 digest of the exact canonical retained binding bytes.
    #[must_use]
    pub const fn canonical_bytes_digest(&self) -> &Digest {
        &self.canonical_bytes_digest
    }

    /// Exact contained-launch digest minted before native preflight.
    #[must_use]
    pub const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    /// Exact active native-preflight digest joined to the launch.
    #[must_use]
    pub const fn preflight_digest(&self) -> &Digest {
        &self.preflight_digest
    }

    /// Exact platform command-domain implementation identity.
    #[must_use]
    pub const fn backend(&self) -> &WireCommandBackendIdentity {
        &self.backend
    }

    /// Exact effect/session/request binding required for cleanup readback.
    #[must_use]
    pub const fn command_domain_binding(&self) -> &CommandDomainCleanupBinding {
        &self.command_domain_binding
    }

    /// Exact child-side descriptor closure report joined to native preflight.
    #[must_use]
    pub const fn closed_exec_descriptors(&self) -> &[i32; 3] {
        &self.closed_exec_descriptors
    }
}

/// Strictly validated restart reconstruction of one durable additive-v12
/// contained-command `LaunchIntended` binding.
///
/// This type remains distinct from [`ValidatedCommandCaptureLaunchBinding`]
/// so a policy-bound request can never be silently projected into the frozen
/// v11 authority vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCommandCaptureLaunchBindingV12 {
    pub(super) request: RunnerRequestEnvelopeV12,
    pub(super) launch_intended_store_head: CommandOutputCaptureStoreHeadV1,
    pub(super) canonical_bytes_digest: Digest,
    pub(super) launch_digest: Digest,
    pub(super) preflight_digest: Digest,
    pub(super) backend: WireCommandBackendIdentity,
    pub(super) command_domain_binding: CommandDomainCleanupBinding,
    pub(super) closed_exec_descriptors: [i32; 3],
}

impl ValidatedCommandCaptureLaunchBindingV12 {
    /// Exact reconstructed and fully validated policy-bound worker command.
    #[must_use]
    pub const fn request(&self) -> &RunnerRequestEnvelopeV12 {
        &self.request
    }

    /// Exact immutable `LaunchIntended` journal head supplied by readback.
    #[must_use]
    pub const fn launch_intended_store_head(&self) -> &CommandOutputCaptureStoreHeadV1 {
        &self.launch_intended_store_head
    }

    /// SHA-256 digest of the exact canonical retained binding bytes.
    #[must_use]
    pub const fn canonical_bytes_digest(&self) -> &Digest {
        &self.canonical_bytes_digest
    }

    /// Exact contained-launch digest minted before native preflight.
    #[must_use]
    pub const fn launch_digest(&self) -> &Digest {
        &self.launch_digest
    }

    /// Exact active native-preflight digest joined to the launch.
    #[must_use]
    pub const fn preflight_digest(&self) -> &Digest {
        &self.preflight_digest
    }

    /// Exact platform command-domain implementation identity.
    #[must_use]
    pub const fn backend(&self) -> &WireCommandBackendIdentity {
        &self.backend
    }

    /// Exact effect/session/request binding required for cleanup readback.
    #[must_use]
    pub const fn command_domain_binding(&self) -> &CommandDomainCleanupBinding {
        &self.command_domain_binding
    }

    /// Exact child-side descriptor closure report joined to native preflight.
    #[must_use]
    pub const fn closed_exec_descriptors(&self) -> &[i32; 3] {
        &self.closed_exec_descriptors
    }
}

/// Exact canonical bytes and digest of one validated command-domain cleanup proof.
#[allow(
    missing_docs,
    reason = "public fields carry the complete restart-validatable cleanup proof"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandCleanupProof {
    pub os_evidence_bytes: Vec<u8>,
    pub os_evidence_digest: Digest,
}

impl TryFrom<&ValidatedCommandDomainCleanupProof> for WireCommandCleanupProof {
    type Error = CommandDomainCleanupProofError;

    fn try_from(proof: &ValidatedCommandDomainCleanupProof) -> Result<Self, Self::Error> {
        proof.validate()?;
        Ok(Self {
            os_evidence_bytes: proof.os_evidence_bytes().to_vec(),
            os_evidence_digest: proof.os_evidence_digest().clone(),
        })
    }
}

impl WireCommandCleanupProof {
    /// Reopens the exact bytes against separately expected backend and effect authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a byte, digest, backend, request-binding, canonical,
    /// native-journal, disposition, or zero-survivor mismatch.
    ///
    /// Every caller of this proof carries a command terminal, so the domain it
    /// describes must be one that existed and was reaped. A proof that no
    /// domain was created holds zero survivors for the opposite reason and is
    /// refused here rather than accepted as an equivalent.
    pub fn readback(
        &self,
        expected_backend: CommandDomainCleanupBackend,
        expected_binding: &CommandDomainCleanupBinding,
    ) -> Result<ValidatedCommandDomainCleanupProof, CommandDomainCleanupProofError> {
        ValidatedCommandDomainCleanupProof::readback_with_disposition(
            &self.os_evidence_bytes,
            &self.os_evidence_digest,
            expected_backend,
            expected_binding,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors,
        )
    }
}

/// Path-free journal closure carried by one completed command response.
///
/// Store-head generations prove strict forward movement from the acquired
/// reservation through complete-stream finish, immutable publication, and the
/// terminal record that makes the full bounded response reconstructable after
/// restart. Store implementations remain outside this DTO.
#[allow(
    missing_docs,
    reason = "public fields are the complete capture-terminal journal schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandOutputCaptureTerminalV1 {
    pub capture_id: String,
    pub acquired_anchor_digest: Digest,
    pub finished_store_head: CommandOutputCaptureStoreHeadV1,
    pub published_store_head: CommandOutputCaptureStoreHeadV1,
    pub terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
    pub expected_output_artifacts: CommandOutputArtifactSetReferenceV1,
    pub terminal_record_digest: Digest,
}

impl WireCommandOutputCaptureTerminalV1 {
    /// Constructs one exact path-free journal closure from store-proven heads
    /// and the terminal record digest returned by durable custody.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed capture identifier, invalid artifact
    /// reference, invalid head, non-monotonic generation, or reused head digest.
    pub fn try_new(
        capture_id: String,
        acquired_anchor_digest: Digest,
        finished_store_head: CommandOutputCaptureStoreHeadV1,
        published_store_head: CommandOutputCaptureStoreHeadV1,
        terminal_prepared_store_head: CommandOutputCaptureStoreHeadV1,
        expected_output_artifacts: CommandOutputArtifactSetReferenceV1,
        terminal_record_digest: Digest,
    ) -> Result<Self, WireProtocolError> {
        let terminal = Self {
            capture_id,
            acquired_anchor_digest,
            finished_store_head,
            published_store_head,
            terminal_prepared_store_head,
            expected_output_artifacts,
            terminal_record_digest,
        };
        terminal.validate()?;
        Ok(terminal)
    }

    /// Validates path-free identity, artifact, and strict journal-head ordering.
    /// The containing terminal separately recomputes `terminal_record_digest`
    /// over the complete terminal payload.
    ///
    /// # Errors
    ///
    /// Returns an error for any malformed field or non-monotonic head sequence.
    pub fn validate(&self) -> Result<(), WireProtocolError> {
        validate_capture_id(&self.capture_id)?;
        self.finished_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.published_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.terminal_prepared_store_head
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        self.expected_output_artifacts
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        if self.finished_store_head.generation >= self.published_store_head.generation
            || self.published_store_head.generation >= self.terminal_prepared_store_head.generation
            || self.finished_store_head.record_digest == self.published_store_head.record_digest
            || self.finished_store_head.record_digest
                == self.terminal_prepared_store_head.record_digest
            || self.published_store_head.record_digest
                == self.terminal_prepared_store_head.record_digest
        {
            return Err(invalid(
                "command-output Finished, Published, and TerminalPrepared heads are not strictly monotonic and distinct",
            ));
        }
        Ok(())
    }
}

/// Complete terminal evidence emitted after command-domain cleanup validates.
#[allow(
    missing_docs,
    reason = "public fields exactly mirror contained execution evidence"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommandTerminalEvidence {
    pub output_capture: WireCommandOutputCaptureTerminalV1,
    pub termination: CommandTerminationV1,
    pub stdout: WireCommandStreamEvidence,
    pub stderr: WireCommandStreamEvidence,
    pub output_artifacts: CommandOutputArtifactSetReferenceV1,
    pub output_digest: Digest,
    pub launch_digest: Digest,
    pub preflight_digest: Digest,
    pub backend: WireCommandBackendIdentity,
    pub cleanup_proof: WireCommandCleanupProof,
    pub duration_ms: u64,
}

impl WireCommandTerminalEvidence {
    /// Validates the complete terminal record and its exact acquired capture.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed evidence or any capture, head, source,
    /// artifact, output-limit, or terminal-record mismatch.
    pub fn validate_for_output_capture(
        &self,
        anchor: &WireCommandOutputCaptureAnchorV1,
    ) -> Result<(), WireProtocolError> {
        validate_command_terminal_capture_bound(anchor, self)
    }

    #[allow(
        dead_code,
        reason = "ordinary command dispatch consumes this one-way adapter when a native backend is admitted"
    )]
    pub(crate) fn try_from_contained(
        evidence: &ContainedExecutionEvidence,
        output_capture: WireCommandOutputCaptureTerminalV1,
    ) -> Result<Self, WireProtocolError> {
        let terminal = Self::from_contained_fields(evidence, output_capture)?;
        validate_command_terminal_shape(&terminal)?;
        Ok(terminal)
    }

    /// Projects contained evidence before the exact `TerminalPrepared` head
    /// exists. The caller must bind the canonical record digest, durably append
    /// those bytes, install the returned head, and then run full validation.
    pub(crate) fn try_from_contained_for_terminal_preparation(
        evidence: &ContainedExecutionEvidence,
        output_capture: WireCommandOutputCaptureTerminalV1,
    ) -> Result<Self, WireProtocolError> {
        let terminal = Self::from_contained_fields(evidence, output_capture)?;
        validate_command_terminal_shape_without_record_digest(&terminal)?;
        Ok(terminal)
    }

    fn from_contained_fields(
        evidence: &ContainedExecutionEvidence,
        output_capture: WireCommandOutputCaptureTerminalV1,
    ) -> Result<Self, WireProtocolError> {
        let termination = match evidence.termination() {
            CommandTermination::Exited(code) => CommandTerminationV1::Exited { code },
            CommandTermination::Signaled(signal) => CommandTerminationV1::Signaled { signal },
            CommandTermination::TimedOut => CommandTerminationV1::TimedOut,
            CommandTermination::Cancelled => CommandTerminationV1::Canceled,
            CommandTermination::OutputLimitExceeded => CommandTerminationV1::OutputLimitExceeded,
        };
        termination
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        let stdout = wire_command_stream(evidence.stdout());
        let stderr = wire_command_stream(evidence.stderr());
        let cleanup_proof = WireCommandCleanupProof::try_from(evidence.cleanup_proof())
            .map_err(|error| invalid(error.to_string()))?;
        let terminal = Self {
            output_capture,
            termination,
            stdout,
            stderr,
            output_artifacts: evidence.output_artifacts().clone(),
            output_digest: evidence.output_digest().clone(),
            launch_digest: evidence.launch_digest().clone(),
            preflight_digest: evidence.preflight_digest().clone(),
            backend: WireCommandBackendIdentity {
                command_domain_backend: evidence.backend().command_domain_backend(),
                backend_id: evidence.backend().backend_id().to_owned(),
                implementation_digest: evidence.backend().implementation_digest().clone(),
            },
            cleanup_proof,
            duration_ms: evidence.duration_ms(),
        };
        Ok(terminal)
    }

    /// Recomputes and installs the canonical v11 terminal-record digest after
    /// every other terminal field has been populated.
    ///
    /// This is intended for the journal writer that is about to persist the
    /// same canonical terminal payload. Receiving clients must validate rather
    /// than rebind the digest.
    ///
    /// # Errors
    ///
    /// Returns an error when any terminal field other than the record digest is
    /// malformed or cannot be canonically encoded.
    pub fn bind_terminal_record_digest(&mut self) -> Result<(), WireProtocolError> {
        validate_command_terminal_shape_without_record_digest(self)?;
        self.output_capture.terminal_record_digest =
            Digest::sha256(&command_terminal_record_bytes_unchecked(self)?);
        validate_command_terminal_shape(self)
    }
}

pub(super) fn wire_command_stream(output: &CapturedOutput) -> WireCommandStreamEvidence {
    WireCommandStreamEvidence {
        retained_bytes: output.bytes().to_vec(),
        complete_digest: output.complete_digest().clone(),
        complete_length: output.complete_length(),
        truncated: output.truncated(),
    }
}

/// What the still-running runner can truthfully say about local private state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireStateDisposition {
    /// No operating-system or durable-state endpoint has yet been proven.
    Unproven,
}

/// Non-authoritative acknowledgement emitted immediately before runner exit.
///
/// This is deliberately not cleanup or completion evidence. The desktop must
/// wait for process exit and independently inspect its platform accounting
/// domain before constructing any terminal cleanup receipt.
#[allow(
    missing_docs,
    reason = "public fields are the exact non-authoritative shutdown acknowledgement"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownPreparedAcknowledgement {
    pub session_id: String,
    pub runner_nonce: Digest,
    pub role: RunnerRole,
    pub accepted_request_count: u64,
    pub command_effects_admitted: u64,
    pub runner_exit_pending: bool,
    pub private_shadow_present: bool,
    pub state_disposition: WireStateDisposition,
    pub acknowledgement_digest: Digest,
}

/// Semantic role of one exact reopened rollback artifact.
#[allow(
    missing_docs,
    reason = "variant fields are the exact artifact-role schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRollbackArtifactKind {
    Plan,
    BaseBlob { operation_index: u32 },
}

/// Exact metadata and content digest for one reopened rollback artifact.
#[allow(
    missing_docs,
    reason = "public fields are the complete artifact schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackArtifact {
    pub kind: WireRollbackArtifactKind,
    pub name: String,
    pub length: u64,
    pub mode: u32,
    pub digest: Digest,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

/// Exact canonical proof that immutable rollback artifacts were reopened.
#[allow(
    missing_docs,
    reason = "public fields mirror the native rollback reference exactly"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackArtifactReference {
    pub transaction_id: String,
    pub change_set_id: String,
    pub base_snapshot: Digest,
    pub touched_target_set_digest: Digest,
    pub target_contract_digest: Digest,
    pub transaction_device: u64,
    pub transaction_inode: u64,
    pub transaction_mode: u32,
    pub transaction_owner_uid: u32,
    pub artifacts_digest: Digest,
    pub artifacts: Vec<WireRollbackArtifact>,
}

impl WireRollbackArtifactReference {
    pub(crate) fn from_native(
        reference: &CapabilityRollbackArtifactReference,
    ) -> Result<Self, WireProtocolError> {
        let wire = Self {
            transaction_id: reference.transaction_id().to_owned(),
            change_set_id: reference.change_set_id().to_owned(),
            base_snapshot: reference.base_snapshot().clone(),
            touched_target_set_digest: reference.touched_target_set_digest().clone(),
            target_contract_digest: reference.target_contract_digest().clone(),
            transaction_device: reference.transaction_device(),
            transaction_inode: reference.transaction_inode(),
            transaction_mode: reference.transaction_mode(),
            transaction_owner_uid: reference.transaction_owner_uid(),
            artifacts_digest: reference.artifacts_digest().clone(),
            artifacts: reference
                .artifacts()
                .iter()
                .map(WireRollbackArtifact::from_native)
                .collect(),
        };
        wire.validate()?;
        if wire.canonical_bytes() != reference.reopened_artifacts_bytes() {
            return Err(invalid(
                "native rollback artifact bytes differ from reconstructed wire metadata",
            ));
        }
        Ok(wire)
    }

    /// Reconstructs the exact canonical native rollback-artifact evidence bytes.
    ///
    /// Frame decoding separately validates every field and requires these bytes
    /// to produce `artifacts_digest` before the reference can be trusted.
    #[must_use]
    pub fn reopened_artifacts_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_identifier("rollback.transaction_id", &self.transaction_id)?;
        validate_identifier("rollback.change_set_id", &self.change_set_id)?;
        if self.transaction_mode != 0o700
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_ROLLBACK_ARTIFACTS
        {
            return Err(invalid(
                "rollback transaction mode, artifact count, or canonical byte length is invalid",
            ));
        }
        let mut previous_base_index = None;
        let mut artifact_identities = std::collections::BTreeSet::new();
        for (position, artifact) in self.artifacts.iter().enumerate() {
            artifact.validate()?;
            if artifact.owner_uid != self.transaction_owner_uid
                || artifact.device != self.transaction_device
                || (position == 0 && artifact.length == 0)
                || !artifact_identities.insert((artifact.device, artifact.inode))
            {
                return Err(invalid(
                    "rollback artifact ownership, device, identity uniqueness, or plan length differs from its transaction",
                ));
            }
            match (&artifact.kind, position) {
                (WireRollbackArtifactKind::Plan, 0) if artifact.name == "plan" => {}
                (WireRollbackArtifactKind::BaseBlob { operation_index }, position)
                    if position > 0
                        && artifact.name == format!("base-{operation_index:06}")
                        && previous_base_index
                            .is_none_or(|previous| *operation_index > previous) =>
                {
                    previous_base_index = Some(*operation_index);
                }
                _ => {
                    return Err(invalid(
                        "rollback artifacts are not the canonical plan/base-blob sequence",
                    ));
                }
            }
        }
        let canonical = self.canonical_bytes();
        if Digest::sha256(&canonical) != self.artifacts_digest {
            return Err(invalid(
                "rollback artifact digest differs from exact reconstructed metadata bytes",
            ));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|error| WireProtocolError::Encode(error.to_string()))?;
        if encoded.len() > MAX_ROLLBACK_WIRE_ENCODED_BYTES {
            return Err(invalid(
                "rollback artifact reference exceeds the proven encoded wire bound",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_for_change_set(
        &self,
        change_set: &ChangeSet,
    ) -> Result<(), WireProtocolError> {
        self.validate()?;
        let expected = std::iter::once((WireRollbackArtifactKind::Plan, "plan".to_owned(), None))
            .chain(
                change_set
                    .operations
                    .iter()
                    .enumerate()
                    .filter_map(|(index, operation)| {
                        let operation_index = u32::try_from(index).ok()?;
                        let expected_digest = match operation {
                            FileOperation::Modify { base_hash, .. }
                            | FileOperation::Delete { base_hash, .. } => base_hash.clone(),
                            FileOperation::Create { .. } => return None,
                        };
                        Some((
                            WireRollbackArtifactKind::BaseBlob { operation_index },
                            format!("base-{operation_index:06}"),
                            Some(expected_digest),
                        ))
                    }),
            )
            .collect::<Vec<_>>();
        if self.change_set_id != change_set.change_set_id
            || self.base_snapshot != change_set.base_snapshot
            || self.touched_target_set_digest != change_set_target_digest(change_set)?
            || self.artifacts.len() != expected.len()
            || self
                .artifacts
                .iter()
                .zip(expected)
                .any(|(artifact, (kind, name, digest))| {
                    artifact.kind != kind
                        || artifact.name != name
                        || digest.is_some_and(|digest| artifact.digest != digest)
                })
        {
            return Err(invalid(
                "rollback artifact reference differs from the exact change-set target contract",
            ));
        }
        Ok(())
    }

    pub(super) fn canonical_bytes(&self) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut encoded = String::new();
        encoded.push_str(ROLLBACK_ARTIFACT_VERSION);
        encoded.push('\n');
        let _ = writeln!(
            encoded,
            "transaction\t{}",
            encode_hex(self.transaction_id.as_bytes())
        );
        let _ = writeln!(
            encoded,
            "change-set\t{}",
            encode_hex(self.change_set_id.as_bytes())
        );
        let _ = writeln!(encoded, "base\t{}", self.base_snapshot);
        let _ = writeln!(encoded, "targets\t{}", self.touched_target_set_digest);
        let _ = writeln!(encoded, "target-contract\t{}", self.target_contract_digest);
        let _ = writeln!(
            encoded,
            "transaction-identity\t{}\t{}\t{:o}\t{}",
            self.transaction_device,
            self.transaction_inode,
            self.transaction_mode,
            self.transaction_owner_uid
        );
        let _ = writeln!(encoded, "artifacts\t{}", self.artifacts.len());
        for artifact in &self.artifacts {
            let (kind, operation_index) = match artifact.kind {
                WireRollbackArtifactKind::Plan => ("plan", "-".to_owned()),
                WireRollbackArtifactKind::BaseBlob { operation_index } => {
                    ("base", operation_index.to_string())
                }
            };
            let _ = writeln!(
                encoded,
                "artifact\t{kind}\t{operation_index}\t{}\t{}\t{:o}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                encode_hex(artifact.name.as_bytes()),
                artifact.length,
                artifact.mode,
                artifact.digest,
                artifact.device,
                artifact.inode,
                artifact.owner_uid,
                artifact.modified_seconds,
                artifact.modified_nanoseconds,
                artifact.changed_seconds,
                artifact.changed_nanoseconds,
            );
        }
        encoded.into_bytes()
    }
}

impl WireRollbackArtifact {
    fn from_native(artifact: &CapabilityRollbackArtifact) -> Self {
        Self {
            kind: match artifact.kind() {
                CapabilityRollbackArtifactKind::Plan => WireRollbackArtifactKind::Plan,
                CapabilityRollbackArtifactKind::BaseBlob { operation_index } => {
                    WireRollbackArtifactKind::BaseBlob {
                        operation_index: *operation_index,
                    }
                }
            },
            name: artifact.name().to_owned(),
            length: artifact.length(),
            mode: artifact.mode(),
            digest: artifact.digest().clone(),
            device: artifact.device(),
            inode: artifact.inode(),
            owner_uid: artifact.owner_uid(),
            modified_seconds: artifact.modified_seconds(),
            modified_nanoseconds: artifact.modified_nanoseconds(),
            changed_seconds: artifact.changed_seconds(),
            changed_nanoseconds: artifact.changed_nanoseconds(),
        }
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_identifier("rollback.artifact.name", &self.name)?;
        if self.mode != 0o600
            || !(0..1_000_000_000).contains(&self.modified_nanoseconds)
            || !(0..1_000_000_000).contains(&self.changed_nanoseconds)
        {
            return Err(invalid(
                "rollback artifact mode or timestamp nanoseconds are invalid",
            ));
        }
        Ok(())
    }
}

/// One exact expected endpoint in an explicit rollback target contract.
#[allow(
    missing_docs,
    reason = "variant fields are the exact expected-endpoint schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRollbackExpectedEndpoint {
    Absent,
    Regular { digest: Digest, mode: u32 },
}

impl WireRollbackExpectedEndpoint {
    fn from_native(endpoint: &CapabilityRollbackExpectedEndpoint) -> Self {
        match endpoint {
            CapabilityRollbackExpectedEndpoint::Absent => Self::Absent,
            CapabilityRollbackExpectedEndpoint::Regular { digest, mode } => Self::Regular {
                digest: digest.clone(),
                mode: *mode,
            },
        }
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        match self {
            Self::Absent => Ok(()),
            Self::Regular { mode, .. } if *mode <= 0o777 => Ok(()),
            Self::Regular { .. } => Err(invalid(
                "rollback expected endpoint mode is outside normalized permission bits",
            )),
        }
    }

    fn endpoint_digest(&self) -> Digest {
        match self {
            Self::Absent => Digest::sha256(ABSENT_ROLLBACK_ENDPOINT_DOMAIN),
            Self::Regular { digest, .. } => digest.clone(),
        }
    }
}

/// One exact safe live endpoint observation.
#[allow(
    missing_docs,
    reason = "variant fields are the exact observed-endpoint schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRollbackObservedEndpoint {
    Absent,
    Regular {
        digest: Digest,
        length: u64,
        mode: u32,
    },
}

impl WireRollbackObservedEndpoint {
    fn from_native(endpoint: &CapabilityRollbackObservedEndpoint) -> Self {
        match endpoint {
            CapabilityRollbackObservedEndpoint::Absent => Self::Absent,
            CapabilityRollbackObservedEndpoint::Regular {
                digest,
                length,
                mode,
            } => Self::Regular {
                digest: digest.clone(),
                length: *length,
                mode: *mode,
            },
        }
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        match self {
            Self::Absent => Ok(()),
            Self::Regular { length, mode, .. }
                if *length <= crate::capability_apply::MAX_APPLY_FILE_BYTES && *mode <= 0o777 =>
            {
                Ok(())
            }
            Self::Regular { .. } => Err(invalid(
                "rollback observed endpoint length or mode exceeds its hard bound",
            )),
        }
    }

    fn endpoint_digest(&self) -> Digest {
        match self {
            Self::Absent => Digest::sha256(ABSENT_ROLLBACK_ENDPOINT_DOMAIN),
            Self::Regular { digest, .. } => digest.clone(),
        }
    }

    fn matches_expected(&self, expected: &WireRollbackExpectedEndpoint) -> bool {
        match (self, expected) {
            (Self::Absent, WireRollbackExpectedEndpoint::Absent) => true,
            (
                Self::Regular { digest, mode, .. },
                WireRollbackExpectedEndpoint::Regular {
                    digest: expected_digest,
                    mode: expected_mode,
                },
            ) => digest == expected_digest && mode == expected_mode,
            (Self::Absent, WireRollbackExpectedEndpoint::Regular { .. })
            | (Self::Regular { .. }, WireRollbackExpectedEndpoint::Absent) => false,
        }
    }
}

/// Exact expected application/base endpoints for one ordered rollback target.
#[allow(
    missing_docs,
    reason = "public fields are the exact target-contract schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackTargetContract {
    pub path: String,
    pub application: WireRollbackExpectedEndpoint,
    pub restored_base: WireRollbackExpectedEndpoint,
}

impl WireRollbackTargetContract {
    fn from_native(target: &CapabilityRollbackTargetContract) -> Result<Self, WireProtocolError> {
        Ok(Self {
            path: portable_path(target.path())?,
            application: WireRollbackExpectedEndpoint::from_native(target.application()),
            restored_base: WireRollbackExpectedEndpoint::from_native(target.restored_base()),
        })
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_relative_path_text(&self.path)?;
        self.application.validate()?;
        self.restored_base.validate()
    }
}

/// One safe descriptor-relative endpoint observation.
#[allow(
    missing_docs,
    reason = "public fields are the exact endpoint-observation schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackPathObservation {
    pub path: String,
    pub endpoint: WireRollbackObservedEndpoint,
}

impl WireRollbackPathObservation {
    fn from_native(
        observation: &CapabilityRollbackPathObservation,
    ) -> Result<Self, WireProtocolError> {
        Ok(Self {
            path: portable_path(observation.path())?,
            endpoint: WireRollbackObservedEndpoint::from_native(observation.endpoint()),
        })
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_relative_path_text(&self.path)?;
        self.endpoint.validate()
    }
}

/// One exact content/absence mismatch in a stable pre-effect observation.
#[allow(
    missing_docs,
    reason = "public fields are the exact rollback-conflict schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackPathConflict {
    pub path: String,
    pub expected_endpoint_digest: Digest,
    pub observed_endpoint_digest: Digest,
}

impl WireRollbackPathConflict {
    fn from_native(conflict: &CapabilityRollbackPathConflict) -> Result<Self, WireProtocolError> {
        Ok(Self {
            path: portable_path(conflict.path())?,
            expected_endpoint_digest: conflict.expected_endpoint_digest().clone(),
            observed_endpoint_digest: conflict.observed_endpoint_digest().clone(),
        })
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_relative_path_text(&self.path)?;
        if self.expected_endpoint_digest == self.observed_endpoint_digest {
            return Err(invalid(
                "rollback conflict expected and observed endpoint digests are equal",
            ));
        }
        Ok(())
    }
}

/// Exact immediate-precondition and final restoration evidence for an explicit
/// rollback. This distinct evidence shape leaves the legacy restoration DTO readable.
#[allow(
    missing_docs,
    reason = "public fields are the complete explicit-rollback evidence schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireExplicitRollbackEvidence {
    pub bundle: StageBundleReference,
    pub rollback: WireRollbackArtifactReference,
    pub transaction_id: String,
    pub change_set_id: String,
    pub target_contract: Vec<WireRollbackTargetContract>,
    pub expected_application_endpoints_digest: Digest,
    pub restored_base_endpoints_digest: Digest,
    pub touched_target_set_digest: Digest,
    pub pre_effect_observations: Vec<WireRollbackPathObservation>,
    pub pre_effect_observations_digest: Digest,
    pub effect_started_at_unix_ms: u64,
    pub post_restore_observations: Vec<WireRollbackPathObservation>,
    pub post_restore_observations_digest: Digest,
    pub final_live_manifest_digest: Digest,
    pub final_live_manifest_observed_at_unix_ms: u64,
}

/// Exact stable stale-target evidence that proves rollback mutation never began.
#[allow(
    missing_docs,
    reason = "public fields are the complete no-live-effect conflict schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackLiveConflict {
    pub bundle: StageBundleReference,
    pub rollback: WireRollbackArtifactReference,
    pub transaction_id: String,
    pub change_set_id: String,
    pub target_contract: Vec<WireRollbackTargetContract>,
    pub expected_application_endpoints_digest: Digest,
    pub touched_target_set_digest: Digest,
    pub observations: Vec<WireRollbackPathObservation>,
    pub observed_endpoints_digest: Digest,
    pub conflicts: Vec<WireRollbackPathConflict>,
    pub live_manifest_digest: Digest,
    pub manifest_observed_at_unix_ms: u64,
    pub observed_at_unix_ms: u64,
    pub rollback_mutation_started: bool,
}

impl WireExplicitRollbackEvidence {
    pub(crate) fn from_native(
        evidence: &CapabilityRollbackSuccessEvidence,
        change_set: &ChangeSet,
    ) -> Result<Self, WireProtocolError> {
        validate_bundle_change_set(evidence.bundle(), change_set)?;
        let wire = Self {
            bundle: evidence.bundle().clone(),
            rollback: WireRollbackArtifactReference::from_native(evidence.rollback())?,
            transaction_id: evidence.rollback().transaction_id().to_owned(),
            change_set_id: evidence.rollback().change_set_id().to_owned(),
            target_contract: evidence
                .target_contract()
                .iter()
                .map(WireRollbackTargetContract::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            expected_application_endpoints_digest: evidence
                .expected_application_endpoints_digest()
                .clone(),
            restored_base_endpoints_digest: evidence.restored_base_endpoints_digest().clone(),
            touched_target_set_digest: evidence.touched_target_set_digest().clone(),
            pre_effect_observations: evidence
                .pre_effect_observations()
                .iter()
                .map(WireRollbackPathObservation::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            pre_effect_observations_digest: evidence.pre_effect_observations_digest().clone(),
            effect_started_at_unix_ms: evidence.effect_started_at_unix_ms(),
            post_restore_observations: evidence
                .post_restore_observations()
                .iter()
                .map(WireRollbackPathObservation::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            post_restore_observations_digest: evidence.post_restore_observations_digest().clone(),
            final_live_manifest_digest: evidence.final_live_manifest_digest().clone(),
            final_live_manifest_observed_at_unix_ms: evidence
                .final_live_manifest_observed_at_unix_ms(),
        };
        wire.validate_for_change_set(change_set)?;
        Ok(wire)
    }

    /// Revalidates this decoded evidence against independently retained request
    /// authority and the exact reopened change set.
    ///
    /// The target vector remains in immutable `ChangeSet.operations` order.
    /// A core adapter that needs path-sorted precondition endpoints must first
    /// call this method, then sort only its separate core projection.
    ///
    /// # Errors
    ///
    /// Returns an error for any bundle, artifact, transaction, path order,
    /// endpoint, observation, digest, timestamp, or bound substitution.
    pub fn validate_against(
        &self,
        expected_bundle: &StageBundleReference,
        expected_rollback: &WireRollbackArtifactReference,
        change_set: &ChangeSet,
    ) -> Result<(), WireProtocolError> {
        if &self.bundle != expected_bundle || &self.rollback != expected_rollback {
            return Err(invalid(
                "explicit rollback evidence differs from independently retained request authority",
            ));
        }
        validate_bundle_change_set(expected_bundle, change_set)?;
        expected_rollback.validate_for_change_set(change_set)?;
        self.validate_for_change_set(change_set)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_rollback_evidence_common(
            &self.bundle,
            &self.rollback,
            &self.transaction_id,
            &self.change_set_id,
            &self.target_contract,
            &self.expected_application_endpoints_digest,
            &self.touched_target_set_digest,
        )?;
        validate_ordered_observations(&self.target_contract, &self.pre_effect_observations)?;
        validate_ordered_observations(&self.target_contract, &self.post_restore_observations)?;
        if self.pre_effect_observations_digest
            != rollback_observations_digest(&self.pre_effect_observations)?
            || self.post_restore_observations_digest
                != rollback_observations_digest(&self.post_restore_observations)?
            || self.restored_base_endpoints_digest
                != wire_restored_base_endpoints_digest(&self.target_contract)?
            || !observations_match_contract(
                &self.target_contract,
                &self.pre_effect_observations,
                true,
            )
            || !observations_match_contract(
                &self.target_contract,
                &self.post_restore_observations,
                false,
            )
            || self.effect_started_at_unix_ms == 0
            || self.final_live_manifest_observed_at_unix_ms < self.effect_started_at_unix_ms
        {
            return Err(invalid(
                "explicit rollback observations, digests, endpoints, or timestamps disagree",
            ));
        }
        validate_bounded_rollback_response(self)
    }

    fn validate_for_change_set(&self, change_set: &ChangeSet) -> Result<(), WireProtocolError> {
        self.validate()?;
        validate_target_contract_for_change_set(&self.target_contract, change_set)?;
        if self.restored_base_endpoints_digest != change_set_restored_endpoints_digest(change_set)?
        {
            return Err(invalid(
                "explicit rollback evidence differs from the exact reopened change set",
            ));
        }
        Ok(())
    }
}

impl WireRollbackLiveConflict {
    pub(crate) fn from_native(
        evidence: &CapabilityRollbackLiveConflict,
        change_set: &ChangeSet,
    ) -> Result<Self, WireProtocolError> {
        validate_bundle_change_set(evidence.bundle(), change_set)?;
        let wire = Self {
            bundle: evidence.bundle().clone(),
            rollback: WireRollbackArtifactReference::from_native(evidence.rollback())?,
            transaction_id: evidence.rollback().transaction_id().to_owned(),
            change_set_id: evidence.rollback().change_set_id().to_owned(),
            target_contract: evidence
                .target_contract()
                .iter()
                .map(WireRollbackTargetContract::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            expected_application_endpoints_digest: evidence
                .expected_application_endpoints_digest()
                .clone(),
            touched_target_set_digest: evidence.touched_target_set_digest().clone(),
            observations: evidence
                .observations()
                .iter()
                .map(WireRollbackPathObservation::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            observed_endpoints_digest: evidence.observed_endpoints_digest().clone(),
            conflicts: evidence
                .conflicts()
                .iter()
                .map(WireRollbackPathConflict::from_native)
                .collect::<Result<Vec<_>, _>>()?,
            live_manifest_digest: evidence.live_manifest_digest().clone(),
            manifest_observed_at_unix_ms: evidence.manifest_observed_at_unix_ms(),
            observed_at_unix_ms: evidence.observed_at_unix_ms(),
            rollback_mutation_started: evidence.rollback_mutation_started(),
        };
        wire.validate_for_change_set(change_set)?;
        Ok(wire)
    }

    /// Revalidates this decoded no-effect conflict against independently
    /// retained request authority and the exact reopened change set.
    ///
    /// # Errors
    ///
    /// Returns an error for any bundle, artifact, transaction, path order,
    /// observation, exact conflict subset, digest, timestamp, or bound
    /// substitution.
    pub fn validate_against(
        &self,
        expected_bundle: &StageBundleReference,
        expected_rollback: &WireRollbackArtifactReference,
        change_set: &ChangeSet,
    ) -> Result<(), WireProtocolError> {
        if &self.bundle != expected_bundle || &self.rollback != expected_rollback {
            return Err(invalid(
                "rollback live-conflict evidence differs from independently retained request authority",
            ));
        }
        validate_bundle_change_set(expected_bundle, change_set)?;
        expected_rollback.validate_for_change_set(change_set)?;
        self.validate_for_change_set(change_set)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_rollback_evidence_common(
            &self.bundle,
            &self.rollback,
            &self.transaction_id,
            &self.change_set_id,
            &self.target_contract,
            &self.expected_application_endpoints_digest,
            &self.touched_target_set_digest,
        )?;
        validate_ordered_observations(&self.target_contract, &self.observations)?;
        let expected_conflicts =
            wire_rollback_conflicts(&self.target_contract, &self.observations)?;
        if self.observed_endpoints_digest != rollback_observations_digest(&self.observations)?
            || self.conflicts.is_empty()
            || self.conflicts != expected_conflicts
            || self.rollback_mutation_started
            || self.manifest_observed_at_unix_ms == 0
            || self.observed_at_unix_ms < self.manifest_observed_at_unix_ms
        {
            return Err(invalid(
                "rollback conflict set, endpoint digest, no-effect claim, or timestamps disagree",
            ));
        }
        for conflict in &self.conflicts {
            conflict.validate()?;
        }
        validate_bounded_rollback_response(self)
    }

    fn validate_for_change_set(&self, change_set: &ChangeSet) -> Result<(), WireProtocolError> {
        self.validate()?;
        validate_target_contract_for_change_set(&self.target_contract, change_set)
    }
}

pub(super) fn validate_rollback_evidence_common(
    bundle: &StageBundleReference,
    rollback: &WireRollbackArtifactReference,
    transaction_id: &str,
    change_set_id: &str,
    target_contract: &[WireRollbackTargetContract],
    expected_application_endpoints_digest: &Digest,
    touched_target_set_digest: &Digest,
) -> Result<(), WireProtocolError> {
    bundle
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    rollback.validate()?;
    validate_identifier("explicit_rollback.transaction_id", transaction_id)?;
    validate_identifier("explicit_rollback.change_set_id", change_set_id)?;
    if target_contract.is_empty() || target_contract.len() > MAX_ROLLBACK_EVIDENCE_TARGETS {
        return Err(invalid(
            "explicit rollback target count is outside its hard bound",
        ));
    }
    let mut paths = std::collections::BTreeSet::new();
    for target in target_contract {
        target.validate()?;
        if !paths.insert(target.path.as_str()) {
            return Err(invalid("explicit rollback target paths are not unique"));
        }
    }
    if transaction_id != rollback.transaction_id
        || change_set_id != bundle.change_set_id
        || change_set_id != rollback.change_set_id
        || bundle.base_snapshot != rollback.base_snapshot
        || touched_target_set_digest != &rollback.touched_target_set_digest
        || touched_target_set_digest != &wire_rollback_target_set_digest(target_contract)?
        || rollback.target_contract_digest != wire_rollback_target_contract_digest(target_contract)?
        || expected_application_endpoints_digest
            != &wire_expected_application_endpoints_digest(target_contract)?
    {
        return Err(invalid(
            "explicit rollback bundle, artifact, transaction, target, or endpoint binding disagrees",
        ));
    }
    Ok(())
}

pub(super) fn validate_ordered_observations(
    targets: &[WireRollbackTargetContract],
    observations: &[WireRollbackPathObservation],
) -> Result<(), WireProtocolError> {
    if observations.len() != targets.len() {
        return Err(invalid(
            "rollback observation count differs from the exact target set",
        ));
    }
    for (target, observation) in targets.iter().zip(observations) {
        observation.validate()?;
        if observation.path != target.path {
            return Err(invalid(
                "rollback observation paths are reordered or substituted",
            ));
        }
    }
    Ok(())
}

pub(super) fn observations_match_contract(
    targets: &[WireRollbackTargetContract],
    observations: &[WireRollbackPathObservation],
    application: bool,
) -> bool {
    targets.iter().zip(observations).all(|(target, observed)| {
        let expected = if application {
            &target.application
        } else {
            &target.restored_base
        };
        observed.endpoint.matches_expected(expected)
    })
}

pub(super) fn wire_rollback_conflicts(
    targets: &[WireRollbackTargetContract],
    observations: &[WireRollbackPathObservation],
) -> Result<Vec<WireRollbackPathConflict>, WireProtocolError> {
    validate_ordered_observations(targets, observations)?;
    let mut conflicts = Vec::new();
    for (target, observation) in targets.iter().zip(observations) {
        if observation.endpoint.matches_expected(&target.application) {
            continue;
        }
        let expected_endpoint_digest = target.application.endpoint_digest();
        let observed_endpoint_digest = observation.endpoint.endpoint_digest();
        if expected_endpoint_digest == observed_endpoint_digest {
            return Err(invalid(
                "mode-only rollback drift is not typed live-conflict authority",
            ));
        }
        conflicts.push(WireRollbackPathConflict {
            path: target.path.clone(),
            expected_endpoint_digest,
            observed_endpoint_digest,
        });
    }
    Ok(conflicts)
}

#[derive(Serialize)]
pub(super) struct WireExpectedApplicationEndpointDigestEntry<'a> {
    pub(super) path: &'a str,
    pub(super) endpoint: &'a WireRollbackExpectedEndpoint,
}

pub(super) fn wire_expected_application_endpoints_digest(
    targets: &[WireRollbackTargetContract],
) -> Result<Digest, WireProtocolError> {
    let entries = targets
        .iter()
        .map(|target| WireExpectedApplicationEndpointDigestEntry {
            path: &target.path,
            endpoint: &target.application,
        })
        .collect::<Vec<_>>();
    digest_wire_contract(EXPECTED_ROLLBACK_ENDPOINTS_DOMAIN, &entries)
}

pub(super) fn rollback_observations_digest(
    observations: &[WireRollbackPathObservation],
) -> Result<Digest, WireProtocolError> {
    digest_wire_contract(OBSERVED_ROLLBACK_ENDPOINTS_DOMAIN, observations)
}

pub(super) fn wire_rollback_target_set_digest(
    targets: &[WireRollbackTargetContract],
) -> Result<Digest, WireProtocolError> {
    let paths = targets
        .iter()
        .map(|target| target.path.as_str())
        .collect::<Vec<_>>();
    digest_wire_contract(b"grok-build.touched-target-set.v1\0", &paths)
}

#[derive(Serialize)]
pub(super) struct WireRollbackTargetContractDigestEntry<'a> {
    pub(super) path: &'a str,
    pub(super) application: &'a WireRollbackExpectedEndpoint,
    pub(super) restored_base: &'a WireRollbackExpectedEndpoint,
}

pub(super) fn wire_rollback_target_contract_digest(
    targets: &[WireRollbackTargetContract],
) -> Result<Digest, WireProtocolError> {
    let entries = targets
        .iter()
        .map(|target| WireRollbackTargetContractDigestEntry {
            path: &target.path,
            application: &target.application,
            restored_base: &target.restored_base,
        })
        .collect::<Vec<_>>();
    digest_wire_contract(ROLLBACK_TARGET_CONTRACT_DOMAIN, &entries)
}

#[derive(Serialize)]
pub(super) struct WireRestoredEndpointDigestEntry<'a> {
    pub(super) path: &'a str,
    pub(super) restored_hash: Option<&'a Digest>,
}

pub(super) fn wire_restored_base_endpoints_digest(
    targets: &[WireRollbackTargetContract],
) -> Result<Digest, WireProtocolError> {
    let entries = targets
        .iter()
        .map(|target| WireRestoredEndpointDigestEntry {
            path: &target.path,
            restored_hash: match &target.restored_base {
                WireRollbackExpectedEndpoint::Absent => None,
                WireRollbackExpectedEndpoint::Regular { digest, .. } => Some(digest),
            },
        })
        .collect::<Vec<_>>();
    digest_wire_contract(b"grok-build.restored-base-endpoints.v1\0", &entries)
}

pub(super) fn digest_wire_contract(
    domain: &[u8],
    value: &(impl Serialize + ?Sized),
) -> Result<Digest, WireProtocolError> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    let mut preimage = Vec::with_capacity(domain.len() + encoded.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&encoded);
    Ok(Digest::sha256(&preimage))
}

/// Validates and commits to one exact canonical [`SprintSpec`].
///
/// The digest is shared by runner initialization and every platform command
/// plan. It is deliberately independent of the runner protocol version so a
/// platform adapter cannot substitute its own sprint encoding or domain.
///
/// # Errors
///
/// Returns an error when the sprint contract is invalid or canonical JSON
/// serialization fails.
pub fn sprint_spec_digest(sprint: &SprintSpec) -> Result<Digest, WireProtocolError> {
    sprint
        .validate()
        .map_err(|error| invalid(format!("sprint contract failed: {error}")))?;
    digest_wire_contract(SPRINT_SPEC_DIGEST_DOMAIN, sprint)
}

pub(super) fn validate_target_contract_for_change_set(
    targets: &[WireRollbackTargetContract],
    change_set: &ChangeSet,
) -> Result<(), WireProtocolError> {
    change_set
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if change_set.operations.len() > MAX_CHANGE_SET_OPERATIONS
        || targets.len() != change_set.operations.len()
    {
        return Err(invalid(
            "rollback target contract count differs from the exact change set",
        ));
    }
    for (target, operation) in targets.iter().zip(&change_set.operations) {
        let path = operation
            .path()
            .to_str()
            .ok_or_else(|| invalid("change-set operation path is not UTF-8"))?;
        let (application_digest, restored_digest) = match operation {
            FileOperation::Create { result_hash, .. } => (Some(result_hash), None),
            FileOperation::Modify {
                base_hash,
                result_hash,
                ..
            } => (Some(result_hash), Some(base_hash)),
            FileOperation::Delete { base_hash, .. } => (None, Some(base_hash)),
        };
        let exact_application = match (&target.application, application_digest) {
            (WireRollbackExpectedEndpoint::Absent, None) => true,
            (WireRollbackExpectedEndpoint::Regular { digest, .. }, Some(expected)) => {
                digest == expected
            }
            _ => false,
        };
        let exact_base = match (&target.restored_base, restored_digest) {
            (WireRollbackExpectedEndpoint::Absent, None) => true,
            (WireRollbackExpectedEndpoint::Regular { digest, .. }, Some(expected)) => {
                digest == expected
            }
            _ => false,
        };
        if target.path != path || !exact_application || !exact_base {
            return Err(invalid(
                "rollback target contract path or content endpoints differ from the change set",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_bounded_rollback_response(
    value: &impl Serialize,
) -> Result<(), WireProtocolError> {
    const ENVELOPE_RESERVE_BYTES: usize = 64 * 1024;
    let encoded =
        serde_json::to_vec(value).map_err(|error| WireProtocolError::Encode(error.to_string()))?;
    if encoded.len() > MAX_WIRE_FRAME_BYTES.saturating_sub(ENVELOPE_RESERVE_BYTES) {
        return Err(invalid(
            "rollback evidence exceeds the bounded runner response frame",
        ));
    }
    Ok(())
}

/// Canonical evidence that one exact staged bundle committed.
#[allow(
    missing_docs,
    reason = "public fields are the complete application evidence schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireApplicationEvidence {
    pub bundle: StageBundleReference,
    pub change_set_id: String,
    pub base_snapshot: Digest,
    pub result_snapshot: Digest,
    pub transaction_id: String,
    pub live_manifest_digest: Digest,
    pub applied_operations_digest: Digest,
    pub touched_path_endpoints_digest: Digest,
    pub touched_target_set_digest: Digest,
    pub rollback: WireRollbackArtifactReference,
}

impl WireApplicationEvidence {
    pub(crate) fn from_native(
        bundle: &StageBundleReference,
        change_set: &ChangeSet,
        outcome: &CapabilityApplyOutcome,
        rollback: &CapabilityRollbackArtifactReference,
        live_manifest: &WorkspaceManifest,
    ) -> Result<Self, WireProtocolError> {
        validate_bundle_change_set(bundle, change_set)?;
        let rollback = WireRollbackArtifactReference::from_native(rollback)?;
        if outcome.change_set_id() != change_set.change_set_id
            || outcome.applied_snapshot() != &change_set.result_snapshot
            || outcome.live_manifest_digest() != &live_manifest.snapshot().snapshot_id
            || outcome.applied_operations_digest() != &change_set_operations_digest(change_set)?
            || outcome.touched_path_endpoints_digest() != &change_set_endpoints_digest(change_set)?
            || outcome.touched_target_set_digest() != &change_set_target_digest(change_set)?
        {
            return Err(invalid(
                "native application outcome differs from the exact staged change set or recaptured live manifest",
            ));
        }
        let evidence = Self {
            bundle: bundle.clone(),
            change_set_id: change_set.change_set_id.clone(),
            base_snapshot: change_set.base_snapshot.clone(),
            result_snapshot: change_set.result_snapshot.clone(),
            transaction_id: outcome.transaction_id().to_owned(),
            live_manifest_digest: outcome.live_manifest_digest().clone(),
            applied_operations_digest: outcome.applied_operations_digest().clone(),
            touched_path_endpoints_digest: outcome.touched_path_endpoints_digest().clone(),
            touched_target_set_digest: outcome.touched_target_set_digest().clone(),
            rollback,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        self.bundle
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        validate_identifier("application.change_set_id", &self.change_set_id)?;
        validate_identifier("application.transaction_id", &self.transaction_id)?;
        self.rollback.validate()?;
        if self.change_set_id != self.bundle.change_set_id
            || self.base_snapshot != self.bundle.base_snapshot
            || self.result_snapshot != self.bundle.result_snapshot
            || self.rollback.transaction_id != self.transaction_id
            || self.rollback.change_set_id != self.bundle.change_set_id
            || self.rollback.base_snapshot != self.bundle.base_snapshot
            || self.rollback.touched_target_set_digest != self.touched_target_set_digest
        {
            return Err(invalid(
                "application bundle, operation, endpoint, target, manifest, transaction, or rollback evidence disagrees",
            ));
        }
        Ok(())
    }
}

/// Exact target-restoration evidence returned by reconciliation or rollback.
#[allow(
    missing_docs,
    reason = "public fields are the complete restoration evidence schema"
)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRollbackEvidence {
    pub bundle: StageBundleReference,
    pub transaction_id: String,
    pub change_set_id: String,
    pub base_snapshot: Digest,
    pub live_manifest_digest: Digest,
    pub restored_base_endpoints_digest: Digest,
    pub touched_target_set_digest: Digest,
}

impl WireRollbackEvidence {
    pub(crate) fn from_native(
        bundle: &StageBundleReference,
        change_set: &ChangeSet,
        outcome: &CapabilityRollbackOutcome,
        live_manifest: &WorkspaceManifest,
    ) -> Result<Self, WireProtocolError> {
        validate_bundle_change_set(bundle, change_set)?;
        let expected_paths = change_set
            .operations
            .iter()
            .map(FileOperation::path)
            .collect::<Vec<_>>();
        if outcome.restored_paths() != expected_paths
            || outcome.change_set_id() != change_set.change_set_id
            || outcome.base_snapshot() != &change_set.base_snapshot
            || outcome.live_manifest_digest() != &live_manifest.snapshot().snapshot_id
            || outcome.restored_base_endpoints_digest()
                != &change_set_restored_endpoints_digest(change_set)?
            || outcome.touched_target_set_digest() != &change_set_target_digest(change_set)?
        {
            return Err(invalid(
                "native rollback outcome differs from the exact staged base endpoints or recaptured live manifest",
            ));
        }
        let evidence = Self {
            bundle: bundle.clone(),
            transaction_id: outcome.transaction_id().to_owned(),
            change_set_id: outcome.change_set_id().to_owned(),
            base_snapshot: outcome.base_snapshot().clone(),
            live_manifest_digest: outcome.live_manifest_digest().clone(),
            restored_base_endpoints_digest: outcome.restored_base_endpoints_digest().clone(),
            touched_target_set_digest: outcome.touched_target_set_digest().clone(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        self.bundle
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        validate_identifier("rollback.transaction_id", &self.transaction_id)?;
        validate_identifier("rollback.change_set_id", &self.change_set_id)?;
        if self.change_set_id != self.bundle.change_set_id
            || self.base_snapshot != self.bundle.base_snapshot
        {
            return Err(invalid(
                "restoration bundle, base, paths, endpoints, targets, or live manifest disagrees",
            ));
        }
        Ok(())
    }
}

impl ShutdownPreparedAcknowledgement {
    /// Constructs the bounded, non-terminal acknowledgement emitted before
    /// runner shutdown or worker cancellation.
    #[must_use]
    pub fn new(
        session_id: &str,
        runner_nonce: Digest,
        role: RunnerRole,
        accepted_request_count: u64,
        command_effects_admitted: u64,
        private_shadow_present: bool,
    ) -> Self {
        let mut acknowledgement = Self {
            session_id: session_id.into(),
            runner_nonce,
            role,
            accepted_request_count,
            command_effects_admitted,
            runner_exit_pending: true,
            private_shadow_present,
            state_disposition: WireStateDisposition::Unproven,
            acknowledgement_digest: Digest::sha256(&[]),
        };
        acknowledgement.acknowledgement_digest = acknowledgement.computed_digest();
        acknowledgement
    }

    pub(super) fn validate(&self) -> Result<(), WireProtocolError> {
        validate_identifier("shutdown.session_id", &self.session_id)?;
        if self.accepted_request_count < 2
            || self.command_effects_admitted > self.accepted_request_count.saturating_sub(2)
            || (matches!(
                self.role,
                RunnerRole::Applier | RunnerRole::LiveStateVerifier
            ) && self.command_effects_admitted != 0)
            || !self.runner_exit_pending
            || self.state_disposition != WireStateDisposition::Unproven
        {
            return Err(invalid(
                "shutdown acknowledgement overstates the still-running endpoint",
            ));
        }
        if self.acknowledgement_digest != self.computed_digest() {
            return Err(invalid(
                "shutdown acknowledgement digest differs from its exact local fields",
            ));
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(SHUTDOWN_ACK_DOMAIN);
        preimage.extend_from_slice(
            &u64::try_from(self.session_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        preimage.extend_from_slice(self.session_id.as_bytes());
        preimage.extend_from_slice(self.runner_nonce.as_str().as_bytes());
        preimage.push(match self.role {
            RunnerRole::Worker => 0,
            RunnerRole::FinalVerifier => 1,
            RunnerRole::Applier => 2,
            RunnerRole::LiveStateVerifier => 3,
        });
        preimage.extend_from_slice(&self.accepted_request_count.to_be_bytes());
        preimage.extend_from_slice(&self.command_effects_admitted.to_be_bytes());
        preimage.push(u8::from(self.runner_exit_pending));
        preimage.push(u8::from(self.private_shadow_present));
        preimage.push(match self.state_disposition {
            WireStateDisposition::Unproven => 0,
        });
        Digest::sha256(&preimage)
    }
}

