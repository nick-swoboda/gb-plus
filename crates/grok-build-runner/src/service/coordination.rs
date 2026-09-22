impl RunnerService {
    fn new(runner_nonce: Digest) -> Self {
        Self {
            retained_launch_preparation: None,
            linux_native_service_install_root: None,
            runner_nonce,
            session: None,
            seen_request_ids: BTreeSet::new(),
            seen_effect_ids: BTreeSet::new(),
            seen_idempotency_keys: BTreeSet::new(),
            expected_sequence: 0,
            command_effects_admitted: 0,
            command_capture_private_state_digest: None,
            command_capture_max_aggregate_output_bytes: None,
            command_capture_store: None,
        }
    }

    fn serve_nonblocking<R: Read + AsFd, W: Write, F: CommandJobFactory>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        command_jobs: &mut F,
    ) -> Result<(), RunnerServiceError> {
        let mut decoder = IncrementalRequestDecoder::new();
        let mut active: Option<ActiveCommandJob> = None;
        loop {
            if let Some(command) = active.take() {
                match self.coordinate_active_step(command, reader, writer, &mut decoder)? {
                    CoordinatorTransition::Idle => {}
                    CoordinatorTransition::Active(command) => active = Some(*command),
                    CoordinatorTransition::Stop => return Ok(()),
                }
                continue;
            }

            if !poll_request_fd(reader, None)? {
                continue;
            }
            match decoder.read_available(reader)? {
                IncrementalRequestEvent::Pending => {}
                IncrementalRequestEvent::EndOfStream => {
                    return Err(RunnerServiceError::UnexpectedEndOfStream);
                }
                IncrementalRequestEvent::Request(envelope) => {
                    match self.dispatch_idle_envelope(*envelope, writer, command_jobs)? {
                        CoordinatorTransition::Idle => {}
                        CoordinatorTransition::Active(command) => active = Some(*command),
                        CoordinatorTransition::Stop => return Ok(()),
                    }
                }
            }
        }
    }

    fn coordinate_active_step<R: Read + AsFd, W: Write>(
        &mut self,
        mut command: ActiveCommandJob,
        reader: &mut R,
        writer: &mut W,
        decoder: &mut IncrementalRequestDecoder,
    ) -> Result<CoordinatorTransition, RunnerServiceError> {
        if command.input_closed {
            return match command.wait_outcome(ACTIVE_COMMAND_POLL_INTERVAL) {
                Ok(Some(outcome)) => self.finish_active_transition(command, outcome, writer),
                Ok(None) => Ok(CoordinatorTransition::Active(Box::new(command))),
                Err(error) => Self::abort_active_command(command, error),
            };
        }
        let request_ready = match poll_request_fd(reader, Some(ACTIVE_COMMAND_POLL_INTERVAL)) {
            Ok(ready) => ready,
            Err(error) => return Self::abort_active_command(command, error),
        };
        if request_ready {
            loop {
                match decoder.read_available(reader) {
                    Ok(IncrementalRequestEvent::Pending) => {
                        if command.pending_control.is_some() && decoder.has_partial_frame() {
                            return Self::abort_active_command(
                                command,
                                RunnerServiceError::CommandJobAlreadyActive,
                            );
                        }
                        break;
                    }
                    Ok(IncrementalRequestEvent::EndOfStream) => {
                        if command.pending_control.is_some() && !decoder.has_partial_frame() {
                            command.input_closed = true;
                            break;
                        }
                        return Self::abort_active_command(
                            command,
                            RunnerServiceError::UnexpectedEndOfStream,
                        );
                    }
                    Ok(IncrementalRequestEvent::Request(envelope)) => {
                        if let Err(error) = self.admit_active_control(&mut command, *envelope) {
                            return Self::abort_active_command(command, error);
                        }
                    }
                    Err(error) => {
                        return Self::abort_active_command(command, error.into());
                    }
                }

                let more_input = match poll_request_fd(reader, Some(Duration::ZERO)) {
                    Ok(ready) => ready,
                    Err(error) => return Self::abort_active_command(command, error),
                };
                if !more_input {
                    break;
                }
            }
        }

        if decoder.has_partial_frame() {
            return Ok(CoordinatorTransition::Active(Box::new(command)));
        }
        match command.try_outcome() {
            Ok(Some(outcome)) => self.finish_active_transition(command, outcome, writer),
            Ok(None) => Ok(CoordinatorTransition::Active(Box::new(command))),
            Err(error) => Self::abort_active_command(command, error),
        }
    }

    fn finish_active_transition<W: Write>(
        &mut self,
        command: ActiveCommandJob,
        outcome: CommandJobOutcome,
        writer: &mut W,
    ) -> Result<CoordinatorTransition, RunnerServiceError> {
        Ok(
            if self.finish_active_command(command, Some(outcome), writer)? {
                CoordinatorTransition::Stop
            } else {
                CoordinatorTransition::Idle
            },
        )
    }

    #[allow(
        dead_code,
        reason = "generic blocking compatibility harness cannot admit asynchronous command jobs"
    )]
    fn serve_blocking<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), RunnerServiceError> {
        loop {
            let envelope =
                read_request(reader)?.ok_or(RunnerServiceError::UnexpectedEndOfStream)?;
            match self.dispatch_idle_envelope(
                ServiceRequestEnvelope::V11(envelope),
                writer,
                &mut DisabledCommandJobFactory,
            )? {
                CoordinatorTransition::Idle => {}
                CoordinatorTransition::Stop => return Ok(()),
                CoordinatorTransition::Active(_) => {
                    return Err(RunnerServiceError::CommandJobProtocol);
                }
            }
        }
    }

    fn dispatch_idle_envelope<W: Write, F: CommandJobFactory>(
        &mut self,
        envelope: ServiceRequestEnvelope,
        writer: &mut W,
        command_jobs: &mut F,
    ) -> Result<CoordinatorTransition, RunnerServiceError> {
        match envelope {
            ServiceRequestEnvelope::V11(envelope) => {
                self.dispatch_idle_v11_envelope(envelope, writer)
            }
            ServiceRequestEnvelope::V12(envelope) => {
                self.dispatch_idle_v12_envelope(envelope, writer, command_jobs, None)
            }
            // v14 is v12 plus an admission. The command path is identical --
            // deliberately so, because a contained command is not a different
            // *request*, it is the same request the desktop separately admitted
            // for release.
            ServiceRequestEnvelope::V14(envelope) => {
                let authority = envelope.contained_command_release.clone();
                self.dispatch_idle_v12_envelope(
                    envelope.as_v12_envelope()?,
                    writer,
                    command_jobs,
                    authority,
                )
            }
            // v15 is v14 plus this runner's own launch preparation. The
            // preparation is retained on the session rather than passed to the
            // command path: it says who this runner *is*, which is a fact about
            // the session and not about any one request.
            ServiceRequestEnvelope::V15(envelope) => {
                if let Some(preparation) = envelope.runner_launch_preparation.clone() {
                    self.retained_launch_preparation = Some(preparation);
                }
                let authority = envelope.contained_command_release.clone();
                self.dispatch_idle_v12_envelope(
                    envelope.as_v12_envelope()?,
                    writer,
                    command_jobs,
                    authority,
                )
            }
        }
    }

    fn dispatch_idle_v11_envelope<W: Write>(
        &mut self,
        envelope: RunnerRequestEnvelope,
        writer: &mut W,
    ) -> Result<CoordinatorTransition, RunnerServiceError> {
        self.validate_envelope_order(&envelope)?;
        let request_id = envelope.request_id.clone();
        let session_id = envelope.session_id.clone();
        let sequence = envelope.sequence;
        let effect = envelope.effect.clone();

        let (response, stop) = if self.session.is_none() {
            match self.initialize(&session_id, envelope.request) {
                Ok(response) => {
                    self.expected_sequence = 1;
                    (response, false)
                }
                Err(error) => {
                    let response = response_envelope(
                        &session_id,
                        &self.runner_nonce,
                        sequence,
                        &request_id,
                        effect,
                        RunnerResponse::initialization_rejected(&error),
                    );
                    write_response(writer, &response)?;
                    return Err(RunnerServiceError::Initialization(error));
                }
            }
        } else if matches!(
            envelope.request,
            RunnerRequest::WorkerRunCommand { .. } | RunnerRequest::FinalVerifierRunCommand { .. }
        ) {
            self.advance_sequence()?;
            (
                RunnerResponse::failed_before_effect(
                    "command_requires_runner_protocol_v12",
                    "new RunCommand requests are admitted only by the policy-bound v12 protocol",
                ),
                false,
            )
        } else {
            let effect_input = effect.as_ref().map(|effect| &effect.input_snapshot);
            let result = self.dispatch(envelope.request, effect_input, None)?;
            self.advance_sequence()?;
            result
        };
        let response = response_envelope(
            &session_id,
            &self.runner_nonce,
            sequence,
            &request_id,
            effect,
            response,
        );
        write_response(writer, &response)?;
        Ok(if stop {
            CoordinatorTransition::Stop
        } else {
            CoordinatorTransition::Idle
        })
    }

    fn dispatch_idle_v12_envelope<W: Write, F: CommandJobFactory>(
        &mut self,
        envelope: RunnerRequestEnvelopeV12,
        writer: &mut W,
        command_jobs: &mut F,
        release_authority: Option<WireContainedCommandReleaseAuthorityV1>,
    ) -> Result<CoordinatorTransition, RunnerServiceError> {
        self.validate_v12_envelope_order(&envelope)?;
        self.session
            .as_ref()
            .ok_or(RunnerServiceError::InitializationOrder)?
            .validate_retained_sprint_authority()?;
        let authority = self.command_effect_authority_v12(&envelope)?;
        // The factory seam is asked first and is empty in production, so a test
        // job always wins where one is installed and the production path is
        // never consulted behind it. Production always falls through to the
        // service's own job builder, which is the only holder of session
        // custody.
        let job = match command_jobs.create(&envelope, &authority) {
            Some(job) => Some(job),
            None => self.production_command_job(&envelope, &authority, release_authority),
        };
        if let Some(job) = job {
            let command_effects_admitted = self
                .command_effects_admitted
                .checked_add(1)
                .ok_or(RunnerServiceError::SequenceMismatch)?;
            let expected_sequence = self
                .expected_sequence
                .checked_add(1)
                .ok_or(RunnerServiceError::SequenceMismatch)?;
            let command = ActiveCommandJob::spawn(envelope, job)?;
            self.command_effects_admitted = command_effects_admitted;
            self.expected_sequence = expected_sequence;
            return Ok(CoordinatorTransition::Active(Box::new(command)));
        }

        let containment_refusal = self.containment_refusal_evidence(&envelope);
        let response = RunnerResponseV12::command_failed_with_containment_refusal(
            envelope.detector_policy().clone(),
            WireFailureClass::BeforeEffect,
            WireCommandFailureCodeV12::ContainmentUnavailable,
            None,
            containment_refusal,
        )?;
        self.advance_sequence()?;
        write_response_v12(writer, &response_envelope_v12(&envelope, response))?;
        Ok(CoordinatorTransition::Idle)
    }

    /// Reads back what a pre-launch containment refusal can actually prove.
    ///
    /// Two independent facts are required and neither is asserted: the capture
    /// this request handed over is still its exact untouched `Acquired`
    /// reservation with no launch record and no v2 journal, and the kernel
    /// reports no command domain, no live child, and no reaped child for this
    /// process. Failing either -- or being unable to read either -- yields no
    /// evidence at all, which leaves the refusal exactly as truthful as it was
    /// before and strictly less believed. A weaker record would be worse than
    /// none, because it would be trusted.
    fn containment_refusal_evidence(
        &self,
        envelope: &RunnerRequestEnvelopeV12,
    ) -> Option<Box<WireContainmentRefusalEvidenceV12>> {
        let acquired = match envelope.request.command_request() {
            RunnerRequest::WorkerRunCommand { output_capture, .. }
            | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } => {
                output_capture.acquired()
            }
            _ => return None,
        };
        let effect = &envelope.effect;
        let store = self.command_capture_store.as_ref()?;
        let recovery = store.reopen_capture(&acquired.capture_id).ok()?;
        // No byte can reach an output object before a durable `LaunchIntended`,
        // so requiring the exact untouched acquired head and the absence of any
        // v1 launch record is what makes "this refusal carries no output" a
        // readback rather than a claim.
        if recovery.state() != CommandOutputCaptureJournalStateV1::Acquired
            || recovery.acquired() != Some(acquired)
            || recovery.store_head() != &acquired.store_head
            || recovery.writer_attached_store_head().is_some()
            || recovery.launch_intended_store_head().is_some()
            || recovery.expected_reference().is_some()
            || recovery.terminal().is_some()
            || recovery.pending_record().is_some()
        {
            return None;
        }
        // The v2 journal exists from reservation onward, so its presence is not
        // the question -- its generation is. Generation four is v2
        // `LaunchIntended`; at or past it the command's output status is not
        // this method's to describe, and the refusal attaches nothing.
        if store
            .reopen_optional_sensitive_output_journal_v2_diagnostic(&acquired.capture_id)
            .ok()?
            .is_some_and(|journal| journal.head().generation >= 4)
        {
            return None;
        }
        let observation = crate::command_domain_absence::observe_linux_command_domain_absence(
            &envelope.session_id,
            &effect.effect_id,
            effect.request_digest.as_str(),
        )
        .ok()?;
        let proof =
            ValidatedCommandDomainCleanupProof::from_linux_absence_observation(&observation)
                .ok()?;
        let evidence = WireContainmentRefusalEvidenceV12 {
            capture_id: acquired.capture_id.clone(),
            untouched_store_head: acquired.store_head.clone(),
            command_domain_backend: proof.backend(),
            no_domain_proof_bytes: proof.os_evidence_bytes().to_vec(),
            no_domain_proof_digest: proof.os_evidence_digest().clone(),
        };
        evidence.validate().ok()?;
        Some(Box::new(evidence))
    }

    fn command_effect_authority_v12(
        &self,
        envelope: &RunnerRequestEnvelopeV12,
    ) -> Result<CommandEffectAuthorityV2, RunnerServiceError> {
        let session = self
            .session
            .as_ref()
            .ok_or(RunnerServiceError::InitializationOrder)?;
        CommandEffectAuthorityV2::from_session_validated(SessionValidatedCommandEnvelopeV12 {
            envelope: envelope.clone(),
            grant_hash: session.grant_hash().clone(),
        })
        .map_err(Into::into)
    }

    fn advance_sequence(&mut self) -> Result<(), RunnerServiceError> {
        self.expected_sequence = self
            .expected_sequence
            .checked_add(1)
            .ok_or(RunnerServiceError::SequenceMismatch)?;
        Ok(())
    }

    fn admit_active_control(
        &mut self,
        command: &mut ActiveCommandJob,
        envelope: ServiceRequestEnvelope,
    ) -> Result<(), RunnerServiceError> {
        let ServiceRequestEnvelope::V11(envelope) = envelope else {
            return Err(RunnerServiceError::CommandJobAlreadyActive);
        };
        if command.pending_control.is_some() {
            return Err(RunnerServiceError::CommandJobAlreadyActive);
        }
        let permitted = matches!(envelope.request, RunnerRequest::Shutdown)
            || matches!(envelope.request, RunnerRequest::WorkerCancel)
                && self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.role() == RunnerRole::Worker);
        if !permitted {
            return Err(RunnerServiceError::CommandJobAlreadyActive);
        }
        self.validate_envelope_order(&envelope)?;
        self.advance_sequence()?;
        command.pending_control = Some(envelope);
        command.cancel();
        Ok(())
    }

    fn finish_active_command<W: Write>(
        &mut self,
        command: ActiveCommandJob,
        outcome: Option<CommandJobOutcome>,
        writer: &mut W,
    ) -> Result<bool, RunnerServiceError> {
        let command_envelope = command.envelope.clone();
        let pending_control = command.pending_control.clone();
        let outcome = command.join(outcome)?;
        let response = match outcome {
            CommandJobOutcome::Terminal(terminal) => match *terminal {
                CommandTerminalOutcome::Contained(evidence) => {
                    self.prepare_command_terminal_response(&command_envelope, &evidence)?
                }
                CommandTerminalOutcome::SensitiveOutputRejected(evidence) => {
                    RunnerResponseV12::command_output_abandoned(&evidence)?
                }
                #[cfg(test)]
                CommandTerminalOutcome::PreparedV12(response) => response,
            },
            CommandJobOutcome::RefusedBeforeLaunch { code } => {
                // Prelaunch refusal preserves Acquired capture custody. Independent
                // readback proves that no domain was created.
                let containment_refusal =
                    if matches!(code, WireCommandFailureCodeV12::ContainmentUnavailable) {
                        self.containment_refusal_evidence(&command_envelope)
                    } else {
                        None
                    };
                RunnerResponseV12::command_failed_with_containment_refusal(
                    command_envelope.detector_policy().clone(),
                    WireFailureClass::BeforeEffect,
                    code,
                    None,
                    containment_refusal,
                )?
            }
            CommandJobOutcome::ReconciliationRequired { reference } => {
                RunnerResponseV12::command_failed(
                    command_envelope.detector_policy().clone(),
                    WireFailureClass::ReconciliationRequired,
                    WireCommandFailureCodeV12::ReconciliationRequired,
                    Some(reference),
                )?
            }
            CommandJobOutcome::UnprovenAfterLaunch => {
                return Err(RunnerServiceError::CommandJobUnprovenAfterLaunch);
            }
            CommandJobOutcome::Panicked => return Err(RunnerServiceError::CommandJobPanicked),
        };
        Self::write_correlated_response_v12(writer, &command_envelope, response)?;

        let Some(control) = pending_control else {
            return Ok(false);
        };
        let (response, stop) = self.dispatch(control.request.clone(), None, None)?;
        if !stop {
            return Err(RunnerServiceError::CommandJobProtocol);
        }
        self.write_correlated_response(writer, &control, response)?;
        Ok(true)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "terminal preparation keeps provisional construction, canonical byte binding, durable append, exact readback, and final response validation in one auditable order"
    )]
    fn prepare_command_terminal_response(
        &self,
        request: &RunnerRequestEnvelopeV12,
        evidence: &ContainedExecutionEvidence,
    ) -> Result<RunnerResponseV12, RunnerServiceError> {
        let (RunnerRequest::WorkerRunCommand { output_capture, .. }
        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. }) =
            request.request.command_request()
        else {
            return Err(RunnerServiceError::CommandJobProtocol);
        };
        let acquired = output_capture.acquired();
        if evidence.output_capture_id() != acquired.capture_id
            || evidence.output_capture_acquired_anchor_digest() != &acquired.acquired_anchor_digest
            || evidence.output_artifacts().source != acquired.source
            || evidence
                .output_capture_launch_intended_store_head()
                .generation
                <= acquired.store_head.generation
            || evidence
                .output_capture_launch_intended_store_head()
                .generation
                >= evidence.output_capture_finished_store_head().generation
            || evidence.output_capture_finished_store_head().generation
                >= evidence.output_capture_published_store_head().generation
        {
            return Err(RunnerServiceError::CommandTerminalPreparation(
                "contained evidence crossed its acquired capture or non-monotonic journal heads"
                    .into(),
            ));
        }
        let terminal_generation = evidence
            .output_capture_published_store_head()
            .generation
            .checked_add(1)
            .ok_or_else(|| {
                RunnerServiceError::CommandTerminalPreparation(
                    "TerminalPrepared generation overflowed u64".into(),
                )
            })?;
        let mut provisional_head_preimage = Vec::new();
        provisional_head_preimage
            .extend_from_slice(b"grok-build/command-terminal-provisional-head/v1\0");
        provisional_head_preimage.extend_from_slice(acquired.capture_id.as_bytes());
        provisional_head_preimage.extend_from_slice(
            evidence
                .output_capture_published_store_head()
                .record_digest
                .as_str()
                .as_bytes(),
        );
        let provisional_terminal_head = CommandOutputCaptureStoreHeadV1 {
            generation: terminal_generation,
            record_digest: Digest::sha256(&provisional_head_preimage),
        };
        let capture_terminal = WireCommandOutputCaptureTerminalV1::try_new(
            acquired.capture_id.clone(),
            acquired.acquired_anchor_digest.clone(),
            evidence.output_capture_finished_store_head().clone(),
            evidence.output_capture_published_store_head().clone(),
            provisional_terminal_head,
            evidence.output_artifacts().clone(),
            Digest::sha256(b"grok-build/pending-command-terminal-record/v1"),
        )
        .map_err(|error| {
            RunnerServiceError::CommandTerminalPreparation(format!(
                "cannot construct provisional terminal capture: {error}"
            ))
        })?;
        let mut terminal =
            WireCommandTerminalEvidence::try_from_contained_for_terminal_preparation(
                evidence,
                capture_terminal,
            )
            .map_err(|error| {
                RunnerServiceError::CommandTerminalPreparation(format!(
                    "contained terminal projection failed: {error}"
                ))
            })?;
        terminal.bind_terminal_record_digest().map_err(|error| {
            RunnerServiceError::CommandTerminalPreparation(format!(
                "canonical terminal-record digest binding failed: {error}"
            ))
        })?;
        terminal
            .validate_for_output_capture(output_capture)
            .map_err(|error| {
                RunnerServiceError::CommandTerminalPreparation(format!(
                    "provisional terminal differs from the exact request capture: {error}"
                ))
            })?;
        let terminal_record = command_terminal_record_bytes(&terminal).map_err(|error| {
            RunnerServiceError::CommandTerminalPreparation(format!(
                "canonical terminal-record encoding failed: {error}"
            ))
        })?;
        let store = self.command_capture_store.as_ref().ok_or_else(|| {
            RunnerServiceError::CommandTerminalPreparation(
                "initialized command session retained no exact output store".into(),
            )
        })?;
        let recovery = store
            .prepare_capture_terminal(
                &acquired.capture_id,
                evidence.output_capture_published_store_head(),
                COMMAND_TERMINAL_CAPTURE_SCHEMA,
                terminal_record.clone(),
            )
            .map_err(|error| {
                RunnerServiceError::CommandTerminalPreparation(format!(
                    "TerminalPrepared journal append failed: {error}"
                ))
            })?;
        let terminal_payload = recovery.terminal().ok_or_else(|| {
            RunnerServiceError::CommandTerminalPreparation(
                "terminal append returned no exact canonical payload".into(),
            )
        })?;
        if recovery.acquired() != Some(acquired)
            || recovery.finished_store_head() != Some(evidence.output_capture_finished_store_head())
            || recovery.published_store_head()
                != Some(evidence.output_capture_published_store_head())
            || recovery.expected_reference() != Some(evidence.output_artifacts())
            || terminal_payload.schema != COMMAND_TERMINAL_CAPTURE_SCHEMA
            || terminal_payload.canonical_bytes != terminal_record
            || terminal_payload.canonical_bytes_digest
                != terminal.output_capture.terminal_record_digest
        {
            return Err(RunnerServiceError::CommandTerminalPreparation(
                "durable TerminalPrepared readback crossed capture, heads, artifact, or canonical bytes"
                    .into(),
            ));
        }
        let terminal_prepared_store_head = recovery
            .terminal_prepared_store_head()
            .ok_or_else(|| {
                RunnerServiceError::CommandTerminalPreparation(
                    "terminal append returned no TerminalPrepared head".into(),
                )
            })?
            .clone();
        if terminal_prepared_store_head.generation != terminal_generation {
            return Err(RunnerServiceError::CommandTerminalPreparation(
                "TerminalPrepared readback did not append the exact Published successor".into(),
            ));
        }
        terminal.output_capture.terminal_prepared_store_head = terminal_prepared_store_head;
        terminal
            .validate_for_output_capture(output_capture)
            .map_err(|error| {
                RunnerServiceError::CommandTerminalPreparation(format!(
                    "durably prepared terminal differs from exact request: {error}"
                ))
            })?;
        let scan_receipt = store
            .record_sensitive_output_clean_terminal_prepared_v2(
                &acquired.capture_id,
                &terminal.output_capture.terminal_prepared_store_head,
                &terminal.output_capture.terminal_record_digest,
                terminal.termination,
            )
            .map_err(|error| {
                RunnerServiceError::CommandTerminalPreparation(format!(
                    "v2 clean TerminalPrepared journal append failed: {error}"
                ))
            })?;
        RunnerResponseV12::command_completed(
            evidence,
            terminal.output_capture,
            request.detector_policy().clone(),
            scan_receipt,
        )
        .map_err(Into::into)
    }

    fn write_correlated_response_v12<W: Write>(
        writer: &mut W,
        request: &RunnerRequestEnvelopeV12,
        response: RunnerResponseV12,
    ) -> Result<(), RunnerServiceError> {
        write_response_v12(writer, &response_envelope_v12(request, response))
    }

    fn write_correlated_response<W: Write>(
        &self,
        writer: &mut W,
        request: &RunnerRequestEnvelope,
        response: RunnerResponse,
    ) -> Result<(), RunnerServiceError> {
        let response = response_envelope(
            &request.session_id,
            &self.runner_nonce,
            request.sequence,
            &request.request_id,
            request.effect.clone(),
            response,
        );
        write_response(writer, &response)?;
        Ok(())
    }

    fn abort_active_command<T>(
        command: ActiveCommandJob,
        error: RunnerServiceError,
    ) -> Result<T, RunnerServiceError> {
        command.cancel();
        command.join(None)?;
        Err(error)
    }

    fn validate_envelope_order(
        &mut self,
        envelope: &RunnerRequestEnvelope,
    ) -> Result<(), RunnerServiceError> {
        if self.seen_request_ids.len() >= MAX_SESSION_REQUESTS {
            return Err(RunnerServiceError::DuplicateRequestId);
        }
        if self.seen_request_ids.contains(&envelope.request_id) {
            return Err(RunnerServiceError::DuplicateRequestId);
        }
        if envelope.sequence != self.expected_sequence {
            return Err(RunnerServiceError::SequenceMismatch);
        }
        match (&self.session, &envelope.request) {
            (None, RunnerRequest::InitializeSession { .. }) => {
                self.seen_request_ids.insert(envelope.request_id.clone());
                Ok(())
            }
            (None, _) | (Some(_), RunnerRequest::InitializeSession { .. }) => {
                Err(RunnerServiceError::InitializationOrder)
            }
            (Some(session), request) => {
                if envelope.session_id != session.session_id() {
                    return Err(RunnerServiceError::SessionMismatch);
                }
                if envelope.runner_nonce.as_ref() != Some(&self.runner_nonce) {
                    return Err(RunnerServiceError::RunnerNonceMismatch);
                }
                if let Some(required) = request.required_role()
                    && required != session.role()
                {
                    return Err(RunnerServiceError::RoleConfusion);
                }
                if let RunnerRequest::WorkerRunCommand { output_capture, .. }
                | RunnerRequest::FinalVerifierRunCommand { output_capture, .. } = request
                {
                    let private_state_digest = self
                        .command_capture_private_state_digest
                        .as_ref()
                        .ok_or(RunnerServiceError::EffectContextMismatch)?;
                    let maximum = self
                        .command_capture_max_aggregate_output_bytes
                        .ok_or(RunnerServiceError::EffectContextMismatch)?;
                    output_capture
                        .validate_session_binding(private_state_digest, maximum)
                        .map_err(|_| RunnerServiceError::EffectContextMismatch)?;
                }
                self.seen_request_ids.insert(envelope.request_id.clone());
                if request.is_session_control() {
                    if envelope.effect.is_some() {
                        return Err(RunnerServiceError::EffectContextMismatch);
                    }
                } else {
                    let effect = envelope
                        .effect
                        .as_ref()
                        .ok_or(RunnerServiceError::EffectContextMismatch)?;
                    let expected_input = session.expected_input_snapshot(request)?;
                    if effect.policy_hash != *session.policy_hash()
                        || !session.effect_identity_matches(effect)
                        || expected_input.is_some_and(|expected| effect.input_snapshot != expected)
                    {
                        return Err(RunnerServiceError::EffectContextMismatch);
                    }
                    if self.seen_effect_ids.contains(&effect.effect_id)
                        || self.seen_idempotency_keys.contains(&effect.idempotency_key)
                    {
                        return Err(RunnerServiceError::DuplicateEffectIdentity);
                    }
                    self.seen_effect_ids.insert(effect.effect_id.clone());
                    self.seen_idempotency_keys
                        .insert(effect.idempotency_key.clone());
                }
                Ok(())
            }
        }
    }

    fn validate_v12_envelope_order(
        &mut self,
        envelope: &RunnerRequestEnvelopeV12,
    ) -> Result<(), RunnerServiceError> {
        if self.seen_request_ids.len() >= MAX_SESSION_REQUESTS {
            return Err(RunnerServiceError::DuplicateRequestId);
        }
        if self.seen_request_ids.contains(&envelope.request_id) {
            return Err(RunnerServiceError::DuplicateRequestId);
        }
        if envelope.sequence != self.expected_sequence {
            return Err(RunnerServiceError::SequenceMismatch);
        }
        let session = self
            .session
            .as_ref()
            .ok_or(RunnerServiceError::InitializationOrder)?;
        if envelope.session_id != session.session_id() {
            return Err(RunnerServiceError::SessionMismatch);
        }
        if envelope.runner_nonce != self.runner_nonce {
            return Err(RunnerServiceError::RunnerNonceMismatch);
        }
        let command = envelope.request.command_request();
        if command.required_role() != Some(session.role()) {
            return Err(RunnerServiceError::RoleConfusion);
        }
        let (RunnerRequest::WorkerRunCommand { output_capture, .. }
        | RunnerRequest::FinalVerifierRunCommand { output_capture, .. }) = command
        else {
            return Err(RunnerServiceError::RoleConfusion);
        };
        let private_state_digest = self
            .command_capture_private_state_digest
            .as_ref()
            .ok_or(RunnerServiceError::EffectContextMismatch)?;
        let maximum = self
            .command_capture_max_aggregate_output_bytes
            .ok_or(RunnerServiceError::EffectContextMismatch)?;
        output_capture
            .validate_session_binding(private_state_digest, maximum)
            .map_err(|_| RunnerServiceError::EffectContextMismatch)?;
        let effect = &envelope.effect;
        let expected_input = session.expected_input_snapshot(command)?;
        if effect.policy_hash != *session.policy_hash()
            || !session.effect_identity_matches(effect)
            || expected_input.is_some_and(|expected| effect.input_snapshot != expected)
        {
            return Err(RunnerServiceError::EffectContextMismatch);
        }
        if self.seen_effect_ids.contains(&effect.effect_id)
            || self.seen_idempotency_keys.contains(&effect.idempotency_key)
        {
            return Err(RunnerServiceError::DuplicateEffectIdentity);
        }
        self.seen_request_ids.insert(envelope.request_id.clone());
        self.seen_effect_ids.insert(effect.effect_id.clone());
        self.seen_idempotency_keys
            .insert(effect.idempotency_key.clone());
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "initialization keeps every authority restoration and capability acquisition step explicit"
    )]
    fn initialize(
        &mut self,
        session_id: &str,
        request: RunnerRequest,
    ) -> Result<RunnerResponse, String> {
        let RunnerRequest::InitializeSession {
            launch_id,
            sprint_id,
            sprint_spec,
            expected_sprint_spec_digest,
            logical_worker_id,
            worker_lease,
            role,
            role_input_authority,
            workspace_grant,
            execution_policy_request,
            expected_policy_hash,
            expected_base_snapshot,
            expected_private_state_digest,
            expected_binary_digest,
            expected_binary_identity,
            private_state_root,
            shadow_root,
        } = request
        else {
            return Err("the first request must initialize the session".into());
        };
        let sprint_spec = *sprint_spec;
        let actual_sprint_spec_digest =
            sprint_spec_digest(&sprint_spec).map_err(|error| error.to_string())?;
        let grant_contract = (*workspace_grant)
            .into_native()
            .map_err(|error| error.to_string())?;
        let grant = WorkspaceGrantIssuer::validate_persisted(grant_contract)
            .map_err(|error| error.to_string())?;
        let policy_request = (*execution_policy_request)
            .into_native()
            .map_err(|error| error.to_string())?;
        let policy = ExecutionPolicyCompiler::compile(&grant, policy_request)
            .map_err(|error| error.to_string())?;
        if actual_sprint_spec_digest != expected_sprint_spec_digest
            || sprint_spec.sprint_id != sprint_id
            || sprint_spec.workspace_grant != *grant.contract()
            || sprint_spec.provider.execution_origin != ExecutionOrigin::HostIsolated
            || policy.contract().resource_limits.wall_time_ms > sprint_spec.budget.max_duration_ms
        {
            return Err(
                "sprint specification differs from restored session authority or budget".into(),
            );
        }
        let role_input_is_valid = match (role, &role_input_authority) {
            (
                RunnerRole::Worker | RunnerRole::FinalVerifier,
                RunnerRoleInputAuthority::IntegrationHead,
            ) => true,
            (RunnerRole::Applier, RunnerRoleInputAuthority::PlanningBase) => {
                sprint_spec.base_snapshot == expected_base_snapshot
            }
            (
                RunnerRole::Applier,
                RunnerRoleInputAuthority::PostCompletionAppliedResult {
                    authority,
                    authority_digest,
                },
            ) => {
                authority.validate().is_ok()
                    && serde_json::to_vec(authority)
                        .ok()
                        .is_some_and(|canonical| Digest::sha256(&canonical) == *authority_digest)
                    && authority.sprint_id == sprint_id
                    && authority.artifact.base_snapshot == sprint_spec.base_snapshot
                    && authority.artifact.result_snapshot == expected_base_snapshot
            }
            (
                RunnerRole::LiveStateVerifier,
                RunnerRoleInputAuthority::LiveStateFinalization { plan, plan_digest },
            ) => validate_live_state_finalization_plan(
                plan,
                plan_digest,
                &sprint_id,
                &sprint_spec,
                &expected_policy_hash,
                &expected_base_snapshot,
            )
            .is_ok(),
            _ => false,
        };
        if !role_input_is_valid {
            return Err(
                "role input authority differs from the initialized role or snapshot".into(),
            );
        }
        if policy.contract().policy_hash != expected_policy_hash {
            return Err("independently compiled policy hash differs from the expected hash".into());
        }
        validate_role_policy(role, &policy)?;
        let command_capture_maximum = match role {
            RunnerRole::Worker | RunnerRole::FinalVerifier => Some(
                authenticated_output_capture_maximum(policy.contract().resource_limits)
                    .map_err(|error| error.to_string())?,
            ),
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => None,
        };

        let (binary_digest, binary_identity) = inspect_current_runner_binary()
            .map_err(|error| format!("cannot authenticate runner binary: {error}"))?;
        if binary_digest != expected_binary_digest || binary_identity != expected_binary_identity {
            return Err(format!(
                "runner binary digest or stable identity differs from launcher evidence (launcher digest={expected_binary_digest} identity={expected_binary_identity:?}; executing digest={binary_digest} identity={binary_identity:?})"
            ));
        }

        let private_state_root = exact_private_state_root(&private_state_root, &grant)?;
        let private_state_digest =
            inspect_private_state_digest(&private_state_root).map_err(|error| error.to_string())?;
        if private_state_digest != expected_private_state_digest {
            return Err("private-state path-chain digest differs from launcher evidence".into());
        }
        let confirmed_private_state_digest =
            inspect_private_state_digest(&private_state_root).map_err(|error| error.to_string())?;
        if confirmed_private_state_digest != private_state_digest {
            return Err("private-state path chain changed during capability acquisition".into());
        }
        let command_capture_store = match role {
            RunnerRole::Worker | RunnerRole::FinalVerifier => Some(
                CapabilityCommandOutputStore::open(&private_state_root)
                    .map_err(|error| error.to_string())?,
            ),
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => None,
        };
        let workspace_identity = WireRootIdentity {
            device_id: grant.identity().device_id(),
            inode: grant.identity().inode(),
        };
        let canonical_root = grant
            .contract()
            .canonical_root
            .to_str()
            .ok_or_else(|| "workspace grant canonical root is not UTF-8".to_string())?
            .to_owned();
        let receipt = InitializationReceipt {
            runner_nonce: self.runner_nonce.clone(),
            launch_id: launch_id.clone(),
            sprint_id: sprint_id.clone(),
            sprint_spec_digest: actual_sprint_spec_digest.clone(),
            logical_worker_id: logical_worker_id.clone(),
            worker_lease: worker_lease.clone(),
            role,
            role_input_authority: role_input_authority.clone(),
            grant_id: grant.contract().grant_id.clone(),
            canonical_root,
            grant_hash: grant.contract().grant_hash.clone(),
            policy_id: policy.contract().policy_id.clone(),
            policy_hash: policy.contract().policy_hash.clone(),
            expected_base_snapshot: expected_base_snapshot.clone(),
            workspace_identity,
            private_state_digest,
            binary_digest,
            binary_identity,
            protocol_digest: runner_protocol_digest(),
        };

        let state = match role {
            RunnerRole::Worker => {
                let shadow_root = shadow_root.ok_or_else(|| {
                    "worker initialization requires one fixed shadow root".to_string()
                })?;
                let logical_worker_id = logical_worker_id.ok_or_else(|| {
                    "worker initialization requires one logical worker identity".to_string()
                })?;
                let worker_lease = worker_lease.ok_or_else(|| {
                    "worker initialization requires one exact worker lease".to_string()
                })?;
                worker_lease
                    .validate_assignment(&sprint_id, &worker_lease.task_id, &logical_worker_id)
                    .map_err(|error| error.to_string())?;
                let shadow_leaf = fixed_shadow_leaf(&private_state_root, &shadow_root)?;
                let shadow_store = CapabilityShadowStore::open(&private_state_root)
                    .map_err(|error| error.to_string())?;
                let bundle_store = CapabilityStageBundleStore::open(&private_state_root)
                    .map_err(|error| error.to_string())?;
                let workspace =
                    CapabilityWorkspace::open(grant.clone()).map_err(|error| error.to_string())?;
                InitializedSession::Worker(Box::new(WorkerSession {
                    session_id: session_id.into(),
                    launch_id,
                    sprint_spec,
                    sprint_spec_digest: actual_sprint_spec_digest,
                    role_input_authority: role_input_authority.clone(),
                    logical_worker_id,
                    worker_lease,
                    expected_base_snapshot,
                    grant,
                    policy,
                    workspace,
                    shadow_store,
                    bundle_store,
                    shadow_leaf,
                    captured_base: None,
                    shadow: None,
                    tools: None,
                    current_shadow_snapshot: None,
                }))
            }
            RunnerRole::FinalVerifier => {
                let shadow_root = shadow_root.ok_or_else(|| {
                    "final-verifier initialization requires one existing fixed shadow root"
                        .to_string()
                })?;
                let shadow_leaf = fixed_existing_shadow_leaf(&private_state_root, &shadow_root)?;
                let shadow_store = CapabilityShadowStore::open(&private_state_root)
                    .map_err(|error| error.to_string())?;
                let workspace =
                    CapabilityWorkspace::open(grant.clone()).map_err(|error| error.to_string())?;
                let verifier = workspace
                    .open_verifier_shadow(
                        &grant,
                        &shadow_store,
                        &shadow_leaf,
                        expected_base_snapshot.clone(),
                        observed_at_unix_ms().map_err(|error| error.to_string())?,
                    )
                    .map_err(|error| error.to_string())?;
                InitializedSession::FinalVerifier(Box::new(FinalVerifierSession {
                    session_id: session_id.into(),
                    launch_id,
                    sprint_spec,
                    sprint_spec_digest: actual_sprint_spec_digest,
                    role_input_authority: role_input_authority.clone(),
                    expected_snapshot: expected_base_snapshot,
                    grant,
                    policy,
                    verifier,
                }))
            }
            RunnerRole::Applier => {
                if shadow_root.is_some() {
                    return Err("applier initialization forbids a shadow root".into());
                }
                let workspace =
                    CapabilityWorkspace::open(grant.clone()).map_err(|error| error.to_string())?;
                let bundle_store = CapabilityStageBundleStore::open(&private_state_root)
                    .map_err(|error| error.to_string())?;
                let journal = private_state_root.join(APPLICATION_JOURNAL_CHILD);
                let applier = CapabilitySafeApplier::open(grant.clone(), &journal)
                    .map_err(|error| error.to_string())?;
                InitializedSession::Applier(Box::new(ApplierSession {
                    session_id: session_id.into(),
                    launch_id,
                    sprint_spec,
                    sprint_spec_digest: actual_sprint_spec_digest,
                    role_input_authority,
                    initialized_input_snapshot: expected_base_snapshot,
                    grant,
                    policy,
                    workspace,
                    bundle_store,
                    applier,
                    recovery_complete: false,
                }))
            }
            RunnerRole::LiveStateVerifier => {
                if shadow_root.is_some() {
                    return Err("live-state-verifier initialization forbids a shadow root".into());
                }
                let workspace =
                    CapabilityWorkspace::open(grant.clone()).map_err(|error| error.to_string())?;
                InitializedSession::LiveStateVerifier(Box::new(LiveStateVerifierSession {
                    session_id: session_id.into(),
                    launch_id,
                    sprint_spec,
                    sprint_spec_digest: actual_sprint_spec_digest,
                    role_input_authority,
                    expected_snapshot: expected_base_snapshot,
                    grant,
                    policy,
                    workspace,
                }))
            }
        };
        self.command_capture_private_state_digest = match role {
            RunnerRole::Worker | RunnerRole::FinalVerifier => {
                Some(receipt.private_state_digest.clone())
            }
            RunnerRole::Applier | RunnerRole::LiveStateVerifier => None,
        };
        self.command_capture_max_aggregate_output_bytes = command_capture_maximum;
        self.command_capture_store = command_capture_store;
        self.session = Some(state);
        Ok(RunnerResponse::Initialized { receipt })
    }

    fn dispatch(
        &mut self,
        request: RunnerRequest,
        effect_input: Option<&Digest>,
        command_effect_authority: Option<&CommandEffectAuthorityV1>,
    ) -> Result<(RunnerResponse, bool), RunnerServiceError> {
        let accepted_request_count = u64::try_from(self.seen_request_ids.len())
            .map_err(|_| RunnerServiceError::SequenceMismatch)?;
        let session = self
            .session
            .as_mut()
            .ok_or(RunnerServiceError::InitializationOrder)?;
        session.validate_retained_sprint_authority()?;
        Ok(match session {
            InitializedSession::Worker(worker) => worker.dispatch(
                request,
                effect_input,
                command_effect_authority,
                &self.runner_nonce,
                accepted_request_count,
                self.command_effects_admitted,
            ),
            InitializedSession::FinalVerifier(verifier) => verifier.dispatch(
                &request,
                effect_input,
                command_effect_authority,
                &self.runner_nonce,
                accepted_request_count,
                self.command_effects_admitted,
            ),
            InitializedSession::Applier(applier) => {
                if command_effect_authority.is_some() {
                    return Err(RunnerServiceError::RoleConfusion);
                }
                applier.dispatch(
                    request,
                    &self.runner_nonce,
                    accepted_request_count,
                    self.command_effects_admitted,
                )
            }
            InitializedSession::LiveStateVerifier(verifier) => {
                if command_effect_authority.is_some() {
                    return Err(RunnerServiceError::RoleConfusion);
                }
                verifier.dispatch(
                    request,
                    &self.runner_nonce,
                    accepted_request_count,
                    self.command_effects_admitted,
                )
            }
            #[cfg(test)]
            InitializedSession::Test(session) => session.dispatch(
                &request,
                &self.runner_nonce,
                accepted_request_count,
                self.command_effects_admitted,
            ),
        })
    }
}

