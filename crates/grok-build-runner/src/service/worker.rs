impl WorkerSession {
    fn command_execution_root_authority(
        &self,
        authority: &CommandEffectAuthorityV1,
    ) -> Result<SessionValidatedWorkerExecutionRoot, String> {
        authority
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        let effect = authority
            .envelope()
            .effect
            .as_ref()
            .ok_or_else(|| "Worker command effect has no durable context".to_string())?;
        let current_snapshot = self
            .current_shadow_snapshot
            .as_ref()
            .ok_or_else(|| "Worker command has no admitted current shadow snapshot".to_string())?;
        if authority.role() != RunnerRole::Worker
            || authority.envelope().session_id != self.session_id
            || authority.grant_hash() != &self.grant.contract().grant_hash
            || effect.launch_id != self.launch_id
            || effect.sprint_id != self.sprint_spec.sprint_id
            || effect.task_id.as_deref() != Some(&self.worker_lease.task_id)
            || effect.worker_id.as_deref() != Some(&self.logical_worker_id)
            || effect.worker_lease.as_ref() != Some(&self.worker_lease)
            || effect.policy_hash != self.policy.contract().policy_hash
            || &effect.input_snapshot != current_snapshot
            || !matches!(
                authority.envelope().request,
                RunnerRequest::WorkerRunCommand { .. }
            )
        {
            return Err(
                "Worker command root custody differs from initialized session/effect authority"
                    .into(),
            );
        }
        let shadow = self
            .shadow
            .as_ref()
            .ok_or_else(|| "Worker command requires its initialized shadow".to_string())?;
        if shadow.root().parent() != Some(self.shadow_store.root())
            || shadow.root().file_name().and_then(|leaf| leaf.to_str())
                != Some(self.shadow_leaf.as_str())
        {
            return Err("Worker command shadow differs from its fixed initialized root".into());
        }
        let private_state_descriptor = self
            .shadow_store
            .clone_command_store_capability()
            .map_err(|error| error.to_string())?;
        let execution_root_descriptor = shadow
            .clone_command_root_capability(&self.grant)
            .map_err(|error| error.to_string())?;
        Ok(SessionValidatedWorkerExecutionRoot {
            command_effect_authority: authority.clone(),
            private_state_root: self.shadow_store.root().to_path_buf(),
            private_state_descriptor,
            execution_root: shadow.root().to_path_buf(),
            execution_root_descriptor,
        })
    }

    fn expected_input_snapshot(
        &self,
        request: &RunnerRequest,
    ) -> Result<Option<Digest>, RunnerServiceError> {
        match request {
            RunnerRequest::WorkerCaptureLive { .. } => {
                Ok(Some(self.expected_base_snapshot.clone()))
            }
            RunnerRequest::WorkerCancel | RunnerRequest::Shutdown => Ok(None),
            RunnerRequest::WorkerCreateShadow { base_snapshot } => Ok(Some(base_snapshot.clone())),
            RunnerRequest::WorkerReadFile { .. }
            | RunnerRequest::WorkerSearchLiteral { .. }
            | RunnerRequest::WorkerCreateFile { .. }
            | RunnerRequest::WorkerReplaceFile { .. }
            | RunnerRequest::WorkerDeleteFile { .. }
            | RunnerRequest::WorkerRunCommand { .. } => self
                .current_shadow_snapshot
                .clone()
                .map(Some)
                .ok_or(RunnerServiceError::EffectContextMismatch),
            RunnerRequest::WorkerStageChanges { change_set, .. } => {
                Ok(Some(change_set.base_snapshot.clone()))
            }
            RunnerRequest::WorkerReconcileFile { .. }
            | RunnerRequest::WorkerPrepareStage { .. }
            | RunnerRequest::WorkerReconcileStage { .. } => {
                Ok(self.current_shadow_snapshot.clone())
            }
            RunnerRequest::InitializeSession { .. }
            | RunnerRequest::FinalVerifierCapture { .. }
            | RunnerRequest::FinalVerifierRunCommand { .. }
            | RunnerRequest::LiveStateVerifierCapture { .. }
            | RunnerRequest::ApplierRecoverPending
            | RunnerRequest::ApplierReconcileStageBundle { .. }
            | RunnerRequest::ApplierApplyBundle { .. }
            | RunnerRequest::ApplierReconcile { .. }
            | RunnerRequest::ApplierRollback { .. }
            | RunnerRequest::ApplierCaptureLive { .. } => Err(RunnerServiceError::RoleConfusion),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "closed worker dispatch keeps role authority auditable"
    )]
    fn dispatch(
        &mut self,
        request: RunnerRequest,
        effect_input: Option<&Digest>,
        command_effect_authority: Option<&CommandEffectAuthorityV1>,
        runner_nonce: &Digest,
        accepted_request_count: u64,
        command_effects_admitted: u64,
    ) -> (RunnerResponse, bool) {
        let fallback_input = self
            .current_shadow_snapshot
            .clone()
            .unwrap_or_else(|| self.expected_base_snapshot.clone());
        let effect_input = effect_input.unwrap_or(&fallback_input);
        match request {
            RunnerRequest::WorkerCaptureLive { created_at_unix_ms } => {
                match self.workspace.capture(&self.grant, created_at_unix_ms) {
                    Ok(manifest)
                        if manifest.snapshot().snapshot_id != self.expected_base_snapshot =>
                    {
                        (
                            RunnerResponse::failed_before_effect(
                                "base_snapshot_mismatch",
                                "descriptor-captured live manifest differs from the initialized sprint base",
                            ),
                            false,
                        )
                    }
                    Ok(manifest) => match WireWorkspaceCapture::from_native(&manifest) {
                        Ok(capture) => {
                            self.captured_base = Some(manifest);
                            (RunnerResponse::WorkspaceCaptured { capture }, false)
                        }
                        Err(error) => (wire_failure(error), false),
                    },
                    Err(error) => (workspace_failure(error), false),
                }
            }
            RunnerRequest::WorkerCreateShadow { base_snapshot } => {
                if self.shadow.is_some() {
                    return (
                        RunnerResponse::failed_before_effect(
                            "shadow_already_created",
                            "the fixed worker shadow can be created only once",
                        ),
                        false,
                    );
                }
                let Some(base) = self.captured_base.as_ref() else {
                    return (
                        RunnerResponse::failed_before_effect(
                            "base_capture_required",
                            "capture the live base before creating the shadow",
                        ),
                        false,
                    );
                };
                if base.snapshot().snapshot_id != base_snapshot {
                    return (
                        RunnerResponse::failed_before_effect(
                            "base_snapshot_mismatch",
                            "requested shadow base differs from the latest descriptor capture",
                        ),
                        false,
                    );
                }
                match self.workspace.create_shadow(
                    &self.grant,
                    base,
                    &self.shadow_store,
                    &self.shadow_leaf,
                ) {
                    Ok(shadow) => {
                        let limits = FileToolLimits::new(
                            1_048_576_u64,
                            1_048_576_u64,
                            MAX_WIRE_SEARCH_MATCHES,
                        );
                        match limits.and_then(|limits| {
                            ShadowFileTools::acquire_capability(
                                &self.grant,
                                &self.policy,
                                &shadow,
                                limits,
                            )
                        }) {
                            Ok(tools) => {
                                self.current_shadow_snapshot = Some(base_snapshot.clone());
                                self.shadow = Some(shadow);
                                self.tools = Some(tools);
                                (RunnerResponse::ShadowCreated { base_snapshot }, false)
                            }
                            Err(error) => (
                                RunnerResponse::failed_requiring_reconciliation(
                                    "shadow_creation_requires_reconciliation",
                                    WireReconciliationReference::SessionPrivateState {
                                        state_id: self.shadow_leaf.clone(),
                                    },
                                    error,
                                ),
                                false,
                            ),
                        }
                    }
                    Err(error) => (
                        RunnerResponse::failed_requiring_reconciliation(
                            "shadow_creation_requires_reconciliation",
                            WireReconciliationReference::SessionPrivateState {
                                state_id: self.shadow_leaf.clone(),
                            },
                            error,
                        ),
                        false,
                    ),
                }
            }
            RunnerRequest::WorkerReadFile { path, max_bytes } => {
                if let Err(response) = self.prove_shadow_input(effect_input) {
                    return (*response, false);
                }
                let Some(tools) = self.tools.as_ref() else {
                    return (shadow_required(), false);
                };
                match tools.read_regular_file(&self.grant, &self.policy, &path, max_bytes) {
                    Ok(result) => {
                        if let Err(response) = self.prove_shadow_input(effect_input) {
                            return (*response, false);
                        }
                        match RunnerResponse::file_read(result) {
                            Ok(response) => (response, false),
                            Err(error) => (wire_failure(error), false),
                        }
                    }
                    Err(error) => (file_failure(error), false),
                }
            }
            RunnerRequest::WorkerSearchLiteral {
                path,
                needle,
                max_bytes,
                max_matches,
            } => {
                if let Err(response) = self.prove_shadow_input(effect_input) {
                    return (*response, false);
                }
                let Some(tools) = self.tools.as_ref() else {
                    return (shadow_required(), false);
                };
                match tools.search_literal(
                    &self.grant,
                    &self.policy,
                    &path,
                    &needle,
                    max_bytes,
                    max_matches,
                ) {
                    Ok(result) => {
                        if let Err(response) = self.prove_shadow_input(effect_input) {
                            return (*response, false);
                        }
                        match RunnerResponse::literal_search(result) {
                            Ok(response) => (response, false),
                            Err(error) => (wire_failure(error), false),
                        }
                    }
                    Err(error) => (file_failure(error), false),
                }
            }
            RunnerRequest::WorkerCreateFile { path, contents } => {
                let before = match self.prove_shadow_input(effect_input) {
                    Ok(manifest) => manifest,
                    Err(response) => return (*response, false),
                };
                if before.entry(Path::new(&path)).is_some() {
                    return (
                        RunnerResponse::failed_before_effect(
                            "mutation_precondition_mismatch",
                            "create target exists in the descriptor-captured input manifest",
                        ),
                        false,
                    );
                }
                let Some(tools) = self.tools.as_ref() else {
                    return (shadow_required(), false);
                };
                let expected_result = Digest::sha256(&contents);
                match tools.create_regular_file(&self.grant, &self.policy, &path, &contents) {
                    Ok(result) if result.previous_digest.is_none() => {
                        let mut expected_entries = before.entries().clone();
                        expected_entries.insert(
                            PathBuf::from(&path),
                            ManifestEntry::from_stored_parts(
                                expected_result.clone(),
                                u64::try_from(contents.len()).unwrap_or(u64::MAX),
                                0o600,
                            ),
                        );
                        (
                            self.finalize_mutation(
                                result,
                                effect_input,
                                Some(&expected_result),
                                &expected_entries,
                            ),
                            false,
                        )
                    }
                    Ok(result) => (
                        self.mutation_reconciliation(
                            &result.path,
                            "create receipt unexpectedly reported a prior endpoint",
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.mark_shadow_uncertain(&error);
                        (file_failure(error), false)
                    }
                }
            }
            RunnerRequest::WorkerReplaceFile {
                path,
                expected_digest,
                contents,
            } => {
                let before = match self.prove_shadow_input(effect_input) {
                    Ok(manifest) => manifest,
                    Err(response) => return (*response, false),
                };
                if before.entry(Path::new(&path)).map(ManifestEntry::digest)
                    != Some(&expected_digest)
                {
                    return (
                        RunnerResponse::failed_before_effect(
                            "mutation_precondition_mismatch",
                            "replace target differs from the descriptor-captured input manifest",
                        ),
                        false,
                    );
                }
                let Some(tools) = self.tools.as_ref() else {
                    return (shadow_required(), false);
                };
                let expected_result = Digest::sha256(&contents);
                match tools.replace_regular_file(
                    &self.grant,
                    &self.policy,
                    &path,
                    &expected_digest,
                    &contents,
                ) {
                    Ok(result) if result.previous_digest.as_ref() == Some(&expected_digest) => {
                        let Some(previous) = before.entry(Path::new(&path)) else {
                            return (
                                self.mutation_reconciliation(
                                    &result.path,
                                    "replace succeeded without a captured prior endpoint",
                                ),
                                false,
                            );
                        };
                        let mut expected_entries = before.entries().clone();
                        expected_entries.insert(
                            PathBuf::from(&path),
                            ManifestEntry::from_stored_parts(
                                expected_result.clone(),
                                u64::try_from(contents.len()).unwrap_or(u64::MAX),
                                previous.mode(),
                            ),
                        );
                        (
                            self.finalize_mutation(
                                result,
                                effect_input,
                                Some(&expected_result),
                                &expected_entries,
                            ),
                            false,
                        )
                    }
                    Ok(result) => (
                        self.mutation_reconciliation(
                            &result.path,
                            "replace receipt did not bind the expected prior endpoint",
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.mark_shadow_uncertain(&error);
                        (file_failure(error), false)
                    }
                }
            }
            RunnerRequest::WorkerDeleteFile {
                path,
                expected_digest,
            } => {
                let before = match self.prove_shadow_input(effect_input) {
                    Ok(manifest) => manifest,
                    Err(response) => return (*response, false),
                };
                if before.entry(Path::new(&path)).map(ManifestEntry::digest)
                    != Some(&expected_digest)
                {
                    return (
                        RunnerResponse::failed_before_effect(
                            "mutation_precondition_mismatch",
                            "delete target differs from the descriptor-captured input manifest",
                        ),
                        false,
                    );
                }
                let Some(tools) = self.tools.as_ref() else {
                    return (shadow_required(), false);
                };
                match tools.delete_regular_file(&self.grant, &self.policy, &path, &expected_digest)
                {
                    Ok(result)
                        if result.previous_digest.as_ref() == Some(&expected_digest)
                            && result.result_digest.is_none() =>
                    {
                        let mut expected_entries = before.entries().clone();
                        expected_entries.remove(Path::new(&path));
                        (
                            self.finalize_mutation(result, effect_input, None, &expected_entries),
                            false,
                        )
                    }
                    Ok(result) => (
                        self.mutation_reconciliation(
                            &result.path,
                            "delete receipt did not bind the expected endpoint",
                        ),
                        false,
                    ),
                    Err(error) => {
                        self.mark_shadow_uncertain(&error);
                        (file_failure(error), false)
                    }
                }
            }
            RunnerRequest::WorkerReconcileFile {
                path,
                expected,
                max_bytes,
            } => {
                let manifest = match self.capture_shadow() {
                    Ok(manifest) => manifest,
                    Err(error) => return (workspace_failure(error), false),
                };
                let actual = manifest
                    .entry(Path::new(&path))
                    .map(|entry| entry.digest().clone());
                let expected_matches = match &expected {
                    crate::wire::WireFileExpectation::Absent => actual.is_none(),
                    crate::wire::WireFileExpectation::Present { digest } => {
                        actual.as_ref() == Some(digest)
                    }
                };
                if actual.is_some() {
                    let Some(tools) = self.tools.as_ref() else {
                        return (shadow_required(), false);
                    };
                    if let Err(error) =
                        tools.read_regular_file(&self.grant, &self.policy, &path, max_bytes)
                    {
                        return (file_failure(error), false);
                    }
                }
                let confirmed = match self.capture_shadow() {
                    Ok(confirmed) => confirmed,
                    Err(error) => return (workspace_failure(error), false),
                };
                if confirmed.snapshot().snapshot_id != manifest.snapshot().snapshot_id {
                    self.current_shadow_snapshot = None;
                    return (
                        RunnerResponse::failed_before_effect(
                            "file_reconciliation_changed",
                            "shadow changed during read-only file reconciliation",
                        ),
                        false,
                    );
                }
                self.current_shadow_snapshot = Some(confirmed.snapshot().snapshot_id.clone());
                (
                    RunnerResponse::FileReconciled {
                        path,
                        expected_matches,
                        actual_digest: actual,
                    },
                    false,
                )
            }
            RunnerRequest::WorkerPrepareStage {
                change_set_id,
                created_at_unix_ms,
            } => {
                let Some(expected_result_snapshot) = self.current_shadow_snapshot.clone() else {
                    return (
                        RunnerResponse::failed_before_effect(
                            "stage_shadow_snapshot_unknown",
                            "reconcile the fixed shadow before preparing an integration effect",
                        ),
                        false,
                    );
                };
                let Some(shadow) = self.shadow.as_mut() else {
                    return (shadow_required(), false);
                };
                match shadow.stage_changes_or_verified_noop(
                    &self.grant,
                    change_set_id,
                    created_at_unix_ms,
                ) {
                    Ok(staged)
                        if staged.change_set().base_snapshot == self.expected_base_snapshot
                            && staged.change_set().result_snapshot == expected_result_snapshot =>
                    {
                        match CapabilityStageBundleStore::preview(&staged) {
                            Ok(expected_bundle) => match RunnerResponse::stage_prepared(
                                staged.change_set().clone(),
                                expected_bundle,
                            ) {
                                Ok(response) => (response, false),
                                Err(error) => (wire_failure(error), false),
                            },
                            Err(error) => (stage_failure(error), false),
                        }
                    }
                    Ok(_) => (
                        RunnerResponse::failed_before_effect(
                            "stage_preparation_snapshot_mismatch",
                            "descriptor-staged endpoints differ from the fixed shadow's exact known base/result snapshots",
                        ),
                        false,
                    ),
                    Err(error) => (workspace_failure(error), false),
                }
            }
            RunnerRequest::WorkerStageChanges {
                change_set,
                expected_bundle,
            } => {
                if *effect_input != change_set.base_snapshot {
                    return (
                        RunnerResponse::failed_before_effect(
                            "stage_base_snapshot_mismatch",
                            "integration effect input differs from the exact requested change-set base",
                        ),
                        false,
                    );
                }
                if self.current_shadow_snapshot.as_ref() != Some(&change_set.result_snapshot) {
                    return (
                        RunnerResponse::failed_before_effect(
                            "stage_result_snapshot_mismatch",
                            "fixed shadow's exact known snapshot differs from the requested change-set result",
                        ),
                        false,
                    );
                }
                let Some(shadow) = self.shadow.as_mut() else {
                    return (shadow_required(), false);
                };
                let created_at_unix_ms = match observed_at_unix_ms() {
                    Ok(timestamp) => timestamp,
                    Err(error) => return (workspace_failure(error), false),
                };
                let staged = match shadow.stage_changes_or_verified_noop(
                    &self.grant,
                    change_set.change_set_id.clone(),
                    created_at_unix_ms,
                ) {
                    Ok(staged) => staged,
                    Err(error) => return (workspace_failure(error), false),
                };
                if staged.change_set() != change_set.as_ref() {
                    self.current_shadow_snapshot =
                        Some(staged.change_set().result_snapshot.clone());
                    return (
                        RunnerResponse::failed_before_effect(
                            "stage_change_set_mismatch",
                            "descriptor-recomputed change set differs from the exact durably authorized contract",
                        ),
                        false,
                    );
                }
                let preview = match CapabilityStageBundleStore::preview(&staged) {
                    Ok(preview) => preview,
                    Err(error) => return (stage_failure(error), false),
                };
                if preview != expected_bundle {
                    return (
                        RunnerResponse::failed_before_effect(
                            "stage_bundle_preview_mismatch",
                            "canonical descriptor-recomputed bundle differs from the exact durably authorized reference",
                        ),
                        false,
                    );
                }
                match self.bundle_store.persist(&staged) {
                    Ok(bundle) if bundle == expected_bundle => match self.capture_shadow() {
                        Ok(manifest)
                            if manifest.snapshot().snapshot_id == change_set.result_snapshot =>
                        {
                            (RunnerResponse::StageBundlePersisted { bundle }, false)
                        }
                        Ok(_) | Err(_) => {
                            self.current_shadow_snapshot = None;
                            (
                                RunnerResponse::failed_requiring_reconciliation(
                                    "stage_shadow_changed_after_publication",
                                    WireReconciliationReference::StageBundle {
                                        bundle: expected_bundle,
                                    },
                                    "shadow changed or became unprovable after immutable stage publication",
                                ),
                                false,
                            )
                        }
                    },
                    Ok(_) => (
                        RunnerResponse::failed_requiring_reconciliation(
                            "stage_published_reference_mismatch",
                            WireReconciliationReference::StageBundle {
                                bundle: expected_bundle,
                            },
                            "stage publication returned a reference other than the exact authorized preview",
                        ),
                        false,
                    ),
                    Err(error) => (stage_failure(error), false),
                }
            }
            RunnerRequest::WorkerReconcileStage { expected_bundle } => {
                match self.bundle_store.reconcile(&expected_bundle) {
                    Ok(bundle) if bundle == expected_bundle => {
                        (RunnerResponse::StageBundleReconciled { bundle }, false)
                    }
                    Ok(_) => (
                        RunnerResponse::failed_before_effect(
                            "stage_reconciliation_mismatch",
                            "read-only stage reconciliation returned a different bundle reference",
                        ),
                        false,
                    ),
                    Err(error) => (stage_failure(error), false),
                }
            }
            RunnerRequest::WorkerRunCommand { .. } => {
                let response = if command_effect_authority
                    .as_ref()
                    .is_some_and(|authority| authority.role() == RunnerRole::Worker)
                {
                    RunnerResponse::failed_before_effect(
                        "command_containment_unavailable",
                        "command execution remains fail-closed until the platform containment backend passes active probes",
                    )
                } else {
                    RunnerResponse::failed_before_effect(
                        "command_effect_authority_missing",
                        "the complete role-exact command-effect authority was not retained",
                    )
                };
                (response, false)
            }
            RunnerRequest::WorkerCancel => {
                let acknowledgement = ShutdownPreparedAcknowledgement::new(
                    &self.session_id,
                    runner_nonce.clone(),
                    RunnerRole::Worker,
                    accepted_request_count,
                    command_effects_admitted,
                    self.shadow.is_some(),
                );
                (
                    RunnerResponse::CancellationPrepared { acknowledgement },
                    true,
                )
            }
            RunnerRequest::Shutdown => {
                let acknowledgement = ShutdownPreparedAcknowledgement::new(
                    &self.session_id,
                    runner_nonce.clone(),
                    RunnerRole::Worker,
                    accepted_request_count,
                    command_effects_admitted,
                    self.shadow.is_some(),
                );
                (RunnerResponse::ShutdownPrepared { acknowledgement }, true)
            }
            _ => (
                RunnerResponse::failed_before_effect(
                    "runner_role_confusion",
                    "request does not belong to the immutable worker role",
                ),
                false,
            ),
        }
    }

    fn capture_shadow(&self) -> Result<WorkspaceManifest, CapabilityWorkspaceError> {
        let shadow = self.shadow.as_ref().ok_or_else(|| {
            CapabilityWorkspaceError::Destination(
                "fixed private shadow has not been created".into(),
            )
        })?;
        shadow.capture(&self.grant, observed_at_unix_ms()?)
    }

    fn prove_shadow_input(
        &mut self,
        expected: &Digest,
    ) -> Result<WorkspaceManifest, Box<RunnerResponse>> {
        let manifest = self.capture_shadow().map_err(workspace_failure)?;
        if manifest.snapshot().snapshot_id != *expected {
            self.current_shadow_snapshot = None;
            return Err(Box::new(RunnerResponse::failed_before_effect(
                "shadow_input_snapshot_mismatch",
                "complete descriptor-captured shadow differs from the durable effect input snapshot",
            )));
        }
        self.current_shadow_snapshot = Some(expected.clone());
        Ok(manifest)
    }

    fn finalize_mutation(
        &mut self,
        result: crate::FileMutationReceipt,
        input_snapshot: &Digest,
        expected_result: Option<&Digest>,
        expected_entries: &BTreeMap<PathBuf, ManifestEntry>,
    ) -> RunnerResponse {
        if result.result_digest.as_ref() != expected_result {
            return self.mutation_reconciliation(
                &result.path,
                "mutation receipt differs from requested result endpoint",
            );
        }
        let manifest = match self.capture_shadow() {
            Ok(manifest) => manifest,
            Err(error) => {
                return self.mutation_reconciliation(
                    &result.path,
                    &format!("cannot recapture complete shadow after mutation: {error}"),
                );
            }
        };
        let actual = manifest.entry(&result.path).map(ManifestEntry::digest);
        if actual != expected_result
            || manifest.entries() != expected_entries
            || manifest.snapshot().snapshot_id == *input_snapshot
        {
            return self.mutation_reconciliation(
                &result.path,
                "post-mutation complete manifest does not prove the requested endpoint change",
            );
        }
        let result_snapshot = manifest.snapshot().snapshot_id.clone();
        self.current_shadow_snapshot = Some(result_snapshot.clone());
        RunnerResponse::mutation(result, input_snapshot.clone(), result_snapshot)
            .unwrap_or_else(wire_failure)
    }

    fn mutation_reconciliation(&mut self, path: &Path, message: &str) -> RunnerResponse {
        self.current_shadow_snapshot = None;
        let reconciliation = path.to_str().map_or_else(
            || WireReconciliationReference::SessionPrivateState {
                state_id: self.shadow_leaf.clone(),
            },
            |path| WireReconciliationReference::File {
                path: path.to_owned(),
            },
        );
        RunnerResponse::failed_requiring_reconciliation(
            "shadow_mutation_requires_reconciliation",
            reconciliation,
            message,
        )
    }

    fn mark_shadow_uncertain(&mut self, error: &FileToolError) {
        if matches!(error, FileToolError::EffectAppliedButUnverified { .. }) {
            self.current_shadow_snapshot = None;
        }
    }
}

