//! Dormant role-sealed publication of one exact aggregate application bundle.
//!
//! The core composition module is deliberately pure and non-authorizing. This
//! runner boundary reopens every exact source bundle, derives result-material
//! metadata from those reopened bytes, reruns the pure algorithm, and publishes
//! only the resulting canonical aggregate bundle. Its journal is artifact
//! custody evidence only: it is not a durable core composition receipt and it
//! grants no application, rollback, completion, or service-routing authority.
//!
//! `Staged` means that source readback, pure derivation, aggregate bytes, and
//! the exact content-addressed aggregate reference are durably bound before the
//! first publication syscall. It intentionally does not claim that the bundle
//! is absent or present: after a crash, exact idempotent `persist` plus full
//! reopen resolves either physical state without searching for an artifact.

#![allow(dead_code)] // Activated only after a current additive core permit exists.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OsMetadataExt};
use cap_std::fs::Permissions;
use cap_std::fs::{
    Dir, DirBuilder, DirBuilderExt, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt,
};
use grok_build_core::{
    ApplicationArtifactCompositionReceiptV2, CompositionAggregateBlobReadbackV2,
    CompositionAggregateCreateModeReadbackV2, CompositionConflict, CompositionResultMaterialKindV2,
    CompositionResultMaterialV2, Digest, FileOperation, MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2,
    MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2,
    MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2,
    NonAuthorizingApplicationCompositionAggregateReadbackV2,
    NonAuthorizingApplicationCompositionPlanV2,
    NonAuthorizingApplicationCompositionPublicationClaimV2,
    NonAuthorizingApplicationCompositionPublicationClosureV2,
    NonAuthorizingApplicationCompositionSourceReadbackV2,
    NonAuthorizingApplicationCompositionSourceV2, TaskIntegrationArtifactReference,
    derive_non_authorizing_application_composition_v2,
};
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::{Deserialize, Serialize};

use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::{CapabilityStageBundleStore, StageBundleError, StageBundleReference, StagedChangeSet};

const JOURNAL_FORMAT_VERSION: u32 = 1;
const JOURNAL_PREFIX: &str = "application-composition-journal-v2-";
const LOCK_FILE: &str = "writer.lock";
const RECORD_PREFIX: &str = "record-";
const RECORD_SUFFIX: &str = ".json";
const RECORD_TEMP_SUFFIX: &str = ".working";
const MAX_JOURNAL_RECORDS: u64 = 3;
const MAX_JOURNAL_RECORD_BYTES: u64 = 256 * 1024;
const JOURNAL_ID_DOMAIN: &[u8] = b"grok-build/application-composition-journal-id/v2\0";
const JOURNAL_RECORD_DIGEST_DOMAIN: &[u8] =
    b"grok-build/application-composition-journal-record/v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionPublicationFaultPointV2 {
    JournalDirectoryCreate,
    JournalDirectoryMode,
    JournalDirectorySync,
    JournalNamespaceSync,
    WriterLockCreate,
    WriterLockMode,
    WriterLockSync,
    WriterLockNamespaceSync,
    RecordTemporaryCreate(u64),
    RecordTemporaryMode(u64),
    RecordTemporaryWrite(u64),
    RecordTemporarySync(u64),
    RecordRename(u64),
    RecordDirectorySync(u64),
    RecordCommittedReadback(u64),
}

#[derive(Clone)]
struct CompositionPublicationFaultInjectorV2 {
    armed: Option<CompositionPublicationFaultPointV2>,
    fired: Rc<Cell<bool>>,
}

impl CompositionPublicationFaultInjectorV2 {
    fn none() -> Self {
        Self {
            armed: None,
            fired: Rc::new(Cell::new(false)),
        }
    }

    #[cfg(test)]
    fn one_shot(point: CompositionPublicationFaultPointV2) -> Self {
        Self {
            armed: Some(point),
            fired: Rc::new(Cell::new(false)),
        }
    }

    fn inject(&self, point: CompositionPublicationFaultPointV2) -> Result<(), String> {
        if self.armed == Some(point) && !self.fired.replace(true) {
            return Err(format!(
                "injected composition publication fault at {point:?}"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ComposerRoleSealKindV2 {
    ApplicationComposer,
    #[cfg(test)]
    CrossedWorker,
}

/// Move-only custody required to enter the publication effect boundary.
///
/// There is intentionally no production constructor while coordinator/service
/// routing and the current additive core composition permit remain absent. The
/// private test constructor exercises the boundary without exporting a way for
/// application or integration-test callers to manufacture publication power.
struct RoleSealedApplicationComposerStateV2 {
    role: ComposerRoleSealKindV2,
    claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
    publication_claim_digest: Digest,
    journal_id: Digest,
    store: CapabilityStageBundleStore,
    journal_root: Dir,
    private_state_root: PathBuf,
    faults: CompositionPublicationFaultInjectorV2,
    _move_only_session: PhantomData<Rc<()>>,
}

/// Move-only capability for a first publication attempt. It can never resume
/// a journal that already contains durable intent.
struct RoleSealedFreshApplicationComposerV2 {
    state: RoleSealedApplicationComposerStateV2,
}

/// Move-only capability for restart reconciliation. It requires the exact
/// durable `Intended` record and can never initiate a fresh publication.
struct RoleSealedApplicationCompositionReconcilerV2 {
    state: RoleSealedApplicationComposerStateV2,
}

impl RoleSealedFreshApplicationComposerV2 {
    #[cfg(test)]
    fn acquire_for_test(
        private_state_root: &Path,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
        role: ComposerRoleSealKindV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        Self::acquire_with_faults_for_test(
            private_state_root,
            claim,
            role,
            CompositionPublicationFaultInjectorV2::none(),
        )
    }

    #[cfg(test)]
    fn acquire_with_fault_for_test(
        private_state_root: &Path,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
        role: ComposerRoleSealKindV2,
        fault: CompositionPublicationFaultPointV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        Self::acquire_with_faults_for_test(
            private_state_root,
            claim,
            role,
            CompositionPublicationFaultInjectorV2::one_shot(fault),
        )
    }

    #[cfg(test)]
    fn acquire_with_faults_for_test(
        private_state_root: &Path,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
        role: ComposerRoleSealKindV2,
        faults: CompositionPublicationFaultInjectorV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        Ok(Self {
            state: RoleSealedApplicationComposerStateV2::acquire_for_test(
                private_state_root,
                claim,
                role,
                faults,
            )?,
        })
    }

    fn publish_fresh(
        self,
    ) -> Result<AggregateCompositionPublicationObservationV2, ApplicationCompositionPublisherError>
    {
        self.state.execute(
            CompositionPublicationEntryV2::Fresh,
            CompositionPublicationTestCut::None,
        )
    }

    #[cfg(test)]
    fn publish_fresh_with_cut(
        self,
        cut: CompositionPublicationTestCut,
    ) -> Result<AggregateCompositionPublicationObservationV2, ApplicationCompositionPublisherError>
    {
        self.state
            .execute(CompositionPublicationEntryV2::Fresh, cut)
    }
}

impl RoleSealedApplicationCompositionReconcilerV2 {
    #[cfg(test)]
    fn acquire_for_test(
        private_state_root: &Path,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
        role: ComposerRoleSealKindV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        Ok(Self {
            state: RoleSealedApplicationComposerStateV2::acquire_for_test(
                private_state_root,
                claim,
                role,
                CompositionPublicationFaultInjectorV2::none(),
            )?,
        })
    }

    fn reconcile(
        self,
    ) -> Result<AggregateCompositionPublicationObservationV2, ApplicationCompositionPublisherError>
    {
        self.state.execute(
            CompositionPublicationEntryV2::Reconciliation,
            CompositionPublicationTestCut::None,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionPublicationEntryV2 {
    Fresh,
    Reconciliation,
}

impl RoleSealedApplicationComposerStateV2 {
    #[cfg(test)]
    fn acquire_for_test(
        private_state_root: &Path,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
        role: ComposerRoleSealKindV2,
        faults: CompositionPublicationFaultInjectorV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        let store = CapabilityStageBundleStore::open(private_state_root)
            .map_err(ApplicationCompositionPublisherError::StageBundle)?;
        let journal_root = store
            .clone_composer_store_capability()
            .map_err(ApplicationCompositionPublisherError::StageBundle)?;
        claim
            .validate_integrity()
            .map_err(ApplicationCompositionPublisherError::Composition)?;
        let publication_claim_digest = claim.publication_claim_digest.clone();
        let journal_id = compute_journal_id(&claim.publication_id, &publication_claim_digest)?;
        Ok(Self {
            role,
            claim,
            publication_claim_digest,
            journal_id,
            store,
            journal_root,
            private_state_root: private_state_root.to_path_buf(),
            faults,
            _move_only_session: PhantomData,
        })
    }

    fn validate_seal(&self) -> Result<(), ApplicationCompositionPublisherError> {
        if self.role != ComposerRoleSealKindV2::ApplicationComposer {
            return Err(authority_error(
                "publication custody belongs to a different runner role",
            ));
        }
        if self.store.root() != self.private_state_root {
            return Err(authority_error(
                "publication custody crossed its retained private-state root",
            ));
        }
        self.claim
            .validate_integrity()
            .map_err(ApplicationCompositionPublisherError::Composition)?;
        if self.claim.publication_claim_digest != self.publication_claim_digest
            || compute_journal_id(&self.claim.publication_id, &self.publication_claim_digest)?
                != self.journal_id
        {
            return Err(authority_error(
                "publication authority changed after the role seal was minted",
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the dormant effect boundary keeps entry-mode admission, source reopening, derivation, journal state, exact publication, and readback in one auditable order"
    )]
    fn execute(
        self,
        entry: CompositionPublicationEntryV2,
        cut: CompositionPublicationTestCut,
    ) -> Result<AggregateCompositionPublicationObservationV2, ApplicationCompositionPublisherError>
    {
        self.validate_seal()?;
        let opening_error = |reason| match entry {
            CompositionPublicationEntryV2::Fresh => {
                ApplicationCompositionPublisherError::FreshPublicationRejected { reason }
            }
            CompositionPublicationEntryV2::Reconciliation => {
                ApplicationCompositionPublisherError::ReconciliationRejected { reason }
            }
        };
        let journal_root = self
            .journal_root
            .try_clone()
            .map_err(|error| opening_error(format!("clone journal root capability: {error}")))?;
        let journal = match entry {
            CompositionPublicationEntryV2::Fresh => CompositionPublicationJournal::open_fresh(
                journal_root,
                self.journal_id.clone(),
                self.faults.clone(),
            ),
            CompositionPublicationEntryV2::Reconciliation => {
                CompositionPublicationJournal::open_existing(
                    journal_root,
                    self.journal_id.clone(),
                    self.faults.clone(),
                )
            }
        }
        .map_err(opening_error)?;
        let mut records = journal.read_records().map_err(opening_error)?;
        let expected_intended = expected_intended_record(
            &self.journal_id,
            &self.claim,
            &self.publication_claim_digest,
        )?;
        match entry {
            CompositionPublicationEntryV2::Fresh if !records.is_empty() => {
                return Err(
                    ApplicationCompositionPublisherError::FreshPublicationRejected {
                        reason: "fresh publication found an existing durable journal record".into(),
                    },
                );
            }
            CompositionPublicationEntryV2::Reconciliation if records.is_empty() => {
                return Err(
                    ApplicationCompositionPublisherError::ReconciliationRejected {
                        reason: "reconciliation requires exact durable publication intent".into(),
                    },
                );
            }
            CompositionPublicationEntryV2::Reconciliation
                if records.first() != Some(&expected_intended) =>
            {
                return Err(
                    ApplicationCompositionPublisherError::ReconciliationRejected {
                        reason: "durable publication intent crossed the sealed claim".into(),
                    },
                );
            }
            CompositionPublicationEntryV2::Fresh
            | CompositionPublicationEntryV2::Reconciliation => {}
        }
        if records.len() == usize::try_from(MAX_JOURNAL_RECORDS).expect("journal bound fits usize")
        {
            journal
                .ensure_no_exact_record_temporaries()
                .map_err(
                    |reason| ApplicationCompositionPublisherError::ReconciliationRejected {
                        reason,
                    },
                )?;
        } else {
            journal
                .cleanup_exact_record_temporaries()
                .map_err(|reason| match entry {
                    CompositionPublicationEntryV2::Fresh => {
                        ApplicationCompositionPublisherError::FreshPublicationRejected { reason }
                    }
                    CompositionPublicationEntryV2::Reconciliation => {
                        ApplicationCompositionPublisherError::ReconciliationRequired {
                            recovery: Box::new(CompositionPublicationReconciliationV2 {
                                journal_id: self.journal_id.clone(),
                                publication_id: self.claim.publication_id.clone(),
                                publication_claim_digest: self.publication_claim_digest.clone(),
                                expected_aggregate: None,
                                durable_stage: CompositionPublicationJournalStageV2::Intended,
                            }),
                            reason,
                        }
                    }
                })?;
        }
        let prepared = self.reopen_and_prepare_aggregate()?;
        let expected_records = expected_journal_records(
            &self.journal_id,
            &self.claim,
            &self.publication_claim_digest,
            &prepared,
        )?;
        let recovery =
            |stage, reason: String| ApplicationCompositionPublisherError::ReconciliationRequired {
                recovery: Box::new(CompositionPublicationReconciliationV2 {
                    journal_id: self.journal_id.clone(),
                    publication_id: self.claim.publication_id.clone(),
                    publication_claim_digest: self.publication_claim_digest.clone(),
                    expected_aggregate: Some(prepared.aggregate_reference.clone()),
                    durable_stage: stage,
                }),
                reason,
            };

        validate_record_prefix(&records, &expected_records).map_err(|reason| match entry {
            CompositionPublicationEntryV2::Fresh => {
                ApplicationCompositionPublisherError::FreshPublicationRejected { reason }
            }
            CompositionPublicationEntryV2::Reconciliation => {
                ApplicationCompositionPublisherError::ReconciliationRejected { reason }
            }
        })?;
        self.store
            .validate_composer_store_capability()
            .map_err(|error| recovery(stage_of_records(&records), error.to_string()))?;

        if entry == CompositionPublicationEntryV2::Fresh {
            journal
                .append(&expected_records[0])
                .map_err(|reason| recovery(CompositionPublicationJournalStageV2::None, reason))?;
            records.push(expected_records[0].clone());
            self.store
                .validate_composer_store_capability()
                .map_err(|error| {
                    recovery(
                        CompositionPublicationJournalStageV2::Intended,
                        error.to_string(),
                    )
                })?;
        }
        if cut == CompositionPublicationTestCut::AfterIntended {
            return Err(recovery(
                CompositionPublicationJournalStageV2::Intended,
                "injected crash after durable publication intent".into(),
            ));
        }

        if records.len() == 1 {
            journal.append(&expected_records[1]).map_err(|reason| {
                recovery(CompositionPublicationJournalStageV2::Intended, reason)
            })?;
            records.push(expected_records[1].clone());
            self.store
                .validate_composer_store_capability()
                .map_err(|error| {
                    recovery(
                        CompositionPublicationJournalStageV2::Staged,
                        error.to_string(),
                    )
                })?;
        }
        if cut == CompositionPublicationTestCut::AfterStaged {
            return Err(recovery(
                CompositionPublicationJournalStageV2::Staged,
                "injected crash after durable aggregate staging".into(),
            ));
        }

        if records.len() == 3 {
            let reopened = self
                .store
                .load(&prepared.aggregate_reference)
                .map_err(|error| {
                    recovery(
                        CompositionPublicationJournalStageV2::Published,
                        format!("published aggregate no longer reopens exactly: {error}"),
                    )
                })?;
            ensure_exact_aggregate_readback(&prepared, &self.claim, &reopened).map_err(
                |reason| recovery(CompositionPublicationJournalStageV2::Published, reason),
            )?;
            self.store
                .validate_composer_store_capability()
                .map_err(|error| {
                    recovery(
                        CompositionPublicationJournalStageV2::Published,
                        error.to_string(),
                    )
                })?;
            return prepared.observation(&self.claim, &self.journal_id, &records[2].record_digest);
        }

        let published = self.store.persist(&prepared.aggregate).map_err(|error| {
            recovery(
                CompositionPublicationJournalStageV2::Staged,
                format!("aggregate stage publication requires exact reconciliation: {error}"),
            )
        })?;
        if published != prepared.aggregate_reference {
            return Err(recovery(
                CompositionPublicationJournalStageV2::Staged,
                "aggregate publication returned a crossed bundle reference".into(),
            ));
        }
        let reopened = self.store.load(&published).map_err(|error| {
            recovery(
                CompositionPublicationJournalStageV2::Staged,
                format!("published aggregate cannot be reopened exactly: {error}"),
            )
        })?;
        ensure_exact_aggregate_readback(&prepared, &self.claim, &reopened)
            .map_err(|reason| recovery(CompositionPublicationJournalStageV2::Staged, reason))?;

        if cut == CompositionPublicationTestCut::AfterBundlePublished {
            return Err(recovery(
                CompositionPublicationJournalStageV2::Staged,
                "injected crash after aggregate publication and before journal closure".into(),
            ));
        }

        journal
            .append(&expected_records[2])
            .map_err(|reason| recovery(CompositionPublicationJournalStageV2::Staged, reason))?;
        self.store
            .validate_composer_store_capability()
            .map_err(|error| {
                recovery(
                    CompositionPublicationJournalStageV2::Published,
                    error.to_string(),
                )
            })?;
        prepared.observation(
            &self.claim,
            &self.journal_id,
            &expected_records[2].record_digest,
        )
    }

    fn reopen_and_prepare_aggregate(
        &self,
    ) -> Result<PreparedAggregateV2, ApplicationCompositionPublisherError> {
        let mut reopened_stages = Vec::with_capacity(self.claim.sources.len());
        let mut projected_sources = Vec::with_capacity(self.claim.sources.len());
        let mut cumulative_reopened_bytes = 0_u64;
        let mut cumulative_source_metadata_bytes = 0_usize;
        let mut cumulative_source_operations = 0_usize;
        for source in &self.claim.sources {
            let reference = StageBundleReference::try_from(&source.artifact).map_err(|error| {
                ApplicationCompositionPublisherError::SourceBundle {
                    ordinal: source.ordinal,
                    reason: error.to_string(),
                }
            })?;
            let staged = self.store.load(&reference).map_err(|error| {
                ApplicationCompositionPublisherError::SourceBundle {
                    ordinal: source.ordinal,
                    reason: error.to_string(),
                }
            })?;
            let observed_source_bytes = staged_blob_bytes(&staged)?;
            if observed_source_bytes != source.reopened_result_blob_bytes {
                return Err(ApplicationCompositionPublisherError::SourceBundle {
                    ordinal: source.ordinal,
                    reason: format!(
                        "reopened result bytes {observed_source_bytes} differ from claimed {}",
                        source.reopened_result_blob_bytes
                    ),
                });
            }
            cumulative_reopened_bytes = checked_cumulative_reopened_source_bytes(
                cumulative_reopened_bytes,
                observed_source_bytes,
            )?;
            let material = source_result_material(source.ordinal, &source.artifact, &staged)?;
            let projected = NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
                source.ordinal,
                source.task_id.clone(),
                source.attempt_id.clone(),
                source.task_done_proof_id.clone(),
                source.task_done_proof_digest.clone(),
                source.integration_receipt_id.clone(),
                source.integration_receipt_digest.clone(),
                staged.change_set().clone(),
                source.artifact.clone(),
                material,
            )
            .map_err(ApplicationCompositionPublisherError::Composition)?;
            validate_reopened_source_operation_count(
                source.ordinal,
                source.source_operation_count,
                &projected,
            )?;
            (
                cumulative_source_metadata_bytes,
                cumulative_source_operations,
            ) = checked_cumulative_reopened_source_metadata(
                cumulative_source_metadata_bytes,
                cumulative_source_operations,
                &projected,
            )?;
            reopened_stages.push(staged);
            projected_sources.push(projected);
        }

        let plan = derive_non_authorizing_application_composition_v2(
            &self.claim.inputs,
            &self.claim.base,
            &projected_sources,
        )
        .map_err(ApplicationCompositionPublisherError::Composition)?;
        let aggregate = assemble_aggregate(&plan, &projected_sources, &reopened_stages)?;
        let aggregate_reference = CapabilityStageBundleStore::preview(&aggregate)
            .map_err(ApplicationCompositionPublisherError::StageBundle)?;
        if aggregate_reference.change_set_id != plan.change_set.change_set_id
            || aggregate_reference.base_snapshot != plan.change_set.base_snapshot
            || aggregate_reference.result_snapshot != plan.change_set.result_snapshot
        {
            return Err(authority_error(
                "aggregate stage preview crossed the rederived composition plan",
            ));
        }
        let source_readback =
            NonAuthorizingApplicationCompositionSourceReadbackV2::try_new_non_authorizing(
                &self.claim,
                projected_sources,
            )
            .map_err(ApplicationCompositionPublisherError::Composition)?;
        let aggregate_readback = aggregate_readback(&self.claim, &aggregate_reference, &aggregate)?;
        Ok(PreparedAggregateV2 {
            plan,
            aggregate,
            aggregate_reference,
            source_readback,
            aggregate_readback,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompositionPublicationTestCut {
    None,
    AfterIntended,
    AfterStaged,
    AfterBundlePublished,
}

struct PreparedAggregateV2 {
    plan: NonAuthorizingApplicationCompositionPlanV2,
    aggregate: StagedChangeSet,
    aggregate_reference: StageBundleReference,
    source_readback: NonAuthorizingApplicationCompositionSourceReadbackV2,
    aggregate_readback: NonAuthorizingApplicationCompositionAggregateReadbackV2,
}

impl PreparedAggregateV2 {
    fn observation(
        &self,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
        journal_id: &Digest,
        journal_head_digest: &Digest,
    ) -> Result<AggregateCompositionPublicationObservationV2, ApplicationCompositionPublisherError>
    {
        let publication_closure =
            NonAuthorizingApplicationCompositionPublicationClosureV2::try_new_non_authorizing(
                claim,
                &self.aggregate_readback,
                journal_id.clone(),
                journal_head_digest.clone(),
            )
            .map_err(ApplicationCompositionPublisherError::Composition)?;
        let composition_receipt = ApplicationArtifactCompositionReceiptV2::try_new_non_authorizing(
            claim,
            &self.source_readback,
            &self.plan,
            &self.aggregate_readback,
            &publication_closure,
        )
        .map_err(ApplicationCompositionPublisherError::Composition)?;
        Ok(AggregateCompositionPublicationObservationV2 {
            publication_claim: claim.clone(),
            source_readback: self.source_readback.clone(),
            composition_plan: self.plan.clone(),
            aggregate_readback: self.aggregate_readback.clone(),
            publication_closure,
            composition_receipt,
        })
    }
}

/// Path-free runner observation carrying the exact non-authorizing core
/// contracts needed for future ledger admission.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AggregateCompositionPublicationObservationV2 {
    publication_claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
    source_readback: NonAuthorizingApplicationCompositionSourceReadbackV2,
    composition_plan: NonAuthorizingApplicationCompositionPlanV2,
    aggregate_readback: NonAuthorizingApplicationCompositionAggregateReadbackV2,
    publication_closure: NonAuthorizingApplicationCompositionPublicationClosureV2,
    composition_receipt: ApplicationArtifactCompositionReceiptV2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CompositionPublicationJournalStageV2 {
    None,
    Intended,
    Staged,
    Published,
}

/// Exact identities needed to reconcile without searching the private store.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompositionPublicationReconciliationV2 {
    journal_id: Digest,
    publication_id: String,
    publication_claim_digest: Digest,
    expected_aggregate: Option<StageBundleReference>,
    durable_stage: CompositionPublicationJournalStageV2,
}

#[derive(Debug)]
enum ApplicationCompositionPublisherError {
    Authority(String),
    FreshPublicationRejected {
        reason: String,
    },
    ReconciliationRejected {
        reason: String,
    },
    SourceBundle {
        ordinal: u32,
        reason: String,
    },
    Composition(CompositionConflict),
    StageBundle(StageBundleError),
    ReconciliationRequired {
        recovery: Box<CompositionPublicationReconciliationV2>,
        reason: String,
    },
}

impl Display for ApplicationCompositionPublisherError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(reason) => {
                write!(formatter, "composition authority rejected: {reason}")
            }
            Self::FreshPublicationRejected { reason } => {
                write!(
                    formatter,
                    "fresh composition publication rejected: {reason}"
                )
            }
            Self::ReconciliationRejected { reason } => {
                write!(formatter, "composition reconciliation rejected: {reason}")
            }
            Self::SourceBundle { ordinal, reason } => {
                write!(formatter, "composition source {ordinal} rejected: {reason}")
            }
            Self::Composition(error) => Display::fmt(error, formatter),
            Self::StageBundle(error) => Display::fmt(error, formatter),
            Self::ReconciliationRequired { recovery, reason } => write!(
                formatter,
                "composition publication {} at {:?} requires reconciliation: {reason}",
                recovery.publication_id, recovery.durable_stage
            ),
        }
    }
}

impl std::error::Error for ApplicationCompositionPublisherError {}

fn authority_error(reason: impl Into<String>) -> ApplicationCompositionPublisherError {
    ApplicationCompositionPublisherError::Authority(reason.into())
}

fn staged_blob_bytes(
    staged: &StagedChangeSet,
) -> Result<u64, ApplicationCompositionPublisherError> {
    staged.blobs().values().try_fold(0_u64, |total, bytes| {
        let length = u64::try_from(bytes.len())
            .map_err(|_| authority_error("source blob length cannot be represented"))?;
        total
            .checked_add(length)
            .ok_or_else(|| authority_error("cumulative reopened source bytes overflowed"))
    })
}

fn checked_cumulative_reopened_source_bytes(
    current: u64,
    additional: u64,
) -> Result<u64, ApplicationCompositionPublisherError> {
    let observed = current
        .checked_add(additional)
        .ok_or_else(|| authority_error("cumulative reopened source bytes overflowed"))?;
    if observed > MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 {
        return Err(authority_error(format!(
            "cumulative reopened source bytes {observed} exceed {MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2}"
        )));
    }
    Ok(observed)
}

fn checked_cumulative_reopened_source_metadata(
    current_metadata_bytes: usize,
    current_operations: usize,
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(usize, usize), ApplicationCompositionPublisherError> {
    let source_metadata_bytes = canonical_json(source, "reopened composition source")?.len();
    let observed_metadata_bytes = current_metadata_bytes
        .checked_add(source_metadata_bytes)
        .ok_or_else(|| authority_error("cumulative reopened source metadata bytes overflowed"))?;
    if observed_metadata_bytes > MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2 {
        return Err(authority_error(format!(
            "cumulative reopened source metadata bytes {observed_metadata_bytes} exceed {MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2}"
        )));
    }

    let observed_operations = current_operations
        .checked_add(source.change_set.operations.len())
        .ok_or_else(|| authority_error("cumulative reopened source operations overflowed"))?;
    if observed_operations > MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2 {
        return Err(authority_error(format!(
            "cumulative reopened source operations {observed_operations} exceed {MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2}"
        )));
    }
    Ok((observed_metadata_bytes, observed_operations))
}

fn validate_reopened_source_operation_count(
    ordinal: u32,
    claimed: u32,
    source: &NonAuthorizingApplicationCompositionSourceV2,
) -> Result<(), ApplicationCompositionPublisherError> {
    let claimed = usize::try_from(claimed)
        .map_err(|_| authority_error("claimed source operation count cannot be represented"))?;
    if source.change_set.operations.len() != claimed {
        return Err(ApplicationCompositionPublisherError::SourceBundle {
            ordinal,
            reason: format!(
                "reopened operation count {} differs from claimed {claimed}",
                source.change_set.operations.len()
            ),
        });
    }
    Ok(())
}

fn source_result_material(
    ordinal: u32,
    artifact: &TaskIntegrationArtifactReference,
    staged: &StagedChangeSet,
) -> Result<Vec<CompositionResultMaterialV2>, ApplicationCompositionPublisherError> {
    let mut material = Vec::new();
    for (index, operation) in staged.change_set().operations.iter().enumerate() {
        let (path, result_digest, operation_kind) = match operation {
            FileOperation::Create { path, result_hash } => {
                let mode = staged.create_mode(path).ok_or_else(|| {
                    ApplicationCompositionPublisherError::SourceBundle {
                        ordinal,
                        reason: "reopened Create has no exact normalized mode".into(),
                    }
                })?;
                (
                    path,
                    result_hash,
                    CompositionResultMaterialKindV2::Create { unix_mode: mode },
                )
            }
            FileOperation::Modify {
                path, result_hash, ..
            } => (path, result_hash, CompositionResultMaterialKindV2::Modify),
            FileOperation::Delete { .. } => continue,
        };
        let bytes = staged.blob(result_digest).ok_or_else(|| {
            ApplicationCompositionPublisherError::SourceBundle {
                ordinal,
                reason: format!("reopened result blob {result_digest} is absent"),
            }
        })?;
        if Digest::sha256(bytes) != *result_digest {
            return Err(ApplicationCompositionPublisherError::SourceBundle {
                ordinal,
                reason: format!("reopened result blob {result_digest} changed after load"),
            });
        }
        material.push(CompositionResultMaterialV2 {
            operation_index: u32::try_from(index).map_err(|_| {
                ApplicationCompositionPublisherError::SourceBundle {
                    ordinal,
                    reason: "source operation index cannot be represented".into(),
                }
            })?,
            path: path
                .to_str()
                .ok_or_else(|| ApplicationCompositionPublisherError::SourceBundle {
                    ordinal,
                    reason: "reopened source path is not portable UTF-8".into(),
                })?
                .to_owned(),
            result_digest: result_digest.clone(),
            byte_length: u64::try_from(bytes.len()).map_err(|_| {
                ApplicationCompositionPublisherError::SourceBundle {
                    ordinal,
                    reason: "source result length cannot be represented".into(),
                }
            })?,
            operation_kind,
            source_artifact_digest: artifact.artifact_digest.clone(),
        });
    }
    Ok(material)
}

fn assemble_aggregate(
    plan: &NonAuthorizingApplicationCompositionPlanV2,
    projected_sources: &[NonAuthorizingApplicationCompositionSourceV2],
    reopened_stages: &[StagedChangeSet],
) -> Result<StagedChangeSet, ApplicationCompositionPublisherError> {
    plan.validate_integrity()
        .map_err(ApplicationCompositionPublisherError::Composition)?;
    if projected_sources.len() != reopened_stages.len() {
        return Err(authority_error(
            "reopened source stages differ from projected source coverage",
        ));
    }
    let mut blobs: BTreeMap<Digest, Vec<u8>> = BTreeMap::new();
    let mut create_modes = BTreeMap::new();
    for material in &plan.result_material {
        let source_index = usize::try_from(material.source_ordinal)
            .map_err(|_| authority_error("aggregate source ordinal cannot be represented"))?;
        let source = projected_sources
            .get(source_index)
            .ok_or_else(|| authority_error("aggregate material names an absent source"))?;
        let staged = reopened_stages
            .get(source_index)
            .ok_or_else(|| authority_error("aggregate material source was not reopened"))?;
        if source.ordinal != material.source_ordinal
            || source.artifact.artifact_digest != material.source_artifact_digest
        {
            return Err(authority_error(
                "aggregate material crossed its source artifact identity",
            ));
        }
        let bytes = staged.blob(&material.result_digest).ok_or_else(|| {
            authority_error("aggregate result bytes are absent from the exact named source")
        })?;
        let byte_length = u64::try_from(bytes.len())
            .map_err(|_| authority_error("aggregate result length cannot be represented"))?;
        if byte_length != material.byte_length || Digest::sha256(bytes) != material.result_digest {
            return Err(authority_error(
                "aggregate result bytes differ in digest or length from the rederived plan",
            ));
        }
        if let Some(existing) = blobs.insert(material.result_digest.clone(), bytes.to_vec())
            && existing.as_slice() != bytes
        {
            return Err(authority_error(
                "equal aggregate result digests reopened with unequal bytes",
            ));
        }
        if let Some(mode) = material.create_mode {
            let prior = create_modes.insert(PathBuf::from(&material.path), mode);
            if prior.is_some() {
                return Err(authority_error("aggregate create-mode path is duplicated"));
            }
        }
    }
    StagedChangeSet::new_with_create_modes(plan.change_set.clone(), blobs, create_modes)
        .map_err(|error| authority_error(format!("aggregate staging failed: {error}")))
}

fn ensure_exact_aggregate_readback(
    prepared: &PreparedAggregateV2,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    reopened: &StagedChangeSet,
) -> Result<(), String> {
    if reopened != &prepared.aggregate {
        return Err(
            "reopened aggregate differs in operations, bytes, digests, lengths, or create modes"
                .into(),
        );
    }
    let observed = aggregate_readback(claim, &prepared.aggregate_reference, reopened)
        .map_err(|error| error.to_string())?;
    if observed != prepared.aggregate_readback {
        return Err("reopened aggregate readback differs".into());
    }
    Ok(())
}

fn aggregate_readback(
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    reference: &StageBundleReference,
    staged: &StagedChangeSet,
) -> Result<
    NonAuthorizingApplicationCompositionAggregateReadbackV2,
    ApplicationCompositionPublisherError,
> {
    let blobs = staged
        .blobs()
        .iter()
        .map(|(digest, bytes)| CompositionAggregateBlobReadbackV2 {
            digest: digest.clone(),
            byte_length: u64::try_from(bytes.len()).expect("usize fits u64"),
        })
        .collect();
    let mut create_modes = staged
        .change_set()
        .operations
        .iter()
        .filter_map(|operation| match operation {
            FileOperation::Create { path, .. } => Some((path, staged.create_mode(path))),
            FileOperation::Modify { .. } | FileOperation::Delete { .. } => None,
        })
        .map(|(path, mode)| {
            Ok(CompositionAggregateCreateModeReadbackV2 {
                path: path
                    .to_str()
                    .ok_or_else(|| authority_error("aggregate path is not portable UTF-8"))?
                    .to_owned(),
                unix_mode: mode
                    .ok_or_else(|| authority_error("aggregate Create has no normalized mode"))?,
            })
        })
        .collect::<Result<Vec<_>, ApplicationCompositionPublisherError>>()?;
    create_modes.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    let artifact = reference
        .to_core_integration_artifact()
        .map_err(ApplicationCompositionPublisherError::StageBundle)?;
    NonAuthorizingApplicationCompositionAggregateReadbackV2::try_new_non_authorizing(
        claim,
        artifact,
        staged.change_set().clone(),
        blobs,
        create_modes,
    )
    .map_err(ApplicationCompositionPublisherError::Composition)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum CompositionPublicationRecordDataV2 {
    Intended {
        publication_id: String,
        publication_claim_digest: Digest,
        source_set_digest: Digest,
        base_projection_digest: Digest,
    },
    /// The exact aggregate is prepared and durably named, and publication is
    /// now allowed; physical publication may or may not have happened.
    Staged {
        source_readback_digest: Digest,
        derivation_record_digest: Digest,
        expected_aggregate: StageBundleReference,
        aggregate_readback_digest: Digest,
    },
    Published {
        expected_aggregate: StageBundleReference,
        aggregate_readback_digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompositionPublicationRecordV2 {
    format_version: u32,
    generation: u64,
    journal_id: Digest,
    predecessor_digest: Option<Digest>,
    data: CompositionPublicationRecordDataV2,
    record_digest: Digest,
}

#[derive(Serialize)]
struct CompositionPublicationRecordPreimageV2<'a> {
    format_version: u32,
    generation: u64,
    journal_id: &'a Digest,
    predecessor_digest: Option<&'a Digest>,
    data: &'a CompositionPublicationRecordDataV2,
}

impl CompositionPublicationRecordV2 {
    fn new(
        generation: u64,
        journal_id: Digest,
        predecessor_digest: Option<Digest>,
        data: CompositionPublicationRecordDataV2,
    ) -> Result<Self, ApplicationCompositionPublisherError> {
        let preimage = CompositionPublicationRecordPreimageV2 {
            format_version: JOURNAL_FORMAT_VERSION,
            generation,
            journal_id: &journal_id,
            predecessor_digest: predecessor_digest.as_ref(),
            data: &data,
        };
        let record_digest = domain_digest(
            JOURNAL_RECORD_DIGEST_DOMAIN,
            &canonical_json(&preimage, "composition publication journal record")?,
        );
        Ok(Self {
            format_version: JOURNAL_FORMAT_VERSION,
            generation,
            journal_id,
            predecessor_digest,
            data,
            record_digest,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.format_version != JOURNAL_FORMAT_VERSION
            || self.generation == 0
            || self.generation > MAX_JOURNAL_RECORDS
        {
            return Err("composition publication journal version or generation differs".into());
        }
        let expected = Self::new(
            self.generation,
            self.journal_id.clone(),
            self.predecessor_digest.clone(),
            self.data.clone(),
        )
        .map_err(|error| error.to_string())?;
        if &expected != self {
            return Err("composition publication journal record digest differs".into());
        }
        Ok(())
    }
}

fn expected_intended_record(
    journal_id: &Digest,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    publication_claim_digest: &Digest,
) -> Result<CompositionPublicationRecordV2, ApplicationCompositionPublisherError> {
    CompositionPublicationRecordV2::new(
        1,
        journal_id.clone(),
        None,
        CompositionPublicationRecordDataV2::Intended {
            publication_id: claim.publication_id.clone(),
            publication_claim_digest: publication_claim_digest.clone(),
            source_set_digest: claim.inputs.source_set_digest.clone(),
            base_projection_digest: claim.base.projection_digest.clone(),
        },
    )
}

fn expected_journal_records(
    journal_id: &Digest,
    claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    publication_claim_digest: &Digest,
    prepared: &PreparedAggregateV2,
) -> Result<Vec<CompositionPublicationRecordV2>, ApplicationCompositionPublisherError> {
    let intended = expected_intended_record(journal_id, claim, publication_claim_digest)?;
    let staged = CompositionPublicationRecordV2::new(
        2,
        journal_id.clone(),
        Some(intended.record_digest.clone()),
        CompositionPublicationRecordDataV2::Staged {
            source_readback_digest: prepared.source_readback.source_readback_digest.clone(),
            derivation_record_digest: prepared.plan.derivation_record.record_digest.clone(),
            expected_aggregate: prepared.aggregate_reference.clone(),
            aggregate_readback_digest: prepared
                .aggregate_readback
                .aggregate_readback_digest
                .clone(),
        },
    )?;
    let published = CompositionPublicationRecordV2::new(
        3,
        journal_id.clone(),
        Some(staged.record_digest.clone()),
        CompositionPublicationRecordDataV2::Published {
            expected_aggregate: prepared.aggregate_reference.clone(),
            aggregate_readback_digest: prepared
                .aggregate_readback
                .aggregate_readback_digest
                .clone(),
        },
    )?;
    Ok(vec![intended, staged, published])
}

fn validate_record_prefix(
    observed: &[CompositionPublicationRecordV2],
    expected: &[CompositionPublicationRecordV2],
) -> Result<(), String> {
    if observed.len() > expected.len() || observed != &expected[..observed.len()] {
        return Err(
            "composition publication journal crossed its exact authority or aggregate".into(),
        );
    }
    Ok(())
}

fn stage_of_records(
    records: &[CompositionPublicationRecordV2],
) -> CompositionPublicationJournalStageV2 {
    match records.len() {
        0 => CompositionPublicationJournalStageV2::None,
        1 => CompositionPublicationJournalStageV2::Intended,
        2 => CompositionPublicationJournalStageV2::Staged,
        _ => CompositionPublicationJournalStageV2::Published,
    }
}

struct CompositionPublicationJournal {
    root: Dir,
    directory: Dir,
    directory_name: String,
    directory_identity: JournalObjectIdentity,
    journal_id: Digest,
    writer_lock: File,
    writer_lock_identity: JournalObjectIdentity,
    faults: CompositionPublicationFaultInjectorV2,
}

impl Drop for CompositionPublicationJournal {
    fn drop(&mut self) {
        // `flock` belongs to the open file description, which forked children may
        // retain. Explicitly unlock before closing the owner's descriptor.
        let _ = flock(&self.writer_lock, FlockOperation::Unlock);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct JournalObjectIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

impl CompositionPublicationJournal {
    fn open_fresh(
        root: Dir,
        journal_id: Digest,
        faults: CompositionPublicationFaultInjectorV2,
    ) -> Result<Self, String> {
        let directory_name = format!("{JOURNAL_PREFIX}{journal_id}");
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        faults.inject(CompositionPublicationFaultPointV2::JournalDirectoryCreate)?;
        let created = match root.create_dir_with(&directory_name, &builder) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(format!("create exact composition journal: {error}")),
        };
        let directory = root
            .open_dir_nofollow(&directory_name)
            .map_err(|error| format!("open exact composition journal: {error}"))?;
        if created {
            faults.inject(CompositionPublicationFaultPointV2::JournalDirectoryMode)?;
            directory
                .set_permissions(Path::new("."), Permissions::from_mode(0o700))
                .map_err(|error| format!("set composition journal mode: {error}"))?;
            faults.inject(CompositionPublicationFaultPointV2::JournalDirectorySync)?;
            sync_directory(&directory)
                .map_err(|error| format!("sync new composition journal: {error}"))?;
            faults.inject(CompositionPublicationFaultPointV2::JournalNamespaceSync)?;
            sync_directory(&root)
                .map_err(|error| format!("sync composition journal namespace: {error}"))?;
        }
        Self::finish_open(root, directory, directory_name, journal_id, faults, true)
    }

    fn open_existing(
        root: Dir,
        journal_id: Digest,
        faults: CompositionPublicationFaultInjectorV2,
    ) -> Result<Self, String> {
        let directory_name = format!("{JOURNAL_PREFIX}{journal_id}");
        let directory = root
            .open_dir_nofollow(&directory_name)
            .map_err(|error| format!("open existing composition journal: {error}"))?;
        Self::finish_open(root, directory, directory_name, journal_id, faults, false)
    }

    fn finish_open(
        root: Dir,
        directory: Dir,
        directory_name: String,
        journal_id: Digest,
        faults: CompositionPublicationFaultInjectorV2,
        allow_lock_creation: bool,
    ) -> Result<Self, String> {
        let directory_identity = validate_private_directory(&directory)?;
        let writer_lock = open_writer_lock(&directory, &faults, allow_lock_creation)?;
        flock(&writer_lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| format!("lock exact composition journal: {error}"))?;
        let writer_lock_identity = validate_named_writer_lock(&directory, &writer_lock)?;
        let journal = Self {
            root,
            directory,
            directory_name,
            directory_identity,
            journal_id,
            writer_lock,
            writer_lock_identity,
            faults,
        };
        journal.validate_named_directory()?;
        Ok(journal)
    }

    fn validate_named_directory(&self) -> Result<(), String> {
        if validate_private_directory(&self.directory)? != self.directory_identity {
            return Err("retained composition journal identity or mode changed".into());
        }
        let named = self
            .root
            .open_dir_nofollow(&self.directory_name)
            .map_err(|error| format!("reopen named composition journal: {error}"))?;
        if validate_private_directory(&named)? != self.directory_identity {
            return Err("named composition journal was replaced".into());
        }
        let current_lock_identity = validate_named_writer_lock(&self.directory, &self.writer_lock)?;
        if current_lock_identity != self.writer_lock_identity {
            return Err("named composition journal writer lock was replaced".into());
        }
        Ok(())
    }

    fn cleanup_exact_record_temporaries(&self) -> Result<(), String> {
        for generation in 1..=MAX_JOURNAL_RECORDS {
            let name = record_temp_name(generation);
            match self.directory.symlink_metadata(&name) {
                Ok(metadata) => {
                    validate_private_file_metadata(&metadata, MAX_JOURNAL_RECORD_BYTES)?;
                    self.directory
                        .remove_file(&name)
                        .map_err(|error| format!("remove exact journal temporary: {error}"))?;
                    sync_directory(&self.directory)
                        .map_err(|error| format!("sync journal temporary cleanup: {error}"))?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect exact journal temporary: {error}")),
            }
        }
        Ok(())
    }

    fn ensure_no_exact_record_temporaries(&self) -> Result<(), String> {
        for generation in 1..=MAX_JOURNAL_RECORDS {
            match self
                .directory
                .symlink_metadata(record_temp_name(generation))
            {
                Ok(_) => {
                    return Err("published composition journal retains a record temporary".into());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("inspect exact journal temporary: {error}")),
            }
        }
        Ok(())
    }

    fn read_records(&self) -> Result<Vec<CompositionPublicationRecordV2>, String> {
        self.validate_named_directory()?;
        let mut records = Vec::new();
        let mut gap = false;
        for generation in 1..=MAX_JOURNAL_RECORDS + 1 {
            let name = record_name(generation);
            match read_private_file_optional(&self.directory, Path::new(&name))? {
                Some(bytes) => {
                    if generation > MAX_JOURNAL_RECORDS || gap {
                        return Err("composition publication journal has a gap or overflow".into());
                    }
                    let record: CompositionPublicationRecordV2 = serde_json::from_slice(&bytes)
                        .map_err(|error| format!("decode composition journal record: {error}"))?;
                    let canonical = serde_json::to_vec(&record)
                        .map_err(|error| format!("encode composition journal record: {error}"))?;
                    if canonical != bytes {
                        return Err("composition publication journal record is noncanonical".into());
                    }
                    record.validate()?;
                    if record.generation != generation || record.journal_id != self.journal_id {
                        return Err("composition publication journal record is crossed".into());
                    }
                    if record.predecessor_digest
                        != records
                            .last()
                            .map(|prior: &CompositionPublicationRecordV2| {
                                prior.record_digest.clone()
                            })
                    {
                        return Err("composition publication journal predecessor differs".into());
                    }
                    records.push(record);
                }
                None => gap = true,
            }
        }
        Ok(records)
    }

    fn append(&self, record: &CompositionPublicationRecordV2) -> Result<(), String> {
        self.validate_named_directory()?;
        record.validate()?;
        let existing = self.read_records()?;
        let expected_generation = u64::try_from(existing.len())
            .map_err(|_| "journal length cannot be represented".to_string())?
            + 1;
        if record.generation != expected_generation
            || record.journal_id != self.journal_id
            || record.predecessor_digest != existing.last().map(|prior| prior.record_digest.clone())
        {
            return Err("journal append does not extend the exact current head".into());
        }
        let bytes = serde_json::to_vec(record)
            .map_err(|error| format!("encode composition journal record: {error}"))?;
        if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_JOURNAL_RECORD_BYTES) {
            return Err("composition publication journal record exceeds its bound".into());
        }
        let temp_name = record_temp_name(record.generation);
        let final_name = record_name(record.generation);
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .follow(FollowSymlinks::No);
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordTemporaryCreate(
                record.generation,
            ))?;
        let mut temporary = self
            .directory
            .open_with(&temp_name, &options)
            .map_err(|error| format!("create exact journal temporary: {error}"))?;
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordTemporaryMode(
                record.generation,
            ))?;
        temporary
            .set_permissions(Permissions::from_mode(0o600))
            .map_err(|error| format!("set journal temporary mode: {error}"))?;
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordTemporaryWrite(
                record.generation,
            ))?;
        temporary
            .write_all(&bytes)
            .map_err(|error| format!("write journal temporary: {error}"))?;
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordTemporarySync(
                record.generation,
            ))?;
        temporary
            .sync_all()
            .map_err(|error| format!("sync journal temporary: {error}"))?;
        validate_private_file_metadata(
            &temporary
                .metadata()
                .map_err(|error| format!("inspect journal temporary: {error}"))?,
            MAX_JOURNAL_RECORD_BYTES,
        )?;
        drop(temporary);

        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordRename(
                record.generation,
            ))?;
        match renameat_with(
            &self.directory,
            Path::new(&temp_name),
            &self.directory,
            Path::new(&final_name),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) => {}
            Err(error) => {
                return Err(format!(
                    "atomic journal record publication could not be proven: {error}"
                ));
            }
        }
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordDirectorySync(
                record.generation,
            ))?;
        sync_directory(&self.directory)
            .map_err(|error| format!("sync journal record namespace: {error}"))?;
        self.faults
            .inject(CompositionPublicationFaultPointV2::RecordCommittedReadback(
                record.generation,
            ))?;
        let committed = read_private_file_optional(&self.directory, Path::new(&final_name))?
            .ok_or_else(|| "committed journal record is absent".to_string())?;
        if committed != bytes {
            return Err("committed journal record differs from exact bytes".into());
        }
        self.validate_named_directory()
    }
}

fn open_writer_lock(
    directory: &Dir,
    faults: &CompositionPublicationFaultInjectorV2,
    allow_creation: bool,
) -> Result<File, String> {
    if !allow_creation {
        let mut open = OpenOptions::new();
        open.read(true).write(true).follow(FollowSymlinks::No);
        let file = directory
            .open_with(LOCK_FILE, &open)
            .map_err(|error| format!("open existing journal lock: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("inspect journal lock: {error}"))?;
        validate_private_file_metadata(&metadata, 0)?;
        if metadata.len() != 0 {
            return Err("composition journal lock is not empty".into());
        }
        return Ok(file);
    }
    let mut create = OpenOptions::new();
    create
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    faults.inject(CompositionPublicationFaultPointV2::WriterLockCreate)?;
    let file = match directory.open_with(LOCK_FILE, &create) {
        Ok(file) => {
            faults.inject(CompositionPublicationFaultPointV2::WriterLockMode)?;
            file.set_permissions(Permissions::from_mode(0o600))
                .map_err(|error| format!("set journal lock mode: {error}"))?;
            faults.inject(CompositionPublicationFaultPointV2::WriterLockSync)?;
            file.sync_all()
                .map_err(|error| format!("sync new journal lock: {error}"))?;
            faults.inject(CompositionPublicationFaultPointV2::WriterLockNamespaceSync)?;
            sync_directory(directory)
                .map_err(|error| format!("sync journal lock namespace: {error}"))?;
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let mut open = OpenOptions::new();
            open.read(true).write(true).follow(FollowSymlinks::No);
            directory
                .open_with(LOCK_FILE, &open)
                .map_err(|error| format!("open exact journal lock: {error}"))?
        }
        Err(error) => return Err(format!("create exact journal lock: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect journal lock: {error}"))?;
    validate_private_file_metadata(&metadata, 0)?;
    if metadata.len() != 0 {
        return Err("composition journal lock is not empty".into());
    }
    Ok(file)
}

fn validate_named_writer_lock(
    directory: &Dir,
    retained: &File,
) -> Result<JournalObjectIdentity, String> {
    let retained_metadata = retained
        .metadata()
        .map_err(|error| format!("inspect retained journal lock: {error}"))?;
    validate_private_file_metadata(&retained_metadata, 0)?;
    if retained_metadata.len() != 0 {
        return Err("retained composition journal lock is not empty".into());
    }
    let mut open = OpenOptions::new();
    open.read(true).write(true).follow(FollowSymlinks::No);
    let named = directory
        .open_with(LOCK_FILE, &open)
        .map_err(|error| format!("reopen named journal lock: {error}"))?;
    let named_metadata = named
        .metadata()
        .map_err(|error| format!("inspect named journal lock: {error}"))?;
    validate_private_file_metadata(&named_metadata, 0)?;
    if named_metadata.len() != 0 {
        return Err("named composition journal lock is not empty".into());
    }
    let retained_identity = journal_object_identity(&retained_metadata);
    if journal_object_identity(&named_metadata) != retained_identity {
        return Err("named composition journal lock differs from the locked object".into());
    }
    Ok(retained_identity)
}

fn read_private_file_optional(directory: &Dir, name: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("open exact journal record: {error}")),
    };
    let first = file
        .metadata()
        .map_err(|error| format!("inspect journal record: {error}"))?;
    validate_private_file_metadata(&first, MAX_JOURNAL_RECORD_BYTES)?;
    let first_identity = journal_object_identity(&first);
    let expected_length = first.len();
    let first_bytes = read_bounded(&mut file, MAX_JOURNAL_RECORD_BYTES)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("rewind journal record: {error}"))?;
    let second_bytes = read_bounded(&mut file, MAX_JOURNAL_RECORD_BYTES)?;
    let second = file
        .metadata()
        .map_err(|error| format!("reinspect journal record: {error}"))?;
    validate_private_file_metadata(&second, MAX_JOURNAL_RECORD_BYTES)?;
    if first_identity != journal_object_identity(&second)
        || first_bytes != second_bytes
        || u64::try_from(first_bytes.len()).ok() != Some(expected_length)
    {
        return Err("composition journal record changed during stable read".into());
    }
    Ok(Some(first_bytes))
}

fn read_bounded(file: &mut File, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read composition journal record: {error}"))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err("composition journal record exceeds its bound".into());
    }
    Ok(bytes)
}

fn validate_private_directory(directory: &Dir) -> Result<JournalObjectIdentity, String> {
    let metadata = directory
        .dir_metadata()
        .map_err(|error| format!("inspect composition journal directory: {error}"))?;
    if !metadata.is_dir()
        || OsMetadataExt::uid(&metadata) != rustix::process::geteuid().as_raw()
        || OsMetadataExt::mode(&metadata) & 0o777 != 0o700
    {
        return Err("composition journal directory is not exact owner-private 0700".into());
    }
    Ok(journal_object_identity(&metadata))
}

fn validate_private_file_metadata(metadata: &Metadata, limit: u64) -> Result<(), String> {
    if !metadata.is_file()
        || OsMetadataExt::uid(metadata) != rustix::process::geteuid().as_raw()
        || OsMetadataExt::mode(metadata) & 0o777 != 0o600
        || OsMetadataExt::nlink(metadata) != 1
        || metadata.len() > limit
    {
        return Err(
            "composition journal file is not singly-linked owner-private 0600 within bounds".into(),
        );
    }
    Ok(())
}

fn journal_object_identity(metadata: &Metadata) -> JournalObjectIdentity {
    JournalObjectIdentity {
        device: cap_fs_ext::MetadataExt::dev(metadata),
        inode: cap_fs_ext::MetadataExt::ino(metadata),
        uid: OsMetadataExt::uid(metadata),
        mode: OsMetadataExt::mode(metadata) & 0o777,
    }
}

fn record_name(generation: u64) -> String {
    format!("{RECORD_PREFIX}{generation:020}{RECORD_SUFFIX}")
}

fn record_temp_name(generation: u64) -> String {
    format!("{}{RECORD_TEMP_SUFFIX}", record_name(generation))
}

fn compute_journal_id(
    publication_id: &str,
    publication_claim_digest: &Digest,
) -> Result<Digest, ApplicationCompositionPublisherError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        publication_id: &'a str,
        publication_claim_digest: &'a Digest,
    }
    Ok(domain_digest(
        JOURNAL_ID_DOMAIN,
        &canonical_json(
            &Preimage {
                publication_id,
                publication_claim_digest,
            },
            "composition journal identity",
        )?,
    ))
}

fn canonical_json(
    value: &impl Serialize,
    label: &'static str,
) -> Result<Vec<u8>, ApplicationCompositionPublisherError> {
    serde_json::to_vec(value)
        .map_err(|error| authority_error(format!("cannot encode {label}: {error}")))
}

fn domain_digest(domain: &[u8], canonical: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + 8 + canonical.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(
        &u64::try_from(canonical.len())
            .expect("usize fits u64")
            .to_be_bytes(),
    );
    preimage.extend_from_slice(canonical);
    Digest::sha256(&preimage)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use grok_build_core::{
        CompositionBaseFileV2, CompositionFinalVerificationBindingV2,
        DescriptorRelativeManifestEntry, DescriptorRelativeWorkspaceManifest,
        NonAuthorizingApplicationCompositionInputsV2, NonAuthorizingCompositionBaseProjectionV2,
    };

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        parent: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = std::env::temp_dir().join(format!(
                "grok-build-composition-publisher-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let state = parent.join("state");
            fs::create_dir(&parent).expect("create fixture parent");
            fs::create_dir(&state).expect("create private state");
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
                .expect("set private-state mode");
            let parent = fs::canonicalize(parent).expect("canonicalize fixture parent");
            Self {
                state: parent.join("state"),
                parent,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.parent);
        }
    }

    #[derive(Clone)]
    struct FileState {
        path: &'static str,
        bytes: &'static [u8],
        mode: u32,
    }

    type ResultBytesSpec<'a> = (&'static [u8], Option<(&'a str, u32)>);

    fn digest(label: &str) -> Digest {
        Digest::sha256(label.as_bytes())
    }

    fn snapshot(files: &[FileState]) -> Digest {
        let entries = files
            .iter()
            .map(|file| DescriptorRelativeManifestEntry {
                path: file.path.into(),
                content_digest: Digest::sha256(file.bytes),
                byte_length: u64::try_from(file.bytes.len()).expect("test length"),
                unix_mode: file.mode,
            })
            .collect::<Vec<_>>();
        DescriptorRelativeWorkspaceManifest::from_captured_entries(digest("grant"), 1, 2, entries)
            .expect("test manifest")
            .manifest_digest
    }

    fn base_projection(files: &[FileState]) -> NonAuthorizingCompositionBaseProjectionV2 {
        NonAuthorizingCompositionBaseProjectionV2::try_new_non_authorizing(
            snapshot(files),
            files
                .iter()
                .map(|file| CompositionBaseFileV2 {
                    path: file.path.into(),
                    content_digest: Digest::sha256(file.bytes),
                    byte_length: u64::try_from(file.bytes.len()).expect("test length"),
                    unix_mode: file.mode,
                })
                .collect(),
            Vec::new(),
        )
        .expect("test base projection")
    }

    fn persist_source(
        fixture: &Fixture,
        change_set_id: &str,
        base: Digest,
        result: Digest,
        operations: Vec<FileOperation>,
        result_bytes: &[ResultBytesSpec<'_>],
    ) -> (TaskIntegrationArtifactReference, StagedChangeSet) {
        let blobs = result_bytes
            .iter()
            .map(|(bytes, _)| (Digest::sha256(bytes), bytes.to_vec()))
            .collect::<BTreeMap<_, _>>();
        let create_modes = result_bytes
            .iter()
            .filter_map(|(_, mode)| mode.map(|(path, mode)| (PathBuf::from(path), mode)))
            .collect();
        let staged = StagedChangeSet::new_with_create_modes(
            grok_build_core::ChangeSet {
                change_set_id: change_set_id.into(),
                base_snapshot: base,
                result_snapshot: result,
                operations,
            },
            blobs,
            create_modes,
        )
        .expect("test source stage");
        let store = CapabilityStageBundleStore::open(&fixture.state).expect("open test store");
        let reference = store.persist(&staged).expect("persist source stage");
        (
            reference
                .to_core_integration_artifact()
                .expect("core source artifact"),
            staged,
        )
    }

    fn source_authority(
        ordinal: u32,
        artifact: TaskIntegrationArtifactReference,
        staged: &StagedChangeSet,
    ) -> grok_build_core::NonAuthorizingApplicationCompositionSourceAuthorityV2 {
        grok_build_core::NonAuthorizingApplicationCompositionSourceAuthorityV2::try_new_non_authorizing(
            ordinal,
            format!("task-{ordinal}"),
            format!("attempt-{ordinal}"),
            format!("task-done-{ordinal}"),
            digest(&format!("task-done-digest-{ordinal}")),
            format!("integration-{ordinal}"),
            digest(&format!("integration-digest-{ordinal}")),
            artifact,
            staged_blob_bytes(staged).expect("test source byte accounting"),
            u32::try_from(staged.change_set().operations.len())
                .expect("test source operation count"),
        )
        .expect("test source authority")
    }

    fn projected_source(
        authority: &grok_build_core::NonAuthorizingApplicationCompositionSourceAuthorityV2,
        staged: &StagedChangeSet,
    ) -> NonAuthorizingApplicationCompositionSourceV2 {
        NonAuthorizingApplicationCompositionSourceV2::try_new_non_authorizing(
            authority.ordinal,
            authority.task_id.clone(),
            authority.attempt_id.clone(),
            authority.task_done_proof_id.clone(),
            authority.task_done_proof_digest.clone(),
            authority.integration_receipt_id.clone(),
            authority.integration_receipt_digest.clone(),
            staged.change_set().clone(),
            authority.artifact.clone(),
            source_result_material(authority.ordinal, &authority.artifact, staged)
                .expect("derive test material"),
        )
        .expect("project test source")
    }

    fn authority(
        base: NonAuthorizingCompositionBaseProjectionV2,
        sources: Vec<(
            grok_build_core::NonAuthorizingApplicationCompositionSourceAuthorityV2,
            StagedChangeSet,
        )>,
    ) -> NonAuthorizingApplicationCompositionPublicationClaimV2 {
        let projected = sources
            .iter()
            .map(|(authority, staged)| projected_source(authority, staged))
            .collect::<Vec<_>>();
        let result = sources
            .last()
            .expect("at least one source")
            .0
            .artifact
            .result_snapshot
            .clone();
        let inputs = NonAuthorizingApplicationCompositionInputsV2::try_new_non_authorizing(
            "sprint-composition",
            base.snapshot.clone(),
            result.clone(),
            digest("complete-task-done-set"),
            CompositionFinalVerificationBindingV2 {
                attempt_id: "final-verification-1".into(),
                attempt_authority_digest: digest("final-verification-authority"),
                snapshot: result,
                complete_criterion_evidence_set_digest: digest("criterion-evidence-set"),
            },
            projected
                .iter()
                .map(|source| source.source_identity.clone())
                .collect(),
        )
        .expect("test composition inputs");
        NonAuthorizingApplicationCompositionPublicationClaimV2::try_new_non_authorizing(
            "composition-publication-1",
            inputs,
            base,
            sources
                .into_iter()
                .map(|(authority, _)| authority)
                .collect(),
        )
        .expect("test publication claim")
    }

    fn one_source_fixture(
        fixture: &Fixture,
    ) -> NonAuthorizingApplicationCompositionPublicationClaimV2 {
        let base = base_projection(&[]);
        let final_files = [FileState {
            path: "a.txt",
            bytes: b"one",
            mode: 0o640,
        }];
        let result = snapshot(&final_files);
        let result_hash = Digest::sha256(b"one");
        let (artifact, staged) = persist_source(
            fixture,
            "source-change-0",
            base.snapshot.clone(),
            result,
            vec![FileOperation::Create {
                path: PathBuf::from("a.txt"),
                result_hash,
            }],
            &[(b"one", Some(("a.txt", 0o640)))],
        );
        let source = source_authority(0, artifact, &staged);
        authority(base, vec![(source, staged)])
    }

    fn multi_source_fixture(
        fixture: &Fixture,
    ) -> NonAuthorizingApplicationCompositionPublicationClaimV2 {
        let base = base_projection(&[]);
        let middle = snapshot(&[FileState {
            path: "a.txt",
            bytes: b"one",
            mode: 0o640,
        }]);
        let final_snapshot = snapshot(&[
            FileState {
                path: "a.txt",
                bytes: b"two!",
                mode: 0o640,
            },
            FileState {
                path: "b.txt",
                bytes: b"bee",
                mode: 0o600,
            },
        ]);
        let (first_artifact, first_staged) = persist_source(
            fixture,
            "source-change-0",
            base.snapshot.clone(),
            middle.clone(),
            vec![FileOperation::Create {
                path: PathBuf::from("a.txt"),
                result_hash: Digest::sha256(b"one"),
            }],
            &[(b"one", Some(("a.txt", 0o640)))],
        );
        let (second_artifact, second_staged) = persist_source(
            fixture,
            "source-change-1",
            middle,
            final_snapshot,
            vec![
                FileOperation::Modify {
                    path: PathBuf::from("a.txt"),
                    base_hash: Digest::sha256(b"one"),
                    result_hash: Digest::sha256(b"two!"),
                },
                FileOperation::Create {
                    path: PathBuf::from("b.txt"),
                    result_hash: Digest::sha256(b"bee"),
                },
            ],
            &[(b"two!", None), (b"bee", Some(("b.txt", 0o600)))],
        );
        authority(
            base,
            vec![
                (
                    source_authority(0, first_artifact, &first_staged),
                    first_staged,
                ),
                (
                    source_authority(1, second_artifact, &second_staged),
                    second_staged,
                ),
            ],
        )
    }

    fn publish(
        fixture: &Fixture,
        authority: NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> AggregateCompositionPublicationObservationV2 {
        RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &fixture.state,
            authority,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .expect("acquire test composer")
        .publish_fresh()
        .expect("publish aggregate")
    }

    fn reconcile(
        fixture: &Fixture,
        claim: NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> AggregateCompositionPublicationObservationV2 {
        RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
            &fixture.state,
            claim,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .expect("acquire test reconciler")
        .reconcile()
        .expect("reconcile aggregate publication")
    }

    fn aggregate_bundle(
        observation: &AggregateCompositionPublicationObservationV2,
    ) -> StageBundleReference {
        StageBundleReference::try_from(&observation.composition_receipt.aggregate_artifact)
            .expect("receipt aggregate reference")
    }

    fn journal_path(
        fixture: &Fixture,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> PathBuf {
        let journal_id =
            compute_journal_id(&claim.publication_id, &claim.publication_claim_digest).unwrap();
        fixture.state.join(format!("{JOURNAL_PREFIX}{journal_id}"))
    }

    fn exact_intent_exists(
        fixture: &Fixture,
        claim: &NonAuthorizingApplicationCompositionPublicationClaimV2,
    ) -> bool {
        let journal_id =
            compute_journal_id(&claim.publication_id, &claim.publication_claim_digest).unwrap();
        let Ok(bytes) = fs::read(journal_path(fixture, claim).join(record_name(1))) else {
            return false;
        };
        let Ok(record) = serde_json::from_slice::<CompositionPublicationRecordV2>(&bytes) else {
            return false;
        };
        expected_intended_record(&journal_id, claim, &claim.publication_claim_digest)
            .is_ok_and(|expected| expected == record)
    }

    fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, (u32, Option<Vec<u8>>)> {
        fn visit(
            root: &Path,
            current: &Path,
            snapshot: &mut BTreeMap<PathBuf, (u32, Option<Vec<u8>>)>,
        ) {
            let mut entries = fs::read_dir(current)
                .expect("read snapshot directory")
                .map(|entry| entry.expect("read snapshot entry"))
                .collect::<Vec<_>>();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(root).expect("snapshot relative path");
                let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
                let mode = metadata.permissions().mode() & 0o777;
                if metadata.is_dir() {
                    snapshot.insert(relative.to_path_buf(), (mode, None));
                    visit(root, &path, snapshot);
                } else {
                    snapshot.insert(
                        relative.to_path_buf(),
                        (mode, Some(fs::read(&path).expect("snapshot file bytes"))),
                    );
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[test]
    fn one_source_is_reopened_rederived_and_published_exactly() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let observation = publish(&fixture, authority.clone());
        assert_eq!(
            observation.composition_receipt.sprint_id,
            authority.inputs.sprint_id
        );
        observation
            .composition_receipt
            .validate_against_non_authorizing(
                &observation.publication_claim,
                &observation.source_readback,
                &observation.composition_plan,
                &observation.aggregate_readback,
                &observation.publication_closure,
            )
            .expect("published receipt crosses all backing");
        let store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        let aggregate = store.load(&aggregate_bundle(&observation)).unwrap();
        assert_eq!(aggregate.change_set().operations.len(), 1);
        assert_eq!(aggregate.create_mode(Path::new("a.txt")), Some(0o640));
        assert_eq!(
            aggregate.blob(&Digest::sha256(b"one")),
            Some(b"one".as_slice())
        );
    }

    #[test]
    fn multiple_sources_publish_one_canonical_base_to_final_bundle() {
        let fixture = Fixture::new();
        let authority = multi_source_fixture(&fixture);
        let observation = publish(&fixture, authority);
        let aggregate = CapabilityStageBundleStore::open(&fixture.state)
            .unwrap()
            .load(&aggregate_bundle(&observation))
            .unwrap();
        assert_eq!(aggregate.change_set().operations.len(), 2);
        assert!(matches!(
            &aggregate.change_set().operations[0],
            FileOperation::Create { path, result_hash }
                if path == Path::new("a.txt") && result_hash == &Digest::sha256(b"two!")
        ));
        assert_eq!(aggregate.create_mode(Path::new("a.txt")), Some(0o640));
        assert_eq!(aggregate.create_mode(Path::new("b.txt")), Some(0o600));
    }

    #[test]
    fn net_zero_chain_publishes_an_exact_verified_no_op_bundle() {
        let fixture = Fixture::new();
        let base_files = [FileState {
            path: "a.txt",
            bytes: b"one",
            mode: 0o644,
        }];
        let base = base_projection(&base_files);
        let middle = snapshot(&[FileState {
            path: "a.txt",
            bytes: b"two",
            mode: 0o644,
        }]);
        let (first_artifact, first_staged) = persist_source(
            &fixture,
            "net-zero-0",
            base.snapshot.clone(),
            middle.clone(),
            vec![FileOperation::Modify {
                path: "a.txt".into(),
                base_hash: Digest::sha256(b"one"),
                result_hash: Digest::sha256(b"two"),
            }],
            &[(b"two", None)],
        );
        let (second_artifact, second_staged) = persist_source(
            &fixture,
            "net-zero-1",
            middle,
            base.snapshot.clone(),
            vec![FileOperation::Modify {
                path: "a.txt".into(),
                base_hash: Digest::sha256(b"two"),
                result_hash: Digest::sha256(b"one"),
            }],
            &[(b"one", None)],
        );
        let authority = authority(
            base,
            vec![
                (
                    source_authority(0, first_artifact, &first_staged),
                    first_staged,
                ),
                (
                    source_authority(1, second_artifact, &second_staged),
                    second_staged,
                ),
            ],
        );
        let observation = publish(&fixture, authority);
        let aggregate = CapabilityStageBundleStore::open(&fixture.state)
            .unwrap()
            .load(&aggregate_bundle(&observation))
            .unwrap();
        assert!(aggregate.change_set().operations.is_empty());
        assert_eq!(
            aggregate.change_set().base_snapshot,
            aggregate.change_set().result_snapshot
        );
        assert!(
            observation
                .composition_receipt
                .derivation_record
                .aggregate_no_op
        );
    }

    #[test]
    fn omitted_and_reordered_sources_fail_closed() {
        let fixture = Fixture::new();
        let authority = multi_source_fixture(&fixture);

        let mut omitted = authority.clone();
        omitted.sources.pop();
        assert!(matches!(
            RoleSealedFreshApplicationComposerV2::acquire_for_test(
                &fixture.state,
                omitted,
                ComposerRoleSealKindV2::ApplicationComposer
            ),
            Err(ApplicationCompositionPublisherError::Composition(_))
        ));

        let mut reordered = authority;
        reordered.sources.swap(0, 1);
        reordered.sources[0].ordinal = 0;
        reordered.sources[1].ordinal = 1;
        assert!(matches!(
            RoleSealedFreshApplicationComposerV2::acquire_for_test(
                &fixture.state,
                reordered,
                ComposerRoleSealKindV2::ApplicationComposer
            ),
            Err(ApplicationCompositionPublisherError::Composition(_))
        ));
    }

    #[test]
    fn crossed_source_reference_fails_before_any_aggregate_publication() {
        let fixture = Fixture::new();
        let mut authority = multi_source_fixture(&fixture);
        authority.sources[0].artifact.artifact_digest =
            authority.sources[1].artifact.artifact_digest.clone();
        assert!(matches!(
            RoleSealedFreshApplicationComposerV2::acquire_for_test(
                &fixture.state,
                authority,
                ComposerRoleSealKindV2::ApplicationComposer,
            ),
            Err(ApplicationCompositionPublisherError::Composition(_))
        ));
    }

    #[test]
    fn modified_source_blob_is_rejected_by_exact_reopening() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let artifact_digest = authority.sources[0].artifact.artifact_digest.clone();
        let bundle = fixture.state.join(format!("stage-{artifact_digest}"));
        let blob = fs::read_dir(bundle)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("blob-"))
            })
            .unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(blob)
            .unwrap();
        file.write_all(b"tampered").unwrap();
        file.sync_all().unwrap();
        let error = RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &fixture.state,
            authority,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .publish_fresh()
        .unwrap_err();
        assert!(matches!(
            error,
            ApplicationCompositionPublisherError::SourceBundle { ordinal: 0, .. }
        ));
    }

    #[test]
    fn every_crash_cut_reconciles_by_exact_identity_and_replay_is_idempotent() {
        for cut in [
            CompositionPublicationTestCut::AfterIntended,
            CompositionPublicationTestCut::AfterStaged,
            CompositionPublicationTestCut::AfterBundlePublished,
        ] {
            let fixture = Fixture::new();
            let authority = multi_source_fixture(&fixture);
            let first = RoleSealedFreshApplicationComposerV2::acquire_for_test(
                &fixture.state,
                authority.clone(),
                ComposerRoleSealKindV2::ApplicationComposer,
            )
            .unwrap()
            .publish_fresh_with_cut(cut)
            .unwrap_err();
            assert!(matches!(
                first,
                ApplicationCompositionPublisherError::ReconciliationRequired { .. }
            ));
            let recovered = reconcile(&fixture, authority.clone());
            let replayed = reconcile(&fixture, authority);
            assert_eq!(recovered, replayed);
        }
    }

    #[test]
    fn fresh_and_reconciliation_entrypoints_admit_only_their_exact_journal_state() {
        let empty_fixture = Fixture::new();
        let empty_claim = one_source_fixture(&empty_fixture);
        let empty_journal_id = compute_journal_id(
            &empty_claim.publication_id,
            &empty_claim.publication_claim_digest,
        )
        .unwrap();
        let store = CapabilityStageBundleStore::open(&empty_fixture.state).unwrap();
        drop(
            CompositionPublicationJournal::open_fresh(
                store.clone_composer_store_capability().unwrap(),
                empty_journal_id,
                CompositionPublicationFaultInjectorV2::none(),
            )
            .unwrap(),
        );
        let empty_reconciliation = RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
            &empty_fixture.state,
            empty_claim.clone(),
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .reconcile()
        .unwrap_err();
        assert!(matches!(
            empty_reconciliation,
            ApplicationCompositionPublisherError::ReconciliationRejected { .. }
        ));
        publish(&empty_fixture, empty_claim);

        let intended_fixture = Fixture::new();
        let intended_claim = one_source_fixture(&intended_fixture);
        RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &intended_fixture.state,
            intended_claim.clone(),
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .publish_fresh_with_cut(CompositionPublicationTestCut::AfterIntended)
        .unwrap_err();
        let repeated_fresh = RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &intended_fixture.state,
            intended_claim.clone(),
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .publish_fresh()
        .unwrap_err();
        assert!(matches!(
            repeated_fresh,
            ApplicationCompositionPublisherError::FreshPublicationRejected { .. }
        ));
        reconcile(&intended_fixture, intended_claim);
    }

    #[test]
    fn reconciliation_rejects_a_valid_but_crossed_durable_intent() {
        let fixture = Fixture::new();
        let claim = one_source_fixture(&fixture);
        RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &fixture.state,
            claim.clone(),
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .publish_fresh_with_cut(CompositionPublicationTestCut::AfterIntended)
        .unwrap_err();
        let journal_id =
            compute_journal_id(&claim.publication_id, &claim.publication_claim_digest).unwrap();
        let crossed = CompositionPublicationRecordV2::new(
            1,
            journal_id,
            None,
            CompositionPublicationRecordDataV2::Intended {
                publication_id: "crossed-publication".into(),
                publication_claim_digest: claim.publication_claim_digest.clone(),
                source_set_digest: claim.inputs.source_set_digest.clone(),
                base_projection_digest: claim.base.projection_digest.clone(),
            },
        )
        .unwrap();
        fs::write(
            journal_path(&fixture, &claim).join(record_name(1)),
            serde_json::to_vec(&crossed).unwrap(),
        )
        .unwrap();
        let error = RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
            &fixture.state,
            claim,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .reconcile()
        .unwrap_err();
        assert!(matches!(
            error,
            ApplicationCompositionPublisherError::ReconciliationRejected { .. }
        ));
    }

    #[test]
    fn published_reconciliation_is_exact_readback_without_filesystem_mutation() {
        let fixture = Fixture::new();
        let claim = one_source_fixture(&fixture);
        let published = publish(&fixture, claim.clone());
        let before = tree_snapshot(&fixture.state);
        let recovered = reconcile(&fixture, claim.clone());
        assert_eq!(recovered, published);
        assert_eq!(tree_snapshot(&fixture.state), before);

        let temporary = journal_path(&fixture, &claim).join(record_temp_name(3));
        fs::write(&temporary, b"unexpected-published-temporary").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let crossed_before = tree_snapshot(&fixture.state);
        let error = RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
            &fixture.state,
            claim,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .reconcile()
        .unwrap_err();
        assert!(matches!(
            error,
            ApplicationCompositionPublisherError::ReconciliationRejected { .. }
        ));
        assert_eq!(tree_snapshot(&fixture.state), crossed_before);
    }

    #[test]
    fn syscall_faults_restart_only_through_the_exact_durable_entrypoint() {
        let points = [
            CompositionPublicationFaultPointV2::JournalDirectoryCreate,
            CompositionPublicationFaultPointV2::JournalDirectoryMode,
            CompositionPublicationFaultPointV2::JournalDirectorySync,
            CompositionPublicationFaultPointV2::JournalNamespaceSync,
            CompositionPublicationFaultPointV2::WriterLockCreate,
            CompositionPublicationFaultPointV2::WriterLockMode,
            CompositionPublicationFaultPointV2::WriterLockSync,
            CompositionPublicationFaultPointV2::WriterLockNamespaceSync,
            CompositionPublicationFaultPointV2::RecordTemporaryCreate(1),
            CompositionPublicationFaultPointV2::RecordTemporaryMode(1),
            CompositionPublicationFaultPointV2::RecordTemporaryWrite(1),
            CompositionPublicationFaultPointV2::RecordTemporarySync(1),
            CompositionPublicationFaultPointV2::RecordRename(1),
            CompositionPublicationFaultPointV2::RecordDirectorySync(1),
            CompositionPublicationFaultPointV2::RecordCommittedReadback(1),
            CompositionPublicationFaultPointV2::RecordTemporaryCreate(2),
            CompositionPublicationFaultPointV2::RecordTemporaryMode(2),
            CompositionPublicationFaultPointV2::RecordTemporaryWrite(2),
            CompositionPublicationFaultPointV2::RecordTemporarySync(2),
            CompositionPublicationFaultPointV2::RecordRename(2),
            CompositionPublicationFaultPointV2::RecordDirectorySync(2),
            CompositionPublicationFaultPointV2::RecordCommittedReadback(2),
            CompositionPublicationFaultPointV2::RecordTemporaryCreate(3),
            CompositionPublicationFaultPointV2::RecordTemporaryMode(3),
            CompositionPublicationFaultPointV2::RecordTemporaryWrite(3),
            CompositionPublicationFaultPointV2::RecordTemporarySync(3),
            CompositionPublicationFaultPointV2::RecordRename(3),
            CompositionPublicationFaultPointV2::RecordDirectorySync(3),
            CompositionPublicationFaultPointV2::RecordCommittedReadback(3),
        ];
        let baseline_fixture = Fixture::new();
        let baseline_claim = one_source_fixture(&baseline_fixture);
        let baseline = publish(&baseline_fixture, baseline_claim);

        for point in points {
            let fixture = Fixture::new();
            let claim = one_source_fixture(&fixture);
            RoleSealedFreshApplicationComposerV2::acquire_with_fault_for_test(
                &fixture.state,
                claim.clone(),
                ComposerRoleSealKindV2::ApplicationComposer,
                point,
            )
            .unwrap()
            .publish_fresh()
            .expect_err("the armed syscall boundary must fail once");

            let recovered = if exact_intent_exists(&fixture, &claim) {
                let repeated_fresh = RoleSealedFreshApplicationComposerV2::acquire_for_test(
                    &fixture.state,
                    claim.clone(),
                    ComposerRoleSealKindV2::ApplicationComposer,
                )
                .unwrap()
                .publish_fresh()
                .unwrap_err();
                assert!(matches!(
                    repeated_fresh,
                    ApplicationCompositionPublisherError::FreshPublicationRejected { .. }
                ));
                reconcile(&fixture, claim)
            } else {
                let rejected = RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
                    &fixture.state,
                    claim.clone(),
                    ComposerRoleSealKindV2::ApplicationComposer,
                )
                .unwrap()
                .reconcile()
                .unwrap_err();
                assert!(matches!(
                    rejected,
                    ApplicationCompositionPublisherError::ReconciliationRejected { .. }
                ));
                publish(&fixture, claim)
            };
            assert_eq!(recovered, baseline, "restart mismatch after {point:?}");
        }
    }

    #[test]
    fn concurrent_writer_for_the_same_exact_journal_is_excluded() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let journal_id = compute_journal_id(
            &authority.publication_id,
            &authority.publication_claim_digest,
        )
        .unwrap();

        let first_store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        let first = CompositionPublicationJournal::open_fresh(
            first_store.clone_composer_store_capability().unwrap(),
            journal_id.clone(),
            CompositionPublicationFaultInjectorV2::none(),
        )
        .unwrap();
        let second_store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        let competing = CompositionPublicationJournal::open_fresh(
            second_store.clone_composer_store_capability().unwrap(),
            journal_id.clone(),
            CompositionPublicationFaultInjectorV2::none(),
        );
        assert!(competing.is_err_and(|reason| reason.contains("lock exact composition journal")));

        drop(first);
        let resumed_store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        CompositionPublicationJournal::open_fresh(
            resumed_store.clone_composer_store_capability().unwrap(),
            journal_id,
            CompositionPublicationFaultInjectorV2::none(),
        )
        .expect("released exact journal can be reopened after restart");
    }

    #[test]
    fn dropping_the_exact_journal_releases_the_writer_lock_past_a_duplicated_description() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let journal_id = compute_journal_id(
            &authority.publication_id,
            &authority.publication_claim_digest,
        )
        .unwrap();

        let store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        let journal = CompositionPublicationJournal::open_fresh(
            store.clone_composer_store_capability().unwrap(),
            journal_id.clone(),
            CompositionPublicationFaultInjectorV2::none(),
        )
        .unwrap();

        // A duplicate description models a forked child retaining the lock after
        // the original descriptor closes.
        let duplicated = journal
            .writer_lock
            .try_clone()
            .expect("duplicate the writer-lock description");

        drop(journal);

        // The exclusion must end with the journal that owns it, not with the
        // last accidental duplicate of its descriptor. Closing alone would not
        // release it here, so a journal that relies on close would refuse this
        // rightful writer with a spurious `Resource temporarily unavailable`.
        let resumed_store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        CompositionPublicationJournal::open_fresh(
            resumed_store.clone_composer_store_capability().unwrap(),
            journal_id,
            CompositionPublicationFaultInjectorV2::none(),
        )
        .expect(
            "a dropped journal releases the writer lock even while a duplicate description is open",
        );

        drop(duplicated);
    }

    #[test]
    fn replacing_the_named_writer_lock_invalidates_the_retained_lock() {
        let fixture = Fixture::new();
        let claim = one_source_fixture(&fixture);
        let journal_id =
            compute_journal_id(&claim.publication_id, &claim.publication_claim_digest).unwrap();
        let store = CapabilityStageBundleStore::open(&fixture.state).unwrap();
        let journal = CompositionPublicationJournal::open_fresh(
            store.clone_composer_store_capability().unwrap(),
            journal_id,
            CompositionPublicationFaultInjectorV2::none(),
        )
        .unwrap();
        let directory = journal_path(&fixture, &claim);
        fs::rename(
            directory.join(LOCK_FILE),
            directory.join("writer.lock.displaced"),
        )
        .unwrap();
        let replacement = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(LOCK_FILE))
            .unwrap();
        replacement
            .set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        replacement.sync_all().unwrap();
        let error = journal.read_records().unwrap_err();
        assert!(
            error.contains("writer lock") || error.contains("locked object"),
            "unexpected lock replacement error: {error}"
        );
    }

    #[test]
    fn cumulative_reopened_blob_bytes_close_exactly_at_the_limit() {
        assert_eq!(
            checked_cumulative_reopened_source_bytes(
                MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2 - 1,
                1,
            )
            .unwrap(),
            MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2
        );
        assert!(
            checked_cumulative_reopened_source_bytes(MAX_COMPOSITION_REOPENED_SOURCE_BYTES_V2, 1,)
                .is_err()
        );
    }

    #[test]
    fn zero_blob_sources_exhaust_metadata_and_operation_budgets_exactly() {
        let fixture = Fixture::new();
        let empty = snapshot(&[]);
        let long_change_set_id = "c".repeat(256);
        let (artifact, staged) = persist_source(
            &fixture,
            &long_change_set_id,
            empty.clone(),
            empty,
            Vec::new(),
            &[],
        );
        assert_eq!(staged_blob_bytes(&staged).unwrap(), 0);
        let authority =
            grok_build_core::NonAuthorizingApplicationCompositionSourceAuthorityV2::try_new_non_authorizing(
                0,
                "t".repeat(256),
                "a".repeat(256),
                "p".repeat(256),
                digest("zero-blob-proof"),
                "i".repeat(256),
                digest("zero-blob-integration"),
                artifact,
                0,
                0,
            )
            .unwrap();
        let projected = projected_source(&authority, &staged);
        let projected_bytes = canonical_json(&projected, "test projected source")
            .unwrap()
            .len();
        assert!(projected_bytes > 0);

        let (metadata_at_limit, operations_at_limit) = checked_cumulative_reopened_source_metadata(
            MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2 - projected_bytes,
            MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2,
            &projected,
        )
        .unwrap();
        assert_eq!(
            metadata_at_limit,
            MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2
        );
        assert_eq!(
            operations_at_limit,
            MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2
        );
        assert!(
            checked_cumulative_reopened_source_metadata(
                MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2 - projected_bytes + 1,
                0,
                &projected,
            )
            .is_err()
        );

        let mut metadata_bytes = 0_usize;
        let mut operations = 0_usize;
        let accepted = MAX_COMPOSITION_REOPENED_SOURCE_METADATA_BYTES_V2 / projected_bytes;
        assert!(
            accepted < grok_build_core::MAX_COMPOSITION_SOURCES_V2,
            "metadata adversary must exhaust its byte budget within the source-count bound"
        );
        for _ in 0..accepted {
            (metadata_bytes, operations) =
                checked_cumulative_reopened_source_metadata(metadata_bytes, operations, &projected)
                    .unwrap();
        }
        assert_eq!(operations, 0);
        assert!(
            checked_cumulative_reopened_source_metadata(metadata_bytes, operations, &projected,)
                .is_err(),
            "many zero-blob, zero-operation projections must hit the metadata bound"
        );

        let one_operation_claim = one_source_fixture(&fixture);
        let one_operation_authority = &one_operation_claim.sources[0];
        let one_operation_reference =
            StageBundleReference::try_from(&one_operation_authority.artifact).unwrap();
        let one_operation_stage = CapabilityStageBundleStore::open(&fixture.state)
            .unwrap()
            .load(&one_operation_reference)
            .unwrap();
        let one_operation = projected_source(one_operation_authority, &one_operation_stage);
        let (_, exact_operations) = checked_cumulative_reopened_source_metadata(
            0,
            MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2 - 1,
            &one_operation,
        )
        .unwrap();
        assert_eq!(
            exact_operations,
            MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2
        );
        assert!(
            checked_cumulative_reopened_source_metadata(
                0,
                MAX_COMPOSITION_REOPENED_SOURCE_OPERATIONS_V2,
                &one_operation,
            )
            .is_err()
        );
    }

    #[test]
    fn crossed_role_cannot_enter_the_publication_boundary() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let error = RoleSealedFreshApplicationComposerV2::acquire_for_test(
            &fixture.state,
            authority,
            ComposerRoleSealKindV2::CrossedWorker,
        )
        .unwrap()
        .publish_fresh()
        .unwrap_err();
        assert!(matches!(
            error,
            ApplicationCompositionPublisherError::Authority(reason)
                if reason.contains("different runner role")
        ));
    }

    #[test]
    fn authority_bounds_fail_before_a_journal_or_aggregate_exists() {
        let fixture = Fixture::new();
        let mut authority = one_source_fixture(&fixture);
        authority.publication_id = "x".repeat(257);
        assert!(matches!(
            RoleSealedFreshApplicationComposerV2::acquire_for_test(
                &fixture.state,
                authority,
                ComposerRoleSealKindV2::ApplicationComposer
            ),
            Err(ApplicationCompositionPublisherError::Composition(_))
        ));
        assert!(fs::read_dir(&fixture.state).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(JOURNAL_PREFIX)
        }));
    }

    #[test]
    fn published_journal_crossing_is_rejected_without_scanning_for_alternatives() {
        let fixture = Fixture::new();
        let authority = one_source_fixture(&fixture);
        let observation = publish(&fixture, authority.clone());
        let journal = fixture.state.join(format!(
            "{JOURNAL_PREFIX}{}",
            observation.publication_closure.publication_journal_id
        ));
        let published = journal.join(record_name(3));
        let bytes = fs::read(&published).unwrap();
        let mut record: CompositionPublicationRecordV2 = serde_json::from_slice(&bytes).unwrap();
        record.record_digest = digest("crossed-record");
        fs::write(&published, serde_json::to_vec(&record).unwrap()).unwrap();
        let error = RoleSealedApplicationCompositionReconcilerV2::acquire_for_test(
            &fixture.state,
            authority,
            ComposerRoleSealKindV2::ApplicationComposer,
        )
        .unwrap()
        .reconcile()
        .unwrap_err();
        assert!(matches!(
            error,
            ApplicationCompositionPublisherError::ReconciliationRejected { .. }
        ));
    }
}
