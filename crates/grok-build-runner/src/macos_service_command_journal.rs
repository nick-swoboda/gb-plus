//! Service-owned durable bridge for canonical macOS command plans.
//!
//! The only authority type in this module is non-cloneable and has no
//! production constructor. Tests can bind it to retained descriptors for the
//! fixed singleton journal. Consequently this module can prove the persistence
//! and type-state shape without making an unsigned development process capable
//! of preparing, releasing, or cleaning a native child.

#![allow(
    dead_code,
    missing_docs,
    reason = "the signed native service mint is intentionally absent"
)]

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_fs_ext::{
    DirExt, FollowSymlinks, MetadataExt as PortableMetadataExt, OpenOptionsFollowExt, OsMetadataExt,
};
use cap_std::fs::Permissions;
use cap_std::fs::{Dir, File, Metadata, OpenOptions, OpenOptionsExt, PermissionsExt};
use grok_build_core::Digest;
use rustix::fs::{FlockOperation, RenameFlags, flock, renameat_with};
use serde::Serialize;

use crate::durable_directory::sync_directory_entries as sync_directory;
use crate::macos_command_plan::{
    MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION, MacosJournalObjectIdentityV1,
    MacosProductionCommandPlanError, MacosProductionServiceJournalBindingV1,
    ValidatedMacosProductionCommandPlanV1, digest_helper_journal_reference,
};
use crate::macos_helper_journal::MacosDurableHeldPreparationReceipt;
#[cfg(test)]
use crate::macos_helper_journal::MacosHelperJournalReference;
use crate::macos_helper_lifecycle::{MacosPostPersistAction, begin_cleaning};
#[cfg(test)]
use crate::macos_helper_protocol::MacosHelperSession;
use crate::macos_helper_protocol::{
    MacosHelperJournalRecord, MacosHelperJournalState, MacosTerminationReason,
};

const SERVICE_COMMAND_JOURNAL_DIRECTORY: &str = "macos-command-journal-v1";
const LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY: &str = "macos-command-journal-v0";
const WRITER_LOCK_NAME: &str = "writer.lock";
const PLAN_PREFIX: &str = "plan-";
const PLAN_SUFFIX: &str = ".json";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_JOURNAL_ENTRIES: usize = 65_536;
const MAX_PREPARED_HANDOFF_BYTES: usize = 1024 * 1024;
const MAX_CLEANUP_HANDOFF_BYTES: usize = 2 * 1024 * 1024;
const HELD_RECORD_DOMAIN: &[u8] = b"grok-build/macos-durable-held-record/v1\0";
const PREPARED_HANDOFF_DOMAIN: &[u8] = b"grok-build/macos-prepared-child-handoff/v1\0";
const CLEANUP_HANDOFF_DOMAIN: &[u8] = b"grok-build/macos-cleanup-only-handoff/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacosServiceCommandJournalFailureClass {
    NotCommitted,
    RecoveryRequired,
    Ambiguous,
    PriorEffectCommitted,
    EffectSubstitution,
}

#[derive(Debug)]
pub(crate) struct MacosServiceCommandJournalError {
    class: MacosServiceCommandJournalFailureClass,
    operation: &'static str,
    detail: String,
}

impl MacosServiceCommandJournalError {
    pub(crate) const fn class(&self) -> MacosServiceCommandJournalFailureClass {
        self.class
    }
}

impl Display for MacosServiceCommandJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "macOS service command journal {} failed ({:?}): {}",
            self.operation, self.class, self.detail
        )
    }
}

impl std::error::Error for MacosServiceCommandJournalError {}

fn failure(
    class: MacosServiceCommandJournalFailureClass,
    operation: &'static str,
    detail: impl Into<String>,
) -> MacosServiceCommandJournalError {
    MacosServiceCommandJournalError {
        class,
        operation,
        detail: detail.into(),
    }
}

fn plan_failure(
    class: MacosServiceCommandJournalFailureClass,
    operation: &'static str,
    error: &MacosProductionCommandPlanError,
) -> MacosServiceCommandJournalError {
    failure(class, operation, error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedDirectoryIdentity {
    object: MacosJournalObjectIdentityV1,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedFileIdentity {
    object: MacosJournalObjectIdentityV1,
    owner_uid: u32,
    mode: u32,
    length: u64,
    links: u64,
}

struct StoredPlan {
    plan: ValidatedMacosProductionCommandPlanV1,
    identity: RetainedFileIdentity,
}

struct JournalScan {
    plans: BTreeMap<String, StoredPlan>,
    temporary_name: Option<String>,
}

/// Non-cloneable ownership of the fixed service-state and singleton journal.
///
/// There is deliberately no production constructor. A future signed helper
/// must mint this from its retained installation capability after audit-token,
/// code-requirement, service-root, account-pool, and helper-store checks.
pub(crate) struct MacosServiceCommandJournalAuthority {
    binding: MacosProductionServiceJournalBindingV1,
    service_state_root: Dir,
    service_state_identity: RetainedDirectoryIdentity,
    journal: Dir,
    journal_identity: RetainedDirectoryIdentity,
    writer_lock: File,
    writer_lock_identity: RetainedFileIdentity,
    helper_journal_reference_bytes: Vec<u8>,
    #[cfg(test)]
    next_failure: Option<TestCommandPlanFailurePoint>,
    #[cfg(test)]
    fail_next_unlock: bool,
}

impl MacosServiceCommandJournalAuthority {
    /// Test-only mint from retained descriptors. Paths never cross this seam.
    #[cfg(test)]
    fn open_test_service_singleton(
        service_state_root: Dir,
        session: &MacosHelperSession,
        helper_journal_reference: &MacosHelperJournalReference,
    ) -> Result<Self, MacosServiceCommandJournalError> {
        session.validate().map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "authenticate-helper-session",
                error.to_string(),
            )
        })?;
        reject_legacy_journal(&service_state_root)?;
        let service_state_identity =
            validate_private_directory(&service_state_root, "service-state root")?;
        let journal = service_state_root
            .open_dir_nofollow(SERVICE_COMMAND_JOURNAL_DIRECTORY)
            .map_err(|error| {
                failure(
                    MacosServiceCommandJournalFailureClass::NotCommitted,
                    "open-singleton-journal",
                    error.to_string(),
                )
            })?;
        let journal_identity = validate_private_directory(&journal, "singleton journal")?;
        require_named_directory_identity(
            &service_state_root,
            SERVICE_COMMAND_JOURNAL_DIRECTORY,
            journal_identity,
        )?;
        if service_state_identity.owner_uid != journal_identity.owner_uid {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-singleton-journal",
                "service-state and journal owners differ",
            ));
        }
        let writer_lock = open_private_lock(&journal)?;
        let writer_lock_identity =
            validate_private_file(&writer_lock, Path::new(WRITER_LOCK_NAME), Some(0))?;
        require_named_file_identity(&journal, WRITER_LOCK_NAME, writer_lock_identity)?;
        let helper_journal_reference_bytes =
            helper_journal_reference
                .canonical_bytes()
                .map_err(|error| {
                    failure(
                        MacosServiceCommandJournalFailureClass::NotCommitted,
                        "bind-helper-journal",
                        error.to_string(),
                    )
                })?;
        let binding = MacosProductionServiceJournalBindingV1::try_new(
            session,
            service_state_identity.object,
            journal_identity.object,
            digest_helper_journal_reference(&helper_journal_reference_bytes),
            service_state_identity.owner_uid,
            service_state_identity.mode,
            journal_identity.mode,
        )
        .map_err(|error| {
            plan_failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-service-authority",
                &error,
            )
        })?;
        let authority = Self {
            binding,
            service_state_root,
            service_state_identity,
            journal,
            journal_identity,
            writer_lock,
            writer_lock_identity,
            helper_journal_reference_bytes,
            next_failure: None,
            fail_next_unlock: false,
        };
        authority.validate_retained()?;
        authority.scan()?;
        Ok(authority)
    }

    pub(crate) const fn binding(&self) -> &MacosProductionServiceJournalBindingV1 {
        &self.binding
    }

    fn require_exact_plan_binding(
        &self,
        plan: &ValidatedMacosProductionCommandPlanV1,
    ) -> Result<(), MacosServiceCommandJournalError> {
        self.validate_retained()?;
        if plan.service_journal_binding() != &self.binding
            || plan.helper_journal_reference_bytes() != self.helper_journal_reference_bytes
            || plan.helper_journal_reference_digest()
                != self.binding.helper_journal_reference_digest()
        {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-complete-command-plan",
                "plan differs from the authenticated helper, service roots, pool, or helper journal",
            ));
        }
        Ok(())
    }

    fn validate_retained(&self) -> Result<(), MacosServiceCommandJournalError> {
        self.binding.validate().map_err(|error| {
            plan_failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "validate-service-binding",
                &error,
            )
        })?;
        reject_legacy_journal(&self.service_state_root)?;
        let state = validate_private_directory(&self.service_state_root, "service-state root")?;
        let journal = validate_private_directory(&self.journal, "singleton journal")?;
        if state != self.service_state_identity
            || journal != self.journal_identity
            || state.object != self.binding.service_state_root_identity()
            || journal.object != self.binding.singleton_journal_root_identity()
            || state.owner_uid != self.binding.service_owner_uid()
            || state.mode != self.binding.service_state_mode()
            || journal.mode != self.binding.singleton_journal_mode()
        {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "validate-retained-roots",
                "retained service-state or singleton journal identity drifted",
            ));
        }
        require_named_directory_identity(
            &self.service_state_root,
            SERVICE_COMMAND_JOURNAL_DIRECTORY,
            self.journal_identity,
        )?;
        let lock = validate_private_file(&self.writer_lock, Path::new(WRITER_LOCK_NAME), Some(0))?;
        if lock != self.writer_lock_identity || lock.owner_uid != self.binding.service_owner_uid() {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "validate-writer-lock",
                "retained writer lock identity drifted",
            ));
        }
        require_named_file_identity(&self.journal, WRITER_LOCK_NAME, self.writer_lock_identity)?;
        if digest_helper_journal_reference(&self.helper_journal_reference_bytes)
            != *self.binding.helper_journal_reference_digest()
        {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "validate-helper-journal",
                "retained helper-journal reference digest drifted",
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the journal scan keeps entry classification and fail-closed identity checks linear for audit"
    )]
    fn scan(&self) -> Result<JournalScan, MacosServiceCommandJournalError> {
        self.validate_retained()?;
        let mut plans = BTreeMap::new();
        let mut temporary_name = None;
        let entries = self.journal.entries().map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "scan-command-journal",
                error.to_string(),
            )
        })?;
        for entry in entries {
            if plans.len() >= MAX_JOURNAL_ENTRIES {
                return Err(failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "scan-command-journal",
                    "journal entry count exceeds its hard bound",
                ));
            }
            let entry = entry.map_err(|error| {
                failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "scan-command-journal",
                    error.to_string(),
                )
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "scan-command-journal",
                    "journal contains a non-UTF-8 entry",
                )
            })?;
            if name == WRITER_LOCK_NAME {
                continue;
            }
            if name.ends_with(TEMP_SUFFIX) {
                validate_temporary_plan_name(&name)?;
                if temporary_name.replace(name).is_some() {
                    return Err(failure(
                        MacosServiceCommandJournalFailureClass::RecoveryRequired,
                        "reconcile-command-plan-temporary",
                        "multiple unresolved command-plan temporaries are present",
                    ));
                }
                continue;
            }
            let digest_text = name
                .strip_prefix(PLAN_PREFIX)
                .and_then(|name| name.strip_suffix(PLAN_SUFFIX))
                .ok_or_else(|| {
                    failure(
                        MacosServiceCommandJournalFailureClass::RecoveryRequired,
                        "scan-command-journal",
                        format!("unknown command-journal entry {name:?}"),
                    )
                })?;
            let expected_digest = Digest::parse(digest_text.to_owned()).map_err(|error| {
                failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "scan-command-journal",
                    error.to_string(),
                )
            })?;
            let (bytes, identity) = read_stable_private_file(&self.journal, Path::new(&name))?;
            if identity.owner_uid != self.binding.service_owner_uid() {
                return Err(failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "read-command-plan",
                    "published plan owner differs from the authenticated service",
                ));
            }
            let plan =
                ValidatedMacosProductionCommandPlanV1::decode_exact(&bytes).map_err(|error| {
                    plan_failure(
                        MacosServiceCommandJournalFailureClass::RecoveryRequired,
                        "decode-command-plan",
                        &error,
                    )
                })?;
            if plan.plan_digest() != &expected_digest || name != plan_file_name(plan.plan_digest())
            {
                return Err(failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "bind-command-plan-name",
                    "published plan name differs from its exact canonical digest",
                ));
            }
            if plans
                .insert(plan.effect_id().to_owned(), StoredPlan { plan, identity })
                .is_some()
            {
                return Err(failure(
                    MacosServiceCommandJournalFailureClass::RecoveryRequired,
                    "scan-command-journal",
                    "one effect has multiple immutable command plans",
                ));
            }
        }
        Ok(JournalScan {
            plans,
            temporary_name,
        })
    }

    #[cfg(test)]
    fn inject_next_failure(&mut self, failure: TestCommandPlanFailurePoint) {
        self.next_failure = Some(failure);
    }

    #[cfg(test)]
    fn inject_next_unlock_failure(&mut self) {
        self.fail_next_unlock = true;
    }
}

#[derive(Debug)]
pub(crate) struct MacosCommandPlanDurableCommitReceipt {
    plan_digest: Digest,
    effect_id: String,
    canonical_bytes_digest: Digest,
    journal_identity: MacosJournalObjectIdentityV1,
    published_file_identity: MacosJournalObjectIdentityV1,
}

impl MacosCommandPlanDurableCommitReceipt {
    fn authenticates(
        &self,
        plan: &ValidatedMacosProductionCommandPlanV1,
        binding: &MacosProductionServiceJournalBindingV1,
    ) -> bool {
        self.plan_digest == *plan.plan_digest()
            && self.effect_id == plan.effect_id()
            && self.canonical_bytes_digest == Digest::sha256(plan.canonical_bytes())
            && self.journal_identity == binding.singleton_journal_root_identity()
            && self.published_file_identity.device_id != 0
            && self.published_file_identity.inode != 0
    }
}

/// Non-admissible type state returned only after exact durable plan readback.
pub(crate) struct JournaledMacosProductionCommandPlanV1 {
    plan: ValidatedMacosProductionCommandPlanV1,
    receipt: MacosCommandPlanDurableCommitReceipt,
    authority: MacosServiceCommandJournalAuthority,
}

impl JournaledMacosProductionCommandPlanV1 {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    pub(crate) const fn permits_release() -> bool {
        false
    }

    /// Binds a helper-journal generation that was independently synchronized
    /// and read back. The result remains contract-only and cannot release.
    pub(crate) fn bind_durable_held_preparation(
        self,
        durable: MacosDurableHeldPreparationReceipt,
    ) -> Result<NonAdmissibleMacosPreparedChildHandoffV1, MacosServiceCommandJournalError> {
        if !self
            .receipt
            .authenticates(&self.plan, self.authority.binding())
            || durable.helper_journal_reference_bytes()
                != self.plan.helper_journal_reference_bytes()
        {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-prepared-child",
                "durable plan receipt or helper-journal reference differs",
            ));
        }
        let record = durable.record();
        record.validate().map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-prepared-child",
                error.to_string(),
            )
        })?;
        if record.state != MacosHelperJournalState::HeldPrepared
            || record.admission_session != *self.plan.helper_session()
            || record.request != *self.plan.helper_request()
            || record.assigned_identity.as_ref() != Some(self.plan.assigned_identity())
            || record.held_preparation_evidence.is_none()
        {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "bind-prepared-child",
                "durable helper record crossed its session, request, UID, or HeldPrepared state",
            ));
        }
        let record_bytes = canonical_held_record_bytes(record)?;
        let binding = PreparedChildBindingV1 {
            format_version: MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION,
            complete_plan_bytes: self.plan.canonical_bytes().to_vec(),
            complete_plan_digest: self.plan.plan_digest().clone(),
            helper_journal_reference_bytes: self.plan.helper_journal_reference_bytes().to_vec(),
            helper_journal_reference_digest: self.plan.helper_journal_reference_digest().clone(),
            durable_held_generation_digest: durable.generation_digest().clone(),
            durable_held_record_bytes: record_bytes,
        };
        let binding_bytes = domain_separated_json(
            PREPARED_HANDOFF_DOMAIN,
            &binding,
            MAX_PREPARED_HANDOFF_BYTES,
            "prepared-child handoff",
        )?;
        let binding_digest = Digest::sha256(&binding_bytes);
        Ok(NonAdmissibleMacosPreparedChildHandoffV1 {
            journaled: self,
            durable,
            binding,
            binding_bytes,
            binding_digest,
        })
    }
}

#[derive(Serialize)]
struct PreparedChildBindingV1 {
    format_version: u32,
    complete_plan_bytes: Vec<u8>,
    complete_plan_digest: Digest,
    helper_journal_reference_bytes: Vec<u8>,
    helper_journal_reference_digest: Digest,
    durable_held_generation_digest: Digest,
    durable_held_record_bytes: Vec<u8>,
}

/// Exact plan-to-held-child join. It deliberately exposes no release method.
pub(crate) struct NonAdmissibleMacosPreparedChildHandoffV1 {
    journaled: JournaledMacosProductionCommandPlanV1,
    durable: MacosDurableHeldPreparationReceipt,
    binding: PreparedChildBindingV1,
    binding_bytes: Vec<u8>,
    binding_digest: Digest,
}

impl NonAdmissibleMacosPreparedChildHandoffV1 {
    pub(crate) const fn permits_execution() -> bool {
        false
    }

    pub(crate) const fn permits_release() -> bool {
        false
    }

    pub(crate) fn exact_plan_bytes(&self) -> &[u8] {
        &self.binding.complete_plan_bytes
    }

    /// Produces a lossless cleanup-only request. It does not persist the
    /// transition or invoke signalling/process-enumeration mechanics.
    pub(crate) fn into_cleanup_only_handoff(
        self,
        reason: MacosTerminationReason,
    ) -> Result<MacosCleanupOnlyHandoffV1, MacosServiceCommandJournalError> {
        let transition = begin_cleaning(self.durable.record(), reason).map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "derive-cleanup-handoff",
                error.to_string(),
            )
        })?;
        if transition.post_persist_action() != MacosPostPersistAction::SealTerminateAndObserve {
            return Err(failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "derive-cleanup-handoff",
                "cleanup transition did not require sealed UID-domain termination",
            ));
        }
        let required_cleaning_record = transition.into_record();
        let preimage = CleanupHandoffPreimageV1 {
            format_version: MACOS_SERVICE_COMMAND_JOURNAL_FORMAT_VERSION,
            prepared_child_binding_bytes: &self.binding_bytes,
            prepared_child_binding_digest: &self.binding_digest,
            exact_held_record: self.durable.record(),
            required_cleaning_record: &required_cleaning_record,
            termination_reason: reason,
        };
        let canonical_bytes = domain_separated_json(
            CLEANUP_HANDOFF_DOMAIN,
            &preimage,
            MAX_CLEANUP_HANDOFF_BYTES,
            "cleanup-only handoff",
        )?;
        let handoff_digest = Digest::sha256(&canonical_bytes);
        Ok(MacosCleanupOnlyHandoffV1 {
            prepared: self,
            required_cleaning_record,
            canonical_bytes,
            handoff_digest,
        })
    }
}

#[derive(Serialize)]
struct CleanupHandoffPreimageV1<'a> {
    format_version: u32,
    prepared_child_binding_bytes: &'a [u8],
    prepared_child_binding_digest: &'a Digest,
    exact_held_record: &'a MacosHelperJournalRecord,
    required_cleaning_record: &'a MacosHelperJournalRecord,
    termination_reason: MacosTerminationReason,
}

/// Cleanup-only type state retaining the complete plan and exact held record.
pub(crate) struct MacosCleanupOnlyHandoffV1 {
    prepared: NonAdmissibleMacosPreparedChildHandoffV1,
    required_cleaning_record: MacosHelperJournalRecord,
    canonical_bytes: Vec<u8>,
    handoff_digest: Digest,
}

impl MacosCleanupOnlyHandoffV1 {
    pub(crate) const fn permits_release() -> bool {
        false
    }

    pub(crate) const fn requires_native_uid_cleanup() -> bool {
        true
    }

    pub(crate) const fn required_cleaning_record(&self) -> &MacosHelperJournalRecord {
        &self.required_cleaning_record
    }

    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn handoff_digest(&self) -> &Digest {
        &self.handoff_digest
    }

    pub(crate) fn exact_plan_bytes(&self) -> &[u8] {
        self.prepared.exact_plan_bytes()
    }
}

/// Lossless, still-non-admissible bridge into the service-owned singleton
/// journal. No native helper, process, release, signal, or cleanup callback is
/// invoked here.
pub(crate) fn journal_macos_production_command_plan(
    plan: ValidatedMacosProductionCommandPlanV1,
    mut authority: MacosServiceCommandJournalAuthority,
) -> Result<JournaledMacosProductionCommandPlanV1, MacosServiceCommandJournalError> {
    authority.require_exact_plan_binding(&plan)?;
    flock(
        &authority.writer_lock,
        FlockOperation::NonBlockingLockExclusive,
    )
    .map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "lock-command-journal",
            error.to_string(),
        )
    })?;
    let committed = persist_complete_plan_locked(&mut authority, &plan);
    let unlock_result = flock(&authority.writer_lock, FlockOperation::Unlock).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "unlock-command-journal",
            error.to_string(),
        )
    });
    #[cfg(test)]
    let unlock = if authority.fail_next_unlock && unlock_result.is_ok() {
        Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "unlock-command-journal",
            "injected retained-lock release failure",
        ))
    } else {
        unlock_result
    };
    #[cfg(not(test))]
    let unlock = unlock_result;
    let receipt = match committed {
        Ok(receipt) => {
            unlock?;
            receipt
        }
        Err(primary) => match unlock {
            Ok(()) => return Err(primary),
            Err(unlock) => {
                return Err(failure(
                    primary.class,
                    primary.operation,
                    format!(
                        "{}; retained-lock release also failed: {unlock}",
                        primary.detail
                    ),
                ));
            }
        },
    };
    Ok(JournaledMacosProductionCommandPlanV1 {
        plan,
        receipt,
        authority,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "atomic plan publication keeps every crash boundary and certainty transition linear"
)]
fn persist_complete_plan_locked(
    authority: &mut MacosServiceCommandJournalAuthority,
    plan: &ValidatedMacosProductionCommandPlanV1,
) -> Result<MacosCommandPlanDurableCommitReceipt, MacosServiceCommandJournalError> {
    authority.validate_retained()?;
    let scan = authority.scan()?;
    if let Some(existing) = scan.plans.get(plan.effect_id()) {
        let class = if existing.plan == *plan {
            MacosServiceCommandJournalFailureClass::PriorEffectCommitted
        } else {
            MacosServiceCommandJournalFailureClass::EffectSubstitution
        };
        return Err(failure(
            class,
            "commit-command-plan",
            format!("effect {} already has an immutable plan", plan.effect_id()),
        ));
    }
    let final_name = plan_file_name(plan.plan_digest());
    let temporary_name = temporary_plan_file_name(plan.plan_digest());
    if let Some(found) = scan.temporary_name {
        reconcile_exact_prepublication_temporary(authority, plan, &temporary_name, &found)?;
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestCommandPlanFailurePoint::PartialWrite) {
        authority.next_failure = None;
        let mut file = create_private_file(&authority.journal, Path::new(&temporary_name))?;
        file.write_all(b"{").map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "write-command-plan-temporary",
                error.to_string(),
            )
        })?;
        file.sync_all().map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "sync-command-plan-temporary",
                error.to_string(),
            )
        })?;
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "write-command-plan-temporary",
            "injected crash after partial temporary write",
        ));
    }

    let mut file = create_private_file(&authority.journal, Path::new(&temporary_name))?;
    file.write_all(plan.canonical_bytes()).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "write-command-plan-temporary",
            error.to_string(),
        )
    })?;
    file.sync_all().map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "sync-command-plan-temporary",
            error.to_string(),
        )
    })?;
    let temporary_identity = validate_private_file(
        &file,
        Path::new(&temporary_name),
        Some(u64::try_from(plan.canonical_bytes().len()).map_err(|_| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "sync-command-plan-temporary",
                "canonical plan length exceeds u64",
            )
        })?),
    )?;
    if temporary_identity.owner_uid != authority.binding.service_owner_uid() {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "sync-command-plan-temporary",
            "temporary plan owner differs from the authenticated service",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestCommandPlanFailurePoint::BeforePublish) {
        authority.next_failure = None;
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "publish-command-plan",
            "injected refusal after temporary file sync",
        ));
    }

    renameat_with(
        &authority.journal,
        Path::new(&temporary_name),
        &authority.journal,
        Path::new(&final_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "publish-command-plan",
            error.to_string(),
        )
    })?;

    #[cfg(test)]
    if authority.next_failure == Some(TestCommandPlanFailurePoint::AfterPublish) {
        authority.next_failure = None;
        return Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "publish-command-plan",
            "injected crash after no-replace publication",
        ));
    }

    sync_directory(&authority.journal).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "sync-command-journal-directory",
            error.to_string(),
        )
    })?;

    #[cfg(test)]
    if authority.next_failure == Some(TestCommandPlanFailurePoint::AfterDirectorySync) {
        authority.next_failure = None;
        return Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "sync-command-journal-directory",
            "injected lost response after directory sync",
        ));
    }

    #[cfg(test)]
    if authority.next_failure == Some(TestCommandPlanFailurePoint::Readback) {
        authority.next_failure = None;
        return Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "readback-command-plan",
            "injected readback refusal",
        ));
    }

    drop(file);
    let (readback_bytes, readback_identity) =
        read_stable_private_file(&authority.journal, Path::new(&final_name))?;
    if readback_identity != temporary_identity || readback_bytes != plan.canonical_bytes() {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "readback-command-plan",
            "published file identity or bytes differ from the synchronized temporary",
        ));
    }
    let readback =
        ValidatedMacosProductionCommandPlanV1::decode_exact(&readback_bytes).map_err(|error| {
            plan_failure(
                MacosServiceCommandJournalFailureClass::Ambiguous,
                "readback-command-plan",
                &error,
            )
        })?;
    if readback != *plan || readback.plan_digest() != plan.plan_digest() {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::Ambiguous,
            "readback-command-plan",
            "canonical plan or digest differs after exact readback",
        ));
    }
    Ok(MacosCommandPlanDurableCommitReceipt {
        plan_digest: readback.plan_digest().clone(),
        effect_id: readback.effect_id().to_owned(),
        canonical_bytes_digest: Digest::sha256(readback.canonical_bytes()),
        journal_identity: authority.journal_identity.object,
        published_file_identity: readback_identity.object,
    })
}

fn plan_file_name(digest: &Digest) -> String {
    format!("{PLAN_PREFIX}{}{PLAN_SUFFIX}", digest.as_str())
}

fn temporary_plan_file_name(digest: &Digest) -> String {
    format!(".{}{TEMP_SUFFIX}", plan_file_name(digest))
}

fn validate_temporary_plan_name(name: &str) -> Result<(), MacosServiceCommandJournalError> {
    let digest = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(TEMP_SUFFIX))
        .and_then(|name| name.strip_prefix(PLAN_PREFIX))
        .and_then(|name| name.strip_suffix(PLAN_SUFFIX))
        .ok_or_else(|| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "reconcile-command-plan-temporary",
                format!("malformed command-plan temporary name {name:?}"),
            )
        })?;
    Digest::parse(digest.to_owned()).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "reconcile-command-plan-temporary",
            error.to_string(),
        )
    })?;
    Ok(())
}

/// Removes only one exact, canonically valid pre-publication temporary for the
/// same plan. No native effect can have occurred at this phase. The removal is
/// synchronized before a fresh atomic publication begins.
fn reconcile_exact_prepublication_temporary(
    authority: &MacosServiceCommandJournalAuthority,
    plan: &ValidatedMacosProductionCommandPlanV1,
    expected_name: &str,
    found_name: &str,
) -> Result<(), MacosServiceCommandJournalError> {
    if found_name != expected_name {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "reconcile-command-plan-temporary",
            "temporary belongs to a different canonical command plan",
        ));
    }
    let (bytes, identity) = read_stable_private_file(&authority.journal, Path::new(found_name))?;
    let decoded = ValidatedMacosProductionCommandPlanV1::decode_exact(&bytes).map_err(|error| {
        plan_failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "reconcile-command-plan-temporary",
            &error,
        )
    })?;
    if identity.owner_uid != authority.binding.service_owner_uid()
        || bytes != plan.canonical_bytes()
        || decoded != *plan
        || decoded.plan_digest() != plan.plan_digest()
    {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "reconcile-command-plan-temporary",
            "temporary bytes, owner, canonical plan, or digest differ",
        ));
    }
    authority.journal.remove_file(found_name).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "remove-command-plan-temporary",
            error.to_string(),
        )
    })?;
    sync_directory(&authority.journal).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "sync-command-plan-temporary-removal",
            error.to_string(),
        )
    })?;
    if authority.scan()?.temporary_name.is_some() {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "reconcile-command-plan-temporary",
            "temporary remained after synchronized removal",
        ));
    }
    Ok(())
}

fn reject_legacy_journal(root: &Dir) -> Result<(), MacosServiceCommandJournalError> {
    match root.symlink_metadata(LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY) {
        Ok(_) => Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "classify-command-journal-version",
            "legacy macos-command-journal-v0 is present and is never interpreted as v1",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "classify-command-journal-version",
            error.to_string(),
        )),
    }
}

fn validate_private_directory(
    directory: &Dir,
    label: &str,
) -> Result<RetainedDirectoryIdentity, MacosServiceCommandJournalError> {
    let metadata = directory.dir_metadata().map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "inspect-private-directory",
            format!("{label}: {error}"),
        )
    })?;
    let identity = RetainedDirectoryIdentity {
        object: object_identity(&metadata),
        owner_uid: OsMetadataExt::uid(&metadata),
        mode: OsMetadataExt::mode(&metadata) & 0o777,
    };
    if !metadata.is_dir() || identity.mode != 0o700 {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "inspect-private-directory",
            format!("{label} is not a real mode-0700 directory"),
        ));
    }
    Ok(identity)
}

fn require_named_directory_identity(
    parent: &Dir,
    name: &str,
    expected: RetainedDirectoryIdentity,
) -> Result<(), MacosServiceCommandJournalError> {
    let named = parent.open_dir_nofollow(name).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "reopen-private-directory",
            error.to_string(),
        )
    })?;
    if validate_private_directory(&named, name)? != expected {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "reopen-private-directory",
            format!("named directory {name:?} was replaced"),
        ));
    }
    Ok(())
}

fn open_private_lock(directory: &Dir) -> Result<File, MacosServiceCommandJournalError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).follow(FollowSymlinks::No);
    directory
        .open_with(WRITER_LOCK_NAME, &options)
        .map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::NotCommitted,
                "open-writer-lock",
                error.to_string(),
            )
        })
}

fn create_private_file(
    directory: &Dir,
    name: &Path,
) -> Result<File, MacosServiceCommandJournalError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "create-command-plan-temporary",
            error.to_string(),
        )
    })?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "set-command-plan-mode",
                error.to_string(),
            )
        })?;
    Ok(file)
}

fn validate_private_file(
    file: &File,
    name: &Path,
    exact_length: Option<u64>,
) -> Result<RetainedFileIdentity, MacosServiceCommandJournalError> {
    let metadata = file.metadata().map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "inspect-private-file",
            format!("{}: {error}", name.display()),
        )
    })?;
    let identity = file_identity(&metadata);
    if !metadata.is_file()
        || identity.links != 1
        || identity.mode != 0o600
        || exact_length.is_some_and(|expected| identity.length != expected)
    {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "inspect-private-file",
            format!(
                "{} is not a singly-linked mode-0600 regular file of the exact length",
                name.display()
            ),
        ));
    }
    Ok(identity)
}

fn require_named_file_identity(
    directory: &Dir,
    name: &str,
    expected: RetainedFileIdentity,
) -> Result<(), MacosServiceCommandJournalError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let named = directory.open_with(name, &options).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "reopen-private-file",
            error.to_string(),
        )
    })?;
    if validate_private_file(&named, Path::new(name), Some(expected.length))? != expected {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "reopen-private-file",
            format!("named file {name:?} was replaced"),
        ));
    }
    Ok(())
}

fn read_stable_private_file(
    directory: &Dir,
    name: &Path,
) -> Result<(Vec<u8>, RetainedFileIdentity), MacosServiceCommandJournalError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = directory.open_with(name, &options).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "open-command-plan-readback",
            error.to_string(),
        )
    })?;
    let before = validate_private_file(&file, name, None)?;
    let mut first = Vec::new();
    Read::by_ref(&mut file)
        .take(
            u64::try_from(crate::macos_command_plan::MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut first)
        .map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "read-command-plan",
                error.to_string(),
            )
        })?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "rewind-command-plan",
            error.to_string(),
        )
    })?;
    let mut second = Vec::new();
    Read::by_ref(&mut file)
        .take(
            u64::try_from(crate::macos_command_plan::MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut second)
        .map_err(|error| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "reread-command-plan",
                error.to_string(),
            )
        })?;
    let after = validate_private_file(&file, name, None)?;
    if first != second
        || before != after
        || u64::try_from(first.len()) != Ok(before.length)
        || first.len() > crate::macos_command_plan::MAX_MACOS_PRODUCTION_COMMAND_PLAN_BYTES
    {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::RecoveryRequired,
            "read-command-plan",
            "command-plan file changed during stable read or exceeds its hard bound",
        ));
    }
    require_named_file_identity(
        directory,
        name.to_str().ok_or_else(|| {
            failure(
                MacosServiceCommandJournalFailureClass::RecoveryRequired,
                "read-command-plan",
                "command-plan name is not UTF-8",
            )
        })?,
        before,
    )?;
    Ok((first, before))
}

fn object_identity(metadata: &Metadata) -> MacosJournalObjectIdentityV1 {
    MacosJournalObjectIdentityV1 {
        device_id: PortableMetadataExt::dev(metadata),
        inode: PortableMetadataExt::ino(metadata),
    }
}

fn file_identity(metadata: &Metadata) -> RetainedFileIdentity {
    RetainedFileIdentity {
        object: object_identity(metadata),
        owner_uid: OsMetadataExt::uid(metadata),
        mode: OsMetadataExt::mode(metadata) & 0o777,
        length: metadata.len(),
        links: PortableMetadataExt::nlink(metadata),
    }
}

fn canonical_held_record_bytes(
    record: &MacosHelperJournalRecord,
) -> Result<Vec<u8>, MacosServiceCommandJournalError> {
    domain_separated_json(
        HELD_RECORD_DOMAIN,
        record,
        MAX_PREPARED_HANDOFF_BYTES,
        "durable held record",
    )
}

fn domain_separated_json<T: Serialize>(
    domain: &[u8],
    value: &T,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, MacosServiceCommandJournalError> {
    let json = serde_json::to_vec(value).map_err(|error| {
        failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "encode-handoff",
            format!("{label}: {error}"),
        )
    })?;
    let mut bytes = Vec::with_capacity(domain.len() + json.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&json);
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(failure(
            MacosServiceCommandJournalFailureClass::NotCommitted,
            "encode-handoff",
            format!("{label} exceeds its hard byte bound"),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestCommandPlanFailurePoint {
    PartialWrite,
    BeforePublish,
    AfterPublish,
    AfterDirectorySync,
    Readback,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, OpenOptions as StdOpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use cap_std::{ambient_authority, fs::Dir};
    use grok_build_core::{
        AcceptanceCriterion, AcceptanceKind, CommandOutputArtifactSourceV1, CommandSpec,
        ExecutionNetwork, ExecutionOrigin, ExecutionPolicyCompiler, ExecutionPolicyRequest,
        MutationMode, PathScope, ProviderProfile, ResourceLimits, SprintBudget, SprintSpec,
        WorkerLease, WorkspaceGrantIssuer, WorkspaceGrantRequest, WorkspaceNetworkPolicy,
        WorkspacePermissions,
    };

    use super::*;
    use crate::macos_command_plan::MacosProductionCommandPlanV1;
    use crate::macos_helper_journal::{
        MacosHelperJournalStore, MacosJournalAcquireOutcome, MacosJournalAppendOutcome,
        MacosJournalDurableLease,
    };
    use crate::macos_helper_lifecycle::{
        intend_cleanup_agent, prepare_identity_record, record_cleanup_agent, record_held_launcher,
    };
    use crate::macos_helper_protocol::{
        MACOS_HELPER_PROTOCOL_VERSION, MacosAssignedIdentity, MacosChildDescriptorBinding,
        MacosChildDescriptorPurpose, MacosExecutableIdentity, MacosExecutionIdentityRecord,
        MacosHeldPreparationEvidence, MacosHelperAttestation, MacosHelperInstallAudit,
        MacosHelperLaunchRequest, MacosHelperNetwork, MacosHelperPreparationBinding,
        MacosIdentityPoolObservation, MacosProcessObservation, descriptor_bindings_digest,
    };
    use crate::service::test_session_validated_command_envelope;
    use crate::wire::{
        CommandEffectAuthorityV1, RUNNER_WIRE_PROTOCOL_VERSION, RunnerRequest,
        RunnerRequestEnvelope, WireCommandSpec, WireEffectContext, command_output_capture_maximum,
        test_command_output_capture_anchor,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        top: PathBuf,
        workspace: PathBuf,
        helper_journal: PathBuf,
        service_state: PathBuf,
        command_journal: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temp root");
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let top = base.join(format!(
                "grok-build-macos-command-bridge-{label}-{}-{sequence}",
                std::process::id()
            ));
            let workspace = top.join("workspace");
            let helper_journal = top.join("helper-journal");
            let service_state = top.join("service-state");
            let command_journal = service_state.join(SERVICE_COMMAND_JOURNAL_DIRECTORY);
            for directory in [
                &top,
                &workspace,
                &helper_journal,
                &service_state,
                &command_journal,
            ] {
                fs::create_dir(directory).expect("create fixture directory");
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .expect("set fixture directory mode");
            }
            write_owner_private(&command_journal.join(WRITER_LOCK_NAME), b"");
            sync_std_directory(&command_journal);
            sync_std_directory(&service_state);
            Self {
                top,
                workspace,
                helper_journal,
                service_state,
                command_journal,
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.top);
        }
    }

    struct Fixture {
        directory: TestDirectory,
        grant: grok_build_core::IssuedWorkspaceGrant,
        policy: grok_build_core::CompiledExecutionPolicy,
        sprint: SprintSpec,
        session: MacosHelperSession,
        pool: MacosIdentityPoolObservation,
        assigned: MacosAssignedIdentity,
        helper_store: MacosHelperJournalStore,
        helper_reference: MacosHelperJournalReference,
    }

    /// A root-installed helper binary, locally attested for an ordinary user.
    const fn local_attestation() -> MacosHelperAttestation {
        MacosHelperAttestation::LocalCodeIdentity {
            install_audit: MacosHelperInstallAudit {
                auditing_uid: 501,
                binary_owner_uid: 0,
                binary_mode: 0o755,
                directory_owner_uid: 0,
                directory_mode: 0o755,
            },
        }
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let directory = TestDirectory::new(label);
            let grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
                grant_id: "grant-macos-command-plan".into(),
                workspace_root: directory.workspace.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
            })
            .expect("issue trusted fixture grant");
            let policy = ExecutionPolicyCompiler::compile(
                &grant,
                ExecutionPolicyRequest {
                    policy_id: "policy-macos-command-plan".into(),
                    read_scopes: vec![PathScope::Workspace],
                    write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
                    environment: Vec::new(),
                    network: ExecutionNetwork::None,
                    mutation_mode: MutationMode::ShadowWorkspace,
                    resource_limits: ResourceLimits {
                        wall_time_ms: 60_000,
                        max_output_bytes: 1_048_576,
                        max_processes: 16,
                        max_memory_bytes: None,
                    },
                    approval_id: None,
                },
            )
            .expect("compile trusted fixture policy");
            let acceptance_command = CommandSpec {
                program: "cargo".into(),
                arguments: vec!["test".into(), "--locked".into()],
                working_directory: PathBuf::new(),
            };
            let sprint = SprintSpec {
                sprint_id: "sprint-macos-command-plan".into(),
                objective: "prove the exact macOS command bridge".into(),
                acceptance_criteria: vec![AcceptanceCriterion {
                    criterion_id: "criterion-macos-command-plan".into(),
                    description: "the exact locked command passes".into(),
                    kind: AcceptanceKind::Automated(acceptance_command),
                }],
                provider: ProviderProfile {
                    backend_id: "fake-provider".into(),
                    model_id: "deterministic-v1".into(),
                    execution_origin: ExecutionOrigin::HostIsolated,
                },
                budget: SprintBudget {
                    max_tasks: 3,
                    max_attempts_per_task: 3,
                    max_tool_calls: 32,
                    max_duration_ms: 600_000,
                },
                max_workers: 3,
                workspace_grant: grant.contract().clone(),
                base_snapshot: digest(60),
            };
            sprint.validate().expect("validate fixture sprint");

            let mut pool = MacosIdentityPoolObservation {
                records: vec![identity(601), identity(602), identity(603)],
                pool_record_digest: digest(0),
            };
            pool.pool_record_digest = pool.computed_digest().expect("compute pool digest");
            let session = MacosHelperSession {
                protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
                policy_version: 7,
                session_nonce: digest(1),
                helper_binary_digest: digest(2),
                helper_requirement_digest: digest(3),
                client_binary_digest: digest(4),
                client_requirement_digest: digest(5),
                pool_record_digest: pool.pool_record_digest.clone(),
                workspace_grant_hash: grant.contract().grant_hash.clone(),
                execution_policy_hash: policy.contract().policy_hash.clone(),
                command_network: MacosHelperNetwork::Denied,
                authenticated_at_unix_ms: 10,
                peer_requirement_matched: true,
                attestation: local_attestation(),
            };
            let assigned = assigned(601);
            let (helper_store, helper_reference) =
                MacosHelperJournalStore::provision(&directory.helper_journal, &session, &pool)
                    .expect("provision exact helper journal");
            Self {
                directory,
                grant,
                policy,
                sprint,
                session,
                pool,
                assigned,
                helper_store,
                helper_reference,
            }
        }

        fn service_authority(
            &self,
        ) -> Result<MacosServiceCommandJournalAuthority, MacosServiceCommandJournalError> {
            let state = Dir::open_ambient_dir(&self.directory.service_state, ambient_authority())
                .expect("open retained service-state descriptor");
            MacosServiceCommandJournalAuthority::open_test_service_singleton(
                state,
                &self.session,
                &self.helper_reference,
            )
        }

        fn plan_and_authority(
            &self,
            command_argument: &str,
            effect_id: &str,
        ) -> (
            ValidatedMacosProductionCommandPlanV1,
            MacosServiceCommandJournalAuthority,
        ) {
            let authority = self
                .service_authority()
                .expect("mint test-only retained service authority");
            let plan = self.plan(command_argument, effect_id, authority.binding().clone());
            (plan, authority)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the fixture builds one complete command plan so tests cannot silently omit a retained authority field"
        )]
        fn plan(
            &self,
            command_argument: &str,
            effect_id: &str,
            binding: MacosProductionServiceJournalBindingV1,
        ) -> ValidatedMacosProductionCommandPlanV1 {
            let command = CommandSpec {
                program: "cargo".into(),
                arguments: vec![command_argument.into()],
                working_directory: PathBuf::new(),
            };
            let command_bytes = serde_json::to_vec(&command).expect("encode exact command");
            let worker_lease = WorkerLease::new(
                self.sprint.sprint_id.clone(),
                1,
                "task-macos-command-plan".into(),
                "worker-macos-command-plan".into(),
                vec![PathScope::Relative(PathBuf::from("src"))],
                11,
            )
            .expect("construct exact worker lease");
            let request_digest = Digest::sha256(&command_bytes);
            let output_capture = test_command_output_capture_anchor(
                CommandOutputArtifactSourceV1 {
                    sprint_id: self.sprint.sprint_id.clone(),
                    runner_launch_id: "launch-macos-command-plan".into(),
                    runner_session_id: "runner-session-macos-command-plan".into(),
                    effect_id: effect_id.into(),
                    request_digest: request_digest.clone(),
                },
                digest(72),
                command_output_capture_maximum(
                    self.policy.contract().resource_limits.max_output_bytes,
                )
                .expect("macOS command plan capture maximum"),
                7,
            );
            let mut envelope = RunnerRequestEnvelope {
                protocol_version: RUNNER_WIRE_PROTOCOL_VERSION,
                session_id: "runner-session-macos-command-plan".into(),
                runner_nonce: Some(digest(70)),
                sequence: 7,
                request_id: format!("wire-request-{command_argument}"),
                effect: Some(WireEffectContext {
                    contract_version: grok_build_core::CONTRACT_VERSION,
                    launch_id: "launch-macos-command-plan".into(),
                    effect_id: effect_id.into(),
                    idempotency_key: format!("idempotency-{command_argument}"),
                    sprint_id: self.sprint.sprint_id.clone(),
                    task_id: Some("task-macos-command-plan".into()),
                    worker_id: Some("worker-macos-command-plan".into()),
                    worker_lease: Some(worker_lease),
                    policy_hash: self.policy.contract().policy_hash.clone(),
                    input_snapshot: digest(71),
                    request_digest,
                    transport_commitment_digest: digest(0),
                }),
                request: RunnerRequest::WorkerRunCommand {
                    command: WireCommandSpec {
                        program: command.program.clone(),
                        arguments: command.arguments.clone(),
                        working_directory: String::new(),
                    },
                    output_capture,
                },
            };
            envelope
                .bind_transport_commitment_digest()
                .expect("bind transport commitment");
            let command_authority = CommandEffectAuthorityV1::from_session_validated(
                test_session_validated_command_envelope(
                    &envelope,
                    &self.grant.contract().grant_hash,
                ),
            )
            .expect("validate command authority")
            .expect("command creates authority");
            let suffix = if command_argument == "test" {
                "test"
            } else {
                "check"
            };
            let preparation = MacosHelperPreparationBinding {
                contract_version: grok_build_core::CONTRACT_VERSION,
                attempt_id: format!("attempt-macos-command-{suffix}"),
                sprint_id: self.sprint.sprint_id.clone(),
                launch_id: "launch-macos-command-plan".into(),
                runner_session_id: envelope.session_id.clone(),
                cleanup_effect_id: "cleanup-macos-command-plan".into(),
                input_snapshot: digest(71),
                native_journal_id: format!("native-journal-macos-command-{suffix}"),
                expected_platform_binding_digest: digest(72),
                claimed_at_unix_ms: 11,
            };
            let mut helper_request = MacosHelperLaunchRequest {
                protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
                policy_version: self.session.policy_version,
                session_nonce: self.session.session_nonce.clone(),
                request_id: format!("helper-request-{command_argument}"),
                preparation,
                runner_session_id: envelope.session_id,
                effect_id: effect_id.into(),
                workspace_grant_hash: self.grant.contract().grant_hash.clone(),
                execution_policy_hash: self.policy.contract().policy_hash.clone(),
                staged_workspace_id: "shadow-macos-command-plan".into(),
                executable_identity: MacosExecutableIdentity::SystemToolchain {
                    policy_entry_id: "cargo-1.97.0".into(),
                    binary_digest: digest(73),
                },
                descriptor_bindings: descriptors(),
                argv: vec!["cargo".into(), command_argument.into()],
                relative_working_directory: ".".into(),
                environment: BTreeMap::new(),
                deadline_unix_ms: 1_000,
                max_output_bytes: self.policy.contract().resource_limits.max_output_bytes,
                max_processes: self.policy.contract().resource_limits.max_processes,
                max_memory_bytes: self.policy.contract().resource_limits.max_memory_bytes,
                command_network: MacosHelperNetwork::Denied,
                seatbelt_profile_digest: digest(74),
                request_digest: digest(0),
            };
            helper_request.request_digest = helper_request
                .computed_digest()
                .expect("compute helper request digest");
            MacosProductionCommandPlanV1::build(
                &self.sprint,
                command_authority,
                &self.grant,
                &self.policy,
                self.session.clone(),
                helper_request,
                &self.pool,
                self.assigned.clone(),
                &self.helper_reference,
                binding,
            )
            .expect("build exact non-admissible macOS command plan")
        }

        fn held_receipt(
            &self,
            request: &MacosHelperLaunchRequest,
        ) -> MacosDurableHeldPreparationReceipt {
            let prepared = prepare_identity_record(
                &self.session,
                request,
                &request.preparation,
                &self.pool,
                self.assigned.clone(),
                [
                    observation(1, 20, self.assigned.uid, false),
                    observation(2, 21, self.assigned.uid, false),
                ],
                22,
            )
            .expect("construct initial helper lifecycle");
            let MacosJournalAcquireOutcome::Ready(ready) = self
                .helper_store
                .acquire(&self.session, &self.pool, self.assigned.clone())
                .expect("acquire helper account")
            else {
                panic!("fresh helper account must be ready");
            };
            let mut durable =
                expect_durable(ready.persist_initial(&self.session, &self.pool, prepared));
            let transition = intend_cleanup_agent(durable.record())
                .expect("persist cleanup-agent intent before effect");
            durable =
                expect_durable(durable.persist_successor(&self.session, &self.pool, transition));
            let transition = record_cleanup_agent(durable.record(), digest(80))
                .expect("persist held-launch intent before effect");
            durable =
                expect_durable(durable.persist_successor(&self.session, &self.pool, transition));
            let held = held_evidence(&self.session, durable.record(), 23);
            let transition = record_held_launcher(durable.record(), &self.session, held)
                .expect("construct exact HeldPrepared successor");
            durable =
                expect_durable(durable.persist_successor(&self.session, &self.pool, transition));
            durable
                .durable_held_preparation_receipt()
                .expect("mint non-cloneable durable held receipt")
        }
    }

    fn digest(marker: u8) -> Digest {
        Digest::sha256(&[marker])
    }

    fn identity(uid: u32) -> MacosExecutionIdentityRecord {
        MacosExecutionIdentityRecord {
            account_name: format!("_grokbuild{uid}"),
            uid,
            gid: uid,
            record_digest: Digest::sha256(&uid.to_be_bytes()),
            login_shell: "/usr/bin/false".into(),
            home_directory: format!("/var/empty/grok-build/{uid}"),
            supplementary_groups: Vec::new(),
            password_locked: true,
            interactive_session_count: 0,
        }
    }

    fn assigned(uid: u32) -> MacosAssignedIdentity {
        let identity = identity(uid);
        MacosAssignedIdentity {
            account_name: identity.account_name,
            uid,
            gid: identity.gid,
            account_record_digest: identity.record_digest,
        }
    }

    fn descriptors() -> Vec<MacosChildDescriptorBinding> {
        [
            (0, MacosChildDescriptorPurpose::StandardInput, true),
            (1, MacosChildDescriptorPurpose::StandardOutput, true),
            (2, MacosChildDescriptorPurpose::StandardError, true),
            (3, MacosChildDescriptorPurpose::HoldControl, false),
            (4, MacosChildDescriptorPurpose::SetupReport, false),
        ]
        .into_iter()
        .map(
            |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
                target_fd,
                purpose,
                object_digest: digest(90 + u8::try_from(target_fd).unwrap()),
                inherited_through_exec,
            },
        )
        .collect()
    }

    fn observation(
        sequence: u32,
        observed_at_unix_ms: u64,
        uid: u32,
        creation_sealed: bool,
    ) -> MacosProcessObservation {
        let mut observation = MacosProcessObservation {
            sequence,
            observed_at_unix_ms,
            uid,
            process_ids: Vec::new(),
            enumeration_digest: digest(0),
            creation_sealed,
        };
        observation.enumeration_digest = observation
            .computed_digest()
            .expect("compute process-observation digest");
        observation
    }

    fn held_evidence(
        session: &MacosHelperSession,
        record: &MacosHelperJournalRecord,
        held_at_unix_ms: u64,
    ) -> MacosHeldPreparationEvidence {
        let mut evidence = MacosHeldPreparationEvidence {
            authenticated_session: session.clone(),
            request_digest: record.request.request_digest.clone(),
            preparation: record.request.preparation.clone(),
            assigned_identity: record.assigned_identity.clone().unwrap(),
            descriptor_bindings_digest: descriptor_bindings_digest(
                &record.request.descriptor_bindings,
            )
            .expect("digest descriptors"),
            setup_readback_digest: digest(81),
            held_at_unix_ms,
            evidence_digest: digest(0),
        };
        evidence.evidence_digest = evidence.computed_digest().expect("digest held evidence");
        evidence
    }

    fn expect_durable(outcome: MacosJournalAppendOutcome<'_>) -> MacosJournalDurableLease<'_> {
        match outcome {
            MacosJournalAppendOutcome::Durable(durable) => *durable,
            MacosJournalAppendOutcome::ReconciliationRequired(reconciliation) => {
                panic!(
                    "expected durable helper generation: {}",
                    reconciliation.cause()
                )
            }
        }
    }

    fn write_owner_private(path: &Path, bytes: &[u8]) {
        let mut options = StdOpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).expect("create owner-private file");
        file.write_all(bytes).expect("write owner-private file");
        file.sync_all().expect("sync owner-private file");
    }

    fn sync_std_directory(path: &Path) {
        StdOpenOptions::new()
            .read(true)
            .open(path)
            .expect("open directory for sync")
            .sync_all()
            .expect("sync directory");
    }

    fn journal_with_test_callback(
        plan: ValidatedMacosProductionCommandPlanV1,
        authority: MacosServiceCommandJournalAuthority,
        callbacks: &AtomicUsize,
    ) -> Result<JournaledMacosProductionCommandPlanV1, MacosServiceCommandJournalError> {
        let journaled = journal_macos_production_command_plan(plan, authority)?;
        callbacks.fetch_add(1, Ordering::SeqCst);
        Ok(journaled)
    }

    fn expect_error<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn canonical_plan_is_lossless_but_never_admissible() {
        let fixture = Fixture::new("canonical-plan");
        let (plan, _authority) = fixture.plan_and_authority("test", "effect-macos-command-plan");
        assert!(!ValidatedMacosProductionCommandPlanV1::permits_execution());
        assert!(!ValidatedMacosProductionCommandPlanV1::permits_release());
        let reopened = ValidatedMacosProductionCommandPlanV1::decode_exact(plan.canonical_bytes())
            .expect("round-trip exact canonical plan");
        assert_eq!(reopened, plan);
        let encoded = String::from_utf8(plan.canonical_bytes().to_vec()).expect("UTF-8 plan");
        for retained in [
            "prove the exact macOS command bridge",
            "grant-macos-command-plan",
            "worker-macos-command-plan",
            "runner-session-macos-command-plan",
            "effect-macos-command-plan",
            "helper_binary_digest",
            "singleton_journal_root_identity",
            "helper_journal_reference_bytes",
            "disabled_until_live_core_claim_and_signed_native_hold_proof",
        ] {
            assert!(encoded.contains(retained), "plan lost {retained}");
        }

        let mut alternate = plan.canonical_bytes().to_vec();
        alternate.push(b' ');
        assert!(ValidatedMacosProductionCommandPlanV1::decode_exact(&alternate).is_err());

        let mut crossed = plan.canonical_bytes().to_vec();
        let needle = b"runner-session-macos-command-plan";
        let position = crossed
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("session identity occurs in plan");
        crossed[position] = b'R';
        assert!(ValidatedMacosProductionCommandPlanV1::decode_exact(&crossed).is_err());
    }

    #[test]
    fn singleton_commit_is_global_across_restart_and_rejects_effect_substitution() {
        let fixture = Fixture::new("global-effect-history");
        let (plan, authority) = fixture.plan_and_authority("test", "effect-macos-global");
        let exact = plan.clone();
        let journaled =
            journal_macos_production_command_plan(plan, authority).expect("commit complete plan");
        assert!(!JournaledMacosProductionCommandPlanV1::permits_execution());
        assert!(!JournaledMacosProductionCommandPlanV1::permits_release());
        drop(journaled);

        let repeated = expect_error(
            journal_macos_production_command_plan(
                exact,
                fixture.service_authority().expect("reopen authority"),
            ),
            "same effect cannot regain authority after restart",
        );
        assert_eq!(
            repeated.class(),
            MacosServiceCommandJournalFailureClass::PriorEffectCommitted
        );

        let (substituted, authority) = fixture.plan_and_authority("check", "effect-macos-global");
        let substitution = expect_error(
            journal_macos_production_command_plan(substituted, authority),
            "same effect with another plan must fail closed",
        );
        assert_eq!(
            substitution.class(),
            MacosServiceCommandJournalFailureClass::EffectSubstitution
        );
    }

    #[test]
    fn exact_synced_prepublication_temp_is_removed_but_crossed_or_partial_temp_quarantines() {
        let fixture = Fixture::new("exact-temp-recovery");
        let (plan, mut authority) = fixture.plan_and_authority("test", "effect-macos-temp-exact");
        authority.inject_next_failure(TestCommandPlanFailurePoint::BeforePublish);
        let error = expect_error(
            journal_macos_production_command_plan(plan.clone(), authority),
            "prepublication response is not durable",
        );
        assert_eq!(
            error.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );
        let callbacks = AtomicUsize::new(0);
        journal_with_test_callback(
            plan,
            fixture.service_authority().expect("reopen exact temp"),
            &callbacks,
        )
        .expect("exact temp is safely removed and republished");
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);

        let partial = Fixture::new("partial-temp-quarantine");
        let (plan, mut authority) = partial.plan_and_authority("test", "effect-macos-temp-partial");
        authority.inject_next_failure(TestCommandPlanFailurePoint::PartialWrite);
        expect_error(
            journal_macos_production_command_plan(plan.clone(), authority),
            "partial write must fail",
        );
        let callbacks = AtomicUsize::new(0);
        let error = expect_error(
            journal_with_test_callback(
                plan,
                partial.service_authority().expect("reopen partial temp"),
                &callbacks,
            ),
            "partial temp cannot be removed as exact",
        );
        assert_eq!(
            error.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);

        let crossed = Fixture::new("crossed-temp-quarantine");
        let (original, mut authority) =
            crossed.plan_and_authority("test", "effect-macos-temp-crossed");
        authority.inject_next_failure(TestCommandPlanFailurePoint::BeforePublish);
        expect_error(
            journal_macos_production_command_plan(original, authority),
            "leave exact temp for original plan",
        );
        let (different, authority) =
            crossed.plan_and_authority("check", "effect-macos-temp-crossed");
        let error = expect_error(
            journal_macos_production_command_plan(different, authority),
            "crossed temp must quarantine",
        );
        assert_eq!(
            error.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );
    }

    #[test]
    fn unlock_failure_cannot_broaden_a_proven_prepublication_cut_to_ambiguous() {
        let fixture = Fixture::new("prepublication-unlock-failure");
        let (plan, mut authority) =
            fixture.plan_and_authority("test", "effect-macos-prepublication-unlock");
        authority.inject_next_failure(TestCommandPlanFailurePoint::BeforePublish);
        authority.inject_next_unlock_failure();
        let callbacks = AtomicUsize::new(0);
        let error = expect_error(
            journal_with_test_callback(plan.clone(), authority, &callbacks),
            "prepublication cut plus unlock failure must not commit",
        );
        assert_eq!(
            error.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);

        journal_macos_production_command_plan(
            plan,
            fixture
                .service_authority()
                .expect("reopen exact prepublication temporary"),
        )
        .expect("exact prepublication temporary remains safely recoverable");
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn every_post_publication_cut_is_ambiguous_and_never_invokes_the_callback() {
        for (index, point) in [
            TestCommandPlanFailurePoint::AfterPublish,
            TestCommandPlanFailurePoint::AfterDirectorySync,
            TestCommandPlanFailurePoint::Readback,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Fixture::new(&format!("post-publication-{index}"));
            let (plan, mut authority) = fixture
                .plan_and_authority("test", &format!("effect-macos-post-publication-{index}"));
            authority.inject_next_failure(point);
            let callbacks = AtomicUsize::new(0);
            let error = expect_error(
                journal_with_test_callback(plan.clone(), authority, &callbacks),
                "post-publication cut must be ambiguous",
            );
            assert_eq!(
                error.class(),
                MacosServiceCommandJournalFailureClass::Ambiguous
            );
            assert_eq!(callbacks.load(Ordering::SeqCst), 0);

            let restart = expect_error(
                journal_with_test_callback(
                    plan,
                    fixture.service_authority().expect("reopen published plan"),
                    &callbacks,
                ),
                "restart must not replay a published effect",
            );
            assert_eq!(
                restart.class(),
                MacosServiceCommandJournalFailureClass::PriorEffectCommitted
            );
            assert_eq!(callbacks.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn parallel_service_root_legacy_version_and_multiple_temps_fail_closed() {
        let first = Fixture::new("service-root-first");
        let second = Fixture::new("service-root-second");
        let (plan, _first_authority) =
            first.plan_and_authority("test", "effect-macos-crossed-service");
        let crossed = expect_error(
            journal_macos_production_command_plan(
                plan,
                second.service_authority().expect("open parallel authority"),
            ),
            "parallel service authority cannot consume another plan",
        );
        assert_eq!(
            crossed.class(),
            MacosServiceCommandJournalFailureClass::NotCommitted
        );

        fs::create_dir(
            first
                .directory
                .service_state
                .join(LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY),
        )
        .expect("create legacy journal marker");
        fs::set_permissions(
            first
                .directory
                .service_state
                .join(LEGACY_SERVICE_COMMAND_JOURNAL_DIRECTORY),
            fs::Permissions::from_mode(0o700),
        )
        .expect("set legacy marker mode");
        let legacy = expect_error(
            first.service_authority(),
            "legacy journal cannot be interpreted as v1",
        );
        assert_eq!(
            legacy.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );

        let multiple = Fixture::new("multiple-temps");
        let (plan, mut authority) =
            multiple.plan_and_authority("test", "effect-macos-multiple-temps");
        authority.inject_next_failure(TestCommandPlanFailurePoint::BeforePublish);
        expect_error(
            journal_macos_production_command_plan(plan, authority),
            "leave first exact temp",
        );
        let second_temp = format!(".{PLAN_PREFIX}{}{PLAN_SUFFIX}{TEMP_SUFFIX}", digest(222));
        write_owner_private(
            &multiple.directory.command_journal.join(second_temp),
            b"crossed",
        );
        let multiple_error = expect_error(
            multiple.service_authority(),
            "multiple temps quarantine the singleton journal",
        );
        assert_eq!(
            multiple_error.class(),
            MacosServiceCommandJournalFailureClass::RecoveryRequired
        );
    }

    #[test]
    fn durable_held_child_handoff_retains_the_full_plan_and_can_only_enter_cleanup() {
        let fixture = Fixture::new("held-cleanup-handoff");
        let (plan, authority) = fixture.plan_and_authority("test", "effect-macos-held-cleanup");
        let exact_plan_bytes = plan.canonical_bytes().to_vec();
        let helper_request = plan.helper_request().clone();
        let journaled = journal_macos_production_command_plan(plan, authority)
            .expect("durably commit complete plan");
        let held_receipt = fixture.held_receipt(&helper_request);
        let prepared = journaled
            .bind_durable_held_preparation(held_receipt)
            .expect("bind exact durable HeldPrepared generation");
        assert!(!NonAdmissibleMacosPreparedChildHandoffV1::permits_execution());
        assert!(!NonAdmissibleMacosPreparedChildHandoffV1::permits_release());
        assert_eq!(prepared.exact_plan_bytes(), exact_plan_bytes);

        let cleanup = prepared
            .into_cleanup_only_handoff(MacosTerminationReason::Canceled)
            .expect("derive cleanup-only lossless handoff");
        assert!(!MacosCleanupOnlyHandoffV1::permits_release());
        assert!(MacosCleanupOnlyHandoffV1::requires_native_uid_cleanup());
        assert_eq!(
            cleanup.required_cleaning_record().state,
            MacosHelperJournalState::Cleaning
        );
        assert_eq!(cleanup.exact_plan_bytes(), exact_plan_bytes);
        assert_eq!(
            cleanup.handoff_digest(),
            &Digest::sha256(cleanup.canonical_bytes())
        );
    }

    #[test]
    fn durable_held_receipt_from_another_helper_store_cannot_cross_the_plan() {
        let first = Fixture::new("held-cross-first");
        let second = Fixture::new("held-cross-second");
        let (plan, authority) = first.plan_and_authority("test", "effect-macos-held-cross");
        let other_binding = second
            .service_authority()
            .expect("open second binding")
            .binding()
            .clone();
        let other_plan = second.plan("test", "effect-macos-held-cross-other", other_binding);
        let crossed_receipt = second.held_receipt(other_plan.helper_request());
        let journaled = journal_macos_production_command_plan(plan, authority)
            .expect("commit first complete plan");
        let error = expect_error(
            journaled.bind_durable_held_preparation(crossed_receipt),
            "helper-store substitution must fail",
        );
        assert_eq!(
            error.class(),
            MacosServiceCommandJournalFailureClass::NotCommitted
        );
    }
}
