//! Exact command-domain cleanup joins derived from durable runner effects.
//!
//! The retained native proof is opaque to core. A trusted desktop boundary
//! must validate it before persistence and again before relying on readback.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::{
    EventLedger, LedgerError, StoredEffectIntent, decode_stored, encode,
    ensure_sprint_not_terminal, load_effect_from_with_receipts, load_effect_intent_row,
    load_effect_request_payload, load_effect_runner_binding, load_event_by_id,
    load_runner_launch_intent_from, load_runner_session_policy_from, reference_mismatch,
    require_contract_version, secure_database_files, sqlite_integer, unsigned_integer,
    validate_effect_proposal_event_shape, validate_finish_effect_kind,
    validate_stored_event_causation, worker_lease_authority, worker_lease_encoding_matches,
};
use crate::{
    AgentEvent, CONTRACT_VERSION, ContractError, Digest, EffectIntent, EffectKind, EffectOutcome,
    PersistedEffect, RunnerLaunchIntent, RunnerSessionPolicyRecord, RunnerSessionPurpose,
};

/// Maximum opaque runner-native proof bytes retained for one command effect.
pub const MAX_COMMAND_DOMAIN_PLATFORM_PROOF_BYTES: usize = 1_048_576;
/// Maximum `RunCommand` effects accepted for one registered runner session.
pub const MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION: usize = 1_024;

/// Schema v11 adds a neutral per-command cleanup proof join. It does not
/// replace or weaken any v1-v10 object.
pub(super) const MIGRATION_V11: &str = r"
    CREATE TABLE command_domain_cleanup_proofs (
        proof_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        launch_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        effect_id TEXT NOT NULL UNIQUE,
        observation_id TEXT UNIQUE,
        request_digest TEXT NOT NULL,
        backend TEXT NOT NULL CHECK (
            backend IN ('MacOsDedicatedIdentity', 'LinuxCgroupV2')
        ),
        disposition TEXT NOT NULL CHECK (
            disposition IN ('ReapedZeroSurvivors', 'NoDomainCreatedBeforeEffect')
        ),
        surviving_processes INTEGER NOT NULL CHECK (surviving_processes = 0),
        platform_proof_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        cleaned_at_unix_ms INTEGER NOT NULL CHECK (cleaned_at_unix_ms > 0),
        platform_proof_bytes BLOB NOT NULL CHECK (
            length(platform_proof_bytes) BETWEEN 1 AND 1048576
        ),
        proof_json BLOB NOT NULL CHECK (length(proof_json) > 0),
        UNIQUE (sprint_id, effect_id),
        UNIQUE (sprint_id, proof_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, launch_id)
            REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, session_id)
            REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT,
        FOREIGN KEY (observation_id)
            REFERENCES effect_observations(observation_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX command_domain_cleanup_proofs_session_idx
    ON command_domain_cleanup_proofs (
        sprint_id, launch_id, session_id, effect_id
    );

    CREATE TRIGGER command_domain_cleanup_proofs_no_update
    BEFORE UPDATE ON command_domain_cleanup_proofs
    BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proofs are immutable'); END;
    CREATE TRIGGER command_domain_cleanup_proofs_no_delete
    BEFORE DELETE ON command_domain_cleanup_proofs
    BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proofs are immutable'); END;

    CREATE TRIGGER command_domain_cleanup_proof_requires_exact_effect
    BEFORE INSERT ON command_domain_cleanup_proofs
    WHEN EXISTS (
        SELECT 1 FROM sprint_completion_proof_states
        WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_non_success_terminal_outcomes
        WHERE sprint_id = NEW.sprint_id
    ) OR EXISTS (
        SELECT 1 FROM sprint_terminal_states
        WHERE sprint_id = NEW.sprint_id
    ) OR NOT EXISTS (
        SELECT 1
        FROM effect_intents intent
        JOIN effect_request_payloads request
          ON request.effect_id = intent.effect_id
         AND request.sprint_id = intent.sprint_id
        JOIN effect_session_bindings binding
          ON binding.effect_id = intent.effect_id
         AND binding.sprint_id = intent.sprint_id
        JOIN runner_launch_intents launch
          ON launch.launch_id = binding.launch_id
         AND launch.sprint_id = binding.sprint_id
        JOIN runner_session_policies session
          ON session.session_id = binding.session_id
         AND session.sprint_id = binding.sprint_id
         AND session.launch_id = launch.launch_id
        LEFT JOIN effect_observations observation
          ON observation.effect_id = intent.effect_id
         AND observation.sprint_id = intent.sprint_id
        LEFT JOIN effect_evidence_payloads evidence
          ON evidence.effect_id = intent.effect_id
         AND evidence.sprint_id = intent.sprint_id
        WHERE intent.effect_id = NEW.effect_id
          AND intent.sprint_id = NEW.sprint_id
          AND intent.effect_kind = 'RunCommand'
          AND intent.request_digest = NEW.request_digest
          AND request.request_digest = NEW.request_digest
          AND binding.launch_id = NEW.launch_id
          AND binding.session_id = NEW.session_id
          AND launch.session_id = NEW.session_id
          AND session.purpose IN ('TaskWorker', 'FinalVerifier')
          AND NEW.observation_id IS observation.observation_id
          AND (
              observation.observation_id IS NULL
              OR (evidence.observation_id = observation.observation_id
                  AND evidence.evidence_digest = observation.evidence_digest)
          )
          AND (
              NEW.disposition = 'ReapedZeroSurvivors'
              OR (NEW.disposition = 'NoDomainCreatedBeforeEffect'
                  AND observation.outcome IN (
                      'FailedBeforeEffect', 'CancelledBeforeEffect'
                  ))
          )
          AND (
              observation.outcome IS NULL
              OR observation.outcome IN (
                  'Succeeded', 'FailedBeforeEffect', 'FailedAfterKnownEffect',
                  'CancelledBeforeEffect', 'Unknown'
              )
          )
          AND session.registered_at_unix_ms <= NEW.cleaned_at_unix_ms
          AND intent.created_at_unix_ms <= NEW.cleaned_at_unix_ms
          AND COALESCE(observation.observed_at_unix_ms,
                       intent.created_at_unix_ms) <= NEW.cleaned_at_unix_ms
    )
    BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proof must bind one exact command lifecycle'); END;

    CREATE TRIGGER command_domain_cleanup_proof_backend_consistent
    BEFORE INSERT ON command_domain_cleanup_proofs
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs proof
        WHERE proof.sprint_id = NEW.sprint_id
          AND proof.launch_id = NEW.launch_id
          AND proof.session_id = NEW.session_id
          AND proof.backend != NEW.backend
    )
    BEGIN SELECT RAISE(ABORT, 'one runner session cannot mix command-domain backends'); END;

    CREATE TRIGGER command_domain_cleanup_proof_set_bound
    BEFORE INSERT ON command_domain_cleanup_proofs
    WHEN (
        SELECT COUNT(*) FROM command_domain_cleanup_proofs proof
        WHERE proof.sprint_id = NEW.sprint_id
          AND proof.launch_id = NEW.launch_id
          AND proof.session_id = NEW.session_id
    ) >= 1024
    BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proof set exceeds its hard bound'); END;

    CREATE TRIGGER command_domain_cleanup_proof_id_global_unique
    BEFORE INSERT ON command_domain_cleanup_proofs
    WHEN EXISTS (SELECT 1 FROM finish_receipt_ids WHERE receipt_id = NEW.proof_id)
      OR EXISTS (SELECT 1 FROM verification_receipts WHERE receipt_id = NEW.proof_id)
      OR EXISTS (SELECT 1 FROM acceptance_receipts WHERE receipt_id = NEW.proof_id)
      OR EXISTS (SELECT 1 FROM completion_receipts WHERE receipt_id = NEW.proof_id)
      OR EXISTS (SELECT 1 FROM v9_completion_receipts WHERE receipt_id = NEW.proof_id)
      OR EXISTS (
          SELECT 1 FROM post_completion_rollback_receipt_ids
          WHERE receipt_id = NEW.proof_id
      )
    BEGIN SELECT RAISE(ABORT, 'command-domain cleanup proof identity must be globally unique'); END;

    CREATE TRIGGER finish_receipt_ids_command_domain_unique
    BEFORE INSERT ON finish_receipt_ids
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER verification_receipts_command_domain_unique
    BEFORE INSERT ON verification_receipts
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER acceptance_receipts_command_domain_unique
    BEFORE INSERT ON acceptance_receipts
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER completion_receipts_command_domain_unique
    BEFORE INSERT ON completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER v9_completion_receipts_command_domain_unique
    BEFORE INSERT ON v9_completion_receipts
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
    CREATE TRIGGER post_completion_receipts_command_domain_unique
    BEFORE INSERT ON post_completion_rollback_receipt_ids
    WHEN EXISTS (
        SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = NEW.receipt_id
    )
    BEGIN SELECT RAISE(ABORT, 'receipt identity must be globally unique'); END;
";

/// Closed native command-accounting backend understood by the desktop trust
/// boundary. Core does not validate either native proof format.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CommandDomainBackend {
    /// Dedicated macOS operating-system identity accounting.
    MacOsDedicatedIdentity,
    /// Delegated Linux cgroup-v2 accounting.
    LinuxCgroupV2,
}

impl CommandDomainBackend {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::MacOsDedicatedIdentity => "MacOsDedicatedIdentity",
            Self::LinuxCgroupV2 => "LinuxCgroupV2",
        }
    }
}

/// Closed durable state of one bound `RunCommand` effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CommandDomainEffectState {
    /// No effect observation is durable yet.
    AwaitingObservation,
    /// The command result is durably successful.
    Succeeded,
    /// Evidence proves the effect did not begin.
    FailedBeforeEffect,
    /// The command ran and later failed with a known result.
    FailedAfterKnownEffect,
    /// Cancellation completed before the effect began.
    CancelledBeforeEffect,
    /// The command result remains unprovable.
    Unknown,
}

impl CommandDomainEffectState {
    const fn unresolved(self) -> bool {
        matches!(self, Self::AwaitingObservation | Self::Unknown)
    }
}

/// Exact durable command binding derived from the ordinary effect ledger.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDomainEffectBinding {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn runner launch.
    pub launch_id: String,
    /// Exact initialized runner session.
    pub session_id: String,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Digest of the exact canonical command request bytes.
    pub request_digest: Digest,
    /// Exact terminal observation, absent while unresolved before observation.
    pub observation_id: Option<String>,
    /// Closed durable effect state.
    pub state: CommandDomainEffectState,
    /// Observation time, absent exactly with `AwaitingObservation`.
    pub finalized_at_unix_ms: Option<u64>,
}

impl CommandDomainEffectBinding {
    /// Validates the self-contained derived binding shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// or inconsistent observation state and timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "command_domain_effect_binding.contract_version",
        )?;
        require_text("command_domain_effect_binding.sprint_id", &self.sprint_id)?;
        require_text("command_domain_effect_binding.launch_id", &self.launch_id)?;
        require_text("command_domain_effect_binding.session_id", &self.session_id)?;
        require_text("command_domain_effect_binding.effect_id", &self.effect_id)?;
        match (
            self.state,
            self.observation_id.as_deref(),
            self.finalized_at_unix_ms,
        ) {
            (CommandDomainEffectState::AwaitingObservation, None, None) => Ok(()),
            (CommandDomainEffectState::AwaitingObservation, _, _) => Err(contract_error(
                "command_domain_effect_binding.state",
                "awaiting observation must not claim an observation identity or time",
            )),
            (_, Some(observation_id), Some(finalized_at)) => {
                require_text(
                    "command_domain_effect_binding.observation_id",
                    observation_id,
                )?;
                require_time(
                    "command_domain_effect_binding.finalized_at_unix_ms",
                    finalized_at,
                )
            }
            _ => Err(contract_error(
                "command_domain_effect_binding.state",
                "terminal effect state requires an observation identity and time",
            )),
        }
    }
}

/// Closed resource-cleanup claim carried by one native platform proof.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CommandDomainCleanupDisposition {
    /// A previously allocated domain was reaped and observed with zero members.
    ReapedZeroSurvivors,
    /// Native evidence proves no accounting domain or target process was made.
    NoDomainCreatedBeforeEffect,
}

impl CommandDomainCleanupDisposition {
    const fn storage_name(self) -> &'static str {
        match self {
            Self::ReapedZeroSurvivors => "ReapedZeroSurvivors",
            Self::NoDomainCreatedBeforeEffect => "NoDomainCreatedBeforeEffect",
        }
    }
}

/// Opaque, digest-bound platform proof for one exact command lifecycle.
///
/// Core validates all durable relationships but deliberately does not validate
/// the native proof format or direct runner exit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDomainCleanupProof {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Globally unique proof identity.
    pub proof_id: String,
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn launch.
    pub launch_id: String,
    /// Exact initialized session.
    pub session_id: String,
    /// Exact `RunCommand` effect.
    pub effect_id: String,
    /// Exact effect observation, absent only when no observation is durable.
    pub observation_id: Option<String>,
    /// Digest of the exact canonical command request.
    pub request_digest: Digest,
    /// Native accounting backend whose proof was validated by desktop.
    pub backend: CommandDomainBackend,
    /// Exact resource-cleanup claim.
    pub disposition: CommandDomainCleanupDisposition,
    /// Observed survivors; always zero for retained authority.
    pub surviving_processes: u64,
    /// Digest of the opaque native proof bytes.
    pub platform_proof_digest: Digest,
    /// Exact bounded opaque native proof bytes.
    pub platform_proof_bytes: Vec<u8>,
    /// Time after domain cleanup/no-domain validation completed.
    pub cleaned_at_unix_ms: u64,
}

impl CommandDomainCleanupProof {
    /// Validates the self-contained proof envelope and byte authentication.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an invalid identity, nonzero survivor
    /// count, empty/oversized proof, digest mismatch, or zero timestamp.
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(
            self.contract_version,
            "command_domain_cleanup_proof.contract_version",
        )?;
        require_text("command_domain_cleanup_proof.proof_id", &self.proof_id)?;
        require_text("command_domain_cleanup_proof.sprint_id", &self.sprint_id)?;
        require_text("command_domain_cleanup_proof.launch_id", &self.launch_id)?;
        require_text("command_domain_cleanup_proof.session_id", &self.session_id)?;
        require_text("command_domain_cleanup_proof.effect_id", &self.effect_id)?;
        if let Some(observation_id) = &self.observation_id {
            require_text(
                "command_domain_cleanup_proof.observation_id",
                observation_id,
            )?;
        }
        if self.surviving_processes != 0 {
            return Err(contract_error(
                "command_domain_cleanup_proof.surviving_processes",
                "must be zero",
            ));
        }
        if self.platform_proof_bytes.is_empty()
            || self.platform_proof_bytes.len() > MAX_COMMAND_DOMAIN_PLATFORM_PROOF_BYTES
        {
            return Err(contract_error(
                "command_domain_cleanup_proof.platform_proof_bytes",
                format!("must contain 1..={MAX_COMMAND_DOMAIN_PLATFORM_PROOF_BYTES} bytes"),
            ));
        }
        if Digest::sha256(&self.platform_proof_bytes) != self.platform_proof_digest {
            return Err(contract_error(
                "command_domain_cleanup_proof.platform_proof_bytes",
                "digest does not authenticate the exact retained native proof",
            ));
        }
        require_time(
            "command_domain_cleanup_proof.cleaned_at_unix_ms",
            self.cleaned_at_unix_ms,
        )
    }
}

/// Fully revalidated binding and its exact durable cleanup proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedCommandDomainCleanup {
    /// Ledger-derived exact command binding.
    pub binding: CommandDomainEffectBinding,
    /// Canonical retained cleanup proof.
    pub proof: CommandDomainCleanupProof,
}

/// Complete exact proof set for one launch/session and expected backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteCommandDomainCleanupSet {
    /// Owning sprint.
    pub sprint_id: String,
    /// Exact pre-spawn launch.
    pub launch_id: String,
    /// Exact initialized session.
    pub session_id: String,
    /// Required native backend.
    pub backend: CommandDomainBackend,
    /// Effect-sorted exact binding/proof set.
    pub entries: Vec<PersistedCommandDomainCleanup>,
}

/// Closed reason the exact command cleanup set is not authoritative yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDomainCleanupIncomplete {
    /// One or more exact effects have no cleanup proof.
    MissingProofs {
        /// Strictly sorted missing effect identities.
        effect_ids: Vec<String>,
    },
    /// Cleanup may be proven, but one or more effect outcomes remain unresolved.
    EffectOutcomeUnresolved {
        /// Strictly sorted unobserved or `Unknown` effect identities.
        effect_ids: Vec<String>,
    },
    /// Both proof and outcome gaps exist.
    MissingProofsAndEffectOutcomeUnresolved {
        /// Strictly sorted missing proof identities.
        missing_effect_ids: Vec<String>,
        /// Strictly sorted unresolved outcome identities.
        unresolved_effect_ids: Vec<String>,
    },
}

/// Closed completeness decision derived solely from durable ledger state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDomainCleanupCompleteness {
    /// Every exact command has a matching proof and a known non-Unknown result.
    Complete(CompleteCommandDomainCleanupSet),
    /// The set cannot authorize aggregate cleanup or completion.
    Incomplete(CommandDomainCleanupIncomplete),
}

impl EventLedger {
    /// Derives the complete exact effect-sorted `RunCommand` binding set for
    /// one launch/session from durable effect and session records.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the lifecycle is absent, cross-bound,
    /// corrupt, non-command, or exceeds the hard per-session effect bound.
    pub fn load_command_domain_effect_bindings(
        &self,
        sprint_id: &str,
        launch_id: &str,
        session_id: &str,
    ) -> Result<Vec<CommandDomainEffectBinding>, LedgerError> {
        load_command_domain_effect_bindings_from(&self.connection, sprint_id, launch_id, session_id)
    }

    /// Atomically records and reopens one opaque desktop-revalidated native
    /// cleanup proof. Exact replay is idempotent.
    ///
    /// Resource cleanup may be retained for an unobserved or `Unknown` effect,
    /// but only `ReapedZeroSurvivors` is admissible in that state and the
    /// completeness decision remains incomplete.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] for an invalid/crossed binding, substituted
    /// request or observation, backend confusion, unsafe disposition, early
    /// timestamp, duplicate identity, terminal sprint, corruption, or storage
    /// failure.
    pub fn record_command_domain_cleanup_proof(
        &mut self,
        proof: &CommandDomainCleanupProof,
    ) -> Result<PersistedCommandDomainCleanup, LedgerError> {
        self.require_writable()?;
        proof.validate()?;
        if let Some(existing) =
            load_command_domain_cleanup_by_effect_optional(&self.connection, &proof.effect_id)?
        {
            if existing.proof == *proof {
                return Ok(existing);
            }
            return Err(reference_mismatch(
                "command-domain cleanup proof",
                "effect already has a different immutable proof",
            ));
        }
        let proof_json = encode("command-domain cleanup proof", proof)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_sprint_not_terminal(&transaction, &proof.sprint_id)?;
        let binding = validate_command_domain_cleanup_proof(&transaction, proof)?;
        if binding.observation_id.is_some() && proof.observation_id != binding.observation_id {
            return Err(reference_mismatch(
                "command-domain cleanup proof",
                "a newly retained proof after result persistence must bind the exact observation identity",
            ));
        }
        ensure_command_domain_proof_id_available(&transaction, &proof.proof_id)?;
        let existing_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM command_domain_cleanup_proofs
             WHERE sprint_id = ?1 AND launch_id = ?2 AND session_id = ?3",
            params![proof.sprint_id, proof.launch_id, proof.session_id],
            |row| row.get(0),
        )?;
        if usize::try_from(existing_count)
            .ok()
            .is_none_or(|count| count >= MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION)
        {
            return Err(reference_mismatch(
                "command-domain cleanup proof set",
                "hard per-session proof bound would be exceeded",
            ));
        }
        insert_command_domain_cleanup_proof_row(&transaction, proof, &proof_json)?;
        transaction
            .commit()
            .map_err(|error| LedgerError::PostCommitStateUncertain {
                operation: "command-domain cleanup proof",
                recovery_id: proof.effect_id.clone(),
                detail: error.to_string(),
            })?;
        secure_database_files(&self.database_path).map_err(|error| {
            LedgerError::PostCommitStateUncertain {
                operation: "command-domain cleanup proof",
                recovery_id: proof.effect_id.clone(),
                detail: error.to_string(),
            }
        })?;
        let persisted = load_command_domain_cleanup_by_effect(&self.connection, &proof.effect_id)
            .map_err(|error| LedgerError::PostCommitStateUncertain {
            operation: "command-domain cleanup proof",
            recovery_id: proof.effect_id.clone(),
            detail: error.to_string(),
        })?;
        if persisted.binding != binding {
            return Err(LedgerError::PostCommitStateUncertain {
                operation: "command-domain cleanup proof",
                recovery_id: proof.effect_id.clone(),
                detail: "post-commit binding changed during canonical readback".into(),
            });
        }
        Ok(persisted)
    }

    /// Loads and fully revalidates the cleanup proof for one command effect.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the proof is absent, corrupt, crossed, or
    /// disagrees with the exact effect lifecycle.
    pub fn load_command_domain_cleanup_proof(
        &self,
        effect_id: &str,
    ) -> Result<PersistedCommandDomainCleanup, LedgerError> {
        load_command_domain_cleanup_by_effect(&self.connection, effect_id)
    }

    /// Computes the exact cleanup completeness decision for one runner
    /// launch/session and expected native backend.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] for an absent/crossed lifecycle, extra or
    /// duplicate proof, backend confusion, request substitution, bound
    /// violation, or any corrupt durable artifact.
    pub fn load_command_domain_cleanup_completeness(
        &self,
        sprint_id: &str,
        launch_id: &str,
        session_id: &str,
        backend: CommandDomainBackend,
    ) -> Result<CommandDomainCleanupCompleteness, LedgerError> {
        load_command_domain_cleanup_completeness_from(
            &self.connection,
            sprint_id,
            launch_id,
            session_id,
            backend,
        )
    }
}

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'command_domain_cleanup_proofs'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(LedgerError::from)
}

fn insert_command_domain_cleanup_proof_row(
    transaction: &Transaction<'_>,
    proof: &CommandDomainCleanupProof,
    proof_json: &[u8],
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO command_domain_cleanup_proofs (
            proof_id, sprint_id, launch_id, session_id, effect_id,
            observation_id, request_digest, backend, disposition,
            surviving_processes, platform_proof_digest, contract_version,
            cleaned_at_unix_ms, platform_proof_bytes, proof_json
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
            ?13, ?14, ?15
         )",
        params![
            proof.proof_id,
            proof.sprint_id,
            proof.launch_id,
            proof.session_id,
            proof.effect_id,
            proof.observation_id,
            proof.request_digest.as_str(),
            proof.backend.storage_name(),
            proof.disposition.storage_name(),
            i64::try_from(proof.surviving_processes)
                .map_err(|_| LedgerError::IntegerOutOfRange("command-domain survivors"))?,
            proof.platform_proof_digest.as_str(),
            i64::from(proof.contract_version),
            sqlite_integer(
                "command_domain_cleanup_proof.cleaned_at_unix_ms",
                proof.cleaned_at_unix_ms,
            )?,
            &proof.platform_proof_bytes,
            proof_json,
        ],
    )?;
    Ok(())
}

/// Inserts a command-domain proof inside an owning atomic terminal
/// transaction after its exact observation row has been staged.
pub(super) fn insert_atomic_command_domain_cleanup_proof(
    transaction: &Transaction<'_>,
    proof: &CommandDomainCleanupProof,
) -> Result<(), LedgerError> {
    proof.validate()?;
    ensure_sprint_not_terminal(transaction, &proof.sprint_id)?;
    let binding = validate_command_domain_cleanup_proof(transaction, proof)?;
    if binding.observation_id.as_deref() != proof.observation_id.as_deref() {
        return Err(reference_mismatch(
            "command-domain cleanup proof",
            "atomic proof must bind the exact staged command observation",
        ));
    }
    ensure_command_domain_proof_id_available(transaction, &proof.proof_id)?;
    let existing_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM command_domain_cleanup_proofs
         WHERE sprint_id = ?1 AND launch_id = ?2 AND session_id = ?3",
        params![proof.sprint_id, proof.launch_id, proof.session_id],
        |row| row.get(0),
    )?;
    if usize::try_from(existing_count)
        .ok()
        .is_none_or(|count| count >= MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION)
    {
        return Err(reference_mismatch(
            "command-domain cleanup proof set",
            "hard per-session proof bound would be exceeded",
        ));
    }
    let proof_json = encode("command-domain cleanup proof", proof)?;
    insert_command_domain_cleanup_proof_row(transaction, proof, &proof_json)
}

fn load_command_domain_effect_bindings_from(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
) -> Result<Vec<CommandDomainEffectBinding>, LedgerError> {
    validate_command_domain_session(connection, sprint_id, launch_id, session_id)?;
    let mut statement = connection.prepare(
        "SELECT binding.effect_id, binding.session_id
         FROM effect_session_bindings binding
         JOIN effect_intents intent ON intent.effect_id = binding.effect_id
         WHERE binding.sprint_id = ?1 AND binding.launch_id = ?2
           AND intent.effect_kind = 'RunCommand'
         ORDER BY binding.effect_id",
    )?;
    let rows = statement
        .query_map(params![sprint_id, launch_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION {
        return Err(reference_mismatch(
            "command-domain effect binding set",
            "hard per-session effect bound is exceeded",
        ));
    }
    let mut bindings = Vec::with_capacity(rows.len());
    for (effect_id, stored_session_id) in rows {
        if stored_session_id.as_deref() != Some(session_id) {
            return Err(LedgerError::Corrupt {
                entity: "command-domain effect binding set",
                detail: format!("command effect '{effect_id}' is crossed to another session"),
            });
        }
        let effect = load_effect_from_with_receipts(connection, &effect_id, false)?;
        if effect.intent.kind != EffectKind::RunCommand || effect.intent.sprint_id != sprint_id {
            return Err(LedgerError::Corrupt {
                entity: "command-domain effect binding set",
                detail: "indexed command binding disagrees with its effect".into(),
            });
        }
        let runner = load_effect_runner_binding(connection, &effect.intent)?;
        let session = runner.session.ok_or_else(|| LedgerError::Corrupt {
            entity: "command-domain effect binding set",
            detail: "RunCommand is not bound to an initialized session".into(),
        })?;
        if runner.launch.launch_id != launch_id || session.session_id != session_id {
            return Err(LedgerError::Corrupt {
                entity: "command-domain effect binding set",
                detail: "effect readback disagrees with requested launch/session".into(),
            });
        }
        let (state, observation_id, finalized_at_unix_ms) =
            command_domain_effect_state(effect.observation.as_ref());
        let binding = CommandDomainEffectBinding {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint_id.to_owned(),
            launch_id: launch_id.to_owned(),
            session_id: session_id.to_owned(),
            effect_id: effect.intent.effect_id,
            request_digest: effect.intent.request_digest,
            observation_id,
            state,
            finalized_at_unix_ms,
        };
        binding.validate().map_err(|error| LedgerError::Corrupt {
            entity: "command-domain effect binding set",
            detail: error.to_string(),
        })?;
        bindings.push(binding);
    }
    Ok(bindings)
}

struct StaticTaskDoneCommandEffect {
    intent: EffectIntent,
    request_bytes: Vec<u8>,
    proposed_event: AgentEvent,
}

/// Revalidates the immutable command authority needed by `TaskDone` without
/// re-entering typed finish-receipt derivation. The caller supplies effects
/// already loaded through the complete no-finish lifecycle path, so terminal
/// observations, evidence, dispatch claims, and mutation links remain covered
/// exactly once before this static join is admitted.
fn load_task_done_static_command_effect(
    connection: &Connection,
    effect_id: &str,
    sprint_id: &str,
    launch: &RunnerLaunchIntent,
    session: &RunnerSessionPolicyRecord,
) -> Result<StaticTaskDoneCommandEffect, LedgerError> {
    let StoredEffectIntent {
        intent,
        intent_json,
        proposed_event_id,
        sprint_id: indexed_sprint_id,
        task_id,
        worker_id,
        causation_event_id,
        idempotency_key,
        correlation_id,
        effect_kind,
        request_digest,
        policy_hash,
        input_snapshot,
        created_at_unix_ms,
        worker_lease_id,
        worker_lease_epoch,
    } = load_effect_intent_row(connection, effect_id)?;
    let stored_created_at =
        unsigned_integer("effect_intent.created_at_unix_ms", created_at_unix_ms)?;
    validate_finish_effect_kind(connection, &intent, &effect_kind)?;
    if intent.effect_id != effect_id
        || !worker_lease_encoding_matches(
            connection,
            &intent.sprint_id,
            "effect intent",
            &intent,
            &intent_json,
        )?
        || intent.sprint_id != indexed_sprint_id
        || intent.task_id != task_id
        || intent.worker_id != worker_id
        || intent.causation_event_id != causation_event_id
        || intent.idempotency_key != idempotency_key
        || intent.correlation_id != correlation_id
        || intent.request_digest.as_str() != request_digest
        || intent.policy_hash.as_str() != policy_hash
        || intent.input_snapshot.as_str() != input_snapshot
        || intent.created_at_unix_ms != stored_created_at
        || !worker_lease_authority::indexed_binding_matches(
            intent.worker_lease.as_ref(),
            worker_lease_id.as_deref(),
            worker_lease_epoch,
        )?
    {
        return Err(LedgerError::Corrupt {
            entity: "task done static command intent",
            detail: "canonical intent disagrees with an immutable indexed column".into(),
        });
    }
    if intent.kind != EffectKind::RunCommand
        || intent.sprint_id != sprint_id
        || session.purpose != RunnerSessionPurpose::TaskWorker
        || intent.task_id.is_none()
        || intent.worker_id.as_deref() != session.worker_id.as_deref()
        || intent.worker_lease != session.worker_lease
        || intent.worker_lease != launch.worker_lease
        || session.launch_id != launch.launch_id
        || intent.policy_hash != session.policy_hash
        || intent.created_at_unix_ms < session.registered_at_unix_ms
        || intent.created_at_unix_ms < launch.created_at_unix_ms
    {
        return Err(reference_mismatch(
            "task done static command intent",
            "command role, task, lease, runner, policy, or timestamp is crossed",
        ));
    }
    let request_bytes = load_effect_request_payload(connection, &intent)?;
    let proposed_event = load_event_by_id(connection, &proposed_event_id)?;
    validate_effect_proposal_event_shape(&intent, &proposed_event).map_err(|error| {
        LedgerError::Corrupt {
            entity: "task done static command proposal",
            detail: error.to_string(),
        }
    })?;
    validate_stored_event_causation(connection, &proposed_event)?;
    Ok(StaticTaskDoneCommandEffect {
        intent,
        request_bytes,
        proposed_event,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the optimized TaskDone loader keeps every static effect, proposal, session, binding, and duplicate-row cross-check in one fail-closed readback boundary"
)]
fn load_task_done_command_domain_effect_bindings_from(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
    validated_effects: &[&PersistedEffect],
) -> Result<Vec<CommandDomainEffectBinding>, LedgerError> {
    let (launch, session) =
        load_validated_command_domain_session(connection, sprint_id, launch_id, session_id)?;
    if launch.worker_lease != session.worker_lease
        || session.purpose != RunnerSessionPurpose::TaskWorker
    {
        return Err(reference_mismatch(
            "task done command-domain runner lifecycle",
            "task launch/session worker authority is crossed",
        ));
    }
    let rows = {
        let mut statement = connection.prepare(
            "SELECT binding.effect_id, binding.sprint_id, binding.launch_id,
                    binding.session_id, binding.contract_version
             FROM effect_session_bindings binding
             JOIN effect_intents intent ON intent.effect_id = binding.effect_id
             WHERE binding.sprint_id = ?1 AND binding.launch_id = ?2
               AND intent.effect_kind = 'RunCommand'
             ORDER BY binding.effect_id",
        )?;
        statement
            .query_map(params![sprint_id, launch_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() > MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION {
        return Err(reference_mismatch(
            "task done command-domain effect binding set",
            "hard per-session effect bound is exceeded",
        ));
    }
    let mut expected_effects = validated_effects
        .iter()
        .copied()
        .filter(|effect| effect.intent.kind == EffectKind::RunCommand)
        .collect::<Vec<_>>();
    expected_effects.sort_by(|left, right| left.intent.effect_id.cmp(&right.intent.effect_id));
    let stored_ids = rows.iter().map(|row| row.0.as_str()).collect::<Vec<_>>();
    let expected_ids = expected_effects
        .iter()
        .map(|effect| effect.intent.effect_id.as_str())
        .collect::<Vec<_>>();
    if stored_ids != expected_ids {
        return Err(LedgerError::Corrupt {
            entity: "task done command-domain effect binding set",
            detail: "static session binding set differs from the fully validated attempt effects"
                .into(),
        });
    }
    let mut bindings = Vec::with_capacity(rows.len());
    for (row, expected) in rows.into_iter().zip(expected_effects) {
        let (effect_id, indexed_sprint_id, indexed_launch_id, indexed_session_id, version) = row;
        require_contract_version("task done effect session binding", version)?;
        if indexed_sprint_id != sprint_id
            || indexed_launch_id != launch_id
            || indexed_session_id.as_deref() != Some(session_id)
        {
            return Err(LedgerError::Corrupt {
                entity: "task done command-domain effect binding set",
                detail: format!("command effect '{effect_id}' is crossed to another runner"),
            });
        }
        let static_effect = load_task_done_static_command_effect(
            connection, &effect_id, sprint_id, &launch, &session,
        )?;
        if expected.intent != static_effect.intent
            || expected.request_bytes != static_effect.request_bytes
            || expected.proposed_event != static_effect.proposed_event
        {
            return Err(LedgerError::Corrupt {
                entity: "task done static command effect",
                detail: "static authority differs from prior complete lifecycle readback".into(),
            });
        }
        let (state, observation_id, finalized_at_unix_ms) =
            command_domain_effect_state(expected.observation.as_ref());
        let binding = CommandDomainEffectBinding {
            contract_version: CONTRACT_VERSION,
            sprint_id: sprint_id.to_owned(),
            launch_id: launch_id.to_owned(),
            session_id: session_id.to_owned(),
            effect_id,
            request_digest: static_effect.intent.request_digest,
            observation_id,
            state,
            finalized_at_unix_ms,
        };
        binding.validate().map_err(|error| LedgerError::Corrupt {
            entity: "task done command-domain effect binding set",
            detail: error.to_string(),
        })?;
        bindings.push(binding);
    }
    Ok(bindings)
}

fn validate_command_domain_session(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
) -> Result<(), LedgerError> {
    load_validated_command_domain_session(connection, sprint_id, launch_id, session_id).map(drop)
}

fn load_validated_command_domain_session(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
) -> Result<(RunnerLaunchIntent, RunnerSessionPolicyRecord), LedgerError> {
    let (launch, _) = load_runner_launch_intent_from(connection, sprint_id, launch_id)?;
    let (session, _) = load_runner_session_policy_from(connection, sprint_id, session_id)?;
    if launch.session_id != session_id
        || session.launch_id != launch_id
        || session.purpose == RunnerSessionPurpose::Applier
        || launch.purpose != session.purpose
        || launch.policy_hash != session.policy_hash
        || launch.grant_hash != session.grant_hash
        || launch.policy_version != session.policy_version
    {
        return Err(reference_mismatch(
            "command-domain runner lifecycle",
            "launch/session, role, policy, grant, or version is crossed",
        ));
    }
    Ok((launch, session))
}

fn command_domain_effect_state(
    observation: Option<&crate::EffectObservation>,
) -> (CommandDomainEffectState, Option<String>, Option<u64>) {
    let Some(observation) = observation else {
        return (CommandDomainEffectState::AwaitingObservation, None, None);
    };
    let state = match observation.outcome {
        EffectOutcome::Succeeded { .. } => CommandDomainEffectState::Succeeded,
        EffectOutcome::FailedBeforeEffect { .. } => CommandDomainEffectState::FailedBeforeEffect,
        EffectOutcome::FailedAfterKnownEffect { .. } => {
            CommandDomainEffectState::FailedAfterKnownEffect
        }
        EffectOutcome::CancelledBeforeEffect { .. } => {
            CommandDomainEffectState::CancelledBeforeEffect
        }
        EffectOutcome::Unknown { .. } => CommandDomainEffectState::Unknown,
    };
    (
        state,
        Some(observation.observation_id.clone()),
        Some(observation.observed_at_unix_ms),
    )
}

fn validate_command_domain_cleanup_proof(
    connection: &Connection,
    proof: &CommandDomainCleanupProof,
) -> Result<CommandDomainEffectBinding, LedgerError> {
    let bindings = load_command_domain_effect_bindings_from(
        connection,
        &proof.sprint_id,
        &proof.launch_id,
        &proof.session_id,
    )?;
    let binding = bindings
        .into_iter()
        .find(|binding| binding.effect_id == proof.effect_id)
        .ok_or_else(|| {
            reference_mismatch(
                "command-domain cleanup proof",
                "effect is not in the exact RunCommand binding set",
            )
        })?;
    validate_command_domain_cleanup_proof_against_binding(connection, proof, &binding)?;
    Ok(binding)
}

fn validate_command_domain_cleanup_proof_against_binding(
    connection: &Connection,
    proof: &CommandDomainCleanupProof,
    binding: &CommandDomainEffectBinding,
) -> Result<(), LedgerError> {
    if proof.sprint_id != binding.sprint_id
        || proof.launch_id != binding.launch_id
        || proof.session_id != binding.session_id
        || proof.effect_id != binding.effect_id
    {
        return Err(reference_mismatch(
            "command-domain cleanup proof",
            "proof identity crosses its exact command binding",
        ));
    }
    let disposition_valid = match binding.state {
        CommandDomainEffectState::FailedBeforeEffect
        | CommandDomainEffectState::CancelledBeforeEffect => matches!(
            proof.disposition,
            CommandDomainCleanupDisposition::ReapedZeroSurvivors
                | CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
        ),
        CommandDomainEffectState::Succeeded
        | CommandDomainEffectState::FailedAfterKnownEffect
        | CommandDomainEffectState::AwaitingObservation
        | CommandDomainEffectState::Unknown => {
            proof.disposition == CommandDomainCleanupDisposition::ReapedZeroSurvivors
        }
    };
    let (session, _) =
        load_runner_session_policy_from(connection, &proof.sprint_id, &proof.session_id)?;
    let existing_backend = connection
        .query_row(
            "SELECT backend FROM command_domain_cleanup_proofs
             WHERE sprint_id = ?1 AND launch_id = ?2 AND session_id = ?3
             LIMIT 1",
            params![proof.sprint_id, proof.launch_id, proof.session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let observation_binding_valid = match (
        proof.observation_id.as_deref(),
        binding.observation_id.as_deref(),
        binding.finalized_at_unix_ms,
    ) {
        (Some(proof_id), Some(binding_id), Some(finalized_at)) => {
            proof_id == binding_id
                && (proof.cleaned_at_unix_ms >= finalized_at
                    || super::sensitive_output_rejection::staged_rejection_allows_cleanup_before_observation(
                        connection,
                        proof,
                        finalized_at,
                    )?)
        }
        (None, None, None) => true,
        (None, Some(_), Some(finalized_at)) => {
            proof.disposition == CommandDomainCleanupDisposition::ReapedZeroSurvivors
                && proof.cleaned_at_unix_ms >= finalized_at
        }
        _ => false,
    };
    if !observation_binding_valid
        || proof.request_digest != binding.request_digest
        || !disposition_valid
        || proof.cleaned_at_unix_ms < session.registered_at_unix_ms
        || existing_backend
            .as_deref()
            .is_some_and(|backend| backend != proof.backend.storage_name())
    {
        return Err(reference_mismatch(
            "command-domain cleanup proof",
            "observation, request, disposition, backend, or ordering differs from the exact command lifecycle",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn load_command_domain_cleanup_proof_row(
    connection: &Connection,
    effect_id: &str,
) -> Result<CommandDomainCleanupProof, LedgerError> {
    let stored = connection
        .query_row(
            "SELECT proof_id, sprint_id, launch_id, session_id,
                    observation_id, request_digest, backend, disposition,
                    surviving_processes, platform_proof_digest,
                    contract_version, cleaned_at_unix_ms,
                    platform_proof_bytes, proof_json
             FROM command_domain_cleanup_proofs WHERE effect_id = ?1",
            [effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| LedgerError::ArtifactNotFound {
            entity: "command-domain cleanup proof",
            id: effect_id.to_owned(),
        })?;
    require_contract_version("command-domain cleanup proof", stored.10)?;
    let proof: CommandDomainCleanupProof =
        decode_stored("command-domain cleanup proof", &stored.13)?;
    proof.validate().map_err(|error| LedgerError::Corrupt {
        entity: "command-domain cleanup proof",
        detail: error.to_string(),
    })?;
    if encode("command-domain cleanup proof", &proof)? != stored.13
        || proof.effect_id != effect_id
        || proof.proof_id != stored.0
        || proof.sprint_id != stored.1
        || proof.launch_id != stored.2
        || proof.session_id != stored.3
        || proof.observation_id != stored.4
        || proof.request_digest.as_str() != stored.5
        || proof.backend.storage_name() != stored.6
        || proof.disposition.storage_name() != stored.7
        || i64::try_from(proof.surviving_processes).ok() != Some(stored.8)
        || proof.platform_proof_digest.as_str() != stored.9
        || proof.cleaned_at_unix_ms
            != super::unsigned_integer(
                "command_domain_cleanup_proof.cleaned_at_unix_ms",
                stored.11,
            )?
        || proof.platform_proof_bytes != stored.12
    {
        return Err(LedgerError::Corrupt {
            entity: "command-domain cleanup proof",
            detail: "canonical proof bytes disagree with indexed columns or retained native proof"
                .into(),
        });
    }
    Ok(proof)
}

fn load_command_domain_cleanup_by_effect(
    connection: &Connection,
    effect_id: &str,
) -> Result<PersistedCommandDomainCleanup, LedgerError> {
    let proof = load_command_domain_cleanup_proof_row(connection, effect_id)?;
    let binding = validate_command_domain_cleanup_proof(connection, &proof).map_err(|error| {
        LedgerError::Corrupt {
            entity: "command-domain cleanup proof",
            detail: error.to_string(),
        }
    })?;
    validate_command_domain_proof_id_global(connection, &proof.proof_id)?;
    Ok(PersistedCommandDomainCleanup { binding, proof })
}

pub(super) fn load_command_domain_cleanup_by_effect_optional(
    connection: &Connection,
    effect_id: &str,
) -> Result<Option<PersistedCommandDomainCleanup>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM command_domain_cleanup_proofs WHERE effect_id = ?1",
            [effect_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if exists {
        load_command_domain_cleanup_by_effect(connection, effect_id).map(Some)
    } else {
        Ok(None)
    }
}

fn load_task_done_command_domain_cleanup_by_effect_optional(
    connection: &Connection,
    binding: &CommandDomainEffectBinding,
) -> Result<Option<PersistedCommandDomainCleanup>, LedgerError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM command_domain_cleanup_proofs WHERE effect_id = ?1",
            [&binding.effect_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(None);
    }
    let proof = load_command_domain_cleanup_proof_row(connection, &binding.effect_id)?;
    validate_command_domain_cleanup_proof_against_binding(connection, &proof, binding).map_err(
        |error| LedgerError::Corrupt {
            entity: "command-domain cleanup proof",
            detail: error.to_string(),
        },
    )?;
    validate_command_domain_proof_id_global(connection, &proof.proof_id)?;
    Ok(Some(PersistedCommandDomainCleanup {
        binding: binding.clone(),
        proof,
    }))
}

/// Reopens one durable command-domain cleanup proof and requires byte-exact
/// equality with the caller-selected proof.
///
/// This comparison helper is intended for enclosing transactions that bind a
/// cleanup proof to another terminal transition. It never inserts or repairs
/// proof authority.
pub(super) fn require_exact_command_domain_cleanup_proof(
    connection: &Connection,
    expected: &CommandDomainCleanupProof,
) -> Result<PersistedCommandDomainCleanup, LedgerError> {
    expected.validate()?;
    let stored = load_command_domain_cleanup_by_effect(connection, &expected.effect_id)?;
    if stored.proof != *expected {
        return Err(reference_mismatch(
            "command-domain cleanup proof",
            "durable proof differs from the exact proof selected by the terminal transition",
        ));
    }
    Ok(stored)
}

pub(super) fn load_command_domain_cleanup_completeness_from(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
    backend: CommandDomainBackend,
) -> Result<CommandDomainCleanupCompleteness, LedgerError> {
    let bindings =
        load_command_domain_effect_bindings_from(connection, sprint_id, launch_id, session_id)?;
    assemble_command_domain_cleanup_completeness(
        connection,
        sprint_id,
        launch_id,
        session_id,
        backend,
        &bindings,
        |binding| load_command_domain_cleanup_by_effect_optional(connection, &binding.effect_id),
    )
}

pub(super) fn load_task_done_command_domain_cleanup_completeness_from(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
    backend: CommandDomainBackend,
    validated_effects: &[&PersistedEffect],
) -> Result<CommandDomainCleanupCompleteness, LedgerError> {
    let bindings = load_task_done_command_domain_effect_bindings_from(
        connection,
        sprint_id,
        launch_id,
        session_id,
        validated_effects,
    )?;
    assemble_command_domain_cleanup_completeness(
        connection,
        sprint_id,
        launch_id,
        session_id,
        backend,
        &bindings,
        |binding| load_task_done_command_domain_cleanup_by_effect_optional(connection, binding),
    )
}

fn assemble_command_domain_cleanup_completeness<F>(
    connection: &Connection,
    sprint_id: &str,
    launch_id: &str,
    session_id: &str,
    backend: CommandDomainBackend,
    bindings: &[CommandDomainEffectBinding],
    mut load_entry: F,
) -> Result<CommandDomainCleanupCompleteness, LedgerError>
where
    F: FnMut(
        &CommandDomainEffectBinding,
    ) -> Result<Option<PersistedCommandDomainCleanup>, LedgerError>,
{
    let mut missing = Vec::new();
    let mut unresolved = Vec::new();
    let mut entries = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if binding.state.unresolved() {
            unresolved.push(binding.effect_id.clone());
        }
        match load_entry(binding)? {
            Some(entry) => {
                if entry.proof.backend != backend {
                    return Err(reference_mismatch(
                        "command-domain cleanup proof set",
                        format!(
                            "effect '{}' uses a different native backend",
                            binding.effect_id
                        ),
                    ));
                }
                entries.push(entry);
            }
            None => missing.push(binding.effect_id.clone()),
        }
    }
    let mut statement = connection.prepare(
        "SELECT effect_id FROM command_domain_cleanup_proofs
         WHERE sprint_id = ?1 AND (launch_id = ?2 OR session_id = ?3)
         ORDER BY effect_id",
    )?;
    let stored_effect_ids = statement
        .query_map(params![sprint_id, launch_id, session_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if stored_effect_ids.len() > MAX_COMMAND_DOMAIN_EFFECTS_PER_SESSION
        || stored_effect_ids.windows(2).any(|pair| pair[0] == pair[1])
        || stored_effect_ids
            != entries
                .iter()
                .map(|entry| entry.binding.effect_id.clone())
                .collect::<Vec<_>>()
    {
        return Err(LedgerError::Corrupt {
            entity: "command-domain cleanup proof set",
            detail: "stored proofs contain an extra, duplicate, or cross-session effect".into(),
        });
    }
    let incomplete = match (missing.is_empty(), unresolved.is_empty()) {
        (false, true) => Some(CommandDomainCleanupIncomplete::MissingProofs {
            effect_ids: missing,
        }),
        (true, false) => Some(CommandDomainCleanupIncomplete::EffectOutcomeUnresolved {
            effect_ids: unresolved,
        }),
        (false, false) => Some(
            CommandDomainCleanupIncomplete::MissingProofsAndEffectOutcomeUnresolved {
                missing_effect_ids: missing,
                unresolved_effect_ids: unresolved,
            },
        ),
        (true, true) => None,
    };
    if let Some(reason) = incomplete {
        Ok(CommandDomainCleanupCompleteness::Incomplete(reason))
    } else {
        Ok(CommandDomainCleanupCompleteness::Complete(
            CompleteCommandDomainCleanupSet {
                sprint_id: sprint_id.to_owned(),
                launch_id: launch_id.to_owned(),
                session_id: session_id.to_owned(),
                backend,
                entries,
            },
        ))
    }
}

fn ensure_command_domain_proof_id_available(
    connection: &Connection,
    proof_id: &str,
) -> Result<(), LedgerError> {
    let exists = live_state_capture_receipt_identity_exists(connection, proof_id)?
        || connection
            .query_row(
                "SELECT 1 FROM command_domain_cleanup_proofs WHERE proof_id = ?1
             UNION ALL SELECT 1 FROM finish_receipt_ids WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM verification_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM acceptance_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM completion_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM v9_completion_receipts WHERE receipt_id = ?1
             UNION ALL SELECT 1 FROM post_completion_rollback_receipt_ids
                 WHERE receipt_id = ?1
             LIMIT 1",
                [proof_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
    if exists {
        Err(LedgerError::ArtifactAlreadyExists {
            entity: "global command-domain proof identity",
            id: proof_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_command_domain_proof_id_global(
    connection: &Connection,
    proof_id: &str,
) -> Result<(), LedgerError> {
    let core_collisions: i64 = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM command_domain_cleanup_proofs WHERE proof_id = ?1)
          + (SELECT COUNT(*) FROM finish_receipt_ids WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM verification_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM acceptance_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM completion_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM v9_completion_receipts WHERE receipt_id = ?1)
          + (SELECT COUNT(*) FROM post_completion_rollback_receipt_ids
             WHERE receipt_id = ?1)",
        [proof_id],
        |row| row.get(0),
    )?;
    let capture_collisions = i64::from(live_state_capture_receipt_identity_exists(
        connection, proof_id,
    )?);
    let collisions =
        core_collisions
            .checked_add(capture_collisions)
            .ok_or(LedgerError::IntegerOutOfRange(
                "global command-domain proof identity count",
            ))?;
    if collisions == 1 {
        Ok(())
    } else {
        Err(LedgerError::Corrupt {
            entity: "command-domain cleanup proof identity",
            detail: "proof identity is absent or collides with another global authority".into(),
        })
    }
}

fn live_state_capture_receipt_identity_exists(
    connection: &Connection,
    receipt_id: &str,
) -> Result<bool, LedgerError> {
    let schema_is_installed = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'live_state_capture_receipt_ids'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !schema_is_installed {
        return Ok(false);
    }
    Ok(connection
        .query_row(
            "SELECT 1 FROM live_state_capture_receipt_ids WHERE receipt_id = ?1",
            [receipt_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn require_version(version: u32, field: &'static str) -> Result<(), ContractError> {
    if version == CONTRACT_VERSION {
        Ok(())
    } else {
        Err(contract_error(
            field,
            format!("expected version {CONTRACT_VERSION}, got {version}"),
        ))
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(contract_error(field, "must not be blank"))
    } else {
        Ok(())
    }
}

fn require_time(field: &'static str, value: u64) -> Result<(), ContractError> {
    if value == 0 {
        Err(contract_error(field, "must be greater than zero"))
    } else {
        Ok(())
    }
}

fn contract_error(field: &'static str, detail: impl Into<String>) -> ContractError {
    ContractError::new(field, detail)
}
