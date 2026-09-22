//! Artifact-bound application requests and post-completion authority.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use super::{
    EventLedger, LedgerError, decode_canonical_request, decode_stored, encode,
    load_application_evidence_from, load_change_set_from, load_effect_from_with_receipts,
    reference_mismatch, require_contract_version,
};
use crate::{
    ApplicationRequest, CONTRACT_VERSION, ChangeSet, ContractError, Digest, EffectIntent,
    EffectKind, TaskIntegrationArtifactReference,
};

/// Maximum canonical bytes retained for one operation-local application
/// artifact authority.
pub const MAX_POST_COMPLETION_APPLICATION_ARTIFACT_AUTHORITY_BYTES: usize = 64 * 1_024;

/// Schema v12 adds artifact authority without rewriting any v1-v11 request or
/// operation bytes.
pub(super) const MIGRATION_V12: &str = r"
    CREATE TABLE legacy_application_request_gaps (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        request_kind TEXT NOT NULL CHECK (request_kind = 'PreV12Unbound'),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO legacy_application_request_gaps (
        effect_id, sprint_id, request_digest, request_kind, contract_version
    )
    SELECT intent.effect_id, intent.sprint_id, intent.request_digest,
           'PreV12Unbound', intent.contract_version
    FROM effect_intents intent
    JOIN finish_effect_kinds kind
      ON kind.effect_id = intent.effect_id
     AND kind.sprint_id = intent.sprint_id
    WHERE kind.effect_kind = 'ApplyChangeSet';

    CREATE TRIGGER legacy_application_request_gaps_no_insert
    BEFORE INSERT ON legacy_application_request_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy application request gaps are migration-only'); END;
    CREATE TRIGGER legacy_application_request_gaps_no_update
    BEFORE UPDATE ON legacy_application_request_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy application request gaps are immutable'); END;
    CREATE TRIGGER legacy_application_request_gaps_no_delete
    BEFORE DELETE ON legacy_application_request_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy application request gaps are immutable'); END;

    CREATE TABLE application_request_artifact_authorities (
        effect_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        change_set_id TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        result_snapshot TEXT NOT NULL,
        artifact_format_version INTEGER NOT NULL CHECK (artifact_format_version > 0),
        artifact_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        request_json BLOB NOT NULL CHECK (
            length(request_json) BETWEEN 1 AND 8323072
        ),
        UNIQUE (sprint_id, effect_id),
        FOREIGN KEY (sprint_id, effect_id)
            REFERENCES effect_intents(sprint_id, effect_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, change_set_id)
            REFERENCES change_sets(sprint_id, change_set_id) ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX application_request_artifact_authorities_artifact_idx
    ON application_request_artifact_authorities (
        sprint_id, change_set_id, artifact_digest
    );

    CREATE TRIGGER application_request_artifact_authorities_no_existing_insert
    BEFORE INSERT ON application_request_artifact_authorities
    WHEN EXISTS (SELECT 1 FROM effect_intents WHERE effect_id = NEW.effect_id)
      OR EXISTS (
          SELECT 1 FROM legacy_application_request_gaps
          WHERE effect_id = NEW.effect_id
      )
    BEGIN SELECT RAISE(ABORT, 'application artifact authority must commit with one new effect'); END;
    CREATE TRIGGER application_request_artifact_authorities_no_update
    BEFORE UPDATE ON application_request_artifact_authorities
    BEGIN SELECT RAISE(ABORT, 'application artifact authorities are immutable'); END;
    CREATE TRIGGER application_request_artifact_authorities_no_delete
    BEFORE DELETE ON application_request_artifact_authorities
    BEGIN SELECT RAISE(ABORT, 'application artifact authorities are immutable'); END;

    CREATE TRIGGER effect_intents_require_application_artifact_authority
    AFTER INSERT ON effect_intents
    WHEN EXISTS (
        SELECT 1 FROM finish_effect_kinds kind
        WHERE kind.effect_id = NEW.effect_id
          AND kind.sprint_id = NEW.sprint_id
          AND kind.effect_kind = 'ApplyChangeSet'
    )
      AND NOT EXISTS (
          SELECT 1
          FROM legacy_application_request_gaps gap
          WHERE gap.effect_id = NEW.effect_id
            AND gap.sprint_id = NEW.sprint_id
            AND gap.request_digest = NEW.request_digest
            AND gap.contract_version = NEW.contract_version
      )
      AND NOT EXISTS (
          SELECT 1
          FROM application_request_artifact_authorities authority
          JOIN effect_request_payloads request
            ON request.effect_id = authority.effect_id
           AND request.sprint_id = authority.sprint_id
          JOIN change_sets change_set
            ON change_set.change_set_id = authority.change_set_id
           AND change_set.sprint_id = authority.sprint_id
          WHERE authority.effect_id = NEW.effect_id
            AND authority.sprint_id = NEW.sprint_id
            AND authority.request_digest = NEW.request_digest
            AND request.request_digest = NEW.request_digest
            AND request.request_bytes = authority.request_json
            AND json_valid(CAST(authority.request_json AS TEXT))
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.contract_version'
                ) = 'integer'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.change_set_id'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.base_snapshot'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.result_snapshot'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.format_version'
                ) = 'integer'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.artifact_digest'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.change_set_id'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.base_snapshot'
                ) = 'text'
            AND json_type(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.result_snapshot'
                ) = 'text'
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.contract_version'
                ) = authority.contract_version
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.change_set_id'
                ) = authority.change_set_id
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.base_snapshot'
                ) = authority.base_snapshot
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.change_set.result_snapshot'
                ) = authority.result_snapshot
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.format_version'
                ) = authority.artifact_format_version
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.artifact_digest'
                ) = authority.artifact_digest
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.change_set_id'
                ) = authority.change_set_id
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.base_snapshot'
                ) = authority.base_snapshot
            AND json_extract(
                    CAST(authority.request_json AS TEXT),
                    '$.artifact.result_snapshot'
                ) = authority.result_snapshot
            AND authority.base_snapshot = NEW.input_snapshot
            AND change_set.base_snapshot = authority.base_snapshot
            AND change_set.result_snapshot = authority.result_snapshot
            AND authority.contract_version = NEW.contract_version
      )
    BEGIN SELECT RAISE(ABORT, 'ApplyChangeSet requires exact artifact-bound request authority'); END;

    CREATE TRIGGER application_receipts_require_application_artifact_authority
    BEFORE INSERT ON application_receipts
    WHEN NOT EXISTS (
        SELECT 1
        FROM application_request_artifact_authorities authority
        WHERE authority.effect_id = NEW.effect_id
          AND authority.sprint_id = NEW.sprint_id
          AND authority.change_set_id = NEW.change_set_id
          AND authority.base_snapshot = NEW.base_snapshot
          AND authority.result_snapshot = NEW.result_snapshot
          AND authority.contract_version = NEW.contract_version
    ) AND NOT EXISTS (
        SELECT 1
        FROM legacy_application_request_gaps gap
        WHERE gap.effect_id = NEW.effect_id
          AND gap.sprint_id = NEW.sprint_id
          AND gap.contract_version = NEW.contract_version
    )
    BEGIN SELECT RAISE(ABORT, 'application receipt requires exact request classification'); END;

    CREATE TABLE legacy_post_completion_application_artifact_gaps (
        operation_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        application_receipt_id TEXT NOT NULL,
        gap_kind TEXT NOT NULL CHECK (gap_kind = 'LegacyMissing'),
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        UNIQUE (sprint_id, operation_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    INSERT INTO legacy_post_completion_application_artifact_gaps (
        operation_id, sprint_id, application_receipt_id, gap_kind,
        contract_version
    )
    SELECT operation_id, sprint_id, application_receipt_id, 'LegacyMissing',
           contract_version
    FROM post_completion_rollback_operations;

    CREATE TRIGGER legacy_post_completion_application_artifact_gaps_no_insert
    BEFORE INSERT ON legacy_post_completion_application_artifact_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy post-completion artifact gaps are migration-only'); END;
    CREATE TRIGGER legacy_post_completion_application_artifact_gaps_no_update
    BEFORE UPDATE ON legacy_post_completion_application_artifact_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy post-completion artifact gaps are immutable'); END;
    CREATE TRIGGER legacy_post_completion_application_artifact_gaps_no_delete
    BEFORE DELETE ON legacy_post_completion_application_artifact_gaps
    BEGIN SELECT RAISE(ABORT, 'legacy post-completion artifact gaps are immutable'); END;

    CREATE TABLE post_completion_application_artifact_authorities (
        operation_id TEXT PRIMARY KEY NOT NULL,
        sprint_id TEXT NOT NULL,
        application_receipt_id TEXT NOT NULL,
        application_effect_id TEXT NOT NULL,
        application_request_digest TEXT NOT NULL,
        change_set_id TEXT NOT NULL,
        base_snapshot TEXT NOT NULL,
        result_snapshot TEXT NOT NULL,
        artifact_format_version INTEGER NOT NULL CHECK (artifact_format_version > 0),
        artifact_digest TEXT NOT NULL,
        authority_digest TEXT NOT NULL,
        contract_version INTEGER NOT NULL CHECK (contract_version > 0),
        authority_json BLOB NOT NULL CHECK (
            length(authority_json) BETWEEN 1 AND 65536
        ),
        UNIQUE (sprint_id, operation_id),
        FOREIGN KEY (sprint_id, operation_id)
            REFERENCES post_completion_rollback_operations(sprint_id, operation_id)
            ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        FOREIGN KEY (sprint_id, application_receipt_id)
            REFERENCES application_receipts(sprint_id, receipt_id) ON DELETE RESTRICT,
        FOREIGN KEY (sprint_id, application_effect_id)
            REFERENCES application_request_artifact_authorities(sprint_id, effect_id)
            ON DELETE RESTRICT
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX post_completion_application_artifact_authorities_source_idx
    ON post_completion_application_artifact_authorities (
        sprint_id, application_receipt_id, application_effect_id
    );

    CREATE TRIGGER post_completion_application_artifact_authorities_no_existing_insert
    BEFORE INSERT ON post_completion_application_artifact_authorities
    WHEN EXISTS (
        SELECT 1 FROM post_completion_rollback_operations
        WHERE operation_id = NEW.operation_id
    ) OR EXISTS (
        SELECT 1 FROM legacy_post_completion_application_artifact_gaps
        WHERE operation_id = NEW.operation_id
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion artifact authority must precede one new operation'); END;
    CREATE TRIGGER post_completion_application_artifact_authorities_no_update
    BEFORE UPDATE ON post_completion_application_artifact_authorities
    BEGIN SELECT RAISE(ABORT, 'post-completion artifact authorities are immutable'); END;
    CREATE TRIGGER post_completion_application_artifact_authorities_no_delete
    BEFORE DELETE ON post_completion_application_artifact_authorities
    BEGIN SELECT RAISE(ABORT, 'post-completion artifact authorities are immutable'); END;

    CREATE TRIGGER post_completion_rollback_operations_require_artifact_authority
    AFTER INSERT ON post_completion_rollback_operations
    WHEN NOT EXISTS (
        SELECT 1 FROM legacy_post_completion_application_artifact_gaps gap
        WHERE gap.operation_id = NEW.operation_id
          AND gap.sprint_id = NEW.sprint_id
          AND gap.application_receipt_id = NEW.application_receipt_id
          AND gap.contract_version = NEW.contract_version
    ) AND NOT EXISTS (
        SELECT 1
        FROM post_completion_application_artifact_authorities authority
        JOIN application_receipts receipt
          ON receipt.receipt_id = authority.application_receipt_id
         AND receipt.sprint_id = authority.sprint_id
        JOIN application_request_artifact_authorities request
          ON request.effect_id = authority.application_effect_id
         AND request.sprint_id = authority.sprint_id
        WHERE authority.operation_id = NEW.operation_id
          AND authority.sprint_id = NEW.sprint_id
          AND authority.application_receipt_id = NEW.application_receipt_id
          AND receipt.effect_id = authority.application_effect_id
          AND receipt.change_set_id = authority.change_set_id
          AND receipt.base_snapshot = authority.base_snapshot
          AND receipt.result_snapshot = authority.result_snapshot
          AND request.request_digest = authority.application_request_digest
          AND request.change_set_id = authority.change_set_id
          AND request.base_snapshot = authority.base_snapshot
          AND request.result_snapshot = authority.result_snapshot
          AND request.artifact_format_version = authority.artifact_format_version
          AND request.artifact_digest = authority.artifact_digest
          AND json_valid(CAST(authority.authority_json AS TEXT))
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.contract_version'
              ) = 'integer'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.sprint_id'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.operation_id'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_receipt_id'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_effect_id'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_request_digest'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.format_version'
              ) = 'integer'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.artifact_digest'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.change_set_id'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.base_snapshot'
              ) = 'text'
          AND json_type(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.result_snapshot'
              ) = 'text'
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.contract_version'
              ) = authority.contract_version
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.sprint_id'
              ) = authority.sprint_id
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.operation_id'
              ) = authority.operation_id
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_receipt_id'
              ) = authority.application_receipt_id
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_effect_id'
              ) = authority.application_effect_id
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.application_request_digest'
              ) = authority.application_request_digest
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.format_version'
              ) = authority.artifact_format_version
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.artifact_digest'
              ) = authority.artifact_digest
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.change_set_id'
              ) = authority.change_set_id
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.base_snapshot'
              ) = authority.base_snapshot
          AND json_extract(
                  CAST(authority.authority_json AS TEXT),
                  '$.artifact.result_snapshot'
              ) = authority.result_snapshot
          AND authority.contract_version = NEW.contract_version
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion operation requires original application artifact authority'); END;

    CREATE TRIGGER post_completion_launches_require_artifact_authority
    BEFORE INSERT ON post_completion_rollback_applier_launches
    WHEN NOT EXISTS (
        SELECT 1 FROM post_completion_application_artifact_authorities
        WHERE operation_id = NEW.operation_id AND sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion launch requires application artifact authority'); END;
    CREATE TRIGGER post_completion_sessions_require_artifact_authority
    BEFORE INSERT ON post_completion_rollback_applier_sessions
    WHEN NOT EXISTS (
        SELECT 1 FROM post_completion_application_artifact_authorities
        WHERE operation_id = NEW.operation_id AND sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion session requires application artifact authority'); END;
    CREATE TRIGGER post_completion_observations_require_artifact_authority
    BEFORE INSERT ON post_completion_rollback_observations
    WHEN NOT EXISTS (
        SELECT 1 FROM post_completion_application_artifact_authorities
        WHERE operation_id = NEW.operation_id AND sprint_id = NEW.sprint_id
    )
    BEGIN SELECT RAISE(ABORT, 'post-completion effect requires application artifact authority'); END;
";

/// Closed readback of an exact application request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationRequestArtifactAuthority {
    /// A v12 request whose digest authenticates the exact aggregate artifact.
    ArtifactBound(Box<ApplicationRequest>),
    /// Exact historical bare-`ChangeSet` bytes retained without artifact
    /// authority.
    LegacyBareChangeSet {
        /// Historical request decoded from its unchanged canonical bytes.
        change_set: ChangeSet,
        /// Digest authenticating those exact historical bytes.
        request_digest: Digest,
    },
    /// Pre-v12 digest-bound request bytes that were never required to decode
    /// before the effect reached a successful application receipt.
    LegacyUnbound {
        /// Digest authenticating the unchanged historical request bytes.
        request_digest: Digest,
    },
}

impl ApplicationRequestArtifactAuthority {
    /// Returns the exact artifact only for authoritative v12 requests.
    #[must_use]
    pub const fn artifact(&self) -> Option<&TaskIntegrationArtifactReference> {
        match self {
            Self::ArtifactBound(request) => Some(&request.artifact),
            Self::LegacyBareChangeSet { .. } | Self::LegacyUnbound { .. } => None,
        }
    }
}

/// Immutable operation-local authority derived from the original successful
/// application's exact request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostCompletionRollbackApplicationArtifactAuthority {
    /// Wire-contract version.
    pub contract_version: u32,
    /// Owning completed sprint.
    pub sprint_id: String,
    /// Exact post-completion rollback operation.
    pub operation_id: String,
    /// Exact successful application receipt.
    pub application_receipt_id: String,
    /// Exact successful application effect.
    pub application_effect_id: String,
    /// Digest of the original canonical [`ApplicationRequest`].
    pub application_request_digest: Digest,
    /// Exact immutable aggregate artifact supplied to that application.
    pub artifact: TaskIntegrationArtifactReference,
}

impl PostCompletionRollbackApplicationArtifactAuthority {
    /// Validates the self-contained authority envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for an unsupported version, blank identity,
    /// invalid artifact, or oversized canonical bytes.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(contract_error(
                "post_completion_application_artifact_authority.contract_version",
                format!(
                    "expected version {CONTRACT_VERSION}, got {}",
                    self.contract_version
                ),
            ));
        }
        require_text(
            "post_completion_application_artifact_authority.sprint_id",
            &self.sprint_id,
        )?;
        require_text(
            "post_completion_application_artifact_authority.operation_id",
            &self.operation_id,
        )?;
        require_text(
            "post_completion_application_artifact_authority.application_receipt_id",
            &self.application_receipt_id,
        )?;
        require_text(
            "post_completion_application_artifact_authority.application_effect_id",
            &self.application_effect_id,
        )?;
        self.artifact.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|error| {
            contract_error(
                "post_completion_application_artifact_authority",
                format!("cannot encode canonically: {error}"),
            )
        })?;
        if canonical.len() > MAX_POST_COMPLETION_APPLICATION_ARTIFACT_AUTHORITY_BYTES {
            return Err(contract_error(
                "post_completion_application_artifact_authority",
                format!(
                    "canonical authority exceeds {MAX_POST_COMPLETION_APPLICATION_ARTIFACT_AUTHORITY_BYTES} bytes"
                ),
            ));
        }
        Ok(())
    }
}

/// Closed authority classification for one post-completion rollback operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostCompletionRollbackApplicationArtifactAuthorityState {
    /// Exact authority derived from an artifact-bound original request.
    Authoritative {
        /// Canonical operation-local authority.
        authority: Box<PostCompletionRollbackApplicationArtifactAuthority>,
        /// SHA-256 of the exact canonical authority bytes.
        authority_digest: Digest,
    },
    /// Migration-marked v10/v11 operation; readable but unable to launch or
    /// execute another mutation.
    LegacyMissing,
}

impl PostCompletionRollbackApplicationArtifactAuthorityState {
    /// Returns the exact artifact only for authoritative v12 operations.
    #[must_use]
    pub const fn artifact(&self) -> Option<&TaskIntegrationArtifactReference> {
        match self {
            Self::Authoritative { authority, .. } => Some(&authority.artifact),
            Self::LegacyMissing => None,
        }
    }
}

impl EventLedger {
    /// Loads the exact artifact-bound or explicitly legacy application request.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the effect is absent, is not an
    /// `ApplyChangeSet`, has crossed/substituted authority, or has both/neither
    /// authoritative and legacy classification.
    pub fn load_application_request_artifact_authority(
        &self,
        effect_id: &str,
    ) -> Result<ApplicationRequestArtifactAuthority, LedgerError> {
        let effect = load_effect_from_with_receipts(&self.connection, effect_id, false)?;
        load_application_request_artifact_authority_from_parts(
            &self.connection,
            &effect.intent,
            &effect.request_bytes,
        )
    }
}

pub(super) fn schema_is_installed(connection: &Connection) -> Result<bool, LedgerError> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table'
               AND name = 'application_request_artifact_authorities'",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(Into::into)
}

pub(super) fn validate_new_application_request(
    connection: &Connection,
    intent: &EffectIntent,
    request_bytes: &[u8],
) -> Result<ApplicationRequest, LedgerError> {
    if intent.kind != EffectKind::ApplyChangeSet
        || intent.task_id.is_some()
        || intent.worker_id.is_some()
    {
        return Err(reference_mismatch(
            "application request",
            "artifact-bound application must be one sprint-scoped ApplyChangeSet intent",
        ));
    }
    let request: ApplicationRequest =
        decode_canonical_request("application request", request_bytes)?;
    request
        .validate()
        .map_err(|error| reference_mismatch("application request", error.to_string()))?;
    let durable = load_change_set_from(
        connection,
        &intent.sprint_id,
        &request.change_set.change_set_id,
    )?;
    if Digest::sha256(request_bytes) != intent.request_digest
        || request.change_set != durable
        || request.change_set.base_snapshot != intent.input_snapshot
    {
        return Err(reference_mismatch(
            "application request",
            "request digest, durable aggregate change set, or input snapshot differs",
        ));
    }
    Ok(request)
}

pub(super) fn insert_application_request_artifact_authority(
    transaction: &Transaction<'_>,
    intent: &EffectIntent,
    request: &ApplicationRequest,
    request_bytes: &[u8],
) -> Result<(), LedgerError> {
    transaction.execute(
        "INSERT INTO application_request_artifact_authorities (
            effect_id, sprint_id, request_digest, change_set_id,
            base_snapshot, result_snapshot, artifact_format_version,
            artifact_digest, contract_version, request_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            intent.effect_id,
            intent.sprint_id,
            intent.request_digest.as_str(),
            request.change_set.change_set_id,
            request.change_set.base_snapshot.as_str(),
            request.change_set.result_snapshot.as_str(),
            i64::from(request.artifact.format_version),
            request.artifact.artifact_digest.as_str(),
            i64::from(request.contract_version),
            request_bytes,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_application_request_artifact_authority_from_parts(
    connection: &Connection,
    intent: &EffectIntent,
    request_bytes: &[u8],
) -> Result<ApplicationRequestArtifactAuthority, LedgerError> {
    if intent.kind != EffectKind::ApplyChangeSet {
        return Err(reference_mismatch(
            "application request artifact authority",
            "effect is not ApplyChangeSet",
        ));
    }
    let authority = connection
        .query_row(
            "SELECT sprint_id, request_digest, change_set_id, base_snapshot,
                    result_snapshot, artifact_format_version, artifact_digest,
                    contract_version, request_json
             FROM application_request_artifact_authorities
             WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .optional()?;
    let legacy = connection
        .query_row(
            "SELECT sprint_id, request_digest, request_kind, contract_version
             FROM legacy_application_request_gaps WHERE effect_id = ?1",
            [&intent.effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    match (authority, legacy) {
        (Some(_), Some(_)) => Err(LedgerError::Corrupt {
            entity: "application request artifact authority",
            detail: "effect has both authoritative and legacy request classifications".into(),
        }),
        (None, None) => Err(LedgerError::Corrupt {
            entity: "application request artifact authority",
            detail:
                "ApplyChangeSet effect has neither authoritative nor legacy request classification"
                    .into(),
        }),
        (Some(stored), None) => {
            require_contract_version("application request artifact authority", stored.7)?;
            let request: ApplicationRequest =
                decode_stored("application request artifact authority", &stored.8)?;
            request.validate().map_err(|error| LedgerError::Corrupt {
                entity: "application request artifact authority",
                detail: error.to_string(),
            })?;
            let durable = load_change_set_from(
                connection,
                &intent.sprint_id,
                &request.change_set.change_set_id,
            )?;
            if encode("application request", &request)? != stored.8
                || stored.8 != request_bytes
                || Digest::sha256(request_bytes) != intent.request_digest
                || intent.sprint_id != stored.0
                || intent.request_digest.as_str() != stored.1
                || request.change_set.change_set_id != stored.2
                || request.change_set.base_snapshot.as_str() != stored.3
                || request.change_set.result_snapshot.as_str() != stored.4
                || i64::from(request.artifact.format_version) != stored.5
                || request.artifact.artifact_digest.as_str() != stored.6
                || request.contract_version != intent.contract_version
                || request.change_set != durable
                || request.change_set.base_snapshot != intent.input_snapshot
            {
                return Err(LedgerError::Corrupt {
                    entity: "application request artifact authority",
                    detail: "canonical request, indexed artifact, digest, intent, or durable change set differs"
                        .into(),
                });
            }
            Ok(ApplicationRequestArtifactAuthority::ArtifactBound(
                Box::new(request),
            ))
        }
        (None, Some(stored)) => {
            require_contract_version("legacy application request gap", stored.3)?;
            if stored.0 != intent.sprint_id
                || stored.1 != intent.request_digest.as_str()
                || stored.2 != "PreV12Unbound"
                || Digest::sha256(request_bytes) != intent.request_digest
            {
                return Err(LedgerError::Corrupt {
                    entity: "legacy application request gap",
                    detail: "marker differs from the exact historical request lifecycle".into(),
                });
            }
            let decoded =
                decode_canonical_request::<ChangeSet>("legacy application request", request_bytes)
                    .ok()
                    .filter(|change_set| change_set.validate().is_ok());
            if let Some(change_set) = decoded {
                Ok(ApplicationRequestArtifactAuthority::LegacyBareChangeSet {
                    change_set,
                    request_digest: intent.request_digest.clone(),
                })
            } else {
                Ok(ApplicationRequestArtifactAuthority::LegacyUnbound {
                    request_digest: intent.request_digest.clone(),
                })
            }
        }
    }
}

pub(super) fn derive_post_completion_application_artifact_authority(
    connection: &Connection,
    sprint_id: &str,
    operation_id: &str,
    application_receipt_id: &str,
) -> Result<PostCompletionRollbackApplicationArtifactAuthority, LedgerError> {
    let application = load_application_evidence_from(connection, application_receipt_id)?;
    let effect = load_effect_from_with_receipts(connection, &application.receipt.effect_id, false)?;
    let classification = load_application_request_artifact_authority_from_parts(
        connection,
        &effect.intent,
        &effect.request_bytes,
    )?;
    let ApplicationRequestArtifactAuthority::ArtifactBound(request) = classification else {
        return Err(reference_mismatch(
            "post-completion application artifact authority",
            "legacy bare-ChangeSet application cannot authorize another mutation",
        ));
    };
    if application.receipt.sprint_id != sprint_id
        || request.change_set.change_set_id != application.receipt.change_set_id
        || request.change_set.base_snapshot != application.receipt.base_snapshot
        || request.change_set.result_snapshot != application.receipt.result_snapshot
    {
        return Err(reference_mismatch(
            "post-completion application artifact authority",
            "successful application receipt differs from its original artifact-bound request",
        ));
    }
    let authority = PostCompletionRollbackApplicationArtifactAuthority {
        contract_version: CONTRACT_VERSION,
        sprint_id: sprint_id.to_owned(),
        operation_id: operation_id.to_owned(),
        application_receipt_id: application_receipt_id.to_owned(),
        application_effect_id: application.receipt.effect_id,
        application_request_digest: effect.intent.request_digest,
        artifact: request.artifact,
    };
    authority.validate()?;
    Ok(authority)
}

pub(super) fn insert_post_completion_application_artifact_authority(
    transaction: &Transaction<'_>,
    authority: &PostCompletionRollbackApplicationArtifactAuthority,
) -> Result<Digest, LedgerError> {
    let authority_bytes = encode("post-completion application artifact authority", authority)?;
    let authority_digest = Digest::sha256(&authority_bytes);
    transaction.execute(
        "INSERT INTO post_completion_application_artifact_authorities (
            operation_id, sprint_id, application_receipt_id,
            application_effect_id, application_request_digest,
            change_set_id, base_snapshot, result_snapshot,
            artifact_format_version, artifact_digest, authority_digest,
            contract_version, authority_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   ?12, ?13)",
        params![
            authority.operation_id,
            authority.sprint_id,
            authority.application_receipt_id,
            authority.application_effect_id,
            authority.application_request_digest.as_str(),
            authority.artifact.change_set_id,
            authority.artifact.base_snapshot.as_str(),
            authority.artifact.result_snapshot.as_str(),
            i64::from(authority.artifact.format_version),
            authority.artifact.artifact_digest.as_str(),
            authority_digest.as_str(),
            i64::from(authority.contract_version),
            authority_bytes,
        ],
    )?;
    Ok(authority_digest)
}

#[allow(clippy::too_many_lines)]
pub(super) fn load_post_completion_application_artifact_authority_state(
    connection: &Connection,
    sprint_id: &str,
    operation_id: &str,
    application_receipt_id: &str,
) -> Result<PostCompletionRollbackApplicationArtifactAuthorityState, LedgerError> {
    let authority = connection
        .query_row(
            "SELECT sprint_id, application_receipt_id, application_effect_id,
                    application_request_digest, change_set_id, base_snapshot,
                    result_snapshot, artifact_format_version, artifact_digest,
                    authority_digest, contract_version, authority_json
             FROM post_completion_application_artifact_authorities
             WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Vec<u8>>(11)?,
                ))
            },
        )
        .optional()?;
    let legacy = connection
        .query_row(
            "SELECT sprint_id, application_receipt_id, gap_kind,
                    contract_version
             FROM legacy_post_completion_application_artifact_gaps
             WHERE operation_id = ?1",
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    match (authority, legacy) {
        (Some(_), Some(_)) => Err(LedgerError::Corrupt {
            entity: "post-completion application artifact authority",
            detail: "operation has both authoritative and legacy classifications".into(),
        }),
        (None, None) => Err(LedgerError::Corrupt {
            entity: "post-completion application artifact authority",
            detail: "operation has neither authoritative nor legacy classification".into(),
        }),
        (None, Some(stored)) => {
            require_contract_version("legacy post-completion application artifact gap", stored.3)?;
            if stored.0 != sprint_id
                || stored.1 != application_receipt_id
                || stored.2 != "LegacyMissing"
            {
                return Err(LedgerError::Corrupt {
                    entity: "legacy post-completion application artifact gap",
                    detail: "marker differs from its exact historical operation".into(),
                });
            }
            let application = load_application_evidence_from(connection, application_receipt_id)?;
            let effect =
                load_effect_from_with_receipts(connection, &application.receipt.effect_id, false)?;
            let source = load_application_request_artifact_authority_from_parts(
                connection,
                &effect.intent,
                &effect.request_bytes,
            )?;
            let ApplicationRequestArtifactAuthority::LegacyBareChangeSet { change_set, .. } =
                source
            else {
                return Err(LedgerError::Corrupt {
                    entity: "legacy post-completion application artifact gap",
                    detail: "legacy operation resolves to an authoritative v12 application request"
                        .into(),
                });
            };
            if application.receipt.sprint_id != sprint_id
                || change_set.change_set_id != application.receipt.change_set_id
                || change_set.base_snapshot != application.receipt.base_snapshot
                || change_set.result_snapshot != application.receipt.result_snapshot
            {
                return Err(LedgerError::Corrupt {
                    entity: "legacy post-completion application artifact gap",
                    detail:
                        "historical application receipt differs from its bare ChangeSet request"
                            .into(),
                });
            }
            Ok(PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing)
        }
        (Some(stored), None) => {
            require_contract_version("post-completion application artifact authority", stored.10)?;
            let authority: PostCompletionRollbackApplicationArtifactAuthority =
                decode_stored("post-completion application artifact authority", &stored.11)?;
            authority.validate().map_err(|error| LedgerError::Corrupt {
                entity: "post-completion application artifact authority",
                detail: error.to_string(),
            })?;
            let authority_digest = Digest::sha256(&stored.11);
            let source = derive_post_completion_application_artifact_authority(
                connection,
                sprint_id,
                operation_id,
                application_receipt_id,
            )?;
            if encode("post-completion application artifact authority", &authority)? != stored.11
                || authority != source
                || authority.operation_id != operation_id
                || authority.sprint_id != stored.0
                || authority.application_receipt_id != stored.1
                || authority.application_effect_id != stored.2
                || authority.application_request_digest.as_str() != stored.3
                || authority.artifact.change_set_id != stored.4
                || authority.artifact.base_snapshot.as_str() != stored.5
                || authority.artifact.result_snapshot.as_str() != stored.6
                || i64::from(authority.artifact.format_version) != stored.7
                || authority.artifact.artifact_digest.as_str() != stored.8
                || authority_digest.as_str() != stored.9
            {
                return Err(LedgerError::Corrupt {
                    entity: "post-completion application artifact authority",
                    detail:
                        "canonical authority, digest, source application, or indexed fields differ"
                            .into(),
                });
            }
            Ok(
                PostCompletionRollbackApplicationArtifactAuthorityState::Authoritative {
                    authority: Box::new(authority),
                    authority_digest,
                },
            )
        }
    }
}

pub(super) fn require_post_completion_application_artifact_authority(
    connection: &Connection,
    sprint_id: &str,
    operation_id: &str,
    application_receipt_id: &str,
) -> Result<PostCompletionRollbackApplicationArtifactAuthority, LedgerError> {
    match load_post_completion_application_artifact_authority_state(
        connection,
        sprint_id,
        operation_id,
        application_receipt_id,
    )? {
        PostCompletionRollbackApplicationArtifactAuthorityState::Authoritative {
            authority,
            ..
        } => Ok(*authority),
        PostCompletionRollbackApplicationArtifactAuthorityState::LegacyMissing => {
            Err(reference_mismatch(
                "post-completion application artifact authority",
                "legacy operation cannot authorize a new launch, session, or effect",
            ))
        }
    }
}

fn require_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(contract_error(field, "must not be blank"))
    } else {
        Ok(())
    }
}

fn contract_error(field: &'static str, detail: impl Into<String>) -> ContractError {
    ContractError::new(field, detail)
}
