//! Ledger unit tests, split from the former inline module by pure
//! movement; part files are mechanical chunks pending semantic regroup.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};

use super::*;
use crate::{
    AcceptanceCriterion, AcceptanceKind, AgentEventKind, ApplicationRequest,
    CommandOutputArtifactSourceV1, CommandOutputStreamArtifactV1, CommandOutputStreamV1,
    CommandSpec, CommandTerminationV1, Digest, ExecutionNetwork, ExecutionOrigin, MutationMode,
    PathScope, ProviderProfile, ProviderResponseResult, ResourceLimits,
    SPRINT_AUTHORITY_CONTRACT_VERSION_V2, SprintBudget, SprintBudgetV2, SprintSpecV2,
    TaskAttemptTerminalEffect, TaskGraphV2, TaskIntegrationArtifactReference, TaskPurposeV2,
    TaskSpec, TaskSpecV2, WorkerCleanupBackend, WorkspaceGrant, WorkspaceNetworkPolicy,
    WorkspacePermissions,
};

pub(crate) mod schema_template;

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDatabase {
    directory: PathBuf,
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let unique = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "grok-build-ledger-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create isolated test directory");
        let path = directory.join("ledger.sqlite3");
        Self { directory, path }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn bind_complete_output_artifacts(
    ledger: &EventLedger,
    verification: &mut VerificationReceipt,
    effect_id: &str,
    runner_launch_id: &str,
    runner_session_id: &str,
    stdout: Vec<u8>,
) -> (Option<CommandOutputArtifactSetReferenceV1>, Vec<u8>) {
    if !command_output_artifact_set_schema_is_installed(&ledger.connection)
        .expect("inspect command output artifact schema")
    {
        verification.output_digest = Digest::sha256(&stdout);
        return (None, stdout);
    }
    let request_bytes =
        encode("verification command request", &verification.command).expect("encode command");
    let artifacts = CommandOutputArtifactSetReferenceV1::try_new(
        CommandOutputArtifactSourceV1 {
            sprint_id: verification.sprint_id.clone(),
            runner_launch_id: runner_launch_id.to_owned(),
            runner_session_id: runner_session_id.to_owned(),
            effect_id: effect_id.to_owned(),
            request_digest: Digest::sha256(&request_bytes),
        },
        CommandOutputStreamArtifactV1 {
            stream: CommandOutputStreamV1::Stdout,
            byte_length: u64::try_from(stdout.len()).expect("test output length fits u64"),
            content_digest: Digest::sha256(&stdout),
        },
        CommandOutputStreamArtifactV1 {
            stream: CommandOutputStreamV1::Stderr,
            byte_length: 0,
            content_digest: Digest::sha256(&[]),
        },
    )
    .expect("construct complete output artifact reference");
    let output_evidence_bytes = artifacts
        .output_evidence_bytes()
        .expect("construct complete output commitment");
    verification.output_digest = Digest::sha256(&output_evidence_bytes);
    (Some(artifacts), output_evidence_bytes)
}

#[derive(Clone, Debug)]
struct PreV24CompletionProjection {
    final_report: FinalReport,
    receipt: CompletionReceipt,
    event: AgentEvent,
}

impl PreV24CompletionProjection {
    fn assert_matches_pre_v24_rows(&self, ledger: &EventLedger) {
        assert_eq!(
            ledger
                .load_completion_receipt(&self.receipt.receipt_id)
                .expect("load exact pre-v24 completion receipt"),
            self.receipt
        );
        assert_eq!(
            load_final_report_from(&ledger.connection, &self.final_report.report_id)
                .expect("load exact pre-v24 final report"),
            self.final_report
        );
        assert_eq!(
            load_event_by_id(&ledger.connection, &self.event.event_id)
                .expect("load exact pre-v24 completion event"),
            self.event
        );
        let proof: (String, String, String, i64) = ledger
            .connection
            .query_row(
                "SELECT proof_state, completion_receipt_id, completion_event_id,
                            terminal_at_unix_ms
                     FROM sprint_completion_proof_states WHERE sprint_id = ?1",
                [&self.receipt.sprint_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("load exact pre-v24 completion proof row");
        assert_eq!(proof.0, "ProvenV9");
        assert_eq!(proof.1, self.receipt.receipt_id);
        assert_eq!(proof.2, self.event.event_id);
        assert_eq!(
            proof.3,
            i64::try_from(self.receipt.completed_at_unix_ms)
                .expect("completion timestamp fits SQLite")
        );
    }

    fn assert_matches_migrated(&self, completion: &PersistedCompletion) {
        assert_eq!(completion.final_report, self.final_report);
        assert_eq!(completion.receipt, self.receipt);
        assert_eq!(
            completion.completion_receipt_wire_digest,
            Digest::sha256(
                &encode_legacy_completion_receipt(&self.receipt)
                    .expect("encode expected historical completion receipt")
            )
        );
        assert_eq!(completion.event, self.event);
        assert_eq!(completion.terminal_state, SprintState::Completed);
        assert!(matches!(
            (&self.receipt.application, &completion.application),
            (
                CompletionApplication::Applied { .. },
                PersistedCompletionApplication::Applied { .. }
            ) | (
                CompletionApplication::VerifiedNoOp { .. },
                PersistedCompletionApplication::VerifiedNoOp(_)
            )
        ));
    }
}

fn record_pre_v24_successful_completion_for_test(
    ledger: &mut EventLedger,
    report: &FinalReport,
    receipt: &CompletionReceipt,
    event: &AgentEvent,
) -> Result<PreV24CompletionProjection, LedgerError> {
    ledger.record_pre_v24_successful_completion_rows(report, receipt, event)?;
    Ok(PreV24CompletionProjection {
        final_report: report.clone(),
        receipt: receipt.clone(),
        event: event.clone(),
    })
}

fn load_migrated_pre_v24_completion(
    ledger: &EventLedger,
    expected: &PreV24CompletionProjection,
) -> PersistedCompletion {
    let version = ledger
        .connection
        .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
        .expect("read migrated completion schema version");
    assert_eq!(version, SCHEMA_VERSION);
    let completion = ledger
        .load_completion(&expected.receipt.sprint_id)
        .expect("load migrated pre-v24 completion")
        .expect("migrated pre-v24 completion remains present");
    expected.assert_matches_migrated(&completion);
    assert!(matches!(
        &completion.live_state_authority,
        PersistedCompletionLiveStateAuthority::PreV24MigrationExemption(_)
    ));
    completion
}

fn digest(character: char) -> Digest {
    Digest::parse(character.to_string().repeat(64)).expect("valid digest")
}

include!("part_01.rs");
include!("part_02.rs");
include!("part_03.rs");
include!("part_04.rs");
include!("part_05.rs");
include!("part_06.rs");
include!("part_07.rs");
include!("part_08.rs");
include!("part_09.rs");
include!("part_10.rs");
include!("part_11.rs");
include!("part_12.rs");
include!("part_13.rs");
include!("part_14.rs");
include!("../task_attempt_finish_tests.rs");
include!("../task_attempt_finish_standard_tests.rs");
include!("../task_attempt_migration_tests.rs");
include!("../task_attempt_phase_recovery_tests.rs");
include!("../task_attempt_recovery_tests.rs");
include!("../task_attempt_unknown_tests.rs");
include!("../sprint_live_state_capture_v23_tests.rs");
include!("../sprint_live_state_capture_v23_additional_tests.rs");
include!("../completion_live_state_capture_v24_tests.rs");
include!("../live_state_drift_blocked_v25_tests.rs");
include!("../sensitive_output_rejection_v29_tests.rs");
include!("../sensitive_output_attempt_repair_v30_tests.rs");
include!("migration_v33.rs");
include!("migration_v34.rs");
include!("migration_v38.rs");
include!("contained_command_release.rs");
