-- Schema v33 hardens the existing parallel current-authority lattice against
-- SQLite's INSERT OR REPLACE conflict algorithm.  With recursive triggers
-- disabled, SQLite may delete a conflicting row without running that row's
-- BEFORE DELETE trigger.  Every primary-key and alternate-UNIQUE identity on
-- the pre-repair current tables is therefore rejected before conflict
-- resolution.  The three current repair-task dormancy tables already carry
-- equivalent guards in their schema-v32 migration.

CREATE TRIGGER current_sprint_authorities_v32_no_replace_v33
BEFORE INSERT ON current_sprint_authorities_v32
WHEN EXISTS (
    SELECT 1 FROM current_sprint_authorities_v32 existing
    WHERE existing.sprint_id = NEW.sprint_id
       OR existing.sprint_spec_digest = NEW.sprint_spec_digest
       OR existing.task_graph_id = NEW.task_graph_id
)
BEGIN SELECT RAISE(ABORT, 'current sprint authority identity already exists'); END;

CREATE TRIGGER current_task_graph_authorities_v32_no_replace_v33
BEFORE INSERT ON current_task_graph_authorities_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_graph_authorities_v32 existing
    WHERE existing.graph_id = NEW.graph_id
       OR existing.sprint_id = NEW.sprint_id
       OR existing.graph_digest = NEW.graph_digest
)
BEGIN SELECT RAISE(ABORT, 'current task graph authority identity already exists'); END;

CREATE TRIGGER current_task_nodes_v32_no_replace_v33
BEFORE INSERT ON current_task_nodes_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_nodes_v32 existing
    WHERE (existing.sprint_id = NEW.sprint_id AND existing.task_id = NEW.task_id)
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.declaration_ordinal = NEW.declaration_ordinal)
       OR (NEW.repair_slot_ordinal IS NOT NULL
           AND existing.sprint_id = NEW.sprint_id
           AND existing.repair_slot_ordinal = NEW.repair_slot_ordinal)
)
BEGIN SELECT RAISE(ABORT, 'current task node identity already exists'); END;

CREATE TRIGGER current_task_done_sets_v32_no_replace_v33
BEFORE INSERT ON current_task_done_sets_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_done_sets_v32 existing
    WHERE existing.set_digest = NEW.set_digest
       OR (existing.sprint_id = NEW.sprint_id AND existing.set_digest = NEW.set_digest)
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone set identity already exists'); END;

CREATE TRIGGER current_task_done_members_v32_no_replace_v33
BEFORE INSERT ON current_task_done_members_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_done_members_v32 existing
    WHERE (existing.set_digest = NEW.set_digest
           AND existing.member_ordinal = NEW.member_ordinal)
       OR (existing.set_digest = NEW.set_digest AND existing.task_id = NEW.task_id)
       OR (existing.set_digest = NEW.set_digest
           AND existing.task_done_proof_id = NEW.task_done_proof_id)
       OR (existing.set_digest = NEW.set_digest
           AND existing.integration_receipt_id = NEW.integration_receipt_id)
       OR (NEW.empty_change_set_id IS NOT NULL
           AND existing.set_digest = NEW.set_digest
           AND existing.empty_change_set_id = NEW.empty_change_set_id)
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone member identity already exists'); END;

CREATE TRIGGER current_task_done_set_seals_v32_no_replace_v33
BEFORE INSERT ON current_task_done_set_seals_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_done_set_seals_v32 existing
    WHERE existing.set_digest = NEW.set_digest
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone set seal identity already exists'); END;

CREATE TRIGGER current_criterion_evidence_sets_v32_no_replace_v33
BEFORE INSERT ON current_criterion_evidence_sets_v32
WHEN EXISTS (
    SELECT 1 FROM current_criterion_evidence_sets_v32 existing
    WHERE existing.set_digest = NEW.set_digest
       OR (existing.sprint_id = NEW.sprint_id AND existing.set_digest = NEW.set_digest)
)
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence set identity already exists'); END;

CREATE TRIGGER current_criterion_evidence_members_v32_no_replace_v33
BEFORE INSERT ON current_criterion_evidence_members_v32
WHEN EXISTS (
    SELECT 1 FROM current_criterion_evidence_members_v32 existing
    WHERE (existing.set_digest = NEW.set_digest
           AND existing.member_ordinal = NEW.member_ordinal)
       OR (existing.set_digest = NEW.set_digest
           AND existing.criterion_id = NEW.criterion_id)
       OR (existing.set_digest = NEW.set_digest
           AND existing.evidence_receipt_id = NEW.evidence_receipt_id)
)
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence member identity already exists'); END;

CREATE TRIGGER current_criterion_evidence_set_seals_v32_no_replace_v33
BEFORE INSERT ON current_criterion_evidence_set_seals_v32
WHEN EXISTS (
    SELECT 1 FROM current_criterion_evidence_set_seals_v32 existing
    WHERE existing.set_digest = NEW.set_digest
)
BEGIN SELECT RAISE(ABORT, 'current criterion-evidence set seal identity already exists'); END;

CREATE TRIGGER current_final_verification_controls_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_controls_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_controls_v32 existing
    WHERE existing.control_id = NEW.control_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.control_id = NEW.control_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification control identity already exists'); END;

CREATE TRIGGER current_final_verification_attempts_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_attempts_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_attempts_v32 existing
    WHERE existing.attempt_id = NEW.attempt_id
       OR existing.request_id = NEW.request_id
       OR existing.final_verification_admission_id = NEW.final_verification_admission_id
       OR existing.authority_digest = NEW.authority_digest
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.attempt_ordinal = NEW.attempt_ordinal)
       OR (existing.sprint_id = NEW.sprint_id AND existing.attempt_id = NEW.attempt_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification attempt identity already exists'); END;

CREATE TRIGGER current_final_verification_capture_closures_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_capture_closures_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_capture_closures_v32 existing
    WHERE existing.closure_id = NEW.closure_id
       OR existing.attempt_id = NEW.attempt_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.closure_id = NEW.closure_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification capture identity already exists'); END;

CREATE TRIGGER current_final_verification_outcomes_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_outcomes_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_outcomes_v32 existing
    WHERE existing.outcome_id = NEW.outcome_id
       OR existing.attempt_id = NEW.attempt_id
       OR existing.closure_id = NEW.closure_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.outcome_id = NEW.outcome_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification outcome identity already exists'); END;

CREATE TRIGGER current_final_verification_repair_activations_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_repair_activations_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_repair_activations_v32 existing
    WHERE existing.activation_id = NEW.activation_id
       OR existing.failed_attempt_id = NEW.failed_attempt_id
       OR existing.failure_outcome_id = NEW.failure_outcome_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.slot_ordinal = NEW.slot_ordinal)
       OR (existing.sprint_id = NEW.sprint_id AND existing.repair_task_id = NEW.repair_task_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification repair activation identity already exists'); END;

CREATE TRIGGER current_final_verification_repair_completions_v32_no_replace_v33
BEFORE INSERT ON current_final_verification_repair_completions_v32
WHEN EXISTS (
    SELECT 1 FROM current_final_verification_repair_completions_v32 existing
    WHERE existing.completion_id = NEW.completion_id
       OR existing.request_id = NEW.request_id
       OR existing.activation_id = NEW.activation_id
       OR existing.failed_attempt_id = NEW.failed_attempt_id
       OR existing.repair_task_done_proof_id = NEW.repair_task_done_proof_id
       OR existing.integration_receipt_id = NEW.integration_receipt_id
       OR existing.change_set_id = NEW.change_set_id
       OR (existing.sprint_id = NEW.sprint_id AND existing.completion_id = NEW.completion_id)
)
BEGIN SELECT RAISE(ABORT, 'current final-verification repair completion identity already exists'); END;

CREATE TRIGGER current_sprint_terminal_outcomes_v32_no_replace_v33
BEFORE INSERT ON current_sprint_terminal_outcomes_v32
WHEN EXISTS (
    SELECT 1 FROM current_sprint_terminal_outcomes_v32 existing
    WHERE existing.sprint_id = NEW.sprint_id
       OR existing.source_attempt_id = NEW.source_attempt_id
       OR existing.source_outcome_id = NEW.source_outcome_id
)
BEGIN SELECT RAISE(ABORT, 'current sprint terminal identity already exists'); END;

CREATE TRIGGER current_task_done_sources_v32_no_replace_v33
BEFORE INSERT ON current_task_done_sources_v32
WHEN EXISTS (
    SELECT 1 FROM current_task_done_sources_v32 existing
    WHERE existing.task_done_proof_id = NEW.task_done_proof_id
       OR existing.source_digest = NEW.source_digest
       OR (NEW.empty_change_set_id IS NOT NULL
           AND existing.task_done_proof_id = NEW.task_done_proof_id
           AND existing.sprint_id = NEW.sprint_id
           AND existing.task_id = NEW.task_id
           AND existing.integration_receipt_id = NEW.integration_receipt_id
           AND existing.integration_kind = NEW.integration_kind
           AND existing.empty_change_set_id = NEW.empty_change_set_id
           AND existing.input_snapshot = NEW.input_snapshot
           AND existing.result_snapshot = NEW.result_snapshot)
)
BEGIN SELECT RAISE(ABORT, 'current TaskDone source identity already exists'); END;

CREATE TRIGGER current_sprint_criteria_v32_no_replace_v33
BEFORE INSERT ON current_sprint_criteria_v32
WHEN EXISTS (
    SELECT 1 FROM current_sprint_criteria_v32 existing
    WHERE (existing.sprint_id = NEW.sprint_id AND existing.criterion_id = NEW.criterion_id)
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.criterion_ordinal = NEW.criterion_ordinal)
)
BEGIN SELECT RAISE(ABORT, 'current criterion projection identity already exists'); END;

CREATE TRIGGER current_automated_verification_sources_v32_no_replace_v33
BEFORE INSERT ON current_automated_verification_sources_v32
WHEN EXISTS (
    SELECT 1 FROM current_automated_verification_sources_v32 existing
    WHERE existing.verification_receipt_id = NEW.verification_receipt_id
       OR (existing.verification_receipt_id = NEW.verification_receipt_id
           AND existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.snapshot_digest = NEW.snapshot_digest)
)
BEGIN SELECT RAISE(ABORT, 'current automated verification source identity already exists'); END;

CREATE TRIGGER current_human_acceptance_prompts_v32_no_replace_v33
BEFORE INSERT ON current_human_acceptance_prompts_v32
WHEN EXISTS (
    SELECT 1 FROM current_human_acceptance_prompts_v32 existing
    WHERE existing.prompt_id = NEW.prompt_id
       OR (existing.prompt_id = NEW.prompt_id
           AND existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.snapshot_digest = NEW.snapshot_digest)
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.issued_event_sequence = NEW.issued_event_sequence)
)
BEGIN SELECT RAISE(ABORT, 'current human acceptance prompt identity already exists'); END;

CREATE TRIGGER current_human_acceptance_decisions_v32_no_replace_v33
BEFORE INSERT ON current_human_acceptance_decisions_v32
WHEN EXISTS (
    SELECT 1 FROM current_human_acceptance_decisions_v32 existing
    WHERE existing.decision_id = NEW.decision_id
       OR existing.prompt_id = NEW.prompt_id
       OR (existing.decision_id = NEW.decision_id
           AND existing.prompt_id = NEW.prompt_id
           AND existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.snapshot_digest = NEW.snapshot_digest)
)
BEGIN SELECT RAISE(ABORT, 'current human acceptance decision identity already exists'); END;

CREATE TRIGGER current_criterion_evidence_receipts_v32_no_replace_v33
BEFORE INSERT ON current_criterion_evidence_receipts_v32
WHEN EXISTS (
    SELECT 1 FROM current_criterion_evidence_receipts_v32 existing
    WHERE existing.receipt_id = NEW.receipt_id
       OR (existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.snapshot_digest = NEW.snapshot_digest)
       OR (existing.receipt_id = NEW.receipt_id
           AND existing.sprint_id = NEW.sprint_id
           AND existing.criterion_id = NEW.criterion_id
           AND existing.snapshot_digest = NEW.snapshot_digest
           AND existing.evidence_kind = NEW.evidence_kind)
)
BEGIN SELECT RAISE(ABORT, 'current criterion evidence receipt identity already exists'); END;
