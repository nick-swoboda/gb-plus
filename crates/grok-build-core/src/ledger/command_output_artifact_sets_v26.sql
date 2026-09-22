CREATE UNIQUE INDEX effect_observations_command_output_identity_idx
ON effect_observations (observation_id, effect_id, sprint_id, request_digest);

CREATE UNIQUE INDEX effect_session_bindings_command_output_identity_idx
ON effect_session_bindings (sprint_id, effect_id, launch_id, session_id);

CREATE UNIQUE INDEX verification_effect_evidence_command_output_identity_idx
ON verification_effect_evidence (
    effect_id, observation_id, sprint_id, runner_launch_id, runner_session_id
);

CREATE TABLE command_output_artifact_sets (
    effect_id TEXT PRIMARY KEY NOT NULL,
    observation_id TEXT NOT NULL UNIQUE,
    sprint_id TEXT NOT NULL,
    runner_launch_id TEXT NOT NULL,
    runner_session_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    manifest_digest TEXT NOT NULL UNIQUE,
    stdout_byte_length INTEGER NOT NULL CHECK (stdout_byte_length >= 0),
    stdout_content_digest TEXT NOT NULL,
    stderr_byte_length INTEGER NOT NULL CHECK (stderr_byte_length >= 0),
    stderr_content_digest TEXT NOT NULL,
    reference_json BLOB NOT NULL CHECK (length(reference_json) > 0),
    UNIQUE (sprint_id, effect_id),
    CHECK (
        grok_command_output_artifact_reference_matches(
            reference_json,
            format_version,
            sprint_id,
            runner_launch_id,
            runner_session_id,
            effect_id,
            request_digest,
            manifest_digest,
            stdout_byte_length,
            stdout_content_digest,
            stderr_byte_length,
            stderr_content_digest
        ) = 1
    ),
    FOREIGN KEY (sprint_id, effect_id)
        REFERENCES effect_intents(sprint_id, effect_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id, effect_id, sprint_id, request_digest)
        REFERENCES effect_observations(
            observation_id, effect_id, sprint_id, request_digest
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, effect_id, runner_launch_id, runner_session_id)
        REFERENCES effect_session_bindings(
            sprint_id, effect_id, launch_id, session_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (effect_id, observation_id, sprint_id, runner_launch_id, runner_session_id)
        REFERENCES verification_effect_evidence(
            effect_id, observation_id, sprint_id, runner_launch_id, runner_session_id
        ) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (sprint_id, runner_launch_id)
        REFERENCES runner_launch_intents(sprint_id, launch_id) ON DELETE RESTRICT,
    FOREIGN KEY (sprint_id, runner_session_id)
        REFERENCES runner_session_policies(sprint_id, session_id) ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE INDEX command_output_artifact_sets_source_idx
ON command_output_artifact_sets (
    sprint_id, runner_launch_id, runner_session_id, request_digest, manifest_digest
);

CREATE INDEX command_output_artifact_sets_stdout_idx
ON command_output_artifact_sets (stdout_content_digest, stdout_byte_length);

CREATE INDEX command_output_artifact_sets_stderr_idx
ON command_output_artifact_sets (stderr_content_digest, stderr_byte_length);

CREATE TRIGGER command_output_artifact_sets_exact_source
BEFORE INSERT ON command_output_artifact_sets
WHEN NOT EXISTS (
    SELECT 1
    FROM effect_intents intent
    JOIN effect_session_bindings binding
      ON binding.effect_id = intent.effect_id
     AND binding.sprint_id = intent.sprint_id
    WHERE intent.effect_id = NEW.effect_id
      AND intent.sprint_id = NEW.sprint_id
      AND intent.effect_kind = 'RunCommand'
      AND intent.request_digest = NEW.request_digest
      AND binding.launch_id = NEW.runner_launch_id
      AND binding.session_id = NEW.runner_session_id
)
BEGIN
    SELECT RAISE(ABORT, 'command output artifact source must match its RunCommand authority');
END;

CREATE TRIGGER command_output_artifact_sets_no_backfill
BEFORE INSERT ON command_output_artifact_sets
WHEN EXISTS (
    SELECT 1 FROM effect_observations
    WHERE effect_id = NEW.effect_id OR observation_id = NEW.observation_id
) OR EXISTS (
    SELECT 1 FROM verification_effect_evidence
    WHERE effect_id = NEW.effect_id OR observation_id = NEW.observation_id
)
BEGIN
    SELECT RAISE(ABORT, 'command output artifacts must commit before their new terminal rows');
END;

CREATE TRIGGER verification_effect_evidence_requires_command_output_artifacts_v26
BEFORE INSERT ON verification_effect_evidence
WHEN NOT EXISTS (
    SELECT 1
    FROM command_output_artifact_sets artifacts
    WHERE artifacts.effect_id = NEW.effect_id
      AND artifacts.observation_id = NEW.observation_id
      AND artifacts.sprint_id = NEW.sprint_id
      AND artifacts.runner_launch_id = NEW.runner_launch_id
      AND artifacts.runner_session_id = NEW.runner_session_id
      AND grok_current_verification_output_artifact_matches(
          NEW.evidence_json, artifacts.reference_json
      ) = 1
)
BEGIN
    SELECT RAISE(ABORT, 'current verification evidence requires exact complete-output artifacts');
END;

CREATE TRIGGER effect_observations_command_output_artifact_success_v26
BEFORE INSERT ON effect_observations
WHEN EXISTS (
    SELECT 1
    FROM command_output_artifact_sets artifacts
    WHERE artifacts.observation_id = NEW.observation_id
      AND (
          NEW.outcome != 'Succeeded'
          OR NEW.effect_kind != 'RunCommand'
          OR artifacts.effect_id != NEW.effect_id
          OR artifacts.sprint_id != NEW.sprint_id
          OR artifacts.request_digest != NEW.request_digest
      )
)
BEGIN
    SELECT RAISE(ABORT, 'command output artifacts require their exact successful RunCommand observation');
END;

CREATE TRIGGER command_output_artifact_sets_terminal_fence
BEFORE INSERT ON command_output_artifact_sets
WHEN EXISTS (
    SELECT 1 FROM sprint_completion_proof_states WHERE sprint_id = NEW.sprint_id
) OR EXISTS (
    SELECT 1 FROM sprint_non_success_terminal_outcomes WHERE sprint_id = NEW.sprint_id
) OR EXISTS (
    SELECT 1 FROM sprint_terminal_states WHERE sprint_id = NEW.sprint_id
)
BEGIN
    SELECT RAISE(ABORT, 'terminal sprints reject command output artifacts');
END;

CREATE TRIGGER command_output_artifact_sets_no_update
BEFORE UPDATE ON command_output_artifact_sets
BEGIN
    SELECT RAISE(ABORT, 'command output artifact sets are immutable');
END;

CREATE TRIGGER command_output_artifact_sets_no_delete
BEFORE DELETE ON command_output_artifact_sets
BEGIN
    SELECT RAISE(ABORT, 'command output artifact sets are immutable');
END;
