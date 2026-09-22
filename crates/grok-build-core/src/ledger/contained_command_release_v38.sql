-- Schema v38: a release subject whose subject is the contained command.
--
-- The runner-launch admission family (v13) models the release of a *runner
-- process*: its subject is a launch, its claim authorizes handing a held child
-- its own image, and its preparation outcome is `HeldChildPrepared`. A
-- contained command is a different subject entirely -- it is an effect inside a
-- sprint, it runs inside a runner that has already been released, and there may
-- be many of them per launch. Reusing the launch claim for it would authorize
-- releasing one process on evidence gathered about another, which is the
-- substitution this schema exists to prevent.
--
-- So this is additive and distinct. Nothing in the v13 family is altered,
-- renamed, or relaxed, and no existing row is rewritten.

CREATE TABLE contained_command_release_admissions (
    command_effect_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    -- The launch whose runner will perform the release. It is recorded so the
    -- desktop can refuse a claim minted for one runner and presented by
    -- another, and it is deliberately NOT the subject: two commands in one
    -- runner share this value and must still be distinct admissions.
    launch_id TEXT NOT NULL,
    -- Digest of the exact contained-command request this admits. The claim
    -- carries it to the runner, and the runner requires the plan it is about
    -- to release to reproduce it, so an admission cannot travel to a different
    -- command.
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    -- Only the Linux backend can host a contained command. `MacOsDedicatedIdentity`
    -- is deliberately absent rather than reserved: ADR-0006's 2026-08-04
    -- amendment makes Linux the containment substrate for both hosts, and a
    -- value no code can honour should not be expressible.
    platform_backend TEXT NOT NULL CHECK (platform_backend IN ('LinuxCgroupV2')),
    contract_version INTEGER NOT NULL CHECK (contract_version > 0),
    admitted_at_unix_ms INTEGER NOT NULL CHECK (admitted_at_unix_ms > 0),
    admission_json BLOB NOT NULL CHECK (
        length(admission_json) BETWEEN 1 AND 65536
    ),
    UNIQUE (sprint_id, command_effect_id),
    FOREIGN KEY (sprint_id, command_effect_id)
        REFERENCES effect_intents(sprint_id, effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE INDEX contained_command_release_admissions_launch_idx
ON contained_command_release_admissions (sprint_id, launch_id);

-- One terminal row per admission, written after the runner reports back.
--
-- Separate from the admission because an admission that never produced a
-- release is a real and different state from one that produced a terminal, and
-- collapsing them would make "was this command released?" unanswerable after a
-- crash.
CREATE TABLE contained_command_release_outcomes (
    command_effect_id TEXT PRIMARY KEY NOT NULL,
    sprint_id TEXT NOT NULL,
    -- `Released` means the runner observed a same-PID exec under the plan's own
    -- containment artefacts. `Refused` means it did not, and carries no
    -- terminal. There is no third value: a release either happened or it did
    -- not, and an ambiguous one is recorded as `Refused` with its reason.
    disposition TEXT NOT NULL CHECK (disposition IN ('Released', 'Refused')),
    -- Present exactly when the disposition is `Released`.
    terminal_json BLOB NULL CHECK (
        terminal_json IS NULL OR length(terminal_json) BETWEEN 1 AND 65536
    ),
    refusal_reason TEXT NULL CHECK (
        refusal_reason IS NULL OR length(refusal_reason) BETWEEN 1 AND 4096
    ),
    recorded_at_unix_ms INTEGER NOT NULL CHECK (recorded_at_unix_ms > 0),
    CHECK (
        (disposition = 'Released' AND terminal_json IS NOT NULL AND refusal_reason IS NULL)
        OR
        (disposition = 'Refused' AND terminal_json IS NULL AND refusal_reason IS NOT NULL)
    ),
    UNIQUE (sprint_id, command_effect_id),
    FOREIGN KEY (command_effect_id)
        REFERENCES contained_command_release_admissions(command_effect_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

-- An outcome may never be replaced. The release is one-shot on the runner side
-- and it is one-shot here, so a second report is a defect rather than an
-- update.
CREATE TRIGGER contained_command_release_outcomes_no_replace
BEFORE UPDATE ON contained_command_release_outcomes
BEGIN
    SELECT RAISE(
        ABORT,
        'contained command release outcomes are write-once and cannot be replaced'
    );
END;
