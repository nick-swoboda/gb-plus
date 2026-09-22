// The v38 contained-command release subject, written and read back.
//
// This is a fragment included from `tests/mod.rs`.
//
// The subject landed with a reader and an exclusion but no writer, so the
// exclusion could never have succeeded in production: it reads a row nothing
// could create. These tests exist because that gap was invisible until someone
// tried to use it.

fn admitted_release_ledger() -> (TestDatabase, EffectIntent) {
    let database = TestDatabase::new();
    let mut ledger = EventLedger::open(&database.path).expect("open a v38 ledger");
    prepare_effect_input(&mut ledger);
    let intent = effect_intent("effect-contained-1", "idem-contained-1", 2_000);
    let proposal = effect_proposal_event(&intent, 1, "event-contained-1");
    record_test_effect_intent(&mut ledger, &intent, &proposal).expect("persist the command effect");
    (database, intent)
}

fn admission_for(intent: &EffectIntent) -> ContainedCommandReleaseAdmissionRecord {
    ContainedCommandReleaseAdmissionRecord {
        contract_version: CONTRACT_VERSION,
        sprint_id: intent.sprint_id.clone(),
        command_effect_id: intent.effect_id.clone(),
        launch_id: "launch-contained-1".to_owned(),
        request_digest: intent.request_digest.to_string(),
        native_evidence_digest: Digest::sha256(b"desktop-outer-preparation-evidence").to_string(),
        platform_backend: "LinuxCgroupV2".to_owned(),
        admitted_at_unix_ms: 3_000,
    }
}

/// The desktop writes an admission and the exclusion then mints a claim from it.
///
/// Before this, the exclusion's only outcome in production was the
/// "no admission exists" refusal, because nothing could write one.
#[test]
fn a_written_admission_is_read_back_and_mints_a_live_claim() {
    let (database, intent) = admitted_release_ledger();
    let mut ledger = EventLedger::open(&database.path).expect("reopen the ledger");
    let record = admission_for(&intent);
    let persisted = ledger
        .record_contained_command_release_admission(&record)
        .expect("the desktop admits this command for release");

    let observed = ledger
        .with_contained_command_release_exclusion(&persisted, |claim| {
            (
                claim.command_effect_id().to_owned(),
                claim.request_digest().to_owned(),
                claim.native_evidence_digest().to_owned(),
            )
        })
        .expect("the exclusion mints a claim from the written admission");

    assert_eq!(observed.0, intent.effect_id);
    assert_eq!(observed.1, intent.request_digest.to_string());
    assert_eq!(observed.2, record.native_evidence_digest);
}

/// An admission cannot name a command effect the ledger has no record of.
///
/// The foreign key is the guard, and this is the control arm for it: one input
/// varied -- an effect id that was never recorded -- and the write is refused.
#[test]
fn an_admission_for_an_unknown_effect_is_refused() {
    let (database, intent) = admitted_release_ledger();
    let mut ledger = EventLedger::open(&database.path).expect("reopen the ledger");
    let mut travelled = admission_for(&intent);
    travelled.command_effect_id = "effect-that-was-never-recorded".to_owned();
    assert!(
        ledger
            .record_contained_command_release_admission(&travelled)
            .is_err(),
        "an admission for an unrecorded effect must be refused"
    );
}

/// One admission per command effect. A second is a defect, not an update.
#[test]
fn a_second_admission_for_the_same_effect_is_refused() {
    let (database, intent) = admitted_release_ledger();
    let mut ledger = EventLedger::open(&database.path).expect("reopen the ledger");
    let record = admission_for(&intent);
    ledger
        .record_contained_command_release_admission(&record)
        .expect("the first admission is written");
    assert!(
        ledger
            .record_contained_command_release_admission(&record)
            .is_err(),
        "a second admission for the same command effect must be refused"
    );
}

/// The release is one-shot: once an outcome exists, the exclusion refuses.
#[test]
fn an_admission_with_a_recorded_outcome_no_longer_mints_a_claim() {
    let (database, intent) = admitted_release_ledger();
    let mut ledger = EventLedger::open(&database.path).expect("reopen the ledger");
    let persisted = ledger
        .record_contained_command_release_admission(&admission_for(&intent))
        .expect("admit the command");

    ledger
        .record_contained_command_release_outcome(
            &intent.sprint_id,
            &intent.effect_id,
            &ContainedCommandReleaseDisposition::Released {
                terminal_json: b"{\"Exit\":9}".to_vec(),
            },
            4_000,
        )
        .expect("record the terminal the runner reported");

    assert!(
        ledger
            .with_contained_command_release_exclusion(&persisted, |_| ())
            .is_err(),
        "a command whose release already produced an outcome must not be admitted again"
    );
}

/// An outcome cannot be recorded for a command that was never admitted, and a
/// second outcome cannot replace the first.
#[test]
fn outcomes_require_an_admission_and_are_write_once() {
    let (database, intent) = admitted_release_ledger();
    let mut ledger = EventLedger::open(&database.path).expect("reopen the ledger");

    assert!(
        ledger
            .record_contained_command_release_outcome(
                &intent.sprint_id,
                &intent.effect_id,
                &ContainedCommandReleaseDisposition::Refused {
                    reason: "no admission was ever written".to_owned(),
                },
                4_000,
            )
            .is_err(),
        "an outcome without an admission must be refused"
    );

    ledger
        .record_contained_command_release_admission(&admission_for(&intent))
        .expect("admit the command");
    ledger
        .record_contained_command_release_outcome(
            &intent.sprint_id,
            &intent.effect_id,
            &ContainedCommandReleaseDisposition::Refused {
                reason: "the service handoff was unavailable".to_owned(),
            },
            4_000,
        )
        .expect("the first outcome is written");
    assert!(
        ledger
            .record_contained_command_release_outcome(
                &intent.sprint_id,
                &intent.effect_id,
                &ContainedCommandReleaseDisposition::Released {
                    terminal_json: b"{\"Exit\":9}".to_vec(),
                },
                5_000,
            )
            .is_err(),
        "a second outcome must not replace the first"
    );
}
