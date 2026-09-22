//! What a containment refusal can close on evidence, in a fork-free binary.
//!
//! The desktop's adapter tests live in the library binary, which also exercises
//! process launch; a process that has created a child cannot answer the absence
//! question, so those tests state the contract as a biconditional. This binary
//! forks nothing, so it can prove the positive half outright: bytes the runner
//! read from the kernel, reopened by the desktop against its own binding, are
//! sufficient to close the `NoDomainCreatedBeforeEffect` disposition.
//!
//! This is the whole of what route 2 buys. It deliberately does not advance the
//! spine: schema v11's admission trigger still requires the command effect's
//! own observation to be `FailedBeforeEffect` or `CancelledBeforeEffect`, and
//! the desktop still classifies a post-dispatch containment refusal as
//! `Unknown`. What changes is that the refusal is now backed by evidence rather
//! than by trust.

#![cfg(target_os = "linux")]

use grok_build_core::{
    CONTRACT_VERSION, CommandDomainBackend, CommandDomainCleanupDisposition,
    CommandDomainCleanupProof, CommandOutputCaptureStoreHeadV1, Digest,
};
use grok_build_runner::{
    CommandDomainCleanupBackend, CommandDomainCleanupBinding, live_containment_refusal_evidence_v12,
};

const SESSION_ID: &str = "refusal-evidence-session";
const EFFECT_ID: &str = "refusal-evidence-effect";
/// Capture identifiers are exactly 64 lowercase hexadecimal characters.
fn capture_id() -> String {
    Digest::sha256(b"refusal-evidence-capture")
        .as_str()
        .to_owned()
}

fn store_head() -> CommandOutputCaptureStoreHeadV1 {
    CommandOutputCaptureStoreHeadV1 {
        generation: 2,
        record_digest: Digest::sha256(b"refusal-evidence-acquired-head"),
    }
}

fn binding() -> CommandDomainCleanupBinding {
    CommandDomainCleanupBinding::try_new(
        SESSION_ID,
        EFFECT_ID,
        Digest::sha256(b"refusal-evidence-request"),
    )
    .expect("exact refusal binding")
}

#[test]
fn runner_read_absence_bytes_close_the_no_domain_disposition() {
    let binding = binding();
    let refusal = live_containment_refusal_evidence_v12(
        SESSION_ID,
        EFFECT_ID,
        binding.command_request_digest(),
        &capture_id(),
        store_head(),
    )
    .expect("a fork-free Linux process must be able to read its own absence answers");

    let proof = refusal
        .readback(&binding)
        .expect("the desktop reopens the runner's bytes against its own binding");
    assert_eq!(
        proof.disposition(),
        CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect
    );
    assert_eq!(proof.backend(), CommandDomainCleanupBackend::LinuxCgroupV2);
    assert_eq!(proof.surviving_processes(), 0);
    assert_eq!(proof.binding(), &binding);

    let cleanup = CommandDomainCleanupProof {
        contract_version: CONTRACT_VERSION,
        proof_id: "command-capture-no-domain-refusal-evidence".into(),
        sprint_id: "refusal-evidence-sprint".into(),
        launch_id: "refusal-evidence-launch".into(),
        session_id: SESSION_ID.into(),
        effect_id: EFFECT_ID.into(),
        observation_id: None,
        request_digest: binding.command_request_digest().clone(),
        backend: CommandDomainBackend::LinuxCgroupV2,
        disposition: CommandDomainCleanupDisposition::NoDomainCreatedBeforeEffect,
        surviving_processes: 0,
        platform_proof_digest: proof.os_evidence_digest().clone(),
        platform_proof_bytes: proof.os_evidence_bytes().to_vec(),
        cleaned_at_unix_ms: 1,
    };
    cleanup
        .validate()
        .expect("runner-read absence bytes close the disposition");
}

/// A refusal reopened against another effect's binding fails. The evidence is
/// bound to one exact command request, so it cannot be replayed onto another.
#[test]
fn refusal_evidence_cannot_be_replayed_onto_another_effect() {
    let refusal = live_containment_refusal_evidence_v12(
        SESSION_ID,
        EFFECT_ID,
        binding().command_request_digest(),
        &capture_id(),
        store_head(),
    )
    .expect("a fork-free Linux process must be able to read its own absence answers");
    let crossed = CommandDomainCleanupBinding::try_new(
        SESSION_ID,
        "another-refusal-evidence-effect",
        Digest::sha256(b"refusal-evidence-request"),
    )
    .expect("crossed binding");
    assert!(refusal.readback(&crossed).is_err());
}

/// The reaping disposition cannot be obtained from absence evidence. This is
/// the property that makes the new decode arm an extension rather than a
/// loosening: every consumer that required a reaped domain still requires one.
#[test]
fn absence_evidence_cannot_satisfy_a_reaped_domain_consumer() {
    let refusal = live_containment_refusal_evidence_v12(
        SESSION_ID,
        EFFECT_ID,
        binding().command_request_digest(),
        &capture_id(),
        store_head(),
    )
    .expect("a fork-free Linux process must be able to read its own absence answers");
    let proof = refusal.readback(&binding()).expect("reopen absence proof");
    assert!(
        proof
            .require_disposition(CommandDomainCleanupDisposition::ReapedZeroSurvivors)
            .is_err()
    );
}
