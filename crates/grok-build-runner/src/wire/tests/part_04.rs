// Restart validation for wire protocol v15, driven by the real frozen v14
// frame. This is a fragment included from `wire/tests/mod.rs`.

/// The frozen v14 frame, exactly as `encode_request_frame_v14` emitted it
/// before v15 existed.
fn frozen_v14_frame() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("wire-protocol")
        .canonicalize()
        .expect("canonicalize the frozen wire fixture directory")
        .join("request-envelope-protocol-v14.frame");
    let bytes = std::fs::read(&path).expect("read the frozen v14 request frame");
    assert_eq!(
        bytes.len(),
        2_689,
        "the frozen v14 frame must be the exact captured artefact"
    );
    bytes
}

/// The frozen frame is still exactly what v14 accepts, and round-trips.
///
/// "v15 refuses it" means nothing until "v14 accepts it" is established, or the
/// refusal would pass equally well against corrupt bytes.
#[test]
fn the_frozen_v14_frame_is_still_exactly_what_v14_accepts() {
    let frame = frozen_v14_frame();
    let envelope = decode_request_frame_v14(&frame).expect("v14 must still decode its own frame");
    assert_eq!(envelope.protocol_version, RUNNER_WIRE_PROTOCOL_VERSION_V14);
    assert!(
        envelope.contained_command_release.is_some(),
        "the frozen frame carries a command-release admission"
    );
    assert_eq!(
        encode_request_frame_v14(&envelope).expect("re-encode the frozen envelope"),
        frame,
        "the frozen frame must round-trip byte-for-byte"
    );
}

/// A real v14 frame is refused by the v15 decoder, naming **both** versions.
#[test]
fn a_frozen_v14_frame_is_refused_by_v15_naming_both_versions() {
    let frame = frozen_v14_frame();
    let error = decode_request_frame_v15(&frame).expect_err("v15 must refuse a v14 frame");
    assert!(
        matches!(
            error,
            WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V15,
                actual: RUNNER_WIRE_PROTOCOL_VERSION_V14,
            }
        ),
        "the refusal must carry both versions structurally: {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("15") && message.contains("14"),
        "the refusal message must name both versions: {message}"
    );
}

/// And the reverse: a v15 frame is refused by v14, naming both versions.
#[test]
fn a_v15_frame_is_refused_by_the_v14_decoder() {
    let encoded = v15_frame_with_preparation(None);
    let error = decode_request_frame_v14(&encoded).expect_err("v14 must refuse a v15 frame");
    assert!(
        matches!(
            error,
            WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V14,
                actual: RUNNER_WIRE_PROTOCOL_VERSION_V15,
            }
        ),
        "the v14 refusal must name both versions: {error}"
    );
}

/// Builds a valid v15 frame from the frozen v14 one, optionally carrying a
/// launch preparation.
fn v15_frame_with_preparation(preparation: Option<WireRunnerLaunchPreparationV1>) -> Vec<u8> {
    let mut envelope = v15_envelope_with_preparation(preparation);
    envelope
        .bind_transport_commitment_digest()
        .expect("bind the v15 commitment");
    encode_request_frame_v15(&envelope).expect("encode a v15 frame")
}

fn v15_envelope_with_preparation(
    preparation: Option<WireRunnerLaunchPreparationV1>,
) -> RunnerRequestEnvelopeV15 {
    let frame = frozen_v14_frame();
    let v14 = decode_request_frame_v14(&frame).expect("decode the frozen v14 envelope");
    RunnerRequestEnvelopeV15 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V15,
        session_id: v14.session_id.clone(),
        runner_nonce: v14.runner_nonce.clone(),
        sequence: v14.sequence,
        request_id: v14.request_id.clone(),
        effect: v14.effect.clone(),
        request: v14.request.clone(),
        contained_command_release: v14.contained_command_release.clone(),
        runner_launch_preparation: preparation,
    }
}

fn sample_preparation(launch_id: &str, sprint_id: &str) -> WireRunnerLaunchPreparationV1 {
    let binding_canonical_bytes = b"canonical-platform-launch-binding-bytes".to_vec();
    WireRunnerLaunchPreparationV1 {
        attempt: RunnerLaunchPreparationAttempt {
            contract_version: CONTRACT_VERSION,
            attempt_id: "attempt-launch-1".to_owned(),
            sprint_id: sprint_id.to_owned(),
            launch_id: launch_id.to_owned(),
            cleanup_effect_id: "cleanup-effect-1".to_owned(),
            native_journal_id: "native-journal-1".to_owned(),
            expected_platform_binding_digest: Digest::sha256(&binding_canonical_bytes),
            claimed_at_unix_ms: 5_000,
        },
        binding_digest: Digest::sha256(&binding_canonical_bytes),
        binding_canonical_bytes,
    }
}

/// A preparation whose digest disagrees with its own bytes is refused at the
/// wire boundary, not carried inward to be refused later.
#[test]
fn a_preparation_whose_digest_does_not_match_its_bytes_is_refused() {
    let frame = frozen_v14_frame();
    let v14 = decode_request_frame_v14(&frame).expect("decode the frozen v14 envelope");
    let mut preparation = sample_preparation(&v14.effect.launch_id, &v14.effect.sprint_id);
    preparation.binding_digest = Digest::sha256(b"a digest of something else entirely");
    let mut envelope = v15_envelope_with_preparation(Some(preparation));
    envelope
        .bind_transport_commitment_digest()
        .expect("bind the commitment");
    let error = encode_request_frame_v15(&envelope)
        .expect_err("a preparation whose halves disagree must be refused");
    assert!(
        error.to_string().contains("differs from its own canonical bytes"),
        "the refusal names the mismatch: {error}"
    );
}

/// A preparation naming a different launch than its own envelope is refused.
#[test]
fn a_preparation_for_another_launch_is_refused() {
    let frame = frozen_v14_frame();
    let v14 = decode_request_frame_v14(&frame).expect("decode the frozen v14 envelope");
    let preparation = sample_preparation("launch-that-is-not-this-one", &v14.effect.sprint_id);
    let mut envelope = v15_envelope_with_preparation(Some(preparation));
    envelope
        .bind_transport_commitment_digest()
        .expect("bind the commitment");
    let error = encode_request_frame_v15(&envelope)
        .expect_err("an identity for another launch must be refused");
    assert!(
        error.to_string().contains("different launch"),
        "the refusal names the mismatch: {error}"
    );
}

/// The preparation is inside the transport commitment.
///
/// Swapping it must invalidate the frame; otherwise a runner could be handed
/// another launch's identity without the frame ceasing to verify.
#[test]
fn substituting_the_launch_preparation_invalidates_the_v15_commitment() {
    let frame = frozen_v14_frame();
    let v14 = decode_request_frame_v14(&frame).expect("decode the frozen v14 envelope");
    let mut admitted =
        v15_envelope_with_preparation(Some(sample_preparation(&v14.effect.launch_id, &v14.effect.sprint_id)));
    admitted
        .bind_transport_commitment_digest()
        .expect("bind the admitted commitment");
    let encoded = encode_request_frame_v15(&admitted).expect("encode the admitted frame");
    decode_request_frame_v15(&encoded).expect("the admitted frame is valid");

    // One input varied: different binding bytes, commitment untouched.
    let mut substituted = admitted.clone();
    let replacement = b"a different canonical platform launch binding".to_vec();
    let preparation = substituted
        .runner_launch_preparation
        .as_mut()
        .expect("the admitted frame carries a preparation");
    preparation.binding_digest = Digest::sha256(&replacement);
    preparation.attempt.expected_platform_binding_digest = Digest::sha256(&replacement);
    preparation.binding_canonical_bytes = replacement;

    let payload = serde_json::to_vec(&substituted).expect("encode the tampered payload");
    let mut tampered = u32::try_from(payload.len())
        .expect("payload length fits u32")
        .to_be_bytes()
        .to_vec();
    tampered.extend_from_slice(&payload);
    let error = decode_request_frame_v15(&tampered)
        .expect_err("a substituted preparation must be refused on decode");
    assert!(
        error.to_string().contains("transport commitment"),
        "the decode refusal names the commitment: {error}"
    );
}

/// A v15 frame with no preparation is valid, and that is deliberate: most
/// requests are not the one that establishes identity.
#[test]
fn a_v15_frame_without_a_preparation_is_valid() {
    let encoded = v15_frame_with_preparation(None);
    let decoded = decode_request_frame_v15(&encoded).expect("v15 without a preparation is valid");
    assert!(decoded.runner_launch_preparation.is_none());
    assert!(
        decoded.contained_command_release.is_some(),
        "the command-release admission still travels independently"
    );
}
