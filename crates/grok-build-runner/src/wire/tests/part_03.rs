// Restart validation for wire protocol v14, driven by the real frozen v12
// frame. This is a fragment included from `wire/tests/mod.rs`.
//
// The point of this file is that it does not build its own v12 frame. A test
// that encodes its input with the same build it then decodes cannot detect a
// version transition that fails only on bytes an *earlier* build emitted, which
// is the only kind of bytes a deployed runner ever receives.

/// The frozen v12 frame, exactly as `encode_request_frame_v12` emitted it.
fn frozen_v12_frame() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("wire-protocol")
        .canonicalize()
        .expect("canonicalize the frozen wire fixture directory")
        .join("request-envelope-protocol-v12.frame");
    let bytes = std::fs::read(&path).expect("read the frozen v12 request frame");
    assert_eq!(
        bytes.len(),
        2_452,
        "the frozen v12 frame must be the exact captured artefact"
    );
    bytes
}

/// The frozen frame is still a *valid v12 frame*, and this build still reads it.
///
/// Without this, a v14 refusal test would pass just as well against corrupt
/// bytes: "v14 refuses it" only means something once "v12 accepts it" is known.
#[test]
fn the_frozen_v12_frame_is_still_exactly_what_v12_accepts() {
    let frame = frozen_v12_frame();
    let envelope = decode_request_frame_v12(&frame).expect("v12 must still decode its own frame");
    assert_eq!(envelope.protocol_version, RUNNER_WIRE_PROTOCOL_VERSION_V12);
    assert_eq!(
        classify_request_frame_version(&frame).expect("classify the frozen frame"),
        RUNNER_WIRE_PROTOCOL_VERSION_V12
    );
    assert_eq!(
        encode_request_frame_v12(&envelope).expect("re-encode the frozen envelope"),
        frame,
        "the frozen frame must round-trip byte-for-byte"
    );
}

/// A real v12 frame is refused by the v14 decoder, **naming both versions**.
#[test]
fn a_frozen_v12_frame_is_refused_by_v14_naming_both_versions() {
    let frame = frozen_v12_frame();
    let error = decode_request_frame_v14(&frame)
        .expect_err("v14 must refuse a v12 frame");
    assert!(
        matches!(
            error,
            WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V14,
                actual: RUNNER_WIRE_PROTOCOL_VERSION_V12,
            }
        ),
        "the refusal must carry both versions structurally: {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("14") && message.contains("12"),
        "the refusal message must name both versions: {message}"
    );
}

/// The version peek is **load-bearing**, and this is the measurement that shows
/// why.
///
/// `serde` treats `Option<T>` as implicitly optional even without
/// `#[serde(default)]`, so a v12 payload does not fail to deserialize as a v14
/// envelope -- it *succeeds*, with `contained_command_release: None`. That is
/// precisely the hazard: a v12 frame would be read as a well-formed v14 request
/// that was simply never admitted for contained release, turning an absent
/// admission into a silently unadmitted command.
///
/// The peek is the only thing standing between those two readings.
#[test]
fn serde_alone_would_silently_read_a_v12_frame_as_an_unadmitted_v14_request() {
    let frame = frozen_v12_frame();
    let silently_accepted: RunnerRequestEnvelopeV14 = serde_json::from_slice(&frame[4..])
        .expect("serde accepts a v12 payload as v14 because Option is implicitly optional");
    assert_eq!(
        silently_accepted.protocol_version, RUNNER_WIRE_PROTOCOL_VERSION_V12,
        "the silently accepted value still carries the v12 version it came from"
    );
    assert!(
        silently_accepted.contained_command_release.is_none(),
        "and its admission is absent rather than refused, which is the hazard"
    );

    // The real decoder refuses it, and names both versions.
    let peeked = decode_request_frame_v14(&frame)
        .expect_err("the real v14 decoder must refuse")
        .to_string();
    assert!(
        peeked.contains("14") && peeked.contains("12"),
        "the peeked refusal names both: {peeked}"
    );
}

/// v14 bytes are refused by the v12 decoder, so the transition is closed in
/// both directions.
#[test]
fn a_v14_frame_is_refused_by_the_v12_decoder() {
    let frame = frozen_v12_frame();
    let v12 = decode_request_frame_v12(&frame).expect("decode the frozen v12 envelope");
    let mut v14 = RunnerRequestEnvelopeV14 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V14,
        session_id: v12.session_id.clone(),
        runner_nonce: v12.runner_nonce.clone(),
        sequence: v12.sequence,
        request_id: v12.request_id.clone(),
        effect: v12.effect.clone(),
        request: v12.request.clone(),
        contained_command_release: None,
    };
    v14.bind_transport_commitment_digest()
        .expect("bind the v14 commitment");
    let encoded = encode_request_frame_v14(&v14).expect("encode a v14 frame");

    let error = decode_request_frame_v12(&encoded)
        .expect_err("v12 must refuse a v14 frame");
    assert!(
        matches!(
            error,
            WireProtocolError::Version {
                expected: RUNNER_WIRE_PROTOCOL_VERSION_V12,
                actual: RUNNER_WIRE_PROTOCOL_VERSION_V14,
            }
        ),
        "the v12 refusal must name both versions too, not an anonymous unknown \
         field: {error}"
    );
    assert_eq!(
        classify_request_frame_version(&encoded).expect("classify the v14 frame"),
        RUNNER_WIRE_PROTOCOL_VERSION_V14
    );
}

/// The release authority is inside the transport commitment.
///
/// Swapping it for another admission must invalidate the frame. If it did not,
/// the runner would check a substituted admission against its journal instead of
/// the one the desktop minted, and the substitution would be invisible.
#[test]
fn substituting_the_release_authority_invalidates_the_v14_commitment() {
    let frame = frozen_v12_frame();
    let v12 = decode_request_frame_v12(&frame).expect("decode the frozen v12 envelope");
    let authority = WireContainedCommandReleaseAuthorityV1 {
        command_effect_id: v12.effect.effect_id.clone(),
        request_digest: v12.effect.request_digest.clone(),
        native_evidence_digest: Digest::sha256(b"desktop-outer-preparation-evidence"),
    };
    let mut admitted = RunnerRequestEnvelopeV14 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V14,
        session_id: v12.session_id.clone(),
        runner_nonce: v12.runner_nonce.clone(),
        sequence: v12.sequence,
        request_id: v12.request_id.clone(),
        effect: v12.effect.clone(),
        request: v12.request.clone(),
        contained_command_release: Some(authority),
    };
    admitted
        .bind_transport_commitment_digest()
        .expect("bind the admitted commitment");
    let encoded = encode_request_frame_v14(&admitted).expect("encode the admitted frame");
    decode_request_frame_v14(&encoded).expect("the admitted frame is valid");

    // One input varied: a different outer evidence digest, commitment untouched.
    let mut substituted = admitted.clone();
    substituted
        .contained_command_release
        .as_mut()
        .expect("the admitted frame carries an authority")
        .native_evidence_digest = Digest::sha256(b"a different desktop's evidence");
    let error = encode_request_frame_v14(&substituted)
        .expect_err("a substituted authority must not encode against the bound commitment");
    assert!(
        error.to_string().contains("transport commitment"),
        "the substitution is caught by the commitment: {error}"
    );

    // And the same substitution is refused on decode, not merely on encode.
    let mut tampered = admitted.clone();
    tampered
        .contained_command_release
        .as_mut()
        .expect("the admitted frame carries an authority")
        .native_evidence_digest = Digest::sha256(b"a different desktop's evidence");
    let payload = serde_json::to_vec(&tampered).expect("encode the tampered payload");
    let mut tampered_frame =
        u32::try_from(payload.len()).expect("payload length fits u32").to_be_bytes().to_vec();
    tampered_frame.extend_from_slice(&payload);
    let error = decode_request_frame_v14(&tampered_frame)
        .expect_err("a tampered authority must be refused on decode");
    assert!(
        error.to_string().contains("transport commitment"),
        "the decode refusal names the commitment: {error}"
    );
}

/// An authority naming a different effect than its own envelope is refused.
#[test]
fn a_release_authority_for_another_effect_is_refused() {
    let frame = frozen_v12_frame();
    let v12 = decode_request_frame_v12(&frame).expect("decode the frozen v12 envelope");
    let mut travelled = RunnerRequestEnvelopeV14 {
        protocol_version: RUNNER_WIRE_PROTOCOL_VERSION_V14,
        session_id: v12.session_id.clone(),
        runner_nonce: v12.runner_nonce.clone(),
        sequence: v12.sequence,
        request_id: v12.request_id.clone(),
        effect: v12.effect.clone(),
        request: v12.request.clone(),
        contained_command_release: Some(WireContainedCommandReleaseAuthorityV1 {
            command_effect_id: "effect-that-is-not-this-one".to_owned(),
            request_digest: v12.effect.request_digest.clone(),
            native_evidence_digest: Digest::sha256(b"desktop-outer-preparation-evidence"),
        }),
    };
    travelled
        .bind_transport_commitment_digest()
        .expect("bind the travelled commitment");
    let error = encode_request_frame_v14(&travelled)
        .expect_err("an admission for another effect must be refused");
    assert!(
        error.to_string().contains("different effect"),
        "the refusal names the mismatch: {error}"
    );
}
