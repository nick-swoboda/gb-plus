use super::*;

fn identity() -> PlusLiveIdentity {
    PlusLiveIdentity::from_configured_key("fixture-secret-key").expect("non-empty fixture identity")
}

#[test]
fn official_tts_request_is_exact_and_debug_redacts_text_and_key() {
    let request = encode_plus_live_tts_request("Read this exact reply.", &identity())
        .expect("encode TTS request");
    assert_eq!(request.endpoint, PLUS_TTS_ENDPOINT);
    assert_eq!(request.host, PLUS_LIVE_HOST);
    assert_eq!(request.path, PLUS_TTS_PATH);
    let body: Value = serde_json::from_str(&request.body).expect("TTS JSON");
    assert_eq!(
        body.get("text").and_then(Value::as_str),
        Some("Read this exact reply.")
    );
    assert_eq!(body.get("voice_id").and_then(Value::as_str), Some("eve"));
    assert_eq!(body.get("language").and_then(Value::as_str), Some("auto"));
    assert_eq!(
        body.pointer("/output_format/codec").and_then(Value::as_str),
        Some("mp3")
    );
    request.with_transport_parts(|canonical_body, authorization| {
        assert_eq!(canonical_body, request.body);
        assert_eq!(authorization, b"fixture-secret-key");
    });
    let debug = format!("{request:?}");
    assert!(!debug.contains("fixture-secret-key"));
    assert!(!debug.contains("Read this exact reply."));
}

#[test]
fn official_tts_text_limit_is_fail_closed() {
    let too_long = "x".repeat(TTS_MAX_TEXT_CHARS + 1);
    let error = encode_plus_live_tts_request(&too_long, &identity())
        .expect_err("provider limit must be enforced");
    assert!(error.to_string().contains("15,000-character"));
    assert!(encode_plus_live_tts_request("  ", &identity()).is_err());
}

#[test]
fn chunked_mp3_response_is_bounded_and_decoded_exactly() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nID3\r\n4\r\nDATA\r\n0\r\n\r\n";
    let audio = parse_tts_http(raw).expect("bounded MP3 response");
    assert_eq!(audio.content_type, "audio/mpeg");
    assert_eq!(audio.bytes, b"ID3DATA");
}

#[test]
fn tts_refuses_redirect_non_audio_empty_and_truncated_bodies() {
    let redirect = b"HTTP/1.1 302 Found\r\nContent-Type: audio/mpeg\r\nContent-Length: 1\r\n\r\nx";
    assert!(parse_tts_http(redirect).is_err());
    let json = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    assert!(parse_tts_http(json).is_err());
    let empty = b"HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nContent-Length: 0\r\n\r\n";
    assert!(parse_tts_http(empty).is_err());
    let truncated =
        b"HTTP/1.1 200 OK\r\nContent-Type: audio/mpeg\r\nContent-Length: 10\r\n\r\nshort";
    assert!(parse_tts_http(truncated).is_err());
}
