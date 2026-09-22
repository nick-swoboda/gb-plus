use std::io::{Cursor, Error, ErrorKind, Read};

use super::*;

fn chunked_http(body: &[u8], fragment_sizes: &[usize]) -> Vec<u8> {
    let mut raw =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n"
            .to_vec();
    let mut offset = 0;
    for requested in fragment_sizes {
        if offset == body.len() {
            break;
        }
        let count = (*requested).min(body.len() - offset);
        raw.extend_from_slice(format!("{count:x}\r\n").as_bytes());
        raw.extend_from_slice(&body[offset..offset + count]);
        raw.extend_from_slice(b"\r\n");
        offset += count;
    }
    if offset < body.len() {
        let count = body.len() - offset;
        raw.extend_from_slice(format!("{count:x}\r\n").as_bytes());
        raw.extend_from_slice(&body[offset..]);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    raw
}

#[test]
fn fragmented_chunked_sse_emits_only_provider_reported_values() {
    let body = concat!(
        "event: response.output_text.delta\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\n\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\n",
        "data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"why\"}\n\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"Hello\"}]}],\"usage\":{\"input_tokens\":11,\"output_tokens\":7,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens_details\":{\"reasoning_tokens\":2}}}}\n\n",
        "data: [DONE]\n\n",
    );
    let raw = chunked_http(body.as_bytes(), &[1, 2, 5, 3, 13, 8, 21]);
    let mut cancelled = || false;
    let mut reader = LiveBodyReader::new(Cursor::new(raw), &mut cancelled).expect("headers");
    assert_eq!(reader.status_code, 200);
    let mut events = Vec::new();
    let mut decoder = ResponsesSseDecoder::default();
    while let Some(piece) = reader.next_piece(&mut cancelled).expect("chunk") {
        decoder
            .push(&piece, &mut |event| events.push(event))
            .expect("SSE");
    }
    let completed = decoder
        .finish(&mut |event| events.push(event))
        .expect("completed response");
    let completed: Value = serde_json::from_slice(&completed).expect("completed JSON");
    assert_eq!(
        completed.get("id").and_then(Value::as_str),
        Some("resp_fixture")
    );
    assert_eq!(
        events,
        vec![
            PlusLiveStreamEvent::AssistantDelta("Hel".into()),
            PlusLiveStreamEvent::AssistantDelta("lo".into()),
            PlusLiveStreamEvent::ThoughtDelta("why".into()),
            PlusLiveStreamEvent::Usage(PlusLiveUsage {
                input_tokens: Some(11),
                output_tokens: Some(7),
                reasoning_tokens: Some(2),
                cached_tokens: Some(3),
            }),
        ]
    );
}

#[test]
fn stream_without_response_completed_is_an_honest_failure() {
    let mut decoder = ResponsesSseDecoder::default();
    decoder
        .push(
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
            &mut |_| {},
        )
        .expect("partial event");
    let error = decoder
        .finish(&mut |_| {})
        .expect_err("completion required");
    assert!(error.to_string().contains("without response.completed"));
}

struct AlwaysTimedOut;

impl Read for AlwaysTimedOut {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::new(ErrorKind::TimedOut, "fixture timeout"))
    }
}

#[test]
fn cancellation_wins_over_repeated_read_timeouts() {
    let mut reader = AlwaysTimedOut;
    let mut buffer = [0_u8; 8];
    let error = read_cancellable(&mut reader, &mut buffer, &mut || true, Instant::now())
        .expect_err("cancelled read");
    assert!(error.to_string().contains("cancelled"));
}

#[test]
fn oversized_headers_are_rejected_even_when_terminator_is_present() {
    let mut raw = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
    raw.resize(LIVE_MAX_HEADER_BYTES + 1, b'a');
    raw.extend_from_slice(b"\r\n\r\n");
    let error = LiveBodyReader::new(Cursor::new(raw), &mut || false)
        .err()
        .expect("header cap");
    assert!(error.to_string().contains("headers exceeded"));
}

#[test]
fn provider_error_payloads_never_enter_a_persistable_native_error() {
    for kind in ["response.failed", "error"] {
        let marker = "TRANSIENT_PROVIDER_ERROR_CANARY_DO_NOT_PERSIST";
        let frame = serde_json::json!({
            "type": kind,
            "error": {"message": marker},
            "response": {"error": {"message": marker}}
        });
        let mut decoder = ResponsesSseDecoder::default();
        let error = decoder
            .push(format!("data: {frame}\n\n").as_bytes(), &mut |_| {})
            .expect_err("Provider failure is still refused");
        assert!(!error.to_string().contains(marker));
        assert!(error.to_string().contains("provider failure"));
    }
}

struct NoReadAfterCompleted(Cursor<Vec<u8>>);
impl Read for NoReadAfterCompleted {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.0.read(buffer)?;
        if count == 0 {
            return Err(Error::other("read attempted after the completed SSE event"));
        }
        Ok(count)
    }
}

#[test]
fn a_completed_sse_response_finishes_without_waiting_for_http_eof() {
    let body = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"completed-keepalive\",\"status\":\"completed\",\"output\":[]}}\n\n";
    let mut raw = chunked_http(body, &[body.len()]);
    assert!(raw.ends_with(b"0\r\n\r\n"));
    raw.truncate(raw.len() - 5);
    let reader =
        LiveBodyReader::new(NoReadAfterCompleted(Cursor::new(raw)), &mut || false).unwrap();
    let result = read_live_sse_response(reader, || false, |_| {})
        .expect("Completed SSE must close locally without an extra HTTP read");
    assert_eq!(
        serde_json::from_slice::<Value>(&result).unwrap()["id"],
        "completed-keepalive"
    );
}

#[test]
fn incomplete_sse_and_done_without_completion_never_admit_a_response() {
    for event in [
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
        "data: [DONE]\n\n",
        "data: {\"type\":\"response.incomplete\"}\n\n",
    ] {
        let mut raw = chunked_http(event.as_bytes(), &[event.len()]);
        raw.truncate(raw.len() - 5);
        let reader =
            LiveBodyReader::new(NoReadAfterCompleted(Cursor::new(raw)), &mut || false).unwrap();
        let error = read_live_sse_response(reader, || false, |_| {}).unwrap_err();
        if event.contains("[DONE]") {
            assert!(error.to_string().contains("without response.completed"));
        } else if event.contains("response.incomplete") {
            assert!(error.to_string().contains("provider failure"));
        }
    }
}

#[test]
fn cancellation_during_terminal_event_delivery_prevents_success() {
    let body = b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"cancel-at-end\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1}}}\n\n";
    let reader = LiveBodyReader::new(Cursor::new(chunked_http(body, &[body.len()])), &mut || {
        false
    })
    .unwrap();
    let cancelled = std::cell::Cell::new(false);
    let result = read_live_sse_response(reader, || cancelled.get(), |_| cancelled.set(true));
    assert!(matches!(result, Err(PlusHostError::LiveCancelled)));
}
