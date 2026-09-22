//! Incremental SSE framing with byte limits before JSON deserialization.

use super::{MCP_MAX_FRAME_BYTES, McpHttpEvent};

#[derive(Default)]
pub(super) struct Decoder {
    line: Vec<u8>,
    data: Vec<u8>,
    event: String,
    cursor: Option<String>,
    after_cr: bool,
    fields: usize,
}

impl Decoder {
    pub(super) fn push(
        &mut self,
        chunk: &[u8],
        events: &mut impl FnMut(McpHttpEvent) -> Result<(), String>,
    ) -> Result<(), String> {
        for byte in chunk {
            if self.after_cr {
                self.after_cr = false;
                if *byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' | b'\n' => {
                    self.consume_line(events)?;
                    self.after_cr = *byte == b'\r';
                }
                byte => {
                    if self.line.len().saturating_add(self.data.len()) >= MCP_MAX_FRAME_BYTES {
                        return Err("MCP SSE event exceeded its byte limit.".into());
                    }
                    self.line.push(*byte);
                }
            }
        }
        Ok(())
    }

    fn consume_line(
        &mut self,
        events: &mut impl FnMut(McpHttpEvent) -> Result<(), String>,
    ) -> Result<(), String> {
        let line = std::mem::take(&mut self.line);
        let text = std::str::from_utf8(&line).map_err(|_| "MCP SSE is not UTF-8.")?;
        if text.is_empty() {
            if !self.data.is_empty() {
                self.data.pop(); // The SSE rule removes the final field-joining LF.
                if !self.data.is_empty() {
                    if !self.event.is_empty() && self.event != "message" {
                        return Err("MCP SSE data used an unsupported event type.".into());
                    }
                    events(McpHttpEvent::Message(std::mem::take(&mut self.data)))?;
                }
                self.data.clear();
            }
            // Never advance replay past a message the broker failed to accept.
            if let Some(cursor) = self.cursor.take() {
                events(McpHttpEvent::Cursor(cursor))?;
            }
            self.event.clear();
            self.fields = 0;
            return Ok(());
        }
        self.fields += 1;
        if self.fields > 4096 {
            return Err("MCP SSE event field limit exceeded.".into());
        }
        if text.starts_with(':') {
            return Ok(());
        }
        let (field, value) = text.split_once(':').unwrap_or((text, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                if self
                    .data
                    .len()
                    .saturating_add(value.len())
                    .saturating_add(1)
                    > MCP_MAX_FRAME_BYTES
                {
                    return Err("MCP SSE data exceeded its byte limit.".into());
                }
                self.data.extend_from_slice(value.as_bytes());
                self.data.push(b'\n');
            }
            "event" => {
                if value.len() > 128 {
                    return Err("MCP SSE event type exceeded its bound.".into());
                }
                value.clone_into(&mut self.event);
            }
            "id" if !value.contains('\0') => {
                if value.len() > 256 || value.chars().any(char::is_control) {
                    return Err("MCP SSE cursor exceeded its bound.".into());
                }
                self.cursor = Some(value.to_owned());
            }
            // Retry fields cannot control app backoff or replay an effect.
            _ => {}
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> Result<(), String> {
        if !self.line.is_empty() || !self.data.is_empty() || self.cursor.is_some() {
            return Err("MCP SSE ended in a partial event; pending delivery is uncertain.".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_chunks_crlf_and_unicode_preserve_exact_message_bytes() {
        let source = "id: first\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"result\":{\"text\":\"é\"}}\r\n\r\n".as_bytes();
        for width in [1, 2, 7, 128] {
            let mut decoder = Decoder::default();
            let mut observed = Vec::new();
            for chunk in source.chunks(width) {
                decoder
                    .push(chunk, &mut |event| {
                        observed.push(event);
                        Ok(())
                    })
                    .unwrap();
            }
            decoder.finish().unwrap();
            assert_eq!(observed.len(), 2);
            assert!(matches!(&observed[1], McpHttpEvent::Cursor(value) if value == "first"));
            let McpHttpEvent::Message(bytes) = &observed[0] else {
                panic!("message expected")
            };
            assert_eq!(
                bytes,
                "{\"jsonrpc\":\"2.0\",\n\"result\":{\"text\":\"é\"}}".as_bytes()
            );
        }
    }

    #[test]
    fn priming_cursors_and_comments_do_not_become_json_messages() {
        let mut decoder = Decoder::default();
        let mut observed = Vec::new();
        decoder
            .push(
                b": keepalive\r\rid: initial\rdata:\r\rid:\r\r",
                &mut |event| {
                    observed.push(event);
                    Ok(())
                },
            )
            .unwrap();
        decoder.finish().unwrap();
        assert_eq!(observed.len(), 2);
        assert!(matches!(&observed[0], McpHttpEvent::Cursor(value) if value == "initial"));
        assert!(matches!(&observed[1], McpHttpEvent::Cursor(value) if value.is_empty()));
    }

    #[test]
    fn incomplete_oversized_and_foreign_events_refuse() {
        let mut decoder = Decoder::default();
        decoder
            .push(b"data: {\"partial\":", &mut |_| Ok(()))
            .unwrap();
        assert!(decoder.finish().is_err());
        let mut decoder = Decoder::default();
        assert!(
            decoder
                .push(&vec![b'x'; MCP_MAX_FRAME_BYTES + 1], &mut |_| Ok(()))
                .is_err()
        );
        let mut decoder = Decoder::default();
        assert!(
            decoder
                .push(b"event: execute\ndata: {}\n\n", &mut |_| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn failed_message_acceptance_never_advances_the_replay_cursor() {
        let mut decoder = Decoder::default();
        let mut cursor_seen = false;
        assert!(
            decoder
                .push(b"id: after-effect\ndata: {}\n\n", &mut |event| {
                    match event {
                        McpHttpEvent::Message(_) => Err("journal commit failed".into()),
                        McpHttpEvent::Cursor(_) => {
                            cursor_seen = true;
                            Ok(())
                        }
                    }
                })
                .is_err()
        );
        assert!(!cursor_seen);
    }
}
