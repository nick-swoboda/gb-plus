//! Bounded pending stdin, pumped alongside output and cancellation checks.

use std::collections::VecDeque;
use std::io::{self, Write};

const MAX_PENDING_FRAMES: usize = 128;
const WRITE_CHUNK: usize = 16 * 1024;

pub(crate) struct ServiceInput {
    queue: VecDeque<Vec<u8>>,
    offset: usize,
    pending: usize,
    limit: usize,
    closing: bool,
}

impl ServiceInput {
    pub(crate) fn new(limit: usize) -> Result<Self, String> {
        if !(1..=16 * 1024 * 1024).contains(&limit) {
            return Err("Service pending-input budget is invalid.".into());
        }
        Ok(Self {
            queue: VecDeque::new(),
            offset: 0,
            pending: 0,
            limit,
            closing: false,
        })
    }

    pub(crate) fn enqueue(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        if self.closing
            || bytes.len() > self.limit.saturating_sub(self.pending)
            || self.queue.len() >= MAX_PENDING_FRAMES
        {
            return Err("Service input is closed or its pending-input budget is occupied.".into());
        }
        if !bytes.is_empty() {
            self.pending += bytes.len();
            self.queue.push_back(bytes);
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) {
        self.closing = true;
    }

    pub(crate) fn should_close(&self) -> bool {
        self.closing && self.pending == 0
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.pending != 0
    }

    pub(crate) fn pump(&mut self, writer: &mut impl Write) -> io::Result<usize> {
        let mut written = 0;
        // A constantly writable pipe cannot starve stdout, stderr or Cancel.
        for _ in 0..4 {
            let Some(front) = self.queue.front() else {
                break;
            };
            let end = front.len().min(self.offset + WRITE_CHUNK);
            match writer.write(&front[self.offset..end]) {
                Ok(0) => return Err(io::ErrorKind::BrokenPipe.into()),
                Ok(count) => {
                    self.offset += count;
                    self.pending -= count;
                    written += count;
                    if self.offset == front.len() {
                        self.queue.pop_front();
                        self.offset = 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PausedWriter {
        available: usize,
        bytes: Vec<u8>,
    }

    impl Write for PausedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.available == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = bytes.len().min(self.available);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.available -= count;
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_blocked_partial_write_retains_exact_bytes_and_defers_eof() {
        let mut input = ServiceInput::new(128).unwrap();
        input.enqueue(b"first frame".to_vec()).unwrap();
        input.enqueue(b"second frame".to_vec()).unwrap();
        input.close();
        let mut writer = PausedWriter {
            available: 3,
            bytes: Vec::new(),
        };
        assert_eq!(input.pump(&mut writer).unwrap(), 3);
        assert!(input.has_pending());
        assert!(!input.should_close());
        assert_eq!(input.pump(&mut writer).unwrap(), 0);
        assert!(input.enqueue(b"late input".to_vec()).is_err());
        writer.available = 128;
        input.pump(&mut writer).unwrap();
        assert!(input.should_close());
        assert!(!input.has_pending());
        assert_eq!(writer.bytes, b"first framesecond frame");
    }

    #[test]
    fn a_writable_stream_still_yields_after_four_chunks() {
        let bytes = vec![42; 512 * 1024];
        let mut input = ServiceInput::new(bytes.len()).unwrap();
        input.enqueue(bytes.clone()).unwrap();
        let mut output = Vec::new();
        assert_eq!(input.pump(&mut output).unwrap(), 4 * WRITE_CHUNK);
        assert!(input.has_pending());
        while input.has_pending() {
            assert!(input.pump(&mut output).unwrap() <= 4 * WRITE_CHUNK);
        }
        assert_eq!(bytes, output);
    }

    #[test]
    fn pending_byte_and_frame_limits_refuse_without_dropping_prior_input() {
        let mut input = ServiceInput::new(4).unwrap();
        input.enqueue(b"kept".to_vec()).unwrap();
        assert!(input.enqueue(b"overflow".to_vec()).is_err());
        let mut output = Vec::new();
        input.pump(&mut output).unwrap();
        assert_eq!(output, b"kept");
        let mut input = ServiceInput::new(1024).unwrap();
        for _ in 0..MAX_PENDING_FRAMES {
            input.enqueue(vec![1]).unwrap();
        }
        assert!(input.enqueue(vec![1]).is_err());
        input.pump(&mut Vec::new()).unwrap();
        input.enqueue(vec![2]).unwrap();
    }
}
