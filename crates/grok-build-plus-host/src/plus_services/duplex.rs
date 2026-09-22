//! Cooperative control writes for a peer that may write before it reads.

use std::io;
use std::time::{Duration, Instant};

pub(super) trait ControlIo {
    /// Drain at most one bounded observation; true means progress.
    fn drain_output(&mut self) -> Result<bool, String>;
    fn write_input(&mut self, bytes: &[u8]) -> io::Result<usize>;
}

pub(super) fn write(
    io: &mut impl ControlIo,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut offset = 0;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err("Contained service input delivery is uncertain.".into());
        }
        let mut progress = false;
        for _ in 0..4 {
            if !io.drain_output()? {
                break;
            }
            progress = true;
        }
        let end = bytes.len().min(offset.saturating_add(16 * 1024));
        match io.write_input(&bytes[offset..end]) {
            Ok(0) => return Err("Contained service input closed mid-frame.".into()),
            Ok(count) => {
                offset += count;
                progress = true;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error.to_string()),
        }
        if !progress {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    struct SocketIo {
        stream: UnixStream,
        output: Vec<u8>,
        written: usize,
    }

    impl ControlIo for SocketIo {
        fn drain_output(&mut self) -> Result<bool, String> {
            let mut bytes = [0; 16 * 1024];
            match self.stream.read(&mut bytes) {
                Ok(0) => Err("peer ended".into()),
                Ok(count) => {
                    self.output.extend_from_slice(&bytes[..count]);
                    Ok(true)
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
                Err(error) => Err(error.to_string()),
            }
        }

        fn write_input(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = self.stream.write(bytes)?;
            self.written += count;
            Ok(count)
        }
    }

    #[test]
    fn peer_output_larger_than_socket_capacity_does_not_deadlock_control_input() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        for stream in [&local, &peer] {
            rustix::net::sockopt::set_socket_send_buffer_size(stream, 64 * 1024).unwrap();
            rustix::net::sockopt::set_socket_recv_buffer_size(stream, 64 * 1024).unwrap();
        }
        let capacity = |sender: &UnixStream, receiver: &UnixStream| {
            rustix::net::sockopt::socket_send_buffer_size(sender).unwrap()
                + rustix::net::sockopt::socket_recv_buffer_size(receiver).unwrap()
        };
        assert!(512 * 1024 > capacity(&peer, &local));
        assert!(768 * 1024 > capacity(&local, &peer));
        local.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            peer.write_all(&vec![b'O'; 512 * 1024]).unwrap();
            let mut bytes = vec![0; 768 * 1024];
            peer.read_exact(&mut bytes).unwrap();
            assert!(bytes.iter().all(|byte| *byte == b'I'));
        });
        let mut io = SocketIo {
            stream: local,
            output: Vec::new(),
            written: 0,
        };
        let result = write(&mut io, &vec![b'I'; 768 * 1024], Duration::from_secs(3));
        // Always close before joining on an error, so the fixture owns cleanup.
        if result.is_err() {
            io.stream.shutdown(std::net::Shutdown::Both).unwrap();
        }
        let worker_result = worker.join();
        result.unwrap();
        worker_result.unwrap();
        while io.output.len() < 512 * 1024 {
            assert!(io.drain_output().unwrap());
        }
        assert!(io.output.iter().all(|byte| *byte == b'O'));
        assert_eq!(io.written, 768 * 1024);
    }

    #[test]
    fn a_peer_that_never_reads_reports_uncertain_partial_delivery_on_deadline() {
        let (local, _peer) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        let mut io = SocketIo {
            stream: local,
            output: Vec::new(),
            written: 0,
        };
        let started = Instant::now();
        let error = write(
            &mut io,
            &vec![42; 4 * 1024 * 1024],
            Duration::from_millis(150),
        )
        .unwrap_err();
        assert!(error.contains("uncertain"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(io.written > 0 && io.written < 4 * 1024 * 1024);
    }
}
