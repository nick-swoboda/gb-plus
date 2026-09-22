//! Process-level evidence for the dedicated runner startup seal.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::io::{FdFlags, fcntl_setfd};

static SPAWN_LOCK: Mutex<()> = Mutex::new(());
static NEXT_SENTINEL: AtomicU64 = AtomicU64::new(1);

struct Sentinel {
    file: File,
    path: std::path::PathBuf,
}

impl Sentinel {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "grok-build-inheritable-descriptor-{}-{}",
            std::process::id(),
            NEXT_SENTINEL.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create inherited-descriptor sentinel");
        Self { file, path }
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn spawn_runner() -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_grok-build-runner"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runner seal probe");
    child
        .stdin
        .take()
        .expect("open runner input")
        .write_all(&0_u32.to_be_bytes())
        .expect("write deliberate invalid frame");
    child
        .wait_with_output()
        .expect("wait for runner seal probe")
}

#[test]
fn exact_stdio_pipe_allowlist_reaches_the_sealed_service() {
    let _guard = SPAWN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let output = spawn_runner();
    assert_eq!(output.status.code(), Some(78));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid runner frame length 0"),
        "unexpected refusal: {stderr}"
    );
    assert!(!stderr.contains("unexpected inherited descriptor set"));
}

#[test]
fn injected_inheritable_descriptor_causes_startup_refusal() {
    let _guard = SPAWN_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sentinel = Sentinel::new();
    fcntl_setfd(&sentinel.file, FdFlags::empty()).expect("make sentinel inheritable");

    let spawn = Command::new(env!("CARGO_BIN_EXE_grok-build-runner"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    // Restore the parent process invariant before interpreting the spawn
    // result. The child received the descriptor state at `exec` time.
    fcntl_setfd(&sentinel.file, FdFlags::CLOEXEC).expect("restore sentinel CLOEXEC");
    let output = spawn
        .expect("spawn runner with injected descriptor")
        .wait_with_output()
        .expect("wait for rejected runner");

    assert_eq!(output.status.code(), Some(78));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected inherited descriptor set"),
        "unexpected refusal: {stderr}"
    );
}
