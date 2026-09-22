//! Linux-only `no_new_privs` host observation for sealed Gate-1 evidence.
//!
//! The native probe runs fixed code on one dedicated thread. It accepts no
//! command, workspace, environment, provider, or credential input. The parent
//! independently reads the exact thread's procfs status before the set, after
//! the set, and after the forbidden clear attempt. Portable code validates the
//! closed observation and raw procfs grammar on every development host.

use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use super::{domain_digest, require_digest};

// Three captures are embedded in one observation capped at 64 KiB. Restrict
// raw bytes to canonical ASCII so JSON escaping can at most double this bound.
const MAX_PROC_STATUS_BYTES: usize = 8 * 1_024;
const PROC_SUPER_MAGIC_VALUE: u64 = 0x0000_9fa0;
const PROBE_CONTRACT_DOMAIN: &[u8] = b"grok-build/linux-no-new-privs-probe/v1\0";
const PROBE_CONTRACT_BYTES: &[u8] =
    b"dedicated-thread\0prctl-get-0\0proc-get-0\0set-1\0prctl-get-1\0proc-get-1\0clear-0-einval\0prctl-get-1\0proc-get-1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinuxNoNewPrivsObservationFactsV1 {
    pub(super) binding_sha256: String,
    pub(super) fixed_input_sha256: String,
    pub(super) probe_contract_sha256: String,
    pub(super) proc_filesystem_magic: u64,
    pub(super) probe_thread_tid: u32,
    pub(super) pre_prctl_value: u32,
    pub(super) pre_proc_status_raw: String,
    pub(super) set_result_errno: i32,
    pub(super) post_set_prctl_value: u32,
    pub(super) post_set_proc_status_raw: String,
    pub(super) clear_result_errno: i32,
    pub(super) post_clear_prctl_value: u32,
    pub(super) post_clear_proc_status_raw: String,
}

impl LinuxNoNewPrivsObservationFactsV1 {
    pub(super) fn validate_for(
        &self,
        expected_binding_sha256: &str,
        expected_fixed_input_sha256: &str,
    ) -> Result<(), LinuxNoNewPrivsError> {
        require_digest("no-new-privs binding", &self.binding_sha256)
            .map_err(|error| invalid(error.to_string()))?;
        require_digest("no-new-privs fixed input", &self.fixed_input_sha256)
            .map_err(|error| invalid(error.to_string()))?;
        if self.binding_sha256 != expected_binding_sha256
            || self.fixed_input_sha256 != expected_fixed_input_sha256
            || self.probe_contract_sha256 != probe_contract_sha256()
            || self.proc_filesystem_magic != PROC_SUPER_MAGIC_VALUE
            || self.probe_thread_tid == 0
            || self.pre_prctl_value != 0
            || self.set_result_errno != 0
            || self.post_set_prctl_value != 1
            || self.clear_result_errno != 22
            || self.post_clear_prctl_value != 1
        {
            return Err(invalid(
                "no-new-privs binding, syscall sequence, procfs identity, or thread identity crossed",
            ));
        }

        let before = parse_proc_status(self.pre_proc_status_raw.as_bytes())?;
        let after_set = parse_proc_status(self.post_set_proc_status_raw.as_bytes())?;
        let after_clear = parse_proc_status(self.post_clear_proc_status_raw.as_bytes())?;
        if before.pid != self.probe_thread_tid
            || after_set.pid != self.probe_thread_tid
            || after_clear.pid != self.probe_thread_tid
            || before.no_new_privs != 0
            || after_set.no_new_privs != 1
            || after_clear.no_new_privs != 1
        {
            return Err(invalid(
                "no-new-privs raw proc status crossed the exact 0 -> 1 -> 1 thread sequence",
            ));
        }
        Ok(())
    }
}

pub(super) fn probe_contract_sha256() -> String {
    domain_digest(PROBE_CONTRACT_DOMAIN, PROBE_CONTRACT_BYTES)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedProcStatus {
    pid: u32,
    no_new_privs: u32,
}

fn parse_proc_status(bytes: &[u8]) -> Result<ParsedProcStatus, LinuxNoNewPrivsError> {
    if bytes.is_empty()
        || bytes.len() > MAX_PROC_STATUS_BYTES
        || !bytes.ends_with(b"\n")
        || bytes.iter().any(|byte| {
            !matches!(*byte, b'\n' | b'\t' | b' '..=b'~') || matches!(*byte, b'"' | b'\\')
        })
    {
        return Err(invalid(
            "proc status is empty, oversized, unterminated, or contains an ambiguous byte",
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("proc status is not UTF-8"))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| invalid("proc status lacks its exact final newline"))?;
    let mut pid = None;
    let mut no_new_privs = None;
    for line in body.split('\n') {
        if line.is_empty() {
            return Err(invalid("proc status contains an empty or trailing line"));
        }
        if line.starts_with("Pid") {
            if pid.is_some() {
                return Err(invalid("proc status contains a duplicate Pid field"));
            }
            let value = line
                .strip_prefix("Pid:\t")
                .ok_or_else(|| invalid("proc status Pid field is not canonical"))?;
            if value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || (value.len() > 1 && value.starts_with('0'))
            {
                return Err(invalid("proc status Pid value is not canonical"));
            }
            let parsed = value
                .parse::<u32>()
                .map_err(|_| invalid("proc status Pid value is out of range"))?;
            if parsed == 0 || parsed.to_string() != value {
                return Err(invalid("proc status Pid value is zero or ambiguous"));
            }
            pid = Some(parsed);
        } else if line.starts_with("NoNewPrivs") {
            if no_new_privs.is_some() {
                return Err(invalid("proc status contains a duplicate NoNewPrivs field"));
            }
            no_new_privs = Some(match line {
                "NoNewPrivs:\t0" => 0,
                "NoNewPrivs:\t1" => 1,
                _ => {
                    return Err(invalid(
                        "proc status NoNewPrivs field is not exactly canonical 0 or 1",
                    ));
                }
            });
        }
    }
    Ok(ParsedProcStatus {
        pid: pid.ok_or_else(|| invalid("proc status lacks one canonical Pid field"))?,
        no_new_privs: no_new_privs
            .ok_or_else(|| invalid("proc status lacks one canonical NoNewPrivs field"))?,
    })
}

#[cfg(target_os = "linux")]
pub(super) fn collect(
    binding_sha256: &str,
    fixed_input_sha256: &str,
) -> Result<LinuxNoNewPrivsObservationFactsV1, LinuxNoNewPrivsError> {
    native::collect(binding_sha256, fixed_input_sha256)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn collect(
    _binding_sha256: &str,
    _fixed_input_sha256: &str,
) -> Result<LinuxNoNewPrivsObservationFactsV1, LinuxNoNewPrivsError> {
    Err(invalid(
        "genuine no-new-privs observation is available only on Linux",
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LinuxNoNewPrivsError(String);

impl Display for LinuxNoNewPrivsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LinuxNoNewPrivsError {}

fn invalid(message: impl Into<String>) -> LinuxNoNewPrivsError {
    LinuxNoNewPrivsError(message.into())
}

#[cfg(target_os = "linux")]
mod native {
    use std::fs::File;
    use std::io::Read as _;
    use std::path::Path;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use rustix::fs::{Mode, OFlags, ResolveFlags, fstatfs, open, openat2};

    use super::{
        LinuxNoNewPrivsError, LinuxNoNewPrivsObservationFactsV1, MAX_PROC_STATUS_BYTES,
        PROC_SUPER_MAGIC_VALUE, invalid, parse_proc_status, probe_contract_sha256,
    };

    const STAGE_TIMEOUT: Duration = Duration::from_secs(5);

    enum WorkerStage {
        Before { tid: u32, prctl_value: u32 },
        AfterSet { set_errno: i32, prctl_value: u32 },
        AfterClear { clear_errno: i32, prctl_value: u32 },
    }

    #[derive(Clone, Copy)]
    enum WorkerCommand {
        Continue,
        Abort,
        Finish,
    }

    struct ProbeThread {
        commands: Sender<WorkerCommand>,
        stages: Receiver<WorkerStage>,
        join: Option<JoinHandle<Result<(), String>>>,
    }

    impl ProbeThread {
        fn start() -> Self {
            let (stage_sender, stages) = mpsc::channel();
            let (commands, command_receiver) = mpsc::channel();
            let join = std::thread::spawn(move || worker(stage_sender, command_receiver));
            Self {
                commands,
                stages,
                join: Some(join),
            }
        }

        fn stage(&self) -> Result<WorkerStage, LinuxNoNewPrivsError> {
            match self.stages.recv_timeout(STAGE_TIMEOUT) {
                Ok(stage) => Ok(stage),
                Err(RecvTimeoutError::Timeout) => {
                    Err(invalid("no-new-privs probe thread timed out"))
                }
                Err(RecvTimeoutError::Disconnected) => Err(invalid(
                    "no-new-privs probe thread disconnected before an exact stage",
                )),
            }
        }

        fn continue_probe(&self) -> Result<(), LinuxNoNewPrivsError> {
            self.commands
                .send(WorkerCommand::Continue)
                .map_err(|_| invalid("no-new-privs probe thread cannot continue"))
        }

        fn finish(mut self) -> Result<(), LinuxNoNewPrivsError> {
            self.commands
                .send(WorkerCommand::Finish)
                .map_err(|_| invalid("no-new-privs probe thread cannot finish"))?;
            let join = self
                .join
                .take()
                .ok_or_else(|| invalid("no-new-privs probe thread join is absent"))?;
            match join.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(invalid(reason)),
                Err(_) => Err(invalid("no-new-privs probe thread panicked")),
            }
        }
    }

    impl Drop for ProbeThread {
        fn drop(&mut self) {
            let _ = self.commands.send(WorkerCommand::Abort);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    pub(super) fn collect(
        binding_sha256: &str,
        fixed_input_sha256: &str,
    ) -> Result<LinuxNoNewPrivsObservationFactsV1, LinuxNoNewPrivsError> {
        let proc_root = open(
            Path::new("/proc"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot open exact procfs root: {error}")))?;
        let filesystem = fstatfs(&proc_root)
            .map_err(|error| invalid(format!("cannot inspect procfs root: {error}")))?;
        if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(invalid("proc root is not the Linux proc filesystem"));
        }
        let process_id = u32::try_from(rustix::process::getpid().as_raw_pid())
            .map_err(|_| invalid("current Linux process ID is out of range"))?;
        let probe = ProbeThread::start();

        let WorkerStage::Before {
            tid,
            prctl_value: pre_prctl_value,
        } = probe.stage()?
        else {
            return Err(invalid(
                "no-new-privs probe emitted a crossed pre-state stage",
            ));
        };
        let pre_proc_status = read_task_status(&proc_root, process_id, tid)?;
        let parsed_pre = parse_proc_status(&pre_proc_status)?;
        if pre_prctl_value != 0 || parsed_pre.pid != tid || parsed_pre.no_new_privs != 0 {
            return Err(invalid(
                "no-new-privs probe host did not begin at exact prctl+proc value 0",
            ));
        }
        probe.continue_probe()?;

        let WorkerStage::AfterSet {
            set_errno: set_result_errno,
            prctl_value: post_set_prctl_value,
        } = probe.stage()?
        else {
            return Err(invalid("no-new-privs probe emitted a crossed set stage"));
        };
        let post_set_proc_status = read_task_status(&proc_root, process_id, tid)?;
        let parsed_post_set = parse_proc_status(&post_set_proc_status)?;
        if set_result_errno != 0
            || post_set_prctl_value != 1
            || parsed_post_set.pid != tid
            || parsed_post_set.no_new_privs != 1
        {
            return Err(invalid(
                "no-new-privs set did not produce exact prctl+proc value 1",
            ));
        }
        probe.continue_probe()?;

        let WorkerStage::AfterClear {
            clear_errno: clear_result_errno,
            prctl_value: post_clear_prctl_value,
        } = probe.stage()?
        else {
            return Err(invalid("no-new-privs probe emitted a crossed clear stage"));
        };
        let post_clear_proc_status = read_task_status(&proc_root, process_id, tid)?;
        let parsed_post_clear = parse_proc_status(&post_clear_proc_status)?;
        if clear_result_errno != 22
            || post_clear_prctl_value != 1
            || parsed_post_clear.pid != tid
            || parsed_post_clear.no_new_privs != 1
        {
            return Err(invalid(
                "no-new-privs clear was not rejected with EINVAL while prctl+proc remained 1",
            ));
        }
        probe.finish()?;

        let facts = LinuxNoNewPrivsObservationFactsV1 {
            binding_sha256: binding_sha256.into(),
            fixed_input_sha256: fixed_input_sha256.into(),
            probe_contract_sha256: probe_contract_sha256(),
            proc_filesystem_magic: PROC_SUPER_MAGIC_VALUE,
            probe_thread_tid: tid,
            pre_prctl_value,
            pre_proc_status_raw: exact_utf8(pre_proc_status)?,
            set_result_errno,
            post_set_prctl_value,
            post_set_proc_status_raw: exact_utf8(post_set_proc_status)?,
            clear_result_errno,
            post_clear_prctl_value,
            post_clear_proc_status_raw: exact_utf8(post_clear_proc_status)?,
        };
        facts.validate_for(binding_sha256, fixed_input_sha256)?;
        Ok(facts)
    }

    fn read_task_status(
        proc_root: &File,
        process_id: u32,
        thread_id: u32,
    ) -> Result<Vec<u8>, LinuxNoNewPrivsError> {
        let relative = format!("{process_id}/task/{thread_id}/status");
        let opened = openat2(
            proc_root,
            Path::new(&relative),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
        )
        .map(File::from)
        .map_err(|error| invalid(format!("cannot open exact probe task status: {error}")))?;
        let filesystem = fstatfs(&opened)
            .map_err(|error| invalid(format!("cannot inspect probe task status: {error}")))?;
        if filesystem.f_type != rustix::fs::PROC_SUPER_MAGIC {
            return Err(invalid("probe task status escaped procfs"));
        }
        let mut bytes = Vec::new();
        opened
            .take(u64::try_from(MAX_PROC_STATUS_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|error| invalid(format!("cannot read exact probe task status: {error}")))?;
        if bytes.is_empty() || bytes.len() > MAX_PROC_STATUS_BYTES {
            return Err(invalid(
                "probe task status is empty or exceeds its hard bound",
            ));
        }
        Ok(bytes)
    }

    // Both endpoints are taken by value on purpose: the worker owns them, so
    // they drop when it returns and the disconnect is what tells `stage()` the
    // probe thread ended. Borrowing them would keep the channel open past the
    // worker's life and turn a crossed stage into a hang.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "owning the channel endpoints is the mechanism that closes them when the probe thread exits"
    )]
    fn worker(
        stages: Sender<WorkerStage>,
        commands: Receiver<WorkerCommand>,
    ) -> Result<(), String> {
        let tid = u32::try_from(rustix::thread::gettid().as_raw_pid())
            .map_err(|_| "probe thread ID is out of range".to_owned())?;
        let pre = rustix::thread::no_new_privs()
            .map_err(|error| format!("cannot read initial no_new_privs: {error}"))?;
        stages
            .send(WorkerStage::Before {
                tid,
                prctl_value: u32::from(pre),
            })
            .map_err(|_| "cannot send initial no_new_privs stage".to_owned())?;
        if !continue_or_abort(&commands)? {
            return Ok(());
        }

        let set_errno = errno_or_zero(rustix::thread::set_no_new_privs(true));
        let after_set = rustix::thread::no_new_privs()
            .map_err(|error| format!("cannot read set no_new_privs: {error}"))?;
        stages
            .send(WorkerStage::AfterSet {
                set_errno,
                prctl_value: u32::from(after_set),
            })
            .map_err(|_| "cannot send set no_new_privs stage".to_owned())?;
        if !continue_or_abort(&commands)? {
            return Ok(());
        }

        let clear_errno = errno_or_zero(rustix::thread::set_no_new_privs(false));
        let after_clear = rustix::thread::no_new_privs()
            .map_err(|error| format!("cannot read final no_new_privs: {error}"))?;
        stages
            .send(WorkerStage::AfterClear {
                clear_errno,
                prctl_value: u32::from(after_clear),
            })
            .map_err(|_| "cannot send clear no_new_privs stage".to_owned())?;
        match commands.recv() {
            Ok(WorkerCommand::Finish | WorkerCommand::Abort) | Err(_) => Ok(()),
            Ok(WorkerCommand::Continue) => {
                Err("probe thread received a crossed final command".to_owned())
            }
        }
    }

    fn continue_or_abort(commands: &Receiver<WorkerCommand>) -> Result<bool, String> {
        match commands.recv() {
            Ok(WorkerCommand::Continue) => Ok(true),
            Ok(WorkerCommand::Abort) | Err(_) => Ok(false),
            Ok(WorkerCommand::Finish) => Err("probe thread received an early finish".to_owned()),
        }
    }

    fn errno_or_zero(result: rustix::io::Result<()>) -> i32 {
        result.map_or_else(rustix::io::Errno::raw_os_error, |()| 0)
    }

    fn exact_utf8(bytes: Vec<u8>) -> Result<String, LinuxNoNewPrivsError> {
        String::from_utf8(bytes).map_err(|_| invalid("probe task status is not exact UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(tid: u32, no_new_privs: u32) -> String {
        format!(
            "Name:\tgrok-build\nPid:\t{tid}\nPPid:\t1\nNoNewPrivs:\t{no_new_privs}\nSeccomp:\t0\n"
        )
    }

    fn exact_facts() -> LinuxNoNewPrivsObservationFactsV1 {
        LinuxNoNewPrivsObservationFactsV1 {
            binding_sha256: "a".repeat(64),
            fixed_input_sha256: "b".repeat(64),
            probe_contract_sha256: probe_contract_sha256(),
            proc_filesystem_magic: PROC_SUPER_MAGIC_VALUE,
            probe_thread_tid: 42,
            pre_prctl_value: 0,
            pre_proc_status_raw: status(42, 0),
            set_result_errno: 0,
            post_set_prctl_value: 1,
            post_set_proc_status_raw: status(42, 1),
            clear_result_errno: 22,
            post_clear_prctl_value: 1,
            post_clear_proc_status_raw: status(42, 1),
        }
    }

    #[test]
    fn exact_no_new_privs_facts_require_zero_set_einval_and_retained_one() {
        let exact = exact_facts();
        exact
            .validate_for(&"a".repeat(64), &"b".repeat(64))
            .unwrap();

        let mutations: &[fn(&mut LinuxNoNewPrivsObservationFactsV1)] = &[
            |facts| facts.pre_prctl_value = 1,
            |facts| facts.pre_proc_status_raw = status(42, 1),
            |facts| facts.set_result_errno = 1,
            |facts| facts.post_set_prctl_value = 0,
            |facts| facts.post_set_proc_status_raw = status(42, 0),
            |facts| facts.clear_result_errno = 0,
            |facts| facts.clear_result_errno = 1,
            |facts| facts.post_clear_prctl_value = 0,
            |facts| facts.post_clear_proc_status_raw = status(42, 0),
            |facts| facts.probe_thread_tid = 43,
            |facts| facts.proc_filesystem_magic = 0,
            |facts| facts.probe_contract_sha256 = "c".repeat(64),
            |facts| facts.binding_sha256 = "d".repeat(64),
            |facts| facts.fixed_input_sha256 = "e".repeat(64),
        ];
        for mutate in mutations {
            let mut changed = exact.clone();
            mutate(&mut changed);
            assert!(
                changed
                    .validate_for(&"a".repeat(64), &"b".repeat(64))
                    .is_err()
            );
        }
    }

    #[test]
    fn proc_status_parser_rejects_missing_duplicate_malformed_and_trailing_ambiguity() {
        for raw in [
            "Pid:\t42\n",
            "NoNewPrivs:\t0\n",
            "Pid:\t42\nPid:\t42\nNoNewPrivs:\t0\n",
            "Pid:\t42\nNoNewPrivs:\t0\nNoNewPrivs:\t0\n",
            "Pid: 42\nNoNewPrivs:\t0\n",
            "Pid:\t042\nNoNewPrivs:\t0\n",
            "Pid:\t42\nNoNewPrivs: 0\n",
            "Pid:\t42\nNoNewPrivs:\t2\n",
            "Pid:\t42\nNoNewPrivs:\t0",
            "Pid:\t42\nNoNewPrivs:\t0\n\n",
            "Pid:\t42\r\nNoNewPrivs:\t0\n",
            "Pid:\t42\nNoNewPrivsExtra:\t0\n",
        ] {
            assert!(parse_proc_status(raw.as_bytes()).is_err(), "raw={raw:?}");
        }
        let mut nul = status(42, 0).into_bytes();
        nul.insert(0, b'\0');
        assert!(parse_proc_status(&nul).is_err());
        let mut invalid_utf8 = status(42, 0).into_bytes();
        invalid_utf8.insert(0, 0xff);
        assert!(parse_proc_status(&invalid_utf8).is_err());
        let mut oversized = vec![b'x'; MAX_PROC_STATUS_BYTES + 1];
        *oversized.last_mut().unwrap() = b'\n';
        assert!(parse_proc_status(&oversized).is_err());
    }

    #[test]
    fn non_linux_collection_fails_closed() {
        #[cfg(not(target_os = "linux"))]
        assert!(collect(&"a".repeat(64), &"b".repeat(64)).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn genuine_linux_no_new_privs_probe_observes_exact_kernel_and_procfs_sequence() {
        let facts = collect(&"a".repeat(64), &"b".repeat(64)).unwrap();
        facts
            .validate_for(&"a".repeat(64), &"b".repeat(64))
            .unwrap();
    }
}
