//! Fixed-policy streaming rejection for secret-shaped command output.
//!
//! The detector is deliberately byte-oriented and dependency-free. Its
//! markers are public policy material, never secret configuration. A stream
//! retains at most `longest marker - 1` undecided bytes, so a marker split at
//! any read boundary is rejected before any byte belonging to that marker can
//! reach a raw-output writer or retained response accumulator.

use grok_build_core::SensitiveOutputDetectionPolicyReferenceV1;
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

#[cfg(target_os = "linux")]
use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};

pub use grok_build_core::SensitiveOutputCoreDumpSuppressionV1;

/// Irreversibly disables core dumps for this runner and proves exact readback.
pub(crate) fn enforce_core_dump_suppression_v1()
-> Result<SensitiveOutputCoreDumpSuppressionV1, SensitiveOutputError> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| SensitiveOutputError::CoreDumpSuppressionFailed)?;
    #[cfg(target_os = "linux")]
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|_| SensitiveOutputError::CoreDumpSuppressionFailed)?;
    read_core_dump_suppression_v1()
}

/// Reads the live process profile and rejects any weakening after admission.
pub(crate) fn read_core_dump_suppression_v1()
-> Result<SensitiveOutputCoreDumpSuppressionV1, SensitiveOutputError> {
    let limit = getrlimit(Resource::Core);
    let core_limit_current = limit
        .current
        .ok_or(SensitiveOutputError::CoreDumpSuppressionFailed)?;
    let core_limit_maximum = limit
        .maximum
        .ok_or(SensitiveOutputError::CoreDumpSuppressionFailed)?;
    #[cfg(target_os = "linux")]
    let linux_dumpable_disabled = Some(
        dumpable_behavior().map_err(|_| SensitiveOutputError::CoreDumpSuppressionFailed)?
            == DumpableBehavior::NotDumpable,
    );
    #[cfg(not(target_os = "linux"))]
    let linux_dumpable_disabled: Option<bool> = None;
    if core_limit_current != 0 || core_limit_maximum != 0 {
        return Err(SensitiveOutputError::CoreDumpSuppressionFailed);
    }
    #[cfg(target_os = "linux")]
    let profile = {
        if linux_dumpable_disabled != Some(true) {
            return Err(SensitiveOutputError::CoreDumpSuppressionFailed);
        }
        SensitiveOutputCoreDumpSuppressionV1::linux()
    };
    #[cfg(target_os = "macos")]
    let profile = {
        if linux_dumpable_disabled.is_some() {
            return Err(SensitiveOutputError::CoreDumpSuppressionFailed);
        }
        SensitiveOutputCoreDumpSuppressionV1::macos()
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(SensitiveOutputError::CoreDumpSuppressionFailed);
    profile
        .validate()
        .map_err(|_| SensitiveOutputError::CoreDumpSuppressionFailed)?;
    Ok(profile)
}

/// Canonically ordered public marker set authenticated by the v1 policy.
///
/// Short provider prefixes such as `sk-` are intentionally absent: without a
/// token-boundary grammar they collide with ordinary prose such as `task-`.
pub(crate) const SENSITIVE_OUTPUT_MARKERS_V1: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "XAI_API_KEY=",
    "OPENAI_API_KEY=",
    "ANTHROPIC_API_KEY=",
    "AWS_SECRET_ACCESS_KEY=",
    "gb-secret-canary-",
];

/// Rejects a substituted or semantically stale detector reference.
pub(crate) fn validate_matcher_policy_v1(
    reference: &SensitiveOutputDetectionPolicyReferenceV1,
) -> Result<(), SensitiveOutputError> {
    reference
        .validate()
        .map_err(|_| SensitiveOutputError::PolicyMismatch)?;
    if SENSITIVE_OUTPUT_MARKERS_V1
        != SensitiveOutputDetectionPolicyReferenceV1::public_literal_markers_v1()
    {
        return Err(SensitiveOutputError::PolicyMismatch);
    }
    Ok(())
}

/// Secret-free result of screening one output chunk.
pub(crate) enum ScreenedSensitiveOutputChunkV1<'a> {
    /// Bytes proven unable to participate in any future marker match.
    CleanPrefix(&'a [u8]),
    /// A marker was found; no byte from the matching candidate was released.
    SensitiveOutputRejected,
    /// A caller crossed the scanner's preallocated chunk ABI.
    ChunkTooLarge,
    /// EOF or rejection already consumed this scanner.
    Closed,
}

/// Closed detector/quarantine failure set. No variant carries output data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SensitiveOutputError {
    /// The admitted policy does not authenticate this exact matcher grammar.
    PolicyMismatch,
    /// Allocation for bounded private in-process quarantine failed.
    PreallocationFailed,
    /// Runner crash-artifact suppression could not be installed and read back.
    CoreDumpSuppressionFailed,
}

/// One stream's byte-oriented marker matcher.
pub(crate) struct SensitiveOutputStreamScannerV1 {
    undecided: Vec<u8>,
    undecided_length: usize,
    scratch: Vec<u8>,
    maximum_chunk_bytes: usize,
    state: ScannerState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ScannerState {
    Active,
    Rejected,
    Finished,
}

impl SensitiveOutputStreamScannerV1 {
    pub(crate) fn try_new(
        policy: &SensitiveOutputDetectionPolicyReferenceV1,
        maximum_chunk_bytes: usize,
    ) -> Result<Self, SensitiveOutputError> {
        validate_matcher_policy_v1(policy)?;
        let suffix_capacity = maximum_marker_length().saturating_sub(1);
        let mut undecided = Vec::new();
        undecided
            .try_reserve_exact(suffix_capacity)
            .map_err(|_| SensitiveOutputError::PreallocationFailed)?;
        undecided.resize(suffix_capacity, 0);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(suffix_capacity.saturating_add(maximum_chunk_bytes))
            .map_err(|_| SensitiveOutputError::PreallocationFailed)?;
        scratch.resize(suffix_capacity.saturating_add(maximum_chunk_bytes), 0);
        Ok(Self {
            undecided,
            undecided_length: 0,
            scratch,
            maximum_chunk_bytes,
            state: ScannerState::Active,
        })
    }

    /// Screens a chunk and returns only the prefix that cannot begin a marker.
    pub(crate) fn screen(&mut self, chunk: &[u8]) -> ScreenedSensitiveOutputChunkV1<'_> {
        match self.state {
            ScannerState::Rejected => {
                return ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected;
            }
            ScannerState::Finished => return ScreenedSensitiveOutputChunkV1::Closed,
            ScannerState::Active => {}
        }
        if chunk.len() > self.maximum_chunk_bytes {
            return ScreenedSensitiveOutputChunkV1::ChunkTooLarge;
        }
        self.scratch.fill(0);
        self.scratch[..self.undecided_length]
            .copy_from_slice(&self.undecided[..self.undecided_length]);
        let candidate_length = self.undecided_length.saturating_add(chunk.len());
        self.scratch[self.undecided_length..candidate_length].copy_from_slice(chunk);
        if contains_marker(&self.scratch[..candidate_length]) {
            wipe(&mut self.scratch);
            wipe(&mut self.undecided);
            self.undecided_length = 0;
            self.state = ScannerState::Rejected;
            return ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected;
        }

        let held = maximum_marker_length()
            .saturating_sub(1)
            .min(candidate_length);
        let released_length = candidate_length.saturating_sub(held);
        wipe(&mut self.undecided);
        self.undecided[..held].copy_from_slice(&self.scratch[released_length..candidate_length]);
        self.undecided_length = held;
        ScreenedSensitiveOutputChunkV1::CleanPrefix(&self.scratch[..released_length])
    }

    pub(crate) fn finish(&mut self) -> Option<&[u8]> {
        if self.state != ScannerState::Active {
            return None;
        }
        self.state = ScannerState::Finished;
        Some(&self.undecided[..self.undecided_length])
    }
}

impl Drop for SensitiveOutputStreamScannerV1 {
    fn drop(&mut self) {
        wipe(&mut self.undecided);
        wipe(&mut self.scratch);
    }
}

fn maximum_marker_length() -> usize {
    SENSITIVE_OUTPUT_MARKERS_V1
        .iter()
        .map(|marker| marker.len())
        .max()
        .expect("fixed policy has at least one marker")
}

fn contains_marker(candidate: &[u8]) -> bool {
    SENSITIVE_OUTPUT_MARKERS_V1.iter().any(|marker| {
        let marker = marker.as_bytes();
        candidate
            .windows(marker.len())
            .any(|window| window == marker)
    })
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORE_DUMP_CHILD_ENV: &str = "GROK_BUILD_TEST_CORE_DUMP_SUPPRESSION_CHILD";

    fn policy() -> SensitiveOutputDetectionPolicyReferenceV1 {
        SensitiveOutputDetectionPolicyReferenceV1::core_v1()
    }

    #[test]
    fn core_dump_zero_hard_limit_is_irreversible_and_profile_reads_back_in_subprocess() {
        if std::env::var_os(CORE_DUMP_CHILD_ENV).is_some() {
            let installed = enforce_core_dump_suppression_v1()
                .expect("child installs exact core-dump suppression");
            assert_eq!(
                read_core_dump_suppression_v1().expect("child reads suppression back"),
                installed
            );
            assert!(
                setrlimit(
                    Resource::Core,
                    Rlimit {
                        current: Some(1),
                        maximum: Some(1),
                    },
                )
                .is_err(),
                "a process cannot raise its hard core-file limit after setting it to zero"
            );
            assert_eq!(
                read_core_dump_suppression_v1()
                    .expect("failed weakening leaves exact suppression readable"),
                installed
            );
            return;
        }

        let executable = std::env::current_exe().expect("resolve current test executable");
        let status = std::process::Command::new(executable)
            .arg("--exact")
            .arg(
                "sensitive_output::tests::core_dump_zero_hard_limit_is_irreversible_and_profile_reads_back_in_subprocess",
            )
            .env(CORE_DUMP_CHILD_ENV, "1")
            .status()
            .expect("launch isolated core-dump suppression child");
        assert!(status.success());
    }

    #[test]
    fn every_marker_is_rejected_at_every_split_point() {
        for marker in SENSITIVE_OUTPUT_MARKERS_V1 {
            let marker = marker.as_bytes();
            for split in 0..=marker.len() {
                let mut scanner = SensitiveOutputStreamScannerV1::try_new(&policy(), 4096)
                    .expect("fixed policy admitted");
                let mut released = Vec::new();
                let mut rejected = false;
                for chunk in [&marker[..split], &marker[split..]] {
                    if rejected {
                        continue;
                    }
                    match scanner.screen(chunk) {
                        ScreenedSensitiveOutputChunkV1::CleanPrefix(bytes) => {
                            released.extend_from_slice(bytes);
                        }
                        ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => {
                            rejected = true;
                        }
                        ScreenedSensitiveOutputChunkV1::ChunkTooLarge
                        | ScreenedSensitiveOutputChunkV1::Closed => {
                            panic!("bounded active scanner returned a non-policy terminal")
                        }
                    }
                }
                assert!(
                    rejected,
                    "marker={:?} split={split}",
                    String::from_utf8_lossy(marker)
                );
                assert!(
                    !released
                        .windows(marker.len())
                        .any(|window| window == marker)
                );
                assert!(scanner.finish().is_none());
            }
        }
    }

    #[test]
    fn invalid_utf8_and_overlapping_prefixes_remain_binary_safe() {
        let mut scanner = SensitiveOutputStreamScannerV1::try_new(&policy(), 4096)
            .expect("fixed policy admitted");
        assert!(matches!(
            scanner.screen(b"\xff\xfeordinary-----BEGIN OPEN"),
            ScreenedSensitiveOutputChunkV1::CleanPrefix(_)
        ));
        assert!(matches!(
            scanner.screen(b"SSH PRIVATE KEY-----\x80"),
            ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected
        ));
    }

    #[test]
    fn clean_overlap_round_trips_with_only_bounded_undecided_suffix() {
        let bytes = b"-----BEGIN OPENSHO ordinary binary \xff\0 output";
        let mut scanner =
            SensitiveOutputStreamScannerV1::try_new(&policy(), 1).expect("fixed policy admitted");
        let mut released = Vec::new();
        for byte in bytes {
            match scanner.screen(std::slice::from_ref(byte)) {
                ScreenedSensitiveOutputChunkV1::CleanPrefix(prefix) => {
                    released.extend_from_slice(prefix);
                }
                ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => {
                    panic!("clean overlap fixture was rejected")
                }
                ScreenedSensitiveOutputChunkV1::ChunkTooLarge
                | ScreenedSensitiveOutputChunkV1::Closed => {
                    panic!("one-byte active scanner returned a non-policy terminal")
                }
            }
        }
        released.extend_from_slice(scanner.finish().expect("clean stream finishes"));
        assert_eq!(released, bytes);
    }

    #[test]
    fn semantic_policy_or_local_grammar_substitution_is_rejected() {
        let mut stale = policy();
        stale.policy_version = stale.policy_version.saturating_add(1);
        assert!(matches!(
            SensitiveOutputStreamScannerV1::try_new(&stale, 4096),
            Err(SensitiveOutputError::PolicyMismatch)
        ));
        let mut changed = SENSITIVE_OUTPUT_MARKERS_V1.to_vec();
        changed.swap(0, 1);
        assert_ne!(
            changed,
            SensitiveOutputDetectionPolicyReferenceV1::public_literal_markers_v1()
        );
    }

    #[test]
    fn spy_raw_and_retained_sinks_never_receive_marker_bytes() {
        let marker = b"gb-secret-canary-";
        let mut scanner = SensitiveOutputStreamScannerV1::try_new(&policy(), 4096)
            .expect("fixed policy admitted");
        let mut raw_spy = Vec::new();
        let mut retained_spy = Vec::new();
        for chunk in [b"safe-prefix:".as_slice(), &marker[..7], &marker[7..]] {
            match scanner.screen(chunk) {
                ScreenedSensitiveOutputChunkV1::CleanPrefix(prefix) => {
                    raw_spy.extend_from_slice(prefix);
                    retained_spy.extend_from_slice(prefix);
                }
                ScreenedSensitiveOutputChunkV1::SensitiveOutputRejected => break,
                ScreenedSensitiveOutputChunkV1::ChunkTooLarge
                | ScreenedSensitiveOutputChunkV1::Closed => {
                    panic!("bounded spy scanner returned a non-policy terminal")
                }
            }
        }
        assert_eq!(raw_spy, retained_spy);
        assert!(!raw_spy.windows(marker.len()).any(|window| window == marker));
    }

    #[test]
    fn eof_is_one_shot_and_chunk_bound_is_not_a_policy_match() {
        let mut scanner =
            SensitiveOutputStreamScannerV1::try_new(&policy(), 4).expect("fixed policy admitted");
        assert!(matches!(
            scanner.screen(b"12345"),
            ScreenedSensitiveOutputChunkV1::ChunkTooLarge
        ));
        assert!(matches!(
            scanner.screen(b"ok"),
            ScreenedSensitiveOutputChunkV1::CleanPrefix(_)
        ));
        assert!(scanner.finish().is_some());
        assert!(scanner.finish().is_none());
        assert!(matches!(
            scanner.screen(b"x"),
            ScreenedSensitiveOutputChunkV1::Closed
        ));
    }
}
