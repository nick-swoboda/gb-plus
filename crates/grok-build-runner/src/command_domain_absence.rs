//! Kernel-read evidence that no command domain exists for one refused effect.
//!
//! A containment refusal is a claim about something that did *not* happen, and
//! the repository's law is that such a claim is worth only what was read back.
//! This module therefore never records a decision the runner made; it records
//! what the kernel answered when the runner asked, at the instant of refusal,
//! three independent questions:
//!
//! 1. does the cgroup-v2 subtree this runner can see contain any command-domain
//!    leaf (`gb-` followed by exactly 64 lowercase hex characters)?
//! 2. does this process have any live child, as the kernel's own
//!    `/proc/self/task/<tid>/children` lists it?
//! 3. has this process ever reaped a child, as the kernel's own child-fault and
//!    child-CPU accounting in `/proc/self/stat` records it?
//!
//! Every field below is the answer to one of those reads. None of them is a
//! constant the runner also wrote, and none is derived from a decision taken in
//! this process: an absence observation that could be produced without asking
//! the kernel would prove nothing, which is exactly the failure mode the
//! `kill_value` write-constant finding named.
//!
//! The observation is deliberately fail-closed and *optional*. If any read is
//! unavailable, any bound is reached, or any answer is not the absence answer,
//! no observation is produced at all and the refusal keeps its historical
//! evidence-free shape. Producing a weaker record instead would reintroduce
//! precisely the trust this module exists to remove.

use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::linux_containment::{CGROUP2_SUPER_MAGIC, is_domain_leaf_name};

/// Canonical schema version for one Linux command-domain absence observation.
pub const LINUX_ABSENCE_OBSERVATION_VERSION: u32 = 1;

/// Maximum bytes accepted from `/proc/self/cgroup`.
const MAX_SELF_CGROUP_BYTES: usize = 4_096;
/// Maximum bytes accepted from one `/proc/self/task/<tid>/children` read.
const MAX_TASK_CHILDREN_BYTES: usize = 4_096;
/// Maximum runner threads whose child lists are read.
const MAX_TASK_CHILDREN_READS: usize = 512;
/// Maximum cgroup directories visited by one bounded subtree scan.
const MAX_SCANNED_DIRECTORIES: u32 = 4_096;
/// Maximum immediate mount-root entry names retained for the reader.
const MAX_SAMPLED_ROOT_ENTRIES: usize = 256;
/// Maximum bytes accepted for one retained cgroup directory entry name.
const MAX_ENTRY_NAME_BYTES: usize = 128;
/// Maximum identifier bytes accepted in the observation's request binding.
const MAX_BINDING_TEXT_BYTES: usize = 256;

/// Device/inode identity of the scanned cgroup-v2 mount root.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxScannedRootIdentity {
    /// `st_dev` of the scanned mount root.
    pub device: u64,
    /// `st_ino` of the scanned mount root.
    pub inode: u64,
}

/// One kernel-maintained live-child list read from a single runner thread.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxTaskChildrenRead {
    /// Thread whose `children` file was read.
    pub thread_id: u32,
    /// Exact retained bytes the kernel returned for that thread.
    pub bytes: Vec<u8>,
}

/// Kernel-maintained accounting that only a reaped child can make nonzero.
///
/// These are `/proc/self/stat` fields 11, 13, 16, and 17. The kernel adds to
/// them when a child is waited for; nothing in user space can clear them. Zero
/// therefore distinguishes "no child was launched" from "a child was launched
/// and is no longer listed", which a live-children read alone cannot do.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReapedChildAccounting {
    /// `cminflt`: minor faults accumulated by reaped children.
    pub minor_faults: u64,
    /// `cmajflt`: major faults accumulated by reaped children.
    pub major_faults: u64,
    /// `cutime`: user-mode ticks accumulated by reaped children.
    pub user_time_ticks: i64,
    /// `cstime`: kernel-mode ticks accumulated by reaped children.
    pub system_time_ticks: i64,
}

/// One canonical, secret-free observation that no Linux command domain exists.
///
/// The record is bound to the exact refused command effect so it cannot be
/// replayed against another request, and it carries the raw kernel bytes it was
/// derived from so a later reader can re-derive the same conclusion instead of
/// trusting this process's summary of it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCommandDomainAbsenceObservationV1 {
    /// Canonical schema version.
    pub schema_version: u32,
    /// Runner session that refused the command.
    pub runner_session_id: String,
    /// Exact command effect that was refused.
    pub effect_id: String,
    /// Exact canonical command-request digest, 64 lowercase hex characters.
    pub request_digest: String,
    /// Complete bytes of `/proc/self/cgroup` at the instant of refusal.
    pub self_cgroup_bytes: Vec<u8>,
    /// Superblock magic read back from the scanned mount by `statfs`.
    pub scanned_filesystem_magic: u64,
    /// Device/inode identity of the scanned mount root.
    pub scanned_root_identity: LinuxScannedRootIdentity,
    /// Number of directories the bounded subtree scan actually visited.
    pub scanned_directory_count: u32,
    /// Sorted immediate entry names of the scanned mount root.
    pub sampled_root_entries: Vec<String>,
    /// Every scanned directory name matching the command-domain leaf grammar.
    pub domain_leaf_candidates: Vec<String>,
    /// Kernel live-child lists, one per runner thread.
    pub task_children_reads: Vec<LinuxTaskChildrenRead>,
    /// Kernel accounting for children this process has already reaped.
    pub reaped_child_accounting: LinuxReapedChildAccounting,
}

impl LinuxCommandDomainAbsenceObservationV1 {
    /// Re-derives the absence conclusion from the retained bytes.
    ///
    /// This is the whole contract of the record: it holds only when every
    /// retained kernel answer is the absence answer. A caller cannot reach a
    /// `NoDomainCreatedBeforeEffect` disposition without it.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is malformed, when the scan did not run
    /// against a real cgroup-v2 superblock, when it visited nothing, when any
    /// command-domain leaf was found, when any thread still lists a live child,
    /// or when the kernel has already accounted for a reaped child.
    pub fn validate(&self) -> Result<(), CommandDomainAbsenceError> {
        if self.schema_version != LINUX_ABSENCE_OBSERVATION_VERSION {
            return Err(CommandDomainAbsenceError::UnsupportedVersion {
                version: self.schema_version,
            });
        }
        self.validate_binding()?;
        self.validate_scanned_namespace()?;
        self.validate_no_domain_leaf()?;
        self.validate_no_child_process()
    }

    /// The observation answers a question about one exact command effect. An
    /// absence read for another request is not evidence about this one.
    fn validate_binding(&self) -> Result<(), CommandDomainAbsenceError> {
        for (field, value) in [
            ("runner_session_id", self.runner_session_id.as_str()),
            ("effect_id", self.effect_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > MAX_BINDING_TEXT_BYTES
                || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
            {
                return Err(CommandDomainAbsenceError::InvalidBinding { field });
            }
        }
        if self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(CommandDomainAbsenceError::InvalidBinding {
                field: "request_digest",
            });
        }
        Ok(())
    }

    /// Emptiness only means "no domain" when it was read in the namespace where
    /// a domain would have been created. A truthful read somewhere else proves
    /// nothing, which is the difference between an absent domain and an
    /// unproven one.
    fn validate_scanned_namespace(&self) -> Result<(), CommandDomainAbsenceError> {
        if self.self_cgroup_bytes.is_empty() || self.self_cgroup_bytes.len() > MAX_SELF_CGROUP_BYTES
        {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "self_cgroup_bytes",
            });
        }
        if !self.self_cgroup_bytes.starts_with(b"0::") {
            return Err(CommandDomainAbsenceError::NotUnifiedHierarchy);
        }
        if self.scanned_filesystem_magic != CGROUP2_SUPER_MAGIC {
            return Err(CommandDomainAbsenceError::NotCgroupV2 {
                magic: self.scanned_filesystem_magic,
            });
        }
        if self.scanned_root_identity.device == 0 || self.scanned_root_identity.inode == 0 {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "scanned_root_identity",
            });
        }
        if self.scanned_directory_count == 0
            || self.scanned_directory_count > MAX_SCANNED_DIRECTORIES
        {
            return Err(CommandDomainAbsenceError::EmptyScan);
        }
        if self.sampled_root_entries.len() > MAX_SAMPLED_ROOT_ENTRIES {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "sampled_root_entries",
            });
        }
        for entry in &self.sampled_root_entries {
            validate_entry_name(entry)?;
        }
        if self
            .sampled_root_entries
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "sampled_root_entries",
            });
        }
        Ok(())
    }

    /// A leaf that exists is a domain that exists, and no surrounding evidence
    /// makes it absent.
    fn validate_no_domain_leaf(&self) -> Result<(), CommandDomainAbsenceError> {
        if let Some(leaf) = self.domain_leaf_candidates.first() {
            return Err(CommandDomainAbsenceError::DomainLeafPresent {
                leaf_name: leaf.clone(),
            });
        }
        // A record that observed a leaf at the root but omitted it from its
        // candidate list would otherwise decode as absence.
        if let Some(leaf) = self
            .sampled_root_entries
            .iter()
            .find(|entry| is_domain_leaf_name(entry))
        {
            return Err(CommandDomainAbsenceError::DomainLeafPresent {
                leaf_name: leaf.clone(),
            });
        }
        Ok(())
    }

    /// No domain also means no target process: a live child could still be
    /// contained by a domain this scan cannot see, and a reaped child means one
    /// existed even though nothing lists it now.
    fn validate_no_child_process(&self) -> Result<(), CommandDomainAbsenceError> {
        if self.task_children_reads.is_empty()
            || self.task_children_reads.len() > MAX_TASK_CHILDREN_READS
        {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "task_children_reads",
            });
        }
        for read in &self.task_children_reads {
            if read.thread_id == 0 || read.bytes.len() > MAX_TASK_CHILDREN_BYTES {
                return Err(CommandDomainAbsenceError::InvalidRead {
                    field: "task_children_reads",
                });
            }
            if !read
                .bytes
                .iter()
                .all(|byte| byte.is_ascii_whitespace() || *byte == 0)
            {
                return Err(CommandDomainAbsenceError::LiveChildPresent {
                    thread_id: read.thread_id,
                });
            }
        }
        if self
            .task_children_reads
            .windows(2)
            .any(|pair| pair[0].thread_id >= pair[1].thread_id)
        {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "task_children_reads",
            });
        }
        let accounting = self.reaped_child_accounting;
        if accounting.minor_faults != 0
            || accounting.major_faults != 0
            || accounting.user_time_ticks != 0
            || accounting.system_time_ticks != 0
        {
            return Err(CommandDomainAbsenceError::ReapedChildAccounted);
        }
        Ok(())
    }
}

fn validate_entry_name(entry: &str) -> Result<(), CommandDomainAbsenceError> {
    if entry.is_empty()
        || entry.len() > MAX_ENTRY_NAME_BYTES
        || entry == "."
        || entry == ".."
        || entry.bytes().any(|byte| byte == b'/' || byte <= 0x20)
    {
        return Err(CommandDomainAbsenceError::InvalidRead {
            field: "entry_name",
        });
    }
    Ok(())
}

/// Closed reason one absence observation could not be produced or believed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDomainAbsenceError {
    /// The record schema version is not the supported one.
    UnsupportedVersion {
        /// Observed schema version.
        version: u32,
    },
    /// A command-effect binding identifier is not canonical.
    InvalidBinding {
        /// Exact invalid binding field.
        field: &'static str,
    },
    /// A retained kernel read is empty, oversized, or otherwise unusable.
    InvalidRead {
        /// Exact unusable field.
        field: &'static str,
    },
    /// A required kernel read could not be performed at all.
    ReadUnavailable {
        /// Exact read that failed.
        field: &'static str,
    },
    /// The host is not running the unified cgroup-v2 hierarchy.
    NotUnifiedHierarchy,
    /// The scanned mount is not a cgroup-v2 superblock.
    NotCgroupV2 {
        /// Observed superblock magic.
        magic: u64,
    },
    /// The bounded scan visited nothing or exceeded its bound.
    EmptyScan,
    /// A command-domain leaf exists, so no domain-absence claim can hold.
    DomainLeafPresent {
        /// Exact leaf directory name observed.
        leaf_name: String,
    },
    /// The kernel still lists a live child for one runner thread.
    LiveChildPresent {
        /// Thread whose child list was not empty.
        thread_id: u32,
    },
    /// The kernel has already accounted for at least one reaped child.
    ReapedChildAccounted,
}

impl Display for CommandDomainAbsenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "unsupported command-domain absence observation version {version}"
                )
            }
            Self::InvalidBinding { field } => {
                write!(
                    formatter,
                    "invalid absence observation binding field {field}"
                )
            }
            Self::InvalidRead { field } => {
                write!(formatter, "unusable absence observation read {field}")
            }
            Self::ReadUnavailable { field } => {
                write!(formatter, "absence observation could not read {field}")
            }
            Self::NotUnifiedHierarchy => {
                formatter.write_str("host does not use the unified cgroup-v2 hierarchy")
            }
            Self::NotCgroupV2 { magic } => write!(
                formatter,
                "scanned mount magic was {magic:#x}, expected {CGROUP2_SUPER_MAGIC:#x}"
            ),
            Self::EmptyScan => {
                formatter.write_str("bounded cgroup subtree scan visited nothing or overflowed")
            }
            Self::DomainLeafPresent { leaf_name } => {
                write!(formatter, "command-domain leaf {leaf_name} exists")
            }
            Self::LiveChildPresent { thread_id } => {
                write!(formatter, "thread {thread_id} still lists a live child")
            }
            Self::ReapedChildAccounted => {
                formatter.write_str("kernel accounting shows this process already reaped a child")
            }
        }
    }
}

impl std::error::Error for CommandDomainAbsenceError {}

#[cfg(target_os = "linux")]
include!("command_domain_absence/linux.rs");

/// Non-Linux hosts have no cgroup-v2 command domain to observe, so no absence
/// observation exists there and the refusal keeps its evidence-free shape.
///
/// # Errors
///
/// Always returns [`CommandDomainAbsenceError::ReadUnavailable`].
#[cfg(not(target_os = "linux"))]
pub fn observe_linux_command_domain_absence(
    _runner_session_id: &str,
    _effect_id: &str,
    _request_digest: &str,
) -> Result<LinuxCommandDomainAbsenceObservationV1, CommandDomainAbsenceError> {
    Err(CommandDomainAbsenceError::ReadUnavailable {
        field: "linux_cgroup_v2",
    })
}

#[cfg(test)]
mod tests;
