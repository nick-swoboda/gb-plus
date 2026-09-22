// Linux reads behind one command-domain absence observation.
//
// Included from `command_domain_absence.rs` under `cfg(target_os = "linux")`.
// Every function here performs a read and returns what the kernel answered; no
// function here decides anything about containment.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::linux::fs::MetadataExt as _;
use std::path::Path;

/// Fixed mount point of the unified cgroup-v2 hierarchy.
const CGROUP2_MOUNT_PATH: &str = "/sys/fs/cgroup";
/// Maximum directory depth visited by one bounded subtree scan.
const MAX_SCAN_DEPTH: u32 = 16;

/// Reads the three independent absence answers and binds them to one effect.
///
/// The answers are about this whole process, not only this effect: a runner
/// that has ever created a child cannot claim that no command domain exists,
/// because the child could have been contained by one. That makes the
/// observation deliberately fragile in a process that forks for other reasons,
/// and correct in the single-purpose runner service, where it is produced.
///
/// # Errors
///
/// Fails, rather than degrading, whenever a read is unavailable, a bound is
/// reached, or any answer is not the absence answer: a partial absence
/// observation is not an absence observation.
pub fn observe_linux_command_domain_absence(
    runner_session_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> Result<LinuxCommandDomainAbsenceObservationV1, CommandDomainAbsenceError> {
    let self_cgroup_bytes = read_bounded("/proc/self/cgroup", MAX_SELF_CGROUP_BYTES)
        .ok_or(CommandDomainAbsenceError::ReadUnavailable {
            field: "/proc/self/cgroup",
        })?;

    let mount = Path::new(CGROUP2_MOUNT_PATH);
    let statfs =
        rustix::fs::statfs(mount).map_err(|_| CommandDomainAbsenceError::ReadUnavailable {
            field: "statfs(/sys/fs/cgroup)",
        })?;
    let scanned_filesystem_magic = u64::try_from(statfs.f_type).unwrap_or_default();

    let metadata =
        fs::metadata(mount).map_err(|_| CommandDomainAbsenceError::ReadUnavailable {
            field: "stat(/sys/fs/cgroup)",
        })?;
    let scanned_root_identity = LinuxScannedRootIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
    };

    let scan = scan_cgroup_subtree(mount)?;

    let task_children_reads = read_task_children()?;
    let reaped_child_accounting = read_reaped_child_accounting()?;

    let observation = LinuxCommandDomainAbsenceObservationV1 {
        schema_version: LINUX_ABSENCE_OBSERVATION_VERSION,
        runner_session_id: runner_session_id.to_owned(),
        effect_id: effect_id.to_owned(),
        request_digest: request_digest.to_owned(),
        self_cgroup_bytes,
        scanned_filesystem_magic,
        scanned_root_identity,
        scanned_directory_count: scan.visited,
        sampled_root_entries: scan.sampled_root_entries,
        domain_leaf_candidates: scan.domain_leaf_candidates,
        task_children_reads,
        reaped_child_accounting,
    };
    observation.validate()?;
    Ok(observation)
}

struct SubtreeScan {
    visited: u32,
    sampled_root_entries: Vec<String>,
    domain_leaf_candidates: Vec<String>,
}

/// Walks the visible cgroup-v2 subtree under one bounded budget.
///
/// The mount is the deepest cgroup this process can see, so a leaf minted for
/// this runner would have to appear inside it. Overflowing either bound aborts
/// the observation rather than reporting a partial absence.
fn scan_cgroup_subtree(root: &Path) -> Result<SubtreeScan, CommandDomainAbsenceError> {
    let mut sampled_root_entries = BTreeSet::new();
    let mut domain_leaf_candidates = BTreeSet::new();
    let mut visited = 0_u32;
    let mut frontier = vec![(root.to_path_buf(), 0_u32)];
    while let Some((directory, depth)) = frontier.pop() {
        if depth > MAX_SCAN_DEPTH {
            return Err(CommandDomainAbsenceError::EmptyScan);
        }
        visited = visited
            .checked_add(1)
            .ok_or(CommandDomainAbsenceError::EmptyScan)?;
        if visited > MAX_SCANNED_DIRECTORIES {
            return Err(CommandDomainAbsenceError::EmptyScan);
        }
        // Skip only a cgroup that vanished; refuse other read errors.
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                visited = visited.saturating_sub(1);
                continue;
            }
            Err(_) => {
                return Err(CommandDomainAbsenceError::ReadUnavailable {
                    field: "read_dir(cgroup)",
                });
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    return Err(CommandDomainAbsenceError::ReadUnavailable {
                        field: "read_dir(cgroup)",
                    });
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    return Err(CommandDomainAbsenceError::ReadUnavailable {
                        field: "read_dir(cgroup)",
                    });
                }
            };
            // `read_dir` reports the entry's own type, so a symlink is never
            // followed into another filesystem.
            if !file_type.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(CommandDomainAbsenceError::InvalidRead {
                    field: "entry_name",
                });
            };
            validate_entry_name(name)?;
            if depth == 0 && sampled_root_entries.len() < MAX_SAMPLED_ROOT_ENTRIES {
                sampled_root_entries.insert(name.to_owned());
            }
            if is_domain_leaf_name(name) {
                domain_leaf_candidates.insert(name.to_owned());
            }
            let next_depth = depth
                .checked_add(1)
                .ok_or(CommandDomainAbsenceError::EmptyScan)?;
            frontier.push((entry.path(), next_depth));
        }
    }
    Ok(SubtreeScan {
        visited,
        sampled_root_entries: sampled_root_entries.into_iter().collect(),
        domain_leaf_candidates: domain_leaf_candidates.into_iter().collect(),
    })
}

/// Reads the kernel's live-child list for every thread of this process.
fn read_task_children() -> Result<Vec<LinuxTaskChildrenRead>, CommandDomainAbsenceError> {
    let tasks =
        fs::read_dir("/proc/self/task").map_err(|_| CommandDomainAbsenceError::ReadUnavailable {
            field: "/proc/self/task",
        })?;
    let mut reads = Vec::new();
    for task in tasks {
        // A thread that exits while `/proc/self/task` is walked leaves nothing
        // to read and lists no child; every other error still aborts.
        let task = match task {
            Ok(task) => task,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err(CommandDomainAbsenceError::ReadUnavailable {
                    field: "/proc/self/task",
                });
            }
        };
        let name = task.file_name();
        let Some(thread_id) = name.to_str().and_then(|text| text.parse::<u32>().ok()) else {
            continue;
        };
        let path = task.path().join("children");
        let Some(bytes) = read_bounded(&path, MAX_TASK_CHILDREN_BYTES) else {
            continue;
        };
        if reads.len() >= MAX_TASK_CHILDREN_READS {
            return Err(CommandDomainAbsenceError::InvalidRead {
                field: "task_children_reads",
            });
        }
        reads.push(LinuxTaskChildrenRead { thread_id, bytes });
    }
    reads.sort_by_key(|read| read.thread_id);
    reads.dedup_by_key(|read| read.thread_id);
    if reads.is_empty() {
        return Err(CommandDomainAbsenceError::ReadUnavailable {
            field: "/proc/self/task/<tid>/children",
        });
    }
    Ok(reads)
}

/// Reads `/proc/self/stat` child accounting fields 11, 13, 16, and 17.
///
/// The executable name in field 2 may contain spaces and parentheses, so the
/// scan starts after the final `)` rather than splitting the whole line.
fn read_reaped_child_accounting() -> Result<LinuxReapedChildAccounting, CommandDomainAbsenceError> {
    let bytes =
        read_bounded("/proc/self/stat", MAX_SELF_CGROUP_BYTES).ok_or(
            CommandDomainAbsenceError::ReadUnavailable {
                field: "/proc/self/stat",
            },
        )?;
    let text = String::from_utf8(bytes).map_err(|_| CommandDomainAbsenceError::InvalidRead {
        field: "/proc/self/stat",
    })?;
    let tail = text
        .rfind(')')
        .and_then(|index| text.get(index + 1..))
        .ok_or(CommandDomainAbsenceError::InvalidRead {
            field: "/proc/self/stat",
        })?;
    let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
    // `tail` starts at field 3, so field N is at index N - 3.
    let unsigned = |field: usize| -> Result<u64, CommandDomainAbsenceError> {
        fields
            .get(field - 3)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(CommandDomainAbsenceError::InvalidRead {
                field: "/proc/self/stat",
            })
    };
    let signed = |field: usize| -> Result<i64, CommandDomainAbsenceError> {
        fields
            .get(field - 3)
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(CommandDomainAbsenceError::InvalidRead {
                field: "/proc/self/stat",
            })
    };
    Ok(LinuxReapedChildAccounting {
        minor_faults: unsigned(11)?,
        major_faults: unsigned(13)?,
        user_time_ticks: signed(16)?,
        system_time_ticks: signed(17)?,
    })
}

fn read_bounded(path: impl AsRef<Path>, maximum: usize) -> Option<Vec<u8>> {
    let bytes = fs::read(path).ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}
