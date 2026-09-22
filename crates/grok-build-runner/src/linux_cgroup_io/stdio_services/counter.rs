//! A durable high-water mark permits receipt pruning without lease replay.

use std::io::Read as _;

use cap_std::fs::{Dir, File};
use serde::{Deserialize, Serialize};

use super::{SERVICE_ROOT, failure, kernel_failure};

const NAME: &str = "sequence-v1.json";
const NEXT: &str = "next-sequence-v1.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Watermark {
    version: u16,
    maximum: u64,
}

pub(super) struct Journal {
    pub(super) records: Dir,
    _lock: File,
    pub(super) maximum: u64,
}

impl Journal {
    pub(super) fn open(state: &Dir) -> Result<Self, String> {
        let fresh = match rustix::fs::mkdirat(state, SERVICE_ROOT, rustix::fs::Mode::RWXU) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(failure(error)),
        };
        let uid = rustix::process::geteuid().as_raw();
        let (records, _) = super::super::open_or_create_private_directory(state, SERVICE_ROOT, uid)
            .map_err(kernel_failure)?;
        let (lock, _) =
            super::super::open_or_create_private_lock(&records, uid).map_err(kernel_failure)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(failure)?;
        if fresh {
            super::super::write_new_private_file(&records, NAME, &encode(0)?, uid)
                .map_err(kernel_failure)?;
            super::super::sync_directory(&records).map_err(failure)?;
            super::super::sync_directory(state).map_err(failure)?;
        }
        // An existing directory with a missing/unknown counter is recovery state,
        // never a fresh counter. In particular, old development receipts survive.
        let watermark: Watermark =
            serde_json::from_slice(&read(&records, NAME)?).map_err(failure)?;
        if watermark.version != 1 {
            return Err("Unknown service lease counter remains recoverable.".into());
        }
        Ok(Self {
            records,
            _lock: lock,
            maximum: watermark.maximum,
        })
    }

    pub(super) fn next(&self) -> Result<u64, String> {
        self.maximum
            .checked_add(1)
            .ok_or("Service lease sequence is exhausted.".into())
    }

    pub(super) fn reserve(&mut self, sequence: u64) -> Result<(), String> {
        if sequence != self.next()? {
            return Err("Service lease is stale or out of sequence; it cannot be replayed.".into());
        }
        if self.records.try_exists(NEXT).map_err(failure)? {
            read(&self.records, NEXT)?; // Validate even an uncommitted temporary before removal.
            self.records.remove_file(NEXT).map_err(failure)?;
        }
        let bytes = encode(sequence)?;
        super::super::write_new_private_file(
            &self.records,
            NEXT,
            &bytes,
            rustix::process::geteuid().as_raw(),
        )
        .map_err(kernel_failure)?;
        self.records
            .rename(NEXT, &self.records, NAME)
            .map_err(failure)?;
        super::super::sync_directory(&self.records).map_err(failure)?;
        if read(&self.records, NAME)? != bytes {
            return Err("Service counter readback differs.".into());
        }
        self.maximum = sequence;
        Ok(())
    }
}

pub(super) fn metadata_name(name: &str) -> bool {
    matches!(name, NAME | NEXT | "writer.lock")
}

pub(super) fn lease_name(sequence: u64) -> String {
    format!("gb-service-{sequence:020}")
}

pub(super) fn lease_sequence(name: &str) -> Result<u64, String> {
    let sequence = name
        .strip_prefix("gb-service-")
        .ok_or("Service lease has no sequence.")?
        .parse::<u64>()
        .map_err(failure)?;
    if sequence == 0 || name != lease_name(sequence) {
        return Err("Service lease sequence is not canonical.".into());
    }
    Ok(sequence)
}

pub(super) fn prune_completed(
    records: &Dir,
    mut sequences: Vec<u64>,
    maximum: u64,
) -> Result<usize, String> {
    sequences.sort_unstable();
    if sequences
        .iter()
        .any(|sequence| *sequence == 0 || *sequence > maximum)
        || sequences.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err("Completed service receipts do not match their durable counter.".into());
    }
    let discarded = sequences.len().saturating_sub(16);
    for sequence in sequences.into_iter().take(discarded) {
        let identity = crate::service_contract::service_lease_digest(&lease_name(sequence));
        records
            .remove_file(format!("lease-{identity}.json"))
            .map_err(failure)?;
    }
    if discarded != 0 {
        super::super::sync_directory(records).map_err(failure)?;
    }
    Ok(discarded)
}

fn encode(maximum: u64) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&Watermark {
        version: 1,
        maximum,
    })
    .map_err(failure)
}

fn read(directory: &Dir, name: &str) -> Result<Vec<u8>, String> {
    read_private_metadata(directory, name, 512)
}

pub(super) fn read_private_metadata(
    directory: &Dir,
    name: &str,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    // A malformed FIFO must refuse before it can block an owning helper.
    let fd = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(failure)?;
    let file = File::from_std(std::fs::File::from(fd));
    let metadata = file.metadata().map_err(failure)?;
    super::super::validate_private_file(&metadata, rustix::process::geteuid().as_raw())
        .map_err(kernel_failure)?;
    let identity = super::super::object_identity(&metadata);
    super::super::require_named_identity(directory, name, identity, "service-counter-read")
        .map_err(kernel_failure)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() as u64 > maximum {
        return Err("Service lease metadata exceeds its bound.".into());
    }
    super::super::require_named_identity(directory, name, identity, "service-counter-read")
        .map_err(kernel_failure)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
