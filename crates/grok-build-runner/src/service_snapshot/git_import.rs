//! Inert Git object import from a verified captured view. No repository command runs.
use super::{ServiceSnapshot, ServiceSnapshotFrame, ServiceSnapshotOperation};
use grok_build_core::Digest;

const MAX_IMPORT_BYTES: usize = 160 * 1024 * 1024;
const MAX_IMPORT_FILES: usize = 16_384;

impl ServiceSnapshot {
    /// Encode exact captured working files for an app-owned empty Git object
    /// store. File modes and bytes are preserved without checkout, attributes,
    /// filters, user Git identity or repository configuration. The caller must
    /// separately admit its Git process and retain the snapshot for empty folders.
    ///
    /// # Errors
    /// Refuses source drift, cancellation, unsafe paths, duplicate spellings,
    /// incomplete transfers or an import exceeding 160 MiB / 16,384 files.
    pub fn git_fast_import(&self, cancelled: &dyn Fn() -> bool) -> Result<Vec<u8>, String> {
        let (files, bytes) = self.size();
        if files > MAX_IMPORT_FILES || bytes > MAX_IMPORT_BYTES as u64 {
            return Err("Child snapshot exceeds its Git import budget.".into());
        }
        let mut import = SnapshotImport::new(self.digest().clone());
        self.transfer(&mut |frame| import.accept(frame), cancelled)?;
        import.finish()
    }
}

struct FileInput {
    path: String,
    executable: bool,
    expected_bytes: u64,
    expected_digest: Digest,
    bytes: Vec<u8>,
}
pub(crate) struct SnapshotImport {
    expected_snapshot: Digest,
    sequence: u64,
    output: Vec<u8>,
    current: Option<FileInput>,
    files: usize,
    finished: bool,
    poisoned: bool,
    paths: std::collections::BTreeSet<String>,
}
impl SnapshotImport {
    pub(crate) fn new(expected: Digest) -> Self {
        // Fixed author/date/ref keep this object store independent of user Git
        // identity, history, hooks, signing configuration and environment.
        let output=b"feature done\ncommit refs/heads/gbplus-snapshot\ncommitter GB Plus <snapshot@localhost> 1 +0000\ndata 17\nGB Plus snapshot\n\n".to_vec();
        Self {
            expected_snapshot: expected,
            sequence: 0,
            output,
            current: None,
            files: 0,
            finished: false,
            poisoned: false,
            paths: std::collections::BTreeSet::new(),
        }
    }
    pub(crate) fn accept(&mut self, frame: &ServiceSnapshotFrame) -> Result<(), String> {
        if self.poisoned {
            return Err("Snapshot import previously failed.".into());
        }
        let result = self.accept_inner(frame);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn accept_inner(&mut self, frame: &ServiceSnapshotFrame) -> Result<(), String> {
        if self.finished || frame.version != 1 || frame.sequence != self.sequence {
            return Err("Snapshot import ordering refused.".into());
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("Snapshot import sequence overflow.")?;
        match &frame.operation {
            ServiceSnapshotOperation::Directory { path } => {
                if self.current.is_some() {
                    return Err("Snapshot file is incomplete.".into());
                }
                validate_path(path)?;
            }
            ServiceSnapshotOperation::File {
                path,
                executable,
                bytes,
                digest,
            } => {
                if self.current.is_some()
                    || self.files >= MAX_IMPORT_FILES
                    || *bytes > MAX_IMPORT_BYTES as u64
                    || self.output.len() as u64 + *bytes > MAX_IMPORT_BYTES as u64
                {
                    return Err("Snapshot import exceeds its file/input budget; parallel isolation is unavailable.".into());
                }
                validate_path(path)?;
                if !self.paths.insert(path.to_lowercase()) {
                    return Err("Snapshot import repeated an ambiguous path.".into());
                }
                self.current = Some(FileInput {
                    path: path.clone(),
                    executable: *executable,
                    expected_bytes: *bytes,
                    expected_digest: digest.clone(),
                    bytes: Vec::new(),
                });
                self.files += 1;
            }
            ServiceSnapshotOperation::Data { bytes } => {
                let file = self.current.as_mut().ok_or("Snapshot data has no file.")?;
                if bytes.len() > 64 * 1024
                    || file.bytes.len() as u64 + bytes.len() as u64 > file.expected_bytes
                {
                    return Err("Snapshot file data exceeded its declaration.".into());
                }
                file.bytes.extend_from_slice(bytes);
            }
            ServiceSnapshotOperation::EndFile => {
                let file = self.current.take().ok_or("Snapshot end has no file.")?;
                if file.bytes.len() as u64 != file.expected_bytes
                    || Digest::sha256(&file.bytes) != file.expected_digest
                {
                    return Err("Snapshot file content changed.".into());
                }
                let mode = if file.executable { "100755" } else { "100644" };
                let header = format!(
                    "M {mode} inline {}\ndata {}\n",
                    quote_path(&file.path),
                    file.bytes.len()
                );
                if self
                    .output
                    .len()
                    .saturating_add(header.len())
                    .saturating_add(file.bytes.len())
                    .saturating_add(8)
                    > MAX_IMPORT_BYTES
                {
                    return Err("Snapshot import byte budget exceeded.".into());
                }
                self.output.extend_from_slice(header.as_bytes());
                self.output.extend_from_slice(&file.bytes);
                self.output.push(b'\n');
            }
            ServiceSnapshotOperation::Finish { digest } => {
                if self.current.is_some() || digest != &self.expected_snapshot {
                    return Err("Snapshot import completion changed identity.".into());
                }
                self.output.extend_from_slice(b"\ndone\n");
                self.finished = true;
            }
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Result<Vec<u8>, String> {
        if self.poisoned || !self.finished || self.output.len() > MAX_IMPORT_BYTES {
            return Err("Snapshot import has not sealed a complete view.".into());
        }
        Ok(self.output)
    }
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4096
        || path.split('/').count() > 33
        || path
            .split('/')
            .any(|p| !crate::service_path_component_allowed(p))
    {
        return Err("Snapshot import path is unavailable.".into());
    }
    Ok(())
}
fn quote_path(path: &str) -> String {
    use std::fmt::Write as _;
    let mut quoted = String::from("\"");
    for byte in path.bytes() {
        match byte {
            b'"' => quoted.push_str("\\\""),
            b'\\' => quoted.push_str("\\\\"),
            0x20..=0x7e => quoted.push(char::from(byte)),
            _ => write!(&mut quoted, "\\{byte:03o}").expect("write to String"),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_cannot_insert_import_commands_and_unicode_bytes_remain_exact() {
        assert_eq!(
            quote_path("file \"one\"\\é.rs"),
            "\"file \\\"one\\\"\\\\\\303\\251.rs\""
        );
        for path in [
            "../outside",
            "a/../../outside",
            ".git/config",
            "a\nM 100644 inline x",
            "/absolute",
            "a//b",
        ] {
            assert!(validate_path(path).is_err());
        }
        validate_path("src/file é.rs").unwrap();
    }
    #[test]
    fn incomplete_and_crossed_snapshot_transfers_cannot_produce_an_import() {
        let digest = Digest::sha256(b"snapshot");
        let mut import = SnapshotImport::new(digest.clone());
        let frame = ServiceSnapshotFrame {
            version: 1,
            sequence: 0,
            operation: ServiceSnapshotOperation::File {
                path: "Cargo.toml".into(),
                executable: false,
                bytes: 3,
                digest: Digest::sha256(b"old"),
            },
        };
        import.accept(&frame).unwrap();
        assert!(import.accept(&frame).is_err());
        assert!(import.finish().is_err());
        let mut import = SnapshotImport::new(digest);
        assert!(
            import
                .accept(&ServiceSnapshotFrame {
                    version: 1,
                    sequence: 0,
                    operation: ServiceSnapshotOperation::Finish {
                        digest: Digest::sha256(b"other")
                    }
                })
                .is_err()
        );
    }
}
