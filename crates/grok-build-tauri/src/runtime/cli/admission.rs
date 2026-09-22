//! Publisher validation precedes even --version; the integration target is pinned.

use std::ffi::OsStr;
use std::io::Read as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

const TARGET_BYTES: u64 = 138_080_336;
const TARGET_SHA256: [u8; 32] = [
    0x9e, 0xf4, 0xa4, 0x0a, 0xd6, 0x0c, 0x6a, 0x51, 0x78, 0xa6, 0x5c, 0xaf, 0x39, 0xc2, 0xa1, 0x48,
    0xe6, 0xa9, 0x8d, 0x0d, 0x2d, 0x35, 0x0b, 0x10, 0x32, 0x9d, 0xee, 0x34, 0xd9, 0x19, 0x5d, 0x9c,
];

pub(super) fn verify_publisher(cli: &Path) -> Result<(), String> {
    let cli = std::fs::canonicalize(cli).map_err(|e| e.to_string())?;
    crate::runtime::system_process::run("/usr/bin/codesign",&[OsStr::new("--verify"),OsStr::new("--strict"),OsStr::new("-R"),OsStr::new("=anchor apple generic and identifier \"xai-grok-pager\" and certificate leaf[subject.OU] = \"5Y6N3AJ54S\""),cli.as_os_str()],&[]).map(|_|()).map_err(|_|"The selected CLI does not satisfy the admitted xAI publisher signature; it was not executed.".into())
}

pub(super) fn verify_target_digest(cli: &Path) -> Result<(), String> {
    let mut file = std::fs::File::open(cli).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() != TARGET_BYTES {
        return Err(
            "CLI 1.0.25 bytes differ from the admitted arm64 release; a new admission is required."
                .into(),
        );
    }
    let mut digest = Sha256::new();
    let mut bytes = [0; 8192];
    let mut count = 0u64;
    loop {
        let read = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        count = count.saturating_add(read as u64);
        if count > TARGET_BYTES {
            return Err("CLI changed during admission.".into());
        }
        digest.update(&bytes[..read]);
    }
    if count != TARGET_BYTES || digest.finalize().as_slice() != TARGET_SHA256 {
        return Err("CLI 1.0.25 digest differs from the exact admitted executable; no ACP process was started.".into());
    }
    Ok(())
}
