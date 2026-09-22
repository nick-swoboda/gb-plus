//! ZIP is decoded to an inert capsule; nothing is extracted or executed.

use super::content::{Blob, Bundle, MAX_BYTES, MAX_FILE_BYTES, MAX_FILES, validate_path};
use super::failure;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read as _};
use zip::{CompressionMethod, ZipArchive};

pub(super) fn decode(bytes: &[u8]) -> Result<Bundle, String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("Extension ZIP exceeds its compressed bound.".into());
    }
    let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(failure)?;
    if zip.len() > MAX_FILES * 2 {
        return Err("Extension ZIP has too many entries.".into());
    }
    let mut bundle = Bundle {
        files: BTreeMap::new(),
    };
    let mut paths = BTreeSet::new();
    let mut total = 0usize;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(failure)?;
        let name = std::str::from_utf8(entry.name_raw())
            .map_err(failure)?
            .to_owned();
        let path = name.strip_suffix('/').unwrap_or(&name);
        validate_path(path)?;
        if !paths.insert(path.to_ascii_lowercase())
            || entry.encrypted()
            || entry.is_symlink()
            || !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            )
        {
            return Err(
                "Extension ZIP has duplicate, encrypted, linked, or unsupported content.".into(),
            );
        }
        let mode = entry.unix_mode().unwrap_or(0);
        let kind = mode & 0o170_000;
        if entry.is_dir() {
            if !matches!(kind, 0 | 0o040_000) || entry.size() != 0 {
                return Err("Extension ZIP directory type is inconsistent.".into());
            }
            continue;
        }
        if !entry.is_file()
            || !matches!(kind, 0 | 0o100_000)
            || entry.size() > MAX_FILE_BYTES as u64
            || bundle.files.len() >= MAX_FILES
        {
            return Err("Extension ZIP file type or size is not admitted.".into());
        }
        let length = usize::try_from(entry.size()).map_err(failure)?;
        total = total
            .checked_add(length)
            .ok_or("Extension ZIP expanded size overflow.")?;
        if total > MAX_BYTES {
            return Err("Extension ZIP expanded size exceeds 64 MiB.".into());
        }
        let mut bytes = Vec::new();
        (&mut entry)
            .take((length as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(failure)?;
        if bytes.len() != length {
            return Err("Extension ZIP file length differs from its inventory.".into());
        }
        bundle.files.insert(
            path.to_owned(),
            Blob {
                executable: mode & 0o111 != 0,
                bytes,
            },
        );
    }
    strip_wrapper(&mut bundle)?;
    bundle.validate()?;
    Ok(bundle)
}

fn strip_wrapper(bundle: &mut Bundle) -> Result<(), String> {
    let root_manifest = [
        "plugin.json",
        ".grok-plugin/plugin.json",
        ".claude-plugin/plugin.json",
        ".codex-plugin/plugin.json",
    ]
    .iter()
    .any(|path| bundle.files.contains_key(*path));
    if root_manifest {
        return Ok(());
    }
    let prefix = bundle
        .files
        .keys()
        .next()
        .and_then(|path| path.split_once('/'))
        .map(|(directory, _)| format!("{directory}/"))
        .ok_or("Extension ZIP has no plugin manifest.")?;
    if !bundle.files.keys().all(|path| path.starts_with(&prefix)) {
        return Err("Extension ZIP has multiple unbound roots.".into());
    }
    let files = std::mem::take(&mut bundle.files);
    bundle.files = files
        .into_iter()
        .map(|(path, blob)| (path[prefix.len()..].to_owned(), blob))
        .collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn archive(paths: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (path, bytes) in paths {
            writer
                .start_file(
                    *path,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    #[test]
    fn wrapped_archive_is_inert_and_traversal_or_case_collisions_refuse() {
        let bytes = archive(&[
            ("release/plugin.json", b"{}"),
            ("release/install.sh", b"#!/bin/sh\nexit 99"),
        ]);
        let bundle = decode(&bytes).unwrap();
        assert!(bundle.files.contains_key("install.sh"));
        assert!(!bundle.files.contains_key("release/install.sh"));
        assert!(decode(&archive(&[("../plugin.json", b"{}")])).is_err());
        assert!(
            decode(&archive(&[
                ("plugin.json", b"{}"),
                ("A", b"a"),
                ("a", b"b")
            ]))
            .is_err()
        );
    }
}
