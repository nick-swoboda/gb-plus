//! Default-safe diagnostic ZIP export for the Activity surface.
//!
//! The exporter accepts only a deliberately reduced, typed snapshot. Chat,
//! command output, environment values, provider headers, Keychain material,
//! workspace bytes, captures, browser profiles, and audio are absent from the
//! input type and therefore cannot be serialized accidentally.

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use grok_build_plus_host::{PlusProjectBook, worktree_recovery_digest};
use serde::{Deserialize, Serialize};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::child_environment::ChildEnvironmentProfile;
use crate::events::DiagnosticEventMetadata;
#[cfg(test)]
use crate::runtime::keychain::KeychainPresence;
use crate::runtime::manager::RuntimeSnapshot;
use crate::runtime::types::ConnectionState;

const DIAGNOSTIC_SCHEMA_VERSION: u16 = 1;
const MAX_ENTRY_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_BYTES: usize = 2 * 1024 * 1024;
const VERSION_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const ZIP_ENTRY_MODE: u32 = 0o600;

const README_ENTRY: &str = "README.txt";
const APP_ENTRY: &str = "app.json";
const HOST_ENTRY: &str = "host.json";
const RUNTIME_ENTRY: &str = "runtime.json";
const PROJECTS_ENTRY: &str = "projects.json";
const SECURITY_ENTRY: &str = "security.json";
const CAPABILITIES_ENTRY: &str = "capabilities.json";
const EVENTS_ENTRY: &str = "events.json";
const RELEASE_ENTRY: &str = "release-evidence.json";
const REDACTION_ENTRY: &str = "redaction.json";
const MANIFEST_ENTRY: &str = "manifest.json";
const RELEASE_RECEIPT_FILE: &str = "GrokBuildReleaseReceipt.json";
const MAX_RELEASE_RECEIPT_BYTES: u64 = 16 * 1024;

const README: &str = "GB Plus diagnostic archive\n\nThis archive is default-safe support metadata. It contains version, host, selected transport, project/worktree path, command-security, and capability-state metadata. It omits credential material, process variables, conversation content, command streams, browser state, captures, audio, and workspace file contents. See redaction.json and manifest.json.\n";

#[derive(Clone, Debug)]
pub(crate) struct DiagnosticInput {
    generated_at_unix_ms: u64,
    projects: DiagnosticProjects,
    security: DiagnosticSecurity,
    runtime: DiagnosticRuntime,
    cli_path: Option<PathBuf>,
    events: Result<Vec<DiagnosticEventMetadata>, String>,
    capabilities: Vec<CapabilityRecord>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticProject {
    id: String,
    source_root: String,
    active_root: String,
    active_worktree_id: Option<String>,
    worktrees: Vec<DiagnosticWorktree>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticWorktree {
    id: String,
    path: String,
    active: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticProjects {
    active_project_id: Option<String>,
    projects: Vec<DiagnosticProject>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticSecurity {
    command_security_kind: String,
    command_security_status: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticRuntime {
    selected_transport: String,
    connection_state: &'static str,
    connected_transport: Option<String>,
    model: Option<String>,
    verified_at_unix_ms: Option<u64>,
    failure_detail: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppRecord {
    schema_version: u16,
    product: &'static str,
    version: &'static str,
    tauri_version: &'static str,
    rustc_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    build_profile: &'static str,
    build_revision: Option<&'static str>,
    build_dirty: Option<bool>,
    frontend_asset_sha256: String,
    generated_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostRecord {
    supported_platform: &'static str,
    runtime_os: &'static str,
    runtime_arch: &'static str,
    product_name: Option<String>,
    product_version: Option<String>,
    build_version: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgramVersion {
    available: bool,
    version: Option<String>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeRecord {
    live: DiagnosticRuntime,
    grok_cli: ProgramVersion,
    assets: Vec<VersionedCapability>,
    sidecars: Vec<VersionedCapability>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionedCapability {
    name: &'static str,
    available: bool,
    version: Option<&'static str>,
    status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityRecord {
    capability: String,
    state: String,
    available: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticEventsRecord {
    available: bool,
    reason: Option<&'static str>,
    events: Vec<DiagnosticEventMetadata>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseReceipt {
    schema_version: u16,
    generated_at_utc: String,
    build_revision: String,
    build_dirty: bool,
    raw_binary_sha256: String,
    raw_version_check: String,
    raw_smoke: String,
    minimum_macos: String,
    architecture: String,
    #[serde(default)]
    voice_engine: Option<String>,
    #[serde(default)]
    voice_models: Option<String>,
    signature_posture: String,
    signing_identity: String,
    keychain_broker_protocol_version: u16,
    keychain_broker_account_version: u16,
    keychain_broker_identifier: String,
    keychain_broker_sha256: String,
    keychain_broker_cd_hash: String,
    keychain_broker_execution: String,
    keychain_broker_requirement_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mcp_broker_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mcp_broker_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mcp_broker_cd_hash: Option<String>,
    linux_command_security_payload_bytes: u64,
    linux_command_security_payload_sha256: String,
    linux_command_security_helper_bytes: u64,
    linux_command_security_helper_sha256: String,
    bubblewrap_corresponding_source_manifest_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleaseEvidenceRecord {
    available: bool,
    receipt: Option<ReleaseReceipt>,
    reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RedactionRecord {
    policy: &'static str,
    included_categories: Vec<&'static str>,
    omitted_categories: Vec<&'static str>,
}

#[derive(Clone, Debug)]
struct ArchiveEntry {
    name: &'static str,
    bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u16,
    generated_at_unix_ms: u64,
    entries: Vec<ManifestEntry>,
    entry_name: &'static str,
    self_hash_policy: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestEntry {
    name: &'static str,
    uncompressed_bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiagnosticExportView {
    pub(crate) path: String,
    pub(crate) archive_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) byte_count: usize,
    pub(crate) entry_count: usize,
    pub(crate) status: &'static str,
    pub(crate) redaction_summary: &'static str,
}

struct BuiltArchive {
    bytes: Vec<u8>,
    manifest_sha256: String,
    entry_count: usize,
}

impl DiagnosticInput {
    pub(crate) fn capture(
        projects: &PlusProjectBook,
        runtime: RuntimeSnapshot,
        command_security_kind: &str,
        command_security_status: &str,
        events: Result<Vec<DiagnosticEventMetadata>, String>,
    ) -> Self {
        let events = events.map(|events| sanitized_diagnostic_events(&events));
        let project_records = projects
            .projects
            .iter()
            .map(|project| DiagnosticProject {
                id: project.id.to_string(),
                source_root: project.root.display().to_string(),
                active_root: project.active_root().display().to_string(),
                active_worktree_id: project.active_worktree_id.as_ref().map(ToString::to_string),
                worktrees: project
                    .worktrees
                    .iter()
                    .map(|worktree| DiagnosticWorktree {
                        id: worktree.id.to_string(),
                        path: worktree.path.display().to_string(),
                        active: project.active_worktree_id.as_deref() == Some(worktree.id.as_str()),
                    })
                    .collect(),
            })
            .collect();
        let (connection_state, connected_transport, model, verified_at_unix_ms, failure_detail) =
            match &runtime.connection {
                ConnectionState::Disconnected => ("Disconnected", None, None, None, None),
                ConnectionState::Probing { transport } => (
                    "Probing",
                    Some(transport.label().to_owned()),
                    None,
                    None,
                    None,
                ),
                ConnectionState::Connected {
                    transport,
                    model,
                    verified_at,
                } => (
                    "Connected",
                    Some(transport.label().to_owned()),
                    hashed_provider_identifier(model),
                    Some(*verified_at),
                    None,
                ),
                ConnectionState::Failed { transport, .. } => (
                    "Failed",
                    Some(transport.label().to_owned()),
                    None,
                    None,
                    Some("Failure text omitted by the default-safe diagnostic policy."),
                ),
            };
        Self {
            generated_at_unix_ms: unix_time_millis(),
            projects: DiagnosticProjects {
                active_project_id: projects.active_id.as_ref().map(ToString::to_string),
                projects: project_records,
            },
            security: DiagnosticSecurity {
                command_security_kind: command_security_kind.to_owned(),
                command_security_status: command_security_status.to_owned(),
            },
            runtime: DiagnosticRuntime {
                selected_transport: runtime.selected_transport.label().to_owned(),
                connection_state,
                connected_transport,
                model,
                verified_at_unix_ms,
                failure_detail,
            },
            cli_path: runtime.cli_path,
            events,
            capabilities: capability_records(),
        }
    }

    pub(crate) fn set_capability(
        &mut self,
        capability: &str,
        state: &str,
        available: bool,
        detail: &str,
    ) {
        let Some(record) = self
            .capabilities
            .iter_mut()
            .find(|record| record.capability == capability)
        else {
            return;
        };
        record.state = bounded_capability_text(state);
        record.available = available;
        record.detail = bounded_capability_text(detail);
    }
}

/// Returns a collision-resistant, human-readable default name without reading
/// locale, environment, or user content.
#[must_use]
pub(crate) fn default_diagnostic_filename() -> String {
    format!("GrokBuild-Diagnostics-{}.zip", unix_time_millis())
}

/// Builds, validates, and atomically promotes one owner-only diagnostic ZIP.
pub(crate) fn export_diagnostic_zip(
    input: &DiagnosticInput,
    destination: &Path,
) -> Result<DiagnosticExportView, String> {
    let destination = validate_destination(destination)?;
    let archive = build_archive(input)?;
    let archive_sha256 = worktree_recovery_digest(&archive.bytes);
    let byte_count = archive.bytes.len();
    let temporary = create_temporary_archive(&destination, &archive.bytes)?;
    if let Err(error) = promote_without_overwrite(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(DiagnosticExportView {
        path: destination.display().to_string(),
        archive_sha256,
        manifest_sha256: archive.manifest_sha256,
        byte_count,
        entry_count: archive.entry_count,
        status: "Diagnostic archive exported",
        redaction_summary: "Credentials, environment values, conversations, command streams, browser state, captures, audio, and workspace contents were omitted.",
    })
}

fn build_archive(input: &DiagnosticInput) -> Result<BuiltArchive, String> {
    let entries = payload_entries(input)?;
    validate_entries(&entries)?;
    let manifest = Manifest {
        schema_version: DIAGNOSTIC_SCHEMA_VERSION,
        generated_at_unix_ms: input.generated_at_unix_ms,
        entries: entries
            .iter()
            .map(|entry| ManifestEntry {
                name: entry.name,
                uncompressed_bytes: entry.bytes.len(),
                sha256: worktree_recovery_digest(&entry.bytes),
            })
            .collect(),
        entry_name: MANIFEST_ENTRY,
        self_hash_policy: "Excluded to avoid a circular self-reference.",
    };
    let manifest_bytes = encode_json(&manifest)?;
    ensure_entry_size(MANIFEST_ENTRY, &manifest_bytes)?;
    let manifest_sha256 = worktree_recovery_digest(&manifest_bytes);
    let bytes = write_archive_entries(&entries, &manifest_bytes)?;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(format!(
            "Diagnostic export refused because the finished archive exceeded {MAX_ARCHIVE_BYTES} bytes."
        ));
    }
    validate_finished_archive(&bytes, &entries, &manifest_bytes)?;
    Ok(BuiltArchive {
        bytes,
        manifest_sha256,
        entry_count: entries.len() + 1,
    })
}

fn runtime_record(input: &DiagnosticInput) -> RuntimeRecord {
    RuntimeRecord {
        live: input.runtime.clone(),
        grok_cli: read_cli_version(input.cli_path.as_deref()),
        assets: vec![
            VersionedCapability {
                name: "Bundled static frontend",
                available: true,
                version: None,
                status: "Identity is the frontendAssetSha256 value in app.json.",
            },
            VersionedCapability {
                name: "xterm.js",
                available: true,
                version: Some("6.0.0 + addon-fit 0.11.0"),
                status: "Bundled as exact local assets; release packaging verifies their admitted SHA-256 values.",
            },
            VersionedCapability {
                name: "Chrome-for-Testing",
                available: false,
                version: None,
                status: "Not provisioned in this build.",
            },
            VersionedCapability {
                name: "Local Voice engine",
                available: true,
                version: Some("whisper.cpp 1.8.3 CPU + Apple Accelerate"),
                status: "Embedded from the fixed-hash patched source; multilingual base/small models are lazy, length/SHA-256 verified Application Support assets.",
            },
        ],
        sidecars: vec![],
    }
}

fn payload_entries(input: &DiagnosticInput) -> Result<Vec<ArchiveEntry>, String> {
    Ok(vec![
        ArchiveEntry {
            name: README_ENTRY,
            bytes: README.as_bytes().to_vec(),
        },
        json_entry(
            APP_ENTRY,
            &AppRecord {
                schema_version: DIAGNOSTIC_SCHEMA_VERSION,
                product: "GB Plus",
                version: env!("CARGO_PKG_VERSION"),
                tauri_version: "2.11.5",
                rustc_version: option_env!("GROK_BUILD_RUSTC_VERSION")
                    .unwrap_or("Unknown (not captured by this build)"),
                target_os: std::env::consts::OS,
                target_arch: std::env::consts::ARCH,
                build_profile: if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                },
                build_revision: build_revision(),
                build_dirty: build_dirty(),
                frontend_asset_sha256: frontend_asset_sha256(),
                generated_at_unix_ms: input.generated_at_unix_ms,
            },
        )?,
        json_entry(HOST_ENTRY, &host_record())?,
        json_entry(RUNTIME_ENTRY, &runtime_record(input))?,
        json_entry(PROJECTS_ENTRY, &input.projects)?,
        json_entry(SECURITY_ENTRY, &input.security)?,
        json_entry(CAPABILITIES_ENTRY, &input.capabilities)?,
        json_entry(EVENTS_ENTRY, &diagnostic_events_record(input))?,
        json_entry(RELEASE_ENTRY, &release_evidence_record())?,
        json_entry(REDACTION_ENTRY, &redaction_record())?,
    ])
}

fn diagnostic_events_record(input: &DiagnosticInput) -> DiagnosticEventsRecord {
    match &input.events {
        Ok(events) => DiagnosticEventsRecord {
            available: true,
            reason: None,
            // Redact again at the serialization boundary. DiagnosticInput is an
            // internal value that tests and future callers can construct or
            // mutate without going through `capture`; the archive writer is the
            // final shared boundary that must never trust provider metadata.
            events: sanitized_diagnostic_events(events),
        },
        Err(_) => DiagnosticEventsRecord {
            available: false,
            reason: Some(
                "Recent redacted event metadata is unavailable; internal failure detail was omitted.",
            ),
            events: Vec::new(),
        },
    }
}

fn sanitized_diagnostic_events(events: &[DiagnosticEventMetadata]) -> Vec<DiagnosticEventMetadata> {
    events
        .iter()
        .cloned()
        .map(|mut event| {
            event.unsupported_provider =
                event
                    .unsupported_provider
                    .as_deref()
                    .map(|provider| match provider {
                        "GrokCliAcp" => "GrokCliAcp".into(),
                        "XaiKeychain" => "XaiKeychain".into(),
                        _ => "provider".into(),
                    });
            event.unsupported_discriminator = event
                .unsupported_discriminator
                .as_deref()
                .and_then(provider_metadata_identity);
            event
        })
        .collect()
}

fn write_archive_entries(
    entries: &[ArchiveEntry],
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let cursor = Cursor::new(Vec::with_capacity(64 * 1024));
    let mut writer = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(ZIP_ENTRY_MODE);
    for entry in entries {
        writer.start_file(entry.name, options).map_err(|error| {
            format!("cannot start diagnostic ZIP entry {}: {error}", entry.name)
        })?;
        writer.write_all(&entry.bytes).map_err(|error| {
            format!("cannot write diagnostic ZIP entry {}: {error}", entry.name)
        })?;
    }
    writer
        .start_file(MANIFEST_ENTRY, options)
        .map_err(|error| format!("cannot start diagnostic ZIP manifest: {error}"))?;
    writer
        .write_all(manifest_bytes)
        .map_err(|error| format!("cannot write diagnostic ZIP manifest: {error}"))?;
    Ok(writer
        .finish()
        .map_err(|error| format!("cannot finish diagnostic ZIP: {error}"))?
        .into_inner())
}

fn json_entry<T: Serialize>(name: &'static str, value: &T) -> Result<ArchiveEntry, String> {
    let bytes = encode_json(value)?;
    ensure_entry_size(name, &bytes)?;
    Ok(ArchiveEntry { name, bytes })
}

fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("cannot encode diagnostic metadata: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn ensure_entry_size(name: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_ENTRY_BYTES {
        return Err(format!(
            "Diagnostic export refused because {name} exceeded {MAX_ENTRY_BYTES} bytes."
        ));
    }
    Ok(())
}

fn validate_entries(entries: &[ArchiveEntry]) -> Result<(), String> {
    let expected = [
        README_ENTRY,
        APP_ENTRY,
        HOST_ENTRY,
        RUNTIME_ENTRY,
        PROJECTS_ENTRY,
        SECURITY_ENTRY,
        CAPABILITIES_ENTRY,
        EVENTS_ENTRY,
        RELEASE_ENTRY,
        REDACTION_ENTRY,
    ];
    if entries.len() != expected.len()
        || entries
            .iter()
            .zip(expected)
            .any(|(entry, expected)| entry.name != expected)
    {
        return Err("Diagnostic export refused an unexpected archive-entry set.".into());
    }
    for entry in entries {
        ensure_entry_size(entry.name, &entry.bytes)?;
        reject_secret_shapes(&entry.bytes)?;
    }
    Ok(())
}

fn reject_secret_shapes(bytes: &[u8]) -> Result<(), String> {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for marker in [
        "xai_api_key=",
        "authorization: bearer ",
        "\"api_key\":",
        "\"apikey\":",
        "\"access_token\":",
        "\"refresh_token\":",
    ] {
        if lower.contains(marker) {
            return Err(
                "Diagnostic export refused metadata matching a credential-bearing shape.".into(),
            );
        }
    }
    Ok(())
}

fn validate_finished_archive(
    bytes: &[u8],
    entries: &[ArchiveEntry],
    manifest: &[u8],
) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("cannot validate finished diagnostic ZIP: {error}"))?;
    if archive.len() != entries.len() + 1 {
        return Err("Finished diagnostic ZIP has an unexpected entry count.".into());
    }
    for expected in entries
        .iter()
        .map(|entry| (entry.name, entry.bytes.as_slice()))
        .chain(std::iter::once((MANIFEST_ENTRY, manifest)))
    {
        let mut file = archive.by_name(expected.0).map_err(|error| {
            format!("finished diagnostic ZIP is missing {}: {error}", expected.0)
        })?;
        if !file.is_file() || file.name() != expected.0 || file.size() > MAX_ENTRY_BYTES as u64 {
            return Err(format!(
                "Finished diagnostic ZIP entry {} violated its fixed boundary.",
                expected.0
            ));
        }
        let mut actual = Vec::with_capacity(expected.1.len());
        file.read_to_end(&mut actual).map_err(|error| {
            format!(
                "cannot re-read diagnostic ZIP entry {}: {error}",
                expected.0
            )
        })?;
        if actual != expected.1 {
            return Err(format!(
                "Finished diagnostic ZIP entry {} did not round-trip exactly.",
                expected.0
            ));
        }
    }
    Ok(())
}

fn validate_destination(destination: &Path) -> Result<PathBuf, String> {
    if !destination.is_absolute() {
        return Err("Diagnostic export requires an absolute destination path.".into());
    }
    if destination.extension().and_then(|value| value.to_str()) != Some("zip") {
        return Err("Diagnostic export filename must end in .zip.".into());
    }
    let name = destination
        .file_name()
        .ok_or_else(|| "Diagnostic export destination has no filename.".to_owned())?;
    let parent = destination
        .parent()
        .ok_or_else(|| "Diagnostic export destination has no parent folder.".to_owned())?;
    let parent = parent
        .canonicalize()
        .map_err(|error| format!("cannot resolve diagnostic export folder: {error}"))?;
    if !parent.is_dir() {
        return Err("Diagnostic export destination parent is not a folder.".into());
    }
    let destination = parent.join(name);
    if destination.exists() {
        return Err(
            "Diagnostic export refused to overwrite an existing file; choose another name.".into(),
        );
    }
    Ok(destination)
}

fn create_temporary_archive(destination: &Path, bytes: &[u8]) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "Diagnostic export destination has no parent folder.".to_owned())?;
    let base = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "Diagnostic export filename is not valid UTF-8.".to_owned())?;
    for attempt in 0_u8..16 {
        let temporary = parent.join(format!(
            ".{base}.grok-build-{}-{}-{attempt}.tmp",
            std::process::id(),
            unix_time_millis()
        ));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create owner-only diagnostic temporary file: {error}"
                ));
            }
        };
        restrict_owner_only(&file)?;
        if let Err(error) = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
        {
            let _ = fs::remove_file(&temporary);
            return Err(format!("cannot durably write diagnostic archive: {error}"));
        }
        return Ok(temporary);
    }
    Err("Diagnostic export could not allocate a unique temporary filename.".into())
}

fn promote_without_overwrite(temporary: &Path, destination: &Path) -> Result<(), String> {
    fs::hard_link(temporary, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            "Diagnostic export refused a destination that appeared during export.".to_owned()
        } else {
            format!("cannot atomically promote diagnostic archive: {error}")
        }
    })?;
    let parent = destination
        .parent()
        .ok_or_else(|| "Diagnostic export destination has no parent folder.".to_owned())?;
    if let Err(error) = sync_directory(parent) {
        let _ = fs::remove_file(destination);
        return Err(format!(
            "cannot sync diagnostic export folder after promotion: {error}"
        ));
    }
    if let Err(error) = fs::remove_file(temporary) {
        return Err(format!(
            "Diagnostic archive was exported, but its hidden temporary hard link could not be removed: {error}"
        ));
    }
    sync_directory(parent)
        .map_err(|error| format!("cannot sync diagnostic export folder after cleanup: {error}"))
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn restrict_owner_only(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot restrict diagnostic archive permissions: {error}"))?;
    }
    let _ = file;
    Ok(())
}

fn host_record() -> HostRecord {
    let values = run_bounded_command(Path::new("/usr/bin/sw_vers"), &[], 4 * 1024)
        .map(|output| parse_sw_vers(&output))
        .unwrap_or_default();
    HostRecord {
        supported_platform: "macOS 15 on Apple Silicon",
        runtime_os: std::env::consts::OS,
        runtime_arch: std::env::consts::ARCH,
        product_name: values.0,
        product_version: values.1,
        build_version: values.2,
    }
}

fn parse_sw_vers(output: &str) -> (Option<String>, Option<String>, Option<String>) {
    let read = |key: &str| {
        output.lines().find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            (candidate.trim() == key)
                .then(|| bounded_plain_text(value.trim(), 128))
                .flatten()
        })
    };
    (
        read("ProductName"),
        read("ProductVersion"),
        read("BuildVersion"),
    )
}

fn read_cli_version(path: Option<&Path>) -> ProgramVersion {
    let Some(path) = path.and_then(|path| path.canonicalize().ok()) else {
        return ProgramVersion {
            available: false,
            version: None,
            status: "Grok CLI was not available when the snapshot was captured.",
        };
    };
    let version = run_bounded_command(&path, &["--version"], 512).and_then(|output| {
        output
            .lines()
            .find_map(|line| bounded_plain_text(line.trim(), 256))
    });
    ProgramVersion {
        available: true,
        status: if version.is_some() {
            "Version read with fixed argv and an empty child environment."
        } else {
            "CLI exists, but its bounded version query failed or timed out."
        },
        version,
    }
}

fn release_evidence_record() -> ReleaseEvidenceRecord {
    let receipt =
        release_receipt_path().and_then(|path| read_validated_release_receipt(&path).ok());
    ReleaseEvidenceRecord {
        available: receipt.is_some(),
        reason: receipt.is_none().then_some(
            "No valid machine-readable bundled release receipt was available; no result was inferred.",
        ),
        receipt,
    }
}

fn release_receipt_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let macos = executable.parent()?;
    if macos.file_name().and_then(|name| name.to_str()) != Some("MacOS") {
        return None;
    }
    let contents = macos.parent()?;
    if contents.file_name().and_then(|name| name.to_str()) != Some("Contents") {
        return None;
    }
    Some(contents.join("Resources").join(RELEASE_RECEIPT_FILE))
}

fn read_validated_release_receipt(path: &Path) -> Result<ReleaseReceipt, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "The bundled release receipt is unavailable.".to_owned())?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RELEASE_RECEIPT_BYTES
    {
        return Err("The bundled release receipt violated its file boundary.".into());
    }
    let bytes =
        fs::read(path).map_err(|_| "The bundled release receipt is unreadable.".to_owned())?;
    let receipt: ReleaseReceipt = serde_json::from_slice(&bytes)
        .map_err(|_| "The bundled release receipt schema is invalid.".to_owned())?;
    validate_release_receipt(receipt)
}

fn validate_release_receipt(receipt: ReleaseReceipt) -> Result<ReleaseReceipt, String> {
    let timestamp_valid = !receipt.generated_at_utc.is_empty()
        && receipt.generated_at_utc.len() <= 32
        && receipt
            .generated_at_utc
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"-:TZ".contains(&byte));
    let revision_valid = receipt.build_revision.len() == 40
        && receipt
            .build_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    let hash_valid = receipt.raw_binary_sha256.len() == 64
        && receipt
            .raw_binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    let signature_valid = match receipt.signature_posture.as_str() {
        "ad-hoc" => receipt.signing_identity == "adhoc",
        "local-self-signed" => {
            receipt.signing_identity.len() == 40
                && receipt
                    .signing_identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
        }
        _ => false,
    };
    let broker_hashes_valid = [
        &receipt.keychain_broker_sha256,
        &receipt.keychain_broker_requirement_sha256,
    ]
    .iter()
    .all(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && receipt.keychain_broker_cd_hash.len() == 40
        && receipt
            .keychain_broker_cd_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    let linux_hashes_valid = [
        &receipt.linux_command_security_payload_sha256,
        &receipt.linux_command_security_helper_sha256,
        &receipt.bubblewrap_corresponding_source_manifest_sha256,
    ]
    .iter()
    .all(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let fixed_values_valid = mcp_receipt_valid(&receipt)
        && receipt.raw_version_check == "passed"
        && receipt.raw_smoke == "passed"
        && receipt.minimum_macos == "15.0"
        && receipt.architecture == "arm64"
        && signature_valid
        && receipt.keychain_broker_protocol_version == 1
        && receipt.keychain_broker_account_version == 3
        && receipt.keychain_broker_identifier == "com.grokbuild.plus.credential-broker"
        && receipt.keychain_broker_execution == "launchd-one-shot-private-unix-peer-validated"
        && broker_hashes_valid
        && receipt.linux_command_security_payload_bytes <= 5_000_000
        && receipt.linux_command_security_payload_bytes > 0
        && receipt.linux_command_security_helper_bytes <= 128 * 1_024 * 1_024
        && receipt.linux_command_security_helper_bytes > 0
        && linux_hashes_valid
        && receipt.bubblewrap_corresponding_source_manifest_sha256
            == "d3efdf2d152b249ac31e8f2599dcfd43eb9bdc05008c2bfa78e94907cc31d50a";
    if timestamp_valid && revision_valid && hash_valid && fixed_values_valid {
        Ok(receipt)
    } else {
        Err("The bundled release receipt failed fixed-value validation.".into())
    }
}

fn mcp_receipt_valid(receipt: &ReleaseReceipt) -> bool {
    match receipt.schema_version {
        6 => {
            receipt.mcp_broker_identifier.is_none()
                && receipt.mcp_broker_sha256.is_none()
                && receipt.mcp_broker_cd_hash.is_none()
        }
        7 => {
            receipt.mcp_broker_identifier.as_deref()
                == Some(grok_build_keychain_broker::MCP_BROKER_CODE_IDENTIFIER)
                && [
                    (receipt.mcp_broker_sha256.as_ref(), 64),
                    (receipt.mcp_broker_cd_hash.as_ref(), 40),
                ]
                .iter()
                .all(|(hash, length)| {
                    hash.is_some_and(|s| {
                        s.len() == *length && s.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                })
        }
        _ => false,
    }
}

fn run_bounded_command(program: &Path, args: &[&str], maximum: usize) -> Option<String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    ChildEnvironmentProfile::Diagnostics.apply(&mut command);
    let mut child = command.spawn().ok()?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().ok()?;
                if !status.success() || output.stdout.len() > maximum {
                    return None;
                }
                return String::from_utf8(output.stdout).ok();
            }
            Ok(None) if started.elapsed() < VERSION_COMMAND_TIMEOUT => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn capability_records() -> Vec<CapabilityRecord> {
    vec![
        CapabilityRecord {
            capability: "Interactive Terminal".into(),
            state: "Available".into(),
            available: true,
            detail: "Direct user shell; explicitly not contained; output is not persisted in diagnostics.".into(),
        },
        CapabilityRecord {
            capability: "Browser".into(),
            state: "Off".into(),
            available: false,
            detail: "Exact runtime not observed by this diagnostic snapshot.".into(),
        },
        CapabilityRecord {
            capability: "Capture".into(),
            state: "Off".into(),
            available: false,
            detail: "macOS Screen Recording state not observed by this diagnostic snapshot.".into(),
        },
        CapabilityRecord {
            capability: "Desktop Control".into(),
            state: "Off".into(),
            available: false,
            detail: "macOS Accessibility and grant state not observed by this diagnostic fixture; target and input content are omitted.".into(),
        },
        CapabilityRecord {
            capability: "Voice".into(),
            state: "Off".into(),
            available: true,
            detail: "Local whisper.cpp runtime is available. Off means no recording is active; permission/model/transcript/audio content is omitted.".into(),
        },
    ]
}

fn bounded_capability_text(value: &str) -> String {
    const MAX_BYTES: usize = 512;
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    if value.len() <= MAX_BYTES {
        return value;
    }
    let mut end = MAX_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn redaction_record() -> RedactionRecord {
    RedactionRecord {
        policy: "default-safe-v1",
        included_categories: vec![
            "application and host identity",
            "selected transport state without failure payloads",
            "project and managed-worktree paths",
            "command-security state",
            "high-power capability state",
        ],
        omitted_categories: vec![
            "credential material",
            "process variables and provider headers",
            "conversation content",
            "command streams",
            "browser profiles and cookies",
            "captures and audio",
            "workspace file contents",
        ],
    }
}

fn hashed_provider_identifier(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 4_096 {
        return None;
    }
    Some(format!(
        "provider_value_sha256:{}",
        worktree_recovery_digest(value.as_bytes())
    ))
}

fn provider_metadata_identity(value: &str) -> Option<String> {
    if let Some(digest) = value.strip_prefix("provider_value_sha256:")
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Some(value.to_owned());
    }
    hashed_provider_identifier(value)
}

fn bounded_plain_text(value: &str, maximum: usize) -> Option<String> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_control)
        || reject_secret_shapes(value.as_bytes()).is_err()
    {
        return None;
    }
    Some(value.to_owned())
}

fn build_revision() -> Option<&'static str> {
    option_env!("GROK_BUILD_REVISION")
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn build_dirty() -> Option<bool> {
    match option_env!("GROK_BUILD_DIRTY") {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)] // Explicit, reviewable closed asset manifest.
fn frontend_asset_sha256() -> String {
    let assets: &[(&str, &[u8])] = &[
        ("app.js", include_bytes!("../ui/app.js")),
        ("index.html", include_bytes!("../ui/index.html")),
        ("styles.css", include_bytes!("../ui/styles.css")),
        (
            "styles/account.css",
            include_bytes!("../ui/styles/account.css"),
        ),
        (
            "styles/terminal.css",
            include_bytes!("../ui/styles/terminal.css"),
        ),
        (
            "styles/activity.css",
            include_bytes!("../ui/styles/activity.css"),
        ),
        (
            "styles/workspace.css",
            include_bytes!("../ui/styles/workspace.css"),
        ),
        (
            "styles/browser.css",
            include_bytes!("../ui/styles/browser.css"),
        ),
        (
            "modules/browser.js",
            include_bytes!("../ui/modules/browser.js"),
        ),
        (
            "modules/capture.js",
            include_bytes!("../ui/modules/capture.js"),
        ),
        (
            "modules/desktop.js",
            include_bytes!("../ui/modules/desktop.js"),
        ),
        ("modules/voice.js", include_bytes!("../ui/modules/voice.js")),
        (
            "modules/read_aloud.js",
            include_bytes!("../ui/modules/read_aloud.js"),
        ),
        (
            "modules/diagnostics.js",
            include_bytes!("../ui/modules/diagnostics.js"),
        ),
        ("modules/dom.js", include_bytes!("../ui/modules/dom.js")),
        (
            "modules/git_review.js",
            include_bytes!("../ui/modules/git_review.js"),
        ),
        (
            "modules/presentation.js",
            include_bytes!("../ui/modules/presentation.js"),
        ),
        (
            "modules/terminal.js",
            include_bytes!("../ui/modules/terminal.js"),
        ),
        ("modules/queue.js", include_bytes!("../ui/modules/queue.js")),
        (
            "modules/timeline.js",
            include_bytes!("../ui/modules/timeline.js"),
        ),
        ("modules/usage.js", include_bytes!("../ui/modules/usage.js")),
        (
            "modules/projects.js",
            include_bytes!("../ui/modules/projects.js"),
        ),
        (
            "modules/review.js",
            include_bytes!("../ui/modules/review.js"),
        ),
        (
            "modules/workspace.js",
            include_bytes!("../ui/modules/workspace.js"),
        ),
        (
            "modules/worktrees.js",
            include_bytes!("../ui/modules/worktrees.js"),
        ),
        (
            "vendor/xterm/xterm.mjs",
            include_bytes!("../ui/vendor/xterm/xterm.mjs"),
        ),
        (
            "vendor/xterm/xterm.css",
            include_bytes!("../ui/vendor/xterm/xterm.css"),
        ),
        (
            "vendor/xterm/addon-fit.mjs",
            include_bytes!("../ui/vendor/xterm/addon-fit.mjs"),
        ),
        (
            "vendor/xterm/LICENSE.xterm",
            include_bytes!("../ui/vendor/xterm/LICENSE.xterm"),
        ),
        (
            "vendor/xterm/LICENSE.addon-fit",
            include_bytes!("../ui/vendor/xterm/LICENSE.addon-fit"),
        ),
    ];
    let total = assets
        .iter()
        .map(|(name, bytes)| name.len() + 1 + bytes.len())
        .sum();
    let mut identity = Vec::with_capacity(total);
    for (name, bytes) in assets {
        identity.extend_from_slice(name.as_bytes());
        identity.push(0);
        identity.extend_from_slice(bytes);
    }
    worktree_recovery_digest(&identity)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Read as _};

    use grok_build_plus_host::{PlusKnownProject, PlusManagedWorktree, PlusProjectBook};

    use super::*;
    use crate::runtime::keychain::KeychainMigrationState;
    use crate::runtime::manager::RuntimeSnapshot;
    use crate::runtime::types::{ConnectionState, ReconnectState, RuntimeTransport};

    fn fixture_input(root: &Path) -> DiagnosticInput {
        let source = root.join("source");
        let worktree = root.join("managed-worktree");
        let projects = PlusProjectBook {
            schema_version: 1,
            active_id: Some("project-id".into()),
            projects: vec![PlusKnownProject {
                id: "project-id".into(),
                name: "source".into(),
                root: source,
                active_worktree_id: Some("worktree-id".into()),
                worktrees: vec![PlusManagedWorktree {
                    id: "worktree-id".into(),
                    task: "excluded task text".into(),
                    branch: "excluded-branch".into(),
                    path: worktree,
                    base_commit: "excluded-base".into(),
                    created_at: 1,
                    recovery_manifest: None,
                    recovery_state: None,
                }],
            }],
        };
        DiagnosticInput::capture(
            &projects,
            RuntimeSnapshot {
                engine: crate::runtime::engine::EngineSettings::default(),
                selected_transport: RuntimeTransport::GrokCliAcp,
                connection: ConnectionState::Connected {
                    transport: RuntimeTransport::GrokCliAcp,
                    model: "grok-test".into(),
                    verified_at: 7,
                },
                keychain_presence: KeychainPresence::Present,
                keychain_migration_state: KeychainMigrationState::BrokerV3,
                onboarding_acknowledged: true,
                auto_reconnect_enabled: true,
                reconnect_state: ReconnectState::Active {
                    expires_at_utc_ms: 604_800_007,
                },
                credential_binding_identity: None,
                keychain_broker_sha256: None,
                signing_identity: "adhoc".into(),
                account_preference_issue: None,
                cli_available: false,
                cli_path: None,
            },
            "off",
            "Command security: Off",
            Ok(Vec::new()),
        )
    }

    fn extracted_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("valid diagnostic ZIP");
        let mut entries = Vec::new();
        for index in 0..archive.len() {
            let mut file = archive.by_index(index).expect("diagnostic entry");
            let name = file.name().to_owned();
            let mut body = Vec::new();
            file.read_to_end(&mut body).expect("read diagnostic entry");
            entries.push((name, body));
        }
        entries
    }

    #[test]
    fn archive_has_fixed_manifested_entries_and_round_trips() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-diagnostic-archive-{}",
            std::process::id()
        ));
        let built = build_archive(&fixture_input(&root)).expect("build diagnostic ZIP");
        let entries = extracted_entries(&built.bytes);
        assert_eq!(entries.len(), 11);
        assert_eq!(
            entries.last().map(|entry| entry.0.as_str()),
            Some(MANIFEST_ENTRY)
        );
        let manifest: serde_json::Value = serde_json::from_slice(
            &entries
                .iter()
                .find(|entry| entry.0 == MANIFEST_ENTRY)
                .expect("manifest entry")
                .1,
        )
        .expect("manifest JSON");
        assert_eq!(manifest["entries"].as_array().map(Vec::len), Some(10));
        let events: serde_json::Value = serde_json::from_slice(
            &entries
                .iter()
                .find(|entry| entry.0 == EVENTS_ENTRY)
                .expect("events entry")
                .1,
        )
        .expect("events JSON");
        assert_eq!(events["available"], true);
        assert_eq!(events["events"].as_array().map(Vec::len), Some(0));
        for entry in manifest["entries"].as_array().expect("manifest entries") {
            let name = entry["name"].as_str().expect("manifest name");
            let body = &entries
                .iter()
                .find(|candidate| candidate.0 == name)
                .expect("manifested body")
                .1;
            assert_eq!(entry["uncompressedBytes"], body.len());
            assert_eq!(entry["sha256"], worktree_recovery_digest(body));
        }
    }

    #[test]
    fn archive_includes_only_redacted_event_metadata() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-diagnostic-events-{}",
            std::process::id()
        ));
        let mut input = fixture_input(&root);
        input.events = Ok(vec![DiagnosticEventMetadata {
            sequence: 7,
            timestamp: "2026-08-22T00:00:00.000Z".into(),
            project_id: Some("project-id".into()),
            session_id: Some("session-id".into()),
            run_id: Some("run-id".into()),
            kind: crate::contracts::AppEventKind::Error,
            payload_type: "error_or_unsupported".into(),
            unsupported_provider: Some("GrokCliAcp".into()),
            unsupported_discriminator: Some("future_provider_variant".into()),
        }]);
        let built = build_archive(&input).expect("build event diagnostic ZIP");
        let events = extracted_entries(&built.bytes)
            .into_iter()
            .find(|entry| entry.0 == EVENTS_ENTRY)
            .expect("events entry")
            .1;
        let events = String::from_utf8(events).expect("events UTF-8");
        assert!(!events.contains("future_provider_variant"));
        assert!(events.contains("provider_value_sha256:"));
        assert!(!events.contains("prompt"));
        assert!(!events.contains("detail"));
        let archive_text = built
            .bytes
            .windows("grok-test".len())
            .any(|window| window == b"grok-test");
        assert!(
            !archive_text,
            "provider model id must be hashed in diagnostics"
        );
    }

    #[test]
    fn sensitive_source_sentinels_are_absent_from_every_entry() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-diagnostic-secrets-{}-{}",
            std::process::id(),
            unix_time_millis()
        ));
        let workspace = root.join("source");
        let state_root = root.join("state");
        fs::create_dir_all(workspace.join("browser-profile")).expect("create sensitive fixture");
        let sentinels = [
            "KEYCHAIN_SENTINEL_7f4d98",
            "ENV_SENTINEL_33c5aa",
            "PROVIDER_HEADER_SENTINEL_b7441f",
            "TRANSCRIPT_SENTINEL_59a3e1",
            "COMMAND_STREAM_SENTINEL_dbd282",
            "BROWSER_COOKIE_SENTINEL_1f3f30",
            "CAPTURE_SENTINEL_4260fe",
            "VOICE_AUDIO_SENTINEL_8c3a20",
            "WORKSPACE_CONTENT_SENTINEL_951df8",
        ];
        fs::write(workspace.join("workspace-secret.txt"), sentinels[8])
            .expect("write workspace sentinel");
        fs::write(workspace.join("browser-profile/cookies.json"), sentinels[5])
            .expect("write browser sentinel");
        fs::create_dir_all(&state_root).expect("create state fixture");
        for (name, sentinel) in [
            ("keychain-test-fixture", sentinels[0]),
            ("environment-test-fixture", sentinels[1]),
            ("provider-headers-test-fixture", sentinels[2]),
            ("capture-test-fixture", sentinels[6]),
            ("voice-test-fixture", sentinels[7]),
        ] {
            fs::write(state_root.join(name), sentinel).expect("write excluded-state sentinel");
        }
        let mut backend = crate::backend::Backend::new(
            grok_build_plus_host::PlusSessionStore::from_state_root(&state_root),
        );
        backend
            .bind_project(&workspace.display().to_string())
            .expect("bind sensitive workspace");
        backend.chat = sentinels[3].into();
        backend.command_outcome = sentinels[4].into();
        let input = backend.diagnostic_input();
        let built = build_archive(&input).expect("build diagnostic ZIP");
        let extracted = extracted_entries(&built.bytes);
        for sentinel in sentinels {
            assert!(
                !built
                    .bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes()),
                "raw archive exposed {sentinel}"
            );
            assert!(
                extracted.iter().all(|(_, body)| !body
                    .windows(sentinel.len())
                    .any(|window| window == sentinel.as_bytes())),
                "extracted archive exposed {sentinel}"
            );
        }
        fs::remove_dir_all(root).expect("remove sensitive fixture");
    }

    #[test]
    fn export_is_owner_only_no_clobber_and_leaves_no_temporary_file() {
        let root = std::env::temp_dir().join(format!(
            "grok-build-diagnostic-export-{}-{}",
            std::process::id(),
            unix_time_millis()
        ));
        fs::create_dir_all(&root).expect("create export root");
        let destination = root.join("diagnostic.zip");
        let view = export_diagnostic_zip(&fixture_input(&root), &destination)
            .expect("export diagnostic ZIP");
        let canonical_destination = root
            .canonicalize()
            .expect("canonical export root")
            .join("diagnostic.zip");
        assert_eq!(view.path, canonical_destination.display().to_string());
        assert!(canonical_destination.is_file());
        assert_eq!(
            fs::read_dir(&root)
                .expect("read export root")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&canonical_destination)
                    .expect("diagnostic metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let before = fs::read(&canonical_destination).expect("read first export");
        let refusal = export_diagnostic_zip(&fixture_input(&root), &destination)
            .expect_err("existing diagnostic must refuse");
        assert!(refusal.contains("refused to overwrite"));
        assert_eq!(
            fs::read(&canonical_destination).expect("read after refusal"),
            before
        );
        fs::remove_dir_all(root).expect("remove export fixture");
    }

    #[test]
    fn credential_shapes_are_rejected_before_compression() {
        assert!(reject_secret_shapes(b"XAI_API_KEY=secret").is_err());
        assert!(reject_secret_shapes(b"Authorization: Bearer secret").is_err());
        assert!(reject_secret_shapes(br#"{"access_token":"secret"}"#).is_err());
    }

    #[test]
    fn failed_connection_omits_provider_failure_payload() {
        let projects = PlusProjectBook::default();
        let secret = "FAILURE_BODY_SENTINEL_61ad2f";
        let input = DiagnosticInput::capture(
            &projects,
            RuntimeSnapshot {
                engine: crate::runtime::engine::EngineSettings::default(),
                selected_transport: RuntimeTransport::XaiKeychain,
                connection: ConnectionState::Failed {
                    transport: RuntimeTransport::XaiKeychain,
                    reason: secret.into(),
                },
                keychain_presence: KeychainPresence::Present,
                keychain_migration_state: KeychainMigrationState::BrokerV3,
                onboarding_acknowledged: true,
                auto_reconnect_enabled: true,
                reconnect_state: ReconnectState::BindingRequired,
                credential_binding_identity: None,
                keychain_broker_sha256: None,
                signing_identity: "adhoc".into(),
                account_preference_issue: None,
                cli_available: false,
                cli_path: None,
            },
            "needs-attention",
            "Command security: Needs attention",
            Ok(Vec::new()),
        );
        let built = build_archive(&input).expect("build failed-state diagnostic ZIP");
        for (_, body) in extracted_entries(&built.bytes) {
            assert!(
                !body
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }

    #[test]
    fn release_receipt_requires_the_closed_public_pass_schema() {
        let valid = format!(
            r#"{{
  "schemaVersion": 6,
  "generatedAtUtc": "2026-08-22T03:43:04Z",
  "buildRevision": "{}",
  "buildDirty": true,
  "rawBinarySha256": "{}",
  "rawVersionCheck": "passed",
  "rawSmoke": "passed",
  "minimumMacos": "15.0",
  "architecture": "arm64",
  "signaturePosture": "ad-hoc",
  "signingIdentity": "adhoc",
  "keychainBrokerProtocolVersion": 1,
  "keychainBrokerAccountVersion": 3,
  "keychainBrokerIdentifier": "com.grokbuild.plus.credential-broker",
  "keychainBrokerSha256": "{}",
  "keychainBrokerCdHash": "{}",
  "keychainBrokerExecution": "launchd-one-shot-private-unix-peer-validated",
  "keychainBrokerRequirementSha256": "{}",
  "linuxCommandSecurityPayloadBytes": 4302312,
  "linuxCommandSecurityPayloadSha256": "{}",
  "linuxCommandSecurityHelperBytes": 9387256,
  "linuxCommandSecurityHelperSha256": "{}",
  "bubblewrapCorrespondingSourceManifestSha256": "{}"
}}"#,
            "a".repeat(40),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(40),
            "e".repeat(64),
            "f".repeat(64),
            "a".repeat(64),
            "d3efdf2d152b249ac31e8f2599dcfd43eb9bdc05008c2bfa78e94907cc31d50a"
        );
        let receipt: ReleaseReceipt = serde_json::from_str(&valid).expect("valid receipt schema");
        assert!(validate_release_receipt(receipt).is_ok());

        let local = valid
            .replace(
                "\"signaturePosture\": \"ad-hoc\"",
                "\"signaturePosture\": \"local-self-signed\"",
            )
            .replace(
                "\"signingIdentity\": \"adhoc\"",
                &format!("\"signingIdentity\": \"{}\"", "C".repeat(40)),
            );
        let receipt: ReleaseReceipt =
            serde_json::from_str(&local).expect("valid local receipt schema");
        assert!(validate_release_receipt(receipt).is_ok());

        let mut v7: serde_json::Value = serde_json::from_str(&valid).unwrap();
        v7["schemaVersion"] = serde_json::json!(7);
        let incomplete: ReleaseReceipt = serde_json::from_value(v7.clone()).unwrap();
        assert!(validate_release_receipt(incomplete).is_err());
        v7["mcpBrokerIdentifier"] =
            serde_json::json!(grok_build_keychain_broker::MCP_BROKER_CODE_IDENTIFIER);
        v7["mcpBrokerSha256"] = serde_json::json!("c".repeat(64));
        v7["mcpBrokerCdHash"] = serde_json::json!("d".repeat(40));
        assert!(validate_release_receipt(serde_json::from_value(v7.clone()).unwrap()).is_ok());
        v7["mcpBrokerIdentifier"] =
            serde_json::json!(grok_build_keychain_broker::BROKER_CODE_IDENTIFIER);
        assert!(validate_release_receipt(serde_json::from_value(v7.clone()).unwrap()).is_err());
        v7["schemaVersion"] = serde_json::json!(6);
        assert!(validate_release_receipt(serde_json::from_value(v7).unwrap()).is_err());

        let unexpected = valid.replacen(
            "\"schemaVersion\": 6,",
            "\"schemaVersion\": 6,\n  \"rawOutput\": \"must-not-enter\",",
            1,
        );
        assert!(serde_json::from_str::<ReleaseReceipt>(&unexpected).is_err());
        let false_pass = valid.replacen("\"rawSmoke\": \"passed\"", "\"rawSmoke\": \"failed\"", 1);
        let receipt: ReleaseReceipt =
            serde_json::from_str(&false_pass).expect("closed receipt shape");
        assert!(validate_release_receipt(receipt).is_err());
    }
}
