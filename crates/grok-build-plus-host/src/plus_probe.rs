//! Fixed contained-command readiness probe and explicit invalid control.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use grok_build_core::{CommandSpec, Digest};

/// Selects the default probe or the explicit invalid control.
pub const PLUS_PROBE_COMMAND_ENV: &str = "GROK_BUILD_PLUS_COMMAND";
/// Optional directory for a locally compiled probe.
pub const PLUS_PROBE_DIR_ENV: &str = "GROK_BUILD_PLUS_PROBE_DIR";
/// Exact immutable probe installed with the Linux helper.
pub const PLUS_PREBUILT_PROBE_ENV: &str = "GROK_BUILD_PLUS_PREBUILT_PROBE";
/// Probe file name recorded in command evidence.
pub const PLUS_PLAN_VALID_PROBE_NAME: &str = "plus-contained-probe";
const PLUS_PREBUILT_PROBE_BYTES: u64 = 3_160;
const PLUS_PREBUILT_PROBE_SHA256: &str =
    "d36421faefab9a6acb9c141b5f4400126676eb8ff6c87a5faef8b9aed871178c";
/// Wall time includes containment launch and the probe itself.
pub const PLUS_CONTAINED_WALL_TIME_MS: u64 = 30_000;
/// Sprint budget ceiling enforced by the installed service.
pub const PLUS_CONTAINED_SPRINT_MAX_DURATION_MS: u64 = 120_000;
/// Process ceiling covers the leader and bounded static-probe launch.
pub const PLUS_CONTAINED_MAX_PROCESSES: u32 = 4;
const PLUS_PLAN_VALID_PROBE_SOURCE: &str = "fn main() {}\n";
/// Returns the dynamic target used to prove plan refusal.
#[must_use]
pub fn plus_invalid_dynamic_command() -> CommandSpec {
    CommandSpec {
        program: "/usr/bin/true".into(),
        arguments: vec!["--grok-build-plus".into()],
        working_directory: PathBuf::new(),
    }
}

/// Resolves the shipped probe or explicit invalid control.
///
/// # Errors
/// Returns why the plan-valid probe is unavailable.
pub fn plus_resolve_probe_command() -> Result<CommandSpec, String> {
    match std::env::var(PLUS_PROBE_COMMAND_ENV) {
        Ok(value) if value == "invalid" || value == "dynamic" => Ok(plus_invalid_dynamic_command()),
        _ => plus_plan_valid_probe_command(),
    }
}

/// Resolves an exact prebuilt probe, or builds the local development probe.
///
/// # Errors
/// Returns why no safe executable probe could be resolved.
pub fn plus_plan_valid_probe_command() -> Result<CommandSpec, String> {
    if let Some(path) = std::env::var_os(PLUS_PREBUILT_PROBE_ENV) {
        let path = PathBuf::from(path);
        validate_prebuilt_probe(
            &path,
            PLUS_PREBUILT_PROBE_BYTES,
            PLUS_PREBUILT_PROBE_SHA256,
            cfg!(target_os = "linux"),
        )?;
        return probe_command(&path);
    }
    let directory = plus_probe_artifact_dir()?;
    fs::create_dir_all(&directory).map_err(|error| {
        format!(
            "cannot create probe directory {}: {error}",
            directory.display()
        )
    })?;
    let source = directory.join("plus-contained-probe.rs");
    let binary = directory.join(PLUS_PLAN_VALID_PROBE_NAME);
    let rebuild = fs::read_to_string(&source).unwrap_or_default() != PLUS_PLAN_VALID_PROBE_SOURCE;
    if rebuild {
        fs::write(&source, PLUS_PLAN_VALID_PROBE_SOURCE)
            .map_err(|error| format!("cannot write probe source {}: {error}", source.display()))?;
    }
    if rebuild || !binary.is_file() {
        build_plan_valid_probe(&source, &binary)?;
    }
    lock_probe_mode(&binary)?;
    probe_command(&binary)
}

fn probe_command(binary: &Path) -> Result<CommandSpec, String> {
    let program = binary
        .canonicalize()
        .map_err(|error| format!("plan-valid probe is not a canonical file: {error}"))?;
    let program = program
        .to_str()
        .ok_or_else(|| "plan-valid probe path is not UTF-8".to_owned())?
        .to_owned();
    Ok(CommandSpec {
        program,
        arguments: vec!["--grok-build-plus".into()],
        working_directory: PathBuf::new(),
    })
}

pub(crate) fn validate_prebuilt_probe(
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    require_root: bool,
) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("prebuilt contained probe path must be absolute and canonical".into());
    }
    if path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize prebuilt contained probe: {error}"))?
        != path
    {
        return Err("prebuilt contained probe path must be absolute and canonical".into());
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("cannot open prebuilt contained probe: {error}"))?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect prebuilt contained probe: {error}"))?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err("prebuilt contained probe length changed".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.permissions().mode() & 0o7777 != 0o555 {
            return Err("prebuilt contained probe mode must be 0555".into());
        }
        if require_root && metadata.uid() != 0 {
            return Err("prebuilt contained probe must be owned by root".into());
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read prebuilt contained probe: {error}"))?;
    if Digest::sha256(&bytes).as_str() != expected_sha256 {
        return Err("prebuilt contained probe checksum changed".into());
    }
    Ok(())
}

fn plus_probe_artifact_dir() -> Result<PathBuf, String> {
    if let Some(configured) = std::env::var_os(PLUS_PROBE_DIR_ENV) {
        let path = PathBuf::from(configured);
        if path.is_absolute() {
            return Ok(path);
        }
        return Err("GROK_BUILD_PLUS_PROBE_DIR must be an absolute directory".into());
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join("gbd-plus-linux-target/plus-probe"));
    }
    Ok(std::env::temp_dir().join("grok-build-plus-probe"))
}

fn build_plan_valid_probe(source: &Path, binary: &Path) -> Result<(), String> {
    let mut command = Command::new(resolve_rustc());
    command
        .arg("--edition")
        .arg("2021")
        .arg("-O")
        .arg("--crate-name")
        .arg("plus_contained_probe")
        .arg("-o")
        .arg(binary)
        .arg(source);
    #[cfg(target_os = "linux")]
    command.args([
        "-C",
        "target-feature=+crt-static",
        "-C",
        "relocation-model=static",
    ]);
    let output = command
        .output()
        .map_err(|error| format!("cannot run rustc for the plan-valid plus probe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustc failed to build the plan-valid plus probe: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !binary.is_file() {
        return Err(format!(
            "rustc reported success but produced no probe at {}",
            binary.display()
        ));
    }
    Ok(())
}

fn lock_probe_mode(binary: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(binary, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot lock probe mode {}: {error}", binary.display()))?;
        let mode = fs::metadata(binary)
            .map_err(|error| format!("cannot stat plan-valid probe: {error}"))?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "plan-valid probe has unsafe writable mode {mode:o}"
            ));
        }
        if mode & 0o111 == 0 {
            return Err("plan-valid probe must be executable".into());
        }
    }
    let _ = binary;
    Ok(())
}

fn resolve_rustc() -> PathBuf {
    std::env::var_os("RUSTC")
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".cargo/bin/rustc"))
                .filter(|path| path.is_file())
        })
        .unwrap_or_else(|| PathBuf::from("rustc"))
}

/// True when presented text is a known-good success or `TimedOut` terminal.
#[must_use]
pub fn plus_presentation_is_known_good_terminal(text: &str) -> bool {
    let success = text.contains("Command succeeded")
        || text.contains("Command timed out")
        || text.contains("CommandCompleted")
        || (text.contains("TimedOut") && !text.contains("BeforeEffect"));
    success && !text.contains("Command failed") && !text.contains("FakeProvider")
}

/// True when presented text is a success-class contained probe (Exited 0).
/// `TimedOut` stays known-good via [`plus_presentation_is_known_good_terminal`]
/// but is not success-class.
#[must_use]
pub fn plus_presentation_is_success_class_terminal(text: &str) -> bool {
    text.contains("Command succeeded")
        && !text.contains("Command timed out")
        && !text.contains("Command failed")
        && !text.contains("FakeProvider")
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn freshly_built_development_probe_has_static_linkage() {
    use std::os::unix::fs::DirBuilderExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "gb-plus-probe-linkage-{}-{nonce}",
        std::process::id()
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let source = directory.join("probe.rs");
    let binary = directory.join(PLUS_PLAN_VALID_PROBE_NAME);
    fs::write(&source, PLUS_PLAN_VALID_PROBE_SOURCE).unwrap();
    build_plan_valid_probe(&source, &binary).expect("build a fresh development probe");
    grok_build_runner::measure_static_elf_linkage_v1(&binary)
        .expect("fresh development probe must have static ELF linkage");
    fs::remove_dir_all(directory).unwrap();
}
