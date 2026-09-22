//! Safe-wrapper Chrome launcher for POSIX CDP descriptors 3 and 4.

use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use nix::unistd::{dup2, execve, setsid};
use sha2::{Digest as _, Sha256};

const CHROME_EXECUTABLE_NAME: &str = "Google Chrome for Testing";
const CHROME_EXECUTABLE_BYTES: u64 = 52_112;
const CHROME_EXECUTABLE_SHA256: &str =
    "e100ea3a3fc9d4dc4433e1f250a2394c894c88355f7d5210b5e57250f08adc15";
const RUNTIME_MARKER: &str = "chrome-for-testing-152.0.7977.54";
const PROFILE_MARKER: &str = "browser-profiles";
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrowserLaunchMode {
    InApp,
    Headed,
}

impl BrowserLaunchMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InApp => "in_app",
            Self::Headed => "headed",
        }
    }

    fn parse(value: &OsStr) -> Result<Self, String> {
        if value == "in_app" {
            Ok(Self::InApp)
        } else if value == "headed" {
            Ok(Self::Headed)
        } else {
            Err("Internal Browser launcher refused an unknown mode.".into())
        }
    }
}

/// Internal signed-binary mode used only by the app Browser runtime to establish
/// Chrome's hard-coded fd 3/4 CDP pipe contract.
///
/// # Errors
///
/// Returns an exact refusal when the internal arguments, executable/profile
/// identity, pipe setup, or Chrome process lifecycle fails validation.
pub fn run_chrome_pipe_launcher(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    let executable = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "Internal Browser launcher is missing the Chrome path.".to_owned())?;
    let profile = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "Internal Browser launcher is missing the profile path.".to_owned())?;
    let mode = arguments
        .next()
        .as_deref()
        .map(BrowserLaunchMode::parse)
        .transpose()?
        .ok_or_else(|| "Internal Browser launcher is missing the launch mode.".to_owned())?;
    if arguments.next().is_some() {
        return Err("Internal Browser launcher refused unexpected arguments.".into());
    }
    let executable = validate_chrome_executable(&executable)?;
    let profile = validate_profile(&profile)?;
    let temporary = profile.join("tmp");
    ensure_private_directory(&temporary)?;

    let session = setsid().map_err(|error| {
        format!("Browser launcher could not create an isolated process group: {error}")
    })?;
    if u32::try_from(session.as_raw()).ok() != Some(std::process::id()) {
        return Err("Browser launcher process-group identity did not match its PID.".into());
    }
    dup2(0, 3).map_err(|error| format!("Browser launcher could not map CDP read fd 3: {error}"))?;
    dup2(1, 4)
        .map_err(|error| format!("Browser launcher could not map CDP write fd 4: {error}"))?;

    let null_input = File::open("/dev/null")
        .map_err(|error| format!("Browser launcher cannot open null input: {error}"))?;
    let null_output = OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .map_err(|error| format!("Browser launcher cannot open null output: {error}"))?;
    dup2(null_input.as_raw_fd(), 0)
        .map_err(|error| format!("Browser launcher cannot isolate Chrome stdin: {error}"))?;
    dup2(null_output.as_raw_fd(), 1)
        .map_err(|error| format!("Browser launcher cannot isolate Chrome stdout: {error}"))?;

    let executable_c = c_string(executable.as_os_str(), "Chrome executable")?;
    let mut argv = Vec::new();
    argv.push(executable_c.clone());
    for argument in chrome_arguments(&profile, mode) {
        argv.push(c_string(&argument, "Chrome argument")?);
    }
    let environment = [
        c_string(
            OsString::from(format!("HOME={}", profile.display())).as_os_str(),
            "Chrome HOME",
        )?,
        c_string(
            OsString::from(format!("TMPDIR={}", temporary.display())).as_os_str(),
            "Chrome TMPDIR",
        )?,
        CString::new("PATH=/usr/bin:/bin").map_err(|_| "Chrome PATH contains NUL.".to_owned())?,
        CString::new("LANG=en_US.UTF-8").map_err(|_| "Chrome LANG contains NUL.".to_owned())?,
        CString::new("LC_CTYPE=UTF-8").map_err(|_| "Chrome LC_CTYPE contains NUL.".to_owned())?,
    ];
    match execve(&executable_c, &argv, &environment) {
        Ok(never) => match never {},
        Err(error) => Err(format!("Verified Chrome execve failed closed: {error}")),
    }
}

fn c_string(value: &OsStr, label: &str) -> Result<CString, String> {
    CString::new(value.as_bytes()).map_err(|_| format!("{label} contains a NUL byte."))
}

fn chrome_arguments(profile: &Path, mode: BrowserLaunchMode) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("--remote-debugging-pipe"),
        OsString::from(format!("--user-data-dir={}", profile.display())),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from("--disable-background-networking"),
        OsString::from("--disable-component-update"),
        OsString::from("--disable-domain-reliability"),
        OsString::from("--disable-sync"),
        OsString::from("--disable-default-apps"),
        OsString::from("--disable-client-side-phishing-detection"),
        OsString::from("--disable-breakpad"),
        OsString::from("--disable-crash-reporter"),
        OsString::from("--disable-extensions"),
        OsString::from("--disable-search-engine-choice-screen"),
        // Chrome for Testing must not reach the user's login Keychain. Chromium
        // documents this switch for macOS automation specifically to prevent a
        // Keychain modal from blocking the browser and its Network Service.
        OsString::from("--use-mock-keychain"),
        OsString::from("--disable-features=DialMediaRouteProvider"),
        OsString::from("--metrics-recording-only"),
        OsString::from("--no-pings"),
        OsString::from("--enable-automation"),
        OsString::from("--window-size=1280,800"),
    ];
    if mode == BrowserLaunchMode::InApp {
        arguments.push(OsString::from("--headless=new"));
    } else {
        arguments.push(OsString::from("--new-window"));
    }
    arguments.push(OsString::from("about:blank"));
    arguments
}

fn validate_chrome_executable(path: &Path) -> Result<PathBuf, String> {
    let canonical = validate_absolute_path(path, "Chrome executable")?;
    if canonical.file_name().and_then(OsStr::to_str) != Some(CHROME_EXECUTABLE_NAME)
        || !canonical
            .components()
            .any(|component| component.as_os_str() == RUNTIME_MARKER)
    {
        return Err("Internal Browser launcher refused a non-managed Chrome path.".into());
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("Cannot inspect managed Chrome executable: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != CHROME_EXECUTABLE_BYTES
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("Managed Chrome executable shape changed before launch.".into());
    }
    if hash_file(&canonical)? != CHROME_EXECUTABLE_SHA256 {
        return Err("Managed Chrome executable failed its launch-time SHA-256 check.".into());
    }
    Ok(canonical)
}

fn validate_profile(path: &Path) -> Result<PathBuf, String> {
    let canonical = validate_absolute_path(path, "Browser profile")?;
    let components = canonical.components().collect::<Vec<_>>();
    let Some(marker_index) = components
        .iter()
        .rposition(|component| component.as_os_str() == PROFILE_MARKER)
    else {
        return Err("Internal Browser launcher refused a profile outside its managed root.".into());
    };
    let identity = components
        .get(marker_index + 1)
        .and_then(|component| component.as_os_str().to_str())
        .filter(|identity| {
            identity.len() == 64
                && identity
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| {
            "Internal Browser launcher refused an invalid profile identity.".to_owned()
        })?;
    if marker_index + 2 != components.len() || identity.is_empty() {
        return Err("Internal Browser launcher refused nested profile authority.".into());
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("Cannot inspect managed Browser profile: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Managed Browser profile is not an owner-only regular directory.".into());
    }
    Ok(canonical)
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(format!("{label} path is invalid."));
    }
    fs::canonicalize(path).map_err(|error| format!("Cannot canonicalize {label}: {error}"))
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create Browser launcher directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect Browser launcher directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Browser launcher refused a symlink or non-directory root.".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("Cannot secure Browser launcher directory: {error}"))
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Cannot open managed Chrome executable: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash managed Chrome executable: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(lowercase_hex(&hash.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_arguments_keep_pipe_and_sandbox_without_a_tcp_fallback() {
        let profile = Path::new(
            "/private/tmp/browser-profiles/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let in_app = chrome_arguments(profile, BrowserLaunchMode::InApp);
        let headed = chrome_arguments(profile, BrowserLaunchMode::Headed);
        let joined = in_app
            .iter()
            .chain(headed.iter())
            .map(|value| value.to_string_lossy())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("--remote-debugging-pipe"));
        assert!(joined.contains("--use-mock-keychain"));
        assert!(joined.contains("--disable-features=DialMediaRouteProvider"));
        assert!(!joined.contains("--remote-debugging-port"));
        assert!(!joined.contains("--no-sandbox"));
        assert!(!joined.contains("--disable-site-isolation"));
        assert!(in_app.iter().any(|value| value == "--headless=new"));
        assert!(!headed.iter().any(|value| value == "--headless=new"));
    }

    #[test]
    fn launcher_mode_and_path_shapes_fail_closed() {
        assert_eq!(
            BrowserLaunchMode::parse(OsStr::new("in_app")),
            Ok(BrowserLaunchMode::InApp)
        );
        assert!(BrowserLaunchMode::parse(OsStr::new("other")).is_err());
        assert!(validate_absolute_path(Path::new("relative"), "fixture").is_err());
        assert!(validate_absolute_path(Path::new("/tmp/../escape"), "fixture").is_err());
    }
}
