//! Exact, user-invoked Colima and Lima installation for Command security.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use grok_build_plus_host::{
    CommandOutcomeClass, PLUS_MANAGED_COLIMA_HOME_RELATIVE, PLUS_MANAGED_COLIMA_RELATIVE,
    PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE, PLUS_MANAGED_LIMACTL_RELATIVE, PlusGuestLifecycle,
    PlusGuestObservation, apply_colima_child_environment, colima_status_running,
    observe_plus_guest, plus_contained_via_colima_ssh_typed, resolve_colima_binary,
    set_managed_container_runtime_verified, start_colima_if_safe,
};
use sha2::{Digest as _, Sha256};

use crate::asset_download::{AssetManager, AssetSpec, ensure_private_directory, sync_directory};

const COLIMA_VERSION: &str = "0.10.3";
const LIMA_VERSION: &str = "2.2.0";
const ALLOWED_HOSTS: &[&str] = &["github.com", "release-assets.githubusercontent.com"];
const COLIMA_ASSET: AssetSpec = AssetSpec {
    id: "colima-0_10_3-mac-arm64",
    filename: "colima-Darwin-arm64-0.10.3",
    url: "https://github.com/abiosoft/colima/releases/download/v0.10.3/colima-Darwin-arm64",
    byte_len: 15_656_320,
    sha256: "980ad8bf61a4ca370243f4cb41401a61276dcd2c2502bee7b9b86f9250169f34",
    allowed_hosts: ALLOWED_HOSTS,
};
const LIMA_ASSET: AssetSpec = AssetSpec {
    id: "lima-2_2_0-mac-arm64",
    filename: "lima-2.2.0-Darwin-arm64.tar.gz",
    url: "https://github.com/lima-vm/lima/releases/download/v2.2.0/lima-2.2.0-Darwin-arm64.tar.gz",
    byte_len: 37_586_365,
    sha256: "bbdef91774885a0d05f7b048c4eb89ae2bcf3a0c252ae7ca7934e63df76d93c3",
    allowed_hosts: ALLOWED_HOSTS,
};
const LIMA_ARCHIVE_ENTRIES: usize = 213;
const LIMA_ARCHIVE_LIST_SHA256: &str =
    "745f3c63a16af6a95e9e2be9b54e1f29987e57ed96e333736bab21c3ae564b4a";
const LIMA_FILES: usize = 137;
const LIMA_DIRECTORIES: usize = 10;
const LIMA_FILE_BYTES: u64 = 80_765_607;
const LIMA_MANIFEST_SHA256: &str =
    "6255eeecd5f90fcfe6824fb0215c54b3a0a2cdb483266c44c8d0ef45b56da098";
const MAX_TAR_OUTPUT: usize = 64 * 1024;
const MAX_RUNTIME_FILE: u64 = 34 * 1024 * 1024;
const SERVICE_PAYLOAD_NAME: &str = "GBPlusCommandSecurityLinuxArm64.tar.gz";
const SERVICE_INSTALL_SCRIPT: &str =
    include_str!("../../../scripts/gb-plus-linux-command-security-install.sh");

#[derive(Clone)]
pub(crate) struct ContainerRuntimeManager {
    root: PathBuf,
    archives: AssetManager,
    installing: Arc<AtomicBool>,
}

impl ContainerRuntimeManager {
    pub(crate) fn new(state_root: &Path) -> Self {
        let root = state_root.join("runtime-assets/command-security");
        let manager = Self {
            archives: AssetManager::new(root.join("archives")),
            root,
            installing: Arc::new(AtomicBool::new(false)),
        };
        set_managed_container_runtime_verified(validate_runtime(&manager.final_root()).is_ok());
        manager
    }

    pub(crate) fn install(&self) -> Result<String, String> {
        if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
            return Err("The Colima helper supports macOS on Apple Silicon only.".into());
        }
        if self.installing.swap(true, Ordering::AcqRel) {
            return Err("The Colima install is already running.".into());
        }
        let result = self.install_inner();
        set_managed_container_runtime_verified(result.is_ok());
        self.installing.store(false, Ordering::Release);
        result
    }

    pub(crate) fn prepare_profile(&self) -> Result<(), String> {
        let final_root = self.final_root();
        match fs::symlink_metadata(&final_root) {
            Ok(_) => {
                if let Err(error) = validate_runtime(&final_root) {
                    set_managed_container_runtime_verified(false);
                    return Err(error);
                }
                set_managed_container_runtime_verified(true);
                let profile = self
                    .root
                    .parent()
                    .and_then(Path::parent)
                    .ok_or_else(|| "The managed runtime root has no state parent.".to_owned())?
                    .join(PLUS_MANAGED_COLIMA_HOME_RELATIVE);
                ensure_private_directory(&profile)?;
                sync_directory(profile.parent().ok_or_else(|| {
                    "The managed Colima profile has no parent directory.".to_owned()
                })?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "Cannot inspect the managed Colima runtime: {error}"
            )),
        }
    }

    pub(crate) fn install_linux_service(&self) -> (Result<String, String>, PlusGuestObservation) {
        let installed = self.install_linux_service_inner();
        let observation = observe_plus_guest();
        let result = installed.and_then(|()| {
            let PlusGuestLifecycle::Ready(target) = &observation.lifecycle else {
                return Err("The installed runner did not become available.".into());
            };
            let probe = plus_contained_via_colima_ssh_typed(target);
            if probe.class != CommandOutcomeClass::Completed {
                return Err(format!(
                    "The contained readiness test failed.\n{}",
                    probe.text
                ));
            }
            Ok("Command security is ready.".into())
        });
        (result, observation)
    }

    fn install_linux_service_inner(&self) -> Result<(), String> {
        self.prepare_profile()?;
        let spec = ServicePayloadSpec::compiled()?;
        let payload = open_service_payload(&spec)?;
        let colima = resolve_colima_binary().ok_or("Colima is unavailable.")?;
        if !colima_status_running(&colima) {
            start_colima_if_safe()?;
        }
        if !colima_status_running(&colima) {
            return Err("Colima did not start.".into());
        }
        let (uid, gid, home) = guest_identity(&colima)?;
        let remote = format!(
            "/tmp/gb-plus-command-security.{}-{}.tar.gz",
            std::process::id(),
            nonce()
        );
        let result = (|| {
            let mut upload = colima_command(&colima);
            upload
                .args(["ssh", "--", "tee"])
                .arg(&remote)
                .stdin(Stdio::from(payload))
                .stdout(Stdio::null());
            checked_output(&mut upload, "payload upload")?;
            let archive_bytes = spec.archive_bytes.to_string();
            let helper_bytes = spec.helper_bytes.to_string();
            let uid = uid.to_string();
            let gid = gid.to_string();
            let mut install = colima_command(&colima);
            install
                .args(["ssh", "--", "sudo", "-n", "sh", "-s", "--"])
                .args([
                    remote.as_str(),
                    &archive_bytes,
                    spec.archive_sha256,
                    &helper_bytes,
                    spec.helper_sha256,
                    &uid,
                    &gid,
                    &home,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = install
                .spawn()
                .map_err(|error| format!("Cannot start the guest installer: {error}"))?;
            child
                .stdin
                .take()
                .ok_or("Guest installer stdin was unavailable.")?
                .write_all(SERVICE_INSTALL_SCRIPT.as_bytes())
                .map_err(|error| format!("Cannot send the guest installer: {error}"))?;
            checked_child(child, "guest installer")
        })();
        let mut cleanup = colima_command(&colima);
        let _ = cleanup
            .args(["ssh", "--", "rm", "-f", "--", &remote])
            .status();
        result?;
        Ok(())
    }

    fn install_inner(&self) -> Result<String, String> {
        ensure_private_directory(&self.root)?;
        let final_root = self.final_root();
        if validate_runtime(&final_root).is_ok() {
            return Ok(format!(
                "Colima {COLIMA_VERSION} and Lima {LIMA_VERSION} are installed and verified."
            ));
        }
        self.archives.install(COLIMA_ASSET, |_, _| {})?;
        self.archives.install(LIMA_ASSET, |_, _| {})?;
        let temporary = self.root.join(format!(
            ".container-runtime-{}-{}",
            std::process::id(),
            nonce()
        ));
        ensure_private_directory(&temporary)?;
        let result = (|| {
            self.copy_colima(&temporary)?;
            validate_lima_archive(self.lima_file()?)?;
            extract_lima(self.lima_file()?, &temporary.join("lima"))?;
            secure_tree(&temporary)?;
            validate_runtime(&temporary)?;
            replace_invalid_runtime(&self.root, &final_root)?;
            fs::rename(&temporary, &final_root).map_err(|error| {
                format!("Cannot promote the verified container runtime: {error}")
            })?;
            sync_directory(&self.root)?;
            Ok(format!(
                "Colima {COLIMA_VERSION} and Lima {LIMA_VERSION} installed and verified. Choose Set up container to continue."
            ))
        })();
        if result.is_err() {
            let _ = remove_temporary(&self.root, &temporary);
        }
        result
    }

    fn copy_colima(&self, temporary: &Path) -> Result<(), String> {
        let mut source = self
            .archives
            .open_verified(COLIMA_ASSET)?
            .ok_or_else(|| "The verified Colima download disappeared before use.".to_owned())?;
        let path = temporary.join(PLUS_MANAGED_COLIMA_RELATIVE);
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .map_err(|error| format!("Cannot create the private Colima executable: {error}"))?;
        std::io::copy(&mut source, &mut target)
            .map_err(|error| format!("Cannot copy the verified Colima executable: {error}"))?;
        target
            .sync_all()
            .map_err(|error| format!("Cannot sync the Colima executable: {error}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot secure the Colima executable: {error}"))
    }

    fn lima_file(&self) -> Result<File, String> {
        self.archives
            .open_verified(LIMA_ASSET)?
            .ok_or_else(|| "The verified Lima download disappeared before use.".to_owned())
    }

    fn final_root(&self) -> PathBuf {
        self.root.join(
            Path::new(PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE)
                .file_name()
                .expect("managed runtime relative path has a final component"),
        )
    }
}

struct ServicePayloadSpec {
    archive_bytes: u64,
    archive_sha256: &'static str,
    helper_bytes: u64,
    helper_sha256: &'static str,
}

impl ServicePayloadSpec {
    fn compiled() -> Result<Self, String> {
        let values = [
            env!("GROK_BUILD_LINUX_PAYLOAD_SHA256"),
            env!("GROK_BUILD_LINUX_HELPER_SHA256"),
        ];
        if values.contains(&"unavailable") {
            return Err("This build has no verified Linux command runner.".into());
        }
        Ok(Self {
            archive_bytes: env!("GROK_BUILD_LINUX_PAYLOAD_BYTES")
                .parse()
                .map_err(|_| "The bundled runner length is invalid.".to_owned())?,
            archive_sha256: values[0],
            helper_bytes: env!("GROK_BUILD_LINUX_HELPER_BYTES")
                .parse()
                .map_err(|_| "The Linux helper length is invalid.".to_owned())?,
            helper_sha256: values[1],
        })
    }
}

fn open_service_payload(spec: &ServicePayloadSpec) -> Result<File, String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("Cannot locate this app: {error}"))?;
    let path = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("This app has no Resources directory.")?
        .join("Resources")
        .join(SERVICE_PAYLOAD_NAME);
    let descriptor = rustix::fs::open(
        &path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| format!("Cannot open the bundled Linux runner: {error}"))?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect the bundled Linux runner: {error}"))?;
    if !metadata.is_file() || metadata.len() != spec.archive_bytes {
        return Err("The bundled Linux runner length changed.".into());
    }
    if hash_reader(&mut file)? != spec.archive_sha256 {
        return Err("The bundled Linux runner checksum changed.".into());
    }
    file.rewind()
        .map_err(|error| format!("Cannot rewind the bundled Linux runner: {error}"))?;
    Ok(file)
}

fn colima_command(colima: &Path) -> Command {
    let mut command = Command::new(colima);
    apply_colima_child_environment(&mut command);
    command
}

fn guest_identity(colima: &Path) -> Result<(u32, u32, String), String> {
    let mut command = colima_command(colima);
    let output = checked_output(
        command.args([
            "ssh",
            "--",
            "sh",
            "-c",
            "printf '%s\\n%s\\n%s\\n' \"$(id -u)\" \"$(id -g)\" \"$HOME\"",
        ]),
        "guest identity",
    )?;
    let mut lines = output.lines();
    let uid = lines.next().and_then(|value| value.parse().ok());
    let gid = lines.next().and_then(|value| value.parse().ok());
    let home = lines.next().filter(|value| value.starts_with('/'));
    match (uid, gid, home, lines.next()) {
        (Some(uid), Some(gid), Some(home), None) if uid != 0 && gid != 0 => {
            Ok((uid, gid, home.to_owned()))
        }
        _ => Err("The Colima user identity was invalid.".into()),
    }
}

fn checked_output(command: &mut Command, label: &str) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("Cannot start {label}: {error}"))?;
    checked_process_output(output, label)
}

fn checked_child(child: std::process::Child, label: &str) -> Result<String, String> {
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Cannot wait for {label}: {error}"))?;
    checked_process_output(output, label)
}

fn checked_process_output(output: std::process::Output, label: &str) -> Result<String, String> {
    if output.stdout.len() + output.stderr.len() > MAX_TAR_OUTPUT {
        return Err(format!("The {label} response was too large."));
    }
    if !output.status.success() {
        return Err(format!(
            "The {label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("The {label} response was not UTF-8."))
}

fn validate_lima_archive(file: File) -> Result<(), String> {
    let output = tar_command(file)
        .args(["-tzf", "-"])
        .output()
        .map_err(|error| format!("Cannot inspect the admitted Lima archive: {error}"))?;
    if !output.status.success() || output.stdout.len() > MAX_TAR_OUTPUT {
        return Err("The admitted Lima archive inventory could not be bounded.".into());
    }
    let list = std::str::from_utf8(&output.stdout)
        .map_err(|_| "The Lima archive inventory is not UTF-8.".to_owned())?;
    if list.lines().count() != LIMA_ARCHIVE_ENTRIES
        || sha256_bytes(&output.stdout) != LIMA_ARCHIVE_LIST_SHA256
        || list.lines().any(unsafe_archive_path)
    {
        return Err("The Lima archive inventory changed or contains an unsafe path.".into());
    }
    Ok(())
}

fn unsafe_archive_path(path: &str) -> bool {
    path.is_empty()
        || path.len() > 2048
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || !path.starts_with("./")
        || Path::new(path).is_absolute()
        || Path::new(path).components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
}

fn extract_lima(file: File, destination: &Path) -> Result<(), String> {
    ensure_private_directory(destination)?;
    let output = tar_command(file)
        .args([
            "--no-same-owner",
            "--no-same-permissions",
            "-xzf",
            "-",
            "-C",
        ])
        .arg(destination)
        .args(["./bin", "./libexec", "./share/lima"])
        .output()
        .map_err(|error| format!("Cannot extract the admitted Lima archive: {error}"))?;
    if !output.status.success() || output.stdout.len() + output.stderr.len() > MAX_TAR_OUTPUT {
        return Err(format!(
            "The admitted Lima archive extraction failed with {}.",
            output.status
        ));
    }
    validate_lima_runtime(destination)
}

fn tar_command(file: File) -> Command {
    let mut command = Command::new("/usr/bin/tar");
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn validate_runtime(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("The managed container runtime is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The managed container runtime root is not a regular directory.".into());
    }
    let colima = root.join(PLUS_MANAGED_COLIMA_RELATIVE);
    let colima_metadata = fs::symlink_metadata(&colima)
        .map_err(|error| format!("The managed Colima executable is unavailable: {error}"))?;
    if colima_metadata.file_type().is_symlink()
        || !colima_metadata.is_file()
        || colima_metadata.len() != COLIMA_ASSET.byte_len
        || colima_metadata.permissions().mode() & 0o111 == 0
        || hash_file(&colima)? != COLIMA_ASSET.sha256
    {
        return Err("The managed Colima executable failed exact verification.".into());
    }
    let lima = root.join("lima");
    validate_lima_runtime(&lima)?;
    let limactl = root.join(PLUS_MANAGED_LIMACTL_RELATIVE);
    let metadata = fs::symlink_metadata(limactl)
        .map_err(|error| format!("The managed Lima executable is unavailable: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err("The managed Lima executable is not a regular executable file.".into());
    }
    Ok(())
}

fn validate_lima_runtime(root: &Path) -> Result<(), String> {
    let manifest = runtime_manifest(root)?;
    if manifest.files != LIMA_FILES
        || manifest.directories != LIMA_DIRECTORIES
        || manifest.bytes != LIMA_FILE_BYTES
        || manifest.sha256 != LIMA_MANIFEST_SHA256
    {
        return Err(format!(
            "The Lima runtime manifest changed (observed {}).",
            manifest.sha256
        ));
    }
    Ok(())
}

struct RuntimeManifest {
    files: usize,
    directories: usize,
    bytes: u64,
    sha256: String,
}

fn runtime_manifest(root: &Path) -> Result<RuntimeManifest, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("The Lima runtime is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("The Lima runtime root is not a regular directory.".into());
    }
    let mut entries = Vec::new();
    collect_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut aggregate = Sha256::new();
    let mut files = 0;
    let mut directories = 1;
    let mut bytes = 0_u64;
    for (relative, path) in entries {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect a Lima runtime entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("The selected Lima runtime contains an unadmitted symlink.".into());
        }
        if metadata.is_dir() {
            directories += 1;
        } else if metadata.is_file() {
            if metadata.len() > MAX_RUNTIME_FILE {
                return Err("A Lima runtime file exceeds the admitted size bound.".into());
            }
            files += 1;
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| "The Lima runtime byte count overflowed.".to_owned())?;
            aggregate.update(
                format!("f\t{relative}\t{}\t{}\n", metadata.len(), hash_file(&path)?).as_bytes(),
            );
        } else {
            return Err("The selected Lima runtime contains a special file.".into());
        }
    }
    Ok(RuntimeManifest {
        files,
        directories,
        bytes,
        sha256: hex(&aggregate.finalize()),
    })
}

fn collect_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    for item in fs::read_dir(directory)
        .map_err(|error| format!("Cannot read a Lima runtime directory: {error}"))?
    {
        let item = item.map_err(|error| format!("Cannot read a Lima runtime entry: {error}"))?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| "A Lima runtime path is invalid.".to_owned())?
            .to_owned();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect a Lima runtime entry: {error}"))?;
        entries.push((relative, path.clone()));
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            collect_entries(root, &path, entries)?;
        }
    }
    Ok(())
}

fn secure_tree(root: &Path) -> Result<(), String> {
    let mut entries = Vec::new();
    collect_entries(root, root, &mut entries)?;
    for (_, path) in entries {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect a container runtime entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("The managed container runtime contains an unadmitted symlink.".into());
        }
        let executable_file = metadata.is_file() && metadata.permissions().mode() & 0o111 != 0;
        let mode = if metadata.is_dir() {
            0o700
        } else if executable_file {
            0o500
        } else if metadata.is_file() {
            0o400
        } else {
            return Err("The managed container runtime contains a special file.".into());
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("Cannot secure a container runtime entry: {error}"))?;
        File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("Cannot sync a container runtime entry: {error}"))?;
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Cannot sync the container runtime root: {error}"))
}

fn replace_invalid_runtime(parent: &Path, target: &Path) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect the invalid managed container runtime: {error}"
            ));
        }
    };
    if target.parent() != Some(parent)
        || target.file_name().and_then(|name| name.to_str())
            != Path::new(PLUS_MANAGED_CONTAINER_RUNTIME_RELATIVE)
                .file_name()
                .and_then(|name| name.to_str())
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
    {
        return Err("Container runtime repair refused an unexpected target.".into());
    }
    fs::remove_dir_all(target)
        .map_err(|error| format!("Cannot remove the invalid managed container runtime: {error}"))?;
    sync_directory(parent)
}

fn remove_temporary(parent: &Path, target: &Path) -> Result<(), String> {
    let valid_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".container-runtime-"));
    if target.parent() != Some(parent) || !valid_name {
        return Err("Container runtime cleanup refused an unexpected target.".into());
    }
    match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(target)
                .map_err(|error| format!("Cannot clean the temporary container runtime: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("Container runtime cleanup refused a symlink or non-directory target.".into()),
    }
}

fn hash_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Cannot open a container runtime file: {error}"))?;
    hash_reader(&mut file)
}

fn hash_reader(file: &mut File) -> Result<String, String> {
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash a container runtime file: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex(&hash.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
            text
        })
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

#[cfg(test)]
#[path = "container_runtime/tests.rs"]
mod tests;
