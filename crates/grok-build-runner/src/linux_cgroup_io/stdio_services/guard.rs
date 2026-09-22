//! Trusted setup enters a new namespace before the final immutable service image.

use super::*;
use rustix::fs::{MemfdFlags, SealFlags};
use std::io::Seek as _;
use std::os::unix::fs::MetadataExt as _;

const READY_PREFIX: &str = "GB_SERVICE_CONTAINED_V1 ";

#[allow(
    clippy::too_many_lines,
    reason = "one linear trusted setup keeps parent authentication, image sealing, and the closed namespace mount table in execution order"
)]
pub(super) fn child() -> Result<(), String> {
    let arguments = std::env::args().skip(2).collect::<Vec<_>>();
    if arguments.len() != 2 {
        return Err("Service child requires its owning process identity.".into());
    }
    let parent: u32 = arguments[0].parse().map_err(failure)?;
    rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
        .map_err(failure)?;
    if rustix::process::Pid::as_raw(rustix::process::getppid())
        != i32::try_from(parent).map_err(failure)?
    {
        return Err("Service owner ended before child initialization.".into());
    }
    if Digest::sha256(&read_bounded_file(
        &format!("/proc/{parent}/exe"),
        128 * 1024 * 1024,
    )?)
    .as_str()
        != arguments[1]
    {
        return Err("Service child's parent is not the admitted helper image.".into());
    }
    let parent_arguments = read_bounded_file(&format!("/proc/{parent}/cmdline"), 16 * 1024)?;
    let parent_arguments = parent_arguments
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parent_arguments.len() != 3 || parent_arguments[1] != b"--gb-contained-service-v1" {
        return Err("Service child is not owned by a service supervisor.".into());
    }
    let parent_namespaces = namespace_identities()?;
    // Exactly one byte at a time: no buffered setup reader may steal service stdin.
    let bytes = read_line_exact(64 * 1024)?;
    let request: ContainedServiceRequest = serde_json::from_slice(&bytes).map_err(failure)?;
    request.validate_shape()?;
    let workspace = open_root(&request.workspace)?;
    let content = open_root(&request.content_root)?;
    if crate::service_tree::digest_held(&workspace)? != request.scope.workspace_digest
        || crate::service_tree::digest_held(&content)? != request.scope.extension_digest
    {
        return Err("Service view differs from its admitted immutable content.".into());
    }
    let relative = Path::new(&request.executable)
        .strip_prefix(&request.content_root)
        .map_err(failure)?;
    let source = content
        .open_with(
            relative,
            OpenOptions::new()
                .read(true)
                .follow(super::super::FollowSymlinks::No),
        )
        .map_err(failure)?
        .into_std();
    let executable = read_image(
        source,
        request.executable_bytes,
        &request.executable_digest,
        request.architecture,
    )?;
    let self_image = read_bounded_file("/proc/self/exe", 128 * 1024 * 1024)?;
    if Digest::sha256(&self_image).as_str() != arguments[1] {
        return Err("Service guard image differs from the installation admission.".into());
    }
    let admitted = super::super::ADMITTED_BUBBLEWRAP_IMAGE_V1;
    let bwrap = super::super::LinuxRetainedExecutablePathProvenance::open_absolute(
        admitted.resolved_path,
        OPERATION,
    )
    .map_err(kernel_failure)?;
    let bwrap_bytes =
        super::super::read_retained_bootstrap_file(&bwrap.file, 128 * 1024, OPERATION)
            .map_err(kernel_failure)?;
    let bwrap_metadata = bwrap.file.metadata().map_err(failure)?;
    if bwrap_metadata.uid() != 0
        || bwrap_metadata.mode() & 0o6022 != 0
        || bwrap_bytes.len() as u64 != admitted.byte_length
        || Digest::sha256(&bwrap_bytes).as_str() != admitted.sha256
    {
        return Err("Service namespace launcher differs from its admitted image.".into());
    }
    bwrap.validate_named(OPERATION).map_err(kernel_failure)?;
    // All images/configuration become read-only data mounts. Source file names
    // never get reopened by the final service. No script or package manager runs.
    let target = sealed("gb-service-target", &executable, true)?;
    let guard = sealed("gb-service-guard", &self_image, true)?;
    let configuration = sealed("gb-service-request", &bytes, false)?;
    let launcher = sealed("gb-service-launcher", &bwrap_bytes, true)?;
    for fd in [
        target.as_fd(),
        guard.as_fd(),
        configuration.as_fd(),
        workspace.as_fd(),
        content.as_fd(),
    ] {
        rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::empty()).map_err(failure)?;
    }
    let mut launch = Command::new(format!("/proc/self/fd/{}", launcher.as_raw_fd()));
    launch.env_clear().args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
    ]);
    for (key, value) in &request.environment {
        launch.args(["--setenv", key, value]);
    }
    launch.args(["--ro-bind", "/usr", "/usr"]);
    for path in ["/lib", "/lib64"] {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_symlink() {
                let target = std::fs::read_link(path).map_err(failure)?;
                let target = target.to_str().ok_or("Non-UTF-8 runtime link.")?;
                if !matches!(
                    (path, target),
                    ("/lib", "usr/lib") | ("/lib64", "usr/lib64")
                ) {
                    return Err("Service runtime library link is not admitted.".into());
                }
                launch.args(["--symlink", target, path]);
            } else if metadata.is_dir() {
                launch.args(["--ro-bind", path, path]);
            } else {
                return Err("Service runtime library surface is not a directory.".into());
            }
        }
    }
    launch
        .args(["--proc", "/proc", "--dev", "/dev", "--dir", "/gb"])
        .args([
            "--perms",
            "0500",
            "--ro-bind-data",
            &target.as_raw_fd().to_string(),
            "/gb/service",
        ])
        .args([
            "--perms",
            "0500",
            "--ro-bind-data",
            &guard.as_raw_fd().to_string(),
            "/gb/guard",
        ])
        .args([
            "--ro-bind-data",
            &configuration.as_raw_fd().to_string(),
            "/gb/request",
        ])
        .args([
            "--ro-bind-fd",
            &workspace.as_raw_fd().to_string(),
            "/workspace",
        ])
        .args([
            "--ro-bind-fd",
            &content.as_raw_fd().to_string(),
            "/extension",
        ])
        .args([
            "--perms",
            "0700",
            "--size",
            &request.limits.scratch_bytes.to_string(),
            "--tmpfs",
            "/scratch",
        ])
        .args([
            "--perms",
            "0700",
            "--dir",
            "/scratch/home",
            "--perms",
            "0700",
            "--dir",
            "/scratch/tmp",
        ])
        .args([
            "--symlink",
            "/scratch/tmp",
            "/tmp",
            "--remount-ro",
            "/",
            "--chdir",
            "/workspace",
            "--",
            "/gb/guard",
            "--gb-contained-service-guard-v1",
        ])
        .arg(serde_json::to_string(&parent_namespaces).map_err(failure)?);
    // Command::exec consumes no shell and resets ordinary child dispositions.
    Err(format!(
        "Service namespace launch failed: {}",
        launch.exec()
    ))
}

pub(super) fn guard() -> Result<(), String> {
    let arguments = std::env::args().skip(2).collect::<Vec<_>>();
    if arguments.len() != 1 || arguments[0].len() > 4096 {
        return Err("Service guard requires bounded parent namespace identities.".into());
    }
    let parent: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&arguments[0]).map_err(failure)?;
    let current = namespace_identities()?;
    if parent.len() != current.len()
        || current
            .iter()
            .any(|(kind, identity)| parent.get(kind).is_none_or(|before| before == identity))
    {
        return Err("Service did not enter all required independent namespaces.".into());
    }
    let request_bytes = read_bounded_file("/gb/request", 64 * 1024)?;
    let request: ContainedServiceRequest =
        serde_json::from_slice(&request_bytes).map_err(failure)?;
    request.validate_shape()?;
    let workspace = open_root("/workspace")?;
    let content = open_root("/extension")?;
    if crate::service_tree::digest_held(&workspace)? != request.scope.workspace_digest
        || crate::service_tree::digest_held(&content)? != request.scope.extension_digest
    {
        return Err("Mounted service view changed before release.".into());
    }
    let image = read_image(
        std::fs::File::open("/gb/service").map_err(failure)?,
        request.executable_bytes,
        &request.executable_digest,
        request.architecture,
    )?;
    let target = sealed("gb-contained-service", &image, true)?;
    let scratch = open_root("/scratch")?;
    let scratch_fs = rustix::fs::fstatfs(&scratch).map_err(failure)?;
    if scratch_fs.f_type != 0x0102_1994
        || scratch_fs
            .f_blocks
            .saturating_mul(u64::try_from(scratch_fs.f_bsize).map_err(failure)?)
            > request.limits.scratch_bytes
        || scratch.dir_metadata().map_err(failure)?.mode() & 0o777 != 0o700
    {
        return Err(
            "Service scratch mount does not enforce its admitted size and private mode.".into(),
        );
    }
    // No installed runtime sockets, SSH agents or host credential homes exist
    // in this namespace. Refuse a widened view before any untrusted instruction.
    for path in ["/run", "/var", "/home", "/root", "/etc", "/sys"] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err("Service namespace contains an unadmitted host surface.".into());
        }
    }
    require_read_only(&workspace)?;
    require_read_only(&content)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(failure)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(128),
            maximum: Some(128),
        },
    )
    .map_err(failure)?;
    install_kernel_policy()?;
    require_no_capabilities()?;
    drop((workspace, content, scratch));
    require_descriptor_closure()?;
    // The guard's line is consumed by the supervisor. Provider/server text
    // cannot become this observation because it is emitted before exec.
    writeln!(std::io::stdout(), "{READY_PREFIX}{}", request.commitment()?).map_err(failure)?;
    std::io::stdout().flush().map_err(failure)?;
    let mut launch = Command::new(format!("/proc/self/fd/{}", target.as_raw_fd()));
    launch
        .arg0("/gb/service")
        .args(&request.arguments)
        .env_clear()
        .envs(&request.environment)
        .current_dir("/workspace");
    Err(format!(
        "Contained service image replacement failed: {}",
        launch.exec()
    ))
}

fn namespace_identities() -> Result<std::collections::BTreeMap<String, String>, String> {
    ["mnt", "net", "pid", "user", "ipc", "uts", "cgroup"]
        .into_iter()
        .map(|kind| {
            let identity = std::fs::read_link(format!("/proc/self/ns/{kind}")).map_err(failure)?;
            let text = identity
                .to_str()
                .ok_or("Invalid service namespace identity.")?;
            if text.len() > 128 || !text.starts_with(&format!("{kind}:[")) || !text.ends_with(']') {
                return Err("Malformed service namespace identity.".into());
            }
            Ok((kind.to_owned(), text.to_owned()))
        })
        .collect()
}

fn require_no_capabilities() -> Result<(), String> {
    let bytes = read_bounded_file("/proc/self/status", 32 * 1024)?;
    let status = String::from_utf8(bytes).map_err(failure)?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .ok_or("Missing service capability readback.")?
            .trim();
        if u64::from_str_radix(value, 16).map_err(failure)? != 0 {
            return Err("Service retained a kernel capability.".into());
        }
    }
    Ok(())
}

fn require_descriptor_closure() -> Result<(), String> {
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/fd").map_err(failure)? {
        let name = entry.map_err(failure)?.file_name();
        let descriptor: u32 = name
            .to_str()
            .ok_or("Invalid service descriptor.")?
            .parse()
            .map_err(failure)?;
        count += 1;
        if count > 128 {
            return Err("Service descriptor ceiling exceeded.".into());
        }
        if descriptor <= 2 {
            continue;
        }
        let text = String::from_utf8(read_bounded_file(
            &format!("/proc/self/fdinfo/{descriptor}"),
            8192,
        )?)
        .map_err(failure)?;
        let flags = text
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .ok_or("Missing service descriptor flags.")?
            .trim();
        if u64::from_str_radix(flags, 8).map_err(failure)? & 0o2_000_000 == 0 {
            return Err("Service release would inherit an extra descriptor.".into());
        }
    }
    Ok(())
}

pub(super) fn expected_ready(request: &ContainedServiceRequest) -> Result<Vec<u8>, String> {
    Ok(format!("{READY_PREFIX}{}", request.commitment()?).into_bytes())
}

fn open_root(path: &str) -> Result<Dir, String> {
    let provenance =
        super::super::LinuxRetainedDirectoryPathProvenance::open_absolute(path, OPERATION)
            .map_err(kernel_failure)?;
    provenance
        .validate_named(OPERATION)
        .map_err(kernel_failure)?;
    Ok(provenance.directory)
}

fn read_image(
    mut source: std::fs::File,
    length: u64,
    digest: &Digest,
    architecture: ServiceArchitecture,
) -> Result<Vec<u8>, String> {
    let before = source.metadata().map_err(failure)?;
    if !before.is_file() || before.len() != length || length > 128 * 1024 * 1024 {
        return Err("Service image type or length differs from admission.".into());
    }
    let mut bytes = Vec::new();
    (&mut source)
        .take(length + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    let after = source.metadata().map_err(failure)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != length
        || Digest::sha256(&bytes) != *digest
        || crate::service_contract::service_elf_architecture(&bytes)? != architecture
    {
        return Err("Service executable changed or has an unadmitted architecture.".into());
    }
    Ok(bytes)
}

fn sealed(name: &str, bytes: &[u8], executable: bool) -> Result<std::fs::File, String> {
    let descriptor = rustix::fs::memfd_create(
        name,
        MemfdFlags::CLOEXEC
            | MemfdFlags::ALLOW_SEALING
            | if executable {
                MemfdFlags::EXEC
            } else {
                MemfdFlags::NOEXEC_SEAL
            },
    )
    .map_err(failure)?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(bytes).map_err(failure)?;
    file.rewind().map_err(failure)?;
    let seals = SealFlags::SEAL
        | SealFlags::SHRINK
        | SealFlags::GROW
        | SealFlags::WRITE
        | SealFlags::FUTURE_WRITE;
    rustix::fs::fcntl_add_seals(&file, seals).map_err(failure)?;
    if !rustix::fs::fcntl_get_seals(&file)
        .map_err(failure)?
        .contains(seals)
    {
        return Err("Service immutable image sealing failed.".into());
    }
    Ok(file)
}

fn read_bounded_file(path: &str, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(failure)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(failure)?;
    if bytes.len() as u64 > maximum {
        return Err("Service configuration limit exceeded.".into());
    }
    Ok(bytes)
}

fn read_line_exact(maximum: usize) -> Result<Vec<u8>, String> {
    let mut input = std::io::stdin().lock();
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        if input.read(&mut byte).map_err(failure)? == 0 {
            return Err("Service owner closed during setup.".into());
        }
        if byte[0] == b'\n' {
            return Ok(bytes);
        }
        if bytes.len() >= maximum {
            return Err("Service setup frame limit exceeded.".into());
        }
        bytes.push(byte[0]);
    }
}

fn require_read_only(directory: &Dir) -> Result<(), String> {
    let name = format!(".gb-service-denial-{}", std::process::id());
    match directory.open_with(
        &name,
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .follow(super::super::FollowSymlinks::No),
    ) {
        Err(error) if error.raw_os_error() == Some(30) => Ok(()), // EROFS, before Landlock.
        Ok(file) => {
            drop(file);
            let _ = directory.remove_file(&name);
            Err("Service source mount is writable.".into())
        }
        Err(_) => Err("Service source mount did not prove read-only enforcement.".into()),
    }
}

fn install_kernel_policy() -> Result<(), String> {
    use landlock::{
        Access as _, AccessFs, CompatLevel, Compatible as _, PathBeneath, PathFd, Ruleset,
        RulesetAttr as _, RulesetCreatedAttr as _, RulesetStatus,
    };
    let abi = crate::linux_dev_domain::observed_landlock_abi();
    if crate::linux_dev_domain::abi_level(abi) == 0 {
        return Err("Services require enforced Landlock.".into());
    }
    let all = AccessFs::from_all(abi);
    let read = AccessFs::from_read(abi);
    let mut rules = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)
        .and_then(Ruleset::create)
        .map_err(failure)?;
    for (path, access) in [
        ("/workspace", read),
        ("/extension", read),
        ("/gb", read),
        ("/usr", read),
        ("/proc", read),
        ("/scratch", all),
        ("/dev/null", all),
        ("/dev/urandom", read),
        ("/dev/zero", read),
    ] {
        let fd = PathFd::new(path).map_err(failure)?;
        let access = if Path::new(path).is_dir() {
            access
        } else {
            access & AccessFs::from_file(abi)
        };
        rules = rules
            .add_rule(PathBeneath::new(fd, access))
            .map_err(failure)?;
    }
    let result = rules.restrict_self().map_err(failure)?;
    if result.ruleset != RulesetStatus::FullyEnforced || !result.no_new_privs {
        return Err("Service Landlock policy did not fully enforce.".into());
    }
    let architecture = crate::linux_command_plan::HOST_AUDIT_ARCHITECTURE;
    let namespace = crate::linux_command_plan::assemble_namespace_program(
        &crate::linux_command_plan::committed_namespace_denials(architecture),
        architecture,
    )?;
    let table = crate::linux_dev_domain::LINUX_NETWORK_SYSCALLS
        .iter()
        .map(|(_, number)| (*number, Vec::new()))
        .collect();
    let target = match architecture {
        crate::linux_command_plan::LinuxAuditArchitectureV1::Aarch64 => {
            seccompiler::TargetArch::aarch64
        }
        crate::linux_command_plan::LinuxAuditArchitectureV1::X86_64 => {
            seccompiler::TargetArch::x86_64
        }
    };
    let network: seccompiler::BpfProgram = seccompiler::SeccompFilter::new(
        table,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::KillProcess,
        target,
    )
    .map_err(failure)?
    .try_into()
    .map_err(failure)?;
    seccompiler::apply_filter_all_threads(&network).map_err(failure)?;
    seccompiler::apply_filter_all_threads(&namespace).map_err(failure)
}

/// An explicitly selected native fixture, distributed as a mode of the same
/// admitted guest helper. It has no access beyond whatever contained it.
pub(super) fn fixture() -> Result<(), String> {
    let mut input = std::io::stdin().lock();
    loop {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            if input.read(&mut byte).map_err(failure)? == 0 {
                return Ok(());
            }
            if byte[0] == b'\n' {
                break;
            }
            if bytes.len() >= 1024 * 1024 {
                return Err("Fixture frame limit.".into());
            }
            bytes.push(byte[0]);
        }
        let message: serde_json::Value = serde_json::from_slice(&bytes).map_err(failure)?;
        let response = if message.get("method").and_then(serde_json::Value::as_str)
            == Some("initialize")
        {
            serde_json::json!({"jsonrpc":"2.0","id":message["id"],"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"gb-contained-fixture","version":"1"}}})
        } else {
            serde_json::json!({"jsonrpc":"2.0","id":message["id"],"result":{"echo":message.get("params")}})
        };
        writeln!(std::io::stdout(), "{response}").map_err(failure)?;
        std::io::stdout().flush().map_err(failure)?;
    }
}
