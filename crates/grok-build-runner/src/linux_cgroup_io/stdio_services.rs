//! Separate stdio leases under the same independently authenticated installation.
//!
//! Checks retain their command journal and release contract. Services have a
//! distinct namespace, no proposal write root, and no route to a host fallback.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use cap_fs_ext::{DirExt as _, OpenOptionsFollowExt as _, OsMetadataExt as _};
use cap_std::fs::{Dir, OpenOptions};
use grok_build_core::Digest;
use serde::{Deserialize, Serialize};

use crate::contained_service::{
    MAX_SERVICE_CONTROL_BYTES, ServiceControl, ServiceEvent, ServiceFrameReader,
    ServiceObservation, ServiceOperation, ServiceTermination,
};
use crate::service_contract::{
    ContainedServiceProfile as ServiceProfile, ContainedServiceRequest, ServiceArchitecture,
};

mod counter;
mod domain;
mod guard;
mod pool;
mod staging;
mod supervisor;

const OPERATION: &str = "contained-stdio-service";
const SERVICE_ROOT: &str = "stdio-leases-v1";
const MAX_LEASE_RECORDS: usize = 128;
const MAX_ACTIVE_LEASES: usize = 8;

fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn kernel_failure(error: super::CgroupIoFailure) -> String {
    let super::CgroupIoFailure {
        operation, detail, ..
    } = error;
    format!("{operation}: {detail}")
}

struct Installation {
    installer_root: String,
    profile: ServiceProfile,
    state: Dir,
    views: Dir,
    delegation: Dir,
    delegation_identity: super::CgroupObjectIdentity,
    helper_digest: Digest,
}

impl Installation {
    fn open(installer_root: &str) -> Result<Self, String> {
        let (handoff, evidence) =
            super::open_installed_linux_native_service_handoff(installer_root)
                .map_err(kernel_failure)?;
        let expected = handoff.external_commitment.journal.clone();
        if handoff.delegation_name != "stdio" {
            return Err("Persistent services require their separate stdio delegation; the Checks delegation cannot be reused.".into());
        }
        let (capability, roots) = handoff
            .into_state_root_capability(&expected)
            .map_err(kernel_failure)?;
        let delegation = roots
            .service_parent
            .open_dir_nofollow(&roots.delegation_name)
            .map_err(failure)?;
        let pool_identity = pool::identity(&roots.service_parent)?;
        super::require_named_cgroup_identity(
            &roots.service_parent,
            &roots.delegation_name,
            expected.delegation_identity,
            OPERATION,
        )
        .map_err(kernel_failure)?;
        if u64::try_from(rustix::fs::fstatfs(&delegation).map_err(failure)?.f_type)
            .map_err(failure)?
            != crate::linux_containment::CGROUP2_SUPER_MAGIC
        {
            return Err("Service delegation is not a cgroup-v2 filesystem.".into());
        }
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(failure)?;
        if boot.len() != 37
            || !boot
                .trim()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err("Service runtime has no valid boot identity.".into());
        }
        let architecture = match std::env::consts::ARCH {
            "aarch64" => ServiceArchitecture::LinuxAarch64,
            // The distributed Bubblewrap image is admitted for ARM64 only.
            _ => return Err("No service launcher is admitted for this guest architecture.".into()),
        };
        // AppArmor's revision file is a long-polling stream, not a regular
        // read-to-EOF file. One bounded read captures the current generation.
        let policy_generation = read_policy_generation()?;
        let (views, _) = super::open_or_create_private_directory(
            &capability.service_state_root,
            "stdio-views-v1",
            rustix::process::geteuid().as_raw(),
        )
        .map_err(kernel_failure)?;
        let views_metadata = views.dir_metadata().map_err(failure)?;
        // Resolve only the directory already admitted through the anchor, then
        // bind its name back to the retained object. A pathname does not mint authority.
        let views_path =
            std::fs::read_link(format!("/proc/self/fd/{}", views.as_raw_fd())).map_err(failure)?;
        if !views_path.is_absolute() || views_path.canonicalize().map_err(failure)? != views_path {
            return Err("Service staging root is not a stable canonical directory.".into());
        }
        let named =
            Dir::open_ambient_dir(&views_path, cap_std::ambient_authority()).map_err(failure)?;
        let named_metadata = named.dir_metadata().map_err(failure)?;
        if (named_metadata.dev(), named_metadata.ino())
            != (views_metadata.dev(), views_metadata.ino())
        {
            return Err("Service staging root name does not match its admitted directory.".into());
        }
        let views_root = views_path
            .to_str()
            .ok_or("Service staging root is not UTF-8.")?
            .to_owned();
        let profile_bytes = serde_json::to_vec(&(
            crate::service_contract::CONTAINED_SERVICE_PROFILE_VERSION,
            &evidence.anchor_sha256,
            &expected.authenticated_platform_service_digest,
            boot.trim(),
            super::ADMITTED_BUBBLEWRAP_IMAGE_V1.sha256,
            architecture,
            policy_generation,
            &views_root,
            (views_metadata.dev(), views_metadata.ino()),
            pool_identity,
        ))
        .map_err(failure)?;
        let profile = ServiceProfile {
            version: crate::service_contract::CONTAINED_SERVICE_PROFILE_VERSION,
            containment_digest: Digest::sha256(&profile_bytes),
            architecture,
            views_root,
            // Operational allocation is populated only for the profile response;
            // changing a counter must not invalidate another live containment lease.
            next_lease_sequence: 0,
        };
        Ok(Self {
            installer_root: installer_root.into(),
            profile,
            state: capability.service_state_root,
            views,
            delegation,
            delegation_identity: expected.delegation_identity,
            helper_digest: expected.authenticated_platform_service_digest,
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        let fresh = Self::open(&self.installer_root)?;
        let live = super::object_identity(&self.delegation.dir_metadata().map_err(failure)?);
        if fresh.profile != self.profile
            || fresh.delegation_identity != self.delegation_identity
            || super::cgroup_identity(live) != self.delegation_identity
        {
            return Err("Contained service installation identity changed.".into());
        }
        Ok(())
    }
}

fn read_policy_generation() -> Result<(String, String, String), String> {
    fn value(path: &str, maximum: usize) -> Result<String, String> {
        let mut file = std::fs::File::open(path).map_err(failure)?;
        let mut bytes = vec![0; maximum + 1];
        let count = file.read(&mut bytes).map_err(failure)?;
        if count == 0 || count > maximum {
            return Err("Service kernel policy identity is missing or oversized.".into());
        }
        bytes.truncate(count);
        String::from_utf8(bytes)
            .map(|text| text.trim_end_matches(['\n', '\0']).to_owned())
            .map_err(failure)
    }
    // The current managed guest requires this LSM. A guest without the policy
    // interfaces must be separately admitted rather than interpreted as unrestricted.
    let revision = value("/sys/kernel/security/apparmor/revision", 32)?;
    if revision.parse::<u64>().is_err() {
        return Err("Service AppArmor generation is malformed.".into());
    }
    let restriction = value("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", 8)?;
    if restriction != "1" {
        return Err("Service guest must retain restricted user namespaces.".into());
    }
    Ok((
        revision,
        restriction,
        value("/proc/self/attr/current", 1024)?,
    ))
}

pub(crate) fn run(mode: &std::ffi::OsStr) -> ExitCode {
    let result = match mode.to_str() {
        Some("--gb-contained-service-v1") => supervisor::run(),
        Some("--gb-contained-service-child-v1") => guard::child(),
        Some("--gb-contained-service-guard-v1") => guard::guard(),
        Some("--gb-contained-service-profile-v1") => profile(),
        Some("--gb-contained-service-fixture-v1") => guard::fixture(),
        _ => Err("Unknown service mode.".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "Contained service refused: {}",
                error
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(512)
                    .collect::<String>()
            );
            ExitCode::from(78)
        }
    }
}

fn installer_argument() -> Result<String, String> {
    let arguments = std::env::args().skip(2).collect::<Vec<_>>();
    if arguments.len() != 1 || !arguments[0].starts_with('/') {
        return Err("A contained service requires exactly one absolute installation root.".into());
    }
    Ok(arguments[0].clone())
}

fn profile() -> Result<(), String> {
    let installation = Installation::open(&installer_argument()?)?;
    let mut profile = installation.profile.clone();
    profile.next_lease_sequence = counter::Journal::open(&installation.state)?.next()?;
    writeln!(
        std::io::stdout(),
        "{}",
        serde_json::to_string(&profile).map_err(failure)?
    )
    .map_err(failure)
}

fn nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), String> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(failure)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(failure)
}

fn write_bounded(
    output: &mut (impl std::io::Write + std::os::fd::AsFd),
    bytes: &[u8],
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offset = 0;
    while offset < bytes.len() {
        match output.write(&bytes[offset..]) {
            Ok(0) => return Err("Service transport closed during a frame.".into()),
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err("Service transport write deadline.".into());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(failure(error)),
        }
    }
    Ok(())
}
