//! Declarative stdio-service requests. Valid shape is never launch authority.

use std::collections::BTreeMap;
use std::path::Path;

use grok_build_core::{CommandSpec, Digest, validate_current_direct_exec_command_v1};
use serde::{Deserialize, Serialize};

/// Version of the app-to-guest service contract.
pub const CONTAINED_SERVICE_CONTRACT_VERSION: u16 = 1;

/// Profiles before four lack positive confirmation after snapshot staging.
pub const CONTAINED_SERVICE_PROFILE_VERSION: u16 = 4;

/// Only native Linux images enter the managed guest service path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceArchitecture {
    /// Linux ARM64.
    LinuxAarch64,
    /// Linux x86-64, when the admitted guest actually uses this architecture.
    LinuxX86_64,
}

/// The broker controls readiness according to the selected protocol.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePurpose {
    /// A persistent MCP stdio connection, ready after validated initialization.
    Mcp,
    /// A single bounded command hook, successful only after validated exit/output.
    Hook,
}

/// Authenticated managed guest generation; this readback is not permission to launch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedServiceProfile {
    /// Exact supported profile version.
    pub version: u16,
    /// Installation, helper, admitted launcher, and guest boot identity.
    pub containment_digest: Digest,
    /// Architecture actually admitted by this guest's service path.
    pub architecture: ServiceArchitecture,
    /// Authenticated owner-only guest root for transferred service views.
    pub views_root: String,
    /// Next one-use lease number. This is allocation metadata, not containment identity.
    pub next_lease_sequence: u64,
}

impl ContainedServiceProfile {
    /// Resolve this one-use lease's private paths inside the authenticated guest.
    /// This does not create directories or authorize the request.
    ///
    /// # Errors
    /// Refuses a profile without the staged-view protocol or invalid paths/requests.
    pub fn snapshot_paths(
        &self,
        request: &ContainedServiceRequest,
    ) -> Result<(String, String), String> {
        if self.version != CONTAINED_SERVICE_PROFILE_VERSION || !absolute_path(&self.views_root) {
            return Err("Guest service profile does not support private view staging.".into());
        }
        let root = format!(
            "{}/gb-service-{}",
            self.views_root,
            request.lease_identity_digest()?
        );
        let workspace = format!("{root}/workspace");
        let content = format!("{root}/extension");
        if !absolute_path(&workspace) || !absolute_path(&content) {
            return Err("Guest service staging path exceeds its bound.".into());
        }
        Ok((workspace, content))
    }
}

/// Exactly two captured views may be transferred on a service connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceView {
    /// The owning project's captured working files.
    Workspace,
    /// The selected immutable extension content.
    Extension,
}

/// App-issued identity expectations; the receiver must resolve and revalidate them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceScope {
    /// Owning app project, never taken from a provider's tool arguments.
    pub project_id: String,
    /// Owning app execution or explicit extension-verification operation.
    pub operation_id: String,
    /// Identity of the exact workspace snapshot supplied to this service.
    pub workspace_digest: Digest,
    /// Immutable enabled extension version.
    pub extension_digest: Digest,
    /// Exact admitted managed-guest containment generation.
    pub containment_digest: Digest,
}

/// Bounds are enforced independently of server responses and annotations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceLimits {
    /// Maximum size of one protocol frame.
    pub frame_bytes: u32,
    /// Total input admitted during the lease.
    pub input_bytes: u64,
    /// Total combined output admitted during the lease.
    pub output_bytes: u64,
    /// Deadline for protocol readiness.
    pub readiness_ms: u64,
    /// Independent maximum lease duration, including protocol stalls.
    pub lifetime_ms: u64,
    /// Maximum size of the private scratch filesystem.
    pub scratch_bytes: u64,
    /// Complete descendant-domain process ceiling.
    pub processes: u32,
    /// Complete descendant-domain memory ceiling.
    pub memory_bytes: u64,
}

impl Default for ServiceLimits {
    fn default() -> Self {
        Self {
            frame_bytes: 1024 * 1024,
            input_bytes: 16 * 1024 * 1024,
            output_bytes: 16 * 1024 * 1024,
            readiness_ms: 10_000,
            lifetime_ms: 15 * 60 * 1000,
            scratch_bytes: 64 * 1024 * 1024,
            processes: 16,
            memory_bytes: 256 * 1024 * 1024,
        }
    }
}

/// A candidate request, not a permission, permit, launch result, or cleanup proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedServiceRequest {
    /// Exact supported contract version.
    pub schema_version: u16,
    /// One-use app-issued lease identity.
    pub lease_id: String,
    /// App-owned scope resolved independently by the broker and guest.
    pub scope: ServiceScope,
    /// Fixed protocol purpose.
    pub purpose: ServicePurpose,
    /// Absolute guest path to the admitted immutable executable.
    pub executable: String,
    /// Immutable installed content mounted read-only at `/extension`.
    pub content_root: String,
    /// Expected SHA-256 of the complete executable image.
    pub executable_digest: Digest,
    /// Expected byte size, checked before hashing/sealing.
    pub executable_bytes: u64,
    /// Architecture must match both the ELF header and admitted guest.
    pub architecture: ServiceArchitecture,
    /// Exact argv after `argv[0]`. No shell interpretation is permitted.
    pub arguments: Vec<String>,
    /// Exact effective environment, including the fixed private defaults.
    pub environment: BTreeMap<String, String>,
    /// Actual read-only workspace source on the guest.
    pub workspace: String,
    /// All protocol, process, memory, and filesystem bounds.
    pub limits: ServiceLimits,
}

impl ContainedServiceRequest {
    /// Validates representation and hard limits without granting any authority.
    ///
    /// # Errors
    /// Refuses unknown versions, unsafe identities/paths, shells, ambient or
    /// secret environment channels, and invalid resource bounds.
    pub fn validate_shape(&self) -> Result<(), String> {
        if self.schema_version != CONTAINED_SERVICE_CONTRACT_VERSION
            || !identifier(&self.lease_id)
            || !identifier(&self.scope.project_id)
            || !identifier(&self.scope.operation_id)
            || !absolute_path(&self.executable)
            || !absolute_path(&self.content_root)
            || !Path::new(&self.executable).starts_with(&self.content_root)
            || self.executable == self.content_root
            || !absolute_path(&self.workspace)
            || !(64..=128 * 1024 * 1024).contains(&self.executable_bytes)
        {
            return Err(
                "Contained service has an unsupported version or invalid identity/image.".into(),
            );
        }
        validate_current_direct_exec_command_v1(&CommandSpec {
            program: self.executable.clone(),
            arguments: self.arguments.clone(),
            working_directory: std::path::PathBuf::new(),
        })
        .map_err(|error| error.to_string())?;
        if self.arguments.len() > 32
            || self.arguments.iter().map(String::len).sum::<usize>() > 32 * 1024
        {
            return Err("Contained service argv exceeds its bounded admission.".into());
        }
        validate_environment(&self.environment)?;
        validate_limits(self.limits, self.purpose)
    }

    /// Commits to every scope, image, argv, environment and containment field.
    ///
    /// # Errors
    /// Refuses invalid requests or serialization failure. A digest is not a permit.
    pub fn commitment(&self) -> Result<Digest, String> {
        self.validate_shape()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let mut framed = b"grok-build/contained-stdio-service/v1\0".to_vec();
        framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        framed.extend_from_slice(&bytes);
        Ok(Digest::sha256(&framed))
    }

    /// Stable replay key for this app-issued, installation-wide one-use lease.
    /// Changing request arguments must never allocate a second effect identity.
    ///
    /// # Errors
    /// Refuses an invalid request before producing its identity key.
    pub fn lease_identity_digest(&self) -> Result<Digest, String> {
        self.validate_shape()?;
        Ok(service_lease_digest(&self.lease_id))
    }
}

pub(crate) fn service_lease_digest(name: &str) -> Digest {
    let mut bytes = b"grok-build/contained-stdio-lease-id/v1\0".to_vec();
    bytes.extend_from_slice(name.as_bytes());
    Digest::sha256(&bytes)
}

/// Effective defaults refer only to paths inside the contained namespace.
#[must_use]
pub fn service_environment() -> BTreeMap<String, String> {
    [
        ("HOME", "/scratch/home"),
        ("TMPDIR", "/scratch/tmp"),
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), String> {
    let defaults = service_environment();
    if environment.len() > 16
        || defaults
            .iter()
            .any(|(key, value)| environment.get(key) != Some(value))
        || environment.iter().any(|(key, value)| {
            (!defaults.contains_key(key)
                && !matches!(key.as_str(), "NO_COLOR" | "RUST_LOG" | "PYTHONUNBUFFERED"))
                || value.len() > 1024
                || value.chars().any(char::is_control)
        })
    {
        return Err(
            "Contained service environment differs from its private admitted profile.".into(),
        );
    }
    Ok(())
}

fn validate_limits(limits: ServiceLimits, purpose: ServicePurpose) -> Result<(), String> {
    let lifetime_max = if purpose == ServicePurpose::Hook {
        30_000
    } else {
        60 * 60 * 1000
    };
    if !(1..=1024 * 1024).contains(&limits.frame_bytes)
        || !(u64::from(limits.frame_bytes)..=64 * 1024 * 1024).contains(&limits.input_bytes)
        || !(u64::from(limits.frame_bytes)..=64 * 1024 * 1024).contains(&limits.output_bytes)
        || !(1..=30_000).contains(&limits.readiness_ms)
        || !(limits.readiness_ms..=lifetime_max).contains(&limits.lifetime_ms)
        || !(1024 * 1024..=256 * 1024 * 1024).contains(&limits.scratch_bytes)
        || !(1..=32).contains(&limits.processes)
        || !(16 * 1024 * 1024..=512 * 1024 * 1024).contains(&limits.memory_bytes)
        || limits.scratch_bytes > limits.memory_bytes / 2
    {
        return Err("Contained service resource limits are missing, inconsistent, or exceed the hard ceilings.".into());
    }
    Ok(())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

fn absolute_path(value: &str) -> bool {
    value.len() <= 4096
        && !value.chars().any(char::is_control)
        && value != "/"
        && Path::new(value).is_absolute()
        && value[1..]
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

/// Checks the native ELF architecture before the admitted image may be sealed.
///
/// # Errors
/// Refuses truncated, non-ELF, non-64-bit, non-little-endian and foreign images.
pub fn service_elf_architecture(header: &[u8]) -> Result<ServiceArchitecture, String> {
    if header.len() < 64
        || &header[..4] != b"\x7fELF"
        || header[4..7] != [2, 1, 1]
        || !matches!(header[7], 0 | 3)
        || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
    {
        return Err("The service requires an admitted native Linux ELF executable; no host fallback is available.".into());
    }
    match u16::from_le_bytes([header[18], header[19]]) {
        183 => Ok(ServiceArchitecture::LinuxAarch64),
        62 => Ok(ServiceArchitecture::LinuxX86_64),
        _ => Err("Service ELF architecture is unsupported by the managed guest interface.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ContainedServiceRequest {
        ContainedServiceRequest {
            schema_version: CONTAINED_SERVICE_CONTRACT_VERSION,
            lease_id: "lease-one".into(),
            scope: ServiceScope {
                project_id: "project-one".into(),
                operation_id: "run-one".into(),
                workspace_digest: Digest::sha256(b"workspace"),
                extension_digest: Digest::sha256(b"extension"),
                containment_digest: Digest::sha256(b"containment"),
            },
            purpose: ServicePurpose::Mcp,
            executable: "/extension/server".into(),
            content_root: "/extension".into(),
            executable_digest: Digest::sha256(b"executable"),
            executable_bytes: 4096,
            architecture: ServiceArchitecture::LinuxAarch64,
            arguments: vec!["--stdio".into()],
            environment: service_environment(),
            workspace: "/managed/workspace".into(),
            limits: ServiceLimits::default(),
        }
    }

    #[test]
    fn commitment_binds_each_subject_instead_of_accepting_one_subject_for_another() {
        let original = request();
        let expected = original.commitment().unwrap();
        let edits: &[fn(&mut ContainedServiceRequest)] = &[
            |value| value.lease_id = "lease-two".into(),
            |value| value.scope.project_id = "project-two".into(),
            |value| value.scope.operation_id = "run-two".into(),
            |value| value.scope.workspace_digest = Digest::sha256(b"other workspace"),
            |value| value.scope.extension_digest = Digest::sha256(b"other extension"),
            |value| value.scope.containment_digest = Digest::sha256(b"other containment"),
            |value| value.executable_digest = Digest::sha256(b"other executable"),
            |value| value.executable = "/extension/other".into(),
            |value| {
                value.content_root = "/extension-v2".into();
                value.executable = "/extension-v2/server".into();
            },
            |value| value.architecture = ServiceArchitecture::LinuxX86_64,
            |value| value.arguments.push("--other".into()),
            |value| {
                value.environment.insert("NO_COLOR".into(), "1".into());
            },
            |value| value.limits.output_bytes += 1,
            |value| value.workspace = "/managed/other".into(),
        ];
        for edit in edits {
            let mut changed = original.clone();
            edit(&mut changed);
            assert_ne!(changed.commitment().unwrap(), expected);
        }
    }

    #[test]
    fn service_requests_refuse_ambient_credentials_shells_unknown_versions_and_unbounded_hooks() {
        let original = request();
        for key in [
            "XAI_API_KEY",
            "GROK_AUTH_PATH",
            "SSH_AUTH_SOCK",
            "LD_PRELOAD",
            "NODE_OPTIONS",
        ] {
            let mut changed = original.clone();
            changed.environment.insert(key.into(), "fixture".into());
            assert!(changed.validate_shape().is_err());
        }
        let mut changed = original.clone();
        changed.executable = "/bin/sh".into();
        assert!(changed.validate_shape().is_err());
        changed = original.clone();
        changed.schema_version += 1;
        assert!(changed.validate_shape().is_err());
        changed = original.clone();
        changed.purpose = ServicePurpose::Hook;
        assert!(changed.validate_shape().is_err());
        changed.limits.lifetime_ms = 10_000;
        changed.validate_shape().unwrap();
        let mut wire = serde_json::to_value(original).unwrap();
        wire["credentials"] = serde_json::json!("unrecognized authority");
        assert!(serde_json::from_value::<ContainedServiceRequest>(wire).is_err());
        for path in [
            "/extension/../server",
            "/extension//server",
            "/extension/./server",
            "/extension/server/",
        ] {
            let mut changed = request();
            changed.executable = path.into();
            assert!(changed.validate_shape().is_err());
        }
    }

    #[test]
    fn changing_arguments_or_project_cannot_reuse_a_one_use_lease() {
        let original = request();
        let mut changed = original.clone();
        changed.arguments.push("--changed".into());
        changed.scope.project_id = "different-project".into();
        assert_ne!(
            original.commitment().unwrap(),
            changed.commitment().unwrap()
        );
        assert_eq!(
            original.lease_identity_digest().unwrap(),
            changed.lease_identity_digest().unwrap()
        );
        changed.lease_id = "a-new-lease".into();
        assert_ne!(
            original.lease_identity_digest().unwrap(),
            changed.lease_identity_digest().unwrap()
        );
    }

    #[test]
    fn staging_pool_profiles_refuse_older_protocols_and_keep_each_lease_in_one_root() {
        let request = request();
        let mut profile = ContainedServiceProfile {
            version: CONTAINED_SERVICE_PROFILE_VERSION,
            containment_digest: request.scope.containment_digest.clone(),
            architecture: request.architecture,
            views_root: "/private/guest/views".into(),
            next_lease_sequence: 1,
        };
        let expected = profile.snapshot_paths(&request).unwrap();
        assert!(expected.0.starts_with("/private/guest/views/gb-service-"));
        assert!(expected.0.ends_with("/workspace"));
        assert!(expected.1.ends_with("/extension"));
        let mut changed = request.clone();
        changed.arguments.push("--different".into());
        assert_eq!(profile.snapshot_paths(&changed).unwrap(), expected);
        changed.lease_id = "another-lease".into();
        assert_ne!(profile.snapshot_paths(&changed).unwrap(), expected);
        for version in [0, 1, 2, 3, 65535] {
            profile.version = version;
            assert!(profile.snapshot_paths(&request).is_err());
        }
        profile.version = CONTAINED_SERVICE_PROFILE_VERSION;
        profile.views_root = "/private/../another".into();
        assert!(profile.snapshot_paths(&request).is_err());
    }

    #[test]
    fn architecture_inspection_never_admits_a_host_script_or_mach_o_image() {
        for bytes in [
            b"#!/bin/sh".as_slice(),
            b"\xcf\xfa\xed\xfe".as_slice(),
            &[0; 64],
        ] {
            assert!(service_elf_architecture(bytes).is_err());
        }
        let mut header = [0; 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4..7].copy_from_slice(&[2, 1, 1]);
        header[16] = 3;
        header[18] = 183;
        assert_eq!(
            service_elf_architecture(&header).unwrap(),
            ServiceArchitecture::LinuxAarch64
        );
        header[18] = 62;
        assert_eq!(
            service_elf_architecture(&header).unwrap(),
            ServiceArchitecture::LinuxX86_64
        );
        header[5] = 2;
        assert!(service_elf_architecture(&header).is_err());
    }
}
