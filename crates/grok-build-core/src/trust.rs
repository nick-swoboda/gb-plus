//! Integrity-checked project trust and immutable execution-policy compilation.
//!
//! Public wire structs in [`crate::contracts`] intentionally remain constructible
//! for persistence and deterministic provider fixtures. They are not proof of
//! authority. This module provides the production path: filesystem-bound grants
//! and policies that can only be obtained after all integrity checks pass.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use sha2::{Digest as Sha2Digest, Sha256};

use crate::contracts::{
    ContractError, Digest, EnvironmentVariable, ExecutionNetwork, ExecutionPolicy, MutationMode,
    PathScope, ResourceLimits, WorkspaceGrant, WorkspaceNetworkPolicy, WorkspacePermissions,
};

const GRANT_HASH_DOMAIN: &[u8] = b"grok-build/workspace-grant/v1";
const POLICY_HASH_DOMAIN: &[u8] = b"grok-build/execution-policy/v1";

/// Stable identity of the exact directory object selected as a workspace.
///
/// A canonical path alone cannot distinguish a trusted directory from a new
/// directory later installed at the same path. Device and inode bind trust to
/// the original Unix filesystem object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIdentity {
    canonical_root: PathBuf,
    device_id: u64,
    inode: u64,
}

impl WorkspaceIdentity {
    /// Captures the canonical absolute path and Unix device/inode of a directory.
    ///
    /// The filesystem root itself is never a valid project workspace because it
    /// would turn project authority into unrestricted host authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the input is not absolute, cannot be
    /// canonicalized, is not a directory, is the filesystem root, contains a
    /// non-UTF-8 component, or is captured on an unsupported platform.
    pub fn capture(root: impl AsRef<Path>) -> Result<Self, ContractError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ContractError::new(
                "workspace_identity.canonical_root",
                "workspace selection must be an absolute path",
            ));
        }

        let canonical_root = fs::canonicalize(root).map_err(|error| {
            ContractError::new(
                "workspace_identity.canonical_root",
                format!("cannot canonicalize workspace root: {error}"),
            )
        })?;
        validate_portable_path("workspace_identity.canonical_root", &canonical_root, true)?;
        if canonical_root.parent().is_none() {
            return Err(ContractError::new(
                "workspace_identity.canonical_root",
                "the filesystem root cannot be trusted as a project workspace",
            ));
        }

        let metadata = fs::metadata(&canonical_root).map_err(|error| {
            ContractError::new(
                "workspace_identity.canonical_root",
                format!("cannot inspect workspace root: {error}"),
            )
        })?;
        if !metadata.is_dir() {
            return Err(ContractError::new(
                "workspace_identity.canonical_root",
                "workspace root must be a directory",
            ));
        }

        #[cfg(unix)]
        {
            Ok(Self {
                canonical_root,
                device_id: metadata.dev(),
                inode: metadata.ino(),
            })
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(ContractError::new(
                "workspace_identity.platform",
                "workspace identity requires Unix device and inode metadata",
            ))
        }
    }

    /// Returns the canonical absolute project root.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Returns the Unix device identifier captured when trust was issued.
    #[must_use]
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Returns the Unix inode captured when trust was issued.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Verifies that the canonical path still names the captured directory object.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if the root disappeared, resolves elsewhere, or
    /// has been replaced at the same path.
    pub fn validate_current(&self) -> Result<(), ContractError> {
        let current = Self::capture(&self.canonical_root).map_err(|error| {
            ContractError::new(
                "workspace_identity.root_replaced",
                format!("trusted workspace is no longer available: {error}"),
            )
        })?;
        if current != *self {
            return Err(ContractError::new(
                "workspace_identity.root_replaced",
                "canonical workspace root no longer names the trusted directory object",
            ));
        }
        Ok(())
    }
}

/// Inputs from which the trusted issuer creates a filesystem-bound grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceGrantRequest {
    /// Stable application-generated grant identifier.
    pub grant_id: String,
    /// Absolute directory selected by the user.
    pub workspace_root: PathBuf,
    /// Project capabilities accepted by the user.
    pub permissions: WorkspacePermissions,
    /// Project-level command-network authority.
    pub network: WorkspaceNetworkPolicy,
    /// Current security-policy version.
    pub policy_version: u32,
}

/// Filesystem-bound grant issued by the production trust path.
///
/// Fields are private so arbitrary contract structs cannot masquerade as trusted
/// authority. Use [`Self::contract`] to persist or embed the wire contract and
/// [`WorkspaceGrantIssuer::validate_persisted`] to restore it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedWorkspaceGrant {
    grant: WorkspaceGrant,
    identity: WorkspaceIdentity,
}

impl IssuedWorkspaceGrant {
    /// Returns the persistable grant contract.
    #[must_use]
    pub const fn contract(&self) -> &WorkspaceGrant {
        &self.grant
    }

    /// Returns the bound filesystem identity.
    #[must_use]
    pub const fn identity(&self) -> &WorkspaceIdentity {
        &self.identity
    }

    /// Revalidates the root identity and canonical grant hash.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if any authority field, hash, path identity, or
    /// permission relationship is invalid.
    pub fn validate_integrity(&self) -> Result<(), ContractError> {
        self.grant.validate_integrity(&self.identity)
    }
}

/// Factory for new and persisted filesystem-bound workspace grants.
#[derive(Clone, Copy, Debug, Default)]
pub struct WorkspaceGrantIssuer;

impl WorkspaceGrantIssuer {
    /// Issues a grant whose hash binds authority to the live directory identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when identity capture or structural validation
    /// fails.
    pub fn issue(request: WorkspaceGrantRequest) -> Result<IssuedWorkspaceGrant, ContractError> {
        let identity = WorkspaceIdentity::capture(&request.workspace_root)?;
        let mut grant = WorkspaceGrant {
            grant_id: request.grant_id,
            canonical_root: identity.canonical_root.clone(),
            permissions: request.permissions,
            network: request.network,
            policy_version: request.policy_version,
            grant_hash: zero_digest(),
        };
        grant.validate()?;
        grant.grant_hash = canonical_grant_hash(&grant, &identity)?;

        let issued = IssuedWorkspaceGrant { grant, identity };
        issued.validate_integrity()?;
        Ok(issued)
    }

    /// Restores a persisted grant only if it still authenticates the live root.
    ///
    /// Because device and inode participate in the grant hash, replacing a
    /// directory at the same path invalidates a persisted grant without requiring
    /// a separately trusted identity record.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a replaced root, modified authority, or an
    /// invalid canonical hash.
    pub fn validate_persisted(
        grant: WorkspaceGrant,
    ) -> Result<IssuedWorkspaceGrant, ContractError> {
        let identity = WorkspaceIdentity::capture(&grant.canonical_root)?;
        grant.validate_integrity(&identity)?;
        Ok(IssuedWorkspaceGrant { grant, identity })
    }
}

impl WorkspaceGrant {
    /// Computes the domain-separated canonical hash for this grant and identity.
    ///
    /// The stored `grant_hash` field is deliberately excluded. Vector ordering or
    /// serialization-map ordering cannot affect this encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when the grant is structurally invalid, its root
    /// does not match the supplied live identity, the root was replaced, or a path
    /// is not portable normalized UTF-8.
    pub fn computed_hash(&self, identity: &WorkspaceIdentity) -> Result<Digest, ContractError> {
        self.validate()?;
        identity.validate_current()?;
        if self.canonical_root != identity.canonical_root {
            return Err(ContractError::new(
                "workspace_grant.canonical_root",
                "does not match the captured workspace identity",
            ));
        }
        canonical_grant_hash(self, identity)
    }

    /// Authenticates the grant hash and exact live workspace identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for structural invalidity, root replacement, or
    /// any hash mismatch.
    pub fn validate_integrity(&self, identity: &WorkspaceIdentity) -> Result<(), ContractError> {
        let expected = self.computed_hash(identity)?;
        if self.grant_hash != expected {
            return Err(ContractError::new(
                "workspace_grant.grant_hash",
                "does not match the canonical filesystem-bound grant hash",
            ));
        }
        Ok(())
    }
}

/// A requested command execution before trusted policy compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPolicyRequest {
    /// Stable action policy identifier.
    pub policy_id: String,
    /// Workspace-relative read authority.
    pub read_scopes: Vec<PathScope>,
    /// Workspace-relative shadow-write authority.
    pub write_scopes: Vec<PathScope>,
    /// Explicit synthetic, non-secret command environment.
    pub environment: Vec<EnvironmentVariable>,
    /// Per-action command-network request.
    pub network: ExecutionNetwork,
    /// Requested workspace mutation mode.
    pub mutation_mode: MutationMode,
    /// Process resource ceilings.
    pub resource_limits: ResourceLimits,
    /// Requested approval for an external effect.
    ///
    /// Version 0.1 grants contain no such authority, so the production compiler
    /// rejects every non-`None` value.
    pub approval_id: Option<String>,
}

/// An execution policy produced by the integrity-checked compiler.
///
/// The contained wire contract is immutable through this type. A caller may clone
/// it for persistence, but only this wrapper represents compiler-validated runner
/// authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledExecutionPolicy {
    policy: ExecutionPolicy,
}

impl CompiledExecutionPolicy {
    /// Returns the immutable execution-policy contract.
    #[must_use]
    pub const fn contract(&self) -> &ExecutionPolicy {
        &self.policy
    }

    /// Restores compiler-shaped policy bytes only after a ledger loader has
    /// revalidated the canonical hash, immutable grant, and least-authority
    /// live-state policy shape. This is crate-private and grants no new
    /// filesystem identity authority.
    pub(crate) fn from_validated_persisted_contract(policy: ExecutionPolicy) -> Self {
        Self { policy }
    }

    #[cfg(test)]
    pub(crate) fn from_test_contract(policy: ExecutionPolicy) -> Self {
        Self { policy }
    }

    /// Revalidates the policy, grant, hashes, and live root identity.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] if authority or identity changed after
    /// compilation.
    pub fn validate_integrity(&self, grant: &IssuedWorkspaceGrant) -> Result<(), ContractError> {
        self.policy.validate_integrity(grant)
    }
}

/// Compiler that converts a request into immutable, least-authority runner policy.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionPolicyCompiler;

impl ExecutionPolicyCompiler {
    /// Compiles and authenticates an execution policy from an issued grant.
    ///
    /// Scope and environment order is canonicalized before hashing. The compiler
    /// rejects command authority absent from the grant, write/read widening,
    /// protected `.git` scopes, secret or loader-control environment names,
    /// network widening, read-only writes, workspace-wide writes, and external
    /// effect approvals.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for any invalid or widened authority.
    pub fn compile(
        grant: &IssuedWorkspaceGrant,
        mut request: ExecutionPolicyRequest,
    ) -> Result<CompiledExecutionPolicy, ContractError> {
        grant.validate_integrity()?;

        request.read_scopes.sort();
        request.write_scopes.sort();
        request.environment.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.value.cmp(&right.value))
        });

        let mut policy = ExecutionPolicy {
            policy_id: request.policy_id,
            grant_hash: grant.grant.grant_hash.clone(),
            workspace_root: grant.grant.canonical_root.clone(),
            read_scopes: request.read_scopes,
            write_scopes: request.write_scopes,
            environment: request.environment,
            network: request.network,
            mutation_mode: request.mutation_mode,
            resource_limits: request.resource_limits,
            approval_id: request.approval_id,
            policy_hash: zero_digest(),
        };
        validate_production_policy(&policy, &grant.grant)?;
        policy.policy_hash = canonical_policy_hash(&policy)?;
        policy.validate_integrity(grant)?;
        Ok(CompiledExecutionPolicy { policy })
    }
}

impl ExecutionPolicy {
    /// Computes this policy's domain-separated canonical SHA-256 hash.
    ///
    /// The stored `policy_hash` is excluded. Set-like scopes and environment
    /// entries are sorted by the encoder, so input ordering cannot alter the hash.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] when a path cannot be represented as portable
    /// normalized UTF-8.
    pub fn computed_hash(&self) -> Result<Digest, ContractError> {
        canonical_policy_hash(self)
    }

    /// Authenticates a policy against an issued grant and the live workspace.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError`] for a forged or stale grant, widened authority,
    /// forbidden environment or path scope, or policy-hash mismatch.
    pub fn validate_integrity(&self, grant: &IssuedWorkspaceGrant) -> Result<(), ContractError> {
        grant.validate_integrity()?;
        validate_production_policy(self, &grant.grant)?;
        let expected = self.computed_hash()?;
        if self.policy_hash != expected {
            return Err(ContractError::new(
                "execution_policy.policy_hash",
                "does not match the canonical execution-policy hash",
            ));
        }
        Ok(())
    }
}

/// A security-relevant change that requires the user to renew project trust.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustRenewalReason {
    /// The requested canonical project path differs from the trusted path.
    CanonicalRootChanged,
    /// A different directory object now exists at the trusted path.
    CanonicalRootReplaced,
    /// The application security-policy version changed.
    SecurityPolicyVersionChanged,
    /// Command networking is being enabled for a previously offline project.
    CommandNetworkEnabled,
    /// One or more project permissions would be widened.
    PermissionAuthorityWidened,
    /// A command credential is newly requested.
    CredentialAccessRequested,
    /// Access to another filesystem root is newly requested.
    FilesystemRootRequested,
    /// A capability with external or irreversible effects is introduced.
    ExternalEffectCapabilityIntroduced,
}

/// Proposed authority used to determine whether project trust must be renewed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRenewalRequest {
    /// Proposed project root.
    pub workspace_root: PathBuf,
    /// Proposed project permissions.
    pub permissions: WorkspacePermissions,
    /// Proposed project command-network policy.
    pub network: WorkspaceNetworkPolicy,
    /// Proposed security-policy version.
    pub policy_version: u32,
    /// Whether new command credential access is requested.
    pub requests_credential_access: bool,
    /// Whether another filesystem root is requested.
    pub requests_additional_filesystem_root: bool,
    /// Whether a new external-effect capability is requested.
    pub introduces_external_effect: bool,
}

/// Computes all reasons a proposed authority requires renewed user trust.
///
/// This assessment verifies that the stored grant was originally bound to its
/// captured identity, then compares the directory currently selected by the
/// request. Same-path device/inode changes are classified as replacement rather
/// than hidden behind a generic integrity error.
///
/// # Errors
///
/// Returns [`ContractError`] if the current grant was modified after issuance or
/// the proposed root cannot be captured safely.
pub fn assess_trust_renewal(
    current: &IssuedWorkspaceGrant,
    request: &TrustRenewalRequest,
) -> Result<BTreeSet<TrustRenewalReason>, ContractError> {
    current.grant.validate()?;
    if current.grant.canonical_root != current.identity.canonical_root {
        return Err(ContractError::new(
            "workspace_grant.canonical_root",
            "does not match its issued workspace identity",
        ));
    }
    if canonical_grant_hash(&current.grant, &current.identity)? != current.grant.grant_hash {
        return Err(ContractError::new(
            "workspace_grant.grant_hash",
            "stored grant authority changed after issuance",
        ));
    }

    let proposed_identity = WorkspaceIdentity::capture(&request.workspace_root)?;
    let mut reasons = BTreeSet::new();
    if proposed_identity.canonical_root != current.identity.canonical_root {
        reasons.insert(TrustRenewalReason::CanonicalRootChanged);
    } else if proposed_identity.device_id != current.identity.device_id
        || proposed_identity.inode != current.identity.inode
    {
        reasons.insert(TrustRenewalReason::CanonicalRootReplaced);
    }
    if request.policy_version != current.grant.policy_version {
        reasons.insert(TrustRenewalReason::SecurityPolicyVersionChanged);
    }
    if current.grant.network == WorkspaceNetworkPolicy::Denied
        && request.network == WorkspaceNetworkPolicy::Allowed
    {
        reasons.insert(TrustRenewalReason::CommandNetworkEnabled);
    }
    if permissions_widen(current.grant.permissions, request.permissions) {
        reasons.insert(TrustRenewalReason::PermissionAuthorityWidened);
    }
    if request.requests_credential_access {
        reasons.insert(TrustRenewalReason::CredentialAccessRequested);
    }
    if request.requests_additional_filesystem_root {
        reasons.insert(TrustRenewalReason::FilesystemRootRequested);
    }
    if request.introduces_external_effect {
        reasons.insert(TrustRenewalReason::ExternalEffectCapabilityIntroduced);
    }
    Ok(reasons)
}

fn permissions_widen(current: WorkspacePermissions, requested: WorkspacePermissions) -> bool {
    (!current.read && requested.read)
        || (!current.write_regular_files && requested.write_regular_files)
        || (!current.execute_commands && requested.execute_commands)
        || (!current.integrate_changes && requested.integrate_changes)
        || (!current.apply_verified_changes && requested.apply_verified_changes)
}

fn validate_production_policy(
    policy: &ExecutionPolicy,
    grant: &WorkspaceGrant,
) -> Result<(), ContractError> {
    policy.validate_against(grant)?;
    if !grant.permissions.execute_commands {
        return Err(ContractError::new(
            "execution_policy.command_execution",
            "grant does not authorize non-interactive commands",
        ));
    }
    reject_duplicate_scopes("execution_policy.read_scopes", &policy.read_scopes)?;
    reject_duplicate_scopes("execution_policy.write_scopes", &policy.write_scopes)?;

    for scope in &policy.read_scopes {
        reject_explicit_git_scope("execution_policy.read_scopes", scope)?;
    }
    for scope in &policy.write_scopes {
        reject_explicit_git_scope("execution_policy.write_scopes", scope)?;
        if matches!(scope, PathScope::Workspace) {
            return Err(ContractError::new(
                "execution_policy.write_scopes",
                "workspace-wide writes include protected .git metadata and are forbidden",
            ));
        }
        if !policy
            .read_scopes
            .iter()
            .any(|read_scope| scope_covers(read_scope, scope))
        {
            return Err(ContractError::new(
                "execution_policy.write_scopes",
                "every writable scope must be contained by a readable scope",
            ));
        }
    }
    for variable in &policy.environment {
        if is_secret_or_loader_environment_name(&variable.name) {
            return Err(ContractError::new(
                "execution_policy.environment.name",
                format!(
                    "environment variable `{}` can convey credentials or inject code",
                    variable.name
                ),
            ));
        }
    }
    if policy.approval_id.is_some() {
        return Err(ContractError::new(
            "execution_policy.approval_id",
            "workspace grants do not authorize external-effect capabilities",
        ));
    }
    Ok(())
}

fn reject_duplicate_scopes(field: &'static str, scopes: &[PathScope]) -> Result<(), ContractError> {
    let mut unique = BTreeSet::new();
    for scope in scopes {
        if !unique.insert(scope) {
            return Err(ContractError::new(
                field,
                "must not contain duplicate scopes",
            ));
        }
    }
    Ok(())
}

fn reject_explicit_git_scope(field: &'static str, scope: &PathScope) -> Result<(), ContractError> {
    if let PathScope::Relative(path) = scope
        && path.components().any(|component| {
            matches!(component, Component::Normal(name)
                if name.to_str().is_some_and(|text| text.eq_ignore_ascii_case(".git")))
        })
    {
        return Err(ContractError::new(
            field,
            "protected .git metadata cannot be an explicit execution scope",
        ));
    }
    Ok(())
}

fn scope_covers(read: &PathScope, requested: &PathScope) -> bool {
    match (read, requested) {
        (PathScope::Workspace, _) => true,
        (PathScope::Relative(_), PathScope::Workspace) => false,
        (PathScope::Relative(read), PathScope::Relative(requested)) => {
            requested == read || requested.starts_with(read)
        }
    }
}

fn is_secret_or_loader_environment_name(name: &str) -> bool {
    const SECRET_EXACT: &[&str] = &[
        "API_KEY",
        "CREDENTIALS",
        "DOCKER_AUTH_CONFIG",
        "GIT_ASKPASS",
        "GPG_AGENT_INFO",
        "KUBECONFIG",
        "NETRC",
        "PASSWORD",
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        "TOKEN",
    ];
    const SECRET_PREFIXES: &[&str] = &[
        "ANTHROPIC_",
        "AWS_",
        "AZURE_",
        "CLOUDFLARE_",
        "DIGITALOCEAN_",
        "GITHUB_",
        "GITLAB_",
        "GOOGLE_",
        "NPM_",
        "OPENAI_",
        "XAI_",
    ];
    const SECRET_SUFFIXES: &[&str] = &[
        "_ACCESS_KEY",
        "_API_KEY",
        "_AUTH",
        "_CREDENTIAL",
        "_CREDENTIALS",
        "_PASSWORD",
        "_PRIVATE_KEY",
        "_SECRET",
        "_TOKEN",
    ];
    const INJECTION_EXACT: &[&str] = &[
        "BASH_ENV",
        "BASHOPTS",
        "ENV",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "NODE_OPTIONS",
        "PERL5OPT",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER",
        "SHELLOPTS",
        "ZDOTDIR",
    ];

    let upper = name.to_ascii_uppercase();
    SECRET_EXACT.contains(&upper.as_str())
        || SECRET_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || SECRET_SUFFIXES.iter().any(|suffix| upper.ends_with(suffix))
        || INJECTION_EXACT.contains(&upper.as_str())
        || upper.starts_with("DYLD_")
        || upper.starts_with("LD_")
}

fn canonical_grant_hash(
    grant: &WorkspaceGrant,
    identity: &WorkspaceIdentity,
) -> Result<Digest, ContractError> {
    if grant.canonical_root != identity.canonical_root {
        return Err(ContractError::new(
            "workspace_grant.canonical_root",
            "does not match the identity included in the canonical hash",
        ));
    }

    let mut encoder = CanonicalHasher::new(GRANT_HASH_DOMAIN);
    encoder.string("grant_id", &grant.grant_id);
    encoder.path("canonical_root", &grant.canonical_root, true)?;
    encoder.u64("root_device_id", identity.device_id);
    encoder.u64("root_inode", identity.inode);
    encoder.boolean("permission_read", grant.permissions.read);
    encoder.boolean(
        "permission_write_regular_files",
        grant.permissions.write_regular_files,
    );
    encoder.boolean(
        "permission_execute_commands",
        grant.permissions.execute_commands,
    );
    encoder.boolean(
        "permission_integrate_changes",
        grant.permissions.integrate_changes,
    );
    encoder.boolean(
        "permission_apply_verified_changes",
        grant.permissions.apply_verified_changes,
    );
    encoder.tag(
        "network",
        match grant.network {
            WorkspaceNetworkPolicy::Denied => 0,
            WorkspaceNetworkPolicy::Allowed => 1,
        },
    );
    encoder.u32("policy_version", grant.policy_version);
    Ok(encoder.finish())
}

fn canonical_policy_hash(policy: &ExecutionPolicy) -> Result<Digest, ContractError> {
    let mut encoder = CanonicalHasher::new(POLICY_HASH_DOMAIN);
    encoder.string("policy_id", &policy.policy_id);
    encoder.string("grant_hash", policy.grant_hash.as_str());
    encoder.path("workspace_root", &policy.workspace_root, true)?;

    let mut read_scopes = policy.read_scopes.clone();
    read_scopes.sort();
    encoder.scopes("read_scopes", &read_scopes)?;
    let mut write_scopes = policy.write_scopes.clone();
    write_scopes.sort();
    encoder.scopes("write_scopes", &write_scopes)?;

    let mut environment = policy.environment.clone();
    environment.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.value.cmp(&right.value))
    });
    encoder.count("environment_count", environment.len());
    for variable in &environment {
        encoder.string("environment_name", &variable.name);
        encoder.string("environment_value", &variable.value);
    }
    encoder.tag(
        "network",
        match policy.network {
            ExecutionNetwork::None => 0,
            ExecutionNetwork::FullForAction => 1,
        },
    );
    encoder.tag(
        "mutation_mode",
        match policy.mutation_mode {
            MutationMode::ReadOnly => 0,
            MutationMode::ShadowWorkspace => 1,
        },
    );
    encoder.u64("wall_time_ms", policy.resource_limits.wall_time_ms);
    encoder.u64("max_output_bytes", policy.resource_limits.max_output_bytes);
    encoder.u32("max_processes", policy.resource_limits.max_processes);
    match policy.resource_limits.max_memory_bytes {
        None => encoder.tag("max_memory_bytes_presence", 0),
        Some(bytes) => {
            encoder.tag("max_memory_bytes_presence", 1);
            encoder.u64("max_memory_bytes", bytes);
        }
    }
    match &policy.approval_id {
        None => encoder.tag("approval_id_presence", 0),
        Some(approval_id) => {
            encoder.tag("approval_id_presence", 1);
            encoder.string("approval_id", approval_id);
        }
    }
    Ok(encoder.finish())
}

struct CanonicalHasher(Sha256);

impl CanonicalHasher {
    fn new(domain: &[u8]) -> Self {
        let mut encoder = Self(Sha256::new());
        encoder.frame(domain);
        encoder
    }

    fn frame(&mut self, bytes: &[u8]) {
        let length =
            u64::try_from(bytes.len()).expect("supported targets use at most 64-bit usize");
        self.0.update(length.to_be_bytes());
        self.0.update(bytes);
    }

    fn label(&mut self, label: &str) {
        self.frame(label.as_bytes());
    }

    fn string(&mut self, label: &str, value: &str) {
        self.label(label);
        self.frame(value.as_bytes());
    }

    fn boolean(&mut self, label: &str, value: bool) {
        self.tag(label, u8::from(value));
    }

    fn tag(&mut self, label: &str, value: u8) {
        self.label(label);
        self.frame(&[value]);
    }

    fn u32(&mut self, label: &str, value: u32) {
        self.label(label);
        self.frame(&value.to_be_bytes());
    }

    fn u64(&mut self, label: &str, value: u64) {
        self.label(label);
        self.frame(&value.to_be_bytes());
    }

    fn count(&mut self, label: &str, value: usize) {
        let value = u64::try_from(value).expect("supported targets use at most 64-bit usize");
        self.u64(label, value);
    }

    fn path(
        &mut self,
        label: &'static str,
        path: &Path,
        must_be_absolute: bool,
    ) -> Result<(), ContractError> {
        let components = portable_components(label, path, must_be_absolute)?;
        self.label(label);
        self.frame(&[u8::from(path.is_absolute())]);
        self.count("path_component_count", components.len());
        for component in components {
            self.frame(component.as_bytes());
        }
        Ok(())
    }

    fn scopes(&mut self, label: &'static str, scopes: &[PathScope]) -> Result<(), ContractError> {
        self.count(label, scopes.len());
        for scope in scopes {
            match scope {
                PathScope::Workspace => self.tag("scope_kind", 0),
                PathScope::Relative(path) => {
                    self.tag("scope_kind", 1);
                    self.path("scope_path", path, false)?;
                }
            }
        }
        Ok(())
    }

    fn finish(self) -> Digest {
        digest_from_bytes(self.0.finalize().into())
    }
}

fn validate_portable_path(
    field: &'static str,
    path: &Path,
    must_be_absolute: bool,
) -> Result<(), ContractError> {
    portable_components(field, path, must_be_absolute).map(|_| ())
}

fn portable_components<'path>(
    field: &'static str,
    path: &'path Path,
    must_be_absolute: bool,
) -> Result<Vec<&'path str>, ContractError> {
    if path.is_absolute() != must_be_absolute {
        return Err(ContractError::new(
            field,
            if must_be_absolute {
                "must be an absolute portable path"
            } else {
                "must be a relative portable path"
            },
        ));
    }
    if !must_be_absolute && path.as_os_str().is_empty() {
        return Err(ContractError::new(
            field,
            "relative portable paths must not be empty",
        ));
    }

    let mut normalized = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if must_be_absolute => {}
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| {
                    ContractError::new(field, "path components must be valid UTF-8")
                })?;
                normalized.push(value);
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(ContractError::new(
                    field,
                    "path must use normalized portable components",
                ));
            }
        }
    }
    Ok(normalized)
}

fn digest_from_bytes(bytes: [u8; 32]) -> Digest {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Digest::parse(text).expect("SHA-256 always formats as a canonical digest")
}

fn zero_digest() -> Digest {
    Digest::parse("0".repeat(64)).expect("zero digest is canonical")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let unique = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "grok-build-core-trust-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn trusted_request(root: &Path) -> WorkspaceGrantRequest {
        WorkspaceGrantRequest {
            grant_id: "grant-1".into(),
            workspace_root: root.to_path_buf(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
        }
    }

    fn policy_request() -> ExecutionPolicyRequest {
        ExecutionPolicyRequest {
            policy_id: "policy-1".into(),
            read_scopes: vec![PathScope::Workspace],
            write_scopes: vec![PathScope::Relative(PathBuf::from("src"))],
            environment: vec![EnvironmentVariable {
                name: "PATH".into(),
                value: "/usr/bin:/bin".into(),
            }],
            network: ExecutionNetwork::None,
            mutation_mode: MutationMode::ShadowWorkspace,
            resource_limits: ResourceLimits {
                wall_time_ms: 10_000,
                max_output_bytes: 1_000_000,
                max_processes: 8,
                max_memory_bytes: Some(512_000_000),
            },
            approval_id: None,
        }
    }

    #[test]
    fn issued_grant_authenticates_authority_and_restores() {
        let root = TestDirectory::new("issue");
        let issued = WorkspaceGrantIssuer::issue(trusted_request(&root.0)).expect("issue grant");
        issued.validate_integrity().expect("valid issued grant");

        let restored = WorkspaceGrantIssuer::validate_persisted(issued.contract().clone())
            .expect("restore authenticated grant");
        assert_eq!(restored, issued);

        let mut tampered = issued.contract().clone();
        tampered.network = WorkspaceNetworkPolicy::Allowed;
        assert_eq!(
            WorkspaceGrantIssuer::validate_persisted(tampered)
                .expect_err("modified authority must invalidate hash")
                .field(),
            "workspace_grant.grant_hash"
        );
    }

    #[test]
    fn identity_rejects_same_path_directory_replacement() {
        let root = TestDirectory::new("replace");
        let identity = WorkspaceIdentity::capture(&root.0).expect("capture identity");
        let displaced = root.0.with_extension("displaced");
        fs::rename(&root.0, &displaced).expect("move trusted directory");
        fs::create_dir(&root.0).expect("create replacement at same path");

        assert_eq!(
            identity
                .validate_current()
                .expect_err("same-path replacement must fail")
                .field(),
            "workspace_identity.root_replaced"
        );
        fs::remove_dir_all(displaced).expect("remove displaced directory");
    }

    #[test]
    fn grant_hash_is_domain_separated_length_framed_and_stable() {
        let identity = WorkspaceIdentity {
            canonical_root: PathBuf::from("/work/project"),
            device_id: 42,
            inode: 9001,
        };
        let grant = WorkspaceGrant {
            grant_id: "grant-1".into(),
            canonical_root: identity.canonical_root.clone(),
            permissions: WorkspacePermissions::trusted(),
            network: WorkspaceNetworkPolicy::Denied,
            policy_version: 1,
            grant_hash: zero_digest(),
        };
        let first = canonical_grant_hash(&grant, &identity).expect("canonical hash");
        let second = canonical_grant_hash(&grant, &identity).expect("canonical hash");
        assert_eq!(first, second);

        let mut changed = grant;
        changed.grant_id = "grant-1\0suffix".into();
        assert_ne!(
            first,
            canonical_grant_hash(&changed, &identity).expect("length-framed hash")
        );
    }

    #[test]
    fn policy_compiler_canonicalizes_order_and_detects_tampering() {
        let root = TestDirectory::new("policy");
        let grant = WorkspaceGrantIssuer::issue(trusted_request(&root.0)).expect("issue grant");

        let mut first_request = policy_request();
        first_request
            .read_scopes
            .push(PathScope::Relative(PathBuf::from("src")));
        first_request.environment.push(EnvironmentVariable {
            name: "LANG".into(),
            value: "C.UTF-8".into(),
        });
        let mut second_request = first_request.clone();
        second_request.read_scopes.reverse();
        second_request.environment.reverse();

        let first = ExecutionPolicyCompiler::compile(&grant, first_request).expect("compile");
        let second = ExecutionPolicyCompiler::compile(&grant, second_request).expect("compile");
        assert_eq!(first, second);
        first.validate_integrity(&grant).expect("valid policy");

        let mut tampered = first.contract().clone();
        tampered.resource_limits.max_processes += 1;
        assert_eq!(
            tampered
                .validate_integrity(&grant)
                .expect_err("modified policy must fail hash")
                .field(),
            "execution_policy.policy_hash"
        );
    }

    #[test]
    fn policy_compiler_rejects_authority_widening() {
        let root = TestDirectory::new("widening");
        let denied = WorkspaceGrantIssuer::issue(trusted_request(&root.0)).expect("issue grant");

        let mut network = policy_request();
        network.network = ExecutionNetwork::FullForAction;
        assert_eq!(
            ExecutionPolicyCompiler::compile(&denied, network)
                .expect_err("network widening must fail")
                .field(),
            "execution_policy.network"
        );

        let mut uncovered_write = policy_request();
        uncovered_write.read_scopes = vec![PathScope::Relative(PathBuf::from("tests"))];
        assert_eq!(
            ExecutionPolicyCompiler::compile(&denied, uncovered_write)
                .expect_err("writes must be contained by reads")
                .field(),
            "execution_policy.write_scopes"
        );

        let mut read_only_write = policy_request();
        read_only_write.mutation_mode = MutationMode::ReadOnly;
        assert_eq!(
            ExecutionPolicyCompiler::compile(&denied, read_only_write)
                .expect_err("read-only mode cannot write")
                .field(),
            "execution_policy.write_scopes"
        );

        let read_only_grant = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            permissions: WorkspacePermissions::read_only(),
            ..trusted_request(&root.0)
        })
        .expect("issue read-only grant");
        let mut read_only_policy = policy_request();
        read_only_policy.write_scopes.clear();
        read_only_policy.mutation_mode = MutationMode::ReadOnly;
        assert_eq!(
            ExecutionPolicyCompiler::compile(&read_only_grant, read_only_policy)
                .expect_err("command authority absent from grant")
                .field(),
            "execution_policy.command_execution"
        );
    }

    #[test]
    fn policy_compiler_rejects_git_credentials_loaders_and_external_effects() {
        let root = TestDirectory::new("forbidden");
        let grant = WorkspaceGrantIssuer::issue(trusted_request(&root.0)).expect("issue grant");

        for forbidden_scope in [".git", ".GIT/config", "src/.git/objects"] {
            let mut request = policy_request();
            request.read_scopes = vec![PathScope::Relative(PathBuf::from(forbidden_scope))];
            request.write_scopes.clear();
            request.mutation_mode = MutationMode::ReadOnly;
            assert_eq!(
                ExecutionPolicyCompiler::compile(&grant, request)
                    .expect_err(".git scope must fail")
                    .field(),
                "execution_policy.read_scopes"
            );
        }

        let mut workspace_write = policy_request();
        workspace_write.write_scopes = vec![PathScope::Workspace];
        assert_eq!(
            ExecutionPolicyCompiler::compile(&grant, workspace_write)
                .expect_err("workspace write includes .git")
                .field(),
            "execution_policy.write_scopes"
        );

        for forbidden_name in ["XAI_API_KEY", "ld_preload", "RUSTC_WRAPPER"] {
            let mut request = policy_request();
            request.environment = vec![EnvironmentVariable {
                name: forbidden_name.into(),
                value: "never-forward-this".into(),
            }];
            assert_eq!(
                ExecutionPolicyCompiler::compile(&grant, request)
                    .expect_err("credential or injection variable must fail")
                    .field(),
                "execution_policy.environment.name"
            );
        }

        let mut external_effect = policy_request();
        external_effect.approval_id = Some("approval-1".into());
        assert_eq!(
            ExecutionPolicyCompiler::compile(&grant, external_effect)
                .expect_err("grant has no external-effect authority")
                .field(),
            "execution_policy.approval_id"
        );
    }

    #[test]
    fn trust_renewal_reports_every_authority_change() {
        let root = TestDirectory::new("renew-current");
        let other = TestDirectory::new("renew-other");
        let current = WorkspaceGrantIssuer::issue(WorkspaceGrantRequest {
            permissions: WorkspacePermissions::read_only(),
            ..trusted_request(&root.0)
        })
        .expect("issue grant");

        let reasons = assess_trust_renewal(
            &current,
            &TrustRenewalRequest {
                workspace_root: other.0.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Allowed,
                policy_version: 2,
                requests_credential_access: true,
                requests_additional_filesystem_root: true,
                introduces_external_effect: true,
            },
        )
        .expect("assess renewal");

        assert_eq!(
            reasons,
            BTreeSet::from([
                TrustRenewalReason::CanonicalRootChanged,
                TrustRenewalReason::SecurityPolicyVersionChanged,
                TrustRenewalReason::CommandNetworkEnabled,
                TrustRenewalReason::PermissionAuthorityWidened,
                TrustRenewalReason::CredentialAccessRequested,
                TrustRenewalReason::FilesystemRootRequested,
                TrustRenewalReason::ExternalEffectCapabilityIntroduced,
            ])
        );
    }

    #[test]
    fn trust_renewal_classifies_same_path_replacement() {
        let root = TestDirectory::new("renew-replace");
        let current = WorkspaceGrantIssuer::issue(trusted_request(&root.0)).expect("issue grant");
        let displaced = root.0.with_extension("old");
        fs::rename(&root.0, &displaced).expect("move original root");
        fs::create_dir(&root.0).expect("create replacement root");

        let reasons = assess_trust_renewal(
            &current,
            &TrustRenewalRequest {
                workspace_root: root.0.clone(),
                permissions: WorkspacePermissions::trusted(),
                network: WorkspaceNetworkPolicy::Denied,
                policy_version: 1,
                requests_credential_access: false,
                requests_additional_filesystem_root: false,
                introduces_external_effect: false,
            },
        )
        .expect("classify replacement");
        assert_eq!(
            reasons,
            BTreeSet::from([TrustRenewalReason::CanonicalRootReplaced])
        );
        fs::remove_dir_all(displaced).expect("remove displaced directory");
    }
}
