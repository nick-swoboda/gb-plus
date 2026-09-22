#![allow(unsafe_code)]

use std::ffi::{CString, OsString, c_void};
use std::fs;
#[cfg(feature = "broker-fixture")]
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
#[cfg(feature = "broker-fixture")]
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use core_foundation::base::TCFType as _;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::CFURL;
use objc2_core_foundation::{
    CFArray as ObjcCFArray, CFRetained as ObjcCFRetained, CFString as ObjcCFString,
};
#[cfg(feature = "broker-fixture")]
use objc2_security::{SecACL, SecKeychainPromptSelector};
use objc2_security::{
    SecAccess, SecItemAttr, SecItemClass, SecKeychain, SecKeychainAttribute,
    SecKeychainAttributeList, SecKeychainItem, SecTrustedApplication,
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, generic_password, get_generic_password,
};
use security_framework_sys::item::kSecUseAuthenticationUI;
use sha2::{Digest as _, Sha256};

use crate::protocol::{
    BrokerAction, BrokerNamespace, BrokerSecret, CredentialTarget, CredentialVersion,
    MAX_SECRET_BYTES, McpCredentialKey, Request, Response, ResponseStatus,
};
use crate::{PARENT_CODE_IDENTIFIER, PROVIDER_KEYCHAIN_SERVICE, provider_account};

const MAX_HELPER_BYTES: u64 = 32 * 1024 * 1024;
const NONINTERACTIVE_TIMEOUT: Duration = Duration::from_secs(8);
const INTERACTIVE_TIMEOUT: Duration = Duration::from_mins(5);
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
const ERR_SEC_AUTH_FAILED: i32 = -25_293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25_308;
const ERR_SEC_USER_CANCELED: i32 = -128;
const LAUNCHD_LABEL_PREFIX: &str = "org.grok-build.desktop.credential-broker.once";
const IPC_DIRECTORY_PREFIX: &str = "grok-build-keychain-broker-ipc.";
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

unsafe extern "C" {
    #[link_name = "kSecUseAuthenticationUIFail"]
    static K_SEC_USE_AUTHENTICATION_UI_FAIL: CFStringRef;
}

/// Immutable configuration used to validate and launch the stable helper.
#[derive(Clone, Debug)]
pub struct BrokerClientConfig {
    namespace: BrokerNamespace,
    helper_path: PathBuf,
    expected_sha256: [u8; 32],
    expected_helper_cdhash: String,
    temporary_directory: PathBuf,
    helper_arguments: Vec<OsString>,
}

impl BrokerClientConfig {
    /// Resolves the fixed helper path relative to the running app executable.
    ///
    /// # Errors
    ///
    /// Refuses a non-bundled executable, invalid signer/hash, or unexpected
    /// bundle layout.
    pub fn for_current_app(
        expected_sha256: &str,
        expected_helper_cdhash: &str,
        parent_signing_identity: &str,
    ) -> Result<Self, String> {
        Self::for_namespace(
            expected_sha256,
            expected_helper_cdhash,
            parent_signing_identity,
            BrokerNamespace::Provider,
        )
    }

    /// Resolve the separate MCP-only helper from the current signed app bundle.
    ///
    /// # Errors
    /// Refuses the same path, hash, signer and owner failures as provider setup.
    pub fn for_current_app_mcp(
        expected_sha256: &str,
        expected_helper_cdhash: &str,
        parent_signing_identity: &str,
    ) -> Result<Self, String> {
        Self::for_namespace(
            expected_sha256,
            expected_helper_cdhash,
            parent_signing_identity,
            BrokerNamespace::Mcp,
        )
    }

    fn for_namespace(
        expected_sha256: &str,
        expected_helper_cdhash: &str,
        parent_signing_identity: &str,
        namespace: BrokerNamespace,
    ) -> Result<Self, String> {
        validated_fingerprint(parent_signing_identity)?;
        let expected_sha256 = parse_sha256(expected_sha256)?;
        let expected_helper_cdhash = validated_cdhash(expected_helper_cdhash)?;
        let executable = fs::canonicalize(
            std::env::current_exe()
                .map_err(|error| format!("cannot resolve the Grok Build+ executable: {error}"))?,
        )
        .map_err(|error| format!("cannot canonicalize the Grok Build+ executable: {error}"))?;
        if executable.file_name().and_then(|name| name.to_str()) != Some("grok-build-tauri") {
            return Err(
                "Stable API-key reconnect requires the bundled Grok Build+ executable.".into(),
            );
        }
        let macos = executable
            .parent()
            .ok_or_else(|| "Bundled Grok Build+ executable has no MacOS directory.".to_owned())?;
        if macos.file_name().and_then(|name| name.to_str()) != Some("MacOS") {
            return Err("Stable API-key reconnect refused an unexpected app layout.".into());
        }
        let contents = macos.parent().ok_or_else(|| {
            "Bundled Grok Build+ executable has no Contents directory.".to_owned()
        })?;
        let helper_path = contents.join("Helpers").join(namespace.executable());
        Ok(Self {
            namespace,
            helper_path,
            expected_sha256,
            helper_arguments: vec![OsString::from("--launchd-once")],
            expected_helper_cdhash,
            temporary_directory: validated_temporary_directory()?,
        })
    }

    #[cfg(feature = "broker-fixture")]
    fn for_fixture(
        helper_path: PathBuf,
        expected_sha256: &str,
        expected_helper_cdhash: &str,
        parent_signing_identity: &str,
        helper_arguments: Vec<OsString>,
    ) -> Result<Self, String> {
        validated_fingerprint(parent_signing_identity)?;
        Ok(Self {
            namespace: BrokerNamespace::Provider,
            helper_path,
            expected_sha256: parse_sha256(expected_sha256)?,
            expected_helper_cdhash: validated_cdhash(expected_helper_cdhash)?,
            temporary_directory: validated_temporary_directory()?,
            helper_arguments,
        })
    }
}

/// Verified client for one stable helper executable.
#[derive(Clone, Debug)]
pub struct BrokerClient {
    config: BrokerClientConfig,
}

impl BrokerClient {
    /// Creates a client after validating the helper on disk.
    ///
    /// # Errors
    ///
    /// Refuses missing, mutable, altered, incorrectly signed, or misplaced
    /// helper code.
    pub fn new(config: BrokerClientConfig) -> Result<Self, String> {
        let client = Self { config };
        client.validate_helper_on_disk()?;
        Ok(client)
    }

    /// Inspects one exact version without returning secret bytes.
    ///
    /// # Errors
    ///
    /// Refuses an invalid helper, peer, frame, or Keychain result.
    pub fn inspect(&self, version: CredentialVersion) -> Result<bool, String> {
        match self.request_target(
            BrokerAction::Inspect,
            CredentialTarget::Provider(version),
            None,
        )? {
            BrokerReply::Ok(None) => Ok(true),
            BrokerReply::Absent => Ok(false),
            BrokerReply::Ok(Some(_)) => {
                Err("Keychain broker returned secret data during a presence check.".into())
            }
        }
    }

    /// Loads one exact version, optionally permitting an explicit macOS prompt.
    ///
    /// # Errors
    ///
    /// Refuses an invalid helper, peer, frame, secret, or Keychain result.
    pub fn load(
        &self,
        version: CredentialVersion,
        allow_interaction: bool,
    ) -> Result<Option<BrokerSecret>, String> {
        let action = if allow_interaction {
            BrokerAction::LoadInteractive
        } else {
            BrokerAction::LoadWithoutUi
        };
        match self.request_target(action, CredentialTarget::Provider(version), None)? {
            BrokerReply::Ok(Some(secret)) => Ok(Some(secret)),
            BrokerReply::Absent => Ok(None),
            BrokerReply::Ok(None) => {
                Err("Keychain broker returned no credential for a successful load.".into())
            }
        }
    }

    /// Stores the broker-owned v3 item. This is an explicit flow only.
    ///
    /// # Errors
    ///
    /// Refuses invalid secret bytes or any helper, peer, frame, or Keychain
    /// failure.
    pub fn store_v3(&self, secret: &[u8]) -> Result<(), String> {
        validate_secret(secret)?;
        match self.request_target(
            BrokerAction::Store,
            CredentialTarget::Provider(CredentialVersion::BrokerV3),
            Some(secret),
        )? {
            BrokerReply::Ok(None) => Ok(()),
            BrokerReply::Absent | BrokerReply::Ok(Some(_)) => {
                Err("Keychain broker returned an invalid store outcome.".into())
            }
        }
    }

    /// Deletes one exact credential generation during explicit cleanup.
    ///
    /// # Errors
    ///
    /// Refuses an invalid helper, peer, frame, or Keychain result.
    pub fn delete(&self, version: CredentialVersion) -> Result<(), String> {
        match self.request_target(
            BrokerAction::Delete,
            CredentialTarget::Provider(version),
            None,
        )? {
            BrokerReply::Ok(None) | BrokerReply::Absent => Ok(()),
            BrokerReply::Ok(Some(_)) => {
                Err("Keychain broker returned secret data during deletion.".into())
            }
        }
    }

    /// Load only the MCP namespace item for this app-issued binding.
    ///
    /// # Errors
    /// Refuses unavailable peers, invalid frames, or denied Keychain interaction.
    pub fn load_mcp(
        &self,
        key: McpCredentialKey,
        allow_interaction: bool,
    ) -> Result<Option<BrokerSecret>, String> {
        let action = if allow_interaction {
            BrokerAction::LoadInteractive
        } else {
            BrokerAction::LoadWithoutUi
        };
        match self.request_target(action, CredentialTarget::Mcp(key), None)? {
            BrokerReply::Ok(Some(secret)) => Ok(Some(secret)),
            BrokerReply::Absent => Ok(None),
            BrokerReply::Ok(None) => Err("Keychain MCP load omitted its secret frame.".into()),
        }
    }
    /// Store bounded compact JSON credentials in the fixed MCP namespace.
    ///
    /// # Errors
    /// Refuses secret/frame/peer validation or Keychain storage failure.
    pub fn store_mcp(&self, key: McpCredentialKey, secret: &[u8]) -> Result<(), String> {
        validate_secret(secret)?;
        match self.request_target(
            BrokerAction::Store,
            CredentialTarget::Mcp(key),
            Some(secret),
        )? {
            BrokerReply::Ok(None) => Ok(()),
            _ => Err("Keychain MCP store returned an invalid response.".into()),
        }
    }
    /// Delete this exact MCP binding without touching the xAI provider account.
    ///
    /// # Errors
    /// Refuses peer/frame validation or Keychain deletion failure.
    pub fn delete_mcp(&self, key: McpCredentialKey) -> Result<(), String> {
        match self.request_target(BrokerAction::Delete, CredentialTarget::Mcp(key), None)? {
            BrokerReply::Ok(None) | BrokerReply::Absent => Ok(()),
            BrokerReply::Ok(Some(_)) => {
                Err("Keychain MCP delete returned an invalid response.".into())
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the one-shot authenticated broker transaction stays linear for security review"
    )]
    fn request_target(
        &self,
        action: BrokerAction,
        target: CredentialTarget,
        secret: Option<&[u8]>,
    ) -> Result<BrokerReply, String> {
        if !self.config.namespace.accepts(target) {
            return Err(
                "Keychain client refused a request for a different helper namespace.".into(),
            );
        }
        self.validate_helper_on_disk()?;
        let (ipc_guard, listener) = create_ipc_listener(&self.config.temporary_directory)?;
        let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let label = format!(
            "{LAUNCHD_LABEL_PREFIX}.{}.{}",
            std::process::id(),
            request_id
        );
        let broker_stdout = ipc_guard.root.join("broker.stdout");
        let broker_stderr = ipc_guard.root.join("broker.stderr");
        let mut submit = Command::new("/bin/launchctl");
        submit
            .args(["submit", "-l", &label, "-o"])
            .arg(&broker_stdout)
            .arg("-e")
            .arg(&broker_stderr)
            .arg("--")
            .arg(&self.config.helper_path)
            .args(&self.config.helper_arguments)
            .arg(&ipc_guard.socket_path)
            .arg(std::process::id().to_string())
            .arg(&self.config.expected_helper_cdhash)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut submit = submit
            .spawn()
            .map_err(|error| format!("cannot submit the verified Keychain broker: {error}"))?;
        wait_for_child(&mut submit, NONINTERACTIVE_TIMEOUT)?;
        let status = submit
            .wait()
            .map_err(|error| format!("cannot collect launchd broker submission: {error}"))?;
        if !status.success() {
            return Err("launchd refused the one-shot Keychain broker job.".into());
        }
        let _job_guard = LaunchdJobGuard::new(label);
        let mut stream = accept_broker(&listener, NONINTERACTIVE_TIMEOUT)?;
        let broker_pid = socket_peer_pid(&stream)?;
        validate_live_code(
            broker_pid,
            &self.config.helper_path,
            self.config.namespace.identifier(),
            CodeIdentity::CdHash(&self.config.expected_helper_cdhash),
        )
        .map_err(|reason| format!("Keychain broker peer validation refused launchd: {reason}"))?;
        let timeout = if action == BrokerAction::LoadWithoutUi || action == BrokerAction::Inspect {
            NONINTERACTIVE_TIMEOUT
        } else {
            INTERACTIVE_TIMEOUT
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("cannot bound the Keychain broker response: {error}"))?;
        stream
            .set_write_timeout(Some(NONINTERACTIVE_TIMEOUT))
            .map_err(|error| format!("cannot bound the Keychain broker request: {error}"))?;
        match target {
            CredentialTarget::Provider(version) => {
                Request::write_to(action, version, secret, &mut stream)?;
            }
            CredentialTarget::Mcp(key) => Request::write_mcp_to(action, key, secret, &mut stream)?,
        }
        let response = match Response::read_socket_frame(&mut stream) {
            Ok(response) => response,
            Err(reason) => {
                std::thread::sleep(Duration::from_millis(250));
                let diagnostic = read_bounded_broker_diagnostic(&broker_stderr);
                if action == BrokerAction::LoadWithoutUi {
                    return Err(
                        "Saved API key did not return a verified response inside the no-UI boundary; automatic reconnect failed closed and the one-shot broker was stopped. Connect explicitly from Account."
                            .into(),
                    );
                }
                return if diagnostic.is_empty() {
                    Err(reason)
                } else {
                    Err(format!("{reason} Broker detail: {diagnostic}"))
                };
            }
        };
        if socket_has_trailing_data(&stream)? {
            return Err("Keychain broker client refused trailing response bytes.".into());
        }
        match response.status {
            ResponseStatus::Ok => {
                if action == BrokerAction::LoadInteractive || action == BrokerAction::LoadWithoutUi
                {
                    Ok(BrokerReply::Ok(Some(response.take_secret()?)))
                } else if response.payload.is_empty() {
                    Ok(BrokerReply::Ok(None))
                } else {
                    Err("Keychain broker returned an unexpected success payload.".into())
                }
            }
            ResponseStatus::Absent => Ok(BrokerReply::Absent),
            ResponseStatus::Refused | ResponseStatus::Error => {
                let reason = response.message_text();
                if reason.is_empty() {
                    Err("Keychain broker refused without a bounded reason.".into())
                } else {
                    Err(reason)
                }
            }
        }
    }

    fn validate_helper_on_disk(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.config.helper_path).map_err(|error| {
            format!(
                "cannot inspect the stable Keychain broker {}: {error}",
                self.config.helper_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("Stable Keychain broker is not a regular non-symlink file.".into());
        }
        if metadata.len() == 0 || metadata.len() > MAX_HELPER_BYTES {
            return Err("Stable Keychain broker has an invalid file size.".into());
        }
        if metadata.uid() != unsafe { libc::getuid() } || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("Stable Keychain broker is not owner-controlled.".into());
        }
        let bytes = fs::read(&self.config.helper_path)
            .map_err(|error| format!("cannot read the stable Keychain broker: {error}"))?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != self.config.expected_sha256 {
            return Err("Stable Keychain broker SHA-256 does not match the signed release.".into());
        }
        validate_static_code(
            &self.config.helper_path,
            self.config.namespace.identifier(),
            CodeIdentity::CdHash(&self.config.expected_helper_cdhash),
        )
    }
}

enum BrokerReply {
    Ok(Option<BrokerSecret>),
    Absent,
}

struct IpcGuard {
    root: PathBuf,
    socket_path: PathBuf,
}

impl Drop for IpcGuard {
    fn drop(&mut self) {
        if self.socket_path.parent() == Some(self.root.as_path())
            && self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(IPC_DIRECTORY_PREFIX))
        {
            let _ = fs::remove_file(&self.socket_path);
            let _ = fs::remove_file(self.root.join("broker.stdout"));
            let _ = fs::remove_file(self.root.join("broker.stderr"));
            let _ = fs::remove_dir(&self.root);
        }
    }
}

struct LaunchdJobGuard {
    label: String,
}

impl LaunchdJobGuard {
    fn new(label: String) -> Self {
        Self { label }
    }
}

impl Drop for LaunchdJobGuard {
    fn drop(&mut self) {
        if !self.label.starts_with(LAUNCHD_LABEL_PREFIX) {
            return;
        }
        let _ = Command::new("/bin/launchctl")
            .args(["remove", &self.label])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn create_ipc_listener(base: &Path) -> Result<(IpcGuard, UnixListener), String> {
    for _ in 0..8 {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!(
            "{IPC_DIRECTORY_PREFIX}{}.{}",
            std::process::id(),
            sequence
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&root) {
            Ok(()) => {
                let socket_path = root.join("broker.sock");
                let listener = UnixListener::bind(&socket_path).map_err(|error| {
                    let _ = fs::remove_dir(&root);
                    format!("cannot bind the private Keychain broker socket: {error}")
                })?;
                fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(
                    |error| {
                        let _ = fs::remove_file(&socket_path);
                        let _ = fs::remove_dir(&root);
                        format!("cannot protect the private Keychain broker socket: {error}")
                    },
                )?;
                listener
                    .set_nonblocking(true)
                    .map_err(|error| format!("cannot bound broker socket acceptance: {error}"))?;
                return Ok((IpcGuard { root, socket_path }, listener));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create the private Keychain broker socket directory: {error}"
                ));
            }
        }
    }
    Err("Keychain broker could not allocate a unique private socket directory.".into())
}

fn accept_broker(listener: &UnixListener, timeout: Duration) -> Result<UnixStream, String> {
    let started = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|error| {
                    format!("cannot restore blocking broker stream semantics: {error}")
                })?;
                return Ok(stream);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < timeout =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("launchd Keychain broker did not connect before the deadline.".into());
            }
            Err(error) => {
                return Err(format!(
                    "cannot accept the launchd Keychain broker connection: {error}"
                ));
            }
        }
    }
}

fn socket_peer_pid(stream: &UnixStream) -> Result<i32, String> {
    let mut pid: libc::pid_t = 0;
    let mut length = libc::socklen_t::try_from(std::mem::size_of_val(&pid))
        .map_err(|_| "socket peer PID length is invalid.".to_owned())?;
    // SAFETY: pid and length are valid writable buffers for LOCAL_PEERPID.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::from_mut(&mut pid).cast::<c_void>(),
            std::ptr::from_mut(&mut length),
        )
    };
    if status != 0 || length as usize != std::mem::size_of_val(&pid) || pid <= 1 {
        Err("Keychain broker could not establish the Unix peer PID.".into())
    } else {
        Ok(pid)
    }
}

fn socket_has_trailing_data(stream: &UnixStream) -> Result<bool, String> {
    let mut byte = [0_u8; 1];
    // SAFETY: byte is a valid writable one-byte buffer and MSG_PEEK leaves the
    // authenticated stream unchanged.
    let result = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            byte.as_mut_ptr().cast::<c_void>(),
            byte.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    match result.cmp(&0) {
        std::cmp::Ordering::Greater => Ok(true),
        std::cmp::Ordering::Equal => Ok(false),
        std::cmp::Ordering::Less => {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                Ok(false)
            } else {
                Err(format!(
                    "Keychain broker could not inspect socket framing: {error}"
                ))
            }
        }
    }
}

fn read_bounded_broker_diagnostic(path: &Path) -> String {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return format!("diagnostic file unavailable: {error}"),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.len() > 4096
    {
        return format!(
            "diagnostic file refused (file={}, owner={}, bytes={})",
            metadata.is_file(),
            metadata.uid(),
            metadata.len()
        );
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return format!("diagnostic file could not be read: {error}"),
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return "diagnostic file was not UTF-8".into();
    };
    let text: String = text
        .trim()
        .replace(['\r', '\n'], " ")
        .chars()
        .take(2048)
        .collect();
    if text.is_empty() {
        "diagnostic file was empty".into()
    } else {
        text
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                terminate_child(child);
                return Err("Keychain broker timed out and was stopped without success.".into());
            }
            Err(error) => {
                terminate_child(child);
                return Err(format!("cannot observe the Keychain broker: {error}"));
            }
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Clone)]
struct ServerConfig {
    namespace: BrokerNamespace,
    service: String,
    mcp_service: String,
    accounts: [String; 3],
    expected_parent_pid: i32,
    expected_parent_executable: String,
    expected_parent_identifier: String,
    expected_helper_cdhash: String,
    parent_signing_identity: String,
}

impl ServerConfig {
    fn account(&self, version: CredentialVersion) -> &str {
        &self.accounts[version as usize - 1]
    }
}

pub(crate) fn run_production_server(namespace: BrokerNamespace) -> Result<(), String> {
    let parent_signing_identity = validated_fingerprint(env!("GROK_BUILD_SIGNING_IDENTITY"))?;
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments.len() != 4 || arguments[0] != "--launchd-once" {
        return Err("Keychain broker requires its exact one-shot launchd socket contract.".into());
    }
    let socket_path = PathBuf::from(&arguments[1]);
    let expected_parent_pid = arguments[2]
        .to_str()
        .ok_or_else(|| "Keychain broker parent PID is not UTF-8.".to_owned())?
        .parse::<i32>()
        .map_err(|_| "Keychain broker parent PID is invalid.".to_owned())?;
    let expected_helper_cdhash = validated_cdhash(
        arguments[3]
            .to_str()
            .ok_or_else(|| "Keychain broker CDHash argument is not UTF-8.".to_owned())?,
    )?;
    let helper = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot resolve the Keychain broker executable: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize the Keychain broker executable: {error}"))?;
    if helper.file_name().and_then(|name| name.to_str()) != Some(namespace.executable()) {
        return Err("Keychain broker refused an unexpected executable name.".into());
    }
    let helpers = helper
        .parent()
        .ok_or_else(|| "Keychain broker has no Helpers directory.".to_owned())?;
    if helpers.file_name().and_then(|name| name.to_str()) != Some("Helpers") {
        return Err("Keychain broker refused an unexpected bundle location.".into());
    }
    let config = ServerConfig {
        namespace,
        service: PROVIDER_KEYCHAIN_SERVICE.to_owned(),
        mcp_service: crate::MCP_KEYCHAIN_SERVICE.to_owned(),
        accounts: [
            provider_account(CredentialVersion::LegacyV1),
            provider_account(CredentialVersion::StableV2),
            provider_account(CredentialVersion::BrokerV3),
        ],
        expected_parent_pid,
        expected_parent_executable: "grok-build-tauri".to_owned(),
        expected_parent_identifier: PARENT_CODE_IDENTIFIER.to_owned(),
        expected_helper_cdhash,
        parent_signing_identity,
    };
    serve(&config, &socket_path)
}

fn serve(config: &ServerConfig, socket_path: &Path) -> Result<(), String> {
    fixture_trace("serve-start");
    validate_launchd_environment()?;
    let self_path = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot resolve the Keychain broker executable: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize the Keychain broker executable: {error}"))?;
    validate_static_code(
        &self_path,
        config.namespace.identifier(),
        CodeIdentity::CdHash(&config.expected_helper_cdhash),
    )?;
    fixture_trace("self-valid");
    validate_socket_path(socket_path)?;
    let mut stream = UnixStream::connect(socket_path).map_err(|error| {
        format!("Keychain broker could not connect its private socket: {error}")
    })?;
    fixture_trace("socket-connected");
    stream
        .set_read_timeout(Some(INTERACTIVE_TIMEOUT))
        .map_err(|error| format!("Keychain broker could not bound its request read: {error}"))?;
    stream
        .set_write_timeout(Some(NONINTERACTIVE_TIMEOUT))
        .map_err(|error| format!("Keychain broker could not bound its response write: {error}"))?;
    let peer_pid = socket_peer_pid(&stream)?;
    fixture_trace("peer-pid-read");
    let validation = if peer_pid == config.expected_parent_pid {
        validate_live_app_code(
            peer_pid,
            &config.expected_parent_executable,
            &config.expected_parent_identifier,
            &config.parent_signing_identity,
        )
    } else {
        Err("Keychain broker refused an unexpected socket peer PID.".into())
    };
    if let Err(reason) = validation {
        fixture_trace("peer-refused");
        return Response::refused(&format!("Keychain broker refused its peer: {reason}"))
            .write_to(&mut stream);
    }
    fixture_trace("peer-valid");
    let request = match Request::read_socket_frame(&mut stream) {
        Ok(request) => request,
        Err(reason) => return Response::refused(&reason).write_to(&mut stream),
    };
    if socket_has_trailing_data(&stream)? {
        return Response::refused("Keychain broker refused trailing request bytes.")
            .write_to(&mut stream);
    }
    fixture_trace("request-read");
    let response = execute_request(config, &request);
    fixture_trace("request-executed");
    if let Err(reason) = peer_is_unchanged(&stream, config) {
        fixture_trace("peer-changed");
        return Response::refused(&reason).write_to(&mut stream);
    }
    fixture_trace("response-writing");
    let written = response.write_to(&mut stream);
    fixture_trace(if written.is_ok() {
        "response-written"
    } else {
        "response-write-failed"
    });
    written
}

#[cfg(feature = "broker-fixture")]
fn fixture_trace(stage: &str) {
    eprintln!("fixture-stage={stage}");
}

#[cfg(not(feature = "broker-fixture"))]
fn fixture_trace(_stage: &str) {}

fn execute_request(config: &ServerConfig, request: &Request) -> Response {
    if !config.namespace.accepts(request.target) {
        return Response::refused("Keychain helper refused a different credential namespace.");
    }
    let (service, account) = match request.target {
        CredentialTarget::Provider(version) => {
            (config.service.clone(), config.account(version).to_owned())
        }
        CredentialTarget::Mcp(key) => (config.mcp_service.clone(), key.account()),
    };
    let account = account.as_str();
    match request.action {
        BrokerAction::Inspect => match inspect_secret(&service, account) {
            Ok(true) => Response::ok(None),
            Ok(false) => Response::absent(),
            Err(failure) => failure.response(),
        },
        BrokerAction::LoadInteractive => match load_secret(&service, account, true) {
            Ok(Some(secret)) => Response::ok(Some(secret.as_slice())),
            Ok(None) => Response::absent(),
            Err(failure) => failure.response(),
        },
        BrokerAction::LoadWithoutUi => match load_secret(&service, account, false) {
            Ok(Some(secret)) => Response::ok(Some(secret.as_slice())),
            Ok(None) => Response::absent(),
            Err(failure) => failure.response(),
        },
        BrokerAction::Store => {
            let Some(secret) = request.secret.as_ref() else {
                return Response::refused("Keychain broker store had no secret payload.");
            };
            match validate_secret(secret.as_slice())
                .and_then(|()| store_secret(&service, account, secret.as_slice()))
            {
                Ok(()) => Response::ok(None),
                Err(reason) => Response::error(&reason),
            }
        }
        BrokerAction::Delete => match delete_secret(&service, account) {
            Ok(()) => Response::ok(None),
            Err(failure) if failure.code == ERR_SEC_ITEM_NOT_FOUND => Response::absent(),
            Err(failure) => failure.response(),
        },
    }
}

struct KeychainFailure {
    code: i32,
    refused: bool,
    reason: String,
}

impl KeychainFailure {
    fn response(&self) -> Response {
        if self.refused {
            Response::refused(&self.reason)
        } else {
            Response::error(&self.reason)
        }
    }
}

fn inspect_secret(service: &str, account: &str) -> Result<bool, KeychainFailure> {
    let service_len = u32::try_from(service.len()).map_err(|_| KeychainFailure {
        code: 0,
        refused: true,
        reason: "Keychain broker service is too long for exact inspection.".into(),
    })?;
    let account_len = u32::try_from(account.len()).map_err(|_| KeychainFailure {
        code: 0,
        refused: true,
        reason: "Keychain broker account is too long for exact inspection.".into(),
    })?;
    #[allow(deprecated, reason = "admitted metadata-only exact Keychain lookup")]
    let status = unsafe {
        SecKeychain::find_generic_password(
            None,
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    match status {
        0 => Ok(true),
        ERR_SEC_ITEM_NOT_FOUND => Ok(false),
        code => Err(keychain_failure("inspect", code, false)),
    }
}

fn load_secret(
    service: &str,
    account: &str,
    allow_interaction: bool,
) -> Result<Option<BrokerSecret>, KeychainFailure> {
    if allow_interaction {
        return load_secret_with_query(true, || {
            get_generic_password(service, account).map_err(security_framework::base::Error::code)
        });
    }
    let mut options = PasswordOptions::new_generic_password(service, account);
    #[allow(
        deprecated,
        reason = "admitted exact no-authentication-UI Keychain query"
    )]
    unsafe {
        let key = CFString::wrap_under_get_rule(kSecUseAuthenticationUI);
        let value = CFString::wrap_under_get_rule(K_SEC_USE_AUTHENTICATION_UI_FAIL);
        options.query.push((key, value.into_CFType()));
    }
    load_secret_with_query(false, || {
        generic_password(options).map_err(security_framework::base::Error::code)
    })
}

fn load_secret_with_query<Query>(
    allow_interaction: bool,
    query: Query,
) -> Result<Option<BrokerSecret>, KeychainFailure>
where
    Query: FnOnce() -> Result<Vec<u8>, i32>,
{
    match query() {
        Ok(bytes) => BrokerSecret::new(bytes)
            .map(Some)
            .map_err(|reason| KeychainFailure {
                code: 0,
                refused: true,
                reason,
            }),
        Err(ERR_SEC_ITEM_NOT_FOUND) => Ok(None),
        Err(code)
            if !allow_interaction
                && matches!(
                    code,
                    ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_USER_CANCELED
                ) =>
        {
            Err(KeychainFailure {
                code,
                refused: true,
                reason: "Saved API key requires macOS authorization; automatic reconnect failed closed without opening a prompt. Connect explicitly from Account."
                    .into(),
            })
        }
        Err(code)
            if allow_interaction && matches!(code, ERR_SEC_AUTH_FAILED | ERR_SEC_USER_CANCELED) =>
        {
            Err(KeychainFailure {
                code,
                refused: true,
                reason: "macOS Keychain authorization was cancelled or refused; the saved API key was not opened."
                    .into(),
            })
        }
        Err(code) => Err(keychain_failure("read", code, false)),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the create-or-update Keychain transaction stays linear for ACL and data ordering review"
)]
fn store_secret(service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot resolve the Keychain broker executable: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize the Keychain broker executable: {error}"))?;
    let executable = CString::new(executable.as_os_str().as_bytes())
        .map_err(|_| "Keychain broker executable path contains a NUL byte.".to_owned())?;
    let mut trusted_ptr = std::ptr::null_mut();
    #[allow(deprecated, reason = "admitted legacy macOS helper-only Keychain ACL")]
    let trusted_status = unsafe {
        SecTrustedApplication::create_from_path(
            executable.as_ptr(),
            std::ptr::NonNull::from(&mut trusted_ptr),
        )
    };
    if trusted_status != 0 {
        return Err(format!(
            "macOS Keychain could not create the exact helper trust object (status {trusted_status})"
        ));
    }
    let trusted_ptr = std::ptr::NonNull::new(trusted_ptr)
        .ok_or_else(|| "macOS Keychain returned no helper trust object.".to_owned())?;
    // SAFETY: the successful create call transferred one retained reference.
    let trusted = unsafe { ObjcCFRetained::<SecTrustedApplication>::from_raw(trusted_ptr) };
    let trusted_apps = ObjcCFArray::from_retained_objects(&[trusted]);
    let trusted_apps_erased: &ObjcCFArray = AsRef::<ObjcCFArray>::as_ref(&*trusted_apps);

    let descriptor = ObjcCFString::from_str("Grok Build+ stable credential broker");
    let mut access_ptr = std::ptr::null_mut();
    #[allow(deprecated, reason = "admitted legacy macOS helper-only Keychain ACL")]
    let access_status = unsafe {
        SecAccess::create(
            &descriptor,
            Some(trusted_apps_erased),
            std::ptr::NonNull::from(&mut access_ptr),
        )
    };
    if access_status != 0 {
        return Err(format!(
            "macOS Keychain could not create the helper-only provider access policy (status {access_status})"
        ));
    }
    let access_ptr = std::ptr::NonNull::new(access_ptr)
        .ok_or_else(|| "macOS Keychain returned no helper-only access policy.".to_owned())?;
    // SAFETY: the successful create call transferred one retained reference.
    let access = unsafe { ObjcCFRetained::<SecAccess>::from_raw(access_ptr) };

    let service_len = u32::try_from(service.len())
        .map_err(|_| "Keychain broker service name is too long.".to_owned())?;
    let account_len = u32::try_from(account.len())
        .map_err(|_| "Keychain broker account name is too long.".to_owned())?;
    let secret_len = u32::try_from(secret.len())
        .map_err(|_| "Keychain broker secret is too long.".to_owned())?;
    let mut item_ptr = std::ptr::null_mut();
    #[allow(deprecated, reason = "admitted exact legacy Keychain item lookup")]
    let find_status = unsafe {
        SecKeychain::find_generic_password(
            None,
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut item_ptr),
        )
    };
    if find_status == 0 {
        let item_ptr = std::ptr::NonNull::new(item_ptr)
            .ok_or_else(|| "macOS Keychain found no item reference for update.".to_owned())?;
        // SAFETY: the successful find call transferred one retained reference.
        let item = unsafe { ObjcCFRetained::<SecKeychainItem>::from_raw(item_ptr) };
        #[allow(deprecated, reason = "admitted helper-only legacy Keychain ACL update")]
        let access_status = unsafe { item.set_access(&access) };
        if access_status != 0 {
            return Err(format!(
                "macOS Keychain could not bind the existing provider item to the stable helper (status {access_status})"
            ));
        }
        #[allow(deprecated, reason = "admitted exact legacy Keychain item update")]
        let update_status = unsafe {
            item.modify_attributes_and_data(
                std::ptr::null(),
                secret_len,
                secret.as_ptr().cast::<c_void>(),
            )
        };
        return if update_status == 0 {
            Ok(())
        } else {
            Err(format!(
                "macOS Keychain could not update the helper-bound xAI provider key (status {update_status})"
            ))
        };
    }
    if find_status != ERR_SEC_ITEM_NOT_FOUND {
        return Err(format!(
            "macOS Keychain could not inspect the helper-bound xAI provider key before storage (status {find_status})"
        ));
    }

    let mut attributes = [
        SecKeychainAttribute {
            tag: SecItemAttr::ServiceItemAttr.0,
            length: service_len,
            data: service.as_ptr().cast_mut().cast::<c_void>(),
        },
        SecKeychainAttribute {
            tag: SecItemAttr::AccountItemAttr.0,
            length: account_len,
            data: account.as_ptr().cast_mut().cast::<c_void>(),
        },
    ];
    let mut attribute_list = SecKeychainAttributeList {
        count: u32::try_from(attributes.len()).expect("fixed attribute count fits u32"),
        attr: attributes.as_mut_ptr(),
    };
    #[allow(
        deprecated,
        reason = "admitted atomic helper-only legacy Keychain item creation"
    )]
    let create_status = unsafe {
        SecKeychainItem::create_from_content(
            SecItemClass::GenericPasswordItemClass,
            std::ptr::NonNull::from(&mut attribute_list),
            secret_len,
            secret.as_ptr().cast::<c_void>(),
            None,
            Some(&access),
            std::ptr::null_mut(),
        )
    };
    if create_status == 0 {
        Ok(())
    } else {
        Err(format!(
            "macOS Keychain could not atomically create the helper-bound xAI provider key (status {create_status})"
        ))
    }
}

fn delete_secret(service: &str, account: &str) -> Result<(), KeychainFailure> {
    delete_generic_password(service, account)
        .map_err(|error| keychain_failure("delete", error.code(), false))
}

fn keychain_failure(operation: &str, code: i32, refused: bool) -> KeychainFailure {
    KeychainFailure {
        code,
        refused,
        reason: format!(
            "macOS Keychain could not {operation} the broker-owned xAI provider item (status {code})"
        ),
    }
}

fn peer_is_unchanged(stream: &UnixStream, config: &ServerConfig) -> Result<(), String> {
    let peer_pid = socket_peer_pid(stream)?;
    if peer_pid != config.expected_parent_pid || unsafe { libc::kill(peer_pid, 0) } != 0 {
        return Err(
            "Keychain broker refused because its verified app peer exited or changed.".into(),
        );
    }
    validate_live_app_code(
        peer_pid,
        &config.expected_parent_executable,
        &config.expected_parent_identifier,
        &config.parent_signing_identity,
    )
}

fn validate_launchd_environment() -> Result<(), String> {
    validate_launchd_environment_names(std::env::vars_os().map(|(name, _)| name))
}

fn validate_launchd_environment_names(
    names: impl IntoIterator<Item = OsString>,
) -> Result<(), String> {
    const FORBIDDEN: [&str; 7] = [
        "XAI_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROK_DEPLOYMENT_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
    ];
    for name in names {
        if let Some(forbidden) = FORBIDDEN
            .iter()
            .find(|forbidden| name.as_os_str() == std::ffi::OsStr::new(forbidden))
        {
            return Err(format!(
                "Keychain broker refused a launchd environment containing {forbidden}."
            ));
        }
    }
    Ok(())
}

fn validate_socket_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("broker.sock")
        || path.as_os_str().as_bytes().len() > 100
    {
        return Err("Keychain broker refused an unexpected socket path.".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "Keychain broker socket has no private parent.".to_owned())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect the broker socket directory: {error}"))?;
    let socket_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect the broker socket: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::getuid() }
        || parent_metadata.permissions().mode() & 0o077 != 0
        || parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.starts_with(IPC_DIRECTORY_PREFIX))
        || !socket_metadata.file_type().is_socket()
        || socket_metadata.uid() != unsafe { libc::getuid() }
        || socket_metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Keychain broker refused an unprotected socket boundary.".into());
    }
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| format!("cannot canonicalize the broker socket directory: {error}"))?;
    if canonical_parent.join("broker.sock") != path {
        return Err("Keychain broker socket path changed during validation.".into());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum CodeIdentity<'a> {
    Certificate(&'a str),
    CdHash(&'a str),
}

fn validate_static_code(
    path: &Path,
    identifier: &str,
    identity: CodeIdentity<'_>,
) -> Result<(), String> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!(
            "cannot canonicalize signed code {}: {error}",
            path.display()
        )
    })?;
    let url = CFURL::from_path(&canonical, false)
        .ok_or_else(|| "cannot represent a signed-code path as a file URL.".to_owned())?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|error| format!("cannot inspect signed code (status {})", error.code()))?;
    let requirement = signing_requirement(identifier, identity)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::CHECK_ALL_ARCHITECTURES | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|error| {
        format!(
            "signed code failed its exact requirement (status {})",
            error.code()
        )
    })?;
    let observed = code
        .path(Flags::NONE)
        .map_err(|error| format!("cannot resolve signed-code path (status {})", error.code()))?
        .to_path()
        .ok_or_else(|| "signed-code path is not a local filesystem path.".to_owned())?;
    let observed = fs::canonicalize(observed)
        .map_err(|error| format!("cannot canonicalize the observed signed-code path: {error}"))?;
    if observed != canonical {
        return Err("signed-code path changed during validation.".into());
    }
    Ok(())
}

fn validate_live_code(
    pid: i32,
    expected_path: &Path,
    identifier: &str,
    identity: CodeIdentity<'_>,
) -> Result<(), String> {
    if pid <= 1 {
        return Err("live code has no eligible process identity.".into());
    }
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|error| format!("cannot inspect live code (status {})", error.code()))?;
    let requirement = signing_requirement(identifier, identity)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|error| {
        format!(
            "live code failed its exact requirement (status {})",
            error.code()
        )
    })?;
    let observed = code
        .path(Flags::NONE)
        .map_err(|error| format!("cannot resolve live-code path (status {})", error.code()))?
        .to_path()
        .ok_or_else(|| "live-code path is not a local filesystem path.".to_owned())?;
    let observed = fs::canonicalize(observed)
        .map_err(|error| format!("cannot canonicalize the live-code path: {error}"))?;
    let expected_executable = fs::canonicalize(expected_path).map_err(|error| {
        format!(
            "cannot canonicalize expected live-code path {}: {error}",
            expected_path.display()
        )
    })?;
    let expected_bundle = expected_executable
        .parent()
        .filter(|directory| directory.file_name().and_then(|name| name.to_str()) == Some("MacOS"))
        .and_then(Path::parent)
        .filter(|directory| {
            directory.file_name().and_then(|name| name.to_str()) == Some("Contents")
        })
        .and_then(Path::parent)
        .map(fs::canonicalize)
        .transpose()
        .map_err(|error| format!("cannot canonicalize expected app bundle path: {error}"))?;
    if observed != expected_executable && expected_bundle.as_ref() != Some(&observed) {
        return Err("live code did not execute from the exact admitted path.".into());
    }
    Ok(())
}

fn validate_live_app_code(
    pid: i32,
    executable_name: &str,
    identifier: &str,
    signing_identity: &str,
) -> Result<(), String> {
    if pid <= 1
        || executable_name.is_empty()
        || executable_name.len() > 128
        || !executable_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-' | b'_'))
    {
        return Err("live app has no eligible process or executable identity.".into());
    }
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|error| format!("cannot inspect live app code (status {})", error.code()))?;
    let requirement = signing_requirement(identifier, CodeIdentity::Certificate(signing_identity))?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|error| {
        format!(
            "live app code failed its exact requirement (status {})",
            error.code()
        )
    })?;
    let observed = code
        .path(Flags::NONE)
        .map_err(|error| format!("cannot resolve live app path (status {})", error.code()))?
        .to_path()
        .ok_or_else(|| "live app path is not a local filesystem path.".to_owned())?;
    let observed = fs::canonicalize(observed)
        .map_err(|error| format!("cannot canonicalize the live app path: {error}"))?;
    let executable = if observed
        .extension()
        .and_then(|extension| extension.to_str())
        == Some("app")
    {
        observed
            .join("Contents")
            .join("MacOS")
            .join(executable_name)
    } else {
        if observed.file_name().and_then(|name| name.to_str()) != Some(executable_name) {
            return Err("live app executed under an unexpected executable name.".into());
        }
        let macos = observed
            .parent()
            .filter(|directory| {
                directory.file_name().and_then(|name| name.to_str()) == Some("MacOS")
            })
            .ok_or_else(|| "live app executable is outside a MacOS bundle directory.".to_owned())?;
        let contents = macos
            .parent()
            .filter(|directory| {
                directory.file_name().and_then(|name| name.to_str()) == Some("Contents")
            })
            .ok_or_else(|| {
                "live app executable is outside a Contents bundle directory.".to_owned()
            })?;
        let bundle = contents
            .parent()
            .filter(|directory| {
                directory
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("app")
            })
            .ok_or_else(|| "live app executable is outside an app bundle.".to_owned())?;
        let _ = bundle;
        observed
    };
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|error| format!("cannot inspect the live app executable: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("live app executable is not an exact owner-controlled file.".into());
    }
    Ok(())
}

fn signing_requirement(
    identifier: &str,
    identity: CodeIdentity<'_>,
) -> Result<SecRequirement, String> {
    validate_identifier(identifier)?;
    let identity_clause = match identity {
        CodeIdentity::Certificate(fingerprint) => format!(
            "certificate leaf = H\"{}\"",
            validated_fingerprint(fingerprint)?.to_ascii_lowercase()
        ),
        CodeIdentity::CdHash(cdhash) => format!(
            "cdhash H\"{}\"",
            validated_cdhash(cdhash)?.to_ascii_lowercase()
        ),
    };
    SecRequirement::from_str(&format!(
        "identifier \"{identifier}\" and {identity_clause}"
    ))
    .map_err(|error| {
        format!(
            "cannot construct the exact code requirement (status {})",
            error.code()
        )
    })
}

fn validate_identifier(identifier: &str) -> Result<(), String> {
    if !identifier.is_empty()
        && identifier.len() <= 128
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        Ok(())
    } else {
        Err("Code-signing identifier is outside the admitted form.".into())
    }
}

fn validated_fingerprint(identity: &str) -> Result<String, String> {
    if identity.len() == 40 && identity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(identity.to_ascii_uppercase())
    } else {
        Err(
            "Stable Keychain broker requires one exact public signing-certificate fingerprint."
                .into(),
        )
    }
}

fn validated_cdhash(cdhash: &str) -> Result<String, String> {
    if cdhash.len() == 40 && cdhash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(cdhash.to_ascii_uppercase())
    } else {
        Err("Stable Keychain broker requires one exact helper CDHash.".into())
    }
}

fn parse_sha256(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Stable Keychain broker requires one exact SHA-256.".into());
    }
    let mut parsed = [0_u8; 32];
    for (index, slot) in parsed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "Stable Keychain broker SHA-256 could not be decoded.".to_owned())?;
    }
    Ok(parsed)
}

fn validate_secret(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err("Keychain broker refused an empty or oversized provider key.".into());
    }
    let text = std::str::from_utf8(secret)
        .map_err(|_| "Keychain broker refused a non-UTF-8 provider key.".to_owned())?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err("Keychain broker refused a blank or control-bearing provider key.".into());
    }
    Ok(())
}

fn validated_temporary_directory() -> Result<PathBuf, String> {
    let canonical = fs::canonicalize("/private/tmp")
        .map_err(|error| format!("cannot canonicalize the system temporary directory: {error}"))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("cannot inspect the system temporary directory: {error}"))?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & u32::from(libc::S_ISVTX) == 0
        || canonical != Path::new("/private/tmp")
    {
        return Err("Keychain broker refused an untrusted system temporary directory.".into());
    }
    Ok(canonical)
}

#[cfg(feature = "broker-fixture")]
mod mcp_fixture;

#[cfg(feature = "broker-fixture")]
fn validate_fixture_target(service: &str, account: &str) -> Result<(), String> {
    let valid = |value: &str, prefix: &str| {
        value.starts_with(prefix)
            && value.len() <= 200
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'_')
            })
    };
    if valid(service, "org.grok-build.desktop.test.") && valid(account, "fixture:") {
        Ok(())
    } else {
        Err("Keychain broker fixture refused a non-fixture target.".into())
    }
}

/// Distinguishes the two signed control parents.
#[cfg(feature = "broker-fixture")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureParentVariant {
    /// Creates through the helper.
    A,
    /// Proves a changed but authorized parent can read through the same helper.
    B,
    /// Proves a wrong identifier or signer cannot read the fixture directly.
    Unauthorized,
}

#[cfg(feature = "broker-fixture")]
/// Runs the test-only helper with a bounded fixture Keychain target.
///
/// # Errors
///
/// Refuses malformed arguments, non-fixture targets, peers, or broker
/// operations.
pub fn run_fixture_broker(arguments: impl Iterator<Item = OsString>) -> Result<(), String> {
    let values: Vec<OsString> = arguments.collect();
    if values.len() != 7
        || (values[0] != "--fixture-launchd-once" && values[0] != "--fixture-mcp-launchd-once")
    {
        return Err("fixture broker requires its exact one-shot launchd test contract.".into());
    }
    let signing_identity = values[1]
        .to_str()
        .ok_or_else(|| "fixture signer is not UTF-8.".to_owned())?;
    let service = values[2]
        .to_str()
        .ok_or_else(|| "fixture service is not UTF-8.".to_owned())?;
    let account = values[3]
        .to_str()
        .ok_or_else(|| "fixture account is not UTF-8.".to_owned())?;
    let socket_path = PathBuf::from(&values[4]);
    let expected_parent_pid = values[5]
        .to_str()
        .ok_or_else(|| "fixture parent PID is not UTF-8.".to_owned())?
        .parse::<i32>()
        .map_err(|_| "fixture parent PID is invalid.".to_owned())?;
    let expected_helper_cdhash = values[6]
        .to_str()
        .ok_or_else(|| "fixture helper CDHash is not UTF-8.".to_owned())?;
    validate_fixture_target(service, account)?;
    let config = ServerConfig {
        namespace: if values[0] == "--fixture-mcp-launchd-once" {
            BrokerNamespace::Mcp
        } else {
            BrokerNamespace::Provider
        },
        service: service.to_owned(),
        mcp_service: format!("{service}.mcp"),
        accounts: [account.to_owned(), account.to_owned(), account.to_owned()],
        expected_parent_pid,
        expected_parent_executable: "grok-build-keychain-parent-fixture".to_owned(),
        expected_parent_identifier: PARENT_CODE_IDENTIFIER.to_owned(),
        expected_helper_cdhash: validated_cdhash(expected_helper_cdhash)?,
        parent_signing_identity: validated_fingerprint(signing_identity)?,
    };
    serve(&config, &socket_path)
}

#[cfg(feature = "broker-fixture")]
/// Runs one of the two signed parent fixtures for cross-build proof.
///
/// # Errors
///
/// Refuses malformed arguments, invalid helper identity, failed controls, or
/// any fixture Keychain operation.
#[allow(
    clippy::too_many_lines,
    reason = "the signed control-vs-enforced fixture stays linear so every boundary is auditable"
)]
pub fn run_fixture_parent(
    variant: FixtureParentVariant,
    arguments: impl Iterator<Item = OsString>,
) -> Result<(), String> {
    const FIXTURE_SECRET: &[u8] = b"grok-build-keychain-broker-fixture";
    // SAFETY: fixture parents are standalone test processes. The alarm keeps
    // an unexpected Security.framework/UI wait from surviving the control.
    unsafe { libc::alarm(60) };
    let mut values: Vec<OsString> = arguments.collect();
    if values.len() != 6 {
        return Err("fixture parent requires helper path, helper SHA-256, signer, service/account, helper CDHash, and result path.".into());
    }
    let result_path = PathBuf::from(
        values
            .pop()
            .ok_or_else(|| "fixture result path disappeared after validation.".to_owned())?,
    );
    let outcome = (|| {
        if values[3]
            .to_str()
            .is_some_and(|target| target.starts_with("org.grok-build.desktop.test.mcp-"))
        {
            return mcp_fixture::run(variant, &values);
        }
        let helper_path = PathBuf::from(&values[0]);
        let helper_sha = values[1]
            .to_str()
            .ok_or_else(|| "fixture helper SHA-256 is not UTF-8.".to_owned())?;
        let signer = values[2]
            .to_str()
            .ok_or_else(|| "fixture signer is not UTF-8.".to_owned())?;
        let target = values[3]
            .to_str()
            .ok_or_else(|| "fixture target is not UTF-8.".to_owned())?;
        let (service, account) = target
            .split_once(',')
            .ok_or_else(|| "fixture target is malformed.".to_owned())?;
        validate_fixture_target(service, account)?;
        let helper_cdhash = values
            .get(4)
            .and_then(|value| value.to_str())
            .ok_or_else(|| "fixture helper CDHash is absent or not UTF-8.".to_owned())?;
        let helper_arguments = vec![
            OsString::from("--fixture-launchd-once"),
            OsString::from(signer),
            OsString::from(service),
            OsString::from(account),
        ];
        if variant == FixtureParentVariant::A {
            let wrong_sha = "0".repeat(64);
            let wrong_sha_error = BrokerClient::new(BrokerClientConfig::for_fixture(
                helper_path.clone(),
                &wrong_sha,
                helper_cdhash,
                signer,
                helper_arguments.clone(),
            )?)
            .expect_err("wrong helper SHA-256 must fail closed");
            if !wrong_sha_error.contains("SHA-256") {
                return Err(format!(
                    "wrong helper SHA-256 control returned an unexpected refusal: {wrong_sha_error}"
                ));
            }

            let wrong_cdhash = "0".repeat(40);
            let wrong_cdhash_error = BrokerClient::new(BrokerClientConfig::for_fixture(
                helper_path.clone(),
                helper_sha,
                &wrong_cdhash,
                signer,
                helper_arguments.clone(),
            )?)
            .expect_err("wrong helper CDHash must fail closed");
            if !wrong_cdhash_error.contains("exact requirement") {
                return Err(format!(
                    "wrong helper CDHash control returned an unexpected refusal: {wrong_cdhash_error}"
                ));
            }

            let missing_helper = helper_path.with_file_name("missing-keychain-broker-fixture");
            let wrong_path_error = BrokerClient::new(BrokerClientConfig::for_fixture(
                missing_helper,
                helper_sha,
                helper_cdhash,
                signer,
                helper_arguments.clone(),
            )?)
            .expect_err("missing helper path must fail closed");
            if !wrong_path_error.contains("cannot inspect") {
                return Err(format!(
                    "wrong helper path control returned an unexpected refusal: {wrong_path_error}"
                ));
            }
        }
        let client = BrokerClient::new(BrokerClientConfig::for_fixture(
            helper_path.clone(),
            helper_sha,
            helper_cdhash,
            signer,
            helper_arguments,
        )?)?;
        match variant {
            FixtureParentVariant::A => {
                let parent_control_account = format!("{account}-parent-control");
                let parent_cdhash = account
                    .split_once(":parent:")
                    .map(|(_, hash)| hash)
                    .ok_or("Provider fixture omitted its parent control identity.")?;
                validated_cdhash(parent_cdhash)?;
                store_secret(service, &parent_control_account, FIXTURE_SECRET)?;
                let control_acl =
                    fixture_access_summary(service, &parent_control_account, parent_cdhash);
                let no_ui_arguments = vec![
                    OsString::from("--fixture-launchd-once"),
                    OsString::from(signer),
                    OsString::from(service),
                    OsString::from(&parent_control_account),
                ];
                let no_ui_client = BrokerClient::new(BrokerClientConfig::for_fixture(
                    helper_path,
                    helper_sha,
                    helper_cdhash,
                    signer,
                    no_ui_arguments,
                )?)?;
                let no_ui_result = if control_acl.is_ok() {
                    no_ui_client.load(CredentialVersion::BrokerV3, false)
                } else {
                    Err("Parent control ACL was not proven.".into())
                };
                delete_generic_password(service, &parent_control_account).map_err(|error| {
                    format!(
                        "direct signed-parent Keychain cleanup control failed (status {}): {error}",
                        error.code()
                    )
                })?;
                control_acl?;
                let no_ui_error = no_ui_result
                    .expect_err("unauthorized automatic helper load must fail without a prompt");
                if !no_ui_error.contains("automatic reconnect failed closed") {
                    return Err(format!(
                        "no-UI Keychain control returned an unexpected refusal: {no_ui_error}"
                    ));
                }
                client.store_v3(FIXTURE_SECRET)?;
                fixture_access_summary(service, account, helper_cdhash)?;
                let loaded = client
                    .load(CredentialVersion::BrokerV3, false)?
                    .ok_or_else(|| "fixture helper did not return its stored item.".to_owned())?;
                if loaded.as_slice() != FIXTURE_SECRET {
                    return Err("fixture helper returned different secret bytes.".into());
                }
                println!(
                    "BROKER FIXTURE A PASS hash=refused cdhash=refused path=refused no-ui=refused"
                );
            }
            FixtureParentVariant::B => {
                let verification = (|| {
                    let loaded = client
                        .load(CredentialVersion::BrokerV3, false)?
                        .ok_or_else(|| {
                            "stable helper did not find the cross-build fixture.".to_owned()
                        })?;
                    if loaded.as_slice() != FIXTURE_SECRET {
                        return Err(
                            "stable helper returned different cross-build fixture bytes.".into(),
                        );
                    }
                    Ok(())
                })();
                let cleanup = client.delete(CredentialVersion::BrokerV3);
                verification.and(cleanup)?;
                println!("BROKER FIXTURE B PASS launchd-helper=allowed cleanup=passed");
            }
            FixtureParentVariant::Unauthorized => {
                if client.inspect(CredentialVersion::BrokerV3).is_ok() {
                    return Err("unauthorized app unexpectedly passed the broker peer gate.".into());
                }
                println!("BROKER FIXTURE UNAUTHORIZED PASS peer=refused");
            }
        }
        Ok(())
    })();
    write_fixture_result(&result_path, outcome.as_ref().err())?;
    outcome
}

#[cfg(feature = "broker-fixture")]
fn write_fixture_result(path: &Path, error: Option<&String>) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.starts_with("result-"))
    {
        return Err("fixture refused an unexpected result path.".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "fixture result path has no parent.".to_owned())?;
    let parent = fs::canonicalize(parent)
        .map_err(|reason| format!("fixture result parent is unavailable: {reason}"))?;
    let metadata = fs::symlink_metadata(&parent)
        .map_err(|reason| format!("fixture result parent cannot be inspected: {reason}"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::getuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.starts_with("grok-build-keychain-broker."))
    {
        return Err(
            "fixture refused a result parent outside its owner-only temporary root.".into(),
        );
    }
    let message = if let Some(error) = error {
        if error.len() > 4096 || error.chars().any(|character| character == '\0') {
            "FAIL fixture error was outside the bounded result format.\n".to_owned()
        } else {
            format!("FAIL {}\n", error.replace(['\r', '\n'], " "))
        }
    } else {
        "PASS\n".to_owned()
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|reason| format!("fixture result file could not be created: {reason}"))?;
    file.write_all(message.as_bytes())
        .map_err(|reason| format!("fixture result file could not be written: {reason}"))?;
    file.sync_all()
        .map_err(|reason| format!("fixture result file could not be synced: {reason}"))
}

#[cfg(feature = "broker-fixture")]
#[allow(
    clippy::too_many_lines,
    reason = "fixture-only ACL shape inspection stays linear for exact partition review"
)]
fn fixture_access_summary(
    service: &str,
    account: &str,
    expected_helper_cdhash: &str,
) -> Result<(), String> {
    let service_len = u32::try_from(service.len())
        .map_err(|_| "fixture service is too long for ACL inspection.".to_owned())?;
    let account_len = u32::try_from(account.len())
        .map_err(|_| "fixture account is too long for ACL inspection.".to_owned())?;
    let mut item_ptr = std::ptr::null_mut();
    #[allow(deprecated, reason = "fixture-only exact Keychain ACL inspection")]
    let status = unsafe {
        SecKeychain::find_generic_password(
            None,
            service_len,
            service.as_ptr().cast(),
            account_len,
            account.as_ptr().cast(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut item_ptr),
        )
    };
    if status != 0 {
        return Err(format!(
            "fixture could not find its exact item for ACL inspection (status {status})"
        ));
    }
    let item_ptr = std::ptr::NonNull::new(item_ptr)
        .ok_or_else(|| "fixture ACL inspection received no item reference.".to_owned())?;
    // SAFETY: the successful find call transferred one retained reference.
    let item = unsafe { ObjcCFRetained::<SecKeychainItem>::from_raw(item_ptr) };
    let mut access_ptr = std::ptr::null_mut();
    #[allow(deprecated, reason = "fixture-only exact Keychain ACL inspection")]
    let status = unsafe { item.copy_access(std::ptr::NonNull::from(&mut access_ptr)) };
    if status != 0 {
        return Err(format!(
            "fixture could not copy its exact item access object (status {status})"
        ));
    }
    let access_ptr = std::ptr::NonNull::new(access_ptr)
        .ok_or_else(|| "fixture ACL inspection received no access object.".to_owned())?;
    // SAFETY: the successful copy call transferred one retained reference.
    let access = unsafe { ObjcCFRetained::<SecAccess>::from_raw(access_ptr) };
    let mut acl_list_ptr: *const ObjcCFArray = std::ptr::null();
    #[allow(deprecated, reason = "fixture-only exact Keychain ACL inspection")]
    let status = unsafe { access.copy_acl_list(std::ptr::NonNull::from(&mut acl_list_ptr)) };
    if status != 0 {
        return Err(format!(
            "fixture could not copy its exact ACL list (status {status})"
        ));
    }
    let acl_list_ptr = std::ptr::NonNull::new(acl_list_ptr.cast_mut())
        .ok_or_else(|| "fixture ACL inspection received no ACL list.".to_owned())?;
    // SAFETY: the successful copy call transferred one retained reference;
    // Security.framework documents every element as a SecACL.
    let acl_list = unsafe { ObjcCFRetained::<ObjcCFArray<SecACL>>::from_raw(acl_list_ptr.cast()) };
    if acl_list.len() != 5 {
        return Err(format!(
            "fixture Keychain ACL had {} entries instead of the enforced macOS 15 shape.",
            acl_list.len()
        ));
    }
    let expected_partition = format!(
        "<string>cdhash:{}</string>",
        validated_cdhash(expected_helper_cdhash)?.to_ascii_lowercase()
    );
    let mut exact_partition = false;
    let mut restricted_application = false;
    for (index, acl) in acl_list.iter().enumerate() {
        let mut applications_ptr: *const ObjcCFArray = std::ptr::null();
        let mut description_ptr: *const ObjcCFString = std::ptr::null();
        let mut prompt = SecKeychainPromptSelector(0);
        #[allow(deprecated, reason = "fixture-only exact Keychain ACL inspection")]
        let status = unsafe {
            acl.copy_contents(
                std::ptr::NonNull::from(&mut applications_ptr),
                std::ptr::NonNull::from(&mut description_ptr),
                std::ptr::NonNull::from(&mut prompt),
            )
        };
        if status != 0 {
            return Err(format!(
                "fixture could not copy ACL entry {index} contents (status {status})"
            ));
        }
        let description_ptr = std::ptr::NonNull::new(description_ptr.cast_mut())
            .ok_or_else(|| format!("fixture ACL entry {index} had no description."))?;
        // SAFETY: the successful copy call transferred one retained reference.
        let description = unsafe { ObjcCFRetained::<ObjcCFString>::from_raw(description_ptr) };
        let application_count = if applications_ptr.is_null() {
            None
        } else {
            let applications_ptr = std::ptr::NonNull::new(applications_ptr.cast_mut())
                .ok_or_else(|| "fixture ACL application list pointer changed.".to_owned())?;
            // SAFETY: the successful copy call transferred one retained CFArray.
            let applications = unsafe { ObjcCFRetained::<ObjcCFArray>::from_raw(applications_ptr) };
            Some(applications.len())
        };
        #[allow(deprecated, reason = "fixture-only exact Keychain ACL inspection")]
        let authorizations = unsafe { acl.authorizations() };
        restricted_application |= authorizations.len() == 6 && application_count == Some(1);
        let description = description.to_string();
        if let Some(decoded) = decode_fixture_hex(&description)
            && let Ok(plist) = std::str::from_utf8(&decoded)
            && plist.contains("<key>Partitions</key>")
        {
            exact_partition =
                plist.contains(&expected_partition) && plist.matches("<string>").count() == 1;
        }
    }
    if !restricted_application || !exact_partition {
        return Err(
            "fixture Keychain ACL did not bind one restricted application and one exact helper CDHash partition."
                .into(),
        );
    }
    Ok(())
}

#[cfg(feature = "broker-fixture")]
fn decode_fixture_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&value[index..index + 2], 16).ok()?);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_identity_hash_and_identifier_inputs_are_exact() {
        assert!(validated_fingerprint("adhoc").is_err());
        assert!(validated_fingerprint("A38B0F65923F277B3EBB2FA6887FFCD9F6C96E0D").is_ok());
        assert!(validated_cdhash("24B8C9DCED3A815AF1B1C163D3E412A58CE73B14").is_ok());
        assert!(validated_cdhash("adhoc").is_err());
        assert!(parse_sha256(&"a".repeat(64)).is_ok());
        assert!(parse_sha256(&"g".repeat(64)).is_err());
        assert!(validate_identifier(crate::BROKER_CODE_IDENTIFIER).is_ok());
        assert!(validate_identifier("bad identifier").is_err());
    }

    #[test]
    fn provider_secret_validation_is_bounded_and_control_free() {
        assert!(validate_secret(b"fixture-key").is_ok());
        assert!(validate_secret(b"").is_err());
        assert!(validate_secret(b"fixture\nkey").is_err());
        assert!(validate_secret(&vec![b'x'; MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    fn launchd_broker_refuses_recognized_secret_environment_before_keychain_access() {
        assert!(
            validate_launchd_environment_names([
                OsString::from("PATH"),
                OsString::from("XPC_SERVICE_NAME"),
            ])
            .is_ok()
        );
        let refused = validate_launchd_environment_names([
            OsString::from("PATH"),
            OsString::from("XAI_API_KEY"),
        ])
        .expect_err("recognized secret environment must fail closed");
        assert_eq!(
            refused,
            "Keychain broker refused a launchd environment containing XAI_API_KEY."
        );
    }

    #[test]
    fn private_socket_contract_accepts_only_the_owner_only_broker_boundary() {
        let base = validated_temporary_directory().expect("trusted system temporary directory");
        let (guard, listener) = create_ipc_listener(&base).expect("private broker socket");
        validate_socket_path(&guard.socket_path).expect("legitimate private socket boundary");
        let wrong_name = guard.root.join("not-the-broker.sock");
        assert!(validate_socket_path(&wrong_name).is_err());
        drop(listener);
        drop(guard);
    }

    #[test]
    fn broker_load_does_not_preflight_with_a_second_inspection() {
        let queries = std::cell::Cell::new(0);
        let result = load_secret_with_query(false, || {
            queries.set(queries.get() + 1);
            Ok(b"fixture-key".to_vec())
        });
        let Ok(Some(loaded)) = result else {
            panic!("single broker query must return the fixture credential");
        };
        assert_eq!(queries.get(), 1);
        assert_eq!(loaded.as_slice(), b"fixture-key");
    }
}
