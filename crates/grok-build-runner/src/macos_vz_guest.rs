//! Virtualization.framework guest boot, integrity, and lifecycle ownership.
//!
//! [`GUEST_IMAGE_PIN_V1`] binds the supplied kernel and root filesystem. Hash both
//! before creating framework objects; [`VzGuest::validated`] requires verification
//! to name the exact boot artifacts. Acquisition belongs to the build-time guest
//! image scripts. Runtime has no unverified-image fallback.
//!
//! [`VzGuestSession`] owns boot, share, health, dispatch, and teardown. A separate
//! process runs [`MACOS_VZ_GUEST_ARGUMENT`] on its main dispatch queue; atomic
//! virtiofs records carry lifecycle control. Lost health or share access returns
//! [`VzGuestErrorKind::GuestUnhealthy`], without launching commands on the host.
//! Linux backend canaries inside the guest establish containment controls.
//!
//! Validate configuration before constructing the VM: missing
//! `com.apple.security.virtualization` can otherwise raise an Objective-C exception
//! across Rust frames. Convert failed validation to
//! [`VzGuestErrorKind::VirtualizationEntitlementMissing`].

#![allow(dead_code)] // Internal guest modes are reached through the runner binary.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt;
use std::io::Read as _;
use std::mem;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

#[cfg(target_os = "macos")]
use darwin_virtualization::VzGuest;

/// Why a guest could not be configured, started, or stopped.
///
/// Every variant is a refusal with a named cause. There is no variant meaning
/// "started without the boundary": a guest either runs under the hypervisor or
/// this module returns an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VzGuestErrorKind {
    /// The host process carries no `com.apple.security.virtualization`
    /// entitlement, so Virtualization.framework refuses the configuration.
    VirtualizationEntitlementMissing,
    /// A file the guest boots from is absent or unreadable.
    MissingBootArtifact,
    /// A boot artifact's bytes do not hash to its committed pin. There is no
    /// weaker outcome for this: an artifact that fails verification is never
    /// booted, and no unverified image is substituted for it.
    GuestImageDigestMismatch,
    /// A boot artifact is not exactly the length its committed pin records.
    GuestImageLengthMismatch,
    /// A plan was offered for boot whose verification does not name the exact
    /// artifacts the plan boots, so no verification covers this boot.
    GuestImageUnverified,
    /// The guest did not publish readiness inside its bound.
    GuestNeverBecameReady,
    /// The guest is dead, hung, or has lost its share. Commands refuse rather
    /// than run anywhere else.
    GuestUnhealthy,
    /// A requested vCPU or memory value is outside what this host allows.
    UnsupportedSizing,
    /// The framework rejected the configuration for some other reason.
    InvalidConfiguration,
    /// `startWithCompletionHandler:` reported a failure.
    StartRefused,
    /// The guest did not reach the stopped state inside its budget.
    BudgetExhausted,
    /// The machine ended in the framework's error state.
    MachineError,
}

/// One typed refusal from this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VzGuestError {
    kind: VzGuestErrorKind,
    detail: String,
}

impl VzGuestError {
    fn new(kind: VzGuestErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// The classified cause.
    pub(crate) const fn kind(&self) -> &VzGuestErrorKind {
        &self.kind
    }

    /// The exact framework or host text behind the refusal.
    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for VzGuestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for VzGuestError {}

/// Immutable guest boot inputs, fixed before framework objects exist. The plan
/// names artifacts and sizing; live lifecycle state belongs to the session.
#[derive(Debug, Clone)]
pub(crate) struct VzLinuxGuestPlan {
    /// Uncompressed kernel image. Apple Silicon requires the raw arm64 `Image`
    /// form, not the gzip-wrapped `vmlinuz` a distribution ships.
    pub(crate) kernel_image: PathBuf,
    /// Initial ramdisk carrying the guest's complete root filesystem.
    pub(crate) initial_ramdisk: PathBuf,
    /// Host directory exported to the guest over virtiofs.
    pub(crate) shared_directory: PathBuf,
    /// Mount tag the guest passes to `mount -t virtiofs <tag>`.
    pub(crate) share_tag: String,
    /// Kernel command line, including the console the serial port carries.
    pub(crate) command_line: String,
    /// Requested vCPU count, checked against the host's allowed range.
    pub(crate) processor_count: u64,
    /// Requested guest memory, checked against the host's allowed range.
    pub(crate) memory_bytes: u64,
    /// Longest this module will wait for the guest to power itself off.
    pub(crate) budget: Duration,
    /// Proof that both boot artifacts matched their committed content pins.
    ///
    /// This is a field rather than a check performed elsewhere because the
    /// verification must travel with the plan: [`VzGuest::validated`] refuses a
    /// plan whose verification does not name the exact two artifacts the plan
    /// boots, so a verification of one image cannot authorize the boot of
    /// another.
    pub(crate) verification: GuestImageVerification,
}

impl VzLinuxGuestPlan {
    /// Refuses a plan whose artifacts are not present before any framework
    /// object is built, so a missing image is a typed error rather than an
    /// Objective-C exception at validation time.
    fn check_artifacts(&self) -> Result<(), VzGuestError> {
        for (label, path) in [
            ("kernel image", self.kernel_image.as_path()),
            ("initial ramdisk", self.initial_ramdisk.as_path()),
        ] {
            if !path.is_file() {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::MissingBootArtifact,
                    format!("{label} {} is not a readable file", path.display()),
                ));
            }
        }
        if !self.shared_directory.is_dir() {
            return Err(VzGuestError::new(
                VzGuestErrorKind::MissingBootArtifact,
                format!(
                    "shared directory {} is not a directory",
                    self.shared_directory.display()
                ),
            ));
        }
        Ok(())
    }
}

/// What one complete boot-run-stop cycle cost and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VzGuestRunReport {
    /// Time from `startWithCompletionHandler:` to its completion handler.
    pub(crate) start_latency: Duration,
    /// Time from that call until the machine was observed stopped.
    pub(crate) total: Duration,
    /// The framework's terminal state code; a completed run is `0`.
    pub(crate) final_state: i64,
    /// Whether the guest powered itself off rather than being forced.
    pub(crate) guest_initiated_stop: bool,
}

/// The exact internal argument that turns this process into a guest host.
///
/// It is deliberately unlike any user-facing flag, and it grants no authority:
/// every path the guest can reach is one this argument vector names, and the
/// guest's console is this process's own stdout.
pub(crate) const MACOS_VZ_GUEST_ARGUMENT: &str = "--grok-build-macos-vz-guest-v1";

/// Boots one guest from this process when the exact internal argument is
/// present, and returns its exit code.
///
/// This is the same shape as the Linux canary helper's entry point and exists
/// for the same reason: `VZVirtualMachine` is bound to the dispatch queue it
/// was created with, this module uses the main queue, and only a process
/// entry point can guarantee it owns the main thread. A `cargo test` binary
/// cannot, which is why the boot path is here rather than in a test.
///
/// The host binary must carry `com.apple.security.virtualization`, applied
/// after `cargo build` by `codesign --force -s - --entitlements …`. Without
/// it this returns [`VZ_GUEST_REFUSED`] and names the missing entitlement; it
/// never falls back to running anything unconfined.
#[cfg(target_os = "macos")]
#[doc(hidden)]
#[must_use]
pub fn run_macos_vz_guest_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next()?;
    if mode != std::ffi::OsStr::new(MACOS_VZ_GUEST_ARGUMENT) {
        return None;
    }
    Some(match host_one_guest(arguments) {
        Ok(report) => {
            eprintln!(
                "vz-guest start_latency_ms={} total_ms={} final_state={} guest_initiated_stop={}",
                report.start_latency.as_millis(),
                report.total.as_millis(),
                report.final_state,
                report.guest_initiated_stop,
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("vz-guest refused: {error}");
            std::process::ExitCode::from(VZ_GUEST_REFUSED)
        }
    })
}

/// Exit code of a host process that refused to boot a guest. Distinct from
/// every ordinary runner exit so a caller cannot confuse the two.
pub(crate) const VZ_GUEST_REFUSED: u8 = 77;

#[cfg(target_os = "macos")]
fn host_one_guest(arguments: std::env::ArgsOs) -> Result<VzGuestRunReport, VzGuestError> {
    let arguments = arguments.collect::<Vec<std::ffi::OsString>>();
    let [
        kernel,
        ramdisk,
        share,
        tag,
        command_line,
        processors,
        memory,
        budget,
    ] = arguments.as_slice()
    else {
        return Err(VzGuestError::new(
            VzGuestErrorKind::InvalidConfiguration,
            "expected kernel, ramdisk, share, tag, command line, vCPUs, memory bytes, budget ms",
        ));
    };
    let number = |value: &std::ffi::OsString, label: &str| -> Result<u64, VzGuestError> {
        value
            .to_str()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or_else(|| {
                VzGuestError::new(
                    VzGuestErrorKind::InvalidConfiguration,
                    format!("{label} is not a number"),
                )
            })
    };
    let text = |value: &std::ffi::OsString, label: &str| -> Result<String, VzGuestError> {
        value.to_str().map(str::to_owned).ok_or_else(|| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("{label} is not valid UTF-8"),
            )
        })
    };
    // The product path verifies before it plans. Both artifacts are read in
    // full and hashed against the constants committed in this source file, and
    // a mismatch returns here rather than reaching a boot loader.
    let kernel_image = PathBuf::from(kernel);
    let initial_ramdisk = PathBuf::from(ramdisk);
    let verification = GuestImageVerification::verify_committed(&kernel_image, &initial_ramdisk)?;
    let plan = VzLinuxGuestPlan {
        kernel_image,
        initial_ramdisk,
        verification,
        shared_directory: PathBuf::from(share),
        share_tag: text(tag, "the share tag")?,
        command_line: text(command_line, "the kernel command line")?,
        processor_count: number(processors, "the vCPU count")?,
        memory_bytes: number(memory, "the memory size")?,
        budget: Duration::from_millis(number(budget, "the budget")?),
    };
    // The guest's console is this process's stdout, duplicated so the
    // framework's file handle owns a descriptor of its own.
    let console = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("the guest console descriptor could not be duplicated: {error}"),
            )
        })?;
    VzGuest::validated(&plan, &console)?.run_to_stop()
}

/// The only target-gated unsafe bridge in this module. Its safe surface is
/// fixed to: build one `VZVirtualMachineConfiguration` from an inert plan,
/// validate it, start the machine, poll its state on the queue that owns it,
/// and stop it. It cannot execute a guest command, open a host path the plan
/// did not name, or apply any host policy.
///
/// Objective-C is the only interface Virtualization.framework publishes — the
/// framework exports no C entry point beyond its error-domain constant — so
/// every call here goes through `objc_msgSend` cast to the exact signature of
/// the selector being sent. That cast is required on arm64, where the variadic
/// form of `objc_msgSend` is not ABI-compatible with a concrete call.
///
/// Two completion handlers take Objective-C blocks. Both are `static`, capture
/// nothing, and are laid out per the documented block ABI with
/// `_NSConcreteGlobalBlock` as their class, so no block runtime helper and no
/// heap copy is involved; each stores its outcome in an atomic the caller
/// polls.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod darwin_virtualization {
    use super::{
        AtomicI32, CString, Duration, Instant, Ordering, Path, VzGuestError, VzGuestErrorKind,
        VzGuestRunReport, VzLinuxGuestPlan, c_char, c_int, c_void, mem, ptr,
    };
    use std::os::fd::{AsRawFd, OwnedFd};

    /// An Objective-C object pointer.
    type Id = *mut c_void;
    /// A registered Objective-C selector.
    type Sel = *const c_void;

    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn objc_msgSend();
        static _NSConcreteGlobalBlock: [*const c_void; 32];
        static _dispatch_main_q: [*const c_void; 8];
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: *const c_void;
        fn CFRunLoopRunInMode(mode: *const c_void, seconds: f64, return_after_source: u8) -> i32;
    }

    // Linking Virtualization is what puts its Objective-C classes, and the
    // Foundation classes it depends on, into this process. `VZErrorDomain` is
    // the framework's only exported C symbol and it is the value that
    // distinguishes an entitlement refusal from any other configuration error.
    #[link(name = "Virtualization", kind = "framework")]
    unsafe extern "C" {
        static VZErrorDomain: Id;
    }

    /// `VZErrorNotSupported`, the code Virtualization.framework returns when
    /// the process carries no virtualization entitlement. Copied from the
    /// macOS 15 SDK's `VZError.h`.
    const VZ_ERROR_NOT_SUPPORTED: i64 = 2;

    /// `VZVirtualMachineStateStopped`, from the macOS 15 SDK's
    /// `VZVirtualMachine.h`.
    const VZ_STATE_STOPPED: i64 = 0;
    /// `VZVirtualMachineStateError`, from the same header.
    const VZ_STATE_ERROR: i64 = 3;

    /// How long each run-loop turn services the queue before the state is
    /// re-read. The machine's queue is the main queue, so this is also the
    /// only place the framework's callbacks can run.
    const TURN_SECONDS: f64 = 0.02;

    /// `BLOCK_IS_GLOBAL` from the block ABI. A global block is never copied or
    /// disposed, which is why neither descriptor slot is needed.
    const BLOCK_IS_GLOBAL: i32 = 1 << 28;

    #[repr(C)]
    struct BlockDescriptor {
        reserved: u64,
        size: u64,
    }

    #[repr(C)]
    struct Block {
        isa: *const c_void,
        flags: i32,
        reserved: i32,
        invoke: *const c_void,
        descriptor: *const BlockDescriptor,
    }

    // SAFETY: both types are immutable statics containing only a function
    // pointer, integers, and the address of a libSystem global; nothing in
    // either is ever written after construction.
    unsafe impl Sync for Block {}
    unsafe impl Sync for BlockDescriptor {}

    static BLOCK_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
        reserved: 0,
        size: mem::size_of::<Block>() as u64,
    };

    /// `-1` unset, `0` the handler reported an error, `1` it reported success.
    static START_OUTCOME: AtomicI32 = AtomicI32::new(-1);
    static STOP_OUTCOME: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn start_completion(_block: *mut c_void, error: Id) {
        START_OUTCOME.store(i32::from(error.is_null()), Ordering::SeqCst);
    }

    extern "C" fn stop_completion(_block: *mut c_void, error: Id) {
        STOP_OUTCOME.store(i32::from(error.is_null()), Ordering::SeqCst);
    }

    static START_BLOCK: Block = Block {
        isa: (&raw const _NSConcreteGlobalBlock).cast(),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke: start_completion as *const c_void,
        descriptor: &raw const BLOCK_DESCRIPTOR,
    };

    static STOP_BLOCK: Block = Block {
        isa: (&raw const _NSConcreteGlobalBlock).cast(),
        flags: BLOCK_IS_GLOBAL,
        reserved: 0,
        invoke: stop_completion as *const c_void,
        descriptor: &raw const BLOCK_DESCRIPTOR,
    };

    fn selector(name: &str) -> Sel {
        let name = CString::new(name).expect("a selector name has no interior nul");
        // SAFETY: `name` is a valid nul-terminated C string for this call, and
        // the runtime copies whatever it needs.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    fn class(name: &str) -> Result<Id, VzGuestError> {
        let symbol = CString::new(name).expect("a class name has no interior nul");
        // SAFETY: `symbol` is a valid nul-terminated C string for this call.
        let value = unsafe { objc_getClass(symbol.as_ptr()) };
        if value.is_null() {
            return Err(VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("Objective-C class {name} is not present in this process"),
            ));
        }
        Ok(value)
    }

    /// Sends a selector taking no argument and returning an object.
    fn send(receiver: Id, name: &str) -> Id {
        // SAFETY: the transmute gives `objc_msgSend` the concrete signature of
        // the selector being sent, which is what the arm64 ABI requires; the
        // receiver is an object this module allocated or the runtime returned.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name))
        }
    }

    /// Sends a selector taking no argument and returning an integer.
    fn send_for_integer(receiver: Id, name: &str) -> i64 {
        // SAFETY: as `send`, with the selector's integer return type.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel) -> i64 =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name))
        }
    }

    /// Sends a selector taking no argument and returning an unsigned integer.
    fn send_for_unsigned(receiver: Id, name: &str) -> u64 {
        // SAFETY: as `send`, with the selector's unsigned return type.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel) -> u64 =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name))
        }
    }

    /// Sends a selector taking one object argument.
    fn send_object(receiver: Id, name: &str, argument: Id) -> Id {
        // SAFETY: as `send`, with one object parameter.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, Id) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), argument)
        }
    }

    /// Sends a selector taking one unsigned-integer argument.
    fn send_unsigned(receiver: Id, name: &str, argument: u64) -> Id {
        // SAFETY: as `send`, with one unsigned parameter.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, u64) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), argument)
        }
    }

    /// Sends a selector taking one `int` argument.
    fn send_int(receiver: Id, name: &str, argument: c_int) -> Id {
        // SAFETY: as `send`, with one `int` parameter.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, c_int) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), argument)
        }
    }

    /// Sends a selector taking two object arguments.
    fn send_two_objects(receiver: Id, name: &str, first: Id, second: Id) -> Id {
        // SAFETY: as `send`, with two object parameters.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, Id, Id) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), first, second)
        }
    }

    /// Sends a selector taking an object and a `BOOL`.
    fn send_object_and_flag(receiver: Id, name: &str, first: Id, second: bool) -> Id {
        // SAFETY: as `send`; `BOOL` is a signed char on this platform.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, Id, i8) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), first, i8::from(second))
        }
    }

    /// Sends a selector taking a C array of objects and its count.
    fn send_object_array(receiver: Id, name: &str, items: &[Id]) -> Id {
        // SAFETY: as `send`; `items` outlives the call and `NSArray` copies it.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, *const Id, usize) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), items.as_ptr(), items.len())
        }
    }

    /// Sends a selector taking an out-`NSError` and returning `BOOL`.
    fn send_for_flag_with_error(receiver: Id, name: &str, error: *mut Id) -> bool {
        // SAFETY: as `send`; `error` points at one writable `Id`.
        let value = unsafe {
            let call: unsafe extern "C" fn(Id, Sel, *mut Id) -> i8 =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), error)
        };
        value != 0
    }

    /// Sends a selector taking one completion-handler block.
    fn send_block(receiver: Id, name: &str, block: *const Block) {
        // SAFETY: as `send`; the block is a `'static` global that outlives any
        // retain the framework takes.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel, *const Block) =
                mem::transmute(objc_msgSend as *const c_void);
            call(receiver, selector(name), block);
        }
    }

    fn nsstring(value: &str) -> Result<Id, VzGuestError> {
        let bytes = CString::new(value).map_err(|_| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                "a guest plan string contains an interior nul",
            )
        })?;
        // SAFETY: `+[NSString stringWithUTF8String:]` copies the bytes.
        let value = unsafe {
            let call: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id =
                mem::transmute(objc_msgSend as *const c_void);
            call(
                class("NSString")?,
                selector("stringWithUTF8String:"),
                bytes.as_ptr(),
            )
        };
        Ok(value)
    }

    fn nsstring_text(value: Id) -> String {
        if value.is_null() {
            return String::new();
        }
        // SAFETY: `-[NSString UTF8String]` returns a nul-terminated buffer
        // valid for the duration of the autorelease scope this call is in.
        unsafe {
            let call: unsafe extern "C" fn(Id, Sel) -> *const c_char =
                mem::transmute(objc_msgSend as *const c_void);
            let raw = call(value, selector("UTF8String"));
            if raw.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
        }
    }

    fn file_url(path: &Path) -> Result<Id, VzGuestError> {
        let text = path.to_str().ok_or_else(|| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("path {} is not valid UTF-8", path.display()),
            )
        })?;
        Ok(send_object(
            class("NSURL")?,
            "fileURLWithPath:",
            nsstring(text)?,
        ))
    }

    fn array(items: &[Id]) -> Result<Id, VzGuestError> {
        Ok(send_object_array(
            class("NSArray")?,
            "arrayWithObjects:count:",
            items,
        ))
    }

    fn allocate(name: &str) -> Result<Id, VzGuestError> {
        Ok(send(send(class(name)?, "alloc"), "init"))
    }

    /// Classifies an `NSError` the framework produced, so the entitlement case
    /// is a distinct typed refusal instead of a generic failure.
    fn classify(error: Id) -> VzGuestError {
        if error.is_null() {
            return VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                "Virtualization.framework refused without supplying an error",
            );
        }
        let message = nsstring_text(send(error, "localizedDescription"));
        let code = send_for_integer(error, "code");
        let domain = send(error, "domain");
        // SAFETY: `VZErrorDomain` is an exported `NSString *` constant.
        let vz_domain = unsafe { VZErrorDomain };
        let same_domain = !domain.is_null()
            && !vz_domain.is_null()
            && send_object(domain, "isEqualToString:", vz_domain) as usize != 0;
        if same_domain
            && code == VZ_ERROR_NOT_SUPPORTED
            && message.contains("com.apple.security.virtualization")
        {
            return VzGuestError::new(VzGuestErrorKind::VirtualizationEntitlementMissing, message);
        }
        VzGuestError::new(VzGuestErrorKind::InvalidConfiguration, message)
    }

    /// One configured, validated, not-yet-started guest.
    ///
    /// Construction is the entitlement gate: [`VzGuest::validated`] returns a
    /// value only when `validateWithError:` said yes, and only that value can
    /// reach [`VzGuest::run_to_stop`]. There is no constructor that skips it.
    pub(crate) struct VzGuest {
        machine: Id,
        budget: Duration,
    }

    impl VzGuest {
        /// Builds and validates a guest configuration from an inert plan.
        ///
        /// # Errors
        ///
        /// Returns [`VzGuestErrorKind::VirtualizationEntitlementMissing`] when
        /// the host process was not signed with the entitlement,
        /// [`VzGuestErrorKind::MissingBootArtifact`] when a named artifact is
        /// absent, [`VzGuestErrorKind::UnsupportedSizing`] when the requested
        /// vCPU or memory value is outside this host's allowed range, and
        /// [`VzGuestErrorKind::InvalidConfiguration`] for every other refusal.
        #[allow(
            clippy::too_many_lines,
            reason = "the boot loader, sizing range check, console, share and the entitlement gate stay in one visible order, because each step's failure mode is the reason the next one is safe to take"
        )]
        pub(crate) fn validated(
            plan: &VzLinuxGuestPlan,
            console: &OwnedFd,
        ) -> Result<Self, VzGuestError> {
            // The supply-chain gate, ahead of every framework object and ahead
            // of the entitlement gate: a plan whose verification does not cover
            // exactly the two artifacts it boots is refused outright, and there
            // is no branch that continues with an unverified image.
            if !plan
                .verification
                .covers(&plan.kernel_image, &plan.initial_ramdisk)
            {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::GuestImageUnverified,
                    format!(
                        "no committed-pin verification covers kernel {} and root filesystem {}",
                        plan.kernel_image.display(),
                        plan.initial_ramdisk.display()
                    ),
                ));
            }
            plan.check_artifacts()?;

            let boot_loader = send_object(
                send(class("VZLinuxBootLoader")?, "alloc"),
                "initWithKernelURL:",
                file_url(&plan.kernel_image)?,
            );
            if boot_loader.is_null() {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::InvalidConfiguration,
                    "VZLinuxBootLoader refused the kernel image",
                ));
            }
            send_object(
                boot_loader,
                "setInitialRamdiskURL:",
                file_url(&plan.initial_ramdisk)?,
            );
            send_object(
                boot_loader,
                "setCommandLine:",
                nsstring(&plan.command_line)?,
            );

            let configuration = allocate("VZVirtualMachineConfiguration")?;
            send_object(configuration, "setBootLoader:", boot_loader);

            // Both sizing setters raise an Objective-C exception outside their
            // allowed range, and no Rust frame can catch that, so the range is
            // read from the class and checked here first.
            let class_object = class("VZVirtualMachineConfiguration")?;
            let minimum_processors = send_for_unsigned(class_object, "minimumAllowedCPUCount");
            let maximum_processors = send_for_unsigned(class_object, "maximumAllowedCPUCount");
            if plan.processor_count < minimum_processors
                || plan.processor_count > maximum_processors
            {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::UnsupportedSizing,
                    format!(
                        "{} vCPUs is outside this host's allowed range {minimum_processors}..={maximum_processors}",
                        plan.processor_count
                    ),
                ));
            }
            let minimum_memory = send_for_unsigned(class_object, "minimumAllowedMemorySize");
            let maximum_memory = send_for_unsigned(class_object, "maximumAllowedMemorySize");
            if plan.memory_bytes < minimum_memory || plan.memory_bytes > maximum_memory {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::UnsupportedSizing,
                    format!(
                        "{} bytes of guest memory is outside this host's allowed range {minimum_memory}..={maximum_memory}",
                        plan.memory_bytes
                    ),
                ));
            }
            send_unsigned(configuration, "setCPUCount:", plan.processor_count);
            send_unsigned(configuration, "setMemorySize:", plan.memory_bytes);

            // One virtio console. The guest's stdout is the caller's
            // descriptor and nothing else; the guest is given no input.
            let writing = send_int(
                send(class("NSFileHandle")?, "alloc"),
                "initWithFileDescriptor:",
                console.as_raw_fd(),
            );
            let attachment = send_two_objects(
                send(class("VZFileHandleSerialPortAttachment")?, "alloc"),
                "initWithFileHandleForReading:fileHandleForWriting:",
                ptr::null_mut(),
                writing,
            );
            let serial_port = allocate("VZVirtioConsoleDeviceSerialPortConfiguration")?;
            send_object(serial_port, "setAttachment:", attachment);
            send_object(configuration, "setSerialPorts:", array(&[serial_port])?);

            // One virtiofs share, writable, carrying exactly the directory the
            // plan named and nothing above it.
            let directory = send_object_and_flag(
                send(class("VZSharedDirectory")?, "alloc"),
                "initWithURL:readOnly:",
                file_url(&plan.shared_directory)?,
                false,
            );
            let share = send_object(
                send(class("VZSingleDirectoryShare")?, "alloc"),
                "initWithDirectory:",
                directory,
            );
            let device = send_object(
                send(class("VZVirtioFileSystemDeviceConfiguration")?, "alloc"),
                "initWithTag:",
                nsstring(&plan.share_tag)?,
            );
            send_object(device, "setShare:", share);
            send_object(
                configuration,
                "setDirectorySharingDevices:",
                array(&[device])?,
            );
            send_object(
                configuration,
                "setEntropyDevices:",
                array(&[allocate("VZVirtioEntropyDeviceConfiguration")?])?,
            );

            // The entitlement gate. A machine is never constructed from a
            // configuration that did not validate, because
            // `initWithConfiguration:queue:` raises an uncatchable
            // Objective-C exception when the entitlement is absent.
            let mut error: Id = ptr::null_mut();
            if !send_for_flag_with_error(configuration, "validateWithError:", &raw mut error) {
                return Err(classify(error));
            }

            // `_dispatch_main_q` is libdispatch's exported main-queue object;
            // `dispatch_get_main_queue()` is an inline C accessor for exactly
            // this address, and taking the address never reads the global.
            let queue: Id = (&raw const _dispatch_main_q).cast_mut().cast();
            let machine = send_two_objects(
                send(class("VZVirtualMachine")?, "alloc"),
                "initWithConfiguration:queue:",
                configuration,
                queue,
            );
            if machine.is_null() {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::InvalidConfiguration,
                    "VZVirtualMachine could not be created from a validated configuration",
                ));
            }
            Ok(Self {
                machine,
                budget: plan.budget,
            })
        }

        /// Starts the guest, waits for it to power itself off, and proves the
        /// machine reached the stopped state before returning.
        ///
        /// The machine's queue is the main queue, so this call must own the
        /// main thread: every turn of the loop runs the main run loop briefly,
        /// which is the only context the framework's callbacks execute in, and
        /// then re-reads the machine state from that same thread.
        ///
        /// # Errors
        ///
        /// Returns [`VzGuestErrorKind::StartRefused`] when the start handler
        /// reported a failure, [`VzGuestErrorKind::MachineError`] when the
        /// machine entered the framework's error state, and
        /// [`VzGuestErrorKind::BudgetExhausted`] when the guest did not stop
        /// in time — in which case the guest is stopped anyway, so no run
        /// leaves a live machine behind.
        pub(crate) fn run_to_stop(self) -> Result<VzGuestRunReport, VzGuestError> {
            START_OUTCOME.store(-1, Ordering::SeqCst);
            STOP_OUTCOME.store(-1, Ordering::SeqCst);
            let started = Instant::now();
            send_block(
                self.machine,
                "startWithCompletionHandler:",
                &raw const START_BLOCK,
            );

            let mut start_latency = None;
            let mut guest_initiated_stop = true;
            let mut failure = None;
            loop {
                Self::turn();
                match START_OUTCOME.load(Ordering::SeqCst) {
                    0 => {
                        failure = Some(VzGuestError::new(
                            VzGuestErrorKind::StartRefused,
                            "startWithCompletionHandler: reported a failure",
                        ));
                        guest_initiated_stop = false;
                        break;
                    }
                    1 if start_latency.is_none() => start_latency = Some(started.elapsed()),
                    _ => {}
                }
                let state = self.state();
                if state == VZ_STATE_STOPPED && start_latency.is_some() {
                    break;
                }
                if state == VZ_STATE_ERROR {
                    failure = Some(VzGuestError::new(
                        VzGuestErrorKind::MachineError,
                        "the machine entered VZVirtualMachineStateError",
                    ));
                    guest_initiated_stop = false;
                    break;
                }
                if started.elapsed() >= self.budget {
                    failure = Some(VzGuestError::new(
                        VzGuestErrorKind::BudgetExhausted,
                        format!(
                            "the guest did not power off within {} ms",
                            self.budget.as_millis()
                        ),
                    ));
                    guest_initiated_stop = false;
                    break;
                }
            }

            // Teardown runs on every path, including both failures above, so
            // no exit from this function leaves a running machine.
            let forced = self.stop_if_running();
            let final_state = self.state();
            if let Some(error) = failure {
                return Err(error);
            }
            Ok(VzGuestRunReport {
                start_latency: start_latency.unwrap_or_default(),
                total: started.elapsed(),
                final_state,
                guest_initiated_stop: guest_initiated_stop && !forced,
            })
        }

        /// Runs the main run loop for one turn so the framework can deliver
        /// callbacks on the queue that owns this machine.
        fn turn() {
            // SAFETY: `kCFRunLoopDefaultMode` is CoreFoundation's exported
            // mode constant and this call only services the current thread's
            // run loop.
            unsafe {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, TURN_SECONDS, 0);
            }
        }

        /// The framework's own state for this machine.
        fn state(&self) -> i64 {
            send_for_integer(self.machine, "state")
        }

        /// Stops a machine that is still running. Returns whether a stop had
        /// to be forced.
        fn stop_if_running(&self) -> bool {
            if self.state() == VZ_STATE_STOPPED {
                return false;
            }
            send_block(
                self.machine,
                "stopWithCompletionHandler:",
                &raw const STOP_BLOCK,
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                Self::turn();
                if self.state() == VZ_STATE_STOPPED {
                    break;
                }
            }
            true
        }
    }
}

// The guest kernel and virtiofs module are acquired at build time from
// Canonical using `GUEST_KERNEL_SOURCE_PIN_V1`. Runtime hashes both supplied
// artifacts against the committed digests before creating VM objects; this
// path performs no online acquisition.

/// Which of the two artifacts one guest boots from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestImageRole {
    /// The raw arm64 `Image` the boot loader loads.
    Kernel,
    /// The gzip cpio initramfs carrying the complete guest root filesystem.
    RootFilesystem,
}

impl GuestImageRole {
    /// The name this role carries in a refusal.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Kernel => "kernel image",
            Self::RootFilesystem => "root filesystem",
        }
    }
}

/// A committed content pin for one guest boot artifact.
///
/// Both the digest and the byte length are pinned. The length is not
/// redundant: it makes a truncated read fail with a refusal that names the
/// truncation instead of a digest mismatch, which is the difference between a
/// diagnosable failure and a mysterious one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestImagePin {
    /// Which artifact this pin governs.
    pub(crate) role: GuestImageRole,
    /// Lowercase hexadecimal SHA-256 of the artifact's complete bytes.
    pub(crate) sha256: &'static str,
    /// The artifact's exact length in bytes.
    pub(crate) byte_length: u64,
}

/// Content pin for the guest image.
///
/// The arm64 kernel comes from Canonical's signed archive, authenticated through
/// [`GUEST_KERNEL_SOURCE_PIN_V1::key_fingerprint`]. The reproducible root filesystem
/// build combines the pinned base image, Canonical's virtiofs module, and this
/// repository's guest-image scripts. Changing either artifact requires review and
/// an updated pin before runtime will boot it.
pub(crate) const GUEST_IMAGE_PIN_V1: [GuestImagePin; 2] = [
    GuestImagePin {
        role: GuestImageRole::Kernel,
        sha256: "ce3cccafc326c6e1cf88a35e2976df1c084f5b1349abc70d0c94f7573181450e",
        byte_length: 59_009_416,
    },
    GuestImagePin {
        role: GuestImageRole::RootFilesystem,
        sha256: "78145fa4735b71d614fdf27c8ee2a67d3e59f264d8618762f96a1679d33372b9",
        byte_length: 98_248_403,
    },
];

/// One archive Canonical publishes, pinned by the digest **Canonical records**
/// for it rather than by one computed from a download.
///
/// The distinction is the whole point of this type. A SHA-256 taken over bytes
/// that just arrived proves those bytes will not change next time; it says
/// nothing about who produced them. The values here are cross-checked against
/// the `Packages` index of a suite whose `InRelease` carries a good signature
/// from [`GuestKernelSourcePin::key_fingerprint`], and a disagreement between
/// the index and this constant is a refusal — so the digest is Canonical's
/// claim that a reviewed commit agreed with, in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublishedArchivePin {
    /// Binary package name, exactly as the index spells it.
    pub(crate) package: &'static str,
    /// Package version, exactly as the index spells it.
    pub(crate) version: &'static str,
    /// Architecture. Pinned so an arm64 build cannot silently take amd64.
    pub(crate) architecture: &'static str,
    /// Path under the archive root, exactly as the index's `Filename` says.
    pub(crate) pool_path: &'static str,
    /// Lowercase hexadecimal SHA-256, exactly as the index's `SHA256` says.
    pub(crate) sha256: &'static str,
    /// Byte length, exactly as the index's `Size` says.
    pub(crate) byte_length: u64,
}

/// Where the guest kernel comes from, and the one thing believed a priori.
///
/// **The chain, link by link.** Everything below the first line is verified
/// rather than trusted:
///
/// 1. `key_fingerprint` — Canonical's published archive-signing identity. This
///    is the anchor and the only trusted-by-assertion item in the chain; a
///    reviewer confirms it out of band against Canonical's own publication of
///    it. `key_sha256` pins the exact exported key bytes as well, so a keyring
///    substituted anywhere upstream fails twice rather than once.
/// 2. The suite's `InRelease`, verified with `gpgv` against a keyring holding
///    *only* that key. A good signature by any other key is still a refusal.
/// 3. The `SHA256` of `<component>/binary-<architecture>/Packages.xz`, read out
///    of that signed text.
/// 4. Each archive's `Filename`, `Size` and `SHA256`, read out of that verified
///    index and required to equal [`PublishedArchivePin`] exactly.
/// 5. The archive bytes, required to hash to what the index said.
/// 6. The kernel payload carved out of the archive and decompressed, required
///    to hash to [`GUEST_IMAGE_PIN_V1`]'s kernel entry, and the module payload
///    to `module_sha256`.
///
/// **What remains trusted by assertion**, stated because a chain that hides its
/// root is worse than one that names it: the fingerprint itself, and Canonical
/// as the publisher. Nothing here attests that Canonical's build of 6.8.0-117
/// corresponds to any particular source; that would need a reproducible-builds
/// attestation Canonical does not publish for kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestKernelSourcePin {
    /// Canonical's archive-signing key fingerprint, uppercase hexadecimal.
    pub(crate) key_fingerprint: &'static str,
    /// SHA-256 of that one key exported on its own.
    pub(crate) key_sha256: &'static str,
    /// Where the keyring carrying that key is fetched from. Its contents are
    /// not trusted: the key is exported from it by fingerprint and then
    /// checked against both pins above.
    pub(crate) keyring_url: &'static str,
    /// Archive root the suite and the pool hang off.
    pub(crate) archive_base: &'static str,
    /// Suite whose `InRelease` is verified.
    pub(crate) suite: &'static str,
    /// Component the index is read from.
    pub(crate) component: &'static str,
    /// Architecture pinned end to end.
    pub(crate) architecture: &'static str,
    /// Kernel release string, which names both the `vmlinuz` inside the kernel
    /// archive and the module directory inside the module archive.
    pub(crate) kernel_release: &'static str,
    /// The archive carrying `vmlinuz`.
    pub(crate) kernel_archive: PublishedArchivePin,
    /// The archive carrying `virtiofs.ko`, which must be the same publisher
    /// and the same kernel release — PID 1 inserts it with `finit_module`, and
    /// a vermagic mismatch is a boot that half-works.
    pub(crate) module_archive: PublishedArchivePin,
    /// SHA-256 of the decompressed `virtiofs.ko`, an input to the reproducible
    /// root-filesystem build rather than a boot artifact.
    pub(crate) module_sha256: &'static str,
    /// Byte length of the decompressed `virtiofs.ko`.
    pub(crate) module_byte_length: u64,
}

/// The committed kernel source chain. See [`GuestKernelSourcePin`].
pub(crate) const GUEST_KERNEL_SOURCE_PIN_V1: GuestKernelSourcePin = GuestKernelSourcePin {
    key_fingerprint: "F6ECB3762474EDA9D21B7022871920D1991BC93C",
    key_sha256: "5ebbeeb474034b1fa7e50abbe6f136e177fc826219e01f314b3623f7b3097e96",
    keyring_url: "https://ports.ubuntu.com/ubuntu-ports/project/ubuntu-archive-keyring.gpg",
    archive_base: "http://ports.ubuntu.com/ubuntu-ports",
    suite: "noble-updates",
    component: "main",
    architecture: "arm64",
    kernel_release: "6.8.0-117-generic",
    kernel_archive: PublishedArchivePin {
        package: "linux-image-6.8.0-117-generic",
        version: "6.8.0-117.117",
        architecture: "arm64",
        pool_path: "pool/main/l/linux-signed/linux-image-6.8.0-117-generic_6.8.0-117.117_arm64.deb",
        sha256: "fcdf0b1cd4529b30e7cdb76325bd0d29344ed23a430598b059da2f180e65b92a",
        byte_length: 18_280_800,
    },
    module_archive: PublishedArchivePin {
        package: "linux-modules-6.8.0-117-generic",
        version: "6.8.0-117.117",
        architecture: "arm64",
        pool_path: "pool/main/l/linux/linux-modules-6.8.0-117-generic_6.8.0-117.117_arm64.deb",
        sha256: "42425ac8e58fa2ca9f7bf89105becd94c0bd90908b21889ffffd7132406c5d51",
        byte_length: 86_999_232,
    },
    module_sha256: "b08fd0a005cbe889d5c5dad82f6100c41e33a4e1638c4af902de29e82361418a",
    module_byte_length: 55_713,
};

/// The acquisition step, relative to this crate's manifest directory.
///
/// The product never runs it. It is named here so the in-tree test that keeps
/// the script's pins equal to the constants above has one place to look, and
/// so a reader of the pin finds the step that produced it.
pub(crate) const GUEST_KERNEL_ACQUISITION_SCRIPT: &str = "guest-image/kernel.sh";

/// The pin governing one role, taken from the committed set.
///
/// # Panics
///
/// Panics only if the committed pin set ever stops covering a role, which is a
/// source-level contradiction rather than a runtime condition.
pub(crate) fn committed_pin(role: GuestImageRole) -> GuestImagePin {
    let mut index = 0;
    while index < GUEST_IMAGE_PIN_V1.len() {
        let candidate = GUEST_IMAGE_PIN_V1[index];
        if candidate.role as u8 == role as u8 {
            return candidate;
        }
        index += 1;
    }
    panic!("the committed guest-image pin set must cover every role");
}

/// One artifact whose complete bytes were read and matched its committed pin.
///
/// The only constructor is [`VerifiedGuestArtifact::verify`]. A value of this
/// type is therefore evidence, not a label: it cannot be produced from an
/// artifact that failed, and it records what was actually read rather than what
/// was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedGuestArtifact {
    role: GuestImageRole,
    path: PathBuf,
    byte_length: u64,
    sha256: String,
    verification: Duration,
}

impl VerifiedGuestArtifact {
    /// Reads the complete artifact and refuses unless it matches the pin.
    ///
    /// The read is streamed in fixed chunks so a 100 MB root filesystem never
    /// becomes a 100 MB allocation, and the length is compared first so a
    /// truncated or replaced-by-a-larger-file artifact is named as such.
    ///
    /// # Errors
    ///
    /// Returns [`VzGuestErrorKind::MissingBootArtifact`] when the path is not a
    /// readable file, [`VzGuestErrorKind::GuestImageLengthMismatch`] when the
    /// artifact is not exactly the pinned length, and
    /// [`VzGuestErrorKind::GuestImageDigestMismatch`] when the bytes hash to
    /// anything other than the pinned digest. There is no weaker outcome: this
    /// function returns a verified artifact or an error.
    pub(crate) fn verify(pin: GuestImagePin, path: &Path) -> Result<Self, VzGuestError> {
        let started = Instant::now();
        let mut file = std::fs::File::open(path).map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::MissingBootArtifact,
                format!(
                    "{} {} could not be opened for verification: {error}",
                    pin.role.label(),
                    path.display()
                ),
            )
        })?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1 << 20];
        let mut length = 0_u64;
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                VzGuestError::new(
                    VzGuestErrorKind::MissingBootArtifact,
                    format!(
                        "{} {} could not be read for verification: {error}",
                        pin.role.label(),
                        path.display()
                    ),
                )
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            length += count as u64;
        }
        if length != pin.byte_length {
            return Err(VzGuestError::new(
                VzGuestErrorKind::GuestImageLengthMismatch,
                format!(
                    "{} {} is {length} bytes; the committed pin is {} bytes",
                    pin.role.label(),
                    path.display(),
                    pin.byte_length
                ),
            ));
        }
        let observed = hex_digest(&hasher.finalize());
        if observed != pin.sha256 {
            return Err(VzGuestError::new(
                VzGuestErrorKind::GuestImageDigestMismatch,
                format!(
                    "{} {} hashes to {observed}; the committed pin is {}",
                    pin.role.label(),
                    path.display(),
                    pin.sha256
                ),
            ));
        }
        Ok(Self {
            role: pin.role,
            path: path.to_path_buf(),
            byte_length: length,
            sha256: observed,
            verification: started.elapsed(),
        })
    }

    /// The verified artifact's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// What reading and hashing the complete artifact cost.
    pub(crate) const fn verification_cost(&self) -> Duration {
        self.verification
    }

    /// The digest that matched.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The artifact's verified length.
    pub(crate) const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// Both boot artifacts, each verified against its committed pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestImageVerification {
    kernel: VerifiedGuestArtifact,
    root_filesystem: VerifiedGuestArtifact,
}

impl GuestImageVerification {
    /// Verifies both artifacts against the committed pin set.
    ///
    /// # Errors
    ///
    /// Propagates the first refusal from [`VerifiedGuestArtifact::verify`]. A
    /// partially verified image is never returned.
    pub(crate) fn verify_committed(
        kernel: &Path,
        root_filesystem: &Path,
    ) -> Result<Self, VzGuestError> {
        Ok(Self {
            kernel: VerifiedGuestArtifact::verify(committed_pin(GuestImageRole::Kernel), kernel)?,
            root_filesystem: VerifiedGuestArtifact::verify(
                committed_pin(GuestImageRole::RootFilesystem),
                root_filesystem,
            )?,
        })
    }

    /// Composes a verification from two artifacts that were each verified.
    ///
    /// Both parameters are [`VerifiedGuestArtifact`] values, so there is no way
    /// to compose one from an artifact that did not verify.
    pub(crate) const fn from_parts(
        kernel: VerifiedGuestArtifact,
        root_filesystem: VerifiedGuestArtifact,
    ) -> Self {
        Self {
            kernel,
            root_filesystem,
        }
    }

    /// Whether this verification is about exactly the two paths named.
    ///
    /// [`VzGuest::validated`] calls this rather than trusting that a plan and
    /// its verification belong together, so a verification for one artifact
    /// cannot be carried over to a boot of another.
    pub(crate) fn covers(&self, kernel: &Path, root_filesystem: &Path) -> bool {
        self.kernel.path == kernel && self.root_filesystem.path == root_filesystem
    }

    /// What verifying both artifacts cost.
    pub(crate) fn total_cost(&self) -> Duration {
        self.kernel.verification + self.root_filesystem.verification
    }

    /// The verified kernel.
    pub(crate) const fn kernel(&self) -> &VerifiedGuestArtifact {
        &self.kernel
    }

    /// The verified root filesystem.
    pub(crate) const fn root_filesystem(&self) -> &VerifiedGuestArtifact {
        &self.root_filesystem
    }
}

/// Lowercase hexadecimal for a digest, without pulling in an encoder.
fn hex_digest(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ignored = write!(text, "{byte:02x}");
    }
    text
}

// The guest's main dispatch queue belongs to a separate process. Lifecycle
// control uses atomic records on the existing virtiofs share, without an
// additional network channel or device.

/// Names inside the share's control directory. One place, so the host and the
/// guest supervisor cannot drift apart silently.
pub(crate) mod control_channel {
    /// Directory under the share that carries the whole channel.
    pub(crate) const DIRECTORY: &str = "control";
    /// Written once by the guest when the share is mounted and the command
    /// image is staged into guest RAM; carries the staging cost in ms.
    pub(crate) const READY: &str = "ready";
    /// Rewritten by the guest every poll turn: `<turn> <guest-uptime-seconds>`.
    pub(crate) const GUEST_HEARTBEAT: &str = "hb";
    /// Rewritten by the host: a strictly increasing integer the guest watches
    /// so a host that dies does not leave a guest running forever.
    pub(crate) const HOST_HEARTBEAT: &str = "hostbeat";
    /// Prefix of a host-to-guest request, renamed into place.
    pub(crate) const REQUEST_PREFIX: &str = "req.";
    /// Prefix of the guest's merged stdout and stderr for one request.
    pub(crate) const OUTPUT_PREFIX: &str = "out.";
    /// Prefix of the guest's result record: `<exit-code> <duration-ms>`.
    pub(crate) const RESULT_PREFIX: &str = "res.";
}

/// How large a guest is, kept separate from the artifacts it boots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VzGuestSizing {
    /// Requested vCPU count.
    pub(crate) processor_count: u64,
    /// Requested guest memory in bytes.
    pub(crate) memory_bytes: u64,
    /// The outer bound on one guest's whole life. The guest-host process stops
    /// the machine when this expires, so a guest cannot outlive its budget even
    /// if every other liveness signal fails.
    pub(crate) budget: Duration,
}

impl VzGuestSizing {
    /// Sizing used by the guest lifecycle probes.
    pub(crate) const fn default_development() -> Self {
        Self {
            processor_count: 4,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            budget: Duration::from_mins(10),
        }
    }
}

/// What the guest last said about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestHeartbeat {
    /// The guest supervisor's poll-turn counter. Strictly increasing while the
    /// guest is idle; frozen while a command runs, because the supervisor
    /// serves one command at a time.
    pub(crate) turn: u64,
    /// Guest uptime in whole milliseconds when that turn was published.
    pub(crate) guest_uptime_millis: u64,
}

/// How the guest-host process ended, as this process could observe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestHostExit {
    /// It was reaped, carrying this exit code when it had one.
    Reaped(Option<i32>),
    /// Its status could not be read at all, which is treated as gone: an
    /// unprovable liveness is never reported as liveness.
    Unobservable,
}

impl GuestHostExit {
    /// The exit code when there was one.
    pub(crate) const fn code(self) -> Option<i32> {
        match self {
            Self::Reaped(code) => code,
            Self::Unobservable => None,
        }
    }
}

/// A guest's observed health at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VzGuestHealth {
    /// The guest-host process is alive, the share is mounted, and the guest
    /// supervisor's heartbeat advanced inside its bound.
    Serving(GuestHeartbeat),
    /// The guest-host process is alive and the guest is executing a command, so
    /// the heartbeat is expected to be frozen. Distinguishing this from a hang
    /// is why the host tracks whether it is waiting for a result.
    Executing(GuestHeartbeat),
}

/// Why a guest cannot be used.
///
/// Every variant is a refusal. There is deliberately no variant meaning "run it
/// on the host instead": this module contains no host-execution path at all,
/// and [`VzGuestSession::run_contained`] is the only way it runs anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VzGuestUnhealthy {
    /// The guest-host process exited; the machine died with it.
    HostProcessExited(Option<i32>),
    /// The share carries no heartbeat at all.
    NoHeartbeat,
    /// The heartbeat stopped advancing while the guest was idle.
    HeartbeatStalled {
        /// The last turn observed.
        turn: u64,
        /// How long it has been frozen.
        frozen_for: Duration,
    },
    /// The control directory disappeared, so the share is gone.
    ShareLost,
}

impl fmt::Display for VzGuestUnhealthy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostProcessExited(code) => write!(
                formatter,
                "the guest-host process exited with {code:?}; the machine died with it"
            ),
            Self::NoHeartbeat => {
                write!(formatter, "the guest published no heartbeat on the share")
            }
            Self::HeartbeatStalled { turn, frozen_for } => write!(
                formatter,
                "the guest heartbeat has been frozen at turn {turn} for {} ms while idle",
                frozen_for.as_millis()
            ),
            Self::ShareLost => write!(
                formatter,
                "the share's control directory is gone, so the guest lost its only channel"
            ),
        }
    }
}

/// How one contained command ended.
///
/// The third variant is the important one. A guest that dies mid-command leaves
/// an effect whose outcome nobody observed, and the only honest report is that
/// it is unknown — the same shape the runner's existing recovery uses for an
/// interrupted native child, and the shape the durable model already
/// reconciles. It is never reported as a failure and never as a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VzGuestCommandOutcome {
    /// The guest ran the command to completion and reported its exit status.
    Completed {
        /// The command's exit code as the guest observed it.
        exit_code: i32,
        /// What the guest measured the command costing.
        guest_duration: Duration,
        /// Host-observed round trip, including channel latency.
        host_duration: Duration,
    },
    /// The command was dispatched and its outcome is not known.
    Uncertain {
        /// Why the outcome cannot be established.
        reason: VzGuestUnhealthy,
        /// Whether the guest had acknowledged the request by consuming it.
        request_consumed: bool,
    },
}

/// What a completed teardown proved, rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VzGuestTeardownProof {
    /// The guest-host process's exit status, obtained by reaping it.
    pub(crate) host_process_exit: Option<i32>,
    /// Whether the guest powered itself off rather than being forced.
    pub(crate) guest_initiated: bool,
    /// The guest heartbeat read twice after teardown, unchanged both times: a
    /// mounted share with a live supervisor cannot produce that.
    pub(crate) heartbeat_frozen_at: Option<u64>,
    /// Open descriptors this process held before the guest booted and after it
    /// was torn down. Equal counts is the claim; the numbers are reported so a
    /// reader can see it was measured rather than asserted.
    pub(crate) host_descriptors_before: usize,
    /// See [`Self::host_descriptors_before`].
    pub(crate) host_descriptors_after: usize,
    /// How long teardown took from the shutdown request to a reaped process.
    pub(crate) elapsed: Duration,
    /// Whether the bounded escalation had to signal the guest-host process.
    pub(crate) escalated: bool,
}

/// One live guest this process owns end to end.
///
/// Boot, share, health, and teardown are all here, and every one of them is a
/// measurement rather than an assumption: boot waits for the guest to say it is
/// ready, health reads a heartbeat the guest publishes, dispatch waits for a
/// result record, and teardown reaps the guest-host process and re-reads the
/// heartbeat to prove nothing is still writing it.
pub(crate) struct VzGuestSession {
    host: std::process::Child,
    control: PathBuf,
    verification: GuestImageVerification,
    next_sequence: u64,
    host_beat: u64,
    ready_latency: Duration,
    staging_millis: u64,
    descriptors_at_boot: usize,
    last_heartbeat: Option<(GuestHeartbeat, Instant)>,
}

/// How long a guest may take to publish its readiness before the boot is
/// refused. Generous against the measured 1.75 s, because a bound that trips on
/// a slow machine is a false refusal, and bounded-but-slow is still bounded.
pub(crate) const GUEST_READY_DEADLINE: Duration = Duration::from_mins(1);

/// How long an idle guest's heartbeat may stay frozen before the guest is
/// unhealthy. The guest publishes one every poll turn, measured at ~10 ms.
pub(crate) const GUEST_HEARTBEAT_BOUND: Duration = Duration::from_secs(5);

/// How often the host re-reads the share while waiting for something.
pub(crate) const GUEST_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// The bound on teardown, after which the escalation gives up rather than
/// blocking forever. D-0013's lesson: a wait that can hang is strictly worse
/// than a wait that can refuse.
pub(crate) const GUEST_TEARDOWN_DEADLINE: Duration = Duration::from_secs(30);

impl VzGuestSession {
    /// Verifies the image, boots one guest, and waits for it to say it is ready.
    ///
    /// The verification happens before the guest-host process is spawned, so an
    /// artifact that does not match its committed pin never reaches a boot
    /// loader. The share's control directory is created by this call and is the
    /// only thing this process writes into the share.
    ///
    /// # Errors
    ///
    /// Propagates every verification refusal;
    /// [`VzGuestErrorKind::MissingBootArtifact`] when the share is not a
    /// directory or its control directory cannot be created;
    /// [`VzGuestErrorKind::StartRefused`] when the guest-host process cannot be
    /// spawned; and [`VzGuestErrorKind::GuestNeverBecameReady`] when the guest
    /// does not publish readiness inside [`GUEST_READY_DEADLINE`] — in which
    /// case the guest-host process is torn down before returning, so a refused
    /// boot leaves no machine.
    pub(crate) fn boot(
        kernel: &Path,
        root_filesystem: &Path,
        share: &Path,
        share_tag: &str,
        command_line: &str,
        sizing: VzGuestSizing,
    ) -> Result<Self, VzGuestError> {
        let verification = GuestImageVerification::verify_committed(kernel, root_filesystem)?;
        if !share.is_dir() {
            return Err(VzGuestError::new(
                VzGuestErrorKind::MissingBootArtifact,
                format!("shared directory {} is not a directory", share.display()),
            ));
        }
        let control = share.join(control_channel::DIRECTORY);
        std::fs::create_dir_all(&control).map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::MissingBootArtifact,
                format!(
                    "the control directory {} could not be created: {error}",
                    control.display()
                ),
            )
        })?;
        for stale in [control_channel::READY, control_channel::GUEST_HEARTBEAT] {
            let _ignored = std::fs::remove_file(control.join(stale));
        }

        let descriptors_at_boot = open_descriptor_count();
        let program = std::env::current_exe().map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::StartRefused,
                format!("this process has no executable path to re-launch: {error}"),
            )
        })?;
        // The one and only process this module ever spawns, and it is this same
        // binary with the internal guest argument. There is no other command,
        // no shell, and no host-execution path anywhere in this module.
        let host = Command::new(program)
            .arg(MACOS_VZ_GUEST_ARGUMENT)
            .arg(verification.kernel().path())
            .arg(verification.root_filesystem().path())
            .arg(share)
            .arg(share_tag)
            .arg(command_line)
            .arg(sizing.processor_count.to_string())
            .arg(sizing.memory_bytes.to_string())
            .arg(sizing.budget.as_millis().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                VzGuestError::new(
                    VzGuestErrorKind::StartRefused,
                    format!("the guest-host process could not be spawned: {error}"),
                )
            })?;

        let mut session = Self {
            host,
            control,
            verification,
            next_sequence: 1,
            host_beat: 0,
            ready_latency: Duration::ZERO,
            staging_millis: 0,
            descriptors_at_boot,
            last_heartbeat: None,
        };
        match session.await_ready() {
            Ok(()) => Ok(session),
            Err(error) => {
                // A boot that refuses must not leave a machine running, so the
                // same bounded escalation teardown runs before the refusal is
                // returned.
                let _ignored = session.force_down();
                Err(error)
            }
        }
    }

    fn await_ready(&mut self) -> Result<(), VzGuestError> {
        let started = Instant::now();
        let ready = self.control.join(control_channel::READY);
        loop {
            self.publish_host_heartbeat();
            // Readiness requires a serving heartbeat, not merely a startup marker.
            if let (Ok(text), Some(beat)) =
                (std::fs::read_to_string(&ready), self.read_guest_heartbeat())
            {
                self.ready_latency = started.elapsed();
                self.staging_millis = text.trim().parse().unwrap_or(0);
                self.last_heartbeat = Some((beat, Instant::now()));
                return Ok(());
            }
            if let Some(status) = self.host_exited() {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::GuestNeverBecameReady,
                    format!(
                        "the guest-host process exited with {status:?} before the guest published readiness"
                    ),
                ));
            }
            if started.elapsed() >= GUEST_READY_DEADLINE {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::GuestNeverBecameReady,
                    format!(
                        "the guest did not publish readiness within {} ms",
                        GUEST_READY_DEADLINE.as_millis()
                    ),
                ));
            }
            std::thread::sleep(GUEST_POLL_INTERVAL);
        }
    }

    /// What boot cost, from spawn to the guest's own readiness mark.
    pub(crate) const fn ready_latency(&self) -> Duration {
        self.ready_latency
    }

    /// What the guest measured staging the command image into guest RAM.
    pub(crate) const fn staging_millis(&self) -> u64 {
        self.staging_millis
    }

    /// The verification this guest booted from.
    pub(crate) const fn verification(&self) -> &GuestImageVerification {
        &self.verification
    }

    /// The guest-host process this session owns.
    pub(crate) fn guest_host_pid(&self) -> u32 {
        self.host.id()
    }

    /// The control directory this session talks to the guest through.
    pub(crate) fn control_directory(&self) -> &Path {
        &self.control
    }

    /// Kills the guest-host process so a probe can measure what a dead guest
    /// does to the health gate.
    ///
    /// This exists only for the enforced half of the health probe. It is the
    /// one input that probe varies, and varying it any other way — unplugging
    /// the share, hanging the supervisor — would test a different failure.
    pub(crate) fn kill_guest_host_for_probe(&mut self) {
        let _ignored = self.host.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && self.host_exited().is_none() {
            std::thread::sleep(GUEST_POLL_INTERVAL);
        }
    }

    /// Reads the guest's current health from operating-system-owned state and
    /// the guest's own published heartbeat.
    ///
    /// This is the fail-closed gate. It never returns a value meaning "unknown
    /// but proceed": either the guest is serving, or the caller receives a
    /// typed refusal naming what is wrong.
    ///
    /// # Errors
    ///
    /// Returns [`VzGuestErrorKind::GuestUnhealthy`] carrying the exact
    /// [`VzGuestUnhealthy`] reason.
    pub(crate) fn health(&mut self) -> Result<VzGuestHealth, VzGuestError> {
        self.publish_host_heartbeat();
        if let Some(status) = self.host_exited() {
            return Err(unhealthy(&VzGuestUnhealthy::HostProcessExited(
                status.code(),
            )));
        }
        if !self.control.is_dir() {
            return Err(unhealthy(&VzGuestUnhealthy::ShareLost));
        }
        let Some(beat) = self.read_guest_heartbeat() else {
            return Err(unhealthy(&VzGuestUnhealthy::NoHeartbeat));
        };
        let now = Instant::now();
        match self.last_heartbeat {
            Some((previous, seen_at)) if previous.turn == beat.turn => {
                let frozen_for = now.saturating_duration_since(seen_at);
                if frozen_for >= GUEST_HEARTBEAT_BOUND {
                    return Err(unhealthy(&VzGuestUnhealthy::HeartbeatStalled {
                        turn: beat.turn,
                        frozen_for,
                    }));
                }
                Ok(VzGuestHealth::Executing(beat))
            }
            _ => {
                self.last_heartbeat = Some((beat, now));
                Ok(VzGuestHealth::Serving(beat))
            }
        }
    }

    /// Dispatches one command into the guest and waits for its result.
    ///
    /// Health is checked before the request is written, so a dead or hung guest
    /// refuses before any effect is created. While waiting, the guest-host
    /// process is watched: if it dies, the outcome becomes
    /// [`VzGuestCommandOutcome::Uncertain`] rather than a failure, because a
    /// command that was dispatched and not observed is exactly the ambiguous
    /// case the durable model must reconcile rather than replay.
    ///
    /// # Errors
    ///
    /// Returns [`VzGuestErrorKind::GuestUnhealthy`] when the pre-dispatch
    /// health check refuses, and [`VzGuestErrorKind::BudgetExhausted`] when the
    /// deadline expires with the guest still healthy.
    pub(crate) fn run_contained(
        &mut self,
        argv: &[String],
        deadline: Duration,
    ) -> Result<(VzGuestCommandOutcome, String), VzGuestError> {
        // Fail closed before anything is dispatched.
        self.health()?;

        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let mut body = String::from("exec\n");
        for argument in argv {
            body.push_str(argument);
            body.push('\n');
        }
        let request = self
            .control
            .join(format!("{}{sequence}", control_channel::REQUEST_PREFIX));
        let staged = self.control.join(format!(".host.{sequence}"));
        std::fs::write(&staged, body.as_bytes()).map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("the request could not be staged on the share: {error}"),
            )
        })?;
        std::fs::rename(&staged, &request).map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::InvalidConfiguration,
                format!("the request could not be published on the share: {error}"),
            )
        })?;

        let started = Instant::now();
        let result = self
            .control
            .join(format!("{}{sequence}", control_channel::RESULT_PREFIX));
        let output = self
            .control
            .join(format!("{}{sequence}", control_channel::OUTPUT_PREFIX));
        loop {
            self.publish_host_heartbeat();
            if let Ok(text) = std::fs::read_to_string(&result) {
                let host_duration = started.elapsed();
                let mut fields = text.split_whitespace();
                let exit_code = fields
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(-1);
                let guest_millis = fields
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(0);
                let captured = std::fs::read_to_string(&output).unwrap_or_default();
                return Ok((
                    VzGuestCommandOutcome::Completed {
                        exit_code,
                        guest_duration: Duration::from_millis(guest_millis),
                        host_duration,
                    },
                    captured,
                ));
            }
            if let Some(status) = self.host_exited() {
                return Ok((
                    VzGuestCommandOutcome::Uncertain {
                        reason: VzGuestUnhealthy::HostProcessExited(status.code()),
                        request_consumed: !request.exists(),
                    },
                    String::new(),
                ));
            }
            if !self.control.is_dir() {
                return Ok((
                    VzGuestCommandOutcome::Uncertain {
                        reason: VzGuestUnhealthy::ShareLost,
                        request_consumed: false,
                    },
                    String::new(),
                ));
            }
            if started.elapsed() >= deadline {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::BudgetExhausted,
                    format!(
                        "the guest did not report a result for command {sequence} within {} ms",
                        deadline.as_millis()
                    ),
                ));
            }
            std::thread::sleep(GUEST_POLL_INTERVAL);
        }
    }

    /// Asks the guest to power itself off, then proves the teardown.
    ///
    /// The proof is read from state this process does not own: the guest-host
    /// process is reaped for its exit status, the guest heartbeat is read twice
    /// afterwards and must be identical both times (a mounted share with a live
    /// supervisor republishes it every poll turn), and this process's open
    /// descriptor count is compared with the count taken before the boot.
    ///
    /// # Errors
    ///
    /// Returns [`VzGuestErrorKind::BudgetExhausted`] when the guest-host
    /// process is still alive after [`GUEST_TEARDOWN_DEADLINE`] of bounded
    /// escalation. The escalation never blocks indefinitely.
    pub(crate) fn shutdown(mut self) -> Result<VzGuestTeardownProof, VzGuestError> {
        let started = Instant::now();
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let staged = self.control.join(format!(".host.{sequence}"));
        let request = self
            .control
            .join(format!("{}{sequence}", control_channel::REQUEST_PREFIX));
        let requested = std::fs::write(&staged, b"shutdown\n")
            .and_then(|()| std::fs::rename(&staged, &request))
            .is_ok();

        let mut escalated = false;
        let status = loop {
            if let Some(status) = self.host_exited() {
                break status;
            }
            if started.elapsed() >= GUEST_TEARDOWN_DEADLINE {
                return Err(VzGuestError::new(
                    VzGuestErrorKind::BudgetExhausted,
                    format!(
                        "the guest-host process was still alive {} ms after a shutdown request and repeated signals",
                        GUEST_TEARDOWN_DEADLINE.as_millis()
                    ),
                ));
            }
            // A guest that will not take a graceful shutdown is escalated on
            // every turn rather than waited on indefinitely.
            if !requested || started.elapsed() >= Duration::from_secs(10) {
                escalated = true;
                let _ignored = self.host.kill();
            }
            std::thread::sleep(GUEST_POLL_INTERVAL);
        };

        let first = self.read_guest_heartbeat();
        std::thread::sleep(Duration::from_millis(200));
        let second = self.read_guest_heartbeat();
        let heartbeat_frozen_at = match (first, second) {
            (Some(one), Some(two)) if one.turn == two.turn => Some(one.turn),
            _ => None,
        };

        Ok(VzGuestTeardownProof {
            host_process_exit: status.code(),
            guest_initiated: !escalated,
            heartbeat_frozen_at,
            host_descriptors_before: self.descriptors_at_boot,
            host_descriptors_after: open_descriptor_count(),
            elapsed: started.elapsed(),
            escalated,
        })
    }

    /// Tears the guest down without requiring it to cooperate. Used when a boot
    /// refuses, where there is nothing to ask politely.
    fn force_down(&mut self) -> Option<GuestHostExit> {
        let deadline = Instant::now() + GUEST_TEARDOWN_DEADLINE;
        loop {
            if let Some(status) = self.host_exited() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            let _ignored = self.host.kill();
            std::thread::sleep(GUEST_POLL_INTERVAL);
        }
    }

    /// `Some(status)` once the guest-host process has been reaped.
    fn host_exited(&mut self) -> Option<GuestHostExit> {
        match self.host.try_wait() {
            Ok(Some(status)) => Some(GuestHostExit::Reaped(status.code())),
            Ok(None) => None,
            // A wait that fails cannot prove the process is alive, and treating
            // an unprovable liveness as liveness is the failure mode this whole
            // module exists to avoid.
            Err(_) => Some(GuestHostExit::Unobservable),
        }
    }

    fn read_guest_heartbeat(&self) -> Option<GuestHeartbeat> {
        let text =
            std::fs::read_to_string(self.control.join(control_channel::GUEST_HEARTBEAT)).ok()?;
        let mut fields = text.split_whitespace();
        let turn = fields.next()?.parse().ok()?;
        // `/proc/uptime` is "<seconds>.<centiseconds>"; it is parsed as two
        // integers rather than through a float so that no rounding, truncation,
        // or sign question enters a liveness measurement.
        let uptime = fields.next()?;
        let (seconds, centiseconds) = uptime.split_once('.').unwrap_or((uptime, "0"));
        let seconds: u64 = seconds.parse().ok()?;
        let centiseconds: u64 = centiseconds.get(..2).unwrap_or("0").parse().ok()?;
        Some(GuestHeartbeat {
            turn,
            guest_uptime_millis: seconds * 1000 + centiseconds * 10,
        })
    }

    /// Publishes host liveness so the guest can shut down if its owner dies.
    fn publish_host_heartbeat(&mut self) {
        self.host_beat += 1;
        let staged = self.control.join(".hostbeat.tmp");
        if std::fs::write(&staged, self.host_beat.to_string().as_bytes()).is_ok() {
            let _ignored =
                std::fs::rename(&staged, self.control.join(control_channel::HOST_HEARTBEAT));
        }
    }
}

/// How many descriptors this process currently holds.
///
/// `/dev/fd` is the kernel's own view on both supported platforms, so this is
/// operating-system-owned state rather than bookkeeping this module maintains
/// about itself.
pub(crate) fn open_descriptor_count() -> usize {
    std::fs::read_dir("/dev/fd").map_or(0, |entries| entries.flatten().count())
}

fn unhealthy(reason: &VzGuestUnhealthy) -> VzGuestError {
    VzGuestError::new(VzGuestErrorKind::GuestUnhealthy, reason.to_string())
}

// Lifecycle probes run in the signed product binary because VM boot needs
// its entitlement. Probes use single-input controls, tear down their guests,
// and grant no production authority.

/// The exact internal argument that runs one lifecycle probe.
pub(crate) const MACOS_VZ_LIFECYCLE_PROBE_ARGUMENT: &str =
    "--grok-build-macos-vz-lifecycle-probe-v1";

/// Runs one lifecycle probe when the exact internal argument is present.
///
/// Usage: `<probe> <kernel> <root filesystem> <share root> [count]`, where the
/// share root is a directory this probe creates per-guest subdirectories under.
#[doc(hidden)]
#[must_use]
pub fn run_macos_vz_lifecycle_probe_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    if arguments.next()? != MACOS_VZ_LIFECYCLE_PROBE_ARGUMENT {
        return None;
    }
    let rest = arguments.collect::<Vec<String>>();
    let [probe, kernel, root_filesystem, share_root, tail @ ..] = rest.as_slice() else {
        eprintln!("vz-lifecycle: expected <probe> <kernel> <rootfs> <share root> [count]");
        return Some(std::process::ExitCode::from(VZ_GUEST_REFUSED));
    };
    let count = tail
        .first()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(5);
    let inputs = ProbeInputs {
        kernel: PathBuf::from(kernel),
        root_filesystem: PathBuf::from(root_filesystem),
        share_root: PathBuf::from(share_root),
        count,
    };
    let outcome = match probe.as_str() {
        "verify" => probe_verify(&inputs),
        "per-command" => probe_per_command_guest(&inputs),
        "persistent" => probe_persistent_guest(&inputs),
        "residue" => probe_residue(&inputs),
        "health" => probe_health(&inputs),
        "teardown" => probe_teardown(&inputs),
        "crash-wait" => probe_crash_wait(&inputs),
        "suite" => probe_canary_suite(&inputs),
        "teardown-escalation" => probe_teardown_escalation(&inputs),
        other => Err(VzGuestError::new(
            VzGuestErrorKind::InvalidConfiguration,
            format!("unknown lifecycle probe {other}"),
        )),
    };
    Some(match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            println!("GBDLC refused {error}");
            std::process::ExitCode::from(VZ_GUEST_REFUSED)
        }
    })
}

/// What every probe is given.
struct ProbeInputs {
    kernel: PathBuf,
    root_filesystem: PathBuf,
    share_root: PathBuf,
    count: usize,
}

impl ProbeInputs {
    /// A private share for one guest, holding whatever the caller staged in the
    /// share root plus this guest's own control directory.
    fn share(&self, label: &str) -> Result<PathBuf, VzGuestError> {
        let share = self.share_root.join(format!("guest-{label}"));
        let _ignored = std::fs::remove_dir_all(&share);
        std::fs::create_dir_all(share.join("deps")).map_err(|error| {
            VzGuestError::new(
                VzGuestErrorKind::MissingBootArtifact,
                format!("the probe share could not be created: {error}"),
            )
        })?;
        for (source, destination) in [
            (
                self.share_root.join("grok-build-runner"),
                share.join("grok-build-runner"),
            ),
            (
                self.share_root.join("deps").join("runner-test"),
                share.join("deps").join("runner-test"),
            ),
        ] {
            if source.is_file() {
                std::fs::copy(&source, &destination).map_err(|error| {
                    VzGuestError::new(
                        VzGuestErrorKind::MissingBootArtifact,
                        format!("the probe share could not be populated: {error}"),
                    )
                })?;
            }
        }
        Ok(share)
    }

    fn boot(&self, label: &str) -> Result<VzGuestSession, VzGuestError> {
        let share = self.share(label)?;
        VzGuestSession::boot(
            &self.kernel,
            &self.root_filesystem,
            &share,
            "gbdws",
            "console=hvc0 panic=10 loglevel=4",
            VzGuestSizing::default_development(),
        )
    }
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// What verifying the committed pins costs, and what it refuses.
fn probe_verify(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    for iteration in 0..inputs.count {
        let verification =
            GuestImageVerification::verify_committed(&inputs.kernel, &inputs.root_filesystem)?;
        println!(
            "GBDLC verify iteration={iteration} kernel_bytes={} kernel_ms={:.2} rootfs_bytes={} rootfs_ms={:.2} total_ms={:.2}",
            verification.kernel().byte_length(),
            verification.kernel().verification_cost().as_secs_f64() * 1000.0,
            verification.root_filesystem().byte_length(),
            verification
                .root_filesystem()
                .verification_cost()
                .as_secs_f64()
                * 1000.0,
            verification.total_cost().as_secs_f64() * 1000.0,
        );
    }
    // The enforced half: one corrupted copy of the same artifact, verified
    // against the same committed pin, must refuse and must name the pin.
    let corrupted = inputs.share_root.join("corrupted-root-filesystem");
    std::fs::copy(&inputs.root_filesystem, &corrupted).map_err(|error| {
        VzGuestError::new(
            VzGuestErrorKind::MissingBootArtifact,
            format!("the corrupted-artifact control could not be staged: {error}"),
        )
    })?;
    corrupt_one_byte(&corrupted)?;
    match GuestImageVerification::verify_committed(&inputs.kernel, &corrupted) {
        Ok(_) => println!("GBDLC verify corrupted_artifact=ACCEPTED refusal=none"),
        Err(error) => println!(
            "GBDLC verify corrupted_artifact=REFUSED kind={:?} detail={}",
            error.kind(),
            error.detail()
        ),
    }
    // And the same corrupted artifact offered to a real boot: the guest-host
    // process must refuse before any machine exists.
    let share = inputs.share("verify-refusal")?;
    match VzGuestSession::boot(
        &inputs.kernel,
        &corrupted,
        &share,
        "gbdws",
        "console=hvc0 panic=10 loglevel=4",
        VzGuestSizing::default_development(),
    ) {
        Ok(session) => {
            let proof = session.shutdown()?;
            println!("GBDLC verify corrupted_boot=BOOTED proof={proof:?}");
        }
        Err(error) => println!(
            "GBDLC verify corrupted_boot=REFUSED kind={:?} detail={}",
            error.kind(),
            error.detail()
        ),
    }
    let _ignored = std::fs::remove_file(&corrupted);
    Ok(())
}

fn corrupt_one_byte(path: &Path) -> Result<(), VzGuestError> {
    let mut bytes = std::fs::read(path).map_err(|error| {
        VzGuestError::new(
            VzGuestErrorKind::MissingBootArtifact,
            format!("the artifact to corrupt could not be read: {error}"),
        )
    })?;
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 0x01;
    }
    std::fs::write(path, &bytes).map_err(|error| {
        VzGuestError::new(
            VzGuestErrorKind::MissingBootArtifact,
            format!("the corrupted artifact could not be written: {error}"),
        )
    })
}

/// One guest per command: the shape that gets residue freedom for free.
fn probe_per_command_guest(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    for iteration in 0..inputs.count {
        let started = Instant::now();
        let mut session = inputs.boot(&format!("per-command-{iteration}"))?;
        let ready = session.ready_latency();
        let staging = session.staging_millis();
        let (outcome, _output) =
            session.run_contained(&argv(&["/bin/true"]), Duration::from_mins(1))?;
        let command_done = started.elapsed();
        let proof = session.shutdown()?;
        println!(
            "GBDLC per-command iteration={iteration} ready_ms={} staging_ms={staging} to_result_ms={} teardown_ms={} whole_ms={} outcome={outcome:?} descriptors={}->{}",
            ready.as_millis(),
            command_done.as_millis(),
            proof.elapsed.as_millis(),
            started.elapsed().as_millis(),
            proof.host_descriptors_before,
            proof.host_descriptors_after,
        );
    }
    Ok(())
}

/// One guest for many commands: the shape that must prove residue freedom.
fn probe_persistent_guest(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    let started = Instant::now();
    let mut session = inputs.boot("persistent")?;
    println!(
        "GBDLC persistent boot ready_ms={} staging_ms={}",
        session.ready_latency().as_millis(),
        session.staging_millis()
    );
    for iteration in 0..inputs.count {
        let health_started = Instant::now();
        let health = session.health()?;
        let health_cost = health_started.elapsed();
        let (outcome, _output) =
            session.run_contained(&argv(&["/bin/true"]), Duration::from_mins(1))?;
        println!(
            "GBDLC persistent iteration={iteration} health_us={} health={health:?} outcome={outcome:?}",
            health_cost.as_micros()
        );
    }
    let whole = started.elapsed();
    let proof = session.shutdown()?;
    println!(
        "GBDLC persistent whole_ms={} teardown_ms={} proof={proof:?}",
        whole.as_millis(),
        proof.elapsed.as_millis()
    );
    Ok(())
}

/// Residue freedom, control against enforced.
///
/// The control half shows the sentinels are observable when nothing separates
/// two observations: one command writes them and looks for them itself. The
/// enforced half runs the identical search as a *second command* in the same
/// persistent guest. The only difference between the halves is the command
/// boundary, which is exactly the input under test.
fn probe_residue(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    const PLANT: &str = concat!(
        "echo sentinel > /tmp/gbd-residue-sentinel; ",
        "echo sentinel > \"$GBD_COMMAND_ROOT/gbd-residue-sentinel\"; ",
        "setsid /bin/sleep 600 >/dev/null 2>&1 & ",
        "sleep 0.2; echo planted"
    );
    const SEARCH: &str = concat!(
        "printf 'tmp_sentinel=%s\\n' \"$(cat /tmp/gbd-residue-sentinel 2>/dev/null || echo ABSENT)\"; ",
        "printf 'root_sentinel=%s\\n' \"$(cat \"$GBD_COMMAND_ROOT/gbd-residue-sentinel\" 2>/dev/null || echo ABSENT)\"; ",
        "printf 'scratch_roots=%s\\n' \"$(ls /scratch 2>/dev/null | tr '\\n' ',')\"; ",
        "printf 'inherited_env=%s\\n' \"$(env | sort | tr '\\n' ',')\"; ",
        "survivors=; for entry in /proc/[0-9]*; do ",
        "  read -r comm < \"$entry/comm\" 2>/dev/null || continue; ",
        "  case \"$comm\" in sleep) survivors=\"$survivors ${entry#/proc/}\";; esac; ",
        "done; printf 'sleep_survivors=%s\\n' \"${survivors:-NONE}\"; ",
        "printf 'own_cgroup=%s\\n' \"$(cat /proc/self/cgroup)\""
    );

    let mut session = inputs.boot("residue")?;

    // Control: plant and search inside one command, so nothing separates them.
    let (control_outcome, control) = session.run_contained(
        &argv(&["/bin/sh", "-c", &format!("{PLANT}; {SEARCH}")]),
        Duration::from_mins(2),
    )?;
    println!("GBDLC residue control outcome={control_outcome:?}");
    for line in control.lines() {
        println!("GBDLC residue control {line}");
    }

    // Enforced: the identical search as the next command in the same guest.
    let (enforced_outcome, enforced) =
        session.run_contained(&argv(&["/bin/sh", "-c", SEARCH]), Duration::from_mins(2))?;
    println!("GBDLC residue enforced outcome={enforced_outcome:?}");
    for line in enforced.lines() {
        println!("GBDLC residue enforced {line}");
    }

    let proof = session.shutdown()?;
    println!("GBDLC residue teardown proof={proof:?}");
    Ok(())
}

/// Health fails closed, control against enforced.
///
/// The control half is a healthy guest running the command. The enforced half
/// is the identical call after the guest-host process has been killed: the only
/// input that changed is whether the guest is alive. The refusal must be typed,
/// must name the guest, and must leave no request on the share — nothing ran
/// anywhere.
fn probe_health(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    let mut session = inputs.boot("health")?;
    let control_health = session.health()?;
    let (control_outcome, control_output) = session.run_contained(
        &argv(&["/bin/sh", "-c", "echo control-half-ran; id -u"]),
        Duration::from_mins(1),
    )?;
    println!(
        "GBDLC health control health={control_health:?} outcome={control_outcome:?} output={:?}",
        control_output.trim()
    );

    session.kill_guest_host_for_probe();
    let enforced_health = session.health();
    println!(
        "GBDLC health enforced health={:?}",
        enforced_health
            .as_ref()
            .map_err(|error| format!("{:?}: {}", error.kind(), error.detail()))
    );
    let enforced = session.run_contained(
        &argv(&["/bin/sh", "-c", "echo enforced-half-ran"]),
        Duration::from_secs(10),
    );
    match enforced {
        Ok((outcome, output)) => println!(
            "GBDLC health enforced DISPATCHED outcome={outcome:?} output={:?}",
            output.trim()
        ),
        Err(error) => println!(
            "GBDLC health enforced REFUSED kind={:?} detail={}",
            error.kind(),
            error.detail()
        ),
    }
    let proof = session.shutdown()?;
    println!("GBDLC health teardown proof={proof:?}");
    Ok(())
}

/// Teardown proves emptiness rather than assuming it.
fn probe_teardown(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    for iteration in 0..inputs.count {
        let before = open_descriptor_count();
        let mut session = inputs.boot(&format!("teardown-{iteration}"))?;
        // Leave the guest with live descendants at teardown, so emptiness is
        // something the teardown has to achieve rather than something it
        // inherits from a quiet guest.
        let (outcome, _output) = session.run_contained(
            &argv(&[
                "/bin/sh",
                "-c",
                "setsid /bin/sleep 600 >/dev/null 2>&1 & sleep 0.2; echo left-a-descendant",
            ]),
            Duration::from_mins(1),
        )?;
        let proof = session.shutdown()?;
        println!(
            "GBDLC teardown iteration={iteration} outcome={outcome:?} exit={:?} guest_initiated={} escalated={} heartbeat_frozen_at={:?} descriptors={}->{} (probe_before={before}) elapsed_ms={}",
            proof.host_process_exit,
            proof.guest_initiated,
            proof.escalated,
            proof.heartbeat_frozen_at,
            proof.host_descriptors_before,
            proof.host_descriptors_after,
            proof.elapsed.as_millis()
        );
    }
    Ok(())
}

/// The bounded escalation, exercised rather than asserted.
///
/// The control half is an ordinary teardown: the shutdown request reaches the
/// guest, it powers itself off, nothing escalates. The enforced half removes
/// the control directory first, so the request cannot be delivered at all —
/// the one input that changed — and teardown must still finish inside its
/// bound by escalating to a signal. D-0013's rule is the point: a wait that can
/// hang is worse than a wait that gives up.
fn probe_teardown_escalation(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    let session = inputs.boot("escalation-control")?;
    let control = session.shutdown()?;
    println!(
        "GBDLC escalation control escalated={} guest_initiated={} exit={:?} elapsed_ms={}",
        control.escalated,
        control.guest_initiated,
        control.host_process_exit,
        control.elapsed.as_millis()
    );

    let session = inputs.boot("escalation-enforced")?;
    let channel = session.control_directory().to_path_buf();
    std::fs::remove_dir_all(&channel).map_err(|error| {
        VzGuestError::new(
            VzGuestErrorKind::InvalidConfiguration,
            format!("the control channel could not be removed for the enforced half: {error}"),
        )
    })?;
    let enforced = session.shutdown()?;
    println!(
        "GBDLC escalation enforced escalated={} guest_initiated={} exit={:?} elapsed_ms={}",
        enforced.escalated,
        enforced.guest_initiated,
        enforced.host_process_exit,
        enforced.elapsed.as_millis()
    );
    Ok(())
}

/// Runs the Linux backend's complete canary suite through the product
/// lifecycle path, so the twelve controls are proven inside a guest this
/// session booted, verified, and tore down — not inside a hand-driven harness.
fn probe_canary_suite(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    let mut session = inputs.boot("suite")?;
    println!(
        "GBDLC suite boot ready_ms={} staging_ms={} kernel_sha={} rootfs_sha={} verify_ms={:.2}",
        session.ready_latency().as_millis(),
        session.staging_millis(),
        session.verification().kernel().sha256(),
        session.verification().root_filesystem().sha256(),
        session.verification().total_cost().as_secs_f64() * 1000.0,
    );
    for iteration in 0..inputs.count {
        let (outcome, output) = session.run_contained(
            &argv(&[
                "/stage/deps/runner-test",
                "command::tests::linux_cgroup_v2_contained_backend",
                "--test-threads=1",
                "--nocapture",
            ]),
            Duration::from_mins(10),
        )?;
        println!("GBDLC suite iteration={iteration} outcome={outcome:?}");
        for line in output.lines() {
            println!("GBDLC suite {line}");
        }
    }
    let proof = session.shutdown()?;
    println!("GBDLC suite teardown proof={proof:?}");
    Ok(())
}

/// Boots a guest, dispatches a long command, publishes the guest-host process
/// id, and then waits. The caller kills *this* process to measure what happens
/// to a guest whose owner dies.
fn probe_crash_wait(inputs: &ProbeInputs) -> Result<(), VzGuestError> {
    let mut session = inputs.boot("crash")?;
    println!(
        "GBDLC crash guest_host_pid={} share={}",
        session.guest_host_pid(),
        session.control_directory().display()
    );
    let (outcome, _output) = session.run_contained(
        &argv(&["/bin/sh", "-c", "echo crash-probe-armed"]),
        Duration::from_mins(1),
    )?;
    println!("GBDLC crash armed outcome={outcome:?}");
    // Deliberately idle: the host publishes no further heartbeat once this
    // process is killed, and the guest's own stall bound is what must end it.
    loop {
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests;
