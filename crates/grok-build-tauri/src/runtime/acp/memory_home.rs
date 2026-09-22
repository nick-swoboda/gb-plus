//! Owner-only wired RAM homes. No raw CLI conversation is written to disk.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Value, json};

use super::process::{ensure_owner_directory, write_owner_only_atomic};
use crate::runtime::system_process::run;

const SECTORS: u64 = 65_536;
const RAM_URI: &str = "ram://65536";
const MAX_HOMES: usize = 8;
static HOMES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<MemoryHome>>>> = OnceLock::new();

pub(super) struct MemoryHome {
    mount: PathBuf,
    device: String,
    attachment_pid: u64,
    mounted_identity: (u64, u64),
    unmounted_identity: Option<(u64, u64)>,
    cleanup_phase: Mutex<CleanupPhase>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupPhase {
    Mounted,
    Unmounted,
    Detached,
}

fn retire_idle(
    homes: &mut BTreeMap<PathBuf, Arc<MemoryHome>>,
    cleanup: impl FnOnce(&MemoryHome) -> Result<(), String>,
) -> Result<(), String> {
    let idle = homes
        .iter()
        .find(|(_, home)| Arc::strong_count(home) == 1)
        .map(|(root, _)| root.clone())
        .ok_or("All bounded RAM homes are in use.")?;
    cleanup(
        homes
            .get(&idle)
            .ok_or("RAM home lost its registry ownership.")?,
    )?;
    homes.remove(&idle);
    Ok(())
}

impl MemoryHome {
    pub(super) fn acquire(root: &Path) -> Result<Arc<Self>, String> {
        let mut homes = HOMES
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| "RAM home registry is unavailable.")?;
        if let Some(home) = homes.get(root) {
            home.validate()?;
            return Ok(home.clone());
        }
        while homes.len() >= MAX_HOMES {
            retire_idle(&mut homes, MemoryHome::cleanup)?;
        }
        let home = Arc::new(Self::create(root)?);
        homes.insert(root.into(), home.clone());
        Ok(home)
    }

    fn create(root: &Path) -> Result<Self, String> {
        cleanup_previous(root)?;
        let mount = root.join(format!(
            "memory-home-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        ensure_owner_directory(&mount)?;
        let mount = fs::canonicalize(mount).map_err(|e| e.to_string())?;
        let underlying = fs::symlink_metadata(&mount).map_err(|e| e.to_string())?;
        let result = run(
            "/usr/bin/hdiutil",
            &[
                OsStr::new("attach"),
                OsStr::new("-nomount"),
                OsStr::new(RAM_URI),
            ],
            &[],
        )?;
        let text =
            std::str::from_utf8(&result).map_err(|_| "RAM attachment returned invalid output.")?;
        let devices = text
            .split_whitespace()
            .filter(|word| word.starts_with("/dev/"))
            .collect::<Vec<_>>();
        if devices.len() != 1 || !device_name(devices[0]) {
            return Err(
                "RAM attachment did not identify one whole device; no format was attempted.".into(),
            );
        }
        let device = devices[0].to_owned();
        let attachment = attachment(&device)?;
        let attachment_pid = attachment
            .get("hdid-pid")
            .and_then(Value::as_u64)
            .ok_or("RAM attachment has no owning process identity.")?;
        let mut home = Self {
            mount,
            device,
            attachment_pid,
            mounted_identity: (0, 0),
            unmounted_identity: Some((underlying.dev(), underlying.ino())),
            cleanup_phase: Mutex::new(CleanupPhase::Unmounted),
        };
        // The exact newly returned whole device must still be the owner-issued
        // RAM URI with the expected sector count. Host disks are never eligible.
        home.validate_attachment()?;
        run(
            "/System/Library/Filesystems/hfs.fs/Contents/Resources/newfs_hfs",
            &[
                OsStr::new("-v"),
                OsStr::new("GBPlusMemory"),
                OsStr::new(&home.device),
            ],
            &[],
        )?;
        home.validate_attachment()?;
        run(
            "/sbin/mount",
            &[
                OsStr::new("-t"),
                OsStr::new("hfs"),
                OsStr::new("-o"),
                OsStr::new("nodev,nosuid,noexec"),
                OsStr::new(&home.device),
                home.mount.as_os_str(),
            ],
            &[],
        )?;
        let metadata = fs::symlink_metadata(&home.mount).map_err(|e| e.to_string())?;
        home.mounted_identity = (metadata.dev(), metadata.ino());
        home.cleanup_phase = Mutex::new(CleanupPhase::Mounted);
        ensure_owner_directory(&home.mount)?;
        write_owner_only_atomic(&root.join("memory-home-receipt.json"), &serde_json::to_vec(&json!({"schemaVersion":2,"ownerPid":std::process::id(),"ownerUid":rustix::process::geteuid().as_raw(),"attachmentPid":attachment_pid,"device":home.device,"mount":home.mount,"sectors":SECTORS,"deviceId":metadata.dev(),"inode":metadata.ino(),"unmountedDeviceId":underlying.dev(),"unmountedInode":underlying.ino()})).map_err(|e| e.to_string())?)?;
        Ok(home)
    }

    pub(super) fn path(&self) -> &Path {
        &self.mount
    }

    pub(super) fn validate(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.mount)
            .map_err(|_| "CLI RAM home is unavailable; the connection must stop.")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o700
            || (metadata.dev(), metadata.ino()) != self.mounted_identity
        {
            return Err("CLI RAM home lost its exact mount identity; execution is refused.".into());
        }
        Ok(())
    }

    fn validate_attachment(&self) -> Result<(), String> {
        let value = attachment(&self.device)?;
        if value.get("hdid-pid").and_then(Value::as_u64) != Some(self.attachment_pid) {
            return Err("RAM attachment process identity changed.".into());
        }
        Ok(())
    }

    fn cleanup(&self) -> Result<(), String> {
        let mut phase = self
            .cleanup_phase
            .lock()
            .map_err(|_| "RAM cleanup state is unavailable.")?;
        if *phase == CleanupPhase::Detached {
            return Ok(());
        }
        let current = attachment_record(&self.device)?;
        if !is_current_attachment(current.as_ref(), self.attachment_pid)? {
            // Absence or a different generation proves this attachment is gone.
            // A replacement device receives no unmount or detach operation.
            *phase = CleanupPhase::Detached;
            return Ok(());
        }
        self.validate_attachment()?;
        if *phase == CleanupPhase::Mounted {
            self.validate()?;
            run("/sbin/umount", &[self.mount.as_os_str()], &[])?;
            *phase = CleanupPhase::Unmounted;
        }
        if let Some(expected) = self.unmounted_identity {
            let metadata = fs::symlink_metadata(&self.mount).map_err(|e| e.to_string())?;
            if (metadata.dev(), metadata.ino()) != expected {
                return Err("RAM cleanup cannot verify the original unmounted directory; ownership retained.".into());
            }
        }
        self.validate_attachment()?;
        run(
            "/usr/bin/hdiutil",
            &[OsStr::new("detach"), OsStr::new(&self.device)],
            &[],
        )?;
        if is_current_attachment(
            attachment_record(&self.device)?.as_ref(),
            self.attachment_pid,
        )? {
            return Err("RAM detach is not proven; attachment ownership retained.".into());
        }
        *phase = CleanupPhase::Detached;
        Ok(())
    }
}

impl Drop for MemoryHome {
    fn drop(&mut self) {
        // Normal eviction proves cleanup before removal. This fallback retains
        // the receipt for explicit recovery if process teardown encounters error.
        let _ = self.cleanup();
    }
}

fn attachment(device: &str) -> Result<Value, String> {
    let row = attachment_record(device)?.ok_or("RAM attachment is absent.")?;
    if row["image-path"] != RAM_URI
        || row["blockcount"].as_u64() != Some(SECTORS)
        || row["blocksize"] != 512
        || row["owner-uid"].as_u64() != Some(u64::from(rustix::process::geteuid().as_raw()))
        || row["writeable"] != true
    {
        return Err(
            "Device is not the expected owner-issued 32 MiB RAM attachment; operation refused."
                .into(),
        );
    }
    Ok(row)
}

fn attachment_record(device: &str) -> Result<Option<Value>, String> {
    let plist = run(
        "/usr/bin/hdiutil",
        &[OsStr::new("info"), OsStr::new("-plist")],
        &[],
    )?;
    let bytes = run(
        "/usr/bin/plutil",
        &[
            OsStr::new("-convert"),
            OsStr::new("json"),
            OsStr::new("-o"),
            OsStr::new("-"),
            OsStr::new("-"),
        ],
        &plist,
    )?;
    let info: Value = serde_json::from_slice(&bytes).map_err(|_| "RAM inventory is malformed.")?;
    let rows = info["images"]
        .as_array()
        .ok_or("RAM inventory has no images.")?;
    let matching = rows
        .iter()
        .filter(|row| {
            row["system-entities"]
                .as_array()
                .is_some_and(|entities| entities.iter().any(|entry| entry["dev-entry"] == device))
        })
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return Err("RAM device has no unique attachment identity.".into());
    }
    Ok(matching.first().map(|row| (*row).clone()))
}

fn is_current_attachment(row: Option<&Value>, expected_pid: u64) -> Result<bool, String> {
    let Some(row) = row else { return Ok(false) };
    let pid = row["hdid-pid"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or("RAM inventory omitted its generation; cleanup ownership remains uncertain.")?;
    Ok(pid == expected_pid)
}

fn device_name(value: &str) -> bool {
    value.strip_prefix("/dev/disk").is_some_and(|number| {
        !number.is_empty() && number.len() <= 4 && number.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn cleanup_previous(root: &Path) -> Result<(), String> {
    let bytes = crate::owner_state::OwnerStateRoot::new(root)
        .file("memory-home-receipt.json", 16 * 1024)
        .map_err(|e| e.to_string())?
        .read()
        .map_err(|e| e.to_string())?;
    let Some(bytes) = bytes else { return Ok(()) };
    let receipt: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "Previous RAM-home receipt is invalid; retained.")?;
    let owner = receipt["ownerPid"]
        .as_u64()
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
        .ok_or("Previous RAM-home owner PID is invalid.")?;
    let Some(device) = receipt["device"]
        .as_str()
        .filter(|device| device_name(device))
    else {
        return Err("Previous RAM-home device is invalid.".into());
    };
    let mount = receipt["mount"]
        .as_str()
        .map(PathBuf::from)
        .ok_or("Previous RAM-home mount is invalid.")?;
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    if mount.parent() != Some(root.as_path())
        || !mount
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("memory-home-"))
        || !matches!(receipt["schemaVersion"].as_u64(), Some(1 | 2))
        || receipt["ownerUid"].as_u64() != Some(u64::from(rustix::process::geteuid().as_raw()))
    {
        return Err(
            "Previous RAM-home receipt does not match this exact attachment; cleanup refused."
                .into(),
        );
    }
    let attachment_pid = receipt["attachmentPid"]
        .as_u64()
        .filter(|pid| *pid > 0)
        .ok_or("Previous RAM attachment PID is invalid.")?;
    let current = attachment_record(device)?;
    if !is_current_attachment(current.as_ref(), attachment_pid)? {
        return Ok(());
    }
    if rustix::process::test_kill_process(owner) != Err(rustix::io::Errno::SRCH) {
        return Err("Previous RAM-home ownership is still active or uncertain; its receipt was retained and no second home was created.".into());
    }
    let mounted_identity = receipt_identity(&receipt, "deviceId", "inode")?;
    let unmounted_identity = (receipt["schemaVersion"] == 2)
        .then(|| receipt_identity(&receipt, "unmountedDeviceId", "unmountedInode"))
        .transpose()?;
    let metadata = fs::symlink_metadata(&mount).map_err(|e| e.to_string())?;
    let identity = (metadata.dev(), metadata.ino());
    let cleanup_phase = if identity == mounted_identity {
        CleanupPhase::Mounted
    } else if Some(identity) == unmounted_identity {
        CleanupPhase::Unmounted
    } else {
        return Err("Previous RAM mount changed identity; its receipt was retained.".into());
    };
    let previous = MemoryHome {
        mount,
        device: device.into(),
        attachment_pid,
        mounted_identity,
        unmounted_identity,
        cleanup_phase: Mutex::new(cleanup_phase),
    };
    previous.cleanup()?;
    drop(previous);
    Ok(())
}

fn receipt_identity(value: &Value, device: &str, inode: &str) -> Result<(u64, u64), String> {
    value[device]
        .as_u64()
        .zip(value[inode].as_u64())
        .filter(|(device, inode)| *device != 0 && *inode != 0)
        .ok_or("Previous RAM receipt lacks a bounded filesystem identity.".into())
}

pub(crate) fn shutdown() {
    if let Some(homes) = HOMES.get()
        && let Ok(mut homes) = homes.lock()
    {
        // Active connections retain their Arc until process teardown. Failed
        // idle cleanup remains tracked; a later acquisition cannot evade the cap.
        let keys = homes.keys().cloned().collect::<Vec<_>>();
        for root in keys {
            let remove = homes
                .get(&root)
                .is_some_and(|home| Arc::strong_count(home) > 1 || home.cleanup().is_ok());
            if remove {
                homes.remove(&root);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_attachment_generation_is_unknown_rather_than_proof_of_cleanup() {
        assert!(!is_current_attachment(None, 7).unwrap());
        assert!(is_current_attachment(Some(&json!({"hdid-pid":7})), 7).unwrap());
        assert!(!is_current_attachment(Some(&json!({"hdid-pid":8})), 7).unwrap());
        for row in [json!({}), json!({"hdid-pid":null}), json!({"hdid-pid":0})] {
            assert!(is_current_attachment(Some(&row), 7).is_err());
        }
    }
    #[test]
    fn failed_cleanup_retains_ownership_and_budget_until_a_verified_retry() {
        let mut homes = BTreeMap::new();
        homes.insert(
            PathBuf::from("fixture"),
            Arc::new(MemoryHome {
                mount: PathBuf::from("unused"),
                device: "/dev/disk9999".into(),
                attachment_pid: 1,
                mounted_identity: (1, 1),
                unmounted_identity: Some((1, 2)),
                cleanup_phase: Mutex::new(CleanupPhase::Detached),
            }),
        );
        assert!(retire_idle(&mut homes, |_| Err("fixture unmount failure".into())).is_err());
        assert_eq!(homes.len(), 1);
        let retained = Arc::clone(homes.values().next().unwrap());
        assert!(retire_idle(&mut homes, |_| panic!("active home reached cleanup")).is_err());
        drop(retained);
        retire_idle(&mut homes, |_| Ok(())).unwrap();
        assert!(homes.is_empty());
    }
    #[test]
    fn only_whole_disk_identifiers_can_reach_fixed_ram_operations() {
        assert!(device_name("/dev/disk4"));
        for value in [
            "/dev/disk4s1",
            "/dev/disk",
            "/dev/disk4;erase",
            "/dev/rdisk4",
            "/dev/disk99999",
        ] {
            assert!(!device_name(value));
        }
    }
    #[test]
    #[ignore = "creates, mounts and detaches one 32 MiB OS RAM fixture"]
    fn real_memory_home_mount_identity_and_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "gbplus-ram-{}-{}",
            std::process::id(),
            crate::runtime::types::unix_time_millis()
        ));
        ensure_owner_directory(&root).unwrap();
        let home = MemoryHome::create(&root).unwrap();
        home.validate().unwrap();
        let receipt = fs::read(root.join("memory-home-receipt.json")).unwrap();
        assert!(cleanup_previous(&root).is_err());
        assert_eq!(
            fs::read(root.join("memory-home-receipt.json")).unwrap(),
            receipt
        );
        fs::write(home.path().join("fixture.txt"), "memory only").unwrap();
        assert_eq!(
            fs::read_to_string(home.path().join("fixture.txt")).unwrap(),
            "memory only"
        );
        let device = home.device.clone();
        home.cleanup().unwrap();
        drop(home);
        assert!(attachment(&device).is_err());
        let recovered = MemoryHome::create(&root).unwrap();
        run("/sbin/umount", &[recovered.mount.as_os_str()], &[]).unwrap();
        let dead = rustix::process::Pid::from_raw(i32::MAX).unwrap();
        assert_eq!(
            rustix::process::test_kill_process(dead),
            Err(rustix::io::Errno::SRCH)
        );
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(root.join("memory-home-receipt.json")).unwrap())
                .unwrap();
        receipt["ownerPid"] = json!(i32::MAX);
        write_owner_only_atomic(
            &root.join("memory-home-receipt.json"),
            &serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        cleanup_previous(&root).expect("recover crash after unmount but before detach");
        assert!(attachment(&recovered.device).is_err());
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }
}
