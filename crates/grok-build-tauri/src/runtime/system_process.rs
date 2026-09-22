//! Bounded, fixed OS helper operations with retained process ownership.

#[cfg(target_os = "macos")]
pub(crate) fn run(
    program: &str,
    args: &[&std::ffi::OsStr],
    input: &[u8],
) -> Result<Vec<u8>, String> {
    if !matches!(
        program,
        "/usr/bin/hdiutil"
            | "/usr/bin/codesign"
            | "/usr/bin/plutil"
            | "/System/Library/Filesystems/hfs.fs/Contents/Resources/newfs_hfs"
            | "/sbin/mount"
            | "/sbin/umount"
    ) {
        return Err("Memory-home helper violates its fixed OS operation policy.".into());
    }
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C");
    let output = crate::bounded_process::collect(
        command,
        input,
        &crate::bounded_process::Limits {
            input: 1024 * 1024,
            output: 1024 * 1024,
            error: 1024 * 1024,
            timeout: std::time::Duration::from_secs(20),
        },
    )?;
    if !output.status.success() {
        return Err(format!("Memory-home OS helper exited {}.", output.status));
    }
    Ok(output.stdout)
}
