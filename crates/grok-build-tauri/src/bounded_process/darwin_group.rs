//! Read-only verification of the still-reserved helper group on macOS.
//!
//! Darwin can return EPERM for a group containing only zombies. Permission
//! errors are accepted only after this bounded read proves every member exited.
//! Observed member PIDs never become authority to signal or wait on a process.

#![allow(unsafe_code)] // Audited, bounded libproc reads; no mutation or retained pointers.

use std::mem::{MaybeUninit, size_of, size_of_val};

use nix::libc;

const PROC_PGRP_ONLY: u32 = 2; // sys/proc_info.h, public macOS SDK.
const MAX_MEMBERS: usize = 1024;

pub(super) fn only_exited_members(group: u32) -> Result<bool, String> {
    verify_members(
        group,
        || list_members(group),
        |pid| member_exited(group, pid),
    )
}

fn verify_members(
    group: u32,
    mut list: impl FnMut() -> Result<Vec<i32>, String>,
    mut exited: impl FnMut(i32) -> Result<Option<bool>, String>,
) -> Result<bool, String> {
    for _ in 0..3 {
        let first = checked_members(group, list()?)?;
        let mut changed = false;
        for &pid in &first {
            match exited(pid)? {
                Some(true) => {}
                Some(false) => return Ok(false),
                None if u32::try_from(pid) == Ok(group) => {
                    return Err(
                        "Reserved helper group leader disappeared during verification.".into(),
                    );
                }
                None => {
                    changed = true;
                    break;
                }
            }
        }
        // A process may spawn a new descendant and exit between enumeration
        // and its status read. Require a second complete identical membership,
        // not just exited status for the members in the first observation.
        if !changed && first == checked_members(group, list()?)? {
            return Ok(true);
        }
    }
    // No cleanup proof yet. The bounded owner/reaper keeps the unreaped leader
    // and retries under its existing deadline; no discovered PID is signalled.
    Ok(false)
}

fn checked_members(group: u32, mut members: Vec<i32>) -> Result<Vec<i32>, String> {
    members.sort_unstable();
    if members.is_empty()
        || members.len() >= MAX_MEMBERS
        || members.iter().any(|pid| *pid <= 0)
        || members.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err("Reserved helper group membership is invalid or truncated.".into());
    }
    if !members.iter().any(|pid| u32::try_from(*pid) == Ok(group)) {
        return Err("Reserved helper group leader is absent from membership readback.".into());
    }
    Ok(members)
}

fn list_members(group: u32) -> Result<Vec<i32>, String> {
    let mut members = [0_i32; MAX_MEMBERS];
    let capacity = i32::try_from(size_of_val(&members)).map_err(|error| error.to_string())?;
    // SAFETY: the initialized, aligned array is writable for exactly capacity
    // bytes. libproc retains no pointer; type 2 reads only this process group.
    let count = unsafe {
        libc::proc_listpids(PROC_PGRP_ONLY, group, members.as_mut_ptr().cast(), capacity)
    };
    if count <= 0 {
        return Err(format!(
            "Cannot verify reserved helper group membership: {}",
            std::io::Error::last_os_error()
        ));
    }
    let count = usize::try_from(count).map_err(|error| error.to_string())?;
    if count >= size_of_val(&members) || !count.is_multiple_of(size_of::<i32>()) {
        return Err("Reserved helper group membership is truncated or malformed.".into());
    }
    Ok(members[..count / size_of::<i32>()].to_vec())
}

fn member_exited(group: u32, pid: i32) -> Result<Option<bool>, String> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let expected =
        i32::try_from(size_of::<libc::proc_bsdinfo>()).map_err(|error| error.to_string())?;
    // SAFETY: storage has the SDK's exact layout, alignment and byte size.
    // arg=1 includes zombies. Only a complete successful write is read.
    let actual = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            1,
            info.as_mut_ptr().cast(),
            expected,
        )
    };
    if actual != expected {
        let error = std::io::Error::last_os_error();
        if actual == 0 && error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(format!(
            "Cannot verify reserved helper member exit: {error}"
        ));
    }
    // SAFETY: the exact-size successful kernel write initialized every
    // field of this plain C integer/array record. No pointer is dereferenced.
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid.cast_unsigned() || info.pbi_pgid != group {
        return Ok(None);
    }
    Ok(Some(info.pbi_status == libc::SZOMB))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn disappeared_descendant_requires_a_new_complete_stable_observation() {
        let mut reads = VecDeque::from([vec![7, 8], vec![7], vec![7]]);
        let result = verify_members(
            7,
            || Ok(reads.pop_front().unwrap()),
            |pid| Ok(if pid == 8 { None } else { Some(true) }),
        )
        .unwrap();
        assert!(result);
        assert!(reads.is_empty());
        assert!(verify_members(7, || Ok(vec![7]), |_| Ok(None)).is_err());
    }

    #[test]
    fn a_new_descendant_after_the_first_scan_prevents_cleanup_proof() {
        let mut reads = VecDeque::from([vec![7, 8], vec![7, 8, 9], vec![7, 8, 9]]);
        assert!(
            !verify_members(
                7,
                || Ok(reads.pop_front().unwrap()),
                |pid| Ok(Some(pid != 9))
            )
            .unwrap()
        );
        assert!(checked_members(7, vec![8]).is_err());
        assert!(checked_members(7, vec![7, 7]).is_err());
        assert!(checked_members(7, vec![7, 0]).is_err());
    }
}
