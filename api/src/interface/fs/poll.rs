use crate::imp::fs::poll::{PollEntry, PollFlags, sys_poll_impl};
use crate::ptr::{PtrWrapper, UserInOutPtr, UserInPtr};
use alloc::vec::Vec;
use axerrno::{LinuxError, LinuxResult};
use axhal::time::{NANOS_PER_MICROS, NANOS_PER_SEC};
use core::ffi::{c_int, c_ulong};
use linux_raw_sys::general::timespec;
use syscall_trace::syscall_trace;

/// Represents a file descriptor being monitored, mirroring C's `struct pollfd`.
///
/// # Memory Layout
/// Uses `#[repr(C)]` to ensure compatibility with libc. All fields directly map to
/// their C counterparts.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserPollFd {
    /// File descriptor to monitor.
    ///
    /// - Negative values cause `events` to be ignored and `revents` to be zeroed.
    /// - To temporarily ignore a descriptor, set to negative (e.g., `!fd` via bitwise complement).
    pub fd: i32,

    /// Requested events (input parameter), constructed via bitwise OR of [`PollFlags`].
    pub events: i16,

    /// Returned events (output parameter), set by kernel. May contain [`PollFlags`]
    /// values even if not requested.
    pub revents: i16,
}

impl Into<PollEntry> for UserPollFd {
    fn into(self) -> PollEntry {
        PollEntry {
            fd: self.fd,
            events: PollFlags::from_bits_truncate(self.events),
            results: PollFlags::from_bits_truncate(self.revents),
        }
    }
}

impl From<PollEntry> for UserPollFd {
    fn from(entry: PollEntry) -> Self {
        UserPollFd {
            fd: entry.fd,
            events: entry.events.bits(),
            revents: entry.results.bits(),
        }
    }
}

#[syscall_trace]
pub fn sys_poll(
    fds: UserInOutPtr<UserPollFd>,
    n_fds: c_ulong,
    timeout: c_int,
) -> LinuxResult<isize> {
    // get params
    let fds = fds.get_as_array(n_fds as _)?;
    let fds_slice: &mut [UserPollFd] = unsafe { core::slice::from_raw_parts_mut(fds, n_fds as _) };
    let mut entries: Vec<PollEntry> = fds_slice.iter().map(|&fd| fd.into()).collect();

    // preform syscall
    let block = timeout < 0;
    let timeout = if timeout < 0 {
        0
    } else {
        timeout as u64 * NANOS_PER_MICROS
    };
    let result = sys_poll_impl(&mut entries, timeout, block)?;

    // copy results back
    let entries: Vec<UserPollFd> = entries.into_iter().map(|fd| fd.into()).collect();
    unsafe { fds.copy_from_nonoverlapping(entries.as_ptr(), n_fds as usize) };
    Ok(result)
}

#[syscall_trace]
pub fn sys_ppoll(
    fds: UserInOutPtr<UserPollFd>,
    n_fds: c_ulong,
    timeout: UserInPtr<timespec>,
    _sigmask: UserInOutPtr<c_ulong>,
) -> LinuxResult<isize> {
    // get params
    let fds = fds.get_as_array(n_fds as _)?;
    let fds_slice: &mut [UserPollFd] = unsafe { core::slice::from_raw_parts_mut(fds, n_fds as _) };
    let mut entries: Vec<PollEntry> = fds_slice.iter().map(|&fd| fd.into()).collect();
    let mut block = false;
    let mut timeout_nanos: u64 = 0;
    if timeout.is_null() {
        block = true;
    } else {
        let t = timeout.get_as_ref()?;
        if t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec > 999_999_999 {
            return Err(LinuxError::EINVAL);
        }
        timeout_nanos = (t.tv_sec as u64 * NANOS_PER_SEC) + t.tv_nsec as u64;
    }

    // preform syscall
    // TODO: implement signal mask
    // pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
    let result = sys_poll_impl(&mut entries, timeout_nanos, block)?;
    // pthread_sigmask(SIG_SETMASK, &origmask, NULL);

    // copy results back
    let entries: Vec<UserPollFd> = entries.into_iter().map(|fd| fd.into()).collect();
    unsafe { fds.copy_from_nonoverlapping(entries.as_ptr(), n_fds as usize) };
    Ok(result)
}
