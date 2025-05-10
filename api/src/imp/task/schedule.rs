use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};
use crate::utils::time::{timespec_to_timevalue, timevalue_to_timespec};
use arceos_posix_api as api;
use axerrno::{LinuxError, LinuxResult};
use axsignal::SignalSet;
use linux_raw_sys::general::timespec;
use starry_core::task::current_thread_data;

pub fn sys_sched_yield() -> LinuxResult<isize> {
    Ok(api::sys_sched_yield() as _)
}

pub fn sys_nanosleep(req: UserConstPtr<timespec>, rem: UserPtr<timespec>) -> LinuxResult<isize> {
    // unsafe { Ok(api::sys_nanosleep(req.get()?, rem.get()?) as _) }
    let req = req.get_as_ref()?;

    if req.tv_nsec < 0 || req.tv_nsec > 999_999_999 || req.tv_sec < 0 {
        return Err(LinuxError::EINVAL);
    }

    let dur = timespec_to_timevalue(*req);
    debug!("[sys_nanosleep] sleep time: {:?}", dur);
    let now = axhal::time::monotonic_time();
    let _ = current_thread_data()
        .signal
        .wait_timeout(SignalSet::default(), Some(dur));
    let after = axhal::time::monotonic_time();
    let actual = after - now;
    if let Some(diff) = dur.checked_sub(actual) {
        unsafe {
            if let Ok(rem) = rem.get() {
                *rem = timevalue_to_timespec(diff);
            }
        }
        Err(LinuxError::EINTR)
    } else {
        Ok(0)
    }
}
