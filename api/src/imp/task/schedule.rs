use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};
use arceos_posix_api as api;
use axerrno::LinuxResult;
use starry_core::task::current_process_data;

pub fn sys_sched_yield() -> LinuxResult<isize> {
    Ok(api::sys_sched_yield() as _)
}

pub fn sys_nanosleep(
    req: UserConstPtr<api::ctypes::timespec>,
    rem: UserPtr<api::ctypes::timespec>,
) -> LinuxResult<isize> {
    unsafe { Ok(api::sys_nanosleep(req.get()?, rem.get()?) as _) }
}
