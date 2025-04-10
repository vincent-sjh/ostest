use core::ffi::c_void;

use axerrno::LinuxResult;
use axtask::{current, TaskExtRef};
use starry_core::task::SigSet;
use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};

pub fn sys_rt_sigprocmask(
    how: i32,
    set: UserConstPtr<SigSet>,
    oldset: UserPtr<SigSet>,
    _sigsetsize: usize,
) -> LinuxResult<isize> {
    let curr = current();
    let taskext = curr.task_ext();
    let oldset = oldset.nullable(UserPtr::get)?;
    if let Some(oldset) = oldset {
        unsafe {
            *oldset = taskext.get_signal_mask();
        }
    }
    let set = set.nullable(UserConstPtr::get)?;
    if let Some(set) = set {
        match how {
            // SIG_BLOCK = 0
            0 => taskext.add_signal(set),
            // SIG_UNBLOCK=1
            1 => taskext.remove_signal(set),
            // SIG_SETMASK
            2 => taskext.set_signal_mask(set),
            _ => {}
        }
    }
    
    Ok(0)
}

pub fn sys_rt_sigaction(
    _signum: i32,
    _act: UserConstPtr<c_void>,
    _oldact: UserPtr<c_void>,
    _sigsetsize: usize,
) -> LinuxResult<isize> {
    warn!("sys_rt_sigaction: not implemented");
    Ok(0)
}

// TODO: [stub] The method signature is not correct yet
pub fn sys_rt_sigtimedwait(
    _signum: i32,
    _act: UserConstPtr<c_void>,
    _old_act: UserPtr<c_void>,
    _sig_set_size: usize,
) -> LinuxResult<isize> {
    warn!("[sys_rt_sigaction] not implemented yet");
    Ok(0)
}

pub fn sys_kill(
    _pid: u64,
    _sig: i32,
) -> LinuxResult<isize> {
    warn!("[sys_kill] not implemented yet");
    Ok(0)
}
