use crate::ptr::{PtrWrapper, UserPtr};
use arceos_posix_api::close_all_file_like;
use core::sync::atomic::Ordering;
use starry_core::task::{current_process, current_thread, current_thread_data};
use undefined_process::Pid;

pub fn sys_exit_impl(exit_code: i32, exit_group: bool) -> ! {
    let addr_clear_child_tid = current_thread_data()
        .addr_clear_child_tid
        .load(Ordering::Relaxed);
    let addr_clear_child_tid = UserPtr::<Pid>::from(addr_clear_child_tid);
    if let Ok(ptr) = addr_clear_child_tid.get() {
        unsafe { ptr.write(0) };
    }
    current_thread().exit(exit_code);
    if current_process().is_zombie() {
        // threads have exited
        // TODO: send signals
    }
    // release thread data
    // FIXME: leak of ax-namespace
    close_all_file_like();
    if exit_group {
        // TODO: kill other threads
    }
    axtask::exit(exit_code)
}
