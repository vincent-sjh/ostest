use core::ffi::{c_char, c_int, c_long};
use axerrno::{LinuxError, LinuxResult};
use axfs::fops;
use axfs::fops::OpenOptions;
use syscall_trace::syscall_trace;
use crate::imp::fs::path::resolve_path_from_fd;
use crate::imp::fs::sys_truncate_impl;
use crate::interface::fs::UserStat;
use crate::ptr::{UserInPtr, UserOutPtr};

#[syscall_trace]
pub fn sys_truncate(path: UserInPtr<c_char>, length:c_long) -> LinuxResult<isize> {
    // get params
    let path = path.get_as_str()?;

    // open file
    let mut options = OpenOptions::new();
    options.truncate(true);

    let file = fops::File::open(path, &options)?;
    sys_truncate_impl(file, length as _)
}

#[syscall_trace]
pub fn sys_ftruncate(fd:c_int, length:c_long) -> LinuxResult<isize> {
    if let Ok(filepath) = resolve_path_from_fd(fd){
        let path = filepath.as_str();
        let mut options = OpenOptions::new();
        options.write(true);

        let file = fops::File::open(path, &options)?;
        sys_truncate_impl(file, length as _)
    } else{
        return Err(LinuxError::EBADFD);
    }
}