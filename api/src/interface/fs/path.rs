use crate::imp::fs::path::sys_renameat_impl;
use crate::ptr::UserInPtr;
use axerrno::LinuxResult;
use core::ffi::{c_char, c_int, c_uint};

pub fn sys_renameat(
    old_dirfd: c_int,
    old_path: UserInPtr<c_char>,
    new_dirfd: c_int,
    new_path: UserInPtr<c_char>,
) -> LinuxResult<isize> {
    sys_renameat_impl(
        old_dirfd,
        old_path.get_as_str()?,
        new_dirfd,
        new_path.get_as_str()?,
        0,
    )
}

pub fn sys_renameat2(
    old_dirfd: c_int,
    old_path: UserInPtr<c_char>,
    new_dirfd: c_int,
    new_path: UserInPtr<c_char>,
    flags: c_uint,
) -> LinuxResult<isize> {
    debug!(
        "sys_renameat2 , old_dirfd: {}, old_path: {}, new_dirfd: {}, new_path: {}, flags: {}",
        old_dirfd,
        old_path.get_as_str()?,
        new_dirfd,
        new_path.get_as_str()?,
        flags
    );
    sys_renameat_impl(
        old_dirfd,
        old_path.get_as_str()?,
        new_dirfd,
        new_path.get_as_str()?,
        flags,
    )
}
