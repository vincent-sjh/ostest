use crate::imp::utils::path::resolve_path_with_parent;
use axerrno::{LinuxError, LinuxResult};
use bitflags::bitflags;
use linux_raw_sys::general::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

bitflags! {
    #[derive(Debug)]
    pub struct RenameFlags: u32 {
        const NOREPLACE = RENAME_NOREPLACE;
        const EXCHANGE = RENAME_EXCHANGE;
        const WHITEOUT = RENAME_WHITEOUT;
    }
}

pub fn sys_rename_impl(
    old_dir_fd: i32,
    old_path: &str,
    new_dir_fd: i32,
    new_path: &str,
    flags: RenameFlags,
) -> LinuxResult<isize> {
    let old_path = resolve_path_with_parent(old_dir_fd, old_path)?;
    let new_path = resolve_path_with_parent(new_dir_fd, new_path)?;

    if flags.contains(RenameFlags::NOREPLACE) && axfs::api::metadata(&new_path).is_ok() {
        return Err(LinuxError::EEXIST);
    }
    // TODO:`EXCHANGE` and `WHITEOUT`
    axfs::api::rename(&old_path, &new_path)?;
    Ok(0)
}

pub fn sys_mkdir_impl(dir_fd: i32, path: &str, mode: u16) -> LinuxResult<isize> {
    if mode != 0 {
        info!("[sys_mkdir_impl] dir mode is not 0, unimplemented and ignored");
    }
    let path = resolve_path_with_parent(dir_fd, path)?;
    if axfs::api::metadata(&path).is_ok() {
        return Err(LinuxError::EEXIST);
    }
    axfs::api::create_dir(&path)?;
    Ok(0)
}

bitflags! {
    #[derive(Debug)]
    pub struct UnlinkFlags: u8 {
        const NO_REMOVE_DIR = 0x1;
        const NO_REMOVE_FILE = 0x2;
    }
}

pub fn sys_unlink_impl(dir_fd: i32, path: &str, flags: UnlinkFlags) -> LinuxResult<isize> {
    let path = resolve_path_with_parent(dir_fd, path)?;
    let meta = axfs::api::metadata(&path)?;
    if meta.is_dir() {
        if flags.contains(UnlinkFlags::NO_REMOVE_DIR) {
            return Err(LinuxError::EISDIR);
        }
        axfs::api::remove_dir(&path)?;
    } else if meta.is_file() {
        if flags.contains(UnlinkFlags::NO_REMOVE_FILE) {
            return Err(LinuxError::ENOTDIR);
        }
        axfs::api::remove_file(&path)?;
    } else {
        // other types of files, like symlink, socket, etc.
        axfs::api::remove_file(&path)?;
    }
    Ok(0)
}
