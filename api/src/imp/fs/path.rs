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

pub fn sys_renameat_impl(
    old_dir_fd: i32,
    old_path: &str,
    new_dir_fd: i32,
    new_path: &str,
    flags: u32,
) -> LinuxResult<isize> {
    debug!(
        "sys_truncate_impl, old_dir_fd: {}, old_path: {}, new_dir_fd: {}, new_path: {}, flags: {}",
        old_dir_fd, old_path, new_dir_fd, new_path, flags
    );
    let flags = RenameFlags::from_bits(flags).ok_or(LinuxError::EINVAL)?;
    let old_path = resolve_path_with_parent(old_dir_fd, old_path)?;
    let new_path = resolve_path_with_parent(new_dir_fd, new_path)?;

    if flags.contains(RenameFlags::NOREPLACE) && axfs::api::metadata(&new_path).is_ok() {
        return Err(LinuxError::EEXIST);
    }
    // TODO:`EXCHANGE` and `WHITEOUT`

    warn!("rename {} to {}", old_path, new_path);
    axfs::api::rename(&old_path, &new_path)?;

    Ok(0)
}
