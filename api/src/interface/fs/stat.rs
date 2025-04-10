use crate::StatX;
use crate::ptr::{PtrWrapper, UserConstPtr, UserPtr};
use crate::status::{FileStatus, TimeSpec, sys_stat_impl};
use arceos_posix_api::AT_FDCWD;
use axerrno::LinuxError;
use axerrno::LinuxResult;
use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong};

// constants
const AT_EMPTY_PATH: c_int = 0x1000;
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

/// File status: struct stat
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserStat {
    /// ID of device containing file
    pub st_dev: c_ulong,
    /// inode number
    pub st_ino: c_ulong,
    /// number of hard links
    /// note that the field sequence is different from other archs
    pub st_nlink: c_ulong,
    /// file type and mode
    pub st_mode: c_uint,
    /// user ID of owner
    pub st_uid: c_uint,
    /// group ID of owner
    pub st_gid: c_uint,
    /// paddings for arch x86_64
    pub _pad0: c_int,
    /// device ID (if special file)
    pub st_rdev: c_ulong,
    /// total size, in bytes
    pub st_size: c_long,
    /// Block size for filesystem I/O
    pub st_blksize: c_long,
    /// number of blocks allocated
    pub st_blocks: c_long,
    /// time of last access
    pub st_atime: TimeSpec,
    /// time of last modification
    pub st_mtime: TimeSpec,
    /// time of last status change
    pub st_ctime: TimeSpec,
    /// glibc reserved for arch x86_64
    pub _glibc_reserved: [c_long; 3],
}

#[cfg(target_arch = "x86_64")]
impl From<FileStatus> for UserStat {
    fn from(fs: FileStatus) -> Self {
        UserStat {
            st_dev: fs.dev as c_ulong,
            st_ino: fs.inode as c_ulong,
            st_nlink: fs.n_link as c_ulong,
            st_mode: fs.mode,
            st_uid: fs.uid,
            st_gid: fs.gid,
            st_rdev: fs.rdev as c_ulong,
            st_size: fs.size as c_long,
            st_blksize: fs.block_size as c_long,
            st_blocks: fs.n_blocks as c_long,
            st_atime: fs.access_time,
            st_mtime: fs.modify_time,
            st_ctime: fs.change_time,
            ..Default::default()
        }
    }
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<UserStat>() == 144, "size of Stat is not 144");

#[cfg(not(target_arch = "x86_64"))]
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserStat {
    /// ID of device containing file
    pub st_dev: c_ulong,
    /// inode number
    pub st_ino: c_ulong,
    /// file type and mode
    pub st_mode: c_uint,
    /// number of hard links
    pub st_nlink: c_uint,
    /// user ID of owner
    pub st_uid: c_uint,
    /// group ID of owner
    pub st_gid: c_uint,
    /// device ID (if special file)
    pub st_rdev: c_ulong,
    /// paddings for arch non x86_64
    pub _pad0: c_long,
    /// total size, in bytes
    pub st_size: c_long,
    /// Block size for filesystem I/O
    pub st_blksize: c_int,
    /// paddings for arch non x86_64
    pub _pad1: c_int,
    /// number of blocks allocated
    pub st_blocks: c_long,
    /// time of last access
    pub st_atime: TimeSpec,
    /// time of last modification
    pub st_mtime: TimeSpec,
    /// time of last status change
    pub st_ctime: TimeSpec,
    /// reserved for arch non x86_64
    pub _unused: [c_int; 2],
}

#[cfg(not(target_arch = "x86_64"))]
impl From<FileStatus> for UserStat {
    fn from(fs: FileStatus) -> Self {
        UserStat {
            st_dev: fs.dev as c_ulong,
            st_ino: fs.inode as c_ulong,
            st_mode: fs.mode,
            st_nlink: fs.n_link as c_uint,
            st_uid: fs.uid,
            st_gid: fs.gid,
            st_rdev: fs.rdev as c_ulong,
            st_size: fs.size as c_long,
            st_blksize: fs.block_size as c_int,
            st_blocks: fs.n_blocks as c_long,
            st_atime: fs.access_time,
            st_mtime: fs.modify_time,
            st_ctime: fs.change_time,
            ..Default::default()
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
const _: () = assert!(size_of::<UserStat>() == 128, "size of Stat is not 128");

pub fn sys_stat(path: UserConstPtr<c_char>, stat_buf: UserPtr<UserStat>) -> LinuxResult<isize> {
    // get params
    let path = path.get_as_str()?;
    let stat_buf = stat_buf.get()?;

    // perform syscall
    let result = (|| -> LinuxResult<_> { sys_stat_impl(-1, path, false) })();

    // check result
    match result {
        Ok(fs) => {
            let stat: UserStat = fs.into();
            debug!(
                "[syscall] stat(pathname={:?}, statbuf={:?}) = {}",
                path, stat, 0
            );
            // copy to user space
            unsafe { stat_buf.write(fs.into()) }
            Ok(0)
        }
        Err(err) => {
            debug!(
                "[syscall] stat(pathname={:?}, statbuf={:p}) = {:?}",
                path, stat_buf, err
            );
            Err(err)
        }
    }
}

/// TODO: ignored following symlinks
pub fn sys_lstat(path: UserConstPtr<c_char>, stat_buf: UserPtr<UserStat>) -> LinuxResult<isize> {
    // get params
    let path = path.get_as_str()?;
    let stat_buf = stat_buf.get()?;

    // perform syscall
    let result = (|| -> LinuxResult<_> { sys_stat_impl(-1, path, true) })();

    // check result
    match result {
        Ok(fs) => {
            let stat: UserStat = fs.into();
            debug!(
                "[syscall] lstat(pathname={:?}, statbuf={:?}) = {}",
                path, stat, 0
            );
            // copy to user space
            unsafe { stat_buf.write(fs.into()) }
            Ok(0)
        }
        Err(err) => {
            debug!(
                "[syscall] lstat(pathname={:?}, statbuf={:p}) = {:?}",
                path, stat_buf, err
            );
            Err(err)
        }
    }
}

pub fn sys_fstat(fd: c_int, stat_buf: UserPtr<UserStat>) -> LinuxResult<isize> {
    // get params
    let stat_buf = stat_buf.get()?;

    // perform syscall
    let result = (|| -> LinuxResult<_> {
        if fd < 0 && fd != AT_FDCWD as i32 {
            Err(LinuxError::EBADFD)
        } else {
            sys_stat_impl(fd, "", false)
        }
    })();

    // check result
    match result {
        Ok(fs) => {
            let stat: UserStat = fs.into();
            debug!("[syscall] fstat(fd={}, statbuf={:?}) = {}", fd, stat, 0);
            // copy to user space
            unsafe { stat_buf.write(fs.into()) }
            Ok(0)
        }
        Err(err) => {
            debug!(
                "[syscall] fstat(fd={}, statbuf={:p}) = {:?}",
                fd, stat_buf, err
            );
            Err(err)
        }
    }
}

pub fn sys_fstatat(
    dir_fd: c_int,
    path: UserConstPtr<c_char>,
    stat_buf: UserPtr<UserStat>,
    flags: c_int,
) -> LinuxResult<isize> {
    // get params
    let path = path.get_as_str().unwrap_or("");
    let stat_buf = stat_buf.get()?;

    // perform syscall
    let result = (|| -> LinuxResult<_> {
        if dir_fd < 0 && dir_fd != AT_FDCWD as i32 {
            return Err(LinuxError::EBADFD);
        }
        // TODO: some flags are ignored
        if path.is_empty() && (flags & AT_EMPTY_PATH == 0) {
            return Err(LinuxError::ENOENT);
        }
        let follow_symlinks = flags & AT_SYMLINK_NOFOLLOW == 0;
        sys_stat_impl(dir_fd, path, follow_symlinks)
    })();

    // check result
    match result {
        Ok(fs) => {
            let stat: UserStat = fs.into();
            debug!(
                "[syscall] fstatat(dirfd={}, pathname={:?}, statbuf={:?}, flags={}) = {}",
                dir_fd, path, stat, flags, 0
            );
            // copy to user space
            unsafe { stat_buf.write(fs.into()) }
            Ok(0)
        }
        Err(err) => {
            debug!(
                "[syscall] fstatat(dirfd={}, pathname={:?}, statbuf={:p}, flags={}) = {:?}",
                dir_fd, path, stat_buf, flags, err
            );
            Err(err)
        }
    }
}

pub fn sys_statx(
    dir_fd: c_int,
    path: UserConstPtr<c_char>,
    flags: c_int,
    _mask: c_uint,
    statx_buf: UserPtr<StatX>,
) -> LinuxResult<isize> {
    // get params
    let path = path.get_as_str().unwrap_or("");
    let statx_buf = statx_buf.get()?;

    // perform syscall
    let result = (|| -> LinuxResult<_> {
        if dir_fd < 0 && dir_fd != AT_FDCWD as i32 {
            return Err(LinuxError::EBADFD);
        }
        // TODO: some flags are ignored
        if path.is_empty() && (flags & AT_EMPTY_PATH == 0) {
            return Err(LinuxError::ENOENT);
        }
        let follow_symlinks = flags & AT_SYMLINK_NOFOLLOW == 0;
        let file_status = sys_stat_impl(dir_fd, path, follow_symlinks)?;
        // TODO: add more fields
        Ok(StatX::from(file_status))
    })();

    // check result
    match result {
        Ok(statx) => {
            debug!(
                "[syscall] statx(dirfd={}, pathname={:?}, flags={}, mask={}, statx_buf={:?}) = {}",
                dir_fd, path, flags, _mask, statx, 0
            );
            // copy to user space
            unsafe { statx_buf.write(statx.into()) }
            Ok(0)
        }
        Err(err) => {
            debug!(
                "[syscall] statx(dirfd={}, pathname={:?}, flags={}, mask={}, statx_buf={:p}) = {:?}",
                dir_fd, path, flags, _mask, statx_buf, err
            );
            Err(err)
        }
    }
}
