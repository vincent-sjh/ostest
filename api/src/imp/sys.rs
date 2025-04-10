use axerrno::LinuxResult;

use crate::ptr::{PtrWrapper, UserPtr};

pub fn sys_getuid() -> LinuxResult<isize> {
    Ok(0)
}

#[repr(C)]
pub struct UtsName {
    /// sysname
    pub sysname: [u8; 65],
    /// nodename
    pub nodename: [u8; 65],
    /// release
    pub release: [u8; 65],
    /// version
    pub version: [u8; 65],
    /// machine
    pub machine: [u8; 65],
    /// domainname
    pub domainname: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: Self::from_str("Starry"),
            nodename: Self::from_str("Starry - machine[0]"),
            release: Self::from_str("10.0.0"),
            version: Self::from_str("10.0.0"),
            machine: Self::from_str("10.0.0"),
            domainname: Self::from_str("https://github.com/BattiestStone4/Starry-On-ArceOS"),
        }
    }
}

impl UtsName {
    fn from_str(info: &str) -> [u8; 65] {
        let mut data: [u8; 65] = [0; 65];
        data[..info.len()].copy_from_slice(info.as_bytes());
        data
    }
}

pub struct Sysinfo{
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    _f: [u8; 22],
}
impl Default for Sysinfo {
    fn default() -> Self {
        Self {
            uptime: 86400,
            loads: [30000,40000,50000],
            totalram: 16*1024*1024*1024,
            freeram: 8*1024*1024*1024,
            sharedram: 512*1024*1024,
            bufferram: 1*1024*1024*1024,
            totalswap: 4*1024*1024*1024,
            freeswap: 3*1024*1024*1024,
            procs: 150,
            _f: [0; 22],
        }
    }
}
pub fn sys_uname(name: UserPtr<UtsName>) -> LinuxResult<isize> {
    unsafe { *name.get()? = UtsName::default() };
    Ok(0)
}

pub fn sys_syslog(
    _type: i32,
    buf: UserPtr<u8>,
    len: usize,
) -> LinuxResult<isize> {
    let buf = buf.get_as_array(len)?;
    let buf: &[u8] = unsafe { core::slice::from_raw_parts(buf, len) };
    let buf = core::str::from_utf8(buf).unwrap_or("Invalid UTF-8");
    info!("[syslog] {}", buf);
    Ok(0)
}

pub fn sys_sysinfo(info: UserPtr<Sysinfo>) -> LinuxResult<isize> {
    let info = info.get()?;
    unsafe { *info = Sysinfo::default() };
    Ok(0)
}
