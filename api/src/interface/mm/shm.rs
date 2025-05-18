use alloc::sync::Arc;
use axerrno::{LinuxError, LinuxResult};
use axhal::mem::virt_to_phys;
use axhal::paging::MappingFlags;
use bitflags::bitflags;
use core::ffi::{c_int, c_ulong};
use memory_addr::{PAGE_SIZE_4K, VirtAddr, VirtAddrRange, align_down_4k, is_aligned_4k};
use starry_core::shared_memory::SHARED_MEMORY_MANAGER;
use starry_core::task::current_process_data;
use syscall_trace::syscall_trace;

bitflags! {
    struct ShmFlags: c_int {
        const IPC_CREAT = 0o1000;
        const IPC_EXCL = 0o2000;
        const IPC_NOWAIT = 0o4000;
        const SHM_RDONLY = 0o10000;
        const SHM_RND = 0o20000;
        const SHM_REMAP = 0o40000;
        const SHM_EXEC = 0o100000;
    }
}

const IPC_PRIVATE: c_int = 0;

#[syscall_trace]
pub fn sys_shmget(key: c_int, size: c_ulong, shm_flag: c_int) -> LinuxResult<isize> {
    error!("shmget: key: {}, size: {}, shm_flag: {}", key, size, shm_flag);
    let size = size as usize;
    let flags = ShmFlags::from_bits_truncate(shm_flag);
    // TODO: permission check
    if key == IPC_PRIVATE {
        // IPC get private
        let key = SHARED_MEMORY_MANAGER.next_available_key();
        let shared_memory = SHARED_MEMORY_MANAGER.create(key, size)?;
        Ok(shared_memory.key as _)
    } else {
        let key = key as u32;
        if SHARED_MEMORY_MANAGER.get(key).is_none() {
            if !flags.contains(ShmFlags::IPC_CREAT) {
                Err(LinuxError::ENOENT)
            } else {
                let shared_memory = SHARED_MEMORY_MANAGER.create(key, size)?;
                Ok(shared_memory.key as _)
            }
        } else {
            if flags.contains(ShmFlags::IPC_CREAT | ShmFlags::IPC_EXCL) {
                Err(LinuxError::EEXIST)
            } else {
                Ok(key as _)
            }
        }
    }
}

#[syscall_trace]
pub fn sys_shmat(shm_id: c_int, shm_addr: c_ulong, shm_flag: c_int) -> LinuxResult<isize> {
    let flags = ShmFlags::from_bits_truncate(shm_flag);
    let key = shm_id as u32;
    let shared_memory = SHARED_MEMORY_MANAGER.get(key).ok_or(LinuxError::EINVAL)?;
    // TODO: check if deleted
    let size = shared_memory.page_count * PAGE_SIZE_4K;
    let process_data = current_process_data();
    let mut addr_space = process_data.addr_space.lock();
    let addr = if shm_addr == 0 {
        addr_space.find_free_area(
            addr_space.base(),
            size,
            VirtAddrRange::new(addr_space.base(), addr_space.end()),
        )
    } else {
        if flags.contains(ShmFlags::SHM_RND) {
            let addr = align_down_4k(shm_addr as usize);
            addr_space.find_free_area(
                VirtAddr::from(addr),
                size,
                VirtAddrRange::new(addr_space.base(), addr_space.end()),
            )
        } else {
            if !is_aligned_4k(shm_addr as _) {
                return Err(LinuxError::EINVAL);
            }
            Some(VirtAddr::from(shm_addr as usize))
        }
    };
    let addr = addr.ok_or(LinuxError::ENOMEM)?;
    // permission
    let mut permission = MappingFlags::USER | MappingFlags::READ;
    if !flags.contains(ShmFlags::SHM_RDONLY) {
        permission |= MappingFlags::WRITE;
    }
    if flags.contains(ShmFlags::SHM_EXEC) {
        permission |= MappingFlags::EXECUTE;
    }
    let paddr = virt_to_phys(VirtAddr::from(shared_memory.addr));
    addr_space.map_linear(addr, paddr, size, permission)?;
    // add to process data
    let process_data = current_process_data();
    let mut process_shared_memory = process_data.shared_memory.lock();
    error!("on attach: shared memory {} count {}", shared_memory.key, Arc::strong_count(&shared_memory));
    process_shared_memory.insert(addr, shared_memory);

    Ok(addr.as_usize() as _)
}

// TODO: implement shmdt
#[syscall_trace]
pub fn sys_shmctl(shm_id: c_int, op: c_int, buf: c_ulong) -> LinuxResult<isize> {
    error!("shmctl: shm_id: {}, op: {}, buf: {}", shm_id, op, buf);
    let key = shm_id as u32;
    let shared_memory = SHARED_MEMORY_MANAGER.get(key).ok_or(LinuxError::EINVAL)?;
    match op {
        0 => {
            // IPC_RMID
            if SHARED_MEMORY_MANAGER.delete(shared_memory.key) {
                Ok(0)
            } else {
                Err(LinuxError::EINVAL)
            }
        }
        1 => {
            // IPC_STAT
            // let stat = unsafe { &mut *(buf as *mut libc::shmid_ds) };
            // stat.shm_perm.key = shared_memory.key as _;
            // stat.shm_perm.mode = 0o600;
            // stat.shm_perm.cuid = 0;
            // stat.shm_perm.uid = 0;
            // stat.shm_perm.gid = 0;
            // stat.shm_perm.cpid = 0;
            // stat.shm_perm.lpid = 0;
            // stat.shm_segsz = shared_memory.page_count * PAGE_SIZE_4K as _;
            Ok(0)
        }
        _ => Err(LinuxError::EINVAL),
    }
}
