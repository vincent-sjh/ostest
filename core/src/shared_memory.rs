use alloc::collections::BTreeMap;
use axalloc::global_allocator;
use axerrno::{LinuxError, LinuxResult};
use axsync::Mutex;
use memory_addr::{PAGE_SIZE_4K, align_up_4k};

#[derive(Copy, Clone)]
pub struct SharedMemory {
    /// The key of the shared memory segment
    pub key: u32,
    /// Physical address of the shared memory segment
    pub addr: usize,
    /// Page count of the shared memory segment
    pub page_count: usize,
}

pub struct SharedMemoryManager {
    mem_map: Mutex<BTreeMap<u32, SharedMemory>>,
}

impl SharedMemoryManager {
    pub fn remove(&self, p0: u32) {
        todo!()
    }
}

impl SharedMemoryManager {
    pub const fn new() -> Self {
        SharedMemoryManager {
            mem_map: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn next_available_key(&self) -> u32 {
        self.mem_map.lock().keys().max().unwrap_or(&0) + 1
    }

    pub fn get(&self, key: u32) -> Option<SharedMemory> {
        self.mem_map.lock().get(&key).copied()
    }

    pub fn create(&self, key: u32, size: usize) -> LinuxResult<SharedMemory> {
        let page_count = size.div_ceil(PAGE_SIZE_4K);
        let allocator = global_allocator();
        // TODO: more error checking
        let vaddr = allocator
            .alloc_pages(page_count, PAGE_SIZE_4K)
            .map_err(|_| LinuxError::ENOMEM)?;
        let shared_memory = SharedMemory {
            key,
            addr: vaddr,
            page_count: size,
        };
        self.mem_map.lock().insert(key, shared_memory);
        Ok(shared_memory)
    }

    pub fn insert(&self, addr: usize, size: usize) -> SharedMemory {
        let key = self.next_available_key();
        let shared_memory = SharedMemory {
            key,
            addr,
            page_count: size,
        };
        self.mem_map.lock().insert(key, shared_memory);
        shared_memory
    }
}

pub static SHARED_MEMORY_MANAGER: SharedMemoryManager = SharedMemoryManager::new();
