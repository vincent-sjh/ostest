use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axmm::{AddrSpace, kernel_aspace};
use axns::AxNamespace;
use core::sync::atomic::{AtomicUsize, Ordering};
use memory_addr::VirtAddrRange;
use spin::Mutex;

pub struct ProcessData {
    /// The command line arguments
    pub command_line: Mutex<Vec<String>>,

    // address space related are shared with all threads
    /// The virtual memory address space.
    pub addr_space: Arc<Mutex<AddrSpace>>,
    /// The user heap bottom
    heap_bottom: AtomicUsize,
    /// The user heap top
    heap_top: AtomicUsize,
    // TODO: resource limits
    // TODO: signals
    // TODO: futex?
}

impl ProcessData {
    pub fn new(command_line: Vec<String>, addr_space: Arc<Mutex<AddrSpace>>) -> Self {
        Self {
            command_line: Mutex::new(command_line),
            addr_space,
            heap_bottom: AtomicUsize::new(axconfig::plat::USER_HEAP_BASE),
            heap_top: AtomicUsize::new(axconfig::plat::USER_HEAP_BASE),
            // rlim: RwLock::default(), }
        }
    }

    pub fn get_heap_bottom(&self) -> usize {
        self.heap_bottom.load(Ordering::Acquire)
    }

    pub fn set_heap_bottom(&self, bottom: usize) {
        self.heap_bottom.store(bottom, Ordering::Release)
    }

    pub fn get_heap_top(&self) -> usize {
        self.heap_top.load(Ordering::Acquire)
    }

    pub fn set_heap_top(&self, top: usize) {
        self.heap_top.store(top, Ordering::Release)
    }
}

impl Drop for ProcessData {
    fn drop(&mut self) {
        // TODO: prevent memory leak
        if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
            // See [`crate::new_user_aspace`]
            let kernel = kernel_aspace().lock();
            self.addr_space
                .lock()
                .clear_mappings(VirtAddrRange::from_start_size(kernel.base(), kernel.size()));
        }
    }
}

pub struct ThreadData {
    /// The process data
    pub process_data: Arc<ProcessData>,
    /// The resource namespace, used by FD_TABLE and CURRENT_DIR, etc.
    pub namespace: AxNamespace,
    /// The clear thread tid field
    ///
    /// See <https://manpages.debian.org/unstable/manpages-dev/set_tid_address.2.en.html#clear_child_tid>
    ///
    /// When the thread exits, the kernel clears the word at this address if it is not NULL.
    pub addr_clear_child_tid: AtomicUsize,
    /// The set thread tid field
    pub addr_set_child_tid: AtomicUsize,
    // TODO: signals
}

impl ThreadData {
    pub fn new(process_data: Arc<ProcessData>) -> Self {
        Self {
            process_data,
            namespace: AxNamespace::new_thread_local(),
            addr_clear_child_tid: AtomicUsize::new(0),
            addr_set_child_tid: AtomicUsize::new(0),
        }
    }
}
