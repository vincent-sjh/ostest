#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

extern crate alloc;
#[macro_use]
extern crate axlog;

mod mm;
mod syscall;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use axalloc::global_allocator;
use starry_core::entry::run_user_app;

#[unsafe(no_mangle)]
fn main() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    let allocator = global_allocator();

    for testcase in testcases {
        error!(
            "memory statistic: used: [{} KiB, {} pages], available: [{} KiB, {} pages]",
            allocator.used_bytes() / 1024,
            allocator.used_pages(),
            allocator.available_bytes() / 1024,
            allocator.available_pages()
        );
        let testcase = testcase.trim();
        if testcase.is_empty() {
            continue;
        }
        // sh mode
        let args = vec!["/musl/busybox", "sh", "-c", testcase];
        // direct mode
        // let args = testcase.split(" ");
        let args: Vec<String> = args.into_iter().map(String::from).collect();

        info!("[task manager] Running user task: {}", testcase);

        let envs = vec![
            "PATH=/bin".to_string(),
            "LD_LIBRARY_PATH=/lib:/lib64".to_string(),
            // "LD_DEBUG=all".to_string(),
        ];

        let exit_code = run_user_app(&args, &envs);
        info!(
            "[task manager] User task {} exited with code: {:?}",
            testcase, exit_code
        );
    }
}
