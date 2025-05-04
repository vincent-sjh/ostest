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
use starry_core::entry::run_user_app;

#[unsafe(no_mangle)]
fn main() {
    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());

    for testcase in testcases {
        let testcase = testcase.trim();
        if testcase.is_empty() {
            continue;
        }
        let args = vec!["/musl/busybox", "sh", "-c", testcase];
        let args: Vec<String> = args.into_iter().map(String::from).collect();

        info!("[task manager] Running user task: {}", testcase);

        let exit_code = run_user_app(&args, &["PATH=/bin".to_string()]);
        info!(
            "[task manager] User task {} exited with code: {:?}",
            testcase, exit_code
        );
    }
}
