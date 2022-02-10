#![no_std]
#![feature(allocator_api)]
#![feature(alloc_error_handler)]
#![feature(vec_into_raw_parts)]

use buddy_alloc::{BuddyAllocParam, FastAllocParam, NonThreadsafeAlloc};
extern crate alloc;

const FAST_HEAP_SIZE: usize = 32 * 1024; // 32 KB
const HEAP_SIZE: usize = 1024 * 1024; // 1M
const LEAF_SIZE: usize = 16;

pub static mut FAST_HEAP: [u8; FAST_HEAP_SIZE] = [0u8; FAST_HEAP_SIZE];
pub static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];

#[cfg_attr(not(test), global_allocator)]
static ALLOC: NonThreadsafeAlloc = unsafe {
    let fast_param = FastAllocParam::new(FAST_HEAP.as_ptr(), FAST_HEAP_SIZE);
    let buddy_param = BuddyAllocParam::new(HEAP.as_ptr(), HEAP_SIZE, LEAF_SIZE);
    NonThreadsafeAlloc::new(fast_param, buddy_param)
};

#[alloc_error_handler]
fn alloc_panic(_: core::alloc::Layout) -> ! {
    panic!("DO NOTHING alloc_error_handler set by kernel");
}

#[panic_handler]
fn unexpected_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod email;
// pub mod rsa_with_sha256;

pub const SUCCESS: i32 = 0;

pub const NULL_ERROR: i32 = -1;
pub const NOT_VERIFY: i32 = -2;
pub const UTF8_ERROR: i32 = -3;
pub const EMAIL_PARSE_ERROR: i32 = -4;
pub const STRING_CONVERT_ERROR: i32 = -5;
pub const RSA_PUBKEY_ERROR: i32 = -6;
