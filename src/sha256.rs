use std::slice::from_raw_parts;

use openssl::sha::Sha256;

use crate::{NULL_ERROR, SUCCESS};

#[no_mangle]
pub extern "C" fn sha256(
    input: *const u8,
    input_len: usize,
    output: &mut *const u8,
    output_len: &mut usize,
) -> i32 {
    let mut sha256 = Sha256::new();
    let input = if input.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { from_raw_parts(input, input_len) }
    };
    sha256.update(input);
    let res = sha256.finish();
    *output_len = res.len();
    *output = res.as_ptr();
    SUCCESS
}
