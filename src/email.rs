use std::{ptr::null_mut, slice::from_raw_parts, str::from_utf8};

use email_rs::Email;

use crate::{
    rsa_with_sha256::{pub_pkey_from_component, pub_pkey_verify},
    EMAIL_PARSE_ERROR, NOT_VERIFY, NULL_ERROR, SUCCESS, UTF8_ERROR,
};

#[no_mangle]
pub extern "C" fn get_email(input: *const u8, input_len: usize, email: &mut *mut Email) -> i32 {
    let input = unsafe { from_raw_parts(input, input_len) };
    let s = match from_utf8(input) {
        Ok(v) => v,
        Err(_) => return UTF8_ERROR,
    };
    match Email::from_str(s) {
        Ok(v) => {
            *email = Box::into_raw(Box::new(v));
            SUCCESS
        }
        Err(_) => EMAIL_PARSE_ERROR,
    }
}

#[no_mangle]
pub extern "C" fn print_email(email: &Email) {
    println!("email:{:?}", email);
}

#[no_mangle]
pub extern "C" fn drop_email(email: *mut Email) {
    unsafe {
        Box::from_raw(email);
    }
}

#[no_mangle]
pub extern "C" fn verify_dkim_signature(email: &Email, e: u32, n: *const u8, n_len: usize) -> i32 {
    let mut pub_pkey = null_mut();
    let ret = pub_pkey_from_component(e, n, n_len, &mut pub_pkey);
    if ret != 0 {
        return ret;
    }
    if pub_pkey.is_null() {
        return NULL_ERROR;
    }

    if email
        .get_dkim_message()
        .into_iter()
        .zip(email.dkim_headers.iter())
        .find(|(dkim_msg, dkim_header)| {
            let handle = || {
                let sig = &dkim_header.signature;
                pub_pkey_verify(
                    pub_pkey,
                    dkim_msg.as_ptr(),
                    dkim_msg.len(),
                    sig.as_ptr(),
                    sig.len(),
                )
            };
            handle() == 0
        })
        .is_none()
    {
        return NOT_VERIFY;
    }

    SUCCESS
}

#[no_mangle]
pub extern "C" fn get_header_value(
    email: &Email,
    header: *const u8,
    header_len: usize,
    res: &mut *const u8,
    res_len: &mut usize,
) -> i32 {
    let header = unsafe { from_raw_parts(header, header_len) };
    let header = match from_utf8(header) {
        Err(_e) => return UTF8_ERROR,
        Ok(v) => v,
    };
    println!("header:{}", header);
    match email.get_header_value(header) {
        Ok(v) => {
            *res_len = v.len();
            *res = v.as_ptr();
            SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn get_body(email: &Email, res: &mut *const u8, res_len: &mut usize) -> i32 {
    match email.get_plain_body() {
        Ok(body) => {
            *res_len = body.len();
            *res = body.as_ptr();
            SUCCESS
        }
        Err(e) => e,
    }
}
