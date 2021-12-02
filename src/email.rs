use std::{
    ffi::{CStr, CString},
    ptr::null_mut,
    slice::from_raw_parts,
    str::from_utf8,
};

use email_rs::Email;

use crate::{
    rsa_with_sha256::{pub_pkey_from_component, pub_pkey_verify},
    EMAIL_PARSE_ERROR, NOT_VERIFY, NULL_ERROR, STRING_CONVERT_ERROR, SUCCESS, UTF8_ERROR,
};

#[no_mangle]
extern "C" fn get_email(input: *const u8, input_len: usize, email: &mut *mut Email) -> i32 {
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
extern "C" fn print_email(email: &Email) {
    println!("email:{:?}", email);
}

#[no_mangle]
extern "C" fn drop_email(email: *mut Email) {
    unsafe {
        Box::from_raw(email);
    }
}

#[no_mangle]
extern "C" fn verify_dkim_signature(
    email: *const Email,
    e: u32,
    n: *const u8,
    n_len: usize,
) -> i32 {
    let mut pub_pkey = null_mut();
    let ret = pub_pkey_from_component(e, n, n_len, &mut pub_pkey);
    if ret != 0 {
        return ret;
    }
    if pub_pkey.is_null() {
        return NULL_ERROR;
    }
    if email.is_null() {
        return NULL_ERROR;
    }
    let email = match unsafe { email.as_ref() } {
        None => return NULL_ERROR,
        Some(v) => v,
    };

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
extern "C" fn get_header_value(
    email: *const Email,
    header: *const u8,
    header_len: usize,
    res: &mut *mut u8,
    res_len: &mut usize,
) -> i32 {
    let header = unsafe { from_raw_parts(header, header_len) };
    let header = match from_utf8(header) {
        Err(_e) => return UTF8_ERROR,
        Ok(v) => v,
    };
    if email.is_null() {
        return NULL_ERROR;
    }
    let email = match unsafe { email.as_ref() } {
        Some(email) => email,
        None => return NULL_ERROR,
    };
    match email.get_header_value(header) {
        Ok(v) => {
            *res_len = v.len() + 1;
            let v = match CString::new(v) {
                Ok(v) => v,
                Err(_) => return STRING_CONVERT_ERROR,
            };
            *res = v.into_raw() as *mut u8;
            SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
extern "C" fn get_body(email: &Email, res: &mut *mut u8, res_len: &mut usize) -> i32 {
    match email.get_plain_body() {
        Ok(body) => {
            *res_len = body.len() + 1;
            let body = match CString::new(body) {
                Ok(b) => b,
                Err(_) => return STRING_CONVERT_ERROR,
            };
            *res = body.into_raw() as *mut u8;
            SUCCESS
        }
        Err(e) => e,
    }
}

#[no_mangle]
extern "C" fn extract_address_of_from(
    ori_from: *const u8,
    ori_from_len: usize,
    from: &mut *mut u8,
    from_len: &mut usize,
) -> i32 {
    let ori_from = if ori_from.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { from_raw_parts(ori_from, ori_from_len) }
    };
    let ori_from = match CStr::from_bytes_with_nul(ori_from) {
        Ok(v) => match v.to_str() {
            Ok(v) => v,
            Err(_) => return STRING_CONVERT_ERROR,
        },
        Err(_) => return STRING_CONVERT_ERROR,
    };

    let from_s = match Email::extract_address_of_from(ori_from) {
        Ok(v) => v,
        Err(e) => return e,
    };
    *from_len = from_s.len() + 1;
    *from = match CString::new(from_s) {
        Ok(v) => v.into_raw() as *mut u8,
        Err(_e) => return STRING_CONVERT_ERROR,
    };
    SUCCESS
}

const SUBJECT_LEN: usize = 7;
const FROM_LEN: usize = 4;

#[no_mangle]
pub extern "C" fn email_verify(
    email_s: *const u8,
    email_s_len: usize,
    e: u32,
    n: *const u8,
    n_len: usize,
    subject: &mut *mut u8,
    subject_len: &mut usize,
    from: &mut *mut u8,
    from_len: &mut usize,
) -> i32 {
    let mut email = null_mut();
    let mut ret = get_email(email_s, email_s_len, &mut email);
    if ret != 0 {
        drop_email(email);
        return ret;
    }
    ret = verify_dkim_signature(email, e, n, n_len);
    if ret != 0 {
        drop_email(email);
        return ret;
    }
    let subject_s = "subject";
    ret = get_header_value(email, subject_s.as_ptr(), SUBJECT_LEN, subject, subject_len);
    if ret != 0 {
        drop_email(email);
        return ret;
    }

    let from_s = "from";
    let mut ori_from = null_mut();
    let mut ori_from_len = 0;
    ret = get_header_value(
        email,
        from_s.as_ptr(),
        FROM_LEN,
        &mut ori_from,
        &mut ori_from_len,
    );
    if ori_from.is_null() {
        drop_email(email);
        return NULL_ERROR;
    }
    unsafe { from_raw_parts(ori_from, ori_from_len) };
    if ret != 0 {
        drop_email(email);
        return ret;
    }
    ret = extract_address_of_from(ori_from, ori_from_len, from, from_len);
    if ret != 0 {
        drop_email(email);
        return ret;
    }
    drop_email(email);
    SUCCESS
}
