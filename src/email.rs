use core::{ptr::null_mut, slice::from_raw_parts, str::from_utf8};

use alloc::boxed::Box;
use cstr_core::{CStr, CString, NulError};
use email_rs::Email;

use crate::{EMAIL_PARSE_ERROR, NULL_ERROR, STRING_CONVERT_ERROR, SUCCESS, UTF8_ERROR};

const SUBJECT_LEN: usize = 7;
const FROM_LEN: usize = 4;

/// # Safety
///
/// This function is not safe.
#[no_mangle]
pub unsafe extern "C" fn get_email(
    input: *const u8,
    input_len: usize,
    email: &mut *mut Email,
) -> i32 {
    let input = from_raw_parts(input, input_len);
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

// #[no_mangle]
// extern "C" fn print_email(email: &Email) {
//     println!("email:{:?}", email);
// }

/// # Safety
///
/// This function is not safe.
#[no_mangle]
pub unsafe extern "C" fn drop_email(email: *mut Email) {
    Box::from_raw(email);
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[no_mangle]
pub unsafe extern "C" fn get_header_value(
    email: *const Email,
    header: *const u8,
    header_len: usize,
    res: &mut *mut u8,
    res_len: &mut usize,
) -> i32 {
    let header = from_raw_parts(header, header_len);
    let header = match from_utf8(header) {
        Err(_e) => return UTF8_ERROR,
        Ok(v) => v,
    };
    if email.is_null() {
        return NULL_ERROR;
    }
    let email = match email.as_ref() {
        Some(email) => email,
        None => return NULL_ERROR,
    };
    match email.get_header_value(header) {
        Ok(v) => match CString::new(v) {
            Ok(v) => {
                let mut v = v.into_bytes_with_nul();
                v.shrink_to_fit();
                let (ptr, len, cap) = v.into_raw_parts();
                assert_eq!(len, cap);
                *res = ptr;
                *res_len = len;
                SUCCESS
            }
            Err(_) => STRING_CONVERT_ERROR,
        },
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn get_body(email: &Email, res: &mut *mut u8, res_len: &mut usize) -> i32 {
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
    match CString::new(from_s) {
        Ok(v) => {
            let mut v = v.into_bytes_with_nul();
            v.shrink_to_fit();
            let (ptr, len, cap) = v.into_raw_parts();
            assert_eq!(len, cap);
            *from = ptr;
            *from_len = len;
            SUCCESS
        }
        Err(_e) => STRING_CONVERT_ERROR,
    }
}
/// # Safety
///
/// This function is not safe.
#[no_mangle]
pub unsafe extern "C" fn get_email_from_header(
    email: &Email,
    from: &mut *mut u8,
    from_len: &mut usize,
) -> i32 {
    let from_s = "from";
    let mut ori_from = null_mut();
    let mut ori_from_len = 0;
    let mut ret = get_header_value(
        email,
        from_s.as_ptr(),
        FROM_LEN,
        &mut ori_from,
        &mut ori_from_len,
    );
    if ori_from.is_null() {
        return NULL_ERROR;
    }
    from_raw_parts(ori_from, ori_from_len);

    if ret != 0 {
        return ret;
    }
    ret = extract_address_of_from(ori_from, ori_from_len, from, from_len);

    ret
}

/// # Safety
///
/// This function is not safe.
#[no_mangle]
pub unsafe extern "C" fn get_email_subject_header(
    email: &Email,
    subject: &mut *mut u8,
    subject_len: &mut usize,
) -> i32 {
    let subject_s = "subject";
    get_header_value(email, subject_s.as_ptr(), SUBJECT_LEN, subject, subject_len)
}

#[no_mangle]
pub extern "C" fn get_email_dkim_msg(
    email: &Email,
    dkim_msg: &mut *const *const u8,
    dkim_msg_len: &mut *const usize,
    dkim_msg_num: &mut usize,
) -> i32 {
    let dkim_msg_raw = email.get_dkim_message();
    let dkim_msg_raw: alloc::vec::Vec<_> = match dkim_msg_raw
        .iter()
        .map(|v| -> Result<_, NulError> { Ok(CString::new(v.as_str())?.into_bytes_with_nul()) })
        .collect()
    {
        Err(_e) => return NULL_ERROR,
        Ok(v) => v,
    };

    let mut dkim_msg_vec = alloc::vec::Vec::new();
    let mut dkim_msg_len_vec = alloc::vec::Vec::new();

    dkim_msg_raw.into_iter().for_each(|mut v| {
        v.shrink_to_fit();
        let (ptr, len, cap) = v.into_raw_parts();
        assert_eq!(len, cap);
        dkim_msg_vec.push(ptr);
        dkim_msg_len_vec.push(len);
    });

    dkim_msg_vec.shrink_to_fit();
    let (ptr, len, cap) = dkim_msg_vec.into_raw_parts();
    assert_eq!(len, cap);
    *dkim_msg = ptr as *const *const u8;

    dkim_msg_len_vec.shrink_to_fit();
    let (ptr, len, cap) = dkim_msg_len_vec.into_raw_parts();
    assert_eq!(len, cap);
    *dkim_msg_len = ptr;

    *dkim_msg_num = len;
    SUCCESS
}

#[no_mangle]
pub extern "C" fn get_email_dkim_sig(
    email: &Email,
    dkim_sig: &mut *const *const u8,
    dkim_sig_len: &mut *const usize,
    dkim_sig_num: &mut usize,
) -> i32 {
    let dkim_raw = &email.dkim_headers;
    let mut dkim_sig_vec = alloc::vec::Vec::new();
    let mut dkim_sig_len_vec = alloc::vec::Vec::new();
    dkim_raw.iter().for_each(|v| {
        let mut v = v.signature.clone();
        v.shrink_to_fit();
        let (ptr, len, cap) = v.into_raw_parts();
        assert_eq!(cap, len);
        dkim_sig_vec.push(ptr);
        dkim_sig_len_vec.push(len);
    });
    dkim_sig_vec.shrink_to_fit();
    dkim_sig_len_vec.shrink_to_fit();
    let (ptr, len, cap) = dkim_sig_vec.into_raw_parts();
    assert_eq!(len, cap);
    *dkim_sig = ptr as *const *const u8;

    let (ptr, len, cap) = dkim_sig_len_vec.into_raw_parts();
    assert_eq!(len, cap);
    *dkim_sig_len = ptr;

    *dkim_sig_num = len;
    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_vec_u8(ptr: *mut u8, len: usize, cap: usize) {
    alloc::vec::Vec::from_raw_parts(ptr, len, cap);
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_vec_usize(ptr: *mut usize, len: usize, cap: usize) {
    alloc::vec::Vec::from_raw_parts(ptr, len, cap);
}

#[no_mangle]
pub unsafe extern "C" fn rust_free_ptr_vec(ptr: *mut *mut u8, len: usize, cap: usize) {
    alloc::vec::Vec::from_raw_parts(ptr, len, cap);
}
