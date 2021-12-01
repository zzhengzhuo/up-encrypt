use std::slice::from_raw_parts;

use openssl::{
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Rsa,
    sign::Verifier,
};

use crate::{NOT_VERIFY, NULL_ERROR, SUCCESS};

pub type Pubkey = Rsa<Public>;
pub type PubPKey = PKey<Public>;

fn openssl_error_to_i32(e: &ErrorStack) -> i32 {
    e.errors()[0].code() as i32
}

#[no_mangle]
pub extern "C" fn print_pub_pkey(input: *const PubPKey) -> i32 {
    let input = if input.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { &*input }
    };
    println!("rsa keypair:{:?}", input);
    SUCCESS
}

#[no_mangle]
pub extern "C" fn drop_pub_pkey(input: *mut PubPKey) {
    unsafe { Box::from_raw(input) };
}

#[no_mangle]
pub extern "C" fn pub_pkey_from_component(
    e: u32,
    n: *const u8,
    n_len: usize,
    pub_pkey_res: &mut *mut PubPKey,
) -> i32 {
    let n = if n.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { from_raw_parts(n, n_len) }
    };

    let e = match BigNum::from_u32(e) {
        Ok(n) => n,
        Err(e) => {
            return openssl_error_to_i32(&e);
        }
    };
    let n = match BigNum::from_slice(n) {
        Ok(n) => n,
        Err(e) => {
            return openssl_error_to_i32(&e);
        }
    };

    let pubkey = match Pubkey::from_public_components(n, e) {
        Ok(v) => v,
        Err(e) => return e.errors()[0].code() as i32,
    };
    match PubPKey::from_rsa(pubkey) {
        Ok(v) => {
            *pub_pkey_res = Box::into_raw(Box::new(v));
            SUCCESS
        }
        Err(e) => openssl_error_to_i32(&e),
    }
}

#[no_mangle]
pub extern "C" fn pub_pkey_verify(
    pub_pkey: *const PubPKey,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    let pub_pkey = if pub_pkey.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { &*pub_pkey }
    };
    let signature = if signature.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { from_raw_parts(signature, signature_len) }
    };
    let message = if message.is_null() {
        return NULL_ERROR;
    } else {
        unsafe { from_raw_parts(message, message_len) }
    };
    let mut verifier = match Verifier::new(MessageDigest::sha256(), &pub_pkey.as_ref()) {
        Ok(v) => v,
        Err(e) => return openssl_error_to_i32(&e),
    };
    if let Err(e) = verifier.update(message) {
        return openssl_error_to_i32(&e);
    }
    match verifier.verify(signature) {
        Ok(true) => SUCCESS,
        Ok(false) => NOT_VERIFY,
        Err(e) => openssl_error_to_i32(&e),
    }
}
