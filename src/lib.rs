pub mod email;
pub mod rsa_with_sha256;
pub mod sha256;

pub const SUCCESS: i32 = 0;

pub const NULL_ERROR: i32 = -1;
pub const NOT_VERIFY: i32 = -2;
pub const UTF8_ERROR: i32 = -3;
pub const EMAIL_PARSE_ERROR: i32 = -4;
pub const STRING_CONVERT_ERROR: i32 = -5;
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
