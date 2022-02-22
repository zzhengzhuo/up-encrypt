#[cfg(test)]
pub mod tests {
    extern crate std;
    #[test]
    fn test_dkim_msg() {
        std::println!("current dir:{:?}", std::env::current_dir().unwrap());
        let email = std::fs::read("./qq.eml").unwrap();
        let email =
            email_rs::Email::from_str(unsafe { std::str::from_utf8_unchecked(&email) }).unwrap();
        std::println!("{}", email.get_dkim_message()[0]);
    }
}
