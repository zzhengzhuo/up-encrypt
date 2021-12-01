extern crate cbindgen;

use std::env;

use cbindgen::Language;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_after_include(
            "typedef struct PKey PubPKey;
typedef struct RustEmail Email;",
        )
        .exclude_item("PubPKey")
        .with_language(Language::C)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("up_encrypt.h");
}
