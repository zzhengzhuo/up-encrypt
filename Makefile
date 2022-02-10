rust:
	cargo build --target riscv64imac-unknown-none-elf --release 

build:rust
	riscv64-unknown-elf-gcc -I. tests/main.c target/riscv64imac-unknown-none-elf/release/libup_encrypt.a

test:build
	riscv64-unknown-elf-run a.out