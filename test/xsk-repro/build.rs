fn main() {
    cc::Build::new()
        .file("../../userspace-dp/csrc/xsk_bridge.c")
        .include("/usr/include")
        .warnings(true)
        .flag("-Wno-unused-parameter")
        .opt_level(2)
        .compile("xsk_bridge");

    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=zstd");
    println!("cargo:rerun-if-changed=../../userspace-dp/csrc/xsk_bridge.c");
    println!("cargo:rerun-if-changed=../../userspace-dp/src/xsk_ffi.rs");
}
