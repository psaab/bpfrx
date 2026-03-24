fn main() {
    // Compile the C bridge that wraps libxdp's inline xsk helpers.
    cc::Build::new()
        .file("csrc/xsk_bridge.c")
        .include("/usr/include")
        .warnings(true)
        .flag("-Wno-unused-parameter")
        .opt_level(2)
        .compile("xsk_bridge");

    // Statically link libxdp and its transitive dependencies so the
    // binary is self-contained (no libxdp.so.1 needed on target VMs).
    println!("cargo:rustc-link-lib=static=xdp");
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=zstd");
    println!("cargo:rerun-if-changed=csrc/xsk_bridge.c");
}
