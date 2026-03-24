fn main() {
    // Compile the C bridge that wraps libxdp's inline xsk helpers.
    cc::Build::new()
        .file("csrc/xsk_bridge.c")
        .include("/usr/include")
        .warnings(true)
        .flag("-Wno-unused-parameter")
        .opt_level(2)
        .compile("xsk_bridge");

    // Link libxdp (provides xsk_umem__create, xsk_socket__create_shared, etc.)
    // and libbpf (dependency of libxdp).
    println!("cargo:rustc-link-lib=xdp");
    println!("cargo:rustc-link-lib=bpf");
    println!("cargo:rerun-if-changed=csrc/xsk_bridge.c");
}
