//! Standalone AF_XDP zero-copy rebind test.
//!
//! Loads its own XDP program (no xpfd dependency), creates XSK sockets,
//! receives packets, does link DOWN/UP, rebinds, and checks receive again.
//!
//! Build the XDP object first:
//!   clang -O2 -g -target bpf -c xdp_pass_redirect.c -o xdp_pass_redirect.o
//!
//! Usage:
//!   xsk-rebind-test <interface> <queue>
//!
//! Must run as root. Sends traffic to itself via raw socket.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

const FRAME_SIZE: u32 = 4096;
const FRAME_COUNT: u32 = 4096;
const HEADROOM: u32 = 256;
const XDP_OBJ: &[u8] = include_bytes!("xdp_pass_redirect.o");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <interface> <queue> [--copy]", args[0]);
        eprintln!("  Must run as root. Loads its own XDP program.");
        std::process::exit(1);
    }
    let iface = &args[1];
    let queue: u32 = args[2].parse().expect("queue must be u32");
    let use_copy = args.get(3).map_or(false, |a| a == "--copy");
    let mode_str = if use_copy { "COPY" } else { "ZERO-COPY" };

    let ifindex = if_nametoindex(iface);
    assert!(ifindex > 0, "interface not found");

    // Load XDP program
    eprintln!("=== Loading standalone XDP program on {} (ifindex {}) ===", iface, ifindex);
    let (prog_fd, map_fd) = load_xdp_prog();
    eprintln!("  prog_fd={} xsk_map_fd={}", prog_fd, map_fd);

    // Attach XDP
    attach_xdp(ifindex, prog_fd);
    eprintln!("  XDP attached");

    // Start background traffic generator (sends UDP to self)
    let traffic_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let traffic_handle = {
        let stop = traffic_stop.clone();
        let iface_owned = iface.to_string();
        std::thread::spawn(move || generate_traffic(&iface_owned, stop))
    };

    eprintln!("\n=== Phase 1: Initial bind ({}) on {} queue {} ===", mode_str, iface, queue);
    let rx1 = run_xsk_phase(iface, queue, map_fd, use_copy, Duration::from_secs(3));
    eprintln!("Phase 1 rx: {}", rx1);

    eprintln!("\n=== Link DOWN/UP on {} ===", iface);
    eprintln!("  ip link set {} down", iface);
    std::process::Command::new("ip").args(["link", "set", iface, "down"]).status().ok();
    std::thread::sleep(Duration::from_millis(200));
    eprintln!("  ip link set {} up", iface);
    std::process::Command::new("ip").args(["link", "set", iface, "up"]).status().ok();
    eprintln!("  waiting 500ms for NIC reinit...");
    std::thread::sleep(Duration::from_millis(500));

    // XDP program survives link cycle (it's attached to the netdev)
    eprintln!("\n=== Phase 2: Rebind ({}) on {} queue {} ===", mode_str, iface, queue);
    let rx2 = run_xsk_phase(iface, queue, map_fd, use_copy, Duration::from_secs(3));
    eprintln!("Phase 2 rx: {}", rx2);

    // Stop traffic
    traffic_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = traffic_handle.join();

    // Detach XDP
    detach_xdp(ifindex);
    eprintln!("  XDP detached");

    unsafe { libc::close(prog_fd) };
    unsafe { libc::close(map_fd) };

    eprintln!();
    if rx1 > 0 && rx2 > 0 {
        eprintln!("RESULT: PASS  phase1_rx={} phase2_rx={}", rx1, rx2);
    } else if rx1 > 0 && rx2 == 0 {
        eprintln!("RESULT: FAIL  (broken after link cycle)  phase1_rx={} phase2_rx=0", rx1);
    } else if rx1 == 0 {
        eprintln!("RESULT: FAIL  (no rx even on initial bind)  phase1_rx=0 phase2_rx={}", rx2);
    } else {
        eprintln!("RESULT: UNEXPECTED  phase1_rx={} phase2_rx={}", rx1, rx2);
    }
    std::process::exit(if rx1 > 0 && rx2 > 0 { 0 } else { 1 });
}

fn run_xsk_phase(iface: &str, queue: u32, xsk_map_fd: i32, use_copy: bool, duration: Duration) -> u64 {
    let area_size = (FRAME_COUNT as usize) * (FRAME_SIZE as usize);
    let area_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(), area_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0,
        )
    };
    assert_ne!(area_ptr, libc::MAP_FAILED, "mmap failed");
    let area_slice = NonNull::from(unsafe {
        &mut *std::ptr::slice_from_raw_parts_mut(area_ptr.cast::<u8>(), area_size)
    });

    let cfg = UmemConfig {
        fill_size: FRAME_COUNT,
        complete_size: FRAME_COUNT,
        frame_size: FRAME_SIZE,
        headroom: HEADROOM,
        flags: 0,
    };
    let umem = unsafe { Umem::new(cfg, area_slice) }.expect("create umem");

    let mut info = IfInfo::invalid();
    info.from_ifindex(if_nametoindex(iface)).expect("ifindex lookup");
    info.set_queue(queue);

    let sock = Socket::with_shared(&info, &umem).expect("create socket");
    let mut device = umem.fq_cq(&sock).expect("create fq/cq");

    let mut offsets = Vec::with_capacity(FRAME_COUNT as usize);
    for idx in 0..FRAME_COUNT {
        if let Some(frame) = umem.frame(BufIdx(idx)) {
            offsets.push(frame.offset);
        }
    }

    // Prime fill ring BEFORE bind
    {
        let mut fill = device.fill(offsets.len() as u32);
        let inserted = fill.insert(offsets.iter().copied());
        fill.commit();
        eprintln!("  fill ring primed: {}/{}", inserted, offsets.len());
    }

    let bind_flags = if use_copy {
        SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_COPY
    } else {
        SocketConfig::XDP_BIND_NEED_WAKEUP | SocketConfig::XDP_BIND_ZEROCOPY
    };
    let sock_cfg = SocketConfig {
        rx_size: std::num::NonZeroU32::new(FRAME_COUNT),
        tx_size: std::num::NonZeroU32::new(256),
        bind_flags,
    };
    let user = umem.rx_tx(&sock, &sock_cfg).expect("bind rx/tx");
    let mut rx = user.map_rx().expect("map rx ring");
    let user_fd = user.as_raw_fd();
    let mode = if use_copy { "copy" } else { "zero-copy" };
    eprintln!("  bound fd={} {}", user_fd, mode);

    // Register in xskmap
    xskmap_update(xsk_map_fd, queue, user_fd as u32);
    eprintln!("  xskmap[{}] = fd {}", queue, user_fd);

    // Trigger NAPI
    for _ in 0..20 {
        let fd = device.as_raw_fd();
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        unsafe { libc::poll(&mut pfd, 1, 1) };
        unsafe { libc::sendto(fd, std::ptr::null(), 0, libc::MSG_DONTWAIT, std::ptr::null(), 0) };
        std::thread::yield_now();
    }

    // Receive loop
    let start = Instant::now();
    let mut total_rx = 0u64;
    let mut poll_count = 0u64;
    while start.elapsed() < duration {
        let available = rx.available();
        if available > 0 {
            let mut recv = rx.receive(available);
            while recv.read().is_some() {
                total_rx += 1;
            }
            let needed = available.min(offsets.len() as u32);
            let mut fill = device.fill(needed);
            fill.insert(offsets.iter().take(needed as usize).copied());
            fill.commit();
        } else {
            poll_count += 1;
            let fd = device.as_raw_fd();
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut pfd, 1, 10) };
        }
    }
    eprintln!("  rx={} empty_polls={}", total_rx, poll_count);

    // Cleanup
    xskmap_delete(xsk_map_fd, queue);
    unsafe { libc::munmap(area_ptr, area_size) };
    total_rx
}

fn generate_traffic(iface: &str, stop: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    // Send UDP packets to the interface's own IP to generate RX traffic.
    // The XDP program intercepts them before they reach the kernel stack.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 { return; }
    let cname = CString::new(iface).unwrap();
    unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, cname.as_ptr() as _, iface.len() as u32 + 1) };
    // Get interface IP
    let ip = get_interface_ip(iface).unwrap_or([10, 0, 61, 1]);
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = 9999u16.to_be();
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip);

    let payload = b"xsk-test-probe";
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        unsafe {
            libc::sendto(fd, payload.as_ptr() as _, payload.len(), libc::MSG_DONTWAIT,
                &sa as *const libc::sockaddr_in as _, std::mem::size_of::<libc::sockaddr_in>() as u32);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    unsafe { libc::close(fd) };
}

fn get_interface_ip(iface: &str) -> Option<[u8; 4]> {
    let output = std::process::Command::new("ip")
        .args(["-4", "-o", "addr", "show", iface])
        .output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "inet X.X.X.X/N" from output
    for word in text.split_whitespace() {
        if word.contains('.') && word.contains('/') {
            let ip_str = word.split('/').next()?;
            let parts: Vec<u8> = ip_str.split('.').filter_map(|p| p.parse().ok()).collect();
            if parts.len() == 4 {
                return Some([parts[0], parts[1], parts[2], parts[3]]);
            }
        }
    }
    None
}

// --- BPF helpers ---

fn load_xdp_prog() -> (i32, i32) {
    // Write XDP object to temp file
    let obj_path = "/tmp/xdp_pass_redirect.o";
    std::fs::write(obj_path, XDP_OBJ).expect("write XDP obj");

    // Use libbpf to load
    let cpath = CString::new(obj_path).unwrap();

    // Open object
    let obj = unsafe { libbpf_sys::bpf_object__open(cpath.as_ptr()) };
    assert!(!obj.is_null(), "bpf_object__open failed");

    // Load programs
    let rc = unsafe { libbpf_sys::bpf_object__load(obj) };
    assert_eq!(rc, 0, "bpf_object__load failed: {}", io::Error::last_os_error());

    // Find program
    let prog_name = CString::new("xdp_redirect_xsk").unwrap();
    let prog = unsafe { libbpf_sys::bpf_object__find_program_by_name(obj, prog_name.as_ptr()) };
    assert!(!prog.is_null(), "program not found");
    let prog_fd = unsafe { libbpf_sys::bpf_program__fd(prog) };
    assert!(prog_fd >= 0, "program fd invalid");

    // Find map
    let map_name = CString::new("xsk_map").unwrap();
    let map = unsafe { libbpf_sys::bpf_object__find_map_by_name(obj, map_name.as_ptr()) };
    assert!(!map.is_null(), "map not found");
    let map_fd = unsafe { libbpf_sys::bpf_map__fd(map) };
    assert!(map_fd >= 0, "map fd invalid");

    // Don't close obj — keep fds alive
    // Leak intentionally: the fds must survive until we detach
    (prog_fd, map_fd)
}

fn attach_xdp(ifindex: u32, prog_fd: i32) {
    let rc = unsafe { libbpf_sys::bpf_xdp_attach(ifindex as i32, prog_fd, 0, std::ptr::null()) };
    assert_eq!(rc, 0, "bpf_xdp_attach failed: {}", io::Error::last_os_error());
}

fn detach_xdp(ifindex: u32) {
    unsafe { libbpf_sys::bpf_xdp_attach(ifindex as i32, -1, 0, std::ptr::null()) };
}

fn xskmap_update(map_fd: i32, key: u32, value: u32) {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            &key as *const u32 as *const _,
            &value as *const u32 as *const _,
            0, // BPF_ANY
        )
    };
    if rc != 0 {
        eprintln!("  WARNING: xskmap_update failed: {}", io::Error::last_os_error());
    }
}

fn xskmap_delete(map_fd: i32, key: u32) {
    unsafe {
        libbpf_sys::bpf_map_delete_elem(
            map_fd,
            &key as *const u32 as *const _,
        );
    }
}

fn if_nametoindex(name: &str) -> u32 {
    let cname = CString::new(name).unwrap();
    unsafe { libc::if_nametoindex(cname.as_ptr()) }
}
