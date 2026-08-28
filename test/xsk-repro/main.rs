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
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use xdpilone::{BufIdx, IfInfo, Socket, SocketConfig, Umem, UmemConfig};

const FRAME_SIZE: u32 = 4096;
const FRAME_COUNT: u32 = 4096;
const HEADROOM: u32 = 256;
const XDP_OBJ: &[u8] = include_bytes!("xdp_pass_redirect.o");

/// #6898 A10-b5-F1: the marker that identifies a frame as OUR generated probe.
///
/// ONE definition, used by both the generator and the receive filter. Two
/// copies of a literal is how the two sides drift, and a drifted marker fails
/// in the direction that matters here — every frame reads as foreign, rx goes
/// to zero, and the tool reports FAIL on a healthy rebind.
const PROBE_MARKER: &[u8] = b"xsk-test-probe";

/// Does this received frame carry our probe marker?
///
/// WHY THIS EXISTS. The XDP program redirects EVERY packet on the queue to the
/// XSK — `xdp_pass_redirect.c` looks the queue up in the xskmap and redirects
/// unconditionally, with no filter. So the receive counters counted ALL traffic
/// on the interface, not the traffic this tool generated.
///
/// That made the PASS criterion unable to detect the bug the tool exists to
/// detect. `rx2 > 0` was satisfied by any background frame — an ARP, an IPv6
/// RA or MLD report, a stray broadcast — so a rebind that was completely broken
/// still reported PASS as long as the link carried any chatter at all. On a
/// live interface IPv6 multicast alone is usually enough.
///
/// A substring scan rather than a parse at fixed offsets: the frame is
/// Ethernet + IP + UDP + payload and the header sizes vary (VLAN tags, IPv4
/// options, v4 vs v6), so a fixed offset would silently stop matching on a
/// tagged or optioned link and reintroduce the false FAIL. Cost is irrelevant
/// — this is a repro tool, not a dataplane.
fn is_probe_frame(frame: &[u8]) -> bool {
    frame
        .windows(PROBE_MARKER.len())
        .any(|w| w == PROBE_MARKER)
}

// UAPI XDP attach flags (linux/if_link.h).
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
const XDP_FLAGS_REPLACE: u32 = 1 << 4;

/// #4906 HC-101: RAII guard around the XDP attach so the program is (a) never
/// attached over an existing one and (b) always detached — but only if it is
/// still ours — even if a later step panics. The previous code attached with
/// flags=0 (silently replacing whatever was on the interface, e.g. the firewall
/// dataplane) and detached to prog=-1 unconditionally; a panic after attach also
/// skipped the manual detach entirely, potentially stripping the NIC of its XDP
/// program.
struct XdpAttachment {
    ifindex: i32,
    prog_fd: i32,
}

impl XdpAttachment {
    fn attach(ifindex: u32, prog_fd: i32) -> io::Result<Self> {
        // UPDATE_IF_NOEXIST => -EBUSY if a program is already attached, so we
        // never clobber the firewall's redirect program.
        let rc = unsafe {
            libbpf_sys::bpf_xdp_attach(
                ifindex as i32,
                prog_fd,
                XDP_FLAGS_UPDATE_IF_NOEXIST,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(-rc));
        }
        Ok(XdpAttachment { ifindex: ifindex as i32, prog_fd })
    }
}

impl Drop for XdpAttachment {
    fn drop(&mut self) {
        // XDP_FLAGS_REPLACE + old_prog_fd => the kernel only detaches if the
        // hook still holds OUR program; if something else took it over, the
        // detach is refused and their program is left intact.
        let mut opts: libbpf_sys::bpf_xdp_attach_opts = unsafe { std::mem::zeroed() };
        opts.sz = std::mem::size_of::<libbpf_sys::bpf_xdp_attach_opts>() as _;
        opts.old_prog_fd = self.prog_fd;
        let rc = unsafe {
            libbpf_sys::bpf_xdp_detach(self.ifindex, XDP_FLAGS_REPLACE, &opts)
        };
        if rc != 0 {
            eprintln!(
                "  XDP detach skipped/failed ({}) — hook not ours anymore",
                io::Error::from_raw_os_error(-rc)
            );
        } else {
            eprintln!("  XDP detached");
        }
    }
}

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

    // Attach XDP (RAII: refuses to replace an existing program; detaches — only
    // if still ours — on drop, including on panic unwind). #4906 HC-101.
    let xdp = match XdpAttachment::attach(ifindex, prog_fd) {
        Ok(x) => x,
        Err(e) => {
            if e.raw_os_error() == Some(libc::EBUSY) {
                eprintln!(
                    "  interface already has an XDP program; refusing to replace \
                     it (would clobber the firewall dataplane). Detach it first \
                     if this is intended."
                );
            } else {
                eprintln!("  bpf_xdp_attach failed: {}", e);
            }
            unsafe { libc::close(prog_fd) };
            unsafe { libc::close(map_fd) };
            std::process::exit(1);
        }
    };
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

    // #4906 HC-090: only run the rebind phase if the link actually cycled. The
    // previous code ignored `ip link` failures (missing binary, no capability,
    // interface refusal) and proceeded to phase 2 regardless — turning a no-op
    // into a misleading PASS/FAIL. Command::new does not use a shell, so the
    // interface name is never interpreted; here we additionally check status.
    eprintln!("\n=== Link DOWN/UP on {} ===", iface);
    eprintln!("  ip link set {} down", iface);
    let down_ok = std::process::Command::new("ip")
        .args(["link", "set", iface, "down"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let link_cycled = if down_ok {
        std::thread::sleep(Duration::from_millis(200));
        eprintln!("  ip link set {} up", iface);
        std::process::Command::new("ip")
            .args(["link", "set", iface, "up"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        false
    };

    let mut rx2 = 0u64;
    if link_cycled {
        eprintln!("  waiting 500ms for NIC reinit...");
        std::thread::sleep(Duration::from_millis(500));
        // XDP program survives link cycle (it's attached to the netdev)
        eprintln!("\n=== Phase 2: Rebind ({}) on {} queue {} ===", mode_str, iface, queue);
        rx2 = run_xsk_phase(iface, queue, map_fd, use_copy, Duration::from_secs(3));
        eprintln!("Phase 2 rx: {}", rx2);
    } else {
        eprintln!(
            "Link DOWN/UP cycle did not complete — skipping phase 2 (rebind); \
             result is INCONCLUSIVE."
        );
    }

    // Stop traffic
    traffic_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = traffic_handle.join();

    // Detach XDP explicitly (drop runs the REPLACE-guarded detach) BEFORE we
    // close prog_fd — the detach's old_prog_fd check needs a valid fd — and
    // before process::exit, which would otherwise skip the Drop.
    drop(xdp);
    unsafe { libc::close(prog_fd) };
    unsafe { libc::close(map_fd) };

    eprintln!();
    let code = if !link_cycled {
        eprintln!("RESULT: INCONCLUSIVE  (link DOWN/UP did not run)  phase1_rx={}", rx1);
        2
    } else if rx1 > 0 && rx2 > 0 {
        eprintln!("RESULT: PASS  phase1_rx={} phase2_rx={}", rx1, rx2);
        0
    } else if rx1 > 0 && rx2 == 0 {
        eprintln!("RESULT: FAIL  (broken after link cycle)  phase1_rx={} phase2_rx=0", rx1);
        1
    } else if rx1 == 0 {
        eprintln!("RESULT: FAIL  (no rx even on initial bind)  phase1_rx=0 phase2_rx={}", rx2);
        1
    } else {
        eprintln!("RESULT: UNEXPECTED  phase1_rx={} phase2_rx={}", rx1, rx2);
        1
    };
    std::process::exit(code);
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

    // #4906 HC-091: keep every xdpilone owner (umem / socket / device / rx /
    // user) inside this block so they are all dropped BEFORE we munmap the
    // backing memory below. The previous code munmap'd `area_ptr` while these
    // owners were still in scope, so their Drop ran against memory that had
    // already been unmapped (teardown fault / race).
    let total_rx = {
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
        let mut foreign_rx = 0u64;
        let mut poll_count = 0u64;
        while start.elapsed() < duration {
            let available = rx.available();
            if available > 0 {
                // #4906 HC-069: capture the address of every descriptor we
                // actually consume, then release the RX reads and hand exactly
                // those frames (chunk-aligned base) back to the fill ring.
                //
                // The previous loop (a) never called recv.release(), so the
                // #[must_use] ReadRx cancelled the peek on Drop and the same
                // descriptors were re-read every iteration — inflating total_rx
                // — and (b) re-inserted the first `needed` ORIGINAL offsets
                // regardless of what was consumed, double-owning frames on the
                // fill ring.
                let mut recv = rx.receive(available);
                let mut recycle: Vec<u64> = Vec::with_capacity(recv.capacity() as usize);
                while let Some(desc) = recv.read() {
                    // #6898 A10-b5-F1: count only OUR probes. Counting every
                    // redirected frame made PASS satisfiable by unrelated
                    // interface traffic, so the tool could not see the failure
                    // it exists to find. Foreign frames are still counted, and
                    // reported, because "rx=0 but 5000 foreign frames seen" and
                    // "rx=0 and the link is silent" are different diagnoses and
                    // the operator needs to tell them apart.
                    let end = (desc.addr as usize).saturating_add(desc.len as usize);
                    let is_ours = if end <= area_size {
                        let bytes = unsafe {
                            std::slice::from_raw_parts(
                                area_ptr.cast::<u8>().add(desc.addr as usize),
                                desc.len as usize,
                            )
                        };
                        is_probe_frame(bytes)
                    } else {
                        false
                    };
                    if is_ours {
                        total_rx += 1;
                    } else {
                        foreign_rx += 1;
                    }
                    recycle.push(desc.addr & !((FRAME_SIZE as u64) - 1));
                }
                recv.release();
                drop(recv);
                if !recycle.is_empty() {
                    let mut fill = device.fill(recycle.len() as u32);
                    fill.insert(recycle.iter().copied());
                    fill.commit();
                }
            } else {
                poll_count += 1;
                let fd = device.as_raw_fd();
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                unsafe { libc::poll(&mut pfd, 1, 10) };
            }
        }
        eprintln!(
            "  rx={} (probe frames)  foreign_rx={} (other traffic on this queue)  empty_polls={}",
            total_rx, foreign_rx, poll_count
        );

        // Deregister before the sockets/umem drop at the end of this block.
        xskmap_delete(xsk_map_fd, queue);
        total_rx
    };

    // Safe now: all UMEM/socket owners have been dropped above.
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

    let payload = PROBE_MARKER;
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
    // #4906 HC-025: load the object straight from the compiled-in bytes with
    // bpf_object__open_mem instead of writing/reading a predictable
    // /tmp/xdp_pass_redirect.o. The old code did `std::fs::write("/tmp/...")`
    // as root, which a pre-planted symlink could redirect to clobber an
    // arbitrary file, and then loaded from that world-writable-namespace path.
    // Loading from memory removes the filesystem path entirely (no symlink /
    // TOCTOU window, no chance of loading a substituted object).
    let obj = unsafe {
        libbpf_sys::bpf_object__open_mem(
            XDP_OBJ.as_ptr() as *const _,
            XDP_OBJ.len() as u64,
            std::ptr::null(),
        )
    };
    assert!(!obj.is_null(), "bpf_object__open_mem failed");

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic redirected frame: Ethernet + IPv4 + UDP + payload. The
    /// marker sits at an OFFSET, which is the whole reason the matcher scans
    /// rather than reading a fixed position.
    fn framed(payload: &[u8], vlan_tagged: bool) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        if vlan_tagged {
            // 802.1Q pushes every later header 4 bytes along — the case a
            // fixed-offset parse silently stops matching on.
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        }
        f.extend_from_slice(&[0u8; 20]); // IPv4 header
        f.extend_from_slice(&[0u8; 8]); // UDP header
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn probe_frame_is_recognised_at_any_offset() {
        assert!(is_probe_frame(&framed(PROBE_MARKER, false)));
        assert!(
            is_probe_frame(&framed(PROBE_MARKER, true)),
            "a VLAN tag shifts every header; a fixed-offset match would stop seeing our own \
             probes on a tagged link and report FAIL on a healthy rebind"
        );
    }

    /// THE CELL THIS FIX EXISTS FOR.
    ///
    /// The XDP program redirects every packet on the queue with no filter, so
    /// before #6898 the receive counters counted background traffic. `rx > 0`
    /// was therefore satisfiable by an ARP or an IPv6 RA while the tool's own
    /// probes were not arriving at all — which is the exact failure the
    /// reproducer exists to detect, reported as PASS.
    #[test]
    fn foreign_traffic_is_not_counted_as_a_probe() {
        // An IPv6 router advertisement is the realistic case: essentially every
        // live link carries them, so this is not an exotic input.
        let ra = framed(b"\x86\x00\x00\x00 router advertisement", false);
        assert!(
            !is_probe_frame(&ra),
            "background interface traffic must not satisfy the PASS criterion — that is what \
             made the reproducer unable to detect a broken rebind"
        );
        assert!(!is_probe_frame(&framed(b"", false)));
        assert!(!is_probe_frame(b"arp who-has"));
    }

    #[test]
    fn short_frames_do_not_panic() {
        // `windows(n)` on a slice shorter than n yields nothing — but a runt
        // frame reaching the matcher is a real possibility on a live queue, and
        // a panic here would take down the tool mid-run.
        for len in 0..PROBE_MARKER.len() {
            assert!(!is_probe_frame(&vec![0u8; len]));
        }
    }

    /// The generator and the matcher must use ONE marker definition.
    ///
    /// A duplicated literal drifts, and it drifts in the direction that hides
    /// the fix: every frame reads as foreign, rx falls to zero, and the tool
    /// reports FAIL on a healthy rebind — a false alarm that looks exactly like
    /// the defect it is supposed to find.
    #[test]
    fn generator_and_matcher_share_one_marker() {
        assert!(
            is_probe_frame(&framed(PROBE_MARKER, false)),
            "the marker the generator sends must be the marker the receiver matches"
        );
    }
}
