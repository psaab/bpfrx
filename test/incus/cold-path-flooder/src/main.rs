// #1607 / #1611 cold-path-flooder — runner body
//
// Generates UDP traffic with randomized source IPs, source ports,
// and (optionally) destination ports against the loss userspace
// cluster firewall. AF_PACKET SOCK_RAW + sendmmsg(batch=32) with
// PACKET_QDISC_BYPASS for sustained ≥2.5 Mpps single-core on
// virtio-VM hosts (per #1611 plan v4 §4.5 + AGY r1 finding 2).
//
// Two regimes:
//   * `--cohort=unbounded` (DEFAULT, AGY r3 axis 1): sweeps /16
//     src-IP × full 16-bit src-port = ~4.3 B unique 5-tuples.
//     Session table fills in ~26 ms; remaining ~99.9% measures
//     the pure policy-eval cold path
//     (cache_miss → policy_eval → install_rejected_fast_return),
//     cross-worker replicate bypassed.
//   * `--cohort=bounded` (DIAGNOSTIC opt-in): fits the session
//     table (DEFAULT_MAX_SESSIONS = 131_072). Every cold-path
//     sample measures real session miss → install → replicate.
//
// True 64 B Ethernet frames: 14 (Eth) + 20 (IPv4) + 8 (UDP) +
// 22 (payload) = 64.
//
// Per #1611 plan v4 the runner runs on `loss:cluster-userspace-host`
// (LAN-side neighbour) and the AF_PACKET TX traffic arrives at the
// firewall's AF_XDP RX socket via normal Ethernet — AF_PACKET TX
// and AF_XDP RX live on independent kernel paths on the two ends.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
#[cfg(test)]
use std::fs;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::raw::c_void;
use std::time::{Duration, Instant};

const MIN_ETH_FRAME: usize = 64;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_WARMUP_SECS: u64 = 2;
const DEFAULT_BATCH: usize = 32;
// Bounded-mode constants — see step-1 #1613 commit msg + plan v2-r4 §4.2.0.
const BOUNDED_SRC_IP_SPAN: u32 = 16_384; // 14 bits
const BOUNDED_SRC_PORT_SPAN: u32 = 8; // 3 bits
const BOUNDED_DST_PORT_SPAN: u32 = 1;
// Unbounded mode defaults — sweeps a full /16 + full 16-bit source-port
// space. 65_536 × 65_536 × 1 = 4_294_967_296 unique 5-tuples.
const DEFAULT_SRC_IP_SPAN: u32 = 65_536;
// Reserved-port-0 avoidance: per #1611 plan §4 + AGY r3 step-2 minor 2,
// userspace-dp/src/afxdp/frame/inspect.rs:207 short-circuits TCP/UDP
// flows with src_port==0 onto a different code path, which would skew
// the cold-path histogram. Default src-port base = 1024 (start of
// ephemeral range). `--src-port-base 0` is permitted opt-in.
const DEFAULT_SRC_PORT_BASE: u16 = 1024;
// Default src-port span = 65_536 - DEFAULT_SRC_PORT_BASE = 64_512. This
// is the largest span that, combined with the default base, keeps every
// generated port in [1024, 65_536) — guaranteed > 0, no u16 wrap. When
// the operator passes `--src-port-base 0` explicitly, they can also pass
// `--src-port-span 65536` to get the full /16. The validator rejects
// base + span > 65_536 either way.
const DEFAULT_SRC_PORT_SPAN: u32 = 64_512;
const DEFAULT_DST_PORT_SPAN: u32 = 1;
const DEFAULT_DST_PORT_BASE: u16 = 5201;

// Frame layout constants — plan v4 §4 frame assembly.
const ETH_HDR: usize = 14;
const IPV4_HDR: usize = 20;
const UDP_HDR: usize = 8;
const UDP_PAYLOAD: usize = 22; // "XPF-COLD-PATH-MIN64\n\0\0"
const FRAME_V4_TOTAL: usize = ETH_HDR + IPV4_HDR + UDP_HDR + UDP_PAYLOAD;
const IPV4_TOTAL_LEN: u16 = (IPV4_HDR + UDP_HDR + UDP_PAYLOAD) as u16; // 50
const UDP_LEN: u16 = (UDP_HDR + UDP_PAYLOAD) as u16; // 30

// Compile-time wire-byte invariants — plan v4 §4 + hidden-invariants §2.
const _: () = assert!(FRAME_V4_TOTAL == 64);
const _: () = assert!(IPV4_TOTAL_LEN == 50);
const _: () = assert!(UDP_LEN == 30);
// Bounded cohort exactly fits DEFAULT_MAX_SESSIONS.
const _: () = assert!(
    BOUNDED_SRC_IP_SPAN as usize
        * BOUNDED_SRC_PORT_SPAN as usize
        * BOUNDED_DST_PORT_SPAN as usize
        == 131_072
);

// PACKET_QDISC_BYPASS constant — not exposed by every libc version,
// so define locally. Value 20 from include/uapi/linux/if_packet.h.
const PACKET_QDISC_BYPASS_OPT: libc::c_int = 20;

// Magic payload to make the 22-byte UDP payload easy to spot in
// pcap. Plan v4 §4 frame assembly.
const PAYLOAD_MAGIC: [u8; UDP_PAYLOAD] = *b"XPF-COLD-PATH-MIN64\n\0\0";

#[derive(Debug, Clone)]
struct Args {
    iface: String,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    dst_port_base: u16,
    dst_port_span: u32,
    src_ip_base: u32,
    src_ip_span: u32,
    src_port_base: u16,
    src_port_span: u32,
    duration: Duration,
    warmup: Duration,
    frame_bytes: usize,
    batch: usize,
    seed: u64,
    cohort_unbounded: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut args = Args {
            iface: "ge-0-0-1".to_string(),
            dst_mac: [0xff; 6],
            src_mac: [0; 6],
            dst_ip: Ipv4Addr::new(172, 16, 80, 200),
            dst_port_base: DEFAULT_DST_PORT_BASE,
            dst_port_span: DEFAULT_DST_PORT_SPAN,
            src_ip_base: u32::from_be_bytes([10, 42, 0, 0]),
            src_ip_span: DEFAULT_SRC_IP_SPAN,
            src_port_base: DEFAULT_SRC_PORT_BASE,
            src_port_span: DEFAULT_SRC_PORT_SPAN,
            duration: Duration::from_secs(DEFAULT_DURATION_SECS),
            warmup: Duration::from_secs(DEFAULT_WARMUP_SECS),
            frame_bytes: MIN_ETH_FRAME,
            batch: DEFAULT_BATCH,
            seed: 0,
            cohort_unbounded: true,
        };
        // Track explicit overrides so --cohort=bounded knows whether to narrow.
        let mut user_set_src_ip_span = false;
        let mut user_set_src_port_span = false;
        let mut user_set_dst_port_span = false;

        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let next = || argv.get(i + 1).cloned().ok_or(format!("{} needs value", arg));
            match arg.as_str() {
                "--iface" => {
                    args.iface = next()?;
                    i += 2;
                }
                "--dst-ip" => {
                    args.dst_ip = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    i += 2;
                }
                "--dst-port-base" => {
                    args.dst_port_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-port-span" => {
                    args.dst_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_dst_port_span = true;
                    i += 2;
                }
                "--src-ip-base" => {
                    let ip: Ipv4Addr = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    args.src_ip_base = u32::from(ip);
                    i += 2;
                }
                "--src-ip-span" => {
                    args.src_ip_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_ip_span = true;
                    i += 2;
                }
                "--src-port-base" => {
                    args.src_port_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--src-port-span" => {
                    args.src_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_port_span = true;
                    i += 2;
                }
                "--duration-secs" => {
                    args.duration =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--warmup-secs" => {
                    args.warmup =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--frame-bytes" => {
                    args.frame_bytes = next()?.parse().map_err(|e| format!("{e}"))?;
                    if args.frame_bytes < MIN_ETH_FRAME {
                        return Err(format!(
                            "frame-bytes {} < MIN_ETH_FRAME {}",
                            args.frame_bytes, MIN_ETH_FRAME
                        ));
                    }
                    // For now the runner only emits 64-byte frames.
                    // Larger frames would need payload padding; defer.
                    if args.frame_bytes != MIN_ETH_FRAME {
                        return Err(format!(
                            "--frame-bytes {} not yet supported; \
                             this runner emits exactly 64-byte frames \
                             (follow-up issue tracks variable-size frames)",
                            args.frame_bytes
                        ));
                    }
                    i += 2;
                }
                "--batch" => {
                    args.batch = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--seed" => {
                    args.seed = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-mac" => {
                    args.dst_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--src-mac" => {
                    args.src_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--cohort" => {
                    let v = next()?;
                    match v.as_str() {
                        "bounded" => args.cohort_unbounded = false,
                        "unbounded" => args.cohort_unbounded = true,
                        _ => return Err(format!("bad --cohort {v}; use bounded|unbounded")),
                    }
                    i += 2;
                }
                "-h" | "--help" => {
                    eprintln!("{}", help());
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        // Default is unbounded (AGY r3 axis 1). Narrow when --cohort=bounded.
        if !args.cohort_unbounded {
            if !user_set_src_ip_span {
                args.src_ip_span = BOUNDED_SRC_IP_SPAN;
            }
            if !user_set_src_port_span {
                args.src_port_span = BOUNDED_SRC_PORT_SPAN;
            }
            if !user_set_dst_port_span {
                args.dst_port_span = BOUNDED_DST_PORT_SPAN;
            }
            // Cohort multiplier u128 to avoid u64 overflow at 3×u32::MAX.
            let cohort = args.src_ip_span as u128
                * args.src_port_span as u128
                * args.dst_port_span as u128;
            if cohort > 131_072 {
                return Err(format!(
                    "bounded cohort {} > DEFAULT_MAX_SESSIONS 131072; \
                     either narrow the spans or omit --cohort bounded \
                     (default is unbounded)",
                    cohort
                ));
            }
        }

        validate_args(&args)?;

        if args.seed == 0 {
            // SAFETY: getpid/clock_gettime are always available on Linux.
            let pid = unsafe { libc::getpid() } as u64;
            let mut ts: libc::timespec = unsafe { zeroed() };
            unsafe {
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            }
            args.seed = pid
                .wrapping_mul(0x9E3779B97F4A7C15)
                ^ (ts.tv_nsec as u64).wrapping_mul(0xBF58476D1CE4E5B9);
            if args.seed == 0 {
                args.seed = 1;
            }
        }

        Ok(args)
    }
}

/// Centralized arg-validation. Pulled out so unit tests can hit
/// every branch without spoofing argv.
fn validate_args(a: &Args) -> Result<(), String> {
    if a.src_ip_span == 0 {
        return Err("--src-ip-span must be >= 1".to_string());
    }
    if a.src_port_span == 0 {
        return Err("--src-port-span must be >= 1".to_string());
    }
    if a.dst_port_span == 0 {
        return Err("--dst-port-span must be >= 1".to_string());
    }
    if a.batch == 0 {
        return Err("--batch must be >= 1".to_string());
    }
    if a.batch > 1024 {
        return Err(format!(
            "--batch {} > 1024 (UIO_MAXIOV); keep batch <= 1024",
            a.batch
        ));
    }
    // AGY r3 step-2 minor 1: dst_port_base + dst_port_span <= 65536.
    if a.dst_port_base as u32 + a.dst_port_span > 65_536 {
        return Err(format!(
            "--dst-port-base {} + --dst-port-span {} > 65536; \
             generated dst port would silently u16-wrap into reserved \
             range. Narrow the span or lower the base.",
            a.dst_port_base, a.dst_port_span
        ));
    }
    // Same overflow guard for src ports.
    if a.src_port_base as u32 + a.src_port_span > 65_536 {
        return Err(format!(
            "--src-port-base {} + --src-port-span {} > 65536; \
             generated src port would silently u16-wrap. Narrow the \
             span or lower the base.",
            a.src_port_base, a.src_port_span
        ));
    }
    Ok(())
}

fn help() -> &'static str {
    "cold-path-flooder — #1607/#1611 cold-path measurement helper

USAGE:
  cold-path-flooder [OPTIONS]

OPTIONS:
  --iface NAME            (default ge-0-0-1)
  --dst-ip IP             (default 172.16.80.200)
  --dst-mac MAC           (required; no ARP-resolve in this runner)
  --src-mac MAC           (default auto-resolved from iface via SIOCGIFHWADDR)
  --dst-port-base N       (default 5201; iperf-a class)
  --dst-port-span N       (default 1)
  --src-ip-base IP        (default 10.42.0.0)
  --src-ip-span N         (default 65536; bounded: 16384)
  --src-port-base N       (default 1024; --src-port-base 0 opts into reserved-port-0 sweep)
  --src-port-span N       (default 64512 = 65536-base; bounded: 8)
  --duration-secs N       (default 30)
  --warmup-secs N         (default 2)
  --frame-bytes N         (default 64; only 64 supported in this runner)
  --batch N               (sendmmsg batch; default 32; min 1 max 1024)
  --seed N                (default: pid XOR clock)
  --cohort bounded|unbounded   (default unbounded)
"
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad MAC {s}"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|e| format!("{e}"))?;
    }
    Ok(out)
}

/// 64-bit xorshift PRNG. Maximum-period (2^64 - 1).
#[derive(Clone, Copy)]
struct Xorshift64(u64);

impl Xorshift64 {
    #[inline(always)]
    fn next(&mut self) -> u64 {
        let mut s = self.0;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.0 = s;
        s
    }
}

/// One transmit slot — a 64-byte frame + the iovec/msghdr that points at it.
/// `#[repr(align(64))]` per AGY r1 finding D — cache-line aligned for the
/// kernel copy path on the sendmmsg fast path.
#[repr(align(64))]
struct TxSlot {
    frame: [u8; FRAME_V4_TOTAL],
}

impl TxSlot {
    fn new() -> Self {
        TxSlot {
            frame: [0u8; FRAME_V4_TOTAL],
        }
    }

    /// Initialise the static parts of the frame (dst MAC, src MAC, ethertype,
    /// IPv4 fixed fields, UDP payload). Variable fields (src IP, src/dst port,
    /// IPv4 csum, IPv4 ID) are mutated per packet.
    fn init_static(&mut self, dst_mac: &[u8; 6], src_mac: &[u8; 6], dst_ip: Ipv4Addr) {
        // Eth header
        self.frame[0..6].copy_from_slice(dst_mac);
        self.frame[6..12].copy_from_slice(src_mac);
        self.frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

        // IPv4 header (will fill mutable fields per-packet)
        self.frame[14] = 0x45; // v=4, ihl=5
        self.frame[15] = 0x00; // tos
        self.frame[16..18].copy_from_slice(&IPV4_TOTAL_LEN.to_be_bytes()); // total_len = 50
        self.frame[18..20].copy_from_slice(&0u16.to_be_bytes()); // id (mutated)
        self.frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF, frag_off=0
        self.frame[22] = 64; // ttl
        self.frame[23] = 17; // proto = UDP
        self.frame[24..26].copy_from_slice(&0u16.to_be_bytes()); // csum (mutated)
        self.frame[26..30].copy_from_slice(&[0; 4]); // src ip (mutated)
        self.frame[30..34].copy_from_slice(&u32::from(dst_ip).to_be_bytes());

        // UDP header
        self.frame[34..36].copy_from_slice(&0u16.to_be_bytes()); // src port (mutated)
        self.frame[36..38].copy_from_slice(&0u16.to_be_bytes()); // dst port (mutated)
        self.frame[38..40].copy_from_slice(&UDP_LEN.to_be_bytes()); // len = 30
        self.frame[40..42].copy_from_slice(&0u16.to_be_bytes()); // csum = 0 per RFC 768

        // UDP payload — fixed magic.
        self.frame[42..64].copy_from_slice(&PAYLOAD_MAGIC);
    }

    /// Mutate per-packet fields: src IP, IPv4 ID, src port, dst port.
    /// Recompute the IPv4 header checksum.
    #[inline(always)]
    fn fill_packet(
        &mut self,
        src_ip: u32,
        ip_id: u16,
        src_port: u16,
        dst_port: u16,
    ) {
        // IPv4 ID
        self.frame[18..20].copy_from_slice(&ip_id.to_be_bytes());
        // IPv4 csum field zero before computing
        self.frame[24..26].copy_from_slice(&0u16.to_be_bytes());
        // IPv4 src
        self.frame[26..30].copy_from_slice(&src_ip.to_be_bytes());
        // UDP src/dst port
        self.frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        self.frame[36..38].copy_from_slice(&dst_port.to_be_bytes());

        // IPv4 header checksum (one's-complement, RFC 1071).
        let mut sum: u32 = 0;
        let hdr = &self.frame[14..34]; // 20 bytes
        for chunk in hdr.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = (!sum as u16).to_be_bytes();
        self.frame[24..26].copy_from_slice(&csum);
    }
}

/// Per-iteration runner state. `slots` and `iovecs` are stable-address heap
/// allocations sized once at startup; `msgs` references the iovecs by raw
/// pointer. Lifetime: all three live for the entire run; nothing is freed
/// or resized in the hot loop.
struct TxRing {
    slots: Vec<TxSlot>,
    iovecs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
    dst_sll: libc::sockaddr_ll,
}

impl TxRing {
    fn new(batch: usize, dst_mac: &[u8; 6], src_mac: &[u8; 6], dst_ip: Ipv4Addr,
           ifindex: i32) -> Self {
        let mut slots: Vec<TxSlot> = (0..batch).map(|_| TxSlot::new()).collect();
        for s in &mut slots {
            s.init_static(dst_mac, src_mac, dst_ip);
        }
        // Construct the sockaddr_ll once; sendmmsg per-msg msg_name points at it.
        // SAFETY: sockaddr_ll is a C-layout POD struct; zero-init is valid
        // before we populate sll_family / sll_protocol / sll_ifindex below.
        let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = ifindex;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(dst_mac);

        // Construct iovecs pointing at each frame.
        let iovecs: Vec<libc::iovec> = slots
            .iter_mut()
            .map(|s| libc::iovec {
                iov_base: s.frame.as_mut_ptr() as *mut c_void,
                iov_len: FRAME_V4_TOTAL,
            })
            .collect();

        TxRing {
            slots,
            iovecs,
            msgs: Vec::with_capacity(batch),
            dst_sll: sll,
        }
    }

    /// Wire the mmsghdr array. Called once after `new()` so the
    /// iovec / sockaddr pointers stay stable for the entire run.
    fn wire_msgs(&mut self) {
        let sll_ptr = (&self.dst_sll) as *const _ as *mut c_void;
        let sll_len = size_of::<libc::sockaddr_ll>() as u32;
        self.msgs.clear();
        for iov in &mut self.iovecs {
            // SAFETY: msghdr is a C-layout POD struct; zero-init is valid
            // before we populate msg_name / msg_iov below.
            let mut hdr: libc::msghdr = unsafe { zeroed() };
            hdr.msg_name = sll_ptr;
            hdr.msg_namelen = sll_len;
            hdr.msg_iov = iov as *mut libc::iovec;
            hdr.msg_iovlen = 1;
            self.msgs.push(libc::mmsghdr {
                msg_hdr: hdr,
                msg_len: 0,
            });
        }
    }
}

/// Resolve --iface to ifindex; fail loudly on 0 (not found).
/// Claude SMR r1 MINOR-3.
fn resolve_ifindex(iface: &str) -> Result<i32, String> {
    let c = CString::new(iface).map_err(|_| "iface name has nul byte".to_string())?;
    // SAFETY: if_nametoindex takes a NUL-terminated C string; CString
    // guarantees that. Return value 0 sentinel handled below.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        let errno = std::io::Error::last_os_error();
        return Err(format!(
            "interface '{}' not found — check `ip link show` ({})",
            iface, errno
        ));
    }
    Ok(idx as i32)
}

/// Verify the interface is IFF_UP via SIOCGIFFLAGS. AGY r1 finding C.
fn check_iface_up(fd: i32, iface: &str) -> Result<(), String> {
    // SAFETY: ifreq is a C-layout POD union; zero-init is the documented
    // pattern for SIOCGIFFLAGS calls (kernel writes ifr_ifru.ifru_flags).
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(format!("iface '{}' name >= IFNAMSIZ", iface));
    }
    for (i, b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    // SAFETY: ifreq is a kernel-defined union; SIOCGIFFLAGS fills
    // ifr_ifru.ifru_flags. We read it back below via a transmute that
    // is well-defined because libc::ifreq is repr(C).
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) };
    if ret < 0 {
        return Err(format!(
            "SIOCGIFFLAGS on '{}': {}",
            iface,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: SIOCGIFFLAGS is documented to write ifr_ifru.ifru_flags
    // (man 7 netdevice). We never read any other ifr_ifru variant.
    let flags = unsafe { ifr.ifr_ifru.ifru_flags };
    if (flags as u32 & libc::IFF_UP as u32) == 0 {
        return Err(format!(
            "interface '{}' is DOWN — run 'ip link set {} up' first",
            iface, iface
        ));
    }
    Ok(())
}

/// Read iface hwaddr metadata via SIOCGIFHWADDR.
fn read_iface_hwaddr(fd: i32, iface: &str) -> Result<(u16, [u8; 6]), String> {
    // SAFETY: ifreq is a C-layout POD union; zero-init before SIOCGIFHWADDR.
    let mut ifr: libc::ifreq = unsafe { zeroed() };
    let name_bytes = iface.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(format!("iface '{}' name >= IFNAMSIZ", iface));
    }
    for (i, b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    let ret = unsafe { libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifr) };
    if ret < 0 {
        return Err(format!(
            "SIOCGIFHWADDR on '{}': {}",
            iface,
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: SIOCGIFHWADDR writes ifr_hwaddr.sa_family and
    // ifr_hwaddr.sa_data[0..6] (well-defined union access).
    let family = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_family as u16 };
    let mut mac = [0u8; 6];
    unsafe {
        for i in 0..6 {
            mac[i] = ifr.ifr_ifru.ifru_hwaddr.sa_data[i] as u8;
        }
    }
    Ok((family, mac))
}

/// Read iface MAC via SIOCGIFHWADDR.
fn read_iface_mac(fd: i32, iface: &str) -> Result<[u8; 6], String> {
    read_iface_hwaddr(fd, iface).map(|(_, mac)| mac)
}

fn format_progress_json(
    elapsed: Duration,
    stats: &RunStats,
    prev_emit_stats: &RunStats,
    emit_window: Duration,
) -> String {
    let tx_packets_delta = stats.tx_packets.saturating_sub(prev_emit_stats.tx_packets);
    let tx_batches_delta = stats.tx_batches.saturating_sub(prev_emit_stats.tx_batches);
    let err_eagain_delta = stats.err_eagain.saturating_sub(prev_emit_stats.err_eagain);
    let err_partial_delta = stats.err_partial.saturating_sub(prev_emit_stats.err_partial);
    let err_other_delta = stats.err_other.saturating_sub(prev_emit_stats.err_other);
    let pps = if emit_window.is_zero() {
        0
    } else {
        (tx_packets_delta as f64 / emit_window.as_secs_f64()) as u64
    };
    format!(
        "{{\"t\":{},\"pps\":{},\"tx_packets_delta\":{},\"tx_batches_delta\":{},\"err_eagain_delta\":{},\"err_partial_delta\":{},\"err_other_delta\":{}}}",
        elapsed.as_secs_f64(),
        pps,
        tx_packets_delta,
        tx_batches_delta,
        err_eagain_delta,
        err_partial_delta,
        err_other_delta
    )
}

#[cfg(test)]
fn select_smoke_test_iface() -> Result<Option<String>, String> {
    match std::env::var("XPF_RAW_SOCKET_TEST_IFACE") {
        Ok(iface) => {
            let iface = iface.trim();
            if iface.is_empty() {
                return Err("XPF_RAW_SOCKET_TEST_IFACE is empty".to_string());
            }
            return Ok(Some(iface.to_string()));
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("XPF_RAW_SOCKET_TEST_IFACE is not valid UTF-8".to_string());
        }
    }

    let entries = fs::read_dir("/sys/class/net")
        .map_err(|e| format!("read_dir('/sys/class/net') failed: {}", e))?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir('/sys/class/net') entry failed: {}", e))?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();

    let ethernet_type = libc::ARPHRD_ETHER.to_string();
    for iface in names {
        let hwtype_path = format!("/sys/class/net/{}/type", iface);
        let operstate_path = format!("/sys/class/net/{}/operstate", iface);
        let hwtype = match fs::read_to_string(&hwtype_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let operstate = match fs::read_to_string(&operstate_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if hwtype.trim() == ethernet_type && operstate.trim() == "up" {
            return Ok(Some(iface));
        }
    }
    Ok(None)
}

/// Open AF_PACKET SOCK_RAW + bind to iface ifindex + enable QDISC_BYPASS +
/// SO_SNDBUF. Returns the fd. Caller drops fd on exit.
fn open_socket(ifindex: i32, frame_bytes: usize, batch: usize) -> Result<i32, String> {
    // SAFETY: socket() is always callable.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::EPERM)
            || errno.raw_os_error() == Some(libc::EACCES)
        {
            return Err(format!(
                "socket(AF_PACKET, SOCK_RAW) failed: {} \
                 --- HINT: re-run with sudo or grant CAP_NET_RAW ---",
                errno
            ));
        }
        return Err(format!("socket(AF_PACKET, SOCK_RAW) failed: {}", errno));
    }

    // SO_SNDBUF — try setting; not fatal if it fails.
    let sndbuf: libc::c_int = (frame_bytes * batch * 256) as libc::c_int;
    // SAFETY: setsockopt with valid fd and value pointer.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // PACKET_QDISC_BYPASS — plan v4 §4.5 + AGY r1 finding 2. Non-fatal
    // on failure (older kernels) but the smoke gate will catch any
    // resulting throughput shortfall.
    let one: libc::c_int = 1;
    // SAFETY: setsockopt with valid fd and value pointer.
    let bypass_ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            PACKET_QDISC_BYPASS_OPT,
            &one as *const _ as *const c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if bypass_ret != 0 {
        eprintln!(
            "warning: PACKET_QDISC_BYPASS setsockopt failed: {} \
             (kernel < 3.14?) — continuing through qdisc",
            std::io::Error::last_os_error()
        );
    }

    // Bind to ifindex.
    // SAFETY: sockaddr_ll is a C-layout POD struct; zero-init before
    // populating sll_family / sll_protocol / sll_ifindex below.
    let mut sll: libc::sockaddr_ll = unsafe { zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = ifindex;
    // SAFETY: bind with valid fd, sockaddr_ll pointer, and correct len.
    let ret = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let errno = std::io::Error::last_os_error();
        // SAFETY: close on a valid fd.
        unsafe {
            libc::close(fd);
        }
        return Err(format!("bind to ifindex {} failed: {}", ifindex, errno));
    }

    Ok(fd)
}

#[derive(Default, Debug, Clone, Copy)]
struct RunStats {
    tx_packets: u64,
    tx_batches: u64,
    err_eagain: u64,
    err_partial: u64,
    err_other: u64,
    first_other_errno: i32,
}

fn run_loop(args: &Args, fd: i32, ring: &mut TxRing) -> Result<RunStats, String> {
    let mut stats = RunStats::default();
    let mut prng = Xorshift64(args.seed);
    let start = Instant::now();
    let mut warmup_stats = RunStats::default();
    let mut in_warmup = !args.warmup.is_zero();
    let mut next_emit_at = start + Duration::from_secs(1);
    let mut prev_emit_at = start;
    let mut prev_emit_stats = RunStats::default();

    loop {
        let now = Instant::now();
        let elapsed = now - start;
        if elapsed >= args.warmup + args.duration {
            break;
        }
        if in_warmup && elapsed >= args.warmup {
            // Snapshot warmup counters; do not count toward run total.
            warmup_stats = stats;
            stats = RunStats::default();
            in_warmup = false;
            // Re-anchor the per-second emit cadence at warmup end so
            // operators see 1-second windows of run-phase data, not
            // mixed-phase windows.
            next_emit_at = now + Duration::from_secs(1);
            prev_emit_at = now;
            prev_emit_stats = RunStats::default();
        }

        // Per-iteration: refill all batch slots with fresh PRNG values.
        for slot in ring.slots.iter_mut() {
            let s = prng.next();
            let src_ip_off = (s as u32) % args.src_ip_span;
            let src_port_v = (((s >> 16) as u32) % args.src_port_span) as u16;
            let src_port = args.src_port_base.wrapping_add(src_port_v);
            let dst_port_v = (((s >> 32) as u32) % args.dst_port_span) as u16;
            let dst_port = args.dst_port_base.wrapping_add(dst_port_v);
            let src_ip = args.src_ip_base.wrapping_add(src_ip_off);
            let ip_id = (s >> 48) as u16;
            slot.fill_packet(src_ip, ip_id, src_port, dst_port);
        }

        // SAFETY: sendmmsg with our owned mmsghdr array and a valid fd.
        let sent = unsafe {
            libc::sendmmsg(
                fd,
                ring.msgs.as_mut_ptr(),
                args.batch as libc::c_uint,
                0,
            )
        };

        if sent < 0 {
            let errno = std::io::Error::last_os_error();
            match errno.raw_os_error() {
                // On Linux EAGAIN == EWOULDBLOCK; ENOBUFS is treated identically
                // per AGY r1 finding A (no logging storm in hot loop).
                Some(libc::EAGAIN) | Some(libc::ENOBUFS) => {
                    stats.err_eagain += 1;
                    std::thread::yield_now();
                    continue;
                }
                Some(libc::EINTR) => continue,
                Some(libc::EPERM) | Some(libc::EACCES) => {
                    return Err(format!(
                        "sendmmsg returned EPERM/EACCES: {} \
                         --- HINT: re-run with sudo or grant CAP_NET_RAW ---",
                        errno
                    ));
                }
                Some(code) => {
                    if stats.err_other == 0 {
                        eprintln!(
                            "sendmmsg first non-recoverable error: {} (errno {})",
                            errno, code
                        );
                        stats.first_other_errno = code;
                    }
                    stats.err_other += 1;
                    std::thread::yield_now();
                    continue;
                }
                None => {
                    return Err(format!("sendmmsg returned -1 without errno: {}", errno));
                }
            }
        }

        let n = sent as u64;
        stats.tx_packets += n;
        if n as usize == args.batch {
            stats.tx_batches += 1;
        } else {
            stats.err_partial += 1;
        }

        // Per-second JSON-lines to stderr — operator visibility.
        if !in_warmup && now >= next_emit_at {
            eprintln!(
                "{}",
                format_progress_json(elapsed, &stats, &prev_emit_stats, now - prev_emit_at)
            );
            prev_emit_at = now;
            prev_emit_stats = stats;
            next_emit_at = now + Duration::from_secs(1);
        }
    }

    // Drop warmup counters (already excluded from `stats`).
    let _ = warmup_stats;
    Ok(stats)
}

fn emit_summary(args: &Args, stats: &RunStats) {
    let secs = args.duration.as_secs_f64();
    let avg_pps = if secs > 0.0 {
        (stats.tx_packets as f64 / secs) as u64
    } else {
        0
    };
    let src_ip_str: Ipv4Addr = Ipv4Addr::from(args.src_ip_base);
    println!(
        "{{\"version\":1,\
         \"cohort\":\"{}\",\
         \"duration_secs\":{},\
         \"warmup_secs\":{},\
         \"frame_bytes\":{},\
         \"batch\":{},\
         \"tx_packets\":{},\
         \"tx_batches\":{},\
         \"avg_pps\":{},\
         \"err_eagain\":{},\
         \"err_partial\":{},\
         \"err_other\":{},\
         \"first_other_errno\":{},\
         \"src_ip_base\":\"{}\",\
         \"src_ip_span\":{},\
         \"src_port_base\":{},\
         \"src_port_span\":{},\
         \"dst_ip\":\"{}\",\
         \"dst_port_base\":{},\
         \"dst_port_span\":{},\
         \"seed\":{},\
         \"clock_source\":\"not-used-in-1611\"}}",
        if args.cohort_unbounded { "unbounded" } else { "bounded" },
        args.duration.as_secs(),
        args.warmup.as_secs(),
        args.frame_bytes,
        args.batch,
        stats.tx_packets,
        stats.tx_batches,
        avg_pps,
        stats.err_eagain,
        stats.err_partial,
        stats.err_other,
        stats.first_other_errno,
        src_ip_str,
        args.src_ip_span,
        args.src_port_base,
        args.src_port_span,
        args.dst_ip,
        args.dst_port_base,
        args.dst_port_span,
        args.seed,
    );
}

fn main() {
    let mut args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", help());
            std::process::exit(2);
        }
    };

    // dst_mac must be explicitly supplied — broadcast default is a sentinel
    // for "operator forgot to pass --dst-mac". Per plan v4 §4 point 1.
    if args.dst_mac == [0xff; 6] {
        eprintln!(
            "error: --dst-mac required; ARP-resolve is not implemented \
             in this runner. On the loss userspace cluster, the peer \
             firewall RETH MAC is stable — pass it explicitly. \
             See docs/pr/1611-flooder-runner-body/plan.md §4."
        );
        std::process::exit(2);
    }

    // Resolve interface + ifindex.
    let ifindex = match resolve_ifindex(&args.iface) {
        Ok(idx) => idx,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Open AF_PACKET SOCK_RAW socket with PACKET_QDISC_BYPASS.
    let fd = match open_socket(ifindex, args.frame_bytes, args.batch) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };

    // Check IFF_UP. AGY r1 finding C.
    if let Err(e) = check_iface_up(fd, &args.iface) {
        eprintln!("error: {e}");
        // SAFETY: close on a valid fd.
        unsafe {
            libc::close(fd);
        }
        std::process::exit(2);
    }

    // Auto-fill src_mac from iface if still default [0; 6].
    if args.src_mac == [0; 6] {
        match read_iface_mac(fd, &args.iface) {
            Ok(mac) => args.src_mac = mac,
            Err(e) => {
                eprintln!("warning: could not read iface MAC ({}); using zeros", e);
            }
        }
    }

    eprintln!(
        "cold-path-flooder v1: iface={} ifindex={} src_mac={:02x?} dst_mac={:02x?} \
         dst_ip={} cohort={} src_port_base={} duration={:?} warmup={:?} frame_bytes={} batch={}",
        args.iface,
        ifindex,
        args.src_mac,
        args.dst_mac,
        args.dst_ip,
        if args.cohort_unbounded { "unbounded" } else { "bounded" },
        args.src_port_base,
        args.duration,
        args.warmup,
        args.frame_bytes,
        args.batch,
    );

    let mut ring = TxRing::new(args.batch, &args.dst_mac, &args.src_mac, args.dst_ip, ifindex);
    ring.wire_msgs();

    let stats = match run_loop(&args, fd, &mut ring) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            // SAFETY: close on a valid fd.
            unsafe {
                libc::close(fd);
            }
            std::process::exit(1);
        }
    };

    // SAFETY: close on a valid fd.
    unsafe {
        libc::close(fd);
    }

    emit_summary(&args, &stats);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_default_args() -> Args {
        Args {
            iface: "ge-0-0-1".to_string(),
            dst_mac: [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01],
            src_mac: [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x02],
            dst_ip: Ipv4Addr::new(172, 16, 80, 200),
            dst_port_base: DEFAULT_DST_PORT_BASE,
            dst_port_span: DEFAULT_DST_PORT_SPAN,
            src_ip_base: u32::from_be_bytes([10, 42, 0, 0]),
            src_ip_span: DEFAULT_SRC_IP_SPAN,
            src_port_base: DEFAULT_SRC_PORT_BASE,
            src_port_span: DEFAULT_SRC_PORT_SPAN,
            duration: Duration::from_secs(DEFAULT_DURATION_SECS),
            warmup: Duration::from_secs(DEFAULT_WARMUP_SECS),
            frame_bytes: MIN_ETH_FRAME,
            batch: DEFAULT_BATCH,
            seed: 1,
            cohort_unbounded: true,
        }
    }

    #[test]
    fn bounded_cohort_constants_fit_max_sessions() {
        let cohort = BOUNDED_SRC_IP_SPAN as u64
            * BOUNDED_SRC_PORT_SPAN as u64
            * BOUNDED_DST_PORT_SPAN as u64;
        assert_eq!(cohort, 131_072);
    }

    #[test]
    fn unbounded_is_default_regime() {
        let default_cohort = DEFAULT_SRC_IP_SPAN as u64
            * DEFAULT_SRC_PORT_SPAN as u64
            * DEFAULT_DST_PORT_SPAN as u64;
        assert!(default_cohort > 131_072);
    }

    #[test]
    fn bounded_cohort_overflow_check_uses_u128() {
        let s1: u32 = u32::MAX;
        let s2: u32 = u32::MAX;
        let s3: u32 = u32::MAX;
        let cohort: u128 = s1 as u128 * s2 as u128 * s3 as u128;
        assert!(cohort > 131_072);
        assert!(cohort > u64::MAX as u128);
    }

    #[test]
    fn zero_spans_and_batch_rejected() {
        let mut a = build_default_args();
        a.src_ip_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.src_port_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.dst_port_span = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.batch = 0;
        assert!(validate_args(&a).is_err());

        a = build_default_args();
        a.batch = 2048;
        assert!(validate_args(&a).is_err());

        assert!(validate_args(&build_default_args()).is_ok());
    }

    #[test]
    fn dst_port_overflow_rejected_by_validator() {
        // AGY r3 step-2 minor 1.
        let mut a = build_default_args();
        a.dst_port_base = 60_000;
        a.dst_port_span = 10_000;
        let err = validate_args(&a).unwrap_err();
        assert!(err.contains("dst-port-base"));
        assert!(err.contains("65536"));
    }

    #[test]
    fn dst_port_base_plus_span_eq_65536_allowed() {
        // Boundary case — dst_port_base + dst_port_span == 65536 is OK.
        let mut a = build_default_args();
        a.dst_port_base = 60_000;
        a.dst_port_span = 5_536;
        assert!(validate_args(&a).is_ok());
    }

    #[test]
    fn src_port_overflow_rejected_by_validator() {
        let mut a = build_default_args();
        a.src_port_base = 60_000;
        a.src_port_span = 10_000;
        let err = validate_args(&a).unwrap_err();
        assert!(err.contains("src-port-base"));
        assert!(err.contains("65536"));
    }

    #[test]
    fn xorshift_nonzero_and_progresses() {
        let mut x = Xorshift64(1);
        let a = x.next();
        let b = x.next();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn parse_mac_valid() {
        let m = parse_mac("02:bf:72:cc:00:01").unwrap();
        assert_eq!(m, [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01]);
    }

    #[test]
    fn parse_mac_invalid_segments() {
        assert!(parse_mac("02:bf:72").is_err());
        assert!(parse_mac("02:bf:72:cc:00:0z").is_err());
    }

    #[test]
    fn unbounded_default_spans_match_plan() {
        assert_eq!(DEFAULT_SRC_IP_SPAN, 65_536);
        // Plan §4 + reserved-port-0 protection: default src_port_span =
        // 65_536 - DEFAULT_SRC_PORT_BASE = 64_512, so emitted ports stay
        // in [1024, 65_536) without u16 wrap.
        assert_eq!(DEFAULT_SRC_PORT_SPAN, 64_512);
        assert_eq!(DEFAULT_SRC_PORT_BASE, 1024);
        assert!(DEFAULT_SRC_PORT_BASE as u32 + DEFAULT_SRC_PORT_SPAN <= 65_536);
        assert_eq!(DEFAULT_DST_PORT_SPAN, 1);
    }

    #[test]
    fn default_src_port_base_skips_reserved_zero() {
        // #1611 plan §4: default src_port_base=1024 to avoid the
        // metadata_tuple_complete short-circuit at
        // userspace-dp/src/afxdp/frame/inspect.rs:207. Operators can
        // opt into port-0 sweep via `--src-port-base 0`.
        assert_eq!(DEFAULT_SRC_PORT_BASE, 1024);
    }

    #[test]
    fn frame_bytes_must_be_at_least_min_eth() {
        assert_eq!(MIN_ETH_FRAME, 64);
        assert!(64 >= MIN_ETH_FRAME);
    }

    /// Plan v4 §4 — wire-byte invariants.
    #[test]
    fn frame_layout_constants_match_plan() {
        assert_eq!(ETH_HDR, 14);
        assert_eq!(IPV4_HDR, 20);
        assert_eq!(UDP_HDR, 8);
        assert_eq!(UDP_PAYLOAD, 22);
        assert_eq!(FRAME_V4_TOTAL, 64);
        assert_eq!(IPV4_TOTAL_LEN, 50);
        assert_eq!(UDP_LEN, 30);
        assert_eq!(PAYLOAD_MAGIC.len(), UDP_PAYLOAD);
    }

    #[test]
    fn frame_assembly_default_v4_is_exactly_64_bytes() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01],
            &[0x02, 0xbf, 0x72, 0xcc, 0x00, 0x02],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(u32::from_be_bytes([10, 42, 0, 5]), 0x1234, 1024, 5201);
        assert_eq!(slot.frame.len(), 64);
    }

    #[test]
    fn frame_assembly_ipv4_total_len_field_is_50() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let total_len = u16::from_be_bytes([slot.frame[16], slot.frame[17]]);
        assert_eq!(total_len, 50);
    }

    #[test]
    fn frame_assembly_udp_len_field_is_30() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let udp_len = u16::from_be_bytes([slot.frame[38], slot.frame[39]]);
        assert_eq!(udp_len, 30);
    }

    #[test]
    fn frame_assembly_udp_csum_is_zero_per_rfc768() {
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        let udp_csum = u16::from_be_bytes([slot.frame[40], slot.frame[41]]);
        assert_eq!(udp_csum, 0);
    }

    #[test]
    fn frame_assembly_ipv4_csum_one_complement_fold() {
        // Golden value: with the static header fields below + src_ip
        // 10.42.0.5, ip_id 0x1234, the IPv4 csum is deterministic.
        // Verify by recomputing externally.
        //
        //   v=4 ihl=5 tos=0      0x4500
        //   total_len = 50       0x0032
        //   id = 0x1234
        //   flags=DF, frag=0     0x4000
        //   ttl=64 proto=17      0x4011
        //   csum (zero for computation)
        //   src = 10.42.0.5      0x0A2A 0x0005
        //   dst = 172.16.80.200  0xAC10 0x50C8
        //
        // 16-bit sum (carry-folded) of header words excluding csum:
        //   0x4500 + 0x0032 + 0x1234 + 0x4000 + 0x4011 + 0x0000
        //     + 0x0A2A + 0x0005 + 0xAC10 + 0x50C8 = 0x1DE7E
        //   carry-fold: 0xDE7E + 0x0001 = 0xDE7F
        //   one's complement: 0xFFFF - 0xDE7F = 0x2180
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(u32::from_be_bytes([10, 42, 0, 5]), 0x1234, 1024, 5201);
        let csum = u16::from_be_bytes([slot.frame[24], slot.frame[25]]);
        assert_eq!(csum, 0x2180, "ipv4 csum mismatch: {:#06x}", csum);
    }

    #[test]
    fn frame_assembly_payload_magic_matches_plan() {
        // Plan v4 §4: payload b"XPF-COLD-PATH-MIN64\n\0\0" (22 bytes).
        let mut slot = TxSlot::new();
        slot.init_static(
            &[0x02; 6],
            &[0x03; 6],
            Ipv4Addr::new(172, 16, 80, 200),
        );
        slot.fill_packet(0x0A2A0001, 0x4321, 1024, 5201);
        assert_eq!(&slot.frame[42..64], PAYLOAD_MAGIC.as_slice());
        assert_eq!(slot.frame[42..62], *b"XPF-COLD-PATH-MIN64\n");
        assert_eq!(slot.frame[62], 0);
        assert_eq!(slot.frame[63], 0);
    }

    #[test]
    fn src_port_zero_never_emitted_with_default_base() {
        // The default config (base=1024, span=64512) keeps every emitted
        // src_port in [1024, 65_536) — strictly above the reserved-port-0
        // short-circuit at userspace-dp/src/afxdp/frame/inspect.rs:207.
        let args = build_default_args();
        assert!(validate_args(&args).is_ok());

        let mut prng = Xorshift64(args.seed);
        for _ in 0..16_384 {
            let s = prng.next();
            let src_port_v = ((s >> 16) as u32 % args.src_port_span) as u16;
            let src_port = args.src_port_base.wrapping_add(src_port_v);
            assert!(
                src_port >= 1024,
                "src_port < 1024: {} (base {} + v {})",
                src_port,
                args.src_port_base,
                src_port_v
            );
        }

        // Confirm the validator hard-rejects a misconfig that would
        // wrap into the reserved range.
        let mut bad = build_default_args();
        bad.src_port_base = 1024;
        bad.src_port_span = 65_536;
        assert!(validate_args(&bad).is_err());
    }

    #[test]
    fn progress_json_reports_window_rate_and_deltas() {
        let prev = RunStats {
            tx_packets: 1_000,
            tx_batches: 31,
            err_eagain: 4,
            err_partial: 1,
            err_other: 2,
            first_other_errno: 0,
        };
        let now = RunStats {
            tx_packets: 3_000,
            tx_batches: 63,
            err_eagain: 7,
            err_partial: 2,
            err_other: 5,
            first_other_errno: 0,
        };
        let line = format_progress_json(
            Duration::from_millis(3500),
            &now,
            &prev,
            Duration::from_millis(500),
        );
        assert!(line.contains("\"t\":3.5"));
        assert!(line.contains("\"pps\":4000"));
        assert!(line.contains("\"tx_packets_delta\":2000"));
        assert!(line.contains("\"tx_batches_delta\":32"));
        assert!(line.contains("\"err_eagain_delta\":3"));
        assert!(line.contains("\"err_partial_delta\":1"));
        assert!(line.contains("\"err_other_delta\":3"));
    }

    #[test]
    fn progress_json_zero_window_clamps_pps_to_zero() {
        let now = RunStats {
            tx_packets: 99,
            ..RunStats::default()
        };
        let line = format_progress_json(
            Duration::from_secs(2),
            &now,
            &RunStats::default(),
            Duration::ZERO,
        );
        assert!(line.contains("\"pps\":0"));
        assert!(line.contains("\"tx_packets_delta\":99"));
    }

    /// CAP_NET_RAW integration test — Codex r1 MAJOR-3.
    /// Skipped by default. Run via:
    ///   XPF_RUN_RAW_SOCKET_TESTS=1 \
    ///   XPF_RAW_SOCKET_TEST_IFACE=eth0 \
    ///   sudo -E cargo test --release \
    ///     -- --ignored test_open_af_packet_raw_smoke
    #[test]
    #[ignore]
    fn test_open_af_packet_raw_smoke() {
        if std::env::var("XPF_RUN_RAW_SOCKET_TESTS").as_deref() != Ok("1") {
            eprintln!("Skipped: set XPF_RUN_RAW_SOCKET_TESTS=1 to run.");
            return;
        }
        let iface = match select_smoke_test_iface().expect("select_smoke_test_iface should work") {
            Some(iface) => iface,
            None => {
                eprintln!(
                    "Skipped: no IFF_UP ARPHRD_ETHER iface found; set XPF_RAW_SOCKET_TEST_IFACE."
                );
                return;
            }
        };
        let ifindex = resolve_ifindex(&iface).expect("smoke-test iface should exist");
        // Open the socket.
        let fd =
            open_socket(ifindex, 64, 1).expect("open_socket on smoke-test iface should succeed");
        assert!(fd >= 0);
        if let Err(err) = check_iface_up(fd, &iface) {
            unsafe {
                libc::close(fd);
            }
            eprintln!("Skipped: {}", err);
            return;
        }
        let (hwaddr_family, iface_mac) =
            read_iface_hwaddr(fd, &iface).expect("SIOCGIFHWADDR should succeed");
        if hwaddr_family != libc::ARPHRD_ETHER as u16 {
            unsafe {
                libc::close(fd);
            }
            eprintln!(
                "Skipped: iface '{}' has ARPHRD {} not ARPHRD_ETHER ({})",
                iface,
                hwaddr_family,
                libc::ARPHRD_ETHER
            );
            return;
        }
        // Build one packet and send.
        let mut ring = TxRing::new(
            1,
            &iface_mac,
            &iface_mac,
            Ipv4Addr::new(127, 0, 0, 1),
            ifindex,
        );
        ring.wire_msgs();
        ring.slots[0].fill_packet(u32::from_be_bytes([127, 0, 0, 1]), 1, 1024, 5201);
        let sent = unsafe {
            libc::sendmmsg(fd, ring.msgs.as_mut_ptr(), 1, 0)
        };
        assert!(sent == 1, "expected sendmmsg to send 1, got {}", sent);
        unsafe {
            libc::close(fd);
        }
    }
}
