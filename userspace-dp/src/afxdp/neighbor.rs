use super::*;

pub(in crate::afxdp) fn monotonic_nanos() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

pub(super) fn monotonic_timestamp_to_datetime(
    last_nanos: u64,
    now_mono: u64,
    now_wall: chrono::DateTime<Utc>,
) -> Option<chrono::DateTime<Utc>> {
    if last_nanos == 0 {
        return None;
    }
    let age_ns = now_mono.saturating_sub(last_nanos).min(i64::MAX as u64) as i64;
    now_wall.checked_sub_signed(chrono::TimeDelta::nanoseconds(age_ns))
}

/// Send a raw Ethernet frame via AF_PACKET on the given interface.
/// Used for ARP/NDP solicitations that must bypass XSK (because the
/// XSK fill ring may not be bootstrapped on the egress interface).

/// Trigger kernel ARP/NDP resolution by sending an ICMP echo via a
/// DGRAM socket bound to the egress interface. The kernel's own ARP
/// stack handles VLAN tagging correctly. No fork/exec overhead.
pub(super) fn trigger_kernel_arp_probe(iface_name: &str, target: IpAddr) {
    match target {
        IpAddr::V4(v4) => {
            // SOCK_RAW ICMP echo — triggers kernel ARP on the bound
            // interface. SOCK_DGRAM IPPROTO_ICMP fails with EINVAL on
            // sendto so we use SOCK_RAW directly.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
            if fd < 0 {
                return;
            }
            let name_c = std::ffi::CString::new(iface_name).unwrap_or_default();
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name_c.as_ptr() as *const libc::c_void,
                    name_c.to_bytes_with_nul().len() as libc::socklen_t,
                );
            }
            // ICMP echo request: type=8, code=0, checksum=0xf7ff
            let icmp: [u8; 8] = [8, 0, 0xf7, 0xff, 0, 0, 0, 0];
            let mut sa: libc::sockaddr_in = unsafe { core::mem::zeroed() };
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            unsafe {
                libc::sendto(
                    fd,
                    icmp.as_ptr() as *const libc::c_void,
                    8,
                    libc::MSG_DONTWAIT,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
                libc::close(fd);
            }
        }
        IpAddr::V6(v6) => {
            // ICMPv6 echo via SOCK_RAW (DGRAM sendto fails with EINVAL)
            let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6) };
            if fd < 0 {
                return;
            }
            let name_c = std::ffi::CString::new(iface_name).unwrap_or_default();
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name_c.as_ptr() as *const libc::c_void,
                    name_c.to_bytes_with_nul().len() as libc::socklen_t,
                );
            }
            let mut sa6: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_addr.s6_addr = v6.octets();
            // ICMPv6 echo request: type=128, code=0, checksum=0 (kernel fills)
            let icmp6 = [128u8, 0, 0, 0, 0, 0, 0, 0];
            // Tell kernel to auto-compute ICMPv6 checksum at offset 2
            let offset: c_int = 2;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_ICMPV6,
                    libc::IPV6_CHECKSUM,
                    &offset as *const c_int as *const libc::c_void,
                    core::mem::size_of::<c_int>() as libc::socklen_t,
                );
            }
            unsafe {
                libc::sendto(
                    fd,
                    icmp6.as_ptr() as *const libc::c_void,
                    8,
                    libc::MSG_DONTWAIT,
                    &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    core::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                );
                libc::close(fd);
            }
        }
    }
}

/// Long-lived neighbor-warmer worker loop (#1636 option C). Spawned
/// once at coordinator bring-up and fed `WarmItem`s via a bounded MPSC
/// queue from `Coordinator::queue_warm_pass`. For each item it:
///
///   1. GCs `last_probed` once per `WARM_GC_INTERVAL_NS` (runs on EVERY
///      loop iteration — idle timeout OR dequeue — so the prune is not
///      bypassed under continuous load).
///   2. Re-checks the item's owning RG is still forwarding-active on
///      this node immediately before firing (per-RG HA gate; an item
///      queued under an active RG but dequeued after demotion must NOT
///      fire).
///   3. Drops items tagged with a stale `warm_generation` (generation
///      collapse — only the latest snapshot's keys are warmed).
///   4. Skips keys probed within `WARM_PER_KEY_RATE_LIMIT_NS`.
///   5. Fires exactly ONE `trigger_kernel_arp_probe()` per (key, gen);
///      the kernel then runs its own retransmit schedule. No userspace
///      retry loop.
///
/// `last_probed.lock().expect(...)` panics on a poisoned mutex: silently
/// skipping forever would leave warming "alive but disabled" and
/// invisible. Panicking kills the worker, breaking the MPSC channel; the
/// next producer `try_send` hits `Disconnected`, increments
/// `warm_disconnected`, and emits the once-only operator warning.
pub(super) fn neighbor_warmer_loop(
    rx: Receiver<WarmItem>,
    last_probed: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
    warm_generation: Arc<AtomicU64>,
    rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    stop: Arc<AtomicBool>,
) {
    let mut last_gc_ns = monotonic_nanos();
    while !stop.load(Ordering::Relaxed) {
        // GC at the top of every iteration (idle OR dequeue path).
        let now = monotonic_nanos();
        if now.saturating_sub(last_gc_ns) >= WARM_GC_INTERVAL_NS {
            if let Ok(mut map) = last_probed.lock() {
                map.retain(|_k, &mut t| now.saturating_sub(t) < WARM_GC_MAX_AGE_NS);
            }
            last_gc_ns = now;
        }
        let item = match rx.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                eprintln!(
                    "xpf-userspace-dp: neighbor warmer worker: channel disconnected; exiting"
                );
                return;
            }
        };
        // Re-check stop after dequeue: stop_inner sets `stop` and drops
        // the sender, but an item already in the channel would otherwise
        // be processed and fire one stray probe on a tearing-down
        // dataplane (Codex r1 Medium). Bail before any side effect.
        if stop.load(Ordering::Relaxed) {
            return;
        }
        // Per-RG HA gate, re-checked immediately before firing.
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let rg_active = rg_runtime
            .load()
            .get(&item.rg_id)
            .map(|group| group.is_forwarding_active(now_secs))
            .unwrap_or(false);
        if !rg_active {
            continue;
        }
        // Generation collapse: drop items from a superseded snapshot.
        if item.generation != warm_generation.load(Ordering::Acquire) {
            continue;
        }
        let key = (item.ifindex, item.hop);
        let now = monotonic_nanos();
        let skip = {
            let mut map = last_probed
                .lock()
                .expect("last_probed mutex poisoned — neighbor warming forcibly disabled");
            match map.get(&key) {
                Some(&t) if now.saturating_sub(t) < WARM_PER_KEY_RATE_LIMIT_NS => true,
                _ => {
                    map.insert(key, now);
                    false
                }
            }
        };
        if !skip {
            trigger_kernel_arp_probe(&item.iface_name, item.hop);
        }
    }
}

/// Add a neighbor entry to the kernel's neighbor table via raw netlink.
/// This ensures the kernel can forward IPv6 (and IPv4) traffic to hosts
/// whose ARP/NDP replies were captured by XSK instead of reaching the kernel.
pub(super) fn add_kernel_neighbor(ifindex: i32, ip: IpAddr, mac: [u8; 6]) {
    // RTM_NEWNEIGH = 28, NLM_F_REQUEST=1, NLM_F_CREATE=0x400, NLM_F_REPLACE=0x100
    const RTM_NEWNEIGH: u16 = 28;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_REPLACE: u16 = 0x100;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    const NUD_REACHABLE: u16 = 0x02;
    let (family, ip_bytes): (u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
    };
    let ip_attr_len = 4 + ip_bytes.len(); // NLA header (4) + payload
    let ip_attr_padded = (ip_attr_len + 3) & !3;
    let mac_attr_len = 4 + 6;
    let mac_attr_padded = (mac_attr_len + 3) & !3;
    // ndmsg: family(1) + pad1(1) + pad2(2) + ifindex(4) + state(2) + flags(1) + type(1) = 12
    let ndmsg_len = 12;
    let total_len = 16 + ndmsg_len + ip_attr_padded + mac_attr_padded; // nlmsghdr(16) + ndmsg + attrs
    let mut buf = vec![0u8; total_len];
    // nlmsghdr
    buf[0..4].copy_from_slice(&(total_len as u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE).to_ne_bytes());
    buf[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
    // ndmsg
    buf[16] = family;
    buf[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    buf[24..26].copy_from_slice(&NUD_REACHABLE.to_ne_bytes());
    // NDA_DST attribute
    let off = 16 + ndmsg_len;
    buf[off..off + 2].copy_from_slice(&(ip_attr_len as u16).to_ne_bytes());
    buf[off + 2..off + 4].copy_from_slice(&NDA_DST.to_ne_bytes());
    buf[off + 4..off + 4 + ip_bytes.len()].copy_from_slice(&ip_bytes);
    // NDA_LLADDR attribute
    let off2 = off + ip_attr_padded;
    buf[off2..off2 + 2].copy_from_slice(&(mac_attr_len as u16).to_ne_bytes());
    buf[off2 + 2..off2 + 4].copy_from_slice(&NDA_LLADDR.to_ne_bytes());
    buf[off2 + 4..off2 + 10].copy_from_slice(&mac);
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return;
    }
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            libc::MSG_DONTWAIT,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        libc::close(fd);
    }
}

/// Monitor kernel neighbor table changes via netlink RTM_NEWNEIGH events.
/// When the kernel resolves ARP/NDP (from our send_raw_frame solicitations
/// or from slow-path reinject), it sends a netlink notification. This thread
/// receives it and updates the helper's dynamic_neighbors cache instantly,
/// so the next packet for that destination finds the neighbor and forwards
/// directly through XSK — no waiting for the Go-side snapshot refresh.
pub(super) fn update_dynamic_neighbor(
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ifindex: i32,
    ip: IpAddr,
    entry: NeighborEntry,
) -> bool {
    dynamic_neighbors.insert_if_changed((ifindex, ip), entry)
}

pub(super) fn remove_dynamic_neighbor(
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    ifindex: i32,
    ip: IpAddr,
) -> bool {
    dynamic_neighbors.remove_if_present(&(ifindex, ip))
}

/// Map mutation performed by [`parse_neighbor_msg`] for one netlink
/// neighbor message. Split from the former plain `bool` (#1771 §2.6) so
/// the monitor loop can count re-dump UPSERTS (`Upserted`) for
/// `netlink_redump_upserts` without conflating them with the
/// FAILED/INCOMPLETE/DELNEIGH removal path (which also "changes" the map
/// but re-adds nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NeighborMsgEffect {
    /// No map mutation (unparseable body, no IP/MAC, or a redundant
    /// update/removal that left the map unchanged).
    None,
    /// A usable RTM_NEWNEIGH inserted or updated the entry.
    Upserted,
    /// An RTM_DELNEIGH, or an RTM_NEWNEIGH in FAILED/INCOMPLETE,
    /// removed a present entry.
    Removed,
}

pub(super) fn parse_neighbor_msg(
    nlmsg_type: u16,
    body: &[u8],
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> NeighborMsgEffect {
    fn removal(removed: bool) -> NeighborMsgEffect {
        if removed {
            NeighborMsgEffect::Removed
        } else {
            NeighborMsgEffect::None
        }
    }
    if body.len() < 12 {
        return NeighborMsgEffect::None;
    }
    let family = body[0];
    let ifindex = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    let state = u16::from_ne_bytes([body[8], body[9]]);
    let mut attr_off = 12usize;
    let mut ip: Option<IpAddr> = None;
    let mut mac: Option<[u8; 6]> = None;
    while attr_off + 4 <= body.len() {
        let attr_len = u16::from_ne_bytes([body[attr_off], body[attr_off + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([body[attr_off + 2], body[attr_off + 3]]);
        if attr_len < 4 || attr_off + attr_len > body.len() {
            break;
        }
        let payload = &body[attr_off + 4..attr_off + attr_len];
        match attr_type {
            1 => {
                if family == libc::AF_INET as u8 && payload.len() >= 4 {
                    ip = Some(IpAddr::V4(Ipv4Addr::new(
                        payload[0], payload[1], payload[2], payload[3],
                    )));
                } else if family == libc::AF_INET6 as u8 && payload.len() >= 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&payload[..16]);
                    ip = Some(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
            }
            2 => {
                if payload.len() >= 6 {
                    mac = Some([
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    ]);
                }
            }
            _ => {}
        }
        attr_off += (attr_len + 3) & !3;
    }
    let Some(ip) = ip else {
        return NeighborMsgEffect::None;
    };
    match nlmsg_type {
        28 => {
            // Treat INCOMPLETE (0x01) and FAILED (0x20) as unusable;
            // everything else (REACHABLE, STALE, DELAY, PROBE,
            // PERMANENT, NOARP) is a valid resolved neighbor.
            const NUD_INCOMPLETE: u16 = 0x01;
            const NUD_FAILED: u16 = 0x20;
            if (state & (NUD_INCOMPLETE | NUD_FAILED)) != 0 {
                return removal(remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip));
            }
            let Some(mac) = mac else {
                return NeighborMsgEffect::None;
            };
            if update_dynamic_neighbor(dynamic_neighbors, ifindex, ip, NeighborEntry { mac }) {
                NeighborMsgEffect::Upserted
            } else {
                NeighborMsgEffect::None
            }
        }
        29 => removal(remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip)),
        _ => NeighborMsgEffect::None,
    }
}

pub(super) fn request_neighbor_dump(fd: c_int, family: u8, seq: u32) -> io::Result<()> {
    const RTM_GETNEIGH: u16 = 30;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ROOT: u16 = 0x100;
    const NLM_F_MATCH: u16 = 0x200;
    let mut buf = [0u8; 28];
    buf[0..4].copy_from_slice(&(28u32).to_ne_bytes());
    buf[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    buf[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH).to_ne_bytes());
    buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    buf[12..16].copy_from_slice(&0u32.to_ne_bytes());
    buf[16] = family;
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    let rc = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Netlink control message types shared by the initial dump and the
/// steady-state monitor loop (re-dump completion detection, #1771 §2.6).
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;

pub(super) fn initial_neighbor_dump(
    fd: c_int,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> io::Result<u64> {
    let mut next_seq = 1u32;
    let mut changed = false;
    let mut buf = vec![0u8; 8192];
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        request_neighbor_dump(fd, family, next_seq)?;
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                let kind = err.kind();
                if kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut {
                    return Err(err);
                }
                continue;
            }
            let mut offset = 0usize;
            let mut dump_done = false;
            while offset + 16 <= n as usize {
                let nlmsg_len = u32::from_ne_bytes([
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ]) as usize;
                let nlmsg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
                let nlmsg_seq = u32::from_ne_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]);
                if nlmsg_len < 16 || offset + nlmsg_len > n as usize {
                    break;
                }
                if nlmsg_seq != next_seq {
                    offset += (nlmsg_len + 3) & !3;
                    continue;
                }
                match nlmsg_type {
                    NLMSG_DONE => {
                        dump_done = true;
                    }
                    NLMSG_ERROR => {
                        return Err(io::Error::other("netlink neighbor dump failed"));
                    }
                    28 | 29 => {
                        changed |= parse_neighbor_msg(
                            nlmsg_type,
                            &buf[offset + 16..offset + nlmsg_len],
                            dynamic_neighbors,
                        ) != NeighborMsgEffect::None;
                    }
                    _ => {}
                }
                offset += (nlmsg_len + 3) & !3;
            }
            if dump_done {
                break;
            }
        }
        next_seq += 1;
    }
    Ok(if changed { 1 } else { 0 })
}

/// Requested receive-buffer size for the neighbor-monitor netlink socket
/// (#1658). Under an RTM_NEWNEIGH/DELNEIGH multicast burst (HA failover,
/// large neighbor churn) the default rcvbuf can overflow and the kernel
/// drops notifications + returns ENOBUFS; the steady-state loop swallows
/// `recv() <= 0` so the loss is silent and `dynamic_neighbors` can
/// permanently desync (the full dump is startup-only). 4 MiB holds many
/// thousands of small (~80-200 B wire, larger skb truesize) events —
/// enough headroom to absorb a full large-L2-domain neighbor flush while
/// the thread is stalled up to one 500 ms SO_RCVTIMEO tick.
const NEIGH_RCVBUF_BYTES: libc::c_int = 4 * 1024 * 1024; // 4 MiB

// Compile-time floor: a future edit must not silently shrink the monitor
// buffer below the burst-absorbing target.
const _: () = assert!(NEIGH_RCVBUF_BYTES >= (1 << 20));

/// Enlarge the netlink monitor receive buffer to `request` bytes.
///
/// Best-effort: tries `SO_RCVBUFFORCE` first (bypasses
/// `net.core.rmem_max`, requires CAP_NET_ADMIN — held because the helper
/// runs as root for AF_XDP/BPF), falling back to plain `SO_RCVBUF`
/// (clamped to `rmem_max`). FORCE makes the buffer guarantee
/// self-contained instead of depending on the Go-side `tuneSocketBuffers`
/// `rmem_max` bump (a cross-process side effect that is silently
/// swallowed on failure).
///
/// Returns the effective buffer size read back via `getsockopt`. The
/// kernel doubles the request for bookkeeping and may clamp the plain
/// `SO_RCVBUF` path to `rmem_max`, so the `setsockopt` return alone hides
/// a silent clamp — the readback is the ground truth and is logged. A
/// tuning failure is logged and tolerated (the monitor still works with
/// the default buffer); crashing the thread over a socket-buffer knob
/// would be a worse outcome.
fn set_neigh_monitor_rcvbuf(fd: libc::c_int, request: libc::c_int) -> libc::c_int {
    // Stack local so &-of-value is well-defined for the FFI pointer.
    let want: libc::c_int = request;
    let optlen = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let forced = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &want as *const libc::c_int as *const libc::c_void,
            optlen,
        )
    };
    let mut via = "SO_RCVBUFFORCE";
    if forced < 0 {
        let force_err = std::io::Error::last_os_error();
        let set = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &want as *const libc::c_int as *const libc::c_void,
                optlen,
            )
        };
        via = "SO_RCVBUF";
        if set < 0 {
            eprintln!(
                "neigh_monitor: SO_RCVBUFFORCE({want}) and SO_RCVBUF({want}) \
                 both failed (force: {force_err}, set: {}); using kernel \
                 default receive buffer",
                std::io::Error::last_os_error()
            );
            via = "default";
        }
    }
    // Read back the effective size: a plain SO_RCVBUF set can succeed
    // while silently clamping to rmem_max, so the setsockopt return is
    // not enough to confirm the preventive buffer is active.
    let mut eff: libc::c_int = 0;
    let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut eff as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        eprintln!(
            "neigh_monitor: rcvbuf set via {via}: requested {want}, \
             effective {eff} bytes"
        );
    } else {
        eprintln!(
            "neigh_monitor: rcvbuf set via {via}: requested {want}, \
             getsockopt readback failed: {}",
            std::io::Error::last_os_error()
        );
    }
    eff
}

pub(super) fn neigh_monitor_thread(
    stop: Arc<AtomicBool>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    neighbor_generation: Arc<AtomicU64>,
    // #1771 §2.6: ENOBUFS/re-dump telemetry. Counted here on the monitor
    // thread but carried on the shared resolver-counter block so it
    // rides the existing status wire path (netlink_enobufs,
    // netlink_redumps, netlink_redump_upserts).
    counters: Arc<super::neighbor_resolver::ResolverCounters>,
) {
    // Create NETLINK_ROUTE socket and subscribe to neighbor events
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        eprintln!("neigh_monitor: failed to create netlink socket");
        return;
    }
    // Bind to RTMGRP_NEIGH group to receive neighbor notifications
    let mut sa: libc::sockaddr_nl = unsafe { core::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    sa.nl_groups = 1 << (libc::RTNLGRP_NEIGH - 1) as u32; // RTMGRP_NEIGH
    let rc = unsafe {
        libc::bind(
            fd,
            &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        eprintln!("neigh_monitor: bind failed");
        unsafe { libc::close(fd) };
        return;
    }
    // Enlarge the receive buffer before the dump + steady-state loop so a
    // burst of RTM_NEWNEIGH/DELNEIGH multicast notifications does not
    // overflow the default rcvbuf and silently drop adverts (#1658). Same
    // fd used by initial_neighbor_dump() and the recv() loop below.
    set_neigh_monitor_rcvbuf(fd, NEIGH_RCVBUF_BYTES);
    // Set 500ms receive timeout for periodic stop check.
    // Neighbor events arrive instantly via the multicast group —
    // recv() returns immediately when the kernel pushes an update.
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            core::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    match initial_neighbor_dump(fd, &dynamic_neighbors) {
        Ok(_) => {
            neighbor_generation.store(1, Ordering::Relaxed);
            eprintln!("neigh_monitor: initial kernel neighbor dump complete");
        }
        Err(err) => {
            neighbor_generation.store(1, Ordering::Relaxed);
            eprintln!("neigh_monitor: initial dump failed: {err}");
        }
    }
    eprintln!("neigh_monitor: listening for kernel neighbor events");
    let mut buf = vec![0u8; 8192];
    // #1771 §2.5: throttle state for the ENOBUFS-triggered upsert re-dump.
    let mut last_redump_ns: u64 = 0;
    let mut redump_seq: u32 = 1000;
    // #1771 §2.6: nlmsg_seq values of the in-flight v4/v6 re-dump
    // requests (0 = none). Dump replies are unicast on this same fd and
    // carry the request seq, while multicast RTM_{NEW,DEL}NEIGH events
    // carry seq 0 — so a seq match identifies a re-dump reply and lets
    // the parse loop below count `netlink_redump_upserts` precisely.
    let mut redump_pending: [u32; 2] = [0, 0];
    while !stop.load(Ordering::Relaxed) {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            // #1771 §2.5: distinguish ENOBUFS (the kernel dropped neighbor
            // multicast notifications on rcvbuf overflow — the silent
            // desync this fixes) from the benign SO_RCVTIMEO timeout.
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOBUFS) => {
                    // #1771 §2.6: every ENOBUFS recv is a kernel-reported
                    // notification loss — count it even when the re-dump
                    // below is throttled away.
                    counters.netlink_enobufs.fetch_add(1, Ordering::Relaxed);
                    // Lost RTM_{NEW,DEL}NEIGH leave dynamic_neighbors
                    // desynced (a dropped good NEWNEIGH blackholes a dst
                    // until its next per-key event). Recover with a THROTTLED
                    // family re-dump whose GETNEIGH replies flow through the
                    // same parse path below: RTM_NEWNEIGH → insert, and a
                    // kernel-reported NUD_FAILED/INCOMPLETE → the existing
                    // #1769 immediate-revocation (correct — a dead neighbor
                    // SHOULD be removed). Crucially this is NOT a
                    // replacement/reconciling dump: it NEVER deletes an entry
                    // merely because it is ABSENT from the dump, so the
                    // RX-learned + manager-populated entries that also feed
                    // dynamic_neighbors survive (the Codex r2 "no absent-key
                    // eviction" requirement). The 5s throttle bounds RTNL
                    // contention if ENOBUFS recurs (AGY F2). The single-key
                    // on-demand GET path is NOT this dump path.
                    let now = monotonic_nanos();
                    if now.saturating_sub(last_redump_ns) > 5_000_000_000 {
                        last_redump_ns = now;
                        redump_seq = redump_seq.wrapping_add(1);
                        let seq_v4 = redump_seq;
                        let v4 = request_neighbor_dump(fd, libc::AF_INET as u8, seq_v4);
                        redump_seq = redump_seq.wrapping_add(1);
                        let seq_v6 = redump_seq;
                        let v6 = request_neighbor_dump(fd, libc::AF_INET6 as u8, seq_v6);
                        // #1771 §2.6: a re-dump counts as ISSUED when at
                        // least one family request was sent; the pending
                        // seqs let the parse loop attribute the unicast
                        // dump replies to this re-dump for the upsert
                        // counter. A failed family keeps seq 0 (no match).
                        redump_pending = [
                            if v4.is_ok() { seq_v4 } else { 0 },
                            if v6.is_ok() { seq_v6 } else { 0 },
                        ];
                        if v4.is_ok() || v6.is_ok() {
                            counters.netlink_redumps.fetch_add(1, Ordering::Relaxed);
                        }
                        match (&v4, &v6) {
                            (Ok(_), Ok(_)) => eprintln!(
                                "neigh_monitor: ENOBUFS — throttled re-dump (v4+v6) issued"
                            ),
                            _ => eprintln!(
                                "neigh_monitor: ENOBUFS — re-dump request failed (v4={v4:?} v6={v6:?})"
                            ),
                        }
                    }
                }
                // SO_RCVTIMEO periodic stop-check timeout — normal, not an
                // error. (EAGAIN == EWOULDBLOCK on Linux; the catch-all below
                // covers the alias without an unreachable-pattern warning.)
                Some(libc::EAGAIN) => {}
                // Any other recv error: skip this read and keep listening.
                _ => {}
            }
            continue;
        }
        if n == 0 {
            // EOF on a netlink socket shouldn't happen; treat as a skip.
            continue;
        }
        // #1769 epoch-guard ordering: bump the generation with `Release`
        // BEFORE mutating dynamic_neighbors. The socket is bound to
        // RTMGRP_NEIGH only, so every recv carries neighbor events; a
        // bump-first per batch guarantees the on-demand resolver's in-lock
        // `Acquire` read (`insert_confirmed_if_unchanged`) observes the
        // advance if ANY mutation in this batch could invalidate its
        // GET-derived MAC — including a DELNEIGH for an already-absent key
        // (which the old `if changed` post-bump missed entirely). The
        // resolver's worst case is a conservative reject, never a stale
        // insert. `store(1)` on dump completion stays the startup
        // sentinel; here we always advance.
        neighbor_generation.fetch_add(1, Ordering::Release);
        let mut offset = 0usize;
        while offset + 16 <= n as usize {
            let nlmsg_len = u32::from_ne_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]) as usize;
            let nlmsg_type = u16::from_ne_bytes([buf[offset + 4], buf[offset + 5]]);
            if nlmsg_len < 16 || offset + nlmsg_len > n as usize {
                break;
            }
            // #1771 §2.6: nlmsg_seq (header bytes 8..12) attributes a
            // message to an in-flight re-dump (multicast events carry 0).
            let nlmsg_seq = u32::from_ne_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ]);
            let from_redump =
                nlmsg_seq != 0 && (nlmsg_seq == redump_pending[0] || nlmsg_seq == redump_pending[1]);
            if nlmsg_type == 28 || nlmsg_type == 29 {
                let effect = parse_neighbor_msg(
                    nlmsg_type,
                    &buf[offset + 16..offset + nlmsg_len],
                    &dynamic_neighbors,
                );
                // Count only genuine re-adds from a re-dump reply: an
                // RTM_NEWNEIGH whose insert CHANGED the map. Removals
                // (FAILED/INCOMPLETE) and no-op updates do not prove a
                // lost-NEWNEIGH was healed.
                if from_redump && effect == NeighborMsgEffect::Upserted {
                    counters
                        .netlink_redump_upserts
                        .fetch_add(1, Ordering::Relaxed);
                }
            } else if nlmsg_type == NLMSG_DONE && from_redump {
                // Re-dump for this family completed — retire its seq so a
                // stale slot can never match a future message.
                if nlmsg_seq == redump_pending[0] {
                    redump_pending[0] = 0;
                }
                if nlmsg_seq == redump_pending[1] {
                    redump_pending[1] = 0;
                }
            }
            offset += (nlmsg_len + 3) & !3; // align to 4
        }
    }
    unsafe { libc::close(fd) };
    eprintln!("neigh_monitor: stopped");
}

/// Enumerate the allowed CPUs described by `is_set` into the caller-provided
/// `buf`, then pick the `worker_id % count`-th entry. Pure helper — no
/// syscalls, no allocations — so behaviour can be regression-tested without
/// mutating the process affinity mask.
///
/// `is_set(cpu)` returns true if CPU index `cpu` is in the allowed mask.
/// `buf.len()` bounds the scan range (caller passes a `[u16; CPU_SETSIZE]`
/// in production; tests pass smaller arrays).
///
/// Returns `None` when the allowed set is empty.
#[cfg(target_os = "linux")]
fn nth_allowed_cpu(
    worker_id: u32,
    is_set: impl Fn(usize) -> bool,
    buf: &mut [u16],
) -> Option<usize> {
    let mut count: usize = 0;
    for cpu in 0..buf.len() {
        if is_set(cpu) {
            // CPU index is <= buf.len() <= u16::MAX in practice
            // (libc::CPU_SETSIZE = 1024). Saturating guard is cheap
            // insurance against a pathological caller.
            buf[count] = cpu.min(u16::MAX as usize) as u16;
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    let idx = (worker_id as usize) % count;
    Some(buf[idx] as usize)
}

/// Pin the current thread to one CPU from the inherited affinity mask.
///
/// The previous implementation used `available_parallelism() % cpus`, which
/// picked an **absolute** CPU index — so under systemd `CPUAffinity=2 3 4 5`
/// the workers pinned to CPUs 0/1/2/3, **outside** the unit-level mask.
/// `sched_setaffinity` silently succeeded because `CPUAffinity=` is plain
/// task affinity (not a cgroup cpuset), so the violation was invisible
/// until it showed up in `/proc/<tid>/status`.
///
/// Fix: read the inherited mask with `sched_getaffinity`, enumerate the
/// allowed CPUs, and pick the `worker_id % allowed_count`-th entry. With
/// no `CPUAffinity=` the allowed set is `0..N-1` and behaviour is
/// unchanged; with `CPUAffinity=2 3 4 5` worker 0→CPU 2, worker 1→CPU 3,
/// worker 2→CPU 4, worker 3→CPU 5.
///
/// Best-effort: returns silently on `sched_getaffinity` failure or an
/// empty mask. Pinning is a tuning hint, not a correctness requirement.
pub(super) fn pin_current_thread(worker_id: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        let mut inherited: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut inherited);
        if libc::sched_getaffinity(0, core::mem::size_of_val(&inherited), &mut inherited) != 0 {
            return;
        }
        // Fixed-size stack buffer sized to CPU_SETSIZE (1024 on Linux
        // glibc). u16 entries keep the footprint at 2 KB — well under
        // the 8 MB Rust default thread stack — and cover the full range
        // of CPU indices the kernel allows (nr_cpu_ids ≤ CONFIG_NR_CPUS,
        // currently 8192 max but CPU_SETSIZE bounds what this codepath
        // sees via cpu_set_t). Called once per worker at thread-start;
        // no hot-path cost.
        let mut allowed = [0u16; libc::CPU_SETSIZE as usize];
        let Some(target) =
            nth_allowed_cpu(worker_id, |cpu| libc::CPU_ISSET(cpu, &inherited), &mut allowed)
        else {
            return;
        };
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(target, &mut set);
        let _ = libc::sched_setaffinity(0, core::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

pub fn neighbor_state_usable_str(state: &str) -> bool {
    neighbor_state_usable(state)
}

pub fn parse_mac_str(s: &str) -> Option<[u8; 6]> {
    parse_mac(s)
}

pub(super) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

pub(super) fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(all(test, target_os = "linux"))]
mod pin_tests {
    use super::nth_allowed_cpu;

    /// Build an `is_set` closure that returns true iff `cpu` is in `allowed`.
    fn mask_from<const N: usize>(allowed: [usize; N]) -> impl Fn(usize) -> bool {
        move |cpu| allowed.contains(&cpu)
    }

    #[test]
    fn nth_allowed_cpu_picks_nth_of_allowed_cpus() {
        let is_set = mask_from([2usize, 3, 4, 5]);
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(2));
        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(3));
        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(4));
        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(5));
        // worker_id 4 wraps around via `worker_id % count`
        assert_eq!(nth_allowed_cpu(4, &is_set, &mut buf), Some(2));
    }

    #[test]
    fn nth_allowed_cpu_returns_none_when_mask_is_empty() {
        let is_set = |_cpu: usize| false;
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, is_set, &mut buf), None);
        assert_eq!(nth_allowed_cpu(7, is_set, &mut buf), None);
    }

    /// #1658: setting SO_RCVBUF[FORCE] on a NETLINK_ROUTE socket must
    /// actually enlarge the effective receive buffer, and the helper must
    /// return the read-back size (the surrounding production recv() loop
    /// ignores its return; this knob must not). Uses a deliberately small
    /// request (256 KiB) so the test does not depend on running as root:
    /// the kernel sets buf = 2 * min(request, rmem_max). On a typical host
    /// rmem_max far exceeds 256 KiB, so the effective size is ~512 KiB; the
    /// assertion below uses a conservative floor (min(2*req, rmem_max),
    /// which is always <= the kernel value) so it stays flake-proof across
    /// privilege levels and any host rmem_max.
    #[test]
    fn neigh_monitor_rcvbuf_enlarges_effective_buffer() {
        const TEST_REQ: libc::c_int = 256 * 1024; // well below typical rmem_max
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        assert!(fd >= 0, "failed to create NETLINK_ROUTE socket for test");

        let effective = super::set_neigh_monitor_rcvbuf(fd, TEST_REQ);

        // Conservative floor: the kernel sets buf = 2 * min(request,
        // rmem_max) (the non-root SO_RCVBUF fallback clamps to rmem_max,
        // NOT 2*rmem_max). min(2*req, rmem_max) is always <= that value,
        // so asserting >= it never false-fails. Fall back to the weaker
        // "grew to at least the request" check if rmem_max is unreadable.
        let rmem_max = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());
        match rmem_max {
            Some(max) => {
                let doubled = 2i64 * TEST_REQ as i64;
                let expected_floor = doubled.min(max);
                assert!(
                    effective as i64 >= expected_floor,
                    "effective {effective} < expected floor {expected_floor} \
                     (request {TEST_REQ}, rmem_max {max})"
                );
                // Confirm the buffer actually grew past the ~208 KB default
                // (unless this host's rmem_max is pathologically small).
                assert!(
                    effective > 212992 || max <= TEST_REQ as i64,
                    "effective {effective} did not exceed the 208 KB default \
                     (rmem_max {max})"
                );
            }
            None => {
                assert!(
                    effective >= TEST_REQ,
                    "effective {effective} < requested {TEST_REQ}"
                );
            }
        }

        unsafe { libc::close(fd) };
    }

    #[test]
    fn nth_allowed_cpu_handles_sparse_masks() {
        let is_set = mask_from([0usize, 7, 15]);
        let mut buf = [0u16; 16];
        assert_eq!(nth_allowed_cpu(0, &is_set, &mut buf), Some(0));
        assert_eq!(nth_allowed_cpu(1, &is_set, &mut buf), Some(7));
        assert_eq!(nth_allowed_cpu(2, &is_set, &mut buf), Some(15));
        // wrap-around: 3 % 3 == 0 -> first entry
        assert_eq!(nth_allowed_cpu(3, &is_set, &mut buf), Some(0));
    }

    /// Counter-factual regression guard for the systemd `CPUAffinity=2 3 4 5`
    /// scenario from #738. Reconstructs the OLD behaviour
    /// (`CPU_SET(worker_id % available_parallelism())`, which pins to an
    /// *absolute* CPU index regardless of the inherited mask) and asserts
    /// that the NEW behaviour picks the `worker_id`-th entry of the allowed
    /// set instead. Without this test a future refactor could silently
    /// revert to `CPU_SET(worker_id % n)` and no other test would catch
    /// it — the other `nth_allowed_cpu_*` tests would still pass because
    /// they exercise the pure helper, not the overall pinning contract.
    #[test]
    fn nth_allowed_cpu_regression_for_systemd_cpuaffinity_2_3_4_5() {
        let allowed_cpus = [2usize, 3, 4, 5];
        let is_set = mask_from(allowed_cpus);
        let mut buf = [0u16; 16];

        // Under the old code, `available_parallelism()` honours the
        // inherited mask and returns 4, so `worker_id % 4` maps to
        // absolute CPUs 0/1/2/3. The NEW code maps the same worker_ids
        // to allowed[0..3] = 2/3/4/5. The issue body verified this live
        // via /proc/<tid>/status:
        //
        //     xpf-userspace-w cpus_allowed=0   <-- old worker 0
        //     xpf-userspace-w cpus_allowed=1   <-- old worker 1
        //     xpf-userspace-w cpus_allowed=2   <-- old worker 2
        //     xpf-userspace-w cpus_allowed=3   <-- old worker 3
        //
        // Expected NEW behaviour: workers pin to cpus_allowed=2/3/4/5.
        for (worker_id, old_absolute_cpu, new_allowed_cpu) in [
            (0u32, 0usize, 2usize),
            (1, 1, 3),
            (2, 2, 4),
            (3, 3, 5),
        ] {
            // Reconstruct the old formula verbatim. Uses the allowed-set
            // *size* (what `available_parallelism()` returned under the
            // systemd mask), not the allowed-set members.
            let reconstructed_old = (worker_id as usize) % allowed_cpus.len();
            assert_eq!(
                reconstructed_old, old_absolute_cpu,
                "old formula reconstruction drifted",
            );

            let picked = nth_allowed_cpu(worker_id, &is_set, &mut buf)
                .expect("allowed mask is non-empty");
            assert_eq!(
                picked, new_allowed_cpu,
                "worker {worker_id} should pin to allowed CPU {new_allowed_cpu}, got {picked}",
            );
            assert!(
                allowed_cpus.contains(&picked),
                "picked CPU {picked} must be inside the systemd CPUAffinity={{2,3,4,5}} mask",
            );
        }

        // The core regression: for workers 0 and 1, the old absolute CPU
        // (0, 1) is strictly outside the systemd mask {2,3,4,5}, while
        // the new picks (2, 3) are strictly inside. This pair alone is
        // enough to refute any revert to `CPU_SET(worker_id % n)` — a
        // revert would pick 0/1 and fall outside the allowed set.
        let old_worker_0 = 0usize; // (0u32 as usize) % 4
        let old_worker_1 = 1usize; // (1u32 as usize) % 4
        assert!(!allowed_cpus.contains(&old_worker_0));
        assert!(!allowed_cpus.contains(&old_worker_1));
        let new_worker_0 =
            nth_allowed_cpu(0, &is_set, &mut buf).expect("allowed mask is non-empty");
        let new_worker_1 =
            nth_allowed_cpu(1, &is_set, &mut buf).expect("allowed mask is non-empty");
        assert!(allowed_cpus.contains(&new_worker_0));
        assert!(allowed_cpus.contains(&new_worker_1));
        assert_ne!(old_worker_0, new_worker_0);
        assert_ne!(old_worker_1, new_worker_1);
    }
}

#[cfg(test)]
mod warmer_tests {
    use super::*;
    use std::time::Duration;

    fn active_rg(rg_id: i32) -> Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>> {
        let now_secs = monotonic_nanos() / 1_000_000_000;
        Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
            rg_id,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        )])))
    }

    fn warm_item(generation: u64, rg_id: i32) -> WarmItem {
        WarmItem {
            // Use an interface name that will not resolve so
            // trigger_kernel_arp_probe is a cheap no-op even without
            // CAP_NET_RAW; the observable effect we assert is the
            // last_probed_at insertion.
            ifindex: 999,
            hop: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            iface_name: "xpf-test-nodev".to_string(),
            generation,
            rg_id,
        }
    }

    fn spawn_loop(
        rx: Receiver<WarmItem>,
        last_probed: Arc<Mutex<FastMap<(i32, IpAddr), u64>>>,
        warm_generation: Arc<AtomicU64>,
        rg_runtime: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            neighbor_warmer_loop(rx, last_probed, warm_generation, rg_runtime, stop)
        })
    }

    fn wait_for<F: Fn() -> bool>(pred: F) -> bool {
        for _ in 0..200 {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn warmer_processes_message_and_records_probe() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(7));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        tx.try_send(warm_item(7, 0)).expect("send");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(
            wait_for(|| last_probed.lock().unwrap().contains_key(&key)),
            "warmer must record the probed key in last_probed_at",
        );
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_drops_stale_generation_items() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(10));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        // Item tagged with an OLD generation (current is 10).
        tx.try_send(warm_item(3, 0)).expect("send stale");
        // Then a current-gen item to act as a barrier we CAN observe.
        tx.try_send(warm_item(10, 0)).expect("send current");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(
            wait_for(|| last_probed.lock().unwrap().contains_key(&key)),
            "current-gen item must be processed",
        );
        // Exactly one insertion total (stale dropped, current recorded);
        // the per-key 5s rate-limit also coalesces, so len stays 1.
        assert_eq!(last_probed.lock().unwrap().len(), 1);
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_skips_inactive_rg_items() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(1));
        // RG runtime has RG 0 active, but the item targets RG 5 (absent).
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        tx.try_send(warm_item(1, 5)).expect("send inactive-rg");
        // Give the worker time to process and discard it.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            last_probed.lock().unwrap().is_empty(),
            "item for a non-forwarding-active RG must not be probed",
        );
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }

    #[test]
    fn warmer_exits_on_disconnect() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(0));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed, warm_generation, rg, stop);
        // Drop the sender WITHOUT setting stop: the recv_timeout must see
        // Disconnected and the loop must exit on its own.
        drop(tx);
        handle.join().expect("warmer must exit cleanly on channel disconnect");
    }

    #[test]
    fn warmer_per_key_rate_limit_coalesces() {
        let (tx, rx) = mpsc::sync_channel::<WarmItem>(8);
        let last_probed = Arc::new(Mutex::new(FastMap::default()));
        let warm_generation = Arc::new(AtomicU64::new(1));
        let rg = active_rg(0);
        let stop = Arc::new(AtomicBool::new(false));
        let handle = spawn_loop(rx, last_probed.clone(), warm_generation.clone(), rg, stop.clone());

        // Same key sent twice within the 5s window → one recorded probe.
        tx.try_send(warm_item(1, 0)).expect("send 1");
        tx.try_send(warm_item(1, 0)).expect("send 2");
        let key = (999, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert!(wait_for(|| last_probed.lock().unwrap().contains_key(&key)));
        // The recorded timestamp must not change on the second (rate-
        // limited) item — assert the map stays at one entry.
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(last_probed.lock().unwrap().len(), 1);
        stop.store(true, Ordering::Relaxed);
        drop(tx);
        handle.join().expect("warmer join");
    }
}
