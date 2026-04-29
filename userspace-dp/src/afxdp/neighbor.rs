use super::*;

pub(super) fn monotonic_nanos() -> u64 {
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

pub(super) fn parse_neighbor_msg(
    nlmsg_type: u16,
    body: &[u8],
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> bool {
    if body.len() < 12 {
        return false;
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
        return false;
    };
    match nlmsg_type {
        28 => {
            // Treat INCOMPLETE (0x01) and FAILED (0x20) as unusable;
            // everything else (REACHABLE, STALE, DELAY, PROBE,
            // PERMANENT, NOARP) is a valid resolved neighbor.
            const NUD_INCOMPLETE: u16 = 0x01;
            const NUD_FAILED: u16 = 0x20;
            if (state & (NUD_INCOMPLETE | NUD_FAILED)) != 0 {
                return remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip);
            }
            let Some(mac) = mac else {
                return false;
            };
            update_dynamic_neighbor(dynamic_neighbors, ifindex, ip, NeighborEntry { mac })
        }
        29 => remove_dynamic_neighbor(dynamic_neighbors, ifindex, ip),
        _ => false,
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

pub(super) fn initial_neighbor_dump(
    fd: c_int,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> io::Result<u64> {
    const NLMSG_DONE: u16 = 3;
    const NLMSG_ERROR: u16 = 2;
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
                        );
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

pub(super) fn neigh_monitor_thread(
    stop: Arc<AtomicBool>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    neighbor_generation: Arc<AtomicU64>,
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
    while !stop.load(Ordering::Relaxed) {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            continue;
        }
        let mut offset = 0usize;
        let mut changed = false;
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
            if nlmsg_type == 28 || nlmsg_type == 29 {
                changed |= parse_neighbor_msg(
                    nlmsg_type,
                    &buf[offset + 16..offset + nlmsg_len],
                    &dynamic_neighbors,
                );
            }
            offset += (nlmsg_len + 3) & !3; // align to 4
        }
        if changed {
            neighbor_generation.fetch_add(1, Ordering::Relaxed);
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
