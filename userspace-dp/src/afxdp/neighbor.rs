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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    ifindex: i32,
    ip: IpAddr,
    entry: NeighborEntry,
) -> bool {
    let Ok(mut neighbors) = dynamic_neighbors.lock() else {
        return false;
    };
    let key = (ifindex, ip);
    if neighbors.get(&key).map(|existing| existing.mac) == Some(entry.mac) {
        return false;
    }
    neighbors.insert(key, entry);
    true
}

pub(super) fn remove_dynamic_neighbor(
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    ifindex: i32,
    ip: IpAddr,
) -> bool {
    let Ok(mut neighbors) = dynamic_neighbors.lock() else {
        return false;
    };
    neighbors.remove(&(ifindex, ip)).is_some()
}

pub(super) fn parse_neighbor_msg(
    nlmsg_type: u16,
    body: &[u8],
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    dynamic_neighbors: Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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

pub(super) fn pin_current_thread(worker_id: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        let cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let cpu = (worker_id as usize) % cpus.max(1);
        let mut set: libc::cpu_set_t = core::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
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
