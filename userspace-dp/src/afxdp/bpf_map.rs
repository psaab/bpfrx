use super::*;

fn uses_kernel_local_session_map_entry(
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> bool {
    metadata.synced
        && !metadata.is_reverse
        && decision.resolution.disposition == ForwardingDisposition::LocalDelivery
        && decision.resolution.tunnel_endpoint_id == 0
}

pub(super) fn diagnose_raw_ring_state(
    sock_fd: c_int,
) -> Option<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    // SOL_XDP = 283, XDP_MMAP_OFFSETS = 1
    const SOL_XDP: i32 = 283;
    const XDP_MMAP_OFFSETS: i32 = 1;
    const XDP_PGOFF_RX_RING: i64 = 0;
    const XDP_PGOFF_TX_RING: i64 = 0x80000000;
    const XDP_UMEM_PGOFF_FILL_RING: i64 = 0x100000000;
    const XDP_UMEM_PGOFF_COMPLETION_RING: i64 = 0x180000000;

    // xdp_mmap_offsets_v2 (kernel >= 5.4): 4 rings × 4 fields × u64 each
    #[repr(C)]
    #[derive(Default)]
    struct XdpRingOffset {
        producer: u64,
        consumer: u64,
        desc: u64,
        flags: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct XdpMmapOffsets {
        rx: XdpRingOffset,
        tx: XdpRingOffset,
        fr: XdpRingOffset,
        cr: XdpRingOffset,
    }

    let mut off = XdpMmapOffsets::default();
    let mut optlen = core::mem::size_of::<XdpMmapOffsets>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock_fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            (&mut off as *mut XdpMmapOffsets).cast::<libc::c_void>(),
            &mut optlen,
        )
    };
    if rc != 0 {
        return None;
    }

    fn read_ring_pair(sock_fd: c_int, off: &XdpRingOffset, pgoff: i64) -> (u32, u32) {
        let map_len = (off.desc.max(off.consumer).max(off.producer) + 8) as usize;
        let mmap_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                map_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                sock_fd,
                pgoff,
            )
        };
        if mmap_ptr == libc::MAP_FAILED {
            return (0, 0);
        }
        let prod = unsafe { *(mmap_ptr.byte_add(off.producer as usize) as *const u32) };
        let cons = unsafe { *(mmap_ptr.byte_add(off.consumer as usize) as *const u32) };
        unsafe { libc::munmap(mmap_ptr, map_len) };
        (prod, cons)
    }

    let (rx_prod, rx_cons) = read_ring_pair(sock_fd, &off.rx, XDP_PGOFF_RX_RING);
    let (fr_prod, fr_cons) = read_ring_pair(sock_fd, &off.fr, XDP_UMEM_PGOFF_FILL_RING);
    let (tx_prod, tx_cons) = read_ring_pair(sock_fd, &off.tx, XDP_PGOFF_TX_RING);
    let (cr_prod, cr_cons) = read_ring_pair(sock_fd, &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING);

    Some((
        rx_prod, rx_cons, fr_prod, fr_cons, tx_prod, tx_cons, cr_prod, cr_cons,
    ))
}

pub(super) fn register_xsk_slot(map_fd: c_int, slot: u32, sock_fd: c_int) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&sock_fd as *const c_int).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn update_heartbeat_slot(map_fd: c_int, slot: u32, timestamp_ns: u64) -> io::Result<()> {
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&slot as *const u32).cast::<c_void>(),
            (&timestamp_ns as *const u64).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn delete_xsk_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn delete_heartbeat_slot(map_fd: c_int, slot: u32) -> io::Result<()> {
    let rc =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, (&slot as *const u32).cast::<c_void>()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn maybe_touch_heartbeat(binding: &mut BindingWorker, now_ns: u64) {
    // The fill ring is primed before bind, so the driver's initial NAPI
    // posts WQEs immediately. All queues should be ready to receive.
    // No xsk_rx_confirmed gating needed.
    let age_ns = now_ns.saturating_sub(binding.last_heartbeat_update_ns);
    if age_ns < HEARTBEAT_UPDATE_INTERVAL_NS {
        return;
    }
    match touch_heartbeat(
        binding.heartbeat_map_fd,
        binding.slot,
        &binding.live,
        now_ns,
    ) {
        Ok(()) => {
            if cfg!(feature = "debug-log") {
                thread_local! {
                    static HB_LOG_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
                }
                let age_ms = age_ns / 1_000_000;
                if age_ms > 1000 {
                    debug_log!(
                        "HB_UPDATE slot={} fd={} age={}ms now_ns={} LATE",
                        binding.slot,
                        binding.heartbeat_map_fd,
                        age_ms,
                        now_ns,
                    );
                }
                HB_LOG_COUNT.with(|c| {
                    let n = c.get();
                    if n < 5 {
                        c.set(n + 1);
                        debug_log!(
                            "HB_UPDATE[{}] slot={} fd={} age={}ms now_ns={} OK",
                            n,
                            binding.slot,
                            binding.heartbeat_map_fd,
                            age_ms,
                            now_ns,
                        );
                    }
                });
            }
            binding.last_heartbeat_update_ns = now_ns;
        }
        Err(err) => {
            eprintln!(
                "HB_UPDATE_ERR slot={} fd={} age={}ms err={}",
                binding.slot,
                binding.heartbeat_map_fd,
                age_ns / 1_000_000,
                err,
            );
            binding
                .live
                .set_error(format!("update heartbeat slot: {err}"));
        }
    }
}

pub(super) fn touch_heartbeat(
    map_fd: c_int,
    slot: u32,
    live: &BindingLiveState,
    now_ns: u64,
) -> io::Result<()> {
    update_heartbeat_slot(map_fd, slot, now_ns)?;
    live.set_last_heartbeat_at(now_ns);
    Ok(())
}

pub(super) fn heartbeat_fresh(last_heartbeat: Option<chrono::DateTime<Utc>>) -> bool {
    match last_heartbeat {
        Some(last) => Utc::now()
            .signed_duration_since(last)
            .to_std()
            .map(|age| age <= HEARTBEAT_STALE_AFTER)
            .unwrap_or(true),
        None => false,
    }
}

pub(super) struct OwnedFd {
    pub(super) fd: c_int,
}

impl OwnedFd {
    pub(super) fn open_bpf_map(path: &str) -> io::Result<Self> {
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid map path"))?;
        let fd = unsafe { libbpf_sys::bpf_obj_get(path.as_ptr()) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        let _ = unsafe { libc::close(self.fd) };
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct UserspaceSessionMapKey {
    addr_family: u8,
    protocol: u8,
    pad: u16,
    src_port: u16,
    dst_port: u16,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

pub(super) fn session_map_key(key: &SessionKey) -> UserspaceSessionMapKey {
    fn encode_ip(ip: &IpAddr) -> [u8; 16] {
        match ip {
            IpAddr::V4(v4) => {
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => v6.octets(),
        }
    }
    UserspaceSessionMapKey {
        addr_family: key.addr_family,
        protocol: key.protocol,
        pad: 0,
        src_port: key.src_port,
        dst_port: key.dst_port,
        src_addr: encode_ip(&key.src_ip),
        dst_addr: encode_ip(&key.dst_ip),
    }
}

pub(super) fn publish_session_map_key(
    map_fd: c_int,
    key: &SessionKey,
    value: u8,
) -> io::Result<()> {
    let map_key = session_map_key(key);
    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&value as *const u8).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) fn publish_live_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_REDIRECT)
}

pub(super) fn publish_kernel_local_session_key(map_fd: c_int, key: &SessionKey) -> io::Result<()> {
    publish_session_map_key(map_fd, key, USERSPACE_SESSION_ACTION_PASS_TO_KERNEL)
}

pub(super) fn publish_live_session_entry(
    map_fd: c_int,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
) -> io::Result<()> {
    publish_live_session_key(map_fd, key)?;
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            publish_live_session_key(map_fd, &wire_key)?;
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            publish_live_session_key(map_fd, &reverse_wire)?;
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            publish_live_session_key(map_fd, &reverse_canonical)?;
        }
    }
    Ok(())
}

// ── BPF conntrack context ──

/// Optional context for mirroring sessions into the BPF conntrack maps.
/// When present, `publish_session_map_entry_for_session` and
/// `delete_session_map_entry_for_removed_session` also write/delete from
/// the kernel-visible `sessions`/`sessions_v6` maps so `show security
/// flow session` displays correct zone and interface information.
#[derive(Clone, Copy)]
pub(super) struct ConntrackCtx<'a> {
    pub(super) v4_fd: c_int,
    pub(super) v6_fd: c_int,
    pub(super) zone_name_to_id: &'a FastMap<String, u16>,
}

// ── BPF conntrack map structs (mirrors C struct session_key / session_value) ──

/// Mirrors C `struct session_key` — 16 bytes, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct BpfSessionKeyV4 {
    src_ip: [u8; 4],   // __be32, network byte order
    dst_ip: [u8; 4],   // __be32, network byte order
    src_port: u16,      // __be16, network byte order
    dst_port: u16,      // __be16, network byte order
    protocol: u8,
    pad: [u8; 3],
}

/// Mirrors C `struct session_value` — full connection state.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfSessionValueV4 {
    state: u8,
    flags: u8,
    tcp_state: u8,
    is_reverse: u8,
    app_timeout: u32,
    session_id: u64,
    created: u64,
    last_seen: u64,
    timeout: u32,
    policy_id: u32,
    ingress_zone: u16,
    egress_zone: u16,
    nat_src_ip: u32,    // __be32, native endian for BPF
    nat_dst_ip: u32,    // __be32, native endian for BPF
    nat_src_port: u16,  // __be16, network byte order
    nat_dst_port: u16,  // __be16, network byte order
    fwd_packets: u64,
    fwd_bytes: u64,
    rev_packets: u64,
    rev_bytes: u64,
    reverse_key: BpfSessionKeyV4,
    alg_type: u8,
    log_flags: u8,
    app_id: u16,
    fib_ifindex: u32,
    fib_vlan_id: u16,
    fib_dmac: [u8; 6],
    fib_smac: [u8; 6],
    fib_gen: u16,
}

/// Mirrors C `struct session_key_v6` — 40 bytes, packed.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct BpfSessionKeyV6 {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,      // __be16, network byte order
    dst_port: u16,      // __be16, network byte order
    protocol: u8,
    pad: [u8; 3],
}

/// Mirrors C `struct session_value_v6` — full connection state with 128-bit IPs.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfSessionValueV6 {
    state: u8,
    flags: u8,
    tcp_state: u8,
    is_reverse: u8,
    app_timeout: u32,
    session_id: u64,
    created: u64,
    last_seen: u64,
    timeout: u32,
    policy_id: u32,
    ingress_zone: u16,
    egress_zone: u16,
    nat_src_ip: [u8; 16],
    nat_dst_ip: [u8; 16],
    nat_src_port: u16,  // __be16, network byte order
    nat_dst_port: u16,  // __be16, network byte order
    fwd_packets: u64,
    fwd_bytes: u64,
    rev_packets: u64,
    rev_bytes: u64,
    reverse_key: BpfSessionKeyV6,
    alg_type: u8,
    log_flags: u8,
    app_id: u16,
    fib_ifindex: u32,
    fib_vlan_id: u16,
    fib_dmac: [u8; 6],
    fib_smac: [u8; 6],
    fib_gen: u16,
}

/// Session flag constants matching C SESS_FLAG_* defines.
const SESS_FLAG_SNAT: u8 = 1 << 0;
const SESS_FLAG_DNAT: u8 = 1 << 1;
/// Session state constants matching C SESS_STATE_* defines.
const SESS_STATE_ESTABLISHED: u8 = 4;

/// Write a session entry to the BPF conntrack map so `show security flow session`
/// displays correct zone and interface information for helper-managed sessions.
///
/// `conntrack_v4_fd` / `conntrack_v6_fd`: FDs for the pinned `sessions` / `sessions_v6`
/// BPF HASH maps. Pass -1 if unavailable (will be a no-op).
pub(super) fn publish_bpf_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    zone_name_to_id: &FastMap<String, u16>,
) {
    let ingress_zone_id = zone_name_to_id
        .get(metadata.ingress_zone.as_ref())
        .copied()
        .unwrap_or(0);
    let egress_zone_id = zone_name_to_id
        .get(metadata.egress_zone.as_ref())
        .copied()
        .unwrap_or(0);

    let now_secs = monotonic_nanos() / 1_000_000_000;

    let mut flags: u8 = 0;
    if decision.nat.rewrite_src.is_some() {
        flags |= SESS_FLAG_SNAT;
    }
    if decision.nat.rewrite_dst.is_some() {
        flags |= SESS_FLAG_DNAT;
    }

    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
            let bpf_key = BpfSessionKeyV4 {
                src_ip: src.octets(),
                dst_ip: dst.octets(),
                src_port: key.src_port.to_be(),
                dst_port: key.dst_port.to_be(),
                protocol: key.protocol,
                pad: [0; 3],
            };

            // Build reverse key
            let rev = reverse_session_key(key, decision.nat);
            let rev_key = match rev.src_ip {
                IpAddr::V4(rsrc) => {
                    let rdst = match rev.dst_ip {
                        IpAddr::V4(d) => d,
                        _ => return,
                    };
                    BpfSessionKeyV4 {
                        src_ip: rsrc.octets(),
                        dst_ip: rdst.octets(),
                        src_port: rev.src_port.to_be(),
                        dst_port: rev.dst_port.to_be(),
                        protocol: rev.protocol,
                        pad: [0; 3],
                    }
                }
                _ => return,
            };

            // NAT IPs: use native endian u32 (IP bytes already in network order,
            // interpret as NativeEndian per CLAUDE.md)
            let nat_src_ip = match decision.nat.rewrite_src {
                Some(IpAddr::V4(ip)) => u32::from_ne_bytes(ip.octets()),
                _ => 0,
            };
            let nat_dst_ip = match decision.nat.rewrite_dst {
                Some(IpAddr::V4(ip)) => u32::from_ne_bytes(ip.octets()),
                _ => 0,
            };
            let nat_src_port = decision.nat.rewrite_src_port.unwrap_or(0).to_be();
            let nat_dst_port = decision.nat.rewrite_dst_port.unwrap_or(0).to_be();

            let value = BpfSessionValueV4 {
                state: SESS_STATE_ESTABLISHED,
                flags,
                tcp_state: 0,
                is_reverse: if metadata.is_reverse { 1 } else { 0 },
                app_timeout: 0,
                session_id: 0,
                created: now_secs,
                last_seen: now_secs,
                timeout: 1800, // default 30min; GC owns real expiry
                policy_id: 0,
                ingress_zone: ingress_zone_id,
                egress_zone: egress_zone_id,
                nat_src_ip,
                nat_dst_ip,
                nat_src_port,
                nat_dst_port,
                fwd_packets: 0,
                fwd_bytes: 0,
                rev_packets: 0,
                rev_bytes: 0,
                reverse_key: rev_key,
                alg_type: 0,
                log_flags: 0,
                app_id: 0,
                fib_ifindex: 0,
                fib_vlan_id: 0,
                fib_dmac: [0; 6],
                fib_smac: [0; 6],
                fib_gen: 0,
            };

            let _ = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    conntrack_v4_fd,
                    (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
                    (&value as *const BpfSessionValueV4).cast::<c_void>(),
                    libbpf_sys::BPF_ANY as u64,
                )
            };
        }
        (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
            let bpf_key = BpfSessionKeyV6 {
                src_ip: src.octets(),
                dst_ip: dst.octets(),
                src_port: key.src_port.to_be(),
                dst_port: key.dst_port.to_be(),
                protocol: key.protocol,
                pad: [0; 3],
            };

            let rev = reverse_session_key(key, decision.nat);
            let rev_key = match rev.src_ip {
                IpAddr::V6(rsrc) => {
                    let rdst = match rev.dst_ip {
                        IpAddr::V6(d) => d,
                        _ => return,
                    };
                    BpfSessionKeyV6 {
                        src_ip: rsrc.octets(),
                        dst_ip: rdst.octets(),
                        src_port: rev.src_port.to_be(),
                        dst_port: rev.dst_port.to_be(),
                        protocol: rev.protocol,
                        pad: [0; 3],
                    }
                }
                _ => return,
            };

            let nat_src_ip = match decision.nat.rewrite_src {
                Some(IpAddr::V6(ip)) => ip.octets(),
                _ => [0; 16],
            };
            let nat_dst_ip = match decision.nat.rewrite_dst {
                Some(IpAddr::V6(ip)) => ip.octets(),
                _ => [0; 16],
            };
            let nat_src_port = decision.nat.rewrite_src_port.unwrap_or(0).to_be();
            let nat_dst_port = decision.nat.rewrite_dst_port.unwrap_or(0).to_be();

            let value = BpfSessionValueV6 {
                state: SESS_STATE_ESTABLISHED,
                flags,
                tcp_state: 0,
                is_reverse: if metadata.is_reverse { 1 } else { 0 },
                app_timeout: 0,
                session_id: 0,
                created: now_secs,
                last_seen: now_secs,
                timeout: 1800,
                policy_id: 0,
                ingress_zone: ingress_zone_id,
                egress_zone: egress_zone_id,
                nat_src_ip,
                nat_dst_ip,
                nat_src_port,
                nat_dst_port,
                fwd_packets: 0,
                fwd_bytes: 0,
                rev_packets: 0,
                rev_bytes: 0,
                reverse_key: rev_key,
                alg_type: 0,
                log_flags: 0,
                app_id: 0,
                fib_ifindex: 0,
                fib_vlan_id: 0,
                fib_dmac: [0; 6],
                fib_smac: [0; 6],
                fib_gen: 0,
            };

            let _ = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    conntrack_v6_fd,
                    (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
                    (&value as *const BpfSessionValueV6).cast::<c_void>(),
                    libbpf_sys::BPF_ANY as u64,
                )
            };
        }
        _ => {}
    }
}

/// Delete a session entry from the BPF conntrack map.
pub(super) fn delete_bpf_conntrack_entry(
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    key: &SessionKey,
) {
    match (key.addr_family as i32, &key.src_ip, &key.dst_ip) {
        (libc::AF_INET, IpAddr::V4(src), IpAddr::V4(dst)) if conntrack_v4_fd >= 0 => {
            let bpf_key = BpfSessionKeyV4 {
                src_ip: src.octets(),
                dst_ip: dst.octets(),
                src_port: key.src_port.to_be(),
                dst_port: key.dst_port.to_be(),
                protocol: key.protocol,
                pad: [0; 3],
            };
            let _ = unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    conntrack_v4_fd,
                    (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
                )
            };
        }
        (libc::AF_INET6, IpAddr::V6(src), IpAddr::V6(dst)) if conntrack_v6_fd >= 0 => {
            let bpf_key = BpfSessionKeyV6 {
                src_ip: src.octets(),
                dst_ip: dst.octets(),
                src_port: key.src_port.to_be(),
                dst_port: key.dst_port.to_be(),
                protocol: key.protocol,
                pad: [0; 3],
            };
            let _ = unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    conntrack_v6_fd,
                    (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
                )
            };
        }
        _ => {}
    }
}

pub(super) fn publish_session_map_entry_for_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> io::Result<()> {
    publish_session_map_entry_for_session_with_conntrack(map_fd, key, decision, metadata, None)
}

pub(super) fn publish_session_map_entry_for_session_with_conntrack(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    ct: Option<ConntrackCtx<'_>>,
) -> io::Result<()> {
    if uses_kernel_local_session_map_entry(decision, metadata) {
        publish_kernel_local_session_key(map_fd, key)?;
        // For SNATed local-delivery sessions (e.g., ICMP to an interface-NAT
        // address), the reply packet arrives with the SNAT address as
        // destination. Publish the reverse session key so the XDP shim
        // redirects reply packets to the helper for reverse-NAT processing
        // instead of passing them to the kernel where no NAT reversal exists.
        if decision.nat.rewrite_src.is_some() {
            let reverse_wire = reverse_session_key(key, decision.nat);
            if reverse_wire != *key {
                publish_live_session_key(map_fd, &reverse_wire)?;
            }
        }
        // Also mirror to conntrack for session display.
        if let Some(ctx) = ct {
            publish_bpf_conntrack_entry(ctx.v4_fd, ctx.v6_fd, key, decision, metadata, ctx.zone_name_to_id);
        }
        return Ok(());
    }
    let result = publish_live_session_entry(map_fd, key, decision.nat, metadata.is_reverse);
    // Mirror to conntrack for session display.
    if let Some(ctx) = ct {
        publish_bpf_conntrack_entry(ctx.v4_fd, ctx.v6_fd, key, decision, metadata, ctx.zone_name_to_id);
    }
    result
}

/// Verify a session key exists in the BPF map (read-back after publish).
pub(super) fn verify_session_key_in_bpf(map_fd: c_int, key: &SessionKey) -> bool {
    let map_key = session_map_key(key);
    let mut value = 0u8;
    let rc = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
            (&mut value as *mut u8).cast::<c_void>(),
        )
    };
    rc == 0
}

/// Count total entries in the BPF USERSPACE_SESSIONS map.
pub(super) fn count_bpf_session_entries(map_fd: c_int) -> u32 {
    let mut count = 0u32;
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key = vec![0u8; key_size];
    let mut next_key = vec![0u8; key_size];
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        return 0;
    }
    count += 1;
    key.copy_from_slice(&next_key);
    loop {
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key.as_ptr().cast::<c_void>(),
                next_key.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
        count += 1;
        key.copy_from_slice(&next_key);
        if count > 10000 {
            break; // safety limit
        }
    }
    count
}

/// Dump first N entries from the BPF USERSPACE_SESSIONS map for debugging.
#[allow(unused_variables)]
pub(super) fn dump_bpf_session_entries(map_fd: c_int, max_entries: u32) {
    let key_size = core::mem::size_of::<UserspaceSessionMapKey>();
    let mut key_bytes = vec![0u8; key_size];
    let mut next_key_bytes = vec![0u8; key_size];
    let mut value = 0u8;
    let mut count = 0u32;
    // First key
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map_fd,
            core::ptr::null(),
            next_key_bytes.as_mut_ptr().cast::<c_void>(),
        )
    };
    if rc != 0 {
        debug_log!("BPF_MAP_DUMP: empty (no entries)");
        return;
    }
    loop {
        // Read the key as UserspaceSessionMapKey
        let map_key: UserspaceSessionMapKey =
            unsafe { core::ptr::read(next_key_bytes.as_ptr().cast()) };
        let _ = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                map_fd,
                next_key_bytes.as_ptr().cast::<c_void>(),
                (&mut value as *mut u8).cast::<c_void>(),
            )
        };
        #[cfg(feature = "debug-log")]
        {
            let src_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[2],
                    map_key.src_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.src_addr[0],
                    map_key.src_addr[1],
                    map_key.src_addr[14],
                    map_key.src_addr[15]
                )
            };
            let dst_ip = if map_key.addr_family == libc::AF_INET as u8 {
                format!(
                    "{}.{}.{}.{}",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[2],
                    map_key.dst_addr[3]
                )
            } else {
                format!(
                    "v6[{:02x}{:02x}::{:02x}{:02x}]",
                    map_key.dst_addr[0],
                    map_key.dst_addr[1],
                    map_key.dst_addr[14],
                    map_key.dst_addr[15]
                )
            };
            debug_log!(
                "BPF_MAP_DUMP[{}]: af={} proto={} {}:{} -> {}:{} val={}",
                count,
                map_key.addr_family,
                map_key.protocol,
                src_ip,
                map_key.src_port,
                dst_ip,
                map_key.dst_port,
                value,
            );
        }
        count += 1;
        if count >= max_entries {
            break;
        }
        key_bytes.copy_from_slice(&next_key_bytes);
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                map_fd,
                key_bytes.as_ptr().cast::<c_void>(),
                next_key_bytes.as_mut_ptr().cast::<c_void>(),
            )
        };
        if rc != 0 {
            break;
        }
    }
    debug_log!("BPF_MAP_DUMP: total={count} entries");
}

pub(super) static SESSION_PUBLISH_VERIFY_OK: AtomicU64 = AtomicU64::new(0);
pub(super) static SESSION_PUBLISH_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
pub(super) static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-log")]
static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);

pub(super) const FALLBACK_STATS_PIN_PATH: &str = "/sys/fs/bpf/bpfrx/userspace_fallback_stats";
pub(super) const FALLBACK_REASON_NAMES: &[&str] = &[
    "ctrl_disabled",     // 0
    "parse_fail",        // 1
    "binding_missing",   // 2
    "binding_not_ready", // 3
    "hb_missing",        // 4
    "hb_stale",          // 5
    "icmp",              // 6
    "early_filter",      // 7
    "adjust_meta",       // 8
    "meta_bounds",       // 9
    "redirect_err",      // 10
    "iface_nat_no_sess", // 11
    "no_session",        // 12
];

pub(super) fn read_fallback_stats() -> Option<Vec<(String, u64)>> {
    let fd = OwnedFd::open_bpf_map(FALLBACK_STATS_PIN_PATH).ok()?;
    let mut result = Vec::new();
    for idx in 0u32..16 {
        let mut value = 0u64;
        let rc = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                fd.fd,
                (&idx as *const u32).cast::<c_void>(),
                (&mut value as *mut u64).cast::<c_void>(),
            )
        };
        if rc == 0 && value > 0 {
            let name = FALLBACK_REASON_NAMES
                .get(idx as usize)
                .copied()
                .unwrap_or("unknown");
            result.push((name.to_string(), value));
        }
    }
    Some(result)
}

pub(super) fn delete_live_session_key(map_fd: c_int, key: &SessionKey) {
    let map_key = session_map_key(key);
    let _ = unsafe {
        libbpf_sys::bpf_map_delete_elem(
            map_fd,
            (&map_key as *const UserspaceSessionMapKey).cast::<c_void>(),
        )
    };
}

pub(super) fn delete_live_session_entry(
    map_fd: c_int,
    key: &SessionKey,
    nat: NatDecision,
    is_reverse: bool,
) {
    delete_live_session_key(map_fd, key);
    if !is_reverse {
        let wire_key = forward_wire_key(key, nat);
        if wire_key != *key {
            delete_live_session_key(map_fd, &wire_key);
        }
        let reverse_wire = reverse_session_key(key, nat);
        if reverse_wire != *key {
            delete_live_session_key(map_fd, &reverse_wire);
        }
        let reverse_canonical = reverse_canonical_key(key, nat);
        if reverse_canonical != *key && reverse_canonical != reverse_wire {
            delete_live_session_key(map_fd, &reverse_canonical);
        }
    }
}

pub(super) fn delete_session_map_entry_for_removed_session(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) {
    delete_session_map_entry_for_removed_session_with_conntrack(map_fd, key, decision, metadata, -1, -1);
}

pub(super) fn delete_session_map_entry_for_removed_session_with_conntrack(
    map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
) {
    if uses_kernel_local_session_map_entry(decision, metadata) {
        delete_live_session_key(map_fd, key);
        // Also delete the reverse-wire alias published for SNATed
        // kernel-local sessions (see publish_session_map_entry_for_session).
        if decision.nat.rewrite_src.is_some() {
            let reverse_wire = reverse_session_key(key, decision.nat);
            if reverse_wire != *key {
                delete_live_session_key(map_fd, &reverse_wire);
            }
        }
        delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, key);
        return;
    }
    delete_live_session_entry(map_fd, key, decision.nat, metadata.is_reverse);
    delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, key);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_delivery_decision(tunnel_endpoint_id: u16) -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        }
    }

    fn synced_forward_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: Arc::<str>::from("trust"),
            egress_zone: Arc::<str>::from("trust"),
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            synced: true,
            nat64_reverse: None,
        }
    }

    #[test]
    fn kernel_local_session_map_entry_requires_zero_tunnel_endpoint() {
        let metadata = synced_forward_metadata();
        assert!(uses_kernel_local_session_map_entry(
            local_delivery_decision(0),
            &metadata
        ));
        assert!(!uses_kernel_local_session_map_entry(
            local_delivery_decision(7),
            &metadata
        ));
    }

    #[test]
    fn kernel_local_session_map_entry_rejects_non_kernel_local_cases() {
        let mut metadata = synced_forward_metadata();
        assert!(!uses_kernel_local_session_map_entry(
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    ..local_delivery_decision(0).resolution
                },
                nat: NatDecision::default(),
            },
            &metadata
        ));

        metadata.synced = false;
        assert!(!uses_kernel_local_session_map_entry(
            local_delivery_decision(0),
            &metadata
        ));

        metadata.synced = true;
        metadata.is_reverse = true;
        assert!(!uses_kernel_local_session_map_entry(
            local_delivery_decision(0),
            &metadata
        ));
    }

    #[test]
    fn bpf_conntrack_struct_sizes_match_c() {
        // Must match C struct sizes from bpfrx_conntrack.h exactly.
        assert_eq!(core::mem::size_of::<BpfSessionKeyV4>(), 16);
        assert_eq!(core::mem::size_of::<BpfSessionValueV4>(), 128);
        assert_eq!(core::mem::size_of::<BpfSessionKeyV6>(), 40);
        assert_eq!(core::mem::size_of::<BpfSessionValueV6>(), 176);
    }
}
