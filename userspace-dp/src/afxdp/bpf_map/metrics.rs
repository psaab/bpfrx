// Telemetry / ring-metrics publishing for the BPF session map.
//
// Pure code motion out of `bpf_map/mod.rs` (#2003): the raw XDP ring
// state probe, the USERSPACE_SESSIONS entry count/dump diagnostics, and
// the always-on / debug-gated publish counters now live here. None of
// these touch the forwarding decision; they exist purely to surface map
// occupancy and publish health to the CLI / Prometheus collectors.
//
// Behaviour-preserving: signatures, the getsockopt/mmap raw-ring probe,
// the bpf_map_get_next_key iteration, the 10000-entry safety limit, and
// the debug-log gating are unchanged from the pre-split orchestrator.
//
// Precedent: the sibling `publish_conntrack.rs` split (#1356).

use super::*;

pub(in crate::afxdp) fn diagnose_raw_ring_state(
    sock_fd: c_int,
) -> Option<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    // SOL_XDP (283) comes from afxdp/mod.rs via `use super::*` —
    // #1826 deduplicated the former local copy.
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

/// Count total entries in the BPF USERSPACE_SESSIONS map.
pub(in crate::afxdp) fn count_bpf_session_entries(map_fd: c_int) -> u32 {
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
pub(in crate::afxdp) fn dump_bpf_session_entries(map_fd: c_int, max_entries: u32) {
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

pub(in crate::afxdp) static SESSION_PUBLISH_VERIFY_OK: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static SESSION_PUBLISH_VERIFY_FAIL: AtomicU64 = AtomicU64::new(0);
/// #1789: failed USERSPACE_SESSIONS BPF-map publishes from call sites
/// that have no per-binding context (HA `upsert_synced_session`,
/// session-glue worker publishes, post-reconcile `replay_synced_sessions`,
/// activation/reverse prewarm). Always-on (NOT debug-gated, unlike the
/// VERIFY counters above which only move under `debug-log`): a swallowed
/// publish `Err` means the XDP shim never learns the key and the flow
/// takes the NO_SESSION degraded path. Per-binding worker poll sites use
/// `BindingLiveState::session_publish_errors` instead; the two are summed
/// by `Coordinator::session_publish_errors_total()` and surfaced as
/// `xpf_userspace_session_publish_errors_total`.
pub(in crate::afxdp) static SESSION_PUBLISH_ERRORS_SHARED: AtomicU64 = AtomicU64::new(0);
/// #2170 HA deferred-delete generation guard observability. These count how
/// often the helper's in-memory SyncedSessionEntry generation guard refused a
/// stale-generation install (`upsert_synced_session`, the delayed-stale-install
/// variant) or a stale-generation delete (`delete_synced_session_gen`,
/// belt-and-suspenders for any helper-side generation-aware delete). The
/// authoritative guard lives in the Go cluster apply layer; these helper-side
/// counters report any divergence/back-stop activity. Surfaced via
/// `Coordinator::session_install_stale_ignored_total()` /
/// `session_delete_stale_ignored_total()`.
pub(in crate::afxdp) static SESSION_INSTALL_STALE_IGNORED: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static SESSION_DELETE_STALE_IGNORED: AtomicU64 = AtomicU64::new(0);
pub(in crate::afxdp) static SESSION_CREATIONS_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug-log")]
pub(in crate::afxdp) static ICMPV6_EMBED_LOGGED: AtomicU32 = AtomicU32::new(0);
