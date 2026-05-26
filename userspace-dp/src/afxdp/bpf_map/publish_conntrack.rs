// Per-address-family publish helpers for `publish_bpf_conntrack_entry`.
//
// Pure code motion out of `bpf_map/mod.rs`: the v4 and v6 arms of the
// original 204-LOC orchestrator now live in `publish_v4_session` and
// `publish_v6_session`. The orchestrator (`publish_bpf_conntrack_entry`)
// stays in the parent module and dispatches by address family.
//
// Both helpers preserve the original side-effect contract:
//   - construct `BpfSessionKey*` from the forward 5-tuple
//   - construct a reverse key via `reverse_session_key()`; on a
//     cross-family reverse-key result, the helper returns early and
//     skips the BPF write entirely (same observable effect as the
//     pre-refactor early returns at the orchestrator level)
//   - populate `BpfSessionValue*` with state, flags, zones, NAT IPs/ports,
//     and the reverse key
//   - `bpf_map_update_elem` with `BPF_ANY`
//   - on failure, `eprintln!("xpf-ha: conntrack vN map update failed: …")`
//
// See #1356.

use super::{
    BpfSessionKeyV4, BpfSessionKeyV6, BpfSessionValueV4, BpfSessionValueV6, SESS_STATE_ESTABLISHED,
    SessionDecision, SessionKey, SessionMetadata, reverse_session_key,
};
use core::ffi::{c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn publish_v4_session(
    conntrack_v4_fd: c_int,
    key: &SessionKey,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u8,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
) {
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
        timeout: 1800, // default 30min; Go GC is SkipSweep'd, helper owns lifetime (#333)
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

    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            conntrack_v4_fd,
            (&bpf_key as *const BpfSessionKeyV4).cast::<c_void>(),
            (&value as *const BpfSessionValueV4).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        eprintln!(
            "xpf-ha: conntrack v4 map update failed: {}",
            io::Error::last_os_error()
        );
    }
}

pub(super) fn publish_v6_session(
    conntrack_v6_fd: c_int,
    key: &SessionKey,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flags: u8,
    ingress_zone_id: u16,
    egress_zone_id: u16,
    now_secs: u64,
) {
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

    let rc = unsafe {
        libbpf_sys::bpf_map_update_elem(
            conntrack_v6_fd,
            (&bpf_key as *const BpfSessionKeyV6).cast::<c_void>(),
            (&value as *const BpfSessionValueV6).cast::<c_void>(),
            libbpf_sys::BPF_ANY as u64,
        )
    };
    if rc < 0 {
        eprintln!(
            "xpf-ha: conntrack v6 map update failed: {}",
            io::Error::last_os_error()
        );
    }
}
