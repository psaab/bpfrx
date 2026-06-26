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
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use core::ffi::{c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// `security alg <proto> disable` bitfield (#2008 H3/H4). Mirrors the Go
// `algDisableFlags` encoding and the legacy flow_config_map ALGFlags layout.
const ALG_DISABLE_DNS: u8 = 0x01;
const ALG_DISABLE_FTP: u8 = 0x02;
const ALG_DISABLE_SIP: u8 = 0x04;
// TFTP's disable bit is carried on the wire for layout parity with the Go
// `algDisableFlags` packer (DNS 0x01 / FTP 0x02 / SIP 0x04 / TFTP 0x08), but
// it has no consumer here: the dataplane has no TFTP conntrack alg_type to
// suppress (`alg_type` is one of none/FTP/SIP/DNS — see xpf_conntrack.h), so
// `alg_type_for_session` never reads this bit. Defined to document the full
// bit layout consistently across Go and Rust; intentionally unused.
#[allow(dead_code)]
const ALG_DISABLE_TFTP: u8 = 0x08;

// alg_type codes written into the conntrack session value, matching
// bpf/headers/xpf_conntrack.h: 0=none, 1=FTP, 2=SIP, 3=DNS.
const ALG_TYPE_NONE: u8 = 0;
const ALG_TYPE_FTP: u8 = 1;
const ALG_TYPE_SIP: u8 = 2;
const ALG_TYPE_DNS: u8 = 3;

/// Derive the conntrack `alg_type` for a session from its forward 5-tuple,
/// honouring the `security alg <proto> disable` bitfield (#2008 H3/H4).
///
/// Previously `alg_type` was hardcoded to 0, so the `alg disable` knob had
/// zero runtime effect: it parsed and compiled into `flow_config_map` but no
/// reader consumed it. This derives the ALG type from the well-known service
/// port (FTP TCP/21, SIP UDP+TCP/5060, DNS UDP/53) UNLESS the matching ALG is
/// disabled, in which case the session is tagged `none` (0) — exactly the
/// Junos semantics of `alg disable` (the ALG is turned off; traffic is NOT
/// dropped). The service port is the destination port for a forward session;
/// the reverse direction's source port mirrors it, so both directions of an
/// ALG session resolve to the same type.
pub(super) fn alg_type_for_session(protocol: u8, src_port: u16, dst_port: u16, disable: u8) -> u8 {
    // The well-known ALG service port can appear as either the forward dst
    // (client -> server) or, for a session keyed in the reverse direction,
    // the src. Treat a match on either port slot as the same ALG.
    let on_port = |p: u16| src_port == p || dst_port == p;
    match protocol {
        PROTO_UDP if on_port(53) => {
            if disable & ALG_DISABLE_DNS != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_DNS
            }
        }
        PROTO_TCP if on_port(21) => {
            if disable & ALG_DISABLE_FTP != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_FTP
            }
        }
        PROTO_UDP | PROTO_TCP if on_port(5060) => {
            if disable & ALG_DISABLE_SIP != 0 {
                ALG_TYPE_NONE
            } else {
                ALG_TYPE_SIP
            }
        }
        _ => ALG_TYPE_NONE,
    }
}

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
    alg_disable_flags: u8,
    app_id: u16,
) {
    let alg_type =
        alg_type_for_session(key.protocol, key.src_port, key.dst_port, alg_disable_flags);
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
        // #3056: the admitting policy's ID, stamped on the session at install.
        // The Go session-row surfaces (`show security flow session`, REST,
        // gRPC) read this slot as `val.PolicyID` and resolve a policy name from
        // it; it was hardcoded `0`, which the Go side renders as the FIRST
        // configured policy (a wrong attribution). `0` stays the value for
        // non-policy-forwarded sessions (their metadata carries `policy_id: 0`).
        policy_id: metadata.policy_id,
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
        alg_type,
        log_flags: 0,
        app_id,
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
    alg_disable_flags: u8,
    app_id: u16,
) {
    let alg_type =
        alg_type_for_session(key.protocol, key.src_port, key.dst_port, alg_disable_flags);
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
        // #3056: see publish_v4_session — stamp the admitting policy ID so the
        // IPv6 live-session rows attribute the policy that admitted the flow.
        policy_id: metadata.policy_id,
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
        alg_type,
        log_flags: 0,
        app_id,
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

#[cfg(test)]
mod alg_type_tests {
    use super::{
        ALG_DISABLE_DNS, ALG_DISABLE_FTP, ALG_DISABLE_SIP, ALG_TYPE_DNS, ALG_TYPE_FTP,
        ALG_TYPE_NONE, ALG_TYPE_SIP, PROTO_TCP, PROTO_UDP, alg_type_for_session,
    };

    // #2008 H3/H4: with no ALG disabled, a session on a well-known ALG
    // service port is tagged with its ALG type. The service port is the
    // forward destination port (client -> server).
    #[test]
    fn dns_session_tagged_when_alg_enabled() {
        // UDP/53 client (ephemeral src) -> server.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, 0),
            ALG_TYPE_DNS,
            "DNS session must be tagged DNS when the DNS ALG is enabled"
        );
    }

    #[test]
    fn ftp_session_tagged_when_alg_enabled() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, 0),
            ALG_TYPE_FTP,
            "FTP session must be tagged FTP when the FTP ALG is enabled"
        );
    }

    #[test]
    fn sip_session_tagged_when_alg_enabled() {
        assert_eq!(alg_type_for_session(PROTO_UDP, 5060, 5060, 0), ALG_TYPE_SIP);
        assert_eq!(alg_type_for_session(PROTO_TCP, 40000, 5060, 0), ALG_TYPE_SIP);
    }

    // The enforcement under test (#2008 H3): when `security alg dns disable`
    // is set, the DNS-disable bit (0x01) MUST suppress the DNS ALG type — the
    // session is tagged `none`. This is the bit the audit found was written to
    // flow_config_map but never read. If the flag read is removed from
    // alg_type_for_session, this assertion regresses to ALG_TYPE_DNS.
    #[test]
    fn dns_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, ALG_DISABLE_DNS),
            ALG_TYPE_NONE,
            "`security alg dns disable` must turn the DNS ALG off (alg_type=none)"
        );
    }

    // #2008 H4: `security alg ftp disable` -> FTP-disable bit (0x02) suppresses
    // the FTP ALG type for TCP/21 sessions.
    #[test]
    fn ftp_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, ALG_DISABLE_FTP),
            ALG_TYPE_NONE,
            "`security alg ftp disable` must turn the FTP ALG off (alg_type=none)"
        );
    }

    #[test]
    fn sip_session_not_tagged_when_alg_disabled() {
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 5060, 5060, ALG_DISABLE_SIP),
            ALG_TYPE_NONE,
            "`security alg sip disable` must turn the SIP ALG off (alg_type=none)"
        );
    }

    // Disabling one ALG must NOT affect another: with only DNS disabled, an
    // FTP session is still tagged FTP (proves the bits are read independently,
    // not as an all-or-nothing gate).
    #[test]
    fn disabling_dns_does_not_affect_ftp() {
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 51000, 21, ALG_DISABLE_DNS),
            ALG_TYPE_FTP
        );
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 41234, 53, ALG_DISABLE_FTP),
            ALG_TYPE_DNS
        );
    }

    // A session keyed in the REVERSE direction carries the well-known ALG
    // service port in the SRC slot (server -> client), not the dst. The
    // `on_port` helper checks `src_port == p || dst_port == p`, so the ALG
    // type must still resolve. Both directions of one ALG session map to the
    // same alg_type, which is required for the reverse conntrack entry the
    // publisher installs alongside the forward entry.
    #[test]
    fn dns_reverse_keyed_session_tagged_on_src_port() {
        // UDP 53 (server) -> ephemeral (client): well-known port in src slot.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 53, 41234, 0),
            ALG_TYPE_DNS,
            "reverse-keyed DNS session must match the well-known port on the src slot"
        );
        // The disable bit still suppresses it in the reverse direction.
        assert_eq!(
            alg_type_for_session(PROTO_UDP, 53, 41234, ALG_DISABLE_DNS),
            ALG_TYPE_NONE,
            "`security alg dns disable` must apply to reverse-keyed sessions too"
        );
    }

    #[test]
    fn ftp_reverse_keyed_session_tagged_on_src_port() {
        // TCP 21 (server) -> ephemeral (client): well-known port in src slot.
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 21, 51000, 0),
            ALG_TYPE_FTP,
            "reverse-keyed FTP session must match the well-known port on the src slot"
        );
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 21, 51000, ALG_DISABLE_FTP),
            ALG_TYPE_NONE,
            "`security alg ftp disable` must apply to reverse-keyed sessions too"
        );
    }

    // Junos `alg disable` turns the ALG OFF; it never drops traffic. The
    // dataplane has no DNS/FTP ALG transform, so a disabled ALG is simply not
    // tagged — non-ALG ports are always `none` regardless of the flags.
    #[test]
    fn non_alg_port_is_always_none() {
        assert_eq!(alg_type_for_session(PROTO_TCP, 12345, 443, 0), ALG_TYPE_NONE);
        assert_eq!(
            alg_type_for_session(PROTO_TCP, 12345, 443, 0xff),
            ALG_TYPE_NONE
        );
        // Wrong protocol on an ALG port (e.g. TCP/53) is not the DNS ALG.
        assert_eq!(alg_type_for_session(PROTO_TCP, 41234, 53, 0), ALG_TYPE_NONE);
    }
}
