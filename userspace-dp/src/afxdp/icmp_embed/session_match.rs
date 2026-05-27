use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v4, parse_embedded_v6};

/// Core embedded ICMP session match logic operating on a frame slice.
/// Returns the session lookup if found. Unlike the NAT variant, this
/// path does not extract NAT reversal info — it only confirms a match
/// exists. Used by callers that need plain session presence.
pub(in crate::afxdp::icmp_embed) fn try_embedded_icmp_session_match_from_frame(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sessions: &mut SessionTable,
    now_ns: u64,
) -> Option<SessionLookup> {
    let l4 = meta.l4_offset as usize;

    let icmp_type = *frame.get(l4)?;
    if !is_icmp_error(meta.protocol, icmp_type) {
        return None;
    }

    let embedded_ip_start = l4 + 8;

    match meta.protocol {
        PROTO_ICMP => {
            let hdr = parse_embedded_v4(frame, embedded_ip_start)?;
            let emb_src = IpAddr::V4(hdr.src);
            let emb_dst = IpAddr::V4(hdr.dst);
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: hdr.proto,
                src_ip: emb_src,
                dst_ip: emb_dst,
                src_port: hdr.src_port,
                dst_port: hdr.dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET as u8,
                hdr.proto,
                emb_src,
                emb_dst,
                hdr.src_port,
                hdr.dst_port,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        PROTO_ICMPV6 => {
            let hdr = parse_embedded_v6(frame, embedded_ip_start)?;
            let emb_src = IpAddr::V6(hdr.src_wire);
            let embedded_key = SessionKey {
                addr_family: libc::AF_INET6 as u8,
                protocol: hdr.proto,
                src_ip: emb_src,
                dst_ip: hdr.dst,
                src_port: hdr.src_port,
                dst_port: hdr.dst_port,
            };
            let reverse_key = embedded_reply_key(
                libc::AF_INET6 as u8,
                hdr.proto,
                emb_src,
                hdr.dst,
                hdr.src_port,
                hdr.dst_port,
            );
            lookup_embedded_session(sessions, &embedded_key, &reverse_key, now_ns)
        }
        _ => None,
    }
}

fn lookup_embedded_session(
    sessions: &mut SessionTable,
    embedded_key: &SessionKey,
    reverse_key: &SessionKey,
    now_ns: u64,
) -> Option<SessionLookup> {
    sessions
        .lookup(embedded_key, now_ns, 0)
        .or_else(|| sessions.lookup(reverse_key, now_ns, 0))
        .or_else(|| {
            sessions
                .find_forward_nat_match(reverse_key)
                .map(|m| SessionLookup {
                    decision: m.decision,
                    metadata: m.metadata,
                })
        })
}
