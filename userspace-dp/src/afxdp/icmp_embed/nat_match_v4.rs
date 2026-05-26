use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v4};
use super::return_resolution::embedded_icmp_return_resolution;

/// IPv4-outer branch of `try_embedded_icmp_nat_match_from_frame`.
/// Mirrors `icmp_embed.rs:210-332` literally. Tries the forward-NAT
/// (rewrite-aware) lookup first; on miss falls back to a plain
/// session lookup in either direction.
pub(in crate::afxdp::icmp_embed) fn match_outer_v4(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let embedded_ip_start = l4 + 8;

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

    // Forward-NAT-by-reverse path: the embedded packet matches the
    // reply direction of a forward-NAT'd session. Recover the original
    // pre-NAT src + port from the forward key.
    if let Some(fwd) =
        lookup_forward_nat_across_scopes(ctx.sessions, ctx.shared_nat_sessions, &reverse_key)
    {
        let nat = fwd.decision.nat;
        let original_src = fwd.key.src_ip;
        let original_src_port = fwd.key.src_port;
        let resolution = embedded_icmp_return_resolution(
            ctx,
            &fwd.key,
            fwd.decision,
            original_src,
            now_ns,
        );
        return Some(EmbeddedIcmpMatch {
            nat,
            original_src,
            original_src_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: fwd.metadata,
        });
    }

    // Session-fallback path: look up the embedded packet as-is or in
    // reverse. If the matched entry is the reverse direction, its
    // resolution already points back to the client; otherwise resolve
    // the return path via embedded_icmp_return_resolution.
    lookup_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &embedded_key,
        now_ns,
        0,
    )
    .or_else(|| {
        lookup_session_across_scopes(
            ctx.sessions,
            ctx.shared_sessions,
            ctx.shared_forward_wire_sessions,
            &reverse_key,
            now_ns,
            0,
        )
    })
    .map(|resolved| {
        let sl = resolved.lookup;
        let resolution = if sl.metadata.is_reverse {
            sl.decision.resolution
        } else {
            embedded_icmp_return_resolution(ctx, &embedded_key, sl.decision, emb_src, now_ns)
        };
        EmbeddedIcmpMatch {
            nat: sl.decision.nat,
            original_src: emb_src,
            original_src_port: hdr.src_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: sl.metadata,
        }
    })
}
