use super::*;
use super::parse::{embedded_reply_key, parse_embedded_v6};
use super::return_resolution::embedded_icmp_return_resolution;

/// IPv6-outer branch of `try_embedded_icmp_nat_match_from_frame`.
/// Mirrors `icmp_embed.rs:333-455` literally. The NPTv6 inbound
/// translation is applied AT THIS CALL SITE on a local copy of
/// `hdr.src_wire`. The wire source is preserved for the forward-NAT
/// reverse key; the translated source is used for embedded_key and
/// for the shared_reverse_key inside the fallback branch.
pub(in crate::afxdp::icmp_embed) fn match_outer_v6(
    frame: &[u8],
    meta: UserspaceDpMeta,
    ctx: &mut NatMatchCtx<'_>,
    now_ns: u64,
) -> Option<EmbeddedIcmpMatch> {
    let l4 = meta.l4_offset as usize;
    let embedded_ip_start = l4 + 8;

    let hdr = parse_embedded_v6(frame, embedded_ip_start)?;

    // NPTv6 inbound translation: applied at the call site, not in the
    // parser. Preserves the wire-vs-translated asymmetry that the
    // forward-NAT reverse_key (uses wire) and the shared_reverse_key
    // (uses translated) depend on. Mirrors icmp_embed.rs:358-360.
    let mut emb_src_lookup_v6 = hdr.src_wire;
    let _nptv6_reverse = ctx.forwarding.nptv6.translate_inbound(&mut emb_src_lookup_v6);
    let emb_src_lookup = IpAddr::V6(emb_src_lookup_v6);

    let embedded_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: hdr.proto,
        src_ip: emb_src_lookup,
        dst_ip: hdr.dst,
        src_port: hdr.src_port,
        dst_port: hdr.dst_port,
    };
    // reverse_key for the forward-NAT lookup uses the WIRE source.
    // Mirrors icmp_embed.rs:369-376.
    let reverse_key = embedded_reply_key(
        libc::AF_INET6 as u8,
        hdr.proto,
        IpAddr::V6(hdr.src_wire),
        hdr.dst,
        hdr.src_port,
        hdr.dst_port,
    );

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

    // Session-fallback path. Inside .or_else we build a SECOND reverse
    // key — this time using the TRANSLATED emb_src_lookup, mirroring
    // icmp_embed.rs:412-419 (shared_reverse_key).
    lookup_session_across_scopes(
        ctx.sessions,
        ctx.shared_sessions,
        ctx.shared_forward_wire_sessions,
        &embedded_key,
        now_ns,
        0,
    )
    .or_else(|| {
        let shared_reverse_key = embedded_reply_key(
            libc::AF_INET6 as u8,
            hdr.proto,
            emb_src_lookup,
            hdr.dst,
            hdr.src_port,
            hdr.dst_port,
        );
        lookup_session_across_scopes(
            ctx.sessions,
            ctx.shared_sessions,
            ctx.shared_forward_wire_sessions,
            &shared_reverse_key,
            now_ns,
            0,
        )
    })
    .map(|resolved| {
        let sl = resolved.lookup;
        let resolution = if sl.metadata.is_reverse {
            sl.decision.resolution
        } else {
            embedded_icmp_return_resolution(
                ctx,
                &embedded_key,
                sl.decision,
                emb_src_lookup,
                now_ns,
            )
        };
        EmbeddedIcmpMatch {
            nat: sl.decision.nat,
            original_src: emb_src_lookup,
            original_src_port: hdr.src_port,
            embedded_proto: hdr.proto,
            resolution,
            metadata: sl.metadata,
        }
    })
}
