// HA session-sync reconstruction helpers (#6234 split out of the
// former monolithic `server/helpers.rs`).
//
// Rebuilds a `SyncedSessionEntry` from the peer's `SessionSyncRequest`
// wire fields: the forward `SessionKey`, the MAC/next-hop parsing, and
// the #4565 NAT64 cross-family reverse-translation reconstruction. Pure
// control-response reconstruction — no packet path, no allocation on the
// worker loop. Bodies byte-for-byte identical to the pre-split source.

use crate::afxdp::{self, SyncedSessionEntry};
use crate::protocol::SessionSyncRequest;

pub(crate) fn build_synced_session_key(
    req: &SessionSyncRequest,
) -> Result<crate::session::SessionKey, String> {
    Ok(crate::session::SessionKey {
        addr_family: req.addr_family,
        protocol: req.protocol,
        src_ip: req
            .src_ip
            .parse()
            .map_err(|e| format!("parse src_ip {}: {e}", req.src_ip))?,
        dst_ip: req
            .dst_ip
            .parse()
            .map_err(|e| format!("parse dst_ip {}: {e}", req.dst_ip))?,
        src_port: req.src_port,
        dst_port: req.dst_port,
    })
}

/// #4565: reconstruct the NAT64 cross-family reverse-translation state for a
/// peer-PROMOTED synced session from the forward v6 `key` + the wire-carried
/// translated pool source `nat64_snat_v4`.
///
/// Returns `Some((snat_v4, dst_v4, Nat64ReverseInfo))` when `snat_v4_str` names
/// a valid IPv4 pool source AND the forward key is IPv6 (a NAT64 forward flow is
/// always keyed on the original IPv6 5-tuple); `None` otherwise (not NAT64 / old
/// peer / malformed). The three outputs are exactly the reverse BIB the standby
/// cannot otherwise rebuild:
///   * `snat_v4`  — the translated pool source (the one wire-carried datum).
///   * `dst_v4`   — the forward v4 destination, the RFC 6052 /96-embedded low 32
///     bits of the synthetic v6 destination `key.dst_ip` (the codebase only
///     supports `<prefix>/96`, so the embedded v4 is the trailing 4 octets).
///   * `Nat64ReverseInfo { orig_src_v6, orig_dst_v6 }` — the original v6 client
///     source and synthetic v6 destination, which ARE the forward key's src/dst.
fn build_nat64_reverse_rebuild(
    key: &crate::session::SessionKey,
    snat_v4_str: &str,
) -> Option<(
    std::net::Ipv4Addr,
    std::net::Ipv4Addr,
    crate::nat64::Nat64ReverseInfo,
)> {
    if snat_v4_str.is_empty() {
        return None;
    }
    let snat_v4: std::net::Ipv4Addr = snat_v4_str.parse().ok()?;
    // A NAT64 forward session is keyed on the original IPv6 5-tuple.
    let (std::net::IpAddr::V6(orig_src_v6), std::net::IpAddr::V6(orig_dst_v6)) =
        (key.src_ip, key.dst_ip)
    else {
        return None;
    };
    // RFC 6052 /96: the embedded IPv4 destination is the low 32 bits of the
    // synthetic IPv6 destination.
    let dst_octets = orig_dst_v6.octets();
    let dst_v4 = std::net::Ipv4Addr::new(
        dst_octets[12],
        dst_octets[13],
        dst_octets[14],
        dst_octets[15],
    );
    Some((
        snat_v4,
        dst_v4,
        crate::nat64::Nat64ReverseInfo {
            orig_src_v6,
            orig_dst_v6,
        },
    ))
}

pub(crate) fn build_synced_session_entry(
    req: &SessionSyncRequest,
    zone_name_to_id: &rustc_hash::FxHashMap<String, u16>,
) -> Result<SyncedSessionEntry, String> {
    let key = build_synced_session_key(req)?;
    let next_hop = if req.next_hop.is_empty() {
        None
    } else {
        Some(
            req.next_hop
                .parse()
                .map_err(|e| format!("parse next_hop {}: {e}", req.next_hop))?,
        )
    };
    let neighbor_mac = parse_session_sync_mac(&req.neighbor_mac)
        .map_err(|e| format!("parse neighbor_mac {}: {e}", req.neighbor_mac))?;
    let src_mac = parse_session_sync_mac(&req.src_mac)
        .map_err(|e| format!("parse src_mac {}: {e}", req.src_mac))?;
    let tx_ifindex = if req.tunnel_endpoint_id != 0 {
        req.tx_ifindex.max(0)
    } else if req.tx_ifindex > 0 {
        req.tx_ifindex
    } else {
        req.egress_ifindex
    };
    let nat_src = if req.nat_src_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_src_ip
                .parse()
                .map_err(|e| format!("parse nat_src_ip {}: {e}", req.nat_src_ip))?,
        )
    };
    let nat_dst = if req.nat_dst_ip.is_empty() {
        None
    } else {
        Some(
            req.nat_dst_ip
                .parse()
                .map_err(|e| format!("parse nat_dst_ip {}: {e}", req.nat_dst_ip))?,
        )
    };
    let nat_src_port = if req.nat_src_port != 0 {
        Some(req.nat_src_port)
    } else {
        None
    };
    let nat_dst_port = if req.nat_dst_port != 0 {
        Some(req.nat_dst_port)
    } else {
        None
    };
    // #4565: rebuild a peer-PROMOTED NAT64 session's cross-family NAT decision +
    // reverse (v4->v6) BIB. A non-empty `nat64_snat_v4` marks a NAT64 forward
    // session (keyed on the ORIGINAL IPv6 5-tuple = `key.src_ip`/`key.dst_ip`).
    // The generic `nat_src`/`nat_dst` fields cannot carry a v4 pool source in a
    // v6 session's slot unambiguously, so on this path they are OVERRIDDEN by
    // the authoritative reconstruction:
    //   * `nat64 = true`             -> tx dispatch routes to the NAT64 frame
    //                                   builder and #4564's standby reserve arms.
    //   * `rewrite_src = snat_v4`    -> the translated pool source (wire field).
    //   * `rewrite_dst = dst_v4`     -> the /96-embedded low 32 of the v6 dst.
    //   * `rewrite_src_port`         -> the translated port (already synced via
    //                                   `nat_src_port`, kept below).
    //   * `nat64_reverse`            -> the original v6 src/dst (= the key), which
    //                                   `build_nat64_forwarded_frame` needs on the
    //                                   reverse path, and which the synthesized
    //                                   reverse companion inherits.
    // `reverse_session_key` then derives the reverse companion's v4 address
    // family + `(dst_v4 -> snat_v4)` tuple from this decision, so the server's
    // v4 reply matches after failover. When the field is empty (not NAT64, or an
    // old peer), the generic decision + `None` reverse are used, bit-identical
    // to pre-#4565 (rolling-upgrade safe).
    let nat64_rebuild = build_nat64_reverse_rebuild(&key, &req.nat64_snat_v4);
    let (nat64_flag, rewrite_src, rewrite_dst, nat64_reverse) = match nat64_rebuild {
        Some((snat_v4, dst_v4, reverse_info)) => (
            true,
            Some(std::net::IpAddr::V4(snat_v4)),
            Some(std::net::IpAddr::V4(dst_v4)),
            Some(reverse_info),
        ),
        None => (false, nat_src, nat_dst, None),
    };
    Ok(SyncedSessionEntry {
        protocol: req.protocol,
        tcp_flags: 0,
        key,
        decision: crate::session::SessionDecision {
            resolution: afxdp::ForwardingResolution {
                disposition: if req.egress_ifindex > 0
                    || req.tx_ifindex > 0
                    || req.tunnel_endpoint_id != 0
                {
                    afxdp::ForwardingDisposition::ForwardCandidate
                } else {
                    afxdp::ForwardingDisposition::NoRoute
                },
                local_ifindex: 0,
                egress_ifindex: req.egress_ifindex,
                tx_ifindex,
                tunnel_endpoint_id: req.tunnel_endpoint_id,
                next_hop,
                neighbor_mac,
                src_mac,
                tx_vlan_id: req.tx_vlan_id,
            },
            nat: crate::nat::NatDecision {
                rewrite_src,
                rewrite_dst,
                rewrite_src_port: nat_src_port,
                rewrite_dst_port: nat_dst_port,
                // #4565: set the NAT64 cross-family bit for a promoted NAT64
                // session so tx dispatch reverse-translates and the reverse key
                // derives its v4 address family. `nptv6` stays default (false).
                nat64: nat64_flag,
                ..crate::nat::NatDecision::default()
            },
        },
        metadata: crate::session::SessionMetadata {
            ingress_iface_id: 0,
            // #919: prefer the wire u16 IDs when populated; fall back
            // to name lookup for older peers that only sent strings.
            ingress_zone: if req.ingress_zone_id != 0 {
                req.ingress_zone_id
            } else {
                zone_name_to_id
                    .get(req.ingress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            egress_zone: if req.egress_zone_id != 0 {
                req.egress_zone_id
            } else {
                zone_name_to_id
                    .get(req.egress_zone.as_str())
                    .copied()
                    .unwrap_or(0)
            },
            owner_rg_id: req.owner_rg_id,
            fabric_ingress: req.fabric_ingress,
            is_reverse: req.is_reverse,
            // #4565: the original v6 src/dst for the reverse (v4->v6) translation
            // of a peer-PROMOTED NAT64 session (Some only when nat64_snat_v4 was
            // carried). The synthesized reverse companion inherits this via
            // build_reverse_session_from_forward_match.
            nat64_reverse,
            // #2785: the per-policy `then log` selection is now carried on
            // the HA session-sync wire (open-frame flags bits 1<<3/1<<4 ->
            // SessionSyncRequest.log_session_{init,close}). A synced session
            // therefore emits the same RT_FLOW SESSION_CREATE/CLOSE records
            // after failover as the node that locally admitted it. An old
            // peer that omits the fields decodes to false (no per-policy
            // log), bit-identical to pre-#2785 behavior.
            log_session_init: req.log_session_init,
            log_session_close: req.log_session_close,
            // #3301: the admitting policy ID now rides the cross-node HA
            // session-sync wire (SessionSyncRequest.policy_id). A peer-PROMOTED
            // session's live-session row / RT_FLOW records resolve the
            // admitting policy that #3056 stamps in-process, instead of the `0`
            // sentinel (which the Go side renders as the FIRST configured
            // policy — a wrong attribution). An old peer omits the field =>
            // serde(default) 0, the legitimate "unattributed" value,
            // bit-identical to pre-#3301 (rolling-upgrade safe).
            policy_id: req.policy_id,
            // #3301: the per-application idle timeout now rides the wire in
            // SECONDS (SessionSyncRequest.inactivity_timeout). Convert to ns via
            // the shared helper (0 => None => use the global per-protocol
            // timeout, the pre-#3301 behavior). A short-timeout app session
            // therefore ages out on the app's value after failover without a
            // real-traffic refresh (#3227).
            inactivity_timeout_ns: crate::session::app_inactivity_timeout_ns(
                if req.inactivity_timeout != 0 {
                    Some(req.inactivity_timeout)
                } else {
                    None
                },
            ),
            // #3301: the per-rule hit-counter handle now rides the wire
            // (SessionSyncRequest.policy_counter_idx). HA requires identical
            // config on both nodes, so the same #3073 idx resolves the same
            // rule on the peer; the established fast path then increments the
            // correct policy hit counter on every forwarded packet after
            // failover. An old peer omits the field => serde(default) 0 ("no
            // per-rule counter"), the pre-#3301 behavior (rolling-upgrade safe).
            policy_counter_idx: req.policy_counter_idx,
            policy_counter: None,
        },
        origin: crate::session::SessionOrigin::SyncImport,
        // #2170: carry the peer's install generation onto the helper entry.
        generation: req.generation,
        // #5212: carry the ORIGINATING node's stable RT_FLOW session id off the
        // wire so this peer-synced session ADOPTS the peer's id instead of
        // minting a fresh node-local one on import (`upsert_synced_with_origin`).
        // A session that opens on the primary and closes here after a failover
        // therefore emits SESSION_CREATE/CLOSE RT_FLOW records under ONE id
        // across both nodes. An old peer omits the field => serde(default) 0,
        // which falls back to `alloc_session_id()` (rolling-upgrade safe).
        session_id: req.session_id,
    })
}

pub(crate) fn parse_session_sync_mac(value: &str) -> Result<Option<[u8; 6]>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let mut out = [0u8; 6];
    let mut count = 0usize;
    for (i, part) in value.split(':').enumerate() {
        if i >= out.len() {
            return Err("too many octets".to_string());
        }
        out[i] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
        count += 1;
    }
    if count != out.len() {
        return Err("expected 6 octets".to_string());
    }
    Ok(Some(out))
}
