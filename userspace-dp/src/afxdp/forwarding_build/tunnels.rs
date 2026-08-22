//! Tunnel-endpoint population for `build_forwarding_state`.
//!
//! Populates `state.tunnel_endpoints` and
//! `state.tunnel_endpoint_by_ifindex`. Must run before the
//! interfaces addresses pass, which reads
//! `tunnel_endpoint_by_ifindex` when building
//! `ConnectedRouteV4/V6.tunnel_endpoint_id`.

use super::super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(super) fn populate_tunnel_endpoints(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    // #5193 (A1-b7-F1): duplicate endpoint ids are rejected BEFORE any state is
    // mutated. Both indexes below are keyed independently — `tunnel_endpoints`
    // by id, `tunnel_endpoint_by_ifindex` by ifindex — so a duplicate id used
    // to install the LAST row under that id while BOTH interfaces' ifindexes
    // resolved to it, silently encapsulating one tunnel's traffic with the
    // other's outer source/destination/key. The Go producer already drops an id
    // collision (`usedIDs`, #1873); this is the snapshot-boundary backstop, and
    // running it as a preflight (rather than mid-loop) is what keeps a rejected
    // snapshot from leaving a half-populated forwarding state behind.
    {
        let mut seen_ids: std::collections::HashSet<u16> =
            std::collections::HashSet::with_capacity(snapshot.tunnel_endpoints.len());
        for endpoint in &snapshot.tunnel_endpoints {
            if endpoint.id == 0 || endpoint.ifindex <= 0 {
                continue;
            }
            if !seen_ids.insert(endpoint.id) {
                return Err(
                    crate::policy::SnapshotIntegrityError::TunnelEndpointDuplicateId {
                        tunnel_id: endpoint.id,
                        ifindex: endpoint.ifindex,
                    },
                );
            }
        }
    }
    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        // #2410: validate the outer-IP TTL ONCE here instead of narrowing it
        // with an unchecked `endpoint.ttl.max(0) as u8`. A value > 255 fails
        // the snapshot closed rather than wrapping (256→0 blackholes the
        // tunnel).
        let ttl = super::validated::TunnelTtl::try_from_snapshot(endpoint.ttl, endpoint.id)?.get();
        let is_wireguard = endpoint.mode == "wireguard";
        // GRE/IPIP require concrete outer source/destination. WireGuard
        // carries the peer in `wg_endpoint` and may have neither
        // (responder-only), so skip the parse-or-drop gate for WG and
        // default the unused outer source/destination to an unspecified
        // address (#1432 S2a).
        let (source, destination) = if is_wireguard {
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            )
        } else {
            let Ok(source) = endpoint.source.parse::<IpAddr>() else {
                continue;
            };
            let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
                continue;
            };
            // #5162: a non-WireGuard tunnel encapsulates in ONE outer IP
            // family, so the outer source and destination MUST be the same
            // family. The Go commit gate (validateTunnelOuterFamilyStrict)
            // rejects a mixed pair, but a config synced from an older peer
            // (pre-#5162) or a corrupt snapshot can still carry one — and the
            // Go producer tags such a row `inet6` when EITHER endpoint is v6,
            // which drives the GRE encoder into the AF_INET6 arm where the v4
            // endpoint yields None → a SILENT per-packet drop. Skip the
            // degenerate row loudly here instead so it installs nothing rather
            // than a blackhole (fail-closed, mirroring the WG hydrate
            // row-drop and the allowed-ips prefix-drop skip-and-continue
            // posture in this file).
            if source.is_ipv6() != destination.is_ipv6() {
                eprintln!(
                    "xpf-userspace-dp: tunnel endpoint {} outer source {} and destination {} are different address families; skipping this endpoint (a GRE/IPIP tunnel encapsulates in one outer family — #5162)",
                    endpoint.id, source, destination
                );
                continue;
            }
            (source, destination)
        };
        let outer_family = match (endpoint.outer_family.as_str(), destination) {
            ("inet6", _) => libc::AF_INET6,
            ("inet", _) => libc::AF_INET,
            (_, IpAddr::V6(_)) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let transport_table =
            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);

        // WireGuard field hydration (#1432 S2a, multi-peer #1434). On a
        // malformed local privkey OR any malformed peer pubkey the
        // endpoint is dropped — a WG tunnel with a bad key cannot
        // function and must not silently install a half-configured
        // engine. The hydration gates live in `hydrate_wg_identity`
        // (#1866) so the coordinator's tombstone-respawn coherence check
        // and the defer-branch prune can never drift from this path's
        // semantics.
        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
        let mut wg_peers: Vec<WgRuntimePeer> = Vec::new();
        if is_wireguard {
            let Some(identity) = hydrate_wg_identity(endpoint) else {
                continue;
            };
            wg_local_privkey = identity.local_privkey;
            wg_peers = identity.peers;
        }

        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
                // #1865: attachment label for the telemetry-row name
                // fallback (linux_name, else logical name — mirrors
                // wg_tombstone_respawn_coherent's row_label).
                interface_label: if endpoint.linux_name.is_empty() {
                    endpoint.interface.clone()
                } else {
                    endpoint.linux_name.clone()
                },
                interface: endpoint.interface.clone(),
                redundancy_group: endpoint.redundancy_group,
                mode: endpoint.mode.clone(),
                outer_family,
                source,
                destination,
                key: endpoint.key,
                ttl,
                transport_table: transport_table.into_owned(),
                wg_listen_port: endpoint.wg_listen_port,
                wg_local_privkey,
                wg_peers,
            },
        );
        // #5193 (A1-b7-F1): ids are unique by the preflight above, but two rows
        // can still name one ifindex (two logical names resolved to the same
        // link). Keep the FIRST — silently overwriting made the decap/connected
        // -route lookups resolve to whichever row happened to sort last.
        if let Some(existing) = state.tunnel_endpoint_by_ifindex.get(&endpoint.ifindex) {
            eprintln!(
                "xpf-userspace-dp: tunnel endpoints {} and {} both claim ifindex {}; keeping {} for the ifindex index (#5193)",
                existing, endpoint.id, endpoint.ifindex, existing
            );
        } else {
            state
                .tunnel_endpoint_by_ifindex
                .insert(endpoint.ifindex, endpoint.id);
        }
        // #2327: kind-segregated decap index — only GRE-mode endpoints
        // are indexed for the GRE (proto-47) decap fast path. A
        // WireGuard or any non-GRE row is intentionally NOT indexed, so
        // a received GRE frame can never be decapped against it even if
        // the outer tuple/key collide. Keyed by the endpoint's own
        // (outer_family, source, destination); the decap lookup queries
        // with the received frame's mirrored (addr_family, outer_dst,
        // outer_src).
        if tunnel_mode_kind(&endpoint.mode) == TunnelKind::Gre {
            state
                .gre_decap_index
                .entry((outer_family, source, destination))
                .or_default()
                .push(endpoint.id);
        }
        if is_wireguard {
            state.has_wg_tunnels = true;
        }
    }
    Ok(())
}

/// #2327: the typed kind of a tunnel-endpoint `mode` string. Centralizes
/// the kind classification that the decap index, the egress encap
/// dispatcher, and the GRE supervision paths all rely on, so a future
/// tunnel kind is added in exactly one place and the egress dispatcher's
/// fail-closed `_ =>` arm cannot silently treat it as GRE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) enum TunnelKind {
    /// `gre` / `ip6gre` — native GRE encapsulation/decapsulation.
    Gre,
    /// `wireguard` — WireGuard engine encap/decap.
    WireGuard,
    /// Any unrecognized / future / malformed mode string. The egress
    /// dispatcher MUST fail closed (drop) on this rather than default to
    /// GRE encap (the pre-#2327 fail-open behavior).
    Unknown,
}

/// Classify a tunnel-endpoint `mode` string into a `TunnelKind`. Mirrors
/// the canonical GRE-kind test used across the supervision paths
/// (`mode == "gre" || mode == "ip6gre"`).
pub(in crate::afxdp) fn tunnel_mode_kind(mode: &str) -> TunnelKind {
    match mode {
        "gre" | "ip6gre" => TunnelKind::Gre,
        "wireguard" => TunnelKind::WireGuard,
        _ => TunnelKind::Unknown,
    }
}

/// #1866: the hydratable WG identity of one tunnel-endpoint snapshot
/// row — the exact field set `wg_identity_unchanged`
/// (`forwarding_build/wg.rs`) keys engine reuse on, hydrated with the
/// exact gates `populate_tunnel_endpoints` applies. Single source of
/// truth shared by the populate pass, the coordinator's
/// tombstone-respawn coherence check, and the defer-branch prune.
pub(in crate::afxdp) struct WgRowIdentity {
    pub(in crate::afxdp) local_privkey: zeroize::Zeroizing<[u8; 32]>,
    pub(in crate::afxdp) peers: Vec<WgRuntimePeer>,
    pub(in crate::afxdp) listen_port: u16,
}

impl WgRowIdentity {
    /// Whether this row identity is byte-identical to a hydrated
    /// runtime endpoint — the same tuple `wg_identity_unchanged`
    /// compares for engine-Arc reuse. The peer slices are compared
    /// order-sensitively (the Go builder sorts by pubkey, so a stable
    /// config yields a stable order — a reorder is treated as a change,
    /// which only forces a benign engine rebuild).
    pub(in crate::afxdp) fn matches_endpoint(&self, ep: &TunnelEndpoint) -> bool {
        self.listen_port == ep.wg_listen_port
            && *self.local_privkey == *ep.wg_local_privkey
            && wg_peers_eq(&self.peers, &ep.wg_peers)
    }
}

/// Order-sensitive equality of two runtime peer slices (#1434). Compares
/// every identity-bearing field INCLUDING the preshared key, so a PSK
/// rotation forces an engine rebuild (the new key takes effect on the
/// next handshake).
pub(in crate::afxdp) fn wg_peers_eq(a: &[WgRuntimePeer], b: &[WgRuntimePeer]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        x.pubkey == y.pubkey
            && x.allowed_ips == y.allowed_ips
            && x.endpoint == y.endpoint
            && x.keepalive_secs == y.keepalive_secs
            && *x.preshared_key == *y.preshared_key
    })
}

/// #1866 / #1434: hydrate the WG identity of a snapshot row, applying
/// the SAME gates as `populate_tunnel_endpoints`' WireGuard arm: mode
/// must be "wireguard", listen_port must be nonzero, the local privkey
/// AND every peer pubkey must decode. Individually-invalid allowed-ips
/// CIDRs are skipped (the peer is kept). An EMPTY `wg_endpoint` hydrates
/// to `None` (responder-only), but a NON-EMPTY endpoint that does not
/// parse to a `SocketAddr` DROPS the row (#5182) — coercing it to `None`
/// silently degraded every such peer to responder-only. A row with ZERO
/// peers is dropped (a peerless
/// WG tunnel can never handshake; the Go commit gate rejects it, and
/// hydrate fails closed for a leniently-loaded one).
///
/// Returns `None` for non-WG rows and for rows the populate pass would
/// drop. Callers needing the populate pass's id/ifindex gates
/// (`id != 0 && ifindex > 0`) must check those separately.
pub(in crate::afxdp) fn hydrate_wg_identity(
    row: &crate::protocol::snapshot::TunnelEndpointSnapshot,
) -> Option<WgRowIdentity> {
    if row.mode != "wireguard" {
        return None;
    }
    // A WG tunnel with no listen port cannot bind a socket and is
    // invisible to the shim steering gate (wg_listen_port == 0 ⇒
    // "no WG"). Drop it rather than install a half-dead tunnel
    // that binds port 0 (Codex MAJOR, #1432).
    if row.wg_listen_port == 0 {
        return None;
    }
    let mut local_privkey = zeroize::Zeroizing::new([0u8; 32]);
    if decode_wg_key_hex(&row.wg_local_privkey_hex, &mut local_privkey).is_err() {
        return None;
    }
    if row.wg_peers.is_empty() {
        return None;
    }
    let mut peers: Vec<WgRuntimePeer> = Vec::with_capacity(row.wg_peers.len());
    for wire in &row.wg_peers {
        let mut peer_pubkey = [0u8; 32];
        // A bad peer pubkey poisons the whole engine (the AllowedIPs
        // LPM / demux index would be inconsistent), so drop the ROW —
        // same fail-closed posture the scalar path had.
        if decode_wg_key_hex(&wire.wg_peer_pubkey_hex, &mut peer_pubkey).is_err() {
            return None;
        }
        let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
        for cidr in &wire.wg_allowed_ips {
            match cidr.parse::<ipnet::IpNet>() {
                Ok(net) => allowed_ips.push(net),
                Err(_) => {
                    // #5194 A3-b3-F6: drop only the malformed prefix (keeping the
                    // peer's other routes), but make the drop OBSERVABLE. The Go
                    // commit gate now rejects a malformed allowed-ips at strict
                    // commit and warns on tolerant load, so this only fires for a
                    // leniently-loaded / peer-synced config that slipped a bad
                    // prefix past the warn path — log which route vanished instead
                    // of leaving the operator to debug a silent blackhole.
                    eprintln!(
                        "xpf-userspace-dp: wireguard allowed-ips {:?} is not a valid CIDR; dropping this prefix (the peer keeps its other routes)",
                        cidr
                    );
                    continue;
                }
            }
        }
        let mut endpoint: Option<SocketAddr> = None;
        if !wire.wg_endpoint.is_empty() {
            // A non-empty endpoint that does not parse to a concrete
            // SocketAddr must fail the ROW closed rather than silently
            // coerce to None (responder-only) (#5182). The pre-fix
            // `.parse().ok()` turned a malformed/port-stripped endpoint
            // into a peer that could never initiate — the exact silent
            // degradation the Go commit gate now rejects; the dataplane
            // keeps defense-in-depth in agreement so a leniently-loaded
            // config fails loudly (drop) instead of quietly.
            let Ok(parsed) = wire.wg_endpoint.parse::<SocketAddr>() else {
                return None;
            };
            // Canonicalize (unmap ::ffff:a.b.c.d) so a configured
            // v4-mapped literal gets the same logical-v4 treatment as a
            // learned endpoint (#1736).
            endpoint = Some(crate::afxdp::wg::canonicalize_endpoint(parsed));
        }
        // PSK is OPTIONAL: an empty hex hydrates to the all-zero key
        // (no PSK). A malformed non-empty PSK drops the row (fail
        // closed — a half-applied PSK would silently break the
        // handshake against a peer that DOES use one).
        let mut preshared_key = zeroize::Zeroizing::new([0u8; 32]);
        if !wire.wg_preshared_key_hex.is_empty()
            && decode_wg_key_hex(&wire.wg_preshared_key_hex, &mut preshared_key).is_err()
        {
            return None;
        }
        peers.push(WgRuntimePeer {
            pubkey: peer_pubkey,
            allowed_ips,
            endpoint,
            keepalive_secs: wire.wg_keepalive_secs,
            preshared_key,
        });
    }
    Some(WgRowIdentity {
        local_privkey,
        peers,
        listen_port: row.wg_listen_port,
    })
}

/// Decode a 64-char hex WG key into a 32-byte array. Returns `Err` on
/// any non-hex char or wrong length.
fn decode_wg_key_hex(hex: &str, out: &mut [u8; 32]) -> Result<(), ()> {
    if hex.len() != 64 {
        return Err(());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(())
}

#[inline]
fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}
