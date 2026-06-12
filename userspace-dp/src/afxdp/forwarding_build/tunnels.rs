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
    previous: Option<&ForwardingState>,
) {
    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        // #1873 R-D (Codex code-review r1): defer a row whose id the
        // PREVIOUS state owned under a different logical name. Without
        // the defer, a worker that observes this state before draining
        // its DeleteSynced commands (or that created an old-owner
        // session in the swap window) would re-resolve the stale id
        // into THIS row and encapsulate the old tunnel's traffic into
        // the new owner. With the row absent the stale id resolves
        // NoRoute -> R-C drop. The coordinator installs the row via an
        // immediate follow-up rebuild once every worker has rotated
        // and the purge has run twice (see refresh_runtime_snapshot).
        if let Some(prev) = previous {
            if let Some(prev_ep) = prev.tunnel_endpoints.get(&endpoint.id) {
                if prev_ep.interface != endpoint.interface {
                    eprintln!(
                        "xpf-userspace-dp: deferring tunnel endpoint id {} (owner {} -> {}) until the remap purge completes (#1873)",
                        endpoint.id, prev_ep.interface, endpoint.interface
                    );
                    state.deferred_reowned_tunnel_ids.push(endpoint.id);
                    continue;
                }
            }
        }
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

        // WireGuard field hydration (#1432 S2a). On any malformed key the
        // endpoint is dropped — a WG tunnel with a bad local privkey or
        // peer pubkey cannot function and must not silently install a
        // half-configured engine. The hydration gates live in
        // `hydrate_wg_identity` (#1866) so the coordinator's
        // tombstone-respawn coherence check and the defer-branch prune
        // can never drift from this path's semantics.
        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
        let mut wg_peer_pubkey = [0u8; 32];
        let mut wg_allowed_ips: Vec<ipnet::IpNet> = Vec::new();
        let mut wg_endpoint: Option<SocketAddr> = None;
        let mut wg_keepalive_secs = endpoint.wg_keepalive_secs;
        if is_wireguard {
            let Some(identity) = hydrate_wg_identity(endpoint) else {
                continue;
            };
            wg_local_privkey = identity.local_privkey;
            wg_peer_pubkey = identity.peer_pubkey;
            wg_allowed_ips = identity.allowed_ips;
            wg_endpoint = identity.endpoint;
            wg_keepalive_secs = identity.keepalive_secs;
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
                ttl: endpoint.ttl.max(0) as u8,
                transport_table,
                wg_listen_port: endpoint.wg_listen_port,
                wg_local_privkey,
                wg_peer_pubkey,
                wg_allowed_ips,
                wg_endpoint,
                wg_keepalive_secs,
            },
        );
        state
            .tunnel_endpoint_by_ifindex
            .insert(endpoint.ifindex, endpoint.id);
        if is_wireguard {
            state.has_wg_tunnels = true;
        }
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
    pub(in crate::afxdp) peer_pubkey: [u8; 32],
    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
    pub(in crate::afxdp) endpoint: Option<SocketAddr>,
    pub(in crate::afxdp) listen_port: u16,
    pub(in crate::afxdp) keepalive_secs: u16,
}

impl WgRowIdentity {
    /// Whether this row identity is byte-identical to a hydrated
    /// runtime endpoint — the same tuple `wg_identity_unchanged`
    /// compares for engine-Arc reuse.
    pub(in crate::afxdp) fn matches_endpoint(&self, ep: &TunnelEndpoint) -> bool {
        self.listen_port == ep.wg_listen_port
            && *self.local_privkey == *ep.wg_local_privkey
            && self.peer_pubkey == ep.wg_peer_pubkey
            && self.allowed_ips == ep.wg_allowed_ips
            && self.endpoint == ep.wg_endpoint
            && self.keepalive_secs == ep.wg_keepalive_secs
    }
}

/// #1866: hydrate the WG identity of a snapshot row, applying the SAME
/// gates as `populate_tunnel_endpoints`' WireGuard arm: mode must be
/// "wireguard", listen_port must be nonzero, both keys must decode.
/// Individually-invalid allowed-ips CIDRs are skipped (the row is
/// kept), and an unparsable/empty `wg_endpoint` hydrates to `None`
/// (responder-only) — neither disqualifies the row.
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
    let mut peer_pubkey = [0u8; 32];
    if decode_wg_key_hex(&row.wg_peer_pubkey_hex, &mut peer_pubkey).is_err() {
        return None;
    }
    let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
    for cidr in &row.wg_allowed_ips {
        match cidr.parse::<ipnet::IpNet>() {
            Ok(net) => allowed_ips.push(net),
            Err(_) => continue,
        }
    }
    let mut endpoint: Option<SocketAddr> = None;
    if !row.wg_endpoint.is_empty() {
        // Canonicalize (unmap ::ffff:a.b.c.d) so a configured v4-mapped
        // literal gets the same logical-v4 treatment as a learned
        // endpoint: correct (smaller) v4 MTU-guard overhead, v4 outer on
        // the transit path, and a target the v4-fallback socket can send
        // to (#1736 Codex r1; folded into the #1866 hydrate helper at
        // the #1868/#1872 merge).
        endpoint = row
            .wg_endpoint
            .parse::<SocketAddr>()
            .ok()
            .map(crate::afxdp::wg::canonicalize_endpoint);
    }
    Some(WgRowIdentity {
        local_privkey,
        peer_pubkey,
        allowed_ips,
        endpoint,
        listen_port: row.wg_listen_port,
        keepalive_secs: row.wg_keepalive_secs,
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
