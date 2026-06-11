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
) {
    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
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
        // half-configured engine.
        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
        let mut wg_peer_pubkey = [0u8; 32];
        let mut wg_allowed_ips: Vec<ipnet::IpNet> = Vec::new();
        let mut wg_endpoint: Option<SocketAddr> = None;
        if is_wireguard {
            // A WG tunnel with no listen port cannot bind a socket and is
            // invisible to the shim steering gate (wg_listen_port == 0 ⇒
            // "no WG"). Drop it rather than install a half-dead tunnel
            // that binds port 0 (Codex MAJOR).
            if endpoint.wg_listen_port == 0 {
                continue;
            }
            if decode_wg_key_hex(&endpoint.wg_local_privkey_hex, &mut wg_local_privkey).is_err() {
                continue;
            }
            if decode_wg_key_hex(&endpoint.wg_peer_pubkey_hex, &mut wg_peer_pubkey).is_err() {
                continue;
            }
            for cidr in &endpoint.wg_allowed_ips {
                match cidr.parse::<ipnet::IpNet>() {
                    Ok(net) => wg_allowed_ips.push(net),
                    Err(_) => continue,
                }
            }
            if !endpoint.wg_endpoint.is_empty() {
                // Canonicalize (unmap ::ffff:a.b.c.d) so a configured
                // v4-mapped literal gets the same logical-v4 treatment
                // as a learned endpoint: correct (smaller) v4 MTU-guard
                // overhead, v4 outer on the transit path, and a target
                // the v4-fallback socket can send to (#1736 Codex r1).
                wg_endpoint = endpoint
                    .wg_endpoint
                    .parse::<SocketAddr>()
                    .ok()
                    .map(crate::afxdp::wg::canonicalize_endpoint);
            }
        }

        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
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
                wg_keepalive_secs: endpoint.wg_keepalive_secs,
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
