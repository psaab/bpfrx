// #1345: per-verb handler for update_neighbors. Body byte-identical to
// handlers.rs lines 186-208.

use super::super::helpers::refresh_status;
use super::super::ServerState;
use crate::{afxdp, NeighborSnapshot};

pub(super) fn update(
    guard: &mut ServerState,
    neighbors: Option<&Vec<NeighborSnapshot>>,
    replace: bool,
) {
    let Some(neighbors) = neighbors else {
        return;
    };
    let mut resolved = Vec::with_capacity(neighbors.len());
    for neigh in neighbors {
        if neigh.ifindex <= 0 || neigh.mac.is_empty() {
            continue;
        }
        let Ok(ip) = neigh.ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        let Some(mac) = afxdp::parse_mac_str(&neigh.mac) else {
            continue;
        };
        if !afxdp::neighbor_state_usable_str(&neigh.state) {
            continue;
        }
        resolved.push((neigh.ifindex, ip, afxdp::NeighborEntry { mac }));
    }
    guard.afxdp.apply_manager_neighbors(replace, &resolved);
    refresh_status(guard);
}
