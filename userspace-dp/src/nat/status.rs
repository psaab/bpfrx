// Source NAT pool status aggregation.
//
// Reads a flat status snapshot from each pool's `PortAllocator` and packs
// it into the wire `SourceNatPoolStatus` consumed by the control plane.

use super::source::SourceNatRule;
use crate::SourceNatPoolStatus;

pub(crate) fn source_nat_pool_statuses(rules: &[SourceNatRule]) -> Vec<SourceNatPoolStatus> {
    rules
        .iter()
        .filter(|rule| rule.pool_mode)
        .map(|rule| {
            let snap = rule.pool_allocator.snapshot();
            SourceNatPoolStatus {
                rule_name: rule.name.clone(),
                pool_name: rule.pool_name.clone(),
                address_count: rule.pool_addresses_v4.len() + rule.pool_addresses_v6.len(),
                port_low: rule.pool_allocator.port_low,
                port_high: rule.pool_allocator.port_high,
                persistent_nat: rule.persistent_nat,
                persistent_nat_permit_any_remote_host: rule.persistent_nat_permit_any_remote_host,
                persistent_nat_inactivity_timeout: rule.persistent_nat_inactivity_timeout_secs,
                live_flows: snap.live_flows,
                used_ports: snap.used_ports,
                persistent_leases: snap.persistent_leases,
                max_tracked_flows: snap.max_tracked_flows,
                allocations_total: snap.allocations_total,
                reuses_total: snap.reuses_total,
                exhaustion_total: snap.exhaustion_total,
            }
        })
        .collect()
}
