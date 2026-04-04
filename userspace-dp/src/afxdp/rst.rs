use super::*;

/// RST suppression is now managed by the Go daemon via netlink (pkg/nftables).
/// This function is a no-op retained to avoid breaking the call site.
pub(super) fn install_kernel_rst_suppression(_state: &ForwardingState) {
    // No-op: the Go daemon installs nftables rules via the netlink API
    // (github.com/google/nftables). See pkg/nftables/rst_suppress.go.
}

/// Removal is also handled by the Go daemon.
pub(crate) fn remove_kernel_rst_suppression() {
    // No-op: the Go daemon manages the nftables table lifecycle.
}

pub(super) fn nat_translated_local_exclusions(
    snapshot: &ConfigSnapshot,
) -> (FastSet<Ipv4Addr>, FastSet<Ipv6Addr>) {
    let mut excluded_v4 = FastSet::default();
    let mut excluded_v6 = FastSet::default();
    let mut to_zones = FastSet::default();
    for rule in &snapshot.source_nat_rules {
        if rule.interface_mode && !rule.off && !rule.to_zone.is_empty() {
            to_zones.insert(rule.to_zone.clone());
        }
    }
    if to_zones.is_empty() {
        return (excluded_v4, excluded_v6);
    }
    for iface in &snapshot.interfaces {
        if iface.zone.is_empty() || !to_zones.contains(&iface.zone) {
            continue;
        }
        if let Some(v4) = pick_interface_v4(iface) {
            excluded_v4.insert(v4);
        }
        if let Some(v6) = pick_interface_v6(iface) {
            excluded_v6.insert(v6);
        }
    }
    (excluded_v4, excluded_v6)
}
