// ===================================================================
// #5802 — the pre-routing DNAT / static-NAT / NPTv6 scope must key on
// the LOGICAL VLAN unit that received the frame, resolved through
// `prerouting_ingress_scope` (which uses `resolve_ingress_logical_-
// ifindex`), NOT the raw physical `meta.ingress_ifindex`. The three
// scope maps (`ifindex_to_zone_id` / `ifindex_to_config_name` /
// `ifindex_to_routing_instance`) are keyed by the logical unit ifindex;
// a VLAN sub-interface's physical parent maps only to its FIRST unit.
// Scoping the pre-routing NAT on the physical parent let a packet on
// one VLAN unit match another unit's scoped NAT rule (or miss its own)
// on a trunk whose units sit in distinct zones / interfaces — a NAT
// scope-escape ahead of the correct logical zone policy.
// ===================================================================
use super::*;

#[cfg(test)]
mod prerouting_scope_tests {
    use super::*;
    use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
    use std::net::IpAddr;

    /// nat_snapshot() already carries reth0.80 (logical 12, parent 11,
    /// VID 80, zone `wan`, the parent's FIRST sub-interface). Add reth0.50
    /// (logical 13, parent 11, VID 50, zone `lan`) so the physical parent
    /// 11 carries TWO VLAN units in DISTINCT zones. Add two scoped inbound
    /// destination-translation rules so both escape directions are covered:
    ///   - a port-based DNAT scoped `from zone wan` (unit-A's zone), and
    ///   - a static (1:1) DNAT scoped `from interface reth0.50` (unit-B's
    ///     OWN interface).
    fn two_vlan_scoped_nat_snapshot() -> crate::ConfigSnapshot {
        let mut snap = crate::afxdp::test_fixtures::nat_snapshot();
        snap.interfaces.push(crate::InterfaceSnapshot {
            name: "reth0.50".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 13,
            parent_ifindex: 11,
            redundancy_group: 1,
            vlan_id: 50,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![crate::InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.50.8/24".to_string(),
                scope: 0,
            }],
            ..Default::default()
        });
        // Port DNAT scoped to unit-A's zone (wan): 172.16.80.200:443/tcp.
        snap.destination_nat_rules
            .push(crate::DestinationNATRuleSnapshot {
                name: "dnat-from-wan".to_string(),
                from_zone: "wan".to_string(),
                destination_address: "172.16.80.200".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
                pool_address: "10.0.61.200".to_string(),
                pool_port: 8443,
                ..Default::default()
            });
        // Static (1:1) DNAT scoped to unit-B's OWN interface (reth0.50).
        snap.static_nat_rules.push(crate::StaticNATRuleSnapshot {
            name: "static-from-reth0-50".to_string(),
            from_interface: "reth0.50".to_string(),
            external_ip: "172.16.50.200".to_string(),
            internal_ip: "10.0.61.201".to_string(),
            ..Default::default()
        });
        snap
    }

    /// #5802 fail-on-revert (wrong-APPLY escape). A DNAT scoped `from zone
    /// wan` must translate only traffic whose LOGICAL ingress unit is in
    /// `wan`. A frame arriving on the VID-50 unit (zone `lan`) must be
    /// scoped OUT. Reverting the fix to scope on the physical parent 11 —
    /// which inherits unit-A's first-unit `wan` zone — makes the VID-50
    /// frame WRONGLY match unit-A's DNAT (NAT applied outside its
    /// configured `from zone`), so the unit-B assertion goes RED.
    #[test]
    fn prerouting_dnat_scope_uses_logical_vlan_unit_zone_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());

        // Fixture sanity: parent 11 / VID 80 -> logical 12 (zone wan);
        // parent 11 / VID 50 -> logical 13 (zone lan). The physical parent
        // 11 inherits ONLY unit-A's (first sub-interface) zone -> wan.
        assert_eq!(resolve_ingress_logical_ifindex(&forwarding, 11, 80), Some(12));
        assert_eq!(resolve_ingress_logical_ifindex(&forwarding, 11, 50), Some(13));
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&12).copied(),
            Some(TEST_WAN_ZONE_ID)
        );
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&13).copied(),
            Some(TEST_LAN_ZONE_ID)
        );
        // #7509 RETARGET, re-expressed and STRICTLY STRONGER. This asserted the
        // parent inherited unit-A's first-unit `wan` zone -- the arbitrary
        // walk-order pick that makes a VID-50 frame wrongly match unit-A's
        // `from zone wan` DNAT, which is the hazard this cell guards.
        //
        // A contested parent now carries no zone, so the hazard is expressed as
        // "the parent names no zone" instead of "the parent names the WRONG
        // zone". Both make a physical-keyed scope decision wrong for the VID-50
        // unit; the new form also distinguishes it from "scoped to some other
        // real zone", which the old form could not.
        //
        // The two assertions above are the control: units 12 and 13 must still
        // resolve to `wan` and `lan`, so this 0 is specific to the contested
        // parent rather than a state with no zones at all.
        assert_eq!(
            forwarding.ifindex_to_zone_id.get(&11).copied().unwrap_or(0),
            0,
            "the physical parent carries units in DIFFERENT zones (wan on \
             unit-A, lan on unit-B), so it resolves to NO zone (#7509)"
        );

        let src: IpAddr = "203.0.113.9".parse().unwrap();
        let dst: IpAddr = "172.16.80.200".parse().unwrap();

        // Unit-A frame (VID 80): scope resolves to wan -> the wan-scoped
        // DNAT MATCHES its OWN zone's traffic.
        let scope_a = prerouting_ingress_scope(&forwarding, 11, 80, None);
        assert_eq!(scope_a.zone_name, "wan");
        assert_eq!(scope_a.logical_ifindex, 12);
        let dnat_a = forwarding.dnat_table.lookup_with_counter_scoped(
            crate::ip_proto::PROTO_TCP,
            src,
            dst,
            51000,
            443,
            scope_a.zone_name,
            scope_a.ifname,
            scope_a.routing_instance,
            None,
        );
        assert!(
            dnat_a.is_some(),
            "unit-A (logical zone wan) must match its own wan-scoped DNAT"
        );

        // Unit-B frame (VID 50): scope resolves to lan -> the wan-scoped
        // DNAT is SCOPED OUT. Reverting to the physical parent makes this
        // resolve to wan and the DNAT WRONGLY matches -> RED (#5802).
        let scope_b = prerouting_ingress_scope(&forwarding, 11, 50, None);
        assert_eq!(
            scope_b.zone_name, "lan",
            "the VID-50 unit must scope on its OWN logical zone (lan), \
             not the parent's inherited wan"
        );
        assert_eq!(scope_b.logical_ifindex, 13);
        let dnat_b = forwarding.dnat_table.lookup_with_counter_scoped(
            crate::ip_proto::PROTO_TCP,
            src,
            dst,
            51000,
            443,
            scope_b.zone_name,
            scope_b.ifname,
            scope_b.routing_instance,
            None,
        );
        assert!(
            dnat_b.is_none(),
            "unit-B (logical zone lan) must NOT match unit-A's wan-scoped \
             DNAT — a cross-VLAN-unit NAT scope-escape (#5802)"
        );
    }

    /// #5802 fail-on-revert (wrong-SKIP escape). A static DNAT scoped
    /// `from interface reth0.50` must translate the VID-50 unit's OWN
    /// traffic. The fix derives the logical ifname `reth0.50`, so the
    /// rule matches. Reverting to the physical parent 11 (which has NO
    /// config-name -> ifname "") makes the interface-scoped rule WRONGLY
    /// MISS, so unit-B's own traffic skips its configured translation ->
    /// the unit-B assertion goes RED.
    #[test]
    fn prerouting_static_dnat_scope_uses_logical_vlan_unit_interface_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());
        let src: IpAddr = "203.0.113.9".parse().unwrap();
        let ext: IpAddr = "172.16.50.200".parse().unwrap();

        // Unit-B frame (VID 50): ifname resolves to reth0.50 -> its OWN
        // reth0.50-scoped static DNAT MATCHES.
        let scope_b = prerouting_ingress_scope(&forwarding, 11, 50, None);
        assert_eq!(scope_b.ifname, "reth0.50");
        let static_b = forwarding.static_nat.match_dnat_with_counter_scoped(
            ext,
            0,
            Some(src),
            scope_b.zone_name,
            scope_b.ifname,
            scope_b.routing_instance,
        );
        assert!(
            static_b.is_some(),
            "unit-B must match its OWN reth0.50-scoped static DNAT (the fix \
             derives the logical ifname); reverting to the physical parent \
             yields ifname \"\" and WRONGLY skips the translation (#5802)"
        );

        // Unit-A frame (VID 80): ifname resolves to reth0.80 -> the
        // reth0.50-scoped rule is correctly scoped OUT.
        let scope_a = prerouting_ingress_scope(&forwarding, 11, 80, None);
        assert_eq!(scope_a.ifname, "reth0.80");
        let static_a = forwarding.static_nat.match_dnat_with_counter_scoped(
            ext,
            0,
            Some(src),
            scope_a.zone_name,
            scope_a.ifname,
            scope_a.routing_instance,
        );
        assert!(
            static_a.is_none(),
            "unit-A must NOT match unit-B's reth0.50-scoped static DNAT"
        );
    }

    /// #5802 non-VLAN regression: an untagged port (reth1.0, ifindex 24)
    /// has no `(parent, vlan)` mapping, so `resolve_ingress_logical_-
    /// ifindex` returns None and `prerouting_ingress_scope` falls back to
    /// the physical ifindex — the scope identity is byte-identical to
    /// pre-#5802 (logical == physical).
    #[test]
    fn prerouting_scope_non_vlan_unchanged_5802() {
        let forwarding = build_forwarding_state(&two_vlan_scoped_nat_snapshot());
        assert_eq!(
            resolve_ingress_logical_ifindex(&forwarding, 24, 0),
            Some(24),
            "an untagged port resolves logical == physical"
        );
        let scope = prerouting_ingress_scope(&forwarding, 24, 0, None);
        assert_eq!(
            scope.logical_ifindex, 24,
            "an untagged port scopes on itself (logical == physical)"
        );
        assert_eq!(scope.zone_name, "lan");
        assert_eq!(scope.ifname, "reth1.0");
        // The derived scope equals the direct physical-keyed lookups (the
        // pre-#5802 behavior) — non-trunk ingress is unchanged.
        assert_eq!(
            forwarding
                .ifindex_to_config_name
                .get(&24)
                .map(|s| s.as_str()),
            Some(scope.ifname),
        );
        assert_eq!(
            forwarding
                .ifindex_to_zone_id
                .get(&24)
                .and_then(|id| forwarding.zone_id_to_name.get(id))
                .map(|s| s.as_str()),
            Some(scope.zone_name),
        );
    }
}
