use super::*;
use crate::test_zone_ids::*;
use crate::{
    FabricSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot,
    InterfaceSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot, TunnelEndpointSnapshot, ZoneSnapshot,
};

pub(super) fn forwarding_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0.50".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![
                InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.50.8/24".to_string(),
                    scope: 0,
                },
                InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:50::8/64".to_string(),
                    scope: 0,
                },
            ],
            ..Default::default()
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "::/0".to_string(),
                next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
        ],
        neighbors: if include_neighbor {
            vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet".to_string(),
                    ip: "172.16.50.1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:50::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
            ]
        } else {
            vec![]
        },
        source_nat_rules: vec![SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
            interface_mode: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub(super) fn native_gre_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "sfmix".to_string(),
                id: TEST_SFMIX_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                ifindex: 12,
                parent_ifindex: 6,
                vlan_id: 80,
                mtu: 1500,
                redundancy_group: 1,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:80::8/64".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "gr-0/0/0.0".to_string(),
                zone: "sfmix".to_string(),
                // #4446: the GRE inner interface belongs to the sfmix
                // routing-instance (real config: `set routing-instances
                // sfmix interface gr-0/0/0.0`), so its connected /30 lands in
                // sfmix.inet.0 — the SAME table as the bare-gateway static
                // route below. The build-time gateway inference is now
                // table-scoped, so the connected route MUST be in the route's
                // table (mirrors the #2388 lookup-site filter).
                routing_instance: "sfmix".to_string(),
                linux_name: "gr-0-0-0".to_string(),
                ifindex: 362,
                mtu: 1476,
                redundancy_group: 1,
                tunnel: true,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.255.192.42/30".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id: 1,
            interface: "gr-0/0/0.0".to_string(),
            linux_name: "gr-0-0-0".to_string(),
            ifindex: 362,
            zone: "sfmix".to_string(),
            redundancy_group: 1,
            mtu: 1476,
            mode: "gre".to_string(),
            outer_family: "inet6".to_string(),
            source: "2001:559:8585:80::8".to_string(),
            destination: "2602:ffd3:0:2::7".to_string(),
            key: 0,
            ttl: 64,
            transport_table: "inet6.0".to_string(),
            ..Default::default()
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2602:ffd3:0:2::/64".to_string(),
                next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
            RouteSnapshot {
                table: "sfmix.inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["10.255.192.41".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
        ],
        neighbors: if include_neighbor {
            vec![NeighborSnapshot {
                interface: "ge-0-0-2.80".to_string(),
                ifindex: 12,
                family: "inet6".to_string(),
                ip: "2001:559:8585:80::1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            }]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

/// A WireGuard tunnel endpoint whose LOGICAL interface MTU (1420) differs
/// from the PHYSICAL underlay egress MTU (1500), used to pin the #2680 fix:
/// the outer-encap MTU guard must gate against the PHYSICAL underlay, not the
/// tunnel logical ifindex. Outer transport egresses on `reth0.80`
/// (ifindex 12, MTU 1500); the WG logical interface `wg0.0` (ifindex 400) has
/// MTU 1420. The 64-hex privkey + one peer with a valid pubkey make the row
/// hydrate (a peerless / keyless WG row is dropped by `hydrate_wg_identity`).
pub(super) fn wg_outer_mtu_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "sfmix".to_string(),
                id: TEST_SFMIX_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2.80".to_string(),
                ifindex: 12,
                parent_ifindex: 6,
                vlan_id: 80,
                mtu: 1500,
                redundancy_group: 1,
                hardware_addr: "02:bf:72:00:50:08".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.80.8/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "wg0.0".to_string(),
                zone: "sfmix".to_string(),
                linux_name: "wg0".to_string(),
                ifindex: 400,
                mtu: 1420,
                redundancy_group: 1,
                tunnel: true,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.123.0.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        tunnel_endpoints: vec![TunnelEndpointSnapshot {
            id: 1,
            interface: "wg0.0".to_string(),
            linux_name: "wg0".to_string(),
            ifindex: 400,
            zone: "sfmix".to_string(),
            redundancy_group: 1,
            mtu: 1420,
            mode: "wireguard".to_string(),
            outer_family: "inet".to_string(),
            source: "172.16.80.8".to_string(),
            // OUTER peer endpoint is OFF the connected subnet so it resolves
            // via the explicit route below to reth0.80 (mirroring the GRE
            // fixture), not a connected/local-delivery short circuit.
            destination: "203.0.113.7".to_string(),
            ttl: 64,
            transport_table: "inet.0".to_string(),
            wg_listen_port: 51820,
            wg_local_privkey_hex: "deadbeef".repeat(8),
            wg_peers: vec![crate::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: "abadcafe".repeat(8),
                wg_allowed_ips: vec!["10.123.0.0/24".to_string()],
                wg_endpoint: "203.0.113.7:51820".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            // The OUTER peer endpoint (203.0.113.7) routes out reth0.80 via
            // the connected next-hop 172.16.80.1.
            destination: "203.0.113.0/24".to_string(),
            next_hops: vec!["172.16.80.1@reth0.80".to_string()],
            discard: false,
            next_table: String::new(),
            preference: 0,
        }],
        ..Default::default()
    }
}

/// #6340: a WG endpoint (id 1) with TWO cryptokey-routed peers whose AllowedIPs
/// live on DISTINCT physical underlay egresses, so a DNAT that rewrites the
/// inner dst ACROSS the two peers changes which physical NIC the frame must
/// egress. Peer A (10.123.0.0/24 → outer endpoint 203.0.113.7) routes out
/// reth0.80 (ifindex 12, physical parent/bind 6, the base fixture); peer B
/// (10.200.0.0/24 → outer endpoint 198.51.100.7) routes out reth0.50 (ifindex
/// 13, physical parent/bind 7). No default route (the #6308 specific-peer-route
/// + tx_ifindex==0 case), so the TX dispatcher consults the peer-route egress
/// helper — which must follow the POST-NAT dst to peer B's NIC, the SAME NIC
/// `wg_encap_frame` emits bytes for. Built by extending `wg_outer_mtu_snapshot`.
pub(super) fn wg_two_peer_dnat_snapshot() -> ConfigSnapshot {
    let mut snap = wg_outer_mtu_snapshot();
    // Second physical underlay egress on a DISTINCT parent NIC (bind 7 != 6).
    snap.interfaces.push(InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-2.50".to_string(),
        ifindex: 13,
        parent_ifindex: 7,
        vlan_id: 50,
        mtu: 1500,
        redundancy_group: 1,
        hardware_addr: "02:bf:72:00:50:07".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    // Route peer B's outer endpoint (198.51.100.7) out reth0.50 via the
    // connected next-hop 172.16.50.1 (mirroring the base peer-A route).
    snap.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "198.51.100.0/24".to_string(),
        next_hops: vec!["172.16.50.1@reth0.50".to_string()],
        discard: false,
        next_table: String::new(),
        preference: 0,
    });
    // Mirror peer B in the endpoint hydration so `endpoint.wg_peers` matches the
    // live two-peer engine the test inserts (the dispatch path selects via the
    // engine's AllowedIPs LPM; this keeps the hydrated snapshot consistent).
    if let Some(ep) = snap.tunnel_endpoints.first_mut() {
        ep.wg_peers.push(crate::TunnelWgPeerSnapshot {
            wg_peer_pubkey_hex: "beadfeed".repeat(8),
            wg_allowed_ips: vec!["10.200.0.0/24".to_string()],
            wg_endpoint: "198.51.100.7:51820".to_string(),
            ..Default::default()
        });
    }
    snap
}

pub(super) fn native_gre_pbr_snapshot(include_neighbor: bool) -> ConfigSnapshot {
    let mut snapshot = native_gre_snapshot(include_neighbor);
    snapshot.zones.insert(
        0,
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
    );
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "reth1.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: 5,
        filter_input_v4: "sfmix-pbr".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.61.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "sfmix-pbr".to_string(),
        family: "inet".to_string(),
        terms: vec![
            FirewallTermSnapshot {
                name: "sfmix-route".to_string(),
                destination_addresses: vec!["10.255.192.40/30".to_string()],
                routing_instance: "sfmix".to_string(),
                log: true,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
        ],
    }];
    snapshot
}

/// #4392: a snapshot whose reth1.0 input filter carries a PBR
/// `then { routing-instance sfmix; <action>; }` term for BOTH inet and inet6,
/// where `action` is `"reject"` / `"discard"` (a DROP term) or `""` (an
/// accept-only routing-instance override, the no-regression forward case).
/// Used to prove the drop-action gate on `ingress_route_table_override`: a
/// reject/discard term must return `RouteOverride::Drop`, an accept term must
/// still return `RouteOverride::Table("sfmix.inet[6].0")`.
pub(super) fn native_gre_pbr_action_snapshot(action: &str) -> ConfigSnapshot {
    let mut snapshot = native_gre_pbr_snapshot(true);
    // Stamp the action onto the existing v4 routing-instance term
    // (`sfmix-route`, the first term of the first filter).
    snapshot.filters[0].terms[0].action = action.to_string();
    // Wire an inet6 sibling filter so the v6 path exercises the same gate.
    if let Some(iface) = snapshot.interfaces.iter_mut().find(|i| i.name == "reth1.0") {
        iface.filter_input_v6 = "sfmix-pbr6".to_string();
    }
    snapshot.filters.push(FirewallFilterSnapshot {
        name: "sfmix-pbr6".to_string(),
        family: "inet6".to_string(),
        terms: vec![
            FirewallTermSnapshot {
                name: "sfmix-route6".to_string(),
                destination_addresses: vec!["2001:559:8585:80::/64".to_string()],
                routing_instance: "sfmix".to_string(),
                action: action.to_string(),
                log: true,
                ..Default::default()
            },
            FirewallTermSnapshot {
                name: "default".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
        ],
    });
    snapshot
}

pub(super) fn forwarding_snapshot_with_next_table(include_neighbor: bool) -> ConfigSnapshot {
    ConfigSnapshot {
        // #2391: the interface references "wan"; define it so the forwarding
        // build does not fail closed (InterfaceUnknownZone).
        zones: vec![ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0.50".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-0.50".to_string(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:50:08".to_string(),
            addresses: vec![
                InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.50.8/24".to_string(),
                    scope: 0,
                },
                InterfaceAddressSnapshot {
                    family: "inet6".to_string(),
                    address: "2001:559:8585:50::8/64".to_string(),
                    scope: 0,
                },
            ],
            ..Default::default()
        }],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "8.8.8.0/24".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "blue.inet.0".to_string(),
                preference: 0,
            },
            RouteSnapshot {
                table: "blue.inet.0".to_string(),
                family: "inet".to_string(),
                destination: "8.8.8.0/24".to_string(),
                next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2606:4700:4700::/48".to_string(),
                next_hops: vec![],
                discard: false,
                next_table: "blue.inet6.0".to_string(),
                preference: 0,
            },
            RouteSnapshot {
                table: "blue.inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "2606:4700:4700::/48".to_string(),
                next_hops: vec!["2001:559:8585:50::1@ge-0/0/0.50".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
        ],
        neighbors: if include_neighbor {
            vec![
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet".to_string(),
                    ip: "172.16.50.1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
                NeighborSnapshot {
                    interface: "ge-0-0-0.50".to_string(),
                    ifindex: 12,
                    family: "inet6".to_string(),
                    ip: "2001:559:8585:50::1".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    state: "reachable".to_string(),
                    router: true,
                    link_local: false,
                },
            ]
        } else {
            vec![]
        },
        ..Default::default()
    }
}

pub(super) fn forwarding_snapshot_with_next_table_loop() -> ConfigSnapshot {
    ConfigSnapshot {
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec![],
            discard: false,
            next_table: "inet.0".to_string(),
            preference: 0,
        }],
        ..Default::default()
    }
}

pub(super) fn nat_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            // #3705: EVERY known zone is host-inbound ENFORCING (the build path
            // inserts an entry regardless of the flag). These fixture zones carry
            // `system-services any-service` so host-bound (local-delivery) traffic
            // is admitted — the explicit form of the pre-#3705 configured=false
            // admit-all default the local-delivery tests rely on. Transit tests
            // never reach the host-inbound gate, so this is behavior-preserving.
            // #3226: `any-service` (not `all`) is the packet-wide admit token —
            // `all` now expands to the named system-service union.
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                redundancy_group: 2,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "10.0.61.1/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:ef00::1/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                parent_ifindex: 11,
                redundancy_group: 1,
                vlan_id: 80,
                hardware_addr: "02:bf:72:00:80:08".to_string(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".to_string(),
                        address: "172.16.80.8/24".to_string(),
                        scope: 0,
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".to_string(),
                        address: "2001:559:8585:80::8/64".to_string(),
                        scope: 0,
                    },
                ],
                ..Default::default()
            },
        ],
        routes: vec![
            RouteSnapshot {
                table: "inet.0".to_string(),
                family: "inet".to_string(),
                destination: "0.0.0.0/0".to_string(),
                next_hops: vec!["172.16.80.1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
            RouteSnapshot {
                table: "inet6.0".to_string(),
                family: "inet6".to_string(),
                destination: "::/0".to_string(),
                next_hops: vec!["2001:559:8585:80::1@reth0.80".to_string()],
                discard: false,
                next_table: String::new(),
                preference: 0,
            },
        ],
        source_nat_rules: vec![
            SourceNATRuleSnapshot {
                name: "snat".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                interface_mode: true,
                ..Default::default()
            },
            SourceNATRuleSnapshot {
                name: "snat6".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["::/0".to_string()],
                interface_mode: true,
                ..Default::default()
            },
        ],
        default_policy: "deny".to_string(),
        policies: vec![PolicyRuleSnapshot {
            name: "allow-all".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        neighbors: vec![
            NeighborSnapshot {
                interface: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                family: "inet".to_string(),
                ip: "172.16.80.1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
            NeighborSnapshot {
                interface: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                family: "inet6".to_string(),
                ip: "2001:559:8585:80::1".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                state: "reachable".to_string(),
                router: true,
                link_local: false,
            },
        ],
        ..Default::default()
    }
}

pub(super) fn nat_snapshot_with_fabric() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "ge-0/0/0".to_string(),
        linux_name: "ge-0-0-0".to_string(),
        ifindex: 21,
        hardware_addr: "02:bf:72:ff:00:01".to_string(),
        ..Default::default()
    });
    snapshot.fabrics = vec![FabricSnapshot {
        parent_unbindable: false,
        name: "fab0".to_string(),
        parent_interface: "ge-0/0/0".to_string(),
        parent_linux_name: "ge-0-0-0".to_string(),
        parent_ifindex: 21,
        overlay_linux_name: "fab0".to_string(),
        overlay_ifindex: 101,
        rx_queues: 2,
        peer_address: "10.99.13.2".to_string(),
        local_mac: "02:bf:72:ff:00:01".to_string(),
        peer_mac: "00:aa:bb:cc:dd:ee".to_string(),
        up: true,
    }];
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "fab0".to_string(),
        ifindex: 101,
        family: "inet".to_string(),
        ip: "10.99.13.2".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    });
    snapshot
}

pub(super) fn policy_deny_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        // #2391: interfaces below reference "lan"/"wan"; the zone table must
        // define them or the forwarding build fails closed (InterfaceUnknownZone).
        // #3705: every known zone is host-inbound enforcing; carry
        // `any-service` so host-bound local-delivery traffic is admitted
        // (explicit form of the pre-#3705 configured=false admit-all default).
        // #3226: `any-service` is the packet-wide admit token — `all` now
        // expands to the named system-service union. Behavior-preserving.
        zones: vec![
            ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
            ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
            ZoneSnapshot {
                name: "dmz".to_string(),
                id: TEST_DMZ_ZONE_ID,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["any-service".to_string()],
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 24,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-0.80".to_string(),
                ifindex: 12,
                parent_ifindex: 11,
                vlan_id: 80,
                hardware_addr: "02:bf:72:00:80:08".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.80.8/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        default_policy: "deny".to_string(),
        policies: vec![PolicyRuleSnapshot {
            name: "allow-other".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

pub(super) fn valid_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        flow_src_port: 0x1234,
        flow_src_addr: [172, 16, 80, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flow_dst_addr: [172, 16, 80, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        config_generation: 11,
        fib_generation: 7,
        ..UserspaceDpMeta::default()
    }
}

pub(super) fn vlan_icmp_reply_frame() -> Vec<u8> {
    let mut frame = vec![
        0x02, 0xbf, 0x72, 0x16, 0x02, 0x00, 0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, 0x81, 0x00, 0x00,
        0x50, 0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
        0xac, 0x10, 0x50, 0xc8, 0xac, 0x10, 0x50, 0x08, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00,
        0x01,
    ];
    frame.resize(98, 0);
    frame
}

pub(super) fn static_nat_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "trust".to_string(),
                id: TEST_TRUST_ZONE_ID,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "untrust".to_string(),
                id: TEST_UNTRUST_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/0".to_string(),
                zone: "trust".to_string(),
                linux_name: "ge-0-0-0".to_string(),
                ifindex: 5,
                hardware_addr: "02:bf:72:01:00:00".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "192.168.1.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/1".to_string(),
                zone: "untrust".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 6,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "203.0.113.1/24".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: vec![RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec!["203.0.113.254@ge-0/0/1".to_string()],
            discard: false,
            next_table: String::new(),
            preference: 0,
        }],
        static_nat_rules: vec![StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            counter_id: 0,
            name: "web-server".to_string(),
            from_zone: "untrust".to_string(),
            from_interface: String::new(),
            from_routing_instance: String::new(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            match_destination_port: 0,
            mapped_port: 0,
        }],
        default_policy: "deny".to_string(),
        policies: vec![
            PolicyRuleSnapshot {
                name: "allow-inbound".to_string(),
                from_zone: "untrust".to_string(),
                to_zone: "trust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                name: "allow-outbound".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        neighbors: vec![
            NeighborSnapshot {
                interface: "ge-0-0-0".to_string(),
                ifindex: 5,
                family: "inet".to_string(),
                ip: "192.168.1.10".to_string(),
                mac: "aa:bb:cc:dd:ee:10".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            },
            NeighborSnapshot {
                interface: "ge-0-0-1".to_string(),
                ifindex: 6,
                family: "inet".to_string(),
                ip: "203.0.113.254".to_string(),
                mac: "aa:bb:cc:dd:ee:fe".to_string(),
                state: "reachable".to_string(),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

/// Compute the RFC 4443 ICMPv6 checksum over the IPv6 pseudo-header
/// (src + dst + upper-layer length + next-header 58) plus the ICMPv6
/// message (`l4_start..packet_end`, checksum field treated as zero).
/// One-shot 16-bit one's-complement fold. Shared by the parser tests
/// (#2368 NDP NA frames) and the poll_stages neighbor-keying tests
/// (#2370) so the stamping logic has a single source of truth.
pub(super) fn compute_icmpv6_checksum(
    frame: &[u8],
    l3_start: usize,
    l4_start: usize,
    packet_end: usize,
) -> u16 {
    const NEXT_HEADER_ICMPV6: u8 = 58;
    let mut sum: u32 = 0;
    let add = |sum: &mut u32, bytes: &[u8]| {
        let mut i = 0;
        while i + 1 < bytes.len() {
            *sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            *sum += (bytes[i] as u32) << 8;
        }
    };
    // pseudo-header: src(16) + dst(16) + len(32) + [0,0,0,58]
    add(&mut sum, &frame[l3_start + 8..l3_start + 24]);
    add(&mut sum, &frame[l3_start + 24..l3_start + 40]);
    let icmp_len = (packet_end - l4_start) as u32;
    add(&mut sum, &icmp_len.to_be_bytes());
    add(&mut sum, &[0, 0, 0, NEXT_HEADER_ICMPV6]);
    // ICMPv6 message with the checksum field zeroed.
    let mut icmp = frame[l4_start..packet_end].to_vec();
    icmp[2] = 0;
    icmp[3] = 0;
    add(&mut sum, &icmp);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Stamp a valid ICMPv6 checksum into `frame` in place (IPv6 base header
/// at `l3_start`, ICMPv6 message at `l4_start`, declared packet end at
/// `packet_end`). See [`compute_icmpv6_checksum`].
pub(super) fn stamp_icmpv6_checksum(
    frame: &mut [u8],
    l3_start: usize,
    l4_start: usize,
    packet_end: usize,
) {
    let csum = compute_icmpv6_checksum(frame, l3_start, l4_start, packet_end);
    frame[l4_start + 2..l4_start + 4].copy_from_slice(&csum.to_be_bytes());
}
