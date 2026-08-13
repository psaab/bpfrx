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

// ---------------------------------------------------------------------------
// #6713 / #6722 secure-tunnel (MAC-less egress) zone fixtures.
//
// These live HERE, not in `afxdp::forwarding::tests`, because three test files
// adjudicate the same shapes — the zone-pair resolver
// (`afxdp::forwarding::tests`), the filter-log egress-zone field
// (`afxdp::poll_descriptor::filter`) and the live-forward request builder
// (`afxdp::frame::tests_ports_live_forward`). Round 3 kept a hand-built
// `ForwardingState` in the latter two and claimed independently maintained
// fixtures could not drift; they can and did — both hand-built states
// populated `ifindex_to_zone_id` alone, so they went RED on a change that the
// real builder made correct. One definition, driven through the real
// `build_forwarding_state`, removes the class.
//
// The row shapes are MEASURED against the Go builders, not assumed:
// `pkg/dataplane/userspace/zone_propagation_6722_test.go` runs
// `buildInterfaceZoneMap` + `buildSnapshot` on these exact configs and pins
// what they emit.
// ---------------------------------------------------------------------------

/// The zone the secure tunnel is put in. Aliases an existing id so nothing has
/// to be added to `test_zone_ids`.
pub(super) const TEST_SIBLING_VPN_ZONE_ID_6722: u16 = TEST_DMZ_ZONE_ID;
/// A SECOND tunnel zone, for the two-units-in-different-zones shape.
pub(super) const TEST_OTHER_VPN_ZONE_ID_6722: u16 = TEST_SFMIX_ZONE_ID;
/// The LAN interface every transit in these fixtures ingresses on.
pub(super) const LAN_IFINDEX_6722: i32 = 24;
/// `st0` and `st0.0` share this ifindex (`snapshotLinuxName` collapses a
/// non-VLAN unit 0 onto its base netdev).
pub(super) const SHARED_TUNNEL_IFINDEX_6722: i32 = 42;
/// `st0.1` gets its own netdev (`LinuxIfName("st0.1")`), hence its own ifindex.
pub(super) const ZONED_TUNNEL_IFINDEX_6722: i32 = 43;
/// `st0.2` in the divergent-zone shape.
pub(super) const THIRD_TUNNEL_IFINDEX_6722: i32 = 44;

fn lan_row_6722() -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: "reth1.0".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: LAN_IFINDEX_6722,
        mtu: 1500,
        hardware_addr: "02:bf:72:01:00:01".to_string(),
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.61.1/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    }
}

fn tunnel_zones_6722() -> Vec<ZoneSnapshot> {
    vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "vpnb".to_string(),
            id: TEST_SIBLING_VPN_ZONE_ID_6722,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "vpnc".to_string(),
            id: TEST_OTHER_VPN_ZONE_ID_6722,
            ..Default::default()
        },
    ]
}

/// `192.168.99.0/24` -> unit 0's next hop (the SHARED ifindex);
/// `192.168.98.0/24` -> unit 1's; `192.168.97.0/24` -> unit 2's.
fn tunnel_routes_6722() -> Vec<RouteSnapshot> {
    ["192.168.99.0/24", "192.168.98.0/24", "192.168.97.0/24"]
        .iter()
        .zip(["10.5.5.2", "10.6.6.2", "10.7.7.2"])
        .map(|(dst, nh)| RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: (*dst).to_string(),
            next_hops: vec![nh.to_string()],
            discard: false,
            next_table: String::new(),
            preference: 5,
        })
        .collect()
}

/// `from-zone lan to-zone vpnb permit` + `from-zone lan to-zone vpnc permit`,
/// under a `deny-all` default policy. Every fixture below shares these, so a
/// to-zone that resolves to EITHER tunnel zone is Permit and a to-zone of 0 is
/// the default deny — the two outcomes are cleanly separable.
fn tunnel_policies_6722() -> Vec<PolicyRuleSnapshot> {
    ["vpnb", "vpnc"]
        .iter()
        .map(|to| PolicyRuleSnapshot {
            name: format!("lan-to-{to}"),
            from_zone: "lan".to_string(),
            to_zone: (*to).to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        })
        .collect()
}

fn tunnel_unit_row_6722(
    name: &str,
    zone: &str,
    linux_name: &str,
    ifindex: i32,
    parent_ifindex: i32,
    address: &str,
) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.to_string(),
        zone: zone.to_string(),
        linux_name: linux_name.to_string(),
        parent_linux_name: "st0".to_string(),
        ifindex,
        parent_ifindex,
        mtu: 1400,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: address.to_string(),
            scope: 0,
        }],
        ..Default::default()
    }
}

/// AMBIGUOUS shared ifindex, the #6722 fail-open shape.
///
/// ```text
/// set interfaces st0 unit 0 family inet address 10.5.5.1/30    # no zone REF
/// set interfaces st0 unit 1 family inet address 10.6.6.1/30
/// set security zones security-zone vpnb interfaces st0.1       # unit 1 only
/// set routing-options static route 192.168.99.0/24 next-hop 10.5.5.2  # -> unit 0
/// set routing-options static route 192.168.98.0/24 next-hop 10.6.6.2  # -> unit 1
/// set security policies default-policy deny-all
/// ```
///
/// The `st0` BASE row arrives carrying `vpnb`: `buildInterfaceZoneMap` writes
/// `out["st0"]` when the only zone reference is `st0.1`. Unit 0 — which the
/// operator deliberately left in NO zone — shares that base ifindex, so the
/// rows on ifindex 42 DISAGREE (`vpnb` vs none) and the ifindex identifies no
/// single zone. `st0.1` is on its own ifindex 43 and is unambiguous.
///
/// Both units are MAC-less, so NEITHER gets a `state.egress` row and the #6713
/// fallback is the only thing that can resolve either to-zone.
pub(super) fn sibling_tunnel_units_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: "vpnb".to_string(),
                linux_name: "st0".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 2,
                ..Default::default()
            },
            tunnel_unit_row_6722(
                "st0.0",
                "",
                "st0",
                SHARED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.5.5.1/30",
            ),
            tunnel_unit_row_6722(
                "st0.1",
                "vpnb",
                "st0.1",
                ZONED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.6.6.1/30",
            ),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// UNAMBIGUOUS shared ifindex — #6713 in its plainest deployed spelling.
///
/// ```text
/// set interfaces st0 unit 0 family inet address 10.5.5.1/30
/// set security zones security-zone vpnb interfaces st0     # the BARE base ref
/// ```
///
/// `buildInterfaceZoneMap` fans a base-named reference out to every unit, so
/// BOTH rows on ifindex 42 carry `vpnb`. The ifindex names exactly one zone and
/// the fallback must resolve it — this is the case a too-strict ambiguity gate
/// would break, and the reason the gate keys on DISAGREEMENT rather than on
/// "more than one row shares this ifindex".
pub(super) fn unanimous_shared_ifindex_tunnel_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: "vpnb".to_string(),
                linux_name: "st0".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 1,
                ..Default::default()
            },
            tunnel_unit_row_6722(
                "st0.0",
                "vpnb",
                "st0",
                SHARED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.5.5.1/30",
            ),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// Two units in DIFFERENT zones on one `st0`, with unit 0 in neither.
///
/// ```text
/// set interfaces st0 unit 0 family inet address 10.5.5.1/30   # no zone REF
/// set security zones security-zone vpnb interfaces st0.1
/// set security zones security-zone vpnc interfaces st0.2
/// ```
///
/// `buildInterfaceZoneMap`'s `out[base]` write is FIRST-write-wins over
/// SORTED zone names, so the base row — and therefore unit 0's ifindex —
/// carries `vpnb`, the alphabetically-first sibling's zone, purely because "b"
/// sorts before "c". Reading `ifindex_to_zone_id` for the egress half would
/// adjudicate unit 0's transit under a zone chosen by alphabetical accident.
pub(super) fn divergent_zone_sibling_units_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: "vpnb".to_string(),
                linux_name: "st0".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 3,
                ..Default::default()
            },
            tunnel_unit_row_6722(
                "st0.0",
                "",
                "st0",
                SHARED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.5.5.1/30",
            ),
            tunnel_unit_row_6722(
                "st0.1",
                "vpnb",
                "st0.1",
                ZONED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.6.6.1/30",
            ),
            tunnel_unit_row_6722(
                "st0.2",
                "vpnc",
                "st0.2",
                THIRD_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.7.7.1/30",
            ),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// POST-QUARANTINE shape: an UNZONED base beside a zoned child.
///
/// `quarantineCollidingZones` (`pkg/dataplane/userspace/zones_quarantine.go`)
/// runs AFTER `buildInterfaceSnapshots` and blanks `Zone` on every row bound to
/// a StableZoneID-colliding zone, expressly so those interfaces fail CLOSED. If
/// the zone that won `out["st0"]` is the quarantined one and a later-sorting
/// sibling's zone survives, the base and unit 0 arrive UNZONED while `st0.1`
/// stays zoned:
///
/// ```text
/// zones `mmm` and `aaa` collide on one StableZoneID -> `mmm` quarantined
/// set security zones security-zone mmm interfaces st0.0    # -> blanked
/// set security zones security-zone zzz interfaces st0.1    # survives
/// ```
///
/// This is what makes `populate_interfaces`' child->parent propagation
/// REACHABLE for a Go-produced snapshot (round 3 asserted it was not): the
/// propagation writes `ifindex_to_zone_id[42] = vpnb` from `st0.1`. The egress
/// half must NOT read that — handing the quarantine's deliberate default-deny
/// back the survivor's zone is the fail-open the quarantine exists to prevent.
pub(super) fn quarantined_base_tunnel_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: String::new(),
                linux_name: "st0".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 2,
                ..Default::default()
            },
            tunnel_unit_row_6722(
                "st0.0",
                "",
                "st0",
                SHARED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.5.5.1/30",
            ),
            tunnel_unit_row_6722(
                "st0.1",
                "vpnb",
                "st0.1",
                ZONED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.6.6.1/30",
            ),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// REUSED ifindex: two UNRELATED interfaces (no parent/child link) landing on
/// one ifindex in differing zones. The kernel recycles an ifindex after a
/// netdev teardown, and `buildLinkSnapshot` resolves each row independently, so
/// a snapshot built across a teardown can name the recycled index twice. There
/// is no basis whatsoever for picking one of the two zones, so the egress half
/// must resolve 0 and let the default policy decide.
pub(super) fn reused_ifindex_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            // BOTH base rows are present: `buildInterfaceSnapshots` emits a base
            // row for every interface, so a shape that shows only the units is
            // one the builder never produces. `st1`'s rows carry the RECYCLED
            // index.
            InterfaceSnapshot {
                name: "st0".to_string(),
                zone: "vpnb".to_string(),
                linux_name: "st0".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 1,
                ..Default::default()
            },
            tunnel_unit_row_6722(
                "st0.0",
                "vpnb",
                "st0",
                SHARED_TUNNEL_IFINDEX_6722,
                SHARED_TUNNEL_IFINDEX_6722,
                "10.5.5.1/30",
            ),
            InterfaceSnapshot {
                name: "st1".to_string(),
                zone: "vpnc".to_string(),
                linux_name: "st1".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                unit_count: 1,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "st1.0".to_string(),
                zone: "vpnc".to_string(),
                linux_name: "st1".to_string(),
                ifindex: SHARED_TUNNEL_IFINDEX_6722,
                mtu: 1400,
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.9.9.1/30".to_string(),
                    scope: 0,
                }],
                ..Default::default()
            },
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// #6722 B1/B2: INTERFACE-LEVEL TUNNEL shapes — several units on ONE ifindex
// that DO get `state.egress` rows.
//
// The xfrmi fixtures above are all MAC-less, so `populate_egress`'s `src_mac`
// gate denies them an egress row and `egress_zone_id` reaches its fallback.
// That made the whole ambiguity suite blind to the OTHER arm of the resolver:
// `self.egress.get(..).map(|i| i.zone_id)` is consulted FIRST, and
// `populate_egress` writes it last-write-wins per ifindex.
//
// A WireGuard interface-level tunnel produces exactly that. `TunnelNameMap`
// (`pkg/config/types.go`) maps every unit WITHOUT its own tunnel stanza onto
// the interface device — the branch explicitly admits WireGuard despite its
// empty GRE-style `source` — so `wg0`, `wg0.0` and `wg0.1` are ONE netdev and
// one ifindex (pinned by `pkg/dataplane/userspace/tunnels_test.go`, which
// asserts all three rows at `LinuxName: "wg0", Ifindex: 42`). They carry
// `tunnel = true`, so `populate_egress` admits them through
// `iface.tunnel.then_some([0; 6])` rather than a real MAC.
//
// My round-5 comment claimed a third row on one ifindex could not come from
// another unit, citing `TunnelNameMap`'s per-unit branch (`gr-0-0-0u1`). That
// branch applies only to units that have their OWN tunnel stanza; the
// interface-level branch does the opposite. The claim was false and it is what
// hid this arm.
// ---------------------------------------------------------------------------

fn wg_row_6722(name: &str, zone: &str, address: Option<&str>) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.to_string(),
        zone: zone.to_string(),
        // Every unit of an interface-level tunnel resolves to the base device.
        linux_name: "wg0".to_string(),
        ifindex: SHARED_TUNNEL_IFINDEX_6722,
        mtu: 1400,
        tunnel: true,
        addresses: address
            .map(|a| {
                vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: a.to_string(),
                    scope: 0,
                }]
            })
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// `[vpnb, none, vpnb]` on one ifindex, WITH egress rows — the #6722 fail-open
/// reached through `state.egress` instead of through the fallback.
///
/// ```text
/// set interfaces wg0 tunnel mode wireguard
/// set interfaces wg0 unit 0 family inet address 10.5.5.1/30   # no zone REF
/// set interfaces wg0 unit 1 family inet address 10.6.6.1/30
/// set security zones security-zone vpnb interfaces wg0.1      # unit 1 only
/// ```
///
/// `buildInterfaceZoneMap` stamps the `wg0` BASE row with `vpnb` for the
/// unit-suffixed reference, `wg0.0` is left in NO zone by the operator, and
/// `wg0.1` carries `vpnb`. All three share ifindex 42. `populate_egress` is
/// last-write-wins, so the final row's `vpnb` lands in `egress[42].zone_id` and
/// `egress_zone_id` returns it WITHOUT consulting the agreement ledger —
/// transit routed out the deliberately-unzoned `wg0.0` matches
/// `from-zone lan to-zone vpnb permit`.
///
/// This is also the shape that shows the pre-#6722 `unzoned_interface_with_
/// egress_row_stays_zone_zero_6713` behaviour was EMISSION-ORDER luck: there
/// the unzoned unit-0 row happened to be emitted last and 0 won; here a zoned
/// row is last and the zone wins.
pub(super) fn wg_iface_tunnel_unzoned_unit_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            wg_row_6722("wg0", "vpnb", None),
            wg_row_6722("wg0.0", "", Some("10.5.5.1/30")),
            wg_row_6722("wg0.1", "vpnb", Some("10.6.6.1/30")),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// `[none, none, vpnb]` — the ZERO SENTINEL first, with egress rows.
///
/// Post-quarantine spelling: the zone that won `out["wg0"]` was the
/// StableZoneID-colliding one, so the base and unit 0 arrive UNZONED while a
/// later-sorting sibling keeps its zone. The zoned row is emitted LAST, so
/// `populate_egress`'s last write is `vpnb` even though two of the three rows
/// name no zone at all.
pub(super) fn wg_iface_tunnel_sentinel_first_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            wg_row_6722("wg0", "", None),
            wg_row_6722("wg0.0", "", Some("10.5.5.1/30")),
            wg_row_6722("wg0.1", "vpnb", Some("10.6.6.1/30")),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

/// `[vpnb, vpnb, vpnb]` — THREE agreeing rows on one ifindex, with egress rows.
///
/// ```text
/// set interfaces wg0 tunnel mode wireguard
/// set interfaces wg0 unit 0 family inet address 10.5.5.1/30
/// set interfaces wg0 unit 1 family inet address 10.6.6.1/30
/// set security zones security-zone vpnb interfaces wg0        # BARE base ref
/// ```
///
/// A base-named zone reference fans out to every unit, so all three rows carry
/// `vpnb` and the ifindex names exactly one zone. This is the SCOPE control for
/// the whole #6722 gate: it must keep resolving `vpnb` and reaching the
/// operator's permit. Over-tightening into "several rows on one ifindex means
/// no zone" would deny an ordinary WireGuard deployment.
pub(super) fn wg_iface_tunnel_unanimous_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: tunnel_zones_6722(),
        interfaces: vec![
            lan_row_6722(),
            wg_row_6722("wg0", "vpnb", None),
            wg_row_6722("wg0.0", "vpnb", Some("10.5.5.1/30")),
            wg_row_6722("wg0.1", "vpnb", Some("10.6.6.1/30")),
        ],
        routes: tunnel_routes_6722(),
        default_policy: "deny".to_string(),
        policies: tunnel_policies_6722(),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// #6722 B2: the BONDLESS-RETH shape — the third way several rows land on one
// ifindex, and the only one that reaches a SHIPPED topology.
//
// `ResolveReth` (`pkg/config/types.go`) collapses a RETH onto its physical
// member's netdev, and `snapshotLinuxName`
// (`pkg/dataplane/userspace/interfaces.go`) applies it to BOTH the `reth1`
// base row and `reth1.0`:
//
//     snapshotLinuxName(reth1)   -> LinuxIfName(ResolveReth("reth1")) = ge-0-0-1
//     snapshotLinuxName(reth1.0) -> LinuxIfName(ResolveReth("reth1")) = ge-0-0-1
//     snapshotLinuxName(ge-0/0/1)-> LinuxIfName("ge-0/0/1")           = ge-0-0-1
//
// Junos zones the RETH, never its member, so `buildInterfaceZoneMap`
// (`pkg/dataplane/userspace/zones.go`) leaves the member row UNZONED and
// `buildInterfaceSnapshots` emits it unfiltered. Three rows, one ifindex,
// and the member's "no zone" DISAGREES with the RETH's.
//
// Measured through the full `buildSnapshot` on the reference cluster config
// (`docs/ha-cluster-userspace.conf`, node 0 — the topology
// `test/incus/loss-userspace-cluster.env` points every HA smoke test at):
//
//     ifindex 24: [ge-0/0/1="" reth1="lan" reth1.0="lan"]   <-- DISAGREE
//     ifindex 25: [ge-0/0/2="" reth0="wan"]                 <-- DISAGREE
//     DefaultPolicy="deny"
//
// Unlike `wg0.0` / `st0.0`, the member's unzoned row is NOT an operator
// statement about a distinct forwarding entity. A RETH and its member are one
// kernel netdev; nothing can egress `ge-0/0/1` that is not `reth1.0` traffic.
// The disagreement is an artefact of describing one device with three rows, so
// the member must cast no zone vote — see `populate_interfaces`.
//
// Direction matters here. The regression this fixture pins is on the EGRESS
// half only: `ifindex_to_zone_id[24]` still carries `lan`, so a packet
// ARRIVING on the LAN is attributed correctly and only the to-zone collapses
// to the 0 sentinel. That asymmetry is the tell.
// ---------------------------------------------------------------------------

/// The WAN-side ingress netdev in the bondless-RETH fixtures (`reth0.80` ->
/// `ge-0-0-2.80`, its own VLAN child netdev and so its own ifindex).
pub(super) const WAN_IFINDEX_6722: i32 = 27;

/// A row on the LAN RETH's SHARED netdev (`ge-0-0-1`, `LAN_IFINDEX_6722`).
/// Every bondless-RETH row resolves to the physical member's netdev, so `name`
/// is the only thing that distinguishes them.
fn reth_row_6722(
    name: &str,
    zone: &str,
    redundant_parent: &str,
    address: Option<&str>,
) -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: name.to_string(),
        zone: zone.to_string(),
        linux_name: "ge-0-0-1".to_string(),
        ifindex: LAN_IFINDEX_6722,
        mtu: 1500,
        // Only the PHYSICAL MEMBER carries this; the reth rows do not.
        redundant_parent: redundant_parent.to_string(),
        // Bondless RETH: the member netdev carries the RETH's virtual MAC, so
        // every row on it is MAC-ful and `populate_egress` gives all three an
        // egress row. This is the `state.egress` arm, not the #6713 fallback.
        hardware_addr: "02:bf:72:01:00:01".to_string(),
        redundancy_group: 2,
        addresses: address
            .map(|a| {
                vec![InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: a.to_string(),
                    scope: 0,
                }]
            })
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// The WAN ingress row: `reth0.80`, a VLAN child with its OWN netdev and
/// ifindex, so the WAN side is unambiguous and only the LAN egress half is
/// under test.
fn wan_row_6722() -> InterfaceSnapshot {
    InterfaceSnapshot {
        name: "reth0.80".to_string(),
        zone: "wan".to_string(),
        linux_name: "ge-0-0-2.80".to_string(),
        ifindex: WAN_IFINDEX_6722,
        vlan_id: 80,
        mtu: 1500,
        hardware_addr: "02:bf:72:00:00:02".to_string(),
        redundancy_group: 1,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.80.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    }
}

fn reth_zones_6722() -> Vec<ZoneSnapshot> {
    vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
    ]
}

/// `from-zone wan to-zone lan permit`, under a `deny-all` default. The LAN is
/// the TO-zone here, which is the half #6722 B1 changed.
fn reth_policies_6722() -> Vec<PolicyRuleSnapshot> {
    vec![PolicyRuleSnapshot {
        name: "wan-to-lan".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    }]
}

/// The reference bondless-RETH LAN: an UNZONED physical member plus a zoned
/// `reth1` base plus a zoned `reth1.0`, all on ONE ifindex.
///
/// ```text
/// set interfaces ge-0/0/1 gigether-options redundant-parent reth1
/// set interfaces reth1 redundant-ether-options redundancy-group 2
/// set interfaces reth1 unit 0 family inet address 10.0.61.1/24
/// set security zones security-zone lan interfaces reth1
/// ```
///
/// Row order matches `buildInterfaceSnapshots`, which walks interface names
/// SORTED — `ge-0/0/1` sorts before `reth1`, so the member votes FIRST and the
/// two agreeing RETH rows follow. That ordering is why the pre-#6722 code
/// (`populate_egress` last-write-wins on the row's own zone) happened to land
/// `lan` and why the ledger, which is order-independent, lands `None` instead.
pub(super) fn reth_member_unzoned_row_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: reth_zones_6722(),
        interfaces: vec![
            wan_row_6722(),
            reth_row_6722("ge-0/0/1", "", "reth1", None),
            reth_row_6722("reth1", "lan", "", None),
            reth_row_6722("reth1.0", "lan", "", Some("10.0.61.1/24")),
        ],
        default_policy: "deny".to_string(),
        policies: reth_policies_6722(),
        ..Default::default()
    }
}

/// OVER-REACH CONTROL fixture: the member row carries its own EXPLICIT zone,
/// different from the RETH's.
///
/// ```text
/// set security zones security-zone wan interfaces ge-0/0/1   # the MEMBER
/// set security zones security-zone lan interfaces reth1
/// ```
///
/// That is a real operator statement about a real conflict, not an artefact of
/// one netdev described three times, so it must keep failing CLOSED. The
/// exemption is scoped to an UNZONED member row for exactly this reason.
pub(super) fn reth_member_explicitly_zoned_snapshot_6722() -> ConfigSnapshot {
    ConfigSnapshot {
        zones: reth_zones_6722(),
        interfaces: vec![
            wan_row_6722(),
            reth_row_6722("ge-0/0/1", "wan", "reth1", None),
            reth_row_6722("reth1", "lan", "", None),
            reth_row_6722("reth1.0", "lan", "", Some("10.0.61.1/24")),
        ],
        default_policy: "deny".to_string(),
        policies: reth_policies_6722(),
        ..Default::default()
    }
}
