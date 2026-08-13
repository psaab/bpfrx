package userspace

import "strings"

// Which interfaces the userspace dataplane does NOT adjudicate.
//
// Split out of maps_sync.go in #6691 round 8. The predicate is ~20 lines of
// code carrying ~180 lines of rationale — five exclusion classes, each with a
// documented reason and a documented cost — and keeping it inline pushed
// maps_sync.go past the 2000-line refactor threshold on comment alone. It has
// four call sites (enumerated in the secure-tunnel arm below), none of which
// lives in maps_sync.go exclusively, so this is a pure move: no signature, no
// behaviour and no caller changes.

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
	if iface.Tunnel {
		return true
	}
	base := iface.Name
	if idx := strings.IndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	switch {
	case strings.HasPrefix(base, "fxp"):
		return true
	case strings.HasPrefix(base, "em"):
		return true
	case strings.HasPrefix(base, "fab"):
		return true
	case base == "lo0":
		return true
	case iface.SecureTunnel:
		// #5619: an IPsec secure tunnel is NOT adjudicated by the userspace
		// dataplane, and this arm says so out loud.
		//
		// KEYED ON OWNERSHIP, NOT ON NAME SHAPE (#6691 round 5). The row's
		// SecureTunnel flag is set by the snapshot builder from
		// Config.SecureTunnelNetdevForRef — some `security ipsec vpn <name>
		// bind-interface` derives this interface's if_id — so this arm
		// excludes exactly the interfaces an IPsec configuration actually
		// binds.
		//
		// It used to test config.IsSecureTunnelIfName(base), which is a
		// LEXICAL predicate: `st` followed by an index in [0, 65536). Nothing
		// reserves the `st` prefix — schema_interfaces.go accepts a wildcard
		// interface name — so
		//
		//	set interfaces st5 unit 0 family inet address 192.0.2.1/24
		//	set security zones security-zone trust interfaces st5.0
		//
		// is a valid config naming a real physical NIC with no VPN anywhere,
		// and the lexical arm dropped it out of adjudication, out of the
		// AF_XDP binding plan and out of the RSS allowlist. That is the
		// traffic outage the previous revision of this comment named while
		// causing it. TestUnownedStNameKeepsItsDataplaneRole pins both
		// directions of the ownership rule — the unowned `st5` keeps its role,
		// and an `st5` a VPN binds still loses it.
		//
		// The lexical predicate is still right for LEXICAL questions —
		// SecureTunnelUnitNetdev uses it to resolve `st<N>.<unit>` to a netdev
		// name — and remains the classifier the constructor-agreement guard
		// pins. It is only wrong as an OWNERSHIP test, which is what this arm
		// asks.
		//
		// Route-based IPsec decrypts in the KERNEL XFRM stack, which delivers
		// the plaintext on the xfrmi netdev (xfrmi_rcv_cb sets skb->dev, then
		// xfrm_input -> gro_cells_receive -> __netif_receive_skb_core). The
		// userspace dataplane has no path to hand a plaintext frame back INTO
		// an xfrmi for the egress direction, so it cannot own this interface
		// end-to-end yet.
		//
		// Until it can, the xfrmi must stay out of the dataplane sets THIS
		// PREDICATE GATES — and only those. There are FOUR call sites, not
		// three (#6691 round 8 corrected the count; the earlier text listed
		// the three that CHANGE an installed set and silently dropped the
		// other two consumers):
		//
		//   1. buildUserspaceIngressIfindexes  — the ingress-adjudication map.
		//   2. UserspaceBoundLinuxInterfaces   — the RSS/AF_XDP allowlist
		//                                        (interfaces.go), name-keyed.
		//   3. snapshotBindingPlanKey          — the plan-key HASH. Excluding
		//                                        the row here is what keeps the
		//                                        key from churning when a
		//                                        tunnel appears or moves.
		//   4. buildUserspaceIngressBindingAliases — measurably INERT for this
		//                                        row: an xfrmi has no parent
		//                                        ifindex, so it is already
		//                                        skipped by the ParentIfindex
		//                                        guard before this predicate is
		//                                        consulted. Listed because a
		//                                        future reader counting call
		//                                        sites will find it, not
		//                                        because it decides anything.
		//
		// The AF_XDP binding PLAN itself is gated on the Rust side by the
		// mirrored include_userspace_binding_interface (userspace-dp), off the
		// secure_tunnel flag this row carries — not by a fifth Go call site.
		//
		// SCOPE, stated because the narrower truth matters: this predicate does
		// NOT make the xfrmi invisible to the dataplane generally. Once #5619
		// made its ifindex resolve, the tunnel DOES enter the Rust
		// forwarding-state maps gated on `ifindex > 0` rather than on this
		// predicate — `populate_interfaces`
		// (userspace-dp/src/afxdp/forwarding_build/interfaces.rs), hence
		// `name_to_ifindex` and the zone map.
		//
		// It does NOT enter the EGRESS map: `populate_egress` needs a source
		// MAC (own, parent's, or the tunnel flag), and an xfrmi is ARPHRD_NONE
		// with no parent and no tunnel flag, so the row hits `None => continue`
		// and no EgressInterface is built. Nor does an authored `next-hop
		// st0.0` resolve: it reaches `parse_route_next_hop` as the bare string
		// `"st0.0"`, which returns `(None, None)` and leaves the target at
		// `(0, 0)` on both revisions — an earlier version of this comment
		// claimed both of those, and both were wrong.
		//
		// AND IT MOVES A TX DISPOSITION — an earlier version of this comment
		// claimed otherwise ("the TX dispatcher drops it as
		// missing_egress_binding either way"). That was WRONG: a LAN->tunnel
		// packet never reaches the TX dispatcher, because the FIB claims it
		// first. Measured end to end, real Go wire snapshot -> real Rust FIB,
		// `next-hop <gw-in-tunnel-subnet>`:
		//
		//	bind-interface st0    : MissingNeighbor before AND after
		//	bind-interface st0.0  : NoRoute before -> MissingNeighbor after
		//
		// Both spellings are ONE tunnel (same if_id, same unit ref `st0.0`),
		// so this is a CONVERGENCE onto what the canonical bare spelling
		// already did — the divergence WAS the name bug. It is still
		// operator-visible, because the two arms differ: `NoRoute` reinjects
		// to the kernel unconditionally, while `MissingNeighbor` resolves zone
		// ids and evaluates policy first, and a DENY exits before the reinject
		// gate.
		//
		// A PERMIT does NOT currently rescue it, and saying otherwise was the
		// review finding: with no EgressInterface (above) the to-zone reads 0,
		// and `evaluate_policy_result_l3_aware` refuses to match any rule —
		// exact, wildcard OR junos-global — when either zone id is 0, so the
		// flow takes the default action. That MAC-less-egress zone resolution
		// is a PRE-EXISTING defect (#6713) fixed by #6722; only once #6722
		// lands does a matching `from-zone <lan> to-zone <tunnel-zone> permit`
		// preserve delivery here. Until then the dotted spelling converges onto
		// the bare spelling's disposition — which is the point, the bare
		// spelling being what master already did — but it converges onto a
		// currently-denying one.
		// TestSecureTunnelSpellingsAgreeOnForwardingInputs pins the
		// convergence.
		//
		// Widening this exclusion to cover those maps would ALSO drop the
		// zone-map entry, and an interface absent from the zone map resolves
		// to zone_id 0 — which, per the guard just cited, matches nothing and
		// falls to the default action, so it would trade an adjudicated
		// disposition for an unadjudicable one.
		//
		// WHY ADMITTING IT IS WORSE, in the order the reasons can actually be
		// ESTABLISHED (#6691 round 8). An earlier revision of this comment led
		// with a claim it could not support, and a review leg was right to
		// refuse it.
		//
		//  1. IT COLLAPSES THE WHOLE BOX TO ONE QUEUE — the load-bearing
		//     reason, and the one that is provable without a NIC. An xfrm
		//     interface has exactly ONE RX queue: `ip -d link` reports
		//     `numrxqueues 1` and `/sys/class/net/<if>/queues` holds a single
		//     `rx-0` (measured in a netns). That single queue is what
		//     userspaceRXQueueCount reads and ships, and the Rust planner takes
		//     the GLOBAL MINIMUM across every candidate
		//     (replan_bindings_from_candidates, planning.rs). So ONE zoned
		//     xfrmi drags every physical interface on the box down to one queue
		//     and one worker — the #3091 ~6 Gbps single-worker regression by a
		//     different route. secure_tunnel_would_collapse_the_global_queue_count
		//     (userspace-dp/src/main_tests.rs) is the fail-on-revert guard.
		//
		//  2. AND IT CANNOT BE HALF-ADMITTED. "Adjudicate but do not bind" is
		//     not available: an ifindex in the shim's ingress map with no READY
		//     binding takes drop_degraded_transit
		//     (userspace-xdp/src/lib.rs, BINDING_MISSING). The ingress map and
		//     the binding plan move together or transit dies, which is why this
		//     one predicate gates both.
		//
		// NOT CLAIMED, deliberately: that an XSK cannot come up on an xfrmi at
		// all. ZERO-COPY plainly cannot (no ndo_bpf / ndo_xsk_wakeup), but
		// zero-copy is not required for every socket role — XskSocketRole::
		// Private returns false from requires_zerocopy, a generic-XDP interface
		// is offered COPY_ONLY_BIND_FLAGS, and a failed shared-UMEM group falls
		// back to a private socket automatically. A copy-mode binding is
		// REACHABLE in that code; whether it succeeds on an ARPHRD_NONE netdev
		// needs a live NIC and is untested. Reason 1 does not depend on it.
		//
		// THE COST IS REAL AND IS NOT A DROP. Decrypted plaintext traverses
		// Linux routing with NO xpf zone policy — see "What actually changes"
		// in the PR and #6700. That gap is what this arm buys the throughput
		// with; it is not what it prevents.
		//
		// Before #5619 this exclusion was an ACCIDENT for ONE spelling ONLY.
		// snapshotLinuxName collapsed unit 0, so `bind-interface st0.0`
		// resolved to the nonexistent netdev `st0`, carried ifindex 0 and fell
		// out of these sets on the `Ifindex <= 0` guard. `bind-interface st0`,
		// `st10.5` and `st0.7` all resolved to REAL ifindexes and were fully
		// adjudicated and RSS-bound — measured, not inferred. So this arm is
		// NEW behaviour for three of the four spellings, not a preserved
		// accident: it is what stops a route-based tunnel from collapsing the
		// AF_XDP binding plan onto a single XSK on a virtual netdev. Do not
		// delete it as inert.
		//
		// The consequence is real and operator-visible: decrypted IPsec
		// plaintext traverses Linux routing with NO xpf zone policy. That is
		// #5619's open half. Deleting this arm without building the egress
		// path re-opens the drop described above.
		return true
	}
	switch iface.Zone {
	case "mgmt", "control":
		return true
	}
	if iface.LocalFabric != "" {
		return true
	}
	return false
}
