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

// userspaceUnbindableNetdev reports whether a row's OWN netdev is one the
// userspace dataplane must never bind an AF_XDP socket to.
//
// #6691 round 8 SPLIT THE EXCLUSION IN TWO, and the split is the fix, not a
// tidy-up. The classes below are properties of the DEVICE — "whatever row asks,
// this netdev may not be bound" — so they are INHERITED by any row that
// redirects its binding onto the device. The classes left in
// userspaceSkipsIngressInterface (a mgmt/control ZONE, a local-fabric ROLE) are
// properties of the ROW, and a sibling row must NOT inherit them.
//
// The distinction is load-bearing in both directions:
//
//   - INHERITED. Under `bind-interface st10` plus a zoned sibling unit
//     (`st10 unit 5 vlan-id 100`, zone trust), the base row `st10` is excluded
//     — it IS the xfrmi — while the unit derives a DIFFERENT if_id
//     (`stIndex<<16 | unit+1`), is correctly SecureTunnel=false, and carries
//     ParentIfindex/ParentLinuxName pointing straight at the live xfrmi. Before
//     this split the child re-admitted its own excluded parent: measured at
//     head, the ingress set was [10 11] with 11 the xfrmi, the RSS allowlist
//     contained "st10", and the Rust planner re-keyed the orphan child onto
//     "st10" and dropped the LAN from 4 planned queues to 1 — the #3091
//     single-worker regression the exclusion exists to prevent, arriving
//     through the child.
//   - NOT INHERITED. A base row in the mgmt zone with a data-zoned VLAN unit
//     (reachable: buildInterfaceZoneMap keys the base off whichever zone entry
//     sorts first, so `security-zone mgmt interfaces ge-0/0/3.0` +
//     `security-zone trust interfaces ge-0/0/3.100` gives base=mgmt,
//     unit=trust) is the ORDINARY case the parent redirect exists for. The
//     trust VLAN's tagged frames arrive on the parent's hardware queues, so
//     the parent's ifindex MUST enter the ingress set or the unit carries no
//     traffic. Inheriting the mgmt exclusion there would be a forwarding
//     regression, not a fix. TestParentRedirectKeepsAMgmtZonedParent is the
//     negative control.
//
// Whether a class can actually leak is a separate question from where it
// belongs, and only ONE class can: Tunnel and LocalFabric are read off the same
// InterfaceConfig by both the base and the unit row, and the fxp/em/fab/lo0
// arms test the BASE name, which a unit shares. SecureTunnel is the only class
// keyed on something (the if_id) that a base and its unit can legitimately
// disagree about. TestExclusionClassesAgreeAcrossParentAndChild pins that
// enumeration so a new class cannot be added on the wrong side unnoticed.
func userspaceUnbindableNetdev(iface InterfaceSnapshot) bool {
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
		// KEYED ON OWNERSHIP OR DEVICE KIND, NEVER ON NAME SHAPE (#6691
		// rounds 5 and 8). The row's SecureTunnel flag is set by the snapshot
		// builder from snapshotSecureTunnel, which is the union of two facts:
		// some `security ipsec vpn <name> bind-interface` NAMES this row's
		// device (Config.SecureTunnelNetdevForRef), OR the netdev this row
		// resolves to has kernel link kind `xfrm` (liveXfrmNetdevs, round 8 —
		// the half that sees a live xfrmi the config no longer describes). So
		// this arm excludes exactly the interfaces that ARE route-based IPsec
		// tunnel devices, by configuration or by kernel fact.
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
		//   4. buildUserspaceIngressBindingAliases — INERT for the xfrmi's own
		//                                        row (an xfrmi has no parent
		//                                        ifindex, so the ParentIfindex
		//                                        guard skips it first). It is
		//                                        NOT inert for the redirect
		//                                        that names the xfrmi as a
		//                                        PARENT, which is why it now
		//                                        consults the refused-netdev
		//                                        index like the other two
		//                                        set-changing sites.
		//
		// Each of the three set-changing sites can be handed this netdev by a
		// row that is NOT this row — a zoned sibling unit redirecting onto its
		// parent. userspaceRefusedNetdevs (below) is what makes the refusal
		// travel with the NETDEV instead of stopping at the row, so the sites
		// enumerated above cannot be re-entered sideways.
		//
		// The AF_XDP binding PLAN itself is gated on the Rust side by the
		// mirrored include_userspace_binding_interface (userspace-dp), off the
		// secure_tunnel flag this row carries — not by a fifth Go call site.
		// Its own orphan-VLAN redirect is closed the same way, by
		// snapshot_refuses_parent_netdev (server/helpers/planning.rs).
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
	return false
}

func userspaceSkipsIngressInterface(iface InterfaceSnapshot) bool {
	// The DEVICE half — inherited by any row that redirects onto this netdev.
	if userspaceUnbindableNetdev(iface) {
		return true
	}
	// The ROW half. Both classes below describe what THIS row is for, not what
	// its netdev is, so a sibling row on the same netdev does not inherit them.
	switch iface.Zone {
	case "mgmt", "control":
		return true
	}
	if iface.LocalFabric != "" {
		return true
	}
	return false
}

// userspaceRefusedNetdevs indexes — by ifindex AND by Linux name — every netdev
// that some row in a snapshot has already been refused an AF_XDP binding for on
// DEVICE grounds (userspaceUnbindableNetdev).
//
// #6691 round 8. It exists because three of the four sets the exclusion gates
// let a row contribute a netdev that is NOT its own: a VLAN child binds its
// physical parent (#2917), so it emits the parent's ifindex into the ingress
// map, the parent's NAME into the RSS allowlist, and a child→parent entry into
// the binding aliases. Each of those is a way for a row to hand the dataplane a
// netdev a DIFFERENT row already failed the predicate for. Asking the row-level
// predicate again at each site cannot catch it — the child passes it. The
// question at a redirect is about the TARGET netdev, so the answer has to be
// indexed by netdev.
//
// BOTH keys are needed, and neither is redundant: the ingress map and the
// aliases are ifindex-keyed, while the RSS allowlist is name-keyed and is
// derived (UserspaceBoundLinuxInterfaces) without resolving ifindexes at all.
//
// Scope: built from rows, so it can only refuse a netdev some row NAMES. That
// is sufficient here because every unit row's parent netdev is the base row's
// netdev, and a unit exists only under a base in cfg.Interfaces.Interfaces — so
// a redirect target always has a row. A netdev no row names cannot be
// redirected onto in the first place.
type userspaceRefusedNetdevs struct {
	ifindex map[int]struct{}
	name    map[string]struct{}
}

func buildUserspaceRefusedNetdevs(ifaces []InterfaceSnapshot) userspaceRefusedNetdevs {
	out := userspaceRefusedNetdevs{
		ifindex: make(map[int]struct{}),
		name:    make(map[string]struct{}),
	}
	for _, iface := range ifaces {
		if !userspaceUnbindableNetdev(iface) {
			continue
		}
		// A LogicalOnly row's ifindex is SYNTHETIC (a private high-range value
		// standing in for a Linux VLAN child that was never created), so it
		// names no kernel netdev and must not be indexed as one. Its LinuxName
		// still is the netdev name the RSS allowlist would emit, so that key is
		// kept.
		if iface.Ifindex > 0 && !iface.LogicalOnly {
			out.ifindex[iface.Ifindex] = struct{}{}
		}
		if iface.LinuxName != "" {
			out.name[iface.LinuxName] = struct{}{}
		}
	}
	return out
}

func (r userspaceRefusedNetdevs) refusesIfindex(ifindex int) bool {
	if ifindex <= 0 {
		return false
	}
	_, refused := r.ifindex[ifindex]
	return refused
}

func (r userspaceRefusedNetdevs) refusesName(name string) bool {
	if name == "" {
		return false
	}
	_, refused := r.name[name]
	return refused
}
