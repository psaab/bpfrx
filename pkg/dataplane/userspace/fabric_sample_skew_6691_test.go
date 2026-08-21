package userspace

import (
	"slices"
	"testing"
)

// A FABRIC ROW AND AN INTERFACE ROW ARE SAMPLED AT DIFFERENT INSTANTS, and the
// refused index is keyed by name AND by ifindex from that skewed evidence
// (#6691 round 16).
//
// buildInterfaceSnapshots (interfaces.go) and buildFabricSnapshotsFrom
// (fabric.go) each take their OWN buildLinkSnapshot netlink sample, and
// SyncFabricState (manager_ha.go) refreshes the fabric rows ALONE and persists
// them back into m.lastSnapshot via persistResolvedFabricsLocked — beside
// interface rows that were never re-sampled. A member netdev that did not exist
// when the interface rows were built and does by the fabric refresh therefore
// leaves an OWNING, UNBINDABLE row at ifindex 0 (snapshotNetdevVotes gives it a
// NAME bucket but no IFINDEX bucket, `vote.ifindex > 0`) next to a fabric row
// carrying a live ifindex.
//
// That is the one shape where the two keys disagree, and before this round the
// readers split on it: the ingress-adjudication map asked only the IFINDEX and
// admitted the netdev, while both NAME-keyed readers refused it — the RSS
// allowlist's own fabric guard (UserspaceBoundLinuxInterfaces) and the Rust
// planner's snapshot_refuses_parent_netdev (server/helpers/planning.rs), which
// tallies owning rows by name with NO ifindex filter and so counts the
// ifindex-0 row. An ifindex in the ingress map with no READY binding is
// drop_degraded_transit (BINDING_MISSING): transit on the fabric parent drops.
//
// FAIL-ON-REVERT: drop the `|| refused.refusesName(fab.ParentLinuxName)`
// disjunct from the fabric loop in buildUserspaceIngressIfindexes and the
// ingress assertion reds with [20].
func TestSkewedFabricSampleKeepsIngressAndAllowlistAgreed(t *testing.T) {
	skewed := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{
				Name: "ge-0/0/3", LinuxName: "ge-0-0-3", Zone: "trust",
				Ifindex: 21, RXQueues: 6,
			},
			// The stale half: this row OWNS the member netdev (its bind target
			// is its own name) and is unbindable (the Tunnel exclusion class),
			// but its own link lookup missed, so it carries ifindex 0.
			{
				Name: "gr-0/0/3", LinuxName: "gr-0-0-3", Zone: "vpn",
				Ifindex: 0, Tunnel: true,
			},
		},
		// The fresh half: the same netdev, resolved.
		Fabrics: []FabricSnapshot{{
			Name: "fab0", ParentInterface: "gr-0/0/3", ParentLinuxName: "gr-0-0-3",
			ParentIfindex: 20, ParentUnbindable: true, RXQueues: 1,
		}},
	}

	// PREMISE: the two keys really do disagree on this snapshot. Without this
	// the assertions below would hold for the uninteresting reason that both
	// keys refuse, and the test would stop covering the skew at all.
	refused := buildUserspaceRefusedNetdevs(skewed)
	if !refused.refusesName("gr-0-0-3") {
		t.Fatalf("premise broken: the owning ifindex-0 row must give the netdev a refused NAME bucket")
	}
	if refused.refusesIfindex(20) {
		t.Fatalf("premise broken: the skew exists only while ifindex 20 has NO refused bucket")
	}

	if got := buildUserspaceIngressIfindexes(skewed); slices.Contains(got, uint32(20)) {
		t.Errorf(
			"ingress map admitted ifindex 20 for a netdev the RSS allowlist and the Rust "+
				"binding planner both refuse: an ifindex adjudicated with no READY binding is "+
				"drop_degraded_transit (BINDING_MISSING). got %v", got,
		)
	}
	// The RSS allowlist's fabric guard IS `refused.refusesName(fab.ParentLinuxName)`
	// (UserspaceBoundLinuxInterfaces, interfaces.go), so the premise assertion
	// above is that reader's verdict verbatim: it refuses the member. The
	// allowlist itself cannot be called here — it takes a *config.Config and
	// takes its OWN kernel sample, which is the very thing this fixture is
	// modelling the skew of.

	// ANTI-VACUITY, and it is the reference cluster's own shape: a fabric
	// parent that nothing refuses must still reach BOTH readers. Without this
	// the assertions above would also pass if the fabric loops stopped
	// contributing anything at all.
	bindable := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{{
			Name: "ge-0/0/3", LinuxName: "ge-0-0-3", Zone: "trust",
			Ifindex: 21, RXQueues: 6,
		}},
		Fabrics: []FabricSnapshot{{
			Name: "fab0", ParentInterface: "ge-0/0/0", ParentLinuxName: "ge-0-0-0",
			ParentIfindex: 20, ParentUnbindable: false, RXQueues: 1,
		}},
	}
	if got := buildUserspaceIngressIfindexes(bindable); !slices.Contains(got, uint32(20)) {
		t.Errorf("an unrefused fabric parent must stay in the ingress map; got %v", got)
	}
	if buildUserspaceRefusedNetdevs(bindable).refusesName("ge-0-0-0") {
		t.Errorf("an unrefused fabric parent must not be refused by NAME either — " +
			"that is the allowlist's own guard predicate")
	}
}

// The SAME skew inside `snapshot.Interfaces`, which needs no fabric refresh at
// all: buildInterfaceSnapshots takes one buildLinkSnapshot for a base row
// (interfaces.go, the base arm) and ANOTHER for that row's netdev when it builds
// each unit's `ParentIfindex` (the unit arm). A base row whose lookup missed
// names the netdev without contributing an ifindex bucket, while its own VLAN
// child carries the live parent ifindex.
//
// Rust drops the child outright — `binding_target_is_refused` routes its bind
// target through the NAME-keyed `snapshot_refuses_parent_netdev`
// (server/helpers/planning.rs) — so an ifindex-only reader here left BOTH the
// child's ifindex and the parent key adjudicated with no READY binding.
// Measured at 76045dfae: Go ingress [11 12] + alias 12->11, Rust planned {}.
//
// FAIL-ON-REVERT: change either `refused.refusesNetdev(...)` call in
// buildUserspaceIngressIfindexes' unit-row branch or in
// buildUserspaceIngressBindingAliases back to `refused.refusesIfindex(...)` and
// the matching assertion reds.
func TestSkewedParentSampleKeepsTheChildOutOfAdjudication(t *testing.T) {
	skewed := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			// The stale half: owns `ge-0-0-5`, unbindable (Tunnel class), own
			// lookup missed.
			{Name: "ge-0/0/5", LinuxName: "ge-0-0-5", Ifindex: 0, Tunnel: true},
			// The fresh half: the child's parent lookup HIT.
			{
				Name: "ge-0/0/5.100", LinuxName: "ge-0-0-5.100", Zone: "trust",
				Ifindex: 12, ParentLinuxName: "ge-0-0-5", ParentIfindex: 11, VLANID: 100,
			},
		},
	}

	// PREMISE: the keys disagree. Without this the fixture stops modelling a skew.
	refused := buildUserspaceRefusedNetdevs(skewed)
	if !refused.refusesName("ge-0-0-5") || refused.refusesIfindex(11) {
		t.Fatalf("premise broken: need refusesName(ge-0-0-5) && !refusesIfindex(11), got %v/%v",
			refused.refusesName("ge-0-0-5"), refused.refusesIfindex(11))
	}

	got := buildUserspaceIngressIfindexes(skewed)
	if slices.Contains(got, uint32(11)) {
		t.Errorf("ingress map admitted the refused parent netdev's ifindex 11; got %v", got)
	}
	if slices.Contains(got, uint32(12)) {
		t.Errorf("ingress map admitted a VLAN child whose bind target the planner refuses, "+
			"so its ifindex is adjudicated with no READY binding; got %v", got)
	}
	if aliases := buildUserspaceIngressBindingAliases(skewed); len(aliases) != 0 {
		t.Errorf("installed a binding alias onto a netdev nothing binds: %v", aliases)
	}

	// ANTI-VACUITY: the same shape with a BINDABLE parent must keep both keys
	// and the alias, so the assertions above are not passing because the VLAN
	// arm stopped contributing anything.
	bindable := &ConfigSnapshot{
		Interfaces: []InterfaceSnapshot{
			{Name: "ge-0/0/5", LinuxName: "ge-0-0-5", Ifindex: 0},
			{
				Name: "ge-0/0/5.100", LinuxName: "ge-0-0-5.100", Zone: "trust",
				Ifindex: 12, ParentLinuxName: "ge-0-0-5", ParentIfindex: 11, VLANID: 100,
			},
		},
	}
	okGot := buildUserspaceIngressIfindexes(bindable)
	if !slices.Contains(okGot, uint32(11)) || !slices.Contains(okGot, uint32(12)) {
		t.Errorf("an unrefused parent must keep both keys in the ingress map; got %v", okGot)
	}
	if aliases := buildUserspaceIngressBindingAliases(bindable); aliases[12] != 11 {
		t.Errorf("an unrefused parent must keep its binding alias; got %v", aliases)
	}
}
