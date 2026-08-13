package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6691 round 5 blocker: the secure-tunnel exclusion was keyed on the NAME
// SHAPE, and it must be keyed on OWNERSHIP.
//
// Nothing reserves the `st` prefix. `pkg/config/schema_interfaces.go` accepts a
// wildcard interface name, so this is a VALID config naming a real physical NIC
// with no VPN anywhere in it:
//
//	set interfaces st5 unit 0 family inet address 192.0.2.1/24
//	set security zones security-zone trust interfaces st5.0
//
// Before the fix, `st5` matched IsSecureTunnelIfName (`st` + an index in
// [0, 65536)) and was dropped out of ingress adjudication, out of the AF_XDP
// binding-plan inputs, and out of the RSS allowlist — a traffic outage on a
// working interface, which is exactly the failure mode the excluding arm's own
// comment named while doing it anyway.
//
// An `st` name is a secure tunnel because an IPsec configuration BINDS it, not
// because it is spelled that way. The oracle is therefore
// Config.SecureTunnelNetdevForRef, which resolves the xfrmi from the authored
// bind-interface and fails closed on an if_id collision.

// stOwnershipConfig compiles the two-interface fixture: an ordinary `ge-0/0/0`
// plus an `st5` unit, with a VPN binding `st5` only when owned is true.
func stOwnershipConfig(t *testing.T, owned bool) *config.Config {
	t.Helper()
	lines := []string{
		"set interfaces st5 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces st5.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	if owned {
		lines = append([]string{"set security ipsec vpn v bind-interface st5"}, lines...)
	}
	return compileForTest5619(t, lines...)
}

// stOwnershipLive is the ifindex the `st5` netdev is stubbed to exist at, and
// `ge-0-0-0` beside it. Without a live link snapshot every row reports ifindex
// 0, and the ingress-set assertion below cannot discriminate anything: both
// membership branches would be comparing against 0.
var stOwnershipLive = map[string]int{"st5": 11, "ge-0-0-0": 10}

// TestUnownedStNameKeepsItsDataplaneRole is the RED-on-revert guard for the
// round-5 blocker.
//
// Fail-on-revert: change userspaceSkipsIngressInterface's secure-tunnel arm
// back to `config.IsSecureTunnelIfName(base)` and the unowned `st5.0` is
// excluded again — this test goes RED on the very first assertion, and the
// ingress-map and RSS assertions below go RED with it.
//
// The OWNED half is the negative control: with `bind-interface st5` present,
// the same name MUST still be excluded. Without it, "keep everything" would
// pass the unowned half while silently reopening the #5619 gap the exclusion
// exists for.
//
// #6691 round 6 — THIS TEST WAS VACUOUS AND IS THE PR'S OWN PROOF, so the
// repair is recorded rather than quietly applied. Two of its three assertions
// asserted nothing:
//
//   - the ingress-set assertion was `if row.Ifindex > 0 && ...`, and no link
//     snapshot was stubbed, so every row carried ifindex 0 and the branch never
//     ran. Making buildUserspaceIngressIfindexes return nil unconditionally
//     left the test PASSING — measured, not inferred.
//   - the RSS assertion accepted `n == row.LinuxName || n == "st5"`, which
//     cannot distinguish the correct `st5` from the round-5 `st5.0`: whichever
//     name the resolver produced, one of the two disjuncts matched it.
//
// Only the predicate assertion bound, so the previous comment's claim that the
// sets were "asserted per SET rather than through the predicate alone" was
// false. Both are now live: the netdev is stubbed into existence at a real
// ifindex, and both sets are asserted against the ABSOLUTE expected name.
func TestUnownedStNameKeepsItsDataplaneRole(t *testing.T) {
	for _, tc := range []struct {
		name      string
		owned     bool
		wantSkip  bool
		wantBound bool
	}{
		{"no VPN binds st5 — an ordinary data interface", false, false, true},
		{"a VPN binds st5 — a real secure tunnel", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer stubLinkSnapshot5619(t, stOwnershipLive)()
			cfg := stOwnershipConfig(t, tc.owned)

			// Premise: the ownership oracle must actually disagree between the
			// two cases, or both halves are asserting the same thing.
			_, ownedByVPN := cfg.SecureTunnelNetdevForRef("st5")
			if ownedByVPN != tc.owned {
				t.Fatalf("premise broken: SecureTunnelNetdevForRef(\"st5\") ok=%v, want %v",
					ownedByVPN, tc.owned)
			}

			var row InterfaceSnapshot
			var found bool
			for _, s := range buildInterfaceSnapshots(cfg) {
				if s.Name == "st5.0" {
					row, found = s, true
				}
			}
			if !found {
				t.Fatal("premise broken: no st5.0 row in the snapshot")
			}

			// The netdev name is asserted ABSOLUTELY, and it is the same under
			// both spellings: `bind-interface st5` creates a device called
			// `st5`, and an unowned `st5` unit 0 collapses onto the NIC `st5`.
			// Round 5 resolved the unowned case to `st5.0` instead — a name on
			// no box, hence ifindex 0, hence out of every set below for a
			// reason that has nothing to do with the predicate under test.
			const wantDev = "st5"
			if row.LinuxName != wantDev {
				t.Fatalf("premise broken: st5.0 resolved to netdev %q, want %q — at any "+
					"other name the row carries ifindex 0 and the set assertions below "+
					"stop discriminating", row.LinuxName, wantDev)
			}
			if row.Ifindex != stOwnershipLive[wantDev] {
				t.Fatalf("premise broken: st5.0 row has ifindex %d, want %d — the stub "+
					"makes %q exist precisely so the ingress-set assertion is live",
					row.Ifindex, stOwnershipLive[wantDev], wantDev)
			}

			if got := userspaceSkipsIngressInterface(row); got != tc.wantSkip {
				t.Errorf("userspaceSkipsIngressInterface(st5.0) = %v, want %v — an `st` name "+
					"is a secure tunnel because a VPN BINDS it, not because it is spelled "+
					"that way; excluding an unowned one drops a real data interface out of "+
					"ingress adjudication, out of its AF_XDP binding and out of the RSS "+
					"allowlist", got, tc.wantSkip)
			}

			// The two ifindex-keyed sets the predicate gates, asserted per SET
			// rather than through the predicate alone — the predicate is the
			// mechanism, these are the consequences an operator sees.
			snapshot := &ConfigSnapshot{Interfaces: buildInterfaceSnapshots(cfg)}
			inIngress := slices.Contains(
				buildUserspaceIngressIfindexes(snapshot), uint32(row.Ifindex))
			if inIngress == tc.wantSkip {
				t.Errorf("st5.0 (ifindex %d) in the ingress-adjudication set = %v, want %v",
					row.Ifindex, inIngress, !tc.wantSkip)
			}

			bound := slices.Contains(UserspaceBoundLinuxInterfaces(cfg), wantDev)
			if bound != tc.wantBound {
				t.Errorf("%q in the RSS/binding allowlist = %v, want %v",
					wantDev, bound, tc.wantBound)
			}
		})
	}
}
