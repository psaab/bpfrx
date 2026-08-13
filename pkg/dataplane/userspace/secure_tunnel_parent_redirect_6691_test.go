package userspace

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #6691 round 8 blockers. Two DIFFERENT ways an excluded xfrmi gets back into
// an adjudicated set, neither of which the row-level exclusion can see.
//
// F1 — A SIBLING LAUNDERS ITS OWN PARENT. Three of the four sets the exclusion
// gates let a row contribute a netdev that is not its own (the #2917 VLAN-child
// binding contract), so a zoned sibling unit of a bound secure tunnel hands the
// dataplane the very netdev the base row was excluded for.
//
// F3 — THE CONFIG STOPS DESCRIBING A LIVE DEVICE. Every predicate in this PR is
// keyed on the config; an xfrmi still in the kernel after its VPN is gone is
// invisible to all of them.

// stubXfrmNetdevs presents a kernel in which exactly the named netdevs are xfrm
// interfaces. Returning nil (no names) is the ordinary box with no route-based
// IPsec, which is also what the real oracle degrades to when the link list
// cannot be read.
func stubXfrmNetdevs(t *testing.T, names ...string) func() {
	t.Helper()
	prev := liveXfrmNetdevs
	var set map[string]bool
	if len(names) > 0 {
		set = make(map[string]bool, len(names))
		for _, name := range names {
			set[name] = true
		}
	}
	liveXfrmNetdevs = func() map[string]bool { return set }
	return func() { liveXfrmNetdevs = prev }
}

// TestParentRedirectCannotReadmitTheExcludedXfrmi is the F1 guard.
//
// The config is STRICT-valid — it compiles through config.CompileConfig, not a
// lenient path. validateZoneInterfaceDefinedStrict admits `st10.5` because the
// zone member's base `st10` is a key of cfg.Interfaces.Interfaces; the
// IPsec-bind-interface term of zoneReferenceableInterfaceBases would admit it
// too, so the entry is doubly reachable and needs no typo.
//
// The base row `st10` IS the xfrmi and is correctly excluded. The unit row
// derives if_id `10<<16 | 6` against the bound `10<<16 | 1`, so it is correctly
// NOT a secure tunnel — and it carries ParentIfindex/ParentLinuxName pointing
// straight at the live xfrmi.
//
// FAIL-ON-REVERT: delete the `refused.refusesIfindex(...)` guard in
// buildUserspaceIngressIfindexes and the vlan/plain subtests both go RED on the
// ingress assertion; delete the `refused.refusesName(...)` guard in
// UserspaceBoundLinuxInterfaces and the vlan subtest goes RED on the allowlist
// assertion. Both were measured at head before the fix: ingress [10 11] and
// allowlist [ge-0-0-0 st10].
//
// The two spellings are BOTH here because they do not leak the same way, and a
// single case would have reported the wrong scope: the plain (non-VLAN) sibling
// leaks into the ingress map exactly as the VLAN one does, but its RSS bind
// target is its OWN netdev (userspaceBindTargetNetdev only redirects a
// VLAN row), so it never put "st10" in the allowlist.
func TestParentRedirectCannotReadmitTheExcludedXfrmi(t *testing.T) {
	const (
		lanIfindex   = 10
		xfrmiIfindex = 11
	)
	live := map[string]int{"ge-0-0-0": lanIfindex, "st10": xfrmiIfindex}

	for _, tc := range []struct {
		name string
		// unitLines are the sibling-unit lines; everything else is shared.
		unitLines []string
		// wantRSS is the FULL expected allowlist, asserted absolutely.
		wantRSS []string
	}{
		{
			name: "vlan sibling",
			unitLines: []string{
				"set interfaces st10 vlan-tagging",
				"set interfaces st10 unit 5 vlan-id 100",
				"set interfaces st10 unit 5 family inet address 192.0.2.1/24",
			},
			// The child's bind target is the PARENT netdev "st10", and it is
			// refused — so only the LAN remains.
			wantRSS: []string{"ge-0-0-0"},
		},
		{
			name: "plain sibling",
			unitLines: []string{
				"set interfaces st10 unit 5 family inet address 192.0.2.1/24",
			},
			// A non-VLAN row binds its OWN netdev, so "st10.5" is what it
			// contributes — a name on no box, exactly as origin/master treats
			// any zoned interface whose netdev is absent. It is NOT the xfrmi.
			wantRSS: []string{"ge-0-0-0", "st10.5"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer stubLinkSnapshot5619(t, live)()
			defer stubXfrmNetdevs(t, "st10")()

			lines := append([]string{
				"set security ipsec vpn V bind-interface st10",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust interfaces st10.5",
			}, tc.unitLines...)
			cfg := compileForTest5619(t, lines...)

			rows := buildInterfaceSnapshots(cfg)
			base, child := rowByName(t, rows, "st10"), rowByName(t, rows, "st10.5")

			// PREMISES. Without all four the assertions below cannot
			// discriminate: an unexcluded parent, an excluded child, an
			// ifindex-less parent or an absent redirect each make the test
			// pass for a reason that has nothing to do with the fix.
			if !userspaceSkipsIngressInterface(base) {
				t.Fatalf("premise broken: the st10 base row is not excluded (SecureTunnel=%v)",
					base.SecureTunnel)
			}
			if userspaceSkipsIngressInterface(child) {
				t.Fatalf("premise broken: the st10.5 sibling is itself excluded " +
					"(SecureTunnel set?) — then no laundering is being tested")
			}
			if base.Ifindex != xfrmiIfindex {
				t.Fatalf("premise broken: st10 resolved to ifindex %d, want %d",
					base.Ifindex, xfrmiIfindex)
			}
			if child.ParentIfindex != xfrmiIfindex || child.ParentLinuxName != "st10" {
				t.Fatalf("premise broken: st10.5 redirects to (%d,%q), want (%d,%q) — "+
					"the redirect IS the mechanism under test",
					child.ParentIfindex, child.ParentLinuxName, xfrmiIfindex, "st10")
			}

			ingress := buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: rows})
			if slices.Contains(ingress, uint32(xfrmiIfindex)) {
				t.Errorf("the excluded xfrmi (ifindex %d) is in the ingress-adjudication "+
					"set %v — a zoned sibling unit re-admitted its own excluded parent "+
					"through the ParentIfindex redirect", xfrmiIfindex, ingress)
			}
			if !slices.Contains(ingress, uint32(lanIfindex)) {
				t.Fatalf("premise broken: the LAN (ifindex %d) fell out of the ingress set "+
					"%v — the fix must drop the redirect, not the box", lanIfindex, ingress)
			}

			if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Equal(got, tc.wantRSS) {
				t.Errorf("RSS/AF_XDP allowlist = %v, want %v", got, tc.wantRSS)
			}

			// The alias table is inert on this config (the child's own netdev
			// does not exist, so the Ifindex<=0 guard drops it first) and is
			// asserted so a future change that makes it live is caught here
			// rather than in production.
			for childIdx, parentIdx := range buildUserspaceIngressBindingAliases(
				&ConfigSnapshot{Interfaces: rows}) {
				if parentIdx == uint32(xfrmiIfindex) {
					t.Errorf("binding alias %d -> %d points at the excluded xfrmi",
						childIdx, parentIdx)
				}
			}
		})
	}
}

// TestParentRedirectKeepsAMgmtZonedParent is the NEGATIVE control for the
// predicate split, and it is the reason the split exists rather than a blanket
// "inherit every exclusion".
//
// buildInterfaceZoneMap keys a base off whichever zone entry sorts first, so
// `security-zone mgmt interfaces ge-0/0/3.0` + `security-zone trust interfaces
// ge-0/0/3.100` really does produce base=mgmt with a trust-zoned VLAN unit
// ("mgmt" < "trust"; the unit-ref arm sets the base and then `continue`s past
// the fan-out that would have claimed the other units).
//
// The mgmt exclusion is a property of the ROW, not of the netdev: the trust
// VLAN's tagged frames arrive on that same physical netdev's hardware queues,
// so its ifindex MUST stay in the ingress set and its name in the allowlist.
// Inheriting the parent's mgmt exclusion here would take the trust VLAN's
// traffic off the dataplane — a forwarding regression wearing the fix's
// clothes.
//
// FAIL-ON-REVERT: move the `mgmt`/`control` arm from
// userspaceSkipsIngressInterface into userspaceUnbindableNetdev and this test
// goes RED on both assertions.
func TestParentRedirectKeepsAMgmtZonedParent(t *testing.T) {
	const parentIfindex = 21
	defer stubLinkSnapshot5619(t, map[string]int{"ge-0-0-3": parentIfindex})()
	defer stubXfrmNetdevs(t)()

	cfg := compileForTest5619(t,
		"set interfaces ge-0/0/3 vlan-tagging",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set interfaces ge-0/0/3 unit 100 vlan-id 100",
		"set interfaces ge-0/0/3 unit 100 family inet address 10.0.100.1/24",
		"set security zones security-zone mgmt interfaces ge-0/0/3.0",
		"set security zones security-zone trust interfaces ge-0/0/3.100",
	)
	rows := buildInterfaceSnapshots(cfg)
	base, child := rowByName(t, rows, "ge-0/0/3"), rowByName(t, rows, "ge-0/0/3.100")

	if base.Zone != "mgmt" {
		t.Fatalf("premise broken: base zone is %q, want mgmt — the split is not being "+
			"exercised", base.Zone)
	}
	if child.Zone != "trust" {
		t.Fatalf("premise broken: VLAN unit zone is %q, want trust", child.Zone)
	}
	if !userspaceSkipsIngressInterface(base) {
		t.Fatal("premise broken: the mgmt-zoned base row is not excluded")
	}
	if userspaceUnbindableNetdev(base) {
		t.Fatal("a mgmt ZONE is a property of the row, not of the netdev — putting it " +
			"in userspaceUnbindableNetdev makes a data-zoned VLAN unit on the same NIC " +
			"inherit it and lose its ingress adjudication")
	}

	ingress := buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: rows})
	if !slices.Contains(ingress, uint32(parentIfindex)) {
		t.Errorf("the physical parent (ifindex %d) is missing from the ingress set %v — "+
			"the trust VLAN unit's tagged frames arrive on THAT netdev's queues, so "+
			"dropping it carries no traffic for the unit", parentIfindex, ingress)
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Contains(got, "ge-0-0-3") {
		t.Errorf("RSS/AF_XDP allowlist = %v, want it to contain ge-0-0-3", got)
	}
}

// TestExclusionClassesAgreeAcrossParentAndChild bounds the enumeration behind
// the split, so "only the secure-tunnel class can leak" is a measured result
// rather than an assertion in a comment.
//
// For each exclusion class it builds a config where the BASE is excluded and a
// zoned VLAN unit sits under it, then reports whether the two rows disagree. A
// class where they AGREE cannot leak through the redirect however it is
// classified — the child is excluded on its own. A class where they DISAGREE
// can, and must therefore be placed deliberately.
//
// FAIL-ON-REVERT: add a new exclusion arm without adding it here and the
// coverage assertion at the end fails.
func TestExclusionClassesAgreeAcrossParentAndChild(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-3": 21, "fxp0": 22, "em0": 23, "gr-0-0-0": 24, "st10": 25, "lo0": 26,
	})()
	defer stubXfrmNetdevs(t, "st10")()

	for _, tc := range []struct {
		class string
		lines []string
		base  string
		child string
		// wantLocal, when non-empty, is the LocalFabric value BOTH rows must
		// carry — the structural reason that class cannot disagree.
		wantLocal string
		// wantDisagree: the base is excluded and the VLAN child is not, so the
		// child can hand the parent's netdev to a consumer.
		wantDisagree bool
	}{
		{
			class: "Tunnel",
			lines: []string{
				"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/0 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces gr-0/0/0.7",
			},
			base:  "gr-0/0/0",
			child: "gr-0/0/0.7",
			// The unit row ORs in the interface-level tunnel flag, so both
			// rows carry it.
			wantDisagree: false,
		},
		{
			class: "fxp name",
			lines: []string{
				"set interfaces fxp0 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces fxp0.7",
			},
			base:  "fxp0",
			child: "fxp0.7",
			// The arm tests the BASE name, which the unit shares.
			wantDisagree: false,
		},
		{
			class: "em name",
			lines: []string{
				"set interfaces em0 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces em0.7",
			},
			base:         "em0",
			child:        "em0.7",
			wantDisagree: false,
		},
		{
			class: "lo0 name",
			lines: []string{
				"set interfaces lo0 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces lo0.7",
			},
			base:         "lo0",
			child:        "lo0.7",
			wantDisagree: false,
		},
		{
			// LocalFabric + the `fab` name arm together. Only a `fab*`
			// interface ever carries LocalFabricMember — the compiler sets it
			// on the fab0/fab1 InterfaceConfig, not on the member NIC
			// (compiler_derivations.go) — so this class cannot be isolated
			// from the name arm by any config, and its exclusion here is
			// over-determined. Both reasons agree across the two rows anyway:
			// the name arm reads the shared BASE name, and LocalFabric is the
			// same InterfaceConfig field copied to both rows (asserted below).
			class: "LocalFabric + fab name",
			lines: []string{
				"set chassis cluster reth-count 2",
				"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/3",
				"set interfaces fab0 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces fab0.7",
				"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
			},
			base:         "fab0",
			child:        "fab0.7",
			wantLocal:    "ge-0/0/3",
			wantDisagree: false,
		},
		{
			class: "SecureTunnel",
			lines: []string{
				"set security ipsec vpn V bind-interface st10",
				"set interfaces st10 unit 7 vlan-id 100",
				"set security zones security-zone trust interfaces st10.7",
			},
			base:  "st10",
			child: "st10.7",
			// The if_id is `stIndex<<16 | unit+1`, so a base and a non-zero
			// unit necessarily derive DIFFERENT ids. This is the one class the
			// two rows can disagree about, and it is the F1 defect.
			wantDisagree: true,
		},
	} {
		t.Run(tc.class, func(t *testing.T) {
			cfg := compileForTest5619(t, tc.lines...)
			rows := buildInterfaceSnapshots(cfg)
			base, child := rowByName(t, rows, tc.base), rowByName(t, rows, tc.child)

			if !userspaceSkipsIngressInterface(base) {
				t.Fatalf("premise broken: the %s base row is not excluded at all", tc.class)
			}
			if tc.wantLocal != "" {
				if base.LocalFabric != tc.wantLocal || child.LocalFabric != tc.wantLocal {
					t.Errorf("LocalFabric = base %q / child %q, want %q on both — the two "+
						"rows read the SAME InterfaceConfig field, which is why this class "+
						"cannot disagree", base.LocalFabric, child.LocalFabric, tc.wantLocal)
				}
			}
			disagree := !userspaceSkipsIngressInterface(child)
			if disagree != tc.wantDisagree {
				t.Errorf("base excluded / child excluded=%v: parent-child disagreement = %v, "+
					"want %v. A class that can disagree is a class a sibling can launder "+
					"through the parent redirect, so it belongs in "+
					"userspaceUnbindableNetdev; one that cannot is free to stay row-scoped",
					!disagree, disagree, tc.wantDisagree)
			}
			if !disagree {
				return
			}
			// Every disagreeing class must be on the DEVICE side of the split,
			// or the redirect guards cannot see it.
			if !userspaceUnbindableNetdev(base) {
				t.Errorf("%s can disagree between a parent and its child, but it is not in "+
					"userspaceUnbindableNetdev — the refused-netdev index is built from "+
					"that predicate, so the redirect guards will not refuse this netdev",
					tc.class)
			}
		})
	}

	// Coverage: the cases above must name every arm the predicate has, or a
	// newly-added class silently escapes the enumeration.
	const wantClasses = 6
	if got := len([]string{
		"Tunnel", "fxp name", "em name", "lo0 name", "LocalFabric + fab name", "SecureTunnel",
	}); got != wantClasses {
		t.Fatalf("enumeration drifted: %d classes, want %d", got, wantClasses)
	}
	// That is every arm of userspaceUnbindableNetdev (Tunnel, the four name
	// prefixes, SecureTunnel) plus the LocalFabric arm of
	// userspaceSkipsIngressInterface. The remaining arm — `mgmt`/`control` —
	// is covered by TestParentRedirectKeepsAMgmtZonedParent, which asserts the
	// OPPOSITE placement on purpose: it CAN disagree and must still not be
	// inherited, because the parent netdev really does carry the child's
	// frames there.
	//
	// The Fabrics loop is deliberately outside all of this. A fabric's binding
	// candidate is its PHYSICAL parent (`ge-0-0-0`), a different netdev from
	// the excluded `fab0` overlay, and it is contributed by its own loop that
	// the refused index does not gate — filtering it would unbind the fabric.
	//
	// THE FABRIC LOOP IS ALSO A THIRD CONTRIBUTOR, and #6691 round 8 was wrong
	// to bound the enumeration by "the predicate's callers". `add(fab.Parent-
	// LinuxName)` (interfaces.go) and `key := uint32(fab.ParentIfindex)`
	// (maps_sync.go) push unconditionally, and Rust replan_queues' fabric loop
	// does too — none of the three asks this predicate or the refused index.
	// Measured with a Tunnel-class member (`set interfaces fab0 fabric-options
	// member-interfaces gr-0/0/3` with an interface-level tunnel on gr-0/0/3):
	// the refused netdev IS in the ingress set and IS in the allowlist. That is
	// PRE-EXISTING — master's fabric loop is identical — and it is NOT reachable
	// for a secure tunnel, per the REFUTED note below. It is tracked as #6998
	// rather than fixed here.
	//
	// REFUTED, and recorded so the next reader does not re-derive it: "a fabric
	// parent could itself be an xfrmi, so the Fabrics loop is a fourth
	// laundering site FOR THE SECURE-TUNNEL CLASS." It is not reachable.
	// Measured with `set interfaces fab0 fabric-options member-interfaces st10`
	// alongside `bind-interface st10`: the snapshot carries ZERO fabric rows,
	// because compiler_derivations.go resolves LocalFabricMember only for a
	// member with an FPC slot (`InterfaceSlot`), and `st10` has none. With no
	// fabric row there is no ParentIfindex for the loop to append — ingress came
	// back [10] and the allowlist [ge-0-0-0], with the xfrmi in neither. The
	// Tunnel class reaches it because `gr-0/0/3` IS slot-shaped; the secure
	// tunnel class cannot.
}

// TestExclusionClassesDisagreeTheOtherWayToo is the CONVERSE of
// TestExclusionClassesAgreeAcrossParentAndChild, and its absence was the
// #6691 round 9 blocker.
//
// Round 8 asked only "BASE excluded, child not" — the direction where a child
// launders its parent. The other direction is "UNIT excluded, base not", and it
// matters for a different reason: when the unit's netdev is the SAME netdev as
// the base's (a unit-0 row with no vlan-id collapses onto the base netdev,
// snapshotLinuxName), an ANY-owner refusal index poisons a netdev that an
// ADMITTED row owns.
//
// For each class this measures the three facts that decide whether the
// direction is dangerous — is the child excluded, is the base excluded, do they
// share a netdev — and then asserts the invariant that makes the answer safe:
// a netdev with a bindable owner is never refused.
//
// FAIL-ON-REVERT: restore the ANY-owner index (refuse as soon as one owner is
// unbindable) and the Tunnel case goes RED on "netdev %q is refused even though
// %s owns it and is bindable".
func TestExclusionClassesDisagreeTheOtherWayToo(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-5": 30, "fxp0": 22, "em0": 23, "gr-0-0-0": 24,
		"st10": 11, "st10.0": 12, "lo0": 26, "ge-0-0-3": 21,
	})()

	for _, tc := range []struct {
		class string
		lines []string
		// xfrm names the LIVE xfrm netdevs for this case.
		xfrm  []string
		base  string
		child string
		// The three measured facts.
		wantChildExcluded bool
		wantBaseExcluded  bool
		wantSharedNetdev  bool
	}{
		{
			// THE BLOCKER. A unit-level tunnel stanza on a base with no
			// interface-level tunnel: the unit row ORs in unit.Tunnel, and its
			// unit-0 LinuxName is the base netdev. Both halves are needed —
			// without the OR the rows would agree, without the collapse they
			// would not share a netdev.
			class: "Tunnel",
			lines: []string{
				"set interfaces ge-0/0/5 vlan-tagging",
				"set interfaces ge-0/0/5 unit 0 tunnel source 10.0.0.1",
				"set interfaces ge-0/0/5 unit 0 tunnel destination 10.0.0.2",
				"set interfaces ge-0/0/5 unit 100 vlan-id 100",
				"set security zones security-zone trust interfaces ge-0/0/5.0",
				"set security zones security-zone trust interfaces ge-0/0/5.100",
			},
			base:              "ge-0/0/5",
			child:             "ge-0/0/5.0",
			wantChildExcluded: true,
			wantBaseExcluded:  false,
			wantSharedNetdev:  true,
		},
		{
			// The name arms strip at the first '.', so the unit tests the same
			// string the base does. They cannot disagree in EITHER direction —
			// which is why a shared netdev is harmless here.
			class: "fxp name",
			lines: []string{
				"set interfaces fxp0 unit 0 family inet address 10.9.9.1/24",
				"set security zones security-zone trust interfaces fxp0.0",
			},
			base:              "fxp0",
			child:             "fxp0.0",
			wantChildExcluded: true,
			wantBaseExcluded:  true,
			wantSharedNetdev:  true,
		},
		{
			class: "em name",
			lines: []string{
				"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
				"set security zones security-zone trust interfaces em0.0",
			},
			base:              "em0",
			child:             "em0.0",
			wantChildExcluded: true,
			wantBaseExcluded:  true,
			wantSharedNetdev:  true,
		},
		{
			class: "lo0 name",
			lines: []string{
				"set interfaces lo0 unit 0 family inet address 10.255.0.1/32",
				"set security zones security-zone trust interfaces lo0.0",
			},
			base:              "lo0",
			child:             "lo0.0",
			wantChildExcluded: true,
			wantBaseExcluded:  true,
			wantSharedNetdev:  true,
		},
		{
			// LocalFabric is one InterfaceConfig field copied onto both rows,
			// and `fab` is a name arm, so this class is over-determined in both
			// directions exactly as the forward test found.
			class: "LocalFabric + fab name",
			lines: []string{
				"set chassis cluster reth-count 2",
				"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/3",
				"set interfaces fab0 unit 0 family inet address 10.100.0.1/24",
				"set security zones security-zone trust interfaces fab0.0",
				"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
			},
			base:              "fab0",
			child:             "fab0.0",
			wantChildExcluded: true,
			wantBaseExcluded:  true,
			wantSharedNetdev:  true,
		},
		{
			// SecureTunnel DOES disagree this way — `bind-interface st10.0`
			// owns the unit and not the base — but the rows do NOT share a
			// netdev: the unit resolves to the device the xfrmi reconciler
			// actually creates (`st10.0`) while the base keeps `st10`. That
			// separation is snapshotLinuxName's #5619 arm, and it is what keeps
			// this disagreement harmless. Measured, not assumed.
			class: "SecureTunnel",
			xfrm:  []string{"st10.0"},
			lines: []string{
				"set security ipsec vpn V bind-interface st10.0",
				"set interfaces st10 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st10.0",
			},
			base:              "st10",
			child:             "st10.0",
			wantChildExcluded: true,
			wantBaseExcluded:  false,
			wantSharedNetdev:  false,
		},
	} {
		t.Run(tc.class, func(t *testing.T) {
			defer stubXfrmNetdevs(t, tc.xfrm...)()
			cfg := compileForTest5619(t, tc.lines...)
			rows := buildInterfaceSnapshots(cfg)
			base, child := rowByName(t, rows, tc.base), rowByName(t, rows, tc.child)

			if got := userspaceUnbindableNetdev(child); got != tc.wantChildExcluded {
				t.Fatalf("child %s unbindable = %v, want %v — the converse direction "+
					"is not being exercised", tc.child, got, tc.wantChildExcluded)
			}
			if got := userspaceUnbindableNetdev(base); got != tc.wantBaseExcluded {
				t.Fatalf("base %s unbindable = %v, want %v", tc.base, got, tc.wantBaseExcluded)
			}
			shared := base.LinuxName == child.LinuxName
			if shared != tc.wantSharedNetdev {
				t.Fatalf("base netdev %q vs child netdev %q: shared = %v, want %v. "+
					"Whether the two rows land on ONE netdev is what decides if a "+
					"disagreement can poison an admitted row",
					base.LinuxName, child.LinuxName, shared, tc.wantSharedNetdev)
			}

			// THE INVARIANT. A netdev with a bindable owner is not refused —
			// whichever row disagrees.
			refused := buildUserspaceRefusedNetdevs(rows)
			for _, owner := range []InterfaceSnapshot{base, child} {
				if !userspaceOwnsItsNetdev(owner) || userspaceUnbindableNetdev(owner) {
					continue
				}
				if refused.refusesName(owner.LinuxName) {
					t.Errorf("netdev %q is refused even though %s owns it and is "+
						"bindable — a sibling row's exclusion was read as a property "+
						"of the device", owner.LinuxName, owner.Name)
				}
				if refused.refusesIfindex(owner.Ifindex) {
					t.Errorf("ifindex %d (%s, netdev %q) is refused even though a "+
						"bindable row owns it", owner.Ifindex, owner.Name, owner.LinuxName)
				}
			}
		})
	}

	// Coverage: same six classes as the forward direction, so the two tests
	// cannot drift apart and leave one direction short of an arm.
	const wantClasses = 6
	if got := len([]string{
		"Tunnel", "fxp name", "em name", "lo0 name", "LocalFabric + fab name", "SecureTunnel",
	}); got != wantClasses {
		t.Fatalf("enumeration drifted: %d classes, want %d", got, wantClasses)
	}
}

// TestAliasTableRefusesEvenWhenTheChildNetdevResolves binds the one refusal
// guard that no reachable config distinguishes, by constructing the state that
// would make it live instead of declaring it untestable.
//
// #6691 round 8 reported this guard as a surviving mutation and justified it
// with "no test can distinguish it — that is a structural claim, not a bound
// one". That was both wrong at the time (the guard WAS live, on the round-9
// blocker config) and a weaker answer than was available.
//
// THE FIXTURE IS SYNTHETIC AND SAYS SO. `st10.5 vlan-id 100` names the netdev
// `st10.100`, which does not exist on a box: the xfrmi reconciler never creates
// it and the kernel cannot create a VLAN on an ARPHRD_NONE parent. So the
// production path is dropped by the `Ifindex <= 0` guard before the refusal is
// consulted, and this test stubs the netdev into existence to reach the line.
// That is legitimate here because the invariant is about the SITE — the alias
// table must not become the one place the refusal is not asked — and the
// reachability it depends on is not this file's to guarantee: #5619 made three
// of the four secure-tunnel spellings resolve to netdevs that previously did
// not.
//
// FAIL-ON-REVERT: delete the `refused.refusesIfindex(...)` guard in
// buildUserspaceIngressBindingAliases and this test goes RED with
// `binding alias 12 -> 11 points at the refused xfrmi`.
func TestAliasTableRefusesEvenWhenTheChildNetdevResolves(t *testing.T) {
	const (
		lanIfindex   = 10
		xfrmiIfindex = 11
		childIfindex = 12
	)
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": lanIfindex,
		"st10":     xfrmiIfindex,
		// SYNTHETIC: see the doc comment. Production reports 0 here.
		"st10.100": childIfindex,
	})()
	defer stubXfrmNetdevs(t, "st10")()

	cfg := compileForTest5619(t,
		"set security ipsec vpn V bind-interface st10",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces st10 vlan-tagging",
		"set interfaces st10 unit 5 vlan-id 100",
		"set interfaces st10 unit 5 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces st10.5",
	)
	rows := buildInterfaceSnapshots(cfg)
	child := rowByName(t, rows, "st10.5")

	// PREMISES. Every one of the four guards ahead of the refusal must be
	// passed, or the test proves nothing about the refusal.
	if userspaceSkipsIngressInterface(child) {
		t.Fatal("premise broken: the child row is itself excluded, so the loop " +
			"drops it before the refusal is asked")
	}
	if child.Ifindex != childIfindex || child.ParentIfindex != xfrmiIfindex {
		t.Fatalf("premise broken: child resolved to (ifindex %d, parent %d), want (%d, %d) "+
			"— the stub is what puts this row past the `Ifindex <= 0` guard",
			child.Ifindex, child.ParentIfindex, childIfindex, xfrmiIfindex)
	}
	if child.LogicalOnly {
		t.Fatal("premise broken: a LogicalOnly row is dropped by its own guard")
	}
	refused := buildUserspaceRefusedNetdevs(rows)
	if !refused.refusesIfindex(xfrmiIfindex) {
		t.Fatalf("premise broken: ifindex %d is not refused, so the guard under test "+
			"has nothing to refuse", xfrmiIfindex)
	}

	for childIdx, parentIdx := range buildUserspaceIngressBindingAliases(
		&ConfigSnapshot{Interfaces: rows}) {
		if parentIdx == uint32(xfrmiIfindex) {
			t.Errorf("binding alias %d -> %d points at the refused xfrmi. The shim "+
				"would treat frames on the child as arriving on a netdev the "+
				"dataplane refused to bind, which has no READY binding — "+
				"drop_degraded_transit (BINDING_MISSING)", childIdx, parentIdx)
		}
	}
}

// TestLogicalOnlyRowNeverOwnsANetdev pins the fact that let round 9 DELETE the
// `!iface.LogicalOnly` clause from buildUserspaceRefusedNetdevs rather than keep
// carrying it as an unfireable belt.
//
// A LogicalOnly row is a bondless RETH VLAN unit whose Linux VLAN child was
// never created (shouldUseLogicalOnlyParentBoundRethVLAN). Its ifindex is
// SYNTHETIC — a private high-range value naming no kernel netdev — so round 8
// kept it out of the ifindex index explicitly. Under the ownership rule it is
// already out: the same conditions that make a row LogicalOnly (VlanID > 0, a
// resolved parent netdev with a different name) make it a VLAN CHILD, and a VLAN
// child does not own the netdev it binds.
//
// This asserts the implication directly, so if either rule moves the redundancy
// is caught here instead of silently becoming a real gap.
func TestLogicalOnlyRowNeverOwnsANetdev(t *testing.T) {
	const (
		parentIfindex = 40
		vlanID        = 80
	)
	defer stubLinkSnapshot5619(t, map[string]int{"lo": parentIfindex})()
	defer stubXfrmNetdevs(t)()

	cfg := &config.Config{}
	cfg.System.DataplaneType = "userspace"
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"lo":    {Name: "lo", RedundantParent: "reth0"},
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{vlanID: {Number: vlanID, VlanID: vlanID}}},
	}

	rows := buildInterfaceSnapshots(cfg)
	unit := rowByName(t, rows, fmt.Sprintf("reth0.%d", vlanID))
	if !unit.LogicalOnly {
		t.Fatalf("premise broken: %s is not LogicalOnly — the fixture no longer "+
			"produces the row this test is about", unit.Name)
	}
	if unit.Ifindex < syntheticInterfaceIfindexMin || unit.Ifindex > syntheticInterfaceIfindexMax {
		t.Fatalf("premise broken: ifindex %d is outside the synthetic range [%d,%d]",
			unit.Ifindex, syntheticInterfaceIfindexMin, syntheticInterfaceIfindexMax)
	}
	if userspaceOwnsItsNetdev(unit) {
		t.Fatalf("a LogicalOnly row owns its netdev (LinuxName %q, ParentLinuxName %q, "+
			"VLANID %d, bind target %q). Its ifindex %d is SYNTHETIC and names no kernel "+
			"netdev, so it must not vote on whether a netdev may be bound — restore an "+
			"explicit LogicalOnly guard in buildUserspaceRefusedNetdevs",
			unit.LinuxName, unit.ParentLinuxName, unit.VLANID,
			userspaceBindTargetNetdev(unit), unit.Ifindex)
	}
	if refused := buildUserspaceRefusedNetdevs(rows); refused.refusesIfindex(unit.Ifindex) {
		t.Errorf("the synthetic ifindex %d entered the refused index", unit.Ifindex)
	}
}

// TestRefusedNetdevNeedsEveryOwnerToAgree is the #6691 round 9 blocker guard: an
// ANY-owner refusal index refuses a netdev an ADMITTED row owns.
//
// The two spellings are both here because they fail differently and a single
// case would have reported the wrong scope. The `ge-*` one is the full damage —
// the base row's name leaves the RSS allowlist AND its VLAN sibling leaves the
// ingress map and the alias table. The WireGuard one is the REACHABILITY: `set
// interfaces wgN unit 0 tunnel mode wireguard` is the canonical spelling
// (verbatim in pkg/config/tunnelid_test.go and in an operator config in
// docs/issues/issue-history.md), and it loses the allowlist entry with no VLAN
// unit involved at all.
//
// Every expected value below is what origin/master produces for the same config,
// asserted absolutely rather than as "not refused" — this is a no-regression
// claim and it should read like one.
//
// FAIL-ON-REVERT: change buildUserspaceRefusedNetdevs back to refusing on ANY
// unbindable owner and both subtests go RED — the ge case on the ingress set
// (`[10 30]` for `[10 30 31]`), the allowlist (`[ge-0-0-0]` for
// `[ge-0-0-0 ge-0-0-5]`) and the aliases (`map[]` for `map[31:30]`); the wg case
// on the allowlist (`[ge-0-0-0]` for `[ge-0-0-0 wg1408]`).
func TestRefusedNetdevNeedsEveryOwnerToAgree(t *testing.T) {
	for _, tc := range []struct {
		name        string
		live        map[string]int
		lines       []string
		wantIngress []uint32
		wantRSS     []string
		wantAliases map[uint32]uint32
	}{
		{
			name: "unit-level tunnel on a data NIC",
			live: map[string]int{"ge-0-0-0": 10, "ge-0-0-5": 30, "ge-0-0-5.100": 31},
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set interfaces ge-0/0/5 vlan-tagging",
				"set interfaces ge-0/0/5 unit 0 tunnel source 10.0.0.1",
				"set interfaces ge-0/0/5 unit 0 tunnel destination 10.0.0.2",
				"set interfaces ge-0/0/5 unit 100 vlan-id 100",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust interfaces ge-0/0/5.0",
				"set security zones security-zone trust interfaces ge-0/0/5.100",
			},
			wantIngress: []uint32{10, 30, 31},
			wantRSS:     []string{"ge-0-0-0", "ge-0-0-5"},
			wantAliases: map[uint32]uint32{31: 30},
		},
		{
			name: "canonical wireguard spelling",
			live: map[string]int{"ge-0-0-0": 10, "wg1408": 40},
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set interfaces wg1408 unit 0 tunnel mode wireguard",
				"set interfaces wg1408 unit 0 tunnel wireguard listen-port 51820",
				"set interfaces wg1408 unit 0 tunnel wireguard private-key " +
					"0000000000000000000000000000000000000000000000000000000000000001",
				"set interfaces wg1408 unit 0 tunnel wireguard peer " +
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa " +
					"allowed-ips 10.9.0.0/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
				"set security zones security-zone trust interfaces wg1408.0",
			},
			wantIngress: []uint32{10, 40},
			wantRSS:     []string{"ge-0-0-0", "wg1408"},
			wantAliases: map[uint32]uint32{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer stubLinkSnapshot5619(t, tc.live)()
			defer stubXfrmNetdevs(t)()
			cfg := compileForTest5619(t, tc.lines...)
			rows := buildInterfaceSnapshots(cfg)

			// PREMISES. Without the disagreement AND the shared netdev this
			// config cannot discriminate the ANY rule from the ALL rule.
			baseName := "ge-0/0/5"
			if _, ok := cfg.Interfaces.Interfaces["wg1408"]; ok {
				baseName = "wg1408"
			}
			base, unit := rowByName(t, rows, baseName), rowByName(t, rows, baseName+".0")
			if userspaceUnbindableNetdev(base) {
				t.Fatalf("premise broken: the %s base row is itself unbindable — then "+
					"nothing is being poisoned", baseName)
			}
			if !userspaceUnbindableNetdev(unit) {
				t.Fatalf("premise broken: the %s.0 unit row is NOT unbindable "+
					"(Tunnel=%v) — the unit-level tunnel stanza is what makes the two "+
					"rows disagree", baseName, unit.Tunnel)
			}
			if base.LinuxName != unit.LinuxName {
				t.Fatalf("premise broken: base netdev %q != unit netdev %q — the unit-0 "+
					"name collapse is what puts both rows on ONE netdev",
					base.LinuxName, unit.LinuxName)
			}

			snap := &ConfigSnapshot{Interfaces: rows}
			if got := buildUserspaceIngressIfindexes(snap); !slices.Equal(got, tc.wantIngress) {
				t.Errorf("ingress-adjudication set = %v, want %v. An ifindex absent here "+
					"takes cpumap_or_pass in the shim and syncInterfaceAttachments "+
					"detaches XDP/TC from it", got, tc.wantIngress)
			}
			if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Equal(got, tc.wantRSS) {
				t.Errorf("RSS/AF_XDP allowlist = %v, want %v. Dropping a netdev here also "+
					"removes its revert path: restoreDefaultRSSIndirection and "+
					"applyCoalescence are both allowlist-scoped", got, tc.wantRSS)
			}
			if got := buildUserspaceIngressBindingAliases(snap); !maps.Equal(got, tc.wantAliases) {
				t.Errorf("binding aliases = %v, want %v", got, tc.wantAliases)
			}
		})
	}
}

// TestRetainedLiveXfrmiLeavesTheAdjudicatedSets is the F3 guard, and it
// COMPOSES the two halves rather than reasoning across them: the retention is
// produced by the real pkg/routing reconciler against a fake kernel, and the
// kernel that reconciler leaves behind is the kernel the snapshot builder then
// reads.
//
// Both routes to the state are driven:
//
//	(a) LinkDel FAILS. deleteLocked retains tracking and returns the error;
//	    Apply joins it. daemon_apply.go treats applyInterfaceReconcile's result
//	    as a DEFERRED error and runs the dataplane apply anyway.
//	(b) DAEMON RESTART. A fresh xfrmManager has EMPTY tracking, so the removed
//	    -desired delete pass has nothing to iterate and issues no LinkDel at
//	    all. The device is never even attempted.
//
// FAIL-ON-REVERT: drop the kernel half of snapshotSecureTunnel (return only
// secureTunnelOwned) and both subtests go RED — measured at head, this snapshot
// produced ingress [10 11] and allowlist [ge-0-0-0 st10].
func TestRetainedLiveXfrmiLeavesTheAdjudicatedSets(t *testing.T) {
	const (
		lanIfindex   = 10
		xfrmiIfindex = 11
	)

	for _, tc := range []struct {
		name        string
		failLinkDel bool
		// restart drops the manager's in-memory tracking before the
		// VPN-removal apply, standing in for a daemon restart.
		restart bool
		// wantApplyErr: route (a) surfaces the failure; route (b) reports a
		// clean convergence while the device is still there, which is what
		// makes it the more dangerous of the two.
		wantApplyErr bool
	}{
		{name: "LinkDel fails", failLinkDel: true, wantApplyErr: true},
		{name: "untracked after daemon restart", restart: true, wantApplyErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kernel := newFakeXfrmKernel()
			mgr := routing.NewManagerWithLinkOpsForTest(kernel)

			// 1. The VPN exists: routing creates the xfrmi.
			bound := map[string]*config.IPsecVPN{
				"V": {Name: "V", BindInterface: "st10"},
			}
			if err := mgr.ApplyXfrmi(bound); err != nil {
				t.Fatalf("premise broken: creating the xfrmi failed: %v", err)
			}
			if !kernel.hasXfrm("st10") {
				t.Fatal("premise broken: the reconciler did not create st10")
			}

			// 2. The VPN is removed. Either the delete fails, or the daemon
			//    restarted and no longer tracks the device.
			if tc.failLinkDel {
				kernel.linkDelErr = errors.New("device busy")
			}
			if tc.restart {
				mgr = routing.NewManagerWithLinkOpsForTest(kernel)
			}
			err := mgr.ApplyXfrmi(nil)
			if (err != nil) != tc.wantApplyErr {
				t.Fatalf("ApplyXfrmi(nil) error = %v, want error present = %v",
					err, tc.wantApplyErr)
			}

			// 3. THE COMPOSITION: the device the reconciler left behind is
			//    still in the kernel, and the config no longer mentions any
			//    VPN. This is the state the dataplane apply then runs against
			//    — applyInterfaceReconcile's error is deferred, so the apply
			//    is NOT skipped.
			if !kernel.hasXfrm("st10") {
				t.Fatal("premise broken: the xfrmi is gone, so there is nothing " +
					"for the snapshot to adjudicate and this test proves nothing")
			}

			defer stubLinkSnapshot5619(t, map[string]int{
				"ge-0-0-0": lanIfindex, "st10": xfrmiIfindex,
			})()
			defer stubXfrmNetdevs(t, kernel.xfrmNames()...)()

			cfg := compileForTest5619(t,
				"set interfaces st10 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st10.0",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			)
			// The config half must be BLIND here, or the kernel half is not
			// what the assertions below are measuring.
			if secureTunnelOwned(cfg, "st10") {
				t.Fatal("premise broken: the config still binds st10, so the " +
					"config-keyed predicate would have caught this on its own")
			}

			rows := buildInterfaceSnapshots(cfg)
			base := rowByName(t, rows, "st10")
			if !base.SecureTunnel {
				t.Error("the retained live xfrmi is not flagged: every predicate in this " +
					"change is config-keyed, and the config no longer describes this " +
					"device — only the kernel does")
			}

			ingress := buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: rows})
			if slices.Contains(ingress, uint32(xfrmiIfindex)) {
				t.Errorf("the retained xfrmi (ifindex %d) is in the ingress-adjudication "+
					"set %v; its single RX queue also becomes the planner's global "+
					"minimum and collapses the box to one worker (#3091)",
					xfrmiIfindex, ingress)
			}
			if !slices.Contains(ingress, uint32(lanIfindex)) {
				t.Fatalf("premise broken: the LAN (ifindex %d) fell out of %v",
					lanIfindex, ingress)
			}
			if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Equal(got, []string{"ge-0-0-0"}) {
				t.Errorf("RSS/AF_XDP allowlist = %v, want [ge-0-0-0]", got)
			}

			// The v5 protocol gate must arm for this snapshot too: a pre-v5
			// helper ignores the flag, plans the binding, and the operator
			// cannot fix it by editing the config.
			if !configHasSecureTunnel(cfg) {
				t.Error("configHasSecureTunnel is false for a config whose snapshot DOES " +
					"carry a flagged row — the gate would stay silent while a pre-v5 " +
					"helper plans the binding this change exists to refuse")
			}
		})
	}
}

func rowByName(t *testing.T, rows []InterfaceSnapshot, name string) InterfaceSnapshot {
	t.Helper()
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("no %q row in the snapshot", name)
	return InterfaceSnapshot{}
}

// fakeXfrmKernel is an in-memory netlink surface for the F3 composition. It
// satisfies pkg/routing's (unexported) linkOps structurally, which is what
// routing.NewManagerWithLinkOpsForTest is for.
type fakeXfrmKernel struct {
	links      map[string]netlink.Link
	nextIndex  int
	linkDelErr error
}

func newFakeXfrmKernel() *fakeXfrmKernel {
	return &fakeXfrmKernel{links: make(map[string]netlink.Link), nextIndex: 100}
}

func (f *fakeXfrmKernel) hasXfrm(name string) bool {
	link, ok := f.links[name]
	if !ok {
		return false
	}
	_, isXfrmi := link.(*netlink.Xfrmi)
	return isXfrmi
}

func (f *fakeXfrmKernel) xfrmNames() []string {
	var out []string
	for name := range f.links {
		if f.hasXfrm(name) {
			out = append(out, name)
		}
	}
	return out
}

func (f *fakeXfrmKernel) LinkByName(name string) (netlink.Link, error) {
	if link, ok := f.links[name]; ok {
		return link, nil
	}
	return nil, netlink.LinkNotFoundError{}
}

func (f *fakeXfrmKernel) LinkAdd(link netlink.Link) error {
	attrs := link.Attrs()
	if _, exists := f.links[attrs.Name]; exists {
		return errors.New("file exists")
	}
	f.nextIndex++
	attrs.Index = f.nextIndex
	f.links[attrs.Name] = link
	return nil
}

func (f *fakeXfrmKernel) LinkDel(link netlink.Link) error {
	if f.linkDelErr != nil {
		return f.linkDelErr
	}
	delete(f.links, link.Attrs().Name)
	return nil
}

func (f *fakeXfrmKernel) LinkSetUp(netlink.Link) error   { return nil }
func (f *fakeXfrmKernel) LinkSetDown(netlink.Link) error { return nil }
func (f *fakeXfrmKernel) LinkSetMaster(netlink.Link, netlink.Link) error {
	return nil
}
func (f *fakeXfrmKernel) LinkSetNoMaster(netlink.Link) error { return nil }
func (f *fakeXfrmKernel) LinkSetMTU(netlink.Link, int) error { return nil }
func (f *fakeXfrmKernel) LinkList() ([]netlink.Link, error) {
	out := make([]netlink.Link, 0, len(f.links))
	for _, link := range f.links {
		out = append(out, link)
	}
	return out, nil
}
func (f *fakeXfrmKernel) AddrAdd(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeXfrmKernel) AddrDel(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeXfrmKernel) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}
