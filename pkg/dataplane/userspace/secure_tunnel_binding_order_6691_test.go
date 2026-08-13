package userspace

import (
	"slices"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6691 round 7. Round 6 correctly split ONE key into TWO questions —
// ownership by the authored spelling, the routing veto by if_id — and then
// asked them in the wrong sequence, and asked the first one symmetrically.
// Both defects are about ORDER and DIRECTION, not about the concepts.
//
// The two questions and the order they must be asked in:
//
//	no name owner        -> unbound        (the ref is not this device's)
//	owner + collision    -> collision veto (routing creates neither)
//	owner + no collision -> bound
//
// Round 6 returned the collision verdict from inside the scan loop, so the veto
// could be cast for a ref NOBODY owned; and it compared BASES ONLY, so
// `bind-interface st5.0` claimed the bare row `st5`.

// lenientStConfig compiles through the REAL tolerant-load compiler
// (CompileConfigLenient), which is the path these cases live on: the #2933
// gate hard-rejects an if_id collision at commit, so a colliding config can
// only arrive by load or peer-sync — precisely the path the collision veto
// exists to govern, as SecureTunnelNetdevForRef's own doc says.
func lenientStConfig(t *testing.T, lines ...string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// snapRow returns the named snapshot row, failing the test when it is absent.
func snapRow(t *testing.T, cfg *config.Config, name string) InterfaceSnapshot {
	t.Helper()
	for _, s := range buildInterfaceSnapshots(cfg) {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("premise broken: no %q row in the snapshot", name)
	return InterfaceSnapshot{}
}

// TestSecureTunnelCollisionVetoRequiresAnOwner pins the ORDER.
//
// The counterexample, and it is the whole finding: two DISTINCT bind-interface
// strings can derive a ref's if_id while NEITHER of them names the ref's
// device.
//
//	set interfaces st5 unit 0 ...          <- an ordinary NIC (nothing
//	set security ipsec vpn a bind-interface st05      reserves the `st`
//	set security ipsec vpn b bind-interface st0005    prefix)
//
// `st05` and `st0005` both derive if_id 0x50001 because XFRMIfNameAndID parses
// the index with strconv.Atoi, which erases leading zeros — but LinuxIfName
// keeps them apart, so routing's desired set contains `st05` and `st0005` and
// NOTHING called `st5`. The collision between those two is real and routing
// will refuse both; it is simply not `st5.0`'s collision. Round 6 cast it
// anyway and SecureTunnelUnitNetdev answered ("st5.0", true), so the unit row
// named a device on no box: ifindex 0, hence no `filter input`, no per-unit
// CoS, no routing-instance binding, a junos-host deny scoped to nothing, and a
// phantom `st5.0` in the AF_XDP/RSS allowlist.
//
// Fail-on-revert: move the collision verdict back inside the scan loop in
// secureTunnelBindingForRef —
//
//	if claimant != "" && name != claimant {
//	        return "", secureTunnelIDCollision
//	}
//
// — and the `neither name owns the ref` sub-test goes RED on every assertion.
//
// The `one of the two names IS the ref's device` sub-test is the negative
// control: without it, DELETING the veto outright would pass.
func TestSecureTunnelCollisionVetoRequiresAnOwner(t *testing.T) {
	for _, tc := range []struct {
		name string
		// bindA/bindB are two DISTINCT authored spellings sharing one if_id.
		bindA, bindB string
		// wantOwner is whether either spelling names the `st5.0` device.
		wantOwner bool
		// wantDev/wantOK are SecureTunnelUnitNetdev("st5.0")'s answer.
		wantDev string
		wantOK  bool
		// wantLinux is the netdev the `st5.0` snapshot row must carry.
		wantLinux string
		// wantIfindex is that row's resulting ifindex; 11 is the live NIC.
		wantIfindex int
	}{
		{
			name:      "neither name owns the ref — the veto is not this ref's to cast",
			bindA:     "st05",
			bindB:     "st0005",
			wantOwner: false,
			// Unowned: the resolver declines and snapshotLinuxName runs its
			// ordinary resolution, which collapses unit 0 onto the NIC.
			wantDev: "", wantOK: false,
			wantLinux: "st5", wantIfindex: 11,
		},
		{
			name:      "one name IS the ref's device — the veto stands",
			bindA:     "st5",
			bindB:     "st05",
			wantOwner: true,
			// Owned AND collided: routing creates neither `st5` nor `st05`,
			// so the honest answer is the ref itself. Collapsing onto `st5`
			// would alias the unit row onto the base row's name.
			wantDev: "st5.0", wantOK: true,
			wantLinux: "st5.0", wantIfindex: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// PREMISE: the two spellings really are distinct names on one
			// if_id, and that if_id really is `st5.0`'s. Without both, the
			// case is not about the veto at all.
			devA, idA := config.XFRMIfNameAndID(tc.bindA)
			devB, idB := config.XFRMIfNameAndID(tc.bindB)
			_, refID := config.XFRMIfNameAndID("st5.0")
			if idA == 0 || idA != idB || idA != refID || devA == devB {
				t.Fatalf("premise broken: %q->(%q,%#x) %q->(%q,%#x) ref st5.0 id %#x — "+
					"this case needs two DISTINCT names on the ref's if_id",
					tc.bindA, devA, idA, tc.bindB, devB, idB, refID)
			}
			if (devA == "st5" || devB == "st5") != tc.wantOwner {
				t.Fatalf("premise broken: devices %q/%q vs wantOwner=%v — ownership of "+
					"`st5.0` is exactly whether one of them is named `st5`",
					devA, devB, tc.wantOwner)
			}

			defer stubLinkSnapshot5619(t, map[string]int{"st5": 11, "ge-0-0-0": 10})()
			cfg := lenientStConfig(t,
				"set security ipsec vpn a bind-interface "+tc.bindA,
				"set security ipsec vpn b bind-interface "+tc.bindB,
				"set interfaces st5 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone trust interfaces st5.0",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			)
			// PREMISE: the tolerant compiler kept BOTH VPNs. If it pruned one
			// there is no collision left and every assertion below is vacuous.
			if n := len(cfg.Security.IPsec.VPNs); n != 2 {
				t.Fatalf("premise broken: %d VPNs survived the lenient compile, want 2", n)
			}

			dev, ok := cfg.SecureTunnelUnitNetdev("st5.0")
			if dev != tc.wantDev || ok != tc.wantOK {
				t.Errorf("SecureTunnelUnitNetdev(\"st5.0\") = (%q, %v), want (%q, %v) — "+
					"a collision between spellings that do not name this ref's device is "+
					"not this ref's collision", dev, ok, tc.wantDev, tc.wantOK)
			}

			// Both colliding cases resolve the OWNERSHIP question to false —
			// routing creates neither device — so the row keeps its dataplane
			// role either way. What differs is the NAME, and the name decides
			// the ifindex, which decides everything ifindex-keyed.
			if _, owned := cfg.SecureTunnelNetdevForRef("st5.0"); owned {
				t.Errorf("SecureTunnelNetdevForRef(\"st5.0\") reported an owner under an " +
					"if_id collision; routing creates NEITHER colliding device")
			}

			row := snapRow(t, cfg, "st5.0")
			if row.LinuxName != tc.wantLinux || row.Ifindex != tc.wantIfindex {
				t.Errorf("st5.0 row = netdev %q / ifindex %d, want %q / %d — at a name on "+
					"no box the row reports ifindex 0 and the Rust plane skips it "+
					"(`if iface.ifindex <= 0`): no filter input, no per-unit CoS, no "+
					"routing-instance binding", row.LinuxName, row.Ifindex,
					tc.wantLinux, tc.wantIfindex)
			}

			// The operator-visible consequence: the AF_XDP/RSS allowlist is
			// keyed by NAME and has NO ifindex guard, so it follows whichever
			// netdev the resolver picked — `st5.0` appears in it exactly when
			// the resolution chose `st5.0`, existing or not. (#6691 round 8:
			// an earlier version of this comment claimed the opposite, that a
			// name on no box "must not enter" the allowlist. It does enter, by
			// construction, and maps_sync.go says so for the sibling `st0`
			// case. What this assertion pins is that the allowlist tracks the
			// RESOLUTION, not that it filters on existence.)
			bound := UserspaceBoundLinuxInterfaces(cfg)
			if got := slices.Contains(bound, "st5.0"); got != (tc.wantLinux == "st5.0") {
				t.Errorf("`st5.0` in the RSS/binding allowlist = %v (allowlist %v), want %v",
					got, bound, tc.wantLinux == "st5.0")
			}
		})
	}
}

// TestSecureTunnelBareRowRequiresTheBareSpelling pins the DIRECTION.
//
// Ownership is not symmetric, and comparing bases only cannot say so:
//
//   - a DOTTED ref (`st5.0`) is a logical unit whose device is whatever
//     spelling was authored — a bare `st5` and an explicit `st5.0` are one
//     xfrmi under two names, so BOTH own it;
//   - a BARE ref (`st5`) is a base row, and snapshotLinuxName gives a base row
//     the netdev `LinuxIfName(ifName)` — literally `st5`. Only an authored
//     bare `st5` creates a device under that name.
//
// Measured before the fix, with a real NIC `st5` (ifindex 11) carrying a zoned
// unit 3 and a VPN binding `st5.0`: the `st5` row came back
// `secureTunnel=true` and `st5` was ABSENT from the RSS/binding allowlist. A
// live NIC removed from the dataplane by a VPN whose device is `st5.0`.
// origin/master keeps `st5` in that allowlist; this restores it.
//
// Fail-on-revert: in bindInterfaceOwnsRef replace the bare-ref arm
//
//	if !refHasUnit { return !bindHasUnit }
//
// with `if !refHasUnit { return true }` (the round-6 base-only comparison) and
// the `st5.0` sub-test goes RED.
//
// The `st5` sub-test is the control in the OTHER direction: without it,
// answering false for every bare ref — or requiring exact string equality for
// every ref — would pass, and either would unbind the canonical bare spelling
// that `bind-interface st0` authors.
func TestSecureTunnelBareRowRequiresTheBareSpelling(t *testing.T) {
	for _, tc := range []struct {
		bindIface string
		// wantBare/wantUnit: does this binding own the BARE row `st5` and the
		// UNIT ref `st5.0`?
		wantBare, wantUnit bool
		// wantDev is the device name both owned answers must carry.
		wantDev string
	}{
		{bindIface: "st5", wantBare: true, wantUnit: true, wantDev: "st5"},
		{bindIface: "st5.0", wantBare: false, wantUnit: true, wantDev: "st5.0"},
	} {
		t.Run(tc.bindIface, func(t *testing.T) {
			// PREMISE: both spellings derive ONE if_id, so nothing below can be
			// explained by the if_id filter — only by the name comparison.
			bindDev, bindID := config.XFRMIfNameAndID(tc.bindIface)
			_, bareID := config.XFRMIfNameAndID("st5")
			_, unitID := config.XFRMIfNameAndID("st5.0")
			if bindID == 0 || bindID != bareID || bindID != unitID {
				t.Fatalf("premise broken: bind %q id %#x, `st5` id %#x, `st5.0` id %#x — "+
					"this case needs all three equal", tc.bindIface, bindID, bareID, unitID)
			}
			if bindDev != tc.wantDev {
				t.Fatalf("premise broken: bind-interface %q creates device %q, want %q",
					tc.bindIface, bindDev, tc.wantDev)
			}

			defer stubLinkSnapshot5619(t, map[string]int{
				"st5": 11, "st5.3": 12, "ge-0-0-0": 10,
			})()
			cfg := lenientStConfig(t,
				"set security ipsec vpn v bind-interface "+tc.bindIface,
				"set interfaces st5 unit 0 family inet address 192.0.2.1/24",
				"set security zones security-zone vpn interfaces st5.0",
				"set interfaces st5 unit 3 family inet address 198.51.100.1/24",
				"set security zones security-zone trust interfaces st5.3",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			)

			// The resolver, both directions, asserted on the NAME as well as
			// the boolean: a caller that reads the name without checking ok
			// would otherwise attach forwarding state to the wrong device.
			bareDev, bareOK := cfg.SecureTunnelNetdevForRef("st5")
			wantBareDev := ""
			if tc.wantBare {
				wantBareDev = tc.wantDev
			}
			if bareOK != tc.wantBare || bareDev != wantBareDev {
				t.Errorf("SecureTunnelNetdevForRef(\"st5\") = (%q, %v), want (%q, %v) — the "+
					"bare row's netdev IS `st5`, and `bind-interface %s` creates %q",
					bareDev, bareOK, wantBareDev, tc.wantBare, tc.bindIface, bindDev)
			}
			unitDev, unitOK := cfg.SecureTunnelNetdevForRef("st5.0")
			if unitOK != tc.wantUnit || unitDev != tc.wantDev {
				t.Errorf("SecureTunnelNetdevForRef(\"st5.0\") = (%q, %v), want (%q, %v) — a "+
					"logical unit resolves through EITHER authored spelling; a bare `st5` "+
					"and an explicit `st5.0` are one xfrmi under two names",
					unitDev, unitOK, tc.wantDev, tc.wantUnit)
			}

			// The snapshot row, and the set an operator sees it in.
			bare := snapRow(t, cfg, "st5")
			if bare.LinuxName != "st5" {
				t.Fatalf("premise broken: the `st5` row resolved to netdev %q — a base row "+
					"must keep LinuxIfName(ifName), or the assertions below are about a "+
					"different device", bare.LinuxName)
			}
			if bare.Ifindex != 11 {
				t.Fatalf("premise broken: the `st5` row has ifindex %d, want 11 — the stub "+
					"makes the NIC exist precisely so its removal is observable",
					bare.Ifindex)
			}
			if bare.SecureTunnel != tc.wantBare {
				t.Errorf("`st5` row secureTunnel = %v, want %v under `bind-interface %s`",
					bare.SecureTunnel, tc.wantBare, tc.bindIface)
			}
			if got := userspaceSkipsIngressInterface(bare); got != tc.wantBare {
				t.Errorf("userspaceSkipsIngressInterface(`st5`) = %v, want %v — under "+
					"`bind-interface st5.0` the device is `st5.0`, so the row named `st5` "+
					"is an ordinary NIC and keeps its dataplane role", got, tc.wantBare)
			}
			bound := UserspaceBoundLinuxInterfaces(cfg)
			if got := slices.Contains(bound, "st5"); got == tc.wantBare {
				t.Errorf("`st5` in the RSS/binding allowlist = %v (allowlist %v), want %v — "+
					"a NIC a VPN does not name keeps its AF_XDP binding",
					got, bound, !tc.wantBare)
			}

			// The unit row is the counterweight: the REAL xfrmi must still be
			// excluded under both spellings, or "stop excluding things" would
			// satisfy the assertions above.
			unit := snapRow(t, cfg, "st5.0")
			if !unit.SecureTunnel || !userspaceSkipsIngressInterface(unit) {
				t.Errorf("`st5.0` row secureTunnel = %v / skipIngress = %v under "+
					"`bind-interface %s`, want true/true — that row IS the xfrmi",
					unit.SecureTunnel, userspaceSkipsIngressInterface(unit), tc.bindIface)
			}
		})
	}
}
