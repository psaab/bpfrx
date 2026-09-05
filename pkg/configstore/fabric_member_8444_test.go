package configstore

import (
	"fmt"
	"strings"
	"testing"
)

// #8444: a typo in `interfaces fabN fabric-options member-interfaces` committed
// clean and left the cluster with NO fabric link.
//
// The mechanism, measured through CheckText before the fix existed:
// deriveFabricInterface selects the fabric interface only from a member whose
// name parses to an FPC slot matching this node. A name that does not parse
// selects nothing, cc.FabricInterface stays EMPTY, and every fabric bring-up in
// pkg/daemon/daemon_run_bringup.go is gated on it — so they are all silently
// skipped. Note what the member LIST does meanwhile: it stays POPULATED, so an
// assertion that FabricMembers is non-empty is green straight through the
// outage. These cells bind the DERIVED interface instead.

// fabricBody8444 is the canonical two-fab cluster shape from
// docs/ha-cluster-userspace.conf. Note deliberately that NEITHER fabric member
// has an `interfaces` stanza of its own — that is how real configs are written
// (a fabric member is a bare NIC with no unit, address or family), and it is
// why this gate cannot be an "is it defined under interfaces" existence check.
func fabricBody8444(m0, m1 string, node int) string {
	return fmt.Sprintf(`
interfaces {
    fxp0 { unit 0 { family inet { dhcp; } } }
    em0 { unit 0 { family inet { address 10.99.12.1/30; } } }
    fab0 {
        fabric-options { member-interfaces { %s; } }
        unit 0 { family inet { address 10.99.13.1/30; } }
    }
    fab1 {
        fabric-options { member-interfaces { %s; } }
    }
}
chassis { cluster { cluster-id 1; node %d; authentication-key test-cluster-psk-8444; } }
`, m0, m1, node)
}

// TestFabricMemberTypoFailsCommit8444 is the fail-on-revert guard: the typo
// must be rejected at commit / commit-check, on EITHER node. It is checked on
// both because one config text is synced verbatim to both nodes — a gate whose
// answer depended on which node evaluated it would accept on one and reject on
// its peer, wedging the sync.
func TestFabricMemberTypoFailsCommit8444(t *testing.T) {
	for _, node := range []int{0, 1} {
		_, err := CheckText(fabricBody8444("fabster", "ge-7/0/0", node), node)
		if err == nil {
			t.Fatalf("node %d: expected commit to reject an unparseable fabric member, got nil", node)
		}
		for _, want := range []string{"fab0", "fabster", "NO fabric link"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("node %d: error %q does not name %q", node, err.Error(), want)
			}
		}
	}
}

// TestFabricMemberDashFormDerivesInterface8444 INVERTED in #8829, and the
// inversion is the point of the comment.
//
// #8444 originally hard-REJECTED `ge-0-0-0` here, on a premise it had measured
// and stated: the dash form "derives nothing on EITHER node", exactly like the
// `fabster` typo. #8829 removed that premise rather than working around it.
// `InterfaceSlot` now parses the operational dash spelling (the spelling
// pkg/daemon/linksetup.go actually emits, so it is what an operator reads off a
// running box), and the dash form now derives fab0 on node 0 and fab1 on node 1
// — identically to the slash form.
//
// It also BRINGS UP identically, which is what makes accepting it safe rather
// than merely permissive: every consumer resolves a member through
// config.LinuxIfName, which is ReplaceAll(name, "/", "-") and therefore
// idempotent on the dash form, so `ge-0-0-0` and `ge-0/0/0` reach the SAME
// kernel netdev at LinkByName (pkg/routing/bond.go enslaveMembers). This is NOT
// the deliberately-out-of-scope `ge-0/0/99` case, which parses and derives but
// names a NIC that does not exist and fails visibly at netlink.
//
// So the old rejection became an over-rejection: it refused a config that
// derives correctly and works — the #4191 class #8444 itself set out to avoid.
// The guard's real purpose, catching a member that derives NOTHING, is
// unchanged and is covered by the `fabster` cell above.
//
// This cell asserts the DERIVATION, not just that the commit was accepted:
// an accepted commit with an empty FabricInterface is precisely the #8444
// outage, and "no error" alone cannot tell the two apart.
func TestFabricMemberDashFormDerivesInterface8444(t *testing.T) {
	cases := []struct {
		node            int
		wantFabric      string
		wantLocalMember string
	}{
		{0, "fab0", "ge-0-0-0"},
		{1, "fab1", "ge-7-0-0"},
	}
	for _, tc := range cases {
		cfg, err := CheckText(fabricBody8444("ge-0-0-0", "ge-7-0-0", tc.node), tc.node)
		if err != nil {
			t.Fatalf("node %d: the dash-form fabric member must commit since #8829 — it parses to an FPC slot and derives: %v", tc.node, err)
		}
		cc := cfg.Chassis.Cluster
		if cc == nil {
			t.Fatalf("node %d: no cluster compiled", tc.node)
		}
		if cc.FabricInterface != tc.wantFabric {
			t.Fatalf("node %d: FabricInterface = %q, want %q — an EMPTY value here is the #8444 outage itself (every fabric bring-up is gated on it), and it is what accepting the commit would otherwise hide",
				tc.node, cc.FabricInterface, tc.wantFabric)
		}
		ifc := cfg.Interfaces.Interfaces[tc.wantFabric]
		if ifc == nil || ifc.LocalFabricMember != tc.wantLocalMember {
			got := "<no interface>"
			if ifc != nil {
				got = ifc.LocalFabricMember
			}
			t.Fatalf("node %d: LocalFabricMember = %q, want %q — the bring-up path consumes this to pick THIS node's physical port",
				tc.node, got, tc.wantLocalMember)
		}
	}
}

// TestFabricMemberValidDerivesInterface8444 is the POSITIVE CONTROL, and it
// binds the HARM rather than the parse: a correct config must still commit AND
// must still produce a non-empty cc.FabricInterface plus the resolved
// LocalFabricMember the bring-up path consumes. A gate that rejected nothing
// would pass the two cells above only by accident; a gate that rejected
// everything would pass them and fail here.
//
// Both nodes are exercised: the SAME config text derives fab0/ge-0/0/0 on node
// 0 and fab1/ge-7/0/0 on node 1.
func TestFabricMemberValidDerivesInterface8444(t *testing.T) {
	cases := []struct {
		node            int
		wantFabric      string
		wantLocalMember string
	}{
		{0, "fab0", "ge-0/0/0"},
		{1, "fab1", "ge-7/0/0"},
	}
	for _, tc := range cases {
		cfg, err := CheckText(fabricBody8444("ge-0/0/0", "ge-7/0/0", tc.node), tc.node)
		if err != nil {
			t.Fatalf("node %d: a correct fabric member config must commit: %v", tc.node, err)
		}
		cc := cfg.Chassis.Cluster
		if cc == nil {
			t.Fatalf("node %d: no cluster compiled", tc.node)
		}
		if cc.FabricInterface != tc.wantFabric {
			t.Fatalf("node %d: FabricInterface = %q, want %q — the fabric bring-up is gated on this being non-empty",
				tc.node, cc.FabricInterface, tc.wantFabric)
		}
		ifc := cfg.Interfaces.Interfaces[tc.wantFabric]
		if ifc == nil || ifc.LocalFabricMember != tc.wantLocalMember {
			got := ""
			if ifc != nil {
				got = ifc.LocalFabricMember
			}
			t.Fatalf("node %d: %s LocalFabricMember = %q, want %q",
				tc.node, tc.wantFabric, got, tc.wantLocalMember)
		}
	}
}

// TestFabricMemberGateIsNotAnExistenceCheck8444 is the anti-over-rejection
// guard, and it is the cell that would have caught the first version of this
// fix. The obvious implementation — require the member to be defined under
// `interfaces`, reusing zoneReferenceableInterfaceBases the way
// validateZoneInterfaceDefinedStrict does — hard-rejects the canonical
// production config on BOTH nodes, because neither ge-0/0/0 nor ge-7/0/0 has an
// `interfaces` stanza in docs/ha-cluster-userspace.conf.
//
// Two rows hold that line:
//   - a `xe-` member (the gate must not be hardcoded to `ge-`), and
//   - a parseable member naming a port that does not exist (ge-0/0/99), which
//     is DELIBERATELY out of scope: measured, it derives normally and the
//     bring-up then fails at netlink with a visible error. That is a different,
//     non-silent defect, and catching it needs exactly the existence check
//     shown unsound above.
func TestFabricMemberGateIsNotAnExistenceCheck8444(t *testing.T) {
	rows := []struct{ name, m0, m1, wantFabric string }{
		{"xe-prefix", "xe-0/0/0", "xe-7/0/0", "fab0"},
		{"parseable-but-absent-port", "ge-0/0/99", "ge-7/0/99", "fab0"},
	}
	for _, r := range rows {
		cfg, err := CheckText(fabricBody8444(r.m0, r.m1, 0), 0)
		if err != nil {
			t.Fatalf("%s: gate must not reject a slot-parseable member (no fabric member "+
				"has its own `interfaces` stanza in a real config): %v", r.name, err)
		}
		if cfg.Chassis.Cluster.FabricInterface != r.wantFabric {
			t.Fatalf("%s: FabricInterface = %q, want %q",
				r.name, cfg.Chassis.Cluster.FabricInterface, r.wantFabric)
		}
	}
}

// TestFabricMemberTypoLenientAtStoreIngress8444 is the #1960 no-brick half, and
// it binds at the STORE INGRESS rather than at the validator: Store.SyncApply
// (and Store.Load, which shares compileTreeLenient) must still accept a config
// an older binary already persisted or a peer already synced, downgrading the
// rejection to a warning. Refusing to start would add an outage to an outage —
// the fabric is already down in that config.
func TestFabricMemberTypoLenientAtStoreIngress8444(t *testing.T) {
	s := newTestStore(t)
	compiled, err := s.SyncApply(fabricBody8444("fabster", "ge-7/0/0", 0), nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a peer-synced config with a bad fabric member: %v", err)
	}
	found := false
	for _, w := range compiled.Warnings {
		if strings.Contains(w, "fabric member interface (downgraded to warning on tolerant path)") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a downgraded fabric-member warning, got warnings: %v", compiled.Warnings)
	}
	// The harm is still present on the tolerant path — that is the point of the
	// warning. Assert it so the cell cannot silently become a strict-path test.
	if compiled.Chassis.Cluster.FabricInterface != "" {
		t.Fatalf("tolerant path unexpectedly derived FabricInterface = %q",
			compiled.Chassis.Cluster.FabricInterface)
	}
}
