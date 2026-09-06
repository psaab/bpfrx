package userspace

import (
	"sort"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9132: a BARE `routing-instances <ri> interface ge-0/0/0` reference must bind
// the interface's ADDRESSED units, not just the bare key.
//
// The two routing binders (buildInterfaceRouteTables, buildInterfaceRoutingInstances)
// keyed a bare reference on `config.CanonicalInterfaceUnitRef(ifname)` alone,
// which for a bare reference is the bare name. The per-unit snapshot rows that
// carry the ADDRESSES are named "<base>.<unit>", so the lookup missed and the
// unit fell back to `inet.0` with `RoutingInstance == ""`. The operator writes a
// routine, accepted, strict-commit-clean sentence, the box reports the interface
// as a VRF member on every show surface, and the dataplane installs the tenant's
// subnet into the DEFAULT table with a working egress ifindex.
//
// It is NOT the #9063 collapse. There, `logicalUnitDeviceKey` normalized two
// DIFFERENT spellings onto ONE key, so the consumer could not tell a whole-device
// reference from a unit-0 one — an over-match. Here nothing collapses:
// `CanonicalInterfaceUnitRef` leaves `ge-0/0/0` and `ge-0/0/0.0` distinct, and
// the bare key simply reaches nothing — an under-match. Same class (an interface
// reference whose key shape is held together by a note), opposite direction,
// opposite fix: #9063 reads the RAW reference to recover a distinction, #9132
// fans a bare reference DOWN to gain reach.

func snapshotByName9132(t *testing.T, snaps []InterfaceSnapshot, name string) InterfaceSnapshot {
	t.Helper()
	for _, s := range snaps {
		if s.Name == name {
			return s
		}
	}
	names := make([]string, 0, len(snaps))
	for _, s := range snaps {
		names = append(names, s.Name)
	}
	t.Fatalf("no interface snapshot named %q; have %v", name, names)
	return InterfaceSnapshot{}
}

func routeTableOf9132(t *testing.T, cfg *config.Config, dest string) string {
	t.Helper()
	snaps := buildInterfaceSnapshots(cfg)
	routes, _, err := buildRouteSnapshots(cfg, snaps, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	tables := make([]string, 0, 2)
	for _, r := range routes {
		if r.Destination == dest {
			tables = append(tables, r.Table)
		}
	}
	if len(tables) == 0 {
		t.Fatalf("no route snapshot for %q; the fixture never produced the prefix "+
			"this cell is about, so a table assertion would be vacuous", dest)
	}
	sort.Strings(tables)
	if len(tables) > 1 {
		t.Fatalf("prefix %q installed into %d tables %v; this cell asserts a single "+
			"owning table and cannot read a multi-table answer", dest, len(tables), tables)
	}
	return tables[0]
}

// THE DEFECT, with the unit spelling as the in-run control.
//
// Both sub-cases configure exactly the same interface, address and instance and
// differ in ONE token — whether the routing-instance reference carries `.0`.
// The unit spelling was already correct at master, so it is what rules out "the
// prefix lands in inet.0 for some unrelated reason".
//
// RED at master on the BARE sub-case: interfaceTablesV4 holds only
// `ge-0/0/0` -> tenant-a.inet.0, the addressed row `ge-0/0/0.0` misses, and the
// connected prefix installs into inet.0.
func TestBareRoutingInstanceRefBindsTheAddressedUnit9132(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"bare", "ge-0/0/0"},
		{"unit-control", "ge-0/0/0.0"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := routingDomainCfg7160(t,
				"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
				"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8:10::1/64",
				"set routing-instances tenant-a instance-type virtual-router",
				"set routing-instances tenant-a interface "+tc.ref,
			)

			v4, v6 := buildInterfaceRouteTables(cfg)
			if got := v4["ge-0/0/0.0"]; got != "tenant-a.inet.0" {
				t.Errorf("interfaceTablesV4[%q] = %q, want %q: the ADDRESSED row is "+
					"the per-unit snapshot, so a reference that does not reach it "+
					"binds no address at all (map = %v)",
					"ge-0/0/0.0", got, "tenant-a.inet.0", v4)
			}
			if got := v6["ge-0/0/0.0"]; got != "tenant-a.inet6.0" {
				t.Errorf("interfaceTablesV6[%q] = %q, want %q", "ge-0/0/0.0", got, "tenant-a.inet6.0")
			}
			if got := buildInterfaceRoutingInstances(cfg)["ge-0/0/0.0"]; got != "tenant-a" {
				t.Errorf("buildInterfaceRoutingInstances[%q] = %q, want %q: the Rust "+
					"side derives the connected table purely from "+
					"InterfaceSnapshot.RoutingInstance, so an empty value here is "+
					"what makes #2388's table scoping inert",
					"ge-0/0/0.0", got, "tenant-a")
			}

			// The snapshot row the dataplane actually consumes.
			unit := snapshotByName9132(t, buildInterfaceSnapshots(cfg), "ge-0/0/0.0")
			if len(unit.Addresses) == 0 {
				t.Fatalf("fixture: the unit row carries no addresses, so nothing "+
					"about table binding is observable from it (row = %+v)", unit)
			}
			if unit.RoutingInstance != "tenant-a" {
				t.Errorf("snapshot %q RoutingInstance = %q, want %q",
					unit.Name, unit.RoutingInstance, "tenant-a")
			}
			if want := uint32(config.StableRoutingInstanceTableID("tenant-a")); unit.RoutingDomain != want {
				t.Errorf("snapshot %q RoutingDomain = %d, want %d",
					unit.Name, unit.RoutingDomain, want)
			}

			// End to end: the connected prefix must not leak into the default table.
			if got := routeTableOf9132(t, cfg, "192.168.10.0/24"); got != "tenant-a.inet.0" {
				t.Errorf("connected prefix 192.168.10.0/24 installed into %q, want "+
					"%q — a VRF-attached interface's subnet reachable from the "+
					"default table, with a valid egress ifindex", got, "tenant-a.inet.0")
			}
			if got := routeTableOf9132(t, cfg, "2001:db8:10::/64"); got != "tenant-a.inet6.0" {
				t.Errorf("connected prefix 2001:db8:10::/64 installed into %q, want %q",
					got, "tenant-a.inet6.0")
			}
		})
	}
}

// The cross-subsystem CONTROL that makes this a defect rather than an
// unsupported input: the sibling binder in the same documented family
// (CanonicalInterfaceUnitRef's own doc names all three) already fans a bare
// reference down. Two of the three did not.
//
// Scoped to BARE references on purpose. The zone binder ALSO fans a UNIT
// reference UP to the physical key, and the routing binders deliberately do
// not — see TestAUnitRefMustNotDragTheBaseIntoTheVRF9132 — so a claim of
// agreement over every reference shape would be false, and levelling the three
// to one behaviour would be consistency achieved in the wrong direction.
func TestAllThreeBindersReachTheSameRowsForABareRef9132(t *testing.T) {
	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 192.168.100.1/24",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/0",
		"set security zones security-zone trust interfaces ge-0/0/0",
	)

	keysFor := func(m map[string]string, want string) []string {
		out := make([]string, 0, len(m))
		for k, v := range m {
			if v == want {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	v4, _ := buildInterfaceRouteTables(cfg)
	zoneKeys := keysFor(config.InterfaceZoneMap(cfg), "trust")
	riKeys := keysFor(buildInterfaceRoutingInstances(cfg), "tenant-a")
	tableKeys := keysFor(v4, "tenant-a.inet.0")

	want := []string{"ge-0/0/0", "ge-0/0/0.0", "ge-0/0/0.100"}
	if len(zoneKeys) != len(want) {
		t.Fatalf("fixture: the zone binder reached %v, not the %v this cell "+
			"compares against — the control moved, so the comparison is not "+
			"about the routing binders any more", zoneKeys, want)
	}
	for _, got := range [][]string{zoneKeys, riKeys, tableKeys} {
		if len(got) != len(want) {
			t.Errorf("binder reached %v, want %v: the three binders in "+
				"CanonicalInterfaceUnitRef's documented family must agree on which "+
				"rows a BARE reference reaches", got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("binder reached %v, want %v", got, want)
				break
			}
		}
	}
}

// OVER-REACH GUARD. A UNIT reference must NOT drag the physical row into the
// VRF.
//
// The base snapshot row's addresses come from the kernel netdev
// (buildLinkSnapshot), and on a real box that netdev carries UNIT 0's
// addresses. Binding the base from a `ge-0/0/0.1` reference would move unit 0's
// prefix into unit 1's routing instance — #9063's hazard pointed the other way.
// The zone binder's fan-UP is right for zones and wrong here, which is why it
// stayed at its own call site rather than moving into the shared helper.
//
// GREEN at master. It constrains what the fix must NOT do.
func TestAUnitRefMustNotDragTheBaseIntoTheVRF9132(t *testing.T) {
	cfg := routingDomainCfg7160(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.168.11.1/24",
		"set routing-instances tenant-a instance-type virtual-router",
		"set routing-instances tenant-a interface ge-0/0/0.1",
	)
	v4, _ := buildInterfaceRouteTables(cfg)
	if got, ok := v4["ge-0/0/0"]; ok {
		t.Errorf("interfaceTablesV4[%q] = %q, but only unit 1 was referenced. The "+
			"base row inherits the kernel netdev's addresses, which are unit 0's, "+
			"so binding it here moves unit 0's prefix into unit 1's instance",
			"ge-0/0/0", got)
	}
	if got, ok := buildInterfaceRoutingInstances(cfg)["ge-0/0/0"]; ok {
		t.Errorf("buildInterfaceRoutingInstances[%q] = %q, but only unit 1 was referenced",
			"ge-0/0/0", got)
	}
	if got := v4["ge-0/0/0.1"]; got != "tenant-a.inet.0" {
		t.Errorf("fixture: the referenced unit itself must still bind; got %q", got)
	}
	if _, ok := v4["ge-0/0/0.0"]; ok {
		t.Errorf("unit 0 was not referenced and must not be bound")
	}
}

// The ordering rule the fan-down forces someone to choose: an EXPLICIT unit
// reference beats a unit key reached by fanning a BARE reference down.
//
// Before #9132 the two could not collide — a bare reference claimed only the
// bare key. A single pass with plain assignment would resolve this by the order
// of `cfg.RoutingInstances`, which is a silent order-dependent VRF binding for a
// contradictory config.
//
// FIXTURE NOTE, and it cost a wrong verdict first. `cfg.RoutingInstances` is in
// AUTHORING order (measured — not sorted by name), but the position of an
// instance is fixed by its FIRST mention, which is the `instance-type` line.
// An earlier version of this cell varied the order of the `interface` lines
// only, so BOTH its sub-cases produced the same slice order, and a
// single-pass-last-writer-wins mutant SURVIVED it: with the bare reference in
// the earlier instance, last-writer-wins happens to agree with the rule. The
// order is now varied where it is actually decided, the slice order is
// ASSERTED so the cell cannot silently stop varying it, and the discriminating
// arrangement — the EXPLICIT unit reference in the EARLIER instance — is the
// first sub-case.
func TestExplicitUnitRefBeatsAFannedDownBareRef9132(t *testing.T) {
	refs := []string{
		"set routing-instances tenant-a interface ge-0/0/0",
		"set routing-instances tenant-b interface ge-0/0/0.1",
	}
	ifaces := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
		"set interfaces ge-0/0/0 unit 1 family inet address 192.168.11.1/24",
	}
	lines := func(firstInstance, secondInstance string) []string {
		out := append([]string{}, ifaces...)
		out = append(out, "set routing-instances "+firstInstance+" instance-type virtual-router")
		out = append(out, "set routing-instances "+secondInstance+" instance-type virtual-router")
		return append(out, refs...)
	}
	for _, tc := range []struct {
		name      string
		lines     []string
		wantOrder []string
	}{
		{
			// THE DISCRIMINATING ARRANGEMENT. The instance holding the EXPLICIT
			// unit reference comes first, so a single pass lets the later bare
			// reference's fan-down overwrite it.
			name:      "explicit-unit-instance-first",
			lines:     lines("tenant-b", "tenant-a"),
			wantOrder: []string{"tenant-b", "tenant-a"},
		},
		{
			// The control: the bare reference's instance comes first, where
			// last-writer-wins happens to agree with the rule. Its job is to
			// show the answer is ORDER-INDEPENDENT, not to catch the mutant.
			name:      "bare-instance-first",
			lines:     lines("tenant-a", "tenant-b"),
			wantOrder: []string{"tenant-a", "tenant-b"},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := routingDomainCfg7160(t, tc.lines...)

			gotOrder := make([]string, 0, len(cfg.RoutingInstances))
			for _, ri := range cfg.RoutingInstances {
				gotOrder = append(gotOrder, ri.Name)
			}
			if len(gotOrder) != len(tc.wantOrder) {
				t.Fatalf("fixture: RoutingInstances = %v, want %v", gotOrder, tc.wantOrder)
			}
			for i := range tc.wantOrder {
				if gotOrder[i] != tc.wantOrder[i] {
					t.Fatalf("fixture: RoutingInstances order = %v, want %v — the two "+
						"sub-cases must differ HERE or neither exercises the ordering rule",
						gotOrder, tc.wantOrder)
				}
			}

			ri := buildInterfaceRoutingInstances(cfg)
			if got := ri["ge-0/0/0.1"]; got != "tenant-b" {
				t.Errorf("buildInterfaceRoutingInstances[%q] = %q, want %q: the "+
					"explicitly named unit must beat the unit key a bare reference "+
					"fans down onto, whichever instance is authored first",
					"ge-0/0/0.1", got, "tenant-b")
			}
			if got := ri["ge-0/0/0.0"]; got != "tenant-a" {
				t.Errorf("buildInterfaceRoutingInstances[%q] = %q, want %q: the bare "+
					"reference still reaches the units nobody named explicitly",
					"ge-0/0/0.0", got, "tenant-a")
			}
			if got := ri["ge-0/0/0"]; got != "tenant-a" {
				t.Errorf("buildInterfaceRoutingInstances[%q] = %q, want %q",
					"ge-0/0/0", got, "tenant-a")
			}
			v4, _ := buildInterfaceRouteTables(cfg)
			if got := v4["ge-0/0/0.1"]; got != "tenant-b.inet.0" {
				t.Errorf("interfaceTablesV4[%q] = %q, want %q: the route-table map "+
					"must resolve the collision the same way the instance map does",
					"ge-0/0/0.1", got, "tenant-b.inet.0")
			}
		})
	}
}

// The fan-down is PURELY ADDITIVE on these maps: every key the pre-#9132 loop
// produced still carries the pre-#9132 value, and the only new keys are unit
// keys of bare references.
//
// The oracle is the old loop, re-implemented here verbatim rather than
// described, so it cannot drift into agreeing with the new code by paraphrase.
// This is what makes the change reviewable without re-reasoning about every
// existing routing-instance test: it can only ADD reach.
func TestBareRefFanDownIsPurelyAdditive9132(t *testing.T) {
	corpus := [][]string{
		{
			"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
			"set routing-instances tenant-a instance-type virtual-router",
			"set routing-instances tenant-a interface ge-0/0/0",
		},
		{
			"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
			"set routing-instances tenant-a instance-type virtual-router",
			"set routing-instances tenant-a interface ge-0/0/0.0",
		},
		{
			"set interfaces ge-0/0/0 vlan-tagging",
			"set interfaces ge-0/0/0 unit 0 family inet address 192.168.10.1/24",
			"set interfaces ge-0/0/0 unit 100 vlan-id 100",
			"set interfaces ge-0/0/0 unit 100 family inet address 192.168.100.1/24",
			"set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/24",
			"set routing-instances tenant-a instance-type virtual-router",
			"set routing-instances tenant-b instance-type virtual-router",
			"set routing-instances tenant-a interface ge-0/0/0",
			"set routing-instances tenant-b interface ge-0/0/1.0",
		},
		{
			// The #5878 non-canonical spelling, which must keep binding the
			// canonical unit key and nothing else.
			"set interfaces ge-0/0/0 unit 1 family inet address 192.168.11.1/24",
			"set routing-instances tenant-a instance-type virtual-router",
			"set routing-instances tenant-a interface ge-0/0/0.01",
		},
	}
	for i, lines := range corpus {
		cfg := routingDomainCfg7160(t, lines...)

		// The pre-#9132 loop, verbatim.
		master := make(map[string]string)
		for _, ri := range cfg.RoutingInstances {
			if ri == nil || ri.Name == "" {
				continue
			}
			for _, ifname := range ri.Interfaces {
				if ifname == "" {
					continue
				}
				master[config.CanonicalInterfaceUnitRef(ifname)] = ri.Name
			}
		}
		if len(master) == 0 {
			t.Fatalf("corpus[%d]: the oracle is empty, so this case asserts nothing", i)
		}

		got := buildInterfaceRoutingInstances(cfg)
		for k, want := range master {
			if have, ok := got[k]; !ok || have != want {
				t.Errorf("corpus[%d]: key %q was %q before #9132 and is now %q (present=%v); "+
					"the fan-down must only ADD keys", i, k, want, have, ok)
			}
		}
		for k := range got {
			if _, ok := master[k]; ok {
				continue
			}
			base, unit, hasUnit := cutOnFirstDot9132(k)
			if !hasUnit || unit == "" {
				t.Errorf("corpus[%d]: new key %q is not a unit key; the fan-down "+
					"must add only units of a bare reference", i, k)
				continue
			}
			if _, ok := master[base]; !ok {
				t.Errorf("corpus[%d]: new key %q has no bare-reference parent %q in "+
					"the pre-#9132 map", i, k, base)
			}
		}
	}
}

func cutOnFirstDot9132(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
