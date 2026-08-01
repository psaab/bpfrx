package userspace

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// secureTunnelIfNameCases is the shared classification table for the two-plane
// `st<N>` mirror (#5619). The Rust half (`secure_tunnel_ifname_matches_go`,
// userspace-dp/src/server/helpers/planning.rs) asserts the SAME table against
// `is_secure_tunnel_ifname`. Keep the two lists identical — a name added on one
// side only is exactly the drift this pair exists to catch.
var secureTunnelIfNameCases = []struct {
	base string
	want bool
}{
	{"st0", true},
	{"st1", true},
	{"st9", true},
	{"st10", true},
	{"st0000", true},
	// Atoi accepts a sign, so both planes must classify these the same way
	// even though XFRMIfNameAndID would refuse to build a device for them.
	{"st-3", true},
	{"st+5", true},
	// Not secure tunnels.
	{"st", false},
	{"stx", false},
	{"st0x", false},
	{"start0", false},
	{"", false},
	{"ge-0-0-0", false},
	{"lo0", false},
	{"fxp0", false},
	{"em0", false},
	{"fab0", false},
	{"reth0", false},
	{"gr-0-0-0", false},
}

// TestSecureTunnelIfNameClassification pins the Go half of the mirror.
func TestSecureTunnelIfNameClassification(t *testing.T) {
	for _, tc := range secureTunnelIfNameCases {
		if got := config.IsSecureTunnelIfName(tc.base); got != tc.want {
			t.Errorf("IsSecureTunnelIfName(%q) = %v, want %v", tc.base, got, tc.want)
		}
	}
}

// TestSecureTunnelResolverParity is the drift guard the #5619 defect needed.
//
// config.ResolveKernelIfName documents that snapshotLinuxName "must be kept in
// sync" with it, but nothing enforced that — and the dataplane copy silently
// lacked the st<N>.<M>-verbatim rule, so a secure-tunnel unit resolved to the
// nonexistent netdev `st0` instead of the `st0.0` the xfrmi reconciler creates.
// This asserts the two resolvers agree on every secure-tunnel unit shape.
func TestSecureTunnelResolverParity(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn v0 bind-interface st0.0",
		"set security ipsec vpn v1 bind-interface st1.7",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces st1 unit 7 family inet address 10.5.7.1/30",
	)

	for _, ref := range []string{"st0.0", "st1.7"} {
		base, unitNum := splitRef5619(t, ref)
		iface := cfg.Interfaces.Interfaces[base]
		if iface == nil {
			t.Fatalf("interface %q missing from compiled config", base)
		}
		unit := iface.Units[unitNum]
		if unit == nil {
			t.Fatalf("unit %d missing from interface %q", unitNum, base)
		}

		ssot := cfg.ResolveKernelIfName(ref)
		dataplane := snapshotLinuxName(cfg, base, iface, unit)
		if dataplane != ssot {
			t.Errorf("resolver drift on %q: ResolveKernelIfName=%q snapshotLinuxName=%q "+
				"(the xfrmi reconciler creates the netdev under the VERBATIM dotted ref, "+
				"so a mismatch means the dataplane looks up a netdev that does not exist)",
				ref, ssot, dataplane)
		}
		if dataplane != ref {
			t.Errorf("snapshotLinuxName(%q) = %q, want the verbatim ref %q — "+
				"XFRMIfNameAndID creates the device as LinuxIfName(bind-interface)",
				ref, dataplane, ref)
		}
	}
}

// TestSecureTunnelUnitResolvesToVerbatimNetdev is the direct #5619 assertion:
// the secure-tunnel unit must resolve to the netdev the xfrmi reconciler
// actually creates, so its ifindex/MTU/addresses resolve at all.
func TestSecureTunnelUnitResolvesToVerbatimNetdev(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
	)

	// The name the xfrmi reconciler will create the device under.
	wantNetdev, ifID := config.XFRMIfNameAndID("st0.0")
	if ifID == 0 {
		t.Fatalf("XFRMIfNameAndID(st0.0) returned if_id 0; test premise broken")
	}

	restore := stubLinkSnapshot5619(t, map[string]int{wantNetdev: 42})
	defer restore()

	var got string
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Name == "st0.0" {
			got = snap.LinuxName
			if snap.Ifindex != 42 {
				t.Errorf("st0.0 Ifindex = %d, want 42 — the unit must resolve to the "+
					"real xfrmi netdev %q, not a name that exists on no box",
					snap.Ifindex, wantNetdev)
			}
		}
	}
	if got != wantNetdev {
		t.Errorf("snapshot LinuxName for st0.0 = %q, want %q (the device XFRMIfNameAndID creates)",
			got, wantNetdev)
	}
}

// TestSecureTunnelStaysOutOfDataplaneSets is the safety half of #5619.
//
// Fixing the name makes the xfrmi ifindex RESOLVE, which would otherwise admit
// it to the ingress-adjudication map and the AF_XDP binding plan. The dataplane
// cannot own an xfrmi end-to-end (no path to hand plaintext back INTO it for
// egress, and no zero-copy XSK on a virtual netdev), so admitting it would make
// the shim claim the interface and drop_degraded_transit DROP the decrypted
// plaintext. The exclusion must be explicit, not an accident of a broken name.
func TestSecureTunnelStaysOutOfDataplaneSets(t *testing.T) {
	cfg := compileForTest5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	)

	restore := stubLinkSnapshot5619(t, map[string]int{"st0.0": 42, "ge-0-0-0": 11})
	defer restore()

	snaps := buildInterfaceSnapshots(cfg)

	// Premise: the fix DID resolve the ifindex — otherwise this test would
	// pass vacuously for the pre-#5619 reason (ifindex 0), proving nothing.
	resolved := false
	for _, s := range snaps {
		if s.Name == "st0.0" {
			if s.LinuxName != "st0.0" || s.Ifindex != 42 {
				t.Fatalf("premise broken: st0.0 resolved to linux=%q ifindex=%d; this test "+
					"must exercise a RESOLVED xfrmi, not the pre-fix ifindex-0 accident",
					s.LinuxName, s.Ifindex)
			}
			resolved = true
		}
	}
	if !resolved {
		t.Fatal("premise broken: no st0.0 unit in the snapshot")
	}

	for _, s := range snaps {
		if s.Name != "st0.0" && s.Name != "st0" {
			continue
		}
		if !userspaceSkipsIngressInterface(s) {
			t.Errorf("userspaceSkipsIngressInterface(%q) = false; a secure tunnel must be "+
				"excluded from the userspace dataplane — admitting it makes the shim claim "+
				"the xfrmi and DROP decrypted plaintext it cannot deliver to an XSK", s.Name)
		}
	}

	for _, ifindex := range buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: snaps}) {
		if ifindex == 42 {
			t.Error("the xfrmi ifindex entered userspace_ingress_ifaces; the shim would then " +
				"steer decrypted plaintext to an XSK that cannot bind on a virtual netdev, " +
				"and drop_degraded_transit would drop it (a dead tunnel, not a policy fix)")
		}
	}

	for _, name := range UserspaceBoundLinuxInterfaces(cfg) {
		if name == "st0.0" || name == "st0" {
			t.Errorf("secure tunnel %q entered the AF_XDP/RSS allowlist", name)
		}
	}
}

// --- helpers -------------------------------------------------------------

// compileForTest5619 runs the REAL parser + compiler so these tests exercise
// the deployed config path rather than a hand-built Config literal.
func compileForTest5619(t *testing.T, lines ...string) *config.Config {
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
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func splitRef5619(t *testing.T, ref string) (string, int) {
	t.Helper()
	base, unit, found := strings.Cut(ref, ".")
	if !found {
		t.Fatalf("ref %q has no unit suffix", ref)
	}
	n, err := strconv.Atoi(unit)
	if err != nil {
		t.Fatalf("ref %q has a non-numeric unit: %v", ref, err)
	}
	return base, n
}

// stubLinkSnapshot5619 makes the named netdevs "exist" with the given
// ifindexes. Any other name resolves to ifindex 0, exactly as buildLinkSnapshot
// behaves for a device that is not on the box.
func stubLinkSnapshot5619(t *testing.T, live map[string]int) func() {
	t.Helper()
	prev := buildLinkSnapshot
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if idx, ok := live[name]; ok {
			return idx, 1500, "02:00:00:00:00:01", nil
		}
		return 0, 0, "", nil
	}
	return func() { buildLinkSnapshot = prev }
}

// --- review conditions -----------------------------------------------------

// TestSecureTunnelAddsNothingToDataplaneSets PROVES the load-bearing claim of
// this change: "net forwarding behaviour is identical before and after".
//
// It is a DIFFERENTIAL, not a fixture match. The same config is compiled twice —
// once with the route-based VPN and its zoned secure tunnel, once with the whole
// IPsec stanza and zone removed — and the ingress-adjudication set and the
// AF_XDP/RSS allowlist must come out BYTE-IDENTICAL. A secure tunnel adds
// nothing to what the dataplane claims.
//
// The premise assertions matter as much as the result: the tunnel row must be
// RESOLVED (verbatim netdev name, real ifindex) in the with-tunnel run. If it
// were unresolved, the sets would match for the pre-fix reason (ifindex 0) and
// the test would prove nothing at all.
func TestSecureTunnelAddsNothingToDataplaneSets(t *testing.T) {
	restore := stubLinkSnapshot5619(t, map[string]int{"st0.0": 42, "ge-0-0-0": 11})
	defer restore()

	lan := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	}
	withTunnel := compileForTest5619(t, append([]string{
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
	}, lan...)...)
	withoutTunnel := compileForTest5619(t, lan...)

	tunnelSnaps := buildInterfaceSnapshots(withTunnel)

	// PREMISE: the tunnel unit resolved. Without this the comparison below is
	// satisfied by the pre-#5619 accident rather than by the exclusion.
	var resolved bool
	for _, s := range tunnelSnaps {
		if s.Name == "st0.0" {
			if s.LinuxName != "st0.0" || s.Ifindex != 42 {
				t.Fatalf("premise broken: st0.0 resolved to linux=%q ifindex=%d, want "+
					"linux=\"st0.0\" ifindex=42 — this test must compare a RESOLVED "+
					"xfrmi, not the pre-fix ifindex-0 accident", s.LinuxName, s.Ifindex)
			}
			resolved = true
		}
	}
	if !resolved {
		t.Fatal("premise broken: no st0.0 unit in the with-tunnel snapshot")
	}

	gotIngress := buildUserspaceIngressIfindexes(&ConfigSnapshot{Interfaces: tunnelSnaps})
	wantIngress := buildUserspaceIngressIfindexes(&ConfigSnapshot{
		Interfaces: buildInterfaceSnapshots(withoutTunnel),
	})
	if !slices.Equal(gotIngress, wantIngress) {
		t.Errorf("adding a route-based IPsec tunnel CHANGED the ingress-adjudication set: "+
			"with tunnel %v, without %v. The xfrmi must add nothing — the shim would "+
			"otherwise claim it and drop the decrypted plaintext it cannot deliver to an XSK",
			gotIngress, wantIngress)
	}
	// The fixture the reshape was measured against: LAN only.
	if !slices.Equal(gotIngress, []uint32{11}) {
		t.Errorf("ingress set = %v, want [11] (the LAN netdev alone)", gotIngress)
	}

	gotAllow := UserspaceBoundLinuxInterfaces(withTunnel)
	wantAllow := UserspaceBoundLinuxInterfaces(withoutTunnel)
	if !slices.Equal(gotAllow, wantAllow) {
		t.Errorf("adding a route-based IPsec tunnel CHANGED the AF_XDP/RSS allowlist: "+
			"with tunnel %v, without %v", gotAllow, wantAllow)
	}
}

// TestSecureTunnelSpellingsAllExcluded scopes the exclusion claim to exactly
// what is implemented, per review condition 4.
//
// The exclusion matches on the BASE name with any unit suffix stripped, so it
// covers every spelling of a secure tunnel: a bare `st0`, the usual `st0.0`,
// and a multi-digit interface AND unit (`st10.5`). It is a base-name match, not
// a whole-string match and not a bare `strings.HasPrefix("st")` — `stx` and
// `start0` are NOT secure tunnels and must stay adjudicated.
func TestSecureTunnelSpellingsAllExcluded(t *testing.T) {
	for _, tc := range []struct {
		bindIface string
		ifName    string
		unit      int
		wantSkip  bool
	}{
		{bindIface: "st0", ifName: "st0", unit: 0, wantSkip: true},
		{bindIface: "st0.0", ifName: "st0", unit: 0, wantSkip: true},
		{bindIface: "st10.5", ifName: "st10", unit: 5, wantSkip: true},
	} {
		t.Run(tc.bindIface, func(t *testing.T) {
			unitRef := fmt.Sprintf("%s.%d", tc.ifName, tc.unit)
			cfg := compileForTest5619(t,
				fmt.Sprintf("set security ipsec vpn v bind-interface %s", tc.bindIface),
				fmt.Sprintf("set interfaces %s unit %d family inet address 10.5.5.1/30", tc.ifName, tc.unit),
				fmt.Sprintf("set security zones security-zone vpn interfaces %s", unitRef),
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
				"set security zones security-zone trust interfaces ge-0/0/0.0",
			)

			// Resolve whichever netdev this spelling materializes, so the row
			// under test carries a REAL ifindex rather than 0.
			devName, ifID := config.XFRMIfNameAndID(tc.bindIface)
			if ifID == 0 {
				t.Fatalf("premise broken: %q resolves to if_id 0", tc.bindIface)
			}
			restore := stubLinkSnapshot5619(t, map[string]int{
				devName: 42, unitRef: 42, "ge-0-0-0": 11,
			})
			defer restore()

			var sawTunnelRow bool
			for _, s := range buildInterfaceSnapshots(cfg) {
				if s.Name != tc.ifName && s.Name != unitRef {
					continue
				}
				sawTunnelRow = true
				if got := userspaceSkipsIngressInterface(s); got != tc.wantSkip {
					t.Errorf("userspaceSkipsIngressInterface(%q) = %v, want %v — the "+
						"exclusion matches the BASE name with the unit stripped, so every "+
						"spelling of a secure tunnel is covered", s.Name, got, tc.wantSkip)
				}
			}
			if !sawTunnelRow {
				t.Fatalf("premise broken: no row for %q / %q in the snapshot", tc.ifName, unitRef)
			}
			for _, ifindex := range buildUserspaceIngressIfindexes(
				&ConfigSnapshot{Interfaces: buildInterfaceSnapshots(cfg)}) {
				if ifindex == 42 {
					t.Errorf("secure tunnel spelled %q entered userspace_ingress_ifaces", tc.bindIface)
				}
			}
		})
	}
}

// TestSecureTunnelNonTunnelStNamesStayAdjudicated is the counterpart scope
// check: names that merely START with "st" are NOT secure tunnels and must keep
// being adjudicated. Without this, "scope the claim" could be satisfied by an
// over-broad prefix match that silently drops a real data interface out of the
// dataplane — a far worse failure than the gap being fixed.
func TestSecureTunnelNonTunnelStNamesStayAdjudicated(t *testing.T) {
	for _, name := range []string{"stx", "start0"} {
		t.Run(name, func(t *testing.T) {
			snap := InterfaceSnapshot{
				Name: name + ".0", LinuxName: name, Zone: "trust", Ifindex: 11,
			}
			if userspaceSkipsIngressInterface(snap) {
				t.Errorf("%q was excluded from the dataplane; only st<N> with a numeric N "+
					"is a secure tunnel, and over-matching silently drops a real data "+
					"interface out of adjudication", snap.Name)
			}
		})
	}
}

// TestSecureTunnelUnitReportsMTUAndAddresses covers the user-visible half of
// this change, which otherwise would ride along unasserted.
//
// Because the unit resolved to the nonexistent netdev `st0`, buildLinkSnapshot
// missed and the secure-tunnel unit reported MTU 0 and no live addresses in
// every snapshot consumer (status output, the CLI, the host-inbound view). With
// the name correct it reports what the kernel actually has.
func TestSecureTunnelUnitReportsMTUAndAddresses(t *testing.T) {
	prev := buildLinkSnapshot
	defer func() { buildLinkSnapshot = prev }()
	buildLinkSnapshot = func(name string) (int, int, string, []InterfaceAddressSnapshot) {
		if name == "st0.0" {
			return 42, 1400, "", []InterfaceAddressSnapshot{
				{Family: "inet", Address: "10.5.5.1/30"},
			}
		}
		return 0, 0, "", nil
	}

	cfg := compileForTest5619(t,
		"set security ipsec vpn myvpn bind-interface st0.0",
		"set interfaces st0 unit 0 family inet address 10.5.5.1/30",
		"set security zones security-zone vpn interfaces st0.0",
	)

	var found bool
	for _, s := range buildInterfaceSnapshots(cfg) {
		if s.Name != "st0.0" {
			continue
		}
		found = true
		if s.MTU != 1400 {
			t.Errorf("st0.0 MTU = %d, want 1400 — a secure-tunnel unit reported MTU 0 "+
				"because it resolved to the nonexistent netdev \"st0\"", s.MTU)
		}
		var live bool
		for _, addr := range s.Addresses {
			if addr.Address == "10.5.5.1/30" {
				live = true
			}
		}
		if !live {
			t.Errorf("st0.0 addresses = %v, want the live 10.5.5.1/30 — the unit reported "+
				"no live addresses because buildLinkSnapshot missed on \"st0\"", s.Addresses)
		}
	}
	if !found {
		t.Fatal("premise broken: no st0.0 unit in the snapshot")
	}
}
