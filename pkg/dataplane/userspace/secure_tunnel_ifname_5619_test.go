package userspace

import (
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
