package userspace

import (
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8994: pkg/config/types.go asks, in a NOTE, that ResolveKernelIfName,
// snapshotLinuxName and resolveJunosIfName be "kept in sync". A comment cannot
// detect drift. This measures whether they actually agree, and pins the one
// place they do not.
//
// WHAT THE MEASUREMENT FOUND, which is narrower than the NOTE implies:
//
//   - resolveJunosIfName is not a third derivation at all. It is literally
//     `config.LinuxIfName(cfg.ResolveReth(ifName))` -- an alias that cannot
//     drift from the expression it is.
//   - For TUNNEL units the other two are also one value: snapshotLinuxName
//     consults cfg.TunnelNameMap(), which is populated from unit.Tunnel.Name,
//     which is what routing keys on. #8995 was filed on that supposed
//     divergence and closed as refuted.
//   - They DO disagree in one reachable case, below.
//
// THE DIVERGENCE. ResolveKernelIfName picks its arm by splitting the ref on
// ".", so a ref that NAMES A DECLARED INTERFACE containing a dot is parsed as
// a unit ref instead. When a tunnel unit publishes a TunnelNameMap entry under
// that same string, the dotted arm consumes the TUNNEL's device and the two
// subsystems name one configured interface differently:
//
//	interface AUTHORED "gr-0/0/0.0"  +  gr-0/0/0 unit 0 carrying a tunnel
//	  ResolveKernelIfName("gr-0/0/0.0") -> "gr-0-0-0"     (the tunnel device)
//	  snapshotLinuxName(..., ifc, nil)  -> "gr-0-0-0.0"   (the interface itself)
//
// The config COMPILES, so an operator can author it.
//
// THIS CELL IS A KNOWN-BAD RATCHET, NOT A PASS. It pins the divergence set to
// exactly the collision case. It reds if the set GROWS (the drift the NOTE
// asks about, now detectable) and equally if it SHRINKS -- which would mean
// someone fixed it, and this cell plus #8994 should then be updated rather
// than the expectation loosened.
//
// The fix is NOT attempted here: ResolveKernelIfName has 15 non-test callers
// including daemon_ha_vip.go and daemon_cluster_bind.go, so changing its
// precedence is a staged change owing the cluster gate, not a drive-by.
func TestResolverAgreement8994(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, l := range []string{
		"set interfaces gr-0/0/0 unit 0 tunnel mode gre",
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
		"set interfaces ge-0/0/4 unit 0 family inet address 10.9.0.1/24",
		// Declared with a dot, NO colliding tunnel entry -- the control that
		// shows the dot alone is not what causes the divergence.
		"set interfaces ip-0/0/9.0 unit 0 family inet address 10.9.1.1/24",
		// Declared with a dot AND colliding with gr-0/0/0 unit 0's map entry.
		"set interfaces gr-0/0/0.0 unit 0 family inet address 10.9.2.1/24",
	} {
		path, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		tree.SetPath(path)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("corpus must COMPILE for this to be a reachable divergence: %v", err)
	}

	// Only refs that name a DECLARED interface are compared. Handing
	// snapshotLinuxName a nil iface makes it return LinuxIfName(ref) by its
	// first line, which manufactures a "divergence" the dataplane can never
	// produce -- it always iterates real (ifName, iface, unit) triples. An
	// earlier draft of this cell reported two such rows as findings.
	var diverged []string
	var compared int
	for ref, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		compared++
		viaConfig := cfg.ResolveKernelIfName(ref)
		viaDataplane := snapshotLinuxName(cfg, ref, ifc, nil)
		if viaConfig != viaDataplane {
			diverged = append(diverged, ref+": config="+viaConfig+" dataplane="+viaDataplane)
		}
	}
	sort.Strings(diverged)

	if compared < 4 {
		t.Fatalf("#8994: compared only %d declared interfaces, want >= 4 — the corpus "+
			"stopped compiling and this cell is measuring less than it claims", compared)
	}
	want := []string{"gr-0/0/0.0: config=gr-0-0-0 dataplane=gr-0-0-0.0"}
	if strings.Join(diverged, "\n") != strings.Join(want, "\n") {
		t.Errorf("#8994: the resolver divergence set CHANGED.\n got:\n  %s\nwant:\n  %s\n\n"+
			"GREW: ResolveKernelIfName and snapshotLinuxName have drifted further apart — "+
			"the NOTE in pkg/config/types.go asks for them to be kept in step and cannot "+
			"detect this. SHRANK: the dotted-ref precedence was fixed; update this cell "+
			"and #8994 rather than loosening the expectation.",
			strings.Join(diverged, "\n  "), strings.Join(want, "\n  "))
	}
}
