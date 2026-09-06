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
// THE DIVERGENCE IS NOW FIXED and this cell asserts the set is EMPTY.
//
// It landed first as a known-bad ratchet pinning that one row, deliberately
// mutation-tested in BOTH directions -- and the mutant that APPLIED the fix
// was what proved the fix worked before it was written for real. The fix
// (resolveKernelIfNameWith: a ref naming a DECLARED interface takes the bare
// arm) then shrank the set to empty, which reddened the ratchet exactly as it
// was designed to, and the expectation moved rather than being loosened.
//
// A red here now means the two derivations have separated again: a tunnel's
// kernel device named one thing by routing and another by the dataplane, which
// is the orphan-device shape. The corpus KEEPS the collision case (a declared
// `gr-0/0/0.0` alongside a tunnel unit publishing that same TunnelNameMap key)
// because that is the row the fix exists for -- removing it would leave a
// green cell measuring nothing.
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
	if len(diverged) != 0 {
		t.Errorf("#8994: ResolveKernelIfName and snapshotLinuxName disagree on %d "+
			"declared interface(s):\n  %s\n\n"+
			"They must name the same kernel device for the same configured interface. "+
			"A ref that NAMES a declared interface takes the bare arm in "+
			"resolveKernelIfNameWith precisely so a dotted authored name is not re-read "+
			"as a unit ref and resolved onto some other device — reverting that arm "+
			"reproduces exactly this. The NOTE in pkg/config/types.go asks for these to "+
			"be kept in step and cannot detect it; this cell can.",
			len(diverged), strings.Join(diverged, "\n  "))
	}
}
