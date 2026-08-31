package flowexport

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 11 / #7422 — the LIVE-PATH half of config.FlowServerExcludedReason.
//
// The show surfaces annotate an excluded flow-server "NOT INSTALLED", and that
// claim rests on a MECHANISM, not on the reserved userspace snapshot field:
// pkg/flowexport owns NetFlow/IPFIX export (#2130), and it cannot reach a
// collector whose port is absent or out of range. collectInstanceVersionCollectors
// omits the port from CollectorConfig.Address when Port <= 0, and dialCollectors
// then hands that bare address to net.Dial("udp", …), which fails with
// "missing port in address"; an out-of-range port fails the same call with
// "invalid port". Either way dialCollectors returns an error, which is fatal
// for the whole collector group.
//
// Writing that in a doc comment and not testing it is exactly the shape that
// makes a "NOT INSTALLED" annotation unfalsifiable. This cell pins the parse
// half of the mechanism (net.ResolveUDPAddr — the same address parser
// net.Dial uses, without opening a socket) against the SAME predicate the
// renderers consult, so the annotation and the runtime cannot drift.
func TestExcludedFlowServerYieldsAnUndialableCollectorAddress7422(t *testing.T) {
	for _, port := range []int{-1, 0, 1, 2055, 65535, 65536, 70000} {
		fs := &config.FlowServer{Address: "10.0.0.1", Port: port}
		inst := &config.SamplingInstance{
			Name:       "s1",
			InputRate:  100,
			FamilyInet: &config.SamplingFamily{FlowServers: []*config.FlowServer{fs}},
		}
		collectors, _, _ := collectInstanceVersionCollectors(
			inst, config.FlowServerVersion9, true, false)
		if len(collectors) != 1 {
			t.Fatalf("port %d: collectInstanceVersionCollectors returned %d "+
				"collectors, want 1 — the fixture no longer reaches the address "+
				"builder and every assertion below is over nothing",
				port, len(collectors))
		}

		_, resolveErr := net.ResolveUDPAddr("udp", collectors[0].Address)
		excluded := config.FlowServerExcludedReason(fs) != ""

		if excluded && resolveErr == nil {
			t.Errorf("port %d: the show surfaces annotate this collector NOT "+
				"INSTALLED, but %q parses as a usable UDP destination. The "+
				"annotation is now crying wolf on a collector that can receive "+
				"records.", port, collectors[0].Address)
		}
		if !excluded && resolveErr != nil {
			t.Errorf("port %d: the show surfaces render this collector as ACTIVE, "+
				"but %q does not resolve (%v). That is the #7422 defect in the "+
				"other direction — a lie the operator has no way to detect.",
				port, collectors[0].Address, resolveErr)
		}
		// Pin the port-0 error text the predicate's doc comment names. A
		// different failure mode would mean the documented mechanism is no
		// longer the one in force.
		if port == 0 && (resolveErr == nil || !strings.Contains(resolveErr.Error(), "missing port")) {
			t.Errorf("port 0: expected a `missing port in address` parse failure, got %v", resolveErr)
		}
	}
}
