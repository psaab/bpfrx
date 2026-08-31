package flowexport

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6565 row 11 / #7422 — the LIVE-PATH half of config.FlowServerExcludedReason,
// updated for #8163.
//
// The show surfaces annotate an excluded flow-server "NOT INSTALLED", and that
// claim rests on a MECHANISM. When this cell was written the mechanism was a
// dial failure: collectInstanceVersionCollectors carried the collector through
// with an address net.Dial could not parse, so the records never left. #8163
// replaced that with a stronger one — the collector is now dropped where the
// list is BUILT, so it never reaches a socket at all.
//
// The cell MOVES with the code rather than being loosened to fit. Asserting
// the old "the address does not resolve" property against the new code would
// have to first assert the collector still EXISTS, which is exactly what #8163
// removed; the honest successor asserts the stronger guarantee, in both
// directions, against the same shared predicate the renderers consult.
func TestExcludedFlowServerProducesNoCollector7422(t *testing.T) {
	for _, port := range []int{-1, 0, 1, 2055, 65535, 65536, 70000} {
		fs := &config.FlowServer{Address: "10.0.0.1", Port: port}
		inst := &config.SamplingInstance{
			Name:       "s1",
			InputRate:  100,
			FamilyInet: &config.SamplingFamily{FlowServers: []*config.FlowServer{fs}},
		}
		collectors, servesInet, _ := collectInstanceVersionCollectors(
			inst, config.FlowServerVersion9, true, false)
		excluded := config.FlowServerExcludedReason(fs) != ""

		if excluded && len(collectors) != 0 {
			t.Errorf("port %d: the show surfaces annotate this collector NOT "+
				"INSTALLED, but the exporter still built %v for it. One "+
				"undialable collector is fatal for its whole group, so this is "+
				"not merely a cosmetic disagreement.", port, collectors)
		}
		if !excluded && len(collectors) != 1 {
			t.Errorf("port %d: the show surfaces render this collector as "+
				"ACTIVE, but the exporter dropped it (%d collectors). That is "+
				"the #7422 defect in the other direction — a lie the operator "+
				"has no way to detect.", port, len(collectors))
		}

		// ServesInet must move with the collector. An instance left claiming
		// it serves inet while every inet collector was excluded would keep
		// consuming 1-in-N sampling slots for records it can never export.
		if excluded && servesInet {
			t.Errorf("port %d: instance still reports ServesInet with no "+
				"usable inet collector", port)
		}

		// The address the surviving collector carries must still be dialable —
		// otherwise the exclusion moved the problem rather than removing it.
		if !excluded && len(collectors) == 1 {
			if _, err := net.ResolveUDPAddr("udp", collectors[0].Address); err != nil {
				t.Errorf("port %d: an INSTALLED collector produced the "+
					"unresolvable address %q (%v)", port, collectors[0].Address, err)
			}
		}
	}

	// Non-vacuity: the loop agrees trivially if the builder returns nothing for
	// EVERY port, since most of the sample is excluded. Pin one positive.
	inst := &config.SamplingInstance{
		Name:       "s1",
		InputRate:  100,
		FamilyInet: &config.SamplingFamily{FlowServers: []*config.FlowServer{{Address: "10.0.0.1", Port: 2055}}},
	}
	if c, _, _ := collectInstanceVersionCollectors(inst, config.FlowServerVersion9, true, false); len(c) != 1 {
		t.Fatalf("the fixture produces no collector even for a healthy port; "+
			"every agreement above was between two empty answers (got %v)", c)
	}
}
