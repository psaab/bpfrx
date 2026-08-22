package frr

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6674 arm B — `routing-options forwarding-table export` is RATIFIED as
// accepting one policy, not a Junos policy chain, and this file records the
// measurement that decides it rather than the claim.
//
// The tempting argument for ratification was that a chain would be
// OBSERVATIONALLY IDENTICAL to taking the first policy, because resolveECMP
// only ever answers "is load-balancing on". That argument is FALSE, and this
// file exists partly to say so: composing a chain by OR-ing the flags gives a
// DIFFERENT answer than taking the first policy whenever the first carries no
// load-balance term and a later one does.
//
// The ratification therefore rests on a different and stronger reason. Junos
// evaluates an export chain PER ROUTE, stopping at the first terminating
// action, so:
//
//   - the cheap composition (OR across the chain) is not Junos — a route
//     accepted by the first policy never reaches the second, yet the OR would
//     apply the second's load-balance to it; and
//   - the faithful composition cannot be expressed, because the value being
//     derived is FRR's GLOBAL `maximum-paths`, which has no per-route form.
//
// A chain needs a per-route forwarding-policy model xpf does not have. That is
// a feature, not a defect in the multi-value read, which is why #6674 closes
// with the reject intact and the "follow-up coming" text removed from six
// source sites.

func policyWithLoadBalance6674(name, lb string) *config.PolicyStatement {
	return &config.PolicyStatement{
		Name:  name,
		Terms: []*config.PolicyTerm{{Name: "t1", LoadBalance: lb}},
	}
}

func resolveECMPFor6674(t *testing.T, selected string, policies ...*config.PolicyStatement) (int, bool) {
	t.Helper()
	byName := make(map[string]*config.PolicyStatement, len(policies))
	for _, p := range policies {
		byName[p.Name] = p
	}
	fc := &FullConfig{
		ForwardingTableExport: selected,
		PolicyOptions:         &config.PolicyOptionsConfig{PolicyStatements: byName},
	}
	return resolveECMP(fc), fc.ConsistentHash
}

// TestForwardingTableExportIsAGlobalToggleNotAChain_6674 measures what
// resolveECMP actually derives, and falsifies the equivalence that would have
// made ratification easy.
//
// Read the two halves together: the first pins that resolveECMP is a function
// of ONE named policy and nothing else, and the second pins that the OR
// composition and the first-policy reading DISAGREE — so "a chain is
// equivalent to its first member" is not available as an argument.
func TestForwardingTableExportIsAGlobalToggleNotAChain_6674(t *testing.T) {
	plain := policyWithLoadBalance6674("plain", "")
	perPacket := policyWithLoadBalance6674("lb", "per-packet")
	consistent := policyWithLoadBalance6674("ch", "consistent-hash")

	t.Run("derives two booleans from one named policy", func(t *testing.T) {
		if paths, ch := resolveECMPFor6674(t, "plain", plain, perPacket, consistent); paths != 0 || ch {
			t.Errorf("selecting a policy with no load-balance term: got maxPaths=%d consistentHash=%v, want 0/false "+
				"(the OTHER policies in the map must not contribute)", paths, ch)
		}
		if paths, ch := resolveECMPFor6674(t, "lb", plain, perPacket, consistent); paths != 64 || ch {
			t.Errorf("per-packet: got maxPaths=%d consistentHash=%v, want 64/false", paths, ch)
		}
		if paths, ch := resolveECMPFor6674(t, "ch", plain, perPacket, consistent); paths != 64 || !ch {
			t.Errorf("consistent-hash: got maxPaths=%d consistentHash=%v, want 64/true", paths, ch)
		}
	})

	t.Run("a chain is not equivalent to its first member", func(t *testing.T) {
		// The discriminating shape: first policy plain, second load-balancing.
		firstOnly, _ := resolveECMPFor6674(t, "plain", plain, perPacket)

		// The OR composition a naive chain implementation would produce.
		orComposed := 0
		for _, name := range []string{"plain", "lb"} {
			if paths, _ := resolveECMPFor6674(t, name, plain, perPacket); paths > orComposed {
				orComposed = paths
			}
		}

		if firstOnly == orComposed {
			t.Fatalf("the two readings AGREE on the discriminating input (%d) — "+
				"then the equivalence argument WOULD hold and this ratification "+
				"needs re-deciding, not this test relaxing", firstOnly)
		}
		t.Logf("measured: first-policy reading = %d, OR-composed chain = %d — "+
			"a chain is a semantic choice, not a no-op", firstOnly, orComposed)
	})

	t.Run("an unresolvable selection contributes nothing", func(t *testing.T) {
		// The reject gate lets an empty SELECTION through (`export [ "" p1 ]`),
		// and the renderer must then look nothing up rather than falling back to
		// some other policy in the map.
		if paths, ch := resolveECMPFor6674(t, "", plain, perPacket, consistent); paths != 0 || ch {
			t.Errorf("empty selection: got maxPaths=%d consistentHash=%v, want 0/false", paths, ch)
		}
		if paths, ch := resolveECMPFor6674(t, "not-defined", perPacket); paths != 0 || ch {
			t.Errorf("dangling selection: got maxPaths=%d consistentHash=%v, want 0/false", paths, ch)
		}
	})
}
