package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestGeneratePolicyOptions_ASPathPrepend is a FAIL-ON-REVERT guard for the
// #2892 BGP `then as-path-prepend` action. A policy term carrying an ordered
// list of ASNs must render the FRR route-map clause `set as-path prepend <asn>
// <asn> ...` with every ASN preserved in order (the repeated ASN is the whole
// AS-path-prepend mechanism — it lengthens the advertised AS_PATH so peers
// prefer a shorter alternate path). Deleting the renderer turns this RED.
func TestGeneratePolicyOptions_ASPathPrepend(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"TE-PREPEND": {
				Name: "TE-PREPEND",
				Terms: []*config.PolicyTerm{
					{
						Name:          "t1",
						FromProtocols: []string{"bgp"},
						Action:        "accept",
						// Three repeats — order and repetition both matter.
						ASPathPrepend: []string{"65001", "65001", "65001"},
					},
				},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)

	want := " set as-path prepend 65001 65001 65001\n"
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in rendered route-map:\n%s", want, got)
	}
}

// TestGeneratePolicyOptions_ASPathPrependEmptyNoClause confirms a term WITHOUT
// any prepend ASNs emits no `set as-path prepend` clause (no churn / no empty
// clause that FRR would reject).
func TestGeneratePolicyOptions_ASPathPrependEmptyNoClause(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"NO-PREPEND": {
				Name:          "NO-PREPEND",
				Terms:         []*config.PolicyTerm{{Name: "t1", Action: "accept"}},
				DefaultAction: "reject",
			},
		},
	}

	got := m.generatePolicyOptions(po)
	if strings.Contains(got, "set as-path prepend") {
		t.Errorf("unexpected as-path prepend clause for a term with no ASNs:\n%s", got)
	}
}
