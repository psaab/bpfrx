package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #5824: end-to-end guard. A policy-statement defined across TWO hierarchical
// blocks must render BOTH terms into the FRR route-map. Before the compiler
// merge fix, the second same-name block REPLACED the first, so the early reject
// term (and its route-filter) never reached FRR — a valid but incomplete
// route-map that over-exports the routes the operator meant to block.
//
// FAIL-ON-REVERT: restoring the fresh-per-instance PolicyStatement overwrite in
// compilePolicyOptions drops term t1, so its `deny` sequence and the
// 10.0.0.0/8 route-filter prefix disappear from the rendered route-map.
func TestPolicyBlockMergeRendersEarlyRejectTerm_5824(t *testing.T) {
	const src = `policy-options {
    policy-statement P {
        term t1 {
            from {
                protocol static;
                route-filter 10.0.0.0/8 orlonger;
            }
            then reject;
        }
    }
    policy-statement P {
        term t2 {
            from {
                protocol bgp;
            }
            then accept;
        }
    }
}
`
	tree, perr := config.NewParser(src).Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, cerr := config.CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	m := New()
	got := m.generatePolicyOptions(&cfg.PolicyOptions)

	// The early block's reject term renders a `deny` sequence.
	if !strings.Contains(got, "route-map P deny") {
		t.Fatalf("early reject term dropped from the route-map (over-export):\n%s", got)
	}
	// ...matched by its route-filter prefix (rendered into a prefix-list entry).
	if !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("early term's route-filter prefix 10.0.0.0/8 missing from the route-map:\n%s", got)
	}
	// The later block's accept term is also present.
	if !strings.Contains(got, "route-map P permit") {
		t.Fatalf("later accept term missing from the route-map:\n%s", got)
	}
}
