package config

// #5824: repeated hierarchical `policy-options policy-statement <name> { ... }`
// blocks are distinct AST instances. compilePolicyOptions used to build a FRESH
// PolicyStatement per instance and do an unconditional
// `po.PolicyStatements[name] = ps`, so a second same-name block silently
// REPLACED the first — its terms / route-filters / actions / default action
// vanished. Flat `set policy-options policy-statement <name> ...` lines compose
// under one node via SetPath, so hierarchical and flat diverged. Routing policy
// is ORDERED security/route-control state: a lost reject term over-exports /
// over-imports; a lost accept term withdraws reachability, while commit and FRR
// apply both look successful.
//
// The fix MERGES same-name blocks (reuse the map entry + a per-policy term index
// across instances), accumulating terms in first-authored ORDER and composing
// repeated fragments of the same term — matching flat-set semantics.
//
// FAIL-ON-REVERT: restoring the fresh-per-instance `po.PolicyStatements[name] =
// ps` overwrite makes the first block's terms disappear — every assertion below
// that the early term survives goes RED.

import (
	"testing"
)

// twoBlockHierarchical: block 1 defines term t1 (from static, route-filter,
// then reject); block 2 (SAME policy name) defines term t2 (from bgp, then
// accept) plus a policy-level default `then reject`.
const twoBlockHierarchical = `policy-options {
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
        then reject;
    }
}
`

func policyP(t *testing.T, cfg *Config) *PolicyStatement {
	t.Helper()
	ps := cfg.PolicyOptions.PolicyStatements["P"]
	if ps == nil {
		t.Fatalf("policy-statement P missing from compiled config")
	}
	return ps
}

func termNames(ps *PolicyStatement) []string {
	names := make([]string, 0, len(ps.Terms))
	for _, tm := range ps.Terms {
		names = append(names, tm.Name)
	}
	return names
}

// Acceptance 1 + 3: two hierarchical same-name blocks with DIFFERENT terms — the
// early block's reject term (t1, with its route-filter) AND the later block's
// accept term (t2) are BOTH present, in authored order.
func TestPolicyStatementHierarchicalBlocksMerge_5824(t *testing.T) {
	tree, err := NewParser(twoBlockHierarchical).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	ps := policyP(t, cfg)
	got := termNames(ps)
	if len(got) != 2 || got[0] != "t1" || got[1] != "t2" {
		t.Fatalf("merged policy must carry BOTH terms in authored order [t1 t2], got %v "+
			"(the early block's term was overwritten)", got)
	}
	// The early reject term must survive intact, with its route-filter.
	t1 := ps.Terms[0]
	if t1.Action != "reject" {
		t.Fatalf("early term t1 must keep Action=reject (a lost reject over-exports), got %q", t1.Action)
	}
	if len(t1.FromProtocols) != 1 || t1.FromProtocols[0] != "static" {
		t.Fatalf("early term t1 must keep from protocol static, got %v", t1.FromProtocols)
	}
	if len(t1.RouteFilters) != 1 || t1.RouteFilters[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("early term t1 must keep its route-filter, got %v", t1.RouteFilters)
	}
	// The later accept term is also present.
	if ps.Terms[1].Action != "accept" {
		t.Fatalf("later term t2 must be accept, got %q", ps.Terms[1].Action)
	}
	// The policy-level default from the later block composes in.
	if ps.DefaultAction != "reject" {
		t.Fatalf("policy default action from the later block must compose, got %q", ps.DefaultAction)
	}
}

// Acceptance 2: hierarchical and flat-set representations of the SAME policy
// compile to an identical PolicyStatement (term set, order, actions,
// route-filters, default action). Flat fixtures use ParseSetCommand + SetPath.
func TestPolicyStatementHierarchicalEqualsFlatSet_5824(t *testing.T) {
	hTree, err := NewParser(twoBlockHierarchical).Parse()
	if err != nil {
		t.Fatalf("parse hierarchical: %v", err)
	}
	hCfg, cerr := CompileConfig(hTree)
	if cerr != nil {
		t.Fatalf("compile hierarchical: %v", cerr)
	}

	fTree := buildFilterTree(t,
		"set policy-options policy-statement P term t1 from protocol static",
		"set policy-options policy-statement P term t1 from route-filter 10.0.0.0/8 orlonger",
		"set policy-options policy-statement P term t1 then reject",
		"set policy-options policy-statement P term t2 from protocol bgp",
		"set policy-options policy-statement P term t2 then accept",
		"set policy-options policy-statement P then reject",
	)
	fCfg, cerr2 := CompileConfig(fTree)
	if cerr2 != nil {
		t.Fatalf("compile flat: %v", cerr2)
	}

	h := policyP(t, hCfg)
	f := policyP(t, fCfg)
	if hn, fn := termNames(h), termNames(f); len(hn) != len(fn) || hn[0] != fn[0] || hn[1] != fn[1] {
		t.Fatalf("hierarchical vs flat term order diverged: %v vs %v", hn, fn)
	}
	if h.DefaultAction != f.DefaultAction {
		t.Fatalf("hierarchical vs flat default action diverged: %q vs %q", h.DefaultAction, f.DefaultAction)
	}
	for i := range h.Terms {
		ht, ft := h.Terms[i], f.Terms[i]
		if ht.Action != ft.Action {
			t.Fatalf("term %s action diverged: %q vs %q", ht.Name, ht.Action, ft.Action)
		}
		if len(ht.RouteFilters) != len(ft.RouteFilters) {
			t.Fatalf("term %s route-filter count diverged: %d vs %d", ht.Name, len(ht.RouteFilters), len(ft.RouteFilters))
		}
		if len(ht.FromProtocols) != len(ft.FromProtocols) {
			t.Fatalf("term %s from-protocol count diverged: %v vs %v", ht.Name, ht.FromProtocols, ft.FromProtocols)
		}
	}
}

// A repeated fragment of the SAME term across blocks composes onto one term
// (from-match in block 1, then-action in block 2) rather than creating a
// duplicate or dropping one fragment.
func TestPolicyStatementSameTermAcrossBlocksMerges_5824(t *testing.T) {
	const src = `policy-options {
    policy-statement Q {
        term shared {
            from {
                protocol static;
            }
        }
    }
    policy-statement Q {
        term shared {
            then reject;
        }
    }
}
`
	tree, err := NewParser(src).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	ps := cfg.PolicyOptions.PolicyStatements["Q"]
	if ps == nil || len(ps.Terms) != 1 {
		t.Fatalf("same-name term across blocks must compose to ONE term, got %v", termNames(ps))
	}
	shared := ps.Terms[0]
	if shared.Name != "shared" {
		t.Fatalf("merged term name = %q, want shared", shared.Name)
	}
	if len(shared.FromProtocols) != 1 || shared.FromProtocols[0] != "static" {
		t.Fatalf("block-1 from-match must survive, got %v", shared.FromProtocols)
	}
	if shared.Action != "reject" {
		t.Fatalf("block-2 then-action must compose onto the same term, got %q", shared.Action)
	}
}

// Acceptance 4: a single block is unchanged — one term, correct action.
func TestPolicyStatementSingleBlockUnchanged_5824(t *testing.T) {
	const src = `policy-options {
    policy-statement Solo {
        term only {
            from {
                protocol direct;
            }
            then accept;
        }
        then reject;
    }
}
`
	tree, err := NewParser(src).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	ps := cfg.PolicyOptions.PolicyStatements["Solo"]
	if ps == nil || len(ps.Terms) != 1 || ps.Terms[0].Name != "only" {
		t.Fatalf("single-block policy must have exactly one term 'only', got %v", termNames(ps))
	}
	if ps.Terms[0].Action != "accept" {
		t.Fatalf("single-block term action = %q, want accept", ps.Terms[0].Action)
	}
	if ps.DefaultAction != "reject" {
		t.Fatalf("single-block default action = %q, want reject", ps.DefaultAction)
	}
}

// twoRootHierarchical: TWO SEPARATE top-level `policy-options {}` roots (not two
// blocks in one root), each defining term x of policy-statement R — root 1 the
// from-match, root 2 the then-action. NewParser appends top-level nodes without
// merging, so compilePolicyOptions runs once PER root with a FRESH psTermIndex.
const twoRootHierarchical = `policy-options {
    policy-statement R {
        term x {
            from {
                protocol static;
            }
        }
    }
}
policy-options {
    policy-statement R {
        term x {
            then reject;
        }
    }
}
`

// Cross-root (#5824 fold): a same-name term across SEPARATE top-level
// policy-options roots must COMPOSE to ONE term, not duplicate. psTermIndex is
// local to each compilePolicyOptions call, so the second root gets a fresh empty
// index; without seeding it from the persisted ps.Terms, term x is appended a
// SECOND time (root-1's fragment on term#0, root-2's on term#1) — FRR then
// renders a malformed double `route-map R` sequence. It must be ONE composed
// term, and hierarchical must equal flat-set for this shape.
//
// FAIL-ON-REVERT: drop the `for _, t := range ps.Terms { termsByName[t.Name]=t }`
// seed and len(R.Terms)==2 (duplicate) — this test goes RED.
func TestPolicyStatementSameTermAcrossRootsMerges_5824(t *testing.T) {
	tree, err := NewParser(twoRootHierarchical).Parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("compile: %v", cerr)
	}
	ps := cfg.PolicyOptions.PolicyStatements["R"]
	if ps == nil {
		t.Fatal("policy-statement R missing from compiled config")
	}
	if len(ps.Terms) != 1 {
		t.Fatalf("a same-name term across SEPARATE top-level policy-options roots must compose "+
			"to ONE term, got %v (a duplicate renders a malformed double route-map) — #5824 cross-root",
			termNames(ps))
	}
	x := ps.Terms[0]
	if x.Name != "x" {
		t.Fatalf("merged term name = %q, want x", x.Name)
	}
	if len(x.FromProtocols) != 1 || x.FromProtocols[0] != "static" {
		t.Fatalf("root-1 from-match must survive the cross-root compose, got %v", x.FromProtocols)
	}
	if x.Action != "reject" {
		t.Fatalf("root-2 then-action must compose onto the SAME term, got %q", x.Action)
	}

	// Hierarchical (two roots) must equal flat-set (which already composes under
	// one node via SetPath) for this shape.
	fTree := buildFilterTree(t,
		"set policy-options policy-statement R term x from protocol static",
		"set policy-options policy-statement R term x then reject",
	)
	fCfg, ferr := CompileConfig(fTree)
	if ferr != nil {
		t.Fatalf("compile flat: %v", ferr)
	}
	fps := fCfg.PolicyOptions.PolicyStatements["R"]
	if fps == nil || len(fps.Terms) != 1 {
		t.Fatalf("flat-set baseline must be ONE term, got %v", termNames(fps))
	}
	if hn, fn := termNames(ps), termNames(fps); len(hn) != len(fn) || hn[0] != fn[0] {
		t.Fatalf("cross-root hierarchical vs flat term set diverged: %v vs %v", hn, fn)
	}
	if ps.Terms[0].Action != fps.Terms[0].Action ||
		len(ps.Terms[0].FromProtocols) != len(fps.Terms[0].FromProtocols) {
		t.Fatalf("cross-root hierarchical term diverged from flat: action %q vs %q, from %v vs %v",
			ps.Terms[0].Action, fps.Terms[0].Action, ps.Terms[0].FromProtocols, fps.Terms[0].FromProtocols)
	}
}
