package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// TestNoSchemaPathPanicsOnTheBlockForm_7568 is the census that justifies
// #7568 being a ONE-SITE fix rather than an audit.
//
// The panic came from `namedInstances` returning two node shapes while one
// caller read a fixed key index. That is a shape a reviewer cannot spot by
// eye — every `.node.Keys[...]` access looks equally plausible — so the claim
// "exactly one site is affected" has to be MEASURED, and re-measured whenever
// a caller is added.
//
// The walk emits the hierarchical block spelling `<path> { probeval; }` for
// EVERY path in setSchema, built from real parsed text, and compiles it under
// recover. A compiler that REJECTS the config is fine; one that PANICS is not,
// because the panic is reachable on the tolerated Store.Load / Store.SyncApply
// ingress where the schema gate is downgraded to a warning (#1960) — it
// crashes the daemon on load rather than refusing the config.
//
// This test is deliberately assumption-free about which nodes are "named
// instances". An earlier version of this probe keyed on `sn.wildcard != nil`,
// reached 12 containers, and reported ZERO panics over a defect that had
// already been reproduced by hand — `policy-options prefix-list` is declared
// `args:1, children:nil`, not a wildcard. A predicate that never reaches the
// subject produces a clean green, which is worse than no test at all. Walk
// everything.
func TestNoSchemaPathPanicsOnTheBlockForm_7568(t *testing.T) {
	var paths []string
	var walk func(nodes map[string]*schemaNode, path []string, depth int)
	walk = func(nodes map[string]*schemaNode, path []string, depth int) {
		if depth > 4 {
			return
		}
		keys := make([]string, 0, len(nodes))
		for k := range nodes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sn := nodes[k]
			// `groups` re-hosts the whole schema under an instance name; its
			// contents are reached on their own below, and walking it again
			// only doubles the runtime.
			if k == "groups" || k == "apply-groups" {
				continue
			}
			p := append(append([]string(nil), path...), k)
			paths = append(paths, strings.Join(p, " "))
			if sn.children != nil {
				walk(sn.children, p, depth+1)
			}
			if sn.wildcard != nil && sn.wildcard.children != nil {
				walk(sn.wildcard.children, append(append([]string(nil), p...), "xa1"), depth+1)
			}
		}
	}
	walk(setSchema.children, nil, 0)

	if len(paths) < 500 {
		t.Fatalf("the walk reached only %d schema paths; it is no longer covering "+
			"the schema and a clean result would mean nothing", len(paths))
	}

	var panicked []string
	for _, p := range paths {
		toks := strings.Fields(p)
		cfg := "probeval;"
		for i := len(toks) - 1; i >= 0; i-- {
			cfg = fmt.Sprintf("%s {\n%s\n}", toks[i], cfg)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = append(panicked, fmt.Sprintf("%s -> %v", p, r))
				}
			}()
			tree, perrs := NewParser(cfg).Parse()
			if len(perrs) > 0 {
				return
			}
			_, _ = CompileConfig(tree)
		}()
	}

	if len(panicked) > 0 {
		t.Fatalf("the compiler PANICS on the hierarchical block spelling at %d of %d "+
			"schema paths. A panic here crashes the daemon on the tolerated load path "+
			"(#1960), it does not reject the config:\n  %s",
			len(panicked), len(paths), strings.Join(panicked, "\n  "))
	}
	t.Logf("block-form probe: %d schema paths, 0 compiler panics", len(paths))
}
