package config

import "testing"

// #7568: `policy-options { prefix-list { <name>; } }` parses cleanly and used
// to PANIC the compiler with "slice bounds out of range [2:1]".
//
// namedInstances returns TWO shapes. When the node carries its own name
// (Keys=["prefix-list", NAME, ...]) it returns that node, so Keys[2:] is the
// #6564 compact-leaf prefix tail. In the hierarchical block spelling it
// instead returns the SUB-node as the instance, whose Keys is just ["NAME"] —
// length 1 — and the unguarded Keys[2:] panicked.
//
// This mattered beyond "reject a bad config": the panic is reachable on the
// TOLERATED ingress. Store.compileTreeLenient (Store.Load / Store.SyncApply)
// deliberately downgrades a SchemaValidate failure to a warning so a config
// the operator did not just author cannot blackout-boot the node or alarm-loop
// HA config sync (#1960) — and then compiles it anyway, reaching the panic.
// A hand-edited persisted config, or one from a peer, crashed the daemon on
// load.
//
// Every test here builds the tree from PARSED TEXT. A hand-assembled Node
// could exhibit the shape without proving the parser ever produces it, which
// would make the whole regression vacuous.

// TestPrefixListBlockFormDoesNotPanic_7568 is the fail-on-revert proof.
func TestPrefixListBlockFormDoesNotPanic_7568(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{"bare-name", "policy-options {\n    prefix-list {\n        foo;\n    }\n}"},
		{"cidr-as-name", "policy-options {\n    prefix-list {\n        10.0.0.0/8;\n    }\n}"},
		{"named-with-prefixes", "policy-options {\n    prefix-list {\n        PL {\n            10.0.0.0/8;\n            192.168.0.0/16;\n        }\n    }\n}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, perrs := NewParser(tc.cfg).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			// A panic here fails the test by crashing the binary, which is the
			// point: this is the shape that used to do exactly that.
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("compile returned an error (a REJECTION is acceptable, "+
					"a panic is not — but this one should compile): %v", err)
			}
		})
	}
}

// TestPrefixListBlockFormCollectsPrefixes_7568 pins that the guard SKIPS the
// compact tail rather than skipping the whole instance: the block spelling's
// prefixes live in the node's children and must still be collected.
func TestPrefixListBlockFormCollectsPrefixes_7568(t *testing.T) {
	cfg := "policy-options {\n    prefix-list {\n        PL {\n            10.0.0.0/8;\n            192.168.0.0/16;\n        }\n    }\n}"
	tree, perrs := NewParser(cfg).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	compiled, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pl := compiled.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatalf("prefix-list PL was not compiled at all; lists=%v", compiled.PolicyOptions.PrefixLists)
	}
	want := map[string]bool{"10.0.0.0/8": true, "192.168.0.0/16": true}
	if len(pl.Prefixes) != len(want) {
		t.Fatalf("PL prefixes = %v, want the two authored entries", pl.Prefixes)
	}
	for _, p := range pl.Prefixes {
		if !want[p] {
			t.Fatalf("PL carries unexpected prefix %q (all: %v)", p, pl.Prefixes)
		}
	}
}

// TestPrefixListCompactLeafStillReadsTail_7568 is the necessary control. The
// fix adds `len(Keys) > 2` around the #6564 compact-leaf read, so it must be
// proven that the guard did not disable the very feature #6564 added — a
// guard that made the panic go away by skipping the tail on EVERY shape would
// pass every other test in this file.
func TestPrefixListCompactLeafStillReadsTail_7568(t *testing.T) {
	cfg := "policy-options {\n    prefix-list PL 10.0.0.0/8;\n}"
	tree, perrs := NewParser(cfg).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	compiled, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pl := compiled.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatal("compact-leaf prefix-list PL was not compiled")
	}
	if len(pl.Prefixes) != 1 || pl.Prefixes[0] != "10.0.0.0/8" {
		t.Fatalf("compact-leaf spelling lost its prefix tail: %v — the #6774/#7568 "+
			"length guard must skip the tail only for the 1-key block shape, "+
			"not for the compact leaf #6564 added", pl.Prefixes)
	}
}

// TestPrefixListBlockFormWithCompactLeafKeepsPrefix_7568 is the cell that
// rejects the OBVIOUS fix. A bare `len(inst.node.Keys) > 2` bounds check at
// the panic site stops the crash and passes every other test in this file —
// but this shape carries Keys=["PL","10.0.0.0/8"], length 2, so the bounds
// check SKIPS it and the list compiles NAMED BUT EMPTY. That is the #6564
// defect (a filter term scoped by a silently-empty prefix-list stops
// matching, on a config that committed clean) reintroduced in the other
// shape. The tail must be taken relative to the NAME, not to a fixed index.
func TestPrefixListBlockFormWithCompactLeafKeepsPrefix_7568(t *testing.T) {
	cfg := "policy-options {\n    prefix-list {\n        PL 10.0.0.0/8;\n    }\n}"
	tree, perrs := NewParser(cfg).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	compiled, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pl := compiled.PolicyOptions.PrefixLists["PL"]
	if pl == nil {
		t.Fatal("prefix-list PL was not compiled")
	}
	if len(pl.Prefixes) != 1 || pl.Prefixes[0] != "10.0.0.0/8" {
		t.Fatalf("PL prefixes = %v, want [10.0.0.0/8]: the block spelling's "+
			"compact value was dropped, so the list is NAMED BUT EMPTY and any "+
			"filter term scoped by it silently stops matching (#6564)", pl.Prefixes)
	}
}

// TestInstanceValueTailHandlesBothNamedInstanceShapes_7568 pins the helper
// directly, including the shapes that must yield nothing.
func TestInstanceValueTailHandlesBothNamedInstanceShapes_7568(t *testing.T) {
	cases := []struct {
		name string
		node *Node
		inst string
		want []string
	}{
		{"self-named-with-tail", &Node{Keys: []string{"prefix-list", "PL", "10.0.0.0/8"}}, "PL", []string{"10.0.0.0/8"}},
		{"self-named-no-tail", &Node{Keys: []string{"prefix-list", "PL"}}, "PL", nil},
		{"block-sub-with-tail", &Node{Keys: []string{"PL", "10.0.0.0/8"}}, "PL", []string{"10.0.0.0/8"}},
		{"block-sub-no-tail", &Node{Keys: []string{"PL"}}, "PL", nil},
		{"name-nowhere", &Node{Keys: []string{"prefix-list", "OTHER", "10.0.0.0/8"}}, "PL", nil},
		{"nil-node", nil, "PL", nil},
	}
	for _, tc := range cases {
		got := instanceValueTail(tc.node, tc.inst)
		if len(got) != len(tc.want) {
			t.Errorf("%s: tail = %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: tail = %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}
