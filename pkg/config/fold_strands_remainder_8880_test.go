package config

import (
	"testing"
)

// #8880: a second from-zone/to-zone block was SILENTLY DISCARDED when the
// `policies` brace was elided.
//
//	security { policies { from-zone a to-zone b {…} from-zone c to-zone d {…} } }   2 zone pairs
//	security { policies   from-zone a to-zone b {…} from-zone c to-zone d {…}   }   1 zone pair
//
// Clean commit, zero warnings, on the product's primary enforcement surface.
//
// THE MECHANISM IS STRANDING, NOT A FAILURE TO SPLIT. The parser splits a run
// packed onto an elided container's line into SIBLINGS, and only the first
// carries the container keyword:
//
//	[policies from-zone a to-zone b]{…}      <- folds into `policies`
//	[from-zone c to-zone d]{…}               <- left behind
//
// The fold built `policies { from-zone a … }` and left the second block as a
// sibling — a `from-zone` node directly under `security`, a position the schema
// does not model, which the compiler then ignores without a word.
//
// `packedStatements: true` on `policies` is NOT the fix and was measured to do
// nothing: that flag governs splitting a packed TAIL, while this is a sequence
// of BRACED BODIES after an elided container brace. Different code path.
//
// THE FIX IS TO DECLINE. If the next sibling is a continuation of the container
// the fold would create, neither half is taken and the tree is left exactly as
// authored. Absorbing the sibling instead would mean rewriting the PARENT's
// child slice, which the walk does not hold.
//
// WHAT THIS CELL DOES AND DOES NOT CLOSE. It closes the STRANDING: the compiler
// never again sees a node in a position the schema cannot represent because of
// this fold. It does NOT make the packed spelling work, and it does not make it
// loud — an unknown child of `security` still commits clean, which is the
// separate gap tracked as the closed-world coverage issue. After this fix the
// packed form applies NOTHING rather than half, which is the honest outcome:
// half-applied security policy is the worse of the two.
func TestFoldDeclinesRatherThanStranding8880(t *testing.T) {
	const zones = `security { zones { security-zone a { } security-zone b { } security-zone c { } security-zone d { } } `
	const rule = `policy p { match { source-address any; destination-address any; application any; } then { permit; } }`

	braced := zones + `policies { from-zone a to-zone b { ` + rule + ` } from-zone c to-zone d { ` + rule + ` } } }`
	packed := zones + `policies from-zone a to-zone b { ` + rule + ` } from-zone c to-zone d { ` + rule + ` } }`

	pairs := func(t *testing.T, txt string) []string {
		t.Helper()
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse: %v", perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if cfg == nil {
			t.Fatalf("fixture must compile: %v", err)
		}
		out := make([]string, 0, len(cfg.Security.Policies))
		for _, zp := range cfg.Security.Policies {
			out = append(out, zp.FromZone+"->"+zp.ToZone)
		}
		return out
	}

	// LIVE CONTROL. The braced arm must deliver BOTH pairs, or the assertion
	// below is measuring a broken fixture rather than the fold.
	if got := pairs(t, braced); len(got) != 2 {
		t.Fatalf("braced control delivered %d zone pairs %v, want 2 — the packed "+
			"assertion below would be vacuous", len(got), got)
	}

	// THE DEFECT: exactly one pair survived, so one block was stranded and
	// discarded. Zero is the post-fix outcome (the fold declines); two would
	// mean the run was fully consumed. Anything equal to ONE means a block was
	// silently dropped, which is what #8880 is.
	got := pairs(t, packed)
	if len(got) == 1 {
		t.Errorf("packed spelling produced exactly ONE zone pair %v while the "+
			"braced spelling produces two. A from-zone/to-zone block was "+
			"STRANDED — folded neither into `policies` nor rejected — and the "+
			"compiler discarded it silently. Half-applied security policy is "+
			"worse than none: the fold must consume the whole run or decline "+
			"(#8880).", got)
	}
}

// The invariant the decline provides, pinned on the AST.
//
// It is NOT "no unmodelled child of `security`" — the authored tree legitimately
// has one, because the operator wrote a packed run the schema does not model in
// that position, and declining leaves it exactly as authored. That is the point
// of declining, and an assertion against it fails on the FIXED code, which is
// how this cell was first written.
//
// The invariant is narrower and is the thing stranding violates: the fold must
// never produce the CONTAINER while leaving a CONTINUATION of it outside. Either
// both or neither.
func TestFoldNeverPairsContainerWithOrphan8880(t *testing.T) {
	const zones = `security { zones { security-zone a { } security-zone b { } security-zone c { } security-zone d { } } `
	const rule = `policy p { match { source-address any; destination-address any; application any; } then { permit; } }`
	txt := zones + `policies from-zone a to-zone b { ` + rule + ` } from-zone c to-zone d { ` + rule + ` } }`

	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs[0])
	}
	normalizeCompactStanzas(tree)

	var secNode *Node
	for _, n := range tree.Children {
		if len(n.Keys) > 0 && n.Keys[0] == "security" {
			secNode = n
		}
	}
	if secNode == nil || len(secNode.Children) == 0 {
		t.Fatal("fixture produced no `security` children, so this cell measured nothing")
	}

	var haveContainer, haveOrphan bool
	sawZones := false
	for _, ch := range secNode.Children {
		if len(ch.Keys) == 0 {
			continue
		}
		switch ch.Keys[0] {
		case "policies":
			// A `policies` node with exactly the container key means the fold ran.
			if len(ch.Keys) == 1 {
				haveContainer = true
			}
		case "from-zone":
			haveOrphan = true
		case "zones":
			sawZones = true
		}
	}
	// LIVE CONTROL: `zones` must be present, or the scan found nothing and both
	// flags would be false for the wrong reason.
	if !sawZones {
		t.Fatal("`zones` not seen under security — the scan above proves nothing")
	}
	if haveContainer && haveOrphan {
		t.Errorf("the fold produced a `policies` container AND left a `from-zone` " +
			"sibling outside it. That sibling is a continuation of the same packed " +
			"run; the schema does not model `from-zone` under `security`, so the " +
			"compiler discards it silently and the zone-pair policy it carries is " +
			"lost. The fold must take the whole run or decline (#8880).")
	}
}
