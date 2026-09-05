package config

import (
	"sort"
	"strings"
	"testing"
)

// A `validator` on a leaf that is NOT a TYPED leaf never runs.
//
// walkSchemaNode gates on:
//
//	childSchema.isTypedLeaf() && (childSchema.validator != nil || childSchema.treeValidator != nil)
//
// and isTypedLeaf() is `valueType != ValueAny`. So a declaration carrying a
// validator with no valueType compiles, reads as correct, and is SILENTLY
// INERT -- the schema asserts a check that does not happen.
//
// This is a CLAIM defect before it is a behavioural one: even where nothing
// depends on the check, the declaration is a lie about what is enforced.
//
// THE CLASS IS CURRENTLY EMPTY, and that is the point of the ratchet rather
// than an argument against it. It cost a full diagnostic pass to find once:
// wiring `validator: ValidateDHGroup` onto the PFS `keys` leaf changed NOTHING
// (#8845) -- SchemaValidate still returned nil for `group99` and for
// `nonsense` -- and the only reason that surfaced was a positive control on a
// sibling leaf that carried the same validator and DID reject. The failure is
// silent and self-consistent; nothing about the declaration looks wrong.
type inertValidator struct {
	path string
	kind string
}

func inertValidators8852() (inert []inertValidator, armed int) {
	// seen keyed by PATH, not node: a node-keyed walk combined with a path
	// filter is non-deterministic under Go's randomised map order, and gives a
	// different count per run while looking stable within one.
	seen := map[string]bool{}
	var walk func(n *schemaNode, path string)
	walk = func(n *schemaNode, path string) {
		if n == nil || seen[path] || strings.Count(path, "/") > 14 {
			return
		}
		seen[path] = true
		for k, c := range n.children {
			// The groups/ mirror is the same nodes under another path; counting
			// it would double every hit.
			if c == nil || (path == "" && k == "groups") {
				continue
			}
			p := path + "/" + k
			if c.validator != nil || c.treeValidator != nil {
				if c.isTypedLeaf() {
					armed++
				} else {
					kind := "validator"
					if c.validator == nil {
						kind = "treeValidator"
					}
					inert = append(inert, inertValidator{p, kind})
				}
			}
			walk(c, p)
		}
		if n.wildcard != nil {
			walk(n.wildcard, path+"/<*>")
		}
	}
	walk(setSchema, "")
	sort.Slice(inert, func(i, j int) bool { return inert[i].path < inert[j].path })
	return
}

const inertBlindness8852 = "\n\nWHAT THIS CELL DOES NOT CHECK: it compares `validator`/`treeValidator` " +
	"against `isTypedLeaf()` and nothing else. It says NOTHING about a validator that " +
	"is armed but WRONG, one that is armed and never reached because its parent path " +
	"cannot compile, or a value rule enforced somewhere other than the schema -- " +
	"`chassis cluster redundancy-group` is gated at strict commit by #5694 with no " +
	"schema validator at all, so \"no validator\" has never meant \"unvalidated\". " +
	"GREEN HERE MEANS \"no declaration promises a check it cannot run\", never \"the " +
	"values are validated\"."

func TestNoInertValidators8852(t *testing.T) {
	inert, armed := inertValidators8852()

	// STABILITY: a census is a claim about the instrument before it is a claim
	// about the tree. Two runs, asserted equal.
	inert2, armed2 := inertValidators8852()
	if armed != armed2 || len(inert) != len(inert2) {
		t.Fatalf("census UNSTABLE across two runs: armed %d vs %d, inert %d vs %d. "+
			"A walk that disagrees with itself cannot support either number.",
			armed, armed2, len(inert), len(inert2))
	}

	// The instrument must be able to SEE something, or a zero is meaningless.
	if armed == 0 {
		t.Fatalf("zero ARMED validators found. The schema has hundreds; this walk " +
			"is not reaching them, and its zero-inert result would be a property of " +
			"the walk rather than of the tree.")
	}

	if len(inert) != 0 {
		var rows []string
		for _, iv := range inert {
			rows = append(rows, "  "+iv.path+"  ["+iv.kind+"]")
		}
		t.Errorf("%d INERT validator declaration(s) -- each promises a check that "+
			"NEVER RUNS:\n%s\n"+
			"walkSchemaNode requires isTypedLeaf() (valueType != ValueAny) BEFORE it "+
			"will call a validator, so these compile, read as correct, and do "+
			"nothing. Two fixes, and they are different: give the leaf a valueType "+
			"if the check is wanted, or DELETE the validator if it is not. Do not "+
			"assume the first -- a validator may have been added speculatively, and "+
			"arming it would newly REJECT values the tolerant Load path accepts "+
			"today.%s",
			len(inert), strings.Join(rows, "\n"), inertBlindness8852)
	}

	t.Logf("armed=%d inert=%d", armed, len(inert))
}

// TestInertValidatorRatchetControl8852 is what makes the zero mean anything.
//
// A NATURAL control was tried first and was worse than useless: running the
// census at the commit before #8845 also returned 0, which looks exactly like a
// broken walk. It was not -- at that commit the leaf carried no validator at
// all, because the inert state existed only in an uncommitted tree between two
// edits. The natural control was measuring a state that never existed.
//
// So the control is a SYNTHETIC injection, and both halves run: the census must
// find an injected inert validator at its exact path, and must return to zero
// when it is removed. Either half alone is satisfiable by a dead instrument --
// one by something that always reports, the other by something that never does.
func TestInertValidatorRatchetControl8852(t *testing.T) {
	// A leaf with no valueType, chosen because arming it would be wrong: the
	// encryption-algorithm vocabulary is not a DH group.
	victim := setSchema.children["security"].children["ike"].children["proposal"].children["encryption-algorithm"]
	if victim == nil {
		t.Fatal("control anchor `security ike proposal encryption-algorithm` not found -- re-derive this control, do not adjust it")
	}
	if victim.isTypedLeaf() {
		t.Fatalf("control anchor is now a TYPED leaf, so injecting a validator would " +
			"ARM it and the control would silently test nothing. Pick another " +
			"untyped anchor and say why here.")
	}
	if victim.validator != nil {
		t.Fatal("control anchor already carries a validator; the injection would not be observable")
	}

	const wantPath = "/security/ike/proposal/encryption-algorithm"
	victim.validator = ValidateDHGroup
	inert, _ := inertValidators8852()
	victim.validator = nil

	found := false
	for _, iv := range inert {
		if iv.path == wantPath {
			found = true
		}
	}
	if !found || len(inert) != 1 {
		t.Errorf("MUTATION SURVIVED: injecting a validator onto an untyped leaf did "+
			"not produce exactly one inert hit at %q (got %d: %v). The census is not "+
			"detecting the thing it claims to detect, so its zero is a number "+
			"generator.%s", wantPath, len(inert), inert, inertBlindness8852)
	}

	// And the restore must restore, or every later cell runs against a mutated
	// schema.
	after, _ := inertValidators8852()
	if len(after) != 0 {
		t.Fatalf("the control did NOT restore the schema: %d inert remain", len(after))
	}
}
