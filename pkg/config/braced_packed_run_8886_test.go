package config

import (
	"fmt"
	"testing"
)

// #8886: two statements packed onto ONE LINE inside an INTACT braced body were
// silently truncated — every statement after the first lost its value.
//
//	dead-peer-detection { interval 20 threshold 5; }
//	  -> interval=20 threshold=0
//
// THIS IS NOT THE BRACE-ELISION SHAPE. The container's brace is present and
// nothing is elided; the operator merely omitted a semicolon, which is the
// commonest typo there is, and `show configuration` renders it back exactly as
// written. The three tracked elision populations all require an operator to OMIT
// A CONTAINER'S BRACE, so none of them counts this.
//
// THE OPT-IN NOW GOVERNS BOTH SPELLINGS. Before this change `packedStatements`
// split a run packed onto the container's LINE and left the same run packed
// inside its BODY broken — so a container could be adjudicated "fixed" for one
// spelling of the identical mistake and remain silently lossy for the other.
// One flag, both shapes. A container that has not opted in is untouched, so the
// per-container remedy work is unchanged in scope.
//
// WHY THE SPLIT IS REACHABLE HERE AND WAS NOT IN #8880: here the CONTAINER is
// the node being visited, so its Children slice is in hand. There it was the
// PARENT's slice, which the walk does not hold, and the fold had to decline
// instead.
func TestBracedPackedRunIsSplit8886(t *testing.T) {
	const base = `security { ike { proposal pr { authentication-method pre-shared-keys; } ` +
		`policy pl { proposals pr; } gateway gw { ike-policy pl; address 192.0.2.1; ` +
		`external-interface ge-0/0/0; dead-peer-detection { %s } } } }`

	read := func(t *testing.T, body string) (interval, threshold int) {
		t.Helper()
		txt := fmt.Sprintf(base, body)
		tree, perrs := NewParser(txt).Parse()
		if len(perrs) > 0 {
			t.Fatalf("fixture must parse (%q): %v", body, perrs[0])
		}
		cfg, err := CompileConfigLenient(tree)
		if cfg == nil {
			t.Fatalf("fixture must compile (%q): %v", body, err)
		}
		for _, g := range cfg.Security.IPsec.Gateways {
			return g.DPDInterval, g.DPDThreshold
		}
		t.Fatalf("fixture produced no gateway (%q), so this cell measured nothing", body)
		return 0, 0
	}

	// LIVE CONTROL, fatal. The separated spelling must deliver BOTH values, or
	// the packed comparison below is against a broken fixture — and a fix that
	// broke the ordinary spelling would otherwise pass here.
	if i, th := read(t, `interval 20; threshold 5;`); i != 20 || th != 5 {
		t.Fatalf("braced-sep control delivered interval=%d threshold=%d, want 20/5 — "+
			"the packed assertion below would be measuring a broken fixture", i, th)
	}

	// Assert BOTH values by name. A count would not distinguish this from the
	// sibling INJECTION mode, which produces MORE members and would read as
	// success.
	i, th := read(t, `interval 20 threshold 5;`)
	if i != 20 {
		t.Errorf("packed run lost the FIRST statement's value: interval=%d, want 20", i)
	}
	if th != 5 {
		t.Errorf("packed run silently discarded the second statement: threshold=%d, "+
			"want 5. Two statements on one line inside an INTACT braced body — no "+
			"elision, just a missing semicolon — and every statement after the "+
			"first loses its value on a clean commit (#8886).", th)
	}
}

// A container that has NOT opted in must be unchanged by this: the per-container
// remedy work keeps its scope.
//
// WHAT THIS CELL CAN AND CANNOT SEE, stated because the answer is not obvious.
// The opt-in is enforced TWICE — once here in splitBracedPackedChildren8886 and
// again inside splitPackedStatements8768, which returns a single statement for a
// container that has not opted in. Removing EITHER gate alone leaves this cell
// GREEN; it reds only when BOTH go. Measured, not assumed.
//
// So this asserts the PROPERTY — an un-opted container is untouched — and not
// either gate. That is the right thing to assert, but a reader must not take a
// green here as evidence that a particular gate is present.
// #9235 RE-ANCHORED THE SUBJECT, and the distinction is worth stating because a
// careless read of this change looks like the gate being weakened.
//
// This cell used `security flow aging`, and #9235 taught compileFlow to expand
// that container's flat run — so `aging` started splitting a braced packed run
// WITHOUT opting into packedStatements and the cell reds. The cell's own
// `t.Skip` anticipated the container opting in and said to pick another one.
//
// It did not opt in, and that is the point: THERE ARE TWO SPLITTING MECHANISMS
// AND THIS OPT-IN GOVERNS ONLY ONE. `packedStatements` gates the schema-level
// brace-elision fold (splitBracedPackedChildren8886 / splitPackedStatements8768).
// A COMPILER READ that calls expandFlatRun / hoistAndSplitRun8939 splits a packed
// run on its own, by a keyword-delimited scan of the node's Keys, and has done
// since #8939 — measured on a container that has never opted in:
//
//	security { flow { tcp-session { closing-timeout 10 established-timeout 20; } } }
//	  -> closing=10 established=20      with packedStatements=false
//
// So `aging` was only ever a valid subject here because it was un-opted AND not
// reached by a compiler-read expansion, and #9235 removed the second property.
// The replacement needs BOTH, and `class-of-service schedulers <s>` has them:
// measured, `schedulers s1 { priority high buffer-size percent 20; }` keeps
// `priority` and DROPS the buffer-size, which is the #8886 shape this cell is
// about.
//
// A container that has NOT opted in must be unchanged by the FOLD. The assertion
// is the same; only the subject moved.
func TestBracedPackedUntouchedWithoutOptIn8886(t *testing.T) {
	sched := setSchema.children["class-of-service"].children["schedulers"]
	if sched == nil {
		t.Fatal("schema has no class-of-service/schedulers — this cell would prove nothing")
	}
	if sched.packedStatements {
		t.Skip("class-of-service schedulers has since opted in; pick another un-opted " +
			"container that no compiler read expands either (see the note above — being " +
			"un-opted is NOT sufficient)")
	}
	txt := `class-of-service { schedulers s1 { priority high buffer-size percent 20; } }`
	tree, perrs := NewParser(txt).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs[0])
	}
	cfg, err := CompileConfigLenient(tree)
	if cfg == nil {
		t.Fatalf("compile: %v", err)
	}
	s1 := cfg.ClassOfService.Schedulers["s1"]
	if s1 == nil {
		t.Fatal("scheduler s1 did not compile — the cell would prove nothing")
	}
	// POSITIVE CONTROL: the FIRST statement must land, or "the second did not"
	// is satisfied by a fixture that compiled nothing at all.
	if s1.Priority != "high" {
		t.Fatalf("POSITIVE CONTROL: the first statement of the packed run did not land "+
			"(priority=%q, want \"high\"); the assertion below would pass vacuously", s1.Priority)
	}
	if s1.BufferSizePercent != 0 {
		t.Errorf("an un-opted container split its packed run (buffer-size percent=%v). "+
			"The FOLD must stay gated on packedStatements: making it global "+
			"changes every container at once, which is the blanket change the "+
			"per-container opt-in exists to avoid (#8886).",
			s1.BufferSizePercent)
	}
}

// The tolerant ingress must accept everything it accepts today. Note it DOES
// schema-validate and downgrade to a warning, so the property is "no new
// REJECTION", not "no new validation".
func TestBracedPackedStillLoads8886(t *testing.T) {
	const base = `security { ike { proposal pr { authentication-method pre-shared-keys; } ` +
		`policy pl { proposals pr; } gateway gw { ike-policy pl; address 192.0.2.1; ` +
		`external-interface ge-0/0/0; dead-peer-detection { %s } } } }`
	for _, body := range []string{
		`interval 20 threshold 5;`,
		`interval 20; threshold 5;`,
		`interval 20;`,
	} {
		tree, perrs := NewParser(fmt.Sprintf(base, body)).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse (%q): %v", body, perrs[0])
		}
		if cfg, err := CompileConfigLenient(tree); err != nil || cfg == nil {
			t.Errorf("the tolerant ingress must still accept %q: %v — a config "+
				"already on disk must keep loading (#1960 no-brick)", body, err)
		}
	}
}
