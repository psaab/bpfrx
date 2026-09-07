package diagcmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// #9143: AllLimiters is a REGISTRY, and a registry's failure mode is omission —
// silent, and invisible in exactly the direction that matters.
//
// The evidence that this is not hypothetical: before #9143 the list lived in
// pkg/api's metrics collector and named session_walk, remote_walk and
// diagnostic. SnapshotReadLimiter was added to limiter.go later and never
// reached it, so its refusals were exported as a permanent 0 — and #8312's
// stated purpose is that a 0 be trustworthy ("if these stay at 0 in the field
// the weighting changes nothing that can be observed"). An unregistered limiter
// is indistinguishable from one that never refuses, so the omission does not
// look like a bug; it looks like a healthy system.
//
// This asserts EXHAUSTIVENESS against the source of truth — the `var X =
// NewLimiter(...)` declarations in limiter.go — rather than against a second
// hand-maintained list, which would be the same drift one level up.
func TestAllLimitersIsExhaustive9143(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "limiter.go", nil, 0)
	if err != nil {
		t.Fatalf("parse limiter.go: %v", err)
	}

	declared := map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				call, ok := vs.Values[i].(*ast.CallExpr)
				if !ok {
					continue
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "NewLimiter" {
					declared[name.Name] = true
				}
			}
		}
	}

	// Positive control: the parse must actually find the limiters. Without
	// this, a parser that returned nothing would make the test vacuously pass
	// and report a clean registry for an empty one.
	if len(declared) < 4 {
		t.Fatalf("source scan found only %d `= NewLimiter(...)` vars (%v) — the scan is broken, "+
			"so its exhaustiveness verdict is meaningless", len(declared), declared)
	}
	for _, want := range []string{"DefaultLimiter", "SessionWalkLimiter", "SnapshotReadLimiter", "VtyshLimiter"} {
		if !declared[want] {
			t.Fatalf("source scan missed %s — the scan is broken", want)
		}
	}

	// Every registered entry must be non-nil and distinctly named.
	seenName := map[string]bool{}
	registered := map[*Limiter]string{}
	for _, nl := range AllLimiters() {
		if nl.Limiter == nil {
			t.Errorf("AllLimiters entry %q has a nil limiter", nl.Name)
			continue
		}
		if seenName[nl.Name] {
			t.Errorf("AllLimiters has a duplicate label %q — two limiters would collide on one metric series", nl.Name)
		}
		seenName[nl.Name] = true
		if prev, dup := registered[nl.Limiter]; dup {
			t.Errorf("AllLimiters registers the same *Limiter under both %q and %q", prev, nl.Name)
		}
		registered[nl.Limiter] = nl.Name
	}

	if got, want := len(AllLimiters()), len(declared); got != want {
		t.Fatalf("AllLimiters has %d entries but limiter.go declares %d limiters (%v) — "+
			"a limiter missing from the registry exports a permanent 0 refusal count, "+
			"which reads exactly like a limiter that never refuses (#9143)",
			got, want, declared)
	}
}
