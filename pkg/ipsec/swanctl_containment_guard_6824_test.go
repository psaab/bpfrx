package ipsec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// swanctl_containment_guard_6824_test.go -- #6824.
//
// Converting the existing assertions fixes the tests that exist today. It does
// nothing about the next one. This guard is the durable half: it fails when a
// test asserts SWANCTL SYNTAX with strings.Contains over a rendered document.
//
// # The predicate, and why it needs no allowlist
//
// The defect is not "containment is used" -- three leak guards in this package
// legitimately assert that a gateway NAME appears nowhere in the output, and
// containment is exactly the right tool for that claim. The defect is spelling
// swanctl's own syntax inside the needle: `"remote_addrs = 203.0.113.1"` or
// `"tun-bad {"`. A needle carrying " = " or ending in " {" is making a claim
// about the document's STRUCTURE while checking only its bytes, and structure
// is what the parser in swanctl_doc_6824_test.go can actually assert.
//
// That discriminator is the whole reason this guard carries no allowlist. An
// allowlist entry is a claim in its own right and owes a test; a predicate that
// separates the two cases on their own merits owes nothing.
//
// # What it does not see
//
// The needle must be a STRING LITERAL at the call site. A table-driven test
// whose expectations live in a struct column -- `strings.Contains(got, c.want)`
// -- is invisible to it, as is any needle built at runtime, and several of the
// assertions converted for #6824 were exactly those shapes.
//
// Measured rather than asserted: against the pre-conversion tree (de6b8c85d)
// this detector flags 76 sites; that tree contained 123 strings.Contains calls
// in pkg/ipsec test files in total, of which many are legitimate assertions on
// error strings and parsed fields rather than on rendered documents. So a clean
// run means "no literal syntax needle", NOT "no containment assertion anywhere",
// and this guard is a ratchet against the common case rather than a proof of the
// general one.
//
// An earlier version of this comment claimed the entire non-flagged remainder
// was table columns. That was wrong, and the way it was wrong is worth keeping:
// the detector was also missing plain literal needles that ended `" {\n"`
// rather than `" {"` -- four of them existed in the base tree -- so the number
// was describing the detector's blind spot as if it were a property of the code
// being measured.
//
// Resolving a table column back to its literals would need type-checked constant
// propagation, a much larger instrument than this defect warrants.

// containmentFinding is one flagged assertion.
type containmentFinding struct {
	file   string
	line   int
	needle string
}

// findSwanctlContainment reports strings.Contains calls whose first argument is
// a value produced by generateConfig/renderConfig and whose needle spells
// swanctl syntax.
//
// It is a free function over an *ast.File rather than a method on the test so
// the guard's own sensitivity control can drive it with synthetic source.
func findSwanctlContainment(fset *token.FileSet, f *ast.File) []containmentFinding {
	// Idents bound to a rendered document, tracked PER FUNCTION.
	//
	// A file-wide name set produces routine false positives: `got` is a common
	// name, and one test binding it to a render made every other function's
	// `strings.Contains(got, "load-all = yes")` -- a legitimate error-message
	// assertion -- a violation. A standing gate that flags unrelated work is
	// worse than one with a known blind spot, because the cost lands on someone
	// who did nothing wrong.
	rendered := map[string]bool{}
	// Render producers: the two render entry points, PLUS any function in this
	// file that returns one of them.
	//
	// `renderMust` is exactly that shape -- it wraps renderConfig and every
	// DHCP assertion went through it -- so an Ident-only match saw none of
	// them. A guard blind to the helper the tests actually use is blind to the
	// tests it is meant to guard.
	producers := map[string]bool{"generateConfig": true, "renderConfig": true}
	calleeName := func(e ast.Expr) string {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return ""
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			return fn.Sel.Name
		case *ast.Ident:
			return fn.Name
		}
		return ""
	}
	// Fixed point, so a helper wrapping a helper is also a producer.
	for changed := true; changed; {
		changed = false
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || producers[fn.Name.Name] {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ret, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range ret.Results {
					if producers[calleeName(r)] {
						producers[fn.Name.Name] = true
						changed = true
					}
				}
				return true
			})
		}
	}
	isRenderCall := func(e ast.Expr) bool { return producers[calleeName(e)] }
	noteAssign := func(lhs, rhs []ast.Expr) {
		for i, l := range lhs {
			id, ok := l.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			// `got, _, err := m.renderConfig(cfg)` binds the document to the
			// FIRST result; a multi-value call has one rhs expression.
			switch {
			case len(rhs) == len(lhs) && isRenderCall(rhs[i]):
				rendered[id.Name] = true
			case len(rhs) == 1 && i == 0 && isRenderCall(rhs[0]):
				rendered[id.Name] = true
			}
		}
	}
	collect := func(sc ast.Node) {
		ast.Inspect(sc, func(n ast.Node) bool {
			// Same rule as inspectCalls: a nested literal is its own scope, so
			// a binding made inside one must not leak to its SIBLINGS. Without
			// this, a render bound in one t.Run closure reached every other
			// closure in the same function and made their locals look rendered.
			if _, ok := n.(*ast.FuncLit); ok && n != sc {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				noteAssign(s.Lhs, s.Rhs)
			case *ast.ValueSpec:
				// `var got = m.generateConfig(cfg)` binds exactly as `:=` does
				// and was invisible while only AssignStmt was inspected.
				lhs := make([]ast.Expr, 0, len(s.Names))
				for _, id := range s.Names {
					lhs = append(lhs, id)
				}
				noteAssign(lhs, s.Values)
			}
			return true
		})
	}

	var out []containmentFinding
	inspectCalls := func(sc ast.Node) {
		ast.Inspect(sc, func(n ast.Node) bool {
			// Do NOT descend into a nested function literal: it is walked as its
			// own scope, and walking it twice reports every finding inside it
			// twice.
			if lit, ok := n.(*ast.FuncLit); ok && n != sc {
				_ = lit
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Contains" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
				return true
			}
			// The subject may be a bound identifier OR the render call inline --
			// `strings.Contains(m.generateConfig(cfg), "a = b")` is the same defect
			// and was missed by an Ident-only check.
			switch subj := call.Args[0].(type) {
			case *ast.Ident:
				if !rendered[subj.Name] {
					return true
				}
			case *ast.CallExpr:
				if !isRenderCall(subj) {
					return true
				}
			default:
				return true
			}
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			needle, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			// Trim before classifying: `"tun1-ts1 {\n"` and `"  good {\n"` are
			// section-opener needles that a bare HasSuffix(" {") misses, and four
			// such sites existed in the pre-conversion tree.
			trimmed := strings.TrimRight(needle, " \t\r\n")
			if !strings.Contains(needle, " = ") && !strings.HasSuffix(trimmed, "{") {
				// A bare token: a leak guard, not a structural claim.
				return true
			}
			out = append(out, containmentFinding{
				file:   filepath.Base(fset.Position(call.Pos()).Filename),
				line:   fset.Position(call.Pos()).Line,
				needle: needle,
			})
			return true
		})
	}

	// PACKAGE-LEVEL declarations first, and they persist across every scope
	// below: a file-level `var got = m.generateConfig(cfg)` is visible to every
	// function, so scoping it away made it invisible to the guard.
	pkgLevel := map[string]bool{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		rendered = map[string]bool{}
		collect(gd)
		for k := range rendered {
			pkgLevel[k] = true
		}
	}

	// Then one scope at a time. A scope is a FuncDecl or a function LITERAL --
	// sibling t.Run closures are separate scopes, so a rendered `got` in one
	// cannot make an unrelated error-message `got` in the next a false
	// positive. Nesting is handled by walking outward-in: an inner literal
	// starts from its enclosing scope's bindings, which is what Go's own
	// scoping does.
	var scope func(n ast.Node, outer map[string]bool)
	scope = func(n ast.Node, outer map[string]bool) {
		rendered = map[string]bool{}
		for k := range outer {
			rendered[k] = true
		}
		collect(n)
		here := map[string]bool{}
		for k := range rendered {
			here[k] = true
		}
		inspectCalls(n)

		ast.Inspect(n, func(m ast.Node) bool {
			lit, ok := m.(*ast.FuncLit)
			if !ok || m == n {
				return true
			}
			scope(lit, here)
			return false
		})
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		scope(fn, pkgLevel)
	}
	return out
}

// countRenderCalls counts actual generateConfig/renderConfig CALL expressions.
//
// The floor below used to grep the file text for "generateConfig(", which
// matched comments and string literals -- including this guard's own synthetic
// snippets, so the file counted itself. Ten empty test files and five comments
// satisfied both floors with no render call anywhere. Counting call nodes makes
// the floor measure the thing it claims to.
func countRenderCalls(f *ast.File) int {
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		case *ast.Ident:
			name = fn.Name
		}
		if name == "generateConfig" || name == "renderConfig" {
			n++
		}
		return true
	})
	return n
}

// TestNoSwanctlSyntaxInContainmentNeedles_6824 is the standing guard.
func TestNoSwanctlSyntaxInContainmentNeedles_6824(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	scanned, withRender := 0, 0
	var findings []containmentFinding
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		scanned++
		if countRenderCalls(f) > 0 {
			withRender++
		}
		findings = append(findings, findSwanctlContainment(fset, f)...)
	}

	// Anti-vacuity floors. A guard that scanned nothing, or that found no
	// rendered documents to guard, passes for the wrong reason and is
	// indistinguishable from a healthy one in a pass/fail table.
	if scanned < 10 {
		t.Fatalf("scanned only %d test files in pkg/ipsec; the guard is not "+
			"reaching the package it is meant to cover", scanned)
	}
	if withRender < 5 {
		t.Fatalf("only %d test files make a real render CALL; the guard has nothing "+
			"to guard and would pass whatever those files said", withRender)
	}

	for _, f := range findings {
		t.Errorf("%s:%d: strings.Contains on a rendered swanctl document with a "+
			"needle spelling swanctl syntax (%q).\n"+
			"\tA needle carrying \" = \" or ending in \" {\" claims something about the "+
			"document's STRUCTURE while checking only its bytes: it cannot say which "+
			"section the setting landed in, whether the key was declared twice, or "+
			"whether a brace balanced.\n"+
			"\tUse parseSwanctlDoc + at()/setting()/requireSetting()/hasNoSetting()/"+
			"hasNoChild() from swanctl_doc_6824_test.go instead. See #6824.",
			f.file, f.line, f.needle)
	}
}

// TestGuardSeesPackageLevelAndNestedScopes_6824 covers the three provenance
// cases a per-FuncDecl walk missed.
//
// Each is an ordinary shape in this package's tests, and each produced ZERO
// findings before: a render bound by a HELPER (renderMust wraps renderConfig,
// and every DHCP assertion went through it), a render bound at PACKAGE level,
// and a violation inside a t.Run CLOSURE.
func TestGuardSeesPackageLevelAndNestedScopes_6824(t *testing.T) {
	for _, c := range []struct {
		name string
		src  string
		want int
	}{
		{
			name: "package-level render binding",
			src: `package ipsec

import "strings"

var got = m.generateConfig(cfg)

func probe() {
	_ = strings.Contains(got, "remote_addrs = 1.1.1.1")
}
`,
			want: 1,
		},
		{
			name: "violation inside a closure, render bound outside it",
			src: `package ipsec

import "strings"

func probe(t *testing.T) {
	got := m.generateConfig(cfg)
	t.Run("x", func(t *testing.T) {
		_ = strings.Contains(got, "remote_addrs = 1.1.1.1")
	})
}
`,
			want: 1,
		},
		{
			name: "sibling closures do NOT collide",
			src: `package ipsec

import "strings"

func probe(t *testing.T) {
	t.Run("renders", func(t *testing.T) {
		got := m.generateConfig(cfg)
		_ = got
	})
	t.Run("asserts an error", func(t *testing.T) {
		got := doThing().Error()
		_ = strings.Contains(got, "load-all = yes")
	})
}
`,
			want: 0,
		},
		{
			name: "a violation is reported ONCE, not once per enclosing scope",
			src: `package ipsec

import "strings"

func probe(t *testing.T) {
	got := m.generateConfig(cfg)
	t.Run("a", func(t *testing.T) {
		t.Run("b", func(t *testing.T) {
			_ = strings.Contains(got, "remote_addrs = 1.1.1.1")
		})
	})
}
`,
			want: 1,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "probe_test.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			if got := findSwanctlContainment(fset, f); len(got) != c.want {
				t.Errorf("found %d finding(s), want %d: %+v", len(got), c.want, got)
			}
		})
	}
}

// TestGuardScopesRenderVariablesPerFunction_6824 is the false-POSITIVE control.
//
// The detector used to collect render-variable names file-wide, so one test
// binding the very common name `got` to a render made every other function's
// `strings.Contains(got, ...)` a violation -- including legitimate
// error-message assertions. A standing gate that flags unrelated work is worse
// than one with a known blind spot, because the cost lands on someone who did
// nothing wrong.
func TestGuardScopesRenderVariablesPerFunction_6824(t *testing.T) {
	src := `package ipsec

import "strings"

func rendersSomething() {
	got := m.generateConfig(cfg)
	_ = got
}

func assertsAnErrorMessage() {
	got := doThing().Error()
	_ = strings.Contains(got, "load-all = yes")
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "probe_test.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	if got := findSwanctlContainment(fset, f); len(got) != 0 {
		t.Errorf("flagged %d finding(s) in a file where the only syntax needle is an "+
			"error-message assertion in a DIFFERENT function: %+v", len(got), got)
	}
}

// TestContainmentGuardSensitivity_6824 is the paired control.
//
// The guard above passes today because the package is clean, which is exactly
// what a guard that can never fire also looks like. These cells drive the same
// detector over synthetic source and require it to flag the violations -- and,
// just as importantly, to leave the legitimate uses alone. Without the negative
// cells a detector that flagged EVERY strings.Contains would satisfy the
// positive ones and be useless in the other direction.
func TestContainmentGuardSensitivity_6824(t *testing.T) {
	cases := []struct {
		name string
		body string
		// extra is appended after the probe function, for a cell that needs a
		// helper DEFINED -- the producer fixed point can only recognise a
		// wrapper it can see.
		extra string
		want  int
	}{
		{
			name: "render produced by a HELPER that wraps renderConfig",
			body: `got := renderMust(cfg)
	_ = strings.Contains(got, "local_addrs = 1.1.1.1")`,
			extra: `
func renderMust(cfg *Config) string { return m.renderConfig(cfg) }
`,
			want: 1,
		},
		{
			name: "section opener needle with a trailing newline",
			body: `got := m.generateConfig(cfg)
	_ = strings.Contains(got, "tun1-ts1 {\n")`,
			want: 1,
		},
		{
			name: "var-declared render subject",
			body: `var got = m.generateConfig(cfg)
	_ = strings.Contains(got, "remote_addrs = 1.1.1.1")`,
			want: 1,
		},
		{
			name: "render call inline as the subject",
			body: `_ = strings.Contains(m.generateConfig(cfg), "remote_addrs = 1.1.1.1")`,
			want: 1,
		},
		{
			name: "setting needle on a render variable",
			body: `got := m.generateConfig(cfg)
	_ = strings.Contains(got, "remote_addrs = 203.0.113.1")`,
			want: 1,
		},
		{
			name: "section-opener needle on a render variable",
			body: `got := m.generateConfig(cfg)
	_ = strings.Contains(got, "tun-bad {")`,
			want: 1,
		},
		{
			name: "multi-value renderConfig binds the first result",
			body: `got, _, err := m.renderConfig(cfg)
	_ = err
	_ = strings.Contains(got, "encap = no")`,
			want: 1,
		},
		{
			name: "bare-token leak guard is NOT flagged",
			body: `got := m.generateConfig(cfg)
	_ = strings.Contains(got, "typo-gw")`,
			want: 0,
		},
		{
			name: "syntax needle on a NON-rendered value is NOT flagged",
			body: `err := doThing()
	_ = strings.Contains(err.Error(), "load-all = yes")`,
			want: 0,
		},
		{
			name: "two violations in one function are both reported",
			body: `got := m.generateConfig(cfg)
	_ = strings.Contains(got, "local_addrs = 1.1.1.1")
	_ = strings.Contains(got, "remote_addrs = 2.2.2.2")`,
			want: 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package ipsec\n\nimport \"strings\"\n\nfunc probe() {\n\t" + c.body + "\n}\n" + c.extra
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "probe_test.go", src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v\n%s", err, src)
			}
			got := findSwanctlContainment(fset, f)
			if len(got) != c.want {
				t.Errorf("detector found %d finding(s), want %d: %+v\n%s",
					len(got), c.want, got, src)
			}
		})
	}
}
