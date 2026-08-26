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
// -- is invisible to it, and several of the assertions converted for #6824 were
// exactly that shape. Run against the pre-conversion tree (de6b8c85d) this
// detector flagged 75 sites out of roughly 100; the rest were table columns.
// So a clean run means "no literal syntax needle", not "no containment
// assertion anywhere", and this guard is a ratchet against the common case
// rather than a proof of the general one. Resolving a table column back to its
// literals would need type-checked constant propagation, which is a much larger
// instrument than the defect warrants.

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
	// Idents bound to a rendered document. Tracked by name only: test bodies
	// are small and shadowing a render variable with a non-render one of the
	// same name inside one file would be perverse, and erring toward flagging
	// is the safe direction for a guard.
	rendered := map[string]bool{}
	isRenderCall := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		name := ""
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		case *ast.Ident:
			name = fn.Name
		}
		return name == "generateConfig" || name == "renderConfig"
	}
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
	ast.Inspect(f, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			noteAssign(s.Lhs, s.Rhs)
		}
		return true
	})

	var out []containmentFinding
	ast.Inspect(f, func(n ast.Node) bool {
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
		subject, ok := call.Args[0].(*ast.Ident)
		if !ok || !rendered[subject.Name] {
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
		if !strings.Contains(needle, " = ") && !strings.HasSuffix(needle, " {") {
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
	return out
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
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(src), "generateConfig(") || strings.Contains(string(src), "renderConfig(") {
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
		t.Fatalf("only %d test files render a swanctl document; the guard has "+
			"nothing to guard and would pass whatever those files said", withRender)
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
		want int
	}{
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
			src := "package ipsec\n\nimport \"strings\"\n\nfunc probe() {\n\t" + c.body + "\n}\n"
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
