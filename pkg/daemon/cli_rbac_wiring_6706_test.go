package daemon

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// loginClassWiring is one production call to applyCLILoginClass, with the
// question this file exists to ask already answered: is the identity it decides
// about the one the KERNEL reports?
type loginClassWiring struct {
	pos      string
	identity string // the third argument, rendered
	direct   bool   // ... and is it a bare osident.Current() call?
}

// applyCLILoginClassWiring returns every call to applyCLILoginClass in f.
//
// DIRECTNESS IS THE WHOLE PREDICATE, and it is deliberately strict: the third
// argument must be the call expression `osident.Current()` itself, written at
// the call site. A variable that happens to hold Current()'s result does not
// count, because a variable can be reassigned between the two lines and this
// analysis cannot see it — the same strictness
// pkg/cli's analyzeFuncClassWrite applies to the class argument, for the same
// reason. If a future refactor genuinely wants a local, it must move
// applyCLILoginClass's identity handling rather than widen this.
func applyCLILoginClassWiring(fset *token.FileSet, f *ast.File) []loginClassWiring {
	var out []loginClassWiring
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "applyCLILoginClass" {
			return true
		}
		w := loginClassWiring{pos: fset.Position(call.Pos()).String(), identity: "<no third argument>"}
		if len(call.Args) == 3 {
			w.identity = renderNode(fset, call.Args[2])
			w.direct = isOsidentCurrentCall(call.Args[2])
		}
		out = append(out, w)
		return true
	})
	return out
}

// isOsidentCurrentCall reports whether expr is exactly `osident.Current()`.
func isOsidentCurrentCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Current" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "osident"
}

func renderNode(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

// TestConsoleLoginClassIsWiredToOsidentCurrent_6706 binds the ONE production
// line that decides WHOSE identity the console's RBAC class is computed from.
//
// WHY IT EXISTS. Every other guard around #6701 sits either side of this line.
// pkg/osident's adoption canary requires pkg/daemon to CONTAIN an
// osident.Current() call — it says so itself, and says it cannot see which
// value reaches the decision. pkg/daemon's behavioural tests pin what
// applyCLILoginClass does with the Identity it is HANDED. Between them sits the
// argument at the call site, and it was bound by nothing: replacing
//
//	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
//
// with
//
//	_ = osident.Current() // decoy, kept only to satisfy the adoption canary
//	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Identity{UID: 0, Name: "root"})
//
// hands ClassRootDefault (super-user) to every console caller — #6701 restored
// in full — and gave `go build ./...` rc 0, `go vet ./...` rc 0 and
// `go test ./pkg/cli/... ./pkg/osident/... ./pkg/daemon/...` rc 0 (#6706 review
// r7 F4, reproduced firsthand before this test was written).
//
// The disclosure of that gap already existed, in pkg/osident's adoption canary.
// A reader of daemon_run.go got no signal from it; this test is in the package
// whose line it is about.
//
// SCOPE, stated rather than implied. It scans EVERY non-test .go file in this
// directory, ignoring build constraints. That is the fail-closed direction: a
// second, build-tagged wiring line must not be able to hide from it.
// applyCLILoginClass is package-private, so this directory is the complete set
// of places that can call it, and the scan is not a sample.
//
// FAIL-ON-REVERT: pass anything but a literal `osident.Current()` as the
// identity, or add a second call site, and this names the file, the line and
// the argument.
func TestConsoleLoginClassIsWiredToOsidentCurrent_6706(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var sites []loginClassWiring
	var filesScanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		filesScanned++
		sites = append(sites, applyCLILoginClassWiring(fset, f)...)
	}

	if len(sites) == 0 {
		t.Fatalf("no production call to applyCLILoginClass in %d files — either the console's "+
			"RBAC class is no longer wired at all, or this scan is not reaching the source it "+
			"claims to check", filesScanned)
	}
	if len(sites) != 1 {
		var where []string
		for _, s := range sites {
			where = append(where, s.pos)
		}
		sort.Strings(where)
		t.Errorf("applyCLILoginClass is called from %d places (%s) — the identity the console's "+
			"class is decided from must have ONE origin; a second site is a second policy",
			len(sites), strings.Join(where, ", "))
	}
	for _, s := range sites {
		if !s.direct {
			t.Errorf("%s: applyCLILoginClass receives identity %s, want a literal "+
				"`osident.Current()` — the RBAC class must be decided about the caller the "+
				"KERNEL reports, and a fabricated or indirect identity here restores #6701 "+
				"while every other test stays green", s.pos, s.identity)
		}
	}
}

// TestLoginClassWiringPredicateRejectsEveryFabrication_6706 proves the
// predicate above discriminates rather than merely matching the current source.
//
// It runs the REAL predicate over the shapes a rewrite of that line could take,
// including the exact decoy the review used, and requires exactly the correct
// one to be accepted.
func TestLoginClassWiringPredicateRejectsEveryFabrication_6706(t *testing.T) {
	const src = `package daemon

func correct(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Current())
}

func fabricatedLiteral(shell userClassSetter, d *Daemon) {
	_ = osident.Current()
	applyCLILoginClass(shell, d.store.ActiveConfig(), osident.Identity{UID: 0, Name: "root"})
}

func viaLocal(shell userClassSetter, d *Daemon) {
	id := osident.Current()
	id.Name = "root"
	applyCLILoginClass(shell, d.store.ActiveConfig(), id)
}

func wrapped(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), promote(osident.Current()))
}

func wrongPackage(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig(), shadow.Current())
}

func wrongArity(shell userClassSetter, d *Daemon) {
	applyCLILoginClass(shell, d.store.ActiveConfig())
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	got := applyCLILoginClassWiring(fset, f)
	if len(got) != 6 {
		t.Fatalf("predicate found %d call sites, want 6 — it is not seeing the calls it judges", len(got))
	}
	want := []struct {
		identity string
		direct   bool
		why      string
	}{
		{"osident.Current()", true, "the kernel credential, read at the call site"},
		{`osident.Identity{UID: 0, Name: "root"}`, false, "the review's decoy: super-user for everyone"},
		{"id", false, "a local that Current() seeded and a later line rewrote"},
		{"promote(osident.Current())", false, "Current()'s result, transformed"},
		{"shadow.Current()", false, "a same-named Current in another package"},
		{"<no third argument>", false, "not the identity-taking signature at all"},
	}
	for i, w := range want {
		if got[i].identity != w.identity || got[i].direct != w.direct {
			t.Errorf("call site %d: identity=%q direct=%v, want identity=%q direct=%v — %s",
				i, got[i].identity, got[i].direct, w.identity, w.direct, w.why)
		}
	}
}
