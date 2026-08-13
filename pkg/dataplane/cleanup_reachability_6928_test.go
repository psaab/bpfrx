package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #6928: bind the CALL-GRAPH claim the stale-pin remediation makes.
//
// The remediation, and the two `types.go` notes beside it, told the operator
// what does and does not release a bpffs pin. That is a claim about which
// production entry points reach `dataplane.Cleanup()` — and it has now been
// wrong in both directions:
//
//   - before r5 it said "a reload" releases the pin. Nothing does that.
//   - r5 replaced it with "restarting xpfd does NOT release it" plus
//     "Cleanup() is reachable only from the `xpfd cleanup` subcommand". Also
//     false: `Manager.Teardown` calls `Cleanup()`, and
//     `daemon_run_shutdown.go` calls `Teardown` on every NON-hitless shutdown
//     ("HA shutdown: tearing down BPF state"). On that path the pins are gone
//     and a plain restart is sufficient.
//
// Both wrong versions carried a PASSING test, because the assertions were
// substring checks on the message. A phrase-presence assertion is satisfied
// identically by a correct and an incorrect instruction — it defends the text,
// not the behaviour, which is exactly how the replacement inherited the same
// blind spot as the thing it replaced.
//
// The claim is about the call graph, so the check is about the call graph. This
// test derives `Cleanup()`'s production callers from the source and fails when
// that set changes, forcing whoever changes it to re-read the operator-facing
// text that describes it. It is not a proxy for the message's correctness: it
// is the same kind of fact the message asserts.
//
// Deliberately NOT asserted here: the message's wording. Recording that the
// prose must contain some phrase is what produced two wrong-but-green rounds.
// stalepin_remediation_5363_test.go keeps only the NEGATIVE — that the
// disproven categorical claims are absent.

// cleanupCaller is one production call to dataplane.Cleanup(), identified by
// the package-relative file and the enclosing function.
type cleanupCaller struct {
	file string // repo-relative, slash-separated
	fn   string
}

func (c cleanupCaller) String() string { return c.file + ":" + c.fn }

// findCleanupCallers walks the repo for non-test calls to Cleanup(), matching
// both the in-package bare form (`Cleanup()`) and the qualified form any other
// package must use (`dataplane.Cleanup()`).
func findCleanupCallers(t *testing.T, root string) []cleanupCaller {
	t.Helper()
	var found []cleanupCaller
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			// Vendored / generated / build-output trees carry no production
			// call sites and would make this walk slow and noisy.
			case ".git", "vendor", "target", "node_modules", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file this package cannot parse is not silently skipped: it
			// could be the one holding a call site.
			t.Fatalf("parse %s: %v", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident: // in-package: Cleanup()
					if fun.Name == "Cleanup" {
						found = append(found, cleanupCaller{rel, fd.Name.Name})
					}
				case *ast.SelectorExpr: // cross-package: dataplane.Cleanup()
					pkg, ok := fun.X.(*ast.Ident)
					if ok && pkg.Name == "dataplane" && fun.Sel.Name == "Cleanup" {
						found = append(found, cleanupCaller{rel, fd.Name.Name})
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].String() < found[j].String() })
	return found
}

// TestCleanupProductionCallersMatchRemediation_6928 pins the production caller
// set of dataplane.Cleanup(). Adding or removing one changes whether a restart
// can clear a stale pin, which is precisely what the remediation and the
// types.go notes describe — so it must not change silently.
func TestCleanupProductionCallersMatchRemediation_6928(t *testing.T) {
	t.Parallel()

	// The package lives at <root>/pkg/dataplane.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	got := findCleanupCallers(t, root)

	// --- PRECONDITION: the walk found something. A walk that silently matched
	// nothing (wrong root, changed AST shape, over-eager SkipDir) would make
	// every assertion below pass vacuously — the same failure mode this test
	// exists to close one level up.
	if len(got) == 0 {
		t.Fatalf("found ZERO production callers of Cleanup() under %s; the walk is "+
			"broken, not the code — Cleanup() is called at least from "+
			"cmd/xpfd/main.go", root)
	}

	want := []string{
		"cmd/xpfd/main.go:main",            // the `xpfd cleanup` subcommand
		"pkg/dataplane/loader.go:Teardown", // non-hitless shutdown path
	}
	gotStr := make([]string, 0, len(got))
	for _, c := range got {
		gotStr = append(gotStr, c.String())
	}
	sort.Strings(want)

	if strings.Join(gotStr, "\n") != strings.Join(want, "\n") {
		t.Fatalf("production callers of Cleanup() changed.\n got:\n  %s\nwant:\n  %s\n\n"+
			"This set decides whether a restart can clear a stale bpffs pin, which is "+
			"what userspaceShimStalePinRemediation and the types.go:sessions notes "+
			"tell an operator mid-upgrade. Re-read BOTH before updating this list "+
			"(#6928).",
			strings.Join(gotStr, "\n  "), strings.Join(want, "\n  "))
	}

	// --- THE PROPERTY THE MESSAGE DEPENDS ON: more than one production caller
	// means "does a restart release the pin?" has no categorical answer. If
	// this ever collapses to the single CLI caller again, the mode-dependent
	// wording becomes wrong in the other direction and must be revisited.
	if len(got) < 2 {
		t.Fatalf("Cleanup() now has a single production caller (%v), so restart "+
			"behaviour IS categorical again — the mode-dependent remediation text "+
			"is now the inaccurate one and must be rewritten (#6928)", gotStr)
	}
}

// TestNonHitlessShutdownReachesTeardown_6928 is the other half of the claim:
// that the second caller is on the ordinary shutdown path rather than some
// decommission-only helper. Without this, `Teardown` could be dead code and the
// caller-set test above would still pass while the mode-dependent wording was
// describing a path nothing takes.
//
// Kept as a source assertion rather than a behavioural one deliberately:
// exercising it for real means calling Cleanup(), which does
// os.RemoveAll("/sys/fs/bpf/xpf") — destroying the pinned dataplane state of
// whatever machine runs the suite. That is not a test, and a test nobody dares
// run is not a guard.
func TestNonHitlessShutdownReachesTeardown_6928(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs(filepath.Join("..", "daemon", "daemon_run_shutdown.go"))
	if err != nil {
		t.Fatalf("resolve shutdown path: %v", err)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	body := string(src)

	// Both arms must be present: the hitless arm that PRESERVES the pins and
	// the non-hitless arm that tears them down. The remediation names both.
	for _, want := range []string{"d.dp.Close()", "d.dp.Teardown()"} {
		if !strings.Contains(body, want) {
			t.Fatalf("%s no longer calls %s. The stale-pin remediation says a hitless "+
				"shutdown preserves the pins and a non-hitless one releases them; if "+
				"one arm is gone that sentence is now false (#6928)",
				filepath.Base(path), want)
		}
	}
}
