package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
// SCOPE, measured rather than asserted (#6928). This pins WHO calls
// `Cleanup()`. It does NOT pin mode PLACEMENT — that a call sits in the
// non-hitless arm specifically, or that anything reaches it at all. That half
// is bound behaviourally, in
// `pkg/daemon/shutdown_dataplane_mode_6928_test.go`, which drives the real
// `runShutdownSequence` with a substituted `RuntimeDataPlane` and asserts both
// arms: non-hitless calls `Teardown` and not `Close`, hitless the reverse.
//
// A previous revision paired this with a SUBSTRING check that
// `daemon_run_shutdown.go` still contained the two call expressions, and
// described it as making the mode claim un-regressable. It did not, and this
// round measured both escapes rather than reasoning about them: inverting the
// condition to `if !hitless`, and replacing the call with
// `// d.dp.Teardown()`, each left that check GREEN (the second still builds).
// Both are RED against the behavioural test, so the substring companion was
// removed rather than re-labelled — it proved a strict subset of what its
// replacement proves.
//
// Deliberately NOT asserted here: the message's wording. Recording that the
// prose must contain some phrase is what produced two wrong-but-green rounds.
// stalepin_remediation_5363_test.go keeps only the NEGATIVE — that the
// disproven categorical claims are absent, which is a check on VOCABULARY and
// is labelled as such there; it cannot tell a true remediation from a false
// one that avoids those words.

// cleanupCaller is one production call to dataplane.Cleanup(), identified by
// the package-relative file and the enclosing function.
type cleanupCaller struct {
	file string // repo-relative, slash-separated
	fn   string
}

func (c cleanupCaller) String() string { return c.file + ":" + c.fn }

// dataplaneImportPath is the package whose Cleanup() this test tracks.
const dataplaneImportPath = "github.com/psaab/xpf/pkg/dataplane"

// dataplaneLocalName reports how `dataplaneImportPath` is bound in f:
// the empty string if f does not import it, "." for a dot-import (where
// `Cleanup()` is written bare), otherwise the qualifier — the alias when the
// import has one, else the package name.
//
// Resolving the IMPORT rather than assuming the spelling `dataplane.Cleanup`
// is what makes an aliased call site visible. The previous revision matched
// the literal qualifier `dataplane`, so `import dp "…/pkg/dataplane"` followed
// by `dp.Cleanup()` was a real production caller this walk silently missed —
// reproduced by adding exactly that file and watching the test stay green.
func dataplaneLocalName(f *ast.File) string {
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || path != dataplaneImportPath {
			continue
		}
		if spec.Name != nil {
			if spec.Name.Name == "_" {
				return "" // blank import: no callable binding
			}
			return spec.Name.Name // "." for a dot-import, else the alias
		}
		return "dataplane" // package name, no alias
	}
	return ""
}

// findCleanupCallers walks the repo for non-test calls to
// dataplane.Cleanup(), resolving the callee through each file's IMPORT
// bindings rather than through its spelling.
//
// Three forms count: the bare `Cleanup()` inside package dataplane itself;
// the bare form in a file that dot-imports the package; and `<q>.Cleanup()`
// where <q> is whatever local name that file bound the package to.
//
// Not resolved, because that needs full type information: a local identifier
// that SHADOWS the package name, and any indirect call (`f := dataplane.Cleanup;
// f()`). Both would need `go/types`; neither is reachable by accident, and the
// walk errs toward reporting rather than hiding.
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

		local := dataplaneLocalName(f)
		// A bare `Cleanup()` names THIS package's function only inside the
		// dataplane package itself, or in a file that dot-imported it. Counting
		// it anywhere else is how an unrelated `Cleanup()` in another package —
		// a perfectly ordinary name — was falsely reported as a caller, which
		// this round reproduced by adding one and watching the caller-set
		// comparison fail on a package that never touches the dataplane.
		bareIsOurs := local == "." ||
			(f.Name.Name == "dataplane" && strings.HasPrefix(rel, "pkg/dataplane/"))
		qualifier := ""
		if local != "" && local != "." {
			qualifier = local
		}
		if !bareIsOurs && qualifier == "" {
			return nil // this file cannot name dataplane.Cleanup at all
		}

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
				case *ast.Ident: // bare: Cleanup()
					if bareIsOurs && fun.Name == "Cleanup" {
						found = append(found, cleanupCaller{rel, fd.Name.Name})
					}
				case *ast.SelectorExpr: // qualified: <local>.Cleanup()
					pkg, ok := fun.X.(*ast.Ident)
					if ok && qualifier != "" && pkg.Name == qualifier && fun.Sel.Name == "Cleanup" {
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

	// --- DIAGNOSTIC, not a vacuity guard. Stating that precisely, because the
	// first version of this comment claimed the latter and was wrong (#6928
	// review): a walk that silently matched nothing (wrong root, changed AST
	// shape, over-eager SkipDir) does NOT pass vacuously. The comparison below
	// is against a NONEMPTY `want`, so an empty result already fails it, and
	// the >= 2 check fails too. What this arm buys is the right DIAGNOSIS —
	// "the walk is broken" instead of a zero-vs-two diff that reads as though
	// the production call sites had been deleted.
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

// The other half of the claim — that the second caller sits on the ORDINARY
// non-hitless shutdown path rather than a decommission-only helper — used to
// live here as a substring check over `pkg/daemon/daemon_run_shutdown.go`. It
// is now bound behaviourally by
// `TestShutdownModeChoosesCloseOrTeardown6928` in `pkg/daemon`, which observes
// which lifecycle method each arm actually calls. See the SCOPE note above for
// the two mutations that survived the substring form and are RED against the
// replacement.
//
// The reason the check could not simply be made behavioural HERE is worth
// recording: exercising it in `pkg/dataplane` means calling `Cleanup()` for
// real, which does `os.RemoveAll("/sys/fs/bpf/xpf")` and would destroy the
// pinned dataplane state of whatever machine runs the suite. Substituting the
// `RuntimeDataPlane` interface at the daemon's call site avoids that entirely:
// the fake records the call and touches no bpffs.
