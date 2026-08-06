package daemon

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #5275 PR2 — the mechanical half of the facade's coverage argument.
//
// The compile-time assertions in dataplane_facade_probes.go prove the facade
// satisfies the probes SOMEBODY REMEMBERED TO MIRROR. That is exactly the
// property that failed: the first cut of this PR mirrored the three assigned
// surfaces plus one probe, and silently dropped four capabilities reached by
// probes nobody had written down — deterministic source-NAT on three surfaces,
// the policy-scheduler state display on two, and cursor session paging on three.
// A hand-maintained list cannot fail for the thing it omits.
//
// This test re-derives the probe set from consumer SOURCE on every run: it
// parses pkg/api, pkg/cli and pkg/grpcapi, finds every `<recv>.dp.(T)` type
// assertion, resolves T (named or inline, embedded interfaces included) to a set
// of method names, and requires the facade to implement each one. A fifth
// omission — a NEW probe naming a method the facade lacks, or a method deleted
// from the facade while a probe still wants it — fails HERE rather than on an
// operator's next boot.
//
// LIMITS, stated so nobody over-reads the result:
//
//   - It recognises the spelling `X.dp.(T)`. A consumer that copies its handle
//     into a local and asserts the local, or that stores the dataplane under a
//     different field name, is invisible to it. Every probe in the tree today is
//     written the recognised way; the count assertions below are what make a
//     silent drop below that population a failure rather than a clean run.
//   - It checks method NAMES, not signatures. Signature agreement is proved
//     transitively instead — see the note on dataplane_facade_probes.go.
//   - It scans the three EXTERNAL consumer packages only. pkg/daemon's own
//     `d.dp.(...)` probes read the raw backend, not the facade, so they are not
//     in scope (and the backend satisfies everything by construction — see
//     `var _ facadeBackend` in dataplane_facade.go).

// consumerProbePackages are the packages that hold the facade. Keep in step
// with the construction sites asserted by TestEveryExternalConsumerHoldsTheFacade.
var consumerProbePackages = []string{"../api", "../cli", "../grpcapi"}

// persistentNATConsumerPackages are the packages that reach the persistent-NAT
// table through a handle that may be the facade. pkg/natshow is included and the
// probe list above is not the right set: natshow renders through its own Reader
// interface, which the facade satisfies, and it is the shared implementation
// behind BOTH the CLI and gRPC show surfaces.
var persistentNATConsumerPackages = []string{"../api", "../cli", "../grpcapi", "../natshow"}

// dataplaneHandleField is the field name every consumer stores its handle in.
const dataplaneHandleField = "dp"

type probeSite struct {
	pkg     string
	file    string
	line    int
	target  string // named interface, or "<inline>"
	methods []string
}

func TestFacadeCoversEveryConsumerProbe(t *testing.T) {
	facadeType := reflect.TypeOf((*dataplaneFacade)(nil))
	facadeMethods := map[string]bool{}
	for i := 0; i < facadeType.NumMethod(); i++ {
		facadeMethods[facadeType.Method(i).Name] = true
	}

	var sites []probeSite
	perPkg := map[string]int{}
	for _, dir := range consumerProbePackages {
		found := collectProbeSites(t, dir)
		perPkg[dir] = len(found)
		sites = append(sites, found...)
	}

	// Coverage: every method any probe reaches for must exist on the facade.
	// This is the assertion that would have caught the four lost capabilities.
	var missing []string
	for _, s := range sites {
		for _, m := range s.methods {
			if !facadeMethods[m] {
				missing = append(missing, fmt.Sprintf(
					"%s:%d asserts the dataplane handle to %s, which needs %s() — "+
						"*dataplaneFacade does not implement it, so this probe FAILS at runtime "+
						"and %s silently takes its degraded fallback branch (#5275)",
					s.file, s.line, s.target, m, s.pkg))
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("the facade narrows the dynamic type below what consumers probe for:\n  %s",
			strings.Join(missing, "\n  "))
	}

	// Population floors. A scan that stops recognising the probe shape would
	// otherwise pass over nothing and read as coverage. Bump these deliberately
	// when probes are genuinely added or removed.
	const wantSites = 27
	if len(sites) != wantSites {
		var detail []string
		for _, s := range sites {
			detail = append(detail, fmt.Sprintf("%s:%d -> %s", s.file, s.line, s.target))
		}
		sort.Strings(detail)
		t.Fatalf("found %d dataplane-handle probe sites, expected %d — if probes were genuinely "+
			"added or removed, update wantSites (and make sure the facade covers any new one); "+
			"if not, the scan has narrowed and is no longer proving coverage.\nfound:\n  %s",
			len(sites), wantSites, strings.Join(detail, "\n  "))
	}
	for dir, n := range perPkg {
		if n == 0 {
			t.Errorf("no probe sites found in %s — every external consumer package runs at least "+
				"one capability probe, so zero means the scan failed to read this package", dir)
		}
	}
}

// collectProbeSites parses one consumer package and returns every
// `<recv>.dp.(T)` assertion in it with T resolved to its method names.
func collectProbeSites(t *testing.T, dir string) []probeSite {
	t.Helper()

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("parsed no packages in %s — the scan is reading nothing", dir)
	}

	var sites []probeSite
	for pkgName, pkg := range pkgs {
		// Package-scope interface declarations, so a named probe target can be
		// resolved (and its embedded interfaces expanded) without type-checking.
		ifaces := map[string]*ast.InterfaceType{}
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if it, ok := ts.Type.(*ast.InterfaceType); ok {
					ifaces[ts.Name.Name] = it
				}
				return true
			})
		}

		for path, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				ta, ok := n.(*ast.TypeAssertExpr)
				if !ok || ta.Type == nil { // ta.Type == nil is a type SWITCH guard
					return true
				}
				sel, ok := ta.X.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != dataplaneHandleField {
					return true
				}
				pos := fset.Position(ta.Pos())
				target, methods := resolveProbeTarget(t, pkgName, filepath.Base(path), pos.Line, ta.Type, ifaces)
				sites = append(sites, probeSite{
					pkg:     pkgName,
					file:    filepath.Join(dir, filepath.Base(path)),
					line:    pos.Line,
					target:  target,
					methods: methods,
				})
				return true
			})
		}
	}
	return sites
}

// resolveProbeTarget turns a probe's asserted type into its method names. Both
// forms in the tree are handled: a package-private named interface, and an
// inline `interface{ ... }` literal. An unrecognised form is a FAILURE, not a
// skip — a probe the scan cannot read is a probe the scan is not covering, and
// that must not look like coverage.
func resolveProbeTarget(t *testing.T, pkg, file string, line int, expr ast.Expr, ifaces map[string]*ast.InterfaceType) (string, []string) {
	t.Helper()

	switch typ := expr.(type) {
	case *ast.InterfaceType:
		return "<inline>", interfaceMethodNames(t, pkg, file, line, typ, ifaces, nil)
	case *ast.Ident:
		it, ok := ifaces[typ.Name]
		if !ok {
			t.Fatalf("%s/%s:%d asserts the dataplane handle to %q, which is not a package-scope "+
				"interface in %s — the scan cannot resolve its method set, so it cannot prove "+
				"the facade covers it", pkg, file, line, typ.Name, pkg)
		}
		return typ.Name, interfaceMethodNames(t, pkg, file, line, it, ifaces, nil)
	default:
		t.Fatalf("%s/%s:%d asserts the dataplane handle to an unsupported type form (%T) — "+
			"teach the scan to read it rather than leaving this probe unproven", pkg, file, line, expr)
		return "", nil
	}
}

// interfaceMethodNames flattens an interface literal's method names, expanding
// embedded interfaces from the same package (cliUserspaceControlProvider embeds
// cliUserspaceStatusProvider; userspaceControlProvider embeds
// userspaceStatusProvider). seen breaks a cyclic embed rather than recursing
// forever.
func interfaceMethodNames(t *testing.T, pkg, file string, line int, it *ast.InterfaceType, ifaces map[string]*ast.InterfaceType, seen map[string]bool) []string {
	t.Helper()

	if seen == nil {
		seen = map[string]bool{}
	}
	var names []string
	for _, field := range it.Methods.List {
		if len(field.Names) > 0 { // a method
			for _, n := range field.Names {
				names = append(names, n.Name)
			}
			continue
		}
		// An embedded interface.
		id, ok := field.Type.(*ast.Ident)
		if !ok {
			t.Fatalf("%s/%s:%d embeds a non-local interface in a dataplane-handle probe — the "+
				"scan cannot expand it, so its methods would go unchecked", pkg, file, line)
		}
		if seen[id.Name] {
			continue
		}
		seen[id.Name] = true
		embedded, ok := ifaces[id.Name]
		if !ok {
			t.Fatalf("%s/%s:%d embeds %q, which is not a package-scope interface in %s — the "+
				"scan cannot expand it", pkg, file, line, id.Name, pkg)
		}
		names = append(names, interfaceMethodNames(t, pkg, file, line, embedded, ifaces, seen)...)
	}
	return names
}

// TestPersistentNATIsFetchedOncePerFunction pins the fetch-once discipline that
// keeps the facade's GetPersistentNAT from crashing the daemon (#5275).
//
// The hazard is specific and does not generalise from the other delegators. The
// backend's GetPersistentNAT is a plain field read that never transitions
// non-nil -> nil; the facade's gate does, the instant the dataplane is dropped.
// A consumer that calls the getter once to nil-check and again to dereference
// therefore has a window in which the second call returns nil — and
// PersistentNATTable.Len/Clear/All all take the table's mutex with no
// nil-receiver guard, so that dereference PANICS a handler goroutine, in a gRPC
// server that chains no panic-recovery interceptor.
//
// Fetching once and checking the fetched value removes the window rather than
// masking it. This scan enforces that shape mechanically, because the safe and
// unsafe versions look nearly identical in review and only the unsafe one is a
// crash. A function is allowed AT MOST ONE call: the count is per top-level
// function (nested closures included), so a closure that re-fetches inside a
// function that already fetched is a failure too — that is the same window.
//
// Deliberately NOT solved by nil-receiver guards on PersistentNATTable: a
// nil-receiver Clear() that silently succeeds would report "Cleared 0
// persistent NAT bindings" for a revoked dataplane, replacing a loud crash with
// a quiet lie to the operator.
//
// WHAT ESCAPES THIS SCAN. It matches a syntactic shape, so it is a blocklist,
// and a blocklist cannot be made complete. These get through today, and the
// escapes are NOT closed on purpose — chasing them would grow the pattern list
// while leaving the next unlisted form open, which is the failure mode this
// project keeps finding. Know them instead:
//
//   - HELPER EXTRACTION. `func (c *CLI) natTable() *T { return
//     c.dp.GetPersistentNAT() }` called twice leaves every FuncDecl at one direct
//     call, and wantCallers is unchanged because the helper replaces the site it
//     was extracted from. Green, window restored.
//   - FETCH IN THE CALLEE. The caller fetches and guards, then hands `dp` to a
//     helper that fetches again. Two functions, one call each.
//   - METHOD VALUE — the one to actually worry about, because an author reaches
//     for it innocently and it defeats the scan SILENTLY. `get :=
//     c.dp.GetPersistentNAT; t1 := get(); t2 := get()` is invisible: the scan
//     counts CallExpr whose Fun is a SelectorExpr, and a method value's call has
//     an Ident there. Both calls vanish, and in a new function the caller floor
//     is untouched too.
//   - A FIFTH CONSUMER PACKAGE. persistentNATConsumerPackages is a hardcoded
//     four; anything outside contributes zero to the floor and is never read.
//
// SO: this is a SUPPLEMENTARY belt, not the binding one. A green run here is not
// evidence the class is gone. The real binding is behavioural —
// TestFacadeRevocationMidCallDoesNotPanicTheClearPath and
// ...TheRenderPath drive real consumers with a real facade and land a revocation
// inside the window deterministically; they catch any of the escapes above that
// actually reaches a consumer entry point they exercise. This scan's job is
// narrower and still worth having: it makes the ONE form that keeps getting
// written by hand fail fast, at a glance, in every package at once.
func TestPersistentNATIsFetchedOncePerFunction(t *testing.T) {
	const getter = "GetPersistentNAT"

	type callSite struct {
		fn    string
		file  string
		count int
	}
	var offenders []callSite
	callers := 0

	for _, dir := range persistentNATConsumerPackages {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		if len(pkgs) == 0 {
			t.Fatalf("parsed no packages in %s — the scan is reading nothing", dir)
		}

		for _, pkg := range pkgs {
			for path, f := range pkg.Files {
				for _, decl := range f.Decls {
					fn, ok := decl.(*ast.FuncDecl)
					if !ok || fn.Body == nil {
						continue
					}
					n := 0
					ast.Inspect(fn.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok {
							return true
						}
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == getter {
							n++
						}
						return true
					})
					if n == 0 {
						continue
					}
					callers++
					if n > 1 {
						offenders = append(offenders, callSite{
							fn:    fn.Name.Name,
							file:  filepath.Join(dir, filepath.Base(path)),
							count: n,
						})
					}
				}
			}
		}
	}

	if len(offenders) > 0 {
		var detail []string
		for _, o := range offenders {
			detail = append(detail, fmt.Sprintf("%s: %s calls %s() %d times",
				o.file, o.fn, getter, o.count))
		}
		sort.Strings(detail)
		t.Fatalf("a consumer fetches the persistent-NAT table more than once in one function. "+
			"Through the revocable facade the later fetch can return nil when the earlier one "+
			"did not, and the table's mutex-taking methods have no nil-receiver guard — so this "+
			"is a daemon PANIC, not a redundancy. Fetch once into a local and check that "+
			"(#5275):\n  %s", strings.Join(detail, "\n  "))
	}

	// Floor: a scan that stops recognising the call shape would otherwise pass
	// over nothing and read as compliance. Bump deliberately when a consumer is
	// genuinely added or removed.
	const wantCallers = 4
	if callers != wantCallers {
		t.Fatalf("found %d functions calling %s(), expected %d — if a consumer was genuinely "+
			"added or removed, update wantCallers (and make sure the new one fetches ONCE); if "+
			"not, the scan has narrowed and is no longer proving anything", callers, getter, wantCallers)
	}
}
