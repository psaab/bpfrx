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
