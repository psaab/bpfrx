package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// #6959: an eBPF map Update whose error is DISCARDED inside a function that
// RETURNS error is the defect this issue is about — the caller (an operator's
// `clear ...`, a config commit) is told the write landed when the map
// rejected it. #6743 fixed two such loops; the census behind #6959 found 15
// more and fixed them. This guard exists so an 18th cannot appear silently.
//
// It is an AST scan, not a text grep, for two reasons:
//
//  1. A regex over the source can be satisfied by a DOC COMMENT that quotes
//     the pattern it looks for. The Go parser is invoked without
//     parser.ParseComments, so comments are not nodes here at all — a
//     comment CANNOT satisfy this gate by construction.
//  2. It must distinguish `zm.Update(...)` (discarded) from
//     `return zm.Update(...)` and `if err := zm.Update(...)` (propagated),
//     which is a statement-shape question a regex cannot answer.
//
// Both discard SPELLINGS are matched: the bare expression statement
// `zm.Update(...)` and the explicit blank assign `_ = zm.Update(...)`. Four
// of the 32 sites in the census used the second form, so a scan that only
// looked for the first would have missed one member of the defect class.

// discardedUpdateAllowlist is the exhaustive set of DELIBERATE discards
// inside error-returning functions. Each entry is a claim with a reason,
// and TestNoUndocumentedDiscardedMapUpdate asserts the reason is written at
// the site.
//
// The set is checked for EXACT equality, not containment. Removing a site
// from the source without removing it here also fails: "fixing" one of these
// would silently change a documented best-effort contract, so it must be a
// deliberate edit to this table.
var discardedUpdateAllowlist = map[string]string{
	"compiler.go:(*Manager).Compile": "redirect_capable is a per-interface optimisation HINT whose " +
		"unset default fails safe (XDP_PASS to the kernel forwarding path), and this is the " +
		"config-commit path, not an operator clear.",
	"maps_policy.go:(*Manager).UpdatePolicyScheduleState": "#3780: the function's documented contract " +
		"is that it ALWAYS reports success so the daemon's scheduler self-heal never spins on this " +
		"retired eBPF path, which pkg/dataplane/userspace shadows at runtime.",
}

// clearArrayEntriesBounds pins the sweep bound at every clearArrayEntriesIn
// call site. #6959 replaced ten hand-written `for i := 0; i < N; i++` loops
// with calls to one shared body; each expression below is BYTE-IDENTICAL to
// the bound its inline loop used at origin/master, so the conversion cannot
// have narrowed a sweep or pointed one at the wrong map's max_entries.
// Whitespace is normalised before comparison.
var clearArrayEntriesBounds = map[string]string{
	"app_ranges":        "MaxAppRanges",
	"zone_counters":     "128",
	"policer_configs":   "MaxPolicers",
	"filter_configs":    "MaxFilterConfigs",
	"screen_configs":    "64",
	"snat_rules":        "MaxZones*MaxZones*MaxSNATRulesPerPair",
	"snat_rules_v6":     "MaxZones*MaxZones*MaxSNATRulesPerPair",
	"nat_pool_configs":  "32",
	"nat64_configs":     "4",
	"nat_rule_counters": "MaxNATRuleCounters",
}

// errorReturningClearHelpers are the same-package helpers that exist ONLY to
// return a map-write error. Discarding one of THEM launders the defect right
// past a scan that only looks at .Update, so they are matched too.
var errorReturningClearHelpers = map[string]bool{
	"clearArrayEntriesIn":      true,
	"clearPolicyCountersIn":    true,
	"clearFilterCountersIn":    true,
	"clearInterfaceCountersIn": true,
}

type discardSite struct {
	key      string // "<file>:<func>"
	file     string
	line     int
	fn       string
	callee   string
	spelling string // "bare-expr" or "blank-assign"
	inErrFn  bool
}

type updateScan struct {
	totalUpdateCalls int // every .Update(...) call, discarded or not
	filesScanned     int
	discards         []discardSite
	boundsSeen       map[string]string // clearArrayEntriesIn map name -> bound expr
}

// scanDirsForDiscardedUpdates parses every non-test .go file under the given
// package directories and reports what it found. Comments are not parsed.
func scanDirsForDiscardedUpdates(t *testing.T, dirs []string) *updateScan {
	t.Helper()
	sc := &updateScan{boundsSeen: map[string]string{}}
	fset := token.NewFileSet()
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			// NOTE: no parser.ParseComments — comments are not nodes, so a
			// doc comment quoting `zm.Update(...)` cannot satisfy this gate.
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			sc.filesScanned++
			scanFile(sc, fset, f, filepath.Base(path))
		}
	}
	return sc
}

func scanFile(sc *updateScan, fset *token.FileSet, f *ast.File, base string) {
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			name = "(" + types.ExprString(fd.Recv.List[0].Type) + ")." + name
		}
		ast.Walk(&discardVisitor{sc: sc, fset: fset, base: base, fn: name, sig: fd.Type}, fd.Body)
	}
}

type discardVisitor struct {
	sc   *updateScan
	fset *token.FileSet
	base string
	fn   string
	sig  *ast.FuncType
}

func (v *discardVisitor) Visit(n ast.Node) ast.Visitor {
	switch t := n.(type) {
	case nil:
		return nil
	case *ast.FuncLit:
		// A closure has its OWN return signature; walk it separately so a
		// discard inside it is judged against the right one.
		ast.Walk(&discardVisitor{sc: v.sc, fset: v.fset, base: v.base, fn: v.fn + ".func", sig: t.Type}, t.Body)
		return nil
	case *ast.CallExpr:
		v.note(t)
	case *ast.ExprStmt:
		if ce, ok := t.X.(*ast.CallExpr); ok {
			v.record(ce, t.Pos(), "bare-expr")
		}
	case *ast.AssignStmt:
		if len(t.Rhs) != 1 || len(t.Lhs) == 0 {
			return v
		}
		for _, l := range t.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok || id.Name != "_" {
				return v
			}
		}
		if ce, ok := t.Rhs[0].(*ast.CallExpr); ok {
			v.record(ce, t.Pos(), "blank-assign")
		}
	}
	return v
}

// note counts every .Update call and every clearArrayEntriesIn bound,
// independent of whether the result is discarded. The count is the
// no-vacuous-sweep assertion: a walker that matched nothing would report
// zero here and fail loudly instead of passing clean.
func (v *discardVisitor) note(ce *ast.CallExpr) {
	if se, ok := ce.Fun.(*ast.SelectorExpr); ok && se.Sel.Name == "Update" {
		v.sc.totalUpdateCalls++
		return
	}
	id, ok := ce.Fun.(*ast.Ident)
	if !ok || id.Name != "clearArrayEntriesIn" || len(ce.Args) < 3 {
		return
	}
	lit, ok := ce.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	mapName := strings.Trim(lit.Value, `"`)
	v.sc.boundsSeen[mapName] = strings.ReplaceAll(types.ExprString(ce.Args[2]), " ", "")
}

func (v *discardVisitor) record(ce *ast.CallExpr, pos token.Pos, spelling string) {
	var callee string
	switch fn := ce.Fun.(type) {
	case *ast.SelectorExpr:
		if fn.Sel.Name != "Update" {
			return
		}
		callee = types.ExprString(fn.X) + ".Update"
	case *ast.Ident:
		if !errorReturningClearHelpers[fn.Name] {
			return
		}
		callee = fn.Name
	default:
		return
	}
	retsErr := false
	if v.sig != nil && v.sig.Results != nil {
		for _, r := range v.sig.Results.List {
			if types.ExprString(r.Type) == "error" {
				retsErr = true
			}
		}
	}
	v.sc.discards = append(v.sc.discards, discardSite{
		key:      v.base + ":" + v.fn,
		file:     v.base,
		line:     v.fset.Position(pos).Line,
		fn:       v.fn,
		callee:   callee,
		spelling: spelling,
		inErrFn:  retsErr,
	})
}

// TestNoUndocumentedDiscardedMapUpdate is the #6959 guard.
//
// Fail-on-revert: restore any of the 15 fixed sites to its blind-write form
// (for example put `zm.Update(i, empty, ebpf.UpdateAny)` back in
// ClearScreenConfigs) and this names the file, line and function.
//
// Over-reach: "fix" either allowlisted site and this fails too, because the
// allowlist is compared for EXACT equality — a documented best-effort
// contract cannot be changed by accident.
func TestNoUndocumentedDiscardedMapUpdate(t *testing.T) {
	t.Parallel()

	sc := scanDirsForDiscardedUpdates(t, []string{".", "userspace"})

	// Anti-vacuity: a broken walker sweeps nothing and passes clean. Assert
	// a NON-ZERO match count before believing any of the findings below.
	if sc.filesScanned < 20 {
		t.Fatalf("scanned only %d non-test .go files; the walker is not reaching the package", sc.filesScanned)
	}
	if sc.totalUpdateCalls == 0 {
		t.Fatal("the scan matched ZERO .Update(...) calls in pkg/dataplane; the pattern is broken, " +
			"so a clean result here means nothing was examined")
	}
	if len(sc.discards) == 0 {
		t.Fatal("the scan matched ZERO discarded calls, but the two allowlisted deliberate discards " +
			"must always be found; the discard-shape detection is broken")
	}

	got := map[string][]discardSite{}
	var noErrReturn []discardSite
	for _, d := range sc.discards {
		if d.inErrFn {
			got[d.key] = append(got[d.key], d)
		} else {
			noErrReturn = append(noErrReturn, d)
		}
	}

	for key, sites := range got {
		if _, ok := discardedUpdateAllowlist[key]; ok {
			continue
		}
		for _, s := range sites {
			t.Errorf("%s:%d %s discards the error from %s (%s) while RETURNING error.\n"+
				"  The caller is told the map write landed when the map rejected it — the #6959 defect.\n"+
				"  Propagate it (see clearArrayEntriesIn), or add %q to discardedUpdateAllowlist with a written reason.",
				s.file, s.line, s.fn, s.callee, s.spelling, key)
		}
	}
	for key := range discardedUpdateAllowlist {
		if _, ok := got[key]; !ok {
			t.Errorf("allowlisted deliberate discard %q is no longer present.\n"+
				"  If that was intentional, the site's documented best-effort contract changed and this\n"+
				"  entry must be removed deliberately: %s", key, discardedUpdateAllowlist[key])
		}
	}

	// The no-error-return class is a DIFFERENT disposition (there is nothing
	// to propagate to) and is deliberately not gated here. Reported so the
	// population stays visible; tracked separately.
	sort.Slice(noErrReturn, func(i, j int) bool {
		if noErrReturn[i].file != noErrReturn[j].file {
			return noErrReturn[i].file < noErrReturn[j].file
		}
		return noErrReturn[i].line < noErrReturn[j].line
	})
	var lines []string
	for _, s := range noErrReturn {
		lines = append(lines, fmt.Sprintf("  %s:%d %s (%s)", s.file, s.line, s.fn, s.spelling))
	}
	t.Logf("#6959 census: %d discarded map writes in functions with NO error return (not gated here):\n%s",
		len(noErrReturn), strings.Join(lines, "\n"))
}

// TestClearArrayEntriesInCallSitesKeepTheirBounds is the second over-reach
// guard: folding ten inline loops into one shared body must not have changed
// how far any of them sweeps. Each bound expression must still be exactly
// what its inline loop used at origin/master.
func TestClearArrayEntriesInCallSitesKeepTheirBounds(t *testing.T) {
	t.Parallel()

	sc := scanDirsForDiscardedUpdates(t, []string{".", "userspace"})

	if len(sc.boundsSeen) == 0 {
		t.Fatal("found ZERO clearArrayEntriesIn call sites; the scan is broken, so a clean result " +
			"here would certify nothing")
	}
	for name, want := range clearArrayEntriesBounds {
		got, ok := sc.boundsSeen[name]
		if !ok {
			t.Errorf("no clearArrayEntriesIn call site clears %q; the clear loop for that map was "+
				"removed or renamed, so its sweep is no longer bound", name)
			continue
		}
		if got != want {
			t.Errorf("clearArrayEntriesIn(%q) sweeps %s, want %s (the map's max_entries, byte-identical "+
				"to the inline loop bound at origin/master); a narrowed sweep leaves stale entries behind",
				name, got, want)
		}
	}
	for name := range sc.boundsSeen {
		if _, ok := clearArrayEntriesBounds[name]; !ok {
			t.Errorf("clearArrayEntriesIn(%q) is a new call site with no pinned bound; add it to "+
				"clearArrayEntriesBounds so its sweep cannot be narrowed silently", name)
		}
	}
}
