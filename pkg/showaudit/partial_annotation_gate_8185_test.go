package showaudit

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #8185: the #6534 census counts SURFACES, not samples.
//
// `reachesPredicate` returns true on the FIRST match, so a render function that
// applies the family's drop verdict to one output and emits another ungated is
// marked annotated, drops out of the `Unannotated` census, and is never
// re-examined. A partly-fixed surface reads as fixed, silently and permanently.
//
// The issue's own honest note is that full dominance analysis is materially
// harder and false-positives on renderers that are CORRECTLY partial —
// `natshow.RenderSourceRuleDetail` annotates pool-mode rules only, because
// interface-mode NAT has no pool to disarm.
//
// So this is the weaker-but-honest signal it asks for. Measured against the
// three instances the issue lists, they are not one class needing dataflow —
// they are TWO syntactic shapes, and both are cheap:
//
//	SHAPE B — the verdict is DISCARDED. `x, _ := config.SomeExcludedReason(...)`
//	  and the function consults the family predicate nowhere else, yet emits a
//	  live dataplane counter read. A fail-closed verdict assigned to `_` is the
//	  sharpest smell in the family and needs no dataflow at all.
//
//	SHAPE A — the verdict is BOUND and then IGNORED. The predicate's result is
//	  assigned to a named variable, and a counter read is emitted that no
//	  enclosing `if` condition mentions that variable.
//
// The counter-example escapes BOTH by construction rather than by an exemption
// entry: `RenderSourceRuleDetail` calls the verdict inline inside the branch
// that consumes it, so it never binds a live verdict and never discards one.
// A detector whose false-positive case is excluded structurally is a design;
// one that needs a list bolted on is a heuristic.

// WHAT THIS GATE DOES NOT CATCH, stated up front because a gate whose blind
// spot is undocumented gets trusted past its range.
//
// Shape A requires the counter read to sit in the SAME BLOCK as the verdict
// binding. A renderer that COLLECTS usage in one loop and RENDERS it, gated, in
// another is therefore invisible to it — and so is the same renderer with its
// gate removed. `showNATSourceSummary` is exactly that shape: it reads the
// counter at :255 while building its `pools` slice and gates the emit on
// `poolDisarm` at :327. Reverting that gate ESCAPES this detector, measured.
//
// The scope requirement is not an oversight; it is the price of not crying
// wolf. Without it the detector flags `showNATSourceSummary` in its CORRECT
// form, because the read and the (correct) gate live in different loops and no
// enclosing condition of the read mentions the verdict. A gate that reds on
// correct code gets loosened or ignored, and either outcome is worse than a
// documented blind spot.
//
// Closing that case needs the read's RESULT followed to its emit — real
// dataflow, which #8185 itself judges materially harder and out of scope for
// the weaker-but-honest signal it asks for. Two of the issue's three instances
// are covered (one by Shape A, one by Shape B); the third is this one.

// dataplaneCounterReads are the live-counter accessors whose result is a
// MEASUREMENT. Emitting one for an object the builder refused is the defect:
// the read succeeds (the id map contains disarmed objects) and returns a 0 the
// surface renders as measured.
var dataplaneCounterReads = []string{
	"ReadNATPortCounter",
	"NATPortCounter",
	"ReadNATRuleCounter",
	"ReadPolicyCounters",
	"ReadGlobalCounter",
}

// verdictBearingHelpers are pkg/config functions whose LAST return value IS a
// drop reason, even though their NAME does not match dropPredicateName.
//
// They are the reason Shape B needs a declared list rather than reusing the
// registry's predicates alone. `SourceNATPoolReportablePorts` returns
// `(int64, string)` and `nat_pool_capacity.go:73` returns the disarm reason on
// a refused pool — so `ports, _ := ...` throws away a fail-closed verdict while
// looking like an ordinary capacity call. #8185 names exactly this: the
// transitive reach through this helper is why one instance stayed in the
// surface census "by accident", and registering the helper as a SurfacePredicate
// would have dropped it from that census and taken the defect with it.
//
// Kept local to this gate rather than added to the shared registry for that
// reason: here the name makes a discard VISIBLE, whereas in `SurfacePredicates`
// the same name would make a renderer read as annotated.
var verdictBearingHelpers = []string{
	"SourceNATPoolReportablePorts",
	"SourceNATPoolReportableAddresses",
}

// verdictAssignments reports, for one function:
//   - bound: names of variables assigned a family-predicate result,
//   - discarded: whether at least one predicate call sent its reason to `_`,
//   - kept: whether at least one predicate call kept its result.
//
// `localWrappers` are same-package functions that RETURN a drop reason —
// `sourceNATPoolNotInstalled` wrapping `config.SourceNATPoolUnusableReason`, for
// instance. They must count, and leaving them out was a real hole: a mutation
// reverting the #8190 gate in showNATSourceSummary ESCAPED this detector,
// because that function binds its verdict from a wrapper rather than from
// `config.` directly. The repo has a whole file of such wrappers
// (pkg/cli/cli_show_nat_notinstalled_7473.go), so a detector that only sees
// qualified config calls is blind to the idiom the codebase actually uses.
func verdictAssignments(fd *ast.FuncDecl, preds, localWrappers []string) (bound []string, discarded, kept bool) {
	b, d, k, _ := verdictAssignmentsScoped(fd, preds, localWrappers)
	return b, d, k
}

// verdictAssignmentsScoped additionally returns, for each bound verdict, the
// span of the BLOCK it was bound in.
//
// Shape A must only consider a counter read that sits in the same block as the
// binding and after it. Without that it flags a renderer which COLLECTS usage
// in one loop and RENDERS it, correctly gated, in another — measured on
// showNATSourceSummary, which builds `p.used` in its collect loop at :255 and
// gates the emit on `poolDisarm` at :327. Two different loops, one correct
// function, and a scope-blind rule calls it a defect.
func verdictAssignmentsScoped(fd *ast.FuncDecl, preds, localWrappers []string) (bound []string, discarded, kept bool, spans [][2]token.Pos) {
	isPred := func(ce *ast.CallExpr) bool {
		switch fn := ce.Fun.(type) {
		case *ast.SelectorExpr:
			id, ok := fn.X.(*ast.Ident)
			if !ok || id.Name != "config" {
				return false
			}
			return contains(preds, fn.Sel.Name)
		case *ast.Ident:
			return contains(localWrappers, fn.Name)
		}
		return false
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		ce, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || !isPred(ce) {
			return true
		}
		// Only the LAST return carries the verdict. A `(count, reason)` helper
		// assigns the COUNT first, and treating that as the verdict was a real
		// bug in an earlier draft of this gate: it bound `ports` / `addrCount`
		// and then reported every counter read as "ungated" against a variable
		// that was never a verdict at all.
		lhs := as.Lhs[len(as.Lhs)-1]
		id, ok := lhs.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "_" {
			discarded = true
			return true
		}
		kept = true
		bound = append(bound, id.Name)
		spans = append(spans, enclosingBlockSpan(fd, as.Pos()))
		return true
	})
	return bound, discarded, kept, spans
}

// enclosingBlockSpan returns the innermost block containing pos.
func enclosingBlockSpan(fd *ast.FuncDecl, pos token.Pos) [2]token.Pos {
	best := [2]token.Pos{fd.Body.Lbrace, fd.Body.Rbrace}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		bs, ok := n.(*ast.BlockStmt)
		if !ok || bs.Lbrace > pos || bs.Rbrace < pos {
			return true
		}
		if bs.Lbrace >= best[0] {
			best = [2]token.Pos{bs.Lbrace, bs.Rbrace}
		}
		return true
	})
	return best
}

// counterReadsOutsideVerdictGuard returns the counter-read call sites in `fd`
// that no enclosing `if` condition gates on any of `verdictVars`.
func counterReadsOutsideVerdictGuard(fset *token.FileSet, fd *ast.FuncDecl, verdictVars []string) []string {
	var out []string
	var guards []string // conditions of the enclosing `if` chain

	mentionsVerdict := func() bool {
		for _, g := range guards {
			for _, v := range verdictVars {
				// Word-ish match: the variable must appear as its own token.
				for _, tok := range strings.FieldsFunc(g, func(r rune) bool {
					return !(r == '_' || r == '.' ||
						(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
				}) {
					if tok == v {
						return true
					}
				}
			}
		}
		return false
	}

	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		switch node := n.(type) {
		case *ast.IfStmt:
			guards = append(guards, exprString(fset, node.Cond))
			if node.Body != nil {
				for _, s := range node.Body.List {
					walk(s)
				}
			}
			guards = guards[:len(guards)-1]
			if node.Else != nil {
				walk(node.Else)
			}
			return
		case *ast.CallExpr:
			if se, ok := node.Fun.(*ast.SelectorExpr); ok &&
				contains(dataplaneCounterReads, se.Sel.Name) && !mentionsVerdict() {
				lbl := se.Sel.Name + " at " + fset.Position(node.Pos()).String()
				readPos[lbl] = node.Pos()
				out = append(out, lbl)
			}
		}
		// generic descent
		ast.Inspect(n, func(c ast.Node) bool {
			if c == n {
				return true
			}
			switch c.(type) {
			case *ast.IfStmt:
				walk(c)
				return false
			case *ast.CallExpr:
				walk(c)
				return false
			}
			return true
		})
	}
	for _, s := range fd.Body.List {
		walk(s)
	}
	return out
}

// partiallyAnnotatedExemptions records renderers this gate FLAGS that are known
// and deliberately not fixed here. Each entry names why and what closes it.
//
// It fails in BOTH directions (TestPartialAnnotationExemptionsAreLive_8185), so
// an entry whose renderer is fixed reds and must be deleted — the list cannot
// rot into permanent permission.
//
// Both current entries are REAL instances, adjudicated rather than waved
// through: each discards a fail-closed verdict and then emits live port usage
// for a pool the builder refused. Neither is fixed here because the fix is a
// STRUCTURED-SURFACE field (protobuf + JSON), which is the open #7473 work —
// fixing them here would collide with it. They are listed so this gate can
// merge in either order relative to that PR, and the liveness test deletes them
// the moment it lands.
var partiallyAnnotatedExemptions = map[string]string{
	// EMPTY, and it got here the right way. This list carried two entries
	// while #7473 was open — GetNATPoolStats and natPoolStatsHandler, both real
	// Shape B instances discarding a verdict and then emitting live port usage
	// for a refused pool. #7473 landed mid-review, the liveness test below
	// immediately red both entries as stale permission, and they were deleted.
	//
	// That is the list working: an exemption cannot outlive the defect it
	// excuses, because the gate fails in BOTH directions.
}

func TestNoPartiallyAnnotatedRenderer_8185(t *testing.T) {
	flagged := detectPartialAnnotations(t)
	sort.Strings(flagged)
	var unexcused []string
	for _, f := range flagged {
		key := strings.SplitN(f, "  [", 2)[0]
		if _, ok := partiallyAnnotatedExemptions[key]; !ok {
			unexcused = append(unexcused, f)
		}
	}
	if len(unexcused) > 0 {
		t.Errorf("%d renderer(s) apply a #6534 drop verdict to part of their output and emit a live "+
			"dataplane counter for the rest. The surface-level census marks these ANNOTATED, so they "+
			"drop out of it permanently and are never re-examined (#8185).\n  %s\n\n"+
			"Either gate the counter read on the verdict, or add the site to "+
			"partiallyAnnotatedExemptions with the reason it is correct.",
			len(unexcused), strings.Join(unexcused, "\n  "))
	}
}

// The exemption list fails in BOTH directions: an entry whose renderer no
// longer trips the detector is stale permission and must be deleted.
func TestPartialAnnotationExemptionsAreLive_8185(t *testing.T) {
	live := map[string]bool{}
	for _, f := range detectPartialAnnotations(t) {
		live[strings.SplitN(f, "  [", 2)[0]] = true
	}
	for site, why := range partiallyAnnotatedExemptions {
		if !live[site] {
			t.Errorf("partiallyAnnotatedExemptions still lists %s, but the detector no longer flags it.\n"+
				"Recorded reason: %s\nThe renderer was fixed (or moved) — delete the entry rather than "+
				"leaving standing permission for a defect that no longer exists.", site, why)
		}
	}
}

// detectPartialAnnotations runs ONE pass over the union of every family's
// predicates plus the verdict-bearing helpers.
//
// One pass, not one per family: a helper like SourceNATPoolReportablePorts is
// not owned by a family, and looping families attributed the same site to each
// of them in turn — nine duplicate findings, several with nonsense attribution
// ("binds the port-mirroring verdict as ports" for a NAT renderer).
func detectPartialAnnotations(t *testing.T) []string {
	t.Helper()
	var preds []string
	for _, f := range families {
		preds = append(preds, f.BuilderPredicates...)
		preds = append(preds, f.SurfacePredicates...)
	}
	preds = append(preds, verdictBearingHelpers...)

	var flagged []string
	for _, dir := range surfacePkgs {
		p := parsePackage(t, dir)
		wrappers := localVerdictWrappers(p, preds)
		for _, key := range p.order {
			rec := p.funcs[key]
			bound, discarded, kept, spans := verdictAssignmentsScoped(rec.fd, preds, wrappers)
			site := dir + "/" + filepath.Base(rec.file) + ":" + rec.fd.Name.Name

			// SHAPE B. Every direct consultation threw the verdict away — but
			// only flag when the function does not reach the verdict through a
			// SAME-PACKAGE helper either. showNATSourceSummary discards at one
			// call site and then consults sourceNATPoolNotInstalled (which
			// returns config.SourceNATPoolUnusableReason) where it actually
			// gates the emit, so it is correct and must not be flagged.
			if discarded && !kept && !callsLocalVerdictHelper(p, rec, preds) {
				if reads := counterReadsOutsideVerdictGuard(p.fset, rec.fd, nil); len(reads) > 0 {
					flagged = append(flagged, site+
						"  [shape B: discards a fail-closed verdict into `_`, then emits "+reads[0]+"]")
					continue
				}
			}
			// SHAPE A. The verdict is bound, and a counter read is emitted that
			// no enclosing condition gates on it.
			if len(bound) > 0 && !reportsVerdictAsData(rec.fd) {
				if reads := counterReadsOutsideVerdictGuard(p.fset, rec.fd, bound); len(reads) > 0 {
					if in := readsInAnyBindingScope(p.fset, reads, spans); len(in) > 0 {
						flagged = append(flagged, site+
							"  [shape A: binds the verdict as "+strings.Join(bound, "/")+
							" but emits "+in[0]+" ungated in the same block]")
					}
				}
			}
		}
	}
	return flagged
}

// callsLocalVerdictHelper reports whether `rec` reaches a family predicate
// through a same-package callee, i.e. by a path other than the discarded call.
func callsLocalVerdictHelper(p *parsedPkg, rec *fnRec, preds []string) bool {
	for _, callee := range calleeNames(rec.fd) {
		cr, ok := p.funcs[callee]
		if !ok {
			continue
		}
		for _, sym := range configCallsIn(p.fset, cr.fd) {
			if contains(preds, sym) || dropPredicateName.MatchString(sym) {
				return true
			}
		}
	}
	return false
}

// reportsVerdictAsData reports whether the function COMMUNICATES the verdict in
// its output rather than suppressing the sample.
//
// Suppression is not the only correct answer, and assuming it was produced a
// false positive the moment #7473 merged: `natRuleStatsHandler` emits
// `HitPackets` from a live counter read AND sets `NotInstalled` /
// `NotInstalledReason` on the same response object. A consumer can tell the
// sample is not authoritative, which is exactly what that wire field is for —
// the structured surfaces cannot append a "NOT INSTALLED" line, so declaring it
// as data IS their annotation.
//
// So a renderer that assigns the verdict into a not-installed output field is
// annotated for this gate's purposes, however its counter read is guarded.
func reportsVerdictAsData(fd *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			se, ok := lhs.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if verdictFieldName.MatchString(se.Sel.Name) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// verdictFieldName matches the output-field family the structured surfaces use
// to carry a drop verdict as data.
var verdictFieldName = regexp.MustCompile(`NotInstalled|Unavailable|Unusable|Disarmed`)

// localVerdictWrappers are the same-package functions whose body reaches a
// family drop predicate and which therefore RETURN a verdict. Binding one is
// binding the verdict, exactly as a direct `config.` call would be.
// A wrapper must RETURN the predicate's result directly — `return
// config.SourceNATPoolUnusableReason(pool)`. Merely CALLING a predicate is not
// enough and was a real false positive: `natNotInstalledLine(reason, expand)`
// takes a reason as INPUT and returns a display line, calling
// config.SourceNATDisarmReasonText on the way. Treating it as verdict-bearing
// made every `line := natNotInstalledLine(...)` look like a bound verdict, and
// flagged showNATSourceRuleSet for emitting a counter near a display string.
func localVerdictWrappers(p *parsedPkg, preds []string) []string {
	var out []string
	for _, key := range p.order {
		fd := p.funcs[key].fd
		found := false
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			rs, ok := n.(*ast.ReturnStmt)
			if !ok || len(rs.Results) != 1 {
				return true
			}
			ce, ok := rs.Results[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			se, ok := ce.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := se.X.(*ast.Ident); ok && id.Name == "config" &&
				(contains(preds, se.Sel.Name) || dropPredicateName.MatchString(se.Sel.Name)) {
				found = true
				return false
			}
			return true
		})
		if found {
			out = append(out, fd.Name.Name)
		}
	}
	return out
}

// readsInAnyBindingScope keeps only the counter reads that sit inside one of
// the blocks a verdict was bound in. A read in a DIFFERENT block is collected
// elsewhere and may be gated at its own emit site, which is not something this
// gate can see and not something it should guess at.
func readsInAnyBindingScope(fset *token.FileSet, reads []string, spans [][2]token.Pos) []string {
	var out []string
	for _, r := range reads {
		pos, ok := readPos[r]
		if !ok {
			continue
		}
		for _, sp := range spans {
			if pos > sp[0] && pos < sp[1] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// readPos maps a formatted counter-read finding back to its position, recorded
// as the findings are produced.
var readPos = map[string]token.Pos{}
