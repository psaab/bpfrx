package config

// #1539: structural canary against AST leakage / shadow execution
// of the retired DPDK sub-tree.
//
// Background
//
// After #1525 (the DPDK retirement umbrella) and #1536
// (`validateDataplaneTypeStrict`, see compiler.go:319), no
// committed config can select the DPDK backend, so on the success
// path of `compileExpanded` the `cfg.System.DPDKDataplane` pointer
// is structurally nil (Option A in `docs/pr/1539-ast-leakage-guard/
// plan.md` clears it explicitly right before `return cfg, nil`).
//
// What is left to defend against is "AST leakage": a future
// commit adds a new strict validator, a new compile helper, or a
// new dataplane hook that reads a field on `*DPDKConfig` (or
// passes the `*DPDKConfig` to a helper) WITHOUT first gating on
// `effectiveDataplaneType(...) == dataplaneTypeDPDK`. Such code
// would silently execute DPDK-specific logic on a userspace
// backend. Option A's nil clear protects the runtime semantics;
// this canary catches the bug at `go test` time so the reviewer
// learns about the missing gate before the code merges.
//
// Scope of the AST gate
//
// The canary walks every non-test Go file under `pkg/config/`
// (the package that owns the DPDK sub-tree) and rejects any
// SelectorExpr of the form `<X>.DPDKDataplane` (read) AND any
// CallExpr whose argument list contains such a SelectorExpr
// (helper pass-through), unless the read sits under a valid
// `effectiveDataplaneType(...)` gate somewhere on its AST
// ancestor chain up to the enclosing function. Package-scope
// initializers have no enclosing function and are therefore
// always findings.
//
// "Valid gate" means one of:
//
//   1. An `*ast.IfStmt` ancestor whose Cond is a
//      `BinaryExpr{Op: ==, X|Y: effectiveDataplaneType(...),
//      Y|X: dataplaneTypeDPDK | "dpdk"}` (either operand order).
//   2. An `*ast.SwitchStmt` ancestor whose `Tag` is a
//      `CallExpr{Fun: effectiveDataplaneType, ...}` AND the
//      enclosing `*ast.CaseClause` has `len(List) == 1` AND the
//      sole entry is `dataplaneTypeDPDK` or the string literal
//      `"dpdk"`. Single-entry is required because a multi-case
//      clause like `case dataplaneTypeDPDK, dataplaneTypeUserspace:`
//      executes for userspace traffic and would otherwise pass
//      a "list contains DPDK" check.
//
// Walking all the way up to the FuncDecl (not just the nearest
// enclosing block) is deliberate: it lets a developer nest more
// conditionals inside a valid outer gate without false-positive
// canary failures. Package scope is treated separately: because
// there is no enclosing FuncDecl, there is also no valid runtime
// gate context, so a package-scope read/pass-through is always a
// canary finding. The negation idiom
// `if effectiveDataplaneType(...) != dataplaneTypeDPDK { return }`
// is NOT a valid gate in v3 — the early-exit analysis adds AST
// surface for marginal value; convert to the positive `==` form.
//
// Acceptable known limitations (Option A is the runtime
// mitigation for both):
//
//   - Storing the pointer in a local variable inside a valid
//     gate and using the local variable outside the gate. The
//     canary cannot statically follow the def-use chain through
//     local assignment.
//   - Storing the pointer in a struct field then accessing the
//     struct field later.
//
// In both cases Option A guarantees the dereferenced field is
// nil at runtime, so an `if x != nil { ... }` reader skips the
// shadow logic and a missing nil check panics safely rather than
// silently executing DPDK code on userspace traffic.
//
// The writer at `pkg/config/compiler_system.go` line ~237
// (`sys.DPDKDataplane = &DPDKConfig{}`) and the call
// `compileDPDKDataplane(child, sys.DPDKDataplane)` are accepted
// by the canary because they live inside
// `switch effectiveDataplaneType(sys.DataplaneType) { case
// dataplaneTypeDPDK: ... }` which is the canonical single-entry
// gate.

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

// dpdkSubtreeLeakageCanaryScanRoots are the directories the
// canary walks for production Go source. Test files and the
// DPDK backend itself (which legitimately reads its own
// sub-tree) are excluded inside the walker.
var dpdkSubtreeLeakageCanaryScanRoots = []string{
	".",
}

// dpdkSubtreeLeakageCanaryExcludeDirs are directory names that
// the walker skips entirely. The DPDK backend manager reads its
// own sub-tree; that is a backend-local internal coupling, not
// an "AST leakage" event a future config-package commit would
// introduce.
var dpdkSubtreeLeakageCanaryExcludeDirs = map[string]struct{}{
	"dpdk": {}, // pkg/dataplane/dpdk — backend-local
}

// dpdkSubtreeLeakageCanaryFileAllowlist allows a small set of
// files to read the sub-tree without a gate check. Today this is
// empty: the in-package writer is recognized structurally via
// the canonical single-entry switch gate, and there are no other
// production readers in pkg/config/ (see
// `TestDPDKSubtreeLeakageCanary_RealRepoIsClean`).
var dpdkSubtreeLeakageCanaryFileAllowlist = map[string]struct{}{}

// dpdkSubtreeLeakageCanarySelectorName is the field selector the
// canary looks for. It matches any expression of the form
// `<X>.DPDKDataplane`, regardless of receiver identifier
// (`cfg.System.DPDKDataplane`, `sys.DPDKDataplane`, …).
const dpdkSubtreeLeakageCanarySelectorName = "DPDKDataplane"

// dpdkSubtreeLeakageCanaryGateFnName is the name of the
// canonical helper that returns the effective dataplane type.
// The canary only accepts gates whose condition / switch tag is
// a CallExpr to this exact identifier.
const dpdkSubtreeLeakageCanaryGateFnName = "effectiveDataplaneType"

// dpdkSubtreeLeakageCanaryDPDKConstName is the name of the
// canonical typed constant the canary accepts on the RHS of an
// equality gate or as a CaseClause label.
const dpdkSubtreeLeakageCanaryDPDKConstName = "dataplaneTypeDPDK"

// dpdkSubtreeLeakageCanaryDPDKLiteral is the bare string literal
// the canary accepts in place of the typed constant.
const dpdkSubtreeLeakageCanaryDPDKLiteral = `"dpdk"`

// dpdkSubtreeLeakageCanaryRepoRoot is the path the canary walks
// when invoked against the real production tree. The test
// package compiles from `pkg/config/`, so the repo root is two
// directories up.
const dpdkSubtreeLeakageCanaryRepoRoot = ".."

// dpdkSubtreeLeakageCanaryProductionScanRoot is the production
// source root the canary scans for the
// `TestDPDKSubtreeLeakageCanary_RealRepoIsClean` test. v3 scope
// is just `pkg/config/` per the round-2 plan (Codex round-1 F1).
// Future canary iterations may expand to scan other packages
// that grow `DPDKDataplane` readers.
var dpdkSubtreeLeakageCanaryProductionScanRoot = filepath.Join(
	dpdkSubtreeLeakageCanaryRepoRoot, "config",
)

// dpdkSubtreeLeakageFinding records a single ungated read or
// pass-through. The test prints findings in stable file:line
// order so failures are easy to triage.
type dpdkSubtreeLeakageFinding struct {
	path string
	line int
	kind string // "read" or "passthrough"
	why  string
}

// scanForDPDKSubtreeLeakage walks `root` and returns every
// ungated `<X>.DPDKDataplane` read or CallExpr pass-through.
func scanForDPDKSubtreeLeakage(t *testing.T, root string) []dpdkSubtreeLeakageFinding {
	t.Helper()

	var findings []dpdkSubtreeLeakageFinding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if _, skip := dpdkSubtreeLeakageCanaryExcludeDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// Strip the leading "../" pair when the caller passes
		// `dpdkSubtreeLeakageCanaryProductionScanRoot` so the
		// allowlist key is package-relative.
		relKey := filepath.ToSlash(path)
		if _, allowed := dpdkSubtreeLeakageCanaryFileAllowlist[relKey]; allowed {
			return nil
		}
		findings = append(findings, scanFileForDPDKSubtreeLeakage(t, path)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].path == findings[j].path {
			return findings[i].line < findings[j].line
		}
		return findings[i].path < findings[j].path
	})
	return findings
}

// scanFileForDPDKSubtreeLeakage parses one Go file and returns
// every ungated read / pass-through.
func scanFileForDPDKSubtreeLeakage(t *testing.T, path string) []dpdkSubtreeLeakageFinding {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// Build a parent map so we can walk ancestors of any node.
	// ast.Inspect uses a nil callback on the way back up the
	// tree which lets us maintain a parent stack: push on
	// non-nil visit, pop on nil visit. The element at the top
	// of the stack at any non-nil visit is the immediate parent
	// of the current node.
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})

	var findings []dpdkSubtreeLeakageFinding

	// Find the enclosing FuncDecl for a node by walking parents.
	enclosingFuncDecl := func(n ast.Node) *ast.FuncDecl {
		for cur := n; cur != nil; {
			parent, ok := parents[cur]
			if !ok {
				return nil
			}
			if fn, isFn := parent.(*ast.FuncDecl); isFn {
				return fn
			}
			cur = parent
		}
		return nil
	}

	// isGatedByDPDK walks every ancestor of `n` up to (but not
	// past) `stopAt` and returns true if any IfStmt / SwitchStmt
	// in that path is a valid single-DPDK gate that contains
	// `n` in its accepting body.
	isGatedByDPDK := func(n ast.Node, stopAt ast.Node) bool {
		cur := n
		for {
			parent, ok := parents[cur]
			if !ok || parent == stopAt {
				return false
			}
			switch p := parent.(type) {
			case *ast.IfStmt:
				// Accept iff `cur` lies inside p.Body AND the
				// Cond is a valid DPDK equality gate.
				if nodeWithinBlock(cur, p.Body, parents) && isDPDKEqualityCond(p.Cond) {
					return true
				}
			case *ast.CaseClause:
				// We need to find p's enclosing SwitchStmt,
				// confirm its Tag is effectiveDataplaneType(...),
				// AND confirm p.List has exactly one entry that
				// is `dataplaneTypeDPDK` or `"dpdk"`.
				if isDPDKSingleCaseClause(p, parents) {
					return true
				}
			}
			cur = parent
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			// Skip the writer-side selectors at LHS of an
			// assignment to nil (Option A's clear) — that is a
			// write of zero value and is not a read of DPDK
			// state. The walker also accepts any SelectorExpr
			// gated by a valid ancestor.
			if node.Sel == nil || node.Sel.Name != dpdkSubtreeLeakageCanarySelectorName {
				return true
			}
			if isLHSOfAssignToNil(node, parents) {
				return true
			}
			// If this SelectorExpr is itself the argument of a
			// CallExpr we will also visit the CallExpr branch
			// below. We still want to fire on a bare read like
			// `_ = sys.DPDKDataplane.Cores`.
			fn := enclosingFuncDecl(node)
			if fn == nil {
				pos := fset.Position(node.Pos())
				findings = append(findings, dpdkSubtreeLeakageFinding{
					path: pos.Filename,
					line: pos.Line,
					kind: "read",
					why: "package-scope read of " +
						dpdkSubtreeLeakageCanarySelectorName,
				})
				return true
			}
			if !isGatedByDPDK(node, fn) {
				pos := fset.Position(node.Pos())
				findings = append(findings, dpdkSubtreeLeakageFinding{
					path: pos.Filename,
					line: pos.Line,
					kind: "read",
					why: "ungated read of " +
						dpdkSubtreeLeakageCanarySelectorName,
				})
			}
		case *ast.CallExpr:
			// Helper-function pass-through: any CallExpr whose
			// arg list contains a SelectorExpr ending in
			// DPDKDataplane must itself sit under a valid gate.
			var passthroughArg *ast.SelectorExpr
			for _, arg := range node.Args {
				if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == dpdkSubtreeLeakageCanarySelectorName {
					passthroughArg = sel
					break
				}
			}
			if passthroughArg == nil {
				return true
			}
			fn := enclosingFuncDecl(node)
			if fn == nil {
				pos := fset.Position(passthroughArg.Pos())
				findings = append(findings, dpdkSubtreeLeakageFinding{
					path: pos.Filename,
					line: pos.Line,
					kind: "passthrough",
					why: "package-scope helper pass-through of " +
						dpdkSubtreeLeakageCanarySelectorName,
				})
				return true
			}
			if !isGatedByDPDK(node, fn) {
				pos := fset.Position(passthroughArg.Pos())
				findings = append(findings, dpdkSubtreeLeakageFinding{
					path: pos.Filename,
					line: pos.Line,
					kind: "passthrough",
					why: "ungated helper pass-through of " +
						dpdkSubtreeLeakageCanarySelectorName,
				})
			}
		}
		return true
	})

	return findings
}

// nodeWithinBlock returns true if `n` is contained in `block`
// per the AST parent chain. A nil block (e.g. else-less if)
// returns false.
func nodeWithinBlock(n ast.Node, block *ast.BlockStmt, parents map[ast.Node]ast.Node) bool {
	if block == nil {
		return false
	}
	for cur := n; cur != nil; {
		if cur == block {
			return true
		}
		parent, ok := parents[cur]
		if !ok {
			return false
		}
		cur = parent
	}
	return false
}

// isDPDKEqualityCond returns true iff cond is
// `effectiveDataplaneType(...) == dataplaneTypeDPDK` or its
// operand-reversed sibling. The string literal `"dpdk"` is also
// accepted on the constant side. The negation `!=` is NOT
// accepted (v3 stance).
func isDPDKEqualityCond(cond ast.Expr) bool {
	be, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if be.Op != token.EQL {
		return false
	}
	return (isEffectiveDataplaneTypeCall(be.X) && isDPDKConstOrLit(be.Y)) ||
		(isEffectiveDataplaneTypeCall(be.Y) && isDPDKConstOrLit(be.X))
}

// isEffectiveDataplaneTypeCall returns true iff expr is a
// CallExpr whose Fun is the bare identifier
// `effectiveDataplaneType`.
func isEffectiveDataplaneTypeCall(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == dpdkSubtreeLeakageCanaryGateFnName
}

// isDPDKConstOrLit returns true iff expr is the identifier
// `dataplaneTypeDPDK` or the string literal `"dpdk"`.
func isDPDKConstOrLit(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == dpdkSubtreeLeakageCanaryDPDKConstName
	case *ast.BasicLit:
		return e.Kind == token.STRING && e.Value == dpdkSubtreeLeakageCanaryDPDKLiteral
	}
	return false
}

// isDPDKSingleCaseClause returns true iff `cc` is enclosed by an
// `*ast.SwitchStmt` whose Tag is `effectiveDataplaneType(...)`
// AND `cc.List` has exactly one entry that is
// `dataplaneTypeDPDK` or `"dpdk"`. Single-entry is required so
// that a multi-case clause like
// `case dataplaneTypeDPDK, dataplaneTypeUserspace:` does NOT
// accept a DPDK read (the block executes for userspace too).
func isDPDKSingleCaseClause(cc *ast.CaseClause, parents map[ast.Node]ast.Node) bool {
	if len(cc.List) != 1 {
		return false
	}
	if !isDPDKConstOrLit(cc.List[0]) {
		return false
	}
	// Walk up to the enclosing SwitchStmt and check Tag.
	for cur := ast.Node(cc); cur != nil; {
		parent, ok := parents[cur]
		if !ok {
			return false
		}
		if sw, isSw := parent.(*ast.SwitchStmt); isSw {
			return isEffectiveDataplaneTypeCall(sw.Tag)
		}
		cur = parent
	}
	return false
}

// isLHSOfAssignToNil returns true iff `sel` appears as the LHS
// of an `AssignStmt` whose RHS is the identifier `nil`. This
// covers Option A's `cfg.System.DPDKDataplane = nil` clear.
func isLHSOfAssignToNil(sel *ast.SelectorExpr, parents map[ast.Node]ast.Node) bool {
	parent, ok := parents[sel]
	if !ok {
		return false
	}
	as, ok := parent.(*ast.AssignStmt)
	if !ok {
		return false
	}
	// Find which LHS index matches our selector.
	lhsIndex := -1
	for i, lhs := range as.Lhs {
		if lhs == sel {
			lhsIndex = i
			break
		}
	}
	if lhsIndex == -1 {
		return false
	}
	// In Go, if len(Rhs) != len(Lhs), it must be a multi-value expression (e.g. call or map read),
	// which cannot be a bare 'nil'.
	if len(as.Rhs) != len(as.Lhs) {
		return false
	}
	// Check if the corresponding RHS expression is exactly the identifier "nil".
	ident, ok := as.Rhs[lhsIndex].(*ast.Ident)
	return ok && ident.Name == "nil"
}

// TestDPDKSubtreeLeakageCanary_RealRepoIsClean asserts the
// production source under `pkg/config/` has zero ungated reads
// or pass-throughs of the DPDK sub-tree. Today the only writer
// is the canonical single-entry switch gate in
// `compiler_system.go`; Option A's nil clear in `compiler.go`
// is recognized as an LHS-of-assign-to-nil and therefore
// excluded. Adding a new ungated reader without a gate will
// fire this test.
func TestDPDKSubtreeLeakageCanary_RealRepoIsClean(t *testing.T) {
	findings := scanForDPDKSubtreeLeakage(t, dpdkSubtreeLeakageCanaryProductionScanRoot)
	if len(findings) == 0 {
		return
	}
	var lines []string
	for _, f := range findings {
		lines = append(lines, formatLeakageFinding(f))
	}
	t.Fatalf("real-repo scan returned %d unexpected DPDK sub-tree leakage finding(s):\n%s",
		len(findings), strings.Join(lines, "\n"))
}

// TestDPDKSubtreeLeakageCanary_PositiveAcceptsIfGate writes a
// fixture with a positive `==` if-gate around the read and
// asserts the canary returns zero findings.
func TestDPDKSubtreeLeakageCanary_PositiveAcceptsIfGate(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": positiveIfGateFixture,
	})
	if findings := scanForDPDKSubtreeLeakage(t, root); len(findings) != 0 {
		t.Fatalf("positive if-gate fixture should be clean, got: %s",
			renderLeakageFindings(findings))
	}
}

// TestDPDKSubtreeLeakageCanary_PositiveAcceptsSwitchGate writes
// a fixture with the canonical `switch effectiveDataplaneType
// { case dataplaneTypeDPDK: }` single-entry gate.
func TestDPDKSubtreeLeakageCanary_PositiveAcceptsSwitchGate(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": positiveSwitchGateFixture,
	})
	if findings := scanForDPDKSubtreeLeakage(t, root); len(findings) != 0 {
		t.Fatalf("positive switch-gate fixture should be clean, got: %s",
			renderLeakageFindings(findings))
	}
}

// TestDPDKSubtreeLeakageCanary_PositiveAcceptsNestedGatedRead
// asserts that a read nested inside a second inner conditional
// is still accepted because the outer gate is on the ancestor
// chain (AGY round-2 MEDIUM).
func TestDPDKSubtreeLeakageCanary_PositiveAcceptsNestedGatedRead(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": positiveNestedGatedReadFixture,
	})
	if findings := scanForDPDKSubtreeLeakage(t, root); len(findings) != 0 {
		t.Fatalf("nested-gated-read fixture should be clean, got: %s",
			renderLeakageFindings(findings))
	}
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsUngatedRead
// asserts the canary fires on a bare ungated read.
func TestDPDKSubtreeLeakageCanary_NegativeRejectsUngatedRead(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeUngatedReadFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "read")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsHelperPassthrough
// asserts the canary fires on an ungated helper pass-through
// `useIt(cfg.System.DPDKDataplane)`.
func TestDPDKSubtreeLeakageCanary_NegativeRejectsHelperPassthrough(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeHelperPassthroughFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "passthrough")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsWrongTypeBranch
// asserts the canary fires on a read inside an
// `effectiveDataplaneType(...) == dataplaneTypeUserspace`
// branch (Codex round-1 F2 counterexample).
func TestDPDKSubtreeLeakageCanary_NegativeRejectsWrongTypeBranch(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeWrongTypeBranchFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "read")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsSwitchMultipleCases
// asserts the canary fires on
// `case dataplaneTypeDPDK, dataplaneTypeUserspace: _ = ...DPDKDataplane`
// (AGY round-2 HIGH multi-case bypass).
func TestDPDKSubtreeLeakageCanary_NegativeRejectsSwitchMultipleCases(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeSwitchMultiCaseFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "read")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsNegationIdiom
// asserts the canary fires on the early-return negation idiom
// `if effectiveDataplaneType(...) != dataplaneTypeDPDK { return };
// _ = ...DPDKDataplane`. v3 explicitly does not accept this
// form; the developer must convert to the positive `==`.
func TestDPDKSubtreeLeakageCanary_NegativeRejectsNegationIdiom(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeNegationIdiomFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "read")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsMultiVariableBypass
// asserts the canary fires when attempting to bypass the write-to-nil
// exclusion using a multi-variable assignment where nil is not mapped to
// DPDKDataplane.
func TestDPDKSubtreeLeakageCanary_NegativeRejectsMultiVariableBypass(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativeMultiVariableBypassFixture,
	})
	requireLeakageFindingKind(t, scanForDPDKSubtreeLeakage(t, root), "read")
}

// TestDPDKSubtreeLeakageCanary_NegativeRejectsPackageScopeInitializer
// asserts the canary fires on package-scope reads and helper pass-throughs.
// Package scope has no enclosing FuncDecl, so there is no valid gate context.
func TestDPDKSubtreeLeakageCanary_NegativeRejectsPackageScopeInitializer(t *testing.T) {
	root := writeLeakageCanaryFixture(t, map[string]string{
		"a.go": negativePackageScopeInitializerFixture,
	})
	findings := scanForDPDKSubtreeLeakage(t, root)
	requireLeakageFindingKind(t, findings, "read")
	requireLeakageFindingKind(t, findings, "passthrough")
}

// Fixtures: each is a self-contained Go source file written to
// a `t.TempDir()` directory and then walked by the canary. The
// fixtures DO NOT compile against the real config package; the
// canary only parses them.

const positiveIfGateFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

const dataplaneTypeDPDK = "dpdk"

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	if effectiveDataplaneType(sys.DataplaneType) == dataplaneTypeDPDK {
		return sys.DPDKDataplane.Cores
	}
	return 0
}
`

const positiveSwitchGateFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

const dataplaneTypeDPDK = "dpdk"

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	switch effectiveDataplaneType(sys.DataplaneType) {
	case dataplaneTypeDPDK:
		return sys.DPDKDataplane.Cores
	}
	return 0
}
`

const positiveNestedGatedReadFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
	Other         bool
}

const dataplaneTypeDPDK = "dpdk"

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	if effectiveDataplaneType(sys.DataplaneType) == dataplaneTypeDPDK {
		if sys.Other {
			return sys.DPDKDataplane.Cores
		}
	}
	return 0
}
`

const negativeUngatedReadFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

func use(sys *sysT) int {
	return sys.DPDKDataplane.Cores
}
`

const negativeHelperPassthroughFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

func useIt(d *DPDKConfig) int { return d.Cores }

func use(sys *sysT) int {
	return useIt(sys.DPDKDataplane)
}
`

const negativeWrongTypeBranchFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

const dataplaneTypeUserspace = "userspace"

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	if effectiveDataplaneType(sys.DataplaneType) == dataplaneTypeUserspace {
		return sys.DPDKDataplane.Cores
	}
	return 0
}
`

const negativeSwitchMultiCaseFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

const (
	dataplaneTypeDPDK      = "dpdk"
	dataplaneTypeUserspace = "userspace"
)

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	switch effectiveDataplaneType(sys.DataplaneType) {
	case dataplaneTypeDPDK, dataplaneTypeUserspace:
		return sys.DPDKDataplane.Cores
	}
	return 0
}
`

const negativeNegationIdiomFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

const dataplaneTypeDPDK = "dpdk"

func effectiveDataplaneType(s string) string { return s }

func use(sys *sysT) int {
	if effectiveDataplaneType(sys.DataplaneType) != dataplaneTypeDPDK {
		return 0
	}
	return sys.DPDKDataplane.Cores
}
`

const negativeMultiVariableBypassFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

func use(sys *sysT) {
	var dummy *DPDKConfig
	dummy, sys.DPDKDataplane = nil, &DPDKConfig{Cores: 4}
}
`

const negativePackageScopeInitializerFixture = `package fixture

type DPDKConfig struct{ Cores int }
type sysT struct {
	DataplaneType string
	DPDKDataplane *DPDKConfig
}

var singleton = &sysT{}

func useIt(d *DPDKConfig) int { return d.Cores }

var _ = singleton.DPDKDataplane
var _ = useIt(singleton.DPDKDataplane)
`

// writeLeakageCanaryFixture writes each fixture string to a
// fresh temp dir and returns the dir path.
func writeLeakageCanaryFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}
	return root
}

// requireLeakageFindingKind fails the test if no finding of the
// expected `kind` ("read" or "passthrough") appears in the set.
func requireLeakageFindingKind(t *testing.T, findings []dpdkSubtreeLeakageFinding, kind string) {
	t.Helper()
	for _, f := range findings {
		if f.kind == kind {
			return
		}
	}
	t.Fatalf("expected at least one canary finding of kind %q, got: %s",
		kind, renderLeakageFindings(findings))
}

// renderLeakageFindings formats every finding for failure
// messages.
func renderLeakageFindings(findings []dpdkSubtreeLeakageFinding) string {
	if len(findings) == 0 {
		return "<no findings>"
	}
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, formatLeakageFinding(f))
	}
	return strings.Join(parts, "\n")
}

// formatLeakageFinding formats a single finding as
// `file:line [kind] why`.
func formatLeakageFinding(f dpdkSubtreeLeakageFinding) string {
	return f.path + ":" + strconv.Itoa(f.line) + " [" + f.kind + "] " + f.why
}
