package dataplane

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// #4626 L01. `policy_id` 0 is overloaded: it is both the id of the literal
// first configured policy (compilePolicies assigns
// policySetID*MaxRulesPerPolicy + i, so the first rule of the first zone-pair
// is 0) AND the value stamped on every session no policy admitted —
// host-inbound, neighbor-seed, fabric, tunnel, every pre-#3056 session, and
// every session synced from an older HA peer during a rolling upgrade.
//
// Resolving it through CompileResult.PolicyNames therefore returns a real
// policy name for sessions that policy never saw. SessionPolicyName is the
// guard; these tests pin both the guard and the fact that the six session-row
// render sites go through it.

// TestSessionPolicyNameReservedIDs_4626 is the guard's own fail-on-revert. The
// map deliberately CARRIES a name at id 0 — that is the whole defect, and a
// fixture without it would pass against a broken implementation.
func TestSessionPolicyNameReservedIDs_4626(t *testing.T) {
	// A realistic compiled map: id 0 is the first configured policy, exactly
	// as compilePolicies emits it, plus the seeded default sentinel.
	names := map[uint32]string{
		0:                       "trust-to-untrust/allow-web",
		1:                       "trust-to-untrust/allow-dns",
		256:                     "dmz-to-untrust/allow-any",
		DefaultPolicySentinelID: DefaultPolicyName,
	}

	t.Run("zero never resolves to the first policy", func(t *testing.T) {
		got := SessionPolicyName(names, 0)
		if got == names[0] {
			t.Fatalf("SessionPolicyName(_, 0) = %q — the first configured policy's name. "+
				"A host-inbound/fabric/tunnel/older-peer session carries id 0 and no policy "+
				"admitted it; naming a real policy there is a confidently wrong attribution "+
				"on a security surface (#4626)", got)
		}
		if got != UnattributedPolicyName {
			t.Fatalf("SessionPolicyName(_, 0) = %q, want %q", got, UnattributedPolicyName)
		}
	})

	t.Run("zero is unattributed with no policies configured", func(t *testing.T) {
		if got := SessionPolicyName(map[uint32]string{}, 0); got != UnattributedPolicyName {
			t.Errorf("empty map: got %q, want %q", got, UnattributedPolicyName)
		}
		if got := SessionPolicyName(nil, 0); got != UnattributedPolicyName {
			t.Errorf("nil map: got %q, want %q", got, UnattributedPolicyName)
		}
	})

	t.Run("default sentinel resolves without a published map", func(t *testing.T) {
		if got := SessionPolicyName(names, DefaultPolicySentinelID); got != DefaultPolicyName {
			t.Errorf("seeded map: got %q, want %q", got, DefaultPolicyName)
		}
		// Before the first apply the map is nil; the sentinel must still not
		// fall through to a raw numeric render (#3057 parity).
		if got := SessionPolicyName(nil, DefaultPolicySentinelID); got != DefaultPolicyName {
			t.Errorf("nil map: got %q, want %q", got, DefaultPolicyName)
		}
	})

	// Over-rejection guard: every UNRESERVED id must still resolve exactly as a
	// direct map index did, including returning "" for an absent id so each
	// caller's own not-found fallback is unchanged.
	t.Run("unreserved ids are unchanged", func(t *testing.T) {
		for _, id := range []uint32{1, 256} {
			if got, want := SessionPolicyName(names, id), names[id]; got != want {
				t.Errorf("SessionPolicyName(_, %d) = %q, want %q — the guard must not "+
					"disturb ordinary policy resolution", id, got, want)
			}
		}
		for _, id := range []uint32{2, 7, 255, 257, 100000, DefaultPolicySentinelID - 1} {
			if got := SessionPolicyName(names, id); got != "" {
				t.Errorf("SessionPolicyName(_, %d) = %q, want \"\" — an absent id must stay "+
					"empty so callers keep their existing numeric/blank fallback", id, got)
			}
		}
	})
}

// sessionPolicyNameDisplayPackages are the packages that turn a policy_id into
// a policy NAME for an operator- or automation-visible surface.
//
// pkg/logging is in the list. An earlier revision excluded it, reasoning that
// the RT_FLOW/event path "owns its own resolver ... and folding the two is a
// separate change". That reasoning did not survive #6851: owning a resolver is
// not exemption from the reserved ids. EventReader.resolvePolicyName took
// DefaultPolicySentinelID (#3057) and then indexed the map, so id 0 resolved to
// the first configured policy there too — the SEVENTH instance of the same
// defect, and the one that matters most, because a log record is durable and
// ships off-box. The exclusion is what let that site sit unguarded through the
// first round: a package carved out of a canary is a package nothing checks, so
// the carve-out needs the same evidence as the fix does.
var sessionPolicyNameDisplayPackages = []string{"cli", "api", "grpcapi", "logging"}

// TestSessionRowSurfacesUseSessionPolicyName_4626 is the render-site binding.
//
// The behavioural tests in pkg/api and pkg/grpcapi drive four of the six render
// sites directly. The remaining two are inside printV4/printV6, closures in
// pkg/cli showFlowSession that fmt.Printf to real stdout behind a live
// dataplane, so no cheap behavioural test reaches them — and a guard nobody
// exercises is exactly how #4626 survived #3056 and #3057. This canary covers
// all six structurally, and any seventh added later, by refusing a direct map
// index in the display packages.
//
// SCOPE, stated rather than implied. It rejects an index of an identifier or
// field named `policyNames`/`PolicyNames` inside a production function of
// pkg/cli, pkg/api, pkg/grpcapi or pkg/logging that never calls a reserved-id
// helper. Three things it does NOT prove:
//
//   - that the helper call DOMINATES the index on every path. A function that
//     consulted a helper in a dead branch and indexed the map on the live one
//     would pass. The check is "this function knows about the reserved ids",
//     not a dataflow proof.
//   - that those packages resolve policy names correctly in general.
//   - anything about a copy of the map stored under another name first.
//
// It binds the specific regression shape: re-inlining `policyNames[val.PolicyID]`
// at a site with no reserved-id handling, which is what all seven instances of
// this defect looked like.
var reservedPolicyHelpers = []string{
	"ReservedPolicyName", "SessionPolicyName", "PeerSessionPolicyName",
}

// scanPolicyNameScope reports unguarded policy-name map indexes inside ONE
// function scope, then recurses into each nested function literal as its own
// scope. A helper call in the parent does not guard a closure, and a helper
// call in one closure does not guard its sibling (#6851).
func scanPolicyNameScope(owner string, body ast.Node, path string, fset *token.FileSet, violations *[]string) {
	var indexes []*ast.IndexExpr
	var nested []*ast.FuncLit
	guarded := false

	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			if node.Body != body {
				nested = append(nested, node)
				return false // its contents belong to ITS scope, not this one
			}
		case *ast.CallExpr:
			for _, h := range reservedPolicyHelpers {
				if isCallTo(node, h) {
					guarded = true
				}
			}
		case *ast.IndexExpr:
			name := ""
			switch x := node.X.(type) {
			case *ast.Ident:
				name = x.Name
			case *ast.SelectorExpr:
				name = x.Sel.Name
			}
			if name == "policyNames" || name == "PolicyNames" {
				indexes = append(indexes, node)
			}
		}
		return true
	}
	ast.Inspect(body, walk)

	if !guarded {
		for _, idx := range indexes {
			*violations = append(*violations, fmt.Sprintf(
				"%s:%d: %s indexes the policy-name map without consulting %v first",
				path, fset.Position(idx.Pos()).Line, owner, reservedPolicyHelpers))
		}
	}
	for i, fl := range nested {
		scanPolicyNameScope(fmt.Sprintf("%s closure #%d", owner, i+1), fl.Body,
			path, fset, violations)
	}
}

// isCallTo reports whether call invokes a function whose (possibly
// package-qualified) name is fn — `fn(...)`, `pkg.fn(...)` or `x.fn(...)`.
func isCallTo(call *ast.CallExpr, fn string) bool {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name == fn
	case *ast.SelectorExpr:
		return f.Sel.Name == fn
	}
	return false
}
func TestSessionRowSurfacesUseSessionPolicyName_4626(t *testing.T) {
	var violations []string
	perPkg := map[string]int{}

	for _, pkg := range sessionPolicyNameDisplayPackages {
		root := filepath.Join("..", pkg)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			perPkg[pkg]++

			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			// Walk per innermost FUNCTION SCOPE — a FuncDecl body, or a nested
			// FuncLit body as its own scope.
			//
			// Two legitimate shapes exist and a blanket "no index" rule rejects
			// one of them:
			//
			//   (a) delegate wholly — SessionPolicyName(policyNames, id);
			//   (b) take the reserved ids first, then index —
			//       `if n, ok := ReservedPolicyName(id); ok { return n }`.
			//
			// (b) is what pkg/logging resolvePolicyName does, and it is correct:
			// the index is only reached for an id that is not reserved.
			//
			// #6851: the scope MUST be the innermost function, not the enclosing
			// FuncDecl. pkg/cli showFlowSession is 557 lines and contains BOTH
			// render sites inside separate printV4/printV6 closures, so a
			// FuncDecl-scoped rule marked the whole function guarded from either
			// closure's helper call — reverting exactly one site left the
			// sibling's call satisfying the rule and the canary green. Measured:
			// reverting only the v6 site passed both this canary and the full
			// pkg/cli suite. Per-FuncLit, each closure stands on its own.
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				scanPolicyNameScope(fn.Name.Name, fn.Body, path, fset, &violations)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// Guard the guard, PER PACKAGE (#6851). A total-file floor does not bind
	// its own dimension: re-adding the pkg/logging carve-out AND reverting
	// ringbuf.go together kept the total above the threshold, so the very
	// regression this list exists to prevent went green. Each package must
	// contribute scanned files of its own.
	// The list itself is the thing being guarded, so assert MEMBERSHIP before
	// coverage (#6851). A per-package file floor only fires for a package that
	// IS listed and scanned nothing — removing "logging" from the list removes
	// it from the loop, so the floor never runs for it and the carve-out
	// reinstates silently. Measured: re-adding the carve-out alone went GREEN
	// against the floor alone.
	required := map[string]bool{"cli": true, "api": true, "grpcapi": true, "logging": true}
	for _, pkg := range sessionPolicyNameDisplayPackages {
		delete(required, pkg)
	}
	for pkg := range required {
		t.Fatalf("pkg/%s was dropped from sessionPolicyNameDisplayPackages. Every one of "+
			"these packages resolves a policy_id into a NAME on an operator- or "+
			"automation-visible surface; carving one out is how the seventh resolver "+
			"survived round 1, and the carve-out that did it was justified by an argument "+
			"the same change disproved", pkg)
	}

	for _, pkg := range sessionPolicyNameDisplayPackages {
		if perPkg[pkg] == 0 {
			t.Fatalf("canary scanned ZERO files in pkg/%s. Its directory exists but "+
				"yielded no production .go files, so every per-file check below is "+
				"vacuously satisfied and the package contributes no coverage while the "+
				"rest of the walk still passes. (A path that does not exist is a "+
				"different case: WalkDir errors and the Fatalf above fires first.) "+
				"Membership is asserted separately, because a package REMOVED from the "+
				"list never reaches this loop at all", pkg)
		}
	}

	if len(violations) > 0 {
		t.Errorf("session-row policy names must resolve through dataplane.SessionPolicyName, "+
			"which reserves id 0 (no policy admitted the session) and the default-policy "+
			"sentinel. A direct map index renders id 0 as the FIRST configured policy — the "+
			"#4626 misattribution. Offending sites:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
