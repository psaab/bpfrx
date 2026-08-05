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

// sessionPolicyNameDisplayPackages are the packages that render a SESSION ROW's
// policy name. pkg/logging is deliberately absent: the RT_FLOW/event path owns
// its own resolver (EventReader.resolvePolicyName, #3057) over a different map
// instance, and folding the two is a separate change.
var sessionPolicyNameDisplayPackages = []string{"cli", "api", "grpcapi"}

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
// SCOPE, stated rather than implied: it rejects an index expression whose
// operand is an identifier or field named `policyNames`/`PolicyNames` inside
// pkg/cli, pkg/api and pkg/grpcapi production files. It does NOT prove those
// packages resolve policy names correctly in general, and it cannot see a copy
// of the map stored under another name first. It binds the specific regression
// shape: re-inlining `policyNames[val.PolicyID]` at a session-row render site.
func TestSessionRowSurfacesUseSessionPolicyName_4626(t *testing.T) {
	var violations []string
	scanned := 0

	for _, pkg := range sessionPolicyNameDisplayPackages {
		root := filepath.Join("..", pkg)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanned++

			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Fatalf("parse %s: %v", path, perr)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				idx, ok := n.(*ast.IndexExpr)
				if !ok {
					return true
				}
				name := ""
				switch x := idx.X.(type) {
				case *ast.Ident:
					name = x.Name
				case *ast.SelectorExpr:
					name = x.Sel.Name
				}
				if name != "policyNames" && name != "PolicyNames" {
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: direct %s[...] index at a session-row display surface",
					path, fset.Position(idx.Pos()).Line, name))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	// Guard the guard: a walk that silently scanned nothing would pass forever.
	if scanned < 20 {
		t.Fatalf("canary scanned only %d files across %v; the walk is broken and this test "+
			"is not checking anything", scanned, sessionPolicyNameDisplayPackages)
	}
	if len(violations) > 0 {
		t.Errorf("session-row policy names must resolve through dataplane.SessionPolicyName, "+
			"which reserves id 0 (no policy admitted the session) and the default-policy "+
			"sentinel. A direct map index renders id 0 as the FIRST configured policy — the "+
			"#4626 misattribution. Offending sites:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
