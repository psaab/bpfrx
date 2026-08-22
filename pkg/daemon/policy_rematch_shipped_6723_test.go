package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// #6723: `deletedPolicyRuntimeIDs`' header called the modified-policy
// (policy-rematch) half "the deferred #4234 ... half, intentionally out of
// scope". It is not deferred — it ships in this same file — and that comment is
// the FIRST thing a reader hits when tracing commit-time session invalidation.
// Following it to a now-closed issue leads to concluding that a shipped,
// security-relevant behaviour (in-progress sessions re-evaluated against a
// tightened policy) is missing, and then either re-implementing it or telling
// an operator xpf does not do it.
//
// WHY THIS GUARD IS A WIRING BIND AND NOT A PHRASE SWEEP. The obvious guard is
// "no comment in this file may say 'deferred'". That is defeated by any
// paraphrase, and worse, it would red on the corrected comments themselves —
// they QUOTE the old wording so a reader can see what changed. A phrase sweep
// would therefore push the next author toward deleting the history rather than
// keeping it.
//
// What actually makes the corrected comment true is that the rematch half is
// WIRED: `clearSessionsForPolicyChanges` calls `clearSessionsForModifiedPolicies`,
// which consults `changedPolicyRuntimeIDs`. Bind that. If someone removes the
// rematch half, the old comment becomes accurate again and this test reds with
// a message saying so — which is the only situation in which reverting the
// wording would be correct.
//
// Parsed with `parser.ParseFile(..., 0)`, so comments are discarded before
// matching: no prose in this file — including this comment — can satisfy it.

func policyInvalidateCallGraph(t *testing.T) map[string]map[string]bool {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	path := filepath.Join(filepath.Dir(self), "daemon_policy_invalidate.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	calls := map[string]map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		set := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := ce.Fun.(type) {
			case *ast.Ident:
				set[fn.Name] = true
			case *ast.SelectorExpr:
				set[fn.Sel.Name] = true
			}
			return true
		})
		calls[fd.Name.Name] = set
	}
	if len(calls) < 5 {
		t.Fatalf("parsed only %d functions from daemon_policy_invalidate.go; "+
			"this guard is not reading the file it claims to audit", len(calls))
	}
	return calls
}

// TestPolicyRematchHalfIsWiredNotDeferred6723 asserts the two edges the
// corrected comments rely on.
func TestPolicyRematchHalfIsWiredNotDeferred6723(t *testing.T) {
	calls := policyInvalidateCallGraph(t)

	for _, edge := range []struct {
		from, to string
		why      string
	}{
		{
			from: "clearSessionsForPolicyChanges",
			to:   "clearSessionsForModifiedPolicies",
			why: "the commit-time invalidation entry point must run the " +
				"modified-policy half alongside the deletion-clear",
		},
		{
			from: "clearSessionsForModifiedPolicies",
			to:   "changedPolicyRuntimeIDs",
			why: "the modified-policy clear must derive its id set from the " +
				"changed-policy diff, not from the deleted-policy one",
		},
	} {
		from, ok := calls[edge.from]
		if !ok {
			t.Fatalf("%s is gone from daemon_policy_invalidate.go; the corrected "+
				"#6723 comments name it as the thing that makes the modified-policy "+
				"half non-deferred", edge.from)
		}
		if !from[edge.to] {
			t.Errorf("%s no longer calls %s.\n"+
				"The policy-rematch half is what makes `deletedPolicyRuntimeIDs`' "+
				"header true: it says the changed-policy case is handled by "+
				"clearSessionsForModifiedPolicies rather than deferred. If that half "+
				"has genuinely been removed, the pre-#6723 wording ('the deferred "+
				"#4234 modified-policy half') becomes correct again and BOTH comments "+
				"must be reverted with it — do not silence this test alone. — %s",
				edge.from, edge.to, edge.why)
		}
	}
}
