package userspace

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

// #7930: a static lock-graph check over this package.
//
// THE DEFECT IT EXISTS FOR. #7095 added the IngressIfaceFold field and a
// resolver to read it; the resolver took m.mu, and its callers already held it.
// Any peer-synced session carrying a non-zero fold wedged the userspace manager
// PERMANENTLY -- and `go test ./...` passed, 69 packages, zero failures.
//
// That is not a missing assertion someone forgot. Every test in this package
// constructs a Manager and calls in from the OUTSIDE, where m.mu is free.
// Reproducing the deadlock needs a test that holds the manager mutex and then
// calls a ...Locked method -- a shape you only write if you are already asking
// about the lock graph. The gap is that nothing PROMPTS the question.
//
// The rule: from any function whose name ends in `Locked`, no transitively
// reachable function in this package may ACQUIRE m.mu.
//
// TRANSITIVITY IS LOAD-BEARING, not thoroughness. The real chain was
//
//	syncSessionV4Locked  (holds m.mu)
//	  -> buildSessionSyncRequestV4   (NOT named *Locked)
//	    -> resolveIngressFold        (acquires m.mu)  = deadlock
//
// so a direct-callee-only check would have missed it: neither the acquirer nor
// its immediate caller carries the suffix.
//
// PRECONDITION. This is checkable only because the package uses the `Locked`
// suffix consistently -- 121 *Locked methods on *Manager. The suffix is what
// carries the invariant. Do NOT port this to a package without the convention;
// there it matches nothing and passes vacuously.

// muAction is one m.mu operation, in source order.
type muAction struct {
	pos    token.Pos
	unlock bool
}

// lockFacts is what the analyzer extracts per function.
type lockFacts struct {
	name     string
	acquires bool     // acquires m.mu without first releasing it
	callees  []string // in-package calls, by function name
	file     string
	line     int
}

// analyzeLockGraph7930 parses the package's non-test sources.
//
// ACQUIRE vs RE-ACQUIRE is the distinction that decides whether this check is
// usable. A naive "a *Locked method must not contain m.mu.Lock()" reports five
// violations here and all five are CORRECT -- the unlock-then-relock pattern
// that releases m.mu for slow I/O and reacquires before returning:
//
//	m.mu.Unlock()
//	err := m.requestSessionSync(ctrlReq)
//	m.mu.Lock()
//
// A check that cries wolf on five correct call sites gets switched off within a
// week, which is worse than no check. So: a Lock is an ACQUIRE only when no
// Unlock precedes it in that function body. The pre-fix resolveIngressFold had
// `m.mu.Lock()` BEFORE its Unlock, so it is correctly an acquire; the five
// legitimate sites have Unlock first.
func analyzeLockGraph7930(t *testing.T, dir string) map[string]*lockFacts {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	out := map[string]*lockFacts{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			lf := &lockFacts{
				name: fn.Name.Name,
				file: filepath.Base(path),
				line: fset.Position(fn.Pos()).Line,
			}
			var actions []muAction
			// Calls launched with `go` run CONCURRENTLY, not while the caller
			// holds m.mu, so a goroutine that acquires the mutex is correct and
			// must not be traversed. This is a SECOND class of legitimate
			// pattern beyond the unlock-then-relock one, and it is only visible
			// to a TRANSITIVE check -- the issue's direct-body form never
			// reaches it. Without this the analyzer reports 17 findings on a
			// clean tree, every one of them a supervisor or status-loop
			// goroutine (`go m.superviseHelper(g)` at process_supervisor.go:240,
			// `go m.statusLoop(ctx)` at process_status.go:149), and a check with
			// 17 false positives is a check nobody runs.
			//
			// The same reasoning covers a call inside a FUNCTION LITERAL. This
			// package schedules deferred work by handing a closure to a timer:
			//
			//	m.scheduleRestartTimer(delay, func() { m.restartHelperAfterCrash(gen) })
			//
			// restartHelperAfterCrash takes m.mu and is correct, because the
			// closure runs from the timer long after scheduleHelperRestartLocked
			// returned and released it. Traversing into closure bodies reports
			// it, and reported it here.
			//
			// KNOWN LIMITATION, stated rather than discovered later: this also
			// skips a closure that IS invoked synchronously while the lock is
			// held, which would be a real deadlock. That is the deliberate
			// trade -- a check with false positives gets switched off, and this
			// package's closures are schedule-for-later by construction. If a
			// synchronously-invoked closure pattern appears here, this
			// exemption needs narrowing to closures that ESCAPE (passed as an
			// argument, assigned, or returned).
			deferred := map[ast.Node]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.GoStmt:
					ast.Inspect(node, func(inner ast.Node) bool {
						deferred[inner] = true
						return true
					})
				case *ast.DeferStmt:
					ast.Inspect(node, func(inner ast.Node) bool {
						deferred[inner] = true
						return true
					})
				case *ast.FuncLit:
					ast.Inspect(node.Body, func(inner ast.Node) bool {
						deferred[inner] = true
						return true
					})
				}
				return true
			})
			goroutine := deferred
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if goroutine[call] {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// m.mu.Lock() / m.mu.Unlock() / RLock / RUnlock
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mu" {
					switch sel.Sel.Name {
					case "Lock", "RLock":
						actions = append(actions, muAction{call.Pos(), false})
					case "Unlock", "RUnlock":
						actions = append(actions, muAction{call.Pos(), true})
					}
					return true
				}
				// m.someMethod(...) — an in-package call to record.
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "m" {
					lf.callees = append(lf.callees, sel.Sel.Name)
				}
				return true
			})
			sort.Slice(actions, func(i, j int) bool { return actions[i].pos < actions[j].pos })
			released := false
			for _, a := range actions {
				if a.unlock {
					released = true
					continue
				}
				if !released {
					lf.acquires = true
					break
				}
			}
			// A method name can appear twice (different receivers); keep the
			// one that acquires, so the check cannot be defeated by a
			// same-named sibling that does not.
			if prev, ok := out[lf.name]; !ok || (lf.acquires && !prev.acquires) {
				out[lf.name] = lf
			}
		}
	}
	return out
}

// reachableAcquirers7930 walks the in-package call graph from root and returns
// every reachable function that acquires m.mu, with the path that reaches it.
func reachableAcquirers7930(facts map[string]*lockFacts, root string) map[string][]string {
	found := map[string][]string{}
	seen := map[string]bool{root: true}
	type item struct {
		name string
		path []string
	}
	queue := []item{{root, []string{root}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		lf, ok := facts[cur.name]
		if !ok {
			continue
		}
		for _, callee := range lf.callees {
			if seen[callee] {
				continue
			}
			seen[callee] = true
			path := append(append([]string{}, cur.path...), callee)
			if c, ok := facts[callee]; ok && c.acquires {
				found[callee] = path
			}
			queue = append(queue, item{callee, path})
		}
	}
	return found
}

func TestNoLockedFunctionReachesAnMuAcquirer7930(t *testing.T) {
	facts := analyzeLockGraph7930(t, ".")

	// Vacuity guards. If the parse or the suffix convention ever stops holding,
	// this test must say so rather than passing by finding nothing.
	if len(facts) == 0 {
		t.Fatal("analyzer found no functions — the parse produced nothing and " +
			"this check is passing vacuously")
	}
	var roots []string
	for name := range facts {
		if strings.HasSuffix(name, "Locked") {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)
	// The precondition, asserted rather than assumed: the suffix convention is
	// what the whole check keys on.
	if len(roots) < 50 {
		t.Fatalf("only %d *Locked functions found — the suffix convention this "+
			"check depends on has eroded, so it now guards almost nothing "+
			"(see the precondition note above)", len(roots))
	}

	var findings []string
	for _, root := range roots {
		for acquirer, path := range reachableAcquirers7930(facts, root) {
			lf := facts[acquirer]
			findings = append(findings, strings.Join(path, " -> ")+
				"  ("+lf.file+":"+itoa7930(lf.line)+" acquires m.mu)")
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		t.Errorf("a *Locked function transitively reaches %d function(s) that "+
			"ACQUIRE m.mu — each is a permanent manager deadlock the whole Go "+
			"suite would still pass (#7095/#7930):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// The POSITIVE control. A checker that does not catch the known instance proves
// nothing, so the pre-#7922 shape is reconstructed here and the analyzer is run
// over it. This is the real chain, with the real names:
//
//	syncSessionV4Locked -> buildSessionSyncRequestV4 -> resolveIngressFold
//
// The middle link carries no `Locked` suffix, which is exactly why a
// direct-callee check would have missed it.
func TestAnalyzerCatchesThePre7922Deadlock7930(t *testing.T) {
	dir := t.TempDir()
	src := `package userspace

type mu struct{}

func (mu) Lock()   {}
func (mu) Unlock() {}

type Manager struct{ mu mu }

func (m *Manager) syncSessionV4Locked() { m.buildSessionSyncRequestV4() }

func (m *Manager) buildSessionSyncRequestV4() { m.resolveIngressFold() }

func (m *Manager) resolveIngressFold() {
	m.mu.Lock()
	m.mu.Unlock()
}

// The unlock-then-relock pattern must NOT be reported: this is the shape of the
// five legitimate sites in the real package.
func (m *Manager) syncSessionRequestLocked() {
	m.mu.Unlock()
	m.slowIO()
	m.mu.Lock()
}

func (m *Manager) slowIO() {}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	facts := analyzeLockGraph7930(t, dir)

	got := reachableAcquirers7930(facts, "syncSessionV4Locked")
	if _, ok := got["resolveIngressFold"]; !ok {
		t.Errorf("the analyzer did NOT catch the known #7095 deadlock — it "+
			"cannot be trusted on the real package. reachable acquirers: %v", keys7930(got))
	}
	// The path must go THROUGH the unsuffixed middle link, which is the reason
	// transitivity is required.
	if path := got["resolveIngressFold"]; len(path) > 0 {
		if !contains7930(path, "buildSessionSyncRequestV4") {
			t.Errorf("path %v does not traverse the unsuffixed intermediate — "+
				"a direct-callee check would have sufficed, so this fixture is "+
				"not testing transitivity", path)
		}
	}

	// The NEGATIVE control, in the same fixture: unlock-then-relock is correct
	// and must not be reported.
	if _, bad := reachableAcquirers7930(facts, "syncSessionRequestLocked")["slowIO"]; bad {
		t.Error("reported the unlock-then-relock pattern — the check would cry " +
			"wolf on the five correct sites in this package and be switched off")
	}
	if facts["syncSessionRequestLocked"].acquires {
		t.Error("classified unlock-then-relock as an ACQUIRE; a Lock preceded " +
			"by an Unlock is a RE-acquire")
	}
	if !facts["resolveIngressFold"].acquires {
		t.Error("did NOT classify a bare Lock as an acquire")
	}
}

func keys7930(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains7930(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func itoa7930(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
