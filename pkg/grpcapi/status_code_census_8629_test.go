package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #8629: every RPC handler's error returns must carry a gRPC status code.
//
// THE DEFECT THIS PINS. A handler returning a bare error surfaces to the client
// as codes.Unknown, so a caller cannot distinguish "your request was malformed"
// from "the subsystem is not running" from a genuine internal fault. 65 error
// returns on this surface were bare. The count is not the point — the point is
// that site 66 is coming, and nothing stopped it.
//
// WHY IT SCANS THE EXPORTED HANDLER AND NOT EVERY RETURN. ShowText's body was
// moved to `showText` and its 63 bare returns are converted once, at the
// boundary, by `rpcStatus`. Converting them individually would leave the next
// show topic bare, which is the non-uniformity #8629 says is worse than the
// uniform wrongness it replaces. So what must hold is a property of the
// EXPORTED method: every error it returns is either already a status, or has
// been routed through `rpcStatus`. A scan of all returns everywhere would red
// on `showText`'s interior and demand exactly the sweep this design rejects.
//
// TWO DEGENERATE-FAILURE GUARDS, because a blind scan and a clean tree produce
// the same output. If the parse finds no handlers, or none of them returns a
// status at all, the scan is broken and says so rather than passing.

// rpcSurfaceMethods are the exported names this file requires to be status-typed.
// Derived from the generated service interface at the time of writing; a method
// that disappears is caught by the coverage floor below rather than silently
// dropping out of the census.
func rpcSurfaceMethods(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("xpfv1", "xpf_grpc.pb.go"))
	if err != nil {
		t.Fatalf("read generated service interface: %v", err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(src), "\n") {
		l := strings.TrimSpace(line)
		i := strings.Index(l, "(context.Context, *")
		if i <= 0 {
			continue
		}
		name := l[:i]
		if name == "" || !isExportedIdent(name) {
			continue
		}
		out[name] = true
	}
	return out
}

func isExportedIdent(s string) bool {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// returnsStatusTyped reports whether every error-position expression in the
// function's returns is a status constructor or the rpcStatus boundary.
func returnsStatusTyped(fn *ast.FuncDecl, fset *token.FileSet, converters map[string]bool) []string {
	var bad []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		// Do NOT descend into a nested function literal. Its returns belong to
		// the closure — a `sort.Slice(..., func(i, j int) bool { return ... })`
		// comparator or a local helper — not to the RPC's error surface. An
		// earlier revision of this test descended, and reported `return true`
		// from a sort comparator as a bare handler error. An over-reporting
		// guard is worse than none: it makes correct code look broken and the
		// remedy is to damage it.
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 {
			return true
		}
		last := ret.Results[len(ret.Results)-1]
		switch e := last.(type) {
		case *ast.Ident:
			if e.Name == "nil" {
				return true
			}
		case *ast.CallExpr:
			s := exprText(e.Fun)
			// A status constructor, the boundary converter, or a call whose own
			// return this delegates wholesale (checked at that function).
			// A status constructor, the boundary converter, a package-local
			// converter whose own returns this test also checks, or delegation
			// to another handler that is itself in the census.
			if strings.HasPrefix(s, "status.") || s == "rpcStatus" || converters[s] {
				return true
			}
			if strings.HasPrefix(s, "s.") && converters[strings.TrimPrefix(s, "s.")] {
				return true
			}
		}
		bad = append(bad, fset.Position(ret.Pos()).String())
		return true
	})
	return bad
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	}
	return ""
}

func TestEveryRPCHandlerReturnsAStatusTypedError8629(t *testing.T) {
	rpcs := rpcSurfaceMethods(t)
	if len(rpcs) < 20 {
		t.Fatalf("the generated service interface yielded only %d RPC names — the "+
			"parse is broken, and every assertion below would hold vacuously "+
			"against an empty census (#8629)", len(rpcs))
	}

	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	type fnRec struct {
		decl *ast.FuncDecl
		name string
	}
	var all []fnRec
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range af.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				all = append(all, fnRec{fn, fn.Name.Name})
			}
		}
	}

	// FIXPOINT. A function is "status-clean" when every error it returns is a
	// status constructor or a call to another status-clean function. Iterating
	// to a fixpoint is what lets the census accept the package's own converters
	// — configMutationStatus, dataplaneActionError, diagExecError — and
	// delegation between handlers, WITHOUT a hand-maintained allowlist that
	// could quietly bless a converter that returns a bare error.
	clean := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, r := range all {
			if clean[r.name] {
				continue
			}
			if len(returnsStatusTyped(r.decl, fset, clean)) == 0 {
				clean[r.name] = true
				changed = true
			}
		}
	}

	handlers, statusReturning := 0, 0
	var offenders []string
	for _, r := range all {
		if r.decl.Recv == nil || !rpcs[r.name] {
			continue
		}
		handlers++
		bad := returnsStatusTyped(r.decl, fset, clean)
		if len(bad) == 0 {
			statusReturning++
		}
		for _, b := range bad {
			offenders = append(offenders, r.name+" at "+b)
		}
	}

	// DEGENERATE-FAILURE GUARD 1: a scan that matched no handlers passes every
	// assertion below, and that is indistinguishable from a clean tree.
	if handlers < 20 {
		t.Fatalf("only %d RPC handlers were matched in this package against %d "+
			"names in the service interface. The scan is broken; a clean result "+
			"here would mean nothing (#8629)", handlers, len(rpcs))
	}
	// DEGENERATE-FAILURE GUARD 2: if NOTHING is recognised as status-typed, the
	// recogniser is broken rather than the tree being perfect.
	if statusReturning == 0 {
		t.Fatalf("not one of %d handlers was recognised as returning a "+
			"status-typed error. The recogniser is broken (#8629)", handlers)
	}

	if len(offenders) > 0 {
		t.Errorf("%d RPC handler return(s) yield a BARE error, which gRPC surfaces "+
			"as codes.Unknown — a caller cannot tell a malformed request from a "+
			"server fault, and the error text a user sees says `code = Unknown`:\n  %s\n\n"+
			"Return status.Error/status.Errorf with the code that says what the "+
			"CALLER should do next: InvalidArgument when the request is wrong, "+
			"Internal when the server failed to produce an answer it should have. "+
			"Do NOT reach for Unavailable or FailedPrecondition unless the retry "+
			"contract is actually known — a wrong Unavailable is a retry storm "+
			"against a permanent failure. For a handler that dispatches to many "+
			"helpers, convert once at the boundary with rpcStatus rather than at "+
			"each site (#8629).",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}
