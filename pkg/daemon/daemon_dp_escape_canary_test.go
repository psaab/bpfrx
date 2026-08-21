package daemon

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

// #2114 (Codex PR #6743 r4-F4, rebuilt in r2 for B2): the COMPLETENESS
// canary for the management-surface conversion.
//
// The behavioural binders (daemon_dp_escape_test.go for gRPC,
// daemon_dp_escape_rest_test.go for REST) prove the live indirection
// actually works end to end. They cannot prove that the THIRD converted
// site — the console CLI, which only runs under isInteractive() and so has
// no unit-reachable startup path — still uses it, nor that a FOURTH
// management consumer added later will.
//
// WHY THIS FILE WAS REBUILT. The r4 scanner asked two questions:
// "does this function DECLARE a variable of a probe type (an
// *ast.ValueSpec whose Type is an Ident)?" and "does its body mention the
// NAME liveDataplane anywhere?". Both are proxies for the real property,
// and both were escapable at daemon_run.go's console-CLI site. Measured at
// 710a87569, `go build ./...` rc 0, `go test ./pkg/daemon/` rc 0 for BOTH:
//
//	C6 (declaration FORM). Replace the two-statement wiring with
//	    `cliDP, _ := d.dataplane().(cliDataPlane)`. A `:=` carrying a
//	    TypeAssertExpr has no ValueSpec, so the old declaredProbeTypesIn
//	    matched nothing and the function was skipped entirely. SURVIVOR.
//
//	C7 (callee-NAME satisfaction). Keep `var cliDP cliDataPlane`, add
//	    `_, _ = d.liveDataplane()` with the result DISCARDED, and wire
//	    `cliDP, _ = rt.(cliDataPlane)` from d.dataplane(). The old
//	    callsLiveDataplaneIn found the name and exempted the function.
//	    SURVIVOR.
//
// This is the sixth instance of one family in this campaign — a matcher
// keyed on a NAME or a declaration FORM where the property is about a
// POSITION or a DATA FLOW (#6676 binding_slot callee substitution, #6706
// `*x.field = CLI{}` write form, #6871 method value, #7003 clamp-helper
// `call.Fun.(*ast.Ident)`-only, #7004 text-level grep). The rebuild
// follows #6871's fix: classify every reference by POSITION after
// unwrapping, and decide on DATA FLOW rather than on the enclosing
// declaration.
//
// WHAT IS ASSERTED NOW, in five rules:
//
//	R1 (no re-derivation). A type assertion to a management-probe type in
//	   a production file outside the declaration allowlist is a violation,
//	   in ANY enclosing declaration form. liveDataplane() already returns a
//	   value that satisfies all three probes structurally; an assertion
//	   means the probe is being re-derived from an untyped runtime handle,
//	   which is the capture-once escape in every spelling. Kills C6 and C7
//	   at the position, not at the form.
//
//	R2 (data flow, not name presence). Every assignment to a probe-typed
//	   variable must have a live-DERIVED right-hand side: the value must
//	   come, transitively within the function, from a call to
//	   liveDataplane(). A discarded call satisfies nothing. Kills C7 a
//	   second time, independently of R1.
//
//	R3 (the consumer's DP field). A value written to a field named `DP`
//	   must be a live-derived identifier, in EVERY write form that names
//	   the field: a `DP:` key in a composite literal of any type, qualified
//	   or not, and an assignment through a selector ending in `.DP`
//	   (`cfg.DP`, `(*p).DP`, `d.held.cfg.DP`). Keyed on the field NAME, not
//	   on a registry of consumer packages and not on the literal's shape.
//	   Both narrowings shipped a measured escape: the registry (retired in
//	   r5) exempted a fourth consumer with its own config type, and the
//	   shape requirement (dropped in r6) exempted the SAME consumer written
//	   as `cfg.DP = probe`, whole package green.
//
//	R4 (the console consumer). A call to cli.New must pass at least one
//	   argument that is BOTH declared with a management-probe type in that
//	   function AND live-derived. Keyed on the ARGUMENT SET rather than on
//	   an index, so a signature reorder cannot make it check the wrong
//	   parameter; the residual is that a site could satisfy it with a
//	   decoy argument while passing something stale as DP, which R1+R2
//	   already make hard to construct.
//
//	R5 (deferred execution is not derivation). An assignment that sits
//	   inside a FuncLit which is NOT invoked in place — `go func(){…}()`,
//	   `defer func(){…}()`, a literal stored or passed on — does not make
//	   its target live, and is reported. Added in r2 after C8g, below.
//
// STATED SCOPE — and one thing this canary CANNOT do.
//
// This is syntactic. It is deliberately NOT a reachability claim, and it
// does not follow a probe value out of the function that built it: a
// helper that wraps liveDataplane() and returns the probe would be
// reported by R2 at its caller, which is the intended strictness — add the
// helper to managementProbeDeclFiles, with a reason, or call liveDataplane
// directly.
//
// More importantly: THE AST CANNOT ESTABLISH TEMPORAL CONTAINMENT IN
// GENERAL. R2 proves a value CAME FROM liveDataplane(); only R5's
// syntactic special-case says anything about WHEN, and it does so by
// enumerating the deferring forms (`go`, `defer`, a literal that is not
// immediately invoked) rather than by deriving execution order.
//
// A wiring that crosses a function boundary is NOT one of the gaps, at
// EITHER consumer, and the reason is structural rather than incidental:
// R3 and R4 both require the value to be live-derived IN THE CALLER BODY
// (liveness is computed per-function), and neither analyses the callee at
// all. Moving the assignment into a helper therefore DEFEATS the rule
// rather than escaping it, whatever the helper's shape. Both sites were
// built and measured, not reasoned about:
//
//   - gRPC (R3): a helper writing the probe through a pointer into the
//     config literal. The canary redded, naming startGRPCServer.
//   - console CLI (R4): both readings of `go d.wireConsole()` —
//     `go d.wireConsole(&cliDP)` with a pointer-writing helper, and the
//     literal no-argument form with the probe hoisted to package scope.
//     Each redded with R4's message, "daemon_run.go:Run calls cli.New
//     without passing a management-probe value derived from
//     liveDataplane()".
//
// An earlier revision listed that console-CLI site among the gaps, as
// "unclaimed ... and not tested in either direction". It was false, and
// false in the dangerous direction: a hedge placed inside a list of
// limitations is not read as a hedge, it is read as a limitation, and it
// invites the next reader to skip the behavioural half believing the AST
// half cannot reach the site.
//
// WHAT REMAINS OUTSIDE R1-R5. An earlier revision said "ONE thing". That
// number came from re-counting the members of a list nobody had checked
// for completeness, which made it more precise and no more true — and
// "one" reads as audited in a way "two" did not. The bound is stated as a
// PREDICATE here instead.
//
// R1 and R2 only see a type that is in managementProbeTypes, so before r5
// the whole analysis was gated on a hand-maintained 3-entry literal that
// no test bound to reality, and R3 on a 2-entry one. A FOURTH management
// consumer wired capture-once with its OWN probe type therefore escaped
// every rule. Measured at 44603f888: a fourth consumer added to Run(),
// sourced through a type assertion — precisely the escape R1 exists to
// kill — and handed to its own Config{DP: ...}, left pkg/daemon at rc=0
// with 0 FAIL. R1 missed (type not in the map), R3 missed (config not in
// the map), R4 missed (not cli.New). Two INDEPENDENT closures in r5:
//
//   - TestManagementProbeRegistryIsComplete PARSES the probe declaration
//     files and reports any interface they declare that is in NEITHER
//     managementProbeTypes nor managementProbeNonConsumerTypes. The
//     population is bounded by the source rather than by a memory:
//     declaring a seventh probe without classifying it reds the suite, and
//     classifying it as a management probe puts it under R1 and R2.
//   - R3 no longer consults a registry of consumer packages at all. It
//     keys on the FIELD — a value written to a field named `DP` must be
//     live-derived, whatever package or type name the consumer wears.
//     managementConsumerConfigs is retired.
//
// R6-B2 CORRECTION, and it is the second time this paragraph has been
// wrong in the same way. r5 wrote the residual as a conjunction whose
// FIRST conjunct — "takes its probe as a plain call argument rather than a
// `DP:` field" — was not required. Measured at 74ece3ff5 in real
// pkg/daemon/daemon_run_servers.go: a fourth consumer whose probe DOES
// reach a `DP:` field escaped anyway, because r5's R3 keyed on the LITERAL
// SHAPE (a KeyValueExpr inside a package-qualified *ast.CompositeLit)
// rather than on the field. `cfg := mgmt.Config{DP: probe}` redded by
// name; `var cfg mgmt.Config; cfg.DP = probe` — one line, same consumer,
// same stale value — left the WHOLE of pkg/daemon at rc=0. R2 could not
// carry it either: its liveness fixpoint filters on `lhs.(*ast.Ident)`,
// and a field write is a SelectorExpr.
//
// R3 now keys on the field NAME in every write form that names it: a `DP:`
// key in a composite literal of ANY type, qualified or not, and an
// assignment through a selector ending in `.DP`, whatever the receiver's
// shape. Each form is pinned by a self-test row, in both directions.
//
// TWO things genuinely remain, and both are properties of the rules rather
// than entries on a list:
//
//   - Runtime-control-flow ordering. R5 enumerates the SYNTACTIC deferring
//     forms; an ordering established by a channel handshake, a sync.Once,
//     or a conditional that only assigns on a path taken later is not
//     syntax and is not seen.
//   - A hand-over that NEVER NAMES THE FIELD. R3 is name-keyed, so it sees
//     nothing in `mgmt.Config{store, probe}` (a positional literal has no
//     `DP` token) or in `newThing(store, probe)` (a plain call argument);
//     R4 covers exactly one call site, `cli.New`, because "this call is a
//     management consumer" has no syntactic signature the way a field name
//     does. Such a consumer escapes the whole fence only if it ALSO
//     declares its probe type outside the two declaration files — declared
//     inside them, the completeness test forces registration and R1/R2
//     apply to it. Do not restate this as a conjunction with a fourth
//     term: a term is only in the predicate if removing it lets something
//     through, which is what r5's first conjunct failed. The positional
//     form is pinned CLEAN by the `residual/` self-test row, so teaching
//     R3 to resolve field positions reds that row and forces this
//     paragraph to be rewritten rather than left to go stale.
//
// Do not read a green run as "the probe is live at the instant the
// consumer uses it". Read it as "no probe value in a production function
// body is sourced from anywhere other than an in-place liveDataplane()
// call". The behavioural half — TestConsoleCLIProbeWiringFollowsTheCell,
// below, plus the gRPC/REST server binders — is what says the wiring
// actually works; neither half alone covers the console-CLI site.
//
// The console-CLI site's BEHAVIOURAL half is
// TestConsoleCLIProbeWiringFollowsTheCell, below: it drives the site's
// exact two-statement wiring through the cliDataPlane interface across a
// disown and a republication. Together the two say "this wiring has the
// live property" (behavioural) and "the production site uses this wiring"
// (structural). Neither alone covers the site, because isInteractive()
// makes the real block unreachable from a unit test.

// managementProbeTypes are the daemon-local probe types whose values are
// handed to a LONG-LIVED downstream consumer (grpcapi.Server.dp,
// api.Server.dp, cli.CLI.dp). R1 and R2 see a function only through this
// map, so an omission here is not a narrower check — it is NO check.
//
// #6743 r5-B2: this map and managementProbeNonConsumerTypes below must
// between them account for EVERY interface the declaration files declare.
// TestManagementProbeRegistryIsComplete enforces that by parsing them, so
// a probe added to runtime_probes.go and forgotten here reds the suite
// instead of silently leaving its consumer unanalysed.
var managementProbeTypes = map[string]bool{
	"apiDataPlane":  true,
	"grpcDataPlane": true,
	"cliDataPlane":  true,
}

// managementProbeNonConsumerTypes are the interfaces the declaration files
// declare that are deliberately NOT management probes, each with the reason
// it is exempt. Being listed here is a CLAIM that the type's values are
// never stored by a long-lived consumer; it is the only way to keep an
// interface out of managementProbeTypes.
var managementProbeNonConsumerTypes = map[string]string{
	"dataplaneReadyProbe":  "lifecycle gate, called inline within one statement; never stored",
	"natSeeder":            "post-Start map seeding, called inline; never stored",
	"fibSyncStarter":       "StartFIBSync, called inline; never stored",
	"liveDataPlaneSurface": "the UNION liveDataPlane forwards to, not a value handed to a consumer",
}

// managementProbeDeclFiles are the files allowed to name a management
// probe type WITHOUT sourcing it from liveDataplane: the declaration site
// and the live adapter's own compile-time assertions.
//
// The SAME set scopes the r5 completeness scan, deliberately: the files
// that may name a probe freely are exactly the files whose interface
// declarations must be classified, so the exemption and the obligation
// cannot drift apart.
var managementProbeDeclFiles = map[string]bool{
	"runtime_probes.go": true,
	"daemon_dp_live.go": true,
}

// captureOnceProbeViolations reports every production function that takes
// a management-probe value from anywhere other than liveDataplane().
func captureOnceProbeViolations(t *testing.T, root string) []string {
	t.Helper()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var violations []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if managementProbeDeclFiles[name] {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(root, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, v := range probeWiringViolations(fn.Body) {
				violations = append(violations, name+":"+fn.Name.Name+" "+v)
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// unwrapTypeExpr strips the wrappers that can sit between a reference and
// the identifier naming the type, so a match is decided on the NAME rather
// than on the spelling: parentheses, a pointer star, and generic
// instantiation in both its single- and multi-argument forms.
func unwrapTypeExpr(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		default:
			return e
		}
	}
}

// probeTypeNameOf returns the management-probe type e names, or "".
func probeTypeNameOf(e ast.Expr) string {
	ident, ok := unwrapTypeExpr(e).(*ast.Ident)
	if !ok || !managementProbeTypes[ident.Name] {
		return ""
	}
	return ident.Name
}

// isLiveDataplaneCall reports whether e is a call to x.liveDataplane().
// It matches on the CALLEE POSITION — call.Fun — after unwrapping, so a
// mention of the name anywhere else in the expression (C7's discarded
// call, a comment, a string) does not qualify.
func isLiveDataplaneCall(e ast.Expr) bool {
	call, ok := unwrapTypeExpr(e).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := unwrapTypeExpr(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "liveDataplane"
}

// probeWiring is the per-function analysis both the fence and its
// self-test drive.
type probeWiring struct {
	// declared maps an identifier name to the probe type it was declared
	// with, for every `var x P` / parameter / named result in the body.
	declared map[string]string
	// live is the set of identifiers whose value came, transitively, from
	// a liveDataplane() call.
	live map[string]bool
	// assigns records every assignment to a declared probe-typed variable.
	assigns []probeAssign
	// asserts records every type assertion to a probe type (R1).
	asserts []string
}

type probeAssign struct {
	name string
	live bool
	via  string
}

// analyzeProbeWiring walks body once for declarations and assertions, then
// runs the live-derivation to a fixpoint (an assignment can make an
// identifier live for an assignment that appeared EARLIER in the source —
// a loop, or a closure — so a single pass would under-report liveness and
// over-report violations).
func analyzeProbeWiring(body *ast.BlockStmt) *probeWiring {
	w := &probeWiring{declared: map[string]string{}, live: map[string]bool{}}

	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if name := probeTypeNameOf(x.Type); name != "" {
				for _, id := range x.Names {
					w.declared[id.Name] = name
				}
			}
		case *ast.FuncLit:
			// A nested literal's parameters and results can be
			// probe-typed too; record them so an assignment inside the
			// literal is judged against a declaration.
			recordProbeParams(x.Type, w.declared)
		case *ast.TypeAssertExpr:
			// R1: position is the assertion's TYPE, regardless of what
			// declaration encloses it.
			if name := probeTypeNameOf(x.Type); name != "" {
				w.asserts = append(w.asserts, name)
			}
		}
		return true
	})

	deferred := deferredFuncLits(body)

	// Fixpoint over assignments. Only assignments whose execution is
	// lexically CONTAINED in this function's own straight-line flow can
	// confer liveness (R5) — see deferredFuncLits.
	for changed := true; changed; {
		changed = false
		forEachAssign(body, deferred, false, func(as *ast.AssignStmt, inDeferred bool) {
			if inDeferred {
				return
			}
			for i, lhs := range as.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				if !rhsIsLive(as, i) {
					continue
				}
				if !w.live[id.Name] {
					w.live[id.Name] = true
					changed = true
				}
			}
		})
		// Propagate through plain ident copies.
		forEachAssign(body, deferred, false, func(as *ast.AssignStmt, inDeferred bool) {
			if inDeferred || len(as.Lhs) != len(as.Rhs) {
				return
			}
			for i, lhs := range as.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name == "_" || w.live[id.Name] {
					continue
				}
				src, ok := unwrapTypeExpr(as.Rhs[i]).(*ast.Ident)
				if ok && w.live[src.Name] {
					w.live[id.Name] = true
					changed = true
				}
			}
		})
	}

	// Record every assignment to a DECLARED probe-typed variable, with the
	// liveness verdict the fixpoint reached.
	forEachAssign(body, deferred, false, func(as *ast.AssignStmt, inDeferred bool) {
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			if _, isProbe := w.declared[id.Name]; !isProbe {
				continue
			}
			via := describeRHS(as, i)
			live := rhsIsLive(as, i) || rhsIsLiveIdent(as, i, w.live)
			if inDeferred {
				// R5: the value IS live-derived, but the derivation runs
				// later. Report it with its own wording so the report says
				// what is actually wrong.
				live = false
				via = via + " inside a FuncLit that is not invoked here " +
					"(go/defer/stored), so the consumer sees the zero value"
			}
			w.assigns = append(w.assigns, probeAssign{name: id.Name, live: live, via: via})
		}
	})
	return w
}

// deferredFuncLits returns the FuncLit nodes in body whose execution is NOT
// lexically contained in the enclosing function's own straight-line flow:
// a literal launched with `go`, scheduled with `defer`, stored in a
// variable or field, returned, or passed as an argument.
//
// #6743 r2-B2, the SEVENTH escape class in this campaign (first found on
// #6871): callee position proves that a value CAME FROM liveDataplane(),
// and says nothing about WHEN. Measured at 710a87569 against the rebuilt
// R1-R4 scanner, `go func() { if live, ok := d.liveDataplane(); ok { cliDP
// = live } }()` at daemon_run.go left pkg/daemon FULL_RC=0: the assertion
// rule sees no assertion, the data-flow rule sees a genuine
// liveDataplane()-derived right-hand side, and the argument rule sees a
// live-derived probe passed to cli.New — while at the instant cli.New
// actually runs cliDP is still the nil zero value (and the write races the
// read).
//
// An immediately-invoked literal `func() { ... }()` IS contained, so it
// stays creditable; `go func(){...}()` and `defer func(){...}()` are not,
// because the CallExpr they wrap is executed by the GoStmt/DeferStmt
// rather than in place.
func deferredFuncLits(body ast.Node) map[*ast.FuncLit]bool {
	// Calls executed by go/defer rather than in place.
	scheduled := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GoStmt:
			scheduled[x.Call] = true
		case *ast.DeferStmt:
			scheduled[x.Call] = true
		}
		return true
	})

	immediate := map[*ast.FuncLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || scheduled[call] {
			return true
		}
		if fl, ok := unwrapTypeExpr(call.Fun).(*ast.FuncLit); ok {
			immediate[fl] = true
		}
		return true
	})

	out := map[*ast.FuncLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if fl, ok := n.(*ast.FuncLit); ok && !immediate[fl] {
			out[fl] = true
		}
		return true
	})
	return out
}

// forEachAssign visits every AssignStmt under n, reporting whether it sits
// inside a deferred (non-immediately-invoked) FuncLit. Nested literals
// inside a deferred one stay deferred.
func forEachAssign(
	n ast.Node,
	deferred map[*ast.FuncLit]bool,
	inDeferred bool,
	fn func(*ast.AssignStmt, bool),
) {
	ast.Inspect(n, func(node ast.Node) bool {
		if node == nil {
			return false
		}
		if fl, ok := node.(*ast.FuncLit); ok && deferred[fl] && !inDeferred {
			forEachAssign(fl.Body, deferred, true, fn)
			return false
		}
		if as, ok := node.(*ast.AssignStmt); ok {
			fn(as, inDeferred)
		}
		return true
	})
}

// recordProbeParams records probe-typed parameters and named results.
func recordProbeParams(ft *ast.FuncType, into map[string]string) {
	if ft == nil {
		return
	}
	for _, fl := range []*ast.FieldList{ft.Params, ft.Results} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			name := probeTypeNameOf(f.Type)
			if name == "" {
				continue
			}
			for _, id := range f.Names {
				into[id.Name] = name
			}
		}
	}
}

// rhsIsLive reports whether the value assigned to Lhs[i] comes directly
// from a liveDataplane() call. The tuple form `v, ok := d.liveDataplane()`
// makes only index 0 live — `ok` is a bool.
func rhsIsLive(as *ast.AssignStmt, i int) bool {
	if len(as.Rhs) == 1 && len(as.Lhs) > 1 {
		return i == 0 && isLiveDataplaneCall(as.Rhs[0])
	}
	if i < len(as.Rhs) {
		return isLiveDataplaneCall(as.Rhs[i])
	}
	return false
}

// rhsIsLiveIdent reports whether the value assigned to Lhs[i] is a copy of
// an already-live identifier.
func rhsIsLiveIdent(as *ast.AssignStmt, i int, live map[string]bool) bool {
	if len(as.Lhs) != len(as.Rhs) || i >= len(as.Rhs) {
		return false
	}
	id, ok := unwrapTypeExpr(as.Rhs[i]).(*ast.Ident)
	return ok && live[id.Name]
}

// describeRHS names the shape of the assigned expression for the report.
func describeRHS(as *ast.AssignStmt, i int) string {
	var e ast.Expr
	if len(as.Rhs) == 1 && len(as.Lhs) > 1 {
		e = as.Rhs[0]
	} else if i < len(as.Rhs) {
		e = as.Rhs[i]
	}
	switch x := unwrapTypeExpr(e).(type) {
	case nil:
		return "an unrecognized expression"
	case *ast.TypeAssertExpr:
		return "a type assertion"
	case *ast.CallExpr:
		if sel, ok := unwrapTypeExpr(x.Fun).(*ast.SelectorExpr); ok && sel.Sel != nil {
			return "a call to " + sel.Sel.Name + "()"
		}
		return "a call"
	case *ast.Ident:
		return "the identifier " + x.Name
	case *ast.SelectorExpr:
		if x.Sel != nil {
			return "the field/selector " + x.Sel.Name
		}
	}
	return "an expression that is not liveDataplane()"
}

// probeWiringViolations applies R1-R4 to one function body.
func probeWiringViolations(body *ast.BlockStmt) []string {
	w := analyzeProbeWiring(body)
	var out []string

	// R1: no re-derivation of a probe by assertion.
	seenAssert := map[string]bool{}
	for _, name := range w.asserts {
		if seenAssert[name] {
			continue
		}
		seenAssert[name] = true
		out = append(out, "asserts "+name+" from an untyped runtime value; "+
			"the probe must come from liveDataplane(), which already satisfies it")
	}

	// R2: every assignment to a probe-typed variable must be live-derived.
	for _, a := range w.assigns {
		if a.live {
			continue
		}
		out = append(out, "assigns "+a.name+" ("+w.declared[a.name]+") from "+a.via+
			", not from liveDataplane()")
	}

	// R3 / R4: the consumer wiring sites.
	out = append(out, consumerWiringViolations(body, w)...)

	sort.Strings(out)
	return out
}

// compositeLitTypeName names the type a composite literal builds, for the
// report: "api.Config" for a qualified type, "localCfg" for an unqualified
// one, "" for an anonymous struct/map/slice literal.
//
// #6743 r6-B2: r5 REQUIRED the qualified form (`*ast.SelectorExpr`), which
// silently exempted every literal of a daemon-local type. The name is a
// report detail; it must not decide whether the rule looks.
func compositeLitTypeName(lit *ast.CompositeLit) string {
	switch t := unwrapTypeExpr(lit.Type).(type) {
	case *ast.SelectorExpr:
		if t.Sel == nil {
			return ""
		}
		if pkg, ok := t.X.(*ast.Ident); ok {
			return pkg.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// selectorWritesDPField reports whether lhs is a write THROUGH a selector
// to a field named DP — `cfg.DP`, `p.DP`, `(*p).DP`, `d.srv.DP` — and
// names the receiver for the report. The receiver's shape is irrelevant to
// the verdict; only the field name is the signature.
func selectorWritesDPField(lhs ast.Expr) (string, bool) {
	sel, ok := unwrapTypeExpr(lhs).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "DP" {
		return "", false
	}
	return receiverName(unwrapTypeExpr(sel.X)), true
}

// receiverName renders a selector's receiver as a dotted path, so the
// report says WHICH value was written rather than just "a struct".
func receiverName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if x.Sel == nil {
			return "a value"
		}
		return receiverName(unwrapTypeExpr(x.X)) + "." + x.Sel.Name
	case *ast.CallExpr:
		return receiverName(unwrapTypeExpr(x.Fun)) + "()"
	case *ast.IndexExpr:
		return receiverName(unwrapTypeExpr(x.X)) + "[...]"
	}
	return "a value"
}

// consumerWiringViolations applies R3 (a write to a consumer's DP field)
// and R4 (cli.New argument set).
//
// R3 keys on the FIELD NAME, in EVERY form that names it: a `DP:` key in a
// composite literal of any type, qualified or not, and an assignment
// through a selector ending in `.DP`. It does NOT key on the literal's
// shape — that was the r5 defect, measured in r6-B2: the same fourth
// consumer that redded as `api.Config{DP: probe}` went GREEN, whole
// package, as `var cfg api.Config; cfg.DP = probe`. R3 never visited the
// AssignStmt and R2 skipped it, because R2's liveness fixpoint filters on
// `lhs.(*ast.Ident)` and a field write is a SelectorExpr.
//
// What a name-keyed rule still cannot see is a hand-over that never names
// the field: a POSITIONAL literal (`consumer.Config{store, probe}`) or a
// plain call argument. That is the honest residual, stated at the head of
// this file and pinned by the `residual/` fixture rows.
func consumerWiringViolations(body *ast.BlockStmt, w *probeWiring) []string {
	var out []string
	report := func(what string) {
		out = append(out, what+" with a DP value that is not derived from liveDataplane()")
	}
	valueIsLive := func(e ast.Expr) bool {
		id, ok := unwrapTypeExpr(e).(*ast.Ident)
		return ok && w.live[id.Name]
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			// R3, field-write form. `cfg.DP = probe` is the one-line
			// escape r5 shipped: it hands the SAME stale probe to the SAME
			// consumer as the composite-literal form and was invisible to
			// every rule.
			for i, lhs := range x.Lhs {
				recv, ok := selectorWritesDPField(lhs)
				if !ok {
					continue
				}
				var rhs ast.Expr
				if len(x.Rhs) == 1 && len(x.Lhs) > 1 {
					// A tuple RHS makes only index 0 the probe; every
					// other index is some other result, so a `.DP` at
					// index > 0 is reported rather than credited.
					if i == 0 {
						rhs = x.Rhs[0]
					}
				} else if i < len(x.Rhs) {
					rhs = x.Rhs[i]
				}
				if rhs == nil || !valueIsLive(rhs) {
					report("assigns the DP field of " + recv)
				}
			}
		case *ast.CompositeLit:
			// R3, keyed-literal form. r5-B2 retired the 2-entry
			// managementConsumerConfigs registry that had made a FOURTH
			// management consumer with its own config type invisible
			// (measured at 44603f888, pkg/daemon rc=0); r6-B2 drops the
			// remaining requirement that the type be package-qualified.
			name := compositeLitTypeName(x)
			for _, elt := range x.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "DP" {
					continue
				}
				if !valueIsLive(kv.Value) {
					if name == "" {
						report("builds an anonymous literal")
					} else {
						report("builds " + name)
					}
				}
			}
		case *ast.CallExpr:
			sel, ok := unwrapTypeExpr(x.Fun).(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != "New" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "cli" {
				return true
			}
			for _, arg := range x.Args {
				id, ok := unwrapTypeExpr(arg).(*ast.Ident)
				if !ok {
					continue
				}
				if _, declaredProbe := w.declared[id.Name]; declaredProbe && w.live[id.Name] {
					return true
				}
			}
			out = append(out, "calls cli.New without passing a management-probe value "+
				"derived from liveDataplane()")
		}
		return true
	})
	return out
}

// TestManagementProbesComeFromLiveDataplane is the whole-package fence.
// It covers the CLI site in daemon_run.go, which the behavioural binders
// cannot reach.
//
// Fail-on-revert: restore the capture-once wiring at ANY of the three call
// sites (startGRPCServer, startHTTPServer, or the isInteractive() block in
// Run) in ANY spelling — a `var` declaration re-sourced from
// d.dataplane(), a `:=` carrying the type assertion, or a discarded
// liveDataplane() call next to an assertion — and that function is
// reported here.
func TestManagementProbesComeFromLiveDataplane(t *testing.T) {
	t.Parallel()

	if v := captureOnceProbeViolations(t, "."); len(v) > 0 {
		t.Fatalf("management-probe values taken as a capture-once snapshot instead of the "+
			"#2114 live indirection:\n%s", strings.Join(v, "\n"))
	}
}

// declaredInterfaceNames returns every interface type name one file
// declares. Parse failures — including a file that has been renamed out
// from under managementProbeDeclFiles — are fatal rather than skipped, so
// the completeness check cannot go vacuously green by finding nothing.
func declaredInterfaceNames(t *testing.T, path string) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name == nil {
				continue
			}
			if _, ok := ts.Type.(*ast.InterfaceType); ok {
				out = append(out, ts.Name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// unclassifiedProbeDecls reports every interface declared in the probe
// declaration files that appears in NEITHER registry.
func unclassifiedProbeDecls(t *testing.T, root string) []string {
	t.Helper()

	var out []string
	for file := range managementProbeDeclFiles {
		for _, name := range declaredInterfaceNames(t, filepath.Join(root, file)) {
			if managementProbeTypes[name] {
				continue
			}
			if _, exempt := managementProbeNonConsumerTypes[name]; exempt {
				continue
			}
			out = append(out, file+":"+name)
		}
	}
	sort.Strings(out)
	return out
}

// TestManagementProbeRegistryIsComplete binds managementProbeTypes to the
// SOURCE (#6743 r5-B2).
//
// R1 and R2 see a function only through managementProbeTypes, so a probe
// type that is not in it is not checked more loosely — it is not checked at
// all. Until r5 nothing bound that map to reality: both it and the retired
// managementConsumerConfigs appeared exactly twice in the tree, at their
// declaration and their single use site, and a FOURTH management consumer
// with its own probe type left pkg/daemon at rc=0 with 0 FAIL.
//
// This test makes the population bounded by the source instead. Every
// interface the declaration files declare must be classified: a management
// probe (managementProbeTypes, hence under R1/R2), or an explicit
// non-consumer with a stated reason (managementProbeNonConsumerTypes).
// There is no third outcome — in particular, no "silently unclassified".
//
// FAIL-ON-REVERT: declare a seventh interface in runtime_probes.go and
// leave it out of both maps. Bound in both directions by
// TestManagementProbeRegistryIsCompleteSelfTest.
func TestManagementProbeRegistryIsComplete(t *testing.T) {
	t.Parallel()

	if v := unclassifiedProbeDecls(t, "."); len(v) > 0 {
		t.Fatalf("probe interfaces declared but classified in NEITHER "+
			"managementProbeTypes nor managementProbeNonConsumerTypes:\n%s\n\n"+
			"A type missing from managementProbeTypes is invisible to R1 and R2, so its "+
			"consumer is not analysed at all. Add it there if its values are handed to a "+
			"long-lived consumer, or to managementProbeNonConsumerTypes with the reason "+
			"it is not.", strings.Join(v, "\n"))
	}
}

// TestManagementProbeRegistryIsCompleteSelfTest drives the completeness
// check in BOTH directions, so it cannot pass by having stopped looking.
func TestManagementProbeRegistryIsCompleteSelfTest(t *testing.T) {
	t.Parallel()

	// Both declaration files must exist in the fixture root: the scan is
	// scoped by managementProbeDeclFiles and a missing file is fatal.
	const classifiedOnly = `package daemon

type cliDataPlane interface{ IsLoaded() bool }
type natSeeder interface{ SeedNATPortCounters() }
`
	const withASeventh = classifiedOnly + `
type mgmtDataPlane interface{ IsLoaded() bool }
`

	t.Run("clean", func(t *testing.T) {
		dir := t.TempDir()
		writeProbeDeclFixture(t, dir, classifiedOnly, "package daemon\n")
		if v := unclassifiedProbeDecls(t, dir); len(v) > 0 {
			t.Fatalf("a fully classified fixture reported %v — the check reports types it "+
				"should accept, which would push maintainers to weaken it", v)
		}
	})

	t.Run("seventh-interface-unclassified", func(t *testing.T) {
		dir := t.TempDir()
		writeProbeDeclFixture(t, dir, withASeventh, "package daemon\n")
		got := unclassifiedProbeDecls(t, dir)
		if len(got) != 1 || !strings.Contains(got[0], "mgmtDataPlane") {
			t.Fatalf("an unclassified probe interface must be reported exactly once, got %v", got)
		}
	})

	t.Run("unclassified-in-the-other-decl-file", func(t *testing.T) {
		// The scan is scoped by managementProbeDeclFiles, not by the name
		// runtime_probes.go: the SECOND allowlisted file is where a probe
		// declaration would most plausibly go to dodge the first.
		dir := t.TempDir()
		writeProbeDeclFixture(t, dir, classifiedOnly,
			"package daemon\n\ntype sneakyDataPlane interface{ IsLoaded() bool }\n")
		got := unclassifiedProbeDecls(t, dir)
		if len(got) != 1 || !strings.Contains(got[0], "sneakyDataPlane") {
			t.Fatalf("an unclassified probe in daemon_dp_live.go must be reported, got %v", got)
		}
	})
}

// writeProbeDeclFixture writes one synthetic copy of each file the
// completeness scan reads.
// #6743 r6-B4: the two drift guards below overlap but are NOT redundant,
// and a sweep that deletes either leaves the suite green for a different
// reason each time. The membership check fires on a RENAME (the map still
// has two entries, but one of them is a file this fixture never writes);
// the length check fires on an ADDITION or a REMOVAL (the scan would read
// a file the fixture never created, or stop reading one it did). Neither
// covers the other's case, so both stay.
func writeProbeDeclFixture(t *testing.T, dir, probes, live string) {
	t.Helper()

	for name, src := range map[string]string{
		"runtime_probes.go": probes,
		"daemon_dp_live.go": live,
	} {
		if !managementProbeDeclFiles[name] {
			t.Fatalf("fixture drift: %s is no longer in managementProbeDeclFiles, so this "+
				"self-test is writing a file the scan does not read", name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if got := len(managementProbeDeclFiles); got != 2 {
		t.Fatalf("fixture drift: managementProbeDeclFiles has %d entries, this self-test "+
			"writes 2; the scan would read a file the fixture never created", got)
	}
}

// probeCanaryFixture is one synthetic package the scanner is driven over.
type probeCanaryFixture struct {
	name string
	src  string
	// want is the substring set the report must contain; empty means the
	// fixture must be clean.
	want []string
}

// probeCanaryFixtures enumerates BOTH directions, and in particular the
// two forms that survived the r4 scanner. Each `bad` entry is a mutation a
// reviewer actually applied to daemon_run.go and measured green.
func probeCanaryFixtures() []probeCanaryFixture {
	const preamble = `package daemon

type cliDataPlane interface{ IsLoaded() bool }
type grpcDataPlane interface{ IsLoaded() bool }

type Daemon struct{}

func (d *Daemon) liveDataplane() (cliDataPlane, bool) { return nil, false }
func (d *Daemon) dataplane() any                      { return nil }
`
	return []probeCanaryFixture{
		{
			name: "live/production-shape",
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	if live, ok := d.liveDataplane(); ok {
		cliDP = live
	}
	_ = cliDP
}
`,
		},
		{
			name: "live/declared-but-never-assigned",
			// The --no-dataplane arm: the probe stays the zero value and
			// the consumer gets a genuine nil. Not capture-once, so clean.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	_ = cliDP
}
`,
		},
		{
			name: "bad/r4-original-capture-once",
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	if rt := d.dataplane(); rt != nil {
		if probe, ok := rt.(cliDataPlane); ok {
			cliDP = probe
		}
	}
	_ = cliDP
}
`,
			want: []string{"startShell asserts cliDataPlane", "assigns cliDP"},
		},
		{
			name: "bad/C6-define-with-type-assertion",
			// r2 B2 C6: no ValueSpec at all, so the r4 scanner skipped the
			// whole function. Caught by R1, which keys on the ASSERTION's
			// position rather than on the enclosing declaration.
			src: preamble + `
func (d *Daemon) startShell() {
	cliDP, _ := d.dataplane().(cliDataPlane)
	_ = cliDP
}
`,
			want: []string{"startShell asserts cliDataPlane"},
		},
		{
			name: "bad/C7-discarded-liveDataplane-call",
			// r2 B2 C7: the NAME liveDataplane is present and the r4
			// scanner exempted the function. Caught twice: by R1 on the
			// assertion, and by R2 because the discarded call makes
			// nothing live.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	_, _ = d.liveDataplane()
	if rt := d.dataplane(); rt != nil {
		cliDP, _ = rt.(cliDataPlane)
	}
	_ = cliDP
}
`,
			want: []string{"startShell asserts cliDataPlane", "assigns cliDP"},
		},
		{
			name: "bad/probe-taken-from-a-field",
			// No assertion at all — R2 alone must carry this one, which is
			// why R1 is not the whole rule.
			src: preamble + `
type holder struct{ saved cliDataPlane }

func (d *Daemon) startShell(h *holder) {
	var cliDP cliDataPlane
	cliDP = h.saved
	_ = cliDP
}
`,
			want: []string{"assigns cliDP"},
		},
		{
			name: "bad/config-DP-field-not-live",
			src: preamble + `
func (d *Daemon) startGRPCServer(stale grpcDataPlane) {
	_ = grpcapi.Config{DP: stale}
}
`,
			want: []string{"builds grpcapi.Config with a DP value"},
		},
		{
			name: "bad/fourth-consumer-own-probe-type-own-config",
			// #6743 r5-B2, the measured escape. A FOURTH management
			// consumer, with a probe type in no registry, sourced through a
			// type assertion — the exact shape R1 exists to kill — and
			// handed to its own config literal. Measured at 44603f888
			// against the registry-keyed rules: pkg/daemon rc=0, 0 FAIL.
			// R1 missed (mgmtDataPlane not in managementProbeTypes), R3
			// missed (mgmt.Config not in the retired
			// managementConsumerConfigs), R4 missed (not cli.New).
			//
			// Caught now by R3 alone, on the `DP:` FIELD — deliberately
			// WITHOUT registering mgmtDataPlane, so this row stays a
			// witness for the unregistered case rather than quietly
			// becoming an R1 row.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }

func (d *Daemon) startMgmt() {
	var mgmtDP mgmtDataPlane
	if rt := d.dataplane(); rt != nil {
		if probe, ok := rt.(mgmtDataPlane); ok {
			mgmtDP = probe
		}
	}
	_ = mgmt.Config{DP: mgmtDP}
}
`,
			want: []string{"builds mgmt.Config with a DP value"},
		},
		{
			name: "live/fourth-consumer-with-a-live-probe",
			// The same fourth consumer wired correctly must stay clean, or
			// the widened R3 is a rule that cannot be satisfied.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }

func (d *Daemon) startMgmt() {
	var mgmtDP cliDataPlane
	if live, ok := d.liveDataplane(); ok {
		mgmtDP = live
	}
	_ = mgmt.Config{DP: mgmtDP}
}
`,
		},
		{
			name: "bad/fourth-consumer-field-assignment",
			// #6743 r6-B2, the ONE-LINE escape r5 shipped. The SAME fourth
			// consumer as the row above, differing only in how the probe
			// reaches the field: `cfg.DP = probe` instead of
			// `mgmt.Config{DP: probe}`. Measured at 74ece3ff5 in real
			// pkg/daemon/daemon_run_servers.go — the composite-literal
			// spelling redded by name, the field-assignment spelling left
			// `go test ./pkg/daemon/ -count=1` at rc=0 with the WHOLE
			// package green and every TestManagementProbe* passing.
			//
			// Mechanism: r5's R3 inspected only *ast.CompositeLit for a
			// KeyValueExpr keyed DP. A field write is an *ast.AssignStmt
			// with an *ast.SelectorExpr LHS, which R3 never visited and R2
			// skips because its liveness fixpoint filters on
			// `lhs.(*ast.Ident)`. R3 now keys on the FIELD NAME in both
			// write forms.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }

func (d *Daemon) startMgmt() {
	var mgmtDP mgmtDataPlane
	if rt := d.dataplane(); rt != nil {
		if probe, ok := rt.(mgmtDataPlane); ok {
			mgmtDP = probe
		}
	}
	var cfg mgmt.Config
	cfg.DP = mgmtDP
}
`,
			want: []string{"assigns the DP field of cfg"},
		},
		{
			name: "live/fourth-consumer-field-assignment-live",
			// The field-write form wired correctly must stay clean, or the
			// new arm is a rule that cannot be satisfied. This is the
			// positive control WITHOUT it, `want: nil` on the row above
			// would be satisfiable by a rule that reports every `.DP`
			// write unconditionally.
			src: preamble + `
func (d *Daemon) startMgmt() {
	var mgmtDP cliDataPlane
	if live, ok := d.liveDataplane(); ok {
		mgmtDP = live
	}
	var cfg mgmt.Config
	cfg.DP = mgmtDP
}
`,
		},
		{
			name: "bad/fourth-consumer-through-a-pointer-field",
			// The same write reached through a pointer and a nested
			// selector. R3 keys on the field NAME, so the receiver's shape
			// — ident, pointer deref, nested selector — does not decide
			// whether the rule looks. Reaching a shape the r6 finding did
			// not name is the point: the finding named `cfg.DP = probe`.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }

func (d *Daemon) startMgmt(cfg *mgmt.Config) {
	var mgmtDP mgmtDataPlane
	if probe, ok := d.dataplane().(mgmtDataPlane); ok {
		mgmtDP = probe
	}
	(*cfg).DP = mgmtDP
	d.held.cfg.DP = mgmtDP
}
`,
			want: []string{
				"assigns the DP field of cfg",
				"assigns the DP field of d.held.cfg",
			},
		},
		{
			name: "bad/fourth-consumer-unqualified-config-type",
			// r5's R3 required the literal's TYPE to be package-qualified
			// (`*ast.SelectorExpr`), so a daemon-local config struct —
			// `localCfg{DP: probe}`, an *ast.Ident type — was exempt. The
			// r6 finding predicted this shape from the filters and did not
			// measure it; this row measures it and keeps it measured.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }
type localCfg struct{ DP mgmtDataPlane }

func (d *Daemon) startMgmt() {
	var mgmtDP mgmtDataPlane
	if probe, ok := d.dataplane().(mgmtDataPlane); ok {
		mgmtDP = probe
	}
	_ = localCfg{DP: mgmtDP}
}
`,
			want: []string{"builds localCfg with a DP value"},
		},
		{
			name: "residual/positional-literal-names-no-field",
			// THE HONEST RESIDUAL, pinned rather than described. R3 is
			// keyed on the field NAME; a positional composite literal
			// contains no `DP` token at all, so nothing in R1-R5 sees this
			// hand-over. It is recorded as CLEAN deliberately: if a later
			// round teaches R3 to resolve field positions, this row reds
			// and forces the residual paragraph at the head of this file
			// to be rewritten instead of quietly going stale.
			src: preamble + `
type mgmtDataPlane interface{ IsLoaded() bool }

func (d *Daemon) startMgmt() {
	var mgmtDP mgmtDataPlane
	if probe, ok := d.dataplane().(mgmtDataPlane); ok {
		mgmtDP = probe
	}
	_ = mgmt.Config{nil, mgmtDP}
}
`,
		},
		{
			name: "bad/cli.New-without-a-live-probe",
			src: preamble + `
func (d *Daemon) startShell(stale cliDataPlane) {
	_ = cli.New(nil, stale)
}
`,
			want: []string{"calls cli.New without passing a management-probe value"},
		},
		{
			name: "live/cli.New-with-a-live-probe",
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	if live, ok := d.liveDataplane(); ok {
		cliDP = live
	}
	_ = cli.New(nil, cliDP)
}
`,
		},
		{
			name: "bad/C8g-goroutine-deferred-wiring",
			// r2 B2 C8g, the SEVENTH escape class: every earlier rule is
			// satisfied — no assertion (R1), a genuinely liveDataplane()-
			// derived right-hand side (R2), a declared probe passed to
			// cli.New (R4) — but the assignment runs in a goroutine, so the
			// consumer is handed the nil zero value. Measured green against
			// the R1-R4 scanner at 710a87569; caught by R5.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	go func() {
		if live, ok := d.liveDataplane(); ok {
			cliDP = live
		}
	}()
	_ = cli.New(nil, cliDP)
}
`,
			want: []string{"assigns cliDP", "not invoked here"},
		},
		{
			name: "bad/C8d-defer-deferred-wiring",
			// The same class through `defer`: the wiring runs on the way
			// OUT of startShell, long after cli.New has taken the probe.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	defer func() {
		if live, ok := d.liveDataplane(); ok {
			cliDP = live
		}
	}()
	_ = cli.New(nil, cliDP)
}
`,
			want: []string{"assigns cliDP", "not invoked here"},
		},
		{
			name: "bad/C8s-stored-closure-wiring",
			// And through a literal that is merely STORED. Nothing invokes
			// it in this body at all, so the probe is never assigned here.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	wire := func() {
		if live, ok := d.liveDataplane(); ok {
			cliDP = live
		}
	}
	_ = wire
	_ = cli.New(nil, cliDP)
}
`,
			want: []string{"assigns cliDP", "not invoked here"},
		},
		{
			name: "live/immediately-invoked-literal-still-counts",
			// R5 must key on DEFERRAL, not on "a FuncLit is present". An
			// IIFE runs in place, so its wiring is as contained as the
			// straight-line form and must stay clean — otherwise the rule
			// is a second proxy (a FORM check) for the property it is
			// meant to encode.
			src: preamble + `
func (d *Daemon) startShell() {
	var cliDP cliDataPlane
	func() {
		if live, ok := d.liveDataplane(); ok {
			cliDP = live
		}
	}()
	_ = cli.New(nil, cliDP)
}
`,
		},
	}
}

// TestManagementProbesComeFromLiveDataplaneSelfTest drives the scanner in
// BOTH directions over synthetic fixtures, so a scanner that silently
// stopped matching cannot make the fence above vacuously green.
//
// The fixtures are parsed, not compiled: grpcapi.Config / cli.New have no
// import here and the scanner is purely syntactic, which is the point —
// it must classify the SHAPE without a type checker.
func TestManagementProbesComeFromLiveDataplaneSelfTest(t *testing.T) {
	t.Parallel()

	for _, fx := range probeCanaryFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(fx.src), 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			got := captureOnceProbeViolations(t, dir)
			if len(fx.want) == 0 {
				if len(got) > 0 {
					t.Fatalf("clean fixture reported violations: %v", got)
				}
				return
			}
			joined := strings.Join(got, "\n")
			for _, want := range fx.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("report %q does not contain %q — the scanner stopped matching "+
						"this escape shape", joined, want)
				}
			}
		})
	}
}

// TestManagementProbeCanaryAllowlistIsFileScoped keeps the exemption a
// FILE property: the declaration site may name a probe type freely, the
// same shape anywhere else may not.
func TestManagementProbeCanaryAllowlistIsFileScoped(t *testing.T) {
	t.Parallel()

	const captured = `package daemon

type cliDataPlane interface{ IsLoaded() bool }

type Daemon2 struct{}

func (d *Daemon2) dataplane() any { return nil }

func (d *Daemon2) startShell() {
	cliDP, _ := d.dataplane().(cliDataPlane)
	_ = cliDP
}
`
	plain := t.TempDir()
	if err := os.WriteFile(filepath.Join(plain, "elsewhere.go"), []byte(captured), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if v := captureOnceProbeViolations(t, plain); len(v) == 0 {
		t.Fatal("the same shape outside the allowlist must be reported")
	}

	exempt := t.TempDir()
	if err := os.WriteFile(filepath.Join(exempt, "runtime_probes.go"), []byte(captured), 0o644); err != nil {
		t.Fatalf("write exempt fixture: %v", err)
	}
	if v := captureOnceProbeViolations(t, exempt); len(v) > 0 {
		t.Fatalf("runtime_probes.go should be exempt, got %v", v)
	}
}

// TestConsoleCLIProbeWiringFollowsTheCell is the BEHAVIOURAL half of the
// console-CLI site's coverage (#6743 r2 B2).
//
// The site itself is inside `if isInteractive()` in Run(), so no unit test
// can execute it. What this test CAN do is drive the site's exact
// two-statement wiring — `var cliDP cliDataPlane` sourced from
// d.liveDataplane() — through the cliDataPlane INTERFACE and assert the
// resulting value follows the #2114 cell in both directions. The gRPC and
// REST sites have server-level binders (daemon_dp_escape_test.go,
// daemon_dp_escape_rest_test.go); this one had neither a behavioural nor a
// working structural guard, because cliDataPlane appears in production
// exactly once and the r4 canary could be escaped there twice.
//
// WHAT THIS DOES AND DOES NOT COVER. It binds "this wiring shape has the
// live property". It does NOT bind "daemon_run.go uses this wiring shape"
// — that is TestManagementProbesComeFromLiveDataplane's R1/R2/R4, above.
// Either one alone leaves the site reachable by a capture-once value.
func TestConsoleCLIProbeWiringFollowsTheCell(t *testing.T) {
	d := &Daemon{}

	// The console-CLI site's wiring, verbatim.
	var cliDP cliDataPlane
	if live, ok := d.liveDataplane(); ok {
		cliDP = live
	}
	if cliDP == nil {
		t.Fatal("liveDataplane() not offered on a default daemon: the console would be " +
			"wired with a nil probe and this test would prove nothing")
	}

	if cliDP.IsLoaded() {
		t.Fatal("IsLoaded() true on an empty cell")
	}

	backend := newEscapeRecorderDP("console")
	d.setDataplane(backend)
	if !cliDP.IsLoaded() {
		t.Fatal("IsLoaded() false after publication: the console probe was a startup " +
			"snapshot, so a backend armed after the shell started is invisible to it")
	}
	if err := cliDP.ClearPolicyCounters(); err != nil {
		t.Fatalf("ClearPolicyCounters() after publication: %v", err)
	}
	if n := backend.clearCalls.Load(); n != 1 {
		t.Fatalf("backend clear calls = %d, want 1", n)
	}

	// The disown the bootstrap-exit arm failure runs.
	d.setDataplane(nil)
	if cliDP.IsLoaded() {
		t.Fatal("IsLoaded() true after the cell was cleared")
	}
	if err := cliDP.ClearPolicyCounters(); err == nil {
		t.Fatal("ClearPolicyCounters() succeeded after the cell was cleared: the console " +
			"kept clearing counters on a backend the daemon had disowned — the exact " +
			"escape #2114 exists to close")
	}
	if n := backend.clearCalls.Load(); n != 1 {
		t.Fatalf("backend clear calls = %d after the disown, want it to stay 1", n)
	}
}
