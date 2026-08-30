package refactoraudit

import (
	"os/exec"
	"strings"
	"testing"
)

// #7297: `commit check` must not be able to reach pkg/dataplane's
// HOST-MUTATING compiler.
//
// #4960 is about pkg/dataplane's CompileConfig mutating the host mid-compile —
// compileZones creates VLANs and reconciles addresses before later phases can
// still fail. A validate-only path that reached it would mutate the host on a
// `commit check`, which is a defect independent of #4960's apply-side redesign
// (#7289).
//
// Today it does not. Store.CommitCheck -> compileTree -> compileTreeStrict
// reaches **pkg/config**'s CompileConfig — the AST-to-typed-structs compiler —
// which is a different function in a different package that happens to share a
// name with pkg/dataplane's CompileConfig(dp, cfg, ...).
//
// THAT SHARED NAME IS THE HAZARD, and it is why this guard exists. Two
// functions called CompileConfig, one of which mutates the host, both reachable
// from a config-compilation context, is precisely the shape where a future
// refactor routes the wrong one in and every existing test stays green —
// because the mutation is a side effect on the host, not a wrong return value.
//
// WHY AN IMPORT-CLOSURE CHECK RATHER THAN A CALL-PATH ONE. A call-path
// assertion pins the ONE route the issue traced and says nothing about a second
// one. Any route from pkg/configstore into the host-mutating compiler must pass
// through an import, so asserting the closure excludes pkg/dataplane covers
// every route including ones nobody has thought of. It is the property itself
// rather than a proxy for it.
//
// This is deliberately NOT a name-based enumeration of forbidden symbols —
// pkg/api's drain_scope_6827_test.go records why those rot (the corpus moves
// with the toolchain and the claim becomes unkeepable). An import closure is
// computed from the code on every run.
func TestCommitCheckCannotReachTheHostMutatingCompiler7297(t *testing.T) {
	const (
		validateOnlyPkg = "github.com/psaab/xpf/pkg/configstore"
		hostMutatingPkg = "github.com/psaab/xpf/pkg/dataplane"
	)

	out, err := exec.Command("go", "list", "-deps", validateOnlyPkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v — this guard is the only thing holding the "+
			"validate-only boundary, so a failure to compute the closure is a failure "+
			"of the guard, not a reason to skip it", validateOnlyPkg, err)
	}

	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Fatal("go list -deps returned NO packages. A closure over an empty set " +
			"would report the boundary intact while checking nothing")
	}

	sawSelf := false
	for _, d := range deps {
		if d == validateOnlyPkg {
			sawSelf = true
		}
		if d == hostMutatingPkg {
			t.Errorf("%s is in %s's dependency closure.\n\n"+
				"Store.CommitCheck runs on that path, so `commit check` can now reach "+
				"pkg/dataplane's CompileConfig — which creates VLANs and reconciles host "+
				"addresses mid-compile (#4960). A validate-only command that mutates the "+
				"host is a defect regardless of #7289's apply-side work.\n\n"+
				"Note the two compilers share a NAME: pkg/config.CompileConfig (AST -> "+
				"typed structs, correct here) and pkg/dataplane.CompileConfig(dp, cfg, ...) "+
				"(host-mutating). Check which one the new call site meant.",
				hostMutatingPkg, validateOnlyPkg)
		}
	}
	if !sawSelf {
		t.Errorf("%s is not in its own dependency closure — the package path is wrong, "+
			"so this guard swept something other than the package it names", validateOnlyPkg)
	}
}
