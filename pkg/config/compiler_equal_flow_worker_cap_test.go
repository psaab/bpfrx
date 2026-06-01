package config

import (
	"strings"
	"testing"
)

// buildTree parses a sequence of `set ...` commands into a ConfigTree
// using the production ParseSetCommand + SetPath path (never NewParser,
// per the flat-set testing gotcha in CLAUDE.md).
func buildTree(t *testing.T, lines []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// validEqualFlowScheduler returns the set lines for a scheduler that
// passes validateClassOfServiceStrict (positive transmit-rate exact, no
// surplus-sharing) so that ONLY validateEqualFlowWorkerCapStrict can fire
// for the worker-cap scenarios below.
func validEqualFlowScheduler(name string) []string {
	return []string{
		"set class-of-service schedulers " + name + " transmit-rate 10m exact",
		"set class-of-service schedulers " + name + " equal-flow-enforcement",
	}
}

// TestCompileRejectsEqualFlowAboveWorkerCap is the FAILING-then-fixed
// gate for #1733: a config that enables equal-flow-enforcement with more
// than MaxEqualFlowWorkers dataplane workers must be hard-rejected at
// commit (the v8 lease rotation silently fail-opens equal-flow above the
// cap, so accepting the config would be a silent fairness fail-open).
func TestCompileRejectsEqualFlowAboveWorkerCap(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		"set system dataplane workers 33", // MaxEqualFlowWorkers + 1
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; want equal-flow worker-cap rejection")
	}
	if !strings.Contains(err.Error(), "equal-flow-enforcement is unsupported") {
		t.Fatalf("error missing worker-cap substring: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "ef-sched") {
		t.Fatalf("error should name the offending scheduler: %q", err.Error())
	}
}

// TestCompileAcceptsEqualFlowAtWorkerCap pins the boundary: exactly
// MaxEqualFlowWorkers workers is supported (the v8 rotation samples
// indices 0..MaxEqualFlowWorkers-1), so it must NOT be rejected.
func TestCompileAcceptsEqualFlowAtWorkerCap(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		"set system dataplane workers 32", // == MaxEqualFlowWorkers
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig at the worker cap returned error: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			t.Fatalf("unexpected worker-cap warning at the boundary: %q", w)
		}
	}
}

// TestCompileAcceptsAboveWorkerCapWithoutEqualFlow verifies the gate only
// fires when equal-flow-enforcement is actually enabled: a high worker
// count alone is fine.
func TestCompileAcceptsAboveWorkerCapWithoutEqualFlow(t *testing.T) {
	lines := []string{
		"set system dataplane-type userspace",
		"set system dataplane workers 64",
		// transmit-rate exact scheduler WITHOUT equal-flow-enforcement.
		"set class-of-service schedulers be-sched transmit-rate 10m exact",
	}
	tree := buildTree(t, lines)

	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig with >cap workers but no equal-flow returned error: %v", err)
	}
}

// TestCompileLenientDowngradesEqualFlowWorkerCap proves the lenient
// compile path (Store.Load / Store.SyncApply) downgrades the worker-cap
// rejection to a cfg.Warnings entry WITHOUT mutating the config: the
// scheduler's EqualFlowEnforcement stays true (the runtime fail-opens it,
// exactly as before this gate), so running behavior is preserved.
func TestCompileLenientDowngradesEqualFlowWorkerCap(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		"set system dataplane workers 33",
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	// Strict still rejects.
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("strict CompileConfig accepted >cap equal-flow config; want rejection")
	}

	// Lenient warns instead.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient rejected >cap equal-flow config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile produced no worker-cap warning: %v", cfg.Warnings)
	}
	// Warning-only downgrade — the leaf is NOT stripped.
	sched := cfg.ClassOfService.Schedulers["ef-sched"]
	if sched == nil || !sched.EqualFlowEnforcement {
		t.Fatal("lenient compile must NOT strip equal-flow-enforcement (warning-only, no mutation)")
	}
}

// TestCompileEqualFlowWorkerCapPerNodeParity is the round-2 semantic-set
// parity gate. A config that sets workers>cap ONLY inside groups{node0}
// (with a benign groups{node1} so ${node} expansion for node1 does not
// error) plus apply-groups "${node}" + equal-flow must reject/warn for
// node0 (effective workers>cap) but NOT for node1 (effective workers
// default <=cap). An AST-walk rewrite that read the raw-tree workers leaf
// would have false-stripped/false-warned node1; computing effective
// workers via the real per-node compile is the fix.
func TestCompileEqualFlowWorkerCapPerNodeParity(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		`set apply-groups "${node}"`,
		// node0: over the cap.
		"set groups node0 system dataplane workers 64",
		// node1: benign group, no workers (effective stays default).
		"set groups node1 system host-name fw1",
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	// node0: strict rejects, lenient warns.
	if _, err := CompileConfigForNode(tree, 0); err == nil {
		t.Fatal("node0 (workers 64) strict compile accepted equal-flow; want rejection")
	}
	cfg0, err := CompileConfigForNodeLenient(tree, 0)
	if err != nil {
		t.Fatalf("node0 lenient compile errored: %v", err)
	}
	if !hasWorkerCapWarning(cfg0) {
		t.Fatalf("node0 lenient compile missing worker-cap warning: %v", cfg0.Warnings)
	}

	// node1: effective workers default (<=cap) — must NOT reject or warn,
	// in EITHER mode. This is the false-positive guard.
	cfg1, err := CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("node1 strict compile errored (false reject — parity bug): %v", err)
	}
	if hasWorkerCapWarning(cfg1) {
		t.Fatalf("node1 strict compile has worker-cap warning (false positive): %v", cfg1.Warnings)
	}
	cfg1l, err := CompileConfigForNodeLenient(tree, 1)
	if err != nil {
		t.Fatalf("node1 lenient compile errored: %v", err)
	}
	if hasWorkerCapWarning(cfg1l) {
		t.Fatalf("node1 lenient compile has worker-cap warning (false positive): %v", cfg1l.Warnings)
	}
}

func hasWorkerCapWarning(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "equal-flow-enforcement is unsupported") {
			return true
		}
	}
	return false
}

// TestCompileEqualFlowWorkerCapAccumulatesWithOtherStrictFamilies pins the
// new validator into the #1538 strict-validator accumulator alongside an
// independent family, so a silent removal of the
// validateEqualFlowWorkerCapStrict append from compileExpanded is caught
// (same rationale as TestCompileAllThreeStrictValidatorsAccumulated). The
// fixture fires the equal-flow-worker-cap family (valid exact equal-flow
// scheduler at workers>cap) AND the policer family (CIR=0) simultaneously.
func TestCompileEqualFlowWorkerCapAccumulatesWithOtherStrictFamilies(t *testing.T) {
	lines := append([]string{
		"set system dataplane-type userspace",
		"set system dataplane workers 33",
		// Policer family: single-rate color-blind leaves CIR=0.
		"set firewall three-color-policer bad-pol single-rate color-blind",
		"set firewall three-color-policer bad-pol then discard",
	}, validEqualFlowScheduler("ef-sched")...)
	tree := buildTree(t, lines)

	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig succeeded; want accumulated worker-cap + policer errors")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "equal-flow-enforcement is unsupported") {
		t.Errorf("error missing worker-cap family substring: %q", errStr)
	}
	if !strings.Contains(errStr, "committed-information-rate") {
		t.Errorf("error missing policer family substring: %q", errStr)
	}
	// Two families → exactly one '\n' separator (errors.Join: N errors →
	// N-1 newlines). A dropped worker-cap append reduces this to 0.
	if nc := strings.Count(errStr, "\n"); nc != 1 {
		t.Errorf("newline count = %d, want 1 (two joined families): %q", nc, errStr)
	}
}

// TestMaxEqualFlowWorkersMatchesRustScratch is the constant-parity canary
// (Codex r1 suggestion): MaxEqualFlowWorkers must stay equal to
// MAX_WORKERS_SCRATCH in
// userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs. If a
// future Rust-side change bumps that constant, this test fails so the Go
// side is updated in lockstep (both retire together under #1731-e).
func TestMaxEqualFlowWorkersMatchesRustScratch(t *testing.T) {
	const rustMaxWorkersScratch = 32 // rotate_epoch_v8.rs:71 MAX_WORKERS_SCRATCH
	if MaxEqualFlowWorkers != rustMaxWorkersScratch {
		t.Fatalf("MaxEqualFlowWorkers = %d, must match Rust MAX_WORKERS_SCRATCH = %d "+
			"(rotate_epoch_v8.rs:71); update both in lockstep (#1731-e retires both)",
			MaxEqualFlowWorkers, rustMaxWorkersScratch)
	}
}
