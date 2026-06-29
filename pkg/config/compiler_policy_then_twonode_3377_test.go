package config

// #3377 (review fold): the security-policy then-action reject gates
// (validatePolicyThenPermitStrict #3114, validatePolicyThenRejectStrict
// #3115, validatePolicyThenDenyStrict #3141) inspected only the FIRST
// action node via thenNode.FindChild (ast.go returns the first match). But
// SetPath can build TWO separate nodes for the same action: a bare leaf
// (`set ... then permit`) plus a later extended form
// (`set ... then permit application-services X`) as a SECOND `permit` node.
// The compiler iterates EVERY `then` child, so the unsupported modifier on
// the second node is silently dropped — yet a FindChild-first gate only
// checked the (valid) bare first node and never emitted the specific
// #3114/#3115 unsupported-modifier diagnostic.
//
// Net effect on the STRICT commit path is NOT a fail-open: the duplicate
// action node trips the #3043 conflicting-terminal-action gate, so the
// commit is still rejected — but with a generic "conflicting terminal
// actions" message instead of the specific "then permit application-
// services is unsupported / fail-open" message #3114 exists to give. On the
// LENIENT load / peer-sync path (#3043 downgraded to a warning, action
// resolved last-wins) the specific #3114/#3115 warning is the one that tells
// the operator their inspection/profile is being dropped — and it was
// SUPPRESSED. The fix makes all three gates iterate every same-named action
// node (FindChildren) and flatten each node's modifier tokens
// (collapsedThenActionTokens), so the specific diagnostic fires regardless
// of how the flat-set was split across lines.
//
// (This two-node split is independent of the #3377 schema change — it
// reproduces identically whether or not permit/reject are declared schema
// leaves; the FindChild-first gap predates #3377.)
//
// Reverting the gate fix to FindChild-first turns these RED: the strict
// error becomes the #3043 conflict (no #3114/#3115 substring) and the
// lenient #3114/#3115 warning disappears.

import (
	"strings"
	"testing"
)

func buildTwoNodePolicyTree(t *testing.T, extra ...string) *ConfigTree {
	t.Helper()
	cmds := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application any",
	}
	return buildPolicyTree(t, append(cmds, extra...))
}

// thenActionNodeCount returns how many `then <action>` nodes the policy `p`
// carries — used to prove the two-line set sequence genuinely produces two
// nodes (the bypass precondition), not a single merged node the old gate
// already caught.
func thenActionNodeCount(tree *ConfigTree, action string) int {
	sec := tree.FindChild("security")
	if sec == nil {
		return 0
	}
	pols := sec.FindChild("policies")
	if pols == nil {
		return 0
	}
	fz := pols.FindChild("from-zone")
	if fz == nil {
		return 0
	}
	pol := fz.FindChild("policy")
	if pol == nil {
		return 0
	}
	then := pol.FindChild("then")
	if then == nil {
		return 0
	}
	return len(then.FindChildren(action))
}

func lenientWarnings(t *testing.T, tree *ConfigTree) []string {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient returned a hard error (should warn + boot): %v", err)
	}
	if cfg == nil {
		t.Fatal("CompileConfigLenient returned nil config")
	}
	return cfg.Warnings
}

func containsSub(warns []string, sub string) bool {
	for _, w := range warns {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

// TestPolicyThen3377_TwoNodePermitBypass asserts a bare `then permit`
// followed by a separate `then permit application-services X` (two permit
// nodes) is rejected at commit with the SPECIFIC #3114 diagnostic, and the
// lenient path emits the #3114 warning. RED on revert to FindChild-first
// (the gate would miss the second node; strict falls back to the generic
// #3043 conflict and the lenient #3114 warning vanishes).
func TestPolicyThen3377_TwoNodePermitBypass(t *testing.T) {
	tree := buildTwoNodePolicyTree(t,
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then permit application-services utm-policy strict-web",
	)
	if n := thenActionNodeCount(tree, "permit"); n != 2 {
		t.Fatalf("precondition: expected 2 then-permit nodes (the two-node bypass), got %d", n)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for two-node then-permit with application-services")
	}
	if !strings.Contains(err.Error(), "#3114") || !strings.Contains(err.Error(), "application-services") {
		t.Fatalf("expected the specific #3114 then-permit diagnostic, got: %v", err)
	}
	if w := lenientWarnings(t, tree); !containsSub(w, "#3114") {
		t.Fatalf("expected a #3114 lenient warning for the second permit node, got: %v", w)
	}
}

// TestPolicyThen3377_TwoNodeRejectBypass is the #3115 sibling: bare
// `then reject` + `then reject profile X`.
func TestPolicyThen3377_TwoNodeRejectBypass(t *testing.T) {
	tree := buildTwoNodePolicyTree(t,
		"set security policies from-zone trust to-zone untrust policy p then reject",
		"set security policies from-zone trust to-zone untrust policy p then reject profile blocked-web",
	)
	if n := thenActionNodeCount(tree, "reject"); n != 2 {
		t.Fatalf("precondition: expected 2 then-reject nodes, got %d", n)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for two-node then-reject with profile")
	}
	if !strings.Contains(err.Error(), "#3115") || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("expected the specific #3115 then-reject diagnostic, got: %v", err)
	}
	if w := lenientWarnings(t, tree); !containsSub(w, "#3115") {
		t.Fatalf("expected a #3115 lenient warning for the second reject node, got: %v", w)
	}
}

// TestPolicyThen3377_TwoNodeDenyBypass is the #3141 sibling: a bare
// `then deny` followed by `then deny <unsupported-modifier>` produces two
// deny nodes (a bare deny leaf + an extended one). The fix's all-nodes walk
// surfaces the specific #3141 unsupported-deny-modifier diagnostic; a
// FindChild-first gate sees only the bare deny first and misses the
// modifier, leaving the strict path on the generic #3043 conflict and
// suppressing the lenient #3141 warning.
func TestPolicyThen3377_TwoNodeDenyBypass(t *testing.T) {
	tree := buildTwoNodePolicyTree(t,
		"set security policies from-zone trust to-zone untrust policy p then deny",
		"set security policies from-zone trust to-zone untrust policy p then deny evilmod",
	)
	if n := thenActionNodeCount(tree, "deny"); n != 2 {
		t.Fatalf("precondition: expected 2 then-deny nodes, got %d", n)
	}
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit rejection for two-node then-deny with an unsupported modifier")
	}
	if !strings.Contains(err.Error(), "#3141") || !strings.Contains(err.Error(), "evilmod") {
		t.Fatalf("expected the specific #3141 then-deny diagnostic, got: %v", err)
	}
	if w := lenientWarnings(t, tree); !containsSub(w, "#3141") {
		t.Fatalf("expected a #3141 lenient warning for the second deny node, got: %v", w)
	}
}

// TestPolicyThen3377_LegitSplitActionNoFalsePositive confirms the all-nodes
// walk does not introduce a false positive: a single bare `then permit`
// (the most common, fully-supported action) still commits cleanly through
// the permit gate. (The permit gate emits only on an unsupported modifier
// token; a bare permit carries none.)
func TestPolicyThen3377_LegitBarePermitCommits(t *testing.T) {
	tree := buildTwoNodePolicyTree(t,
		"set security policies from-zone trust to-zone untrust policy p then permit",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("a bare then permit must commit cleanly, got: %v", err)
	}
}
