package config

import (
	"strings"
	"testing"
)

// compileSNMPLines builds a config tree from flat-set lines and compiles it via
// the strict (commit) path.
func compileSNMPLines(t *testing.T, lines []string) (*Config, error) {
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
	return CompileConfig(tree)
}

// TestSNMPTrapGroup_TypoRejected is the fail-on-revert guard for #2990. A
// typoed trap-group child key (`tragets` instead of `targets`) must be REJECTED
// at commit. Before the fix the compiler only consumed `targets` and silently
// dropped every other child, so a typo committed as a valid zero-target trap
// group that sent no notifications. Reverting the compiler's unknown-key /
// zero-target rejection makes this test pass-compile (no error) and fail.
func TestSNMPTrapGroup_TypoRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp trap-group managers tragets 10.0.0.10",
	})
	if err == nil {
		t.Fatal("typoed trap-group key 'tragets' compiled without error (#2990 regression)")
	}
	if !strings.Contains(err.Error(), "tragets") {
		t.Fatalf("error %q does not name the offending key 'tragets'", err)
	}
}

// TestSNMPTrapGroup_ZeroTargetsRejected guards the companion zero-target case:
// a trap group with no targets sends nothing and must be rejected at commit.
func TestSNMPTrapGroup_ZeroTargetsRejected(t *testing.T) {
	_, err := compileSNMPLines(t, []string{
		"set snmp trap-group empty version v2",
	})
	if err == nil {
		t.Fatal("trap-group with zero targets compiled without error (#2990)")
	}
	if !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("error %q does not explain the zero-target rejection", err)
	}
}

// TestSNMPTrapGroup_ValidAccepted confirms the fix does not over-reject: a
// well-formed trap group (single target, multiple targets, with version /
// categories) compiles and the targets land in the typed config.
func TestSNMPTrapGroup_ValidAccepted(t *testing.T) {
	cfg, err := compileSNMPLines(t, []string{
		"set snmp community public authorization read-only",
		"set snmp trap-group managers targets 10.0.0.10",
		"set snmp trap-group managers targets 10.0.0.11",
		"set snmp trap-group managers version v2",
		"set snmp trap-group managers categories link",
	})
	if err != nil {
		t.Fatalf("valid trap-group failed to compile: %v", err)
	}
	tg := cfg.System.SNMP.TrapGroups["managers"]
	if tg == nil {
		t.Fatal("trap-group 'managers' missing from compiled config")
	}
	if len(tg.Targets) != 2 {
		t.Fatalf("targets = %v, want 2 entries", tg.Targets)
	}
	want := map[string]bool{"10.0.0.10": false, "10.0.0.11": false}
	for _, target := range tg.Targets {
		if _, ok := want[target]; !ok {
			t.Fatalf("unexpected target %q", target)
		}
		want[target] = true
	}
	for target, seen := range want {
		if !seen {
			t.Fatalf("expected target %q missing", target)
		}
	}
}

// TestSNMPTrapGroup_BracketedTargets confirms a bracketed/flat-set list of
// targets accumulates (the multi-value leaf contract, docs/config-schema.md).
func TestSNMPTrapGroup_BracketedTargets(t *testing.T) {
	cfg, err := compileSNMPLines(t, []string{
		"set snmp trap-group managers targets [ 10.0.0.10 10.0.0.11 10.0.0.12 ]",
	})
	if err != nil {
		t.Fatalf("bracketed targets failed to compile: %v", err)
	}
	tg := cfg.System.SNMP.TrapGroups["managers"]
	if tg == nil || len(tg.Targets) != 3 {
		t.Fatalf("bracketed targets = %v, want 3 entries", tg)
	}
}
