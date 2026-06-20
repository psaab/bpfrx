package config

import (
	"strings"
	"testing"
)

// #2079: commit-time validation for `security nat source
// pool-utilization-alarm`. All tests use the production ParseSetCommand +
// SetPath path (buildTree), never NewParser (the flat-set gotcha in CLAUDE.md).

func TestPoolUtilizationAlarmValidThresholds(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 70",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid thresholds should compile, got: %v", err)
	}
	a := cfg.Security.NAT.PoolUtilizationAlarm
	if a == nil || a.RaiseThreshold != 80 || a.ClearThreshold != 70 {
		t.Fatalf("alarm not stored correctly: %+v", a)
	}
}

func TestPoolUtilizationAlarmRejectsBareStanza(t *testing.T) {
	// A bare `pool-utilization-alarm;` compiles to raise=0/clear=0 — an
	// always-firing alarm. Must be a commit error.
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("bare pool-utilization-alarm (raise=0) must be rejected")
	}
	if !strings.Contains(err.Error(), "raise-threshold") {
		t.Fatalf("error should mention raise-threshold, got: %v", err)
	}
}

func TestPoolUtilizationAlarmRejectsInverted(t *testing.T) {
	// clear >= raise is invalid (hysteresis meaningless).
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 70 clear-threshold 80",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("clear > raise must be rejected")
	}
	if !strings.Contains(err.Error(), "clear-threshold") {
		t.Fatalf("error should mention clear-threshold, got: %v", err)
	}
}

func TestPoolUtilizationAlarmRejectsEqual(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 75 clear-threshold 75",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("clear == raise must be rejected")
	}
}

func TestPoolUtilizationAlarmRejectsOutOfRange(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 150 clear-threshold 70",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("raise > 100 must be rejected")
	}
}

func TestPoolUtilizationAlarmRejectsZeroClear(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 0",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("clear-threshold 0 must be rejected")
	}
}

// #2079 (review BLOCKER 1): the strict commit gate must NOT brick a daemon
// restart. CompileConfigLenient (the Store.Load path) must ACCEPT a previously-
// valid-but-now-invalid alarm config (committed before this gate existed) and
// downgrade the violation to a WARNING — otherwise the daemon fails closed on
// restart per the #1960 fail-closed-on-compile-failure behavior.
func TestPoolUtilizationAlarmLenientLoadAccepts(t *testing.T) {
	cases := [][]string{
		{"set security nat source pool-utilization-alarm"},                                        // bare (raise=0)
		{"set security nat source pool-utilization-alarm raise-threshold 70 clear-threshold 80"},  // inverted
		{"set security nat source pool-utilization-alarm raise-threshold 75 clear-threshold 75"},  // equal
		{"set security nat source pool-utilization-alarm raise-threshold 150 clear-threshold 70"}, // out of range
		{"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 0"},   // zero clear
	}
	for i, lines := range cases {
		tree := buildTree(t, lines)
		// Strict rejects.
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("case %d: strict CompileConfig must reject", i)
		}
		// Lenient accepts + warns.
		tree2 := buildTree(t, lines)
		cfg, err := CompileConfigLenient(tree2)
		if err != nil {
			t.Fatalf("case %d: CompileConfigLenient must NOT fail (brick-on-restart), got: %v", i, err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "pool-utilization-alarm") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("case %d: lenient load must emit a pool-utilization-alarm warning, warnings=%v", i, cfg.Warnings)
		}
	}
}

// A valid config must NOT produce a warning under lenient compile.
func TestPoolUtilizationAlarmLenientValidNoWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security nat source pool-utilization-alarm raise-threshold 80 clear-threshold 70",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("valid config lenient compile: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "pool-utilization-alarm") {
			t.Fatalf("valid config must not warn, got: %q", w)
		}
	}
}
