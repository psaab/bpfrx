package config

// Regression tests for the fable-review-166 CoS config-schema gaps
// (#4217 G-4, #4218 G-3, #4219 G-5, #4220 G-1). Each of the four
// scheduler/interface leaves below was untyped, missing, or inert; the
// fix types them so garbage HARD-REJECTS at commit and adds
// accepted-but-inert commit warnings for the two knobs the dataplane
// does not enforce (codel-target AQM, priority-low-min-share).
//
// FAIL-ON-REVERT: dropping the typed-leaf metadata from schema_cos.go
// (or the warnings from compiler_validate_warn.go) makes the "rejects"
// / "warns" assertions go RED — the garbage values commit clean again
// and the inert knobs go silent, exactly the pre-fix behavior.

import (
	"strings"
	"testing"
)

func hb166SchemaCheck(t *testing.T, cmds ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return SchemaValidate(tree, nil)
}

func hb166Compile(t *testing.T, cmds ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hb166HasWarning(cfg *Config, substr string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// --- G-4: shaping-rate / burst-size typed (unit level + interface level) ---

func TestHB166_G4_ShapingRate_RejectsGarbage(t *testing.T) {
	// Unit level and #4021 interface level. Before #4217 both committed
	// as 0 (parseBandwidthLimit silent-zero) and the shaper vanished.
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10gg",
		"set class-of-service interfaces reth0 shaping-rate 10gg",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "shaping-rate") {
			t.Fatalf("%q: error should reference shaping-rate: %v", cmd, err)
		}
	}
}

func TestHB166_G4_ShapingRate_AcceptsValid(t *testing.T) {
	good := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 25g",
		"set class-of-service interfaces reth0 shaping-rate 1g",
	}
	for _, cmd := range good {
		if err := hb166SchemaCheck(t, cmd); err != nil {
			t.Fatalf("%q: expected accept, got %v", cmd, err)
		}
	}
}

func TestHB166_G4_BurstSize_RejectsGarbage(t *testing.T) {
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10m burst-size garbage",
		"set class-of-service interfaces reth0 shaping-rate 10m burst-size garbage",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "burst-size") {
			t.Fatalf("%q: error should reference burst-size: %v", cmd, err)
		}
	}
}

func TestHB166_G4_BurstSize_AcceptsValid(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10m burst-size 15k"); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

// --- G-3: codel-target typed + inert warning ---

func TestHB166_G3_CodelTarget_RejectsGarbage(t *testing.T) {
	err := hb166SchemaCheck(t,
		"set class-of-service schedulers be codel-target banana")
	if err == nil {
		t.Fatal("expected rejection for codel-target banana, got nil")
	}
	if !strings.Contains(err.Error(), "codel-target") {
		t.Fatalf("error should reference codel-target: %v", err)
	}
}

func TestHB166_G3_CodelTarget_AcceptsValidAndWarnsInert(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service schedulers be codel-target 5"); err != nil {
		t.Fatalf("expected codel-target 5 to pass schema, got %v", err)
	}
	cfg := hb166Compile(t,
		"set class-of-service schedulers be codel-target 5")
	if !hb166HasWarning(cfg, "codel-target is accepted for compatibility but inert") {
		t.Fatalf("expected inert codel-target warning; got: %v", cfg.Warnings)
	}
}

// --- G-5: oversubscription-policy + priority-low-min-share typed ---

func TestHB166_G5_GuaranteeRateFraction_RejectsOutOfRange(t *testing.T) {
	// The compiler silently clamps 1.7 -> 1.0 today; the schema now
	// rejects the out-of-range fraction at commit.
	err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 1.7")
	if err == nil {
		t.Fatal("expected rejection for guarantee-rate 1.7, got nil")
	}
	if !strings.Contains(err.Error(), "guarantee-rate") {
		t.Fatalf("error should reference guarantee-rate: %v", err)
	}
}

func TestHB166_G5_GuaranteeRateFraction_AcceptsValid(t *testing.T) {
	good := []string{
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 0.7",
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy proportional",
		"set class-of-service interfaces reth0 oversubscription-policy guarantee-rate 0.5",
	}
	for _, cmd := range good {
		if err := hb166SchemaCheck(t, cmd); err != nil {
			t.Fatalf("%q: expected accept, got %v", cmd, err)
		}
	}
}

func TestHB166_G5_PriorityLowMinShare_RejectsGarbage(t *testing.T) {
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 10gg",
		"set class-of-service interfaces reth0 priority-low-min-share 10gg",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "priority-low-min-share") {
			t.Fatalf("%q: error should reference priority-low-min-share: %v", cmd, err)
		}
	}
}

// --- G-1: priority-low-min-share accepted but inert warning ---

func TestHB166_G1_PriorityLowMinShare_AcceptsValidAndWarnsInert(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 100m"); err != nil {
		t.Fatalf("expected priority-low-min-share 100m to pass schema, got %v", err)
	}
	cfg := hb166Compile(t,
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 100m")
	if !hb166HasWarning(cfg, "priority-low-min-share is accepted for compatibility but inert") {
		t.Fatalf("expected inert priority-low-min-share warning; got: %v", cfg.Warnings)
	}
}

// --- completion: the new leaves are reachable via `set ... ?` ---

func TestHB166_Completion_NewLeavesPresent(t *testing.T) {
	// codel-target under schedulers.
	sched := CompleteSetPathWithValues(
		[]string{"class-of-service", "schedulers", "be"}, nil)
	if !containsCompletionName(sched, "codel-target") {
		t.Fatalf("expected codel-target in schedulers completions; got %v", completionNames(sched))
	}
	// oversubscription-policy + priority-low-min-share under interfaces>unit.
	unit := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0", "unit", "80"}, nil)
	for _, want := range []string{"oversubscription-policy", "priority-low-min-share", "shaping-rate"} {
		if !containsCompletionName(unit, want) {
			t.Fatalf("expected %q in unit completions; got %v", want, completionNames(unit))
		}
	}
	// oversubscription-policy children.
	oversub := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0", "unit", "80", "oversubscription-policy"}, nil)
	for _, want := range []string{"guarantee-rate", "proportional"} {
		if !containsCompletionName(oversub, want) {
			t.Fatalf("expected %q in oversubscription-policy completions; got %v", want, completionNames(oversub))
		}
	}
	// Interface-level (#4021) leaves too.
	iface := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0"}, nil)
	for _, want := range []string{"oversubscription-policy", "priority-low-min-share", "shaping-rate"} {
		if !containsCompletionName(iface, want) {
			t.Fatalf("expected %q in interface-level completions; got %v", want, completionNames(iface))
		}
	}
}
