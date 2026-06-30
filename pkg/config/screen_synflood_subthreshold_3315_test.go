package config

import (
	"testing"
)

// TestSynFloodTimeoutNoLongerWarnsWhenEnforced is the #3527 inversion of the
// retired #3315 inert-warning test. `syn-flood timeout` is now enforced as a
// per-zone override of the half-open session window (tcp_opening_ns) — see
// pkg/dataplane/userspace/screens.go (SYNFloodTimeout) and the dataplane's
// SessionTable opening overrides — so the compiler MUST NOT emit the legacy
// accepted-but-inert advisory. Reinstate the warning branch and this goes RED.
func TestSynFloodTimeoutNoLongerWarnsWhenEnforced(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option p tcp syn-flood attack-threshold 2000",
		"set security screen ids-option p tcp syn-flood timeout 20",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid syn-flood timeout: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "syn-flood timeout") {
		t.Fatalf("syn-flood timeout is now enforced (#3527) and must not warn, warnings=%v", cfg.Warnings)
	}
	if hasWarningContaining(cfg.Warnings, "NOT yet enforced") {
		t.Fatalf("the inert-warning must be gone now that timeout is enforced, warnings=%v", cfg.Warnings)
	}
	// Sanity: the leaf still parses into the typed config so the snapshot
	// builder can publish it.
	if sf := cfg.Security.Screen["p"].TCP.SynFlood; sf == nil || sf.Timeout != 20 {
		t.Fatalf("expected syn-flood timeout 20 parsed into typed config, got %+v", sf)
	}
}

// TestSynFloodNoTimeoutNoWarning: with no timeout leaf, no inert warning fires.
func TestSynFloodNoTimeoutNoWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option p tcp syn-flood attack-threshold 2000",
		"set security screen ids-option p tcp syn-flood source-threshold 100",
		"set security screen ids-option p tcp syn-flood destination-threshold 200",
		"set security screen ids-option p tcp syn-flood alarm-threshold 1000",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid syn-flood profile: %v", err)
	}
	if hasWarningContaining(cfg.Warnings, "syn-flood timeout") {
		t.Fatalf("no timeout configured but a timeout warning fired, warnings=%v", cfg.Warnings)
	}
	// A modest attack/source ratio must NOT trigger the source-threshold advisory.
	if hasWarningContaining(cfg.Warnings, "below attack-threshold") {
		t.Fatalf("modest attack/source ratio must not trigger the advisory, warnings=%v", cfg.Warnings)
	}
}

// TestSynFloodSourceRatioAdvisory: an attack-threshold orders of magnitude above
// source-threshold is the one regime where the per-source count-min sketch can
// false-throttle legitimate sources, so the compiler advises (never rejects).
func TestSynFloodSourceRatioAdvisory(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option p tcp syn-flood attack-threshold 20000",
		"set security screen ids-option p tcp syn-flood source-threshold 10",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid (if lopsided) syn-flood profile: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "below attack-threshold") {
		t.Fatalf("expected a source-threshold ratio advisory, warnings=%v", cfg.Warnings)
	}
}
