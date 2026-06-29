package config

import (
	"testing"
)

// TestSynFloodTimeoutEmitsInertWarning asserts the #3315 commit-time advisory
// for `syn-flood timeout`: the leaf parses and commits cleanly but is not yet
// enforced by the dataplane (it maps to the per-zone half-open session window,
// a tracked follow-up), so the compiler warns it is accepted-but-inert. Without
// this the leaf is silently dead — exactly the configured-but-not-enforced trap
// #3315 fixes for the source/destination/alarm leaves.
func TestSynFloodTimeoutEmitsInertWarning(t *testing.T) {
	tree := buildTree(t, []string{
		"set security screen ids-option p tcp syn-flood attack-threshold 2000",
		"set security screen ids-option p tcp syn-flood timeout 20",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit rejected a valid syn-flood timeout: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, "syn-flood timeout 20 is accepted but NOT yet enforced") {
		t.Fatalf("expected a syn-flood timeout inert-warning, warnings=%v", cfg.Warnings)
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
