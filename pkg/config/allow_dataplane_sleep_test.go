package config

import (
	"strings"
	"testing"
)

// Tests for #2008 H13 Stage 1 — forwarding-options allow-dataplane-sleep.
// Stage 1 is schema + typed field + an accepted-but-unenforced commit
// warning; the idle-yield dataplane runtime is Stage 2 (deferred, lab-gated).

// The leaf parses and compiles onto the typed field, and commit emits the
// accepted-but-unenforced warning.
func TestAllowDataplaneSleep_ParsesFieldSetAndWarns(t *testing.T) {
	cfg := compileSetLines(t, []string{
		`set forwarding-options allow-dataplane-sleep`,
	})

	if !cfg.ForwardingOptions.AllowDataplaneSleep {
		t.Fatal("allow-dataplane-sleep did not set ForwardingOptions.AllowDataplaneSleep")
	}

	warnings := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(warnings, "allow-dataplane-sleep") {
		t.Fatalf("expected an allow-dataplane-sleep commit warning, got %v", cfg.Warnings)
	}
	if !strings.Contains(warnings, "not yet implemented") &&
		!strings.Contains(warnings, "accepted-only") {
		t.Fatalf("warning does not flag the knob as unenforced: %v", cfg.Warnings)
	}
}

// Absent leaf: field stays false and no spurious warning is emitted.
func TestAllowDataplaneSleep_AbsentNoWarn(t *testing.T) {
	cfg := compileSetLines(t, []string{
		`set forwarding-options family inet6 mode flow-based`,
	})
	if cfg.ForwardingOptions.AllowDataplaneSleep {
		t.Fatal("AllowDataplaneSleep set without the leaf configured")
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "allow-dataplane-sleep") {
			t.Fatalf("unexpected allow-dataplane-sleep warning when leaf absent: %q", w)
		}
	}
}

// The schema accepts the leaf via structural completion (it is a real typed
// leaf now, not a no-schema-match fall-through).
func TestAllowDataplaneSleep_SchemaCompletes(t *testing.T) {
	results := CompleteSetPathWithValues([]string{"forwarding-options"}, nil)
	if !containsCompletionName(results, "allow-dataplane-sleep") {
		t.Fatalf("allow-dataplane-sleep not offered by schema completion under forwarding-options: %v",
			completionNames(results))
	}
}
