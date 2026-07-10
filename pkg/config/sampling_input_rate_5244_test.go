package config

import (
	"strings"
	"testing"
)

// #5244 — sampling instance input-rate lower-bound gate (compiler-side
// defense-in-depth).
//
// A negative `forwarding-options sampling instance <name> input rate` is a
// fail-open: the exporter's `SamplingRate > 1` 1-in-N gate is false for a
// negative value (every eligible flow exports, the ratio is ignored) and the
// retired eBPF cast wrapped it into a huge divisor. At STRICT operator commit
// this is already hard-rejected by the #1979 SchemaValidate typed-leaf gate
// (`ValidateInteger(0, maxWireU32)` on the rate leaf), which runs before the
// compiler — so `compileSampling` itself never saw the value guarded, unlike
// the sibling `compilePortMirroring`, which carries its own inline lower-bound
// guard as defense-in-depth. This gate closes that asymmetry: a compiler-side
// bound (validateSamplingInputRateStrict) that also fires on paths reaching the
// compiler without the typed-leaf gate (tolerant load / peer-sync, direct
// CompileConfig callers, future refactors). Strict on commit / commit-check;
// tolerant load / peer-sync downgrades to a warning (#1960). `0` stays valid
// (sample every packet, per Junos and the port-mirroring sibling).
//
// These tests exercise the compiler-side gate directly via CompileConfig /
// CompileConfigLenient (which do NOT run SchemaValidate), so they isolate the
// gate and FAIL if it is reverted.

// TestSamplingNegativeInputRateRejected: a negative input rate is hard-rejected
// at strict commit. This FAILS (negative accepted -> wrap / fail-open) if the
// bound check is reverted.
func TestSamplingNegativeInputRateRejected(t *testing.T) {
	cmds := []string{
		"set forwarding-options sampling instance s input rate -1",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a negative sampling input rate; expected rejection")
	}
	for _, want := range []string{"sampling instance", "s", "negative", "-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

// TestSamplingZeroInputRateAccepted: 0 is a VALID rate (sample every packet)
// per Junos and the port-mirroring sibling; it must NOT be rejected.
func TestSamplingZeroInputRateAccepted(t *testing.T) {
	cmds := []string{
		"set forwarding-options sampling instance s input rate 0",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a zero (sample-every-packet) sampling input rate: %v", err)
	}
}

// TestSamplingValidInputRateAccepted: a normal positive 1-in-N rate compiles
// cleanly and is stored unchanged.
func TestSamplingValidInputRateAccepted(t *testing.T) {
	cmds := []string{
		"set forwarding-options sampling instance s input rate 1000",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a valid sampling input rate: %v", err)
	}
	if cfg.ForwardingOptions.Sampling == nil {
		t.Fatal("sampling config missing after compile")
	}
	inst := cfg.ForwardingOptions.Sampling.Instances["s"]
	if inst == nil {
		t.Fatal("sampling instance s missing after compile")
	}
	if inst.InputRate != 1000 {
		t.Errorf("input rate = %d, want 1000 (valid rate must be stored unchanged)", inst.InputRate)
	}
}

// TestSamplingNegativeInputRateLenientWarns: on the tolerant load / peer-sync
// path a negative rate is downgraded to a warning so an already-persisted or
// peer-synced config authored by a pre-guard version still boots (#1960).
func TestSamplingNegativeInputRateLenientWarns(t *testing.T) {
	cmds := []string{
		"set forwarding-options sampling instance s input rate -5",
		"set forwarding-options sampling instance s family inet output flow-server 10.0.0.1 port 2055",
	}
	tree := buildTreeFromSet(t, cmds)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must NOT hard-reject a negative sampling input rate: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "sampling instance input rate") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("lenient compile must emit a downgraded warning for the negative rate; warnings=%v", cfg.Warnings)
	}
}
