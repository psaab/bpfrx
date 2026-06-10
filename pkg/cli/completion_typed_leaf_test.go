package cli

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #1319 PR 1 — frontend-boundary tests for typed-leaf value completion.
//
// These assert the SYMPTOM-1 fix at the real local-CLI completion entry
// point (completeConfigWithDesc), NOT the config-level helper. The
// research found that the merged Phase 1/2 only pinned a cmdtree
// CompleteFromTreeWithDesc path that the live `set ... ?` completer never
// uses; testing only the helper would pass while the live path regressed.
// completeConfigWithDesc is what the interactive CLI calls for `set` tab/`?`
// completion, so it is the load-bearing boundary.

func newTypedLeafCLI(t *testing.T) *CLI {
	t.Helper()
	store := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	return &CLI{store: store}
}

func candNames(cands []completionCandidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.name
	}
	return out
}

func hasCand(cands []completionCandidate, name string) bool {
	for _, c := range cands {
		if c.name == name {
			return true
		}
	}
	return false
}

// Symptom-1 demonstration: `set class-of-service schedulers be
// transmit-rate ?` (trailing space → empty partial at the value slot)
// must surface the <rate> placeholder and example values through the live
// CLI completer. On master this returns nothing for the value slot.
func TestCompleteConfig_TransmitRate_ShowsRatePlaceholderAndExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
		"",
	)
	if !hasCand(cands, "<rate>") {
		t.Fatalf("expected <rate> placeholder at value slot, got %v", candNames(cands))
	}
	for _, ex := range []string{"100k", "10m", "1g", "10g"} {
		if !hasCand(cands, ex) {
			t.Fatalf("expected rate example %q, got %v", ex, candNames(cands))
		}
	}
}

// After the value is supplied, the completer surfaces the `exact` modifier
// child (not the placeholder again).
func TestCompleteConfig_TransmitRate_AfterValueShowsExact(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate", "1g"},
		"",
	)
	if !hasCand(cands, "exact") {
		t.Fatalf("expected `exact` modifier after consumed rate, got %v", candNames(cands))
	}
	if hasCand(cands, "<rate>") {
		t.Fatalf("placeholder should not reappear after value is set, got %v", candNames(cands))
	}
}

// priority is an enum leaf: `set ... priority ?` shows <value> + the enum
// example set.
func TestCompleteConfig_Priority_ShowsEnumExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "class-of-service", "schedulers", "be", "priority"},
		"",
	)
	for _, want := range []string{"low", "medium-low", "medium-high", "high", "strict-high"} {
		if !hasCand(cands, want) {
			t.Fatalf("expected priority enum example %q, got %v", want, candNames(cands))
		}
	}
}

// buffer-size is a byte-size-or-percent leaf.
func TestCompleteConfig_BufferSize_ShowsExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "class-of-service", "schedulers", "be", "buffer-size"},
		"",
	)
	if !hasCand(cands, "<bytes|percent>") {
		t.Fatalf("expected <bytes|percent> placeholder, got %v", candNames(cands))
	}
	for _, ex := range []string{"16m", "256k", "10%"} {
		if !hasCand(cands, ex) {
			t.Fatalf("expected buffer-size example %q, got %v", ex, candNames(cands))
		}
	}
}

// Prefix-partial at the value slot still surfaces matching examples:
// `set ... transmit-rate 1` should narrow to examples beginning with "1".
func TestCompleteConfig_TransmitRate_PartialFiltersExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "class-of-service", "schedulers", "be", "transmit-rate"},
		"1",
	)
	if !hasCand(cands, "1g") {
		t.Fatalf("expected 1g for partial \"1\", got %v", candNames(cands))
	}
	if hasCand(cands, "<rate>") {
		t.Fatalf("placeholder <rate> should be filtered out by partial \"1\", got %v", candNames(cands))
	}
	if hasCand(cands, "256k") {
		t.Fatalf("256k should not match partial \"1\", got %v", candNames(cands))
	}
}

// --- #1319 PR 2: chassis-cluster typed leaves at the live CLI boundary ---

// `set chassis cluster heartbeat-interval ?` surfaces the <integer>
// placeholder (with the range in its description) and the examples.
func TestCompleteConfig_HeartbeatInterval_ShowsIntegerPlaceholderAndExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "chassis", "cluster", "heartbeat-interval"},
		"",
	)
	if !hasCand(cands, "<integer>") {
		t.Fatalf("expected <integer> placeholder at value slot, got %v", candNames(cands))
	}
	for _, ex := range []string{"100", "200", "1000"} {
		if !hasCand(cands, ex) {
			t.Fatalf("expected heartbeat-interval example %q, got %v", ex, candNames(cands))
		}
	}
}

// peer-fencing is an enum leaf: its sole accepted value is surfaced.
func TestCompleteConfig_PeerFencing_ShowsEnumValue(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "chassis", "cluster", "peer-fencing"},
		"",
	)
	if !hasCand(cands, "disable-rg") {
		t.Fatalf("expected enum value disable-rg, got %v", candNames(cands))
	}
}

// Deep path: the typed priority leaf under redundancy-group <id> node <id>
// still reaches the value slot through two instance-name args.
func TestCompleteConfig_RGNodePriority_ShowsExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "chassis", "cluster", "redundancy-group", "1", "node", "0", "priority"},
		"",
	)
	if !hasCand(cands, "<integer>") {
		t.Fatalf("expected <integer> placeholder, got %v", candNames(cands))
	}
	for _, ex := range []string{"100", "200", "254"} {
		if !hasCand(cands, ex) {
			t.Fatalf("expected priority example %q, got %v", ex, candNames(cands))
		}
	}
}

// Prefix-partial filtering applies to chassis examples too.
func TestCompleteConfig_RethAdvertiseInterval_PartialFiltersExamples(t *testing.T) {
	c := newTypedLeafCLI(t)
	cands := c.completeConfigWithDesc(
		[]string{"set", "chassis", "cluster", "reth-advertise-interval"},
		"3",
	)
	if !hasCand(cands, "30") {
		t.Fatalf("expected 30 for partial \"3\", got %v", candNames(cands))
	}
	if hasCand(cands, "<integer>") {
		t.Fatalf("placeholder should be filtered out by partial \"3\", got %v", candNames(cands))
	}
	if hasCand(cands, "100") {
		t.Fatalf("100 should not match partial \"3\", got %v", candNames(cands))
	}
}
