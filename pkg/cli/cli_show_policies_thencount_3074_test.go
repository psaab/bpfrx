package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3074: the per-policy `then count` modifier must give a policy runtime
// meaning — its packet/byte counter is displayed independent of the
// system-wide `security policy-stats system-wide enable` knob. Before
// #3074 `then count` was parsed and stored but inert: the six display
// surfaces gated solely on the system-wide knob, so a `then count`
// policy reported 0 unless the operator ALSO enabled system-wide stats.
//
// These tests assert, with the system-wide knob OFF, that a policy WITH
// `then count` shows its live count while a sibling policy WITHOUT it
// stays at 0 (the pre-#3074 behavior). Reverting the `|| pol.Count`
// display gate makes the `then count` assertion go RED (the counted row
// drops back to 0).
func newThenCountCLIStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	// Two policies in the same zone-pair: counted-web has `then count`,
	// plain-web does not. System-wide policy-stats is left OFF.
	cmds := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy counted-web match source-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy counted-web match application any",
		"security policies from-zone trust to-zone untrust policy counted-web then permit",
		"security policies from-zone trust to-zone untrust policy counted-web then count",
		"security policies from-zone trust to-zone untrust policy plain-web match source-address any",
		"security policies from-zone trust to-zone untrust policy plain-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy plain-web match application any",
		"security policies from-zone trust to-zone untrust policy plain-web then permit",
	}
	for _, cmd := range cmds {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if cfg.Security.PolicyStatsEnabled {
		t.Fatal("precondition: PolicyStatsEnabled must be OFF")
	}
	// Confirm the parser/compiler recorded `then count` on counted-web only.
	var sawCounted, sawPlain bool
	for _, zpp := range cfg.Security.Policies {
		for _, pol := range zpp.Policies {
			switch pol.Name {
			case "counted-web":
				sawCounted = true
				if !pol.Count {
					t.Fatal("counted-web missing Count=true after `then count`")
				}
			case "plain-web":
				sawPlain = true
				if pol.Count {
					t.Fatal("plain-web unexpectedly has Count=true")
				}
			}
		}
	}
	if !sawCounted || !sawPlain {
		t.Fatalf("policies not found (counted=%v plain=%v)", sawCounted, sawPlain)
	}
	return store
}

func TestCLIShowPoliciesHitCountThenCountOverridesStatsKnob(t *testing.T) {
	store := newThenCountCLIStore(t)
	cfg := store.ActiveConfig()

	// Resolve which rule slot each policy occupies (config order is
	// deterministic for a single zone-pair: slot i = position in
	// zpp.Policies). counted-web/plain-web → slots 0/1 in some order.
	var countedID, plainID uint32
	for _, zpp := range cfg.Security.Policies {
		for i, pol := range zpp.Policies {
			switch pol.Name {
			case "counted-web":
				countedID = uint32(i)
			case "plain-web":
				plainID = uint32(i)
			}
		}
	}

	c := &CLI{
		store: store,
		dp: &policyCounterCLIDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				countedID: {Packets: 42, Bytes: 4242},
				plainID:   {Packets: 99, Bytes: 9999},
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showPoliciesHitCount(cfg, "", ""); err != nil {
			t.Fatalf("showPoliciesHitCount() error = %v", err)
		}
	})

	countedRow, plainRow := rowFor(out, "counted-web"), rowFor(out, "plain-web")
	if countedRow == "" || plainRow == "" {
		t.Fatalf("policy rows not found in output:\n%s", out)
	}
	// `then count` policy must surface its live count even with the
	// system-wide knob OFF (the #3074 fix). Revert -> this fails.
	if !strings.Contains(countedRow, "42") {
		t.Fatalf("counted-web (then count) missing live count 42 with stats OFF:\n%s", countedRow)
	}
	// The sibling without `then count` keeps the pre-#3074 behavior: 0.
	if strings.Contains(plainRow, "99") {
		t.Fatalf("plain-web (no then count) leaked live count 99 with stats OFF:\n%s", plainRow)
	}
}

func rowFor(out, name string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	return ""
}
