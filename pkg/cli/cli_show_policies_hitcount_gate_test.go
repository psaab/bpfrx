package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #2118: the local-CLI `show security policies hit-count` table must
// honor `security policy-stats system-wide enable` exactly like the
// Prometheus collector (#2008 M4) and the gRPC surfaces, so all surfaces
// agree. These tests assert the "Policy count" column reflects live
// counts when the knob is on and reads 0 when off, for the SAME
// populated dataplane.

type policyCounterCLIDP struct {
	*dataplane.Manager
	counters map[uint32]dataplane.CounterValue
}

func (d *policyCounterCLIDP) IsLoaded() bool { return true }

func (d *policyCounterCLIDP) ReadPolicyCounters(policyID uint32) (dataplane.CounterValue, error) {
	return d.counters[policyID], nil
}

func newPolicyHitCountCLIStore(t *testing.T, statsEnabled bool) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	cmds := []string{
		"security zones security-zone trust",
		"security zones security-zone untrust",
		"security policies from-zone trust to-zone untrust policy allow-web match source-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match destination-address any",
		"security policies from-zone trust to-zone untrust policy allow-web match application any",
		"security policies from-zone trust to-zone untrust policy allow-web then permit",
	}
	if statsEnabled {
		cmds = append(cmds, "security policy-stats system-wide enable")
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
	if cfg == nil || cfg.Security.PolicyStatsEnabled != statsEnabled {
		t.Fatalf("PolicyStatsEnabled precondition not met (want %v)", statsEnabled)
	}
	return store
}

func TestCLIShowPoliciesHitCountHonorsPolicyStats(t *testing.T) {
	for _, tc := range []struct {
		name    string
		statsOn bool
	}{
		{name: "enabled", statsOn: true},
		{name: "disabled", statsOn: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newPolicyHitCountCLIStore(t, tc.statsOn)
			cfg := store.ActiveConfig()
			// trust->untrust is the only policy set -> set 0, rule 0.
			ruleID := uint32(0)
			c := &CLI{
				store: store,
				dp: &policyCounterCLIDP{
					Manager:  dataplane.New(),
					counters: map[uint32]dataplane.CounterValue{ruleID: {Packets: 42, Bytes: 4242}},
				},
			}

			var callErr error
			out := captureStdout(t, func() {
				callErr = c.showPoliciesHitCount(cfg, "", "")
			})
			if callErr != nil {
				t.Fatalf("showPoliciesHitCount() error = %v", callErr)
			}

			var row string
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "allow-web") {
					row = line
					break
				}
			}
			if row == "" {
				t.Fatalf("allow-web row not found in output:\n%s", out)
			}
			if tc.statsOn {
				if !strings.Contains(row, "42") {
					t.Fatalf("policy-stats ON: allow-web row missing live count 42:\n%s", row)
				}
			} else {
				if strings.Contains(row, "42") {
					t.Fatalf("policy-stats OFF: allow-web row leaked live count 42 (must be 0):\n%s", row)
				}
			}
		})
	}
}
