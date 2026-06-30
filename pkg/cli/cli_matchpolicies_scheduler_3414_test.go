package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// schedOnlyMatchStore commits a config whose ONLY trust->untrust rule is a
// scheduled PERMIT bound to "after-hours", with default-policy deny and NO
// unscheduled fallback — so the `show security match-policies` verdict turns
// entirely on whether the scheduled rule is treated active. The dataplane drops
// such a rule whenever per-scheduler active-state is unavailable
// (policyRuleInactive: nil map => Inactive), so the CLI simulator must report
// default-deny on that path (#3414).
func schedOnlyMatchStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler after-hours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy night-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name after-hours;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// schedMatchCLI builds a CLI over schedOnlyMatchStore. When withProvider is
// false the dp is a bare *dataplane.Manager, which satisfies cliRuntime but NOT
// policySchedulerStateProvider — exactly the state-unavailable path
// (c.policySchedulerActiveState returns ok=false).
func schedMatchCLI(t *testing.T, active map[string]bool, withProvider bool) *CLI {
	t.Helper()
	c := &CLI{store: schedOnlyMatchStore(t)}
	if withProvider {
		c.dp = &schedulerStateDP{Manager: dataplane.New(), active: active}
	} else {
		c.dp = dataplane.New()
	}
	return c
}

// TestShowMatchPoliciesScheduledPolicyFailsClosedWhenStateUnavailable pins
// #3414 on the CLI `show security match-policies` simulator. With NO
// scheduler-state provider (early boot / NoDataplane) the simulator must treat
// the scheduler-bound permit as INACTIVE — exactly as the dataplane does — and
// fall through to the default-policy. Before #3414 c.policyInactiveFn()
// returned nil on this path, so the scheduled permit was simulated
// as-if-active and the CLI certified a PERMIT the dataplane is skipping.
//
// RED-on-revert: reverting cli_show_security_dispatch.go:policyInactiveFn to
//
//	state, ok := c.policySchedulerActiveState(); if !ok { return nil }
//
// makes the no-provider case below print the matched "Policy: night-allow"
// verdict instead of the default-deny fall-through, so the assertions fail.
// Positive controls C/D (provider present) are unaffected by that revert.
func TestShowMatchPoliciesScheduledPolicyFailsClosedWhenStateUnavailable(t *testing.T) {
	args := []string{"from-zone", "trust", "to-zone", "untrust", "protocol", "tcp", "destination-port", "80"}

	// Case A: no provider -> state unavailable -> fail closed (default deny).
	t.Run("no provider -> fail closed default deny", func(t *testing.T) {
		c := schedMatchCLI(t, nil, false)
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies(c.store.ActiveConfig(), args); err != nil {
				t.Fatalf("showMatchPolicies() error = %v", err)
			}
		})
		if !strings.Contains(out, "No matching policy found for trust -> untrust") {
			t.Fatalf("want default-deny fall-through (scheduled permit must be skipped when state unavailable); got:\n%s", out)
		}
		if strings.Contains(out, "Policy: night-allow") {
			t.Fatalf("scheduled permit was certified as a match with unavailable state (#3414 regression):\n%s", out)
		}
	})

	// Case C (positive control): provider present, scheduler ACTIVE -> permit.
	t.Run("scheduler active -> permit", func(t *testing.T) {
		c := schedMatchCLI(t, map[string]bool{"after-hours": true}, true)
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies(c.store.ActiveConfig(), args); err != nil {
				t.Fatalf("showMatchPolicies() error = %v", err)
			}
		})
		if !strings.Contains(out, "Matching policy:") || !strings.Contains(out, "Policy: night-allow") {
			t.Fatalf("want matched night-allow permit (scheduler active); got:\n%s", out)
		}
	})

	// Case D (regression anchor): provider present, scheduler INACTIVE ->
	// default deny (the #3104 behavior, unchanged by #3414).
	t.Run("scheduler inactive -> default deny", func(t *testing.T) {
		c := schedMatchCLI(t, map[string]bool{"after-hours": false}, true)
		out := captureStdout(t, func() {
			if err := c.showMatchPolicies(c.store.ActiveConfig(), args); err != nil {
				t.Fatalf("showMatchPolicies() error = %v", err)
			}
		})
		if !strings.Contains(out, "No matching policy found for trust -> untrust") {
			t.Fatalf("want default-deny fall-through (scheduler inactive); got:\n%s", out)
		}
		if strings.Contains(out, "Policy: night-allow") {
			t.Fatalf("inactive scheduled permit was certified as a match:\n%s", out)
		}
	})
}
