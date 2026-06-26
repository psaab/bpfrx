package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// schedulerStateDP is a cliRuntime that also advertises a fixed
// per-scheduler active-state map (the optional
// policySchedulerStateProvider capability the userspace adapter exposes
// at runtime). It lets the policy-detail show surfaces resolve runtime
// scheduler state without a live dataplane.
type schedulerStateDP struct {
	*dataplane.Manager
	active map[string]bool
}

func (d *schedulerStateDP) PolicySchedulerActiveState() map[string]bool {
	return d.active
}

// schedulerPolicyStore commits one zone-pair with a scheduler-bound
// policy ("sched-off") and a plain policy ("plain-allow"), plus a
// global scheduler-bound policy ("g-sched-off").
func schedulerPolicyStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
            }
            policy plain-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy g-sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
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

// TestShowPoliciesDetailReflectsSchedulerInactive pins #3062: the CLI
// policy-detail surfaces render State: inactive for a policy bound to a
// runtime-inactive scheduler, while a plain (non-scheduled) policy still
// renders State: enabled.
//
// FAIL-ON-REVERT: reverting the policyDetailState() render in
// showPoliciesDetail (cli_show_security.go) back to a hardcoded
// "State: enabled" makes the "sched-off ... State: inactive" assertion
// (and the "Scheduler: workhours (inactive)" line) go RED, while the
// plain-allow assertion stays green.
func TestShowPoliciesDetailReflectsSchedulerInactive(t *testing.T) {
	store := schedulerPolicyStore(t)
	c := &CLI{
		store: store,
		dp: &schedulerStateDP{
			Manager: dataplane.New(),
			active:  map[string]bool{"workhours": false},
		},
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showPoliciesDetail(cfg, "", "")
	})
	if callErr != nil {
		t.Fatalf("showPoliciesDetail() error = %v", callErr)
	}

	if !strings.Contains(out, "Policy: sched-off, action-type: permit, State: inactive,") {
		t.Fatalf("detail output missing inactive scheduler-bound policy state:\n%s", out)
	}
	if !strings.Contains(out, "Scheduler: workhours (inactive)") {
		t.Fatalf("detail output missing scheduler name line:\n%s", out)
	}
	if !strings.Contains(out, "Policy: plain-allow, action-type: permit, State: enabled,") {
		t.Fatalf("detail output changed state of plain (active) policy:\n%s", out)
	}
	if !strings.Contains(out, "Policy: g-sched-off, action-type: permit, State: inactive,") {
		t.Fatalf("detail output missing inactive global scheduler-bound policy state:\n%s", out)
	}
}

// TestShowPoliciesDetailActiveSchedulerStaysEnabled asserts that a
// scheduled policy whose scheduler is currently ACTIVE keeps the
// bit-identical "State: enabled" rendering (no Scheduler line) — only
// inactivity changes the output.
func TestShowPoliciesDetailActiveSchedulerStaysEnabled(t *testing.T) {
	store := schedulerPolicyStore(t)
	c := &CLI{
		store: store,
		dp: &schedulerStateDP{
			Manager: dataplane.New(),
			active:  map[string]bool{"workhours": true},
		},
	}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(store.ActiveConfig(), "", ""); err != nil {
			t.Fatalf("showPoliciesDetail() error = %v", err)
		}
	})
	if !strings.Contains(out, "Policy: sched-off, action-type: permit, State: enabled,") {
		t.Fatalf("active scheduler policy should render enabled:\n%s", out)
	}
	if strings.Contains(out, "Scheduler: workhours (inactive)") {
		t.Fatalf("active scheduler policy must not print an inactive scheduler line:\n%s", out)
	}
}

// TestShowPoliciesDetailNoProviderStaysEnabled asserts the bit-identical
// fallback: when the dataplane does not expose scheduler state, every
// policy renders State: enabled (pre-#3062 behaviour).
func TestShowPoliciesDetailNoProviderStaysEnabled(t *testing.T) {
	store := schedulerPolicyStore(t)
	// Bare *dataplane.Manager satisfies cliRuntime but NOT
	// policySchedulerStateProvider.
	c := &CLI{store: store, dp: dataplane.New()}
	out := captureStdout(t, func() {
		if err := c.showPoliciesDetail(store.ActiveConfig(), "", ""); err != nil {
			t.Fatalf("showPoliciesDetail() error = %v", err)
		}
	})
	if !strings.Contains(out, "Policy: sched-off, action-type: permit, State: enabled,") {
		t.Fatalf("no-provider fallback should render enabled:\n%s", out)
	}
	if strings.Contains(out, "State: inactive") {
		t.Fatalf("no-provider fallback must not claim inactive:\n%s", out)
	}
}
