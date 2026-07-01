package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// schedulerStateDP is a grpcRuntime that also advertises a fixed
// per-scheduler active-state map (the optional
// policySchedulerStateProvider capability the userspace adapter exposes
// at runtime).
type schedulerStateDP struct {
	*dataplane.Manager
	active map[string]bool
}

func (d *schedulerStateDP) PolicySchedulerActiveState() map[string]bool {
	return d.active
}

func schedulerPolicyServer(t *testing.T, active map[string]bool, withProvider bool) *Server {
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
	s := &Server{store: store}
	if withProvider {
		s.dp = &schedulerStateDP{Manager: dataplane.New(), active: active}
	} else {
		// Bare *dataplane.Manager satisfies grpcRuntime but NOT
		// policySchedulerStateProvider.
		s.dp = dataplane.New()
	}
	return s
}

// TestGRPCShowPoliciesDetailReflectsSchedulerInactive pins #3062 on the
// gRPC text policy-detail surface: a scheduler-inactive policy header
// gains ", State: inactive, Scheduler: <name>"; the plain (active)
// policy header stays bit-identical (no suffix).
//
// FAIL-ON-REVERT: reverting the policyDetailStateSuffix() call in
// showPoliciesDetail (server_show_policies_text.go) back to a bare
// "\n  Policy: %s, action-type: %s\n" makes the "State: inactive"
// assertions go RED.
func TestGRPCShowPoliciesDetailReflectsSchedulerInactive(t *testing.T) {
	s := schedulerPolicyServer(t, map[string]bool{"workhours": false}, true)

	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()

	if !strings.Contains(out, "Policy: sched-off, action-type: Permit, State: inactive, Scheduler: workhours") {
		t.Fatalf("gRPC detail missing inactive scheduler-bound policy state:\n%s", out)
	}
	if !strings.Contains(out, "Policy: g-sched-off, action-type: Permit, State: inactive, Scheduler: workhours") {
		t.Fatalf("gRPC detail missing inactive global scheduler-bound policy state:\n%s", out)
	}
	// The plain policy header must stay suffix-free (no State suffix). The
	// #3667 Index column follows action-type directly for an active policy, so
	// matching "action-type: Permit, Index: " proves no State suffix was
	// inserted between them.
	if !strings.Contains(out, "Policy: plain-allow, action-type: Permit, Index: ") {
		t.Fatalf("gRPC detail changed plain (active) policy header:\n%s", out)
	}
}

// TestGRPCShowPoliciesDetailActiveSchedulerNoSuffix asserts an active
// scheduler keeps the bit-identical header (no suffix).
func TestGRPCShowPoliciesDetailActiveSchedulerNoSuffix(t *testing.T) {
	s := schedulerPolicyServer(t, map[string]bool{"workhours": true}, true)
	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()
	if !strings.Contains(out, "Policy: sched-off, action-type: Permit, Index: ") {
		t.Fatalf("active scheduler policy should keep bit-identical header:\n%s", out)
	}
	if strings.Contains(out, "State: inactive") {
		t.Fatalf("active scheduler policy must not be marked inactive:\n%s", out)
	}
}

// TestGRPCShowPoliciesDetailNoProviderNoSuffix asserts the fallback: no
// provider -> no header changes (pre-#3062 byte-identical output).
func TestGRPCShowPoliciesDetailNoProviderNoSuffix(t *testing.T) {
	s := schedulerPolicyServer(t, nil, false)
	var buf strings.Builder
	s.showPoliciesDetail("", &buf)
	out := buf.String()
	if !strings.Contains(out, "Policy: sched-off, action-type: Permit, Index: ") {
		t.Fatalf("no-provider fallback should keep bit-identical header:\n%s", out)
	}
	if strings.Contains(out, "State: inactive") {
		t.Fatalf("no-provider fallback must not claim inactive:\n%s", out)
	}
}
