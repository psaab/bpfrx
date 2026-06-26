package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3059: the gRPC text `show security policies hit-count` view looped only
// zone-pair policies and omitted global policies, even though the runtime
// enforces them and every other surface (gRPC detail, CLI, Prometheus, REST
// inventory after #3045/#3050, structured GetPolicies) counts them. These
// tests are the fail-on-revert guard: the hit-count text must include a
// global policy row with the correct dataplane counter ID.

// globalHitCountStore builds a config with one zone-pair policy plus one
// global policy and enables policy-stats so the hit-count surface reads live
// counters.
func globalHitCountStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    policy-stats {
        system-wide enable;
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy zone-allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        global {
            policy global-deny {
                match { source-address any; destination-address any; application any; }
                then { deny; }
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
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	if !cfg.Security.PolicyStatsEnabled {
		t.Fatal("PolicyStatsEnabled = false, want true")
	}
	if len(cfg.Security.GlobalPolicies) != 1 {
		t.Fatalf("GlobalPolicies len = %d, want 1", len(cfg.Security.GlobalPolicies))
	}
	return store
}

// globalDenyPolicyID resolves the dataplane counter slot for the single
// global global-deny rule. Global counter IDs continue from the zone-pair
// loop: the first global rule uses policySetID == len(cfg.Security.Policies),
// the same alignment the dataplane and #3045/#3050 use.
func globalDenyPolicyID(store *configstore.Store) uint32 {
	cfg := store.ActiveConfig()
	return uint32(len(cfg.Security.Policies))*dataplane.MaxRulesPerPolicy + 0
}

// TestShowPoliciesHitCountIncludesGlobalPolicies is the #3059 fail-on-revert
// guard: the gRPC hit-count text must render a global policy row with the
// dataplane counter read at the continued (global) counter ID. If
// showPoliciesHitCount reverts to zone-pair-only enumeration, the global row
// is absent and this test goes RED.
func TestShowPoliciesHitCountIncludesGlobalPolicies(t *testing.T) {
	store := globalHitCountStore(t)
	globalID := globalDenyPolicyID(store)
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				globalID: {Packets: 77, Bytes: 7700},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-hit-count"})
	if err != nil {
		t.Fatalf("ShowText(policies-hit-count) error = %v", err)
	}
	out := resp.GetOutput()

	// The zone-pair row must still be present (no regression).
	if !strings.Contains(out, "zone-allow") {
		t.Fatalf("zone-pair policy zone-allow missing from hit-count output:\n%s", out)
	}

	// Locate the global-deny data row.
	var row string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "global-deny") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatalf("global policy global-deny missing from hit-count output; "+
			"globals omitted (#3059 regression):\n%s", out)
	}
	// Global row uses "*"/"*" zones and the live counts at the continued ID.
	fields := strings.Fields(row)
	if len(fields) < 2 || fields[0] != "*" || fields[1] != "*" {
		t.Fatalf("global row missing */* zone columns: %q", row)
	}
	if !strings.Contains(row, "deny") {
		t.Fatalf("global-deny row missing deny action: %q", row)
	}
	if !strings.Contains(row, "77") || !strings.Contains(row, "7700") {
		t.Fatalf("global-deny row missing live counts (want 77/7700) at counter ID %d:\n%s",
			globalID, row)
	}
}
