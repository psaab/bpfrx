package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3476: the gRPC policy/screen display + completion surfaces dereference nil
// zone-pair sets, nil rules, nil global rules, and nil screen-profile map
// values reachable on the tolerant / HA-sync config path (#3474) that the
// runtime walker tolerates. These tests inject those nil slots into the live
// ActiveConfig and drive each surface; reverting any of the server_show_zones.go
// / server_show_policies_text.go / server_helpers.go / server_show_security_text.go
// / server_cluster.go nil guards makes the matching subtest panic (RED on revert).

func nilSlotGRPCStore(t *testing.T) *configstore.Store {
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
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; count; }
            }
        }
        global {
            policy g1 {
                match { source-address any; destination-address any; application any; }
                then { deny; count; }
            }
        }
    }
    screen {
        ids-option sp {
            tcp { land; syn-flood; }
            icmp { ping-death; }
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
	if cfg == nil || len(cfg.Security.Policies) == 0 || len(cfg.Security.GlobalPolicies) == 0 {
		t.Fatalf("fixture missing policies")
	}
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, nil)
	cfg.Security.Policies = append(cfg.Security.Policies, nil)
	cfg.Security.GlobalPolicies = append(cfg.Security.GlobalPolicies, nil)
	cfg.Security.Screen["zz-nil-profile"] = nil
	return store
}

func nilSlotGRPCServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		store: nilSlotGRPCStore(t),
		dp: &schedulerCounterGRPCDP{
			Manager:  dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{},
		},
	}
}

func TestGetPoliciesNilSlotsNoPanic(t *testing.T) {
	s := nilSlotGRPCServer(t)
	if _, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{}); err != nil {
		t.Fatalf("GetPolicies error = %v", err)
	}
}

func TestGetScreenNilProfileNoPanic(t *testing.T) {
	s := nilSlotGRPCServer(t)
	if _, err := s.GetScreen(context.Background(), &pb.GetScreenRequest{}); err != nil {
		t.Fatalf("GetScreen error = %v", err)
	}
}

func TestScreenChecksNilReturnsNil(t *testing.T) {
	if got := screenChecks(nil); got != nil {
		t.Fatalf("screenChecks(nil) = %v, want nil", got)
	}
}

func TestShowTextSecurityNilSlotsNoPanic(t *testing.T) {
	for _, topic := range []string{"policies-hit-count", "policies-detail", "screen"} {
		t.Run(topic, func(t *testing.T) {
			s := nilSlotGRPCServer(t)
			if _, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic}); err != nil {
				t.Fatalf("ShowText(%s) error = %v", topic, err)
			}
		})
	}
}

// nilSlotZonesGRPCStore builds a zone (trust) that references a screen profile
// plus a trust->untrust policy set, then injects a nil screen-profile value for
// the referenced profile, a nil rule, and a nil zone-pair set. This exercises
// the `show security zones` detail renderer's present-but-nil screen lookup and
// its policy-summary zpp/pol derefs (the #3476 sites missed in the first pass).
func nilSlotZonesGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            screen sp;
        }
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
    screen {
        ids-option sp {
            tcp { land; syn-flood; }
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
	if cfg == nil || len(cfg.Security.Policies) == 0 {
		t.Fatalf("fixture missing policies")
	}
	cfg.Security.Screen["sp"] = nil // zone trust now references a nil profile
	cfg.Security.Policies[0].Policies = append(cfg.Security.Policies[0].Policies, nil)
	cfg.Security.Policies = append(cfg.Security.Policies, nil)
	return store
}

func TestShowZonesDetailNilSlotsNoPanic(t *testing.T) {
	s := &Server{store: nilSlotZonesGRPCStore(t)} // dp nil: skip counters, run screen+summary
	if _, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "zones-detail"}); err != nil {
		t.Fatalf("ShowText(zones-detail) error = %v", err)
	}
}

func TestValueProviderPolicyNameNilSlotsNoPanic(t *testing.T) {
	s := nilSlotGRPCServer(t)
	// zone-pair completion path (iterates cfg.Security.Policies)
	_ = s.valueProvider(config.ValueHintPolicyName,
		[]string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy"})
	// global completion path (iterates cfg.Security.GlobalPolicies)
	_ = s.valueProvider(config.ValueHintPolicyName,
		[]string{"security", "policies", "global", "policy"})
}
