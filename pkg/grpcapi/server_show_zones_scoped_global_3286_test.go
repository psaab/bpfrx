package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3286: a scoped global policy (#3148, `match from-zone`/`to-zone`) was
// rendered as all-zones in the gRPC GetPolicies inventory — the per-rule
// match-zone context was dropped, so an operator could not tell that a
// global rule was narrowed to a zone pair. The structured response now
// carries MatchFromZone/MatchToZone on the global rule. These tests are the
// fail-on-revert guard: drop the population in server_show_zones.go and the
// scoped assertion goes RED (zones come back empty / all-zones).

// scopedGlobalGRPCStore builds a config with one scoped global policy
// (from-zone trust, to-zone untrust) and one unscoped (all-zones) global
// policy so the inventory must distinguish them.
func scopedGlobalGRPCStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        global {
            policy scoped-global {
                match {
                    from-zone trust;
                    to-zone untrust;
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
            }
            policy open-global {
                match { source-address any; destination-address any; application any; }
                then { permit; }
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
	if len(cfg.Security.GlobalPolicies) != 2 {
		t.Fatalf("GlobalPolicies len = %d, want 2", len(cfg.Security.GlobalPolicies))
	}
	return store
}

// TestGetPoliciesScopedGlobalCarriesZones is the #3286 fail-on-revert guard:
// the gRPC GetPolicies global row must carry the scoped from/to-zone on the
// scoped rule and leave them empty on the unscoped rule.
func TestGetPoliciesScopedGlobalCarriesZones(t *testing.T) {
	s := &Server{store: scopedGlobalGRPCStore(t)}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}

	var sawScoped, sawOpen bool
	for _, policy := range resp.GetPolicies() {
		// Globals are still grouped under the all-zones "*"/"*" PolicyInfo.
		if policy.GetFromZone() != "*" || policy.GetToZone() != "*" {
			continue
		}
		for _, rule := range policy.GetRules() {
			switch rule.GetName() {
			case "scoped-global":
				sawScoped = true
				if rule.GetMatchFromZone() != "trust" || rule.GetMatchToZone() != "untrust" {
					t.Fatalf("scoped-global match zones = %q/%q, want trust/untrust "+
						"(scoped global rendered as all-zones — #3286 regression)",
						rule.GetMatchFromZone(), rule.GetMatchToZone())
				}
			case "open-global":
				sawOpen = true
				if rule.GetMatchFromZone() != "" || rule.GetMatchToZone() != "" {
					t.Fatalf("open-global match zones = %q/%q, want empty (all-zones global)",
						rule.GetMatchFromZone(), rule.GetMatchToZone())
				}
			}
		}
	}
	if !sawScoped {
		t.Fatal("scoped-global policy missing from gRPC GetPolicies global group")
	}
	if !sawOpen {
		t.Fatal("open-global policy missing from gRPC GetPolicies global group")
	}
}

// TestShowTextPoliciesScopedGlobalShowsZones is the #3286 fail-on-revert guard
// for the gRPC text surfaces (ShowText): the hit-count table row for a scoped
// global must carry its zone pair (not "*"/"*"), and the detail view must print
// the Source/Destination zone scope.
func TestShowTextPoliciesScopedGlobalShowsZones(t *testing.T) {
	s := &Server{store: scopedGlobalGRPCStore(t)}

	hc, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-hit-count"})
	if err != nil {
		t.Fatalf("ShowText(policies-hit-count) error = %v", err)
	}
	var scopedRow string
	for _, line := range strings.Split(hc.GetOutput(), "\n") {
		if strings.Contains(line, "scoped-global") {
			scopedRow = line
			break
		}
	}
	if scopedRow == "" {
		t.Fatalf("scoped-global missing from hit-count text:\n%s", hc.GetOutput())
	}
	if !strings.Contains(scopedRow, "trust") || !strings.Contains(scopedRow, "untrust") {
		t.Fatalf("hit-count scoped-global row = %q, want trust/untrust columns "+
			"(scoped global shown as all-zones — #3286 regression)", scopedRow)
	}

	det, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "policies-detail"})
	if err != nil {
		t.Fatalf("ShowText(policies-detail) error = %v", err)
	}
	out := det.GetOutput()
	idx := strings.Index(out, "scoped-global")
	if idx < 0 {
		t.Fatalf("scoped-global missing from detail text:\n%s", out)
	}
	block := out[idx:]
	if !strings.Contains(block, "Source zone: trust") || !strings.Contains(block, "Destination zone: untrust") {
		t.Fatalf("detail text scoped-global block missing zone scope "+
			"(want Source zone: trust / Destination zone: untrust):\n%s", block)
	}
}
