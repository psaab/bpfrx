package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// scopeIDPolicyStore commits two zone pairs that share a duplicate policy NAME
// "allow" (legal in Junos) plus a scoped global policy, so a name-only verdict
// is ambiguous — exactly the #3331 case.
func scopeIDPolicyStore(t *testing.T) *configstore.Store {
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
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        from-zone untrust to-zone trust {
            policy allow {
                match { source-address any; destination-address any; application any; }
                then { deny; }
            }
        }
        global {
            policy g-allow {
                match { source-address any; destination-address any; application any; from-zone trust; }
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
	return store
}

// TestMatchPoliciesResponseCarriesScopeAndID pins #3331 on the gRPC surface:
// the MatchPolicies response must report Global, FromZone/ToZone scope, and the
// stable runtime PolicyId so a caller can disambiguate a verdict when policy
// names collide across zone pairs / global scope.
//
// RED-on-revert: before #3331 MatchPoliciesResponse carried only
// policy_name/action, so Global/FromZone/ToZone/PolicyId are all zero-value and
// every assertion below fails.
func TestMatchPoliciesResponseCarriesScopeAndID(t *testing.T) {
	store := scopeIDPolicyStore(t)
	s := &Server{store: store}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)

	// untrust->trust "allow" (deny) — a zone-pair match.
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "untrust", ToZone: "trust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected match, got %+v", resp)
	}
	if resp.Global {
		t.Errorf("Global = true, want false (zone-pair policy)")
	}
	if resp.FromZone != "untrust" || resp.ToZone != "trust" {
		t.Errorf("scope = %s->%s, want untrust->trust", resp.FromZone, resp.ToZone)
	}
	if resp.PolicyName != "allow" {
		t.Errorf("PolicyName = %q, want allow", resp.PolicyName)
	}
	// PolicyId must be the untrust->trust set's runtime ID, NOT the same-named
	// trust->untrust policy's.
	var untrustSet, trustSet int
	for i, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		if zpp.FromZone == "untrust" && zpp.ToZone == "trust" {
			untrustSet = i
		}
		if zpp.FromZone == "trust" && zpp.ToZone == "untrust" {
			trustSet = i
		}
	}
	wantID := ids[[2]uint32{uint32(untrustSet), 0}]
	if resp.GetPolicyId() != wantID {
		t.Errorf("PolicyId = %d, want %d (untrust->trust runtime ID)", resp.GetPolicyId(), wantID)
	}
	// #3623: on a match the id must be PRESENT (pointer non-nil), even at 0.
	if resp.PolicyId == nil {
		t.Errorf("PolicyId absent on a matched response; want explicit presence (#3623)")
	}
	if otherID := ids[[2]uint32{uint32(trustSet), 0}]; otherID == resp.GetPolicyId() {
		t.Errorf("duplicate-name policies share PolicyId %d; cannot disambiguate", resp.GetPolicyId())
	}

	// trust->untrust matches the SCOPED GLOBAL g-allow first? No — the exact
	// zone-pair "allow" (permit) outranks global. Query a pair with NO exact
	// zone-pair rule so the scoped global wins, proving the global branch
	// stamps scope/id too. trust->untrust has an exact rule, so use a flow that
	// only the global covers: trust as ingress, but choose to-zone that has no
	// exact pair. Here trust->untrust IS exact (permit), so assert that path
	// reports the zone-pair, then separately exercise the global via from trust
	// to a different (defined) zone with no exact pair.
	respGP, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "trust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(global) error = %v", err)
	}
	if !respGP.Matched || !respGP.Global {
		t.Fatalf("expected scoped-global match for trust->trust, got %+v", respGP)
	}
	if respGP.PolicyName != "g-allow" {
		t.Errorf("PolicyName = %q, want g-allow", respGP.PolicyName)
	}
	if respGP.FromZone != "trust" {
		t.Errorf("global scope from-zone = %q, want trust", respGP.FromZone)
	}
	wantGID := ids[[2]uint32{uint32(len(cfg.Security.Policies)), 0}]
	if respGP.GetPolicyId() != wantGID {
		t.Errorf("PolicyId = %d, want %d (global set runtime ID)", respGP.GetPolicyId(), wantGID)
	}
}
