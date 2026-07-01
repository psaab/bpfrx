package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3623: proto3 explicit presence for the runtime policy_id. The first runtime
// policy legitimately has policy_id 0; a bare proto3 uint32 omits the zero value
// on the wire, so a generic JSON/proto client could not distinguish "first
// policy, id 0" from "field unset". PolicyRule.policy_id and
// MatchPoliciesResponse.policy_id are now `optional uint32` (pointer + presence
// in Go): the inventory always sets it (always present), and match-policies sets
// it only on a match (present even at 0; absent on no match). These tests assert
// the pointer is non-nil AND the value is 0 for the first policy. RED-on-revert:
// drop `optional` back to a plain scalar and the presence (nil-pointer) checks
// fail.

// firstPolicyZeroGRPCStore commits a single zone-pair policy whose sole rule is
// the first runtime policy — its span-accumulated runtime id is 0.
func firstPolicyZeroGRPCStore(t *testing.T) *configstore.Store {
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
        from-zone trust to-zone untrust {
            policy allow-first {
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
	return store
}

func TestGetPoliciesConveysPolicyIDZeroForFirstRule(t *testing.T) {
	store := firstPolicyZeroGRPCStore(t)
	s := &Server{store: store}

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	ids := dpuserspace.RuntimePolicyIDs(cfg)
	if got := dpuserspace.RuntimePolicyIndex(ids, 0, 0); got != 0 {
		t.Fatalf("first policy runtime id = %d, want 0 (fixture no longer exercises the id-0 edge)", got)
	}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}

	var found *pb.PolicyRule
	for _, pi := range resp.GetPolicies() {
		for _, r := range pi.GetRules() {
			if r.GetName() == "allow-first" {
				found = r
			}
		}
	}
	if found == nil {
		t.Fatalf("allow-first missing from gRPC GetPolicies inventory")
	}
	// Explicit presence: the pointer must be set even though the value is 0.
	if found.PolicyId == nil {
		t.Fatalf("allow-first PolicyId absent (nil) for id 0 — #3623 regression: " +
			"a bare proto3 scalar drops the first policy's join key on the wire")
	}
	if found.GetPolicyId() != 0 {
		t.Fatalf("allow-first PolicyId = %d, want 0", found.GetPolicyId())
	}
}

func TestMatchPoliciesConveysPolicyIDZeroForFirstRule(t *testing.T) {
	store := firstPolicyZeroGRPCStore(t)
	s := &Server{store: store}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies() error = %v", err)
	}
	if !resp.GetMatched() {
		t.Fatalf("expected a match for trust->untrust, got %+v", resp)
	}
	if resp.PolicyId == nil {
		t.Fatalf("matched-first-policy PolicyId absent (nil) — #3623 regression: " +
			"a matched first policy (id 0) is indistinguishable from no match on the wire")
	}
	if resp.GetPolicyId() != 0 {
		t.Fatalf("matched PolicyId = %d, want 0 (first policy)", resp.GetPolicyId())
	}

	// The unmatched path must leave PolicyId unset so a client never reads a
	// no-match verdict as "matched policy 0".
	un, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "untrust", ToZone: "trust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(unmatched) error = %v", err)
	}
	if un.GetMatched() {
		t.Fatalf("expected NO match for untrust->trust, got %+v", un)
	}
	if un.PolicyId != nil {
		t.Fatalf("unmatched response set PolicyId = %d; want unset (nil)", un.GetPolicyId())
	}
}
