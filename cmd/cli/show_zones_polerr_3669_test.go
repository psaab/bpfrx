package main

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3669: the remote `show security zones` view discarded the GetPolicies error
// (`polResp, _ := ...`) and still returned success. When the policy inventory
// RPC failed, the per-zone "Policies:" references were silently omitted — which
// reads identically to "these zones have no policies" — and the command exited
// 0. On a firewall a partial policy view must fail loud so an operator (or
// automation scraping exit status) can tell a control-plane degradation apart
// from genuinely policy-free zones.
//
// FAIL-ON-REVERT: restoring `polResp, _ := c.client.GetPolicies(...)` (dropping
// the error) makes showZones return nil, so the "expected non-nil error"
// assertion goes RED.
func TestShowZonesSurfacesGetPoliciesError(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{
				{Name: "trust", Interfaces: []string{"ge-0-0-0"}},
			},
		},
		getPoliciesErr: errors.New("rpc failure: connection refused"),
	}
	c := &ctl{client: fake}

	var out string
	var err error
	out = captureStdout(t, func() {
		err = c.showZones("")
	})

	if err == nil {
		t.Fatal("showZones returned nil error when GetPolicies failed; " +
			"a swallowed policy-inventory failure renders zones as policy-free " +
			"with exit 0 (#3669)")
	}
	if !strings.Contains(err.Error(), "policy inventory unavailable") {
		t.Errorf("error = %q, want it to name the degraded policy inventory", err)
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, want it to wrap the underlying RPC error", err)
	}
	// GetZones succeeded, so the zone body is still rendered (partial output is
	// preserved — the failure is surfaced via the returned error, not by
	// swallowing valid zone data).
	if !strings.Contains(out, "Zone: trust") {
		t.Errorf("zone body not rendered on policy-inventory failure:\n%s", out)
	}
}

// TestShowZonesSucceedsWhenPolicyInventoryOK guards the happy path: when
// GetPolicies succeeds the command returns nil and renders the policy
// references, so the #3669 error-surfacing change does not regress the normal
// case.
func TestShowZonesSucceedsWhenPolicyInventoryOK(t *testing.T) {
	fake := &fakeBpfrxClient{
		getZonesResp: &pb.GetZonesResponse{
			Zones: []*pb.ZoneInfo{
				{Name: "trust", Interfaces: []string{"ge-0-0-0"}},
			},
		},
		getPoliciesResp: &pb.GetPoliciesResponse{
			Policies: []*pb.PolicyInfo{
				{
					FromZone: "trust",
					ToZone:   "untrust",
					Rules:    []*pb.PolicyRule{{Name: "allow-web", Action: "permit"}},
				},
			},
		},
	}
	c := &ctl{client: fake}

	out := captureStdout(t, func() {
		if err := c.showZones(""); err != nil {
			t.Fatalf("showZones returned error on the happy path: %v", err)
		}
	})
	// #3683 (M01): the remote summary now renders the tiered "Policy summary"
	// block (zone-pair / global / default), replacing the pre-#3683 compact
	// "Policies: from <peer> (N rules)" refs line.
	if !strings.Contains(out, "[zone-pair] trust -> untrust: allow-web (permit)") {
		t.Errorf("expected zone-pair policy tier rendered for trust zone:\n%s", out)
	}
}
