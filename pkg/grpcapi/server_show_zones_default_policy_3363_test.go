package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestGetPoliciesIncludesDefaultPolicyRow is the #3363 fail-on-revert guard for
// the STRUCTURED GetPolicies RPC. The implicit default-policy catch-all now has
// a reserved hit counter (read via dataplane.DefaultPolicySentinelID), and every
// other surface (REST /policies, CLI, gRPC text, Prometheus) renders it as a
// synthetic "-"/"-" / default-policy row. GetPolicies must surface the same row
// with the live counter; if the synthetic append is reverted, this test goes RED.
func TestGetPoliciesIncludesDefaultPolicyRow(t *testing.T) {
	store := globalHitCountStore(t) // policy-stats enabled, 1 zone-pair + 1 global
	s := &Server{
		store: store,
		dp: &schedulerCounterGRPCDP{
			Manager: dataplane.New(),
			counters: map[uint32]dataplane.CounterValue{
				dataplane.DefaultPolicySentinelID: {Packets: 42, Bytes: 4200},
			},
		},
	}

	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}

	// Locate the synthetic default-policy row: a "-"/"-" PolicyInfo carrying a
	// single rule named dataplane.DefaultPolicyName.
	var defRule *pb.PolicyRule
	var defInfo *pb.PolicyInfo
	for _, pi := range resp.GetPolicies() {
		for _, r := range pi.GetRules() {
			if r.GetName() == dataplane.DefaultPolicyName {
				defRule = r
				defInfo = pi
				break
			}
		}
		if defRule != nil {
			break
		}
	}
	if defRule == nil {
		t.Fatalf("GetPolicies() missing synthetic default-policy row (Name=%q); "+
			"#3363 structured-RPC parity reverted", dataplane.DefaultPolicyName)
	}

	if defInfo.GetFromZone() != "-" || defInfo.GetToZone() != "-" {
		t.Fatalf("default-policy row zones = %q/%q, want -/-",
			defInfo.GetFromZone(), defInfo.GetToZone())
	}
	if defRule.GetPolicyId() != dataplane.DefaultPolicySentinelID {
		t.Fatalf("default-policy row PolicyId = %d, want sentinel %d",
			defRule.GetPolicyId(), dataplane.DefaultPolicySentinelID)
	}
	if defRule.GetRuleId() != dataplane.DefaultPolicyName {
		t.Fatalf("default-policy row RuleId = %q, want %q",
			defRule.GetRuleId(), dataplane.DefaultPolicyName)
	}
	// The live counter read through the DefaultPolicySentinelID handle must be
	// surfaced — not a zero/tautological value.
	if defRule.GetHitPackets() != 42 || defRule.GetHitBytes() != 4200 {
		t.Fatalf("default-policy row counts = %d/%d, want 42/4200 (counter read "+
			"via DefaultPolicySentinelID not surfaced)",
			defRule.GetHitPackets(), defRule.GetHitBytes())
	}
}
