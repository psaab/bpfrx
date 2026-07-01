package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #3624: the gRPC structured policy inventory (GetPolicies / PolicyRule) dropped
// a policy's scheduler binding (scheduler_name) and its runtime scheduler state
// (inactive). #3062 exposed both only on the human-readable TEXT policy-detail
// surface (server_show_policies_text.go), so a structured audit client driving
// GetPolicies could not tell that a permit/deny rule is time-gated, nor that it
// is currently runtime-inactive — it displayed a dormant rule as an active
// allow/deny. PolicyRule now carries scheduler_name + inactive, populated for
// zone-pair AND global policies from the same provider the text surface uses
// (Server.policySchedulerActiveState). These are the fail-on-revert guards:
// drop the population in server_show_zones.go (GetPolicies) and the assertions
// below go RED.
//
// The store harness (schedulerPolicyServer) is shared with the #3062 text-detail
// test: sched-off (scheduled zone-pair permit, "workhours"), plain-allow (plain
// permit), g-sched-off (scheduled global permit, "workhours").

func grpcInventoryRules(t *testing.T, s *Server) map[string]*pb.PolicyRule {
	t.Helper()
	resp, err := s.GetPolicies(context.Background(), &pb.GetPoliciesRequest{})
	if err != nil {
		t.Fatalf("GetPolicies() error = %v", err)
	}
	rules := map[string]*pb.PolicyRule{}
	for _, pi := range resp.GetPolicies() {
		for _, r := range pi.GetRules() {
			rules[r.GetName()] = r
		}
	}
	return rules
}

func TestGRPCGetPoliciesExposesSchedulerBindingAndInactiveState(t *testing.T) {
	// Case A: live scheduler state present and INACTIVE. Scheduled zone-pair AND
	// global rules report their binding and are marked inactive; the plain rule
	// stays active with no binding.
	t.Run("scheduler inactive -> scheduler_name + inactive=true", func(t *testing.T) {
		s := schedulerPolicyServer(t, map[string]bool{"workhours": false}, true)
		rules := grpcInventoryRules(t, s)

		so := rules["sched-off"]
		if so == nil {
			t.Fatalf("sched-off missing from gRPC inventory")
		}
		if so.GetSchedulerName() != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q (gRPC dropped the scheduler binding — #3624 regression)",
				so.GetSchedulerName(), "workhours")
		}
		if !so.GetInactive() {
			t.Fatalf("sched-off inactive = false, want true (scheduler inactive; gRPC dropped runtime state — #3624 regression)")
		}

		gso := rules["g-sched-off"]
		if gso == nil {
			t.Fatalf("g-sched-off missing from gRPC inventory")
		}
		if gso.GetSchedulerName() != "workhours" || !gso.GetInactive() {
			t.Fatalf("g-sched-off scheduler_name=%q inactive=%v, want workhours/true (global path not plumbed — #3624)",
				gso.GetSchedulerName(), gso.GetInactive())
		}

		pl := rules["plain-allow"]
		if pl == nil {
			t.Fatalf("plain-allow missing from gRPC inventory")
		}
		if pl.GetSchedulerName() != "" || pl.GetInactive() {
			t.Fatalf("plain-allow scheduler_name=%q inactive=%v, want empty/false (unscheduled rule must not gain state)",
				pl.GetSchedulerName(), pl.GetInactive())
		}
	})

	// Case B (positive control): scheduler ACTIVE -> binding reported,
	// inactive=false. Guards against over-marking every scheduled rule inactive.
	t.Run("scheduler active -> scheduler_name kept, inactive=false", func(t *testing.T) {
		s := schedulerPolicyServer(t, map[string]bool{"workhours": true}, true)
		rules := grpcInventoryRules(t, s)
		so := rules["sched-off"]
		if so.GetSchedulerName() != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q", so.GetSchedulerName(), "workhours")
		}
		if so.GetInactive() {
			t.Fatalf("sched-off inactive = true, want false (scheduler active)")
		}
	})

	// Case C (fail-open display): no provider -> binding still reported
	// (config-derived) but inactive stays false, matching the #3062 text
	// surface's fail-open display and keeping the output unchanged for existing
	// consumers.
	t.Run("no provider -> scheduler_name kept, inactive=false", func(t *testing.T) {
		s := schedulerPolicyServer(t, nil, false)
		rules := grpcInventoryRules(t, s)
		so := rules["sched-off"]
		if so.GetSchedulerName() != "workhours" {
			t.Fatalf("sched-off scheduler_name = %q, want %q (binding is config-derived, always reported)",
				so.GetSchedulerName(), "workhours")
		}
		if so.GetInactive() {
			t.Fatalf("sched-off inactive = true, want false (no provider must fail open on the DISPLAY surface)")
		}
	})
}
