package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestShowTestPolicyRejectsDuplicate is the #3709 RED-on-revert guard for the
// gRPC ShowText "test-policy:" bridge. The comma/equals key=value loop
// re-assigned fromZone/dstPort/... on a repeated key, silently LAST-winning, so
// a duplicate selector (e.g. `from=trust,from=dmz`) evaluated a DIFFERENT packet
// than the operator typed — and disagreed with REST (first-win) on which value
// survived. The handler now reports a duplicate-selector diagnostic instead.
//
// FAIL-ON-REVERT: removing the seen-key guard makes these topics silently
// last-win and print a "Policy match" (or a default verdict) with no diagnostic,
// flipping the assertions red.
func TestShowTestPolicyRejectsDuplicate(t *testing.T) {
	s := &Server{store: matchPoliciesTestStore(t)}
	topics := []string{
		"test-policy:from=trust,from=dmz,to=untrust",
		"test-policy:from=trust,to=untrust,port=80,port=443",
		"test-policy:from=trust,to=untrust,proto=tcp,proto=udp",
	}
	for _, topic := range topics {
		t.Run(topic, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
			if err != nil {
				t.Fatalf("ShowText(%q) err = %v", topic, err)
			}
			if !strings.Contains(resp.Output, "specified more than once") {
				t.Fatalf("output = %q, want a duplicate-selector diagnostic", resp.Output)
			}
			if strings.Contains(resp.Output, "Policy match") {
				t.Fatalf("duplicate selector produced a policy match (silent last-win): %q", resp.Output)
			}
		})
	}
}
