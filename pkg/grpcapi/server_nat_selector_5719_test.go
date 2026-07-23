package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestGetNATRuleStatsRejectsUnknownSelector is a FAIL-ON-REVERT guard for the
// #5719 (codex-review-182 C-API) unknown-NAT-stats-selector diagnostic gap.
//
// GetNATRuleStats selects a NAT-rule family from req.NatType, honouring only
// "" (default = source), "source", and "destination". Before the fix, any
// other value fell through both branches and returned an EMPTY response with a
// NIL error — a false "no NAT rules" answer indistinguishable from an empty
// firewall. The fix rejects an unknown selector with codes.InvalidArgument.
//
// RED on revert: delete the selector validation in GetNATRuleStats and the
// "bogus" / "src" / "static" cases return (empty, nil) instead of an
// InvalidArgument error, flipping the first sub-test's want-error assertion.
func TestGetNATRuleStatsRejectsUnknownSelector(t *testing.T) {
	s := &Server{store: newNATStatsGRPCStore(t)}

	// Unknown selectors must be rejected as InvalidArgument, not rendered as
	// an empty result set.
	for _, bad := range []string{"src", "static", "bogus", "SOURCE", "dest"} {
		resp, err := s.GetNATRuleStats(context.Background(),
			&pb.GetNATRuleStatsRequest{NatType: bad})
		if err == nil {
			t.Fatalf("NatType=%q: got nil error (empty result masked the typo); want InvalidArgument", bad)
		}
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("NatType=%q: error code = %v, want InvalidArgument; err: %v", bad, status.Code(err), err)
		}
		if resp != nil {
			t.Fatalf("NatType=%q: want nil response on rejected selector, got %+v", bad, resp)
		}
	}

	// The valid selectors must still succeed. "" and "source" select the two
	// configured source-NAT rules; "destination" is valid but empty here.
	for _, good := range []string{"", "source", "destination"} {
		resp, err := s.GetNATRuleStats(context.Background(),
			&pb.GetNATRuleStatsRequest{NatType: good})
		if err != nil {
			t.Fatalf("NatType=%q: unexpected error: %v", good, err)
		}
		if resp == nil {
			t.Fatalf("NatType=%q: nil response on valid selector", good)
		}
	}

	// Sanity: the default/source selector actually returns the two seeded
	// rules, so the accept path is not a vacuous pass.
	resp, err := s.GetNATRuleStats(context.Background(), &pb.GetNATRuleStatsRequest{})
	if err != nil {
		t.Fatalf("default selector error: %v", err)
	}
	if len(resp.Rules) != 2 {
		t.Fatalf("default selector rule count = %d, want 2", len(resp.Rules))
	}
}
