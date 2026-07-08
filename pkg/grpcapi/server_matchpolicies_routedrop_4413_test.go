package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/policymatch"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestMatchPoliciesSurfacesBroadcastRouteDrop is the #4413 (ps-review-007
// dropped finding) coverage for the gRPC surface: a broadcast (or other
// route-drop-before-policy class) DESTINATION must carry the #4373 route-drop
// advisory on the MatchPolicies response, so a gRPC / remote-CLI client is not
// told a permit/deny verdict describes real forwarding for a destination the
// transit path drops at route lookup BEFORE the policy engine. The advisory
// rides EVERY verdict path — a positive match AND the default-policy
// fall-through.
//
// This locks the gRPC handler's plumbing of RouteDropBeforePolicy /
// RouteDropClass / RouteDropNote (server_cluster.go MatchPolicies), which the
// #4373 policymatch-layer tests (pkg/policymatch/route_drop_4373_test.go) do
// not exercise — those assert the simulator Result, not the transport response.
//
// RED-on-revert: dropping the RouteDropBeforePolicy/RouteDropClass/RouteDropNote
// assignment from the matched OR the no-match/default return path in
// server_cluster.go zeroes the corresponding response field and the matching
// subtest below fails.
func TestMatchPoliciesSurfacesBroadcastRouteDrop(t *testing.T) {
	// hostInboundStore: trust->untrust permit, default deny, defined zones.
	store := hostInboundStore(t)
	s := &Server{store: store}

	const bcast = "255.255.255.255"

	// Positive match: trust->untrust permit-any matches even for a broadcast
	// destination, but the packet never forwards — the advisory must ride the
	// matched verdict.
	t.Run("matched-permit", func(t *testing.T) {
		resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
			FromZone:      "trust",
			ToZone:        "untrust",
			DestinationIp: bcast,
		})
		if err != nil {
			t.Fatalf("MatchPolicies(match) error = %v", err)
		}
		if !resp.Matched {
			t.Fatalf("Matched = false, want true (trust->untrust permit-any)")
		}
		assertBroadcastAdvisory(t, resp)
	})

	// No-match / default: untrust->trust has no rule -> default deny. The
	// broadcast advisory must ride the default verdict too.
	t.Run("default-deny", func(t *testing.T) {
		resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
			FromZone:      "untrust",
			ToZone:        "trust",
			DestinationIp: bcast,
		})
		if err != nil {
			t.Fatalf("MatchPolicies(default) error = %v", err)
		}
		if resp.Matched {
			t.Fatalf("Matched = true, want false (default deny)")
		}
		if !resp.DefaultUsed {
			t.Fatalf("DefaultUsed = false, want true (default deny path)")
		}
		assertBroadcastAdvisory(t, resp)
	})

	// Control: an ordinary unicast destination reaches the policy engine and
	// must NOT carry the advisory on either verdict path — so the plumbing is
	// destination-classified, not stamped unconditionally.
	t.Run("unicast-no-advisory", func(t *testing.T) {
		resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
			FromZone:      "trust",
			ToZone:        "untrust",
			DestinationIp: "10.0.2.7",
		})
		if err != nil {
			t.Fatalf("MatchPolicies(unicast) error = %v", err)
		}
		if resp.RouteDropBeforePolicy || resp.RouteDropClass != "" || resp.RouteDropNote != "" {
			t.Fatalf("unicast dst wrongly carries route-drop advisory: %+v", resp)
		}
	})
}

func assertBroadcastAdvisory(t *testing.T, resp *pb.MatchPoliciesResponse) {
	t.Helper()
	if !resp.RouteDropBeforePolicy {
		t.Fatalf("RouteDropBeforePolicy = false, want true for a broadcast destination")
	}
	if resp.RouteDropClass != "broadcast" {
		t.Fatalf("RouteDropClass = %q, want %q", resp.RouteDropClass, "broadcast")
	}
	if !strings.HasPrefix(resp.RouteDropNote, policymatch.RouteDropNotePrefix) {
		t.Fatalf("RouteDropNote %q missing SSOT prefix %q", resp.RouteDropNote, policymatch.RouteDropNotePrefix)
	}
	if !strings.Contains(resp.RouteDropNote, "broadcast") {
		t.Fatalf("RouteDropNote %q does not name class broadcast", resp.RouteDropNote)
	}
	if !strings.Contains(resp.RouteDropNote, "route lookup") {
		t.Fatalf("RouteDropNote %q must state the packet is dropped at route lookup", resp.RouteDropNote)
	}
}
