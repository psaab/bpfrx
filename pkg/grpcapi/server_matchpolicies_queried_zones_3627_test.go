package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestMatchPoliciesEchoesQueriedZones pins #3627 M06 on the gRPC surface: the
// MatchPolicies response must echo the QUERIED from-zone/to-zone on EVERY
// answer — positive match, no-match/default, and host-inbound — so a stored
// diagnostic proves which zone pair was tested without a copy of the request.
//
// This is distinct from the #3331 from_zone/to_zone (the matched policy's
// SCOPE, set only on a positive match). queried_from_zone/queried_to_zone are
// the query context.
//
// RED-on-revert: dropping the QueriedFromZone/QueriedToZone assignment from any
// of the three unmatched/matched return paths in server_cluster.go zeroes the
// echoed field and the corresponding assertion below fails.
func TestMatchPoliciesEchoesQueriedZones(t *testing.T) {
	// hostInboundStore: trust->untrust permit, default deny, defined zones
	// trust/untrust — enough to exercise host-inbound + no-match + match.
	store := hostInboundStore(t)
	s := &Server{store: store}

	// No-match / default: untrust->trust has no rule -> default deny. The
	// matched-scope from_zone/to_zone are empty here, but the queried pair must
	// still be echoed.
	dd, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "untrust", ToZone: "trust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(default) error = %v", err)
	}
	if dd.Matched {
		t.Fatalf("matched = true, want false (default deny)")
	}
	if dd.QueriedFromZone != "untrust" || dd.QueriedToZone != "trust" {
		t.Errorf("default path queried zones = %q->%q, want untrust->trust",
			dd.QueriedFromZone, dd.QueriedToZone)
	}

	// Host-inbound: to-zone junos-host with no host policy -> local delivery.
	hi, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "junos-host",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(host-inbound) error = %v", err)
	}
	if !hi.HostInboundUnmatched {
		t.Fatalf("host_inbound_unmatched = false, want true; got %+v", hi)
	}
	if hi.QueriedFromZone != "trust" || hi.QueriedToZone != "junos-host" {
		t.Errorf("host-inbound path queried zones = %q->%q, want trust->junos-host",
			hi.QueriedFromZone, hi.QueriedToZone)
	}

	// Positive match: trust->untrust permit. The matched-scope from_zone/to_zone
	// (#3331) AND the queried echo must both be populated and here coincide.
	m, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies(match) error = %v", err)
	}
	if !m.Matched {
		t.Fatalf("matched = false, want true (trust->untrust permit)")
	}
	if m.QueriedFromZone != "trust" || m.QueriedToZone != "untrust" {
		t.Errorf("matched path queried zones = %q->%q, want trust->untrust",
			m.QueriedFromZone, m.QueriedToZone)
	}
}
