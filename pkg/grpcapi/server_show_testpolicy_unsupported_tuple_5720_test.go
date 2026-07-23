package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestShowTestPolicyUnsupportedTupleFamily5720 pins the #5720 gRPC-text render
// (the remote CLI `test policy` / `show security match-policies` backend): an
// IPv4 source with an IPv6 destination is an impossible tuple (NAT46 is
// unimplemented), so the forwarding path never produces it and the runtime
// matcher fails closed. The ShowText handler must surface the dedicated
// UnsupportedTupleFamily verdict, NOT a fabricated "Default deny (no matching
// policy)" — the latter would send an operator to add a permit policy that can
// never take effect. This binds the render-side of the #5720 policymatch gate;
// the Match-side fail-closed verdict is bound by
// policymatch.TestMatchRejectsV4SrcV6DstTuple.
//
// FAIL-ON-REVERT: dropping the `case res.UnsupportedTupleFamily` arm in
// server_show_firewall.go makes the impossible tuple fall through to the
// default "no matching policy" branch — the want-DisplayAction assertion (and
// the must-NOT-contain "no matching policy" assertion) then fail.
func TestShowTestPolicyUnsupportedTupleFamily5720(t *testing.T) {
	// A same-family V4 tuple sanity-permits through the fixture; the mixed tuple
	// below is what must divert to the dedicated verdict.
	s := fragTextPolicyStore(t)

	topic := "test-policy:from=trust,to=untrust,src=10.1.2.3,dst=2001:db8::1,proto=tcp"
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: topic})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	// The dedicated verdict names the impossible NAT46 tuple.
	if !strings.Contains(resp.Output, "NAT46 is not implemented") {
		t.Fatalf("V4src/V6dst tuple must render the UnsupportedTupleFamily verdict; output: %q", resp.Output)
	}
	// And must NOT fabricate a "(no matching policy)" default-deny verdict.
	if strings.Contains(resp.Output, "no matching policy") {
		t.Fatalf("impossible tuple must NOT report a fabricated (no matching policy) verdict; output: %q", resp.Output)
	}
}
