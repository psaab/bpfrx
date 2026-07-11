// #5570: `clear security policies hit-count` recognizes only the first two
// tokens and issues an UNSCOPED GLOBAL clear (`clear-policy-counters`). Before
// the fix any trailing selector — e.g. `... from-zone trust` — was silently
// dropped and the command still wiped EVERY policy hit counter while returning
// success. That is a destructive-command fail-closed violation: the operator
// asked to scope the clear, the command cannot honor a scope, so it must ERROR
// rather than silently clear everything. Only the exact two-token form (no
// trailing selector) is the intentional global clear.

package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// clearPolicyCounterRecorder records SystemAction calls so a test can assert a
// global clear-policy-counters was NOT issued for a scoped-looking request.
type clearPolicyCounterRecorder struct {
	pb.BpfrxServiceClient

	calls      int
	lastAction string
}

func (f *clearPolicyCounterRecorder) SystemAction(
	_ context.Context, in *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.calls++
	f.lastAction = in.GetAction()
	return &pb.SystemActionResponse{Message: "ok"}, nil
}

// Trailing selectors must ERROR before any RPC — never fall through to the
// unscoped global clear.
//
// Goes RED on revert: the old `len(args) >= 2` gate ignores trailing tokens and
// issues clear-policy-counters, so calls would be 1 and err nil.
func TestClearPoliciesHitCountTrailingSelectorNoRPC_5570(t *testing.T) {
	for _, args := range [][]string{
		{"policies", "hit-count", "from-zone", "trust"},  // scoped-looking selector
		{"policies", "hit-count", "to-zone", "untrust"},  // scoped-looking selector
		{"policies", "hit-count", "policy", "allow-web"}, // per-policy selector
		{"policies", "hit-count", "extra"},               // stray extra token
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			fake := &clearPolicyCounterRecorder{}
			c := &ctl{client: fake}
			if err := c.handleClearSecurity(args); err == nil {
				t.Fatalf("handleClearSecurity(%v) = nil; want a usage/selector error", args)
			}
			if fake.calls != 0 {
				t.Fatalf("SystemAction issued %d times (action=%q); expected 0 — a "+
					"scoped-looking clear must not wipe ALL policy hit counters", fake.calls, fake.lastAction)
			}
		})
	}
}

// The exact two-token form is the intentional global clear and still sends.
func TestClearPoliciesHitCountExactStillClears_5570(t *testing.T) {
	fake := &clearPolicyCounterRecorder{}
	c := &ctl{client: fake}
	if err := c.handleClearSecurity([]string{"policies", "hit-count"}); err != nil {
		t.Fatalf("handleClearSecurity([policies hit-count]) unexpected error: %v", err)
	}
	if fake.calls != 1 || fake.lastAction != "clear-policy-counters" {
		t.Fatalf("handleClearSecurity([policies hit-count]): calls=%d action=%q; want 1 / clear-policy-counters",
			fake.calls, fake.lastAction)
	}
}
