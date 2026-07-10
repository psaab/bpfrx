// #4883-C: `request chassis cluster failover redundancy-group <N> node` with
// no node value used to silently drop the bare `node` and send an untargeted
// `cluster-failover:<N>` (ManualFailover) — a truncated automation token
// triggered a REAL redundancy-group failover. The CLI must reject the
// malformed command BEFORE issuing the SystemAction RPC.

package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// failoverRecorder records SystemAction calls so a test can assert an
// untargeted failover was NOT issued.
type failoverRecorder struct {
	pb.BpfrxServiceClient

	calls   int
	actions []string
}

func (f *failoverRecorder) SystemAction(
	_ context.Context, in *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	f.calls++
	f.actions = append(f.actions, in.GetAction())
	return &pb.SystemActionResponse{Message: "ok"}, nil
}

// A bare `node` (no value) must ERROR before any RPC — never fall through to
// an untargeted cluster-failover.
//
// Goes RED on revert: the old `len(args) >= 4` gate skips the bare `node` and
// sends `cluster-failover:1`, so calls would be 1 and err nil.
func TestRequestFailoverNodeRequiresValue_4883(t *testing.T) {
	fake := &failoverRecorder{}
	c := &ctl{client: fake}

	err := c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1", "node"})
	if err == nil {
		t.Fatal("handleRequestChassisClusterFailover(... node) returned nil; expected a usage error")
	}
	if fake.calls != 0 {
		t.Fatalf("SystemAction issued %d times (%v); expected 0 — a missing node value "+
			"must not trigger an untargeted RG failover", fake.calls, fake.actions)
	}
}

// The well-formed variants still send the correct action (no regression): a
// node-scoped failover and a plain RG failover.
func TestRequestFailoverWellFormedStillSends_4883(t *testing.T) {
	cases := []struct {
		args   []string
		action string
	}{
		{[]string{"redundancy-group", "1", "node", "0"}, "cluster-failover:1:node0"},
		{[]string{"redundancy-group", "1"}, "cluster-failover:1"},
	}
	for _, tc := range cases {
		fake := &failoverRecorder{}
		c := &ctl{client: fake}
		if err := c.handleRequestChassisClusterFailover(tc.args); err != nil {
			t.Fatalf("handleRequestChassisClusterFailover(%v) unexpected error: %v", tc.args, err)
		}
		if fake.calls != 1 || fake.actions[0] != tc.action {
			t.Fatalf("handleRequestChassisClusterFailover(%v): calls=%d actions=%v; want 1 / [%s]",
				tc.args, fake.calls, fake.actions, tc.action)
		}
	}
}
