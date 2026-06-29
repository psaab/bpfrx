// Tests for #3447 on the remote CLI surface: a malformed `rollback <arg>`
// must NOT silently fall through to the Rollback RPC with N=0 (which discards
// the candidate). Before the fix, shared.go parsed the argument with
// strconv.Atoi and ignored the error, leaving n=0 — so `rollback foo` issued
// Rollback{N:0}. The strict parse now rejects malformed and negative tokens
// with a clear error before any RPC is issued.

package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// rollbackRecorderClient embeds the generated client and records Rollback
// RPCs. Any RPC the test does not stub will nil-panic — which is what we want,
// since the rollback dispatch path must only ever touch Rollback.
type rollbackRecorderClient struct {
	pb.BpfrxServiceClient

	calls int
	lastN int32
}

func (f *rollbackRecorderClient) Rollback(
	_ context.Context, in *pb.RollbackRequest, _ ...grpc.CallOption,
) (*pb.RollbackResponse, error) {
	f.calls++
	f.lastN = in.GetN()
	return &pb.RollbackResponse{}, nil
}

// TestRemoteRollbackMalformedNoRPC verifies that a malformed argument returns
// a hard error and crucially does NOT issue the Rollback RPC. Reverting the
// strict parse makes these cases issue Rollback{N:0} (silent candidate
// discard) — failing the call-count assertion.
func TestRemoteRollbackMalformedNoRPC(t *testing.T) {
	for _, arg := range []string{"foo", "1x", "-1", "abc", "99999999999999999999"} {
		t.Run(arg, func(t *testing.T) {
			fake := &rollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			err := c.dispatchConfig("rollback " + arg)
			if err == nil {
				t.Fatalf("rollback %q returned nil error; expected rejection", arg)
			}
			if fake.calls != 0 {
				t.Fatalf("rollback %q issued the Rollback RPC %d times (last N=%d); "+
					"expected 0 — must not silently fall through to rollback 0",
					arg, fake.calls, fake.lastN)
			}
		})
	}
}

// TestRemoteRollbackValidIssuesRPC pins the preserved behaviors: the bare
// `rollback` alias and `rollback 0` both issue N=0 (discard candidate), and a
// valid index is passed through to the server (which range-checks it).
func TestRemoteRollbackValidIssuesRPC(t *testing.T) {
	cases := []struct {
		line  string
		wantN int32
	}{
		{"rollback", 0},
		{"rollback 0", 0},
		{"rollback 2", 2},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			fake := &rollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig(tc.line); err != nil {
				t.Fatalf("%q: %v", tc.line, err)
			}
			if fake.calls != 1 {
				t.Fatalf("%q: Rollback issued %d times; want 1", tc.line, fake.calls)
			}
			if fake.lastN != tc.wantN {
				t.Fatalf("%q: Rollback N=%d; want %d", tc.line, fake.lastN, tc.wantN)
			}
		})
	}
}
