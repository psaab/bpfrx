// Tests for #4868 on the remote CLI surface: commit/rollback grammar +
// int->int32 narrowing must fail CLOSED. Before the fix:
//   - an unknown `commit` modifier (e.g. the typo `commit confimed 10`) fell
//     through to the permanent Commit RPC (a management-stranding change with
//     no rollback timer);
//   - `commit confirmed junk|0|-1` silently kept the 10-minute default, and
//     `commit confirmed 4294967297` narrowed through int32 to Minutes=1;
//   - `rollback 4294967296` was a valid int that wrapped through int32 to 0,
//     silently discarding the candidate.

package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// commitRecorderClient records Commit / CommitConfirmed RPCs. GetStatus is
// stubbed so refreshPrompt() on the success path does not nil-panic. Any other
// RPC nil-panics, which is what we want — the commit path must only ever touch
// these.
type commitRecorderClient struct {
	pb.BpfrxServiceClient

	commitCalls  int
	confirmCalls int
	lastMinutes  int32
}

func (f *commitRecorderClient) Commit(
	_ context.Context, _ *pb.CommitRequest, _ ...grpc.CallOption,
) (*pb.CommitResponse, error) {
	f.commitCalls++
	return &pb.CommitResponse{}, nil
}

func (f *commitRecorderClient) CommitConfirmed(
	_ context.Context, in *pb.CommitConfirmedRequest, _ ...grpc.CallOption,
) (*pb.CommitConfirmedResponse, error) {
	f.confirmCalls++
	f.lastMinutes = in.GetMinutes()
	return &pb.CommitConfirmedResponse{}, nil
}

func (f *commitRecorderClient) GetStatus(
	_ context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption,
) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// An unknown modifier must ERROR before any RPC — never fall through to the
// permanent Commit.
func TestRemoteCommitUnknownModifierNoRPC_4868(t *testing.T) {
	for _, line := range []string{"commit confimed 10", "commit bogus", "commit synchronize"} {
		t.Run(line, func(t *testing.T) {
			fake := &commitRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig(line); err == nil {
				t.Fatalf("%q: expected an error for an unknown commit modifier", line)
			}
			if fake.commitCalls != 0 || fake.confirmCalls != 0 {
				t.Fatalf("%q: issued Commit=%d CommitConfirmed=%d; expected 0 — "+
					"an unknown modifier must not permanent-commit", line, fake.commitCalls, fake.confirmCalls)
			}
		})
	}
}

// A malformed / zero / negative / int32-overflowing / over-max timeout must
// ERROR before any RPC — never silently arm a default or a truncated value.
func TestRemoteCommitConfirmedInvalidNoRPC_4868(t *testing.T) {
	for _, line := range []string{
		"commit confirmed junk",
		"commit confirmed 1x",
		"commit confirmed 0",
		"commit confirmed -1",
		"commit confirmed 4294967297", // int32 overflow (old code -> Minutes=1)
		"commit confirmed 99999",      // over the Junos max
		"commit confirmed 5 extra",    // wrong arity
	} {
		t.Run(line, func(t *testing.T) {
			fake := &commitRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig(line); err == nil {
				t.Fatalf("%q: expected an error", line)
			}
			if fake.confirmCalls != 0 {
				t.Fatalf("%q: issued CommitConfirmed %d times (Minutes=%d); expected 0",
					line, fake.confirmCalls, fake.lastMinutes)
			}
		})
	}
}

// Valid confirmed timeouts pass the exact minutes (no narrowing / no default
// swallow).
func TestRemoteCommitConfirmedValidMinutes_4868(t *testing.T) {
	cases := []struct {
		line string
		want int32
	}{
		{"commit confirmed", 10}, // default
		{"commit confirmed 5", 5},
		{"commit confirmed 65535", 65535}, // max boundary
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			fake := &commitRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig(tc.line); err != nil {
				t.Fatalf("%q: %v", tc.line, err)
			}
			if fake.confirmCalls != 1 || fake.lastMinutes != tc.want {
				t.Fatalf("%q: calls=%d Minutes=%d; want 1 / %d",
					tc.line, fake.confirmCalls, fake.lastMinutes, tc.want)
			}
		})
	}
}

// #4868 C: a rollback index that fits int64 but not int32 must be rejected,
// not wrapped to 0 (silent candidate discard). Complements the #3447 malformed
// cases in rollback_3447_test.go.
func TestRemoteRollbackInt32WrapNoRPC_4868(t *testing.T) {
	for _, arg := range []string{"4294967296", "4294967297", "2147483648"} {
		t.Run(arg, func(t *testing.T) {
			fake := &rollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig("rollback " + arg); err == nil {
				t.Fatalf("rollback %q returned nil; expected out-of-range rejection", arg)
			}
			if fake.calls != 0 {
				t.Fatalf("rollback %q issued the RPC %d times (last N=%d); expected 0 — "+
					"int32 wrap to 0 discards the candidate", arg, fake.calls, fake.lastN)
			}
		})
	}
}
