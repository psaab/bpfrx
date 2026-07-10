// Tests for #5052 on the remote CLI surface: the read-only rollback DISPLAY
// selectors (`show system rollback [compare] N` and `show | compare rollback
// N`) must NOT truncate an out-of-range index through int32 and silently
// render the WRONG rollback slot with a success exit.
//
// Before the fix these three paths parsed with strconv.Atoi and cast int32(n).
// On this 64-bit target strconv.Atoi("4294967297") succeeds, passes the n >= 1
// check, then int32(4294967297) == 1 — so the RPC carried slot 1 while the
// operator asked for a different (invalid) selector. The shared selector parser
// (parseRollbackSelector, ParseInt with a 32-bit width) rejects the value with
// strconv.ErrRange before any RPC is issued.
//
// RED-on-revert: reverting parseRollbackSelector back to Atoi + int32() makes
// each overflow case return a nil error AND issue the display RPC with the
// truncated selector (RollbackN/N == 1), failing both the error assertion and
// the zero-call assertion below.

package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// showRollbackRecorderClient records the read-only rollback display RPCs
// (ShowRollback, ShowCompare) and the selector each carried. GetStatus is
// stubbed so any success-path prompt refresh does not nil-panic; every other
// RPC nil-panics, which is what we want — these display paths must only ever
// touch ShowRollback / ShowCompare.
type showRollbackRecorderClient struct {
	pb.BpfrxServiceClient

	rollbackCalls int
	rollbackN     int32
	compareCalls  int
	compareN      int32
}

func (f *showRollbackRecorderClient) ShowRollback(
	_ context.Context, in *pb.ShowRollbackRequest, _ ...grpc.CallOption,
) (*pb.ShowRollbackResponse, error) {
	f.rollbackCalls++
	f.rollbackN = in.GetN()
	return &pb.ShowRollbackResponse{Output: "stub"}, nil
}

func (f *showRollbackRecorderClient) ShowCompare(
	_ context.Context, in *pb.ShowCompareRequest, _ ...grpc.CallOption,
) (*pb.ShowCompareResponse, error) {
	f.compareCalls++
	f.compareN = in.GetRollbackN()
	return &pb.ShowCompareResponse{Output: "stub"}, nil
}

func (f *showRollbackRecorderClient) GetStatus(
	_ context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption,
) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// An int32-overflowing (or otherwise invalid) display selector must ERROR
// before any RPC — never truncate to a valid-looking slot and render it.
func TestShowRollbackDisplaySelectorOverflowNoRPC_5052(t *testing.T) {
	// 4294967297 == 2^32+1 -> int32 wraps to 1; 4294967296 == 2^32 -> 0;
	// 2147483648 == MaxInt32+1 -> ErrRange; plus a malformed and a
	// non-positive token that must also be rejected.
	overflow := []string{"4294967297", "4294967296", "2147483648", "foo", "0"}

	for _, arg := range overflow {
		arg := arg
		t.Run("show system rollback/"+arg, func(t *testing.T) {
			fake := &showRollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchOperational("show system rollback " + arg); err == nil {
				t.Fatalf("show system rollback %q returned nil; expected rejection", arg)
			}
			if fake.rollbackCalls != 0 {
				t.Fatalf("show system rollback %q issued ShowRollback %d times (N=%d); expected 0",
					arg, fake.rollbackCalls, fake.rollbackN)
			}
		})
		t.Run("show system rollback compare/"+arg, func(t *testing.T) {
			fake := &showRollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchOperational("show system rollback compare " + arg); err == nil {
				t.Fatalf("show system rollback compare %q returned nil; expected rejection", arg)
			}
			if fake.compareCalls != 0 {
				t.Fatalf("show system rollback compare %q issued ShowCompare %d times (RollbackN=%d); expected 0",
					arg, fake.compareCalls, fake.compareN)
			}
		})
		t.Run("show | compare rollback/"+arg, func(t *testing.T) {
			fake := &showRollbackRecorderClient{}
			c := &ctl{client: fake, configMode: true}
			if err := c.dispatchConfig("show | compare rollback " + arg); err == nil {
				t.Fatalf("show | compare rollback %q returned nil; expected rejection", arg)
			}
			if fake.compareCalls != 0 {
				t.Fatalf("show | compare rollback %q issued ShowCompare %d times (RollbackN=%d); expected 0",
					arg, fake.compareCalls, fake.compareN)
			}
		})
	}
}

// A valid in-range selector (including the MaxInt32 boundary) must pass through
// UNCHANGED — proving the fix only rejects the truncating tail, not legitimate
// large slots.
func TestShowRollbackDisplaySelectorValidPassthrough_5052(t *testing.T) {
	const maxInt32 = int32(2147483647)

	t.Run("show system rollback 2", func(t *testing.T) {
		fake := &showRollbackRecorderClient{}
		c := &ctl{client: fake, configMode: true}
		if err := c.dispatchOperational("show system rollback 2"); err != nil {
			t.Fatal(err)
		}
		if fake.rollbackCalls != 1 || fake.rollbackN != 2 {
			t.Fatalf("ShowRollback calls=%d N=%d; want 1 / 2", fake.rollbackCalls, fake.rollbackN)
		}
	})

	t.Run("show system rollback MaxInt32", func(t *testing.T) {
		fake := &showRollbackRecorderClient{}
		c := &ctl{client: fake, configMode: true}
		if err := c.dispatchOperational("show system rollback 2147483647"); err != nil {
			t.Fatal(err)
		}
		if fake.rollbackCalls != 1 || fake.rollbackN != maxInt32 {
			t.Fatalf("ShowRollback calls=%d N=%d; want 1 / %d", fake.rollbackCalls, fake.rollbackN, maxInt32)
		}
	})

	t.Run("show system rollback compare 3", func(t *testing.T) {
		fake := &showRollbackRecorderClient{}
		c := &ctl{client: fake, configMode: true}
		if err := c.dispatchOperational("show system rollback compare 3"); err != nil {
			t.Fatal(err)
		}
		if fake.compareCalls != 1 || fake.compareN != 3 {
			t.Fatalf("ShowCompare calls=%d RollbackN=%d; want 1 / 3", fake.compareCalls, fake.compareN)
		}
	})

	t.Run("show | compare rollback MaxInt32", func(t *testing.T) {
		fake := &showRollbackRecorderClient{}
		c := &ctl{client: fake, configMode: true}
		if err := c.dispatchConfig("show | compare rollback 2147483647"); err != nil {
			t.Fatal(err)
		}
		if fake.compareCalls != 1 || fake.compareN != maxInt32 {
			t.Fatalf("ShowCompare calls=%d RollbackN=%d; want 1 / %d", fake.compareCalls, fake.compareN, maxInt32)
		}
	})
}
