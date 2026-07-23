package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// confirmPendingProbeClient records whether the GetConfigModeStatus poll passed
// a context carrying a deadline. It embeds the generated client so only
// GetConfigModeStatus is stubbed; any other RPC nil-panics.
type confirmPendingProbeClient struct {
	pb.BpfrxServiceClient
	sawDeadline bool
	confirm     bool
}

func (f *confirmPendingProbeClient) GetConfigModeStatus(
	ctx context.Context, _ *pb.GetConfigModeStatusRequest, _ ...grpc.CallOption,
) (*pb.GetConfigModeStatusResponse, error) {
	_, f.sawDeadline = ctx.Deadline()
	return &pb.GetConfigModeStatusResponse{ConfirmPending: f.confirm}, nil
}

// #5649 (codex-181 C181-C13): the pre-prompt commit-confirm status poll used
// context.Background(), so a daemon that accepted the connection but never
// completed GetConfigModeStatus would wedge the interactive client before
// Readline — there is no active command context for Ctrl-C to cancel here.
// The poll now runs on a BOUNDED context (confirmPendingTimeout).
//
// FAIL-ON-REVERT: restoring context.Background() in confirmPending makes the
// polled context carry no deadline, so sawDeadline is false and this goes RED.
func TestConfirmPendingUsesBoundedContext_5649(t *testing.T) {
	fake := &confirmPendingProbeClient{confirm: true}

	if !confirmPending(fake) {
		t.Fatal("confirmPending should report the pending state the daemon returned")
	}
	if !fake.sawDeadline {
		t.Fatal("GetConfigModeStatus poll must use a bounded context (a deadline); " +
			"context.Background() would let an unresponsive daemon wedge the prompt")
	}

	// A daemon reporting no pending confirm yields false without spuriously
	// printing the advisory line.
	fake.confirm = false
	if confirmPending(fake) {
		t.Fatal("confirmPending should be false when ConfirmPending is false")
	}
}
