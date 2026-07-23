package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// showStatsBuffersFakeClient embeds pb.BpfrxServiceClient (so only the two RPCs
// showStatistics(detail=true) calls are stubbed; any other RPC nil-panics,
// which never happens on this path). GetGlobalStats always succeeds; ShowText
// (the supplemental "buffers" topic) is configurable to fail.
type showStatsBuffersFakeClient struct {
	pb.BpfrxServiceClient
	showTextErr error
}

func (f *showStatsBuffersFakeClient) GetGlobalStats(
	_ context.Context, _ *pb.GetGlobalStatsRequest, _ ...grpc.CallOption,
) (*pb.GetGlobalStatsResponse, error) {
	return &pb.GetGlobalStatsResponse{}, nil
}

func (f *showStatsBuffersFakeClient) ShowText(
	_ context.Context, _ *pb.ShowTextRequest, _ ...grpc.CallOption,
) (*pb.ShowTextResponse, error) {
	if f.showTextErr != nil {
		return nil, f.showTextErr
	}
	return &pb.ShowTextResponse{Output: "Buffer utilization: 5%\n"}, nil
}

// TestShowStatisticsDetailPropagatesBuffersError_5328 is the #5328 (A10-b1-F4)
// RED-on-revert guard: `show security statistics detail` must propagate a
// failed supplemental buffers read, not swallow it and exit 0 with the buffer
// section silently omitted.
//
// FAIL-ON-REVERT: restore `if err == nil && text.Output != ""` + `return nil`
// and the error case returns nil → the "want error" assertion goes RED.
func TestShowStatisticsDetailPropagatesBuffersError_5328(t *testing.T) {
	wantErr := errors.New("buffers RPC degraded")
	c := &ctl{client: &showStatsBuffersFakeClient{showTextErr: wantErr}}

	if err := c.showStatistics(true); err == nil {
		t.Fatal("showStatistics(detail=true) swallowed a buffers read error and returned nil")
	}

	// Sanity: a healthy buffers read still succeeds (the error path is the only
	// behavior change).
	c = &ctl{client: &showStatsBuffersFakeClient{}}
	if err := c.showStatistics(true); err != nil {
		t.Fatalf("showStatistics(detail=true) with a healthy buffers read: %v", err)
	}
}
