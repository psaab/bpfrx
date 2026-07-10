// #5323: `show security flow session summary` (remote CLI) rendered a
// HARDCODED Maximum-sessions:10000000. #5320: an unreachable cluster peer was
// swallowed, so the local-only counts printed as if complete. These tests pin
// the dynamic-max render and the peer-unreachable warning.
package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// TestPrintSessionSummaryBlockDynamicMax asserts the render uses the response's
// max_sessions, not the retired hardcoded 10000000 (#5323).
//
// FAIL-ON-REVERT: restoring `Maximum-sessions: 10000000` makes the 786432
// assertion go red.
func TestPrintSessionSummaryBlockDynamicMax(t *testing.T) {
	out := captureStdout(t, func() {
		printSessionSummaryBlock(&pb.GetSessionSummaryResponse{ForwardOnly: 5, MaxSessions: 786432})
	})
	if !strings.Contains(out, "Maximum-sessions: 786432") {
		t.Fatalf("output missing dynamic max:\n%s", out)
	}
	if strings.Contains(out, "10000000") {
		t.Fatalf("output still prints the retired hardcoded max:\n%s", out)
	}
}

// TestPrintSessionSummaryBlockUnknownMax asserts a 0 max (no dataplane status)
// renders "unknown" rather than a fabricated authoritative bound (#5323).
func TestPrintSessionSummaryBlockUnknownMax(t *testing.T) {
	out := captureStdout(t, func() {
		printSessionSummaryBlock(&pb.GetSessionSummaryResponse{ForwardOnly: 1})
	})
	if !strings.Contains(out, "Maximum-sessions: unknown") {
		t.Fatalf("output missing unknown fallback:\n%s", out)
	}
}

// summaryFakeClient stubs GetSessionSummary so the remote showSessionSummary
// path can be driven without a live daemon.
type summaryFakeClient struct {
	pb.BpfrxServiceClient
	resp *pb.GetSessionSummaryResponse
}

func (f *summaryFakeClient) GetSessionSummary(
	_ context.Context, _ *pb.GetSessionSummaryRequest, _ ...grpc.CallOption,
) (*pb.GetSessionSummaryResponse, error) {
	return f.resp, nil
}

// TestShowSessionSummaryPeerUnreachableWarning asserts the remote CLI prints a
// LOCAL-ONLY warning when the cluster peer was requested but unreachable
// (#5320), instead of silently showing the local counts as complete.
//
// FAIL-ON-REVERT: dropping the peer_status==UNREACHABLE branch in
// showSessionSummary drops the warning line.
func TestShowSessionSummaryPeerUnreachableWarning(t *testing.T) {
	c := &ctl{client: &summaryFakeClient{resp: &pb.GetSessionSummaryResponse{
		ForwardOnly: 3,
		MaxSessions: 786432,
		PeerStatus:  pb.PeerFetchStatus_PEER_FETCH_STATUS_UNREACHABLE,
		PeerError:   "dial peer node 1: connection refused",
	}}}

	out := captureStdout(t, func() {
		if err := c.showSessionSummary(); err != nil {
			t.Fatalf("showSessionSummary: %v", err)
		}
	})
	if !strings.Contains(out, "cluster peer unreachable") {
		t.Fatalf("output missing peer-unreachable warning:\n%s", out)
	}
	if !strings.Contains(out, "LOCAL-ONLY") {
		t.Fatalf("output missing LOCAL-ONLY qualifier:\n%s", out)
	}
	if !strings.Contains(out, "Maximum-sessions: 786432") {
		t.Fatalf("output missing dynamic max:\n%s", out)
	}
}

// TestShowSessionSummaryNoWarningWhenOK asserts no spurious warning when the
// peer status is not unreachable (standalone / OK).
func TestShowSessionSummaryNoWarningWhenOK(t *testing.T) {
	c := &ctl{client: &summaryFakeClient{resp: &pb.GetSessionSummaryResponse{
		ForwardOnly: 3,
		MaxSessions: 786432,
		PeerStatus:  pb.PeerFetchStatus_PEER_FETCH_STATUS_NOT_APPLICABLE,
	}}}
	out := captureStdout(t, func() {
		if err := c.showSessionSummary(); err != nil {
			t.Fatalf("showSessionSummary: %v", err)
		}
	})
	if strings.Contains(out, "cluster peer unreachable") {
		t.Fatalf("spurious peer-unreachable warning on a standalone summary:\n%s", out)
	}
}
