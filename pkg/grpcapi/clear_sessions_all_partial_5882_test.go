// #5882: the chunked clear-ALL path (ClearAllSessions -> clearSessionsChunkedV4
// then …V6) is NON-atomic — a V6-phase failure can leave IPv4 already fully
// deleted, and ClearAllSessions returns the PARTIAL v4/v6 counts alongside the
// error. The gRPC ClearSessions clear-all branch must surface those partial
// counts via the response Ipv4Cleared/Ipv6Cleared + Failures/FailureSummary
// (the same partial-success contract the FILTERED path already honors, #2468)
// instead of discarding them behind a bare RPC error.
//
// FAIL-ON-REVERT: restoring the old `return nil, status.Errorf(...)` makes the
// partial-failure test get a nil response + bare error (counts lost), flipping
// its "want a response, not a bare error" and count/Failures assertions RED.
package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// clearAllPartialDP is a minimal grpcRuntime fake for the clear-ALL branch: it
// embeds *dataplane.Manager to satisfy the rest of the interface and overrides
// only IsLoaded + ClearAllSessions so a test can inject the partial counts +
// error a mid-operation chunked clear returns.
type clearAllPartialDP struct {
	*dataplane.Manager
	v4  int
	v6  int
	err error
}

func (d *clearAllPartialDP) IsLoaded() bool { return true }

func (d *clearAllPartialDP) ClearAllSessions() (int, int, error) {
	return d.v4, d.v6, d.err
}

// allReq is a parameterless request -> the clear-ALL branch of ClearSessions.
func allReq() *pb.ClearSessionsRequest { return &pb.ClearSessionsRequest{} }

// A clear-all that deleted IPv4 then failed clearing IPv6 must return a
// RESPONSE carrying the partial counts + a Failures>0 marker, not a bare error.
func TestClearSessionsRPCClearAllPartialCountsSurvive(t *testing.T) {
	dp := &clearAllPartialDP{
		Manager: dataplane.New(),
		v4:      7, // IPv4 table fully cleared before the IPv6 phase failed
		v6:      0,
		err:     fmt.Errorf("ipv6 chunk delete EIO"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), allReq())
	// #5882: partial clear-all is reported via the response, never a bare error.
	if err != nil {
		t.Fatalf("ClearSessions returned a bare error, want a response: %v", err)
	}
	if resp == nil {
		t.Fatalf("nil response on partial clear-all")
	}
	if resp.Ipv4Cleared != 7 {
		t.Fatalf("Ipv4Cleared=%d, want 7 (V4 fully deleted before V6 failed)", resp.Ipv4Cleared)
	}
	if resp.Ipv6Cleared != 0 {
		t.Fatalf("Ipv6Cleared=%d, want 0", resp.Ipv6Cleared)
	}
	if resp.Failures == 0 {
		t.Fatalf("clear-all failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
	if resp.FailureSummary == "" {
		t.Fatalf("empty FailureSummary on a partial clear-all failure")
	}
}

// The err==nil clear-all path is unchanged: Failures==0 and the exact counts.
func TestClearSessionsRPCClearAllSuccessNoFailures(t *testing.T) {
	dp := &clearAllPartialDP{
		Manager: dataplane.New(),
		v4:      5,
		v6:      3,
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), allReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures != 0 {
		t.Fatalf("success clear-all reported Failures=%d summary=%q, want 0", resp.Failures, resp.FailureSummary)
	}
	if resp.Ipv4Cleared != 5 || resp.Ipv6Cleared != 3 {
		t.Fatalf("counts v4=%d v6=%d, want 5/3", resp.Ipv4Cleared, resp.Ipv6Cleared)
	}
}
