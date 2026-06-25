// #2468: the gRPC ClearSessions RPC must report sub-operation failures
// (iterator, reverse/companion deletes) via the response Failures /
// FailureSummary fields instead of returning a bare success. These
// tests inject failures through a grpcRuntime that embeds
// *dataplane.Manager and overrides the session methods. They are
// fail-on-revert: the old `_ =`/fire-and-forget discards leave Failures
// at 0 and the assertions go RED.
package grpcapi

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type clearFaultGRPCDP struct {
	*dataplane.Manager

	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue

	iterErr    error
	iterV6Err  error
	delErr     error
	delDNATErr error
}

func (d *clearFaultGRPCDP) IsLoaded() bool { return true }

func (d *clearFaultGRPCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for k, v := range d.v4Sessions {
		if !fn(k, v) {
			break
		}
	}
	return d.iterErr
}

func (d *clearFaultGRPCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return d.iterV6Err
}

func (d *clearFaultGRPCDP) DeleteSession(dataplane.SessionKey) error     { return d.delErr }
func (d *clearFaultGRPCDP) DeleteSessionV6(dataplane.SessionKeyV6) error { return nil }
func (d *clearFaultGRPCDP) DeleteDNATEntry(dataplane.DNATKey) error      { return d.delDNATErr }
func (d *clearFaultGRPCDP) DeleteDNATEntryV6(dataplane.DNATKeyV6) error  { return nil }

func seedGRPCV4(snat bool) map[dataplane.SessionKey]dataplane.SessionValue {
	key := dataplane.SessionKey{Protocol: 6}
	val := dataplane.SessionValue{}
	if snat {
		val.Flags = dataplane.SessFlagSNAT
	}
	return map[dataplane.SessionKey]dataplane.SessionValue{key: val}
}

func newClearServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
		// cluster nil -> standalone, peer-clear is a clean no-op.
	}
}

// protocol-only request -> filtered clear path.
func protoReq() *pb.ClearSessionsRequest {
	return &pb.ClearSessionsRequest{Protocol: "tcp"}
}

func TestClearSessionsRPCReportsIteratorFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		iterErr:    fmt.Errorf("map dump truncated"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("iterator failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
}

func TestClearSessionsRPCReportsDeleteFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		delErr:     fmt.Errorf("kernel map delete EBUSY"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("delete failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
	// forward delete failed -> not counted as cleared.
	if resp.Ipv4Cleared != 0 {
		t.Fatalf("Ipv4Cleared=%d, want 0 when forward delete fails", resp.Ipv4Cleared)
	}
}

func TestClearSessionsRPCReportsDNATCompanionFailure(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(true), // SNAT -> DNAT companion delete attempted
		delDNATErr: fmt.Errorf("dnat map delete failed"),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("DNAT companion failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
}

// Happy path: all sub-operations succeed -> Failures==0, cleared count
// accurate, no spurious failure summary.
func TestClearSessionsRPCHappyPathNoFailures(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(true),
	}
	s := newClearServer(t, dp)
	resp, err := s.ClearSessions(context.Background(), protoReq())
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures != 0 {
		t.Fatalf("happy path reported Failures=%d summary=%q, want 0", resp.Failures, resp.FailureSummary)
	}
	if resp.Ipv4Cleared != 1 {
		t.Fatalf("Ipv4Cleared=%d, want 1", resp.Ipv4Cleared)
	}
}
