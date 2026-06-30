package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// clearOKGRPCDP is a loaded dataplane whose clear-all succeeds with no faults,
// so the only failure a ClearSessions can report comes from the HA peer leg.
type clearOKGRPCDP struct {
	*dataplane.Manager
}

func (d *clearOKGRPCDP) IsLoaded() bool                      { return true }
func (d *clearOKGRPCDP) ClearAllSessions() (int, int, error) { return 1, 0, nil }

// TestClearSessionsPeerFailureNamesPeerNode asserts the #3423 FOLD 3 contract:
// when the cluster peer clear fails, the ClearSessions FailureSummary names the
// PEER NODE so the operator knows which node still holds uncleared sessions —
// a bare "dial peer" did not. The peer is unreachable (an unroutable TEST-NET
// fabric address), so clearPeerSessions returns the dial error.
//
// peerNodeIDForMsg derives the peer id deterministically (local node 0 ->
// peer node 1) since no heartbeat has set PeerNodeID() in this synthetic
// cluster, so the summary must mention "peer node 1".
//
// FAIL-ON-REVERT: reverting clearPeerSessions to the bare "dial peer: %w"
// drops the node id and the substring assertion goes RED.
func TestClearSessionsPeerFailureNamesPeerNode(t *testing.T) {
	s := &Server{
		store:            newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:               &clearOKGRPCDP{Manager: dataplane.New()},
		cluster:          cluster.NewManager(0, 1),
		fabricPeerAddrFn: func() []string { return []string{"192.0.2.1"} }, // RFC5737 TEST-NET-1, unroutable
	}

	// Empty request -> clear-all path; no x-peer-forwarded -> peer leg runs.
	resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{})
	if err != nil {
		t.Fatalf("ClearSessions unexpected RPC error: %v", err)
	}
	if resp.Failures == 0 {
		t.Fatalf("peer-clear failure not reported: Failures=0, summary=%q", resp.FailureSummary)
	}
	if !strings.Contains(resp.FailureSummary, "peer node 1") {
		t.Fatalf("failure_summary = %q, want it to name the peer node (\"peer node 1\")", resp.FailureSummary)
	}
}
