package cluster

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestHandleRemoteFailoverFailedFenceDowngradesAck pins the transport half of
// the #6371 fix: the daemon's fence barrier now resolves with a FAILURE verdict
// when the local rg_active clear was rejected, and that verdict must reach the
// peer as failoverAckFailed — never as failoverAckApplied. An applied-ack on a
// fence that did not actuate is exactly the two-owner window #5640 closed.
//
// Fail-on-revert: drop the error branch on `s.WaitFailoverApplied(rgID)` in
// handleRemoteFailover and the applied-ack is sent regardless of the verdict.
func TestHandleRemoteFailoverFailedFenceDowngradesAck(t *testing.T) {
	ss := NewSessionSync(":0", "10.0.0.2:4785", nil)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	ss.mu.Lock()
	ss.conn0 = local
	ss.mu.Unlock()
	ss.stats.Connected.Store(true)

	ss.OnRemoteFailover = func(int, uint64) error { return nil }
	fenceErr := errors.New("redundancy group 7 rg_active=false not applied on demotion")
	ss.WaitFailoverApplied = func(int, uint64) error { return fenceErr }

	frames := make(chan syncFrame, 4)
	readFramesInto(peer, frames)

	go ss.handleRemoteFailover(local, 7, 42)

	select {
	case f := <-frames:
		if f.typ != syncMsgFailoverAck {
			t.Fatalf("frame type = %d, want failover ack %d", f.typ, syncMsgFailoverAck)
		}
		if len(f.payload) < 2 || f.payload[0] != 7 {
			t.Fatalf("ack payload = %v, want rg=7", f.payload)
		}
		if f.payload[1] == failoverAckApplied {
			t.Fatal("ack status = applied after a FAILED fence verdict: the peer would " +
				"promote while this node may still own the RG (#6371)")
		}
		if f.payload[1] != failoverAckFailed {
			t.Fatalf("ack status = %d, want failed %d", f.payload[1], failoverAckFailed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no failover ack delivered for a failed fence verdict")
	}
}
