package cluster

import (
	"context"
	"net"
	"testing"
	"time"
)

// #5078 Blocker 2, second half: a legacy peer's first frame — consumed by the
// handshake read and carried out as a pendingFrame — used to be executed
// BEFORE the connection was admitted.
//
// That call site sat above installConn, so a frame could mutate cluster state
// on a connection that was never installed. `syncMsgFence` on that path reaches
// OnFenceReceived, which disables every routing group, so a peer that had not
// proven the PSK could fence the node with a single frame on first contact.
// Combined with the first-contact dual-accept grace (now removed — see
// TestSyncAuthHandshakeKeyedNodeRejectsLegacyPeer) that was a complete
// PSK-less HA denial of service, needing no reflection weakness at all.
//
// The frame is still processed — dropping it would lose a message and break
// stream order — but only AFTER installConn, under the same admission the
// receive loop runs with.
//
// RED on revert: move the `if pending != nil { s.handleMessage(...) }` block
// back above installConn and the callback observes no installed connection.
func TestPendingFrameExecutesOnlyAfterInstall_5078(t *testing.T) {
	// Migration window open so the legacy peer is admitted at all and a pending
	// frame is actually produced; the fail-closed default rejects it outright,
	// which is the other half of the fix and is pinned separately.
	s := newAuthSyncMigration(t, []byte("psk"), false, true)

	type observation struct {
		fired     bool
		installed bool
	}
	obs := make(chan observation, 1)
	s.OnFenceReceived = func() {
		s.mu.Lock()
		installed := s.conn0 != nil || s.conn1 != nil
		s.mu.Unlock()
		obs <- observation{fired: true, installed: installed}
	}

	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// beginSetup is normally performed by the accept/connect loop; handle the
	// connection directly here (finishSetup tolerates an untracked conn).
	go s.handleNewConnection(ctx, 0, ca)

	// Legacy peer: drain the local HELLO, then send a FENCE as its first frame.
	if _, _, err := readSyncFrameRaw(cb); err != nil {
		t.Fatalf("legacy peer failed to read HELLO: %v", err)
	}
	if err := writeMsg(cb, syncMsgFence, nil); err != nil {
		t.Fatalf("legacy peer failed to send fence: %v", err)
	}

	select {
	case o := <-obs:
		if !o.fired {
			t.Fatal("fence callback did not fire")
		}
		if !o.installed {
			t.Fatal("the pending frame executed BEFORE the connection was installed (#5078): " +
				"a peer that was never admitted could fence the node")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fence callback never fired; the pending frame was not processed at all")
	}
}
