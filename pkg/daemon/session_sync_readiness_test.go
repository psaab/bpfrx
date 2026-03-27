package daemon

import (
	"testing"
	"time"
)

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestSessionSyncPeerDisconnected_PreservesReadinessAfterBulk(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(true)
	d.syncBulkPrimed.Store(true)

	d.onSessionSyncPeerDisconnected()

	if !d.cluster.IsSyncReady() {
		t.Fatal("completed bulk sync should preserve takeover readiness across disconnects")
	}
}

func TestSessionSyncPeerDisconnected_UnprimedFallsBackToTimeout(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(true)

	d.onSessionSyncPeerDisconnected()

	if d.cluster.IsSyncReady() {
		t.Fatal("unprimed disconnect should clear readiness immediately")
	}
	waitForCondition(t, 200*time.Millisecond, d.cluster.IsSyncReady,
		"sync readiness timeout should release hold for an unprimed standby")
}

func TestSessionSyncPeerConnected_PrimedRestoresReadinessImmediately(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(false)
	d.syncBulkPrimed.Store(true)

	d.onSessionSyncPeerConnected()

	if !d.cluster.IsSyncReady() {
		t.Fatal("primed reconnect should restore readiness immediately")
	}
}

func TestSessionSyncBulkReceived_PrimesReadiness(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(false)
	d.onSessionSyncBulkReceived()

	if !d.syncBulkPrimed.Load() {
		t.Fatal("bulk sync callback should mark standby as primed")
	}
	if !d.cluster.IsSyncReady() {
		t.Fatal("bulk sync callback should release takeover readiness")
	}
}
