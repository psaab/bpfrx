package daemon

import (
	"testing"
	"time"

	"github.com/psaab/bpfrx/pkg/cluster"
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

func TestSessionSyncPeerDisconnected_ClearsReadinessAndFallsBackToTimeout(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(true)
	d.syncBulkPrimed.Store(true)

	d.onSessionSyncPeerDisconnected()

	if d.cluster.IsSyncReady() {
		t.Fatal("disconnect should clear readiness for the current sync generation")
	}
	if d.syncBulkPrimed.Load() {
		t.Fatal("disconnect should clear bulk priming state")
	}
	waitForCondition(t, 200*time.Millisecond, d.cluster.IsSyncReady,
		"sync readiness timeout should release hold after disconnect")
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

func TestSessionSyncPeerConnected_ClearsReadinessThenFallsBackToTimeout(t *testing.T) {
	d := &Daemon{
		cluster:          newClusterManager(false),
		syncReadyTimeout: 20 * time.Millisecond,
	}
	t.Cleanup(d.stopSyncReadyTimer)

	d.cluster.SetSyncReady(true)
	d.syncBulkPrimed.Store(true)

	d.onSessionSyncPeerConnected()

	if d.cluster.IsSyncReady() {
		t.Fatal("reconnect should hold readiness until the new bulk sync completes")
	}
	if d.syncBulkPrimed.Load() {
		t.Fatal("reconnect should clear the previous bulk-primed state")
	}
	waitForCondition(t, 200*time.Millisecond, d.cluster.IsSyncReady,
		"sync readiness timeout should release hold while reconnect bulk is pending")
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

func TestSyncPrimeProgressObservedDetectsInboundProgress(t *testing.T) {
	baseline := cluster.SyncStatsSnapshot{
		SessionsReceived:  10,
		SessionsInstalled: 9,
		DeletesReceived:   3,
	}
	current := baseline
	current.SessionsReceived++
	if !syncPrimeProgressObserved(current, baseline) {
		t.Fatal("expected inbound sync progress to be detected")
	}
}

func TestSyncPrimeProgressObservedFalseWithoutProgress(t *testing.T) {
	baseline := cluster.SyncStatsSnapshot{
		SessionsReceived:  10,
		SessionsInstalled: 9,
		DeletesReceived:   3,
	}
	if syncPrimeProgressObserved(baseline, baseline) {
		t.Fatal("expected no progress when counters are unchanged")
	}
}

func TestSessionSyncBulkAckReceivedMarksPeerPrimed(t *testing.T) {
	d := &Daemon{}
	d.syncPeerBulkPrimed.Store(false)
	d.onSessionSyncBulkAckReceived()
	if !d.syncPeerBulkPrimed.Load() {
		t.Fatal("bulk ack callback should mark peer primed")
	}
}
