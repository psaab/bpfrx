// #3868: HA config divergence on a commit-confirmed TIMEOUT.
//
// The standby receives the unconfirmed config (C2) via config-sync SyncApply,
// which arms NO confirm timer, so it holds C2 as its PERMANENT active. When the
// confirm window expires, executeConfirmedRollback (PromoteRollback) reverts
// ONLY the local node's store to the prior confirmed config (C1). Before this
// fix it never pushed the rollback to the peer, so the nodes DIVERGED
// (primary=C1, standby=C2) and a failover would serve the abandoned C2.
//
// These tests pin the fix: the confirm-timeout rollback must re-sync the
// rolled-back config (C1) to the peer, and must self-guard the peer-absent case
// (nil cluster/sessionSync — no crash).
package daemon

import (
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// TestExecuteConfirmedRollbackResyncsPeer proves executeConfirmedRollback
// re-syncs the rolled-back config to the cluster peer, AFTER the store has been
// promoted back to the rollback target. RED-on-revert: dropping the
// d.resyncRolledBackConfigToPeer() call leaves the seam uncalled (calls==0) and
// the standby stuck on the abandoned config — exactly the #3868 divergence.
func TestExecuteConfirmedRollbackResyncsPeer(t *testing.T) {
	s, gen := newRollbackTestStore(t) // active=B pending, rollback target=A
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}

	var (
		calls        int
		syncedConfig string
	)
	// The real peer-resync path (syncConfigToPeer -> pushConfigToPeer ->
	// SessionSync.QueueConfig) needs a live TCP transport, so observe the call
	// through the injected seam. Read ShowActive() at call time — this is
	// exactly the text pushConfigToPeer would queue, so it proves the re-sync
	// carries the rolled-back config (C1 = host-name A), not the abandoned one.
	d.syncPeerForTest = func() {
		calls++
		syncedConfig = d.store.ShowActive()
	}

	d.executeConfirmedRollback(gen)

	// Local store must have rolled back to A.
	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("after rollback local active host-name = %q, want A", got)
	}
	// The peer re-sync must have fired exactly once.
	if calls != 1 {
		t.Fatalf("executeConfirmedRollback must re-sync the rolled-back config to the peer "+
			"exactly once; got %d calls (standby would keep the abandoned config — #3868)", calls)
	}
	// It must have pushed the rollback target C1 (host-name A), not the
	// abandoned unconfirmed C2 (host-name B) — proving the re-sync happens
	// AFTER PromoteRollback.
	if !strings.Contains(syncedConfig, "host-name A") {
		t.Fatalf("peer re-sync pushed the wrong config; want the rolled-back C1 (host-name A), "+
			"got:\n%s", syncedConfig)
	}
	if strings.Contains(syncedConfig, "host-name B") {
		t.Fatalf("peer re-sync pushed the abandoned unconfirmed C2 (host-name B) — re-sync ran "+
			"BEFORE PromoteRollback:\n%s", syncedConfig)
	}
}

// TestExecuteConfirmedRollbackResyncPeerAbsent proves the confirm-timeout
// rollback re-sync self-guards when there is no peer: with nil
// cluster/sessionSync (and no test seam) the real syncConfigToPeer path runs
// and must no-op cleanly — no panic — while the local store still rolls back.
// The existing reverse-sync-on-reconnect converges the peer when it returns.
func TestExecuteConfirmedRollbackResyncPeerAbsent(t *testing.T) {
	s, gen := newRollbackTestStore(t) // active=B pending, rollback target=A
	// No cluster, no sessionSync, no syncPeerForTest seam: exercises the real
	// syncConfigToPeer nil-guard.
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	d.applyBodyForTest = func(_ *config.Config) {}

	// Must not panic even though the real peer-resync path runs with no peer.
	d.executeConfirmedRollback(gen)

	if got := s.ActiveConfig().System.HostName; got != "A" {
		t.Fatalf("after rollback (peer absent) local active host-name = %q, want A", got)
	}
}
