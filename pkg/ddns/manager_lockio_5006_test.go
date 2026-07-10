package ddns

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// manager_lockio_5006_test.go: #5006 — the DHCP dynamic-DNS Manager must NOT
// hold m.mu across the blocking RFC 2136 DNS UPDATE wire I/O
// (upsertLocked/deleteOwnedLocked call updater.UpsertLease/DeleteLease, bounded
// only by the ~5s DDNS reconcile timeout). The telemetry/CLI readers Stats()
// and OwnedRecordViews() take m.mu, so a slow/offline authoritative server used
// to stall `show system services dynamic-dns` and Prometheus scrapes for the
// full DNS exchange. These are the fail-on-revert proofs: revert the providerIO
// lock-release wrapping in manager.go and the "reader proceeds while wire I/O is
// blocked" assertions HANG until the bounded wait fires t.Fatal.
//
// The blockingUpdater double is shared with surface_a_lockio_test.go (same
// package): every UpsertLease/DeleteLease signals entry on `entered` and blocks
// until `release` is closed.

// managerWithBlockingUpdater builds a production-shaped Manager whose live
// (non-nop) updater is the blocking double. Leaving m.newUpdater nil keeps the
// static updater in force for the pass, so the reconcile drives the real
// write-ahead → wire-add → confirm path through bu.
func managerWithBlockingUpdater(t *testing.T, bu *blockingUpdater, src *fakeLeaseSource) *Manager {
	t.Helper()
	dir := t.TempDir()
	return newManagerForTesting(
		src.parser(),
		bu,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
}

// TestManagerLockNotHeldDuringUpsert proves m.mu is released while the provider
// UpsertLease is in flight (#5006). A blocking provider holds the wire add open;
// concurrently Stats() and OwnedRecordViews() (both take m.mu) MUST complete. If
// the lock were held across the I/O the readers would block until release and
// the bounded wait below fires — the fail-on-revert assertion.
func TestManagerLockNotHeldDuringUpsert(t *testing.T) {
	bu := newBlockingUpdater()
	src := &fakeLeaseSource{v4: laptopMacLease()}
	m := managerWithBlockingUpdater(t, bu, src)
	cfg := ddnsCfg("dns.example.com")

	reconcileDone := make(chan error, 1)
	go func() { reconcileDone <- m.Reconcile(context.Background(), cfg) }()

	// Wait until the provider Upsert is actually in flight (wire add open).
	select {
	case <-bu.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider UpsertLease never started")
	}

	// While the wire op is blocked, the telemetry readers (which take m.mu)
	// MUST proceed. If the lock were held across the I/O they block and the
	// bounded wait fires — the #5006 regression.
	readerDone := make(chan struct{})
	go func() {
		_ = m.Stats()
		_ = m.OwnedRecordViews()
		close(readerDone)
	}()
	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats()/OwnedRecordViews() blocked while DNS UpsertLease was in flight — m.mu held across wire I/O (#5006 regression)")
	}

	close(bu.release)
	select {
	case err := <-reconcileDone:
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Reconcile did not finish after provider released")
	}
	if bu.upserts != 1 {
		t.Fatalf("expected exactly one upsert, got %d", bu.upserts)
	}
	if st := m.Stats(); st.UpsertOK != 1 {
		t.Fatalf("expected UpsertOK=1 after release, got %+v", st)
	}
}

// TestManagerLockNotHeldDuringDelete proves m.mu is released while a withdraw's
// provider DeleteLease is in flight (#5006). First publish a record, then drive
// a withdraw (family disabled → owned record deleted) while the provider delete
// blocks; a concurrent Stats()/OwnedRecordViews() must proceed.
func TestManagerLockNotHeldDuringDelete(t *testing.T) {
	bu := newBlockingUpdater()
	src := &fakeLeaseSource{v4: laptopMacLease()}
	m := managerWithBlockingUpdater(t, bu, src)
	cfg := ddnsCfg("dns.example.com")

	// Publish once (let the add through immediately).
	pubDone := make(chan error, 1)
	go func() { pubDone <- m.Reconcile(context.Background(), cfg) }()
	<-bu.entered
	close(bu.release)
	if err := <-pubDone; err != nil {
		t.Fatalf("publish reconcile: %v", err)
	}
	if st := m.Stats(); st.OwnedRecords != 1 {
		t.Fatalf("expected 1 owned record after publish, got %+v", st)
	}

	// Re-arm the release gate for the delete pass.
	bu.release = make(chan struct{})

	// Reconcile with DDNS disabled → the owned record is withdrawn (Pass 1
	// delete of a now-disabled family) through the SAME live updater.
	disabled := ddnsCfg("dns.example.com")
	disabled.DynamicDNS.Enabled = false
	withdrawDone := make(chan error, 1)
	go func() { withdrawDone <- m.Reconcile(context.Background(), disabled) }()

	select {
	case <-bu.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider DeleteLease never started")
	}

	readerDone := make(chan struct{})
	go func() {
		_ = m.Stats()
		_ = m.OwnedRecordViews()
		close(readerDone)
	}()
	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats()/OwnedRecordViews() blocked while DNS DeleteLease was in flight — m.mu held across wire I/O (#5006 regression)")
	}

	close(bu.release)
	select {
	case err := <-withdrawDone:
		if err != nil {
			t.Fatalf("withdraw reconcile: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withdraw Reconcile did not finish after provider released")
	}
	if bu.deletes != 1 {
		t.Fatalf("expected exactly one delete, got %d", bu.deletes)
	}
	if st := m.Stats(); st.DeleteOK != 1 || st.OwnedRecords != 0 {
		t.Fatalf("expected DeleteOK=1 and no owned records after withdraw, got %+v", st)
	}
}
