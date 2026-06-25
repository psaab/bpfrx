package dhcpserver

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"
)

// ddns_integration_test.go: helpers for the real-parser → pkg/ddns-engine
// integration tests that stayed in pkg/dhcpserver (#2691 P1a). These tests
// exercise the keaLeaseParser → engine wiring end-to-end: the Kea-memfile
// parser is package-local (ddns_leases.go) but the reconcile engine moved to
// pkg/ddns, so they build a manager via NewDDNSManagerForTesting (which wires
// the real parser) and drive it with synthetic memfiles. They assert engine
// behavior (no mass-delete on a mangled header, owned-record preservation/
// clearing) through the exported test seams (DDNSLeasePaths, OwnedForTesting,
// OwnedKeysForTesting) rather than reaching into engine internals.

// fakeUpdater records every upsert/delete so the integration tests can assert
// no destructive delete fired when a lease source went untrusted. (The
// pkg/ddns engine's own fakeUpdater is unexported; this is the dhcpserver-side
// equivalent used only by the cross-package integration tests.)
type fakeUpdater struct {
	mu      sync.Mutex
	upserts []LeaseDNSRecord
	deletes []LeaseDNSRecord
}

func newFakeUpdater() *fakeUpdater { return &fakeUpdater{} }

func (f *fakeUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts = append(f.upserts, rec)
	return nil
}

func (f *fakeUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletes = append(f.deletes, rec)
	return nil
}

func (f *fakeUpdater) deleteNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.deletes))
	for _, r := range f.deletes {
		out = append(out, r.FQDN+"="+r.Addr.String())
	}
	sort.Strings(out)
	return out
}

// testDDNS builds a DDNSManager (pkg/ddns engine) wired with the real
// package-local Kea-memfile parser and temp-dir state/lease paths, using the
// fixed updater up.
func testDDNS(t *testing.T, up DNSUpdater) *DDNSManager {
	t.Helper()
	dir := t.TempDir()
	return NewDDNSManagerForTesting(
		up,
		filepath.Join(dir, "state.json"),
		filepath.Join(dir, "leases4.csv"),
		filepath.Join(dir, "leases6.csv"),
		"node0",
		func() time.Time { return time.Unix(1_700_000_000, 0) },
		nil, // fixed updater; no resolve-per-Reconcile factory
	)
}

// mustP4 returns the manager's v4 lease path (the engine's leasePath4 is no
// longer a directly-reachable field after the #2691 P1a move).
func mustP4(m *DDNSManager) string {
	p4, _ := m.DDNSLeasePaths()
	return p4
}
