package ddns

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// ddns_durability_test.go: #2662 write-ahead ownership durability. These
// tests prove the orphan window is closed — a crash AFTER a successful DNS
// add but BEFORE the end-of-pass save can no longer strand a live RR with no
// durable ownership record, because the ownership intent is now persisted
// BEFORE the wire add (write-ahead). They also prove a refused add removes
// the pre-written intent (no phantom ownership), and a durable-write failure
// before the add suppresses the publish (record reported not safely owned).

// readDurableOwnership loads the on-disk ownership store and returns the
// owned records keyed by ownedRecordKey. A missing file is an empty map.
func readDurableOwnership(t *testing.T, path string) map[string]ownedRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]ownedRecord{}
	}
	if err != nil {
		t.Fatalf("read durable state %s: %v", path, err)
	}
	var f ddnsStateFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse durable state %s: %v", path, err)
	}
	out := map[string]ownedRecord{}
	for _, r := range f.Records {
		out[ownedRecordKey(r.Identity, r.Address)] = r
	}
	return out
}

// snapshotUpdater is a live (non-nop) updater that, on each UpsertLease,
// snapshots the CURRENT durable ownership store. This lets a test assert
// that ownership was ALREADY durable at the instant the DNS add happened —
// the write-ahead invariant. It can also be told to refuse a name (return
// errDDNSConflictRefused) so the refused-add intent-removal path is exercised.
type snapshotUpdater struct {
	statePath string
	read      func(path string) map[string]ownedRecord
	// durableAtAdd[fqdn] = the durable store contents at the moment FQDN was
	// added.
	durableAtAdd map[string]map[string]ownedRecord
	refuse       map[string]bool
	upserts      []string
	deletes      []string
}

func (s *snapshotUpdater) UpsertLease(_ context.Context, rec LeaseDNSRecord) error {
	if s.refuse[rec.FQDN] {
		return errDDNSConflictRefused
	}
	if s.durableAtAdd == nil {
		s.durableAtAdd = map[string]map[string]ownedRecord{}
	}
	s.durableAtAdd[rec.FQDN] = s.read(s.statePath)
	s.upserts = append(s.upserts, rec.FQDN)
	return nil
}

func (s *snapshotUpdater) DeleteLease(_ context.Context, rec LeaseDNSRecord) error {
	s.deletes = append(s.deletes, rec.FQDN)
	return nil
}

// TestUpsertWriteAheadDurableBeforeAdd is the core fail-on-revert test: at
// the instant the DNS add fires, the ownership record MUST already be in the
// durable on-disk store. With the pre-#2662 end-of-pass-only save the durable
// store at add time is EMPTY -> the assertion fails (an orphaned RR would be
// possible on a crash here).
func TestUpsertWriteAheadDurableBeforeAdd(t *testing.T) {
	up := &snapshotUpdater{}
	m := testDDNS(t, up)
	up.statePath = m.state.path
	up.read = func(p string) map[string]ownedRecord { return readDurableOwnership(t, p) }

	pol := enabledPolicy()
	leases := []Lease{leaseV4("10.0.1.50", "mac:aabb", "laptop")}
	if err := runReconcile(t, m, pol, leases); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(up.upserts) != 1 {
		t.Fatalf("want 1 upsert, got %v", up.upserts)
	}
	fqdn := up.upserts[0]
	durable := up.durableAtAdd[fqdn]
	if len(durable) != 1 {
		t.Fatalf("write-ahead violated: durable store at add time = %v (want the owned record already persisted BEFORE the add)", durable)
	}
	// And the record persisted before the add must be for this exact tuple.
	var found bool
	for _, r := range durable {
		if r.FQDN == fqdn && r.Address == "10.0.1.50" {
			found = true
		}
	}
	if !found {
		t.Fatalf("durable store at add time missing the record for %s: %v", fqdn, durable)
	}
}

// TestUpsertCrashAfterAddBeforeEndOfPassSave simulates a crash AFTER a
// successful DNS add but BEFORE the end-of-pass save by failing every save
// AFTER the write-ahead pre-write has landed. A fresh manager loading the
// durable state MUST still know it owns the record (so a later release can
// clean it). fail-on-revert: with end-of-pass-only persistence the record
// would never reach disk and the fresh manager would own nothing -> orphan.
func TestUpsertCrashAfterAddBeforeEndOfPassSave(t *testing.T) {
	up := &snapshotUpdater{}
	m := testDDNS(t, up)
	up.statePath = m.state.path
	up.read = func(p string) map[string]ownedRecord { return readDurableOwnership(t, p) }

	// Allow exactly the FIRST save (the write-ahead pre-write) to succeed,
	// then fail every subsequent save (the post-add confirm + end-of-pass).
	// This models a crash/disk-full that strikes after the write-ahead has
	// durably recorded ownership and after the DNS add succeeded.
	real := m.state.writeFile
	if real == nil {
		real = func(path string, data []byte, perm os.FileMode) error {
			return os.WriteFile(path, data, perm)
		}
	}
	var saves int
	m.state.writeFile = func(path string, data []byte, perm os.FileMode) error {
		saves++
		if saves == 1 {
			return real(path, data, perm)
		}
		return os.ErrPermission // crash/disk-full after the add
	}

	pol := enabledPolicy()
	leases := []Lease{leaseV4("10.0.1.50", "mac:aabb", "laptop")}
	_ = runReconcile(t, m, pol, leases) // confirm/end-of-pass save errors are tolerated

	if len(up.upserts) != 1 {
		t.Fatalf("want the DNS add to have happened, got upserts=%v", up.upserts)
	}

	// A fresh manager loading the durable state MUST own the record.
	fresh, err := loadDDNSState(m.state.path)
	if err != nil {
		t.Fatalf("load durable state: %v", err)
	}
	if _, ok := fresh.get("mac:aabb", "10.0.1.50"); !ok {
		t.Fatalf("orphan: fresh manager has no durable ownership for the live RR; records=%v", fresh.records)
	}
}

// TestUpsertRefusedAddRemovesIntent proves a refused add (name owned by
// another party) removes the pre-written write-ahead intent so no phantom
// ownership survives. A phantom would let a later release delete a record xpf
// did not create.
func TestUpsertRefusedAddRemovesIntent(t *testing.T) {
	up := &snapshotUpdater{refuse: map[string]bool{}}
	m := testDDNS(t, up)
	up.statePath = m.state.path
	up.read = func(p string) map[string]ownedRecord { return readDurableOwnership(t, p) }
	up.refuse["laptop.example.com"] = true

	pol := enabledPolicy()
	leases := []Lease{leaseV4("10.0.1.50", "mac:aabb", "laptop")}
	if err := runReconcile(t, m, pol, leases); err != nil {
		t.Fatalf("reconcile (refused add must not fail the pass): %v", err)
	}
	if len(up.upserts) != 0 {
		t.Fatalf("refused add should record no successful upsert, got %v", up.upserts)
	}
	// Neither in-memory nor durable ownership may claim the refused name.
	if _, ok := m.state.get("mac:aabb", "10.0.1.50"); ok {
		t.Fatalf("phantom in-memory ownership survived a refused add")
	}
	durable := readDurableOwnership(t, m.state.path)
	if len(durable) != 0 {
		t.Fatalf("phantom durable ownership survived a refused add: %v", durable)
	}
}

// TestUpsertPreAddSaveFailureSuppressesPublish proves that when the durable
// pre-write FAILS the DNS add does NOT run (record reported not safely
// owned), and no in-memory or durable ownership is left behind.
func TestUpsertPreAddSaveFailureSuppressesPublish(t *testing.T) {
	up := &snapshotUpdater{}
	m := testDDNS(t, up)
	up.statePath = m.state.path
	up.read = func(p string) map[string]ownedRecord { return readDurableOwnership(t, p) }

	m.state.writeFile = func(path string, data []byte, perm os.FileMode) error {
		return os.ErrPermission // every save fails, including the write-ahead pre-write
	}

	pol := enabledPolicy()
	leases := []Lease{leaseV4("10.0.1.50", "mac:aabb", "laptop")}
	err := runReconcile(t, m, pol, leases)
	if err == nil {
		t.Fatalf("reconcile should surface the durable-write failure")
	}
	if len(up.upserts) != 0 {
		t.Fatalf("publish must be suppressed when ownership cannot be durably recorded; got %v", up.upserts)
	}
	if _, ok := m.state.get("mac:aabb", "10.0.1.50"); ok {
		t.Fatalf("in-memory ownership left after a suppressed publish")
	}
}
